#!/usr/bin/env python3

"""Test FAUCET valve_route."""

# pylint: disable=protected-access

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random
import unittest

from faucet.router import Router
from faucet.valve_route import ValveIPv4RouteManager
from faucet.vlan import VLAN


def replaced_router_for_vlan(self, vlan):
    """ValveRouteManager._router_for_vlan() as it was before the lookup.

    Kept verbatim, as the oracle for the differential test below.
    """
    if self.routers:
        for router in self.routers.values():
            if vlan in router.vlans:
                return router
    return None


def replaced_routed_vlans(self, vlan):
    """ValveRouteManager._routed_vlans() as it was before the lookup.

    Kept verbatim, as the oracle for the differential test below.
    """
    if self.global_routing:
        return set([self.global_vlan])
    vlans = set([vlan])
    if self.routers:
        for router in self.routers.values():
            if vlan in router.vlans:
                vlans = vlans.union(router.vlans)
    return vlans


def vlan_key(vlan):
    """Return what identifies a VLAN in a routed set: its VID and its name.

    The global routing answer is an AnonVLAN, which has a VID and no name.
    """
    return (vlan.vid, getattr(vlan, "name", None))


class ValveRouteManagerVLANTestCase(unittest.TestCase):
    """Test which VLANs and routers a VLAN is routed with."""

    @staticmethod
    def build_vlan(vid, name):
        """Return a finalized VLAN with this VID and name."""
        vlan = VLAN(name, 1, {"vid": vid})
        vlan.finalize()
        return vlan

    @staticmethod
    def build_routers(*router_vlans):
        """Return finalized routers, in order, each naming its VLANs."""
        routers = {}
        for index, (name, vlans) in enumerate(router_vlans):
            router = Router(name, index, {"vlans": [vlan.vid for vlan in vlans]})
            router.vlans = list(vlans)
            router.finalize()
            routers[name] = router
        return routers

    @staticmethod
    def build_route_manager(routers):
        """Return a route manager with only what these tests reach for."""
        return ValveIPv4RouteManager(
            None,
            None,
            0,
            0,
            0,
            0,
            0,
            False,
            False,
            False,
            None,
            None,
            None,
            routers,
            None,
        )

    def test_routed_vlans_union(self):
        """Test a VLAN is routed with every VLAN of every router naming it."""
        office = self.build_vlan(100, "office")
        guest = self.build_vlan(200, "guest")
        voip = self.build_vlan(300, "voip")
        routers = self.build_routers(
            ("r1", [office, guest]),
            ("r2", [office, voip]),
            ("r3", [guest, voip]),
        )
        route_manager = self.build_route_manager(routers)
        self.assertEqual(
            {vlan.vid for vlan in route_manager._routed_vlans(office)},
            {100, 200, 300},
            "routed vlans not the union of the routers naming this vlan",
        )

    def test_routed_vlans_unrouted(self):
        """Test a VLAN no router names is routed only with itself."""
        office = self.build_vlan(100, "office")
        lonely = self.build_vlan(999, "lonely")
        route_manager = self.build_route_manager(self.build_routers(("r1", [office])))
        self.assertEqual(
            route_manager._routed_vlans(lonely),
            {lonely},
            "unrouted vlan routed with something else",
        )

    def test_routed_vlans_previous_config(self):
        """Test a VLAN carried over a reload is not the VLAN with its VID."""
        # merge_dyn can leave a port pointing at the previous config's VLAN,
        # so two objects share one VID and each routes with its own router.
        office = self.build_vlan(100, "office")
        was_office = self.build_vlan(100, "office-was")
        guest = self.build_vlan(200, "guest")
        voip = self.build_vlan(300, "voip")
        routers = self.build_routers(
            ("r1", [office, guest]), ("r2", [was_office, voip])
        )
        route_manager = self.build_route_manager(routers)
        self.assertEqual(
            {vlan.vid for vlan in route_manager._routed_vlans(office)},
            {100, 200},
            "vlan routed with a same VID vlan from another config",
        )
        self.assertEqual(
            {vlan.vid for vlan in route_manager._routed_vlans(was_office)},
            {100, 300},
            "vlan from another config routed with the current one",
        )

    def test_router_for_vlan_first(self):
        """Test route ownership follows the first router naming the VLAN."""
        office = self.build_vlan(100, "office")
        routers = self.build_routers(("r1", [office]), ("r2", [office]))
        route_manager = self.build_route_manager(routers)
        self.assertIs(
            route_manager._router_for_vlan(office),
            routers["r1"],
            "router for vlan not the first configured",
        )

    def test_router_for_vlan_unrouted(self):
        """Test a VLAN no router names has no router."""
        office = self.build_vlan(100, "office")
        lonely = self.build_vlan(999, "lonely")
        route_manager = self.build_route_manager(self.build_routers(("r1", [office])))
        self.assertEqual(
            route_manager._router_for_vlan(lonely),
            None,
            "unrouted vlan has a router",
        )

    def test_routers_by_vid_reused(self):
        """Test lookups read the index built at construction, not the routers."""
        office = self.build_vlan(100, "office")
        guest = self.build_vlan(200, "guest")
        routers = self.build_routers(("r1", [office, guest]))
        route_manager = self.build_route_manager(routers)
        routers_by_vid = route_manager.routers_by_vid
        self.assertEqual(sorted(routers_by_vid), [100, 200], "index not keyed by VID")
        route_manager._routed_vlans(office)
        route_manager._router_for_vlan(office)
        self.assertIs(
            route_manager.routers_by_vid, routers_by_vid, "index rebuilt by a lookup"
        )
        routers_by_vid.clear()
        self.assertEqual(
            route_manager._routed_vlans(office),
            {office},
            "routed vlans found without the index",
        )
        self.assertIsNone(
            route_manager._router_for_vlan(office), "router found without the index"
        )

    def test_routed_vlans_match_replaced_scan(self):
        """Test random routers route each VLAN as the replaced scan did.

        Generated sets of VLANs and routers, including VLANs carried over
        from a previous config that share a VID with a current one, must
        give the same routed VLANs and the same router by the lookup as by
        scanning every router.
        """
        rng = random.Random(1)
        for sample in range(200):
            vids = rng.sample(range(2, 4000), rng.randint(2, 6))
            vlans = [self.build_vlan(vid, "v%d" % vid) for vid in vids]
            vlans.extend(
                self.build_vlan(vid, "v%d-was" % vid)
                for vid in rng.sample(vids, rng.randint(0, 2))
            )
            router_vlans = [
                ("r%d" % index, rng.sample(vlans, rng.randint(1, min(4, len(vlans)))))
                for index in range(rng.randint(0, 4))
            ]
            route_manager = self.build_route_manager(self.build_routers(*router_vlans))
            for vlan in vlans:
                with self.subTest(sample=sample, vlan=vlan.name):
                    self.assertEqual(
                        {
                            vlan_key(routed)
                            for routed in route_manager._routed_vlans(vlan)
                        },
                        {
                            vlan_key(routed)
                            for routed in replaced_routed_vlans(route_manager, vlan)
                        },
                        "routed vlans differ from the replaced scan",
                    )
                    self.assertIs(
                        route_manager._router_for_vlan(vlan),
                        replaced_router_for_vlan(route_manager, vlan),
                        "router differs from the replaced scan",
                    )


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
