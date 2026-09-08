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

import unittest

from faucet.router import Router
from faucet.valve_route import ValveIPv4RouteManager
from faucet.vlan import VLAN


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


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
