#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_warm_routers_kept_vlans.py."""

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
from unittest import mock

from os_ken.ofproto import ofproto_v1_3 as ofp

from faucet import valve_of
from faucet.valve import Valve

from tests.unit.faucet.test_valve_config import ValveWarmRoutersTestBase


class ValveWarmRoutersKeptVLANsTestBase(ValveWarmRoutersTestBase):
    """Warm start a routers change and check it deletes no VLAN it keeps.

    A routers change is applied pair by pair. Deleting a VLAN it keeps and
    adding it again would flush the VLAN's hosts and expire the next hops of
    every VLAN routed with it, leaving them unrouted until every host and
    gateway is learned again. The routing assertions only see that as routes
    missing, as if a test forgot to learn the hosts; these name the cause.
    """

    def kept_hosts(self, kept_vids):
        """Return the hosts learned on each of kept_vids."""
        vlans = self.valves_manager.valves[self.DP_ID].dp.vlans
        return {vid: sorted(vlans[vid].dyn_host_cache) for vid in kept_vids}

    def assert_no_vlan_deleted(self, config, deleted_vids=()):
        """Assert a warm start of config deletes no VLAN but deleted_vids.

        Valve.del_vlan is called for no other VLAN, no flow is deleted by
        another VLAN's VID alone, as deleting that VLAN would, and every
        other VLAN keeps the hosts it had learned.
        """
        dp = self.valves_manager.valves[self.DP_ID].dp
        kept_vids = set(dp.vlans) - set(deleted_vids)
        hosts = self.kept_hosts(kept_vids)
        self.assertTrue(any(hosts.values()), msg="no hosts learned to keep")
        with mock.patch.object(
            Valve, "del_vlan", autospec=True, side_effect=Valve.del_vlan
        ) as del_vlan:
            ofmsgs = self.update_config(config, reload_type="warm")[self.DP_ID]
        self.assertEqual(
            sorted(deleted_vids),
            sorted(call.args[1].vid for call in del_vlan.call_args_list),
            msg="VLANs deleted",
        )
        vlan_wide = []
        for ofmsg in ofmsgs:
            if not valve_of.is_flowdel(ofmsg):
                continue
            match = dict(ofmsg.match.items())
            vid = match.get("vlan_vid")
            if not isinstance(vid, int) or set(match) - {"vlan_vid", "eth_type"}:
                continue
            vid &= ~ofp.OFPVID_PRESENT
            if vid in kept_vids:
                vlan_wide.append(str(ofmsg))
        self.assertEqual([], vlan_wide, msg="flows deleted by a kept VLAN's VID")
        self.assertEqual(hosts, self.kept_hosts(kept_vids), msg="hosts of kept VLANs")


class ValveWarmRoutersFailoverKeptVLANsTestCase(ValveWarmRoutersKeptVLANsTestBase):
    """Test failing over between uplinks deletes no VLAN."""

    MOVED = dict(ValveWarmRoutersTestBase.UPLINKS, clients1="uplink2")

    def test_failover_deletes_no_vlan(self):
        """Test a failover, a pairing and their reverse delete no VLAN.

        Each changes only which VLANs route with which, so each VLAN keeps
        its hosts and every next hop stays resolved.
        """
        moved_all = {client: "uplink2" for client in self.UPLINKS}
        pairing = (("clients1", "clients2"),)
        for change, uplinks, pairings in (
            ("failover", self.MOVED, ()),
            ("failback", self.UPLINKS, ()),
            ("failover all", moved_all, ()),
            ("failback all", self.UPLINKS, ()),
            ("pairing added", self.UPLINKS, pairing),
            ("pairing removed", self.UPLINKS, ()),
            ("uplink removed", dict(self.UPLINKS, clients1=None), ()),
            ("uplink added", self.UPLINKS, ()),
        ):
            with self.subTest(change=change):
                # Every host is learned before each change, whatever the
                # changes before it did.
                for port in self.LEARN_PORTS:
                    self.learn(port)
                self.assert_no_vlan_deleted(self.config(uplinks, pairings))
                self.assert_routing(uplinks, pairings)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
