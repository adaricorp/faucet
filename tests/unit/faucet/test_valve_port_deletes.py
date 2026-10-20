#!/usr/bin/env python3

"""Unit tests for the flows faucet deletes when a port goes down or changes."""

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

from os_ken.ofproto import ofproto_v1_3 as ofp

from clib.valve_test_lib import ValveTestBases

from faucet import valve_of


TRUNK_CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: "Open vSwitch"
        interfaces:
            p1:
                number: 1
                tagged_vlans: [%s]
            p2:
                number: 2
                native_vlan: v100
                tagged_vlans: [v200, v300]
            p3:
                number: 3
                native_vlan: v300
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
    v300:
        vid: 0x300
"""


def trunk_config(p1_vlans="v100, v200, v300"):
    """Return TRUNK_CONFIG with p1 tagged on p1_vlans."""
    return TRUNK_CONFIG % p1_vlans


class ValvePortDeletesTestBase(ValveTestBases.ValveTestNetwork):
    """Read what a port going down, or a reload, deletes."""

    REQUIRE_TFM = False

    def valve(self):
        """Return the DP's valve."""
        return self.valves_manager.valves[self.DP_ID]

    def table_id(self, table_name):
        """Return the ID of the DP's table_name table."""
        return self.valve().dp.tables[table_name].table_id

    def port_down(self, port_no):
        """Take port_no's link down, and return the flow mods sent."""
        valve = self.valve()
        ofmsgs = valve.port_status_handler(
            port_no, ofp.OFPPR_MODIFY, ofp.OFPPS_LINK_DOWN, [], self.mock_time(0)
        ).get(valve, [])
        return self.apply_ofmsgs(ofmsgs)

    def port_up(self, port_no):
        """Bring port_no's link up, and return the flow mods sent."""
        valve = self.valve()
        ofmsgs = valve.port_status_handler(
            port_no, ofp.OFPPR_MODIFY, 0, [], self.mock_time(0)
        ).get(valve, [])
        return self.apply_ofmsgs(ofmsgs)

    def table_flows(self, table_name):
        """Return the flows in the DP's table_name table."""
        return self.network.tables[self.DP_ID].tables[self.table_id(table_name)]


class ValvePortVLANDeleteTestCase(ValvePortDeletesTestBase):
    """Test a port's tagged VLAN flows are deleted by their match and priority."""

    def setUp(self):
        """Set up a DP with a trunk."""
        self.setup_valves(trunk_config())

    def port_vlan_deletes(self, ofmsgs, port_no):
        """Return the deletes in ofmsgs of port_no's flows for a VLAN ID."""
        return [
            ofmsg
            for ofmsg in ofmsgs
            if valve_of.is_flowdel(ofmsg)
            and ofmsg.table_id == self.table_id("vlan")
            and ofmsg.match.get("in_port") == port_no
            and "vlan_vid" in ofmsg.match
        ]

    def port_vids(self, port_no):
        """Return the VLAN IDs port_no has a flow for in the VLAN table."""
        return {
            flow.match_values["vlan_vid"].int & ~ofp.OFPVID_PRESENT
            for flow in self.table_flows("vlan")
            if "in_port" in flow.match_values
            and flow.match_values["in_port"].int == port_no
            and "vlan_vid" in flow.match_values
        }

    def assert_strict(self, deletes):
        """Assert deletes are strict, at the priority their flows were added."""
        self.assertTrue(deletes)
        for ofmsg in deletes:
            self.assertEqual(ofp.OFPFC_DELETE_STRICT, ofmsg.command, msg=ofmsg)
            self.assertEqual(
                self.valve().switch_manager.low_priority, ofmsg.priority, msg=ofmsg
            )

    def test_port_down(self):
        """Test a trunk going down deletes each of its VLANs' flows strictly."""
        self.assertEqual({0x100, 0x200, 0x300}, self.port_vids(1))
        deletes = self.port_vlan_deletes(self.port_down(1), 1)
        self.assertEqual(
            [0x100, 0x200, 0x300],
            sorted(ofmsg.match["vlan_vid"] & ~ofp.OFPVID_PRESENT for ofmsg in deletes),
        )
        self.assert_strict(deletes)
        self.assertEqual(set(), self.port_vids(1))
        # p2's untagged VLAN's flow matches no VLAN ID.
        self.assertEqual({ofp.OFPVID_NONE, 0x200, 0x300}, self.port_vids(2))
        self.port_up(1)
        self.assertEqual({0x100, 0x200, 0x300}, self.port_vids(1))

    def test_warm_start_removes_vlan(self):
        """Test a warm start that takes a VLAN off a trunk deletes its flow strictly."""
        ofmsgs = self.update_config(trunk_config("v100, v200"), reload_type="warm")[
            self.DP_ID
        ]
        deletes = self.port_vlan_deletes(ofmsgs, 1)
        # The kept VLANs' deletes go as their flows are added again.
        self.assertEqual(
            [0x300],
            [ofmsg.match["vlan_vid"] & ~ofp.OFPVID_PRESENT for ofmsg in deletes],
        )
        self.assert_strict(deletes)
        self.assertEqual({0x100, 0x200}, self.port_vids(1))


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
