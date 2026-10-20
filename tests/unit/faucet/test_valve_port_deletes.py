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

from os_ken.lib.packet import slow
from os_ken.ofproto import ofproto_v1_3 as ofp

from clib.valve_test_lib import FAUCET_MAC, ValveTestBases

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


# p3 and p4 flood ARP and ND only to ports that are not restricted, so the
# others flood from their own flood flows, which flood to p3 and p4 too.
RESTRICTED_CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: "Open vSwitch"
        interfaces:
            p1:
                number: 1
                tagged_vlans: [v100, v200]
            p2:
                number: 2
                native_vlan: v100
            p3:
                number: 3
                native_vlan: v100
                restricted_bcast_arpnd: true
            p4:
                number: 4
                native_vlan: v100
                restricted_bcast_arpnd: %s
            p5:
                number: 5
                native_vlan: v200
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
"""


def restricted_config(p4_restricted):
    """Return RESTRICTED_CONFIG with p4 restricted if p4_restricted."""
    return RESTRICTED_CONFIG % str(p4_restricted).lower()


# p5 keeps the pipeline the same when p2 stops being a hairpin port.
LACP_HAIRPIN_CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: "Open vSwitch"
        interfaces:
            p1:
                number: 1
                tagged_vlans: [v100, v200]
                lacp: 1
                max_hosts: %(p1_max_hosts)u
            p2:
                number: 2
                native_vlan: v200
                hairpin: %(p2_hairpin)s
            p3:
                number: 3
                native_vlan: v200
            p4:
                number: 4
                tagged_vlans: [v100, v200]
            p5:
                number: 5
                native_vlan: v100
                hairpin: true
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
        max_hosts: %(v200_max_hosts)u
"""


def lacp_hairpin_config(changed):
    """Return LACP_HAIRPIN_CONFIG, with p1, p2 and v200 changed if changed."""
    return LACP_HAIRPIN_CONFIG % {
        "p1_max_hosts": (10, 20)[changed],
        "p2_hairpin": ("true", "false")[changed],
        "v200_max_hosts": (10, 20)[changed],
    }


# p3 and p4 are a LAG.
LAG_SYNC_CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: "Open vSwitch"
        lacp_timeout: 5
        interfaces:
            p1:
                number: 1
                tagged_vlans: [v100, v200]
            p2:
                number: 2
                tagged_vlans: [%s]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
                lacp: 1
            p4:
                number: 4
                tagged_vlans: [v100, v200]
                lacp: 1
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
"""


def lag_sync_config(p2_vlans):
    """Return LAG_SYNC_CONFIG with p2 tagged on p2_vlans."""
    return LAG_SYNC_CONFIG % p2_vlans


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

    def port_flood_deletes(self, ofmsgs):
        """Return the deletes in ofmsgs of port specific flood flows."""
        return [
            ofmsg
            for ofmsg in ofmsgs
            if valve_of.is_flowdel(ofmsg)
            and ofmsg.table_id == self.table_id("flood")
            and "in_port" in ofmsg.match
        ]

    def port_flood_ports(self):
        """Return the ports with a port specific flood flow."""
        return {
            flow.match_values["in_port"].int
            for flow in self.table_flows("flood")
            if "in_port" in flow.match_values
        }

    def flood_table(self):
        """Return the flood table, comparably."""
        return sorted(str(flow) for flow in self.table_flows("flood"))

    def cold_flood_table(self, ports_up=None):
        """Cold start the DP with ports_up up, and return its flood table."""
        self.valve().datapath_disconnect(self.mock_time())
        self.connect_dp(ports_up=ports_up)
        return self.flood_table()

    def rcv_lacp(self, port_no, sync):
        """Receive LACP on port_no, in sync if sync, and return the flow mods sent."""
        return self.rcv_packet(
            port_no,
            0,
            {
                "actor_system": "0e:00:00:00:00:02",
                "partner_system": FAUCET_MAC,
                "eth_dst": slow.SLOW_PROTOCOL_MULTICAST,
                "eth_src": "0e:00:00:00:00:02",
                "actor_state_synchronization": sync,
            },
        )


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


class ValvePortFloodDeletesTestCase(ValvePortDeletesTestBase):
    """Test faucet deletes no port specific flood flow it has not added."""

    def setUp(self):
        """Set up a DP whose ports flood as their VLANs do."""
        self.setup_valves(trunk_config())

    def test_port_down(self):
        """Test a trunk going down deletes no port specific flood flow."""
        self.assertFalse(self.port_flood_ports())
        self.assertFalse(self.port_flood_deletes(self.port_down(1)))
        flood_table = self.flood_table()
        self.assertEqual(flood_table, self.cold_flood_table(ports_up={2, 3}))
        self.assertFalse(self.port_flood_deletes(self.port_up(1)))
        self.assertFalse(self.port_flood_deletes(self.port_down(1)))
        self.assertEqual(flood_table, self.flood_table())

    def test_port_down_before_cold_start(self):
        """Test the switch gets every delete until faucet cold starts it."""
        self.valve().switch_manager.flood_flow_ports = None
        deletes = self.port_flood_deletes(self.port_down(1))
        self.assertEqual({2, 3}, {ofmsg.match["in_port"] for ofmsg in deletes})
        self.cold_flood_table()
        self.assertFalse(self.port_flood_deletes(self.port_down(1)))

    def test_warm_start(self):
        """Test a warm start keeps what the switch has for the next config."""
        flood_flows = self.valve().switch_manager.flood_flow_ports
        self.assertIsNotNone(flood_flows)
        self.update_config(trunk_config("v100, v200"), reload_type="warm")
        self.assertIs(flood_flows, self.valve().switch_manager.flood_flow_ports)
        self.assertFalse(self.port_flood_deletes(self.port_down(2)))
        self.assertEqual(self.flood_table(), self.cold_flood_table(ports_up={1, 3}))


class ValveRestrictedPortFloodDeletesTestCase(ValvePortDeletesTestBase):
    """Test faucet deletes the port specific flood flows it has added."""

    def setUp(self):
        """Set up a DP with ports that flood ARP and ND unlike their VLAN."""
        self.setup_valves(restricted_config(False))

    def test_port_down(self):
        """Test a port going down leaves the other ports' flood flows."""
        self.assertEqual({1, 2, 4}, self.port_flood_ports())
        flood_table = self.flood_table()
        self.assertFalse(self.port_flood_deletes(self.port_down(3)))
        self.assertFalse(self.port_flood_deletes(self.port_down(4)))
        self.assertEqual({1, 2, 4}, self.port_flood_ports())
        self.assertEqual(flood_table, self.flood_table())

    def test_warm_start_restricts_port(self):
        """Test a warm start deletes the flood flows of an unchanged port."""
        self.update_config(restricted_config(True), reload_type="warm")
        # p3 floods ARP and ND to p4 now, unlike v100.
        self.assertEqual({1, 2, 3, 4}, self.port_flood_ports())
        self.assertEqual(self.flood_table(), self.cold_flood_table())
        ofmsgs = self.update_config(restricted_config(False), reload_type="warm")[
            self.DP_ID
        ]
        self.assertIn(
            3, {ofmsg.match["in_port"] for ofmsg in self.port_flood_deletes(ofmsgs)}
        )
        self.assertEqual({1, 2, 4}, self.port_flood_ports())
        self.assertEqual(self.flood_table(), self.cold_flood_table())
        # Added since the cold start: deleted again too.
        self.update_config(restricted_config(True), reload_type="warm")
        self.update_config(restricted_config(False), reload_type="warm")
        self.assertEqual({1, 2, 4}, self.port_flood_ports())
        self.assertEqual(self.flood_table(), self.cold_flood_table())


class ValveLACPPortFloodDeletesTestCase(ValvePortDeletesTestBase):
    """Test the deletes of flood flows a warm start adds and deletes again."""

    def setUp(self):
        """Set up a DP with a LAG port and a hairpin port on v200, LAG up."""
        self.setup_valves(lacp_hairpin_config(False))
        self.lacp_up(1)

    def lacp_up(self, port_no):
        """Bring up LACP on port_no, and return the flow mods sent."""
        return self.rcv_lacp(port_no, 1)

    def vlan_port_flood_ports(self, vid):
        """Return the ports with a port specific flood flow on VLAN vid."""
        return {
            flow.match_values["in_port"].int
            for flow in self.table_flows("flood")
            if "in_port" in flow.match_values
            and flow.match_values["vlan_vid"].int == vid | ofp.OFPVID_PRESENT
        }

    def test_warm_start_changes_lag_and_hairpin(self):
        """Test p2's hairpin flood flows go once it is no longer hairpin.

        The warm start takes p1's LAG down first, which adds v200's flood
        flows for the previous config again, p2's hairpin ones among them,
        before it deletes v200 and adds it for the new one. A delete of a
        flow added in the same batch is not sent, so faucet must still
        delete p2's flows the next time it builds v200's flood flows, as p1
        coming up again does, although p2 has had none added since. This
        relies on the warm start adding p1's VLANs back as it takes the LAG
        down; ValveLAGSyncFloodDeletesTestCase does not.
        """
        self.assertEqual({2}, self.vlan_port_flood_ports(0x200))
        self.update_config(lacp_hairpin_config(True), reload_type="warm")
        self.lacp_up(1)
        self.assertEqual(set(), self.vlan_port_flood_ports(0x200))
        flood_table = self.flood_table()
        self.cold_flood_table()
        self.lacp_up(1)
        self.assertEqual(flood_table, self.flood_table())


class ValveLAGSyncFloodDeletesTestCase(ValvePortDeletesTestBase):
    """Test a LAG member's flood flows go as its LAG loses sync."""

    def test_lag_loses_sync_after_warm_start(self):
        """Test a port keeps every flood flow delete once it has had one.

        p4 coming up in the LAG gives p3 flood flows of its own, as p3 must
        not flood back to its LAG. After a warm start that changes v200's
        other ports, the members lose sync in turn, and faucet deletes p3's
        flood flows one flood destination at a time, so it must not forget
        p3 as it sends the first of those deletes.
        """
        self.setup_valves(lag_sync_config("v100, v200"))
        self.rcv_lacp(4, 1)
        self.update_config(lag_sync_config("v100"), reload_type="warm")
        self.rcv_lacp(3, 0)
        self.rcv_lacp(4, 0)
        flood_table = self.flood_table()
        self.assertEqual(flood_table, self.cold_flood_table())


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
