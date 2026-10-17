#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valve.py."""

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

from collections import namedtuple

import copy
import time
import unittest

from os_ken.lib import mac
from os_ken.lib.packet import slow
from os_ken.ofproto import ether
from os_ken.ofproto import ofproto_v1_3 as ofp
from os_ken.ofproto import ofproto_v1_3_parser as parser

from faucet import valve_of
from faucet import valve_packet
from faucet.config_parser_util import yaml_load, yaml_dump

from clib.valve_test_lib import (
    CONFIG,
    DP1_CONFIG,
    FAUCET_MAC,
    GROUP_DP1_CONFIG,
    IDLE_DP1_CONFIG,
    ValveTestBases,
)

from clib.fakeoftable import CONTROLLER_PORT


class ValveTestCase(
    ValveTestBases.ValveTestBig
):  # pylint: disable=too-few-public-methods
    """Run complete set of basic tests."""


class ValveFuzzTestCase(ValveTestBases.ValveTestNetwork):
    """Test unknown ports/VLANs."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_fuzz_vlan(self):
        """Test unknown VIDs/ports."""
        for _ in range(0, 3):
            for i in range(0, 64):
                self.rcv_packet(
                    1,
                    i,
                    {
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.P2_V200_MAC,
                        "ipv4_src": "10.0.0.2",
                        "ipv4_dst": "10.0.0.3",
                        "vid": i,
                    },
                )
            for i in range(0, 64):
                self.rcv_packet(
                    i,
                    0x100,
                    {
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.P2_V200_MAC,
                        "ipv4_src": "10.0.0.2",
                        "ipv4_dst": "10.0.0.3",
                        "vid": 0x100,
                    },
                )
        # pylint: disable=no-member
        # pylint: disable=no-value-for-parameter
        cache_info = valve_packet.parse_packet_in_pkt.cache_info()
        self.assertGreater(cache_info.hits, cache_info.misses, msg=cache_info)


class ValveCoprocessorTestCase(ValveTestBases.ValveTestNetwork):
    """Test direct packet output using coprocessor."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                coprocessor: {strategy: vlan_vid, vlan_vid_base: 0x200}
            p2:
                number: 2
                native_vlan: testvlan
            p3:
                number: 3
                native_vlan: testvlan
vlans:
    testvlan:
        vid: 0x100
        acls_in: [bypassedbycoprocessor]
acls:
    bypassedbycoprocessor:
        - rule:
            ipv4_src: 10.0.0.99
            dl_type: 0x0800
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic coprocessor config"""
        self.setup_valves(self.CONFIG)

    def test_output(self):
        # VID for direct output to port 2
        copro_vid_out = (0x200 + 2) | ofp.OFPVID_PRESENT
        direct_match = {
            "in_port": 1,
            "vlan_vid": copro_vid_out,
            "eth_type": ether.ETH_TYPE_IP,
            "eth_src": self.P1_V100_MAC,
            "eth_dst": mac.BROADCAST_STR,
        }
        table = self.network.tables[self.DP_ID]
        self.assertTrue(table.is_output(direct_match, port=2))
        p2_host_match = {
            "eth_src": self.P1_V100_MAC,
            "eth_dst": self.P2_V200_MAC,
            "ipv4_src": "10.0.0.2",
            "ipv4_dst": "10.0.0.3",
            "eth_type": ether.ETH_TYPE_IP,
        }
        p2_host_receive = copy.deepcopy(p2_host_match)
        p2_host_receive.update({"in_port": 2})
        # learn P2 host
        self.rcv_packet(2, 0x100, p2_host_receive)
        # copro can send to P2 via regular pipeline and is not subject to VLAN ACL.
        p2_copro_host_receive = copy.deepcopy(p2_host_match)
        p2_copro_host_receive.update(
            {
                "in_port": 1,
                "ipv4_src": "10.0.0.99",
                "ipv4_dst": "10.0.0.3",
                "eth_src": p2_host_match["eth_dst"],
                "eth_dst": p2_host_match["eth_src"],
            }
        )
        p2_copro_host_receive["vlan_vid"] = 0x100 | ofp.OFPVID_PRESENT
        self.assertTrue(table.is_output(p2_copro_host_receive, port=2, vid=0x100))
        # copro send to P2 was not flooded
        self.assertFalse(table.is_output(p2_copro_host_receive, port=3, vid=0x100))


class ValveRestBcastTestCase(ValveTestBases.ValveTestNetwork):
    """Test restricted broadcast."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                restricted_bcast_arpnd: true
            p2:
                number: 2
                native_vlan: 0x100
            p3:
                number: 3
                native_vlan: 0x100
                restricted_bcast_arpnd: true
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config with restricted broadcast enabled"""
        self.setup_valves(self.CONFIG)

    def test_rest_bcast(self):
        match = {
            "in_port": 1,
            "vlan_vid": 0,
            "eth_type": ether.ETH_TYPE_IP,
            "eth_src": self.P1_V100_MAC,
            "eth_dst": mac.BROADCAST_STR,
        }
        table = self.network.tables[self.DP_ID]
        self.assertTrue(table.is_output(match, port=2))
        self.assertFalse(table.is_output(match, port=3))
        match = {
            "in_port": 2,
            "vlan_vid": 0,
            "eth_type": ether.ETH_TYPE_IP,
            "eth_src": self.P1_V100_MAC,
            "eth_dst": mac.BROADCAST_STR,
        }
        self.assertTrue(table.is_output(match, port=1))
        self.assertTrue(table.is_output(match, port=3))


class ValveUnusedMeterTestCase(ValveTestBases.ValveTestNetwork):
    """Test unused meters are not configured."""

    CONFIG = (
        """
meters:
    unusedmeter:
        meter_id: 1
        entry:
            flags: "KBPS"
            bands:
                [
                    {
                        type: "DROP",
                        rate: 1
                    }
                ]
    usedmeter:
        meter_id: 2
        entry:
            flags: "KBPS"
            bands:
                [
                    {
                        type: "DROP",
                        rate: 2
                    }
                ]
acls:
    meteracl:
        - rule:
            actions:
                meter: usedmeter
                allow: 1
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acls_in: [meteracl]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup meter and ACL config"""
        self.setup_valves(self.CONFIG)

    def test_usedmeter(self):
        valve = self.valves_manager.valves[self.DP_ID]
        self.assertEqual(["usedmeter"], list(valve.dp.meters.keys()))


class ValveOFErrorTestCase(ValveTestBases.ValveTestNetwork):
    """Test decoding of OFErrors."""

    def setUp(self):
        self.setup_valves(CONFIG)

    def test_oferror_parser(self):
        """Test OF error parser works"""
        for type_code, error_tuple in valve_of.OFERROR_TYPE_CODE.items():
            self.assertTrue(isinstance(type_code, int))
            type_str, error_codes = error_tuple
            self.assertTrue(isinstance(type_str, str))
            for error_code, error_str in error_codes.items():
                self.assertTrue(isinstance(error_code, int))
                self.assertTrue(isinstance(error_str, str))
        test_err = parser.OFPErrorMsg(
            datapath=None, type_=ofp.OFPET_FLOW_MOD_FAILED, code=ofp.OFPFMFC_UNKNOWN
        )
        valve = self.valves_manager.valves[self.DP_ID]
        valve.oferror(test_err)
        test_unknown_type_err = parser.OFPErrorMsg(
            datapath=None, type_=666, code=ofp.OFPFMFC_UNKNOWN
        )
        valve.oferror(test_unknown_type_err)
        test_unknown_code_err = parser.OFPErrorMsg(
            datapath=None, type_=ofp.OFPET_FLOW_MOD_FAILED, code=666
        )
        valve.oferror(test_unknown_code_err)


class ValveGroupTestCase(ValveTestBases.ValveTestNetwork):
    """Tests for datapath with group support."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
"""
        % GROUP_DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_unknown_eth_dst_rule(self):
        """Test that packets with unkown eth dst addrs get flooded correctly.

        They must be output to each port on the associated vlan, with the
        correct vlan tagging. And they must not be forwarded to a port not
        on the associated vlan
        """
        self.learn_hosts()
        matches = [
            {
                "in_port": 3,
                "vlan_vid": self.V100,
            },
            {"in_port": 2, "vlan_vid": 0, "eth_dst": self.P1_V100_MAC},
            {"in_port": 1, "vlan_vid": 0, "eth_src": self.P1_V100_MAC},
            {
                "in_port": 3,
                "vlan_vid": self.V200,
                "eth_src": self.P2_V200_MAC,
            },
        ]
        self.verify_flooding(matches)


class ValveIdleLearnTestCase(ValveTestBases.ValveTestNetwork):
    """Smoke test for idle-flow based learning. This feature is not currently reliable."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                output_only: True
                mirror: 4
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
"""
        % IDLE_DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config with mirroring"""
        self.setup_valves(self.CONFIG)

    def test_known_eth_src_rule(self):
        """Test removal flow handlers."""
        self.learn_hosts()
        valve = self.valves_manager.valves[self.DP_ID]
        self.assertTrue(
            valve.flow_timeout(
                self.mock_time(300),
                valve.dp.tables["eth_dst"].table_id,
                {"vlan_vid": self.V100, "eth_dst": self.P1_V100_MAC},
            )
        )
        self.assertFalse(
            valve.flow_timeout(
                self.mock_time(300),
                valve.dp.tables["eth_src"].table_id,
                {"vlan_vid": self.V100, "in_port": 1, "eth_src": self.P1_V100_MAC},
            )
        )

    def test_host_learn_coldstart(self):
        """Test flow learning, including cold-start cache invalidation"""
        valve = self.valves_manager.valves[self.DP_ID]
        match = {
            "in_port": 3,
            "vlan_vid": self.V100,
            "eth_type": ether.ETH_TYPE_IP,
            "eth_src": self.P3_V100_MAC,
            "eth_dst": self.P1_V100_MAC,
        }
        table = self.network.tables[self.DP_ID]
        self.assertTrue(table.is_output(match, port=1))
        self.assertTrue(table.is_output(match, port=2))
        self.assertTrue(table.is_output(match, port=CONTROLLER_PORT))
        self.learn_hosts()
        self.assertTrue(table.is_output(match, port=1))
        self.assertFalse(table.is_output(match, port=2))
        self.assertFalse(table.is_output(match, port=CONTROLLER_PORT))
        self.cold_start()
        self.assertTrue(table.is_output(match, port=1))
        self.assertTrue(table.is_output(match, port=2))
        self.assertTrue(table.is_output(match, port=CONTROLLER_PORT))
        self.mock_time(valve.dp.timeout // 4 * 3)
        self.learn_hosts()
        self.assertTrue(table.is_output(match, port=1))
        self.assertFalse(table.is_output(match, port=2))
        self.assertFalse(table.is_output(match, port=CONTROLLER_PORT))


class ValveLACPTestCase(ValveTestBases.ValveTestNetwork):
    """Test LACP."""

    CONFIG = (
        """
dps:
    s1:
%s
        lacp_timeout: 5
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                lacp: 1
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                tagged_vlans: [v300]
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
    v300:
        vid: 0x300
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup lacp config and activate ports"""
        self.setup_valves(self.CONFIG)
        self.activate_all_ports()

    def test_lacp(self):
        """Test LACP comes up."""
        test_port = 1
        labels = self.port_labels(test_port)
        valve = self.valves_manager.valves[self.DP_ID]
        self.assertEqual(1, int(self.get_prom("port_lacp_state", labels=labels)))
        self.assertFalse(valve.dp.ports[1].non_stack_forwarding())
        self.rcv_packet(
            test_port,
            0,
            {
                "actor_system": "0e:00:00:00:00:02",
                "partner_system": FAUCET_MAC,
                "eth_dst": slow.SLOW_PROTOCOL_MULTICAST,
                "eth_src": "0e:00:00:00:00:02",
                "actor_state_synchronization": 1,
            },
        )
        self.assertEqual(3, int(self.get_prom("port_lacp_state", labels=labels)))
        self.assertTrue(valve.dp.ports[1].non_stack_forwarding())
        self.learn_hosts()
        self.verify_expiry()

    def test_lacp_flap(self):
        """Test LACP handles state 0->1->0."""
        valve = self.valves_manager.valves[self.DP_ID]
        test_port = 1
        labels = self.port_labels(test_port)
        self.assertEqual(1, int(self.get_prom("port_lacp_state", labels=labels)))
        self.assertFalse(valve.dp.ports[1].non_stack_forwarding())
        self.rcv_packet(
            test_port,
            0,
            {
                "actor_system": "0e:00:00:00:00:02",
                "partner_system": FAUCET_MAC,
                "eth_dst": slow.SLOW_PROTOCOL_MULTICAST,
                "eth_src": "0e:00:00:00:00:02",
                "actor_state_synchronization": 1,
            },
        )
        self.assertEqual(3, int(self.get_prom("port_lacp_state", labels=labels)))
        self.assertTrue(valve.dp.ports[1].non_stack_forwarding())
        self.learn_hosts()
        self.verify_expiry()
        self.rcv_packet(
            test_port,
            0,
            {
                "actor_system": "0e:00:00:00:00:02",
                "partner_system": FAUCET_MAC,
                "eth_dst": slow.SLOW_PROTOCOL_MULTICAST,
                "eth_src": "0e:00:00:00:00:02",
                "actor_state_synchronization": 0,
            },
        )
        self.assertEqual(5, int(self.get_prom("port_lacp_state", labels=labels)))
        self.assertFalse(valve.dp.ports[1].non_stack_forwarding())
        self.assertEqual(
            4, int(self.get_prom("port_lacp_state_change_count_total", labels=labels))
        )

    def test_lacp_timeout(self):
        """Test LACP comes up and then times out."""
        valve = self.valves_manager.valves[self.DP_ID]
        test_port = 1
        labels = self.port_labels(test_port)
        self.assertEqual(1, int(self.get_prom("port_lacp_state", labels=labels)))
        self.assertFalse(valve.dp.ports[1].non_stack_forwarding())
        self.rcv_packet(
            test_port,
            0,
            {
                "actor_system": "0e:00:00:00:00:02",
                "partner_system": FAUCET_MAC,
                "eth_dst": slow.SLOW_PROTOCOL_MULTICAST,
                "eth_src": "0e:00:00:00:00:02",
                "actor_state_synchronization": 1,
            },
        )
        self.assertEqual(3, int(self.get_prom("port_lacp_state", labels=labels)))
        self.assertTrue(valve.dp.ports[1].non_stack_forwarding())
        future_now = self.mock_time(10)
        expire_ofmsgs = valve.state_expire(future_now, None)
        self.assertTrue(expire_ofmsgs)
        self.assertEqual(1, int(self.get_prom("port_lacp_state", labels=labels)))
        self.assertFalse(valve.dp.ports[1].non_stack_forwarding())

    def test_dp_disconnect(self):
        """Test LACP state when disconnects."""
        test_port = 1
        labels = self.port_labels(test_port)
        self.assertEqual(1, int(self.get_prom("port_lacp_state", labels=labels)))
        self.rcv_packet(
            test_port,
            0,
            {
                "actor_system": "0e:00:00:00:00:02",
                "partner_system": FAUCET_MAC,
                "eth_dst": slow.SLOW_PROTOCOL_MULTICAST,
                "eth_src": "0e:00:00:00:00:02",
                "actor_state_synchronization": 1,
            },
        )
        self.assertEqual(3, int(self.get_prom("port_lacp_state", labels=labels)))
        self.disconnect_dp()
        self.assertEqual(0, int(self.get_prom("port_lacp_state", labels=labels)))


class ValveTFMSizeOverride(ValveTestBases.ValveTestNetwork):
    """Test TFM size override."""

    CONFIG = (
        """
dps:
    s1:
%s
        table_sizes:
            eth_src: 999
        interfaces:
            p1:
                number: 1
                native_vlan: v100
vlans:
    v100:
        vid: 0x100
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config with overriden TFM sizing"""
        self.setup_valves(self.CONFIG)

    def test_size(self):
        table = self.network.tables[self.DP_ID]
        tfm_by_name = {body.name: body for body in table.tfm.values()}
        eth_src_table = tfm_by_name.get(b"eth_src", None)
        self.assertTrue(eth_src_table)
        if eth_src_table is not None:
            self.assertEqual(999, eth_src_table.max_entries)


class ValveTFMSize(ValveTestBases.ValveTestNetwork):
    """Test TFM sizer."""

    NUM_PORTS = 128

    CONFIG = (
        """
dps:
    s1:
%s
        lacp_timeout: 5
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                lacp: 1
                lacp_active: True
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                tagged_vlans: [v300]
        interface_ranges:
            6-128:
                native_vlan: v100
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
    v300:
        vid: 0x300
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_size(self):
        table = self.network.tables[self.DP_ID]
        tfm_by_name = {body.name: body for body in table.tfm.values()}
        flood_table = tfm_by_name.get(b"flood", None)
        self.assertTrue(flood_table)
        if flood_table is not None:
            self.assertGreater(flood_table.max_entries, self.NUM_PORTS * 2)


class ValveActiveLACPTestCase(ValveTestBases.ValveTestNetwork):
    """Test LACP."""

    CONFIG = (
        """
dps:
    s1:
%s
        lacp_timeout: 5
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                lacp: 1
                lacp_active: True
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                tagged_vlans: [v300]
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
    v300:
        vid: 0x300
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic lacp config and activate ports"""
        self.setup_valves(self.CONFIG)
        self.activate_all_ports()

    def test_lacp(self):
        """Test LACP comes up."""
        test_port = 1
        labels = self.port_labels(test_port)
        self.assertEqual(1, int(self.get_prom("port_lacp_state", labels=labels)))
        # Ensure LACP packet sent.
        valve = self.valves_manager.valves[self.DP_ID]
        ofmsgs = valve.fast_advertise(self.mock_time(), None)[valve]
        self.assertTrue(ValveTestBases.packet_outs_from_flows(ofmsgs))
        self.rcv_packet(
            test_port,
            0,
            {
                "actor_system": "0e:00:00:00:00:02",
                "partner_system": FAUCET_MAC,
                "eth_dst": slow.SLOW_PROTOCOL_MULTICAST,
                "eth_src": "0e:00:00:00:00:02",
                "actor_state_synchronization": 1,
            },
        )
        self.assertEqual(3, int(self.get_prom("port_lacp_state", labels=labels)))
        self.learn_hosts()
        self.verify_expiry()


class ValveL2LearnTestCase(ValveTestBases.ValveTestNetwork):
    """Test L2 Learning"""

    def setUp(self):
        self.setup_valves(CONFIG)

    def test_expiry(self):
        learn_labels = {"vid": str(0x200), "eth_src": self.P2_V200_MAC}
        self.assertEqual(0, self.get_prom("learned_l2_port", labels=learn_labels))
        self.learn_hosts()
        self.assertEqual(2.0, self.get_prom("learned_l2_port", labels=learn_labels))
        self.verify_expiry()
        self.assertEqual(0, self.get_prom("learned_l2_port", labels=learn_labels))


class SoftPipelineTestCase(ValveTestBases.ValveTestNetwork):
    """Test warm starting match changes with soft pipeline."""

    REQUIRE_TFM = False

    CONFIG = """
acls:
    acl1:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            actions:
                allow: 0
    acl2:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            ip_proto: 6
            actions:
                allow: 0
dps:
    s1:
        hardware: Open vSwitch
        dp_id: 0x1
        interfaces:
            p1:
                number: 1
                native_vlan: 100
                acls_in: [acl1]
"""

    def setUp(self):
        """Setup basic port and vlan config with ACLs"""
        self.setup_valves(self.CONFIG)

    def test_soft(self):
        config = yaml_load(self.CONFIG)
        config["dps"]["s1"]["interfaces"]["p1"]["acls_in"] = ["acl2"]
        # We changed match conditions only, so this can be a warm start.
        self.update_config(yaml_dump(config), reload_type="warm")


class HardPipelineTestCase(ValveTestBases.ValveTestNetwork):
    """Test cold starting match conditions with hard pipeline."""

    CONFIG = """
acls:
    acl1:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            actions:
                allow: 0
    acl2:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            ip_proto: 6
            actions:
                allow: 0
dps:
    s1:
        hardware: GenericTFM
        dp_id: 0x1
        interfaces:
            p1:
                number: 1
                native_vlan: 100
                acls_in: [acl1]
"""

    def setUp(self):
        """Setup basic port and vlan config with ACLs"""
        self.setup_valves(self.CONFIG)

    def test_hard(self):
        config = yaml_load(self.CONFIG)
        config["dps"]["s1"]["interfaces"]["p1"]["acls_in"] = ["acl2"]
        # Changed match conditions require restart.
        self.update_config(yaml_dump(config), reload_type="cold")


class ValveMirrorTestCase(ValveTestBases.ValveTestBig):
    """Test ACL and interface mirroring."""

    # TODO: check mirror packets are present/correct

    CONFIG = (
        """
acls:
    mirror_ospf:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            actions:
                mirror: p5
                allow: 1
        - rule:
            dl_type: 0x800
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                lldp_beacon:
                    enable: True
                    system_name: "faucet"
                    port_descr: "first_port"
                acls_in: [mirror_ospf]
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                output_only: True
                mirror: 4
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
        routes:
            - route:
                ip_dst: 10.99.99.0/24
                ip_gw: 10.0.0.1
            - route:
                ip_dst: 10.99.98.0/24
                ip_gw: 10.0.0.99
    v200:
        vid: 0x200
        faucet_vips: ['fc00::1:254/112', 'fe80::1:254/64']
        routes:
            - route:
                ip_dst: 'fc00::10:0/112'
                ip_gw: 'fc00::1:1'
            - route:
                ip_dst: 'fc00::20:0/112'
                ip_gw: 'fc00::1:99'
routers:
    router1:
        bgp:
            as: 1
            connect_mode: 'passive'
            neighbor_as: 2
            port: 9179
            routerid: '1.1.1.1'
            server_addresses: ['127.0.0.1']
            neighbor_addresses: ['127.0.0.1']
            vlan: v100
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup complex config with routing, bgp, mirroring and ACLs"""
        self.setup_valves(self.CONFIG)

    def test_unmirror(self):
        config = yaml_load(self.CONFIG)
        del config["dps"]["s1"]["interfaces"]["p5"]["mirror"]
        self.update_config(yaml_dump(config), reload_type="warm")


class ValvePortDescTestCase(ValveTestBases.ValveTestNetwork):
    """Test OFPMP_PORT_DESC reply handling."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v100
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup simple configuration with no ports up"""
        ofmsgs = self.setup_valves(self.CONFIG, ports_up=[])[self.DP_ID]
        self.valve = self.valves_manager.valves[self.DP_ID]

        self.assertFalse(ofmsgs)
        self.assertFalse(self.valve.dp.dyn_up_port_nos)

    @staticmethod
    def _inport_flows(in_port, ofmsgs, table_id=0):
        return [
            ofmsg
            for ofmsg in ValveTestBases.flowmods_from_flows(ofmsgs)
            if ofmsg.match.get("in_port") == in_port and ofmsg.table_id == table_id
        ]

    @staticmethod
    def _build_port_descs(port_nos, port_nos_up=None):
        descs = []
        for port_no in port_nos:
            desc = namedtuple("port_no", "state")
            desc.port_no = port_no
            desc.state = 0 if port_no in port_nos_up else valve_of.ofp.OFPPS_LINK_DOWN
            descs.append(desc)
        return descs

    def _update_port_desc(self, port_nos, port_nos_up=None):
        descs = self._build_port_descs(port_nos, port_nos_up)
        ofmsgs_by_valve = self.valve.port_desc_stats_reply_handler(
            descs, [], time.time()
        )
        return ofmsgs_by_valve[self.valve]

    def test_unconfigured_ports(self):
        port_nos = [11, 12]
        port_nos_up = [12]
        ofmsgs = self._update_port_desc(port_nos, port_nos_up)

        self.assertTrue(self.valve.dp.dyn_up_port_nos == set(port_nos_up))
        self.assertFalse(ofmsgs)

    def test_configured_ports(self):
        # Note: the _inport_flows() asserts track 'delta's based on
        #  port changes, not the absolute port state

        # Start with a selection of ports
        port_nos = [1, 2]
        port_nos_up = [1]
        ofmsgs = self._update_port_desc(port_nos, port_nos_up)

        self.assertTrue(self.valve.dp.dyn_up_port_nos == set(port_nos_up))
        self.assertTrue(ofmsgs)
        self.assertTrue(self._inport_flows(1, ofmsgs))
        self.assertFalse(self._inport_flows(2, ofmsgs))

        # Take port2 link-up
        port_nos_up = [1, 2]
        ofmsgs = self._update_port_desc(port_nos, port_nos_up)

        self.assertTrue(self.valve.dp.dyn_up_port_nos == set(port_nos_up))
        self.assertTrue(ofmsgs)
        self.assertFalse(self._inport_flows(1, ofmsgs))
        self.assertTrue(self._inport_flows(2, ofmsgs))

        # Take port1 link-down
        port_nos_up = [2]
        ofmsgs = self._update_port_desc(port_nos, port_nos_up)

        self.assertTrue(self.valve.dp.dyn_up_port_nos == set(port_nos_up))
        self.assertTrue(ofmsgs)
        self.assertTrue(self._inport_flows(1, ofmsgs))
        self.assertFalse(self._inport_flows(2, ofmsgs))

        # Take port1 link-up and remove port2
        port_nos = [1]
        port_nos_up = [1]
        ofmsgs = self._update_port_desc(port_nos, port_nos_up)

        self.assertTrue(self.valve.dp.dyn_up_port_nos == set(port_nos_up))
        self.assertTrue(ofmsgs)
        self.assertTrue(self._inport_flows(1, ofmsgs))
        self.assertTrue(self._inport_flows(2, ofmsgs))


class ValveAtomicColdStartTestCase(ValveTestBases.ValveTestNetwork):
    """Test a cold start replacing the flows in one atomic bundle."""

    REQUIRE_TFM = False

    CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: "Open vSwitch"
        atomic_cold_start: true
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v100
vlans:
    v100:
        vid: 0x100
        faucet_vips: ["10.0.0.254/24"]
"""

    class FakeDatapath:
        """Record what faucet sends, numbering messages as the switch would."""

        ofproto = ofp
        ofproto_parser = parser

        def __init__(self):
            self.sent = []
            self.closed = False
            self.xid = 0

        def send_msg(self, msg):
            """Record msg with its own xid."""
            if msg.xid is None:
                self.xid += 1
                msg.set_xid(self.xid)
            msg.serialize()
            self.sent.append(msg)

        def close(self):
            """Record a close."""
            self.closed = True

    def setUp(self):
        """Setup a routed VLAN."""
        self.setup_valves(self.CONFIG)
        self.valve = self.valves_manager.valves[self.DP_ID]

    @staticmethod
    def _global_deletes(ofmsgs):
        return [ofmsg for ofmsg in ofmsgs if valve_of.is_global_flowdel(ofmsg)]

    def _cold_start(self, disconnect=True):
        """Connect the DP again, and return what faucet sends the switch."""
        ryu_dp = self.FakeDatapath()
        if disconnect:
            self.valve.datapath_disconnect(self.mock_time())
        features = self.valve.switch_features(None)
        ofmsgs = self.valve.datapath_connect(self.mock_time(), {1, 2})
        self.valve.send_flows(ryu_dp, ofmsgs, self.mock_time())
        return features, ryu_dp

    @staticmethod
    def _bundle(ryu_dp):
        """Return the bundle messages sent to ryu_dp."""
        return [
            ofmsg
            for ofmsg in ryu_dp.sent
            if isinstance(ofmsg, (parser.ONFBundleCtrlMsg, parser.ONFBundleAddMsg))
        ]

    def _commit_reply(self, ryu_dp, xid=None):
        """Return the switch's reply to the commit of the bundle sent to ryu_dp."""
        commit = self._bundle(ryu_dp)[-1]
        reply = parser.ONFBundleCtrlMsg(
            None, commit.bundle_id, ofp.ONF_BCT_COMMIT_REPLY, 0, []
        )
        reply.xid = commit.xid if xid is None else xid
        return reply

    def _bundle_counts(self):
        """Return the bundles sent, committed, refused and lost."""
        return tuple(
            int(self.get_prom("faucet_cold_start_bundles%s_total" % outcome))
            for outcome in ("", "_committed", "_refused", "_lost")
        )

    def _atomic_status(self):
        return int(self.get_prom("dp_atomic_cold_start"))

    def test_bundle_ofmsgs(self):
        """Test flow mods go in one bundle, in order, and the rest around it."""
        flowdel = self.valve._delete_all_valve_flows()[0]
        config = valve_of.faucet_config()
        async_config = valve_of.faucet_async()
        packetout = valve_of.packetout(1, bytes(64))
        ofmsgs = self.valve.dp.tables["vlan"].flowdrop(priority=1)
        bundled = valve_of.bundle_ofmsgs(
            [config, flowdel, valve_of.barrier(), ofmsgs, async_config, packetout], 7
        )
        kinds = [type(ofmsg).__name__ for ofmsg in bundled]
        self.assertEqual(
            kinds,
            [
                "OFPSetConfig",
                "ONFBundleCtrlMsg",
                "ONFBundleAddMsg",
                "ONFBundleAddMsg",
                "ONFBundleCtrlMsg",
                "OFPBarrierRequest",
                "OFPSetAsync",
                "OFPPacketOut",
            ],
        )
        self.assertEqual(bundled[1].type, ofp.ONF_BCT_OPEN_REQUEST)
        self.assertEqual(bundled[4].type, ofp.ONF_BCT_COMMIT_REQUEST)
        self.assertEqual(
            [ofmsg.message.command for ofmsg in bundled[2:4]],
            [ofp.OFPFC_DELETE, ofp.OFPFC_ADD],
        )
        for ofmsg in bundled[1:5]:
            self.assertEqual(ofmsg.bundle_id, 7)
            self.assertEqual(ofmsg.flags, ofp.ONF_BF_ATOMIC | ofp.ONF_BF_ORDERED)
        self.assertIsNone(
            valve_of.bundle_ofmsgs([flowdel, self.valve.dp.groups.delete_all()], 7)
        )
        self.assertIsNone(valve_of.bundle_ofmsgs([config, packetout], 7))

    def test_cold_start_in_one_bundle(self):
        """Test connecting keeps the flows and replaces them in one bundle."""
        features, ryu_dp = self._cold_start()
        self.assertFalse(self._global_deletes(features), "flows deleted on connect")
        kinds = [type(ofmsg).__name__ for ofmsg in ryu_dp.sent]
        open_index = kinds.index("ONFBundleCtrlMsg")
        commit_index = len(kinds) - 1 - kinds[::-1].index("ONFBundleCtrlMsg")
        self.assertEqual(ryu_dp.sent[open_index].type, ofp.ONF_BCT_OPEN_REQUEST)
        self.assertEqual(ryu_dp.sent[commit_index].type, ofp.ONF_BCT_COMMIT_REQUEST)
        inside = ryu_dp.sent[open_index + 1 : commit_index]
        self.assertTrue(inside)
        self.assertTrue(
            all(
                kind == "ONFBundleAddMsg"
                for kind in kinds[open_index + 1 : commit_index]
            )
        )
        self.assertTrue(
            valve_of.is_global_flowdel(inside[0].message),
            "bundle does not start with the delete",
        )
        self.assertFalse(
            any(valve_of.is_flowmod(ofmsg) for ofmsg in ryu_dp.sent),
            "flow mod outside the bundle",
        )
        async_index = kinds.index("OFPSetAsync")
        self.assertGreater(
            async_index, commit_index, "packet ins asked for before the commit"
        )
        self.assertTrue(
            all(ofmsg.xid == ofmsg.message.xid for ofmsg in inside),
            "inner xid not the outer xid",
        )
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        self.assertEqual(1, self._atomic_status())

    def test_committed_bundle(self):
        """Test the switch committing the bundle is counted once."""
        _, ryu_dp = self._cold_start()
        bundle = self._bundle(ryu_dp)
        open_reply = parser.ONFBundleCtrlMsg(
            None, bundle[0].bundle_id, ofp.ONF_BCT_OPEN_REPLY, 0, []
        )
        open_reply.xid = bundle[0].xid
        for reply in (open_reply, self._commit_reply(ryu_dp, xid=bundle[-1].xid + 1)):
            self.valve.bundle_ctrl_reply(reply)
            self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        self.valve.bundle_ctrl_reply(self._commit_reply(ryu_dp))
        self.valve.bundle_ctrl_reply(self._commit_reply(ryu_dp))
        self.valve.datapath_disconnect(self.mock_time())
        self.assertEqual((1, 1, 0, 0), self._bundle_counts())
        self.assertEqual(1, self._atomic_status())

    def test_refused_bundle(self):
        """Test a refused bundle reconnects, to cold start without one."""
        error = parser.OFPErrorMsg(
            None, type_=ofp.OFPET_BAD_INSTRUCTION, code=ofp.OFPBIC_BAD_TABLE_ID
        )
        # With no bundle in flight, an error without an xid is only an error.
        self.assertFalse(self.valve.oferror(error))
        _, ryu_dp = self._cold_start()
        bundle = self._bundle(ryu_dp)
        of_errors = self.get_prom("of_errors_total")
        # A flow mod the switch cannot apply has an error of its own, and
        # the switch still commits the rest of the bundle.
        error.xid = bundle[1].xid
        self.assertFalse(self.valve.oferror(error))
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        self.assertEqual(1, self._atomic_status())
        # Failing the commit, it applies none of the bundle.
        error = parser.OFPErrorMsg(
            None, type_=ofp.OFPET_EXPERIMENTER, exp_type=2313, experimenter=0x4F4E4600
        )
        error.xid = bundle[-1].xid
        self.assertTrue(self.valve.oferror(error))
        self.assertEqual((1, 0, 1, 0), self._bundle_counts())
        self.assertEqual(0, self._atomic_status())
        self.assertEqual(of_errors + 2, self.get_prom("of_errors_total"))
        self.assertFalse(self.valve.oferror(error), "refused twice")
        features, ryu_dp = self._cold_start()
        self.assertTrue(self._global_deletes(features), "no delete once refused")
        self.assertFalse(self._bundle(ryu_dp), "bundled again once refused")
        self.assertEqual((1, 0, 1, 0), self._bundle_counts())

    def test_lost_bundles(self):
        """Test bundles lost in a row to disconnections stop bundling."""
        max_lost = self.valve.ATOMIC_COLD_START_MAX_LOST
        for _ in range(max_lost):
            _, ryu_dp = self._cold_start()
        # A commit starts the count of bundles lost in a row again.
        self.valve.bundle_ctrl_reply(self._commit_reply(ryu_dp))
        self.assertEqual((max_lost, 1, 0, max_lost - 1), self._bundle_counts())
        for _ in range(max_lost):
            _, ryu_dp = self._cold_start()
            self.assertTrue(self._bundle(ryu_dp), "stopped bundling too soon")
        self.assertEqual(1, self._atomic_status())
        features, ryu_dp = self._cold_start()
        self.assertTrue(self._global_deletes(features), "no delete once lost")
        self.assertFalse(self._bundle(ryu_dp), "bundled again once lost")
        self.assertEqual((2 * max_lost, 1, 0, 2 * max_lost - 1), self._bundle_counts())
        self.assertEqual(0, self._atomic_status())

    def test_reconnect_loses_bundle(self):
        """Test a reconnection with no disconnection loses an open bundle."""
        _, ryu_dp = self._cold_start()
        self.valve.switch_features(None)
        self.assertEqual((1, 0, 0, 1), self._bundle_counts())
        # A late answer to the lost bundle's commit is not counted.
        self.valve.bundle_ctrl_reply(self._commit_reply(ryu_dp))
        error = parser.OFPErrorMsg(
            None, type_=ofp.OFPET_EXPERIMENTER, exp_type=2313, experimenter=0x4F4E4600
        )
        error.xid = self._bundle(ryu_dp)[-1].xid
        self.assertFalse(self.valve.oferror(error))
        self.assertEqual((1, 0, 0, 1), self._bundle_counts())

    def _cold_start_on(self, ryu_dp):
        """Cold start the DP on connection ryu_dp, with no switch features."""
        ofmsgs = self.valve.datapath_connect(self.mock_time(), {1, 2}, ryu_dp)
        self.valve.send_flows(ryu_dp, ofmsgs, self.mock_time())
        return self._bundle(ryu_dp)

    def test_replaced_connection_loses_bundle(self):
        """Test a cold start on a new connection loses the old one's bundle.

        A switch that connects again before its old connection is seen to end
        has that connection replaced with no disconnection, so faucet can
        send a cold start on the old connection after the new one's switch
        features, and then cold start the new one.
        """
        self.valve.datapath_disconnect(self.mock_time())
        old_dp = self.FakeDatapath()
        new_dp = self.FakeDatapath()
        # Each connection numbers its messages from its own random xid.
        new_dp.xid = 1000
        self.valve.switch_features(None)
        self.valve.switch_features(None)
        self.assertTrue(self._cold_start_on(old_dp))
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        self.assertTrue(self._cold_start_on(new_dp), "new connection not bundled")
        self.assertEqual((2, 0, 0, 1), self._bundle_counts())
        # More sent on the connection the bundle went on loses nothing.
        self.valve.send_flows(new_dp, [valve_of.barrier()], self.mock_time())
        self.assertEqual((2, 0, 0, 1), self._bundle_counts())
        # A late answer on the old connection is not counted; the new one's is.
        self.valve.bundle_ctrl_reply(self._commit_reply(old_dp))
        self.assertEqual((2, 0, 0, 1), self._bundle_counts())
        self.valve.bundle_ctrl_reply(self._commit_reply(new_dp))
        self.assertEqual((2, 1, 0, 1), self._bundle_counts())
        self.assertEqual(1, self._atomic_status())

    def test_replaced_connection_commits_before_cold_start(self):
        """Test a bundle a replaced connection commits before the cold start counts.

        os_ken sends on the new connection once it has registered it, before
        faucet cold starts it, and still passes on what the old connection
        received before os_ken closed it.
        """
        self.valve.datapath_disconnect(self.mock_time())
        old_dp = self.FakeDatapath()
        new_dp = self.FakeDatapath()
        new_dp.xid = 1000
        self.valve.switch_features(None)
        self.valve.switch_features(None)
        self.assertTrue(self._cold_start_on(old_dp))
        flowmods = [self.valve.dp.tables["vlan"].flowdrop(priority=1)]
        self.valve.send_flows(new_dp, flowmods, self.mock_time())
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        self.valve.bundle_ctrl_reply(self._commit_reply(old_dp))
        self.assertEqual((1, 1, 0, 0), self._bundle_counts())
        self.assertTrue(self._cold_start_on(new_dp), "new connection not bundled")
        self.assertEqual((2, 1, 0, 0), self._bundle_counts())

    def test_replaced_connections_lose_bundles(self):
        """Test bundles lost in a row to replaced connections stop bundling."""
        max_lost = self.valve.ATOMIC_COLD_START_MAX_LOST
        for lost in range(max_lost):
            self.assertTrue(self._cold_start_on(self.FakeDatapath()))
            self.assertEqual((lost + 1, 0, 0, lost), self._bundle_counts())
            self.assertEqual(1, self._atomic_status())
        ryu_dp = self.FakeDatapath()
        self.assertFalse(self._cold_start_on(ryu_dp), "bundled again once lost")
        self.assertTrue(self._global_deletes(ryu_dp.sent), "flows not deleted")
        self.assertEqual((max_lost, 0, 0, max_lost), self._bundle_counts())
        self.assertEqual(0, self._atomic_status())

    def test_cold_start_not_sent(self):
        """Test a cold start never sent bundles nothing sent later."""
        flowmods = [self.valve.dp.tables["vlan"].flowdrop(priority=1)]
        for disconnect in (True, False):
            self.valve.switch_features(None)
            self.valve.datapath_connect(self.mock_time(), {1, 2})
            # The DP went before the cold start was sent.
            if disconnect:
                self.valve.datapath_disconnect(self.mock_time())
            else:
                self.valve.switch_features(None)
            ryu_dp = self.FakeDatapath()
            self.valve.send_flows(ryu_dp, flowmods, self.mock_time())
            self.assertFalse(self._bundle(ryu_dp), "bundled a later send")
        self.assertEqual((0, 0, 0, 0), self._bundle_counts())

    def test_toggle_without_cold_start(self):
        """Test changing atomic_cold_start applies from the next cold start."""
        warm = self.get_prom("faucet_config_reload_warm_total")
        for atomic in (False, True):
            self.update_config(
                self.CONFIG.replace(
                    "atomic_cold_start: true", "atomic_cold_start: %s" % atomic
                ),
                reload_expected=False,
            )
            self.assertEqual(warm, self.get_prom("faucet_config_reload_warm_total"))
            self.assertEqual(int(atomic), self._atomic_status())
            features, ryu_dp = self._cold_start()
            self.assertNotEqual(atomic, bool(self._global_deletes(features)))
            self.assertEqual(atomic, bool(self._bundle(ryu_dp)))

    def test_cold_start_with_groups(self):
        """Test a cold start with group changes still deletes, without a bundle."""
        self.update_config(
            self.CONFIG.replace(
                "atomic_cold_start: true",
                "atomic_cold_start: true\n        group_table: true",
            ),
        )
        features, ryu_dp = self._cold_start()
        self.assertFalse(self._global_deletes(features), "flows deleted on connect")
        self.assertFalse(self._bundle(ryu_dp), "group changes bundled")
        self.assertTrue(self._global_deletes(ryu_dp.sent), "flows not deleted")
        self.assertTrue(any(valve_of.is_groupdel(ofmsg) for ofmsg in ryu_dp.sent))
        self.assertEqual((0, 0, 0, 0), self._bundle_counts())

    def test_atomic_cold_start_hardware(self):
        """Test atomic_cold_start is refused on hardware without bundles."""
        self.update_config(
            self.CONFIG.replace('"Open vSwitch"', '"GenericTFM"'),
            reload_expected=False,
            error_expected=1,
        )

    def _open_error(self, ryu_dp, xid=None):
        """Return the error the switch answers the open of ryu_dp's bundle with.

        The switch answers a bundle's open with an error when it discards the
        bundle, as it does once the bundle has received nothing for the
        switch's bundle idle timeout.
        """
        error = parser.OFPErrorMsg(
            None,
            type_=ofp.OFPET_EXPERIMENTER,
            exp_type=ofp.ONFERR_ET_TIMEOUT,
            experimenter=0x4F4E4600,
        )
        error.xid = self._bundle(ryu_dp)[0].xid if xid is None else xid
        error.datapath = ryu_dp
        return error

    def _commit_error(self, ryu_dp):
        """Return the error the switch answers a commit it fails with."""
        error = parser.OFPErrorMsg(
            None, type_=ofp.OFPET_EXPERIMENTER, exp_type=2313, experimenter=0x4F4E4600
        )
        error.xid = self._bundle(ryu_dp)[-1].xid
        error.datapath = ryu_dp
        return error

    def test_discarded_bundle(self):
        """Test a bundle discarded before its commit reconnects, and is lost.

        The switch makes a new bundle of the adds sent after it discards one,
        so it can commit part of the cold start.
        """
        _, ryu_dp = self._cold_start()
        of_errors = self.get_prom("of_errors_total")
        self.assertTrue(self.valve.oferror(self._open_error(ryu_dp)))
        self.assertEqual(of_errors + 1, self.get_prom("of_errors_total"))
        # The switch times a bundle out once: another timeout is only an error.
        self.assertFalse(self.valve.oferror(self._open_error(ryu_dp)))
        self.assertEqual(of_errors + 2, self.get_prom("of_errors_total"))
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        # What the switch commits, or fails to, under the bundle's id is not
        # the bundle.
        self.valve.bundle_ctrl_reply(self._commit_reply(ryu_dp))
        self.assertFalse(self.valve.oferror(self._commit_error(ryu_dp)))
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        self.assertEqual(1, self._atomic_status())
        # The connection ends, and its cold start is bundled again.
        features, ryu_dp = self._cold_start()
        self.assertEqual((2, 0, 0, 1), self._bundle_counts())
        self.assertFalse(self._global_deletes(features), "flows deleted on connect")
        self.assertTrue(self._bundle(ryu_dp), "not bundled again once discarded")
        self.valve.bundle_ctrl_reply(self._commit_reply(ryu_dp))
        self.assertEqual((2, 1, 0, 1), self._bundle_counts())
        self.assertEqual(1, self._atomic_status())

    def test_discarded_bundles(self):
        """Test bundles discarded in a row stop bundling, as lost ones do."""
        max_lost = self.valve.ATOMIC_COLD_START_MAX_LOST
        for lost in range(max_lost):
            _, ryu_dp = self._cold_start()
            self.assertTrue(self._bundle(ryu_dp), "stopped bundling too soon")
            self.assertTrue(self.valve.oferror(self._open_error(ryu_dp)))
            self.assertEqual(1, self._atomic_status())
            self.valve.datapath_disconnect(self.mock_time())
            self.assertEqual((lost + 1, 0, 0, lost + 1), self._bundle_counts())
        self.assertEqual(0, self._atomic_status())
        features, ryu_dp = self._cold_start()
        self.assertTrue(self._global_deletes(features), "no delete once discarded")
        self.assertFalse(self._bundle(ryu_dp), "bundled again once discarded")
        self.assertEqual((max_lost, 0, 0, max_lost), self._bundle_counts())

    def test_open_error_on_old_connection(self):
        """Test only an answer on the bundle's own connection discards it.

        Each connection numbers its messages from its own xid, so an old
        connection's answer can carry the xid of the bundle's open.
        """
        old_dp = self.FakeDatapath()
        _, ryu_dp = self._cold_start()
        open_xid = self._bundle(ryu_dp)[0].xid
        for other_dp in (old_dp, None):
            self.assertFalse(
                self.valve.oferror(self._open_error(other_dp, xid=open_xid))
            )
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        self.assertTrue(self.valve.oferror(self._open_error(ryu_dp)))
        self.valve.datapath_disconnect(self.mock_time())
        self.assertEqual((1, 0, 0, 1), self._bundle_counts())

    def test_open_refused(self):
        """Test a switch that refuses the bundle's open refuses it at the commit.

        A switch that cannot take a bundle, as one without bundles or a
        connection in the secondary role, answers each of its messages with
        an error, in the order they were sent.
        """
        _, ryu_dp = self._cold_start()
        bundle = self._bundle(ryu_dp)
        of_errors = self.get_prom("of_errors_total")
        error = parser.OFPErrorMsg(
            None, type_=ofp.OFPET_BAD_REQUEST, code=ofp.OFPBRC_IS_SLAVE
        )
        error.datapath = ryu_dp
        for ofmsg in bundle[:-1]:
            error.xid = ofmsg.xid
            self.assertFalse(self.valve.oferror(error))
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        error.xid = bundle[-1].xid
        self.assertTrue(self.valve.oferror(error))
        self.assertEqual(of_errors + len(bundle), self.get_prom("of_errors_total"))
        self.assertEqual((1, 0, 1, 0), self._bundle_counts())
        self.assertEqual(0, self._atomic_status())

    def test_open_error_then_commit(self):
        """Test the commit tells after an error on the open other than a timeout.

        A switch that already has a bundle of the id refuses the open, and
        discards that bundle, then makes a new one of the adds after the
        open, so of all of the cold start, which it commits.
        """
        _, ryu_dp = self._cold_start()
        error = self._open_error(ryu_dp)
        error.exp_type = ofp.ONFERR_ET_BAD_ID
        self.assertFalse(self.valve.oferror(error))
        self.valve.bundle_ctrl_reply(self._commit_reply(ryu_dp))
        self.assertEqual((1, 1, 0, 0), self._bundle_counts())
        self.assertEqual(1, self._atomic_status())

    def test_errors_on_bundle_connection(self):
        """Test other errors on the bundle's connection are handled as before."""
        _, ryu_dp = self._cold_start()
        bundle = self._bundle(ryu_dp)
        of_errors = self.get_prom("of_errors_total")
        for xid in (bundle[1].xid, bundle[-1].xid + 1):
            error = parser.OFPErrorMsg(
                None, type_=ofp.OFPET_BAD_INSTRUCTION, code=ofp.OFPBIC_BAD_TABLE_ID
            )
            error.xid = xid
            error.datapath = ryu_dp
            self.assertFalse(self.valve.oferror(error))
        self.assertEqual(of_errors + 2, self.get_prom("of_errors_total"))
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        # Nor is another experimenter's error of the timeout's type on the open.
        error = self._open_error(ryu_dp)
        error.experimenter = 0x2320
        self.assertFalse(self.valve.oferror(error))
        # Nor a timeout that answers an add: the switch answers with the
        # message that made the bundle, so that is one it made of adds.
        self.assertFalse(
            self.valve.oferror(self._open_error(ryu_dp, xid=bundle[1].xid))
        )
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        # The timeout that answers the bundle's open still discards it.
        self.assertTrue(self.valve.oferror(self._open_error(ryu_dp)))
        # Committed or refused, a bundle's open has no answer to wait for.
        _, ryu_dp = self._cold_start()
        self.valve.bundle_ctrl_reply(self._commit_reply(ryu_dp))
        self.assertFalse(self.valve.oferror(self._open_error(ryu_dp)))
        _, ryu_dp = self._cold_start()
        self.assertTrue(self.valve.oferror(self._commit_error(ryu_dp)))
        self.assertFalse(self.valve.oferror(self._open_error(ryu_dp)))
        self.valve.datapath_disconnect(self.mock_time())
        self.assertEqual((3, 1, 1, 1), self._bundle_counts())
        self.assertEqual(0, self._atomic_status())


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
