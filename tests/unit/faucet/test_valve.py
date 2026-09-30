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
from ipaddress import ip_address, ip_network

import copy
import time
import unittest

from os_ken.lib import mac
from os_ken.lib.packet import arp, icmpv6, slow
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


class ValveGatewayExpiryTestCase(ValveTestBases.ValveTestNetwork):
    """Test addresses no route uses are resolved only until they are dead."""

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
            p3:
                number: 3
                tagged_vlans: [v100]
vlans:
    v100:
        vid: 0x100
        faucet_vips: ["10.0.0.254/24", "fc00::1:254/112"]
        routes:
            - route:
                ip_dst: "10.99.0.0/24"
                ip_gw: "10.0.0.99"
            - route:
                ip_dst: "fc00::99:0/112"
                ip_gw: "fc00::1:99"
"""
        % DP1_CONFIG
    )

    HOST_MAC = "00:00:00:01:00:01"
    HOST_IPS = {4: "10.0.0.1", 6: "fc00::1:1"}
    VIPS = {4: "10.0.0.254", 6: "fc00::1:254"}
    # The gateway of the configured routes, and one for a route added later.
    STATIC_GWS = {4: "10.0.0.99", 6: "fc00::1:99"}
    OTHER_GWS = {4: "10.0.0.98", 6: "fc00::1:98"}
    ADDED_DSTS = {4: "10.98.0.0/24", 6: "fc00::98:0/112"}
    TRUNK_PORT = 3

    def setUp(self):
        """Setup a routed VLAN with a static route."""
        self.setup_valves(self.CONFIG)

    def _valve(self):
        """Return the valve."""
        return self.valves_manager.valves[self.DP_ID]

    def _vlan(self):
        """Return the routed VLAN."""
        return self._valve().dp.vlans[0x100]

    @staticmethod
    def _requested(ofmsgs):
        """Return the IP addresses ofmsgs send an ARP request or an NS for."""
        requested = set()
        for pkt_out in ValveTestBases.packet_outs_from_flows(ofmsgs):
            pkt = valve_packet.parse_packet_in_pkt(bytes(pkt_out.data), None)[0]
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
                requested.add(ip_address(arp_pkt.dst_ip))
            icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
            if icmpv6_pkt and icmpv6_pkt.type_ == icmpv6.ND_NEIGHBOR_SOLICIT:
                requested.add(ip_address(icmpv6_pkt.data.dst))
        return requested

    def _resolvers(self, cycles, secs=None):
        """Run faucet's resolvers every secs, with nothing answering, and
        return the IP addresses each run requests. By default every entry
        is due on every run."""
        valve = self._valve()
        if secs is None:
            secs = valve.dp.max_resolve_backoff_time * 2
        requested = []
        for _ in range(cycles):
            now = self.mock_time(secs)
            ofmsgs = valve.resolve_gateways(now, None).get(valve, [])
            ofmsgs.extend(valve.state_expire(now, None).get(valve, []))
            self.apply_ofmsgs(ofmsgs)
            requested.append(self._requested(ofmsgs))
        return requested

    def _learn_host(self, ipv, port=1):
        """Have the host request a VIP, so faucet routes it."""
        host_ip = self.HOST_IPS[ipv]
        vip = ip_address(self.VIPS[ipv])
        match = {"eth_src": self.HOST_MAC}
        if ipv == 4:
            match.update(
                {
                    "eth_dst": mac.BROADCAST_STR,
                    "arp_code": arp.ARP_REQUEST,
                    "arp_source_ip": host_ip,
                    "arp_target_ip": str(vip),
                }
            )
        else:
            match.update(
                {
                    "eth_dst": valve_packet.ipv6_link_eth_mcast(vip),
                    "ipv6_src": host_ip,
                    "ipv6_dst": str(valve_packet.ipv6_solicited_node_from_ucast(vip)),
                    "neighbor_solicit_ip": str(vip),
                }
            )
        self.rcv_packet(port, 0x100, match)
        self.assertIn(ip_network(host_ip), self._vlan().routes_by_ipv(ipv))

    def _reply(self, ipv, port):
        """Have the host answer faucet's request, by ARP or by ND."""
        host_ip = self.HOST_IPS[ipv]
        match = {"eth_src": self.HOST_MAC, "eth_dst": self._vlan().faucet_mac}
        if ipv == 4:
            match.update(
                {
                    "arp_code": arp.ARP_REPLY,
                    "arp_source_ip": host_ip,
                    "arp_target_ip": self.VIPS[ipv],
                }
            )
        else:
            match.update(
                {
                    "ipv6_src": host_ip,
                    "ipv6_dst": self.VIPS[ipv],
                    "neighbor_advert_ip": host_ip,
                }
            )
        self.rcv_packet(port, 0x100, match)

    def _trunk_down(self, secs):
        """Take the trunk down for secs, running the resolvers every 2s as
        faucet does, and return the IP addresses each run requests."""
        self.set_port_down(self.TRUNK_PORT)
        return self._resolvers(secs // 2, secs=2)

    def _resolve_until_dead(self, ipv, ip_gw):
        """Run the resolvers until an address is dead, and return how many
        runs requested it. Assert it is neither requested nor a neighbour after."""
        retries = self._valve().dp.max_host_fib_retry_count
        requested = self._resolvers(retries + 2)
        self.assertNotIn(ip_network(ip_gw), self._vlan().routes_by_ipv(ipv))
        after = self._resolvers(retries + 2)
        self.assertFalse([run for run in after if ip_gw in run])
        self.assertNotIn(ip_gw, self._vlan().neigh_cache_by_ipv(ipv))
        return len([run for run in requested if ip_gw in run])

    def _test_dead_host(self, ipv):
        """Test a host that stops replying is not resolved once it is dead,
        also once its port flaps."""
        host_ip = ip_address(self.HOST_IPS[ipv])
        retries = self._valve().dp.max_host_fib_retry_count
        self._learn_host(ipv)
        self.assertEqual(retries, self._resolve_until_dead(ipv, host_ip))
        # vlan_neighbors counts only the static route's gateway.
        self.valves_manager.update_metrics(self.mock_time(0))
        labels = {"vlan": str(0x100), "ipv": str(ipv)}
        self.assertEqual(1, self.get_prom("vlan_neighbors", labels=labels))
        # It was expired as dead, not with its port, so its port coming up
        # again does not request it again.
        self.set_port_down(1)
        self.set_port_up(1)
        after_flap = self._resolvers(retries + 2)
        self.assertFalse([run for run in after_flap if host_ip in run])
        self.assertNotIn(host_ip, self._vlan().neigh_cache_by_ipv(ipv))

    def _test_port_down_host(self, ipv):
        """Test a host whose route was expired with its port is still resolved,
        until it is dead."""
        self._learn_host(ipv)
        self.set_port_down(1)
        self.set_port_up(1)
        self.assertNotIn(
            ip_network(self.HOST_IPS[ipv]), self._vlan().routes_by_ipv(ipv)
        )
        self.assertEqual(
            self._valve().dp.max_host_fib_retry_count,
            self._resolve_until_dead(ipv, ip_address(self.HOST_IPS[ipv])),
        )

    def _test_deleted_route_gw(self, ipv):
        """Test a gateway whose last route is deleted is still resolved,
        until it is dead."""
        valve = self._valve()
        ip_gw = ip_address(self.OTHER_GWS[ipv])
        ip_dst = ip_network(self.ADDED_DSTS[ipv])
        self.apply_ofmsgs(valve.add_route(self._vlan(), ip_gw, ip_dst))
        self.apply_ofmsgs(valve.del_route(self._vlan(), ip_dst))
        self.assertEqual(
            valve.dp.max_host_fib_retry_count,
            self._resolve_until_dead(ipv, ip_gw),
        )

    def _test_static_route_gw(self, ipv):
        """Test a gateway a route uses is resolved however long it is silent,
        also once another route through it is deleted."""
        valve = self._valve()
        ip_gw = ip_address(self.STATIC_GWS[ipv])
        ip_dst = ip_network(self.ADDED_DSTS[ipv])
        retries = valve.dp.max_host_fib_retry_count
        self.apply_ofmsgs(valve.add_route(self._vlan(), ip_gw, ip_dst))
        requested = self._resolvers(retries + 2)
        self.apply_ofmsgs(valve.del_route(self._vlan(), ip_dst))
        requested.extend(self._resolvers(retries + 2))
        self.assertTrue(all(ip_gw in run for run in requested[-retries:]))
        self.assertIn(ip_gw, self._vlan().neigh_cache_by_ipv(ipv))

    def _test_port_outage(self, ipv, secs):
        """Test a host on a trunk down for longer than it is resolved is
        resolved again once the trunk is up, and learned when it answers."""
        host_ip = ip_address(self.HOST_IPS[ipv])
        retries = self._valve().dp.max_host_fib_retry_count
        self._learn_host(ipv, port=self.TRUNK_PORT)
        down = self._trunk_down(secs)
        self.assertEqual(retries, len([run for run in down if host_ip in run]))
        self.assertNotIn(host_ip, self._vlan().neigh_cache_by_ipv(ipv))
        self.set_port_up(self.TRUNK_PORT)
        after_up = self._resolvers(2, secs=2)
        self.assertIn(host_ip, after_up[-1])
        self._reply(ipv, self.TRUNK_PORT)
        entry = self._vlan().neigh_cache_by_ipv(ipv)[host_ip]
        self.assertEqual(self.HOST_MAC, entry.eth_src)
        if ipv == 6:
            # An advert routes the host again; an ARP reply is only cached.
            self.assertIn(ip_network(host_ip), self._vlan().routes_by_ipv(ipv))

    def _test_port_outage_silent_host(self, ipv):
        """Test a host that does not answer once its trunk is up again is
        requested as often as any other, and then no more."""
        host_ip = ip_address(self.HOST_IPS[ipv])
        self._learn_host(ipv, port=self.TRUNK_PORT)
        # Long enough to use up most of the host's requests, but not all.
        self._trunk_down(300)
        self.set_port_up(self.TRUNK_PORT)
        self.assertEqual(
            self._valve().dp.max_host_fib_retry_count,
            self._resolve_until_dead(ipv, host_ip),
        )

    def _test_port_outage_moved_host(self, ipv):
        """Test a host that answers on another port while its trunk is down
        keeps what was learned there once the trunk is up."""
        host_ip = ip_address(self.HOST_IPS[ipv])
        self._learn_host(ipv, port=self.TRUNK_PORT)
        down = self._trunk_down(4)
        self.assertIn(host_ip, down[-1])
        self._reply(ipv, 1)
        self.set_port_up(self.TRUNK_PORT)
        nexthop_cache = self._vlan().neigh_cache_by_ipv(ipv)
        self.assertIn(host_ip, nexthop_cache)
        self.assertEqual(self.HOST_MAC, nexthop_cache[host_ip].eth_src)
        self.assertEqual(1, nexthop_cache[host_ip].port.number)
        if ipv == 6:
            self.assertIn(ip_network(host_ip), self._vlan().routes_by_ipv(ipv))

    def _test_port_flaps_silent_host(self, ipv):
        """Test a trunk that goes down again and again resolves a host that
        never answers again only the first time it is up."""
        host_ip = ip_address(self.HOST_IPS[ipv])
        retries = self._valve().dp.max_host_fib_retry_count
        self._learn_host(ipv, port=self.TRUNK_PORT)
        requested = []
        for secs in (600, 10, 10, 1800):
            requested.extend(self._trunk_down(secs))
            self.set_port_up(self.TRUNK_PORT)
            requested.extend(self._resolvers(15, secs=2))
        requested.extend(self._resolvers(retries + 2))
        self.assertEqual(2 * retries, len([run for run in requested if host_ip in run]))
        self.assertNotIn(host_ip, self._vlan().neigh_cache_by_ipv(ipv))

    def test_dead_host_ipv4(self):
        """Test an IPv4 host that stops replying is not resolved once dead."""
        self._test_dead_host(4)

    def test_dead_host_ipv6(self):
        """Test an IPv6 host that stops replying is not resolved once dead."""
        self._test_dead_host(6)

    def test_port_down_host_ipv4(self):
        """Test an IPv4 host expired with its port is resolved until dead."""
        self._test_port_down_host(4)

    def test_port_down_host_ipv6(self):
        """Test an IPv6 host expired with its port is resolved until dead."""
        self._test_port_down_host(6)

    def test_deleted_route_gw_ipv4(self):
        """Test an IPv4 gateway with no routes left is resolved until dead."""
        self._test_deleted_route_gw(4)

    def test_deleted_route_gw_ipv6(self):
        """Test an IPv6 gateway with no routes left is resolved until dead."""
        self._test_deleted_route_gw(6)

    def test_static_route_gw_ipv4(self):
        """Test an IPv4 gateway a route uses is always resolved."""
        self._test_static_route_gw(4)

    def test_static_route_gw_ipv6(self):
        """Test an IPv6 gateway a route uses is always resolved."""
        self._test_static_route_gw(6)

    def test_port_outage_10m_ipv4(self):
        """Test an IPv4 host is resolved again after a 10 minute outage."""
        self._test_port_outage(4, 600)

    def test_port_outage_10m_ipv6(self):
        """Test an IPv6 host is resolved again after a 10 minute outage."""
        self._test_port_outage(6, 600)

    def test_port_outage_30m_ipv4(self):
        """Test an IPv4 host is resolved again after a 30 minute outage."""
        self._test_port_outage(4, 1800)

    def test_port_outage_30m_ipv6(self):
        """Test an IPv6 host is resolved again after a 30 minute outage."""
        self._test_port_outage(6, 1800)

    def test_port_outage_silent_host_ipv4(self):
        """Test a silent IPv4 host is resolved until dead after an outage."""
        self._test_port_outage_silent_host(4)

    def test_port_outage_silent_host_ipv6(self):
        """Test a silent IPv6 host is resolved until dead after an outage."""
        self._test_port_outage_silent_host(6)

    def test_port_outage_moved_host_ipv4(self):
        """Test an IPv4 host that answers on another port during an outage
        keeps its entry."""
        self._test_port_outage_moved_host(4)

    def test_port_outage_moved_host_ipv6(self):
        """Test an IPv6 host that answers on another port during an outage
        keeps its entry and its route."""
        self._test_port_outage_moved_host(6)

    def test_port_flaps_silent_host_ipv4(self):
        """Test a silent IPv4 host is resolved again once, however often
        its port flaps."""
        self._test_port_flaps_silent_host(4)

    def test_port_flaps_silent_host_ipv6(self):
        """Test a silent IPv6 host is resolved again once, however often
        its port flaps."""
        self._test_port_flaps_silent_host(6)


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


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
