#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valve_dot1x.py."""

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

import unittest

from faucet import faucet_dot1x
from faucet import valve_of

from clib.valve_test_lib import (
    DOT1X_CONFIG,
    DOT1X_ACL_CONFIG,
    ValveTestBases,
    build_pkt,
)


class ValveDot1xSmokeTestCase(ValveTestBases.ValveTestNetwork):
    """Smoke test to check dot1x can be initialized."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                dot1x: true
            p2:
                number: 2
                output_only: True
vlans:
    v100:
        vid: 0x100
    student:
        vid: 0x200
        dot1x_assigned: True

"""
        % DOT1X_CONFIG
    )

    def setUp(self):
        """Setup basic 802.1x config"""
        self.setup_valves(self.CONFIG)

    def test_get_mac_str(self):
        """Test NFV port formatter."""
        self.assertEqual("00:00:00:0f:01:01", faucet_dot1x.get_mac_str(15, 257))

    def test_handlers(self):
        """Test dot1x logoff/failure handlers."""
        valve_index = self.dot1x.dp_id_to_valve_index[self.DP_ID]
        port_no = 1
        vlan_name = "student"
        filter_id = "block_http"
        for handler in (self.dot1x.logoff_handler, self.dot1x.failure_handler):
            handler("0e:00:00:00:00:ff", faucet_dot1x.get_mac_str(valve_index, port_no))
        self.dot1x.auth_handler(
            "0e:00:00:00:00:ff",
            faucet_dot1x.get_mac_str(valve_index, port_no),
            vlan_name=vlan_name,
            filter_id=filter_id,
        )


class ValveDot1xACLSmokeTestCase(ValveDot1xSmokeTestCase):
    """Smoke test to check dot1x can be initialized with dot1x ACLs."""

    ACL_CONFIG = """
acls:
    auth_acl:
        - rule:
            actions:
                allow: 1
    noauth_acl:
        - rule:
            actions:
                allow: 0
"""

    CONFIG = """
{}
dps:
    s1:
{}
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                dot1x: true
                dot1x_acl: True
            p2:
                number: 2
                output_only: True
vlans:
    v100:
        vid: 0x100
    student:
        vid: 0x200
        dot1x_assigned: True
""".format(
        ACL_CONFIG, DOT1X_ACL_CONFIG
    )


class ValveDot1xMABSmokeTestCase(ValveDot1xSmokeTestCase):
    """Smoke test to check dot1x can be initialized with dot1x MAB."""

    CONFIG = """
dps:
    s1:
{}
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                dot1x: true
                dot1x_mab: True
            p2:
                number: 2
                output_only: True
vlans:
    v100:
        vid: 0x100
""".format(
        DOT1X_CONFIG
    )


class ValveDot1xDynACLSmokeTestCase(ValveDot1xSmokeTestCase):
    """Smoke test to check dot1x can be initialized with dynamic dot1x ACLs."""

    CONFIG = (
        """
acls:
    accept_acl:
        dot1x_assigned: True
        rules:
        - rule:
            dl_type: 0x800      # Allow ICMP / IPv4
            ip_proto: 1
            actions:
                allow: True
        - rule:
            dl_type: 0x0806     # ARP Packets
            actions:
                allow: True
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                dot1x: true
                dot1x_dyn_acl: True

            p2:
                number: 2
                output_only: True
vlans:
    v100:
        vid: 0x100
"""
        % DOT1X_CONFIG
    )

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_handlers(self):
        valve_index = self.dot1x.dp_id_to_valve_index[self.DP_ID]
        port_no = 1
        vlan_name = None
        filter_id = "accept_acl"
        for handler in (self.dot1x.logoff_handler, self.dot1x.failure_handler):
            handler("0e:00:00:00:00:ff", faucet_dot1x.get_mac_str(valve_index, port_no))
        self.dot1x.auth_handler(
            "0e:00:00:00:00:ff",
            faucet_dot1x.get_mac_str(valve_index, port_no),
            vlan_name=vlan_name,
            filter_id=filter_id,
        )


class ValveDot1xPacketInMetricsTestCase(ValveTestBases.ValveTestNetwork):
    """Test the port metrics a packet in updates on an 802.1X port."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                dot1x: true
            p2:
                number: 2
                output_only: True
            p3:
                number: 3
                native_vlan: v100
vlans:
    v100:
        vid: 0x100
    student:
        vid: 0x200
        dot1x_assigned: True
"""
        % DOT1X_CONFIG
    )

    def setUp(self):
        """Setup an 802.1X port"""
        self.setup_valves(self.CONFIG)
        self.activate_all_ports()

    def _learn(self, port, vid, eth_src):
        """Send a packet in as faucet does, without rcv_packet()'s metric_update."""
        valve = self.valves_manager.valves[self.DP_ID]
        pkt = build_pkt(
            {
                "eth_src": eth_src,
                "eth_dst": self.UNKNOWN_MAC,
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.2",
                "vid": vid,
            }
        )
        msg = namedtuple(
            "null_msg",
            ("match", "in_port", "data", "total_len", "cookie", "reason"),
        )(
            {"in_port": port},
            port,
            pkt.data,
            len(pkt.data),
            valve.dp.cookie,
            valve_of.ofp.OFPR_ACTION,
        )
        self.valves_manager.valve_packet_in(self.mock_time(0), valve, msg)

    def _port_hosts_learned(self, port_name, vid):
        labels = {"vlan": str(vid), "port": port_name, "port_description": port_name}
        return self.get_prom("port_vlan_hosts_learned", labels=labels)

    def test_assigned_vlan_updates_at_packet_in(self):
        """Test a packet in on the assigned VLAN updates the port's metrics on it."""
        valve = self.valves_manager.valves[self.DP_ID]
        valve.add_dot1x_native_vlan(1, "student")
        self.valves_manager.update_metrics(self.mock_time())
        self.assertEqual(0, self._port_hosts_learned("p1", 0x200))
        self._learn(1, 0x200, self.P1_V200_MAC)
        self.assertEqual(1, self._port_hosts_learned("p1", 0x200))

    def test_native_vlan_updates_after_assignment(self):
        """Test a packet in updates the native VLAN of a port assigned another."""
        valve = self.valves_manager.valves[self.DP_ID]
        self._learn(1, 0x100, self.P1_V100_MAC)
        self.valves_manager.update_metrics(self.mock_time(0))
        self.assertEqual(1, self._port_hosts_learned("p1", 0x100))
        valve.add_dot1x_native_vlan(1, "student")
        # The assignment takes p1 off v100's ports, so metric_update no
        # longer refreshes p1's v100 metrics; only a packet in from p1 does.
        now = self.mock_time(valve.dp.timeout * 2)
        self.valves_manager.valve_flow_services(now, "state_expire")
        self.assertEqual(
            0,
            valve.dp.vlans[0x100].cached_hosts_count_on_port(valve.dp.ports[1]),
        )
        self._learn(1, 0x200, self.P1_V200_MAC)
        self.assertEqual(0, self._port_hosts_learned("p1", 0x100))
        self.valves_manager.update_metrics(self.mock_time())
        self.assertEqual(0, self._port_hosts_learned("p1", 0x100))

    def test_native_vlan_updates_after_reload(self):
        """Test a packet in updates the native VLAN of an assigned port after a reload."""
        valve = self.valves_manager.valves[self.DP_ID]
        warm_config = self.CONFIG.replace(
            "number: 3\n", "number: 3\n                max_hosts: 4\n"
        )
        cold_config = warm_config.replace(
            "\nvlans:",
            "\n            p4:\n                number: 4\n"
            "                native_vlan: v100\nvlans:",
        )
        for config, reload_type in ((warm_config, "warm"), (cold_config, "cold")):
            self._learn(1, 0x100, self.P1_V100_MAC)
            self.valves_manager.update_metrics(self.mock_time(0))
            self.assertEqual(1, self._port_hosts_learned("p1", 0x100))
            valve.add_dot1x_native_vlan(1, "student")
            # The reload leaves p1 alone, so p1 keeps its assigned VLAN,
            # which is the previous config's VLAN object, not the new one's.
            self.update_config(config, reload_type=reload_type)
            now = self.mock_time(valve.dp.timeout * 2)
            self.valves_manager.valve_flow_services(now, "state_expire")
            self._learn(1, 0x200, self.P1_V200_MAC)
            self.assertEqual(0, self._port_hosts_learned("p1", 0x100), reload_type)
            self.valves_manager.update_metrics(self.mock_time())
            self.assertEqual(0, self._port_hosts_learned("p1", 0x100), reload_type)
            valve.del_dot1x_native_vlan(1)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
