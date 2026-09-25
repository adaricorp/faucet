#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valve.py."""

# pylint: disable=too-many-lines

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


from functools import partial
import contextlib
import copy
import hashlib
import ipaddress
import os
import random
import unittest
from unittest import mock
import time

from ipaddress import ip_address

from os_ken.lib.packet import arp
from os_ken.lib.packet import icmpv6
from os_ken.ofproto import ofproto_v1_3 as ofp

from clib.fakeoftable import CONTROLLER_PORT
from clib.valve_test_lib import (
    BASE_DP1_CONFIG,
    CONFIG,
    DP1_CONFIG,
    FAUCET_MAC,
    ValveTestBases,
)
from faucet import config_parser_util, valve_of, valve_packet
from faucet.conf import InvalidConfigError
from faucet.config_parser import dp_parser
from faucet.valve import Valve
from faucet.valve_route import (
    ValveIPv4RouteManager,
    ValveIPv6RouteManager,
    ValveRouteManager,
)
from faucet.valve_switch_standalone import ValveSwitchManager


class ValveIncludeTestCase(ValveTestBases.ValveTestNetwork):
    """Test include optional files."""

    CONFIG = (
        """
include-optional: ['/does/not/exist/']
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
        """Setup config with non-existent optional include file"""
        self.setup_valves(self.CONFIG)

    def test_include_optional(self):
        """Test include optional files."""
        self.assertEqual(1, int(self.get_prom("dp_status")))


class ValveBadConfTestCase(ValveTestBases.ValveTestNetwork):
    """Test recovery from a bad config file."""

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

    MORE_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x100
"""
        % DP1_CONFIG
    )

    BAD_CONFIG = """
dps: {}
"""

    def setUp(self):
        """Setup invalid config"""
        self.setup_valves(self.CONFIG)

    def test_bad_conf(self):
        """Test various config types & config reloading"""
        for config, load_error in (
            (self.CONFIG, 0),
            (self.BAD_CONFIG, 1),
            (self.CONFIG, 0),
            (self.MORE_CONFIG, 0),
            (self.BAD_CONFIG, 1),
            (self.CONFIG, 0),
        ):
            with open(self.config_file, "w", encoding="utf-8") as config_file:
                config_file.write(config)
            self.valves_manager.request_reload_configs(
                self.mock_time(), self.config_file
            )
            self.assertEqual(
                load_error,
                self.get_prom("faucet_config_load_error", bare=True),
                msg="%u: %s" % (load_error, config),
            )


class ValveAddVLANACLTestCase(ValveTestBases.ValveTestNetwork):
    """Test addition of an ACL to a VLAN."""

    ACLS = """
    acl_a:
      - rule:
        eth_type: 0x0804
        actions:
          allow: 0
      - rule:
        actions:
          allow: 1
"""

    CONFIG = """
acls:
%s
vlans:
  vlan1:
    acls_in:
    - acl_a
    vid: 0x100
  vlan2:
    vid: 0x200
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: vlan1
            p2:
                number: 2
                native_vlan: vlan2
""" % (
        ACLS,
        DP1_CONFIG,
    )

    ADD_ACL_VLAN2_CONFIG = """
acls:
%s
vlans:
  vlan1:
    acls_in:
    - acl_a
    vid: 0x100
  vlan2:
    acls_in:
    - acl_a
    vid: 0x200
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: vlan1
            p2:
                number: 2
                native_vlan: vlan2
""" % (
        ACLS,
        DP1_CONFIG,
    )

    def setUp(self):
        """Setup basic ACL config"""
        self.setup_valves(self.CONFIG)

    def test_add_vlan_acl(self):
        """Test VLAN ACL can be added."""
        table = self.network.tables[self.DP_ID]

        self.assertFalse(
            table.is_output({"in_port": 1, "vlan_vid": 0, "eth_type": 0x0804}),
            msg="Packet not blocked by ACL",
        )
        self.assertTrue(
            table.is_output({"in_port": 2, "vlan_vid": 0, "eth_type": 0x0804}),
            msg="Packet not allowed by ACL",
        )

        def verify_func():
            for port in [1, 2]:
                self.assertFalse(
                    table.is_output(
                        {"in_port": port, "vlan_vid": 0, "eth_type": 0x0804}
                    ),
                    msg="Packet not blocked by ACL",
                )

        self.update_and_revert_config(
            self.CONFIG,
            self.ADD_ACL_VLAN2_CONFIG,
            reload_type="warm",
            verify_func=verify_func,
        )


class ValveChangeVLANACLTestCase(ValveTestBases.ValveTestNetwork):
    """Test changing an ACL on a VLAN."""

    CONFIG = (
        """
acls:
  acl1:
  - rule:
      eth_type: 0x0806
      actions:
        allow: 1
vlans:
  vlan1:
    acls_in:
    - acl1
    vid: 10
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
"""
        % DP1_CONFIG
    )

    MORE_CONFIG = (
        """
acls:
  acl1:
  - rule:
      eth_type: 0x0806
      actions:
        allow: 1
  - rule:
      eth_type: 0x0800
      actions:
        allow: 0
vlans:
  vlan1:
    acls_in:
    - acl1
    vid: 10
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_change_vlan_acl(self):
        """Test vlan ACL change is detected and packets are correctly allowed/blocked."""
        table = self.network.tables[self.DP_ID]

        self.assertTrue(
            table.is_output({"in_port": 1, "vlan_vid": 0, "eth_type": 0x0806}),
            msg="Packet not allowed by ACL",
        )

        def verify_func():
            self.assertTrue(
                table.is_output({"in_port": 1, "vlan_vid": 0, "eth_type": 0x0806}),
                msg="Packet not allowed by ACL",
            )
            self.assertFalse(
                table.is_output({"in_port": 1, "vlan_vid": 0, "eth_type": 0x0800}),
                msg="Packet not blocked by ACL",
            )

        self.update_and_revert_config(
            self.CONFIG, self.MORE_CONFIG, "warm", verify_func=verify_func
        )


class ValveDeleteVLANACLTestCase(ValveTestBases.ValveTestNetwork):
    """Test deletion of an ACL from a VLAN."""

    ACLS = """
    acl_a:
      - rule:
        eth_type: 0x0804
        actions:
          allow: 0
      - rule:
        actions:
          allow: 1
"""

    CONFIG = """
acls:
%s
vlans:
  vlan1:
    acls_in:
    - acl_a
    vid: 0x100
  vlan2:
    acls_in:
    - acl_a
    vid: 0x200
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: vlan1
            p2:
                number: 2
                native_vlan: vlan2
""" % (
        ACLS,
        DP1_CONFIG,
    )

    DELETE_ACL_VLAN2_CONFIG = """
acls:
%s
vlans:
  vlan1:
    acls_in:
    - acl_a
    vid: 0x100
  vlan2:
    vid: 0x200
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: vlan1
            p2:
                number: 2
                native_vlan: vlan2
""" % (
        ACLS,
        DP1_CONFIG,
    )

    def setUp(self):
        """Setup basic ACL config"""
        self.setup_valves(self.CONFIG)

    def test_delete_vlan_acl(self):
        """Test VLAN ACL can be deleted."""
        table = self.network.tables[self.DP_ID]

        for port in [1, 2]:
            self.assertFalse(
                table.is_output({"in_port": port, "vlan_vid": 0, "eth_type": 0x0804}),
                msg="Packet not blocked by ACL",
            )

        def verify_func():
            self.assertFalse(
                table.is_output({"in_port": 1, "vlan_vid": 0, "eth_type": 0x0804}),
                msg="Packet not blocked by ACL",
            )
            self.assertTrue(
                table.is_output({"in_port": 2, "vlan_vid": 0, "eth_type": 0x0804}),
                msg="Packet not allowed by ACL",
            )

        self.update_and_revert_config(
            self.CONFIG,
            self.DELETE_ACL_VLAN2_CONFIG,
            reload_type="warm",
            verify_func=verify_func,
        )


class ValveChangePortTestCase(ValveTestBases.ValveTestNetwork):
    """Test changes to config on ports."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
                permanent_learn: True
"""
        % DP1_CONFIG
    )

    LESS_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
                permanent_learn: False
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_delete_permanent_learn(self):
        """Test port permanent learn can deconfigured."""
        table = self.network.tables[self.DP_ID]
        before_table_state = table.table_state()
        self.rcv_packet(
            2,
            0x200,
            {
                "eth_src": self.P2_V200_MAC,
                "eth_dst": self.P3_V200_MAC,
                "ipv4_src": "10.0.0.2",
                "ipv4_dst": "10.0.0.3",
                "vid": 0x200,
            },
        )
        self.update_and_revert_config(
            self.CONFIG,
            self.LESS_CONFIG,
            "warm",
            before_table_states={self.DP_ID: before_table_state},
        )


class ValveDeletePortTestCase(ValveTestBases.ValveTestNetwork):
    """Test deletion of a port."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
            p3:
                number: 3
                tagged_vlans: [0x100]
"""
        % DP1_CONFIG
    )

    LESS_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_port_delete(self):
        """Test port can be deleted."""
        self.update_and_revert_config(self.CONFIG, self.LESS_CONFIG, "cold")


class ValveAddPortMirrorNoDelVLANTestCase(ValveTestBases.ValveTestNetwork):
    """Test addition of port mirroring does not cause a del VLAN."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
            p3:
                number: 3
                output_only: true
"""
        % DP1_CONFIG
    )

    MORE_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
            p3:
                number: 3
                output_only: true
                mirror: [1]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        _ = self.setup_valves(self.CONFIG)[self.DP_ID]

    def test_port_mirror(self):
        """Test addition of port mirroring is a warm start."""
        _ = self.update_config(self.MORE_CONFIG, reload_type="warm")[self.DP_ID]


class ValveAddPortTestCase(ValveTestBases.ValveTestNetwork):
    """Test addition of a port."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
"""
        % DP1_CONFIG
    )

    MORE_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
            p3:
                number: 3
                tagged_vlans: [0x100]
"""
        % DP1_CONFIG
    )

    @staticmethod
    def _inport_flows(in_port, ofmsgs):
        return [
            ofmsg
            for ofmsg in ValveTestBases.flowmods_from_flows(ofmsgs)
            if ofmsg.match.get("in_port") == in_port
        ]

    def setUp(self):
        """Setup basic port and vlan config"""
        initial_ofmsgs = self.setup_valves(self.CONFIG)[self.DP_ID]
        self.assertFalse(self._inport_flows(3, initial_ofmsgs))

    def test_port_add(self):
        """Test port can be added."""
        reload_ofmsgs = self.update_config(self.MORE_CONFIG, reload_type="cold")[
            self.DP_ID
        ]
        self.assertTrue(self._inport_flows(3, reload_ofmsgs))


class ValveAddPortTrafficTestCase(ValveTestBases.ValveTestNetwork):
    """Test addition of a port with traffic."""

    # NOTE: This needs to use 'Generic' hardware,
    #  as GenericTFM does not support 'warm' start
    REQUIRE_TFM = False

    CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: Generic
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
"""

    MORE_CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: Generic
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
            p3:
                number: 3
                tagged_vlans: [0x100]
"""

    @staticmethod
    def _inport_flows(in_port, ofmsgs):
        return [
            ofmsg
            for ofmsg in ValveTestBases.flowmods_from_flows(ofmsgs)
            if ofmsg.match.get("in_port") == in_port
        ]

    def _learn(self, in_port):
        ucast_pkt = self.pkt_match(in_port, 1)
        ucast_pkt["in_port"] = in_port
        ucast_pkt["vlan_vid"] = self.V100

        table = self.network.tables[self.DP_ID]
        self.assertTrue(table.is_output(ucast_pkt, port=CONTROLLER_PORT))
        self.rcv_packet(in_port, self.V100, ucast_pkt)

    def _unicast_between(self, in_port, out_port, not_out=1):
        ucast_match = self.pkt_match(in_port, out_port)
        ucast_match["in_port"] = in_port
        ucast_match["vlan_vid"] = self.V100

        table = self.network.tables[self.DP_ID]
        self.assertTrue(table.is_output(ucast_match, port=out_port))
        self.assertFalse(table.is_output(ucast_match, port=not_out))

    def setUp(self):
        initial_ofmsgs = self.setup_valves(self.CONFIG)[self.DP_ID]
        self.assertFalse(self._inport_flows(3, initial_ofmsgs))

    def test_port_add_no_ofmsgs(self):
        """New config does not generate new flows."""
        update_ofmsgs = self.update_config(self.MORE_CONFIG, reload_type="warm")[
            self.DP_ID
        ]
        self.assertFalse(self._inport_flows(3, update_ofmsgs))

    def test_port_add_link_state(self):
        """New port can be added in link-down state."""
        self.update_config(self.MORE_CONFIG, reload_type="warm")

        self.add_port(3, link_up=False)
        self.port_expected_status(3, 0)

        self.set_port_link_up(3)
        self.port_expected_status(3, 1)

    def test_port_add_traffic(self):
        """New port can be added, and pass traffic."""
        self.update_config(self.MORE_CONFIG, reload_type="warm")

        self.add_port(3)

        self._learn(2)
        self._learn(3)

        self._unicast_between(2, 3)
        self._unicast_between(3, 2)


class ValveAddPortRelearnTestCase(ValveTestBases.ValveTestNetwork):
    """Test hosts are learned again after a port is added to their VLAN."""

    # NOTE: This uses 'Open vSwitch' hardware, as with GenericTFM
    #  a change in table sizes would make the reload a cold start.
    REQUIRE_TFM = False

    CONFIG = """
vlans:
    v100:
        vid: 0x100
        faucet_vips: ["10.0.0.254/24"]
    v200:
        vid: 0x200
dps:
    s1:
        dp_id: 1
        hardware: Open vSwitch
        ignore_learn_ins: 0
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
"""

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def _learn(self, in_port, vid, eth_src):
        """Receive an ARP request from a host."""
        self.rcv_packet(
            in_port,
            vid,
            {
                "eth_src": eth_src,
                "eth_dst": self.BROADCAST_MAC,
                "arp_source_ip": "10.0.0.%u" % in_port,
                "arp_target_ip": "10.0.0.254",
            },
        )

    def _learned(self, in_port, vid, eth_src):
        """Return True if a host has an eth_src flow and is not punted."""
        table = self.network.tables[self.DP_ID]
        valve = self.valves_manager.valves[self.DP_ID]
        match = {
            "in_port": in_port,
            "vlan_vid": 0,
            "eth_src": eth_src,
            "eth_dst": self.UNKNOWN_MAC,
            "eth_type": 0x800,
            "ipv4_src": "10.0.0.%u" % in_port,
            "ipv4_dst": "10.0.0.99",
        }
        eth_src_flow = table.single_table_lookup(
            dict(match, vlan_vid=vid | ofp.OFPVID_PRESENT),
            valve.dp.tables["eth_src"].table_id,
        )
        return (
            eth_src_flow is not None
            and "eth_src" in eth_src_flow.match_values
            and not table.is_output(match, port=CONTROLLER_PORT)
        )

    def test_port_add_relearn(self):
        """Test hosts on a VLAN a port is added to are learned again."""
        self._learn(1, 0x100, self.P1_V100_MAC)
        self._learn(2, 0x200, self.P2_V200_MAC)
        self.assertTrue(self._learned(1, 0x100, self.P1_V100_MAC))
        self.assertTrue(self._learned(2, 0x200, self.P2_V200_MAC))

        config = config_parser_util.yaml_load(self.CONFIG)
        config["dps"]["s1"]["interfaces"]["p3"] = {"number": 3, "native_vlan": "v100"}
        self.update_config(config_parser_util.yaml_dump(config), reload_type="warm")
        self.set_port_up(3)
        # Only the VLAN the port was added to had its flows deleted.
        self.assertFalse(self._learned(1, 0x100, self.P1_V100_MAC))
        self.assertTrue(self._learned(2, 0x200, self.P2_V200_MAC))

        # Well within cache_update_guard_time, the host is learned again.
        self._learn(1, 0x100, self.P1_V100_MAC)
        self.assertTrue(self._learned(1, 0x100, self.P1_V100_MAC))


class ValveAddPortRelearnL2TestCase(ValveAddPortRelearnTestCase):
    """Test hosts are learned again after a port is added to an unrouted VLAN."""

    CONFIG = """
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
dps:
    s1:
        dp_id: 1
        hardware: Open vSwitch
        ignore_learn_ins: 0
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
"""


class ValveWarmStartVLANTestCase(ValveTestBases.ValveTestNetwork):
    """Test change of port VLAN only is a warm start."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 9
                tagged_vlans: [0x100]
            p2:
                number: 11
                tagged_vlans: [0x100]
            p3:
                number: 13
                tagged_vlans: [0x100]
            p4:
                number: 14
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    WARM_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 9
                tagged_vlans: [0x100]
            p2:
                number: 11
                tagged_vlans: [0x100]
            p3:
                number: 13
                tagged_vlans: [0x100]
            p4:
                number: 14
                native_vlan: 0x300
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_warm_start(self):
        """Test VLAN change is warm startable and metrics maintained."""
        self.update_and_revert_config(self.CONFIG, self.WARM_CONFIG, "warm")
        self.rcv_packet(
            9,
            0x100,
            {
                "eth_src": self.P1_V100_MAC,
                "eth_dst": self.UNKNOWN_MAC,
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.2",
            },
        )
        vlan_labels = {"vlan": str(int(0x100))}
        port_labels = {"port": "p1", "port_description": "p1"}
        port_labels.update(vlan_labels)

        def verify_func():
            self.assertEqual(1, self.get_prom("vlan_hosts_learned", labels=vlan_labels))
            self.assertEqual(
                1, self.get_prom("port_vlan_hosts_learned", labels=port_labels)
            )

        verify_func()
        self.update_config(self.WARM_CONFIG, reload_type="warm")
        verify_func()


class ValveDeleteVLANTestCase(ValveTestBases.ValveTestNetwork):
    """Test deleting VLAN."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100, 0x200]
            p2:
                number: 2
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    LESS_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x200]
            p2:
                number: 2
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_delete_vlan(self):
        """Test VLAN can be deleted."""
        self.update_and_revert_config(self.CONFIG, self.LESS_CONFIG, "cold")


class ValveChangeDPTestCase(ValveTestBases.ValveTestNetwork):
    """Test changing DP."""

    CONFIG = (
        """
dps:
    s1:
%s
        priority_offset: 4321
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x100
"""
        % DP1_CONFIG
    )

    NEW_CONFIG = (
        """
dps:
    s1:
%s
        priority_offset: 1234
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x100
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config with priority offset"""
        self.setup_valves(self.CONFIG)

    def test_change_dp(self):
        """Test DP changed."""
        self.update_and_revert_config(self.CONFIG, self.NEW_CONFIG, "cold")


class ValveAddVLANTestCase(ValveTestBases.ValveTestNetwork):
    """Test adding VLAN."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100, 0x200]
            p2:
                number: 2
                tagged_vlans: [0x100]
"""
        % DP1_CONFIG
    )

    MORE_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100, 0x200]
            p2:
                number: 2
                tagged_vlans: [0x100, 0x300]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_add_vlan(self):
        """Test VLAN can added."""
        self.update_and_revert_config(self.CONFIG, self.MORE_CONFIG, "cold")


class ValveAddACLTestCase(ValveTestBases.ValveTestNetwork):
    """Test addition of an ACL to a port."""

    ACLS = """
    acl_a:
      - rule:
        eth_type: 0x0804
        actions:
          allow: 0
      - rule:
        actions:
          allow: 1
"""

    CONFIG = """
acls:
%s
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_a
            p2:
                number: 2
                native_vlan: 0x200
""" % (
        ACLS,
        DP1_CONFIG,
    )

    ADD_ACL_P2_CONFIG = """
acls:
%s
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_a
            p2:
                number: 2
                native_vlan: 0x200
                acl_in: acl_a
""" % (
        ACLS,
        DP1_CONFIG,
    )

    def setUp(self):
        """Setup basic ACL config"""
        self.setup_valves(self.CONFIG)

    def test_add_port_acl(self):
        """Test port ACL can be added."""
        table = self.network.tables[self.DP_ID]

        self.assertFalse(
            table.is_output({"in_port": 1, "vlan_vid": 0, "eth_type": 0x0804}),
            msg="Packet not blocked by ACL",
        )
        self.assertTrue(
            table.is_output({"in_port": 2, "vlan_vid": 0, "eth_type": 0x0804}),
            msg="Packet not allowed by ACL",
        )

        def verify_func():
            for port in [1, 2]:
                self.assertFalse(
                    table.is_output(
                        {"in_port": port, "vlan_vid": 0, "eth_type": 0x0804}
                    ),
                    msg="Packet not blocked by ACL",
                )

        self.update_and_revert_config(
            self.CONFIG,
            self.ADD_ACL_P2_CONFIG,
            reload_type="warm",
            verify_func=verify_func,
        )


class ValveChangeACLTestCase(ValveTestBases.ValveTestNetwork):
    """Test changes to ACL on a port."""

    CONFIG = (
        """
acls:
    acl_same_a:
        - rule:
            actions:
                allow: 1
    acl_same_b:
        - rule:
            actions:
                allow: 1
    acl_diff_c:
        - rule:
            actions:
                allow: 0
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_same_a
            p2:
                number: 2
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    SAME_CONTENT_CONFIG = (
        """
acls:
    acl_same_a:
        - rule:
            actions:
                allow: 1
    acl_same_b:
        - rule:
            actions:
                allow: 1
    acl_diff_c:
        - rule:
            actions:
                allow: 0
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_same_b
            p2:
                number: 2
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    DIFF_CONTENT_CONFIG = (
        """
acls:
    acl_same_a:
        - rule:
            actions:
                allow: 1
    acl_same_b:
        - rule:
            actions:
                allow: 1
    acl_diff_c:
        - rule:
            actions:
                allow: 0
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_diff_c
            p2:
                number: 2
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic ACL config"""
        self.setup_valves(self.CONFIG)

    def test_change_port_acl(self):
        """Test port ACL can be changed."""
        self.update_and_revert_config(self.CONFIG, self.SAME_CONTENT_CONFIG, "warm")
        self.update_config(self.SAME_CONTENT_CONFIG, reload_type="warm")
        self.rcv_packet(
            1,
            0x100,
            {
                "eth_src": self.P1_V100_MAC,
                "eth_dst": self.UNKNOWN_MAC,
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.2",
            },
        )
        vlan_labels = {"vlan": str(int(0x100))}
        port_labels = {"port": "p1", "port_description": "p1"}
        port_labels.update(vlan_labels)

        def verify_func():
            self.assertEqual(1, self.get_prom("vlan_hosts_learned", labels=vlan_labels))
            self.assertEqual(
                1, self.get_prom("port_vlan_hosts_learned", labels=port_labels)
            )

        verify_func()
        # ACL changed but we kept the learn cache.
        self.update_config(self.DIFF_CONTENT_CONFIG, reload_type="warm")
        verify_func()


class ValveDeleteACLTestCase(ValveTestBases.ValveTestNetwork):
    """Test deletion of an ACL from a port."""

    ACLS = """
    acl_a:
      - rule:
        eth_type: 0x0804
        actions:
          allow: 0
      - rule:
        actions:
          allow: 1
"""

    CONFIG = """
acls:
%s
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_a
            p2:
                number: 2
                native_vlan: 0x200
                acl_in: acl_a
""" % (
        ACLS,
        DP1_CONFIG,
    )

    DELETE_ACL_P2_CONFIG = """
acls:
%s
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_a
            p2:
                number: 2
                native_vlan: 0x200
""" % (
        ACLS,
        DP1_CONFIG,
    )

    def setUp(self):
        """Setup basic ACL config"""
        self.setup_valves(self.CONFIG)

    def test_delete_port_acl(self):
        """Test port ACL can be deleted."""
        table = self.network.tables[self.DP_ID]

        for port in [1, 2]:
            self.assertFalse(
                table.is_output({"in_port": port, "vlan_vid": 0, "eth_type": 0x0804}),
                msg="Packet not blocked by ACL",
            )

        def verify_func():
            self.assertFalse(
                table.is_output({"in_port": 1, "vlan_vid": 0, "eth_type": 0x0804}),
                msg="Packet not blocked by ACL",
            )
            self.assertTrue(
                table.is_output({"in_port": 2, "vlan_vid": 0, "eth_type": 0x0804}),
                msg="Packet not allowed by ACL",
            )

        self.update_and_revert_config(
            self.CONFIG,
            self.DELETE_ACL_P2_CONFIG,
            reload_type="warm",
            verify_func=verify_func,
        )


class ValveChangeMirrorTestCase(ValveTestBases.ValveTestNetwork):
    """Test changes mirroring port."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                output_only: True
            p3:
                number: 3
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    MIRROR_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                mirror: p1
            p3:
                number: 3
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_change_port_acl(self):
        """Test port ACL can be changed."""
        self.update_and_revert_config(
            self.CONFIG, self.MIRROR_CONFIG, reload_type="warm"
        )

        vlan_labels = {"vlan": str(int(0x100))}
        port_labels = {"port": "p1", "port_description": "p1"}
        port_labels.update(vlan_labels)

        def verify_prom():
            self.assertEqual(1, self.get_prom("vlan_hosts_learned", labels=vlan_labels))
            self.assertEqual(
                1, self.get_prom("port_vlan_hosts_learned", labels=port_labels)
            )

        self.rcv_packet(
            1,
            0x100,
            {
                "eth_src": self.P1_V100_MAC,
                "eth_dst": self.UNKNOWN_MAC,
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.2",
            },
        )

        verify_prom()
        # Now mirroring port 1 but we kept the cache.
        self.update_config(self.MIRROR_CONFIG, reload_type="warm")
        verify_prom()
        # Now unmirror again.
        self.update_config(self.CONFIG, reload_type="warm")
        verify_prom()


class ValveACLTestCase(ValveTestBases.ValveTestNetwork):
    """Test ACL drop/allow and reloading."""

    def setUp(self):
        self.setup_valves(CONFIG)

    def test_vlan_acl_deny(self):
        """Test VLAN ACL denies a packet."""
        acl_config = (
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
                native_vlan: v300
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
        acl_in: drop_non_ospf_ipv4
    v300:
        vid: 0x300
acls:
    drop_non_ospf_ipv4:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            actions:
                allow: 1
        - rule:
            dl_type: 0x800
            actions:
                allow: 0
"""
            % DP1_CONFIG
        )

        drop_match = {
            "in_port": 2,
            "vlan_vid": 0,
            "eth_type": 0x800,
            "ipv4_dst": "192.0.2.1",
        }
        accept_match = {
            "in_port": 2,
            "vlan_vid": 0,
            "eth_type": 0x800,
            "ipv4_dst": "224.0.0.5",
        }
        table = self.network.tables[self.DP_ID]

        # base case
        for match in (drop_match, accept_match):
            self.assertTrue(
                table.is_output(match, port=3, vid=self.V200),
                msg="Packet not output before adding ACL",
            )

        def verify_func():
            self.flap_port(2)
            self.assertFalse(
                table.is_output(drop_match), msg="Packet not blocked by ACL"
            )
            self.assertTrue(
                table.is_output(accept_match, port=3, vid=self.V200),
                msg="Packet not allowed by ACL",
            )

        self.update_and_revert_config(
            CONFIG, acl_config, reload_type="cold", verify_func=verify_func
        )


class ValveEgressACLTestCase(ValveTestBases.ValveTestNetwork):
    """Test ACL drop/allow and reloading."""

    def setUp(self):
        self.setup_valves(CONFIG)

    def test_vlan_acl_deny(self):
        """Test VLAN ACL denies a packet."""
        allow_host_v6 = "fc00:200::1:1"
        deny_host_v6 = "fc00:200::1:2"
        faucet_v100_vip = "fc00:100::1"
        faucet_v200_vip = "fc00:200::1"
        acl_config = """
dps:
    s1:
{dp1_config}
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
        faucet_mac: '{mac}'
        faucet_vips: ['{v100_vip}/64']
    v200:
        vid: 0x200
        faucet_mac: '{mac}'
        faucet_vips: ['{v200_vip}/64']
        acl_out: drop_non_allow_host_v6
        minimum_ip_size_check: false
routers:
    r_v100_v200:
        vlans: [v100, v200]
acls:
    drop_non_allow_host_v6:
        - rule:
            ipv6_dst: '{allow_host}'
            eth_type: 0x86DD
            actions:
                allow: 1
        - rule:
            eth_type: 0x86DD
            actions:
                allow: 0
""".format(
            dp1_config=DP1_CONFIG,
            mac=FAUCET_MAC,
            v100_vip=faucet_v100_vip,
            v200_vip=faucet_v200_vip,
            allow_host=allow_host_v6,
        )

        l2_drop_match = {
            "in_port": 2,
            "eth_dst": self.P3_V200_MAC,
            "vlan_vid": 0,
            "eth_type": 0x86DD,
            "ipv6_dst": deny_host_v6,
        }
        l2_accept_match = {
            "in_port": 3,
            "eth_dst": self.P2_V200_MAC,
            "vlan_vid": 0x200 | ofp.OFPVID_PRESENT,
            "eth_type": 0x86DD,
            "ipv6_dst": allow_host_v6,
        }
        v100_accept_match = {"in_port": 1, "vlan_vid": 0}
        table = self.network.tables[self.DP_ID]

        # base case
        for match in (l2_drop_match, l2_accept_match):
            self.assertTrue(
                table.is_output(match, port=4),
                msg="Packet not output before adding ACL",
            )

        def verify_func():
            self.assertTrue(
                table.is_output(v100_accept_match, port=3),
                msg="Packet not output when on vlan with no ACL",
            )
            self.assertFalse(
                table.is_output(l2_drop_match, port=3), msg="Packet not blocked by ACL"
            )
            self.assertTrue(
                table.is_output(l2_accept_match, port=2),
                msg="Packet not allowed by ACL",
            )

            # unicast
            self.rcv_packet(
                2,
                0x200,
                {
                    "eth_src": self.P2_V200_MAC,
                    "eth_dst": self.P3_V200_MAC,
                    "vid": 0x200,
                    "ipv6_src": allow_host_v6,
                    "ipv6_dst": deny_host_v6,
                    "neighbor_advert_ip": allow_host_v6,
                },
            )
            self.rcv_packet(
                3,
                0x200,
                {
                    "eth_src": self.P3_V200_MAC,
                    "eth_dst": self.P2_V200_MAC,
                    "vid": 0x200,
                    "ipv6_src": deny_host_v6,
                    "ipv6_dst": allow_host_v6,
                    "neighbor_advert_ip": deny_host_v6,
                },
            )

            self.assertTrue(
                table.is_output(l2_accept_match, port=2),
                msg="Packet not allowed by ACL",
            )
            self.assertFalse(
                table.is_output(l2_drop_match, port=3), msg="Packet not blocked by ACL"
            )

            # l3
            l3_drop_match = {
                "in_port": 1,
                "eth_dst": FAUCET_MAC,
                "vlan_vid": 0,
                "eth_type": 0x86DD,
                "ipv6_dst": deny_host_v6,
            }
            l3_accept_match = {
                "in_port": 1,
                "eth_dst": FAUCET_MAC,
                "vlan_vid": 0,
                "eth_type": 0x86DD,
                "ipv6_dst": allow_host_v6,
            }

            self.assertTrue(
                table.is_output(l3_accept_match, port=2),
                msg="Routed packet not allowed by ACL",
            )
            self.assertFalse(
                table.is_output(l3_drop_match, port=3),
                msg="Routed packet not blocked by ACL",
            )

        # multicast
        self.update_and_revert_config(
            CONFIG, acl_config, "cold", verify_func=verify_func
        )


class ValveReloadConfigProfile(ValveTestBases.ValveTestNetwork):
    """Test reload processing time."""

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
        % BASE_DP1_CONFIG
    )
    NUM_PORTS = 100

    baseline_total_tt = None

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(CONFIG)

    def test_profile_reload(self):
        """Test reload processing time."""
        orig_config = copy.copy(self.CONFIG)

        def load_orig_config():
            pstats_out, _ = self.profile(partial(self.update_config, orig_config))
            self.baseline_total_tt = (
                pstats_out.total_tt
            )  # pytype: disable=attribute-error

        for i in range(2, 100):
            self.CONFIG += """
            p%u:
                number: %u
                native_vlan: 0x100
""" % (
                i,
                i,
            )

        for i in range(5):
            load_orig_config()
            pstats_out, pstats_text = self.profile(
                partial(self.update_config, self.CONFIG, reload_type="cold")
            )
            cache_info = valve_of.output_non_output_actions.cache_info()
            self.assertGreater(cache_info.hits, cache_info.misses, msg=cache_info)
            total_tt_prop = (
                pstats_out.total_tt / self.baseline_total_tt
            )  # pytype: disable=attribute-error
            # must not be 20x slower, to ingest config for 100 interfaces than 1.
            # TODO: This test might have to be run separately,
            # since it is marginal on GitHub actions due to parallel test runs.
            if total_tt_prop < 20:
                for valve in self.valves_manager.valves.values():
                    for table in valve.dp.tables.values():
                        cache_info = (
                            table._trim_inst.cache_info()
                        )  # pylint: disable=protected-access
                        self.assertGreater(
                            cache_info.hits, cache_info.misses, msg=cache_info
                        )
                return
            time.sleep(i)

        self.fail("%f: %s" % (total_tt_prop, pstats_text))


class ValveTestVLANRef(ValveTestBases.ValveTestNetwork):
    """Test reference to same VLAN by name or VID."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 333
            p2:
                number: 2
                native_vlan: threes
vlans:
    threes:
        vid: 333
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_vlan_refs(self):
        """Test same VLAN is referred to."""
        vlans = self.valves_manager.valves[self.DP_ID].dp.vlans
        self.assertEqual(1, len(vlans))
        self.assertEqual("threes", vlans[333].name, vlans[333])
        self.assertEqual(2, len(vlans[333].untagged))


class ValveTestConfigHash(ValveTestBases.ValveTestNetwork):
    """Verify faucet_config_hash_info update after config change"""

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

    def _get_info(self, metric, name):
        """Return (single) info dict for metric"""
        # There doesn't seem to be a nice API for this,
        # so we use the prometheus client internal API
        metrics = list(metric.collect())
        self.assertEqual(len(metrics), 1)
        samples = metrics[0].samples
        self.assertEqual(len(samples), 1)
        sample = samples[0]
        self.assertEqual(sample.name, name)
        return sample.labels

    def _check_hashes(self):
        """Verify and return faucet_config_hash_info labels"""
        labels = self._get_info(
            metric=self.metrics.faucet_config_hash, name="faucet_config_hash_info"
        )
        files = labels["config_files"].split(",")
        hashes = labels["hashes"].split(",")
        self.assertTrue(len(files) == len(hashes) == 1)
        self.assertEqual(files[0], self.config_file, "wrong config file")
        hash_value = config_parser_util.config_file_hash(self.config_file)
        self.assertEqual(hashes[0], hash_value, "hash validation failed")
        return labels

    def _change_config(self):
        """Change self.CONFIG"""
        if "0x100" in self.CONFIG:
            self.CONFIG = self.CONFIG.replace("0x100", "0x200")
        else:
            self.CONFIG = self.CONFIG.replace("0x200", "0x100")
        self.update_config(self.CONFIG, reload_expected=True)
        return self.CONFIG

    def test_config_hash_func(self):
        """Verify that faucet_config_hash_func is set correctly"""
        labels = self._get_info(
            metric=self.metrics.faucet_config_hash_func, name="faucet_config_hash_func"
        )
        hash_funcs = list(labels.values())
        self.assertEqual(len(hash_funcs), 1, "found multiple hash functions")
        hash_func = hash_funcs[0]
        # Make sure that it matches and is supported in hashlib
        self.assertEqual(hash_func, config_parser_util.CONFIG_HASH_FUNC)
        self.assertTrue(hash_func in hashlib.algorithms_guaranteed)

    def test_config_hash_update(self):
        """Verify faucet_config_hash_info is properly updated after config"""
        # Verify that hashes change after config is changed
        old_config = self.CONFIG
        old_hashes = self._check_hashes()
        starting_hashes = old_hashes
        self._change_config()
        new_config = self.CONFIG
        self.assertNotEqual(old_config, new_config, "config not changed")
        new_hashes = self._check_hashes()
        self.assertNotEqual(
            old_hashes, new_hashes, "hashes not changed after config change"
        )
        # Verify that hashes don't change after config isn't changed
        old_hashes = new_hashes
        self.update_config(self.CONFIG, reload_expected=False)
        new_hashes = self._check_hashes()
        self.assertEqual(old_hashes, new_hashes, "hashes changed when config didn't")
        # Verify that hash is restored when config is restored
        self._change_config()
        new_hashes = self._check_hashes()
        self.assertEqual(
            new_hashes, starting_hashes, "hashes should be restored to starting values"
        )


class ValveTestConfigRevert(ValveTestBases.ValveTestNetwork):
    """Test configuration revert"""

    CONFIG = """
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""

    CONFIG_AUTO_REVERT = True

    def setUp(self):
        """Setup basic port and vlan config with hardware type set"""
        self.setup_valves(self.CONFIG)

    def test_config_revert(self):
        """Verify config is automatically reverted if bad."""
        self.assertEqual(self.get_prom("faucet_config_load_error", bare=True), 0)
        self.update_config("***broken***", reload_expected=True, error_expected=1)
        self.assertEqual(self.get_prom("faucet_config_load_error", bare=True), 1)
        with open(self.config_file, "r", encoding="utf-8") as config_file:
            config_content = config_file.read()
        self.assertEqual(self.CONFIG, config_content)
        self.update_config(self.CONFIG + "\n", reload_expected=False, error_expected=0)
        more_config = (
            self.CONFIG
            + """
            p2:
                number: 2
                native_vlan: 0x100
        """
        )
        self.update_config(
            more_config, reload_expected=True, reload_type="warm", error_expected=0
        )


class ValveTestConfigRevertBootstrap(ValveTestBases.ValveTestNetwork):
    """Test configuration auto reverted if bad"""

    BAD_CONFIG = """
    *** busted ***
"""
    GOOD_CONFIG = """
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""

    CONFIG_AUTO_REVERT = True

    def setUp(self):
        """Setup invalid config"""
        self.setup_valves(self.BAD_CONFIG, error_expected=1)

    def test_config_revert(self):
        """Verify config is automatically reverted if bad."""
        self.assertEqual(self.get_prom("faucet_config_load_error", bare=True), 1)
        self.update_config(
            self.GOOD_CONFIG + "\n", reload_expected=False, error_expected=0
        )
        self.assertEqual(self.get_prom("faucet_config_load_error", bare=True), 0)


class ValveTestConfigApplied(ValveTestBases.ValveTestNetwork):
    """Test cases for faucet_config_applied."""

    CONFIG = """
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        interfaces:
            p1:
                description: "one thing"
                number: 1
                native_vlan: 0x100
"""
    NEW_DESCR_CONFIG = """
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        interfaces:
            p1:
                description: "another thing"
                number: 1
                native_vlan: 0x100
"""

    def setUp(self):
        """Setup basic port and vlan config with hardware type set"""
        self.setup_valves(self.CONFIG)

    def test_config_applied_update(self):
        """Verify that config_applied increments after DP connect"""
        # 100% for a single datapath
        self.assertEqual(self.get_prom("faucet_config_applied", bare=True), 1.0)
        # Add a second datapath, which currently isn't programmed
        self.CONFIG += """
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""
        self.update_config(self.CONFIG, reload_expected=False)
        # Should be 50%
        self.assertEqual(self.get_prom("faucet_config_applied", bare=True), 0.5)
        # We don't have a way to simulate the second datapath connecting,
        # we update the statistic manually
        self.valves_manager.update_config_applied({0x2: True})
        # Should be 100% now
        self.assertEqual(self.get_prom("faucet_config_applied", bare=True), 1.0)

    def test_description_only(self):
        """Test updating config description"""
        self.update_config(self.NEW_DESCR_CONFIG, reload_expected=False)


class ValveReloadConfigTestCase(
    ValveTestBases.ValveTestBig
):  # pylint: disable=too-few-public-methods
    """Repeats the tests after a config reload."""

    def setUp(self):
        super().setUp()
        self.flap_port(1)
        self.update_config(CONFIG, reload_type="warm", reload_expected=False)


class ValveStaticRouteDeadNextHopTestCase(ValveTestBases.ValveTestNetwork):
    CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
    routes:
        - route:
            ip_dst: 10.99.98.0/24
            ip_gw: 10.10.0.1
        - route:
            ip_dst: 2000::/64
            ip_gw: fa00::1
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan1
""" % (
        DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_dead_nexthop(self):
        """Test static routes are removed when nexthop is dead."""
        table = self.network.tables[self.DP_ID]
        tfm_by_name = {body.name: body for body in table.tfm.values()}
        ipv4_fib_table = tfm_by_name.get(b"ipv4_fib")
        ipv6_fib_table = tfm_by_name.get(b"ipv6_fib")
        eth_dst_table = tfm_by_name.get(b"eth_dst")
        if ipv4_fib_table is None:
            self.fail("ipv4_fib table is missing from TFM")
        if ipv6_fib_table is None:
            self.fail("ipv6_fib table is missing from TFM")
        if eth_dst_table is None:
            self.fail("eth_dst table is missing from TFM")

        arp_pkt = {
            "eth_src": self.P1_V100_MAC,
            "eth_dst": self.BROADCAST_MAC,
            "eth_type": 0x806,
            "arp_source_ip": "10.10.0.1",
            "arp_target_ip": "10.10.0.254",
        }
        nd_pkt = {
            "eth_src": self.P1_V100_MAC,
            "eth_dst": valve_packet.ipv6_link_eth_mcast(ip_address("fa00::254")),
            "ipv6_src": "fa00::1",
            "ipv6_dst": str(
                valve_packet.ipv6_solicited_node_from_ucast(ip_address("fa00::254"))
            ),
            "neighbor_solicit_ip": "fa00::254",
        }
        ipv4_match = {
            "vlan_vid": self.V100,
            "eth_type": 0x800,
            "ipv4_dst": "10.99.98.1",
        }
        ipv6_match = {
            "vlan_vid": self.V100,
            "eth_type": 0x86DD,
            "ipv6_dst": "2000::1",
        }

        self.rcv_packet(1, 0x100, arp_pkt)
        self.rcv_packet(1, 0x100, nd_pkt)

        for match, table_id in [
            (ipv4_match, ipv4_fib_table.table_id),
            (ipv6_match, ipv6_fib_table.table_id),
        ]:
            _, _, next_table = table.get_table_output(match, table_id)
            self.assertEqual(next_table, eth_dst_table.table_id)

        self.set_port_link_down(1)

        for match, table_id in [
            (ipv4_match, ipv4_fib_table.table_id),
            (ipv6_match, ipv6_fib_table.table_id),
        ]:
            _, _, next_table = table.get_table_output(match, table_id)
            self.assertEqual(next_table, None)

        self.set_port_link_up(1)

        self.rcv_packet(1, 0x100, arp_pkt)
        self.rcv_packet(1, 0x100, nd_pkt)

        for match, table_id in [
            (ipv4_match, ipv4_fib_table.table_id),
            (ipv6_match, ipv6_fib_table.table_id),
        ]:
            _, _, next_table = table.get_table_output(match, table_id)
            self.assertEqual(next_table, eth_dst_table.table_id)


class ValveAddVIPTestCase(ValveTestBases.ValveTestNetwork):
    """Test adding VIPs to a VLAN."""

    FAUCET_MAC2 = "0e:00:00:00:00:02"

    CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_mac: "%s"
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    MORE_CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_vips:
      - "10.20.0.254/24"
      - "fb00::254/64"
      - "fe80::c00:ff:fe00:2/64"
    faucet_mac: "%s"
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_add_vip(self):
        """Test adding VIPs to a VLAN is a warm start."""
        table = self.network.tables[self.DP_ID]

        def verify_func():
            self.assertTrue(
                table.is_output(
                    {
                        "in_port": 2,
                        "vlan_vid": 0,
                        "eth_type": 0x800,
                        "eth_src": self.P2_V200_MAC,
                        "eth_dst": self.FAUCET_MAC2,
                        "ipv4_src": "10.20.0.1",
                        "ipv4_dst": "10.20.0.253",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet not sent to controller",
            )
            self.assertTrue(
                table.is_output(
                    {
                        "in_port": 2,
                        "vlan_vid": 0,
                        "eth_type": 0x86DD,
                        "eth_src": self.P2_V200_MAC,
                        "eth_dst": self.FAUCET_MAC2,
                        "ipv6_src": "fb00::1",
                        "ipv6_dst": "fb00::254",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet not sent to controller",
            )
            self.assertTrue(
                table.is_output(
                    {
                        "in_port": 2,
                        "vlan_vid": 0,
                        "eth_type": 0x86DD,
                        "eth_src": self.P2_V200_MAC,
                        "eth_dst": valve_packet.ipv6_link_eth_mcast(
                            ip_address("fe80::c00:ff:fe00:2")
                        ),
                        "ipv6_src": "fe80::200:ff:fe02:2",
                        "ipv6_dst": "fe80::c00:ff:fe00:2",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet not sent to controller",
            )

        self.update_and_revert_config(
            self.CONFIG,
            self.MORE_CONFIG,
            reload_type="warm",
            verify_func=verify_func,
        )


class ValveDeleteVIPTestCase(ValveTestBases.ValveTestNetwork):
    """Test deleting VIPs from a VLAN."""

    FAUCET_MAC2 = "0e:00:00:00:00:02"

    CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_vips:
      - "10.20.0.254/24"
      - "fb00::254/64"
      - "fe80::c00:ff:fe00:2/64"
    faucet_mac: "%s"
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    MORE_CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_mac: "%s"
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_delete_vip(self):
        """Test deleting VIPs from a VLAN is a warm start."""
        table = self.network.tables[self.DP_ID]

        def verify_func():
            self.l2_learn_host(2, 0x200, self.P2_V200_MAC)
            self.assertFalse(
                table.is_output(
                    {
                        "in_port": 2,
                        "vlan_vid": 0,
                        "eth_type": 0x800,
                        "eth_src": self.P2_V200_MAC,
                        "eth_dst": self.FAUCET_MAC2,
                        "ipv4_src": "10.20.0.1",
                        "ipv4_dst": "10.20.0.254",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet sent to controller",
            )
            self.assertFalse(
                table.is_output(
                    {
                        "in_port": 2,
                        "vlan_vid": 0,
                        "eth_type": 0x86DD,
                        "eth_src": self.P2_V200_MAC,
                        "eth_dst": self.FAUCET_MAC2,
                        "ipv6_src": "fb00::1",
                        "ipv6_dst": "fb00::254",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet sent to controller",
            )
            self.assertFalse(
                table.is_output(
                    {
                        "in_port": 2,
                        "vlan_vid": 0,
                        "eth_type": 0x86DD,
                        "eth_src": self.P2_V200_MAC,
                        "eth_dst": valve_packet.ipv6_link_eth_mcast(
                            ip_address("fe80::c00:ff:fe00:2")
                        ),
                        "ipv6_src": "fe80::200:ff:fe02:2",
                        "ipv6_dst": "fe80::c00:ff:fe00:2",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet sent to controller",
            )

        self.update_and_revert_config(
            self.CONFIG,
            self.MORE_CONFIG,
            reload_type="warm",
            verify_func=verify_func,
        )


class ValveAddVIPInterVLANRouteTestCase(ValveTestBases.ValveTestNetwork):
    FAUCET_MAC2 = "0e:00:00:00:00:02"

    CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_mac: "%s"
routers:
    router-1:
        vlans: [vlan1, vlan2]
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    MORE_CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_vips:
      - "10.20.0.254/24"
      - "fb00::254/64"
      - "fe80::c00:ff:fe00:2/64"
    faucet_mac: "%s"
routers:
    router-1:
        vlans: [vlan1, vlan2]
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_add_vip(self):
        """Test adding VIPs to a VLAN with InterVLAN routing is a warm start."""
        table = self.network.tables[self.DP_ID]

        def verify_func():
            self.assertTrue(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x800,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv4_src": "10.10.0.1",
                        "ipv4_dst": "10.20.0.254",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet not routed",
            )
            self.assertTrue(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x86DD,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv6_src": "fa00::1",
                        "ipv6_dst": "fb00::254",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet not routed",
            )

        self.update_and_revert_config(
            self.CONFIG,
            self.MORE_CONFIG,
            reload_type="warm",
            verify_func=verify_func,
        )


class ValveDeleteVIPInterVLANRouteTestCase(ValveTestBases.ValveTestNetwork):
    FAUCET_MAC2 = "0e:00:00:00:00:02"

    CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_vips:
      - "10.20.0.254/24"
      - "fb00::254/64"
      - "fe80::c00:ff:fe00:2/64"
    faucet_mac: "%s"
routers:
    router-1:
        vlans: [vlan1, vlan2]
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    MORE_CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_mac: "%s"
routers:
    router-1:
        vlans: [vlan1, vlan2]
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_delete_vip(self):
        """Test deleting VIPs from a VLAN with InterVLAN routing is a warm start."""
        table = self.network.tables[self.DP_ID]

        def verify_func():
            self.assertFalse(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x800,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv4_src": "10.10.0.1",
                        "ipv4_dst": "10.20.0.254",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet routed",
            )
            self.assertFalse(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x86DD,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv6_src": "fa00::1",
                        "ipv6_dst": "fb00::254",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet routed",
            )

        self.update_and_revert_config(
            self.CONFIG,
            self.MORE_CONFIG,
            reload_type="warm",
            verify_func=verify_func,
        )


class ValveAddVIPGlobalInterVLANRouteTestCase(ValveTestBases.ValveTestNetwork):
    FAUCET_MAC2 = "0e:00:00:00:00:02"

    CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_mac: "%s"
routers:
    router-1:
        vlans: [vlan1, vlan2]
dps:
    s1:
%s
        global_vlan: 4094
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    MORE_CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_vips:
      - "10.20.0.254/24"
      - "fb00::254/64"
      - "fe80::c00:ff:fe00:2/64"
    faucet_mac: "%s"
routers:
    router-1:
        vlans: [vlan1, vlan2]
dps:
    s1:
%s
        global_vlan: 4094
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_add_vip(self):
        """Test adding VIPs to a VLAN with global InterVLAN routing is a warm start."""
        table = self.network.tables[self.DP_ID]

        def verify_func():
            self.assertTrue(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x800,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv4_src": "10.10.0.1",
                        "ipv4_dst": "10.20.0.254",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet not routed",
            )
            self.assertTrue(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x86DD,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv6_src": "fa00::1",
                        "ipv6_dst": "fb00::254",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet not routed",
            )

        self.update_and_revert_config(
            self.CONFIG,
            self.MORE_CONFIG,
            reload_type="warm",
            verify_func=verify_func,
        )


class ValveDeleteVIPGlobalInterVLANRouteTestCase(ValveTestBases.ValveTestNetwork):
    FAUCET_MAC2 = "0e:00:00:00:00:02"

    CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_vips:
      - "10.20.0.254/24"
      - "fb00::254/64"
      - "fe80::c00:ff:fe00:2/64"
    faucet_mac: "%s"
routers:
    router-1:
        vlans: [vlan1, vlan2]
dps:
    s1:
%s
        global_vlan: 4094
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    MORE_CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_mac: "%s"
routers:
    router-1:
        vlans: [vlan1, vlan2]
dps:
    s1:
%s
        global_vlan: 4094
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_delete_vip(self):
        """Test deleting VIPs from a VLAN with global InterVLAN routing is a warm start."""
        table = self.network.tables[self.DP_ID]

        def verify_func():
            self.assertFalse(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x800,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv4_src": "10.10.0.1",
                        "ipv4_dst": "10.20.0.254",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet routed",
            )
            self.assertFalse(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x86DD,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv6_src": "fa00::1",
                        "ipv6_dst": "fb00::254",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=CONTROLLER_PORT,
                ),
                msg="Packet routed",
            )

        self.update_and_revert_config(
            self.CONFIG,
            self.MORE_CONFIG,
            reload_type="warm",
            verify_func=verify_func,
        )


class ValveAddStaticRouteInterVLANRouteTestCase(ValveTestBases.ValveTestNetwork):
    FAUCET_MAC2 = "0e:00:00:00:00:02"

    CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_vips:
      - "10.20.0.254/24"
      - "fb00::254/64"
      - "fe80::c00:ff:fe00:2/64"
    faucet_mac: "%s"
routers:
    router-1:
        vlans: [vlan1, vlan2]
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    MORE_CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_vips:
      - "10.20.0.254/24"
      - "fb00::254/64"
      - "fe80::c00:ff:fe00:2/64"
    routes:
        - route:
            ip_dst: 10.99.99.0/24
            ip_gw: 10.20.0.1
        - route:
            ip_dst: 2000::/64
            ip_gw: fb00::1
        - route:
            ip_dst: 2001::/64
            ip_gw: fe80::200:ff:fe02:2
    faucet_mac: "%s"
routers:
    router-1:
        vlans: [vlan1, vlan2]
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_add_static_route(self):
        """Test adding static routes to a VLAN with InterVLAN routing is a warm start."""
        table = self.network.tables[self.DP_ID]
        self.l2_learn_host(1, 0x100, self.P1_V100_MAC)
        # Hosts learned on the unchanged VLAN must survive the reloads.
        self.l3_learn_host(
            1,
            0x100,
            self.P1_V100_MAC,
            [
                ip_address("10.10.0.1"),
                ip_address("fa00::1"),
                ip_address("fe80::200:ff:fe01:1"),
            ],
            [
                ip_address("10.10.0.254"),
                ip_address("fa00::254"),
                ip_address("fe80::c00:ff:fe00:1"),
            ],
        )
        before_table_state = table.table_state()

        def verify_func():
            self.l3_learn_host(
                2,
                0x200,
                self.P2_V200_MAC,
                [
                    ip_address("10.20.0.1"),
                    ip_address("fb00::1"),
                    ip_address("fe80::200:ff:fe02:2"),
                ],
                [
                    ip_address("10.20.0.254"),
                    ip_address("fb00::254"),
                    ip_address("fe80::c00:ff:fe00:2"),
                ],
            )

            self.assertTrue(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x800,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv4_src": "10.10.0.1",
                        "ipv4_dst": "10.99.99.1",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=2,
                ),
                msg="Packet not routed",
            )
            self.assertTrue(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x86DD,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv6_src": "fa00::1",
                        "ipv6_dst": "2000::1",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=2,
                ),
                msg="Packet not routed",
            )
            self.assertTrue(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x86DD,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv6_src": "fa00::1",
                        "ipv6_dst": "2001::1",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=2,
                ),
                msg="Packet not routed",
            )

        self.update_and_revert_config(
            self.CONFIG,
            self.MORE_CONFIG,
            reload_type="warm",
            verify_func=verify_func,
            before_table_states={self.DP_ID: before_table_state},
        )


class ValveDeleteStaticRouteInterVLANRouteTestCase(ValveTestBases.ValveTestNetwork):
    FAUCET_MAC2 = "0e:00:00:00:00:02"

    CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_vips:
      - "10.20.0.254/24"
      - "fb00::254/64"
      - "fe80::c00:ff:fe00:2/64"
    routes:
        - route:
            ip_dst: 10.99.99.0/24
            ip_gw: 10.20.0.1
        - route:
            ip_dst: 2000::/64
            ip_gw: fb00::1
        - route:
            ip_dst: 2001::/64
            ip_gw: fe80::200:ff:fe02:2
    faucet_mac: "%s"
routers:
    router-1:
        vlans: [vlan1, vlan2]
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    MORE_CONFIG = """
vlans:
  vlan1:
    vid: 0x100
    faucet_vips:
      - "10.10.0.254/24"
      - "fa00::254/64"
      - "fe80::c00:ff:fe00:1/64"
  vlan2:
    vid: 0x200
    faucet_vips:
      - "10.20.0.254/24"
      - "fb00::254/64"
      - "fe80::c00:ff:fe00:2/64"
    faucet_mac: "%s"
routers:
    router-1:
        vlans: [vlan1, vlan2]
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
            2:
                native_vlan: vlan2
""" % (
        FAUCET_MAC2,
        DP1_CONFIG,
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_delete_static_route(self):
        """Test deleting static routes from a VLAN with InterVLAN routing is a warm start."""
        table = self.network.tables[self.DP_ID]
        self.l2_learn_host(1, 0x100, self.P1_V100_MAC)
        # Hosts learned on the unchanged VLAN must survive the reloads.
        self.l3_learn_host(
            1,
            0x100,
            self.P1_V100_MAC,
            [
                ip_address("10.10.0.1"),
                ip_address("fa00::1"),
                ip_address("fe80::200:ff:fe01:1"),
            ],
            [
                ip_address("10.10.0.254"),
                ip_address("fa00::254"),
                ip_address("fe80::c00:ff:fe00:1"),
            ],
        )
        before_table_state = table.table_state()

        def verify_func():
            self.l3_learn_host(
                2,
                0x200,
                self.P2_V200_MAC,
                [
                    ip_address("10.20.0.1"),
                    ip_address("fb00::1"),
                    ip_address("fe80::200:ff:fe02:2"),
                ],
                [
                    ip_address("10.20.0.254"),
                    ip_address("fb00::254"),
                    ip_address("fe80::c00:ff:fe00:2"),
                ],
            )

            self.assertFalse(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x800,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv4_src": "10.10.0.1",
                        "ipv4_dst": "10.99.99.1",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=2,
                ),
                msg="Packet routed",
            )
            self.assertFalse(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x86DD,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv6_src": "fa00::1",
                        "ipv6_dst": "2000::1",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=2,
                ),
                msg="Packet routed",
            )
            self.assertFalse(
                table.is_output(
                    {
                        "in_port": 1,
                        "vlan_vid": 0,
                        "eth_type": 0x86DD,
                        "eth_src": self.P1_V100_MAC,
                        "eth_dst": self.FAUCET_MAC,
                        "ipv6_src": "fa00::1",
                        "ipv6_dst": "2001::1",
                        "echo_request_data": self.ICMP_PAYLOAD,
                    },
                    port=2,
                ),
                msg="Packet routed",
            )

        self.update_and_revert_config(
            self.CONFIG,
            self.MORE_CONFIG,
            reload_type="warm",
            verify_func=verify_func,
            before_table_states={self.DP_ID: before_table_state},
        )


class ValveWarmRoutedVLANTestBase(ValveTestBases.ValveTestNetwork):
    """Warm start a VLAN routed with other VLANs, without relearning any hosts.

    Uses Open vSwitch, so that adding a VLAN does not change the pipeline.
    """

    REQUIRE_TFM = False

    CONFIG = """
vlans:
    uplink:
        vid: 0x100
        faucet_vips: ["10.0.0.254/24", "fc00::254/64"]
        routes:
            - route:
                ip_dst: 0.0.0.0/0
                ip_gw: 10.0.0.1
            - route:
                ip_dst: ::/0
                ip_gw: fc00::1%(uplink_routes)s
    servers:
        vid: 0x200
        faucet_vips: ["10.2.0.254/24", "fc02::254/64"]
    clients1:
        vid: %(clients1_vid)u
        faucet_vips: ["10.11.0.254/%(clients1_prefixlen)u", "fc11::254/64"]
    clients2:
        vid: 0x400
        faucet_vips: ["10.12.0.254/24", "fc12::254/64"]
routers:%(routers)s
dps:
    s1:
        dp_id: 1
        hardware: "Open vSwitch"
        ignore_learn_ins: 0
        global_vlan: %(global_vlan)u
        interfaces:
            1:
                native_vlan: uplink
            2:
                native_vlan: servers
            3:
                native_vlan: clients1
            4:
                native_vlan: clients2
"""

    ROUTERS = """
    clients1-servers:
        vlans: [servers, clients1]
    clients1-uplink:
        vlans: [uplink, clients1]
    clients2-servers:
        vlans: [servers, clients2]
    clients2-uplink:
        vlans: [uplink, clients2]"""
    GLOBAL_VLAN = 0

    # MAC, IPv4 and IPv6 address of the host learned on each port.
    HOSTS = {
        1: ("00:00:00:01:00:01", "10.0.0.1", "fc00::1"),
        2: ("00:00:00:02:00:01", "10.2.0.1", "fc02::1"),
        3: ("00:00:00:03:00:01", "10.11.0.1", "fc11::1"),
        4: ("00:00:00:04:00:01", "10.12.0.1", "fc12::1"),
    }
    INTERNET = ("192.0.2.1", "2001:db8::1")

    def config(self, clients1_vid=0x300, clients1_prefixlen=24, uplink_routes=""):
        """Return the config, optionally with clients1 or uplink changed."""
        return self.CONFIG % {
            "clients1_vid": clients1_vid,
            "clients1_prefixlen": clients1_prefixlen,
            "uplink_routes": uplink_routes,
            "routers": self.ROUTERS,
            "global_vlan": self.GLOBAL_VLAN,
        }

    def setUp(self):
        """Setup routed VLANs and learn a host on each."""
        self.setup_valves(self.config())
        dp = self.valves_manager.valves[self.DP_ID].dp
        for port, (mac, ipv4, ipv6) in self.HOSTS.items():
            vlan = dp.ports[port].native_vlan
            self.l3_learn_host(
                port,
                vlan.vid,
                mac,
                [ip_address(ipv4), ip_address(ipv6)],
                [vip.ip for vip in vlan.faucet_vips],
            )

    def routed(self, in_port, ip_dst, out_port, eth_dst=None):
        """Return True if the host on in_port is routed to ip_dst via out_port."""
        eth_src, ipv4, ipv6 = self.HOSTS[in_port]
        ipv = ip_address(ip_dst).version
        match = {
            "in_port": in_port,
            "vlan_vid": 0,
            "eth_type": 0x800 if ipv == 4 else 0x86DD,
            "eth_src": eth_src,
            "eth_dst": FAUCET_MAC,
            "ipv%u_src" % ipv: ipv4 if ipv == 4 else ipv6,
            "ipv%u_dst" % ipv: ip_dst,
        }
        if eth_dst is None:
            eth_dst = self.HOSTS[out_port][0]
        outputs = self.network.tables[self.DP_ID].get_port_outputs(match)
        return any(pkt["eth_dst"] == eth_dst for pkt in outputs.get(out_port, []))

    def assert_routed_via_other_vlans(self, port):
        """Assert the host on port reaches the internet and the server."""
        destinations = [(ip_dst, 1) for ip_dst in self.INTERNET + self.HOSTS[1][1:]]
        destinations.extend((ip_dst, 2) for ip_dst in self.HOSTS[2][1:])
        for ip_dst, out_port in destinations:
            self.assertTrue(
                self.routed(port, ip_dst, out_port),
                msg="port %u to %s not routed" % (port, ip_dst),
            )


class ValveWarmChangeRoutedVLANTestCase(ValveWarmRoutedVLANTestBase):
    """Test changing a routed VLAN keeps routes resolved on other VLANs."""

    def test_change_routed_vlan(self):
        """Test changing clients1 does not remove routes from clients2."""
        self.update_config(self.config(clients1_prefixlen=23), reload_type="warm")
        self.assert_routed_via_other_vlans(4)
        self.assert_routed_via_other_vlans(3)


class ValveWarmChangeGlobalRoutedVLANTestCase(ValveWarmChangeRoutedVLANTestCase):
    """Test changing a globally routed VLAN keeps routes resolved on other VLANs."""

    ROUTERS = """
    router-1:
        vlans: [uplink, servers, clients1, clients2]"""
    GLOBAL_VLAN = 4000


class ValveWarmChangeRoutedVLANVIDTestCase(ValveWarmRoutedVLANTestBase):
    """Test changing the VID of a routed VLAN."""

    def test_change_vid(self):
        """Test the new VID gets the routes resolved on other VLANs."""
        self.update_config(self.config(clients1_vid=0x500), reload_type="warm")
        self.assert_routed_via_other_vlans(3)


class ValveWarmChangeUplinkVLANTestCase(ValveWarmRoutedVLANTestBase):
    """Test changing the uplink VLAN."""

    UPLINK_ROUTES = """
            - route:
                ip_dst: 198.51.100.0/24
                ip_gw: 10.0.0.1"""

    def test_change_uplink_vlan(self):
        """Test hosts learned on the client VLANs stay reachable from the uplink."""
        self.update_config(
            self.config(uplink_routes=self.UPLINK_ROUTES), reload_type="warm"
        )
        for port in (3, 4):
            for ip_dst in self.HOSTS[port][1:]:
                self.assertTrue(
                    self.routed(1, ip_dst, port),
                    msg="uplink to %s not routed" % ip_dst,
                )


class ValveWarmChangeRoutedVLANResolvingTestCase(ValveWarmRoutedVLANTestBase):
    """Test changing a routed VLAN while a nexthop on another VLAN resolves."""

    SERVER2_MAC = "00:00:00:02:00:02"
    SERVER2_IP = "10.2.0.2"

    def test_resolving_nexthop(self):
        """Test a nexthop resolving during a warm start is routed once resolved."""
        mac, ipv4, _ = self.HOSTS[4]
        # Traffic for an unresolved server is dropped while it is resolved.
        self.rcv_packet(
            4,
            0x400,
            {
                "eth_src": mac,
                "eth_dst": FAUCET_MAC,
                "ipv4_src": ipv4,
                "ipv4_dst": self.SERVER2_IP,
                "echo_request_data": self.ICMP_PAYLOAD,
            },
        )
        self.assertFalse(self.routed(4, self.SERVER2_IP, 2, self.SERVER2_MAC))
        self.update_config(self.config(clients1_prefixlen=23), reload_type="warm")
        self.rcv_packet(
            2,
            0x200,
            {
                "eth_src": self.SERVER2_MAC,
                "eth_dst": FAUCET_MAC,
                "eth_type": 0x806,
                "arp_code": arp.ARP_REPLY,
                "arp_source_ip": self.SERVER2_IP,
                "arp_target_ip": "10.2.0.254",
            },
        )
        self.assertTrue(self.routed(4, self.SERVER2_IP, 2, self.SERVER2_MAC))


# pylint: disable=protected-access
# VLAN deletion as it was before dp_vlan_refs(), when every VLAN deleted
# rescanned all the VLANs on the DP. Kept verbatim, bar calling the base
# class explicitly, as the reference that the batched scans must match.


def _rescan_valve_del_vlan(self, vlan, dp_vlans):
    """Delete a configured VLAN."""
    self.logger.info("Delete VLAN %s" % vlan)
    ofmsgs = []
    for manager in self._managers:
        ofmsgs.extend(manager.del_vlan(vlan, dp_vlans))
    expired_hosts = list(vlan.dyn_host_cache.values())
    for entry in expired_hosts:
        self._update_expired_host(entry, vlan)
    vlan.reset_caches()
    return ofmsgs


def _rescan_valve_del_vlans(self, vlans, dp_vlans):
    """Delete configured VLANs."""
    ofmsgs = []
    for vlan in vlans:
        ofmsgs.extend(self.del_vlan(vlan, dp_vlans))
    return ofmsgs


def _rescan_switch_del_drop_spoofed_faucet_mac_rules(self, vlan, dp_vlans):
    """Remove rules to drop spoofed faucet mac"""
    ofmsgs = []
    if self.drop_spoofed_faucet_mac:
        dp_macs = [vlan.faucet_mac for vlan in dp_vlans]
        if vlan.faucet_mac not in dp_macs:
            ofmsgs.extend(self.pipeline.remove_filter({"eth_src": vlan.faucet_mac}))
    return ofmsgs


def _rescan_switch_del_vlan(self, vlan, dp_vlans):
    """Delete a VLAN."""
    ofmsgs = [
        self.flood_table.flowdel(match=self.flood_table.match(vlan=vlan)),
        self.eth_src_table.flowdel(match=self.eth_src_table.match(vlan=vlan)),
    ]
    ofmsgs.extend(self.del_drop_spoofed_faucet_mac_rules(vlan, dp_vlans))
    return ofmsgs


def _rescan_route_del_faucet_mac(self, faucet_mac, dp_vlans):
    """Delete flows associated with a given faucet mac"""
    ofmsgs = []
    max_prefixlen = 32 if self.IPV == 4 else 128

    dp_macs = set()
    dp_mac_global_vip_present = {}
    for dp_vlan in dp_vlans:
        if dp_vlan.faucet_vips_by_ipv(self.IPV):
            dp_macs.add(dp_vlan.faucet_mac)
            if dp_vlan.faucet_mac not in dp_mac_global_vip_present:
                dp_mac_global_vip_present[dp_vlan.faucet_mac] = False
            for faucet_vip in dp_vlan.faucet_vips_by_ipv(self.IPV):
                if not faucet_vip.ip.is_link_local:
                    dp_mac_global_vip_present[dp_vlan.faucet_mac] = True
                    break

    if faucet_mac not in dp_macs:
        # FAUCET MAC is no longer used by any VLAN on DP
        for eth_type in self.CONTROL_ETH_TYPES:
            ofmsgs.append(
                self.vip_table.flowdel(
                    match=self.vip_table.match(eth_dst=faucet_mac, eth_type=eth_type)
                )
            )
    elif not dp_mac_global_vip_present[faucet_mac]:
        # FAUCET MAC remains active on DP, but only used by link-local VIP
        ofmsgs.append(
            self.vip_table.flowdel(
                match=self.vip_table.match(
                    eth_dst=faucet_mac,
                    eth_type=self.ETH_TYPE,
                    nw_proto=self.ICMP_TYPE,
                ),
                priority=self.route_priority + max_prefixlen - 1,
                strict=True,
            )
        )
        ofmsgs.append(
            self.vip_table.flowdel(
                match=self.vip_table.match(
                    eth_dst=faucet_mac,
                    eth_type=self.ETH_TYPE,
                ),
                priority=self.route_priority + max_prefixlen - 3,
                strict=True,
            )
        )

    if True not in dp_mac_global_vip_present.values():
        # No global scope VIPs left on DP
        ofmsgs.append(
            self.vip_table.flowdel(
                match=self.vip_table.match(
                    eth_type=self.ETH_TYPE, nw_proto=self.ICMP_TYPE
                ),
                priority=self.route_priority + max_prefixlen - 2,
                strict=True,
            )
        )
        ofmsgs.append(
            self.vip_table.flowdel(
                match=self.vip_table.match(eth_type=self.ETH_TYPE),
                priority=self.route_priority + max_prefixlen - 4,
                strict=True,
            )
        )
    return ofmsgs


def _rescan_route_del_vlan(self, vlan, dp_vlans):
    """Delete a VLAN."""
    ofmsgs = []
    if not vlan.faucet_vips_by_ipv(self.IPV):
        return ofmsgs
    ofmsgs.append(self.fib_table.flowdel(match=self.fib_table.match(vlan=vlan)))
    ofmsgs.extend(self._del_faucet_mac(vlan.faucet_mac, dp_vlans))

    # Expire next hops for this VLAN to remove static routes
    # from FIB of VLANs in same router as this one
    self.expire_vlan_nexthops(vlan)

    dp_faucet_vips = set()
    dp_faucet_vip_hosts = set()
    if len(vlan.faucet_vips_by_ipv(self.IPV)) >= 1 and self.global_routing:
        for dp_vlan in dp_vlans:
            for faucet_vip in dp_vlan.faucet_vips_by_ipv(self.IPV):
                dp_faucet_vips.add(faucet_vip)
                faucet_vip_host = self._host_from_faucet_vip(faucet_vip)
                dp_faucet_vip_hosts.add(faucet_vip_host)

    for faucet_vip in vlan.faucet_vips_by_ipv(self.IPV):
        ofmsgs.extend(
            self._del_faucet_vip(vlan, faucet_vip, dp_faucet_vip_hosts, dp_faucet_vips)
        )
    return ofmsgs


def _rescan_ipv4_route_del_vlan(self, vlan, dp_vlans):
    """Delete a VLAN."""
    ofmsgs = _rescan_route_del_vlan(self, vlan, dp_vlans)
    if not vlan.faucet_vips_by_ipv(self.IPV):
        return ofmsgs

    dp_faucet_vip_hosts = set()
    for dp_vlan in dp_vlans:
        for faucet_vip in dp_vlan.faucet_vips_by_ipv(self.IPV):
            faucet_vip_host = self._host_from_faucet_vip(faucet_vip)
            dp_faucet_vip_hosts.add(faucet_vip_host)

    for faucet_vip in vlan.faucet_vips_by_ipv(self.IPV):
        faucet_vip_host = self._host_from_faucet_vip(faucet_vip)
        if faucet_vip_host not in dp_faucet_vip_hosts:
            # Remove ARP for FAUCET VIP flow
            ofmsgs.append(
                self.vip_table.flowdel(
                    match=self.vip_table.match(
                        eth_type=valve_of.ether.ETH_TYPE_ARP,
                        eth_dst=valve_of.mac.BROADCAST_STR,
                        nw_dst=faucet_vip_host,
                    ),
                )
            )
    return ofmsgs


def _rescan_ipv6_route_del_vlan(self, vlan, dp_vlans):
    """Delete a VLAN."""
    ofmsgs = _rescan_route_del_vlan(self, vlan, dp_vlans)
    if not vlan.faucet_vips_by_ipv(self.IPV):
        return ofmsgs

    dp_mcast_macs = set()
    dp_faucet_vip_broadcasts = set()
    dp_link_local_present = False
    for dp_vlan in dp_vlans:
        for faucet_vip in dp_vlan.faucet_vips_by_ipv(self.IPV):
            if faucet_vip.is_link_local:
                dp_link_local_present = True
            faucet_vip_host_nd_mcast = valve_packet.ipv6_link_eth_mcast(
                valve_packet.ipv6_solicited_node_from_ucast(faucet_vip.ip)
            )
            dp_mcast_macs.add(faucet_vip_host_nd_mcast)
            if self.global_routing:
                faucet_vip_broadcast = ipaddress.IPv6Interface(
                    faucet_vip.network.broadcast_address
                )
                dp_faucet_vip_broadcasts.add(faucet_vip_broadcast)

    if not dp_link_local_present:
        # No link local FAUCET VIPs present on any VLAN on DP
        ofmsgs.append(
            self.vip_table.flowdel(
                match=self.vip_table.match(
                    eth_type=self.ETH_TYPE,
                    eth_dst=valve_packet.IPV6_ALL_ROUTERS_MCAST,
                    nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                    icmpv6_type=icmpv6.ND_ROUTER_SOLICIT,
                ),
            )
        )

    for faucet_vip in vlan.faucet_vips_by_ipv(self.IPV):
        faucet_vip_host_nd_mcast = valve_packet.ipv6_link_eth_mcast(
            valve_packet.ipv6_solicited_node_from_ucast(faucet_vip.ip)
        )
        if faucet_vip_host_nd_mcast not in dp_mcast_macs:
            # Remove IPv6 NS for FAUCET VIP flow
            ofmsgs.append(
                self.vip_table.flowdel(
                    match=self.vip_table.match(
                        eth_type=self.ETH_TYPE,
                        eth_dst=faucet_vip_host_nd_mcast,
                        nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                        icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT,
                    ),
                )
            )
        if self.global_routing:
            faucet_vip_broadcast = ipaddress.IPv6Interface(
                faucet_vip.network.broadcast_address
            )
            if faucet_vip_broadcast not in dp_faucet_vip_broadcasts:
                # FAUCET VIP broadcast route no longer in use on DP
                ofmsgs.append(
                    self.fib_table.flowdel(
                        match=self._route_match(self.global_vlan, faucet_vip_broadcast),
                    )
                )
    return ofmsgs


# pylint: enable=protected-access


def _rescan_per_vlan():
    """Patch VLAN deletion back to rescanning the DP for every VLAN."""
    stack = contextlib.ExitStack()
    stack.enter_context(
        mock.patch.multiple(
            Valve, del_vlan=_rescan_valve_del_vlan, del_vlans=_rescan_valve_del_vlans
        )
    )
    stack.enter_context(
        mock.patch.multiple(
            ValveSwitchManager,
            del_vlan=_rescan_switch_del_vlan,
            del_drop_spoofed_faucet_mac_rules=_rescan_switch_del_drop_spoofed_faucet_mac_rules,
        )
    )
    stack.enter_context(
        mock.patch.object(
            ValveRouteManager, "_del_faucet_mac", _rescan_route_del_faucet_mac
        )
    )
    stack.enter_context(
        mock.patch.object(
            ValveIPv4RouteManager, "del_vlan", _rescan_ipv4_route_del_vlan
        )
    )
    stack.enter_context(
        mock.patch.object(
            ValveIPv6RouteManager, "del_vlan", _rescan_ipv6_route_del_vlan
        )
    )
    return stack


class ValveDeleteVLANRefsTestCase(ValveTestBases.ValveTestNetwork):
    """Test gathering the DP's VLAN references once for a batch of VLAN
    deletions deletes the same flows as rescanning the DP for every VLAN."""

    REQUIRE_TFM = False
    SAMPLES = 100

    FAUCET_MACS = (None, "0e:00:00:00:00:01", "0e:00:00:00:00:02")
    VIPS = (
        (None, "10.0.1.254/24", "10.0.1.254/25", "10.0.2.254/24"),
        (None, "fc00::1:254/112", "fc00::1:254/120", "fc01::1:254/112"),
        (None, "fe80::c00:ff:fe00:1/64", "fe80::c00:ff:fe00:2/64"),
    )

    CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: 'Open vSwitch'
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def _random_config(self, rng):
        """Return a config with VLANs that share FAUCET MACs and VIPs."""
        vlans = {}
        for i in range(rng.randint(1, 6)):
            vlan = {"vid": 0x100 + i}
            faucet_mac = rng.choice(self.FAUCET_MACS)
            if faucet_mac:
                vlan["faucet_mac"] = faucet_mac
            faucet_vips = [rng.choice(vips) for vips in self.VIPS]
            vlan["faucet_vips"] = [vip for vip in faucet_vips if vip]
            vlans["v%u" % i] = vlan
        dp_config = {
            "dp_id": self.DP_ID,
            "hardware": "Open vSwitch",
            "drop_spoofed_faucet_mac": rng.choice((True, False)),
            "proactive_learn_v4": rng.choice((True, False)),
            "interfaces": {"p1": {"number": 1, "tagged_vlans": list(vlans)}},
        }
        routers = {}
        for i in range(rng.randint(0, 2)):
            router_vlans = rng.sample(
                list(vlans), rng.randint(min(2, len(vlans)), len(vlans))
            )
            routers["r%u" % i] = {"vlans": router_vlans}
        if len(routers) == 1 and rng.choice((True, False)):
            dp_config["global_vlan"] = 0x300
        config = {"vlans": vlans, "dps": {"s1": dp_config}}
        if routers:
            config["routers"] = routers
        return config_parser_util.yaml_dump(config)

    def _parse_dp(self, config):
        """Return the DP in config, or None if config is not valid."""
        config_file = os.path.join(self.tmpdir, "parse.yaml")
        with open(config_file, "w", encoding="utf-8") as config_fh:
            config_fh.write(config)
        try:
            _, _, dps, _ = dp_parser(config_file, self.LOGNAME)
        except InvalidConfigError:
            return None
        return dps[0]

    def test_del_vlans_refs(self):
        """Test deleting random VLANs against random DP VLANs."""
        rng = random.Random(1)
        compared = 0
        referenced = 0
        for _ in range(self.SAMPLES):
            old_config = self._random_config(rng)
            new_dp = self._parse_dp(self._random_config(rng))
            if new_dp is None or self._parse_dp(old_config) is None:
                continue
            self.update_config(old_config, reload_type=None)
            valve = self.valves_manager.valves[self.DP_ID]
            old_vlans = list(valve.dp.vlans.values())
            vlans = rng.sample(old_vlans, rng.randint(1, len(old_vlans)))
            with _rescan_per_vlan():
                expected = [
                    str(ofmsg)
                    for ofmsg in valve.del_vlans(vlans, new_dp.vlans.values())
                ]
                unreferenced = {str(ofmsg) for ofmsg in valve.del_vlans(vlans, [])}
            ofmsgs = [
                str(ofmsg) for ofmsg in valve.del_vlans(vlans, new_dp.vlans.values())
            ]
            self.assertEqual(expected, ofmsgs)
            compared += 1
            if unreferenced - set(expected):
                referenced += 1
        self.assertGreater(compared, self.SAMPLES // 3)
        self.assertGreater(referenced, 0)


class _ScannedVLANs(list):
    """VLANs that count how many times they are scanned."""

    scans = 0

    def __iter__(self):
        self.scans += 1
        return super().__iter__()


class ValveWarmStartManyRoutedVLANsTestCase(ValveTestBases.ValveTestNetwork):
    """Test warm starting many routed VLANs does work linear in their number."""

    REQUIRE_TFM = False
    VLANS = 64

    VLANS_CONFIG = "".join(
        """
    v%u:
        vid: %u
        faucet_vips: ["10.0.%u.254/24", "fc00::%x:254/112", "fe80::c00:ff:fe00:1/64"]
"""
        % (i, 0x100 + i, i, i)
        for i in range(VLANS)
    )
    TAGGED_VLANS = ", ".join("v%u" % i for i in range(VLANS))

    CONFIG = """
vlans:%s
dps:
    s1:
        dp_id: 1
        hardware: 'Open vSwitch'
        interfaces:
            p1:
                number: 1
                tagged_vlans: [%s]
""" % (
        VLANS_CONFIG,
        TAGGED_VLANS,
    )

    MORE_CONFIG = (
        CONFIG
        + """
            p2:
                number: 2
                tagged_vlans: [%s]
"""
        % TAGGED_VLANS
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_add_trunk_port(self):
        """Test adding a port that carries every VLAN, which changes them all."""
        # pylint: disable=protected-access
        del_vlans = Valve.del_vlans
        host_from_faucet_vip = ValveRouteManager._host_from_faucet_vip
        batches = []
        vip_hosts = []

        def scanned_del_vlans(valve, vlans, dp_vlans):
            dp_vlans = _ScannedVLANs(dp_vlans)
            batches.append((vlans, dp_vlans))
            return del_vlans(valve, vlans, dp_vlans)

        def counted_host_from_faucet_vip(route_manager, faucet_vip):
            vip_hosts.append(faucet_vip)
            return host_from_faucet_vip(route_manager, faucet_vip)

        with mock.patch.object(
            Valve, "del_vlans", scanned_del_vlans
        ), mock.patch.object(
            ValveRouteManager, "_host_from_faucet_vip", counted_host_from_faucet_vip
        ):
            self.update_config(self.MORE_CONFIG, reload_type="warm")

        self.assertEqual(1, len(batches))
        vlans, dp_vlans = batches[0]
        self.assertEqual(self.VLANS, len(vlans))
        # The DP's VLANs are scanned a few times for the whole batch,
        # not once or more for every VLAN deleted, so work on their VIPs
        # grows with the number of VLANs rather than its square.
        self.assertLess(dp_vlans.scans, self.VLANS // 4)
        self.assertLessEqual(len(vip_hosts), 10 * self.VLANS)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
