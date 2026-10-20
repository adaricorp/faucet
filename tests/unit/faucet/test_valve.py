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
import random
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
    build_pkt,
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


class ValvePortHostsCountTestCase(ValveTestBases.ValveTestNetwork):
    """Test a port's count of hosts over all its VLANs, which max_hosts limits."""

    REQUIRE_TFM = False

    CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: Open vSwitch
        ignore_learn_ins: 0
        interfaces:
            p1:
                number: 1
                tagged_vlans: [v100, v200, v300]
                max_hosts: 3
            p2:
                number: 2
                native_vlan: v100
                tagged_vlans: [v200]
            p3:
                number: 3
                native_vlan: v300
                max_hosts: 4
            p4:
                number: 4
                coprocessor: {strategy: vlan_vid}
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
    v300:
        vid: 0x300
"""

    VIDS = (0x100, 0x200, 0x300)

    def setUp(self):
        """Setup a trunk with max_hosts, and ports on some of its VLANs"""
        self.setup_valves(self.CONFIG)

    def apply_ofmsgs(self, ofmsgs, dp_id=None, offset=0, all_offsets=False):
        """Apply ofmsgs, by default without replaying them at an offset.

        These tests check host counts, not flows, and the replay would take
        most of their time.
        """
        return super().apply_ofmsgs(ofmsgs, dp_id, offset, all_offsets)

    def _config_variants(self):
        """Return configs that a warm start can change between."""
        changes = (
            {},
            {"p1": {"description": "trunk"}},
            {"p1": {"tagged_vlans": ["v100", "v200"]}},
            {"p2": {"tagged_vlans": ["v200", "v300"]}},
            {"p3": {"max_hosts": 2}},
            {"v200": {"max_hosts": 100}},
        )
        variants = []
        for change in changes:
            config = yaml_load(self.CONFIG)
            for name, conf in change.items():
                if name in config["vlans"]:
                    config["vlans"][name].update(conf)
                else:
                    config["dps"]["s1"]["interfaces"][name].update(conf)
            variants.append(yaml_dump(config))
        return variants

    def _valve(self):
        return self.valves_manager.valves[self.DP_ID]

    def _learn(self, port_no, vid, eth_src):
        return self.rcv_packet(
            port_no,
            vid,
            {
                "eth_src": eth_src,
                "eth_dst": self.BROADCAST_MAC,
                "eth_type": ether.ETH_TYPE_IP,
                "ipv4_src": "0.0.0.0",
                "ipv4_dst": "255.255.255.255",
            },
        )[self.DP_ID]

    def _expire(self, secs):
        self.valves_manager.valve_flow_services(self.mock_time(secs), "state_expire")

    def _is_ban(self, ofmsgs, port_no):
        valve = self._valve()
        eth_src_table = valve.dp.tables["eth_src"]
        return any(
            valve_of.is_flowmod(ofmsg)
            and ofmsg.table_id == eth_src_table.table_id
            and ofmsg.hard_timeout == valve.dp.learn_ban_timeout
            and ofmsg.match.get("in_port", None) == port_no
            and not ofmsg.instructions
            for ofmsg in ofmsgs
        )

    def _check_hosts_counts(self, msg):
        """Check every port's count against counting its VLANs' host caches."""
        for port in self._valve().dp.ports.values():
            vlans_count = sum(
                vlan.cached_hosts_count_on_port(port) for vlan in port.vlans()
            )
            self.assertEqual(vlans_count, port.hosts_count(), "%s %s" % (port, msg))

    def test_max_hosts_on_trunk(self):
        """Test max_hosts bans learning at the count over all the port's VLANs."""
        valve = self._valve()
        port = valve.dp.ports[1]
        learn_timeout = valve.switch_manager.learn_timeout
        self.assertFalse(self._is_ban(self._learn(1, 0x100, "0e:00:00:00:01:01"), 1))
        counter = port.hosts_counter
        self.mock_time(learn_timeout // 2)
        for vid in (0x200, 0x300):
            self.assertFalse(self._is_ban(self._learn(1, vid, "0e:00:00:00:01:02"), 1))
        self.assertEqual(3, port.hosts_count())
        # A host already learned on the VLAN is not banned.
        self.assertFalse(self._is_ban(self._learn(1, 0x200, "0e:00:00:00:01:02"), 1))
        self.assertTrue(self._is_ban(self._learn(1, 0x100, "0e:00:00:00:01:03"), 1))
        self.assertEqual(1, port.dyn_learn_ban_count)
        self.assertIsNone(valve.dp.vlans[0x100].cached_host("0e:00:00:00:01:03"))
        self.assertEqual(3, port.hosts_count())
        # Only the first host expires, which unbans the port.
        self._expire(learn_timeout // 2 + 1)
        self.assertIsNone(valve.dp.vlans[0x100].cached_host("0e:00:00:00:01:01"))
        self.assertEqual(2, port.hosts_count())
        self.assertFalse(self._is_ban(self._learn(1, 0x300, "0e:00:00:00:01:03"), 1))
        self.assertEqual(3, port.hosts_count())
        self.assertTrue(self._is_ban(self._learn(1, 0x200, "0e:00:00:00:01:04"), 1))
        self.assertEqual(2, port.dyn_learn_ban_count)
        # The port counted its VLANs once, and the count was kept since.
        self.assertIs(counter, port.hosts_counter)
        self._check_hosts_counts("after bans")

    def test_hosts_count_cache_cleared(self):
        """Test a port counts again when a VLAN's host cache is cleared in place."""
        valve = self._valve()
        port = valve.dp.ports[1]
        for vid in self.VIDS:
            self._learn(1, vid, "0e:00:00:00:01:01")
        self.assertEqual(3, port.hosts_count())
        vlan = valve.dp.vlans[0x200]
        vlan.dyn_host_cache.clear()
        vlan.dyn_host_cache_by_port.clear()
        self.assertEqual(2, port.hosts_count())
        self.assertFalse(self._is_ban(self._learn(1, 0x200, "0e:00:00:00:01:02"), 1))
        self.assertTrue(self._is_ban(self._learn(1, 0x200, "0e:00:00:00:01:03"), 1))

    def test_hosts_count_warm_start(self):
        """Test a port keeps its count of hosts across a warm start."""
        variants = self._config_variants()
        valve = self._valve()
        learn_timeout = valve.switch_manager.learn_timeout
        self._learn(1, 0x100, "0e:00:00:00:01:01")
        self.mock_time(learn_timeout // 2)
        self._learn(1, 0x200, "0e:00:00:00:01:02")
        self._learn(1, 0x300, "0e:00:00:00:01:03")
        self._learn(3, 0x300, "0e:00:00:00:03:01")
        self.assertTrue(self._is_ban(self._learn(1, 0x100, "0e:00:00:00:01:04"), 1))
        old_port = valve.dp.ports[1]
        old_vlans = dict(valve.dp.vlans)
        self.assertEqual(3, old_port.hosts_count())

        # Only p3 changes, so p1 and the VLANs carry their dyn state over,
        # and the VLANs' host caches with it. A port's count is not dyn state.
        self.update_config(variants[4], reload_type="warm")
        port = valve.dp.ports[1]
        self.assertIsNot(old_port, port)
        self.assertEqual(1, port.dyn_learn_ban_count)
        for vid, vlan in valve.dp.vlans.items():
            self.assertIs(
                old_vlans[vid].dyn_host_cache_by_port, vlan.dyn_host_cache_by_port
            )
        self.assertIsNone(port.hosts_counter)
        self.assertEqual(3, port.hosts_count())
        self.assertIsNone(old_port.hosts_counter.count)
        self.assertEqual(0, valve.dp.ports[3].hosts_count())
        self.assertTrue(self._is_ban(self._learn(1, 0x200, "0e:00:00:00:01:04"), 1))
        # A host learned before the warm start still leaves the new port's count.
        self._expire(learn_timeout // 2 + 1)
        self.assertEqual(2, port.hosts_count())
        self.assertFalse(self._is_ban(self._learn(1, 0x200, "0e:00:00:00:01:04"), 1))
        self.assertEqual(3, port.hosts_count())
        self._check_hosts_counts("after a port change")

        # A change to one of its VLANs changes the trunk, which clears its hosts.
        self.update_config(variants[5], reload_type="warm")
        port = valve.dp.ports[1]
        self.assertEqual(0, port.hosts_count())
        for vid in self.VIDS:
            self.assertFalse(self._is_ban(self._learn(1, vid, "0e:00:00:00:01:05"), 1))
        self.assertEqual(3, port.hosts_count())
        self.assertTrue(self._is_ban(self._learn(1, 0x300, "0e:00:00:00:01:06"), 1))
        self._check_hosts_counts("after a VLAN change")

    def _random_change(self, rng, variants, seen):
        """Make one random change to the hosts, ports or config."""
        valve = self._valve()
        learn_timeout = valve.switch_manager.learn_timeout
        guard_time = valve.switch_manager.cache_update_guard_time
        port_no = rng.choice(tuple(valve.dp.ports))
        action = rng.choice(
            ("learn",) * 8
            + ("time", "time", "expire", "port", "link", "dot1x")
            + ("reload", "reload", "cold_start")
        )
        if action == "learn":
            vid = rng.choice(self.VIDS)
            eth_src = "0e:00:00:00:00:%02x" % rng.randint(1, 12)
            entry = valve.dp.vlans[vid].cached_host(eth_src)
            seen["moves"] += entry is not None and entry.port.number != port_no
            seen["bans"] += self._is_ban(self._learn(port_no, vid, eth_src), port_no)
        elif action == "time":
            self.mock_time(rng.choice((1, guard_time + 1)))
        elif action == "expire":
            self._expire(rng.choice((1, guard_time, learn_timeout + 1)))
        elif action in ("port", "link"):
            set_down, set_up = {
                "port": (self.set_port_down, self.set_port_up),
                "link": (self.set_port_link_down, self.set_port_link_up),
            }[action]
            set_down(port_no)
            self._check_hosts_counts("%s %u down" % (action, port_no))
            set_up(port_no)
        elif action == "dot1x" and port_no != 4:
            vlan_name = rng.choice((None, "v100", "v200", "v300"))
            if vlan_name is None:
                self.apply_ofmsgs(valve.del_dot1x_native_vlan(port_no))
            else:
                self.apply_ofmsgs(valve.add_dot1x_native_vlan(port_no, vlan_name))
        elif action == "reload":
            seen["variant"] = rng.choice(
                [i for i in range(len(variants)) if i != seen["variant"]]
            )
            self.update_config(variants[seen["variant"]], reload_type=None)
        elif action == "cold_start":
            self.cold_start()
        return action

    def test_hosts_count_matches_vlans(self):
        """Test port host counts against counting their VLANs, in random changes."""
        variants = self._config_variants()
        warm_starts = self.get_prom("faucet_config_reload_warm_total")
        seen = {"moves": 0, "bans": 0}
        for seed in range(2):
            rng = random.Random(seed)
            seen["variant"] = 0
            for step in range(150):
                action = self._random_change(rng, variants, seen)
                self._check_hosts_counts("seed %u step %u %s" % (seed, step, action))
            self.update_config(variants[0], reload_type=None)
            self.cold_start()
        self.assertGreater(
            self.get_prom("faucet_config_reload_warm_total"), warm_starts
        )
        self.assertTrue(seen["moves"])
        self.assertTrue(seen["bans"])


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


class ValvePacketInMetricsTestCase(ValveTestBases.ValveTestNetwork):
    """Test which VLANs' metrics a packet in updates."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [v100, v200]
            p2:
                number: 2
                native_vlan: v100
            p3:
                number: 3
                tagged_vlans: [v100, v200]
                lacp: 1
            p4:
                number: 4
                native_vlan: v200
                tagged_vlans: [v100]
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup ports on two VLANs"""
        self.setup_valves(self.CONFIG)
        self.activate_all_ports()

    def _packet_in(self, port, vid, match):
        """Send a packet in as faucet does, without rcv_packet()'s metric_update."""
        valve = self.valves_manager.valves[self.DP_ID]
        if vid:
            match = dict(match, vid=vid)
        pkt = build_pkt(match)
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

    def _learn(self, port, vid, eth_src):
        self._packet_in(
            port,
            vid,
            {
                "eth_src": eth_src,
                "eth_dst": self.UNKNOWN_MAC,
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.2",
            },
        )

    def _hosts_learned(self, port_name, vid):
        vlan_labels = {"vlan": str(vid)}
        port_labels = dict(vlan_labels, port=port_name, port_description=port_name)
        return (
            self.get_prom("vlan_hosts_learned", labels=vlan_labels),
            self.get_prom("port_vlan_hosts_learned", labels=port_labels),
        )

    def test_packet_in_updates_own_vlan(self):
        """Test a packet in updates its own VLAN and no other VLAN of its port."""
        valve = self.valves_manager.valves[self.DP_ID]
        port = valve.dp.ports[1]
        # Learned, but not yet in metrics.
        valve.dp.vlans[0x200].add_cache_host(self.P1_V200_MAC, port, self.mock_time())
        self._learn(1, 0x100, self.P1_V100_MAC)
        self.assertEqual((1, 1), self._hosts_learned("p1", 0x100))
        self.assertEqual((0, 0), self._hosts_learned("p1", 0x200))
        self._learn(2, 0x100, self.P2_V100_MAC)
        self.assertEqual((2, 1), self._hosts_learned("p2", 0x100))
        self.assertEqual((0, 0), self._hosts_learned("p1", 0x200))
        self.valves_manager.update_metrics(self.mock_time())
        self.assertEqual((2, 1), self._hosts_learned("p1", 0x100))
        self.assertEqual((1, 1), self._hosts_learned("p1", 0x200))

    def test_packet_in_tagged_vlan_skips_native_vlan(self):
        """Test a packet in on a tagged VLAN does not update the port's native VLAN."""
        valve = self.valves_manager.valves[self.DP_ID]
        port = valve.dp.ports[4]
        # Learned, but not yet in metrics.
        valve.dp.vlans[0x200].add_cache_host(
            "00:00:00:02:00:04", port, self.mock_time()
        )
        self._learn(4, 0x100, "00:00:00:01:00:04")
        self.assertEqual((1, 1), self._hosts_learned("p4", 0x100))
        self.assertEqual((0, 0), self._hosts_learned("p4", 0x200))

    def test_packet_in_vlan_not_on_port(self):
        """Test a packet in on a VLAN its port is not on updates no port metrics."""
        valve = self.valves_manager.valves[self.DP_ID]
        port = valve.dp.ports[2]
        # Learned on the port's own VLAN, but not yet in metrics.
        valve.dp.vlans[0x100].add_cache_host(self.P2_V100_MAC, port, self.mock_time())
        self._learn(2, 0x200, self.P2_V200_MAC)
        self.assertEqual((0, 0), self._hosts_learned("p2", 0x100))
        port_labels = {
            "vlan": str(0x200),
            "port": "p2",
            "port_description": "p2",
            "dp_name": self.DP_NAME,
            "dp_id": "0x%x" % self.DP_ID,
        }
        self.assertIsNone(
            self.registry.get_sample_value("port_vlan_hosts_learned", port_labels)
        )

    def test_non_vlan_packet_in_updates_all_vlans(self):
        """Test a packet in with no VLAN (LACP) updates every VLAN of its port."""
        valve = self.valves_manager.valves[self.DP_ID]
        port = valve.dp.ports[3]
        for vid, eth_src in ((0x100, self.P3_V100_MAC), (0x200, self.P3_V200_MAC)):
            valve.dp.vlans[vid].add_cache_host(eth_src, port, self.mock_time())
        self._packet_in(
            3,
            0,
            {
                "actor_system": "0e:00:00:00:00:02",
                "partner_system": FAUCET_MAC,
                "eth_dst": slow.SLOW_PROTOCOL_MULTICAST,
                "eth_src": "0e:00:00:00:00:02",
                "actor_state_synchronization": 1,
            },
        )
        self.assertEqual((1, 1), self._hosts_learned("p3", 0x100))
        self.assertEqual((1, 1), self._hosts_learned("p3", 0x200))


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


class ValveLACPPortDownTestCase(ValveTestBases.ValveTestNetwork):
    """Test the flows left when an LACP port with LACP up goes down."""

    # p5 keeps the pipeline the same when p2 stops being a hairpin port.
    CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: "Open vSwitch"
        interfaces:
            p1:
                number: 1
                tagged_vlans: [%(p1_vlans)s]
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
"""

    REQUIRE_TFM = False

    def config(self, p1_vlans="v100, v200", p1_max_hosts=255, p2_hairpin="true"):
        """Return CONFIG with p1's VLANs and max_hosts, and p2's hairpin."""
        return self.CONFIG % {
            "p1_vlans": p1_vlans,
            "p1_max_hosts": p1_max_hosts,
            "p2_hairpin": p2_hairpin,
        }

    def setUp(self):
        """Set up the DP and bring up LACP on p1."""
        self.setup_valves(self.config())
        self.rcv_packet(
            1,
            0,
            {
                "actor_system": "0e:00:00:00:00:02",
                "partner_system": FAUCET_MAC,
                "eth_dst": slow.SLOW_PROTOCOL_MULTICAST,
                "eth_src": "0e:00:00:00:00:02",
                "actor_state_synchronization": 1,
            },
        )

    def table_flows(self, table_name):
        """Return the flows in the DP's table_name table."""
        valve = self.valves_manager.valves[self.DP_ID]
        table_id = valve.dp.tables[table_name].table_id
        return self.network.tables[self.DP_ID].tables[table_id]

    def port_flows(self, table_name, port_no):
        """Return the flows in table_name that match in_port port_no."""
        return [
            flow
            for flow in self.table_flows(table_name)
            if "in_port" in flow.match_values
            and flow.match_values["in_port"].int == port_no
        ]

    def flows(self):
        """Return every flow on the DP, comparably."""
        return sorted(
            str(flow)
            for table in self.network.tables[self.DP_ID].tables
            for flow in table
        )

    def hairpin_flood_flows(self, port_no):
        """Return the flood flows that flood from port_no back out of it."""
        return [
            flow
            for flow in self.port_flows("flood", port_no)
            for instruction in flow.instructions
            for action in getattr(instruction, "actions", ())
            if getattr(action, "port", None) == ofp.OFPP_IN_PORT
        ]

    def vlan_flows(self, port_no, vid):
        """Return the vlan table's flows for port_no on VLAN vid."""
        return [
            flow
            for flow in self.port_flows("vlan", port_no)
            if "vlan_vid" in flow.match_values
            and flow.match_values["vlan_vid"].int == vid | ofp.OFPVID_PRESENT
        ]

    def assert_cold_start_flows(self):
        """Assert a cold start leaves the DP with the flows it has now."""
        flows = self.flows()
        self.cold_start()
        self.assertEqual(flows, self.flows())

    def test_warm_start_no_longer_hairpin(self):
        """Test p2 loses its hairpin flood flows in a warm start changing p1."""
        self.assertTrue(self.hairpin_flood_flows(2))
        self.update_config(
            self.config(p1_max_hosts=5, p2_hairpin="false"), reload_type="warm"
        )
        self.assertFalse(self.hairpin_flood_flows(2))
        self.assert_cold_start_flows()

    def test_warm_start_leaves_vlan(self):
        """Test p1 takes in no v200 traffic once a warm start removes it."""
        self.assertTrue(self.vlan_flows(1, 0x200))
        self.update_config(self.config(p1_vlans="v100"), reload_type="warm")
        self.assertFalse(self.vlan_flows(1, 0x200))
        self.assert_cold_start_flows()

    def test_port_down(self):
        """Test p1 down keeps only its drop flow, and the flood flows without it."""
        self.set_port_link_down(1)
        self.assertEqual(
            [[]], [list(flow.instructions) for flow in self.port_flows("vlan", 1)]
        )
        flood_flows = sorted(str(flow) for flow in self.table_flows("flood"))
        self.valves_manager.valves[self.DP_ID].datapath_disconnect(self.mock_time())
        self.connect_dp(ports_up=[2, 3, 4, 5])
        self.assertEqual(
            flood_flows, sorted(str(flow) for flow in self.table_flows("flood"))
        )


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
    GW_MAC = "00:00:00:01:00:99"
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

    def _reply(self, ipv, port, host_ip=None, eth_src=None):
        """Have the host, or host_ip at eth_src, answer faucet's request, by
        ARP or by ND."""
        if host_ip is None:
            host_ip, eth_src = self.HOST_IPS[ipv], self.HOST_MAC
        match = {"eth_src": eth_src, "eth_dst": self._vlan().faucet_mac}
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

    def _resolve_static_gw(self, ipv):
        """Have the static routes' gateway answer faucet's request from the
        trunk, and return its address."""
        ip_gw = ip_address(self.STATIC_GWS[ipv])
        self.assertTrue([run for run in self._resolvers(3, secs=2) if ip_gw in run])
        self._reply(ipv, self.TRUNK_PORT, str(ip_gw), self.GW_MAC)
        entry = self._vlan().neigh_cache_by_ipv(ipv)[ip_gw]
        self.assertEqual(self.GW_MAC, entry.eth_src)
        self.assertEqual(self.TRUNK_PORT, entry.port.number)
        return ip_gw

    def _runs_to_request(self, ip_gw):
        """Run the resolvers every 2s, as faucet does, with nothing answering,
        and return how many runs it takes to request ip_gw (one more than
        max_resolve_backoff_time if it is not requested by then)."""
        runs = self._valve().dp.max_resolve_backoff_time
        for run in range(1, runs + 1):
            if ip_gw in self._resolvers(1, secs=2)[0]:
                return run
        return runs + 1

    def _test_route_gw_port_outage(self, ipv, secs, other_ports=True):
        """Test a gateway a route uses, on a trunk down for secs, is requested
        again by the second resolver run after the trunk is up, as a gateway
        new to the cache is, and resolved when it answers. With no other port
        of its VLAN up, no request goes out while the trunk is down."""
        ip_gw = self._resolve_static_gw(ipv)
        if not other_ports:
            self.set_port_down(1)
            self.set_port_down(2)
        down = self._trunk_down(secs)
        sent_down = len([run for run in down if ip_gw in run])
        if other_ports:
            self.assertGreater(sent_down, 0)
        else:
            self.assertEqual(0, sent_down)
        self.set_port_up(self.TRUNK_PORT)
        self.assertLessEqual(self._runs_to_request(ip_gw), 2)
        # That request is lost: the next follows as soon, too.
        self.assertLessEqual(self._runs_to_request(ip_gw), 2)
        self._reply(ipv, self.TRUNK_PORT, str(ip_gw), self.GW_MAC)
        entry = self._vlan().neigh_cache_by_ipv(ipv)[ip_gw]
        self.assertEqual(self.GW_MAC, entry.eth_src)
        self.assertEqual(self.TRUNK_PORT, entry.port.number)

    def _test_route_gw_port_flaps(self, ipv):
        """Test a gateway a route uses that stops answering, behind a trunk
        that goes down again and again, is requested again at once only the
        first time the trunk is up."""
        ip_gw = self._resolve_static_gw(ipv)
        self._trunk_down(300)
        self.set_port_up(self.TRUNK_PORT)
        self.assertLessEqual(self._runs_to_request(ip_gw), 2)
        for _ in range(5):
            self._trunk_down(300)
            self.set_port_up(self.TRUNK_PORT)
            entry = self._vlan().neigh_cache_by_ipv(ipv)[ip_gw]
            self.assertGreater(entry.resolve_retries, 1)

    def _test_route_gw_silent_port_outage(self, ipv):
        """Test a gateway a route uses that missed more requests than a host
        is sent before it is dead, and then went down with its trunk, is
        requested again by the second resolver run after the trunk is up."""
        valve = self._valve()
        ip_gw = self._resolve_static_gw(ipv)
        retries = valve.dp.max_host_fib_retry_count
        self._resolvers(retries)
        entry = self._vlan().neigh_cache_by_ipv(ipv)[ip_gw]
        self.assertGreaterEqual(entry.resolve_retries, retries)
        self.assertEqual(self.GW_MAC, entry.eth_src)
        self._trunk_down(300)
        self.set_port_up(self.TRUNK_PORT)
        self.assertLessEqual(self._runs_to_request(ip_gw), 2)

    def _test_route_gw_other_port_up(self, ipv):
        """Test another port coming up while a gateway's trunk is down leaves
        the gateway's requests as they were, to be restarted once the trunk
        is up."""
        ip_gw = self._resolve_static_gw(ipv)
        self._trunk_down(300)
        nexthop_cache = self._vlan().neigh_cache_by_ipv(ipv)
        entry = nexthop_cache[ip_gw]
        retries = entry.resolve_retries
        self.assertGreater(retries, 1)
        self.set_port_down(1)
        self.set_port_up(1)
        self.assertIs(entry, nexthop_cache.get(ip_gw))
        self.assertEqual(retries, entry.resolve_retries)
        self._resolvers(150, secs=2)
        self.set_port_up(self.TRUNK_PORT)
        self.assertLessEqual(self._runs_to_request(ip_gw), 2)

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

    def test_route_gw_port_outage_5m_ipv4(self):
        """Test an IPv4 gateway a route uses is requested at once after a
        5 minute outage of its port."""
        self._test_route_gw_port_outage(4, 300)

    def test_route_gw_port_outage_5m_ipv6(self):
        """Test an IPv6 gateway a route uses is requested at once after a
        5 minute outage of its port."""
        self._test_route_gw_port_outage(6, 300)

    def test_route_gw_port_outage_30s_ipv4(self):
        """Test an IPv4 gateway a route uses is requested at once after a
        30 second outage of its port."""
        self._test_route_gw_port_outage(4, 30)

    def test_route_gw_only_port_outage_ipv4(self):
        """Test an IPv4 gateway a route uses is requested at once after a
        5 minute outage of the only port up on its VLAN."""
        self._test_route_gw_port_outage(4, 300, other_ports=False)

    def test_route_gw_only_port_outage_ipv6(self):
        """Test an IPv6 gateway a route uses is requested at once after a
        5 minute outage of the only port up on its VLAN."""
        self._test_route_gw_port_outage(6, 300, other_ports=False)

    def test_route_gw_port_flaps_ipv4(self):
        """Test a silent IPv4 gateway a route uses is requested again at
        once only the first time its flapping port is up."""
        self._test_route_gw_port_flaps(4)

    def test_route_gw_port_flaps_ipv6(self):
        """Test a silent IPv6 gateway a route uses is requested again at
        once only the first time its flapping port is up."""
        self._test_route_gw_port_flaps(6)

    def test_route_gw_silent_port_outage_ipv4(self):
        """Test an IPv4 gateway a route uses that went silent before its port
        went down is requested at once after the outage."""
        self._test_route_gw_silent_port_outage(4)

    def test_route_gw_silent_port_outage_ipv6(self):
        """Test an IPv6 gateway a route uses that went silent before its port
        went down is requested at once after the outage."""
        self._test_route_gw_silent_port_outage(6)

    def test_route_gw_other_port_up_ipv4(self):
        """Test another port up leaves an IPv4 gateway on a trunk still down
        as it was."""
        self._test_route_gw_other_port_up(4)

    def test_route_gw_other_port_up_ipv6(self):
        """Test another port up leaves an IPv6 gateway on a trunk still down
        as it was."""
        self._test_route_gw_other_port_up(6)

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

    def _update_port_desc(self, port_nos, port_nos_up=None, more=False):
        descs = self._build_port_descs(port_nos, port_nos_up)
        ofmsgs_by_valve = self.valve.port_desc_stats_reply_handler(
            descs, [], time.time(), more=more
        )
        return ofmsgs_by_valve.get(self.valve, [])

    def test_unconfigured_ports(self):
        port_nos = [11, 12]
        port_nos_up = [12]
        ofmsgs = self._update_port_desc(port_nos, port_nos_up)

        self.assertTrue(self.valve.dp.dyn_up_port_nos == set(port_nos_up))
        self.assertFalse(ofmsgs)

    def test_cold_start_asks_port_desc_after_async(self):
        """Test a cold start asks for port descriptions after its async config.

        A port that changes state while the datapath connects reports it
        before the async config allows the report through, so only the
        second description, taken after it, shows the change.
        """
        ofmsgs = self.valve.datapath_connect(time.time(), set())
        sent = [type(ofmsg) for ofmsg in self.valve.prepare_send_flows(ofmsgs)]
        self.assertIn(valve_of.parser.OFPPortDescStatsRequest, sent)
        self.assertLess(
            sent.index(valve_of.parser.OFPSetAsync),
            sent.index(valve_of.parser.OFPPortDescStatsRequest),
        )

    def test_split_reply_judged_whole(self):
        """Test a reply split across messages is judged only once complete.

        A switch with more ports than fit one message describes them in
        parts. A port missing from one part is described in another, so
        no part on its own may take a port down.
        """
        port_nos = [1, 2]
        self.assertTrue(self._update_port_desc(port_nos, port_nos_up=port_nos))
        self.assertEqual(set(port_nos), self.valve.dp.dyn_up_port_nos)

        # The same ports, split across two parts: nothing changed.
        self.assertFalse(self._update_port_desc([1], port_nos_up=[1], more=True))
        self.assertEqual(set(port_nos), self.valve.dp.dyn_up_port_nos)
        self.assertFalse(self._update_port_desc([2], port_nos_up=[2]))
        self.assertEqual(set(port_nos), self.valve.dp.dyn_up_port_nos)

        # The same ports in one message: the control.
        self.assertFalse(self._update_port_desc(port_nos, port_nos_up=port_nos))
        self.assertEqual(set(port_nos), self.valve.dp.dyn_up_port_nos)

        # A change in the first part is acted on once the last has arrived.
        self.assertFalse(self._update_port_desc([1], port_nos_up=[], more=True))
        self.assertEqual(set(port_nos), self.valve.dp.dyn_up_port_nos)
        ofmsgs = self._update_port_desc([2], port_nos_up=[2])
        self.assertEqual({2}, self.valve.dp.dyn_up_port_nos)
        self.assertTrue(self._inport_flows(1, ofmsgs))
        self.assertFalse(self._inport_flows(2, ofmsgs))

    def test_split_reply_flag_read_from_message(self):
        """Test a reply part's flag that more parts follow is acted on."""
        self.assertTrue(self._update_port_desc([1, 2], port_nos_up=[1, 2]))
        for port_nos, flags in (([1], valve_of.ofp.OFPMPF_REPLY_MORE), ([2], 0)):
            msg = valve_of.parser.OFPPortDescStatsReply(
                None, body=self._build_port_descs(port_nos, port_nos), flags=flags
            )
            self.valves_manager.port_desc_stats_reply_handler(
                self.valve, msg, time.time()
            )
            self.assertEqual({1, 2}, self.valve.dp.dyn_up_port_nos)

    def test_partial_reply_dropped_on_reconnect(self):
        """Test the parts of an unfinished reply do not outlive the connection."""
        self.assertFalse(self._update_port_desc([2], port_nos_up=[2], more=True))
        self.valve.datapath_disconnect(time.time())
        self.valve.datapath_connect(time.time(), {1, 2})
        self.assertEqual({1, 2}, self.valve.dp.dyn_up_port_nos)
        # A complete reply from the new connection without port 2 takes it
        # down; the stale part from before must not keep it up.
        ofmsgs = self._update_port_desc([1], port_nos_up=[1])
        self.assertEqual({1}, self.valve.dp.dyn_up_port_nos)
        self.assertTrue(self._inport_flows(2, ofmsgs))

    def test_partial_reply_dropped_on_connect_alone(self):
        """Test a connection that replaces one never seen to drop also drops
        the parts of an unfinished reply."""
        self.assertFalse(self._update_port_desc([2], port_nos_up=[2], more=True))
        self.valve.datapath_connect(time.time(), {1, 2})
        ofmsgs = self._update_port_desc([1], port_nos_up=[1])
        self.assertEqual({1}, self.valve.dp.dyn_up_port_nos)
        self.assertTrue(self._inport_flows(2, ofmsgs))

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

    def test_ports_before_cold_start(self):
        """Test ports up before a cold start add their flows with it, not before."""
        self.disconnect_dp()
        self.assertFalse(self.valve.dp.dyn_running)
        ofmsgs = self._update_port_desc([1, 2], [1, 2])
        self.assertEqual(self.valve.dp.dyn_up_port_nos, {1, 2})
        self.assertFalse(ValveTestBases.flowmods_from_flows(ofmsgs))

        ofmsgs = self.connect_dp(ports_up=[1, 2])
        self.assertTrue(self._inport_flows(1, ofmsgs))
        self.assertTrue(self._inport_flows(2, ofmsgs))
        self.assertTrue(self.valve.dp.ports[1].dyn_phys_up)
        self.assertTrue(self.valve.dp.ports[2].dyn_phys_up)


class ValvePortDescAlwaysUpTestCase(ValveTestBases.ValveTestNetwork):
    """Test OFPMP_PORT_DESC reply handling of a port ignoring its status."""

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
                opstatus_reconf: false
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup with both ports up."""
        self.setup_valves(self.CONFIG, ports_up=[1, 2])
        self.valve = self.valves_manager.valves[self.DP_ID]
        self.assertEqual({1, 2}, self.valve.dp.dyn_up_port_nos)

    def test_link_down_reply_keeps_port_up(self):
        """Test a reply showing the port link-down leaves it up.

        The cold start brought the port up regardless of its link, and a
        later change to the port must find it up to give it flows.
        """
        descs = ValvePortDescTestCase._build_port_descs([1, 2], port_nos_up=[1])
        ofmsgs_by_valve = self.valve.port_desc_stats_reply_handler(
            descs, [], time.time()
        )
        self.assertFalse(ofmsgs_by_valve.get(self.valve, []))
        self.assertEqual({1, 2}, self.valve.dp.dyn_up_port_nos)

        config = yaml_load(self.CONFIG)
        port_conf = config["dps"]["s1"]["interfaces"]["p2"]
        del port_conf["native_vlan"]
        port_conf["tagged_vlans"] = ["v100", "v200"]
        self.update_config(yaml_dump(config), reload_type="warm")
        self.assertTrue(
            self.network.tables[self.DP_ID].is_output(
                {
                    "in_port": 2,
                    "vlan_vid": 0x100 | valve_of.ofp.OFPVID_PRESENT,
                    "eth_src": "00:00:00:00:00:02",
                    "eth_dst": "ff:ff:ff:ff:ff:ff",
                },
                port=1,
            ),
            "changed port has no flows",
        )


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
        self.assertEqual([], self.valve.oferror(error))
        _, ryu_dp = self._cold_start()
        bundle = self._bundle(ryu_dp)
        of_errors = self.get_prom("of_errors_total")
        # A flow mod the switch cannot apply has an error of its own, and
        # the switch still commits the rest of the bundle.
        error.xid = bundle[1].xid
        self.assertEqual([], self.valve.oferror(error))
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        self.assertEqual(1, self._atomic_status())
        # Failing the commit, it applies none of the bundle.
        error = parser.OFPErrorMsg(
            None, type_=ofp.OFPET_EXPERIMENTER, exp_type=2313, experimenter=0x4F4E4600
        )
        error.xid = bundle[-1].xid
        self.assertIsNone(self.valve.oferror(error))
        self.assertEqual((1, 0, 1, 0), self._bundle_counts())
        self.assertEqual(0, self._atomic_status())
        self.assertEqual(of_errors + 2, self.get_prom("of_errors_total"))
        self.assertEqual([], self.valve.oferror(error), "refused twice")
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
        self.assertEqual([], self.valve.oferror(error))
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
        self.assertIsNone(self.valve.oferror(self._open_error(ryu_dp)))
        self.assertEqual(of_errors + 1, self.get_prom("of_errors_total"))
        # The switch times a bundle out once: another timeout is only an error.
        self.assertEqual([], self.valve.oferror(self._open_error(ryu_dp)))
        self.assertEqual(of_errors + 2, self.get_prom("of_errors_total"))
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        # What the switch commits, or fails to, under the bundle's id is not
        # the bundle.
        self.valve.bundle_ctrl_reply(self._commit_reply(ryu_dp))
        self.assertEqual([], self.valve.oferror(self._commit_error(ryu_dp)))
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
            self.assertIsNone(self.valve.oferror(self._open_error(ryu_dp)))
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
            self.assertEqual(
                [], self.valve.oferror(self._open_error(other_dp, xid=open_xid))
            )
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        self.assertIsNone(self.valve.oferror(self._open_error(ryu_dp)))
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
            self.assertEqual([], self.valve.oferror(error))
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        error.xid = bundle[-1].xid
        self.assertIsNone(self.valve.oferror(error))
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
        self.assertEqual([], self.valve.oferror(error))
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
            self.assertEqual([], self.valve.oferror(error))
        self.assertEqual(of_errors + 2, self.get_prom("of_errors_total"))
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        # Nor is another experimenter's error of the timeout's type on the open.
        error = self._open_error(ryu_dp)
        error.experimenter = 0x2320
        self.assertEqual([], self.valve.oferror(error))
        # Nor a timeout that answers an add: the switch answers with the
        # message that made the bundle, so that is one it made of adds.
        self.assertEqual(
            [], self.valve.oferror(self._open_error(ryu_dp, xid=bundle[1].xid))
        )
        self.assertEqual((1, 0, 0, 0), self._bundle_counts())
        # The timeout that answers the bundle's open still discards it.
        self.assertIsNone(self.valve.oferror(self._open_error(ryu_dp)))
        # Committed or refused, a bundle's open has no answer to wait for.
        _, ryu_dp = self._cold_start()
        self.valve.bundle_ctrl_reply(self._commit_reply(ryu_dp))
        self.assertEqual([], self.valve.oferror(self._open_error(ryu_dp)))
        _, ryu_dp = self._cold_start()
        self.assertIsNone(self.valve.oferror(self._commit_error(ryu_dp)))
        self.assertEqual([], self.valve.oferror(self._open_error(ryu_dp)))
        self.valve.datapath_disconnect(self.mock_time())
        self.assertEqual((3, 1, 1, 1), self._bundle_counts())
        self.assertEqual(0, self._atomic_status())


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
