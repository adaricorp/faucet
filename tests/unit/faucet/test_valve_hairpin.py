#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valve_hairpin.py."""

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

from faucet import valve_of
from faucet.config_parser_util import yaml_load, yaml_dump

from clib.valve_test_lib import ValveTestBases


class ValveHairpinLearnTestCase(ValveTestBases.ValveTestNetwork):
    """Test learning hosts on a hairpin port."""

    # The hairpin option set on p1; subclasses test the others.
    HAIRPIN_OPTION = "hairpin_unicast"
    # The hairpin option of a port added next to p1, so that the datapath
    # mixes hairpin_routed with another hairpin option.
    OTHER_OPTION = "hairpin_routed"
    # The hairpin table's match fields, each mapped to whether it is
    # masked, while p1 is the only hairpin port.
    TABLE_MATCH_TYPES = {"in_port": False, "vlan_vid": False, "eth_dst": False}

    # A soft pipeline, so that config changes can warm start.
    REQUIRE_TFM = False

    # Both VLANs are routed for the tests of hairpin_routed: the subclass
    # that sets it on p1, and the tests here that give it to a port. Such
    # a port sends back only packets FAUCET routed, and FAUCET routes only
    # on a VLAN with faucet_vips.
    CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: Open vSwitch
        interfaces:
            p1:
                number: 1
                tagged_vlans: [v100, v200]
            p2:
                number: 2
                native_vlan: v100
            p3:
                number: 3
                native_vlan: v200
vlans:
    v100:
        vid: 0x100
        faucet_vips: ["10.100.0.254/24"]
    v200:
        vid: 0x200
        faucet_vips: ["10.200.0.254/24"]
routers:
    r1:
        vlans: [v100, v200]
"""

    def setUp(self):
        """Setup a hairpin port on two VLANs, and a port without hairpin on each"""
        self.setup_valves(yaml_dump(self._config()))

    def _config(self):
        """Return the config, with the hairpin option set on p1."""
        config = yaml_load(self.CONFIG)
        config["dps"]["s1"]["interfaces"]["p1"][self.HAIRPIN_OPTION] = True
        return config

    def _guard_time(self):
        """Return the time after which a host on the same port is refreshed."""
        valve = self.valves_manager.valves[self.DP_ID]
        return valve.switch_manager.cache_update_guard_time

    def _learn(self, port_no, vid, eth_src):
        """Receive a packet from a host, and return the flows sent."""
        return self.rcv_packet(
            port_no,
            vid,
            {
                "eth_src": eth_src,
                "eth_dst": self.UNKNOWN_MAC,
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.2",
            },
        )[self.DP_ID]

    def _hairpin_ofmsgs(self, ofmsgs, eth_dst=None):
        """Return the flowmods sent to the hairpin table."""
        valve = self.valves_manager.valves[self.DP_ID]
        table_id = valve.dp.tables["eth_dst_hairpin"].table_id
        return [
            ofmsg
            for ofmsg in ofmsgs
            if valve_of.is_flowmod(ofmsg)
            and ofmsg.table_id == table_id
            and (eth_dst is None or ofmsg.match.get("eth_dst") == eth_dst)
        ]

    def _hairpin_flowmods(self, ofmsgs, eth_dst=None):
        """Return the command and match of each flowmod sent to the hairpin table."""
        return [
            (ofmsg.command, dict(ofmsg.match.items()))
            for ofmsg in self._hairpin_ofmsgs(ofmsgs, eth_dst)
        ]

    def _faucet_mac(self, vid):
        """Return the FAUCET MAC of a VLAN."""
        return self.valves_manager.valves[self.DP_ID].dp.vlans[vid].faucet_mac

    def _hairpin_match(self, port_no, vid, eth_dst, option=None):
        """Return the match of a host's hairpin flow on a port with an option.

        The option defaults to p1's. A hairpin_routed port's flow also
        matches the VLAN's FAUCET MAC.
        """
        match = {
            "in_port": port_no,
            "vlan_vid": vid | ofp.OFPVID_PRESENT,
            "eth_dst": eth_dst,
        }
        if (option or self.HAIRPIN_OPTION) == "hairpin_routed":
            match["eth_src"] = self._faucet_mac(vid)
        return match

    def _replaced(self, port_no, vid, eth_dst, option=None):
        """Return the hairpin flowmods that replace a host's hairpin flow."""
        return [
            (
                ofp.OFPFC_DELETE,
                {"vlan_vid": vid | ofp.OFPVID_PRESENT, "eth_dst": eth_dst},
            ),
            (ofp.OFPFC_ADD, self._hairpin_match(port_no, vid, eth_dst, option)),
        ]

    def _assert_replaced(self, ofmsgs, port_no, vid, eth_dst, option=None):
        """Assert a host's hairpin flow is deleted, then added again."""
        self.assertEqual(
            self._replaced(port_no, vid, eth_dst, option),
            self._hairpin_flowmods(ofmsgs, eth_dst),
        )
        # A hairpin flow outputs only to IN_PORT, so a delete limited to
        # flows that output to the host's port would not remove it.
        delete = self._hairpin_ofmsgs(ofmsgs, eth_dst)[0]
        self.assertEqual(
            (ofp.OFPP_ANY, ofp.OFPG_ANY), (delete.out_port, delete.out_group)
        )

    def _hairpinned(self, port_no, vid, eth_dst):
        """Return True if a packet for a host is output back out of its port."""
        return self._switched_back(port_no, vid, eth_dst)

    def _switched_back(self, port_no, vid, eth_dst):
        """Return True if a packet switched to a host is output back out of its port."""
        port_outputs = self.network.tables[self.DP_ID].get_port_outputs(
            {
                "in_port": port_no,
                "vlan_vid": vid | ofp.OFPVID_PRESENT,
                "eth_src": self.UNKNOWN_MAC,
                "eth_dst": eth_dst,
                "eth_type": 0x800,
            }
        )
        # Only an output to IN_PORT leaves the switch: an output to a port
        # number equal to in_port is dropped.
        return ofp.OFPP_IN_PORT in port_outputs

    def _routed_back(self, port_no, vid, eth_dst):
        """Return True if a packet routed to a host is output back out of its port.

        Routing sets eth_src to the VLAN's FAUCET MAC, then sends the packet
        on to the hairpin table, so look it up there.
        """
        valve = self.valves_manager.valves[self.DP_ID]
        outputs, _, _ = self.network.tables[self.DP_ID].get_table_output(
            {
                "in_port": port_no,
                "vlan_vid": vid | ofp.OFPVID_PRESENT,
                "eth_src": self._faucet_mac(vid),
                "eth_dst": eth_dst,
                "eth_type": 0x800,
            },
            valve.dp.tables["eth_dst_hairpin"].table_id,
        )
        return ofp.OFPP_IN_PORT in outputs

    def _table_shape(self):
        """Return whether the hairpin table is exact match, and its match fields.

        Each match field maps to whether the table matches it masked.
        """
        table = self.valves_manager.valves[self.DP_ID].dp.tables["eth_dst_hairpin"]
        return table.exact_match, dict(table.match_types)

    def _port_hairpin_flows(self, port_no):
        """Return the hairpin table's flows for packets in on a port."""
        valve = self.valves_manager.valves[self.DP_ID]
        table_id = valve.dp.tables["eth_dst_hairpin"].table_id
        return sorted(
            str(flow)
            for flow in self.network.tables[self.DP_ID].tables[table_id]
            if "in_port" in flow.match_values
            and flow.match_values["in_port"].int == port_no
        )

    def test_refresh_replaces_hairpin_flow(self):
        """Test refreshing a host deletes its hairpin flow before adding it.

        An add that replaces a flow need not restart its idle timeout, so
        an unused hairpin flow would otherwise idle out while its host is
        still learned.
        """
        self._learn(1, 0x100, self.P1_V100_MAC)
        self.mock_time(self._guard_time() + 1)
        self._assert_replaced(
            self._learn(1, 0x100, self.P1_V100_MAC), 1, 0x100, self.P1_V100_MAC
        )

    def test_relearn_after_port_status(self):
        """Test re-learning a host after a port status replaces its hairpin flow."""
        self._learn(1, 0x100, self.P1_V100_MAC)
        # A later port status, even one that changes nothing, makes the
        # next learn on the port a re-learn rather than a refresh.
        self.mock_time()
        self.set_port_link_up(1)
        self.mock_time(self._guard_time() + 1)
        self._assert_replaced(
            self._learn(1, 0x100, self.P1_V100_MAC), 1, 0x100, self.P1_V100_MAC
        )

    def test_relearn_on_port_added_warm(self):
        """Test re-learning a host on a hairpin port a warm start added while up."""
        # The switch reports the port up before the config has it.
        self.set_port_up(4)
        config = self._config()
        config["dps"]["s1"]["interfaces"]["p4"] = {
            "number": 4,
            "tagged_vlans": ["v100"],
            self.HAIRPIN_OPTION: True,
        }
        self.update_config(yaml_dump(config), reload_type="warm")
        self._learn(4, 0x100, self.P1_V100_MAC)
        for _ in range(2):
            self.mock_time(self._guard_time() + 1)
            self._assert_replaced(
                self._learn(4, 0x100, self.P1_V100_MAC), 4, 0x100, self.P1_V100_MAC
            )

    def test_mixed_hairpin_port_added_warm(self):
        """Test warm adding, then removing, a port with another hairpin option.

        While hairpin_routed and another hairpin option share the datapath,
        the hairpin table matches eth_src, unmasked, and is not exact match.
        Neither change removes or alters the flows of the hairpin port
        already there.
        """
        self._learn(1, 0x100, self.P1_V100_MAC)
        flows = self._port_hairpin_flows(1)
        self.assertTrue(flows)
        self.assertEqual((True, self.TABLE_MATCH_TYPES), self._table_shape())
        self.set_port_up(4)
        config = self._config()
        config["dps"]["s1"]["interfaces"]["p4"] = {
            "number": 4,
            "tagged_vlans": ["v100"],
            self.OTHER_OPTION: True,
        }
        self.update_config(yaml_dump(config), reload_type="warm")
        self.assertEqual(
            (False, {**self.TABLE_MATCH_TYPES, "eth_src": False}), self._table_shape()
        )
        self.assertEqual(flows, self._port_hairpin_flows(1))
        self.assertTrue(self._hairpinned(1, 0x100, self.P1_V100_MAC))
        self._assert_replaced(
            self._learn(4, 0x100, self.P2_V100_MAC),
            4,
            0x100,
            self.P2_V100_MAC,
            self.OTHER_OPTION,
        )
        self.mock_time(self._guard_time() + 1)
        self._assert_replaced(
            self._learn(1, 0x100, self.P1_V100_MAC), 1, 0x100, self.P1_V100_MAC
        )
        self.update_config(yaml_dump(self._config()), reload_type="warm")
        self.assertEqual((True, self.TABLE_MATCH_TYPES), self._table_shape())
        self.assertEqual(flows, self._port_hairpin_flows(1))
        self.assertTrue(self._hairpinned(1, 0x100, self.P1_V100_MAC))
        self.mock_time(self._guard_time() + 1)
        self._assert_replaced(
            self._learn(1, 0x100, self.P1_V100_MAC), 1, 0x100, self.P1_V100_MAC
        )

    def _change_option_warm(self, config):
        """Learn a host on p1, then warm start with p1's option changed.

        p1 takes the other option in place of its own. The warm start
        deletes the flows the old option added, so none of them outlives it,
        and the host's next learn adds its flow as the new option says.
        """
        self._learn(1, 0x100, self.P1_V100_MAC)
        self.assertTrue(self._port_hairpin_flows(1))
        interface = config["dps"]["s1"]["interfaces"]["p1"]
        del interface[self.HAIRPIN_OPTION]
        interface[self.OTHER_OPTION] = True
        self.update_config(yaml_dump(config), reload_type="warm")
        self.assertEqual([], self._port_hairpin_flows(1))
        self.mock_time(self._guard_time() + 1)
        self._learn(1, 0x100, self.P1_V100_MAC)
        self.assertEqual(1, len(self._port_hairpin_flows(1)))
        self.assertTrue(self._routed_back(1, 0x100, self.P1_V100_MAC))
        self.assertEqual(
            self.OTHER_OPTION != "hairpin_routed",
            self._switched_back(1, 0x100, self.P1_V100_MAC),
        )

    def test_option_changed_warm(self):
        """Test a warm start that changes a port's hairpin option."""
        self._change_option_warm(self._config())

    def test_option_changed_warm_without_idle_dst(self):
        """Test a warm start that changes a port's hairpin option, without idle_dst.

        Hairpin flows then have no idle timeout, so a flow the old option
        added would never go.
        """
        config = self._config()
        config["dps"]["s1"]["idle_dst"] = False
        self.update_config(yaml_dump(config), reload_type="cold")
        self._change_option_warm(config)

    def test_learn_after_vlan_warm_start(self):
        """Test learning a host after a warm start changed its VLAN.

        The warm start empties the VLAN's host cache, so the next learn
        deletes no host first: it deletes the host's hairpin flow, in case
        the switch still has one, before adding it.
        """
        self._learn(1, 0x100, self.P1_V100_MAC)
        # A change to the VLAN's own config starts it with an empty cache.
        config = self._config()
        config["vlans"]["v100"]["unicast_flood"] = False
        self.update_config(yaml_dump(config), reload_type="warm")
        self._assert_replaced(
            self._learn(1, 0x100, self.P1_V100_MAC), 1, 0x100, self.P1_V100_MAC
        )

    def test_refresh_without_idle_dst(self):
        """Test a hairpin flow that cannot idle out is not deleted on a refresh."""
        config = self._config()
        config["dps"]["s1"]["idle_dst"] = False
        self.update_config(yaml_dump(config), reload_type="cold")
        self._learn(1, 0x100, self.P1_V100_MAC)
        self.mock_time(self._guard_time() + 1)
        self.assertEqual(
            [(ofp.OFPFC_ADD, self._hairpin_match(1, 0x100, self.P1_V100_MAC))],
            self._hairpin_flowmods(
                self._learn(1, 0x100, self.P1_V100_MAC), self.P1_V100_MAC
            ),
        )

    def test_learn_without_hairpin(self):
        """Test learning a host on a port without hairpin sends no hairpin flows."""
        self.assertEqual(
            [], self._hairpin_flowmods(self._learn(2, 0x100, self.P2_V100_MAC))
        )
        # A refresh.
        self.mock_time(self._guard_time() + 1)
        self.assertEqual(
            [], self._hairpin_flowmods(self._learn(2, 0x100, self.P2_V100_MAC))
        )
        # A re-learn after a port status.
        self.mock_time()
        self.set_port_link_up(2)
        self.mock_time(self._guard_time() + 1)
        self.assertEqual(
            [], self._hairpin_flowmods(self._learn(2, 0x100, self.P2_V100_MAC))
        )

    def test_refresh_keeps_other_vlan(self):
        """Test refreshing a host on one VLAN keeps its hairpin flow on another."""
        self._learn(1, 0x100, self.P1_V100_MAC)
        self._learn(1, 0x200, self.P1_V100_MAC)
        self.assertTrue(self._hairpinned(1, 0x200, self.P1_V100_MAC))
        self.mock_time(self._guard_time() + 1)
        self._learn(1, 0x100, self.P1_V100_MAC)
        self.assertTrue(self._hairpinned(1, 0x100, self.P1_V100_MAC))
        self.assertTrue(self._hairpinned(1, 0x200, self.P1_V100_MAC))

    def test_refresh_keeps_hairpinning(self):
        """Test a host is still hairpinned after it is refreshed."""
        self._learn(1, 0x100, self.P1_V100_MAC)
        self.assertTrue(self._hairpinned(1, 0x100, self.P1_V100_MAC))
        self.mock_time(self._guard_time() + 1)
        self._learn(1, 0x100, self.P1_V100_MAC)
        self.assertTrue(self._hairpinned(1, 0x100, self.P1_V100_MAC))

    def test_move_replaces_hairpin_flow(self):
        """Test moving a host to and from a hairpin port."""
        self._learn(2, 0x100, self.P2_V100_MAC)
        self.mock_time(self._guard_time() + 1)
        self._assert_replaced(
            self._learn(1, 0x100, self.P2_V100_MAC), 1, 0x100, self.P2_V100_MAC
        )
        self.assertTrue(self._hairpinned(1, 0x100, self.P2_V100_MAC))
        self.mock_time(self._guard_time() + 1)
        self.assertEqual(
            self._replaced(1, 0x100, self.P2_V100_MAC)[:1],
            self._hairpin_flowmods(
                self._learn(2, 0x100, self.P2_V100_MAC), self.P2_V100_MAC
            ),
        )
        self.assertFalse(self._hairpinned(1, 0x100, self.P2_V100_MAC))


class ValveHairpinAllLearnTestCase(ValveHairpinLearnTestCase):
    """Test learning hosts on a port that hairpins all traffic."""

    HAIRPIN_OPTION = "hairpin"


class ValveHairpinIdleLearnTestCase(ValveHairpinLearnTestCase):
    """Test learning hosts on a hairpin port, with idle-flow based learning."""

    def _config(self):
        """Return the config, learning from idle flows, without idle_dst."""
        config = super()._config()
        config["dps"]["s1"]["use_idle_timeout"] = True
        # Learned flows still idle out: idle_dst does not apply here.
        config["dps"]["s1"]["idle_dst"] = False
        return config

    def test_refresh_without_idle_dst(self):
        """Test idle_dst does not stop a refresh replacing the hairpin flow."""
        self._learn(1, 0x100, self.P1_V100_MAC)
        self.mock_time(self._guard_time() + 1)
        self._assert_replaced(
            self._learn(1, 0x100, self.P1_V100_MAC), 1, 0x100, self.P1_V100_MAC
        )

    def test_option_changed_warm_without_idle_dst(self):
        """Test a warm start that changes a port's hairpin option, without idle_dst.

        The config already has idle_dst off.
        """
        self._change_option_warm(self._config())

    def test_dst_flow_removed_replaces_hairpin_flow(self):
        """Test the eth_dst flow of a host idling out replaces its hairpin flow."""
        self._learn(1, 0x100, self.P1_V100_MAC)
        valve = self.valves_manager.valves[self.DP_ID]
        ofmsgs = valve.flow_timeout(
            self.mock_time(self._guard_time() + 1),
            valve.dp.tables["eth_dst"].table_id,
            {"vlan_vid": self.V100, "eth_dst": self.P1_V100_MAC},
        )
        self._assert_replaced(self.apply_ofmsgs(ofmsgs), 1, 0x100, self.P1_V100_MAC)
        self.assertTrue(self._hairpinned(1, 0x100, self.P1_V100_MAC))


class ValveHairpinRoutedLearnTestCase(ValveHairpinLearnTestCase):
    """Test learning hosts on a port that hairpins only routed packets."""

    HAIRPIN_OPTION = "hairpin_routed"
    OTHER_OPTION = "hairpin_unicast"
    TABLE_MATCH_TYPES = {
        "in_port": False,
        "vlan_vid": False,
        "eth_dst": False,
        "eth_src": False,
    }

    def _config(self):
        """Return the config, with a FAUCET MAC of its own on each VLAN."""
        config = super()._config()
        config["vlans"]["v100"]["faucet_mac"] = "0e:00:00:00:01:00"
        config["vlans"]["v200"]["faucet_mac"] = "0e:00:00:00:02:00"
        return config

    def _hairpinned(self, port_no, vid, eth_dst):
        """Return True if a packet routed to a host is output back out of its port."""
        return self._routed_back(port_no, vid, eth_dst)


class ValveHairpinRoutedTestCase(ValveTestBases.ValveTestNetwork):
    """Test routing between two VLANs on a hairpin_routed port.

    Port 2 is a hairpin_unicast port on the same VLANs.
    """

    # The hairpin option of each port.
    HAIRPIN_OPTIONS = {1: "hairpin_routed", 2: "hairpin_unicast"}
    GLOBAL_VLAN = 0
    # The hairpin table's match fields, each mapped to whether it is
    # masked, and whether the table is exact match.
    TABLE_MATCH_TYPES = {
        "in_port": False,
        "vlan_vid": False,
        "eth_dst": False,
        "eth_src": False,
    }
    TABLE_EXACT_MATCH = False

    CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: GenericTFM
        ignore_learn_ins: 0
        interfaces:
            p1:
                number: 1
                tagged_vlans: [v100, v200, v300]
            p2:
                number: 2
                tagged_vlans: [v100, v200, v300]
vlans:
    v100:
        vid: 0x100
        faucet_mac: "0e:00:00:00:01:00"
        faucet_vips: ["10.100.0.254/24", "fc00:100::254/64"]
    v200:
        vid: 0x200
        faucet_mac: "0e:00:00:00:02:00"
        faucet_vips: ["10.200.0.254/24", "fc00:200::254/64"]
    v300:
        vid: 0x300
routers:
    r1:
        vlans: [v100, v200]
"""

    def setUp(self):
        """Learn routed and switched hosts behind each hairpin port.

        A routed host on each routed VLAN, and switched hosts on a routed
        VLAN and on a VLAN that is not routed.
        """
        config = yaml_load(self.CONFIG)
        config["dps"]["s1"]["global_vlan"] = self.GLOBAL_VLAN
        for port_no, option in self.HAIRPIN_OPTIONS.items():
            config["dps"]["s1"]["interfaces"]["p%u" % port_no][option] = True
        self.setup_valves(yaml_dump(config))
        for port_no in self.HAIRPIN_OPTIONS:
            for vid in (0x100, 0x200):
                self.l3_learn_host(
                    port_no,
                    vid,
                    self._mac(port_no, vid),
                    self._host_ips(port_no, vid),
                    [vip.ip for vip in self._vlan(vid).faucet_vips],
                )
            for vid, host in ((0x100, 2), (0x300, 1), (0x300, 2)):
                self.rcv_packet(
                    port_no,
                    vid,
                    {
                        "eth_src": self._mac(port_no, vid, host),
                        "eth_dst": self.UNKNOWN_MAC,
                        "ipv4_src": "10.0.0.1",
                        "ipv4_dst": "10.0.0.2",
                    },
                )

    @staticmethod
    def _mac(port_no, vid, host=1):
        """Return the MAC of a host behind a port on a VLAN."""
        return "00:00:00:%02x:%02x:%02x" % (port_no, vid >> 8, host)

    def _vlan(self, vid):
        """Return a VLAN."""
        return self.valves_manager.valves[self.DP_ID].dp.vlans[vid]

    def _host_ips(self, port_no, vid):
        """Return the addresses of the routed host behind a port on a VLAN."""
        return [vip.network[port_no] for vip in self._vlan(vid).faucet_vips]

    def _host_ip(self, port_no, vid, ipv):
        """Return the address of one IP version of a routed host."""
        return next(ip for ip in self._host_ips(port_no, vid) if ip.version == ipv)

    def _port_outputs(self, port_no, vid, eth_src, eth_dst, **fields):
        """Return the packets that a packet from a port is output back to it as."""
        match = {
            "in_port": port_no,
            "vlan_vid": vid | ofp.OFPVID_PRESENT,
            "eth_src": eth_src,
            "eth_dst": eth_dst,
            "eth_type": 0x800,
        }
        match.update(fields)
        port_outputs = self.network.tables[self.DP_ID].get_port_outputs(match)
        # Only an output to IN_PORT leaves the switch: an output to a port
        # number equal to in_port is dropped.
        return port_outputs.get(ofp.OFPP_IN_PORT, [])

    def _routed_back(self, port_no, src_vid, dst_vid, ipv):
        """Return the packets routed between two hosts on a port output back to it."""
        return self._port_outputs(
            port_no,
            src_vid,
            self._mac(port_no, src_vid),
            self._vlan(src_vid).faucet_mac,
            eth_type=0x800 if ipv == 4 else 0x86DD,
            **{
                "ipv%u_src" % ipv: str(self._host_ip(port_no, src_vid, ipv)),
                "ipv%u_dst" % ipv: str(self._host_ip(port_no, dst_vid, ipv)),
            },
        )

    def test_routed_hairpinned(self):
        """Test packets routed between two VLANs on a port are output back to it.

        Each leaves on the VLAN it is routed to, from that VLAN's FAUCET MAC.
        """
        for port_no in self.HAIRPIN_OPTIONS:
            for src_vid, dst_vid in ((0x100, 0x200), (0x200, 0x100)):
                for ipv in (4, 6):
                    with self.subTest(port=port_no, src_vid=src_vid, ipv=ipv):
                        pkts = self._routed_back(port_no, src_vid, dst_vid, ipv)
                        self.assertTrue(pkts)
                        for pkt in pkts:
                            self.assertEqual(
                                (
                                    dst_vid | ofp.OFPVID_PRESENT,
                                    self._vlan(dst_vid).faucet_mac,
                                    self._mac(port_no, dst_vid),
                                ),
                                (pkt["vlan_vid"], pkt["eth_src"], pkt["eth_dst"]),
                            )

    def test_switched_hairpinned_unless_routed(self):
        """Test switched packets are output back to a port, unless hairpin_routed.

        Whether on a VLAN that is not routed, between two hosts on a routed
        VLAN, or from a host that is not learned.
        """
        for port_no, option in self.HAIRPIN_OPTIONS.items():
            for vid, eth_src, eth_dst in (
                (0x300, self._mac(port_no, 0x300, 2), self._mac(port_no, 0x300)),
                (0x100, self._mac(port_no, 0x100, 2), self._mac(port_no, 0x100)),
                (0x100, self._mac(port_no, 0x100, 3), self._mac(port_no, 0x100)),
            ):
                with self.subTest(port=port_no, vid=vid, eth_src=eth_src):
                    self.assertEqual(
                        option != "hairpin_routed",
                        bool(self._port_outputs(port_no, vid, eth_src, eth_dst)),
                    )

    def test_flooded_hairpinned_only_with_hairpin(self):
        """Test only a hairpin port outputs flooded packets back to itself."""
        for port_no, option in self.HAIRPIN_OPTIONS.items():
            for vid in (0x100, 0x300):
                with self.subTest(port=port_no, vid=vid):
                    self.assertEqual(
                        option == "hairpin",
                        bool(
                            self._port_outputs(
                                port_no,
                                vid,
                                self._mac(port_no, vid, 2),
                                self.BROADCAST_MAC,
                            )
                        ),
                    )

    def test_table_shape(self):
        """Test the hairpin table's match fields, their masks and exact_match."""
        table = self.valves_manager.valves[self.DP_ID].dp.tables["eth_dst_hairpin"]
        self.assertEqual(self.TABLE_MATCH_TYPES, dict(table.match_types))
        self.assertEqual(self.TABLE_EXACT_MATCH, table.exact_match)


class ValveHairpinRoutedGlobalTestCase(ValveHairpinRoutedTestCase):
    """Test routing between two VLANs on a hairpin_routed port, with a global VLAN."""

    GLOBAL_VLAN = 0x800


class ValveHairpinRoutedOnlyTestCase(ValveHairpinRoutedTestCase):
    """Test routing between two VLANs on two hairpin_routed ports.

    With every hairpin port hairpin_routed, the hairpin table is still
    exact match.
    """

    HAIRPIN_OPTIONS = {1: "hairpin_routed", 2: "hairpin_routed"}
    TABLE_EXACT_MATCH = True


class ValveHairpinUnicastTestCase(ValveHairpinRoutedTestCase):
    """Test routing between two VLANs on hairpin ports, none hairpin_routed.

    Without a hairpin_routed port, the hairpin table is as it always was.
    """

    HAIRPIN_OPTIONS = {1: "hairpin_unicast", 2: "hairpin"}
    TABLE_MATCH_TYPES = {"in_port": False, "vlan_vid": False, "eth_dst": False}
    TABLE_EXACT_MATCH = True


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
