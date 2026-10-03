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

    # A soft pipeline, so that config changes can warm start.
    REQUIRE_TFM = False

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
    v200:
        vid: 0x200
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

    @staticmethod
    def _replaced(port_no, vid, eth_dst):
        """Return the hairpin flowmods that replace a host's hairpin flow."""
        vlan_vid = vid | ofp.OFPVID_PRESENT
        return [
            (ofp.OFPFC_DELETE, {"vlan_vid": vlan_vid, "eth_dst": eth_dst}),
            (
                ofp.OFPFC_ADD,
                {"in_port": port_no, "vlan_vid": vlan_vid, "eth_dst": eth_dst},
            ),
        ]

    def _assert_replaced(self, ofmsgs, port_no, vid, eth_dst):
        """Assert a host's hairpin flow is deleted, then added again."""
        self.assertEqual(
            self._replaced(port_no, vid, eth_dst),
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
            [
                (
                    ofp.OFPFC_ADD,
                    {
                        "in_port": 1,
                        "vlan_vid": self.V100,
                        "eth_dst": self.P1_V100_MAC,
                    },
                )
            ],
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


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
