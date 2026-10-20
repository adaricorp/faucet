#!/usr/bin/env python3

"""Unit tests for learned hosts and next hops kept by a warm start."""

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

from os_ken.lib.packet import arp

from clib.valve_test_lib import FAUCET_MAC, ValveTestBases


CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: "Open vSwitch"
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v100
            p3:
                number: 3
                tagged_vlans: [v100, v200]
vlans:
    v100:
        vid: 0x100
        faucet_vips: ["10.0.0.254/24"]
    v200:
        vid: 0x200
        max_hosts: %u
"""


class ValveRehomeLearnedHostsTestCase(ValveTestBases.ValveTestNetwork):
    """Test a warm start leaves learned hosts and next hops on the new config's ports."""

    REQUIRE_TFM = False

    def setUp(self):
        """Set up a routed VLAN with a host and a next hop learned on p1."""
        self.setup_valves(CONFIG % 10)
        self.rcv_packet(
            1,
            0x100,
            {
                "eth_src": self.P1_V100_MAC,
                "eth_dst": FAUCET_MAC,
                "arp_code": arp.ARP_REPLY,
                "arp_source_ip": "10.0.0.1",
                "arp_target_ip": "10.0.0.254",
            },
        )

    def learned(self):
        """Return the host cache and next hop entries of v100."""
        vlan = self.valves_manager.valves[self.DP_ID].dp.vlans[0x100]
        entries = list(vlan.dyn_host_cache.values())
        for neigh_cache in vlan.dyn_neigh_cache_by_ipv.values():
            entries.extend(neigh_cache.values())
        return entries

    def test_warm_start(self):
        """Test the entries of a VLAN a warm start keeps hold the new config's port."""
        before = self.learned()
        self.assertEqual(2, len(before))
        old_port = before[0].port
        self.update_config(CONFIG % 20, reload_type="warm")
        dp = self.valves_manager.valves[self.DP_ID].dp
        self.assertIsNot(old_port, dp.ports[1])
        after = self.learned()
        self.assertEqual(before, after)
        for entry in after:
            self.assertIs(dp.ports[1], entry.port, msg=entry)
            self.assertIn(dp.vlans[0x100], entry.port.vlans())


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
