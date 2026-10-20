#!/usr/bin/env python3

"""Unit tests for the ports and VLANs a warm start adds."""

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

import collections
import unittest
from unittest import mock

from os_ken.ofproto import ofproto_v1_3 as ofp

from clib.valve_test_lib import ValveTestBases

from faucet import valve as valve_module


CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: "Open vSwitch"
        interfaces:
            p4:
                number: 4
                native_vlan: v300
%s
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
    v300:
        vid: 0x300
"""

PORTS = """
            p2:
                number: 2
                native_vlan: v200
            p3:
                number: 3
                tagged_vlans: [v100, v300]
"""

# p1 added, p2 and p3 changed, on the same VLANs.
NEW_PORTS = """
            p1:
                number: 1
                tagged_vlans: [v100, v200, v300]
            p2:
                number: 2
                native_vlan: v100
            p3:
                number: 3
                tagged_vlans: [v100, v200, v300]
"""


class ValvePortsAddTestCase(ValveTestBases.ValveTestNetwork):
    """Test a warm start that adds and changes ports builds their VLANs once."""

    REQUIRE_TFM = False

    def setUp(self):
        """Set up a DP, and the switch's port 1 up but not in its config."""
        self.setup_valves(CONFIG % PORTS)
        valve = self.valves_manager.valves[self.DP_ID]
        valve.port_status_handler(1, ofp.OFPPR_ADD, 0, [], self.mock_time(0))

    def table_str(self):
        """Return the DP's flow table, comparably."""
        table = self.network.tables[self.DP_ID]
        table.sort_tables()
        return str(table)

    def test_added_and_changed_ports(self):
        """Test each VLAN is built once for its ports, and once as changed."""
        add_vlan = valve_module.Valve.add_vlan
        with mock.patch.object(
            valve_module.Valve, "add_vlan", autospec=True, side_effect=add_vlan
        ) as built:
            self.update_config(CONFIG % NEW_PORTS, reload_type="warm")
        self.assertEqual(
            {0x100: 2, 0x200: 2, 0x300: 2},
            collections.Counter(call.args[1].vid for call in built.call_args_list),
        )
        warm = self.table_str()
        self.cold_start()
        self.assertEqual(warm, self.table_str())


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
