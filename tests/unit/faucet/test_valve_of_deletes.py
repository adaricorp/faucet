#!/usr/bin/env python3

"""Unit tests for the flow deletes valve_flowreorder() leaves out or merges."""

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
from os_ken.ofproto import ofproto_v1_3_parser as parser

from clib.valve_test_lib import ValveTestBases

from faucet import valve_of


def flowdel(
    table_id, match, priority=0, strict=False, out_port=ofp.OFPP_ANY, cookie_mask=0
):  # pylint: disable=too-many-arguments,too-many-positional-arguments
    """Return a flow delete."""
    return parser.OFPFlowMod(
        datapath=None,
        cookie=0,
        cookie_mask=cookie_mask,
        table_id=table_id,
        command=ofp.OFPFC_DELETE_STRICT if strict else ofp.OFPFC_DELETE,
        priority=priority,
        out_port=out_port,
        out_group=ofp.OFPG_ANY,
        match=valve_of.match(match),
    )


def flowadd(table_id, match, priority=1):
    """Return a flow add."""
    return parser.OFPFlowMod(
        datapath=None,
        table_id=table_id,
        command=ofp.OFPFC_ADD,
        priority=priority,
        match=valve_of.match(match),
        instructions=[],
    )


def deletes_sent(ofmsgs):
    """Return the flow deletes valve_flowreorder() keeps of ofmsgs, as strings."""
    return sorted(
        str(ofmsg)
        for ofmsg in valve_of.valve_flowreorder(ofmsgs, use_barriers=False)
        if valve_of.is_flowdel(ofmsg)
    )


class ValveOfCoveredDeletesTestCase(unittest.TestCase):  # pytype: disable=module-attr
    """Test a delete that another in its table covers is left out."""

    VLAN = {"vlan_vid": 0x100 | ofp.OFPVID_PRESENT}

    def test_covered(self):
        """Test deletes whose match has all of a wider one's fields go."""
        wide = flowdel(1, self.VLAN)
        others = [
            flowdel(1, dict(self.VLAN, in_port=1), priority=5, strict=True),
            flowdel(1, dict(self.VLAN, eth_dst="0e:00:00:00:00:01")),
            flowdel(1, dict(self.VLAN, in_port=2), out_port=3),
        ]
        self.assertEqual([str(wide)], deletes_sent([wide] + others))
        self.assertEqual([str(wide)], deletes_sent(others + [wide]))
        add = flowadd(1, dict(self.VLAN, in_port=1))
        self.assertEqual(
            [str(add)],
            [
                str(ofmsg)
                for ofmsg in valve_of.valve_flowreorder(
                    [wide] + others + [add], use_barriers=False
                )
                if not valve_of.is_flowdel(ofmsg)
            ],
        )

    def test_not_covered(self):
        """Test deletes that remove what no other one does are kept."""
        deletes = [
            flowdel(1, self.VLAN),
            # Another table.
            flowdel(2, dict(self.VLAN, in_port=1)),
            # Another VLAN.
            flowdel(1, {"in_port": 2, "vlan_vid": 0x200 | ofp.OFPVID_PRESENT}),
            # Not the VLAN's field.
            flowdel(1, {"in_port": 1}),
            # A mask is not the value.
            flowdel(1, {"vlan_vid": (0x100 | ofp.OFPVID_PRESENT, 0x1F00)}),
        ]
        self.assertEqual(sorted(str(ofmsg) for ofmsg in deletes), deletes_sent(deletes))

    def test_filtered_wider_delete(self):
        """Test a wider delete that is strict or filtered covers no other."""
        narrow = flowdel(1, dict(self.VLAN, in_port=1))
        for wide in (
            flowdel(1, self.VLAN, strict=True),
            flowdel(1, self.VLAN, out_port=1),
            flowdel(1, self.VLAN, cookie_mask=0xFF),
        ):
            self.assertEqual(
                sorted([str(wide), str(narrow)]), deletes_sent([wide, narrow])
            )

    def test_equal_deletes(self):
        """Test non-strict deletes with the same match do not remove each other."""
        deletes = [flowdel(1, self.VLAN, priority=1), flowdel(1, self.VLAN, priority=2)]
        self.assertEqual(sorted(str(ofmsg) for ofmsg in deletes), deletes_sent(deletes))


class ValveCoveredDeletesTestCase(ValveTestBases.ValveTestNetwork):
    """Test a warm start sends no delete another one it sends covers."""

    REQUIRE_TFM = False
    CONFIG = """
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
            p3:
                number: 3
                tagged_vlans: [v100, v200]
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
%s
"""

    def config(self, p1_vlans, v200_options=""):
        """Return CONFIG with p1 on p1_vlans, and v200 with options."""
        return self.CONFIG % (p1_vlans, v200_options)

    def setUp(self):
        """Set up a DP with a trunk."""
        self.setup_valves(self.config("v100, v200"))

    def test_warm_start(self):
        """Test a warm start that changes a VLAN and a trunk sends no covered delete."""
        ofmsgs = self.update_config(
            self.config("v100", "        max_hosts: 10"), reload_type="warm"
        )[self.DP_ID]
        deletes = [ofmsg for ofmsg in ofmsgs if valve_of.is_flowdel(ofmsg)]
        self.assertTrue(deletes)
        self.assertEqual(deletes, valve_of.remove_covered_flowdels(deletes))
        flood_table_id = (
            self.valves_manager.valves[self.DP_ID].dp.tables["flood"].table_id
        )
        v200 = 0x200 | ofp.OFPVID_PRESENT
        v200_flood_deletes = [
            ofmsg
            for ofmsg in deletes
            if ofmsg.table_id == flood_table_id and ofmsg.match.get("vlan_vid") == v200
        ]
        # The VLAN's flood flows go in one delete, not port by port.
        self.assertEqual(1, len(v200_flood_deletes), msg=v200_flood_deletes)
        self.assertEqual({"vlan_vid": v200}, dict(v200_flood_deletes[0].match.items()))
        warm = self.table_str()
        self.cold_start()
        self.assertEqual(warm, self.table_str())

    def table_str(self):
        """Return the DP's flow table, comparably."""
        table = self.network.tables[self.DP_ID]
        table.sort_tables()
        return str(table)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
