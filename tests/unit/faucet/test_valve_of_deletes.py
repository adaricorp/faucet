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


def vid(vlan_vid):
    """Return vlan_vid as a match on a VLAN tag."""
    return vlan_vid | ofp.OFPVID_PRESENT


def vid_blocks_match(deletes):
    """Return the VLAN IDs deletes of VLAN IDs match."""
    vids = set()
    for ofmsg in deletes:
        value = ofmsg.match["vlan_vid"]
        mask = 0x1FFF
        if isinstance(value, tuple):
            value, mask = value
        vids.update(
            vlan_vid for vlan_vid in range(4096) if vid(vlan_vid) & mask == value
        )
    return vids


class ValveOfMergedVIDDeletesTestCase(unittest.TestCase):  # pytype: disable=module-attr
    """Test deletes that differ only in VLAN ID are merged."""

    def reorder(self, deletes, table_ids=(1,)):
        """Return the flow deletes of deletes, reordered."""
        return [
            ofmsg
            for ofmsg in valve_of.valve_flowreorder(
                deletes, use_barriers=False, vid_merge_table_ids=table_ids
            )
            if valve_of.is_flowdel(ofmsg)
        ]

    def test_merged(self):
        """Test deletes of VLAN IDs become the fewest deletes of masked VLAN IDs."""
        vids = list(range(0x100, 0x110)) + [0x120, 0x122, 0x123]
        deletes = [flowdel(1, {"vlan_vid": vid(vlan_vid)}) for vlan_vid in vids]
        merged = self.reorder(deletes)
        self.assertEqual(
            sorted(
                [vid(0x120), (vid(0x100), vid(0xFF0)), (vid(0x122), vid(0xFFE))],
                key=str,
            ),
            sorted((ofmsg.match["vlan_vid"] for ofmsg in merged), key=str),
        )
        for ofmsg in merged:
            self.assertEqual(ofp.OFPFC_DELETE, ofmsg.command)
            self.assertEqual(1, ofmsg.table_id)
            self.assertEqual(["vlan_vid"], [name for name, _ in ofmsg.match.items()])
        self.assertEqual(set(vids), vid_blocks_match(merged))
        # Sent as they are, without a table to merge in.
        self.assertEqual(len(deletes), len(self.reorder(deletes, table_ids=())))
        self.assertEqual(len(deletes), len(self.reorder(deletes, table_ids=(2,))))

    def test_exact(self):
        """Test merged deletes match the VLAN IDs of the deletes and no other."""
        for vids in (
            range(1, 4095),
            range(1, 4095, 2),
            [1, 2, 4094],
            list(range(0x200, 0x400)) + list(range(0x401, 0x600)),
            [0x7FF, 0x800, 0x801],
        ):
            vids = set(vids)
            merged = self.reorder(
                [flowdel(1, {"vlan_vid": vid(vlan_vid)}) for vlan_vid in vids]
            )
            self.assertLessEqual(len(merged), len(vids))
            self.assertEqual(vids, vid_blocks_match(merged))
            for ofmsg in merged:
                value = ofmsg.match["vlan_vid"]
                if isinstance(value, tuple):
                    self.assertNotEqual(ofp.OFPVID_PRESENT, value[1] & 0x1FFF)

    def test_not_merged(self):
        """Test deletes that differ in more than their VLAN ID are not merged."""
        deletes = [
            flowdel(1, {"vlan_vid": vid(0x100), "in_port": 1}),
            flowdel(1, {"vlan_vid": vid(0x101), "in_port": 2}),
            flowdel(1, {"vlan_vid": vid(0x102)}, strict=True),
            flowdel(1, {"vlan_vid": vid(0x103)}, out_port=1),
            flowdel(1, {"vlan_vid": vid(0x104)}, priority=1),
            flowdel(1, {"vlan_vid": vid(0x105)}, priority=2),
            flowdel(1, {"vlan_vid": ofp.OFPVID_NONE, "in_port": 3}),
            flowdel(1, {"vlan_vid": (vid(0x106), vid(0xFFE)), "in_port": 4}),
            flowdel(1, {"vlan_vid": vid(0x108), "in_port": 4}),
        ]
        self.assertEqual(
            sorted(str(ofmsg) for ofmsg in deletes),
            sorted(str(ofmsg) for ofmsg in self.reorder(deletes)),
        )


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


class ValveMergedVIDDeletesTestCase(ValveTestBases.ValveTestNetwork):
    """Test a warm start that deletes VLANs deletes their flows with fewer deletes."""

    REQUIRE_TFM = False
    VIDS = range(0x100, 0x140)
    HARDWARE = "Open vSwitch"

    def config(self, vids):
        """Return a DP whose ports carry the VLANs of vids, with VLAN ACLs."""
        vlans = "".join(
            "    v%x:\n        vid: 0x%x\n        acls_in: [allow]\n"
            % (vlan_vid, vlan_vid)
            for vlan_vid in vids
        )
        names = ", ".join("v%x" % vlan_vid for vlan_vid in vids)
        return """
acls:
    allow:
        - rule:
            actions:
                allow: 1
dps:
    s1:
        dp_id: 1
        hardware: "%s"
        interfaces:
            p1:
                number: 1
                tagged_vlans: [%s]
            p2:
                number: 2
                tagged_vlans: [%s]
            p3:
                number: 3
                native_vlan: v%x
vlans:
%s""" % (
            self.HARDWARE,
            names,
            names,
            vids[0],
            vlans,
        )

    def setUp(self):
        """Set up a DP with two trunks on many VLANs."""
        self.setup_valves(self.config(self.VIDS))

    def test_warm_start(self):
        """Test the deletes of deleted VLANs' flows are merged, but in ACL tables."""
        valve = self.valves_manager.valves[self.DP_ID]
        tables = valve.dp.tables
        kept = self.VIDS[:4]
        ofmsgs = self.update_config(self.config(kept), reload_type="warm")[self.DP_ID]
        deleted = set(self.VIDS) - set(kept)
        vid_deletes = {}
        for ofmsg in ofmsgs:
            if valve_of.is_flowdel(ofmsg) and "vlan_vid" in ofmsg.match:
                vid_deletes.setdefault(ofmsg.table_id, []).append(ofmsg)
        for table_name in ("flood", "eth_src"):
            deletes = [
                ofmsg
                for ofmsg in vid_deletes[tables[table_name].table_id]
                if ["vlan_vid"] == [name for name, _ in ofmsg.match.items()]
            ]
            self.assertEqual(deleted, vid_blocks_match(deletes), msg=table_name)
            self.assertLess(len(deletes), len(deleted) / 4, msg=table_name)
        # A VLAN ACL's rule can match a masked VLAN ID itself.
        vlan_acl_deletes = vid_deletes[tables["vlan_acl"].table_id]
        self.assertEqual(
            {vid(vlan_vid) for vlan_vid in deleted},
            {ofmsg.match["vlan_vid"] for ofmsg in vlan_acl_deletes},
        )
        warm = self.table_str()
        self.cold_start()
        self.assertEqual(warm, self.table_str())

    def table_str(self):
        """Return the DP's flow table, comparably."""
        table = self.network.tables[self.DP_ID]
        table.sort_tables()
        return str(table)

    def test_tables(self):
        """Test the tables merged in are those that match VLAN IDs unmasked."""
        valve = self.valves_manager.valves[self.DP_ID]
        tables = valve.dp.tables
        table_ids = valve.vid_merge_table_ids()
        for table_name in ("vlan", "eth_src", "eth_dst", "flood"):
            self.assertIn(tables[table_name].table_id, table_ids, msg=table_name)
        self.assertNotIn(tables["vlan_acl"].table_id, table_ids)
        for table_name, table in tables.items():
            if table.table_id in table_ids:
                self.assertIs(False, table.match_types["vlan_vid"], msg=table_name)
        # Nor a table whose config matches masked VLAN IDs.
        flood_table = tables["flood"]
        flood_table.match_types = dict(flood_table.match_types, vlan_vid=True)
        self.assertNotIn(flood_table.table_id, valve.vid_merge_table_ids())
        flood_table.match_types["vlan_vid"] = False
        # Such a table refuses a flow that matches a VLAN ID with a mask.
        flood_table = tables["flood"]
        with self.assertRaises(AssertionError):
            flood_table.flowmod(
                match=valve_of.match({"vlan_vid": (vid(0x100), vid(0xFF0))}),
                priority=1,
            )


class ValveMergedVIDDeletesGenericTestCase(ValveMergedVIDDeletesTestCase):
    """Test deletes of VLAN IDs are merged on Open vSwitch alone."""

    HARDWARE = "Generic"

    def test_warm_start(self):
        """Test a warm start sends a delete per deleted VLAN, and table."""
        valve = self.valves_manager.valves[self.DP_ID]
        self.assertEqual(frozenset(), valve.vid_merge_table_ids())
        flood_table_id = valve.dp.tables["flood"].table_id
        ofmsgs = self.update_config(self.config(self.VIDS[:4]), reload_type="warm")[
            self.DP_ID
        ]
        self.assertEqual(
            {vid(vlan_vid) for vlan_vid in self.VIDS[4:]},
            {
                ofmsg.match["vlan_vid"]
                for ofmsg in ofmsgs
                if valve_of.is_flowdel(ofmsg)
                and ofmsg.table_id == flood_table_id
                and ["vlan_vid"] == [name for name, _ in ofmsg.match.items()]
            },
        )

    def test_tables(self):
        """Test no table is merged in."""
        self.assertEqual(
            frozenset(), self.valves_manager.valves[self.DP_ID].vid_merge_table_ids()
        )


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
