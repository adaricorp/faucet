#!/usr/bin/env python3

"""Unit tests for the OpenFlow matches valve_of makes."""

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

import hashlib
import inspect
import unittest

from os_ken.ofproto import ofproto_v1_3 as ofp
from os_ken.ofproto import ofproto_v1_3_parser as parser

from clib.valve_test_lib import ValveTestBases

from faucet import valve_of


# Matches as faucet makes them, from its tables and from ACLs.
MATCHES = (
    {},
    {"in_port": 1},
    {"in_port": 1, "vlan_vid": 0x100 | ofp.OFPVID_PRESENT},
    {"vlan_vid": ofp.OFPVID_NONE},
    {"vlan_vid": (ofp.OFPVID_PRESENT, ofp.OFPVID_PRESENT)},
    {"vlan_vid": (0x100 | ofp.OFPVID_PRESENT, 0xFF0 | ofp.OFPVID_PRESENT)},
    {"eth_dst": "0e:00:00:00:00:01", "vlan_vid": 0x200 | ofp.OFPVID_PRESENT},
    {"eth_dst": ("01:80:c2:00:00:00", "ff:ff:ff:00:00:00"), "in_port": 2},
    {"eth_src": "00:00:00:01:00:01", "eth_type": 0x0806, "arp_op": 1},
    {"eth_type": 0x0806, "arp_tpa": "10.0.0.254", "arp_spa": "10.0.0.1"},
    {"eth_type": 0x0800, "ipv4_dst": ("10.0.0.0", "255.255.255.0")},
    {"eth_type": 0x0800, "ipv4_src": "10.0.0.1", "ip_proto": 6, "tcp_dst": 22},
    {"eth_type": 0x0800, "ip_proto": 17, "udp_src": 68, "udp_dst": 67},
    {"eth_type": 0x0800, "ip_proto": 1, "icmpv4_type": 8},
    {"eth_type": 0x86DD, "ipv6_dst": ("fc00::", "ffff:ffff:ffff:ffff::")},
    {"eth_type": 0x86DD, "ip_proto": 58, "icmpv6_type": 135},
    {"metadata": (0x1, 0xFF), "vlan_pcp": 3},
    {"eth_type": 0x0800, "ct_state": (0x21, 0x21), "ct_zone": 10},
    # In reverse OXM order, which a match sorts.
    {"tcp_dst": 80, "ip_proto": 6, "eth_type": 0x0800, "in_port": 3},
)

# Digests of the os_ken code that valve_of._ofpmatch() reproduces.
OS_KEN_DIGESTS = {
    "OFPMatch.__init__": "2029a16ccae9339c",
    "OFPMatch._composed_with_old_api": "3b6b84bcfd861773",
    "Flow.__init__": "800514aa2acf550b",
    "FlowWildcards.__init__": "b153b5aa4da32543",
}


def shared():
    """Return the Flow and FlowWildcards the matches valve_of makes share."""
    # pylint: disable=protected-access
    return (valve_of._SHARED_FLOW, valve_of._SHARED_FLOW_WILDCARDS)


def serialized(ofmatch):
    """Return ofmatch as a switch receives it."""
    buf = bytearray()
    ofmatch.serialize(buf, 0)
    return bytes(buf)


class ValveOfMatchTestCase(unittest.TestCase):  # pytype: disable=module-attr
    """Test a match faucet makes is the match os_ken makes, less its old API."""

    def assert_same_match(self, match_fields):
        """Assert valve_of and OFPMatch() make the same match of match_fields."""
        lean = valve_of.match(match_fields)
        ofmatch = parser.OFPMatch(**match_fields)
        self.assertIs(parser.OFPMatch, type(lean))
        self.assertEqual(sorted(vars(ofmatch)), sorted(vars(lean)))
        for attr, value in vars(ofmatch).items():
            if attr in ("_flow", "_wc"):
                self.assertEqual(vars(value), vars(getattr(lean, attr)), msg=attr)
            else:
                self.assertEqual(value, getattr(lean, attr), msg=attr)
        self.assertEqual(serialized(ofmatch), serialized(lean))
        self.assertEqual(ofmatch.length, lean.length)
        self.assertEqual(str(ofmatch), str(lean))
        self.assertEqual(ofmatch.to_jsondict(), lean.to_jsondict())
        self.assertEqual(
            ofmatch.items(), parser.OFPMatch.parser(serialized(lean), 0).items()
        )

    def assert_shared_unchanged(self):
        """Assert the Flow and FlowWildcards matches share are as made."""
        flow, wildcards = shared()
        self.assertEqual(vars(parser.Flow()), vars(flow))
        self.assertEqual(vars(parser.FlowWildcards()), vars(wildcards))

    def test_same_match(self):
        """Test matches are made as OFPMatch(**match_fields) makes them."""
        for match_fields in MATCHES:
            self.assert_same_match(match_fields)
        self.assert_shared_unchanged()

    def test_shared_cannot_change(self):
        """Test the old API cannot change the Flow and FlowWildcards matches share.

        Were one match to change them, os_ken would serialize every match from
        them instead of from its own fields.
        """
        lean = valve_of.match({"in_port": 1})
        other_fields = {"in_port": 2, "eth_dst": "0e:00:00:00:00:01"}
        other = valve_of.match(other_fields)
        for change in (
            lambda: lean.set_dl_src(b"\x0e\x00\x00\x00\x00\x02"),
            lambda: lean.set_in_port(3),
            lambda: lean.set_vlan_vid(0x100),
        ):
            with self.assertRaises(TypeError):
                change()
        for obj, attr in zip(shared(), ("in_port", "wildcards")):
            with self.assertRaises(TypeError):
                setattr(obj, attr, 0)
            with self.assertRaises(TypeError):
                delattr(obj, attr)
        self.assert_shared_unchanged()
        # pylint: disable=protected-access
        self.assertFalse(other._composed_with_old_api())
        self.assertEqual(serialized(parser.OFPMatch(**other_fields)), serialized(other))

    def test_match_from_dict(self):
        """Test a match from an ACL's dict shares the same Flow and FlowWildcards."""
        lean = valve_of.match_from_dict(
            {"dl_type": 0x0800, "nw_src": "10.0.0.0/8", "vlan_vid": 0x100}
        )
        # pylint: disable=protected-access
        self.assertEqual(shared(), (lean._flow, lean._wc))
        self.assert_same_match(dict(lean.items()))
        self.assertFalse(lean._composed_with_old_api())

    def test_os_ken_internals(self):
        """Test the os_ken code valve_of._ofpmatch() reproduces has not changed.

        If this fails, os_ken has changed how OFPMatch makes a match: check
        that valve_of._ofpmatch() still makes what OFPMatch(**kwargs) does,
        then update OS_KEN_DIGESTS.
        """
        self.assertEqual(
            OS_KEN_DIGESTS,
            {
                func.__qualname__: hashlib.sha256(
                    inspect.getsource(func).encode()
                ).hexdigest()[:16]
                for func in (
                    # pylint: disable=protected-access
                    parser.OFPMatch.__init__,
                    parser.OFPMatch._composed_with_old_api,
                    parser.Flow.__init__,
                    parser.FlowWildcards.__init__,
                )
            },
        )


class ValveMatchTestCase(ValveTestBases.ValveTestNetwork):
    """Test the matches of a DP's flows are what os_ken makes, less its old API."""

    CONFIG = """
acls:
    acl1:
        - rule:
            dl_type: 0x0800
            nw_src: 10.0.0.0/8
            actions:
                allow: 1
dps:
    s1:
        dp_id: 1
        hardware: "Open vSwitch"
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                acls_in: [acl1]
            p2:
                number: 2
                tagged_vlans: [v100, v200]
vlans:
    v100:
        vid: 0x100
        faucet_vips: ["10.0.0.254/24", "fc00::1:254/112"]
    v200:
        vid: 0x200
        faucet_vips: ["10.0.1.254/24"]
routers:
    r1:
        vlans: [v100, v200]
"""
    REQUIRE_TFM = False

    def setUp(self):
        """Set up a routed DP with an ACL."""
        self.setup_valves(self.CONFIG)

    def test_flows(self):
        """Test every flow's match shares one Flow and FlowWildcards, unchanged."""
        flowmods = [
            ofmsg
            for ofmsg in self.connect_dp()
            if isinstance(ofmsg, parser.OFPFlowMod) and ofmsg.match.items()
        ]
        self.assertTrue(flowmods)
        for ofmsg in flowmods:
            # pylint: disable=protected-access
            self.assertEqual(shared(), (ofmsg.match._flow, ofmsg.match._wc))
            self.assertEqual(
                serialized(parser.OFPMatch(**dict(ofmsg.match.items()))),
                serialized(ofmsg.match),
            )
        flow, wildcards = shared()
        self.assertEqual(vars(parser.Flow()), vars(flow))
        self.assertEqual(vars(parser.FlowWildcards()), vars(wildcards))


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
