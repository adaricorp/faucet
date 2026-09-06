#!/usr/bin/env python3

"""Test FAUCET valve_packet."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
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

from os_ken.ofproto import ether

from faucet import valve_packet


class PacketMetaTestCase(unittest.TestCase):  # pytype: disable=module-attr
    """Test PacketMeta completeness after reparsing."""

    VID = 100
    ETH_SRC = "0e:00:00:00:00:02"
    ETH_DST = "0e:00:00:00:00:01"
    SRC_IP = "10.0.0.1"
    DST_IP = "10.0.0.2"

    @staticmethod
    def pkt_meta(data, orig_len, eth_type):
        """Return a PacketMeta with only the completeness fields populated."""
        return valve_packet.PacketMeta(
            None, data, orig_len, None, None, None, None, None, None, None, eth_type
        )

    def padded_arp_reply(self, pad_to):
        """Return a tagged ARP reply zero padded out to pad_to bytes."""
        pkt = valve_packet.arp_reply(
            self.VID, self.ETH_SRC, self.ETH_DST, self.SRC_IP, self.DST_IP
        )
        data = bytes(pkt.data)
        self.assertLessEqual(len(data), pad_to, "ARP reply longer than the padding")
        return data + b"\x00" * (pad_to - len(data))

    def parsed_pkt_meta(self, data):
        """Return a PacketMeta for data, parsed the way Valve parses one."""
        pkt, eth_pkt, eth_type, vlan_pkt, _ = valve_packet.parse_packet_in_pkt(data, 0)
        return valve_packet.PacketMeta(
            None,
            data,
            len(data),
            pkt,
            eth_pkt,
            vlan_pkt,
            None,
            None,
            eth_pkt.src,
            eth_pkt.dst,
            eth_type,
        )

    def test_packet_complete_all_data(self):
        """Test a packet whose data covers the whole frame is complete."""
        pkt_meta = self.pkt_meta(b"\x00" * 64, 64, ether.ETH_TYPE_ARP)
        self.assertTrue(pkt_meta.packet_complete())

    def test_packet_complete_truncated_ip(self):
        """Test a truncated IPv4 packet is not complete."""
        pkt_meta = self.pkt_meta(b"\x00" * 174, 1514, ether.ETH_TYPE_IP)
        self.assertFalse(pkt_meta.packet_complete())

    def test_packet_complete_unpadded_arp(self):
        """Test an ARP reply short enough to be retained whole is complete."""
        data = self.padded_arp_reply(valve_packet.VLAN_ARP_PKT_SIZE)
        pkt_meta = self.parsed_pkt_meta(data)
        pkt_meta.reparse_ip()
        self.assertEqual(len(pkt_meta.data), valve_packet.VLAN_ARP_PKT_SIZE)
        self.assertEqual(pkt_meta.orig_len, valve_packet.VLAN_ARP_PKT_SIZE)
        self.assertTrue(pkt_meta.packet_complete())

    def test_packet_complete_padded_arp(self):
        """Test an ARP reply padded past the retained size is still complete.

        reparse() truncates ARP down to MAX_ETH_TYPE_PKT_SIZE while orig_len
        keeps the whole frame length, so a peer that pads its replies past
        that size would otherwise never be seen as complete, and the ARP
        would never be answered or learned as a next hop.
        """
        data = self.padded_arp_reply(valve_packet.VLAN_ARP_PKT_SIZE + 4)
        pkt_meta = self.parsed_pkt_meta(data)
        pkt_meta.reparse_ip()
        self.assertEqual(len(pkt_meta.data), valve_packet.VLAN_ARP_PKT_SIZE)
        self.assertEqual(pkt_meta.orig_len, valve_packet.VLAN_ARP_PKT_SIZE + 4)
        self.assertTrue(pkt_meta.packet_complete())


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
