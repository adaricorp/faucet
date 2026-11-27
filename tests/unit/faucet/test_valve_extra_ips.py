#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valve_extra_ips.py."""

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

from collections import namedtuple
from ipaddress import ip_address, ip_network
import unittest
from unittest import mock

from os_ken.lib.packet import arp, ethernet, ipv4
from os_ken.ofproto import ofproto_v1_3 as ofp

from clib.fakeoftable import CONTROLLER_PORT, IN_PORT
from clib.valve_test_lib import FAUCET_MAC, ValveTestBases
from faucet import config_parser_util, valve_of, valve_packet
from faucet.valve import Valve
from faucet.valve_route import ExtraIPState

from tests.unit.faucet.test_valve_config import ValveARPResponderTestBase


class ValveExtraIPsTestBase(ValveARPResponderTestBase):
    """Answer ARP for further addresses on a VLAN, from flows on the switch.

    office lists 10.0.0.10 and 10.0.0.11 in faucet_extra_ips, and routes
    192.0.2.0/24 via 10.0.0.1. Ports 1 and 2 are untagged on office, port 3
    tags office and guest, port 4 is untagged on guest, and port 5 on lab.
    With CLAIM, each test starts once FAUCET has claimed every address, and
    a restart or a warm start claims those it lists anew (see claim()).
    """

    EXTRA_IPS = ["10.0.0.10", "10.0.0.11"]
    OFFICE = {
        "faucet_extra_ips": EXTRA_IPS,
        "routes": [{"route": {"ip_dst": "192.0.2.0/24", "ip_gw": "10.0.0.1"}}],
    }
    OTHER_MAC = "00:00:00:01:00:02"
    NO_MAC = "00:00:00:00:00:00"
    CLAIM = True

    def setUp(self):
        """Setup the routed VLANs, and claim their faucet_extra_ips."""
        super().setUp()
        if self.CLAIM:
            self.claim()

    def restart(self, config):
        """Cold start a new faucet and switch with the config, claim its
        faucet_extra_ips, and return what claiming them sends."""
        super().restart(config)
        if self.CLAIM:
            return self.claim()
        return []

    def warm_start(self, config):
        """Warm start to config, claim the faucet_extra_ips it adds, and return
        what is sent to the switch."""
        ofmsgs = super().warm_start(config)
        if self.CLAIM:
            ofmsgs = ofmsgs + self.claim()
        return ofmsgs

    def unclaimed(self):
        """Return the faucet_extra_ips of the running config that FAUCET has
        not claimed."""
        return sorted(
            str(extra_ip)
            for vlan in self.valves_manager.valves[self.DP_ID].dp.vlans.values()
            for extra_ip in vlan.faucet_extra_ips
            if vlan.dyn_extra_ip_state[extra_ip].state != ExtraIPState.CLAIMED
        )

    def switch_live(self):
        """Have the switch send FAUCET a packet in, as it does once it has
        flows after a cold start: LLDP from a neighbour on port 5."""
        with mock.patch.object(self.valves_manager, "valve_flow_services"):
            self.rcv_packet(
                5,
                0,
                {
                    "eth_src": "00:00:00:05:00:01",
                    "eth_dst": "01:80:c2:00:00:0e",
                    "chassis_id": "00:00:00:05:00:01",
                    "port_id": 1,
                },
            )

    def claim(self):
        """Have FAUCET probe for the faucet_extra_ips of the running config
        until it claims them all, once the switch sends packet ins, and
        return what it sends meanwhile."""
        ofmsgs = []
        if self.unclaimed():
            dp = self.valves_manager.valves[self.DP_ID].dp
            if not dp.packet_in_since_cold_start():
                self.switch_live()
            for _ in range(30):
                ofmsgs.extend(self.resolvers(1))
                if not self.unclaimed():
                    break
        self.assertEqual([], self.unclaimed())
        return ofmsgs

    def config(self, vlans=None, interfaces=None, arp_responder=True):
        """Return the config, with office's faucet_extra_ips and route unless
        vlans changes them, and VLANs or interfaces updated or deleted (None)."""
        vlans = dict(vlans or {})
        if vlans.get("office", {}) is not None:
            vlans["office"] = dict(self.OFFICE, **vlans.get("office", {}))
        return super().config(vlans, interfaces, arp_responder)

    def routed_config(self, global_vlan=None, **kwargs):
        """Return the config with office and guest routed together, through
        the global VLAN if one is given."""
        config = config_parser_util.yaml_load(self.config(**kwargs))
        config["routers"] = {"office-guest": {"vlans": ["office", "guest"]}}
        if global_vlan:
            config["dps"]["s1"]["global_vlan"] = global_vlan
        return config_parser_util.yaml_dump(config)

    def extra_ips_config(self, extra_ips, **vlans):
        """Return the config with office listing extra_ips."""
        office = dict(vlans.pop("office", {}), faucet_extra_ips=extra_ips)
        return self.config(vlans=dict(vlans, office=office))

    def vlan(self, vid=0x100):
        """Return a VLAN of the running config."""
        return self.valves_manager.valves[self.DP_ID].dp.vlans[vid]

    def route_manager(self):
        """Return the running IPv4 route manager."""
        # pylint: disable=protected-access
        return self.valves_manager.valves[self.DP_ID]._route_manager_by_ipv[4]

    def address_flows(self, address):
        """Return the flows on the switch that match an address exactly, as
        the ARP target or sender or the IPv4 destination, with their table's
        name."""
        dp = self.valves_manager.valves[self.DP_ID].dp
        names = {table.table_id: name for name, table in dp.tables.items()}
        return [
            (names[table_id], flow)
            for table_id, flows in enumerate(self.network.tables[self.DP_ID].tables)
            for flow in flows
            if any(
                flow.match_values.get(key) == flow.match_to_bits(key, address)
                and flow.match_masks[key] == flow.match_to_bits(key, -1)
                for key in ("arp_tpa", "arp_spa", "ipv4_dst")
            )
        ]

    def assert_extra_ip_answered(self, port, vid, sender_ip, extra_ip):
        """Assert the switch answers a request or a probe for one of
        faucet_extra_ips back out its port, tagged if the port is tagged on
        the VLAN, with faucet_mac. Only a probe goes to the controller too."""
        dp = self.valves_manager.valves[self.DP_ID].dp
        tagged = dp.vlans[vid].port_is_tagged(dp.ports[port])
        request = self.arp_request(port, vid if tagged else 0, sender_ip, extra_ip)
        expected = {
            IN_PORT: [
                {
                    "in_port": port,
                    "vlan_vid": vid | ofp.OFPVID_PRESENT if tagged else 0,
                    "eth_src": dp.vlans[vid].faucet_mac,
                    "eth_dst": self.HOST_MAC,
                    "eth_type": 0x806,
                    "arp_op": arp.ARP_REPLY,
                    "arp_sha": dp.vlans[vid].faucet_mac,
                    "arp_spa": extra_ip,
                    "arp_tha": self.HOST_MAC,
                    "arp_tpa": sender_ip,
                }
            ]
        }
        if sender_ip == "0.0.0.0":
            expected[CONTROLLER_PORT] = [
                dict(request, vlan_vid=vid | ofp.OFPVID_PRESENT)
            ]
        self.assertEqual(expected, self.outputs(request))

    def assert_extra_ips_answered(self, extra_ips=None):
        """Assert the switch answers requests and probes for each of office's
        faucet_extra_ips on each of its running ports."""
        vlan = self.vlan()
        port_nos = sorted(port.number for port in vlan.get_ports() if port.running())
        for extra_ip in extra_ips or self.EXTRA_IPS:
            # A host in the subnet of the VIP whose subnet holds the address.
            faucet_vip = vlan.vip_map(ip_address(extra_ip))
            host_ip = str(next(faucet_vip.network.hosts()))
            for port in port_nos:
                for sender_ip in (host_ip, "0.0.0.0"):
                    with self.subTest(port=port, extra_ip=extra_ip, sender=sender_ip):
                        self.assert_extra_ip_answered(
                            port, vlan.vid, sender_ip, extra_ip
                        )

    def ipv4(self, port, vid, dst_ip, eth_dst=FAUCET_MAC, src_ip="10.0.0.1"):
        """Return an IPv4 packet received on a port, tagged with vid if not 0."""
        return {
            "in_port": port,
            "vlan_vid": vid | ofp.OFPVID_PRESENT if vid else 0,
            "eth_src": self.HOST_MAC,
            "eth_dst": eth_dst,
            "eth_type": 0x800,
            "ip_proto": 17,
            "ipv4_src": src_ip,
            "ipv4_dst": dst_ip,
        }

    def learn(self, src_ip, port=1, eth_src=None):
        """Have the controller learn a host from its ARP request for the VIP."""
        return self.rcv_packet(
            port,
            0x100,
            {
                "eth_src": eth_src or self.OTHER_MAC,
                "eth_dst": self.BROADCAST_MAC,
                "arp_code": arp.ARP_REQUEST,
                "arp_source_ip": src_ip,
                "arp_target_ip": "10.0.0.254",
            },
        )[self.DP_ID]

    @staticmethod
    def requested(ofmsgs):
        """Return the addresses ofmsgs send an ARP request for, or send an
        ARP reply or an IPv4 packet to: not gratuitous ARP, which announces
        its address, nor an ARP probe, which looks for a host using it."""
        requested = set()
        for pkt_out in ValveTestBases.packet_outs_from_flows(ofmsgs):
            pkt = valve_packet.parse_packet_in_pkt(bytes(pkt_out.data), None)[0]
            arp_pkt = pkt.get_protocol(arp.arp)
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            if arp_pkt is not None:
                if arp_pkt.src_ip not in (arp_pkt.dst_ip, "0.0.0.0"):
                    requested.add(arp_pkt.dst_ip)
            elif ipv4_pkt is not None:
                requested.add(ipv4_pkt.dst)
        return requested

    def resolvers(self, secs):
        """Run faucet's resolvers at a time, and return what they send."""
        valve = self.valves_manager.valves[self.DP_ID]
        now = self.mock_time(secs)
        ofmsgs = valve.resolve_gateways(now, None).get(valve, [])
        ofmsgs.extend(valve.state_expire(now, None).get(valve, []))
        self.apply_ofmsgs(ofmsgs)
        return ofmsgs

    def arp_in(self, port, opcode, src_ip, dst_ip, **kwargs):
        """Have FAUCET handle ARP the switch sends it from a port on office,
        tagged as the switch sends it: to eth_dst or broadcast, from eth_src
        or HOST_MAC, with src_mac or eth_src as the sender MAC."""
        eth_src = kwargs.get("eth_src", self.HOST_MAC)
        eth_dst = kwargs.get("eth_dst", self.BROADCAST_MAC)
        pkt = valve_packet.build_pkt_header(
            0x100, eth_src, eth_dst, valve_of.ether.ETH_TYPE_ARP
        )
        pkt.add_protocol(
            arp.arp(
                opcode=opcode,
                src_mac=kwargs.get("src_mac", eth_src),
                src_ip=src_ip,
                dst_mac=self.NO_MAC if opcode == arp.ARP_REQUEST else eth_dst,
                dst_ip=dst_ip,
            )
        )
        pkt.serialize()
        valve = self.valves_manager.valves[self.DP_ID]
        msg = namedtuple(
            "null_msg", ("match", "in_port", "data", "total_len", "cookie", "reason")
        )(
            {"in_port": port},
            port,
            pkt.data,
            len(pkt.data),
            valve.dp.cookie,
            valve_of.ofp.OFPR_ACTION,
        )
        self.valves_manager.valve_packet_in(self.mock_time(0), valve, msg)
        ofmsgs = self.last_flows_to_dp[self.DP_ID]
        self.last_flows_to_dp[self.DP_ID] = []
        self.apply_ofmsgs(ofmsgs)

    def assert_not_local(self, address, vid=0x100):
        """Assert FAUCET has no next hop, route or gateway for an address."""
        vlan = self.vlan(vid)
        ipa = ip_address(address)
        self.assertNotIn(ipa, vlan.neigh_cache_by_ipv(4))
        self.assertNotIn(ip_network(address), vlan.routes_by_ipv(4))
        self.assertEqual([], vlan.ip_dsts_for_ip_gw(ipa))
        self.assertNotIn(ipa, vlan.dyn_host_gws_by_ipv[4])
        self.assertNotIn(ipa, vlan.dyn_route_gws_by_ipv[4])


class ValveExtraIPsAnswerTestCase(ValveExtraIPsTestBase):
    """Test the switch answers ARP for faucet_extra_ips, and drops traffic
    routed to them."""

    def test_answered(self):
        """Test a request or a probe for each address is answered with
        faucet_mac out the port it came in on, tagged as it came in, and
        that the VIP still is."""
        self.assert_extra_ips_answered()
        self.assert_all_answered()

    def test_not_answered(self):
        """Test the switch leaves a request it is not to answer as it would
        without the option."""
        for port, vid, sender_ip, target_ip, opcode in (
            # For an address no VLAN lists.
            (1, 0, "10.0.0.1", "10.0.0.12", arp.ARP_REQUEST),
            (1, 0, "0.0.0.0", "10.0.0.12", arp.ARP_REQUEST),
            # From outside its VLAN's subnets.
            (1, 0, "10.2.0.1", "10.0.0.10", arp.ARP_REQUEST),
            (3, 0x100, "192.0.2.1", "10.0.0.10", arp.ARP_REQUEST),
            # On another VLAN, from either VLAN's subnet.
            (3, 0x200, "10.2.0.1", "10.0.0.10", arp.ARP_REQUEST),
            (4, 0, "10.0.0.1", "10.0.0.10", arp.ARP_REQUEST),
            (4, 0, "0.0.0.0", "10.0.0.10", arp.ARP_REQUEST),
            (5, 0, "10.0.0.1", "10.0.0.10", arp.ARP_REQUEST),
            # A reply.
            (1, 0, "10.0.0.1", "10.0.0.10", arp.ARP_REPLY),
            (1, 0, "0.0.0.0", "10.0.0.10", arp.ARP_REPLY),
        ):
            with self.subTest(port=port, sender_ip=sender_ip, target_ip=target_ip):
                self.assert_not_answered(
                    self.arp_request(port, vid, sender_ip, target_ip, opcode)
                )

    def test_flows(self):
        """Test each address has a flow for its VLAN and for each running port
        the VLAN is untagged on, for requests and for probes, above the VIP's
        controller flows, and a FIB flow to the VIP table, where its traffic
        is dropped, and that ARP from it goes to the controller, and is
        forwarded unless it is a reply to faucet_mac, above them all."""
        route_priority = self.route_manager().route_priority
        dp = self.valves_manager.valves[self.DP_ID].dp
        l2_table_id = self.valves_manager.valves[
            self.DP_ID
        ].pipeline.output_table.table_id
        for extra_ip in self.EXTRA_IPS:
            with self.subTest(extra_ip=extra_ip):
                flows = self.address_flows(extra_ip)
                responders = [
                    (
                        flow.priority,
                        (
                            flow.match_values["in_port"].int
                            if "in_port" in flow.match_values
                            else None
                        ),
                        flow.match_values["arp_spa"]
                        == flow.match_to_bits("arp_spa", "0.0.0.0"),
                        getattr(flow.instructions[0].actions[0], "port", None)
                        == CONTROLLER_PORT,
                    )
                    for name, flow in flows
                    if name == "vip" and self.is_responder(flow)
                ]
                # Requests from the subnet go to the switch alone, probes to
                # the controller too.
                self.assertEqual(
                    sorted(
                        (
                            (route_priority + 32 + 1 + bool(port), port, probe, probe)
                            for port in (None, 1, 2)
                            for probe in (False, True)
                        ),
                        key=str,
                    ),
                    sorted(responders, key=str),
                )
                others = sorted(
                    (
                        name,
                        flow.priority,
                        [getattr(inst, "table_id", None) for inst in flow.instructions],
                    )
                    for name, flow in flows
                    if not self.is_responder(flow)
                )
                self.assertEqual(
                    [
                        ("ipv4_fib", route_priority + 32, [dp.tables["vip"].table_id]),
                        ("vip", route_priority + 32, []),
                        ("vip", route_priority + 35, [None, l2_table_id]),
                        ("vip", route_priority + 35, [None, l2_table_id]),
                        ("vip", route_priority + 36, [None]),
                    ],
                    others,
                )
        # The VIP's own controller flows are below the address's.
        self.assertEqual(
            [route_priority + 32],
            [
                flow.priority
                for name, flow in self.address_flows("10.0.0.254")
                if name == "vip" and not self.is_responder(flow)
            ],
        )

    def test_serialize(self):
        """Test the switch is sent flows OpenFlow 1.3 can encode."""
        hosts = [(extra_ip, "255.255.255.255") for extra_ip in self.EXTRA_IPS]
        ofmsgs = [
            ofmsg
            for ofmsg in self.cold_start()
            if valve_of.is_flowaddmod(ofmsg)
            and (
                dict(ofmsg.match.items()).get("arp_tpa") in self.EXTRA_IPS
                or dict(ofmsg.match.items()).get("arp_spa") in hosts
                or dict(ofmsg.match.items()).get("ipv4_dst") in hosts
            )
        ]
        self.assertEqual(2 * 11, len(ofmsgs))
        for ofmsg in ofmsgs:
            valve_of.verify_flowmod(ofmsg)

    def test_dropped(self):
        """Test IPv4 traffic to an address is dropped, where to the VIP or to
        an unknown host it would go to the controller."""
        for port, vid in ((1, 0), (3, 0x100)):
            with self.subTest(port=port):
                self.assertEqual({}, self.outputs(self.ipv4(port, vid, "10.0.0.10")))
                for dst_ip in ("10.0.0.254", "10.0.0.12"):
                    self.assertIn(
                        CONTROLLER_PORT, self.outputs(self.ipv4(port, vid, dst_ip))
                    )

    def test_dropped_routed(self):
        """Test IPv4 traffic routed to an address from another VLAN is dropped,
        routed through VLANs or through a global VLAN."""
        for global_vlan in (None, 0xFFE):
            with self.subTest(global_vlan=global_vlan):
                self.restart(self.routed_config(global_vlan=global_vlan))
                self.assert_extra_ips_answered()
                for port, vid in ((4, 0), (3, 0x200)):
                    guest = self.ipv4(
                        port, vid, "10.0.0.10", self.GUEST_MAC, src_ip="10.2.0.1"
                    )
                    self.assertEqual({}, self.outputs(guest))
                    self.assertIn(
                        CONTROLLER_PORT,
                        self.outputs(dict(guest, ipv4_dst="10.0.0.12")),
                    )

    def test_no_other_flows_changed(self):
        """Test listing addresses changes no other flow, nor the pipeline."""
        extra_flows = {
            str(flow)
            for extra_ip in self.EXTRA_IPS
            for _, flow in self.address_flows(extra_ip)
        }
        self.assertEqual(22, len(extra_flows))
        others = [flow for flow in self.flows() if flow[1] not in extra_flows]
        pipeline = self.valves_manager.valves[self.DP_ID].dp.pipeline_str()
        self.restart(self.extra_ips_config([]))
        self.assertEqual(others, self.flows())
        self.assertEqual(
            pipeline, self.valves_manager.valves[self.DP_ID].dp.pipeline_str()
        )


class ValveExtraIPsLocalTestCase(ValveExtraIPsTestBase):
    """Test FAUCET treats faucet_extra_ips as its own addresses: it never
    learns or resolves one as a host or a gateway."""

    def test_not_learned(self):
        """Test a host using an address is not learned from its ARP request
        for the VIP, its ARP reply, or its ping of the VIP, where a host on
        an address not listed is, and that FAUCET does not answer it."""
        for kind, pkt in (
            (
                "request",
                {
                    "eth_dst": self.BROADCAST_MAC,
                    "arp_code": arp.ARP_REQUEST,
                    "arp_target_ip": "10.0.0.254",
                },
            ),
            (
                "reply",
                {
                    "eth_dst": FAUCET_MAC,
                    "arp_code": arp.ARP_REPLY,
                    "arp_target_ip": "10.0.0.254",
                },
            ),
            (
                "ping",
                {
                    "eth_dst": FAUCET_MAC,
                    "ipv4_dst": "10.0.0.254",
                    "echo_request_data": b"ping",
                },
            ),
        ):
            for address, local in (("10.0.0.10", True), ("10.0.0.12", False)):
                with self.subTest(kind=kind, address=address):
                    self.restart(self.config())
                    src = "ipv4_src" if kind == "ping" else "arp_source_ip"
                    ofmsgs = self.rcv_packet(
                        1, 0x100, dict(pkt, eth_src=self.OTHER_MAC, **{src: address})
                    )[self.DP_ID]
                    if local:
                        self.assertNotIn(address, self.requested(ofmsgs))
                        self.assert_not_local(address)
                    else:
                        self.assertIn(ip_network(address), self.vlan().routes_by_ipv(4))

    def test_not_routed_via(self):
        """Test no route can be added via an address, nor to it as a host,
        though one to a wider subnet that starts at it can."""
        valve = self.valves_manager.valves[self.DP_ID]
        vlan = self.vlan()
        self.assertIsNone(valve.router_vlan_for_ip_gw(vlan, ip_address("10.0.0.10")))
        self.assertEqual(
            vlan, valve.router_vlan_for_ip_gw(vlan, ip_address("10.0.0.1"))
        )
        for ip_gw, ip_dst in (
            ("10.0.0.10", "203.0.113.0/24"),
            ("10.0.0.1", "10.0.0.10/32"),
        ):
            with self.subTest(ip_gw=ip_gw, ip_dst=ip_dst):
                self.assertEqual(
                    [],
                    valve.add_route(vlan, ip_address(ip_gw), ip_network(ip_dst)),
                )
                self.assertNotIn(ip_network(ip_dst), vlan.routes_by_ipv(4))
        valve.add_route(vlan, ip_address("10.0.0.1"), ip_network("10.0.0.10/31"))
        self.assertEqual(
            ip_address("10.0.0.1"),
            vlan.routes_by_ipv(4).get(ip_network("10.0.0.10/31")),
        )
        # Routed together with guest, guest cannot route via it either.
        self.restart(self.routed_config())
        valve = self.valves_manager.valves[self.DP_ID]
        self.assertIsNone(
            valve.router_vlan_for_ip_gw(self.vlan(0x200), ip_address("10.0.0.10"))
        )
        self.assertEqual(
            [],
            valve.add_route(
                self.vlan(0x200), ip_address("10.0.0.1"), ip_network("10.0.0.10/32")
            ),
        )

    def test_not_resolved(self):
        """Test FAUCET sends no ARP request for an address, even asked to."""
        vlan = self.vlan()
        # pylint: disable=protected-access
        resolve = self.route_manager()._resolve_gw_on_vlan
        faucet_vip = vlan.vip_map(ip_address("10.0.0.10"))
        self.assertEqual([], resolve(vlan, faucet_vip, ip_address("10.0.0.10")))
        self.assertTrue(resolve(vlan, faucet_vip, ip_address("10.0.0.12")))
        requested = set()
        for secs in range(5, 300, 5):
            requested.update(self.requested(self.resolvers(secs)))
        self.assertIn("10.0.0.1", requested)
        self.assertFalse(requested & set(self.EXTRA_IPS))

    def test_purged_when_listed(self):
        """Test listing an address FAUCET has learned as a host, and as a
        gateway, forgets its next hop and the routes via it, and that FAUCET
        then asks for it no more."""
        self.restart(self.extra_ips_config([]))
        valve = self.valves_manager.valves[self.DP_ID]
        self.learn("10.0.0.10")
        self.apply_ofmsgs(
            valve.add_route(
                self.vlan(), ip_address("10.0.0.10"), ip_network("203.0.113.0/24")
            )
        )
        self.assertIn(1, self.outputs(self.ipv4(2, 0, "10.0.0.10")))
        self.assertIn(1, self.outputs(self.ipv4(2, 0, "203.0.113.1")))
        self.assertTrue(self.vlan().neigh_cache_by_ipv(4).get(ip_address("10.0.0.10")))
        self.warm_start(self.extra_ips_config(["10.0.0.10"]))
        self.assert_not_local("10.0.0.10")
        self.assertNotIn(ip_network("203.0.113.0/24"), self.vlan().routes_by_ipv(4))
        self.assertEqual({}, self.outputs(self.ipv4(2, 0, "10.0.0.10")))
        self.assertNotIn(1, self.outputs(self.ipv4(2, 0, "203.0.113.1")))
        self.assert_extra_ips_answered(["10.0.0.10"])
        requested = set()
        for secs in range(5, 600, 5):
            requested.update(self.requested(self.resolvers(secs)))
        self.assertNotIn("10.0.0.10", requested)
        self.assert_not_local("10.0.0.10")


class ValveExtraIPsAnnounceTestCase(ValveExtraIPsTestBase):
    """Test FAUCET announces faucet_extra_ips."""

    def packet_in(self, port, vid, match):
        """Have FAUCET handle a packet in between two runs of its services."""
        with mock.patch.object(self.valves_manager, "valve_flow_services"):
            return self.rcv_packet(port, vid, match)[self.DP_ID]

    def learn_gateway(self, ip_gw="10.0.0.1", port=1, vid=0x100):
        """Have FAUCET learn a gateway from its ARP request for the VIP."""
        vlan = self.vlan(vid)
        self.packet_in(
            port,
            vid,
            {
                "eth_src": self.HOST_MAC,
                "eth_dst": self.BROADCAST_MAC,
                "arp_code": arp.ARP_REQUEST,
                "arp_source_ip": ip_gw,
                "arp_target_ip": str(vlan.vip_map(ip_address(ip_gw)).ip),
            },
        )
        self.assertTrue(vlan.neigh_cache_by_ipv(4)[ip_address(ip_gw)].eth_src)

    def announced(self, ofmsgs, extra_ips=None):
        """Return the ARP packets ofmsgs send from faucet_extra_ips, each as
        its output ports, VID (0 untagged), Ethernet destination, opcode,
        sender MAC and IP, and target MAC and IP."""
        extra_ips = set(extra_ips or self.EXTRA_IPS)
        sent = []
        for pkt_out in ValveTestBases.packet_outs_from_flows(ofmsgs):
            pkt, _, _, _, vid = valve_packet.parse_packet_in_pkt(
                bytes(pkt_out.data), None
            )
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt is None or arp_pkt.src_ip not in extra_ips:
                continue
            sent.append(
                (
                    tuple(sorted(action.port for action in pkt_out.actions)),
                    vid or 0,
                    pkt.get_protocol(ethernet.ethernet).dst,
                    arp_pkt.opcode,
                    arp_pkt.src_mac,
                    arp_pkt.src_ip,
                    arp_pkt.dst_mac,
                    arp_pkt.dst_ip,
                )
            )
        return sorted(sent)

    def gratuitous(self, extra_ips=None):
        """Return the gratuitous ARP request and reply that announce each of
        faucet_extra_ips on office, flooded to its ports with faucet_mac."""
        return sorted(
            (
                ports,
                vid,
                self.BROADCAST_MAC,
                opcode,
                FAUCET_MAC,
                extra_ip,
                tha,
                extra_ip,
            )
            for extra_ip in extra_ips or self.EXTRA_IPS
            for ports, vid in (((1, 2), 0), ((3,), 0x100))
            for opcode, tha in (
                (arp.ARP_REQUEST, self.NO_MAC),
                (arp.ARP_REPLY, self.BROADCAST_MAC),
            )
        )

    def requests(self, ip_gw="10.0.0.1", port=1, vid=0, extra_ips=None):
        """Return the ARP request from each of faucet_extra_ips to a gateway
        learned with HOST_MAC."""
        return sorted(
            (
                (port,),
                vid,
                self.HOST_MAC,
                arp.ARP_REQUEST,
                FAUCET_MAC,
                extra_ip,
                self.NO_MAC,
                ip_gw,
            )
            for extra_ip in extra_ips or self.EXTRA_IPS
        )

    def test_cold_start(self):
        """Test claiming each address announces it once, then a request from
        it is sent to the route's gateway once its MAC is known, and that a
        cold start of the switch announces them again."""
        self.assertEqual(self.gratuitous(), self.announced(self.restart(self.config())))
        for _ in range(2):
            self.assertEqual([], self.announced(self.resolvers(1)))
            self.learn_gateway()
            self.assertEqual(self.requests(), self.announced(self.resolvers(1)))
            self.assertEqual([], self.announced(self.resolvers(1)))
            self.cold_start()
            self.assertEqual(self.gratuitous(), self.announced(self.resolvers(1)))

    def test_gateway_subnet(self):
        """Test the request from an address goes only to the gateways in its
        own subnet, tagged on a tagged port."""
        claimed = self.restart(
            self.extra_ips_config(
                ["10.0.0.10", "10.1.0.10"],
                office={
                    "faucet_vips": ["10.0.0.254/24", "10.1.0.254/24", "fc00::254/64"],
                    "routes": [
                        {"route": {"ip_dst": "192.0.2.0/24", "ip_gw": "10.0.0.1"}},
                        {"route": {"ip_dst": "198.51.100.0/24", "ip_gw": "10.1.0.1"}},
                    ],
                },
            )
        )
        extra_ips = ["10.0.0.10", "10.1.0.10"]
        self.assertEqual(self.gratuitous(extra_ips), self.announced(claimed, extra_ips))
        self.learn_gateway()
        self.learn_gateway("10.1.0.1", port=3)
        self.assertEqual(
            sorted(
                self.requests(extra_ips=["10.0.0.10"])
                + self.requests("10.1.0.1", 3, 0x100, ["10.1.0.10"])
            ),
            self.announced(self.resolvers(1), extra_ips),
        )

    def test_paced(self):
        """Test at most 16 addresses of a VLAN are announced at a time, as
        after a cold start of the switch."""
        extra_ips = ["10.0.0.%u" % host for host in range(10, 30)]
        self.restart(self.extra_ips_config(extra_ips))
        self.cold_start()
        announced = []
        for count in (16, 4, 0):
            sent = self.announced(self.resolvers(1), extra_ips)
            self.assertEqual(count, len({pkt[5] for pkt in sent}))
            announced.extend(sent)
        self.assertEqual(self.gratuitous(extra_ips), sorted(announced))

    def test_not_before_running(self):
        """Test nothing is announced while the switch is not connected, not
        even a refresh that is due, and that it is announced once it is."""
        timeout = self.valves_manager.valves[self.DP_ID].dp.arp_neighbor_timeout
        self.resolvers(1)
        self.learn_gateway()
        self.assertEqual(self.requests(), self.announced(self.resolvers(1)))
        self.disconnect_dp()
        self.assertEqual([], self.announced(self.resolvers(timeout)))
        self.connect_dp()
        self.assertEqual(self.gratuitous(), self.announced(self.resolvers(1)))

    def test_refresh(self):
        """Test the request to a gateway is sent again once per neighbor
        timeout, without announcing the address again."""
        timeout = self.valves_manager.valves[self.DP_ID].dp.arp_neighbor_timeout
        self.resolvers(1)
        self.learn_gateway()
        self.assertEqual(self.requests(), self.announced(self.resolvers(1)))
        self.assertEqual([], self.announced(self.resolvers(timeout - 3)))
        self.assertEqual(self.requests(), self.announced(self.resolvers(2)))
        self.assertEqual([], self.announced(self.resolvers(1)))

    def test_added(self):
        """Test a warm start claims and announces the addresses it adds alone,
        including one listed again after it was removed."""
        self.resolvers(1)
        extra_ips = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
        self.assertEqual(
            self.gratuitous(["10.0.0.12"]),
            self.announced(
                self.warm_start(self.extra_ips_config(["10.0.0.11", "10.0.0.12"])),
                extra_ips,
            ),
        )
        self.assertEqual(
            self.gratuitous(["10.0.0.10"]),
            self.announced(self.warm_start(self.config()), extra_ips),
        )


class ValveExtraIPsForeignTestCase(ValveExtraIPsTestBase):
    """Test ARP from other hosts using faucet_extra_ips is counted, and
    forwarded as it was before."""

    def extra_ip_metrics(self, extra_ip="10.0.0.10", vid=0x100):
        """Return an address's vlan_extra_ip_state and the count of ARP from
        other hosts using it, each None if not reported."""
        labels = dict(
            self.valves_manager.valves[self.DP_ID].dp.base_prom_labels(),
            vlan=str(vid),
            ip=extra_ip,
        )
        return tuple(
            self.registry.get_sample_value(var, labels)
            for var in ("vlan_extra_ip_state", "vlan_extra_ip_foreign_arp_total")
        )

    def arp_out(self, port, opcode, src_ip, dst_ip, eth_dst=None):
        """Return the ports the switch sends ARP from HOST_MAC on a port to."""
        eth_dst = eth_dst or self.BROADCAST_MAC
        return sorted(
            self.outputs(
                dict(
                    self.arp_request(port, 0, src_ip, dst_ip, opcode=opcode),
                    eth_dst=eth_dst,
                    arp_tha=self.NO_MAC if opcode == arp.ARP_REQUEST else eth_dst,
                )
            )
        )

    def test_forwarded(self):
        """Test ARP from an address goes to the controller and on as before,
        unanswered even when it is a gratuitous request or a request for the
        VIP, but for ARP to faucet_mac, which goes to the controller alone."""
        self.learn("10.0.0.2", port=2)
        flooded = [1, 2, 3, CONTROLLER_PORT]
        for opcode, dst_ip, eth_dst, outputs in (
            (arp.ARP_REQUEST, "10.0.0.10", None, flooded),
            (arp.ARP_REPLY, "10.0.0.10", None, flooded),
            (arp.ARP_REQUEST, "10.0.0.2", None, flooded),
            (arp.ARP_REQUEST, "10.0.0.254", None, flooded),
            (arp.ARP_REQUEST, "10.0.0.2", self.OTHER_MAC, [2, CONTROLLER_PORT]),
            (arp.ARP_REPLY, "10.0.0.2", self.OTHER_MAC, [2, CONTROLLER_PORT]),
            (arp.ARP_REQUEST, "10.0.0.254", FAUCET_MAC, [CONTROLLER_PORT]),
            (arp.ARP_REPLY, "10.0.0.254", FAUCET_MAC, [CONTROLLER_PORT]),
        ):
            with self.subTest(opcode=opcode, dst_ip=dst_ip, eth_dst=eth_dst):
                self.assertEqual(
                    outputs, self.arp_out(1, opcode, "10.0.0.10", dst_ip, eth_dst)
                )

    def test_counted(self):
        """Test the ARP faucet handles from another host using an address is
        counted, on a tagged port or not, and logged with the host's MAC and port once
        per neighbor timeout; but not its ARP to other hosts, which faucet
        does not handle."""
        timeout = self.valves_manager.valves[self.DP_ID].dp.arp_neighbor_timeout
        with mock.patch.object(self.route_manager().logger, "warning") as warning:
            for count, (port, opcode, dst_ip, eth_dst) in enumerate(
                (
                    (1, arp.ARP_REQUEST, "10.0.0.10", self.BROADCAST_MAC),
                    (1, arp.ARP_REPLY, "10.0.0.10", self.BROADCAST_MAC),
                    (3, arp.ARP_REQUEST, "10.0.0.254", self.BROADCAST_MAC),
                    (1, arp.ARP_REPLY, "10.0.0.254", FAUCET_MAC),
                ),
                start=1,
            ):
                self.arp_in(port, opcode, "10.0.0.10", dst_ip, eth_dst=eth_dst)
                self.assertEqual((1, count), self.extra_ip_metrics())
            self.arp_in(
                1, arp.ARP_REPLY, "10.0.0.10", "10.0.0.2", eth_dst=self.OTHER_MAC
            )
            self.assertEqual((1, 4), self.extra_ip_metrics())
            self.assertEqual((1, 0), self.extra_ip_metrics("10.0.0.11"))
            message = (
                "%s on Port 1 sent ARP from 10.0.0.10, "
                "which VLAN 256 lists in faucet_extra_ips"
            )
            self.assertEqual(
                [mock.call(message % self.HOST_MAC)], warning.call_args_list
            )
            self.mock_time(timeout - 1)
            self.arp_in(1, arp.ARP_REQUEST, "10.0.0.10", "10.0.0.10")
            self.assertEqual(1, warning.call_count)
            self.mock_time(1)
            self.arp_in(1, arp.ARP_REQUEST, "10.0.0.10", "10.0.0.10")
            self.assertEqual(2, warning.call_count)
        self.assertEqual((1, 6), self.extra_ip_metrics())

    def test_own_mac_ignored(self):
        """Test ARP from faucet_mac using an address, as another datapath's
        announcements carry, is not counted, whether it is the Ethernet source
        or the sender MAC."""
        for eth_src, src_mac in (
            (FAUCET_MAC, FAUCET_MAC),
            (self.HOST_MAC, FAUCET_MAC),
            (FAUCET_MAC, self.HOST_MAC),
        ):
            with self.subTest(eth_src=eth_src, src_mac=src_mac):
                self.arp_in(
                    1,
                    arp.ARP_REQUEST,
                    "10.0.0.10",
                    "10.0.0.10",
                    eth_src=eth_src,
                    src_mac=src_mac,
                )
                self.assertEqual((1, 0), self.extra_ip_metrics())
        self.arp_in(1, arp.ARP_REQUEST, "10.0.0.10", "10.0.0.10")
        self.assertEqual((1, 1), self.extra_ip_metrics())

    def test_probe_logged(self):
        """Test another host's probe for an address is logged once per
        neighbor timeout, though ARP from the address was logged, and not
        counted, and that no other probe is, nor a reply from a probe's sender
        address."""
        timeout = self.valves_manager.valves[self.DP_ID].dp.arp_neighbor_timeout
        self.arp_in(1, arp.ARP_REQUEST, "10.0.0.10", "10.0.0.10")
        with mock.patch.object(self.route_manager().logger, "info") as info:
            for _ in range(2):
                for eth_src, opcode, dst_ip in (
                    (self.HOST_MAC, arp.ARP_REQUEST, "10.0.0.10"),
                    (self.HOST_MAC, arp.ARP_REQUEST, "10.0.0.10"),
                    (FAUCET_MAC, arp.ARP_REQUEST, "10.0.0.11"),
                    (self.HOST_MAC, arp.ARP_REPLY, "10.0.0.11"),
                    (self.HOST_MAC, arp.ARP_REQUEST, "10.0.0.12"),
                ):
                    self.arp_in(1, opcode, "0.0.0.0", dst_ip, eth_src=eth_src)
                self.mock_time(timeout)
        message = (
            "%s on Port 1 probed for 10.0.0.10, "
            "which VLAN 256 lists in faucet_extra_ips"
        )
        self.assertEqual(
            [mock.call(message % self.HOST_MAC)] * 2,
            [call for call in info.call_args_list if "probed" in call.args[0]],
        )
        self.assertEqual((1, 1), self.extra_ip_metrics())

    def test_metrics(self):
        """Test each address is reported claimed, with no ARP from other hosts
        counted, once the switch connects; that its count is kept as the
        addresses or the VLAN change or the switch reconnects; and that its
        metrics go with the address, or with its VLAN."""
        guest = {"faucet_extra_ips": ["10.2.0.10"]}
        self.restart(self.config(vlans={"guest": guest}))
        for extra_ip, vid in (
            ("10.0.0.10", 0x100),
            ("10.0.0.11", 0x100),
            ("10.2.0.10", 0x200),
        ):
            self.assertEqual((1, 0), self.extra_ip_metrics(extra_ip, vid))
        self.arp_in(1, arp.ARP_REQUEST, "10.0.0.10", "10.0.0.10")
        office = {"faucet_extra_ips": ["10.0.0.10", "10.0.0.12"]}
        for vlans in (
            {"office": office, "guest": guest},
            {"office": dict(office, max_hosts=2), "guest": guest},
        ):
            with self.subTest(vlans=vlans):
                self.warm_start(self.config(vlans=vlans))
                self.assertEqual((1, 1), self.extra_ip_metrics())
                self.assertEqual((None, None), self.extra_ip_metrics("10.0.0.11"))
                self.assertEqual((1, 0), self.extra_ip_metrics("10.0.0.12"))
        self.disconnect_dp()
        self.connect_dp()
        self.assertEqual((1, 1), self.extra_ip_metrics())
        self.warm_start(
            self.config(
                vlans={"office": office, "guest": None},
                interfaces={3: {"tagged_vlans": ["office"]}, 4: {"native_vlan": "lab"}},
            )
        )
        self.assertEqual((None, None), self.extra_ip_metrics("10.2.0.10", 0x200))
        self.assertEqual((1, 1), self.extra_ip_metrics())


class ValveExtraIPsWarmTestBase(ValveExtraIPsTestBase):
    """Warm start changes of faucet_extra_ips."""

    def warm_extra_ips(self, config, changed_ips, deleted_vids=()):
        """Warm start to config, assert it deletes and adds back no VLAN but
        deleted_vids, and that every flow it sends is for one of changed_ips
        if no VLAN is deleted. Return what it sends."""
        with mock.patch.object(
            Valve, "del_vlan", autospec=True, side_effect=Valve.del_vlan
        ) as del_vlan, mock.patch.object(
            Valve, "add_vlan", autospec=True, side_effect=Valve.add_vlan
        ) as add_vlan:
            ofmsgs = self.warm_start(config)
        self.assertEqual(
            sorted(deleted_vids),
            sorted(call.args[1].vid for call in del_vlan.call_args_list),
        )
        if not deleted_vids:
            self.assertEqual([], add_vlan.call_args_list)
            addresses = set(changed_ips)
            for ofmsg in ofmsgs:
                if not valve_of.is_flowmod(ofmsg):
                    continue
                match = dict(ofmsg.match.items())
                address = match.get(
                    "arp_tpa",
                    match.get("ipv4_dst", match.get("arp_spa", (None,)))[0],
                )
                self.assertIn(address, addresses, msg=str(ofmsg))
        return ofmsgs

    def learn_gateway(self):
        """Learn office's gateway, 10.0.0.1 on port 1, and return what the
        switch sends for traffic routed through it."""
        self.learn("10.0.0.1", eth_src=self.HOST_MAC)
        self.resolvers(5)
        routed = self.outputs(self.ipv4(2, 0, "192.0.2.1"))
        self.assertIn(1, routed)
        return routed

    def assert_gateway_kept(self, routed):
        """Assert office's gateway is still learned, and routed through."""
        self.assertTrue(self.vlan().neigh_cache_by_ipv(4).get(ip_address("10.0.0.1")))
        self.assertEqual(routed, self.outputs(self.ipv4(2, 0, "192.0.2.1")))

    def assert_gone(self, extra_ip):
        """Assert the switch has no flow for an address, nor answers for it."""
        self.assertEqual([], self.address_flows(extra_ip))
        for port, vid in ((1, 0), (3, 0x100)):
            for sender_ip in ("10.0.0.1", "0.0.0.0"):
                self.assert_not_answered(
                    self.arp_request(port, vid, sender_ip, extra_ip)
                )


class ValveExtraIPsWarmTestCase(ValveExtraIPsWarmTestBase):
    """Test adding or removing faucet_extra_ips is a warm start of their
    flows alone."""

    def test_add(self):
        """Test listing addresses adds their flows alone, as a cold start
        would, though no address was listed before."""
        self.restart(self.extra_ips_config([]))
        config = self.config()
        ofmsgs = self.warm_extra_ips(config, self.EXTRA_IPS)
        self.assertTrue(ofmsgs)
        self.assert_extra_ips_answered()
        self.assert_cold_start_same(config)

    def test_remove(self):
        """Test removing an address deletes its flows alone, strictly, and
        keeps the others'."""
        config = self.extra_ips_config(["10.0.0.10"])
        ofmsgs = self.warm_extra_ips(config, ["10.0.0.11"])
        self.assertTrue(ofmsgs)
        for ofmsg in ofmsgs:
            if valve_of.is_flowmod(ofmsg):
                self.assertEqual(ofp.OFPFC_DELETE_STRICT, ofmsg.command, msg=str(ofmsg))
        self.assert_gone("10.0.0.11")
        self.assert_extra_ips_answered(["10.0.0.10"])
        self.assert_cold_start_same(config)

    def test_remove_all(self):
        """Test removing every address deletes all their flows."""
        config = self.extra_ips_config([])
        self.warm_extra_ips(config, self.EXTRA_IPS)
        for extra_ip in self.EXTRA_IPS:
            self.assert_gone(extra_ip)
        self.assert_all_answered()
        self.assert_cold_start_same(config)

    def test_replace(self):
        """Test replacing an address with another, in another subnet of the
        VLAN, and on the same VLAN's other subnet."""
        vips = ["10.0.0.254/24", "10.1.0.254/24", "fc00::254/64"]
        for before, after in (
            (["10.0.0.10", "10.0.0.11"], ["10.0.0.11", "10.0.0.12"]),
            (["10.0.0.10"], ["10.1.0.10"]),
        ):
            with self.subTest(before=before, after=after):
                self.restart(
                    self.extra_ips_config(before, office={"faucet_vips": vips})
                )
                config = self.extra_ips_config(after, office={"faucet_vips": vips})
                self.warm_extra_ips(config, set(before) ^ set(after))
                for extra_ip in set(before) - set(after):
                    self.assert_gone(extra_ip)
                self.assert_extra_ips_answered(after)
                self.assert_cold_start_same(config)

    def test_hosts_kept(self):
        """Test changing addresses keeps the hosts and next hops learned on
        the VLAN, and their routes."""
        routed = self.learn_gateway()
        self.warm_extra_ips(
            self.extra_ips_config(["10.0.0.12"]),
            ["10.0.0.10", "10.0.0.11", "10.0.0.12"],
        )
        self.assert_gateway_kept(routed)
        self.assert_extra_ips_answered(["10.0.0.12"])

    def test_port_down(self):
        """Test a port that goes down loses its flows for the addresses, even
        if they change while it is down, and gets them back when it comes up."""
        self.set_port_down(1)
        self.assertEqual([], self.responder_matches(in_port=1))
        self.warm_extra_ips(
            self.extra_ips_config(["10.0.0.11", "10.0.0.12"]),
            ["10.0.0.10", "10.0.0.12"],
        )
        self.assertEqual([], self.responder_matches(in_port=1))
        self.set_port_up(1)
        self.assert_extra_ips_answered(["10.0.0.11", "10.0.0.12"])
        self.assert_gone("10.0.0.10")

    def test_global_routing(self):
        """Test adding and removing an address with a global VLAN."""
        self.restart(self.routed_config(global_vlan=0xFFE))
        config = self.routed_config(
            global_vlan=0xFFE,
            vlans={"office": {"faucet_extra_ips": ["10.0.0.11", "10.0.0.12"]}},
        )
        self.warm_extra_ips(config, ["10.0.0.10", "10.0.0.12"])
        self.assert_gone("10.0.0.10")
        self.assert_extra_ips_answered(["10.0.0.11", "10.0.0.12"])
        self.assert_cold_start_same(config)


class ValveExtraIPsWarmVLANTestCase(ValveExtraIPsWarmTestBase):
    """Test changing faucet_extra_ips with their VLAN or its ports, or
    deleting the VLAN."""

    def test_with_other_changes(self):
        """Test changing addresses with the VLAN, or with its ports."""
        for vlans, interfaces in (
            ({"office": {"max_hosts": 2}}, None),
            (None, {2: {"native_vlan": "guest"}}),
            (None, {6: {"native_vlan": "office"}}),
        ):
            with self.subTest(vlans=vlans, interfaces=interfaces):
                self.restart(self.config())
                vlans = dict(vlans or {})
                vlans["office"] = dict(
                    vlans.get("office", {}), faucet_extra_ips=["10.0.0.11", "10.0.0.12"]
                )
                config = self.config(vlans=vlans, interfaces=interfaces)
                self.warm_start(config)
                if 6 in (interfaces or {}):
                    # An added port is answered for once it is up.
                    self.set_port_up(6)
                self.assert_gone("10.0.0.10")
                self.assert_extra_ips_answered(["10.0.0.11", "10.0.0.12"])
                self.assert_cold_start_same(config)

    def test_hosts_kept_with_port(self):
        """Test changing addresses as a port joins the VLAN keeps the hosts
        and next hops learned on the VLAN, as the port joining alone does."""
        routed = self.learn_gateway()
        self.warm_start(
            self.config(
                vlans={"office": {"faucet_extra_ips": ["10.0.0.13"]}},
                interfaces={6: {"native_vlan": "office"}},
            )
        )
        self.assert_gateway_kept(routed)
        self.assert_extra_ips_answered(["10.0.0.13"])

    def test_delete_vlan(self):
        """Test deleting a VLAN deletes all the flows for its addresses, and
        leaves those of another VLAN."""
        self.restart(self.config(vlans={"guest": {"faucet_extra_ips": ["10.2.0.10"]}}))
        self.assertTrue(self.address_flows("10.2.0.10"))
        config = self.config(
            vlans={"guest": None},
            interfaces={3: {"tagged_vlans": ["office"]}, 4: {"native_vlan": "lab"}},
        )
        # lab gains port 4, so it is changed, deleted and added back.
        self.warm_extra_ips(config, [], deleted_vids=[0x200, 0x300])
        self.assertEqual([], self.address_flows("10.2.0.10"))
        self.assert_extra_ips_answered()
        self.assert_cold_start_same(config)


class ValveExtraIPsAnswerTFMTestCase(ValveExtraIPsAnswerTestCase):
    """Test the switch answers ARP for faucet_extra_ips with a TFM pipeline."""

    REQUIRE_TFM = True
    HARDWARE = "Open vSwitch TFM"


class ValveExtraIPsWarmTFMTestCase(ValveExtraIPsWarmTestCase):
    """Test adding or removing faucet_extra_ips is a warm start with a TFM
    pipeline, which listing the first address does not change."""

    REQUIRE_TFM = True
    HARDWARE = "Open vSwitch TFM"


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
