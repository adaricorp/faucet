#!/usr/bin/env python3

"""Test FAUCET valve_route."""

# pylint: disable=protected-access

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

import ipaddress
import random
import unittest

from os_ken.lib.packet import arp, icmpv6

from clib.valve_test_lib import ValveTestBases
from faucet import valve_packet
from faucet.router import Router
from faucet.valve_route import ValveIPv4RouteManager
from faucet.vlan import VLAN


def replaced_router_for_vlan(self, vlan):
    """ValveRouteManager._router_for_vlan() as it was before the lookup.

    Kept verbatim, as the oracle for the differential test below.
    """
    if self.routers:
        for router in self.routers.values():
            if vlan in router.vlans:
                return router
    return None


def replaced_routed_vlans(self, vlan):
    """ValveRouteManager._routed_vlans() as it was before the lookup.

    Kept verbatim, as the oracle for the differential test below.
    """
    if self.global_routing:
        return set([self.global_vlan])
    vlans = set([vlan])
    if self.routers:
        for router in self.routers.values():
            if vlan in router.vlans:
                vlans = vlans.union(router.vlans)
    return vlans


def vlan_key(vlan):
    """Return what identifies a VLAN in a routed set: its VID and its name.

    The global routing answer is an AnonVLAN, which has a VID and no name.
    """
    return (vlan.vid, getattr(vlan, "name", None))


class ValveRouteManagerVLANTestCase(unittest.TestCase):
    """Test which VLANs and routers a VLAN is routed with."""

    @staticmethod
    def build_vlan(vid, name):
        """Return a finalized VLAN with this VID and name."""
        vlan = VLAN(name, 1, {"vid": vid})
        vlan.finalize()
        return vlan

    @staticmethod
    def build_routers(*router_vlans):
        """Return finalized routers, in order, each naming its VLANs."""
        routers = {}
        for index, (name, vlans) in enumerate(router_vlans):
            router = Router(name, index, {"vlans": [vlan.vid for vlan in vlans]})
            router.vlans = list(vlans)
            router.finalize()
            routers[name] = router
        return routers

    @staticmethod
    def build_route_manager(routers):
        """Return a route manager with only what these tests reach for."""
        return ValveIPv4RouteManager(
            None,
            None,
            0,
            0,
            0,
            0,
            0,
            False,
            False,
            False,
            None,
            None,
            None,
            routers,
            None,
        )

    def test_routed_vlans_union(self):
        """Test a VLAN is routed with every VLAN of every router naming it."""
        office = self.build_vlan(100, "office")
        guest = self.build_vlan(200, "guest")
        voip = self.build_vlan(300, "voip")
        routers = self.build_routers(
            ("r1", [office, guest]),
            ("r2", [office, voip]),
            ("r3", [guest, voip]),
        )
        route_manager = self.build_route_manager(routers)
        self.assertEqual(
            {vlan.vid for vlan in route_manager._routed_vlans(office)},
            {100, 200, 300},
            "routed vlans not the union of the routers naming this vlan",
        )

    def test_routed_vlans_unrouted(self):
        """Test a VLAN no router names is routed only with itself."""
        office = self.build_vlan(100, "office")
        lonely = self.build_vlan(999, "lonely")
        route_manager = self.build_route_manager(self.build_routers(("r1", [office])))
        self.assertEqual(
            route_manager._routed_vlans(lonely),
            {lonely},
            "unrouted vlan routed with something else",
        )

    def test_routed_vlans_previous_config(self):
        """Test a VLAN carried over a reload is not the VLAN with its VID."""
        # merge_dyn can leave a port pointing at the previous config's VLAN,
        # so two objects share one VID and each routes with its own router.
        office = self.build_vlan(100, "office")
        was_office = self.build_vlan(100, "office-was")
        guest = self.build_vlan(200, "guest")
        voip = self.build_vlan(300, "voip")
        routers = self.build_routers(
            ("r1", [office, guest]), ("r2", [was_office, voip])
        )
        route_manager = self.build_route_manager(routers)
        self.assertEqual(
            {vlan.vid for vlan in route_manager._routed_vlans(office)},
            {100, 200},
            "vlan routed with a same VID vlan from another config",
        )
        self.assertEqual(
            {vlan.vid for vlan in route_manager._routed_vlans(was_office)},
            {100, 300},
            "vlan from another config routed with the current one",
        )

    def test_router_for_vlan_first(self):
        """Test route ownership follows the first router naming the VLAN."""
        office = self.build_vlan(100, "office")
        routers = self.build_routers(("r1", [office]), ("r2", [office]))
        route_manager = self.build_route_manager(routers)
        self.assertIs(
            route_manager._router_for_vlan(office),
            routers["r1"],
            "router for vlan not the first configured",
        )

    def test_router_for_vlan_unrouted(self):
        """Test a VLAN no router names has no router."""
        office = self.build_vlan(100, "office")
        lonely = self.build_vlan(999, "lonely")
        route_manager = self.build_route_manager(self.build_routers(("r1", [office])))
        self.assertEqual(
            route_manager._router_for_vlan(lonely),
            None,
            "unrouted vlan has a router",
        )

    def test_routers_by_vid_reused(self):
        """Test lookups read the index built at construction, not the routers."""
        office = self.build_vlan(100, "office")
        guest = self.build_vlan(200, "guest")
        routers = self.build_routers(("r1", [office, guest]))
        route_manager = self.build_route_manager(routers)
        routers_by_vid = route_manager.routers_by_vid
        self.assertEqual(sorted(routers_by_vid), [100, 200], "index not keyed by VID")
        route_manager._routed_vlans(office)
        route_manager._router_for_vlan(office)
        self.assertIs(
            route_manager.routers_by_vid, routers_by_vid, "index rebuilt by a lookup"
        )
        routers_by_vid.clear()
        self.assertEqual(
            route_manager._routed_vlans(office),
            {office},
            "routed vlans found without the index",
        )
        self.assertIsNone(
            route_manager._router_for_vlan(office), "router found without the index"
        )

    def test_routed_vlans_match_replaced_scan(self):
        """Test random routers route each VLAN as the replaced scan did.

        Generated sets of VLANs and routers, including VLANs carried over
        from a previous config that share a VID with a current one, must
        give the same routed VLANs and the same router by the lookup as by
        scanning every router.
        """
        rng = random.Random(1)
        for sample in range(200):
            vids = rng.sample(range(2, 4000), rng.randint(2, 6))
            vlans = [self.build_vlan(vid, "v%d" % vid) for vid in vids]
            vlans.extend(
                self.build_vlan(vid, "v%d-was" % vid)
                for vid in rng.sample(vids, rng.randint(0, 2))
            )
            router_vlans = [
                ("r%d" % index, rng.sample(vlans, rng.randint(1, min(4, len(vlans)))))
                for index in range(rng.randint(0, 4))
            ]
            route_manager = self.build_route_manager(self.build_routers(*router_vlans))
            for vlan in vlans:
                with self.subTest(sample=sample, vlan=vlan.name):
                    self.assertEqual(
                        {
                            vlan_key(routed)
                            for routed in route_manager._routed_vlans(vlan)
                        },
                        {
                            vlan_key(routed)
                            for routed in replaced_routed_vlans(route_manager, vlan)
                        },
                        "routed vlans differ from the replaced scan",
                    )
                    self.assertIs(
                        route_manager._router_for_vlan(vlan),
                        replaced_router_for_vlan(route_manager, vlan),
                        "router differs from the replaced scan",
                    )


class ValveRouteManagerVIPMapTestCase(unittest.TestCase):
    """Test which VIP subnets are resolved from a VLAN in several routers."""

    @staticmethod
    def build_vlan(vid, name, faucet_vips):
        """Return a finalized VLAN with this VID, name and VIPs."""
        vlan = VLAN(name, 1, {"vid": vid, "faucet_vips": faucet_vips})
        vlan.finalize()
        return vlan

    @staticmethod
    def vip_map_scan(route_manager, vlan, ipa):
        """Return the VLAN and VIP for an address by scanning the routers.

        Each router maps a subnet to the last of its VLANs with it, the
        first router naming the VLAN keeps a subnet, and the most specific
        subnet holding the address wins.
        """
        subnets = {}
        for router in route_manager.routers.values():
            if vlan not in router.vlans:
                continue
            router_subnets = {}
            for router_vlan in router.vlans:
                for faucet_vip in router_vlan.faucet_vips_by_ipv(ipa.version):
                    router_subnets[faucet_vip.network] = (router_vlan, faucet_vip)
            for network, result in router_subnets.items():
                subnets.setdefault(network, result)
        holding = [network for network in subnets if ipa in network]
        if not holding:
            return (None, None)
        return subnets[max(holding, key=lambda network: network.prefixlen)]

    def lookup(self, route_manager, vlan, ipa):
        """Return the VLAN and VIP the route manager resolves an address in."""
        vip_map = route_manager.vip_maps_by_vid.get(vlan.vid, None)
        self.assertIsNotNone(vip_map, "no VIP map for a routed vlan")
        return vip_map.get(ipa, (None, None))

    def test_vip_map_all_routers(self):
        """Test a VLAN resolves in the VLANs of every router naming it."""
        host = self.build_vlan(100, "host", ["10.10.0.254/24"])
        office = self.build_vlan(200, "office", ["10.20.0.254/24"])
        guest = self.build_vlan(300, "guest", ["10.30.0.254/24"])
        routers = ValveRouteManagerVLANTestCase.build_routers(
            ("r1", [host, office]), ("r2", [host, guest])
        )
        route_manager = ValveRouteManagerVLANTestCase.build_route_manager(routers)
        for ipa, vlan in (
            ("10.20.0.1", office),
            ("10.30.0.1", guest),
            ("10.10.0.1", host),
        ):
            result_vlan, faucet_vip = self.lookup(
                route_manager, host, ipaddress.ip_address(ipa)
            )
            self.assertIs(result_vlan, vlan, "%s not resolved in its vlan" % ipa)
            self.assertIn(faucet_vip, vlan.faucet_vips)
        self.assertEqual(
            self.lookup(route_manager, office, ipaddress.ip_address("10.30.0.1")),
            (None, None),
            "resolved in a vlan no router of this vlan names",
        )

    def test_vip_map_same_subnet_first_router(self):
        """Test a subnet in two routers resolves in the first router's VLAN."""
        host = self.build_vlan(100, "host", ["10.10.0.254/24"])
        office = self.build_vlan(200, "office", ["10.20.0.254/24"])
        office_too = self.build_vlan(201, "office-too", ["10.20.0.253/24"])
        routers = ValveRouteManagerVLANTestCase.build_routers(
            ("r1", [host, office]), ("r2", [host, office_too])
        )
        route_manager = ValveRouteManagerVLANTestCase.build_route_manager(routers)
        result_vlan, _ = self.lookup(
            route_manager, host, ipaddress.ip_address("10.20.0.1")
        )
        self.assertIs(result_vlan, office, "first router's vlan not kept")

    def test_vip_map_most_specific(self):
        """Test a more specific subnet in a later router wins, as in the FIB."""
        host = self.build_vlan(100, "host", ["10.10.0.254/24"])
        office = self.build_vlan(200, "office", ["10.20.0.254/16"])
        lab = self.build_vlan(300, "lab", ["10.20.5.254/24"])
        routers = ValveRouteManagerVLANTestCase.build_routers(
            ("r1", [host, office]), ("r2", [host, lab])
        )
        route_manager = ValveRouteManagerVLANTestCase.build_route_manager(routers)
        for ipa, vlan in (("10.20.5.1", lab), ("10.20.6.1", office)):
            result_vlan, _ = self.lookup(route_manager, host, ipaddress.ip_address(ipa))
            self.assertIs(result_vlan, vlan, "%s not resolved in %s" % (ipa, vlan))

    def test_vip_map_unrouted(self):
        """Test a VLAN no router names has no map, and one with no VIPs an empty one."""
        host = self.build_vlan(100, "host", ["10.10.0.254/24"])
        bare = self.build_vlan(200, "bare", [])
        lonely = self.build_vlan(999, "lonely", ["10.99.0.254/24"])
        routers = ValveRouteManagerVLANTestCase.build_routers(("r1", [host, bare]))
        route_manager = ValveRouteManagerVLANTestCase.build_route_manager(routers)
        self.assertNotIn(lonely.vid, route_manager.vip_maps_by_vid)
        self.assertEqual(
            self.lookup(route_manager, bare, ipaddress.ip_address("10.99.0.1")),
            (None, None),
        )

    def test_vip_map_matches_scan(self):
        """Test random routers resolve every address as scanning them would."""
        rng = random.Random(1)
        subnets = [
            "10.0.0.254/16",
            "10.0.1.254/24",
            "10.0.2.254/24",
            "10.0.1.126/25",
            "10.1.0.254/24",
            "10.2.0.254/24",
        ]
        addresses = [
            ipaddress.ip_address(ipa)
            for ipa in ("10.0.1.1", "10.0.1.200", "10.0.2.1", "10.0.9.1")
            + ("10.1.0.1", "10.2.0.1", "10.3.0.1")
        ]
        for sample in range(200):
            vids = rng.sample(range(2, 4000), rng.randint(2, 6))
            vlans = [
                self.build_vlan(
                    vid, "v%d" % vid, rng.sample(subnets, rng.randint(0, 2))
                )
                for vid in vids
            ]
            router_vlans = [
                ("r%d" % index, rng.sample(vlans, rng.randint(1, min(4, len(vlans)))))
                for index in range(rng.randint(1, 4))
            ]
            routers = ValveRouteManagerVLANTestCase.build_routers(*router_vlans)
            route_manager = ValveRouteManagerVLANTestCase.build_route_manager(routers)
            for vlan in vlans:
                vip_map = route_manager.vip_maps_by_vid.get(vlan.vid, None)
                if vip_map is None:
                    continue
                for ipa in addresses:
                    with self.subTest(sample=sample, vlan=vlan.name, ipa=str(ipa)):
                        self.assertEqual(
                            vip_map.get(ipa, (None, None)),
                            self.vip_map_scan(route_manager, vlan, ipa),
                            "resolved differently from a scan of the routers",
                        )


class ValveProactiveLearnRoutersTestCase(ValveTestBases.ValveTestNetwork):
    """Test a host's traffic resolves a destination behind any of its routers."""

    REQUIRE_TFM = False

    CONFIG = """
vlans:
  host:
    vid: 0x100
    faucet_mac: "0e:00:00:00:01:00"
    faucet_vips: ["10.10.0.254/24", "fc10::254/64"]
  office:
    vid: 0x200
    faucet_mac: "0e:00:00:00:02:00"
    faucet_vips: ["10.20.0.254/24", "fc20::254/64"]
  guest:
    vid: 0x300
    faucet_mac: "0e:00:00:00:03:00"
    faucet_vips: ["10.30.0.254/24", "fc30::254/64"]
routers:
  host-office:
    vlans: [host, office]
  host-guest:
    vlans: [host, guest]
dps:
  s1:
    dp_id: 1
    hardware: "Open vSwitch"
    ignore_learn_ins: 0
    interfaces:
      1:
        native_vlan: host
      2:
        native_vlan: office
      3:
        native_vlan: guest
"""

    HOST = ("00:00:00:01:00:01", {4: "10.10.0.1", 6: "fc10::1"})
    # Port, VID, MAC and addresses of a host on each VLAN routed with host's.
    # host-guest sorts before host-office, so office is behind the second.
    CLIENTS = {
        "office": (2, 0x200, "00:00:00:02:00:01", {4: "10.20.0.1", 6: "fc20::1"}),
        "guest": (3, 0x300, "00:00:00:03:00:01", {4: "10.30.0.1", 6: "fc30::1"}),
    }

    def setUp(self):
        """Setup the routed VLANs."""
        self.setup_valves(self.CONFIG)

    def _vlan(self, vid):
        """Return a VLAN."""
        return self.valves_manager.valves[self.DP_ID].dp.vlans[vid]

    def _from_host(self, client, ipv):
        """Return a packet from the host to a client, as the switch sees it."""
        host_mac, host_ips = self.HOST
        client_ips = self.CLIENTS[client][3]
        return {
            "in_port": 1,
            "vlan_vid": 0,
            "eth_type": 0x800 if ipv == 4 else 0x86DD,
            "eth_src": host_mac,
            "eth_dst": self._vlan(0x100).faucet_mac,
            "ipv%u_src" % ipv: host_ips[ipv],
            "ipv%u_dst" % ipv: client_ips[ipv],
            "echo_request_data": self.ICMP_PAYLOAD,
        }

    @staticmethod
    def _requested(ofmsgs):
        """Return the addresses ofmsgs send an ARP request or an NS for."""
        requested = set()
        for pkt_out in ValveTestBases.packet_outs_from_flows(ofmsgs):
            pkt = valve_packet.parse_packet_in_pkt(bytes(pkt_out.data), None)[0]
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
                requested.add(arp_pkt.dst_ip)
            icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
            if icmpv6_pkt and icmpv6_pkt.type_ == icmpv6.ND_NEIGHBOR_SOLICIT:
                requested.add(icmpv6_pkt.data.dst)
        return requested

    def _reply(self, client, ipv):
        """Reply from a client to faucet's request, by ARP or by ND."""
        port, vid, client_mac, client_ips = self.CLIENTS[client]
        vlan = self._vlan(vid)
        client_ip = client_ips[ipv]
        vip = str(vlan.vip_map(ipaddress.ip_address(client_ip)).ip)
        match = {"eth_src": client_mac, "eth_dst": vlan.faucet_mac}
        if ipv == 4:
            match.update(
                {
                    "arp_code": arp.ARP_REPLY,
                    "arp_source_ip": client_ip,
                    "arp_target_ip": vip,
                }
            )
        else:
            match.update(
                {
                    "ipv6_src": client_ip,
                    "ipv6_dst": vip,
                    "neighbor_advert_ip": client_ip,
                }
            )
        self.rcv_packet(port, vid, match)

    def test_host_traffic_resolves_client(self):
        """Test the host's traffic to a client behind either router resolves it."""
        table = self.network.tables[self.DP_ID]
        for client, (port, _, client_mac, client_ips) in self.CLIENTS.items():
            for ipv in (4, 6):
                with self.subTest(client=client, ipv=ipv):
                    from_host = self._from_host(client, ipv)
                    ofmsgs = self.rcv_packet(1, 0x100, dict(from_host))[self.DP_ID]
                    self.assertIn(
                        client_ips[ipv],
                        self._requested(ofmsgs),
                        "host's traffic did not resolve the client",
                    )
                    self._reply(client, ipv)
                    outputs = table.get_port_outputs(dict(from_host))
                    self.assertTrue(
                        any(
                            pkt["eth_dst"] == client_mac
                            for pkt in outputs.get(port, [])
                        ),
                        "host's traffic not routed to the client once it replied",
                    )

    def test_resolved_client_kept(self):
        """Test a packet reaching faucet for a resolved client leaves its route."""
        table = self.network.tables[self.DP_ID]
        for client, (port, vid, client_mac, client_ips) in self.CLIENTS.items():
            for ipv in (4, 6):
                with self.subTest(client=client, ipv=ipv):
                    from_host = self._from_host(client, ipv)
                    self.rcv_packet(1, 0x100, dict(from_host))
                    self._reply(client, ipv)
                    # The next packet raced the route's flows to the switch.
                    ofmsgs = self.rcv_packet(1, 0x100, dict(from_host))[self.DP_ID]
                    self.assertNotIn(
                        client_ips[ipv],
                        self._requested(ofmsgs),
                        "resolved client resolved again",
                    )
                    cache = self._vlan(vid).neigh_cache_by_ipv(ipv)
                    self.assertEqual(
                        cache[ipaddress.ip_address(client_ips[ipv])].eth_src,
                        client_mac,
                        "resolved client's neighbour entry reset",
                    )
                    outputs = table.get_port_outputs(dict(from_host))
                    self.assertTrue(
                        any(
                            pkt["eth_dst"] == client_mac
                            for pkt in outputs.get(port, [])
                        ),
                        "resolved client's route replaced",
                    )

    def test_advertised_client_routed(self):
        """Test a packet reaching faucet for a client known only from its
        advert, with no route yet, routes it."""
        table = self.network.tables[self.DP_ID]
        for client, (port, vid, client_mac, client_ips) in self.CLIENTS.items():
            for ipv in (4, 6):
                with self.subTest(client=client, ipv=ipv):
                    self._reply(client, ipv)
                    cache = self._vlan(vid).neigh_cache_by_ipv(ipv)
                    self.assertEqual(
                        cache[ipaddress.ip_address(client_ips[ipv])].eth_src,
                        client_mac,
                        "client's advert not cached",
                    )
                    from_host = self._from_host(client, ipv)
                    self.rcv_packet(1, 0x100, dict(from_host))
                    outputs = table.get_port_outputs(dict(from_host))
                    self.assertTrue(
                        any(
                            pkt["eth_dst"] == client_mac
                            for pkt in outputs.get(port, [])
                        ),
                        "advertised client not routed",
                    )

    def test_resolved_client_route_restored(self):
        """Test a packet reaching faucet for a resolved client whose route's
        flows are gone puts them back."""
        table = self.network.tables[self.DP_ID]
        valve = self.valves_manager.valves[self.DP_ID]
        for client, (port, vid, client_mac, client_ips) in self.CLIENTS.items():
            for ipv in (4, 6):
                with self.subTest(client=client, ipv=ipv):
                    from_host = self._from_host(client, ipv)
                    self.rcv_packet(1, 0x100, dict(from_host))
                    self._reply(client, ipv)
                    # The switch loses the route's flows, but faucet's
                    # neighbour entry still holds the client's MAC.
                    route_manager = valve._route_manager_by_ipv[ipv]
                    client_route = ipaddress.ip_network(client_ips[ipv])
                    table.apply_ofmsgs(
                        route_manager._del_route_flows(self._vlan(vid), client_route)
                    )
                    outputs = table.get_port_outputs(dict(from_host))
                    self.assertFalse(
                        any(
                            pkt["eth_dst"] == client_mac
                            for pkt in outputs.get(port, [])
                        ),
                        "client's route not deleted",
                    )
                    self.rcv_packet(1, 0x100, dict(from_host))
                    outputs = table.get_port_outputs(dict(from_host))
                    self.assertTrue(
                        any(
                            pkt["eth_dst"] == client_mac
                            for pkt in outputs.get(port, [])
                        ),
                        "resolved client's route not restored",
                    )


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
