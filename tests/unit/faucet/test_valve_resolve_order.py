#!/usr/bin/env python3

"""Unit tests for the order in which faucet requests next hops."""

# pylint: disable=protected-access

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

import random
import unittest

from os_ken.lib import mac
from os_ken.lib.packet import arp, icmpv6

from faucet import valve_of
from faucet import valve_packet

from clib.valve_test_lib import ValveTestBases, build_pkt


class ValveResolveOrderTestCase(ValveTestBases.ValveTestNetwork):
    """Test next hops with no MAC and refreshes of resolved ones are requested
    in turn, with faucet's default arp_neighbor_timeout and
    max_hosts_per_resolve_cycle.

    The resolvers run on the mock clock as faucet's services run them:
    resolve_gateways every 2s and state_expire every 5s. Packets in go to
    the valve alone, so no other resolver run is hidden between them."""

    CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: 'GenericTFM'
        ignore_learn_ins: 0
        ofchannel_log: '/dev/null'
        table_sizes:
            eth_src: 1024
            eth_dst: 1024
            ipv4_fib: 1024
            ipv6_fib: 1024
            flood: 1024
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
vlans:
    v100:
        vid: 0x100
        faucet_mac: "0e:00:00:00:01:00"
        faucet_vips: ["10.0.0.254/16", "fc00::1:254/112"]
    v200:
        vid: 0x200
        faucet_mac: "0e:00:00:00:02:00"
        faucet_vips: ["10.200.0.254/24", "fc00::200:254/112"]
routers:
    r1:
        vlans: [v100, v200]
"""

    VIPS = {
        (0x100, 4): "10.0.0.254",
        (0x100, 6): "fc00::1:254",
        (0x200, 4): "10.200.0.254",
        (0x200, 6): "fc00::200:254",
    }
    HOSTS = 40
    FIRST_HOST = {4: ip_address("10.0.1.0"), 6: ip_address("fc00::1:1000")}
    LATE_HOST = {4: ip_address("10.0.250.1"), 6: ip_address("fc00::1:2501")}
    LATE_MAC = "00:00:00:0f:00:01"
    # Destinations of routes through FIRST_HOST + i.
    ROUTE_DSTS = {4: "10.%u.0.0/16", 6: "fc00:%x::/64"}
    # Where more refreshes come due than a run requests, which ones it takes
    # is random, so one can wait a while: how long the late host test gives
    # every resolved host to be refreshed, and the longest a host may go
    # unrefreshed while 20 silent addresses take their turns.
    REFRESH_WINDOW = 240
    SILENT_REFRESH_GAP = 300
    CLIENT = {4: "10.200.0.1", 6: "fc00::200:1"}
    CLIENT_MAC = "00:00:00:02:00:01"

    def setUp(self):
        """Setup a routed VLAN of hosts and a client VLAN."""
        self.setup_valves(self.CONFIG)

    def _valve(self):
        """Return the valve."""
        return self.valves_manager.valves[self.DP_ID]

    @staticmethod
    def _requested(ofmsgs):
        """Return the IP addresses ofmsgs send an ARP request or an NS for."""
        requested = []
        for pkt_out in ValveTestBases.packet_outs_from_flows(ofmsgs):
            pkt = valve_packet.parse_packet_in_pkt(bytes(pkt_out.data), None)[0]
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
                requested.append(ip_address(arp_pkt.dst_ip))
            icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
            if icmpv6_pkt and icmpv6_pkt.type_ == icmpv6.ND_NEIGHBOR_SOLICIT:
                requested.append(ip_address(icmpv6_pkt.data.dst))
        return requested

    def _packet_in(self, port, match):
        """Give the valve one packet in, apply what it sends and return it."""
        valve = self._valve()
        pkt = build_pkt(match)
        msg = namedtuple(
            "null_msg",
            ("match", "in_port", "data", "total_len", "cookie", "reason"),
        )(
            {"in_port": port},
            port,
            pkt.data,
            len(pkt.data),
            valve.dp.cookie,
            valve_of.ofp.OFPR_ACTION,
        )
        now = self.mock_time(0)
        ofmsgs = valve.rcv_packet(now, {}, valve.parse_pkt_meta(msg)).get(valve, [])
        self.apply_ofmsgs(ofmsgs)
        return ofmsgs

    def _ask_vip(self, port, vid, host_ip, eth_src):
        """Have a host request a VIP, by ARP or by ND."""
        vip = ip_address(self.VIPS[(vid, host_ip.version)])
        match = {"eth_src": eth_src, "vid": vid}
        if host_ip.version == 4:
            match.update(
                {
                    "eth_dst": mac.BROADCAST_STR,
                    "arp_code": arp.ARP_REQUEST,
                    "arp_source_ip": str(host_ip),
                    "arp_target_ip": str(vip),
                }
            )
        else:
            match.update(
                {
                    "eth_dst": valve_packet.ipv6_link_eth_mcast(vip),
                    "ipv6_src": str(host_ip),
                    "ipv6_dst": str(valve_packet.ipv6_solicited_node_from_ucast(vip)),
                    "neighbor_solicit_ip": str(vip),
                }
            )
        return self._packet_in(port, match)

    def _reply(self, port, vid, host_ip, eth_src):
        """Have a host answer faucet's request, by ARP or by ND."""
        vlan = self._valve().dp.vlans[vid]
        vip = self.VIPS[(vid, host_ip.version)]
        match = {"eth_src": eth_src, "eth_dst": vlan.faucet_mac, "vid": vid}
        if host_ip.version == 4:
            match.update(
                {
                    "arp_code": arp.ARP_REPLY,
                    "arp_source_ip": str(host_ip),
                    "arp_target_ip": vip,
                }
            )
        else:
            match.update(
                {
                    "ipv6_src": str(host_ip),
                    "ipv6_dst": vip,
                    "neighbor_advert_ip": str(host_ip),
                }
            )
        return self._packet_in(port, match)

    def _tick(self):
        """Advance the clock 1s and run the resolvers due then. Return the
        IP addresses they request."""
        valve = self._valve()
        now = self.mock_time(1)
        ofmsgs = []
        if now % 2 == 0:
            ofmsgs.extend(valve.resolve_gateways(now, None).get(valve, []))
        if now % 5 == 0:
            ofmsgs.extend(valve.state_expire(now, None).get(valve, []))
        self.apply_ofmsgs(ofmsgs)
        return self._requested(ofmsgs)

    @staticmethod
    def _host_mac(i):
        return "00:00:00:01:%02x:%02x" % ((i >> 8) & 0xFF, i & 0xFF)

    def _hosts(self, ipv, count):
        return {self.FIRST_HOST[ipv] + i: self._host_mac(i) for i in range(count)}

    def _learn_spread(self, hosts):
        """Learn hosts one after another over one neighbour timeout, so their
        refreshes come due spread out, and run the resolvers for one more,
        answering every request meanwhile."""
        timeout = self._valve().dp.arp_neighbor_timeout
        pending = sorted(hosts)
        for secs in range(2 * timeout + 10):
            while pending and len(pending) * timeout > (timeout - secs) * len(hosts):
                host_ip = pending.pop(0)
                self._ask_vip(1, 0x100, host_ip, hosts[host_ip])
            for host_ip in self._tick():
                if host_ip in hosts:
                    self._reply(1, 0x100, host_ip, hosts[host_ip])

    def _send_to(self, ipv, ip_dst):
        """Have a client on the other VLAN send to an address."""
        match = {
            "eth_src": self.CLIENT_MAC,
            "eth_dst": "0e:00:00:00:02:00",
            "vid": 0x200,
            "echo_request_data": bytes(16),
        }
        if ipv == 4:
            match.update({"ipv4_src": self.CLIENT[ipv], "ipv4_dst": str(ip_dst)})
        else:
            match.update({"ipv6_src": self.CLIENT[ipv], "ipv6_dst": str(ip_dst)})
        return self._requested(self._packet_in(2, match))

    def _routed(self, ipv, host_ip):
        """Return True if faucet has a MAC and a host route for host_ip."""
        vlan = self._valve().dp.vlans[0x100]
        entry = vlan.neigh_cache_by_ipv(ipv).get(host_ip)
        return (
            entry is not None
            and entry.eth_src is not None
            and ip_network(host_ip) in vlan.routes_by_ipv(ipv)
        )

    def _test_late_host(self, ipv, hosts):
        """Test a host that misses faucet's first request, on a VLAN whose
        refreshes due each run exceed max_hosts_per_resolve_cycle, is
        requested again within a few runs and routed when it answers. Also
        test every resolved host stays routed and is refreshed meanwhile."""
        late = self.LATE_HOST[ipv]
        hosts = self._hosts(ipv, hosts)
        self._learn_spread(hosts)
        # The late host misses this one.
        self.assertIn(late, self._send_to(ipv, late))
        asked_at = []
        refreshed = set()
        for secs in range(1, self.REFRESH_WINDOW + 1):
            for host_ip in self._tick():
                if host_ip == late:
                    asked_at.append(secs)
                    self._reply(1, 0x100, late, self.LATE_MAC)
                elif host_ip in hosts:
                    refreshed.add(host_ip)
                    self._reply(1, 0x100, host_ip, hosts[host_ip])
        self.assertTrue(asked_at, msg="late host never requested again")
        self.assertLessEqual(asked_at[0], 10)
        self.assertTrue(self._routed(ipv, late))
        self.assertEqual(set(hosts), refreshed)
        for host_ip in hosts:
            self.assertTrue(self._routed(ipv, host_ip), msg=host_ip)

    def _test_silent_hosts(self, ipv):
        """Test addresses nobody answers, more of them than one run requests,
        are requested until dead, while refreshes of resolved hosts, fewer
        than a run requests, go on, and every one of those is refreshed once
        they are dead."""
        valve = self._valve()
        hosts = self._hosts(ipv, self.HOSTS // 2)
        self._learn_spread(hosts)
        silent = [self.LATE_HOST[ipv] + i for i in range(20)]
        requests = {}
        for host_ip in silent:
            requests[host_ip] = self._send_to(ipv, host_ip).count(host_ip)
        retries = valve.dp.max_host_fib_retry_count
        backoff = valve.dp.max_resolve_backoff_time
        refreshed_at = dict.fromkeys(hosts, 0)
        longest_gap = 0
        refreshed_after = set()
        dead_by = retries * backoff
        for secs in range(1, dead_by + 61):
            for host_ip in self._tick():
                if host_ip in requests:
                    requests[host_ip] += 1
                elif host_ip in hosts:
                    longest_gap = max(longest_gap, secs - refreshed_at[host_ip])
                    refreshed_at[host_ip] = secs
                    if secs > dead_by:
                        refreshed_after.add(host_ip)
                    self._reply(1, 0x100, host_ip, hosts[host_ip])
        for host_ip in silent:
            self.assertGreaterEqual(requests[host_ip], retries, msg=host_ip)
        self.assertLessEqual(longest_gap, self.SILENT_REFRESH_GAP)
        self.assertEqual(set(hosts), refreshed_after)
        for host_ip in hosts:
            self.assertTrue(self._routed(ipv, host_ip), msg=host_ip)

    def _test_address_stream(self, ipv, secs):
        """Test a steady stream of new addresses nobody answers, more than a
        run requests, does not hold off the refreshes of resolved hosts, fewer
        than a run requests."""
        hosts = self._hosts(ipv, self.HOSTS // 4)
        self._learn_spread(hosts)
        refreshed_at = dict.fromkeys(hosts, 0)
        gaps = []
        for sec in range(1, secs + 1):
            self._send_to(ipv, self.LATE_HOST[ipv] + sec)
            for host_ip in self._tick():
                if host_ip in hosts:
                    gaps.append(sec - refreshed_at[host_ip])
                    refreshed_at[host_ip] = sec
                    self._reply(1, 0x100, host_ip, hosts[host_ip])
        gaps.extend(secs - sec for sec in refreshed_at.values())
        self.assertLessEqual(max(gaps), 2 * self._valve().dp.arp_neighbor_timeout)
        for host_ip in hosts:
            self.assertTrue(self._routed(ipv, host_ip), msg=host_ip)

    def _order(self, keys):
        """Cache a next hop due for each (resolved, retries) in keys, in
        random order, and return the (resolved, retries) of each in the order
        the resolvers take them."""
        valve = self._valve()
        vlan = valve.dp.vlans[0x100]
        route_manager = valve._route_manager_by_ipv[4]
        cache = vlan.neigh_cache_by_ipv(4)
        cache.clear()
        now = self.mock_time(0)
        # Every one is due: older than the neighbour timeout, and either
        # never retried or last retried a while ago.
        cache_time = now - route_manager.neighbor_timeout - 1
        keys = list(keys)
        random.shuffle(keys)
        ip_gws = [self.FIRST_HOST[4] + i for i in range(len(keys))]
        for i, (resolved, retries) in enumerate(keys):
            entry = route_manager._update_nexthop_cache(
                cache_time,
                vlan,
                self._host_mac(i) if resolved else None,
                valve.dp.ports[1],
                ip_gws[i],
            )
            entry.resolve_retries = retries
            if retries or not resolved:
                entry.next_retry_time = now - 1
        order = route_manager._vlan_unresolved_nexthops(vlan, ip_gws, now)
        self.assertEqual(sorted(ip_gws), sorted(order))
        return [
            (cache[ip_gw].eth_src is not None, cache[ip_gw].resolve_retries)
            for ip_gw in order
        ]

    def test_order(self):
        """Test next hops with no MAC and refreshes of resolved ones are taken
        in turn, starting with one with no MAC, each never tried/oldest
        first, and the rest of either once the other runs out."""
        no_mac = [(False, retries) for retries in (0, 0, 1, 3)]
        refreshes = [(True, retries) for retries in (0, 2)]
        self.assertEqual(
            [(False, 0), (True, 0), (False, 0), (True, 2), (False, 1), (False, 3)],
            self._order(no_mac + refreshes),
        )
        no_mac = [(False, 1)]
        refreshes = [(True, retries) for retries in (0, 0, 1, 4)]
        self.assertEqual(
            [(False, 1), (True, 0), (True, 0), (True, 1), (True, 4)],
            self._order(no_mac + refreshes),
        )

    def _test_route_gateway_order(self, ipv):
        """Test the route gateway resolver too requests a gateway with no MAC
        that missed a request, when more resolved ones are due a refresh than
        a run requests."""
        valve = self._valve()
        vlan = valve.dp.vlans[0x100]
        route_manager = valve._route_manager_by_ipv[ipv]
        cycle = valve.dp.max_hosts_per_resolve_cycle
        ip_gws = [self.FIRST_HOST[ipv] + i for i in range(2 * cycle + 1)]
        for i, ip_gw in enumerate(ip_gws):
            ip_dst = ip_network(self.ROUTE_DSTS[ipv] % (100 + i))
            self.apply_ofmsgs(valve.add_route(vlan, ip_gw, ip_dst))
        now = self.mock_time(0)
        cache_time = now - route_manager.neighbor_timeout - 1
        late = ip_gws.pop()
        for i, ip_gw in enumerate(ip_gws):
            route_manager._update_nexthop_cache(
                cache_time, vlan, self._host_mac(i), valve.dp.ports[1], ip_gw
            )
        entry = route_manager._update_nexthop_cache(cache_time, vlan, None, None, late)
        entry.resolve_retries = 1
        entry.next_retry_time = now - 1
        requested = self._requested(route_manager.resolve_gateways(vlan, now))
        self.assertEqual(cycle, len(requested))
        self.assertIn(late, requested)

    def test_route_gateway_order_ipv4(self):
        """Test an IPv4 route gateway with no MAC is requested among refreshes."""
        self._test_route_gateway_order(4)

    def test_route_gateway_order_ipv6(self):
        """Test an IPv6 route gateway with no MAC is requested among refreshes."""
        self._test_route_gateway_order(6)

    def test_late_host_ipv4(self):
        """Test an IPv4 host that misses its first request among 40 resolved."""
        self._test_late_host(4, self.HOSTS)

    def test_late_host_ipv6(self):
        """Test an IPv6 host that misses its first request among 40 resolved."""
        self._test_late_host(6, self.HOSTS)

    def test_late_host_few_ipv4(self):
        """Test an IPv4 host that misses its first request among a few."""
        self._test_late_host(4, 3)

    def test_silent_hosts_ipv4(self):
        """Test 20 silent IPv4 addresses do not stop refreshes for long."""
        self._test_silent_hosts(4)

    def test_silent_hosts_ipv6(self):
        """Test 20 silent IPv6 addresses do not stop refreshes for long."""
        self._test_silent_hosts(6)

    def test_address_stream_ipv4(self):
        """Test a new silent IPv4 address every second for 2 minutes does not
        hold off refreshes."""
        self._test_address_stream(4, 120)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
