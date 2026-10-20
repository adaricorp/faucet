"""Valve IPv4/IPv6 routing implementation."""

# pylint: disable=too-many-lines

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import defaultdict, deque
from itertools import zip_longest
import random
import time

import ipaddress

from os_ken.lib.packet import arp, icmp, icmpv6, ipv4, ipv6
import pytricia

from faucet import valve_of
from faucet import valve_packet
from faucet.valve_manager_base import ValveManagerBase


class AnonVLAN:
    """The anonymous VLAN for global routing"""

    def __init__(self, vid):
        self.vid = vid


class NextHop:
    """Describes a directly connected (at layer 2) nexthop."""

    __slots__ = [
        "cache_time",
        "eth_src",
        "last_retry_time",
        "next_retry_time",
        "resolve_retries",
        "port",
    ]

    def __init__(self, eth_src, port, now):
        self.eth_src = eth_src
        self.port = port
        self.cache_time = now
        self.resolve_retries = 0
        self.last_retry_time = None
        self.next_retry_time = None
        if not self.eth_src:
            self.next_retry_time = now

    def age(self, now):
        """Return age of this nexthop."""
        return now - self.cache_time

    def dead(self, max_fib_retries):
        """Return True if this nexthop is considered dead."""
        return self.resolve_retries >= max_fib_retries

    def next_retry(self, now, max_resolve_backoff_time):
        """Increment state for next retry."""
        self.resolve_retries += 1
        self.last_retry_time = now
        self.next_retry_time = now + min(
            (2**self.resolve_retries + random.randint(0, self.resolve_retries)),
            max_resolve_backoff_time,
        )

    def resolution_due(self, now, max_age):
        """Return True if this nexthop is due to be re resolved/retried."""
        if self.eth_src is not None and self.age(now) < max_age:
            return False
        if self.next_retry_time is None or self.next_retry_time < now:
            return True
        return False

    def __str__(self):
        return "%s %s" % (self.eth_src, self.port)

    def __repr__(self):
        return self.__str__()


class ExtraIPState:  # pylint: disable=too-few-public-methods
    """Whether the switch answers ARP for one of a VLAN's faucet_extra_ips.

    FAUCET probes for the address before the switch answers for it, as RFC
    5227 has a host probe for an address before it uses it, and claims it if
    no other host answers. It holds back from one another host uses, and
    probes for it again later. It never gives up an address it has claimed.
    """

    __slots__ = [
        "backoff",
        "change_time",
        "next_time",
        "probes",
        "state",
    ]

    PROBING = 0
    CLAIMED = 1
    HELD = 2
    NAMES = ("probing", "claimed", "held")

    def __init__(self, now):
        self.state = self.PROBING
        # When the state last changed, or the address was listed.
        self.change_time = now
        # The probes sent in the round in progress.
        self.probes = 0
        # When the next probe is due, or the address is claimed.
        self.next_time = None
        # The seconds held back from the address, while held.
        self.backoff = 0


class ValveRouteManager(ValveManagerBase):
    """Base class to implement RIB/FIB."""

    __slots__ = [
        "active",
        "arp_responder",
        "neighbor_timeout",
        "dec_ttl",
        "fib_table",
        "pipeline",
        "multi_out",
        "notify",
        "global_vlan",
        "global_routing",
        "host_fib_sent",
        "logger",
        "max_host_fib_retry_count",
        "max_hosts_per_resolve_cycle",
        "max_resolve_backoff_time",
        "proactive_learn",
        "route_priority",
        "routers",
        "routers_by_vid",
        "vip_maps_by_vid",
        "vip_table",
        "switch_manager",
        "inc_var",
        "set_var",
        "remove_var",
        "prom_labels",
        "extra_ip_log_times",
    ]

    IPV = 0
    ETH_TYPE = None
    ICMP_TYPE = None
    ICMP_SIZE = None
    MAX_PACKET_IN_SIZE = valve_of.MAX_PACKET_IN_BYTES
    CONTROL_ETH_TYPES = ()  # type: ignore
    IP_PKT = None
    # Seconds for which a packet in does not send a host's FIB flows again.
    HOST_FIB_GUARD_TIME = 5

    def __init__(
        self,
        logger,
        notify,
        global_vlan,
        neighbor_timeout,
        max_hosts_per_resolve_cycle,
        max_host_fib_retry_count,
        max_resolve_backoff_time,
        proactive_learn,
        dec_ttl,
        multi_out,
        fib_table,
        vip_table,
        pipeline,
        routers,
        stack_manager,
        arp_responder=False,
        inc_var=None,
        set_var=None,
        remove_var=None,
        prom_labels=None,
    ):
        self.notify = notify
        self.inc_var = inc_var
        self.set_var = set_var
        self.remove_var = remove_var
        self.prom_labels = prom_labels
        self.extra_ip_log_times = {}
        self.logger = logger
        self.global_vlan = AnonVLAN(global_vlan)
        self.neighbor_timeout = neighbor_timeout
        self.max_hosts_per_resolve_cycle = max_hosts_per_resolve_cycle
        self.max_host_fib_retry_count = max_host_fib_retry_count
        self.max_resolve_backoff_time = max_resolve_backoff_time
        self.proactive_learn = proactive_learn
        self.arp_responder = arp_responder
        self.dec_ttl = dec_ttl
        self.multi_out = multi_out
        self.fib_table = fib_table
        self.vip_table = vip_table
        self.pipeline = pipeline
        self.route_priority = self._LPM_PRIORITY
        self.routers = routers
        self.routers_by_vid = self._routers_by_vid()
        self.vip_maps_by_vid = self._vip_maps_by_vid()
        self.host_fib_sent = {}
        self.active = False
        self.global_routing = self._global_routing()
        self.stack_manager = stack_manager
        if self.global_routing:
            self.logger.info("global routing enabled")

    def notify_learn(self, pkt_meta):
        self.notify(
            {
                "L3_LEARN": {
                    "eth_src": pkt_meta.eth_src,
                    "l3_src_ip": str(pkt_meta.l3_src),
                    "port_no": pkt_meta.port.number,
                    "vid": pkt_meta.vlan.vid,
                }
            }
        )

    def nexthop_dead(self, nexthop_cache_entry):
        """Returns true if the nexthop_cache_entry is considered dead"""
        return nexthop_cache_entry.dead(self.max_host_fib_retry_count)

    @staticmethod
    def _unicast_to_vip(pkt_meta):
        """Return true if packet is from a src in the connected network and dst ip is
        a faucet vip. I.e: Packet is traffic bound for a VIP"""
        return (
            pkt_meta.eth_dst == pkt_meta.vlan.faucet_mac
            and pkt_meta.vlan.from_connected_to_vip(pkt_meta.l3_src, pkt_meta.l3_dst)
        )

    @staticmethod
    def _gw_resolve_pkt():
        return None

    @staticmethod
    def _gw_respond_pkt():
        return None

    def _flood_stack_links(self, pkt_builder, vlan, multi_out, *args):
        """Return flood packet-out actions to stack ports for gw resolving"""
        ofmsgs = []
        if self.stack_manager:
            ports = []
            if self.stack_manager.stack.is_root():
                ports = list(
                    self.stack_manager.away_ports
                    - self.stack_manager.inactive_away_ports
                    - self.stack_manager.pruned_away_ports
                )
            else:
                if self.stack_manager.chosen_towards_port is not None:
                    ports = [self.stack_manager.chosen_towards_port]
            if ports:
                running_port_nos = [port.number for port in ports if port.running()]
                pkt = pkt_builder(vlan.vid, *args)
                if running_port_nos:
                    random.shuffle(running_port_nos)
                    if multi_out:
                        ofmsgs.append(
                            valve_of.packetouts(running_port_nos, bytes(pkt.data))
                        )
                    else:
                        ofmsgs.extend(
                            [
                                valve_of.packetout(port_no, bytes(pkt.data))
                                for port_no in running_port_nos
                            ]
                        )
        return ofmsgs

    def _resolve_gw_on_vlan(self, vlan, faucet_vip, ip_gw):
        """Return flood packet-out actions for gw resolving"""
        ofmsgs = []
        if vlan.is_extra_ip(ip_gw):
            # FAUCET's own address, which it never resolves.
            return ofmsgs
        stack_ofmsgs = self._flood_stack_links(
            self._gw_resolve_pkt(),
            vlan,
            self.multi_out,
            vlan.faucet_mac,
            valve_of.mac.BROADCAST_STR,
            faucet_vip.ip,
            ip_gw,
        )
        if stack_ofmsgs:
            ofmsgs.extend(stack_ofmsgs)
        vlan_ofmsgs = vlan.flood_pkt(
            self._gw_resolve_pkt(),
            self.multi_out,
            vlan.faucet_mac,
            valve_of.mac.BROADCAST_STR,
            faucet_vip.ip,
            ip_gw,
        )
        if vlan_ofmsgs:
            ofmsgs.extend(vlan_ofmsgs)
        return ofmsgs

    def _resolve_gw_on_port(self, vlan, port, faucet_vip, ip_gw, eth_dst):
        """Return packet-out actions for outputting to a specific port"""
        return vlan.pkt_out_port(
            self._gw_resolve_pkt(), port, vlan.faucet_mac, eth_dst, faucet_vip.ip, ip_gw
        )

    def _controller_and_flood(self):
        """Return instructions to forward packet to l2-forwarding"""
        return self.pipeline.accept_to_l2_forwarding(
            actions=(valve_of.output_controller(max_len=self.MAX_PACKET_IN_SIZE),)
        )

    def _resolve_vip_response(self, pkt_meta, solicited_ip, now):
        """Learn host requesting for router, and return packet-out ofmsgs router response"""
        ofmsgs = []
        vlan = pkt_meta.vlan
        if pkt_meta.vlan.is_faucet_vip(solicited_ip) and pkt_meta.vlan.ip_in_vip_subnet(
            pkt_meta.l3_src
        ):
            src_ip = pkt_meta.l3_src
            eth_src = pkt_meta.eth_src
            port = pkt_meta.port
            if self._stateful_gw(vlan, src_ip):
                ofmsgs.extend(self._add_host_fib_route(vlan, src_ip, blackhole=False))
                ofmsgs.extend(self._update_nexthop(now, vlan, port, eth_src, src_ip))
                if ofmsgs:
                    self.logger.info(
                        "Resolve response to %s from %s"
                        % (solicited_ip, pkt_meta.log())
                    )
            ofmsgs.append(
                vlan.pkt_out_port(
                    self._gw_respond_pkt(),
                    port,
                    vlan.faucet_mac,
                    eth_src,
                    solicited_ip,
                    src_ip,
                )
            )
        return ofmsgs

    def _gw_advert(self, pkt_meta, target_ip, now):
        """Receive an advert, so update nexthop information"""
        ofmsgs = []
        vlan = pkt_meta.vlan
        if vlan.ip_in_vip_subnet(target_ip):
            if self._stateful_gw(vlan, target_ip):
                ofmsgs.extend(
                    self._update_nexthop(
                        now, vlan, pkt_meta.port, pkt_meta.eth_src, target_ip
                    )
                )
                if ofmsgs:
                    self.logger.info(
                        "Received advert for %s from %s" % (target_ip, pkt_meta.log())
                    )
        return ofmsgs

    def _vlan_routes(self, vlan):
        """Return vlan routes"""
        return vlan.routes_by_ipv(self.IPV)

    def _vlan_nexthop_cache(self, vlan):
        """Return vlan neighbour cache"""
        return vlan.neigh_cache_by_ipv(self.IPV)

    def _expire_nexthops(self, now, vlan, dead_nexthops):
        """Expire list of next hops for a vlan"""
        ofmsgs = []
        for ip_gw, nexthop_cache_entry in dead_nexthops:
            self.logger.info(
                "marking %s as a dead nexthop" % nexthop_cache_entry.eth_src
            )
            ofmsgs.extend(
                self._expire_gateway_flows(ip_gw, nexthop_cache_entry, vlan, now)
            )
        return ofmsgs

    def expire_vlan_nexthops(self, vlan):
        """Expire all hosts on a vlan"""
        now = time.time()
        nexthop_cache = self._vlan_nexthop_cache(vlan)
        dead_nexthops = [
            (ip_gw, nexthop_cache_entry)
            for ip_gw, nexthop_cache_entry in nexthop_cache.items()
            if nexthop_cache_entry
        ]
        return self._expire_nexthops(now, vlan, dead_nexthops)

    def expire_port_nexthops(self, port, vids=None):
        """Expire all hosts on a port (only on VLANs in vids, if specified)"""
        ofmsgs = []
        now = time.time()
        for vlan in port.vlans():
            if vids is not None and vlan.vid not in vids:
                continue
            nexthop_cache = self._vlan_nexthop_cache(vlan)
            dead_nexthops = [
                (ip_gw, nexthop_cache_entry)
                for ip_gw, nexthop_cache_entry in nexthop_cache.items()
                if nexthop_cache_entry
                and nexthop_cache_entry.port
                and port.number == nexthop_cache_entry.port.number
            ]
            ofmsgs.extend(self._expire_nexthops(now, vlan, dead_nexthops))
        return ofmsgs

    def add_port(self, port):
        """Restart the requests for next hops expired with a port, now it is up.

        Those sent while the port was down could not reach them through it.
        An outage longer than the requests take would drop a host, and would
        leave a gateway a route uses requested only every
        max_resolve_backoff_time. A next hop heard from since, on another
        port, is left as it is.
        """
        for vlan in port.vlans():
            nexthop_cache = self._vlan_nexthop_cache(vlan)
            for ip_gw in vlan.pop_port_expired_gws(port, self.IPV):
                if self._cached_nexthop_eth_dst(vlan, ip_gw) is not None:
                    continue
                nexthop_cache.pop(ip_gw, None)
                vlan.add_route_gw(ip_gw)
        return []

    def _vlan_nexthop_cache_entry(self, vlan, ip_gw):
        """Return nexthop cache entry"""
        nexthop_cache = self._vlan_nexthop_cache(vlan)
        return nexthop_cache.get(ip_gw, None)

    def _del_vlan_nexthop_cache_entry(self, vlan, ip_gw):
        nexthop_cache = self._vlan_nexthop_cache(vlan)
        del nexthop_cache[ip_gw]

    def _host_fib_sent_recently(self, now, vlan, host_ip, eth_dst):
        """Return True if a host's FIB flows went to the switch too recently
        for a packet in to send them again.

        Args:
            now (float): seconds since epoch.
            vlan (vlan): VLAN of the host.
            host_ip (ipaddress.ip_address): IP address of host.
            eth_dst (str): MAC address the flows route to, None for a blackhole.
        Returns:
            bool: True if the same flows were sent within the guard time and
                not deleted since.
        """
        sent = self.host_fib_sent.get(vlan.vid, {}).get(host_ip, None)
        if sent is None:
            return False
        sent_time, sent_eth_dst = sent
        guard_time = self.HOST_FIB_GUARD_TIME
        if sent_eth_dst is None:
            # Not if the blackhole could have timed out since.
            guard_time = min(
                guard_time,
                self.max_resolve_backoff_time * self.max_host_fib_retry_count,
            )
        return sent_eth_dst == eth_dst and 0 <= now - sent_time < guard_time

    def _set_host_fib_sent(self, now, vlan, host_ip, eth_dst):
        """Note that a host's FIB flows went to the switch."""
        self.host_fib_sent.setdefault(vlan.vid, {})[host_ip] = (now, eth_dst)

    def _nexthop_actions(self, eth_dst, vlan):
        """Return flowrule actions for fib entry"""
        actions = []
        if self.dec_ttl:
            actions.append(valve_of.dec_ip_ttl())
        if self.routers:
            actions.append(self.fib_table.set_vlan_vid(vlan.vid))
        actions.extend(
            [
                self.fib_table.set_field(eth_src=vlan.faucet_mac),
                self.fib_table.set_field(eth_dst=eth_dst),
            ]
        )
        return tuple(actions)

    def _route_match(self, vlan, ip_dst):
        """Return vid, dst, eth_type flowrule match for fib entry"""
        return self.fib_table.match(vlan=vlan, eth_type=self.ETH_TYPE, nw_dst=ip_dst)

    def _route_priority(self, ip_dst):
        """Return ip dst priority"""
        prefixlen = ipaddress.ip_network(ip_dst).prefixlen
        return self.route_priority + prefixlen

    def _routers_by_vid(self):
        """Return each VID's (VLAN, router) pairs, in configuration order."""
        # Asking every router whether it names a VLAN, for every VLAN, is
        # quadratic and every miss compares two Conf objects. Keep the VLAN
        # each router named, not just the VID: after a reload merge_dyn can
        # leave a port pointing at the previous config's object for that VID.
        routers_by_vid = {}
        if self.routers:
            for router in self.routers.values():
                for router_vlan in router.vlans:
                    routers_by_vid.setdefault(router_vlan.vid, []).append(
                        (router_vlan, router)
                    )
        return routers_by_vid

    def _vip_maps_by_vid(self):
        """Return each VID's map from every VIP subnet its routers route to."""
        # A VLAN in several routers is routed to the VIP subnets of all of
        # them (_routed_vlans()), so resolving a destination must look in
        # all of them too, not only the first. One map per VID, built once:
        # the most specific subnet wins, as in the FIB, and on the same
        # subnet the first router, as before.
        vip_maps_by_vid = {}
        for vid, vlan_routers in self.routers_by_vid.items():
            vip_map = pytricia.PyTricia(  # pylint: disable=c-extension-no-member
                32 if self.IPV == 4 else 128
            )
            for _router_vlan, router in vlan_routers:
                router_vip_map = router.vip_map_by_ipv.get(self.IPV, {})
                for network in router_vip_map:
                    if not vip_map.has_key(network):
                        vip_map[network] = router_vip_map[network]
            vip_maps_by_vid[vid] = vip_map
        return vip_maps_by_vid

    def _routers_for_vlan(self, vlan):
        """Return the routers that name this VLAN, in configuration order."""
        # A generator, so _router_for_vlan() stops at the first one.
        return (
            router
            for router_vlan, router in self.routers_by_vid.get(vlan.vid, ())
            if router_vlan is vlan or router_vlan == vlan
        )

    def _router_for_vlan(self, vlan):
        """Return vlan router if any"""
        for router in self._routers_for_vlan(vlan):
            return router
        return None

    def _routed_vlans(self, vlan):
        """Return vlans that have routers"""
        if self.global_routing:
            return set([self.global_vlan])
        vlans = set([vlan])
        for router in self._routers_for_vlan(vlan):
            # union(), as before: only the search changes, not the set.
            vlans = vlans.union(router.vlans)
        return vlans

    @staticmethod
    def _stateful_gw(vlan, dst_ip):
        return not dst_ip.is_link_local or vlan.ip_dsts_for_ip_gw(dst_ip)

    def _global_routing(self):
        """Return true if global routing is enabled"""
        return self.global_vlan.vid and self.routers and len(self.routers) == 1

    def _add_faucet_fib_to_vip(self, vlan, priority, faucet_vip, faucet_vip_host):
        """Router flowmods"""
        ofmsgs = []
        learn_connected_priority = self.route_priority + faucet_vip.network.prefixlen
        faucet_mac = vlan.faucet_mac
        actions = None
        if self.global_routing:
            vlan_mac = valve_packet.int_in_mac(faucet_mac, vlan.vid)
            actions = [
                self.fib_table.set_field(eth_dst=vlan_mac),
                self.fib_table.set_vlan_vid(self.global_vlan.vid),
            ]
        ofmsgs.extend(
            self.pipeline.select_packets(
                self.fib_table,
                {"eth_type": self.ETH_TYPE, "eth_dst": faucet_mac, "vlan": vlan},
                actions,
            )
        )
        if self.global_routing:
            vlan = self.global_vlan
        ofmsgs.append(
            self.fib_table.flowmod(
                self._route_match(vlan, faucet_vip_host),
                priority=priority,
                inst=(self.fib_table.goto(self.vip_table),),
            )
        )
        if self.proactive_learn and not faucet_vip.ip.is_link_local:
            routed_vlans = self._routed_vlans(vlan)
            for routed_vlan in routed_vlans:
                ofmsgs.append(
                    self.fib_table.flowmod(
                        self._route_match(routed_vlan, faucet_vip),
                        priority=learn_connected_priority,
                        inst=(self.fib_table.goto(self.vip_table),),
                    )
                )
            # Unicast ICMP to us.
            priority -= 1
            ofmsgs.append(
                self.vip_table.flowcontroller(
                    self.vip_table.match(
                        eth_type=self.ETH_TYPE,
                        eth_dst=faucet_mac,
                        nw_proto=self.ICMP_TYPE,
                    ),
                    priority=priority,
                    max_len=self.ICMP_SIZE,
                )
            )
            # Learn + flood other ICMP not unicast to us.
            priority -= 1
            ofmsgs.append(
                self.vip_table.flowmod(
                    self.vip_table.match(
                        eth_type=self.ETH_TYPE, nw_proto=self.ICMP_TYPE
                    ),
                    priority=priority,
                    inst=self._controller_and_flood(),
                )
            )
            # Learn from other IP traffic unicast to us.
            priority -= 1
            ofmsgs.append(
                self.vip_table.flowcontroller(
                    self.vip_table.match(eth_type=self.ETH_TYPE, eth_dst=faucet_mac),
                    priority=priority,
                    max_len=self.MAX_PACKET_IN_SIZE,
                )
            )
            # Learn + flood IP traffic not unicast to us.
            priority -= 1
            ofmsgs.append(
                self.vip_table.flowmod(
                    self.vip_table.match(eth_type=self.ETH_TYPE),
                    priority=priority,
                    inst=self._controller_and_flood(),
                )
            )
        return ofmsgs

    def _add_faucet_vip_nd(self, vlan, priority, faucet_vip, faucet_vip_host):
        raise NotImplementedError  # pragma: no cover

    def add_extra_ips(self, _vlan, _extra_ips):
        """Return the flows for some of a VLAN's faucet_extra_ips: none but
        IPv4's."""
        return []

    def del_extra_ips(self, _vlan, _extra_ips):
        """Return deletes of the flows for some of a VLAN's faucet_extra_ips:
        none but IPv4's."""
        return []

    def extra_ips_due(self, _vlan, _now, _live=True):
        """Return the ARP due for a VLAN's faucet_extra_ips: none but IPv4's."""
        return []

    def del_extra_ip_metrics(self, _vlan, _extra_ips):
        """Remove the metrics of some of a VLAN's faucet_extra_ips: IPv4's."""

    def keep_extra_ip_states(self, _vlan, _new_vlan):
        """Keep the state of a VLAN's faucet_extra_ips in a new config: IPv4's."""

    def add_vlan(self, vlan, cold_start):
        """Add a VLAN."""
        ofmsgs = []
        if cold_start:
            # The switch has none of the FIB flows of the VLAN's hosts.
            self.host_fib_sent.pop(vlan.vid, None)
        # add controller IPs if configured.
        for faucet_vip in vlan.faucet_vips_by_ipv(self.IPV):
            max_prefixlen = faucet_vip.ip.max_prefixlen
            faucet_vip_host = self._host_from_faucet_vip(faucet_vip)
            priority = self.route_priority + max_prefixlen
            ofmsgs.extend(
                self._add_faucet_vip_nd(vlan, priority, faucet_vip, faucet_vip_host)
            )
            ofmsgs.extend(
                self._add_faucet_fib_to_vip(vlan, priority, faucet_vip, faucet_vip_host)
            )
        routed_vlans = self._routed_vlans(vlan)
        if not cold_start and not self.global_routing:
            for routed_vlan in routed_vlans:
                if routed_vlan == vlan or isinstance(routed_vlan, AnonVLAN):
                    continue
                for faucet_vip in routed_vlan.faucet_vips_by_ipv(self.IPV):
                    if self.proactive_learn and not faucet_vip.ip.is_link_local:
                        # When warm starting, reinstall FIB routes for FAUCET VIP subnets
                        # of other VLANs in the same router as this VLAN
                        learn_connected_priority = (
                            self.route_priority + faucet_vip.network.prefixlen
                        )
                        ofmsgs.append(
                            self.fib_table.flowmod(
                                self._route_match(vlan, faucet_vip),
                                priority=learn_connected_priority,
                                inst=(self.fib_table.goto(self.vip_table),),
                            )
                        )
        return ofmsgs

    def dp_vlan_refs(self, dp_vlans):
        """Return FAUCET MACs, VIPs and VIP hosts in use by VLANs on the DP."""
        dp_macs = set()
        dp_mac_global_vip_present = {}
        dp_faucet_vips = set()
        dp_faucet_vip_hosts = set()
        for dp_vlan in dp_vlans:
            if dp_vlan.faucet_vips_by_ipv(self.IPV):
                dp_macs.add(dp_vlan.faucet_mac)
                if dp_vlan.faucet_mac not in dp_mac_global_vip_present:
                    dp_mac_global_vip_present[dp_vlan.faucet_mac] = False
                for faucet_vip in dp_vlan.faucet_vips_by_ipv(self.IPV):
                    if not faucet_vip.ip.is_link_local:
                        dp_mac_global_vip_present[dp_vlan.faucet_mac] = True
                        break
            for faucet_vip in dp_vlan.faucet_vips_by_ipv(self.IPV):
                dp_faucet_vips.add(faucet_vip)
                faucet_vip_host = self._host_from_faucet_vip(faucet_vip)
                dp_faucet_vip_hosts.add(faucet_vip_host)
        return (dp_macs, dp_mac_global_vip_present, dp_faucet_vips, dp_faucet_vip_hosts)

    def _del_faucet_mac(self, faucet_mac, dp_macs, dp_mac_global_vip_present):
        """Delete flows associated with a given faucet mac"""
        ofmsgs = []
        max_prefixlen = 32 if self.IPV == 4 else 128

        if faucet_mac not in dp_macs:
            # FAUCET MAC is no longer used by any VLAN on DP
            for eth_type in self.CONTROL_ETH_TYPES:
                ofmsgs.append(
                    self.vip_table.flowdel(
                        match=self.vip_table.match(
                            eth_dst=faucet_mac, eth_type=eth_type
                        )
                    )
                )
        elif not dp_mac_global_vip_present[faucet_mac]:
            # FAUCET MAC remains active on DP, but only used by link-local VIP
            ofmsgs.append(
                self.vip_table.flowdel(
                    match=self.vip_table.match(
                        eth_dst=faucet_mac,
                        eth_type=self.ETH_TYPE,
                        nw_proto=self.ICMP_TYPE,
                    ),
                    priority=self.route_priority + max_prefixlen - 1,
                    strict=True,
                )
            )
            ofmsgs.append(
                self.vip_table.flowdel(
                    match=self.vip_table.match(
                        eth_dst=faucet_mac,
                        eth_type=self.ETH_TYPE,
                    ),
                    priority=self.route_priority + max_prefixlen - 3,
                    strict=True,
                )
            )

        if True not in dp_mac_global_vip_present.values():
            # No global scope VIPs left on DP
            ofmsgs.append(
                self.vip_table.flowdel(
                    match=self.vip_table.match(
                        eth_type=self.ETH_TYPE, nw_proto=self.ICMP_TYPE
                    ),
                    priority=self.route_priority + max_prefixlen - 2,
                    strict=True,
                )
            )
            ofmsgs.append(
                self.vip_table.flowdel(
                    match=self.vip_table.match(eth_type=self.ETH_TYPE),
                    priority=self.route_priority + max_prefixlen - 4,
                    strict=True,
                )
            )
        return ofmsgs

    def _del_faucet_vip(self, vlan, faucet_vip, dp_faucet_vip_hosts, dp_faucet_vips):
        """Delete flows associated with a given faucet vip"""
        ofmsgs = []
        if self.global_routing:
            faucet_vip_host = self._host_from_faucet_vip(faucet_vip)
            if faucet_vip_host not in dp_faucet_vip_hosts:
                # FAUCET VIP host route no longer in use on DP
                ofmsgs.append(
                    self.fib_table.flowdel(
                        match=self._route_match(self.global_vlan, faucet_vip_host)
                    )
                )
            if (
                self.proactive_learn
                and not faucet_vip.ip.is_link_local
                and faucet_vip not in dp_faucet_vips
            ):
                # FAUCET VIP no longer in use on DP
                ofmsgs.append(
                    self.fib_table.flowdel(
                        match=self._route_match(self.global_vlan, faucet_vip)
                    )
                )
            return ofmsgs
        if self.proactive_learn and not faucet_vip.ip.is_link_local:
            routed_vlans = self._routed_vlans(vlan)
            router_faucet_vips = set()
            for routed_vlan in routed_vlans:
                if routed_vlan == vlan or isinstance(routed_vlan, AnonVLAN):
                    continue
                router_faucet_vips.update(routed_vlan.faucet_vips)
            if faucet_vip not in router_faucet_vips:
                for routed_vlan in routed_vlans:
                    # FAUCET VIP no longer in use by any VLANs in router
                    ofmsgs.append(
                        self.fib_table.flowdel(
                            match=self._route_match(routed_vlan, faucet_vip)
                        )
                    )
        return ofmsgs

    def del_vlan(self, vlan, dp_vlan_refs):
        """Delete a VLAN."""
        # A VLAN without a VIP of this IP version still has FIB flows if it
        # is routed with a VLAN that has one.
        ofmsgs = [self.fib_table.flowdel(match=self.fib_table.match(vlan=vlan))]
        if not vlan.faucet_vips_by_ipv(self.IPV):
            return ofmsgs
        dp_macs, dp_mac_global_vip_present, dp_faucet_vips, dp_faucet_vip_hosts = (
            dp_vlan_refs
        )
        ofmsgs.extend(
            self._del_faucet_mac(vlan.faucet_mac, dp_macs, dp_mac_global_vip_present)
        )

        # Expire next hops for this VLAN to remove static routes
        # from FIB of VLANs in same router as this one
        ofmsgs.extend(self.expire_vlan_nexthops(vlan))

        for faucet_vip in vlan.faucet_vips_by_ipv(self.IPV):
            ofmsgs.extend(
                self._del_faucet_vip(
                    vlan, faucet_vip, dp_faucet_vip_hosts, dp_faucet_vips
                )
            )
        return ofmsgs

    def _add_resolved_route(
        self, vlan, ip_gw, ip_dst, eth_dst, is_updated, readd=False
    ):
        """Return flowmods for enabling routing of a resolved nexthop"""
        ofmsgs = []
        if is_updated:
            self.logger.info(
                "Updating next hop for route %s via %s (%s) on VLAN %u"
                % (ip_dst, ip_gw, eth_dst, vlan.vid)
            )
            ofmsgs.extend(self._del_route_flows(vlan, ip_dst))
        elif readd:
            # Every packet that races the route's flows to the switch asks
            # for this, so a burst of them must not flood the log.
            self.logger.debug(
                "Re-adding route %s via %s (%s) on VLAN %u"
                % (ip_dst, ip_gw, eth_dst, vlan.vid)
            )
        else:
            self.logger.info(
                "Adding new route %s via %s (%s) on VLAN %u"
                % (ip_dst, ip_gw, eth_dst, vlan.vid)
            )
        inst = self.pipeline.accept_to_l2_forwarding(
            actions=self._nexthop_actions(eth_dst, vlan)
        )
        routed_vlans = self._routed_vlans(vlan)
        for routed_vlan in routed_vlans:
            in_match = self._route_match(routed_vlan, ip_dst)
            ofmsgs.append(
                self.fib_table.flowmod(
                    in_match, priority=self._route_priority(ip_dst), inst=inst
                )
            )
        return ofmsgs

    def add_routed_vlan_routes(self, vlan):
        """Add routes via nexthops resolved on the other VLANs routed with a VLAN.

        A route is installed on every VLAN routed with its nexthop's VLAN when
        the nexthop resolves, and not again unless the nexthop's MAC changes.
        A VLAN added or changed by a warm start gets them from the nexthop cache.

        Args:
            vlan (vlan): VLAN to add the routes to.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        if self.global_routing:
            # Routes match the global VLAN, which a warm start leaves in place.
            return ofmsgs
        for routed_vlan in self._routed_vlans(vlan):
            if routed_vlan == vlan or isinstance(routed_vlan, AnonVLAN):
                continue
            for ip_gw in self._vlan_nexthop_cache(routed_vlan):
                eth_dst = self._cached_nexthop_eth_dst(routed_vlan, ip_gw)
                if eth_dst is None:
                    continue
                inst = self.pipeline.accept_to_l2_forwarding(
                    actions=self._nexthop_actions(eth_dst, routed_vlan)
                )
                for ip_dst in routed_vlan.ip_dsts_for_ip_gw(ip_gw):
                    ofmsgs.append(
                        self.fib_table.flowmod(
                            self._route_match(vlan, ip_dst),
                            priority=self._route_priority(ip_dst),
                            inst=inst,
                        )
                    )
        return ofmsgs

    @staticmethod
    def routed_peers(routers):
        """Return the VLANs each VLAN routes with.

        Args:
            routers (dict): routers by name.
        Returns:
            dict: {vid: set of the VIDs it shares a router with}, for each VLAN
                that shares a router with another.
        """
        peers = defaultdict(set)
        for router in routers.values():
            vids = {vlan.vid for vlan in router.vlans}
            if len(vids) > 1:
                for vid in vids:
                    peers[vid].update(vids)
        for vid, vids in peers.items():
            vids.discard(vid)
        return dict(peers)

    def _peer_fib_keys(self, peer):
        """Return every destination a VLAN can have installed on its peers' FIB.

        Its connected subnets, as _add_faucet_fib_to_vip() installs them, and
        every destination in its route table, hosts learned on it included,
        whatever state the next hop is in: a flow installed while the next hop
        was resolved, or as a blackhole while it resolves, stays until deleted.

        Args:
            peer (VLAN): VLAN the flows come from.
        Returns:
            dict: {ip_network: nw_dst the flow matches}.
        """
        keys = {}
        if self.proactive_learn:
            for faucet_vip in peer.faucet_vips_by_ipv(self.IPV):
                if not faucet_vip.ip.is_link_local:
                    keys[faucet_vip.network] = faucet_vip
        for ip_dst in self._vlan_routes(peer):
            keys[ip_dst] = ip_dst
        return keys

    def _peer_fib_entries(self, peer, keys=None):
        """Return the FIB entries a VLAN installs on the VLANs it routes with.

        Its connected subnets, as _add_faucet_fib_to_vip() installs them, and
        its routes via resolved next hops, as _add_resolved_route() does. A
        route via a next hop not yet resolved is left out, as a cold start
        installs it only once resolved.

        Args:
            peer (VLAN): VLAN the entries come from.
            keys (set): only return these destinations, if given.
        Returns:
            dict: {ip_network: (nw_dst to match, eth_dst)}, where eth_dst is
                the next hop of a route, or None for a connected subnet.
        """
        entries = {}
        if self.proactive_learn:
            for faucet_vip in peer.faucet_vips_by_ipv(self.IPV):
                if faucet_vip.ip.is_link_local:
                    continue
                if keys is None or faucet_vip.network in keys:
                    entries[faucet_vip.network] = (faucet_vip, None)
        routes = self._vlan_routes(peer)
        if keys is None:
            ip_dsts = list(routes)
        elif len(routes) < len(keys):
            ip_dsts = [ip_dst for ip_dst in routes if ip_dst in keys]
        else:
            ip_dsts = [ip_dst for ip_dst in keys if ip_dst in routes]
        for ip_dst in ip_dsts:
            eth_dst = self._cached_nexthop_eth_dst(peer, routes[ip_dst])
            if eth_dst is not None:
                entries[ip_dst] = (ip_dst, eth_dst)
        return entries

    def _peer_fib_flowmod(self, vlan, peer, nw_dst, eth_dst):
        """Return the flowmod for one entry of _peer_fib_entries() on vlan."""
        if eth_dst is None:
            return self.fib_table.flowmod(
                self._route_match(vlan, nw_dst),
                priority=self.route_priority + nw_dst.network.prefixlen,
                inst=(self.fib_table.goto(self.vip_table),),
            )
        return self.fib_table.flowmod(
            self._route_match(vlan, nw_dst),
            priority=self._route_priority(nw_dst),
            inst=self.pipeline.accept_to_l2_forwarding(
                actions=self._nexthop_actions(eth_dst, peer)
            ),
        )

    def withdraw_lost_peers(self, vlans, new_peers, new_vids):
        """Return deletes for what each VLAN has from the VLANs it stops routing with.

        Called on the running config, before a warm start deletes any port or
        VLAN, which expires the hosts and next hops learned on them. Every
        destination the lost peer can have installed (see _peer_fib_keys())
        gets a delete, in both directions, whether or not the VLAN has a VIP
        of this IP version; replay_gained_peers() sends it unless the VLAN
        still has the destination from elsewhere. The next hop caches are not
        read, so a flow is deleted whatever state its next hop is in; a strict
        delete of a flow not installed does nothing.

        Deleting a VLAN deletes its connected subnets from the VLANs it
        routed with, and not strictly (see _del_faucet_vip()), so every flow
        they have inside those subnets goes too. So when a lost peer is
        deleted, every destination inside its connected subnets that a VLAN
        itself or a VLAN it keeps routing with can install is withdrawn from
        it too, for replay_gained_peers() to look up again.

        Args:
            vlans (dict): the running config's VLANs by VID.
            new_peers (dict): routed_peers() of the new config.
            new_vids (set): the new config's VIDs.
        Returns:
            dict: {vid: {ip_network: flow delete}}.
        """
        withdrawals = defaultdict(dict)
        peer_keys = {}

        def fib_keys(peer_vid):
            if peer_vid not in peer_keys:
                peer_keys[peer_vid] = self._peer_fib_keys(vlans[peer_vid])
            return peer_keys[peer_vid]

        for vid, peers in self.routed_peers(self.routers).items():
            lost_vids = peers - new_peers.get(vid, set())
            for peer_vid in lost_vids:
                for key, nw_dst in fib_keys(peer_vid).items():
                    withdrawals[vid][key] = self._fib_withdrawal(
                        vlans[vid], key, nw_dst
                    )
            if vid not in new_vids:
                continue
            # Not lost_vids - new_vids: subtracting a dict view from a set
            # steps through the whole view, once for every VLAN.
            deleted_subnets = self._connected_subnets(
                vlans[peer_vid] for peer_vid in lost_vids if peer_vid not in new_vids
            )
            if not deleted_subnets:
                continue
            for kept_vid in (peers - lost_vids) | {vid}:
                for key, nw_dst in fib_keys(kept_vid).items():
                    if key not in withdrawals[vid] and self._inside(
                        key, deleted_subnets
                    ):
                        withdrawals[vid][key] = self._fib_withdrawal(
                            vlans[vid], key, nw_dst
                        )
        return withdrawals

    def _fib_withdrawal(self, vlan, key, nw_dst):
        """Return the strict delete of the FIB flow for a _peer_fib_keys() key."""
        return self.fib_table.flowdel(
            self._route_match(vlan, nw_dst),
            priority=self.route_priority + key.prefixlen,
            strict=True,
        )

    def _connected_subnets(self, vlans):
        """Return the connected subnets that VLANs install on the VLANs they
        route with (see _add_faucet_fib_to_vip()).

        Args:
            vlans (iterable): VLANs.
        Returns:
            dict: {prefix length: set of ip_network}.
        """
        subnets = defaultdict(set)
        if self.proactive_learn:
            for vlan in vlans:
                for faucet_vip in vlan.faucet_vips_by_ipv(self.IPV):
                    if not faucet_vip.ip.is_link_local:
                        subnets[faucet_vip.network.prefixlen].add(faucet_vip.network)
        return subnets

    @staticmethod
    def _inside(ip_dst, subnets):
        """Return True if ip_dst is, or is inside, one of _connected_subnets()."""
        return any(
            prefixlen <= ip_dst.prefixlen
            and ip_dst.supernet(new_prefix=prefixlen) in prefixlen_subnets
            for prefixlen, prefixlen_subnets in subnets.items()
        )

    def _peer_fib_winners(self, vlans, vid, peer_vids, kept_vids, keys):
        """Return the entry a VLAN's FIB has for each destination, and its VLAN.

        A VLAN has entries from itself and from each VLAN it routes with (see
        _peer_fib_entries()). As on a cold start, where _add_resolved_route()
        overwrites the connected subnets add_vlan() installs as next hops
        resolve, a route via a resolved next hop wins over a connected subnet.
        Between two of a kind, where a cold start's choice depends on which
        next hop resolves last, the VLAN itself and the VLANs it kept routing
        with win over those it gains, so a route in use stays where it is,
        and then the lowest VID wins.

        Args:
            vlans (dict): VLANs by VID; a VLAN not in it provides nothing.
            vid (int): VID of the VLAN.
            peer_vids (set): VIDs of the VLANs it routes with.
            kept_vids (set): VIDs of those it routed with before, too.
            keys (set): the destinations to look up.
        Returns:
            dict: {ip_network: (VLAN the entry is from, nw_dst, eth_dst)}, for
                each destination that one of them provides.
        """
        winners = {}
        kept = sorted(vlans.keys() & (kept_vids | {vid}))
        gained = sorted(vlans.keys() & (peer_vids - kept_vids - {vid}))
        for peer_vid in kept + gained:
            peer = vlans[peer_vid]
            for key, (nw_dst, eth_dst) in self._peer_fib_entries(peer, keys).items():
                if key not in winners or (
                    eth_dst is not None and winners[key][2] is None
                ):
                    winners[key] = (peer, nw_dst, eth_dst)
        return winners

    def replay_gained_peers(self, vlans, old_peers, withdrawals):
        """Return flows for what each VLAN gets from the VLANs it starts routing with.

        Called on the new config, once a warm start has added and changed its
        VLANs. Each destination a VLAN gets from a peer it gains (see
        _peer_fib_entries()), or had withdrawn by withdraw_lost_peers(), is
        looked up again over the VLAN itself and every VLAN it now routes
        with (see _peer_fib_winners()). The winner's entry is added, and a
        withdrawn destination that none of them provides is deleted; nothing
        else is sent. So a destination moving from one router to another (a
        default route moving between uplinks) is only ever added: an add
        replaces the flow with the same match and priority in place.

        Args:
            vlans (dict): the new config's VLANs by VID.
            old_peers (dict): routed_peers() of the running config.
            withdrawals (dict): withdraw_lost_peers() of the running config.
        Returns:
            list: OpenFlow messages.
        """
        new_peers = self.routed_peers(self.routers)
        gained_entries = {}
        ofmsgs = []
        for vid in sorted(new_peers.keys() | withdrawals.keys()):
            withdrawn = withdrawals.get(vid, {})
            peer_vids = new_peers.get(vid, set())
            kept_vids = peer_vids & old_peers.get(vid, set())
            keys = set(withdrawn)
            for peer_vid in peer_vids - kept_vids:
                if peer_vid not in gained_entries:
                    gained_entries[peer_vid] = self._peer_fib_entries(vlans[peer_vid])
                keys.update(gained_entries[peer_vid])
            if not keys:
                continue
            winners = self._peer_fib_winners(vlans, vid, peer_vids, kept_vids, keys)
            for key in keys:
                if key in winners:
                    ofmsgs.append(self._peer_fib_flowmod(vlans[vid], *winners[key]))
                else:
                    ofmsgs.append(withdrawn[key])
        return ofmsgs

    def _update_nexthop_cache(self, now, vlan, eth_src, port, ip_gw):
        """Add information to the nexthop cache and return the new object"""
        nexthop = NextHop(eth_src, port, now)
        nexthop_cache = self._vlan_nexthop_cache(vlan)
        nexthop_cache[ip_gw] = nexthop
        return nexthop

    def _update_nexthop(self, now, vlan, port, eth_src, resolved_ip_gw):
        """Update routes where nexthop is newly resolved or changed.

        Args:
            now (float): seconds since epoch.
            vlan (vlan): VLAN containing this RIB/FIB.
            port (port): port for nexthop.
            eth_src (str): MAC address for nexthop.
            resolved_ip_gw (IPAddress): IP address for nexthop
        Returns:
            list: OpenFlow messages, if routes need to be updated.
        """
        ofmsgs = []
        cached_eth_dst = self._cached_nexthop_eth_dst(vlan, resolved_ip_gw)

        if cached_eth_dst != eth_src:
            is_updated = cached_eth_dst is not None
            for ip_dst in vlan.ip_dsts_for_ip_gw(resolved_ip_gw):
                ofmsgs.extend(
                    self._add_resolved_route(
                        vlan, resolved_ip_gw, ip_dst, eth_src, is_updated
                    )
                )
            host_route = ipaddress.ip_network(resolved_ip_gw.exploded)
            if self._vlan_routes(vlan).get(host_route, None) == resolved_ip_gw:
                self._set_host_fib_sent(now, vlan, resolved_ip_gw, eth_src)

        self._update_nexthop_cache(now, vlan, eth_src, port, resolved_ip_gw)
        return ofmsgs

    def _vlan_unresolved_nexthops(self, vlan, ip_gws, now):
        """Return unresolved or expired IP gateways, never tried/oldest first,
        taking those with no MAC and refreshes of resolved ones in turn.

        A refresh due counts as never tried. Taken by tries alone, a next hop
        with no MAC that missed a request, and so is not routed at all, waits
        for as long as more refreshes come due each cycle than it requests.
        Taken with no MAC strictly first, refreshes wait instead, for as long
        as new addresses keep coming, as from a scan of the subnet, and a
        next hop that has gone stays routed.

        Args:
           vlan (vlan): VLAN containing this RIB/FIB.
           ip_gws (list): tuple, IP gateway and controller IP in same subnet.
           now (float): seconds since epoch.
        Returns:
           list: prioritized list of gateways.
        """
        vlan_nexthop_cache = self._vlan_nexthop_cache(vlan)
        nexthop_entries = [
            (ip_gw, vlan_nexthop_cache.get(ip_gw, None)) for ip_gw in ip_gws
        ]
        not_fresh_nexthops = [
            (ip_gw, entry)
            for ip_gw, entry in nexthop_entries
            if entry is None or entry.resolution_due(now, self.neighbor_timeout)
        ]
        no_mac_by_retries = defaultdict(list)
        refreshes_by_retries = defaultdict(list)
        for ip_gw, entry in not_fresh_nexthops:
            if entry is None:
                entry = self._update_nexthop_cache(now, vlan, None, None, ip_gw)
            if entry.eth_src is None:
                no_mac_by_retries[entry.resolve_retries].append(ip_gw)
            else:
                refreshes_by_retries[entry.resolve_retries].append(ip_gw)
        unresolved_nexthops = deque()
        for turn in zip_longest(
            self._fewest_retries_first(no_mac_by_retries),
            self._fewest_retries_first(refreshes_by_retries),
        ):
            unresolved_nexthops.extend(ip_gw for ip_gw in turn if ip_gw is not None)
        return unresolved_nexthops

    @staticmethod
    def _fewest_retries_first(nexthops_by_retries):
        """Return next hops, fewest retries first, those with as many in random
        order."""
        nexthops_in_order = []
        for _retries, nexthops in sorted(nexthops_by_retries.items()):
            random.shuffle(nexthops)
            nexthops_in_order.extend(nexthops)
        return nexthops_in_order

    def advertise(self, vlan):
        raise NotImplementedError  # pragma: no cover

    def _resolve_gateway_flows(self, ip_gw, nexthop_cache_entry, vlan, now):
        """Return packet-out ofmsgs using ARP/ND to resolve for nexthop"""
        faucet_vip = vlan.vip_map(ip_gw)
        if not faucet_vip:
            self.logger.info("Not resolving %s (not in connected network)" % ip_gw)
            return []
        resolve_flows = []
        last_retry_time = nexthop_cache_entry.last_retry_time
        nexthop_cache_entry.next_retry(now, self.max_resolve_backoff_time)
        if (
            vlan.targeted_gw_resolution
            and last_retry_time is None
            and nexthop_cache_entry.port is not None
        ):
            port = nexthop_cache_entry.port
            eth_dst = nexthop_cache_entry.eth_src
            resolve_flows = [
                self._resolve_gw_on_port(vlan, port, faucet_vip, ip_gw, eth_dst)
            ]
        else:
            resolve_flows = self._resolve_gw_on_vlan(vlan, faucet_vip, ip_gw)
        if resolve_flows:
            if last_retry_time is None:
                self.logger.info(
                    "resolving %s (%u flows) on VLAN %u"
                    % (ip_gw, len(resolve_flows), vlan.vid)
                )
            else:
                self.logger.info(
                    "resolving %s retry %u (last attempt was %us ago; %u flows) on VLAN %u"
                    % (
                        ip_gw,
                        nexthop_cache_entry.resolve_retries,
                        now - last_retry_time,
                        len(resolve_flows),
                        vlan.vid,
                    )
                )
        return resolve_flows

    def _expire_gateway_flows(self, ip_gw, nexthop_cache_entry, vlan, now):
        """Return ofmsgs deleting the expired nexthop information"""
        expire_flows = []
        self.logger.info(
            "expiring dead route %s (age %us) on %s"
            % (ip_gw, nexthop_cache_entry.age(now), vlan)
        )
        port = nexthop_cache_entry.port
        # The resolvers expire only a dead next hop, and never a gateway a
        # route uses, however many of its requests have gone unanswered.
        route_gw = vlan.ip_dsts_for_ip_gw(ip_gw) and not vlan.is_host_fib_route(ip_gw)
        if port is not None and (
            route_gw or not self.nexthop_dead(nexthop_cache_entry)
        ):
            # Expired with its port, not by the resolvers: see add_port().
            vlan.add_port_expired_gw(port, ip_gw)
        self._del_vlan_nexthop_cache_entry(vlan, ip_gw)
        expire_flows = self._del_host_fib_route(
            vlan, ipaddress.ip_network(ip_gw.exploded)
        )
        for ip_dst in vlan.ip_dsts_for_ip_gw(ip_gw):
            expire_flows.extend(self._del_route_flows(vlan, ip_dst))
        if port is None:
            expire_flows = []
        return expire_flows

    def _resolve_expire_gateway_flows(self, ip_gw, nexthop_cache_entry, vlan, now):
        """If cache entry is dead then delete related flows
        otherwise return packet-out ofmsgs to resolve nexthops"""
        if self.nexthop_dead(nexthop_cache_entry):
            expire_flows = self._expire_gateway_flows(
                ip_gw, nexthop_cache_entry, vlan, now
            )
            vlan.del_route_gw(ip_gw)
            return expire_flows
        return self._resolve_gateway_flows(ip_gw, nexthop_cache_entry, vlan, now)

    def _resolve_route_gateway_flows(self, ip_gw, nexthop_cache_entry, vlan, now):
        """Resolve a route gateway. One that no route uses, such as a host
        whose route was expired with its port, is expired once dead."""
        if vlan.ip_dsts_for_ip_gw(ip_gw):
            return self._resolve_gateway_flows(ip_gw, nexthop_cache_entry, vlan, now)
        return self._resolve_expire_gateway_flows(ip_gw, nexthop_cache_entry, vlan, now)

    def _resolve_gateways_flows(
        self, resolve_handler, vlan, now, unresolved_nexthops, remaining_attempts
    ):
        """Resolve for nexthops using the resolve_handler
        Return packet-out ofmsgs using V4 ARP/V6 ND to resolve nexthops
        """
        ofmsgs = []
        for ip_gw in unresolved_nexthops:
            if remaining_attempts == 0:
                break
            entry = self._vlan_nexthop_cache_entry(vlan, ip_gw)
            if entry is None:
                continue
            if not entry.resolution_due(now, self.neighbor_timeout):
                continue
            resolve_flows = resolve_handler(ip_gw, entry, vlan, now)
            if resolve_flows:
                ofmsgs.extend(resolve_flows)
                remaining_attempts -= 1
        return ofmsgs

    def resolve_gateways(self, vlan, now, resolve_all=True):
        """Re/resolve gateways.

        Args:
            vlan (vlan): VLAN containing this RIB/FIB.
            now (float): seconds since epoch.
            resolve_all (bool): attempt to resolve all unresolved gateways.
        Returns:
            list: OpenFlow messages.
        """
        unresolved_gateways = []
        if resolve_all:
            unresolved_gateways = self._vlan_unresolved_nexthops(
                vlan, vlan.dyn_route_gws_by_ipv[self.IPV], now
            )
            vlan.dyn_unresolved_route_ip_gws[self.IPV] = unresolved_gateways
        else:
            if vlan.dyn_unresolved_route_ip_gws[self.IPV]:
                unresolved_gateways = [
                    vlan.dyn_unresolved_route_ip_gws[self.IPV].popleft()
                ]
        return self._resolve_gateways_flows(
            self._resolve_route_gateway_flows,
            vlan,
            now,
            unresolved_gateways,
            self.max_hosts_per_resolve_cycle,
        )

    def resolve_expire_hosts(self, vlan, now, resolve_all=True):
        """Re/resolve hosts.

        Args:
            vlan (vlan): VLAN containing this RIB/FIB.
            now (float): seconds since epoch.
            resolve_all (bool): attempt to resolve all unresolved gateways.
        Returns:
            list: OpenFlow messages.
        """
        unresolved_gateways = []
        if resolve_all:
            unresolved_gateways = self._vlan_unresolved_nexthops(
                vlan, vlan.dyn_host_gws_by_ipv[self.IPV], now
            )
            vlan.dyn_unresolved_host_ip_gws[self.IPV] = unresolved_gateways
        else:
            if vlan.dyn_unresolved_host_ip_gws[self.IPV]:
                unresolved_gateways = [
                    vlan.dyn_unresolved_host_ip_gws[self.IPV].popleft()
                ]
        return self._resolve_gateways_flows(
            self._resolve_expire_gateway_flows,
            vlan,
            now,
            unresolved_gateways,
            self.max_hosts_per_resolve_cycle,
        )

    def _cached_nexthop_eth_dst(self, vlan, ip_gw):
        """Return nexthop cache entry eth_dst for the ip_gw"""
        entry = self._vlan_nexthop_cache_entry(vlan, ip_gw)
        if entry is not None and entry.eth_src is not None:
            return entry.eth_src
        return None

    @staticmethod
    def _host_ip_to_host_int(host_ip):
        return ipaddress.ip_interface(ipaddress.ip_network(host_ip))

    def _host_from_faucet_vip(self, faucet_vip):
        return self._host_ip_to_host_int(faucet_vip.ip)

    def _vlan_nexthop_cache_limit(self, vlan):
        raise NotImplementedError  # pragma: no cover

    def _proactive_resolve_neighbor(self, now, pkt_meta):
        """Packet not directly destined for router but we can learn from the packet anyway"""
        vlan = pkt_meta.vlan
        dst_ip = pkt_meta.l3_dst
        ofmsgs = []
        if self.proactive_learn:
            # The VLAN a packet arrives on is the current config's, so its VID
            # finds the routers naming it.
            vip_map = self.vip_maps_by_vid.get(vlan.vid, None)
            if vip_map is None:
                faucet_vip = vlan.vip_map(dst_ip)
            else:
                vlan, faucet_vip = vip_map.get(dst_ip, (None, None))
            if (
                vlan
                and vlan.ip_in_vip_subnet(dst_ip, faucet_vip)
                and faucet_vip.ip != dst_ip
                and self._stateful_gw(vlan, dst_ip)
            ):
                limit = self._vlan_nexthop_cache_limit(vlan)
                if limit is None or len(self._vlan_nexthop_cache(vlan)) < limit:
                    # TODO: avoid relearning L3 source if same L3 source tries
                    # multiple L3 destinations quickly.
                    ofmsgs.extend(self.add_host_fib_route_from_pkt(now, pkt_meta))
                    cached_eth_dst = self._cached_nexthop_eth_dst(vlan, dst_ip)
                    if cached_eth_dst is not None:
                        # A resolved destination reaches us only while no flows
                        # route to it: not yet, no longer, or never, when it is
                        # known from an advert alone. Route it, not blackhole it.
                        # Packets queued at the switch before the route's flows
                        # got there arrive after them: if the flows went out
                        # moments ago, do not send them again.
                        host_route = ipaddress.ip_network(dst_ip.exploded)
                        if self._vlan_routes(vlan).get(host_route, None) != dst_ip:
                            ofmsgs.extend(self._add_host_fib_route(vlan, dst_ip))
                        elif not self._host_fib_sent_recently(
                            now, vlan, dst_ip, cached_eth_dst
                        ):
                            ofmsgs.extend(
                                self._add_resolved_route(
                                    vlan,
                                    dst_ip,
                                    host_route,
                                    cached_eth_dst,
                                    False,
                                    readd=True,
                                )
                            )
                            self._set_host_fib_sent(now, vlan, dst_ip, cached_eth_dst)
                        return ofmsgs
                    resolution_in_progress = (
                        dst_ip in vlan.dyn_host_gws_by_ipv[self.IPV]
                    )
                    # Nor a blackhole that went out moments ago.
                    blackhole = not self._host_fib_sent_recently(
                        now, vlan, dst_ip, None
                    )
                    ofmsgs.extend(
                        self._add_host_fib_route(vlan, dst_ip, blackhole=blackhole)
                    )
                    if blackhole:
                        self._set_host_fib_sent(now, vlan, dst_ip, None)
                    nexthop_cache_entry = self._update_nexthop_cache(
                        now, vlan, None, None, dst_ip
                    )
                    if not resolution_in_progress:
                        resolve_flows = self._resolve_gateway_flows(
                            dst_ip,
                            nexthop_cache_entry,
                            vlan,
                            nexthop_cache_entry.cache_time,
                        )
                        ofmsgs.extend(resolve_flows)
        return ofmsgs

    def router_vlan_for_ip_gw(self, vlan, ip_gw):
        """Return router VLAN for IP gateway (or None).

        Args:
            vlan (vlan): VLAN containing this RIB.
            ip_gw (ipaddress.ip_address): IP address of nexthop.
        Returns:
            VLAN for this gateway or None.
        """
        router = self._router_for_vlan(vlan)
        if router is not None:
            vlan, _ = router.vip_map(ip_gw)
        elif not vlan.vip_map(ip_gw):
            return None
        if vlan is not None and vlan.is_extra_ip(ip_gw):
            # FAUCET's own address is no gateway.
            return None
        return vlan

    def add_route(self, vlan, ip_gw, ip_dst):
        """Add a route to the RIB.

        Args:
            vlan (vlan): VLAN containing this RIB.
            ip_gw (ipaddress.ip_address): IP address of nexthop.
            ip_dst (ipaddress.ip_network): destination IP network.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        vlan = self.router_vlan_for_ip_gw(vlan, ip_gw)
        if vlan is None:
            self.logger.error(
                (
                    "Cannot resolve destination VLAN for gateway %s "
                    "(not in global router?)" % ip_gw
                )
            )
            return ofmsgs
        if vlan.is_faucet_vip(ip_dst):
            return ofmsgs
        if ip_dst.prefixlen == ip_dst.max_prefixlen and vlan.is_extra_ip(
            ip_dst.network_address
        ):
            self.logger.warning(
                "Not adding route %s via %s, as VLAN %u lists %s in faucet_extra_ips"
                % (ip_dst, ip_gw, vlan.vid, ip_dst.network_address)
            )
            return ofmsgs
        routes = self._vlan_routes(vlan)
        if routes.get(ip_dst, None) == ip_gw:
            return ofmsgs

        vlan.add_route(ip_dst, ip_gw)
        cached_eth_dst = self._cached_nexthop_eth_dst(vlan, ip_gw)
        if cached_eth_dst is not None:
            ofmsgs.extend(
                self._add_resolved_route(
                    vlan=vlan,
                    ip_gw=ip_gw,
                    ip_dst=ip_dst,
                    eth_dst=cached_eth_dst,
                    is_updated=False,
                )
            )
        return ofmsgs

    def _add_host_fib_route(self, vlan, host_ip, blackhole=False):
        """Add a host FIB route.

        Args:
            vlan (vlan): VLAN containing this RIB.
            host_ip (ipaddress.ip_address): IP address of host.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        if blackhole:
            priority = self._route_priority(host_ip)
            host_int = self._host_ip_to_host_int(host_ip)
            timeout = (
                self.max_resolve_backoff_time * self.max_host_fib_retry_count
                + random.randint(0, self.max_resolve_backoff_time * 2)
            )
            routed_vlans = self._routed_vlans(vlan)
            for routed_vlan in routed_vlans:
                in_match = self._route_match(routed_vlan, host_int)
                ofmsgs.append(
                    self.fib_table.flowmod(
                        in_match, priority=priority, hard_timeout=timeout
                    )
                )
        host_route = ipaddress.ip_network(host_ip.exploded)
        ofmsgs.extend(self.add_route(vlan, host_ip, host_route))
        return ofmsgs

    def _del_host_fib_route(self, vlan, host_ip):
        """Delete a host FIB route.

        Args:
            vlan (vlan): VLAN containing this RIB.
            host_ip (ipaddress.ip_address): IP address of host.
        Returns:
            list: OpenFlow messages.
        """
        host_route = ipaddress.ip_network(host_ip.exploded)
        return self.del_route(vlan, host_route)

    def _ip_pkt(self, pkt):
        """Return an IP packet from an Ethernet packet.

        Args:
            pkt: ryu.lib.packet from host.
        Returns:
            IP ryu.lib.packet parsed from pkt.
        """
        return pkt.get_protocol(self.IP_PKT)

    def add_host_fib_route_from_pkt(self, now, pkt_meta):
        """Add a host FIB route given packet from host.

        Args:
            now (float): seconds since epoch.
            pkt_meta (PacketMeta): received packet.
        Returns:
            list: OpenFlow messages.
        """
        src_ip = pkt_meta.l3_src
        ofmsgs = []
        if (
            src_ip
            and pkt_meta.vlan.ip_in_vip_subnet(src_ip)
            and self._stateful_gw(pkt_meta.vlan, src_ip)
        ):
            ip_pkt = self._ip_pkt(pkt_meta.pkt)
            if ip_pkt:
                ofmsgs.extend(
                    self._add_host_fib_route(pkt_meta.vlan, src_ip, blackhole=False)
                )
                ofmsgs.extend(
                    self._update_nexthop(
                        now, pkt_meta.vlan, pkt_meta.port, pkt_meta.eth_src, src_ip
                    )
                )
        return ofmsgs

    def _del_route_flows(self, vlan, ip_dst):
        """Delete all flows matching the vlan and ip_dst"""
        ofmsgs = []
        if ip_dst.prefixlen == ip_dst.max_prefixlen:
            # A packet for the host sends its flows again at once.
            self.host_fib_sent.get(vlan.vid, {}).pop(ip_dst.network_address, None)
        routed_vlans = self._routed_vlans(vlan)
        for routed_vlan in routed_vlans:
            route_match = self._route_match(routed_vlan, ip_dst)
            ofmsgs.append(
                self.fib_table.flowdel(
                    route_match, priority=self._route_priority(ip_dst), strict=True
                )
            )
        return ofmsgs

    def del_route(self, vlan, ip_dst):
        """Delete a route from the RIB.

        Only one route with this exact destination is supported.

        Args:
            vlan (vlan): VLAN containing this RIB.
            ip_dst (ipaddress.ip_network): destination IP network.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        if vlan.is_faucet_vip(ip_dst):
            return ofmsgs
        routes = self._vlan_routes(vlan)
        if ip_dst in routes:
            vlan.del_route(ip_dst)
            ofmsgs.extend(self._del_route_flows(vlan, ip_dst))
        return ofmsgs

    def control_plane_handler(self, now, pkt_meta):
        return self._proactive_resolve_neighbor(now, pkt_meta)


class ValveIPv4RouteManager(ValveRouteManager):
    """Implement IPv4 RIB/FIB."""

    IPV = 4
    ETH_TYPE = valve_of.ether.ETH_TYPE_IP
    ICMP_TYPE = valve_of.inet.IPPROTO_ICMP
    ICMP_SIZE = valve_packet.VLAN_ICMP_ECHO_REQ_SIZE
    CONTROL_ETH_TYPES = (valve_of.ether.ETH_TYPE_IP, valve_of.ether.ETH_TYPE_ARP)  # type: ignore
    IP_PKT = ipv4.ipv4
    # The sender address of an ARP probe (RFC 5227).
    ARP_PROBE_SPA = ipaddress.ip_network("0.0.0.0/32")
    # The most of a VLAN's faucet_extra_ips probed for or announced at a time.
    EXTRA_IP_ANNOUNCE_PER_CYCLE = 16
    # Probing for one of faucet_extra_ips, as RFC 5227 has a host probe for an
    # address before it uses it: the probes in a round, the seconds at least
    # between them, and the seconds after the last before the switch answers
    # for the address, if no other host has.
    EXTRA_IP_PROBE_NUM = 3
    EXTRA_IP_PROBE_INTERVAL = 1
    EXTRA_IP_ANNOUNCE_WAIT = 2
    # The seconds FAUCET waits before it probes again for an address another
    # host uses, doubling from the first to the last.
    EXTRA_IP_HOLD_MIN = 2
    EXTRA_IP_HOLD_MAX = 600

    def advertise(self, _vlan):
        return []

    @staticmethod
    def _gw_resolve_pkt():
        return valve_packet.arp_request

    @staticmethod
    def _gw_respond_pkt():
        return valve_packet.arp_reply

    def _vlan_nexthop_cache_limit(self, vlan):
        return vlan.proactive_arp_limit

    @staticmethod
    def _arp_responder_answers(faucet_vip):
        """Return True if the switch answers ARP for a VIP.

        Not for a /31 or /32 VIP: ip_in_vip_subnet() takes both addresses of
        a /31 for its network and broadcast addresses, so FAUCET answers no
        ARP from the far end of a point-to-point /31, and the switch does not
        either, leaving the link as it is without arp_responder. A /32 VIP,
        which the config refuses anyway, has no far end.
        """
        return faucet_vip.network.prefixlen < 31

    def _arp_responder_match(
        self, vlan, faucet_vip, target_host, port=None, probe=False
    ):
        """Return the match and priority of a flow that answers ARP for an
        address: a VIP, or one of faucet_extra_ips in the VIP's subnet.

        Given a port the VLAN is untagged on, the flow matches that port, at a
        priority above the VLAN's own flow, which answers tagged ports. With
        probe, it matches an ARP probe for the address (RFC 5227), whose
        sender address is 0.0.0.0, rather than a request from the subnet.
        """
        in_port = None
        priority = self.route_priority + faucet_vip.ip.max_prefixlen + 1
        if port is not None:
            in_port = port.number
            priority += 1
        arp_spa = faucet_vip.network
        if probe:
            arp_spa = self.ARP_PROBE_SPA
        match = self.vip_table.match(
            in_port=in_port,
            vlan=vlan,
            eth_type=valve_of.ether.ETH_TYPE_ARP,
            arp_op=arp.ARP_REQUEST,
            nw_dst=target_host,
            arp_spa=arp_spa,
        )
        return match, priority

    def _arp_responder(self, vlan, faucet_vip, target_host, port=None, probe=False):
        """Return a flow that answers ARP requests for an address on the switch.

        A request for a VIP goes to the controller unchanged first, which
        learns the host and answers it too, and so does a probe. The switch
        then rewrites it into the reply and sends it back out the port it came
        in on, which it can do while the controller is busy. Given a port the
        VLAN is untagged on, the flow matches that port and sends the reply
        untagged.
        """
        actions = []
        if probe or target_host.ip == faucet_vip.ip:
            actions.append(valve_of.output_controller(valve_packet.VLAN_ARP_PKT_SIZE))
        actions.extend(
            [
                valve_of.copy_field("eth_src", "eth_dst", 48),
                self.vip_table.set_field(eth_src=vlan.faucet_mac),
                self.vip_table.set_field(arp_op=arp.ARP_REPLY),
                valve_of.copy_field("arp_sha", "arp_tha", 48),
                self.vip_table.set_field(arp_sha=vlan.faucet_mac),
                valve_of.copy_field("arp_spa", "arp_tpa", 32),
                self.vip_table.set_field(arp_spa=str(target_host.ip)),
            ]
        )
        if port is not None:
            actions.append(valve_of.pop_vlan())
        actions.append(valve_of.output_in_port())
        match, priority = self._arp_responder_match(
            vlan, faucet_vip, target_host, port, probe
        )
        return self.vip_table.flowmod(
            match,
            priority=priority,
            inst=(valve_of.apply_actions(actions),),
        )

    def _extra_ip_fib_vlan(self, vlan):
        """Return the VLAN the FIB flow for one of a VLAN's faucet_extra_ips
        matches."""
        if self.global_routing:
            return self.global_vlan
        return vlan

    def _extra_ip_answers(self, vlan, extra_ip):
        """Return the flows that answer ARP for one of a VLAN's
        faucet_extra_ips, once FAUCET has claimed it.

        The switch answers a request for the address from the VIP's subnet
        with faucet_mac, as it does for the VIP, but sends nothing to the
        controller: FAUCET learns no host from it, as the address is its own.
        It also answers an ARP probe for the address, so that a device about
        to take the address finds it in use, and copies the probe to the
        controller. As for a VIP, there is a flow for the VLAN, which answers
        tagged ports, and one for each running port it is untagged on.
        """
        faucet_vip = vlan.vip_map(extra_ip)
        target_host = self._host_ip_to_host_int(extra_ip)
        ofmsgs = []
        for port in [None] + [port for port in vlan.untagged if port.running()]:
            ofmsgs.append(self._arp_responder(vlan, faucet_vip, target_host, port=port))
            ofmsgs.append(
                self._arp_responder(
                    vlan, faucet_vip, target_host, port=port, probe=True
                )
            )
        return ofmsgs

    def _extra_ip_probes_seen(self, vlan, extra_ip):
        """Return the flow that sends another host's ARP probes for one of a
        VLAN's faucet_extra_ips to the controller and on, unanswered, until
        FAUCET claims the address. It has the match and priority of the flow
        for the VLAN that answers them after (see _extra_ip_answers()), which
        replaces it."""
        faucet_vip = vlan.vip_map(extra_ip)
        target_host = self._host_ip_to_host_int(extra_ip)
        match, priority = self._arp_responder_match(
            vlan, faucet_vip, target_host, probe=True
        )
        return self.vip_table.flowcontroller(
            match,
            priority=priority,
            inst=self.pipeline.accept_to_l2_forwarding(),
            max_len=valve_packet.VLAN_ARP_PKT_SIZE,
        )

    def _extra_ip_flows(self, vlan, extra_ip):
        """Return the flows for one of a VLAN's faucet_extra_ips.

        Once FAUCET has claimed the address, the switch answers ARP for it
        (see _extra_ip_answers()). Until then, requests for it go on as for
        any other host's address, and probes for it go to the controller too.

        IPv4 traffic to the address is sent to the VIP table, as it is for a
        VIP, and dropped there, whether FAUCET has claimed it or not. The drop
        matches no VLAN, as traffic routed from another VLAN reaches the VIP
        table too, through the FIB flow for the address's subnet. ARP from
        the address goes to the controller (see _extra_ip_sender_matches()).
        """
        target_host = self._host_ip_to_host_int(extra_ip)
        priority = self._route_priority(target_host)
        state = vlan.dyn_extra_ip_state[extra_ip]
        if state.state == ExtraIPState.CLAIMED:
            ofmsgs = self._extra_ip_answers(vlan, extra_ip)
        else:
            ofmsgs = [self._extra_ip_probes_seen(vlan, extra_ip)]
        ofmsgs.append(
            self.fib_table.flowmod(
                self._route_match(self._extra_ip_fib_vlan(vlan), target_host),
                priority=priority,
                inst=(self.fib_table.goto(self.vip_table),),
            )
        )
        ofmsgs.append(
            self.vip_table.flowdrop(
                self.vip_table.match(eth_type=self.ETH_TYPE, nw_dst=target_host),
                priority=priority,
            )
        )
        for match, priority, forward in self._extra_ip_sender_matches(vlan, extra_ip):
            inst = ()
            if forward:
                inst = self.pipeline.accept_to_l2_forwarding()
            ofmsgs.append(
                self.vip_table.flowcontroller(
                    match,
                    priority=priority,
                    inst=inst,
                    max_len=valve_packet.VLAN_ARP_PKT_SIZE,
                )
            )
        return ofmsgs

    def _extra_ip_sender_matches(self, vlan, extra_ip):
        """Return the match and priority of each flow for ARP on a VLAN whose
        sender is one of its faucet_extra_ips, and whether it forwards it.

        Such ARP is from another host using the address, or from another
        datapath announcing it with faucet_mac, and goes to the controller,
        which counts the first. ARP to faucet_mac goes to the controller
        alone, as any other host's does, and the rest is forwarded too, so
        that the switch does not take the other host's own ARP from it. The
        flows are above those that answer requests for the address, so that
        a gratuitous request for it is not answered.
        """
        priority = self.route_priority + extra_ip.max_prefixlen + 3
        sender = ipaddress.ip_network(extra_ip)
        return [
            (
                self.vip_table.match(
                    vlan=vlan,
                    eth_type=valve_of.ether.ETH_TYPE_ARP,
                    eth_dst=vlan.faucet_mac,
                    arp_spa=sender,
                ),
                priority + 1,
                False,
            ),
        ] + [
            (
                self.vip_table.match(
                    vlan=vlan,
                    eth_type=valve_of.ether.ETH_TYPE_ARP,
                    arp_op=arp_op,
                    arp_spa=sender,
                ),
                priority,
                True,
            )
            for arp_op in (arp.ARP_REQUEST, arp.ARP_REPLY)
        ]

    def _extra_ip_port_deletes(self, vlan, extra_ip, port):
        """Return strict deletes of the flows that answer ARP for one of a
        VLAN's faucet_extra_ips on a port it is untagged on, or with no port,
        of the VLAN's own."""
        faucet_vip = vlan.vip_map(extra_ip)
        target_host = self._host_ip_to_host_int(extra_ip)
        ofmsgs = []
        for probe in (False, True):
            match, priority = self._arp_responder_match(
                vlan, faucet_vip, target_host, port=port, probe=probe
            )
            ofmsgs.append(
                self.vip_table.flowdel(match=match, priority=priority, strict=True)
            )
        return ofmsgs

    def _extra_ip_unvlanned_deletes(self, extra_ip):
        """Return strict deletes of the flows for one of faucet_extra_ips that
        match no VLAN of the config: the drop, and with global routing, the
        FIB flow."""
        target_host = self._host_ip_to_host_int(extra_ip)
        priority = self._route_priority(target_host)
        ofmsgs = [
            self.vip_table.flowdel(
                match=self.vip_table.match(eth_type=self.ETH_TYPE, nw_dst=target_host),
                priority=priority,
                strict=True,
            )
        ]
        if self.global_routing:
            ofmsgs.append(
                self.fib_table.flowdel(
                    match=self._route_match(self.global_vlan, target_host),
                    priority=priority,
                    strict=True,
                )
            )
        return ofmsgs

    def _extra_ip_deletes(self, vlan, extra_ip):
        """Return strict deletes of every flow for one of a VLAN's
        faucet_extra_ips, each with the match and priority it was added with,
        so that the address goes without touching any other flow."""
        ofmsgs = []
        for port in [None] + list(vlan.untagged):
            ofmsgs.extend(self._extra_ip_port_deletes(vlan, extra_ip, port))
        for match, priority, _ in self._extra_ip_sender_matches(vlan, extra_ip):
            ofmsgs.append(
                self.vip_table.flowdel(match=match, priority=priority, strict=True)
            )
        if not self.global_routing:
            target_host = self._host_ip_to_host_int(extra_ip)
            ofmsgs.append(
                self.fib_table.flowdel(
                    match=self._route_match(vlan, target_host),
                    priority=self._route_priority(target_host),
                    strict=True,
                )
            )
        ofmsgs.extend(self._extra_ip_unvlanned_deletes(extra_ip))
        return ofmsgs

    def _purge_extra_ip(self, vlan, extra_ip):
        """Forget what FAUCET learned of an address before it was listed in
        faucet_extra_ips: its next hop, the routes via it, its host route
        among them, and its place among the gateways it resolves."""
        ofmsgs = []
        if self._vlan_nexthop_cache_entry(vlan, extra_ip) is not None:
            self._del_vlan_nexthop_cache_entry(vlan, extra_ip)
        for ip_dst in sorted(vlan.ip_dsts_for_ip_gw(extra_ip)):
            ofmsgs.extend(self.del_route(vlan, ip_dst))
        # Deleting its last route leaves the address among the route gateways.
        vlan.forget_extra_ip_gws(extra_ip)
        return ofmsgs

    def add_extra_ips(self, vlan, extra_ips):
        """Add the flows for some of a VLAN's faucet_extra_ips, and probe for
        each that the VLAN lists anew before the switch answers for it.

        Args:
            vlan (VLAN): the VLAN that lists them.
            extra_ips (iterable): the addresses.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        for extra_ip in sorted(extra_ips):
            state = vlan.dyn_extra_ip_state.get(extra_ip, None)
            if state is None:
                # Listed anew, or FAUCET has started: all are probed for.
                state = ExtraIPState(time.time())
                vlan.dyn_extra_ip_state[extra_ip] = state
            ofmsgs.extend(self._purge_extra_ip(vlan, extra_ip))
            ofmsgs.extend(self._extra_ip_flows(vlan, extra_ip))
            self._add_extra_ip_metrics(vlan, extra_ip, state)
        return ofmsgs

    def _extra_ip_labels(self, vlan, extra_ip):
        """Return the metric labels of one of a VLAN's faucet_extra_ips."""
        return dict(self.prom_labels, vlan=vlan.vid, ip=str(extra_ip))

    def _add_extra_ip_metrics(self, vlan, extra_ip, state):
        """Report one of a VLAN's faucet_extra_ips in its state, keeping the
        counts an address listed already has, and starting them at 0 for one
        listed anew rather than reporting nothing."""
        if self.set_var is None or self.inc_var is None:
            return
        labels = self._extra_ip_labels(vlan, extra_ip)
        self.set_var("vlan_extra_ip_state", state.state, labels)
        self.set_var("vlan_extra_ip_state_change_time", state.change_time, labels)
        for var in ("vlan_extra_ip_foreign_arp", "vlan_extra_ip_state_changes"):
            self.inc_var(var, labels, 0)

    def del_extra_ip_metrics(self, vlan, extra_ips):
        """Remove the metrics of some of a VLAN's faucet_extra_ips.

        Args:
            vlan (VLAN): the VLAN that listed them, in the config that added
                their metrics.
            extra_ips (iterable): the addresses.
        """
        if self.remove_var is None:
            return
        for extra_ip in sorted(extra_ips):
            labels = self._extra_ip_labels(vlan, extra_ip)
            for var in (
                "vlan_extra_ip_state",
                "vlan_extra_ip_state_changes",
                "vlan_extra_ip_state_change_time",
                "vlan_extra_ip_foreign_arp",
            ):
                self.remove_var(var, labels)

    def keep_extra_ip_states(self, vlan, new_vlan):
        """Give a new config's VLAN the state of each of the faucet_extra_ips
        it still lists, and forget those it does not, so that FAUCET probes
        for one again if it is listed again.

        A VLAN whose config is otherwise unchanged shares its state with the
        new config's already (see Conf.merge_dyn()). If the VLAN's faucet_mac
        changes, FAUCET probes again for the addresses it has claimed or is
        probing for, as other hosts know them by the old MAC.

        Args:
            vlan (VLAN): the VLAN in the running config.
            new_vlan (VLAN): the VLAN with its VID in the new config.
        """
        states = new_vlan.dyn_extra_ip_state
        if states is not vlan.dyn_extra_ip_state:
            states.update(vlan.dyn_extra_ip_state)
        for extra_ip in set(states) - new_vlan.faucet_extra_ips:
            del states[extra_ip]
        if new_vlan.faucet_mac == vlan.faucet_mac:
            return
        now = time.time()
        for extra_ip in sorted(states):
            state = states[extra_ip]
            if state.state == ExtraIPState.HELD:
                continue
            state.probes = 0
            state.next_time = None
            if state.state == ExtraIPState.CLAIMED:
                self._extra_ip_set_state(
                    new_vlan, extra_ip, state, ExtraIPState.PROBING, now
                )

    def del_extra_ips(self, vlan, extra_ips):
        """Delete the flows for some of a VLAN's faucet_extra_ips, strictly.

        Args:
            vlan (VLAN): the VLAN that listed them, in the config that added
                their flows.
            extra_ips (iterable): the addresses.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        for extra_ip in sorted(extra_ips):
            ofmsgs.extend(self._extra_ip_deletes(vlan, extra_ip))
            # Announced again if listed again.
            vlan.dyn_extra_ip_refresh.pop(extra_ip, None)
        return ofmsgs

    def add_vlan(self, vlan, cold_start):
        if cold_start:
            # The switch has lost the flows that answered for them, so others
            # may have stopped using faucet_mac for them: announce them again.
            vlan.dyn_extra_ip_refresh.clear()
            # Nor could answers to probes have reached FAUCET while the switch
            # had no flows: a round of them starts over.
            for state in vlan.dyn_extra_ip_state.values():
                state.probes = 0
        ofmsgs = super().add_vlan(vlan, cold_start)
        ofmsgs.extend(self.add_extra_ips(vlan, vlan.faucet_extra_ips))
        return ofmsgs

    def _extra_ip_gratuitous(self, vlan, extra_ip):
        """Return a gratuitous ARP request and reply for one of a VLAN's
        faucet_extra_ips, flooded with faucet_mac."""
        ofmsgs = []
        for pkt_builder in (valve_packet.arp_request, valve_packet.arp_reply):
            ofmsgs.extend(
                vlan.flood_pkt(
                    pkt_builder,
                    self.multi_out,
                    vlan.faucet_mac,
                    valve_of.mac.BROADCAST_STR,
                    extra_ip,
                    extra_ip,
                )
            )
        return ofmsgs

    def _extra_ip_gw_requests(self, vlan, extra_ip, told_gws):
        """Return an ARP request from one of a VLAN's faucet_extra_ips to each
        route gateway in its subnet with a MAC that is not in told_gws, and
        add those gateways to told_gws."""
        ofmsgs = []
        faucet_vip = vlan.vip_map(extra_ip)
        for ip_gw in sorted(vlan.dyn_route_gws_by_ipv[self.IPV] - told_gws):
            nexthop = self._vlan_nexthop_cache_entry(vlan, ip_gw)
            if (
                ip_gw not in faucet_vip.network
                or nexthop is None
                or nexthop.eth_src is None
            ):
                continue
            ofmsgs.append(
                vlan.pkt_out_port(
                    valve_packet.arp_request,
                    nexthop.port,
                    vlan.faucet_mac,
                    nexthop.eth_src,
                    extra_ip,
                    ip_gw,
                )
            )
            told_gws.add(ip_gw)
        return ofmsgs

    def _extra_ip_announce(self, vlan, extra_ip, now):
        """Return the ARP due that announces one of a VLAN's faucet_extra_ips,
        which FAUCET has claimed (see extra_ips_due())."""
        ofmsgs = []
        refresh = vlan.dyn_extra_ip_refresh.get(extra_ip, None)
        if refresh is None:
            ofmsgs.extend(self._extra_ip_gratuitous(vlan, extra_ip))
        if refresh is None or refresh[0] <= now:
            refresh = (now + self.neighbor_timeout, set())
            vlan.dyn_extra_ip_refresh[extra_ip] = refresh
        ofmsgs.extend(self._extra_ip_gw_requests(vlan, extra_ip, refresh[1]))
        return ofmsgs

    def _extra_ip_probe(self, vlan, extra_ip):
        """Return an ARP probe (RFC 5227) for one of a VLAN's faucet_extra_ips,
        flooded with faucet_mac: none if no port of the VLAN is running."""
        return vlan.flood_pkt(
            valve_packet.arp_request,
            self.multi_out,
            vlan.faucet_mac,
            valve_of.mac.BROADCAST_STR,
            self.ARP_PROBE_SPA.network_address,
            extra_ip,
        )

    def _extra_ip_set_state(self, vlan, extra_ip, state, new_state, now):
        """Move one of a VLAN's faucet_extra_ips to a new state, and report it."""
        state.state = new_state
        state.change_time = now
        self.logger.info(
            "VLAN %u faucet_extra_ips %s is now %s"
            % (vlan.vid, extra_ip, ExtraIPState.NAMES[new_state])
        )
        if self.set_var is None or self.inc_var is None:
            return
        labels = self._extra_ip_labels(vlan, extra_ip)
        self.set_var("vlan_extra_ip_state", new_state, labels)
        self.set_var("vlan_extra_ip_state_change_time", now, labels)
        self.inc_var("vlan_extra_ip_state_changes", labels)

    def _extra_ip_probe_due(self, vlan, extra_ip, state, now, live):
        """Return the probe due for one of a VLAN's faucet_extra_ips, if any,
        or the flows that answer for it, if FAUCET claims it now.

        FAUCET claims an address it is probing for, or holds, once a round of
        EXTRA_IP_PROBE_NUM probes has had no answer for EXTRA_IP_ANNOUNCE_WAIT
        seconds after the last (see _extra_ip_conflict() for an answer). A
        round goes on only while the switch is live (see extra_ips_due()). A
        claimed address is probed for once per neighbor timeout, so that a
        host that has taken it without probing answers, and is counted, but
        FAUCET never gives it up.
        """
        if state.next_time is not None and now < state.next_time:
            return []
        if state.state == ExtraIPState.CLAIMED:
            ofmsgs = self._extra_ip_probe(vlan, extra_ip)
            if ofmsgs:
                state.next_time = now + self.neighbor_timeout
            return ofmsgs
        if not live:
            return []
        if state.probes == self.EXTRA_IP_PROBE_NUM:
            state.probes = 0
            state.next_time = now + self.neighbor_timeout
            self._extra_ip_set_state(vlan, extra_ip, state, ExtraIPState.CLAIMED, now)
            return self._extra_ip_answers(vlan, extra_ip)
        ofmsgs = self._extra_ip_probe(vlan, extra_ip)
        if ofmsgs:
            state.probes += 1
            state.next_time = now + self.EXTRA_IP_PROBE_INTERVAL
            if state.probes == self.EXTRA_IP_PROBE_NUM:
                state.next_time = now + self.EXTRA_IP_ANNOUNCE_WAIT
        return ofmsgs

    def extra_ips_due(self, vlan, now, live=True):
        """Return the ARP and flows due for a VLAN's faucet_extra_ips.

        FAUCET probes for each address before the switch answers for it, and
        claims it if no other host answers (see _extra_ip_probe_due()). Faucet
        announces each address it has claimed that it has not announced, as
        when it claims it or the switch cold starts, with a gratuitous ARP
        request and reply, flooded with faucet_mac. It also sends an ARP
        request from the address to each route gateway in its subnet, once
        the gateway's MAC is known, and again once per neighbor timeout, since
        a host records the sender of a request to it (RFC 826) whether or not
        it heeds gratuitous ARP. At most EXTRA_IP_ANNOUNCE_PER_CYCLE addresses
        of a VLAN send any of these in one call, the rest in later ones.

        Args:
            vlan (VLAN): the VLAN that lists them.
            now (float): seconds since epoch.
            live (bool): True if the switch has sent a packet in since its last
                cold start: until then, answers to probes could be lost.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        sent = 0
        for extra_ip in sorted(vlan.faucet_extra_ips):
            if sent == self.EXTRA_IP_ANNOUNCE_PER_CYCLE:
                break
            state = vlan.dyn_extra_ip_state.get(extra_ip, None)
            if state is None:
                # The VLAN has not been added to the switch.
                continue
            extra_ip_ofmsgs = self._extra_ip_probe_due(vlan, extra_ip, state, now, live)
            if state.state == ExtraIPState.CLAIMED:
                extra_ip_ofmsgs.extend(self._extra_ip_announce(vlan, extra_ip, now))
            if extra_ip_ofmsgs:
                sent += 1
                ofmsgs.extend(extra_ip_ofmsgs)
        return ofmsgs

    def _add_faucet_vip_nd(self, vlan, priority, faucet_vip, faucet_vip_host):
        ofmsgs = []
        # ARP
        ofmsgs.extend(
            self.pipeline.select_packets(
                self.vip_table, {"eth_type": valve_of.ether.ETH_TYPE_ARP, "vlan": vlan}
            )
        )
        if self.arp_responder and self._arp_responder_answers(faucet_vip):
            # ARP request for FAUCET VIP from its subnet, answered by the switch.
            # The per-port flows are added with the VLAN, not with the port, as
            # a warm start that moves a port between VLANs deletes and adds both
            # VLANs without restarting their other ports.
            ofmsgs.append(self._arp_responder(vlan, faucet_vip, faucet_vip_host))
            for port in vlan.untagged:
                if port.running():
                    ofmsgs.append(
                        self._arp_responder(vlan, faucet_vip, faucet_vip_host, port)
                    )
        # ARP for FAUCET VIP
        ofmsgs.append(
            self.vip_table.flowcontroller(
                self.vip_table.match(
                    eth_type=valve_of.ether.ETH_TYPE_ARP,
                    eth_dst=valve_of.mac.BROADCAST_STR,
                    nw_dst=faucet_vip_host,
                ),
                priority=priority,
                max_len=valve_packet.VLAN_ARP_PKT_SIZE,
            )
        )
        # ARP reply to FAUCET VIP
        ofmsgs.append(
            self.vip_table.flowcontroller(
                self.vip_table.match(
                    eth_type=valve_of.ether.ETH_TYPE_ARP, eth_dst=vlan.faucet_mac
                ),
                priority=priority,
                max_len=valve_packet.VLAN_ARP_PKT_SIZE,
            )
        )
        priority -= 1
        # Other ARP
        ofmsgs.append(
            self.vip_table.flowmod(
                self.vip_table.match(eth_type=valve_of.ether.ETH_TYPE_ARP),
                priority=priority,
                inst=self.pipeline.accept_to_l2_forwarding(),
            )
        )
        return ofmsgs

    def del_vlan(self, vlan, dp_vlan_refs):
        """Delete a VLAN."""
        ofmsgs = super().del_vlan(vlan, dp_vlan_refs)
        if not vlan.faucet_vips_by_ipv(self.IPV):
            return ofmsgs

        _, _, _, dp_faucet_vip_hosts = dp_vlan_refs

        for faucet_vip in vlan.faucet_vips_by_ipv(self.IPV):
            faucet_vip_host = self._host_from_faucet_vip(faucet_vip)
            if faucet_vip_host not in dp_faucet_vip_hosts:
                # Remove ARP for FAUCET VIP flow
                ofmsgs.append(
                    self.vip_table.flowdel(
                        match=self.vip_table.match(
                            eth_type=valve_of.ether.ETH_TYPE_ARP,
                            eth_dst=valve_of.mac.BROADCAST_STR,
                            nw_dst=faucet_vip_host,
                        ),
                    )
                )
        if self.arp_responder:
            # The ARP responder flows match the VLAN, so no other VLAN uses them.
            ofmsgs.append(self.vip_table.flowdel(match=self.vip_table.match(vlan=vlan)))
            # Nor those of its faucet_extra_ips that match no VLAN.
            for extra_ip in sorted(vlan.faucet_extra_ips):
                ofmsgs.extend(self._extra_ip_unvlanned_deletes(extra_ip))
        return ofmsgs

    def del_port(self, port):
        """Delete the ARP responder flows of a port untagged on a routed VLAN.

        Each flow is deleted strictly, as it was added, so that a warm start
        that deletes and adds back a port that stays on its VLAN, as changing
        the port does, replaces the flow in place: the add supersedes a delete
        with the same match and priority. Deleted by in_port instead, the flow
        would be gone from the delete until the add, while the port's flows in
        earlier tables, which are deleted later or replaced in place, still let
        its requests through, and the VLAN's own flow would answer them tagged.
        """
        vlan = port.native_vlan
        ofmsgs = []
        if not self.arp_responder or vlan is None:
            return ofmsgs
        for faucet_vip in vlan.faucet_vips_by_ipv(self.IPV):
            if self._arp_responder_answers(faucet_vip):
                match, priority = self._arp_responder_match(
                    vlan, faucet_vip, self._host_from_faucet_vip(faucet_vip), port
                )
                ofmsgs.append(
                    self.vip_table.flowdel(match=match, priority=priority, strict=True)
                )
        for extra_ip in sorted(vlan.faucet_extra_ips):
            ofmsgs.extend(self._extra_ip_port_deletes(vlan, extra_ip, port))
        return ofmsgs

    def _add_host_fib_route_from_reply(self, now, pkt_meta):
        """Add a host FIB route given an ARP reply that changed no routes.

        An ARP request for a VIP adds the host's route, and so does an IPv6
        advert that changes no routes, as Valve.router_rcv_packet adds it from
        the advert's IP header and then runs the resolvers once more. An ARP
        reply has no IP header, so do both here, or a host that only replies,
        such as one whose route was expired with its port, is not routed again.
        """
        ofmsgs = []
        vlan = pkt_meta.vlan
        src_ip = pkt_meta.l3_src
        if vlan.ip_in_vip_subnet(src_ip) and self._stateful_gw(vlan, src_ip):
            ofmsgs.extend(self._add_host_fib_route(vlan, src_ip, blackhole=False))
            ofmsgs.extend(
                self._update_nexthop(now, vlan, pkt_meta.port, pkt_meta.eth_src, src_ip)
            )
        if ofmsgs:
            ofmsgs.extend(self.resolve_gateways(vlan, now, resolve_all=False))
            ofmsgs.extend(self.resolve_expire_hosts(vlan, now, resolve_all=False))
        return ofmsgs

    def _extra_ip_log_due(self, now, vlan, extra_ip, kind):
        """Return True if ARP of a kind about one of a VLAN's faucet_extra_ips
        is to be logged: once per neighbor timeout."""
        key = (vlan.vid, extra_ip, kind)
        last_time = self.extra_ip_log_times.get(key, None)
        if last_time is not None and now - last_time < self.neighbor_timeout:
            return False
        self.extra_ip_log_times[key] = now
        return True

    def _extra_ip_conflict(self, now, vlan, extra_ip):
        """Hold back from one of a VLAN's faucet_extra_ips that another host
        uses, unless FAUCET has claimed it.

        FAUCET probes for a held address again once it has heard nothing from
        the other host for the back-off. That starts at EXTRA_IP_HOLD_MIN, and
        doubles, up to EXTRA_IP_HOLD_MAX, each time the other host answers a
        round of probes.
        """
        state = vlan.dyn_extra_ip_state.get(extra_ip, None)
        if state is None or state.state == ExtraIPState.CLAIMED:
            return
        if state.state == ExtraIPState.PROBING:
            state.backoff = self.EXTRA_IP_HOLD_MIN
            self._extra_ip_set_state(vlan, extra_ip, state, ExtraIPState.HELD, now)
        elif state.probes:
            state.backoff = min(2 * state.backoff, self.EXTRA_IP_HOLD_MAX)
        state.probes = 0
        state.next_time = now + state.backoff

    def _extra_ip_arp(self, now, pkt_meta, arp_pkt):
        """Count ARP from another host using one of the VLAN's faucet_extra_ips.

        Such ARP has the address as its sender, and is counted and logged
        with the host's MAC and port. FAUCET holds back from the address if
        it has not claimed it yet, as it does if another host probes for it,
        which is logged too, but never gives up one it has claimed (see
        _extra_ip_conflict()). ARP from faucet_mac is another datapath's,
        announcing the same address, and is ignored.

        Faucet handles only ARP to faucet_mac or a multicast address (see
        Valve._control_plane_handler()), so the other host's ARP to other
        hosts is counted only in the packet counts of the switch's flows for
        ARP from the address (see _extra_ip_sender_matches()).
        """
        vlan = pkt_meta.vlan
        if vlan.faucet_mac in (pkt_meta.eth_src, arp_pkt.src_mac):
            return
        if vlan.is_extra_ip(pkt_meta.l3_src):
            extra_ip = pkt_meta.l3_src
            if self.inc_var is not None:
                self.inc_var(
                    "vlan_extra_ip_foreign_arp", self._extra_ip_labels(vlan, extra_ip)
                )
            if self._extra_ip_log_due(now, vlan, extra_ip, "foreign"):
                self.logger.warning(
                    "%s on %s sent ARP from %s, which VLAN %u lists in faucet_extra_ips"
                    % (pkt_meta.eth_src, pkt_meta.port, extra_ip, vlan.vid)
                )
            self._extra_ip_conflict(now, vlan, extra_ip)
        elif (
            arp_pkt.opcode == arp.ARP_REQUEST
            and pkt_meta.l3_src == self.ARP_PROBE_SPA.network_address
            and vlan.is_extra_ip(pkt_meta.l3_dst)
        ):
            extra_ip = pkt_meta.l3_dst
            if self._extra_ip_log_due(now, vlan, extra_ip, "probe"):
                self.logger.info(
                    "%s on %s probed for %s, which VLAN %u lists in faucet_extra_ips"
                    % (pkt_meta.eth_src, pkt_meta.port, extra_ip, vlan.vid)
                )
            self._extra_ip_conflict(now, vlan, extra_ip)

    def _control_plane_arp_handler(self, now, pkt_meta):
        """Handle ARP packets destined for the router"""
        ofmsgs = []
        if not pkt_meta.eth_type == valve_of.ether.ETH_TYPE_ARP:
            return ofmsgs
        arp_pkt = pkt_meta.pkt.get_protocol(arp.arp)
        if arp_pkt is None:
            return ofmsgs
        self._extra_ip_arp(now, pkt_meta, arp_pkt)
        opcode = arp_pkt.opcode
        if opcode == arp.ARP_REQUEST:
            if pkt_meta.eth_dst in (
                valve_of.mac.BROADCAST_STR,
                pkt_meta.vlan.faucet_mac,
            ):
                ofmsgs.extend(
                    self._resolve_vip_response(pkt_meta, pkt_meta.l3_dst, now)
                )
        elif opcode == arp.ARP_REPLY:
            if pkt_meta.eth_dst == pkt_meta.vlan.faucet_mac:
                ofmsgs.extend(self._gw_advert(pkt_meta, pkt_meta.l3_src, now))
                if not ofmsgs:
                    ofmsgs.extend(self._add_host_fib_route_from_reply(now, pkt_meta))
        self.notify_learn(pkt_meta)
        return ofmsgs

    def _control_plane_icmp_handler(self, now, pkt_meta, ipv4_pkt):
        """Handle ICMP packets destined for the router"""
        ofmsgs = []
        if ipv4_pkt.proto != valve_of.inet.IPPROTO_ICMP:
            return ofmsgs
        if self._unicast_to_vip(pkt_meta):
            pkt_meta.reparse_all()
            icmp_pkt = pkt_meta.pkt.get_protocol(icmp.icmp)
            if icmp_pkt is None:
                return ofmsgs
            if icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                ofmsgs.append(
                    pkt_meta.vlan.pkt_out_port(
                        valve_packet.echo_reply,
                        pkt_meta.port,
                        pkt_meta.vlan.faucet_mac,
                        pkt_meta.eth_src,
                        pkt_meta.l3_dst,
                        pkt_meta.l3_src,
                        icmp_pkt.data,
                    )
                )
                # ping but no previous ARP request for FAUCET VIP
                # from this host. Missed ARP request or host has
                # static ARP entry for us?
                if self._cached_nexthop_eth_dst(pkt_meta.vlan, pkt_meta.l3_src) is None:
                    ofmsgs.extend(self.add_host_fib_route_from_pkt(now, pkt_meta))
        return ofmsgs

    def _control_plane_time_exceeded_handler(self, pkt_meta, ipv4_pkt):
        """Handle ICMP TTL expired packets"""
        ofmsgs = []
        src_ip = pkt_meta.l3_src
        vlan = pkt_meta.vlan
        faucet_vip = vlan.ip_in_vip_subnet(src_ip)
        if faucet_vip is None:
            return ofmsgs
        pkt_meta.reparse_all()
        # get offset to L3 header
        l3_offset = pkt_meta.l3_offset()
        if l3_offset is None:
            return ofmsgs
        l4_offset = l3_offset + valve_packet.IPV4_HEADER_SIZE
        # need to embed layer 3 header + 8 bytes of layer 4 header in time exceeded response
        data = pkt_meta.pkt.data[l3_offset : l4_offset + 8]
        ofmsgs.append(
            pkt_meta.vlan.pkt_out_port(
                valve_packet.time_exceeded,
                pkt_meta.port,
                pkt_meta.vlan.faucet_mac,
                pkt_meta.eth_src,
                faucet_vip.ip,
                pkt_meta.l3_src,
                data,
            )
        )
        return ofmsgs

    def control_plane_handler(self, now, pkt_meta):
        """Handle packets destined for router otherwise proactively learn host information"""
        if pkt_meta.packet_complete():
            arp_replies = self._control_plane_arp_handler(now, pkt_meta)
            if arp_replies:
                return arp_replies
            ipv4_pkt = self._ip_pkt(pkt_meta.pkt)
            if ipv4_pkt is None:
                return []
            if pkt_meta.reason == valve_of.ofp.OFPR_INVALID_TTL:
                time_exceeded_replies = self._control_plane_time_exceeded_handler(
                    pkt_meta, ipv4_pkt
                )
                if time_exceeded_replies:
                    return time_exceeded_replies
                return []
            icmp_replies = self._control_plane_icmp_handler(now, pkt_meta, ipv4_pkt)
            if icmp_replies:
                return icmp_replies
        return super().control_plane_handler(now, pkt_meta)


class ValveIPv6RouteManager(ValveRouteManager):
    """Implement IPv6 FIB."""

    IPV = 6
    ETH_TYPE = valve_of.ether.ETH_TYPE_IPV6
    ICMP_TYPE = valve_of.inet.IPPROTO_ICMPV6
    ICMP_SIZE = valve_packet.VLAN_ICMP6_ECHO_REQ_SIZE
    CONTROL_ETH_TYPES = (valve_of.ether.ETH_TYPE_IPV6,)  # type: ignore
    IP_PKT = ipv6.ipv6

    @staticmethod
    def _gw_resolve_pkt():
        return valve_packet.nd_request

    @staticmethod
    def _gw_respond_pkt():
        return valve_packet.nd_advert

    def _vlan_nexthop_cache_limit(self, vlan):
        return vlan.proactive_nd_limit

    def _add_faucet_vip_nd(self, vlan, priority, faucet_vip, faucet_vip_host):
        faucet_vip_host_nd_mcast = valve_packet.ipv6_link_eth_mcast(
            valve_packet.ipv6_solicited_node_from_ucast(faucet_vip.ip)
        )
        ofmsgs = []
        # RA if this is a link local FAUCET VIP
        if faucet_vip.ip.is_link_local:
            match = {
                "eth_type": self.ETH_TYPE,
                "eth_dst": valve_packet.IPV6_ALL_ROUTERS_MCAST,
                "vlan": vlan,
            }
            ofmsgs.extend(self.pipeline.select_packets(self.vip_table, match))
            ofmsgs.append(
                self.vip_table.flowmod(
                    self.vip_table.match(
                        eth_type=self.ETH_TYPE,
                        eth_dst=valve_packet.IPV6_ALL_ROUTERS_MCAST,
                        nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                        icmpv6_type=icmpv6.ND_ROUTER_SOLICIT,
                    ),
                    priority=priority,
                    inst=self._controller_and_flood(),
                )
            )
        # IPv6 ping unicast to FAUCET
        ofmsgs.append(
            self.vip_table.flowcontroller(
                self.vip_table.match(
                    eth_type=self.ETH_TYPE,
                    eth_dst=vlan.faucet_mac,
                    nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                    icmpv6_type=icmpv6.ICMPV6_ECHO_REQUEST,
                ),
                priority=priority,
                max_len=self.ICMP_SIZE,
            )
        )
        # IPv6 NA unicast to FAUCET.
        ofmsgs.append(
            self.vip_table.flowcontroller(
                self.vip_table.match(
                    eth_type=self.ETH_TYPE,
                    eth_dst=vlan.faucet_mac,
                    nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                    icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT,
                ),
                priority=priority,
                max_len=self.ICMP_SIZE,
            )
        )
        # IPv6 NS for FAUCET VIP
        match = {
            "eth_type": self.ETH_TYPE,
            "eth_dst": faucet_vip_host_nd_mcast,
            "vlan": vlan,
        }
        ofmsgs.extend(self.pipeline.select_packets(self.vip_table, match))
        ofmsgs.append(
            self.vip_table.flowmod(
                self.vip_table.match(
                    eth_type=self.ETH_TYPE,
                    eth_dst=faucet_vip_host_nd_mcast,
                    nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                    icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT,
                ),
                priority=priority,
                inst=self._controller_and_flood(),
            )
        )
        return ofmsgs

    def _add_faucet_fib_to_vip(self, vlan, priority, faucet_vip, faucet_vip_host):
        ofmsgs = super()._add_faucet_fib_to_vip(
            vlan, priority, faucet_vip, faucet_vip_host
        )
        faucet_vip_broadcast = ipaddress.IPv6Interface(
            faucet_vip.network.broadcast_address
        )
        if self.global_routing:
            vlan = self.global_vlan
        ofmsgs.append(
            self.fib_table.flowmod(
                self._route_match(vlan, faucet_vip_broadcast),
                priority=priority,
                inst=(self.fib_table.goto(self.vip_table),),
            )
        )
        return ofmsgs

    def dp_vlan_refs(self, dp_vlans):
        """Return FAUCET MACs, VIPs, VIP hosts, VIP ND multicast MACs
        and VIP broadcasts in use by VLANs on the DP."""
        dp_mcast_macs = set()
        dp_faucet_vip_broadcasts = set()
        dp_link_local_present = False
        for dp_vlan in dp_vlans:
            for faucet_vip in dp_vlan.faucet_vips_by_ipv(self.IPV):
                if faucet_vip.is_link_local:
                    dp_link_local_present = True
                faucet_vip_host_nd_mcast = valve_packet.ipv6_link_eth_mcast(
                    valve_packet.ipv6_solicited_node_from_ucast(faucet_vip.ip)
                )
                dp_mcast_macs.add(faucet_vip_host_nd_mcast)
                if self.global_routing:
                    faucet_vip_broadcast = ipaddress.IPv6Interface(
                        faucet_vip.network.broadcast_address
                    )
                    dp_faucet_vip_broadcasts.add(faucet_vip_broadcast)
        return (
            super().dp_vlan_refs(dp_vlans),
            dp_mcast_macs,
            dp_faucet_vip_broadcasts,
            dp_link_local_present,
        )

    def del_vlan(self, vlan, dp_vlan_refs):
        """Delete a VLAN."""
        (
            route_refs,
            dp_mcast_macs,
            dp_faucet_vip_broadcasts,
            dp_link_local_present,
        ) = dp_vlan_refs
        ofmsgs = super().del_vlan(vlan, route_refs)
        if not vlan.faucet_vips_by_ipv(self.IPV):
            return ofmsgs

        if not dp_link_local_present:
            # No link local FAUCET VIPs present on any VLAN on DP
            ofmsgs.append(
                self.vip_table.flowdel(
                    match=self.vip_table.match(
                        eth_type=self.ETH_TYPE,
                        eth_dst=valve_packet.IPV6_ALL_ROUTERS_MCAST,
                        nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                        icmpv6_type=icmpv6.ND_ROUTER_SOLICIT,
                    ),
                )
            )

        for faucet_vip in vlan.faucet_vips_by_ipv(self.IPV):
            faucet_vip_host_nd_mcast = valve_packet.ipv6_link_eth_mcast(
                valve_packet.ipv6_solicited_node_from_ucast(faucet_vip.ip)
            )
            if faucet_vip_host_nd_mcast not in dp_mcast_macs:
                # Remove IPv6 NS for FAUCET VIP flow
                ofmsgs.append(
                    self.vip_table.flowdel(
                        match=self.vip_table.match(
                            eth_type=self.ETH_TYPE,
                            eth_dst=faucet_vip_host_nd_mcast,
                            nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                            icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT,
                        ),
                    )
                )
            if self.global_routing:
                faucet_vip_broadcast = ipaddress.IPv6Interface(
                    faucet_vip.network.broadcast_address
                )
                if faucet_vip_broadcast not in dp_faucet_vip_broadcasts:
                    # FAUCET VIP broadcast route no longer in use on DP
                    ofmsgs.append(
                        self.fib_table.flowdel(
                            match=self._route_match(
                                self.global_vlan, faucet_vip_broadcast
                            ),
                        )
                    )
        return ofmsgs

    def _nd_solicit_handler(self, now, pkt_meta, _ipv6_pkt, icmpv6_pkt):
        ofmsgs = []
        solicited_ip = ipaddress.ip_address(icmpv6_pkt.data.dst)
        ofmsgs.extend(self._resolve_vip_response(pkt_meta, solicited_ip, now))
        self.notify_learn(pkt_meta)
        return ofmsgs

    def _nd_advert_handler(self, now, pkt_meta, _ipv6_pkt, icmpv6_pkt):
        ofmsgs = []
        target_ip = ipaddress.ip_address(icmpv6_pkt.data.dst)
        ofmsgs.extend(self._gw_advert(pkt_meta, target_ip, now))
        self.notify_learn(pkt_meta)
        return ofmsgs

    def _router_solicit_handler(self, _now, pkt_meta, _ipv6_pkt, _icmpv6_pkt):
        ofmsgs = []
        link_local_vips, other_vips = pkt_meta.vlan.link_and_other_vips(self.IPV)
        for vip in link_local_vips:
            if pkt_meta.l3_src in vip.network:
                ofmsgs.append(
                    pkt_meta.vlan.pkt_out_port(
                        valve_packet.router_advert,
                        pkt_meta.port,
                        pkt_meta.vlan.faucet_mac,
                        pkt_meta.eth_src,
                        vip.ip,
                        pkt_meta.l3_src,
                        other_vips,
                    )
                )
                self.logger.info(
                    "Responded to RS solicit from %s (%s)"
                    % (pkt_meta.l3_src, pkt_meta.log())
                )
                break
        return ofmsgs

    def _echo_request_handler(self, now, pkt_meta, ipv6_pkt, icmpv6_pkt):
        ofmsgs = []
        if self._unicast_to_vip(pkt_meta):
            ofmsgs.append(
                pkt_meta.vlan.pkt_out_port(
                    valve_packet.icmpv6_echo_reply,
                    pkt_meta.port,
                    pkt_meta.vlan.faucet_mac,
                    pkt_meta.eth_src,
                    pkt_meta.l3_dst,
                    pkt_meta.l3_src,
                    ipv6_pkt.hop_limit,
                    icmpv6_pkt.data.id,
                    icmpv6_pkt.data.seq,
                    icmpv6_pkt.data.data,
                )
            )
            # ping but no previous ND request for FAUCET VIP
            # from this host. Missed ND request or host has
            # static ND entry for us?
            if self._cached_nexthop_eth_dst(pkt_meta.vlan, pkt_meta.l3_src) is None:
                ofmsgs.extend(self.add_host_fib_route_from_pkt(now, pkt_meta))
        return ofmsgs

    _icmpv6_handlers = {
        icmpv6.ND_NEIGHBOR_SOLICIT: (_nd_solicit_handler, icmpv6.nd_neighbor, 32),
        icmpv6.ND_NEIGHBOR_ADVERT: (_nd_advert_handler, icmpv6.nd_neighbor, 32),
        icmpv6.ND_ROUTER_SOLICIT: (_router_solicit_handler, None, 32),
        icmpv6.ICMPV6_ECHO_REQUEST: (_echo_request_handler, icmpv6.echo, 96),
    }

    def _control_plane_icmpv6_handler(self, now, pkt_meta, ipv6_pkt):
        """Handle ICMPv6 packets destined for router"""
        ofmsgs = []
        # Must be ICMPv6 and have no extended headers.
        if ipv6_pkt.nxt != valve_of.inet.IPPROTO_ICMPV6:
            return ofmsgs
        if ipv6_pkt.ext_hdrs:
            return ofmsgs
        src_ip = pkt_meta.l3_src
        vlan = pkt_meta.vlan
        if not vlan.ip_in_vip_subnet(src_ip):
            return ofmsgs
        reparse_size = 32
        pkt_meta.reparse_ip(payload=reparse_size)
        icmpv6_pkt = pkt_meta.pkt.get_protocol(icmpv6.icmpv6)
        if icmpv6_pkt is None:
            return ofmsgs
        icmpv6_type = icmpv6_pkt.type_
        if (
            ipv6_pkt.hop_limit != valve_packet.IPV6_MAX_HOP_LIM
            and icmpv6_type != icmpv6.ICMPV6_ECHO_REQUEST
        ):
            return ofmsgs
        handler, payload_type, type_reparse_size = self._icmpv6_handlers.get(
            icmpv6_type, (None, None, None)
        )
        if handler is not None and (
            payload_type is None or isinstance(icmpv6_pkt.data, payload_type)
        ):
            if type_reparse_size != reparse_size:
                pkt_meta.reparse_ip(payload=type_reparse_size)
                icmpv6_pkt = pkt_meta.pkt.get_protocol(icmpv6.icmpv6)
            ofmsgs = handler(self, now, pkt_meta, ipv6_pkt, icmpv6_pkt)
        return ofmsgs

    def _control_plane_time_exceeded_handler(self, pkt_meta, ipv6_pkt):
        """Handle ICMPv6 TTL expired packets"""
        ofmsgs = []
        # Must have no extended headers.
        if ipv6_pkt.ext_hdrs:
            return ofmsgs
        src_ip = pkt_meta.l3_src
        vlan = pkt_meta.vlan
        faucet_vip = vlan.ip_in_vip_subnet(src_ip)
        if faucet_vip is None:
            return ofmsgs
        reparse_size = 32
        pkt_meta.reparse_ip(payload=reparse_size)
        # get offset to L3 header
        l3_offset = pkt_meta.l3_offset()
        if l3_offset is None:
            return ofmsgs
        l4_offset = l3_offset + valve_packet.IPV6_HEADER_SIZE
        # pad out 4 reserved bytes
        data = b"\00" * 4
        # need to embed layer 3 header + layer 4 packet
        # (without exceeding ipv6 minimum MTU)
        # in time exceeded response
        data += pkt_meta.pkt.data[l3_offset : l4_offset + 512]
        ofmsgs.append(
            pkt_meta.vlan.pkt_out_port(
                valve_packet.icmpv6_time_exceeded,
                pkt_meta.port,
                pkt_meta.vlan.faucet_mac,
                pkt_meta.eth_src,
                faucet_vip.ip,
                pkt_meta.l3_src,
                data,
            )
        )
        return ofmsgs

    def control_plane_handler(self, now, pkt_meta):
        """Resolve packets destined for router or proactively learn host information"""
        if pkt_meta.packet_complete():
            ipv6_pkt = self._ip_pkt(pkt_meta.pkt)
            if ipv6_pkt is None:
                return []
            if pkt_meta.reason == valve_of.ofp.OFPR_INVALID_TTL:
                time_exceeded_replies = self._control_plane_time_exceeded_handler(
                    pkt_meta, ipv6_pkt
                )
                if time_exceeded_replies:
                    return time_exceeded_replies
                return []
            icmp_replies = self._control_plane_icmpv6_handler(now, pkt_meta, ipv6_pkt)
            if icmp_replies:
                return icmp_replies
        return super().control_plane_handler(now, pkt_meta)

    def advertise(self, vlan):
        ofmsgs = []
        link_local_vips, other_vips = vlan.link_and_other_vips(self.IPV)
        for link_local_vip in link_local_vips:
            # https://tools.ietf.org/html/rfc4861#section-6.1.2
            ofmsgs.extend(
                vlan.flood_pkt(
                    valve_packet.router_advert,
                    self.multi_out,
                    vlan.faucet_mac,
                    valve_packet.IPV6_ALL_NODES_MCAST,
                    link_local_vip.ip,
                    valve_packet.IPV6_ALL_NODES,
                    other_vips,
                )
            )
        return ofmsgs
