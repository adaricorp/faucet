#!/usr/bin/env python3

"""Warm reload of a routed VLAN: the new VLAN caches nothing whose flows are gone."""

import unittest

from os_ken.ofproto import ofproto_v1_3 as ofp

from clib.fakeoftable import CONTROLLER_PORT
from clib.valve_test_lib import FAUCET_MAC, ValveTestBases
from faucet import config_parser_util


class ValveWarmVlanCacheTestCase(ValveTestBases.ValveTestNetwork):
    """A host or neighbour cached by a VLAN after a warm reload still has its flows."""

    REQUIRE_TFM = False

    CONFIG = """
vlans:
    v100:
        vid: 0x100
        faucet_vips: ["10.0.0.254/24"]
    v200:
        vid: 0x200
        faucet_vips: ["10.0.1.254/24"]
routers:
    r1:
        vlans: [v100, v200]
dps:
    s1:
        dp_id: 1
        hardware: Open vSwitch
        ignore_learn_ins: 0
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
            p3:
                number: 3
                native_vlan: v100
"""

    HOSTS = (
        (1, 0x100, "10.0.0.1"),
        (3, 0x100, "10.0.0.3"),
        (2, 0x200, "10.0.1.2"),
    )

    def setUp(self):
        self.extra_hosts = ()
        self.setup_valves(self.CONFIG)
        for port in (1, 2, 3):
            self.set_port_up(port)
        for port, vid, host_ip in self.HOSTS:
            self._arp(port, vid, host_ip)
        for port, vid, _ in self.HOSTS:
            self.assertTrue(self._learned(port, vid), (port, vid))
        self.assertTrue(self._vlan(0x100).dyn_neigh_cache_by_ipv[4])

    @staticmethod
    def _mac(port):
        return "00:00:00:00:%02x:%02x" % (port, port)

    def _valve(self):
        return self.valves_manager.valves[self.DP_ID]

    def _vlan(self, vid):
        return self._valve().dp.vlans[vid]

    def _arp(self, port, vid, host_ip):
        gateway = {0x100: "10.0.0.254", 0x200: "10.0.1.254", 0x300: "10.0.3.254"}[vid]
        self.rcv_packet(
            port,
            vid,
            {
                "eth_src": self._mac(port),
                "eth_dst": self.BROADCAST_MAC,
                "arp_source_ip": host_ip,
                "arp_target_ip": gateway,
            },
        )

    def _learned(self, port, vid):
        """The host has an eth_src flow and its unknown-destination IP is not punted."""
        table = self.network.tables[self.DP_ID]
        match = {
            "in_port": port,
            "vlan_vid": 0,
            "eth_src": self._mac(port),
            "eth_dst": self.UNKNOWN_MAC,
            "eth_type": 0x800,
            "ipv4_src": "10.0.%u.%u" % (0 if vid == 0x100 else 1, port),
            "ipv4_dst": "10.0.%u.99" % (0 if vid == 0x100 else 1),
        }
        flow = table.single_table_lookup(
            dict(match, vlan_vid=vid | ofp.OFPVID_PRESENT),
            self._valve().dp.tables["eth_src"].table_id,
        )
        return (
            flow is not None
            and "eth_src" in flow.match_values
            and not table.is_output(match, port=CONTROLLER_PORT)
        )

    def _routed_to(self, host_ip):
        """A packet routed from the other VLAN reaches the host's port, not the controller."""
        hosts = self.HOSTS + self.extra_hosts
        by_ip = {h_ip: (port, vid) for port, vid, h_ip in hosts}
        port, vid = by_ip[host_ip]
        routed_with = set()
        for router in self._valve().dp.routers.values():
            vids = {vlan.vid for vlan in router.vlans}
            if vid in vids:
                routed_with |= vids - {vid}
        src_port, _, src_ip = next(h for h in hosts if h[1] in routed_with)
        table = self.network.tables[self.DP_ID]
        match = {
            "in_port": src_port,
            "vlan_vid": 0,
            "eth_src": self._mac(src_port),
            "eth_dst": FAUCET_MAC,
            "eth_type": 0x800,
            "ipv4_src": src_ip,
            "ipv4_dst": host_ip,
        }
        return table.is_output(match, port=port) and not table.is_output(
            match, port=CONTROLLER_PORT
        )

    def _check_caches_have_flows(self, vid):
        """Every host the VLAN caches has its eth_src flow; every neighbour, its route."""
        vlan = self._vlan(vid)
        for entry in vlan.dyn_host_cache.values():
            msg = "VLAN %x caches %s on port %u but its flows are gone" % (
                vid,
                entry.eth_src,
                entry.port.number,
            )
            self.assertTrue(self._learned(entry.port.number, vid), msg)
        for host_ip in vlan.dyn_neigh_cache_by_ipv[4]:
            msg = "VLAN %x caches neighbour %s but traffic routed to it is punted" % (
                vid,
                host_ip,
            )
            self.assertTrue(self._routed_to(str(host_ip)), msg)

    def _reload(self, edit, reload_type="warm"):
        config = config_parser_util.yaml_load(self.CONFIG)
        edit(config)
        old_ports = set(self._valve().dp.ports)
        self.update_config(
            config_parser_util.yaml_dump(config), reload_type=reload_type
        )
        # Only a port the new config added gets a port status, as on a real
        # warm start. A status on every port would refresh its
        # dyn_update_time, so a host cached with its flows gone would be
        # learned over and the re-learning check below could not fail.
        for port in self._valve().dp.ports:
            if port not in old_ports:
                self.set_port_up(port)

    def _verify_after(self, changed_vids=(0x100,)):
        for port, vid, host_ip in self.extra_hosts:
            self._arp(port, vid, host_ip)
        for vid in (0x100, 0x200):
            self._check_caches_have_flows(vid)
        # Every host is learned again from its next packet.
        for port, vid, host_ip in self.HOSTS:
            self._arp(port, vid, host_ip)
        for port, vid, _ in self.HOSTS:
            self.assertTrue(self._learned(port, vid), (port, vid))
        for vid in changed_vids:
            self.assertTrue(self._vlan(vid).dyn_neigh_cache_by_ipv[4], vid)

    def test_ports_only(self):
        """Control: v100 changed only through a port added to it."""

        def edit(config):
            config["dps"]["s1"]["interfaces"]["p4"] = {
                "number": 4,
                "native_vlan": "v100",
            }

        self._reload(edit)
        self._verify_after()

    def test_vip_added(self):
        """v100's own config changed: a VIP added."""

        def edit(config):
            config["vlans"]["v100"]["faucet_vips"].append("10.0.2.254/24")

        self._reload(edit)
        self._verify_after()

    def test_route_added(self):
        """v100's own config changed: a static route added."""

        def edit(config):
            config["vlans"]["v100"]["routes"] = [
                {"route": {"ip_dst": "10.99.0.0/24", "ip_gw": "10.0.0.1"}}
            ]

        self._reload(edit)
        self._verify_after()

    def test_vlan_option_changed(self):
        """v100's own config changed: a VLAN option."""

        def edit(config):
            config["vlans"]["v100"]["max_hosts"] = 100

        self._reload(edit)
        self._verify_after()


class ValveWarmDot1xTestBase(ValveTestBases.ValveTestNetwork):
    """Port 3 is moved by 802.1X to DOT1X_VLAN, and has a host learned there.

    Conf.merge_dyn() copies an unchanged port's dyn_dot1x_native_vlan, so after
    a warm start port 3's VLAN is the previous config's object for that VID,
    while packets are learned on the running config's. Its hosts_count() and
    max_hosts read the held object.
    """

    REQUIRE_TFM = False
    CONFIG = None
    DOT1X_VLAN = None
    DOT1X_VID = None
    MAC_A = "0e:00:00:00:03:0a"
    MAC_B = "0e:00:00:00:03:0b"

    def setUp(self):
        self.setup_valves(self.CONFIG)
        valve = self._valve()
        for port in valve.dp.ports:
            self.set_port_up(port)
        self.apply_ofmsgs(valve.add_dot1x_native_vlan(3, self.DOT1X_VLAN))
        self._learn(1, 0x100, "0e:00:00:00:01:01")
        if 0x200 in valve.dp.vlans:
            self._learn(2, 0x200, "0e:00:00:00:02:02")
        self._learn(3, self.DOT1X_VID, self.MAC_A)
        self.assertTrue(self._learned(3, self.DOT1X_VID, self.MAC_A))
        self.assertIs(self._held(), valve.dp.vlans[self.DOT1X_VID])

    def _valve(self):
        return self.valves_manager.valves[self.DP_ID]

    def _held(self):
        """The VLAN object port 3 holds as its 802.1X native VLAN."""
        return self._valve().dp.ports[3].dyn_dot1x_native_vlan

    def _learn(self, port, vid, mac):
        self.rcv_packet(
            port,
            vid,
            {
                "eth_src": mac,
                "eth_dst": self.BROADCAST_MAC,
                "eth_type": 0x800,
                "ipv4_src": "0.0.0.0",
                "ipv4_dst": "255.255.255.255",
            },
        )

    def _learned(self, port, vid, mac):
        table = self.network.tables[self.DP_ID]
        match = {
            "in_port": port,
            "vlan_vid": 0,
            "eth_src": mac,
            "eth_dst": self.UNKNOWN_MAC,
            "eth_type": 0x800,
            "ipv4_src": "10.1.1.1",
            "ipv4_dst": "10.1.1.2",
        }
        flow = table.single_table_lookup(
            dict(match, vlan_vid=vid | ofp.OFPVID_PRESENT),
            self._valve().dp.tables["eth_src"].table_id,
        )
        return (
            flow is not None
            and "eth_src" in flow.match_values
            and not table.is_output(match, port=CONTROLLER_PORT)
        )

    def _reload(self, edit):
        config = config_parser_util.yaml_load(self.CONFIG)
        edit(config)
        old_ports = set(self._valve().dp.ports)
        self.update_config(config_parser_util.yaml_dump(config), reload_type="warm")
        for port in self._valve().dp.ports:
            if port not in old_ports:
                self.set_port_up(port)

    @staticmethod
    def _macs(vlan, port):
        return sorted(str(entry.eth_src) for entry in vlan.cached_hosts_on_port(port))

    def _check_port3_hosts_have_flows(self):
        port = self._valve().dp.ports[3]
        for vlan in port.vlans():
            for entry in vlan.cached_hosts_on_port(port):
                msg = "port 3 reports %s on VLAN %x but its flows are gone" % (
                    entry.eth_src,
                    vlan.vid,
                )
                self.assertTrue(self._learned(3, vlan.vid, str(entry.eth_src)), msg)


class ValveWarmDot1xVlanCacheTestCase(ValveWarmDot1xTestBase):
    """802.1X moved port 3 to v200, which a warm start changes."""

    CONFIG = """
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
dps:
    s1:
        dp_id: 1
        hardware: Open vSwitch
        ignore_learn_ins: 0
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
            p3:
                number: 3
                native_vlan: v100
                max_hosts: 1
"""
    DOT1X_VLAN = "v200"
    DOT1X_VID = 0x200

    @staticmethod
    def _ports_only(config):
        config["dps"]["s1"]["interfaces"]["p4"] = {"number": 4, "native_vlan": "v200"}

    @staticmethod
    def _own_config(config):
        config["vlans"]["v200"]["max_hosts"] = 100

    def test_dot1x_ports_only_hosts_have_flows(self):
        """v200 changed only through a port: port 3 reports no host whose flows are gone."""
        self._reload(self._ports_only)
        self._check_port3_hosts_have_flows()

    def test_dot1x_ports_only_relearn_max_hosts(self):
        """v200 changed only through a port: port 3 (max_hosts 1) learns its host again."""
        self._reload(self._ports_only)
        bans = self._valve().dp.ports[3].dyn_learn_ban_count
        self._learn(3, 0x200, self.MAC_A)
        self.assertEqual(
            bans,
            self._valve().dp.ports[3].dyn_learn_ban_count,
            "port 3 banned from learning its only host (max_hosts 1)",
        )
        self.assertTrue(
            self._learned(3, 0x200, self.MAC_A), "port 3's host not learned again"
        )

    def test_dot1x_ports_only_views_agree(self):
        """v200 changed only through a port: port 3's VLAN and the running one agree."""
        self._reload(self._ports_only)
        port = self._valve().dp.ports[3]
        self._learn(3, 0x200, self.MAC_A)
        self.assertEqual(
            self._macs(self._valve().dp.vlans[0x200], port),
            self._macs(self._held(), port),
            "port 3's VLAN object and the running VLAN disagree on its hosts",
        )

    def test_dot1x_own_config_hosts_have_flows(self):
        """v200's own config changed: port 3 reports no host whose flows are gone."""
        self._reload(self._own_config)
        self._check_port3_hosts_have_flows()


class ValveWarmDot1xDeletedVlanTestCase(ValveWarmDot1xTestBase):
    """802.1X moved port 3 to v300, which a warm start deletes."""

    CONFIG = """
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
    v300:
        vid: 0x300
dps:
    s1:
        dp_id: 1
        hardware: Open vSwitch
        ignore_learn_ins: 0
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
            p3:
                number: 3
                native_vlan: v100
                max_hosts: 1
            p5:
                number: 5
                native_vlan: v300
"""
    DOT1X_VLAN = "v300"
    DOT1X_VID = 0x300

    def test_dot1x_vlan_deleted_hosts_have_flows(self):
        """v300 deleted: port 3 reports no host on it, whose flows are gone."""

        def edit(config):
            del config["vlans"]["v300"]
            config["dps"]["s1"]["interfaces"]["p5"]["native_vlan"] = "v100"

        self._reload(edit)
        held = self._held()
        self.assertEqual(
            [],
            self._macs(held, self._valve().dp.ports[3]) if held is not None else [],
            "port 3 still reports hosts on the deleted VLAN, whose flows are gone",
        )


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
