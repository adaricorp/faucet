#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_warm_vlan_ports.py."""

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

import copy
import unittest
from ipaddress import ip_address
from types import SimpleNamespace

from os_ken.lib.packet import slow
from os_ken.ofproto import ofproto_v1_3 as ofp

from clib.valve_test_lib import FAUCET_MAC, ValveTestBases
from faucet import config_parser_util
from faucet import valve_of


class ValveWarmVLANPortsTestBase(ValveTestBases.ValveTestNetwork):
    """Warm start a change to the ports of routed VLANs, without relearning.

    An uplink with a default route and a static route via its gateway, a
    server VLAN, and two client VLANs on two trunks and an access port, each
    client VLAN routed with the uplink and with the servers. Uses Open
    vSwitch, so that adding a VLAN does not change the pipeline.
    """

    REQUIRE_TFM = False

    SWITCH_PORTS = tuple(range(1, 9))
    ROUTES = ("0.0.0.0/0", "10.99.0.0/24")

    # (port, VID): (MAC, IPv4 address) of each host learned. The uplink's
    # host is its gateway.
    HOSTS = {
        (1, 0x100): ("00:00:00:01:01:00", "10.0.0.1"),
        (2, 0x200): ("00:00:00:02:02:00", "10.2.0.1"),
        (3, 0x300): ("00:00:00:03:03:00", "10.11.0.3"),
        (3, 0x400): ("00:00:00:03:04:00", "10.12.0.3"),
        (4, 0x300): ("00:00:00:04:03:00", "10.11.0.4"),
        (4, 0x400): ("00:00:00:04:04:00", "10.12.0.4"),
        (5, 0x300): ("00:00:00:05:03:00", "10.11.0.5"),
    }
    VIPS = {
        0x100: "10.0.0.254",
        0x200: "10.2.0.254",
        0x300: "10.11.0.254",
        0x400: "10.12.0.254",
        0x500: "10.13.0.254",
    }
    CLIENTS = {"clients1": 0x300, "clients2": 0x400}

    def base_config(self):
        """Return the config as a dict."""
        vlans = {
            "uplink": {
                "vid": 0x100,
                "faucet_vips": ["10.0.0.254/24"],
                "faucet_mac": "0e:00:00:00:01:00",
                "routes": [
                    {"route": {"ip_dst": ip_dst, "ip_gw": "10.0.0.1"}}
                    for ip_dst in self.ROUTES
                ],
            },
            # A VLAN ACL here, so that a client VLAN gaining one does not
            # add the first, which changes the pipeline.
            "servers": {
                "vid": 0x200,
                "faucet_vips": ["10.2.0.254/24"],
                "faucet_mac": "0e:00:00:00:02:00",
                "acls_in": ["allow"],
            },
        }
        routers = {}
        for name, vid in self.CLIENTS.items():
            vlans[name] = {
                "vid": vid,
                "faucet_vips": ["%s/24" % self.VIPS[vid]],
                "faucet_mac": "0e:00:00:00:%02x:00" % (vid >> 8),
            }
            routers["%s-uplink" % name] = {"vlans": ["uplink", name]}
            routers["%s-servers" % name] = {"vlans": ["servers", name]}
        return {
            "acls": {
                "allow": [{"rule": {"actions": {"allow": 1}}}],
                "port-allow": [{"rule": {"actions": {"allow": 1}}}],
                "allow-ipv4": [
                    {"rule": {"eth_type": 0x800, "actions": {"allow": 1}}},
                    {"rule": {"actions": {"allow": 1}}},
                ],
            },
            "vlans": vlans,
            "routers": routers,
            "dps": {
                "s1": {
                    "dp_id": 1,
                    "hardware": "Open vSwitch",
                    "ignore_learn_ins": 0,
                    "interfaces": {
                        # A port ACL here, so that a trunk gaining one does
                        # not add the first, which changes the pipeline.
                        1: {"native_vlan": "uplink", "acls_in": ["port-allow"]},
                        2: {"native_vlan": "servers"},
                        3: {"tagged_vlans": ["clients1", "clients2"]},
                        4: {"tagged_vlans": ["clients1", "clients2"]},
                        5: {"native_vlan": "clients1"},
                    },
                }
            },
        }

    @staticmethod
    def add_clients3(config, ports):
        """Add a third client VLAN, with its routers, on ports."""
        config["vlans"]["clients3"] = {
            "vid": 0x500,
            "faucet_vips": ["10.13.0.254/24"],
            "faucet_mac": "0e:00:00:00:05:00",
        }
        config["routers"]["clients3-uplink"] = {"vlans": ["uplink", "clients3"]}
        config["routers"]["clients3-servers"] = {"vlans": ["servers", "clients3"]}
        for port in ports:
            interfaces = config["dps"]["s1"]["interfaces"]
            interfaces[port]["tagged_vlans"].append("clients3")

    @staticmethod
    def interfaces(config):
        """Return the config's interfaces."""
        return config["dps"]["s1"]["interfaces"]

    def setUp(self):
        """Start with every switch port up, and learn every host."""
        self.config = self.base_config()
        self.fib_ofmsgs = []
        self.setup_valves(config_parser_util.yaml_dump(self.config))
        # The switch's port description reply: a port the config does not
        # have yet is up, so a warm start that adds it adds its flows.
        valve = self.valves_manager.valves[self.DP_ID]
        self.apply_ofmsgs(
            valve.port_desc_stats_reply_handler(
                [SimpleNamespace(port_no=port, state=0) for port in self.SWITCH_PORTS],
                [],
                self.mock_time(),
            ).get(valve, [])
        )
        self.learn(self.HOSTS)
        self.assertEqual(set(self.HOSTS), self.routed_hosts())

    def learn(self, hosts):
        """Learn hosts, each by an ARP request for its VLAN's VIP."""
        for (port, vid), (mac, host_ip) in hosts.items():
            self.l3_learn_host(
                port, vid, mac, [ip_address(host_ip)], [ip_address(self.VIPS[vid])]
            )

    def fib(self):
        """Return the IPv4 FIB, as {(VID, destination): eth_dst it sets}."""
        valve = self.valves_manager.valves[self.DP_ID]
        fib_table_id = valve.dp.tables["ipv4_fib"].table_id
        routes = {}
        for flow in self.network.tables[self.DP_ID].tables[fib_table_id]:
            if "ipv4_dst" not in flow.match_values:
                continue
            ip_dst = "%s/%u" % (
                ip_address(flow.match_values["ipv4_dst"].bytes),
                flow.match_masks["ipv4_dst"].bin.count("1"),
            )
            vid = flow.match_values["vlan_vid"].int & ~ofp.OFPVID_PRESENT
            for instruction in flow.instructions:
                if instruction.type != ofp.OFPIT_APPLY_ACTIONS:
                    continue
                for action in instruction.actions:
                    if getattr(action, "key", None) == "eth_dst":
                        routes[(vid, ip_dst)] = action.value
        return routes

    def routed_vids(self, vid):
        """Return the VIDs a VLAN is routed with, itself included."""
        vids = {vid}
        for router in self.valves_manager.valves[self.DP_ID].dp.routers.values():
            router_vids = {vlan.vid for vlan in router.vlans}
            if vid in router_vids:
                vids |= router_vids
        return vids

    def routed_hosts(self):
        """Return the hosts of HOSTS routed on every VLAN routed with theirs,
        and cached as a resolved next hop."""
        valve = self.valves_manager.valves[self.DP_ID]
        fib = self.fib()
        routed = set()
        for (port, vid), (mac, host_ip) in self.HOSTS.items():
            if vid not in valve.dp.vlans:
                continue
            entry = valve.dp.vlans[vid].neigh_cache_by_ipv(4).get(ip_address(host_ip))
            if entry is None or entry.eth_src != mac or entry.port.number != port:
                continue
            if all(
                fib.get((routed_vid, "%s/32" % host_ip)) == mac
                for routed_vid in self.routed_vids(vid)
            ):
                routed.add((port, vid))
        return routed

    def static_routes(self):
        """Return the client VLANs routing each of ROUTES via the gateway."""
        fib = self.fib()
        gateway_mac = self.HOSTS[(1, 0x100)][0]
        return {
            (vid, ip_dst)
            for (vid, ip_dst), eth_dst in fib.items()
            if ip_dst in self.ROUTES and eth_dst == gateway_mac
        }

    def warm_start(self, config):
        """Warm start config, and return the IPv4 FIB deletes it sent."""
        self.config = config
        ofmsgs = self.update_config(
            config_parser_util.yaml_dump(config), reload_type="warm"
        )[self.DP_ID]
        fib_table_id = (
            self.valves_manager.valves[self.DP_ID].dp.tables["ipv4_fib"].table_id
        )
        self.fib_ofmsgs = [
            ofmsg
            for ofmsg in ofmsgs
            if valve_of.is_flowmod(ofmsg) and ofmsg.table_id == fib_table_id
        ]
        return [ofmsg for ofmsg in self.fib_ofmsgs if valve_of.is_flowdel(ofmsg)]

    def route_adds(self):
        """Return the IPv4 FIB adds of the last warm start that route via a
        next hop, setting its eth_dst."""
        return [
            ofmsg
            for ofmsg in self.fib_ofmsgs
            if valve_of.is_flowaddmod(ofmsg)
            and any(
                getattr(action, "key", None) == "eth_dst"
                for instruction in ofmsg.instructions
                if instruction.type == ofp.OFPIT_APPLY_ACTIONS
                for action in instruction.actions
            )
        ]

    def assert_relearned_as_cold(self):
        """Assert relearning every host gives the flows a cold start does."""
        hosts = {
            key: host
            for key, host in self.HOSTS.items()
            if key[0] in self.interfaces(self.config)
        }
        self.learn(hosts)
        warm = self.flows()
        self.teardown_valves()
        self.network = None
        self.setup_valves(config_parser_util.yaml_dump(self.config))
        self.learn(hosts)
        self.assertEqual(self.flows(), warm)

    def flows(self):
        """Return every flow on the switch, in a canonical order."""
        table = self.network.tables[self.DP_ID]
        table.sort_tables()
        return str(table)


class ValveWarmVLANPortsTestCase(ValveWarmVLANPortsTestBase):
    """Test a VLAN changed only through its ports keeps its routing."""

    # The uplink's routes, on every VLAN routed with it.
    ALL_ROUTES = {
        (vid, ip_dst)
        for vid in (0x100, 0x300, 0x400)
        for ip_dst in ValveWarmVLANPortsTestBase.ROUTES
    }

    def test_add_trunk(self):
        """Test adding a trunk that carries every client VLAN.

        Every client VLAN changes through its ports alone, so every host
        stays routed, and no route is deleted or sent again.
        """
        config = copy.deepcopy(self.config)
        self.interfaces(config)[6] = {"tagged_vlans": ["clients1", "clients2"]}
        self.assertEqual([], self.warm_start(config))
        self.assertEqual([], self.route_adds())
        self.assertEqual(set(self.HOSTS), self.routed_hosts())
        self.assertEqual(self.ALL_ROUTES, self.static_routes())
        self.assert_relearned_as_cold()

    def test_delete_trunk(self):
        """Test deleting a trunk keeps every host but its own routed."""
        config = copy.deepcopy(self.config)
        del self.interfaces(config)[4]
        self.warm_start(config)
        self.assertEqual(
            {key for key in self.HOSTS if key[0] != 4}, self.routed_hosts()
        )
        valve = self.valves_manager.valves[self.DP_ID]
        for (port, vid), (_, host_ip) in self.HOSTS.items():
            if port == 4:
                self.assertNotIn(
                    ip_address(host_ip), valve.dp.vlans[vid].neigh_cache_by_ipv(4)
                )
                self.assertNotIn((vid, "%s/32" % host_ip), self.fib())
        self.assert_relearned_as_cold()

    def test_add_access_port(self):
        """Test adding an access port to one client VLAN."""
        config = copy.deepcopy(self.config)
        self.interfaces(config)[6] = {"native_vlan": "clients1"}
        self.assertEqual([], self.warm_start(config))
        self.assertEqual(set(self.HOSTS), self.routed_hosts())
        self.assert_relearned_as_cold()

    def test_add_uplink_port(self):
        """Test adding a port to the uplink keeps its gateway and its routes."""
        config = copy.deepcopy(self.config)
        self.interfaces(config)[6] = {"native_vlan": "uplink"}
        self.assertEqual([], self.warm_start(config))
        uplink = self.valves_manager.valves[self.DP_ID].dp.vlans[0x100]
        self.assertIn(ip_address("10.0.0.1"), uplink.neigh_cache_by_ipv(4))
        self.assertEqual(self.ALL_ROUTES, self.static_routes())
        self.assertEqual(set(self.HOSTS), self.routed_hosts())

    def test_delete_static_route_after_add_port(self):
        """Test a route deleted after a port joins its gateway's VLAN goes."""
        config = copy.deepcopy(self.config)
        self.interfaces(config)[6] = {"native_vlan": "uplink"}
        self.warm_start(config)
        config = copy.deepcopy(config)
        config["vlans"]["uplink"]["routes"] = [
            {"route": {"ip_dst": "0.0.0.0/0", "ip_gw": "10.0.0.1"}}
        ]
        self.warm_start(config)
        self.learn({(1, 0x100): self.HOSTS[(1, 0x100)]})
        self.assertEqual(
            {(vid, "0.0.0.0/0") for vid in (0x100, 0x300, 0x400)},
            self.static_routes(),
        )

    def test_vlan_acl_change(self):
        """Test a client VLAN gaining an ACL keeps its routing.

        Each port of the VLAN changes with it, but no route does.
        """
        config = copy.deepcopy(self.config)
        config["vlans"]["clients1"]["acls_in"] = ["allow-ipv4"]
        self.assertEqual([], self.warm_start(config))
        self.assertEqual(set(self.HOSTS), self.routed_hosts())
        self.assert_relearned_as_cold()

    def test_vlan_own_change(self):
        """Test a client VLAN whose own config changes expires its next hops."""
        config = copy.deepcopy(self.config)
        config["vlans"]["clients1"]["max_hosts"] = 100
        self.warm_start(config)
        self.assertEqual(
            {key for key in self.HOSTS if key[1] != 0x300}, self.routed_hosts()
        )
        self.assert_relearned_as_cold()

    def test_port_change_beside_overlapping_change(self):
        """Test a VLAN changed through its ports beside a changed VLAN whose
        subnet overlaps its own expires its next hops: hosts on both could
        share a host route on the VLANs routed with them."""
        config = copy.deepcopy(self.config)
        self.interfaces(config)[6] = {"native_vlan": "clients1"}
        config["vlans"]["clients2"]["faucet_vips"] = ["10.10.0.254/15"]
        self.warm_start(config)
        self.assertEqual(
            {key for key in self.HOSTS if key[1] not in (0x300, 0x400)},
            self.routed_hosts(),
        )
        valve = self.valves_manager.valves[self.DP_ID]
        for (_, vid), (_, host_ip) in self.HOSTS.items():
            if vid in (0x300, 0x400):
                self.assertNotIn(
                    ip_address(host_ip), valve.dp.vlans[vid].neigh_cache_by_ipv(4)
                )

    def test_port_and_routers_change(self):
        """Test a VLAN whose ports and routed VLANs change together."""
        config = copy.deepcopy(self.config)
        self.interfaces(config)[6] = {"native_vlan": "clients1"}
        del config["routers"]["clients1-servers"]
        self.warm_start(config)
        self.assert_relearned_as_cold()


class ValveWarmTrunkVLANsTestCase(ValveWarmVLANPortsTestBase):
    """Test a trunk whose VLANs change keeps next hops on the VLANs it keeps."""

    def hosts_but(self, *gone):
        """Return the keys of HOSTS but those in gone."""
        return {key for key in self.HOSTS if key not in gone}

    def assert_expired(self, *gone):
        """Assert hosts' next hops are expired, and their routes deleted."""
        valve = self.valves_manager.valves[self.DP_ID]
        fib = self.fib()
        for port, vid in gone:
            host_ip = self.HOSTS[(port, vid)][1]
            if vid in valve.dp.vlans:
                self.assertNotIn(
                    ip_address(host_ip), valve.dp.vlans[vid].neigh_cache_by_ipv(4)
                )
            self.assertFalse(
                [key for key in fib if key[1] == "%s/32" % host_ip], msg=host_ip
            )

    def test_trunk_gains_vlan(self):
        """Test a network added on one trunk keeps the trunk's next hops."""
        config = copy.deepcopy(self.config)
        self.add_clients3(config, [3])
        self.warm_start(config)
        self.assertEqual(set(self.HOSTS), self.routed_hosts())
        self.assert_relearned_as_cold()

    def test_trunks_gain_vlan(self):
        """Test a network added on every trunk keeps their next hops."""
        config = copy.deepcopy(self.config)
        self.add_clients3(config, [3, 4])
        self.assertEqual([], self.warm_start(config))
        self.assertEqual(set(self.HOSTS), self.routed_hosts())
        self.assert_relearned_as_cold()

    def test_trunk_gains_vlan_and_acl(self):
        """Test a trunk gaining a VLAN and an ACL keeps its next hops."""
        config = copy.deepcopy(self.config)
        self.add_clients3(config, [3])
        self.interfaces(config)[3]["acls_in"] = ["port-allow"]
        self.warm_start(config)
        self.assertEqual(set(self.HOSTS), self.routed_hosts())
        self.assert_relearned_as_cold()

    def test_trunk_loses_vlan(self):
        """Test a trunk losing a VLAN expires only the next hops on it."""
        config = copy.deepcopy(self.config)
        self.interfaces(config)[4]["tagged_vlans"] = ["clients1"]
        self.warm_start(config)
        self.assertEqual(self.hosts_but((4, 0x400)), self.routed_hosts())
        self.assert_expired((4, 0x400))
        self.assert_relearned_as_cold()

    def test_network_removed(self):
        """Test removing a network from every trunk keeps their other next hops."""
        config = copy.deepcopy(self.config)
        del config["vlans"]["clients2"]
        for router in ("clients2-uplink", "clients2-servers"):
            del config["routers"][router]
        for port in (3, 4):
            self.interfaces(config)[port]["tagged_vlans"] = ["clients1"]
        self.warm_start(config)
        self.assertEqual(self.hosts_but((3, 0x400), (4, 0x400)), self.routed_hosts())
        self.assert_expired((3, 0x400), (4, 0x400))
        self.assert_relearned_as_cold()

    def test_trunk_retags_vlan(self):
        """Test a trunk carrying a VLAN untagged instead expires its next hops."""
        config = copy.deepcopy(self.config)
        self.interfaces(config)[3] = {
            "native_vlan": "clients1",
            "tagged_vlans": ["clients2"],
        }
        self.warm_start(config)
        self.assertEqual(self.hosts_but((3, 0x300)), self.routed_hosts())
        self.assert_expired((3, 0x300))

    def test_access_port_moves(self):
        """Test an access port moved to another VLAN expires its next hops."""
        config = copy.deepcopy(self.config)
        self.interfaces(config)[5] = {"native_vlan": "clients2"}
        self.warm_start(config)
        self.assertEqual(self.hosts_but((5, 0x300)), self.routed_hosts())
        self.assert_expired((5, 0x300))
        self.assert_relearned_as_cold()

    def test_trunk_own_change(self):
        """Test a trunk's own config changing otherwise expires all its next hops."""
        config = copy.deepcopy(self.config)
        self.interfaces(config)[3]["max_hosts"] = 100
        self.warm_start(config)
        self.assertEqual(self.hosts_but((3, 0x300), (3, 0x400)), self.routed_hosts())
        self.assert_expired((3, 0x300), (3, 0x400))
        self.assert_relearned_as_cold()


class ValveWarmVLANPortsARPResponderTestCase(ValveWarmVLANPortsTestBase):
    """Test the switch's ARP responder when a VLAN's ports alone change.

    The VLAN keeps its routing, so its flows answering ARP for its VIP stay,
    and the per-port ones follow the ports added and deleted.
    """

    def base_config(self):
        config = super().base_config()
        config["dps"]["s1"]["arp_responder"] = True
        return config

    def vip_flows(self):
        """Return the vip table's flows, in a canonical order."""
        table = self.network.tables[self.DP_ID]
        table.sort_tables()
        vip_table_id = self.valves_manager.valves[self.DP_ID].dp.tables["vip"].table_id
        return str(table.tables[vip_table_id])

    def assert_vip_flows_as_cold(self, config):
        """Assert a warm start of config leaves the vip table a cold start has."""
        self.warm_start(config)
        warm = self.vip_flows()
        self.teardown_valves()
        self.network = None
        self.setup_valves(config_parser_util.yaml_dump(config))
        self.assertEqual(self.vip_flows(), warm)

    def test_add_access_port(self):
        """Test an access port added to a client VLAN is answered untagged."""
        config = copy.deepcopy(self.config)
        self.interfaces(config)[6] = {"native_vlan": "clients1"}
        self.assert_vip_flows_as_cold(config)

    def test_delete_access_port(self):
        """Test an access port deleted from a client VLAN is no longer answered."""
        config = copy.deepcopy(self.config)
        del self.interfaces(config)[5]
        self.assert_vip_flows_as_cold(config)

    def test_access_port_tagged(self):
        """Test an access port that tags its VLAN instead is answered tagged."""
        config = copy.deepcopy(self.config)
        self.interfaces(config)[5] = {"tagged_vlans": ["clients1"]}
        self.assert_vip_flows_as_cold(config)


class ValveWarmVLANPortsLACPTestCase(ValveWarmVLANPortsTestBase):
    """Test an LACP port leaving a VLAN that changes only through its ports.

    Deleting an LACP port expires none of its next hops, so the VLAN's
    routing is not kept: its next hops expire with it, as before.
    """

    HOSTS = {
        **ValveWarmVLANPortsTestBase.HOSTS,
        (6, 0x300): ("00:00:00:06:03:00", "10.11.0.6"),
    }

    def base_config(self):
        config = super().base_config()
        self.interfaces(config)[6] = {"native_vlan": "clients1", "lacp": 1}
        return config

    def learn(self, hosts):
        """Bring up LACP on port 6 first, so that it forwards."""
        self.rcv_packet(
            6,
            0,
            {
                "actor_system": "0e:00:00:00:00:02",
                "partner_system": FAUCET_MAC,
                "eth_dst": slow.SLOW_PROTOCOL_MULTICAST,
                "eth_src": "0e:00:00:00:00:02",
                "actor_state_synchronization": 1,
            },
        )
        super().learn(hosts)

    def test_delete_lacp_port(self):
        """Test deleting the LACP port expires the next hop behind it."""
        config = copy.deepcopy(self.config)
        del self.interfaces(config)[6]
        self.warm_start(config)
        vlan = self.valves_manager.valves[self.DP_ID].dp.vlans[0x300]
        self.assertNotIn(ip_address("10.11.0.6"), vlan.neigh_cache_by_ipv(4))
        self.assertFalse([key for key in self.fib() if key[1] == "10.11.0.6/32"])


class ValveWarmVLANPortsStackTestCase(ValveWarmVLANPortsTestBase):
    """Test a VLAN of a stacked datapath changed only through its ports.

    A host can move to another stack port with the topology, so the VLAN's
    next hops expire with it, as before.
    """

    def base_config(self):
        config = super().base_config()
        config["dps"]["s1"]["stack"] = {"priority": 1}
        self.interfaces(config)[8] = {"stack": {"dp": "s2", "port": 1}}
        config["dps"]["s2"] = {
            "dp_id": 2,
            "hardware": "Open vSwitch",
            "interfaces": {
                1: {"stack": {"dp": "s1", "port": 8}},
                2: {"native_vlan": "clients1"},
            },
        }
        return config

    def test_add_access_port(self):
        """Test adding an access port to a client VLAN expires its next hops."""
        config = copy.deepcopy(self.config)
        self.interfaces(config)[6] = {"native_vlan": "clients1"}
        self.warm_start(config)
        self.assertEqual(
            {key for key in self.HOSTS if key[1] != 0x300}, self.routed_hosts()
        )


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
