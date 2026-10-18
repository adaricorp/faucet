#!/usr/bin/env python3

"""Unit tests for the OpenFlow priorities of ACL rules."""

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

import os
import shutil
import tempfile
import unittest

from clib.fakeoftable import FlowMod
from clib.valve_test_lib import (
    BASE_DP1_CONFIG,
    DOT1X_ACL_CONFIG,
    DOT1X_CONFIG,
    ValveTestBases,
)

from faucet import config_parser as cp
from faucet import faucet_dot1x
from faucet import valve_of
from faucet.valve_acl import ValveAclManager

# More rules than the 0x5000 priorities that ACL rules used to count down
# from: rule 0x5000 would have had priority 0, the table miss's.
MANY_RULES = 0x5000 + 16
RULES_PER_ACL = 10


def rule_ip(index):
    """Return the IPv4 source that ACL rule index allows."""
    return "10.%u.%u.%u" % ((index >> 16) & 0xFF, (index >> 8) & 0xFF, index & 0xFF)


def acls_config(rules, exact_match=False):
    """Return ACLs, as config, of rules allowing one IPv4 source each, and their names.

    The rules are spread over ACLs of RULES_PER_ACL rules, and followed by
    an ACL that drops the rest of 10.0.0.0/8 and allows everything else, so
    the order of the rules decides what a packet gets."""
    lines = ["acls:"]
    names = []
    for first in range(0, rules, RULES_PER_ACL):
        name = "allow%u" % first
        names.append(name)
        lines.append("    %s:" % name)
        if exact_match:
            lines.append("        exact_match: True")
            lines.append("        rules:")
        for index in range(first, min(first + RULES_PER_ACL, rules)):
            lines.append(
                "        - rule: {eth_type: 0x0800, ipv4_src: '%s', actions: {allow: 1}}"
                % rule_ip(index)
            )
    if not exact_match:
        names.append("rest")
        lines.extend(
            [
                "    rest:",
                "        - rule: {eth_type: 0x0800, ipv4_src: '10.0.0.0/8',"
                " actions: {allow: 0}}",
                "        - rule: {actions: {allow: 1}}",
            ]
        )
    return "\n".join(lines) + "\n", names


def port_acls_config(rules, dp_config=BASE_DP1_CONFIG, exact_match=False):
    """Return a config with ACLs of rules on port 1."""
    acls, names = acls_config(rules, exact_match=exact_match)
    return (
        acls
        + """
vlans:
    v100:
        vid: 100
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                acls_in: [%s]
            p2:
                number: 2
                native_vlan: v100
"""
        % (
            dp_config,
            ", ".join(names),
        )
    )


class ValveAclManyRulesTestCase(ValveTestBases.ValveTestNetwork):
    """ACLs on a port with more rules than 0x5000 install in their order."""

    # The fake switch scans and sorts its tables for each flow mod, which
    # does not scale to the flows of these tests, so they check the flows
    # faucet sends instead of applying them.
    sent = None

    def apply_ofmsgs(
        self, ofmsgs, dp_id=None, offset=1, all_offsets=False
    ):  # pylint: disable=unused-argument
        """Prepare ofmsgs as the harness does, and keep them, applying none."""
        if not ofmsgs:
            return ofmsgs
        valve = self.valves_manager.valves[dp_id or self.DP_ID]
        self.sent = valve.prepare_send_flows(ofmsgs)
        return self.sent

    def _port1_acl_flows(self):
        """Return the port_acl flows sent for port 1, by rule."""
        dp = self.valves_manager.valves[self.DP_ID].dp
        table_id = dp.tables["port_acl"].table_id
        flows = []
        by_rule = {}
        for ofmsg in self.sent:
            if (
                valve_of.is_flowaddmod(ofmsg)
                and ofmsg.table_id == table_id
                and ofmsg.match.get("in_port") == 1
            ):
                flow = FlowMod(ofmsg)
                flows.append(flow)
                src = ofmsg.match.get("ipv4_src")
                if isinstance(src, tuple):
                    src = "/".join(src)
                by_rule.setdefault(src, []).append(flow)
        return flows, by_rule

    def _verify_order(self, rules):
        flows, by_rule = self._port1_acl_flows()
        self.assertEqual(rules + 2, len(flows))
        ordered = [by_rule[rule_ip(index)] for index in range(rules)]
        ordered.extend([by_rule["10.0.0.0/255.0.0.0"], by_rule[None]])
        for rule_flows in ordered:
            self.assertEqual(1, len(rule_flows), rule_flows)
        priorities = [rule_flows[0].priority for rule_flows in ordered]
        # Every rule its own priority, in the order of the rules, from the
        # top of the ACL band down, and all above the table miss.
        self.assertEqual(ValveAclManager.ACL_PRIORITY, priorities[0])
        for higher, lower in zip(priorities, priorities[1:]):
            self.assertGreater(higher, lower)
        valve = self.valves_manager.valves[self.DP_ID]
        self.assertGreater(priorities[-1], valve.dp.lowest_priority)
        self.assertLess(priorities[0], valve.acl_manager.override_priority)

        def first_match(ipv4_src):
            pkt = {"in_port": 1, "eth_type": 0x0800, "ipv4_src": ipv4_src}
            for flow in sorted(flows, reverse=True):
                if flow.pkt_matches(pkt):
                    return flow
            return None

        # Past the old band: the last allow wins over the drop after it,
        # which wins over the allow of everything after that.
        self.assertEqual(ordered[rules - 1][0], first_match(rule_ip(rules - 1)))
        self.assertEqual(ordered[rules][0], first_match("10.255.255.254"))
        self.assertEqual(ordered[rules + 1][0], first_match("192.0.2.1"))

    def test_cold_start(self):
        """Cold start a port with more ACL rules than 0x5000."""
        self.setup_valves(port_acls_config(MANY_RULES))
        self._verify_order(MANY_RULES)

    def test_warm_start(self):
        """Warm start a port to more ACL rules than 0x5000."""
        self.setup_valves(port_acls_config(1))
        self._verify_order(1)
        self.update_config(port_acls_config(MANY_RULES), reload_type="warm")
        self._verify_order(MANY_RULES)
        dp = self.valves_manager.valves[self.DP_ID].dp
        self.assertTrue(
            [
                ofmsg
                for ofmsg in self.sent
                if valve_of.is_flowdel(ofmsg)
                and ofmsg.table_id == dp.tables["port_acl"].table_id
                and ofmsg.match.get("in_port") == 1
            ]
        )


# With the table miss at 65000, ACLs used together can have 534 rules,
# few enough to apply to the fake switch.
LOWEST_PRIORITY = 65000
MAX_RULES = ValveAclManager.max_rules(LOWEST_PRIORITY)
LOWEST_PRIORITY_DP1_CONFIG = (
    """
        lowest_priority: %u
        table_sizes: {port_acl: 1024}
"""
    % LOWEST_PRIORITY
    + BASE_DP1_CONFIG
)


# An 802.1X ACL's rules count down from the 802.1X flows' priority instead.
# With the table miss four below it, an 802.1X ACL can have four rules.
DOT1X_LOWEST_PRIORITY = ValveAclManager.max_rules(0, dot1x=True) - 4
DOT1X_MAX_RULES = ValveAclManager.max_rules(DOT1X_LOWEST_PRIORITY, dot1x=True)


def dot1x_config(rules, acl_name="dyn_acl", exact_match=False):
    """Return a config whose 802.1X ACL acl_name has rules, for port 1.

    acl_name is dyn_acl, an ACL with dot1x_assigned that port 1 gets for a
    host that authenticates (dot1x_dyn_acl), or the DP's auth_acl or
    noauth_acl (dot1x_acl), the other of which has one rule."""
    acl_lines = ["        rules:"]
    for index in range(rules):
        acl_lines.append(
            "        - rule: {eth_type: 0x0800, ipv4_src: '%s', actions: {allow: 1}}"
            % rule_ip(index)
        )
    if exact_match:
        acl_lines.insert(0, "        exact_match: True")
    if acl_name == "dyn_acl":
        acl_lines.insert(0, "        dot1x_assigned: True")
        acls = {acl_name: acl_lines}
        dp_config = DOT1X_CONFIG
        port_config = "dot1x_dyn_acl: True"
    else:
        other = {"auth_acl": "noauth_acl", "noauth_acl": "auth_acl"}[acl_name]
        acls = {
            acl_name: acl_lines,
            other: ["        - rule: {actions: {allow: 0}}"],
        }
        dp_config = DOT1X_ACL_CONFIG
        port_config = "dot1x_acl: True"
    lines = ["acls:"]
    for name, rule_lines in acls.items():
        lines.append("    %s:" % name)
        lines.extend(rule_lines)
    return (
        "\n".join(lines)
        + """
vlans:
    v100:
        vid: 100
dps:
    s1:
        lowest_priority: %u
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                dot1x: True
                %s
            p2:
                number: 2
                output_only: True
"""
        % (DOT1X_LOWEST_PRIORITY, dp_config, port_config)
    )


class ValveAclRuleLimitTestCase(ValveTestBases.ValveTestNetwork):
    """faucet rejects ACLs with more rules than priorities, and keeps running."""

    def test_rules_above_table_miss(self):
        """As many rules as fit are all above the table miss."""
        self.setup_valves(port_acls_config(MAX_RULES - 2, LOWEST_PRIORITY_DP1_CONFIG))
        table = self.network.tables[self.DP_ID]
        dp = self.valves_manager.valves[self.DP_ID].dp
        table_id = dp.tables["port_acl"].table_id
        priorities = sorted(
            flow.priority
            for flow in table.tables[table_id]
            if flow.match_values.get("in_port") is not None
        )
        self.assertEqual(MAX_RULES + 1, len(priorities))  # and p2's allow
        self.assertEqual(LOWEST_PRIORITY + 1, priorities[0])
        for pkt, out in (
            ({"ipv4_src": rule_ip(MAX_RULES - 3)}, True),
            ({"ipv4_src": "10.255.255.254"}, False),
            ({"ipv4_src": "192.0.2.1"}, True),
        ):
            pkt.update({"in_port": 1, "eth_type": 0x0800})
            flow = table.single_table_lookup(pkt, table_id)
            self.assertEqual(out, bool(flow.instructions), (pkt, flow))

    def test_reload_too_many_rules(self):
        """A reload with too many rules on a port keeps the running config."""
        self.setup_valves(port_acls_config(MAX_RULES - 2, LOWEST_PRIORITY_DP1_CONFIG))
        dp = self.valves_manager.valves[self.DP_ID].dp
        self.update_config(
            port_acls_config(MAX_RULES - 1, LOWEST_PRIORITY_DP1_CONFIG),
            error_expected=1,
        )
        self.assertFalse(self.last_flows_to_dp[self.DP_ID])
        valve = self.valves_manager.valves[self.DP_ID]
        self.assertIs(dp, valve.dp)
        self.assertEqual(
            MAX_RULES, sum(len(acl.rules) for acl in valve.dp.ports[1].acls_in)
        )

    def test_dot1x_rules_above_table_miss(self):
        """An 802.1X ACL with as many rules as fit is all above the table miss."""
        self.setup_valves(dot1x_config(DOT1X_MAX_RULES))
        mac = "0e:00:00:00:00:ff"
        valve_index = self.dot1x.dp_id_to_valve_index[self.DP_ID]
        self.dot1x.auth_handler(
            mac,
            faucet_dot1x.get_mac_str(valve_index, 1),
            vlan_name=None,
            filter_id="dyn_acl",
        )
        # The harness keeps the flows faucet sends; apply them.
        self.network.apply_ofmsgs(self.DP_ID, self.last_flows_to_dp[self.DP_ID])
        table = self.network.tables[self.DP_ID]
        dp = self.valves_manager.valves[self.DP_ID].dp
        table_id = dp.tables["port_acl"].table_id
        priorities = sorted(
            flow.priority
            for flow in table.tables[table_id]
            if flow.match_values.get("ipv4_src") is not None
        )
        self.assertEqual(
            list(
                range(
                    DOT1X_LOWEST_PRIORITY + 1,
                    DOT1X_LOWEST_PRIORITY + DOT1X_MAX_RULES + 1,
                )
            ),
            priorities,
        )
        for index in range(DOT1X_MAX_RULES):
            pkt = {
                "in_port": 1,
                "eth_src": mac,
                "eth_type": 0x0800,
                "ipv4_src": rule_ip(index),
            }
            flow = table.single_table_lookup(pkt, table_id)
            self.assertEqual(
                DOT1X_LOWEST_PRIORITY + DOT1X_MAX_RULES - index, flow.priority
            )


class AclRuleLimitConfigTestCase(unittest.TestCase):  # pytype: disable=module-attr
    """Config parsing counts the rules of ACLs used together."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _parse(self, config):
        conf_file = os.path.join(self.tmpdir, "faucet.yaml")
        with open(conf_file, "w", encoding="utf-8") as conf:
            conf.write(config)
        return cp.dp_parser(conf_file, "/dev/null")

    def _parses(self, config):
        try:
            self._parse(config)
        except cp.InvalidConfigError:
            return False
        return True

    def _vlan_config(self, rules, key):
        acls, names = acls_config(rules)
        return (
            acls
            + """
vlans:
    v100:
        vid: 100
        %s: [%s]
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
"""
            % (
                key,
                ", ".join(names),
                LOWEST_PRIORITY_DP1_CONFIG,
            )
        )

    def _dp_acls_config(self, rules):
        acls, names = acls_config(rules)
        return (
            acls
            + """
vlans:
    v100:
        vid: 100
dps:
    s1:
        dp_acls: [%s]
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
"""
            % (", ".join(names), LOWEST_PRIORITY_DP1_CONFIG)
        )

    def test_default_limit(self):
        """ACLs used together can have 65534 rules by default."""
        self.assertEqual(65534, ValveAclManager.max_rules(0))

    def test_port_acls_in(self):
        """A port's acls_in can have as many rules as fit."""
        self.assertTrue(
            self._parses(port_acls_config(MAX_RULES - 2, LOWEST_PRIORITY_DP1_CONFIG))
        )
        with self.assertRaisesRegex(
            cp.InvalidConfigError,
            "port 1 acls_in has 535 ACL rules, more than the 534 that",
        ):
            self._parse(port_acls_config(MAX_RULES - 1, LOWEST_PRIORITY_DP1_CONFIG))

    def test_vlan_acls_in(self):
        """A VLAN's acls_in can have as many rules as fit."""
        self.assertTrue(self._parses(self._vlan_config(MAX_RULES - 2, "acls_in")))
        self.assertFalse(self._parses(self._vlan_config(MAX_RULES - 1, "acls_in")))

    def test_vlan_acls_out(self):
        """A VLAN's acls_out can have as many rules as fit."""
        self.assertTrue(self._parses(self._vlan_config(MAX_RULES - 2, "acls_out")))
        self.assertFalse(self._parses(self._vlan_config(MAX_RULES - 1, "acls_out")))

    def test_dp_acls(self):
        """A DP's dp_acls can have as many rules as fit."""
        self.assertTrue(self._parses(self._dp_acls_config(MAX_RULES - 2)))
        self.assertFalse(self._parses(self._dp_acls_config(MAX_RULES - 1)))

    def test_exact_match(self):
        """Exact match ACLs share a priority, so have no limit."""
        self.assertTrue(
            self._parses(
                port_acls_config(
                    MAX_RULES + 1, LOWEST_PRIORITY_DP1_CONFIG, exact_match=True
                )
            )
        )

    def test_dot1x_default_limit(self):
        """An 802.1X ACL can have 16384 rules by default."""
        self.assertEqual(16384, ValveAclManager.max_rules(0, dot1x=True))

    def test_dot1x_assigned_acl(self):
        """An ACL with dot1x_assigned can have as many rules as fit."""
        self.assertTrue(self._parses(dot1x_config(DOT1X_MAX_RULES)))
        with self.assertRaisesRegex(
            cp.InvalidConfigError,
            "802.1X ACL dyn_acl has 5 ACL rules, more than the 4 that an 802.1X",
        ):
            self._parse(dot1x_config(DOT1X_MAX_RULES + 1))

    def test_dot1x_auth_acls(self):
        """An auth_acl or a noauth_acl can have as many rules as fit."""
        for acl_name in ("auth_acl", "noauth_acl"):
            self.assertTrue(self._parses(dot1x_config(DOT1X_MAX_RULES, acl_name)))
            self.assertFalse(self._parses(dot1x_config(DOT1X_MAX_RULES + 1, acl_name)))

    def test_dot1x_exact_match(self):
        """An exact match 802.1X ACL shares a priority, so has no limit."""
        self.assertTrue(
            self._parses(dot1x_config(DOT1X_MAX_RULES + 1, exact_match=True))
        )


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
