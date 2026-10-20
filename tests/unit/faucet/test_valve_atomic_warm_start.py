#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valve_atomic_warm_start.py."""

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
import itertools
import os
import unittest
from unittest import mock

from os_ken.ofproto import ofproto_common
from os_ken.ofproto import ofproto_v1_3 as ofp
from os_ken.ofproto import ofproto_v1_3_parser as parser
from prometheus_client import CollectorRegistry

from faucet import faucet
from faucet import valve_of

from clib.valve_test_lib import ValveTestBases


CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: "%s"
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v100
            p3:
                number: 3
                tagged_vlans: [%s]
            p4:
                number: 4
                native_vlan: v200
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
"""


def config(options=(), p3_vlans="v100", hardware="Open vSwitch"):
    """Return CONFIG with DP options set to true, and p3 on p3_vlans."""
    dp_options = "\n".join("        %s: true" % option for option in options)
    return CONFIG % (hardware, dp_options, p3_vlans)


class FakeDatapath:
    """Record what faucet sends, numbering messages as the switch would."""

    ofproto = ofp
    ofproto_parser = parser

    def __init__(self, first_xid=0):
        self.sent = []
        self.closed = False
        # Each connection numbers its messages from its own random xid.
        self.xid = first_xid

    def send_msg(self, msg):
        """Record msg with its own xid."""
        if msg.xid is None:
            self.xid += 1
            msg.set_xid(self.xid)
        msg.serialize()
        self.sent.append(msg)

    def close(self):
        """Record a close."""
        self.closed = True


def flow_body(ofmsg):
    """Return a sent flow mod as the switch reads it, less its xid."""
    return bytes(ofmsg.buf[:4] + ofmsg.buf[8:])


def bundle_ctrls(ofmsgs, ctrl_type):
    """Return the bundle control messages of ctrl_type in ofmsgs."""
    return [
        ofmsg
        for ofmsg in ofmsgs
        if isinstance(ofmsg, parser.ONFBundleCtrlMsg) and ofmsg.type == ctrl_type
    ]


def bundled(ofmsgs):
    """Return the messages of the bundle adds in ofmsgs."""
    return [
        ofmsg.message for ofmsg in ofmsgs if isinstance(ofmsg, parser.ONFBundleAddMsg)
    ]


def commit_error(commit):
    """Return the error a switch answers a commit it fails with."""
    error = parser.OFPErrorMsg(
        None,
        type_=ofp.OFPET_EXPERIMENTER,
        exp_type=ofp.ONFERR_ET_FAILED,
        experimenter=ofproto_common.ONF_EXPERIMENTER_ID,
    )
    error.xid = commit.xid
    return error


def open_error(bundle_open, ryu_dp):
    """Return the error a switch answers a bundle's open with on ryu_dp.

    The switch answers a bundle's open with an error when it discards the
    bundle, as it does once the bundle has received nothing for the switch's
    bundle idle timeout.
    """
    error = parser.OFPErrorMsg(
        None,
        type_=ofp.OFPET_EXPERIMENTER,
        exp_type=ofp.ONFERR_ET_TIMEOUT,
        experimenter=ofproto_common.ONF_EXPERIMENTER_ID,
    )
    error.xid = bundle_open.xid
    error.datapath = ryu_dp
    return error


def commit_reply(commit):
    """Return the reply a switch answers a commit it applies with."""
    reply = parser.ONFBundleCtrlMsg(
        None, commit.bundle_id, ofp.ONF_BCT_COMMIT_REPLY, commit.flags, []
    )
    reply.xid = commit.xid
    return reply


class ValveAtomicWarmStartTestBase(ValveTestBases.ValveTestNetwork):
    """Send what the valves send through Valve.send_flows() to a fake switch."""

    REQUIRE_TFM = False
    OPTIONS = ("atomic_warm_start",)

    def __init__(self, *args, **kwargs):
        self.ryu_dp = None
        self.valve = None
        super().__init__(*args, **kwargs)

    def setUp(self):
        """Set up a routed DP on a fake switch."""
        self.setup(self.OPTIONS)

    def setup(self, options):
        """Set up the valves with DP options set to true."""
        self.ryu_dp = FakeDatapath()
        self.setup_valves(config(options))
        self.valve = self.valves_manager.valves[self.DP_ID]

    def setup_again(self, options):
        """Set up new valves, on a new switch, with DP options set to true."""
        self.teardown_valves()
        # Or setup_valves() checks the new switch's tables against the old one's.
        self.network = None  # pylint: disable=attribute-defined-outside-init
        self.setup(options)

    def send_flows_to_dp_by_id(self, valve, flows):
        """Send flows to the fake switch as faucet does, and record them."""
        # faucet finds no switch to send to while the DP is down.
        if valve.dp.dyn_running:
            valve.send_flows(self.ryu_dp, flows, self.mock_time(0))
        self.last_flows_to_dp[valve.dp.dp_id] = flows

    def sent(self, func):
        """Return what the switch is sent while func runs."""
        start = len(self.ryu_dp.sent)
        func()
        return self.ryu_dp.sent[start:]

    def reconnect(self):
        """Connect the DP again, and return what the switch is sent."""
        self.valve.datapath_disconnect(self.mock_time())
        return self.sent(
            lambda: self.valve.send_flows(
                self.ryu_dp,
                self.valve.switch_features(None)
                + self.valve.datapath_connect(self.mock_time(), {1, 2, 3, 4}),
                self.mock_time(),
            )
        )

    def bundle_counts(self, restart_type="warm"):
        """Return the bundles sent, committed, refused and lost."""
        return tuple(
            int(
                self.get_prom(
                    "faucet_%s_start_bundles%s_total" % (restart_type, outcome)
                )
            )
            for outcome in ("", "_committed", "_refused", "_lost")
        )

    def atomic_status(self, restart_type="warm"):
        """Return 1 if starts of restart_type are bundled."""
        return int(self.get_prom("dp_atomic_%s_start" % restart_type))

    def warm_start(self, p3_vlans="v100,v200", options=None):
        """Warm start onto p3 tagged on p3_vlans, and return what is sent."""
        if options is None:
            options = self.OPTIONS
        return self.sent(
            lambda: self.update_config(
                config(options, p3_vlans=p3_vlans), reload_type="warm"
            )
        )

    def change_flows(self):
        """Send the switch a flow mod without a bundle, as a packet in can."""
        self.valve.send_flows(
            self.ryu_dp,
            [self.valve.dp.tables["vlan"].flowdrop(priority=1)],
            self.mock_time(),
        )

    def assert_bundled(self, sent):
        """Assert sent holds every flow mod in one ordered, atomic bundle."""
        self.assertFalse(
            [ofmsg for ofmsg in sent if valve_of.is_flowmod(ofmsg)],
            msg="flow mod outside the bundle",
        )
        kinds = [type(ofmsg).__name__ for ofmsg in sent]
        (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
        (commit,) = bundle_ctrls(sent, ofp.ONF_BCT_COMMIT_REQUEST)
        open_index = sent.index(bundle_open)
        commit_index = sent.index(commit)
        self.assertTrue(
            all(
                kind == "ONFBundleAddMsg"
                for kind in kinds[open_index + 1 : commit_index]
            )
        )
        self.assertEqual(
            "OFPBarrierRequest", kinds[commit_index + 1], msg="no barrier on commit"
        )
        for ofmsg in sent[open_index : commit_index + 1]:
            self.assertEqual(ofmsg.bundle_id, commit.bundle_id)
            self.assertEqual(ofmsg.flags, ofp.ONF_BF_ATOMIC | ofp.ONF_BF_ORDERED)
        return commit

    def assert_not_bundled(self, sent):
        """Assert sent holds flow mods and no bundle."""
        self.assertTrue([ofmsg for ofmsg in sent if valve_of.is_flowmod(ofmsg)])
        self.assertFalse(
            [
                ofmsg
                for ofmsg in sent
                if isinstance(ofmsg, (parser.ONFBundleAddMsg, parser.ONFBundleCtrlMsg))
            ],
            msg="bundled",
        )


class ValveAtomicWarmStartTestCase(ValveAtomicWarmStartTestBase):
    """Test a warm start changing the flows in one atomic bundle."""

    def test_warm_start_in_one_bundle(self):
        """Test a warm start sends its deletes and adds in one bundle."""
        self.assertEqual(1, self.atomic_status())
        sent = self.warm_start()
        self.assert_bundled(sent)
        commands = {ofmsg.command for ofmsg in bundled(sent)}
        self.assertIn(ofp.OFPFC_ADD, commands)
        self.assertTrue(commands & {ofp.OFPFC_DELETE, ofp.OFPFC_DELETE_STRICT})
        self.assertEqual((1, 0, 0, 0), self.bundle_counts())
        self.assertEqual((0, 0, 0, 0), self.bundle_counts("cold"))

    def test_bundle_is_unbundled_batch(self):
        """Test the bundle holds the flow mods sent without it, in order."""
        self.setup_again(())
        unbundled = [
            flow_body(ofmsg)
            for ofmsg in self.warm_start(options=())
            if valve_of.is_flowmod(ofmsg)
        ]
        self.setup_again(self.OPTIONS)
        sent = self.warm_start()
        self.assert_bundled(sent)
        self.assertTrue(unbundled)
        self.assertEqual(unbundled, [flow_body(ofmsg) for ofmsg in bundled(sent)])

    def test_bundled_only_when_warm(self):
        """Test a cold start, a cold reload and other sends are not bundled."""
        sent = self.sent(
            lambda: self.update_config(config(self.OPTIONS), reload_type=None)
        )
        self.assertFalse(sent, msg="no change, yet sent")
        self.valve.datapath_disconnect(self.mock_time())
        sent = self.sent(
            lambda: self.update_config(config(self.OPTIONS, "v200"), reload_type="warm")
        )
        self.assertFalse(sent, msg="warm start sent to a DP that is down")
        # The switch connects, and faucet reloads before the DP is up.
        features = self.valve.switch_features(None)
        sent = self.sent(
            lambda: self.update_config(config(self.OPTIONS, "v100"), reload_type="warm")
        )
        self.assertFalse(sent, msg="warm start sent to a DP that is not yet up")
        self.assert_not_bundled(
            self.sent(
                lambda: self.valve.send_flows(
                    self.ryu_dp,
                    features
                    + self.valve.datapath_connect(self.mock_time(), {1, 2, 3, 4}),
                    self.mock_time(),
                )
            )
        )
        cold_config = config(self.OPTIONS, "v200").replace(
            "dp_id: 1", "dp_id: 1\n        timeout: 600"
        )
        sent = self.sent(lambda: self.update_config(cold_config, reload_type="cold"))
        self.assertTrue(self.ryu_dp.closed, msg="cold reload did not reconnect")
        self.assertFalse(bundled(sent))
        sent = self.sent(
            lambda: self.rcv_packet(
                1,
                0x100,
                {
                    "eth_src": self.P1_V100_MAC,
                    "eth_dst": self.UNKNOWN_MAC,
                    "ipv4_src": "10.0.0.1",
                    "ipv4_dst": "10.0.0.4",
                },
            )
        )
        self.assert_not_bundled(sent)

    def test_option_off(self):
        """Test a warm start without the option is not bundled."""
        self.setup_again(())
        self.assert_not_bundled(self.warm_start(options=()))
        self.assertEqual(0, self.atomic_status())
        self.assertEqual((0, 0, 0, 0), self.bundle_counts())

    def test_toggle_without_cold_start(self):
        """Test changing atomic_warm_start applies from the next warm start."""
        reloads = [
            self.get_prom("faucet_config_reload_%s_total" % restart_type)
            for restart_type in ("cold", "warm")
        ]
        p3_vlans = "v100"
        for options, new_p3_vlans in (((), "v100,v200"), (self.OPTIONS, "v100")):
            self.update_config(config(options, p3_vlans), reload_expected=False)
            self.assertEqual(
                reloads,
                [
                    self.get_prom("faucet_config_reload_%s_total" % restart_type)
                    for restart_type in ("cold", "warm")
                ],
            )
            self.assertEqual(int(bool(options)), self.atomic_status())
            sent = self.warm_start(p3_vlans=new_p3_vlans, options=options)
            self.assertEqual(bool(options), bool(bundled(sent)))
            p3_vlans = new_p3_vlans
            reloads[1] += 1

    def test_commit(self):
        """Test a committed bundle is forgotten, and the next one bundled."""
        commit = self.assert_bundled(self.warm_start())
        self.valve.bundle_ctrl_reply(commit_reply(commit))
        self.valve.bundle_ctrl_reply(commit_reply(commit))
        self.assertEqual((1, 1, 0, 0), self.bundle_counts())
        # Committed, its flow mods are no longer kept to send again.
        self.assertIsNone(self.valve._bundle_resend)  # pylint: disable=protected-access
        self.assertEqual([], self.valve.oferror(commit_error(commit)))
        self.assert_bundled(self.warm_start(p3_vlans="v100"))
        self.assertEqual((2, 1, 0, 0), self.bundle_counts())
        self.assertEqual(1, self.atomic_status())

    def test_flow_mod_error(self):
        """Test an error on one flow mod in a bundle refuses no bundle.

        The switch leaves a flow mod it cannot decode out of the bundle, and
        commits the rest.
        """
        sent = self.warm_start()
        self.assert_bundled(sent)
        bundle_add = next(
            ofmsg for ofmsg in sent if isinstance(ofmsg, parser.ONFBundleAddMsg)
        )
        error = parser.OFPErrorMsg(
            None, type_=ofp.OFPET_BAD_MATCH, code=ofp.OFPBMC_BAD_PREREQ
        )
        error.xid = bundle_add.xid
        errors = self.get_prom("of_errors_total")
        self.assertEqual([], self.valve.oferror(error))
        self.assertEqual(errors + 1, self.get_prom("of_errors_total"))
        self.assertFalse(self.ryu_dp.closed)

    def test_refused_bundle_sent_again(self):
        """Test a refused bundle's flow mods are sent again without one."""
        sent = self.warm_start()
        commit = self.assert_bundled(sent)
        errors = self.get_prom("of_errors_total")
        flow_msgs = self.valve.oferror(commit_error(commit))
        self.assertEqual(errors + 1, self.get_prom("of_errors_total"))
        self.assertTrue(flow_msgs)
        self.assertEqual((1, 0, 1, 0), self.bundle_counts())
        self.assertEqual(0, self.atomic_status())
        resent = self.sent(
            lambda: self.valve.send_flows(self.ryu_dp, flow_msgs, self.mock_time())
        )
        self.assert_not_bundled(resent)
        self.assertEqual(
            [flow_body(ofmsg) for ofmsg in bundled(sent)],
            [flow_body(ofmsg) for ofmsg in resent if valve_of.is_flowmod(ofmsg)],
        )
        self.assertEqual(
            [], self.valve.oferror(commit_error(commit)), msg="refused twice"
        )
        self.assert_not_bundled(self.warm_start(p3_vlans="v100"))

    def test_refused_bundle_after_flows_changed(self):
        """Test a bundle refused after flows changed since reconnects."""
        commit = self.assert_bundled(self.warm_start())
        self.change_flows()
        self.assertIsNone(self.valve.oferror(commit_error(commit)))
        self.assertEqual((1, 0, 1, 0), self.bundle_counts())
        self.assertEqual(0, self.atomic_status())

    def test_disconnect(self):
        """Test a disconnect forgets a bundle the switch has yet to commit."""
        commit = self.assert_bundled(self.warm_start())
        self.valve.datapath_disconnect(self.mock_time())
        self.assertIsNone(self.valve._bundle_resend)  # pylint: disable=protected-access
        self.assertEqual([], self.valve.oferror(commit_error(commit)))
        self.assertEqual((1, 0, 0, 1), self.bundle_counts())
        self.assertEqual(1, self.atomic_status())

    def test_lost_bundles(self):
        """Test bundles lost in a row to disconnections stop bundling."""
        max_lost = self.valve.ATOMIC_WARM_START_MAX_LOST
        p3_vlans = itertools.cycle(("v100,v200", "v100"))
        for _ in range(max_lost - 1):
            self.assert_bundled(self.warm_start(next(p3_vlans)))
            self.assert_not_bundled(self.reconnect())
        # A commit starts the count of bundles lost in a row again.
        commit = self.assert_bundled(self.warm_start(next(p3_vlans)))
        self.valve.bundle_ctrl_reply(commit_reply(commit))
        for _ in range(max_lost):
            self.assert_bundled(self.warm_start(next(p3_vlans)))
            self.assertEqual(1, self.atomic_status())
            self.reconnect()
        self.assertEqual(0, self.atomic_status())
        self.assert_not_bundled(self.warm_start(next(p3_vlans)))
        self.assertEqual((2 * max_lost, 1, 0, 2 * max_lost - 1), self.bundle_counts())

    def test_discarded_bundle(self):
        """Test a bundle discarded before its commit is sent again, and lost.

        The switch makes a new bundle of the adds sent after it discards one,
        so it can commit part of the warm start before the flow mods sent
        again reach it.
        """
        sent = self.warm_start()
        commit = self.assert_bundled(sent)
        (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
        errors = self.get_prom("of_errors_total")
        flow_msgs = self.valve.oferror(open_error(bundle_open, self.ryu_dp))
        self.assertEqual(errors + 1, self.get_prom("of_errors_total"))
        self.assertTrue(flow_msgs)
        self.assertEqual((1, 0, 0, 1), self.bundle_counts())
        self.assertEqual(1, self.atomic_status())
        resent = self.sent(
            lambda: self.valve.send_flows(self.ryu_dp, flow_msgs, self.mock_time())
        )
        self.assert_not_bundled(resent)
        self.assertEqual(
            [flow_body(ofmsg) for ofmsg in bundled(sent)],
            [flow_body(ofmsg) for ofmsg in resent if valve_of.is_flowmod(ofmsg)],
        )
        # The switch times a bundle out once, and what it commits, or fails
        # to, under the bundle's id is not the bundle.
        self.assertEqual([], self.valve.oferror(open_error(bundle_open, self.ryu_dp)))
        self.valve.bundle_ctrl_reply(commit_reply(commit))
        self.assertEqual([], self.valve.oferror(commit_error(commit)))
        self.assertEqual((1, 0, 0, 1), self.bundle_counts())
        self.assertEqual(errors + 3, self.get_prom("of_errors_total"))
        # The next warm start is bundled again.
        commit = self.assert_bundled(self.warm_start(p3_vlans="v100"))
        self.valve.bundle_ctrl_reply(commit_reply(commit))
        self.assertEqual((2, 1, 0, 1), self.bundle_counts())
        self.assertEqual(1, self.atomic_status())

    def test_discarded_bundle_after_flows_changed(self):
        """Test a bundle discarded after flows changed since reconnects, and is lost."""
        sent = self.warm_start()
        commit = self.assert_bundled(sent)
        (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
        self.change_flows()
        self.assertIsNone(self.valve.oferror(open_error(bundle_open, self.ryu_dp)))
        self.assertEqual((1, 0, 0, 0), self.bundle_counts())
        # The switch times a bundle out once, and what it commits under the
        # bundle's id is not the bundle.
        self.assertEqual([], self.valve.oferror(open_error(bundle_open, self.ryu_dp)))
        self.valve.bundle_ctrl_reply(commit_reply(commit))
        self.assertEqual((1, 0, 0, 0), self.bundle_counts())
        # A warm start before the reconnect goes without a bundle.
        self.assert_not_bundled(self.warm_start(p3_vlans="v100"))
        # The connection ends, and the next warm start is bundled again.
        self.assert_not_bundled(self.reconnect())
        self.assertEqual((1, 0, 0, 1), self.bundle_counts())
        self.assertEqual(1, self.atomic_status())
        self.assert_bundled(self.warm_start())

    def test_flow_mods_sent_again_after_discard(self):
        """Test the flow mods sent again leave the flows the warm start would.

        Of a bundle it discarded, the switch commits only the adds sent after
        the timeout, however many there were, before the flow mods sent again
        reach it.
        """
        # p3 gains a VLAN, then loses it again.
        for p3_vlans in ("v100,v200", "v100"):
            before = copy.deepcopy(self.network.tables[self.DP_ID])
            sent = self.warm_start(p3_vlans)
            intended = self.network.tables[self.DP_ID].table_state()
            self.assertNotEqual(intended, before.table_state())
            self.assert_bundled(sent)
            (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
            flow_msgs = self.valve.oferror(open_error(bundle_open, self.ryu_dp))
            first_resent = len(self.ryu_dp.sent)
            self.valve.send_flows(self.ryu_dp, flow_msgs, self.mock_time())
            resent = self.ryu_dp.sent[first_resent:]
            flow_mods = bundled(sent)
            for timed_out in range(len(flow_mods) + 1):
                table = copy.deepcopy(before)
                table.apply_ofmsgs(flow_mods[timed_out:] + resent)
                self.assertEqual(
                    intended, table.table_state(), msg=(p3_vlans, timed_out)
                )

    def test_discarded_bundles(self):
        """Test bundles discarded in a row stop bundling, as lost ones do."""
        max_lost = self.valve.ATOMIC_WARM_START_MAX_LOST
        p3_vlans = itertools.cycle(("v100,v200", "v100"))
        for lost in range(max_lost):
            self.assertEqual(1, self.atomic_status())
            sent = self.warm_start(next(p3_vlans))
            self.assert_bundled(sent)
            (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
            flow_msgs = self.valve.oferror(open_error(bundle_open, self.ryu_dp))
            self.assertTrue(flow_msgs)
            self.valve.send_flows(self.ryu_dp, flow_msgs, self.mock_time())
            self.assertEqual((lost + 1, 0, 0, lost + 1), self.bundle_counts())
        self.assertEqual(0, self.atomic_status())
        self.assert_not_bundled(self.warm_start(next(p3_vlans)))
        self.assertEqual((max_lost, 0, 0, max_lost), self.bundle_counts())

    def test_open_refused(self):
        """Test a switch that refuses the bundle's open refuses it at the commit.

        A switch that cannot take a bundle, as one without bundles or a
        connection in the secondary role, answers each of its messages with
        an error, in the order they were sent.
        """
        sent = self.warm_start()
        commit = self.assert_bundled(sent)
        bundle = [
            ofmsg
            for ofmsg in sent
            if isinstance(ofmsg, (parser.ONFBundleCtrlMsg, parser.ONFBundleAddMsg))
        ]
        errors = self.get_prom("of_errors_total")
        error = parser.OFPErrorMsg(
            None, type_=ofp.OFPET_BAD_REQUEST, code=ofp.OFPBRC_IS_SLAVE
        )
        error.datapath = self.ryu_dp
        for ofmsg in bundle[:-1]:
            error.xid = ofmsg.xid
            self.assertEqual([], self.valve.oferror(error))
        self.assertEqual((1, 0, 0, 0), self.bundle_counts())
        error.xid = commit.xid
        self.assertTrue(self.valve.oferror(error), msg="refused, not sent again")
        self.assertEqual(errors + len(bundle), self.get_prom("of_errors_total"))
        self.assertEqual((1, 0, 1, 0), self.bundle_counts())
        self.assertEqual(0, self.atomic_status())

    def test_open_error_then_commit(self):
        """Test the commit tells after an error on the open other than a timeout.

        A switch that already has a bundle of the id refuses the open, and
        discards that bundle, then makes a new one of the adds after the
        open, so of all of the warm start, which it commits.
        """
        sent = self.warm_start()
        commit = self.assert_bundled(sent)
        (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
        error = open_error(bundle_open, self.ryu_dp)
        error.exp_type = ofp.ONFERR_ET_BAD_ID
        self.assertEqual([], self.valve.oferror(error))
        self.valve.bundle_ctrl_reply(commit_reply(commit))
        self.assertEqual((1, 1, 0, 0), self.bundle_counts())
        self.assertEqual(1, self.atomic_status())

    def test_errors_on_bundle_connection(self):
        """Test other errors on the bundle's connection are handled as before."""
        sent = self.warm_start()
        self.assert_bundled(sent)
        bundle_add = next(
            ofmsg for ofmsg in sent if isinstance(ofmsg, parser.ONFBundleAddMsg)
        )
        error = parser.OFPErrorMsg(
            None, type_=ofp.OFPET_BAD_MATCH, code=ofp.OFPBMC_BAD_PREREQ
        )
        error.xid = bundle_add.xid
        error.datapath = self.ryu_dp
        self.assertEqual([], self.valve.oferror(error))
        self.assertEqual((1, 0, 0, 0), self.bundle_counts())
        # Nor is another experimenter's error of the timeout's type on the open.
        (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
        error = open_error(bundle_open, self.ryu_dp)
        error.experimenter = ofproto_common.NX_EXPERIMENTER_ID
        self.assertEqual([], self.valve.oferror(error))
        # Nor a timeout that answers an add: the switch answers with the
        # message that made the bundle, so that is one it made of adds.
        self.assertEqual([], self.valve.oferror(open_error(bundle_add, self.ryu_dp)))
        self.assertEqual((1, 0, 0, 0), self.bundle_counts())
        # The timeout that answers the bundle's open still discards it.
        self.assertTrue(self.valve.oferror(open_error(bundle_open, self.ryu_dp)))
        # Refused, a bundle's open has no answer to wait for.
        sent = self.warm_start(p3_vlans="v100")
        error = commit_error(self.assert_bundled(sent))
        error.datapath = self.ryu_dp
        self.assertTrue(self.valve.oferror(error), msg="refused, not sent again")
        (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
        self.assertEqual([], self.valve.oferror(open_error(bundle_open, self.ryu_dp)))
        self.assertEqual((2, 0, 1, 1), self.bundle_counts())
        self.assertEqual(0, self.atomic_status())

    def test_atomic_warm_start_hardware(self):
        """Test atomic_warm_start is refused on hardware without bundles."""
        self.update_config(
            config(self.OPTIONS, hardware="GenericTFM"),
            reload_expected=False,
            error_expected=1,
        )


class ValveAtomicColdAndWarmStartTestCase(ValveAtomicWarmStartTestBase):
    """Test atomic cold and warm starts on one DP."""

    OPTIONS = ("atomic_cold_start", "atomic_warm_start")

    def test_warm_start_after_cold_start(self):
        """Test a warm start bundles behind the cold start's bundle, and after it."""
        self.valve.datapath_disconnect(self.mock_time())
        sent = self.sent(
            lambda: self.valve.send_flows(
                self.ryu_dp,
                self.valve.datapath_connect(self.mock_time(), {1, 2, 3, 4}),
                self.mock_time(),
            )
        )
        cold_commit = self.assert_bundled(sent)
        # Behind the cold start's bundle, which the switch commits first.
        behind = self.assert_bundled(self.warm_start())
        self.assertGreater(behind.bundle_id, cold_commit.bundle_id)
        self.valve.bundle_ctrl_reply(commit_reply(cold_commit))
        self.valve.bundle_ctrl_reply(commit_reply(behind))
        commit = self.assert_bundled(self.warm_start(p3_vlans="v100"))
        self.assertGreater(commit.bundle_id, behind.bundle_id)
        self.assertEqual((1, 1, 0, 0), self.bundle_counts("cold"))
        self.assertEqual((2, 1, 0, 0), self.bundle_counts())
        self.assertTrue(self.valve.oferror(commit_error(commit)))
        self.assertEqual((1, 1, 0, 0), self.bundle_counts("cold"))
        self.assertEqual((2, 1, 1, 0), self.bundle_counts())
        self.assertEqual(1, self.atomic_status("cold"))
        self.assertEqual(0, self.atomic_status())
        self.valve.datapath_disconnect(self.mock_time())
        cold_start = self.valve.switch_features(None) + self.valve.datapath_connect(
            self.mock_time(), {1, 2, 3, 4}
        )
        self.assert_bundled(
            self.sent(
                lambda: self.valve.send_flows(self.ryu_dp, cold_start, self.mock_time())
            )
        )

    def test_lost_by_restart_type(self):
        """Test warm start bundles are lost in a row whatever cold starts commit."""
        max_lost = self.valve.ATOMIC_WARM_START_MAX_LOST
        p3_vlans = itertools.cycle(("v100,v200", "v100"))
        cold_commit = self.assert_bundled(self.reconnect())
        for _ in range(max_lost):
            self.valve.bundle_ctrl_reply(commit_reply(cold_commit))
            self.assertEqual(1, self.atomic_status())
            self.assert_bundled(self.warm_start(next(p3_vlans)))
            cold_commit = self.assert_bundled(self.reconnect())
        self.assertEqual(0, self.atomic_status())
        self.assertEqual(1, self.atomic_status("cold"))
        self.assertEqual((max_lost, 0, 0, max_lost), self.bundle_counts())
        self.assertEqual((max_lost + 1, max_lost, 0, 0), self.bundle_counts("cold"))

    def cold_start_on(self, ryu_dp, features=()):
        """Cold start the DP on connection ryu_dp, and return what it is sent."""
        self.ryu_dp = ryu_dp
        return self.sent(
            lambda: self.valve.send_flows(
                ryu_dp,
                list(features)
                + self.valve.datapath_connect(self.mock_time(), {1, 2, 3, 4}, ryu_dp),
                self.mock_time(),
            )
        )

    def connect_again(self):
        """Return a new connection from the switch, once it sends its features.

        A switch that connects again before its old connection is seen to end
        has that connection replaced with no disconnection, so the DP is
        still up when the new connection sends its features.
        """
        new_dp = FakeDatapath(first_xid=1000)
        features = self.valve.switch_features(mock.Mock(datapath=new_dp))
        self.assertTrue(self.valve.dp.dyn_running)
        return new_dp, features

    def test_reload_on_old_connection_while_connecting_again(self):
        """Test a bundle sent on a connection that is being replaced is lost.

        faucet sends on the old connection until os_ken registers the new
        one, so a reload just after the new one's features warm starts the
        DP on the old connection.
        """
        new_dp, features = self.connect_again()
        warm_commit = self.assert_bundled(self.warm_start())
        self.assertEqual((1, 0, 0, 0), self.bundle_counts())
        cold_commit = self.assert_bundled(self.cold_start_on(new_dp, features))
        self.assertEqual((1, 0, 0, 1), self.bundle_counts())
        self.assertEqual((1, 0, 0, 0), self.bundle_counts("cold"))
        # A late answer on the old connection is not counted.
        self.valve.bundle_ctrl_reply(commit_reply(warm_commit))
        self.valve.bundle_ctrl_reply(commit_reply(cold_commit))
        self.assertEqual((1, 0, 0, 1), self.bundle_counts())
        self.assertEqual((1, 1, 0, 0), self.bundle_counts("cold"))
        self.assertEqual(1, self.atomic_status())

    def test_reload_on_new_connection_while_connecting_again(self):
        """Test a reload on a new connection leaves its cold start bundled.

        Once os_ken registers the new connection, faucet sends on it, and a
        reload before faucet handles the reconnection warm starts the DP
        there, ahead of the cold start that replaces its flows.
        """
        new_dp, features = self.connect_again()
        self.ryu_dp = new_dp
        self.assert_not_bundled(self.warm_start())
        commit = self.assert_bundled(self.cold_start_on(new_dp, features))
        self.assertEqual((0, 0, 0, 0), self.bundle_counts())
        self.valve.bundle_ctrl_reply(commit_reply(commit))
        self.assertEqual((1, 1, 0, 0), self.bundle_counts("cold"))
        # Cold started, the DP is warm started in a bundle again.
        self.assert_bundled(self.warm_start(p3_vlans="v100"))
        self.assertEqual((1, 0, 0, 0), self.bundle_counts())
        self.assertEqual(1, self.atomic_status())

    def test_cold_start_on_new_connection_loses_bundle(self):
        """Test cold starting a new connection loses a bundle on the old one.

        faucet can cold start the old connection after the new one's switch
        features, and then warm start the DP on it, before it cold starts
        the new connection.
        """
        old_dp = self.ryu_dp
        new_dp, features = self.connect_again()
        cold_commit = self.assert_bundled(self.cold_start_on(old_dp))
        self.valve.bundle_ctrl_reply(commit_reply(cold_commit))
        warm_commit = self.assert_bundled(self.warm_start())
        self.assertEqual((1, 0, 0, 0), self.bundle_counts())
        cold_commit = self.assert_bundled(self.cold_start_on(new_dp, features))
        self.assertEqual((1, 0, 0, 1), self.bundle_counts())
        self.assertEqual((2, 1, 0, 0), self.bundle_counts("cold"))
        # A late answer on the old connection is not counted, nor sent again.
        self.assertEqual([], self.valve.oferror(commit_error(warm_commit)))
        self.valve.bundle_ctrl_reply(commit_reply(warm_commit))
        self.assertEqual((1, 0, 0, 1), self.bundle_counts())
        self.valve.bundle_ctrl_reply(commit_reply(cold_commit))
        self.assertEqual((2, 2, 0, 0), self.bundle_counts("cold"))
        self.assertEqual(1, self.atomic_status())

    def test_old_connection_commits_while_connecting_again(self):
        """Test a bundle the old connection commits before the cold start counts.

        os_ken registers the new connection before faucet cold starts it, so
        faucet can send on it while the old connection's answer to a bundle
        still waits to be handled.
        """
        new_dp, features = self.connect_again()
        warm_commit = self.assert_bundled(self.warm_start())
        flowmods = [self.valve.dp.tables["vlan"].flowdrop(priority=1)]
        self.valve.send_flows(new_dp, flowmods, self.mock_time())
        self.assertEqual((1, 0, 0, 0), self.bundle_counts())
        self.valve.bundle_ctrl_reply(commit_reply(warm_commit))
        self.assertEqual((1, 1, 0, 0), self.bundle_counts())
        self.assert_bundled(self.cold_start_on(new_dp, features))
        self.assertEqual((1, 1, 0, 0), self.bundle_counts())
        self.assertEqual((1, 0, 0, 0), self.bundle_counts("cold"))

    def test_cold_start_on_old_connection_while_connecting_again(self):
        """Test the old connection's cold start leaves the new one's bundled.

        faucet can cold start the old connection after the new one's switch
        features, and then reload once os_ken has registered the new one,
        before it cold starts that.
        """
        for commit in (True, False):
            old_dp = self.ryu_dp
            new_dp, features = self.connect_again()
            cold_commit = self.assert_bundled(self.cold_start_on(old_dp))
            if commit:
                self.valve.bundle_ctrl_reply(commit_reply(cold_commit))
            self.ryu_dp = new_dp
            self.assert_not_bundled(self.warm_start(("v100", "v100,v200")[commit]))
            self.valve.bundle_ctrl_reply(
                commit_reply(self.assert_bundled(self.cold_start_on(new_dp, features)))
            )
        self.assertEqual((0, 0, 0, 0), self.bundle_counts())
        self.assertEqual((4, 3, 0, 1), self.bundle_counts("cold"))
        self.assertEqual(1, self.atomic_status())

    def test_discarded_cold_start_bundle(self):
        """Test a cold start's bundle discarded before its commit is lost.

        Reconnecting, the cold start is bundled again, and the warm starts'
        bundles are counted on their own.
        """
        sent = self.reconnect()
        self.assert_bundled(sent)
        (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
        self.assertIsNone(self.valve.oferror(open_error(bundle_open, self.ryu_dp)))
        self.assertEqual((1, 0, 0, 0), self.bundle_counts("cold"))
        # Until the connection ends, the bundle is still the switch's.
        self.assert_not_bundled(self.warm_start())
        cold_commit = self.assert_bundled(self.reconnect())
        self.assertEqual((2, 0, 0, 1), self.bundle_counts("cold"))
        self.valve.bundle_ctrl_reply(commit_reply(cold_commit))
        self.assertEqual((2, 1, 0, 1), self.bundle_counts("cold"))
        self.assertEqual((0, 0, 0, 0), self.bundle_counts())
        self.assertEqual(1, self.atomic_status("cold"))
        self.assertEqual(1, self.atomic_status())

    def test_open_error_on_old_connection(self):
        """Test only an answer on the bundle's own connection discards it.

        A switch that connects again before its old connection is seen to end
        has that connection replaced. Each connection numbers its messages
        from its own xid, so an answer from the old one still to be handled
        can carry the xid of the open of a bundle on the new one.
        """
        old_dp = self.ryu_dp
        new_dp, features = self.connect_again()
        sent = self.cold_start_on(new_dp, features)
        cold_commit = self.assert_bundled(sent)
        (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
        self.assertEqual([], self.valve.oferror(open_error(bundle_open, old_dp)))
        self.valve.bundle_ctrl_reply(commit_reply(cold_commit))
        self.assertEqual((1, 1, 0, 0), self.bundle_counts("cold"))
        sent = self.warm_start()
        self.assert_bundled(sent)
        (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
        self.assertEqual([], self.valve.oferror(open_error(bundle_open, old_dp)))
        self.assertEqual((1, 0, 0, 0), self.bundle_counts())
        # The new connection's timeout on the open discards the bundle.
        self.assertTrue(self.valve.oferror(open_error(bundle_open, new_dp)))
        self.assertEqual((1, 0, 0, 1), self.bundle_counts())
        self.assertEqual((1, 1, 0, 0), self.bundle_counts("cold"))

    def test_lost_to_new_connections(self):
        """Test warm start bundles lost in a row to new connections stop bundling."""
        max_lost = self.valve.ATOMIC_WARM_START_MAX_LOST
        p3_vlans = itertools.cycle(("v100,v200", "v100"))
        for lost in range(max_lost + 1):
            cold = self.cold_start_on(FakeDatapath(first_xid=1000 * (lost + 1)))
            self.assertEqual((lost, 0, 0, lost), self.bundle_counts())
            # Losing a warm start's bundle leaves the cold start bundled.
            self.valve.bundle_ctrl_reply(commit_reply(self.assert_bundled(cold)))
            if lost < max_lost:
                self.assertEqual(1, self.atomic_status())
                self.assert_bundled(self.warm_start(next(p3_vlans)))
        self.assertEqual(0, self.atomic_status())
        self.assertEqual(1, self.atomic_status("cold"))
        self.assert_not_bundled(self.warm_start(next(p3_vlans)))
        self.assertEqual((max_lost, 0, 0, max_lost), self.bundle_counts())
        self.assertEqual((max_lost + 1, max_lost + 1, 0, 0), self.bundle_counts("cold"))


class FaucetBundleHandlersTestCase(unittest.TestCase):  # pytype: disable=module-attr
    """Test faucet acting on a bundle's answers."""

    def setUp(self):
        """Set up faucet with one mock valve."""
        os.environ["FAUCET_CONFIG"] = "/dev/null"
        os.environ["FAUCET_LOG"] = "/dev/null"
        os.environ["FAUCET_EXCEPTION_LOG"] = "/dev/null"
        self.os_ken_app = faucet.Faucet(dpset={}, reg=CollectorRegistry())
        self.valve = mock.Mock()
        self.ryu_dp = mock.Mock()
        self.msg = mock.Mock()
        self.os_ken_app._get_valve = mock.Mock(  # pylint: disable=protected-access
            return_value=(self.valve, self.ryu_dp, self.msg)
        )

    def _error_sends(self, oferror):
        self.valve.oferror.return_value = oferror
        with mock.patch.object(self.os_ken_app, "_send_flow_msgs") as send_flow_msgs:
            self.os_ken_app.error_handler(None)
        self.valve.oferror.assert_called_once_with(self.msg)
        self.valve.oferror.reset_mock()
        return send_flow_msgs

    def test_error_handler(self):
        """Test a refused bundle's flow mods are sent again, or reconnect."""
        flow_msgs = [valve_of.barrier()]
        self._error_sends(flow_msgs).assert_called_once_with(
            self.valve, flow_msgs, ryu_dp=self.ryu_dp
        )
        self._error_sends([]).assert_not_called()
        # Valve.send_flows() ends the connection, as for a cold reload.
        self._error_sends(None).assert_called_once_with(
            self.valve, None, ryu_dp=self.ryu_dp
        )

    def test_bundle_ctrl_handler(self):
        """Test a bundle control reply goes to its valve."""
        self.os_ken_app.bundle_ctrl_handler(None)
        self.valve.bundle_ctrl_reply.assert_called_once_with(self.msg)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
