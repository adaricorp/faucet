#!/usr/bin/env python3

"""Unit tests for the memory a cold or warm start's bundle holds."""

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
from unittest import mock

from os_ken.ofproto import ofproto_v1_3 as ofp
from os_ken.ofproto import ofproto_v1_3_parser as parser

from faucet import valve as valve_module
from faucet import valve_of
from faucet import valves_manager as valves_manager_module

from tests.unit.faucet.test_valve_atomic_warm_start import (
    ValveAtomicWarmStartTestBase,
    bundle_ctrls,
    bundled,
    commit_error,
    commit_reply,
    flow_body,
    open_error,
)


class ValveBundleOfmsgsTestCase(unittest.TestCase):  # pytype: disable=module-attr
    """Test a bundle's messages are made as they are sent."""

    def test_lazy(self):
        """Test the flow mods are wrapped, themselves, as each is reached."""
        flowmods = [
            valve_of.flowmod(
                cookie=0,
                command=ofp.OFPFC_ADD,
                table_id=table_id,
                priority=1,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                match_fields=valve_of.match({"in_port": table_id + 1}),
                inst=(),
                hard_timeout=0,
                idle_timeout=0,
            )
            for table_id in range(3)
        ]
        ofmsgs = [valve_of.faucet_config()] + flowmods + [valve_of.faucet_async()]
        for xid, flowmod in enumerate(flowmods, start=1):
            flowmod.xid = xid
        lazy = valve_of.bundle_ofmsgs_lazy(ofmsgs, 9)
        assert lazy is not None
        count, messages = lazy
        self.assertEqual(2 + 3 + 3, count)
        self.assertIs(ofmsgs[0], next(messages))
        bundle_open = next(messages)
        self.assertEqual(ofp.ONF_BCT_OPEN_REQUEST, bundle_open.type)
        first = next(messages)
        self.assertIsInstance(first, parser.ONFBundleAddMsg)
        self.assertIs(flowmods[0], first.message)
        self.assertIsNone(flowmods[0].xid)
        # Not yet reached.
        self.assertEqual(2, flowmods[1].xid)
        rest = list(messages)
        self.assertEqual(count, 3 + len(rest))
        self.assertEqual(flowmods[1:], [ofmsg.message for ofmsg in rest[:2]])
        self.assertEqual(
            [str(ofmsg) for ofmsg in valve_of.bundle_ofmsgs(ofmsgs, 9)],
            [str(ofmsg) for ofmsg in [ofmsgs[0], bundle_open, first] + rest],
        )
        self.assertIsNone(valve_of.bundle_ofmsgs_lazy(ofmsgs[:1], 9))
        self.assertIsNone(
            valve_of.bundle_ofmsgs_lazy(flowmods + [valve_of.groupdel()], 9)
        )


class ValveBundleMemoryTestCase(ValveAtomicWarmStartTestBase):
    """Test a warm start's bundle holds its flow mods once."""

    def resend(self):
        """Return the flow mods the valve keeps to send again."""
        return self.valve._bundle_resend  # pylint: disable=protected-access

    def test_flow_mods_bundled_themselves(self):
        """Test the bundle wraps the flow mods kept to send again, not copies."""
        sent = self.warm_start()
        self.assert_bundled(sent)
        inner = bundled(sent)
        self.assertTrue(inner)
        self.assertEqual(len(self.resend()), len(inner))
        for flow_mod, bundled_flow_mod in zip(self.resend(), inner):
            self.assertIs(flow_mod, bundled_flow_mod)

    def assert_sent_again(self, sent, flow_msgs):
        """Assert flow_msgs, sent again, are sent's flow mods with new xids."""
        for flow_msg in flow_msgs:
            self.assertIsNone(flow_msg.xid)
            self.assertIsNone(flow_msg.buf)
        bundle_xids = {
            ofmsg.xid
            for ofmsg in sent
            if isinstance(ofmsg, (parser.ONFBundleAddMsg, parser.ONFBundleCtrlMsg))
        }
        resent = self.sent(
            lambda: self.valve.send_flows(self.ryu_dp, flow_msgs, self.mock_time())
        )
        self.assert_not_bundled(resent)
        resent_flow_mods = [ofmsg for ofmsg in resent if valve_of.is_flowmod(ofmsg)]
        self.assertFalse(bundle_xids & {ofmsg.xid for ofmsg in resent_flow_mods})
        self.assertEqual(
            sorted(flow_body(ofmsg) for ofmsg in bundled(sent)),
            sorted(flow_body(ofmsg) for ofmsg in resent_flow_mods),
        )

    def test_refused_bundle_sent_again(self):
        """Test a refused bundle's flow mods go again with xids of their own."""
        sent = self.warm_start()
        commit = self.assert_bundled(sent)
        self.assert_sent_again(sent, self.valve.oferror(commit_error(commit)))

    def test_discarded_bundle_sent_again(self):
        """Test a discarded bundle's flow mods go again with xids of their own."""
        sent = self.warm_start()
        self.assert_bundled(sent)
        (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
        self.assert_sent_again(
            sent, self.valve.oferror(open_error(bundle_open, self.ryu_dp))
        )


class ValveTrimMemoryTestCase(ValveAtomicWarmStartTestBase):
    """Test faucet hands memory back after a large start."""

    def test_after_commit(self):
        """Test memory is handed back once the switch commits a bundle."""
        with mock.patch.object(valve_module, "_trim_memory") as trim_memory:
            commit = self.assert_bundled(self.warm_start())
            trim_memory.assert_not_called()
            self.valve.bundle_ctrl_reply(commit_reply(commit))
            trim_memory.assert_called_once_with()
            self.valve.bundle_ctrl_reply(commit_reply(commit))
            trim_memory.assert_called_once_with()

    def test_after_unbundled_send(self):
        """Test memory is handed back after a large send without a bundle."""
        self.setup_again(())
        for trim_after, calls in ((10**6, 0), (10, 1)):
            # Not the collection the reload asks for, which trims too.
            with mock.patch.object(
                valve_module.Valve, "TRIM_AFTER_FLOW_MSGS", trim_after
            ), mock.patch.object(
                valves_manager_module, "collect_garbage"
            ), mock.patch.object(
                valve_module, "_trim_memory"
            ) as trim_memory:
                sent = self.warm_start(
                    p3_vlans=("v100,v200", "v100")[calls], options=()
                )
                self.assert_not_bundled(sent)
                self.assertGreater(len(sent), 10)
                self.assertEqual(calls, trim_memory.call_count)

    def test_without_glibc(self):
        """Test handing memory back, with or without glibc, collects no garbage."""
        with mock.patch("gc.collect") as collect:
            for error in (OSError("no libc.so.6"), AttributeError("malloc_trim")):
                with mock.patch.object(valve_module.ctypes, "CDLL", side_effect=error):
                    valve_module._trim_memory()  # pylint: disable=protected-access
            with mock.patch.object(valve_module.ctypes, "CDLL") as cdll:
                valve_module._trim_memory()  # pylint: disable=protected-access
                cdll.return_value.malloc_trim.assert_called_once_with(0)
            collect.assert_not_called()


class ValveCollectReplacedConfigsTestCase(ValveAtomicWarmStartTestBase):
    """Test faucet collects the configs reloads replace, once no bundle waits."""

    def collect_garbage(self):
        """Return a mock of the garbage collection a reload asks for."""
        return mock.patch.object(valves_manager_module, "collect_garbage")

    def services(self):
        """Run a periodic service, as faucet does every few seconds."""
        self.valves_manager.valve_flow_services(self.mock_time(0), "fast_state_expire")

    def test_after_bundle_answered(self):
        """Test a reload collects once the switch commits its bundle."""
        with self.collect_garbage() as collect_garbage:
            commit = self.assert_bundled(self.warm_start())
            self.services()
            collect_garbage.assert_not_called()
            self.valve.bundle_ctrl_reply(commit_reply(commit))
            collect_garbage.assert_not_called()
            self.services()
            collect_garbage.assert_called_once_with()
            self.services()
            collect_garbage.assert_called_once_with()

    def test_after_bundle_lost(self):
        """Test a reload collects once its bundle's connection is gone."""
        with self.collect_garbage() as collect_garbage:
            self.assert_bundled(self.warm_start())
            self.valve.datapath_disconnect(self.mock_time())
            collect_garbage.assert_not_called()
            self.services()
            collect_garbage.assert_called_once_with()

    def test_without_bundle(self):
        """Test a reload that sends no bundle collects at once."""
        self.setup_again(())
        with self.collect_garbage() as collect_garbage:
            self.assert_not_bundled(self.warm_start(options=()))
            collect_garbage.assert_called_once_with()
            self.services()
            collect_garbage.assert_called_once_with()

    def test_collect_garbage(self):
        """Test the collection hands the memory it frees back to the OS."""
        calls = mock.Mock()
        with mock.patch("gc.collect", calls.collect), mock.patch.object(
            valve_module, "_trim_memory", calls.trim
        ):
            valve_module.collect_garbage()
        self.assertEqual([mock.call.collect(), mock.call.trim()], calls.mock_calls)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
