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

from os_ken.ofproto import ofproto_v1_3 as ofp
from os_ken.ofproto import ofproto_v1_3_parser as parser

from faucet import valve_of

from tests.unit.faucet.test_valve_atomic_warm_start import (
    ValveAtomicWarmStartTestBase,
    bundle_ctrls,
    bundled,
    commit_error,
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


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
