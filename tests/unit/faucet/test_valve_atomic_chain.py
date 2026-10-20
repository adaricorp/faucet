#!/usr/bin/env python3

"""Unit tests for a bundle sent behind one the switch has yet to commit."""

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

from faucet import valves_manager as valves_manager_module

from tests.unit.faucet.test_valve_atomic_unread import (
    ValveAtomicUnreadTestBase,
    commit_reply_on,
)
from tests.unit.faucet.test_valve_atomic_warm_start import (
    FakeDatapath,
    ValveAtomicWarmStartTestBase,
    bundle_ctrls,
    commit_error,
    commit_reply,
    open_error,
)


class ValveAtomicChainTestCase(ValveAtomicWarmStartTestBase):
    """Test warm starts sent in bundles behind one in flight."""

    def end_connection(self):
        """End the connection, as faucet does when oferror() returns None."""
        self.valve.send_flows(self.ryu_dp, None, self.mock_time())
        self.assertTrue(self.ryu_dp.closed)

    def abandoned(self):
        """Return the warm start bundles lost to a connection faucet ended."""
        return int(self.get_prom("faucet_warm_start_bundles_abandoned_total"))

    def test_warm_starts_in_turn(self):
        """Test a warm start sent before the switch commits the last is bundled.

        The switch commits the bundle in flight before it reads the next
        one's open, so commits each whole, in turn.
        """
        first = self.assert_bundled(self.warm_start())
        second = self.assert_bundled(self.warm_start(p3_vlans="v100"))
        third = self.assert_bundled(self.warm_start())
        self.assertLess(first.bundle_id, second.bundle_id)
        self.assertLess(second.bundle_id, third.bundle_id)
        self.assertEqual((3, 0, 0, 0), self.bundle_counts())
        for commit, committed in ((first, 1), (second, 2), (third, 3)):
            self.valve.bundle_ctrl_reply(commit_reply(commit))
            self.assertEqual((3, committed, 0, 0), self.bundle_counts())
        self.assertEqual(1, self.atomic_status())
        # Only the last bundle's flow mods can be sent again: the switch
        # refusing it has the flows the earlier ones left.
        fourth = self.assert_bundled(self.warm_start(p3_vlans="v100"))
        fifth = self.assert_bundled(self.warm_start())
        self.valve.bundle_ctrl_reply(commit_reply(fourth))
        self.assertTrue(self.valve.oferror(commit_error(fifth)))
        self.assertEqual((5, 4, 1, 0), self.bundle_counts())

    def test_collect_after_last_bundle(self):
        """Test reloads' replaced configs are collected after the last bundle."""
        with mock.patch.object(
            valves_manager_module, "collect_garbage"
        ) as collect_garbage:
            first = self.assert_bundled(self.warm_start())
            second = self.assert_bundled(self.warm_start(p3_vlans="v100"))
            self.valve.bundle_ctrl_reply(commit_reply(first))
            self.valves_manager.valve_flow_services(
                self.mock_time(0), "fast_state_expire"
            )
            collect_garbage.assert_not_called()
            self.valve.bundle_ctrl_reply(commit_reply(second))
            self.valves_manager.valve_flow_services(
                self.mock_time(0), "fast_state_expire"
            )
            collect_garbage.assert_called_once_with()

    def test_refused_bundle_ahead(self):
        """Test a bundle refused with a later bundle behind it reconnects.

        The later bundle changed the flows the refused one was built to
        leave, so the switch has neither's, and the later one's flow mods
        cannot be sent again. faucet ends the connection before it reads
        whether the switch committed the later one.
        """
        commit = self.assert_bundled(self.warm_start())
        later = self.assert_bundled(self.warm_start(p3_vlans="v100"))
        errors = self.get_prom("of_errors_total")
        self.assertIsNone(self.valve.oferror(commit_error(commit)))
        self.assertEqual(errors + 1, self.get_prom("of_errors_total"))
        self.assertEqual((2, 0, 1, 0), self.bundle_counts())
        self.assertEqual(0, self.atomic_status())
        self.assertEqual([], self.valve.oferror(commit_error(commit)))
        self.end_connection()
        # The later bundle is the switch's until the connection ends.
        self.assert_not_bundled(self.reconnect())
        self.valve.bundle_ctrl_reply(commit_reply(later))
        self.assertEqual((2, 0, 1, 1), self.bundle_counts())
        self.assertEqual(1, self.abandoned())

    def test_discarded_bundle_ahead(self):
        """Test a bundle discarded with a later bundle behind it reconnects.

        Both are lost with the connection, the discarded one toward those
        lost in a row, and the later one, whose answer faucet ends the
        connection before reading, not.
        """
        sent = self.warm_start()
        commit = self.assert_bundled(sent)
        (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
        self.assert_bundled(self.warm_start(p3_vlans="v100"))
        self.assertIsNone(self.valve.oferror(open_error(bundle_open, self.ryu_dp)))
        self.assertEqual((2, 0, 0, 0), self.bundle_counts())
        self.valve.bundle_ctrl_reply(commit_reply(commit))
        self.assertEqual([], self.valve.oferror(commit_error(commit)))
        self.assertEqual((2, 0, 0, 0), self.bundle_counts())
        self.end_connection()
        self.assertEqual((2, 0, 0, 1), self.bundle_counts())
        self.assert_not_bundled(self.reconnect())
        self.assertEqual((2, 0, 0, 2), self.bundle_counts())
        self.assertEqual(1, self.abandoned())
        self.assertEqual(
            1, self.valve._bundles_lost["warm"]  # pylint: disable=protected-access
        )
        self.assertEqual(1, self.atomic_status())

    def test_warm_start_to_another_connection(self):
        """Test a warm start to another connection than the bundle's is not bundled.

        The switch commits bundles in turn on one connection only.
        """
        self.assert_bundled(self.warm_start())
        self.ryu_dp = FakeDatapath(first_xid=1000)
        self.assert_not_bundled(self.warm_start(p3_vlans="v100"))
        self.assertEqual((1, 0, 0, 0), self.bundle_counts())


class ValveAtomicChainUnreadTestCase(ValveAtomicUnreadTestBase):
    """Test bundles in flight when faucet ends their connection."""

    def test_cold_reload_with_bundles_in_turn(self):
        """Test a cold reload leaves every bundle in flight unread.

        The switch answers them in turn, before the end of the connection, or
        faucet counts those unanswered lost, and none toward those in a row.
        """
        for answered in (2, 1, 0):
            old_dp = self.ryu_dp
            commits = [
                self.assert_bundled(self.warm_start(p3_vlans))
                for p3_vlans in ("v100,v200", "v100")
            ]
            self.cold_reload()
            for commit in commits[:answered]:
                self.valve.bundle_ctrl_reply(commit_reply_on(commit, old_dp))
            before = self.bundle_counts()
            self.valve.datapath_disconnect(self.mock_time())
            self.assertEqual(before[3] + 2 - answered, self.bundle_counts()[3])
            self.connect(first_xid=1000 * (answered + 1))
            # Back to the first config, through another cold reload.
            self.cold_reload(p3_vlans="v100")
            self.valve.datapath_disconnect(self.mock_time())
            self.connect(first_xid=1000 * (answered + 1) + 500)
        self.assertEqual((6, 3, 0, 3), self.bundle_counts())
        self.assertEqual(3, self.abandoned())
        self.assertEqual(1, self.atomic_status())


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
