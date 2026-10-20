#!/usr/bin/env python3

"""Unit tests for a bundle whose connection faucet ends before it reads its answer."""

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

from functools import partial
import itertools
import unittest

from os_ken.ofproto import ofproto_v1_3 as ofp

from tests.unit.faucet.test_valve_atomic_warm_start import (
    FakeDatapath,
    ValveAtomicWarmStartTestBase,
    bundle_ctrls,
    bundled,
    commit_error,
    commit_reply,
    config,
    open_error,
)


def timeout_config(options, p3_vlans, timeout):
    """Return config() with the DP's timeout set, if timeout is not None."""
    text = config(options, p3_vlans=p3_vlans)
    if timeout is None:
        return text
    # A change to the DP's own timeout cold starts it.
    return text.replace("dp_id: 1\n", "dp_id: 1\n        timeout: %u\n" % timeout)


def commit_reply_on(commit, ryu_dp):
    """Return the reply a switch answers a commit it applies with, on ryu_dp."""
    reply = commit_reply(commit)
    reply.datapath = ryu_dp
    return reply


class ValveAtomicUnreadTestBase(ValveAtomicWarmStartTestBase):
    """Reload to cold start, which ends the connection a bundle was sent on."""

    def __init__(self, *args, **kwargs):
        self.dp_timeout = None
        super().__init__(*args, **kwargs)

    def setup(self, options):
        """Set up the valves with DP options set to true."""
        self.dp_timeout = None
        super().setup(options)

    def abandoned(self, restart_type="warm"):
        """Return the lost bundles whose connection faucet ended unanswered."""
        return int(
            self.get_prom("faucet_%s_start_bundles_abandoned_total" % restart_type)
        )

    def warm_start(self, p3_vlans="v100,v200", options=None):
        """Warm start onto p3 tagged on p3_vlans, and return what is sent."""
        if options is None:
            options = self.OPTIONS
        return self.sent(
            lambda: self.update_config(
                timeout_config(options, p3_vlans, self.dp_timeout),
                reload_type="warm",
            )
        )

    def cold_reload(self, p3_vlans="v100,v200"):
        """Reload to a config that cold starts the DP, and return what is sent.

        faucet ends the connection itself, to cold start the DP when the
        switch connects again, and the switch's answers that the connection
        received before it ended are handled after the reload.
        """
        self.dp_timeout = 600 if self.dp_timeout is None else None
        with open(self.config_file, "w", encoding="utf-8") as config_file:
            config_file.write(timeout_config(self.OPTIONS, p3_vlans, self.dp_timeout))
        old_dp = self.ryu_dp
        sent = self.sent(
            lambda: self.prom_inc(
                partial(
                    self.valves_manager.request_reload_configs,
                    self.mock_time(10),
                    self.config_file,
                ),
                var="faucet_config_reload_cold_total",
            )
        )
        self.assertTrue(old_dp.closed, msg="cold reload did not reconnect")
        return sent

    def connect(self, first_xid):
        """Connect the switch on a new connection, and return what it is sent."""
        self.ryu_dp = FakeDatapath(first_xid=first_xid)
        return self.sent(
            lambda: self.valve.send_flows(
                self.ryu_dp,
                self.valve.switch_features(None)
                + self.valve.datapath_connect(self.mock_time(), {1, 2, 3, 4}),
                self.mock_time(),
            )
        )


class ValveAtomicUnreadTestCase(ValveAtomicUnreadTestBase):
    """Test a bundle faucet ends the connection of before reading its answer."""

    def test_commit_after_cold_reload(self):
        """Test a commit read after faucet ends the bundle's connection counts.

        To cold start the DP on a reload, faucet ends the connection itself.
        The switch's answer to the commit of a bundle sent before can wait
        behind the reload, to be handled after it, and before the end of the
        connection.
        """
        old_dp = self.ryu_dp
        commit = self.assert_bundled(self.warm_start())
        self.assertFalse(bundled(self.cold_reload(p3_vlans="v100")))
        # Not yet lost: the switch's answer may still be read.
        self.assertEqual((1, 0, 0, 0), self.bundle_counts())
        self.valve.bundle_ctrl_reply(commit_reply_on(commit, old_dp))
        self.assertEqual((1, 1, 0, 0), self.bundle_counts())
        self.valve.datapath_disconnect(self.mock_time())
        self.valve.bundle_ctrl_reply(commit_reply_on(commit, old_dp))
        self.assertEqual((1, 1, 0, 0), self.bundle_counts())
        self.assertEqual(0, self.abandoned())
        self.assert_not_bundled(self.connect(first_xid=1000))
        self.assert_bundled(self.warm_start())
        self.assertEqual(1, self.atomic_status())

    def test_cold_reloads_before_commits_answered(self):
        """Test bundles left unanswered by a cold reload are lost, not in a row.

        Whether the switch committed them is unknown, and faucet ending the
        connection says nothing of the switch, so bundling stays on.
        """
        max_lost = self.valve.ATOMIC_WARM_START_MAX_LOST
        p3_vlans = itertools.cycle(("v100,v200", "v100"))
        for lost in range(max_lost + 1):
            old_dp = self.ryu_dp
            commit = self.assert_bundled(self.warm_start(next(p3_vlans)))
            self.cold_reload(next(p3_vlans))
            # An answer on another connection is not this bundle's.
            self.valve.bundle_ctrl_reply(commit_reply_on(commit, FakeDatapath()))
            error = commit_error(commit)
            error.datapath = FakeDatapath()
            self.assertEqual([], self.valve.oferror(error))
            self.assertEqual((lost + 1, 0, 0, lost), self.bundle_counts())
            # The end of the connection: no answer is coming.
            self.valve.datapath_disconnect(self.mock_time())
            self.valve.bundle_ctrl_reply(commit_reply_on(commit, old_dp))
            self.assertEqual((lost + 1, 0, 0, lost + 1), self.bundle_counts())
            self.assertEqual(lost + 1, self.abandoned())
            self.assertEqual(1, self.atomic_status())
            self.assert_not_bundled(self.connect(first_xid=1000 * (lost + 1)))
        self.assert_bundled(self.warm_start(next(p3_vlans)))

    def test_cold_reload_neither_loses_nor_commits_in_a_row(self):
        """Test a bundle left unanswered by a cold reload leaves the count in a row.

        It neither counts toward the bundles lost in a row nor starts their
        count again.
        """
        max_lost = self.valve.ATOMIC_WARM_START_MAX_LOST
        p3_vlans = itertools.cycle(("v100,v200", "v100"))
        for _ in range(max_lost - 1):
            self.assert_bundled(self.warm_start(next(p3_vlans)))
            self.reconnect()
        self.assert_bundled(self.warm_start(next(p3_vlans)))
        self.cold_reload(next(p3_vlans))
        self.connect(first_xid=1000)
        self.assertEqual(1, self.atomic_status())
        self.assert_bundled(self.warm_start(next(p3_vlans)))
        self.reconnect()
        self.assertEqual(0, self.atomic_status())
        self.assertEqual((max_lost + 1, 0, 0, max_lost + 1), self.bundle_counts())
        self.assertEqual(1, self.abandoned())

    def test_errors_after_cold_reload(self):
        """Test the switch's errors on a bundle after faucet ends its connection.

        A timeout on the open discards the bundle, which is lost toward those
        in a row, and what the switch commits after it is not the bundle. A
        refused commit leaves the switch on its old flows, as on any
        connection. Either way faucet is already reconnecting.
        """
        sent = self.warm_start()
        commit = self.assert_bundled(sent)
        (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
        old_dp = self.ryu_dp
        self.cold_reload()
        errors = self.get_prom("of_errors_total")
        self.assertEqual([], self.valve.oferror(open_error(bundle_open, old_dp)))
        self.assertEqual(errors + 1, self.get_prom("of_errors_total"))
        self.valve.bundle_ctrl_reply(commit_reply_on(commit, old_dp))
        self.valve.datapath_disconnect(self.mock_time())
        self.assertEqual((1, 0, 0, 1), self.bundle_counts())
        self.assertEqual(0, self.abandoned())
        self.assertEqual(1, self.atomic_status())
        self.connect(first_xid=1000)
        commit = self.assert_bundled(self.warm_start(p3_vlans="v100"))
        old_dp = self.ryu_dp
        self.cold_reload()
        error = commit_error(commit)
        error.datapath = old_dp
        self.assertEqual([], self.valve.oferror(error))
        self.assertEqual(errors + 2, self.get_prom("of_errors_total"))
        self.valve.datapath_disconnect(self.mock_time())
        self.assertEqual((2, 0, 1, 1), self.bundle_counts())
        self.assertEqual(0, self.abandoned())
        self.assertEqual(0, self.atomic_status())

    def test_cold_reload_after_discard(self):
        """Test a bundle the switch discarded before a cold reload is lost.

        The switch has not committed it, so it counts toward those in a row.
        """
        sent = self.warm_start()
        self.assert_bundled(sent)
        (bundle_open,) = bundle_ctrls(sent, ofp.ONF_BCT_OPEN_REQUEST)
        self.assert_not_bundled(self.warm_start(p3_vlans="v100"))
        self.assertIsNone(self.valve.oferror(open_error(bundle_open, self.ryu_dp)))
        # The reload is handled before the reconnect the discard ordered.
        self.cold_reload()
        self.assertEqual((1, 0, 0, 1), self.bundle_counts())
        self.assertEqual(0, self.abandoned())
        self.assertEqual(
            1, self.valve._bundles_lost["warm"]  # pylint: disable=protected-access
        )


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
