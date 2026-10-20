#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valveapp_smoke.py."""

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
import os
import tempfile
import unittest
from unittest import mock
from prometheus_client import CollectorRegistry
from os_ken.controller import dpset
from os_ken.controller.ofp_event import EventOFPMsgBase
from faucet import faucet
from faucet import valve_of


class OSKenAppBundleTest(unittest.TestCase):  # pytype: disable=module-attr
    """Test FAUCET handling a switch's replies to a cold start's bundle."""

    CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: "Open vSwitch"
        atomic_cold_start: true
        interfaces:
            p1:
                number: 1
                native_vlan: v100
vlans:
    v100:
        vid: 0x100
"""

    class FakeDatapath:
        """A connected switch, recording what FAUCET sends it."""

        ofproto = valve_of.ofp
        ofproto_parser = valve_of.parser

        def __init__(self):
            self.id = 1  # pylint: disable=invalid-name
            self.ports = {}
            self.sent = []
            self.closed = False
            self.xid = 0

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

    def setUp(self):
        tmpdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmpdir.cleanup)
        config_file = os.path.join(tmpdir.name, "faucet.yaml")
        with open(config_file, "w", encoding="utf-8") as config:
            config.write(self.CONFIG)
        env = mock.patch.dict(
            os.environ,
            {
                "FAUCET_CONFIG": config_file,
                "FAUCET_LOG": "/dev/null",
                "FAUCET_EXCEPTION_LOG": "/dev/null",
            },
        )
        env.start()
        self.addCleanup(env.stop)
        self.registry = CollectorRegistry()
        self.ryu_dp = self.FakeDatapath()
        self.os_ken_app = faucet.Faucet(dpset={1: self.ryu_dp}, reg=self.registry)
        self.os_ken_app.reload_config(None)

    def _event(self, msg):
        msg.datapath = self.ryu_dp
        return EventOFPMsgBase(msg=msg)

    def _cold_start_bundle(self):
        """Connect the switch, and return the bundle FAUCET sends it."""
        features = namedtuple("msg", ["datapath"])(self.ryu_dp)
        self.os_ken_app.features_handler(EventOFPMsgBase(msg=features))
        self.os_ken_app._datapath_connect(dpset.EventDP(self.ryu_dp, True))
        return [
            ofmsg
            for ofmsg in self.ryu_dp.sent
            if isinstance(
                ofmsg,
                (valve_of.parser.ONFBundleCtrlMsg, valve_of.parser.ONFBundleAddMsg),
            )
        ]

    def _prom(self, var):
        return self.registry.get_sample_value(var, {"dp_id": "0x1", "dp_name": "s1"})

    def test_bundle_committed(self):
        """Test the switch's commit reply reaches the datapath's valve."""
        commit = self._cold_start_bundle()[-1]
        self.assertEqual(1, self._prom("faucet_cold_start_bundles_total"))
        reply = valve_of.parser.ONFBundleCtrlMsg(
            None, commit.bundle_id, valve_of.ofp.ONF_BCT_COMMIT_REPLY, 0, []
        )
        reply.xid = commit.xid
        self.os_ken_app.bundle_ctrl_handler(self._event(reply))
        self.assertEqual(1, self._prom("faucet_cold_start_bundles_committed_total"))
        self.assertFalse(self.ryu_dp.closed)

    def test_bundle_refused(self):
        """Test a refused bundle closes the connection, and other errors do not."""
        bundle = self._cold_start_bundle()
        error = valve_of.parser.OFPErrorMsg(
            None, type_=valve_of.ofp.OFPET_BAD_REQUEST, code=0
        )
        # On the bundle's open too: only a timeout there discards the bundle.
        for xid in (self.ryu_dp.xid + 1, bundle[0].xid, bundle[1].xid):
            error.xid = xid
            self.os_ken_app.error_handler(self._event(error))
            self.assertFalse(self.ryu_dp.closed)
        error.xid = bundle[-1].xid
        self.os_ken_app.error_handler(self._event(error))
        self.assertTrue(self.ryu_dp.closed)
        self.assertEqual(1, self._prom("faucet_cold_start_bundles_refused_total"))

    def test_bundle_discarded(self):
        """Test a bundle discarded before its commit closes the connection.

        The switch answers the bundle's open with an error when it discards
        it, and can then commit part of it, so the bundle is lost when the
        connection ends, not committed.
        """
        bundle = self._cold_start_bundle()
        error = valve_of.parser.OFPErrorMsg(
            None,
            type_=valve_of.ofp.OFPET_EXPERIMENTER,
            exp_type=valve_of.ofp.ONFERR_ET_TIMEOUT,
            experimenter=0x4F4E4600,
        )
        error.xid = bundle[0].xid
        self.os_ken_app.error_handler(self._event(error))
        self.assertTrue(self.ryu_dp.closed)
        reply = valve_of.parser.ONFBundleCtrlMsg(
            None, bundle[-1].bundle_id, valve_of.ofp.ONF_BCT_COMMIT_REPLY, 0, []
        )
        reply.xid = bundle[-1].xid
        self.os_ken_app.bundle_ctrl_handler(self._event(reply))
        self.os_ken_app.connect_or_disconnect_handler(dpset.EventDP(self.ryu_dp, False))
        self.assertEqual(
            [1, 0, 0, 1],
            [
                self._prom("faucet_cold_start_bundles%s_total" % outcome)
                for outcome in ("", "_committed", "_refused", "_lost")
            ],
        )
        self.assertEqual(1, self._prom("dp_atomic_cold_start"))

    def test_bundle_committed_after_cold_reload(self):
        """Test a commit handled after a reload ends its connection counts.

        A reload that cold starts the DP ends the connection, and the
        switch's commit reply, queued behind the reload, is handled after it,
        before the end of the connection.
        """
        commit = self._cold_start_bundle()[-1]
        with open(os.environ["FAUCET_CONFIG"], "w", encoding="utf-8") as config:
            config.write(
                self.CONFIG.replace("dp_id: 1", "dp_id: 1\n        timeout: 600")
            )
        self.os_ken_app.reload_config(None)
        self.assertTrue(self.ryu_dp.closed)
        reply = valve_of.parser.ONFBundleCtrlMsg(
            None, commit.bundle_id, valve_of.ofp.ONF_BCT_COMMIT_REPLY, 0, []
        )
        reply.xid = commit.xid
        self.os_ken_app.bundle_ctrl_handler(self._event(reply))
        self.os_ken_app.connect_or_disconnect_handler(dpset.EventDP(self.ryu_dp, False))
        self.assertEqual(
            [1, 1, 0, 0, 0],
            [
                self._prom("faucet_cold_start_bundles%s_total" % outcome)
                for outcome in ("", "_committed", "_refused", "_lost", "_abandoned")
            ],
        )
        self.assertEqual(1, self._prom("dp_atomic_cold_start"))

    def test_bundle_lost_to_new_connection(self):
        """Test cold starting a new connection loses a bundle on the old one.

        A switch that connects again before its old connection is seen to end
        has that connection replaced, and FAUCET told of the new one only once
        os_ken has closed the old one.
        """
        old_dp, new_dp = self.ryu_dp, self.FakeDatapath()
        new_dp.xid = 1000
        for ryu_dp in (old_dp, new_dp):
            features = namedtuple("msg", ["datapath"])(ryu_dp)
            self.os_ken_app.features_handler(EventOFPMsgBase(msg=features))
        self.os_ken_app._datapath_connect(dpset.EventDP(old_dp, True))
        self.os_ken_app.dpset[1] = new_dp
        self.os_ken_app._datapath_connect(dpset.EventDPReconnected(new_dp))
        self.assertEqual(2, self._prom("faucet_cold_start_bundles_total"))
        self.assertEqual(1, self._prom("faucet_cold_start_bundles_lost_total"))
        self.assertTrue(
            [
                ofmsg
                for ofmsg in new_dp.sent
                if isinstance(ofmsg, valve_of.parser.ONFBundleCtrlMsg)
            ]
        )


class OSKenAppSmokeTest(unittest.TestCase):  # pytype: disable=module-attr
    """Test bare instantiation of controller classes."""

    @staticmethod
    def _fake_dp():
        datapath = namedtuple("datapath", ["id", "close"])(0, lambda: None)
        return datapath

    def test_faucet(self):
        """Test FAUCET can be initialized."""
        os.environ["FAUCET_CONFIG"] = "/dev/null"
        os.environ["FAUCET_LOG"] = "/dev/null"
        os.environ["FAUCET_EXCEPTION_LOG"] = "/dev/null"
        os_ken_app = faucet.Faucet(dpset={}, reg=CollectorRegistry())
        os_ken_app.reload_config(None)
        self.assertFalse(os_ken_app._config_files_changed())
        os_ken_app.metric_update(None)
        event_dp = dpset.EventDPReconnected(dp=self._fake_dp())
        for enter in (True, False):
            event_dp.enter = enter
            os_ken_app.connect_or_disconnect_handler(event_dp)
        for event_handler in (
            os_ken_app.error_handler,
            os_ken_app.bundle_ctrl_handler,
            os_ken_app.features_handler,
            os_ken_app.packet_in_handler,
            os_ken_app.desc_stats_reply_handler,
            os_ken_app.port_desc_stats_reply_handler,
            os_ken_app.port_status_handler,
            os_ken_app.flowremoved_handler,
            os_ken_app.reconnect_handler,
            os_ken_app._datapath_connect,
            os_ken_app._datapath_disconnect,
        ):
            msg = namedtuple("msg", ["datapath"])(self._fake_dp())
            event = EventOFPMsgBase(msg=msg)
            event.dp = msg.datapath
            event_handler(event)
        os_ken_app._check_thread_exception()
        os_ken_app._thread_jitter(1)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
