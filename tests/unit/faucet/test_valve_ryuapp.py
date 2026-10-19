#!/usr/bin/env python3

"""Test FAUCET valve_ryuapp."""

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

import os
import signal
import threading
import time
import unittest
from unittest import mock

from os_ken.base import app_manager
from os_ken.controller import event
from os_ken.controller.handler import MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub

from faucet.valve_ryuapp import EventReconfigure, OSKenAppBase


class EventBusy(event.EventBase):  # pylint: disable=too-few-public-methods
    """Event whose handler fills the event queue, then takes signals."""


class EventFill(event.EventBase):  # pylint: disable=too-few-public-methods
    """Event filling the event queue."""


class EventSignal(event.EventBase):  # pylint: disable=too-few-public-methods
    """Event whose handler takes a signal."""


class SignalApp(OSKenAppBase):
    """An app that records its reloads."""

    logname = "faucet"
    exc_logname = logname + ".exception"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.busy_signals = 0
        self.busy_sleep = 0
        self.busy_waiters = 0
        self.log = []
        self.places_at_signal = None
        self.reloaded = hub.Event()

    @staticmethod
    def sighup_from_thread(delay):
        """Send SIGHUP to the main thread from another thread after delay."""
        main_thread = threading.main_thread().ident
        timer = threading.Timer(
            delay, signal.pthread_kill, (main_thread, signal.SIGHUP)
        )
        timer.start()
        return timer

    @set_ev_cls(EventBusy, MAIN_DISPATCHER)
    def busy_handler(self, _ryu_event):
        """Fill the event queue, then take SIGHUPs, as a long reload would."""
        if self.busy_waiters:
            # Queued first, so its handler runs next, with one place free.
            self.send_event(self.name, EventSignal())
        while not self.events.full():
            self.send_event(self.name, EventFill())
        if self.busy_waiters:
            # Senders waiting for a place, as the switch's reader and the
            # periodic threads wait during a long reload.
            for _ in range(self.busy_waiters):
                hub.spawn(self.send_event, self.name, EventFill())
            while self._events_sem.balance > -self.busy_waiters:
                hub.sleep(0)
        for _ in range(self.busy_signals):
            self.log.append("signal")
            signal.raise_signal(signal.SIGHUP)
            # Let what the signal started run while the queue is still full.
            hub.sleep(0)
        if self.busy_sleep:
            # Wait with the queue full, as on a slow switch, while the hub
            # takes a SIGHUP.
            self.log.append("signal")
            timer = self.sighup_from_thread(self.busy_sleep / 2)
            hub.sleep(self.busy_sleep)
            timer.join()

    @set_ev_cls(EventSignal, MAIN_DISPATCHER)
    def signal_event_handler(self, _ryu_event):
        """Take a SIGHUP, with one place free and senders waiting for it."""
        self.places_at_signal = (
            self._events_sem.counter,
            self._events_sem.balance,
        )
        self.log.append("signal")
        signal.raise_signal(signal.SIGHUP)

    @set_ev_cls(EventReconfigure, MAIN_DISPATCHER)
    def reload_config(self, _ryu_event):
        """Record a reload."""
        self.log.append("reload")
        self.reloaded.set()


class OSKenAppSignalTest(unittest.TestCase):  # pytype: disable=module-attr
    """Test reloading on SIGHUP, with the app's own event loop running."""

    TIMEOUT = 5

    def setUp(self):
        env = mock.patch.dict(
            os.environ,
            {
                "FAUCET_CONFIG": "/dev/null",
                "FAUCET_LOG": "/dev/null",
                "FAUCET_EXCEPTION_LOG": "/dev/null",
            },
        )
        env.start()
        self.addCleanup(env.stop)
        self.app = SignalApp(dpset={})
        app_manager.register_app(self.app)
        self.addCleanup(app_manager.unregister_app, self.app)
        handler = signal.signal(signal.SIGHUP, self.app.signal_handler)
        self.addCleanup(signal.signal, signal.SIGHUP, handler)
        self.addCleanup(hub.kill, hub.spawn(self.app._event_loop))

    def _wait_for_reloads(self, reloads):
        deadline = time.monotonic() + self.TIMEOUT
        while True:
            self.app.reloaded.clear()
            remaining = deadline - time.monotonic()
            if self.app.log.count("reload") >= reloads or remaining <= 0:
                return
            self.app.reloaded.wait(timeout=remaining)

    def test_sighup(self):
        """Test SIGHUP reloads."""
        signal.raise_signal(signal.SIGHUP)
        self._wait_for_reloads(1)
        self.assertEqual(["reload"], self.app.log)

    def test_sighup_event_loop_full_queue(self):
        """Test SIGHUPs reload when they interrupt the event loop with its queue full."""
        self.app.busy_signals = 3
        self.app.send_event(self.app.name, EventBusy())
        self._wait_for_reloads(3)
        self.assertEqual(["signal"] * 3 + ["reload"] * 3, self.app.log)

    def test_sighup_event_loop_senders_waiting(self):
        """Test SIGHUP reloads when it interrupts the event loop as other senders wait."""
        self.app.busy_waiters = 2
        self.app.send_event(self.app.name, EventBusy())
        self._wait_for_reloads(1)
        self.assertEqual(["signal", "reload"], self.app.log)
        # The signal came with a place free in the queue, and senders waiting for it.
        free, balance = self.app.places_at_signal
        self.assertEqual(1, free)
        self.assertLess(balance, 0)

    def test_sighup_hub_full_queue(self):
        """Test SIGHUP reloads when it interrupts the hub with the event queue full."""
        self.app.busy_sleep = 0.5
        self.app.send_event(self.app.name, EventBusy())
        self._wait_for_reloads(1)
        self.assertEqual(["signal", "reload"], self.app.log)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
