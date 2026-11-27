#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valve_extra_ips_probe.py."""

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

from ipaddress import ip_address
import time
import unittest

from os_ken.lib.packet import arp, ethernet

from clib.fakeoftable import CONTROLLER_PORT, IN_PORT
from clib.valve_test_lib import FAUCET_MAC, ValveTestBases
from faucet import valve_packet
from faucet.valve_route import ExtraIPState

from tests.unit.faucet.test_valve_extra_ips import ValveExtraIPsTestBase


class ValveExtraIPsProbeTestBase(ValveExtraIPsTestBase):
    """Probe for faucet_extra_ips before the switch answers for them.

    Each test starts as the switch connects, before it has sent FAUCET a
    packet in, with 10.0.0.10 and 10.0.0.11 listed on office.
    """

    CLAIM = False
    NEW_MAC = "0e:00:00:00:01:00"

    def state(self, extra_ip="10.0.0.10", vid=0x100):
        """Return an address's state."""
        return self.vlan(vid).dyn_extra_ip_state[ip_address(extra_ip)]

    def extra_ip_metrics(self, extra_ip="10.0.0.10", vid=0x100):
        """Return an address's vlan_extra_ip_state, its count of changes, the
        time of the last, and its count of ARP from other hosts using it, each
        None if not reported."""
        labels = dict(
            self.valves_manager.valves[self.DP_ID].dp.base_prom_labels(),
            vlan=str(vid),
            ip=extra_ip,
        )
        return tuple(
            self.registry.get_sample_value(var, labels)
            for var in (
                "vlan_extra_ip_state",
                "vlan_extra_ip_state_changes_total",
                "vlan_extra_ip_state_change_time",
                "vlan_extra_ip_foreign_arp_total",
            )
        )

    def probes(self, ofmsgs):
        """Return the ARP probes ofmsgs send, each as its output ports, VID (0
        untagged), Ethernet source and destination, sender MAC and target IP."""
        sent = []
        for pkt_out in ValveTestBases.packet_outs_from_flows(ofmsgs):
            pkt, _, _, _, vid = valve_packet.parse_packet_in_pkt(
                bytes(pkt_out.data), None
            )
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt is None or arp_pkt.src_ip != "0.0.0.0":
                continue
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            self.assertEqual(arp.ARP_REQUEST, arp_pkt.opcode)
            self.assertEqual(self.NO_MAC, arp_pkt.dst_mac)
            sent.append(
                (
                    tuple(sorted(action.port for action in pkt_out.actions)),
                    vid or 0,
                    eth_pkt.src,
                    eth_pkt.dst,
                    arp_pkt.src_mac,
                    arp_pkt.dst_ip,
                )
            )
        return sorted(sent)

    def expected_probes(self, extra_ips=None, mac=FAUCET_MAC):
        """Return the probes for faucet_extra_ips on office, flooded to its
        ports with faucet_mac."""
        return sorted(
            (ports, vid, mac, self.BROADCAST_MAC, mac, extra_ip)
            for extra_ip in extra_ips or self.EXTRA_IPS
            for ports, vid in (((1, 2), 0), ((3,), 0x100))
        )

    def probed(self, ofmsgs, extra_ip="10.0.0.10"):
        """Return True if ofmsgs probe for an address."""
        return any(probe[5] == extra_ip for probe in self.probes(ofmsgs))

    def foreign(self, extra_ip="10.0.0.10"):
        """Have FAUCET handle ARP from another host using an address."""
        self.arp_in(2, arp.ARP_REQUEST, extra_ip, "10.0.0.1", eth_src=self.OTHER_MAC)

    def probe_in(self, extra_ip="10.0.0.10"):
        """Have FAUCET handle another host's probe for an address."""
        self.arp_in(2, arp.ARP_REQUEST, "0.0.0.0", extra_ip, eth_src=self.OTHER_MAC)

    def assert_unanswered(self, extra_ip="10.0.0.10"):
        """Assert the switch answers neither a request nor a probe for an
        address, but floods both, and copies the probe to the controller."""
        for sender_ip in ("10.0.0.1", "0.0.0.0"):
            with self.subTest(extra_ip=extra_ip, sender=sender_ip):
                outputs = self.outputs(self.arp_request(1, 0, sender_ip, extra_ip))
                self.assertNotIn(IN_PORT, outputs)
                self.assertIn(2, outputs)
                self.assertIn(3, outputs)
                if sender_ip == "0.0.0.0":
                    self.assertIn(CONTROLLER_PORT, outputs)

    def probe_round(self, extra_ip="10.0.0.10"):
        """Run the resolvers each second through a round of probes, asserting
        an address is probed for each second, then claimed two seconds after
        the last probe."""
        for probe in range(3):
            with self.subTest(probe=probe):
                self.assertTrue(self.probed(self.resolvers(1), extra_ip))
                self.assertNotEqual(ExtraIPState.CLAIMED, self.state(extra_ip).state)
        self.assertFalse(self.probed(self.resolvers(1), extra_ip))
        self.assertNotEqual(ExtraIPState.CLAIMED, self.state(extra_ip).state)
        self.resolvers(1)
        self.assertEqual(ExtraIPState.CLAIMED, self.state(extra_ip).state)


class ValveExtraIPsProbeTestCase(ValveExtraIPsProbeTestBase):
    """Test FAUCET probes for faucet_extra_ips, claims those no other host
    uses, and holds back from those another host does."""

    def test_probes_then_claims(self):
        """Test FAUCET sends three probes for each address a second apart, and
        claims each two seconds after the last, with no other host answering,
        when the switch answers for it. Until then, requests and probes for it
        are flooded, unanswered."""
        before = time.time()
        self.restart(self.config())
        after = time.time()
        for extra_ip in self.EXTRA_IPS:
            state, changes, change_time, foreign = self.extra_ip_metrics(extra_ip)
            self.assertEqual((ExtraIPState.PROBING, 0, 0), (state, changes, foreign))
            self.assertTrue(before <= change_time <= after)
            self.assert_unanswered(extra_ip)
        self.switch_live()
        for probe in range(3):
            with self.subTest(probe=probe):
                self.assertEqual(self.expected_probes(), self.probes(self.resolvers(1)))
                self.assertEqual([], self.probes(self.resolvers(0)))
                for extra_ip in self.EXTRA_IPS:
                    self.assert_unanswered(extra_ip)
        self.assertEqual([], self.probes(self.resolvers(1)))
        for extra_ip in self.EXTRA_IPS:
            self.assertEqual(ExtraIPState.PROBING, self.state(extra_ip).state)
            self.assert_unanswered(extra_ip)
        self.assertEqual([], self.probes(self.resolvers(1)))
        for extra_ip in self.EXTRA_IPS:
            self.assertEqual(
                (ExtraIPState.CLAIMED, 1, self.mock_now_sec, 0),
                self.extra_ip_metrics(extra_ip),
            )
        self.assert_extra_ips_answered()

    def test_conflict_holds(self):
        """Test ARP from another host using an address FAUCET is probing for
        holds it back from the address, which the switch does not answer for,
        while it claims the others."""
        self.switch_live()
        self.assertTrue(self.probed(self.resolvers(1)))
        self.foreign()
        self.assertEqual(
            (ExtraIPState.HELD, 1, self.mock_now_sec, 1),
            self.extra_ip_metrics("10.0.0.10"),
        )
        for _ in range(5):
            self.assertFalse(self.probed(self.resolvers(1)))
            self.foreign()
        self.assertEqual(ExtraIPState.HELD, self.state().state)
        self.assertEqual(ExtraIPState.CLAIMED, self.state("10.0.0.11").state)
        self.assert_unanswered("10.0.0.10")
        self.assert_extra_ips_answered(["10.0.0.11"])

    def test_simultaneous_probe_holds(self):
        """Test another host's probe for an address FAUCET is probing for
        holds it back from the address too, as both may be about to use it."""
        self.switch_live()
        self.assertTrue(self.probed(self.resolvers(1)))
        self.probe_in()
        self.assertEqual(
            (ExtraIPState.HELD, 1, self.mock_now_sec, 0),
            self.extra_ip_metrics("10.0.0.10"),
        )
        for _ in range(5):
            self.assertFalse(self.probed(self.resolvers(1)))
            self.probe_in()
        self.assertEqual(ExtraIPState.HELD, self.state().state)
        self.assert_unanswered("10.0.0.10")

    def test_reply_from_probe_sender_not_held(self):
        """Test an ARP reply from a probe's sender address for an address
        FAUCET is probing for is no probe, and holds nothing back."""
        self.switch_live()
        self.assertTrue(self.probed(self.resolvers(1)))
        self.arp_in(2, arp.ARP_REPLY, "0.0.0.0", "10.0.0.10", eth_src=self.OTHER_MAC)
        self.assertEqual(ExtraIPState.PROBING, self.state().state)
        self.claim()
        self.assertEqual((ExtraIPState.CLAIMED, 1), self.extra_ip_metrics()[:2])

    def test_backoff(self):
        """Test FAUCET probes for a held address again two seconds after the
        other host was last heard from, doubling the wait each time the other
        host answers a round of probes up to ten minutes, and claims the
        address once a round has no answer."""
        self.switch_live()
        self.resolvers(1)
        self.foreign()
        for backoff in (2, 4, 8, 16, 32, 64, 128, 256, 512, 600, 600):
            with self.subTest(backoff=backoff):
                self.assertFalse(self.probed(self.resolvers(backoff - 1)))
                self.assertTrue(self.probed(self.resolvers(1)))
                self.foreign()
                self.assertEqual(ExtraIPState.HELD, self.state().state)
        self.assertFalse(self.probed(self.resolvers(599)))
        self.probe_round()
        self.assertEqual(
            (ExtraIPState.CLAIMED, 2, self.mock_now_sec, 12), self.extra_ip_metrics()
        )
        self.assert_extra_ips_answered()

    def test_held_until_quiet(self):
        """Test ARP from the other host between rounds of probes for a held
        address puts the next round off, without doubling the wait."""
        self.switch_live()
        self.resolvers(1)
        self.foreign()
        self.resolvers(1)
        self.foreign()
        self.assertFalse(self.probed(self.resolvers(1)))
        self.assertTrue(self.probed(self.resolvers(1)))
        self.foreign()
        self.assertFalse(self.probed(self.resolvers(3)))
        self.assertTrue(self.probed(self.resolvers(1)))

    def test_held_state_steady(self):
        """Test a held address is reported held while FAUCET probes for it
        again, until it claims it."""
        self.switch_live()
        self.resolvers(1)
        self.foreign()
        held_time = self.mock_now_sec
        self.resolvers(1)
        for _ in range(4):
            self.resolvers(1)
            self.assertEqual(
                (ExtraIPState.HELD, 1, held_time, 1), self.extra_ip_metrics("10.0.0.10")
            )
            self.assertEqual(ExtraIPState.HELD, self.state().state)
        self.resolvers(1)
        self.assertEqual(
            (ExtraIPState.CLAIMED, 2, self.mock_now_sec, 1),
            self.extra_ip_metrics("10.0.0.10"),
        )

    def test_claimed_never_given_up(self):
        """Test ARP from another host using a claimed address, or its probe for
        it, is counted, but the switch goes on answering for the address."""
        self.claim()
        claimed = self.extra_ip_metrics()
        self.foreign()
        self.probe_in()
        self.resolvers(1)
        self.foreign()
        self.assertEqual(claimed[:3] + (2,), self.extra_ip_metrics())
        self.assertEqual(ExtraIPState.CLAIMED, self.state().state)
        self.assert_extra_ips_answered()

    def test_claimed_probed(self):
        """Test FAUCET probes for a claimed address once per neighbor timeout,
        so that a host using it without having probed answers."""
        timeout = self.valves_manager.valves[self.DP_ID].dp.arp_neighbor_timeout
        self.claim()
        for _ in range(2):
            self.assertEqual([], self.probes(self.resolvers(timeout - 1)))
            self.assertEqual(self.expected_probes(), self.probes(self.resolvers(1)))
        self.foreign()
        self.assertEqual((ExtraIPState.CLAIMED, 1), self.extra_ip_metrics()[:2])
        self.assertEqual(1, self.extra_ip_metrics()[3])

    def test_waits_for_packet_ins(self):
        """Test a round of probes waits until the switch sends a packet in
        after it connects, and starts over if it cold starts in the round."""
        for _ in range(5):
            self.assertEqual([], self.probes(self.resolvers(1)))
        self.switch_live()
        for _ in range(2):
            self.assertEqual(self.expected_probes(), self.probes(self.resolvers(1)))
        self.cold_start()
        for _ in range(5):
            self.assertEqual([], self.probes(self.resolvers(1)))
        self.assertEqual(ExtraIPState.PROBING, self.state().state)
        self.switch_live()
        self.probe_round()
        self.assert_extra_ips_answered()

    def test_probes_paced(self):
        """Test at most 16 addresses of a VLAN are probed for at a time, and
        that all are claimed."""
        extra_ips = ["10.0.0.%u" % host for host in range(10, 30)]
        self.restart(self.extra_ips_config(extra_ips))
        self.switch_live()
        probed = {probe[5] for probe in self.probes(self.resolvers(1))}
        self.assertEqual(set(extra_ips[:16]), probed)
        self.claim()

    def test_cold_start_keeps_state(self):
        """Test a cold start of the switch keeps an address held, unanswered,
        and another claimed, answered, without probing for either."""
        self.switch_live()
        for _ in range(5):
            self.resolvers(1)
            self.foreign()
        self.assertEqual(ExtraIPState.HELD, self.state().state)
        self.assertEqual(ExtraIPState.CLAIMED, self.state("10.0.0.11").state)
        self.cold_start()
        self.assertEqual([], self.probes(self.resolvers(1)))
        self.assertEqual((ExtraIPState.HELD, 1), self.extra_ip_metrics()[:2])
        self.assertEqual(
            (ExtraIPState.CLAIMED, 1), self.extra_ip_metrics("10.0.0.11")[:2]
        )
        self.assert_unanswered("10.0.0.10")
        self.assert_extra_ips_answered(["10.0.0.11"])

    def test_no_port_running(self):
        """Test no probe counts while the VLAN has no port running, as none is
        sent."""
        self.switch_live()
        for port in (1, 2, 3):
            self.set_port_down(port)
        for _ in range(5):
            self.assertEqual([], self.probes(self.resolvers(1)))
        self.assertEqual(
            (ExtraIPState.PROBING, 0), (self.state().state, self.state().probes)
        )
        self.set_port_up(2)
        self.switch_live()
        self.assertTrue(self.probed(self.resolvers(1)))
        self.assertEqual(1, self.state().probes)


class ValveExtraIPsProbeConfigTestCase(ValveExtraIPsProbeTestBase):
    """Test what a new config keeps of whether FAUCET has claimed each of
    faucet_extra_ips."""

    def assert_kept(self, config, claimed_ips):
        """Assert a warm start to config keeps the addresses claimed, and
        answered, and sends no probe for them."""
        ofmsgs = self.warm_start(config)
        self.assertEqual([], self.probes(ofmsgs))
        for extra_ip in claimed_ips:
            with self.subTest(extra_ip=extra_ip):
                self.assertEqual(
                    (ExtraIPState.CLAIMED, 1), self.extra_ip_metrics(extra_ip)[:2]
                )
        self.assert_extra_ips_answered(claimed_ips)

    def test_kept(self):
        """Test a claimed address stays claimed through other addresses being
        listed, a change of the VLAN's ports, and a change of the VLAN."""
        self.claim()
        config = self.extra_ips_config(["10.0.0.10", "10.0.0.11", "10.0.0.12"])
        self.assert_kept(config, self.EXTRA_IPS)
        self.assertEqual(ExtraIPState.PROBING, self.state("10.0.0.12").state)
        self.assert_unanswered("10.0.0.12")
        # The switch is still live: the added address is probed for at once.
        self.assertEqual(
            self.expected_probes(["10.0.0.12"]), self.probes(self.resolvers(1))
        )
        self.claim()
        for vlans, interfaces in (
            (None, {2: {"description": "printer"}}),
            ({"office": {"max_hosts": 2}}, None),
        ):
            with self.subTest(vlans=vlans, interfaces=interfaces):
                self.assert_kept(
                    self.config(vlans=vlans, interfaces=interfaces), self.EXTRA_IPS
                )
        self.assertEqual([], self.address_flows("10.0.0.12"))

    def test_new_mac(self):
        """Test FAUCET probes again, with the new MAC, for each address it has
        claimed if the VLAN's faucet_mac changes."""
        self.claim()
        config = self.config(vlans={"office": {"faucet_mac": self.NEW_MAC}})
        self.warm_start(config)
        for extra_ip in self.EXTRA_IPS:
            self.assertEqual(
                (ExtraIPState.PROBING, 2), self.extra_ip_metrics(extra_ip)[:2]
            )
            self.assert_unanswered(extra_ip)
        self.switch_live()
        self.assertEqual(
            self.expected_probes(mac=self.NEW_MAC), self.probes(self.resolvers(1))
        )

    def test_new_mac_restarts_round(self):
        """Test a change of the VLAN's faucet_mac starts a round of probes in
        progress over, with the new MAC."""
        self.switch_live()
        for _ in range(2):
            self.assertEqual(self.expected_probes(), self.probes(self.resolvers(1)))
        self.warm_start(self.config(vlans={"office": {"faucet_mac": self.NEW_MAC}}))
        for _ in range(3):
            self.assertEqual(
                self.expected_probes(mac=self.NEW_MAC), self.probes(self.resolvers(1))
            )
        self.assertEqual([], self.probes(self.resolvers(1)))
        self.assertEqual(ExtraIPState.PROBING, self.state().state)
        self.resolvers(1)
        self.assertEqual(ExtraIPState.CLAIMED, self.state().state)

    def test_new_mac_keeps_held(self):
        """Test a held address waits out its back-off, still held, through a
        change of the VLAN's faucet_mac, then is probed for with the new MAC."""
        self.switch_live()
        self.resolvers(1)
        self.foreign()
        for backoff in (2, 4, 8):
            self.assertTrue(self.probed(self.resolvers(backoff)))
            self.foreign()
        start = self.mock_now_sec
        self.warm_start(self.config(vlans={"office": {"faucet_mac": self.NEW_MAC}}))
        self.assertFalse(self.probed(self.resolvers(start + 15 - self.mock_now_sec)))
        self.assertEqual((ExtraIPState.HELD, 1), self.extra_ip_metrics()[:2])
        probes = self.probes(self.resolvers(1))
        self.assertIn(
            ((1, 2), 0, self.NEW_MAC, self.BROADCAST_MAC, self.NEW_MAC, "10.0.0.10"),
            probes,
        )

    def test_relisted(self):
        """Test FAUCET probes again for an address listed again after it was
        removed, and that removing one removes its metrics."""
        self.claim()
        self.warm_start(self.extra_ips_config(["10.0.0.11"]))
        self.assertEqual((None, None, None, None), self.extra_ip_metrics("10.0.0.10"))
        self.assertEqual(
            (ExtraIPState.CLAIMED, 1), self.extra_ip_metrics("10.0.0.11")[:2]
        )
        self.warm_start(self.config())
        self.assertEqual(
            (ExtraIPState.PROBING, 0), self.extra_ip_metrics("10.0.0.10")[:2]
        )
        self.assert_unanswered("10.0.0.10")

    def test_restart(self):
        """Test a new FAUCET probes again for every address, and reports no
        changes yet."""
        self.claim()
        self.restart(self.config())
        for extra_ip in self.EXTRA_IPS:
            self.assertEqual(
                (ExtraIPState.PROBING, 0), self.extra_ip_metrics(extra_ip)[:2]
            )
            self.assert_unanswered(extra_ip)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
