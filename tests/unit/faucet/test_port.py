"""Unit tests for Port"""

import logging
import unittest
from unittest import mock

from faucet.conf import Conf
from faucet.dp import DP
from faucet.port import Port
from faucet.port import (
    LACP_ACTOR_NOTCONFIGURED,
    LACP_PORT_NOTCONFIGURED,
    LACP_ACTOR_INIT,
    LACP_ACTOR_UP,
    LACP_ACTOR_NOSYNC,
    LACP_ACTOR_NONE,
    LACP_PORT_UNSELECTED,
    LACP_PORT_SELECTED,
    LACP_PORT_STANDBY,
)
from faucet.valve import ValveLogger


class MockVLAN:  # pylint: disable=too-few-public-methods
    """Mock class for VLAN so we can inject into Port"""

    def __init__(self, name):
        self.name = name


class FaucetPortMethodTest(unittest.TestCase):  # pytype: disable=module-attr
    """Test a range of methods on Port"""

    def test_vlans(self):
        """Test that the vlans() method behaves correctly"""

        vlan100 = MockVLAN("v100")
        vlan200 = MockVLAN("v200")
        vlan300 = MockVLAN("v300")

        tagged_vlans = [vlan200, vlan300]
        native_vlan = vlan100

        port = Port(1, 1, {})
        port.native_vlan = native_vlan
        self.assertIn(native_vlan, port.vlans())
        port.tagged_vlans = tagged_vlans
        self.assertEqual(set(port.vlans()), set([native_vlan] + tagged_vlans))
        port.native_vlan = None
        self.assertEqual(set(port.vlans()), set(tagged_vlans))

    def test_conf_diff_summary(self):
        """Test the summary names changed keys and counts only changed list items"""
        old_port = Port(1, 1, {"tagged_vlans": [101, 102, 103, 104]})
        new_port = Port(
            1,
            1,
            {
                "description": "trunk",
                "acls_in": ["acl1"],
                "tagged_vlans": [101, 105, 106, 104, 107],
            },
        )
        self.assertEqual(
            "acls_in (1 added, 0 deleted), description, "
            "tagged_vlans (3 added, 2 deleted)",
            old_port.conf_diff_summary(new_port),
        )
        self.assertEqual(
            "acls_in (0 added, 1 deleted), description, "
            "tagged_vlans (2 added, 3 deleted)",
            new_port.conf_diff_summary(old_port),
        )
        self.assertEqual("", old_port.conf_diff_summary(old_port))

    def test_conf_changes_diff_only_at_debug(self):
        """Test a changed port's diff is built only when debug is logged"""
        old_ports = {1: Port(1, 1, {"tagged_vlans": [101, 102]})}
        new_ports = {
            1: Port(1, 1, {"description": "trunk", "tagged_vlans": [101, 102, 103]})
        }
        logger = ValveLogger(logging.getLogger("faucet.valve"), 1, "s1")
        summary = (
            "INFO:faucet.valve:DPID 1 (0x1) s1 port 1 changed: "
            "description, tagged_vlans (1 added, 0 deleted)"
        )
        conf_diff = Conf.conf_diff
        diffs = []

        def counted_conf_diff(conf, other):
            diffs.append(conf)
            return conf_diff(conf, other)

        with mock.patch.object(Conf, "conf_diff", counted_conf_diff):
            for level, diffs_built in (("INFO", 0), ("DEBUG", 1)):
                diffs.clear()
                with self.assertLogs("faucet.valve", level=level) as logs:
                    # pylint: disable=protected-access
                    DP._get_conf_changes(
                        logger, "port", old_ports, new_ports, diff=True
                    )
                changes = [line for line in logs.output if "port 1 changed:" in line]
                self.assertEqual(summary, changes[0], level)
                self.assertEqual(diffs_built, len(diffs), level)
                self.assertEqual(1 + diffs_built, len(changes), changes)
        self.assertTrue(changes[1].startswith("DEBUG:"), changes)
        self.assertIn('"description": "trunk"', changes[1])


class FaucetLACPPortFunctions(unittest.TestCase):  # pytype: disable=module-attr
    """Test port LACP state functions work as expected"""

    def test_lacp_actor_update(self):
        """Test updating port LACP information causes correct actor state changes"""
        port = Port(1, 1, {})
        port.enabled = True
        port.dyn_phys_up = True
        # Before configuring the LACP state machine, default is notconfigured
        self.assertEqual(port.dyn_lacp_port_selected, LACP_PORT_NOTCONFIGURED)
        self.assertEqual(port.dyn_lacp_actor_state, LACP_ACTOR_NOTCONFIGURED)
        # Move to initial configuration state when no packets have been received yet
        port.lacp_actor_update(False, None, None)
        self.assertEqual(port.dyn_lacp_actor_state, LACP_ACTOR_INIT)
        # Receiving first packets but no SYNC bit set
        port.lacp_actor_update(False, 1, 1)
        self.assertEqual(port.dyn_lacp_actor_state, LACP_ACTOR_NOSYNC)
        # Receiving sync packets
        port.lacp_actor_update(True, 1, 1)
        self.assertEqual(port.dyn_lacp_actor_state, LACP_ACTOR_UP)
        # Port phys down, move to ACTOR_NONE state
        port.dyn_phys_up = False
        port.lacp_actor_update(True, 1, 1)
        self.assertEqual(port.dyn_lacp_actor_state, LACP_ACTOR_NONE)
        port.lacp_actor_update(False, None, None)
        self.assertEqual(port.dyn_lacp_actor_state, LACP_ACTOR_NONE)
        # Go back to init once port restarted
        port.dyn_phys_up = True
        port.lacp_actor_update(False, None, None)
        self.assertEqual(port.dyn_lacp_actor_state, LACP_ACTOR_INIT)
        # Cold starting will force the port to revert to notconfigured state
        port.lacp_actor_update(False, None, None, True)
        self.assertEqual(port.dyn_lacp_actor_state, LACP_ACTOR_NOTCONFIGURED)

    def test_lacp_flags(self):
        """Test port LACP flags returns correct flags for current port states"""
        port = Port(1, 1, {})
        # LACP config option to force flags on
        port.lacp_collect_and_distribute = True
        self.assertEqual(port.get_lacp_flags(), (1, 1, 1))
        port.lacp_collect_and_distribute = False
        # Port is selected, so flags should be on
        port.dyn_lacp_port_selected = LACP_PORT_SELECTED
        self.assertEqual(port.get_lacp_flags(), (1, 1, 1))
        # Port in standby, only allow sync
        port.dyn_lacp_port_selected = LACP_PORT_STANDBY
        self.assertEqual(port.get_lacp_flags(), (1, 0, 0))
        # Port not in standby, or selected
        port.dyn_lacp_port_selected = LACP_PORT_UNSELECTED
        self.assertEqual(port.get_lacp_flags(), (0, 0, 0))
        port.dyn_lacp_port_selected = LACP_PORT_NOTCONFIGURED
        self.assertEqual(port.get_lacp_flags(), (0, 0, 0))

    def test_lacp_port_update(self):
        """Test LACP port options"""
        port = Port(1, 1, {})
        port.enabled = True
        port.dyn_phys_up = True
        # Port defaults to NOTCONFIGURED
        self.assertEqual(port.dyn_lacp_port_selected, LACP_PORT_NOTCONFIGURED)
        # Now call update to configure port and get initial state
        #   depending on the chosen DP
        port.lacp_port_update(False)
        self.assertEqual(port.dyn_lacp_port_selected, LACP_PORT_UNSELECTED)
        # Now select our the port's current DP
        port.lacp_port_update(True)
        self.assertEqual(port.dyn_lacp_port_selected, LACP_PORT_SELECTED)
        # Test option to force standby mode
        # Option forces the statemachine to revert to STANDBY mode when not selected
        port.lacp_standby = True
        port.lacp_port_update(True)
        self.assertEqual(port.dyn_lacp_port_selected, LACP_PORT_SELECTED)
        port.lacp_port_update(False)
        self.assertEqual(port.dyn_lacp_port_selected, LACP_PORT_STANDBY)
        # Test forcing selected port
        port.lacp_standby = False
        port.lacp_selected = True
        port.lacp_port_update(False)
        self.assertEqual(port.dyn_lacp_port_selected, LACP_PORT_SELECTED)
        # Test forcing unselected port
        port.lacp_selected = False
        port.lacp_unselected = True
        port.lacp_port_update(True)
        self.assertEqual(port.dyn_lacp_port_selected, LACP_PORT_UNSELECTED)
        # Test reverting to unconfigured on port cold start
        port.lacp_unselected = False
        port.lacp_port_update(False, True)
        self.assertEqual(port.dyn_lacp_port_selected, LACP_PORT_NOTCONFIGURED)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
