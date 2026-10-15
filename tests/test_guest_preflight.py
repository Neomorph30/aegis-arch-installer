"""Tests for the read-only guest preflight CLI."""
from __future__ import annotations

import contextlib
import io
import json
import unittest
from unittest import mock

from lab.guest_preflight import main, run_preflight
from lab.guest_probe import GuestProbeError


def valid_observation():
    return {
        "environment": {"sys_vendor": "QEMU", "product_name": "Q35"},
        "network_mode": "disabled",
        "active_swaps": [],
        "devices": [
            {"path": "/dev/vda", "type": "disk", "serial": "AEGIS-LAB-PRIMARY",
             "size_bytes": 24 * 1024**3, "read_only": False, "mountpoints": [],
             "holders": [], "active_swap": False, "children": []},
            {"path": "/dev/vdb", "type": "disk", "serial": "AEGIS-LAB-SECONDARY",
             "size_bytes": 8 * 1024**3, "read_only": True, "mountpoints": [],
             "holders": [], "active_swap": False, "children": []},
            {"path": "/dev/sr0", "type": "rom", "read_only": True},
        ],
    }


class GuestPreflightCLITests(unittest.TestCase):
    def test_valid_observation_returns_review_only_spec(self):
        code, result = run_preflight(valid_observation)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "PREFLIGHT_ONLY")
        self.assertFalse(result["execution_enabled"])

    def test_probe_failure_returns_actionable_blocked_record(self):
        def fail():
            raise GuestProbeError("lsblk timed out")
        code, result = run_preflight(fail)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["execution_enabled"])
        self.assertFalse(result["disk_changes_performed"])
        self.assertIn("Correct the lab configuration", result["recovery"])

    def test_cli_emits_machine_readable_json(self):
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()):
            with mock.patch("lab.guest_preflight.run_preflight",
                                     return_value=(0, {"status": "PREFLIGHT_ONLY", "execution_enabled": False})):
                code = main([])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "PREFLIGHT_ONLY")

    def test_non_qemu_observation_is_blocked(self):
        obs = valid_observation()
        obs["environment"]["sys_vendor"] = "Physical Host"
        code, result = run_preflight(lambda: obs)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("QEMU Q35", result["error"])


if __name__ == "__main__":
    unittest.main()
