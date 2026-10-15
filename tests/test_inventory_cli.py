"""CLI integration tests for the read-only structured inventory assessor."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.cli import _require_live_target_reviewable, main
from aegis.planner import PlanError


def observation(**overrides):
    device = {
        "path": "/dev/test0",
        "type": "disk",
        "serial": "TEST-SERIAL-0",
        "wwn": "TEST-WWN-0",
        "mountpoints": [None],
        "holders": [],
        "active_swap": False,
        "ambiguous": False,
        "children": [],
    }
    device.update(overrides)
    return {"devices": [device]}


class InventoryAssessorCliTests(unittest.TestCase):
    def run_assess(self, data):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "inventory.json"
            filename.write_text(json.dumps(data), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(["assess", "--inventory", str(filename)])
            return code, stdout.getvalue(), stderr.getvalue()

    def test_valid_fixture_reports_review_only_and_never_authorizes_writes(self):
        code, output, error = self.run_assess(observation())
        result = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        self.assertEqual(result["status"], "review_required")
        self.assertIs(result["write_authorized"], False)

    def test_unsafe_fixture_returns_nonzero_and_never_authorizes_writes(self):
        code, output, _ = self.run_assess(observation(mountpoints=["/"]))
        result = json.loads(output)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "blocked")
        self.assertIs(result["write_authorized"], False)

    @patch("aegis.cli.read_assessment_observation")
    def test_live_assessment_uses_read_only_hardware_observation(self, probe):
        probe.return_value = observation()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["assess", "--live"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "review_required")
        probe.assert_called_once_with()

    @patch("aegis.cli.read_assessment_observation")
    def test_live_probe_failure_is_nonzero_and_does_not_claim_clearance(self, probe):
        from aegis.hardware import HardwareInspectionError
        probe.side_effect = HardwareInspectionError("swap state unavailable")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["assess", "--live"])
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("swap state unavailable", stderr.getvalue())

    @patch("aegis.cli.read_assessment_observation")
    def test_live_target_guard_accepts_review_only_target(self, probe):
        probe.return_value = observation()
        _require_live_target_reviewable("/dev/test0")

    @patch("aegis.cli.read_assessment_observation")
    def test_live_target_guard_blocks_changed_identity_snapshot(self, probe):
        probe.return_value = observation(serial="REPLACED-SERIAL")
        with self.assertRaises(PlanError):
            _require_live_target_reviewable("/dev/test0", {
                "path": "/dev/test0", "serial": "TEST-SERIAL-0",
                "wwn": "TEST-WWN-0", "size": None,
            })

    @patch("aegis.cli.read_assessment_observation")
    def test_live_target_guard_blocks_mounted_target(self, probe):
        probe.return_value = observation(mountpoints=["/"])
        with self.assertRaises(PlanError):
            _require_live_target_reviewable("/dev/test0")

    @patch("aegis.cli.read_assessment_observation")
    def test_live_target_guard_blocks_duplicate_identity_across_disks(self, probe):
        first = observation()["devices"][0]
        second = dict(first, path="/dev/test1")
        probe.return_value = {"devices": [first, second]}
        with self.assertRaises(PlanError):
            _require_live_target_reviewable("/dev/test0")

    @patch("aegis.cli.read_assessment_observation")
    def test_live_target_guard_requires_unique_fresh_match(self, probe):
        probe.return_value = observation()
        with self.assertRaises(PlanError):
            _require_live_target_reviewable("/dev/missing")

    def test_malformed_fixture_is_reported_as_blocked(self):
        code, output, _ = self.run_assess({"devices": "not-a-list"})
        result = json.loads(output)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "blocked")
        self.assertIs(result["write_authorized"], False)


if __name__ == "__main__":
    unittest.main()
