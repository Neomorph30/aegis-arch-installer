"""CLI integration tests for the read-only structured inventory assessor."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from aegis.cli import main


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

    def test_malformed_fixture_is_reported_as_blocked(self):
        code, output, _ = self.run_assess({"devices": "not-a-list"})
        result = json.loads(output)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "blocked")
        self.assertIs(result["write_authorized"], False)


if __name__ == "__main__":
    unittest.main()
