"""Unit tests for review-only guest session; no device commands run."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from lab.guest_probe import GuestProbeError
from lab.guest_review_session import run_review_session
from lab.transaction_journal import TransactionJournal


def sample():
    return {
        "environment": {"sys_vendor": "QEMU", "product_name": "Standard PC Q35"},
        "network_mode": "disabled", "active_swaps": [],
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


class GuestReviewSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.directory = root / "private"
        self.directory.mkdir(mode=0o700)
        self.journal = TransactionJournal(self.directory / "journal.jsonl")

    def test_exact_confirmation_completes_only_review_phases(self):
        obs = sample()
        result = run_review_session(
            self.journal, probe=lambda: copy.deepcopy(obs),
            confirm=lambda plan, phrase: phrase,
        )
        self.assertEqual(result["status"], "REVIEW_ONLY_COMPLETE")
        self.assertFalse(result["execution_enabled"])
        self.assertFalse(result["commands_executed"])
        self.assertFalse(result["disk_changes_performed"])
        self.assertEqual(result["completed_phases"], ["preflight", "explicit_target_review"])
        events = self.journal.read()
        self.assertEqual([e["phase"] for e in events if e["event_type"] == "phase_intent"],
                         ["preflight", "explicit_target_review"])
        self.assertEqual([e["status"] for e in events if e["event_type"] == "phase_result"],
                         ["SUCCEEDED", "SUCCEEDED"])

    def test_wrong_confirmation_stops_before_target_review(self):
        result = run_review_session(self.journal, probe=sample, confirm=lambda plan, phrase: "yes")
        self.assertEqual(result["status"], "BLOCKED")
        events = self.journal.read()
        self.assertEqual([e["phase"] for e in events if e["event_type"] == "phase_intent"], ["preflight"])
        self.assertEqual(events[-1]["status"], "STOP_AND_PRESERVE_EVIDENCE")

    def test_target_change_between_preflight_observations_blocks(self):
        first = sample()
        changed = sample()
        changed["devices"][0]["serial"] = "WRONG"
        values = iter([first, first, changed])
        result = run_review_session(self.journal, probe=lambda: copy.deepcopy(next(values)),
                                    confirm=lambda plan, phrase: phrase)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(self.journal.read()[-1]["status"], "FAILED")
        self.assertEqual(self.journal.read()[-1]["phase"], "preflight")

    def test_probe_failure_is_journaled(self):
        def fail():
            raise GuestProbeError("read-only lsblk probe timed out")
        result = run_review_session(self.journal, probe=fail, confirm=lambda plan, phrase: phrase)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(self.journal.read()[-1]["note_code"], "probe_timeout")

    def test_existing_journal_is_not_overwritten(self):
        self.journal.path.write_text("preserve")
        result = run_review_session(self.journal, probe=sample, confirm=lambda plan, phrase: phrase)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(self.journal.path.read_text(), "preserve")

    def test_target_change_after_confirmation_blocks(self):
        original = sample()
        changed = sample()
        changed["devices"][0]["size_bytes"] += 1024**3
        values = iter([original, original, original, changed])
        result = run_review_session(self.journal, probe=lambda: copy.deepcopy(next(values)),
                                    confirm=lambda plan, phrase: phrase)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(self.journal.read()[-1]["phase"], "explicit_target_review")
        self.assertEqual(self.journal.read()[-1]["status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
