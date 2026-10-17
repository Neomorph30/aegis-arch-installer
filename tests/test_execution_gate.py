"""Tests for the review-only phase gate; no guest or disk commands are run."""
from __future__ import annotations

import json
import unittest

from lab.execution_gate import assess_phase_request, confirmation_phrase
from lab.guest_preflight import run_preflight
from lab.workflow_plan import build_review_plan


def observation():
    return {
        "environment": {"sys_vendor": "QEMU", "product_name": "Standard PC Q35"},
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


class ExecutionGateTests(unittest.TestCase):
    def setUp(self):
        self.observed = observation()
        code, spec = run_preflight(lambda: self.observed)
        self.assertEqual(code, 0)
        self.plan = build_review_plan(spec, self.observed)

    def assess(self, phase, confirmation=None, events=None, obs=None, plan=None):
        return assess_phase_request(
            self.plan if plan is None else plan,
            self.observed if obs is None else obs,
            phase, confirmation, [] if events is None else events,
        )

    def test_read_only_preflight_gate_passes_without_confirmation(self):
        result = self.assess("preflight")
        self.assertEqual(result["status"], "GATE_PASSED_REVIEW_ONLY")
        self.assertFalse(result["execution_enabled"])
        self.assertFalse(result["commands_executed"])
        self.assertFalse(result["journal_written"])
        self.assertFalse(result["disk_changes_performed"])

    def test_destructive_phase_requires_exact_target_phrase(self):
        self.assertEqual(self.assess("partition_gpt")["status"], "BLOCKED")
        phrase = confirmation_phrase(self.plan["target"])
        self.assertIn("AEGIS-LAB-PRIMARY", phrase)
        result = self.assess("partition_gpt", confirmation=phrase)
        self.assertEqual(result["status"], "BLOCKED")  # explicit target-review phase has not succeeded

    def test_explicit_target_review_requires_exact_confirmation(self):
        from lab.transaction_journal import TransactionJournal
        import tempfile
        from pathlib import Path
        phrase = confirmation_phrase(self.plan["target"])
        self.assertEqual(self.assess("explicit_target_review", confirmation="yes")["status"], "BLOCKED")
        with tempfile.TemporaryDirectory() as tmp:
            journal = TransactionJournal(Path(tmp) / "journal.jsonl")
            journal.append("phase_intent", phase="preflight", status="STARTED")
            journal.append("phase_result", phase="preflight", status="SUCCEEDED")
            result = self.assess("explicit_target_review", confirmation=phrase, events=journal.read())
        self.assertEqual(result["status"], "GATE_PASSED_REVIEW_ONLY")
        self.assertFalse(result["execution_enabled"])

    def test_target_review_then_partition_gate_requires_journal_evidence(self):
        from lab.transaction_journal import TransactionJournal
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            journal = TransactionJournal(Path(tmp) / "journal.jsonl")
            journal.append("phase_intent", phase="preflight", status="STARTED")
            journal.append("phase_result", phase="preflight", status="SUCCEEDED")
            journal.append("phase_intent", phase="explicit_target_review", status="STARTED")
            journal.append("phase_result", phase="explicit_target_review", status="SUCCEEDED")
            result = self.assess("partition_gpt", confirmation=confirmation_phrase(self.plan["target"]),
                                 events=journal.read())
        self.assertEqual(result["status"], "GATE_PASSED_REVIEW_ONLY")
        self.assertFalse(result["execution_enabled"])
        self.assertFalse(result["journal_written"])

    def test_changed_target_fails_closed(self):
        changed = observation()
        changed["devices"][0]["serial"] = "WRONG-DISK"
        self.assertEqual(self.assess("preflight", obs=changed)["status"], "BLOCKED")

    def test_altered_plan_gate_fails_closed(self):
        altered = json.loads(json.dumps(self.plan))
        altered["phases"][2]["required_gates"] = []
        self.assertEqual(self.assess("partition_gpt", confirmation="CONFIRM AEGIS-LAB-PRIMARY 24 GiB",
                                     plan=altered)["status"], "BLOCKED")

    def test_unknown_phase_fails_closed(self):
        self.assertEqual(self.assess("run-arbitrary-shell", confirmation="yes")["status"], "BLOCKED")

    def test_malformed_extra_phase_entry_fails_closed_without_exception(self):
        altered = json.loads(json.dumps(self.plan))
        altered["phases"].append("unexpected non-object phase")
        result = self.assess("preflight", plan=altered)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["execution_enabled"])
        self.assertFalse(result["disk_changes_performed"])

    def test_invalid_journal_fails_closed(self):
        self.assertEqual(self.assess("preflight", events=[{"password": "secret"}])["status"], "BLOCKED")

    def test_completed_phase_cannot_be_retried(self):
        from lab.transaction_journal import TransactionJournal
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            journal = TransactionJournal(Path(tmp) / "journal.jsonl")
            journal.append("phase_intent", phase="preflight", status="STARTED")
            journal.append("phase_result", phase="preflight", status="SUCCEEDED")
            result = self.assess("preflight", events=journal.read())
        self.assertEqual(result["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
