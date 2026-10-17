"""Safety and recovery tests for the Layer 07 transaction journal."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from lab.transaction_journal import (
    JournalError,
    TransactionJournal,
    assess_recovery,
    parse_journal,
)


class TransactionJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "install.jsonl"
        self.journal = TransactionJournal(self.path)

    def test_hash_chained_intent_and_result_round_trip(self):
        intent = self.journal.append("phase_intent", phase="preflight", status="STARTED")
        result = self.journal.append("phase_result", phase="preflight", status="SUCCEEDED", exit_code=0)
        events = self.journal.read()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["event_hash"], intent["event_hash"])
        self.assertEqual(events[1]["previous_hash"], intent["event_hash"])
        self.assertEqual(events[1]["event_hash"], result["event_hash"])
        self.assertEqual(assess_recovery(events)["action"], "REVIEW_BEFORE_NEXT_PHASE")

    def test_new_journal_fsyncs_file_and_parent_directory(self):
        from unittest.mock import patch
        with patch("lab.transaction_journal.os.fsync", wraps=os.fsync) as sync:
            self.journal.append("phase_intent", phase="preflight", status="STARTED")
        self.assertEqual(sync.call_count, 2)

    def test_existing_journal_append_fsyncs_file(self):
        self.journal.append("phase_intent", phase="preflight", status="STARTED")
        from unittest.mock import patch
        with patch("lab.transaction_journal.os.fsync", wraps=os.fsync) as sync:
            self.journal.append("phase_result", phase="preflight", status="SUCCEEDED")
        self.assertEqual(sync.call_count, 1)

    def test_destructive_failure_requires_preserving_evidence(self):
        self.journal.append("phase_intent", phase="partition_gpt", status="STARTED")
        self.journal.append("phase_result", phase="partition_gpt", status="FAILED",
                            note_code="command_nonzero", exit_code=1)
        assessment = assess_recovery(self.journal.read())
        self.assertEqual(assessment["action"], "STOP_AND_PRESERVE_EVIDENCE")
        self.assertEqual(assessment["reason"], "destructive_phase_failed")

    def test_unmatched_intent_is_ambiguous_and_cannot_resume(self):
        self.journal.append("phase_intent", phase="luks2_format_root", status="STARTED")
        self.assertEqual(assess_recovery(self.journal.read())["action"], "STOP_AND_PRESERVE_EVIDENCE")
        with self.assertRaisesRegex(JournalError, "no result"):
            self.journal.append("phase_intent", phase="format_btrfs", status="STARTED")

    def test_automatic_retry_of_completed_phase_is_forbidden(self):
        self.journal.append("phase_intent", phase="preflight", status="STARTED")
        self.journal.append("phase_result", phase="preflight", status="FAILED", note_code="probe_timeout")
        with self.assertRaisesRegex(JournalError, "retries are forbidden"):
            self.journal.append("phase_intent", phase="preflight", status="STARTED")

    def test_result_without_intent_is_forbidden(self):
        with self.assertRaisesRegex(JournalError, "no unique unmatched intent"):
            self.journal.append("phase_result", phase="format_efi", status="FAILED")

    def test_corrupt_hash_chain_is_rejected(self):
        self.journal.append("phase_intent", phase="preflight", status="STARTED")
        raw = self.path.read_text()
        event = json.loads(raw)
        event["phase"] = "partition_gpt"
        self.path.write_text(json.dumps(event) + "\n")
        with self.assertRaisesRegex(JournalError, "hash mismatch"):
            self.journal.read()

    def test_partial_final_record_is_preserved_and_rejected(self):
        self.journal.append("phase_intent", phase="preflight", status="STARTED")
        with self.path.open("ab") as stream:
            stream.write(b'{"partial":')
        with self.assertRaisesRegex(JournalError, "incomplete record"):
            self.journal.read()

    def test_arbitrary_free_form_fields_are_rejected(self):
        self.journal.append("phase_intent", phase="preflight", status="STARTED")
        event = self.journal.read()[0]
        event["password"] = "must never be accepted"
        with self.assertRaisesRegex(JournalError, "schema mismatch"):
            parse_journal((json.dumps(event) + "\n").encode())

    def test_unresolved_phase_only_allows_stop_recovery_decision(self):
        self.journal.append("phase_intent", phase="format_btrfs", status="STARTED")
        with self.assertRaisesRegex(JournalError, "only stop and preserve"):
            self.journal.append("recovery_decision", status="RECREATE_EPHEMERAL_VM_AFTER_EVIDENCE_CAPTURE")
        self.journal.append("recovery_decision", status="STOP_AND_PRESERVE_EVIDENCE",
                            note_code="state_ambiguous")
        self.assertEqual(self.journal.read()[-1]["event_type"], "recovery_decision")

    def test_malformed_hash_type_is_rejected_as_journal_error(self):
        self.journal.append("phase_intent", phase="preflight", status="STARTED")
        event = self.journal.read()[0]
        event["event_hash"] = 123
        with self.assertRaisesRegex(JournalError, "event hash is malformed"):
            parse_journal((json.dumps(event) + "\n").encode())

    def test_malformed_field_types_raise_journal_error(self):
        self.journal.append("phase_intent", phase="preflight", status="STARTED")
        event = self.journal.read()[0]
        event["phase"] = []
        with self.assertRaisesRegex(JournalError, "phase is not allowlisted"):
            parse_journal((json.dumps(event) + "\n").encode())

    def test_oversized_journal_is_rejected(self):
        with self.assertRaisesRegex(JournalError, "exceeds the supported evidence size"):
            parse_journal(b"x" * (1024 * 1024 + 1))

    def test_append_cannot_grow_journal_past_configured_limit(self):
        from unittest.mock import patch
        self.journal.append("phase_intent", phase="preflight", status="STARTED")
        existing_size = self.path.stat().st_size
        with patch("lab.transaction_journal.MAX_JOURNAL_BYTES", existing_size):
            with self.assertRaisesRegex(JournalError, "Appending would exceed"):
                self.journal.append("phase_result", phase="preflight", status="SUCCEEDED")
        self.assertEqual(self.path.stat().st_size, existing_size)
        self.assertEqual(len(self.journal.read()), 1)

    def test_oversized_journal_file_is_rejected_by_read_and_append(self):
        self.path.write_bytes(b"x" * (1024 * 1024 + 1))
        os.chmod(self.path, 0o600)
        with self.assertRaisesRegex(JournalError, "exceeds the supported evidence size"):
            self.journal.read()
        with self.assertRaisesRegex(JournalError, "exceeds the supported evidence size"):
            self.journal.append("phase_intent", phase="preflight", status="STARTED")
        self.assertEqual(self.path.stat().st_size, 1024 * 1024 + 1)


    def test_symlink_journal_is_rejected(self):
        target = Path(self.temp.name) / "target"
        target.write_text("")
        self.path.symlink_to(target)
        with self.assertRaises(JournalError):
            self.journal.append("phase_intent", phase="preflight", status="STARTED")

    def test_note_code_is_allowlisted_and_no_free_form_message_exists(self):
        with self.assertRaisesRegex(JournalError, "allowlisted"):
            self.journal.append("phase_intent", phase="preflight", status="STARTED",
                                note_code="credential=secret")

    def test_file_permissions_are_private(self):
        self.journal.append("phase_intent", phase="preflight", status="STARTED")
        os.chmod(self.path, 0o644)
        with self.assertRaisesRegex(JournalError, "private single-link"):
            self.journal.read()


if __name__ == "__main__":
    unittest.main()
