"""Integrity and identity checks for Arch ISO boot media."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from lab.iso_validation import ISOValidationError, main, verify_arch_iso


def make_iso(path: Path, *, label: str = "ARCH_202610", size: int = 40 * 1024) -> str:
    payload = bytearray(size)
    offset = 16 * 2048
    payload[offset] = 1
    payload[offset + 1:offset + 6] = b"CD001"
    payload[offset + 6] = 1
    payload[offset + 40:offset + 72] = label.encode("ascii").ljust(32, b" ")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


class ArchISOValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "arch.iso"
        self.digest = make_iso(self.path)

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "O_NOFOLLOW"), "Requires Linux O_NOFOLLOW file-open flag")
    def test_valid_arch_iso_requires_pinned_digest(self):
        result = verify_arch_iso(self.path, self.digest, min_size=32 * 1024)
        self.assertTrue(result["verified"])
        self.assertEqual(result["sha256"], self.digest)
        self.assertEqual(result["volume_label"], "ARCH_202610")

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "O_NOFOLLOW"), "Requires Linux O_NOFOLLOW file-open flag")
    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ISOValidationError, "does not match"):
            verify_arch_iso(self.path, "0" * 64, min_size=32 * 1024)

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "O_NOFOLLOW"), "Requires Linux O_NOFOLLOW file-open flag")
    def test_non_arch_volume_label_rejected(self):
        digest = make_iso(self.path, label="MY_CUSTOM_LINUX")
        with self.assertRaisesRegex(ISOValidationError, "volume label"):
            verify_arch_iso(self.path, digest, min_size=32 * 1024)

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "O_NOFOLLOW"), "Requires Linux O_NOFOLLOW file-open flag")
    def test_malformed_iso9660_descriptor_rejected(self):
        self.path.write_bytes(b"X" * (40 * 1024))
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ISOValidationError, "descriptor"):
            verify_arch_iso(self.path, digest, min_size=32 * 1024)

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "O_NOFOLLOW"), "Requires Linux O_NOFOLLOW file-open flag")
    def test_too_small_iso_rejected(self):
        small = self.path
        small.write_bytes(b"small")
        digest = hashlib.sha256(b"small").hexdigest()
        with self.assertRaisesRegex(ISOValidationError, "too small"):
            verify_arch_iso(small, digest, min_size=1)

    def test_invalid_digest_format_rejected(self):
        with self.assertRaisesRegex(ISOValidationError, "64 hexadecimal"):
            verify_arch_iso(self.path, "not-a-digest", min_size=32 * 1024)

    def test_cli_emits_machine_readable_success(self):
        with patch("lab.iso_validation.verify_arch_iso", return_value={
            "verified": True, "size_bytes": 200 * 1024**2,
            "sha256": "a" * 64, "volume_label": "ARCH_202610",
        }), contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = main(["--iso", "arch.iso", "--sha256", "a" * 64])
        self.assertEqual(code, 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["status"], "VERIFIED_ARCH_ISO")
        self.assertFalse(result["execution_enabled"])

    def test_cli_failure_emits_blocked_recovery_record(self):
        with patch("lab.iso_validation.verify_arch_iso", side_effect=ISOValidationError("digest mismatch")), \
             contextlib.redirect_stdout(io.StringIO()) as stdout, \
             contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = main(["--iso", "arch.iso", "--sha256", "b" * 64])
        self.assertEqual(code, 2)
        result = __import__("json").loads(stdout.getvalue())
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["verified"])
        self.assertIn("independently trusted official source", result["recovery"])
        self.assertIn("do not boot", stderr.getvalue())

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "O_NOFOLLOW"), "Requires Linux unprivileged symlinks and O_NOFOLLOW")
    def test_symlink_rejected(self):
        link = Path(self.temp.name) / "linked.iso"
        link.symlink_to(self.path)
        with self.assertRaisesRegex(ISOValidationError, "symlink or device"):
            verify_arch_iso(link, self.digest, min_size=32 * 1024)


if __name__ == "__main__":
    unittest.main()
