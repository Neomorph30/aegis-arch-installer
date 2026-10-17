"""Integration tests for requiring ISO verification before VM preparation."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from lab.runtime import LabConfig, LabError, command_lines, prepare_workspace


class LabISOIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.code = self.root / "OVMF_CODE.fd"
        self.vars = self.root / "OVMF_VARS.fd"
        self.iso = self.root / "arch.iso"
        self.code.write_bytes(b"firmware-code")
        self.vars.write_bytes(b"firmware-vars")
        self.iso.write_bytes(b"synthetic iso test data")
        self.firmware = (self.code, self.vars)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Requires Linux workspace permissions (mode 0700)")
    def test_iso_without_expected_digest_is_refused_before_disk_creation(self):
        with self.assertRaisesRegex(LabError, "requires an independently supplied"):
            prepare_workspace(self.workspace, LabConfig(), self.firmware, self.iso)
        self.assertFalse((self.workspace / "primary.raw").exists())
        self.assertFalse((self.workspace / "secondary.raw").exists())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Requires Linux workspace permissions (mode 0700)")
    def test_iso_digest_without_iso_is_refused_before_disk_creation(self):
        with self.assertRaisesRegex(LabError, "without an ISO path"):
            prepare_workspace(self.workspace, LabConfig(), self.firmware, None, iso_sha256="a" * 64)
        self.assertFalse((self.workspace / "primary.raw").exists())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Requires Linux workspace permissions (mode 0700)")
    def test_verified_iso_is_copied_then_checked_before_qemu_args(self):
        digest = "a" * 64
        with patch("lab.runtime.verify_arch_iso", return_value={"verified": True, "sha256": digest}) as verify:
            prepared = prepare_workspace(self.workspace, LabConfig(), self.firmware,
                                         self.iso, iso_sha256=digest)
        self.assertTrue(prepared["iso"].is_file())
        verify.assert_called_once_with(prepared["iso"], digest)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Requires Linux workspace permissions (mode 0700)")
    def test_verified_iso_is_first_boot_device(self):
        with patch("lab.runtime.verify_arch_iso", return_value={"verified": True}):
            prepared = prepare_workspace(self.workspace, LabConfig(), self.firmware,
                                         self.iso, iso_sha256="c" * 64)
        _, qemu = command_lines(LabConfig(), self.firmware, prepared)
        boot_index = qemu.index("-boot")
        self.assertEqual(qemu[boot_index + 1], "order=d")
        self.assertIn("readonly=on", qemu[qemu.index("-drive", boot_index):][1])

    @unittest.skipUnless(sys.platform.startswith("linux"), "Requires Linux workspace permissions (mode 0700)")
    def test_integrity_failure_prevents_prepared_iso_from_being_returned(self):
        from lab.iso_validation import ISOValidationError
        with patch("lab.runtime.verify_arch_iso", side_effect=ISOValidationError("digest mismatch")):
            with self.assertRaisesRegex(LabError, "ISO verification failed"):
                prepare_workspace(self.workspace, LabConfig(), self.firmware,
                                  self.iso, iso_sha256="b" * 64)


if __name__ == "__main__":
    unittest.main()
