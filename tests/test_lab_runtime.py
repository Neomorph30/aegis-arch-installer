"""Regression tests for the disposable VM launcher input boundaries."""
from __future__ import annotations

import contextlib
import io
from pathlib import Path
import unittest

from lab.runtime import LabError, main, type_qmp_command


class GuestPreflightLauncherTests(unittest.TestCase):
    def test_qmp_typing_refuses_uppercase_and_unapproved_characters_before_connecting(self):
        for command in ("echo OK", "python /tmp/a.py", "echo $HOME", ""):
            with self.subTest(command=command), self.assertRaises(LabError):
                type_qmp_command(Path("/tmp/nonexistent-qmp-socket"), command)

    def test_guest_preflight_vm_has_explicit_keyboard_and_read_only_payload(self):
        import tempfile
        from lab.runtime import LabConfig, command_lines

        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            prepared = {
                "primary": folder / "primary.raw",
                "secondary": folder / "secondary.raw",
                "vars": folder / "OVMF_VARS.fd",
                "tpm_dir": folder / "tpm-state",
                "tpm_sock": folder / "tpm.sock",
                "qmp_sock": folder / "qmp.sock",
                "iso": folder / "installer.iso",
                "payload_iso": folder / "guest-preflight.iso",
            }
            _, qemu = command_lines(
                LabConfig(), (folder / "OVMF_CODE.fd", folder / "OVMF_VARS.fd"),
                prepared, observe_boot=True, observe_guest_preflight=True,
            )
        self.assertIn("qemu-xhci,id=usb", qemu)
        self.assertIn("usb-kbd,bus=usb.0", qemu)
        self.assertIn("scsi-cd,bus=scsi0.0,scsi-id=1,drive=guestpayload", qemu)
        payload_drive = next(arg for arg in qemu if "id=guestpayload" in arg and arg.startswith("if=none"))
        self.assertIn("readonly=on", payload_drive)

    def test_guest_preflight_requires_explicit_payload(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = main(["--smoke", "--observe-guest-preflight"])
        self.assertEqual(result, 2)
        self.assertIn("--guest-preflight-payload", stderr.getvalue())

    def test_guest_payload_requires_explicit_preflight_mode(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = main(["--smoke", "--guest-preflight-payload", "/tmp/payload.iso"])
        self.assertEqual(result, 2)
        self.assertIn("--observe-guest-preflight", stderr.getvalue())

    def test_guest_preflight_cannot_be_combined_with_live_only_observation(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = main([
                "--smoke", "--observe-live", "--observe-guest-preflight",
                "--guest-preflight-payload", "/tmp/payload.iso",
            ])
        self.assertEqual(result, 2)
        self.assertIn("choose only one boot observation mode", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
