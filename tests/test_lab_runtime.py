"""Regression tests for the disposable VM launcher input boundaries."""
from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lab.runtime import LabError, main, type_qmp_command


class GuestPreflightLauncherTests(unittest.TestCase):
    def test_live_prompt_detection_rejects_boot_log_false_positives(self):
        from lab.runtime import _has_arch_live_root_prompt

        self.assertTrue(_has_arch_live_root_prompt("root@archiso ~ #"))
        self.assertTrue(_has_arch_live_root_prompt("root @ archiso ~ #"))
        self.assertTrue(_has_arch_live_root_prompt("root archiso ~ #"))
        self.assertFalse(_has_arch_live_root_prompt("root@archiso appears in boot log"))
        self.assertFalse(_has_arch_live_root_prompt(
            "root@archiso early hook #2 running hook archisol_loop_mnt"
        ))
        self.assertFalse(_has_arch_live_root_prompt(
            "root@archiso ~ #\\nservice starting"
        ))
        self.assertFalse(_has_arch_live_root_prompt(
            "archiso login: root automatic login to install arch linux"
        ))
        self.assertFalse(_has_arch_live_root_prompt(
            "arch linux 7.2.7-archiso-1 (tty1) archiso login: root (automatic login) to install arch linux follow the installation guide"
        ))
        self.assertFalse(_has_arch_live_root_prompt(
            "boot log root@archiso ~ # service starting"
        ))
        self.assertFalse(_has_arch_live_root_prompt(
            "root@archiso ~ #\\nservice starting"
        ))
        self.assertFalse(_has_arch_live_root_prompt(
            "running hook archiso_loop_mnt root=/dev/ram0 early hook udev"
        ))
        self.assertFalse(_has_arch_live_root_prompt("Arch Linux install medium"))

    def test_failure_screenshot_is_preserved_only_to_private_opt_in_directory(self):
        from lab.runtime import _preserve_failure_screenshot

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            screenshot = root / "screen.png"
            screenshot.write_bytes(b"diagnostic screenshot bytes")
            output = root / "diagnostics"
            output.mkdir(mode=0o700)
            with patch.dict(os.environ, {"AEGIS_LAB_DIAGNOSTICS_DIR": str(output)}):
                self.assertEqual(
                    _preserve_failure_screenshot(screenshot),
                    "final guest screen preserved as guest-screen.png",
                )
            saved = output / "guest-screen.png"
            self.assertEqual(saved.read_bytes(), screenshot.read_bytes())
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)

    def test_failure_screenshot_diagnostics_are_opt_in_and_never_overwrite(self):
        from lab.runtime import _preserve_failure_screenshot

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            screenshot = root / "screen.png"
            screenshot.write_bytes(b"screen")
            output = root / "diagnostics"
            output.mkdir(mode=0o700)
            with patch.dict(os.environ, {}, clear=True):
                self.assertIsNone(_preserve_failure_screenshot(screenshot))
            target = output / "guest-screen.png"
            target.write_bytes(b"existing evidence")
            with patch.dict(os.environ, {"AEGIS_LAB_DIAGNOSTICS_DIR": str(output)}):
                self.assertIsNone(_preserve_failure_screenshot(screenshot))
            self.assertEqual(target.read_bytes(), b"existing evidence")

    def test_failure_screenshot_rejects_non_private_diagnostics_directory(self):
        from lab.runtime import _preserve_failure_screenshot

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            screenshot = root / "screen.png"
            screenshot.write_bytes(b"screen")
            output = root / "diagnostics"
            output.mkdir(mode=0o755)
            with patch.dict(os.environ, {"AEGIS_LAB_DIAGNOSTICS_DIR": str(output)}):
                self.assertIsNone(_preserve_failure_screenshot(screenshot))
            self.assertFalse((output / "guest-screen.png").exists())

    def test_arch_login_banner_is_not_mistaken_for_prompt(self):
        from lab.runtime import _arch_live_root_prompt_line

        banner = (
            "arch linux 7.2.7-archiso-1 tty1 archiso login: root "
            "automatic login to install arch linux follow the installation guide"
        )
        self.assertIsNone(_arch_live_root_prompt_line(banner))
        self.assertEqual(_arch_live_root_prompt_line("root@archiso ~ #"), "root@archiso ~ #")

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
        self.assertFalse(any("scsi-id=1,drive=guestpayload" in arg for arg in qemu))
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
