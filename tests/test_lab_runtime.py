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
