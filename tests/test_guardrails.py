"""Enforce preview-only boundaries while the project has no installation executor."""

import ast
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aegis import hardware
from aegis.cli import _load_json, _write_json

ROOT = Path(__file__).resolve().parent.parent


class GuardrailTests(unittest.TestCase):
    def test_no_disk_mutation_interface(self):
        import aegis
        self.assertFalse(hasattr(aegis, "install"))
        self.assertFalse(hasattr(aegis, "execute_install"))
        self.assertFalse((ROOT / "aegis" / "executor.py").exists())
        self.assertFalse((ROOT / "aegis" / "partitioner.py").exists())

    def test_subprocess_calls_confined_to_audited_modules(self):
        for file in (ROOT / "aegis").glob("*.py"):
            tree = ast.parse(file.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    if any(alias.name == "subprocess" for alias in node.names):
                        self.assertIn(file.name, {"hardware.py", "network.py"})
                if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                    self.fail(f"Unexpected subprocess import: {file}")
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                        self.assertEqual(node.func.attr, "run")
                        self.assertIn(file.name, {"hardware.py", "network.py"})
                        self.assertFalse(any(k.arg == "shell" and isinstance(k.value, ast.Constant)
                                             and k.value.value is True for k in node.keywords))

    def test_probes_are_explicitly_allowlisted(self):
        with self.assertRaises(hardware.HardwareInspectionError):
            hardware._run_readonly(["wipefs", "-a", "/dev/sdx"])
        with self.assertRaises(hardware.HardwareInspectionError):
            hardware._run_readonly(["lsblk", "--output", "PATH"])

    def test_reports_exclusively_create_mode_600_files(self):
        with tempfile.TemporaryDirectory() as d:
            destination = Path(d) / "plan.json"
            _write_json(str(destination), {
                "status": "PROPOSAL_ONLY",
                "password": "pw-seeded-1",
                "tpm-pin": "pin-seeded-2",
                "luks_recovery_key": "recovery-seeded-3",
                "signing_private_key": "private-seeded-4",
                "api_key": "api-seeded-5",
                "details": "credential=string-seeded-6 token:string-seeded-7",
            })
            self.assertEqual(os.stat(destination).st_mode & 0o777, 0o600)
            rendered = destination.read_text(encoding="utf-8")
            for secret in ("pw-seeded-1", "pin-seeded-2", "recovery-seeded-3",
                           "private-seeded-4", "api-seeded-5", "string-seeded-6",
                           "string-seeded-7"):
                self.assertNotIn(secret, rendered)
            clean = json.loads(rendered)
            self.assertEqual(clean["password"], "[REDACTED]")
            self.assertEqual(clean["tpm-pin"], "[REDACTED]")
            self.assertEqual(clean["luks_recovery_key"], "[REDACTED]")
            with self.assertRaises(FileExistsError):
                _write_json(str(destination), {"x": True})


    def test_cli_plan_outputs_reject_forged_verification_status(self):
        from contextlib import redirect_stderr, redirect_stdout
        from io import StringIO
        from aegis.cli import main

        with tempfile.TemporaryDirectory() as d:
            inventory = Path(d) / "inventory.json"
            inventory.write_text(json.dumps({"disks": []}), encoding="utf-8")
            forged_plan = {
                "status": "PROPOSAL_ONLY",
                "execution_enabled": False,
                "tests": [{"name": "fake verification", "result": "PASSED"}],
            }
            for output_file in (False, True):
                with self.subTest(output_file=output_file):
                    destination = Path(d) / "forged.json"
                    error, stdout = StringIO(), StringIO()
                    args = ["plan", "--primary", "/dev/fake",
                            "--inventory", str(inventory)]
                    if output_file:
                        args.extend(["--output", str(destination)])
                    with patch("aegis.cli.build_storage_plan", return_value=forged_plan):
                        with redirect_stderr(error), redirect_stdout(stdout):
                            result = main(args)
                    self.assertEqual(result, 2)
                    self.assertIn("claims execution", error.getvalue())
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertFalse(destination.exists())

    def test_report_output_rejects_existing_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            protected = Path(d) / "protected.txt"
            protected.write_text("do not replace")
            link = Path(d) / "alias.json"
            link.symlink_to(protected)
            with self.assertRaises(OSError):
                _write_json(str(link), {"x": 1})
            self.assertEqual(protected.read_text(), "do not replace")

    def test_large_input_json_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            filename = Path(d) / "large.json"
            filename.write_text('{"x":"' + 'a' * (2 * 1024 * 1024) + '"}')
            with self.assertRaises(ValueError):
                _load_json(str(filename))

    def test_fixture_does_not_access_machine(self):
        # Simulated inventory never runs actual hardware probes.
        fixture = ROOT / "fixtures" / "desktop-example.json"
        with patch("aegis.cli.inspect", side_effect=AssertionError("live hardware accessed")):
            from aegis.cli import _inventory
            data = _inventory(str(fixture))
        self.assertEqual(data["cpu"], "Intel Core Ultra 7 265K (EXAMPLE HARDWARE)")


if __name__ == "__main__":
    unittest.main()
