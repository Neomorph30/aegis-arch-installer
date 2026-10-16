import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "desktop-example.json"


def cli(*args, input_text=None):
    return subprocess.run([sys.executable, "-m", "aegis", *args], cwd=ROOT,
                          input=input_text, capture_output=True, text=True, timeout=15)


class CLIIntegrationTests(unittest.TestCase):
    def test_fixture_hardware_cli(self):
        result = cli("inspect", "--inventory", str(FIXTURE), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["disks"]), 3)

    def test_proposal_and_html_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            proposal = Path(directory) / "proposal.json"
            html = Path(directory) / "report.html"
            p = cli("plan", "--inventory", str(FIXTURE), "--primary", "/dev/nvme0n1",
                    "--secondary", "/dev/sda", "--output", str(proposal))
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertFalse(json.loads(proposal.read_text())["execution_enabled"])
            r = cli("report", "--plan", str(proposal), "--output", str(html))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("NO INSTALLATION HAS TAKEN PLACE", html.read_text())
            self.assertNotIn("EXAMPLE-NVME-0001", html.read_text())
            reattempt = cli("plan", "--inventory", str(FIXTURE), "--primary", "/dev/nvme0n1", "--output", str(proposal))
            self.assertEqual(reattempt.returncode, 2)
            self.assertIn("exist", reattempt.stderr.lower())

    def test_wizard_fixture_simulation(self):
        p = cli("wizard", "--inventory", str(FIXTURE), input_text="1\n2\n1\n1\n\n")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("NON-DESTRUCTIVE", p.stdout)
        self.assertIn("No installation or disk modifications occurred", p.stdout)

    def test_wizard_cancel_safe(self):
        p = cli("wizard", "--inventory", str(FIXTURE), input_text="\n")
        self.assertEqual(p.returncode, 0)
        self.assertIn("Cancelled", p.stdout)

    def test_profile_never_claims_installed_and_defaults_to_kde(self):
        p = cli("profile", "--inventory", str(FIXTURE))
        self.assertEqual(p.returncode, 0, p.stderr)
        result = json.loads(p.stdout)
        self.assertEqual(result["status"], "RECOMMENDATIONS_ONLY")
        self.assertEqual(result["desktop"]["id"], "kde-plasma")

    def test_profile_rejects_unqualified_desktop(self):
        p = cli("profile", "--inventory", str(FIXTURE), "--desktop", "gnome")
        self.assertEqual(p.returncode, 2)
        self.assertIn("not yet qualified", p.stderr)

    def test_profile_explicit_kde_selection(self):
        p = cli("profile", "--inventory", str(FIXTURE), "--desktop", "kde-plasma")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["desktop"]["id"], "kde-plasma")

    def test_report_rejects_executable_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            proposal = Path(directory) / "unsafe.json"
            proposal.write_text(json.dumps({"status": "PROPOSAL_ONLY", "execution_enabled": True}))
            p = cli("report", "--plan", str(proposal), "--output", str(Path(directory) / "r.html"))
            self.assertEqual(p.returncode, 2)
            self.assertIn("Refusing report", p.stderr)


if __name__ == "__main__":
    unittest.main()

class MenuIntegrationTests(unittest.TestCase):
    def test_menu_hardware_and_exit_fixture(self):
        with __import__("unittest.mock").mock.patch("sys.stdin.isatty", return_value=True):
            from aegis.cli import menu
            from unittest.mock import patch
            import io
            with patch("builtins.input", side_effect=["1", "5"]), patch("sys.stdout", new_callable=io.StringIO) as out:
                result = menu(str(FIXTURE))
            self.assertEqual(result, 0)
            self.assertIn("EXAMPLE", out.getvalue())
            self.assertIn("Exiting without changes", out.getvalue())

    def test_unattended_invocation_prints_help_not_prompts(self):
        p = cli()
        self.assertEqual(p.returncode, 0)
        self.assertIn("usage", p.stdout)


class ProposalOutputHardeningTests(unittest.TestCase):
    def _valid_proposal(self, directory):
        proposal = Path(directory) / "proposal.json"
        generated = cli("plan", "--inventory", str(FIXTURE), "--primary", "/dev/nvme0n1",
                        "--output", str(proposal))
        self.assertEqual(generated.returncode, 0, generated.stderr)
        return proposal

    def test_cli_rejects_forged_verification_before_creating_html(self):
        for status in ("PASSED", "PASS", "SUCCESS", "verified", "COMPLETE"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                proposal = self._valid_proposal(directory)
                data = json.loads(proposal.read_text(encoding="utf-8"))
                data["tests"][0]["result"] = status
                data["warnings"].append("password=CANARY_PASSWORD_71c2")
                proposal.write_text(json.dumps(data), encoding="utf-8")
                output = Path(directory) / "report.html"
                result = cli("report", "--plan", str(proposal), "--output", str(output))
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertFalse(output.exists(), "invalid evidence must be rejected before output creation")
                self.assertNotIn(status, result.stdout + result.stderr)
                self.assertNotIn("CANARY_PASSWORD_71c2", result.stdout + result.stderr)

    def test_cli_rejects_forged_verification_before_overwriting_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            proposal = self._valid_proposal(directory)
            data = json.loads(proposal.read_text(encoding="utf-8"))
            data["tests"][0]["result"] = "PASSED"
            proposal.write_text(json.dumps(data), encoding="utf-8")
            output = Path(directory) / "existing.html"
            sentinel = "DO_NOT_OVERWRITE_CANARY_9d21"
            output.write_text(sentinel, encoding="utf-8")
            result = cli("report", "--plan", str(proposal), "--output", str(output))
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertEqual(output.read_text(encoding="utf-8"), sentinel)
            self.assertNotIn(sentinel, result.stdout + result.stderr)

    def test_cli_report_redacts_synthetic_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            proposal = self._valid_proposal(directory)
            data = json.loads(proposal.read_text(encoding="utf-8"))
            data["warnings"].append(
                "password=CANARY_PASSWORD_a1 "
                "tpm_pin:CANARY_TPM_PIN_b2 "
                "luks_recovery_key=CANARY_LUKS_RECOVERY_c3 "
                "private_key=CANARY_PRIVATE_KEY_d4 "
                "api_key=CANARY_API_KEY_e5 "
                "credential=CANARY_CREDENTIAL_f6"
            )
            proposal.write_text(json.dumps(data), encoding="utf-8")
            output = Path(directory) / "shareable.html"
            result = cli("report", "--plan", str(proposal), "--output", str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            rendered = output.read_text(encoding="utf-8")
            for secret in (
                "CANARY_PASSWORD_a1", "CANARY_TPM_PIN_b2", "CANARY_LUKS_RECOVERY_c3",
                "CANARY_PRIVATE_KEY_d4", "CANARY_API_KEY_e5", "CANARY_CREDENTIAL_f6",
            ):
                with self.subTest(secret=secret):
                    self.assertNotIn(secret, rendered)
            self.assertIn("[REDACTED]", rendered)
