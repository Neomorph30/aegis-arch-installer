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

    def test_profile_never_claims_installed(self):
        p = cli("profile", "--inventory", str(FIXTURE))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["status"], "RECOMMENDATIONS_ONLY")

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
