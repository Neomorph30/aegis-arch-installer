"""Layer 01 capability gates must never overstate pre-alpha readiness."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

from aegis.assurance import CAPABILITIES, manifest
from tools.security_lint import check_source, run_check

ROOT = Path(__file__).resolve().parent.parent


class AssuranceTests(unittest.TestCase):
    def test_declaration_is_explicitly_non_production(self):
        m = manifest()
        self.assertEqual(m["schema_version"], 1)
        self.assertFalse(m["installation_enabled"])
        self.assertFalse(m["security_certification"])
        self.assertEqual(m["external_security_review"], "NOT_COMPLETED")
        self.assertTrue(all(c.status in ("PREVIEW_ONLY", "NOT_IMPLEMENTED") for c in CAPABILITIES))

    def test_unique_capability_ids_with_provenance(self):
        self.assertEqual(len({c.id for c in CAPABILITIES}), len(CAPABILITIES))
        self.assertTrue(all(c.description and c.evidence for c in CAPABILITIES))
        self.assertEqual(next(c.status for c in CAPABILITIES if c.id == "privileged-executor"), "NOT_IMPLEMENTED")

    def test_layer07_primitives_are_preview_only_and_not_installation(self):
        capabilities = {item.id: item for item in CAPABILITIES}
        for name in ("disposable-vm-lab", "guest-install-preflight", "iso-integrity-gate", "transaction-journal"):
            self.assertEqual(capabilities[name].status, "PREVIEW_ONLY")
            self.assertTrue(capabilities[name].evidence)
        self.assertEqual(capabilities["privileged-executor"].status, "NOT_IMPLEMENTED")
        self.assertFalse(manifest()["installation_enabled"])

    def test_cli_assurance_json(self):
        p = subprocess.run([sys.executable, "-m", "aegis", "assurance", "--json"],
                           cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stderr)
        m = json.loads(p.stdout)
        self.assertFalse(m["installation_enabled"])
        self.assertIn("security-guardian", [c["id"] for c in m["capabilities"]])

    def test_cli_assurance_never_claims_security_verified(self):
        p = subprocess.run([sys.executable, "-m", "aegis", "assurance"],
                           cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("NOT SECURITY CERTIFIED", p.stdout)
        self.assertIn("No installation or disk writes", p.stdout)

    def test_versioned_requirements(self):
        data = json.loads((ROOT / "docs" / "SECURITY_REQUIREMENTS.json").read_text())
        self.assertEqual(data["schema_version"], 1)
        self.assertNotIn("CERTIFIED", data["status"].split("_"))
        reqs = data["requirements"]
        self.assertGreaterEqual(len(reqs), 12)
        self.assertEqual(len(reqs), len({r["id"] for r in reqs}))
        allowed = {"NOT_IMPLEMENTED", "PARTIAL", "PREVIEW_IMPLEMENTED_UNQUALIFIED"}
        self.assertTrue(all(r["implementation"] in allowed for r in reqs))
        self.assertTrue(all(r["requirement"] and r["evidence_required"] and r["gate"] for r in reqs))

    def test_required_security_documents(self):
        for doc in ("SUPPORT_MATRIX.md", "QUALITY_STANDARDS.md", "RISK_REGISTER.md", "THREAT_MODEL.md", "RELEASE_GATES.md"):
            self.assertTrue((ROOT / "docs" / doc).is_file(), doc)


class PreviewStaticGuardTests(unittest.TestCase):
    def test_current_source_clean(self):
        self.assertEqual([], run_check(ROOT))

    def test_reject_privileged_module(self):
        self.assertIn("executor-like", " ".join(check_source("pass", "aegis/executor.py")))

    def test_reject_mutating_primitives(self):
        samples = [
            "import os\nos.system('wipefs -a /dev/sda')",
            "import subprocess\nsubprocess.run(['echo','hi'])",
            "import subprocess\nsubprocess.run(['echo'], shell=True)",
            "import subprocess\nsubprocess.run(['echo'], **{'shell':True})",
            "from subprocess import run\nrun(['echo'])",
            "from ctypes import CDLL",
            "def wipe_disk(): pass",
            "exec('print(1)')",
            "import os as shell_api\nshell_api.system('true')",
            "from os import system as spawn_it\nspawn_it('true')",
            "import subprocess as subprocess2\nsubprocess2.run(['true'])",
            "getattr(__import__('os'),'system')('true')",
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(check_source(sample, "aegis/test_feature.py"))

    def test_reject_shell_even_in_allowlisted_module(self):
        self.assertTrue(check_source("import subprocess\nsubprocess.run(['echo'], shell=True)", "aegis/network.py"))
        self.assertFalse(check_source("import subprocess\nsubprocess.run(['echo'], shell=False)", "aegis/network.py"))

    def test_ci_policy_rejects_unpinned_action(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "aegis").mkdir()
            (root / "aegis" / "__init__.py").write_text("\n")
            path = root / ".github" / "workflows" / "test.yml"
            path.parent.mkdir(parents=True)
            path.write_text("permissions:\n  contents: read\nsteps:\n  - uses: actions/checkout@v6\n  - run: python tools/security_lint.py\n  - persist-credentials: false\n")
            violations = run_check(root)
            self.assertTrue(any("pinned" in item for item in violations), violations)

    def test_invalid_source_rejected(self):
        self.assertIn("invalid Python syntax", " ".join(check_source("def bad(", "aegis/z.py")))


if __name__ == "__main__":
    unittest.main()
