"""CLI tests for safe, read-only workflow-plan construction."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from lab.guest_preflight import run_preflight
from lab.workflow_plan_cli import main


def observation():
    return {
        "environment": {"sys_vendor": "QEMU", "product_name": "Standard PC Q35"},
        "network_mode": "disabled",
        "active_swaps": [],
        "devices": [
            {"path": "/dev/vda", "type": "disk", "serial": "AEGIS-LAB-PRIMARY",
             "size_bytes": 24 * 1024**3, "read_only": False, "mountpoints": [],
             "holders": [], "active_swap": False, "children": []},
            {"path": "/dev/vdb", "type": "disk", "serial": "AEGIS-LAB-SECONDARY",
             "size_bytes": 8 * 1024**3, "read_only": True, "mountpoints": [],
             "holders": [], "active_swap": False, "children": []},
            {"path": "/dev/sr0", "type": "rom", "read_only": True},
        ],
    }


class WorkflowPlanCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o700)
        code, self.spec = run_preflight(observation)
        self.assertEqual(code, 0)
        self.spec_path = self.root / "spec.json"
        self.obs_path = self.root / "observation.json"
        self.spec_path.write_text(json.dumps(self.spec), encoding="utf-8")
        self.obs_path.write_text(json.dumps(observation()), encoding="utf-8")
        os.chmod(self.spec_path, 0o600)
        os.chmod(self.obs_path, 0o600)

    def tearDown(self):
        self.tmp.cleanup()

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "O_NOFOLLOW"), "Requires Linux O_NOFOLLOW file-open flag")
    def test_valid_files_emit_review_only_plan(self):
        from contextlib import redirect_stdout, redirect_stderr
        from io import StringIO
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--spec", str(self.spec_path), "--observation", str(self.obs_path)])
        result = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "TARGET_RECONFIRMED_REVIEW_PLAN")
        self.assertFalse(result["execution_enabled"])
        self.assertFalse(result["disk_changes_performed"])

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "O_NOFOLLOW"), "Requires Linux O_NOFOLLOW file-open flag")
    def test_changed_observation_fails_closed(self):
        from contextlib import redirect_stdout, redirect_stderr
        from io import StringIO
        changed = observation()
        changed["devices"][0]["serial"] = "NOT-THE-LAB-DISK"
        self.obs_path.write_text(json.dumps(changed), encoding="utf-8")
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--spec", str(self.spec_path), "--observation", str(self.obs_path)])
        result = json.loads(stdout.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["disk_changes_performed"])

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "O_NOFOLLOW"), "Requires Linux unprivileged symlinks and O_NOFOLLOW")
    def test_symlink_input_is_rejected(self):
        from contextlib import redirect_stdout, redirect_stderr
        from io import StringIO
        link = self.root / "linked.json"
        link.symlink_to(self.spec_path)
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--spec", str(link), "--observation", str(self.obs_path)])
        result = json.loads(stdout.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "BLOCKED")

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "O_NOFOLLOW"), "Requires Linux O_NOFOLLOW file-open flag")
    def test_non_object_json_is_rejected(self):
        from contextlib import redirect_stdout, redirect_stderr
        from io import StringIO
        self.spec_path.write_text("[]", encoding="utf-8")
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--spec", str(self.spec_path), "--observation", str(self.obs_path)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
