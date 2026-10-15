"""Layer 06: virtual-only boundary tests use regular files, never block devices."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from aegis.planner import build_storage_plan
from aegis.virtual_executor import VirtualExecutionError, simulate_execution

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = json.loads((ROOT / "fixtures" / "desktop-example.json").read_text())


class VirtualExecutionBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "private"
        self.root.mkdir(mode=0o700)
        self.image = self.root / "primary.raw"
        self.image.write_bytes(b"synthetic test disk; no partition table")
        self.image.chmod(0o600)
        self.plan = build_storage_plan(copy.deepcopy(FIXTURE), "/dev/nvme0n1")

    def approved(self):
        return {
            "/dev/nvme0n1": {
                "serial": self.plan["primary"]["serial"],
                "wwn": self.plan["primary"]["wwn"],
            }
        }

    def run_simulation(self, **overrides):
        args = {
            "plan": self.plan,
            "workspace": self.root,
            "virtual_targets": {"/dev/nvme0n1": self.image},
            "approved_identities": self.approved(),
        }
        args.update(overrides)
        return simulate_execution(**args)

    def test_records_simulation_without_mutating_image(self):
        before = self.image.read_bytes()
        record = self.run_simulation()
        self.assertEqual(record["mode"], "VIRTUAL_SIMULATION_ONLY")
        self.assertFalse(record["execution_performed"])
        self.assertFalse(record["physical_devices_accessed"])
        self.assertEqual(self.image.read_bytes(), before)
        journal = json.loads((self.root / "execution-journal.json").read_text())
        self.assertEqual(journal["plan_digest"], self.plan["plan_digest"])
        self.assertEqual((self.root / "execution-journal.json").stat().st_mode & 0o777, 0o600)

    def test_plan_tampering_is_rejected(self):
        self.plan["actions"][0]["target"] = "/dev/sda"
        with self.assertRaisesRegex(VirtualExecutionError, "digest"):
            self.run_simulation()

    def test_identity_mismatch_is_rejected(self):
        with self.assertRaisesRegex(VirtualExecutionError, "identity"):
            self.run_simulation(approved_identities={"/dev/nvme0n1": {"serial": "WRONG", "wwn": "WRONG"}})

    def test_every_destructive_target_requires_mapping_and_approval(self):
        with self.assertRaisesRegex(VirtualExecutionError, "explicit virtual mapping"):
            self.run_simulation(virtual_targets={}, approved_identities={})

    def test_symlink_target_rejected(self):
        link = self.root / "linked.raw"
        link.symlink_to(self.image)
        with self.assertRaisesRegex(VirtualExecutionError, "symlinks"):
            self.run_simulation(virtual_targets={"/dev/nvme0n1": link})

    def test_block_device_rejected(self):
        with self.assertRaises(VirtualExecutionError):
            self.run_simulation(virtual_targets={"/dev/nvme0n1": "/dev/null"})

    def test_target_outside_workspace_rejected(self):
        outside = Path(self.temp.name) / "outside.raw"
        outside.write_bytes(b"not in lab workspace")
        outside.chmod(0o600)
        with self.assertRaisesRegex(VirtualExecutionError, "direct children"):
            self.run_simulation(virtual_targets={"/dev/nvme0n1": outside})

    def test_public_workspace_rejected(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(VirtualExecutionError, "private directory"):
            self.run_simulation()

    def test_existing_journal_is_never_overwritten(self):
        journal = self.root / "execution-journal.json"
        journal.write_text("preserve evidence")
        with self.assertRaisesRegex(VirtualExecutionError, "already exists"):
            self.run_simulation()
        self.assertEqual(journal.read_text(), "preserve evidence")

    def test_blocked_plan_cannot_be_simulated(self):
        blocked = build_storage_plan(copy.deepcopy(FIXTURE), "/dev/sdb")
        with self.assertRaisesRegex(VirtualExecutionError, "Blocked"):
            simulate_execution(blocked, workspace=self.root,
                virtual_targets={"/dev/sdb": self.image},
                approved_identities={"/dev/sdb": {"serial": "EXAMPLE-USB-0003"}})

if __name__ == "__main__":
    unittest.main()
