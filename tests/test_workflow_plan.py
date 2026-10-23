"""Tests for the non-executing, fresh-target workflow review plan."""
from __future__ import annotations

import copy
import unittest

from lab.guest_preflight import run_preflight
from lab.workflow_plan import WorkflowPlanError, build_review_plan


def observation():
    return {
        "environment": {"sys_vendor": "QEMU", "product_name": "Standard PC Q35"},
        "network_mode": "disabled",
        "active_swaps": [],
        "devices": [
            {"path": "/dev/vda", "major_minor": "252:0", "type": "disk", "serial": "AEGIS-LAB-PRIMARY",
             "size_bytes": 24 * 1024**3, "read_only": False, "mountpoints": [],
             "holders": [], "active_swap": False, "children": []},
            {"path": "/dev/vdb", "major_minor": "252:16", "type": "disk", "serial": "AEGIS-LAB-SECONDARY",
             "size_bytes": 8 * 1024**3, "read_only": True, "mountpoints": [],
             "holders": [], "active_swap": False, "children": []},
            {"path": "/dev/sr0", "major_minor": "11:0", "type": "rom", "read_only": True, "children": []},
        ],
    }


class WorkflowPlanTests(unittest.TestCase):
    def setUp(self):
        code, self.spec = run_preflight(lambda: observation())
        self.assertEqual(code, 0)

    def test_current_observation_yields_review_only_plan(self):
        plan = build_review_plan(self.spec, observation())
        self.assertEqual(plan["status"], "TARGET_RECONFIRMED_REVIEW_PLAN")
        self.assertFalse(plan["execution_enabled"])
        self.assertFalse(plan["disk_changes_performed"])
        self.assertEqual(plan["target"]["serial"], "AEGIS-LAB-PRIMARY")
        self.assertEqual(plan["secondary_policy"], "PRESERVE")
        self.assertEqual(len(plan["phases"]), len(self.spec["phases"]))
        self.assertIn("journal_intent", plan["phases"][2]["required_gates"])

    def test_tampered_original_spec_is_rejected(self):
        spec = copy.deepcopy(self.spec)
        spec["target"]["serial"] = "OTHER-DISK"
        with self.assertRaisesRegex(WorkflowPlanError, "digest"):
            build_review_plan(spec, observation())

    def test_changed_target_serial_blocks_plan(self):
        changed = observation()
        changed["devices"][0]["serial"] = "UNEXPECTED-DISK"
        with self.assertRaisesRegex(WorkflowPlanError, "Fresh target observation"):
            build_review_plan(self.spec, changed)

    def test_changed_target_capacity_blocks_plan(self):
        changed = observation()
        changed["devices"][0]["size_bytes"] += 1024**3
        with self.assertRaisesRegex(WorkflowPlanError, "changed since preflight"):
            build_review_plan(self.spec, changed)

    def test_changed_network_mode_blocks_plan(self):
        changed = observation()
        changed["network_mode"] = "user-nat-explicit"
        with self.assertRaisesRegex(WorkflowPlanError, "changed since preflight"):
            build_review_plan(self.spec, changed)

    def test_mounted_target_blocks_plan(self):
        changed = observation()
        changed["devices"][0]["mountpoints"] = ["/mnt/target"]
        with self.assertRaisesRegex(WorkflowPlanError, "Fresh target observation"):
            build_review_plan(self.spec, changed)

    def test_unknown_or_reordered_phases_block_plan(self):
        spec = copy.deepcopy(self.spec)
        spec["phases"][2], spec["phases"][3] = spec["phases"][3], spec["phases"][2]
        from lab.install_spec import _digest
        spec["spec_digest"] = _digest({key: value for key, value in spec.items() if key != "spec_digest"})
        with self.assertRaisesRegex(WorkflowPlanError, "out of order"):
            build_review_plan(spec, observation())

    def test_plan_is_data_only_and_does_not_call_subprocess(self):
        # The planner accepts an already captured observation and has no executor hook.
        plan = build_review_plan(self.spec, observation())
        self.assertTrue(all(phase["execution_enabled"] is False for phase in plan["phases"]))
        self.assertIn("no commands", " ".join(plan["limitations"]).lower())


if __name__ == "__main__":
    unittest.main()
