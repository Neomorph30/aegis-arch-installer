import unittest

from aegis.planner import PlanError, build_storage_plan, verify_storage_plan_integrity
from aegis.reporting import html_report, public_view


def inventory():
    return {"disks": [
        {"path": "/dev/nvme0n1", "size": 1000 * 10**9, "type": "disk", "serial": "PRIMARY-001",
         "model": "Example NVMe", "tran": "nvme", "rm": False, "ro": False, "hotplug": False, "mountpoints": [None],
         "children": [{"path": "/dev/nvme0n1p1", "fstype": "vfat", "mountpoints": [], "children": []}]},
        {"path": "/dev/sdb", "size": 2000 * 10**9, "type": "disk", "serial": "SECONDARY-002",
         "model": "Example SATA", "tran": "sata", "rm": False, "ro": False, "hotplug": False, "mountpoints": [None],
         "children": [{"path": "/dev/sdb1", "fstype": "crypto_LUKS", "mountpoints": [], "children": []}]},
    ]}


class PlannerTests(unittest.TestCase):
    def test_malformed_option_types_raise_plan_error_not_type_error(self):
        for kwargs in ({"secondary_action": []}, {"filesystem": {}}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(PlanError):
                    build_storage_plan(inventory(), "/dev/nvme0n1", **kwargs)

    def test_secondary_preserved_by_default(self):
        plan = build_storage_plan(inventory(), "/dev/nvme0n1", "/dev/sdb")
        self.assertFalse(plan["execution_enabled"])
        self.assertEqual([x["action"] for x in plan["actions"]], ["erase", "preserve"])
        self.assertFalse(plan["actions"][1]["destructive"])

    def test_secondary_erase_is_proposal_only(self):
        plan = build_storage_plan(inventory(), "/dev/nvme0n1", "/dev/sdb", "erase")
        self.assertTrue(plan["actions"][1]["destructive"])
        self.assertFalse(plan["execution_enabled"])

    def test_same_disk_rejected(self):
        with self.assertRaises(PlanError):
            build_storage_plan(inventory(), "/dev/nvme0n1", "/dev/nvme0n1")

    def test_unknown_disk_rejected(self):
        with self.assertRaises(PlanError):
            build_storage_plan(inventory(), "/dev/sdz")

    def test_undersized_disk_rejected(self):
        data = inventory()
        data["disks"][0]["size"] = 10 * 1024 ** 3
        with self.assertRaises(PlanError):
            build_storage_plan(data, "/dev/nvme0n1")

    def test_unlock_existing_luks(self):
        plan = build_storage_plan(inventory(), "/dev/nvme0n1", "/dev/sdb", "unlock-existing")
        self.assertEqual(plan["actions"][1]["action"], "unlock-existing")
        self.assertFalse(plan["actions"][1]["destructive"])

    def test_unlock_requires_luks(self):
        data = inventory()
        data["disks"][1]["children"][0]["fstype"] = "ext4"
        with self.assertRaises(PlanError):
            build_storage_plan(data, "/dev/nvme0n1", "/dev/sdb", "unlock-existing")

    def test_report_escapes_html_and_redacts_secrets(self):
        plan = build_storage_plan(inventory(), "/dev/nvme0n1")
        secret = "AEGIS-TEST-SECRET-TPM-PIN-91A7"
        plan["tpm_pin"] = secret
        plan["warnings"].append("bad <script>alert('x')</script>")
        output = html_report(plan)
        self.assertNotIn(secret, output)
        self.assertIn("&quot;tpm_pin&quot;: &quot;[REDACTED]&quot;", output)
        self.assertNotIn("<script>", output)
        self.assertIn("&lt;script&gt;", output)
        self.assertEqual(public_view({"password": "pw"})["password"], "[REDACTED]")


    def test_missing_readonly_state_blocks_destructive_proposal(self):
        data = inventory()
        data["disks"][0].pop("ro")
        plan = build_storage_plan(data, "/dev/nvme0n1")
        self.assertEqual(plan["review_state"], "BLOCKED")
        self.assertTrue(any("read/write state could not be verified" in item for item in plan["blockers"]))

    def test_missing_removable_state_blocks_destructive_proposal(self):
        data = inventory()
        data["disks"][0].pop("rm")
        plan = build_storage_plan(data, "/dev/nvme0n1")
        self.assertEqual(plan["review_state"], "BLOCKED")
        self.assertTrue(any("removable state could not be verified" in item for item in plan["blockers"]))

    def test_missing_hotplug_state_blocks_destructive_proposal(self):
        data = inventory()
        data["disks"][0].pop("hotplug")
        plan = build_storage_plan(data, "/dev/nvme0n1")
        self.assertEqual(plan["review_state"], "BLOCKED")
        self.assertTrue(any("hotplug state could not be verified" in item for item in plan["blockers"]))

    def test_plan_digest_detects_tampering(self):
        plan = build_storage_plan(inventory(), "/dev/nvme0n1")
        self.assertTrue(verify_storage_plan_integrity(plan))
        plan["actions"][0]["target"] = "/dev/sdb"
        self.assertFalse(verify_storage_plan_integrity(plan))

    def test_duplicate_identity_anywhere_blocks_plan(self):
        data = inventory()
        data["disks"].append({
            "path": "/dev/sdc", "size": 500 * 10**9, "type": "disk",
            "serial": "PRIMARY-001", "rm": False, "ro": False,
        })
        with self.assertRaises(PlanError):
            build_storage_plan(data, "/dev/nvme0n1")

    def test_malformed_device_paths_block_plan(self):
        for path in ("/dev/nvme0n1\n", "/dev//sda", "/dev/../sda", "/dev/sda;echo"):
            with self.subTest(path=path):
                data = inventory()
                data["disks"][0]["path"] = path
                with self.assertRaises(PlanError):
                    build_storage_plan(data, path)

    def test_control_characters_in_stable_identifiers_block_plan(self):
        data = inventory()
        data["disks"][0]["serial"] = "PRIMARY-001\nforged"
        with self.assertRaises(PlanError):
            build_storage_plan(data, "/dev/nvme0n1")

    def test_missing_mountpoint_observations_fail_closed(self):
        data = inventory()
        data["disks"][0].pop("mountpoints")
        with self.assertRaises(PlanError):
            build_storage_plan(data, "/dev/nvme0n1")

        data = inventory()
        data["disks"][0]["children"][0].pop("mountpoints")
        with self.assertRaises(PlanError):
            build_storage_plan(data, "/dev/nvme0n1")

    def test_missing_disk_or_nested_child_topology_fails_closed(self):
        cases = [
            ("disk", None),
            ("child", None),
            ("grandchild", None),
        ]
        for target, _ in cases:
            with self.subTest(target=target):
                data = inventory()
                if target == "disk":
                    data["disks"][0].pop("children")
                elif target == "child":
                    data["disks"][0]["children"][0].pop("children")
                else:
                    data["disks"][0]["children"][0]["children"] = [{"path": "/dev/nvme0n1p2", "mountpoints": []}]
                with self.assertRaises(PlanError):
                    build_storage_plan(data, "/dev/nvme0n1")

    def test_malformed_partition_observations_fail_closed(self):
        cases = [
            {"mountpoints": {"root": "/"}},
            {"mountpoints": ["   "]},
            {"mountpoints": [42]},
            {"children": {"unexpected": "mapping"}},
        ]
        for change in cases:
            with self.subTest(change=change):
                data = inventory()
                data["disks"][0]["children"][0].update(change)
                with self.assertRaises(PlanError):
                    build_storage_plan(data, "/dev/nvme0n1")

    def test_malformed_disk_entry_blocks_plan(self):
        data = inventory()
        data["disks"].append("not-a-disk-object")
        with self.assertRaises(PlanError):
            build_storage_plan(data, "/dev/nvme0n1")

    def test_plan_has_inventory_fingerprint_and_digest(self):
        plan = build_storage_plan(inventory(), "/dev/nvme0n1")
        self.assertEqual(len(plan["inventory_fingerprint"]), 64)
        self.assertEqual(len(plan["plan_digest"]), 64)
        self.assertEqual(plan["schema_version"], "0.3")
        self.assertFalse(plan["execution_enabled"])

    def test_no_executor_available(self):
        # Safety invariant: the preview package exposes no disk-mutation subsystem.
        import aegis
        self.assertFalse(hasattr(aegis, "execute_install"))


if __name__ == "__main__":
    unittest.main()
