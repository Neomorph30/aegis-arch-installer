import unittest

from aegis.planner import PlanError, build_storage_plan
from aegis.reporting import html_report, public_view


def inventory():
    return {"disks": [
        {"path": "/dev/nvme0n1", "size": 1000 * 10**9, "type": "disk", "serial": "PRIMARY-001",
         "model": "Example NVMe", "tran": "nvme", "rm": False, "ro": False,
         "children": [{"path": "/dev/nvme0n1p1", "fstype": "vfat", "mountpoints": []}]},
        {"path": "/dev/sdb", "size": 2000 * 10**9, "type": "disk", "serial": "SECONDARY-002",
         "model": "Example SATA", "tran": "sata", "rm": False, "ro": False,
         "children": [{"path": "/dev/sdb1", "fstype": "crypto_LUKS", "mountpoints": []}]},
    ]}


class PlannerTests(unittest.TestCase):
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
        plan["tpm_pin"] = "12345"
        plan["warnings"].append("bad <script>alert('x')</script>")
        output = html_report(plan)
        self.assertNotIn("12345", output)
        self.assertNotIn("<script>", output)
        self.assertIn("&lt;script&gt;", output)
        self.assertEqual(public_view({"password": "pw"})["password"], "[REDACTED]")

    def test_no_executor_available(self):
        # Safety invariant: the preview package exposes no disk-mutation subsystem.
        import aegis
        self.assertFalse(hasattr(aegis, "execute_install"))


if __name__ == "__main__":
    unittest.main()
