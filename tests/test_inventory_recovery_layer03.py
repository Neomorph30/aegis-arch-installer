import unittest
from aegis.inventory import assess_inventory
from aegis.recovery import classify_failure

class InventoryTests(unittest.TestCase):
    def test_invalid_root_fails_closed(self):
        self.assertEqual(assess_inventory({})["status"], "blocked")
    def test_mounted_device_not_safe(self):
        r=assess_inventory({"devices":[{"path":"/dev/sda","type":"disk","mountpoints":["/"]}]})
        self.assertEqual(r["status"], "blocked")
        self.assertEqual(r["devices"][0]["state"], "blocked")
        self.assertFalse(r["write_authorized"])
    def test_duplicate_path_blocked(self):
        r=assess_inventory({"devices":[{"path":"/dev/sda","type":"disk"},{"path":"/dev/sda","type":"disk"}]})
        self.assertEqual(r["status"], "blocked")
    def test_duplicate_stable_identity_blocked(self):
        r=assess_inventory({"devices":[{"path":"/dev/sda","serial":"same"},{"path":"/dev/sdb","serial":"same"}]})
        self.assertEqual(r["status"], "blocked")
    def test_nested_mapper_flagged(self):
        r=assess_inventory({"devices":[{"path":"/dev/mapper/root","type":"crypt"}]})
        self.assertEqual(r["devices"][0]["state"], "blocked")
    def test_malformed_child_tree(self):
        r=assess_inventory({"devices":[{"path":"/dev/sda","children":"not-list"}]})
        self.assertEqual(r["status"], "blocked")
    def test_tree_depth_limit(self):
        n={"path":"/dev/sda","type":"disk"}
        cur=n
        for i in range(20):
            child={"path":f"/dev/loop{i}","type":"loop"}
            cur["children"]=[child]; cur=child
        self.assertEqual(assess_inventory({"devices":[n]})["status"], "blocked")

class RecoveryTests(unittest.TestCase):
    def test_read_only_timeout_retries_once(self):
        self.assertEqual(classify_failure("inventory","timeout",1).action,"retry_once")
    def test_second_failure_stops(self):
        self.assertEqual(classify_failure("inventory","timeout",2).action,"stop_and_report")
    def test_format_never_retried(self):
        self.assertEqual(classify_failure("format","timeout").action,"stop_and_inspect")
    def test_identity_mismatch_stops(self):
        self.assertEqual(classify_failure("inventory","identity-mismatch").action,"stop_and_report")
    def test_unknown_error_stops(self):
        self.assertEqual(classify_failure("read-only-probe","unknown").action,"stop_and_report")

if __name__ == "__main__":
    unittest.main()
