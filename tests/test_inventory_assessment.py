"""Adversarial regression tests for the read-only inventory assessor."""
from __future__ import annotations

import unittest

from aegis.inventory import assess_inventory


def disk(**overrides):
    value = {"path": "/dev/nvme0n1", "type": "disk", "serial": "SERIAL-A",
             "wwn": "WWN-A", "mountpoints": [None], "holders": [],
             "active_swap": False, "ambiguous": False, "children": []}
    value.update(overrides)
    return value


def assess(*devices):
    return assess_inventory({"devices": list(devices)})


class InventoryAssessmentTests(unittest.TestCase):
    def test_valid_device_is_review_only_never_authorized(self):
        result = assess(disk())
        self.assertEqual(result["status"], "review_required")
        self.assertFalse(result["write_authorized"])
        self.assertEqual(result["devices"][0]["state"], "review")

    def test_invalid_root_schema_fails_closed(self):
        for value in (None, [], {}, {"devices": None}, {"devices": []}):
            with self.subTest(value=value):
                result = assess_inventory(value)
                self.assertEqual(result["status"], "blocked")
                self.assertFalse(result["write_authorized"])

    def test_missing_or_malformed_path_blocks(self):
        for path in (None, "", "sda", "/dev/../etc/passwd", "/dev/sda\n", "/dev/sda;rm"):
            with self.subTest(path=path):
                result = assess(disk(path=path))
                self.assertEqual(result["status"], "blocked")
                self.assertFalse(result["write_authorized"])

    def test_duplicate_paths_block_both_assessment(self):
        result = assess(disk(), disk(serial="SERIAL-B", wwn="WWN-B"))
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(any(f["code"] == "AMBIGUOUS_PATH" for f in result["findings"]))

    def test_duplicate_serial_or_wwn_across_devices_blocks(self):
        cases = [
            (disk(), disk(path="/dev/sda", serial="SERIAL-A", wwn="WWN-B")),
            (disk(), disk(path="/dev/sda", serial="SERIAL-B", wwn="WWN-A")),
        ]
        for pair in cases:
            with self.subTest(pair=pair):
                result = assess(*pair)
                self.assertEqual(result["status"], "blocked")
                self.assertTrue(any(f["code"] == "DUPLICATE_IDENTITY" for f in result["findings"]))

    def test_same_serial_and_wwn_text_on_one_device_is_not_self_collision(self):
        result = assess(disk(serial="SAME", wwn="SAME"))
        self.assertEqual(result["status"], "review_required")

    def test_malformed_identifier_blocks(self):
        for key, value in (("serial", 42), ("wwn", []), ("serial", "SERIAL\nA")):
            with self.subTest(key=key, value=value):
                result = assess(disk(**{key: value}))
                self.assertEqual(result["status"], "blocked")

    def test_mount_swap_holder_and_ambiguous_states_are_never_clear(self):
        cases = [
            (disk(mountpoints=["/"]), "mounted"),
            (disk(active_swap=True), "active_swap"),
            (disk(holders=["dm-0"]), "has_holders"),
            (disk(ambiguous=True), "ambiguous_identity"),
            (disk(type="crypt"), "has_holders"),
        ]
        for value, reason in cases:
            with self.subTest(reason=reason):
                result = assess(value)
                self.assertEqual(result["status"], "blocked")
                self.assertIn(reason, result["devices"][0]["reasons"])

    def test_unknown_mount_holder_and_state_shapes_block(self):
        cases = [
            disk(mountpoints={"root": "/"}),
            disk(holders=[42]),
            disk(active_swap="false"),
            disk(ambiguous="no"),
            disk(children="not-a-list"),
            disk(type=None),
        ]
        for value in cases:
            with self.subTest(value=value):
                result = assess(value)
                self.assertEqual(result["status"], "blocked")
                self.assertFalse(result["write_authorized"])

    def test_malformed_nested_node_and_tree_depth_fail_closed(self):
        result = assess(disk(children=["not-a-device"]))
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(any(f["code"] == "MALFORMED_NODE" for f in result["findings"]))

        root = disk()
        current = root
        for index in range(18):
            child = disk(path=f"/dev/fake{index}", serial=f"S{index}", wwn=f"W{index}")
            current["children"] = [child]
            current = child
        result = assess(root)
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(any(f["code"] == "TREE_LIMIT" for f in result["findings"]))

    def test_malformed_child_collection_blocks_whole_result(self):
        result = assess(disk(children={"unexpected": "mapping"}))
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(any(f["code"] == "MALFORMED_CHILDREN" for f in result["findings"]))

    def test_valid_null_mountpoints_and_empty_holders_are_not_false_positives(self):
        result = assess(disk(mountpoints=[None, ""], holders=[]))
        self.assertEqual(result["status"], "review_required")
        self.assertEqual(result["devices"][0]["reasons"], [])

    def test_no_result_ever_authorizes_writes(self):
        fixtures = [
            assess(disk()),
            assess(disk(mountpoints=["/"])),
            assess(disk(path="/dev/../sda")),
            assess("malformed"),
        ]
        for result in fixtures:
            with self.subTest(result=result):
                self.assertIs(result["write_authorized"], False)


if __name__ == "__main__":
    unittest.main()
