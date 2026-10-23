"""Boundary tests for iterative device-tree validation."""
from __future__ import annotations

import unittest

from lab.device_tree import DeviceTreeValidationError, validate_device_forest


def chain(depth: int) -> dict:
    """Build a tree whose deepest node has the requested depth."""
    root = {"children": []}
    node = root
    for _ in range(depth):
        child = {"children": []}
        node["children"].append(child)
        node = child
    return root


class DeviceTreeTests(unittest.TestCase):
    def test_depth_16_is_accepted(self):
        validate_device_forest([chain(16)], require_children=True)

    def test_depth_17_is_rejected(self):
        with self.assertRaisesRegex(DeviceTreeValidationError, "maximum depth"):
            validate_device_forest([chain(17)], require_children=True)

    def test_4096_nodes_across_multiple_roots_are_accepted(self):
        roots = [
            {"children": [{"children": []} for _ in range(2047)]},
            {"children": [{"children": []} for _ in range(2047)]},
        ]
        validate_device_forest(roots, require_children=True)

    def test_4097_nodes_are_rejected(self):
        roots = [
            {"children": [{"children": []} for _ in range(2047)]},
            {"children": [{"children": []} for _ in range(2048)]},
        ]
        with self.assertRaisesRegex(DeviceTreeValidationError, "maximum node count"):
            validate_device_forest(roots, require_children=True)

    def test_missing_children_is_rejected_when_required(self):
        with self.assertRaisesRegex(
            DeviceTreeValidationError, "children are missing or malformed"
        ):
            validate_device_forest([{}], require_children=True)

    def test_missing_children_is_allowed_for_probe_schema(self):
        validate_device_forest([{}], require_children=False)

    def test_non_list_children_are_rejected(self):
        with self.assertRaisesRegex(DeviceTreeValidationError, "children are malformed"):
            validate_device_forest([{"children": {}}], require_children=False)

    def test_non_dictionary_child_is_rejected(self):
        with self.assertRaisesRegex(DeviceTreeValidationError, "malformed child"):
            validate_device_forest(
                [{"children": [None]}], require_children=True
            )


if __name__ == "__main__":
    unittest.main()
