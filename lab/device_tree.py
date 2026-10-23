"""Iterative structural validation for device trees."""
from __future__ import annotations

from typing import Any


MAX_DEVICE_TREE_DEPTH = 16
MAX_DEVICE_TREE_NODES = 4096


class DeviceTreeValidationError(ValueError):
    """A device tree is malformed or exceeds safe traversal limits."""


def validate_device_forest(
    roots: list[Any],
    *,
    require_children: bool,
) -> None:
    """Validate a forest iteratively; root depth is zero.

    Iterator frames avoid copying every sibling into a second stack before the
    node-count limit can be enforced.
    """
    stack = [(iter(roots), 0)]
    visited = 0

    while stack:
        siblings, depth = stack[-1]
        try:
            node = next(siblings)
        except StopIteration:
            stack.pop()
            continue

        if depth > MAX_DEVICE_TREE_DEPTH:
            raise DeviceTreeValidationError(
                "Device tree exceeds maximum depth (16)"
            )

        if not isinstance(node, dict):
            raise DeviceTreeValidationError(
                "Device tree contains a malformed child"
            )

        visited += 1
        if visited > MAX_DEVICE_TREE_NODES:
            raise DeviceTreeValidationError(
                "Device tree exceeds maximum node count (4096)"
            )

        if require_children and "children" not in node:
            raise DeviceTreeValidationError(
                "Device tree children are missing or malformed"
            )

        children = node.get("children", [])
        if not isinstance(children, list):
            message = (
                "Device tree children are missing or malformed"
                if require_children
                else "Device children are malformed"
            )
            raise DeviceTreeValidationError(message)

        if children:
            stack.append((iter(children), depth + 1))
