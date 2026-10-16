"""Tests for the future guest-only write gate; no block devices are opened."""
from __future__ import annotations

import unittest

from lab.guest_storage_gate import (
    GuestStorageGateError,
    PRIMARY_BYTES,
    SECONDARY_BYTES,
    validate_lab_primary,
)


def node(path, serial, size, *, ro=False, children=None, mountpoints=None,
         holders=None, active_swap=False, ambiguous=False, removable=False):
    return {
        "path": path,
        "type": "disk",
        "serial": serial,
        "size": size,
        "ro": ro,
        "rm": removable,
        "mountpoints": mountpoints if mountpoints is not None else [],
        "holders": holders if holders is not None else [],
        "active_swap": active_swap,
        "ambiguous": ambiguous,
        "children": children if children is not None else [],
    }


def fixture():
    return {"devices": [
        node("/dev/vda", "AEGIS-LAB-PRIMARY", PRIMARY_BYTES),
        node("/dev/vdb", "AEGIS-LAB-SECONDARY", SECONDARY_BYTES, ro=True),
    ]}


class GuestStorageGateTests(unittest.TestCase):
    def test_exact_unused_lab_pair_is_only_eligible_for_separate_consent(self):
        result = validate_lab_primary(fixture())
        self.assertEqual(result["status"], "ELIGIBLE_FOR_SEPARATE_EXPLICIT_LAB_CONSENT")
        self.assertEqual(result["target"]["serial"], "AEGIS-LAB-PRIMARY")
        self.assertFalse(result["write_authorized"])
        self.assertFalse(result["writes_performed"])

    def test_extra_or_missing_root_disk_is_rejected(self):
        value = fixture()
        value["devices"].append(node("/dev/vdc", "HOST-DISK", 500 * 1024**3))
        with self.assertRaisesRegex(GuestStorageGateError, "exactly the two"):
            validate_lab_primary(value)

    def test_root_devices_must_be_exact_whole_disks(self):
        sample = fixture()
        sample["devices"][1]["type"] = "part"
        with self.assertRaisesRegex(GuestStorageGateError, "whole virtual disks"):
            validate_lab_primary(sample)
        sample = fixture()
        sample["devices"][1]["serial"] = "AEGIS-LAB-PRIMARY"
        with self.assertRaisesRegex(GuestStorageGateError, "exactly one AEGIS-LAB-PRIMARY"):
            validate_lab_primary(sample)

    def test_preexisting_partitions_block_lab_write_eligibility(self):
        sample = fixture()
        child = node("/dev/vda1", None, PRIMARY_BYTES - 1024**3)
        child["type"] = "part"
        sample["devices"][0]["children"] = [child]
        with self.assertRaisesRegex(GuestStorageGateError, "must be blank whole disks"):
            validate_lab_primary(sample)

    def test_primary_identity_and_capacity_are_exact(self):
        for key, value in (("serial", "OTHER"), ("size", PRIMARY_BYTES - 1)):
            sample = fixture()
            sample["devices"][0][key] = value
            with self.subTest(key=key), self.assertRaises(GuestStorageGateError):
                validate_lab_primary(sample)

    def test_secondary_must_be_exact_and_read_only(self):
        sample = fixture()
        sample["devices"][1]["ro"] = False
        with self.assertRaisesRegex(GuestStorageGateError, "read-only"):
            validate_lab_primary(sample)

    def test_mounted_descendant_blocks(self):
        sample = fixture()
        part = node("/dev/vda1", None, PRIMARY_BYTES - 1024**3, mountpoints=["/"])
        part["type"] = "part"
        sample["devices"][0]["children"] = [part]
        with self.assertRaisesRegex(GuestStorageGateError, "Mounted"):
            validate_lab_primary(sample)

    def test_holder_or_active_swap_blocks(self):
        for field, value in (("holders", ["dm-0"]), ("active_swap", True)):
            sample = fixture()
            sample["devices"][0][field] = value
            with self.subTest(field=field), self.assertRaises(GuestStorageGateError):
                validate_lab_primary(sample)

    def test_unknown_safety_state_blocks(self):
        sample = fixture()
        sample["devices"][0]["active_swap"] = None
        with self.assertRaisesRegex(GuestStorageGateError, "Unverified active-swap"):
            validate_lab_primary(sample)

    def test_ambiguous_or_removable_primary_blocks(self):
        for field, value in (("ambiguous", True), ("rm", True)):
            sample = fixture()
            sample["devices"][0][field] = value
            with self.subTest(field=field), self.assertRaises(GuestStorageGateError):
                validate_lab_primary(sample)

    def test_duplicate_paths_and_incomplete_topology_block(self):
        sample = fixture()
        sample["devices"][1]["path"] = sample["devices"][0]["path"]
        with self.assertRaisesRegex(GuestStorageGateError, "duplicate"):
            validate_lab_primary(sample)
        sample = fixture()
        sample["devices"][0].pop("children")
        with self.assertRaisesRegex(GuestStorageGateError, "Incomplete child topology"):
            validate_lab_primary(sample)


if __name__ == "__main__":
    unittest.main()
