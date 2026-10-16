"""Tests for the future guest-only write gate; no block devices are opened."""
from __future__ import annotations

import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch
from types import SimpleNamespace

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

    def test_lsblk_null_mountpoint_means_unmounted(self):
        sample = fixture()
        sample["devices"][0]["mountpoints"] = [None]
        result = validate_lab_primary(sample)
        self.assertFalse(result["write_authorized"])

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

    @patch("pathlib.Path.iterdir", return_value=[])
    @patch("pathlib.Path.read_text", return_value="Filename Type Size Used Priority\\n")
    @patch("subprocess.run")
    def test_live_observer_normalizes_lsblk_and_reads_sysfs(self, run, read_text, iterdir):
        import json
        from lab.guest_storage_gate import observe_guest_storage
        payload = {"blockdevices": [
            {"path": "/dev/sr0", "type": "rom", "serial": "ARCH-ISO",
             "size": 700 * 1024**2, "ro": True, "rm": True,
             "mountpoints": [None], "maj:min": "11:0", "children": []},
            {"path": "/dev/loop0", "type": "loop", "serial": None,
             "size": 700 * 1024**2, "ro": True, "rm": False,
             "mountpoints": [None], "maj:min": "7:0", "children": []},
            {"path": "/dev/vda", "type": "disk", "serial": "AEGIS-LAB-PRIMARY",
             "size": PRIMARY_BYTES, "ro": False, "rm": False,
             "mountpoints": [None], "maj:min": "252:0", "children": []},
            {"path": "/dev/vdb", "type": "disk", "serial": "AEGIS-LAB-SECONDARY",
             "size": SECONDARY_BYTES, "ro": True, "rm": False,
             "mountpoints": [None], "maj:min": "252:1", "children": []},
        ]}
        run.return_value = SimpleNamespace(stdout=json.dumps(payload))
        observed = observe_guest_storage()
        self.assertEqual(len(observed["devices"]), 2)
        self.assertEqual(observed["devices"][0]["path"], "/dev/vda")
        self.assertEqual(observed["devices"][0]["mountpoints"], [])
        self.assertEqual(observed["devices"][0]["holders"], [])
        self.assertFalse(observed["devices"][0]["active_swap"])
        self.assertEqual(validate_lab_primary(observed)["target"]["serial"], "AEGIS-LAB-PRIMARY")
        run.assert_called_once()
        iterdir.assert_called()

    @patch("lab.guest_storage_gate.observe_guest_storage", return_value=fixture())
    def test_preflight_cli_reports_eligibility_without_authorizing_writes(self, probe):
        from lab.guest_storage_gate import main
        output = StringIO()
        with redirect_stdout(output):
            status = main(["--preflight"])
        self.assertEqual(status, 0)
        result = __import__("json").loads(output.getvalue())
        self.assertFalse(result["write_authorized"])
        self.assertFalse(result["writes_performed"])
        probe.assert_called_once_with()

    @patch("lab.guest_storage_gate.observe_guest_storage",
           side_effect=GuestStorageGateError("synthetic unsafe topology"))
    def test_preflight_cli_fails_closed_and_reports_blocked(self, probe):
        from lab.guest_storage_gate import main
        output = StringIO()
        with redirect_stdout(output):
            status = main(["--preflight"])
        self.assertEqual(status, 2)
        result = __import__("json").loads(output.getvalue())
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["write_authorized"])
        self.assertFalse(result["writes_performed"])

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
