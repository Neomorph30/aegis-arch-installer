"""Layer 07 preflight specification tests; no VM or disk operations are run."""
from __future__ import annotations

import copy
import unittest

from lab.install_spec import (
    InstallSpecError,
    build_guest_install_spec,
    verify_guest_install_spec,
    EFI_BYTES,
    MIN_PRIMARY_BYTES,
)


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


class GuestInstallSpecTests(unittest.TestCase):
    def test_builds_review_only_spec(self):
        spec = build_guest_install_spec(observation())
        self.assertEqual(spec["status"], "PREFLIGHT_ONLY")
        self.assertFalse(spec["execution_enabled"])
        self.assertEqual(spec["target"]["path"], "/dev/vda")
        self.assertEqual(spec["target"]["secondary_policy"], "PRESERVE")
        self.assertEqual(spec["layout"][0]["size_bytes"], EFI_BYTES)
        self.assertEqual(spec["layout"][1]["encryption"], "LUKS2")
        self.assertTrue(verify_guest_install_spec(spec))

    def test_digest_detects_tampering(self):
        spec = build_guest_install_spec(observation())
        spec["target"]["path"] = "/dev/vdb"
        self.assertFalse(verify_guest_install_spec(spec))

    def test_duplicate_kernel_device_identity_is_rejected(self):
        obs = observation()
        obs["devices"][1]["major_minor"] = obs["devices"][0]["major_minor"]
        with self.assertRaisesRegex(InstallSpecError, "Duplicate kernel major/minor identity"):
            build_guest_install_spec(obs)

    def test_missing_kernel_device_identity_is_rejected(self):
        obs = observation()
        obs["devices"][0].pop("major_minor")
        with self.assertRaisesRegex(InstallSpecError, "Kernel major/minor identity"):
            build_guest_install_spec(obs)

    def test_non_qemu_environment_rejected(self):
        obs = observation()
        obs["environment"]["sys_vendor"] = "Generic Host"
        with self.assertRaisesRegex(InstallSpecError, "QEMU Q35"):
            build_guest_install_spec(obs)

    def test_unlabelled_or_wrong_serial_rejected(self):
        obs = observation()
        obs["devices"][0]["serial"] = "HOST-DISK"
        with self.assertRaisesRegex(InstallSpecError, "serial mismatch"):
            build_guest_install_spec(obs)

    def test_unexpected_root_block_device_type_is_rejected(self):
        obs = observation()
        obs["devices"].append({"path": "/dev/mapper/host-root", "type": "mpath",
                               "read_only": True})
        with self.assertRaisesRegex(InstallSpecError, "Unexpected block-device root type"):
            build_guest_install_spec(obs)

    def test_extra_disk_rejected(self):
        obs = observation()
        extra = copy.deepcopy(obs["devices"][0])
        extra.update(path="/dev/vdc", major_minor="252:32", serial="UNEXPECTED")
        obs["devices"].append(extra)
        with self.assertRaisesRegex(InstallSpecError, "exactly two lab disks"):
            build_guest_install_spec(obs)

    def test_mounted_child_rejected(self):
        obs = observation()
        obs["devices"][0]["children"] = [
            {"path": "/dev/vda1", "major_minor": "252:1", "type": "part", "mountpoints": ["/mnt/host-data"], "children": []}
        ]
        with self.assertRaisesRegex(InstallSpecError, "partition"):
            build_guest_install_spec(obs)

    def test_active_swap_rejected(self):
        obs = observation()
        obs["active_swaps"] = ["/dev/vda2"]
        with self.assertRaisesRegex(InstallSpecError, "swap"):
            build_guest_install_spec(obs)

    def test_missing_readonly_boot_medium_rejected(self):
        obs = observation()
        obs["devices"] = obs["devices"][:-1]
        with self.assertRaisesRegex(InstallSpecError, "boot medium"):
            build_guest_install_spec(obs)

    def test_secondary_must_be_readonly_in_layer07(self):
        obs = observation()
        obs["devices"][1]["read_only"] = False
        with self.assertRaisesRegex(InstallSpecError, "Secondary lab disk"):
            build_guest_install_spec(obs)

    def test_small_primary_rejected(self):
        obs = observation()
        obs["devices"][0]["size_bytes"] = MIN_PRIMARY_BYTES - 1
        with self.assertRaisesRegex(InstallSpecError, "at least 24 GiB"):
            build_guest_install_spec(obs)

    def test_malformed_top_level_device_fails_closed(self):
        obs = observation()
        obs["devices"].append(None)
        with self.assertRaisesRegex(InstallSpecError, "malformed observation"):
            build_guest_install_spec(obs)

    def test_missing_primary_readonly_state_fails_closed(self):
        obs = observation()
        obs["devices"][0].pop("read_only")
        with self.assertRaisesRegex(InstallSpecError, "read/write state"):
            build_guest_install_spec(obs)

    def test_missing_mountpoints_fails_closed(self):
        obs = observation()
        obs["devices"][0].pop("mountpoints")
        with self.assertRaisesRegex(InstallSpecError, "Mountpoint observations are missing"):
            build_guest_install_spec(obs)

    def test_malformed_holder_state_fails_closed(self):
        obs = observation()
        obs["devices"][0]["holders"] = None
        with self.assertRaisesRegex(InstallSpecError, "holder state"):
            build_guest_install_spec(obs)

    def test_malformed_active_swap_list_fails_closed(self):
        obs = observation()
        obs["active_swaps"] = [None]
        with self.assertRaisesRegex(InstallSpecError, "Active swap observations are malformed"):
            build_guest_install_spec(obs)

    def test_missing_secondary_capacity_fails_closed(self):
        obs = observation()
        obs["devices"][1].pop("size_bytes")
        with self.assertRaisesRegex(InstallSpecError, "Secondary lab disk capacity"):
            build_guest_install_spec(obs)

    def test_network_mode_must_be_explicit(self):
        obs = observation()
        obs.pop("network_mode")
        with self.assertRaisesRegex(InstallSpecError, "Network mode"):
            build_guest_install_spec(obs)


if __name__ == "__main__":
    unittest.main()
