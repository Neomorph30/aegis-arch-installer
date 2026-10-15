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
            {"path": "/dev/vda", "type": "disk", "serial": "AEGIS-LAB-PRIMARY",
             "size_bytes": 24 * 1024**3, "read_only": False, "mountpoints": [],
             "holders": [], "active_swap": False, "children": []},
            {"path": "/dev/vdb", "type": "disk", "serial": "AEGIS-LAB-SECONDARY",
             "size_bytes": 8 * 1024**3, "read_only": True, "mountpoints": [],
             "holders": [], "active_swap": False, "children": []},
            {"path": "/dev/sr0", "type": "rom", "read_only": True},
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

    def test_extra_disk_rejected(self):
        obs = observation()
        extra = copy.deepcopy(obs["devices"][0])
        extra.update(path="/dev/vdc", serial="UNEXPECTED")
        obs["devices"].append(extra)
        with self.assertRaisesRegex(InstallSpecError, "exactly two lab disks"):
            build_guest_install_spec(obs)

    def test_mounted_child_rejected(self):
        obs = observation()
        obs["devices"][0]["children"] = [
            {"path": "/dev/vda1", "type": "part", "mountpoints": ["/mnt/host-data"]}
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
        with self.assertRaisesRegex(InstallSpecError, "secondary lab disk"):
            build_guest_install_spec(obs)

    def test_small_primary_rejected(self):
        obs = observation()
        obs["devices"][0]["size_bytes"] = MIN_PRIMARY_BYTES - 1
        with self.assertRaisesRegex(InstallSpecError, "at least 24 GiB"):
            build_guest_install_spec(obs)

    def test_network_mode_must_be_explicit(self):
        obs = observation()
        obs.pop("network_mode")
        with self.assertRaisesRegex(InstallSpecError, "Network mode"):
            build_guest_install_spec(obs)


if __name__ == "__main__":
    unittest.main()
