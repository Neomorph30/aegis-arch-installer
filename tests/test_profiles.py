"""Tests for KDE-first advisory system profiles."""
from __future__ import annotations

import unittest

from aegis.profiles import recommend


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.inventory = {
            "architecture": "x86_64",
            "cpu": "Example AMD CPU",
            "gpu_devices": ["Advanced Micro Devices, Inc. [AMD/ATI] [1002:abcd]"],
            "tpm_version": "unknown",
        }

    def test_kde_is_default_desktop_candidate(self):
        result = recommend(self.inventory)
        self.assertEqual(result["desktop"]["id"], "kde-plasma")
        self.assertEqual(result["desktop"]["status"], "RECOMMENDATIONS_ONLY")
        self.assertIn("plasma-meta", result["package_candidates"])
        self.assertIn("sddm", result["package_candidates"])
        self.assertIn("dolphin", result["package_candidates"])
        self.assertIn("xdg-desktop-portal-kde", result["package_candidates"])
        self.assertEqual(result["status"], "RECOMMENDATIONS_ONLY")

    def test_security_and_workload_candidates_remain_present(self):
        result = recommend(self.inventory, profile="secure-gaming")
        packages = set(result["package_candidates"])
        for package in ("cryptsetup", "btrfs-progs", "networkmanager", "firewalld",
                        "apparmor", "linux", "linux-lts", "steam", "gamemode"):
            self.assertIn(package, packages)
        self.assertEqual(result["optimization"]["status"], "NOT_RUN")

    def test_unknown_desktop_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Unknown desktop"):
            recommend(self.inventory, desktop="custom-desktop")

    def test_unqualified_desktop_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "not yet qualified"):
            recommend(self.inventory, desktop="gnome")

    def test_workstation_profile_omits_gaming_specific_candidates(self):
        result = recommend(self.inventory, profile="secure-workstation")
        packages = set(result["package_candidates"])
        self.assertIn("plasma-meta", packages)
        self.assertNotIn("steam", packages)
        self.assertNotIn("gamemode", packages)


if __name__ == "__main__":
    unittest.main()
