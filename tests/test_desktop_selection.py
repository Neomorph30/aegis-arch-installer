"""Regression tests for the AEGIS desktop selection contract."""
from __future__ import annotations

import unittest

from aegis.desktop_selection import (
    CORE_SECURITY_CONTROLS,
    DEFAULT_DESKTOP,
    DesktopSelectionError,
    desktop_catalog,
    resolve_desktop_selection,
)


class DesktopSelectionTests(unittest.TestCase):
    def test_kde_is_default_and_review_only(self):
        result = resolve_desktop_selection()
        self.assertEqual(DEFAULT_DESKTOP, "kde-plasma")
        self.assertEqual(result["desktop"], "kde-plasma")
        self.assertTrue(result["default_applied"])
        self.assertFalse(result["execution_enabled"])
        self.assertEqual(result["selection_status"], "REVIEW_ONLY")

    def test_explicit_kde_selection_is_valid(self):
        result = resolve_desktop_selection("kde-plasma")
        self.assertFalse(result["default_applied"])
        self.assertEqual(result["core_security_controls"], list(CORE_SECURITY_CONTROLS))

    def test_future_desktops_are_visible_but_not_selectable(self):
        catalog = {item["id"]: item for item in desktop_catalog()}
        self.assertTrue(catalog["gnome"]["selectable"] is False)
        self.assertTrue(catalog["xfce"]["selectable"] is False)
        with self.assertRaisesRegex(DesktopSelectionError, "not yet qualified"):
            resolve_desktop_selection("gnome")
        with self.assertRaisesRegex(DesktopSelectionError, "not yet qualified"):
            resolve_desktop_selection("xfce")

    def test_unknown_and_non_string_choices_fail_closed(self):
        for value in ("custom-shell", "", None):
            if value is None:
                continue  # None intentionally means the KDE default.
            with self.subTest(value=value), self.assertRaises(DesktopSelectionError):
                resolve_desktop_selection(value)
        with self.assertRaises(DesktopSelectionError):
            resolve_desktop_selection(123)  # type: ignore[arg-type]

    def test_desktop_choice_does_not_change_security_or_optimizer_contract(self):
        result = resolve_desktop_selection("kde-plasma")
        self.assertEqual(result["core_security_controls"], [
            "disk_encryption", "boot_integrity", "least_privilege",
            "firewall", "recovery", "security_reporting",
        ])
        self.assertEqual(result["hardware_optimization"]["selection"], "independent_of_desktop")
        self.assertEqual(result["hardware_optimization"]["status"], "NOT_RUN")
        self.assertTrue(result["hardware_optimization"]["requires_measurement_and_rollback"])

    def test_catalog_returns_detached_data(self):
        catalog = desktop_catalog()
        catalog[0]["notes"].append("mutated")
        self.assertNotIn("mutated", desktop_catalog()[0]["notes"])


if __name__ == "__main__":
    unittest.main()
