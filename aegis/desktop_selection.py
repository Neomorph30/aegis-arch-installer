"""Desktop selection contract: KDE is the only initial supported default.

This is configuration metadata only. It does not install packages, alter security
controls, or tune hardware. Future desktops stay visible but unavailable until
their integration and recovery tests qualify them.
"""
from __future__ import annotations

from typing import Any

SCHEMA_VERSION = 1
DEFAULT_DESKTOP = "kde-plasma"

_DESKTOPS: tuple[dict[str, Any], ...] = (
    {
        "id": "kde-plasma",
        "name": "KDE Plasma",
        "status": "SUPPORTED_DEFAULT",
        "selectable": True,
        "default": True,
        "session_types": ["wayland", "x11"],
        "notes": ["Initial target; must pass installation, login, update and recovery tests before release."],
    },
    {
        "id": "gnome",
        "name": "GNOME",
        "status": "PLANNED_NOT_QUALIFIED",
        "selectable": False,
        "default": False,
        "session_types": ["wayland", "x11"],
        "notes": ["Enable only after display-manager, accessibility, security and recovery qualification."],
    },
    {
        "id": "xfce",
        "name": "Xfce",
        "status": "PLANNED_NOT_QUALIFIED",
        "selectable": False,
        "default": False,
        "session_types": ["x11"],
        "notes": ["Enable only after package, login, security and recovery qualification."],
    },
    {
        "id": "other",
        "name": "Other / custom desktop",
        "status": "UNSUPPORTED",
        "selectable": False,
        "default": False,
        "session_types": [],
        "notes": ["Custom desktop stacks are not accepted by the initial installer contract."],
    },
)

# These controls belong to the base system and must not depend on desktop choice.
CORE_SECURITY_CONTROLS = (
    "disk_encryption",
    "boot_integrity",
    "least_privilege",
    "firewall",
    "recovery",
    "security_reporting",
)


class DesktopSelectionError(ValueError):
    """Desktop choice is unknown or not qualified for this release."""


def desktop_catalog() -> list[dict[str, Any]]:
    """Return detached catalog data for a UI; no desktop is installed here."""
    return [{**entry, "session_types": list(entry["session_types"]),
             "notes": list(entry["notes"])} for entry in _DESKTOPS]


def resolve_desktop_selection(desktop_id: str | None = None) -> dict[str, Any]:
    """Resolve a validated desktop choice into a non-executing configuration record."""
    selected_id = DEFAULT_DESKTOP if desktop_id is None else desktop_id
    if not isinstance(selected_id, str):
        raise DesktopSelectionError("Desktop selection must be a listed identifier")
    entry = next((item for item in _DESKTOPS if item["id"] == selected_id), None)
    if entry is None:
        raise DesktopSelectionError("Unknown desktop identifier")
    if not entry["selectable"]:
        raise DesktopSelectionError(
            f"{entry['name']} is not yet qualified; KDE Plasma remains the supported default"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "desktop": entry["id"],
        "display_name": entry["name"],
        "selection_status": "REVIEW_ONLY",
        "default_applied": desktop_id is None,
        "execution_enabled": False,
        "session_types": list(entry["session_types"]),
        "core_security_controls": list(CORE_SECURITY_CONTROLS),
        "hardware_optimization": {
            "selection": "independent_of_desktop",
            "status": "NOT_RUN",
            "requires_measurement_and_rollback": True,
        },
        "limitations": [
            "Configuration metadata only; no packages installed and no system settings changed.",
            "Desktop choice cannot disable or replace core security controls.",
            "Hardware optimization must use fresh hardware observations and workload goals, not desktop identity alone.",
        ],
    }
