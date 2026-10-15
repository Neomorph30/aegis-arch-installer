"""AEGIS CLI: hardware observation, storage proposals, reports. Zero disk mutations."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

from .assurance import formatted_manifest
from .hardware import HardwareInspectionError, inspect
from .network import NetworkSetupError, interactive_preflight, network_preflight, print_network_status, launch_wifi_setup
from .planner import PlanError, build_storage_plan
from .profiles import recommend
from .reporting import html_report, public_view

MAX_JSON_INPUT_BYTES = 2 * 1024 * 1024


def _load_json(filename: str) -> dict[str, Any]:
    path = Path(filename)
    if path.stat().st_size > MAX_JSON_INPUT_BYTES:
        raise ValueError("Input JSON is too large for a planning report")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    return data


def _write_new(path: str, content: str) -> None:
    p = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(p, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(content)


def _write_json(path: str, data: dict[str, Any]) -> None:
    _write_new(path, json.dumps(public_view(data), indent=2, ensure_ascii=False) + "\n")


def _print_devices(disks: list[dict[str, Any]]) -> None:
    if not disks:
        print("No physical disks detected")
    for index, disk in enumerate(disks, 1):
        size = disk.get("size")
        gib = f"{size / 1024**3:.1f} GiB" if isinstance(size, (int, float)) else "unknown"
        print(f" {index}. {disk.get('path') or 'UNKNOWN'}  {gib}  {disk.get('model') or ''}"
              f"  SN={disk.get('serial') or 'unknown'}")


def _inventory(filename: str | None) -> dict[str, Any]:
    return _load_json(filename) if filename else inspect()


def _choose(prompt: str, max_index: int) -> int | None:
    entry = input(prompt).strip()
    if not entry:
        return None
    try:
        number = int(entry)
    except ValueError as exc:
        raise ValueError("Please enter a numeric choice") from exc
    if number < 1 or number > max_index:
        raise ValueError("Choice is outside the displayed range")
    return number - 1


def wizard(inventory_file: str | None = None) -> int:
    data = _inventory(inventory_file)
    print("\nAEGIS — NON-DESTRUCTIVE DEVELOPER PREVIEW\nNo disk changes will occur.\n")
    print(f"CPU: {data.get('cpu')} | RAM: {data.get('ram_mib')} MiB | UEFI: {data.get('uefi_detected')}")
    print(f"TPM: {data.get('tpm_version', 'unknown')} (enrollment not tested)")
    disks = data.get("disks", [])
    _print_devices(disks)
    if not disks:
        return 2
    primary_index = _choose("\nPrimary disk number (proposal only, Enter to cancel): ", len(disks))
    if primary_index is None:
        print("Cancelled. No changes made.")
        return 0
    primary = disks[primary_index]["path"]
    remaining = [d for i, d in enumerate(disks) if i != primary_index]
    secondary = None
    secondary_action = "preserve"
    if remaining:
        print("\nSecondary disks (default: none; included disks are preserved by default)")
        _print_devices(remaining)
        second_index = _choose("Secondary disk number (Enter = none): ", len(remaining))
        if second_index is not None:
            secondary = remaining[second_index]["path"]
            print("Secondary action: 1) preserve [default], 2) unlock existing LUKS, 3) propose erase")
            action_choice = input("Action number: ").strip() or "1"
            actions = {"1": "preserve", "2": "unlock-existing", "3": "erase"}
            if action_choice not in actions:
                raise ValueError("Invalid secondary action")
            secondary_action = actions[action_choice]
    fs_choice = input("Root filesystem: 1) Btrfs [default], 2) ext4: ").strip() or "1"
    if fs_choice not in ("1", "2"):
        raise ValueError("Invalid filesystem choice")
    filesystem = {"1": "btrfs", "2": "ext4"}[fs_choice]
    plan = build_storage_plan(data, primary, secondary, secondary_action, filesystem=filesystem)
    print("\n===== PROPOSED ACTIONS (NO DISK WRITES) =====")
    for action in plan["actions"]:
        print(f"{action['target']}: {action['action'].upper()} — "
              f"{'DESTRUCTIVE' if action['destructive'] else 'NON-DESTRUCTIVE'}")
        for partition in action["partitions"]:
            print(f"  {partition['label']}: {partition['size_bytes'] / 1024**3:.2f} GiB ({partition['filesystem']})")
    print(f"\nREVIEW: {plan['review_state']}")
    for blocker in plan["blockers"]:
        print(" BLOCKER:", blocker)
    for warning in plan["warnings"]:
        print(" WARNING:", warning)
    filename = input("\nWrite JSON proposal to NEW filename (Enter = do not save): ").strip()
    if filename:
        _write_json(filename, plan)
        print("Proposal written:", filename)
    print("\nNo installation or disk modifications occurred.")
    return 0


def menu(inventory_file: str | None = None) -> int:
    """Minimal keyboard-accessible first screen for the live environment.

    No installation execution or disk operations. Network changes require consent.
    """
    print("\nAEGIS // SECURE ARCH INSTALLER — DEVELOPER PREVIEW 0.2")
    print("NO DISK WRITES: this build cannot install an operating system.\n")
    if inventory_file is None:
        print("\nNETWORK PREFLIGHT (optional network setup only)" )
        interactive_preflight()
    else:
        print("Using fixture inventory: real network preflight skipped.")
    while True:
        print("1) Inspect detected hardware")
        print("2) Plan storage using guided wizard (read-only)")
        print("3) View secure gaming profile (advisory)")
        print("4) View secure workstation profile (advisory)")
        print("5) Exit")
        print("6) Check internet / configure Wi-Fi")
        choice = input("Select [1-6]: ").strip()
        if choice == "5" or not choice:
            print("Exiting without changes.")
            return 0
        if choice == "1":
            data = _inventory(inventory_file)
            print(f"\nCPU: {data.get('cpu')} | TPM: {data.get('tpm_version', 'unverified')}")
            print(f"UEFI: {data.get('uefi_detected')} | Secure Boot: {data.get('secure_boot_state', 'unverified')}")
            _print_devices(data.get("disks", []))
        elif choice == "2":
            wizard(inventory_file)
        elif choice == "6":
            interactive_preflight()
        elif choice in ("3", "4"):
            profile = "secure-gaming" if choice == "3" else "secure-workstation"
            print(json.dumps(recommend(_inventory(inventory_file), profile), indent=2))
        else:
            print("Invalid selection; no changes made.")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis", description="AEGIS developer preview — NO DISK WRITES")
    sub = parser.add_subparsers(dest="command")
    p_menu = sub.add_parser("menu", help="Interactive, non-destructive main menu")
    p_menu.add_argument("--inventory", help="Use simulated hardware inventory")
    p_inspect = sub.add_parser("inspect", help="Read-only hardware inventory")
    p_inspect.add_argument("--json", action="store_true")
    p_inspect.add_argument("--inventory", help="Load fixture JSON rather than inspect live hardware")
    p_plan = sub.add_parser("plan", help="Read-only storage partition proposal")
    p_plan.add_argument("--primary", required=True)
    p_plan.add_argument("--secondary")
    p_plan.add_argument("--secondary-action", choices=["preserve", "unlock-existing", "erase"], default="preserve")
    p_plan.add_argument("--filesystem", choices=["btrfs", "ext4"], default="btrfs")
    p_plan.add_argument("--inventory", help="Load fixture JSON; never touches device contents")
    p_plan.add_argument("--output", help="Save local 0600 JSON plan to a NEW file")
    p_wizard = sub.add_parser("wizard", help="Interactive read-only storage wizard")
    p_wizard.add_argument("--inventory", help="Use a simulated JSON fixture")
    p_profile = sub.add_parser("profile", help="Show proposed software/security profile; no changes")
    p_profile.add_argument("--name", choices=["secure-workstation", "secure-gaming"], default="secure-gaming")
    p_profile.add_argument("--inventory", help="Use a simulated JSON fixture")
    p_assurance = sub.add_parser("assurance", help="Read-only feature and safety readiness status")
    p_assurance.add_argument("--json", action="store_true")
    p_network = sub.add_parser("network", help="Check HTTPS connectivity; opt-in interactive Wi-Fi setup")
    p_network.add_argument("--connect", action="store_true", help="Offer interactive Wi-Fi setup when HTTPS cannot be verified")
    p_report = sub.add_parser("report", help="Render read-only HTML plan report")
    p_report.add_argument("--plan", required=True)
    p_report.add_argument("--output", required=True)
    p_report.add_argument("--private", action="store_true", help="Keep hardware serials in HTML (local use only)")
    args = parser.parse_args(argv)
    try:
        if args.command is None or args.command == "menu":
            if not sys.stdin.isatty():
                parser.print_help()
                return 0
            return menu(getattr(args, "inventory", None))
        if args.command == "inspect":
            data = _inventory(args.inventory)
            if args.json:
                print(json.dumps(public_view(data), indent=2))
            else:
                print(f"CPU: {data.get('cpu')} | RAM: {data.get('ram_mib')} MiB")
                print(f"UEFI: {data.get('uefi_detected')} | TPM: {data.get('tpm_version', 'unverified')}")
                print(f"Secure Boot: {data.get('secure_boot_state', 'unverified')}")
                _print_devices(data.get("disks", []))
        elif args.command == "plan":
            plan = build_storage_plan(_inventory(args.inventory), args.primary, args.secondary,
                                      args.secondary_action, filesystem=args.filesystem)
            if args.output:
                _write_json(args.output, plan)
                print("Read-only proposal saved:", args.output)
            else:
                print(json.dumps(public_view(plan), indent=2))
        elif args.command == "wizard":
            return wizard(args.inventory)
        elif args.command == "profile":
            print(json.dumps(recommend(_inventory(args.inventory), args.name), indent=2))
        elif args.command == "assurance":
            print(formatted_manifest(as_json=args.json))
        elif args.command == "network":
            if args.connect:
                if not sys.stdin.isatty() or not sys.stdout.isatty():
                    raise NetworkSetupError("Interactive Wi-Fi setup requires a local terminal")
                interactive_preflight()
            else:
                print_network_status(network_preflight())
        elif args.command == "report":
            plan = _load_json(args.plan)
            _write_new(args.output, html_report(plan, shareable=not args.private))
            print("Non-executed planning report saved:", args.output)
    except (HardwareInspectionError, NetworkSetupError, PlanError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"AEGIS: {exc}", file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print("\nAEGIS cancelled. No changes made.", file=sys.stderr)
        return 130
    return 0
