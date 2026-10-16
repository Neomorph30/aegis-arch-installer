"""AEGIS CLI: hardware observation, storage proposals, reports. Zero disk mutations."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

from .assurance import formatted_manifest
from .hardware import HardwareInspectionError, inspect, read_assessment_observation
from .inventory import assess_inventory
from .network import NetworkSetupError, interactive_preflight, network_preflight, print_network_status, launch_wifi_setup
from .planner import PlanError, build_storage_plan
from .profiles import recommend
from .reporting import html_report, public_view, validate_proposal_evidence

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


def _readline(prompt: str) -> str | None:
    """Treat EOF/Ctrl-C as a safe cancellation instead of a traceback."""
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\nInput closed or interrupted. Cancelling this step safely.")
        return None


def _choose(prompt: str, max_index: int, *, attempts: int = 3) -> int | None:
    """Bounded input recovery; Enter cancels, invalid input never changes state."""
    if max_index < 1:
        return None
    for attempt in range(attempts):
        raw_entry = _readline(prompt)
        if raw_entry is None:
            return None
        entry = raw_entry.strip()
        if not entry:
            return None
        try:
            number = int(entry)
        except ValueError:
            print("Please enter a number from the displayed list, or press Enter to cancel.")
        else:
            if 1 <= number <= max_index:
                return number - 1
            print(f"Choose a number between 1 and {max_index}, or press Enter to cancel.")
        if attempt + 1 < attempts:
            print(f"Try again ({attempts - attempt - 1} attempt(s) remaining).")
    print("Input retry limit reached. Cancelling this step safely.")
    return None


def _require_live_target_reviewable(target: str, expected: dict[str, Any] | None = None) -> None:
    """Block live proposals if a fresh target snapshot is unsafe or identity changed."""
    observation = read_assessment_observation()
    whole = assess_inventory(observation)
    if any(item.get("code") == "DUPLICATE_IDENTITY" for item in whole.get("findings", [])):
        raise PlanError("Live inventory has duplicate stable device identities; resolve ambiguity before planning")
    matches = [node for node in observation.get("devices", [])
               if isinstance(node, dict) and node.get("path") == target]
    if len(matches) != 1:
        raise PlanError("Selected live disk is not uniquely present in fresh hardware observations")
    fresh = matches[0]
    if expected is not None:
        for field in ("serial", "wwn", "size"):
            old_value = expected.get(field)
            new_value = fresh.get(field)
            if old_value != new_value:
                raise PlanError(
                    f"Selected disk {field} changed between inventory and safety assessment; refresh and retry"
                )
        if not any(isinstance(fresh.get(field), str) and fresh[field].strip()
                   for field in ("serial", "wwn")):
            raise PlanError("Selected live disk has no stable identity in the fresh safety assessment")
    result = assess_inventory({"devices": matches})
    if result.get("status") == "blocked":
        codes = sorted({item.get("code", "UNKNOWN") for item in result.get("findings", [])
                        if item.get("severity") == "error"})
        raise PlanError("Live storage assessment blocked this disk: " + ", ".join(codes))


def wizard(inventory_file: str | None = None) -> int:
    try:
        data = _inventory(inventory_file)
    except (HardwareInspectionError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Hardware inventory unavailable: {exc}", file=sys.stderr)
        print("Recovery: verify the inventory source and retry. No changes made.")
        return 2
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
    selected_primary = disks[primary_index]
    primary = selected_primary.get("path") if isinstance(selected_primary, dict) else None
    if not isinstance(primary, str) or not primary.startswith("/dev/"):
        print("Selected device has no valid /dev path. Cancelling safely; refresh inventory.")
        return 2
    remaining = [d for i, d in enumerate(disks) if i != primary_index]
    secondary = None
    secondary_action = "preserve"
    if remaining:
        print("\nSecondary disks (default: none; included disks are preserved by default)")
        _print_devices(remaining)
        second_index = _choose("Secondary disk number (Enter = none): ", len(remaining))
        if second_index is not None:
            selected_secondary = remaining[second_index]
            secondary = selected_secondary.get("path") if isinstance(selected_secondary, dict) else None
            if not isinstance(secondary, str) or not secondary.startswith("/dev/"):
                print("Selected secondary device has no valid /dev path. Cancelling safely.")
                return 2
            print("Secondary action: 1) preserve [default], 2) unlock existing LUKS, 3) propose erase")
            actions = {"1": "preserve", "2": "unlock-existing", "3": "erase"}
            action_index = _choose("Action number [1-3, Enter = preserve]: ", 3)
            secondary_action = actions[str((action_index if action_index is not None else 0) + 1)]
    fs_index = _choose("Root filesystem: 1) Btrfs [default], 2) ext4: ", 2)
    filesystem = "btrfs" if fs_index is None or fs_index == 0 else "ext4"
    try:
        if inventory_file is None:
            _require_live_target_reviewable(
                primary, next((disk for disk in data.get("disks", [])
                               if isinstance(disk, dict) and disk.get("path") == primary), None))
            if secondary is not None:
                _require_live_target_reviewable(
                    secondary, next((disk for disk in data.get("disks", [])
                                     if isinstance(disk, dict) and disk.get("path") == secondary), None))
        plan = build_storage_plan(data, primary, secondary, secondary_action, filesystem=filesystem)
    except (PlanError, KeyError, TypeError, ValueError) as exc:
        print(f"Cannot create a safe proposal: {exc}", file=sys.stderr)
        print("Recovery: refresh inventory, resolve blockers, and start a new proposal.")
        return 2
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
    raw_filename = _readline("\nWrite JSON proposal to NEW filename (Enter = do not save): ")
    filename = raw_filename.strip() if raw_filename is not None else ""
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
        try:
            interactive_preflight()
        except (NetworkSetupError, OSError, ValueError) as exc:
            print(f"Network preflight unavailable: {exc}", file=sys.stderr)
            print("Recovery: continue without network changes; retry from menu option 6 if needed.")
    else:
        print("Using fixture inventory: real network preflight skipped.")
    while True:
        print("1) Inspect detected hardware")
        print("2) Plan storage using guided wizard (read-only)")
        print("3) View secure gaming profile (advisory)")
        print("4) View secure workstation profile (advisory)")
        print("5) Exit")
        print("6) Check internet / configure Wi-Fi")
        raw_choice = _readline("Select [1-6]: ")
        if raw_choice is None:
            print("Exiting without changes.")
            return 0
        choice = raw_choice.strip()
        if choice == "5" or not choice:
            print("Exiting without changes.")
            return 0
        if choice == "1":
            try:
                data = _inventory(inventory_file)
            except (HardwareInspectionError, OSError, ValueError, KeyError, TypeError) as exc:
                print(f"Hardware inventory unavailable: {exc}", file=sys.stderr)
                print("Recovery: refresh the inventory source and retry; returning to menu.")
                continue
            print(f"\nCPU: {data.get('cpu')} | TPM: {data.get('tpm_version', 'unverified')}")
            print(f"UEFI: {data.get('uefi_detected')} | Secure Boot: {data.get('secure_boot_state', 'unverified')}")
            _print_devices(data.get("disks", []))
        elif choice == "2":
            wizard(inventory_file)
        elif choice == "6":
            interactive_preflight()
        elif choice in ("3", "4"):
            profile = "secure-gaming" if choice == "3" else "secure-workstation"
            try:
                recommendation = recommend(_inventory(inventory_file), profile)
            except (HardwareInspectionError, OSError, ValueError, KeyError, TypeError) as exc:
                print(f"Cannot generate a trustworthy profile: {exc}", file=sys.stderr)
                print("Recovery: refresh hardware inventory and retry; returning to menu.")
                continue
            print(json.dumps(recommendation, indent=2))
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
    p_assess = sub.add_parser("assess", help="Assess block-device observations; read-only")
    assess_source = p_assess.add_mutually_exclusive_group(required=True)
    assess_source.add_argument("--inventory",
                               help="JSON fixture with a devices list; no hardware probing or disk writes")
    assess_source.add_argument("--live", action="store_true",
                               help="Collect live read-only block-device, holder and swap observations")
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
    p_profile.add_argument("--desktop", choices=["kde-plasma", "gnome", "xfce", "other"], default="kde-plasma",
                           help="Desktop candidate; KDE Plasma is the only qualified initial choice")
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
        if args.command == "assess":
            observation = read_assessment_observation() if args.live else _load_json(args.inventory)
            result = assess_inventory(observation)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 2 if result["status"] == "blocked" else 0
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
            inventory = _inventory(args.inventory)
            if args.inventory is None:
                _require_live_target_reviewable(
                    args.primary, next((disk for disk in inventory.get("disks", [])
                                        if isinstance(disk, dict) and disk.get("path") == args.primary), None))
                if args.secondary is not None:
                    _require_live_target_reviewable(
                        args.secondary, next((disk for disk in inventory.get("disks", [])
                                              if isinstance(disk, dict) and disk.get("path") == args.secondary), None))
            plan = build_storage_plan(inventory, args.primary, args.secondary,
                                      args.secondary_action, filesystem=args.filesystem)
            if args.output:
                _write_json(args.output, plan)
                print("Read-only proposal saved:", args.output)
            else:
                validate_proposal_evidence(plan)
                print(json.dumps(public_view(plan), indent=2))
        elif args.command == "wizard":
            return wizard(args.inventory)
        elif args.command == "profile":
            print(json.dumps(recommend(_inventory(args.inventory), args.name, args.desktop), indent=2))
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
