"""Read-only observation adapter for the Layer 07 guest preflight spec."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any, Callable

LSBLK_FIELDS = "NAME,PATH,TYPE,SIZE,SERIAL,RO,MOUNTPOINTS,PKNAME,PARTTYPE,PARTLABEL,MAJ:MIN"


class GuestProbeError(RuntimeError):
    """Guest hardware could not be safely observed."""


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _run_lsblk(run: Callable[..., Any] = subprocess.run) -> str:
    command = ["lsblk", "--json", "--bytes", "--tree", "--output", LSBLK_FIELDS]
    for attempt in range(2):
        try:
            result = run(command, check=True, capture_output=True, text=True, timeout=8)
            break
        except subprocess.TimeoutExpired as exc:
            if attempt == 0:
                continue  # One bounded retry is safe for this read-only probe.
            raise GuestProbeError("Read-only lsblk probe timed out twice; do not continue installation") from exc
        except (OSError, subprocess.SubprocessError) as exc:
            raise GuestProbeError("Read-only lsblk probe failed; do not continue installation") from exc
    if not isinstance(result.stdout, str):
        raise GuestProbeError("lsblk returned no textual output")
    return result.stdout


def _mountpoints(node: dict[str, Any]) -> list[str]:
    if "mountpoints" not in node:
        raise GuestProbeError("Mountpoint data is missing from lsblk")
    value = node["mountpoints"]
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or any(
        entry is not None and not isinstance(entry, str) for entry in value
    ):
        raise GuestProbeError("Malformed mountpoint data from lsblk")
    return [entry for entry in value if isinstance(entry, str) and entry.strip()]


def _normalize(node: Any, sys_root: Path, swaps: set[str]) -> dict[str, Any]:
    if not isinstance(node, dict):
        raise GuestProbeError("Malformed device node from lsblk")
    path = node.get("path")
    if not isinstance(path, str) or not path.startswith("/dev/"):
        raise GuestProbeError("Device node has no valid path; refresh discovery")
    name = path.removeprefix("/dev/")
    raw_major_minor = node.get("maj:min")
    if not isinstance(raw_major_minor, str) or raw_major_minor.count(":") != 1:
        raise GuestProbeError("Device node has no valid kernel major/minor identity; refresh discovery")
    try:
        major_text, minor_text = raw_major_minor.split(":", 1)
        if not major_text.isdecimal() or not minor_text.isdecimal():
            raise ValueError("non-decimal identity")
        major_minor = f"{int(major_text)}:{int(minor_text)}"
    except ValueError as exc:
        raise GuestProbeError("Device node has malformed kernel major/minor identity") from exc
    size = node.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise GuestProbeError("Device size is missing or malformed")
    raw_ro = node.get("ro")
    if type(raw_ro) not in (bool, int) or raw_ro not in (0, 1):
        raise GuestProbeError("Device read-only flag is missing or malformed")
    raw_children = node.get("children", [])
    if not isinstance(raw_children, list):
        raise GuestProbeError("Device children are malformed")
    holders_dir = sys_root / "class" / "block" / name / "holders"
    try:
        holders = sorted(item.name for item in holders_dir.iterdir())
    except OSError:
        # Unknown is not equivalent to empty; the spec rejects this sentinel.
        holders = ["UNVERIFIED"]
    normalized = {
        "path": path,
        "major_minor": major_minor,
        "type": node.get("type"),
        "serial": node.get("serial"),
        "size_bytes": size,
        "read_only": bool(raw_ro),
        "mountpoints": _mountpoints(node),
        "holders": holders,
        "active_swap": path in swaps,
        "children": [],
    }
    normalized["children"] = [_normalize(child, sys_root, swaps) for child in raw_children]
    return normalized


def _network_mode(sys_path: Path, run: Callable[..., Any]) -> str:
    """Recognize only the fixed QEMU user-NAT address/route; unknown networks block preflight."""
    try:
        interfaces = {entry.name for entry in (sys_path / "class" / "net").iterdir()}
    except OSError:
        return "unverified"
    external = interfaces - {"lo"}
    if not external:
        return "disabled"
    if len(external) != 1:
        return "unverified"
    interface = next(iter(external))
    try:
        address_result = run(
            ["ip", "-json", "-4", "address", "show", "dev", interface],
            check=True, capture_output=True, text=True, timeout=5,
        )
        route_result = run(
            ["ip", "-json", "route", "show", "default", "dev", interface],
            check=True, capture_output=True, text=True, timeout=5,
        )
        addresses = json.loads(address_result.stdout)
        routes = json.loads(route_result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, TypeError, AttributeError):
        return "unverified"
    address_ok = (
        isinstance(addresses, list)
        and any(
            isinstance(item, dict) and item.get("ifname") == interface
            and any(
                isinstance(addr, dict) and addr.get("family") == "inet"
                and addr.get("local") == "10.0.2.15" and addr.get("prefixlen") == 24
                for addr in item.get("addr_info", [])
            )
            for item in addresses
        )
    )
    route_ok = (
        isinstance(routes, list)
        and any(
            isinstance(route, dict) and route.get("dst") == "default"
            and route.get("gateway") == "10.0.2.2" and route.get("dev") == interface
            for route in routes
        )
    )
    return "user-nat-explicit" if address_ok and route_ok else "unverified"


def observe_guest(
    *,
    sys_root: str | Path = "/sys",
    proc_root: str | Path = "/proc",
    run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Collect a conservative observation; this function never writes to devices."""
    sys_path, proc_path = Path(sys_root), Path(proc_root)
    raw = _run_lsblk(run)
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise GuestProbeError("lsblk output is invalid JSON") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("blockdevices"), list):
        raise GuestProbeError("lsblk output has an unexpected schema")

    swaps: set[str] = set()
    try:
        swap_text = (proc_path / "swaps").read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise GuestProbeError("Cannot verify active swap state; do not continue installation") from exc
    for line in swap_text.splitlines()[1:]:
        fields = line.split()
        if fields:
            swaps.add(fields[0])

    devices = []
    for node in parsed["blockdevices"]:
        if not isinstance(node, dict):
            raise GuestProbeError("Malformed top-level lsblk node")
        if node.get("type") in ("disk", "rom"):
            devices.append(_normalize(node, sys_path, swaps))

    network_mode = _network_mode(sys_path, run)

    return {
        "environment": {
            "sys_vendor": _read(sys_path / "class" / "dmi" / "id" / "sys_vendor"),
            "product_name": _read(sys_path / "class" / "dmi" / "id" / "product_name"),
        },
        "network_mode": network_mode,
        "active_swaps": sorted(swaps),
        "devices": devices,
        "observation_notes": [
            "Read-only guest observation; not a cryptographic attestation of virtualization.",
            "user-nat-explicit is recognized only from the conventional QEMU user-NAT IPv4 address and default route; this is not network attestation.",
            "A future executor must independently re-probe identity immediately before each mutation.",
        ],
    }
