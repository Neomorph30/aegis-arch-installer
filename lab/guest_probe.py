"""Read-only observation adapter for the Layer 07 guest preflight spec."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any, Callable

LSBLK_FIELDS = "NAME,PATH,TYPE,SIZE,SERIAL,RO,MOUNTPOINTS,PKNAME,PARTTYPE,PARTLABEL"


class GuestProbeError(RuntimeError):
    """Guest hardware could not be safely observed."""


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _run_lsblk(run: Callable[..., Any] = subprocess.run) -> str:
    command = ["lsblk", "--json", "--bytes", "--tree", "--output", LSBLK_FIELDS]
    try:
        result = run(command, check=True, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GuestProbeError("Read-only lsblk probe failed; do not continue installation") from exc
    if not isinstance(result.stdout, str):
        raise GuestProbeError("lsblk returned no textual output")
    return result.stdout


def _mountpoints(node: dict[str, Any]) -> list[str]:
    value = node.get("mountpoints") or []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise GuestProbeError("Malformed mountpoint data from lsblk")
    return [entry for entry in value if isinstance(entry, str) and entry.strip()]


def _normalize(node: Any, sys_root: Path, swaps: set[str]) -> dict[str, Any]:
    if not isinstance(node, dict):
        raise GuestProbeError("Malformed device node from lsblk")
    path = node.get("path")
    if not isinstance(path, str) or not path.startswith("/dev/"):
        raise GuestProbeError("Device node has no valid path; refresh discovery")
    name = path.removeprefix("/dev/")
    size = node.get("size")
    if size is not None and (isinstance(size, bool) or not isinstance(size, int)):
        raise GuestProbeError("Device size is malformed")
    raw_children = node.get("children") or []
    if not isinstance(raw_children, list):
        raise GuestProbeError("Device children are malformed")
    holders_dir = sys_root / "class" / "block" / name / "holders"
    try:
        holders = sorted(item.name for item in holders_dir.iterdir())
    except OSError:
        holders = []
    normalized = {
        "path": path,
        "type": node.get("type"),
        "serial": node.get("serial"),
        "size_bytes": size,
        "read_only": node.get("ro") in (1, True, "1"),
        "mountpoints": _mountpoints(node),
        "holders": holders,
        "active_swap": path in swaps,
        "children": [],
    }
    normalized["children"] = [_normalize(child, sys_root, swaps) for child in raw_children]
    return normalized


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
    swap_text = _read(proc_path / "swaps")
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

    net_dir = sys_path / "class" / "net"
    try:
        interfaces = {entry.name for entry in net_dir.iterdir()}
    except OSError:
        interfaces = set()
    network_mode = "disabled" if not (interfaces - {"lo"}) else "unverified"

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
            "A future executor must independently re-probe identity immediately before each mutation.",
        ],
    }
