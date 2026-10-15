"""Read-only Layer 07 guest preflight CLI; does not install or modify disks."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable

from .guest_probe import GuestProbeError, observe_guest
from .install_spec import InstallSpecError, build_guest_install_spec


def run_preflight(probe: Callable[[], dict[str, Any]] = observe_guest) -> tuple[int, dict[str, Any]]:
    try:
        observation = probe()
        spec = build_guest_install_spec(observation)
    except (GuestProbeError, InstallSpecError, OSError, ValueError, TypeError) as exc:
        return 2, {
            "schema_version": 1,
            "status": "BLOCKED",
            "execution_enabled": False,
            "error": str(exc),
            "recovery": "Stop here. Correct the lab configuration, re-run read-only discovery, and review a new spec.",
            "disk_changes_performed": False,
        }
    return 0, spec


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AEGIS Layer 07 read-only guest preflight; no installation")
    parser.add_argument("--json", action="store_true", help="emit the machine-readable review spec (default)")
    parser.parse_args(argv)
    code, result = run_preflight()
    print(json.dumps(result, indent=2, sort_keys=True))
    if code:
        print("Preflight blocked. No disk changes were performed.", file=sys.stderr)
    else:
        print("Preflight only. No disk changes were performed.", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
