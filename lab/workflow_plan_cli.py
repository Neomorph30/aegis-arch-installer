"""CLI for building a review-only guest workflow plan from JSON evidence.

This command reads two bounded regular files and writes the plan to stdout only.
It never probes hardware, executes installation commands, or modifies storage.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

from .workflow_plan import WorkflowPlanError, build_review_plan

MAX_INPUT_BYTES = 1024 * 1024


class PlanInputError(ValueError):
    """Input evidence file is not safe to read or valid JSON."""


def _read_json(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise PlanInputError("Input file could not be opened safely") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PlanInputError("Input must be a single-link regular file, not a device, pipe, or symlink")
        if info.st_size <= 0 or info.st_size > MAX_INPUT_BYTES:
            raise PlanInputError("Input file is empty or exceeds the 1 MiB limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, MAX_INPUT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_INPUT_BYTES:
                raise PlanInputError("Input grew beyond the 1 MiB limit while being read")
        if total != info.st_size:
            raise PlanInputError("Input changed while being read; recapture evidence")
    finally:
        os.close(fd)
    try:
        result = json.loads(b"".join(chunks))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PlanInputError("Input is not valid UTF-8 JSON") from exc
    if not isinstance(result, dict):
        raise PlanInputError("Input JSON root must be an object")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build an AEGIS Layer 07 review-only plan; no installation or disk changes"
    )
    parser.add_argument("--spec", required=True, help="JSON output from guest preflight")
    parser.add_argument("--observation", required=True, help="Fresh guest observation JSON")
    args = parser.parse_args(argv)
    try:
        spec = _read_json(args.spec)
        observation = _read_json(args.observation)
        plan = build_review_plan(spec, observation)
    except (PlanInputError, WorkflowPlanError, OSError, ValueError, TypeError) as exc:
        print(json.dumps({
            "schema_version": 1,
            "status": "BLOCKED",
            "execution_enabled": False,
            "disk_changes_performed": False,
            "error": str(exc),
            "recovery": "Preserve evidence, refresh read-only discovery, and review a new preflight spec.",
        }, sort_keys=True), file=sys.stdout)
        print("Workflow plan blocked. No disk changes were performed.", file=sys.stderr)
        return 2
    print(json.dumps(plan, indent=2, sort_keys=True))
    print("Review plan only. No installation commands or disk changes were performed.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
