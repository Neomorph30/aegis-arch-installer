"""Conservative AST-level guardrail for the NON-DESTRUCTIVE AEGIS preview.

This is a review aid, not a sandbox, formal proof or malicious-code detector.
Only a small known list of modules may launch processes; adding a privileged
installer requires separate design/review rather than weakening these checks.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

APPROVED_SUBPROCESS_MODULES = frozenset({"hardware.py", "network.py"})
APPROVED_LAB_SUBPROCESS_MODULES = frozenset({
    "lab/runtime.py", "lab/guest_probe.py", "lab/guest_storage_gate.py",
})
FORBIDDEN_MODULES = frozenset({"ctypes", "pty"})
FORBIDDEN_CALLS = frozenset({
    "os.system", "os.popen", "os.fork", "os.execv", "os.execve", "os.spawnv",
    "os.spawnve", "os.posix_spawn", "os.posix_spawnp", "eval", "exec",
    "builtins.eval", "builtins.exec",
})
FORBIDDEN_INSTALLER_FILES = frozenset({"executor.py", "partitioner.py", "disk_writer.py"})


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _subprocess_allowed(filename: str) -> bool:
    """Allow subprocess only in audited modules, using paths for the lab layer."""
    normalized = filename.replace("\\", "/").lstrip("./")
    if normalized.startswith("lab/"):
        return normalized in APPROVED_LAB_SUBPROCESS_MODULES
    if "/" in normalized:
        return normalized.startswith("aegis/") and Path(normalized).name in APPROVED_SUBPROCESS_MODULES
    # Bare names are retained for direct unit tests of the checker.
    return normalized in APPROVED_SUBPROCESS_MODULES


def check_source(source: str, filename: str) -> list[str]:
    """Return violations; use distinct, stable diagnostics in CI and tests."""
    errors: list[str] = []
    name = Path(filename).name
    if name in FORBIDDEN_INSTALLER_FILES:
        errors.append(f"{filename}: executor-like module prohibited in preview")
    try:
        root = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return errors + [f"{filename}:{exc.lineno}: invalid Python syntax"]
    # Resolve common direct imports/aliases so a refactor cannot trivially
    # bypass the guardrail by spelling os.system as shell_api.system.
    imported_modules: dict[str, str] = {}
    imported_functions: dict[str, str] = {}
    for node in ast.walk(root):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                imported_functions[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    for node in ast.walk(root):
        line = getattr(node, "lineno", 0)
        prefix = f"{filename}:{line}"
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess" and not _subprocess_allowed(filename):
                    errors.append(f"{prefix}: subprocess import not allowlisted")
                if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                    errors.append(f"{prefix}: forbidden module import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == "subprocess":
                errors.append(f"{prefix}: subprocess direct import forbidden")
            if mod == "os" and any(alias.name.startswith(("exec", "spawn")) or alias.name in {"system", "popen", "fork", "posix_spawn", "posix_spawnp"} for alias in node.names):
                errors.append(f"{prefix}: os execution function import forbidden")
            if mod.split(".")[0] in FORBIDDEN_MODULES:
                errors.append(f"{prefix}: forbidden module import {mod}")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in {"execute_install", "format_disk", "wipe_disk", "install_os"}:
                errors.append(f"{prefix}: privileged entrypoint forbidden in preview")
        elif isinstance(node, ast.Call):
            called = _call_name(node.func)
            if called in imported_functions:
                called = imported_functions[called]
            elif called and "." in called:
                base, _, child = called.partition(".")
                if base in imported_modules:
                    called = imported_modules[base] + "." + child
            if called in {"__import__", "importlib.import_module"}:
                errors.append(f"{prefix}: dynamic module loading forbidden in preview")
            if called == "getattr" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                base = _call_name(node.args[0])
                target = imported_modules.get(base or "", base)
                if target in ("os", "subprocess"):
                    errors.append(f"{prefix}: dynamic execution-API lookup forbidden in preview")
            if called in FORBIDDEN_CALLS:
                errors.append(f"{prefix}: forbidden direct execution {called}")
            if called and called.startswith("subprocess."):
                if not _subprocess_allowed(filename) or called != "subprocess.run":
                    errors.append(f"{prefix}: subprocess call {called} not allowlisted")
            if called and called.startswith("os.exec"):
                errors.append(f"{prefix}: os.exec family forbidden")
            if called and called.startswith("os.spawn"):
                errors.append(f"{prefix}: os.spawn family forbidden")
            if called in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output"}:
                for kw in node.keywords:
                    if kw.arg is None:
                        errors.append(f"{prefix}: subprocess keyword expansion forbidden")
                    if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and kw.value.value is False):
                        errors.append(f"{prefix}: subprocess shell option forbidden")
    return errors


def run_check(root: Path) -> list[str]:
    package = root / "aegis"
    errors: list[str] = []
    if not package.is_dir():
        return [f"{package}: source package missing"]
    for source in sorted(package.rglob("*.py")):
        errors.extend(check_source(source.read_text(encoding="utf-8"), str(source.relative_to(root))))
    # The lab contains controlled QEMU/read-only probe subprocesses; scan it too,
    # with a separate path-specific allowlist so new executor-like code cannot bypass preview checks.
    lab = root / "lab"
    if not lab.is_dir():
        errors.append(f"{lab}: lab package missing")
    else:
        for source in sorted(lab.rglob("*.py")):
            errors.extend(check_source(source.read_text(encoding="utf-8"), str(source.relative_to(root))))
    # CI supply-chain contract: pinned upstream actions and no writable tokens.
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        errors.append("GitHub Actions workflow directory missing")
    else:
        workflows = list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml"))
        if not workflows:
            errors.append("No GitHub Actions safety/test workflow present")
        for workflow in workflows:
            data = workflow.read_text(encoding="utf-8")
            display = str(workflow.relative_to(root))
            for i, line in enumerate(data.splitlines(), 1):
                action = re.match(r"^\s*(?:-\s*)?uses:\s*([^#\s]+)", line)
                if action and not re.fullmatch(r"[A-Za-z0-9_.\-/]+@[a-f0-9]{40}", action.group(1)):
                    errors.append(f"{display}:{i}: GitHub action must be pinned to full SHA")
            if re.search(r"(?m)^\s*pull_request_target\s*:", data) or re.search(r"(?m)^\s*workflow_run\s*:", data):
                errors.append(f"{display}: untrusted triggering event forbidden")
            if not re.search(r"(?m)^permissions:\s*\n\s+contents:\s*read\s*$", data):
                errors.append(f"{display}: top-level contents: read-only token required")
            if "persist-credentials: false" not in data:
                errors.append(f"{display}: checkout credentials must not persist")
            if "tools/security_lint.py" not in data:
                errors.append(f"{display}: preview guardrail must run in CI")
            if workflow.name == "arch-live-boot.yml":
                if "--network-mode disabled" not in data:
                    errors.append(f"{display}: live preflight must run with guest networking disabled")
                if "--network-mode user-nat-explicit" in data:
                    errors.append(f"{display}: live preflight must not enable guest NAT")
    return errors


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    errors = run_check(root)
    if errors:
        print("AEGIS PREVIEW GUARDRAIL FAILED", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("AEGIS preview AST guardrail passed (review aid, not security certification).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
