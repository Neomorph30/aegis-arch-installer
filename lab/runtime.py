"""Host-side, opt-in disposable VM launcher.

No interface accepts a host block-device path, VM device arguments, USB passthrough
or filesystem sharing. A smoke test only proves that the VM can stay running
for a bounded interval; it does NOT prove guest boot or installation success.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import socket
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable

from .iso_validation import ISOValidationError, verify_arch_iso

# Firmware code/vars must be paired by vendor and size: do not mix 2M/4M images.
FIRMWARE_PAIRS = (
    ("/usr/share/edk2/x64/OVMF_CODE.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd"),
    ("/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd"),
    ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
    ("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
)
QEMU = "qemu-system-x86_64"
SWTPM = "swtpm"
PRIMARY_BYTES = 24 * 1024**3
SECONDARY_BYTES = 8 * 1024**3
ISO_MAX_BYTES = 8 * 1024**3
NETWORK_MODES = {"disabled", "user-nat-explicit"}


class LabError(RuntimeError):
    """Refuse unsafe/unsupported labs instead of falling back to host devices."""


@dataclass(frozen=True)
class LabConfig:
    ram_mib: int = 2048
    cpus: int = 2
    primary_bytes: int = PRIMARY_BYTES
    secondary_bytes: int = SECONDARY_BYTES
    seconds: float = 5.0

    def validate(self) -> None:
        if not (1024 <= self.ram_mib <= 8192):
            raise LabError("RAM must be 1024–8192 MiB")
        if not (1 <= self.cpus <= 4):
            raise LabError("CPU count must be 1–4")
        if not (1 * 1024**3 <= self.primary_bytes <= 128 * 1024**3):
            raise LabError("Primary virtual disk must be 1–128 GiB")
        if not (1 * 1024**3 <= self.secondary_bytes <= 128 * 1024**3):
            raise LabError("Secondary virtual disk must be 1–128 GiB")
        if not (1 <= self.seconds <= 30):
            raise LabError("Smoke-test seconds must be 1–30")


def _regular_nonlink(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1


def find_firmware(pairs=FIRMWARE_PAIRS) -> tuple[Path, Path] | None:
    for code, vars_template in pairs:
        c, v = Path(code), Path(vars_template)
        if _regular_nonlink(c) and _regular_nonlink(v):
            return c, v
    return None


def dependencies() -> dict[str, object]:
    firmware = find_firmware()
    return {
        "qemu_present": shutil.which(QEMU) is not None,
        "swtpm_present": shutil.which(SWTPM) is not None,
        "ovmf_pair_present": firmware is not None,
        "ovmf_code": str(firmware[0]) if firmware else None,
        "ovmf_vars_template": str(firmware[1]) if firmware else None,
        "kvm_used": False,
        "guest_network_enabled": False,
        "host_passthrough_enabled": False,
        "arch_installer_enabled": False,
    }


def _exclusive_sparse_file(path: Path, size: int) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise LabError("Virtual disk must be a regular file")
        os.ftruncate(fd, size)  # sparse file only; no physical block-device writes
    finally:
        os.close(fd)


def _copy_regular_file(src: Path, dst: Path, *, max_bytes: int) -> int:
    # Open with O_NONBLOCK so a path substituted with a FIFO cannot hang us;
    # O_NOFOLLOW prohibits final-component symlinks, fstat rejects block devices.
    fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise LabError("Source must be one regular file, not a device or symlink")
        if before.st_size <= 0 or before.st_size > max_bytes:
            raise LabError("Source exceeds permitted size or is empty")
        with os.fdopen(os.open(dst, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600), "wb") as out:
            copied = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > max_bytes:
                    raise LabError("Source grew past permitted size")
                out.write(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ) or copied != before.st_size:
            raise LabError("Source changed while being copied")
        return copied
    finally:
        os.close(fd)


def prepare_workspace(workspace: Path, config: LabConfig, firmware: tuple[Path, Path], iso: Path | None, *, iso_sha256: str | None = None) -> dict[str, Path]:
    """Only call inside private TemporaryDirectory created by this process."""
    config.validate()
    if not workspace.is_dir() or workspace.is_symlink() or (workspace.stat().st_mode & 0o077):
        raise LabError("Refusing non-private workspace")
    if iso is not None and iso_sha256 is None:
        raise LabError("An ISO requires an independently supplied --iso-sha256 digest")
    if iso is None and iso_sha256 is not None:
        raise LabError("An ISO digest was supplied without an ISO path")
    p = workspace / "primary.raw"
    s = workspace / "secondary.raw"
    _exclusive_sparse_file(p, config.primary_bytes)
    _exclusive_sparse_file(s, config.secondary_bytes)
    v = workspace / "OVMF_VARS.fd"
    _copy_regular_file(firmware[1], v, max_bytes=32 * 1024 * 1024)
    tpm_state = workspace / "tpm-state"
    tpm_state.mkdir(mode=0o700)
    result = {"primary": p, "secondary": s, "vars": v, "tpm_dir": tpm_state, "tpm_sock": workspace / "tpm.sock", "qmp_sock": workspace / "qmp.sock"}
    if iso is not None:
        if iso_sha256 is None:
            raise LabError("An ISO requires an independently supplied --iso-sha256 digest")
        dst = workspace / "installer.iso"
        _copy_regular_file(iso, dst, max_bytes=ISO_MAX_BYTES)
        try:
            verify_arch_iso(dst, iso_sha256)
        except ISOValidationError as exc:
            raise LabError(f"Installer ISO verification failed: {exc}") from exc
        result["iso"] = dst
    return result


def command_lines(
    config: LabConfig,
    firmware: tuple[Path, Path],
    prepared: dict[str, Path],
    *,
    interactive: bool = False,
    network_mode: str = "disabled",
    observe_boot: bool = False,
) -> tuple[list[str], list[str]]:
    """Construct hard-coded QEMU options; no user-supplied QEMU options."""
    config.validate()
    if network_mode not in NETWORK_MODES:
        raise LabError("Unsupported network mode; choose disabled or explicit user-mode NAT")
    # Only accept previously generated canonical basenames under one workspace.
    folder = prepared["primary"].parent
    required = {"primary": "primary.raw", "secondary": "secondary.raw", "vars": "OVMF_VARS.fd", "tpm_dir": "tpm-state", "tpm_sock": "tpm.sock", "qmp_sock": "qmp.sock"}
    for name, basename in required.items():
        if prepared[name] != folder / basename:
            raise LabError(f"Unexpected {name} path")
    if "iso" in prepared and prepared["iso"] != folder / "installer.iso":
        raise LabError("Unexpected ISO path")
    # QEMU option-valued paths cannot contain argument separators.
    paths = [str(folder), str(firmware[0]), str(firmware[1])]
    if any(any(char in v for char in ",\n\r") for v in paths):
        raise LabError("Unsupported character in firmware or workspace path")
    tpm = [SWTPM, "socket", "--tpm2", "--tpmstate", f"dir={prepared['tpm_dir']}",
           "--ctrl", f"type=unixio,path={prepared['tpm_sock']}", "--flags", "startup-clear"]
    qemu = [QEMU, "-no-user-config", "-nodefaults", "-machine", "q35,accel=tcg",
            "-cpu", "max", "-m", str(config.ram_mib), "-smp", str(config.cpus),
            "-display", "vnc=127.0.0.1:0" if observe_boot else ("gtk" if interactive else "none"),
            "-monitor", "none", "-serial", "none",
            "-nic", "none" if network_mode == "disabled" else "user,model=virtio-net-pci",
            "-device", "VGA",
            "-qmp", f"unix:{prepared['qmp_sock']},server=on,wait=off",
            "-drive", f"if=pflash,format=raw,readonly=on,file={firmware[0]}",
            "-drive", f"if=pflash,format=raw,file={prepared['vars']}",
            "-blockdev", f"driver=file,node-name=primary_file,filename={prepared['primary']}",
            "-blockdev", "driver=raw,node-name=primary,file=primary_file",
            "-device", "virtio-blk-pci,drive=primary,serial=AEGIS-LAB-PRIMARY",
            "-blockdev", f"driver=file,node-name=secondary_file,filename={prepared['secondary']},read-only=on",
            "-blockdev", "driver=raw,node-name=secondary,file=secondary_file,read-only=on",
            "-device", "virtio-blk-pci,drive=secondary,serial=AEGIS-LAB-SECONDARY",
            "-chardev", f"socket,id=chrtpm,path={prepared['tpm_sock']}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
            "-device", "tpm-tis,tpmdev=tpm0"]
    if "iso" in prepared:
        # Explicitly boot the verified read-only installer medium before the blank target disk.
        qemu += ["-boot", "order=d",
                 "-drive", f"if=none,id=installer,media=cdrom,format=raw,readonly=on,file={prepared['iso']}",
                 "-device", "virtio-scsi-pci,id=scsi0",
                 "-device", "scsi-cd,bus=scsi0.0,drive=installer"]
    return tpm, qemu


def query_qmp(path: Path, screenshot_path: Path | None = None) -> dict[str, object]:
    """Ask QEMU whether it is running and optionally capture a guest display screenshot."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3.0)
        client.connect(str(path))
        with client.makefile("rwb") as stream:
            def receive() -> dict:
                for _ in range(16):
                    line = stream.readline(64 * 1024)
                    if not line:
                        raise LabError("QMP disconnected")
                    msg = json.loads(line)
                    if "error" in msg:
                        raise LabError("QMP command failed")
                    if "return" in msg or "QMP" in msg:
                        return msg
                raise LabError("QMP returned too many unexpected messages")

            hello = receive()
            if "QMP" not in hello:
                raise LabError("QMP greeting missing")
            def cmd(command: str, arguments: dict[str, object] | None = None) -> object:
                request: dict[str, object] = {"execute": command}
                if arguments is not None:
                    request["arguments"] = arguments
                stream.write(json.dumps(request).encode() + b"\n")
                stream.flush()
                msg = receive()
                if "return" not in msg:
                    raise LabError("QMP reply missing")
                return msg["return"]
            cmd("qmp_capabilities")
            status = cmd("query-status")
            tpm = cmd("query-tpm")
            if not isinstance(status, dict) or status.get("status") != "running":
                raise LabError("QEMU machine is not in running state")
            if not isinstance(tpm, list) or not any(x.get("id") == "tpm0" for x in tpm if isinstance(x, dict)):
                raise LabError("QEMU did not register virtual TPM")
            result: dict[str, object] = {"qmp_running": True, "qmp_tpm_detected": True}
            if screenshot_path is not None:
                cmd("screendump", {"filename": str(screenshot_path), "format": "png"})
                if not _regular_nonlink(screenshot_path) or screenshot_path.stat().st_size < 1024:
                    raise LabError("QEMU screenshot evidence is missing or unexpectedly small")
                result["screenshot_captured"] = True
            return result


def _finish(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def launch(
    config: LabConfig,
    iso: Path | None = None,
    *,
    iso_sha256: str | None = None,
    smoke: bool = True,
    network_mode: str = "disabled",
    observe_boot: bool = False,
    observe_live: bool = False,
    live_timeout_seconds: int = 120,
    popen: Callable[..., subprocess.Popen] = subprocess.Popen,
) -> dict[str, object]:
    """Launch the disposable VM; always clean up state and processes."""
    config.validate()
    if network_mode not in NETWORK_MODES:
        raise LabError("Unsupported network mode; choose disabled or explicit user-mode NAT")
    if (observe_boot or observe_live) and iso is None:
        raise LabError("Boot observation requires a verified Arch ISO")
    if (observe_boot or observe_live) and shutil.which("tesseract") is None:
        raise LabError("Boot observation requires Tesseract OCR; no boot claim will be made")
    if isinstance(live_timeout_seconds, bool) or not isinstance(live_timeout_seconds, int) or not 30 <= live_timeout_seconds <= 240:
        raise LabError("Live boot timeout must be an integer from 30 to 240 seconds")
    if observe_boot and observe_live:
        raise LabError("Choose boot-menu observation or live-environment observation, not both")
    if os.name != "posix" or os.geteuid() == 0:
        raise LabError("Run lab as a non-root Linux user")
    available = dependencies()
    if not all(available[k] for k in ("qemu_present", "swtpm_present", "ovmf_pair_present")):
        raise LabError("Install QEMU, swtpm and a matching OVMF code/vars pair first")
    firmware = find_firmware()
    assert firmware is not None
    # Use OS-controlled secure name generation, independent of TMPDIR overrides.
    with tempfile.TemporaryDirectory(prefix="aegis-lab-", dir="/tmp") as work:
        folder = Path(work)
        paths = prepare_workspace(folder, config, firmware, iso, iso_sha256=iso_sha256)
        tpm_args, vm_args = command_lines(config, firmware, paths, interactive=not smoke,
                                           network_mode=network_mode,
                                           observe_boot=(observe_boot or observe_live))
        tpm_proc = None
        vm_proc = None
        try:
            with (folder / "tpm.stderr").open("wb") as tpm_log, (folder / "qemu.stderr").open("wb") as vm_log:
                tpm_proc = popen(tpm_args, cwd=folder, stdout=subprocess.DEVNULL, stderr=tpm_log, stdin=subprocess.DEVNULL)
                deadline = time.monotonic() + 10
                while not paths["tpm_sock"].exists():
                    if tpm_proc.poll() is not None:
                        raise LabError("Software TPM exited before its socket was ready")
                    if time.monotonic() > deadline:
                        raise LabError("Software TPM did not create a socket")
                    time.sleep(.1)
                vm_proc = popen(vm_args, cwd=folder, stdout=subprocess.DEVNULL, stderr=vm_log, stdin=subprocess.DEVNULL)
                if smoke:
                    qmp_deadline = time.monotonic() + 10
                    while not paths["qmp_sock"].exists():
                        if vm_proc.poll() is not None:
                            raise LabError("QEMU exited before its QMP socket was ready")
                        if time.monotonic() > qmp_deadline:
                            raise LabError("QEMU did not create its QMP socket")
                        time.sleep(.1)
                    if observe_boot:
                        # Give OVMF and the ISO bootloader time to present the UEFI menu.
                        time.sleep(min(12.0, config.seconds / 2))
                        screenshot = folder / "boot-screen.png"
                        evidence = query_qmp(paths["qmp_sock"], screenshot)
                        try:
                            ocr = subprocess.run(
                                ["tesseract", str(screenshot), "stdout", "--psm", "6"],
                                check=True, capture_output=True, text=True, timeout=10,
                            ).stdout
                        except (OSError, subprocess.SubprocessError) as exc:
                            raise LabError("Boot screenshot OCR failed; guest boot remains unverified") from exc
                        normalized_ocr = " ".join(ocr.casefold().split())
                        boot_menu_detected = (
                            "arch linux" in normalized_ocr and "install medium" in normalized_ocr
                        )
                        evidence["arch_boot_menu_detected"] = boot_menu_detected
                        evidence["guest_boot_verified"] = boot_menu_detected
                        if not boot_menu_detected:
                            raise LabError("Verified ISO attached, but expected Arch UEFI boot-menu text was not detected")
                    elif observe_live:
                        # The live ISO may take over a minute to initialize under software emulation.
                        screenshot = folder / "live-screen.png"
                        deadline = time.monotonic() + live_timeout_seconds
                        attempts = 0
                        live_detected = False
                        while time.monotonic() < deadline:
                            attempts += 1
                            query_qmp(paths["qmp_sock"], screenshot)
                            try:
                                ocr = subprocess.run(
                                    ["tesseract", str(screenshot), "stdout", "--psm", "6"],
                                    check=True, capture_output=True, text=True, timeout=10,
                                ).stdout
                            except (OSError, subprocess.SubprocessError) as exc:
                                detail = getattr(exc, "stderr", None)
                                if isinstance(detail, bytes):
                                    detail = detail.decode("utf-8", errors="replace")
                                detail = " ".join(str(detail or "").split())[:240]
                                suffix = f": {detail}" if detail else f" ({type(exc).__name__})"
                                raise LabError("Live-environment screenshot OCR failed" + suffix + "; boot remains unverified") from exc
                            normalized_ocr = " ".join(ocr.casefold().split())
                            if "archiso" in normalized_ocr and "root" in normalized_ocr:
                                live_detected = True
                                break
                            if vm_proc.poll() is not None:
                                raise LabError("QEMU exited before the Arch live environment was detected")
                            time.sleep(3.0)
                        if not live_detected:
                            raise LabError("Arch live-environment prompt was not detected before timeout; boot remains unverified")
                        evidence = {
                            "qmp_running": True,
                            "qmp_tpm_detected": True,
                            "screenshot_captured": True,
                            "live_environment_detected": True,
                            "live_environment_marker": "archiso-and-root-prompt",
                            "boot_ocr_attempts": attempts,
                            "guest_boot_verified": True,
                        }
                    else:
                        evidence = query_qmp(paths["qmp_sock"])
                    deadline = time.monotonic() + config.seconds
                    while time.monotonic() < deadline:
                        if vm_proc.poll() is not None:
                            raise LabError("QEMU exited before the launch smoke interval completed")
                        time.sleep(min(.1, max(.001, deadline - time.monotonic())))
                    if vm_proc.poll() is not None:
                        raise LabError("QEMU exited during launch smoke interval")
                    return {"status": ("LIVE_ENVIRONMENT_DETECTED" if observe_live else ("BOOT_MENU_DETECTED" if observe_boot else "LAUNCH_SMOKE_PASSED")),
                            "seconds": config.seconds,
                            "live_timeout_seconds": live_timeout_seconds if observe_live else None,
                            "guest_boot_verified": bool((observe_boot and evidence.get("arch_boot_menu_detected")) or (observe_live and evidence.get("live_environment_detected"))),
                            "installation_performed": False,
                            "network_mode": network_mode,
                            "guest_network_enabled": network_mode == "user-nat-explicit",
                            "inbound_port_forwarding_enabled": False,
                            "guest_disks": 2, "virtual_tpm_requested": True, **evidence}
                rc = vm_proc.wait()
                return {"status": "VM_EXITED", "exit_code": rc, "guest_boot_verified": False,
                        "installation_performed": False, "network_mode": network_mode,
                        "guest_network_enabled": network_mode == "user-nat-explicit",
                        "inbound_port_forwarding_enabled": False}
        except (LabError, OSError) as exc:
            # Preserve bounded emulator diagnostics before TemporaryDirectory cleanup.
            # These logs contain emulator errors, not credentials or user secrets.
            details = []
            for name in ("qemu.stderr", "tpm.stderr"):
                try:
                    detail = (folder / name).read_text(encoding="utf-8", errors="replace").strip()
                except OSError:
                    continue
                if detail:
                    details.append(f"{name}: {detail[-1200:]}")
            if details:
                raise LabError(f"{exc}; emulator diagnostics: {' | '.join(details)}") from exc
            if isinstance(exc, LabError):
                raise
            raise LabError(f"Virtual lab launch failed: {exc}") from exc
        finally:
            _finish(vm_proc)
            _finish(tpm_proc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AEGIS isolated disposable virtual-machine lab (no Arch installer)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="inspect installed lab dependencies; no changes")
    group.add_argument("--smoke", action="store_true", help="launch UEFI/TPM virtual machine for a short time")
    group.add_argument("--run", action="store_true", help="start interactive VM; Ctrl+C cleans up disposable state")
    parser.add_argument("--observe-boot", action="store_true",
                        help="capture loopback-only VNC screenshot and verify Arch UEFI boot-menu text with OCR")
    parser.add_argument("--observe-live", action="store_true",
                        help="wait for an Arch live-environment root prompt using screenshot OCR (requires verified ISO)")
    parser.add_argument("--live-timeout-seconds", type=int, default=120,
                        help="live environment observation timeout (30–240 seconds)")
    parser.add_argument("--iso", type=Path, help="optional local Arch ISO to verify and copy into private lab")
    parser.add_argument("--iso-sha256", help="expected SHA-256 from an independently trusted Arch download/checksum source")
    parser.add_argument("--network-mode", choices=sorted(NETWORK_MODES), default="disabled",
                        help="disabled by default; user-nat-explicit enables outbound guest NAT without port forwarding")
    parser.add_argument("--seconds", type=float, default=20.0 if "--observe-boot" in (argv if argv is not None else sys.argv[1:]) else 5.0,
                        help="smoke interval (1–30 seconds; boot observation defaults to 20)")
    parser.add_argument("--ram-mib", type=int, default=2048)
    parser.add_argument("--cpus", type=int, default=2)
    args = parser.parse_args(argv)
    if (args.observe_boot or args.observe_live) and not args.smoke:
        print("AEGIS lab refused: boot observation must be paired with --smoke.", file=sys.stderr)
        return 2
    if args.observe_boot and args.observe_live:
        print("AEGIS lab refused: choose only one boot observation mode.", file=sys.stderr)
        return 2
    if args.check:
        print(json.dumps(dependencies(), indent=2, sort_keys=True))
        return 0
    if args.iso is not None and args.iso_sha256 is None:
        print("AEGIS lab refused: --iso requires --iso-sha256 from an independently trusted source.", file=sys.stderr)
        return 2
    if args.iso is None and args.iso_sha256 is not None:
        print("AEGIS lab refused: --iso-sha256 requires --iso.", file=sys.stderr)
        return 2
    try:
        result = launch(LabConfig(ram_mib=args.ram_mib, cpus=args.cpus, seconds=args.seconds),
                        args.iso, iso_sha256=args.iso_sha256, smoke=args.smoke,
                        network_mode=args.network_mode, observe_boot=args.observe_boot,
                        observe_live=args.observe_live, live_timeout_seconds=args.live_timeout_seconds)
    except (LabError, OSError) as exc:
        print(f"AEGIS lab refused/failed: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("AEGIS lab interrupted; disposable workspace cleaned up.", file=sys.stderr)
        return 130
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if args.smoke or args.observe_boot or args.observe_live or result.get("exit_code") == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
