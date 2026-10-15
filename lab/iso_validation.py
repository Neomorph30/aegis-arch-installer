"""Strict, read-only integrity check for a local Arch Linux ISO."""
from __future__ import annotations

import hashlib
import hmac
import re
import stat
from pathlib import Path


class ISOValidationError(ValueError):
    """The ISO cannot be trusted for the disposable guest boot."""


SECTOR_SIZE = 2048
PRIMARY_VOLUME_DESCRIPTOR_OFFSET = 16 * SECTOR_SIZE
MIN_ARCH_ISO_BYTES = 100 * 1024**2
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def verify_arch_iso(
    path: str | Path,
    expected_sha256: str,
    *,
    min_size: int = MIN_ARCH_ISO_BYTES,
) -> dict[str, object]:
    """Verify file type, ISO9660 PVD, Arch volume label and caller-pinned SHA-256."""
    if not isinstance(expected_sha256, str) or not SHA256_PATTERN.fullmatch(expected_sha256):
        raise ISOValidationError("Expected SHA-256 must be exactly 64 hexadecimal characters")
    if isinstance(min_size, bool) or not isinstance(min_size, int) or min_size < 1:
        raise ISOValidationError("Minimum ISO size is invalid")
    source = Path(path)
    # Open once with no-follow semantics; all checks use the same file descriptor.
    import os
    try:
        raw_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise ISOValidationError("ISO must be a readable regular file, not a symlink or device") from exc
    try:
        before = os.fstat(raw_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ISOValidationError("ISO must be a single-link regular file")
        if before.st_size < max(min_size, PRIMARY_VOLUME_DESCRIPTOR_OFFSET + SECTOR_SIZE):
            raise ISOValidationError("ISO is too small or lacks an ISO9660 primary volume descriptor")
        os.lseek(raw_fd, PRIMARY_VOLUME_DESCRIPTOR_OFFSET, os.SEEK_SET)
        descriptor = os.read(raw_fd, SECTOR_SIZE)
        if len(descriptor) != SECTOR_SIZE or descriptor[0] != 1 or descriptor[1:6] != b"CD001" or descriptor[6] != 1:
            raise ISOValidationError("ISO9660 primary volume descriptor is missing or malformed")
        label = descriptor[40:72].decode("ascii", errors="replace").strip(" \x00")
        if not label.upper().startswith("ARCH_"):
            raise ISOValidationError("ISO volume label is not an expected Arch Linux installation image")
        os.lseek(raw_fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(raw_fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        after = os.fstat(raw_fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ) or total != before.st_size:
            raise ISOValidationError("ISO changed during integrity verification; retry with a stable local file")
        actual = digest.hexdigest()
        if not hmac.compare_digest(actual, expected_sha256.lower()):
            raise ISOValidationError("ISO SHA-256 does not match the independently supplied expected digest")
        return {"verified": True, "size_bytes": total, "sha256": actual, "volume_label": label}
    finally:
        os.close(raw_fd)
