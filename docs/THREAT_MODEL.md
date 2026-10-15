# Preliminary threat model (review required)

## Protect against

- Accidental selection or deletion of the wrong disk.
- Malicious modification of unsigned boot components.
- Disclosure of disk keys, recovery credentials and installation logs.
- Physical theft of a powered-off computer.
- Untrusted network inputs, unsigned downloads and spoofed update artifacts.
- Remote lockout from unsafe firewall changes.
- Unreliable upgrades that break encrypted boot or driver availability.

## Limits

- An unlocked and fully compromised root account can bypass many controls.
- TPM + PIN does not replace offline encrypted backups.
- Btrfs snapshots do not replace independent backups.
- Antivirus cannot guarantee detection of all malware.
- Secure Boot enrollment varies widely by firmware platform.
- Safe rollback of partition rewrites is not guaranteed.

## Non-negotiable engineering controls for a future executor

- Device identity bound to serial/WWN/major-minor and rechecked before writes.
- Explicit per-device authorization, with a last-mile confirmation barrier.
- Installation media exclusion, mounted-volume and filesystem/RAID checks.
- Clearly identified destructive operations; no implicit secondary wipes.
- Backup verification and safe handling of recovery secrets.
- Reject unsupported, ambiguous or unvalidated configurations.
- Automated virtual-disk and virtual-TPM tests; independent review.
