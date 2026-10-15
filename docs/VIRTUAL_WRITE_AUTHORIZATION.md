# Disposable-VM write authorization gate

## Current state

**No installer disk writer is enabled.** `lab/guest_storage_gate.py` is a pure
validation contract. It never opens a device, invokes a command, partitions,
formats or encrypts anything. Its success result means only
`ELIGIBLE_FOR_SEPARATE_EXPLICIT_LAB_CONSENT`; `write_authorized` remains
`false`.

The host lab currently creates two exclusive regular-file-backed virtual disks:
a 24 GiB primary and an 8 GiB secondary attached read-only. It disables guest
networking and does not expose host USB, host filesystems or a host block-device
path. The QEMU process is still not a formally hardened sandbox.

## Mandatory gates before enabling any guest write

1. **Host boundary:** independently review QEMU arguments and prove there is no
   block-device, USB, directory, network or other host passthrough path. Only
   process-created regular files in the private temporary workspace may be
   attached. Reject unexpected QEMU arguments and disk count.
2. **Guest identity:** observe exactly two root block disks. Require the primary
   serial `AEGIS-LAB-PRIMARY` and exact 24 GiB capacity; require the secondary
   serial `AEGIS-LAB-SECONDARY`, exact 8 GiB capacity and read-only state.
   Refuse extra/missing disks, duplicate paths, missing child topology, unstable
   identity, removable targets, read-only primary, mounted descendants, holders,
   active or unknown swap, and ambiguous states.
3. **Fresh revalidation:** repeat inventory and stable identity checks inside the
   guest immediately before every mutating storage step. A stale plan or changed
   major/minor, serial, WWN, capacity, partition tree or mount/holder state
   invalidates authorization.
4. **Explicit one-use consent:** show the exact target serial, capacity, current
   partition map and all planned destructive operations. Require a separate,
   non-reusable confirmation bound to the plan digest and primary serial. No
   consent flag may be stored in an editable plan file.
5. **Transaction and recovery:** test interruption after each step, process
   termination, simulated power loss, partial GPT writes, LUKS header backup,
   offline recovery credential export, unlock failure and full rollback/rebuild
   from the disposable workspace. Never log PINs, passphrases or recovery keys.
6. **Verification:** independently inspect the final GPT, EFI filesystem, LUKS2
   metadata, Btrfs/ext4 layout, boot files and guest boot. Reports must separate
   PASSED, FAILED, WARNING, SKIPPED and UNVERIFIED; exit status alone is not proof.
7. **Review:** run the full CI matrix and the actual QEMU/OVMF/swtpm workflow on
   the exact commit; obtain independent review of the executor and fault-injection
   evidence before enabling the guest writer.

## Physical-device boundary

This gate is **not** permission for physical-device writes. The host application
must not grow a general block-device writer as a side effect of the VM work.
Physical installation remains disabled until the separate physical-device gates
in `RELEASE_GATES.md` are independently reviewed and satisfied.

## Current evidence and limits

Unit tests for the pure gate use synthetic JSON only and never open block devices.
The existing QEMU smoke test proves launch and virtual TPM registration, not guest
boot, Arch installation, encryption, or recovery. A successful preflight result
must never be described as an installation or write authorization.
