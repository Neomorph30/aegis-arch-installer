# AEGIS report contract

## Preview 0.2

- JSON *proposals* use `status=PROPOSAL_ONLY`, `execution_enabled=false`,
  `review_state`, blockers, warnings and proposed exact byte-offset partitions.
- HTML reports identify all boot/encryption/security changes as **NOT EXECUTED**.
- Shared HTML defaults to redacting disk serial, WWN and selected identifiers.
- Local JSON files and private HTML can contain hardware serial numbers and
  must never be uploaded publicly without additional review.
- All files are exclusively created with mode 0600; no silent overwrite.
- Redaction is defence-in-depth. **Never include credentials in input JSON.**

## Required post-install report for a future release

1. Actual hardware identifiers and firmware capabilities (private local copy).
2. Original and final storage maps, encryption metadata (no secret keys).
3. Boot verification, TPM policy, key enrollment and offline recovery evidence.
4. Kernel versions, drivers, package sources and installed applications.
5. Firewall rules, remote-management preservation and connectivity checks.
6. Malware signatures/scanning policy, AppArmor and security-update state.
7. Optimization baselines, changes, measurements and reversible rollbacks.
8. Explicit failed, skipped, unsupported and pending verification operations.
9. Tested recovery procedures, external backup status and next steps.

Allowed validation states: `PASSED`, `FAILED`, `WARNING`, `SKIPPED`,
`UNVERIFIED`, `NOT_APPLICABLE`. A command exit code of zero alone is never
adequate evidence of a successful security control. A machine is never
reported as fully secure based on a single score or superficial test.
