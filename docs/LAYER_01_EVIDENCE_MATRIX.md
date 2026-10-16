# Layer 01 requirement-to-evidence matrix

**Review baseline:** branch `layer-03-inventory-validation-hardening`, 2026-10-16  
**Decision:** Layer 01 remains **AMBER / NOT EXITED**. This matrix is a review aid, not an audit certificate. A status is not green merely because a requirement is documented or CI passes.

## Status meanings

- **EVIDENCED (preview boundary only):** implementation and automated tests support the narrowly stated preview claim.
- **OPEN — LAYER 01:** required engineering evidence is missing or the current requirement is marked partial/unqualified.
- **DEFERRED — RELEASE GATE:** deliberately not implemented in the non-destructive preview; the named gate must block activation/release until evidence exists.
- **EXTERNAL REVIEW:** cannot be self-approved by the project author or CI.

## Requirement traceability

| ID | Gate | Declared implementation | Evidence currently present | Assessment / acceptance needed |
|---|---|---|---|---|
| AEGIS-SEC-001 | before_physical_install | NOT_IMPLEMENTED | `docs/RELEASE_GATES.md`; no executor is shipped | **DEFERRED — RELEASE GATE.** Keep all write paths absent. Before physical install, provide host-exclusion, identity-swap and active-holder fault-injection evidence. |
| AEGIS-SEC-002 | before_physical_install | NOT_IMPLEMENTED | `docs/RELEASE_GATES.md`; no destructive execution path | **DEFERRED — RELEASE GATE.** Before execution, prove one-use per-target consent and test bypass attempts. |
| AEGIS-SEC-003 | before_virtual_executor | NOT_IMPLEMENTED | `docs/THREAT_MODEL.md`; preview static guard in `tools/security_lint.py` | **DEFERRED — EXECUTOR GATE.** A static checker is not privilege isolation. Independent API/boundary review and hostile-plan tests required before any executor. |
| AEGIS-SEC-004 | before_physical_install | NOT_IMPLEMENTED | `docs/RELEASE_GATES.md`; no encryption executor | **DEFERRED — RELEASE GATE.** Require recovery drills, crash tests and secret-safe evidence before enabling. |
| AEGIS-SEC-005 | before_physical_install | NOT_IMPLEMENTED | `docs/THREAT_MODEL.md`; no trusted-boot executor | **DEFERRED — RELEASE GATE.** Require signed-boot tamper, update, PCR mismatch and TPM-loss recovery evidence. |
| AEGIS-SEC-006 | pre_alpha | PREVIEW_IMPLEMENTED_UNQUALIFIED | `aegis/network.py`, `tests/test_network.py`, `docs/SUPPORT_MATRIX.md` | **OPEN — LAYER 01.** Review every live-network subprocess and consent boundary; add/verify consent-bypass, cancellation, error and secret non-disclosure tests. State precisely which network changes are possible. Do not claim hardware qualification. |
| AEGIS-SEC-007 | before_public_release | PARTIAL | `.github/workflows/test.yml`, `tools/security_lint.py`, `docs/QUALITY_STANDARDS.md` | **DEFERRED — RELEASE GATE, with baseline controls evidenced.** Actions are SHA-pinned and CI permissions are read-only; reproducible builds and signed distribution are not complete. Require provenance, dependency/build controls, reproducibility and signature-verification evidence before public release. |
| AEGIS-SEC-008 | before_public_release | PARTIAL | `aegis/assurance.py`, `aegis/reporting.py`, `tests/test_assurance.py`, `tests/test_safety.py`; preview CI on commit `d0af98acc4c2459c311aa16edd64deeddef9e413` passed Python 3.11–3.13: https://github.com/Neomorph30/aegis-arch-installer/actions/runs/38891750318 | **OPEN — BASELINE ASSURANCE.** Proposal HTML rejects missing/malformed evidence and forged PASSED/unknown states; this is not yet a unified installed-system status contract. Add explicit JSON/HTML parity tests and test contradictory/malformed evidence across CLI and report paths. |
| AEGIS-SEC-009 | before_public_release | NOT_IMPLEMENTED | `docs/RELEASE_GATES.md`; no firewall policy executor | **DEFERRED — RELEASE GATE.** Do not implement live firewall changes until remote-lockout, IPv6/DHCP/DNS and rollback evidence exists. |
| AEGIS-SEC-010 | before_public_release | NOT_IMPLEMENTED | `aegis/assurance.py`; optimization is declared preview-only | **DEFERRED — RELEASE GATE.** No tuning executor is shipped. Require benchmark/regression comparisons and rollback proof before enabling changes. |
| AEGIS-SEC-011 | pre_alpha | PARTIAL | `aegis/reporting.py`, `tests/test_safety.py`; seeded-secret regression suite passed in Python 3.11–3.13 on commit `d0af98acc4c2459c311aa16edd64deeddef9e413`: https://github.com/Neomorph30/aegis-arch-installer/actions/runs/38891750318 | **OPEN — LAYER 01.** Seeded tests cover shareable JSON/HTML and compound free-text assignments, including `luks_recovery_key`. Redaction remains defence-in-depth, not a guarantee. Still test exception/CLI output and local-file permissions/failure paths; prefer preventing secret ingestion over relying on redaction. |
| AEGIS-SEC-012 | before_public_release | NOT_IMPLEMENTED | `aegis/assurance.py` explicitly sets `security_certification=false` and external review `NOT_COMPLETED`; `docs/RELEASE_GATES.md` | **BASELINE CLAIM CURRENTLY FAIL-CLOSED; RELEASE EVIDENCE OPEN.** Preserve the explicit non-certified state. Before public-ready claims, require independent signoff and linked, immutable evidence for recovery and supported-hardware qualification. |

## Layer 01 exit checklist

- [x] Versioned security requirements exist and have unique IDs.
- [x] Threat model, risk register, support matrix, quality standards and release gates exist.
- [x] Preview CI runs the static guardrail, unit tests, compilation and CLI smoke checks on Python 3.11–3.13.
- [x] Current assurance manifest explicitly says installation is disabled and security certification is false.
- [ ] Close AEGIS-SEC-006's pre-alpha consent/network-boundary evidence gap.
- [ ] Close AEGIS-SEC-011's seeded-secret leakage evidence gap for every report/output path.
- [ ] Close AEGIS-SEC-008's structured status contract and JSON/HTML parity tests.
- [ ] Reconcile each status in this matrix against current test names and CI run links; update the matrix whenever implementation changes.
- [ ] Obtain independent technical review of the code, threat model and guardrails before any privileged executor is introduced.

## Evidence rules

1. Link exact commit SHAs, CI run/job URLs and test names when recording a passed item; never write "verified" based only on a document claim.
2. A skipped or unrun test is **UNVERIFIED**, not PASSED.
3. Keep future release gates open until the actual feature exists and the required evidence is attached.
4. This matrix does not grant permission for physical disk writes, firmware changes, TPM enrollment or live firewall changes.
