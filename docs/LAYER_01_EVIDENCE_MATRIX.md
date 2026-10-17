# Layer 01 requirement-to-evidence matrix

**Review baseline:** PR head `95e758bffbab5b84b1643fb76d2eaf010ed8c16b`, 2026-10-17  
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
| AEGIS-SEC-008 | before_public_release | PARTIAL | `aegis/assurance.py`, `aegis/reporting.py`, `tests/test_assurance.py`, `tests/test_safety.py`, `tests/test_cli_integration.py`; Preview Safety and Unit Tests passed on PR head `95e758bffbab5b84b1643fb76d2eaf010ed8c16b` across Python 3.11–3.13: https://github.com/Neomorph30/aegis-arch-installer/actions/runs/39061556381. Disposable Arch live-boot verification on the same head passed: https://github.com/Neomorph30/aegis-arch-installer/actions/runs/39061556442. The current workflow disables guest networking and confirms read-only preflight; this does not verify installation, encryption or recovery. | **OPEN — BASELINE ASSURANCE.** Proposal HTML rejects missing/malformed evidence and forged PASSED/unknown states; this is not yet a unified installed-system status contract. Expanded JSON/HTML parity tests include malformed, missing and contradictory evidence plus CLI output-creation refusal. CI passed on the cited head; broader installed-system verification remains open. |
| AEGIS-SEC-009 | before_public_release | NOT_IMPLEMENTED | `docs/RELEASE_GATES.md`; no firewall policy executor | **DEFERRED — RELEASE GATE.** Do not implement live firewall changes until remote-lockout, IPv6/DHCP/DNS and rollback evidence exists. |
| AEGIS-SEC-010 | before_public_release | NOT_IMPLEMENTED | `aegis/assurance.py`; optimization is declared preview-only | **DEFERRED — RELEASE GATE.** No tuning executor is shipped. Require benchmark/regression comparisons and rollback proof before enabling changes. |
| AEGIS-SEC-011 | pre_alpha | PARTIAL | `aegis/reporting.py`, `tests/test_safety.py`, `tests/test_cli_integration.py`; Preview Safety and Unit Tests passed on PR head `95e758bffbab5b84b1643fb76d2eaf010ed8c16b` across Python 3.11–3.13: https://github.com/Neomorph30/aegis-arch-installer/actions/runs/39061556381. Seeded tests cover shareable JSON/HTML, quoted credential and multiline PEM canaries, and CLI report paths. This confirms the current suite passed, not that every possible output path is covered. | **OPEN — LAYER 01.** Redaction remains defence-in-depth, not a guarantee. Still test local-file permissions/failure paths; prefer preventing secret ingestion over relying on redaction. |
| AEGIS-SEC-012 | before_public_release | NOT_IMPLEMENTED | `aegis/assurance.py` explicitly sets `security_certification=false` and external review `NOT_COMPLETED`; `docs/RELEASE_GATES.md` | **BASELINE CLAIM CURRENTLY FAIL-CLOSED; RELEASE EVIDENCE OPEN.** Preserve the explicit non-certified state. Before public-ready claims, require independent signoff and linked, immutable evidence for recovery and supported-hardware qualification. |

## Layer 01 exit checklist

- [x] Versioned security requirements exist and have unique IDs.
- [x] Threat model, risk register, support matrix, quality standards and release gates exist.
- [x] Preview CI runs the static guardrail, unit tests, compilation and CLI smoke checks on Python 3.11–3.13.
- [x] Current assurance manifest explicitly says installation is disabled and security certification is false.
- [x] Close AEGIS-SEC-006's noninteractive consent regression test: noninteractive `network --connect` fails closed without launching interactive setup. CI passed on commit `10b9a1eea4cf38840fdf7f1d84115b08181318d2`: https://github.com/Neomorph30/aegis-arch-installer/actions/runs/39014787332. Broader independent network-boundary review remains open.
- [x] Added quoted credential and multiline PEM canaries to public JSON/HTML and CLI report tests; malformed-report CLI tests also pass on commit `10b9a1eea4cf38840fdf7f1d84115b08181318d2`: https://github.com/Neomorph30/aegis-arch-installer/actions/runs/39014787332. Full secret-leakage coverage across every output/error path remains open.
- [x] Malformed/contradictory CLI evidence cases and report-output refusal tests passed on commit `10b9a1eea4cf38840fdf7f1d84115b08181318d2`: https://github.com/Neomorph30/aegis-arch-installer/actions/runs/39014787332. A unified installed-system status contract remains open.
- [x] Reconcile the current report/secret-handling evidence links with the passing preview regression run; this does not close the remaining coverage gaps.
- [ ] Obtain independent technical review of the code, threat model and guardrails before any privileged executor is introduced.

## Evidence rules

1. Link exact commit SHAs, CI run/job URLs and test names when recording a passed item; never write "verified" based only on a document claim.
2. A skipped or unrun test is **UNVERIFIED**, not PASSED.
3. Keep future release gates open until the actual feature exists and the required evidence is attached.
4. This matrix does not grant permission for physical disk writes, firmware changes, TPM enrollment or live firewall changes.
