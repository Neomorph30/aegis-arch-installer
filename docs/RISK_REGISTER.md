# Risk register — preliminary and intentionally conservative

Scales: Likelihood (L) and Impact (I), 1 low–5 high; simple L × I ranking
prioritizes effort but is not a proof of residual safety. Risks remain OPEN
until evidence and independent review close them.

| ID | Threat / failure mode | L | I | Minimum mitigation / test | Status |
|---|---|---:|---:|---|---|
| R01 | Wrong disk selected, installation USB overwritten | 3 | 5 | Stable identity and active-holder revalidation; per-disk consent; VM fault injection | Open |
| R02 | Lost root or secondary LUKS key | 3 | 5 | Independent offline recovery, header backups, verified unlock drills | Open |
| R03 | TPM policy change bricks boot | 4 | 4 | Signed UKI PCR policy and recoverable passphrase fallback | Open |
| R04 | Privileged executor accepts malicious plan | 3 | 5 | Typed allowlist, separate privilege boundary, hostile-input tests | Open |
| R05 | Install fails midway / power loss | 4 | 4 | Idempotent journal, safe resume, documented recovery, interruption tests | Open |
| R06 | Installer supply-chain compromise | 3 | 5 | Pinned CI, reproducible and signed ISO/releases, no inline remote scripts | Open |
| R07 | Secret disclosed via logs/HTML/JSON | 3 | 5 | No credential collection unless essential, redaction and seeded leak tests | Open |
| R08 | Firewall locks out SSH / remote management | 3 | 4 | Existing-flow preservation, temporary rules, watchdog rollback | Open |
| R09 | Gaming optimizations weaken security/stability | 3 | 3 | Conservative reversible profiles, benchmark and rollback gates | Open |
| R10 | Wrong hardware inference produces broken system | 4 | 4 | Capability qualification, explicit unsupported state, kernel fallback | Open |
| R11 | Malicious fixture or huge JSON causes denial of service | 3 | 3 | Input size/depth limits, typed constraints and fuzz tests | Open |
| R12 | Public reports expose hardware/private identifiers | 3 | 3 | Private local reports, shareable redaction, automated regression tests | Open |
| R13 | Network verification misdiagnoses captive portal/TLS/DNS | 4 | 2 | Never equate failed HTTPS with confirmed offline; offer manual diagnosis | Partially mitigated |
| R14 | Unsafe biometric PAM change prevents login | 3 | 4 | Keep password fallback, test sensor loss and screen/SDDM separation | Open |

Highest-priority engineering risks before physical disk writes: R01–R07.
A green preview CI does not reduce their severity without actual VM/hardware
and recovery evidence.
