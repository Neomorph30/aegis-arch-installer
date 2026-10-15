# Engineering quality and release standards — Layer 01

## Scope and review

AEGIS is *not* currently an installer. The read-only boundary is enforced
through module separation, explicit subprocess argument allowlists, a narrow
AST static regression checker and unit tests. These are detection measures,
**not a sandbox or complete security proof**. All contributors must review code.

### Mandatory for every pull request

1. The change has a clear purpose, scoped affected modules, and an issue or
   documented requirement it addresses.
2. Unit and integration tests cover success, error and cancellation paths.
   Security-sensitive changes also test malicious and corrupted inputs.
3. Preview-only source must pass `python tools/security_lint.py`. No system
   installation, partition-formatting or privileged executor code is allowed.
4. `python -m unittest discover -s tests -v`, source compilation, fixture CLI
   smoke checks and CI's Python 3.11/3.12/3.13 matrix must pass.
5. Negative cases fail closed and have useful, redacted messages. Do not record
   credentials, recovery keys, signing keys or privileged environment data.
6. Update the threat model, requirements, support matrix and recovery notes
   if the change affects a trust boundary.
7. Attach test evidence. A reviewer must inspect the diff and unresolved
   warnings before merging. A green CI result alone is never a security audit.

### Security-sensitive code review expectations

- Separate untrusted input, observation, pure plan, human approval, and a future
  executor. Never accept executable shell fragments in plans.
- Use explicit argument vectors; no shell interpolation or process environment
  leaks. Subprocess use remains limited to reviewed hardware/network modules.
- Redaction is not enough to justify collecting secrets; avoid ingesting
  secrets into application data entirely where possible.
- Firmware/TPM, encrypted storage and Secure Boot operations require an
  independently reviewed privilege boundary, disposable VM evidence and a
  verified recovery path *before* enabling the operation on physical disks.
- Check upstream archiso/systemd/cryptsetup/pacman documentation at the time of
  implementation; do not rely on guessed commands or stale assumptions.

### Supply-chain controls

- GitHub Actions use read-only permissions, SHA-pinned upstream actions, short
  timeouts and no persistent checkout credentials.
- The current package has **no runtime third-party Python dependencies**.
  Python build tooling still comes from packaging infrastructure and is not
  hermetically pinned; reproducible builds and signed releases remain a future
  release blocker.
- No untrusted `curl | sh` bootstrap; verify downloaded installer packages
  using published, trusted release signatures before production use.
- Review changes to CI workflows, toolchain configuration and package metadata
  as supply-chain sensitive.
- Treat inbound PR code as untrusted; do not expose production secrets to PR jobs.

### Exit gate for Layer 01

Engineering implementation is finished when requirements, support scope, risk
register, documented threat model, executable guardrails, tests and CI are
merged and passing. **Independent third-party security audit remains OPEN**.
The project is not certified production-ready on completion of this layer.

### How to run

```bash
python tools/security_lint.py
python -m unittest discover -s tests -v
python -m compileall -q aegis tests tools
python -m aegis assurance --json
```
