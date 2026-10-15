# Contributing to AEGIS

AEGIS is not currently an installer: the public development preview can only
inspect and propose. Thank you for helping keep its safety boundary clear.

1. Open an issue describing a bug, test fixture or documentation improvement.
2. Add failing tests first. Prefer a fictional `lsblk` JSON fixture over
   touching real hardware; never upload actual recovery credentials.
3. Keep changes within read-only interfaces and use static command arguments.
4. Run `python tools/security_lint.py`, `python -m unittest discover -s tests -v`,
   and `python -m compileall -q aegis tests tools` before proposing a PR.
   CI is pinned to reviewed GitHub Action commits and runs Python 3.11–3.13.
   See `docs/QUALITY_STANDARDS.md` for the required failure-path test evidence.
5. Document unsupported devices rather than making unverified compatibility claims.
6. Do **not** add a partitioning or encryption executor to the main branch.
   Such work requires separate threat-model review and disposable-VM evidence.

Contributor code is expected to follow the MIT licence included in this project.
Do not include copyrighted third-party source code or binary firmware in PRs.
