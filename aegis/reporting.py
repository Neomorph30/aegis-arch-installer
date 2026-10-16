"""Reports for proposals, not assertions that installation/security passed."""

from __future__ import annotations

from html import escape
from typing import Any
import json
import re

# Compare normalized names so common separator variants (tpm-pin, tpm pin,
# private-key, etc.) receive the same treatment.
REDACT_TERMS = {
    "password", "passphrase", "secret", "credential", "keyfile",
    "recoverykey", "luksrecoverykey", "tpmpin", "token", "privatekey",
    "apikey",
}
IDENTIFIER_TERMS = {"serial", "wwn", "partuuid", "uuid", "macaddress"}
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passphrase|secret|credential|keyfile|token|"
    r"recovery[_-]?key|tpm[_-]?pin|private[_-]?key|api[_-]?key)"
    r"\s*([=:])\s*([^\s,;]+)"
)


def public_view(value: Any, *, shareable: bool = False) -> Any:
    """Redact key-named secrets; additionally remove identifiers in shared copies.

    This is defence-in-depth, not a guarantee that arbitrary input contains no
    secrets. The planner never accepts secrets. Don't paste private text into
    report inputs. Local JSON files are created mode 0600.
    """
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            lower = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if any(term in lower for term in REDACT_TERMS) or (shareable and lower in IDENTIFIER_TERMS):
                result[str(key)] = "[REDACTED]"
            else:
                result[str(key)] = public_view(item, shareable=shareable)
        return result
    if isinstance(value, list):
        return [public_view(v, shareable=shareable) for v in value]
    if isinstance(value, str):
        return SECRET_ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", value)
    return value


def html_report(plan: dict[str, Any], *, shareable: bool = True) -> str:
    if not isinstance(plan, dict) or plan.get("status") != "PROPOSAL_ONLY" or plan.get("execution_enabled") is not False:
        raise ValueError("Refusing report: input is not a non-executable AEGIS proposal")
    clean = public_view(plan, shareable=shareable)
    actions = "\n".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            escape(str(x.get("target", ""))),
            escape(str(x.get("action", ""))),
            "YES" if x.get("destructive") else "No",
            escape(str(x.get("description", ""))),
        ) for x in clean.get("actions", []) if isinstance(x, dict)
    )
    warnings = "\n".join(f"<li>{escape(str(w))}</li>" for w in clean.get("warnings", []))
    blockers = "\n".join(f"<li>{escape(str(w))}</li>" for w in clean.get("blockers", []))
    checks = "\n".join(
        "<tr><td>{}</td><td>{}</td></tr>".format(escape(str(t.get("name", ""))),
                                                      escape(str(t.get("result", ""))))
        for t in clean.get("tests", []) if isinstance(t, dict)
    )
    raw = escape(json.dumps(clean, indent=2, ensure_ascii=False))
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>AEGIS read-only installation proposal</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:1000px;margin:2.5em auto;padding:0 1.2em;color:#1b2531}}
header{{border-bottom:3px solid #166b60;padding-bottom:1em}}.banner{{padding:1em;background:#fff2dc;border-left:5px solid #bd7300}}
table{{border-collapse:collapse;width:100%}}td,th{{padding:.7em;text-align:left;border-bottom:1px solid #ddd;vertical-align:top}}
pre{{padding:1em;background:#f2f5f8;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-word}}
.blockers{{border-left:4px solid #b43838;padding-left:1em}}.muted{{color:#536071}}
</style></head><body>
<header><h1>AEGIS — installation planning report</h1><p>Developer preview • proposal only • {escape(str(clean.get('created_utc', '')))}</p></header>
<p class="banner"><strong>NO INSTALLATION HAS TAKEN PLACE.</strong> Proposed actions, encryption,
Secure Boot, TPM, recovery, firewall and gaming configuration are <strong>NOT EXECUTED OR VERIFIED</strong>.</p>
<p><strong>Storage review state:</strong> {escape(str(clean.get('review_state', 'UNVERIFIED')))}</p>
<h2>Proposed storage actions</h2><table><thead><tr><th>Device</th><th>Action</th><th>Destructive</th><th>Description</th></tr></thead>
<tbody>{actions}</tbody></table>
<h2>Safety blockers</h2><div class="blockers"><ul>{blockers if blockers else '<li>None flagged by this limited preflight; executor verification is still required.</li>'}</ul></div>
<h2>Warnings</h2><ul>{warnings}</ul>
<h2>Verification status</h2><table><thead><tr><th>Check</th><th>Status</th></tr></thead><tbody>{checks}</tbody></table>
<h2>Sanitized local plan</h2><p class="muted">{'Device identifiers hidden for sharing.' if shareable else 'Device identifiers visible; keep this report private.'}</p><pre>{raw}</pre>
</body></html>'''
