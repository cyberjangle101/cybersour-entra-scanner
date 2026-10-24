"""Turns raw findings into decisions: policy overrides, accepted-risk suppressions, run-to-run diff, score, remediation snippets.

Everything here works on the list of Finding objects AFTER the checks ran; nothing here talks to Microsoft Graph.
Input files (policy, suppressions, baseline) are untrusted: they are size-limited, parsed as JSON only and strictly validated.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

from .models import ConfigError

MAX_FILE_BYTES = 5_000_000
SEVERITIES = ("critical", "high", "medium", "low", "info")
WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}


def _read_json(path, what):
    """Read a small JSON file, turning every problem into a ConfigError with a plain message."""
    p = Path(path)
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            raise ConfigError(f"{what} file {p} is larger than {MAX_FILE_BYTES // 1_000_000} MB.")
        return json.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise ConfigError(f"Cannot read {what} file {p}: {e.strerror or e}") from None
    except ValueError as e:
        raise ConfigError(f"{what} file {p} is not valid JSON: {e}") from None


def fingerprint(f):
    """Stable short hash of a finding's id plus the objects it affects, so two runs can be compared."""
    raw = f.id + "\n" + "\n".join(sorted(str(x) for x in f.evidence))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------- policy: disable checks, change severities
def load_policy(path):
    """{'disable': [ids], 'severity': {id: level}} from a JSON file. Unknown keys are rejected so typos are not silent."""
    data = _read_json(path, "policy")
    if not isinstance(data, dict) or set(data) - {"disable", "severity", "note"}:
        raise ConfigError("Policy file must be a JSON object with only the keys: disable, severity, note.")
    disable, sev = data.get("disable", []), data.get("severity", {})
    if not (isinstance(disable, list) and all(isinstance(x, str) for x in disable)):
        raise ConfigError("Policy 'disable' must be a list of finding ids such as [\"CA-009\"].")
    if not (isinstance(sev, dict) and all(isinstance(k, str) and v in SEVERITIES for k, v in sev.items())):
        raise ConfigError(f"Policy 'severity' must map finding ids to one of {', '.join(SEVERITIES)}.")
    return {"disable": set(disable), "severity": sev}


def apply_policy(findings, policy):
    """Drop disabled checks and re-grade severities. Returns (kept findings, ids disabled, ids re-graded)."""
    kept, off, regraded = [], [], []
    for f in findings:
        if f.id in policy["disable"] and f.status not in ("SKIPPED", "ERROR"):
            off.append(f.id)
            continue
        if f.id in policy["severity"]:
            new = policy["severity"][f.id]
            if f.status in ("FAIL", "WARN"):
                f.severity = new
            f.risk = new
            regraded.append(f.id)
        kept.append(f)
    return kept, sorted(set(off)), sorted(set(regraded))


# --------------------------------------------------------------------------- suppressions (accepted risk)
def load_suppressions(path):
    """List of accepted-risk entries. Every entry MUST name an owner, a reason and an expiry date: risk acceptance is never open-ended."""
    data = _read_json(path, "suppressions")
    rows = data.get("suppressions") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise ConfigError("Suppressions file must be a JSON list (or {\"suppressions\": [...]}).")
    out = []
    for n, r in enumerate(rows, 1):
        if not isinstance(r, dict) or not all(isinstance(r.get(k), str) and r[k].strip() for k in ("id", "owner", "reason", "expires")):
            raise ConfigError(f"Suppression #{n} needs non-empty text for: id, owner, reason, expires (YYYY-MM-DD).")
        try:
            expires = dt.date.fromisoformat(r["expires"])
        except ValueError:
            raise ConfigError(f"Suppression #{n} ({r['id']}): expires must be a date like 2026-12-31.") from None
        scope = r.get("scope", [])
        if not (isinstance(scope, list) and all(isinstance(s, str) for s in scope)):
            raise ConfigError(f"Suppression #{n} ({r['id']}): scope must be a list of strings.")
        out.append({"id": r["id"], "owner": r["owner"], "reason": r["reason"], "expires": expires, "scope": scope})
    return out


def apply_suppressions(findings, rules, today=None):
    """Mark FAIL/WARN findings covered by an unexpired rule as SUPPRESSED (kept in reports, excluded from the score and exit code).

    An expired rule changes nothing but is noted on the finding so the owner is reminded. A rule with a `scope` only covers a
    finding whose EVERY affected object contains one of the scope strings, so a new problem object is never hidden by an old waiver.
    """
    today = today or dt.date.today()
    for f in findings:
        if f.status not in ("FAIL", "WARN"):
            continue
        for r in rules:
            if r["id"] != f.id:
                continue
            if r["scope"] and not (f.evidence and all(any(s in str(e) for s in r["scope"]) for e in f.evidence)):
                continue
            if r["expires"] < today:
                f.detail += f" [Accepted-risk waiver by {r['owner']} EXPIRED on {r['expires']}.]"
                continue
            f.suppression = {"owner": r["owner"], "reason": r["reason"], "expires": r["expires"].isoformat(), "original_status": f.status}
            f.status = "SUPPRESSED"
            break
    return findings


# --------------------------------------------------------------------------- baseline diff
def load_baseline(path):
    """Findings of an earlier JSON report as {id: {status, fingerprint}}."""
    data = _read_json(path, "baseline")
    rows = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise ConfigError("Baseline must be a JSON report previously written by this tool.")
    return {r["id"]: {"status": r.get("status"), "fingerprint": r.get("fingerprint", ""), "title": r.get("title", "")}
            for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str)}


def diff_against(findings, baseline):
    """Compare this run with a baseline: new problems, resolved problems, and problems whose affected objects changed."""
    bad = ("FAIL", "WARN")
    now = {f.id: f for f in findings}
    new = [f.id for f in findings if f.status in bad and baseline.get(f.id, {}).get("status") not in bad]
    was_bad = [i for i, b in baseline.items() if b["status"] in bad and i in now]
    # A problem waived since the baseline is still a problem: report it as accepted, never as resolved.
    resolved = [i for i in was_bad if now[i].status not in bad and now[i].status != "SUPPRESSED"]
    accepted = [i for i in was_bad if now[i].status == "SUPPRESSED"]
    changed = [f.id for f in findings if f.status in bad and baseline.get(f.id, {}).get("status") in bad
               and baseline[f.id]["fingerprint"] and baseline[f.id]["fingerprint"] != f.fingerprint]
    gone = [i for i, b in baseline.items() if b["status"] in bad and i not in now]
    return {"new": sorted(new), "resolved": sorted(resolved), "accepted": sorted(accepted), "changed": sorted(changed), "not_run_now": sorted(gone)}


# --------------------------------------------------------------------------- score
def _area_score(rows):
    """100 minus the weighted share of failed risk. FAIL counts fully, WARN half; SUPPRESSED/INFO/MANUAL are ignored."""
    possible = lost = 0.0
    for f in rows:
        if f.status not in ("PASS", "FAIL", "WARN"):
            continue
        w = WEIGHT.get(f.risk or (f.severity if f.status != "PASS" else "medium"), WEIGHT["medium"])
        possible += w
        lost += w if f.status == "FAIL" else w / 2 if f.status == "WARN" else 0
    return None if possible == 0 else round(100 * (1 - lost / possible))


def grade(score):
    """Letter grade for a 0-100 score."""
    return "n/a" if score is None else "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"


def summarize(findings, areas):
    """Executive summary: overall and per-area score, grade, counts and the five most serious open risks."""
    per = {}
    for key, name in areas.items():
        rows = [f for f in findings if f.category == key]
        s = _area_score(rows)
        if s is not None:
            per[key] = {"name": name, "score": s, "grade": grade(s)}
    overall = _area_score(findings)
    open_ = [f for f in findings if f.status in ("FAIL", "WARN")]
    open_.sort(key=lambda f: (SEVERITIES.index(f.severity) if f.severity in SEVERITIES else 9, f.status != "FAIL", f.id))
    counts = {}
    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1
    # Pass rates count only controls with a verdict (PASS / FAIL / WARN); MANUAL, INFO, SKIPPED and accepted risks are left out.
    evaluated = [f for f in findings if f.status in ("PASS", "FAIL", "WARN")]
    cis_auto = [f for f in evaluated if f.cis]
    cis_pass = sum(1 for f in cis_auto if f.status == "PASS")
    return {"score": overall, "grade": grade(overall), "areas": per, "counts": counts,
            "top_risks": [{"id": f.id, "title": f.title, "severity": f.severity, "status": f.status} for f in open_[:5]],
            "controls_evaluated": len(evaluated), "controls_pass": sum(1 for f in evaluated if f.status == "PASS"),
            "cis_automated_total": len(cis_auto), "cis_automated_pass": cis_pass,
            "cis_automated_pass_percent": round(100 * cis_pass / len(cis_auto)) if cis_auto else None}


# --------------------------------------------------------------------------- remediation snippets (guidance only; never executed)
_PS = "Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess'   # a WRITE scope: this is for a human administrator, not for this scanner\n"
SNIPPETS = {
    "CA-001": _PS + "# Portal: Entra admin centre > Protection > Conditional Access > New policy > Users: All, Client apps: Exchange ActiveSync + Other, Grant: Block",
    "CA-002": _PS + "# Portal: New policy > Users: All (exclude emergency accounts), Target: All resources, Grant: Require MFA (or an authentication strength)",
    "CA-011": "# Portal: New policy > Users: directory roles (all admin roles), Grant: Require authentication strength 'Phishing-resistant MFA'",
    "CA-016": "# Portal: New policy > Conditions > Authentication flows: Device code flow, Grant: Block",
    "ADM-001": "# Portal: Roles & admins > Global Administrator > review assignments; make non-emergency holders PIM-eligible",
    "ADM-009": "# Create two cloud-only accounts named e.g. bg1@<tenant>.onmicrosoft.com, assign Global Administrator permanently, register FIDO2 keys,\n"
               "# store credentials offline, exclude them from Conditional Access, and alert on any sign-in (Azure Monitor / Sentinel).",
    "AUTH-002": "# Portal: Protection > Authentication methods > Policies > SMS / Voice > Disable (after moving users to Authenticator or FIDO2)",
    "TEN-001": "# PowerShell (needs a WRITE scope, human use only):\n# Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom 'adminsAndGuestInviters'",
    "APP-020": "# Portal: Enterprise applications > Consent and permissions > User consent settings > Do not allow user consent (or verified publishers only)",
    "PIM-001": "# Portal: Identity Governance > Privileged Identity Management > Microsoft Entra roles > Assignments > convert permanent to eligible",
    "LEG-001": "# 1) Find the clients: Sign-in logs > Client app filter = legacy. 2) Move them to modern auth. 3) Enforce the CA-001 block policy.",
    "HYB-002": "# On the sync server: Start-ADSyncSyncCycle -PolicyType Delta ; verify Password Hash Sync in Entra Connect Health",
}


def remediation_script(f):
    """Guidance text for a failing finding: a specific snippet when one exists, else the portal setting and Learn page."""
    if f.status not in ("FAIL", "WARN"):
        return ""
    if f.id in SNIPPETS:
        return SNIPPETS[f.id]
    return f"# Change: {f.setting}\n# Guide: {f.learn}" if f.setting else ""


def finalize(findings, areas, policy=None, suppressions=None, baseline=None, today=None):
    """Run the whole post-processing pipeline in the right order. Returns (findings, extras for the report meta)."""
    for f in findings:
        f.fingerprint = fingerprint(f)
    extras = {}
    if policy:
        findings, off, graded = apply_policy(findings, policy)
        extras["policy"] = {"disabled": off, "severity_overrides": graded}
    if suppressions:
        apply_suppressions(findings, suppressions, today)
    for f in findings:
        f.script = remediation_script(f)
    summary = summarize(findings, areas)
    extras["summary"] = summary
    if baseline is not None:
        extras["diff"] = diff_against(findings, baseline)
    return findings, extras
