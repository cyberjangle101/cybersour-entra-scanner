"""Multi-tenant batch mode: scan many tenants one after another and write a combined overview next to the per-tenant reports.

The batch file is JSON and may contain ONLY references to credentials (a secret FILE, a certificate path, a federated token
file, a Key Vault URL ...), never secret values. A file that contains a secret value is rejected outright.
"""
from __future__ import annotations

import datetime as dt
import html
import json
import re
import secrets
from argparse import Namespace
from pathlib import Path

from .models import ConfigError, SEV_RANK, write_private
from .postprocess import _read_json

# Keys a tenant entry may set; anything else is rejected so a typo cannot silently be ignored.
ALLOWED = {"name", "tenant", "client_id", "auth", "cloud", "client_secret_file", "cert_path", "cert_thumbprint", "federated_token_file",
           "federated_audience", "keyvault_secret", "areas", "policy", "suppressions", "baseline"}
FORBIDDEN_HINT = re.compile(r"secret$|password|passphrase|token$", re.I)       # e.g. "client_secret", "password", "cert_passphrase"
ALLOWED_SHARED = {"proxy", "ca_bundle", "timeout", "check_timeout", "max_runtime", "max_users", "cloud", "policy", "suppressions", "sarif", "junit", "csv"}


def load_batch(path):
    """Validate the batch file and return (shared defaults dict, list of tenant dicts)."""
    data = _read_json(path, "batch")
    if not isinstance(data, dict) or not isinstance(data.get("tenants"), list) or not data["tenants"]:
        raise ConfigError('Batch file must look like {"tenants": [{"name": ..., "tenant": ..., "client_id": ...}], "defaults": {...}}.')
    shared = data.get("defaults", {})
    if not isinstance(shared, dict) or set(shared) - ALLOWED_SHARED:
        raise ConfigError("Batch 'defaults' may only contain: " + ", ".join(sorted(ALLOWED_SHARED)) + ".")
    names = set()
    for n, t in enumerate(data["tenants"], 1):
        if not isinstance(t, dict):
            raise ConfigError(f"Batch tenant #{n} must be an object.")
        for key in t:
            if key not in ALLOWED:
                hint = " Secret VALUES are never accepted in a batch file; use client_secret_file, cert_path, federated_token_file or keyvault_secret." \
                    if FORBIDDEN_HINT.search(key) else ""
                raise ConfigError(f"Batch tenant #{n}: unknown key '{key}'.{hint}")
        if not all(isinstance(t.get(k), str) and t[k].strip() for k in ("name", "tenant")):
            raise ConfigError(f"Batch tenant #{n} needs text values for 'name' and 'tenant'.")
        if not re.fullmatch(r"[A-Za-z0-9._ -]{1,60}", t["name"]):
            raise ConfigError(f"Batch tenant #{n}: 'name' may only contain letters, digits, space, dot, dash and underscore.")
        if t["name"] in names:
            raise ConfigError(f"Batch tenant name '{t['name']}' is used twice.")
        names.add(t["name"])
    return shared, data["tenants"]


def _args_for(entry, shared, base, out_dir):
    """Namespace for one tenant: CLI settings < batch defaults < tenant entry. Interactive prompts are always off."""
    a = dict(vars(base))
    a.update(shared)
    a.update({k: v for k, v in entry.items() if k != "name"})
    a.update(output_dir=str(out_dir), prompt_secret=False, secret_stdin=False, prompt_passphrase=False, client_secret=None, batch=None)
    a.setdefault("auth", "secret")
    a.setdefault("areas", None)
    return Namespace(**a)


def run_batch(path, base_args, execute, log=print):
    """Scan every tenant. A failure in one tenant is recorded and the next tenant still runs. Returns (rows, combined html path)."""
    shared, tenants = load_batch(path)
    root = Path(base_args.output_dir)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    rows = []
    for entry in tenants:
        folder = root / re.sub(r"[^A-Za-z0-9._-]", "_", entry["name"])
        log(f"=== {entry['name']} ===")
        try:
            res = execute(_args_for(entry, shared, base_args, folder), log)
            f = res["findings"]
            sev = {s: sum(1 for x in f if x.status in ("FAIL", "WARN") and x.severity == s) for s in ("critical", "high", "medium", "low")}
            rows.append({"name": entry["name"], "ok": True, "score": res["summary"]["score"], "grade": res["summary"]["grade"], "severity": sev,
                         "coverage": res["coverage"][2], "report": str(res["html_path"].relative_to(root)),
                         "worst": min((SEV_RANK[x.severity] for x in f if x.status in ("FAIL", "WARN")), default=99)})
        except Exception as e:                      # noqa: BLE001 - one broken tenant must not stop the others
            log(f"  {entry['name']}: FAILED - {type(e).__name__}: {e}")
            rows.append({"name": entry["name"], "ok": False, "error": f"{type(e).__name__}: {e}"})
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    write_private(root / f"combined-{stamp}.json", json.dumps({"generated": stamp, "tenants": rows}, indent=2))
    out = root / f"combined-{stamp}.html"
    write_private(out, combined_html(rows))
    return rows, out


def combined_html(rows):
    """One-page overview: a row per tenant with score, grade, severity counts and a link to its full report."""
    esc, nonce = html.escape, secrets.token_urlsafe(16)
    body = []
    for r in sorted(rows, key=lambda r: (not r["ok"], r.get("score") if r.get("score") is not None else 101)):
        if not r["ok"]:
            body.append(f'<tr><td>{esc(r["name"])}</td><td colspan="7" class="bad">Scan failed: {esc(r["error"])}</td></tr>')
            continue
        s = r["severity"]
        body.append(f'<tr><td>{esc(r["name"])}</td><td>{r["score"]}</td><td>{esc(r["grade"])}</td><td>{s["critical"]}</td><td>{s["high"]}</td>'
                    f'<td>{s["medium"]}</td><td>{s["low"]}</td><td>{r["coverage"]}%</td>'
                    f'<td><a href="{esc(r["report"])}">report</a></td></tr>')
    css = ("body{font:15px system-ui,sans-serif;margin:24px auto;max-width:1000px;padding:0 16px}table{border-collapse:collapse;width:100%}"
           "td,th{border-bottom:1px solid #8884;padding:6px 10px;text-align:left}.bad{color:#d1242f}")
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" '
            f'content="default-src \'none\'; style-src \'nonce-{nonce}\'; base-uri \'none\'; form-action \'none\'">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>Entra posture - all tenants</title>'
            f'<style nonce="{nonce}">{css}</style></head><body><h1>Entra posture - all tenants</h1><table><thead><tr><th>Tenant</th><th>Score</th>'
            f'<th>Grade</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Checks run</th><th></th></tr></thead><tbody>'
            + "".join(body) + "</tbody></table></body></html>")
