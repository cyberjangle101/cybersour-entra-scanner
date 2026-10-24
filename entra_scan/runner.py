"""Runs the checks one by one, isolates their failures, and turns the results into a scan summary.

Golden rule: a check that cannot read its data is reported as SKIPPED with the reason. It is NEVER reported as a pass.
Each check runs inside its own try/except, so one bad API answer cannot stop the scan or hide the other results.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict
from pathlib import Path

from . import __version__, checks, metadata, permissions  # noqa: F401  (importing `checks` registers every check)
from . import export, postprocess
from .auth import build_token_provider
from .clouds import get_cloud
from .context import Ctx
from .graph import Graph
from .models import CHECKS, ConfigError, Finding, GraphError, SkipCheck, one, write_private
from .report import render_html

# Display order and names of the areas (a finding's `category`). Users can scan a subset with --areas.
AREAS = {
    "ca": "Conditional Access",
    "roles": "Privileged access",
    "governance": "Identity governance (PIM, access reviews)",
    "users": "Users & MFA registration",
    "authn": "Authentication methods & passwords",
    "apps": "Applications & consent",
    "tenant": "Tenant, guest & domain settings",
    "devices": "Device settings",
    "hybrid": "Hybrid identity",
    "network": "Named locations",
    "signins": "Sign-in log evidence",
    "groups": "Groups",
    "idp": "Identity Protection",
    "manual": "Manual verification (CIS items Graph cannot read)",
}


PREFIX = {"SKIPPED": "SKIP", "ERROR": "ERR"}      # finding-id prefix for checks that could not run


def should_skip(e: GraphError):
    """True when the error means 'no permission / no licence / feature not in this tenant' rather than a real fault."""
    m = e.message.lower()
    return e.status in (401, 403, 408) or any(k in m for k in ("premium", "licen", "not applicable", "not enrolled"))


def run_scan(ctx: Ctx, areas=None, log=print, stop=None):
    """Run every check in the chosen areas (None = all) and return the list of findings, with metadata stamped on."""
    findings = []
    budget = getattr(ctx.args, "check_timeout", 0) or 0           # seconds per check (0 = unlimited)
    max_runtime = getattr(ctx.args, "max_runtime", 0) or 0        # seconds for the whole scan (0 = unlimited)
    scan_started = time.monotonic()
    ctx.partial_reason = ""
    for area, fn in CHECKS:
        if areas and area not in areas:
            continue
        if stop is not None and stop.is_set():
            log("Scan cancelled; results are partial.")
            break
        if max_runtime and time.monotonic() - scan_started > max_runtime:
            ctx.partial_reason = f"maximum runtime of {max_runtime}s reached; remaining checks were not run"
            log(f"Scan stopped: {ctx.partial_reason}.")
            break
        title = (fn.__doc__ or fn.__name__).strip()
        started = time.time()
        ctx.g.deadline = time.monotonic() + budget if budget else None
        try:
            produced = fn(ctx)
            findings += produced
            note = f"ok ({len(produced)} findings, {time.time() - started:.1f}s)"
        except SkipCheck as e:
            findings.append(Finding(f"SKIP-{fn.__name__}", area, title, "SKIPPED", "info", str(e), needs=", ".join(fn.needs)))
            note = "skipped"
        except GraphError as e:
            status = "SKIPPED" if should_skip(e) else "ERROR"
            hint = (f" The app needs these Microsoft Graph application permissions with admin consent: {', '.join(fn.needs)}; "
                    "some checks also need an Entra ID P1/P2 licence." if status == "SKIPPED" else "")
            findings.append(Finding(f"{PREFIX[status]}-{fn.__name__}", area, title, status, "info", f"{str(e).rstrip('.')}.{hint}",
                                    evidence=[str(e.url)[:200]], needs=", ".join(fn.needs)))
            note = status.lower()
        except Exception as e:                       # noqa: BLE001 - one broken check must never stop the scan
            findings.append(Finding(f"ERR-{fn.__name__}", area, title, "ERROR", "info", f"{type(e).__name__}: {e}", needs=", ".join(fn.needs)))
            note = "error"
        log(f"  [{area}] {title} ... {note}")
    ctx.g.deadline = None
    return metadata.apply(findings)


def setup_logging(args):
    """--verbose prints request lines (method, path, status, timing, request-id; never tokens or bodies); --log-file keeps them (owner-only)."""
    logger = logging.getLogger("entra_scan")
    for h in list(logger.handlers):                   # a second scan in the same process (GUI, batch) must not duplicate lines
        logger.removeHandler(h)
        h.close()
    logger.propagate = False
    verbose, path = getattr(args, "verbose", False), getattr(args, "log_file", None)
    logger.setLevel(logging.DEBUG if (verbose or path) else logging.WARNING)
    fmt = logging.Formatter("%(asctime)s %(name)s %(message)s")
    if verbose:
        h = logging.StreamHandler()
        h.setFormatter(fmt)
        logger.addHandler(h)
    if path:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        h = logging.StreamHandler(os.fdopen(fd, "a", encoding="utf-8"))
        h.setFormatter(fmt)
        logger.addHandler(h)


def scan_coverage(findings, areas=None):
    """(checks selected, checks that could not run, percent that ran).  Skipped/errored checks are never counted as run."""
    selected_areas = set(areas) if areas else {a for a, _ in CHECKS}
    selected = sum(1 for a, _ in CHECKS if a in selected_areas)
    not_run = sum(1 for f in findings if f.status in ("SKIPPED", "ERROR"))
    return selected, not_run, (100 * (selected - not_run) // selected if selected else 100)


def execute_scan(args, log=print, stop=None):
    """Sign in, run the scan, post-process and write the reports. Shared by the CLI, the GUI and batch mode.

    Raises ConfigError for credential / settings problems (message is safe to show a user).
    """
    # Validate every input file BEFORE signing in so a typo fails in a second, not after a long scan.
    policy = postprocess.load_policy(args.policy) if getattr(args, "policy", None) else None
    waivers = postprocess.load_suppressions(args.suppressions) if getattr(args, "suppressions", None) else None
    baseline = postprocess.load_baseline(args.baseline) if getattr(args, "baseline", None) else None
    cloud = get_cloud(getattr(args, "cloud", None) or "commercial")
    setup_logging(args)
    provider = build_token_provider(args)
    provider()                                       # fail fast on bad credentials instead of erroring in every check
    graph = Graph(provider, cloud=cloud, proxy=getattr(args, "proxy", None), ca_bundle=getattr(args, "ca_bundle", None),
                  timeout=getattr(args, "timeout", None) or 60)
    ctx = Ctx(graph, args)
    try:
        org = one(graph.get("/organization", {"$select": "id,displayName"}))
    except GraphError:
        org = {}
    meta = {"tenant": org.get("displayName", getattr(args, "tenant", None) or "?"), "tenant id": org.get("id", "?"),
            "scanned": ctx.now.strftime("%Y-%m-%d %H:%M UTC"), "tool": f"Entra Posture Scanner {__version__}", "cloud": cloud.name}
    log(f"Scanning {meta['tenant']} ...")
    areas = list(getattr(args, "areas", None) or []) or None
    findings = run_scan(ctx, areas, log, stop)
    selected, not_run, pct = scan_coverage(findings, areas)
    # A check group is one check function; each produces several findings (the controls listed in the report), so this
    # number is much smaller than the number of findings and must not be labelled "checks".
    meta["check groups run"] = (f"{selected - not_run} of {selected} ({pct}%)"
                                + (f"; {not_run} could not read their data (see Skipped / errors)" if not_run else ""))
    meta["graph requests"] = graph.calls
    cancelled = bool(stop is not None and stop.is_set())
    if cancelled:
        meta["note"] = "PARTIAL - scan cancelled"
    elif ctx.partial_reason:
        meta["note"] = "PARTIAL - " + ctx.partial_reason

    findings, extras = postprocess.finalize(findings, AREAS, policy, waivers, baseline)
    summary, diff = extras["summary"], extras.get("diff")
    meta["score"] = f"{summary['score']} ({summary['grade']})" if summary["score"] is not None else "n/a"
    if "policy" in extras:
        meta["policy"] = f"{len(extras['policy']['disabled'])} checks disabled, {len(extras['policy']['severity_overrides'])} severities changed"
    if waivers:
        meta["accepted risks"] = sum(f.status == "SUPPRESSED" for f in findings)

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = ctx.now.strftime("%Y%m%d-%H%M%S")
    base = out / f"entra-posture-{stamp}"
    json_path, html_path = base.with_suffix(".json"), base.with_suffix(".html")
    write_private(json_path, json.dumps({"meta": meta, "summary": summary, "diff": diff, "policy": extras.get("policy"),
                                         "findings": [asdict(f) for f in findings]}, indent=2))
    write_private(html_path, render_html(meta, findings, AREAS, summary, diff))
    paths = {"json_path": json_path, "html_path": html_path}
    if getattr(args, "sarif", False):
        paths["sarif_path"] = base.with_suffix(".sarif")
        write_private(paths["sarif_path"], export.sarif_text(meta, findings))
    if getattr(args, "junit", False):
        paths["junit_path"] = base.with_suffix(".junit.xml")
        write_private(paths["junit_path"], export.junit_text(meta, findings, AREAS))
    return {"meta": meta, "findings": findings, "summary": summary, "diff": diff, **paths,
            "cancelled": cancelled, "coverage": (selected, not_run, pct)}
