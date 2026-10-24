"""Command-line interface.  Run `python entra_posture_scan.py --help`.

Exit codes:  0 = finished, nothing at/above --fail-on;  1 = findings at/above --fail-on or coverage below --min-coverage;
             2 = bad settings / credentials;  3 = unexpected error.
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .auth import AUTH_METHODS, HOW_TO_SUPPLY_IT, resolve_credentials
from .clouds import CLOUDS
from .models import SEV_RANK, SEVERITIES, ConfigError, GraphError


def build_parser():
    """Define every command-line option. allow_abbrev is off so a typo cannot silently match a different flag."""
    from .runner import AREAS
    p = argparse.ArgumentParser(
        prog="entra_posture_scan", allow_abbrev=False,
        description="Read-only Microsoft Entra ID security posture scan (CIS Microsoft 365 Foundations Benchmark v5.0.0 aligned).")
    p.add_argument("--tenant", help="Tenant ID (GUID) or domain, e.g. contoso.onmicrosoft.com (env AZURE_TENANT_ID)")
    p.add_argument("--client-id", help="Application (client) ID of the scanner app registration (env AZURE_CLIENT_ID)")
    p.add_argument("--auth", choices=AUTH_METHODS, default="secret",
                   help="Sign-in method (default: secret). federated = workload identity federation (no secret); managed-identity = Azure resource identity")
    p.add_argument("--cloud", choices=sorted(CLOUDS), default="commercial", help="Microsoft cloud: commercial, usgov (GCC High), usgovdod (DoD), china")
    g = p.add_argument_group("client secret (pick one; the secret itself is never accepted on the command line)")
    g.add_argument("--prompt-secret", action="store_true", help="Type the secret at a hidden prompt")
    g.add_argument("--secret-stdin", action="store_true", help="Read the secret from the first line of standard input")
    g.add_argument("--client-secret-file", metavar="PATH", help="Read the secret from a file (owner-only permissions)")
    g.add_argument("--client-secret", nargs="?", const="", help=argparse.SUPPRESS)      # accepted only to refuse it with advice
    c = p.add_argument_group("certificate sign-in (--auth cert)")
    c.add_argument("--cert-path", metavar="PEM", help="PEM private key file (env AZURE_CLIENT_CERT_PATH)")
    c.add_argument("--cert-thumbprint", help="Certificate SHA-1 thumbprint (env AZURE_CLIENT_CERT_THUMBPRINT)")
    c.add_argument("--prompt-passphrase", action="store_true", help="Prompt for the private key passphrase")
    f = p.add_argument_group("federated / managed identity / Key Vault (no stored secret)")
    f.add_argument("--federated-token-file", metavar="PATH", help="File holding the external identity token (Kubernetes/Azure workload identity). GitHub Actions OIDC is detected automatically")
    f.add_argument("--federated-audience", help="Token audience override (default depends on --cloud)")
    f.add_argument("--keyvault-secret", metavar="URL", help="https://<vault>.vault.azure.net/secrets/<name>: read the client secret from Key Vault using the managed identity")
    n = p.add_argument_group("network and limits")
    n.add_argument("--proxy", metavar="URL", help="HTTPS proxy, e.g. http://proxy.corp:8080 (credentials in the URL are not logged)")
    n.add_argument("--ca-bundle", metavar="PEM", help="CA bundle file for TLS-inspecting proxies")
    n.add_argument("--timeout", type=_positive, default=60, help="Seconds to wait for each Graph request (default 60)")
    n.add_argument("--check-timeout", type=int, default=0, metavar="SEC", help="Stop a check after SEC seconds and report it SKIPPED (0 = no limit)")
    n.add_argument("--max-runtime", type=int, default=0, metavar="SEC", help="Stop starting new checks after SEC seconds; the report is marked PARTIAL (0 = no limit)")
    n.add_argument("--verbose", action="store_true", help="Print every request path, status and timing (never tokens or response bodies)")
    n.add_argument("--log-file", metavar="PATH", help="Append the same request log to a file (owner-only permissions)")
    d = p.add_argument_group("decisions and comparison")
    d.add_argument("--policy", metavar="JSON", help='Policy file: {"disable": ["CA-009"], "severity": {"ADM-004": "medium"}}')
    d.add_argument("--suppressions", metavar="JSON", help="Accepted-risk file: entries with id, owner, reason, expires (and optional scope)")
    d.add_argument("--baseline", metavar="JSON", help="An earlier JSON report; the new report shows what is new, resolved or changed")
    d.add_argument("--batch", metavar="JSON", help="Scan many tenants listed in a batch file and write a combined overview")
    s = p.add_argument_group("scan options")
    s.add_argument("--areas", nargs="+", choices=sorted(AREAS), metavar="AREA", help="Only these areas: " + ", ".join(sorted(AREAS)))
    s.add_argument("--max-users", type=_positive, default=50000, help="Stop reading users after this many (default 50000)")
    s.add_argument("--output-dir", default="reports", help="Where to write the HTML and JSON reports (default ./reports)")
    s.add_argument("--csv", action="store_true", help="Also write a CSV file")
    s.add_argument("--sarif", action="store_true", help="Also write a SARIF 2.1.0 file (code-scanning dashboards)")
    s.add_argument("--junit", action="store_true", help="Also write a JUnit XML file (CI test reports)")
    s.add_argument("--fail-on", choices=SEVERITIES[:4], help="Exit 1 if any FAIL/WARN is at or above this severity")
    s.add_argument("--min-coverage", type=int, default=0, metavar="PCT", help="Exit 1 if fewer than PCT%% of checks could run")
    i = p.add_argument_group("information (no sign-in needed)")
    i.add_argument("--list-permissions", action="store_true", help="Print the Graph permissions to grant, and why")
    i.add_argument("--list-checks", action="store_true", help="Print every check and the permission it needs")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _positive(v):
    n = int(v)
    if n < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return n


def main(argv=None):
    """Entry point: handle info flags, refuse unsafe secret flags, run the scan and translate failures into exit codes."""
    parser = build_parser()
    args = parser.parse_args(argv)
    from . import permissions
    from .models import CHECKS
    if args.list_permissions:
        print("Microsoft Graph APPLICATION permissions to grant (read-only), then give admin consent:\n")
        for name, why, used_by in permissions.permission_table():
            print(f"  {name}\n      {why}\n      used by: {', '.join(used_by)}\n")
        print("Nothing else is needed: no Azure, Exchange, Defender or write permission is used.")
        return 0
    if args.list_checks:
        for area, fn in CHECKS:
            print(f"{area:11} {fn.__name__:26} needs: {', '.join(fn.needs) or '-'}")
        return 0
    if args.client_secret is not None:
        print("Refusing --client-secret: a value on the command line is visible to other users and in shell history.\n" + HOW_TO_SUPPLY_IT,
              file=sys.stderr)
        return 2
    try:
        from .runner import execute_scan
        if args.batch:
            return _run_batch(args, execute_scan)
        resolve_credentials(args)
        result = execute_scan(args)
    except ConfigError as e:
        print(f"Settings problem: {e}", file=sys.stderr)
        return 2
    except GraphError as e:
        print(f"Microsoft Graph error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except Exception as e:                           # noqa: BLE001
        print(f"Unexpected error: {type(e).__name__}: {e}", file=sys.stderr)
        return 3
    findings = result["findings"]
    if args.csv:
        from .report import export_csv
        export_csv(findings, result["html_path"].with_suffix(".csv"))
    issues = [f for f in findings if f.status in ("FAIL", "WARN")]        # accepted risks (SUPPRESSED) are deliberately not counted
    sm = result["summary"]
    print(f"\nDone: {len(issues)} issues, {sum(f.status == 'PASS' for f in findings)} passed, "
          f"{sum(f.status == 'MANUAL' for f in findings)} manual, {sum(f.status == 'SUPPRESSED' for f in findings)} accepted risk. "
          f"Score {sm['score']} ({sm['grade']}). Coverage {result['coverage'][2]}%.\nReport: {result['html_path']}")
    if result["diff"] is not None:
        d = result["diff"]
        print(f"Since baseline: {len(d['new'])} new, {len(d['resolved'])} resolved, {len(d['accepted'])} newly accepted risk, "
              f"{len(d['changed'])} changed.")
    if args.min_coverage and result["coverage"][2] < args.min_coverage:
        print(f"Coverage {result['coverage'][2]}% is below --min-coverage {args.min_coverage}%.", file=sys.stderr)
        return 1
    if args.fail_on and any(SEV_RANK[f.severity] <= SEV_RANK[args.fail_on] for f in issues):
        return 1
    return 0


def _run_batch(args, execute_scan):
    """Scan every tenant in the batch file; exit 1 if any tenant failed to scan or has findings at/above --fail-on."""
    from .batch import run_batch
    rows, combined = run_batch(args.batch, args, execute_scan)
    failed = [r["name"] for r in rows if not r["ok"]]
    print(f"\nBatch done: {len(rows) - len(failed)} of {len(rows)} tenants scanned. Overview: {combined}")
    if failed:
        print("Failed: " + ", ".join(failed), file=sys.stderr)
        return 1
    if args.fail_on and any(r["worst"] <= SEV_RANK[args.fail_on] for r in rows):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
