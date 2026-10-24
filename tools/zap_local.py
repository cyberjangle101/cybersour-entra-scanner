"""Run the OWASP ZAP baseline locally, without Docker: the same check as .github/workflows/zap.yml.

What it does, in plain terms:
  1. writes the hostile-data sample report (tools/make_sample_report.py) to a temporary folder;
  2. serves it on 127.0.0.1 only, on a free port, for the length of the scan;
  3. runs ZAP's automation framework: spider (1 minute max) + passive scan, with the reviewed rules in .zap/rules.tsv turned off;
  4. prints every alert and exits 1 if any remain (the CI baseline fails on warnings too).
Nothing is sent anywhere but the local server; ZAP's own update checks are switched off.

Usage:  python tools/zap_local.py [--zap-home DIR] [--java PATH] [--keep]
Defaults: ZAP in %LOCALAPPDATA%\\Programs\\zap\\ZAP_2.17.0, Java 17+ in %LOCALAPPDATA%\\Programs\\temurin-jre-21 (or $ZAP_HOME / $ZAP_JAVA).
"""
import argparse, functools, glob, http.server, json, os, shutil, socketserver, subprocess, sys, tempfile, threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROGRAMS = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Programs")


def default_java():
    """The portable Java next to ZAP, if installed; ZAP 2.17 needs Java 17+, so a system Java 8 must not be picked up."""
    found = sorted(glob.glob(os.path.join(PROGRAMS, "temurin-jre-21", "*", "bin", "java.exe")))
    return os.environ.get("ZAP_JAVA") or (found[-1] if found else "java")


def ignored_rules(path):
    """Rule ids marked IGNORE in a ZAP baseline rules file (tab-separated: id, action, reason)."""
    ids = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\r\n").split("\t")
            if len(parts) >= 2 and parts[0].strip().isdigit() and parts[1].strip() == "IGNORE":
                ids.append(int(parts[0]))
    return ids


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    """Static file handler that keeps the console for ZAP's own output."""

    def log_message(self, *_args):
        """Drop the per-request access log."""


def serve(folder):
    """Serve `folder` on 127.0.0.1 on a free port in a background thread; returns (server, port)."""
    srv = socketserver.TCPServer(("127.0.0.1", 0), functools.partial(QuietHandler, directory=folder))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def main():
    """Build, serve and scan the sample report; exit 0 when ZAP raises no alerts outside the reviewed list."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--zap-home", default=os.environ.get("ZAP_HOME") or os.path.join(PROGRAMS, "zap", "ZAP_2.17.0"))
    ap.add_argument("--java", default=default_java())
    ap.add_argument("--keep", action="store_true", help="keep the temporary folder (report, plan) for inspection")
    ap.add_argument("--no-ignore", action="store_true", help="do not apply .zap/rules.tsv (proves the scan does raise the reviewed alerts)")
    a = ap.parse_args()
    jars = glob.glob(os.path.join(a.zap_home, "zap-*.jar"))
    if not jars:
        sys.exit(f"ZAP not found in {a.zap_home} (use --zap-home or set ZAP_HOME).")

    work = tempfile.mkdtemp(prefix="zap-local-")
    site, out = os.path.join(work, "site"), os.path.join(work, "out")
    os.makedirs(out)                                                # ZAP's report job does not create its folder
    # A persistent ZAP home, so the beta passive rules (which CI's Docker image includes) are installed once, not per run.
    home = os.path.join(os.path.dirname(a.zap_home), "home")
    zap = [a.java, "-Xmx1g", "-jar", jars[0], "-cmd", "-dir", home, "-config", "start.checkForUpdates=false"]
    if not glob.glob(os.path.join(home, "plugin", "pscanrulesBeta-*.zap")):
        print("Installing ZAP add-on pscanrulesBeta (one time, from ZAP's add-on marketplace) ...", flush=True)
        subprocess.run(zap + ["-addoninstall", "pscanrulesBeta"], cwd=a.zap_home, check=True)  # nosemgrep: dangerous-subprocess-use-audit, dangerous-subprocess-use-tainted-env-args  (developer's own paths/env, list args, no shell)
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "make_sample_report.py"), site], check=True)
    srv, port = serve(site)
    url = f"http://127.0.0.1:{port}/index.html"
    ignore = [] if a.no_ignore else ignored_rules(os.path.join(ROOT, ".zap", "rules.tsv"))
    plan = {                                                        # JSON is valid YAML, so no YAML library is needed
        "env": {"contexts": [{"name": "report", "urls": [f"http://127.0.0.1:{port}/"]}],
                "parameters": {"failOnError": True, "progressToStdout": True}},
        "jobs": [
            {"type": "passiveScan-config", "parameters": {"maxAlertsPerRule": 10},
             "rules": [{"id": i, "threshold": "off"} for i in ignore]},
            {"type": "spider", "parameters": {"url": url, "maxDuration": 1}},
            {"type": "passiveScan-wait", "parameters": {"maxDuration": 5}},
            {"type": "report", "parameters": {"template": "traditional-json", "reportDir": out, "reportFile": "zap-report"}},
        ]}
    plan_path = os.path.join(work, "plan.yaml")
    with open(plan_path, "w", encoding="utf-8") as fh:
        json.dump(plan, fh, indent=2)
    try:
        print(f"ZAP {os.path.basename(jars[0])} against {url} ({len(ignore)} reviewed rules ignored)", flush=True)
        rc = subprocess.run(zap + ["-autorun", plan_path], cwd=a.zap_home).returncode  # nosemgrep: dangerous-subprocess-use-audit, dangerous-subprocess-use-tainted-env-args  (as above)
    finally:
        srv.shutdown()
    reports = glob.glob(os.path.join(out, "zap-report*.json"))
    if not reports:
        sys.exit(f"ZAP exited with {rc} and wrote no report (see the output above).")
    with open(reports[0], encoding="utf-8") as fh:
        alerts = [al for s in json.load(fh).get("site", []) for al in s.get("alerts", [])]
    for al in alerts:
        print(f"ALERT  {al.get('pluginid')}  {al.get('riskdesc')}  {al.get('name')}  x{al.get('count')}")
    print(f"\nZAP alerts outside .zap/rules.tsv: {len(alerts)}  (ignored rules: {', '.join(map(str, ignore))})")
    if a.keep:
        print(f"Kept: {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
    sys.exit(1 if alerts or rc not in (0, 2) else 0)               # rc 2 = ZAP warnings, judged from the report above


if __name__ == "__main__":
    main()
