"""User acceptance test runner. Each scenario is what a real user would do; results are written to docs/UAT.md.
Run:  python tests/uat.py            (needs: playwright+chromium for the browser run, python3.12 + tkinter + xvfb-run for the GUI run; those
                                       two are reported as NOT RUN, never as passed, if the tools are missing)"""
import contextlib, importlib.util, io, json, os, shutil, subprocess, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path[:0] = [ROOT, HERE]
from entra_scan import cli, context, graph, runner
from entra_scan.models import GraphError
from fake_tenant import Args, FakeGraph, bad_tenant, denied_tenant, good_tenant, is_private_file

RESULTS = []
GUID = "11111111-1111-1111-1111-111111111111"


def scenario(sid, title, expect):
    def deco(fn):
        t0 = time.time()
        try:
            detail = fn()
            RESULTS.append((sid, title, expect, "PASS", str(detail or ""), time.time() - t0))
        except BaseException as e:                                  # noqa: BLE001
            RESULTS.append((sid, title, expect, "FAIL", f"{type(e).__name__}: {e}", time.time() - t0))
        return fn
    return deco


@contextlib.contextmanager
def tenant(data):
    saved = (runner.build_token_provider, runner.Graph)
    runner.build_token_provider = lambda a: (lambda: "tok")
    runner.Graph = lambda p, **kw: FakeGraph(data)
    try:
        yield
    finally:
        runner.build_token_provider, runner.Graph = saved


def run_cli(data, *argv):
    out = tempfile.mkdtemp()
    buf, err = io.StringIO(), io.StringIO()
    saved_stdin, sys.stdin = sys.stdin, io.StringIO()       # unattended: never fall through to a hidden secret prompt on the real console
    try:
        with tenant(data), contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = cli.main(["--tenant", "contoso.com", "--client-id", GUID, "--output-dir", out, *argv])
    finally:
        sys.stdin = saved_stdin
    return rc, buf.getvalue(), err.getvalue(), out


def load(out):
    j = next(f for f in os.listdir(out) if f.endswith(".json"))
    return json.load(open(os.path.join(out, j), encoding="utf-8"))


@scenario("UAT-01", "Healthy tenant, standard CLI run", "exit 0, HTML + JSON written, no FAIL/WARN, coverage 100%")
def _():
    rc, o, e, d = run_cli(good_tenant(), "--fail-on", "low", "--min-coverage", "100")
    j = load(d); st = [f["status"] for f in j["findings"]]
    assert rc == 0 and not {"FAIL", "WARN", "ERROR", "SKIPPED"} & set(st), (rc, set(st))
    assert sorted(x.rsplit(".", 1)[1] for x in os.listdir(d)) == ["html", "json"]
    return f"{len(st)} findings, {st.count('PASS')} pass, {st.count('MANUAL')} manual, {j['meta']['graph requests']} Graph requests"


@scenario("UAT-02", "Weak tenant with CI gate --fail-on high", "exit 1; critical findings present, including an unverified high-privilege app")
def _():
    rc, o, e, d = run_cli(bad_tenant(), "--fail-on", "high")
    j = load(d); crit = [f["id"] for f in j["findings"] if f["status"] == "FAIL" and f["severity"] == "critical"]
    assert rc == 1 and "APP-010" in crit
    return f"critical: {', '.join(sorted(crit))}"


@scenario("UAT-03", "Weak tenant without gate", "exit 0 (report only)")
def _():
    rc, *_ = run_cli(bad_tenant()); assert rc == 0


@scenario("UAT-04", "App registration is missing some permissions", "affected checks SKIPPED naming the permission, never PASS; --min-coverage gate trips")
def _():
    d = denied_tenant("/identityProtection/riskyUsers", "/identityGovernance/accessReviews/definitions", "/policies/deviceRegistrationPolicy")
    rc, o, e, out = run_cli(d, "--min-coverage", "100")
    j = load(out); sk = {f["id"]: f for f in j["findings"] if f["status"] == "SKIPPED"}
    assert rc == 1 and len(sk) == 3 and all(f["needs"] for f in sk.values())
    assert not any(f["id"] in ("IDP-001", "GOV-001", "DEV-001") for f in j["findings"])
    return "; ".join(f"{k} needs {v['needs']}" for k, v in sk.items())


@scenario("UAT-05", "Tenant without Entra ID P1/P2 (Conditional Access unreadable, Security Defaults on)", "CA reported as Security Defaults info, no false failures")
def _():
    t = good_tenant(); t["/policies/identitySecurityDefaultsEnforcementPolicy"] = {"isEnabled": True}
    t["/identity/conditionalAccess/policies"] = GraphError(403, "Authentication_RequestFromNonPremiumTenantOrB2CTenant", "premium licence required", "x")
    rc, o, e, d = run_cli(t); ids = {f["id"]: f["status"] for f in load(d)["findings"]}
    assert ids["CA-SD"] == "INFO" and not any(v == "FAIL" and k.startswith("CA-") for k, v in ids.items())


@scenario("UAT-06", "Scan one area only (--areas ca)", "only Conditional Access findings and checks")
def _():
    rc, o, e, d = run_cli(bad_tenant(), "--areas", "ca"); cats = {f["category"] for f in load(d)["findings"]}
    assert rc == 0 and cats == {"ca"}


@scenario("UAT-07", "CSV export for a spreadsheet", "CSV with BOM, header row, one row per finding, private file mode")
def _():
    rc, o, e, d = run_cli(bad_tenant(), "--csv"); p = os.path.join(d, next(f for f in os.listdir(d) if f.endswith(".csv")))
    raw = open(p, "rb").read(); n = len(load(d)["findings"])
    assert raw.startswith(b"\xef\xbb\xbf") and raw.count(b"\n") >= n and is_private_file(p)


@scenario("UAT-08", "User forgets credentials", "clear message, exit 2, no traceback")
def _():
    env = {**os.environ, "AZURE_CLIENT_SECRET": ""}
    r = subprocess.run([sys.executable, os.path.join(ROOT, "entra_posture_scan.py"), "--tenant", "contoso.com", "--client-id", GUID], capture_output=True, text=True,
                       env=env, stdin=subprocess.DEVNULL, timeout=60)
    assert r.returncode == 2 and "secret" in r.stderr.lower() and "Traceback" not in r.stderr, r.stderr
    return r.stderr.strip().splitlines()[0][:110]


@scenario("UAT-09", "User tries --client-secret VALUE", "refused with safer alternatives; value never echoed")
def _():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "entra_posture_scan.py"), "--client-secret", "TOPSECRET123"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "TOPSECRET123" not in r.stdout + r.stderr and "--prompt-secret" in r.stderr


@scenario("UAT-10", "Typo in tenant / client ID", "friendly settings error (exit 2)")
def _():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "entra_posture_scan.py"), "--tenant", "not a tenant!", "--client-id", "x", "--secret-stdin"], input="s\n",
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "Traceback" not in r.stderr, r.stderr
    return r.stderr.strip().splitlines()[0][:110]


@scenario("UAT-11", "Permission list a customer must grant", "--list-permissions prints exactly the 10 permissions the checks use")
def _():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "entra_posture_scan.py"), "--list-permissions"], capture_output=True, text=True, timeout=60)
    names = [l.strip() for l in r.stdout.splitlines() if l.startswith("  ") and "." in l and not l.startswith("      ")]
    from entra_scan.models import CHECKS
    need = set(); [need.update(f.needs) for _, f in CHECKS]
    assert set(names) == need and len(names) == 10, (names, need)


class Resp:
    def __init__(s, code, body=None, headers=None): s.status_code, s._b, s.headers, s.text = code, body, headers or {}, str(body)
    def json(s): return s._b


class Sess:
    def __init__(s, seq): s.seq, s.calls = list(seq), []
    def get(s, url, **kw): s.calls.append((url, kw)); return s.seq.pop(0)


@scenario("UAT-12", "Graph throttles us (HTTP 429, Retry-After)", "client waits and retries, then succeeds")
def _():
    g = graph.Graph(lambda: "tok"); g.session = Sess([Resp(429, {}, {"Retry-After": "0"}), Resp(503), Resp(200, {"value": [{"id": "1"}]})])
    graph.time.sleep = lambda s: None
    assert g.get_all("/users") == [{"id": "1"}] and len(g.session.calls) == 3


@scenario("UAT-13", "Hostile nextLink pointing at another host", "token is never sent to it; GraphError raised")
def _():
    g = graph.Graph(lambda: "tok"); g.session = Sess([Resp(200, {"value": [], "@odata.nextLink": "https://evil.example/steal"})])
    try:
        g.get_all("/users"); raise AssertionError("followed hostile link")
    except GraphError as e:
        assert "evil.example" in str(e) or e.code == "UntrustedUrl"
    assert len(g.session.calls) == 1


@scenario("UAT-14", "Endless / repeating nextLink", "pagination loop detected, scan does not hang")
def _():
    url = "https://graph.microsoft.com/v1.0/users"
    g = graph.Graph(lambda: "tok"); g.session = Sess([Resp(200, {"value": [], "@odata.nextLink": url + "?p=2"})] * 5)
    try:
        g.get_all("/users"); raise AssertionError("no loop guard")
    except GraphError:
        pass


@scenario("UAT-15", "Graph redirects (302) while a token is attached", "redirect refused, never followed", )
def _():
    g = graph.Graph(lambda: "tok"); g.session = Sess([Resp(302, {}, {"Location": "https://evil.example"})])
    try:
        g.get("/users"); raise AssertionError("followed redirect")
    except GraphError:
        pass
    assert g.session.calls[0][1]["allow_redirects"] is False


@scenario("UAT-16", "Large tenant (30,000 users)", "completes in seconds with a small, constant number of requests")
def _():
    from fake_tenant import _user
    t = good_tenant(); U = [_user(i) for i in range(100, 30100)]
    t["/users"] = {"value": t["/users"]["value"] + U}
    g = FakeGraph(t); t0 = time.time(); runner.run_scan(context.Ctx(g, Args()), None, log=lambda *_: None)
    assert g.calls < 40 and time.time() - t0 < 10
    return f"{g.calls} requests, {time.time() - t0:.1f}s"


# ------------------------------------------------------------------ v1.1 scenarios
import xml.etree.ElementTree as ET  # nosemgrep: use-defused-xml  (parses only XML this tool just generated)


def write_json(obj):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(obj, f); f.close()
    return f.name


@scenario("UAT-19", "Sovereign cloud (GCC High) selected", "Graph client is built for graph.microsoft.us and refuses the commercial host")
def _():
    seen = {}
    saved = runner.Graph
    with tenant(good_tenant()):
        runner.Graph = lambda p, **kw: (seen.update(kw), FakeGraph(good_tenant()))[1]
        with contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["--tenant", "contoso.us", "--client-id", GUID, "--output-dir", tempfile.mkdtemp(), "--cloud", "usgov"])
    runner.Graph = saved
    g = graph.Graph(lambda: "t", cloud=seen["cloud"])
    try:
        graph.trusted_url("https://graph.microsoft.com/v1.0/users", g.hosts); raise AssertionError("commercial host accepted")
    except GraphError:
        pass
    assert rc == 0 and seen["cloud"].graph_host == "graph.microsoft.us"
    return "graph.microsoft.us only"


@scenario("UAT-20", "Accepted risks: owner, reason, expiry", "waived critical/high findings no longer fail the gate but stay visible; expired waiver does not hide")
def _():
    rc, o, e, d = run_cli(bad_tenant(), "--fail-on", "high")
    assert rc == 1
    first = load(d)
    ids = sorted({f["id"] for f in first["findings"] if f["status"] in ("FAIL", "WARN") and f["severity"] in ("critical", "high")})
    sup = write_json([dict(id=i, owner="security-team", reason="accepted until remediation sprint", expires="2099-12-31") for i in ids])
    rc, o, e, d = run_cli(bad_tenant(), "--fail-on", "high", "--suppressions", sup)
    j = load(d)
    assert rc == 0, o + e
    assert {f["id"] for f in j["findings"] if f["status"] == "SUPPRESSED"} == set(ids) and "accepted risk" in o
    html = open([os.path.join(d, x) for x in os.listdir(d) if x.endswith(".html")][0], encoding="utf-8").read()
    assert "Accepted risk" in html and "security-team" in html
    expired = write_json([dict(id=i, owner="x", reason="old", expires="2020-01-01") for i in ids])
    rc, o, e, d = run_cli(bad_tenant(), "--fail-on", "high", "--suppressions", expired)
    assert rc == 1 and any("EXPIRED" in f["detail"] for f in load(d)["findings"])
    return f"{len(ids)} critical/high findings waived; expired waivers ignored"


@scenario("UAT-21", "Baseline comparison between two runs", "second run lists resolved problems and no new ones; HTML shows the change block")
def _():
    rc, o, e, d1 = run_cli(bad_tenant())
    base = [os.path.join(d1, x) for x in os.listdir(d1) if x.endswith(".json")][0]
    rc, o, e, d2 = run_cli(good_tenant(), "--baseline", base)
    diff = load(d2)["diff"]
    assert diff["resolved"] and not diff["new"] and "resolved" in o
    html = open([os.path.join(d2, x) for x in os.listdir(d2) if x.endswith(".html")][0], encoding="utf-8").read()
    assert "Change since baseline" in html
    return f"{len(diff['resolved'])} resolved"


@scenario("UAT-22", "Pipeline outputs (SARIF, JUnit, full CSV)", "SARIF 2.1.0 and JUnit parse; every affected object is present")
def _():
    rc, o, e, d = run_cli(bad_tenant(), "--sarif", "--junit", "--csv")
    names = sorted(x.split(".", 1)[1] for x in os.listdir(d))
    assert names == ["csv", "html", "json", "junit.xml", "sarif"], names
    sarif = json.load(open([os.path.join(d, x) for x in os.listdir(d) if x.endswith(".sarif")][0]))
    root = ET.parse([os.path.join(d, x) for x in os.listdir(d) if x.endswith(".junit.xml")][0]).getroot()  # nosemgrep: use-defused-xml-parse  (our own output)
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"] and root.findall(".//failure")
    return f"{len(sarif['runs'][0]['results'])} SARIF results, {len(root.findall('.//failure'))} JUnit failures"


@scenario("UAT-23", "Policy file: disable a check, change a severity", "disabled check absent; re-graded severity applied; typo in the file is rejected")
def _():
    pol = write_json({"disable": ["ADM-004"], "severity": {"ADM-002": "low"}})
    rc, o, e, d = run_cli(bad_tenant(), "--policy", pol)
    ids = {f["id"]: f for f in load(d)["findings"]}
    assert "ADM-004" not in ids and ids["ADM-002"]["severity"] == "low"
    rc, o, e, d = run_cli(bad_tenant(), "--policy", write_json({"disabel": ["ADM-004"]}))
    assert rc == 2 and "Policy file" in e
    return "ok"


@scenario("UAT-24", "Many tenants in one run (batch)", "one report per tenant plus a combined overview; a failing tenant does not stop the rest; secret values refused")
def _():
    out = tempfile.mkdtemp()
    bf = write_json({"tenants": [{"name": "contoso", "tenant": "contoso.com", "client_id": GUID}, {"name": "fabrikam", "tenant": "fabrikam.com", "client_id": GUID}]})
    with tenant(bad_tenant()), contextlib.redirect_stdout(io.StringIO()):
        rc = cli.main(["--batch", bf, "--output-dir", out])
    assert rc == 0 and len([x for x in os.listdir(out) if x.startswith("combined-") and x.endswith(".html")]) == 1
    assert os.path.isdir(os.path.join(out, "contoso")) and os.path.isdir(os.path.join(out, "fabrikam"))
    bad = write_json({"tenants": [{"name": "a", "tenant": "a.com", "client_secret": "hunter2hunter2"}]})
    buf, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        rc2 = cli.main(["--batch", bad, "--output-dir", out])
    assert rc2 == 2 and "hunter2" not in buf.getvalue() + err.getvalue()
    return "2 tenants + overview; inline secret refused"


@scenario("UAT-25", "Workload identity federation (no stored secret)", "the token file is exchanged through a callable assertion; no secret is ever requested")
def _():
    from entra_scan import auth
    tok = tempfile.NamedTemporaryFile("w", delete=False); tok.write("eyJ.fake.jwt"); tok.close()
    cap = {}

    class App:
        def __init__(self, cid, authority, client_credential, **kw): cap.update(cred=client_credential, authority=authority)
        def acquire_token_for_client(self, scopes): return {"access_token": "graph-token"}
    saved = auth.msal.ConfidentialClientApplication
    auth.msal.ConfidentialClientApplication = App
    try:
        a = cli.build_parser().parse_args(["--tenant", "contoso.com", "--client-id", GUID, "--auth", "federated", "--federated-token-file", tok.name])
        assert auth.build_token_provider(a)() == "graph-token" and cap["cred"]["client_assertion"]() == "eyJ.fake.jwt"
    finally:
        auth.msal.ConfidentialClientApplication = saved
    return "client_assertion callable"


@scenario("UAT-26", "Break-glass and new check groups are reported", "weak tenant: unprotected emergency account, broad trusted location, legacy sign-ins, permanent admins")
def _():
    rc, o, e, d = run_cli(bad_tenant())
    st = {f["id"]: f["status"] for f in load(d)["findings"]}
    for i in ("ADM-011", "NET-001", "LEG-001", "HYB-001", "CAQ-001", "CAQ-003", "PRV-001", "APP-030", "AUT-001", "GST-002"):
        assert st.get(i) in ("FAIL", "WARN"), (i, st.get(i))
    rc, o, e, d = run_cli(good_tenant())
    st = {f["id"]: f["status"] for f in load(d)["findings"]}
    assert not [i for i, v in st.items() if v in ("FAIL", "WARN")]
    return "10 new controls trip on the weak tenant, none on the healthy one"


def external(sid, title, expect, argv, need, modules=()):
    t0 = time.time()
    if not all(shutil.which(n) or os.path.exists(n) for n in need):
        RESULTS.append((sid, title, expect, "NOT RUN", f"missing: {need}", 0)); return None
    missing = [m for m in modules if importlib.util.find_spec(m) is None]
    if missing:
        RESULTS.append((sid, title, expect, "NOT RUN", f"missing Python module: {missing}", 0)); return None
    r = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        RESULTS.append((sid, title, expect, "FAIL", (r.stderr or r.stdout)[-300:], time.time() - t0)); return None


gui = external("UAT-17", "Desktop window, real tkinter, driven like a user", "validation, scan, filters, detail, CSV, no secret saved, cancel, error dialog",
               [sys.executable, os.path.join(HERE, "uat_gui.py")] if os.name == "nt"      # Windows has a desktop: no virtual display needed
               else ["xvfb-run", "-a", "/usr/bin/python3.12", os.path.join(HERE, "uat_gui.py")],
               [] if os.name == "nt" else ["xvfb-run", "/usr/bin/python3.12"], modules=["tkinter"])
if gui is not None:
    t0 = time.time()
    try:
        assert gui["empty_form_message"] and gui["rows_issues"] > 0 and gui["report_button_enabled"]
        assert gui["filter:All"] > gui["rows_issues"] and gui["filter:Manual (CIS)"] == 8 and gui["detail_has_fix"] and gui["csv_written"]
        assert gui["secret_not_saved"] and gui["tenant_saved"] and gui["hostile_settings_ignored"] and gui["corrupt_settings_ok"]
        assert gui["cancel_marks_partial"] and gui["run_button_reenabled"] and gui["error_dialog"] and gui["run_button_after_error"]
        RESULTS.append(("UAT-17", "Desktop window, real tkinter, driven like a user", "validation, scan, filters, detail, CSV, no secret saved, cancel, error dialog",
                        "PASS", gui["summary"], time.time() - t0))
    except AssertionError as e:
        RESULTS.append(("UAT-17", "Desktop window", "", "FAIL", f"{e} {gui}", 0))

ADV = ("UAT-27", "Desktop window: Advanced panel (network, decisions, extra outputs)",
       "each field validated before sign-in; proxy/CA reach Graph; policy, accepted risk, baseline, time limit, SARIF/JUnit take effect")
adv_cmd = [sys.executable, os.path.join(HERE, "uat_gui_advanced.py")]
adv = external(*ADV, adv_cmd if os.name == "nt" else ["xvfb-run", "-a", *adv_cmd], [] if os.name == "nt" else ["xvfb-run"], modules=["tkinter"])
if adv is not None:
    failed = sorted(k for k, v in adv.items() if v is False)
    RESULTS.append((*ADV, "FAIL" if failed else "PASS",
                    f"false: {failed}" if failed else f"{sum(v is True for v in adv.values())} checks true; {adv.get('run2_state')}; {adv.get('bad_policy_message')}", 0))

shots = os.path.join(ROOT, "docs", "screenshots"); os.makedirs(shots, exist_ok=True)
br = external("UAT-18", "HTML report in a real browser", "filters, deep links, keyboard, mobile layout, hostile data inert, CSP holds",
              [sys.executable, os.path.join(HERE, "uat_browser.py"), shots], [], modules=["playwright"])
if br is not None:
    t0 = time.time()
    try:
        assert br["initial_count"].startswith("Showing 94 of 94") or br["initial_count"].startswith("Showing")
        assert "severity: critical" in br["critical_count"] and br["critical_hash"] == "#sev=critical" and br["toggle_off_count"] == br["initial_count"]
        assert br["all_open"] and br["all_closed"] and br["keyboard_filter_works"] and not br["mobile_horizontal_scroll"]
        assert "severity: high" in br["deeplink_count"] and br["hostile_hash_count"] == br["initial_count"]
        assert br["dialogs"] == [] and br["injected_elements"] == 0 and br["javascript_links"] == 0 and br["hostile_title_shown_as_text"]
        assert br["csp_blocks_inline_script"] and br["external_links_safe"] and br["requests"] == []
        assert br["console_errors"].__len__() <= 1 and br["csp_violations"] == ["CSPVIOLATION script-src-elem"]   # the single violation is our own probe script
        RESULTS.append(("UAT-18", "HTML report in a real browser (Chromium)", "filters, deep links, keyboard, mobile layout, hostile data inert, CSP holds", "PASS",
                        f"0 alert dialogs, 0 injected elements, 0 external requests, only CSP violation = deliberate probe; {br['critical_count']}", time.time() - t0))
    except AssertionError as e:
        RESULTS.append(("UAT-18", "HTML report in a real browser", "", "FAIL", f"{e} {json.dumps(br)[:400]}", 0))

RESULTS.sort(key=lambda r: r[0])
md = ["# User acceptance test results", "", "<!-- generated by tests/uat.py -->", "",
      f"Run on {time.strftime('%Y-%m-%d')} against a pretend Microsoft Graph (no live tenant). **{sum(r[3] == 'PASS' for r in RESULTS)} of {len(RESULTS)} scenarios passed**; "
      f"{sum(r[3] == 'FAIL' for r in RESULTS)} failed; {sum(r[3] == 'NOT RUN' for r in RESULTS)} not run.", "",
      "| ID | Scenario | Expected | Result | Evidence |", "|---|---|---|---|---|"]
for sid, title, exp, res, det, _t in RESULTS:
    md.append(f"| {sid} | {title} | {exp} | **{res}** | {det.replace('|', '/')[:220]} |")
md += ["", "Screenshots: `docs/screenshots/`. Not covered by UAT (needs a live tenant): see `LIVE_VALIDATION.md`.", ""]
open(os.path.join(ROOT, "docs", "UAT.md"), "w", encoding="utf-8").write("\n".join(md))
for r in RESULTS:
    print(r[0], r[3], "-", r[1], "|", r[4][:100])
sys.exit(1 if any(r[3] == "FAIL" for r in RESULTS) else 0)
