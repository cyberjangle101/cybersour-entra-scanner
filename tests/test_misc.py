"""Permissions hygiene, metadata completeness, docs freshness, CLI, GUI logic, report output."""
import csv, json, os, re, shutil, subprocess, sys, tempfile
import pytest
from entra_scan import auth, cli, gui, metadata, permissions, report, runner
from entra_scan.models import CHECKS, ConfigError, Finding
from fake_tenant import Args, FakeGraph, bad_tenant, good_tenant, is_private_file
from entra_scan import context

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANARY = "CANARY~secret.value-123"


def test_permission_hygiene():
    used = set()
    for _, fn in CHECKS:
        used |= set(fn.needs)
    assert used == set(permissions.PURPOSE), used ^ set(permissions.PURPOSE)
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    for n in used:
        assert permissions.PERMISSION_RX.match(n) and n in readme
    assert len(used) == 10
    for fn_ in ("README.md", "SECURITY.md"):
        assert "intune read" not in open(os.path.join(ROOT, fn_), encoding="utf-8").read().lower()


def test_every_finding_id_has_learn_and_setting():
    ids = set()
    for t in (good_tenant(), bad_tenant()):
        ids |= {f.id for f in runner.run_scan(context.Ctx(FakeGraph(t), Args()), None, log=lambda *_: None)}
    for i in ids:
        if i.startswith(("SKIP-", "ERR-", "CA-NA", "CA-SD", "CA-000")):
            continue
        assert i in metadata.SETTING, f"{i} has no setting description"
        assert metadata.LEARN.get(i, "").startswith("https://learn.microsoft.com/"), f"{i} has no Learn link"


def test_docs_are_current():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import gen_docs
    for name, text in (("PERMISSIONS.md", gen_docs.permissions_md()), ("CIS_COVERAGE.md", gen_docs.coverage_md())):
        assert open(os.path.join(ROOT, "docs", name), encoding="utf-8").read() == text, f"run tools/gen_docs.py ({name})"


def ns(**kw):
    d = dict(auth="secret", secret_stdin=False, client_secret_file=None, prompt_secret=False, prompt_passphrase=False,
             cert_path=None, cert_passphrase=None, client_secret=None)
    d.update(kw)
    return type("A", (), d)()


class In:
    def __init__(self, t, tty=False): self.t, self.tty = t, tty
    def readline(self): return self.t.splitlines(True)[0] if self.t else ""
    def isatty(self): return self.tty


def test_credential_sources(tmp_path):
    a = ns(secret_stdin=True); auth.resolve_credentials(a, environ={}, stdin=In(CANARY + "\n")); assert a.client_secret == CANARY
    with pytest.raises(ConfigError): auth.resolve_credentials(ns(secret_stdin=True), environ={}, stdin=In("\n"))
    f = tmp_path / "s"; f.write_text("\n " + CANARY + " \nx\n"); os.chmod(f, 0o600)
    a = ns(client_secret_file=str(f)); auth.resolve_credentials(a, environ={}, stdin=In("")); assert a.client_secret == CANARY
    with pytest.raises(ConfigError): auth.resolve_credentials(ns(client_secret_file=str(tmp_path / "nope")), environ={}, stdin=In(""))
    with pytest.raises(ConfigError): auth.resolve_credentials(ns(client_secret_file=str(f), secret_stdin=True), environ={}, stdin=In("x"))
    a = ns(prompt_secret=True); auth.resolve_credentials(a, environ={}, stdin=In("", True), prompt=lambda m: CANARY); assert a.client_secret == CANARY
    a = ns(); auth.resolve_credentials(a, environ={"AZURE_CLIENT_SECRET": "e"}, stdin=In("", True), prompt=lambda m: 1 / 0); assert a.client_secret is None
    a = ns(); auth.resolve_credentials(a, environ={}, stdin=In("", False), prompt=lambda m: 1 / 0); assert a.client_secret is None


def test_null_device_stdin_is_not_interactive():
    """Windows: NUL reports isatty() True; treating it as a keyboard made unattended runs hang in getpass."""
    with open(os.devnull) as nul:
        assert not auth.is_interactive(nul)
        a = ns(); auth.resolve_credentials(a, environ={}, stdin=nul, prompt=lambda m: 1 / 0); assert a.client_secret is None


def run_cli(*argv, inp=None):
    return subprocess.run([sys.executable, os.path.join(ROOT, "entra_posture_scan.py"), *argv], capture_output=True, text=True, input=inp,
                          env={**os.environ, "AZURE_CLIENT_SECRET": ""}, timeout=60)


def test_cli_refuses_secret_value_and_abbreviations():
    for argv in (["--client-secret", CANARY], ["--client-secret=" + CANARY]):
        r = run_cli(*argv)
        assert r.returncode == 2 and CANARY not in r.stdout + r.stderr
    assert run_cli("--client-secr", "x").returncode == 2
    assert run_cli("--max-users", "0").returncode == 2
    r = run_cli("--list-permissions")
    assert r.returncode == 0 and "Policy.Read.DeviceConfiguration" in r.stdout
    assert run_cli("--list-checks").returncode == 0


def test_cli_missing_settings_is_clean_error():
    r = run_cli("--tenant", "bad tenant!", "--client-id", "x", "--secret-stdin", inp="s\n")
    assert r.returncode == 2 and "Traceback" not in r.stderr


def test_cli_end_to_end_with_fake_graph(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "build_token_provider", lambda a: (lambda: "tok"))
    monkeypatch.setattr(runner, "Graph", lambda p, **kw: FakeGraph(bad_tenant()))
    out = tmp_path / "o"
    rc = cli.main(["--tenant", "contoso.com", "--client-id", "11111111-1111-1111-1111-111111111111", "--output-dir", str(out), "--csv", "--fail-on", "high"])
    assert rc == 1
    files = sorted(p.suffix for p in out.iterdir()); assert files == [".csv", ".html", ".json"]
    assert is_private_file(next(out.glob("*.json")))
    monkeypatch.setattr(runner, "Graph", lambda p, **kw: FakeGraph(good_tenant()))
    assert cli.main(["--tenant", "contoso.com", "--client-id", "11111111-1111-1111-1111-111111111111", "--output-dir", str(out), "--fail-on", "low", "--min-coverage", "100"]) == 0


# ------------------------------------------------------------------ GUI logic
FORM = {"auth": "secret", "tenant": "contoso.com", "client_id": "x", "secret": "s", "areas": {"ca": True}, "max_users": "0", "output_dir": ""}


def test_gui_build_args_validation():
    keys = list(runner.AREAS)
    a = gui.build_args(FORM, keys); assert a.areas == ["ca"] and a.max_users == 50000 and a.output_dir == "./reports"
    for bad in ({"tenant": ""}, {"client_id": " "}, {"auth": "device"}, {"areas": {}}, {"areas": None}, {"max_users": "-1"}, {"max_users": "abc"}, {"secret": ""}):
        with pytest.raises(ValueError):
            gui.build_args({**FORM, **bad}, keys)
    with pytest.raises(ValueError): gui.build_args("nope", keys)
    with pytest.raises(ValueError): gui.build_args({**FORM, "auth": "cert", "cert_path": "/nonexistent", "cert_thumbprint": "a"}, keys)


def test_gui_filters_and_summary():
    f = runner.run_scan(context.Ctx(FakeGraph(bad_tenant()), Args()), None, log=lambda *_: None)
    s = gui.sort_findings(f)
    assert s[0].status == "FAIL" and s[0].severity == "critical"
    assert all(x.status in ("FAIL", "WARN") for x in gui.filter_findings(f, gui.FILTERS[0]))
    assert len(gui.filter_findings(f, "Manual (CIS)")) == 8
    assert "Critical:" in gui.summarize(f) and gui.finding_detail(s[0])


# ------------------------------------------------------------------ report
def hostile_findings():
    x = "<script>alert(1)</script>"
    return [Finding("T-1", "ca", x, "FAIL", "high", x, x, [x, "=HYPERLINK(\"http://evil\")"], cis=x, learn="javascript:alert(1)", setting=x),
            Finding("T-2", "<img src=x onerror=alert(1)>", x, "PASS"),
            Finding("T-3", "roles", "ok", "MANUAL", "info", "d", learn="https://learn.microsoft.com/en-us/entra/x")]


def test_report_escapes_and_has_csp():
    h = report.render_html({"tenant": x_ if (x_ := "<b>t</b>") else ""}, hostile_findings(), runner.AREAS)
    body = h.split("<script nonce")[0]
    assert "<script>alert(1)</script>" not in h and "<img src=x" not in h and "javascript:alert" not in h
    assert "Content-Security-Policy" in h and "script-src 'nonce-" in h and "&lt;b&gt;t&lt;/b&gt;" in body
    assert h.count('<script nonce') == 1
    assert 'href="https://learn.microsoft.com/en-us/entra/x"' in h and 'rel="noopener noreferrer"' in h


def test_csv_formula_injection(tmp_path):
    p = tmp_path / "f.csv"; report.export_csv(hostile_findings(), p)
    cells = [c for row in csv.reader(open(p, encoding="utf-8-sig")) for c in row]
    assert not any(c[:1] in "=+-@" and c for c in cells if c)
    assert is_private_file(p)


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_report_filters_in_dom_shim(tmp_path):
    F = Finding
    fs = [F("A-1", "roles", "a", "FAIL", "critical", "d"), F("B-1", "ca", "b", "FAIL", "high", "d"), F("C-1", "tenant", "c", "FAIL", "high", "d"),
          F("D-1", "ca", "d", "WARN", "medium", "d"), F("E-1", "ca", "e", "PASS"), F("M-1", "manual", "m", "MANUAL", "info", "d")]
    p = tmp_path / "r.html"; p.write_text(report.render_html({"t": "x"}, fs, runner.AREAS), encoding="utf-8")
    run = lambda h="": json.loads(subprocess.run(["node", os.path.join(ROOT, "tests", "report_dom_shim.js"), str(p), h], capture_output=True, text=True, check=True).stdout)
    r = run()
    assert len(r["initial"]["visible"]) == 6
    assert r["critical"]["visible"] == ["roles:FAIL:critical"] and r["critical"]["url"] == "#sev=critical"
    assert len(r["toggled_off"]["visible"]) == 6
    assert sorted(r["high"]["visible"]) == ["ca:FAIL:high", "tenant:FAIL:high"]
    assert r["passed"]["visible"] == ["ca:PASS:-"] and len(r["issues"]["visible"]) == 4 and r["expanded"] is True
    assert run("#sev=high&mod=ca")["initial"]["visible"] == ["ca:FAIL:high"]
