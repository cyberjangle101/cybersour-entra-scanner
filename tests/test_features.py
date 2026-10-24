"""v1.1 features: clouds, federated / managed-identity / Key Vault sign-in, time budgets, SARIF, JUnit, batch, CLI wiring."""
import json
import os
import xml.etree.ElementTree as ET  # nosemgrep: use-defused-xml  (parses only XML this tool just generated)
from argparse import Namespace

import pytest
import requests

from entra_scan import auth, batch, cli, context, export, graph as graph_mod, postprocess as pp, report, runner
from entra_scan.clouds import CLOUDS, get_cloud
from entra_scan.models import ConfigError, GraphError
from fake_tenant import Args, FakeGraph, bad_tenant, good_tenant, is_private_file

GUID = "11111111-1111-1111-1111-111111111111"


def scan(tenant, **kw):
    ctx = context.Ctx(FakeGraph(tenant), Args(**kw))
    fs = runner.run_scan(ctx, None, log=lambda *_: None)
    return pp.finalize(fs, runner.AREAS)[0]


# ------------------------------------------------------------------ clouds
def test_unknown_cloud_is_an_error_not_a_fallback():
    with pytest.raises(ConfigError):
        get_cloud("mars")


@pytest.mark.parametrize("name", sorted(CLOUDS))
def test_graph_only_talks_to_its_own_cloud(name):
    g = graph_mod.Graph(lambda: "tok", cloud=get_cloud(name))
    for other in CLOUDS.values():
        if other.graph_host != g.cloud.graph_host:
            with pytest.raises(GraphError):
                graph_mod.trusted_url(f"https://{other.graph_host}/v1.0/users", g.hosts)
    assert graph_mod.trusted_url(g.cloud.graph_url + "/users", g.hosts)


def test_proxy_and_ca_bundle_are_applied(tmp_path):
    g = graph_mod.Graph(lambda: "t", proxy="http://proxy:8080", ca_bundle=str(tmp_path / "ca.pem"), timeout=7)
    assert g.session.proxies["https"] == "http://proxy:8080" and g.session.verify.endswith("ca.pem") and g.timeout == 7


# ------------------------------------------------------------------ federated / managed identity / Key Vault
def test_federated_token_file(tmp_path):
    f = tmp_path / "tok"
    f.write_text("jwt-value\n")
    assert auth.read_federated_assertion(Namespace(federated_token_file=str(f), cloud="commercial"), environ={}) == "jwt-value"
    f.write_text("")
    with pytest.raises(ConfigError):
        auth.read_federated_assertion(Namespace(federated_token_file=str(f), cloud="commercial"), environ={})
    with pytest.raises(ConfigError):
        auth.read_federated_assertion(Namespace(federated_token_file=None, cloud="commercial"), environ={})


class FakeSession:
    def __init__(self, status=200, body=None):
        self.status, self.body, self.calls = status, body or {}, []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        s = self
        return type("R", (), {"status_code": s.status, "json": lambda self: s.body})()


def test_github_oidc_host_is_validated_before_the_runner_token_is_sent():
    args = Namespace(federated_token_file=None, cloud="usgov", federated_audience=None, proxy=None, ca_bundle=None)
    evil = {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://evil.example/token?x=1", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-secret"}
    sess = FakeSession()
    with pytest.raises(ConfigError):
        auth.read_federated_assertion(args, environ=evil, session=sess)
    assert sess.calls == []
    ok = {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/abc?api=1", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-secret"}
    sess = FakeSession(200, {"value": "oidc-jwt"})
    assert auth.read_federated_assertion(args, environ=ok, session=sess) == "oidc-jwt"
    url, kw = sess.calls[0]
    assert "audience=" in url and "USGov" in requests.utils.unquote(url) and kw["allow_redirects"] is False


@pytest.mark.parametrize("url", ["http://v.vault.azure.net/secrets/s", "https://evil.example/secrets/s", "https://v.vault.azure.net.evil.com/secrets/s",
                                 "https://v.vault.usgovcloudapi.net/secrets/s"])
def test_keyvault_url_must_be_a_vault_in_the_chosen_cloud(url):
    with pytest.raises(ConfigError):
        auth.fetch_keyvault_secret(url, Namespace(cloud="commercial"), mi_client=object(), session=FakeSession())


def test_keyvault_secret_fetch():
    mi = type("MI", (), {"acquire_token_for_client": lambda self, resource: {"access_token": "kvtok"}})()
    sess = FakeSession(200, {"value": " s3cret \n"})
    v = auth.fetch_keyvault_secret("https://myvault.vault.azure.net/secrets/scanner", Namespace(cloud="commercial"), mi_client=mi, session=sess)
    assert v == "s3cret" and "api-version=7.4" in sess.calls[0][0]
    with pytest.raises(ConfigError):
        auth.fetch_keyvault_secret("https://myvault.vault.azure.net/secrets/scanner", Namespace(cloud="commercial"), mi_client=mi, session=FakeSession(403))


def test_managed_identity_provider(monkeypatch):
    seen = {}
    mi = type("MI", (), {"acquire_token_for_client": lambda self, resource: seen.setdefault("res", resource) and {"access_token": "mitoken"}})()
    monkeypatch.setattr(auth, "_managed_identity_client", lambda a: mi)
    assert auth.build_token_provider(Namespace(auth="managed-identity", cloud="china"))() == "mitoken"
    assert seen["res"] == "https://microsoftgraph.chinacloudapi.cn"


def test_federated_provider_uses_a_callable_assertion(tmp_path, monkeypatch):
    f = tmp_path / "t"
    f.write_text("jwt")
    captured = {}

    class App:
        def __init__(self, cid, authority, client_credential, **kw):
            captured.update(authority=authority, cred=client_credential, kw=kw)

        def acquire_token_for_client(self, scopes):
            captured["scopes"] = scopes
            return {"access_token": "x"}
    monkeypatch.setattr(auth.msal, "ConfidentialClientApplication", App)
    a = Namespace(auth="federated", tenant="contoso.com", client_id=GUID, cloud="usgov", federated_token_file=str(f), federated_audience=None,
                  proxy="http://p:1", ca_bundle=None, timeout=5)
    assert auth.build_token_provider(a)() == "x"
    assert captured["authority"] == "https://login.microsoftonline.us/contoso.com" and captured["scopes"] == ["https://graph.microsoft.us/.default"]
    assert captured["cred"]["client_assertion"]() == "jwt" and captured["kw"]["proxies"]["https"] == "http://p:1"


# ------------------------------------------------------------------ time budget
def test_check_timeout_marks_check_skipped_not_passed():
    class Slow(FakeGraph):
        def _lookup(self, path, params):
            if path == "/identityProtection/riskyUsers":
                raise GraphError(408, "TimeBudgetExceeded", "The time budget for this check ran out", path)
            return super()._lookup(path, params)
    ctx = context.Ctx(Slow(good_tenant()), Args(check_timeout=5))
    fs = {f.id: f for f in runner.run_scan(ctx, None, log=lambda *_: None)}
    skipped = [f for f in fs.values() if f.status == "SKIPPED"]
    assert skipped and all("time budget" in f.detail for f in skipped)
    assert not any(f.status == "ERROR" for f in fs.values())


def test_max_runtime_makes_the_scan_partial():
    ctx = context.Ctx(FakeGraph(good_tenant()), Args(max_runtime=-1))
    fs = runner.run_scan(ctx, None, log=lambda *_: None)
    assert fs == [] and "maximum runtime" in ctx.partial_reason


# ------------------------------------------------------------------ exports
def test_sarif_structure_and_full_evidence():
    fs = scan(bad_tenant())
    s = json.loads(export.sarif_text({"tenant": "Contoso", "tenant id": GUID}, fs))
    run = s["runs"][0]
    assert s["version"] == "2.1.0" and run["results"] and {r["id"] for r in run["tool"]["driver"]["rules"]} >= {r["ruleId"] for r in run["results"]}
    assert all(r["level"] in ("error", "warning", "note") and r["partialFingerprints"]["entraPosture/v1"] for r in run["results"])
    big = next(f for f in fs if f.status in ("FAIL", "WARN"))
    big.evidence = [f"user{i} [id{i}]" for i in range(300)]
    again = json.loads(export.sarif_text({"tenant": "x"}, fs))
    assert len(next(r for r in again["runs"][0]["results"] if r["ruleId"] == big.id)["properties"]["evidence"]) == 300


def test_sarif_marks_accepted_risk_as_suppressed():
    fs = scan(bad_tenant())
    f = next(x for x in fs if x.status == "FAIL")
    f.suppression, f.status = {"owner": "sec", "reason": "ok", "expires": "2099-01-01", "original_status": "FAIL"}, "SUPPRESSED"
    res = next(r for r in json.loads(export.sarif_text({}, fs))["runs"][0]["results"] if r["ruleId"] == f.id)
    assert res["suppressions"][0]["status"] == "accepted" and "sec" in res["suppressions"][0]["justification"]


def test_junit_is_well_formed_and_escapes_hostile_names():
    fs = scan(bad_tenant())
    f = next(x for x in fs if x.status == "FAIL")
    f.evidence = ['<script>alert(1)</script> & "quote" ]]>']
    xml = export.junit_text({}, fs, runner.AREAS)
    root = ET.fromstring(xml)                                       # raises if the XML is malformed
    assert root.tag == "testsuites" and root.findall(".//failure") and "<script>" not in xml


def test_html_caps_evidence_but_json_and_csv_do_not(tmp_path):
    fs = scan(bad_tenant())
    f = next(x for x in fs if x.status == "FAIL")
    f.evidence = [f"user{i} [id{i}]" for i in range(100)]
    page = report.render_html({}, fs, runner.AREAS)
    assert "user24 [id24]" in page and "user25 [id25]" not in page and "75 more" in page
    report.export_csv(fs, tmp_path / "r.csv")
    assert "user99 [id99]" in (tmp_path / "r.csv").read_text(encoding="utf-8-sig")


def test_html_summary_and_diff_blocks_render_escaped():
    fs = scan(bad_tenant())
    sm = pp.summarize(fs, runner.AREAS)
    page = report.render_html({}, fs, runner.AREAS, sm, {"new": ["<b>X</b>"], "resolved": [], "changed": [], "not_run_now": []})
    assert "Executive summary" in page and "&lt;b&gt;X&lt;/b&gt;" in page and "<b>X</b>" not in page


# ------------------------------------------------------------------ batch
def write(tmp_path, obj, name="b.json"):
    p = tmp_path / name
    p.write_text(json.dumps(obj))
    return p


@pytest.mark.parametrize("entry", [{"name": "a", "tenant": "t", "client_secret": "hunter2"}, {"name": "a", "tenant": "t", "cert_passphrase": "x"},
                                   {"name": "a", "tenant": "t", "password": "x"}, {"name": "a/../b", "tenant": "t"}, {"name": "", "tenant": "t"},
                                   {"name": "a", "tenant": "t", "weird": 1}])
def test_batch_rejects_secret_values_and_bad_names(tmp_path, entry):
    with pytest.raises(ConfigError) as e:
        batch.load_batch(write(tmp_path, {"tenants": [entry]}))
    assert "hunter2" not in str(e.value)


def test_batch_runs_every_tenant_even_if_one_fails(tmp_path):
    p = write(tmp_path, {"tenants": [{"name": "good", "tenant": "g.com", "client_id": GUID}, {"name": "broken", "tenant": "b.com", "client_id": GUID},
                                     {"name": "bad", "tenant": "x.com", "client_id": GUID}]})
    tenants = {"g.com": good_tenant, "x.com": bad_tenant}

    def execute(args, log):
        if args.tenant == "b.com":
            raise ConfigError("no credentials <img src=x>")
        fs = pp.finalize(runner.run_scan(context.Ctx(FakeGraph(tenants[args.tenant]()), Args()), None, log=lambda *_: None), runner.AREAS)[0]
        out = tmp_path / "out" / args.tenant
        out.mkdir(parents=True, exist_ok=True)
        html = out / "r.html"
        html.write_text("x")
        return {"findings": fs, "summary": pp.summarize(fs, runner.AREAS), "coverage": (33, 0, 100), "html_path": html}
    base = Namespace(output_dir=str(tmp_path / "out"))
    rows, combined = batch.run_batch(p, base, execute, log=lambda *_: None)
    assert [r["ok"] for r in rows] == [True, False, True]
    page = combined.read_text()
    assert "Scan failed" in page and "&lt;img" in page and "<img" not in page
    assert rows[0]["score"] > rows[2]["score"]


# ------------------------------------------------------------------ CLI wiring end to end
def test_cli_all_new_outputs_and_inputs(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "build_token_provider", lambda a: (lambda: "tok"))
    seen = {}

    def fake_graph(p, **kw):
        seen.update(kw)
        return FakeGraph(bad_tenant())
    monkeypatch.setattr(runner, "Graph", fake_graph)
    out = tmp_path / "o"
    common = ["--tenant", "contoso.com", "--client-id", GUID, "--output-dir", str(out), "--cloud", "usgov", "--proxy", "http://p:3128", "--sarif", "--junit",
              "--log-file", str(tmp_path / "scan.log")]
    pol = write(tmp_path, {"disable": ["ADM-004"], "severity": {"ADM-002": "low"}}, "pol.json")
    sup = write(tmp_path, [{"id": "ADM-001", "owner": "sec", "reason": "accepted", "expires": "2099-01-01"}], "sup.json")
    assert cli.main(common + ["--policy", str(pol), "--suppressions", str(sup)]) == 0
    assert seen["cloud"].name == "usgov" and seen["proxy"] == "http://p:3128"
    report_json = next(out.glob("entra-posture-*.json"))
    data = json.loads(report_json.read_text())
    ids = {f["id"]: f for f in data["findings"]}
    assert "ADM-004" not in ids and ids["ADM-001"]["status"] == "SUPPRESSED" and ids["ADM-002"]["severity"] == "low"
    assert data["summary"]["grade"] and list(out.glob("*.sarif")) and list(out.glob("*.junit.xml"))
    assert is_private_file(tmp_path / "scan.log")
    # second run against the first report as a baseline, with a hardened tenant: things get resolved
    monkeypatch.setattr(runner, "Graph", lambda p, **kw: FakeGraph(good_tenant()))
    out2 = tmp_path / "o2"
    assert cli.main(["--tenant", "contoso.com", "--client-id", GUID, "--output-dir", str(out2), "--baseline", str(report_json)]) == 0
    diff = json.loads(next(out2.glob("*.json")).read_text())["diff"]
    assert diff["resolved"] and not diff["new"]


def test_cli_bad_input_files_are_exit_2(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "build_token_provider", lambda a: (lambda: "tok"))
    bad = tmp_path / "x.json"
    bad.write_text("{nope")
    base = ["--tenant", "contoso.com", "--client-id", GUID, "--output-dir", str(tmp_path / "o")]
    for flag in ("--policy", "--suppressions", "--baseline"):
        assert cli.main(base + [flag, str(bad)]) == 2


def test_cli_batch_exit_codes(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "build_token_provider", lambda a: (lambda: "tok"))
    monkeypatch.setattr(runner, "Graph", lambda p, **kw: FakeGraph(bad_tenant()))
    b = write(tmp_path, {"tenants": [{"name": "one", "tenant": "contoso.com", "client_id": GUID}]})
    out = tmp_path / "o"
    assert cli.main(["--batch", str(b), "--output-dir", str(out)]) == 0
    assert list(out.glob("combined-*.html")) and (out / "one").is_dir()
    assert cli.main(["--batch", str(b), "--output-dir", str(out), "--fail-on", "high"]) == 1


# ------------------------------------------------------------------ GUI logic for the new options
def _form(**kw):
    base = {"auth": "secret", "tenant": "contoso.com", "client_id": "x", "secret": "s", "areas": {"ca": True}, "max_users": "0", "output_dir": ""}
    base.update(kw)
    return base


def test_gui_new_modes_and_options(tmp_path):
    from entra_scan import gui
    keys = list(runner.AREAS)
    tok, pol = tmp_path / "t", tmp_path / "p.json"
    tok.write_text("jwt")
    pol.write_text("{}")
    a = gui.build_args(_form(auth="federated", secret="", federated_token_file=str(tok), cloud="usgov", proxy="http://p:1", policy=str(pol),
                             check_timeout="30", sarif=True), keys)
    assert a.auth == "federated" and a.cloud == "usgov" and a.check_timeout == 30 and a.sarif is True and a.junit is False
    a = gui.build_args(_form(auth="managed-identity", tenant="", client_id="", secret=""), keys)
    assert a.auth == "managed-identity"
    for bad in ({"auth": "federated", "secret": "", "federated_token_file": ""}, {"cloud": "mars"}, {"proxy": "ftp://x"}, {"policy": str(tmp_path / "nope")},
                {"check_timeout": "-3"}, {"check_timeout": "abc"}, {"baseline": str(tmp_path)}):
        with pytest.raises(ValueError):
            gui.build_args(_form(**bad), keys)


def test_gui_filters_summary_and_detail_cap():
    from entra_scan import gui
    fs = scan(bad_tenant())
    f = next(x for x in fs if x.status == "FAIL")
    f.suppression, f.status = {"owner": "sec", "reason": "r", "expires": "2099-01-01"}, "SUPPRESSED"
    assert [x.id for x in gui.filter_findings(fs, "Accepted risk")] == [f.id] and "Accepted risk: 1" in gui.summarize(fs)
    f.evidence = [f"u{i}" for i in range(500)]
    text = gui.finding_detail(f)
    assert "u199" in text and "u200" not in text and "300 more" in text and "Accepted risk by sec" in text


# ------------------------------------------------------------------ setup script stays in step with the scanner
def test_setup_script_requests_exactly_the_scanner_permissions():
    import re
    from entra_scan import permissions
    text = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "setup_app_registration.ps1"), encoding="utf-8").read()
    block = re.search(r"\$Permissions = @\((.*?)\)", text, re.S).group(1)
    assert set(re.findall(r"'([A-Za-z.]+)'", block)) == set(permissions.PURPOSE)
    assert "ReadWrite" not in block                                  # the scanner's own app never gets a write permission
    assert re.search(r"\$Permissions = ", text) and "-WhatIf" in text


def test_every_check_permission_is_one_of_the_ten():
    from entra_scan import permissions
    from entra_scan.models import CHECKS
    used = {p for _a, fn in CHECKS for p in fn.needs}
    assert used <= set(permissions.PURPOSE) and len(permissions.PURPOSE) == 10
