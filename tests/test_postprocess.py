"""Policy overrides, accepted-risk suppressions, baseline diff, score and snippets."""
import datetime as dt
import json

import pytest

from entra_scan import context, postprocess as pp, runner
from entra_scan.models import ConfigError
from fake_tenant import Args, FakeGraph, bad_tenant, good_tenant


def findings(tenant):
    return runner.run_scan(context.Ctx(FakeGraph(tenant), Args()), None, log=lambda *_: None)


def write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj))
    return p


def test_policy_disables_and_regrades(tmp_path):
    fs = findings(bad_tenant())
    pol = pp.load_policy(write(tmp_path, "p.json", {"disable": ["ADM-004"], "severity": {"ADM-002": "low"}}))
    kept, off, graded = pp.apply_policy(fs, pol)
    assert "ADM-004" not in {f.id for f in kept} and off == ["ADM-004"] and graded == ["ADM-002"]
    assert next(f for f in kept if f.id == "ADM-002").severity == "low"


@pytest.mark.parametrize("bad", [{"disable": "ADM-004"}, {"severity": {"X": "urgent"}}, {"nope": 1}, [1]])
def test_policy_rejects_bad_shapes(tmp_path, bad):
    with pytest.raises(ConfigError):
        pp.load_policy(write(tmp_path, "p.json", bad))


def test_suppression_needs_owner_reason_expiry(tmp_path):
    with pytest.raises(ConfigError):
        pp.load_suppressions(write(tmp_path, "s.json", [{"id": "CA-001", "owner": "a", "reason": "r"}]))
    with pytest.raises(ConfigError):
        pp.load_suppressions(write(tmp_path, "s.json", [{"id": "CA-001", "owner": "a", "reason": "r", "expires": "tomorrow"}]))


def test_suppression_applies_and_expires(tmp_path):
    today = dt.date(2026, 10, 24)
    rule = lambda exp, **kw: pp.load_suppressions(write(tmp_path, "s.json", [dict(id="ADM-001", owner="sec", reason="accepted", expires=exp, **kw)]))
    fs = findings(bad_tenant())
    assert next(f for f in fs if f.id == "ADM-001").status == "FAIL"
    pp.apply_suppressions(fs, rule("2026-12-31"), today)
    f = next(f for f in fs if f.id == "ADM-001")
    assert f.status == "SUPPRESSED" and f.suppression["owner"] == "sec" and f.suppression["original_status"] == "FAIL"
    fs = findings(bad_tenant())
    pp.apply_suppressions(fs, rule("2026-01-01"), today)
    f = next(f for f in fs if f.id == "ADM-001")
    assert f.status == "FAIL" and "EXPIRED" in f.detail


def test_scoped_suppression_does_not_hide_new_objects(tmp_path):
    fs = findings(bad_tenant())
    rules = pp.load_suppressions(write(tmp_path, "s.json", [dict(id="ADM-002", owner="o", reason="r", expires="2099-01-01", scope=["nobody-like-this"])]))
    pp.apply_suppressions(fs, rules, dt.date(2026, 10, 24))
    assert next(f for f in fs if f.id == "ADM-002").status == "FAIL"


def test_diff_new_resolved_changed(tmp_path):
    old = findings(bad_tenant())
    for f in old:
        f.fingerprint = pp.fingerprint(f)
    base = write(tmp_path, "b.json", {"findings": [{"id": f.id, "status": f.status, "fingerprint": f.fingerprint, "title": f.title} for f in old]})
    new = findings(good_tenant())
    for f in new:
        f.fingerprint = pp.fingerprint(f)
    d = pp.diff_against(new, pp.load_baseline(base))
    assert d["resolved"] and not d["new"]
    d2 = pp.diff_against(old, pp.load_baseline(base))
    assert d2 == {"new": [], "resolved": [], "changed": [], "not_run_now": []}


def test_score_orders_good_above_bad_and_ignores_suppressed():
    good, bad = pp.summarize(findings(good_tenant()), runner.AREAS), pp.summarize(findings(bad_tenant()), runner.AREAS)
    assert good["score"] > bad["score"] and good["grade"] in "AB" and bad["grade"] in "DF"
    assert len(bad["top_risks"]) == 5 and bad["top_risks"][0]["severity"] == "critical"
    fs = findings(bad_tenant())
    before = pp.summarize(fs, runner.AREAS)["score"]
    for f in fs:
        if f.status in ("FAIL", "WARN"):
            f.status = "SUPPRESSED"
    assert pp.summarize(fs, runner.AREAS)["score"] > before


def test_bad_files_are_rejected_cleanly(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("{not json")
    with pytest.raises(ConfigError):
        pp.load_baseline(p)
    with pytest.raises(ConfigError):
        pp.load_baseline(tmp_path / "missing.json")


def test_snippets_are_text_only_and_flag_write_scopes():
    fs = [f for f in findings(bad_tenant()) if f.status in ("FAIL", "WARN")]
    scripts = [pp.remediation_script(f) for f in fs]
    assert all(isinstance(s, str) for s in scripts) and any(scripts)
    assert all("human" in s or "Portal" in s or "Change:" in s or "#" in s for s in scripts if s)
