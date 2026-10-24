"""UAT (GUI): the "Advanced: network, decisions, extra outputs" panel, driven in the REAL tkinter window like a user.

Unlike uat_gui.py, the real execute_scan pipeline runs (policy, accepted risks, baseline, SARIF/JUnit, per-check time limit);
only sign-in and the network are replaced by the pretend tenant.  Needs a display (Windows desktop, or xvfb-run on Linux).
Prints one JSON object: every key is a check that must be true, plus a few values for the evidence column.
"""
import datetime as dt
import json, os, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.dirname(HERE), HERE]
import tkinter
from entra_scan import gui, runner
from entra_scan.models import GraphError
from fake_tenant import FakeGraph, bad_tenant

tmp = tempfile.mkdtemp()
os.environ["APPDATA"] = tmp                                    # keep settings out of the real profile
SLOW_PATH = "/identityProtection/riskyUsers"                    # answers slower than the per-check limit set in run 2
cap = {"graph_kwargs": None, "sign_ins": 0}
TENANT = {"data": bad_tenant()}


class SlowGraph(FakeGraph):
    """The pretend Graph, honouring the per-check deadline the way graph.Graph._request does."""
    deadline = None

    def _lookup(self, path, params):
        if path == SLOW_PATH and self.deadline is not None:
            time.sleep(1.5)
            if time.monotonic() > self.deadline:
                raise GraphError(408, "TimeBudgetExceeded", "The time budget for this check ran out (see --check-timeout)", path)
        return super()._lookup(path, params)


def fake_token_provider(_args):
    cap["sign_ins"] += 1
    return lambda: "tok"


def fake_graph(_provider, **kw):
    cap["graph_kwargs"] = kw                                     # proxy / CA bundle / cloud as the window passed them on
    return SlowGraph(TENANT["data"])


runner.build_token_provider, runner.Graph = fake_token_provider, fake_graph


def write(name, obj):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(obj if isinstance(obj, str) else json.dumps(obj))
    return p


def drive(self):
    out = {}
    shown = []
    import tkinter.messagebox as mb
    mb.showwarning = lambda t, m: shown.append(m)
    mb.showerror = lambda t, m: shown.append(m)
    self.withdraw()                                              # drive it without flashing a window on the tester's screen

    def wait():
        t0 = time.time()
        while self.run_btn.instate(["disabled"]) and time.time() - t0 < 60:
            self.update(); time.sleep(0.05)
        self.update()

    def newest(ext, folder):
        files = sorted(f for f in os.listdir(folder) if f.endswith(ext))
        return os.path.join(folder, files[-1]) if files else None

    def start_expect_message(**fields):
        """Set fields, press Run, return the dialog text (the scan must not start)."""
        before = len(shown)
        for k, v in fields.items():
            self.v[k].set(v)
        self._start(); self.update()
        msg = shown[-1] if len(shown) > before else None
        for k in fields:
            self.v[k].set("")
        return msg

    # ---- 0. required basics
    self.v["tenant"].set("contoso.com"); self.v["client_id"].set("11111111-1111-1111-1111-111111111111"); self.v["secret"].set("s3cret")
    run1_dir, run2_dir = os.path.join(tmp, "run1"), os.path.join(tmp, "run2")

    # ---- 1. every Advanced field is validated before anything starts (no sign-in happens)
    missing = os.path.join(tmp, "nope.json")
    out["proxy_bad_scheme"] = start_expect_message(proxy="ftp://proxy:8080")
    out["ca_bundle_missing"] = start_expect_message(ca_bundle=missing)
    out["policy_missing"] = start_expect_message(policy=missing)
    out["suppressions_missing"] = start_expect_message(suppressions=missing)
    out["baseline_missing"] = start_expect_message(baseline=missing)
    out["timeout_negative"] = start_expect_message(check_timeout="-1")
    out["timeout_text"] = start_expect_message(check_timeout="ten")
    self.v["check_timeout"].set("0")
    out["no_sign_in_during_validation"] = cap["sign_ins"] == 0

    # ---- 2. a file that exists but is wrong is refused with a clear message, still before sign-in
    bad_policy = write("bad-policy.json", {"disable": "CA-001", "colour": "red"})
    self.v["policy"].set(bad_policy); self.v["output_dir"].set(run1_dir)
    self._start(); wait()
    out["bad_policy_message"] = shown[-1]
    out["bad_policy_before_sign_in"] = cap["sign_ins"] == 0
    out["bad_policy_state"] = self.prog_state.cget("text")
    self.v["policy"].set("")

    # ---- 3. run 1: SARIF + JUnit ticked, nothing else -> baseline for run 2
    self.flags["sarif"].set(True); self.flags["junit"].set(True)
    self._start(); wait()
    j1 = newest(".json", run1_dir)
    out["run1_outputs"] = sorted(os.path.splitext(f)[1] if not f.endswith(".junit.xml") else ".junit.xml" for f in os.listdir(run1_dir))
    out["run1_state"] = self.prog_state.cget("text")
    out["run1_bar_full"] = float(self.prog["value"]) == float(self.prog["maximum"]) and float(self.prog["maximum"]) > 1

    # ---- 4. run 2: every Advanced option at once, against a tenant where one problem was fixed
    TENANT["data"] = bad_tenant()
    TENANT["data"]["/policies/adminConsentRequestPolicy"] = {"isEnabled": True, "reviewers": [{"query": "x"}]}   # fixed since run 1
    ca_pem = write("corp-ca.pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    policy = write("policy.json", {"disable": ["CA-001"], "severity": {"ADM-001": "low"}, "note": "UAT"})
    expires = (dt.date.today() + dt.timedelta(days=30)).isoformat()
    waivers = write("waivers.json", [{"id": "AUTH-002", "owner": "j.tester", "reason": "SMS needed for frontline staff until rollout", "expires": expires}])
    for k, v in {"proxy": "http://proxy.example:8080", "ca_bundle": ca_pem, "policy": policy, "suppressions": waivers,
                 "baseline": j1, "check_timeout": "1", "output_dir": run2_dir}.items():
        self.v[k].set(v)
    self._start(); wait()
    j2 = newest(".json", run2_dir)
    rep = json.load(open(j2, encoding="utf-8"))
    by_id = {f["id"]: f for f in rep["findings"]}
    html = open(newest(".html", run2_dir), encoding="utf-8").read()
    kw = cap["graph_kwargs"] or {}
    out["proxy_passed_to_graph"] = kw.get("proxy") == "http://proxy.example:8080"
    out["ca_bundle_passed_to_graph"] = kw.get("ca_bundle") == ca_pem
    out["policy_disabled_CA_001"] = "CA-001" not in by_id and "CA-001" in rep["policy"]["disabled"]
    out["policy_regraded_ADM_001"] = by_id.get("ADM-001", {}).get("severity") == "low"
    out["waiver_AUTH_002_suppressed"] = by_id.get("AUTH-002", {}).get("status") == "SUPPRESSED"
    out["waiver_owner_in_report"] = "j.tester" in html
    out["baseline_diff_present"] = rep["diff"] is not None and "Change since baseline" in html
    out["baseline_fixed_is_resolved"] = rep["diff"]["resolved"] == ["TEN-008"]
    out["baseline_waived_is_accepted_not_resolved"] = rep["diff"]["accepted"] == ["AUTH-002"] and "Newly accepted risk" in html
    timed_out = [f for f in rep["findings"] if f["status"] == "SKIPPED" and "time budget" in f["detail"].lower()]
    out["check_timeout_skipped_slow_check"] = len(timed_out) == 1
    out["run2_outputs"] = sorted(os.path.splitext(f)[1] if not f.endswith(".junit.xml") else ".junit.xml" for f in os.listdir(run2_dir))
    out["run2_state"] = self.prog_state.cget("text")
    out["meta_check_groups_run"] = rep["meta"].get("check groups run")

    # ---- 5. settings: Advanced paths are remembered only where intended, the secret never
    saved = json.loads(open(gui.settings_path(), encoding="utf-8").read())
    out["secret_not_saved"] = "s3cret" not in json.dumps(saved)

    print(json.dumps(out))
    self.destroy()


tkinter.Tk.mainloop = drive
gui.run_gui()
