"""UAT (GUI): drive the REAL tkinter window like a user. Needs a display (xvfb-run) and a Python with tkinter.
Prints one JSON object. Sign-in is replaced by the pretend tenant; everything else (form, threads, tables, export) is real."""
import json, os, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.dirname(HERE), HERE]
import tkinter
from entra_scan import context, gui, report, runner
from fake_tenant import Args, FakeGraph, bad_tenant

out = {}
tmp = tempfile.mkdtemp()
os.environ["APPDATA"] = tmp                                   # keep settings out of the real profile


MODE = {"m": "normal"}


def fake_exec(args, log=print, stop=None):
    if MODE["m"] == "error":
        raise runner.ConfigError("The client secret is wrong (test).")
    if MODE["m"] == "cancel":
        stop.set()                                   # user pressed Cancel during the scan
    ctx = context.Ctx(FakeGraph(bad_tenant()), args)
    f = runner.run_scan(ctx, args.areas, log, stop)
    d = os.path.join(args.output_dir); os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "r.html"); open(p, "w", encoding="utf-8").write(report.render_html({"t": "x"}, f, runner.AREAS))
    from pathlib import Path
    return {"meta": {}, "findings": f, "json_path": Path(d) / "r.json", "html_path": Path(p), "cancelled": bool(stop and stop.is_set()), "coverage": (1, 0, 100)}


runner.execute_scan = fake_exec


def drive(self):
    def wait():
        t0 = time.time()
        while self.run_btn.instate(["disabled"]) and time.time() - t0 < 30:
            self.update(); time.sleep(0.05)
        self.update()
    # 1. empty form -> friendly validation, nothing starts
    shown = []
    import tkinter.messagebox as mb
    mb.showwarning = lambda t, m: shown.append(m); mb.showerror = lambda t, m: shown.append(m)
    self._start(); out["empty_form_message"] = shown[-1] if shown else None
    # 2. fill the form and scan
    self.v["tenant"].set("contoso.com"); self.v["client_id"].set("11111111-1111-1111-1111-111111111111"); self.v["secret"].set("s3cret")
    self.v["output_dir"].set(os.path.join(tmp, "reports"))
    self._start(); wait()
    out["rows_issues"] = len(self.tree.get_children()); out["summary"] = self.summary.cget("text")
    out["report_button_enabled"] = str(self.report_btn.cget("state")) == "normal"
    # 3. filters
    for m in gui.FILTERS:
        self.v["filter"].set(m); self._refresh_tree(); self.update(); out["filter:" + m] = len(self.tree.get_children())
    # 4. detail pane
    self.v["filter"].set(gui.FILTERS[0]); self._refresh_tree(); self.tree.selection_set("0"); self.update()
    out["detail_has_fix"] = "How to fix" in self.detail.get("1.0", "end")
    # 5. CSV export
    import tkinter.filedialog as fd
    fd.asksaveasfilename = lambda **k: os.path.join(tmp, "x.csv"); self._export_csv()
    out["csv_written"] = os.path.exists(os.path.join(tmp, "x.csv"))
    # 6. secret never saved
    saved = open(gui.settings_path(), encoding="utf-8").read()
    out["secret_not_saved"] = "s3cret" not in saved and "secret" not in json.loads(saved)
    out["tenant_saved"] = json.loads(saved).get("tenant") == "contoso.com"
    # 7. hostile settings file is ignored, not trusted
    gui.settings_path().write_text(json.dumps({"tenant": ["x"], "auth": "device", "areas": "nope", "max_users": True, "client_id": {"a": 1}}))
    self.v["tenant"].set(""); self._load_settings(); out["hostile_settings_ignored"] = self.v["tenant"].get() == "" and self.v["auth"].get() == "Client secret"
    gui.settings_path().write_text("{not json"); self._load_settings(); out["corrupt_settings_ok"] = True
    # 8. cancel: the stop flag is raised mid-scan -> partial result, window stays usable
    self.v["tenant"].set("contoso.com"); MODE["m"] = "cancel"; self._start(); wait()
    out["cancel_marks_partial"] = "partial" in self.summary.cget("text"); out["run_button_reenabled"] = str(self.run_btn.cget("state")) == "normal"
    # 9. a failing scan shows an error dialog and re-enables Run
    MODE["m"] = "error"; self._start(); wait()
    out["error_dialog"] = shown[-1]; out["run_button_after_error"] = str(self.run_btn.cget("state")) == "normal"
    print(json.dumps(out)); self.destroy()


tkinter.Tk.mainloop = drive
gui.run_gui()
