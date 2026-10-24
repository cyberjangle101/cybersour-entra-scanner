"""Desktop front end (tkinter, no extra dependencies) over runner.execute_scan().

How it works, in plain terms:
  * The form is validated by build_args() (pure function, unit-tested) and turned into the same settings the CLI uses.
  * The scan runs in a worker thread and talks to the window through a queue, so the window never freezes.
  * The client secret lives in memory only. Only non-secret settings (tenant, client ID, options) are saved to settings.json.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import threading
import webbrowser
from pathlib import Path

from .models import SEV_RANK, SEVERITIES, STATUS_ORDER, ConfigError, write_private
from .report import export_csv

AUTH_MODES = {"Client secret": "secret", "Certificate (PEM key)": "cert", "Workload identity (token file)": "federated",
              "Managed identity (Azure resource)": "managed-identity"}
CLOUD_NAMES = {"Commercial / GCC": "commercial", "GCC High (not live-tested)": "usgov", "DoD (not live-tested)": "usgovdod",
               "China 21Vianet (not live-tested)": "china"}
FILTERS = ["Issues (fail / warn)", "All", "Passed", "Manual (CIS)", "Accepted risk", "Skipped / errors"]
DETAIL_EVIDENCE_LINES = 200          # the detail pane shows this many affected objects; the saved reports carry all of them
SEV_COLORS = {"critical": "#f2a6ae", "high": "#f8c9c9", "medium": "#fbe7b0", "low": "#cfe2f9"}


# ----------------------------------------------------------------------------- pure logic (unit-testable, no window needed)
def settings_path() -> Path:
    """Where non-secret GUI settings are stored (per user)."""
    base = os.environ.get("APPDATA") or str(Path.home() / ".config")
    return Path(base) / "EntraPostureScanner" / "settings.json"


def build_args(form: dict, area_keys) -> argparse.Namespace:
    """Validate the form and build the settings object for execute_scan. Raises ValueError with a message fit for a dialog box."""
    if not isinstance(form, dict):
        raise ValueError("Invalid form.")
    text = lambda k: "" if form.get(k) is None else str(form.get(k))
    f = {k: text(k) for k in ("tenant", "client_id", "auth", "secret", "cert_path", "cert_thumbprint", "output_dir", "max_users", "cloud",
                              "federated_token_file", "proxy", "ca_bundle", "policy", "suppressions", "baseline", "check_timeout")}
    if f["auth"] not in ("secret", "cert", "federated", "managed-identity"):
        raise ValueError("Choose a sign-in method.")
    if f["cloud"] and f["cloud"] not in CLOUD_NAMES.values():
        raise ValueError("Choose a Microsoft cloud.")
    if f["auth"] != "managed-identity":
        if not f["tenant"].strip():
            raise ValueError("Enter the tenant ID or domain.")
        if not f["client_id"].strip():
            raise ValueError("Enter the application (client) ID.")
    if f["auth"] == "federated" and not f["federated_token_file"].strip() and not os.environ.get("AZURE_FEDERATED_TOKEN_FILE"):
        raise ValueError("Workload identity sign-in needs the path of the token file.")
    for key, label in (("federated_token_file", "Token file"), ("ca_bundle", "CA bundle"), ("policy", "Policy file"),
                       ("suppressions", "Accepted-risk file"), ("baseline", "Baseline report")):
        if f[key].strip():
            try:
                found = Path(f[key].strip()).is_file()
            except (OSError, ValueError):
                found = False
            if not found:
                raise ValueError(f"{label} not found.")
    if f["proxy"].strip() and not f["proxy"].strip().lower().startswith(("http://", "https://")):
        raise ValueError("Proxy must start with http:// or https://.")
    try:
        check_timeout = int(f["check_timeout"].strip() or 0)
        if check_timeout < 0:
            raise ValueError
    except ValueError:
        raise ValueError("Per-check time limit must be a whole number of seconds (0 = no limit).") from None
    if f["auth"] == "secret" and not (f["secret"] or os.environ.get("AZURE_CLIENT_SECRET")):
        raise ValueError("Enter the client secret (or set AZURE_CLIENT_SECRET).")
    if f["auth"] == "cert":
        if not f["cert_path"].strip() or not f["cert_thumbprint"].strip():
            raise ValueError("Certificate sign-in needs the PEM private key file and the certificate thumbprint.")
        try:
            found = Path(f["cert_path"]).is_file()
        except (OSError, ValueError):                    # absurdly long or malformed path
            found = False
        if not found:
            raise ValueError("Certificate key file not found.")
    areas_form = form.get("areas")
    if not isinstance(areas_form, dict):
        raise ValueError("Select at least one area.")
    chosen = [a for a in area_keys if areas_form.get(a)]
    if not chosen:
        raise ValueError("Select at least one area.")
    try:
        max_users = int(f["max_users"].strip() or 0)
        if max_users < 0:
            raise ValueError
    except ValueError:
        raise ValueError("Max users must be a whole number (0 = no limit).") from None
    return argparse.Namespace(
        auth=f["auth"], tenant=f["tenant"].strip(), client_id=f["client_id"].strip(), client_secret=f["secret"] or None,
        cert_path=f["cert_path"].strip() or None, cert_thumbprint=f["cert_thumbprint"].strip() or None, cert_passphrase=None,
        output_dir=f["output_dir"].strip() or "./reports", areas=None if len(chosen) == len(list(area_keys)) else chosen,
        max_users=max_users or 50000, cloud=f["cloud"] or "commercial", federated_token_file=f["federated_token_file"].strip() or None,
        federated_audience=None, keyvault_secret=None, proxy=f["proxy"].strip() or None, ca_bundle=f["ca_bundle"].strip() or None,
        timeout=60, check_timeout=check_timeout, max_runtime=0, verbose=False, log_file=None, policy=f["policy"].strip() or None,
        suppressions=f["suppressions"].strip() or None, baseline=f["baseline"].strip() or None,
        sarif=bool(form.get("sarif")), junit=bool(form.get("junit")))


def sort_findings(findings):
    """Order findings: failures first, then by severity, then by id."""
    return sorted(findings, key=lambda x: (STATUS_ORDER.get(x.status, 9), SEV_RANK.get(x.severity, 9), x.id))


def filter_findings(findings, mode: str):
    """Apply the 'Show' drop-down to the findings list."""
    if mode == "All":
        return list(findings)
    keep = {"Passed": ("PASS",), "Manual (CIS)": ("MANUAL",), "Accepted risk": ("SUPPRESSED",), "Skipped / errors": ("SKIPPED", "ERROR")}.get(mode, ("FAIL", "WARN"))
    return [x for x in findings if x.status in keep]


def summarize(findings) -> str:
    """One-line count of issues by severity plus passed / manual / skipped."""
    n = {s: 0 for s in SEVERITIES[:4]}
    for x in findings:
        if x.status in ("FAIL", "WARN") and x.severity in n:
            n[x.severity] += 1
    return ("  |  ".join(f"{k.capitalize()}: {v}" for k, v in n.items())
            + f"  |  Passed: {sum(x.status == 'PASS' for x in findings)}  |  Manual: {sum(x.status == 'MANUAL' for x in findings)}"
            + f"  |  Accepted risk: {sum(x.status == 'SUPPRESSED' for x in findings)}"
            + f"  |  Skipped/errors: {sum(x.status in ('SKIPPED', 'ERROR') for x in findings)}")


def is_check_done_line(text) -> bool:
    """True for the line runner.run_scan logs when one check group finishes ("  [area] title ... ok (...)"); drives the progress bar."""
    return isinstance(text, str) and text.startswith("  [") and "] " in text and " ... " in text


def run_outcome(res) -> tuple[str, str]:
    """(label, colour) shown next to the progress bar when a scan ends: green when every check group ran, amber otherwise."""
    if not isinstance(res, dict):
        return "Finished", "amber"
    if res.get("cancelled"):
        return "Partial - cancelled", "amber"
    if str((res.get("meta") or {}).get("note") or "").startswith("PARTIAL"):
        return "Partial - stopped early", "amber"
    coverage = res.get("coverage")
    if isinstance(coverage, (tuple, list)) and len(coverage) == 3 and coverage[1]:
        return f"Complete - {coverage[1]} of {coverage[0]} check groups could not run", "amber"
    return "Complete", "green"


def finding_detail(x) -> str:
    """Plain-text detail pane for one finding."""
    lines = [x.title, f"{x.id}  -  {x.status}" + (f"  -  {x.severity}" if x.status in ("FAIL", "WARN") else ""), ""]
    if x.detail:
        lines += [x.detail, ""]
    if x.remediation:
        lines += ["How to fix:", f"  {x.remediation}", ""]
    if x.setting:
        lines += [f"Setting checked: {x.setting}", ""]
    if x.needs and x.status in ("SKIPPED", "ERROR"):
        lines += [f"Needs permission: {x.needs}", ""]
    if x.learn:
        lines += [f"Microsoft Learn: {x.learn}", "(double-click the row to open it)", ""]
    if x.cis:
        lines += [f"Benchmark: {x.cis}", ""]
    if x.suppression:
        lines += [f"Accepted risk by {x.suppression.get('owner', '?')} until {x.suppression.get('expires', '?')}: {x.suppression.get('reason', '')}", ""]
    if x.script:
        lines += ["Guidance only (never run by this tool):", x.script, ""]
    if x.evidence:
        lines += ["Evidence:"] + [f"  - {e}" for e in x.evidence[:DETAIL_EVIDENCE_LINES]]
        if len(x.evidence) > DETAIL_EVIDENCE_LINES:
            lines.append(f"  ... and {len(x.evidence) - DETAIL_EVIDENCE_LINES} more (all are in the saved JSON / CSV report)")
    return "\n".join(lines)


def open_path(path):
    """Open a file or folder with the operating system's default application."""
    path = Path(path)
    if not path.exists():
        raise OSError(f"{path} does not exist (was it moved or deleted?)")
    if hasattr(os, "startfile"):
        try:
            # Windows only. `path` is always a file we wrote ourselves (report folder), never user-typed text or tenant data.
            os.startfile(str(path))  # type: ignore[attr-defined]  # nosemgrep: dangerous-spawn-process-audit
            return
        except OSError:
            pass                                     # no program is registered for .html, or access was refused: try the browser directly
    if not webbrowser.open(path.resolve().as_uri()):
        raise OSError("no web browser could be started")


# ----------------------------------------------------------------------------- window
def run_gui():
    """Build and run the window (tkinter is imported here so the pure helpers above work without a display)."""
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    from tkinter.scrolledtext import ScrolledText

    from . import permissions
    from .runner import AREAS, execute_scan, scan_coverage

    try:                                       # crisp text on high-DPI Windows screens
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001
        pass

    class App(tk.Tk):
        """The main window."""
        def __init__(self):
            """Create the window state, the form variables, then build the widgets and load saved settings."""
            super().__init__()
            self.title("Microsoft Entra ID Posture Scanner")
            self.geometry("1120x780")
            self.minsize(940, 620)
            self.q: queue.Queue = queue.Queue()
            self.stop_evt = threading.Event()
            self.result, self.findings, self.shown = None, [], []
            self.v = {"tenant": tk.StringVar(), "client_id": tk.StringVar(), "auth": tk.StringVar(value="Client secret"),
                      "secret": tk.StringVar(), "cert_path": tk.StringVar(), "cert_thumbprint": tk.StringVar(),
                      "max_users": tk.StringVar(value="0"), "output_dir": tk.StringVar(value=str(Path.home() / "EntraPostureReports")),
                      "filter": tk.StringVar(value=FILTERS[0]), "cloud": tk.StringVar(value=list(CLOUD_NAMES)[0]),
                      "federated_token_file": tk.StringVar(), "proxy": tk.StringVar(), "ca_bundle": tk.StringVar(), "policy": tk.StringVar(),
                      "suppressions": tk.StringVar(), "baseline": tk.StringVar(), "check_timeout": tk.StringVar(value="0")}
            self.flags = {"sarif": tk.BooleanVar(value=False), "junit": tk.BooleanVar(value=False)}
            self.areas = {a: tk.BooleanVar(value=True) for a in AREAS}
            self._build()
            self._load_settings()
            self._on_auth_change()
            self.protocol("WM_DELETE_WINDOW", self._close)
            self.after(100, self._poll)

        def _build(self):
            """Lay out the connection form, scan options, action bar, findings table and log."""
            pad = {"padx": 8, "pady": 4}
            root = ttk.Frame(self, padding=10)
            root.pack(fill="both", expand=True)
            conn = ttk.LabelFrame(root, text="Connection (read-only Entra app registration)", padding=8)
            conn.pack(fill="x")
            conn.columnconfigure(1, weight=1)
            conn.columnconfigure(3, weight=1)
            ttk.Label(conn, text="Tenant ID / domain").grid(row=0, column=0, sticky="w", **pad)
            ttk.Entry(conn, textvariable=self.v["tenant"]).grid(row=0, column=1, sticky="ew", **pad)
            ttk.Label(conn, text="Client (app) ID").grid(row=0, column=2, sticky="w", **pad)
            ttk.Entry(conn, textvariable=self.v["client_id"]).grid(row=0, column=3, sticky="ew", **pad)
            ttk.Label(conn, text="Sign-in method").grid(row=1, column=0, sticky="w", **pad)
            cb = ttk.Combobox(conn, textvariable=self.v["auth"], values=list(AUTH_MODES), state="readonly")
            cb.grid(row=1, column=1, sticky="ew", **pad)
            cb.bind("<<ComboboxSelected>>", lambda _e: self._on_auth_change())
            ttk.Label(conn, text="Cloud").grid(row=1, column=2, sticky="e", **pad)
            ttk.Combobox(conn, textvariable=self.v["cloud"], values=list(CLOUD_NAMES), state="readonly", width=22).grid(row=1, column=3, sticky="w", **pad)
            ttk.Button(conn, text="Which permissions do I need?", command=self._show_permissions).grid(row=5, column=3, sticky="e", **pad)

            self.secret_row = ttk.Frame(conn)
            self.secret_row.grid(row=2, column=0, columnspan=4, sticky="ew")
            self.secret_row.columnconfigure(1, weight=1)
            ttk.Label(self.secret_row, text="Client secret").grid(row=0, column=0, sticky="w", **pad)
            ttk.Entry(self.secret_row, textvariable=self.v["secret"], show="•").grid(row=0, column=1, sticky="ew", **pad)
            ttk.Label(self.secret_row, text="Kept in memory only, never saved.", foreground="gray").grid(row=0, column=2, **pad)

            self.cert_row = ttk.Frame(conn)
            self.cert_row.grid(row=3, column=0, columnspan=4, sticky="ew")
            self.cert_row.columnconfigure(1, weight=1)
            ttk.Label(self.cert_row, text="PEM private key").grid(row=0, column=0, sticky="w", **pad)
            ttk.Entry(self.cert_row, textvariable=self.v["cert_path"]).grid(row=0, column=1, sticky="ew", **pad)
            ttk.Button(self.cert_row, text="Browse...", command=self._browse_cert).grid(row=0, column=2, **pad)
            ttk.Label(self.cert_row, text="Thumbprint").grid(row=1, column=0, sticky="w", **pad)
            ttk.Entry(self.cert_row, textvariable=self.v["cert_thumbprint"]).grid(row=1, column=1, sticky="ew", **pad)

            self.fed_row = ttk.Frame(conn)
            self.fed_row.grid(row=4, column=0, columnspan=4, sticky="ew")
            self.fed_row.columnconfigure(1, weight=1)
            ttk.Label(self.fed_row, text="Token file").grid(row=0, column=0, sticky="w", **pad)
            ttk.Entry(self.fed_row, textvariable=self.v["federated_token_file"]).grid(row=0, column=1, sticky="ew", **pad)
            ttk.Button(self.fed_row, text="Browse...", command=lambda: self._browse("federated_token_file", "Token file")).grid(row=0, column=2, **pad)

            self.mi_row = ttk.Frame(conn)
            self.mi_row.grid(row=4, column=0, columnspan=4, sticky="ew")
            ttk.Label(self.mi_row, text="Uses this Azure resource's managed identity. Leave Client ID empty for system-assigned.", foreground="gray").pack(anchor="w", **pad)

            adv = ttk.LabelFrame(root, text="Advanced: network, decisions, extra outputs", padding=8)
            adv.pack(fill="x", pady=(8, 0))
            adv.columnconfigure(1, weight=1)
            adv.columnconfigure(3, weight=1)
            for r, (a, b) in enumerate((("proxy", "ca_bundle"), ("policy", "suppressions"), ("baseline", "check_timeout"))):
                for c, key in ((0, a), (2, b)):
                    label = {"proxy": "Proxy URL", "ca_bundle": "CA bundle", "policy": "Policy file", "suppressions": "Accepted-risk file",
                             "baseline": "Compare with report", "check_timeout": "Seconds per check (0=off)"}[key]
                    ttk.Label(adv, text=label).grid(row=r, column=c, sticky="w", **pad)
                    ttk.Entry(adv, textvariable=self.v[key]).grid(row=r, column=c + 1, sticky="ew", **pad)
            ttk.Checkbutton(adv, text="Also write SARIF", variable=self.flags["sarif"]).grid(row=3, column=0, sticky="w", **pad)
            ttk.Checkbutton(adv, text="Also write JUnit XML", variable=self.flags["junit"]).grid(row=3, column=1, sticky="w", **pad)
            pick = ttk.Frame(adv)
            pick.grid(row=3, column=2, columnspan=2, sticky="e")
            for key, text in (("ca_bundle", "CA bundle..."), ("policy", "Policy..."), ("suppressions", "Accepted risks..."), ("baseline", "Baseline...")):
                ttk.Button(pick, text=text, command=lambda k=key, t=text: self._browse(k, t.rstrip("."))).pack(side="left", padx=2)

            opt = ttk.LabelFrame(root, text="Scan options", padding=8)
            opt.pack(fill="x", pady=(8, 0))
            ttk.Label(opt, text="Areas to scan").grid(row=0, column=0, sticky="w", padx=6)
            for i, (a, title) in enumerate(AREAS.items()):
                ttk.Checkbutton(opt, text=title, variable=self.areas[a]).grid(row=1 + i // 3, column=i % 3, sticky="w", padx=10, pady=2)
            r2 = ttk.Frame(opt)
            r2.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(6, 0))
            r2.columnconfigure(3, weight=1)
            ttk.Label(r2, text="Max users (0 = all)").grid(row=0, column=0, padx=6)
            ttk.Spinbox(r2, from_=0, to=1_000_000, increment=1000, width=9, textvariable=self.v["max_users"]).grid(row=0, column=1)
            ttk.Label(r2, text="Save reports to").grid(row=0, column=2, padx=(14, 4))
            ttk.Entry(r2, textvariable=self.v["output_dir"]).grid(row=0, column=3, sticky="ew")
            ttk.Button(r2, text="Browse...", command=self._browse_out).grid(row=0, column=4, padx=6)

            bar = ttk.Frame(root)
            bar.pack(fill="x", pady=8)
            self.run_btn = ttk.Button(bar, text="Run scan", command=self._start)
            self.run_btn.pack(side="left")
            self.cancel_btn = ttk.Button(bar, text="Cancel", command=self._cancel, state="disabled")
            self.cancel_btn.pack(side="left", padx=6)
            self.prog = ttk.Progressbar(bar, mode="determinate", length=160, maximum=1)
            self.prog.pack(side="left", padx=(10, 4))
            self.prog_state = ttk.Label(bar, text="")      # Running / Complete / Partial / Failed once a scan has started
            self.prog_state.pack(side="left")
            self.report_btn = ttk.Button(bar, text="Open HTML report", command=self._open_report, state="disabled")
            self.report_btn.pack(side="right")
            self.csv_btn = ttk.Button(bar, text="Export CSV...", command=self._export_csv, state="disabled")
            self.csv_btn.pack(side="right", padx=6)
            self.folder_btn = ttk.Button(bar, text="Open folder", command=self._open_folder, state="disabled")
            self.folder_btn.pack(side="right")

            self.summary = ttk.Label(root, text="No scan run yet.", font=("Segoe UI", 10, "bold"))
            self.summary.pack(fill="x")
            nb = ttk.Notebook(root)
            nb.pack(fill="both", expand=True, pady=(6, 0))
            self.nb = nb
            fr = ttk.Frame(nb)
            nb.add(fr, text="Findings")
            top = ttk.Frame(fr)
            top.pack(fill="x", pady=4)
            ttk.Label(top, text="Show").pack(side="left", padx=4)
            fcb = ttk.Combobox(top, textvariable=self.v["filter"], values=FILTERS, state="readonly", width=22)
            fcb.pack(side="left")
            fcb.bind("<<ComboboxSelected>>", lambda _e: self._refresh_tree())
            paned = ttk.PanedWindow(fr, orient="vertical")
            paned.pack(fill="both", expand=True)
            tf = ttk.Frame(paned)
            self.tree = ttk.Treeview(tf, columns=("sev", "status", "id", "cat", "title"), show="headings", selectmode="browse")
            for col, txt, w in (("sev", "Severity", 80), ("status", "Status", 70), ("id", "ID", 80), ("cat", "Area", 90), ("title", "Finding", 700)):
                self.tree.heading(col, text=txt)
                self.tree.column(col, width=w, anchor="w", stretch=(col == "title"))
            sb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=sb.set)
            self.tree.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            for sev, colr in SEV_COLORS.items():
                self.tree.tag_configure(sev, background=colr, foreground="#111111")
            self.tree.tag_configure("PASS", foreground="#1a7f37")
            self.tree.bind("<<TreeviewSelect>>", self._on_select)
            self.tree.bind("<Double-1>", self._open_learn)
            paned.add(tf, weight=3)
            self.detail = ScrolledText(paned, height=9, wrap="word", font=("Segoe UI", 10), state="disabled")
            paned.add(self.detail, weight=2)
            lf = ttk.Frame(nb)
            nb.add(lf, text="Log")
            self.log = ScrolledText(lf, wrap="word", font=("Consolas", 9), state="disabled")
            self.log.pack(fill="both", expand=True)
            self.status = ttk.Label(self, text="Ready", anchor="w", relief="sunken")
            self.status.pack(fill="x", side="bottom")

        # ---- small helpers
        def _on_auth_change(self):
            mode = AUTH_MODES.get(self.v["auth"].get(), "secret")
            for row, m in ((self.secret_row, "secret"), (self.cert_row, "cert"), (self.fed_row, "federated"), (self.mi_row, "managed-identity")):
                row.grid() if m == mode else row.grid_remove()

        def _show_permissions(self):
            lines = [f"{n}\n    {why}" for n, why, _ in permissions.permission_table()]
            messagebox.showinfo("Microsoft Graph application permissions (read-only)",
                                "Grant these to the app registration, then 'Grant admin consent':\n\n" + "\n\n".join(lines))

        def _browse_cert(self):
            p = filedialog.askopenfilename(title="PEM private key", filetypes=[("PEM", "*.pem *.key"), ("All files", "*.*")])
            if p:
                self.v["cert_path"].set(p)

        def _browse(self, key, title):
            p = filedialog.askopenfilename(title=title)
            if p:
                self.v[key].set(p)

        def _browse_out(self):
            p = filedialog.askdirectory(title="Report folder")
            if p:
                self.v["output_dir"].set(p)

        def _logline(self, text):
            if is_check_done_line(text):
                self.prog.configure(value=min(float(self.prog["value"]) + 1, float(self.prog["maximum"])))
            self.log.configure(state="normal")
            self.log.insert("end", text + "\n")
            self.log.see("end")
            self.log.configure(state="disabled")

        def _load_settings(self):
            """Restore non-secret settings. Anything unexpected in the file is ignored rather than trusted."""
            try:
                d = json.loads(settings_path().read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return
            if not isinstance(d, dict):
                return
            for k in ("tenant", "client_id", "cert_path", "cert_thumbprint", "max_users", "output_dir", "proxy", "ca_bundle", "federated_token_file"):
                if isinstance(d.get(k), (str, int)) and not isinstance(d.get(k), bool):
                    self.v[k].set(d[k])
            if d.get("cloud") in CLOUD_NAMES:
                self.v["cloud"].set(d["cloud"])
            if d.get("auth") in AUTH_MODES:
                self.v["auth"].set(d["auth"])
            areas = d.get("areas")
            for a, on in (areas.items() if isinstance(areas, dict) else ()):
                if a in self.areas:
                    self.areas[a].set(bool(on))

        def _save_settings(self):
            d = {k: self.v[k].get() for k in ("tenant", "client_id", "auth", "cert_path", "cert_thumbprint", "max_users", "output_dir", "proxy",
                                              "ca_bundle", "federated_token_file")}
            d["cloud"] = self.v["cloud"].get()
            d["areas"] = {a: v.get() for a, v in self.areas.items()}
            try:                                   # the secret is deliberately never included
                settings_path().parent.mkdir(parents=True, exist_ok=True)
                write_private(settings_path(), json.dumps(d, indent=2))
            except OSError:
                pass

        # ---- run / cancel
        def _form(self):
            return {"auth": AUTH_MODES.get(self.v["auth"].get(), ""), "tenant": self.v["tenant"].get(), "client_id": self.v["client_id"].get(),
                    "secret": self.v["secret"].get(), "cert_path": self.v["cert_path"].get(), "cert_thumbprint": self.v["cert_thumbprint"].get(),
                    "max_users": self.v["max_users"].get(), "output_dir": self.v["output_dir"].get(),
                    "cloud": CLOUD_NAMES.get(self.v["cloud"].get(), "commercial"), "federated_token_file": self.v["federated_token_file"].get(),
                    "proxy": self.v["proxy"].get(), "ca_bundle": self.v["ca_bundle"].get(), "policy": self.v["policy"].get(),
                    "suppressions": self.v["suppressions"].get(), "baseline": self.v["baseline"].get(), "check_timeout": self.v["check_timeout"].get(),
                    "sarif": self.flags["sarif"].get(), "junit": self.flags["junit"].get(),
                    "areas": {a: v.get() for a, v in self.areas.items()}}

        def _start(self):
            """Validate the form, save non-secret settings and start the scan in a worker thread."""
            try:
                args = build_args(self._form(), list(AREAS))
            except ValueError as e:
                messagebox.showwarning("Check your settings", str(e))
                return
            self._save_settings()
            self.stop_evt.clear()
            self.result, self.findings = None, []
            self._refresh_tree()
            self.log.configure(state="normal")
            self.log.delete("1.0", "end")
            self.log.configure(state="disabled")
            self.run_btn.configure(state="disabled")
            self.cancel_btn.configure(state="normal")
            for b in (self.report_btn, self.csv_btn, self.folder_btn):
                b.configure(state="disabled")
            self.summary.configure(text="Scanning...")
            self.status.configure(text="Scanning - this can take a few minutes on large tenants")
            self.prog.configure(maximum=max(scan_coverage([], args.areas)[0], 1), value=0)
            self._set_state("Running...", "")
            threading.Thread(target=self._work, args=(args,), daemon=True).start()

        def _work(self, args):
            put = self.q.put
            try:
                put(("done", execute_scan(args, log=lambda m: put(("log", m)), stop=self.stop_evt)))
            except ConfigError as e:
                put(("error", str(e)))
            except Exception as e:  # noqa: BLE001 - anything unexpected is shown to the user instead of dying silently
                put(("error", f"{type(e).__name__}: {e}"))

        def _cancel(self):
            self.stop_evt.set()
            self.cancel_btn.configure(state="disabled")
            self.status.configure(text="Cancelling after the current check finishes...")

        def _poll(self):
            try:
                while True:
                    kind, payload = self.q.get_nowait()
                    {"log": self._logline, "done": self._finish, "error": self._fail}[kind](payload)
            except queue.Empty:
                pass
            self.after(100, self._poll)

        def _finish(self, res):
            self._end_run()
            self.result, self.findings = res, sort_findings(res["findings"])
            sm = res.get("summary") or {}
            score = f"Score: {sm['score']} ({sm['grade']})  |  " if sm.get("score") is not None else ""
            self.summary.configure(text=score + summarize(self.findings) + ("   (partial - cancelled)" if res["cancelled"] else ""))
            self.status.configure(text=f"Done. Reports saved to {res['html_path'].parent}")
            if not res["cancelled"]:
                self.prog.configure(value=self.prog["maximum"])
            self._set_state(*run_outcome(res))
            for b in (self.report_btn, self.csv_btn, self.folder_btn):
                b.configure(state="normal")
            self.nb.select(0)
            self._refresh_tree()

        def _fail(self, msg):
            self._end_run()
            self.summary.configure(text="Scan failed.")
            self.status.configure(text="Scan failed")
            self._set_state("Failed", "red")
            self._logline("ERROR: " + msg)
            messagebox.showerror("Scan failed", msg)

        def _set_state(self, text, colour):
            """Outcome text beside the progress bar; colour is green / amber / red, or "" for neutral."""
            fg = {"green": "#1a7f37", "amber": "#9a6700", "red": "#cf222e"}.get(colour, "")
            self.prog_state.configure(text=("✔ " if colour == "green" else "✖ " if colour == "red" else "") + text, foreground=fg)

        def _end_run(self):
            self.run_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")

        # ---- results
        def _refresh_tree(self):
            self.tree.delete(*self.tree.get_children())
            self.shown = filter_findings(self.findings, self.v["filter"].get())
            for i, x in enumerate(self.shown):
                sev = x.severity if x.status in ("FAIL", "WARN") else ""
                self.tree.insert("", "end", iid=str(i), values=(sev or "-", x.status, x.id, x.category, x.title), tags=(sev or x.status,))
            self._set_detail("")

        def _set_detail(self, text):
            self.detail.configure(state="normal")
            self.detail.delete("1.0", "end")
            self.detail.insert("1.0", text)
            self.detail.configure(state="disabled")

        def _open_learn(self, _e=None):
            sel = self.tree.selection()
            if sel and 0 <= int(sel[0]) < len(self.shown):
                url = self.shown[int(sel[0])].learn
                if url.startswith("https://learn.microsoft.com/"):
                    webbrowser.open(url)

        def _on_select(self, _e):
            sel = self.tree.selection()
            if sel:
                self._set_detail(finding_detail(self.shown[int(sel[0])]))

        def _open_safely(self, path):
            """Open a report/folder; if the system refuses, say why and where the file is instead of failing silently."""
            try:
                open_path(path)
            except OSError as e:
                messagebox.showwarning("Could not open it", f"{e}\n\nThe file is here:\n{path}\n\nOpen it manually from File Explorer or drag it into a browser.")

        def _open_report(self):
            if self.result:
                self._open_safely(self.result["html_path"])

        def _open_folder(self):
            if self.result:
                self._open_safely(self.result["html_path"].parent)

        def _export_csv(self):
            p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="entra-posture-findings.csv")
            if p:
                try:
                    export_csv(self.findings, p)
                    self.status.configure(text=f"Exported {len(self.findings)} findings to {p}")
                except OSError as e:
                    messagebox.showerror("Export failed", str(e))

        def _close(self):
            self.stop_evt.set()
            self.destroy()

    App().mainloop()
