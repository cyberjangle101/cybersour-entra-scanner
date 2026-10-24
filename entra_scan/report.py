"""Report writers: a single self-contained HTML page (filterable), plus CSV for spreadsheets.

Security notes (the report contains tenant data, so it is treated as untrusted-input output):
  * every value is HTML-escaped before it is placed in the page;
  * a Content-Security-Policy with a per-report random nonce blocks any script that is not ours, even if escaping failed;
  * links are only rendered for https://learn.microsoft.com/ addresses;
  * CSV cells that start with = + - @ are prefixed with ' so spreadsheets cannot run them as formulas.
"""
from __future__ import annotations

import csv
import html
import io
import json
import secrets
from collections import defaultdict

from .models import SEV_RANK, SEVERITIES, STATUS_ORDER, write_private

LEARN_PREFIX = "https://learn.microsoft.com/"

STYLE = """
:root{--bg:#fff;--fg:#1b1f24;--mut:#59636e;--card:#f6f8fa;--bd:#d0d7de;--critical:#a40e26;--high:#d1242f;--medium:#bf8700;--low:#0969da;--info:#6e7781;--pass:#1a7f37;--manual:#8250df;--link:#0969da}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#9198a1;--card:#161b22;--bd:#30363d;--critical:#ff7b72;--high:#f85149;--medium:#d29922;--low:#58a6ff;--info:#8b949e;--pass:#3fb950;--manual:#bc8cff;--link:#58a6ff}}
body{font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px;max-width:1100px;margin-inline:auto}
h1{margin:0 0 4px}h2{margin-top:32px;border-bottom:1px solid var(--bd);padding-bottom:6px}
a{color:var(--link)}.mut{color:var(--mut)}.cards{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}
.c{font:inherit;color:inherit;text-align:left;background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:10px 16px;min-width:96px;cursor:pointer}
.c b{font-size:22px;display:block}.c:hover{border-color:var(--fg)}.c[aria-pressed=true]{outline:2px solid var(--low);outline-offset:1px}
.c.zero{opacity:.55}
.n.critical{color:var(--critical)}.n.high{color:var(--high)}.n.medium{color:var(--medium)}.n.low{color:var(--low)}.n.pass{color:var(--pass)}.n.manual{color:var(--manual)}
.f{background:var(--card);border:1px solid var(--bd);border-left:5px solid var(--info);border-radius:6px;margin:8px 0;padding:0}
.f summary{cursor:pointer;padding:10px 14px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.f .b{padding:0 14px 12px}.f[data-sev=critical]{border-left-color:var(--critical)}.f[data-sev=high]{border-left-color:var(--high)}
.f[data-sev=medium]{border-left-color:var(--medium)}.f[data-sev=low]{border-left-color:var(--low)}.f[data-st=PASS]{border-left-color:var(--pass)}.f[data-st=MANUAL]{border-left-color:var(--manual)}
.tag{font-size:11px;font-weight:700;letter-spacing:.04em;padding:1px 7px;border-radius:10px;border:1px solid currentColor;text-transform:uppercase}
.tag.critical{color:var(--critical)}.tag.high{color:var(--high)}.tag.medium{color:var(--medium)}.tag.low{color:var(--low)}.tag.PASS{color:var(--pass)}.tag.MANUAL{color:var(--manual)}.tag.info,.tag.SKIPPED,.tag.ERROR,.tag.INFO{color:var(--info)}
code{font-size:12.5px}ul{margin:6px 0;padding-left:20px;overflow-wrap:anywhere}
.bar{margin:8px 0}.bar button,.tools button{font:inherit;background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:6px;padding:4px 10px;margin:2px;cursor:pointer}
.bar button[aria-pressed=true]{outline:2px solid var(--low)}.bar .lbl{display:inline-block;min-width:70px;color:var(--mut)}
#count{margin:10px 0;font-weight:600}.learn{margin:6px 0}
.tag.SUPPRESSED{color:var(--manual)}.f[data-st=SUPPRESSED]{border-left-color:var(--manual);opacity:.8}
.sum{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:4px 18px 14px;margin:16px 0}.score{display:flex;gap:12px;align-items:baseline}
.bigscore{font-size:44px}.g{font-weight:700;padding:2px 10px;border-radius:6px;border:1px solid currentColor}.gA,.gB{color:var(--pass)}.gC{color:var(--medium)}.gD,.gF{color:var(--critical)}
.areas{border-collapse:collapse}.areas td,.areas th{padding:3px 14px 3px 0;text-align:left}pre.fix{background:var(--bg);border:1px solid var(--bd);border-radius:6px;padding:8px;overflow:auto;white-space:pre-wrap}
"""

# Filtering logic: severity cards, area buttons and status buttons narrow the list; the state is kept in the URL hash.
SCRIPT = """
(function(){
var st={sev:'',mod:'',s:'all'};
var items=[].slice.call(document.querySelectorAll('.f')),heads=[].slice.call(document.querySelectorAll('h2[data-mod]'));
function show(e){var s=e.dataset.st;
 if(st.sev&&!((s==='FAIL'||s==='WARN')&&e.dataset.sev===st.sev))return false;
 if(st.mod&&e.dataset.mod!==st.mod)return false;
 if(st.s==='issues')return s==='FAIL'||s==='WARN';
 if(st.s==='PASS')return s==='PASS';
 if(st.s==='MANUAL')return s==='MANUAL';
 if(st.s==='SKIPPED')return s==='SKIPPED'||s==='ERROR';
 if(st.s==='SUPPRESSED')return s==='SUPPRESSED';
 return true}
function apply(){var n=0;items.forEach(function(e){var v=show(e);e.hidden=!v;if(v)n++});
 heads.forEach(function(h){var x=h.nextElementSibling,any=false;while(x&&x.classList.contains('f')){if(!x.hidden)any=true;x=x.nextElementSibling}h.hidden=!any});
 document.querySelectorAll('.c').forEach(function(b){b.setAttribute('aria-pressed',String(b.dataset.sev===st.sev&&!!st.sev))});
 document.querySelectorAll('#mods button').forEach(function(b){b.setAttribute('aria-pressed',String((b.dataset.m||'')===st.mod))});
 document.querySelectorAll('#stat button').forEach(function(b){b.setAttribute('aria-pressed',String(b.dataset.s===st.s))});
 document.getElementById('count').textContent='Showing '+n+' of '+items.length+' findings'+(st.sev?' - severity: '+st.sev:'');
 var h=[];if(st.sev)h.push('sev='+st.sev);if(st.mod)h.push('mod='+st.mod);if(st.s!=='all')h.push('s='+st.s);
 try{history.replaceState(null,'',h.length?'#'+h.join('&'):location.pathname+location.search)}catch(e){}}
document.querySelectorAll('.c[data-sev]').forEach(function(b){b.onclick=function(){st.sev=(st.sev===b.dataset.sev)?'':b.dataset.sev;if(st.sev&&st.s!=='all')st.s='all';apply()}});
document.querySelectorAll('#mods button').forEach(function(b){b.onclick=function(){st.mod=b.dataset.m||'';apply()}});
document.querySelectorAll('#stat button').forEach(function(b){b.onclick=function(){st.s=b.dataset.s;if(st.s!=='all'&&st.s!=='issues')st.sev='';apply()}});
document.querySelectorAll('.c[data-s]').forEach(function(b){b.onclick=function(){st.sev='';st.s=b.dataset.s;apply()}});
document.getElementById('exp').onclick=function(){items.forEach(function(e){e.open=true})};
document.getElementById('col').onclick=function(){items.forEach(function(e){e.open=false})};
document.getElementById('reset').onclick=function(){st={sev:'',mod:'',s:'all'};apply()};
function readHash(){var ok={sev:['critical','high','medium','low',''],s:['all','issues','PASS','MANUAL','SKIPPED','SUPPRESSED']};
 var n={sev:'',mod:'',s:'all'};
 location.hash.replace(/^#/,'').split('&').forEach(function(p){var kv=p.split('='),k=kv[0],v=kv[1]||'';try{v=decodeURIComponent(v)}catch(e){v=''}
  if(k==='sev'||k==='s'){if(ok[k].indexOf(v)>=0)n[k]=v}                      /* only known values are accepted from the address bar */
  else if(k==='mod'&&heads.some(function(h){return h.dataset.mod===v}))n.mod=v});
 st=n}
readHash();
window.addEventListener('hashchange',function(){readHash();apply()});
apply();
})();
"""

GAPS = ("Not covered by this scan: anything outside Microsoft Entra ID (Exchange, SharePoint, Teams, Defender, Azure resources), "
        "per-user MFA state, the Entra admin-center restriction, LinkedIn connections, the collaboration allow-list, password hash sync and the "
        "SSPR scope (these are listed as MANUAL items because Microsoft Graph cannot read them with an app-only token). "
        "A SKIPPED check means the data could not be read (permission, licence or preview feature); it is never a pass.")


HTML_EVIDENCE_CAP = 25          # the page shows this many affected objects per finding; JSON, CSV, SARIF and JUnit carry all of them


def _summary_html(summary, diff, esc):
    """Executive summary (score, per-area grades, top risks) and the comparison with the baseline, as plain classed markup."""
    if not summary:
        return ""
    areas = "".join(f'<tr><td>{esc(a["name"])}</td><td>{a["score"]}</td><td><span class="g g{esc(a["grade"])}">{esc(a["grade"])}</span></td></tr>'
                    for a in summary["areas"].values())
    risks = "".join(f'<li><span class="tag {esc(r["severity"])}">{esc(r["severity"])}</span> {esc(r["title"])} <code>{esc(r["id"])}</code></li>'
                    for r in summary["top_risks"]) or "<li>No open risks.</li>"
    cis = summary.get("cis_automated_pass_percent")
    # Spell out both fractions: a bare "37% of CIS checks" reads as wrong next to the "passed" card, which counts every control.
    rates = ""
    if cis is not None:
        rates += f'; {summary.get("cis_automated_pass", "?")} of {summary.get("cis_automated_total", "?")} automated CIS controls pass ({cis}%)'
    if summary.get("controls_evaluated"):
        rates += (f'; {summary["controls_pass"]} of {summary["controls_evaluated"]} evaluated controls pass overall '
                  "(manual, informational and skipped items are not counted)")
    html_ = (f'<section class="sum"><h2>Executive summary</h2><div class="score"><b class="bigscore">{summary["score"] if summary["score"] is not None else "n/a"}</b>'
             f'<span class="g g{esc(summary["grade"])}">{esc(summary["grade"])}</span><span class="mut">weighted posture score (0-100)'
             + esc(rates) + '</span></div>'
             f'<table class="areas"><thead><tr><th>Area</th><th>Score</th><th>Grade</th></tr></thead><tbody>{areas}</tbody></table>'
             f'<h3>Top risks</h3><ol class="risks">{risks}</ol>')
    if diff is not None:
        li = lambda ids: "".join(f"<code>{esc(i)}</code> " for i in ids) or "none"
        html_ += (f'<h3>Change since baseline</h3><ul><li><b>New problems:</b> {li(diff["new"])}</li><li><b>Resolved:</b> {li(diff["resolved"])}</li>'
                  f'<li><b>Newly accepted risk (not fixed):</b> {li(diff.get("accepted", []))}</li>'
                  f'<li><b>Changed affected objects:</b> {li(diff["changed"])}</li><li><b>No longer run:</b> {li(diff["not_run_now"])}</li></ul>')
    return html_ + "</section>"


def render_html(meta, findings, areas, summary=None, diff=None):
    """Build the report page. `areas` maps category id -> display title (and fixes the section order)."""
    esc = html.escape
    nonce = secrets.token_urlsafe(16)                 # lets our own <style>/<script> run while anything injected cannot
    counts = defaultdict(int)
    for f in findings:
        if f.status in ("FAIL", "WARN"):
            counts[f.severity] += 1

    cards = "".join(
        f'<button class="c{" zero" if not counts[s] else ""}" data-sev="{s}" aria-pressed="false">'
        f'<b class="n {s}">{counts[s]}</b>{s}</button>' for s in SEVERITIES[:4])
    cards += (f'<button class="c" data-s="PASS" aria-pressed="false"><b class="n pass">{sum(f.status == "PASS" for f in findings)}</b>passed</button>'
              f'<button class="c" data-s="MANUAL" aria-pressed="false"><b class="n manual">{sum(f.status == "MANUAL" for f in findings)}</b>manual</button>'
              f'<button class="c" data-s="SKIPPED" aria-pressed="false"><b>{sum(f.status in ("SKIPPED", "ERROR") for f in findings)}</b>skipped / error</button>')

    present = [a for a in areas if any(f.category == a for f in findings)]
    present += [a for a in dict.fromkeys(f.category for f in findings) if a not in areas]
    title = lambda a: areas.get(a, a)
    modbar = '<button data-m="" aria-pressed="true">All areas</button>' + "".join(
        f'<button data-m="{esc(a)}" aria-pressed="false">{esc(title(a))} ({sum(1 for f in findings if f.category == a and f.status in ("FAIL", "WARN"))})</button>'
        for a in present)

    body = []
    for a in present:
        body.append(f'<h2 data-mod="{esc(a)}">{esc(title(a))}</h2>')
        for f in sorted((x for x in findings if x.category == a), key=lambda x: (STATUS_ORDER.get(x.status, 9), SEV_RANK.get(x.severity, 9), x.id)):
            sev = f.severity if f.status in ("FAIL", "WARN") else ""
            shown = f.evidence[:HTML_EVIDENCE_CAP]
            evidence = "".join(f"<li>{esc(str(e))}</li>" for e in shown)
            if len(f.evidence) > len(shown):
                evidence += f'<li class="mut">... and {len(f.evidence) - len(shown)} more (full list in the JSON / CSV report)</li>'
            learn = (f'<p class="learn"><b>Microsoft Learn:</b> <a href="{esc(f.learn)}" target="_blank" rel="noopener noreferrer">'
                     f'{esc(f.learn.replace(LEARN_PREFIX, ""))}</a></p>') if f.learn.startswith(LEARN_PREFIX) else ""
            body.append(
                f'<details class="f" data-st="{esc(f.status)}" data-sev="{esc(sev)}" data-mod="{esc(a)}" data-cat="{esc(f.category)}"><summary>'
                f'<span class="tag {esc(sev or f.status)}">{esc(sev or f.status)}</span>'
                f'<span class="tag {esc(f.status)}">{esc(f.status)}</span><strong>{esc(f.title)}</strong>'
                f'<span class="mut"><code>{esc(f.id)}</code></span></summary><div class="b">'
                + (f"<p>{esc(f.detail)}</p>" if f.detail else "")
                + (f'<p><b>Setting checked:</b> <code>{esc(f.setting)}</code></p>' if f.setting else "")
                + (f'<p><b>Needs permission:</b> <code>{esc(f.needs)}</code></p>' if f.needs and f.status in ("SKIPPED", "ERROR") else "")
                + (f"<p><b>Fix:</b> {esc(f.remediation)}</p>" if f.remediation else "")
                + learn
                + (f'<p class="mut">{esc(f.cis)}</p>' if f.cis else "")
                + (f'<p class="mut">{esc("; ".join(k + ": " + ", ".join(v) for k, v in f.frameworks.items()))}</p>' if f.frameworks else "")
                + (f'<p><b>Accepted risk</b> (was {esc(f.suppression.get("original_status", ""))}) by {esc(f.suppression.get("owner", ""))} until '
                   f'{esc(f.suppression.get("expires", ""))}: {esc(f.suppression.get("reason", ""))}</p>' if f.suppression else "")
                + (f'<p class="mut">Guidance only, never run by this tool:</p><pre class="fix">{esc(f.script)}</pre>' if f.script else "")
                + (f'<p class="mut">Affected (name [identifier]):</p><ul>{evidence}</ul>' if evidence else "") + "</div></details>")

    metas = " &middot; ".join(f"{esc(str(k))}: {esc(str(v))}" for k, v in meta.items())
    csp = f"default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; base-uri 'none'; form-action 'none'"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{csp}"><meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Entra ID Posture Report</title>
<style nonce="{nonce}">{STYLE}</style></head><body>
<h1>Microsoft Entra ID posture report</h1>
<div class="mut">{metas}</div>
{_summary_html(summary, diff, esc)}
<div class="cards" role="group" aria-label="Filter by severity">{cards}</div>
<div class="bar" id="mods" role="group" aria-label="Filter by area"><span class="lbl">Area</span>{modbar}</div>
<div class="bar" id="stat" role="group" aria-label="Filter by status"><span class="lbl">Status</span>
<button data-s="all" aria-pressed="true">All</button><button data-s="issues">Issues only</button><button data-s="PASS">Passed</button><button data-s="MANUAL">Manual (CIS)</button><button data-s="SUPPRESSED">Accepted risk</button><button data-s="SKIPPED">Skipped / errors</button></div>
<div class="tools"><button id="exp">Expand all</button><button id="col">Collapse all</button><button id="reset">Reset filters</button></div>
<div id="count" aria-live="polite"></div>
{chr(10).join(body)}
<h2>Coverage gaps</h2><p class="mut">{esc(GAPS)}</p>
<script nonce="{nonce}">{SCRIPT}</script></body></html>"""


# --------------------------------------------------------------------------- CSV
def csv_safe(v):
    """Neutralise spreadsheet formula injection: tenant-controlled names such as '=HYPERLINK(...)' must stay plain text in Excel."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def export_csv(findings, path):
    """Write findings to a CSV file (UTF-8 with BOM so Excel opens it correctly). The file is private to the current user."""
    buf = io.StringIO(newline="")
    w = csv.writer(buf)                    # nosemgrep: use-defusedcsv  (every cell goes through csv_safe() below, which neutralises formulas)
    w.writerow(["id", "area", "status", "severity", "title", "detail", "remediation", "evidence", "cis", "learn_url", "setting", "frameworks", "fingerprint", "suppression"])
    for f in sorted(findings, key=lambda x: (STATUS_ORDER.get(x.status, 9), SEV_RANK.get(x.severity, 9), x.id)):
        w.writerow([csv_safe(x) for x in (f.id, f.category, f.status, f.severity if f.status in ("FAIL", "WARN") else "", f.title, f.detail,
                                          f.remediation, " | ".join(map(str, f.evidence)), f.cis, f.learn, f.setting,
                                          json.dumps(f.frameworks) if f.frameworks else "", f.fingerprint,
                                          json.dumps(f.suppression) if f.suppression else "")])
    write_private(path, "﻿" + buf.getvalue())
