"""Build a PDF evidence report from a semgrep JSON result (proof that the static analysis ran over the whole code base).
Usage: python tools/semgrep_pdf.py docs/security/semgrep.json docs/security/semgrep-report.pdf [run.log] [triage.json]
triage.json (optional): {"<check_id>|<path>:<line>": "reason this finding is accepted / fixed"}"""
import collections, datetime, json, os, re, sys
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, KeepTogether

src, dst = sys.argv[1], sys.argv[2]
log = open(sys.argv[3], encoding="utf-8", errors="replace").read() if len(sys.argv) > 3 and os.path.exists(sys.argv[3]) else ""
triage = json.load(open(sys.argv[4], encoding="utf-8")) if len(sys.argv) > 4 and os.path.exists(sys.argv[4]) else {}
d = json.load(open(src, encoding="utf-8"))
root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(src))))

ss = getSampleStyleSheet()
H1, H2, B = ss["Title"], ss["Heading2"], ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
S = ParagraphStyle("s", parent=B, fontSize=7.5, leading=9.5)
M = ParagraphStyle("m", parent=S, fontName="Courier", fontSize=7)
esc = lambda x: str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
P = lambda t, st=S: Paragraph(esc(t), st)

scanned = sorted(d.get("paths", {}).get("scanned", []))
skipped = d.get("paths", {}).get("skipped", [])
results, errors = d.get("results", []), d.get("errors", [])
sev = collections.Counter(r["extra"]["severity"] for r in results)
m = re.search(r"Scanning (\d+) files? .*?with (\d+) (?:Code )?rules", log.replace("\n", " "))
rules_line = m.group(0) if m else "(rule count not captured in log)"
by_ext = collections.Counter(os.path.splitext(f)[1] or "(none)" for f in scanned)
loc = 0
for f in scanned:
    try:
        loc += sum(1 for _ in open(os.path.join(root, f), encoding="utf-8", errors="ignore"))
    except OSError:
        pass

story = [Paragraph("Static Application Security Testing report", H1), Paragraph("Semgrep scan of the Entra ID Posture Scanner", ss["Heading3"]), Spacer(1, 6)]
meta = [["Tool", f"Semgrep {d.get('version', '?')} (open-source CLI, offline, metrics off)"],
        ["Date", datetime.date.today().isoformat()],
        ["Target", "Entire repository: application, tests, tools, docs, CI workflows, launchers"],
        ["Rule sources", "Official semgrep-rules repository (github.com/semgrep/semgrep-rules): python, javascript, generic, yaml, bash"],
        ["Scope proof", f"{len(scanned)} files scanned, {loc:,} lines; {len(skipped)} files skipped by semgrep"],
        ["Engine summary", rules_line],
        ["Findings", f"{len(results)} total  (ERROR {sev.get('ERROR', 0)}, WARNING {sev.get('WARNING', 0)}, INFO {sev.get('INFO', 0)}); scan errors: {len(errors)}"]]
t = Table([[P(a, B), P(b, B)] for a, b in meta], colWidths=[32 * mm, 140 * mm])
t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
story += [t, Spacer(1, 8)]
verdict = "No findings were reported." if not results else f"{len(results)} finding(s) reported; each is triaged below."
story += [Paragraph("Result", H2), Paragraph(esc(verdict + " Errors during the scan: " + (str(len(errors)) if errors else "none") + "."), B), Paragraph("Files by type", H2)]
story += [Table([[P(k), P(v)] for k, v in sorted(by_ext.items())], colWidths=[40 * mm, 30 * mm], style=[("GRID", (0, 0), (-1, -1), 0.3, colors.grey)])]

story += [Paragraph("Findings and triage", H2)]
if results:
    rows = [[P("Severity"), P("Rule"), P("Location"), P("Disposition")]]
    for r in results:
        key = f"{r['check_id']}|{r['path']}:{r['start']['line']}"
        rows.append([P(r["extra"]["severity"]), P(r["check_id"].split(".")[-1] + " - " + r["extra"]["message"][:160]), P(f"{r['path']}:{r['start']['line']}"),
                     P(triage.get(key) or triage.get(r["check_id"].split(".")[-1] + "|" + r["path"]) or triage.get(r["check_id"].split(".")[-1], "UNTRIAGED"))])
    t = Table(rows, colWidths=[18 * mm, 78 * mm, 38 * mm, 40 * mm], repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)
else:
    story.append(Paragraph("None.", B))
if errors:
    story += [Paragraph("Scan errors", H2)] + [Paragraph(esc(e.get("message", str(e))[:300]), S) for e in errors[:30]]

story += [PageBreak(), Paragraph("Appendix A - files scanned (proof of coverage)", H2)]
story += [Paragraph(esc("  |  ".join(scanned)), M)]
if skipped:
    story += [Paragraph("Appendix B - files skipped by semgrep", H2), Paragraph(esc("  |  ".join(f"{s.get('path')} ({s.get('reason')})" if isinstance(s, dict) else str(s) for s in skipped[:200])), M)]
story += [Paragraph("Appendix C - scan log (tail)", H2), Paragraph(esc(log[-2500:] or "(no log supplied)").replace("\n", "<br/>"), M)]
story += [Spacer(1, 8), Paragraph("Reproduce: git clone https://github.com/semgrep/semgrep-rules; semgrep scan --metrics=off --config semgrep-rules/python --config semgrep-rules/generic "
                                  "--config semgrep-rules/javascript --config semgrep-rules/yaml --config semgrep-rules/bash --json -o semgrep.json .", S)]
SimpleDocTemplate(dst, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm, title="Semgrep SAST report").build(story)
print("wrote", dst, "| findings:", len(results), "| files:", len(scanned))
