"""Machine-readable outputs for pipelines: SARIF 2.1.0 (code-scanning dashboards) and JUnit XML (CI test reports).

Both carry the COMPLETE evidence list of every finding. Values come from the tenant, so XML is produced with ElementTree
(which escapes text and attributes) and JSON with json.dumps; nothing is concatenated by hand.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET     # nosec nosemgrep: use-defused-xml  (used only to BUILD XML, never to parse untrusted input)

from . import __version__

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
OPEN = ("FAIL", "WARN")


def to_sarif(meta, findings):
    """SARIF log: one rule per check id, one result per open (or accepted-risk) finding. Accepted risks carry a suppression record."""
    rules, results = {}, []
    for f in findings:
        if f.status not in OPEN + ("SUPPRESSED",):
            continue
        rules.setdefault(f.id, {
            "id": f.id, "name": f.id.replace("-", ""), "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.remediation or f.title}, "helpUri": f.learn or "https://learn.microsoft.com/en-us/entra/",
            "properties": {"area": f.category, "cis": f.cis, "frameworks": f.frameworks, "tags": ["entra", "security"]}})
        sev = f.severity if f.severity in SARIF_LEVEL else "medium"
        res = {
            "ruleId": f.id, "level": SARIF_LEVEL[sev], "message": {"text": f"{f.title}: {f.detail}".strip(": ")},
            "locations": [{"logicalLocations": [{"name": str(meta.get("tenant", "tenant")), "kind": "namespace",
                                                  "fullyQualifiedName": f"{meta.get('tenant id', '?')}/{f.category}/{f.id}"}]}],
            "partialFingerprints": {"entraPosture/v1": f.fingerprint},
            "properties": {"status": f.suppression.get("original_status", f.status), "severity": sev, "evidence": [str(e) for e in f.evidence],
                           "setting": f.setting, "remediation": f.remediation}}
        if f.status == "SUPPRESSED":
            res["suppressions"] = [{"kind": "external", "status": "accepted",
                                    "justification": f"{f.suppression.get('reason', '')} (owner {f.suppression.get('owner', '?')}, until {f.suppression.get('expires', '?')})"}]
        results.append(res)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Entra Posture Scanner", "version": __version__, "informationUri": "https://learn.microsoft.com/en-us/entra/",
                            "rules": list(rules.values())}},
        "results": results, "properties": {"tenant": meta.get("tenant"), "scanned": meta.get("scanned")}}]}


def sarif_text(meta, findings):
    """SARIF as a JSON string."""
    return json.dumps(to_sarif(meta, findings), indent=2)


def junit_text(meta, findings, areas):
    """JUnit XML: a suite per area. FAIL/WARN = failure, ERROR = error, SKIPPED/MANUAL/SUPPRESSED = skipped, PASS/INFO = passed."""
    root = ET.Element("testsuites", name="Entra Posture Scanner", tests=str(len(findings)))
    for area in dict.fromkeys(f.category for f in findings):
        rows = [f for f in findings if f.category == area]
        suite = ET.SubElement(root, "testsuite", name=areas.get(area, area), tests=str(len(rows)),
                              failures=str(sum(f.status in OPEN for f in rows)), errors=str(sum(f.status == "ERROR" for f in rows)),
                              skipped=str(sum(f.status in ("SKIPPED", "MANUAL", "SUPPRESSED") for f in rows)))
        for f in rows:
            case = ET.SubElement(suite, "testcase", classname=f"entra.{area}", name=f"{f.id} {f.title}")
            body = f"{f.detail}\nFix: {f.remediation}\nAffected:\n" + "\n".join(str(e) for e in f.evidence)
            if f.status in OPEN:
                ET.SubElement(case, "failure", message=f"[{f.severity}] {f.title}"[:200], type=f.status).text = body
            elif f.status == "ERROR":
                ET.SubElement(case, "error", message=f.detail[:200], type="ERROR").text = body
            elif f.status in ("SKIPPED", "MANUAL", "SUPPRESSED"):
                ET.SubElement(case, "skipped", message=(f.detail or f.status)[:200])
    return ET.tostring(root, encoding="unicode", xml_declaration=False)
