"""Write a sample HTML report from the pretend tenant (hostile strings included) for dynamic-analysis tools such as OWASP ZAP.
Usage: python tools/make_sample_report.py OUTPUT_DIR"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "tests")]
from entra_scan import context, report, runner  # noqa: E402
from entra_scan.models import Finding  # noqa: E402
from fake_tenant import Args, FakeGraph, bad_tenant  # noqa: E402

out = sys.argv[1] if len(sys.argv) > 1 else "sample"
os.makedirs(out, exist_ok=True)
f = runner.run_scan(context.Ctx(FakeGraph(bad_tenant()), Args()), None, log=lambda *_: None)
evil = '"><img src=x onerror=alert(1)><script>alert(2)</script>'
f.append(Finding("HOSTILE-1", "ca", evil, "FAIL", "high", evil, evil, [evil, "<svg onload=alert(3)>"], cis=evil, learn="javascript:alert(4)", setting=evil))
open(os.path.join(out, "index.html"), "w", encoding="utf-8").write(report.render_html({"tenant": evil}, f, runner.AREAS))
print("wrote", os.path.join(out, "index.html"))
