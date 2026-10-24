"""UAT + dynamic analysis of the HTML report in a REAL browser (Chromium via Playwright), served over HTTP.
Hostile strings are embedded in the report; the test proves none executes, the CSP holds, and the filters work for a user.
Prints one JSON object. Usage: python tests/uat_browser.py [screenshot_dir]"""
import http.server, json, os, socketserver, subprocess, sys, tempfile, threading
from playwright.sync_api import sync_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
shots = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp()
site = tempfile.mkdtemp()
subprocess.run([sys.executable, os.path.join(ROOT, "tools", "make_sample_report.py"), site], check=True, capture_output=True)


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(s, *a, **k): super().__init__(*a, directory=site, **k)
    def log_message(s, *a): pass


srv = socketserver.TCPServer(("127.0.0.1", 0), H); port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = f"http://127.0.0.1:{port}/index.html"
out = {"dialogs": [], "console_errors": [], "csp_violations": [], "requests": []}

with sync_playwright() as p:
    b = p.chromium.launch()
    for scheme in ("light", "dark"):
        pg = b.new_page(color_scheme=scheme, viewport={"width": 1280, "height": 900})
        pg.on("dialog", lambda d: (out["dialogs"].append(d.message), d.dismiss()))      # any alert()/confirm() = script executed
        pg.on("console", lambda m: out["console_errors"].append(m.text) if m.type in ("error", "warning") else None)
        pg.on("request", lambda r: out["requests"].append(r.url) if not r.url.startswith(f"http://127.0.0.1:{port}") and not r.url.startswith("data:") else None)
        pg.add_init_script("document.addEventListener('securitypolicyviolation', e => console.error('CSPVIOLATION ' + e.violatedDirective))")
        pg.goto(URL); pg.wait_for_timeout(300)
        if scheme == "light":
            txt = lambda: pg.inner_text("#count")
            out["initial_count"] = txt()
            pg.click('.c[data-sev="critical"]'); out["critical_count"] = txt(); out["critical_hash"] = pg.evaluate("location.hash")
            out["critical_pressed"] = pg.get_attribute('.c[data-sev="critical"]', "aria-pressed")
            pg.click('.c[data-sev="critical"]'); out["toggle_off_count"] = txt()
            pg.click('.c[data-sev="high"]'); out["high_count"] = txt()
            pg.click("#reset"); pg.click('#mods button[data-m="ca"]'); out["area_ca_count"] = txt()
            pg.click("#reset"); pg.click('#stat button[data-s="MANUAL"]'); out["manual_count"] = txt()
            pg.click("#reset"); pg.click("#exp"); out["all_open"] = pg.evaluate("[...document.querySelectorAll('.f')].every(e=>e.open)")
            pg.click("#col"); out["all_closed"] = pg.evaluate("[...document.querySelectorAll('.f')].every(e=>!e.open)")
            # keyboard: severity cards are real buttons reachable by Tab and activated by Enter
            pg.click("#reset"); pg.focus('.c[data-sev="critical"]'); pg.keyboard.press("Enter"); out["keyboard_filter_works"] = "severity: critical" in txt()
            # deep links, including hostile ones
            pg.goto(URL + "#sev=high&mod=ca"); pg.reload(); out["deeplink_count"] = txt()
            pg.goto(URL + '#sev=<img src=x onerror=alert(9)>&mod="><script>alert(8)</script>&s=%3Cb%3E'); pg.reload(); out["hostile_hash_count"] = txt()
            pg.goto(URL); pg.screenshot(path=os.path.join(shots, "report-light.png"))
            # mobile: no horizontal scroll
            pg.set_viewport_size({"width": 375, "height": 800}); pg.wait_for_timeout(200)
            out["mobile_horizontal_scroll"] = pg.evaluate("document.documentElement.scrollWidth > window.innerWidth + 1")
            pg.screenshot(path=os.path.join(shots, "report-mobile.png"))
            # injected content check: hostile text is displayed as TEXT
            out["hostile_title_shown_as_text"] = "<img src=x onerror=alert(1)>" in pg.inner_text("body")
            out["injected_elements"] = pg.evaluate("document.querySelectorAll('img[src=x], svg[onload], body script:not([nonce])').length")
            out["javascript_links"] = pg.evaluate("[...document.querySelectorAll('a')].filter(a=>a.href.startsWith('javascript:')).length")
            out["external_links_safe"] = pg.evaluate("[...document.querySelectorAll('a[target=_blank]')].every(a=>/noopener/.test(a.rel))")
            # try to run inline script and inline handler: the CSP must stop both
            out["csp_blocks_inline_script"] = pg.evaluate("""() => new Promise(res => { const s=document.createElement('script'); s.textContent='window.__pwned=1'; document.body.appendChild(s); setTimeout(()=>res(!window.__pwned),100)})""")
            out["csp_meta"] = pg.evaluate("document.querySelector('meta[http-equiv=Content-Security-Policy]').content")
        else:
            pg.screenshot(path=os.path.join(shots, "report-dark.png"))
    b.close()
out["csp_violations"] = [m for m in out["console_errors"] if m.startswith("CSPVIOLATION")]
out["console_errors"] = [m for m in out["console_errors"] if not m.startswith("CSPVIOLATION")]
print(json.dumps(out))
