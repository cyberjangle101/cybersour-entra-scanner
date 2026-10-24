"""Verify every Microsoft Learn link used by the scanner still resolves (needs internet; run locally or in CI).
Usage: python tools/check_links.py      Exit code 1 if any link is broken."""
import os, sys, urllib.error, urllib.request
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from entra_scan import metadata  # noqa: E402

urls = sorted({u for u in metadata.LEARN.values()})


def probe(u):
    if not u.startswith("https://learn.microsoft.com/"):      # only our own documentation links are ever fetched
        return u, "refused-non-learn-url"
    try:
        req = urllib.request.Request(u, headers={"User-Agent": "link-check"})
        with urllib.request.urlopen(req, timeout=20) as r:  # nosemgrep: dynamic-urllib-use-detected  (https learn.microsoft.com only, checked above)
            return u, r.status
    except urllib.error.HTTPError as e:
        return u, e.code
    except Exception as e:  # noqa: BLE001
        return u, type(e).__name__


with ThreadPoolExecutor(8) as ex:
    bad = [(u, s) for u, s in ex.map(probe, urls) if s != 200]
print(f"{len(urls)} links checked, {len(bad)} not OK")
for u, s in bad:
    print(" ", s, u)
sys.exit(1 if bad else 0)
