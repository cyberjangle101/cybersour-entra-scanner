# Security assurance summary (2026-10-24)

| Check | Tool | Result | Evidence |
|---|---|---|---|
| Static analysis | **Semgrep 1.182.1**, 864 official rules (python, javascript, generic, yaml, bash) | Ran over the **whole repository** (v1.1.0): 70 files, 0 scan errors. 94 findings, all triaged: 0 exploitable; real items fixed (unpinned CI actions, missing file encodings, NaN test, urllib scheme guard); rest false positives or test-only | `semgrep-report.pdf` (proof of scope + triage), `semgrep.json`, `semgrep-run.log`, `semgrep-triage.json` |
| Extra static analysis | In-house AST scanner (`tools/sast.py`) | No HIGH/MEDIUM in application code (test-only subprocess calls accepted) | `python tools/sast.py` |
| Secrets scanning | **trufflehog v3 (Truffle Security) did NOT run here** - the build environment blocks GitHub release downloads and the Go module proxy, so it could not be installed or compiled. Substitutes ran: `trufflehog3` (a different, PyPI Python project), `detect-secrets`, and the in-house scanner | 0 real secrets. detect-secrets: 7 hits, all false positives (UI labels, a deliberate hostile test URL, setting names, a test canary) | `trufflehog3.json`, `scan-ds.json`. **A real trufflehog workflow is shipped** (`.github/workflows/trufflehog.yml`, SHA-pinned) - run it on first push |
| Dynamic analysis | **OWASP ZAP did NOT run here** (no release download, no Docker daemon). Substitute: real-Chromium test of the HTML report with hostile data (`tests/uat_browser.py`, UAT-18) | 0 alert dialogs, 0 injected elements, 0 javascript: links, 0 external requests; CSP blocked an injected inline script; only the deliberate probe violated CSP. **A ZAP baseline workflow is shipped** (`.github/workflows/zap.yml`) | `docs/UAT.md`, `docs/screenshots/`. Note: the product has no web server; the report page is its only web surface |
| Dependency scanning | **pip-audit** (OSV/PyPI advisories) on the fully pinned tree | 10 packages, 0 known vulnerabilities | `pip-audit.json`, `constraints.txt` |
| Fuzzing | Custom seeded fuzzer, seed 1337 x 1000 iterations plus 10 further seeds x 300-800 during hardening (`tests/fuzz.py`, `fuzz-report.txt`) | 0 problems. Inputs: Graph API responses (incl. the v1.1 endpoints), policy / accepted-risk / baseline / batch files, federated-token and Key Vault inputs, every CLI flag/value, GUI form values, GUI settings file, credential sources (stdin/file/prompt), helper functions, report/CSV writers | `fuzz-report.txt` |

## Defects found by these activities (and fixed)
* Conditional Access: a *user-risk* policy that also required MFA wrongly satisfied "MFA for all users" (false PASS). Policies narrowed by risk, platform, location, device filter or client type no longer count.
* Authorization policy: consent-policy assignment was read from one location only; now both documented locations are read (would have been a false PASS).
* Report CSP: inline `style=` attributes were blocked by the report's own Content-Security-Policy in a real browser (severity colours lost). Replaced by classes.
* GUI: an extremely long certificate path raised an unhandled `OSError`; now a friendly message.
* Graph client: non-object / malformed pages are now rejected centrally (`checked_page`); rows lacking identifiers are skipped instead of raising.
* Report deep links react to hash changes and accept only known filter values.

* v1.1 fuzzing found: a NUL byte in `--federated-token-file` escaped as a raw `ValueError` (now a ConfigError); several new checks and `load_admins` / `Ctx` id maps assumed Graph fields were strings or dicts (now guarded, so odd data no longer ends a check as ERROR).

## Known limits
* Fuzzed hostile data can still end a few long-standing checks (access reviews, app permissions, device settings, user staleness, cross-tenant access, authenticator settings) as ERROR; this is the designed safe outcome (reported, never PASS).
* All tests use a pretend Graph; see `LIVE_VALIDATION.md` for what needs one run against a real tenant.
* With deliberately corrupted API data, individual checks may end as ERROR (reported, counted as "not run", never PASS); the scan itself never crashes.
