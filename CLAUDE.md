# Entra Posture Scanner - project guide for Claude Code

Read-only Microsoft Entra ID posture scanner (CIS Microsoft 365 Foundations v5.0.0 aligned). Python 3.10+, CLI + tkinter GUI.
Everything it does against Microsoft Graph is a GET. It must stay that way, and it must stay within the 10 permissions in `entra_scan/permissions.py` (PURPOSE).

## Working efficiently (saves credits)
- Do not re-read files you just edited, and do not dump big files. Use Grep for a symbol, then Read only the lines you need (offset/limit).
- Start from this map instead of exploring:
  - `entra_scan/checks/*.py` one file per area; each check is `@check(area, needs=(permissions,))`
  - `models.py` Finding + helpers | `graph.py` GET-only client | `auth.py` sign-in | `postprocess.py` policy/suppressions/baseline/score
  - `report.py` HTML/CSV | `export.py` SARIF/JUnit | `batch.py` multi-tenant | `cli.py` / `gui.py` front ends
  - `metadata.py` Learn links, setting paths, CIS and NIST/ISO mappings | `tests/fake_tenant.py` the pretend Graph
- Work in small steps and run the narrowest test first (`python -m pytest tests/test_checks.py -q -k ADM-011`). Run the full gate (below) ONCE when the change is finished, not after every edit.
- Never loop on a failing scan tool. If a tool cannot run (no network, not installed), say so once and move on.
- Keep replies short: what changed, what the gate showed, what is unverified. No recaps of steps.
- Do not regenerate or rewrite unchanged files, and never paste reports/PDFs/JSON into the chat; give the path.

## Rules for any change
- Read-only forever: no POST/PATCH/DELETE to Graph, no `*.ReadWrite.*` permission. Add a permission only with a Microsoft Learn citation in `permissions.ENDPOINTS`, and update `tools/setup_app_registration.ps1` (a test enforces the match).
- A check that cannot read its data is SKIPPED, never PASS. Treat all Graph data as hostile: guard types (`isinstance`), never use API values as dict keys unchecked, escape in reports.
- Secrets never as CLI values, never in logs/reports/batch files (files, env vars, prompts, Key Vault, federation only).
- New check = function in `checks/` + metadata entries (LEARN_PATHS, SETTING, frameworks) + fake-tenant data (healthy passes, weak fails) + one RULE_MATRIX row in `tests/test_checks.py`. Then `python tools/gen_docs.py`.
- Comments explain why in plain English; keep docstrings on every function.
- Say honestly what was only tested against mocks. Update `LIVE_VALIDATION.md` for anything needing a real tenant.

## Mandatory gate after EVERY code change (run all, report results honestly)
Run in this order; stop and fix on the first failure, then rerun from that step.
1. Unit/rule-matrix tests: `python -m pytest tests -q`
2. Docs in sync: `python tools/gen_docs.py` (a test fails if docs are stale)
3. Fuzzing (Python project, so tests/fuzz.py replaces Go native fuzzing): `python tests/fuzz.py 500 <new seed>` - must report `PROBLEMS: 0`. Extend `tests/fuzz.py` when a new input (flag, file, endpoint) is added.
4. User acceptance: `python tests/uat.py` (writes docs/UAT.md; all scenarios PASS). Add a scenario for every new user-visible feature. GUI/browser scenarios need python3.12+tkinter+xvfb-run and Playwright; if missing they print NOT RUN, which is not a pass - say so.
5. Stress: `python tests/uat.py` includes the 30,000-user tenant (UAT-16); for any change touching paging, users or evidence, also run `python tests/fuzz.py 2000` and confirm no slowdown versus the previous run.
6. Static analysis: `semgrep scan --config p/python --config p/security-audit --config p/secrets --metrics=off --json -o docs/security/semgrep.json .` then `python tools/semgrep_pdf.py docs/security/semgrep.json docs/security/semgrep-report.pdf docs/security/semgrep-run.log docs/security/semgrep-triage.json`. Every finding in app code is fixed or triaged with a reason in `semgrep-triage.json`. Also `python tools/sast.py`.
7. Secrets: `trufflehog filesystem . --no-update` and `trufflehog git file://. --no-update` if installed (CI also runs it; on the Windows dev PC it is `%LOCALAPPDATA%\Programs\trufflehog\trufflehog.exe`, not on PATH; exclude `.venv`); otherwise `trufflehog3` or `detect-secrets scan`, plus `python tools/secret_scan.py`. Entropy hits on SHA-pinned GitHub Action hashes are known false positives.
8. Dependencies: `osv-scanner --lockfile constraints.txt` (preferred) or `pip-audit -r constraints.txt`. Keep `constraints.txt` fully pinned.
9. Dynamic scan (OWASP ZAP): the only web surface is the generated HTML report. Run `python tools/zap_local.py` (portable ZAP + Java, no Docker; same baseline and `.zap/rules.tsv` as `.github/workflows/zap.yml` in CI; must print 0 alerts). New alerts are fixed, or added to `.zap/rules.tsv` with a reason only if they cannot apply to a local HTML file. If Docker/ZAP is unavailable locally, run `python tests/uat.py` (UAT-18 drives the report in real Chromium with hostile data) and state clearly that ZAP itself did not run.
10. Update `docs/security/SECURITY_ASSURANCE.md` with new counts, tool versions, defects found, and anything that did NOT run.

Skip a step only if the change cannot affect it (e.g. docs-only change: steps 1-2 only) and say which steps were skipped and why.

## Release
- Bump `__version__` in `entra_scan/__init__.py` and add a CHANGELOG entry.
- Windows build: `build_exe.bat` (Windows, local) or the `build-windows-exe` workflow. Outputs `EntraPostureScanner-GUI.exe` and `EntraPostureScanner-CLI.exe`. Cannot be built on Linux.
- Package without `__pycache__` / `.pytest_cache`.
