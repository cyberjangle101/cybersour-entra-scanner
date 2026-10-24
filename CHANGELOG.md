# Changelog

## 1.1.1 (unreleased)
- Fix GRP-003 (public Microsoft 365 groups) failing with 400 Request_UnsupportedQuery: `visibility` is not filterable on `/groups`,
  so Microsoft 365 groups are read and filtered for Public in the scanner.
- Fix AUTH-001..007 failing with 400 Request_UnsupportedQuery: method configurations are now read from the inline
  `authenticationMethodConfigurations` of `/policies/authenticationMethodsPolicy` (per-method GET by id as a fallback) instead of
  listing the collection, which Graph does not support.
- Fix unattended Windows runs hanging at a hidden secret prompt: stdin redirected from NUL (scheduled tasks, services, CI) reports
  `isatty()` True, so the CLI now also requires a real console (`GetConsoleMode`) before prompting.
- Tests: file-mode (600) assertions apply on POSIX only; `tests/uat.py` no longer reads the real console and reports the browser run
  as NOT RUN (not FAIL) when Playwright is missing.
- CI: Gitleaks runs from the checksum-verified release binary (the action is outside the allowed-actions policy) with reviewed
  false positives in `.gitleaks.toml`; TruffleHog no longer passes `--fail` twice; pip-audit audits `constraints.txt`.
- CI: Semgrep findings already accepted in `docs/security/semgrep-triage.json` are marked inline with `nosemgrep` so the CI gate
  passes; the ZAP baseline ignores reviewed test-server alerts (`.zap/rules.tsv`) and no longer tries to open issues.
- Report: "checks run" is now "check groups run" and says how many could not read their data (a group yields several findings,
  so the old label read as a wrong total). JSON `meta` key renamed from `checks run` to `check groups run`.
- Report: the CIS pass rate states its counts ("N of M automated CIS controls pass") next to the overall rate over every control
  with a verdict; `summary` gains `controls_evaluated`, `controls_pass`, `cis_automated_total`, `cis_automated_pass`.
- Baseline comparison: a problem waived since the baseline is listed as "newly accepted risk", no longer as "resolved"
  (found in UAT). `diff` gains `accepted`.
- Desktop window: the progress bar fills per check group and ends with Complete / Partial / Failed instead of just stopping.
- UAT-27 drives the Advanced panel in the real window with the real pipeline; UAT-17 and UAT-27 run on Windows without xvfb.
  README documents the Advanced panel and what each report number counts.

## 1.1.0
- New check groups: break-glass verification (ADM-011..014), hybrid sync (HYB), named locations (NET), Conditional Access quality (CAQ), privileged depth (PRV),
  app-registration risk (APP-030..033), legacy sign-in evidence (LEG), partner tenants (GST), authentication strengths (AUT-001). Still the same ten Graph permissions.
- CA-008 no longer counts detected emergency-access accounts as risky exclusions.
- Sign-in without a stored secret: workload identity federation, managed identity, Key Vault secret source.
- Sovereign clouds (`--cloud`), proxy, CA bundle, request timeout, per-check budget, maximum runtime, verbose log file.
- Accepted-risk file (owner, reason, expiry), policy file (disable checks / change severity), baseline comparison, multi-tenant batch mode.
- Executive summary and score, NIST 800-53 / ISO 27001 cross-references, remediation guidance snippets (text only).
- SARIF 2.1.0 and JUnit outputs; JSON, CSV, SARIF and JUnit carry the complete evidence list (HTML shows the first 25 per finding).
- `tools/setup_app_registration.ps1` (untested; see LIVE_VALIDATION.md).

## 1.0.0
- Initial standalone Entra ID scanner (CIS Microsoft 365 Foundations v5.0.0, 43 Entra controls).
