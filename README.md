# Microsoft Entra ID Posture Scanner

A **read-only** scanner for Microsoft Entra ID, aligned to the CIS Microsoft 365 Foundations Benchmark **v5.0.0** (all 43 Entra controls are covered:
36 evaluated automatically, 7 listed as MANUAL items that Microsoft Graph cannot read), plus extra checks beyond CIS (break-glass verification, hybrid sync health,
named locations, Conditional Access quality, permanent privileged assignments, app-registration risk, legacy sign-in evidence, partner tenants, authentication strengths).
It produces a filterable HTML report with an executive score, JSON, and optional CSV, SARIF and JUnit. Command line and desktop window. See `docs/CIS_COVERAGE.md`.
Still the same ten read-only Graph permissions as v1.0.

## 1. Create the app registration (once)
1. Entra admin center > App registrations > New registration (single tenant). Note the **Application (client) ID** and **Tenant ID**.
2. API permissions > Add > Microsoft Graph > **Application permissions**, add exactly these ten (also in `python entra_posture_scan.py --list-permissions`):

| Permission | Used for |
|---|---|
| `Policy.Read.All` | Conditional Access, Security Defaults, authorization policy, authentication methods, admin consent workflow, cross-tenant access |
| `Policy.Read.DeviceConfiguration` | Device join/registration settings (`Policy.Read.All` does not cover this one for apps) |
| `Directory.Read.All` | Organisation, domains, groups, group settings, licence SKUs, delegated consent grants |
| `User.Read.All` | Users, guests, licences, password flags |
| `Application.Read.All` | App registrations, enterprise apps and their granted permissions |
| `AuditLog.Read.All` | MFA registration report and last sign-in dates |
| `RoleManagement.Read.Directory` | Admin role assignments and PIM eligibility |
| `RoleManagementPolicy.Read.Directory` | PIM activation rules |
| `AccessReview.Read.All` | Access review definitions |
| `IdentityRiskyUser.Read.All` | Identity Protection risky users |

3. Click **Grant admin consent**. Per-endpoint verification is in `docs/PERMISSIONS.md`.
4. Certificates & secrets: create a client secret (short expiry) or upload a certificate, **or** use no stored secret at all (section 2, "No stored secret").
   `tools/setup_app_registration.ps1 -WhatIf` automates steps 1-4 (it needs the Microsoft Graph PowerShell SDK; it has not been run by the author, so read it and use `-WhatIf` first).

Licences: Conditional Access / sign-in activity need Entra ID P1; PIM, access reviews, Identity Protection need P2. A check that cannot read its data is reported **SKIPPED** (never PASS).

## 2. Run it
```
pip install -r requirements.txt
python entra_posture_scan.py --tenant <tenant> --client-id <app id> --prompt-secret
python entra_posture_gui.py            # desktop window
```
Secret sources (there is deliberately **no** `--client-secret VALUE` flag, because command-line values are visible to other users and shell history):
`AZURE_CLIENT_SECRET` environment variable, `--prompt-secret`, `--secret-stdin`, or `--client-secret-file PATH`.
Certificate sign-in: `--auth cert --cert-path key.pem --cert-thumbprint <sha1> [--prompt-passphrase]`.

Useful options: `--areas ca roles` (subset), `--csv`, `--sarif`, `--junit`, `--fail-on high`, `--min-coverage 90` (CI exit codes), `--list-checks`.
Exit codes: 0 ok, 1 gate failed, 2 settings problem, 3 unexpected error.

**No stored secret**
- `--auth federated` exchanges an external identity token (workload identity federation). In GitHub Actions with `permissions: id-token: write` nothing else is needed;
  elsewhere give `--federated-token-file PATH` (Kubernetes / Azure workload identity). Create the federated credential on the app (the setup script can do it).
- `--auth managed-identity` uses the Azure VM / Function / Automation / Container App identity (grant it the ten Graph app roles). `--client-id` selects a user-assigned identity.
- `--keyvault-secret https://<vault>.vault.azure.net/secrets/<name>` reads the client secret from Key Vault with the managed identity at run time.

**Clouds and networks**: `--cloud commercial|usgov|usgovdod|china` (GCC High, DoD, 21Vianet; GCC uses commercial), `--proxy URL`, `--ca-bundle PEM`, `--timeout SEC`,
`--check-timeout SEC` (a slow check becomes SKIPPED), `--max-runtime SEC` (report marked PARTIAL), `--verbose` / `--log-file PATH` (request paths, status and timing only; never tokens or bodies).

**Decisions and trends** (JSON files, validated strictly; unknown keys are rejected):
- `--policy policy.json` &nbsp; `{"disable": ["CA-009"], "severity": {"ADM-004": "medium"}}`
- `--suppressions waivers.json` &nbsp; `[{"id": "CA-008", "owner": "j.smith", "reason": "break-glass design", "expires": "2026-12-31", "scope": ["bg1@"]}]`
  Owner, reason and expiry are mandatory. A waived finding becomes **SUPPRESSED** (still shown, left out of the score and the `--fail-on` gate). An expired waiver is ignored and flagged. `scope` limits a waiver to named objects, so a new bad object is not hidden.
- `--baseline earlier-report.json` shows what is new, resolved or changed since that run.
- `--batch tenants.json` scans many tenants and writes `combined-*.html`; the file may reference credentials (`client_secret_file`, `cert_path`, `federated_token_file`, `keyvault_secret`) but **never contains secret values**:
  `{"tenants": [{"name": "contoso", "tenant": "contoso.com", "client_id": "<guid>", "client_secret_file": "/secure/contoso.txt"}], "defaults": {"cloud": "commercial"}}`

**Desktop window: the "Advanced: network, decisions, extra outputs" panel.** All fields are optional; leave them empty for a normal scan.
Each one is the same as a command-line option above and is checked when you press *Run scan*, before anything signs in (a wrong path,
a bad proxy address or a malformed file gives a message and nothing starts).

| Field | Same as | What it does |
|---|---|---|
| Proxy URL | `--proxy` | Send all Microsoft sign-in and Graph traffic through this proxy. Must start with `http://` or `https://`. |
| CA bundle | `--ca-bundle` | A PEM file of extra trusted root certificates, for networks that inspect TLS. |
| Policy file | `--policy` | Your organisation's decisions: turn checks off (`disable`) or change their severity (`severity`). Shown in the report header. |
| Accepted-risk file | `--suppressions` | Risks you have accepted, each with owner, reason and expiry. They show as **SUPPRESSED**, are left out of the score, and come back when the waiver expires. |
| Compare with report | `--baseline` | An earlier JSON report from this tool. The new report lists what is new, resolved (actually fixed), newly accepted risk (waived, not fixed) and changed. |
| Seconds per check (0=off) | `--check-timeout` | A check group that takes longer is stopped and reported **SKIPPED**, never PASS. |
| Also write SARIF / JUnit XML | `--sarif` / `--junit` | Extra files for code-scanning dashboards and CI test reports, next to the HTML and JSON. |

The progress bar fills as each check group finishes and ends with **Complete**, **Complete - N check groups could not run**
(look at *Skipped / errors* for the missing permission or licence), **Partial** (cancelled or stopped early) or **Failed** (see the log).

**Windows .exe** (`EntraPostureScanner-GUI.exe` = window, `EntraPostureScanner-CLI.exe` = command line): run `build_exe.bat` on a Windows PC with Python installed (it builds in a clean virtual environment and prints any error), or push the repo to GitHub and run the *build-windows-exe* workflow, then download the `EntraPostureScanner-windows` artifact.

## 3. Reading the report
Statuses: PASS, WARN, FAIL, INFO, **MANUAL** (cannot be read via Graph; do it by hand), **SUPPRESSED** (accepted risk with owner and expiry), SKIPPED / ERROR (could not run). Click a severity card, area or status button to filter.
The **score** (0-100, letter grade) is a weighted share of failed risk: critical 10, high 6, medium 3, low 1; WARN counts half; passed controls count at the weight they would carry if they failed. It is a trend indicator, not a compliance rating.

What the numbers count:
- **Check groups run: 25 of 33** - the scanner has 33 check groups (one per area of settings it reads). Each group produces several
  findings, which is why the report lists far more than 33 items. A group that cannot read its data (missing permission or licence)
  appears under *Skipped / errors*; it is never counted as passed.
- **N of M automated CIS controls pass** - only findings that map to a CIS Microsoft 365 benchmark item *and* got a verdict
  (PASS, FAIL or WARN). MANUAL items, informational findings and findings without a CIS reference are not in this number.
- **N of M evaluated controls pass overall** - every finding with a verdict, CIS-mapped or not. This is the same PASS count as the
  *passed* card; the card total also includes MANUAL, INFO and skipped items, which have no verdict.
The page shows the first 25 affected objects of each finding; JSON, CSV, SARIF and JUnit carry all of them. Each finding also lists indicative NIST 800-53 and ISO 27001 references (evidence for the control, not proof of compliance), and failing items carry guidance snippets that are text only and never run by the tool.

## 4. Safety
Only GET requests to the selected cloud's Graph host; redirects are never followed; tokens never leave that host; reports are written owner-only; the report page has a
nonce-based Content-Security-Policy. See `SECURITY.md`. Not covered: Exchange, SharePoint, Teams, Defender, Azure resources (separate apps).

## 5. Development
`python -m pytest tests` runs unit, rule-matrix, CLI, report, GUI-logic and fuzz tests. `python tools/gen_docs.py` regenerates `docs/`.
`python tests/uat.py` runs the user-acceptance scenarios (GUI ones need tkinter; the browser one needs Playwright + Chromium).
`python tools/zap_local.py` runs the same OWASP ZAP baseline as CI without Docker; it needs ZAP 2.17 (cross-platform zip) and a Java 17+
runtime, by default in `%LOCALAPPDATA%\Programs\zap\ZAP_2.17.0` and `%LOCALAPPDATA%\Programs\temurin-jre-21` (or `--zap-home` / `--java`).
The full pre-merge checklist is in `CLAUDE.md`.
