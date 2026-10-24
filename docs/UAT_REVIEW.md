# Cloud security engineer review: UAT verdict and gap analysis

Scope: Entra ID Posture Scanner v1.0.0. Tested against a pretend Graph (no live tenant), so this reviews behaviour and design, not live accuracy.

## 1. Workflows walked as an engineer

| Workflow | Verdict | Notes |
|---|---|---|
| First-time setup (app registration, 10 permissions, consent) | Pass | README + `--list-permissions` are clear. No script to create the app registration automatically. |
| Interactive run (GUI) and one-off report | Pass | Filters, detail pane, CSV all work. |
| Scripted/CI run with a gate (`--fail-on`, `--min-coverage`) | Pass, limited | Exit codes work. Only HTML/JSON/CSV output: no SARIF/JUnit, so no native CI annotations. |
| Unattended scheduled run in Azure / GitHub Actions | **Gap** | Only client secret or certificate sign-in. No managed identity, no workload identity federation (OIDC), no Key Vault. A long-lived secret on a runner is what most teams are trying to avoid. |
| Re-run monthly and see what changed | **Gap** | No baseline/diff. Each report is standalone. |
| Accept a known risk (e.g. break-glass exclusion) | **Gap** | No suppression/exception file, so accepted findings reappear every run and drown new ones. |
| Hand evidence to an auditor | Partial | CIS reference per finding is good. Evidence lists are capped at 25 items, including in the JSON, so the full affected list is lost. No executive summary or score. |
| Run against GCC High / DoD / China cloud | **Gap (hard block)** | Graph host is hard-coded to graph.microsoft.com and the login authority to login.microsoftonline.com; the allow-list rejects `graph.microsoft.us` / `microsoftgraph.chinacloudapi.cn`. |
| Run behind a corporate proxy | Partial | `requests` honours HTTPS_PROXY, but there is no flag, custom CA option or timeout setting, and no verbose/debug log for troubleshooting. |
| Scan many tenants (MSP, multi-subsidiary) | Gap | One tenant per run, no combined report. |

## 2. Missing checks (high value, achievable with the current permissions)

1. **Break-glass verification (turns MAN-008 into an automatic check).** ADM-009 already finds candidate emergency accounts; compute whether every enabled Conditional Access policy excludes them, and flag if they hold licences or lack a FIDO2/passkey method.
2. **Password hash sync / hybrid health.** `/organization` exposes `onPremisesSyncEnabled`, `onPremisesLastSyncDateTime` and `onPremisesLastPasswordSyncDateTime` (covered by Directory.Read.All). Replaces manual item MAN-006 for most tenants and flags stale sync.
3. **Named locations and trusted-IP hygiene.** Overly broad trusted ranges silently weaken every policy that uses "trusted location" (Policy.Read.All).
4. **Conditional Access quality beyond presence:** policies that exclude large groups, policies with no assignment, duplicate/conflicting policies, disabled policies older than N days, policies targeting "All users" with `includeApplications: Office365` only, workload-identity CA for service principals, token protection and continuous access evaluation settings.
5. **Privileged-identity depth:** role-assignable groups and who owns them, permanent vs eligible split per role, Global Admin count including group-based assignments, service principals holding privileged roles, PIM max activation duration and notifications (not only approval/MFA).
6. **Application risk:** apps with owners who are guests or departed users, app registrations with no owner, secrets on apps that hold Tier-1 permissions, redirect URIs using http/wildcards, apps with credentials and `Directory.ReadWrite.All`.
7. **Sign-in evidence for legacy auth.** Blocking legacy auth is checked; actual legacy sign-ins in the last 30 days are not (needs `AuditLog.Read.All`, already requested, and Entra P1).
8. **Guest posture:** guests by domain, guests with privileged access, B2B direct connect, cross-tenant inbound/outbound settings per partner (currently only the default policy is read).
9. **Authentication strengths / passkey profiles and registration-campaign scope** (AUTH-004 only checks the campaign is enabled).

## 3. Missing product features (ranked)

| Pri | Feature | Why an engineer needs it | Effort |
|---|---|---|---|
| P1 | Workload identity federation + managed identity + Key Vault secret source | Removes long-lived secrets; enables GitHub Actions / Azure Automation runs | M |
| P1 | Baseline & diff (`--baseline previous.json`, "new / fixed / unchanged") | Trending, change control, "what did we break this month" | M |
| P1 | Suppressions file (`id`, scope, reason, owner, expiry date) | Accepted risk without noise; expiry forces review | S |
| P1 | Sovereign-cloud support (`--cloud commercial\|usgov\|usgovdod\|china`) | Hard block for public-sector tenants | S |
| P2 | Full evidence export (no 25-item cap in JSON/CSV; cap only in HTML) | Auditor and remediation team need the whole list | S |
| P2 | SARIF + JUnit output | Native CI/GitHub code-scanning integration | S |
| P2 | Executive summary: score per area, top 5 risks, framework coverage % (CIS) | Management reporting | M |
| P2 | Remediation helpers: copy-paste PowerShell/Graph snippet per finding (read-only guidance, never auto-apply) | Faster fixes | M |
| P2 | Proxy/CA bundle/timeout flags, `--verbose` log file with request IDs (no tokens) | Troubleshooting in locked-down networks | S |
| P3 | Multi-tenant batch mode with combined report | MSPs / large orgs | M |
| P3 | Per-check enable/disable and severity overrides | Tailor to policy | S |
| P3 | Setup script to create the app registration and grant the 10 permissions | Faster onboarding | S |
| P3 | Other frameworks mapping (NIST 800-53, ISO 27001, Microsoft Secure Score ids) | Compliance teams | M |

## 4. Quality issues noticed during review

* **Silent truncation:** `sample()` caps lists at 25 in all outputs (see above).
* **ERROR vs SKIPPED naming:** corrupted data shows as ERROR with a Python exception string; engineers would prefer a clearer "unexpected data shape" message plus the endpoint. (Contained, never PASS.)
* **No scan-wide timeout / per-check time budget**, so one hung call can stall a scheduled run (single request timeout is 60 s).
* **Single severity scale, no likelihood/effort**: cannot prioritise quick wins.
* **Learn links unverified** from the build environment (run `tools/check_links.py`).
* **CA-008 (exclusions) is noisy**, as it cannot tell break-glass exclusions from risky ones (fixed by feature 1 above).

## 5. Recommended next release (1.1)

Sovereign clouds, suppressions, baseline/diff, uncapped evidence, workload identity federation / managed identity, then break-glass verification and password-hash-sync detection. These close every hard blocker above and convert two MANUAL items into automatic checks.


## Addendum: v1.1.0
Every recommendation in this review was implemented in v1.1.0 (see `CHANGELOG.md`). Re-tested: 163 automated tests, 26 acceptance scenarios (UAT-19..26 are new).
Still unverified against a live tenant, and listed in `LIVE_VALIDATION.md` items 10-17: the new Graph query forms, sovereign clouds, managed identity / federation / Key Vault flows, the PowerShell setup script, and proxy behaviour.
