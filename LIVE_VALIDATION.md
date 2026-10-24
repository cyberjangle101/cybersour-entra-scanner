# What still needs a live tenant

All automated and acceptance tests use a pretend Graph. Before relying on results, run once against a test tenant and confirm:

1. **`/policies/deviceRegistrationPolicy`** answers a GET on v1.0 with only `Policy.Read.DeviceConfiguration` (docs list the resource; availability and the exact
   `allowedToJoin` / `localAdmins` shapes should be confirmed). If it 403/404s, DEV-* will show SKIPPED, which is the safe outcome.
2. **`authorizationPolicy` consent property location** - the scan reads `defaultUserRolePermissions.permissionGrantPoliciesAssigned` and falls back to the top-level
   `permissionGrantPolicyIdsAssignedToDefaultUserRole`. Confirm TEN-003 matches the portal (Enterprise apps > Consent and permissions).
3. **PIM policy rule IDs** (`Approval_EndUser_Assignment`, `Enablement_EndUser_Assignment`, `AuthenticationContext_EndUser_Assignment`) and the `$filter` form on
   `/policies/roleManagementPolicyAssignments` return data for Global Administrator (GOV-003/004/005).
4. **Admin role GUIDs** in `entra_scan/checks/conditional_access.py` (`ADMIN_ROLES`) were checked against Microsoft's built-in roles page; confirm against your tenant's
   `roleTemplates` if a role looks missing.
5. **Authentication-method configuration IDs** (`Sms`, `Voice`, `Email`, `Fido2`, `MicrosoftAuthenticator`) and the Authenticator `featureSettings` shape (AUTH-001..007).
6. **Microsoft Learn links** in `entra_scan/metadata.py` - many were written from documentation structure and have not been link-checked from this build environment.
   Run `python tools/check_links.py` from a machine with internet access.
7. **Throttling behaviour** on a large tenant (HTTP 429 handling is unit-tested, not load-tested).
8. **Licence behaviour**: confirm a tenant without Entra ID P1/P2 yields SKIPPED (not errors) for CA, sign-in activity, PIM, access reviews, Identity Protection.
9. **GUI on Windows** (the window was tested with tkinter on Linux under a virtual display; high-DPI and the .exe build are untested).

## Added in v1.1 (all mocked; none has run against a live tenant)
10. **`/roleManagement/directory/roleAssignmentScheduleInstances?$filter=assignmentType eq 'Assigned'&$expand=principal(...)`** (PRV-001/002). Microsoft Learn lists
    `assignmentType` (Assigned / Activated) and a `principal` relationship but does not detail the `$filter`/`$expand` forms. A 400 here makes the check SKIPPED.
11. **`/auditLogs/signIns?$filter=createdDateTime ge ... and status/errorCode eq 0`** (LEG-001): confirm the filter and `clientAppUsed` values return legacy protocols in your tenant, and that the volume cap (1000 rows) is acceptable.
12. **Applications `$expand=owners($select=...)`** (APP-032/033) on a tenant with many apps; **cross-tenant `partners`** shape (`inboundTrust`, `b2bCollaborationInbound.usersAndGroups.targets`);
    **`authenticationStrengthPolicies`** `allowedCombinations` values (AUT-001); **`organization.onPremisesLastPasswordSyncDateTime`** (HYB-002).
13. **Break-glass detection is a heuristic** (cloud-only Global Administrators on `*.onmicrosoft.com`). Confirm it finds your real emergency accounts; if your naming differs ADM-009/011-014 will under-report.
14. **Sovereign clouds** (`--cloud usgov|usgovdod|china`): host names, authority, scope and Key Vault suffix come from Microsoft documentation; none was exercised against a real GCC High / DoD / China tenant.
15. **Managed identity, workload identity federation (GitHub OIDC and token file) and Key Vault secret fetch**: tested with mocks of MSAL and the HTTP layer only. Run each once in the real environment.
16. **`tools/setup_app_registration.ps1`** was never executed (no PowerShell in the build environment). Run with `-WhatIf` first and review the commands.
17. **Proxy / `--ca-bundle`** behaviour behind a real TLS-inspecting proxy.
