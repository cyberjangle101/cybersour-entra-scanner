"""Check logic against a pretend tenant.

* the hardened tenant must produce no issues at all (so a regression that adds a false alarm is caught);
* the weak tenant must trip the expected controls;
* each rule is also tested on its own: take the hardened tenant, weaken ONE setting, and that rule (and only the rules we
  expect) must stop passing.  This is the CIS rule matrix.
* a missing permission or licence must give SKIPPED, never PASS.
"""
import collections

import pytest

from entra_scan import context, runner
from entra_scan.models import GraphError
from fake_tenant import GA, Args, FakeGraph, _ago, _assign, _user, bad_tenant, denied_tenant, good_tenant


def scan(tenant, **kw):
    ctx = context.Ctx(FakeGraph(tenant), Args(**kw))
    return {f.id: f for f in runner.run_scan(ctx, None, log=lambda *_: None)}


def policy(tenant, name):
    return next(p for p in tenant["/identity/conditionalAccess/policies"]["value"] if p["displayName"] == name)


def drop_policy(name):
    def mutate(t):
        pols = t["/identity/conditionalAccess/policies"]["value"]
        t["/identity/conditionalAccess/policies"]["value"] = [p for p in pols if p["displayName"] != name]
    return mutate


def set_state(name, state):
    return lambda t: policy(t, name).update(state=state)


def user(tenant, uid):
    return next(u for u in tenant["/users"]["value"] if u["id"] == uid)


def authz(**kw):
    return lambda t: t["/policies/authorizationPolicy"].update(kw)


def authz_default(**kw):
    return lambda t: t["/policies/authorizationPolicy"]["defaultUserRolePermissions"].update(kw)


def method_state(method_id, state):
    def mutate(t):
        for m in t["/policies/authenticationMethodsPolicy"]["authenticationMethodConfigurations"]:
            if m["id"] == method_id:
                m["state"] = state
    return mutate


def add_admins(t):
    for i in (3, 4, 5):
        t["/roleManagement/directory/roleAssignments"]["value"].append(_assign(i))


def remove_breakglass(t):
    for u in ("u21", "u22"):
        user(t, u)["userPrincipalName"] = f"{u}@contoso.com"


def unregister(uid):
    def mutate(t):
        for r in t["/reports/authenticationMethods/userRegistrationDetails"]["value"]:
            if r["id"] == uid:
                r.update(isMfaRegistered=False, isMfaCapable=False, methodsRegistered=[])
    return mutate


def pim(**rules):
    def mutate(t):
        t["/policies/roleManagementPolicyAssignments"] = lambda params: {"value": [{"policy": {"rules": [
            {"id": "Approval_EndUser_Assignment", "setting": {"isApprovalRequired": rules.get("approval", True)}},
            {"id": "Enablement_EndUser_Assignment", "enabledRules": rules.get("enabled", ["MultiFactorAuthentication"])},
            {"id": "AuthenticationContext_EndUser_Assignment", "isEnabled": False}]}}]}
    return mutate


def grp_setting(name, **values):
    def mutate(t):
        for s in t["/groupSettings"]["value"]:
            if s["displayName"] == name:
                s["values"] = [{"name": k, "value": v} for k, v in values.items()]
    return mutate


# (rule id, what we weaken, mutation)  -> the rule must stop passing
RULE_MATRIX = [
    # ---- Conditional Access (CIS 5.2.2.x)
    ("CA-001", "no policy blocks legacy auth", drop_policy("Block legacy auth")),
    ("CA-002", "no MFA-for-everyone policy", drop_policy("MFA all users")),
    ("CA-006", "no sign-in risk policy", drop_policy("Block risky sign-ins")),
    ("CA-007", "no user risk policy", drop_policy("User risk")),
    ("CA-010", "no admin session policy", drop_policy("Admins phishing-resistant")),
    ("CA-011", "no phishing-resistant admin policy", drop_policy("Admins phishing-resistant")),
    ("CA-012", "no risk block policy", drop_policy("Block risky sign-ins")),
    ("CA-013", "no managed device policy", drop_policy("Compliant device")),
    ("CA-014", "no device policy for registration", drop_policy("Device to register security info")),
    ("CA-015", "no Intune every-time policy", drop_policy("Intune enrollment every time")),
    ("CA-016", "no device-code block", drop_policy("Block device code")),
    ("CA-016", "device-code block is report-only", set_state("Block device code", "enabledForReportingButNotEnforced")),
    ("CA-001", "legacy block only covers one client type",
     lambda t: policy(t, "Block legacy auth")["conditions"].update(clientAppTypes=["other"])),
    ("CA-001", "legacy block excludes everyone but a group",
     lambda t: policy(t, "Block legacy auth")["conditions"].update(users={"includeUsers": ["some-user"]})),
    ("CA-010", "admin sign-in frequency is 24h",
     lambda t: policy(t, "Admins phishing-resistant")["sessionControls"]["signInFrequency"].update(value=24)),
    ("CA-010", "admin browser session is persistent",
     lambda t: policy(t, "Admins phishing-resistant")["sessionControls"]["persistentBrowser"].update(mode="always")),
    ("CA-011", "admins get plain MFA, not phishing-resistant",
     lambda t: policy(t, "Admins phishing-resistant").update(grantControls={"builtInControls": ["mfa"]})),
    ("CA-011", "admin policy misses a role",
     lambda t: policy(t, "Admins phishing-resistant")["conditions"]["users"].update(includeRoles=list(policy(t, "Admins phishing-resistant")["conditions"]["users"]["includeRoles"])[:-1])),
    ("CA-012", "risk block only covers high",
     lambda t: policy(t, "Block risky sign-ins")["conditions"].update(signInRiskLevels=["high"])),
    ("CA-008", "an enabled policy has exclusions",
     lambda t: policy(t, "MFA all users")["conditions"]["users"].update(excludeUsers=["u9"])),
    # ---- authentication methods (CIS 5.2.3.x, 5.2.4.x)
    ("AUTH-002", "SMS enabled", method_state("Sms", "enabled")),
    ("AUTH-002", "voice enabled", method_state("Voice", "enabled")),
    ("AUTH-007", "email OTP enabled", method_state("Email", "enabled")),
    ("AUTH-003", "FIDO2 disabled", method_state("Fido2", "disabled")),
    ("AUTH-001", "Authenticator disabled", method_state("MicrosoftAuthenticator", "disabled")),
    ("AUTH-006", "system-preferred MFA off",
     lambda t: t["/policies/authenticationMethodsPolicy"].update(systemCredentialPreferences={"state": "disabled"})),
    ("AUTH-004", "registration campaign off",
     lambda t: t["/policies/authenticationMethodsPolicy"].update(registrationEnforcement={"authenticationMethodsRegistrationCampaign": {"state": "disabled"}})),
    ("PWD-001", "no banned password list", grp_setting("Password Rule Settings", EnableBannedPasswordCheck="False")),
    ("PWD-002", "on-prem protection in audit mode",
     grp_setting("Password Rule Settings", EnableBannedPasswordCheck="True", BannedPasswordList="x", EnableBannedPasswordCheckOnPremises="True",
                 BannedPasswordCheckOnPremisesMode="Audit")),
    ("PWD-003", "lockout threshold 50",
     grp_setting("Password Rule Settings", EnableBannedPasswordCheck="True", BannedPasswordList="x", EnableBannedPasswordCheckOnPremises="True",
                 BannedPasswordCheckOnPremisesMode="Enforce", LockoutThreshold="50")),
    # ---- tenant / guest / consent (CIS 5.1.x)
    ("TEN-001", "everyone can invite guests", authz(allowInvitesFrom="everyone")),
    ("TEN-002", "guests have member-level access", authz(guestUserRoleId="a0b1b346-4d3e-4e8b-98f8-753987be4970")),
    ("TEN-003", "users can consent to apps",
     authz_default(permissionGrantPoliciesAssigned=["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"])),
    ("TEN-012", "users can consent to risky apps", authz(allowUserConsentForRiskyApps=True)),
    ("TEN-004", "users can create tenants", authz_default(allowedToCreateTenants=True)),
    ("TEN-005", "users can register apps", authz_default(allowedToCreateApps=True)),
    ("TEN-010", "users can create security groups", authz_default(allowedToCreateSecurityGroups=True)),
    ("TEN-011", "users can read BitLocker keys", authz_default(allowedToReadBitlockerKeysForOwnedDevice=True)),
    ("TEN-007", "MSOnline allowed", authz(blockMsolPowerShell=False)),
    ("TEN-008", "admin consent workflow off", lambda t: t.update({"/policies/adminConsentRequestPolicy": {"isEnabled": False}})),
    ("DOM-003", "passwords expire after 90 days",
     lambda t: t["/domains"]["value"][0].update(passwordValidityPeriodInDays=90)),
    ("DOM-001", "an unverified domain exists",
     lambda t: t["/domains"]["value"].append({"id": "new.contoso.com", "isVerified": False})),
    # ---- privileged access (CIS 1.1.x, 5.3.x)
    ("ADM-001", "five Global Admins", add_admins),
    ("ADM-001", "only one Global Admin",
     lambda t: t["/roleManagement/directory/roleAssignments"].update(value=[_assign(1)])),
    ("ADM-002", "a guest holds an admin role", lambda t: user(t, "u1").update(userType="Guest")),
    ("ADM-003", "a synced admin", lambda t: user(t, "u2").update(onPremisesSyncEnabled=True)),
    ("ADM-005", "a disabled admin keeps a role", lambda t: user(t, "u2").update(accountEnabled=False)),
    ("ADM-006", "an admin has not signed in for a year",
     lambda t: user(t, "u2").update(signInActivity={"lastSuccessfulSignInDateTime": "2025-01-01T00:00:00Z"})),
    ("ADM-007", "an admin has no MFA", unregister("u1")),
    ("ADM-009", "no break-glass accounts", remove_breakglass),
    ("PIM-001", "no eligible assignments",
     lambda t: t.update({"/roleManagement/directory/roleEligibilityScheduleInstances": {"value": []}})),
    ("GOV-001", "no access reviews", lambda t: t.update({"/identityGovernance/accessReviews/definitions": {"value": []}})),
    ("GOV-002", "no access reviews", lambda t: t.update({"/identityGovernance/accessReviews/definitions": {"value": []}})),
    ("GOV-003", "no approval to activate GA", pim(approval=False)),
    ("GOV-004", "no approval to activate PRA", pim(approval=False)),
    ("GOV-005", "no MFA to activate GA", pim(enabled=[])),
    # ---- groups / devices / identity protection / users
    ("GRP-001", "no dynamic guest group", lambda t: t.update({"/groups": lambda p: {"value": []}})),
    ("GRP-002", "everyone can create M365 groups", grp_setting("Group.Unified", EnableGroupCreation="true")),
    ("GRP-003", "a public M365 group exists",
     lambda t: t.update({"/groups": lambda p: {"value": [{"id": "g9", "displayName": "Open", "visibility": "Public"}]}})),
    ("DEV-001", "50 devices per user", lambda t: t["/policies/deviceRegistrationPolicy"].update(userDeviceQuota=50)),
    ("DEV-003", "LAPS off", lambda t: t["/policies/deviceRegistrationPolicy"].update(localAdminPassword={"isEnabled": False})),
    ("DEV-004", "MFA to join not required", lambda t: t["/policies/deviceRegistrationPolicy"].update(multiFactorAuthConfiguration="notRequired")),
    ("DEV-005", "Global Admins are local admins",
     lambda t: t["/policies/deviceRegistrationPolicy"]["azureADJoin"].update(localAdmins={"enableGlobalAdmins": True})),
    ("IDP-001", "a high-risk user",
     lambda t: t.update({"/identityProtection/riskyUsers": {"value": [{"id": "u5", "userPrincipalName": "u5@c.com", "riskLevel": "high", "riskState": "atRisk"}]}})),
    ("USR-001", "a member has no MFA", unregister("u5")),
    ("USR-004", "a member is not MFA capable", unregister("u6")),
    ("USR-010", "a member inactive for 2 years",
     lambda t: user(t, "u5").update(signInActivity={"lastSuccessfulSignInDateTime": "2024-01-01T00:00:00Z"})),
    ("USR-013", "password never-expire flag lost", lambda t: user(t, "u5").update(passwordPolicies="DisableStrongPassword")),
    ("USR-014", "a disabled account keeps a licence", lambda t: user(t, "u5").update(accountEnabled=False)),
    # ---- applications
    ("APP-001", "an expired secret",
     lambda t: t.update({"/applications": {"value": [{"id": "a1", "appId": "a", "displayName": "X", "passwordCredentials": [
         {"keyId": "k", "startDateTime": "2020-01-01T00:00:00Z", "endDateTime": "2026-01-01T00:00:00Z"}]}]}})),
    ("APP-003", "a 5-year secret",
     lambda t: t.update({"/applications": {"value": [{"id": "a1", "appId": "a", "displayName": "X", "passwordCredentials": [
         {"keyId": "k", "startDateTime": "2026-01-01T00:00:00Z", "endDateTime": "2031-01-01T00:00:00Z"}]}]}})),
    # ---- v1.1 checks
    ("ADM-011", "break-glass accounts not excluded from a CA policy", lambda t: policy(t, "MFA all users")["conditions"]["users"].update(excludeUsers=[])),
    ("ADM-012", "break-glass account has no FIDO2 key", lambda t: next(r for r in t["/reports/authenticationMethods/userRegistrationDetails"]["value"] if r["id"] == "u21").update(methodsRegistered=["microsoftAuthenticatorPush"])),
    ("ADM-013", "break-glass account used 2 days ago", lambda t: user(t, "u21").update(signInActivity={"lastSuccessfulSignInDateTime": _ago(2)})),
    ("ADM-014", "break-glass account is licensed", lambda t: user(t, "u21").update(assignedLicenses=[{"skuId": "s"}])),
    ("HYB-001", "directory sync stopped 10 days ago", lambda t: t["/organization"]["value"][0].update(onPremisesSyncEnabled=True, onPremisesLastSyncDateTime=_ago(10), onPremisesLastPasswordSyncDateTime=_ago(0))),
    ("HYB-002", "password hash sync never ran", lambda t: t["/organization"]["value"][0].update(onPremisesSyncEnabled=True, onPremisesLastSyncDateTime=_ago(0), onPremisesLastPasswordSyncDateTime=None)),
    ("NET-001", "trusted location is a /8", lambda t: t.update({"/identity/conditionalAccess/namedLocations": {"value": [{"id": "n", "displayName": "ISP", "isTrusted": True, "ipRanges": [{"cidrAddress": "10.0.0.0/8"}]}]}})),
    ("CAQ-001", "report-only for a year", lambda t: policy(t, "MFA all users").update(state="enabledForReportingButNotEnforced", modifiedDateTime=_ago(365))),
    ("CAQ-002", "disabled for a year", lambda t: policy(t, "Block device code").update(state="disabled", modifiedDateTime=_ago(365))),
    ("CAQ-003", "enabled policy with no controls", lambda t: policy(t, "Compliant device").update(grantControls=None)),
    ("PRV-001", "five permanent Global Administrators", lambda t: t["/roleManagement/directory/roleAssignmentScheduleInstances"]["value"].extend(
        {"id": f"x{i}", "roleDefinitionId": GA, "principalId": f"u{i}", "directoryScopeId": "/", "endDateTime": None, "principal": {}} for i in (1, 2, 3))),
    ("APP-030", "plain-HTTP redirect URI", lambda t: t["/applications"]["value"].append({"id": "a", "displayName": "x", "web": {"redirectUris": ["http://evil.example/cb"]}, "owners": [{"id": "o"}]})),
    ("APP-033", "guest owns an app", lambda t: t["/applications"]["value"].append({"id": "a", "displayName": "x", "owners": [{"id": "o", "userType": "Guest"}]})),
    ("LEG-001", "IMAP sign-in succeeded", lambda t: t.update({"/auditLogs/signIns": {"value": [{"userPrincipalName": "a@contoso.com", "clientAppUsed": "imap4"}]}})),
    ("GST-002", "partner may bring all users", lambda t: t.update({"/policies/crossTenantAccessPolicy/partners": {"value": [{"tenantId": "t", "b2bCollaborationInbound": {"usersAndGroups": {"accessType": "allowed", "targets": [{"target": "AllUsers"}]}}}]}})),
    ("AUT-001", "custom strength allows SMS", lambda t: t.update({"/policies/authenticationStrengthPolicies": {"value": [{"id": "c", "policyType": "custom", "displayName": "easy", "allowedCombinations": ["sms"]}]}})),
]


def test_good_tenant_has_no_issues():
    f = scan(good_tenant())
    bad = {i: (x.status, x.detail[:80]) for i, x in f.items() if x.status in ("FAIL", "WARN", "ERROR", "SKIPPED")}
    assert not bad, bad


def test_bad_tenant_trips_the_obvious_controls():
    f = scan(bad_tenant())
    failing = {i for i, x in f.items() if x.status in ("FAIL", "WARN")}
    expected = {"CA-002", "CA-001", "ADM-001", "ADM-002", "ADM-003", "ADM-007", "AUTH-002", "TEN-001", "TEN-003", "APP-010", "IDP-001",
                "GOV-001", "GOV-003", "DOM-003", "DEV-003"}
    assert expected <= failing, sorted(expected - failing)
    assert f["APP-010"].severity == "critical" and f["APP-010"].status == "FAIL"
    assert not [i for i, x in f.items() if x.status == "ERROR"]


@pytest.mark.parametrize("rule,why,mutate", RULE_MATRIX, ids=[f"{r}-{w}" for r, w, _ in RULE_MATRIX])
def test_rule_matrix(rule, why, mutate):
    t = good_tenant()
    assert scan(t)[rule].status in ("PASS", "INFO"), "baseline must pass"
    t = good_tenant()
    mutate(t)
    after = scan(t)
    assert after[rule].status in ("FAIL", "WARN"), f"{rule} should flag: {why} -> {after[rule].status}: {after[rule].detail[:120]}"
    errors = [i for i, x in after.items() if x.status == "ERROR"]
    assert not errors, errors


def test_near_miss_names_the_missing_roles():
    t = good_tenant()
    inc = policy(t, "Admins phishing-resistant")["conditions"]["users"]["includeRoles"]
    policy(t, "Admins phishing-resistant")["conditions"]["users"]["includeRoles"] = inc[:-2]
    f = scan(t)["CA-011"]
    assert f.status == "FAIL" and "missing 2 role" in f.detail


def test_report_only_policy_is_a_warning_not_a_pass():
    t = good_tenant()
    set_state("Block legacy auth", "enabledForReportingButNotEnforced")(t)
    f = scan(t)["CA-001"]
    assert f.status == "WARN" and "report-only" in f.detail.lower()


# ---------------------------------------------------------------- permissions and licences: never a false PASS
@pytest.mark.parametrize("missing,area_ids", [
    ("/identity/conditionalAccess/policies", ["CA-010"]),
    ("/policies/deviceRegistrationPolicy", ["DEV-001"]),
    ("/identityGovernance/accessReviews/definitions", ["GOV-001"]),
    ("/identityProtection/riskyUsers", ["IDP-001"]),
    ("/oauth2PermissionGrants", ["APP-020"]),
    ("/applications", ["APP-001"]),
])
def test_missing_permission_is_skipped_never_pass(missing, area_ids):
    f = scan(denied_tenant(missing))
    for i in area_ids:
        assert i not in f or f[i].status not in ("PASS",), f"{i} passed although {missing} was unreadable"
    skipped = [x for x in f.values() if x.status == "SKIPPED"]
    assert skipped, "an unreadable endpoint must surface as SKIPPED"
    assert all(x.needs for x in skipped), "a skipped check must say which permission it needs"


def test_pim_unreadable_is_skipped():
    t = good_tenant()
    t["/policies/roleManagementPolicyAssignments"] = GraphError(403, "Forbidden", "no P2", "x")
    f = scan(t)
    assert "GOV-003" not in f and any(i.startswith("SKIP-pim_role_settings") for i in f)


def test_security_defaults_tenant():
    t = good_tenant()
    t["/policies/identitySecurityDefaultsEnforcementPolicy"] = {"isEnabled": True}
    t["/identity/conditionalAccess/policies"] = GraphError(403, "Forbidden", "needs P1", "x")
    f = scan(t)
    assert f["CA-SD"].status == "INFO" and f["CA-NA"].status == "INFO"
    assert not any(i.startswith("CA-0") and x.status == "FAIL" for i, x in f.items() if i != "CA-SD")


def test_no_p1_licence_signin_activity_fallback():
    """Without Entra P1, /users with signInActivity answers 403; the scan must still work and say sign-in dates are unavailable."""
    t = good_tenant()
    users = t["/users"]["value"]

    def users_api(params):
        if "signInActivity" in (params or {}).get("$select", ""):
            from entra_scan.models import GraphError
            raise GraphError(403, "Authentication_RequestFromNonPremiumTenantOrB2CTenant", "Neither tenant is B2C or tenant doesn't have premium license", "u")
        return {"value": [{k: v for k, v in u.items() if k != "signInActivity"} for u in users]}
    t["/users"] = users_api
    f = scan(t)
    assert not [i for i, x in f.items() if x.status == "ERROR"]
    assert f["USR-010"].status != "PASS" or "unavailable" in f["USR-010"].detail.lower() or f["USR-010"].status == "INFO"


def test_coverage_excludes_nothing_hidden():
    ctx = context.Ctx(FakeGraph(denied_tenant("/identityProtection/riskyUsers", "/applications")), Args())
    findings = runner.run_scan(ctx, None, log=lambda *_: None)
    selected, not_run, pct = runner.scan_coverage(findings)
    assert not_run == 3 and pct < 100 and selected == 33


def test_areas_filter():
    ctx = context.Ctx(FakeGraph(good_tenant()), Args())
    f = runner.run_scan(ctx, ["ca"], log=lambda *_: None)
    assert {x.category for x in f} == {"ca"}


def test_public_groups_are_filtered_client_side():
    """UAT: filtering /groups on visibility answers 400 Request_UnsupportedQuery; GRP-003 must ask for Microsoft 365 groups only."""
    t = good_tenant()
    t["/groups"] = lambda p: {"value": [{"id": "g1", "displayName": "Private team", "visibility": "Private"},
                                        {"id": "g2", "displayName": "Open team", "visibility": "Public"}]} if "Unified" in p["$filter"] else {"value": []}
    f = scan(t)["GRP-003"]
    assert f.status == "WARN" and "1 public" in f.detail


def test_auth_method_configs_read_from_policy_not_the_unsupported_list():
    """UAT: GET .../authenticationMethodConfigurations answers 400 Request_UnsupportedQuery; the configs come inline in the policy."""
    g = FakeGraph(good_tenant())
    f = {x.id: x for x in runner.run_scan(context.Ctx(g, Args()), ["authn"], log=lambda *_: None)}
    assert all(f[i].status == "PASS" for i in ("AUTH-001", "AUTH-003", "AUTH-005"))
    assert "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations" not in g.log


def test_auth_method_configs_fall_back_to_per_method_reads():
    """If the policy comes back without its inline configurations, each method is read by id; a missing method (404) is tolerated."""
    t = good_tenant()
    configs = {c["id"]: c for c in t["/policies/authenticationMethodsPolicy"].pop("authenticationMethodConfigurations")}
    base = "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/"
    for method in context.AUTH_METHOD_IDS:
        t[base + method] = configs[method]
    t[base + "Email"] = GraphError(404, "Request_ResourceNotFound", "not found", "Email")    # method absent in this tenant
    f = scan(t)
    assert all(f[i].status == "PASS" for i in ("AUTH-001", "AUTH-002", "AUTH-003", "AUTH-005", "AUTH-007"))


def test_every_check_is_isolated():
    """A check that blows up with an unexpected exception becomes an ERROR finding; the others still run."""
    t = good_tenant()
    t["/policies/authorizationPolicy"] = lambda p: 1 / 0
    f = scan(t)
    assert any(i.startswith("ERR-authorization_policy") for i in f) and f["CA-001"].status == "PASS"
    assert collections.Counter(x.status for x in f.values())["PASS"] > 40
