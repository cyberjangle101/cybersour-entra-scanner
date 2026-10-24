"""A pretend Microsoft Graph for tests and user-acceptance runs.  No network, no credentials.

`FakeGraph(data)` answers GETs from a dict {path: response}.  A path that is missing answers 403 (like a missing permission),
a value that is an Exception instance is raised, and a value that is a callable is called with the query params.
Two ready-made tenants: `good_tenant()` (hardened) and `bad_tenant()` (typical weak setup).
"""
import datetime as _dt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from entra_scan.models import GraphError  # noqa: E402
from entra_scan.graph import checked_page  # noqa: E402
from entra_scan.checks import conditional_access as _ca  # noqa: E402


TENANT = "11111111-1111-1111-1111-111111111111"
GA = "62e90394-69f5-4237-9190-012177145e10"          # Global Administrator role template id


class FakeGraph:
    def __init__(self, data):
        self.data, self.calls, self.log = data, 0, []

    def _lookup(self, path, params):
        self.calls += 1
        self.log.append(path)
        if path in self.data:
            v = self.data[path]
        else:
            for prefix, v2 in self.data.items():           # prefix match for per-object paths such as /users/<id>
                if prefix.endswith("*") and path.startswith(prefix[:-1]):
                    v = v2
                    break
            else:
                raise GraphError(403, "Authorization_RequestDenied", "Insufficient privileges to complete the operation.", path)
        if isinstance(v, Exception):
            raise v
        return v(params) if callable(v) else v

    # The real client normalises every answer with checked_page(); the fake does the same so hostile shapes behave like production.
    def get(self, path, params=None):
        return checked_page(self._lookup(path, params), path)

    def get_all(self, path, params=None, limit=0):
        rows = checked_page(self._lookup(path, params), path).get("value", [])
        return rows[:limit] if limit else rows


def is_private_file(path):
    """True if a report/log file is readable by its owner only.

    POSIX: the mode must be exactly 600.  Windows: os.stat only reflects the read-only flag (a new file always reads 666) and
    access is governed by the folder's ACL instead, so the mode bits cannot be asserted there.
    """
    return os.name != "posix" or oct(os.stat(path).st_mode)[-3:] == "600"


class Args:
    """Stand-in for the parsed command line."""
    def __init__(self, **kw):
        self.max_users, self.areas = 50000, None
        self.__dict__.update(kw)


def _ago(days):
    """ISO timestamp `days` days before now, so fixtures never go stale as the calendar moves."""
    return (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _assign(i, role=GA):
    """A tenant-wide role assignment with the principal expanded, as Graph returns with $expand=principal."""
    return {"id": f"ra{i}", "roleDefinitionId": role, "principalId": f"u{i}", "directoryScopeId": "/",
            "principal": {"@odata.type": "#microsoft.graph.user", "userPrincipalName": f"admin{i}@contoso.com", "displayName": f"Admin {i}"}}


def _user(i, **kw):
    u = {"id": f"u{i}", "displayName": f"User {i}", "userPrincipalName": f"user{i}@contoso.com", "accountEnabled": True,
         "userType": "Member", "createdDateTime": "2022-01-01T00:00:00Z", "onPremisesSyncEnabled": False,
         "assignedLicenses": [{"skuId": "s"}], "signInActivity": {"lastSuccessfulSignInDateTime": _ago(4)}}
    u.update(kw)
    return u


def _pol(name, state="enabled", users=None, apps=None, grant=None, session=None, **cond):
    """Build a Conditional Access policy the way Graph returns it."""
    conditions = {"users": users or {"includeUsers": ["All"]}, "applications": apps or {"includeApplications": ["All"]},
                  "clientAppTypes": ["all"]}
    conditions.update(cond)
    return {"id": "p-" + name.replace(" ", "-"), "displayName": name, "state": state, "conditions": conditions,
            "grantControls": grant, "sessionControls": session}


def _pim_policy(params):
    """PIM role policy as Graph returns it for the role named in the $filter: approval and MFA are required."""
    role = (params or {}).get("$filter", "").split("roleDefinitionId eq '")[-1].rstrip("'")
    return {"value": [{"roleDefinitionId": role, "policy": {"rules": [
        {"id": "Approval_EndUser_Assignment", "setting": {"isApprovalRequired": True}},
        {"id": "Enablement_EndUser_Assignment", "enabledRules": ["MultiFactorAuthentication", "Justification"]},
        {"id": "AuthenticationContext_EndUser_Assignment", "isEnabled": False}]}}]}


def _groups(params):
    """/groups answers differently for the dynamic-guest-group query and the Microsoft 365 group query."""
    flt = (params or {}).get("$filter", "")
    if "visibility" in flt:                               # as real Graph: visibility is not filterable
        raise GraphError(400, "Request_UnsupportedQuery", "Unsupported or invalid query filter clause specified for property 'visibility' of resource 'Group'.", "/groups")
    if "Unified" in flt:
        return {"value": [{"id": "g-team", "displayName": "Project team", "visibility": "Private"}]}    # no public ones
    return {"value": [{"id": "g-guests", "displayName": "All guests", "membershipRule": '(user.userType -eq "Guest")'}]}


def compliant_ca_policies():
    """A policy set that satisfies every Conditional Access control we check (CA-001 .. CA-016)."""
    admins = {"includeRoles": list(_ca.ADMIN_ROLES.values())}
    pols = [
        _pol("Block legacy auth", grant={"builtInControls": ["block"]}, clientAppTypes=["exchangeActiveSync", "other"]),
        _pol("MFA all users", grant={"builtInControls": ["mfa"]}),
        _pol("Admins phishing-resistant", users=admins, grant={"authenticationStrength": {"id": _ca.PHISHING_RESISTANT_STRENGTH}},
             session={"signInFrequency": {"isEnabled": True, "type": "hours", "value": 4, "frequencyInterval": "timeBased"},
                      "persistentBrowser": {"isEnabled": True, "mode": "never"}}),
        _pol("Block risky sign-ins", grant={"builtInControls": ["block"]}, signInRiskLevels=["high", "medium"]),
        _pol("User risk", grant={"builtInControls": ["mfa", "passwordChange"]}, userRiskLevels=["high"]),
        _pol("Compliant device", grant={"builtInControls": ["compliantDevice"]}),
        _pol("Device to register security info", apps={"includeUserActions": [_ca.REGISTER_SECURITY_INFO]}, grant={"builtInControls": ["compliantDevice"]}),
        _pol("Intune enrollment every time", apps={"includeApplications": [_ca.INTUNE_ENROLLMENT_APP]}, grant={"builtInControls": ["mfa"]},
             session={"signInFrequency": {"isEnabled": True, "frequencyInterval": "everyTime"}}),
        _pol("Block device code", grant={"builtInControls": ["block"]}, authenticationFlows={"transferMethods": "deviceCodeFlow"}),
    ]
    for p in pols:                                        # emergency-access accounts u21/u22 are excluded from every policy that targets everyone
        if "All" in p["conditions"]["users"].get("includeUsers", []):
            p["conditions"]["users"]["excludeUsers"] = ["u21", "u22"]
    return pols


def good_tenant():
    ga = [_user(i, displayName=f"Admin {i}", userPrincipalName=f"admin{i}@contoso.com", assignedLicenses=[]) for i in (1, 2)]
    # Two cloud-only emergency ("break-glass") Global Administrators on the onmicrosoft.com domain.
    ga += [_user(i, displayName=f"Break glass {i}", userPrincipalName=f"bg{i}@contoso.onmicrosoft.com", assignedLicenses=[], signInActivity={"lastSuccessfulSignInDateTime": _ago(60)})
           for i in (21, 22)]
    users = ga + [_user(i) for i in range(3, 8)]
    return {
        "/organization": {"value": [{"id": TENANT, "displayName": "Contoso"}]},
        "/domains": {"value": [{"id": "contoso.com", "isVerified": True, "passwordValidityPeriodInDays": 2147483647, "isDefault": True}]},
        "/subscribedSkus": {"value": [{"skuId": "s", "skuPartNumber": "ENTRA_ID_P2"}]},
        "/users": {"value": users},
        "/reports/authenticationMethods/userRegistrationDetails": {"value": [
            {"id": u["id"], "userPrincipalName": u["userPrincipalName"], "isMfaRegistered": True, "isMfaCapable": True,
             "isAdmin": u["id"] in ("u1", "u2", "u21", "u22"),
             "methodsRegistered": ["fido2"] if u["id"] in ("u21", "u22") else ["microsoftAuthenticatorPush"], "userType": "member"} for u in users]},
        "/roleManagement/directory/roleDefinitions": {"value": [{"id": GA, "templateId": GA, "displayName": "Global Administrator"}]},
        "/roleManagement/directory/roleAssignments": {"value": [
            _assign(1), _assign(2), _assign(21), _assign(22)]},
        "/roleManagement/directory/roleEligibilityScheduleInstances": {"value": [{"id": "e1", "roleDefinitionId": GA, "principalId": "u3"}]},
        "/identity/conditionalAccess/policies": {"value": compliant_ca_policies()},
        "/policies/identitySecurityDefaultsEnforcementPolicy": {"isEnabled": False},
        "/policies/authorizationPolicy": {"allowInvitesFrom": "adminsAndGuestInviters", "allowedToCreateTenants": False,
            "allowedToCreateApps": False, "allowedToCreateSecurityGroups": False, "guestUserRoleId": "2af84b1e-32c8-42b7-82bc-daa82404023b",
            "defaultUserRolePermissions": {"allowedToCreateApps": False, "allowedToCreateSecurityGroups": False, "allowedToCreateTenants": False,
                "allowedToReadBitlockerKeysForOwnedDevice": False, "permissionGrantPoliciesAssigned": []},
            "allowUserConsentForRiskyApps": False, "allowedToUseSSPR": True, "blockMsolPowerShell": True},
        "/policies/adminConsentRequestPolicy": {"isEnabled": True, "reviewers": [{"query": "x"}]},
        "/policies/authenticationMethodsPolicy": {"policyMigrationState": "migrationComplete", "systemCredentialPreferences": {"state": "enabled"},
            "registrationEnforcement": {"authenticationMethodsRegistrationCampaign": {"state": "enabled"}},
            "authenticationMethodConfigurations": [           # Graph returns these inline in the policy
                {"id": "Sms", "state": "disabled"}, {"id": "Voice", "state": "disabled"}, {"id": "Email", "state": "disabled"},
                {"id": "Fido2", "state": "enabled"},
                {"id": "MicrosoftAuthenticator", "state": "enabled", "featureSettings": {
                    "displayAppInformationRequiredState": {"state": "enabled"}, "displayLocationInformationRequiredState": {"state": "enabled"}}}]},
        # As real Graph: listing the configurations collection directly is not supported.
        "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations": GraphError(
            400, "Request_UnsupportedQuery", "The request is not supported.", "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations"),
        "/policies/crossTenantAccessPolicy/default": {"b2bCollaborationInbound": {"usersAndGroups": {"accessType": "allowed"}}},
        "/policies/deviceRegistrationPolicy": {"userDeviceQuota": 10, "multiFactorAuthConfiguration": "required",
            "azureADJoin": {"isAdminConfigurable": True, "localAdmins": {"enableGlobalAdmins": False},
                            "allowedToJoin": {"@odata.type": "#microsoft.graph.enumeratedDeviceRegistrationMembership", "users": ["g1"]}},
            "localAdminPassword": {"isEnabled": True}},
        "/policies/roleManagementPolicyAssignments": _pim_policy,
        "/identityGovernance/accessReviews/definitions": {"value": [
            {"id": "r1", "displayName": "Guest review", "scope": {"query": "./members/microsoft.graph.user?$filter=(userType eq 'Guest')"}},
            {"id": "r2", "displayName": "Admin review", "scope": {"query": "/roleManagement/directory/roleAssignmentScheduleInstances"}}]},
        "/identityProtection/riskyUsers": {"value": []},
        "/applications": {"value": []}, "/servicePrincipals": {"value": []}, "/groups": _groups, "/groupSettings": {"value": [
            {"displayName": "Group.Unified", "values": [{"name": "EnableGroupCreation", "value": "false"}]},
            {"displayName": "Password Rule Settings", "values": [
                {"name": "EnableBannedPasswordCheck", "value": "True"}, {"name": "BannedPasswordList", "value": "contoso\tsummer"},
                {"name": "EnableBannedPasswordCheckOnPremises", "value": "True"}, {"name": "BannedPasswordCheckOnPremisesMode", "value": "Enforce"},
                {"name": "LockoutThreshold", "value": "10"}]}]},
        "/oauth2PermissionGrants": {"value": []},
        # v1.1 data sources (empty / healthy in the hardened tenant)
        "/identity/conditionalAccess/namedLocations": {"value": []},
        "/roleManagement/directory/roleAssignmentScheduleInstances": {"value": [
            {"id": "s21", "roleDefinitionId": GA, "principalId": "u21", "directoryScopeId": "/", "assignmentType": "Assigned", "endDateTime": None,
             "principal": {"displayName": "Break glass 21"}},
            {"id": "s22", "roleDefinitionId": GA, "principalId": "u22", "directoryScopeId": "/", "assignmentType": "Assigned", "endDateTime": None,
             "principal": {"displayName": "Break glass 22"}}]},
        "/auditLogs/signIns": {"value": []},
        "/policies/crossTenantAccessPolicy/partners": {"value": []},
        "/policies/authenticationStrengthPolicies": {"value": [{"id": "builtin", "policyType": "builtIn", "displayName": "MFA", "allowedCombinations": ["sms"]}]},
        # Every "API" lookup answers 404 (API not present) unless a test installs it, which is a valid, quiet outcome.
        "/servicePrincipals(appId=*": GraphError(404, "Request_ResourceNotFound", "not found", "sp"),
    }


def bad_tenant():
    d = good_tenant()
    ga = [_user(i, displayName=f"Admin {i}", userPrincipalName=f"admin{i}@contoso.com") for i in range(1, 8)]
    ga.append(_user(8, userType="Guest", userPrincipalName="g_ext#EXT#@contoso.com", displayName="Guest admin"))
    ga.append(_user(9, onPremisesSyncEnabled=True, displayName="Synced admin"))
    ga.append(_user(30, userPrincipalName="bg30@contoso.onmicrosoft.com", displayName="Break glass 30"))
    users = ga + [_user(i, signInActivity={"lastSuccessfulSignInDateTime": "2024-01-01T00:00:00Z"}) for i in range(10, 14)]
    d["/users"] = {"value": users}
    d["/reports/authenticationMethods/userRegistrationDetails"] = {"value": [
        {"id": u["id"], "userPrincipalName": u["userPrincipalName"], "isMfaRegistered": False, "isMfaCapable": False,
         "isAdmin": False, "methodsRegistered": [], "userType": "member"} for u in users]}
    d["/roleManagement/directory/roleAssignments"] = {"value": [_assign(i) for i in range(1, 10)] + [_assign(30)]}
    d["/roleManagement/directory/roleEligibilityScheduleInstances"] = {"value": []}
    d["/policies/identitySecurityDefaultsEnforcementPolicy"] = {"isEnabled": False}
    d["/policies/authorizationPolicy"] = {"allowInvitesFrom": "everyone", "guestUserRoleId": "a0b1b346-4d3e-4e8b-98f8-753987be4970",
        "defaultUserRolePermissions": {"allowedToCreateApps": True, "allowedToCreateSecurityGroups": True, "allowedToCreateTenants": True,
            "allowedToReadBitlockerKeysForOwnedDevice": True, "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]},
        "allowUserConsentForRiskyApps": True}
    d["/policies/adminConsentRequestPolicy"] = {"isEnabled": False}
    d["/policies/deviceRegistrationPolicy"] = {"userDeviceQuota": 50, "azureADJoin": {"isAdminConfigurable": True}, "localAdminPassword": {"isEnabled": False}}
    d["/identityProtection/riskyUsers"] = {"value": [{"id": "u1", "userPrincipalName": "admin1@contoso.com", "riskLevel": "high", "riskState": "atRisk"}]}
    d["/domains"] = {"value": [{"id": "contoso.com", "isVerified": True, "passwordValidityPeriodInDays": 90, "isDefault": True}]}
    d["/identity/conditionalAccess/policies"] = {"value": [
        _pol("MFA for some", users={"includeUsers": ["All"], "excludeUsers": ["u1"]}, apps={"includeApplications": ["Office365"]}, grant={"builtInControls": ["mfa"]})]}
    d["/policies/roleManagementPolicyAssignments"] = {"value": []}
    d["/identityGovernance/accessReviews/definitions"] = {"value": []}
    d["/roleManagement/directory/roleEligibilityScheduleInstances"] = {"value": []}
    d["/groups"] = {"value": []}
    d["/groupSettings"] = {"value": []}
    d["/policies/authenticationMethodsPolicy"] = {"policyMigrationState": "preMigration", "authenticationMethodConfigurations": [
        {"id": "Sms", "state": "enabled"}, {"id": "Voice", "state": "enabled"}, {"id": "Email", "state": "enabled"},
        {"id": "MicrosoftAuthenticator", "state": "enabled", "featureSettings": {}}]}
    d["/policies/authorizationPolicy"]["blockMsolPowerShell"] = False
    # An unverified app from another tenant that can write every mailbox, plus a risky delegated grant.
    graph_appid = "00000003-0000-0000-c000-000000000000"
    d[f"/servicePrincipals(appId='{graph_appid}')"] = {"id": "graph-sp", "appRoles": [{"id": "role-mail", "value": "Mail.ReadWrite"}]}
    d["/servicePrincipals/graph-sp/appRoleAssignedTo"] = {"value": [
        {"principalType": "ServicePrincipal", "principalId": "evil-sp", "principalDisplayName": "Shady Mailer", "appRoleId": "role-mail"}]}
    d["/servicePrincipals"] = {"value": [{"id": "evil-sp", "displayName": "Shady Mailer", "appOwnerOrganizationId": "99999999-9999-9999-9999-999999999999",
                                          "servicePrincipalType": "Application"}]}
    d["/oauth2PermissionGrants"] = {"value": [{"clientId": "evil-sp", "consentType": "AllPrincipals", "scope": "Mail.Read Files.Read.All"}]}
    d["/organization"] = {"value": [{"id": TENANT, "displayName": "Contoso", "onPremisesSyncEnabled": True,
                                     "onPremisesLastSyncDateTime": _ago(200), "onPremisesLastPasswordSyncDateTime": None}]}
    d["/identity/conditionalAccess/namedLocations"] = {"value": [
        {"id": "nl1", "displayName": "Whole ISP", "isTrusted": True, "ipRanges": [{"cidrAddress": "10.0.0.0/8"}]},
        {"id": "nl2", "displayName": "Unused", "isTrusted": False, "countriesAndRegions": ["GB"]}]}
    d["/identity/conditionalAccess/policies"]["value"] += [
        dict(_pol("Old report only", state="enabledForReportingButNotEnforced", grant={"builtInControls": ["mfa"]}), modifiedDateTime=_ago(300)),
        _pol("Does nothing", grant=None)]
    d["/roleManagement/directory/roleAssignmentScheduleInstances"] = {"value": [
        {"id": f"s{i}", "roleDefinitionId": GA, "principalId": f"u{i}", "directoryScopeId": "/", "assignmentType": "Assigned", "endDateTime": None,
         "principal": {"displayName": f"Admin {i}"}} for i in range(1, 6)]}
    d["/auditLogs/signIns"] = {"value": [{"userPrincipalName": "old@contoso.com", "clientAppUsed": "imap4"}]}
    d["/policies/crossTenantAccessPolicy/partners"] = {"value": [{"tenantId": "t-partner", "inboundTrust": {"isMfaAccepted": False},
        "b2bCollaborationInbound": {"usersAndGroups": {"accessType": "allowed", "targets": [{"target": "AllUsers"}]}}}]}
    d["/policies/authenticationStrengthPolicies"] = {"value": [{"id": "c1", "policyType": "custom", "displayName": "Easy", "allowedCombinations": ["sms", "password,sms"]}]}
    d["/applications"] = {"value": [{"id": "a1", "appId": "aaaa", "displayName": "Old app", "signInAudience": "AzureADMultipleOrgs",
        "web": {"redirectUris": ["http://app.contoso.com/cb", "https://*.contoso.com/x"]}, "requiredResourceAccess": [{"resourceAppId": "x"}], "owners": [],
        "passwordCredentials": [{"keyId": "k1", "displayName": "s", "startDateTime": "2020-01-01T00:00:00Z", "endDateTime": "2026-01-01T00:00:00Z"}]}]}
    return d


def denied_tenant(*paths):
    """A good tenant where the given paths answer 403 (permission missing)."""
    d = good_tenant()
    for p in paths:
        d.pop(p, None)
    return d
