"""What access the scanner needs, and why.  This file is the single source of truth.

Each check declares the permission(s) it reads with (see `needs=` on the @check decorator). `required_permissions()`
collects them, so the README, `--list-permissions`, the GUI and the tests can never drift from the code.

All permissions are Microsoft Graph *Application* permissions and all are read-only. ENDPOINTS records, for every
Graph endpoint the scanner calls, the least-privileged permission Microsoft documents for it ("least") and what
the scanner asks for ("requested"), with the page the claim was verified against.
"""
from __future__ import annotations

import re

LEARN = "https://learn.microsoft.com/en-us/graph/api/"

# Why each permission is requested, in plain words.
PURPOSE = {
    "Policy.Read.All": "Conditional Access policies, Security Defaults, authorization policy (guest, consent, tenant-creation settings), "
                       "authentication methods policy, admin consent workflow, cross-tenant access defaults",
    "Policy.Read.DeviceConfiguration": "Device settings (who can join devices, device limit, LAPS). Policy.Read.All does not cover this "
                                       "endpoint for application access",
    "Directory.Read.All": "Tenant, domains, groups and group settings, licence SKUs, delegated-consent grants",
    "User.Read.All": "Users: licences, guest state, sync state, password flags, sign-in activity",
    "Application.Read.All": "App registrations (secret and certificate expiry) and enterprise apps with their granted permissions",
    "AuditLog.Read.All": "Authentication-method registration report, last-sign-in dates (the latter also needs Entra ID P1) and the sign-in log (legacy-protocol evidence)",
    "RoleManagement.Read.Directory": "Entra role definitions, assignments and PIM eligible assignments",
    "RoleManagementPolicy.Read.Directory": "PIM role settings (approval and MFA on activation)",
    "AccessReview.Read.All": "Access review definitions (guest and privileged-role reviews)",
    "IdentityRiskyUser.Read.All": "Identity Protection risky users",
}

# endpoint -> (least privileged application permission per Microsoft Learn, permission the scanner requests, doc page, how verified)
ENDPOINTS = [
    ("/identity/conditionalAccess/policies",                       "Policy.Read.All", "Policy.Read.All", "conditionalaccessroot-list-policies", "Learn page read 2026-10-24"),
    ("/policies/identitySecurityDefaultsEnforcementPolicy",        "Policy.Read.All", "Policy.Read.All", "identitysecuritydefaultsenforcementpolicy-get", "Learn page read 2026-10-24"),
    ("/policies/authorizationPolicy",                              "Policy.Read.All", "Policy.Read.All", "authorizationpolicy-get", "Learn page read 2026-10-24"),
    ("/policies/authenticationMethodsPolicy (+ configurations)",   "Policy.Read.AuthenticationMethod", "Policy.Read.All", "authenticationmethodspolicy-get", "Learn page read; Policy.Read.All is listed as the higher-privileged alternative and also covers the other policy endpoints"),
    ("/policies/adminConsentRequestPolicy",                        "Policy.Read.All", "Policy.Read.All", "adminconsentrequestpolicy-get", "Learn page read 2026-10-24"),
    ("/policies/crossTenantAccessPolicy/default",                  "Policy.Read.All", "Policy.Read.All", "crosstenantaccesspolicyconfigurationdefault-get", "Learn page read 2026-10-24"),
    ("/policies/deviceRegistrationPolicy",                         "Policy.Read.DeviceConfiguration", "Policy.Read.DeviceConfiguration", "deviceregistrationpolicy-get", "Learn page read (beta page; v1.0 resource exists, GET availability to be confirmed on a live tenant)"),
    ("/policies/roleManagementPolicyAssignments (+ policy rules)", "RoleManagementPolicy.Read.Directory", "RoleManagementPolicy.Read.Directory", "policyroot-list-rolemanagementpolicyassignments", "Learn page read 2026-10-24"),
    ("/roleManagement/directory/roleDefinitions",                  "RoleManagement.Read.Directory", "RoleManagement.Read.Directory", "rbacapplication-list-roleassignments", "Learn page read (roleAssignments page; definitions use the same permission set)"),
    ("/roleManagement/directory/roleAssignments",                  "RoleManagement.Read.Directory", "RoleManagement.Read.Directory", "rbacapplication-list-roleassignments", "Learn page read 2026-10-24"),
    ("/roleManagement/directory/roleEligibilityScheduleInstances", "RoleEligibilitySchedule.Read.Directory", "RoleManagement.Read.Directory", "rbacapplication-list-roleeligibilityscheduleinstances", "Learn page read; RoleManagement.Read.Directory is the listed higher-privileged option and is already required"),
    ("/identityGovernance/accessReviews/definitions",              "AccessReview.Read.All", "AccessReview.Read.All", "accessreviewset-list-definitions", "Learn page read 2026-10-24"),
    ("/identityProtection/riskyUsers",                             "IdentityRiskyUser.Read.All", "IdentityRiskyUser.Read.All", "riskyuser-list", "Learn page read 2026-10-24"),
    ("/reports/authenticationMethods/userRegistrationDetails",     "AuditLog.Read.All", "AuditLog.Read.All", "authenticationmethodsroot-list-userregistrationdetails", "Learn page read 2026-10-24 (Reports.Read.All is NOT needed)"),
    ("/users (+ signInActivity)",                                  "User.Read.All", "User.Read.All + AuditLog.Read.All", "user-list", "Learn page read; signInActivity additionally needs AuditLog.Read.All and Entra ID P1/P2"),
    ("/applications",                                              "Application.Read.All", "Application.Read.All", "application-list", "Learn page read 2026-10-24"),
    ("/servicePrincipals, /servicePrincipals/{id}/appRoleAssignedTo", "Application.Read.All", "Application.Read.All", "serviceprincipal-list-approleassignedto", "Learn page read 2026-10-24"),
    ("/oauth2PermissionGrants",                                    "Directory.Read.All", "Directory.Read.All", "oauth2permissiongrant-list", "Learn page read 2026-10-24 (the only read-only option)"),
    ("/organization",                                              "Organization.Read.All", "Directory.Read.All", "organization-list", "Learn page read; Directory.Read.All is listed and is already required"),
    ("/domains",                                                   "Domain.Read.All", "Directory.Read.All", "domain-list", "Learn page read; Directory.Read.All is listed and is already required"),
    ("/subscribedSkus",                                            "LicenseAssignment.Read.All", "Directory.Read.All", "subscribedsku-list", "Learn page read; Directory.Read.All is listed and is already required"),
    ("/groupSettings",                                             "GroupSettings.Read.All", "Directory.Read.All", "group-list-settings", "Learn page read; Directory.Read.All is listed and is already required"),
    ("/groups",                                                    "Group.Read.All", "Directory.Read.All", "group-list", "Learn page read; Directory.Read.All is listed and is already required"),
    ("/identity/conditionalAccess/namedLocations",                 "Policy.Read.All", "Policy.Read.All", "conditionalaccessroot-list-namedlocations", "Learn page read 2026-10-24"),
    ("/roleManagement/directory/roleAssignmentScheduleInstances",  "RoleAssignmentSchedule.Read.Directory", "RoleManagement.Read.Directory", "rbacapplication-list-roleassignmentscheduleinstances", "Learn page read 2026-10-24; RoleManagement.Read.Directory is listed and already required. The $filter/$expand=principal forms are not detailed on the page (see LIVE_VALIDATION.md)"),
    ("/auditLogs/signIns",                                         "AuditLog.Read.All", "AuditLog.Read.All", "signin-list", "Learn page read 2026-10-24 (needs Entra ID P1 in practice)"),
    ("/policies/crossTenantAccessPolicy/partners",                 "Policy.Read.All", "Policy.Read.All", "crosstenantaccesspolicy-list-partners", "Learn page read 2026-10-24"),
    ("/policies/authenticationStrengthPolicies",                   "Policy.Read.AuthenticationMethod", "Policy.Read.All", "authenticationstrengthroot-list-policies", "Learn page read 2026-10-24; Policy.Read.All is listed and already required"),
]

# Things a CIS recommendation asks for that Graph app-only access cannot read; reported as MANUAL, never as a pass.
NOT_AVAILABLE = {
    "/directory/onPremisesSynchronization": "Microsoft documents this as DELEGATED-only (Global Administrator); application permissions are not supported "
                                            "(onpremisesdirectorysynchronization-get). Password hash sync therefore cannot be checked by an unattended scan.",
}

def valid_permission_name(name):
    """True for names shaped like 'Policy.Read.All': two or more dot-separated alphanumeric parts, each starting upper-case.

    Written without a regular expression so it is linear-time on any input (no backtracking).
    """
    parts = str(name).split(".")
    return len(parts) >= 2 and all(p[:1].isupper() and p.isascii() and p.isalnum() for p in parts)


class _Matcher:
    """Keeps the old `PERMISSION_RX.match(name)` call style working."""
    match = staticmethod(lambda n: valid_permission_name(n) or None)


PERMISSION_RX = _Matcher()


def required_permissions(checks=None):
    """Sorted list of every permission some check needs, from the @check declarations."""
    if checks is None:
        from . import runner  # noqa: F401  (importing the runner registers all checks)
        from .models import CHECKS
        checks = CHECKS
    names = set()
    for _cat, fn in checks:
        names.update(getattr(fn, "needs", ()))
    return sorted(names)


def permission_table(checks=None):
    """[(permission, purpose, [check names that use it])] for display."""
    if checks is None:
        from . import runner  # noqa: F401
        from .models import CHECKS
        checks = CHECKS
    users: dict[str, list[str]] = {}
    for _cat, fn in checks:
        for p in getattr(fn, "needs", ()):
            users.setdefault(p, []).append(fn.__name__)
    return [(p, PURPOSE.get(p, "?"), sorted(users[p])) for p in sorted(users)]
