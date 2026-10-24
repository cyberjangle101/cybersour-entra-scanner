"""Conditional Access (CA-*) and Security Defaults.

Conditional Access is the policy engine that decides, at every sign-in, whether to allow, block or challenge for MFA.
The checks here ask: "is there an ENABLED policy that does X?".  A policy that is only in report-only mode does not
count as a pass (it is reported as a WARN), because it enforces nothing.

CIS references are to the CIS Microsoft 365 Foundations Benchmark v5.0.0 (section 5.2.2).
"""
from __future__ import annotations

from ..context import Ctx
from .privileged import break_glass_ids
from ..models import FAIL, INFO, PASS, WARN, SkipCheck, check, ref, verdict

C = "ca"

AZURE_MANAGEMENT_APP = "797f4846-ba00-4fd7-ba43-dac1f8f63013"      # "Microsoft Azure Management" cloud app
INTUNE_ENROLLMENT_APP = "d4ebce55-015a-49b5-a083-c84d1797ae8c"      # "Microsoft Intune Enrollment" cloud app
PHISHING_RESISTANT_STRENGTH = "00000000-0000-0000-0000-000000000004"  # built-in authentication strength
REGISTER_SECURITY_INFO = "urn:user:registersecurityinfo"             # the "register security information" user action

# The administrator roles CIS 5.2.2.1 requires MFA for (name -> role template ID; IDs verified against Microsoft Learn).
ADMIN_ROLES = {
    "Application Administrator": "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
    "Authentication Administrator": "c4e39bd9-1100-46d3-8c65-fb160da0071f",
    "Billing Administrator": "b0f54661-2d74-4c50-afa3-1ec803f12efe",
    "Cloud Application Administrator": "158c047a-c907-4556-b7ef-446551a6b5f7",
    "Conditional Access Administrator": "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
    "Exchange Administrator": "29232cdf-9323-42fd-ade2-1d097af3e4de",
    "Global Administrator": "62e90394-69f5-4237-9190-012177145e10",
    "Global Reader": "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
    "Helpdesk Administrator": "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "Password Administrator": "966707d0-3269-4727-9be2-8c3a10f19b9d",
    "Privileged Authentication Administrator": "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
    "Privileged Role Administrator": "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "Security Administrator": "194ae4cb-b126-40b2-bd5b-6091b380977d",
    "SharePoint Administrator": "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
    "User Administrator": "fe930be7-5e62-47db-91af-98c3a49a38b1",
}
_ROLE_NAME = {v: k for k, v in ADMIN_ROLES.items()}


# --------------------------------------------------------------------------- tiny readers for the policy JSON
# Graph returns deeply nested objects where any level can be null; these helpers always return something safe.
def _cond(p, key):
    return (p.get("conditions") or {}).get(key) or {}


def _grant_controls(p):
    return (p.get("grantControls") or {}).get("builtInControls") or []


def _strength_id(p):
    return ((p.get("grantControls") or {}).get("authenticationStrength") or {}).get("id")


def _session(p, key):
    return (p.get("sessionControls") or {}).get(key) or {}


def _all_users(p):
    return "All" in (_cond(p, "users").get("includeUsers") or [])


def _all_apps(p):
    return "All" in (_cond(p, "applications").get("includeApplications") or [])


def _narrowed(p, client_types=True):
    """True when the policy only applies to a SUBSET of sign-ins, so it cannot count as 'for everyone, always'.

    Examples that narrow a policy: a sign-in/user risk level, specific platforms, specific locations, a device filter, or
    only some client app types (for example browser only). Without this, a 'user risk' policy that also requires MFA would
    wrongly satisfy 'MFA for all users'.  `client_types=False` skips the client-type test (legacy-auth blocks are *defined* by it).
    """
    c = p.get("conditions") or {}
    if any(c.get(k) for k in ("signInRiskLevels", "userRiskLevels", "insiderRiskLevels", "servicePrincipalRiskLevels")):
        return True
    if (c.get("platforms") or {}).get("includePlatforms") not in (None, [], ["all"]):
        return True
    if (c.get("locations") or {}).get("includeLocations") not in (None, [], ["All"]):
        return True
    if c.get("devices"):
        return True
    types = set(c.get("clientAppTypes") or ["all"])
    return client_types and "all" not in types and not {"browser", "mobileAppsAndDesktopClients"} <= types


def _requires_mfa(p):
    """MFA is required either by the classic 'mfa' control or by any authentication strength."""
    return "mfa" in _grant_controls(p) or _strength_id(p) is not None


def _blocks(p):
    return "block" in _grant_controls(p)


def _missing_admin_roles(p):
    """Admin roles (from CIS's list) that this policy does NOT target. [] = fully covered; None = does not target admins at all."""
    if _all_users(p):
        return []                                               # everyone includes every admin
    included = set(_cond(p, "users").get("includeRoles") or [])
    if not included & set(ADMIN_ROLES.values()):
        return None
    return [name for name, rid in ADMIN_ROLES.items() if rid not in included]


def _targets_all_admins(p):
    return _missing_admin_roles(p) == []


# --------------------------------------------------------------------------- shared evaluator
def _evaluate(rows, enabled, report_only):
    """Turn (id, title, severity, test, fix[, partial_test]) rows into findings.

    PASS    an enabled policy satisfies the test.
    WARN    only a report-only policy satisfies it (not enforced).
    FAIL    nothing satisfies it. If a policy comes close (right idea, but not every admin role targeted) the detail says so.
    """
    out = []
    for row in rows:
        i, title, sev, test, fix = row[:5]
        near = row[5] if len(row) > 5 else None
        hit = [ref(p.get("displayName"), p.get("id")) for p in enabled if test(p)]
        ro = [ref(p.get("displayName"), p.get("id")) for p in report_only if test(p)]
        if hit:
            out.append(PASS(i, C, title, "Covered by: " + ", ".join(hit)[:300]))
        elif ro:
            out.append(WARN(i, C, title, sev, "Only satisfied by report-only policies; they are logged but not enforced.", fix, ro))
        else:
            detail = "No enabled policy satisfies this control."
            if near:
                gaps = []
                for p in enabled:
                    if near(p):
                        missing = _missing_admin_roles(p)
                        if missing:
                            gaps.append(f"{ref(p.get('displayName'), p.get('id'))} is missing {len(missing)} role(s): {', '.join(missing)}")
                if gaps:
                    detail += " Closest policies cover only some administrator roles. " + " | ".join(gaps)[:600]
            out.append(FAIL(i, C, title, sev, detail, fix))
    return out


# --------------------------------------------------------------------------- the checks
@check("ca", needs=("Policy.Read.All",))
def conditional_access(ctx: Ctx):
    """Conditional Access baseline (legacy auth, MFA, risk policies)"""
    if ctx.security_defaults_enabled():
        return [INFO("CA-SD", C, "Security Defaults are enabled",
                     "Security Defaults give baseline MFA and block legacy authentication. Move to Conditional Access "
                     "(Entra ID P1) when you need exclusions, device controls or risk-based rules.")]
    policies = ctx.conditional_access_policies()
    if policies is None:
        return [FAIL("CA-000", C, "Conditional Access unreadable and Security Defaults are off", "high",
                     "Could not read Conditional Access policies (missing Policy.Read.All or no Entra ID P1 licence) and "
                     "Security Defaults are disabled, so no MFA baseline can be confirmed.",
                     "Enable Security Defaults, or license Entra ID P1 and deploy Conditional Access baseline policies.")]
    enabled = [p for p in policies if p.get("state") == "enabled"]
    report_only = [p for p in policies if p.get("state") == "enabledForReportingButNotEnforced"]
    if not enabled:
        return [FAIL("CA-000", C, "No enabled Conditional Access policies and Security Defaults are off", "critical",
                     f"{len(policies)} policies exist, none enforced.",
                     "Enforce MFA for all users and block legacy authentication immediately.")]

    def legacy_blocked(p):
        """True if the policy blocks Exchange ActiveSync and 'other' (legacy) clients for everyone."""
        types = set((p.get("conditions") or {}).get("clientAppTypes") or [])
        return _blocks(p) and _all_users(p) and _all_apps(p) and {"exchangeActiveSync", "other"} <= types and not _narrowed(p, client_types=False)

    rows = [
        ("CA-001", "Legacy authentication is blocked", "high", legacy_blocked,
         "Create a policy: all users, all resources, client apps = Exchange ActiveSync + other clients, grant = block."),
        ("CA-002", "MFA required for all users on all apps", "high",
         lambda p: _all_users(p) and _all_apps(p) and _requires_mfa(p) and not _narrowed(p),
         "Create a policy requiring MFA (or an authentication strength) for all users and all resources."),
        ("CA-003", "MFA required for all administrator roles", "critical",
         lambda p: _requires_mfa(p) and _all_apps(p) and _targets_all_admins(p) and not _narrowed(p),
         "Require MFA for every directory role (the CIS list of 15 roles) on all resources.",
         lambda p: _requires_mfa(p) and _all_apps(p)),
        ("CA-004", "MFA required for guest / external users", "medium",
         lambda p: _requires_mfa(p) and not _narrowed(p) and ((_all_users(p) and _all_apps(p)) or _cond(p, "users").get("includeGuestsOrExternalUsers")),
         "Add a policy targeting guests and external users that requires MFA."),
        ("CA-005", "MFA required for Azure management", "medium",
         lambda p: _requires_mfa(p) and not _narrowed(p) and (_all_apps(p) or AZURE_MANAGEMENT_APP in (_cond(p, "applications").get("includeApplications") or [])),
         "Require MFA for the 'Microsoft Azure Management' cloud app."),
        ("CA-006", "Sign-in risk policy enforced (Identity Protection)", "medium",
         lambda p: "high" in ((p.get("conditions") or {}).get("signInRiskLevels") or []) and _all_users(p),
         "Require MFA or block at medium/high sign-in risk for all users (needs Entra ID P2)."),
        ("CA-007", "User risk policy enforced (Identity Protection)", "medium",
         lambda p: "high" in ((p.get("conditions") or {}).get("userRiskLevels") or []) and _all_users(p),
         "Require a secure password change at high user risk for all users (needs Entra ID P2)."),
    ]
    out = _evaluate(rows, enabled, report_only)

    # CA-008: exclusions are the classic bypass. List every enabled policy that excludes users, groups or roles.
    exclusions = []
    bg = break_glass_ids(ctx)                       # emergency-access exclusions are EXPECTED, so they are not counted as risky
    for p in enabled:
        u = _cond(p, "users")
        n_users = len([x for x in (u.get("excludeUsers") or []) if x not in bg])
        n_groups, n_roles = (len(u.get(k) or []) for k in ("excludeGroups", "excludeRoles"))
        if n_users or n_groups or n_roles:
            exclusions.append(f"{ref(p.get('displayName'), p.get('id'))}: excludes {n_users} users, {n_groups} groups, {n_roles} roles")
    out.append(verdict("CA-008", C, "Enabled Conditional Access policies have no user/group exclusions", not exclusions, "low",
                       "Exclusions are common bypass paths; each should be justified, time-boxed and monitored (detected emergency-access accounts are ignored).",
                       "Review exclusions; use a single documented break-glass group.", exclusions, warn=True))
    out.append(INFO("CA-009", C, "Conditional Access policy inventory",
                    f"{len(enabled)} enabled, {len(report_only)} report-only, {len(policies) - len(enabled) - len(report_only)} disabled."))
    return out


@check("ca", needs=("Policy.Read.All",))
def conditional_access_cis(ctx: Ctx):
    """Conditional Access: session, device, strength and flow controls (CIS 5.2.2.4 to 5.2.2.12)"""
    if ctx.security_defaults_enabled():
        return [INFO("CA-NA", C, "Conditional Access session, device and flow controls not evaluated",
                     "Security Defaults are on, so Conditional Access policies are not in use. CA-010 to CA-016 apply once you move to Conditional Access.")]
    policies = ctx.conditional_access_policies()
    if policies is None:
        raise SkipCheck("Conditional Access policies are unreadable (needs Policy.Read.All and Entra ID P1).")
    enabled = [p for p in policies if p.get("state") == "enabled"]
    report_only = [p for p in policies if p.get("state") == "enabledForReportingButNotEnforced"]

    def admin_session(p):
        """True if admins get a short sign-in frequency (4h or every time) and a non-persistent browser session."""
        freq, browser = _session(p, "signInFrequency"), _session(p, "persistentBrowser")
        short = (freq.get("frequencyInterval") == "everyTime"
                 or (freq.get("type") == "hours" and 0 < (freq.get("value") or 99) <= 4))
        return (_targets_all_admins(p) and _all_apps(p) and freq.get("isEnabled") and short
                and browser.get("isEnabled") and browser.get("mode") == "never")

    def risk_blocked(p):
        """True if sign-ins at medium AND high risk are blocked for all users."""
        levels = set((p.get("conditions") or {}).get("signInRiskLevels") or [])
        return _blocks(p) and _all_users(p) and {"high", "medium"} <= levels

    def managed_device(p):
        """True if all users on all apps must use a compliant or hybrid-joined device."""
        return (_all_users(p) and _all_apps(p) and not _narrowed(p)
                and bool({"compliantDevice", "domainJoinedDevice"} & set(_grant_controls(p))))

    def device_for_registration(p):
        """True if registering security info needs a managed device (or is blocked)."""
        actions = _cond(p, "applications").get("includeUserActions") or []
        return (REGISTER_SECURITY_INFO in actions and _all_users(p)
                and (bool({"compliantDevice", "domainJoinedDevice"} & set(_grant_controls(p))) or _blocks(p)))

    def intune_every_time(p):
        """True if the Intune Enrollment app forces sign-in every time."""
        apps = _cond(p, "applications").get("includeApplications") or []
        return (INTUNE_ENROLLMENT_APP in apps and _all_users(p)
                and _session(p, "signInFrequency").get("frequencyInterval") == "everyTime")

    def device_code_blocked(p):
        """True if the device code flow is blocked for all users."""
        flows = str(_cond(p, "authenticationFlows").get("transferMethods") or "")
        return _blocks(p) and _all_users(p) and "deviceCodeFlow" in flows

    rows = [
        ("CA-010", "Administrators have a short sign-in frequency and non-persistent browser sessions", "medium", admin_session,
         "Policy for all admin roles: sign-in frequency 4 hours or less (or every time) and persistent browser session = Never.",
         lambda p: bool(_session(p, "signInFrequency").get("isEnabled"))),
        ("CA-011", "Phishing-resistant MFA is required for administrators", "medium",
         lambda p: _targets_all_admins(p) and _all_apps(p) and _strength_id(p) == PHISHING_RESISTANT_STRENGTH,
         "Policy for all admin roles with grant = authentication strength 'Phishing-resistant MFA' (passkeys / FIDO2 / certificate).",
         lambda p: _strength_id(p) == PHISHING_RESISTANT_STRENGTH),
        ("CA-012", "Sign-in risk is blocked at medium and high", "medium", risk_blocked,
         "Policy for all users: condition sign-in risk = high and medium, grant = block (needs Entra ID P2)."),
        ("CA-013", "A managed device is required for authentication", "medium", managed_device,
         "Policy for all users and all resources requiring a compliant device or hybrid-joined device."),
        ("CA-014", "A managed device is required to register security information", "medium", device_for_registration,
         "Policy on the user action 'Register security information' requiring a compliant/hybrid-joined device (or blocking untrusted locations)."),
        ("CA-015", "Intune enrollment requires sign-in every time", "low", intune_every_time,
         "Policy on the 'Microsoft Intune Enrollment' app with session control sign-in frequency = Every time."),
        ("CA-016", "The device code sign-in flow is blocked", "high", device_code_blocked,
         "Policy for all users: conditions > authentication flows = device code flow, grant = block (exclude only documented exceptions)."),
    ]
    return _evaluate(rows, enabled, report_only)

