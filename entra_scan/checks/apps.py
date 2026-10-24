"""Applications (APP-*): app-registration credentials, high-privilege application permissions and risky consent grants.

Why this matters: an app with a powerful permission is an admin account that never gets MFA, never gets a holiday and
whose secret is often sitting in a config file. 'Illicit consent' (a user clicks Accept on a malicious app) is a
common way to gain a foothold without stealing a password.
"""
from __future__ import annotations

from collections import defaultdict

from ..context import Ctx
from ..models import MICROSOFT_TENANT, INFO, GraphError, check, parse_time, ref, sample, seg, verdict

C = "apps"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
# Resource APIs whose application permissions we audit (Microsoft Graph, Exchange Online, SharePoint Online).
RESOURCES = {GRAPH_APP_ID: "Microsoft Graph", "00000002-0000-0ff1-ce00-000000000000": "Exchange Online",
             "00000003-0000-0ff1-ce00-000000000000": "SharePoint Online"}
# Tier 1: lets the app escalate privilege or write tenant-wide / read everything.
TIER1 = {
    "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All",
    "Directory.ReadWrite.All", "PrivilegedAccess.ReadWrite.AzureAD", "Policy.ReadWrite.ConditionalAccess",
    "Policy.ReadWrite.AuthenticationMethod", "UserAuthenticationMethod.ReadWrite.All", "User.ReadWrite.All",
    "Group.ReadWrite.All", "RoleManagementPolicy.ReadWrite.Directory", "Sites.FullControl.All",
    "full_access_as_app", "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All", "Sites.ReadWrite.All",
}
# Tier 2: broad read access.
TIER2 = {
    "Mail.Read", "MailboxSettings.ReadWrite", "Files.Read.All", "Sites.Read.All", "Directory.Read.All",
    "Chat.Read.All", "ChannelMessage.Read.All", "Calendars.ReadWrite", "Contacts.ReadWrite",
    "Exchange.ManageAsApp", "Sites.Manage.All", "User.Read.All", "Group.Read.All",
}
RISKY_DELEGATED = TIER1 | {"Mail.Read", "Files.Read.All", "Sites.Read.All", "EWS.AccessAsUser.All",
                           "Mail.ReadWrite.Shared", "Mail.Send.Shared", "Chat.Read.All"}
SP_FIELDS = "id,displayName,appOwnerOrganizationId,servicePrincipalType,verifiedPublisher"
EXPIRY_WARNING_DAYS = 30
LONG_SECRET_DAYS = 730
MAX_PRINCIPALS = 300          # cap on service principals described per check, to bound runtime on huge tenants


# --------------------------------------------------------------------------- service principal lookup
def _service_principals(ctx: Ctx):
    """{id: service principal} for the whole tenant, loaded once (far fewer calls than one lookup per app)."""
    def load():
        """Fetch every service principal once; a failure yields an empty map so lookups fall back to single GETs."""
        try:
            return {sp["id"]: sp for sp in ctx.g.get_all("/servicePrincipals", {"$select": SP_FIELDS, "$top": "999"}) if "id" in sp}
        except GraphError:
            return {}
    return ctx.cached("sp_all", load)


def _sp_info(ctx: Ctx, sp_id):
    """Look up one service principal: the bulk list first, a single GET only for stragglers."""
    known = _service_principals(ctx)
    if sp_id not in known:
        try:
            known[sp_id] = ctx.g.get(f"/servicePrincipals/{seg(sp_id)}", {"$select": SP_FIELDS})
        except GraphError:
            known[sp_id] = {}
    return known[sp_id]


def _origin(ctx: Ctx, info):
    """Who owns this app: 'microsoft', 'managed-identity', 'this tenant' or an external tenant (verified or UNVERIFIED publisher)."""
    owner = info.get("appOwnerOrganizationId")
    if owner == MICROSOFT_TENANT:
        return "microsoft"
    if info.get("servicePrincipalType") == "ManagedIdentity":
        return "managed-identity"
    if owner == ctx.tenant_id():
        return "this tenant"
    publisher = (info.get("verifiedPublisher") or {}).get("displayName")
    return f"external tenant, {'verified: ' + publisher if publisher else 'UNVERIFIED publisher'}"


# --------------------------------------------------------------------------- checks
@check("apps", needs=("Application.Read.All",))
def app_credentials(ctx: Ctx):
    """App registration secret and certificate hygiene"""
    apps = ctx.g.get_all("/applications", {"$select": "id,appId,displayName,signInAudience,passwordCredentials,keyCredentials", "$top": "999"})
    expired, expiring, long_lived = [], [], []
    for a in apps:
        for kind, creds in (("secret", a.get("passwordCredentials") or []), ("certificate", a.get("keyCredentials") or [])):
            for c in creds:
                end, start = parse_time(c.get("endDateTime")), parse_time(c.get("startDateTime"))
                label = (f"{a.get('displayName')} [appId {a.get('appId')}, objectId {a.get('id')}]: {kind} "
                         f"'{c.get('displayName') or str(c.get('keyId', ''))[:8]}' (keyId {c.get('keyId')})")
                if end and end < ctx.now:
                    expired.append(f"{label} expired {end:%Y-%m-%d}")
                elif end and (end - ctx.now).days <= EXPIRY_WARNING_DAYS:
                    expiring.append(f"{label} expires {end:%Y-%m-%d}")
                if kind == "secret" and end and start and (end - start).days > LONG_SECRET_DAYS and end > ctx.now:
                    long_lived.append(f"{label} valid {(end - start).days}d")
    multi_tenant = [ref(a.get("displayName"), a.get("appId")) for a in apps
                    if a.get("signInAudience") in ("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount", "PersonalMicrosoftAccount")]
    return [
        verdict("APP-001", C, "No expired credentials left on app registrations", not expired, "low",
                f"{len(expired)} expired credentials.", "Remove expired secrets and certificates.", sample(expired), warn=True),
        verdict("APP-002", C, f"No app credentials expire within {EXPIRY_WARNING_DAYS} days", not expiring, "medium",
                "Upcoming expiry causes outages and rushed, poorly reviewed rotation.",
                "Rotate now; prefer certificates or workload identity federation over secrets.", sample(expiring), warn=True),
        verdict("APP-003", C, "No client secrets valid for more than 2 years", not long_lived, "medium",
                "Long-lived secrets widen the window in which a leak is useful.",
                "Cap secret lifetime with an app management policy and move to certificates or federated credentials.", sample(long_lived)),
        INFO("APP-004", C, "Multi-tenant app registrations",
             f"{len(multi_tenant)} of {len(apps)} apps accept sign-ins from other tenants.", sample(multi_tenant)),
    ]


@check("apps", needs=("Application.Read.All", "Directory.Read.All"))
def app_permissions(ctx: Ctx):
    """High-privilege application permissions granted to apps"""
    granted = defaultdict(set)          # (principal id, name, API) -> set of permission names
    for app_id, api_name in RESOURCES.items():
        try:
            resource = ctx.g.get(f"/servicePrincipals(appId='{seg(app_id)}')", {"$select": "id,appRoles"})
        except GraphError as e:
            if e.status == 404:                         # that API is not present in this tenant
                continue
            raise
        role_names = {r["id"]: r["value"] for r in (resource.get("appRoles") or []) if isinstance(r, dict) and r.get("id") and r.get("value")}
        for assignment in ctx.g.get_all(f"/servicePrincipals/{seg(resource['id'])}/appRoleAssignedTo"):
            if not (assignment.get("principalId") and assignment.get("appRoleId")):
                continue                                # incomplete row: nothing to attribute
            if assignment.get("principalType") == "ServicePrincipal" and role_names.get(assignment["appRoleId"]):
                granted[(assignment["principalId"], assignment.get("principalDisplayName", "?"), api_name)].add(role_names[assignment["appRoleId"]])

    tier1, tier2 = [], []
    for (pid, name, api_name), perms in list(granted.items())[:MAX_PRINCIPALS]:
        high, medium = perms & TIER1, perms & TIER2
        if not (high or medium):
            continue
        origin = _origin(ctx, _sp_info(ctx, pid))
        if origin == "microsoft":
            continue                                    # first-party Microsoft apps are expected to hold these
        line = f"{ref(name, pid)} [{api_name}] ({origin}): {', '.join(sorted(high or medium))}"
        (tier1 if high else tier2).append(line)
    unverified = [x for x in tier1 if "UNVERIFIED" in x]
    return [
        verdict("APP-010", C, "No unverified external apps hold high-privilege application permissions", not unverified, "critical",
                "Apps from other tenants with no verified publisher hold powerful permissions.",
                "Investigate immediately; revoke consent and review sign-in and audit logs for the app.", unverified),
        verdict("APP-011", C, "Apps with tenant-wide write or full-data application permissions", not tier1, "high",
                f"{len(tier1)} service principals hold privilege-escalation or all-mailbox / all-file permissions.",
                "Validate the business need; scope with RBAC for Applications or Sites.Selected; remove unused.", sample(tier1), warn=True),
        verdict("APP-012", C, "Apps with broad read application permissions", not tier2, "medium",
                f"{len(tier2)} service principals hold broad read permissions.", "Review and scope to the minimum required.", sample(tier2), warn=True),
    ]


@check("apps", needs=("Directory.Read.All", "Application.Read.All"))
def oauth_consent(ctx: Ctx):
    """Delegated consent grants (illicit-consent risk)"""
    grants = ctx.g.get_all("/oauth2PermissionGrants", {"$top": "999"})
    admin_consented, user_consented = defaultdict(set), defaultdict(set)
    for g in grants:
        if not g.get("clientId"):
            continue
        risky = set((g.get("scope") or "").split()) & RISKY_DELEGATED
        if risky:
            (admin_consented if g.get("consentType") == "AllPrincipals" else user_consented)[g["clientId"]] |= risky

    def describe(book):
        """Turn {client id: scopes} into readable lines plus the subset whose publisher is unverified."""
        lines, unverified = [], []
        for client_id, scopes in list(book.items())[:100]:
            info = _sp_info(ctx, client_id)
            origin = _origin(ctx, info)
            if origin == "microsoft":
                continue
            line = f"{ref(info.get('displayName', client_id), client_id)} ({origin}): {', '.join(sorted(scopes))}"
            lines.append(line)
            if "UNVERIFIED" in origin:
                unverified.append(line)
        return lines, unverified

    admin_lines, admin_unverified = describe(admin_consented)
    user_lines, user_unverified = describe(user_consented)
    both = admin_unverified + user_unverified
    return [
        verdict("APP-020", C, "No unverified external apps have risky delegated consent", not both, "high",
                "Unverified third-party apps hold risky delegated scopes (the illicit-consent-grant pattern).",
                "Revoke the grants, disable the enterprise app and hunt for token use in audit and sign-in logs.", sample(both)),
        verdict("APP-021", C, "Tenant-wide (admin) consents with risky scopes", not admin_lines, "medium",
                f"{len(admin_lines)} apps have admin-consented risky scopes for all users.", "Review each; remove unused consent.", sample(admin_lines), warn=True),
        verdict("APP-022", C, "User-consented grants with risky scopes", not user_lines, "medium",
                f"{len(user_lines)} apps have user-consented risky scopes.", "Restrict user consent and enable the admin consent workflow.", sample(user_lines), warn=True),
    ]
