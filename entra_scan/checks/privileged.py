"""Privileged access (ADM-*): who holds powerful Entra roles, and how well those accounts are protected.

CIS references are to the CIS Microsoft 365 Foundations Benchmark v5.0.0 (section 1.1 and 5.2.2).
"""
from __future__ import annotations

from ..context import Ctx
from ..models import FAIL, INFO, PASS, GraphError, check, ref, sample, seg, verdict, WARN

C = "roles"

# Roles that can change security settings, read mail/files in bulk or reset other people's credentials.
PRIVILEGED_ROLES = {
    "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
    "Security Administrator", "Exchange Administrator", "SharePoint Administrator", "User Administrator",
    "Conditional Access Administrator", "Application Administrator", "Cloud Application Administrator",
    "Authentication Administrator", "Intune Administrator", "Hybrid Identity Administrator",
    "Helpdesk Administrator", "Password Administrator", "Groups Administrator", "Teams Administrator",
}
# CIS 1.1.4: an admin account should carry only a licence with a small application footprint (Entra ID P1/P2, not M365 E5 ...).
REDUCED_FOOTPRINT_SKUS = {"AAD_PREMIUM", "AAD_PREMIUM_P2", "AAD_BASIC", "AAD_PREMIUM_P1"}
STALE_ADMIN_DAYS = 90


def load_admins(ctx: Ctx):
    """{principal id: {kind, roles, name}} for every principal that holds a privileged role at tenant scope.

    kind is 'user', 'group' or 'servicePrincipal'.  Roles scoped to an administrative unit are ignored: they are not tenant-wide.
    """
    def load():
        """Compute the result once; the surrounding function caches it on the scan context."""
        definitions = {d["id"]: (d["displayName"] if isinstance(d.get("displayName"), str) else d["id"]) for d in
                       [x for x in ctx.g.get_all("/roleManagement/directory/roleDefinitions", {"$select": "id,displayName"}) if isinstance(x.get("id"), str) and x["id"]]}
        admins = {}
        for a in ctx.g.get_all("/roleManagement/directory/roleAssignments", {"$expand": "principal"}):
            if a.get("directoryScopeId", "/") != "/" or not (isinstance(a.get("roleDefinitionId"), str) and isinstance(a.get("principalId"), str)
                                                              and a["roleDefinitionId"] and a["principalId"]):
                continue                             # only well-formed, tenant-wide assignments (ids are used as dict keys)
            role = definitions.get(a["roleDefinitionId"], a["roleDefinitionId"])
            if role not in PRIVILEGED_ROLES:
                continue
            principal = a.get("principal") if isinstance(a.get("principal"), dict) else {}
            kind = str(principal.get("@odata.type") or "").rsplit(".", 1)[-1] or "unknown"
            entry = admins.setdefault(a["principalId"], {"kind": kind, "roles": set(),
                                                         "name": principal.get("userPrincipalName") or principal.get("displayName") or a["principalId"]})
            entry["roles"].add(role)
        return admins
    return ctx.cached("admins", load)


def break_glass_candidates(ctx: Ctx):
    """{user id: user object} of likely emergency-access accounts: cloud-only Global Administrators on the *.onmicrosoft.com domain.

    This is a heuristic (Graph has no 'break-glass' flag). It is shared by ADM-009, the ADM-011..014 break-glass checks and CA-008.
    """
    def load():
        """Loader for the cached value."""
        admins = load_admins(ctx)
        users = {k: v for k, v in admins.items() if v["kind"] == "user" and "Global Administrator" in v["roles"]}
        details = _admin_user_details(ctx, users)
        return {uid: d for uid, d in details.items()
                if not d.get("onPremisesSyncEnabled") and str(d.get("userPrincipalName", "")).lower().endswith(".onmicrosoft.com")}
    return ctx.cached("break_glass", load)


def break_glass_ids(ctx: Ctx):
    """Set of emergency-access account ids; empty if they cannot be determined (never raises)."""
    try:
        return set(break_glass_candidates(ctx))
    except GraphError:
        return set()


def _admin_user_details(ctx: Ctx, admin_users):
    """Details for each admin user. Reuses the tenant-wide user list when it has them; otherwise asks per user."""
    known = ctx.users_by_id()
    details = {}
    select = "id,displayName,userPrincipalName,userType,accountEnabled,onPremisesSyncEnabled,assignedLicenses"
    for uid in list(admin_users)[:200]:
        if uid in known:
            details[uid] = known[uid]
            continue
        try:                                              # not in the (possibly capped) list: fetch just this user
            details[uid] = ctx.g.get(f"/users/{seg(uid)}", {"$select": select + ",signInActivity"})
        except GraphError:
            try:
                details[uid] = ctx.g.get(f"/users/{seg(uid)}", {"$select": select})
            except GraphError:
                continue
    return details


def _sku_names(ctx: Ctx):
    """{skuId: skuPartNumber}, e.g. {'<guid>': 'AAD_PREMIUM_P2'}. Empty if the licence list cannot be read."""
    def load():
        """Compute the result once; the surrounding function caches it on the scan context."""
        try:
            return {s["skuId"]: str(s.get("skuPartNumber", "?")) for s in ctx.g.get_all("/subscribedSkus") if isinstance(s.get("skuId"), str)}
        except GraphError:
            return {}
    return ctx.cached("skus", load)


@check("roles", needs=("RoleManagement.Read.Directory", "User.Read.All", "AuditLog.Read.All", "Directory.Read.All"))
def privileged_accounts(ctx: Ctx):
    """Privileged role hygiene (admin count, cloud-only, licences, MFA, stale)"""
    admins = load_admins(ctx)
    users = {k: v for k, v in admins.items() if v["kind"] == "user"}
    out = []

    # ADM-001 (CIS 1.1.3): between two and four Global Administrators. One is a single point of failure; many is a big attack surface.
    ga = [ref(v["name"], k) for k, v in users.items() if "Global Administrator" in v["roles"]]
    n = len(ga)
    if n < 2:
        out.append(FAIL("ADM-001", C, "Between two and four Global Administrators", "medium",
                        f"{n} Global Administrator(s) found; no redundancy or break-glass capacity.",
                        "Keep 2 to 4 Global Administrators, including two cloud-only emergency-access accounts.", ga))
    elif n > 4:
        out.append(FAIL("ADM-001", C, "Between two and four Global Administrators", "high" if n > 5 else "medium",
                        f"{n} standing Global Administrators (CIS recommends 2 to 4).",
                        "Reduce to 2-4; use least-privileged roles and PIM for everyone else.", sample(ga)))
    else:
        out.append(PASS("ADM-001", C, "Between two and four Global Administrators", f"{n} Global Administrators."))

    details = _admin_user_details(ctx, users)
    upn = lambda d: ref(d.get("userPrincipalName"), d.get("id"))

    guests = [upn(d) for d in details.values() if d.get("userType") == "Guest"]
    out.append(verdict("ADM-002", C, "No guest accounts hold privileged roles", not guests, "high",
                       "External guest identities hold admin roles.", "Remove roles from guests; use internal accounts.", guests))

    synced = [upn(d) for d in details.values() if d.get("onPremisesSyncEnabled")]
    out.append(verdict("ADM-003", C, "Privileged accounts are cloud-only", not synced, "medium",
                       "Admins synced from on-premises AD can be compromised through an on-premises domain compromise.",
                       "Use dedicated cloud-only admin accounts.", synced))

    # ADM-004 (CIS 1.1.4): admins should have no licence, or one with a small footprint (Entra ID P1/P2).
    skus = _sku_names(ctx)
    heavy = []
    for d in details.values():
        names = [str(skus.get(l.get("skuId"), l.get("skuId", "?"))) if isinstance(l.get("skuId"), str) else "?" for l in d.get("assignedLicenses") or [] if isinstance(l, dict)]
        if names and (not skus or any(x not in REDUCED_FOOTPRINT_SKUS for x in names)):
            heavy.append(f"{upn(d)}: {', '.join(map(str, names))}")
    out.append(verdict("ADM-004", C, "Admin accounts carry only reduced-footprint licences", not heavy, "low",
                       "Licensed admin accounts have mailboxes and collaboration apps, which makes them phishing targets.",
                       "Use separate admin accounts with no licence or an Entra ID P1/P2 licence only.", heavy, warn=True))

    disabled = [upn(d) for d in details.values() if d.get("accountEnabled") is False]
    out.append(verdict("ADM-005", C, "No disabled accounts hold privileged roles", not disabled, "low",
                       "Disabled accounts still hold role assignments.", "Remove role assignments from disabled accounts.", disabled))

    stale = []
    for d in details.values():
        last = ctx.last_seen(d)
        if last and ctx.age_days(last) > STALE_ADMIN_DAYS:
            stale.append(f"{upn(d)} (last sign-in {ctx.age_days(last)}d ago)")
    out.append(verdict("ADM-006", C, f"Privileged accounts signed in within {STALE_ADMIN_DAYS} days", not stale, "medium",
                       "Inactive privileged accounts are unwatched doors.", "Remove or disable unused admin accounts.", stale))

    try:
        registered = ctx.registration_by_id()
        no_mfa = [ref(v["name"], k) for k, v in users.items() if k in registered and not registered[k].get("isMfaRegistered")]
        out.append(verdict("ADM-007", C, "All privileged users are registered for MFA", not no_mfa, "critical",
                           "Admin accounts with no MFA method registered.",
                           "Register phishing-resistant MFA (FIDO2 / passkey) and enforce it with Conditional Access.", no_mfa))
    except GraphError:
        out.append(INFO("ADM-007", C, "Admin MFA registration not evaluated", "Needs AuditLog.Read.All."))

    others = [f"{ref(v['name'], k)} ({v['kind']}): {', '.join(sorted(v['roles']))}" for k, v in admins.items() if v["kind"] != "user"]
    if others:
        out.append(INFO("ADM-008", C, "Groups / service principals holding privileged roles",
                        "Review the membership and credentials of each; they are equivalent to admin accounts.", sample(others)))

    # ADM-009 (CIS 1.1.2): two emergency-access ("break-glass") accounts. We can only look for likely candidates:
    # cloud-only Global Administrators on the *.onmicrosoft.com domain. Whether they are excluded from policies and monitored is manual.
    candidates = [upn(d) for d in break_glass_candidates(ctx).values()]
    out.append(verdict("ADM-009", C, "At least two cloud-only emergency-access Global Administrators exist", len(candidates) >= 2, "medium",
                       f"Found {len(candidates)} cloud-only Global Administrator(s) on the onmicrosoft.com domain (likely break-glass accounts).",
                       "Create two cloud-only emergency-access accounts, exclude them from Conditional Access, protect them with FIDO2 keys and alert on every sign-in.",
                       candidates, warn=True))
    if len(admins) and len(users) > 200:
        out.append(INFO("ADM-010", C, "Admin detail limited to 200 users", f"{len(users)} admin users exist; only the first 200 were inspected."))
    return out


FIDO_METHODS = {"fido2", "passKeyDeviceBound", "passKeyDeviceBoundAuthenticator", "passKeySynced"}


@check("roles", needs=("RoleManagement.Read.Directory", "User.Read.All", "AuditLog.Read.All", "Directory.Read.All", "Policy.Read.All"))
def break_glass(ctx: Ctx):
    """Emergency-access (break-glass) account verification"""
    cands = break_glass_candidates(ctx)
    if not cands:
        return [INFO("ADM-011", C, "Break-glass verification skipped", "No cloud-only *.onmicrosoft.com Global Administrators were found to verify (see ADM-009).")]
    upn = lambda d: ref(d.get("userPrincipalName"), d.get("id"))
    out = []

    # ADM-011: emergency accounts must be excluded from every enabled CA policy that could lock them out (CIS 1.1.2 intent).
    blocking = []
    for pol in ctx.conditional_access_policies():
        if pol.get("state") != "enabled":
            continue
        u = (pol.get("conditions") or {}).get("users") or {}
        included = {x for x in (u.get("includeUsers") or []) if isinstance(x, str)}
        excluded = {x for x in (u.get("excludeUsers") or []) if isinstance(x, str)}
        if not ({"All"} & included or included & set(cands)):
            continue                                 # policy does not target these accounts
        missing = [upn(d) for k, d in cands.items() if k not in excluded]
        if missing:
            blocking.append(f"{ref(pol.get('displayName'), pol.get('id'))}: not excluded -> {', '.join(missing)}")
    out.append(verdict("ADM-011", C, "Break-glass accounts are excluded from Conditional Access policies", not blocking, "high",
                       "A CA misconfiguration or MFA outage could lock out every administrator including emergency accounts.",
                       "Exclude at least two emergency accounts from all CA policies (and protect them with a FIDO2 key and alerting).", blocking))

    # ADM-012: they should hold a phishing-resistant credential since MFA exemptions are common.
    try:
        reg = ctx.registration_by_id()
        weak = [upn(d) for k, d in cands.items() if not (set(reg.get(k, {}).get("methodsRegistered") or []) & FIDO_METHODS)]
        out.append(verdict("ADM-012", C, "Break-glass accounts have a FIDO2 / passkey registered", not weak, "medium",
                           "Emergency accounts without a phishing-resistant method rely on a password alone.",
                           "Register at least one FIDO2 security key per emergency account, stored securely offline.", weak, warn=True))
    except GraphError:
        out.append(INFO("ADM-012", C, "Break-glass FIDO2 registration not evaluated", "Needs AuditLog.Read.All."))

    # ADM-013: any recent use should be an incident or a test; list it so it can be correlated with alerts.
    recent = []
    for d in cands.values():
        last = ctx.last_seen(d)
        if last and ctx.age_days(last) <= 30:
            recent.append(f"{upn(d)} (last sign-in {ctx.age_days(last)}d ago)")
    out.append(verdict("ADM-013", C, "Break-glass accounts not used in the last 30 days", not recent, "medium",
                       "Emergency accounts were used recently; confirm the use was authorised and alerted.",
                       "Alert on every emergency-account sign-in and review the sign-in log for these accounts.", recent, warn=True))

    # ADM-014: no mailbox/app licences on them (smaller phishing surface).
    skus = _sku_names(ctx)
    licensed = [upn(d) for d in cands.values() if d.get("assignedLicenses")]
    out.append(verdict("ADM-014", C, "Break-glass accounts carry no licences", not licensed, "low",
                       "Licensed emergency accounts have mailboxes and are reachable by phishing.",
                       "Remove licences from emergency-access accounts.", licensed, warn=True))
    return out
