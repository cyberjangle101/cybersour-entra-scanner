"""Extended posture checks added in v1.1 (HYB, NET, CAQ, PRV, APP, LEG, AUT, GST).

Everything here is still read-only and uses only the existing ten Graph application permissions.
Every check tolerates null / missing fields: Graph objects vary by licence and tenant age.
"""
from __future__ import annotations

import ipaddress

from ..context import Ctx
from ..models import FAIL, INFO, PASS, WARN, GraphError, SkipCheck, check, parse_time, ref, sample, verdict

HYBRID_SYNC_MAX_HOURS = 24          # a healthy Entra Connect syncs every 30 minutes; a day without sync is a fault
STALE_REPORT_ONLY_DAYS = 90
LEGACY_LOOKBACK_DAYS = 7
BROAD_IPV4_PREFIX = 16              # a trusted range larger than a /16 (65k addresses) is almost never a "corporate office"
WEAK_STRENGTH_METHODS = {"sms", "voice", "email", "temporaryAccessPassOneTime", "temporaryAccessPassMultiUse"}
LEGACY_CLIENTS = {"exchangeActiveSync", "imap4", "pop3", "smtp", "other", "authenticatedSmtp", "mapiOverHttp",
                  "reportingWebServices", "exchangeWebServices", "offlineAddressBook", "autodiscover", "universalOutlook"}


def _d(x):
    """A dict, or {} for anything else (null, number, list ...): nested Graph fields can have any type in a hostile or odd response."""
    return x if isinstance(x, dict) else {}


def _l(x):
    """A list, or [] for anything else."""
    return x if isinstance(x, list) else []


def _text(x):
    """A string, or '' for anything else: hostile or unexpected JSON types must never be used as dict keys or set members."""
    return x if isinstance(x, str) else ""


def _hours_since(ctx: Ctx, value):
    """Hours between now and an ISO timestamp, or None if absent."""
    t = parse_time(value)
    return None if t is None else (ctx.now - t).total_seconds() / 3600


# --------------------------------------------------------------------------- hybrid identity
@check("hybrid", needs=("Directory.Read.All",))
def hybrid_sync(ctx: Ctx):
    """Hybrid identity: directory and password hash sync health"""
    org = ctx.organization()
    if not org:
        raise SkipCheck("The organization object is unreadable (needs Directory.Read.All).")
    if not org.get("onPremisesSyncEnabled"):
        return [PASS("HYB-001", "hybrid", "Directory synchronisation is healthy (not used: cloud-only tenant)"),
                PASS("HYB-002", "hybrid", "Password hash synchronisation is healthy (not used: cloud-only tenant)")]
    out = []
    h = _hours_since(ctx, org.get("onPremisesLastSyncDateTime"))
    out.append(verdict("HYB-001", "hybrid", f"Directory sync ran within the last {HYBRID_SYNC_MAX_HOURS} hours",
                       h is not None and h <= HYBRID_SYNC_MAX_HOURS, "high",
                       "Directory synchronisation has never reported a run." if h is None else f"Last directory sync was {h:.0f} hours ago.",
                       "Check the Microsoft Entra Connect / Cloud Sync health blade and the sync server."))
    # CIS 5.1.8.1: password hash sync. The *setting* is delegated-only, but its freshness timestamp is readable.
    p = _hours_since(ctx, org.get("onPremisesLastPasswordSyncDateTime"))
    out.append(verdict("HYB-002", "hybrid", f"Password hash sync ran within the last {HYBRID_SYNC_MAX_HOURS} hours",
                       p is not None and p <= HYBRID_SYNC_MAX_HOURS, "medium",
                       "Password hash sync has never run (it may be off)." if p is None else f"Last password hash sync was {p:.0f} hours ago.",
                       "Enable password hash synchronisation (it also powers leaked-credential detection) and fix the sync service.", warn=True))
    return out


# --------------------------------------------------------------------------- named locations
def _broad(cidr):
    """True when an IP range is wider than BROAD_IPV4_PREFIX (IPv4) or wider than /32 for IPv6."""
    try:
        net = ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        return False
    return net.prefixlen < (BROAD_IPV4_PREFIX if net.version == 4 else 48)


@check("network", needs=("Policy.Read.All",))
def named_locations(ctx: Ctx):
    """Conditional Access named locations"""
    locs = ctx.named_locations()
    if locs is None:
        raise SkipCheck("Named locations are unreadable (needs Policy.Read.All).")
    locs = [l for l in locs if isinstance(l, dict)]
    trusted = [l for l in locs if l.get("isTrusted")]
    broad = []
    for l in trusted:
        for r in _l(l.get("ipRanges")):
            if _broad(_d(r).get("cidrAddress")):
                broad.append(f"{ref(l.get('displayName'), l.get('id'))}: {r.get('cidrAddress')}")
    ctry = [l for l in locs if "countriesAndRegions" in l]
    out = [verdict("NET-001", "network", "Trusted locations are not overly broad", not broad, "high",
                   "Trusted IP ranges larger than a /16 let a huge address space skip MFA wherever policy trusts 'named locations'.",
                   "Trust only specific corporate egress addresses; never whole ISP or cloud ranges.", broad),
           INFO("NET-002", "network", "Named locations inventory",
                f"{len(locs)} named locations ({len(trusted)} trusted, {len(ctry)} country-based).",
                sample([ref(l.get("displayName"), l.get("id")) + (" [trusted]" if l.get("isTrusted") else "") for l in locs]))]
    # NET-003: a trusted location that no enabled policy references is dead configuration (or a forgotten exception).
    pols = ctx.conditional_access_policies() or []
    used = set()
    for p in pols:
        loc = _d(_d(p.get("conditions")).get("locations"))
        used.update(x for x in _l(loc.get("includeLocations")) if isinstance(x, str))
        used.update(x for x in _l(loc.get("excludeLocations")) if isinstance(x, str))
    unused = [ref(l.get("displayName"), l.get("id")) for l in locs if isinstance(l.get("id"), str) and l["id"] not in used]
    if pols:
        out.append(verdict("NET-003", "network", "Every named location is used by a Conditional Access policy", not unused, "low",
                           "Unreferenced named locations are stale configuration.", "Delete unused locations.", unused, warn=True))
    return out


# --------------------------------------------------------------------------- Conditional Access quality
@check("ca", needs=("Policy.Read.All",))
def ca_quality(ctx: Ctx):
    """Conditional Access policy quality (stale, empty, ineffective policies)"""
    pols = ctx.conditional_access_policies()
    if pols is None:
        raise SkipCheck("Conditional Access policies are unreadable (needs Policy.Read.All and Entra ID P1).")
    ref_ = lambda p: ref(p.get("displayName"), p.get("id"))
    stale_ro, stale_off, empty = [], [], []
    for p in pols:
        changed = parse_time(p.get("modifiedDateTime")) or parse_time(p.get("createdDateTime"))
        age = ctx.age_days(changed) if changed else None
        if p.get("state") == "enabledForReportingButNotEnforced" and age is not None and age > STALE_REPORT_ONLY_DAYS:
            stale_ro.append(f"{ref_(p)} (report-only for {age}d)")
        if p.get("state") == "disabled" and age is not None and age > STALE_REPORT_ONLY_DAYS:
            stale_off.append(f"{ref_(p)} (disabled for {age}d)")
        g, s = _d(p.get("grantControls")), _d(p.get("sessionControls"))
        if p.get("state") == "enabled" and not (g.get("builtInControls") or g.get("authenticationStrength") or g.get("customAuthenticationFactors")
                                                  or g.get("termsOfUse") or any(s.get(k) for k in s)):
            empty.append(ref_(p))
    return [
        verdict("CAQ-001", "ca", f"No policy stuck in report-only for over {STALE_REPORT_ONLY_DAYS} days", not stale_ro, "medium",
                "Report-only policies protect nothing; long-lived ones were probably forgotten.", "Review the report-only results and enforce or delete.", stale_ro, warn=True),
        verdict("CAQ-002", "ca", f"No policy disabled for over {STALE_REPORT_ONLY_DAYS} days", not stale_off, "low",
                "Long-disabled policies add clutter and hide intent.", "Delete policies that will not be re-enabled.", stale_off, warn=True),
        verdict("CAQ-003", "ca", "Enabled policies enforce a grant or session control", not empty, "medium",
                "These enabled policies have no grant or session control, so they have no effect.", "Add controls or delete the policy.", empty),
    ]


# --------------------------------------------------------------------------- privileged depth
CRITICAL_ROLES = {"Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator"}


@check("roles", needs=("RoleManagement.Read.Directory",))
def privileged_depth(ctx: Ctx):
    """Privileged access depth (permanent assignments, high-impact roles held by non-humans)"""
    try:
        rows = ctx.g.get_all("/roleManagement/directory/roleAssignmentScheduleInstances",
                             {"$filter": "assignmentType eq 'Assigned'", "$expand": "principal($select=id,displayName)"})
        defs = {d["id"]: d.get("displayName", d["id"]) for d in ctx.g.get_all("/roleManagement/directory/roleDefinitions", {"$select": "id,displayName"})
                if isinstance(d, dict) and isinstance(d.get("id"), str)}
        defs = {k: (v if isinstance(v, str) else k) for k, v in defs.items()}
    except GraphError as e:
        raise SkipCheck(f"Role assignment schedules are unreadable ({e.message[:120]}). Needs Entra ID P2 and RoleManagement.Read.Directory.")
    perma = []
    for r in (x for x in rows if isinstance(x, dict)):
        name = defs.get(_text(r.get("roleDefinitionId")), _text(r.get("roleDefinitionId")))
        if name in CRITICAL_ROLES and not r.get("endDateTime") and r.get("directoryScopeId", "/") == "/":
            who = _d(r.get("principal"))
            perma.append(f"{ref(who.get('displayName'), r.get('principalId'))}: {name}")
    return [verdict("PRV-001", "roles", "Critical roles are time-bound (no permanent Global/Privileged Role/Privileged Auth Admin)", len(perma) <= 2, "high",
                    f"{len(perma)} permanent (never-expiring) active assignments of critical roles; up to 2 emergency accounts are expected.",
                    "Convert to PIM-eligible assignments, keeping only the emergency accounts permanent.", perma, warn=True),
            INFO("PRV-002", "roles", "Permanent critical-role assignments",
                 f"{len(perma)} found.", sample(perma)) if perma else PASS("PRV-002", "roles", "No permanent critical-role assignments")]


# --------------------------------------------------------------------------- application risk
@check("apps", needs=("Application.Read.All",))
def app_registration_risk(ctx: Ctx):
    """App registration risk (redirect URIs, multi-tenant exposure, ownership)"""
    apps = ctx.g.get_all("/applications", {"$select": "id,displayName,signInAudience,web,spa,publicClient,requiredResourceAccess",
                                            "$expand": "owners($select=id,userPrincipalName,userType)", "$top": "100"}, limit=ctx.args.max_users)
    label = lambda a: ref(a.get("displayName"), a.get("id"))
    insecure, multi, noown, guestown = [], [], [], []
    for a in apps:
        uris = [u for u in _l(_d(a.get("web")).get("redirectUris")) + _l(_d(a.get("spa")).get("redirectUris")) if isinstance(u, str)]
        bad = [u for u in uris if str(u).lower().startswith("http://") and "localhost" not in str(u).lower() and "127.0.0.1" not in str(u)]
        bad += [u for u in uris if "*" in str(u)]
        if bad:
            insecure.append(f"{label(a)}: {', '.join(bad[:3])}")
        if a.get("signInAudience") in ("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount", "PersonalMicrosoftAccount") and a.get("requiredResourceAccess"):
            multi.append(label(a))
        owners = [o for o in _l(a.get("owners")) if isinstance(o, dict)]
        if not owners:
            noown.append(label(a))
        if any((o.get("userType") == "Guest") for o in owners):
            guestown.append(label(a))
    return [
        verdict("APP-030", "apps", "App registrations use HTTPS redirect URIs without wildcards", not insecure, "high",
                "Plain-HTTP or wildcard redirect URIs allow token interception or open-redirect abuse.", "Use exact HTTPS redirect URIs.", insecure),
        verdict("APP-031", "apps", "App registrations that request permissions are single-tenant", not multi, "low",
                "Multi-tenant registrations are reachable from other tenants.", "Set sign-in audience to this organisation only unless external use is intended.", multi, warn=True),
        verdict("APP-032", "apps", "Every app registration has an owner", not noown, "low",
                "Ownerless apps have nobody accountable for credentials and permissions.", "Assign at least two owners.", noown, warn=True),
        verdict("APP-033", "apps", "No app registration is owned by a guest", not guestown, "medium",
                "A guest owner can add credentials to the app.", "Make internal users the owners.", guestown),
    ]


# --------------------------------------------------------------------------- legacy sign-in evidence
@check("signins", needs=("AuditLog.Read.All",))
def legacy_signins(ctx: Ctx):
    """Evidence of legacy-authentication sign-ins in the sign-in log"""
    since = (ctx.now - __import__("datetime").timedelta(days=LEGACY_LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        rows = ctx.g.get_all("/auditLogs/signIns", {"$filter": f"createdDateTime ge {since} and status/errorCode eq 0", "$top": "200"}, limit=1000)
    except GraphError as e:
        raise SkipCheck(f"Sign-in logs are unreadable ({e.message[:120]}). They need AuditLog.Read.All and Entra ID P1.")
    legacy = {}
    for r in rows:
        if _text(r.get("clientAppUsed")) in LEGACY_CLIENTS:
            legacy.setdefault(_text(r.get("userPrincipalName")) or "?", set()).add(r.get("clientAppUsed"))
    ev = [f"{u}: {', '.join(sorted(c))}" for u, c in sorted(legacy.items())]
    return [verdict("LEG-001", "signins", f"No successful legacy-authentication sign-ins in the last {LEGACY_LOOKBACK_DAYS} days", not legacy, "high",
                    f"{len(legacy)} accounts signed in successfully with legacy protocols (these bypass MFA).",
                    "Block legacy authentication with Conditional Access after moving these clients to modern authentication.", ev)]


# --------------------------------------------------------------------------- guests and partners
@check("tenant", needs=("Policy.Read.All",))
def partner_tenants(ctx: Ctx):
    """Cross-tenant partner configurations"""
    try:
        partners = ctx.g.get_all("/policies/crossTenantAccessPolicy/partners")
    except GraphError as e:
        raise SkipCheck(f"Partner configurations are unreadable ({e.message[:120]}).")
    no_trust, open_inbound = [], []
    for p in partners:
        tid = p.get("tenantId", "?")
        trust = _d(p.get("inboundTrust"))
        if not trust.get("isMfaAccepted"):
            no_trust.append(tid)
        b2b = _d(_d(p.get("b2bCollaborationInbound")).get("usersAndGroups"))
        if any(t.get("target") == "AllUsers" for t in _l(b2b.get("targets")) if isinstance(t, dict)) and b2b.get("accessType") == "allowed":
            open_inbound.append(tid)
    return [INFO("GST-001", "tenant", "Partner organisations with specific cross-tenant settings", f"{len(partners)} partner configurations.",
                 sample([str(p.get("tenantId")) for p in partners])),
            verdict("GST-002", "tenant", "Partner tenants do not get blanket inbound B2B access", not open_inbound, "low",
                    "These partners may bring all of their users in as guests.", "Limit inbound B2B collaboration to named users/groups.", open_inbound, warn=True)]


# --------------------------------------------------------------------------- authentication strengths and registration campaign
@check("authn", needs=("Policy.Read.All",))
def auth_strengths(ctx: Ctx):
    """Custom authentication strengths"""
    out = []
    try:
        strengths = ctx.g.get_all("/policies/authenticationStrengthPolicies")
    except GraphError as e:
        strengths = None
        out.append(INFO("AUT-001", "authn", "Authentication strengths not evaluated", e.message[:140]))
    if strengths is not None:
        weak = [ref(s.get("displayName"), s.get("id")) for s in strengths if s.get("policyType") == "custom"
                and any(m in WEAK_STRENGTH_METHODS or "sms" in str(m).lower() for m in _l(s.get("allowedCombinations")))]
        out.append(verdict("AUT-001", "authn", "Custom authentication strengths exclude SMS, voice and e-mail", not weak, "medium",
                           "A custom strength permits weak, phishable methods.", "Remove SMS/voice/email/TAP combinations from custom strengths.", weak, warn=True))
    return out
