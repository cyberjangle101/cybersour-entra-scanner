"""Users (USR-*): MFA registration coverage, stale accounts, guests and password flags.

CIS references are to the CIS Microsoft 365 Foundations Benchmark v5.0.0 (5.2.3.4 'MFA capable').
"""
from __future__ import annotations

from ..context import Ctx
from ..models import INFO, Finding, SkipCheck, check, parse_time as _t, ref, sample, verdict

C = "users"
STALE_USER_DAYS = 90
STALE_GUEST_DAYS = 180
PENDING_GUEST_DAYS = 30
# Methods an attacker can intercept or socially engineer: text/voice/email. A user who only has these is weakly protected.
WEAK_METHODS = {"mobilePhone", "alternateMobilePhone", "officePhone", "email"}


@check("users", needs=("AuditLog.Read.All",))
def mfa_registration(ctx: Ctx):
    """MFA registration coverage"""
    rows = [r for r in ctx.registration_details() if r.get("userType") == "member"]
    if not rows:
        return [INFO("USR-001", C, "No member registration data returned")]
    upn = lambda r: ref(r.get("userPrincipalName"), r.get("id"))
    registered = [r for r in rows if r.get("isMfaRegistered")]
    pct = 100 * len(registered) / len(rows)
    missing = [upn(r) for r in rows if not r.get("isMfaRegistered")]
    out = [verdict("USR-001", C, "All member users are registered for MFA", not missing, "high" if pct < 80 else "medium",
                   f"{len(registered)}/{len(rows)} members registered ({pct:.1f}%).",
                   "Run a registration campaign; enforce registration with Conditional Access.", sample(missing))]
    weak = [upn(r) for r in registered if set(r.get("methodsRegistered") or []) <= WEAK_METHODS]
    out.append(verdict("USR-002", C, "No users rely only on SMS / voice / email for MFA", not weak, "low",
                       f"{len(weak)} users have only phone- or email-based methods (phishable, SIM-swap risk).",
                       "Move users to Authenticator (number matching) or passkeys / FIDO2.", sample(weak), warn=True))
    passwordless = sum(1 for r in rows if r.get("isPasswordlessCapable"))
    out.append(INFO("USR-003", C, "Passwordless capability", f"{passwordless}/{len(rows)} members are passwordless-capable."))
    # USR-004 (CIS 5.2.3.4): 'MFA capable' is stricter than 'registered': the user has a method the tenant's policy actually allows.
    incapable = [upn(r) for r in rows if r.get("isMfaCapable") is False]
    out.append(verdict("USR-004", C, "All member users are MFA capable", not incapable, "high" if pct < 80 else "medium",
                       f"{len(incapable)} members have no usable MFA method under the current authentication-methods policy.",
                       "Have these users register a method the policy allows (Authenticator, passkey, FIDO2).", sample(incapable)))
    return out


@check("users", needs=("User.Read.All", "AuditLog.Read.All"))
def user_hygiene(ctx: Ctx):
    """Stale accounts, guests and weak-password flags"""
    users = ctx.users()
    out = []
    if ctx.signin_available:
        stale = []
        for u in users:
            if u.get("userType") != "Member" or not u.get("accountEnabled"):
                continue
            last = ctx.last_seen(u)
            created = ctx.age_days(_t(u.get("createdDateTime")))
            idle = ctx.age_days(last) if last else created      # never signed in: measure from creation
            if idle is not None and idle > STALE_USER_DAYS:
                stale.append(f"{ref(u.get('userPrincipalName'), u.get('id'))} ({'never signed in' if not last else str(idle) + 'd idle'})")
        pct = 100 * len(stale) / max(len(users), 1)
        out.append(verdict("USR-010", C, f"Enabled member accounts active in the last {STALE_USER_DAYS} days", not stale,
                           "medium" if pct > 5 else "low", f"{len(stale)} enabled members are inactive or have never signed in.",
                           "Disable or delete dormant accounts; automate with access reviews or lifecycle workflows.", sample(stale)))
    else:
        out.append(Finding("USR-010", C, "Stale account detection", "SKIPPED", "info",
                           "signInActivity is unavailable (needs AuditLog.Read.All and Entra ID P1)."))

    guests = [u for u in users if u.get("userType") == "Guest"]
    pending = [ref(u.get("userPrincipalName"), u.get("id")) for u in guests if u.get("externalUserState") == "PendingAcceptance"
               and (ctx.age_days(_t(u.get("externalUserStateChangeDateTime"))) or 0) > PENDING_GUEST_DAYS]
    out.append(INFO("USR-011", C, "Guest accounts", f"{len(guests)} guests of {len(users)} users."))
    out.append(verdict("USR-012", C, f"No guest invitations pending more than {PENDING_GUEST_DAYS} days", not pending, "low",
                       "Old unaccepted invitations.", "Delete stale pending guests; use access reviews.", sample(pending), warn=True))
    weak_pwd = [ref(u.get("userPrincipalName"), u.get("id")) for u in users if "DisableStrongPassword" in (u.get("passwordPolicies") or "")]
    out.append(verdict("USR-013", C, "No accounts have the strong-password requirement disabled", not weak_pwd, "high",
                       "DisableStrongPassword is set on these accounts.", "Clear the flag: Update-MgUser -PasswordPolicies None.", sample(weak_pwd)))
    disabled_lic = [ref(u.get("userPrincipalName"), u.get("id")) for u in users if u.get("accountEnabled") is False and u.get("assignedLicenses")]
    out.append(verdict("USR-014", C, "Disabled accounts are unlicensed", not disabled_lic, "low",
                       "Disabled users still consume licences and may keep mailbox data.",
                       "Remove licences (convert mailboxes to shared / archive) as part of offboarding.", sample(disabled_lic), warn=True))
    return out


@check("users", needs=("User.Read.All", "AuditLog.Read.All"))
def user_staleness(ctx: Ctx):
    """Licensed accounts and guests that stopped signing in"""
    users = ctx.users()
    if not ctx.signin_available:
        raise SkipCheck("signInActivity is unavailable (needs AuditLog.Read.All and Entra ID P1).")
    licensed_idle, guest_idle = [], []
    for u in users:
        last = ctx.last_seen(u)
        idle = ctx.age_days(last) if last else ctx.age_days(_t(u.get("createdDateTime")))
        if idle is None:
            continue
        label = f"{ref(u.get('userPrincipalName'), u.get('id'))} ({'never signed in' if not last else str(idle) + 'd idle'})"
        if u.get("userType") == "Member" and u.get("accountEnabled") and u.get("assignedLicenses") and idle > STALE_USER_DAYS:
            licensed_idle.append(label)
        if u.get("userType") == "Guest" and idle > STALE_GUEST_DAYS:
            guest_idle.append(label)
    return [
        verdict("USR-015", C, f"Licensed members are active (none idle more than {STALE_USER_DAYS} days)", not licensed_idle, "medium",
                f"{len(licensed_idle)} licensed, enabled accounts are idle: wasted licences and an easy takeover target.",
                "Reclaim licences and disable or delete the accounts; automate with lifecycle workflows.", sample(licensed_idle)),
        verdict("USR-016", C, f"Guest accounts are active (none idle more than {STALE_GUEST_DAYS} days)", not guest_idle, "medium",
                f"{len(guest_idle)} guests have not signed in for {STALE_GUEST_DAYS}+ days (or never) but may still reach Teams, sites and files.",
                "Run access reviews on guests and groups; delete dormant guests.", sample(guest_idle)),
    ]

