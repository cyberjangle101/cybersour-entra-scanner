"""Tenant settings (TEN-*, XTA-*, DOM-*): who may invite guests, consent to apps, create tenants; domains; cross-tenant defaults.

CIS references are to the CIS Microsoft 365 Foundations Benchmark v5.0.0 (5.1.2.x, 5.1.5.x, 5.1.6.x, 1.3.1).
"""
from __future__ import annotations

from ..context import Ctx
from ..models import FAIL, INFO, PASS, WARN, GraphError, check, verdict

C = "tenant"
GUEST_SAME_AS_MEMBERS = "a0b1b346-4d3e-4e8b-98f8-753987be4970"
GUEST_ROLES = {GUEST_SAME_AS_MEMBERS: "same access as members", "10dae51f-b6af-4016-8d66-8c2a99b929b3": "limited access (default)",
               "2af84b1e-32c8-42b7-82bc-daa82404023b": "restricted access"}
NEVER_EXPIRES = 2147483647            # Graph's "passwords never expire" marker


@check("tenant", needs=("Policy.Read.All",))
def authorization_policy(ctx: Ctx):
    """Authorization policy: guests, user consent, tenant/app/group creation"""
    p = ctx.authorization_policy()
    defaults = p.get("defaultUserRolePermissions") or {}
    out = []

    # TEN-001 (CIS 5.1.6.3): only admins and Guest Inviters should invite guests.
    inv = p.get("allowInvitesFrom")
    if inv == "everyone":
        out.append(FAIL("TEN-001", C, "Guest invitations are limited to the Guest Inviter role", "medium",
                        "Anyone, including guests, can invite external users.",
                        "Set to 'Only users assigned to specific admin roles' (adminsAndGuestInviters)."))
    elif inv == "adminsGuestInvitersAndAllMembers":
        out.append(WARN("TEN-001", C, "Guest invitations are limited to the Guest Inviter role", "low",
                        "All member users can invite guests (CIS wants admins and Guest Inviters only).",
                        "Set to 'Only users assigned to specific admin roles' (adminsAndGuestInviters)."))
    else:
        out.append(PASS("TEN-001", C, "Guest invitations are limited to the Guest Inviter role", f"allowInvitesFrom = {inv}"))

    # TEN-002 (CIS 5.1.6.2): guests should see only their own objects, not browse the directory.
    role = GUEST_ROLES.get(p.get("guestUserRoleId"), p.get("guestUserRoleId"))
    out.append(verdict("TEN-002", C, "Guests have limited directory access", p.get("guestUserRoleId") != GUEST_SAME_AS_MEMBERS, "high",
                       f"Guests have: {role}.", "Set guest access to 'limited' or 'restricted'."))

    # TEN-003 (CIS 5.1.5.1): user consent to apps.
    # Graph exposes the assigned consent policies under defaultUserRolePermissions; older documentation and some tenants show the
    # top-level permissionGrantPolicyIdsAssignedToDefaultUserRole. Read both so a layout difference cannot hide an open consent policy.
    assigned = (defaults.get("permissionGrantPoliciesAssigned") or p.get("permissionGrantPoliciesAssigned")
                or p.get("permissionGrantPolicyIdsAssignedToDefaultUserRole") or [])
    self_consent = [x for x in assigned if x.startswith("ManagePermissionGrantsForSelf.")]
    if any("microsoft-user-default-legacy" in x for x in self_consent):
        out.append(FAIL("TEN-003", C, "Users cannot consent to apps accessing company data", "high",
                        "Users can consent to any app's permissions (illicit consent grant risk).",
                        "Disable user consent, or restrict to verified publishers and low-risk permissions, and enable the admin consent workflow."))
    elif self_consent:
        out.append(WARN("TEN-003", C, "Users cannot consent to apps accessing company data", "low",
                        f"Users may consent to some apps ({', '.join(self_consent)}). CIS expects user consent to be off.",
                        "Set 'Do not allow user consent' and route requests through the admin consent workflow."))
    else:
        out.append(PASS("TEN-003", C, "Users cannot consent to apps accessing company data"))

    # TEN-012: a policy flag that lets users consent to apps Microsoft rates as risky.
    out.append(verdict("TEN-012", C, "Users cannot consent to apps Microsoft flags as risky", p.get("allowUserConsentForRiskyApps") is not True, "high",
                       "allowUserConsentForRiskyApps is true.", "Set allowUserConsentForRiskyApps to false."))

    out.append(verdict("TEN-004", C, "Non-admin users cannot create tenants", not defaults.get("allowedToCreateTenants"), "medium",
                       "Any user can create new Entra tenants.", "Set 'Restrict non-admin users from creating tenants' to Yes."))
    out.append(verdict("TEN-005", C, "Users cannot register applications (third-party integrated apps)", not defaults.get("allowedToCreateApps"), "low",
                       "Any user can register apps (and become their owner).", "Set 'Users can register applications' to No; use the Application Developer role.", warn=True))
    out.append(verdict("TEN-006", C, "Email-verified self-service join is disabled", not p.get("allowEmailVerifiedUsersToJoinOrganization"), "medium",
                       "Users with a verified email at your domain can join the tenant uninvited.", "Set allowEmailVerifiedUsersToJoinOrganization = false."))
    out.append(verdict("TEN-007", C, "Legacy MSOnline PowerShell is blocked", bool(p.get("blockMsolPowerShell")), "low",
                       "The deprecated MSOnline module is still allowed.", "Set blockMsolPowerShell = true.", warn=True))
    try:
        consent_policy = ctx.g.get("/policies/adminConsentRequestPolicy")
        # TEN-008 (CIS 5.1.5.2)
        out.append(verdict("TEN-008", C, "Admin consent request workflow is enabled", consent_policy.get("isEnabled"), "medium",
                           "Users have no sanctioned way to request app access.", "Enable the admin consent workflow with named reviewers."))
    except GraphError:
        out.append(INFO("TEN-008", C, "Admin consent workflow not evaluated", "adminConsentRequestPolicy could not be read."))
    out.append(verdict("TEN-010", C, "Users cannot create security groups", not defaults.get("allowedToCreateSecurityGroups"), "low",
                       "Any user can create security groups (sprawl, and groups that can later gain access).",
                       "Disable 'Users can create security groups' in Entra group settings.", warn=True))
    # TEN-011: BitLocker recovery keys let someone read a disk. Only admins should be able to fetch them.
    out.append(verdict("TEN-011", C, "Users cannot read BitLocker recovery keys for their own devices",
                       defaults.get("allowedToReadBitlockerKeysForOwnedDevice") is False, "low",
                       "Any user can read the BitLocker recovery key of devices they own.",
                       "Set 'Restrict users from recovering the BitLocker keys for their owned devices' to Yes.", warn=True))
    return out


@check("tenant", needs=("Policy.Read.All",))
def cross_tenant_access(ctx: Ctx):
    """Cross-tenant access defaults for B2B collaboration"""
    d = ctx.g.get("/policies/crossTenantAccessPolicy/default")
    inbound = d.get("b2bCollaborationInbound") or {}
    users = (inbound.get("usersAndGroups") or {}).get("accessType")
    apps = (inbound.get("applications") or {}).get("accessType")
    trust = d.get("inboundTrust") or {}
    open_inbound = users == "allowed" and apps == "allowed"
    return [
        verdict("XTA-001", C, "Default inbound B2B collaboration is not open to every external tenant", not open_inbound, "low",
                "The default allows users from any external organisation to collaborate inbound to all your apps.",
                "Block B2B inbound by default and allow specific partner organisations in Cross-tenant access settings > Organizational settings.", warn=True),
        INFO("XTA-002", C, "Inbound trust of external MFA / device claims",
             f"MFA accepted: {trust.get('isMfaAccepted')}, compliant device accepted: {trust.get('isCompliantDeviceAccepted')}, "
             f"hybrid-joined accepted: {trust.get('isHybridAzureADJoinedDeviceAccepted')}. "
             "Accepting MFA claims avoids double prompts but trusts the partner's MFA policy."),
    ]


@check("tenant", needs=("Directory.Read.All",))
def domains_check(ctx: Ctx):
    """Domain verification, federation and password expiry"""
    domains = ctx.domains()
    domains = [d for d in domains if d.get("id")]
    unverified = [d["id"] for d in domains if not d.get("isVerified")]
    federated = [d["id"] for d in domains if d.get("authenticationType") == "Federated"]
    # DOM-003 (CIS 1.3.1): forced rotation encourages predictable passwords; NIST and CIS advise 'never expire' when MFA is in place.
    expiring = [f"{d['id']} ({d.get('passwordValidityPeriodInDays')}d)" for d in domains
                if d.get("isVerified") and d.get("passwordValidityPeriodInDays") not in (None, NEVER_EXPIRES)]
    return [
        verdict("DOM-001", C, "No unverified domains left in the tenant", not unverified, "low",
                "Unverified domains were added but never completed.", "Remove unused unverified domains.", unverified, warn=True),
        INFO("DOM-002", C, "Federated domains",
             "Federated authentication shifts trust to your identity provider (AD FS or third party): protect it as Tier 0.", federated),
        verdict("DOM-003", C, "Passwords are set to never expire", not expiring, "low",
                "Forced periodic rotation encourages predictable passwords (NIST SP 800-63B and CIS advise against it).",
                "Set the password expiration policy to 'never expire' once MFA and banned-password protection are in place.", expiring, warn=True),
    ]
