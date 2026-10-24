"""Identity governance (GOV-*, PIM-*): just-in-time admin access, access reviews and PIM activation rules.

CIS references are to the CIS Microsoft 365 Foundations Benchmark v5.0.0 (5.3.1 to 5.3.5).
PIM and access reviews need Entra ID P2 or Entra ID Governance; without them these checks report SKIPPED, never PASS.
"""
from __future__ import annotations

import json

from ..context import Ctx
from ..models import INFO, WARN, PASS, GraphError, SkipCheck, check, verdict
from .privileged import load_admins

C = "governance"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
PRIVILEGED_ROLE_ADMIN = "e8611ab8-c189-46e8-94e1-60213ab1f814"


@check("governance", needs=("RoleManagement.Read.Directory",))
def pim_usage(ctx: Ctx):
    """Privileged Identity Management: are admin roles eligible (just-in-time) rather than permanent?"""
    # "Eligible" means the person must activate the role (just in time) instead of holding it permanently.
    # An empty list can also mean PIM is not licensed, so the message below says so rather than claiming a hard failure.
    eligible = ctx.g.get_all("/roleManagement/directory/roleEligibilityScheduleInstances", {"$top": "200"})
    permanent = len(load_admins(ctx))
    if eligible:
        return [PASS("PIM-001", C, "Privileged Identity Management is used to manage roles",
                     f"{len(eligible)} eligible assignments, {permanent} privileged principals with standing access.")]
    return [WARN("PIM-001", C, "Privileged Identity Management is used to manage roles", "medium",
                 f"{permanent} privileged principals have standing access and none use just-in-time elevation (or PIM is not licensed).",
                 "Adopt PIM (Entra ID P2 / Governance): make admin roles eligible with MFA, approval and a maximum duration.")]


@check("governance", needs=("AccessReview.Read.All",))
def access_reviews(ctx: Ctx):
    """Access reviews for guest users and for privileged roles"""
    # We search each review's scope text for "guest" or for directory-role endpoints, because the scope is a free-form query string.
    definitions = ctx.g.get_all("/identityGovernance/accessReviews/definitions")
    text = {d.get("id", i): json.dumps([d.get("scope"), d.get("instanceEnumerationScope")]).lower() for i, d in enumerate(definitions)}
    guest = [d.get("displayName", "?") for i, d in enumerate(definitions) if "guest" in text[d.get("id", i)]]
    roles = [d.get("displayName", "?") for i, d in enumerate(definitions)
             if any(k in text[d.get("id", i)] for k in ("roleassignmentscheduleinstances", "roleeligibilityscheduleinstances", "/rolemanagement/"))]
    none_exist = "No access reviews are configured." if not definitions else f"{len(definitions)} access reviews exist"
    return [
        verdict("GOV-001", C, "A recurring access review covers guest users", bool(guest), "medium",
                none_exist + ("; none target guests." if definitions else ""),
                "Create a recurring access review of guest users and of Microsoft 365 groups / Teams that have guests (needs Entra ID Governance or P2)."),
        verdict("GOV-002", C, "A recurring access review covers privileged roles", bool(roles), "medium",
                none_exist + ("; none target privileged roles." if definitions else ""),
                "Create an access review of privileged role assignments (Entra roles) with a quarterly or shorter cadence."),
    ]


def _role_rules(ctx: Ctx, role_id):
    """{rule id: rule} of the PIM policy for one Entra role, or None if PIM policies are unreadable."""
    try:
        res = ctx.g.get("/policies/roleManagementPolicyAssignments", {
            "$filter": f"scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '{role_id}'",
            "$expand": "policy($expand=rules)"})
    except GraphError as e:
        if e.status in (400, 403, 404):
            return None
        raise
    rows = res.get("value") or []
    rules = ((rows[0].get("policy") or {}).get("rules") or []) if rows else []
    return {r.get("id"): r for r in rules if isinstance(r, dict)}


@check("governance", needs=("RoleManagementPolicy.Read.Directory",))
def pim_role_settings(ctx: Ctx):
    """PIM activation rules for Global Administrator and Privileged Role Administrator"""
    out = []
    for role_name, role_id, approval_id, mfa_id in (
            ("Global Administrator", GLOBAL_ADMIN, "GOV-003", "GOV-005"),
            ("Privileged Role Administrator", PRIVILEGED_ROLE_ADMIN, "GOV-004", None)):
        rules = _role_rules(ctx, role_id)
        if rules is None:
            raise SkipCheck("PIM role settings are unreadable (needs RoleManagementPolicy.Read.Directory and Entra ID P2).")
        approval = (rules.get("Approval_EndUser_Assignment") or {}).get("setting") or {}
        out.append(verdict(approval_id, C, f"Approval is required to activate {role_name}", approval.get("isApprovalRequired") is True, "medium",
                           f"isApprovalRequired = {approval.get('isApprovalRequired')} on the {role_name} PIM policy.",
                           f"In PIM > Roles > {role_name} > Role settings, turn on 'Require approval to activate' and name approvers."))
        if mfa_id:
            enabled = (rules.get("Enablement_EndUser_Assignment") or {}).get("enabledRules") or []
            auth_context = (rules.get("AuthenticationContext_EndUser_Assignment") or {}).get("isEnabled") is True
            out.append(verdict(mfa_id, C, f"MFA (or an authentication context) is required to activate {role_name}",
                               "MultiFactorAuthentication" in enabled or auth_context, "medium",
                               f"enabledRules = {enabled}; authentication context enabled = {auth_context}.",
                               "Require Azure MFA (or a Conditional Access authentication context) on activation."))
    return out
