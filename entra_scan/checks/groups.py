"""Groups (GRP-*): guest-targeting dynamic group, who may create Microsoft 365 groups, and public groups.

CIS references are to the CIS Microsoft 365 Foundations Benchmark v5.0.0 (5.1.3.1 and 1.2.1).
"""
from __future__ import annotations

import re

from ..context import Ctx
from ..models import check, ref, sample, verdict

C = "groups"
MAX_GROUPS = 2000
MAX_M365_GROUPS = 20000             # GRP-003 reads all Microsoft 365 groups (public and private), so it needs a higher cap
# user.userType -eq "Guest"  (any spacing / casing)
GUEST_RULE = re.compile(r'user\.usertype\s*-eq\s*"guest"', re.IGNORECASE)


@check("groups", needs=("Directory.Read.All",))
def dynamic_guest_group(ctx: Ctx):
    """A dynamic group containing all guest users exists"""
    groups = ctx.g.get_all("/groups", {"$filter": "groupTypes/any(c:c eq 'DynamicMembership')",
                                       "$select": "id,displayName,membershipRule", "$top": "999"}, limit=MAX_GROUPS)
    matching = [ref(g.get("displayName"), g.get("id")) for g in groups if GUEST_RULE.search(str(g.get("membershipRule") or ""))]
    return [verdict("GRP-001", C, "A dynamic group for guest users exists", bool(matching), "low",
                    f"None of {len(groups)} dynamic groups has the rule (user.userType -eq \"Guest\").",
                    "Create a dynamic user group with the rule (user.userType -eq \"Guest\") and use it to target guest policies.", warn=True)]


@check("groups", needs=("Directory.Read.All",))
def group_creation(ctx: Ctx):
    """Who may create Microsoft 365 groups"""
    unified = next((s for s in ctx.group_settings() if s.get("displayName") == "Group.Unified"), None)
    values = {v.get("name"): v.get("value") for v in (unified or {}).get("values", []) if isinstance(v, dict)}
    restricted = str(values.get("EnableGroupCreation", "true")).lower() == "false"
    return [verdict("GRP-002", C, "Microsoft 365 group creation is restricted to a managed group", restricted, "low",
                    "Every user can create Microsoft 365 groups (and therefore Teams and SharePoint sites): sprawl and unmanaged sharing.",
                    "Set EnableGroupCreation = false and name a security group of approved creators (GroupCreationAllowedGroupId).", warn=True)]


@check("groups", needs=("Directory.Read.All",))
def public_groups(ctx: Ctx):
    """Public Microsoft 365 groups"""
    # visibility does not support $filter (Graph answers 400 Request_UnsupportedQuery), so read every Microsoft 365 group and filter here.
    groups = ctx.g.get_all("/groups", {"$filter": "groupTypes/any(c:c eq 'Unified')",
                                       "$select": "id,displayName,visibility", "$top": "999"}, limit=MAX_M365_GROUPS)
    names = [ref(g.get("displayName"), g.get("id")) for g in groups if str(g.get("visibility") or "").lower() == "public"]
    return [verdict("GRP-003", C, "Only organisationally approved public Microsoft 365 groups exist", not names, "low",
                    f"{len(names)} public Microsoft 365 groups: anyone in the organisation can join and read their content.",
                    "Review each group; make it private unless it is meant for everyone.", sample(names), warn=True)]
