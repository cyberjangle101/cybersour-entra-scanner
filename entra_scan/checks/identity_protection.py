"""Identity Protection (IDP-*): users Microsoft currently considers compromised or at risk. Needs Entra ID P2."""
from __future__ import annotations

from ..context import Ctx
from ..models import check, ref, sample, verdict

C = "idp"


@check("idp", needs=("IdentityRiskyUser.Read.All",))
def risky_users(ctx: Ctx):
    """Identity Protection: users currently at risk"""
    risky = ctx.g.get_all("/identityProtection/riskyUsers", {"$filter": "riskState eq 'atRisk'", "$top": "100"}, limit=500)
    high = [ref(u.get("userPrincipalName"), u.get("id")) for u in risky if u.get("riskLevel") == "high"]
    medium = [ref(u.get("userPrincipalName"), u.get("id")) for u in risky if u.get("riskLevel") == "medium"]
    return [verdict("IDP-001", C, "No users are at high risk", not high, "critical",
                    f"{len(high)} users flagged high risk and not remediated.",
                    "Investigate, revoke sessions, force a password reset and MFA re-registration.", sample(high)),
            verdict("IDP-002", C, "No users are at medium risk", not medium, "medium",
                    f"{len(medium)} users flagged medium risk.", "Triage and remediate or dismiss.", sample(medium), warn=True)]
