"""CIS recommendations that Microsoft Graph cannot read with an app-only token.

They are listed in every report as MANUAL (never PASS) so the audit is complete: you can see exactly which CIS
Entra recommendations were verified automatically and which need a person to look. Each entry says where to look.
"""
from __future__ import annotations

from ..context import Ctx
from ..models import MANUAL, check

C = "manual"

# (id, title, why it is manual, where to check / what good looks like)
ITEMS = [
    ("MAN-001", "'Per-user MFA' is disabled for all users (CIS 5.1.2.1)",
     "Per-user MFA state is not exposed by Microsoft Graph v1.0. It overrides Conditional Access and makes policies harder to reason about.",
     "Entra admin center > Users > Per-user MFA: every user should show 'Disabled' (MFA enforced by Conditional Access instead)."),
    ("MAN-002", "Access to the Entra admin center is restricted for non-admins (CIS 5.1.2.4)",
     "The 'Restrict access to Microsoft Entra admin center' switch has no Graph v1.0 endpoint.",
     "Entra admin center > Users > User settings > 'Restrict access to Microsoft Entra admin center' = Yes."),
    ("MAN-003", "The 'Stay signed in?' prompt is hidden (CIS 5.1.2.5)",
     "Company branding's 'show option to remain signed in' is not read by this scanner.",
     "Entra admin center > Company branding > Default sign-in experience > 'Show option to remain signed in' = No."),
    ("MAN-004", "LinkedIn account connections are disabled (CIS 5.1.2.6)",
     "There is no Graph v1.0 endpoint for this user setting.",
     "Entra admin center > Users > User settings > LinkedIn account connections = No."),
    ("MAN-005", "Collaboration invitations are sent to allowed domains only (CIS 5.1.6.1)",
     "The external-collaboration allow/deny list is not exposed by Graph v1.0.",
     "Entra admin center > External Identities > External collaboration settings > Collaboration restrictions = 'Allow invitations only to the specified domains'."),
    ("MAN-006", "Password hash sync is enabled for hybrid deployments (CIS 5.1.8.1)",
     "The only Graph endpoint (/directory/onPremisesSynchronization) supports delegated Global Administrator access only; Microsoft documents application permissions as not supported.",
     "Entra admin center > Entra Connect > Connect Sync > 'Password hash sync' = Enabled, or run Get-MgDirectoryOnPremiseSynchronization as a Global Administrator and check passwordSyncEnabled. Skip if you have no hybrid identity."),
    ("MAN-007", "Self-service password reset is enabled for 'All' (CIS 5.2.4.1)",
     "The SSPR scope setting is not available in Graph v1.0.",
     "Entra admin center > Protection > Password reset > Properties > Self service password reset enabled = All."),
    ("MAN-008", "Emergency-access accounts are excluded from Conditional Access and monitored (CIS 1.1.2)",
     "The scanner can find likely break-glass accounts (ADM-009) but cannot know whether you alert on their use.",
     "Confirm two cloud-only accounts exist, are excluded from at least one policy so they cannot be locked out, use FIDO2/long passwords stored offline, and every sign-in triggers an alert."),
]


@check("manual")
def manual_items(ctx: Ctx):
    """CIS recommendations that need a person to verify"""
    return [MANUAL(i, C, title, why, fix) for i, title, why, fix in ITEMS]
