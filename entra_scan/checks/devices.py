"""Device settings (DEV-*): who may join or register devices to the tenant, and how local admin rights are handled.

Source: the tenant-wide device registration policy (Entra admin center > Devices > Device settings).
These are Entra hardening practices; they are not in CIS Microsoft 365 Foundations v5.0.0.
"""
from __future__ import annotations

from ..context import Ctx
from ..models import INFO, check, verdict

C = "devices"
MAX_DEVICES_PER_USER = 20            # Microsoft's default is 50; a user rarely needs more than a handful


def _membership_kind(membership):
    """'all' | 'selected' | 'none' | '?' for a deviceRegistrationMembership object (distinguished by its @odata.type)."""
    kind = str((membership or {}).get("@odata.type", "")).lower()
    if "alldeviceregistrationmembership" in kind:
        return "all"
    if "enumerateddeviceregistrationmembership" in kind:
        return "selected"
    if "nodeviceregistrationmembership" in kind:
        return "none"
    return "?"


@check("devices", needs=("Policy.Read.DeviceConfiguration",))
def device_settings(ctx: Ctx):
    """Device join/registration policy, device limit, MFA to join, local admin rights and LAPS"""
    # One policy object answers all five device checks, so it is read once. A 403 here almost always means the app lacks
    # Policy.Read.DeviceConfiguration (Policy.Read.All is NOT enough for application access to this endpoint).
    policy = ctx.cached("device_policy", lambda: ctx.g.get("/policies/deviceRegistrationPolicy"))
    join = policy.get("azureADJoin") or {}
    register = policy.get("azureADRegistration") or {}
    out = []

    quota = policy.get("userDeviceQuota")
    out.append(verdict("DEV-001", C, f"A user may have at most {MAX_DEVICES_PER_USER} devices", isinstance(quota, int) and quota <= MAX_DEVICES_PER_USER, "low",
                       f"userDeviceQuota = {quota}. A compromised account can enrol many devices.",
                       f"Set 'Maximum number of devices per user' to {MAX_DEVICES_PER_USER} or fewer.", warn=True))

    join_kind, reg_kind = _membership_kind(join.get("allowedToJoin")), _membership_kind(register.get("allowedToRegister"))
    out.append(verdict("DEV-002", C, "Joining devices to Entra is limited to selected users or groups", join_kind in ("selected", "none"), "low",
                       f"Entra join is allowed for: {join_kind}. Any user can join a device to your tenant.",
                       "Restrict 'Users may join devices to Microsoft Entra' to a group (for example IT or Autopilot enrolment).", warn=True))

    laps = (policy.get("localAdminPassword") or {}).get("isEnabled")
    out.append(verdict("DEV-003", C, "Windows LAPS is enabled for Entra-joined devices", laps is True, "medium",
                       f"localAdminPassword.isEnabled = {laps}. Shared or static local admin passwords allow lateral movement.",
                       "Enable 'Microsoft Entra Local Administrator Password Solution (LAPS)' and deploy a LAPS policy.", warn=True))

    mfa = policy.get("multiFactorAuthConfiguration")
    out.append(verdict("DEV-004", C, "MFA is required to join or register devices", mfa == "required", "low",
                       f"multiFactorAuthConfiguration = {mfa}. (A Conditional Access policy on the 'Register or join devices' action is the modern alternative.)",
                       "Require MFA to register or join devices, or use Conditional Access.", warn=True))

    local_admins = join.get("localAdmins")
    if isinstance(local_admins, dict) and "enableGlobalAdmins" in local_admins:
        out.append(verdict("DEV-005", C, "Global Administrators are not local admins on every joined device",
                           local_admins.get("enableGlobalAdmins") is False, "medium",
                           "Every Global Administrator becomes a local administrator on every Entra-joined device.",
                           "Set 'Global administrators local administrator on Microsoft Entra joined devices' to No and use LAPS.", warn=True))
    else:
        out.append(INFO("DEV-005", C, "Global Administrators as local admins not evaluated", "The policy did not expose azureADJoin.localAdmins."))
    return out
