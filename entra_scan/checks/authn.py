"""Authentication methods and password protection (AUTH-*, PWD-*).

Which sign-in methods users may use, how resistant they are to phishing and MFA-fatigue attacks, and how passwords
are screened.  CIS references are to the CIS Microsoft 365 Foundations Benchmark v5.0.0 (5.2.3.x).
"""
from __future__ import annotations

from ..context import Ctx
from ..models import INFO, check, verdict

C = "authn"
MAX_LOCKOUT_THRESHOLD = 10          # Microsoft's default; a higher value lets attackers guess more passwords per lockout window


@check("authn", needs=("Policy.Read.All",))
def auth_methods(ctx: Ctx):
    """Authentication methods policy (Authenticator, SMS/voice, FIDO2, email OTP)"""
    state = {name: cfg.get("state") for name, cfg in ctx.auth_method_configs().items()}
    policy = ctx.auth_methods_policy()
    out = [
        verdict("AUTH-001", C, "Microsoft Authenticator enabled", state.get("MicrosoftAuthenticator") == "enabled", "medium",
                "Authenticator is not enabled for sign-in / MFA.", "Enable Authenticator with number matching and context."),
        # CIS 5.2.3.5: weak methods (SMS, voice, email) should be off.
        verdict("AUTH-002", C, "SMS and voice authentication methods disabled", state.get("Sms") != "enabled" and state.get("Voice") != "enabled", "low",
                f"SMS={state.get('Sms')}, Voice={state.get('Voice')}: phishable and vulnerable to SIM swap.",
                "Disable SMS/voice for admins first, then for everyone once Authenticator or passkeys are rolled out.", warn=True),
        verdict("AUTH-003", C, "FIDO2 / passkeys enabled", state.get("Fido2") == "enabled", "low",
                "No phishing-resistant method is available to users.", "Enable FIDO2 / passkeys, at least for admins.", warn=True),
    ]
    campaign = ((policy.get("registrationEnforcement") or {}).get("authenticationMethodsRegistrationCampaign") or {}).get("state")
    out.append(verdict("AUTH-004", C, "Registration campaign enabled", campaign == "enabled", "low",
                       f"Registration campaign state: {campaign}.", "Enable the campaign to nudge users onto Authenticator.", warn=True))
    # AUTH-006 (CIS 5.2.3.6): users are offered their most secure registered method first.
    preferred = (policy.get("systemCredentialPreferences") or {}).get("state")
    out.append(verdict("AUTH-006", C, "System-preferred multifactor authentication is enabled", preferred == "enabled", "low",
                       f"systemCredentialPreferences.state = {preferred}. Users may be prompted with a weaker method than they have registered.",
                       "Set system-preferred MFA to Enabled for all users.", warn=True))
    # AUTH-007: email one-time passcode is a weak, phishable factor (CIS 5.2.3.5 lists it among weak methods).
    out.append(verdict("AUTH-007", C, "Email one-time passcode method disabled", state.get("Email") != "enabled", "low",
                       f"Email OTP state = {state.get('Email')}. A mailbox compromise then becomes an MFA bypass.",
                       "Disable the Email method in the authentication methods policy.", warn=True))
    return out


@check("authn", needs=("Policy.Read.All",))
def authenticator_settings(ctx: Ctx):
    """Microsoft Authenticator number matching and app context (MFA-fatigue protection)"""
    config = ctx.auth_method_configs().get("MicrosoftAuthenticator") or {}
    if config.get("state") != "enabled":
        return [INFO("AUTH-005", C, "Authenticator not enabled; number matching not evaluated")]
    features = config.get("featureSettings") or {}
    setting = lambda k: ((features.get(k) or {}).get("state") or "default")
    number, app, location = (setting("numberMatchingRequiredState"), setting("displayAppInformationRequiredState"),
                             setting("displayLocationInformationRequiredState"))
    ok = all(v in ("enabled", "default") for v in (number, app, location))      # 'default' is on for everyone now
    return [verdict("AUTH-005", C, "Authenticator MFA-fatigue protection (number matching + app/location context)", ok, "medium",
                    f"numberMatching={number}, appContext={app}, locationContext={location}.",
                    "Set number matching, application name and geographic location to Enabled for all users.")]


@check("authn", needs=("Directory.Read.All",))
def password_protection(ctx: Ctx):
    """Password protection: banned-password list, on-premises enforcement, smart lockout"""
    setting = next((s for s in ctx.group_settings() if s.get("displayName") == "Password Rule Settings"), None)
    if not setting:
        return [INFO("PWD-001", C, "Password Protection is at defaults",
                     "No custom banned-password list or lockout settings exist; Microsoft's global banned list still applies. "
                     "CIS expects a custom list (PWD-001) and, for hybrid tenants, enforcement on-premises (PWD-002).")]
    v = {x.get("name"): x.get("value") for x in setting.get("values", []) if isinstance(x, dict)}
    custom_list = v.get("EnableBannedPasswordCheck") == "True" and bool(str(v.get("BannedPasswordList") or "").strip())
    onprem = v.get("EnableBannedPasswordCheckOnPremises") == "True" and v.get("BannedPasswordCheckOnPremisesMode") == "Enforce"
    try:
        threshold = int(v.get("LockoutThreshold", 10))
    except (TypeError, ValueError):
        threshold = 10
    return [
        verdict("PWD-001", C, "Custom banned password list is enabled and populated", custom_list, "low",
                "The custom banned password list is off or empty.", "Enable it and add company, product and location terms.", warn=True),
        verdict("PWD-002", C, "Password protection is enforced for on-premises AD", onprem, "low",
                "On-premises password protection is off or in Audit mode (or not deployed; irrelevant for cloud-only tenants).",
                "Switch to Enforce after reviewing audit results.", warn=True),
        verdict("PWD-003", C, f"Smart lockout threshold is {MAX_LOCKOUT_THRESHOLD} or lower", threshold <= MAX_LOCKOUT_THRESHOLD, "low",
                f"LockoutThreshold = {threshold}: attackers get more guesses per lockout.", f"Set the lockout threshold to {MAX_LOCKOUT_THRESHOLD} or lower.", warn=True),
    ]
