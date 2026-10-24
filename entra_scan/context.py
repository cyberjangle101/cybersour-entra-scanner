"""Shared scan state: the Graph client, user options, a cache, and the tenant-wide data several checks reuse.

Why a cache?  Many checks need the same data (all users, the authentication-methods policy, the role
assignments).  Each is fetched once per scan and shared, which keeps the number of Graph calls (and the
chance of being throttled) low.
"""
from __future__ import annotations

import datetime as dt

from .models import GraphError, one, parse_time

# Authentication methods the AUTH-* checks read (fallback when the policy omits its inline configurations).
AUTH_METHOD_IDS = ("MicrosoftAuthenticator", "Sms", "Voice", "Fido2", "Email")


class Ctx:
    """Everything one scan shares: the Graph client, options, and a cache so each endpoint is read at most once."""
    def __init__(self, graph, args):
        self.g = graph
        self.args = args
        self.now = dt.datetime.now(dt.timezone.utc)      # one clock for the whole scan so ages are consistent
        self._cache = {}
        self.signin_available = True                     # flips to False if signInActivity cannot be read (no P1 / permission)

    # -- generic cache ----------------------------------------------------------------------
    def cached(self, key, loader):
        """Return the value stored under `key`, calling `loader()` the first time only."""
        if key not in self._cache:
            self._cache[key] = loader()
        return self._cache[key]

    def age_days(self, when):
        """Whole days between `when` (a datetime) and the scan start; None if `when` is not a datetime."""
        return (self.now - when).days if isinstance(when, dt.datetime) else None

    # -- tenant-wide data shared by several checks --------------------------------------------
    def tenant_id(self):
        """This tenant's ID (used to tell our own apps from external ones)."""
        return self.cached("tenant_id", lambda: one(self.g.get("/organization", {"$select": "id"}))["id"])

    def organization(self):
        """The tenant's organization object, including hybrid-sync timestamps (Directory.Read.All). {} if unreadable."""
        def load():
            """Loader for the cached value."""
            try:
                return one(self.g.get("/organization", {"$select": "id,displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime,"
                                                                    "onPremisesLastPasswordSyncDateTime"}))
            except GraphError:
                return {}
        return self.cached("organization", load)

    def named_locations(self):
        """Conditional Access named locations, or None if unreadable."""
        def load():
            """Loader for the cached value."""
            try:
                return self.g.get_all("/identity/conditionalAccess/namedLocations")
            except GraphError:
                return None
        return self.cached("named_locations", load)

    def domains(self):
        """All domains in the tenant."""
        return self.cached("domains", lambda: self.g.get_all("/domains"))

    def registration_details(self):
        """Per-user authentication-method registration report (needs AuditLog.Read.All)."""
        return self.cached("reg", lambda: self.g.get_all(
            "/reports/authenticationMethods/userRegistrationDetails", limit=self.args.max_users))

    def registration_by_id(self):
        """MFA registration rows keyed by user id."""
        return self.cached("reg_by_id", lambda: {r["id"]: r for r in self.registration_details() if isinstance(r, dict) and isinstance(r.get("id"), str)})

    def users(self):
        """All users, with last-sign-in data when the tenant allows it (Entra ID P1 + AuditLog.Read.All)."""
        def load():
            """Loader for the cached value."""
            fields = ("id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,assignedLicenses,"
                      "passwordPolicies,externalUserState,externalUserStateChangeDateTime,onPremisesSyncEnabled")
            try:
                return self.g.get_all("/users", {"$select": fields + ",signInActivity", "$top": "120"}, limit=self.args.max_users)
            except GraphError as e:
                if e.status not in (400, 403):
                    raise
                self.signin_available = False            # fall back to a plain user list; stale-account checks will say SKIPPED
                return self.g.get_all("/users", {"$select": fields, "$top": "999"}, limit=self.args.max_users)
        return self.cached("users", load)

    def users_by_id(self):
        """Users keyed by id, so per-admin lookups need no extra requests."""
        return self.cached("users_by_id", lambda: {u["id"]: u for u in self.users() if isinstance(u, dict) and isinstance(u.get("id"), str)})

    def last_seen(self, user):
        """Most recent sign-in (interactive, non-interactive or successful) as a datetime, or None if never / unknown."""
        key = ("seen", user.get("id"))
        if user.get("id") is not None and key in self._cache:          # two checks ask about every user: compute once
            return self._cache[key]
        activity = user.get("signInActivity") or {}
        times = (parse_time(activity.get(k)) for k in
                 ("lastSignInDateTime", "lastNonInteractiveSignInDateTime", "lastSuccessfulSignInDateTime"))
        result = max(filter(None, times), default=None)
        if user.get("id") is not None:
            self._cache[key] = result
        return result

    def auth_methods_policy(self):
        """The tenant-wide authentication methods policy."""
        return self.cached("amp", lambda: self.g.get("/policies/authenticationMethodsPolicy"))

    def auth_method_configs(self):
        """{method id: configuration} e.g. {'Sms': {...state...}, 'MicrosoftAuthenticator': {...}}.

        Graph returns the configurations inside the policy object.  Listing the collection on its own
        (GET .../authenticationMethodConfigurations) is not a supported operation and answers 400 Request_UnsupportedQuery,
        so if the policy ever comes back without them each method the checks use is read by id instead.
        """
        def load():
            """Loader for the cached value."""
            configs = self.auth_methods_policy().get("authenticationMethodConfigurations")
            if not isinstance(configs, list):
                configs = []
                for method in AUTH_METHOD_IDS:
                    try:
                        configs.append(self.g.get(f"/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/{method}"))
                    except GraphError as e:
                        if e.status != 404:                  # 404: method not present in this tenant; anything else is a real failure
                            raise
            return {c["id"]: c for c in configs if isinstance(c, dict) and isinstance(c.get("id"), str)}
        return self.cached("amc", load)

    def authorization_policy(self):
        """The authorization policy (guest, consent and user-permission defaults)."""
        return self.cached("authz", lambda: one(self.g.get("/policies/authorizationPolicy")))

    def group_settings(self):
        """Directory group settings objects (Group.Unified, Password Rule Settings, ...)."""
        return self.cached("group_settings", lambda: self.g.get_all("/groupSettings"))

    def conditional_access_policies(self):
        """All CA policies, or None if they cannot be read (no P1 licence or no permission)."""
        def load():
            """Loader for the cached value."""
            try:
                return self.g.get_all("/identity/conditionalAccess/policies")
            except GraphError as e:
                if e.status not in (400, 403):
                    raise
                return None
        return self.cached("ca", load)

    def security_defaults_enabled(self):
        """True/False for Security Defaults, or None when it cannot be read."""
        return self.cached("sd", lambda: bool(self.g.get("/policies/identitySecurityDefaultsEnforcementPolicy").get("isEnabled")))
