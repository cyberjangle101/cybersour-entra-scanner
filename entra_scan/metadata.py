"""Extra information attached to every finding, kept apart from the check logic so it is easy to review:

  LEARN    the Microsoft Learn article that explains the fix (or how to investigate)
  SETTING  the exact Graph object/property (or portal setting) the verdict is based on, so you can find and change the right thing
  CIS      the CIS Microsoft 365 Foundations Benchmark v5.0.0 recommendation the check implements (where one exists)

`apply()` stamps these onto each finding. The tests assert that every finding id has a Learn link and a Setting.
"""
from __future__ import annotations

_L = "https://learn.microsoft.com/en-us/"
_CA = "entra/identity/conditional-access/"
_AUTH = "entra/identity/authentication/"
_PIM = "entra/id-governance/privileged-identity-management/"
_RBAC = "entra/identity/role-based-access-control/"
_EXT = "entra/external-id/external-collaboration-settings-configure"
_CONSENT = "entra/identity/enterprise-apps/"
_USERS = "entra/fundamentals/users-default-permissions"
_INACTIVE = "entra/identity/monitoring-health/howto-manage-inactive-user-accounts"

LEARN_PATHS = {
    # Conditional Access
    "CA-SD": "entra/fundamentals/security-defaults", "CA-000": "entra/fundamentals/security-defaults", "CA-NA": _CA + "overview",
    "CA-001": _CA + "policy-block-legacy-authentication", "CA-002": _CA + "policy-all-users-mfa", "CA-003": _CA + "policy-admin-mfa",
    "CA-004": _CA + "policy-guests-mfa", "CA-005": _CA + "concept-conditional-access-cloud-apps",
    "CA-006": "entra/id-protection/howto-identity-protection-configure-risk-policies", "CA-007": "entra/id-protection/howto-identity-protection-configure-risk-policies",
    "CA-008": _CA + "plan-conditional-access", "CA-009": _CA + "concept-conditional-access-report-only",
    "CA-010": _CA + "howto-conditional-access-session-lifetime", "CA-011": _CA + "policy-admin-phish-resistant-mfa",
    "CA-012": "entra/id-protection/howto-identity-protection-configure-risk-policies", "CA-013": _CA + "policy-all-users-device-compliance",
    "CA-014": _CA + "howto-conditional-access-policy-registration",
    "CA-015": _CA + "howto-conditional-access-session-lifetime", "CA-016": _CA + "policy-block-authentication-flows",
    # Privileged access
    "ADM-001": _RBAC + "best-practices", "ADM-002": _RBAC + "best-practices", "ADM-003": _RBAC + "best-practices", "ADM-004": _RBAC + "best-practices",
    "ADM-005": _RBAC + "best-practices", "ADM-006": _INACTIVE, "ADM-007": _AUTH + "concept-authentication-strengths", "ADM-008": _RBAC + "groups-concept",
    "ADM-009": _RBAC + "security-emergency-access", "ADM-010": _RBAC + "best-practices",
    # Governance
    "PIM-001": _PIM + "pim-configure", "GOV-001": "entra/id-governance/create-access-review", "GOV-002": _PIM + "pim-create-roles-and-resource-roles-review",
    "GOV-003": _PIM + "pim-how-to-change-default-settings", "GOV-004": _PIM + "pim-how-to-change-default-settings", "GOV-005": _PIM + "pim-how-to-change-default-settings",
    # Users
    "USR-001": _AUTH + "how-to-mfa-registration-campaign", "USR-002": _AUTH + "concept-authentication-strengths", "USR-003": _AUTH + "concept-authentication-passwordless",
    "USR-004": _AUTH + "howto-authentication-methods-activity", "USR-010": _INACTIVE, "USR-011": _EXT, "USR-012": _EXT,
    "USR-013": _AUTH + "concept-sspr-policy", "USR-014": "entra/id-governance/understanding-lifecycle-workflows", "USR-015": _INACTIVE,
    "USR-016": "entra/id-governance/access-reviews-overview",
    # Applications
    "APP-001": "entra/identity-platform/certificate-credentials", "APP-002": "entra/identity-platform/certificate-credentials",
    "APP-003": "graph/api/resources/appmanagementpolicy", "APP-004": "entra/identity-platform/howto-convert-app-to-be-multi-tenant",
    "APP-010": _CONSENT + "manage-application-permissions", "APP-011": _CONSENT + "manage-application-permissions", "APP-012": _CONSENT + "manage-application-permissions",
    "APP-020": "defender-office-365/detect-and-remediate-illicit-consent-grants", "APP-021": "defender-office-365/detect-and-remediate-illicit-consent-grants",
    "APP-022": _CONSENT + "configure-user-consent",
    # Tenant settings
    "TEN-001": _EXT, "TEN-002": _EXT, "TEN-003": _CONSENT + "configure-user-consent", "TEN-004": _USERS, "TEN-005": _USERS, "TEN-006": _EXT,
    "TEN-007": "powershell/microsoftgraph/migration-steps", "TEN-008": _CONSENT + "configure-admin-consent-workflow", "TEN-010": _USERS,
    "TEN-011": "entra/identity/devices/manage-device-identities", "TEN-012": _CONSENT + "configure-user-consent",
    "XTA-001": "entra/external-id/cross-tenant-access-overview", "XTA-002": "entra/external-id/cross-tenant-access-settings-b2b-collaboration",
    "DOM-001": "microsoft-365/admin/setup/add-domain", "DOM-002": "entra/identity/hybrid/connect/whatis-fed", "DOM-003": _AUTH + "concept-sspr-policy",
    # Authentication methods
    "AUTH-001": _AUTH + "concept-authentication-methods", "AUTH-002": _AUTH + "concept-authentication-methods", "AUTH-003": _AUTH + "howto-authentication-passwordless-security-key",
    "AUTH-004": _AUTH + "how-to-mfa-registration-campaign", "AUTH-005": _AUTH + "how-to-mfa-number-match", "AUTH-006": _AUTH + "concept-system-preferred-multifactor-authentication",
    "AUTH-007": _AUTH + "concept-authentication-methods-manage",
    "PWD-001": _AUTH + "concept-password-ban-bad", "PWD-002": _AUTH + "concept-password-ban-bad-on-premises", "PWD-003": _AUTH + "howto-password-smart-lockout",
    # Devices
    "DEV-001": "entra/identity/devices/manage-device-identities", "DEV-002": "entra/identity/devices/manage-device-identities",
    "DEV-003": "entra/identity/devices/howto-manage-local-admin-passwords", "DEV-004": "entra/identity/devices/manage-device-identities",
    "DEV-005": "entra/identity/devices/assign-local-admin",
    # Groups
    "GRP-001": "entra/identity/users/groups-dynamic-membership", "GRP-002": "microsoft-365/solutions/manage-creation-of-groups",
    "GRP-003": "entra/fundamentals/concept-learn-about-groups",
    # Identity Protection
    "IDP-001": "entra/id-protection/howto-identity-protection-remediate-unblock", "IDP-002": "entra/id-protection/howto-identity-protection-investigate-risk",
    # Manual items
    "MAN-001": _AUTH + "howto-mfa-userstates", "MAN-002": _USERS, "MAN-003": "entra/fundamentals/how-to-customize-branding",
    "MAN-004": "entra/identity/users/linkedin-user-consent", "MAN-005": _EXT, "MAN-006": "entra/identity/hybrid/connect/whatis-phs",
    "MAN-007": _AUTH + "tutorial-enable-sspr", "MAN-008": _RBAC + "security-emergency-access",
}
LEARN = {k: _L + v for k, v in LEARN_PATHS.items()}
# Shown on SKIPPED / ERROR findings: how to grant the access the check needs.
SETUP_LEARN = _L + "graph/permissions-reference"

_G = "Graph "
SETTING = {
    "CA-SD": _G + "/policies/identitySecurityDefaultsEnforcementPolicy > isEnabled",
    "CA-000": _G + "/policies/identitySecurityDefaultsEnforcementPolicy > isEnabled; /identity/conditionalAccess/policies > state",
    "CA-NA": _G + "/policies/identitySecurityDefaultsEnforcementPolicy > isEnabled",
    "CA-001": _G + "/identity/conditionalAccess/policies > conditions.clientAppTypes (exchangeActiveSync + other), conditions.users.includeUsers = All, grantControls.builtInControls = block",
    "CA-002": _G + "/identity/conditionalAccess/policies > conditions.users.includeUsers = All, conditions.applications.includeApplications = All, grantControls (mfa / authenticationStrength)",
    "CA-003": _G + "/identity/conditionalAccess/policies > conditions.users.includeRoles (15 CIS admin roles), grantControls (mfa / authenticationStrength)",
    "CA-004": _G + "/identity/conditionalAccess/policies > conditions.users.includeGuestsOrExternalUsers, grantControls mfa",
    "CA-005": _G + "/identity/conditionalAccess/policies > conditions.applications.includeApplications = Microsoft Azure Management (797f4846-ba00-4fd7-ba43-dac1f8f63013)",
    "CA-006": _G + "/identity/conditionalAccess/policies > conditions.signInRiskLevels (contains high)",
    "CA-007": _G + "/identity/conditionalAccess/policies > conditions.userRiskLevels (contains high)",
    "CA-008": _G + "/identity/conditionalAccess/policies > conditions.users.excludeUsers / excludeGroups / excludeRoles",
    "CA-009": _G + "/identity/conditionalAccess/policies > state",
    "CA-010": _G + "/identity/conditionalAccess/policies > sessionControls.signInFrequency (<= 4 hours or everyTime), sessionControls.persistentBrowser.mode = never",
    "CA-011": _G + "/identity/conditionalAccess/policies > grantControls.authenticationStrength.id = 00000000-0000-0000-0000-000000000004 (Phishing-resistant MFA)",
    "CA-012": _G + "/identity/conditionalAccess/policies > conditions.signInRiskLevels (high + medium), grantControls.builtInControls = block",
    "CA-013": _G + "/identity/conditionalAccess/policies > grantControls.builtInControls (compliantDevice / domainJoinedDevice)",
    "CA-014": _G + "/identity/conditionalAccess/policies > conditions.applications.includeUserActions = urn:user:registersecurityinfo + device grant control",
    "CA-015": _G + "/identity/conditionalAccess/policies > Microsoft Intune Enrollment (d4ebce55-015a-49b5-a083-c84d1797ae8c) + sessionControls.signInFrequency.frequencyInterval = everyTime",
    "CA-016": _G + "/identity/conditionalAccess/policies > conditions.authenticationFlows.transferMethods = deviceCodeFlow + block",
    "ADM-001": _G + "/roleManagement/directory/roleAssignments > Global Administrator (62e90394-69f5-4237-9190-012177145e10) principal count",
    "ADM-002": _G + "/roleManagement/directory/roleAssignments?$expand=principal > user.userType = Guest",
    "ADM-003": _G + "/users > onPremisesSyncEnabled (role holders)", "ADM-004": _G + "/users > assignedLicenses.skuId vs /subscribedSkus > skuPartNumber",
    "ADM-005": _G + "/users > accountEnabled (role holders)", "ADM-006": _G + "/users > signInActivity (role holders)",
    "ADM-007": _G + "/reports/authenticationMethods/userRegistrationDetails > isMfaRegistered (role holders)",
    "ADM-008": _G + "/roleManagement/directory/roleAssignments?$expand=principal > @odata.type (group / servicePrincipal)",
    "ADM-009": _G + "/users > userPrincipalName (*.onmicrosoft.com), onPremisesSyncEnabled (Global Administrators)",
    "ADM-010": _G + "/roleManagement/directory/roleAssignments (count)",
    "PIM-001": _G + "/roleManagement/directory/roleEligibilityScheduleInstances (any exist)",
    "GOV-001": _G + "/identityGovernance/accessReviews/definitions > scope.query (userType eq 'Guest')",
    "GOV-002": _G + "/identityGovernance/accessReviews/definitions > scope.query (role assignment / eligibility instances)",
    "GOV-003": _G + "/policies/roleManagementPolicyAssignments (Global Administrator) > policy.rules[Approval_EndUser_Assignment].setting.isApprovalRequired",
    "GOV-004": _G + "/policies/roleManagementPolicyAssignments (Privileged Role Administrator) > policy.rules[Approval_EndUser_Assignment].setting.isApprovalRequired",
    "GOV-005": _G + "/policies/roleManagementPolicyAssignments (Global Administrator) > rules[Enablement_EndUser_Assignment].enabledRules contains MultiFactorAuthentication",
    "USR-001": _G + "/reports/authenticationMethods/userRegistrationDetails > isMfaRegistered", "USR-002": _G + "/reports/authenticationMethods/userRegistrationDetails > methodsRegistered",
    "USR-003": _G + "/reports/authenticationMethods/userRegistrationDetails > isPasswordlessCapable", "USR-004": _G + "/reports/authenticationMethods/userRegistrationDetails > isMfaCapable",
    "USR-010": _G + "/users > signInActivity, createdDateTime", "USR-011": _G + "/users > userType = Guest", "USR-012": _G + "/users > externalUserState, externalUserStateChangeDateTime",
    "USR-013": _G + "/users > passwordPolicies contains DisableStrongPassword", "USR-014": _G + "/users > accountEnabled = false and assignedLicenses",
    "USR-015": _G + "/users > assignedLicenses and signInActivity", "USR-016": _G + "/users > userType = Guest and signInActivity",
    "APP-001": _G + "/applications > passwordCredentials / keyCredentials > endDateTime", "APP-002": _G + "/applications > passwordCredentials / keyCredentials > endDateTime",
    "APP-003": _G + "/applications > passwordCredentials > startDateTime to endDateTime", "APP-004": _G + "/applications > signInAudience",
    "APP-010": _G + "/servicePrincipals/{id}/appRoleAssignedTo + /servicePrincipals > appOwnerOrganizationId, verifiedPublisher",
    "APP-011": _G + "/servicePrincipals/{id}/appRoleAssignedTo > appRoleId", "APP-012": _G + "/servicePrincipals/{id}/appRoleAssignedTo > appRoleId",
    "APP-020": _G + "/oauth2PermissionGrants > scope, consentType; /servicePrincipals > verifiedPublisher", "APP-021": _G + "/oauth2PermissionGrants > consentType = AllPrincipals, scope",
    "APP-022": _G + "/oauth2PermissionGrants > consentType = Principal, scope",
    "TEN-001": _G + "/policies/authorizationPolicy > allowInvitesFrom", "TEN-002": _G + "/policies/authorizationPolicy > guestUserRoleId",
    "TEN-003": _G + "/policies/authorizationPolicy > defaultUserRolePermissions.permissionGrantPoliciesAssigned", "TEN-004": _G + "/policies/authorizationPolicy > defaultUserRolePermissions.allowedToCreateTenants",
    "TEN-005": _G + "/policies/authorizationPolicy > defaultUserRolePermissions.allowedToCreateApps", "TEN-006": _G + "/policies/authorizationPolicy > allowEmailVerifiedUsersToJoinOrganization",
    "TEN-007": _G + "/policies/authorizationPolicy > blockMsolPowerShell", "TEN-008": _G + "/policies/adminConsentRequestPolicy > isEnabled",
    "TEN-010": _G + "/policies/authorizationPolicy > defaultUserRolePermissions.allowedToCreateSecurityGroups",
    "TEN-011": _G + "/policies/authorizationPolicy > defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice",
    "TEN-012": _G + "/policies/authorizationPolicy > allowUserConsentForRiskyApps",
    "XTA-001": _G + "/policies/crossTenantAccessPolicy/default > b2bCollaborationInbound.usersAndGroups / applications > accessType",
    "XTA-002": _G + "/policies/crossTenantAccessPolicy/default > inboundTrust",
    "DOM-001": _G + "/domains > isVerified", "DOM-002": _G + "/domains > authenticationType = Federated", "DOM-003": _G + "/domains > passwordValidityPeriodInDays",
    "AUTH-001": _G + "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator > state",
    "AUTH-002": _G + "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Sms and Voice > state",
    "AUTH-003": _G + "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Fido2 > state",
    "AUTH-004": _G + "/policies/authenticationMethodsPolicy > registrationEnforcement.authenticationMethodsRegistrationCampaign.state",
    "AUTH-005": _G + "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator > featureSettings",
    "AUTH-006": _G + "/policies/authenticationMethodsPolicy > systemCredentialPreferences.state",
    "AUTH-007": _G + "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Email > state",
    "PWD-001": _G + "/groupSettings (Password Rule Settings) > EnableBannedPasswordCheck, BannedPasswordList",
    "PWD-002": _G + "/groupSettings (Password Rule Settings) > EnableBannedPasswordCheckOnPremises, BannedPasswordCheckOnPremisesMode",
    "PWD-003": _G + "/groupSettings (Password Rule Settings) > LockoutThreshold",
    "DEV-001": _G + "/policies/deviceRegistrationPolicy > userDeviceQuota", "DEV-002": _G + "/policies/deviceRegistrationPolicy > azureADJoin.allowedToJoin",
    "DEV-003": _G + "/policies/deviceRegistrationPolicy > localAdminPassword.isEnabled", "DEV-004": _G + "/policies/deviceRegistrationPolicy > multiFactorAuthConfiguration",
    "DEV-005": _G + "/policies/deviceRegistrationPolicy > azureADJoin.localAdmins.enableGlobalAdmins",
    "GRP-001": _G + "/groups?$filter=groupTypes/any(c:c eq 'DynamicMembership') > membershipRule", "GRP-002": _G + "/groupSettings (Group.Unified) > EnableGroupCreation, GroupCreationAllowedGroupId",
    "GRP-003": _G + "/groups?$filter=groupTypes/any(c:c eq 'Unified') > visibility eq 'Public'",
    "IDP-001": _G + "/identityProtection/riskyUsers > riskState = atRisk, riskLevel = high", "IDP-002": _G + "/identityProtection/riskyUsers > riskState = atRisk, riskLevel = medium",
    "MAN-001": "Portal: Entra admin center > Users > Per-user MFA", "MAN-002": "Portal: Entra admin center > Users > User settings > Restrict access to Microsoft Entra admin center",
    "MAN-003": "Portal: Entra admin center > Company branding > Default sign-in experience > Show option to remain signed in",
    "MAN-004": "Portal: Entra admin center > Users > User settings > LinkedIn account connections",
    "MAN-005": "Portal: Entra admin center > External Identities > External collaboration settings > Collaboration restrictions",
    "MAN-006": "Portal: Entra admin center > Entra Connect > Connect Sync; or Graph /directory/onPremisesSynchronization > features.passwordSyncEnabled (delegated only)",
    "MAN-007": "Portal: Entra admin center > Protection > Password reset > Properties", "MAN-008": "Portal: Conditional Access exclusions + alert rules for break-glass accounts",
}

_CIS = "CIS Microsoft 365 Foundations Benchmark v5.0.0, "
_CIS_ROWS = {
    "CA-001": ("5.2.2.3", "Enable Conditional Access policies to block legacy authentication"),
    "CA-002": ("5.2.2.2", "Ensure multifactor authentication is enabled for all users"),
    "CA-003": ("5.2.2.1", "Ensure multifactor authentication is enabled for all users in administrative roles"),
    "CA-006": ("5.2.2.7", "Enable Identity Protection sign-in risk policies"), "CA-007": ("5.2.2.6", "Enable Identity Protection user risk policies"),
    "CA-010": ("5.2.2.4", "Ensure sign-in frequency is enabled and browser sessions are not persistent for administrative users"),
    "CA-011": ("5.2.2.5", "Ensure 'Phishing-resistant MFA strength' is required for Administrators"),
    "CA-012": ("5.2.2.8", "Ensure 'sign-in risk' is blocked for medium and high risk"),
    "CA-013": ("5.2.2.9", "Ensure a managed device is required for authentication"),
    "CA-014": ("5.2.2.10", "Ensure a managed device is required to register security information"),
    "CA-015": ("5.2.2.11", "Ensure sign-in frequency for Intune Enrollment is set to 'Every time'"),
    "CA-016": ("5.2.2.12", "Ensure the device code sign-in flow is blocked"),
    "ADM-001": ("1.1.3", "Ensure that between two and four global admins are designated"),
    "ADM-003": ("1.1.1", "Ensure administrative accounts are cloud-only"),
    "ADM-004": ("1.1.4", "Ensure administrative accounts use licenses with a reduced application footprint"),
    "ADM-009": ("1.1.2", "Ensure two emergency access accounts have been defined"),
    "PIM-001": ("5.3.1", "Ensure 'Privileged Identity Management' is used to manage roles"),
    "GOV-001": ("5.3.2", "Ensure 'Access reviews' for guest users are configured"),
    "GOV-002": ("5.3.3", "Ensure 'Access reviews' for privileged roles are configured"),
    "GOV-003": ("5.3.4", "Ensure approval is required for Global Administrator role activation"),
    "GOV-004": ("5.3.5", "Ensure approval is required for Privileged Role Administrator activation"),
    "USR-004": ("5.2.3.4", "Ensure all member users are 'MFA capable'"),
    "AUTH-005": ("5.2.3.1", "Ensure Microsoft Authenticator is configured to protect against MFA fatigue"),
    "AUTH-002": ("5.2.3.5", "Ensure weak authentication methods are disabled"), "AUTH-007": ("5.2.3.5", "Ensure weak authentication methods are disabled"),
    "AUTH-006": ("5.2.3.6", "Ensure system-preferred multifactor authentication is enabled"),
    "PWD-001": ("5.2.3.2", "Ensure custom banned passwords lists are used"), "PWD-002": ("5.2.3.3", "Ensure password protection is enabled for on-prem Active Directory"),
    "DOM-003": ("1.3.1", "Ensure the 'Password expiration policy' is set to 'Set passwords to never expire'"),
    "TEN-001": ("5.1.6.3", "Ensure guest user invitations are limited to the Guest Inviter role"), "TEN-002": ("5.1.6.2", "Ensure that guest user access is restricted"),
    "TEN-003": ("5.1.5.1", "Ensure user consent to apps accessing company data on their behalf is not allowed"),
    "TEN-004": ("5.1.2.3", "Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'"),
    "TEN-005": ("5.1.2.2", "Ensure third party integrated applications are not allowed"), "TEN-008": ("5.1.5.2", "Ensure the admin consent workflow is enabled"),
    "GRP-001": ("5.1.3.1", "Ensure a dynamic group for guest users is created"), "GRP-003": ("1.2.1", "Ensure that only organizationally managed/approved public groups exist"),
    "MAN-001": ("5.1.2.1", "Ensure 'Per-user MFA' is disabled"), "MAN-002": ("5.1.2.4", "Ensure access to the Entra admin center is restricted"),
    "MAN-003": ("5.1.2.5", "Ensure the option to remain signed in is hidden"), "MAN-004": ("5.1.2.6", "Ensure 'LinkedIn account connections' is disabled"),
    "MAN-005": ("5.1.6.1", "Ensure that collaboration invitations are sent to allowed domains only"),
    "MAN-006": ("5.1.8.1", "Ensure that password hash sync is enabled for hybrid deployments"),
    "MAN-007": ("5.2.4.1", "Ensure 'Self service password reset enabled' is set to 'All'"), "MAN-008": ("1.1.2", "Ensure two emergency access accounts have been defined"),
}
CIS_MAP = {k: f"{_CIS}{num}: {title}" for k, (num, title) in _CIS_ROWS.items()}


# --------------------------------------------------------------------------- v1.1 checks
_HYB = "entra/identity/hybrid/connect/"
LEARN_PATHS.update({
    "ADM-011": _RBAC + "security-emergency-access", "ADM-012": _RBAC + "security-emergency-access",
    "ADM-013": _RBAC + "security-emergency-access", "ADM-014": _RBAC + "security-emergency-access",
    "HYB-001": _HYB + "how-to-connect-health-sync", "HYB-002": _HYB + "whatis-phs",
    "NET-001": _CA + "concept-assignment-network", "NET-002": _CA + "concept-assignment-network", "NET-003": _CA + "concept-assignment-network",
    "CAQ-001": _CA + "concept-conditional-access-report-only", "CAQ-002": _CA + "plan-conditional-access", "CAQ-003": _CA + "plan-conditional-access",
    "PRV-001": _PIM + "pim-configure", "PRV-002": _PIM + "pim-configure",
    "APP-030": "entra/identity-platform/reply-url", "APP-031": "entra/identity-platform/howto-modify-supported-accounts",
    "APP-032": "entra/identity-platform/howto-add-app-roles-in-apps", "APP-033": "entra/identity/enterprise-apps/assign-app-owners",
    "LEG-001": _CA + "policy-block-legacy-authentication",
    "GST-001": "entra/external-id/cross-tenant-access-overview", "GST-002": "entra/external-id/cross-tenant-access-settings-b2b-collaboration",
    "AUT-001": _AUTH + "concept-authentication-strengths",
})
LEARN.update({k: _L + v for k, v in LEARN_PATHS.items() if k not in LEARN})

SETTING.update({
    "ADM-011": _G + "/identity/conditionalAccess/policies > conditions.users.excludeUsers (break-glass account ids)",
    "ADM-012": _G + "/reports/authenticationMethods/userRegistrationDetails > methodsRegistered (fido2 / passKey)",
    "ADM-013": _G + "/users > signInActivity (break-glass accounts)", "ADM-014": _G + "/users > assignedLicenses (break-glass accounts)",
    "HYB-001": _G + "/organization > onPremisesLastSyncDateTime", "HYB-002": _G + "/organization > onPremisesLastPasswordSyncDateTime",
    "NET-001": _G + "/identity/conditionalAccess/namedLocations > ipNamedLocation.isTrusted, ipRanges",
    "NET-002": _G + "/identity/conditionalAccess/namedLocations", "NET-003": _G + "/identity/conditionalAccess/policies > conditions.locations",
    "CAQ-001": _G + "/identity/conditionalAccess/policies > state = enabledForReportingButNotEnforced, modifiedDateTime",
    "CAQ-002": _G + "/identity/conditionalAccess/policies > state = disabled, modifiedDateTime",
    "CAQ-003": _G + "/identity/conditionalAccess/policies > grantControls, sessionControls",
    "PRV-001": _G + "/roleManagement/directory/roleAssignmentScheduleInstances?$filter=assignmentType eq 'Assigned' > endDateTime",
    "PRV-002": _G + "/roleManagement/directory/roleAssignmentScheduleInstances (permanent critical roles)",
    "APP-030": _G + "/applications > web.redirectUris, spa.redirectUris", "APP-031": _G + "/applications > signInAudience, requiredResourceAccess",
    "APP-032": _G + "/applications?$expand=owners", "APP-033": _G + "/applications?$expand=owners > userType = Guest",
    "LEG-001": _G + "/auditLogs/signIns > clientAppUsed (last 7 days, successful)",
    "GST-001": _G + "/policies/crossTenantAccessPolicy/partners", "GST-002": _G + "/policies/crossTenantAccessPolicy/partners > b2bCollaborationInbound",
    "AUT-001": _G + "/policies/authenticationStrengthPolicies > allowedCombinations (custom)",
})

# --------------------------------------------------------------------------- other frameworks (cross-references, not certifications)
# NIST SP 800-53 Rev. 5 control families and ISO/IEC 27001:2022 Annex A controls each check supports. Chosen by theme; a
# mapping says the check is EVIDENCE for the control, not that passing it makes you compliant.
_THEME = {
    "mfa": (["IA-2(1)", "IA-2(2)", "IA-5"], ["A.5.17", "A.8.5"]),
    "admin": (["AC-2(7)", "AC-5", "AC-6", "AC-6(5)"], ["A.5.15", "A.5.18", "A.8.2"]),
    "access": (["AC-2", "AC-3", "AC-6"], ["A.5.15", "A.5.18"]),
    "review": (["AC-2(3)", "AC-2(4)", "CA-7"], ["A.5.18", "A.5.36"]),
    "network": (["AC-17", "SC-7", "AC-19"], ["A.8.20", "A.8.22"]),
    "password": (["IA-5(1)", "IA-5"], ["A.5.17"]),
    "apps": (["CM-7", "CM-8", "AC-6", "SA-9"], ["A.5.19", "A.5.23", "A.8.9"]),
    "guest": (["AC-2", "AC-21", "AC-20"], ["A.5.14", "A.5.19"]),
    "device": (["CM-2", "CM-6", "AC-19"], ["A.8.1", "A.8.9"]),
    "monitor": (["AU-6", "SI-4", "IR-4"], ["A.8.15", "A.8.16"]),
    "config": (["CM-2", "CM-6"], ["A.8.9"]),
}
_THEME_OF_PREFIX = {"CA": "config", "ADM": "admin", "PIM": "admin", "GOV": "review", "USR": "mfa", "AUTH": "mfa", "PWD": "password",
                    "APP": "apps", "TEN": "guest", "DEV": "device", "GRP": "access", "IDP": "monitor", "MAN": "config",
                    "HYB": "config", "NET": "network", "CAQ": "config", "PRV": "admin", "LEG": "monitor", "GST": "guest", "AUT": "mfa"}
_THEME_OVERRIDE = {"CA-001": "mfa", "CA-002": "mfa", "CA-003": "mfa", "CA-004": "mfa", "CA-011": "mfa", "CA-013": "device", "CA-014": "device",
                   "CA-006": "monitor", "CA-007": "monitor", "CA-012": "monitor", "ADM-007": "mfa", "ADM-012": "mfa", "ADM-006": "access",
                   "ADM-013": "monitor", "USR-010": "access", "USR-016": "guest"}


def frameworks_for(finding_id):
    """{'NIST 800-53': [...], 'ISO 27001': [...]} for a finding id; {} for scanner-internal ids (SKIP-/ERR-)."""
    theme = _THEME_OVERRIDE.get(finding_id) or _THEME_OF_PREFIX.get(finding_id.split("-")[0])
    if theme is None:
        return {}
    nist, iso = _THEME[theme]
    return {"NIST 800-53": list(nist), "ISO 27001": list(iso)}


def apply(findings):
    """Stamp Learn link, setting path and CIS reference onto each finding (in place) and return them."""
    for f in findings:
        f.cis = CIS_MAP.get(f.id, "")
        f.setting = SETTING.get(f.id, "")
        f.learn = LEARN.get(f.id) or (SETUP_LEARN if f.status in ("SKIPPED", "ERROR") else "")
        f.frameworks = frameworks_for(f.id)
    return findings
