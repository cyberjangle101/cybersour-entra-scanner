<#
.SYNOPSIS
  Creates the READ-ONLY app registration the Entra Posture Scanner signs in with, grants the 10 Microsoft Graph
  application permissions and (optionally) admin consent, and sets up ONE credential.

.DESCRIPTION
  Run this ONCE, as a person who may create app registrations and grant admin consent (Application Administrator +
  Privileged Role Administrator, or Global Administrator). It signs you in interactively; the scanner itself never needs
  those rights. The script:
    1. creates the app registration and its service principal (single tenant);
    2. adds the application permissions listed in $Permissions (looked up by NAME at run time, never by hard-coded ID);
    3. with -GrantConsent, grants admin consent for them;
    4. creates exactly one credential, chosen with -Credential:
         Certificate  self-signed certificate, public part uploaded, PEM private key written to -OutDir (default)
         Federated    workload identity federation for a GitHub repo (-GitHubRepo owner/repo [-GitHubEnvironment name]) - NO secret exists
         Secret       a client secret written to a 0600-style file in -OutDir; it is never printed
         None         no credential (add one yourself)
  -WhatIf shows what would happen without changing anything.

  IMPORTANT: this script WRITES to your tenant (it creates an app) - that is its purpose. The scanner it prepares only reads.
  It was written against the Microsoft.Graph PowerShell SDK but has NOT been executed in the environment where the scanner was
  built (no PowerShell there). Review it and use -WhatIf first.

.EXAMPLE
  ./setup_app_registration.ps1 -TenantId contoso.onmicrosoft.com -GrantConsent -WhatIf
.EXAMPLE
  ./setup_app_registration.ps1 -TenantId contoso.onmicrosoft.com -Credential Federated -GitHubRepo contoso/posture-pipeline -GrantConsent
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [string] $DisplayName = 'Entra Posture Scanner (read-only)',
    [ValidateSet('Certificate', 'Federated', 'Secret', 'None')] [string] $Credential = 'Certificate',
    [string] $GitHubRepo,
    [string] $GitHubEnvironment,
    [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')] [string] $Environment = 'Global',
    [int] $ValidityDays = 365,
    [string] $OutDir = (Join-Path (Get-Location) 'scanner-credential'),
    [switch] $GrantConsent
)

$ErrorActionPreference = 'Stop'

# The ten READ-ONLY Microsoft Graph application permissions the scanner uses (kept in step with entra_scan/permissions.py by a test).
$Permissions = @(
    'Policy.Read.All', 'Policy.Read.DeviceConfiguration', 'Directory.Read.All', 'User.Read.All', 'Application.Read.All',
    'AuditLog.Read.All', 'RoleManagement.Read.Directory', 'RoleManagementPolicy.Read.Directory', 'AccessReview.Read.All',
    'IdentityRiskyUser.Read.All'
)
$GraphAppId = '00000003-0000-0000-c000-000000000000'          # Microsoft Graph's well-known application ID in every cloud
$Audience = @{ Global = 'api://AzureADTokenExchange'; USGov = 'api://AzureADTokenExchangeUSGov'; USGovDoD = 'api://AzureADTokenExchangeUSGov'; China = 'api://AzureADTokenExchangeChina' }[$Environment]

if ($Credential -eq 'Federated' -and -not $GitHubRepo) { throw '-Credential Federated needs -GitHubRepo owner/repo.' }
if ($GitHubRepo -and $GitHubRepo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw '-GitHubRepo must look like owner/repo.' }

if (-not (Get-Module -ListAvailable Microsoft.Graph.Applications)) {
    throw 'Install the SDK first:  Install-Module Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns -Scope CurrentUser'
}
# Delegated sign-in for the PERSON running this script; these scopes are only used here, never by the scanner.
Connect-MgGraph -TenantId $TenantId -Environment $Environment -NoWelcome -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All'

# 1. Resolve each permission NAME to its appRole ID from Graph's own service principal.
$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
$resourceAccess = foreach ($name in $Permissions) {
    $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $name -and $_.AllowedMemberTypes -contains 'Application' }
    if (-not $role) { throw "Permission $name was not found as an application role on Microsoft Graph in this cloud." }
    @{ Id = $role.Id; Type = 'Role' }
}

# 2. App registration + service principal.
$existing = Get-MgApplication -Filter "displayName eq '$DisplayName'"
if ($existing) { throw "An app named '$DisplayName' already exists ($($existing.AppId)). Pick another -DisplayName or delete it first." }

if ($PSCmdlet.ShouldProcess($DisplayName, 'Create app registration with 10 read-only Graph application permissions')) {
    $app = New-MgApplication -DisplayName $DisplayName -SignInAudience 'AzureADMyOrg' `
        -RequiredResourceAccess @(@{ ResourceAppId = $GraphAppId; ResourceAccess = $resourceAccess })
    $sp = New-MgServicePrincipal -AppId $app.AppId
    Write-Host "Created app '$DisplayName'  client ID: $($app.AppId)"

    # 3. Admin consent: one appRoleAssignment per permission.
    if ($GrantConsent) {
        foreach ($ra in $resourceAccess) {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $ra.Id | Out-Null
        }
        Write-Host 'Admin consent granted for all 10 permissions.'
    } else {
        Write-Host 'Admin consent NOT granted: ask a Global Administrator to click "Grant admin consent" (Entra > App registrations > API permissions).'
    }

    # 4. One credential.
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    switch ($Credential) {
        'Certificate' {
            $cert = New-SelfSignedCertificate -Subject "CN=$DisplayName" -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable `
                -KeySpec Signature -NotAfter (Get-Date).AddDays($ValidityDays) -HashAlgorithm SHA256 -KeyLength 3072
            Update-MgApplication -ApplicationId $app.Id -KeyCredentials @(@{ Type = 'AsymmetricX509Cert'; Usage = 'Verify'; Key = $cert.RawData; DisplayName = 'scanner'
                    StartDateTime = $cert.NotBefore; EndDateTime = $cert.NotAfter })
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            $pem = ("-----BEGIN " + "PRIVATE KEY-----`n") + [Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey(), 'InsertLineBreaks') + ("`n-----END " + "PRIVATE KEY-----`n")
            $keyFile = Join-Path $OutDir 'scanner-key.pem'
            Set-Content -Path $keyFile -Value $pem -NoNewline
            Write-Host "Certificate thumbprint: $($cert.Thumbprint)"
            Write-Host "Private key written to $keyFile - protect it like a password. Run the scanner with:  --auth cert --cert-path `"$keyFile`" --cert-thumbprint $($cert.Thumbprint)"
        }
        'Federated' {
            $subject = if ($GitHubEnvironment) { "repo:${GitHubRepo}:environment:$GitHubEnvironment" } else { "repo:${GitHubRepo}:ref:refs/heads/main" }
            New-MgApplicationFederatedIdentityCredential -ApplicationId $app.Id -BodyParameter @{
                Name = 'github-posture-scan'; Issuer = 'https://token.actions.githubusercontent.com'; Subject = $subject; Audiences = @($Audience) } | Out-Null
            Write-Host "Federated credential created for subject '$subject'. No secret exists. Run the scanner in that workflow with:  --auth federated --client-id $($app.AppId) --tenant $TenantId"
        }
        'Secret' {
            $pwd = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{ DisplayName = 'scanner'; EndDateTime = (Get-Date).AddDays($ValidityDays) }
            $file = Join-Path $OutDir 'client-secret.txt'
            Set-Content -Path $file -Value $pwd.SecretText -NoNewline                       # never echoed to the console or logs
            if ($IsLinux -or $IsMacOS) { chmod 600 $file } else { icacls $file /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null }
            Write-Host "Client secret written to $file (expires $($pwd.EndDateTime)). Run the scanner with:  --client-secret-file `"$file`""
        }
        'None' { Write-Host 'No credential created.' }
    }
    Write-Host "`nTenant: $TenantId   Client ID: $($app.AppId)"
}
Disconnect-MgGraph | Out-Null
