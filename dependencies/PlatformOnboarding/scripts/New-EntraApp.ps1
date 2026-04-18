#Requires -Version 5.1
<#
.SYNOPSIS
    Create (or reuse) an Entra ID App Registration with the specified API permissions,
    grant admin consent, and optionally assign Azure RBAC at a chosen scope. Outputs
    the tenant id / app id / secret so it can be handed to a solution's LauncherConfig.ps1.

.DESCRIPTION
    Platform-level onboarding helper. Used by the community + internal flavours of
    every solution. Idempotent: re-running with the same -AppDisplayName updates the
    existing app in place.

    Provisions:
      1. Entra App registration (single-tenant)
      2. Service Principal for the app
      3. Client secret (configurable expiry)
      4. API permissions (Graph / Defender / any resource) with admin consent
      5. Optional Azure RBAC role assignments at subscription / MG / root scope
      6. Optional certificate upload (public-key only) for certificate-based auth

    On exit, writes a JSON manifest to SCRIPTS\Output\<AppDisplayName>-onboarding.json
    with every value a launcher needs (TenantId, ClientId, Secret [if created],
    ObjectId). The SecretValue is ALSO printed to the console ONCE -- Entra does not
    let you retrieve it later.

.PARAMETER AppDisplayName
    Display name for the Entra app. e.g. 'SecurityInsight-SPN'.

.PARAMETER GraphApplicationPermissions
    Array of Graph application permission names (e.g. 'Directory.Read.All',
    'ThreatHunting.Read.All'). Leave empty to skip.

.PARAMETER DefenderApplicationPermissions
    Array of WindowsDefenderATP application permission names (e.g. 'Machine.ReadWrite.All').

.PARAMETER AzureRbacRoles
    Hashtable mapping role name -> scope, e.g.
      @{ 'Reader' = '/subscriptions/<sub-id>'; 'Tag Contributor' = '/providers/Microsoft.Management/managementGroups/<root-id>' }

.PARAMETER CertificatePublicKeyPath
    Optional path to a .cer file whose public key is uploaded to the app for
    certificate-based auth. Pair with New-SelfSignedCertificate.ps1 output.

.PARAMETER SkipSecretCreation
    Skip creating a client secret. Useful when you've uploaded a certificate
    (Cert auth) and don't need a secret.

.PARAMETER SecretExpiryDays
    Default: 180. Max recommended: 365.

.EXAMPLE
    .\New-EntraApp.ps1 -AppDisplayName SecurityInsight-SPN `
        -GraphApplicationPermissions @('ThreatHunting.Read.All','Directory.Read.All') `
        -DefenderApplicationPermissions @('Machine.ReadWrite.All') `
        -AzureRbacRoles @{ 'Tag Contributor' = '/providers/Microsoft.Management/managementGroups/<mg-id>' }
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AppDisplayName,
    [string[]]$GraphApplicationPermissions    = @(),
    [string[]]$DefenderApplicationPermissions = @(),
    [hashtable]$AzureRbacRoles                = @{},
    [string]$CertificatePublicKeyPath,
    [switch]$SkipSecretCreation,
    [int]$SecretExpiryDays = 180
)

$ErrorActionPreference = 'Stop'

if (-not $global:SpnTenantId -or [string]::IsNullOrWhiteSpace([string]$global:SpnTenantId)) {
    throw "PlatformOnboarding\\New-EntraApp: `$global:SpnTenantId not set. Configure the bootstrap SPN in LauncherConfig.ps1 first."
}

foreach ($name in 'Microsoft.Graph.Authentication','Microsoft.Graph.Applications','Az.Accounts','Az.Resources') {
    if (-not (Get-Module -ListAvailable -Name $name)) {
        Write-Host "[STEP] Installing $name ..." -ForegroundColor Cyan
        Install-Module $name -Scope CurrentUser -Force -AllowClobber
    }
}
Import-Module Microsoft.Graph.Applications -WarningAction SilentlyContinue -ErrorAction Stop
Import-Module Az.Accounts -WarningAction SilentlyContinue -ErrorAction Stop
Import-Module Az.Resources -WarningAction SilentlyContinue -ErrorAction Stop

# Expect the current session to be authenticated already -- launcher handles that.
if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
    throw "New-EntraApp: no Microsoft Graph session. Launcher must connect first."
}
if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
    throw "New-EntraApp: no Azure session. Launcher must connect first."
}

Write-Host "[STEP] Resolving or creating application: $AppDisplayName" -ForegroundColor Cyan
$existing = Get-MgApplication -Filter "displayName eq '$AppDisplayName'" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[OK]   Existing application found (appId=$($existing.AppId))" -ForegroundColor Green
    $app = $existing | Select-Object -First 1
} else {
    $app = New-MgApplication -DisplayName $AppDisplayName -SignInAudience 'AzureADMyOrg'
    Write-Host "[OK]   Created application (appId=$($app.AppId))" -ForegroundColor Green
}

Write-Host "[STEP] Resolving or creating service principal" -ForegroundColor Cyan
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
if (-not $sp) {
    $sp = New-MgServicePrincipal -AppId $app.AppId
    Write-Host "[OK]   SP created (objectId=$($sp.Id))" -ForegroundColor Green
} else {
    Write-Host "[OK]   Existing SP (objectId=$($sp.Id))" -ForegroundColor Green
}

# -------- API permissions ----------
if ($GraphApplicationPermissions.Count -gt 0 -or $DefenderApplicationPermissions.Count -gt 0) {
    Write-Host "[STEP] Configuring API permissions" -ForegroundColor Cyan
    $requiredResourceAccess = @()
    if ($GraphApplicationPermissions.Count -gt 0) {
        $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop
        $ids = foreach ($p in $GraphApplicationPermissions) {
            $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $p }
            if (-not $role) { throw "Graph application permission '$p' not found." }
            @{ Id = $role.Id; Type = 'Role' }
        }
        $requiredResourceAccess += @{ ResourceAppId = $graphSp.AppId; ResourceAccess = @($ids) }
    }
    if ($DefenderApplicationPermissions.Count -gt 0) {
        # WindowsDefenderATP
        $defSp = Get-MgServicePrincipal -Filter "appId eq 'fc780465-2017-40d4-a0c5-307022471b92'" -ErrorAction SilentlyContinue
        if (-not $defSp) { Write-Warning "WindowsDefenderATP service principal not found in tenant; skipping Defender permissions." }
        else {
            $ids = foreach ($p in $DefenderApplicationPermissions) {
                $role = $defSp.AppRoles | Where-Object { $_.Value -eq $p }
                if (-not $role) { throw "Defender application permission '$p' not found." }
                @{ Id = $role.Id; Type = 'Role' }
            }
            $requiredResourceAccess += @{ ResourceAppId = $defSp.AppId; ResourceAccess = @($ids) }
        }
    }
    Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $requiredResourceAccess
    Write-Host "[OK]   Required resource access set" -ForegroundColor Green

    Write-Host "[STEP] Granting admin consent (app-role assignments on each resource SP)" -ForegroundColor Cyan
    foreach ($rra in $requiredResourceAccess) {
        $resourceSp = Get-MgServicePrincipal -Filter "appId eq '$($rra.ResourceAppId)'"
        foreach ($access in $rra.ResourceAccess) {
            try {
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
                    -PrincipalId $sp.Id -ResourceId $resourceSp.Id -AppRoleId $access.Id -ErrorAction Stop | Out-Null
                Write-Host ("[OK]     granted {0} on {1}" -f $access.Id, $resourceSp.DisplayName) -ForegroundColor Green
            } catch {
                if ($_.Exception.Message -match 'already exists|already been granted') {
                    Write-Host ("[INFO]   already consented {0} on {1}" -f $access.Id, $resourceSp.DisplayName) -ForegroundColor Gray
                } else { throw }
            }
        }
    }
}

# -------- Optional certificate upload ----------
if ($CertificatePublicKeyPath) {
    if (-not (Test-Path -LiteralPath $CertificatePublicKeyPath)) { throw "Certificate public key not found: $CertificatePublicKeyPath" }
    Write-Host "[STEP] Uploading certificate public key to app" -ForegroundColor Cyan
    $certBytes = [System.IO.File]::ReadAllBytes($CertificatePublicKeyPath)
    $keyCredential = @{
        Type            = 'AsymmetricX509Cert'
        Usage           = 'Verify'
        Key             = $certBytes
        DisplayName     = (Split-Path $CertificatePublicKeyPath -Leaf)
    }
    Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($keyCredential)
    Write-Host "[OK]   Certificate uploaded" -ForegroundColor Green
}

# -------- Optional client secret ----------
$secretInfo = $null
if (-not $SkipSecretCreation) {
    Write-Host "[STEP] Creating client secret (expires in $SecretExpiryDays days)" -ForegroundColor Cyan
    $endDate = (Get-Date).AddDays($SecretExpiryDays).ToUniversalTime()
    $pwdCred = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
        DisplayName = "Created by PlatformOnboarding on $((Get-Date).ToString('yyyy-MM-dd'))"
        EndDateTime = $endDate
    }
    $secretInfo = [pscustomobject]@{ KeyId = $pwdCred.KeyId; Value = $pwdCred.SecretText; EndDateTime = $pwdCred.EndDateTime }
    Write-Host ("[OK]   Secret created. Value: {0}" -f $pwdCred.SecretText) -ForegroundColor Yellow
    Write-Host "[WARN] Copy this value NOW. Entra does not allow retrieving it later." -ForegroundColor Yellow
}

# -------- Azure RBAC ----------
if ($AzureRbacRoles.Count -gt 0) {
    Write-Host "[STEP] Assigning Azure RBAC roles" -ForegroundColor Cyan
    foreach ($roleName in $AzureRbacRoles.Keys) {
        $scope = $AzureRbacRoles[$roleName]
        try {
            New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName $roleName -Scope $scope -ErrorAction Stop | Out-Null
            Write-Host "[OK]     '$roleName' granted at $scope" -ForegroundColor Green
        } catch {
            if ($_.Exception.Message -match 'already exists|RoleAssignmentExists') {
                Write-Host "[INFO]   '$roleName' already assigned at $scope" -ForegroundColor Gray
            } else { Write-Warning "Failed granting '$roleName' at $scope -- $($_.Exception.Message)" }
        }
    }
}

# -------- Write output manifest ----------
$outDir = Join-Path $PSScriptRoot 'Output'
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
$safeName = ($AppDisplayName -replace '[^A-Za-z0-9._-]','_')
$outFile = Join-Path $outDir "$safeName-onboarding.json"
@{
    AppDisplayName = $AppDisplayName
    TenantId       = (Get-MgContext).TenantId
    ClientId       = $app.AppId
    ObjectId       = $app.Id
    SpObjectId     = $sp.Id
    SecretKeyId    = if ($secretInfo) { $secretInfo.KeyId } else { $null }
    SecretValue    = if ($secretInfo) { $secretInfo.Value } else { $null }
    SecretExpires  = if ($secretInfo) { $secretInfo.EndDateTime } else { $null }
    CreatedUtc     = [datetime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $outFile -Encoding UTF8

Write-Host ""
Write-Host "================================================================"
Write-Host (" App onboarding complete.")
Write-Host ("   TenantId : {0}" -f (Get-MgContext).TenantId)
Write-Host ("   ClientId : {0}" -f $app.AppId)
if ($secretInfo) {
Write-Host ("   Secret   : {0}   (expires {1:yyyy-MM-dd})" -f $secretInfo.Value, $secretInfo.EndDateTime)
}
Write-Host (" Manifest written to: {0}" -f $outFile)
Write-Host "================================================================"
