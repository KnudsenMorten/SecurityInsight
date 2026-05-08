<#
.SYNOPSIS
    Creates or updates a tenant-level Entra ID Diagnostic Setting that streams
    sign-in + audit logs to the SecurityInsight Log Analytics workspace.

.DESCRIPTION
    Calls the Azure Monitor diagnosticSettings REST API at the tenant scope
    (provider 'microsoft.aadiam') to create / update a single Diagnostic
    Setting. Idempotent: PUT semantics replace the named setting; existing
    settings with other names (e.g. a Sentinel-side one) are left untouched.

    Categories shipped by default (the engine's RA queries reference them):
      SignInLogs                       -- interactive user sign-ins
      AuditLogs                        -- directory writes
      NonInteractiveUserSignInLogs     -- refresh-token / device-code sign-ins
      ServicePrincipalSignInLogs       -- SPN logins
      ManagedIdentitySignInLogs        -- MSI logins
      UserRiskEvents                   -- Identity Protection user-risk events
      ProvisioningLogs                 -- HR/SCIM provisioning
      MicrosoftGraphActivityLogs       -- Graph API activity (audit trail)

    The operator running /api/apply needs Entra **Security Administrator**
    or **Global Administrator** (tenant-level Diagnostic Settings require it).
    Lower-privileged callers get a clear AuthorizationFailed error surfaced
    from the API.

.PARAMETER WorkspaceResourceId
    Full ARM ResourceId of the SI Log Analytics workspace. Required.

.PARAMETER Name
    Diagnostic Setting name. Default 'SI-EntraDiag'. PUT semantics: changing
    the name creates a NEW setting (the old one stays).

.PARAMETER Categories
    Optional override of the category list. Default: the 8 categories above.

.OUTPUTS
    pscustomobject @{ Name; Created; WorkspaceResourceId; Categories; Url }

.NOTES
    Status: v2.2.136 -- new in /api/apply Phase 4.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$WorkspaceResourceId,
    [Parameter()]          [string]$Name = 'SI-EntraDiag',
    [Parameter()]          [string[]]$Categories = @(
        'SignInLogs','AuditLogs','NonInteractiveUserSignInLogs',
        'ServicePrincipalSignInLogs','ManagedIdentitySignInLogs',
        'UserRiskEvents','ProvisioningLogs','MicrosoftGraphActivityLogs'
    )
)

$ErrorActionPreference = 'Stop'

function _Step([string]$msg) { Write-Host "  [STEP] $msg" -ForegroundColor Cyan }
function _Ok  ([string]$msg) { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function _Info([string]$msg) { Write-Host "  [INFO] $msg" -ForegroundColor Gray }
function _Warn([string]$msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "=== Set-SIEntraDiagnosticSetting ===" -ForegroundColor Cyan
_Info ("setting name : {0}" -f $Name)
_Info ("workspace    : {0}" -f $WorkspaceResourceId)
_Info ("categories   : {0}" -f ($Categories -join ', '))
Write-Host ""

# ---------- Acquire ARM token (Az.Accounts 5.0+ returns SecureString) ----------
_Step "acquire ARM access token"
Import-Module Az.Accounts -ErrorAction Stop
$ctx = Get-AzContext -ErrorAction Stop
if (-not $ctx) { throw 'No Az context. Run Connect-AzAccount before launching the wizard.' }

$rawToken = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop
if ($rawToken.Token -is [System.Security.SecureString]) {
    # Az.Accounts 5.0+: SecureString. Marshal via BSTR.
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($rawToken.Token)
    try { $accessToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
} else {
    $accessToken = [string]$rawToken.Token
}
_Ok "token acquired"

# ---------- Build payload ----------
$logs = @()
foreach ($c in $Categories) {
    $logs += [ordered]@{
        category = $c
        enabled  = $true
        retentionPolicy = [ordered]@{ days = 0; enabled = $false }
    }
}
$body = [ordered]@{
    properties = [ordered]@{
        workspaceId = $WorkspaceResourceId
        logs        = $logs
    }
} | ConvertTo-Json -Depth 8 -Compress

# ---------- PUT to tenant-scope diagnosticSettings ----------
$apiVersion = '2017-04-01'
$uri = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/$Name`?api-version=$apiVersion"
_Step ("PUT {0}" -f $uri)

$headers = @{
    Authorization = "Bearer $accessToken"
    'Content-Type' = 'application/json'
}

try {
    $resp = Invoke-RestMethod -Method PUT -Uri $uri -Headers $headers -Body $body -ErrorAction Stop
    _Ok ("Entra Diagnostic Setting '{0}' created / updated" -f $Name)
} catch {
    $msg = $_.Exception.Message
    # Surface AuthorizationFailed clearly so the operator knows it's a role
    # gap, not a bug. The aadiam scope requires Security Admin or Global
    # Admin; subscription-level Owner is not sufficient.
    if ($msg -match 'AuthorizationFailed' -or $msg -match 'Forbidden' -or $msg -match '403') {
        throw ("AuthorizationFailed creating Entra Diagnostic Setting. " +
               "The signed-in operator needs the Entra 'Security Administrator' or 'Global Administrator' " +
               "role at tenant scope. Subscription-level Owner is NOT sufficient -- aadiam diagnosticSettings " +
               "are tenant-scoped. Original: $msg")
    }
    throw
}

[pscustomobject]@{
    Name                = $Name
    Created             = $true
    WorkspaceResourceId = $WorkspaceResourceId
    Categories          = $Categories
    Url                 = $uri
}
