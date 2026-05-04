#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.KeyVault
<#
    SecurityInsight v2.2 -- one-shot auth + workspace bootstrap.

    Reads SPN credentials and workspace pointers from the customer's Key
    Vault + platform-defaults, then appends them to
    config/SecurityInsight.custom.ps1 as $global:SI_SPN_* + $global:SI_*
    variables.

    PRECEDENCE:
      1. Static globals win    -- if $global:SI_SPN_AppId is already set in
                                  the custom file BEFORE this script runs,
                                  no KV lookup happens. Customer fully
                                  controls the SPN choice.
      2. KV lookup is fallback -- if the static globals aren't set, pull
                                  from KeyVault using the canonical names.
                                  Default: Modern-ApplicationId-Azure +
                                  Modern-Secret-Azure (one SPN does it all:
                                  Graph reads, ARG, LA ingest).

    Single-SPN model: the same SPN handles BOTH Graph reads (Defender
    hunting + Entra) AND Log Analytics DCR ingest. Simpler than the
    25 two-SPN split. The SPN must already have:
      - Microsoft Graph app roles: ThreatHunting.Read.All, Device.Read.All,
        User.Read.All, Application.Read.All
      - Reader on subscription (for Search-AzGraph)
      - Monitoring Metrics Publisher on the DCR resource group
      - Storage Blob/Table/Queue Data Contributor on the v2.2 storage account
        (only if using OAuth storage; not needed when using shared key)

    Backwards-compat: if the custom file already has the legacy
    $global:SI_Graph_AppId / $global:SI_LogIngest_AppId entries from
    25 deployments, this script ALSO writes the equivalent
    SI_SPN_* aliases so the new code path works without manual cleanup.
#>

[CmdletBinding()]
param(
    # Optional: only consulted when the customer hasn't already set
    # $global:SI_SPN_AppId / SI_SPN_Secret in custom.ps1 (static-wins-over-KV).
    # If you keep your SPN secrets in custom.ps1 directly, omit this entirely.
    [Parameter()][string]$KeyVaultName,

    [Parameter()][string]$CustomFile = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\config\SecurityInsight.custom.ps1',

    # KV secret-name overrides. When NOT supplied, the script auto-detects:
    #   1. Try canonical SI_-prefixed names ('SI_SPN_AppId' / 'SI_SPN_Secret') --
    #      mirrors the global variable names so customers with a dedicated SI SPN
    #      get parity between their KV layout and their custom.ps1 globals.
    #   2. Fall back to the 2linkit internal-mode names
    #      ('Modern-ApplicationId-Azure' / 'Modern-Secret-Azure') so existing
    #      internal deployments keep working without flag changes.
    # When supplied explicitly, the auto-detect is skipped and exactly the
    # secret names you pass are used (any naming convention is allowed).
    [Parameter()][string]$SpnAppIdSecretName,
    [Parameter()][string]$SpnSecretSecretName
)

$ErrorActionPreference = 'Stop'

# ---- helper: SPN auth probe (OAuth client_credentials against Entra) -----
# Returns @{ Ok=<bool>; ExpiresIn=<int seconds>; Error=<string> }. Used by both
# the early-return path (existing block in custom.ps1) and the full bootstrap
# path so the operator ALWAYS sees explicit confirmation that the resolved
# credential actually authenticates against the target tenant.
function Test-SISpnConnection {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$AppId,
        [Parameter(Mandatory)][string]$Secret,
        [string]$Resource = 'https://graph.microsoft.com/.default'
    )
    $body = @{
        grant_type    = 'client_credentials'
        client_id     = $AppId
        client_secret = $Secret
        scope         = $Resource
    }
    try {
        $resp = Invoke-RestMethod -Method Post `
            -Uri ('https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $TenantId) `
            -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
        return @{ Ok = $true; ExpiresIn = [int]$resp.expires_in }
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        return @{ Ok = $false; Error = $msg }
    }
}

function Write-SIAuthResult {
    param(
        [Parameter(Mandatory)][hashtable]$Probe,
        [Parameter(Mandatory)][string]$AuthSource,
        [Parameter(Mandatory)][string]$AppId,
        [Parameter(Mandatory)][string]$TenantId,
        [string]$ExtraDetail
    )
    $detail = if ($ExtraDetail) { "  ($ExtraDetail)" } else { '' }
    if ($Probe.Ok) {
        Write-Host ''
        Write-Host '  CONNECTED OK' -ForegroundColor Green
        Write-Host ('    AUTH METHOD   : ServicePrincipal + Client Secret') -ForegroundColor Green
        Write-Host ('    AUTH SOURCE   : {0}{1}' -f $AuthSource, $detail) -ForegroundColor Green
        Write-Host ('    SPN AppId     : {0}' -f $AppId) -ForegroundColor Green
        Write-Host ('    TenantId      : {0}' -f $TenantId) -ForegroundColor Green
        Write-Host ('    Token expires : {0} seconds (Microsoft Graph access token acquired)' -f $Probe.ExpiresIn) -ForegroundColor Green
        Write-Host ''
    } else {
        Write-Host ''
        Write-Host '  AUTH FAILED' -ForegroundColor Red
        Write-Host ('    AUTH METHOD   : ServicePrincipal + Client Secret (attempted)') -ForegroundColor Red
        Write-Host ('    AUTH SOURCE   : {0}{1}' -f $AuthSource, $detail) -ForegroundColor Red
        Write-Host ('    SPN AppId     : {0}' -f $AppId) -ForegroundColor Red
        Write-Host ('    TenantId      : {0}' -f $TenantId) -ForegroundColor Red
        Write-Host ('    Error         : {0}' -f $Probe.Error) -ForegroundColor Red
        Write-Host ''
        throw 'SPN authentication test failed -- credentials do not work against the target tenant. See error above.'
    }
}

Write-Host ''
Write-Host '=== SecurityInsight auth + workspace bootstrap ==='
Write-Host ('  KeyVault    : {0}' -f $(if ($KeyVaultName) { $KeyVaultName } else { '<not supplied>' }))
Write-Host ('  CustomFile  : {0}' -f $CustomFile)
Write-Host ''

# Load existing custom file so we can honour static-wins-over-KV precedence.
if (Test-Path $CustomFile) {
    . $CustomFile
}

# Idempotency: if the SPN block already sits in the custom file, skip
# rewrites unless force-re-run -- but ALWAYS verify the existing creds
# actually authenticate so the operator gets explicit "connected OK"
# confirmation, not silent assumption.
$customRaw = if (Test-Path $CustomFile) { Get-Content -Path $CustomFile -Raw } else { '' }
if ($customRaw -match '\$global:SI_SPN_AppId' -and -not $global:SI_RebuildAuthBlock) {
    $existingAppId    = [string]$global:SI_SPN_AppId
    $existingSecret   = [string]$global:SI_SPN_Secret
    $existingTenantId = [string]$global:SI_SPN_TenantId
    if (-not $existingAppId -or -not $existingSecret -or -not $existingTenantId) {
        throw "custom.ps1 contains an SI_SPN_AppId line but one of SI_SPN_AppId / SI_SPN_Secret / SI_SPN_TenantId is empty after dot-source. Inspect $CustomFile."
    }
    $probe = Test-SISpnConnection -TenantId $existingTenantId -AppId $existingAppId -Secret $existingSecret
    Write-SIAuthResult -Probe $probe -AuthSource 'custom.ps1' -AppId $existingAppId -TenantId $existingTenantId `
                       -ExtraDetail 'existing SI_SPN_AppId block; no file rewrite. Set $global:SI_RebuildAuthBlock = $true to re-pull.'
    return
}

# Static-wins-over-KV: did the customer already set $global:SI_SPN_* via
# their own pre-loaded custom file or environment? If so, SKIP the KV
# fetch entirely.
$staticSpnPresent = -not [string]::IsNullOrWhiteSpace([string]$global:SI_SPN_AppId) `
                  -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_SPN_Secret)

if ($staticSpnPresent) {
    Write-Host '[1/4] AUTH SOURCE: custom.ps1 ($global:SI_SPN_AppId / $global:SI_SPN_Secret read directly from file)'
    $spnAppId  = [string]$global:SI_SPN_AppId
    $spnSecret = [string]$global:SI_SPN_Secret
} else {
    # Backwards compat: if the legacy $global:SI_Graph_AppId is already set
    #, copy it forward to SI_SPN_*.
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_Graph_AppId)) {
        Write-Host '[1/4] AUTH SOURCE: custom.ps1 ($global:SI_Graph_AppId / $global:SI_Graph_Secret aliased to SI_SPN_*)'
        $spnAppId  = [string]$global:SI_Graph_AppId
        $spnSecret = [string]$global:SI_Graph_Secret
    } else {
        if ([string]::IsNullOrWhiteSpace($KeyVaultName)) {
            throw "No SPN credentials found. Either (a) set `$global:SI_SPN_AppId / SI_SPN_Secret in $CustomFile, or (b) re-run with -KeyVaultName <vault> (the script will auto-detect canonical 'SI_SPN_AppId' / 'SI_SPN_Secret' or fall back to internal-mode 'Modern-*-Azure' secret names; pass -SpnAppIdSecretName / -SpnSecretSecretName to override)."
        }

        function Get-KvSecretText {
            param($Vault, $Name)
            try {
                $sec = Get-AzKeyVaultSecret -VaultName $Vault -Name $Name -ErrorAction Stop
            } catch { return $null }
            if (-not $sec) { return $null }
            if ($sec.SecretValue) {
                return [System.Net.NetworkCredential]::new('', $sec.SecretValue).Password
            }
            return $sec.SecretValueText
        }

        # Auto-detect secret names when caller didn't pass them explicitly:
        #   priority 1 -- canonical SI_ names (matches $global:SI_SPN_* variable names)
        #   priority 2 -- internal-mode 'Modern-*-Azure' names
        # Caller-supplied -SpnAppIdSecretName / -SpnSecretSecretName always win.
        $appIdNameExplicit  = $PSBoundParameters.ContainsKey('SpnAppIdSecretName')  -and -not [string]::IsNullOrWhiteSpace($SpnAppIdSecretName)
        $secretNameExplicit = $PSBoundParameters.ContainsKey('SpnSecretSecretName') -and -not [string]::IsNullOrWhiteSpace($SpnSecretSecretName)

        $candidatePairs = @()
        if ($appIdNameExplicit -and $secretNameExplicit) {
            $candidatePairs += ,@($SpnAppIdSecretName, $SpnSecretSecretName)
        } else {
            $candidatePairs += ,@('SI_SPN_AppId',           'SI_SPN_Secret')           # priority 1 (preferred -- matches global names)
            $candidatePairs += ,@('Modern-ApplicationId-Azure','Modern-Secret-Azure')  # priority 2 (2linkit internal mode)
        }

        $spnAppId = $null; $spnSecret = $null; $resolvedAppName = $null; $resolvedSecretName = $null
        foreach ($pair in $candidatePairs) {
            $appName = $pair[0]; $secName = $pair[1]
            $appVal  = Get-KvSecretText -Vault $KeyVaultName -Name $appName
            $secVal  = Get-KvSecretText -Vault $KeyVaultName -Name $secName
            if ($appVal -and $secVal) {
                $spnAppId = $appVal; $spnSecret = $secVal
                $resolvedAppName = $appName; $resolvedSecretName = $secName
                break
            }
        }
        if (-not $spnAppId -or -not $spnSecret) {
            $tried = ($candidatePairs | ForEach-Object { '({0} / {1})' -f $_[0], $_[1] }) -join ', '
            throw "Could not resolve SPN credentials from Key Vault '$KeyVaultName'. Tried: $tried. Either grant the running identity Get-Secret on those names OR pass -SpnAppIdSecretName / -SpnSecretSecretName with the actual names you have."
        }
        Write-Host ('[1/4] AUTH SOURCE: KeyVault {0}  (secrets {1} / {2})' -f $KeyVaultName, $resolvedAppName, $resolvedSecretName)
    }
}
Write-Host ('       SPN AppId : {0}' -f $spnAppId)

Write-Host '[2/4] Resolving workspace + DCE/DCR globals from platform-defaults ...'
$tenantId = $global:TenantID
$wsResId  = $global:MainLogAnalyticsWorkspaceResourceId
$dceName  = $global:AzDceNameSrv
$dcrRG    = $global:AzDcrResourceGroupSrv

foreach ($pair in @(
    @{ Name = 'TenantID'; Value = $tenantId },
    @{ Name = 'MainLogAnalyticsWorkspaceResourceId'; Value = $wsResId },
    @{ Name = 'AzDceNameSrv'; Value = $dceName },
    @{ Name = 'AzDcrResourceGroupSrv'; Value = $dcrRG }
)) {
    if ([string]::IsNullOrWhiteSpace($pair.Value)) {
        throw "Required global '$($pair.Name)' is empty. Load PlatformConfiguration\config\platform-defaults.ps1 before running this bootstrap."
    }
    Write-Host ('       {0,-40} : {1}' -f $pair.Name, $pair.Value)
}

# Verify resolved credentials actually authenticate BEFORE writing them to
# disk. Acquires a short-lived Microsoft Graph access token via OAuth
# client_credentials flow against the target tenant. Failure aborts the
# bootstrap with a clear message instead of writing dud creds to custom.ps1.
$probe = Test-SISpnConnection -TenantId $tenantId -AppId $spnAppId -Secret $spnSecret
$authSourceLabel = if ($staticSpnPresent) { 'custom.ps1' }
                   elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SI_Graph_AppId)) { 'custom.ps1' }
                   else { 'KeyVault {0}' -f $KeyVaultName }
$authExtra = if ($staticSpnPresent) { '$global:SI_SPN_AppId / $global:SI_SPN_Secret read directly' }
             elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SI_Graph_AppId)) { 'legacy $global:SI_Graph_AppId / $global:SI_Graph_Secret aliased to SI_SPN_*' }
             else { 'secrets {0} / {1}' -f $resolvedAppName, $resolvedSecretName }
Write-SIAuthResult -Probe $probe -AuthSource $authSourceLabel -AppId $spnAppId -TenantId $tenantId -ExtraDetail $authExtra

# Resolve the SPN's ObjectId from its AppId (needed for DCR-level
# Monitoring Metrics Publisher grants AzLogDcrIngestPS performs).
$spnObjectId = $null
try {
    $sp = Get-AzADServicePrincipal -ApplicationId $spnAppId -ErrorAction Stop
    if ($sp) { $spnObjectId = $sp.Id }
} catch { }
if (-not $spnObjectId) {
    throw "Failed to resolve ObjectId for SPN AppId $spnAppId. Ensure the SPN exists in tenant $tenantId and the running account has Application.Read.All / Directory.Read.All."
}
Write-Host ('       SPN ObjectId : {0}' -f $spnObjectId)

Write-Host '[3/4] Building auth block ...'
$block = @"


# ============================================================================
#  v2.2 SI auth + workspace -- written by Bootstrap-Auth.ps1
# ============================================================================
# Single-SPN model: same credential handles Graph reads + LA ingest.
# Static globals here OVERRIDE Bootstrap-Auth's KV lookup on next run --
# delete these lines + re-run if you want a fresh KV pull.
`$global:SI_SPN_AppId           = '$spnAppId'
`$global:SI_SPN_Secret          = '$spnSecret'
`$global:SI_SPN_TenantId        = '$tenantId'
`$global:SI_SPN_ObjectId        = '$spnObjectId'

# Backwards-compat aliases for 25 callers that still read the
# old names. New code reads SI_SPN_* directly.
`$global:SI_Graph_AppId         = `$global:SI_SPN_AppId
`$global:SI_Graph_Secret        = `$global:SI_SPN_Secret
`$global:SI_Graph_TenantId      = `$global:SI_SPN_TenantId
`$global:SI_LogIngest_AppId     = `$global:SI_SPN_AppId
`$global:SI_LogIngest_Secret    = `$global:SI_SPN_Secret
`$global:SI_LogIngest_TenantId  = `$global:SI_SPN_TenantId
`$global:SI_LogIngest_ObjectId  = `$global:SI_SPN_ObjectId

`$global:SI_WorkspaceResourceId = '$wsResId'
`$global:SI_DceName             = '$dceName'
`$global:SI_DcrResourceGroup    = '$dcrRG'
"@

Write-Host '[4/5] Appending to custom.ps1 ...'
Add-Content -Path $CustomFile -Value $block -Encoding UTF8

Write-Host '[5/5] Granting Monitoring Metrics Publisher to SPN at DCR RG scope ...'
# AzLogDcrIngestPS uses this role to POST rows to the Log Ingestion API.
# Granted ONCE here (operator context = elevated). Stage Output runs with
# AzDcrSetLogIngestApiAppPermissionsDcrLevel=$false so the SPN doesn't
# need role-assignment perms at runtime.
$subId = ($wsResId -split '/')[2]
$dcrRgScope = '/subscriptions/{0}/resourceGroups/{1}' -f $subId, $dcrRG
$existing = Get-AzRoleAssignment -ObjectId $spnObjectId -RoleDefinitionName 'Monitoring Metrics Publisher' -Scope $dcrRgScope -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host ('       already granted -- {0}' -f $dcrRgScope)
} else {
    try {
        New-AzRoleAssignment -ObjectId $spnObjectId -RoleDefinitionName 'Monitoring Metrics Publisher' -Scope $dcrRgScope -ErrorAction Stop | Out-Null
        Write-Host ('       granted -- {0}' -f $dcrRgScope)
    } catch {
        Write-Warning ('       FAILED to grant role: {0}' -f $_.Exception.Message)
        Write-Warning ('       run manually as elevated user: az role assignment create --role "Monitoring Metrics Publisher" --assignee {0} --scope {1}' -f $spnObjectId, $dcrRgScope)
    }
}

Write-Host ''
Write-Host '  DONE. Globals available in next dot-source of custom.ps1.'
Write-Host '  Single-SPN globals: SI_SPN_AppId / Secret / TenantId / ObjectId.'
Write-Host '  Backwards-compat aliases: SI_Graph_* + SI_LogIngest_* point at the same values.'
