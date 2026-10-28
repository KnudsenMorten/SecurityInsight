#Requires -Version 5.1
<#
    THE ONLY SIGN-IN OF THE SETTINGS PAGE: reads the last profile snapshot for the tier-rule dry run. Run as its own
    Windows PowerShell process by Read-SITierSnapshot (SI-TierDryRun.ps1), so the install's config globals and the
    engines' credential never enter the wizard's process. READ-ONLY: one KQL query per engine, nothing written.

    Sign-in = the engines' own (operator, 2026-10-02: "the rule dry-run signs in with the engines' SPN"):
      * the install's config layers, in the order an engine launcher loads them -- shared defaults, the endpoint
        launcher's defaults, config\SecurityInsight.custom.ps1, launcher\endpoint\LauncherConfig.custom.ps1 -- then the
        same SI_SPN_* -> Spn* bridge, then the community launcher's connect order: managed identity, SPN + Key Vault
        secret, SPN + certificate, SPN + secret (Community installs often use a secret -- it stays supported);
      * or an explicit certificate connection in the request (TenantId, ClientId, CertificateThumbprint,
        WorkspaceResourceId) -- for an install whose sign-in comes from the platform, not its config files.
    🔒 Initialize-LauncherConfig is NOT called: it writes a config snapshot into logs\ and prunes old ones, and a dry
    run writes nothing. The layers are dot-sourced directly instead.
    🔒 Az context autosave is off for this process: the sign-in never lands in the operator's saved Azure context.

    Output: exactly one line '#SI-SNAPSHOT#<base64 UTF-8 JSON>#' -- @{ error; auth; notes; engines = @{ <engine> =
    @{ snapshotTime; rows } } }. Everything else the config prints is ignored by the caller.
#>
param([Parameter(Mandatory)][string]$Request)

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-AzRest.ps1') }
if (-not (Get-Command -Name Read-SILaParts -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-LaParts.ps1') }

$result = [ordered]@{ error = $null; auth = $null; notes = @(); engines = [ordered]@{} }
$notes = New-Object System.Collections.Generic.List[string]
$signedIn = $false
try {
    $req = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Request)) | ConvertFrom-Json
    $root = [string]$req.installPath
    if (-not $root -or -not (Test-Path -LiteralPath (Join-Path $root 'config'))) { throw "not a SecurityInsight installation: $root" }
    $conn = $req.connection

    if (-not $conn) {
        # ---- the install's config, as an engine launcher reads it (community) ----
        $layers = @(
            (Join-Path $root 'launcher\_lib\SecurityInsight.shared-defaults.ps1')
            (Join-Path $root 'launcher\endpoint\LauncherConfig.defaults.ps1')
            (Join-Path $root 'config\SecurityInsight.custom.ps1')
            (Join-Path $root 'launcher\endpoint\LauncherConfig.custom.ps1')
        )
        foreach ($l in $layers) {
            if (-not (Test-Path -LiteralPath $l)) { continue }
            try { . $l } catch { $notes.Add(('{0}: {1}' -f (Split-Path -Leaf $l), $_.Exception.Message)) }
        }
        if ($global:SI_SPN_TenantId       -and -not $global:SpnTenantId)              { $global:SpnTenantId              = [string]$global:SI_SPN_TenantId }
        if ($global:SI_SPN_AppId          -and -not $global:SpnClientId)              { $global:SpnClientId              = [string]$global:SI_SPN_AppId }
        if ($global:SI_SPN_Secret         -and -not $global:SpnClientSecret)          { $global:SpnClientSecret          = [string]$global:SI_SPN_Secret }
        if ($global:SI_SPN_CertThumbprint -and -not $global:SpnCertificateThumbprint) { $global:SpnCertificateThumbprint = [string]$global:SI_SPN_CertThumbprint }
    }

    $ErrorActionPreference = 'Stop'
    if (-not $conn -and -not $global:SpnTenantId -and -not [bool]$global:UseManagedIdentity) {
        throw 'no sign-in is configured for the engines: set SI_SPN_TenantId and SI_SPN_AppId with SI_SPN_CertThumbprint or SI_SPN_Secret in config\SecurityInsight.custom.ps1 (the engines read the same values)'
    }
    # The dry run reads over plain REST, like the engines -- no PowerShell module needed.
    Disable-SIAzContextAutosave -Scope Process | Out-Null

    # ---- sign in: the community launcher's order ----
    if ($conn) {
        Connect-SIAzAccount -ServicePrincipal -Tenant ([string]$conn.TenantId) -ApplicationId ([string]$conn.ClientId) -CertificateThumbprint ([string]$conn.CertificateThumbprint) -Scope Process -WarningAction SilentlyContinue | Out-Null
        $result.auth = 'SPN + certificate (given)'
    } else {
        if ([bool]$global:UseManagedIdentity) {
            Connect-SIAzAccount -Identity -Scope Process -WarningAction SilentlyContinue | Out-Null
            $result.auth = 'managed identity'
        } elseif ($global:SpnKeyVaultName -and $global:SpnSecretName) {
            if (-not $global:SpnClientId) { throw 'SPN + Key Vault sign-in needs SpnClientId (SI_SPN_AppId)' }
            Connect-SIAzAccount -Identity -Scope Process -WarningAction SilentlyContinue | Out-Null
            $sec = (Get-SIAzKeyVaultSecret -VaultName $global:SpnKeyVaultName -Name $global:SpnSecretName).SecretValue
            if (-not $sec) { throw ("Key Vault returned no value for the secret '{0}'" -f $global:SpnSecretName) }
            Disconnect-SIAzAccount -Scope Process -WarningAction SilentlyContinue | Out-Null
            Connect-SIAzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential ([pscredential]::new([string]$global:SpnClientId, $sec)) -Scope Process -WarningAction SilentlyContinue | Out-Null
            $result.auth = 'SPN + Key Vault secret'
        } elseif ($global:SpnCertificateThumbprint) {
            if (-not $global:SpnClientId) { throw 'SPN + certificate sign-in needs SI_SPN_AppId' }
            Connect-SIAzAccount -ServicePrincipal -Tenant $global:SpnTenantId -ApplicationId $global:SpnClientId -CertificateThumbprint $global:SpnCertificateThumbprint -Scope Process -WarningAction SilentlyContinue | Out-Null
            $result.auth = 'SPN + certificate'
        } elseif ($global:SpnClientId -and $global:SpnClientSecret) {
            $sec = ConvertTo-SecureString -String ([string]$global:SpnClientSecret) -AsPlainText -Force
            Connect-SIAzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential ([pscredential]::new([string]$global:SpnClientId, $sec)) -Scope Process -WarningAction SilentlyContinue | Out-Null
            $result.auth = 'SPN + secret'
        } else {
            throw 'no sign-in is configured for the engines: SI_SPN_AppId with SI_SPN_CertThumbprint or SI_SPN_Secret is missing in config\SecurityInsight.custom.ps1'
        }
    }
    $signedIn = $true

    # ---- the workspace the engines write to ----
    $wsRid = if ($conn -and $conn.WorkspaceResourceId) { [string]$conn.WorkspaceResourceId } else { [string]$global:SI_WorkspaceResourceId }
    $m = [regex]::Match($wsRid, '^/subscriptions/(?<sub>[^/]+)/resourcegroups/(?<rg>[^/]+)/providers/microsoft\.operationalinsights/workspaces/(?<name>[^/]+)$', 'IgnoreCase')
    if (-not $m.Success) { throw 'SI_WorkspaceResourceId is not set to a Log Analytics workspace resource id in the config -- the dry run reads the profile tables there' }
    Set-SIAzContext -SubscriptionId $m.Groups['sub'].Value -Scope Process -WarningAction SilentlyContinue | Out-Null
    $ws = Get-SIAzOperationalInsightsWorkspace -ResourceGroupName $m.Groups['rg'].Value -Name $m.Groups['name'].Value

    foreach ($p in $req.queries.PSObject.Properties) {
        # #639 lane 4: an engine's whole snapshot -- read in parts when one answer cannot carry it; a cut answer is refused
        # (the dry run then says why, never shows part of the snapshot as all of it)
        $resp = Read-SILaParts -WorkspaceId ([string]$ws.CustomerId) -Query ([string]$p.Value) -Wait 300 -What ('the {0} snapshot' -f $p.Name) -Log { param($l, $m) $notes.Add([string]$m) }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($r in @($resp.Rows)) {
            $o = [ordered]@{}; foreach ($q in $r.PSObject.Properties) { $o[$q.Name] = $q.Value }
            $rows.Add($o)
        }
        $t = if ($rows.Count) { [string]$rows[0]['CollectionTime'] } else { $null }
        $result.engines[$p.Name] = [ordered]@{ snapshotTime = $t; rows = [object[]]$rows.ToArray() }
    }
} catch {
    $result.error = $_.Exception.Message
} finally {
    if ($signedIn) { try { Disconnect-SIAzAccount -Scope Process -WarningAction SilentlyContinue | Out-Null } catch { } }
}
$result.notes = [string[]]$notes.ToArray()
$json = $result | ConvertTo-Json -Depth 8 -Compress
[Console]::Out.WriteLine('#SI-SNAPSHOT#' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json)) + '#')
