#Requires -Version 5.1
<#
    Asset tagging's ACTIVITY LOG (#236): one row per planned or executed write, sent to the asset-tag activity table
    (SI_AssetTagActivity_CL through dcr-si-assettag-activity, the names SI_AssetTagActivityTable /
    SI_AssetTagActivityDcr override) -- the same table the profilers' read-only tagging stage fills with WouldApply rows.

    WHY. Asset tagging is the only SecurityInsight engine that WRITES to the customer's tenant (Defender machine tags,
    Azure resource tags, Entra custom security attributes). In a report-only run every write it WOULD make is a row with
    Status = WouldApply; in a run that writes, every write it MADE is a row with Status = Applied, and every refused or
    failed one is a row too. So what the engine did -- or would do -- is visible in Log Analytics and in the web app,
    not only in a console transcript.

    Status values: WouldApply | Applied | AlreadyPresent | Failed | Skipped.
    Target values: Defender (machine tag) | Azure (resource tag) | Entra (custom security attribute).

    Nothing here sends anything unless Publish-ATActivity is called, and that needs the install's workspace, data
    collection endpoint and DCR resource group (SI_WorkspaceResourceId, SI_DceName, SI_DcrResourceGroup). Without them
    it says so and returns; the rows stay in the run's transcript summary.

    PS 5.1 safe: no ?. / ??.
#>

if (-not (Get-Variable -Name ATActivity -Scope Script -ErrorAction SilentlyContinue) -or $null -eq $script:ATActivity) {
    $script:ATActivity = New-Object System.Collections.Generic.List[object]
}

function New-ATActivityRow {
    <# PURE. One activity row. AssetTierLevel is read from the tag name ('<stem>--tier<N>--SI'), -1 when it carries none. #>
    param(
        [Parameter(Mandatory)][ValidateSet('Defender', 'Azure', 'Entra')][string]$Target,
        [Parameter(Mandatory)][ValidateSet('WouldApply', 'Applied', 'AlreadyPresent', 'Failed', 'Skipped')][string]$Status,
        [string]$Rule, [string]$RuleMode, [string]$QueryEngine,
        [string]$TargetId, [string]$TargetName, [string]$AssetTag, [string]$AssetTagType,
        [string]$ErrorMessage, [bool]$WhatIf = $false,
        [string]$RunId = [string]$global:SI_AssetTaggingRunId,
        [string]$AuthMode = [string]$global:SI_AssetTaggingAuthMode,
        [datetime]$CollectionTime = [datetime]::UtcNow
    )
    $tier = -1
    $m = [regex]::Match([string]$AssetTag, '--tier(\d+)--SI$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($m.Success) { $tier = [int]$m.Groups[1].Value }
    [pscustomobject][ordered]@{
        CollectionTime = $CollectionTime.ToUniversalTime().ToString('o')
        SI_RunId       = $RunId
        SI_Engine      = 'asset-tagging'
        AssetTagName   = $Rule
        Mode           = $RuleMode
        QueryEngine    = $QueryEngine
        Target         = $Target
        TargetId       = $TargetId
        TargetName     = $TargetName
        AssetTag       = $AssetTag
        AssetTagType   = $AssetTagType
        AssetTierLevel = $tier
        Status         = $Status
        WhatIf         = $WhatIf
        RunMode        = $(if ($WhatIf) { 'report' } else { 'apply' })
        SignIn         = $AuthMode
        ErrorMessage   = $ErrorMessage
    }
}

function Add-ATActivity {
    <# Record one row (New-ATActivityRow's parameters). Returns nothing. #>
    param(
        [Parameter(Mandatory)][string]$Target, [Parameter(Mandatory)][string]$Status,
        [string]$Rule, [string]$RuleMode, [string]$QueryEngine,
        [string]$TargetId, [string]$TargetName, [string]$AssetTag, [string]$AssetTagType,
        [string]$ErrorMessage, [bool]$WhatIf = $false
    )
    if ($null -eq $script:ATActivity) { $script:ATActivity = New-Object System.Collections.Generic.List[object] }
    $script:ATActivity.Add((New-ATActivityRow @PSBoundParameters))
}

function Get-ATActivity { if ($null -eq $script:ATActivity) { return @() }; return $script:ATActivity.ToArray() }

function Clear-ATActivity { $script:ATActivity = New-Object System.Collections.Generic.List[object] }

function Get-ATActivitySummary {
    <# PURE. Counts per Status, for the run's last line. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $out = [ordered]@{ WouldApply = 0; Applied = 0; AlreadyPresent = 0; Failed = 0; Skipped = 0 }
    foreach ($r in @($Rows)) { $s = [string]$r.Status; if ($out.Contains($s)) { $out[$s]++ } }
    [pscustomobject]$out
}

function Get-ATActivityAuthParams {
    <#
        PURE. The sign-in AzLogDcrIngestPS (or its REST twin) posts the rows with -- the SAME identity the run tags as:
        the managed identity when its switch is on, otherwise the SPN by certificate, otherwise by secret. $null when
        none is set (nothing is posted).
    #>
    param([hashtable]$Globals)
    if (-not $Globals) { $Globals = @{}; foreach ($v in (Get-Variable -Scope Global)) { $Globals[$v.Name] = $v.Value } }
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    $app = [string](& $g 'SpnClientId'); if (-not $app) { $app = [string](& $g 'SI_SPN_AppId') }
    $tid = [string](& $g 'SpnTenantId'); if (-not $tid) { $tid = [string](& $g 'SI_SPN_TenantId') }
    if ([bool](& $g 'SI_UseManagedIdentity')) {
        $p = @{ UseManagedIdentity = $true }
        if ($app) { $p['AzAppId'] = $app }
        if ($tid) { $p['TenantId'] = $tid }
        $cid = [string](& $g 'SI_UAMI_ClientId'); if ($cid) { $p['ManagedIdentityClientId'] = $cid }
        return $p
    }
    $thumb = [string](& $g 'SpnCertificateThumbprint'); if (-not $thumb) { $thumb = [string](& $g 'SI_SPN_CertThumbprint') }
    $sec = [string](& $g 'SpnClientSecret'); if (-not $sec) { $sec = [string](& $g 'SI_SPN_Secret') }
    if ($app -and $tid -and $thumb) { return @{ AzAppId = $app; AzAppCertificateThumbprint = $thumb; TenantId = $tid } }
    if ($app -and $tid -and $sec) { return @{ AzAppId = $app; AzAppSecret = $sec; TenantId = $tid } }
    return $null
}

function Publish-ATActivity {
    <#
        Send the run's activity rows to the asset-tag activity table. Returns @{ Published; Rows; Table; Dcr; Reason }.
        Never throws: a run whose writes are done must not be reported as failed because its log could not be sent --
        the failure is returned (and printed by the caller) instead. -Send is a test seam { param($Rows, $Table, $Dcr) }.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(Get-ATActivity), [scriptblock]$Send, [hashtable]$Globals)
    if (-not $Globals) { $Globals = @{}; foreach ($v in (Get-Variable -Scope Global)) { $Globals[$v.Name] = $v.Value } }
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    $table = if ([string](& $g 'SI_AssetTagActivityTable')) { [string](& $g 'SI_AssetTagActivityTable') } else { 'SI_AssetTagActivity' }
    $dcr   = if ([string](& $g 'SI_AssetTagActivityDcr'))   { [string](& $g 'SI_AssetTagActivityDcr') }   else { 'dcr-si-assettag-activity' }
    $res = [ordered]@{ Published = $false; Rows = @($Rows).Count; Table = $table; Dcr = $dcr; Reason = '' }
    if (@($Rows).Count -eq 0) { $res.Reason = 'no planned or executed writes in this run'; return [pscustomobject]$res }
    if ($Send) {
        try { & $Send @($Rows) $table $dcr; $res.Published = $true }
        catch { $res.Reason = $_.Exception.Message }
        return [pscustomobject]$res
    }
    $missing = @('SI_WorkspaceResourceId', 'SI_DceName', 'SI_DcrResourceGroup' | Where-Object { [string]::IsNullOrWhiteSpace([string](& $g $_)) })
    if ($missing.Count) { $res.Reason = ('the activity log is not configured ({0} not set)' -f ($missing -join ', ')); return [pscustomobject]$res }
    $auth = Get-ATActivityAuthParams -Globals $Globals
    if (-not $auth) { $res.Reason = 'no identity to send the activity log with'; return [pscustomobject]$res }
    try {
        if (-not (Get-Command -Name Send-SILogData -ErrorAction SilentlyContinue)) {
            . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-LogIngest.ps1'))
        }
        if (Get-Command -Name Initialize-SIIngestGlobals -ErrorAction SilentlyContinue) { Initialize-SIIngestGlobals }
        $spnObjectId = if ($global:SI_SPN_ObjectId) { [string]$global:SI_SPN_ObjectId } else { [string]$global:SI_LogIngest_ObjectId }
        $data = @($Rows)
        if (Get-Command -Name Select-SIIngestTarget -ErrorAction SilentlyContinue) { Select-SIIngestTarget -AuthParams $auth -DcrName $dcr }
        # THE WHOLE SET DECIDES THE SCHEMA, never a sample (audit #48): the module declares the union of the columns it is handed.
        $null = Update-SILogTableSchema -AzLogWorkspaceResourceId ([string]$global:SI_WorkspaceResourceId) @auth `
            -DceName ([string]$global:SI_DceName) -DcrName $dcr -DcrResourceGroup ([string]$global:SI_DcrResourceGroup) `
            -TableName $table -Data $data -LogIngestServicePricipleObjectId $spnObjectId `
            -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false -AzLogDcrTableCreateFromAnyMachine $true -AzLogDcrTableCreateFromReferenceMachine @() 4>$null
        if (Get-Command -Name Select-SIIngestTarget -ErrorAction SilentlyContinue) { Select-SIIngestTarget -AuthParams $auth -DcrName $dcr }
        $data = Repair-SILogColumnName -Data $data 4>$null
        $data = Format-SILogRowsToSchema -Data $data 4>$null
        $null = Send-SILogData -DceName ([string]$global:SI_DceName) -DcrName $dcr -Data $data -TableName $table @auth 4>$null
        $res.Published = $true
    } catch {
        $res.Reason = $_.Exception.Message
    }
    [pscustomobject]$res
}
