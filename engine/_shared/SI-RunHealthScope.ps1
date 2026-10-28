#Requires -Version 5.1
<#
    A run-health START and END record for an engine that is not driven by the profiling orchestrator or Risk Analysis
    -- the trend rollup and asset tagging. Without them those runs left nothing in SI_RunHealth_CL, so a crashed or
    failed run could not be told from one that never ran, and no telemetry run report was sent for them either (that
    report goes out at the run-health END).

    Usage (the engine body between the two calls, End in a finally):
        $rh = Start-SIRunHealth -Engine 'asset-trend'
        $rhExit = 'success'; $rhMsg = ''
        try { ... } catch { $rhExit = 'error'; $rhMsg = $_.Exception.Message; throw }
        finally { Stop-SIRunHealth -Context $rh -ExitReason $rhExit -ErrorMessage $rhMsg }

    Neither function ever throws: a health record must never be the reason a run fails. Same record shape as the
    other engines (Send-SIRunHealthRow); a dry run writes no record, as everywhere else.
    PS 5.1 safe.
#>

if (-not (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue)) {
    try { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling/shared/Send-SIRunHealthRow.ps1') } catch { }
}

function New-SIRunHealthContext {
    <# PURE. The run context every run-health record and the telemetry run report are built from. #>
    param([Parameter(Mandatory)][string]$Engine, [string]$RunId)
    if ([string]::IsNullOrWhiteSpace($RunId)) { $RunId = [guid]::NewGuid().ToString() }
    $now = [datetime]::UtcNow
    [pscustomobject]@{
        RunId          = $RunId
        Engine         = $Engine
        ShardIndex     = 0
        ShardCount     = 1
        StartedAt      = $now
        CollectionTime = $now
    }
}

function Initialize-SIRunHealthIdentity {
    <# Fill the SI_SPN_* names the record's sign-in reads from the older names an install may carry (Spn*, then the
       platform's HighPriv_Modern_*). Only EMPTY names are filled; a value already set always stands. #>
    $pairs = @(
        @('SI_SPN_TenantId',       'SpnTenantId',              'HighPriv_Modern_TenantID'),
        @('SI_SPN_AppId',          'SpnClientId',              'HighPriv_Modern_ApplicationID_Azure'),
        @('SI_SPN_CertThumbprint', 'SpnCertificateThumbprint', 'HighPriv_Modern_CertificateThumbprint_Azure'),
        @('SI_SPN_Secret',         'SpnClientSecret',          'HighPriv_Modern_ApplicationSecret_Azure'),
        @('SI_SPN_ObjectId',       'SpnObjectId',              '')
    )
    foreach ($p in $pairs) {
        $cur = [string](Get-Variable -Name $p[0] -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
        if (-not [string]::IsNullOrWhiteSpace($cur)) { continue }
        foreach ($src in @($p[1], $p[2])) {
            if (-not $src) { continue }
            $v = [string](Get-Variable -Name $src -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
            if (-not [string]::IsNullOrWhiteSpace($v)) { Set-Variable -Name $p[0] -Scope Global -Value $v; break }
        }
    }
    # A certificate wins over a secret, as in the profiling engines -- the record is then signed in by certificate.
    if ($global:SI_SPN_CertThumbprint -and $global:SI_SPN_Secret) { $global:SI_SPN_Secret = $null }
}

function Send-SIRunHealthScoped {
    <# One record. -RecordInReportMode: the engine's WhatIfMode means "change nothing in the estate" (asset tagging's
       report-only default), not "write nothing to Log Analytics" -- that engine still writes its activity table, so its
       health record is written too. WhatIfMode is restored afterwards, whatever happens. #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Phase, [switch]$RecordInReportMode,
          [int]$AssetCount = -1, [string]$ExitReason = '', [string]$ErrorMessage = '')
    if (-not (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue)) { return }
    $savedWhatIf = $global:WhatIfMode
    try {
        if ($RecordInReportMode) { $global:WhatIfMode = $false }
        if ($Phase -eq 'Start') { Send-SIRunHealthRow -RunContext $Context -Phase 'Start' 4>$null }
        else { Send-SIRunHealthRow -RunContext $Context -Phase 'End' -AssetCount $AssetCount -ExitReason $ExitReason -ErrorMessage $ErrorMessage 4>$null }
    } catch { }
    finally { $global:WhatIfMode = $savedWhatIf }
}

function Start-SIRunHealth {
    <# Sends the START record and returns the run context for Stop-SIRunHealth. Never throws. #>
    param([Parameter(Mandatory)][string]$Engine, [string]$RunId, [switch]$RecordInReportMode)
    $ctx = New-SIRunHealthContext -Engine $Engine -RunId $RunId
    try { $ctx | Add-Member -NotePropertyName 'RecordInReportMode' -NotePropertyValue ([bool]$RecordInReportMode) -Force } catch { }
    try { Initialize-SIRunHealthIdentity } catch { }
    try { if (Get-Command -Name Initialize-SIIngestGlobals -ErrorAction SilentlyContinue) { Initialize-SIIngestGlobals } } catch { }
    Send-SIRunHealthScoped -Context $ctx -Phase 'Start' -RecordInReportMode:([bool]$RecordInReportMode)
    return $ctx
}

function Stop-SIRunHealth {
    <# Sends the END record (which also sends the telemetry run report). Once per context; never throws. #>
    param(
        [AllowNull()]$Context,
        [string]$ExitReason = 'success',
        [string]$ErrorMessage = '',
        [int]$AssetCount = -1
    )
    if ($null -eq $Context) { return }
    if ($Context.PSObject.Properties['EndSent'] -and $Context.EndSent) { return }
    try { $Context | Add-Member -NotePropertyName 'EndSent' -NotePropertyValue $true -Force } catch { }
    if ($ExitReason -notin @('success', 'success-partial', 'dry-run', 'throttled', 'error', 'settings-error')) { $ExitReason = 'error' }   # dry-run: #276, throttled: #532
    $inReport = $false
    if ($Context.PSObject.Properties['RecordInReportMode']) { $inReport = [bool]$Context.RecordInReportMode }
    Send-SIRunHealthScoped -Context $Context -Phase 'End' -RecordInReportMode:$inReport `
        -AssetCount $AssetCount -ExitReason $ExitReason -ErrorMessage $ErrorMessage
}
