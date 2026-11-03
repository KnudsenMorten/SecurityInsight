#Requires -Version 5.1
<#
    #1049 F0 -- WHERE THE IDENTITY COLLECTION'S TIME GOES, MEASURED (coordinator-approved 2026-11-01: "measurement, no data
    change"). At one ring-2 install the identity step takes 13-19 hours every run; the log lines of the producer said when a
    phase STARTED, never how long it took, how often Microsoft asked SecurityInsight to slow down, or how long it then waited.

    Each phase of the identity producer's discovery (the role reads, the MFA registration, the role-holding groups, Azure RBAC,
    IdentityInfo, Exposure Graph, the user pages and the sign-in methods read inside them, the service principals and the
    application permissions read per principal, ...) is timed here and said TWICE:
      * one log line   "[timing] identity: <phase> took <s> s (<rows> rows; <detail>)";
      * one row in cfg.StepPhaseTime (engine\_shared\SI-StepPhase.ps1, Job 'identity', joined to the run by the job
        execution) -- readable through the Support app's SQL access at once, no log lag.
    A phase that runs once per page (the sign-in methods, the application permissions) adds up its time and is said ONCE at
    the end of the source (Add-SIIdentityPhaseTotal / Write-SIIdentityPhaseTotals).

    MEASUREMENT ONLY: nothing here changes what is read, kept or written as product data; a timer or a row that fails never
    fails the collection (every function here never throws). Outside a job execution (no CONTAINER_APP_JOB_EXECUTION_NAME)
    or without a settings database only the log line is written.
#>

if (-not (Get-Command -Name Write-SIStepPhase -ErrorAction SilentlyContinue)) {
    $__sipt = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-StepPhase.ps1')
    if ([IO.File]::Exists($__sipt)) { . $__sipt }
}

function Format-SIIdentityPhaseLine {
    <# PURE. The one log line of a phase. -Rows -1 = not counted. #>
    param([Parameter(Mandatory)][string]$Phase, [double]$Seconds, [long]$Rows = -1, [string]$Detail = '')
    $inner = New-Object System.Collections.Generic.List[string]
    if ($Rows -ge 0) { $inner.Add(('{0:N0} rows' -f $Rows)) }
    if ("$Detail".Trim()) { $inner.Add("$Detail".Trim()) }
    $tail = if ($inner.Count) { ' (' + ($inner -join '; ') + ')' } else { '' }
    '[timing] identity: {0} took {1} s{2}' -f $Phase, ([Math]::Round([double]$Seconds, 1)).ToString('0.0', [Globalization.CultureInfo]::InvariantCulture), $tail
}

function Get-SIIdentityPhaseInvoke {
    <#
        The settings database seam the phase rows go to, or $null (only the log line then). A test sets
        $global:SI_IdentityPhaseInvoke. In a job execution with a settings database: one seam per process
        (New-SIDataSqlInvoke -- the managed identity in a container, else the certificate). Never throws.
    #>
    try {
        if ($global:SI_IdentityPhaseInvoke -is [scriptblock]) { return $global:SI_IdentityPhaseInvoke }
        if ($global:SI_IdentityPhaseInvokeTried) { return $null }
        $global:SI_IdentityPhaseInvokeTried = $true
        if (-not "$env:CONTAINER_APP_JOB_EXECUTION_NAME".Trim()) { return $null }
        $ps = [string]$global:SI_ProSqlServer; $pd = [string]$global:SI_ProSqlDatabase
        if (-not $ps.Trim() -or -not $pd.Trim()) { return $null }
        if (-not (Get-Command -Name New-SIDataSqlInvoke -ErrorAction SilentlyContinue)) {
            $ds = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'data-sql', 'SI-DataSql.ps1')
            if ([IO.File]::Exists($ds)) { . $ds }
        }
        if (-not (Get-Command -Name New-SIDataSqlInvoke -ErrorAction SilentlyContinue)) { return $null }
        $global:SI_IdentityPhaseInvoke = New-SIDataSqlInvoke -Server $ps -Database $pd -AppId ([string]$global:SI_SPN_AppId) -TenantId ([string]$global:SI_SPN_TenantId) -CertThumbprint ([string]$global:SI_SPN_CertThumbprint)
        return $global:SI_IdentityPhaseInvoke
    } catch { return $null }
}

function Write-SIIdentityPhase {
    <# One phase said: the log line and its cfg.StepPhaseTime row. Returns the line. Never throws. #>
    param([Parameter(Mandatory)][string]$Phase, [double]$Seconds, [long]$Rows = -1, [string]$Detail = '')
    $line = ''
    try {
        $line = Format-SIIdentityPhaseLine -Phase $Phase -Seconds $Seconds -Rows $Rows -Detail $Detail
        if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $line } else { Write-Host $line }
        $inv = Get-SIIdentityPhaseInvoke
        if ($inv -and (Get-Command -Name Write-SIStepPhase -ErrorAction SilentlyContinue)) {
            $log = { param($l, $m) if (Get-Command -Name Write-SIWarn -ErrorAction SilentlyContinue) { Write-SIWarn $m } else { Write-Warning $m } }
            $null = Write-SIStepPhase -Invoke $inv -Job 'identity' -Phase $Phase -Seconds ([double]$Seconds) -Rows $Rows -Log $log
        }
    } catch { }
    $line
}

function Start-SIIdentityPhase {
    <# A timer for one phase (hand it to Stop-SIIdentityPhase). Never throws. #>
    param([Parameter(Mandatory)][string]$Phase)
    [pscustomobject]@{ Phase = $Phase; Watch = [System.Diagnostics.Stopwatch]::StartNew() }
}

function Stop-SIIdentityPhase {
    <# The phase's end: said once (Write-SIIdentityPhase). A $null timer = nothing. Returns the seconds. Never throws. #>
    param($Timer, [long]$Rows = -1, [string]$Detail = '')
    try {
        if ($null -eq $Timer -or $null -eq $Timer.Watch) { return 0.0 }
        $Timer.Watch.Stop()
        $s = $Timer.Watch.Elapsed.TotalSeconds
        $null = Write-SIIdentityPhase -Phase ([string]$Timer.Phase) -Seconds $s -Rows $Rows -Detail $Detail
        return $s
    } catch { return 0.0 }
}

function Reset-SIIdentityPhaseTotals { $global:SI_IdentityPhaseTotals = [ordered]@{} }

function Add-SIIdentityPhaseTotal {
    <# A part of a phase that runs many times (per page, per principal): its seconds, rows and calls added up. Never throws. #>
    param([Parameter(Mandatory)][string]$Phase, [double]$Seconds, [long]$Rows = 0, [long]$Calls = 0)
    try {
        if ($null -eq $global:SI_IdentityPhaseTotals) { Reset-SIIdentityPhaseTotals }
        if (-not $global:SI_IdentityPhaseTotals.Contains($Phase)) { $global:SI_IdentityPhaseTotals[$Phase] = @{ Seconds = 0.0; Rows = 0L; Calls = 0L } }
        $t = $global:SI_IdentityPhaseTotals[$Phase]
        $t.Seconds = [double]$t.Seconds + [double]$Seconds; $t.Rows = [long]$t.Rows + $Rows; $t.Calls = [long]$t.Calls + $Calls
    } catch { }
}

function Write-SIIdentityPhaseTotals {
    <# The added-up phases (-Prefix: only those starting with it), each said once, then forgotten. Never throws. #>
    param([string]$Prefix = '')
    try {
        if ($null -eq $global:SI_IdentityPhaseTotals) { return }
        foreach ($k in @($global:SI_IdentityPhaseTotals.Keys)) {
            if ($Prefix -and -not ([string]$k).StartsWith($Prefix)) { continue }
            $t = $global:SI_IdentityPhaseTotals[$k]
            $detail = if ([long]$t.Calls -gt 0) { '{0:N0} call(s), summed over the pages' -f [long]$t.Calls } else { 'summed over the pages' }
            $null = Write-SIIdentityPhase -Phase ([string]$k) -Seconds ([double]$t.Seconds) -Rows ([long]$t.Rows) -Detail $detail
            $global:SI_IdentityPhaseTotals.Remove($k)
        }
    } catch { }
}

function Format-SIGraphRetrySummary {
    <#
        PURE. The Microsoft Graph pager's retries in one line (-Counts: @{ 'HTTP429' = n; 'HTTP503' = n; ... }, -SleptSeconds: the
        time spent waiting before asking again). $null when nothing was asked again.
    #>
    param([AllowNull()][System.Collections.IDictionary]$Counts, [double]$SleptSeconds = 0)
    $total = 0L
    $parts = New-Object System.Collections.Generic.List[string]
    if ($Counts) {
        foreach ($k in @($Counts.Keys | Sort-Object)) {
            $n = [long]$Counts[$k]; if ($n -le 0) { continue }
            $total += $n
            $parts.Add(('{0} {1:N0}' -f ([string]$k -replace '^HTTP', 'HTTP '), $n))
        }
    }
    if ($total -le 0) { return $null }
    '[timing] identity: Microsoft Graph was asked again {0:N0} time(s) ({1}); {2} s waited before asking again' -f $total, ($parts -join ', '), ([Math]::Round($SleptSeconds, 1)).ToString('0.0', [Globalization.CultureInfo]::InvariantCulture)
}

function Write-SIGraphRetrySummary {
    <# The pager's retry counters (IdentityRoleFetcher.ps1 Invoke-SIGraphPaged), said once and as a phase row ('graph retries
       waited', its seconds = the time waited). -Counts / -SleptSeconds: tests. Never throws. #>
    param([AllowNull()][System.Collections.IDictionary]$Counts = $null, [double]$SleptSeconds = -1)
    try {
        # from the process-wide counters: read, then started again -- each source says only its own retries
        if ($null -eq $Counts) { $Counts = $global:SI_GraphRetryCount; $global:SI_GraphRetryCount = @{} }
        if ($SleptSeconds -lt 0) { $SleptSeconds = [double]$global:SI_GraphRetrySleptSeconds; $global:SI_GraphRetrySleptSeconds = 0.0 }
        $line = Format-SIGraphRetrySummary -Counts $Counts -SleptSeconds $SleptSeconds
        if (-not $line) { return $null }
        if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $line } else { Write-Host $line }
        $total = 0L; foreach ($k in @($Counts.Keys)) { $total += [long]$Counts[$k] }
        $inv = Get-SIIdentityPhaseInvoke
        if ($inv -and (Get-Command -Name Write-SIStepPhase -ErrorAction SilentlyContinue)) { $null = Write-SIStepPhase -Invoke $inv -Job 'identity' -Phase 'graph retries: waited' -Seconds $SleptSeconds -Rows $total }
        return $line
    } catch { return $null }
}
