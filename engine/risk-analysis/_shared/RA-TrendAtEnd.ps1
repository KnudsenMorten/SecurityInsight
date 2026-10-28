#Requires -Version 5.1
<#
    #306 -- THE DAILY TREND ROW, WRITTEN AT THE END OF RISK ANALYSIS (operator 2026-10-05: "for me trend is just a view in
    the gui"). The risk trend is no longer a job of the daily pipeline: the Pro web app draws its trends from the SQL
    history, and every install keeps its narrow daily row in SI_Trend_CL -- written here, by the Risk Analysis DETAILED run
    that produced the numbers, from the very rows it has just published (never from a Log Analytics snapshot that may
    still be yesterday's while today's is being ingested). The asset-trend job stays, runnable by hand.
    #636 (owner 2026-10-19: "i prefer to switch so detailed becomes the engine default and summary is optional"): the row
    came from the Summary run; the Summary step is now off by default, so the Detailed run writes it -- the trend counts
    FINDINGS (one per issue per asset), not Summary rows. The number changes once (said on the trend page).

    Read-only except for its own table (the trend engine's rule). It never fails the Risk Analysis run: a trend row that
    cannot be written is said once, and the day is a gap in the trend (unknown, not zero).
#>

function Test-SIRaTrendAtEnd {
    <#
        PURE. Does this Risk Analysis run write the day's trend row? @{ Run; Why }.
          * only a DETAILED run (the trend's grain since #636: the findings) that published its rows to Log Analytics, not
            a dry run;
          * never from a partial run (a lost query bucket, or a profile whose own run was partial -- working rule 4: a
            partial result is never shipped as whole; the day is a gap);
          * SI_Trend_AtEndOfRiskAnalysis: $false turns it off (e.g. while the asset-trend job is kept as a step).
    #>
    param([bool]$Detailed, [bool]$Published, [bool]$WhatIfRun, [int]$RowCount, [int]$LostBuckets = 0, [string]$UpstreamExit = 'success', $Setting,
          # #830 the copy of the report rows to Log Analytics (SendToLogAnalytics, Test-SIRaReportCopyOn): SI_Trend_CL is part of
          # that optional output, OFF by default -- the trend is kept in the database (sidata.FindingDaily / AssetDaily)
          [bool]$Copy = $true)
    $mk = { param($r, $w) [pscustomobject]@{ Run = [bool]$r; Why = $w } }
    $off = if ($Setting -is [bool]) { -not $Setting } else { ([string]$Setting).Trim() -match '^(?i)(0|false|\$false|no|off)$' }
    if ($off) { return (& $mk $false 'switched off (SI_Trend_AtEndOfRiskAnalysis)') }
    if (-not $Copy) { return (& $mk $false 'the copy of the report rows to Log Analytics is off (the default) -- the trend is kept in the database, SecurityInsight''s pages read it there') }
    if (-not $Detailed) { return (& $mk $false 'not a detailed run (the trend counts the detailed findings)') }
    if ($WhatIfRun) { return (& $mk $false 'a dry run publishes nothing') }
    if (-not $Published) { return (& $mk $false 'the run did not publish its rows to Log Analytics') }
    if ($RowCount -le 0) { return (& $mk $false 'the run produced no rows') }
    if ($LostBuckets -gt 0) { return (& $mk $false ('{0} query bucket(s) were lost -- a partial run is not a trend point (today is a gap, not a drop)' -f $LostBuckets)) }
    if ($UpstreamExit -and $UpstreamExit -ne 'success') { return (& $mk $false 'a profile this run read was partial -- not a trend point (today is a gap, not a drop)') }
    & $mk $true 'the day''s trend row, from the findings this run published'
}

function Invoke-SIRaTrendAtEnd {
    <#
        Writes the day's trend row by running the trend engine with -PublishedRows (the rows this run posted to Log
        Analytics, Detailed grain).
        -Engine: the trend engine's script (default: engine\asset-trend\Invoke-SITrend.ps1). Never throws.
        Returns @{ Ran; Why }.
    #>
    # -Rollup / -RowCount (#638): the day's rollup already computed in SQL from the rows this run wrote, and how many rows
    # it covers -- the rows themselves are not handed over.
    param([AllowEmptyCollection()][object[]]$Rows = @(), [bool]$Detailed, [bool]$Published, [bool]$WhatIfRun, [int]$LostBuckets = 0, [string]$UpstreamExit = 'success',
          $Setting, [string]$Engine, [scriptblock]$Log = { param($Level, $Message) Write-Host ('[trend] {0}' -f $Message) },
          [AllowNull()][object[]]$Rollup, [long]$RowCount = -1, [bool]$Copy = $true)
    $n = if ($RowCount -ge 0) { [int][Math]::Min([long][int]::MaxValue, $RowCount) } else { @($Rows).Count }
    $d = Test-SIRaTrendAtEnd -Detailed $Detailed -Published $Published -WhatIfRun $WhatIfRun -RowCount $n -LostBuckets $LostBuckets -UpstreamExit $UpstreamExit -Setting $Setting -Copy $Copy
    if (-not $d.Run) { & $Log 'INFO' ('the daily trend row is not written: {0}' -f $d.Why); return [pscustomobject]@{ Ran = $false; Why = $d.Why } }
    if (-not $Engine) { $Engine = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'asset-trend', 'Invoke-SITrend.ps1') }
    try {
        & $Log 'INFO' 'writing the daily trend row (from the findings this run published)'
        # #394: DOT-SOURCED in a child scope, never run with the call operator. A script run with `&` gets a script scope of its own, and
        # every shared function Risk Analysis already loaded (the run-health record, the telemetry report, the uplink)
        # reads its settings from `$script:` -- which then resolves to the trend's EMPTY script scope: the trend's END
        # report died with "You cannot call a method on a null-valued expression". Dot-sourced inside `& { }`, `$script:`
        # stays Risk Analysis's own, while the trend's variables, preferences and functions stay in the child scope.
        if ($null -ne $Rollup) { $null = & { param($__siTrendEngine, $__siTrendRollup) . $__siTrendEngine -Grain Detailed -PublishedRollup $__siTrendRollup } $Engine @($Rollup) }
        else { $null = & { param($__siTrendEngine, $__siTrendRows) . $__siTrendEngine -Grain Detailed -PublishedRows $__siTrendRows } $Engine @($Rows) }
        [pscustomobject]@{ Ran = $true; Why = $d.Why }
    } catch {
        & $Log 'WARN' ('the daily trend row could not be written ({0}) -- today is a gap in the trend; run the risk trend job by hand to fill it' -f $_.Exception.Message)
        [pscustomobject]@{ Ran = $false; Why = $_.Exception.Message }
    }
}
