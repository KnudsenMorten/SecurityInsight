#Requires -Version 5.1
<#
.SYNOPSIS
    AUDIT #57.1(a) -- run-over-run row-count regression guard.

.DESCRIPTION
    SecurityInsight has now had THREE silent-loss defects in which a run reported success
    while producing less data than the day before:

      #48        the DCR schema sample was positional, so 82 of 151 columns were dropped at
                 ingest for two months. Rows posted, run logged SUCCESS.
      v2.2.415   a cross-domain attack-path report spent 2h30m timing out and then reported
                 "no findings" -- indistinguishable from a genuinely clean result.
      #57        Microsoft reshaped an ExposureGraph property, so both Azure recommendation
                 reports matched nothing. Valid KQL, ~130s, exit 0, zero rows
                 (75 -> 0 Summary and 304 -> 0 Detailed overnight).

    Every one of those was found by a HUMAN noticing, never by the engine. The common shape is
    that ABSENCE LOOKS LIKE GOOD NEWS. This guard exists to make absence loud.

    It compares each report's row count against the same report's count in the last run that
    completed, and reports:
      * WENT-TO-ZERO  -- produced rows before, produces none now. The #57 signature.
      * LARGE-DROP    -- fell by more than $DropFraction of its previous value.

.NOTES
    🔑 IT WARNS, IT NEVER FAILS. A customer who genuinely remediates every finding SHOULD
    reach zero, and a guard that cries wolf on success gets switched off. THE SIGNAL IS THE
    TRANSITION, NOT THE VALUE -- which is also why this is run-over-run per tenant rather
    than a threshold. An absolute expected-count test cannot work across ~30 customers.

    History lives beside the AutoBucket cache and is keyed by TEMPLATE then report, because
    the same report name legitimately yields different counts under Summary vs Detailed.

    PowerShell 5.1: hashtables only, no ternary, no null-conditional.
#>

# #278 -- which reports hand their findings to another report (the run-over-run comparison must know).
. (Join-Path $PSScriptRoot 'RA-ReportHandoff.ps1')

function Get-RAThresholdReportNames {
    <#
      #407 -- THRESHOLD REPORTS: the reports whose whole result is ONE row that exists only while a tenant-wide count
      is over a threshold (Identity_TooManyGlobalAdmins_Summary: `summarize GACount = dcount(...)` then
      `where GACount > 5`). For them 1 -> 0 is the count falling to or below the threshold -- the finding is resolved,
      not lost -- so WENT-TO-ZERO is reported as BELOW-THRESHOLD: a logged warning that never makes the run partial.
      Ring 1, 2026-10-05: an admin's 8-hour PIM activation of Global Administrator took the count from 5 to 6 and
      back; the report went 0 -> 1 -> 0 and the second transition made the Risk Analysis run partial and held the
      data sync. Kept in step with the catalog by SIv3-ThresholdReportGuard.Tests.ps1, which finds every report of
      this shape with Test-RAThresholdShapedQuery and fails when one is missing here (or listed here but not of the shape).
      #690 (23), 2026-10-15: the Detailed report carries the same "more than 5" threshold (its rows exist only while the
      tenant-wide count is over it), so its N -> 0 is below the threshold too.
    #>
    @('Identity_TooManyGlobalAdmins_Summary', 'Identity_TooManyGlobalAdmins_Detailed')
}

function Test-RAThresholdShapedQuery {
    <#
      PURE. $true when the query aggregates WITHOUT a `by` clause (one row for the whole tenant) and then filters
      that aggregate against a number (`| where <aggregate> > 5`). The shape Get-RAThresholdReportNames lists.
      Comments and string literals are removed first so a `|` or `by` inside them cannot mislead it.
    #>
    param([AllowEmptyString()][string]$Query)
    if ([string]::IsNullOrWhiteSpace($Query)) { return $false }
    $q = [regex]::Replace($Query, '//[^\r\n]*', '')
    $q = [regex]::Replace($q, '"((?:[^"\\\r\n]|\\.)*)"', '""')
    $q = [regex]::Replace($q, "'((?:[^'\\\r\n]|\\.)*)'", "''")
    $aggNames = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($q, '\|\s*summarize\b')) {
        $s = $m.Index + $m.Length; $d = 0; $i = $s
        for (; $i -lt $q.Length; $i++) {
            $c = $q[$i]
            if ($c -eq '(' -or $c -eq '[') { $d++ }
            elseif ($c -eq ')' -or $c -eq ']') { $d-- }
            elseif ($d -eq 0 -and ($c -eq '|' -or $c -eq ';')) { break }
        }
        $body = $q.Substring($s, $i - $s)
        if ($body -match '\bby\b') { continue }
        foreach ($a in [regex]::Matches($body, '(\w+)\s*=\s*\w+\s*\(')) { [void]$aggNames.Add($a.Groups[1].Value) }
    }
    if ($aggNames.Count -eq 0) { return $false }
    foreach ($t in [regex]::Matches($q, '\|\s*where\s+(\w+)\s*(>=|>)\s*\d+')) {
        if ($aggNames.Contains($t.Groups[1].Value)) { return $true }
    }
    return $false
}

function Get-RARowCountHistoryPath {
    param([Parameter(Mandatory=$true)][string]$SettingsPath)
    Join-Path $SettingsPath "OUTPUT\RowCountHistory.json"
}

function Get-RARowCountRegressions {
    <#
      PURE + SIDE-EFFECT FREE so it can be unit-tested without a run.
      -Previous / -Current : hashtable of reportName -> [int] rowCount
      Returns an array of finding hashtables (Report, Kind, Previous, Current).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Previous,
        [Parameter(Mandatory=$true)][hashtable]$Current,
        [Parameter()][double]$DropFraction = 0.8,
        # The reports this run ATTEMPTED. A report that was attempted and produced no count at all
        # (it threw, or skipped out before recording) is the loudest failure there is -- and it was
        # the one case this guard could not see, because it iterated only the reports that DID count.
        [Parameter()][string[]]$Attempted = @(),
        # #278 report -> the reports that took over part of its findings (Get-RAReportSuccessorMap).
        [Parameter()][hashtable]$Successors,
        # #407 the one-row threshold reports (Get-RAThresholdReportNames). Not passed = the shipped list.
        [Parameter()][AllowEmptyCollection()][string[]]$ThresholdReports
    )

    $findings = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Successors) { $Successors = Get-RAReportSuccessorMap }
    if (-not $PSBoundParameters.ContainsKey('ThresholdReports')) { $ThresholdReports = @(Get-RAThresholdReportNames) }

    # #278 HANDOFF-LOST: a report handed findings to a receiving report that was attempted this run and produced
    # NOTHING (it failed). Those findings are in no report this run -- whatever the history says, and even on the
    # very first run, which is exactly when ring 1 lost them (the receiver failed on every run, so it never had a count).
    foreach ($giver in @($Successors.Keys | Sort-Object)) {
        if (-not $Current.ContainsKey($giver)) { continue }
        foreach ($recv in @($Successors[$giver])) {
            if ((@($Attempted) -contains $recv) -and -not $Current.ContainsKey($recv)) {
                [void]$findings.Add(@{ Report = $giver; Kind = 'HANDOFF-LOST'; Previous = $null; Current = [int]$Current[$giver]; Successor = $recv })
            }
        }
    }

    # MISSING first: attempted, no result, and it had findings last time. Its findings are UNKNOWN,
    # not remediated -- a downstream consumer that reads absence as "fixed" would close them.
    foreach ($name in @($Attempted | Where-Object { $_ } | Sort-Object -Unique)) {
        if ($Current.ContainsKey($name)) { continue }
        if (-not $Previous.ContainsKey($name)) { continue }
        $prevM = [int]$Previous[$name]
        if ($prevM -le 0) { continue }
        [void]$findings.Add(@{ Report = $name; Kind = 'MISSING'; Previous = $prevM; Current = $null })
    }

    foreach ($name in @($Current.Keys | Sort-Object)) {
        if (-not $Previous.ContainsKey($name)) { continue }   # new report -- nothing to compare

        $prev = [int]$Previous[$name]
        $curr = [int]$Current[$name]

        # Only a DOWNWARD move from a non-zero baseline is interesting. A report that was
        # already zero staying zero is the normal state of a clean tenant, and an increase
        # is never a loss signal (#57's fix legitimately took one report 75 -> 334).
        if ($prev -le 0) { continue }
        if ($curr -ge $prev) { continue }

        # #278 HANDED-OFF: the first run in which a receiving report exists. The rows that left this report are
        # reported THERE now, so comparing the report with itself reads a deliberate move as a loss (the 2.2 -> 3
        # upgrade said "LARGE-DROP 720 -> 19" while all 701 were in the receiving report). Only when the two
        # together hold what this report held -- a receiver that came up short is still a loss and still warns.
        $isDrop = ($curr -eq 0) -or ($DropFraction -gt 0 -and (($prev - $curr) / [double]$prev) -ge $DropFraction)
        if ($isDrop) {
            $newRecv = @(Get-RAHandoffReceiversNew -Report $name -Previous $Previous -Current $Current -Successors $Successors)
            if ($newRecv.Count -gt 0) {
                $recvRows = 0
                foreach ($r in $newRecv) { $recvRows += [int]$Current[$r] }
                $combined = $curr + $recvRows
                if (-not ($DropFraction -gt 0 -and (($prev - $combined) / [double]$prev) -ge $DropFraction) -and $combined -gt 0) {
                    [void]$findings.Add(@{ Report = $name; Kind = 'HANDED-OFF'; Previous = $prev; Current = $curr; Successor = ($newRecv -join ', '); SuccessorCurrent = $recvRows })
                    continue
                }
            }
        }

        if ($curr -eq 0 -and (@($ThresholdReports) -contains $name)) {
            # #407 a threshold report at zero = its count is no longer over the threshold. Reported, never a loss.
            [void]$findings.Add(@{ Report = $name; Kind = 'BELOW-THRESHOLD'; Previous = $prev; Current = 0 })
        }
        elseif ($curr -eq 0) {
            [void]$findings.Add(@{ Report = $name; Kind = 'WENT-TO-ZERO'; Previous = $prev; Current = 0 })
        }
        elseif ($DropFraction -gt 0 -and (($prev - $curr) / [double]$prev) -ge $DropFraction) {
            [void]$findings.Add(@{ Report = $name; Kind = 'LARGE-DROP'; Previous = $prev; Current = $curr })
        }
    }

    return @($findings.ToArray())
}

function Read-RARowCountHistory {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$TemplateName
    )
    $empty = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $empty }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $empty }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $obj) { return $empty }
        $node = $obj.PSObject.Properties[$TemplateName]
        if ($null -eq $node -or $null -eq $node.Value) { return $empty }
        $out = @{}
        foreach ($p in $node.Value.PSObject.Properties) {
            $n = 0
            if ([int]::TryParse([string]$p.Value, [ref]$n)) { $out[$p.Name] = $n }
        }
        return $out
    } catch {
        # A corrupt history file must never break a run -- it only costs one comparison.
        return $empty
    }
}

function Write-RARowCountHistory {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$TemplateName,
        [Parameter(Mandatory=$true)][hashtable]$Counts
    )
    try {
        $root = @{}
        if (Test-Path -LiteralPath $Path) {
            $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $existing = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    foreach ($p in $existing.PSObject.Properties) {
                        $inner = @{}
                        foreach ($q in $p.Value.PSObject.Properties) { $inner[$q.Name] = $q.Value }
                        $root[$p.Name] = $inner
                    }
                }
            }
        }
        $root[$TemplateName] = $Counts

        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
        }
        ($root | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Warning ("RowCountGuard: could not persist history to {0}: {1}" -f $Path, $_.Exception.Message)
    }
}

function Get-RAZeroRowWarning {
    <#
      PURE. The WARN line for a report that returned NO rows while its previous run had some -- said AT THE REPORT, in its
      own section of the log, not only in the summary at the end of the run (ring 1: 20 identity reports came back with 0
      rows and no error after the reports moved to a new source, and nothing next to them said so). $null when the report
      had no rows last time either, or has no history. A threshold report (Get-RAThresholdReportNames) says it is below
      its threshold instead.
    #>
    param([Parameter(Mandatory)][string]$ReportName, [hashtable]$Previous)
    if ($null -eq $Previous -or -not $Previous.ContainsKey($ReportName)) { return $null }
    $prev = 0; if (-not [int]::TryParse([string]$Previous[$ReportName], [ref]$prev)) { return $null }
    if ($prev -le 0) { return $null }
    if (@(Get-RAThresholdReportNames) -contains $ReportName) {
        return ("[RowCountGuard] {0}: 0 rows (previous run {1}) -- the count it measures is at or below its threshold." -f $ReportName, $prev)
    }
    return ("[RowCountGuard] WENT-TO-ZERO {0}: 0 rows this run, {1} in the previous run. Either every finding was remediated or the query no longer matches its data -- check the report before trusting the result." -f $ReportName, $prev)
}

function Write-RAZeroRowWarning {
    <# The report's zero-row WARN (Get-RAZeroRowWarning), against the previous run's counts read ONCE per run. Never throws. #>
    param([Parameter(Mandatory)][string]$ReportName, [string]$SettingsPath = [string]$global:SettingsPath, [string]$TemplateName = [string]$global:ReportTemplate)
    try {
        if ([string]::IsNullOrWhiteSpace($SettingsPath)) { return }
        if ([string]::IsNullOrWhiteSpace($TemplateName)) { $TemplateName = 'UnknownTemplate' }
        if ($null -eq $script:_RAPrevRowCounts -or [string]$script:_RAPrevRowCountsTemplate -ne $TemplateName) {
            $script:_RAPrevRowCounts = Read-RARowCountHistory -Path (Get-RARowCountHistoryPath -SettingsPath $SettingsPath) -TemplateName $TemplateName
            $script:_RAPrevRowCountsTemplate = $TemplateName
        }
        $line = Get-RAZeroRowWarning -ReportName $ReportName -Previous $script:_RAPrevRowCounts
        if ($line) { Write-Warn2 $line }
    } catch { }
}

function Invoke-RARowCountGuard {
    <#
      Compare this run's per-report counts against the previous run, report, then persist.
      Returns the findings array so a caller can surface it (mail/summary) if it wants.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SettingsPath,
        [Parameter(Mandatory=$true)][string]$TemplateName,
        [Parameter(Mandatory=$true)][hashtable]$Counts,
        [Parameter()][double]$DropFraction = 0.8,
        [Parameter()][string[]]$Attempted = @(),
        [Parameter()][switch]$SkipPersist
    )

    $path = Get-RARowCountHistoryPath -SettingsPath $SettingsPath
    $prev = Read-RARowCountHistory -Path $path -TemplateName $TemplateName
    $findings = @(Get-RARowCountRegressions -Previous $prev -Current $Counts -DropFraction $DropFraction -Attempted $Attempted)
    # #278 a hand-off is reported, never warned; a lost hand-off always warns -- even on the first run.
    $handed = @($findings | Where-Object { $_.Kind -eq 'HANDED-OFF' })
    $lostHo = @($findings | Where-Object { $_.Kind -eq 'HANDOFF-LOST' })
    $below  = @($findings | Where-Object { $_.Kind -eq 'BELOW-THRESHOLD' })
    $warn   = @($findings | Where-Object { $_.Kind -ne 'HANDED-OFF' -and $_.Kind -ne 'HANDOFF-LOST' -and $_.Kind -ne 'BELOW-THRESHOLD' })
    foreach ($f in $handed) {
        Write-Info ("[RowCountGuard] {0}: {1} -> {2}. The other recommendations are now reported in {3} ({4} row(s)) -- moved, not lost." -f $f.Report, $f.Previous, $f.Current, $f.Successor, $f.SuccessorCurrent)
    }
    foreach ($f in $lostHo) {
        Write-Warn2 ("[RowCountGuard] HANDOFF-LOST  {0} left the recommendations Defender for Cloud carries to {1}, and {1} produced NO RESULT this run -- those findings are in no report. They are UNKNOWN, not remediated. Fix {1} and re-run." -f $f.Report, $f.Successor)
    }
    # #407 a warning in the log, never an incomplete report: the count this report measures fell to or below its threshold.
    foreach ($f in $below) {
        Write-Warn2 ("[RowCountGuard] BELOW-THRESHOLD  {0}: {1} -> 0. This report has a row only while a tenant-wide count is over its threshold, so the count is now at or below it -- the finding is resolved, not lost, and the run stays complete. If the count did not really change, check the report's source data." -f $f.Report, $f.Previous)
    }

    if ($prev.Count -eq 0) {
        Write-Info ("[RowCountGuard] no prior run recorded for template '{0}' -- baseline established from this run ({1} report(s))." -f $TemplateName, $Counts.Count)
    }
    elseif ($warn.Count -eq 0) {
        Write-Info ("[RowCountGuard] {0} report(s) compared against the previous run -- no report lost its findings." -f $Counts.Count)
    }
    else {
        Write-Warn2 ("[RowCountGuard] {0} report(s) produced FEWER findings than the previous run. A run can report success and still be missing data. Investigate before trusting this export." -f $warn.Count)
        foreach ($f in $warn) {
            if ($f.Kind -eq 'MISSING') {
                Write-Warn2 ("  MISSING       {0}: {1} finding(s) last run, NO RESULT this run -- the report failed. Its findings are UNKNOWN, not remediated. Re-run the report." -f $f.Report, $f.Previous)
            } elseif ($f.Kind -eq 'WENT-TO-ZERO') {
                Write-Warn2 ("  WENT-TO-ZERO  {0}: {1} -> 0. Either every finding was genuinely remediated, or the query stopped matching (a changed upstream property does exactly this)." -f $f.Report, $f.Previous)
            } else {
                Write-Warn2 ("  LARGE-DROP    {0}: {1} -> {2}." -f $f.Report, $f.Previous, $f.Current)
            }
        }
    }

    if (-not $SkipPersist) {
        # MERGE, never replace. A report that produced no count this run keeps its last known value,
        # so it is compared again next run instead of silently losing its baseline -- replacing the
        # history is how a report failing every night would read "no report lost its findings" forever.
        $merged = @{}
        foreach ($k in @($prev.Keys))   { $merged[$k] = $prev[$k] }
        foreach ($k in @($Counts.Keys)) { $merged[$k] = $Counts[$k] }
        Write-RARowCountHistory -Path $path -TemplateName $TemplateName -Counts $merged
    }
    return $findings
}

function Get-RAIncompleteReports {
    <#
      PURE. The reports that did not deliver a whole result this run -- their findings are UNKNOWN, not remediated -- one
      entry per report: @{ Report; Why }. A report is incomplete when
        * its query failed or its result could not be read                     (-Failures, recorded by the engine)
        * it was attempted and produced no count at all                        (it threw before recording one)
        * the guard says HANDOFF-LOST (the GIVER: what it left to a report that failed is in no report), MISSING,
          WENT-TO-ZERO or LARGE-DROP.
      HANDED-OFF is a move, not a loss, and never makes a report incomplete. Nor does BELOW-THRESHOLD (#407: a one-row
      threshold report whose count fell to or below its threshold) -- it is a logged warning only.
      A run with an incomplete report ends partial: the data sync holds that collection and the close-loop closes nothing
      on it. The guard's history still takes this run's counts, so a drop that was real is accepted on the next run --
      a genuine clean-up is reported one run later, never lost; a lost result is never reported as fixed.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [AllowEmptyCollection()][string[]]$Attempted = @(),
        [hashtable]$Counts,
        [AllowEmptyCollection()][object[]]$Failures = @()
    )
    if ($null -eq $Counts) { $Counts = @{} }
    $order = New-Object System.Collections.Generic.List[string]
    $why = @{}
    $add = {
        param([string]$r, [string]$w)
        if ([string]::IsNullOrWhiteSpace($r)) { return }
        if (-not $why.ContainsKey($r)) { $why[$r] = New-Object System.Collections.Generic.List[string]; [void]$order.Add($r) }
        if (-not $why[$r].Contains($w)) { [void]$why[$r].Add($w) }
    }
    foreach ($f in @($Failures)) {
        if ($null -eq $f) { continue }
        & $add ([string]$f.Report) ([string]$f.Why)
    }
    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $k = [string]$f.Kind
        switch ($k) {
            'HANDOFF-LOST' { & $add ([string]$f.Report) ("the findings it leaves to {0} are in no report, because {0} produced no result" -f [string]$f.Successor) }
            'MISSING'      { & $add ([string]$f.Report) ("it produced no result ({0} finding(s) last run)" -f [int]$f.Previous) }
            'WENT-TO-ZERO' { & $add ([string]$f.Report) ("it went from {0} finding(s) last run to none" -f [int]$f.Previous) }
            'LARGE-DROP'   { & $add ([string]$f.Report) ("it went from {0} finding(s) last run to {1}" -f [int]$f.Previous, [int]$f.Current) }
            default { }   # HANDED-OFF, BELOW-THRESHOLD (#407): the report delivered its whole result
        }
    }
    foreach ($a in @($Attempted | Where-Object { $_ } | Sort-Object -Unique)) {
        if ($Counts.ContainsKey([string]$a)) { continue }
        if ($why.ContainsKey([string]$a)) { continue }
        & $add ([string]$a) 'it produced no result'
    }
    foreach ($r in $order) { @{ Report = $r; Why = ($why[$r] -join '; ') } }
}

function Format-RAIncompleteReports {
    <# PURE. The run-health message for the incomplete reports: one line a dashboard and the data sync can show as is. #>
    param([AllowEmptyCollection()][object[]]$Incomplete = @())
    $items = @($Incomplete | Where-Object { $_ })
    if ($items.Count -eq 0) { return '' }
    $parts = @($items | ForEach-Object { ("{0} ({1})" -f [string]$_.Report, [string]$_.Why) })
    ("{0} report(s) incomplete -- their findings are unknown, not remediated: {1}" -f $items.Count, ($parts -join '; '))
}
