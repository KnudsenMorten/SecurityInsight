#Requires -Version 5.1
<#
.SYNOPSIS
    #278 -- REPORTS THAT HAND THEIR FINDINGS TO ANOTHER REPORT. One map, three readers.

.DESCRIPTION
    Since #147 the Exposure Graph recommendation reports (Azure_Recommendations_*) drop every
    (resource, recommendation) pair that Defender for Cloud already carries, because the Defender
    recommendation reports (Azure_DefenderRecommendations_*) report it -- a recommendation is counted
    once. That hand-off is only correct while the receiving report actually RUNS AND SUCCEEDS.
    Measured 2026-10-04:

      * the 2.2 -> 3 upgrade test: Azure_Recommendations_Detailed 720 -> 19. Every one of the 701 rows
        that left was in Azure_DefenderRecommendations_Detailed (700 by the same ARM id + recommendation,
        1 by name on the same resource). Nothing was lost -- but both run-over-run guards compared the
        report with ITSELF and said LARGE-DROP / COLUMN-EMPTIED, and the operator read "v3 is wrong".
      * ring 1 (Pro): Azure_DefenderRecommendations_* failed with a 400 on every run (a typed union stub
        against a table whose count columns are long). The graph report still handed 170 rows to it, so
        those findings -- and all 750 Defender rows -- were in NO report, and nothing said so.

    Readers:
      Resolve-RADefenderHandoffBlock  the query side -- empties the hand-off lookup when the receiving
                                      report is not part of this run.
      Get-RARowCountRegressions       recognises a hand-off on the first run of the receiving report
                                      (informational, not LARGE-DROP), and warns HANDOFF-LOST when the
                                      receiving report was attempted and produced nothing.
      Get-RAColumnFillRegressions     does not compare column fill across a hand-off (a different
                                      population of rows, so a fill fraction says nothing).

    PowerShell 5.1: hashtables only, no ternary, no null-conditional.
#>

function Get-RAReportSuccessorMap {
    <#
      Report -> the reports that took over part of its findings. Same grain on both sides, because the
      run-over-run history is kept per template and the Summary and Detailed templates are separate.
    #>
    @{
        'Azure_Recommendations_Detailed' = @('Azure_DefenderRecommendations_Detailed')
        'Azure_Recommendations_Summary'  = @('Azure_DefenderRecommendations_Summary')
    }
}

function Resolve-RADefenderHandoffBlock {
    <#
      PURE. When -ReportName hands findings to a report that is NOT in -IncludedReports, the block between
      //__DEFENDER_HANDOFF_BEGIN__ and //__DEFENDER_HANDOFF_END__ becomes an empty lookup, so the report keeps
      every finding it has. A query without the markers, or a report whose receiver is included, is
      returned unchanged. -IncludedReports empty = unknown = unchanged (never guess a removal).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Query,
        [Parameter(Mandatory)][string]$ReportName,
        [AllowEmptyCollection()][string[]]$IncludedReports = @(),
        [hashtable]$Successors
    )
    $begin = '//__DEFENDER_HANDOFF_BEGIN__'
    $end   = '//__DEFENDER_HANDOFF_END__'
    if ([string]::IsNullOrEmpty($Query) -or -not $Query.Contains($begin)) { return $Query }
    $inc = @($IncludedReports | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($inc.Count -eq 0) { return $Query }
    if ($null -eq $Successors) { $Successors = Get-RAReportSuccessorMap }
    $receivers = @()
    if ($Successors.ContainsKey($ReportName)) { $receivers = @($Successors[$ReportName]) }
    if ($receivers.Count -eq 0) { return $Query }
    $missing = @($receivers | Where-Object { $inc -notcontains $_ })
    if ($missing.Count -eq 0) { return $Query }
    $rx = [regex]::Escape($begin) + '(?<body>.*?)' + [regex]::Escape($end)
    $m = [regex]::Match($Query, $rx, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $m.Success) { return $Query }
    $var = '_dfcPairs'
    if ($m.Groups['body'].Value -match 'let\s+(\w+)\s*=') { $var = $Matches[1] }
    $nl = [Environment]::NewLine
    $newBlock = $begin + $nl + ('let {0} = datatable(_dfcKey:string)[];' -f $var) + $nl + $end
    if (Get-Command Write-Info -ErrorAction SilentlyContinue) {
        Write-Info ("{0}: {1} is not part of this run -- every recommendation stays in this report instead of being left to it." -f $ReportName, ($missing -join ', '))
    }
    return $Query.Replace($m.Value, $newBlock)
}

function Get-RAHandoffReceiversNew {
    <#
      PURE. For -Report, the receiving reports that produced a count THIS run and had none recorded before:
      the run in which the hand-off first took effect.
    #>
    param([Parameter(Mandatory)][string]$Report, [Parameter(Mandatory)][hashtable]$Previous,
          [Parameter(Mandatory)][hashtable]$Current, [hashtable]$Successors)
    if ($null -eq $Successors -or -not $Successors.ContainsKey($Report)) { return @() }
    @(@($Successors[$Report]) | Where-Object { $Current.ContainsKey($_) -and -not $Previous.ContainsKey($_) })
}
