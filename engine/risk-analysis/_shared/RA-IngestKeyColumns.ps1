#Requires -Version 5.1
<#
    RA-IngestKeyColumns -- a Risk Analysis snapshot is never posted without its key columns (#294).

    Found live 2026-10-05 on ring 1: a Risk Analysis Detailed run wrote 14,624 rows to SI_RiskAnalysis_Detailed_CL with
    CollectionTime, ConfigurationId, SecuritySeverity, CriticalityTier, RiskScoreTotal and SolutionVersion EMPTY on every
    row, and the run logged success. Such a snapshot cannot be loaded as a day, shown or trended -- and to everything
    downstream it looks like a finished run in which every finding disappeared. The cause was a data collection rule that
    declared 11 columns (SI-LogIngest.ps1, Assert-SILogDcrCoversData); this is the second, independent line: whatever the
    cause, the rows about to be posted are checked, and a key column that is empty on EVERY row refuses the post.

    PURE functions. PS 5.1 safe.
#>

function Get-RAIngestKeyColumns {
    <# The columns every Risk Analysis row is identified, placed in time and scored by (Summary and Detailed alike). #>
    @('CollectionTime', 'SolutionVersion', 'ConfigurationId', 'SecuritySeverity', 'CriticalityTier', 'RiskScoreTotal')
}

function Get-RAIngestKeyColumnGaps {
    <#
        PURE. Of -Columns (default: Get-RAIngestKeyColumns), those that are EMPTY ON EVERY ROW of -Rows -- missing, $null,
        or blank text. A column filled on at least one row is no gap (CriticalityTier is legitimately empty on some rows).
        No rows -> no gaps (nothing is posted).
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Rows = @(), [string[]]$Columns = @(Get-RAIngestKeyColumns))
    $list = @(@($Rows) | Where-Object { $null -ne $_ })
    if ($list.Count -eq 0) { return @() }
    $gaps = New-Object System.Collections.Generic.List[string]
    foreach ($c in $Columns) {
        $filled = $false
        foreach ($r in $list) {
            $v = if ($r -is [System.Collections.IDictionary]) { $r[$c] } elseif ($r.PSObject.Properties[$c]) { $r.PSObject.Properties[$c].Value } else { $null }
            if ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) { $filled = $true; break }
        }
        if (-not $filled) { [void]$gaps.Add($c) }
    }
    return $gaps.ToArray()
}

function Get-RAIngestKeyColumnMessage {
    <# PURE. The one sentence a refused post produces (customer language). #>
    param([Parameter(Mandatory)][string[]]$Columns, [int]$Rows, [string]$TableName)
    ("Every one of the {0} row(s) for {1}_CL has {2} empty. A Risk Analysis snapshot without them cannot be shown, loaded as a day or trended, so it was not posted; this run is marked as failed." -f `
        $Rows, ($TableName -replace '_CL$', ''), ($Columns -join ', '))
}
