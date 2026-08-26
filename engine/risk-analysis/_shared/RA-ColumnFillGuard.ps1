#Requires -Version 5.1
<#
.SYNOPSIS
    AUDIT #57.1(d) -- run-over-run COLUMN-POPULATION regression guard.

.DESCRIPTION
    The sibling of #57.1(a). The row-count guard notices when a report loses its ROWS; this one
    notices when the rows are all still there and the CONTENT drains out of them.

    It exists because v2.2.422 found a defect the row-count guard provably could not have caught:

      #58.5   CMDB enrichment had been empty on EVERY OAuth run since v2.2.314. The cache could
              not be written at all. Measured: 0 of 1,810 rows carried cmdbName / cmdbCriticality /
              cmdbDataSensitivity, while cmdbId sat at 66% -- a dangling foreign key, which is
              exactly why it looked partly healthy. Every row was present and correct in number.
              The row-count guard saw 1,810 -> 1,810 and said nothing, correctly.

    🔴 WHAT THIS GUARD DOES **NOT** COVER -- corrected 2026-08-11, it was overclaimed.
    It captures from $Shaped, i.e. WHAT THE ENGINE PRODUCES. Loss that happens AFTER that point is
    invisible to it by construction:

      #48     the DCR schema sample was positional, so 82 of 151 columns were dropped AT INGEST.
              The engine produced all 151 correctly; Log Analytics stored 69. This guard would NOT
              have caught it, and earlier text here claiming otherwise was wrong.

    Ingest-side loss is covered by a DIFFERENT mechanism -- the union schema sample plus
    tests/pester/SI-IngestSchemaCoverage.Tests.ps1. The two are COMPLEMENTARY, and neither is
    redundant: this one guards the produced rows, that one guards what reaches the table.
    Same lesson, opposite side of the ingest boundary.

    Three findings, in descending severity:
      * COLUMN-VANISHED -- the column was populated before and is not in the schema at all now.
                           Its real-world shape is audit #26 (output shaping dropping a column
                           from the export), NOT #48. It is also the one a naive implementation
                           cannot see (see THE TRAP below).
      * COLUMN-EMPTIED  -- the column is still there, still had values yesterday, and is 100%
                           blank today. The #58.5 signature.
      * FILL-DROP       -- still populated, but its fill rate fell by more than $DropFraction.

.NOTES
    🔑 IT WARNS, IT NEVER FAILS -- same contract as #57.1(a), for the same reason. A guard that
    cries wolf on a legitimate change gets switched off, and then it protects nothing.

    🔑 THE COMPARISON IS ON FILL **FRACTION**, NEVER ON THE RAW FILLED COUNT. Row counts in this
    tenant move on their own between runs -- a control run with unchanged code showed one report
    going 5 -> 3 -> 5. A column that stays 100% populated while its report legitimately drops
    1,397 -> 700 rows would look like a 50% loss if counts were compared. It is not a loss; the
    fraction is 1.0 both times. This is the single most important line in the file.

    🪤 THE TRAP -- WHY THE PREVIOUS SCHEMA IS ITERATED, NOT THE CURRENT ONE.
    The severe case (#48) is a column that disappears ENTIRELY. Such a column has no entry in the
    current snapshot at all, so a loop over the CURRENT columns skips it silently -- the guard
    would be blind to precisely the worst defect it was built for. This is the same mistake
    #57.1(a) made in its first cut (capturing only where rows > 0, leaving it unable to see a
    report going to zero). Iterate what we HAD; ask what happened to it.

    🔑 THIS GUARD DELIBERATELY STAYS SILENT ON A ZERO-ROW REPORT. If a report produces no rows,
    every column in it is trivially empty. Reporting 50 COLUMN-EMPTIED findings for one report
    that went to zero -- an event #57.1(a) already reports ONCE, accurately -- is how a useful
    guard becomes noise. The row-count guard owns that transition; this one defers to it.

    PowerShell 5.1: hashtables only, no ternary, no null-conditional.
#>

function Get-RAColumnFillHistoryPath {
    param([Parameter(Mandatory=$true)][string]$SettingsPath)
    Join-Path $SettingsPath "OUTPUT\ColumnFillHistory.json"
}

function Get-RAColumnFillSnapshot {
    <#
      Reduce a report's SHAPED rows to { '__rows' = <n>; '<column>' = <filled count>; ... }.

      PURE + SIDE-EFFECT FREE so it can be unit-tested without a run.

      Every column seen on any row is initialised to 0 BEFORE its value is inspected, so a column
      that is present-but-always-blank records a 0 rather than going missing. That distinction is
      what separates COLUMN-EMPTIED from COLUMN-VANISHED, and without it the two collapse into
      one another.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object[]]$Rows)

    $snap   = @{}
    $rowArr = @($Rows)
    $snap['__rows'] = $rowArr.Count
    if ($rowArr.Count -eq 0) { return $snap }

    foreach ($row in $rowArr) {
        if ($null -eq $row) { continue }
        foreach ($p in $row.PSObject.Properties) {
            $name = [string]$p.Name
            if ($name -eq '__rows') { continue }              # reserved for the denominator
            if (-not $snap.ContainsKey($name)) { $snap[$name] = 0 }

            $v = $p.Value
            if ($null -eq $v) { continue }

            # A numeric 0 and a boolean $false are LEGITIMATE VALUES, not absence -- stringify
            # first so they count as populated ("0" / "False" are not whitespace). Only $null,
            # '', whitespace and an empty collection read as unpopulated.
            $s = [string]$v
            if (-not [string]::IsNullOrWhiteSpace($s)) { $snap[$name] = $snap[$name] + 1 }
        }
    }

    return $snap
}

function Get-RAColumnFillRegressions {
    <#
      PURE + SIDE-EFFECT FREE.
      -Previous / -Current : hashtable of reportName -> snapshot (as built above).
      Returns an array of finding hashtables.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Previous,
        [Parameter(Mandatory=$true)][hashtable]$Current,
        [Parameter()][double]$DropFraction = 0.8
    )

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($report in @($Current.Keys | Sort-Object)) {
        if (-not $Previous.ContainsKey($report)) { continue }   # new report -- no baseline

        $currSnap = $Current[$report]
        $prevSnap = $Previous[$report]
        if ($null -eq $currSnap -or $null -eq $prevSnap) { continue }
        if (-not ($currSnap -is [hashtable]) -or -not ($prevSnap -is [hashtable])) { continue }

        $currRows = 0
        $prevRows = 0
        if ($currSnap.ContainsKey('__rows')) { $currRows = [int]$currSnap['__rows'] }
        if ($prevSnap.ContainsKey('__rows')) { $prevRows = [int]$prevSnap['__rows'] }

        # Defer to #57.1(a) on the went-to-zero transition -- see the header note.
        if ($currRows -le 0) { continue }
        if ($prevRows -le 0) { continue }

        # 🪤 Iterate the PREVIOUS schema. A vanished column is absent from $currSnap, so looping
        # over the current one would skip the most severe case entirely.
        foreach ($col in @($prevSnap.Keys | Sort-Object)) {
            if ($col -eq '__rows') { continue }

            $prevFilled = [int]$prevSnap[$col]
            if ($prevFilled -le 0) { continue }                 # nothing was there to lose

            $prevFrac = $prevFilled / [double]$prevRows

            if (-not $currSnap.ContainsKey($col)) {
                [void]$findings.Add(@{
                    Report          = $report
                    Column          = $col
                    Kind            = 'COLUMN-VANISHED'
                    PreviousFilled  = $prevFilled
                    PreviousRows    = $prevRows
                    CurrentFilled   = 0
                    CurrentRows     = $currRows
                    PreviousFillPct = [math]::Round(($prevFrac * 100), 1)
                    CurrentFillPct  = 0.0
                })
                continue
            }

            $currFilled = [int]$currSnap[$col]
            $currFrac   = $currFilled / [double]$currRows

            # Fraction, not count. See the header -- this is what makes ordinary row drift silent.
            if ($currFrac -ge $prevFrac) { continue }

            $kind = $null
            if ($currFilled -eq 0) {
                $kind = 'COLUMN-EMPTIED'
            }
            elseif ($DropFraction -gt 0 -and ((($prevFrac - $currFrac) / $prevFrac) -ge $DropFraction)) {
                $kind = 'FILL-DROP'
            }
            if ($null -eq $kind) { continue }

            [void]$findings.Add(@{
                Report          = $report
                Column          = $col
                Kind            = $kind
                PreviousFilled  = $prevFilled
                PreviousRows    = $prevRows
                CurrentFilled   = $currFilled
                CurrentRows     = $currRows
                PreviousFillPct = [math]::Round(($prevFrac * 100), 1)
                CurrentFillPct  = [math]::Round(($currFrac * 100), 1)
            })
        }
    }

    return @($findings.ToArray())
}

function Read-RAColumnFillHistory {
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
        foreach ($rp in $node.Value.PSObject.Properties) {
            if ($null -eq $rp.Value) { continue }
            $snap = @{}
            foreach ($cp in $rp.Value.PSObject.Properties) {
                $n = 0
                if ([int]::TryParse([string]$cp.Value, [ref]$n)) { $snap[$cp.Name] = $n }
            }
            $out[$rp.Name] = $snap
        }
        return $out
    } catch {
        # A corrupt history file must never break a run -- it only costs one comparison.
        return $empty
    }
}

function Write-RAColumnFillHistory {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$TemplateName,
        [Parameter(Mandatory=$true)][hashtable]$Snapshots
    )
    try {
        $root = @{}
        if (Test-Path -LiteralPath $Path) {
            $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $existing = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    foreach ($tp in $existing.PSObject.Properties) {
                        $reports = @{}
                        if ($null -ne $tp.Value) {
                            foreach ($rp in $tp.Value.PSObject.Properties) {
                                $snap = @{}
                                if ($null -ne $rp.Value) {
                                    foreach ($cp in $rp.Value.PSObject.Properties) { $snap[$cp.Name] = $cp.Value }
                                }
                                $reports[$rp.Name] = $snap
                            }
                        }
                        $root[$tp.Name] = $reports
                    }
                }
            }
        }

        # 🔑 MERGE, DO NOT REPLACE THE TEMPLATE NODE. A report that threw inside the per-report
        # catch records no snapshot this run. Replacing the node wholesale would delete its
        # baseline, so the NEXT run would have nothing to compare against -- the guard would go
        # quiet for exactly the report that just misbehaved. A stale baseline beats no baseline.
        $node = @{}
        if ($root.ContainsKey($TemplateName) -and $root[$TemplateName] -is [hashtable]) {
            $node = $root[$TemplateName]
        }
        foreach ($k in @($Snapshots.Keys)) { $node[$k] = $Snapshots[$k] }
        $root[$TemplateName] = $node

        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
        }
        ($root | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Warning ("ColumnFillGuard: could not persist history to {0}: {1}" -f $Path, $_.Exception.Message)
    }
}

function Invoke-RAColumnFillGuard {
    <#
      Compare this run's per-report column fill against the previous run, report, then persist.
      Returns the findings array so a caller can surface it (mail/summary) if it wants.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SettingsPath,
        [Parameter(Mandatory=$true)][string]$TemplateName,
        [Parameter(Mandatory=$true)][hashtable]$Snapshots,
        [Parameter()][double]$DropFraction = 0.8,
        [Parameter()][switch]$SkipPersist
    )

    $path     = Get-RAColumnFillHistoryPath -SettingsPath $SettingsPath
    $prev     = Read-RAColumnFillHistory -Path $path -TemplateName $TemplateName
    $findings = @(Get-RAColumnFillRegressions -Previous $prev -Current $Snapshots -DropFraction $DropFraction)

    if ($prev.Count -eq 0) {
        Write-Info ("[ColumnFillGuard] no prior run recorded for template '{0}' -- baseline established from this run ({1} report(s))." -f $TemplateName, $Snapshots.Count)
    }
    elseif ($findings.Count -eq 0) {
        Write-Info ("[ColumnFillGuard] {0} report(s) compared against the previous run -- no column lost its content." -f $Snapshots.Count)
    }
    else {
        Write-Warn2 ("[ColumnFillGuard] {0} column(s) carry LESS data than the previous run while their rows remained. Every row is present and the columns are blank, which a row count cannot see. Investigate before trusting this export." -f $findings.Count)
        foreach ($f in $findings) {
            if ($f.Kind -eq 'COLUMN-VANISHED') {
                Write-Warn2 ("  COLUMN-VANISHED {0}.{1}: was {2}/{3} rows ({4}%), column is NO LONGER IN THE SCHEMA. The column was dropped between the query and the export." -f $f.Report, $f.Column, $f.PreviousFilled, $f.PreviousRows, $f.PreviousFillPct)
            }
            elseif ($f.Kind -eq 'COLUMN-EMPTIED') {
                Write-Warn2 ("  COLUMN-EMPTIED  {0}.{1}: was {2}/{3} rows ({4}%), now 0/{5} (0%). The column still ships; it is blank on every row. Either the upstream source stopped supplying it, or an enrichment step silently failed." -f $f.Report, $f.Column, $f.PreviousFilled, $f.PreviousRows, $f.PreviousFillPct, $f.CurrentRows)
            }
            else {
                Write-Warn2 ("  FILL-DROP       {0}.{1}: {2}% -> {3}% ({4}/{5} -> {6}/{7} rows)." -f $f.Report, $f.Column, $f.PreviousFillPct, $f.CurrentFillPct, $f.PreviousFilled, $f.PreviousRows, $f.CurrentFilled, $f.CurrentRows)
            }
        }
    }

    if (-not $SkipPersist) {
        Write-RAColumnFillHistory -Path $path -TemplateName $TemplateName -Snapshots $Snapshots
    }
    return $findings
}
