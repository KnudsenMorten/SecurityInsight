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
        [Parameter()][double]$DropFraction = 0.8
    )

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($name in @($Current.Keys | Sort-Object)) {
        if (-not $Previous.ContainsKey($name)) { continue }   # new report -- nothing to compare

        $prev = [int]$Previous[$name]
        $curr = [int]$Current[$name]

        # Only a DOWNWARD move from a non-zero baseline is interesting. A report that was
        # already zero staying zero is the normal state of a clean tenant, and an increase
        # is never a loss signal (#57's fix legitimately took one report 75 -> 334).
        if ($prev -le 0) { continue }
        if ($curr -ge $prev) { continue }

        if ($curr -eq 0) {
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
        [Parameter()][switch]$SkipPersist
    )

    $path = Get-RARowCountHistoryPath -SettingsPath $SettingsPath
    $prev = Read-RARowCountHistory -Path $path -TemplateName $TemplateName
    $findings = @(Get-RARowCountRegressions -Previous $prev -Current $Counts -DropFraction $DropFraction)

    if ($prev.Count -eq 0) {
        Write-Info ("[RowCountGuard] no prior run recorded for template '{0}' -- baseline established from this run ({1} report(s))." -f $TemplateName, $Counts.Count)
    }
    elseif ($findings.Count -eq 0) {
        Write-Info ("[RowCountGuard] {0} report(s) compared against the previous run -- no report lost its findings." -f $Counts.Count)
    }
    else {
        Write-Warn2 ("[RowCountGuard] {0} report(s) produced FEWER findings than the previous run. A run can report success and still be missing data. Investigate before trusting this export." -f $findings.Count)
        foreach ($f in $findings) {
            if ($f.Kind -eq 'WENT-TO-ZERO') {
                Write-Warn2 ("  WENT-TO-ZERO  {0}: {1} -> 0. Either every finding was genuinely remediated, or the query stopped matching (a changed upstream property does exactly this)." -f $f.Report, $f.Previous)
            } else {
                Write-Warn2 ("  LARGE-DROP    {0}: {1} -> {2}." -f $f.Report, $f.Previous, $f.Current)
            }
        }
    }

    if (-not $SkipPersist) {
        Write-RARowCountHistory -Path $path -TemplateName $TemplateName -Counts $Counts
    }
    return $findings
}
