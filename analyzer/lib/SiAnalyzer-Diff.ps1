#Requires -Version 5.1
<#
.SYNOPSIS
    SI Analyzer -- pure snapshot-diff + score-timeline aggregation.

.DESCRIPTION
    Offline-testable core. Operates on already-fetched RA rows (PSCustomObjects
    with at least: ConfigurationId, ConfigurationName, RiskScoreTotal,
    CriticalityTierLevel, SecurityDomain, CollectionTime). No network.

      * Get-SiLatestSnapshot       -- pick rows for max(CollectionTime).
      * Get-SiSnapshotDiff         -- new / closed / open / regressed / improved
                                      between two snapshots (by ConfigurationId).
      * Get-SiScoreTimeline        -- total + per-tier score per CollectionTime,
                                      with the headline delta vs the prior point.

    PowerShell 5.1-safe (no ?., no ??, no ternary, no .Where method chains that
    require pwsh-only behaviour).
#>

Set-StrictMode -Version Latest

function ConvertTo-SiTime {
    param($Value)
    if ($null -eq $Value) { return [datetime]::MinValue }
    if ($Value -is [datetime]) { return $Value }
    $dt = [datetime]::MinValue
    $ok = [datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal,
        [ref]$dt)
    if ($ok) { return $dt }
    return [datetime]::MinValue
}

function Get-SiCollectionTimes {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)
    $set = New-Object System.Collections.Generic.SortedSet[datetime]
    foreach ($r in $Rows) {
        if ($null -ne $r -and $r.PSObject.Properties.Name -contains 'CollectionTime') {
            [void]$set.Add((ConvertTo-SiTime $r.CollectionTime))
        }
    }
    # Return a plain [datetime[]] (sorted ascending). Comma-protecting a collection
    # here re-introduces the foreach wrapper trap for callers; an explicit typed
    # array is unambiguous and indexable.
    $arr = New-Object 'System.Collections.Generic.List[datetime]'
    foreach ($d in $set) { [void]$arr.Add($d) }
    # No comma-protection: callers assign directly and index/.Count this; the
    # comma wrapper would make .Count always read 1. @()-wrap at the call site.
    return [datetime[]]$arr.ToArray()
}

function Get-SiLatestSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)
    if ($null -eq $Rows -or $Rows.Count -eq 0) { return @() }
    $times = @(Get-SiCollectionTimes -Rows $Rows)
    if ($times.Count -eq 0) { return @() }
    $max = $times[$times.Count - 1]
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Rows) {
        if ((ConvertTo-SiTime $r.CollectionTime) -eq $max) { [void]$out.Add($r) }
    }
    # No comma-protection: callers @()-wrap, and @(,@(...)) does NOT cancel in
    # PS 5.1 (it leaves a single-element wrapper -> nested-array bugs). Return plain.
    return $out.ToArray()
}

# ---------------------------------------------------------------------------
# Snapshot diff. Compares the two most-recent CollectionTime snapshots (or two
# explicit snapshots passed as -CurrentRows / -PreviousRows). Identity is the
# ConfigurationId. A finding is:
#   new       -- present now, absent before
#   closed    -- present before, absent now (or score fell to/below ClosedThreshold)
#   open      -- present in both
#   regressed -- open AND score went up by >= MoveThreshold
#   improved  -- open AND score went down by >= MoveThreshold
# Returns counts + the row lists + the total-score delta.
# ---------------------------------------------------------------------------
function Get-SiSnapshotDiff {
    [CmdletBinding(DefaultParameterSetName='Auto')]
    param(
        [Parameter(Mandatory, ParameterSetName='Auto')][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory, ParameterSetName='Explicit')][AllowEmptyCollection()][object[]]$CurrentRows,
        [Parameter(Mandatory, ParameterSetName='Explicit')][AllowEmptyCollection()][object[]]$PreviousRows,
        [double]$ClosedThreshold = 0,
        [double]$MoveThreshold = 0.01
    )

    if ($PSCmdlet.ParameterSetName -eq 'Auto') {
        $times = @(Get-SiCollectionTimes -Rows $Rows)
        if ($times.Count -eq 0) {
            return [pscustomobject]@{
                New=@(); Closed=@(); Open=@(); Regressed=@(); Improved=@()
                NewCount=0; ClosedCount=0; OpenCount=0; RegressedCount=0; ImprovedCount=0
                CurrentTotal=0.0; PreviousTotal=0.0; ScoreDelta=0.0
                CurrentTime=$null; PreviousTime=$null
            }
        }
        $cur = $times[$times.Count - 1]
        $prev = if ($times.Count -ge 2) { $times[$times.Count - 2] } else { $null }
        $CurrentRows = @($Rows | Where-Object { (ConvertTo-SiTime $_.CollectionTime) -eq $cur })
        $PreviousRows = if ($null -ne $prev) { @($Rows | Where-Object { (ConvertTo-SiTime $_.CollectionTime) -eq $prev }) } else { @() }
    }

    # Index by ConfigurationId (last write wins per snapshot).
    $curIdx = @{}
    foreach ($r in $CurrentRows) { if ($null -ne $r) { $curIdx[[string]$r.ConfigurationId] = $r } }
    $prevIdx = @{}
    foreach ($r in $PreviousRows) { if ($null -ne $r) { $prevIdx[[string]$r.ConfigurationId] = $r } }

    $new = New-Object System.Collections.Generic.List[object]
    $closed = New-Object System.Collections.Generic.List[object]
    $open = New-Object System.Collections.Generic.List[object]
    $regressed = New-Object System.Collections.Generic.List[object]
    $improved = New-Object System.Collections.Generic.List[object]

    foreach ($id in $curIdx.Keys) {
        $row = $curIdx[$id]
        $curScore = [double]$row.RiskScoreTotal
        if (-not $prevIdx.ContainsKey($id)) {
            [void]$new.Add($row)
        } else {
            [void]$open.Add($row)
            $prevScore = [double]$prevIdx[$id].RiskScoreTotal
            $delta = $curScore - $prevScore
            if ($delta -ge $MoveThreshold) {
                [void]$regressed.Add([pscustomobject]@{ Row=$row; PreviousScore=$prevScore; CurrentScore=$curScore; Delta=$delta })
            } elseif ($delta -le (-1 * $MoveThreshold)) {
                [void]$improved.Add([pscustomobject]@{ Row=$row; PreviousScore=$prevScore; CurrentScore=$curScore; Delta=$delta })
            }
        }
    }

    # Closed = in previous, not in current, OR present-but-fell to/below threshold.
    foreach ($id in $prevIdx.Keys) {
        if (-not $curIdx.ContainsKey($id)) {
            [void]$closed.Add($prevIdx[$id])
        } else {
            $curScore = [double]$curIdx[$id].RiskScoreTotal
            $prevScore = [double]$prevIdx[$id].RiskScoreTotal
            if ($prevScore -gt $ClosedThreshold -and $curScore -le $ClosedThreshold) {
                [void]$closed.Add($curIdx[$id])
            }
        }
    }

    # Normalise to arrays -- under StrictMode an unbound param ($null, from the
    # other parameter set) or a scalar would make .Count / [0] throw. Build the
    # arrays element-by-element so an empty/$null source can never collapse to $null.
    $curArr  = New-Object System.Collections.Generic.List[object]
    if ($null -ne $CurrentRows)  { foreach ($r in $CurrentRows)  { [void]$curArr.Add($r) } }
    $prevArr = New-Object System.Collections.Generic.List[object]
    if ($null -ne $PreviousRows) { foreach ($r in $PreviousRows) { [void]$prevArr.Add($r) } }

    $curTotal = 0.0; foreach ($r in $curArr) { $curTotal += [double]$r.RiskScoreTotal }
    $prevTotal = 0.0; foreach ($r in $prevArr) { $prevTotal += [double]$r.RiskScoreTotal }

    $curTime = $null; $prevTime = $null
    if ($curArr.Count -gt 0) { $curTime = ConvertTo-SiTime $curArr[0].CollectionTime }
    if ($prevArr.Count -gt 0) { $prevTime = ConvertTo-SiTime $prevArr[0].CollectionTime }

    return [pscustomobject]@{
        New            = @($new.ToArray())
        Closed         = @($closed.ToArray())
        Open           = @($open.ToArray())
        Regressed      = @($regressed.ToArray())
        Improved       = @($improved.ToArray())
        NewCount       = $new.Count
        ClosedCount    = $closed.Count
        OpenCount      = $open.Count
        RegressedCount = $regressed.Count
        ImprovedCount  = $improved.Count
        CurrentTotal   = [math]::Round($curTotal, 2)
        PreviousTotal  = [math]::Round($prevTotal, 2)
        ScoreDelta     = [math]::Round(($curTotal - $prevTotal), 2)
        CurrentTime    = $curTime
        PreviousTime   = $prevTime
    }
}

# ---------------------------------------------------------------------------
# Score timeline. One point per CollectionTime: total score, finding count, and
# a per-tier breakdown (keyed by CriticalityTierLevel). Adds a percent delta vs
# the prior point for the headline caption ("down 12%").
# ---------------------------------------------------------------------------
function Get-SiScoreTimeline {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)

    $byTime = @{}
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $t = ConvertTo-SiTime $r.CollectionTime
        $key = $t.ToString('o')
        if (-not $byTime.ContainsKey($key)) {
            $byTime[$key] = [pscustomobject]@{
                CollectionTime = $t
                TotalScore = 0.0
                FindingCount = 0
                PerTier = @{}
            }
        }
        $pt = $byTime[$key]
        $pt.TotalScore += [double]$r.RiskScoreTotal
        $pt.FindingCount += 1
        $tier = if ($r.PSObject.Properties.Name -contains 'CriticalityTierLevel' -and $r.CriticalityTierLevel) { [string]$r.CriticalityTierLevel } else { 'Unclassified' }
        if (-not $pt.PerTier.ContainsKey($tier)) { $pt.PerTier[$tier] = 0.0 }
        $pt.PerTier[$tier] += [double]$r.RiskScoreTotal
    }

    $points = @($byTime.Values | Sort-Object CollectionTime)
    $out = New-Object System.Collections.Generic.List[object]
    $prev = $null
    foreach ($p in $points) {
        $pct = $null
        $delta = $null
        if ($null -ne $prev -and $prev.TotalScore -ne 0) {
            $delta = [math]::Round(($p.TotalScore - $prev.TotalScore), 2)
            $pct = [math]::Round((($p.TotalScore - $prev.TotalScore) / $prev.TotalScore) * 100, 1)
        }
        [void]$out.Add([pscustomobject]@{
            CollectionTime = $p.CollectionTime.ToString('o')
            TotalScore     = [math]::Round($p.TotalScore, 2)
            FindingCount   = $p.FindingCount
            PerTier        = $p.PerTier
            DeltaFromPrev  = $delta
            PercentFromPrev = $pct
        })
        $prev = $p
    }
    return $out.ToArray()
}
