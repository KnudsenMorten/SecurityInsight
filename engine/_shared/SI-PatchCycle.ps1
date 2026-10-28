#Requires -Version 5.1
<#
    THE PATCH CYCLE of a missing patch (#636, owner 2026-10-19: "we need a filter option, where we filter between 'being
    fixed during monthly lifecycle' vs. 'catch-up older than 1 month'" / "make sure the emails are also adjusted to the new
    conclusions, so we dont send wrong signals. include both angles with gaps vs. monthly lifecycle").

    A raw count of missing CVEs overstates the work: one monthly cumulative update closes hundreds of CVEs per device.
    Every place that shows missing patches shows the three groups side by side instead:
      cycle    IN THE MONTHLY CYCLE -- the recommended update was released at most -CatchUpDays (SI_PatchCycle_CatchUpDays,
               30) before the collection: the normal rollout, no action
      catchup  CATCH-UP -- the update is older: these devices are behind; act on these
      nofix    NO SINGLE UPDATE / NO FIX -- no recommended update (browsers, third-party software, configuration): fixed by
               their own owner
      unknown  an update whose month cannot be read from its name -- NOT CLASSIFIED (unknown cycle); every place that shows
               the three groups also shows this one whenever it is above 0 (#906: never hide findings)
    The finding's own si_patch_cycle wins when a source gives it ("In monthly cycle", "Catch-up (older than 1 month)", "No
    fix available", "Unknown"). The release of an update is the 2nd Tuesday of the month its name says ("October 2026
    Security Updates"). The SQL twin is the data sync's key figures (engine\pro-data\_shared\SI-DataKeyFigures.ps1,
    Get-SIKeyFigurePatchesSql); a test holds the two equal. PURE throughout; Community and Pro alike (no SQL).
#>

$script:SIPatchCycleMonths = @{ january = 1; february = 2; march = 3; april = 4; may = 5; june = 6; july = 7; august = 8; september = 9; october = 10; november = 11; december = 12 }

function Get-SIPatchCycleMonth {
    <# PURE. The first day of the month an update's name says ("October 2026 Security Updates"), $null when it names none. #>
    param([string]$UpdateName)
    if (-not $UpdateName) { return $null }
    $y = [regex]::Match($UpdateName, '20[0-9][0-9]')
    if (-not $y.Success) { return $null }
    $low = $UpdateName.ToLowerInvariant()
    # the lowest month number whose name is in the text (the SQL twin: TOP (1) ... ORDER BY the month number)
    $m = @($script:SIPatchCycleMonths.GetEnumerator() | Where-Object { $low.Contains($_.Key) } | Sort-Object Value | Select-Object -First 1)
    if (-not $m.Count) { return $null }
    [datetime]::new([int]$y.Value, [int]$m[0].Value, 1)
}

function Get-SIPatchCycleRelease {
    <# PURE. The release of a month's updates: its 2nd Tuesday. #>
    param([Parameter(Mandatory)][datetime]$Month)
    $first = [datetime]::new($Month.Year, $Month.Month, 1)
    $offset = (([int][DayOfWeek]::Tuesday) - [int]$first.DayOfWeek + 7) % 7
    $first.AddDays(7 + $offset)
}

function Get-SIPatchCycle {
    <# PURE. cycle | catchup | nofix | unknown for one missing patch (see above). #>
    param([string]$Given, [string]$UpdateId, [string]$UpdateName, [Parameter(Mandatory)][datetime]$CollectionTime, [int]$CatchUpDays = 30)
    $g = "$Given".Trim().ToLowerInvariant()
    if ($g.StartsWith('in monthly')) { return 'cycle' }
    if ($g.StartsWith('catch')) { return 'catchup' }
    if ($g.StartsWith('no fix')) { return 'nofix' }
    if ($g.StartsWith('unknown')) { return 'unknown' }
    if (-not "$UpdateId".Trim() -and -not "$UpdateName".Trim()) { return 'nofix' }
    $month = Get-SIPatchCycleMonth -UpdateName $UpdateName
    if ($null -eq $month) { return 'unknown' }
    $days = ($CollectionTime.Date - (Get-SIPatchCycleRelease -Month $month).Date).Days
    if ($days -le $CatchUpDays) { return 'cycle' }
    'catchup'
}

function New-SIPatchCycleTally {
    <# A tally to add the rows of a run to, one at a time (the Risk Analysis KPI loop pages its rows). #>
    param([datetime]$CollectionTime = [datetime]::UtcNow, [int]$CatchUpDays = 30)
    [pscustomobject]@{
        CollectionTime = $CollectionTime; CatchUpDays = $CatchUpDays; Findings = [long]0
        Devices = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        Groups = @{ cycle = [long]0; catchup = [long]0; nofix = [long]0; unknown = [long]0 }
        GroupDevices = @{
            cycle = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            catchup = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            nofix = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            unknown = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        }
        CatchUpFixes = @{}
        Cycles = @{}
    }
}

function Get-SIPatchCycleRowValue {
    <# PURE. The first of -Names that the row carries with a value ('' when none). #>
    param($Row, [string[]]$Names)
    foreach ($n in $Names) {
        $v = $null
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { $v = $Row[$n] } }
        elseif ($null -ne $Row -and $Row.PSObject.Properties[$n]) { $v = $Row.$n }
        if ($null -ne $v -and "$v".Trim()) { return "$v".Trim() }
    }
    ''
}

function Add-SIPatchCycleRow {
    <# Adds one Risk Analysis row: a CVE finding only (its CVE id, else a configuration id that is one). Cheap for any other row. #>
    param([Parameter(Mandatory)]$Tally, $Row)
    if ($null -eq $Row) { return }
    $cve = Get-SIPatchCycleRowValue $Row @('si_cve', 'Cve', 'CveId')
    if (-not $cve) { $cfg = Get-SIPatchCycleRowValue $Row @('ConfigurationId'); if ($cfg -like 'CVE-*') { $cve = $cfg } }
    if (-not $cve) { return }
    $uid = Get-SIPatchCycleRowValue $Row @('si_fix_recommended_update_id', 'RecommendedSecurityUpdateId')
    $upd = Get-SIPatchCycleRowValue $Row @('si_fix_recommended_update', 'RecommendedSecurityUpdate')
    $key = "$uid|$upd"
    if ($Tally.Cycles.ContainsKey($key) -and -not (Get-SIPatchCycleRowValue $Row @('si_patch_cycle'))) { $c = $Tally.Cycles[$key] }
    else {
        $c = Get-SIPatchCycle -Given (Get-SIPatchCycleRowValue $Row @('si_patch_cycle')) -UpdateId $uid -UpdateName $upd -CollectionTime $Tally.CollectionTime -CatchUpDays $Tally.CatchUpDays
        if (-not (Get-SIPatchCycleRowValue $Row @('si_patch_cycle'))) { $Tally.Cycles[$key] = $c }
    }
    $dev = Get-SIPatchCycleRowValue $Row @('si_ci_id', 'SI_AssetId', 'AssetId', 'AssetName')
    $Tally.Findings++
    $Tally.Groups[$c]++
    if ($dev) { [void]$Tally.Devices.Add($dev); [void]$Tally.GroupDevices[$c].Add($dev) }
    if ($c -eq 'catchup' -and $uid) {
        if (-not $Tally.CatchUpFixes.ContainsKey($uid)) {
            $Tally.CatchUpFixes[$uid] = [pscustomobject]@{ Id = $uid; Name = $upd; Findings = [long]0; Devices = (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)); Month = (Get-SIPatchCycleMonth -UpdateName $upd) }
        }
        $fx = $Tally.CatchUpFixes[$uid]; $fx.Findings++; if ($dev) { [void]$fx.Devices.Add($dev) }
    }
}

function Complete-SIPatchCycleTally {
    <#
        PURE. The tally as plain numbers: Findings, Devices and per group (cycle, catchup, nofix, unknown) Findings, Devices
        and Share (percent of the findings); the catch-up fixes oldest and largest first with how many months behind.
    #>
    param([Parameter(Mandatory)]$Tally)
    $groups = foreach ($g in 'cycle', 'catchup', 'nofix', 'unknown') {
        $n = [long]$Tally.Groups[$g]
        [pscustomobject]@{ Code = $g; Findings = $n; Devices = [long]$Tally.GroupDevices[$g].Count
                           Share = $(if ($Tally.Findings -gt 0) { [Math]::Round(100.0 * $n / $Tally.Findings, 1) } else { 0.0 }) }
    }
    $col = [datetime]::new($Tally.CollectionTime.Year, $Tally.CollectionTime.Month, 1)
    $fixes = @($Tally.CatchUpFixes.Values | ForEach-Object {
        $behind = $null; if ($null -ne $_.Month) { $behind = (($col.Year - $_.Month.Year) * 12) + $col.Month - $_.Month.Month }
        [pscustomobject]@{ Id = $_.Id; Name = $_.Name; Findings = $_.Findings; Devices = [long]$_.Devices.Count; MonthsBehind = $behind }
    } | Sort-Object @{ Expression = { if ($null -eq $_.MonthsBehind) { -1 } else { $_.MonthsBehind } }; Descending = $true }, @{ Expression = 'Findings'; Descending = $true })
    [pscustomobject]@{ Findings = [long]$Tally.Findings; Devices = [long]$Tally.Devices.Count; CatchUpDays = $Tally.CatchUpDays; Groups = @($groups); CatchUpFixes = $fixes }
}

function ConvertTo-SIPatchCycleMailHtml {
    <#
        PURE. "Missing patches" in a mail (the one SI mail layout): the three groups side by side with their share and devices,
        the total only after them, catch-up first in what to do, what catch-up means. '' when the run has no missing patch.
    #>
    param($Summary)
    if ($null -eq $Summary -or [long]$Summary.Findings -le 0) { return '' }
    if (-not (Get-Command -Name ConvertTo-SIMailHeadingHtml -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-MailLayout.ps1')) }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $g = @{}; foreach ($x in @($Summary.Groups)) { $g[[string]$x.Code] = $x }
    $line = { param($code) $x = $g[$code]; [string]::Format($inv, '<strong>{0:N0}</strong> findings on {1:N0} devices ({2:0.0} %)', $x.Findings, $x.Devices, $x.Share) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append((ConvertTo-SIMailHeadingHtml 'Missing patches'))
    [void]$sb.Append((ConvertTo-SIMailLineHtml -Topic '1. In monthly cycle' -Html ((& $line 'cycle') + ' &mdash; the normal rollout, no action')))
    [void]$sb.Append((ConvertTo-SIMailLineHtml -Topic '2. Catch-up' -Html ((& $line 'catchup') + ' &mdash; the fix is older than the monthly cycle: <strong>act on these</strong>')))
    [void]$sb.Append((ConvertTo-SIMailLineHtml -Topic '3. No single update / no fix' -Html ((& $line 'nofix') + ' &mdash; browsers, third-party software, configuration: who owns those updates?')))
    # #906: never hide a finding -- the ones no group takes are said, with the same words as the Executive page
    if ([long]$g['unknown'].Findings -gt 0) { [void]$sb.Append((ConvertTo-SIMailLineHtml -Topic 'Not classified (unknown cycle)' -Html ((& $line 'unknown') + ' &mdash; an update whose month cannot be read; counted in none of the three groups'))) }
    [void]$sb.Append((ConvertTo-SIMailLineHtml -Topic 'All together' -Html ([string]::Format($inv, '{0:N0} findings on {1:N0} devices &mdash; one monthly cumulative update can close hundreds of CVEs per device: read the groups, not the total', $Summary.Findings, $Summary.Devices))))
    $top = @($Summary.CatchUpFixes) | Select-Object -First 1
    if ($top) {
        $behind = if ($null -eq $top.MonthsBehind) { 'how far behind is not known' } elseif ($top.MonthsBehind -le 1) { '1 month behind' } else { "$($top.MonthsBehind) months behind" }
        [void]$sb.Append((ConvertTo-SIMailLineHtml -Topic 'First: catch-up' -Html ([string]::Format($inv, 'start with KB{0} ({1}, {2}): {3:N0} findings on {4:N0} devices', ([string]$top.Id).TrimStart('K', 'B'), [System.Net.WebUtility]::HtmlEncode([string]$top.Name), $behind, $top.Findings, $top.Devices))))
    }
    $L = $script:SIMailLayout
    [void]$sb.Append(('<p style="{0}font-size:12px;line-height:1.5;color:{1};margin:4px 0 14px 0;" data-mail-patch-scope>Catch-up = the recommended update was released more than {2} days before this run (SI_PatchCycle_CatchUpDays).</p>' -f $L.Font, $L.Muted, [int]$Summary.CatchUpDays))
    $sb.ToString()
}
