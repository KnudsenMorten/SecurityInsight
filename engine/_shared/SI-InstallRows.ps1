#Requires -Version 5.1
<#
    SI v3 -- READ THIS INSTALL'S PROFILE ROWS, NOT THE NEWEST OF ANY INSTALL (#212). One place, one rule.

    🔴 THE TRAP. Two installs can write the same SI_*_Profile_CL tables -- measured 2026-10-02 on the internal tenant:
    the v3 tree stamps SolutionVersion = '3.0.0+v3', the released engine's daily run stamps nothing, and its 13:21 run
    was newer than this install's 06:07 run. A reader that takes `max(CollectionTime)` or
    `arg_max(CollectionTime, *) by PrimaryEntityId` straight off the table then reads the OTHER install's rows -- its
    tiers, its rules -- with no error anywhere.

    🔑 THE RULE. Keep the rows of THIS install's edition (SolutionVersion ending '+v3' for a v3 install, anything else
    for a 2.x one) as soon as this install has written ANY row of its edition in the window. When it has none there
    yet, every row is kept, exactly as before. The filter goes BEFORE the max / arg_max: arg_max-then-filter is a
    different query (finding #83).
      * a customer runs one install: every row is theirs -- nothing changes;
      * an UPGRADE (2.x rows, then +v3 rows, one install): from the first +v3 row on, no 2.x row is read.
        🔴 #397 (v3 upgrade test, 2026-10-05). The earlier rule also kept every 2.x row OLDER than this install's
        first row, so that a weekly-cadence asset last profiled before the upgrade stayed visible. But 3.0 merges and
        renames endpoints that 2.2 kept apart, and each such 2.2 row has its OWN PrimaryEntityId -- so a per-asset
        arg_max over 8 days returned it NEXT TO the merged 3.0 row: 298 endpoint rows on every RA run for 8 days where
        3.0 has 192. The duplicates 3.0 removed came back in the reports. A 2.x row and a 3.x row now never mix.
        The cadence case is closed at its source instead: a fingerprint-cache record written by another edition never
        lets a v3 run skip an asset (FingerprintCache.ps1 stamps si_edition; Invoke-Collect.ps1 checks it), so the
        first complete v3 run writes a v3 row for every asset;
      * two installs on one workspace: the other install's rows are not read once this one has written.
    The edition, not the exact version: 3.0.0+v3 -> 3.0.1+v3 is the same install.

    PURE -- nothing here queries anything. NO Set-StrictMode here (it leaks into the caller's scope).
#>

# No $script: state -- the profilers' readers dot-source this file inside a function.

function Get-SIInstallFamilyPredicateKql {
    <#
        The KQL predicate "this row was written by this install's edition", or $null when the version says nothing
        (empty, '(dev)', or not a version) -- then no filter is applied at all.
    #>
    param([AllowEmptyString()][AllowNull()][string]$SolutionVersion)
    if ([string]::IsNullOrWhiteSpace($SolutionVersion) -or $SolutionVersion -eq '(dev)') { return $null }
    if ($SolutionVersion -notmatch '^[0-9][A-Za-z0-9._\-]{0,48}(\+v3)?$') { return $null }
    $col = 'tostring(column_ifexists("SolutionVersion", ""))'
    if ($SolutionVersion -match '\+v3$') { return ('{0} endswith "+v3"' -f $col) }
    ('not({0} endswith "+v3")' -f $col)
}

function Get-SIInstallRowsFilterKql {
    <#
        The `| where` stage that keeps only this install's rows of -TableName once this install has any row in the last
        -LookbackDays (0 = the whole table); with no row of this install there, every row is kept. Rows of the other
        edition are never read next to this install's (#397). Empty when the version says nothing. No `;`, no
        `| project`, no `//` -- it is inserted into let-blocks whose shape other code reads.
    #>
    param([Parameter(Mandatory)][string]$TableName, [AllowEmptyString()][AllowNull()][string]$SolutionVersion, [int]$LookbackDays = 0)
    if ($TableName -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "not a table name: $TableName" }
    $fam = Get-SIInstallFamilyPredicateKql -SolutionVersion $SolutionVersion
    if (-not $fam) { return '' }
    $win = if ($LookbackDays -gt 0) { (' | where TimeGenerated > ago({0}d)' -f $LookbackDays) } else { '' }
    ('| where {0} or (toscalar({1}{2} | where {0} | count) == 0)' -f $fam, $TableName, $win)
}

function Add-SIInstallRowsFilter {
    <#
        Every read of a profile table in -Query gets the install filter right after the table name, so whatever the
        query does next (max, arg_max, a join) sees this install's rows. -TableName names the tables to filter (default:
        every SI_<x>_Profile_CL). Strings and // comments are left alone; a `let T = ...` definition is not a read.
          T | ...      -> T | where <keep> | ...      (the `let x = T | ...` shape other code parses stays intact)
          T) / T; / end -> T | where <keep>
          anything else (a union list, `join T on`) -> (T | where <keep>)
        Idempotent: a query that already carries the filter is returned unchanged.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query, [AllowEmptyString()][AllowNull()][string]$SolutionVersion,
          [int]$LookbackDays = 0, [string[]]$TableName)
    $fam = Get-SIInstallFamilyPredicateKql -SolutionVersion $SolutionVersion
    if (-not $fam -or [string]::IsNullOrEmpty($Query)) { return $Query }
    if ($Query.Contains(('| where {0} or (toscalar(' -f $fam))) { return $Query }
    $tblRx = if ($TableName) { '\b(?:' + ((@($TableName) | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b' } else { '\bSI_[A-Za-z][A-Za-z0-9]*_Profile_CL\b' }
    $rx = New-Object System.Text.RegularExpressions.Regex ('(?<skip>@?"(?:[^"\\\r\n]|\\.)*"|@?''(?:[^''\\\r\n]|\\.)*''|//[^\r\n]*)|(?<t>' + $tblRx + ')')
    $sb = New-Object System.Text.StringBuilder
    $pos = 0
    foreach ($m in $rx.Matches($Query)) {
        if (-not $m.Groups['t'].Success) { continue }
        $t = $m.Value
        $end = $m.Index + $m.Length
        $i = $end; while ($i -lt $Query.Length -and [char]::IsWhiteSpace($Query[$i])) { $i++ }
        $next = if ($i -lt $Query.Length) { $Query[$i] } else { [char]0 }
        if ($next -eq '=' -and -not ($i + 1 -lt $Query.Length -and $Query[$i + 1] -eq '=')) { continue }   # let T = ... : a definition
        $j = $m.Index - 1; while ($j -ge 0 -and [char]::IsWhiteSpace($Query[$j])) { $j-- }
        if ($j -ge 0 -and $Query[$j] -eq '.') { continue }                                              # a member, not a table
        $filter = Get-SIInstallRowsFilterKql -TableName $t -SolutionVersion $SolutionVersion -LookbackDays $LookbackDays
        [void]$sb.Append($Query, $pos, $m.Index - $pos)
        if ($next -eq '|' -or $next -eq ')' -or $next -eq ';' -or $next -eq [char]0) { [void]$sb.Append($t + ' ' + $filter) }
        else { [void]$sb.Append('(' + $t + ' ' + $filter + ')') }
        $pos = $end
    }
    [void]$sb.Append($Query, $pos, $Query.Length - $pos)
    $sb.ToString()
}
