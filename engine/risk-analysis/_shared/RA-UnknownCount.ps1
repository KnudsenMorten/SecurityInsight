#Requires -Version 5.1
<#
    #546 UNKNOWN IS NEVER A FINDING -- and the run log SAYS how much was unknown, per report.

    A report never turns a missing value into a finding: the CI build lists what it could not decide for an identity's
    origin (si_unknown_fields -- e.g. the password age of a synchronised account whose Active Directory record is not
    collected) and the factors it therefore could not evaluate (si_rf_unknown); the reports read an undecided value as
    null. What a report could NOT judge is counted here, so "0 findings" is never mistaken for "0 problems":

        Identity_PrivilegedUser_StalePassword_Summary: 41 asset(s) in scope could not be judged (value unknown, NOT
        counted as findings) -- old_password 41

    What a report is about is read from its own query (the generic queries name them, #541):
        set_has_element(si_rf_p | si_rf_c, "<factor id>")         a factor           -> CIs whose si_rf_unknown holds it
        set_has_element(si_unknown_fields, "<si field>")          an undecided field -> CIs whose si_unknown_fields holds it
    over the run's CI index (Get-RACiIndex), within the report's tier scope (the scope block's SI_ScopeTiers).

    PURE (the index is passed in). PowerShell 5.1: no ?. / ??, no ternary.
#>

function Get-RAUnknownSubjects {
    <# PURE. The factor ids and SI fields a report query judges: @{ Factors = [string[]]; Fields = [string[]] }. #>
    param([AllowEmptyString()][string]$Query)
    $f = New-Object System.Collections.Generic.List[string]
    $d = New-Object System.Collections.Generic.List[string]
    if (-not $Query) { return @{ Factors = @(); Fields = @() } }
    # comments out: a factor id named in a // line is not a judgement
    $q = [regex]::Replace($Query, '(?m)//[^\r\n]*', '')
    foreach ($m in [regex]::Matches($q, 'set_has_element\(\s*si_rf_[pc]\s*,\s*"([a-z0-9_]+)"\s*\)')) { $v = $m.Groups[1].Value; if (-not $f.Contains($v)) { $f.Add($v) } }
    foreach ($m in [regex]::Matches($q, 'set_has_element\(\s*si_unknown_fields\s*,\s*"([a-z0-9_]+)"\s*\)')) { $v = $m.Groups[1].Value; if (-not $d.Contains($v)) { $d.Add($v) } }
    return @{ Factors = $f.ToArray(); Fields = $d.ToArray() }
}

function Get-RAQueryScopeTiers {
    <# PURE. The tiers of the query's scope block (let SI_ScopeTiers = dynamic([0, 1])), or @() = every tier. #>
    param([AllowEmptyString()][string]$Query)
    if (-not $Query) { return @() }
    $m = [regex]::Match($Query, 'let\s+SI_ScopeTiers\s*=\s*dynamic\(\[([0-9,\s]*)\]\)')
    if (-not $m.Success) { return @() }
    return @(@($m.Groups[1].Value -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
}

function Get-RAItemList {
    <# PURE. A CI value as a string list: an array, a JSON array text, or nothing. #>
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) {
        $s = $Value.Trim(); if (-not $s) { return @() }
        if ($s.StartsWith('[')) { try { return @(@($s | ConvertFrom-Json) | Where-Object { $_ } | ForEach-Object { [string]$_ }) } catch { return @() } }
        return @($s)
    }
    return @(@($Value) | Where-Object { $_ } | ForEach-Object { [string]$_ })
}

function Get-RAUnknownCounts {
    <#
    .SYNOPSIS  PURE. Per subject (factor id / field), how many CIs of the index could not be judged; plus the distinct total.
    .OUTPUTS   @{ Total = <distinct CIs>; By = ordered subject -> count }
    #>
    param([hashtable]$Index, [string[]]$Factors = @(), [string[]]$Fields = @(), [int[]]$Tiers = @())
    $by = [ordered]@{}
    $total = 0
    if ($null -eq $Index -or $null -eq $Index.ById -or (@($Factors).Count + @($Fields).Count) -eq 0) { return @{ Total = 0; By = $by } }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    # (#639 not @(): the run's keyed CI index walks every CI a page at a time here -- one page held, never the set)
    foreach ($ci in $Index.ById.Values) {
        if ($null -eq $ci) { continue }
        $id = [string]$ci.si_ci_id
        if (-not $id -or -not $seen.Add($id)) { continue }
        if (@($Tiers).Count -gt 0) {
            $tp = $ci.PSObject.Properties['si_tier']
            if ($tp -and $null -ne $tp.Value -and "$($tp.Value)" -ne '' -and @($Tiers) -notcontains [int]$tp.Value) { continue }
        }
        $rfu = $ci.PSObject.Properties['si_rf_unknown']; $uf = $ci.PSObject.Properties['si_unknown_fields']
        $rfuList = @(); if ($rfu) { $rfuList = Get-RAItemList $rfu.Value }
        $ufList = @(); if ($uf) { $ufList = Get-RAItemList $uf.Value }
        $hit = $false
        foreach ($x in @($Factors)) { if ($rfuList -contains $x) { if ($by.Contains($x)) { $by[$x]++ } else { $by[$x] = 1 }; $hit = $true } }
        foreach ($x in @($Fields)) { if ($ufList -contains $x) { if ($by.Contains($x)) { $by[$x]++ } else { $by[$x] = 1 }; $hit = $true } }
        if ($hit) { $total++ }
    }
    return @{ Total = $total; By = $by }
}

function Format-RAUnknownLine {
    <# PURE. One plain run-log line for a report, '' when nothing was unknown. #>
    param([string]$ReportName, $Counts)
    if ($null -eq $Counts -or [int]$Counts.Total -le 0) { return '' }
    $parts = @(@($Counts.By.Keys) | ForEach-Object { '{0} {1}' -f $_, $Counts.By[$_] })
    return ('{0}: {1} asset(s) in scope could not be judged (value unknown, NOT counted as findings) -- {2}' -f $ReportName, $Counts.Total, ($parts -join ', '))
}

function Get-RAUnknownLine {
    <# The report's unknown line from the run's CI index ('' when the report judges nothing undecidable or there are no CIs). Never throws. #>
    param([AllowEmptyString()][string]$Query, [string]$ReportName, [hashtable]$Index)
    try {
        $s = Get-RAUnknownSubjects -Query $Query
        if ((@($s.Factors).Count + @($s.Fields).Count) -eq 0) { return '' }
        if ($null -eq $Index) { if (Get-Command -Name Get-RACiIndex -ErrorAction SilentlyContinue) { $Index = Get-RACiIndex } }
        $c = Get-RAUnknownCounts -Index $Index -Factors $s.Factors -Fields $s.Fields -Tiers (Get-RAQueryScopeTiers -Query $Query)
        return (Format-RAUnknownLine -ReportName $ReportName -Counts $c)
    } catch { return '' }
}
