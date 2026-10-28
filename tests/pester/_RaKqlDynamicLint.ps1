#Requires -Version 5.1
<#
    The static lint behind SIv3-RaKqlDynamicTypes.Tests.ps1: every argument of set_has_element (the set), set_difference
    (all) and strcat_array (the array) in a Risk Analysis query must be DYNAMIC -- a dynamic-producing call (dynamic(),
    todynamic(), pack_array(), make_set(), split(), set_*, array_* ...), a property of a dynamic value (X.Categories), a
    coalesce / iff with a dynamic branch, column_ifexists(..., dynamic(...)), a dynamic source column of the graph tables, or
    a name the query assigns from one of those. Ring 1, 2026-10-10: a list that reached these functions as TEXT failed 24
    reports at once ("set_has_element(): argument #1 must be a dynamic"). Pure; no Kusto needed.
#>

$script:RAKqlDynamicCalls = '^(?:dynamic|todynamic|parse_json|pack_array|pack|bag_pack|pack_dictionary|make_set|make_set_if|make_list|make_list_if|make_list_with_nulls|make_bag|make_bag_if|split|extract_all|bag_keys|bag_merge|bag_remove_keys|array_[a-z_]+|set_[a-z_]+|range|zip|treepath|mv_[a-z_]+)\s*\('
# graph / Defender columns that are dynamic in the source table
$script:RAKqlDynamicSourceColumns = @('Categories', 'EntityIds', 'NodeProperties', 'EdgeProperties', 'SourceNodeCategories', 'TargetNodeCategories')

function Get-RAKqlStripped {
    param([string]$Kql)
    $s = [regex]::Replace($Kql, '(?m)//[^\r\n]*', '')
    $s = [regex]::Replace($s, '@?"(?:[^"\\\r\n]|\\.)*"', '"s"')
    $s = [regex]::Replace($s, "@?'(?:[^'\\\r\n]|\\.)*'", "'s'")
    return $s
}

function Split-RAKqlArgs {
    <# The top-level arguments of the call whose '(' is at $Open. #>
    param([string]$S, [int]$Open)
    $args2 = New-Object System.Collections.Generic.List[string]
    $d = 0; $start = $Open + 1
    for ($i = $Open; $i -lt $S.Length; $i++) {
        $c = $S[$i]
        if ($c -eq '(' -or $c -eq '[' -or $c -eq '{') { $d++ }
        elseif ($c -eq ')' -or $c -eq ']' -or $c -eq '}') {
            $d--
            if ($d -eq 0) { $args2.Add($S.Substring($start, $i - $start).Trim()); break }
        }
        elseif ($c -eq ',' -and $d -eq 1) { $args2.Add($S.Substring($start, $i - $start).Trim()); $start = $i + 1 }
    }
    return $args2.ToArray()
}

function Get-RAKqlAssignments {
    <# Every expression the query assigns to $Name (`Name = <expr>` in extend / project / summarize / let / mv-apply). #>
    param([string]$S, [string]$Name)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($S, '(?<![\w.])' + [regex]::Escape($Name) + '\s*=(?!=)\s*')) {
        $i = $m.Index + $m.Length; $d = 0; $st = $i
        for (; $i -lt $S.Length; $i++) {
            $c = $S[$i]
            if ($c -eq '(' -or $c -eq '[' -or $c -eq '{') { $d++ }
            elseif ($c -eq ')' -or $c -eq ']' -or $c -eq '}') { if ($d -eq 0) { break }; $d-- }
            elseif ($d -eq 0 -and ($c -eq ',' -or $c -eq '|' -or $c -eq ';')) { break }
        }
        $out.Add($S.Substring($st, $i - $st).Trim())
    }
    return $out.ToArray()
}

function Test-RAKqlDynamicExpr {
    param([string]$S, [string]$Expr, [int]$Depth = 0, [hashtable]$Seen = @{})
    $e = $Expr.Trim()
    while ($e.StartsWith('(') -and $e.EndsWith(')') -and @(Split-RAKqlArgs -S $e -Open 0).Count -eq 1 -and @(Split-RAKqlArgs -S $e -Open 0)[0].Length -eq $e.Length - 2) { $e = $e.Substring(1, $e.Length - 2).Trim() }
    if ($Depth -gt 6 -or -not $e) { return $false }
    if ($e -match $script:RAKqlDynamicCalls) { return $true }
    if ($e -match '^(coalesce|iff|iif|case)\s*\(') {
        $a = @(Split-RAKqlArgs -S $e -Open $e.IndexOf('('))
        $cand = switch -Regex ($Matches[1]) { '^(iff|iif)$' { @($a | Select-Object -Skip 1) } '^case$' { @(for ($k = 1; $k -lt $a.Count; $k += 2) { $a[$k] }) + @($a[-1]) } default { $a } }
        foreach ($x in $cand) { if (Test-RAKqlDynamicExpr -S $S -Expr $x -Depth ($Depth + 1) -Seen $Seen) { return $true } }
        return $false
    }
    if ($e -match '^column_ifexists\s*\(') {
        $a = @(Split-RAKqlArgs -S $e -Open $e.IndexOf('('))
        return ($a.Count -ge 2 -and (Test-RAKqlDynamicExpr -S $S -Expr $a[1] -Depth ($Depth + 1) -Seen $Seen))
    }
    # a property or element of a dynamic value is dynamic
    if ($e -match '^[A-Za-z_]\w*(\.[A-Za-z_]\w*|\[[^\]]+\])+$') { return $true }
    if ($e -match '^[A-Za-z_]\w*$') {
        if ($script:RAKqlDynamicSourceColumns -contains $e) { return $true }
        if ($Seen.ContainsKey($e)) { return $false }
        $Seen[$e] = $true
        foreach ($x in (Get-RAKqlAssignments -S $S -Name $e)) { if (Test-RAKqlDynamicExpr -S $S -Expr $x -Depth ($Depth + 1) -Seen $Seen) { return $true } }
        # mv-apply / mv-expand ... to typeof(dynamic)
        if ($S -match ('(?<![\w.])' + [regex]::Escape($e) + '\s*=\s*[^|]*?\bto\s+typeof\(\s*dynamic\s*\)')) { return $true }
        return $false
    }
    return $false
}

function Get-RAKqlDynamicArgViolations {
    <# PURE. 'fn(arg)' for every argument of the three set / array functions that is not shown dynamic. #>
    param([string]$Query)
    $S = Get-RAKqlStripped $Query
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($S, '\b(set_has_element|set_difference|strcat_array)\s*\(')) {
        $fn = $m.Groups[1].Value
        $a = @(Split-RAKqlArgs -S $S -Open ($m.Index + $m.Length - 1))
        $check = if ($fn -eq 'set_difference') { $a } else { @($a | Select-Object -First 1) }
        foreach ($x in $check) {
            if (-not (Test-RAKqlDynamicExpr -S $S -Expr $x -Seen @{})) { $out.Add(('{0}({1})' -f $fn, ($x -replace '\s+', ' '))) }
        }
    }
    return $out.ToArray()
}
