#Requires -Version 5.1
<#
    #677 GUARD OVER THE WHOLE REPORT CATALOG: A JOIN AGAINST A LOOKUP THAT IS CUT PER SLICE USES THE KEY THE SLICE IS CUT ON.

    A report that goes to advanced hunting has its SecurityInsight lookups inlined into the request. A lookup with a
    column the engine keys on (Get-SICLBucketKey -- _ciLink's _ciKey) is CUT per slice: each slice carries the rows whose
    key hashes into it. The graph rows of the slice are cut by the bucket filter on the report's DeviceKey. So a join
    against a cut lookup finds its row only when the row's key IS the slice key -- any other key's lookup row sits in the
    slice its own key hashes to, and the leftouter join comes back empty everywhere else, silently (#677: 19 reports did
    this; #675 the same through a summarize).

    Held for every report that goes to advanced hunting and inlines a lookup: every join whose right side reads a cut
    lookup (directly, or through a let over it, renames followed) has as its LEFT key `DeviceKey`, or the one column the
    report sets DeviceKey to (`| extend DeviceKey = <column>`), and as its RIGHT key the lookup's cut column. The other
    asset of a row -- a device a user signs in to, the source of a path -- is read from a lookup that is NOT cut with the
    rows: _ciPeer, declared under LookupNeededKeys (travels whole while it fits, else reduced to the slice's own keys).
#>

BeforeDiscovery {
    $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $yaml = [IO.File]::ReadAllText((Join-Path $siRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')) -replace "`r", ''
    $catalog = $yaml.Substring(0, $yaml.IndexOf("`nReportTemplates:"))
    $script:ReportCases = @([regex]::Matches($catalog, '(?s)- ReportName: (\S+)\n(.*?)(?=\n    - ReportName: |\z)') |
        ForEach-Object { @{ Name = $_.Groups[1].Value; Body = $_.Groups[2].Value } })
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1')
    $script:_CrossDomainBucketCoalesce = @()
    $script:LetRx = '(?ms)\blet\s+(?<var>\w+)\s*=\s*(?<body>[^;]*?\bSI_[A-Za-z]+(?:_Profile)?_CL\b[^;]*?);'

    function script:Remove-TextAndComments { param([string]$Text)
        $s = [regex]::Replace($Text, '"[^"\n]*"', '""')
        $s = [regex]::Replace($s, "'[^'\n]*'", "''")
        return [regex]::Replace($s, '//[^\n]*', '')
    }
    function script:Get-LookupColumns { param([string]$LetBody)
        $pm = [regex]::Matches($LetBody, '(?s)\|\s*project\s+(?!-)(.*?)(?=\||\)\s*$|$)')
        if ($pm.Count -eq 0) { return @() }
        $last = $pm[$pm.Count - 1].Groups[1].Value
        $depth = 0; $cur = ''; $parts = New-Object System.Collections.Generic.List[string]
        foreach ($ch in $last.ToCharArray()) {
            if ($ch -eq '(' -or $ch -eq '[') { $depth++ } elseif ($ch -eq ')' -or $ch -eq ']') { $depth-- }
            if ($ch -eq ',' -and $depth -le 0) { $parts.Add($cur); $cur = '' } else { $cur += $ch }
        }
        if ($cur.Trim()) { $parts.Add($cur) }
        return @($parts | ForEach-Object { if ($_ -match '^\s*([A-Za-z_]\w*)') { $Matches[1] } } | Where-Object { $_ })
    }
    # The column the engine cuts a lookup's rows on (its first column Get-SICLBucketKey reads), '' when it is not cut.
    # (each column's value is its own name, so the engine's answer IS the column name)
    function script:Get-CutColumn { param([string[]]$Columns)
        if (@($Columns).Count -eq 0) { return '' }
        $all = [ordered]@{}; foreach ($x in $Columns) { $all[$x] = $x }
        return [string](Get-SICLBucketKey -Row ([pscustomobject]$all))
    }
    # Every join of a (stripped) query whose right side reads a cut lookup: @{ Right; LeftKey; RightKey; CutKey }.
    function script:Get-CutLookupJoins { param([string]$Stripped)
        $cut = @{}   # lookup or let over it -> @{ Cut = <column name in it>; Base = <lookup> }
        foreach ($m in [regex]::Matches($Stripped, $script:LetRx)) {
            $c = Get-CutColumn -Columns @(Get-LookupColumns -LetBody $m.Groups['body'].Value)
            if ($c) { $cut[$m.Groups['var'].Value] = @{ Cut = $c; Base = $m.Groups['var'].Value } }
        }
        # a let over a cut lookup (`let X = _ciLink | project k = _ciKey, ...`) is cut on the same key, renamed or not
        foreach ($m in [regex]::Matches($Stripped, '(?ms)\blet\s+(\w+)\s*=\s*(\w+)\b([^;]*);')) {
            $src = $m.Groups[2].Value
            if (-not $cut.ContainsKey($src) -or $cut.ContainsKey($m.Groups[1].Value)) { continue }
            $k = $cut[$src].Cut
            $ren = [regex]::Match($m.Groups[3].Value, '\bproject\b[^;]*?\b(\w+)\s*=\s*' + [regex]::Escape($k) + '\b')
            $cut[$m.Groups[1].Value] = @{ Cut = $(if ($ren.Success) { $ren.Groups[1].Value } else { $k }); Base = $cut[$src].Base }
        }
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($jm in [regex]::Matches($Stripped, '\|\s*(?:join|lookup)\b(?:\s+kind\s*=\s*\w+)?\s*')) {
            $i = $jm.Index + $jm.Length
            if ($i -ge $Stripped.Length) { continue }
            if ($Stripped[$i] -eq '(') {
                $depth = 0; $j = $i
                for (; $j -lt $Stripped.Length; $j++) { if ($Stripped[$j] -eq '(') { $depth++ } elseif ($Stripped[$j] -eq ')') { $depth--; if ($depth -eq 0) { break } } }
                $right = $Stripped.Substring($i + 1, $j - $i - 1); $after = $Stripped.Substring($j + 1)
            } else {
                $nm = [regex]::Match($Stripped.Substring($i), '^(\w+)'); $right = $nm.Value; $after = $Stripped.Substring($i + $nm.Length)
            }
            $first = [regex]::Match($right.Trim(), '^(\w+)').Groups[1].Value
            if (-not $cut.ContainsKey($first)) { continue }
            $k = $cut[$first].Cut
            $ren = [regex]::Match($right, '\bproject\b[^|]*?\b(\w+)\s*=\s*' + [regex]::Escape($k) + '\b')
            if ($ren.Success) { $k = $ren.Groups[1].Value }
            $on = [regex]::Match($after, '^\s*on\s+([^\n]+)')
            $cond = $on.Groups[1].Value.Trim()
            $m1 = [regex]::Match($cond, '\$left\.(\w+)\s*==\s*\$right\.(\w+)'); $m2 = [regex]::Match($cond, '\$right\.(\w+)\s*==\s*\$left\.(\w+)')
            if ($m1.Success) { $lk = $m1.Groups[1].Value; $rk = $m1.Groups[2].Value }
            elseif ($m2.Success) { $lk = $m2.Groups[2].Value; $rk = $m2.Groups[1].Value }
            elseif ($cond -match '^(\w+)\s*$') { $lk = $Matches[1]; $rk = $Matches[1] }
            else { $lk = '?'; $rk = '?' }
            $out.Add([pscustomobject]@{ Right = $first; Base = $cut[$first].Base; LeftKey = $lk; RightKey = $rk; CutKey = $k })
        }
        return @($out.ToArray())
    }
    # The keys a report's rows are sliced on: DeviceKey, and the one plain column it sets DeviceKey to.
    function script:Get-SliceKeys { param([string]$Stripped)
        $keys = @('DeviceKey')
        foreach ($m in [regex]::Matches($Stripped, '(?m)\|\s*extend\s+DeviceKey\s*=\s*(\w+)\s*$')) { $keys += $m.Groups[1].Value }
        return @($keys | Select-Object -Unique)
    }
    function script:Get-Violations { param([string]$Query)
        $s = Remove-TextAndComments -Text $Query
        $sk = Get-SliceKeys -Stripped $s
        @(Get-CutLookupJoins -Stripped $s | Where-Object { $_.RightKey -ne $_.CutKey -or $sk -notcontains $_.LeftKey } |
            ForEach-Object { '{0} on {1} == {2} (the lookup {3} is cut on {4}; the rows on {5})' -f $_.Right, $_.LeftKey, $_.RightKey, $_.Base, $_.CutKey, ($sk -join ' / ') })
    }
    function script:Test-GoesToAdvancedHunting { param([string]$Query)
        return (($Query -match '\bExposureGraph(?:Nodes|Edges)\b') -or (Test-RAQueryNeedsAdvancedHunting -Query $Query))
    }
}

Describe 'the guard sees what it guards (controls)' {
    It 'finds the cut lookup joins of the catalog -- green must not mean "scanned nothing"' {
        $yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')) -replace "`r", ''
        $n = 0
        foreach ($m in [regex]::Matches($yaml.Substring(0, $yaml.IndexOf("`nReportTemplates:")), '(?s)- ReportName: (\S+)\n(.*?)(?=\n    - ReportName: |\z)')) {
            $q = $m.Groups[2].Value; $q = $q.Substring([Math]::Max(0, $q.IndexOf('ReportQuery:')))
            if (-not (Test-GoesToAdvancedHunting -Query (Remove-TextAndComments -Text $q))) { continue }
            $n += @(Get-CutLookupJoins -Stripped (Remove-TextAndComments -Text $q)).Count
        }
        $n | Should -BeGreaterThan 20 -Because 'the Device_*, Azure_Recommendations_*, LogonTo and vulnerable-device reports join _ciLink on their slice key'
    }
    It 'catches each shape #677 found (the old queries, in miniature)' {
        $link = "let _ciLink = SI_CI_CL | project _ciKey, si_tier;`n"
        # S1: rows sliced on the user, device CI joined on another key
        Get-Violations -Query ($link + "T | extend DeviceKey = iif(isnotempty(U), U, N)`n| join kind=leftouter (_ciLink) on `$left.DeviceCiKey == `$right._ciKey") | Should -Not -BeNullOrEmpty
        # S2: a let over the cut lookup, renamed, joined on the target's key
        Get-Violations -Query ($link + "let _TargetCi = _ciLink | project _tKey = _ciKey, T = si_tier;`nT | join kind=leftouter (_TargetCi) on `$left.TargetKey == `$right._tKey") | Should -Not -BeNullOrEmpty
        # S3: a renamed projection inside the join, on the source's key
        Get-Violations -Query ($link + "T | join kind=leftouter (_ciLink | project _srcCiKey = _ciKey, S = si_tier) on `$left.SourceCiKey == `$right._srcCiKey") | Should -Not -BeNullOrEmpty
        # aligned: DeviceKey, or the column DeviceKey is set to
        Get-Violations -Query ($link + "T | join kind=leftouter (_ciLink) on `$left.DeviceKey == `$right._ciKey") | Should -BeNullOrEmpty
        Get-Violations -Query ($link + "N | extend DeviceKey = NodeCiKey`n| join kind=leftouter (_ciLink | project _ciKey, X = si_tier) on `$left.NodeCiKey == `$right._ciKey") | Should -BeNullOrEmpty
        # a lookup the slices do not cut (no key column the engine reads) is out of scope here (SIv3-LookupBucketingGuard)
        Get-Violations -Query ("let _ciPeer = SI_CI_CL | project _peerKey = k, peer_tier = t;`nT | join kind=leftouter (_ciPeer) on `$left.SourceCiKey == `$right._peerKey") | Should -BeNullOrEmpty
    }
}

Describe 'every join against a cut lookup is on the slice key -- <Name>' -ForEach $script:ReportCases {
    It 'no join reads a cut lookup on any other key' {
        $q = $Body.Substring([Math]::Max(0, $Body.IndexOf('ReportQuery:')))
        if (-not (Test-GoesToAdvancedHunting -Query (Remove-TextAndComments -Text $q))) { Set-ItResult -Skipped -Because 'answered by Log Analytics itself: nothing is inlined or cut'; return }
        Get-Violations -Query $q | Should -BeNullOrEmpty -Because 'a cut lookup holds a row only in the slice its key hashes to: join it on the slice key, or read the other asset from _ciPeer (declared under LookupNeededKeys)'
    }
}
