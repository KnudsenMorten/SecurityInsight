#Requires -Version 5.1
<#
    #400 -- static lint: a join must never match on an EMPTY key.

    WHY. KQL joins "" to "". Both Device_Recommendations reports joined the endpoint profile with
        | join kind=leftouter (_ep) on $left.DI_AadDeviceId == $right.AadDeviceId
    and a device without an Entra device id (servers, Linux, phones, printers, unnamed endpoints) has DI_AadDeviceId "".
    Every such TVM row therefore matched EVERY profile row that also lacks the id, and took that row's name, id, tier and
    cmdb. Measured on the v3 upgrade-test tenant (2026-10-06): Device_Recommendations_Detailed 421 rows on 2.2 ->
    1,099 on 3.0 for 306 distinct findings -- one server's controls on 35 other assets. 2.2 hid it only because its
    dedup collapsed the copies by name; 3.0 keys the dedup on the asset id and shows every copy.

    WHAT IT ENFORCES. For every `join` / `lookup` in the locked catalog, the RIGHT-hand key must be guarded against
    empty -- a `| where isnotempty(<key>)` or `| where <key> != ""` inside the join's parentheses or in the let-binding
    it names -- unless the key is on the NEVER-EMPTY list below, each entry with the reason it cannot be empty. A
    guarded right side is enough: an empty left key then has nothing to match.
    The list is closed for the keys that CAN be empty (Entra device ids, names, UPNs): they may never be listed.

    #505 (CI design, V3-DATA-MODEL 2.21.1). The profile joins (_ep / _ap on AadDeviceId, EpJoinKey, names) are gone:
    a finding is tied to its CI with `join kind=leftouter (_ciLink) on $left.<provider id> == $right._ciKey`, and the
    canonical _ciLink block keeps only `where isnotempty(_ciKey)` -- so the CI link key can never be empty. A RENAME of
    a guarded key (`_ciLink | project _srcCiKey = _ciKey`, or a let-binding over _ciLink that renames it) is guarded too:
    the scanner follows the rename back to the binding it reads.
#>

BeforeAll {
    $script:SolutionRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:LockedYaml   = Join-Path $script:SolutionRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'

    # Right-hand keys that cannot be empty BY CONSTRUCTION. Burn down, never add a key that can be empty.
    $script:NeverEmptyKeys = [ordered]@{
        'Hop1_SourceCredentialId' = 'ExposureGraphEdges.SourceNodeId -- a graph node id is never empty'
        'Hop2_SourceIdentityId'   = 'ExposureGraphEdges.SourceNodeId -- a graph node id is never empty'
        'DeviceId'                = 'Defender DeviceInfo / TVM primary key'
        'CveId'                   = 'DeviceTvmSoftwareVulnerabilitiesKB primary key'
        'ConfigurationId'         = 'DeviceTvmSecureConfigurationAssessmentKB primary key'
        'Category'                = 'static datatable lookup -- it has no empty key row'
        'Subcategory'             = 'static datatable lookup -- it has no empty key row'
        '_dfcKey'                 = 'strcat("h", hash(...)) -- never empty'
        '_pairKey'                = 'strcat(DeviceKey, "|", CVE) -- never empty'
        '_swKey'                  = 'strcat(DeviceId, "|", CveId) over DeviceTvmSoftwareVulnerabilities -- never empty; both parts are that table''s primary key'
    }
    # #690 (3) retired 'LinkedAzureResourceId': the identity-on-resource reports now join on _roleScope (every scope of the
    # resource, guarded by isnotempty(_roleScope) in _publicResourceScopes -- the scanner proves it on its own).
    # #505 retired from the list: '_v3Pk' (the profile table key) and '_kp' (now `_ciLink | project _kp = _ciKey`, a
    # rename of the guarded CI link key, which the scanner proves on its own).
    # Any key whose name contains NodeId is an Exposure Graph node id (NodeId, TargetNodeId, CVENodeId_join, ...).
    $script:NodeIdRx = 'NodeId'

    function Get-SIJoinKeyGuards {
        <# Every join/lookup in a catalog: report, left key, right key, whether the right key is guarded. PURE. #>
        param([Parameter(Mandatory)][string]$Text)
        $lines = $Text -split "`n"
        # comments out (a // inside a string literal such as https:// is preceded by ':' and kept)
        $clean = ($lines | ForEach-Object { $_ -replace '(?<!:)//.*$', '' }) -join "`n"
        $blocks = [regex]::Split($clean, '(?m)^\s*-\s*ReportName:\s*')
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($b in $blocks) {
            $rn = ($b -split "`n")[0].Trim()
            foreach ($jm in [regex]::Matches($b, '\|\s*(?:join|lookup)\b(?:\s+kind\s*=\s*\w+)?\s*')) {
                $i = $jm.Index + $jm.Length
                if ($i -ge $b.Length) { continue }
                if ($b[$i] -eq '(') {
                    $depth = 0; $j = $i
                    for (; $j -lt $b.Length; $j++) {
                        if ($b[$j] -eq '(') { $depth++ } elseif ($b[$j] -eq ')') { $depth--; if ($depth -eq 0) { break } }
                    }
                    $right = $b.Substring($i + 1, $j - $i - 1); $after = $b.Substring($j + 1)
                } else {
                    $nm = [regex]::Match($b.Substring($i), '^(\w+)'); $right = $nm.Value; $after = $b.Substring($i + $nm.Length)
                }
                $on = [regex]::Match($after, '^\s*on\s+([^\r\n]+)')
                if (-not $on.Success) { continue }
                $cond = $on.Groups[1].Value.Trim()
                $m1 = [regex]::Match($cond, '\$left\.(\w+)\s*==\s*\$right\.(\w+)')
                $m2 = [regex]::Match($cond, '\$right\.(\w+)\s*==\s*\$left\.(\w+)')
                if ($m1.Success)     { $lk = $m1.Groups[1].Value; $rk = $m1.Groups[2].Value }
                elseif ($m2.Success) { $lk = $m2.Groups[2].Value; $rk = $m2.Groups[1].Value }
                elseif ($cond -match '^(\w+)\s*$') { $lk = $Matches[1]; $rk = $Matches[1] }
                else { continue }   # multi-column keys (summary re-joins on the grouping columns) are not ids
                # the binding the join names: the LAST definition of it before the join
                $bind = $right
                $nameOnly = [regex]::Match($right.Trim(), '^(\w+)')
                if ($nameOnly.Success) {
                    $defs = @([regex]::Matches($b.Substring(0, $jm.Index), '\blet\s+' + [regex]::Escape($nameOnly.Groups[1].Value) + '\s*=([^;]*);'))
                    if ($defs.Count) { $bind = $right + "`n" + $defs[$defs.Count - 1].Groups[1].Value }
                }
                $k = [regex]::Escape($rk)
                $guarded = $bind -match ('\|\s*where\b[^|;]*(?:isnotempty\(\s*(?:tostring\(\s*column_ifexists\(\s*")?' + $k + '\b|\b' + $k + '\s*!=\s*"")')
                $renamedFrom = ''
                if (-not $guarded) {
                    # #505 -- a plain rename of a guarded key is guarded (`_ciLink | project _srcCiKey = _ciKey`). Follow
                    # the rename to its source column, and look for that column's guard in every binding the right side
                    # (or the let-binding it names) reads -- their LAST definition before the join.
                    $ren = [regex]::Match($bind, '(?m)\bproject\b[^;]*?\b' + $k + '\s*=\s*(\w+)\s*(?=,|\)|\||$)')
                    if ($ren.Success -and $ren.Groups[1].Value -ne $rk) {
                        $src = [regex]::Escape($ren.Groups[1].Value)
                        $pre = $b.Substring(0, $jm.Index)
                        $ext = $bind
                        foreach ($w in @([regex]::Matches($bind, '\b(\w+)\b') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)) {
                            $d = @([regex]::Matches($pre, '\blet\s+' + [regex]::Escape($w) + '\s*=([^;]*);'))
                            if ($d.Count) { $ext += "`n" + $d[$d.Count - 1].Groups[1].Value }
                        }
                        if ($ext -match ('\|\s*where\b[^|;]*(?:isnotempty\(\s*(?:tostring\(\s*column_ifexists\(\s*")?' + $src + '\b|\b' + $src + '\s*!=\s*"")')) {
                            $guarded = $true; $renamedFrom = $ren.Groups[1].Value
                        }
                    }
                }
                [void]$out.Add([pscustomobject]@{ Report = $rn; LeftKey = $lk; RightKey = $rk; Guarded = $guarded; RenamedFrom = $renamedFrom; Right = ($right.Trim() -split "`n")[0].Trim() })
            }
        }
        $out.ToArray()
    }

    function Get-SIUnguardedEmptyKeyJoins {
        param([Parameter(Mandatory)][string]$Text)
        @(Get-SIJoinKeyGuards -Text $Text | Where-Object {
            -not $_.Guarded -and -not $script:NeverEmptyKeys.Contains($_.RightKey) -and $_.RightKey -notmatch $script:NodeIdRx })
    }

    $script:CatalogText = [System.IO.File]::ReadAllText($script:LockedYaml)
}

Describe 'a join never matches on an empty key -- #400' {

    It 'the scanner reads the whole locked catalog (control -- green must not mean "scanned nothing")' {
        $all = @(Get-SIJoinKeyGuards -Text $script:CatalogText)
        # #505 -- the profile fallback chains (several joins per finding) are gone, so the catalog has fewer joins
        # (156 on 2026-10-09, was > 250); the CI joins are about a quarter of them.
        $all.Count | Should -BeGreaterThan 140
        @($all | Where-Object Guarded).Count | Should -BeGreaterThan 50
        @($all | Where-Object { $_.RightKey -eq '_ciKey' }).Count | Should -BeGreaterThan 20
        # #677: the other end of a row (a user's device, a path's source and target) is joined on _ciPeer's _peerKey
        @($all | Where-Object { $_.RightKey -eq '_peerKey' -and $_.Guarded }).Count | Should -BeGreaterOrEqual 25 -Because '9 + 16 _ciPeer joins on 2026-10-15'
        @($all | Where-Object { $_.RenamedFrom -eq '_ciKey' }).Count | Should -BeGreaterThan 5 -Because 'the rename rule must see the renamed CI link keys'
        @($all | Where-Object { $_.Report -like 'Device_Recommendations_*' }).Count | Should -BeGreaterThan 8
    }

    It 'the rename rule follows a renamed key to a guarded source only (control)' {
        $base = @(
            '    - ReportName: Synthetic'
            '      ReportQuery:'
            '      - |-'
            '          let _src = T | project k, v;'
            '          let _ren = _src | project _k2 = k, v;'
            '          X'
            '              | join kind=leftouter (_ren) on $left.a == $right._k2'
            '              | join kind=leftouter (_src | project _k3 = k) on $left.b == $right._k3'
        ) -join "`n"
        $hit = @(Get-SIUnguardedEmptyKeyJoins -Text $base)
        @($hit | ForEach-Object RightKey | Sort-Object) | Should -Be @('_k2', '_k3') -Because 'the source column k is not guarded'
        $good = $base.Replace('let _src = T | project k, v;', 'let _src = T | where isnotempty(k) | project k, v;')
        @(Get-SIUnguardedEmptyKeyJoins -Text $good).Count | Should -Be 0
        # an expression is not a rename: tolower(k) can still be empty only if k is, but the rule does not guess
        $expr = $good.Replace('project _k3 = k)', 'project _k3 = strcat(k, ""))')
        @(Get-SIUnguardedEmptyKeyJoins -Text $expr | ForEach-Object RightKey) | Should -Be @('_k3')
    }

    It 'the CI link key can never be empty: every _ciLink block in the catalog, and the canonical generator, guard _ciKey' {
        $blocks = @([regex]::Matches($script:CatalogText, '(?s)//__SI_CI_LINK_BEGIN__(.*?)//__SI_CI_LINK_END__'))
        $blocks.Count | Should -BeGreaterThan 20
        @($blocks | Where-Object { $_.Groups[1].Value -notmatch '\|\s*where isnotempty\(_ciKey\)' }).Count | Should -Be 0
        . (Join-Path $script:SolutionRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
        Get-RACiKqlBlock -Kind link | Should -Match '\|\s*where isnotempty\(_ciKey\)'
        @(Get-SIJoinKeyGuards -Text $script:CatalogText | Where-Object { $_.RightKey -eq '_ciKey' -and -not $_.Guarded }).Count | Should -Be 0
    }

    It 'the scanner fires on the #400 shape (control -- a rule that matches nothing protects nothing)' {
        $bad = @(
            '    - ReportName: Device_Recommendations_Detailed'
            '      ReportQuery:'
            '      - |-'
            '          let _ep = SI_Endpoint_Profile_CL | summarize arg_max(CollectionTime, *) by EpJoinKey | where isnotempty(EpJoinKey) | project EpJoinKey, AadDeviceId;'
            '          TVM_Base'
            '              | join kind=leftouter (_ep)              on $left.DI_AadDeviceId == $right.AadDeviceId'
        ) -join "`n"
        $hit = @(Get-SIUnguardedEmptyKeyJoins -Text $bad)
        $hit.Count | Should -Be 1
        $hit[0].RightKey | Should -Be 'AadDeviceId'
        $good = $bad.Replace('(_ep)', '(_ep | where isnotempty(AadDeviceId))')
        @(Get-SIUnguardedEmptyKeyJoins -Text $good).Count | Should -Be 0
        # a guard in the let-binding it names counts too
        $bound = $bad.Replace('| project EpJoinKey, AadDeviceId;', '| project EpJoinKey, AadDeviceId | where AadDeviceId != "";')
        @(Get-SIUnguardedEmptyKeyJoins -Text $bound).Count | Should -Be 0
    }

    It 'no join or lookup in the locked catalog can match an empty key' {
        $hits = @(Get-SIUnguardedEmptyKeyJoins -Text $script:CatalogText)
        $msg = ($hits | ForEach-Object { '{0}: $left.{1} == $right.{2} (right: {3})' -f $_.Report, $_.LeftKey, $_.RightKey, $_.Right }) -join " || "   # one line: the gate shows the first line of a failure
        $hits.Count | Should -Be 0 -Because ("guard the right key with | where isnotempty(<key>) -- an empty key matches every other empty key: " + $msg)
    }

    It 'both Device_Recommendations reports join the CI on the Defender device id, guarded -- never on the Entra device id' {
        $guards = @(Get-SIJoinKeyGuards -Text $script:CatalogText)
        $dr = @($guards | Where-Object { $_.Report -like 'Device_Recommendations_*' -and $_.LeftKey -eq 'DeviceKey' -and $_.RightKey -eq '_ciKey' })
        $dr.Count | Should -Be 2
        @($dr | Where-Object { -not $_.Guarded }).Count | Should -Be 0
        @($dr | ForEach-Object { $_.Report } | Sort-Object) | Should -Be @('Device_Recommendations_Detailed', 'Device_Recommendations_Summary')
        @($guards | Where-Object { $_.Report -like 'Device_Recommendations_*' -and ($_.LeftKey -match 'AadDeviceId' -or $_.RightKey -match 'AadDeviceId') }).Count | Should -Be 0 -Because 'the #400 join is gone with the profile'
    }

    It 'every never-empty entry is still a key the catalog joins on (the list burns down, it does not go stale)' {
        $used = @(Get-SIJoinKeyGuards -Text $script:CatalogText | ForEach-Object RightKey | Select-Object -Unique)
        foreach ($k in $script:NeverEmptyKeys.Keys) { $used | Should -Contain $k -Because "'$k' is listed as never-empty; remove it if no join uses it" }
    }

    It 'a key that can be empty is never on the never-empty list' {
        foreach ($k in $script:NeverEmptyKeys.Keys) {
            $k | Should -Not -Match '(?i)AadDeviceId|Upn|UserPrincipalName|Name$|_SIName|_dn|_devKey|_scope'
        }
    }
}
