#Requires -Version 5.1
<#
    A REPORT THAT SUMMARIZES ITS OWN ASSET LIST MUST ALSO SUMMARIZE THE PAIR.

    🔴 WHY THIS EXISTS, measured 2026-08-29 and not derived by reading. `ImpactedAssetIds` shipped
    ALIGNED and EMPTY on 55 of 62 Summary reports -- correctly-sized lists of empty strings. The
    engine's name -> id map is built from the rows it is handed, and for these reports those rows are
    already SUMMARIZED: after the report's own `summarize ... by`, the per-asset rows are gone.

    The measurement, from a real run with the engine instrumented:

        report=Identity_NoMFA_Summary rows=3
          row0 columns : ... ConfigurationName, ..., AssetId, ...     <- no name column at all
          idByName keys (1) : User missing MFA registration           <- the ConfigurationName fallback
          row0.SI_AssetName = <ABSENT>   row0.AssetName = <ABSENT>   row0.DisplayName = <ABSENT>
          row0.ImpactedAssets = 'AppTest;Helpdesk (Admin, Legacy, AD, L0, T0);...'

    So the map had ONE key -- the finding's name -- while the list it had to resolve held the actual
    user names. Nothing matched, and every id resolved to ''. No engine-side change can fix that: the
    correspondence between a name and its id only exists BEFORE the summarize.

    🔑 THE ONLY PLACE THE PAIR SURVIVES IS THE KQL. `ImpactedAssetPairs = make_set(strcat(<the same
    name expression>, "|", <this row's asset id>))` carries both halves through the summarize as ONE
    token; the engine splits on the LAST '|' (names carry arbitrary punctuation in real estates, ids
    do not) and drops the helper column so it is never shipped.

    🪤 THE NAME EXPRESSION MUST BE THE SAME ONE. If the pair is built from a different expression than
    `ImpactedAssets`, the pair route -- which overwrites BOTH lists -- silently republishes a
    different set of names, and `ImpactedAssetCount` moves with it. That is asserted below by
    comparing the two make_set arguments, not merely by asserting the pair exists.

    🔒 THERE ARE NO EXEMPTIONS, AND THAT IS AN OPERATOR RULING (2026-08-29): *"this must work in all
    summary reports"*, *"both ids and assetnames/list"* -- consistent with the standing contract in
    the handoff, *"si_assetid and si_assetname is a unique identifier all assets have and the
    impactedassetlist and impactedassetids are just the list form of these per row"*.

    🪤 SIX Attack_Paths REPORTS WERE ALMOST EXEMPTED ON A MISREADING, and the misreading is worth
    keeping. Their name looks like a chain -- `strcat_array(TargetAssets_Path, ";")` -- so it reads as
    "many assets, one id, not pairable". It is not: `TargetAssets_Path` is a `make_set` inside a
    summarize whose `by` clause ALREADY CONTAINS THAT ASSET'S OWN ID (`FinalTargetId`,
    `ExposedResourceNodeId`, `DataLocationNodeId` -- one per family, which is why they are named
    individually rather than pattern-matched). One id per group means one name per group, so the pair
    is EXACT here, not an approximation. **Read the by-clause before calling something unpairable.**

    #505 (CI design, V3-DATA-MODEL 2.21.1). The id half of a pair is now the CI's id: `si_ci_id` itself, or a column
    the report defines as `iif(isnotempty(si_ci_id), si_ci_id, <provider id>)` (AssetId / TargetAssetId) so an asset
    no CI links still carries its provider id. The Attack_Paths family pairs against TargetAssetId (Credential_Based:
    the AssetId its CollapsedPaths carries as min(TargetAssetId)), carried per group of the family's node id -- the
    by-clause rule above is unchanged. Retired with the profile: the coalesce(SI_AssetId, AssetId_From_CL, AssetId)
    chain as "the one canonical expression", and the v3-vs-2.2 profile snapshot selectors (maxif / coalesce(V3, Any));
    the CI block selects the newest CI build of the v3-only SI_CI_CL instead.
#>

BeforeAll {
    $script:SIRootDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Catalog   = Join-Path $script:SIRootDir 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'

    # The Attack_Paths reports that build an asset list pair against the id their own CollapsedPaths summarize groups by.
    # Listed here so the test can assert the RIGHT id is used -- a pair that compiled against the
    # wrong id column would still be "present" and would still align.
    # Group = the node id the CollapsedPaths summarize groups by; Pair = the id column the pair carries; Carry = how
    # CollapsedPaths carries that id per group (so the pair stays 1:1 with the group's names).
    $script:PathFamilyIds = @{
        'Attack_Paths_Summary_Github_to_Azure_Resources'                         = @{ Group = 'FinalTargetId';         Pair = 'TargetAssetId'; Carry = 'TargetAssetId = any(TargetAssetId)' }
        'Attack_Paths_Summary_Public_IP_to_VM_with_CVE_Exploitation'             = @{ Group = 'ExposedResourceNodeId'; Pair = 'TargetAssetId'; Carry = 'TargetAssetId = any(TargetAssetId)' }
        'Attack_Paths_Summary_Identity_Group_Membership_to_Privileged_Resources' = @{ Group = 'FinalTargetId';         Pair = 'TargetAssetId'; Carry = 'TargetAssetId = any(TargetAssetId)' }
        'Attack_Paths_Summary_Data_Sensitivity_to_Exposed_Credentials'           = @{ Group = 'DataLocationNodeId';    Pair = 'TargetAssetId'; Carry = 'TargetAssetId = any(TargetAssetId)' }
        'Attack_Paths_Summary_Credential_Based_Lateral_Movement'                 = @{ Group = 'FinalTargetId';         Pair = 'AssetId';       Carry = 'AssetId = min(tostring(column_ifexists("TargetAssetId", "")))' }
    }
    # #690: Attack_Paths_Detailed_Credential_Based_Lateral_Movement left this list -- it is one row per path now (its AssetId
    # is the path source's CI id), so it builds no asset list and no pair (SIv3-AttackPathLabels guards its grain).

    # Balanced-paren extraction of a make_set(...) argument. A regex cannot do this -- every one of
    # these arguments contains nested parentheses, and several contain quoted ')' characters.
    function script:Get-MakeSetArg {
        param([string]$Text)
        $i = $Text.IndexOf('make_set(')
        if ($i -lt 0) { return $null }
        $start = $i + 'make_set('.Length
        $depth = 1
        for ($j = $start; $j -lt $Text.Length; $j++) {
            $c = $Text[$j]
            if     ($c -eq '(') { $depth++ }
            elseif ($c -eq ')') { $depth--; if ($depth -eq 0) { return $Text.Substring($start, $j - $start) } }
        }
        return $null
    }

    # Walk the catalog as TEXT, per report block. Parsing the YAML would work too, but the assertion is
    # about two lines that must sit in the same summarize, which is a text property of the query.
    function script:Get-AllReports {
        $lines   = Get-Content -Path $script:Catalog -Encoding UTF8
        $reports = New-Object System.Collections.ArrayList
        $name    = $null
        $body    = New-Object System.Collections.ArrayList
        foreach ($l in $lines) {
            if ($l -match '^    - ReportName:\s*(.+?)\s*$') {
                if ($name -and $body.Count -gt 0) {
                    [void]$reports.Add([pscustomobject]@{ Name = $name; Body = ($body -join [Environment]::NewLine) })
                }
                $name = $Matches[1]
                $body = New-Object System.Collections.ArrayList
                continue
            }
            if ($name) { [void]$body.Add($l) }
        }
        if ($name -and $body.Count -gt 0) {
            [void]$reports.Add([pscustomobject]@{ Name = $name; Body = ($body -join [Environment]::NewLine) })
        }
        @($reports)
    }

    # only the reports that build an asset NAME list inside their own query
    function script:Get-AssetListReports {
        @($script:AllReports | Where-Object { $_.Body -match '(?m)^\s*ImpactedAssets\s*=' })
    }

    # Every `| project` that FOLLOWS the pair must carry it forward. A projection that omits it
    # discards the helper inside the query, before any engine code runs.
    function script:Get-ReportsDroppingPair {
        $bad = New-Object System.Collections.ArrayList
        foreach ($r in $script:AllReports) {
            $lines = $r.Body -split "`r?`n"
            $pairAt = -1
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match 'ImpactedAssetPairs\s*=') { $pairAt = $i; break }
            }
            if ($pairAt -lt 0) { continue }
            for ($i = $pairAt + 1; $i -lt $lines.Count; $i++) {
                # `project`, not project-away / project-rename / project-keep
                if ($lines[$i] -notmatch '^\s*\|\s*project(\s|$)') { continue }
                $sb = New-Object System.Text.StringBuilder
                [void]$sb.AppendLine($lines[$i])
                for ($j = $i + 1; $j -lt $lines.Count; $j++) {
                    if ($lines[$j] -match '^\s*\|\s*[a-z]') { break }
                    [void]$sb.AppendLine($lines[$j])
                }
                if ($sb.ToString() -notmatch 'ImpactedAssetPairs') { [void]$bad.Add($r.Name); break }
            }
        }
        @($bad)
    }

    # #505 -- "this row's asset id" is the CI's id: si_ci_id, or a column defined from it with a provider-id fallback.
    $script:CiIdColRx = '(?<col>\w+)\s*=\s*(?:iif|iff|case)\(\s*isnotempty\(si_ci_id\),\s*(?:tostring\()?si_ci_id\)?\s*,'

    # The (name, id) halves of a pair token: the make_set argument split at its LAST ', "|", '. A flattened
    # strcat(a, b, "|", id) is the same name as strcat(strcat(a, b), "|", id) -- strcat is associative.
    function script:Split-PairArg {
        param([string]$PairArg)
        $sep = $PairArg.LastIndexOf(', "|", ')
        if ($sep -lt 0 -or -not $PairArg.StartsWith('strcat(') -or -not $PairArg.EndsWith(')')) { return $null }
        $name = $PairArg.Substring('strcat('.Length, $sep - 'strcat('.Length).Trim()
        $id   = $PairArg.Substring($sep + ', "|", '.Length, $PairArg.Length - $sep - ', "|", '.Length - 1).Trim()
        [pscustomobject]@{ Name = $name; Id = $id }
    }
    # A name expression in its flattened form: strcat(a, b) and the bare argument list a, b compare equal.
    function script:Get-FlatName {
        param([string]$Expr)
        $e = $Expr.Trim()
        if ($e.StartsWith('strcat(') -and $e.EndsWith(')')) {
            # only when the outer strcat( closes at the very end
            $depth = 0; $closesAtEnd = $true
            for ($k = 'strcat'.Length; $k -lt $e.Length; $k++) {
                if ($e[$k] -eq '(') { $depth++ } elseif ($e[$k] -eq ')') { $depth--; if ($depth -eq 0 -and $k -lt $e.Length - 1) { $closesAtEnd = $false; break } }
            }
            if ($closesAtEnd) { return $e.Substring('strcat('.Length, $e.Length - 'strcat('.Length - 1).Trim() }
        }
        $e
    }

    $script:AllReports  = script:Get-AllReports
    $script:ListReports = script:Get-AssetListReports
}

Describe 'SI v3 catalog -- ImpactedAssetsList and ImpactedAssetIds are built as a PAIR' {

    It 'finds the reports that build an asset list in their own KQL' {
        # Guards the guard: if the extraction breaks, every assertion below passes vacuously.
        @($script:ListReports).Count | Should -BeGreaterThan 40
    }

    It 'EVERY report that summarizes an asset list also summarizes ImpactedAssetPairs -- no exemptions' {
        $missing = @($script:ListReports |
            Where-Object { $_.Body -notmatch 'ImpactedAssetPairs' } |
            ForEach-Object { $_.Name })
        ($missing -join ', ') | Should -BeExactly ''
    }

    It 'no report BUILDS the pair and then PROJECTS IT AWAY -- the defect that made 11 reports look unfixable' {
        # 🔴 THIS IS THE ONE THAT COST A WHOLE SESSION. 11 reports emitted
        # `ImpactedAssetPairs` from their summarize and then dropped it in a LATER `| project`, so the
        # engine never received the column at all -- measured, not inferred: the engine's own rows for
        # Device_Missing_CVEs_Summary came back with rowsWithPairCol=0 while the rendered KQL plainly
        # contained the aggregate. Every downstream theory (the join key, the hybrid inliner, the AH
        # response shape) was investigated against a column that had already been thrown away inside
        # the query.
        # 🔑 AND IT IS ROUTE-INDEPENDENT, which is why it must be guarded here rather than in the
        # engine: the projection runs inside the KQL, so it fails identically on advanced hunting,
        # LA-direct and the Sentinel data lake. Customers are spread across all three (operator,
        # 2026-08-29: "6000 customers have different config about ah and la with/without datalake",
        # "so it must work for all 6000 customers"), so a route-specific fix would be no fix at all.
        # 🪤 The correlation that nearly sent me the wrong way: every report where the pair worked was
        # LA-direct and every failing one was advanced hunting. That was a COINCIDENCE -- the
        # LA-route reports simply happen not to end in a `project`.
        $dropping = script:Get-ReportsDroppingPair
        ($dropping -join ', ') | Should -BeExactly ''
    }

    It 'no report selects a profile snapshot; every report''s CI block selects the newest CI build' {
        # 🔴 History: BOTH EDITIONS WROTE THE SAME PROFILE TABLES, and a bare max(CollectionTime) handed a report the
        # v2.2 snapshot whenever v2.2 ran last (measured 2026-08-29: SEVEN Identity reports returned ZERO findings).
        # #505 -- the reports read the CI (SI_CI_CL), which only v3 writes, and the canonical block (RA-CiKql.ps1)
        # selects the CIs of the newest build. The v3-vs-2.2 selectors (maxif / coalesce(V3, Any)) are retired with it.
        $txt = (Get-Content -Path $script:Catalog -Encoding UTF8 -Raw)
        ([regex]::Matches($txt, 'toscalar\(\s*SI_[A-Za-z]+_Profile_CL\b')).Count | Should -Be 0
        $blocks = @([regex]::Matches($txt, '(?s)//__SI_CI_(LINK|ASSET)_BEGIN__(.*?)//__SI_CI_\1_END__'))
        $blocks.Count | Should -BeGreaterThan 100 -Because 'every report carries at least one CI block (control)'
        @($blocks | Where-Object { $_.Groups[2].Value -notmatch '\| where _ciBuild == toscalar\(SI_CI_CL \| where TimeGenerated > ago\(\d+d\) \| summarize max\(todatetime\(si_collection_time\)\)\)' }).Count | Should -Be 0
    }

    It 'the Attack_Paths family pairs against the id its own summarize groups by' {
        # Presence is not enough: a pair built against the wrong id column would still align, and
        # would silently attribute one node's id to another node's name.
        $wrong = New-Object System.Collections.ArrayList
        foreach ($n in $script:PathFamilyIds.Keys) {
            $r = @($script:ListReports | Where-Object { $_.Name -eq $n })
            if ($r.Count -ne 1) { [void]$wrong.Add(('{0}: no longer builds an asset list' -f $n)); continue }
            $flat = ($r[0].Body -replace '\s+', ' ')
            $f = $script:PathFamilyIds[$n]
            $want = ('"|", tostring({0})' -f $f.Pair)
            if ($flat -notmatch [regex]::Escape($want)) { [void]$wrong.Add(('{0}: expected {1}' -f $n, $want)) }
            # ...and the node id must still be a grouping key of the summarize the names come from, or the
            # 1:1 that makes this pair exact no longer holds.
            if ($flat -notmatch [regex]::Escape($f.Group + ';')) {
                [void]$wrong.Add(('{0}: {1} is no longer a by-clause key' -f $n, $f.Group))
            }
            # #505 -- the pair's id is carried per group, and it is the CI id of THAT node (its node id where no CI links it)
            if ($flat -notmatch [regex]::Escape($f.Carry)) { [void]$wrong.Add(('{0}: CollapsedPaths no longer carries {1}' -f $n, $f.Carry)) }
            $derive = ('| extend TargetAssetId = iif(isnotempty(si_ci_id), si_ci_id, tostring({0}))' -f $f.Group)
            if ($flat -notmatch [regex]::Escape($derive)) { [void]$wrong.Add(('{0}: expected {1}' -f $n, $derive)) }
        }
        ($wrong -join ' || ') | Should -BeExactly ''
    }

    It 'the pair is built from the SAME name expression as the list' {
        # Two different expressions would republish a different set of names, because the engine's
        # pair route overwrites ImpactedAssetsList as well as ImpactedAssetIds.
        $mismatched = New-Object System.Collections.ArrayList
        $script:PairsCompared = 0
        foreach ($r in $script:ListReports) {
            if ($r.Body -notmatch 'ImpactedAssetPairs') { continue }
            $flat = ($r.Body -replace '\s+', ' ')
            $listIdx = $flat.IndexOf('ImpactedAssets =')
            $pairIdx = $flat.IndexOf('ImpactedAssetPairs =')
            if ($listIdx -lt 0 -or $pairIdx -lt 0) { continue }
            $listArg = script:Get-MakeSetArg $flat.Substring($listIdx)
            # the pair wraps the name in strcat(<name>, "|", <id>) -- take the make_set arg, then peel
            # the leading 'strcat(' and cut at the pair separator.
            $pairArg = script:Get-MakeSetArg $flat.Substring($pairIdx)
            if (-not $listArg -or -not $pairArg) { continue }
            $script:PairsCompared++
            $p = script:Split-PairArg $pairArg
            if (-not $p) { [void]$mismatched.Add(('{0}: pair token has no separator' -f $r.Name)); continue }
            # strcat is associative: strcat(strcat(a, b), "|", id) and strcat(a, b, "|", id) carry the same name
            if ((script:Get-FlatName $p.Name) -ne (script:Get-FlatName $listArg)) {
                [void]$mismatched.Add(('{0}: list=<{1}> pair=<{2}>' -f $r.Name, $listArg.Trim(), $p.Name))
            }
        }
        $script:PairsCompared | Should -BeGreaterThan 40 -Because 'the comparison must have run (control)'
        ($mismatched -join ' || ') | Should -BeExactly ''
    }

    It 'the name comparison tells a different name from a flattened one (control)' {
        (script:Get-FlatName 'strcat(a, " (", b, ")")') | Should -Be (script:Get-FlatName (script:Split-PairArg 'strcat(strcat(a, " (", b, ")"), "|", si_ci_id)').Name)
        (script:Get-FlatName 'strcat(a, " -> ", b)') | Should -Be (script:Get-FlatName (script:Split-PairArg 'strcat(a, " -> ", b, "|", AssetId)').Name)
        (script:Get-FlatName 'strcat(a, " -> ", b)') | Should -Not -Be (script:Get-FlatName (script:Split-PairArg 'strcat(a, " -> ", c, "|", AssetId)').Name)
        (script:Split-PairArg 'strcat(strcat(a, "|", b), "|", si_ci_id)').Id | Should -Be 'si_ci_id' -Because 'the id is cut at the LAST separator'
    }

    It 'every pair carries the CI id -- si_ci_id, or a column the report derives from it' {
        # #505 -- the one canonical id is the CI's (si_ci_id). A report may carry it through a column it defines as
        # iif(isnotempty(si_ci_id), si_ci_id, <provider id>) (AssetId / TargetAssetId), so an asset no CI links still
        # has its provider id. The six Attack_Paths reports pair against their own by-clause id, asserted above, and are
        # named rather than pattern-matched so a NEW divergence still fails.
        $known = @($script:PathFamilyIds.Keys)
        $offenders = New-Object System.Collections.ArrayList
        $checked = 0
        foreach ($r in $script:ListReports) {
            $flat = ($r.Body -replace '\s+', ' ')
            $pairIdx = $flat.IndexOf('ImpactedAssetPairs =')
            if ($pairIdx -lt 0 -or $known -contains $r.Name) { continue }
            $p = script:Split-PairArg (script:Get-MakeSetArg $flat.Substring($pairIdx))
            if (-not $p) { [void]$offenders.Add(('{0}: pair token has no separator' -f $r.Name)); continue }
            $checked++
            $id = $p.Id -replace '^tostring\((\w+)\)$', '$1'
            if ($id -eq 'si_ci_id') { continue }
            $derived = @([regex]::Matches($flat, $script:CiIdColRx) | ForEach-Object { $_.Groups['col'].Value })
            if ($derived -notcontains $id) { [void]$offenders.Add(('{0}: pair id <{1}>' -f $r.Name, $p.Id)) }
        }
        $checked | Should -BeGreaterThan 40 -Because 'the check must have run (control)'
        ($offenders -join ', ') | Should -BeExactly ''
    }

    It 'the id rule rejects a pair whose id is not the CI''s (control)' {
        $flat = '| extend AssetId = iif(isnotempty(si_ci_id), si_ci_id, DeviceKey) | extend Other = tostring(DeviceKey)'
        @([regex]::Matches($flat, $script:CiIdColRx) | ForEach-Object { $_.Groups['col'].Value }) | Should -Be @('AssetId')
    }
}
