#Requires -Version 5.1
<#
    SI v3 -- ImpactedAssetsList / ImpactedAssetIds ARE A PAIR, and this file EXECUTES the code that
    builds them.

    🔴 WHY IT EXISTS, and it is the sharpest coverage lesson of the session. The pairing shipped with
    `$idByName.Contains($name)` on a `Dictionary[string,string]`. A Dictionary's .Contains() takes a
    KeyValuePair, so that throws:

        Cannot find an overload for "Contains" and the argument count: "1".

    A HASHTABLE has .Contains($key) and returns $false quietly, which is exactly why the wrong method
    reads as correct. On a live Risk Analysis run it failed **every Summary report** -- 61 x
    "report failed -- skipping" -- and the engine produced **ZERO rows**.

    🪤 AND THE OFFLINE SUITE WAS 3068 PASSED / 0 FAILED OVER IT. Every existing guard on this area
    asserts the SOURCE TEXT (that the ids are built by walking $impactedAssets, that $assetIdVals is
    gone). Not one of them ever CALLED Calculate-RiskScore, so the block they describe was never
    executed. A source-shape assertion cannot fail on a runtime method-overload error.

    🔑 So this file calls the real function with real rows. It is slower and fussier than a regex, and
    it is the only kind of test that could have caught this.
#>

BeforeAll {
    $script:SIRoot = (Resolve-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..')).Path
    $script:RiskScorePath = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskScore.ps1'
    # #559: Calculate-RiskScore calls the SI-keyed index lookup (RA-RiskIndexSi.ps1) and the factor impacts (RA-FactorKeys.ps1)
    $script:RiskIndexSiPath = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexSi.ps1'
    $script:FactorKeysPath = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-FactorKeys.ps1'

    # 🔴 RUN THE CHILD FROM A FILE, NEVER FROM -Command. `powershell.exe -Command "<script>"` re-parses
    # the string on the command line and STRIPS INNER DOUBLE QUOTES -- and it does so only when the
    # PARENT is Windows PowerShell 5.1, because pwsh 7 quotes native arguments differently.
    # Measured 2026-08-29 with the identical literal in both parents:
    #     pwsh 7 parent -> child sees ["srv-a|id-a","srv-b|id-b"]     (real JSON)
    #     5.1    parent -> child sees [srv-a|id-a,srv-b|id-b]         (NOT JSON)
    # So the LA-direct JSON-shape test passed under pwsh and failed under 5.1 while the ENGINE was
    # correct in both -- the harness was feeding it a mangled string. A file argument is parsed by
    # nobody, so the child gets the bytes verbatim on either host. This is the same family as the
    # repo's existing rule about passing text to PowerShell via a file rather than inline.
    function script:Invoke-Child {
        param([string]$Script)
        $f = Join-Path ([IO.Path]::GetTempPath()) ("si-pairtest-{0}.ps1" -f [guid]::NewGuid().ToString('N'))
        try {
            # UTF-8 WITH BOM: 5.1 reads a BOM-less file as ANSI (repo audit #70).
            [System.IO.File]::WriteAllText($f, $Script, (New-Object System.Text.UTF8Encoding($true)))
            & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $f 2>&1
        } finally {
            Remove-Item $f -Force -ErrorAction SilentlyContinue
        }
    }

    # Calculate-RiskScore is a large function with a wide surface; invoke it in a CHILD process so a
    # dot-source of the whole RA shared tree cannot leak state into the rest of the suite.
    function script:Invoke-Calc {
        param([object[]]$Rows)
        $rowsLiteral = ($Rows | ForEach-Object {
            "[pscustomobject]@{{ SecurityDomain='{0}'; Category='{1}'; Subcategory='{2}'; ConfigurationName='{3}'; ConfigurationId='{4}'; SecuritySeverity='{5}'; CriticalityTierLevel='{6}'; SI_AssetName='{7}'; SI_AssetId='{8}' }}" -f `
                $_.SecurityDomain, $_.Category, $_.Subcategory, $_.ConfigurationName, $_.ConfigurationId,
                $_.SecuritySeverity, $_.CriticalityTierLevel, $_.SI_AssetName, $_.SI_AssetId
        }) -join ",`n"

        $cmd = @"
`$ErrorActionPreference='Stop'
Set-StrictMode -Off
. '$script:RiskIndexSiPath'
. '$script:FactorKeysPath'
. '$script:RiskScorePath'
`$rows = @(
$rowsLiteral
)
`$idx = New-SIRiskIndexSi -Rows @()   # #559: an empty SI-keyed index

`$out = Calculate-RiskScore -Rows `$rows -RiskIndex `$idx ``
        -CategoryInputName 'Category' -SubCategoryInputName 'Subcategory' ``
        -ConfigurationIdInputName 'ConfigurationId' -SecuritySeverityInputName 'SecuritySeverity' ``
        -CriticalityTierLevelInputName 'CriticalityTierLevel' -ReportName 'T_Summary'
`$r = @(`$out)[0]
`$L = @(`$r.ImpactedAssetsList)
`$I = @(`$r.ImpactedAssetIds)
'RESULT|' + `$L.Count + '|' + `$I.Count + '|' + (`$L -join ';') + '|' + (`$I -join ';')
"@
        ,@(script:Invoke-Child $cmd)
    }

    # Same idea, but the row carries the KQL-side helper column `ImpactedAssetPairs`. Since 2026-08-29
    # ALL 61 Summary reports emit it, so both what it produces and what happens to it afterwards are
    # customer-visible on every report rather than on seven.
    # 🪤 THE PROBE'S FIELD SEPARATOR IS '<>' AND NOT '|' ON PURPOSE. '|' is the pair separator under
    # test, and an asset name is allowed to contain one -- splitting the probe output on '|'
    # re-created inside the test the exact ambiguity the code is being tested for, and reported a
    # correct result as a failure.
    function script:Invoke-CalcPairs {
        param([string]$PairsLiteral)
        $cmd = @"
`$ErrorActionPreference='Stop'
Set-StrictMode -Off
. '$script:RiskIndexSiPath'
. '$script:FactorKeysPath'
. '$script:RiskScorePath'
`$rows = @(
    [pscustomobject]@{ SecurityDomain='Endpoint'; Category='C'; Subcategory='S'
                       ConfigurationName='CVE-1'; ConfigurationId='id-1'
                       SecuritySeverity='High'; CriticalityTierLevel='Low - tier 3'
                       ImpactedAssetPairs = $PairsLiteral }
)
`$idx = New-SIRiskIndexSi -Rows @()   # #559: an empty SI-keyed index

`$out = Calculate-RiskScore -Rows `$rows -RiskIndex `$idx ``
        -CategoryInputName 'Category' -SubCategoryInputName 'Subcategory' ``
        -ConfigurationIdInputName 'ConfigurationId' -SecuritySeverityInputName 'SecuritySeverity' ``
        -CriticalityTierLevelInputName 'CriticalityTierLevel' -ReportName 'T_Summary'
`$r = @(`$out)[0]
`$has = if (`$r.PSObject.Properties['ImpactedAssetPairs']) { 'SHIPPED' } else { 'removed' }
'PAIRS<>' + `$has + '<>' + ((@(`$r.ImpactedAssetsList)) -join ';') + '<>' + ((@(`$r.ImpactedAssetIds)) -join ';') + '<>' + [string]`$r.ImpactedAssetCount
"@
        ,@(script:Invoke-Child $cmd)
    }

    function script:Get-PairsProbe {
        param([object[]]$Out)
        $line = @($Out | Where-Object { "$_" -like 'PAIRS<>*' })[0]
        if (-not $line) { return $null }
        ,@("$line" -split '<>')
    }
}

Describe 'the impacted-asset pair, EXECUTED (not asserted from source text)' {

    It 'runs at all -- a Dictionary method-overload error fails every Summary report' {
        # 🔴 THE REGRESSION. `.Contains($key)` on Dictionary[string,string] throws; `.ContainsKey($key)`
        # is correct. This case is the whole reason the file exists.
        $out = script:Invoke-Calc -Rows @(
            [pscustomobject]@{ SecurityDomain='Endpoint'; Category='C'; Subcategory='S'
                               ConfigurationName='CVE-1'; ConfigurationId='id-1'
                               SecuritySeverity='High'; CriticalityTierLevel='Low - tier 3'
                               SI_AssetName='srv-a'; SI_AssetId='mde:aaa' }
        )
        ($out -join "`n") | Should -Not -Match 'Cannot find an overload'
        ($out -join "`n") | Should -Match 'RESULT\|'
    }

    It 'emits the two lists at EQUAL LENGTH -- they were 555 vs 50 before the pairing' {
        $out = script:Invoke-Calc -Rows @(
            [pscustomobject]@{ SecurityDomain='Endpoint'; Category='C'; Subcategory='S'
                               ConfigurationName='CVE-1'; ConfigurationId='id-1'
                               SecuritySeverity='High'; CriticalityTierLevel='Low - tier 3'
                               SI_AssetName='srv-a'; SI_AssetId='mde:aaa' }
            [pscustomobject]@{ SecurityDomain='Endpoint'; Category='C'; Subcategory='S'
                               ConfigurationName='CVE-1'; ConfigurationId='id-1'
                               SecuritySeverity='High'; CriticalityTierLevel='Low - tier 3'
                               SI_AssetName='srv-b'; SI_AssetId='mde:bbb' }
        )
        $line = @($out | Where-Object { "$_" -like 'RESULT|*' })[0]
        $line | Should -Not -BeNullOrEmpty -Because "Calculate-RiskScore must return a row; got: $($out -join ' / ')"
        $parts = "$line" -split '\|'
        $parts[1] | Should -BeExactly $parts[2] -Because 'the names list and the ids list must be the same length'
    }

    It 'keeps each id at its own NAME position -- ordinal order, so the pairing is readable' {
        $out = script:Invoke-Calc -Rows @(
            [pscustomobject]@{ SecurityDomain='Endpoint'; Category='C'; Subcategory='S'
                               ConfigurationName='CVE-1'; ConfigurationId='id-1'
                               SecuritySeverity='High'; CriticalityTierLevel='Low - tier 3'
                               SI_AssetName='zzz-host'; SI_AssetId='id-for-zzz' }
            [pscustomobject]@{ SecurityDomain='Endpoint'; Category='C'; Subcategory='S'
                               ConfigurationName='CVE-1'; ConfigurationId='id-1'
                               SecuritySeverity='High'; CriticalityTierLevel='Low - tier 3'
                               SI_AssetName='aaa-host'; SI_AssetId='id-for-aaa' }
        )
        $line = @($out | Where-Object { "$_" -like 'RESULT|*' })[0]
        $parts = "$line" -split '\|'
        $names = $parts[3] -split ';'
        $ids   = $parts[4] -split ';'
        # ORDINAL sort puts 'aaa-host' first on every host. Under culture sort on this da-DK machine
        # 'aa' collates LAST, so this assertion also pins that the ordinal sorter is in use.
        $names[0] | Should -BeExactly 'aaa-host'
        $ids[0]   | Should -BeExactly 'id-for-aaa'
        $names[1] | Should -BeExactly 'zzz-host'
        $ids[1]   | Should -BeExactly 'id-for-zzz'
    }
}

Describe 'the KQL-side helper column ImpactedAssetPairs -- used, then never shipped' {

    It 'splits a real array on the LAST pipe, so a name containing one survives' {
        # Real estate data: '192.168.1.217---Sonos-Play:1---RINCON_...'. Ids are GUIDs / ARM paths /
        # MDE ids and carry no pipe, so last-separator is safe where first-separator is not.
        $p = script:Get-PairsProbe (script:Invoke-CalcPairs -PairsLiteral "@('a|b|id-1','plain|id-2')")
        $p | Should -Not -BeNullOrEmpty
        $p[2] | Should -BeExactly 'a|b;plain'
        $p[3] | Should -BeExactly 'id-1;id-2'
    }

    It 'accepts the LA-direct shape too -- a dynamic arrives as JSON TEXT, not an array' {
        # 🔴 THIS RUNS UNDER powershell.exe, i.e. PS 5.1, which is what customers run. The engine
        # already carries a scar here (v2.2.438/439): `@($s | ConvertFrom-Json)` collects the whole
        # deserialized array as ONE element on 5.1 and as N elements on pwsh 7, so a fix can be
        # correct in test and inert in production. Every CL-backed Summary report takes this route.
        $p = script:Get-PairsProbe (script:Invoke-CalcPairs -PairsLiteral "'[`"srv-a|id-a`",`"srv-b|id-b`"]'")
        $p | Should -Not -BeNullOrEmpty
        $p[2] | Should -BeExactly 'srv-a;srv-b'
        $p[3] | Should -BeExactly 'id-a;id-b'
    }

    It 'accepts a BARE STRING -- a one-element make_set arrives with no brackets at all' {
        # 🔴 Measured on a live advanced-hunting run 2026-08-29: a group holding exactly ONE asset
        # produced `mgmt1.2linkit.local|fa6a7a3b-...` -- not JSON, not an array. ConvertFrom-Json threw,
        # the catch emptied the list, and that row silently lost its id while multi-asset rows kept
        # theirs. Data-dependent and invisible to any fixture that only tests a multi-element set.
        $p = script:Get-PairsProbe (script:Invoke-CalcPairs -PairsLiteral "'srv-solo|id-solo'")
        $p | Should -Not -BeNullOrEmpty -Because "got: $(( script:Invoke-CalcPairs -PairsLiteral "'srv-solo|id-solo'") -join ' / ')"
        $p[2] | Should -BeExactly 'srv-solo'
        $p[3] | Should -BeExactly 'id-solo'
    }

    It 'does NOT split a bare token on a semicolon -- an asset name may contain one' {
        $p = script:Get-PairsProbe (script:Invoke-CalcPairs -PairsLiteral "'a;b|id-1'")
        $p[2] | Should -BeExactly 'a;b'
        $p[3] | Should -BeExactly 'id-1'
    }

    It 'ImpactedAssetCount describes the list the PAIR produced, not the one the KQL counted' {
        # 🔴 Measured on a full run 2026-08-29: Device_Recommendations_Summary published 232 names
        # against 250 ids. Its KQL sets ImpactedAssetCount = array_length(ImpactedAssetsList) BEFORE
        # the engine replaces that list from the pairs, so the count described a list that no longer
        # existed. One asset legitimately carries two ids (the same host under two findings) and
        # make_set keeps both, so the pair list really is longer than the name-only set.
        # Audit #25's invariant is that the count describes THE SET THAT IS DISPLAYED.
        $p = script:Get-PairsProbe (script:Invoke-CalcPairs -PairsLiteral "@('srv-a|id-1','srv-a|id-2','srv-b|id-3')")
        $p | Should -Not -BeNullOrEmpty
        $names = @($p[2] -split ';')
        $ids   = @($p[3] -split ';')
        $ids.Count | Should -Be $names.Count
        [int]$p[4] | Should -Be $names.Count -Because 'the count must equal the published list length'
        [int]$p[4] | Should -Be 3
    }

    It 'REMOVES the helper column when it parsed' {
        $p = script:Get-PairsProbe (script:Invoke-CalcPairs -PairsLiteral "@('srv-a|id-a')")
        $p[1] | Should -BeExactly 'removed'
    }

    It 'REMOVES the helper column when it is PRESENT BUT NULL -- the leak this catches' {
        # 🔴 The removal used to live inside the `$null -ne $_pairsRaw` branch, so a group whose
        # make_set produced nothing skipped it and shipped ImpactedAssetPairs to the customer as a
        # column of nulls. Survivable while 7 reports emitted the helper; with all 61 emitting it,
        # any report with one empty group leaks a new column into the workbook and into LA.
        $p = script:Get-PairsProbe (script:Invoke-CalcPairs -PairsLiteral '$null')
        $p | Should -Not -BeNullOrEmpty
        $p[1] | Should -BeExactly 'removed'
    }

    It 'REMOVES the helper column on a DETAILED report too -- the grain must not matter' {
        # 🔴 CAUGHT ON THE FIRST DETAILED RUN OF THE SESSION, 2026-08-30. The pair block lives inside
        # `if ($isSummaryReport)`, so its removal only ever ran for Summary reports and a Detailed
        # report that builds the pair shipped the helper straight to the customer:
        # "helper columns leaked? ImpactedAssetPairs=True" in a 311-column workbook.
        # Every other assertion in this file uses a report name ending in _Summary, so none of them
        # could ever have seen it -- which is why the removal is now unconditional.
        $cmd = @"
`$ErrorActionPreference='Stop'
Set-StrictMode -Off
. '$script:RiskIndexSiPath'
. '$script:FactorKeysPath'
. '$script:RiskScorePath'
`$rows = @(
    [pscustomobject]@{ SecurityDomain='Endpoint'; Category='C'; Subcategory='S'
                       ConfigurationName='CVE-1'; ConfigurationId='id-1'
                       SecuritySeverity='High'; CriticalityTierLevel='Low - tier 3'
                       ImpactedAssetPairs = @('srv-a|id-a') }
)
`$idx = New-SIRiskIndexSi -Rows @()   # #559: an empty SI-keyed index

`$out = Calculate-RiskScore -Rows `$rows -RiskIndex `$idx ``
        -CategoryInputName 'Category' -SubCategoryInputName 'Subcategory' ``
        -ConfigurationIdInputName 'ConfigurationId' -SecuritySeverityInputName 'SecuritySeverity' ``
        -CriticalityTierLevelInputName 'CriticalityTierLevel' -ReportName 'T_Detailed'
`$r = @(`$out)[0]
'DET<>' + `$(if (`$r.PSObject.Properties['ImpactedAssetPairs']) { 'SHIPPED' } else { 'removed' })
"@
        $o = script:Invoke-Child $cmd
        $line = @($o | Where-Object { "$_" -like 'DET<>*' })[0]
        $line | Should -Not -BeNullOrEmpty -Because "got: $($o -join ' / ')"
        (("$line" -split '<>')[1]) | Should -BeExactly 'removed'
    }

    It 'REMOVES the helper column when it is an EMPTY set' {
        # `make_set` over a group that matched nothing returns [] -- present, parseable, and empty.
        $p = script:Get-PairsProbe (script:Invoke-CalcPairs -PairsLiteral '@()')
        $p[1] | Should -BeExactly 'removed'
    }
}
