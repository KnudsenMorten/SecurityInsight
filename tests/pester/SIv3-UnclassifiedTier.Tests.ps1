#Requires -Version 5.1
<#
    UNCLASSIFIED ASSETS AND FINDINGS (operator, 2026-10-05, live on ring 1): "why do i have unclassified assets. either have
    a default value or page where i can see the unclassified assets and link them to a tier".

    Measured on ring 1's newest collection: 96 Unclassified findings --
      * 93 on Azure resources NO PROFILER HAS SEEN (outside the subscriptions the Azure profiler reads; the Exposure Graph
        sees the whole tenant) -- Risk Analysis returned no tier and no asset id;
      * 2 on subscription scope nodes (subscriptions are not profiled; no profiled resource in them to borrow a tier from);
      * 1 on an asset that HAS Tier 3 -- an attack-path report returned the asset twice, one row without the tier.
    Every profiled asset already had a tier -- but from a constant 3 in each profile builder, not from the rule set.

    What these tests keep true:
      * the DEFAULT tier is a RULE (asset-profiling-enrichment/shared/AssetProfileByDefaultTier.locked.yaml, `fallback: true`),
        one detection per asset kind, Tier 3 shipped -- configurable (custom copy / overlay / Pro), and turned off it is
        honoured (no tier, never a hidden constant);
      * the default rule never VOTES: the rule set the profilers combine (MIN) leaves it out;
      * the four profile builders take the default from the rule, not from a literal;
      * Risk Analysis gives a finding on an asset no profiler has seen a tier from the rule set -- the rules a name decides
        (a Tier board pin among them) first, else the default rule -- and leaves profiled rows, attack-path rows, Summary
        rows and rows whose kind cannot be told alone;
      (The Pro data load's half -- a finding without a tier takes its asset's tier -- is in SIv3-DataSync.Tests.ps1: this file
      ships in the Community edition, which has no Pro data load.)
    Offline; PS 5.1 and 7.
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\asset-profiling\shared\Resolve-SIDefaultTier.ps1')
    . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-UnprofiledTier.ps1')
    function Write-SIInfo { param($m) }
    $script:SavedOverlay = $global:SI_EnrichmentDataRoot
    $script:SavedProRules = $global:SI_ProRulesFromSql

    function script:New-Overlay {
        $d = Join-Path ([System.IO.Path]::GetTempPath()) ('si-unclass-' + [guid]::NewGuid().ToString('N').Substring(0, 10))
        New-Item -ItemType Directory -Force (Join-Path $d 'shared') | Out-Null
        $d
    }
    function script:Set-Text([string]$Path, [string]$Text) {
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
        [System.IO.File]::WriteAllText($Path, $Text)
    }
    # the exact shape of a Tier board pin (pro-management RuleTemplates.Pin) for an asset with no kind
    function script:New-PinText([string]$Id, [string]$Name, [int]$Tier) {
        $pattern = "(?i)^" + [regex]::Escape($Name) + '$'
        @(
            "# Written by the SecurityInsight management GUI -- pins $Name to Tier $Tier (management GUI).",
            "id: $Id", 'appliesTo: any', 'mode: append', "purpose: 'Pinned to Tier $Tier in the management GUI'", "category: 'Custom'", "description: 'test'",
            '', 'detections:', "  - id: $Id", '    detect:', '      any:', '        - kind: nameMatches', '          namePatterns:',
            "            - '$pattern'", '    set:', "      Tier: $Tier", "      Purpose: 'Pinned to Tier $Tier in the management GUI'", "      Category: 'Custom'", ''
        ) -join "`r`n"
    }
    function script:Row([hashtable]$h) { [pscustomobject]$h }
}

AfterAll {
    $global:SI_EnrichmentDataRoot = $script:SavedOverlay
    $global:SI_ProRulesFromSql = $script:SavedProRules
}

Describe 'the default tier is a RULE in the rule set, not a constant in the code' {
    BeforeEach { $global:SI_EnrichmentDataRoot = $null; $global:SI_ProRulesFromSql = $false; Clear-SIDefaultTierCache }

    It 'ships as a fallback rule with one Tier 3 detection per asset kind' {
        $p = Join-Path $script:Root 'asset-profiling-enrichment\shared\AssetProfileByDefaultTier.locked.yaml'
        Test-Path $p | Should -BeTrue
        $t = [System.IO.File]::ReadAllText($p)
        $t | Should -Match '(?m)^fallback:\s+true'
        $t | Should -Match '(?m)^appliesTo:\s+any'
        foreach ($k in 'endpoint', 'identity', 'azure', 'publicip') {
            $d = Get-SIDefaultTier -Engine $k
            $d.Tier | Should -Be 3 -Because "the shipped default for $k is Tier 3"
            $d.RuleId | Should -Be 'AssetProfileByDefaultTier'
            $d.DetectionId | Should -Be "DefaultTier-$k"
        }
    }

    It 'never votes: the rule set the profilers combine leaves it out, and -Fallback returns only it' {
        foreach ($k in 'endpoint', 'identity', 'azure', 'publicip') {
            $normal = @(Get-SIRuleSet -Engine $k 3>$null | ForEach-Object { $_ })
            @($normal | Where-Object { $_.Id -eq 'AssetProfileByDefaultTier' }).Count | Should -Be 0
            @($normal | Where-Object { $_.Fallback }).Count | Should -Be 0
            $fb = @(Get-SIRuleSet -Engine $k -Fallback 3>$null | ForEach-Object { $_ })
            @($fb | Where-Object { $_.Fallback }).Id | Should -Be @('AssetProfileByDefaultTier')
        }
    }

    It 'is configurable: a custom copy in the overlay changes one kind and keeps the others' {
        $ov = New-Overlay
        try {
            $t = [System.IO.File]::ReadAllText((Join-Path $script:Root 'asset-profiling-enrichment\shared\AssetProfileByDefaultTier.locked.yaml'))
            # identity's detection -> Tier 2 (the first Tier line after its detection id)
            $at = $t.IndexOf('DefaultTier-identity')
            $head = $t.Substring(0, $at); $tail = $t.Substring($at)
            $custom = $head + ([regex]'(?m)^(\s+Tier:\s+)3').Replace($tail, '${1}2', 1)
            Set-Text (Join-Path $ov 'shared\AssetProfileByDefaultTier.custom.yaml') $custom
            $global:SI_EnrichmentDataRoot = $ov
            Clear-SIDefaultTierCache
            (Get-SIDefaultTier -Engine identity).Tier | Should -Be 2
            (Get-SIDefaultTier -Engine endpoint).Tier | Should -Be 3
            (Get-SIDefaultTier -Engine azure).Tier | Should -Be 3
        } finally { Remove-Item -Recurse -Force $ov -ErrorAction SilentlyContinue }
    }

    It 'turned off, it is honoured: no default tier at all (the asset is Unclassified), never a hidden 3' {
        $ov = New-Overlay
        try {
            Set-Text (Join-Path $ov 'shared\AssetProfileByDefaultTier.custom.yaml') "id: AssetProfileByDefaultTier`r`nmode: disable`r`n"
            $global:SI_EnrichmentDataRoot = $ov
            Clear-SIDefaultTierCache
            Get-SIDefaultTier -Engine azure | Should -BeNullOrEmpty
            Get-SIDefaultTierValue -Engine endpoint | Should -BeNullOrEmpty
            # ... also when the rules come from the Pro database (the shipped file is not taken back in)
            $global:SI_ProRulesFromSql = $true
            Clear-SIDefaultTierCache
            Get-SIDefaultTierValue -Engine identity | Should -BeNullOrEmpty
        } finally { Remove-Item -Recurse -Force $ov -ErrorAction SilentlyContinue }
    }

    It 'a Pro rule set that does not carry the default rule yet (older templates): the shipped rule applies' {
        $ov = New-Overlay
        try {
            Set-Text (Join-Path $ov 'endpoint\SomeTemplateRule.locked.yaml') "id: SomeTemplateRule`r`nappliesTo: endpoint`r`nmode: locked`r`ndetections:`r`n  - id: X`r`n    detect:`r`n      any:`r`n        - kind: nameMatches`r`n          namePatterns: ['(?i)^nothing-matches-this$']`r`n    set:`r`n      Tier: 1`r`n"
            $global:SI_EnrichmentDataRoot = $ov
            $global:SI_ProRulesFromSql = $true
            Clear-SIDefaultTierCache
            @(Get-SIRuleSet -Engine endpoint -Fallback 3>$null | ForEach-Object { $_ } | Where-Object { $_.Fallback }).Count | Should -Be 0 -Because 'the Pro rule set is only the overlay'
            (Get-SIDefaultTier -Engine endpoint).Tier | Should -Be 3
        } finally { Remove-Item -Recurse -Force $ov -ErrorAction SilentlyContinue }
    }

    It 'the four profile builders take the default from the rule -- no literal tier 3 fallback is left' {
        foreach ($b in 'Azure', 'Endpoint', 'Identity', 'PublicIp') {
            $t = [System.IO.File]::ReadAllText((Join-Path $script:Root "engine\asset-profiling\shared\Build-${b}ProfileRow.ps1"))
            $t | Should -Match 'Resolve-SIDefaultTier\.ps1'
            $t | Should -Match 'Get-SIDefaultTierValue -Engine '
            $t | Should -Not -Match "catch\s*\{\s*3\s*\}" -Because "$b must not fall back to a constant"
            $t | Should -Not -Match "else\s*\{\s*3\s*\}" -Because "$b must not fall back to a constant"
            $t | Should -Not -Match "\['Tier'\]\s*=\s*3\b"
        }
    }

    It 'the attribution says the default rule set the tier, and says Unclassified when no rule applies' {
        . (Join-Path $script:Root 'engine\asset-profiling\shared\Get-SITierAttribution.ps1')
        (Get-SITierAttribution -FinalTier 3 -Sources @{} -DefaultTier 3).SI_TierReason | Should -Match 'is the default -- no tier source matched this asset, so the default tier rule set it'
        (Get-SITierAttribution -FinalTier 2 -Sources @{} -DefaultTier 2).SI_TierSetBy | Should -Be 'default'
        (Get-SITierAttribution -FinalTier 2 -Sources @{} -DefaultTier 2).SI_TierReason | Should -Not -Match 'Report this' -Because 'a default of 2 is the rule, not a divergence'
        (Get-SITierAttribution -FinalTier $null -Sources @{} -DefaultTier $null).SI_TierReason | Should -Match 'Unclassified'
    }

    It 'the rule engine knows the detection kind the default rule uses (the web validator: xunit UnclassifiedTierTests)' {
        (Get-SIKindRegistry).ContainsKey('assetKind') | Should -BeTrue
        Test-SIKind_assetKind -Asset @{ SI_AssetKind = 'azure' } -Args @{ kinds = @('azure') } | Should -BeTrue
        Test-SIKind_assetKind -Asset @{ SI_AssetKind = 'identity' } -Args @{ kinds = @('azure', 'endpoint') } | Should -BeFalse
        Test-SIKind_assetKind -Asset @{ Name = 'x' } -Args @{ kinds = @('azure') } | Should -BeFalse -Because 'no kind never matches'
    }
}

Describe 'Risk Analysis: a finding on an asset no profiler has seen gets its tier from the rule set' {
    BeforeEach { $global:SI_EnrichmentDataRoot = $null; $global:SI_ProRulesFromSql = $false; Clear-SIDefaultTierCache }

    It 'tells the asset kind from the row: type first, then an ARM id, then the domain' {
        Get-RAAssetKindOfRow -Row (Row @{ AssetType = 'microsoft.keyvault/vaults'; SecurityDomain = 'Azure' }) | Should -Be 'azure'
        Get-RAAssetKindOfRow -Row (Row @{ AssetType = 'subscriptions'; SecurityDomain = 'Azure' }) | Should -Be 'azure'
        Get-RAAssetKindOfRow -Row (Row @{ AssetType = 'Endpoint'; SecurityDomain = 'Azure' }) | Should -Be 'endpoint' -Because 'a VM in an Azure report is a device'
        Get-RAAssetKindOfRow -Row (Row @{ AssetType = 'MultiTenantSP'; SecurityDomain = 'Identity' }) | Should -Be 'identity'
        Get-RAAssetKindOfRow -Row (Row @{ AssetType = 'Guest'; SecurityDomain = 'Identity' }) | Should -Be 'identity'
        Get-RAAssetKindOfRow -Row (Row @{ AssetType = 'PublicIP'; SecurityDomain = 'PublicIP' }) | Should -Be 'publicip'
        Get-RAAssetKindOfRow -Row (Row @{ AssetType = ''; AssetId = 'az:/subscriptions/x'; SecurityDomain = 'Identity' }) | Should -Be 'azure'
        Get-RAAssetKindOfRow -Row (Row @{ AssetType = ''; SecurityDomain = 'Endpoint' }) | Should -Be 'endpoint'
        Get-RAAssetKindOfRow -Row (Row @{ AssetType = 'Something'; SecurityDomain = '' }) | Should -Be ''
    }

    It 'resolves ring 1''s three shapes, and leaves the rest alone' {
        $rows = @(
            (Row @{ AssetName = 'kv-outside-scope'; AssetType = 'microsoft.keyvault/vaults'; SecurityDomain = 'Azure'; CriticalityTier = $null; CriticalityTierLevel = 'Low - tier 3'; AssetDetectedInReportName = 'Azure_Recommendations_Detailed' }),
            (Row @{ AssetName = 'Demo subscription'; AssetType = 'subscriptions'; AssetId = 'az:/subscriptions/x'; SecurityDomain = 'Azure'; CriticalityTier = ''; CriticalityTierLevel = ''; AssetDetectedInReportName = 'Azure_Recommendations_Detailed' }),
            (Row @{ AssetName = 'paw-07'; AssetType = 'Workstation'; SecurityDomain = 'Endpoint'; CriticalityTier = $null; CriticalityTierLevel = ''; AssetDetectedInReportName = 'Device_Missing_CVEs_Detailed' }),
            (Row @{ AssetName = 'profiled-vm'; AssetType = 'Endpoint'; SecurityDomain = 'Endpoint'; CriticalityTier = 1; CriticalityTierLevel = 'High - tier 1'; AssetDetectedInReportName = 'Device_Missing_CVEs_Detailed' }),
            (Row @{ AssetName = 'rg-path'; AssetType = 'resourcegroups'; SecurityDomain = 'Identity'; CriticalityTier = $null; Category = 'Attack Paths'; AssetDetectedInReportName = 'Attack_Paths_Detailed_Identity_Group_Membership_to_Privileged_Resources' }),
            (Row @{ AssetName = 'mystery'; AssetType = 'Something'; SecurityDomain = ''; CriticalityTier = $null; AssetDetectedInReportName = 'X_Detailed' })
        )
        $st = @{}
        $out = @(Set-RAUnprofiledTiers -Rows $rows -ReportName 'Azure_Recommendations_Detailed' -Stats $st)
        $out.Count | Should -Be 6 -Because 'never drops a row'
        $out[0].CriticalityTier | Should -Be 3; $out[0].CriticalityTierLevel | Should -Be 'Low - tier 3'
        $out[1].CriticalityTier | Should -Be 3
        $out[2].CriticalityTier | Should -Be 0 -Because 'a name rule (Privileged Access Workstation) decides before the default'
        $out[2].CriticalityTierLevel | Should -Be 'Critical - tier 0'
        $out[3].CriticalityTier | Should -Be 1 -Because 'a profiled tier is never second-guessed'
        $out[4].CriticalityTier | Should -BeNullOrEmpty -Because 'an attack path carries its TARGET tier -- never a name lookup of its source'
        $out[5].CriticalityTier | Should -BeNullOrEmpty -Because 'no kind, no guess'
        $st.Resolved | Should -Be 3; $st.ByRule | Should -Be 1; $st.ByDefault | Should -Be 2; $st.Left | Should -Be 1
    }

    It 'leaves a Summary report alone (one row per tier bucket, not one asset)' {
        $r = @(Row @{ AssetName = 'a; b'; AssetType = 'microsoft.storage/storageaccounts'; SecurityDomain = 'Azure'; CriticalityTier = $null })
        $out = @(Set-RAUnprofiledTiers -Rows $r -ReportName 'Azure_Recommendations_Summary')
        $out[0].CriticalityTier | Should -BeNullOrEmpty
    }

    It 'a Tier board pin of an Unclassified asset is honoured by the next run (matched by name, for an asset no profiler sees)' {
        $ov = New-Overlay
        try {
            Set-Text (Join-Path $ov 'shared\gui-pin-0123456789abcdef.custom.yaml') (New-PinText -Id 'gui-pin-0123456789abcdef' -Name 'Demo subscription' -Tier 1)
            $global:SI_EnrichmentDataRoot = $ov
            Clear-SIDefaultTierCache
            $r = Resolve-SIUnprofiledTier -Engine azure -Name 'Demo subscription'
            $r.Tier | Should -Be 1; $r.SetBy | Should -Be 'rule'; $r.RuleId | Should -Be 'gui-pin-0123456789abcdef'
            (Resolve-SIUnprofiledTier -Engine azure -Name 'demo SUBSCRIPTION').Tier | Should -Be 1 -Because 'names compare case-insensitively'
            (Resolve-SIUnprofiledTier -Engine azure -Name 'Demo subscription 2').Tier | Should -Be 3 -Because 'the pin is an exact name'
            $row = Row @{ AssetName = 'Demo subscription'; AssetType = 'subscriptions'; SecurityDomain = 'Azure'; CriticalityTier = $null; CriticalityTierLevel = 'Low - tier 3' }
            $out = @(Set-RAUnprofiledTiers -Rows @($row) -ReportName 'Azure_Recommendations_Detailed')
            $out[0].CriticalityTier | Should -Be 1
            $out[0].CriticalityTierLevel | Should -Be 'High - tier 1'
        } finally { Remove-Item -Recurse -Force $ov -ErrorAction SilentlyContinue }
    }

    It 'with the default rule turned off, an unmatched row keeps no tier (Unclassified) -- and is counted' {
        $ov = New-Overlay
        try {
            Set-Text (Join-Path $ov 'shared\AssetProfileByDefaultTier.custom.yaml') "id: AssetProfileByDefaultTier`r`nmode: disable`r`n"
            $global:SI_EnrichmentDataRoot = $ov
            Clear-SIDefaultTierCache
            $st = @{}
            $out = @(Set-RAUnprofiledTiers -Rows @(Row @{ AssetName = 'kv1'; AssetType = 'microsoft.keyvault/vaults'; SecurityDomain = 'Azure'; CriticalityTier = $null }) -ReportName 'Azure_Recommendations_Detailed' -Stats $st)
            $out[0].CriticalityTier | Should -BeNullOrEmpty
            $st.Left | Should -Be 1
        } finally { Remove-Item -Recurse -Force $ov -ErrorAction SilentlyContinue }
    }

    It 'runs on every report BEFORE the tier filter and the scoring' {
        $t = [System.IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $t | Should -Match "_shared/RA-UnprofiledTier\.ps1"
        $call = $t.IndexOf('Set-RAUnprofiledTiers -Rows $ResultFiltered')
        $call | Should -BeGreaterThan 0
        $call | Should -BeGreaterThan $t.IndexOf('Set-RAExemptionMarks -Rows $ResultFiltered')
        $call | Should -BeLessThan $t.IndexOf('@{ Name="CriticalityTierLevel"; Column=$CriticalityTierLevelInputName')
        $call | Should -BeLessThan $t.IndexOf('$RiskScoreArray = Calculate-RiskScore')
    }
}
