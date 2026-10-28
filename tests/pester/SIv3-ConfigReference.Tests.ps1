#Requires -Version 5.1
<#
    THE CONFIG FILES DOCUMENT WHAT 3.0 READS, AND NOTHING IT IGNORES (#177, #187 -- 2026-09-30 config review).

    The review traced every setting both ways: 12 names documented that nothing read (a customer setting one
    changed nothing, silently), v3 settings documented nowhere, samples using names the engine ignores
    (SI_Shodan_ExtraIPs) or values that fell back with a warning (a bare-number tier cadence became 24h), and RA
    template names the launchers never read.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Schedule.ps1')
    $script:Ref = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'config\SecurityInsight.custom.reference.ps1')
}

Describe 'a tier cadence given as a bare number is HOURS (#187)' {
    It '336 is 14 days, not the 24h fallback' { (Resolve-SITimespan -Spec '336').TotalDays | Should -Be 14 }
    It 'the unit forms are unchanged' {
        (Resolve-SITimespan -Spec '12h').TotalHours | Should -Be 12
        (Resolve-SITimespan -Spec '3d').TotalDays | Should -Be 3
        (Resolve-SITimespan -Spec '1h30m').TotalMinutes | Should -Be 90
    }
    It 'garbage still falls back to 24h with a warning' {
        (Resolve-SITimespan -Spec 'soon' 3>$null).TotalHours | Should -Be 24
    }
}

Describe 'the reference documents the 3.0 settings (#177)' {
    It '<_> is documented' -ForEach @(
        'SI_KeyVaultName', 'SI_KvMiClientId', 'SI_CollectDefenderRecommendations', 'SI_AzureRecommendation_TableName',
        'SI_AzureRecommendation_DcrName', 'SI_AzureEgNonAssetTypes', 'SI_RequireRecentSignIn_Identity', 'SI_PayloadProfile',
        'SI_AssetDecisionsPath', 'SI_PublicIp_TableName', 'SI_PublicIp_DcrName', 'SI_Trend_Grain', 'SI_Trend_Weeks',
        'SI_BucketLateRetries', 'SI_AutoBucketDefaultDetailed', 'AI_MaxAttempts', 'RA_MailEvenIfEmpty', 'SI_TenantDomain',
        'SI_Bootstrap_SubscriptionId', 'SI_Bootstrap_ResourceGroupName', 'SI_Bootstrap_AcrName', 'SI_Bootstrap_ScheduleTrend'
    ) {
        $script:Ref | Should -Match ('\$global:' + [regex]::Escape($_) + '\s*=')
    }
    It 'the storage key is not an active line (SI storage is OAuth by default)' {
        $script:Ref | Should -Not -Match '(?m)^\$global:SI_StorageKey\s*='
    }
}

Describe 'no config file documents a setting nothing reads (#187)' {
    It '<_> is gone from the reference' -ForEach @(
        'SI_HostMode', 'SI_Shodan_ExtraIPs', 'SI_Shodan_SkipLA_Ingest', 'SI_RequireMasterPresence', 'SI_RiskAnalysis_RiskScoreModelOverride',
        'SI_RiskAnalysis_RiskFactorFieldsExtra', 'SI_DceIngestUri', 'SI_AzureResourceSubscriptions', 'SI_DiscoveryMode_azure',
        'SubscriptionNameExcludePatterns', 'TroubleshootingMode'
    ) {
        $script:Ref | Should -Not -Match ('\$global:' + [regex]::Escape($_) + '\s*=')
    }
    It 'the legacy public-IP names are explained, not offered' {
        $script:Ref | Should -Not -Match '\$global:SI_Shodan_(TableName|DcrName)\s*='
        $script:Ref | Should -Match 'SI_Shodan_TableName / SI_Shodan_DcrName are no longer read since 3\.0\.0'
    }
    It 'the publicip sample uses the name the engine reads' {
        $s = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'launcher\publicip\LauncherConfig.custom.sample.ps1')
        $s | Should -Not -Match 'SI_Shodan_ExtraIPs'
        $s | Should -Match 'SI_PublicIP_ExtraTargets'
    }
    It 'no shipped config uses an aliased _Bucket template name' {
        foreach ($f in 'config\SecurityInsight.custom.reference.ps1', 'launcher\risk-analysis\LauncherConfig.defaults.ps1', 'launcher\risk-analysis\LauncherConfig.custom.sample.ps1') {
            (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot $f)) | Should -Not -Match 'RiskAnalysis_(Summary|Detailed)_Bucket' -Because $f
        }
    }
}

Describe 'the RA launchers read the template names the reference documents (#187)' {
    It '<_> honours RiskAnalysis_ReportTemplate_Default_Summary/Detailed' -ForEach @('launcher.internal-vm.ps1', 'launcher.community-vm.ps1') {
        $c = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot "launcher\risk-analysis\$_")
        $c | Should -Match '\$ReportTemplate_Default_Summary\s+= \[string\]\$global:RiskAnalysis_ReportTemplate_Default_Summary'
        $c | Should -Match '\$ReportTemplate_Default_Detailed = \[string\]\$global:RiskAnalysis_ReportTemplate_Default_Detailed'
    }
}

Describe 'the DCE resource group backfill prefers the DCR resource group (#187)' {
    BeforeAll { . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1') }
    AfterEach { foreach ($n in 'SI_DceResourceGroup', 'SI_DcrResourceGroup', 'DceResourceGroup') { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue } }
    It 'the shared default DceResourceGroup (always set) does not beat the customer DCR resource group' {
        $global:DceResourceGroup = 'rg-dce-securityinsight'; $global:SI_DcrResourceGroup = 'rg-customer'
        Initialize-SIIngestGlobals
        $global:SI_DceResourceGroup | Should -Be 'rg-customer'
    }
}
