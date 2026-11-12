#Requires -Version 5.1
<#
    SecurityInsight -- THE SETTINGS CATALOG MARKS ONLY LICENSED FEATURES AS PRO (framework PRO-COMMUNITY-SAME, owner 2026-11-11:
    "it must be same pro community"; Pro and Community are built and run the same, only the licensed FEATURES differ).

    Until 2026-11-11 engine\pro-settings\Build-SISettingsCatalog.ps1 marked 91 settings edition 'pro' by a NAME pattern
    (SI_Pro_*, SI_KeyFigures_*, SI_Bootstrap_WebAppCpu, SI_UpdateRing, ...) although most of them shape how every install
    runs -- job and database sizes, retention, guards, data quality, the pipeline, the update ring. What must hold now:
      - a setting is 'pro' ONLY when it carries a licensed feature ('licensedFeature'), from a fixed list: the three paid
        features of engine\SI-FeatureCatalog.ps1 (servicenow-connector -- which also gates the close-loop mails --,
        governance, cmdb-connectors), 'licence' (the licence request) and 'template-channel' (the Invardia template channel);
      - every setting that carries a feature is 'pro', every other one is 'community' and carries none;
      - the settings that shape how SI runs are 'community', and the Community reference's glossary lists them;
      - the generator decides by the list, never by a name pattern;
      - a community setting's "More info" does not ask for a Pro licence; a licensed one does.
    Offline: reads the shipped catalog, the generator and the feature catalog only.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Cat = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'config\settings.catalog.locked.json')) | ConvertFrom-Json
    $script:Settings = @($script:Cat.settings)
    $script:Allowed = @('servicenow-connector', 'governance', 'cmdb-connectors', 'licence', 'template-channel')
    function script:Get-Setting([string]$Name) { @($script:Settings | Where-Object { $_.name -eq $Name })[0] }
    function script:Get-Feature($S) { if ($S.PSObject.Properties['licensedFeature']) { [string]$S.licensedFeature } else { '' } }
}

Describe 'the edition mark follows the licence' {
    It 'every Pro setting carries a licensed feature from the fixed list' {
        $pro = @($script:Settings | Where-Object { $_.edition -eq 'pro' })
        $pro.Count | Should -BeGreaterThan 0
        foreach ($s in $pro) { $script:Allowed | Should -Contain (Get-Feature $s) -Because "$($s.name) is Pro, so it must name the licensed feature it belongs to" }
    }
    It 'a setting that carries a feature is Pro; every other setting is community and carries none' {
        foreach ($s in $script:Settings) {
            $f = Get-Feature $s
            if ($f) { $s.edition | Should -Be 'pro' -Because "$($s.name) belongs to $f" }
            else { $s.edition | Should -Be 'community' -Because "$($s.name) belongs to no licensed feature" }
        }
    }
    It 'the paid feature keys are the ones the licence gates in the engines' {
        . (Join-Path $script:SIRoot 'engine\SI-FeatureCatalog.ps1')
        $paid = @(Get-SIFeatureCatalog | ForEach-Object Name)
        foreach ($k in 'servicenow-connector', 'governance', 'cmdb-connectors') { $paid | Should -Contain $k }
        foreach ($f in @($script:Settings | ForEach-Object { Get-Feature $_ } | Where-Object { $_ } | Sort-Object -Unique)) {
            ($paid -contains $f -or $f -in 'licence', 'template-channel') | Should -BeTrue -Because "$f is a licensed feature"
        }
    }
    It 'each licensed area keeps its settings Pro (the ServiceNow connector and close-loop mail, the SQL CMDB, governance, the licence, the template channel)' {
        $want = [ordered]@{
            SI_EnableServiceNowCmdb = 'servicenow-connector'; SI_VulnSync_Run = 'servicenow-connector'; Mail_CloseLoop_Daily_SendMail = 'servicenow-connector'
            SI_Pro_CmdbSql_Enabled = 'cmdb-connectors'; SI_Pro_GovernanceNotify_SendMail = 'governance'; SI_Pro_TaskDigest_SendMail = 'governance'
            SI_Pro_DepartmentReport_SendMail = 'governance'; SI_LicenseRequest_Auto = 'licence'; SI_InvardiaUpdate_HoldMicrosoftContent = 'template-channel'
        }
        foreach ($n in $want.Keys) {
            $s = Get-Setting $n
            $s | Should -Not -BeNullOrEmpty -Because "$n is a setting"
            $s.edition | Should -Be 'pro' -Because $n
            Get-Feature $s | Should -Be $want[$n] -Because $n
        }
    }
}

Describe 'the settings that shape how SI runs are community' {
    It '<_> is community and carries no licensed feature' -ForEach @(
        'SI_Bootstrap_WebAppCpu', 'SI_Bootstrap_WebAppMemory', 'SI_Bootstrap_SqlServiceObjective', 'SI_UpdateRing', 'SI_InvardiaUpdate_Enabled',
        'SI_Update_RenameDisplayNames', 'SI_Pipeline_StartTime', 'SI_Pro_Pipeline_GoOnAfterFailedStep', 'SI_Pro_PublishPartialRun',
        'SI_Pro_DataRetentionDays', 'SI_Pro_AuditRetentionMonths', 'SI_Pro_DataQuality_AssetDropPercent', 'SI_Pro_DataQuality_Mail_Enabled',
        'SI_Pro_SourceDropout_HoldDeliveryDays', 'SI_KeyFigures_RecentDays', 'SI_AssetProperties', 'SI_Correlation_RowLimit',
        'SI_Pro_AssetTagging_Apply', 'SI_VulnSync_CloseAfterRuns', 'SI_Pro_CmdbSql_SeenWithinDays', 'SI_Cmdb_RetireAfterDays'
    ) {
        $s = Get-Setting $_
        $s | Should -Not -BeNullOrEmpty -Because "$_ is a setting"
        $s.edition | Should -Be 'community' -Because "$_ controls how every install runs, Pro and Community alike"
        Get-Feature $s | Should -BeNullOrEmpty
    }
    It 'the Community reference''s glossary lists them, and leaves the licensed ones out' {
        $ref = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'config\SecurityInsight.custom.reference.ps1'))
        $at = $ref.IndexOf('# >>> SETTINGS GLOSSARY'); $at | Should -BeGreaterThan 0
        $g = $ref.Substring($at)
        foreach ($n in 'SI_UpdateRing', 'SI_Bootstrap_WebAppCpu', 'SI_Pro_DataRetentionDays', 'SI_KeyFigures_RecentDays') { $g.Contains("[$n]") | Should -BeTrue -Because "$n is a Community setting" }
        foreach ($n in 'SI_Pro_TaskDigest_SendMail', 'SI_EnableServiceNowCmdb', 'SI_LicenseRequest_Auto') { $g.Contains("[$n]") | Should -BeFalse -Because "$n is licensed" }
    }
    It 'a community setting''s More info does not ask for a Pro licence; a licensed one does' {
        (Get-Setting 'SI_UpdateRing').info.requires | Should -Not -Match 'Pro licence'
        (Get-Setting 'SI_Pro_DataRetentionDays').info.requires | Should -Not -Match 'Pro licence'
        (Get-Setting 'SI_Pro_TaskDigest_SendMail').info.requires | Should -Match 'Pro licence'
    }
}

Describe 'the generator decides by the list, never by a name pattern' {
    It 'Build-SISettingsCatalog.ps1 marks pro only from its licensed list' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\pro-settings\Build-SISettingsCatalog.ps1'))
        $src | Should -Not -Match '\$proRe\b' -Because 'the name pattern marked run-shaping settings Pro'
        $src | Should -Match "edition\s+=\s+\`$\(if \(\`$licensedFeatureOf\.ContainsKey\(\`$name\)\) \{ 'pro' \} else \{ 'community' \}\)"
        $src | Should -Match "entry\['licensedFeature'\] = \`$licensedFeatureOf\[\`$name\]"
        foreach ($k in $script:Allowed) { $src | Should -Match ("'{0}'\s+=\s+@\(" -f [regex]::Escape($k)) }
    }
}
