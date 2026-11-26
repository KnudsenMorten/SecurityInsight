#Requires -Version 7.0
<#
    #1373 DEFENDER'S OWN REMEDIATION TYPE DECIDES A RECOMMENDATION'S TASK (owner 2026-11-25: "why does fx update openssl show as
    policy" -> "Use Defender's type"; "problem is that you left out the remediation task").
      * the Defender recommendations read (the one read per run, SecurityRecommendation.Read.All -- no new permission) gives every
        recommendation's remediationType / productName / vendor; a recommendation row of another provider that names it by title
        ("Update openssl" = "<remediationType> <productName>", or its recommendationName) carries them as si_recommendation_*;
        a Defender configuration row and a CVE row are unchanged;
      * the task rule (finding-fields.locked.json): Update / Upgrade -> software-upgrade (Software deployment) with the software
        Defender names; ConfigurationChange -> configuration (Policy); Uninstall -> other (Manual); no type -> configuration as
        before (the same task key);
      * a version-less software task is named "(bundles <product>)" when the evidence shows it inside an application.
    Pure (no SQL); the build over a real SQL Server is in SIv3-FindingFoldDb.
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-DefenderRecommendationContext.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataRemediationTask.ps1')
    $script:DM = Join-Path $script:Root 'data-model'
    $script:Map = (Get-SIDataModelTemplate -Name 'finding-fields' -Root $script:DM).Document
    $script:VM = (Get-SIDataModelTemplate -Name 'value-maps' -Root $script:DM).Document.maps
    $script:Plan = Get-SIFindingFieldPlan -Map $script:Map
    function script:Units([hashtable]$V) { @(ConvertTo-SIRemediationTaskUnits -Values $V -Map $script:Map -Plan $script:Plan -ValueMaps $script:VM) }
    function script:Rec([string]$Type, [string]$Title) { $h = @{ si_finding_type = 'recommendation'; si_finding_key = 'k-' + $Title; si_title = $Title }; if ($Type) { $h['si_recommendation_remediation_type'] = $Type; $h['si_recommendation_product'] = 'openssl'; $h['si_recommendation_vendor'] = 'openssl' }; $h }
}

Describe 'the Defender read: the remediation type of a recommendation, by title' {
    BeforeAll {
        $global:RA_DefenderRecIndex = $null
        $api = @(
            [pscustomobject]@{ id = 'va-_-openssl-_-openssl'; productName = 'openssl'; vendor = 'openssl'; recommendationName = 'Update Openssl'; remediationType = 'Update'; exposureImpact = 1.0 },
            [pscustomobject]@{ id = 'va-_-microsoft-_-windows_server_2012_r2'; productName = 'windows_server_2012_r2'; vendor = 'microsoft'; recommendationName = 'Upgrade to a supported version of Windows Server'; remediationType = 'Upgrade' },
            [pscustomobject]@{ id = 'va-_-adobe-_-flash'; productName = 'flash'; vendor = 'adobe'; recommendationName = 'Uninstall Adobe Flash'; remediationType = 'Uninstall' },
            [pscustomobject]@{ id = 'sca-_-scid-2011'; recommendationName = 'Turn on PUA protection'; remediationType = 'ConfigurationChange'; exposureImpact = 0.5 })
        $script:Ix = Get-RADefenderRecommendationIndex -Refresh -Fetch { param($u) @{ Complete = $true; Rows = $(if ($u -match 'skip') { @() } else { $api }) } }
        $script:Rows = @(
            [pscustomobject]@{ ConfigurationId = '4b5d9550-guid'; ConfigurationName = 'Update openssl' },
            [pscustomobject]@{ ConfigurationId = 'mdc-2'; ConfigurationName = 'Upgrade windows_server_2012_r2' },
            [pscustomobject]@{ ConfigurationId = 'mdc-3'; ConfigurationName = 'Uninstall Adobe Flash' },
            [pscustomobject]@{ ConfigurationId = 'mdc-4'; ConfigurationName = 'Turn on PUA protection' },
            [pscustomobject]@{ ConfigurationId = 'mdc-5'; ConfigurationName = 'Storage accounts should restrict network access' },
            [pscustomobject]@{ ConfigurationId = 'scid-2011'; ConfigurationName = 'Turn on PUA protection' },
            [pscustomobject]@{ ConfigurationId = 'CVE-2026-0001'; ConfigurationName = 'Update openssl'; SI_AffectedVendor = 'openssl'; SI_AffectedProduct = 'openssl' })
        $script:Out = Add-RADefenderRecommendationContext -Rows $script:Rows -Index $script:Ix
    }
    AfterAll { $global:RA_DefenderRecIndex = $null }
    It 'a row of another provider gets Defender''s type and software by "<type> <product>" or by the recommendation''s name' {
        ($script:Out[0].si_recommendation_remediation_type, $script:Out[0].si_recommendation_product, $script:Out[0].si_recommendation_vendor) | Should -Be @('Update', 'openssl', 'openssl')
        $script:Out[1].si_recommendation_remediation_type | Should -Be 'Upgrade'
        $script:Out[1].si_recommendation_product | Should -Be 'windows_server_2012_r2'
        $script:Out[2].si_recommendation_remediation_type | Should -Be 'Uninstall'
        $script:Out[3].si_recommendation_remediation_type | Should -Be 'ConfigurationChange'
    }
    It 'a row Defender does not name stays without a type; a Defender configuration row and a CVE row get no type (unchanged)' {
        $script:Out[4].PSObject.Properties['si_recommendation_remediation_type'] | Should -BeNullOrEmpty
        $script:Out[5].PSObject.Properties['si_recommendation_remediation_type'] | Should -BeNullOrEmpty
        $script:Out[5].si_exposure_impact | Should -Be 0.5
        $script:Out[6].PSObject.Properties['si_recommendation_remediation_type'] | Should -BeNullOrEmpty
        $script:Out[6].si_exposure_impact | Should -Be 1.0
        $script:Out[0].PSObject.Properties['si_exposure_impact'] | Should -BeNullOrEmpty -Because 'a title row gets the type only, nothing else'
    }
    It 'LIVE 3.1.50: a Defender for Cloud "<verb> <product>" the Defender for Endpoint list does not hold is typed by its title''s verb' {
        $rows = @([pscustomobject]@{ ConfigurationId = 'g1'; ConfigurationName = 'Update libc6' },
                  [pscustomobject]@{ ConfigurationId = 'g2'; ConfigurationName = 'Upgrade python3.9' },
                  [pscustomobject]@{ ConfigurationId = 'g3'; ConfigurationName = 'Uninstall telnet' },
                  [pscustomobject]@{ ConfigurationId = 'g4'; ConfigurationName = 'Update 2026-10 Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems (KB5126655)' },
                  [pscustomobject]@{ ConfigurationId = 'g5'; ConfigurationName = 'Storage accounts should restrict network access' })
        # the Defender read refused: the title rule still types them
        $out = Add-RADefenderRecommendationContext -Rows $rows -Index @{ Complete = $false; Error = '403'; Index = @{} } -Log { param($m) } -ReportName 'Azure_DefenderRecommendations_Detailed'
        ($out[0].si_recommendation_remediation_type, $out[0].si_recommendation_product) | Should -Be @('Update', 'libc6')
        ($out[1].si_recommendation_remediation_type, $out[1].si_recommendation_product) | Should -Be @('Upgrade', 'python3.9')
        $out[2].si_recommendation_remediation_type | Should -Be 'Uninstall'
        $out[3].PSObject.Properties['si_recommendation_remediation_type'] | Should -BeNullOrEmpty -Because 'a title of several words is not "<verb> <product>"'
        $out[4].PSObject.Properties['si_recommendation_remediation_type'] | Should -BeNullOrEmpty
        # another report's "Update x" is not Defender's: left as it is
        $o2 = Add-RADefenderRecommendationContext -Rows @([pscustomobject]@{ ConfigurationId = 'r1'; ConfigurationName = 'Update foo' }) -Index @{ Complete = $true; Index = @{} } -Log { param($m) } -ReportName 'Identity_NoMFA_Detailed'
        $o2[0].PSObject.Properties['si_recommendation_remediation_type'] | Should -BeNullOrEmpty
        # Defender's list wins where it names the recommendation (the earlier case: the API's own product)
        $script:Out[1].si_recommendation_product | Should -Be 'windows_server_2012_r2'
    }
    It 'the Risk Analysis call names its report (the title rule is for Defender''s reports only)' {
        $t = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $t | Should -Match 'Add-RADefenderRecommendationContext -Rows @\(\$ResultFiltered\) -Log \{ param\(\$m\) Write-Warn2 \$m \} -ReportName \(\[string\]\$ReportName\)'
    }
    It 'the fields are stored with the finding only, never a report''s own column' {
        $t = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\_shared\RA-SqlStream.ps1'))
        $t | Should -Match "'si_recommendation_remediation_type', 'si_recommendation_product', 'si_recommendation_vendor'"
    }
}

Describe 'the task rule: Defender''s type decides the kind and the tool' {
    It 'Update -> software-upgrade (Software deployment) with the software Defender names' {
        $u = Units (Rec 'Update' 'Update openssl')
        @($u).Count | Should -Be 1
        ($u[0].Kind, $u[0].TaskName, $u[0].Product, $u[0].Vendor, $u[0].Version) | Should -Be @('software-upgrade', 'Update openssl', 'openssl', 'openssl', '')
        $u[0].TaskKey | Should -Be 'software-upgrade|update openssl'
    }
    It 'Upgrade -> software-upgrade' { (Units (Rec 'Upgrade' 'Upgrade openssl'))[0].Kind | Should -Be 'software-upgrade' }
    It 'ConfigurationChange -> configuration, the same task key as before' {
        $u = Units (Rec 'ConfigurationChange' 'Turn on PUA protection')
        ($u[0].Kind, $u[0].TaskKey, $u[0].Product) | Should -Be @('configuration', 'configuration|turn on pua protection', '')
    }
    It 'Uninstall -> other (the tool Manual)' { (Units (Rec 'Uninstall' 'Uninstall Adobe Flash'))[0].Kind | Should -Be 'other' }
    It 'no type -> configuration, exactly as before' {
        $u = Units (Rec '' 'Update openssl')
        ($u[0].Kind, $u[0].TaskKey) | Should -Be @('configuration', 'configuration|update openssl')
    }
    It 'the tools: software-upgrade = Software deployment, configuration = Policy, other = Manual' {
        $s = Get-SIRemediationTaskChannelSql -Kind 'o.Kind'
        $s | Should -Match "WHEN N'software-upgrade' THEN N'Software deployment'"
        $s | Should -Match "WHEN N'configuration' THEN N'Policy'"
        $s | Should -Match "ELSE N'Manual' END"
    }
    It 'the task build reads the type and the software it names (stored with the finding, a recommendation''s rows only)' {
        $rf = Get-SIRemediationTaskRuleFields -Plan $script:Plan
        foreach ($x in 'si_recommendation_remediation_type', 'si_recommendation_product', 'si_recommendation_vendor') { @($rf.Known) | Should -Contain $x }
        (Get-SIRemediationTaskColumns)['si_recommendation_remediation_type'] | Should -Match "k\.Typ = N'recommendation' AND ISJSON\(f\.DetailJson\) = 1"
    }
    It 'a version-less software copy inside an application: one task per application, "(bundles <product>)"' {
        $ev = [ordered]@{ DeviceId = 'd1'; Vendor = 'openssl'; Product = 'openssl'; Version = '3.0.1'; PathType = 'disk'; FullPath = 'C:\Program Files\Foo\libssl.dll'; InstallKind = 'bundled'; Application = 'Foo'; ApplicationSource = 'folder'; CollectionTime = [datetime]'2026-11-01' }
        $b = Get-SIRemediationTaskBundledUnits -Rows @($ev) -Product 'openssl' -Version ''
        @($b.Units).Count | Should -Be 1
        $b.Units[0].TaskName | Should -Be 'Update Foo (bundles openssl)'
        $b.Units[0].Paths | Should -Be 'C:\Program Files\Foo\libssl.dll'
        (Get-SIRemediationTaskBundledUnits -Rows @($ev) -Product 'openssl' -Version '3.0.1').Units[0].TaskName | Should -Be 'Update Foo (bundles openssl 3.0.1)'
    }
}
