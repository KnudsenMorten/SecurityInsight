#Requires -Version 5.1
<#
    #690 -- THE REPORT QUERY DEFECTS STILL OPEN AFTER THE CERTIFICATION ROUNDS (ops/report-certification/reviews/review-ABD.md,
    review-C2.md, review-E.md), fixed in the shipped report definitions and the Exposure Graph mapping. Owner approval
    2026-10-15: "approved to fix all engine logic, reports, make new def etc".

      (12) Device_Recommendations (Summary + Detailed): the applicable filter ran BEFORE taking each device and setting's
           latest assessment -- a setting whose newest assessment says it no longer applies was reported from an older row
           (stale, presented as current). Now the latest row decides. The subcategory falls back to the assessment's own.
      (13) Device_EndOfSupport_Software (Summary + Detailed): a device with no DeviceInfo row in 30 days was named by its
           Defender id (a GUID) although the inventory carries its name -- the inventory's own DeviceName is used next.
      (14) Azure_Recommendations (Summary + Detailed): recommendation names with leading spaces (the graph writes some
           that way) are shown and keyed trimmed; the hand-off to the Defender report keeps comparing the graph's own text.
           Azure_DefenderRecommendations (Summary + Detailed): the subscription tier came from the sliced CI link (the #675
           defect fixed in the graph report) -- it now reads the same canonical per-run block.
      (2b) Attack_Paths_*_Data_Sensitivity_to_Exposed_Credentials: NOT a defect -- every label is lower-cased before the
           allowlist (NormalizeLabel), so the graph's entra-userCookie meets entra-usercookie. Pinned here.
      (16) the Exposure Graph mapping: a service principal / managed identity node's NodeName is its OBJECT ID -- its name
           is rawData.accountDisplayName; appId, appOwnerOrganizationId and accountEnabled are mapped too (Entra wins).

    Offline: the shipped YAML and mapping are read; nothing runs a query. Every changed // comment inside a query has no
    colon (a colon there breaks the YAML parse).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    $yaml = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Catalog = ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText($yaml)) -SourceName $yaml
    function script:QueryOf([string]$Name) {
        $r = @($script:Catalog.Reports | Where-Object { [string]$_.ReportName -eq $Name })[0]
        if ($null -eq $r) { throw "no report $Name" }
        (@($r.ReportQuery) -join "`n")
    }
    function script:IndexOfRx([string]$Text, [string]$Pattern) { $m = [regex]::Match($Text, $Pattern); if ($m.Success) { $m.Index } else { -1 } }
    $script:Changed = @('Device_Recommendations_Summary', 'Device_Recommendations_Detailed', 'Device_EndOfSupport_Software_Summary', 'Device_EndOfSupport_Software_Detailed',
                        'Azure_Recommendations_Summary', 'Azure_Recommendations_Detailed', 'Azure_DefenderRecommendations_Summary', 'Azure_DefenderRecommendations_Detailed')
}

Describe '(12) Device_Recommendations -- the latest assessment decides, then the applicable filter' {
    It '<_>: arg_max by device and setting comes BEFORE the applicable filter' -ForEach @('Device_Recommendations_Summary', 'Device_Recommendations_Detailed') {
        $q = QueryOf $_
        $base = [regex]::Match($q, '(?s)let TVM_Base =.*?;\s*\n').Value
        $base | Should -Not -BeNullOrEmpty
        $am = IndexOfRx $base '\| summarize arg_max\(Timestamp, \*\) by DeviceId, ConfigurationId'
        $ap = IndexOfRx $base '\| where iff\(onlyApplicable, IsApplicable == 1, true\)'
        $am | Should -BeGreaterThan 0
        $ap | Should -BeGreaterThan $am -Because 'an older applicable row must never stand in for a newest row that says not applicable'
        # the non-compliant filter still reads the latest row
        $base | Should -Match '\| where IsCompliant == false'
    }
    It '<_>: the subcategory falls back to the assessment''s own when the KB has none' -ForEach @('Device_Recommendations_Summary', 'Device_Recommendations_Detailed') {
        QueryOf $_ | Should -Match ([regex]::Escape('Subcategory       = coalesce(KB_ConfigurationSubcategory, tostring(column_ifexists("ConfigurationSubcategory", ""))),'))
    }
    It 'emulated -- a setting applicable a week ago and not applicable now is NOT reported' {
        $rows = @(
            [pscustomobject]@{ DeviceId = 'd1'; ConfigurationId = 'scid-1'; Timestamp = [datetime]'2026-10-01'; IsApplicable = 1; IsCompliant = 0 }
            [pscustomobject]@{ DeviceId = 'd1'; ConfigurationId = 'scid-1'; Timestamp = [datetime]'2026-10-08'; IsApplicable = 0; IsCompliant = 0 }
            [pscustomobject]@{ DeviceId = 'd1'; ConfigurationId = 'scid-2'; Timestamp = [datetime]'2026-10-08'; IsApplicable = 1; IsCompliant = 0 })
        # the old order: filter applicable, then latest -> scid-1 from the stale row
        $old = @($rows | Where-Object { $_.IsApplicable -eq 1 } | Group-Object DeviceId, ConfigurationId | ForEach-Object { $_.Group | Sort-Object Timestamp -Descending | Select-Object -First 1 } | Where-Object { $_.IsCompliant -eq 0 })
        # the new order: latest, then applicable
        $new = @($rows | Group-Object DeviceId, ConfigurationId | ForEach-Object { $_.Group | Sort-Object Timestamp -Descending | Select-Object -First 1 } | Where-Object { $_.IsApplicable -eq 1 -and $_.IsCompliant -eq 0 })
        @($old.ConfigurationId) | Should -Be @('scid-1', 'scid-2')
        @($new.ConfigurationId) | Should -Be @('scid-2')
    }
}

Describe '(13) Device_EndOfSupport_Software -- the inventory''s own device name before the Defender id' {
    It '<_>: _invDeviceName is kept and used after DeviceInfo''s name, before the CI name and the id' -ForEach @('Device_EndOfSupport_Software_Summary', 'Device_EndOfSupport_Software_Detailed') {
        $q = QueryOf $_
        $q | Should -Match '_invDeviceName = take_anyif\(tostring\(DeviceName\), isnotempty\(tostring\(DeviceName\)\)\) by DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion'
        $case = [regex]::Match($q, '(?s)\| extend AssetName = case\(.*?DeviceKey\)').Value
        $di = $case.IndexOf('DI_DeviceName'); $inv = $case.IndexOf('_invDeviceName'); $ci = $case.IndexOf('si_asset_name')
        $di | Should -BeGreaterThan 0
        $inv | Should -BeGreaterThan $di
        $ci | Should -BeGreaterThan $inv
    }
    It 'the summarize keeps one row per device and software -- the name is an aggregate, never a key (no extra rows)' {
        foreach ($n in 'Device_EndOfSupport_Software_Summary', 'Device_EndOfSupport_Software_Detailed') {
            (QueryOf $n) | Should -Not -Match 'by DeviceId, DeviceName, SoftwareVendor'
        }
    }
}

Describe '(14) Azure recommendations -- trimmed names, and the subscription tier from the per-run block' {
    It '<_>: the name is shown trimmed' -ForEach @('Azure_Recommendations_Summary', 'Azure_Recommendations_Detailed') {
        $q = QueryOf $_
        $q | Should -Match ([regex]::Escape('| extend ConfigurationName = trim(@"\s+", tostring(FindingName))'))
        $q | Should -Not -Match '\| extend ConfigurationName = tostring\(FindingName\)'
        # an exclusion written with or without the spaces matches
        $q | Should -Match ([regex]::Escape('| where not (FindingName in (SI_ExcludedConfigurationIds)) and not (trim(@"\s+", tostring(FindingName)) in (SI_ExcludedConfigurationIds))'))
    }
    It 'Detailed: the ConfigurationId (the finding key) is trimmed too' {
        QueryOf 'Azure_Recommendations_Detailed' | Should -Match ([regex]::Escape('| extend ConfigurationId   = trim(@"\s+", tostring(FindingName))'))
    }
    It '<_>: the hand-off to the Defender report still compares the graph''s own text (no duplicate, no loss)' -ForEach @('Azure_Recommendations_Summary', 'Azure_Recommendations_Detailed') {
        $q = QueryOf $_
        $q | Should -Match ([regex]::Escape('| extend _dfcKey = strcat("h", tostring(hash(strcat(tolower(tostring(AssetName)), "|", tolower(tostring(FindingName))))))'))
    }
    It 'emulated -- a leading space no longer makes a second name for the same recommendation' {
        $names = @(' Ensure storage account public access is disabled', 'Ensure storage account public access is disabled')
        @($names | ForEach-Object { $_ -replace '^\s+|\s+$', '' } | Select-Object -Unique).Count | Should -Be 1
    }
    It '<_>: the subscription tier comes from the canonical per-run block, never from the sliced _ciLink' -ForEach @('Azure_DefenderRecommendations_Summary', 'Azure_DefenderRecommendations_Detailed') {
        $q = QueryOf $_
        $q | Should -Match '//__SI_CI_SUBTIER_BEGIN__'
        $q | Should -Not -Match 'let _subTier = _ciLink'
        $q | Should -Match ([regex]::Escape('| join kind=leftouter (_subTierG) on _sub'))
        # the per-run block of the Defender reports is the same text as the graph report's (one rule)
        $mine = [regex]::Match($q, '(?s)//__SI_CI_SUBTIER_BEGIN__.*?//__SI_CI_SUBTIER_END__').Value
        $graph = [regex]::Match((QueryOf 'Azure_Recommendations_Detailed'), '(?s)//__SI_CI_SUBTIER_BEGIN__.*?//__SI_CI_SUBTIER_END__').Value
        $mine | Should -Be $graph
    }
}

Describe '(2b) Data_Sensitivity_to_Exposed_Credentials -- NOT a defect: labels are lower-cased before the allowlist' {
    It '<_>: the credential label is normalised (tolower) before the in() against the allowlist' -ForEach @('Attack_Paths_Summary_Data_Sensitivity_to_Exposed_Credentials', 'Attack_Paths_Detailed_Data_Sensitivity_to_Exposed_Credentials') {
        $q = QueryOf $_
        $q | Should -Match ([regex]::Escape('let NormalizeLabel = (s:string) { tolower(trim(" ", replace_string(s, " ", ""))) };'))
        $q | Should -Match '\| extend CredentialNodeLabelNorm = NormalizeLabel\(Credential(Node)?Label\)'
        $q | Should -Match ([regex]::Escape('| where CredentialNodeLabelNorm in (CredentialLabels);'))
        $q | Should -Match '"entra-usercookie"'
    }
}

Describe '(16) the Exposure Graph mapping names a service principal by its name, not its object id' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
        . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
        $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
        function script:SpRecord($Raw, [string]$Label = 'serviceprincipal', [string]$Name = '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0') {
            $node = [pscustomobject]@{ NodeId = 'n-1'; NodeLabel = $Label; NodeName = $Name; NodeProperties = [pscustomobject]@{ rawData = $Raw } }
            (ConvertTo-SIRecord -Object ([pscustomobject]@{ node = $node }) -Mapping $script:Model.Mappings['eg'] -RecordType 'service_principal' `
                -Catalog $script:Model['field-catalog'] -ValueMaps $script:Model['value-maps'].maps -CollectionTime ([datetime]::UtcNow)).Record
        }
    }
    It 'si_asset_name / si_display_name = rawData.accountDisplayName; the app id, owning tenant and enabled state are carried' {
        $r = SpRecord ([pscustomobject]@{ accountDisplayName = ' Contoso Backup '; appId = 'AAAA-1111'; appOwnerOrganizationId = 'ABCD1234-0000'; accountEnabled = $true })
        $r['si_asset_name'] | Should -Be 'Contoso Backup'
        $r['si_display_name'] | Should -Be 'Contoso Backup'
        $r['si_app_id'] | Should -Be 'aaaa-1111'
        $r['si_app_owner_org_id'] | Should -Be 'abcd1234-0000'
        $r['si_account_enabled'] | Should -BeTrue
    }
    It 'a managed identity the same way; the object id only when the graph gives no name' {
        (SpRecord ([pscustomobject]@{ accountDisplayName = 'id-backup' }) 'managedidentity')['si_asset_name'] | Should -Be 'id-backup'
        (SpRecord ([pscustomobject]@{}))['si_asset_name'] | Should -Be '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0'
    }
    It 'a user and a device keep NodeName (unchanged)' {
        $node = [pscustomobject]@{ NodeId = 'n-2'; NodeLabel = 'user'; NodeName = 'Mok'; NodeProperties = [pscustomobject]@{ rawData = [pscustomobject]@{ accountDisplayName = 'other' } } }
        $u = (ConvertTo-SIRecord -Object ([pscustomobject]@{ node = $node }) -Mapping $script:Model.Mappings['eg'] -RecordType 'user' -Catalog $script:Model['field-catalog'] -ValueMaps $script:Model['value-maps'].maps).Record
        $u['si_asset_name'] | Should -Be 'Mok'
    }
    It 'Entra stays the authority for the name, the app id and the owning tenant (the graph is the fallback)' {
        $f = @($script:Model['field-catalog'].fields)
        foreach ($n in 'si_app_id', 'si_app_owner_org_id') {
            $a = @(@($f | Where-Object name -eq $n)[0].resolution.authority)
            $a[0] | Should -Be 'entra'
            $a | Should -Contain 'eg'
        }
        @(Test-SIDataModel -Model $script:Model | Where-Object { $_ -match 'mappings/eg' }) | Should -BeNullOrEmpty
    }
    # the web app is not in the Community copy: this check runs where it is (Test-Path)
    It 'the Pro copy of the field catalog is the same file' -Skip:(-not (Test-Path -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'pro-management')))) {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\field-catalog.locked.json')) |
            Should -Be ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'pro-management\src\SI.Management.Core\ProData\DataModel\field-catalog.locked.json')))
    }
}

Describe 'the changed queries stay parseable' {
    It '<_>: no // comment inside the query carries a colon' -ForEach @('Device_Recommendations_Summary', 'Device_Recommendations_Detailed', 'Device_EndOfSupport_Software_Summary', 'Device_EndOfSupport_Software_Detailed',
                                                                    'Azure_Recommendations_Summary', 'Azure_Recommendations_Detailed', 'Azure_DefenderRecommendations_Summary', 'Azure_DefenderRecommendations_Detailed') {
        $q = QueryOf $_
        foreach ($l in @($q -split "`r?`n" | Where-Object { $_ -match '^\s*//' -and $_ -match '#690' })) { $l | Should -Not -Match ':' }
    }
}
