#Requires -Version 5.1
<#
    DEFENDER FOR CLOUD PROVES INTERNET EXPOSURE THROUGH ITS OWN MAPPING (#527 (7), owner 2026-10-10: "factors in si are more
    static, but source fields may chg").

    The same fact has a different field name in every source. Defender for Cloud's Unhealthy internet-exposure
    assessments (Resource Graph securityresources) become provider 'mdc' records (engine/asset-profiling/discovery/
    Get-SIMdcExposure.ps1); data-model/mappings/mdc.locked.json maps exposure.internetExposed onto si_internet_exposed,
    the only field the risk factor internet_exposed reads.

    What these tests keep true:
      * the query reads securityresources assessments, Unhealthy, the internet-exposure ones, one row per resource -- REST
        Resource Graph only, no module
      * a resource becomes ONE mdc azure_resource record whose SI fields are azure_resource_id (strong: it joins the
        resource's Azure record into one CI) and si_internet_exposed = true
      * si_internet_exposed lists mdc in its authority; the factor's providers name mdc; the factor itself reads only si_*
      * a failed read is said, records nothing and marks the pull incomplete (absence proves nothing)
      * wired into the Azure discovery, after the resources, never failing it
    Offline; PS 7 (v3 gate).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIMdcExposure.ps1')
    $script:Model = Get-SIDataModel
}

Describe 'the Defender for Cloud exposure query' {
    It 'reads the Unhealthy internet-exposure assessments, one row per resource' {
        $q = Get-SIMdcExposureKql
        $q | Should -Match "(?m)^securityresources\r?$"
        $q | Should -Match "type =~ 'microsoft\.security/assessments'"
        $q | Should -Match "properties\.status\.code\) =~ 'Unhealthy'"
        $q | Should -Match "'483f12ed-ae23-447e-a2de-a67a10db4353'"
        $q | Should -Match 'summarize Assessments = make_set\(DisplayName\) by ResourceId'
    }
    It 'uses REST Resource Graph only (no PowerShell module)' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIMdcExposure.ps1'))
        $t | Should -Match 'Search-SIAzGraph'
        $t | Should -Not -Match 'Search-AzGraph|Import-Module|Get-AzSecurity'
    }
}

Describe 'an exposed resource becomes an mdc record on si_internet_exposed' {
    BeforeEach { $null = Reset-SIRecordCapture -Engine azure -Clear }
    It 'one record: azure_resource_id (lower-case) + si_internet_exposed = true; the pull is complete' {
        $n = Invoke-SIMdcExposureCapture -Query { param($q) @([pscustomobject]@{ ResourceId = '/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/VM1'; Assessments = @('Management ports should be closed on your virtual machines') }) }
        $n | Should -Be 1
        $res = ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model
        @($res.Errors) | Should -BeNullOrEmpty
        $r = @($res.Rows)[0]
        $r.si_provider | Should -Be 'mdc'
        $r.si_record_type | Should -Be 'azure_resource'
        $r.si_class | Should -Be 'cloud_resource'
        $r.azure_resource_id | Should -Be '/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm1'
        $r.si_internet_exposed | Should -BeTrue
        $global:SIRecordCaptureState.Pulls['mdc'].Complete | Should -BeTrue
    }
    It 'a failed read records nothing and marks the pull incomplete' {
        $n = Invoke-SIMdcExposureCapture -Query { param($q) throw 'AuthorizationFailed' } -WarningAction SilentlyContinue
        $n | Should -Be 0
        @(Get-SICapturedRecords).Count | Should -Be 0
        $global:SIRecordCaptureState.Pulls['mdc'].Complete | Should -BeFalse
    }
}

Describe 'the data model links it' {
    It 'si_internet_exposed lists mdc in its authority and mdc is a known provider' {
        $f = @($script:Model['field-catalog'].fields | Where-Object { $_.name -eq 'si_internet_exposed' })[0]
        @($f.resolution.authority) | Should -Contain 'mdc'
        @($script:Model['field-catalog'].providers) | Should -Contain 'mdc'
        $script:Model.Mappings.Contains('mdc') | Should -BeTrue
    }
    It 'the factor internet_exposed names mdc as a provider and reads only SI fields' {
        $fac = @($script:Model['risk-factors'].factors | Where-Object { $_.id -eq 'internet_exposed' })[0]
        $fac.providers.mdc[0].sources | Should -Be @('exposure.internetExposed')
        ($fac.when | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match 'exposure\.'
    }
    It 'is wired into the Azure discovery after the resources, never failing it' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromAzureResources.ps1'))
        $t | Should -Match "try \{ \`$mdcN = Invoke-SIMdcExposureCapture -SubscriptionIds \`$SubscriptionIds"
        $t.IndexOf('Invoke-SIMdcExposureCapture') | Should -BeGreaterThan $t.IndexOf("Set-SIFullSourcePull -SourceSystem 'arm'")
    }
}
