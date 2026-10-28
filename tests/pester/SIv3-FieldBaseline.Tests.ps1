#Requires -Version 5.1
<#
    THE SI BASELINE DATASET (REQUIREMENTS #455, V3-DATA-MODEL 2.4.2) -- engine/data-model/SI-FieldBaseline.ps1.

      * COMPLETE FOR RISK ANALYSIS: every v2 profile column a Risk Analysis report reads has its entry in the column map
        (risk-analysis-detection/ra-ci-migration.locked.json) and every SI field the map names is in the catalog.
      * EVERY BASELINE FIELD CAN BE FILLED: each record / both field that is not computed has a provider mapping.
      * WHO FILLS A FIELD comes from the mappings (Get-SIFieldProviders), and an authority field's order has a place for
        every provider that fills it (Test-SIDataModel refuses a mapping whose provider is not in the order).
      * The web app's copy of the catalog is the catalog.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-FieldBaseline.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Baseline = Get-SIFieldBaseline -Model $script:Model -SIRoot $script:SIRoot
}

Describe 'SI baseline dataset (#455)' {
    # #505: every report reads the CI (SI_CI_CL), none a profile table -- the baseline inspects what Risk Analysis reads now
    It 'reads the Risk Analysis catalogue (every report that reads the CI is inspected; none reads a profile table)' {
        $script:Baseline.RaCiReports | Should -BeGreaterThan 50
        $script:Baseline.RaFields | Should -BeGreaterThan 40
        $script:Baseline.RaReports | Should -Be 0
        $script:Baseline.RaColumns | Should -Be 0
    }
    It 'has an SI field (or an explicit provider / dropped entry) for every profile column Risk Analysis reads' {
        @($script:Baseline.Gaps | Where-Object { $_.Kind -eq 'ra-column-unmapped' } | ForEach-Object { '{0} ({1})' -f $_.Item, $_.Detail }) | Should -BeNullOrEmpty
    }
    It 'defines every SI field the column map names' {
        @($script:Baseline.Gaps | Where-Object { $_.Kind -eq 'ra-field-missing' } | ForEach-Object { '{0} ({1})' -f $_.Item, $_.Detail }) | Should -BeNullOrEmpty
    }
    It 'can fill every baseline field from at least one provider' {
        @($script:Baseline.Gaps | Where-Object { $_.Kind -eq 'no-provider' } | ForEach-Object { $_.Item }) | Should -BeNullOrEmpty
    }
    It 'describes every baseline field (type, description, providers)' {
        foreach ($f in $script:Baseline.Fields) {
            $f.Type | Should -Not -BeNullOrEmpty -Because $f.Name
            $f.Description | Should -Not -BeNullOrEmpty -Because $f.Name
            @($f.Providers).Count | Should -BeGreaterThan 0 -Because $f.Name
        }
        @($script:Baseline.Fields).Count | Should -BeGreaterThan 100
    }
    It 'links the Risk Analysis profile columns to the fields that replace them' {
        $f = $script:Baseline.Fields | Where-Object { $_.Name -eq 'si_account_enabled' }
        @($f.RaColumns) | Should -Contain 'AccountEnabled'
        @($f.Providers) | Should -Contain 'entra'
    }

}

Describe 'Identity look-ups reach the Entra record (profile part)' {
    BeforeAll { . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1') }
    It 'hands the identity profiler''s computed values to the Entra record of the same object, and the mapping fills the SI fields' {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        Add-SIRecordPart -Provider 'entra' -RecordType 'user' -Key 'AAAA-1' -Part 'user' -Object ([pscustomobject]@{ id = 'aaaa-1'; displayName = 'Break Glass'; accountEnabled = $true })
        Add-SIRecordPartsFromProfileRows -Rows @(
            [pscustomobject]@{ ObjectType = 'User'; PrimaryEntityId = 'AAAA-1'; IsBreakGlass = $true; EntraRolesPermanentVerdict_Tier = 0 },
            [pscustomobject]@{ ObjectType = 'Group'; PrimaryEntityId = 'GGGG-1'; IsBreakGlass = $true },
            [pscustomobject]@{ ObjectType = 'User'; PrimaryEntityId = 'NOT-CAPTURED'; IsBreakGlass = $true })
        $cap = @(Get-SICapturedRecords)
        $cap.Count | Should -Be 1
        $cap[0].Object.profile.IsBreakGlass | Should -BeTrue
        $rec = ConvertTo-SIRecord -Object $cap[0].Object -Mapping $script:Model.Mappings['entra'] -RecordType 'user' -Catalog $script:Model['field-catalog'] `
            -ValueMaps $script:Model['value-maps'].maps -CollectionTime ([datetime]'2026-10-10T03:00:00Z') -RunId 'r1'
        $rec.Record['si_is_break_glass'] | Should -BeTrue
        $rec.Record['si_privilege_tier_permanent'] | Should -Be 0
        $null = Reset-SIRecordCapture -Clear
    }
}

Describe 'Who fills a field (Get-SIFieldProviders)' {
    It 'derives the providers, record types and sources from the mappings' {
        $p = Get-SIFieldProviders -Model $script:Model
        $mde = @($p['mde_device_id'] | Where-Object { $_.Provider -eq 'mde' })[0]
        $mde | Should -Not -BeNullOrEmpty
        @($mde.RecordTypes) | Should -Contain 'device'
        @($mde.Sources) | Should -Contain 'machine.id'
        @($p['si_internet_exposed'] | ForEach-Object { $_.Provider }) | Should -Contain 'mde'
    }
    It 'refuses a mapping whose provider has no place in the field''s authority order' {
        $m = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
        $item = [pscustomobject]@{ field = 'si_os_version'; recordTypes = @('device'); sources = @('machine.osVersion'); normalize = @('trim') }
        $f = $m['field-catalog'].fields | Where-Object { $_.name -eq 'si_os_version' }
        $f.resolution.authority = @(@($f.resolution.authority) | Where-Object { $_ -ne 'mde' })
        $m.Mappings['mde'].mappings = @($m.Mappings['mde'].mappings) + $item
        ((Test-SIDataModel -Model $m) -join "`n") | Should -Match "fills 'si_os_version' but 'mde' has no place"
    }
    It 'accepts a CMDB provider through the cmdb_owner token' {
        $p = (Test-SIDataModel -Model $script:Model) -join "`n"
        $p | Should -Not -Match "mappings/(cmdb|servicenow): fills"
    }
}
