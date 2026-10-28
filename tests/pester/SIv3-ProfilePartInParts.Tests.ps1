#Requires -Version 5.1
<#
    THE IDENTITY PROFILE PART IN A RUN COLLECTED IN PARTS (engine/data-model/SI-RecordCapture.ps1 Add-SIRecordPartsFromProfileRows,
    SI-RecordHandover.ps1). Ring 1, 2026-10-10: discovery captured every Entra record and handed it over; the worker that built
    the profile rows held none of them, so "the record of this object is captured here" was false for every identity and the
    'profile' part (roles, permissions, privilege tiers, sign-in, shadow admin, credential expiry) was never kept -- every
    identity CI came out without them and the identity Risk Analysis reports returned nothing.
    What these tests keep true:
      * a part (SI_COLLECT_PHASE = parts) keeps the profile part although it holds no Entra record, and hands it over;
      * the merge joins it with discovery's record of the same object -- one record, the provider part AND the profile part;
      * a merged record made only of attached parts (a profile row whose object discovery never captured) is not published;
      * outside a part, a profile row still never creates a record;
      * a service principal's creation time reaches si_created through the profile part.
    Offline. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    function script:MemStore {
        $m = @{}
        [pscustomobject]@{
            Data  = $m
            Write = { param($Path, $Text) $m[$Path] = [string]$Text }.GetNewClosure()
            Read  = { param($Path) $m[$Path] }.GetNewClosure()
            List  = { param($Prefix) @($m.Keys | Where-Object { $_.StartsWith($Prefix) } | Sort-Object) }.GetNewClosure()
        }
    }
    function script:ProfileRows {
        @(
            [pscustomobject]@{ PrimaryEntityId = 'S1'; ObjectType = 'ServicePrincipal'; AppId = 'APP-1'; CreatedDateTime = '2024-01-02T03:04:05Z'
                EntraRoles_Permanent = '["Privileged Role Administrator"]'; EntraRolesPermanentVerdict_Tier = 0
                EntraAppPermissions_Application = '["Directory.ReadWrite.All"]'; LastSignInDateTime = '2025-01-01T00:00:00Z' },
            [pscustomobject]@{ PrimaryEntityId = 'GHOST'; ObjectType = 'User'; DisplayName = 'discovery never captured me' }
        )
    }
}

AfterAll { [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', $null) }

Describe 'the profile part in a run collected in parts' {
    It 'a part that holds no Entra record still keeps the profile part, and hands it over' {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        Add-SIRecordPartsFromProfileRows -Rows (ProfileRows) -InParts $true
        $global:SIRecordCaptureState.Records.ContainsKey('entra|service_principal|s1') | Should -BeTrue
        @($global:SIRecordCaptureState.Records['entra|service_principal|s1'].Parts.Keys) | Should -Be @('profile')
        $s = MemStore
        Save-SIRecordHandover -Store $s -Engine identity -RunId 'r1' -Who 'part-00001' -Buckets 1 | Should -Be 2 -Because 'the worker handed over nothing on ring 1 -- that was the defect'
    }
    It 'reads the phase from SI_COLLECT_PHASE when -InParts is not given' {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', 'parts')
        try { Add-SIRecordPartsFromProfileRows -Rows (ProfileRows) } finally { [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', $null) }
        $global:SIRecordCaptureState.Records.ContainsKey('entra|service_principal|s1') | Should -BeTrue
    }
    It 'outside a part a profile row never creates a record' {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        Add-SIRecordPartsFromProfileRows -Rows (ProfileRows)
        $global:SIRecordCaptureState.Records.Count | Should -Be 0
    }
    It 'the merge joins discovery''s record and the part''s profile into ONE record; a profile-only record is dropped' {
        $s = MemStore
        # discovery: the provider object
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        Add-SIRecordPart -Provider entra -RecordType service_principal -Key 'S1' -Part sp -Object @{ id = 'S1'; displayName = 'App'; appId = 'APP-1'; servicePrincipalType = 'Application' }
        $null = Save-SIRecordHandover -Store $s -Engine identity -RunId 'r2' -Who 'discover' -Buckets 1
        # the part: the profile rows only
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        Add-SIRecordPartsFromProfileRows -Rows (ProfileRows) -InParts $true
        $null = Save-SIRecordHandover -Store $s -Engine identity -RunId 'r2' -Who 'part-00001' -Buckets 1
        $merged = $null
        foreach ($p in @(& $s.List 'collect/identity/r2/records/' | Sort-Object @{ Expression = { if ($_ -match '/records/discover/') { '0' + $_ } else { '1' + $_ } } })) {
            $merged = Merge-SIRecordHandover -Documents @((& $s.Read $p) | ConvertFrom-Json) -Into $merged
        }
        Remove-SIRecordHandoverOrphans -State $merged | Should -Be 1
        @($merged.Records.Keys) | Should -Be @('entra|service_principal|s1')
        @($merged.Records['entra|service_principal|s1'].Parts.Keys | Sort-Object) | Should -Be @('profile', 'sp')
        $global:SIRecordCaptureState = $merged
        $row = @((ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model).Rows)[0]
        $row.si_entra_roles_permanent | Should -Not -BeNullOrEmpty
        $row.si_privilege_tier_permanent | Should -Be 0
        $row.si_app_permissions | Should -Not -BeNullOrEmpty
        $row.si_last_sign_in | Should -Not -BeNullOrEmpty
        $row.si_created | Should -Not -BeNullOrEmpty -Because 'a service principal''s creation time comes from the profile part'
        $global:SIRecordCaptureState = $null
    }
    It 'Publish-SIRecordHandover drops the orphans before it publishes' {
        $code = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1'))
        $code | Should -Match '(?s)function Publish-SIRecordHandover.*Remove-SIRecordHandoverOrphans -State \$merged.*Publish-SIRecords'
    }
    It 'CreatedDateTime is a profile part column and maps to si_created for service principals' {
        $script:SIIdentityProfilePartColumns | Should -Contain 'CreatedDateTime'
        $m = Get-Content -LiteralPath (Join-Path $script:SIRoot 'data-model\mappings\entra.locked.json') -Raw | ConvertFrom-Json
        @($m.mappings | Where-Object { $_.field -eq 'si_created' -and @($_.recordTypes) -contains 'service_principal' -and @($_.sources) -contains 'profile.CreatedDateTime' }).Count | Should -Be 1
    }
}
