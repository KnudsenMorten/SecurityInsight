#Requires -Version 5.1
<#
    UNWRITTEN FIELDS -- every SI field a report reads is filled from data SecurityInsight already collects, or says
    honestly that it cannot be (follow-up of #546).

    Six Entra mappings read 'profile.<column>' sources no profiler wrote, so the SI fields stayed empty and reports MISSED
    findings (the shadow-admin reports could never fire). What these keep true:
      1. GUARD       every 'profile.<column>' source in data-model/mappings is a column the identity profile part carries
                     ($script:SIIdentityProfilePartColumns) and the identity profiler writes (its schema or its risk-factor
                     derivation), or a column the record-parts code computes ($script:SIIdentityProfileComputedColumns)
      2. MDI         the IdentityInfo row the identity discovery already reads is captured as the user's Defender for
                     Identity record (no new read, no new permission): service account, investigation priority percentile,
                     blast radius, the on-premises object id reach their SI fields; a failed read leaves the records frozen
      3. SHADOW      si_is_shadow_admin is computed from the critical AD groups and the Entra roles; unknown (no critical
                     group data, not a user) stays unknown -- never false
      4. EG          a synchronised account's password change from an Exposure Graph node whose primary provider is Active
                     Directory (rawData.passwordUpdateTime); a cloud node's value is not taken
      5. GAP CLOSED  si_passwordless_only is now read (#549: the users' authentication methods, UserAuthenticationMethod.Read.All):
                     the catalog no longer carries needsRead, the Entra mapping fills it from the 'authenticationMethods'
                     part, and the baseline lists no gap for it (the read itself: SIv3-PasswordlessOnly.Tests.ps1)
      6. DEAD SOURCES the never-written sources are gone (IsPasswordNeverExpires, IsPasswordlessOnly, ENTRA_/MDI_IsServiceAccount,
                     MDI_InvestigationPriorityPct); password-never-expires keeps its two written sources
    Offline; PS 7 (v3 gate). Nothing is sent anywhere.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Get-SIRiskFactors.ps1')
    $script:Model = Get-SIDataModel
    function script:Map([string]$Provider, $Object, [string]$RecordType) {
        (ConvertTo-SIRecord -Object $Object -Mapping $script:Model.Mappings[$Provider] -RecordType $RecordType -Catalog $script:Model['field-catalog'] `
            -ValueMaps $script:Model['value-maps'].maps -CollectionTime ([datetime]'2026-10-10T03:00:00Z') -RunId 'run-1').Record
    }
    $script:Oid = 'aaaaaaaa-0000-0000-0000-000000000546'
    # an IdentityInfo row as Get-SIIdentityInfoByObjectId projects it (fictional values)
    $script:IdentityInfo = [pscustomobject]@{
        AccountObjectId = $script:Oid; AccountUPN = 'svc-backup@contoso.test'; AccountDisplayName = 'svc-backup'; AccountSID = 's-1-5-21-1-2-3-1105'
        OnPremisesAccountObjectId = 'bbbbbbbb-0000-0000-0000-000000000546'; IsAccountEnabled = $true; IsServiceAccount = $true
        BlastRadius = 'High'; InvestigationPriority = 7; InvestigationPriorityPercentile = 93; RiskLevel = 'Medium'
    }
}

Describe 'GUARD: every profile.* mapping source is written (unwritten fields)' {
    BeforeAll {
        $script:Schema = @((Get-Content (Join-Path $script:SIRoot 'asset-profiling-schema\identity.schema.locked.json') -Raw | ConvertFrom-Json).fields | ForEach-Object { [string]$_.name })
        $script:RfKeys = @((Get-SIIdentityRiskFactors -Record ([pscustomobject]@{ Upn = 'x@contoso.test' })).Keys | ForEach-Object { [string]$_ })
        $script:Sources = New-Object System.Collections.Generic.List[object]
        foreach ($p in $script:Model.Mappings.Keys) {
            foreach ($i in @($script:Model.Mappings[$p].mappings)) {
                foreach ($s in @($i.sources)) { if ([string]$s -match '^profile\.([A-Za-z0-9_]+)') { $script:Sources.Add([pscustomobject]@{ Provider = $p; Field = [string]$i.field; Column = $Matches[1] }) } }
            }
        }
    }
    It 'the guard sees the profile sources (control: it cannot pass by finding none)' {
        $script:Sources.Count | Should -BeGreaterThan 15
    }
    It 'every profile.<column> source is a column the profile part carries or computes' {
        $carried = @($script:SIIdentityProfilePartColumns) + @($script:SIIdentityProfileComputedColumns)
        @($script:Sources | Where-Object { $carried -notcontains $_.Column } | ForEach-Object { '{0}: {1} <- profile.{2}' -f $_.Provider, $_.Field, $_.Column }) | Should -BeNullOrEmpty
    }
    It 'every column the profile part carries is written by the identity profiler (schema or risk-factor derivation)' {
        $written = @($script:Schema) + @($script:RfKeys)
        @($script:SIIdentityProfilePartColumns | Where-Object { $written -notcontains $_ }) | Should -BeNullOrEmpty
    }
    It 'a computed column is never also expected from the profiler row (one writer)' {
        @($script:SIIdentityProfileComputedColumns | Where-Object { $script:SIIdentityProfilePartColumns -contains $_ }) | Should -BeNullOrEmpty
    }
    It 'the guard fires on a never-written source (control)' {
        $carried = @($script:SIIdentityProfilePartColumns) + @($script:SIIdentityProfileComputedColumns)
        $carried | Should -Not -Contain 'IsPasswordlessOnly'
        $carried | Should -Not -Contain 'MDI_InvestigationPriorityPct'
    }
    It 'the dead sources are gone and password-never-expires keeps its written sources' {
        $all = @($script:Sources | ForEach-Object { $_.Column })
        foreach ($c in 'IsPasswordNeverExpires', 'IsPasswordlessOnly', 'ENTRA_IsServiceAccount', 'MDI_IsServiceAccount', 'MDI_InvestigationPriorityPct') { $all | Should -Not -Contain $c }
        $pne = @($script:Model.Mappings['entra'].mappings | Where-Object { $_.field -eq 'si_password_never_expires' } | ForEach-Object { @($_.sources) })
        $pne | Should -Contain 'user.passwordPolicies'
        $pne | Should -Contain 'profile.HasPasswordNeverExpires'
    }
}

Describe 'Defender for Identity: the IdentityInfo row already read is the mdi record' {
    It 'is captured by the identity discovery, for users the Entra collection holds, with the pull''s outcome' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraUsers.ps1'))
        $t | Should -Match ([regex]::Escape("Add-SIRecordPart -Provider 'mdi' -RecordType 'user' -Key ([string]`$u.id) -Part 'identity' -Object `$ii"))
        $t | Should -Match ([regex]::Escape("Set-SIRecordPull -Provider 'mdi'"))
        $f = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1'))
        $f | Should -Match "IdentityInfoState'\] = \[pscustomobject\]@\{ Complete = \`$false"
        $f | Should -Match "IdentityInfoState'\] = \[pscustomobject\]@\{ Complete = \`$true"
        $f | Should -Match 'InvestigationPriorityPercentile' -Because 'the read already projects the percentile'
        $f | Should -Match 'IsServiceAccount'
    }
    It 'service account, investigation priority percentile, blast radius and the ids reach their SI fields' {
        $r = Map 'mdi' ([pscustomobject]@{ identity = $script:IdentityInfo }) 'user'
        $r['si_is_service_account'] | Should -BeTrue
        $r['si_mdi_investigation_priority_pct'] | Should -Be 93
        $r['si_mdi_blast_radius'] | Should -Not -BeNullOrEmpty
        $r['entra_object_id'] | Should -Be $script:Oid
        $r['ad_object_guid'] | Should -Be 'bbbbbbbb-0000-0000-0000-000000000546' -Because 'IdentityInfo names it OnPremisesAccountObjectId'
        $r['si_upn'] | Should -Be 'svc-backup@contoso.test'
    }
    It 'a row without the values leaves the fields empty (unknown), never false' {
        $r = Map 'mdi' ([pscustomobject]@{ identity = [pscustomobject]@{ AccountObjectId = $script:Oid } }) 'user'
        $r.Contains('si_is_service_account') | Should -BeFalse
        $r.Contains('si_mdi_investigation_priority_pct') | Should -BeFalse
    }
    It 'the record carries no sign-in, so it never decides a synchronised account''s sign-in' {
        $r = Map 'mdi' ([pscustomobject]@{ identity = $script:IdentityInfo }) 'user'
        $r.Contains('si_last_sign_in') | Should -BeFalse
        $f = @($script:Model['field-catalog'].fields | Where-Object { $_.name -eq 'si_last_sign_in' })[0]
        @($f.resolution.byOrigin.synced.decidedBy) | Should -Not -Contain 'mdi'
    }
}

Describe 'Shadow admin, computed from the critical AD groups and the Entra roles' {
    BeforeAll {
        # the profile row's Properties as Build-IdentityProfileRow writes them: collect.entra = the discovery's ENTRA_* keys
        $script:ReadDone   = @{ collect = @{ entra = @{ RoleReadComplete = $true } } }
        $script:ReadFailed = @{ collect = @{ entra = @{ RoleReadComplete = $false } } }
        $global:SI_EntraRoleReadState = $null
    }
    AfterAll { $global:SI_EntraRoleReadState = $null }
    It 'critical AD groups and no Entra role = shadow admin -- ONLY with the role read known complete (the row''s stamp)' {
        Get-SIShadowAdminFromProfileRow -Row ([pscustomobject]@{ ObjectType = 'User'; AdNestedCriticalGroups = '[{"groupName":"Domain Admins"}]'; EntraRoles_Permanent = '[]'; EntraRoles_Eligible = $null; Properties = $script:ReadDone }) | Should -BeTrue
    }
    It 'critical AD groups AND an Entra role = visible in Entra, not a shadow admin' {
        Get-SIShadowAdminFromProfileRow -Row ([pscustomobject]@{ ObjectType = 'User'; AdNestedCriticalGroups = @('Domain Admins'); EntraRoles_Permanent = '["Global Reader"]' }) | Should -BeFalse
        Get-SIShadowAdminFromProfileRow -Row ([pscustomobject]@{ ObjectType = 'User'; AdNestedCriticalGroups = @('Domain Admins'); EntraRoles_Eligible = @('Security Administrator') }) | Should -BeFalse
    }
    It 'no critical AD group = false; critical groups not read = UNKNOWN; not a user = UNKNOWN' {
        Get-SIShadowAdminFromProfileRow -Row ([pscustomobject]@{ ObjectType = 'User'; AdNestedCriticalGroups = '[]' }) | Should -BeFalse
        Get-SIShadowAdminFromProfileRow -Row ([pscustomobject]@{ ObjectType = 'User' }) | Should -BeNullOrEmpty
        Get-SIShadowAdminFromProfileRow -Row ([pscustomobject]@{ ObjectType = 'User'; AdNestedCriticalGroups = '' }) | Should -BeNullOrEmpty
        Get-SIShadowAdminFromProfileRow -Row ([pscustomobject]@{ ObjectType = 'ServicePrincipal'; AdNestedCriticalGroups = '[{"groupName":"Domain Admins"}]' }) | Should -BeNullOrEmpty
    }
    It 'reaches si_is_shadow_admin through the Entra record''s profile part (and an unknown stays out of the part)' {
        $global:SIRecordCaptureState = $null
        $null = Reset-SIRecordCapture
        Add-SIRecordPart -Provider 'entra' -RecordType 'user' -Key $script:Oid -Part 'user' -Object ([pscustomobject]@{ id = $script:Oid; userPrincipalName = 'admin@contoso.test' })
        Add-SIRecordPartsFromProfileRows -Rows @([pscustomobject]@{ ObjectType = 'User'; PrimaryEntityId = $script:Oid; AdNestedCriticalGroups = '[{"groupName":"Domain Admins"}]'; EntraRoles_Permanent = '[]'; EntraRoles_Eligible = '[]'; Properties = $script:ReadDone })
        $rec = $global:SIRecordCaptureState.Records["entra|user|$($script:Oid)"]
        ($rec.Parts['profile'].SIJson | ConvertFrom-Json).IsShadowAdmin | Should -BeTrue -Because 'a part is kept as compact JSON (#475)'
        $obj = [pscustomobject]@{}; foreach ($k in $rec.Parts.Keys) { $obj | Add-Member -NotePropertyName $k -NotePropertyValue ($rec.Parts[$k].SIJson | ConvertFrom-Json) }
        (Map 'entra' $obj 'user')['si_is_shadow_admin'] | Should -BeTrue
        $null = Reset-SIRecordCapture -Clear
        Add-SIRecordPart -Provider 'entra' -RecordType 'user' -Key $script:Oid -Part 'user' -Object ([pscustomobject]@{ id = $script:Oid })
        Add-SIRecordPartsFromProfileRows -Rows @([pscustomobject]@{ ObjectType = 'User'; PrimaryEntityId = $script:Oid; DisplayName = 'x' })
        ($global:SIRecordCaptureState.Records["entra|user|$($script:Oid)"].Parts['profile'].SIJson | ConvertFrom-Json).PSObject.Properties['IsShadowAdmin'] | Should -BeNullOrEmpty
        $global:SIRecordCaptureState = $null
    }
}

Describe 'SHADOW-ADMIN GUARD: true only when the Entra role read is known to have completed' {
    BeforeAll {
        # the fetcher's functions, taken from the file (no Graph, no token): the role-read state and two of the reads
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1'), [ref]$null, [ref]$null)
        # #899: and the read check the two role reads go through
        foreach ($n in 'Set-SIEntraRoleReadPart', 'Test-SIEntraRoleReadComplete', 'Get-SIEntraRoleAssignmentsByPrincipal', 'Get-SIEntraPIMEligibleByPrincipal', 'Add-SIEntraActivatedRolesToEligible',
                       'Read-SIEntraRoleSetChecked', 'Read-SIGraphIdSet', 'Get-SIGraphRowKey', 'Test-SIIdSetEqual', 'Format-SIIdSetRead') {
            $fn = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true)
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        function script:Write-SIInfo { param($Message) }
        function script:Get-SIGraphHttpStatus { param($ErrorRecord) 403 }
        $script:CritRow = { param($Props) [pscustomobject]@{ ObjectType = 'User'; AdNestedCriticalGroups = '[{"groupName":"Domain Admins"}]'; EntraRoles_Permanent = '[]'; EntraRoles_Eligible = '[]'; Properties = $Props } }
        $script:AllParts = @('Definitions', 'Permanent', 'Eligible', 'GroupTypes', 'GroupMembers', 'PimForGroups')
    }
    BeforeEach { $global:SI_EntraRoleReadState = $null; $script:_SICache = @{} }
    AfterAll { $global:SI_EntraRoleReadState = $null }

    It 'role read FAILED + a critical AD group + no role found = UNKNOWN (null), never true' {
        Get-SIShadowAdminFromProfileRow -Row (& $script:CritRow @{ collect = @{ entra = @{ RoleReadComplete = $false } } }) | Should -BeNullOrEmpty
    }
    It 'role read COMPLETE + no role + a critical AD group = TRUE' {
        Get-SIShadowAdminFromProfileRow -Row (& $script:CritRow @{ collect = @{ entra = @{ RoleReadComplete = $true } } }) | Should -BeTrue
    }
    It 'the read''s state cannot be told (no stamp, no run-level flag) = UNKNOWN' {
        Get-SIShadowAdminFromProfileRow -Row (& $script:CritRow $null) | Should -BeNullOrEmpty
    }
    It 'without a stamp, the run-level flag decides: every part complete = true, one part failed or missing = unknown' {
        foreach ($p in $script:AllParts) { Set-SIEntraRoleReadPart -Part $p -Complete $true }
        Get-SIShadowAdminFromProfileRow -Row (& $script:CritRow $null) | Should -BeTrue
        Set-SIEntraRoleReadPart -Part 'Eligible' -Complete $false -ErrorText 'HTTP 403'
        Get-SIShadowAdminFromProfileRow -Row (& $script:CritRow $null) | Should -BeNullOrEmpty
        $global:SI_EntraRoleReadState = $null
        foreach ($p in @($script:AllParts | Where-Object { $_ -ne 'PimForGroups' })) { Set-SIEntraRoleReadPart -Part $p -Complete $true }
        Get-SIShadowAdminFromProfileRow -Row (& $script:CritRow $null) | Should -BeNullOrEmpty -Because 'a read that never recorded its outcome is not complete'
    }
    It 'the row''s stamp wins over the run-level flag (it belongs to the run that built the row) and works as JSON text' {
        foreach ($p in $script:AllParts) { Set-SIEntraRoleReadPart -Part $p -Complete $true }
        Get-SIShadowAdminFromProfileRow -Row (& $script:CritRow @{ collect = @{ entra = @{ RoleReadComplete = $false } } }) | Should -BeNullOrEmpty
        $global:SI_EntraRoleReadState = $null
        Get-SIShadowAdminFromProfileRow -Row (& $script:CritRow '{"collect":{"entra":{"RoleReadComplete":true}}}') | Should -BeTrue
    }
    It 'a role the read DID find makes it false even when the read was incomplete (the identity is visible in Entra)' {
        $row = [pscustomobject]@{ ObjectType = 'User'; AdNestedCriticalGroups = @('Domain Admins'); EntraRoles_Permanent = '["Global Reader"]'; Properties = @{ collect = @{ entra = @{ RoleReadComplete = $false } } } }
        Get-SIShadowAdminFromProfileRow -Row $row | Should -BeFalse
    }
    It 'the state: a part read twice is complete only when both reads were; no state = not complete; an empty part list = every part' {
        Test-SIEntraRoleReadComplete -State $null | Should -BeFalse
        Set-SIEntraRoleReadPart -Part 'Permanent' -Complete $false -ErrorText 'throttled'
        Set-SIEntraRoleReadPart -Part 'Permanent' -Complete $true
        $global:SI_EntraRoleReadState['Permanent'].Complete | Should -BeFalse
        $global:SI_EntraRoleReadState['Permanent'].Error | Should -Be 'throttled'
        foreach ($p in $script:AllParts) { Set-SIEntraRoleReadPart -Part $p -Complete $true }
        Test-SIEntraRoleReadComplete | Should -BeFalse -Because 'Permanent failed once this run'
        Test-SIEntraRoleReadComplete -Parts @() -State @{ Permanent = [pscustomobject]@{ Complete = $true } } | Should -BeFalse -Because 'an empty list means every part, not none'
    }
    It 'the PIM-eligible read that fails (403: no P2 or no permission) records NOT complete; one that succeeds records complete' {
        function script:Invoke-SIGraphPaged { param($RelativeUrl, $Token, $OnPage) throw 'Forbidden' }
        $null = Get-SIEntraPIMEligibleByPrincipal -Token 't' -RoleDefinitionMap @{ r1 = 'Global Administrator' } 3>$null
        $global:SI_EntraRoleReadState['Eligible'].Complete | Should -BeFalse
        $global:SI_EntraRoleReadState = $null; $script:_SICache = @{}
        function script:Invoke-SIGraphPaged { param($RelativeUrl, $Token, $OnPage) @([pscustomobject]@{ principalId = 'u1'; roleDefinitionId = 'r1' }) }
        $m = Get-SIEntraPIMEligibleByPrincipal -Token 't' -RoleDefinitionMap @{ r1 = 'Global Administrator' }
        $m['u1'] | Should -Contain 'Global Administrator'
        $global:SI_EntraRoleReadState['Eligible'].Complete | Should -BeTrue
    }
    It 'the permanent read that fails records NOT complete and still fails loudly' {
        function script:Invoke-SIGraphPaged { param($RelativeUrl, $Token, $OnPage) throw 'HTTP 503' }
        { Get-SIEntraRoleAssignmentsByPrincipal -Token 't' -RoleDefinitionMap @{ r1 = 'x' } } | Should -Throw '*503*'
        $global:SI_EntraRoleReadState['Permanent'].Complete | Should -BeFalse
    }
    It 'every role read records its outcome, and the discovery stamps the verdict on each user' {
        $f = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1'))
        foreach ($p in $script:AllParts) { $f | Should -Match ("Set-SIEntraRoleReadPart -Part '{0}' -Complete \`$false" -f $p) -Because "a failed $p read must say so" }
        foreach ($p in 'Permanent', 'Eligible', 'GroupTypes', 'GroupMembers', 'PimForGroups') { $f | Should -Match ("Set-SIEntraRoleReadPart -Part '{0}' -Complete \`$true" -f $p) }
        $f | Should -Match ([regex]::Escape("Set-SIEntraRoleReadPart -Part 'Definitions' -Complete (`$map.Count -gt 0)"))
        $f | Should -Match ([regex]::Escape('$global:SI_EntraRoleReadState = $null')) -Because 'a cache reset clears the state with it'
        $d = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraUsers.ps1'))
        $d | Should -Match ([regex]::Escape('ENTRA_RoleReadComplete       = [bool]$roleReadComplete'))
        $d | Should -Match ([regex]::Escape('$roleReadComplete = [bool](Test-SIEntraRoleReadComplete)'))
        $d | Should -Match ([regex]::Escape("Set-SIEntraRoleReadPart -Part 'GroupMembers' -Complete `$true")) -Because 'no role-assigned group = nothing to expand'
    }
    It 'the mdi pull: IdentityInfo state not visible + nothing read = NOT complete (kept)' {
        $d = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraUsers.ps1'))
        $d | Should -Match ([regex]::Escape("elseif (`$null -eq `$identityInfoMap -or `$identityInfoMap.Count -eq 0) { `$iiOk = `$false"))
    }
}

Describe 'Exposure Graph: a synchronised account''s password change from its Active Directory node' {
    It 'an Active Directory node''s passwordUpdateTime reaches si_password_last_changed' {
        $node = [pscustomobject]@{ NodeId = 'eg-ad-1'; NodeLabel = 'user'; NodeProperties = [pscustomobject]@{ rawData = [pscustomobject]@{ primaryProvider = 'ActiveDirectory'; passwordUpdateTime = '2026-09-30T08:00:00Z'; accountObjectId = $script:Oid } } }
        $r = Map 'eg' ([pscustomobject]@{ node = $node }) 'user'
        (ConvertTo-SIUtcOrNull $r['si_password_last_changed']) | Should -Be ([datetime]::SpecifyKind([datetime]'2026-09-30T08:00:00', [DateTimeKind]::Utc))
    }
    It 'a cloud (Entra) node''s value is NOT taken -- it may only follow Entra' {
        $node = [pscustomobject]@{ NodeId = 'eg-aad-1'; NodeLabel = 'user'; NodeProperties = [pscustomobject]@{ rawData = [pscustomobject]@{ primaryProvider = 'AzureActiveDirectory'; passwordUpdateTime = '2020-01-01T00:00:00Z' } } }
        (Map 'eg' ([pscustomobject]@{ node = $node }) 'user').Contains('si_password_last_changed') | Should -BeFalse
    }
    It 'rawData stored as JSON text works the same' {
        $node = [pscustomobject]@{ NodeId = 'eg-ad-2'; NodeLabel = 'user'; NodeProperties = [pscustomobject]@{ rawData = '{"primaryProvider":"ActiveDirectory","passwordUpdateTime":"2026-09-30T08:00:00Z"}' } }
        (Map 'eg' ([pscustomobject]@{ node = $node }) 'user').Contains('si_password_last_changed') | Should -BeTrue
    }
    It 'Exposure Graph is in the synchronised account''s password authority, after Active Directory; the old_password factor names it' {
        $f = @($script:Model['field-catalog'].fields | Where-Object { $_.name -eq 'si_password_last_changed' })[0]
        @($f.resolution.byOrigin.synced.authority) | Should -Contain 'eg'
        @($f.resolution.byOrigin.synced.authority)[0] | Should -Be 'ad'
        $op = @($script:Model['risk-factors'].factors | Where-Object { $_.id -eq 'old_password' })[0]
        $op.providers.eg | Should -Not -BeNullOrEmpty
        @(Test-SIRiskFactorProviders -Model $script:Model) | Should -BeNullOrEmpty
    }
}

Describe 'the passwordless-only gap is closed: the field is read (#549)' {
    It 'the catalog no longer says it needs a read; exactly one mapping fills it -- Entra''s authenticationMethods part' {
        $f = @($script:Model['field-catalog'].fields | Where-Object { $_.name -eq 'si_passwordless_only' })[0]
        $f.PSObject.Properties['needsRead'] | Should -BeNullOrEmpty
        $all = New-Object System.Collections.Generic.List[object]
        foreach ($p in $script:Model.Mappings.Keys) { foreach ($m in @($script:Model.Mappings[$p].mappings | Where-Object { $_.field -eq 'si_passwordless_only' })) { $all.Add([pscustomobject]@{ Provider = $p; Sources = @($m.sources) }) } }
        $all.Count | Should -Be 1
        $all[0].Provider | Should -Be 'entra'
        $all[0].Sources | Should -Be @('authenticationMethods.passwordlessOnly')
    }
    It 'the baseline lists no gap for it (neither needs-read nor no-provider nor an authority without a mapping)' {
        . (Join-Path $script:SIRoot 'engine\data-model\SI-FieldBaseline.ps1')
        $b = Get-SIFieldBaseline -Model $script:Model -SIRoot $script:SIRoot
        @($b.Gaps | Where-Object { $_.Item -eq 'si_passwordless_only' }) | Should -BeNullOrEmpty
        @($b.Fields | Where-Object { $_.Name -eq 'si_passwordless_only' })[0].Providers | Should -Contain 'entra'
    }
    It 'the shipped data model stays valid' {
        @(Test-SIDataModel -Model $script:Model) | Should -BeNullOrEmpty
    }
}
