#Requires -Version 5.1
<#
    DATA FIXES FROM THE RING 1 INVESTIGATION (2026-10-11) -- each a defect seen on internal ring 1, fixed at the root:

      1. the operator's TIER TAG (EmployeeWorkstations--tier2--SI) is a CI rule claim: low priority (asserted, last in the
         trust list) -- it sets the tier only when no observed rule claims one, and always beats the default rule;
      2. si_publisher_verified can be FALSE (whenAbsent on the mapping item); the unverified-publisher report leaves out
         Microsoft's own apps and keeps only Tier 0/1 high permission;
      3. no report names a column twice in OutputPropertyOrder, and the engine de-duplicates the column list anyway;
      4. a finding is keyed to its CI when the report published the CI's id as AssetId;
      5. the DCE/DCR cache refresh never prompts for a mandatory parameter under managed identity;
      6. a column's type is never inherited from the column before it (LastSignInDays was declared datetime), and a number
         sent to an existing datetime column lands in a `<column>_Number` companion;
      7. after a run changed a rule, every column that carries a value in the posted rows is checked (old columns too);
      8. full asset metadata of a run collected in parts: discovery and the parts hand over, the run's last step publishes
         ONCE (not once per part).
    Offline, PS 5.1 + 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Trust = Get-SICiTrustIndex $script:Model['trust']
    $script:Ctx = @{ Lists = (Get-SIDataModelListContext $script:Model); Now = [datetime]'2026-10-11T06:00:00Z' }
    $script:Yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
}

Describe '1. the operator tier tag on the CI (low priority)' {
    BeforeAll {
        $script:TagRules = @(ConvertTo-SICiTagTierRules -TagPattern '(?i)tier[_-]?(?<tier>[0-3])(--SI)?')
        $kind = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'assetKind'; kinds = @('endpoint') }) }
        $sw = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'hasSoftwareInstalled'; tvmSoftwareNames = @('contoso/agent') }) }
        $mk = { param($id, $detect, $set, [bool]$fb) [pscustomobject]@{ Id = $id; AppliesTo = @('endpoint'); Mode = 'merge'; osPlatformScope = @(); Purpose = $null; Category = $null; Description = $id
                Detections = @([pscustomobject]@{ Id = 'd1'; Detect = $detect; Set = $set; ExcludeAssets = @() }); File = "$id.yaml"; Folder = 'test'; Source = 'tree'; Fallback = $fb } }
        $script:Default = @((ConvertTo-SICiRules -RuleSet @((& $mk 'default' $kind @{ Tier = 3 } $true))).Rules)
        $script:Observed3 = @((ConvertTo-SICiRules -RuleSet @((& $mk 'agent' $sw @{ Tier = 3; Purpose = 'Workstation agent' } $false))).Rules)
    }
    It 'one rule per tier, asserted, devices only, mechanism operator.tier_tag' {
        $script:TagRules.Count | Should -Be 4
        foreach ($r in $script:TagRules) { $r.asserted | Should -BeTrue; $r.mechanism | Should -Be 'operator.tier_tag'; @($r.classes) | Should -Be @('device') }
        @($script:TagRules | ForEach-Object { $_.set['si_tier'] }) | Should -Be @(0, 1, 2, 3)
    }
    It 'operator.tier_tag is LAST in the shipped trust list, and trusted' {
        $last = @($script:Model['trust'].order)[-1]
        $last.id | Should -Be 'operator.tier_tag'
        $last.trusted | Should -BeTrue
    }
    It 'a device tagged tier 2 with nothing else claiming gets tier 2 (it used to get the default 3)' {
        $ci = [ordered]@{ si_class = 'device'; si_tags = @([ordered]@{ source = 'mde'; name = 'EmployeeWorkstations--tier2--SI'; value = '' }) }
        $null = Invoke-SICiRules -Ci $ci -Rules @($script:Default + $script:TagRules) -Trust $script:Trust -Context $script:Ctx -Now $script:Ctx.Now
        $ci.si_tier | Should -Be 2
        $ci.si_tier_set_by | Should -Be 'tag' -Because 'the web app filters on who decided: the tag, not an SI rule'
        $ci.si_tier_reason | Should -Match 'operator-tier-tag/tier2'
    }
    It 'an observed rule wins over the tag -- the tag never moves an observed tier (tags are low priority)' {
        $ci = [ordered]@{ si_class = 'device'; si_installed_software = @('contoso/agent'); si_tags = @([ordered]@{ source = 'mde'; name = 'Old--tier0--SI'; value = '' }) }
        $null = Invoke-SICiRules -Ci $ci -Rules @($script:Default + $script:Observed3 + $script:TagRules) -Trust $script:Trust -Context $script:Ctx -Now $script:Ctx.Now
        $ci.si_tier | Should -Be 3
        @($ci.si_tier_claims | Where-Object { $_.rule -eq 'operator-tier-tag/tier0' }).Count | Should -Be 1 -Because 'the tag claim is recorded even when it does not decide'
    }
    It 'several tier tags: the lowest tier (MIN)' {
        $ci = [ordered]@{ si_class = 'device'; si_tags = @([ordered]@{ source = 'eg'; name = 'A--tier3--SI'; value = '' }, [ordered]@{ source = 'eg'; name = 'B--tier1--SI'; value = '' }) }
        $null = Invoke-SICiRules -Ci $ci -Rules @($script:Default + $script:TagRules) -Trust $script:Trust -Context $script:Ctx
        $ci.si_tier | Should -Be 1
    }
    It 'a pattern without a tier group, or not a regex, gives no rules -- never one that matches every device' {
        @(ConvertTo-SICiTagTierRules -TagPattern '(?i)tier' 3>$null).Count | Should -Be 0
        @(ConvertTo-SICiTagTierRules -TagPattern '(?<tier>[0-3' 3>$null).Count | Should -Be 0
    }
    It 'WIRING: the CI build''s rules include the tag rules' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1'))
        $src | Should -Match ([regex]::Escape('@($conv.Rules) + @($native.Rules) + @(Get-SICiTagTierRules)'))
    }
}

Describe '2. si_publisher_verified can be false; the unverified-publisher report' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\data-model\SI-FieldMapper.ps1')
        $script:MapSp = { param($o) (ConvertTo-SIRecord -Object $o -Mapping $script:Model.Mappings['entra'] -RecordType 'service_principal' -Catalog $script:Model['field-catalog'] `
                    -ValueMaps $script:Model['value-maps'].maps -CollectionTime ([datetime]'2026-10-11T03:00:00Z') -RunId 'run-1').Record }
    }
    It 'an SP whose verifiedPublisher has no id is NOT verified (false); one with an id is verified' {
        $un = & $script:MapSp ([pscustomobject]@{ sp = [pscustomobject]@{ id = 'sp-1'; displayName = 'App'; verifiedPublisher = [pscustomobject]@{ verifiedPublisherId = $null; displayName = $null } } })
        $un['si_publisher_verified'] | Should -BeExactly $false
        $no = & $script:MapSp ([pscustomobject]@{ sp = [pscustomobject]@{ id = 'sp-2'; displayName = 'App2' } })
        $no['si_publisher_verified'] | Should -BeExactly $false -Because 'the SP is there, the publisher id is not'
        $ok = & $script:MapSp ([pscustomobject]@{ sp = [pscustomobject]@{ id = 'sp-3'; displayName = 'App3'; verifiedPublisher = [pscustomobject]@{ verifiedPublisherId = '1234567' } } })
        $ok['si_publisher_verified'] | Should -BeExactly $true
    }
    It 'whenAbsent applies only when the source object is there (a record without the sp part says nothing)' {
        $item = @($script:Model.Mappings['entra'].mappings | Where-Object { $_.field -eq 'si_publisher_verified' })[0]
        $none = Get-SIMappingValues -MapItem $item -Object ([pscustomobject]@{ signIn = [pscustomobject]@{ x = 1 } }) -ValueMaps $script:Model['value-maps'].maps
        $none.Count | Should -Be 0
        Test-SISourceRootPresent -Object ([pscustomobject]@{ sp = 1 }) -Path 'sp.verifiedPublisher.verifiedPublisherId' | Should -BeTrue
        Test-SISourceRootPresent -Object ([pscustomobject]@{ x = 1 }) -Path 'sp.verifiedPublisher.verifiedPublisherId' | Should -BeFalse
        Test-SISourceRootPresent -Object ([pscustomobject]@{ sp = 1 }) -Path 'sp' | Should -BeFalse
    }
    It 'the compiled mapper and the reference (Get-SIMappingValues) agree on whenAbsent' {
        $item = @($script:Model.Mappings['entra'].mappings | Where-Object { $_.field -eq 'si_publisher_verified' })[0]
        $vals = Get-SIMappingValues -MapItem $item -Object ([pscustomobject]@{ sp = [pscustomobject]@{ id = 'sp-2' } }) -ValueMaps $script:Model['value-maps'].maps
        @($vals) | Should -Be @($false)
    }
    It 'present without whenAbsent is unchanged: si_fix_available stays unknown for a CVE with no named update (no false zero-day)' {
        $item = @($script:Model.Mappings['mde'].mappings | Where-Object { $_.field -eq 'si_fix_available' -and @($_.recordTypes) -contains 'vulnerability' })[0]
        $vals = Get-SIMappingValues -MapItem $item -Object ([pscustomobject]@{ vuln = [pscustomobject]@{ CveId = 'CVE-2026-1' } }) -ValueMaps $script:Model['value-maps'].maps
        @($vals).Count | Should -Be 0
    }
    It 'the report leaves out Microsoft first-party apps and keeps only Tier 0/1 high permission (Summary and Detailed)' {
        foreach ($rn in 'Identity_SPN_UnverifiedPublisher_HighPermission_Summary', 'Identity_SPN_UnverifiedPublisher_HighPermission_Detailed') {
            $i = $script:Yaml.IndexOf("- ReportName: $rn"); $i | Should -BeGreaterThan 0
            $next = $script:Yaml.IndexOf('- ReportName:', $i + 10)
            $chunk = $script:Yaml.Substring($i, $next - $i)
            $chunk | Should -Match ([regex]::Escape('where not(si_app_owner_org_id in (SI_List_microsoft_first_party_tenants))'))
            $chunk | Should -Match ([regex]::Escape('where si_high_risk_permission_grant == true or si_privilege_tier_permanent in (0, 1)'))
            $chunk | Should -Match ([regex]::Escape('let SI_List_microsoft_first_party_tenants = dynamic(['))
        }
        @($script:Model['lists'].lists | Where-Object { $_.id -eq 'microsoft_first_party_tenants' })[0].values | Should -Contain 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
    }
}

Describe '3. OutputPropertyOrder: no column twice' {
    It 'no report in the shipped YAML lists a column twice (any case)' {
        $dups = New-Object System.Collections.Generic.List[string]
        $name = ''; $in = $false; $seen = @{}
        foreach ($ln in ($script:Yaml -split "`r?`n")) {
            if ($ln -match '^\s*- ReportName:\s*(\S+)') { $name = $Matches[1]; $in = $false }
            elseif ($ln -match '^\s*OutputPropertyOrder:\s*$') { $in = $true; $seen = @{} }
            elseif ($in) {
                if ($ln -match '^\s*- (.+)$') { $k = $Matches[1].Trim().ToLowerInvariant(); if ($seen.ContainsKey($k)) { $dups.Add("$name : $k") } else { $seen[$k] = 1 } }
                else { $in = $false }
            }
        }
        $dups | Should -BeNullOrEmpty
    }
    It 'Get-RAUniqueColumns keeps the first of each name (case-insensitive), drops blanks -- Select-Object can no longer throw' {
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RowShaping.ps1')
        $c = Get-RAUniqueColumns -Columns @('A', 'RiskFactorIds', 'B', 'riskfactorids', '', $null, 'A')
        $c | Should -Be @('A', 'RiskFactorIds', 'B')
        { [pscustomobject]@{ A = 1; RiskFactorIds = 'x'; B = 2 } | Select-Object -Property $c } | Should -Not -Throw
    }
    It 'WIRING: the engine de-duplicates right before the shaping Select-Object' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $i = $src.IndexOf('$DesiredColumns = Get-RAUniqueColumns -Columns $DesiredColumns')
        $i | Should -BeGreaterThan 0
        $i | Should -BeLessThan $src.IndexOf('$Shaped = $RiskScoreArray | Select-Object -Property $DesiredColumns')
    }
}

Describe '4. a finding is keyed to its CI' {
    BeforeAll { . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-Findings.ps1') }
    It 'si_ci_id first; else AssetId when AssetIdSource says it is the CI; else nothing' {
        Get-SIFindingCiId ([pscustomobject]@{ si_ci_id = 'ci-1'; AssetId = 'x' }) | Should -Be 'ci-1'
        Get-SIFindingCiId ([pscustomobject]@{ AssetId = 'ci-2'; AssetIdSource = 'SecurityInsight CI' }) | Should -Be 'ci-2'
        Get-SIFindingCiId ([pscustomobject]@{ AssetId = 'ci-3'; AssetIdSource = 'ci' }) | Should -Be 'ci-3'
        Get-SIFindingCiId ([pscustomobject]@{ AssetId = 'aa:bb'; AssetIdSource = 'Exposure Graph node id' }) | Should -Be ''
    }
    It 'ConvertTo-SIFindingRows keys the finding on the CI from AssetId (si_ci_id filled, no asset: key)' {
        $rows = @([pscustomobject]@{ ConfigurationId = 'IDENTITY-ESCALATION-006'; ConfigurationName = 'x'; AssetId = 'ci-9'; AssetIdSource = 'SecurityInsight CI'; AssetName = 'App'; SecuritySeverity = 'High'; ReportName = 'R' })
        $f = @(ConvertTo-SIFindingRows -Rows $rows -CollectionTime ([datetime]'2026-10-11T00:00:00Z'))
        $f.Count | Should -Be 1
        $f[0].si_ci_id | Should -Be 'ci-9'
        $f[0].PSObject.Properties['si_asset_id'] | Should -BeNullOrEmpty
    }
    It 'WIRING: the engine labels a row whose AssetId is its si_ci_id' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $src | Should -Match ([regex]::Escape('$_src = $script:SIAssetIdSourceCi'))
        $map = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AssetIdentityMap.ps1'))
        $map | Should -Match ([regex]::Escape("`$script:SIAssetIdSourceCi = 'SecurityInsight CI'"))
    }
}

Describe '5. the DCE/DCR cache refresh never prompts' {
    BeforeAll { . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\Ensure-SecurityInsightInfra.ps1') }
    It 'no parameter is Mandatory where a managed-identity caller has nothing to give' {
        $p = (Get-Command Ensure-SecurityInsightAzDceDcrCache).Parameters
        foreach ($n in 'AzAppId', 'TenantId') { @($p[$n].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory }).Count | Should -Be 0 }
        $p.ContainsKey('AzAppCertificateStoreLocation') | Should -BeTrue -Because 'the cert callers splat it (Send-SIRunHealthRow) -- an unknown parameter failed the call'
    }
    It 'the managed-identity splat Send-SIRunHealthRow passes runs without a prompt and reads the lists as the identity' {
        Mock Get-SIDceList { @() }
        Mock Get-SIDcrList { @() }
        $authParams = @{ UseManagedIdentity = $true; ManagedIdentityClientId = 'mi-client' }
        { Ensure-SecurityInsightAzDceDcrCache @authParams -SubscriptionId 'sub' -DceResourceGroup 'rg' -DcrResourceGroup 'rg' -Force } | Should -Not -Throw
        Should -Invoke Get-SIDceList -Times 1 -Exactly -ParameterFilter { $UseManagedIdentity -and $ManagedIdentityClientId -eq 'mi-client' }
    }
    It 'the app path without an app id says so -- it does not prompt' {
        { Ensure-SecurityInsightAzDceDcrCache -AzAppSecret 's' -Force } | Should -Throw '*AzAppId and -TenantId are required*'
    }
}

Describe '6. a column type is never inherited; a number into a datetime column lands in <column>_Number' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ColumnTypeAlign.ps1')
    }
    It 'LastSignInDays (a double) after LastSignInDateTime is real -- not datetime' {
        $s = @(Get-SILogSchemaRest -Data @([pscustomobject]@{ LastSignInDateTime = [datetime]'2026-10-01T00:00:00Z'; LastSignInDays = [double]12 }) -As Array)
        ($s | Where-Object name -eq 'LastSignInDays').type | Should -Be 'real'
        ($s | Where-Object name -eq 'LastSignInDateTime').type | Should -Be 'datetime'
    }
    It 'an empty first value does not decide: the first row with a value does; never a value = dynamic' {
        $s = @(Get-SILogSchemaRest -Data @([pscustomobject]@{ A = 'x'; LastSignInDays = $null; Never = $null }, [pscustomobject]@{ A = 'y'; LastSignInDays = 40; Never = $null }) -As Array)
        ($s | Where-Object name -eq 'LastSignInDays').type | Should -BeIn @('int', 'long')
        ($s | Where-Object name -eq 'Never').type | Should -Be 'dynamic'
    }
    It 'an existing datetime column that receives numbers gets a <column>_Number companion (whole days as long)' {
        $types = @{ LastSignInDays = 'datetime'; AssetName = 'string'; TimeGenerated = 'datetime' }
        $rows = @([pscustomobject]@{ AssetName = 'a'; LastSignInDays = 12 }, [pscustomobject]@{ AssetName = 'b'; LastSignInDays = $null })
        $need = @(Get-RALaNumberCompanions -Rows $rows -Types $types)
        $need | Should -Be @('LastSignInDays')
        $r = Set-RALaColumnTypes -Rows $rows -Types $types -NumberCompanions $need
        $rows[0].LastSignInDays_Number | Should -Be 12
        $rows[0].LastSignInDays_Number | Should -BeOfType [long]
        $rows[0].LastSignInDays | Should -BeNullOrEmpty
        $r.MovedToNumber['LastSignInDays'] | Should -Be 1
        @(Get-RALaNumberCompanions -Rows @([pscustomobject]@{ When = '2026-10-01T00:00:00Z' }) -Types @{ When = 'datetime' }).Count | Should -Be 0 -Because 'a date is not a number'
    }
    It 'WIRING: the Risk Analysis post declares and fills the companion' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $src | Should -Match ([regex]::Escape('-NumberCompanions $__numCols -EnsureCompanionTyped'))
        $src | Should -Match ([regex]::Escape('-TextCompanions $__txtCols -NumberCompanions $__numCols'))
    }
}

Describe '7. after a rule change every posted column with values is checked' {
    BeforeAll { . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1') }
    BeforeEach { $global:SI_LogIngestRunCache = $null; $global:SI_LogIngestNotes = $null }
    AfterEach { $global:SI_LogIngestNewColumns = $null; $global:SI_LogIngestRunCache = $null; $global:SI_LogIngestNotes = $null }
    It 'the new column first, then every other column that carries a value' {
        Mock Wait-SILogColumnsStored { $script:Checked = @($Columns); [pscustomobject]@{ Verdict = 'stored'; Missing = @(); WaitedSec = 30; Detail = '' } }
        $global:SI_LogIngestNewColumns = @{ 'dcr-x' = [pscustomobject]@{ Table = 'SI_X'; Columns = @('NewCol'); WorkspaceResourceId = '/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w' } }
        $rows = @([pscustomobject]@{ Old = 'v'; NewCol = 'n'; Empty = ''; CollectionTime = [datetime]'2026-10-11T00:00:00Z' })
        Confirm-SILogNewColumns -DcrName 'dcr-x' -TableName 'SI_X_CL' -Data $rows -Bound @{} 6>$null
        $script:Checked[0] | Should -Be 'NewCol'
        $script:Checked | Should -Contain 'Old'
        $script:Checked | Should -Contain 'CollectionTime'
        $script:Checked | Should -Not -Contain 'Empty'
    }
    It 'an OLD column read back empty is said (the next run stores it) but is only propagation lag' {
        Mock Wait-SILogColumnsStored { [pscustomobject]@{ Verdict = 'not-stored'; Rows = 1; Missing = @('CriticalityTier'); WaitedSec = 30; Detail = '' } }
        $global:SI_LogIngestNewColumns = @{ 'dcr-x' = [pscustomobject]@{ Table = 'SI_X'; Columns = @('NewCol'); WorkspaceResourceId = '/w' } }
        $rows = @([pscustomobject]@{ CriticalityTier = 1; NewCol = 'n' })
        $w = @(Confirm-SILogNewColumns -DcrName 'dcr-x' -TableName 'SI_X_CL' -Data $rows -Bound @{} 3>&1 6>$null | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        $w.Count | Should -Be 1
        [string]$w[0] | Should -Match 'CriticalityTier are missing.*next run stores'
        @(Get-SILogIngestNotes)[0].Kind | Should -Be 'column-lag'
    }
    It 'no column added in this run: nothing is checked (no wait on every post)' {
        Mock Wait-SILogColumnsStored { throw 'must not be called' }
        $global:SI_LogIngestNewColumns = @{}
        { Confirm-SILogNewColumns -DcrName 'dcr-x' -TableName 'SI_X_CL' -Data @([pscustomobject]@{ A = 1 }) -Bound @{} } | Should -Not -Throw
        Should -Invoke Wait-SILogColumnsStored -Times 0 -Exactly
    }
}

BeforeDiscovery {
    # the Pro publisher (not in the Community copy): the hand-over tests run only where it is
    $script:HasProPublisher = Test-Path -LiteralPath (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\asset-properties\_shared\SI-AssetPropertiesProfiler.ps1')
}

Describe '8. full asset metadata of a run collected in parts: published ONCE by the run''s last step' -Skip:(-not $script:HasProPublisher) {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-FullAssetProperties.ps1')
        $pro = Join-Path $script:SIRoot 'engine\asset-properties\_shared\SI-AssetPropertiesProfiler.ps1'
        if (Test-Path -LiteralPath $pro) { . $pro }
        function script:New-MemStore {
            $h = @{}
            [pscustomobject]@{
                Data  = $h
                Read  = { param($Path) if ($h.ContainsKey($Path)) { $h[$Path] } else { $null } }.GetNewClosure()
                Write = { param($Path, $Text) $h[$Path] = [string]$Text }.GetNewClosure()
                List  = { param($Prefix) @($h.Keys | Where-Object { $_.StartsWith($Prefix) }) }.GetNewClosure()
            }
        }
        $script:Ct = [datetime]::SpecifyKind([datetime]'2026-10-11T04:00:00', 'Utc')
    }
    AfterEach {
        foreach ($v in 'SI_COLLECT_PHASE', 'SI_COLLECT_PART', 'SI_COLLECT_ENGINE_RUN') { [Environment]::SetEnvironmentVariable($v, $null) }
        $global:SI_AssetPropsHandoverStore = $null
        $null = Reset-SIFullAssetProperties
    }
    It 'discovery hands over its kept objects; each part its rows; the last step resolves them to every part''s rows and publishes once' {
        $store = New-MemStore
        # the producer: identity at the full level, two users + one SP kept by discovery
        $null = Reset-SIFullAssetProperties -Engine identity
        Set-SIFullAssetPropertiesLevel -Level full
        Add-SIFullSourceObject -SourceSystem 'entra-user' -Object ([pscustomobject]@{ id = 'u-1'; userPrincipalName = 'a@x' }) -AnchorColumn 'EntraAccountObjectId' -AnchorValue 'u-1'
        Add-SIFullSourceObject -SourceSystem 'entra-user' -Object ([pscustomobject]@{ id = 'u-2'; userPrincipalName = 'b@x' }) -AnchorColumn 'EntraAccountObjectId' -AnchorValue 'u-2'
        Add-SIFullSourceObject -SourceSystem 'entra-serviceprincipal' -Object ([pscustomobject]@{ id = 'sp-1'; displayName = 'App' }) -AnchorColumn 'EntraAccountObjectId' -AnchorValue 'sp-1'
        Set-SIFullSourcePull -SourceSystem 'entra-user'
        Set-SIFullSourcePull -SourceSystem 'entra-serviceprincipal'
        Save-SIFullAssetPropertiesDiscoverHandover -Engine identity -RunId 'run-p' -Store $store | Should -Be 3
        # two parts (two processes): each built some of the profile rows; Publish-SIFullAssetProperties hands over, never publishes
        Mock Publish-SIProfilerAssetProperties { throw 'a part must not publish' }
        $global:SI_AssetPropsHandoverStore = $store
        [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', 'parts'); [Environment]::SetEnvironmentVariable('SI_COLLECT_ENGINE_RUN', 'run-p')
        [Environment]::SetEnvironmentVariable('SI_COLLECT_PART', '0')
        $null = Publish-SIFullAssetProperties -RunContext ([pscustomobject]@{ Engine = 'identity'; RunId = 'run-p'; CollectionTime = $script:Ct; ShardCount = 2 }) -Rows @(
            [pscustomobject]@{ SI_AssetId = 'id-u1'; SI_AssetName = 'a@x'; EntraAccountObjectId = 'u-1'; SomethingElse = 'not handed over' }) 6>$null
        [Environment]::SetEnvironmentVariable('SI_COLLECT_PART', '1')
        $null = Publish-SIFullAssetProperties -RunContext ([pscustomobject]@{ Engine = 'identity'; RunId = 'run-p'; CollectionTime = $script:Ct; ShardCount = 2 }) -Rows @(
            [pscustomobject]@{ SI_AssetId = 'id-u2'; SI_AssetName = 'b@x'; EntraAccountObjectId = 'u-2' }, [pscustomobject]@{ SI_AssetId = 'id-sp1'; SI_AssetName = 'App'; EntraAccountObjectId = 'sp-1' }) 6>$null
        Should -Invoke Publish-SIProfilerAssetProperties -Times 0 -Exactly
        @($store.Data.Keys | Where-Object { $_ -like '*/part-00001/rows-*' }).Count | Should -Be 1
        $store.Data[@($store.Data.Keys | Where-Object { $_ -like '*/part-00000/rows-*' })[0]] | Should -Not -Match 'SomethingElse'
        # the run's last step: ONE publish, the run's CollectionTime, every object resolved
        $script:Calls = 0
        $res = Publish-SIAssetPropsHandover -Store $store -Engine identity -RunId 'run-p' -CollectionTime $script:Ct -Publish {
            param($RunContext, $ProfileRows, $Entries, $Pulls)
            $script:Calls++
            $script:Built = ConvertTo-SIProfilerAssetPropertyRows -Engine $RunContext.Engine -ProfileRows $ProfileRows -Entries $Entries -Pulls $Pulls -CollectionTime $RunContext.CollectionTime -RunId $RunContext.RunId
            $script:Rc = $RunContext
            'ok'
        } 6>$null
        $script:Calls | Should -Be 1 -Because 'once per run, not once per part: the guard compares a whole run, and the asset page never sees a run in pieces'
        $script:Rc.CollectionTime | Should -Be $script:Ct
        [int]$script:Rc.ShardCount | Should -Be 1 -Because 'the whole run is here, so the collection-change guard applies'
        @($script:Built.Rows).Count | Should -Be 3
        @($script:Built.Rows | ForEach-Object { $_.SI_AssetId } | Sort-Object) | Should -Be @('id-sp1', 'id-u1', 'id-u2')
        @($script:Built.Rows | Where-Object { $_.SourceSystem -eq 'entra-serviceprincipal' }).Count | Should -Be 1
        $script:Built.Unresolved['entra-user'].Missed | Should -Be 0
    }
    It 'a run that handed nothing over (security level) publishes nothing, silently' {
        Publish-SIAssetPropsHandover -Store (New-MemStore) -Engine identity -RunId 'none' -CollectionTime $script:Ct -Publish { throw 'no' } | Should -BeNullOrEmpty
    }
    It 'the producer at the security level hands nothing over' {
        $null = Reset-SIFullAssetProperties -Engine identity
        Save-SIFullAssetPropertiesDiscoverHandover -Engine identity -RunId 'r' -Store (New-MemStore) | Should -BeNullOrEmpty
    }
    It 'WIRING: the container hands discovery over (KEDA producer + discover child) and publishes once in the last step (KEDA last worker + records slice 0)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        ([regex]::Matches($src, [regex]::Escape('& $saveDiscoverAssetProps ([string]$ri.RunId)'))).Count | Should -Be 2
        $src | Should -Match ([regex]::Escape('$null = & $publishAssetPropsHandover $RecEngineRun $recCt'))
        $src | Should -Match ([regex]::Escape('if ($slice -eq 0) { $null = & $publishAssetPropsHandover $recRun $recCt }'))
        $src.IndexOf('$publishAssetPropsHandover = {') | Should -BeLessThan $src.IndexOf('$finishKedaRecords = {')
    }
}
