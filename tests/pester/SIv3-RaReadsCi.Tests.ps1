#Requires -Version 5.1
<#
    EVERY RISK ANALYSIS REPORT READS THE CI (REQUIREMENTS #505; V3-DATA-MODEL 2.10 / 2.19 / 2.21). Operator 2026-10-09:
    "all kqls must be refined to the design from yesterday". What these tests keep true, for every report in
    risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml:
      * no report reads a v2 profile table (SI_*_Profile_CL) -- D14, they stop at v3 -- not even a graph-only one;
      * outside the documented graph-only list (ra-ci-migration.locked.json, each with its reason):
          - an RF_P_* / RF_C_* flag for an ASSET factor the catalog evaluates (data-model/risk-factors.locked.json) is read
            from the CI's factors (si_rf_p / si_rf_c), never computed from columns by the report;
          - no join on AadDeviceId, a name, SI_AssetId or the old EpJoinKey -- a finding is tied to its CI through _ciKey
            (the CI's link ids);
      * every RF flag a report sets is a known factor (a legacy token of the catalog);
      * every SI field a report names is in the field catalog AND in the SI_CI_CL contract (the full row the CI build
        posts, SI-CiBuildSql.ps1 $SICiPostFields, plus the block's computed columns) -- except a FINDING field (catalog
        level 'finding'), which the report produces itself as a column of the finding and so only has to be in the catalog;
      * every CI block is the canonical one (RA-CiKql.ps1 regenerates it byte for byte);
      * the asset block's fields are all posted by the CI build and all in the catalog; the migration map names real fields.
    Offline: reads files only. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
    . (Join-Path $script:SIRoot 'tools\ra-ci\Get-RaReportInventory.ps1')
    $script:Reports = @((ConvertFrom-SIYaml -Path (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')).Reports)
    $script:Mig = Get-Content -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\ra-ci-migration.locked.json') -Raw | ConvertFrom-Json
    $script:Factors = @((Get-Content -LiteralPath (Join-Path $script:SIRoot 'data-model\risk-factors.locked.json') -Raw | ConvertFrom-Json).factors)
    $script:Catalog = @{}
    foreach ($f in @((Get-Content -LiteralPath (Join-Path $script:SIRoot 'data-model\field-catalog.locked.json') -Raw | ConvertFrom-Json).fields)) { $script:Catalog[[string]$f.name] = $f }
    # the SI_CI_CL contract, read from the CI build's own list (parsed, not run)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildSql.ps1'), [ref]$null, [ref]$null)
    $as = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.AssignmentStatementAst] -and $x.Left.Extent.Text -eq '$script:SICiPostFields' }, $true)
    $script:PostFields = @(& ([scriptblock]::Create($as.Right.Extent.Text)))
    # columns every SI_CI_CL row carries + the CI blocks' computed columns
    $script:Contract = @{}
    foreach ($c in @($script:PostFields) + @('si_ci_id', 'si_row_kind', 'si_collection_time', 'si_content_hash', 'si_last_seen', 'si_rf_p', 'si_rf_c')) { $script:Contract[[string]$c] = $true }
    $script:Inv = @(Get-RaReportInventory -Reports $script:Reports -ProfileColumns (Get-RaProfileColumns -SiRoot $script:SIRoot -Migration $script:Mig) -Factors $script:Factors -Migration $script:Mig)
    $script:AssetFactorTokens = @{}
    foreach ($f in $script:Factors) {
        if ([string]$f.appliesTo -eq 'asset' -and [string]$f.evaluatedBy -eq 'catalog') { foreach ($t in @($f.legacyTokens)) { if ($t) { $script:AssetFactorTokens[[string]$t] = [string]$f.id } } }
    }
    $script:GraphOnly = @{}
    foreach ($g in @($script:Mig.graphOnly)) { $script:GraphOnly[[string]$g.report] = [string]$g.reason }
}

Describe 'Every Risk Analysis report reads the CI, not the profile tables (#505)' {
    It 'the YAML has the 124 reports and the inventory saw all of them' {
        $script:Inv.Count | Should -Be $script:Reports.Count
        $script:Reports.Count | Should -BeGreaterOrEqual 124
    }
    It 'no report reads a v2 profile table (D14 -- they stop at v3)' {
        $bad = @($script:Inv | Where-Object { @($_.ProfileTables).Count -gt 0 } | ForEach-Object { '{0}: {1}' -f $_.Report, (@($_.ProfileTables) -join ', ') })
        $bad | Should -BeNullOrEmpty
    }
    It 'every report reads SI_CI_CL through a canonical CI block' {
        $bad = @($script:Inv | Where-Object { -not $_.ReadsCi -or @($_.CiBlocks).Count -eq 0 } | ForEach-Object { $_.Report })
        $bad | Should -BeNullOrEmpty
    }
    It 'every CI block is the canonical one (RA-CiKql.ps1 regenerates it unchanged)' {
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($r in $script:Reports) {
            $q = (@($r.ReportQuery) -join "`n") -replace "`r", ''
            if ($q -notmatch '__SI_CI_(LINK|ASSET)_BEGIN__') { continue }
            if ((Resolve-RACiBlocks -Query $q -StaleDays 30) -ne $q) { $bad.Add([string]$r.ReportName) }
        }
        $bad | Should -BeNullOrEmpty
    }
    It 'outside the graph-only list, an asset factor flag is read from the CI (si_rf_p / si_rf_c), never computed by the report' {
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($i in $script:Inv) {
            if ($script:GraphOnly.ContainsKey($i.Report)) { continue }
            foreach ($k in @($i.RfFlags.Keys)) {
                if ($script:AssetFactorTokens.ContainsKey($k) -and @($i.RfFromCi) -notcontains $k) { $bad.Add(('{0}: {1} (factor {2})' -f $i.Report, $k, $script:AssetFactorTokens[$k])) }
            }
        }
        $bad | Should -BeNullOrEmpty
    }
    It 'every RF flag a report sets is a factor of the catalog' {
        $bad = @($script:Inv | ForEach-Object { $r = $_; @($r.RfFlags.GetEnumerator()) | Where-Object { -not $_.Value } | ForEach-Object { '{0}: {1}' -f $r.Report, $_.Key } })
        $bad | Should -BeNullOrEmpty
    }
    It 'outside the graph-only list, no join on AadDeviceId, a name or SI_AssetId -- findings join their CI on _ciKey' {
        $bad = @($script:Inv | Where-Object { -not $script:GraphOnly.ContainsKey($_.Report) -and @($_.NameJoins).Count -gt 0 } | ForEach-Object { '{0}: {1}' -f $_.Report, (@($_.NameJoins) -join ' | ') })
        $bad | Should -BeNullOrEmpty
    }
    It 'every SI field a report reads is in the field catalog and in the SI_CI_CL contract' {
        $bad = New-Object System.Collections.Generic.List[string]
        # #541: the scope block (//__SI_SCOPE_BEGIN__..END__) is generated by the engine from the data model -- its criteria
        # functions (SI_InList_<id>, SI_Factor_<id>) take PARAMETERS named after the SI fields their condition reads
        # (si_os_name, si_cvss ...), which the report passes from its own columns; they are not SI_CI_CL reads.
        $outside = @{}
        foreach ($r in $script:Reports) {
            $q = [regex]::Replace(((@($r.ReportQuery) -join "`n") -replace "`r", ''), '(?s)//__SI_SCOPE_BEGIN__.*?//__SI_SCOPE_END__', '')
            $set = @{}; foreach ($m in [regex]::Matches($q, '\bsi_[a-z0-9_]+\b')) { $set[$m.Value] = $true }
            $outside[[string]$r.ReportName] = $set
        }
        foreach ($i in $script:Inv) {
            foreach ($f in @($i.SiFields)) {
                if ($outside.ContainsKey([string]$i.Report) -and -not $outside[[string]$i.Report].ContainsKey($f)) { continue }
                # the block's computed sets and the SI_CI_CL row-kind columns (posted by the CI build, not catalog fields)
                if ($f -in 'si_rf_p', 'si_rf_c', 'si_row_kind', 'si_content_hash') { continue }
                if (-not $script:Catalog.ContainsKey($f)) { $bad.Add(('{0}: {1} is not in the field catalog' -f $i.Report, $f)); continue }
                # a FINDING field (the catalog's level 'finding': how to fix, the affected software, the CVE's own context,
                # a certificate's expiry ...) is a column of the finding the report itself produces from its source -- it is
                # not read from the CI, so it is not in the SI_CI_CL row. It must be in the catalog (checked above).
                if ([string]$script:Catalog[$f].level -eq 'finding') { continue }
                if (-not $script:Contract.ContainsKey($f)) { $bad.Add(('{0}: {1} is not in the SI_CI_CL row' -f $i.Report, $f)) }
            }
        }
        $bad | Should -BeNullOrEmpty
    }
    It 'every graph-only report says why' {
        foreach ($g in @($script:Mig.graphOnly)) {
            [string]$g.reason | Should -Not -BeNullOrEmpty -Because ([string]$g.report)
            @($script:Reports | ForEach-Object { [string]$_.ReportName }) | Should -Contain ([string]$g.report)
        }
    }
}

Describe 'The CI blocks and the SI_CI_CL contract (#505)' {
    It 'every asset-block field is in the catalog, with the catalog''s type, and is posted by the CI build' {
        foreach ($k in $script:RACiAssetFields.Keys) {
            $script:Catalog.ContainsKey($k) | Should -BeTrue -Because $k
            [string]$script:RACiAssetFields[$k] | Should -Be ([string]$script:Catalog[$k].type) -Because $k
            $script:PostFields | Should -Contain $k
        }
    }
    It 'every field the CI build posts is in the catalog' {
        foreach ($k in $script:PostFields) { $script:Catalog.ContainsKey([string]$k) | Should -BeTrue -Because $k }
    }
    It 'every SI field the migration map names is in the catalog' {
        foreach ($p in @($script:Mig.columnMap.PSObject.Properties)) {
            $si = [string]$p.Value.si
            foreach ($m in [regex]::Matches($si, '\bsi_[a-z0-9_]+\b')) {
                $n = $m.Value
                if ($n -in 'si_rf_p', 'si_rf_c' -or $n.EndsWith('_')) { continue }
                $script:Catalog.ContainsKey($n) | Should -BeTrue -Because ('{0} -> {1}' -f $p.Name, $n)
            }
        }
    }
    It 'the link block keys a CI by every linked id, lower-case, one CI per key' {
        $b = Get-RACiKqlBlock -Kind link
        $b | Should -Match ([regex]::Escape('extract_all(@''"id"\s*:\s*"([^"]+)"'''))
        $b | Should -Match ([regex]::Escape('summarize arg_max(_ciBuild, *) by _ciKey'))
        foreach ($l in 'si_link_mde', 'si_link_entra', 'si_link_azure', 'si_link_eg', 'si_link_ad', 'si_link_intune') { $b | Should -Match $l }
    }
    It 'both blocks: the newest build''s CIs, the latest full row within the stale days, seen rows for liveness' {
        foreach ($k in 'link', 'asset') {
            $b = Get-RACiKqlBlock -Kind $k -StaleDays 45
            $b | Should -Match 'ago\(45d\)'
            $b | Should -Match ([regex]::Escape('arg_max(iff(_ciKind == "seen", datetime(1900-01-01), _ciT), *) by _ciId'))
            $b | Should -Match ([regex]::Escape('| where _ciKind != "seen"'))
            $b | Should -Match ([regex]::Escape('where _ciBuild == toscalar(SI_CI_CL'))
            $b | Should -Match ([regex]::Escape('si_stale_ = isnotnull(_ciSeen) and _ciSeen < ago(45d)'))
            ($b -split "`n" | Where-Object { $_ -match '^\s*let ' }).Count | Should -Be 1 -Because 'one let per block: the hybrid pre-fetcher cuts a binding at its first ;'
            ([regex]::Matches(($b -replace '(?m)//[^\r\n]*', ''), ';')).Count | Should -Be 1
        }
    }
    It 'the factor sets take production factors with impact > 0, by axis' {
        $b = Get-RACiKqlBlock -Kind link
        $b | Should -Match ([regex]::Escape('si_rf_p = make_set_if(tostring(_ciRf.id), tostring(_ciRf.axis) == "probability" and tostring(_ciRf.stage) in ("production", "") and todouble(_ciRf.impact) > 0)'))
        $b | Should -Match ([regex]::Escape('si_rf_c = make_set_if(tostring(_ciRf.id), tostring(_ciRf.axis) == "consequence"'))
    }
    It 'the engine regenerates the blocks with SI_ActiveStaleDays and keeps the indentation and class filter' {
        $q = "x`n" + (ConvertTo-RACiIndentedBlock -Block (Get-RACiKqlBlock -Kind asset -Classes identity) -Indent '    ') + "`n_ciAsset"
        $global:SI_ActiveStaleDays = 12
        try { $r = Resolve-RACiBlocks -Query $q } finally { $global:SI_ActiveStaleDays = $null }
        $r | Should -Match 'ago\(12d\)'
        $r | Should -Match ([regex]::Escape('where tostring(si_class) in ("identity")'))
        $r | Should -Match '(?m)^    //__SI_CI_ASSET_BEGIN__'
        (Resolve-RACiBlocks -Query $q -StaleDays 30) | Should -Be $q
        # #541: the engine regenerates them through the scope preamble (with the report's scope and factor set)
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) | Should -Match ([regex]::Escape('$raScope = Resolve-RAScopePreamble -Query $Query'))
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ScopePreamble.ps1')) | Should -Match ([regex]::Escape('Resolve-RACiBlocks -Query $q -StaleDays ([int]$active.StaleDays) -Scope $active'))
    }
    It 'the hybrid pre-fetcher buckets the CI link rows on _ciKey, aligned with the report''s DeviceKey' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1'))
        $t | Should -Match ([regex]::Escape("foreach (`$col in '_ciKey','EpJoinKey'"))
        $t | Should -Match ([regex]::Escape("`$egStdCols = @{'_ciKey'=`$true;"))
    }
}

Describe 'The fields the reports need reach the CI (#505): the identity profiler''s look-ups on the Entra record' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
        . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
        $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    }
    It 'a user''s and a service principal''s profile row become the ''profile'' part of their Entra record, mapped to SI fields' {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        Add-SIRecordPart -Provider entra -RecordType user -Key 'U1' -Part user -Object @{ id = 'U1'; userPrincipalName = 'a@x.dk'; userType = 'Member'; accountEnabled = $true }
        Add-SIRecordPart -Provider entra -RecordType service_principal -Key 'S1' -Part sp -Object @{ id = 'S1'; displayName = 'App'; servicePrincipalType = 'Application' }
        Add-SIRecordPartsFromProfileRows -Rows @(
            [pscustomobject]@{ PrimaryEntityId = 'U1'; ObjectType = 'User'; DisplayName = 'Anna'; EntraRolesPermanentVerdict_Tier = 0; EntraRolesEligibleVerdict_Tier = 1; IsBreakGlass = $true
                EntraRoles_Permanent = '["Global Administrator"]'; CSA = '{"SI":{"AssetTier":"tier-0"}}'; ExternalUserState = 'Accepted'; NestedGroups = '["G1"]' },
            [pscustomobject]@{ PrimaryEntityId = 'S1'; ObjectType = 'ServicePrincipal'; AppId = 'APP-1'; IsOrphanSPN = $true; CredentialExpiryDays = -3
                EntraAppPermissions_Application = '["Directory.ReadWrite.All"]'; IsHighRiskPermissionGrant = $true; IsThirdPartyMultiTenantSpn = $false },
            [pscustomobject]@{ PrimaryEntityId = 'NOPE'; ObjectType = 'User'; DisplayName = 'no record captured' },
            [pscustomobject]@{ PrimaryEntityId = 'G1'; ObjectType = 'Group'; DisplayName = 'a group' })
        @($global:SIRecordCaptureState.Records.Keys | Sort-Object) | Should -Be @('entra|service_principal|s1', 'entra|user|u1') -Because 'a profile row never creates a record'
        $rows = @((ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model).Rows)
        $u = $rows | Where-Object { $_.si_record_type -eq 'user' }
        $s = $rows | Where-Object { $_.si_record_type -eq 'service_principal' }
        $u.si_display_name | Should -Be 'Anna'
        $u.si_privilege_tier_permanent | Should -Be 0
        $u.si_privilege_tier_eligible | Should -Be 1
        $u.si_is_break_glass | Should -BeTrue
        $u.si_external_user_state | Should -Be 'Accepted'
        @($u.si_entra_roles_permanent) | Should -Contain 'Global Administrator'
        @($u.si_group_memberships) | Should -Contain 'G1'
        $s.si_app_id | Should -Be 'app-1'
        $s.si_is_orphan_sp | Should -BeTrue
        $s.si_credential_expiry_days | Should -Be -3
        $s.si_high_risk_permission_grant | Should -BeTrue
        $s.si_is_third_party_multitenant | Should -BeFalse
        @($s.si_app_permissions) | Should -Contain 'Directory.ReadWrite.All'
    }
    It 'the new fields are resolved onto the CI (level both, not computed) and posted in SI_CI_CL' {
        foreach ($n in 'si_display_name', 'si_app_id', 'si_external_user_state', 'si_high_risk_permission_grant', 'si_vulns', 'si_privilege_tier_permanent', 'si_privilege_tier_eligible', 'si_is_break_glass') {
            [string]$script:Catalog[$n].level | Should -Be 'both' -Because $n
            [string]$script:Catalog[$n].resolution.policy | Should -Not -Be 'computed' -Because $n
            $script:PostFields | Should -Contain $n
        }
    }
    It 'Shodan''s CVE list is a public IP field (si_vulns)' {
        $m = Get-Content -LiteralPath (Join-Path $script:SIRoot 'data-model\mappings\shodan.locked.json') -Raw | ConvertFrom-Json
        @($m.mappings | Where-Object { $_.field -eq 'si_vulns' }).Count | Should -Be 1
        $null = Reset-SIRecordCapture -Engine 'publicip' -Clear
        Add-SIRecordPart -Provider shodan -RecordType public_ip -Key '1.2.3.4' -Part host -Object @{ ip_str = '1.2.3.4'; ports = @(22, 443); vulns = @('cve-2024-1', 'CVE-2024-2') }
        $r = @((ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model).Rows)[0]
        @($r.si_vulns) | Should -Be @('CVE-2024-1', 'CVE-2024-2')
    }
}