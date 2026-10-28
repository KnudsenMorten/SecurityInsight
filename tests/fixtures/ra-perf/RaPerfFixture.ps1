#Requires -Version 7.0
<#
    Risk Analysis per-row performance -- the shared fixture of tests\pester\SIv3-RaRowPerformance.Tests.ps1.

      Import-RaPerfEngine -SIRoot <root>   loads the Risk Analysis pieces one query slice passes through (the same files the
                                           engine dot-sources), with the console helpers stubbed
      New-RaPerfRawRows -Count n           n rows as the advanced-hunting answer hands them over (one dictionary per row, the
                                           columns of Device_Missing_CVEs_Detailed's final project; empty values left out,
                                           as Graph leaves them out) -- deterministic (seeded)
      New-RaPerfCis -Count n               the CIs those rows belong to (by Defender device id)
      Get-RaPerfFilterFunction             Filter-ObjectsByColumn, lifted out of Invoke-RiskAnalysis.ps1 (it cannot be dot-sourced)

    Synthetic data only: no tenant, no customer value.
#>

function Import-RaPerfEngine {
    param([Parameter(Mandatory)][string]$SIRoot)
    $ra = Join-Path $SIRoot 'engine\risk-analysis\_shared'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ra 'RA-ExcelReport.ps1'), [ref]$null, [ref]$null)
    foreach ($n in 'New-RiskIndex', 'Get-RAColumnUnion') {
        . ([scriptblock]::Create(($ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }.GetNewClosure(), $true)).Extent.Text.Replace("function $n", "function global:$n")))
    }
    $main = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'), [ref]$null, [ref]$null)
    . ([scriptblock]::Create(($main.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Filter-ObjectsByColumn' }, $true)).Extent.Text.Replace('function Filter-ObjectsByColumn', 'function global:Filter-ObjectsByColumn')))
    $files = @(
        'engine\_shared\SI-AssetIdentity.ps1',
        'engine\data-model\SI-DataModelTemplates.ps1', 'engine\data-model\SI-Conditions.ps1', 'engine\data-model\SI-Classification.ps1', 'engine\data-model\SI-FindingTexts.ps1',
        'engine\risk-analysis\_shared\RA-RowShaping.ps1', 'engine\risk-analysis\_shared\RA-Exemptions.ps1',
        'engine\risk-analysis\_shared\RA-RiskIndexOrder.ps1', 'engine\risk-analysis\_shared\RA-RiskIndexSi.ps1', 'engine\risk-analysis\_shared\RA-FactorKeys.ps1',
        'engine\risk-analysis\_shared\RA-CiContext.ps1', 'engine\risk-analysis\_shared\RA-UnprofiledTier.ps1', 'engine\risk-analysis\_shared\RA-DefenderCveContext.ps1', 'engine\risk-analysis\_shared\RA-DefenderRecommendationContext.ps1',
        'engine\risk-analysis\_shared\RA-RecommendationExclusions.ps1', 'engine\risk-analysis\_shared\RA-AssetIdentityMap.ps1',
        'engine\risk-analysis\_shared\RA-RiskScore.ps1', 'engine\risk-analysis\_shared\RA-ParallelScore.ps1', 'engine\risk-analysis\_shared\RA-Findings.ps1', 'engine\risk-analysis\_shared\RA-ColumnFillGuard.ps1',
        'engine\risk-analysis\_shared\RA-SqlStream.ps1', 'engine\_shared\data-sql\SI-DataModel.ps1', 'engine\_shared\data-sql\SI-DataSql.ps1',
        'engine\_shared\data-sql\SI-DataSummary.ps1', 'engine\asset-trend\_shared\SI-TrendRollup.ps1', 'engine\_shared\SI-OutputScope.ps1')
    # dot-sourced into the CALLER's scope (Pester's BeforeAll / the bench), as the engine dot-sources them into its own
    $files | ForEach-Object { Join-Path $SIRoot $_ }
}

function New-RaPerfRandom { param([int]$Seed = 638) [System.Random]::new($Seed) }

# the explained score's engine edit as text pairs (Get-RaPerfBeforeScripts applies them to the old copies)
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'risk-explain\RiskExplainEdits.ps1')

function New-RaPerfRawRows {
    <# n rows as Graph's advanced-hunting answer hands them over: Dictionary[string,object] per row, empty values absent. #>
    param([int]$Count = 1000, [int]$Assets = 1500, [int]$Cves = 2500, [int]$Seed = 638, [switch]$Messy)
    $rnd = New-RaPerfRandom $Seed
    $tiers = @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3')
    $sevs = @('Very High', 'High', 'Medium', 'Low')
    $vendors = @('microsoft', 'google', 'mozilla', 'adobe', 'oracle', '7-zip')
    $products = @('windows_server_2019', 'chrome', 'firefox', 'acrobat_reader', 'jre', '7-zip', 'edge_chromium', 'office')
    $out = New-Object 'System.Collections.Generic.List[object]' $Count
    for ($i = 0; $i -lt $Count; $i++) {
        $a = $rnd.Next(0, $Assets); $c = $rnd.Next(0, $Cves); $t = $a % 4
        $cve = 'CVE-{0}-{1}' -f (2015 + ($c % 11)), (10000 + $c)
        $exploit = ($c % 7 -eq 0); $kit = ($c % 23 -eq 0)
        $v = $vendors[$c % $vendors.Count]; $p = $products[$c % $products.Count]
        $d = New-Object 'System.Collections.Generic.Dictionary[string,object]'
        $d['SecurityDomain'] = 'Endpoint'; $d['Category'] = 'Vulnerabilities'; $d['Subcategory'] = 'CVEs (Missing Updates)'
        $d['ConfigurationName'] = 'Update vulnerable software'; $d['ConfigurationId'] = $cve
        $d['AssetName'] = ('host{0:d5}.corp.example' -f $a); $d['AssetId'] = ('ci-{0:d5}' -f $a); $d['AssetType'] = 'Endpoint'
        $d['Impact'] = [double](4 + ($c % 60) / 10.0); $d['SecuritySeverity'] = $sevs[$c % 4]
        $d['CriticalityTier'] = [long]$t; $d['CriticalityTierLevel'] = $tiers[$t]
        if ($a % 9 -eq 0) { $d['cmdbId'] = ('cmdb-{0}' -f ($a % 40)); $d['cmdbName'] = ('Service {0}' -f ($a % 40)); $d['cmdbCriticality'] = @('High', 'Medium', 'Critical')[$a % 3]; $d['cmdbDataSensitivity'] = @('Restricted', 'Confidential', 'Internal')[$a % 3] }
        $d['RiskFactor_Consequence'] = [long]$(if ($exploit) { 1 } else { 0 })
        if ($exploit) { $d['RiskFactor_Consequence_Detailed'] = 'RemoteCodeExecutionRisk' }
        $rfp = New-Object System.Collections.Generic.List[string]
        if ($exploit -or $kit) { $rfp.Add('ExploitSignals') }
        if ($a % 5 -eq 0) { $rfp.Add('InternetExposed') }
        if ($a % 11 -eq 0) { $rfp.Add('UnsupportedOS') }
        $d['RiskFactor_Probability'] = [long]$rfp.Count
        if ($rfp.Count) { $d['RiskFactor_Probability_Detailed'] = ($rfp -join ';') }
        $ids = New-Object System.Collections.Generic.List[string]
        if ($a % 5 -eq 0) { $ids.Add('internet_exposed') }; if ($a % 11 -eq 0) { $ids.Add('unsupported_os') }
        if ($ids.Count) { $d['RiskFactorIds'] = ($ids -join ';') }
        if ($d.ContainsKey('cmdbCriticality')) { $d['RiskScore_Weight_Detailed'] = 'cmdbCriticality=' + $d['cmdbCriticality'] }
        $d['RiskScore_Weight_Factor'] = [long]100; $d['RiskFactor_Weight'] = [long]100
        $d['HasExploit'] = $exploit; $d['IsExploitVerified'] = ($c % 13 -eq 0); $d['IsInExploitKit'] = $kit; $d['IsZeroDay'] = ($c % 97 -eq 0)
        if ($c % 3) { $d['CVELastModified'] = ('2026-0{0}-1{1}T08:00:00Z' -f (1 + $c % 9), ($c % 10)) }
        $d['CVSSDesc'] = ('A remote code execution vulnerability exists in {0} {1} when it handles crafted input. See https://msrc.example.test/update-guide/vulnerability/{2} for details.' -f $v, $p, $cve)
        $d['SI_AffectedVendor'] = $v; $d['SI_AffectedProduct'] = $p; $d['SI_AffectedVersion'] = ('{0}.{1}.{2}' -f (1 + $c % 30), ($c % 10), ($c % 1000))
        if ($c % 4) { $d['SI_FixReference'] = ('KB{0}' -f (5000000 + $c)); $d['si_fix_recommended_update'] = ('KB{0}' -f (5000000 + $c)); $d['si_fix_recommended_update_id'] = [string](5000000 + $c) }
        $d['si_affected_software'] = ('{0} {1} ({2})' -f $p, $d['SI_AffectedVersion'], $v)
        $d['si_fix_remediation'] = $(if ($c % 4) { 'Install the security update KB{0} on the device.' -f (5000000 + $c) } else { 'Update {0} to a version that fixes {1}.' -f $d['si_affected_software'], $cve })
        $d['MdeDeviceId'] = ('{0:x40}' -f $a).Substring(0, 40)
        $d['si_reference_url'] = 'https://nvd.nist.gov/vuln/detail/' + $cve
        if ($c % 5) { $d['si_published'] = ('2025-{0:d2}-{1:d2}T00:00:00Z' -f (1 + $c % 12), (1 + $c % 27)); $d['si_epss'] = [double](($c % 1000) / 1000.0); $d['si_cvss_vector'] = $(if ($c % 2) { 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } else { 'CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H' }); $d['si_cve_supportability'] = 'Supported' }
        if ($c % 17 -eq 0) { $d['si_cve_tags'] = 'ZeroDay;NoSecurityUpdate' }
        if ($c % 6 -eq 0) { $d['si_eos_status'] = 'EOS Version'; $d['si_eos_date'] = '2024-10-08T00:00:00Z' }
        if ($c % 8 -eq 0) { $d['si_affected_path'] = ('C:\Program Files\{0}\{1}.exe;HKLM\SOFTWARE\{0}' -f $v, $p) }
        if ($Messy) {
            # the shapes real answers carry and the plain synthetic rows do not
            if ($i % 7 -eq 0) { $null = $d.Remove('CriticalityTier'); $null = $d.Remove('CriticalityTierLevel') }       # a device without a tier yet
            if ($i % 11 -eq 1) { $d['Impact'] = $null; $d['AssetType'] = '' }                                           # null and empty cells
            if ($i % 13 -eq 2) { $d['SI_AffectedVendor'] = [object[]]@($v, 'microsoft', $v); $d['SI_AffectedProduct'] = [object[]]@($p, '') }   # lists in cells
            if ($i % 17 -eq 3) { $d['CVSSDesc'] = ('x' * 9000) + ' https://example.test/' + $cve + ' ' + ('CVE-2024-1234 ' * 400) }      # very long text
            if ($i % 19 -eq 4) { $d['RiskFactor_Probability_Detailed'] = ' ; ExploitSignals ;; InternetExposed;Internet-Exposed; ' }
            if ($i % 23 -eq 5) { $d['MdeDeviceId'] = ([string]$d['MdeDeviceId']).ToUpperInvariant(); $d['AssetName'] = $null }
            if ($i % 29 -eq 6) { $d['si_published'] = [datetime]::new(2020, 1, 1, 0, 0, 0, [DateTimeKind]::Utc); $d['si_epss'] = [decimal]0.25 }
            if ($i % 31 -eq 7) { $d['RiskFactor_Weight'] = [long]13750; $d['RiskScore_Weight_Factor'] = [double]137.5; $d['RiskScore_Weight_Detailed'] = 'cmdbCriticality=High;si_environment=Production' }
            if ($i % 37 -eq 8) { $d['ConfigurationName'] = ''; $d['ConfigurationId'] = '' }                              # no finding key at all
            if ($i % 41 -eq 9) { $d['si_cve_tags'] = [object[]]@('ZeroDay', 'NoSecurityUpdate'); $d['si_affected_path'] = [object[]]@() }
        }
        $out.Add($d)
    }
    # a few exact duplicates (two joins inflate a row): the scoring keeps one
    for ($i = 0; $i -lt [Math]::Floor($Count / 200); $i++) { $out.Add($out[$i * 7]) }
    , $out.ToArray()
}

function New-RaPerfSummaryRows {
    <# Summary rows as a Summary report's query projects them (one row per group): the impacted assets as a list, as the
       name|id pairs (a list, JSON text, or a bare single pair), an issue list -- the shapes the engine handles. #>
    param([int]$Count = 200, [int]$Seed = 641)
    $rnd = New-RaPerfRandom $Seed
    $tiers = @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3')
    $sevs = @('Very High', 'High', 'Medium', 'Low')
    $out = New-Object 'System.Collections.Generic.List[object]'
    for ($i = 0; $i -lt $Count; $i++) {
        $t = $i % 4; $n = 1 + $rnd.Next(0, 6)
        $names = @(for ($k = 0; $k -lt $n; $k++) { 'host{0:d5}.corp.example' -f $rnd.Next(0, 300) })
        $pairs = @($names | ForEach-Object { "$_|ci-$($_.Substring(4, 5))" })
        $pairShape = switch ($i % 3) { 0 { [object[]]$pairs } 1 { ConvertTo-Json -InputObject @($pairs) -Compress } default { [string]$pairs[0] } }
        $row = [ordered]@{ SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs (Missing Updates)'; ConfigurationName = ('Update vulnerable software {0}' -f ($i % 17))
            ConfigurationId = ('CVE-2025-{0}' -f (20000 + ($i % 40))); Impact = [double](5 + ($i % 5)); SecuritySeverity = $sevs[$i % 4]; CriticalityTier = [long]$t; CriticalityTierLevel = $tiers[$t]
            cmdbId = $(if ($i % 5 -eq 0) { 'cmdb-1' } else { '' }); cmdbName = $(if ($i % 5 -eq 0) { 'Service 1' } else { '' }); cmdbCriticality = ''; cmdbDataSensitivity = $(if ($i % 7 -eq 0) { 'Restricted' } else { '' })
            RiskFactor_Consequence = 1; RiskFactor_Consequence_Detailed = 'RemoteCodeExecutionRisk'; RiskFactor_Probability = 1; RiskFactor_Probability_Detailed = 'ExploitSignals;InternetExposed'
            RiskFactorIds = ''; RiskScore_Weight_Detailed = ''; RiskScore_Weight_Factor = 100; RiskFactor_Weight = 100
            ImpactedAssetsList = [object[]]$names; ImpactedAssetPairs = $pairShape; IssueList = [object[]]@('CVE-1')
            MoreDetails = ('CVE-2025-{0} => https://nvd.nist.gov/vuln/detail/CVE-2025-{0}' -f (20000 + ($i % 40)))
            si_affected_software = 'chrome 1.2 (google)'; si_epss = 0.5; si_published = '2026-01-01T00:00:00Z' }
        if ($i % 4 -eq 0) { $row['ImpactedAssetCount'] = [long]$names.Count }
        if ($i % 6 -eq 0) { $row['Categories'] = 'Credential Access, Lateral Movement' }
        $out.Add([pscustomobject]$row)
    }
    , $out.ToArray()
}

function New-RaPerfCis {
    <# The CIs of the assets: si_link_mde = the device id the rows carry; tier, class, OS and risk factors as the CI build writes them. #>
    param([int]$Assets = 1500, [switch]$FromSql)
    $out = New-Object 'System.Collections.Generic.List[object]'
    for ($a = 0; $a -lt $Assets; $a++) {
        $rf = '[]'
        if ($a % 5 -eq 0) { $rf = '[{"id":"internet_exposed","axis":"probability","impact":4,"stage":"production"}]' }
        $out.Add([pscustomobject]@{ si_ci_id = ('ci-{0:d5}' -f $a); si_asset_name = ('host{0:d5}.corp.example' -f $a); si_tier = [string]($a % 4); si_class = 'device'
            si_os_platform = $(if ($a % 3) { 'Windows11' } else { 'WindowsServer2019' }); si_device_category = $(if ($a % 3) { 'Endpoint' } else { 'Server' })
            si_link_mde = ('{0:x40}' -f $a).Substring(0, 40); si_risk_factors = $rf; si_criticality_factor = $(if ($a % 9 -eq 0) { '1.25' } else { '' }) })
    }
    if (-not $FromSql) { return , $out.ToArray() }
    # as the stream reads them from sidata.Ci (Get-RAStreamCiIndex): the CI document stored as JSON and read back -- the
    # risk factors and linked objects are then LISTS OF OBJECTS, not JSON text; the stale mark and context fields added
    $sql = New-Object 'System.Collections.Generic.List[object]'
    foreach ($c in $out) {
        $doc = [ordered]@{}
        foreach ($p in $c.PSObject.Properties) { $doc[$p.Name] = $p.Value }
        $doc['si_risk_factors'] = $(if ([string]$c.si_risk_factors -ne '[]') { [object[]]@([pscustomobject]@{ id = 'internet_exposed'; axis = 'probability'; impact = 4; stage = 'production'; tokens = [object[]]@('Internet-Exposed', 'InternetExposureSignal') }) } else { [object[]]@() })
        $doc['si_linked_objects'] = [object[]]@([pscustomobject]@{ id = $c.si_link_mde; type = 'mde' }, [pscustomobject]@{ id = ('eg:dev:' + $c.si_link_mde); type = 'eg' })
        $doc['si_cmdb_id'] = $(if ($c.si_tier -eq '0') { 'cmdb-7' } else { '' }); $doc['si_cmdb_name'] = $(if ($c.si_tier -eq '0') { 'Payroll' } else { '' })
        $doc['si_environment'] = 'Production'; $doc['si_backup_protected'] = $true; $doc['si_pending_critical_patches'] = [long]3
        $j = ConvertTo-RAStreamJson -Row ([pscustomobject]$doc)
        $back = ConvertFrom-RAStreamJson -Json $j.Json
        Add-Member -InputObject $back -NotePropertyName 'si_stale_' -NotePropertyValue 'false' -Force
        $sql.Add($back)
    }
    , $sql.ToArray()
}

function Get-RaPerfBeforeScripts {
    <#
        The Risk Analysis files AS THEY WERE before the per-row performance change (tests\fixtures\ra-perf\before\*.before.txt,
        copied verbatim from the engine), as script blocks to dot-source over the current ones -- so the SAME slice can be
        run through the old code and the new code in one process and every output compared. $PSScriptRoot in them is
        replaced by the folder the file lived in (their own dot-sources and data paths resolve as in the engine).
    #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $map = [ordered]@{
        'RA-RowShaping.ps1' = 'engine\risk-analysis\_shared'; 'RA-RiskIndexSi.ps1' = 'engine\risk-analysis\_shared'; 'RA-FactorKeys.ps1' = 'engine\risk-analysis\_shared'
        'RA-CiContext.ps1' = 'engine\risk-analysis\_shared'; 'RA-RiskScore.ps1' = 'engine\risk-analysis\_shared'; 'RA-Findings.ps1' = 'engine\risk-analysis\_shared'
        'RA-SqlStream.ps1' = 'engine\risk-analysis\_shared'; 'RA-DefenderCveContext.ps1' = 'engine\risk-analysis\_shared'
        'RA-DefenderRecommendationContext.ps1' = 'engine\risk-analysis\_shared'; 'RA-UnprofiledTier.ps1' = 'engine\risk-analysis\_shared'; 'SI-Classification.ps1' = 'engine\data-model'; 'SI-DataModel.ps1' = 'engine\_shared\data-sql'
    }
    $dir = Join-Path $PSScriptRoot 'before'
    # FEATURES THAT CAME AFTER the speed-up (the comparison is about speed, not about them): the same edit applied to the old
    # copy, so the old and the new code make the same rows. #772 the ServiceNow sub-CI: a finding target reads the one before
    # it (si_servicenow_subci reads si_component), it is a forced output column next to the component, and the finding carries it.
    $later = @{
        'SI-Classification.ps1' = @(@("else { `$out[`$t.Field] = `$t.Fallback; `$rules[`$t.Field] = 'fallback' }",
                                        "else { `$out[`$t.Field] = `$t.Fallback; `$rules[`$t.Field] = 'fallback' }`n        if (`$Item -is [System.Collections.IDictionary]) { `$Item[`$t.Field] = `$out[`$t.Field] }"),
                                    # #772 the OS family of a row (Set-SIRaRowOsFamily is the current file's; the old copy does not redefine it)
                                    @("foreach (`$k in @(`$vals.Keys)) { if (`$k -ne '_rules') { `$Row[`$k] = `$vals[`$k] } }",
                                      "foreach (`$k in @(`$vals.Keys)) { if (`$k -ne '_rules') { `$Row[`$k] = `$vals[`$k] } }`n        `$null = Set-SIRaRowOsFamily -Row `$Row -Index `$Index"),
                                    # #772 the patch cycle's facts on the item (Add-SIPatchCycleFacts is the current file's)
                                    @("`$item = ConvertTo-SIFindingClassificationItem -Row `$Row -WithRow:([bool]`$Index.HasSourcePath)", "`$item = ConvertTo-SIFindingClassificationItem -Row `$Row -WithRow:([bool]`$Index.HasSourcePath)`n        `$null = Add-SIPatchCycleFacts -Item `$item -Row `$Row"))
        'RA-RiskScore.ps1'      = @(@("'RiskScoreKPI','si_component') {", "'RiskScoreKPI','si_component','si_servicenow_subci','si_patch_cycle') {"),
                                    @("(`$forceCol -ne 'si_component' -or `$tmp2.Contains(`$forceCol))", "((`$forceCol -notin 'si_component', 'si_servicenow_subci', 'si_patch_cycle') -or `$tmp2.Contains(`$forceCol))"))
        'RA-Findings.ps1'       = @(@("`$comp = `$cp }", "`$comp = `$cp; `$subciFromComp = `$true }`n            `$sc = [string](& `$g `$r 'si_servicenow_subci'); if (`$sc -and (-not `$subci -or `$subciFromComp)) { `$subci = `$sc }; `$subciFromComp = `$false`n            `$pc = [string](& `$g `$r 'si_patch_cycle'); if (`$pc -and (Get-SIPatchCycleRank `$pc) -gt (Get-SIPatchCycleRank `$patch)) { `$patch = `$pc }`n            `$cvp = [string](& `$g `$r 'si_cve_published'); if (`$cvp -and (-not `$cvePub -or [string]::CompareOrdinal(`$cvp, `$cvePub) -lt 0)) { `$cvePub = `$cvp }`n            `$frd = [string](& `$g `$r 'si_fix_release_date'); if (`$frd -and (-not `$fixRel -or [string]::CompareOrdinal(`$frd, `$fixRel) -gt 0)) { `$fixRel = `$frd }"),
                                    @("if (`$comp) { `$o['si_component'] = `$comp }", "if (`$comp) { `$o['si_component'] = `$comp }`n        if (`$subci) { `$o['si_servicenow_subci'] = `$subci }`n        if (`$patch) { `$o['si_patch_cycle'] = `$patch }`n        if (`$cvePub) { `$o['si_cve_published'] = `$cvePub }`n        if (`$fixRel) { `$o['si_fix_release_date'] = `$fixRel }"))
    }
    foreach ($k in $map.Keys) {
        $t = [IO.File]::ReadAllText((Join-Path $dir ($k + '.before.txt')))
        if ($later.ContainsKey($k)) {
            foreach ($pair in $later[$k]) {
                if (-not $t.Contains($pair[0])) { throw ("the old copy of {0} no longer carries the text a later feature is applied to: {1}" -f $k, $pair[0]) }
                $t = $t.Replace($pair[0], $pair[1])
            }
            if ($k -eq 'RA-Findings.ps1') { $t = $t.Replace("`$comp = ''; ", "`$comp = ''; `$subci = ''; `$subciFromComp = `$false; `$patch = ''; `$cvePub = ''; `$fixRel = ''; ") }
        }
        # #910 the explained score (four added columns): the same pairs as the engine edit (tests\fixtures\risk-explain)
        if ($k -in 'RA-FactorKeys.ps1', 'RA-RiskScore.ps1') { $t = Invoke-RiskExplainEdit -Text $t -File $k }
        $root = (Join-Path $SIRoot $map[$k]).Replace("'", "''")
        [scriptblock]::Create($t.Replace('$PSScriptRoot', "'$root'"))
    }
    # Get-RAColumnUnion as it was (RA-ExcelReport.ps1 is loaded for this one function)
    $xa = [System.Management.Automation.Language.Parser]::ParseInput([IO.File]::ReadAllText((Join-Path $dir 'RA-ExcelReport.ps1.before.txt')), [ref]$null, [ref]$null)
    [scriptblock]::Create(($xa.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Get-RAColumnUnion' }, $true)).Extent.Text.Replace('function Get-RAColumnUnion', 'function global:Get-RAColumnUnion'))
    # Filter-ObjectsByColumn lives in Invoke-RiskAnalysis.ps1
    [scriptblock]::Create([IO.File]::ReadAllText((Join-Path $dir 'Filter-ObjectsByColumn.ps1.before.txt')).Replace('function Filter-ObjectsByColumn', 'function global:Filter-ObjectsByColumn'))
}

function Get-RaPerfValueText {
    <# PURE. One cell as text that tells types apart (the comparison of the old and new output): type + invariant value; lists item by item. #>
    param($Value)
    if ($null -eq $Value) { return '~' }
    if ($Value -is [System.Management.Automation.PSObject] -and $Value -isnot [System.Management.Automation.PSCustomObject]) { $Value = $Value.PSObject.BaseObject }
    if ($Value -is [string]) { return 's:' + $Value }
    if ($Value -is [double] -or $Value -is [single]) { return ('{0}:{1}' -f $Value.GetType().Name, $Value.ToString('R', [Globalization.CultureInfo]::InvariantCulture)) }
    if ($Value -is [System.IFormattable] -and $Value -isnot [System.Collections.IEnumerable]) { return ('{0}:{1}' -f $Value.GetType().Name, $Value.ToString($null, [Globalization.CultureInfo]::InvariantCulture)) }
    if ($Value -is [bool]) { return 'b:' + $Value }
    if ($Value -is [System.Collections.IDictionary]) { return 'D{' + ((@($Value.Keys) | ForEach-Object { [string]$_ + '=' + (Get-RaPerfValueText $Value[$_]) }) -join ',') + '}' }
    if ($Value -is [System.Collections.IEnumerable]) { $l = New-Object System.Collections.Generic.List[string]; foreach ($e in $Value) { $l.Add((Get-RaPerfValueText $e)) }; return ('{0}[{1}]' -f $Value.GetType().Name, ($l -join ',')) }
    if ($Value -is [System.Management.Automation.PSCustomObject] -or $Value -is [System.Management.Automation.PSObject]) { return 'O{' + ((@($Value.PSObject.Properties) | ForEach-Object { $_.Name + '=' + (Get-RaPerfValueText $_.Value) }) -join ',') + '}' }
    return ('{0}:{1}' -f $Value.GetType().Name, [string]$Value)
}

function Get-RaPerfRowText {
    <# PURE. One row: every column in its order, its name, its type and its value. #>
    param($Row)
    $l = New-Object System.Collections.Generic.List[string]
    foreach ($p in $Row.PSObject.Properties) { $l.Add($p.Name + '=' + (Get-RaPerfValueText $p.Value)) }
    $l -join [char]31
}

function Invoke-RaPerfSlice {
    <#
        ONE QUERY SLICE through the Risk Analysis steps, in the order Invoke-RAReportRows takes them (Invoke-RiskAnalysis.ps1):
        result conversion, the filters, the CI / Defender context, scoring, the trace identity and column shaping, and the
        SQL write (the seam stubbed: every statement's JSON is kept). Returns @{ Times (stage -> seconds); Rows (per stage
        count); Scored; Shaped; Items (the JSON of every row written) }.
    #>
    param([Parameter(Mandatory)][object[]]$Raw, [Parameter(Mandatory)][object[]]$Cis, [Parameter(Mandatory)]$RiskIndex,
          [string]$ReportName = 'Device_Missing_CVEs_Detailed', [ValidateSet('legacy', 'ci')][string]$Mode = 'legacy', [switch]$Say)
    $ProgressPreference = 'SilentlyContinue'
    $opo = Get-RaPerfOutputOrder
    $times = [ordered]@{}; $counts = [ordered]@{}
    $sw = [Diagnostics.Stopwatch]::new()
    $sw.Restart()
    if ($Say) { Write-Host "STAGE conversion" }
    $rows = ConvertTo-PSObjectDeep $Raw -StripOData -CastPrimitiveArrays
    $times['conversion'] = $sw.Elapsed.TotalSeconds; $counts['conversion'] = @($rows).Count

    $sw.Restart()
    if ($Say) { Write-Host "STAGE filters" }
    $rows = @(Set-RAExemptionMarks -Rows $rows -ReportName $ReportName -FindingColumns @('ConfigurationId'))
    $st = @{}; $rows = @(Set-RAUnprofiledTiers -Rows $rows -ReportName $ReportName -LevelColumn 'CriticalityTierLevel' -Stats $st)
    $rows = @(Filter-ObjectsByColumn -InputObject @($rows) -ColumnToFilter 'CriticalityTierLevel' -InScopeData @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3') -CaseInsensitive -IncludeBlank:$true -FilterName 'CriticalityTierLevel')
    $rows = @(Filter-ObjectsByColumn -InputObject @($rows) -ColumnToFilter 'SecuritySeverity' -InScopeData @('Very High', 'High', 'Medium-High', 'Medium', 'Low') -CaseInsensitive -IncludeBlank:$true -FilterName 'SecuritySeverity')
    $times['filters'] = $sw.Elapsed.TotalSeconds; $counts['filters'] = $rows.Count

    $ciIdx = New-RACiIndex -Cis $Cis
    $cveIx = @{}; foreach ($r in $rows) { $k = ([string]$r.ConfigurationId).ToUpperInvariant(); if (-not $cveIx.ContainsKey($k) -and ((($k.Length + [int]$k[$k.Length - 1]) % 3) -eq 0)) { $cveIx[$k] = [ordered]@{ si_exploit_verified = ($k.Length % 2 -eq 0); si_in_exploit_kit = $false; si_exploit_types = 'Remote'; si_exposed_devices = 3 } } }
    $recIx = @{}; foreach ($v in 'microsoft', 'google', 'mozilla') { foreach ($p in 'chrome', 'firefox', 'office') { $recIx["va|$v|$p"] = [ordered]@{ si_exposure_impact = 2.5; si_active_alert = $false } } }
    $sw.Restart()
    if ($Say) { Write-Host "STAGE context" }
    $rows = Add-RACiContext -Rows @($rows) -FactorSet @() -Index $ciIdx -Mode $Mode
    $times['  context:ci'] = $sw.Elapsed.TotalSeconds; $counts['  context:ci'] = $rows.Count
    $rows = Add-RADefenderCveContext -Rows @($rows) -Index @{ Index = $cveIx; Complete = $true } -Log { param($m) }
    $rows = Add-RADefenderRecommendationContext -Rows @($rows) -Index @{ Index = $recIx; Complete = $true } -Log { param($m) }
    $times['context'] = $sw.Elapsed.TotalSeconds; $counts['context'] = @($rows).Count
    $ctxCopy = @(foreach ($r in @($rows)) { $r.PSObject.Copy() })

    $sw.Restart()
    if ($Say) { Write-Host "STAGE scoring" }
    $scored = Calculate-RiskScore -Rows @($rows) -RiskIndex $RiskIndex -SecurityDomain 'Endpoint' -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
        -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -OutputPropertyOrder $opo `
        -SortBy @('RiskScoreTotal_Weighted') -Descending -ReportName $ReportName
    $times['scoring'] = $sw.Elapsed.TotalSeconds; $counts['scoring'] = @($scored).Count

    # the steps after scoring (Invoke-RAReportRows): the run's stamp, the trace identity, the column union, the shaping
    $sw.Restart()
    if ($Say) { Write-Host "STAGE shaping" }
    foreach ($row in @($scored)) {
        Add-Member -InputObject $row -NotePropertyName 'CollectionTime' -NotePropertyValue '2026-10-14T00:00:00.000Z' -Force
        Add-Member -InputObject $row -NotePropertyName 'SolutionVersion' -NotePropertyValue '3.0.0' -Force
    }
    $sub = [ordered]@{}; $sub['stamp'] = $sw.Elapsed.TotalSeconds
    Set-RATraceIdentity -Rows @($scored) -IsDetailed $true
    $sub['trace'] = $sw.Elapsed.TotalSeconds
    $un = Get-RAColumnUnion -Rows $scored
    $sub['union'] = $sw.Elapsed.TotalSeconds
    $trace = @('CollectionTime', 'SolutionVersion', 'TraceName', 'TraceID')
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($c in $opo) { $cols.Add($c) }
    foreach ($c in $un) { if (-not $cols.Contains($c) -and $c -notin $trace) { $cols.Add($c) } }
    foreach ($c in $trace) { $cols.Add($c) }
    $shaped = $scored | Select-Object -Property $cols.ToArray()
    $sub['select'] = $sw.Elapsed.TotalSeconds
    $shaped = $shaped | ForEach-Object { if ($_.RiskScoreTotal -isnot [double]) { $_.RiskScoreTotal = ConvertTo-RADouble -Value $_.RiskScoreTotal -Default 0.0 }; $_ }
    $sub['double'] = $sw.Elapsed.TotalSeconds
    $times['shaping'] = $sw.Elapsed.TotalSeconds; $counts['shaping'] = @($shaped).Count
    $prev = 0.0; foreach ($k in $sub.Keys) { $times['  shaping:' + $k] = $sub[$k] - $prev; $counts['  shaping:' + $k] = $counts['scoring']; $prev = $sub[$k] }
    $prev = 0.0; foreach ($k in $sub.Keys) { $times['  shaping:' + $k] = $sub[$k] - $prev; $counts['  shaping:' + $k] = $counts['scoring']; $prev = $sub[$k] }

    $items = New-Object System.Collections.Generic.List[string]
    $seam = { param($Sql, $Params, $Mode)
        if ($Params -and $Params.ContainsKey('j')) { $j = [string]$Params['j']; $items.Add($j); return [regex]::Matches($j, '"RaReport":').Count }
        if ($Sql -match 'COL_LENGTH') { return 1 }
        if ($Sql -match 'OUTPUT inserted.CollectionId') { return 7 }
        0 }.GetNewClosure()
    $stream = New-RAStream -Invoke $seam -Grain Detailed -CollectionTime ([datetime]::new(2026, 10, 14, 0, 0, 0, [DateTimeKind]::Utc)) -Log { param($l, $m) }
    $null = Start-RAStreamReport -Stream $stream -ReportName $ReportName -Staged $false
    $sw.Restart()
    if ($Say) { Write-Host "STAGE sql write" }
    Add-RAStreamColumns -Stream $stream -Columns $cols.ToArray()
    $view = Select-RAReportRows -Rows @($shaped)
    $set = New-Object 'System.Collections.Generic.HashSet[object]' ([System.Collections.Generic.ReferenceEqualityComparer]::Instance)
    foreach ($v in @($view.Rows)) { [void]$set.Add($v) }
    $written = Write-RAStreamRows -Stream $stream -Rows @($shaped) -Bucket '9/24' -InView $set -IsDetailedShape $true -ConfigurationIdInputName ConfigurationId `
        -SortColumn 'RiskScoreTotal_Weighted' -FallbackSortColumn 'RiskScoreTotal' -Dedup $true -Equivalence $null
    $times['sql write'] = $sw.Elapsed.TotalSeconds; $counts['sql write'] = [long]$written

    [pscustomobject]@{ Times = $times; Rows = $counts; Context = $ctxCopy; Scored = @($scored); Shaped = @($shaped); Items = $items.ToArray() }
}

$script:RaPerfOutputOrder = @('SecurityDomain', 'Category', 'Subcategory', 'ConfigurationName', 'ConfigurationId', 'AssetName', 'AssetId', 'AssetType', 'Impact', 'SecuritySeverity',
    'CriticalityTier', 'CriticalityTierLevel', 'RiskFactor_Consequence_Detailed', 'RiskFactor_Consequence', 'RiskFactor_Probability_Detailed', 'RiskFactorIds', 'RiskFactor_Probability',
    'RiskConsequenceScore', 'RiskProbabilityScore', 'RiskScoreTotal', 'RiskScore_Weight_Detailed', 'RiskScore_Weight_Factor', 'RiskScoreTotal_Weighted', 'RiskRating',
    'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity', 'MoreDetails', 'AssetDetectedInReportName')
function Get-RaPerfOutputOrder { , $script:RaPerfOutputOrder }
