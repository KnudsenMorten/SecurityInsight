#Requires -Version 7.0
<#
    Risk Analysis -- the steps of ONE QUERY SLICE between the column union and the database write: the shared fixture of
    tests\pester\SIv3-RaShapingSpeed.Tests.ps1 and of the vendor bench tests\fixtures\ra-perf\shaping-bench.ps1.

    Measured live 2026-10-16 (a 4-core container, Device_Missing_CVEs_Detailed, 64 slices of 14,000-18,000 rows): about
    4.5 minutes of every 10-minute slice passed with no line at all between "[columns] ... recovered that are absent from
    row 1" and "prepared for the database". This fixture rebuilds that slice offline, so the engine's own steps can be
    timed one by one:

      New-RaShapingRows -Count n          n scored rows shaped like that report's: ~79 columns on row 1 (the report's own
                                          columns, the score columns, the CI's si_* columns), 14 more that row 1 does not
                                          carry and later rows do (a Graph answer leaves an empty value out), mixed values
                                          (text, numbers, true/false, lists, dates, nulls) -- deterministic (seeded)
      Get-RaShapingColumns -Rows r        the report's column list, built the way Invoke-RAReportRows builds it
      ConvertTo-RaShapedRows              the engine's shaping, as Invoke-RAReportRows does it (Select-Object -Property,
                                          then the risk score made a number)
      Invoke-RaShapingStages              the steps in the engine's order, each timed: shaping, the column-fill
                                          measurement, the report's columns + the view, the database write (the SQL seam
                                          stubbed: every statement's JSON is kept; -SqlDelaySeconds makes the
                                          remove-before-write statement take that long, as a slow database would)

    Measured with it on the test VM (14,000 rows x 93 columns): every PowerShell step together takes seconds; a script
    loop is SLOWER than Select-Object (compiled) for the shaping. The minutes were the database's remove-before-write
    statement (Get-RAStreamDeleteBucketSql), measured with tests\fixtures\ra-perf\bucket-delete-bench.ps1.

    Synthetic data only: no tenant, no customer value.
#>
function New-RaShapingRows {
    <# n scored rows as Calculate-RiskScore hands them on ([pscustomobject] from an ordered dictionary). #>
    param([int]$Count = 14000, [int]$Assets = 2400, [int]$Seed = 1416)
    $rnd = [System.Random]::new($Seed)
    $tiers = @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3')
    $sevs = @('Very High', 'High', 'Medium', 'Low')
    $vendors = @('microsoft', 'google', 'mozilla', 'adobe', 'oracle', '7-zip')
    $products = @('windows_server_2019', 'chrome', 'firefox', 'acrobat_reader', 'jre', '7-zip', 'edge_chromium', 'office')
    $out = [System.Collections.Generic.List[object]]::new($Count)
    for ($i = 0; $i -lt $Count; $i++) {
        $a = $rnd.Next(0, $Assets); $c = $rnd.Next(0, 4000); $t = $a % 4
        $cve = 'CVE-{0}-{1}' -f (2015 + ($c % 11)), (10000 + $c)
        $v = $vendors[$c % $vendors.Count]; $p = $products[$c % $products.Count]
        $exploit = ($c % 7 -eq 0)
        $h = [ordered]@{}
        # the report's own columns (its OutputPropertyOrder)
        $h['SecurityDomain'] = 'Endpoint'; $h['Category'] = 'Vulnerabilities'; $h['Subcategory'] = 'CVEs (Missing Updates)'
        $h['ConfigurationName'] = 'Update vulnerable software'; $h['ConfigurationId'] = $cve
        $h['AssetName'] = ('host{0:d5}.corp.example' -f $a); $h['AssetId'] = ('ci-{0:d5}' -f $a); $h['AssetType'] = 'Endpoint'; $h['AssetIdSource'] = 'SI asset id'
        $h['Impact'] = [double](4 + ($c % 60) / 10.0); $h['SecuritySeverity'] = $sevs[$c % 4]
        $h['CriticalityTier'] = [long]$t; $h['CriticalityTierLevel'] = $tiers[$t]
        $h['RiskFactor_Consequence_Detailed'] = $(if ($exploit) { 'RemoteCodeExecutionRisk' } else { '' })
        $h['RiskFactor_Consequence'] = [long]$(if ($exploit) { 1 } else { 0 })
        $h['RiskFactor_Probability_Detailed'] = $(if ($a % 5 -eq 0) { 'ExploitSignals;InternetExposed' } else { 'ExploitSignals' })
        $h['RiskFactorIds'] = $(if ($a % 5 -eq 0) { 'internet_exposed' } else { '' })
        $h['RiskFactor_Probability'] = [long]$(if ($a % 5 -eq 0) { 2 } else { 1 })
        $h['RiskConsequenceScore'] = [double](3 + ($c % 5)); $h['RiskProbabilityScore'] = [double](2 + ($a % 4))
        # the total score: mostly a number, sometimes text (as some reports hand it on) -- the shaping makes it a number
        $h['RiskScoreTotal'] = $(switch ($i % 9) { 0 { [string]('{0}.5' -f (10 + $c % 40)) } 1 { [long](10 + $c % 40) } 2 { '' } default { [double](10.25 + ($c % 40)) } })
        $h['RiskScore_Weight_Detailed'] = $(if ($a % 9 -eq 0) { 'cmdbCriticality=High' } else { '' })
        $h['RiskScore_Weight_Factor'] = [double]$(if ($a % 9 -eq 0) { 125 } else { 100 })
        $h['RiskScoreTotal_Weighted'] = [double](12.5 + ($c % 40))
        $h['RiskRating'] = @('Critical', 'High', 'Medium', 'Low')[$c % 4]
        $h['cmdbId'] = $(if ($a % 9 -eq 0) { 'cmdb-{0}' -f ($a % 40) } else { '' }); $h['cmdbName'] = $(if ($a % 9 -eq 0) { 'Service {0}' -f ($a % 40) } else { '' })
        $h['cmdbCriticality'] = ''; $h['cmdbDataSensitivity'] = ''
        $h['MoreDetails'] = ('{0} => https://nvd.nist.gov/vuln/detail/{0}' -f $cve) + $(if ($c % 3 -eq 0) { "`r`n" + ('Exploit available; ' * 20) } else { '' })
        $h['AssetDetectedInReportName'] = 'Device_Missing_CVEs_Detailed'
        $h['HasExploit'] = $exploit; $h['IsExploitVerified'] = ($c % 13 -eq 0); $h['IsInExploitKit'] = ($c % 23 -eq 0); $h['IsZeroDay'] = ($c % 97 -eq 0)
        $h['CVSSDesc'] = ('A remote code execution vulnerability exists in {0} {1} when it handles crafted input. See https://msrc.example.test/{2}.' -f $v, $p, $cve)
        $h['MdeDeviceId'] = ('{0:x40}' -f $a).Substring(0, 40)
        $h['SI_AssetId'] = $h['AssetId']; $h['SI_AssetName'] = $h['AssetName']
        $h['SI_AffectedVendor'] = $(if ($i % 13 -eq 2) { [object[]]@($v, 'microsoft') } else { $v }); $h['SI_AffectedProduct'] = $p
        $h['SI_AffectedVersion'] = ('{0}.{1}.{2}' -f (1 + $c % 30), ($c % 10), ($c % 1000))
        $h['si_affected_software'] = ('{0} {1} ({2})' -f $p, $h['SI_AffectedVersion'], $v)
        $h['si_fix_remediation'] = ('Install the security update KB{0} on the device.' -f (5000000 + $c))
        $h['si_reference_url'] = 'https://nvd.nist.gov/vuln/detail/' + $cve
        # the CI's columns (the si_* context every Detailed row carries)
        $h['si_ci_id'] = $h['AssetId']; $h['si_asset_name'] = $h['AssetName']; $h['si_tier'] = [string]$t; $h['si_class'] = 'device'
        $h['si_os_platform'] = $(if ($a % 3) { 'Windows11' } else { 'WindowsServer2019' }); $h['si_device_category'] = $(if ($a % 3) { 'Endpoint' } else { 'Server' })
        $h['si_environment'] = 'Production'; $h['si_backup_protected'] = ($a % 2 -eq 0); $h['si_pending_critical_patches'] = [long]($a % 6)
        $h['si_criticality_factor'] = $(if ($a % 9 -eq 0) { '1.25' } else { '' }); $h['si_internet_facing'] = ($a % 5 -eq 0)
        $h['si_owner'] = ('owner{0}@corp.example' -f ($a % 50)); $h['si_department'] = ('Dept {0}' -f ($a % 12)); $h['si_location'] = ('Site {0}' -f ($a % 7))
        $h['si_last_seen'] = [datetime]::new(2026, 10, 1 + ($a % 14), 8, 0, 0, [DateTimeKind]::Utc)
        $h['si_first_seen'] = '2025-01-01T00:00:00Z'; $h['si_stale_'] = 'false'; $h['si_link_mde'] = $h['MdeDeviceId']
        $h['si_link_entra'] = ('{0:x8}-0000-0000-0000-{0:x12}' -f $a); $h['si_link_intune'] = ''; $h['si_cmdb_id'] = $h['cmdbId']; $h['si_cmdb_name'] = $h['cmdbName']
        $h['si_risk_factors'] = $(if ($a % 5 -eq 0) { [object[]]@('internet_exposed') } else { [object[]]@() })
        $h['si_exposure_score'] = [double](($a % 100) / 10.0); $h['si_onboarding_status'] = 'Onboarded'; $h['si_health_status'] = 'Active'
        $h['si_os_version'] = ('10.0.{0}' -f (19000 + $a % 3000)); $h['si_domain'] = 'corp.example'; $h['si_ip_address'] = ('10.{0}.{1}.{2}' -f ($a % 250), ($a % 200), ($a % 100))
        $h['ReportName'] = 'Device_Missing_CVEs_Detailed'
        $h['CollectionTime'] = '2026-10-16T05:00:00.000Z'; $h['SolutionVersion'] = '3.0.0.202610152242'
        $h['TraceName'] = ('Device_Missing_CVEs_Detailed-{0}-{1}-SI' -f $cve, $h['AssetId']); $h['TraceID'] = ('{0:x32}' -f ($i * 7919 + $c))
        # 14 columns row 1 does NOT carry (an empty value is left out of a Graph answer, so the first row may lack them)
        if ($i -gt 0) {
            if ($c % 3) { $h['si_published'] = ('2025-{0:d2}-{1:d2}T00:00:00Z' -f (1 + $c % 12), (1 + $c % 27)) }
            if ($c % 5) { $h['si_epss'] = [double](($c % 1000) / 1000.0) }
            if ($c % 2) { $h['si_cvss_vector'] = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }
            if ($c % 4) { $h['si_cve_supportability'] = 'Supported' }
            if ($c % 17 -eq 0) { $h['si_cve_tags'] = [object[]]@('ZeroDay', 'NoSecurityUpdate') }
            if ($c % 6 -eq 0) { $h['si_eos_status'] = 'EOS Version'; $h['si_eos_date'] = '2024-10-08T00:00:00Z' }
            if ($c % 8 -eq 0) { $h['si_affected_path'] = ('C:\Program Files\{0}\{1}.exe' -f $v, $p) }
            if ($c % 4) { $h['SI_FixReference'] = ('KB{0}' -f (5000000 + $c)); $h['si_fix_recommended_update'] = ('KB{0}' -f (5000000 + $c)); $h['si_fix_recommended_update_id'] = [string](5000000 + $c) }
            if ($c % 3 -eq 1) { $h['CVELastModified'] = ('2026-0{0}-1{1}T08:00:00Z' -f (1 + $c % 9), ($c % 10)) }
            if ($c % 10 -eq 0) { $h['SI_ExemptionId'] = [string](1000 + $c % 50); $h['SI_ExemptedUntil'] = '2027-01-01T00:00:00Z' }
        }
        $out.Add([pscustomobject]$h)
    }
    , $out.ToArray()
}

$script:RaShapingOutputOrder = @('SecurityDomain', 'Category', 'Subcategory', 'ConfigurationName', 'ConfigurationId', 'AssetName', 'AssetId', 'AssetType', 'Impact', 'SecuritySeverity',
    'CriticalityTier', 'CriticalityTierLevel', 'RiskFactor_Consequence_Detailed', 'RiskFactor_Consequence', 'RiskFactor_Probability_Detailed', 'RiskFactorIds', 'RiskFactor_Probability',
    'RiskConsequenceScore', 'RiskProbabilityScore', 'RiskScoreTotal', 'RiskScore_Weight_Detailed', 'RiskScore_Weight_Factor', 'RiskScoreTotal_Weighted', 'RiskRating',
    'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity', 'MoreDetails', 'AssetDetectedInReportName')

function Get-RaShapingColumns {
    <# The report's columns, built the way Invoke-RAReportRows builds them: OutputPropertyOrder, the computed columns, the
       union of every row's columns, the weight columns after the total, the trace columns last, each name once. #>
    param([Parameter(Mandatory)][object[]]$Rows)
    $trace = @('CollectionTime', 'SolutionVersion', 'TraceName', 'TraceID')
    $computed = @('RiskConsequenceScore', 'RiskProbabilityScore', 'RiskScoreTotal', 'RiskScoreTotal_Weighted', 'RiskScore_Weight_Factor', 'RiskScore_Weight_Detailed',
        'RiskFactor_Consequence', 'RiskFactor_Consequence_Detailed', 'RiskFactor_Probability', 'RiskFactor_Probability_Detailed', 'AssetDetectedInReportName')
    $l = [System.Collections.Generic.List[object]]::new()
    foreach ($x in $script:RaShapingOutputOrder) { if ($x -notin $trace) { $l.Add($x) } }
    foreach ($x in $computed) { if ($l -notcontains $x) { $l.Add($x) } }
    foreach ($x in (Get-RAColumnUnion -Rows $Rows)) { if ($l -notcontains $x -and $x -notin $trace) { $l.Add($x) } }
    Get-RAUniqueColumns -Columns (@($l.ToArray()) + $trace)
}

function ConvertTo-RaShapedRows {
    <# The engine's shaping (Invoke-RiskAnalysis.ps1, Invoke-RAReportRows), as it is written there. #>
    param($RiskScoreArray, [string[]]$DesiredColumns, [string]$RiskScoreOutputName)
    $Shaped = $RiskScoreArray | Select-Object -Property $DesiredColumns

    # Ensure RiskScore is numeric
    $Shaped = $Shaped | ForEach-Object {
      if ($_.$RiskScoreOutputName -isnot [double]) {
        $_.$RiskScoreOutputName = ConvertTo-RADouble -Value $_.$RiskScoreOutputName -Default 0.0
      }
      $_
    }
    $Shaped
}

function New-RaShapingStream {
    <# A Detailed stream whose SQL seam keeps every statement's JSON (no database). -SqlDelaySeconds: the remove-before-write
       statement takes that long. Returns @{ Stream; Items; Log }. #>
    param([double]$SqlDelaySeconds = 0)
    $items = [System.Collections.Generic.List[string]]::new()
    $log = [System.Collections.Generic.List[string]]::new()
    $seam = { param($Sql, $Params, $Mode)
        if ($Params -and $Params.ContainsKey('j')) { $j = [string]$Params['j']; $items.Add($j); return [regex]::Matches($j, '"RaReport":').Count }
        if ($Sql -match 'COL_LENGTH') { return 1 }
        if ($Sql -match 'OUTPUT inserted.CollectionId') { return 7 }
        if ($SqlDelaySeconds -gt 0 -and $Sql -match 'DELETE FROM sidata\.Finding WHERE CollectionId' -and $Params -and [string]$Params['Bucket'] -ne '*') { [System.Threading.Thread]::Sleep([int]($SqlDelaySeconds * 1000)) }
        0 }.GetNewClosure()
    $stream = New-RAStream -Invoke $seam -Grain Detailed -CollectionTime ([datetime]::new(2026, 10, 16, 5, 0, 0, [DateTimeKind]::Utc)) -Log { param($l, $m) $log.Add([string]$m) }.GetNewClosure()
    $null = Start-RAStreamReport -Stream $stream -ReportName 'Device_Missing_CVEs_Detailed' -Staged $false
    [pscustomobject]@{ Stream = $stream; Items = $items; Log = $log }
}

function Invoke-RaShapingStages {
    <#
        The steps of one slice after the column union, in the order Invoke-RAReportRows and Write-RAStreamBucketRows take
        them, each timed. Returns @{ Times (stage -> seconds); Shaped; Items; Written; Log }.
    #>
    param([Parameter(Mandatory)][object[]]$Rows, [Parameter(Mandatory)][string[]]$Columns, [double]$SqlDelaySeconds = 0)
    $ProgressPreference = 'SilentlyContinue'
    $times = [ordered]@{}
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $shaped = @(ConvertTo-RaShapedRows -RiskScoreArray $Rows -DesiredColumns $Columns -RiskScoreOutputName 'RiskScoreTotal')
    $times['shaping (Select-Object + score as a number)'] = $sw.Elapsed.TotalSeconds
    $sw.Restart()
    $snap = Get-RAColumnFillSnapshot -Rows @($shaped)
    $null = Merge-RAColumnFillSnapshot -Into @{ '__rows' = 5; 'AssetName' = 5 } -Add $snap
    $times['column fill measurement'] = $sw.Elapsed.TotalSeconds
    $s = New-RaShapingStream -SqlDelaySeconds $SqlDelaySeconds
    $sw.Restart()
    Add-RAStreamColumns -Stream $s.Stream -Columns @($Columns)
    $view = Select-RAReportRows -Rows @($shaped)
    $set = New-Object 'System.Collections.Generic.HashSet[object]' ([System.Collections.Generic.ReferenceEqualityComparer]::Instance)
    foreach ($v in @($view.Rows)) { if ($null -ne $v) { [void]$set.Add($v) } }
    $times['report columns + view (exempted rows)'] = $sw.Elapsed.TotalSeconds
    $sw.Restart()
    $n = Write-RAStreamRows -Stream $s.Stream -Rows @($shaped) -Bucket '57/64' -InView $set -IsDetailedShape $true -ConfigurationIdInputName ConfigurationId `
        -SortColumn 'RiskScoreTotal_Weighted' -FallbackSortColumn 'RiskScoreTotal' -Dedup $true -Equivalence $null
    $times['remove-before-write + prepared for the database + write'] = $sw.Elapsed.TotalSeconds
    [pscustomobject]@{ Times = $times; Shaped = $shaped; Items = $s.Items.ToArray(); Written = [long]$n; Log = $s.Log.ToArray() }
}