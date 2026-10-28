#Requires -Version 5.1
<#
    THE CVE REPORTS CARRY EVERY CVE DEFENDER VULNERABILITY MANAGEMENT REPORTS (#150).

    Device_Missing_CVEs_* were built only from Exposure Graph CVE edges. Measured on the internal tenant
    2026-09-28: DeviceTvmSoftwareVulnerabilities held 14,398 device x CVE pairs on 20 devices, the graph
    10,140 on 19 -- 4 devices had no CVE edge and 11 were short (one by 1,315): ~1 in 3 findings never
    reached the report. The graph rows stay; the vulnerability-management rows the graph lacks are added
    with IDENTICAL columns (a union with a mismatched column set would silently misalign), the same
    DeviceKey (so the bucket filter partitions them the same way), de-duplicated on device + CVE, and the
    customer's CVE content filter applies to them too.

    #505 (CI design, V3-DATA-MODEL 2.21.1). DeviceKey is now the Defender device id on both sides -- the graph's
    EntityIds SenseDeviceId (else the node id), DeviceTvm's DeviceId, lower-case -- because it is also the key the
    finding is joined to its CI with (_ciKey). The de-dup pair key is DeviceKey|CVE (was device short name|CVE), and
    the MDE exclusion comes from DeviceInfo's ExclusionReason alone (the Entra device id and internet-facing flag the
    TVM rows used to read for the profile join are gone).
#>

BeforeDiscovery { $script:Reports = @(@{ Name = 'Device_Missing_CVEs_Summary' }, @{ Name = 'Device_Missing_CVEs_Detailed' }) }

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    function script:Get-ReportBlock([string]$Name) {
        [regex]::Match($script:Yaml, '(?s)- ReportName: ' + [regex]::Escape($Name) + '\r?\n(.*?)(?=\r?\n    - ReportName: |\z)').Groups[1].Value
    }
    function script:Get-ProjectedNames([string]$Text) {
        # one projected column per line: `Name = <expr>,` or a bare `Name,`
        @([regex]::Matches($Text, '(?m)^\s*(\w+)\s*(?:=|,\s*$|$)') | ForEach-Object { $_.Groups[1].Value })
    }
}

Describe 'report <Name>' -ForEach $script:Reports {
    BeforeAll { $script:B = Get-ReportBlock $Name }

    It 'adds the vulnerability-management findings to the graph findings' {
        $script:B | Should -Match 'let _TvmOnly = DeviceTvmSoftwareVulnerabilities'
        $script:B | Should -Match '(?m)^\s*union _AssetFindingEdges, _TvmOnly\s*$'
    }
    It 'de-duplicates on Defender device id + CVE against the graph rows (both sides build the key the same way)' {
        $script:B | Should -Match 'let _egCvePairs = _AssetFindingEdges'
        $script:B | Should -Match ([regex]::Escape('| distinct _pairKey = strcat(DeviceKey, "|", toupper(FindingName));'))
        $script:B | Should -Match ([regex]::Escape('| extend _pairKey = strcat(DeviceKey, "|", toupper(CveId))'))
        $script:B | Should -Match '\| join kind=leftanti \(_egCvePairs\) on _pairKey'
    }
    It 'projects EXACTLY the graph rows'' columns' {
        $eg  = [regex]::Match($script:B, '(?s)let _AssetFindingEdges =.*?\| project (.*?);').Groups[1].Value
        # a projected column may be computed (name = expression, e.g. #666's _fromGraph = true): compare its NAME
        $egCols = @($eg -split ',' | ForEach-Object { ($_ -split '=', 2)[0].Trim() } | Where-Object { $_ })
        $tvm = [regex]::Match($script:B, '(?s)let _TvmOnly = .*?\| project\r?\n(.*?);').Groups[1].Value
        $tvmCols = Get-ProjectedNames $tvm
        $egCols.Count | Should -BeGreaterThan 10 -Because 'the graph projection must be found (control)'
        ($tvmCols | Sort-Object) -join ',' | Should -Be (($egCols | Sort-Object) -join ',')
    }
    It 'keys the bucket partition the same way (DeviceKey = the Defender device id, lower-case, on both sides)' {
        $script:B | Should -Match ([regex]::Escape('| extend DeviceKey = iif(isnotempty(MdeDeviceId), MdeDeviceId, tolower(AssetNodeId))'))
        $script:B | Should -Match '\| extend MdeDeviceId = tolower\(coalesce\(extract\(''"type":"SenseDeviceId"'
        $script:B | Should -Match ([regex]::Escape('| extend DeviceKey = tolower(tostring(DeviceId))'))
        $script:B.IndexOf('union _AssetFindingEdges, _TvmOnly') | Should -BeLessThan $script:B.LastIndexOf('//__BUCKET_FILTER_BEGIN__')
        # ...and it is the key the finding is joined to its CI with, after the bucket filter
        $script:B.LastIndexOf('//__BUCKET_FILTER_BEGIN__') | Should -BeLessThan $script:B.IndexOf('| join kind=leftouter (_ciLink) on $left.DeviceKey == $right._ciKey')
    }
    It 'drops MDE-excluded devices, as the graph rows do (else they re-enter because the graph lacks them)' {
        $tvm = [regex]::Match($script:B, '(?s)let _TvmOnly = .*?\| join kind=leftanti').Value
        $tvm | Should -Match ([regex]::Escape('DeviceInfo | extend ExclusionReason = tostring(column_ifexists("ExclusionReason", "")) | summarize arg_max(Timestamp, ExclusionReason) by DeviceId'))
        $tvm | Should -Match '\| where isempty\(ExclusionReason\)'
        $script:B | Should -Match '\| where EG_IsExcluded == false' -Because 'the graph rows drop MDE-excluded devices'
    }
    It 'carries its own CVE content-filter block' {
        $script:B | Should -Match '//__CVE_FILTER_TVM_BEGIN__\r?\n\s*\| where 1 == 1\r?\n\s*//__CVE_FILTER_TVM_END__'
    }
}

Describe 'the engine applies the customer CVE filter to the vulnerability-management rows' {
    BeforeAll {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1') -Raw
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        $fn  = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Resolve-CveFilterBlock' }, $true) | Select-Object -First 1
        $script:CveFilterBeginMark = '//__CVE_FILTER_BEGIN__'; $script:CveFilterEndMark = '//__CVE_FILTER_END__'
        $script:_CveFilterBeginMark = $script:CveFilterBeginMark; $script:_CveFilterEndMark = $script:CveFilterEndMark
        . ([scriptblock]::Create($fn.Extent.Text))
        function script:Write-Info { param($m) }
        function script:ConvertTo-RADouble { param($Value, $Default) if ($null -eq $Value) { $Default } else { [double]$Value } }
    }
    AfterEach { foreach ($v in 'SI_CVE_MinSeverity','SI_CVE_MinCvssScore','SI_CVE_RequireExploit','SI_CVE_MaxPublishedAgeDays') { Remove-Variable -Scope Global -Name $v -ErrorAction SilentlyContinue } }
    It 'no filter set: both blocks stay no-op' {
        $q = Get-ReportBlock 'Device_Missing_CVEs_Detailed'
        $r = Resolve-CveFilterBlock -Query $q -ReportName x
        $r | Should -Be $q
    }
    It 'min severity + CVSS + exploit: the TVM block gets the same rules on its own columns' {
        $global:SI_CVE_MinSeverity = 'High'; $global:SI_CVE_MinCvssScore = 7.5; $global:SI_CVE_RequireExploit = $true
        $r = Resolve-CveFilterBlock -Query (Get-ReportBlock 'Device_Missing_CVEs_Detailed') -ReportName x
        $tvm = [regex]::Match($r, '(?s)//__CVE_FILTER_TVM_BEGIN__(.*?)//__CVE_FILTER_TVM_END__').Groups[1].Value
        $tvm | Should -Match 'where tostring\(TvmSeverity\) in~ \("Critical", "High"\)'
        $tvm | Should -Match 'where toreal\(CvssScore\) >= 7\.5'
        $tvm | Should -Match 'where tobool\(IsExploitAvailable\) == true'
    }
}
