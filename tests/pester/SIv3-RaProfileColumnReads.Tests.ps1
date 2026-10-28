#Requires -Version 5.1
<#
    A LOCKED REPORT MAY ONLY READ COLUMNS A PROFILE TABLE REALLY HAS, IN A TYPE THE OPERATOR ACCEPTS.

    WHY. The four public-IP reports (PublicIP_OpenPorts_* and PublicIP_Vulnerabilities_*) failed on every
    workspace that had SI_PublicIP_Profile_CL rows. Measured live 2026-10-03 through the Log Analytics data
    plane (the ARM proxy route reports both as a bare "Syntax Error"):

        SEM0100  'summarize' operator: Failed to resolve scalar expression named 'AssetName'
        SEM0001  Summarize group key 'cmdbName' is of a 'dynamic' type ...

    1. AssetName left every profile table on 2026-08-28 (SI_AssetName replaced it). Reads wrapped in
       column_ifexists() survived that, and SIv3-CatalogReadsSIColumns guards them; a BARE read is a hard
       semantic error, and nothing looked for it. The public-IP reports were the only ones left.
    2. The SI tables store cmdbId / cmdbName / cmdbCriticality / cmdbDataSensitivity as DYNAMIC
       (getschema on all four profile tables, and on the v2.2 SI_VulnerabilityPIP_CL). A summarize key
       cannot be dynamic, so a report must tostring() those columns before grouping on them -- every
       other report already did. This rule therefore covers every SI_*_CL source, not only profiles.

    Both are visible in the YAML without a workspace, so both are linted here over EVERY locked report.
    The public-IP reports never ran with data before (the table was empty or absent), which is why a
    green offline gate said nothing for so long.

    #505 -- the reports read the CI (SI_CI_CL) instead of the profile tables, so rule 1 has nothing left to find in
    the catalog (its detector stays, held by the controls); rule 2 still runs over every report, since every report
    reads SI_CI_CL. The public-IP reports are found by name now (they read the CI's public_ip class).
    #690 (35) -- the public-IP reports dropped that class filter and read every CI with a Shodan link
    (where isnotempty(si_link_shodan)); the control checks that selection instead.
#>

BeforeAll {
    $script:SIRoot  = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Catalog = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'

    # Every report's name and the text from its ReportQuery key onward. Line-based on purpose: no YAML module.
    function script:Get-LockedReports([string]$Path) {
        $raw = [System.IO.File]::ReadAllText($Path)
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($c in [regex]::Split($raw, '(?m)^(?=\s+- ReportName:)')) {
            $m = [regex]::Match($c, '(?m)^\s+- ReportName:\s*(\S+)')
            if (-not $m.Success) { continue }
            $qi = $c.IndexOf('ReportQuery:')
            if ($qi -lt 0) { continue }
            $out.Add([pscustomobject]@{ Name = $m.Groups[1].Value; Query = $c.Substring($qi) })
        }
        return $out
    }

    # KQL with every string literal emptied and every // comment removed, so prose and literals never match.
    function script:Get-KqlCode([string]$Query) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($line in ($Query -split "`r?`n")) {
            $s = [regex]::Replace($line, '"(?:[^"\\]|\\.)*"|''(?:[^''\\]|\\.)*''', '""')
            $ci = $s.IndexOf('//'); if ($ci -ge 0) { $s = $s.Substring(0, $ci) }
            [void]$sb.AppendLine($s)
        }
        return $sb.ToString()
    }

    # Findings for one query that reads a profile table: bare AssetName reads, and summarize keys on a raw cmdb column.
    function script:Get-ProfileColumnDefects([string]$Name, [string]$Query) {
        $hits = New-Object System.Collections.Generic.List[string]
        $code = script:Get-KqlCode $Query
        # cmdb* are dynamic on every SI_*_CL table (v2.2 SI_VulnerabilityPIP_CL included); AssetName is gone only from profile tables.
        if ($code -notmatch '\bSI_\w+_CL\b') { return $hits }
        if ($code -match '\bSI_\w+_Profile_CL\b') {
            $assign = [regex]::Match($code, '(?<![\w.])AssetName\s*=(?!=)')
            $assignAt = if ($assign.Success) { $assign.Index } else { [int]::MaxValue }
            foreach ($m in [regex]::Matches($code, '(?<![\w."])AssetName\b(?!\s*=(?!=))')) {
                if ($m.Index -lt $assignAt) { $hits.Add(('{0}: reads AssetName, which no profile table has (use SI_AssetName)' -f $Name)); break }
            }
        }
        foreach ($bm in [regex]::Matches($code, '(?s)\|\s*summarize\b.*?\bby\b(.*?)(?=\n\s*\||\z)')) {
            $by = $bm.Groups[1].Value
            $before = $code.Substring(0, $bm.Groups[1].Index)
            foreach ($col in 'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity') {
                if ($by -notmatch ('(?<![\w.])' + $col + '\b(?!\s*=(?!=))')) { continue }
                if ($before -match ('(?<![\w.])' + $col + '\s*=(?!=)')) { continue }
                $hits.Add(('{0}: groups by the raw (dynamic) {1} column -- tostring() it first' -f $Name, $col))
            }
        }
        return $hits
    }

    $script:Reports = script:Get-LockedReports $script:Catalog
}

Describe 'locked reports read profile columns that exist, in a groupable type' {

    It 'the catalog parsed (control -- green must not mean "scanned nothing")' {
        $script:Reports.Count | Should -BeGreaterThan 100
        # #505 -- the public-IP reports read their assets from the CI (SI_CI_CL, class public_ip), not SI_PublicIP_Profile_CL
        @($script:Reports | Where-Object { $_.Name -like 'PublicIP_*' }).Count | Should -Be 4
        $pipNames = @($script:Reports | Where-Object { $_.Name -like 'PublicIP_*' } | ForEach-Object { $_.Name } | Sort-Object)
        ($pipNames -join ',') | Should -Be 'PublicIP_OpenPorts_Detailed,PublicIP_OpenPorts_Summary,PublicIP_Vulnerabilities_Detailed,PublicIP_Vulnerabilities_Summary'
        # #690 (35) -- the class filter (si_class in ("public_ip")) left the catalog: the reports read EVERY CI Shodan
        # scans (an Azure public IP resource is a cloud_resource CI with a Shodan link). Still from the CI, never the profile table.
        @($script:Reports | Where-Object {
            $code = script:Get-KqlCode $_.Query
            $_.Name -like 'PublicIP_*' -and
            $code -match '\bSI_CI_CL\b' -and
            $code -notmatch '\bSI_PublicIP_Profile_CL\b' -and
            $code -match '\|\s*where isnotempty\(si_link_shodan\)'
        }).Count | Should -Be 4
        # the cmdb rule runs on every report that reads an SI_*_CL table -- now every report (SI_CI_CL)
        @($script:Reports | Where-Object { (script:Get-KqlCode $_.Query) -match '\bSI_\w+_CL\b' }).Count | Should -BeGreaterThan 100
    }

    It 'the detector fires on the shape that broke the public-IP reports (control)' {
        $broken = @'
ReportQuery:
      - |-
        SI_PublicIP_Profile_CL
        | extend cmdbId = ""
        // a comment naming AssetName and cmdbName = "x" must not count
        | summarize ImpactedAssets = make_set(strcat(AssetName, " (", IpAddress, ")"))
          by SecurityDomain, cmdbId, cmdbName, cmdbCriticality, cmdbDataSensitivity = ""
'@
        $hits = @(script:Get-ProfileColumnDefects 'Broken' $broken)
        ($hits -join "`n") | Should -Match 'reads AssetName'
        ($hits -join "`n") | Should -Match 'raw \(dynamic\) cmdbName'
        ($hits -join "`n") | Should -Match 'raw \(dynamic\) cmdbCriticality'
        ($hits -join "`n") | Should -Not -Match 'raw \(dynamic\) cmdbId'                 # extended to a string above
        ($hits -join "`n") | Should -Not -Match 'raw \(dynamic\) cmdbDataSensitivity'    # computed in the by-clause
    }

    It 'the detector accepts the fixed shape (control)' {
        $fixed = @'
ReportQuery:
      - |-
        SI_PublicIP_Profile_CL
        | extend AssetName       = iif(isnotempty(tostring(column_ifexists("SI_AssetName", ""))), tostring(column_ifexists("SI_AssetName", "")), tostring(column_ifexists("AssetName", "")))
        | extend cmdbName        = tostring(column_ifexists("cmdbName", ""))
        | extend cmdbCriticality = tostring(column_ifexists("cmdbCriticality", ""))
        | summarize ImpactedAssets = make_set(strcat(AssetName, " (", IpAddress, ")"))
          by SecurityDomain, cmdbName, cmdbCriticality, cmdbDataSensitivity = ""
'@
        @(script:Get-ProfileColumnDefects 'Fixed' $fixed).Count | Should -Be 0
    }

    It 'no locked report reads AssetName off a profile table, or groups by a raw cmdb column' {
        $all = New-Object System.Collections.Generic.List[string]
        foreach ($r in $script:Reports) { foreach ($h in (script:Get-ProfileColumnDefects $r.Name $r.Query)) { $all.Add($h) } }
        $all.Count | Should -Be 0 -Because ("each of these fails on a workspace that has rows:`n" + ($all -join "`n"))
    }

    It 'the public-IP reports keep their bucket and weighting markers' {
        $pip = @($script:Reports | Where-Object { $_.Name -like 'PublicIP_*' })
        $pip.Count | Should -Be 4
        foreach ($r in $pip) {
            $r.Query | Should -Match '//__BUCKET_FILTER_BEGIN__' -Because $r.Name
            $r.Query | Should -Match '//__BUCKET_FILTER_END__' -Because $r.Name
            $r.Query | Should -Match '//__WEIGHTED_FACTORS_BEGIN__' -Because $r.Name
            $r.Query | Should -Match '//__WEIGHTED_FACTORS_END__' -Because $r.Name
        }
    }
}
