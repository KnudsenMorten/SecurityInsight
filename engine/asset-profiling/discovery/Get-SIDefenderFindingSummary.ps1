#Requires -Version 5.1
<#
    Get-SIDefenderFindingSummary -- Defender's vulnerability and secure-configuration data as part of the device RECORD,
    SUMMARISED PER DEVICE (owner 2026-10-11, "Both, in two steps" -- step 2: record capture, summarised per device rather
    than one record per CVE row).

    One advanced hunting query per batch of devices; every table is summarised INSIDE the query to one row per device:

      vulnerabilities   DeviceTvmSoftwareVulnerabilities + DeviceTvmSoftwareVulnerabilitiesKB: how many vulnerabilities
                        (distinct CVE per device), per severity, how many with a known exploit, the highest CVSS, how many
                        software products are affected, the newest and the oldest publication date, and the TOP ones -- id
                        (the CVE) AND name (the software), severity, CVSS, exploit, the recommended update.
      configurations    DeviceTvmSecureConfigurationAssessment + ...KB: how many security settings were assessed, how many
                        the device does not meet, the highest impact among them, their categories, when it was assessed,
                        and the TOP ones -- id (the configuration id) AND name, category, impact.

    Each becomes a part of the device's Defender record (provider mde, record type device, parts 'vulnerabilities' and
    'configurations'), so their properties show under "Records per source", in continuous discovery and -- through
    data-model/mappings/mde.locked.json -- as SI fields on the device and its CI. The FINDINGS themselves keep arriving
    through Risk Analysis (one finding per device and CVE / setting); nothing here changes a report or a score.

    A device none of the tables has a row for gets NO part: it is unknown whether Defender assessed it, and unknown is
    never written as "no vulnerabilities". When a table holds no row for the WHOLE tenant, the device says
    "no data (licence missing or not collected yet)" -- an empty table is the only evidence, so the licence
    is not claimed missing and si_not_licensed is not set from it.

    A table the tenant does not have is read as empty (union isfuzzy with a stub), a column it does not have as empty
    (column_ifexists). READ ONLY. Never throws: a query that fails is said once, with whether it must be FIXED (a refused
    query gives the same answer when run again) and the devices keep everything else. PowerShell 7, REST only.
#>

$script:SI_MdeTvmFindingLicence = 'Microsoft Defender Vulnerability Management'
# what a device says when the WHOLE tenant has no row in the table: an empty table is the only evidence (the licence may be
# missing, or Defender has not collected yet), so the licence is never claimed missing from it
$script:SI_MdeTvmFindingNoData = 'no data (licence missing or not collected yet)'
$script:SI_MdeTvmFindingTop = 5

if (-not (Get-Command -Name ConvertFrom-SIDefenderJson -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIDefenderDeviceContext.ps1') }
if (-not (Get-Command -Name Read-SIHuntingPages -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/SI-HuntingPages.ps1') }
# devices per summary query (a page, not a limit: every device is read, page by page)
$script:SI_MdeSummaryPageDevices = 1000

function Get-SIDefenderFindingSummaryKql {
    <#
    .SYNOPSIS  PURE. The one advanced hunting query for a batch of Defender device ids: one row per device that has a
               vulnerability or an assessed security setting, plus the tenant-wide "this table has rows" marks. Ids are
               checked (hex), never free text. The top items are collected per severity (never by row order), so the
               most severe are in the list whatever order the rows arrive in.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$DeviceIds, [int]$Top = $script:SI_MdeTvmFindingTop)
    $ids = @($DeviceIds | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ -match '^[0-9a-f]{16,64}$' } | Sort-Object -Unique)
    if ($ids.Count -eq 0) { return '' }
    if ($Top -lt 1) { $Top = 1 }
    $list = ($ids | ForEach-Object { '"' + $_ + '"' }) -join ','
    return @"
let _ids = dynamic([$list]);
let _vulAny = toscalar(union isfuzzy=true (datatable(DeviceId:string)[]), (DeviceTvmSoftwareVulnerabilities) | take 1 | count);
let _cfgAny = toscalar(union isfuzzy=true (datatable(DeviceId:string)[]), (DeviceTvmSecureConfigurationAssessment) | take 1 | count);
let _kb = union isfuzzy=true (datatable(CveId:string)[]), (DeviceTvmSoftwareVulnerabilitiesKB)
    | extend CveId = toupper(tostring(CveId))
    | extend _cvss = todouble(column_ifexists("CvssScore", real(null))), _expl = toint(tobool(column_ifexists("IsExploitAvailable", bool(null)))), _pub = todatetime(column_ifexists("PublishedDate", datetime(null)))
    | summarize _cvss = max(_cvss), _expl = max(_expl), _pub = min(_pub) by CveId;
let _vb = union isfuzzy=true (datatable(DeviceId:string, CveId:string)[]), (DeviceTvmSoftwareVulnerabilities)
    | extend DeviceId = tolower(tostring(DeviceId))
    | where DeviceId in (_ids)
    | extend CveId = toupper(tostring(CveId)), _sev = tostring(column_ifexists("VulnerabilitySeverityLevel", "")),
             _vendor = tostring(column_ifexists("SoftwareVendor", "")), _name = tostring(column_ifexists("SoftwareName", "")), _ver = tostring(column_ifexists("SoftwareVersion", "")),
             _fix = tostring(column_ifexists("RecommendedSecurityUpdate", ""))
    | where isnotempty(CveId);
let _sw = _vb | summarize VulnerableSoftware = dcount(strcat(_vendor, "|", _name)) by DeviceId;
let _vs = _vb
    | summarize _sev = take_any(_sev), _sws = make_set(trim(" ", strcat(_name, " ", _ver)), 3), _fix = take_anyif(_fix, isnotempty(_fix)) by DeviceId, CveId
    | join kind=leftouter _kb on CveId
    | extend _rank = case(_sev =~ "Critical", 4, _sev =~ "High", 3, _sev =~ "Medium", 2, _sev =~ "Low", 1, 0)
    | extend _item = pack("id", CveId, "name", strcat_array(_sws, "; "), "severity", _sev, "cvss", _cvss, "exploit", _expl == 1, "published", _pub, "fix", _fix)
    | order by DeviceId asc, _cvss desc, CveId asc
    | summarize Vulnerabilities = count(), VulnCritical = countif(_rank == 4), VulnHigh = countif(_rank == 3), VulnMedium = countif(_rank == 2), VulnLow = countif(_rank == 1),
                VulnExploitable = countif(_expl == 1), VulnHighestCvss = max(_cvss), VulnNewestPublished = max(_pub), VulnOldestPublished = min(_pub),
                VulnTopCritical = make_list_if(_item, _rank == 4, $Top), VulnTopHigh = make_list_if(_item, _rank == 3, $Top),
                VulnTopMedium = make_list_if(_item, _rank == 2, $Top), VulnTopLow = make_list_if(_item, _rank <= 1, $Top) by DeviceId
    | join kind=leftouter _sw on DeviceId
    | project-away DeviceId1;
let _ckb = union isfuzzy=true (datatable(ConfigurationId:string)[]), (DeviceTvmSecureConfigurationAssessmentKB)
    | extend ConfigurationId = tostring(ConfigurationId)
    | extend _cname = tostring(column_ifexists("ConfigurationName", "")), _ccat = tostring(column_ifexists("ConfigurationCategory", "")), _kimpact = todouble(column_ifexists("ConfigurationImpact", real(null)))
    | summarize _cname = take_any(_cname), _ccat = take_any(_ccat), _kimpact = max(_kimpact) by ConfigurationId;
let _cs = union isfuzzy=true (datatable(DeviceId:string, ConfigurationId:string)[]), (DeviceTvmSecureConfigurationAssessment)
    | extend DeviceId = tolower(tostring(DeviceId))
    | where DeviceId in (_ids)
    | extend ConfigurationId = tostring(ConfigurationId), _ok = toint(tobool(column_ifexists("IsCompliant", bool(null)))), _app = toint(tobool(column_ifexists("IsApplicable", bool(null)))),
             _impact = todouble(column_ifexists("ConfigurationImpact", real(null))), _t = todatetime(column_ifexists("Timestamp", datetime(null)))
    | where isnotempty(ConfigurationId) and (isnull(_app) or _app == 1)
    | summarize _ok = min(_ok), _impact = max(_impact), _t = max(_t) by DeviceId, ConfigurationId
    | join kind=leftouter _ckb on ConfigurationId
    | extend _imp = coalesce(_impact, _kimpact)
    | extend _citem = pack("id", ConfigurationId, "name", _cname, "category", _ccat, "impact", _imp)
    | order by DeviceId asc, _imp desc, ConfigurationId asc
    | summarize ConfigAssessed = count(), ConfigNonCompliant = countif(_ok == 0), ConfigHighestImpact = maxif(_imp, _ok == 0), ConfigAssessedAt = max(_t),
                ConfigCategories = make_set_if(_ccat, _ok == 0 and isnotempty(_ccat), 12),
                ConfigTopHigh = make_list_if(_citem, _ok == 0 and _imp >= 8, $Top), ConfigTopOther = make_list_if(_citem, _ok == 0 and (isnull(_imp) or _imp < 8), $Top) by DeviceId;
union (_vs | project DeviceId), (_cs | project DeviceId)
| distinct DeviceId
| join kind=leftouter _vs on DeviceId
| join kind=leftouter _cs on DeviceId
| project DeviceId, Vulnerabilities, VulnCritical, VulnHigh, VulnMedium, VulnLow, VulnExploitable, VulnHighestCvss, VulnerableSoftware, VulnNewestPublished, VulnOldestPublished,
          VulnTopCritical, VulnTopHigh, VulnTopMedium, VulnTopLow,
          ConfigAssessed, ConfigNonCompliant, ConfigHighestImpact, ConfigAssessedAt, ConfigCategories, ConfigTopHigh, ConfigTopOther,
          HasVulnerabilityData = (_vulAny > 0), HasConfigurationData = (_cfgAny > 0)
"@
}

function ConvertTo-SIDefenderTopItems {
    <# PURE. Lists of top items (each list already the most relevant first), in order of importance -> the first -Top items as objects; a list may be an array or its JSON text. #>
    param([object[]]$Lists = @(), [int]$Top = $script:SI_MdeTvmFindingTop)
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($l in $Lists) {
        $items = $l
        if ($l -is [string]) { $items = ConvertFrom-SIDefenderJson $l }
        foreach ($i in @($items)) {
            if ($out.Count -ge $Top) { break }
            if ($null -eq $i -or $i -is [string]) { continue }
            $id = ''; if ($i.PSObject.Properties['id']) { $id = ([string]$i.id).Trim() }
            if (-not $id -or $seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            $o = [ordered]@{}
            foreach ($p in $i.PSObject.Properties) { if ($null -ne $p.Value -and "$($p.Value)" -ne '') { $o[$p.Name] = $p.Value } }
            $out.Add([pscustomobject]$o)
        }
    }
    return , $out.ToArray()
}

function Format-SIDefenderTopItem {
    <# PURE. One top item as a line: id AND name side by side, then what makes it matter. "CVE-2026-1 -- chrome 128.0 (Critical, CVSS 9.8, exploit available)". #>
    param($Item)
    if ($null -eq $Item) { return '' }
    $g = { param($n) $p = $Item.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { $p.Value } else { $null } }
    $id = [string](& $g 'id'); $name = ([string](& $g 'name')).Trim()
    $bits = New-Object System.Collections.Generic.List[string]
    foreach ($n in 'severity', 'category') { $v = ([string](& $g $n)).Trim(); if ($v) { $bits.Add($v) } }
    $cvss = & $g 'cvss'; if ($null -ne $cvss -and "$cvss" -ne '') { $bits.Add('CVSS ' + ([double]$cvss).ToString('0.0', [System.Globalization.CultureInfo]::InvariantCulture)) }
    $imp = & $g 'impact'; if ($null -ne $imp -and "$imp" -ne '') { $bits.Add('impact ' + ([double]$imp).ToString('0.#', [System.Globalization.CultureInfo]::InvariantCulture)) }
    $ex = & $g 'exploit'; if ("$ex" -in 'True', 'true', '1') { $bits.Add('exploit available') }
    $t = $id; if ($name) { $t = $id + ' -- ' + $name }
    if ($bits.Count -gt 0) { $t = $t + ' (' + ($bits -join ', ') + ')' }
    $t
}

function ConvertTo-SIDefenderFindingSummary {
    <#
    .SYNOPSIS  PURE. One row of the summary query as the device's two record parts: @{ Vulnerabilities; Configurations;
               NotLicensed } -- each only when the row has it. A tenant whose table holds no row at all says
               "no data (licence missing or not collected yet)" in the part's Status; NotLicensed stays empty (an empty
               table does not prove a missing licence).
    #>
    param($Row)
    if ($null -eq $Row) { return $null }
    $g = { param($n) $p = $Row.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    $num = { param($n) $v = & $g $n; $x = 0; if ($null -ne $v -and [int]::TryParse(([string]$v), [ref]$x)) { $x } else { $null } }
    $dbl = { param($n) $v = & $g $n; $x = 0.0; if ($null -ne $v -and "$v" -ne '' -and [double]::TryParse(([string]$v), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$x)) { $x } else { $null } }
    $no = { param($v) ($null -ne $v -and "$v" -in 'False', 'false', '0') }
    $notLicensed = New-Object System.Collections.Generic.List[string]
    $vuln = $null; $cfg = $null

    $total = & $num 'Vulnerabilities'
    if ($null -ne $total -and $total -gt 0) {
        $v = [ordered]@{ Total = $total }
        foreach ($pair in @(@('Critical', 'VulnCritical'), @('High', 'VulnHigh'), @('Medium', 'VulnMedium'), @('Low', 'VulnLow'), @('Exploitable', 'VulnExploitable'), @('Software', 'VulnerableSoftware'))) {
            $n = & $num $pair[1]; if ($null -ne $n) { $v[$pair[0]] = $n }
        }
        $c = & $dbl 'VulnHighestCvss'; if ($null -ne $c) { $v['HighestCvss'] = $c }
        foreach ($pair in @(@('NewestPublished', 'VulnNewestPublished'), @('OldestPublished', 'VulnOldestPublished'))) { $d = & $g $pair[1]; if ($null -ne $d -and "$d" -ne '') { $v[$pair[0]] = $d } }
        $top = ConvertTo-SIDefenderTopItems -Lists @((& $g 'VulnTopCritical'), (& $g 'VulnTopHigh'), (& $g 'VulnTopMedium'), (& $g 'VulnTopLow'))
        if (@($top).Count -gt 0) { $v['Top'] = @($top); $v['TopText'] = @(@($top) | ForEach-Object { Format-SIDefenderTopItem $_ }) }
        $vuln = [pscustomobject]$v
    } elseif (& $no (& $g 'HasVulnerabilityData')) {
        $vuln = [pscustomobject][ordered]@{ Status = $script:SI_MdeTvmFindingNoData }
    }

    $assessed = & $num 'ConfigAssessed'
    if ($null -ne $assessed -and $assessed -gt 0) {
        $c = [ordered]@{ Assessed = $assessed }
        $n = & $num 'ConfigNonCompliant'; if ($null -ne $n) { $c['NonCompliant'] = $n }
        $i = & $dbl 'ConfigHighestImpact'; if ($null -ne $i) { $c['HighestImpact'] = $i }
        $at = & $g 'ConfigAssessedAt'; if ($null -ne $at -and "$at" -ne '') { $c['AssessedAt'] = $at }
        $catRaw = @(& $g 'ConfigCategories')
        if ($catRaw.Count -eq 1 -and $catRaw[0] -is [string] -and $catRaw[0].Trim().StartsWith('[')) { $catRaw = @(ConvertFrom-SIDefenderJson $catRaw[0]) }
        $cats = @($catRaw | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Sort-Object -Unique)
        if ($cats.Count -gt 0) { $c['Categories'] = $cats }
        $top = ConvertTo-SIDefenderTopItems -Lists @((& $g 'ConfigTopHigh'), (& $g 'ConfigTopOther'))
        if (@($top).Count -gt 0) { $c['Top'] = @($top); $c['TopText'] = @(@($top) | ForEach-Object { Format-SIDefenderTopItem $_ }) }
        $cfg = [pscustomobject]$c
    } elseif (& $no (& $g 'HasConfigurationData')) {
        $cfg = [pscustomobject][ordered]@{ Status = $script:SI_MdeTvmFindingNoData }
    }
    if ($null -eq $vuln -and $null -eq $cfg) { return $null }
    return @{ Vulnerabilities = $vuln; Configurations = $cfg; NotLicensed = $notLicensed.ToArray() }
}

function Get-SIDefenderFindingSummary {
    <#
    .SYNOPSIS  The summaries of a batch of devices: Defender device id (lower) -> @{ Vulnerabilities; Configurations;
               NotLicensed }. Never throws.
    .PARAMETER Query  test seam: { param($kql) rows } instead of the Graph call.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$DeviceIds, [scriptblock]$Query, [int]$PageDevices = $script:SI_MdeSummaryPageDevices)
    $out = @{}
    # one query per page of devices, each retried, a failed page asked once more at the end (Read-SIHuntingPages); a page
    # that still failed is said and its devices keep their previous summaries -- never "no vulnerabilities"
    $read = Read-SIHuntingPages -Ids $DeviceIds -Kql { param($p) Get-SIDefenderFindingSummaryKql -DeviceIds $p } -Query $Query -PageSize $PageDevices
    foreach ($fl in $read.Failed) {
        Write-Warning ('Defender vulnerability and security-setting summaries were not read for {0} device(s): {1} -- {2}. The device records keep their previous summaries; the findings in Risk Analysis are not affected.' -f $fl.Count, (Get-SIHuntingFailureKind $fl), $fl.Error)
    }
    $rows = $read.Rows
    # the tenant-wide "this table has rows" marks are the same on every row; a device WITHOUT a row still needs them
    $hasV = $null; $hasC = $null
    foreach ($r in $rows) {
        if ($null -eq $r) { continue }
        if ($null -eq $hasV -and $r.PSObject.Properties['HasVulnerabilityData']) { $hasV = $r.HasVulnerabilityData }
        if ($null -eq $hasC -and $r.PSObject.Properties['HasConfigurationData']) { $hasC = $r.HasConfigurationData }
        $id = ([string]$r.DeviceId).Trim().ToLowerInvariant()
        if (-not $id) { continue }
        $s = ConvertTo-SIDefenderFindingSummary -Row $r
        if ($null -ne $s) { $out[$id] = $s }
    }
    # only a tenant-wide EMPTY table is said for the devices without a row ("no data ..."); a device without a row in a
    # tenant that has rows stays unknown -- it is never written as "no vulnerabilities"
    if ($null -ne $hasV -or $null -ne $hasC) {
        foreach ($d in @($DeviceIds)) {
            $id = ([string]$d).Trim().ToLowerInvariant()
            if (-not $id -or $out.ContainsKey($id) -or -not $read.ReadIds.Contains($id)) { continue }
            $s = ConvertTo-SIDefenderFindingSummary -Row ([pscustomobject]@{ DeviceId = $id; HasVulnerabilityData = $hasV; HasConfigurationData = $hasC })
            if ($null -ne $s) { $out[$id] = $s }
        }
    }
    return $out
}

# =====================================================================================================================
#  SOFTWARE INVENTORY per device (#499) -- DeviceTvmSoftwareInventory as part 'softwareInventory' of the device record,
#  ALWAYS (the rule index's 'software' part exists only while a rule asks hasSoftwareInstalled). Its own query per page
#  of devices: a device's product list is long, so it does not ride in the summary query above. Every product is kept
#  (vendor/product), and the products past or near their end of support with version, status and date.
# =====================================================================================================================
$script:SI_MdeSoftwarePageDevices = 500

function Get-SIDefenderSoftwareInventoryKql {
    <# PURE. One advanced hunting query for a page of Defender device ids (checked hex ids, never free text): one row per device. #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$DeviceIds)
    $ids = @($DeviceIds | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ -match '^[0-9a-f]{16,64}$' } | Sort-Object -Unique)
    if ($ids.Count -eq 0) { return '' }
    $list = ($ids | ForEach-Object { '"' + $_ + '"' }) -join ','
    return @"
let _ids = dynamic([$list]);
union isfuzzy=true (datatable(DeviceId:string, SoftwareVendor:string, SoftwareName:string)[]), (DeviceTvmSoftwareInventory)
| extend DeviceId = tolower(tostring(DeviceId))
| where DeviceId in (_ids)
| extend _p = tolower(strcat(tostring(SoftwareVendor), "/", tostring(SoftwareName))), _ver = tostring(column_ifexists("SoftwareVersion", "")),
         _eos = tostring(column_ifexists("EndOfSupportStatus", "")), _eosd = todatetime(column_ifexists("EndOfSupportDate", datetime(null)))
| where isnotempty(tostring(SoftwareName))
| extend _eosItem = iff(isnotempty(_eos), strcat(_p, " ", _ver, " (", _eos, iff(isnotnull(_eosd), strcat(", ", format_datetime(_eosd, "yyyy-MM-dd")), ""), ")"), "")
| summarize Installed = dcount(_p), Products = make_set(_p), EndOfSupport = dcountif(_p, isnotempty(_eos)), EndOfSupportItems = make_set_if(_eosItem, isnotempty(_eosItem)) by DeviceId
| order by DeviceId asc
"@
}

function ConvertTo-SIDefenderSoftwareInventory {
    <# PURE. One row of the inventory query -> the 'softwareInventory' part (Installed, Products, EndOfSupport, EndOfSupportItems); $null without products. #>
    param($Row)
    if ($null -eq $Row) { return $null }
    $list = { param($v) if ($v -is [string]) { $t = $v.Trim(); if ($t.StartsWith('[')) { $v = ConvertFrom-SIDefenderJson $t } else { $v = @($t) } }; @(@($v) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Sort-Object -Unique) }
    $products = & $list $Row.Products
    if ($products.Count -eq 0) { return $null }
    $o = [ordered]@{ Installed = $products.Count; Products = $products }
    $n = 0; if ($null -ne $Row.Installed -and [int]::TryParse([string]$Row.Installed, [ref]$n)) { $o.Installed = $n }
    $eos = & $list $Row.EndOfSupportItems
    $e = 0; if ($null -ne $Row.EndOfSupport -and [int]::TryParse([string]$Row.EndOfSupport, [ref]$e)) { $o['EndOfSupport'] = $e } else { $o['EndOfSupport'] = $eos.Count }
    if ($eos.Count -gt 0) { $o['EndOfSupportItems'] = $eos }
    [pscustomobject]$o
}

function Add-SIDefenderSoftwareInventoryParts {
    <#
    .SYNOPSIS  Reads the software inventory of the given Defender devices, one query per page of devices (each answer kept
               as parts and let go), into part 'softwareInventory' of each device's record. Returns @{ Devices; Pages;
               Failed }. A device without inventory rows gets no part (unknown, never "no software"). Never throws.
    .PARAMETER Query  test seam: { param($kql) rows }.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$DeviceIds, [scriptblock]$Query, [int]$PageDevices = $script:SI_MdeSoftwarePageDevices)
    $res = @{ Devices = 0; Pages = 0; Failed = 0 }
    if (-not (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue)) { return $res }
    $ids = @($DeviceIds | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
    if ($PageDevices -lt 1) { $PageDevices = 1 }
    # each page retried, a failed page asked once more at the end (Read-SIHuntingPages); each page's rows kept as parts and let go
    $keep = {
        param($rows)
        foreach ($r in $rows) {
            try {
                $id = ([string]$r.DeviceId).Trim().ToLowerInvariant()
                $part = ConvertTo-SIDefenderSoftwareInventory -Row $r
                if ($id -and $null -ne $part) { Add-SIRecordPart -Provider 'mde' -RecordType 'device' -Key $id -Part 'softwareInventory' -Object $part; $res.Devices++ }
            } catch { }
        }
    }
    $read = Read-SIHuntingPages -Ids $ids -Kql { param($p) Get-SIDefenderSoftwareInventoryKql -DeviceIds $p } -Query $Query -PageSize $PageDevices -OnRows $keep
    $res.Pages = $read.Pages
    foreach ($fl in $read.Failed) {
        $res.Failed++
        Write-Warning ('Defender software inventory was not read for {0} device(s): {1} -- {2}. Those devices keep their previous software list; nothing else is affected.' -f $fl.Count, (Get-SIHuntingFailureKind $fl), $fl.Error)
    }
    $res
}

function Add-SIDefenderFindingSummaryParts {
    <#
    .SYNOPSIS  Reads the summaries of the given Defender device ids and keeps them as the 'vulnerabilities' and
               'configurations' parts of each device's record. Returns the number of devices that got one. Does nothing
               without the record capture.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$DeviceIds, [scriptblock]$Query)
    if (-not (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue)) { return 0 }
    $ids = @($DeviceIds | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
    if ($ids.Count -eq 0) { return 0 }
    $a = @{ DeviceIds = $ids }; if ($Query) { $a['Query'] = $Query }
    $sum = Get-SIDefenderFindingSummary @a
    $n = 0
    foreach ($id in @($sum.Keys)) {
        try {
            $s = $sum[$id]
            if ($null -ne $s.Vulnerabilities) { Add-SIRecordPart -Provider 'mde' -RecordType 'device' -Key $id -Part 'vulnerabilities' -Object $s.Vulnerabilities }
            if ($null -ne $s.Configurations) { Add-SIRecordPart -Provider 'mde' -RecordType 'device' -Key $id -Part 'configurations' -Object $s.Configurations }
            if (@($s.NotLicensed).Count -gt 0) { Add-SIRecordPart -Provider 'mde' -RecordType 'device' -Key $id -Part 'findingLicence' -Object ([pscustomobject]@{ NotLicensed = @($s.NotLicensed) }) }
            $n++
        } catch { }
    }
    return $n
}
