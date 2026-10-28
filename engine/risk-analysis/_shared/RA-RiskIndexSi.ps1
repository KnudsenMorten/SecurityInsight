#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  THE RISK INDEX, RE-KEYED TO THE SI GENERIC FIELDS (REQUIREMENTS #559, owner 2026-10-10: "base values come from the
#  risk index. that is the magic ... risk index base values must be adjusted to the si names ... if mde has not
#  responded in 7 days on a server, it is critical - but on a client for a user being on vacation it is not same
#  criticality").
#
#  WHAT A ROW MEANS (riskscore.index.locked.csv, and the customer's riskscore.index.custom.csv)
#    Matchers  si_finding_type, si_category, si_subcategory, si_component, si_finding_key, asset_class  -- blank = any
#              si_severity  (consulted for the VULNERABILITY base only)
#              si_tier      (consulted for the ASSET base only)
#    Scores    AssetBase (the asset side's base: by finding x asset class x tier)
#              VulnerabilityBase (the vulnerability side's base: by finding type / category / subcategory / severity)
#              -- a blank score means "this row does not set that score": the search goes on.
#    Order     Precedence (1 = checked first); rows without one after the numbered rows, in file order.
#
#  HOW A FINDING IS SCORED -- unchanged from 3.0 (RA-RiskIndexOrder.ps1): FIRST MATCH WINS, per base, top down. A filled
#  matcher must equal the finding's value (case-insensitive); a blank finding value never fits a filled matcher. ONE
#  extension: asset_class 'device' is the FAMILY of device_server / device_client, so a 'device' row fits both (the v2.2
#  'Endpoint' rows translate to it), while a device_server row fits only servers. No row -> 0.
#      asset side         = AssetBase + SUM(enabled asset factors' impacts)          no cap
#      vulnerability side = VulnerabilityBase + SUM(enabled finding factors' impacts)  no cap
#      risk score         = asset side x vulnerability side                         (RA-RiskScore.ps1)
#
#  v2.2 KEYS ARE TRANSLATED, NEVER LOST (riskscore.index.translation.locked.json, shipped as data). A file with the v2.2
#  columns (SecurityDomain, Category, SubCategory, ConfigurationId, SecuritySeverity, CriticalityTierLevel and the two
#  score columns) is first put in first-match form when it has no Precedence column (ConvertTo-SIRiskIndexFirstMatch --
#  the v2.2 ladder, proved in SIv3-RiskIndexOrder.Tests.ps1), then translated row for row, in order, so every v2.2 base
#  value is carried over and first-match over the translated rows scores a translated finding exactly as v2.2 did
#  (tests/pester/SIv3-RiskIndexSi.Tests.ps1). The shipped index IS that translation of the 3.0 index (99 rows), plus the
#  owner's server / client rows in front.
#
#  PowerShell 7 (v3); written 5.1-safe. Pure functions except Get-SIRiskIndexTranslation (reads the shipped table once).
#######################################################################################################

$script:SIRiskIndexSiColumns = @('si_finding_type', 'si_category', 'si_subcategory', 'si_component', 'si_finding_key', 'asset_class',
    'si_severity', 'VulnerabilityBase', 'si_tier', 'AssetBase', 'Comments', 'Precedence')
$script:SIRiskIndexSiMatchers = @('si_finding_type', 'si_category', 'si_subcategory', 'si_component', 'si_finding_key', 'asset_class')
$script:SIRiskIndexV22Columns = @('SecurityDomain', 'Category', 'SubCategory', 'ConfigurationId', 'SecuritySeverity',
    'RiskConsequenceScore_SecuritySeverity', 'CriticalityTierLevel', 'RiskProbablityScore_CriticialityTierLevel')
$script:SIRiskIndexTranslationPath = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))), 'risk-analysis-detection', 'riskscore.index.translation.locked.json')

# the shipped table, used when the file cannot be read (a stripped package): the same values, so a v2.2 file still scores
$script:SIRiskIndexTranslationDefault = @{
    columns = [ordered]@{ SecurityDomain = 'asset_class'; Category = 'si_category'; SubCategory = 'si_subcategory'; ConfigurationId = 'si_finding_key'
        SecuritySeverity = 'si_severity'; RiskConsequenceScore_SecuritySeverity = 'VulnerabilityBase'; CriticalityTierLevel = 'si_tier'
        RiskProbablityScore_CriticialityTierLevel = 'AssetBase'; Comments = 'Comments'; Precedence = 'Precedence' }
    values = @{
        asset_class = @{ 'endpoint' = 'device'; 'identity' = 'identity'; 'azure' = 'cloud_resource'; 'publicip' = 'public_ip' }
        si_severity = @{ 'very high' = 'critical'; 'critical' = 'critical'; 'high' = 'high'; 'medium-high' = 'medium_high'; 'medium' = 'medium'; 'moderate' = 'medium'; 'low' = 'low'; 'informational' = 'info'; 'info' = 'info' }
        si_tier = @{ 'critical - tier 0' = '0'; 'high - tier 1' = '1'; 'medium - tier 2' = '2'; 'low - tier 3' = '3' }
    }
}

function Get-SIRiskIndexTranslation {
    <# The v2.2 -> SI translation table: @{ columns = ordered v2.2 -> SI; values = SI column -> @{ lower-case v2.2 value -> SI value } }.
       Read once per process from riskscore.index.translation.locked.json; the built-in copy when it cannot be read. #>
    param([string]$Path = $script:SIRiskIndexTranslationPath)
    if ($script:SIRiskIndexTranslationCache -and -not $PSBoundParameters.ContainsKey('Path')) { return $script:SIRiskIndexTranslationCache }
    $t = $script:SIRiskIndexTranslationDefault
    try {
        if ($Path -and (Test-Path -LiteralPath $Path)) {
            $j = [System.IO.File]::ReadAllText($Path) | ConvertFrom-Json
            $cols = [ordered]@{}; foreach ($p in $j.columns.PSObject.Properties) { $cols[$p.Name] = [string]$p.Value }
            $vals = @{}
            foreach ($p in $j.values.PSObject.Properties) { $m = @{}; foreach ($q in $p.Value.PSObject.Properties) { $m[$q.Name.ToLowerInvariant()] = [string]$q.Value }; $vals[$p.Name] = $m }
            $t = @{ columns = $cols; values = $vals }
        }
    } catch { $t = $script:SIRiskIndexTranslationDefault }
    if (-not $PSBoundParameters.ContainsKey('Path')) { $script:SIRiskIndexTranslationCache = $t }
    return $t
}

function Get-SIRiskIndexCellSi {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return '' }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name) -and $null -ne $Row[$Name]) { return [string]$Row[$Name] } else { return '' } }
    $p = $Row.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return '' }
    [string]$p.Value
}

function Get-SIRiskIndexRowColumns {
    param($Row)
    if ($null -eq $Row) { return @() }
    if ($Row -is [System.Collections.IDictionary]) { return @($Row.Keys | ForEach-Object { [string]$_ }) }
    return @($Row.PSObject.Properties.Name)
}

function Test-SIRiskIndexV22Form {
    <# PURE. $true when the rows are written with the v2.2 columns (they carry a v2.2 score column and no SI score column). #>
    param([AllowEmptyCollection()][object[]]$Rows)
    $first = @($Rows | Where-Object { $null -ne $_ } | Select-Object -First 1)
    if (-not $first.Count) { return $false }
    $cols = Get-SIRiskIndexRowColumns $first[0]
    if ($cols -contains 'AssetBase' -or $cols -contains 'VulnerabilityBase') { return $false }
    return ($cols -contains 'RiskConsequenceScore_SecuritySeverity' -or $cols -contains 'RiskProbablityScore_CriticialityTierLevel' -or $cols -contains 'CriticalityTierLevel')
}

function ConvertTo-SIRiskIndexSiValue {
    <# PURE. One v2.2 value -> its SI value for an SI column (the table's value map; an unlisted value is kept as written). #>
    param([string]$Column, [AllowNull()][AllowEmptyString()][string]$Value, [hashtable]$Translation)
    if (-not $Translation) { $Translation = Get-SIRiskIndexTranslation }
    $v = ([string]$Value).Trim()
    if ($v -eq '') { return '' }
    if ($Translation.values -and $Translation.values.ContainsKey($Column)) {
        $m = $Translation.values[$Column]
        $k = $v.ToLowerInvariant()
        if ($m.ContainsKey($k)) { return [string]$m[$k] }
    }
    return $v
}

function ConvertTo-SIRiskIndexSiRow {
    <# PURE. ONE row -> an SI-keyed [ordered] row: a 2.2-keyed row translated column by column (its Precedence kept), an
       SI row copied. For one row at a time (a Pro item); a whole 2.2 file without Precedence goes through
       ConvertTo-SIRiskIndexSiRows (the ladder needs every row). #>
    param([Parameter(Mandatory)]$Row, [hashtable]$Translation)
    if (-not $Translation) { $Translation = Get-SIRiskIndexTranslation }
    $o = [ordered]@{}; foreach ($c in $script:SIRiskIndexSiColumns) { $o[$c] = '' }
    if (Test-SIRiskIndexV22Form @($Row)) {
        foreach ($src in $Translation.columns.Keys) {
            $dst = [string]$Translation.columns[$src]
            if ($o.Contains($dst)) { $o[$dst] = ConvertTo-SIRiskIndexSiValue -Column $dst -Value (Get-SIRiskIndexCellSi $Row $src) -Translation $Translation }
        }
    } else {
        foreach ($c in $script:SIRiskIndexSiColumns) { $o[$c] = Get-SIRiskIndexCellSi $Row $c }
    }
    return $o
}

function ConvertTo-SIRiskIndexSiRows {
    <#
        PURE. Index rows -> SI-keyed rows ([ordered] dictionaries with $script:SIRiskIndexSiColumns), in first-match order.
          * SI rows (AssetBase / VulnerabilityBase columns): kept, ordered by Precedence (stable)
          * v2.2 rows: a file without Precedence is converted by the v2.2 ladder first (ConvertTo-SIRiskIndexFirstMatch),
            then every row is translated column by column (riskscore.index.translation.locked.json), keeping its order
        Precedence is renumbered 1..n in the returned order.
    #>
    param([AllowEmptyCollection()][object[]]$Rows, [hashtable]$Translation)
    $rows = @($Rows | Where-Object { $null -ne $_ })
    if ($rows.Count -eq 0) { return }
    if (-not $Translation) { $Translation = Get-SIRiskIndexTranslation }
    $out = [System.Collections.Generic.List[object]]::new()
    if (Test-SIRiskIndexV22Form $rows) {
        $ordered = @()
        if (Get-Command -Name Get-SIRiskIndexOrderedRows -ErrorAction SilentlyContinue) { $ordered = @(Get-SIRiskIndexOrderedRows -Rows $rows) } else { $ordered = $rows }
        foreach ($r in $ordered) {
            $o = [ordered]@{}; foreach ($c in $script:SIRiskIndexSiColumns) { $o[$c] = '' }
            foreach ($src in $Translation.columns.Keys) {
                $dst = [string]$Translation.columns[$src]
                if (-not $o.Contains($dst)) { continue }
                $o[$dst] = ConvertTo-SIRiskIndexSiValue -Column $dst -Value (Get-SIRiskIndexCellSi $r $src) -Translation $Translation
            }
            $out.Add($o)
        }
    } else {
        $keys = New-Object 'System.Collections.Generic.List[double]'
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $t = (Get-SIRiskIndexCellSi $rows[$i] 'Precedence').Trim(); $d = 0.0
            if ($t -ne '' -and [double]::TryParse($t, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $keys.Add($d) } else { $keys.Add([double]::MaxValue) }
        }
        $idx = [int[]](0..($rows.Count - 1))
        foreach ($i in @($idx | Sort-Object -Property @{ Expression = { $keys[$_] } }, @{ Expression = { $_ } })) {
            $o = [ordered]@{}; foreach ($c in $script:SIRiskIndexSiColumns) { $o[$c] = (Get-SIRiskIndexCellSi $rows[$i] $c) }
            $out.Add($o)
        }
    }
    $k = 0; foreach ($o in $out) { $k++; $o['Precedence'] = [string]$k }
    $out.ToArray()
}

function New-SIRiskIndexSiRules {
    <#
        PURE. SI rows in first-match order -> @{ Asset = rules; Vulnerability = rules }. A rule: @{ M = string[7] (the six
        matchers + tier / severity, lower-case; $null = any); Score = double; Position = 1-based row }. A row without a
        score for a kind is not a rule of that kind.
    #>
    param([AllowEmptyCollection()][object[]]$OrderedRows)
    $res = @{}
    foreach ($kind in 'Asset', 'Vulnerability') {
        $scoreCol = 'AssetBase'; $vCol = 'si_tier'
        if ($kind -eq 'Vulnerability') { $scoreCol = 'VulnerabilityBase'; $vCol = 'si_severity' }
        $list = [System.Collections.Generic.List[object]]::new()
        $pos = 0
        foreach ($r in @($OrderedRows)) {
            $pos++
            $s = Get-SIRiskIndexCellSi $r $scoreCol
            if ([string]::IsNullOrWhiteSpace($s)) { continue }
            $m = New-Object 'object[]' 7
            for ($i = 0; $i -lt 6; $i++) { $v = (Get-SIRiskIndexCellSi $r $script:SIRiskIndexSiMatchers[$i]).Trim(); $m[$i] = $(if ($v -eq '') { $null } else { $v.ToLowerInvariant() }) }
            $vv = (Get-SIRiskIndexCellSi $r $vCol).Trim(); $m[6] = $(if ($vv -eq '') { $null } else { $vv.ToLowerInvariant() })
            $n = 0.0
            [void][double]::TryParse($s.Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)
            $list.Add(@{ M = $m; Score = $n; Position = $pos })
        }
        $res[$kind] = $list.ToArray()
    }
    $res
}

function Find-SIRiskIndexSiRule {
    <#
        PURE. The first rule whose filled matchers all fit the finding's values. -Values: string[7] in the order
        si_finding_type, si_category, si_subcategory, si_component, si_finding_key, asset_class, tier-or-severity.
        asset_class: a matcher fits the same class or the class's family ('device' fits device_server / device_client).
    #>
    param([object[]]$Rules, [string[]]$Values)
    $lv = New-Object 'object[]' 7
    for ($i = 0; $i -lt 7; $i++) { $lv[$i] = $(if ([string]::IsNullOrWhiteSpace($Values[$i])) { $null } else { ([string]$Values[$i]).Trim().ToLowerInvariant() }) }
    $fam = $null; if ($lv[5]) { $u = ([string]$lv[5]).IndexOf('_'); if ($u -gt 0 -and ([string]$lv[5]).StartsWith('device_')) { $fam = ([string]$lv[5]).Substring(0, $u) } }
    foreach ($rule in $Rules) {
        $m = $rule.M; $fit = $true
        for ($i = 0; $i -lt 7; $i++) {
            if ($null -eq $m[$i]) { continue }
            if ($m[$i] -ceq $lv[$i]) { continue }
            if ($i -eq 5 -and $null -ne $fam -and $m[$i] -ceq $fam) { continue }
            $fit = $false; break
        }
        if ($fit) { return $rule }
    }
    $null
}

function New-SIRiskIndexSi {
    <#
        PURE. The SI-keyed risk index Calculate-RiskScore looks its two bases up in. -Rows the shipped index, -OverlayRows the
        customer's own rows (walked FIRST, #398). Either may be SI-keyed or v2.2-keyed (translated). Returns the index object.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [AllowEmptyCollection()][object[]]$OverlayRows = @(), [hashtable]$Translation)
    $Rows = @($Rows | Where-Object { $null -ne $_ }); $OverlayRows = @($OverlayRows | Where-Object { $null -ne $_ })
    $srcForm = $(if (Test-SIRiskIndexV22Form $Rows) { $(if (@(Get-SIRiskIndexRowColumns $Rows[0]) -contains 'Precedence') { 'v3-v2.2keys' } else { 'v2.2' }) } else { 'si' })
    $ovForm = ''
    if ($OverlayRows.Count) { $ovForm = $(if (Test-SIRiskIndexV22Form $OverlayRows) { $(if (@(Get-SIRiskIndexRowColumns $OverlayRows[0]) -contains 'Precedence') { 'v3-v2.2keys' } else { 'v2.2' }) } else { 'si' }) }
    $ov = @(); if ($OverlayRows.Count) { $ov = @(ConvertTo-SIRiskIndexSiRows -Rows $OverlayRows -Translation $Translation) }
    $sh = @(); if ($Rows.Count) { $sh = @(ConvertTo-SIRiskIndexSiRows -Rows $Rows -Translation $Translation) }
    $ordered = @($ov) + @($sh)
    $rules = New-SIRiskIndexSiRules -OrderedRows $ordered
    [pscustomobject]@{
        Form                 = 'si'
        Mode                 = 'first-match'
        OrderedRows          = $ordered
        OrderedRowCount      = $ordered.Count
        OverlayRowCount      = $ov.Count
        SourceForm           = $srcForm
        OverlayForm          = $ovForm
        Asset_Rules          = $rules['Asset']
        Vulnerability_Rules  = $rules['Vulnerability']
        # the column a row's security domain is read from when it has no asset class (kept for the callers' defaults)
        SecurityDomainColumn = 'SecurityDomain'
        Memo                 = ([System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal))
    }
}

function Get-SIRiskIndexAssetClass {
    <#
        PURE. The asset class the index keys on: device_server / device_client (a device with a known category or OS),
        device (a device neither says), identity, cloud_resource, public_ip; '' when the class is unknown.
    #>
    param([string]$Class, [string]$DeviceCategory, [string]$OsPlatform, [string]$OsName)
    $c = ([string]$Class).Trim().ToLowerInvariant()
    switch ($c) {
        'device' {
            $cat = ([string]$DeviceCategory).Trim().ToLowerInvariant()
            $os = (([string]$OsPlatform) + ' ' + ([string]$OsName)).Trim().ToLowerInvariant()
            if ($cat -eq 'server' -or $os -match 'server') { return 'device_server' }
            if ($cat -in 'endpoint', 'workstation', 'desktop', 'laptop', 'mobile', 'client') { return 'device_client' }
            if ($os -match '^(windows ?(7|8|10|11|xp|vista))|macos|mac os|ios|ipados|android') { return 'device_client' }
            return 'device'
        }
        { $_ -in 'identity', 'cloud_resource', 'public_ip' } { return $c }
        default { return '' }
    }
}

function Get-SIRiskIndexFindingValues {
    <#
        PURE. One finding row -> @{ Asset = string[7]; Vulnerability = string[7] } (the values the two lookups compare).
          si_finding_type  the row's si_finding_type, else 'cve' for a CVE key, else blank
          si_category      si_category, else the report's Category column (-CategoryInputName)
          si_subcategory   si_subcategory, else Subcategory / SubCategory (-SubCategoryInputName)
          si_component     si_component (#561), else blank
          si_finding_key   si_finding_key, else ConfigurationId (-ConfigurationIdInputName)
          asset_class      si_asset_class (the CI context), else the row's si_class split by its OS columns, else the
                           report's security domain translated (Endpoint -> device ...)
          tier             CriticalityTier (0..3), else the tier label translated, else si_tier
          severity         the severity label translated (keeps v2.2's Medium-High band), else si_severity
    #>
    param([Parameter(Mandatory)]$Row, [string]$CategoryInputName = 'Category', [string]$SubCategoryInputName = 'Subcategory',
          [string]$ConfigurationIdInputName = 'ConfigurationId', [string]$SecuritySeverityInputName = 'SecuritySeverity',
          [string]$CriticalityTierLevelInputName = 'CriticalityTierLevel', [string]$DomainValue = '', [hashtable]$Translation)
    if (-not $Translation) { $Translation = Get-SIRiskIndexTranslation }
    $g = { param($n) if (-not $n) { return '' }; $p = $Row.PSObject.Properties[$n]; if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n) -and $null -ne $Row[$n]) { return ([string]$Row[$n]).Trim() } else { return '' } }; if ($p -and $null -ne $p.Value) { return ([string]$p.Value).Trim() }; return '' }
    $first = { param([string[]]$names) foreach ($n in $names) { $v = & $g $n; if ($v -ne '') { return $v } }; return '' }
    $key = & $first @('si_finding_key', $ConfigurationIdInputName, 'ConfigurationId')
    $ftype = & $g 'si_finding_type'
    if ($ftype -eq '' -and $key -match '^(?i)CVE-\d{4}-\d+$') { $ftype = 'cve' }
    $cat = & $first @('si_category', $CategoryInputName, 'Category')
    $sub = & $first @('si_subcategory', $SubCategoryInputName, 'Subcategory', 'SubCategory')
    $comp = & $g 'si_component'
    $ac = & $g 'si_asset_class'
    if ($ac -eq '') {
        $cls = & $g 'si_class'
        if ($cls -ne '') { $ac = Get-SIRiskIndexAssetClass -Class $cls -DeviceCategory (& $first @('si_device_category', 'DeviceCategory')) -OsPlatform (& $first @('si_os_platform', 'OSPlatform', 'OsPlatform', 'MDE_OSPlatform')) -OsName (& $first @('si_os_name')) }
    }
    if ($ac -eq '') {
        $dom = $DomainValue; if (-not $dom) { $dom = & $first @('SecurityDomain', 'si_security_domain') }
        $ac = ConvertTo-SIRiskIndexSiValue -Column 'asset_class' -Value $dom -Translation $Translation
        if ($ac -eq 'device') {
            $os = & $first @('si_os_platform', 'OSPlatform', 'OsPlatform', 'MDE_OSPlatform')
            if ($os -ne '') { $ac = Get-SIRiskIndexAssetClass -Class 'device' -OsPlatform $os -DeviceCategory (& $first @('si_device_category', 'DeviceCategory')) }
        }
    }
    $tier = ''
    $tn = & $g 'CriticalityTier'
    $d = 0.0
    if ($tn -ne '' -and [double]::TryParse($tn, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $tier = [string][int][Math]::Floor($d) }
    if ($tier -eq '') { $tl = & $first @($CriticalityTierLevelInputName, 'CriticalityTierLevel'); if ($tl -ne '') { $tier = ConvertTo-SIRiskIndexSiValue -Column 'si_tier' -Value $tl -Translation $Translation } }
    if ($tier -eq '') { $tier = & $g 'si_tier' }
    $sev = ''
    $sl = & $first @($SecuritySeverityInputName, 'SecuritySeverity')
    if ($sl -ne '') { $sev = ConvertTo-SIRiskIndexSiValue -Column 'si_severity' -Value $sl -Translation $Translation }
    if ($sev -eq '') { $sev = (& $g 'si_severity').ToLowerInvariant() }
    $base = @($ftype, $cat, $sub, $comp, $key, $ac)
    return @{ Asset = [string[]](@($base) + @($tier)); Vulnerability = [string[]](@($base) + @($sev)) }
}

function Get-SIRiskIndexSiScore {
    <# PURE (memoised on the index). The base of one kind ('Asset' | 'Vulnerability') for the finding values: @{ Score; Position }
       (Position 0 = no row fits -> 0). #>
    param([Parameter(Mandatory)]$Index, [Parameter(Mandatory)][ValidateSet('Asset', 'Vulnerability')][string]$Kind, [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$Values)
    # the memo key: a loop, not a pipeline (this runs twice per finding row)
    $mkParts = [System.Collections.Generic.List[string]]::new([int]($Values.Count))
    foreach ($v in $Values) { $mkParts.Add(([string]$v).Trim().ToLowerInvariant()) }
    $mk = $Kind + [char]31 + ($mkParts -join [char]31)
    $hit = $null
    if ($Index.Memo -and $Index.Memo.TryGetValue($mk, [ref]$hit)) { return $hit }
    $rules = $Index.Asset_Rules; if ($Kind -eq 'Vulnerability') { $rules = $Index.Vulnerability_Rules }
    $rule = Find-SIRiskIndexSiRule -Rules @($rules) -Values $Values
    $res = $(if ($null -eq $rule) { @{ Score = 0.0; Position = 0 } } else { @{ Score = [double]$rule.Score; Position = [int]$rule.Position } })
    if ($Index.Memo) { $Index.Memo[$mk] = $res }
    $res
}

function ConvertTo-SIRiskIndexSiCsvText {
    <# PURE. SI rows in first-match order -> the CSV text the engine reads (SI columns, Precedence renumbered 1..n). #>
    param([AllowEmptyCollection()][object[]]$OrderedRows)
    $q = { param([string]$s) if ($s -match '[",\r\n]' -or $s -ne $s.Trim()) { '"' + $s.Replace('"', '""') + '"' } else { $s } }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add(($script:SIRiskIndexSiColumns -join ','))
    $k = 0
    foreach ($r in @($OrderedRows)) {
        $k++
        $lines.Add((@(foreach ($c in $script:SIRiskIndexSiColumns) { if ($c -eq 'Precedence') { [string]$k } else { & $q (Get-SIRiskIndexCellSi $r $c) } }) -join ','))
    }
    ($lines.ToArray() -join "`r`n") + "`r`n"
}
