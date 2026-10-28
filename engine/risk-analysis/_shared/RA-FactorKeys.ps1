#Requires -Version 5.1
<#
    ONE FACTOR, COUNTED ONCE -- the risk-factor key Risk Analysis compares tokens by.

    A risk factor reaches a finding row from up to three places: the report's own KQL (RF_P_InternetExposed ->
    "Internet-Exposed"), the CI context (the catalog id "internet_exposed", RA-CiContext.ps1) and the engine's own
    signals and asset baseline in Calculate-RiskScore ("InternetExposureSignal", "Tier0BlastRadius"). The catalog
    (data-model/risk-factors.locked.json) says which of those names are the SAME factor: every catalog factor lists the
    legacy tokens it replaces. This file turns that into one key per factor, so a token added by the engine or the CI
    is skipped when the row already carries the same factor under another name.

    Only factors the catalog evaluates (evaluatedBy = catalog) map: the 'report_scoped' entry lists tokens that are
    each their own factor inside one report, so they keep their own letters-only key.

    The report's OWN token list is never collapsed by this key (a report may emit two tokens a catalog factor groups,
    e.g. RF_P_Stale and RF_P_StaleLogin, and its score must not drop); only tokens ADDED on top of it are checked.

    PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode.
#>

# #559 the finding factors are evaluated on the row's SI fields with the data model's condition language
if (-not (Get-Command -Name Test-SIConditionTri -ErrorAction SilentlyContinue)) {
    $__raCond = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'data-model', 'SI-Conditions.ps1')
    if (Test-Path -LiteralPath $__raCond) { . $__raCond }
}
$script:RAFactorCatalogPath =[System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))), 'data-model', 'risk-factors.locked.json')

function ConvertTo-RALetterKey {
    <# PURE. A token by its letters only: RF_P_InternetExposed == Internet-Exposed == internet_exposed -> internetexposed. #>
    param([AllowNull()][AllowEmptyString()][string]$Token)
    (([string]$Token) -replace '^(?i)RF_[PC]_', '' -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
}

function New-RAFactorAliasMap {
    <# PURE. Catalog document -> @{ <letter key of a legacy token or id> = <letter key of the factor id> }. #>
    param($Catalog)
    $map = @{}
    foreach ($f in @($Catalog.factors)) {
        if ($null -eq $f -or [string]$f.evaluatedBy -ne 'catalog') { continue }
        $id = ConvertTo-RALetterKey ([string]$f.id)
        if (-not $id) { continue }
        $map[$id] = $id
        # #559 the SHORT name is what reports show now -- it is a token of its factor first (InternetExposed is internet_exposed)
        if ($f.PSObject.Properties['shortName']) { $k = ConvertTo-RALetterKey ([string]$f.shortName); if ($k -and -not $map.ContainsKey($k)) { $map[$k] = $id } }
        foreach ($t in @($f.legacyTokens)) { $k = ConvertTo-RALetterKey ([string]$t); if ($k -and -not $map.ContainsKey($k)) { $map[$k] = $id } }
        # the catalog's description (name) is a token too (reports showed it 2026-10-10 .. #559), so "Client secret in use" is has_secret
        if ($f.PSObject.Properties['name']) { $k = ConvertTo-RALetterKey ([string]$f.name); if ($k -and -not $map.ContainsKey($k)) { $map[$k] = $id } }
    }
    return $map
}

# ================================================================================================================
# #559 RISK FACTOR MODEL V2 in the score -- each factor's short name, side and impact, keyed like the alias map.
# The engine-side twin of SI-RiskFactorCatalog.ps1's Get-SIRiskFactorState / -Side / -Impact / -ShortName (Risk
# Analysis loads without the data-model scripts in its tests); tests/pester/SIv3-RiskFactorModelV2.Tests.ps1 proves the
# two agree on every shipped factor.
# ================================================================================================================

# tokens that name something that is NOT a risk factor any more: they are dropped from the score and the report column
# (#559: break glass is a classification -- si_is_break_glass feeds the tier rules and the break-glass reports)
$script:RARetiredFactorTokens = @('RF_P_BreakGlass', 'break_glass', 'BreakGlass', 'Emergency-access account')

function Get-RAFactorMeta {
    <#
        PURE. One catalog factor -> @{ Id; ShortName; Side = asset | vulnerability; Impact (what it adds when enabled, 1..5;
        0 when disabled); Enabled; Axis; ReportScoped }. A built-in factor is always enabled; a factor without a state
        follows its pre-v2 stage (not_used / testing = disabled).
    #>
    param($Factor)
    $g = { param($n) $p = $Factor.PSObject.Properties[$n]; if ($Factor -is [System.Collections.IDictionary]) { if ($Factor.Contains($n)) { return $Factor[$n] } else { return $null } }; if ($p) { return $p.Value }; return $null }
    $id = [string](& $g 'id')
    $cls = [string](& $g 'class')
    $st = ([string](& $g 'state')).Trim().ToLowerInvariant()
    $stage = ([string](& $g 'stage')).Trim().ToLowerInvariant()
    $enabled = $true
    # a factor without a class is built-in (the contract the web app reads it by); only 'optional' can be switched off
    if ($cls -eq 'optional') {
        if ($st -eq 'disabled') { $enabled = $false }
        elseif ($st -eq '' -and $stage -in 'not_used', 'testing') { $enabled = $false }
    }
    $imp = 0.0
    $raw = & $g 'impact'
    $ok = $false
    if ($null -ne $raw) { $ok = [double]::TryParse(([string]$raw).Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$imp) }
    if (-not $ok) { $imp = 1.0 }
    if ($imp -lt 1) { $imp = 1.0 }
    if ($imp -gt 5) { $imp = 5.0 }
    $sn = ([string](& $g 'shortName')).Trim()
    if (-not $sn) { $sn = ([string](& $g 'name')).Trim() }
    if (-not $sn) { $sn = $id }
    $side = 'asset'; if ([string](& $g 'appliesTo') -eq 'finding') { $side = 'vulnerability' }
    return @{ Id = $id; ShortName = $sn; Side = $side; Impact = $(if ($enabled) { [int][Math]::Round($imp) } else { 0 }); Enabled = $enabled; Axis = [string](& $g 'axis'); ReportScoped = ($id -eq 'report_scoped' -or [string](& $g 'evaluatedBy') -eq 'report') }
}

function New-RAFactorImpactMap {
    <#
        PURE. Catalog document -> @{ ByKey = <letter key of an id / short name / legacy token / name> -> Get-RAFactorMeta;
        ById = id -> meta; ReportScoped = the report_scoped entry's meta (the impact a report's own token counts with);
        Retired = letter keys of tokens that are no factor (#559 break glass) }. Report-scoped legacy tokens map to the
        report_scoped entry under their OWN key (each is its own factor inside its report).
    #>
    param($Catalog)
    $byKey = @{}; $byId = @{}; $rs = $null
    foreach ($f in @($Catalog.factors)) {
        if ($null -eq $f) { continue }
        $m = Get-RAFactorMeta $f
        if (-not $m.Id) { continue }
        $byId[$m.Id] = $m
        if ($m.Id -eq 'report_scoped') { $rs = $m; continue }
        if ([string]$f.evaluatedBy -ne 'catalog') { continue }
        $aliases = @($m.Id, $m.ShortName) + @($f.legacyTokens)
        if ($f.PSObject.Properties['name']) { $aliases += [string]$f.name }
        foreach ($t in $aliases) { $k = ConvertTo-RALetterKey ([string]$t); if ($k -and -not $byKey.ContainsKey($k)) { $byKey[$k] = $m } }
    }
    if ($null -eq $rs) { $rs = @{ Id = 'report_scoped'; ShortName = 'ReportFactor'; Side = 'vulnerability'; Impact = 1; Enabled = $true; Axis = 'probability'; ReportScoped = $true } }
    $retired = @{}; foreach ($t in $script:RARetiredFactorTokens) { $k = ConvertTo-RALetterKey $t; if ($k) { $retired[$k] = $true } }
    foreach ($k in @($retired.Keys)) { if ($byKey.ContainsKey($k)) { $retired.Remove($k) } }   # a catalog factor of that name wins (a customer's own)
    return @{ ByKey = $byKey; ById = $byId; ReportScoped = $rs; Retired = $retired }
}

function Get-RAFactorCatalogFactors {
    <# The run's catalog factors, read once per process (data model + overlay when it loads, else the shipped file). The
       built-in factors a customer override tried to disable are enabled again here and said once in the run log (#559,
       Resolve-SIRiskFactorBuiltinState when the data-model scripts are loaded). #>
    if ($null -ne $global:RA_FactorCatalogFactors) { return @($global:RA_FactorCatalogFactors) }
    $f = $null
    if ($global:SI_DataModelRoot -or $global:SI_DataModelOverlayRoot) {
        try {
            if (Get-Command -Name Get-SIDataModel -ErrorAction SilentlyContinue) {
                $m = Get-SIDataModel -OverlayRoot $global:SI_DataModelOverlayRoot
                $f = @($m['risk-factors'].factors)
            }
        } catch { $f = $null }
    }
    if ($null -eq $f) {
        try { if (Test-Path -LiteralPath $script:RAFactorCatalogPath) { $f = @(([System.IO.File]::ReadAllText($script:RAFactorCatalogPath) | ConvertFrom-Json).factors) } } catch { $f = $null }
    }
    if ($null -eq $f) { $f = @() }
    if (Get-Command -Name Resolve-SIRiskFactorBuiltinState -ErrorAction SilentlyContinue) {
        $res = Resolve-SIRiskFactorBuiltinState -Factors $f
        foreach ($line in @($res.Lines)) { Write-Warning $line }
    }
    $global:RA_FactorCatalogFactors = $f
    return @($f)
}

function ConvertTo-RARiskRatingBands {
    <# PURE. A risk_rating_bands list -> @(critical, high, moderate) thresholds; $null when the list is missing or not three
       whole numbers > 0, highest first (the caller then uses the built-in 50 / 30 / 15). #>
    param($List)
    if ($null -eq $List) { return $null }
    $vals = $null
    if ($List -is [System.Collections.IDictionary]) { $vals = $List['values'] } elseif ($List.PSObject.Properties['values']) { $vals = $List.values }
    $n = @()
    foreach ($v in @($vals)) { $d = 0.0; if (-not [double]::TryParse(([string]$v).Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $null }; $n += $d }
    if ($n.Count -ne 3 -or $n[2] -le 0 -or $n[0] -le $n[1] -or $n[1] -le $n[2]) { return $null }
    return $n
}

function Get-RARiskRatingBands {
    <# The run's risk rating bands (data-model list risk_rating_bands, the customer's override included), read once per
       process; the built-in 50 / 30 / 15 when the list is missing or invalid (the validation reports an invalid one). #>
    if ($null -ne $global:RA_RiskRatingBands) { return @($global:RA_RiskRatingBands) }
    $b = $null
    if ($global:SI_DataModelRoot -or $global:SI_DataModelOverlayRoot) {
        try {
            if (Get-Command -Name Get-SIDataModel -ErrorAction SilentlyContinue) {
                $m = Get-SIDataModel -OverlayRoot $global:SI_DataModelOverlayRoot
                $b = ConvertTo-RARiskRatingBands (@($m['lists'].lists) | Where-Object { $_ -and [string]$_.id -eq 'risk_rating_bands' } | Select-Object -First 1)
            }
        } catch { $b = $null }
    }
    if ($null -eq $b) {
        try {
            $lp = [System.IO.Path]::Combine((Split-Path -Parent $script:RAFactorCatalogPath), 'lists.locked.json')
            if (Test-Path -LiteralPath $lp) { $b = ConvertTo-RARiskRatingBands (@(([System.IO.File]::ReadAllText($lp) | ConvertFrom-Json).lists) | Where-Object { $_ -and [string]$_.id -eq 'risk_rating_bands' } | Select-Object -First 1) }
        } catch { $b = $null }
    }
    if ($null -eq $b) { $b = @(50.0, 30.0, 15.0) }
    $global:RA_RiskRatingBands = $b
    return @($b)
}

function Get-RAFactorImpactMap {
    <# The run's impact map, built once per process from the run's catalog (data model + overlay, else the shipped file). #>
    if ($global:RA_FactorImpactMap -is [hashtable]) { return $global:RA_FactorImpactMap }
    $global:RA_FactorImpactMap = New-RAFactorImpactMap -Catalog ([pscustomobject]@{ factors = @(Get-RAFactorCatalogFactors) })
    return $global:RA_FactorImpactMap
}

function Get-RARiskFactorLegendRows {
    <#
    .SYNOPSIS  #558 / #559 the "Risk factors" legend of every Excel export (a sheet) and PDF (an appendix): one row per
               catalog factor -- ShortName, Description, AppliesTo ("Asset" / "Vulnerability"), Impact, Class, Group, State,
               Id -- asset factors first, then vulnerability factors, by group and short name. The run's catalog (the
               customer's impacts and states) unless -Factors is given. The engine-side twin of SI-RiskFactorCatalog.ps1
               Get-SIRiskFactorLegend (same rows; a test proves it).
    #>
    param([AllowEmptyCollection()][object[]]$Factors)
    if (-not $PSBoundParameters.ContainsKey('Factors')) { $Factors = @(Get-RAFactorCatalogFactors) }
    $groups = @('Exposure', 'Device health', 'Identity', 'Privilege', 'Apps', 'Importance', 'Exploitability', 'Impact', 'Severity', 'Lifecycle')
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($f in @($Factors)) {
        if ($null -eq $f) { continue }
        $m = Get-RAFactorMeta $f
        if (-not $m.Id) { continue }
        $desc = ''; if ($f.PSObject.Properties['name']) { $desc = ([string]$f.name).Trim() }
        if (-not $desc -and $f.PSObject.Properties['description']) { $desc = ([string]$f.description).Trim() }
        $cls = 'Built-in'; if ($f.PSObject.Properties['class'] -and [string]$f.class -eq 'optional') { $cls = 'Optional' }
        $grp = ''; if ($f.PSObject.Properties['group']) { $grp = [string]$f.group }
        $rows.Add([pscustomobject][ordered]@{
                ShortName   = $m.ShortName
                Description = $desc
                AppliesTo   = $(if ($m.Side -eq 'vulnerability') { 'Vulnerability' } else { 'Asset' })
                Impact      = [int]$m.Impact
                Class       = $cls
                Group       = $grp
                State       = $(if ($m.Enabled) { 'Enabled' } else { 'Disabled' })
                Id          = $m.Id
            })
    }
    $gi = @{}; for ($i = 0; $i -lt $groups.Count; $i++) { $gi[$groups[$i]] = $i }
    return @($rows | Sort-Object -Property @{ Expression = { if ($_.AppliesTo -eq 'Asset') { 0 } else { 1 } } }, @{ Expression = { if ($gi.ContainsKey($_.Group)) { $gi[$_.Group] } else { 99 } } }, ShortName)
}

function Measure-RARowFactors {
    <#
    .SYNOPSIS  PURE. #559 THE FACTOR PART OF ONE ROW'S SCORE. The row's tokens -> each factor ONCE, on its side, with its
               impact; the sums are what the two sides add (no cap).
                 * a token that names a catalog factor (id, short name, legacy token, description) is that factor: its side
                   (asset factor -> asset side, finding factor -> vulnerability side), its impact, shown by its SHORT name;
                   a disabled factor is dropped (not shown, adds 0)
                 * a token the catalog does not know is a report-scoped factor (the report's own question): it keeps the
                   side its column put it on (-AssetTokens = the asset side, -VulnerabilityTokens = the vulnerability side)
                   and counts the report_scoped entry's impact (default 1); shown as the report wrote it
                 * a retired token (break glass, #559) is dropped
                 * ONE FACTOR COUNTS ONCE: the same factor under two names, or on both lists, counts once (on its own side)
                 * -UnnamedAssetCount: a report that gave its factors as a NUMBER only (no names) -- each counts the
                   report_scoped impact on the asset side (the side those numbers always sat on)
               Returns @{ AssetTokens; VulnerabilityTokens (display names, in arrival order); AssetImpact; VulnerabilityImpact;
               AssetIds; VulnerabilityIds (the catalog ids that counted) }.
    #>
    param([AllowEmptyCollection()][string[]]$AssetTokens = @(), [AllowEmptyCollection()][string[]]$VulnerabilityTokens = @(),
          [int]$UnnamedAssetCount = 0, [hashtable]$Map)
    if (-not $Map) { $Map = Get-RAFactorImpactMap }
    $seen = @{}
    $aT = [System.Collections.Generic.List[string]]::new(); $vT = [System.Collections.Generic.List[string]]::new()
    $aI = [System.Collections.Generic.List[string]]::new(); $vI = [System.Collections.Generic.List[string]]::new()
    $aSum = 0; $vSum = 0
    # #910 each counted factor with its impact ("Name=impact"), in the order of the names -- the explained score
    $aX = [System.Collections.Generic.List[string]]::new(); $vX = [System.Collections.Generic.List[string]]::new()
    $rs = $Map.ReportScoped
    # (a list, never += on an array in a loop)
    $walk = [System.Collections.Generic.List[object]]::new()
    foreach ($t in @($AssetTokens)) { $walk.Add(@('asset', [string]$t)) }
    foreach ($t in @($VulnerabilityTokens)) { $walk.Add(@('vulnerability', [string]$t)) }
    foreach ($w in $walk) {
        $tok = $w[1].Trim()
        if (-not $tok) { continue }
        $k = ConvertTo-RALetterKey $tok
        if (-not $k) { continue }
        if ($Map.Retired.ContainsKey($k)) { continue }
        if ($Map.ByKey.ContainsKey($k)) {
            $m = $Map.ByKey[$k]
            $sk = 'id:' + $m.Id
            if ($seen.ContainsKey($sk)) { continue }
            $seen[$sk] = $true
            if (-not $m.Enabled) { continue }
            if ($m.Side -eq 'vulnerability') { $vT.Add($m.ShortName); $vI.Add($m.Id); $vSum += [int]$m.Impact; $vX.Add($m.ShortName + '=' + [int]$m.Impact) }
            else { $aT.Add($m.ShortName); $aI.Add($m.Id); $aSum += [int]$m.Impact; $aX.Add($m.ShortName + '=' + [int]$m.Impact) }
            continue
        }
        $sk = 'tok:' + $k
        if ($seen.ContainsKey($sk)) { continue }
        $seen[$sk] = $true
        if (-not $rs.Enabled) { continue }
        if ($w[0] -eq 'vulnerability') { $vT.Add($tok); $vSum += [int]$rs.Impact; $vX.Add($tok + '=' + [int]$rs.Impact) } else { $aT.Add($tok); $aSum += [int]$rs.Impact; $aX.Add($tok + '=' + [int]$rs.Impact) }
    }
    if ($UnnamedAssetCount -gt 0 -and $rs.Enabled) { $aSum += ($UnnamedAssetCount * [int]$rs.Impact); for ($u = 0; $u -lt $UnnamedAssetCount; $u++) { $aX.Add('ReportFactor=' + [int]$rs.Impact) } }
    return @{ AssetTokens = $aT.ToArray(); VulnerabilityTokens = $vT.ToArray(); AssetImpact = $aSum; VulnerabilityImpact = $vSum; AssetIds = $aI.ToArray(); VulnerabilityIds = $vI.ToArray(); AssetImpacts = $aX.ToArray(); VulnerabilityImpacts = $vX.ToArray() }
}

function Get-RAFindingFactorTokens {
    <#
    .SYNOPSIS  #559 the catalog's FINDING factors evaluated on one finding row over its SI fields (si_exploit_verified,
               si_in_exploit_kit, si_cvss_vector, si_fix_available, si_due_date, si_published, ... -- #560 maps them per
               source). Returns the short names of the enabled finding factors whose condition HOLDS. A field the row does
               not carry (or carries empty) is UNKNOWN, and unknown is never a finding (#546): the factor is simply not
               added. Report-scoped entries and asset factors are never evaluated here. Needs SI-Conditions.ps1
               (Test-SIConditionTri); without it nothing is added.
    #>
    param([Parameter(Mandatory)]$Row, [AllowEmptyCollection()][object[]]$Factors = @(), [hashtable]$Context = @{},
          # PERFORMANCE: New-RAFindingFactorPlan over the same factors -- the per-factor work (meta, condition fields) done
          # once per slice instead of once per row; the evaluation is the same
          [hashtable]$Plan)
    $out = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $Plan) {
        if (-not $Plan.Ready) { return $out.ToArray() }
        $item = @{}
        foreach ($p in $Row.PSObject.Properties) { if ($p.Name -like 'si_*') { $item[$p.Name] = $p.Value } }
        foreach ($it in $Plan.Items) {
            $m = $it.Meta
            $unknown = [System.Collections.Generic.List[string]]::new()
            foreach ($fn in $it.Fields) {
                $v = $null; if ($item.ContainsKey([string]$fn)) { $v = $item[[string]$fn] }
                if ($null -eq $v -or ([string]$v).Trim() -eq '') { $unknown.Add([string]$fn) }
            }
            $hit = $null
            try { $hit = Test-SIConditionTri -Condition $it.Factor.when -Item $item -Context $Context -UnknownFields $unknown.ToArray() } catch { $hit = $null }
            if ($hit -eq $true) { $out.Add($m.ShortName) }
        }
        return $out.ToArray()
    }
    if (-not (Get-Command -Name Test-SIConditionTri -ErrorAction SilentlyContinue)) { return $out.ToArray() }
    $item = @{}
    foreach ($p in $Row.PSObject.Properties) { if ($p.Name -like 'si_*') { $item[$p.Name] = $p.Value } }
    foreach ($f in $Factors) {
        if ($null -eq $f -or [string]$f.appliesTo -ne 'finding' -or [string]$f.evaluatedBy -ne 'catalog') { continue }
        $m = Get-RAFactorMeta $f
        if (-not $m.Enabled -or $m.ReportScoped) { continue }
        $unknown = [System.Collections.Generic.List[string]]::new()
        foreach ($fn in (Get-SIConditionFields $f.when)) {
            $v = $null; if ($item.ContainsKey([string]$fn)) { $v = $item[[string]$fn] }
            if ($null -eq $v -or ([string]$v).Trim() -eq '') { $unknown.Add([string]$fn) }
        }
        $hit = $null
        try { $hit = Test-SIConditionTri -Condition $f.when -Item $item -Context $Context -UnknownFields $unknown.ToArray() } catch { $hit = $null }
        if ($hit -eq $true) { $out.Add($m.ShortName) }
    }
    return $out.ToArray()
}

function New-RAFindingFactorPlan {
    <#
    .SYNOPSIS  PERFORMANCE. The part of Get-RAFindingFactorTokens that is the same for every row: the finding factors it
               evaluates (finding, catalog-evaluated, enabled, not report-scoped -- the same filter, in catalog order), each
               with its meta and the fields its condition reads; Fields = every such field once. Ready = the condition
               language is loaded (without it nothing is added, as before).
    #>
    param([AllowEmptyCollection()][object[]]$Factors = @())
    $items = [System.Collections.Generic.List[object]]::new()
    $fields = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ready = [bool](Get-Command -Name Test-SIConditionTri -ErrorAction SilentlyContinue)
    if ($ready) {
        foreach ($f in $Factors) {
            if ($null -eq $f -or [string]$f.appliesTo -ne 'finding' -or [string]$f.evaluatedBy -ne 'catalog') { continue }
            $m = Get-RAFactorMeta $f
            if (-not $m.Enabled -or $m.ReportScoped) { continue }
            $fl = [System.Collections.Generic.List[string]]::new()
            foreach ($fn in (Get-SIConditionFields $f.when)) { $fl.Add([string]$fn); if ($seen.Add([string]$fn)) { $fields.Add([string]$fn) } }
            $items.Add(@{ Factor = $f; Meta = $m; Fields = $fl.ToArray() })
        }
    }
    @{ Items = $items.ToArray(); Fields = $fields.ToArray(); Ready = $ready }
}

function Get-RAFindingFactorPlanKey {
    <#
    .SYNOPSIS  PERFORMANCE. PURE. The values of the fields the plan's conditions read on one row, as one text: two rows with
               the same key get the same finding factors (a condition reads nothing else -- with no lists in the context, an
               in_list leaf fails the same way for every row). $null when a value is not a plain value (a list, an object):
               such a row is evaluated on its own. Only si_* columns count (the item Get-RAFindingFactorTokens builds).
    #>
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][hashtable]$Plan)
    $props = $Row.PSObject.Properties
    $sb = New-Object System.Text.StringBuilder
    foreach ($fn in $Plan.Fields) {
        $v = $null
        if ($fn -like 'si_*') { $p = $props[$fn]; if ($p) { $v = $p.Value } }
        if ($v -is [System.Management.Automation.PSObject]) { $v = $v.PSObject.BaseObject }
        if ($null -eq $v) { [void]$sb.Append('~') }
        elseif ($v -is [string]) { [void]$sb.Append('s').Append($v.Length).Append(':').Append($v) }
        elseif ($v -is [bool]) { [void]$sb.Append('b').Append($(if ($v) { '1' } else { '0' })) }
        elseif ($v -is [datetime]) { [void]$sb.Append('d').Append($v.Ticks).Append('k').Append([int]$v.Kind) }
        elseif ($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal] -or $v -is [single] -or $v -is [int16] -or $v -is [byte]) {
            $t = ([System.IFormattable]$v).ToString($(if ($v -is [double] -or $v -is [single]) { 'R' } else { $null }), [System.Globalization.CultureInfo]::InvariantCulture)
            [void]$sb.Append('n').Append($v.GetType().Name).Append(':').Append($t)
        }
        else { return $null }
        [void]$sb.Append([char]0)
    }
    $sb.ToString()
}

function Get-RAFactorAliasMap {
    <# The shipped catalog's alias map, read once per process. Empty when the catalog cannot be read (letters-only keys then). #>
    if ($global:RA_FactorAliasMap -is [hashtable]) { return $global:RA_FactorAliasMap }
    $map = @{}
    # the run's catalog when the data model is loaded (Pro: the settings database's, Community: with its custom file) --
    # a factor the customer renamed in the catalog is still recognised by its new display name
    if ($global:SI_DataModelRoot -or $global:SI_DataModelOverlayRoot) {
        try {
            if (Get-Command -Name Get-SIDataModel -ErrorAction SilentlyContinue) {
                $m = Get-SIDataModel -OverlayRoot $global:SI_DataModelOverlayRoot
                $map = New-RAFactorAliasMap -Catalog ([pscustomobject]@{ factors = @($m['risk-factors'].factors) })
                if ($map.Count) { $global:RA_FactorAliasMap = $map; return $map }
            }
        } catch { $map = @{} }
    }
    try {
        if (Test-Path -LiteralPath $script:RAFactorCatalogPath) {
            $map = New-RAFactorAliasMap -Catalog ([System.IO.File]::ReadAllText($script:RAFactorCatalogPath) | ConvertFrom-Json)
        }
    } catch { $map = @{} }
    $global:RA_FactorAliasMap = $map
    return $map
}

function ConvertTo-RAFactorKey {
    <# A token -> the key of the factor it names (the catalog id's letters when the catalog knows it, else its own letters). #>
    param([AllowNull()][AllowEmptyString()][string]$Token, [hashtable]$Map)
    $k = ConvertTo-RALetterKey $Token
    if (-not $Map) { $Map = Get-RAFactorAliasMap }
    if ($k -and $Map.ContainsKey($k)) { return [string]$Map[$k] }
    return $k
}

function Get-RACiFactorColumns {
    <# The catalog factors that have their own SI_CI_CL column (ciColumn), as column names si_rf_<id>. #>
    $cat = $null
    try { if (Test-Path -LiteralPath $script:RAFactorCatalogPath) { $cat = [System.IO.File]::ReadAllText($script:RAFactorCatalogPath) | ConvertFrom-Json } } catch { $cat = $null }
    if ($null -eq $cat) { return @() }
    @(@($cat.factors) | Where-Object { $_ -and [string]$_.appliesTo -eq 'asset' -and [string]$_.evaluatedBy -eq 'catalog' -and $_.PSObject.Properties['ciColumn'] -and $_.ciColumn -eq $true } | ForEach-Object { 'si_rf_' + [string]$_.id })
}

function Get-RACiFactorKql {
    <#
        #464 -- a KQL helper a report CAN use: _SiCiFactors() = one row per CI (its latest FULL SI_CI_CL row within
        SI_ActiveStaleDays, default 30) with its provider links and the catalog's per-CI factor columns: si_rf_<id>
        (true / false, null before the CI build wrote it) and si_rf_count. A report joins it on the id it carries
        (si_link_mde = DeviceId, si_link_entra = AccountObjectId, si_link_azure = ResourceId, si_link_eg = NodeId) instead of
        computing InternetExposed / NoMFA / ... from its own sources. Log Analytics only (SI_CI_CL is a workspace table).
        A report asks for it with the marker line //__SI_CI_FACTORS__ (Resolve-RACiFactorsBlock).
    #>
    param([int]$LookbackDays = 0)
    if ($LookbackDays -le 0) { $LookbackDays = 30; if ($global:SI_ActiveStaleDays -and [int]$global:SI_ActiveStaleDays -gt 0) { $LookbackDays = [int]$global:SI_ActiveStaleDays } }
    $cols = @(Get-RACiFactorColumns | ForEach-Object { "{0} = tobool(column_ifexists('{0}', bool(null)))" -f $_ })
    $proj = @("si_ci_id = si_k_", "si_class = tostring(column_ifexists('si_class', ''))", "si_tier = toint(column_ifexists('si_tier', int(null)))") +
            @('si_link_mde', 'si_link_entra', 'si_link_azure', 'si_link_eg', 'si_link_ad', 'si_link_intune' | ForEach-Object { "{0} = tolower(tostring(column_ifexists('{0}', '')))" -f $_ }) +
            @("si_rf_count = toint(column_ifexists('si_rf_count', int(null)))") + $cols +
            # #546 field authority by identity origin: the identity facts as the CI build resolved them (AD / Defender for
            # Identity for a synchronised account, Entra for a cloud-only one), the factors it could not decide, and whether
            # the sign-in is KNOWN -- a CI row without an origin (written before #546) is not known: unknown is never a finding
            @("si_identity_origin = tostring(column_ifexists('si_identity_origin', ''))",
              "si_unknown_fields = column_ifexists('si_unknown_fields', dynamic(null))",
              "si_rf_unknown = column_ifexists('si_rf_unknown', dynamic(null))",
              "si_password_last_changed = todatetime(column_ifexists('si_password_last_changed', datetime(null)))",
              "si_password_never_expires = tobool(column_ifexists('si_password_never_expires', bool(null)))",
              "si_last_sign_in = todatetime(column_ifexists('si_last_sign_in', datetime(null)))",
              "si_sign_in_known = toint(isnotempty(tostring(column_ifexists('si_identity_origin', ''))) and coalesce(array_index_of(todynamic(column_ifexists('si_unknown_fields', dynamic(null))), 'si_last_sign_in'), -1) < 0)",
              "si_password_known = toint(isnotempty(tostring(column_ifexists('si_identity_origin', ''))) and coalesce(array_index_of(todynamic(column_ifexists('si_unknown_fields', dynamic(null))), 'si_password_last_changed'), -1) < 0)")
    @"
let _SiCiFactors = () {
    SI_CI_CL
    | where TimeGenerated > ago($($LookbackDays)d)
    | where tostring(column_ifexists('si_row_kind', '')) in ('full', '')
    | extend si_k_ = tostring(si_ci_id), si_t_ = todatetime(si_collection_time)
    | where isnotempty(si_k_)
    | summarize arg_max(si_t_, *) by si_k_
    | project $($proj -join ', ')
};
"@
}

function Resolve-RACiFactorsBlock {
    <# A query's //__SI_CI_FACTORS__ marker line -> the _SiCiFactors() helper (Get-RACiFactorKql). No marker: unchanged. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query)
    $rx = '(?m)^[ \t]*//__SI_CI_FACTORS__[ \t]*\r?$'
    if (-not [regex]::IsMatch($Query, $rx)) { return $Query }
    $kql = Get-RACiFactorKql
    return [regex]::Replace($Query, $rx, { param($m) $kql.TrimEnd() }, 'Multiline')
}

# #541: the tier factors removed from the catalog (#527). Tier counts ONLY through the tier multiplier and the risk index --
# no report emits these as a factor (the ids, their legacy tokens, and the privileged / tier-0 tokens reports used to compute
# themselves). tests/pester/SIv3-RaScopePreamble.Tests.ps1 refuses a shipped query that still names one.
$script:RARetiredTierFactorIds = @('tier0', 'tier0_or_1', 'tier0_blast_radius', 'adfs_server', 'exchange_server', 'business_critical_asset')
$script:RARetiredTierTokens = @('RF_P_Tier0', 'RF_P_ADTier0', 'RF_P_Tier01', 'RF_P_Privileged', 'IsAdfsServer', 'IsExchangeServer', 'Tier0BlastRadius',
    'BusinessCriticalAsset', 'PrivilegedSPN', 'Tier0Identity', 'Tier0ServiceAccount', 'ServiceAccountPrivileged', 'HasPrivilegedRole', 'Tier0Admin',
    'Tier0EligibleAdmin', 'Tier0EligibleRole', 'Tier0CloudRole', 'Tier0Permissions', 'Tier0Asset', 'PrivilegedIdentity', 'ServiceAccountIsPrivileged')
function Get-RARetiredTierFactors { @{ Ids = @($script:RARetiredTierFactorIds); Tokens = @($script:RARetiredTierTokens) } }