#Requires -Version 5.1
<#
    SecurityInsight Pro -- OUTPUT SCOPE PER DESTINATION (#274).

    Risk Analysis decides WHAT is found (each report's own severity / tier scope, the report templates). The output scope
    decides what each DESTINATION receives of it:
        excel             Risk Analysis's own read-time view: the workbook, the JSON sibling, the AI summary, the KPIs and
                          the mail (the rows Select-RAReportRows keeps). Log Analytics always receives every row.
        vuln-sql          the vulnerability close-loop's SQL connector(s)          (Invoke-SIVulnLoop.ps1, the plan step)
        vuln-servicenow   the vulnerability close-loop's ServiceNow connector(s)   (Invoke-SIVulnLoop.ps1, the plan step)
        cmdb-sql          the SQL CMDB connector -- an ASSET scope (tiers, asset kinds)
        cmdb-servicenow   the ServiceNow CMDB connector (Invoke-SICmdb.ps1) -- an ASSET scope (tiers, asset kinds)

    Where it comes from: the Pro settings database (cfg.ItemOverride, kind 'outputscope', one item per destination),
    materialised by Export-SIProConfig into <run>\config\output-scope.json (SI_ProConfigRoot) with every named report
    template already resolved to its reports. No file, or no entry for a destination = everything passes (today's
    behaviour, unchanged).

    THE RULE (one rule, the C# preview counts with the same one -- SI.Management.Core.ProData.OutputScope):
      - an empty list = any value passes;
      - a BLANK value on a row passes (as Risk Analysis's own scope filter keeps blanks -- IncludeBlank);
      - severity compares by its key (case, spaces, '-' and '_' do not count; Critical = Very High, as #246);
      - tier compares by number (0..3): a number, or a tier label ("High - tier 1");
      - reports: the row passes when ANY of its report names is in the resolved report list.
      - FILTERS (owner 2026-10-19, "define filters on one or more filters like risk rating"): 'filters' = { "<SI field>":
        { "values": [...] } } -- risk rating, class, component, patch cycle, OS family, ServiceNow sub-CI, or any other SI
        field of the finding (si_*). A row passes a filter when ANY of its values for the field is one of the values (case
        does not count; OR within a filter); every filter must pass (AND across). A row WITHOUT a value for the field does
        not pass a filter on it (owner: "we can NOT have a finding without a risk rating" -- such a row is raised as
        "Classification incomplete", never hidden by a scope). The old lists (severities, tiers, domains) keep today's rule
        -- a blank passes -- so no scope in force changes.

    🔒 A SCOPE NEVER CLOSES ANYTHING AS FIXED. The CMDB connectors leave a CI that is out of scope exactly as it is. The
    vulnerability connectors (#279 decision 3, operator 2026-10-04) close an open record whose finding left the scope
    with the reason 'Out of scope' -- never Remediated, never counted by the close ceiling -- and reopen it when it comes
    back: narrowing a scope can never read as "remediated" (#217, rule 4).

    The SQL CMDB connector (Invoke-SICmdbSql.ps1) passes Get-SIOutputScope -Destination 'cmdb-sql' to its sync core, which
    narrows BOTH sides of its plan (Select-SICmdbScopedPlanInput) -- it retires absent CIs, so a scope must never make a CI
    read as absent. The ServiceNow CMDB connector has no link store yet (it never closes); it filters its asset list.

    NO Set-StrictMode here -- it leaks into the caller's scope.
#>

$script:SIOutputScopeDestinations = [ordered]@{
    'excel'           = @{ Asset = $false; Label = 'Excel + mail' }
    'vuln-sql'        = @{ Asset = $false; Label = 'Vulnerability connector (SQL)' }
    'vuln-servicenow' = @{ Asset = $false; Label = 'Vulnerability connector (ServiceNow)' }
    'cmdb-sql'        = @{ Asset = $true;  Label = 'CMDB connector (SQL)' }
    'cmdb-servicenow' = @{ Asset = $true;  Label = 'CMDB connector (ServiceNow)' }
}
$script:SIOutputScopeFile = 'output-scope.json'
$script:SIOutputScopeSeverityKeys = @('veryhigh', 'high', 'mediumhigh', 'medium', 'low', 'informational')
$script:SIOutputScopeDomains = @('Endpoint', 'Identity', 'Azure', 'PublicIP')
# #817 (owner 2026-10-20: "i should see all asset kinds incl. public ip + identity ... dont limit options"): every kind
# the data holds -- the C# twin is ReportVocabulary.AssetKinds
$script:SIOutputScopeAssetKinds = @('endpoint', 'identity', 'azure', 'publicip')

# The fields a scope filter offers by name (any other si_* field of the finding is accepted too): the columns a row
# carries it under (first that has a value -- a Risk Analysis row names the risk rating RiskRating), its values when the
# list is closed, and the default for a row without a value. The web app's twin: OutputScopeFilter.Fields (C#).
$script:SIOutputScopeFilterFields = [ordered]@{
    'si_risk_rating'      = @{ Label = 'Risk rating'; Columns = @('RiskRating', 'si_risk_rating'); Values = @('Critical', 'High', 'Moderate', 'Low') }
    'si_category'         = @{ Label = 'Category'; Columns = @('si_category', 'Category'); Values = @() }
    'si_subcategory'      = @{ Label = 'Subcategory'; Columns = @('si_subcategory', 'SubCategory', 'Subcategory'); Values = @() }
    'si_class'            = @{ Label = 'Class'; Columns = @('si_class', 'AssetClass'); Values = @('device', 'identity', 'cloud_resource', 'public_ip') }
    'si_component'        = @{ Label = 'Component'; Columns = @('si_component', 'Component'); Values = @('OS', 'SQL', 'Network', 'Hardware', 'Browser', 'Office', 'Application', 'Other') }
    'si_patch_cycle'      = @{ Label = 'Patch cycle'; Columns = @('si_patch_cycle'); Values = @() }
    'si_os_family'        = @{ Label = 'OS family'; Columns = @('si_os_family'); Values = @() }
    'si_servicenow_subci' = @{ Label = 'ServiceNow sub-CI'; Columns = @('si_servicenow_subci'); Values = @() }
}

function Get-SIOutputScopeFilterColumns {
    <# PURE. The row columns a filter field is read from (a named field's list, else the field itself). #>
    param([Parameter(Mandatory)][string]$Field)
    if ($script:SIOutputScopeFilterFields.Contains($Field)) { return @($script:SIOutputScopeFilterFields[$Field].Columns) }
    @($Field)
}

function Test-SIOutputScopeFilters {
    <#
        PURE. Does a row pass every filter of a scope? -Values: field -> the row's value(s) for it (a list, one value, or
        nothing). OR within a filter, AND across filters; a row without a value does not pass.
    #>
    param($Scope, [hashtable]$Values)
    if ($null -eq $Scope -or -not $Scope.PSObject.Properties['Filters']) { return $true }
    foreach ($f in @($Scope.Filters)) {
        if ($null -eq $f) { continue }
        $have = @()
        if ($null -ne $Values -and $Values.ContainsKey($f.Field)) { $have = @(Get-SIOutputScopeNames $Values[$f.Field] | ForEach-Object { $_.ToLowerInvariant() }) }
        if ($have.Count -eq 0) { return $false }
        $hit = $false
        foreach ($h in $have) { if ($f.Values -contains $h) { $hit = $true; break } }
        if (-not $hit) { return $false }
    }
    $true
}

function Get-SIOutputScopeRowFields {
    <# PURE. A row's values for the scope's filter fields (each from the first of its columns that has a value). #>
    param($Row, $Scope)
    $h = @{}
    if ($null -eq $Scope -or -not $Scope.PSObject.Properties['Filters']) { return $h }
    foreach ($f in @($Scope.Filters)) {
        $h[$f.Field] = Get-SIOutputScopeRowValue $Row @(Get-SIOutputScopeFilterColumns -Field $f.Field)
    }
    $h
}

function Get-SIOutputScopeDestinations { $script:SIOutputScopeDestinations }

function ConvertTo-SISeverityKey {
    <# PURE. A severity's comparison key: lower case without spaces, '-' and '_'; Critical is Very High (#246). #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $k = ($Value.Trim().ToLowerInvariant() -replace '[\s\-_]', '')
    switch ($k) { 'critical' { 'veryhigh' } 'moderate' { 'medium' } 'info' { 'informational' } 'information' { 'informational' } default { $k } }
}

function ConvertTo-SIOutputScopeTier {
    <# PURE. A tier as a number 0..3: a number, or a tier label ("High - tier 1"). $null = blank / unreadable. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $null }
    $n = 0
    if ([int]::TryParse($s, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return $n }
    $m = [regex]::Match($s, '(?i)tier\s*(\d)')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    $null
}

function Get-SIOutputScopeValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return , $Object[$Name] } else { return $null } }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return , $p.Value }
    $null
}

function Get-SIOutputScopeList {
    param($Object, [string]$Name)
    $v = Get-SIOutputScopeValue $Object $Name
    if ($null -eq $v) { return }
    if ($v -is [string]) { if ($v.Trim()) { return $v.Trim() } else { return } }
    @(@($v) | Where-Object { $null -ne $_ -and "$_".Trim() -ne '' } | ForEach-Object { if ($_ -is [string]) { $_.Trim() } else { $_ } })
}

function Test-SIOutputScopeBody {
    <#
        PURE. The reasons an output scope item is not accepted (empty = accepted). -Key is the destination. Same rules as
        the web app's OutputScope.Validate (C#).
    #>
    param([string]$Key, $Body)
    $why = New-Object System.Collections.Generic.List[string]
    $spec = $script:SIOutputScopeDestinations[$Key]
    if (-not $spec) { $why.Add(("'{0}' is not a destination ({1})" -f $Key, (@($script:SIOutputScopeDestinations.Keys) -join ', '))); return $why.ToArray() }
    if ($null -eq $Body -or -not ($Body -is [System.Management.Automation.PSCustomObject] -or $Body -is [System.Collections.IDictionary])) { $why.Add('an output scope must be a JSON object'); return $why.ToArray() }
    $names = if ($Body -is [System.Collections.IDictionary]) { @($Body.Keys | ForEach-Object { [string]$_ }) } else { @($Body.PSObject.Properties | ForEach-Object { $_.Name }) }
    $allowed = if ($spec.Asset) { @('tiers', 'assetKinds') } else { @('templates', 'reports', 'severities', 'tiers', 'domains', 'filters') }
    foreach ($n in $names) { if ($allowed -notcontains $n) { $why.Add(("'{0}' is not a scope of {1} ({2})" -f $n, $Key, ($allowed -join ', '))) } }
    foreach ($n in $names) {
        if ($n -eq 'filters') { continue }
        $v = Get-SIOutputScopeValue $Body $n
        if ($null -ne $v -and -not ($v -is [System.Collections.IEnumerable] -and $v -isnot [string])) { $why.Add(("'{0}' must be a list" -f $n)) }
    }
    $flt = Get-SIOutputScopeValue $Body 'filters'
    if ($null -ne $flt) {
        if (-not ($flt -is [System.Management.Automation.PSCustomObject] -or $flt -is [System.Collections.IDictionary])) { $why.Add("'filters' must be an object: { ""<field>"": { ""values"": [...] } }") }
        else {
            $fnames = if ($flt -is [System.Collections.IDictionary]) { @($flt.Keys | ForEach-Object { [string]$_ }) } else { @($flt.PSObject.Properties | ForEach-Object { $_.Name }) }
            foreach ($fn in $fnames) {
                if ($fn -notmatch '^si_[a-z0-9_]{1,80}$') { $why.Add(("filters: '{0}' is not an SI field (si_...)" -f $fn)); continue }
                $fo = Get-SIOutputScopeValue $flt $fn
                $vals = @(Get-SIOutputScopeList $fo 'values')
                if ($vals.Count -eq 0) { $why.Add(("filters: '{0}' names no value" -f $fn)) }
                foreach ($x in $vals) { if (([string]$x).Length -gt 200) { $why.Add(("filters: a value of '{0}' is longer than 200 characters" -f $fn)) } }
                foreach ($pn in @(if ($fo -is [System.Collections.IDictionary]) { $fo.Keys } else { $fo.PSObject.Properties.Name })) { if ([string]$pn -ne 'values') { $why.Add(("filters: '{0}' takes values only, not '{1}'" -f $fn, $pn)) } }
                $known = $script:SIOutputScopeFilterFields[$fn]
                if ($known -and @($known.Values).Count) {
                    foreach ($x in $vals) { if (@($known.Values | Where-Object { $_ -ieq [string]$x }).Count -eq 0) { $why.Add(("filters: '{0}' is not a {1} ({2})" -f $x, $known.Label.ToLowerInvariant(), (@($known.Values) -join ', '))) } }
                }
            }
        }
    }
    if ($why.Count) { return $why.ToArray() }
    foreach ($t in @(Get-SIOutputScopeList $Body 'tiers')) {
        $n = ConvertTo-SIOutputScopeTier $t
        if ($null -eq $n -or $n -lt 0 -or $n -gt 3 -or ("$t" -notmatch '^\s*[0-3]\s*$')) { $why.Add(("tiers: '{0}' is not a tier (0, 1, 2 or 3)" -f $t)) }
    }
    foreach ($s in @(Get-SIOutputScopeList $Body 'severities')) {
        if ($script:SIOutputScopeSeverityKeys -notcontains (ConvertTo-SISeverityKey ([string]$s))) { $why.Add(("severities: '{0}' is not a severity" -f $s)) }
    }
    foreach ($d in @(Get-SIOutputScopeList $Body 'domains')) {
        if (@($script:SIOutputScopeDomains | Where-Object { $_ -ieq [string]$d }).Count -eq 0) { $why.Add(("domains: '{0}' is not a security domain ({1})" -f $d, ($script:SIOutputScopeDomains -join ', '))) }
    }
    foreach ($k in @(Get-SIOutputScopeList $Body 'assetKinds')) {
        if ($script:SIOutputScopeAssetKinds -notcontains ([string]$k).ToLowerInvariant()) { $why.Add(("assetKinds: '{0}' is not an asset kind the CMDB connectors read ({1})" -f $k, ($script:SIOutputScopeAssetKinds -join ', '))) }
    }
    foreach ($n in 'templates', 'reports') {
        foreach ($r in @(Get-SIOutputScopeList $Body $n)) { if ([string]$r -notmatch '^[A-Za-z0-9_]{1,100}$') { $why.Add(("{0}: '{1}' is not a report name" -f $n, $r)) } }
    }
    $why.ToArray()
}

function ConvertTo-SIOutputScope {
    <#
        PURE. One destination's scope as the engines use it: @{ Destination; Severities (keys); Tiers (int); Domains (lower);
        AssetKinds (lower); ReportFilter (bool); Reports (HashSet, ordinal); Unresolved (template names not resolved) }.
        $null for no body.
    #>
    param([string]$Destination, $Body)
    if ($null -eq $Body) { return $null }
    $reports = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $templates = @(Get-SIOutputScopeList $Body 'templates')
    $named = @(Get-SIOutputScopeList $Body 'reports')
    $resolvedRaw = Get-SIOutputScopeValue $Body 'resolvedReports'
    $unresolved = @()
    if ($null -ne $resolvedRaw) { foreach ($r in @($resolvedRaw)) { if ($r) { [void]$reports.Add([string]$r) } } }
    else {
        foreach ($r in $named) { [void]$reports.Add([string]$r) }
        $unresolved = $templates
    }
    [pscustomobject]@{
        Destination  = $Destination
        Severities   = @(Get-SIOutputScopeList $Body 'severities' | ForEach-Object { ConvertTo-SISeverityKey ([string]$_) } | Where-Object { $_ })
        Tiers        = @(Get-SIOutputScopeList $Body 'tiers' | ForEach-Object { ConvertTo-SIOutputScopeTier $_ } | Where-Object { $null -ne $_ })
        Domains      = @(Get-SIOutputScopeList $Body 'domains' | ForEach-Object { ([string]$_).ToLowerInvariant() })
        AssetKinds   = @(Get-SIOutputScopeList $Body 'assetKinds' | ForEach-Object { ([string]$_).ToLowerInvariant() })
        ReportFilter = (($templates.Count + $named.Count) -gt 0)
        Reports      = $reports
        Unresolved   = $unresolved
        Filters      = @(ConvertTo-SIOutputScopeFilterList (Get-SIOutputScopeValue $Body 'filters'))
    }
}

function ConvertTo-SIOutputScopeFilterList {
    <# PURE. The 'filters' object -> @{ Field; Values (lower) } per field, by name. #>
    param($Filters)
    if ($null -eq $Filters) { return }
    $names = if ($Filters -is [System.Collections.IDictionary]) { @($Filters.Keys | ForEach-Object { [string]$_ }) } else { @($Filters.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($n in @($names | Sort-Object)) {
        $fo = Get-SIOutputScopeValue $Filters $n
        $vals = @(Get-SIOutputScopeList $fo 'values' | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ })
        if ($vals.Count -eq 0) { continue }
        [pscustomobject]@{ Field = $n; Values = $vals }
    }
}

function Get-SIOutputScope {
    <#
        The scope of one destination for this run, or $null (everything passes). Reads <SI_ProConfigRoot>\output-scope.json
        (materialised by the Pro settings layer); -ConfigRoot overrides (tests). A file that cannot be read THROWS: a scope
        the operator set must never silently become "everything".
    #>
    param([Parameter(Mandatory)][string]$Destination, [string]$ConfigRoot)
    if (-not $script:SIOutputScopeDestinations.Contains($Destination)) { throw ("'{0}' is not an output destination ({1})" -f $Destination, (@($script:SIOutputScopeDestinations.Keys) -join ', ')) }
    if ([string]::IsNullOrWhiteSpace($ConfigRoot)) { $ConfigRoot = [string]$global:SI_ProConfigRoot }
    if ([string]::IsNullOrWhiteSpace($ConfigRoot)) { return $null }
    $p = [System.IO.Path]::Combine($ConfigRoot, $script:SIOutputScopeFile)
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    $text = [System.IO.File]::ReadAllText($p).TrimStart([char]0xFEFF)
    try { $doc = $text | ConvertFrom-Json -ErrorAction Stop } catch { throw ("the output scope file {0} is not valid JSON: {1}" -f $p, $_.Exception.Message) }
    $dests = Get-SIOutputScopeValue $doc 'destinations'
    $body = Get-SIOutputScopeValue $dests $Destination
    if ($null -eq $body) { return $null }
    ConvertTo-SIOutputScope -Destination $Destination -Body $body
}

function Get-SIOutputScopeText {
    <# PURE. One line saying what a scope lets through (for the run log). #>
    param($Scope)
    if ($null -eq $Scope) { return 'everything' }
    $parts = New-Object System.Collections.Generic.List[string]
    if ($Scope.ReportFilter) { $parts.Add(('{0} report(s)' -f $Scope.Reports.Count)) }
    if (@($Scope.Severities).Count) { $parts.Add(('severity ' + (@($Scope.Severities) -join ', '))) }
    if (@($Scope.Tiers).Count) { $parts.Add(('tier ' + (@($Scope.Tiers) -join ', '))) }
    if (@($Scope.Domains).Count) { $parts.Add(('domain ' + (@($Scope.Domains) -join ', '))) }
    if (@($Scope.AssetKinds).Count) { $parts.Add(('asset kind ' + (@($Scope.AssetKinds) -join ', '))) }
    if ($Scope.PSObject.Properties['Filters']) {
        foreach ($f in @($Scope.Filters)) { if ($f) { $parts.Add(('{0} {1}' -f $f.Field, (@($f.Values) -join ', '))) } }
    }
    if ($parts.Count -eq 0) { return 'everything' }
    $parts -join '; '
}

function Test-SIOutputScopeFinding {
    <#
        PURE. Does one finding pass the scope? -Reports: the report name(s) the finding came from. Blank values pass.
    #>
    param($Scope, [AllowNull()][AllowEmptyString()][string]$Severity, [AllowNull()]$Tier, [AllowNull()][AllowEmptyString()][string]$Domain, [AllowNull()][string[]]$Reports,
          [hashtable]$Fields)
    if ($null -eq $Scope) { return $true }
    # the filters (risk rating, class, component ...) -- only when the caller hands the row's values over (-Fields); a
    # caller that checks one dimension (a domain) leaves them to its own call
    if ($PSBoundParameters.ContainsKey('Fields') -and -not (Test-SIOutputScopeFilters -Scope $Scope -Values $Fields)) { return $false }
    if (@($Scope.Severities).Count) {
        $k = ConvertTo-SISeverityKey $Severity
        if ($k -and @($Scope.Severities) -notcontains $k) { return $false }
    }
    if (@($Scope.Tiers).Count) {
        $t = ConvertTo-SIOutputScopeTier $Tier
        if ($null -ne $t -and @($Scope.Tiers) -notcontains $t) { return $false }
    }
    if (@($Scope.Domains).Count -and -not [string]::IsNullOrWhiteSpace($Domain)) {
        if (@($Scope.Domains) -notcontains $Domain.Trim().ToLowerInvariant()) { return $false }
    }
    if ($Scope.ReportFilter) {
        $names = @($Reports | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($names.Count) {
            $hit = $false
            foreach ($n in $names) { if ($Scope.Reports.Contains($n.Trim())) { $hit = $true; break } }
            if (-not $hit) { return $false }
        }
    }
    $true
}

function Test-SIOutputScopeAsset {
    <# PURE. Does one asset pass a CMDB destination's asset scope (tiers, asset kinds)? Blank values pass. #>
    param($Scope, [AllowNull()]$Tier, [AllowNull()][AllowEmptyString()][string]$Kind)
    if ($null -eq $Scope) { return $true }
    if (@($Scope.Tiers).Count) {
        $t = ConvertTo-SIOutputScopeTier $Tier
        if ($null -ne $t -and @($Scope.Tiers) -notcontains $t) { return $false }
    }
    if (@($Scope.AssetKinds).Count -and -not [string]::IsNullOrWhiteSpace($Kind)) {
        if (@($Scope.AssetKinds) -notcontains $Kind.Trim().ToLowerInvariant()) { return $false }
    }
    $true
}

function Get-SIOutputScopeRowValue {
    param($Row, [string[]]$Names)
    foreach ($n in $Names) {
        $v = Get-SIOutputScopeValue $Row $n
        if ($null -ne $v -and "$v".Trim() -ne '') { return $v }
    }
    $null
}

function Select-SIOutputScopeRows {
    <#
        PURE. The rows of a Risk Analysis run that pass the scope (Excel + mail). A row's severity is SecuritySeverity, its
        tier CriticalityTier (else the CriticalityTierLevel label), its domain SecurityDomain, its report
        AssetDetectedInReportName (else ReportName). Returns @{ Rows; Dropped }. No scope = every row, Dropped 0.
    #>
    param([AllowNull()][object[]]$Rows, $Scope)
    $all = @($Rows | Where-Object { $null -ne $_ })
    if ($null -eq $Scope) { return [pscustomobject]@{ Rows = $all; Dropped = 0 } }
    $kept = New-Object System.Collections.Generic.List[object]; $dropped = 0
    foreach ($r in $all) {
        $sev = [string](Get-SIOutputScopeRowValue $r @('SecuritySeverity'))
        $tier = Get-SIOutputScopeRowValue $r @('CriticalityTier', 'CriticalityTierLevel')
        $dom = [string](Get-SIOutputScopeRowValue $r @('SecurityDomain'))
        $rep = [string](Get-SIOutputScopeRowValue $r @('AssetDetectedInReportName', 'ReportName'))
        if (Test-SIOutputScopeFinding -Scope $Scope -Severity $sev -Tier $tier -Domain $dom -Reports @($rep) -Fields (Get-SIOutputScopeRowFields -Row $r -Scope $Scope)) { $kept.Add($r) } else { $dropped++ }
    }
    [pscustomobject]@{ Rows = $kept.ToArray(); Dropped = $dropped }
}

function Get-SIVulnScopeDestination {
    <# PURE. The output destination of a vulnerability connector kind ('sql' | 'servicenow'); $null for one with none (rest). #>
    param([string]$Kind)
    switch (([string]$Kind).ToLowerInvariant()) { 'sql' { 'vuln-sql' } 'servicenow' { 'vuln-servicenow' } default { $null } }
}

function Get-SIOutputScopeNames {
    <# PURE. Names from a query column: a list, a KQL dynamic array as JSON text ('["a","b"]' -- how a make_set comes back
       from the query cmdlets), or one plain value. Blank names are dropped. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return }
    if ($Value -is [string]) {
        $t = $Value.Trim()
        if ($t.StartsWith('[')) {
            try { $arr = $t | ConvertFrom-Json -ErrorAction Stop } catch { $arr = @($t) }
            foreach ($x in @($arr)) { if ($null -ne $x -and "$x".Trim() -ne '') { "$x".Trim() } }
            return
        }
        if ($t) { $t }
        return
    }
    foreach ($x in @($Value)) { if ($null -ne $x -and "$x".Trim() -ne '') { "$x".Trim() } }
}

function Select-SICmdbScopedPlanInput {
    <#
        PURE. A CMDB connector's plan inputs narrowed to its asset scope. -Desired / -Actual: CiKey -> CI (each with Kind and
        Tier). A CI SI sees that is OUT of scope leaves the desired set AND the table's side -- it is neither created, updated
        nor counted absent / retired: the table keeps it exactly as it is. A CI SI no longer sees is untouched by the scope.
        Returns @{ Desired; Actual (ordered dictionaries); OutOfScope; LeftAsIs }.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Desired, [Parameter(Mandatory)][System.Collections.IDictionary]$Actual, $Scope)
    if ($null -eq $Scope) { return [pscustomobject]@{ Desired = $Desired; Actual = $Actual; OutOfScope = 0; LeftAsIs = 0 } }
    $d2 = [ordered]@{}; $out = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($k in @($Desired.Keys)) {
        $ci = $Desired[$k]
        if (Test-SIOutputScopeAsset -Scope $Scope -Tier (Get-SIOutputScopeValue $ci 'Tier') -Kind ([string](Get-SIOutputScopeValue $ci 'Kind'))) { $d2[$k] = $ci } else { [void]$out.Add([string]$k) }
    }
    $a2 = [ordered]@{}; $left = 0
    foreach ($k in @($Actual.Keys)) { if ($out.Contains([string]$k)) { $left++ } else { $a2[$k] = $Actual[$k] } }
    [pscustomobject]@{ Desired = $d2; Actual = $a2; OutOfScope = $out.Count; LeftAsIs = $left }
}

function Select-SIVulnScopedPlanInput {
    <#
        PURE. A vulnerability connector's plan inputs narrowed to its scope. -SnapshotRows: the desired-set query's rows
        (AssetId, Cve, Severity, Tier, Domains, Reports). A finding OUT of scope leaves the desired set -- it is never
        opened -- and its key goes to OutOfScopeKeys: #279 decision 3 (operator, 2026-10-04) closes an open record of it
        with the reason 'Out of scope' (never as fixed, never counted by the close ceiling; back in scope = reopened).
        -Actual is returned unchanged. Records SI does not report at all are untouched by the scope.
        -AssetAlias (#279): @{ '<previous asset id lower>' = '<current SI_AssetId>' }. A target record stored under a
        previous asset id is judged by the asset's CURRENT id -- OnTarget counts it, and the plan (given the same alias)
        closes it as out of scope, never as absent or fixed.
        Returns @{ Desired; Actual; OutOfScope (findings); OutOfScopeKeys (key -> why); OnTarget (target records out of scope) }.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Desired, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Actual,
          [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$SnapshotRows, $Scope, [hashtable]$AssetAlias)
    if ($null -eq $Scope) { return [pscustomobject]@{ Desired = @($Desired); Actual = @($Actual); OutOfScope = 0; OutOfScopeKeys = @{}; OnTarget = 0 } }
    $keyOf = { param($id, $cve) ('{0}|{1}' -f ([string]$id).Trim().ToLowerInvariant(), ([string]$cve).Trim().ToUpperInvariant()) }
    $out = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($r in $SnapshotRows) {
        if ($null -eq $r) { continue }
        $reports = @(Get-SIOutputScopeNames (Get-SIOutputScopeValue $r 'Reports'))
        if (-not $reports.Count) { $reports = @(Get-SIOutputScopeNames (Get-SIOutputScopeValue $r 'ReportName')) }
        $domains = @(Get-SIOutputScopeNames (Get-SIOutputScopeValue $r 'Domains'))
        if (-not $domains.Count) { $domains = @(Get-SIOutputScopeNames (Get-SIOutputScopeValue $r 'SecurityDomain')) }
        $domOk = ($domains.Count -eq 0)
        foreach ($d in $domains) { if (Test-SIOutputScopeFinding -Scope $Scope -Domain $d) { $domOk = $true; break } }
        # the filters read the snapshot's F_<field> sets (Get-SIVulnDesiredKql -ScopeFields), else the field's own columns
        $fv = @{}
        foreach ($f in @($Scope.Filters)) {
            if ($null -eq $f) { continue }
            $set = Get-SIOutputScopeValue $r ('F_' + $f.Field)
            if ($null -eq $set) { $set = Get-SIOutputScopeRowValue $r @(Get-SIOutputScopeFilterColumns -Field $f.Field) }
            $fv[$f.Field] = $set
        }
        $pass = $domOk -and (Test-SIOutputScopeFinding -Scope $Scope -Severity ([string](Get-SIOutputScopeValue $r 'Severity')) -Tier (Get-SIOutputScopeValue $r 'Tier') -Reports $reports -Fields $fv)
        if (-not $pass) { [void]$out.Add((& $keyOf (Get-SIOutputScopeValue $r 'AssetId') (Get-SIOutputScopeValue $r 'Cve'))) }
    }
    $d2 = @($Desired | Where-Object { $null -ne $_ -and -not $out.Contains((& $keyOf $_.CorrelationId $_.Cve)) })
    $currentId = {
        param($id)
        $k = ([string]$id).Trim().ToLowerInvariant()
        if ($k -and $null -ne $AssetAlias -and $AssetAlias.ContainsKey($k)) { return [string]$AssetAlias[$k] }
        $id
    }
    $why = ('this connector''s output scope ({0}) leaves the finding out -- closed as out of scope, not as fixed' -f (Get-SIOutputScopeText $Scope))
    $keys = @{}; foreach ($k in $out) { $keys[$k] = $why }
    $onTarget = @($Actual | Where-Object { $null -ne $_ -and $out.Contains((& $keyOf (& $currentId $_.CorrelationId) $_.Cve)) }).Count
    [pscustomobject]@{ Desired = $d2; Actual = @($Actual); OutOfScope = $out.Count; OutOfScopeKeys = $keys; OnTarget = $onTarget }
}
