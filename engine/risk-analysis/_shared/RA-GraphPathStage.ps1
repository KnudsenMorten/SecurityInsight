#Requires -Version 5.1
<#
    THE ATTACK-PATH REPORTS FROM VULNERABLE DEVICES TO AZURE, READ ONCE PER RUN AND JOINED IN SQL (REQUIREMENTS #1275
    stage 2, owner 2026-11-18: "the heavy part is read in smaller steps (once per run) and joined in SI").

    Attack_Paths_Detailed_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure and its Summary sibling
    walk the Exposure Graph: device -[contains | has credentials of | frequently logged in by]-> secret / identity
    -[any of the six labels, 0..3]-> principal -[has role on]-> scope -[any, 0..2]-> Azure resource. Their query builds
    the whole graph (make-graph over every edge of the six labels, every identity, secret and Azure node) in EVERY query
    slice and only the devices are cut: a slice at 1/256 still timed out at the largest tenants (a fixed cost, not size).

    Here the graph is read ONCE PER RUN as two plain reads, each cut on a hash so a part of it is a part of the work:
      S1  the nodes the query's node table holds (the vulnerable devices with their device key, highest CVSS and Exposure
          Graph risk factors; every identity, secret and Azure node), each with its category and label tests evaluated by
          the query engine itself (bits), keyed by the first 32 hex digits of hash_sha256(NodeId);
      S2  the edges of the six labels (source key, target key, label class, the label text of a device edge).
    Both go through the report loop's own hunting call (Invoke-GraphHuntingQuery: its 429 / busy back-off, its 504 count,
    its row-limit check) and are written to SQL (sidata.RaGraphNode / RaGraphEdge, keyed by the run). Each part is checked:
    the rows stored = the source's count of that step, asked before and again after the read (a graph that changed while
    it was read is read again; never mixed).
    Then, in SQL, once per run: credential / identity -> principal in 0..3 steps (sidata.RaGraphCP) and role scope -> Azure
    target in 0..2 steps (sidata.RaGraphST), the target tests of the query applied. Each report slice (the engine's own
    slicing, unchanged) then asks SQL for its devices only: device -> credential -> principal -> role -> scope -> target,
    grouped by device and target -- and the rest of the report query (the CI joins, the columns, the weights, the scope
    filter) is done here in PowerShell, row for row as the KQL does it (ConvertTo-RAGpsDetailedRows / -SummaryRows).

    SEMANTICS (probed in advanced hunting 2026-11-18, .ops\ra-stage2-probe\semantics.json):
      * an edge whose end is not in the node table is KEPT: that end is a node without properties (name "", no category);
      * a variable-length step may revisit a node (walk), and *0 includes the start node;
      * make_set keeps "" as a value; strings sort ordinally; coalesce("", x) = x; coalesce([], x) = [].
    So the graph holds EVERY edge of the six labels, and the only thing a query slice changes is that a vulnerable device
    read in another slice is a node without properties there. It can never be a device, a credential / identity or a
    target (each needs its category), and a device is never a subscription / resource group scope -- so no path is lost
    by slicing; only the principal's NAME of such a path read as "" before. The new path names it. Each run says how many
    rows that concerns (Get-RAGpsSliceRows .OtherPartPrincipal), once.

    NEVER a partial graph: a part of S1 / S2 that cannot be read, or a count that does not match, ends the load as failed
    ("lookup unavailable"): every report that needs it is NOT COMPLETE and keeps its last complete result (nothing closes).
    A query that is not exactly the one this port was written for (a custom query, a changed locked query) is not
    touched: it runs as before (Get-RAGraphStagePlan, the shape check).

    Scratch tables: keyed by the run; removed at the end of the run; every load first removes what an earlier run of the
    same kind left (a run that stopped half way) and anything older than two days.
    PowerShell 5.1-safe: no ternary, no null-conditional.
#>

$script:RAGpsReports = @{
    'Attack_Paths_Detailed_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure' = 'Detailed'
    'Attack_Paths_Summary_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure'  = 'Summary'
}
$script:RAGpsLabels = '"contains", "has credentials of", "frequently logged in by", "can authenticate as", "member of", "has role on"'
$script:RAGpsDeviceLabels = '"contains", "has credentials of", "frequently logged in by"'
# node bits (computed by the query engine at read time, so every category / label test is the query's own)
$script:RAGpsBit = @{ Secret = 1; Identity = 2; Azure = 4; Device = 8; Vulnerable = 16; Storage = 32; Scope = 64; Target = 128 }
$script:RAGpsSet = $null          # the run's graph in SQL: @{ RunKey; Nodes; Edges; Cp; St; Seconds }
$script:RAGpsSetFailed = $null    # the load failed (a worker of the run learns it from the manifest): the reason
$script:RAGpsWorker = $false      # this process is a queue worker: it uses the producer's load, never loads itself
$script:RAGpsShapeSaid = @{}      # report -> said once that its query is not the one this port was written for
$script:RAGpsRun = $null          # per run: rows whose principal is a device read in another slice (said once at the end)

# ------------------------------------------------------------------------------------------------------------------
#  S1 / S2 -- THE READS (KQL)
# ------------------------------------------------------------------------------------------------------------------
function Get-RAGpsPartFilter {
    <# PURE. Part -Page of -Pages of a read, cut on the hash of -Column (the same hash-modulo the slices use: lossless, every
       row in exactly one part, a part halved = the two parts of twice the count). '' for one part. #>
    param([Parameter(Mandatory)][string]$Column, [long]$Pages = 1, [long]$Page = 0)
    if ($Pages -le 1) { return '' }
    return ('| where (tolong(strcat("0x", substring(hash_sha256({0}), 0, 8))) % {1}) == {2}' -f $Column, $Pages, $Page)
}

function Get-RAGpsNodeKql {
    <#
        PURE. S1: the report query's node table (VulnerableDevices + Identities + Credentials + AzureNodes, the vulnerable
        device's columns exactly as VulnerableDevices / _DeviceEnrichment compute them), part -Page of -Pages, cut on the
        node id. -Count: the number of rows. Bits: 1 secret, 2 identity, 4 environmentAzure, 8 device, 16 a vulnerable-
        device row, 32 the storage-account label, 64 a subscription / resource-group label, 128 a resource label the
        query takes as a target (microsoft.*, not resources/ or authorization/). Bh = the slice hash of the device key
        (the engine's bucket filter on DeviceKey).
    #>
    param([long]$Pages = 1, [long]$Page = 0, [switch]$Count)
    $kql = @"
let _siVd = ExposureGraphNodes
| where set_has_element(Categories, "device")
| where tobool(coalesce(NodeProperties.rawData.highRiskVulnerabilityInsights.hasHighOrCritical,
                        NodeProperties.raw.highRiskVulnerabilityInsights.hasHighOrCritical,
                        NodeProperties.highRiskVulnerabilityInsights.hasHighOrCritical)) == true
| extend _ids = tostring(EntityIds)
| extend MdeDeviceId = tolower(coalesce(extract('"type":"SenseDeviceId","id":"([^"]+)"', 1, _ids), extract('"id":"([^"]+)","type":"SenseDeviceId"', 1, _ids)))
| extend DeviceKey = iif(isnotempty(MdeDeviceId), MdeDeviceId, tolower(NodeId))
| extend RawData = todynamic(NodeProperties).rawData
| extend RiskFactorsArray = todynamic(coalesce(RawData.risk.riskFactors, todynamic(NodeProperties).risk.riskFactors, dynamic([])))
| extend RiskFactorsArray = iff(isnull(RiskFactorsArray), dynamic([]), RiskFactorsArray)
| mv-apply rf = RiskFactorsArray on (
    where isnotempty(trim(" ", tostring(rf)))
    | summarize RiskFactorSet = make_set(tostring(rf))
  )
| extend RiskFactorSet = coalesce(RiskFactorSet, dynamic([]))
| project NodeId, NodeName, NodeLabel, Categories, DeviceKey, RiskFactorSet, Cvss = todouble(NodeProperties.rawData.highRiskVulnerabilityInsights.maxCvssScore), V = 1;
let _siOther = ExposureGraphNodes
| where set_has_element(Categories, "identity") or set_has_element(Categories, "secret") or set_has_element(Categories, "environmentAzure")
| project NodeId, NodeName, NodeLabel, Categories, V = 0;
union _siVd, _siOther
$(Get-RAGpsPartFilter -Column 'NodeId' -Pages $Pages -Page $Page)
"@
    if ($Count) { return ($kql.TrimEnd() + "`n| count") }
    return ($kql.TrimEnd() + "`n" + @'
| project K = substring(hash_sha256(NodeId), 0, 32), NodeId, NodeName, NodeLabel,
          Fl = toint(iff(set_has_element(Categories, "secret"), 1, 0) + iff(set_has_element(Categories, "identity"), 2, 0)
                   + iff(set_has_element(Categories, "environmentAzure"), 4, 0) + iff(set_has_element(Categories, "device"), 8, 0)
                   + iff(V == 1, 16, 0)
                   + iff(NodeLabel =~ "microsoft.storage/storageaccounts", 32, 0)
                   + iff(NodeLabel in~ ("subscriptions", "resourcegroups", "microsoft.resources/subscriptions", "microsoft.resources/resourcegroups"), 64, 0)
                   + iff(NodeLabel startswith "microsoft." and not(NodeLabel startswith "microsoft.resources/") and not(NodeLabel startswith "microsoft.authorization/"), 128, 0)),
          DeviceKey, RiskFactorSet, Cvss,
          Bh = iff(V == 1 and isnotempty(DeviceKey), tolong(strcat("0x", substring(hash_sha256(DeviceKey), 0, 8))), long(null))
'@.TrimEnd())
}

function Get-RAGpsEdgeKql {
    <# PURE. S2: every edge of the six labels make-graph is built from (an edge to a node outside the node table is kept, as
       the query keeps it), part -Page of -Pages, cut on the source id. L: 1 has role on, 2 a device edge label (contains /
       has credentials of / frequently logged in by -- Lt its text as written), 3 the others. -Count: the number of rows. #>
    param([long]$Pages = 1, [long]$Page = 0, [switch]$Count)
    $kql = @"
ExposureGraphEdges
| where EdgeLabel in~ ($($script:RAGpsLabels))
$(Get-RAGpsPartFilter -Column 'SourceNodeId' -Pages $Pages -Page $Page)
"@
    if ($Count) { return ($kql.TrimEnd() + "`n| count") }
    return ($kql.TrimEnd() + "`n" + @"
| project S = substring(hash_sha256(SourceNodeId), 0, 32), T = substring(hash_sha256(TargetNodeId), 0, 32),
          L = toint(case(EdgeLabel =~ "has role on", 1, EdgeLabel in~ ($($script:RAGpsDeviceLabels)), 2, 3)),
          Lt = iff(EdgeLabel in~ ($($script:RAGpsDeviceLabels)), EdgeLabel, "")
"@.TrimEnd())
}

# ------------------------------------------------------------------------------------------------------------------
#  SMALL PURE HELPERS
# ------------------------------------------------------------------------------------------------------------------
function Get-RAGpsValue {
    <# PURE. A column of a row however it is held: a dictionary (a hunting answer's bag, a SQL row), a compact / custom object.
       DBNull reads as $null. #>
    param($Row, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    else { $p = $Row.PSObject.Properties[$Name]; if ($p) { $v = $p.Value } }
    if ($v -is [System.DBNull]) { return $null }
    # advanced hunting writes a typed null as {} (an empty bag)
    if ($v -is [System.Collections.IDictionary] -and $v.Count -eq 0) { return $null }
    if ($v -is [System.Management.Automation.PSCustomObject] -and @($v.PSObject.Properties).Count -eq 0) { return $null }
    return $v
}

function Get-RAGpsRows {
    <# PURE. The rows of a read however the seam handed them: the rows, or one array holding them (a reader answers ONE
       list -- wrapped once more by @() around the call). #>
    param($Answer)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($Answer)) {
        if ($null -eq $x) { continue }
        if ($x -is [System.Collections.IDictionary] -or $x -is [string] -or -not ($x -is [System.Collections.IEnumerable])) { $out.Add($x); continue }
        foreach ($y in $x) { if ($null -ne $y) { $out.Add($y) } }
    }
    return , $out.ToArray()
}

function Test-RAGpsHasColumn {
    <# PURE. Whether -Row carries the column at all (KQL column_ifexists). #>
    param($Row, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Row) { return $false }
    if ($Row -is [System.Collections.IDictionary]) { return $Row.Contains($Name) }
    return ($null -ne $Row.PSObject.Properties[$Name])
}

function ConvertTo-RAGpsKqlString {
    <# PURE. KQL tostring(): null -> ""; a bool -> true / false; a number in the invariant form; an array / bag -> its JSON. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [System.IFormattable] -and -not ($Value -is [datetime])) { return $Value.ToString($null, [System.Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [System.Collections.IEnumerable]) { return (ConvertTo-Json -InputObject @($Value) -Compress -Depth 8) }
    return [string]$Value
}

function ConvertTo-RAGpsArray {
    <# PURE. A dynamic array as a lookup row carries it (Log Analytics hands dynamic values as their JSON text; a hunting
       answer as an array) -> object[]; null / empty text -> $null (KQL null). A JSON value that is not an array -> $null. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return $null }
    if ($Value -is [string]) {
        $t = $Value.Trim()
        if ($t -eq '' -or $t -eq 'null' -or -not $t.StartsWith('[')) { return $null }
        $a = ConvertFrom-Json -InputObject $t
        return , ([object[]]@($a | ForEach-Object { $_ }))
    }
    if ($Value -is [System.Collections.IDictionary]) { return $null }
    if ($Value -is [System.Collections.IEnumerable]) { return , ([object[]]@($Value | ForEach-Object { $_ })) }
    return $null
}

function ConvertTo-RAGpsInt {
    <# PURE. KQL toint(): null / empty / not a number -> $null. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return $null }
    if ($Value -is [int]) { return $Value }
    if ($Value -is [bool]) { if ($Value) { return 1 } else { return 0 } }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $null }
    $d = 0.0
    if ([double]::TryParse($s, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return [int][Math]::Truncate($d) }
    if ($s -eq 'true') { return 1 }
    if ($s -eq 'false') { return 0 }
    return $null
}

function ConvertTo-RAGpsDouble {
    <# PURE. A real as a row carries it -> [double]; null / empty / not a number -> $null. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return $null }
    if ($Value -is [double]) { return $Value }
    $d = 0.0
    if ([double]::TryParse(([string]$Value).Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
    return $null
}

function ConvertTo-RAGpsBool {
    <# PURE. A bool as a lookup row carries it (true / false text, or a bool); anything else -> $null. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return $null }
    if ($Value -is [bool]) { return $Value }
    $s = ([string]$Value).Trim().ToLowerInvariant()
    if ($s -in 'true', '1') { return $true }
    if ($s -in 'false', '0') { return $false }
    return $null
}

function Test-RAGpsEmpty {
    <# PURE. KQL isempty() on a string: null or "". #>
    param($Value)
    return ($null -eq $Value -or $Value -is [System.DBNull] -or ([string]$Value) -eq '')
}

function Get-RAGpsSortedSet {
    <# PURE. KQL make_set over -Values (an empty string is a value; a null is not), in ordinal order (the stored order is
       then the same every run -- the query engine's order is the order it met them in). #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Values)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($v in @($Values)) { if ($null -ne $v -and -not ($v -is [System.DBNull])) { [void]$set.Add([string]$v) } }
    $arr = New-Object 'string[]' $set.Count
    $set.CopyTo($arr)
    [System.Array]::Sort($arr, [System.StringComparer]::Ordinal)
    return , ([object[]]$arr)
}

function Get-RAGpsSeverity {
    <# PURE. The query's SecuritySeverity case() over the highest CVSS (null -> "Low", as case() falls through). #>
    param($Cvss)
    if ($null -eq $Cvss) { return 'Low' }
    $c = [double]$Cvss
    if ($c -ge 9.0) { return 'Very High' }
    if ($c -ge 7.0) { return 'High' }
    if ($c -ge 5.0) { return 'Medium-High' }
    if ($c -ge 3.0) { return 'Medium' }
    return 'Low'
}

function Get-RAGpsTierLevel {
    <# PURE. The query's CriticalityTierLevel case(). #>
    param($Tier)
    if ($null -eq $Tier) { return '' }
    switch ([int]$Tier) { 0 { return 'Critical - tier 0' } 1 { return 'High - tier 1' } 2 { return 'Medium - tier 2' } }
    return 'Low - tier 3'
}

function Get-RAGpsEntryVector {
    <# PURE. The Detailed query's EntryVector case() over the device edge (=~: case-insensitive) and the first hop's label
       (==: case-sensitive). #>
    param([AllowEmptyString()][AllowNull()][string]$DeviceEdge, [AllowEmptyString()][AllowNull()][string]$FirstHopLabel)
    $e = [string]$DeviceEdge; $l = [string]$FirstHopLabel
    $oi = [System.StringComparison]::OrdinalIgnoreCase
    if ([string]::Equals($e, 'contains', $oi)) {
        $known = @{ 'entra-userCookie' = 'Entra session cookie'; 'azure-active-directory-app-secret' = 'AAD app secret'
                    'azure-active-directory-user-credentials' = 'Cached AAD user credentials'; 'azure-storage-shared-access-signature' = 'SAS token'
                    'azure-storage-connection-string' = 'Storage connection string'; 'azure-database-connection-string' = 'DB connection string'
                    'azure-app-configuration-key' = 'App Configuration key'; 'github-personal-access-token' = 'GitHub PAT'
                    'openai-api-key' = 'OpenAI API key'; 'user-azure-cli-secret' = 'Cached Azure CLI token' }
        foreach ($k in $known.Keys) { if ([string]::Equals($k, $l, [System.StringComparison]::Ordinal)) { return $known[$k] } }
        return ('Other secret: ' + $l)
    }
    if ([string]::Equals($e, 'has credentials of', $oi)) { return 'Owner / cached credential' }
    if ([string]::Equals($e, 'frequently logged in by', $oi)) { return 'Interactive logon' }
    return $e
}

function Get-RAGpsTargetType {
    <# PURE. TargetType and AttackPathName of the query, from the target's label. #>
    param([AllowEmptyString()][AllowNull()][string]$TargetLabel)
    if ([string]::Equals([string]$TargetLabel, 'microsoft.storage/storageaccounts', [System.StringComparison]::OrdinalIgnoreCase)) {
        return @{ Type = 'Storage account'; Name = 'Device with high severity vulnerabilities allows lateral movement to Azure storage account' }
    }
    return @{ Type = 'Azure resource'; Name = 'Device with high severity vulnerabilities allows lateral movement to Azure resource' }
}

function Get-RAGpsRowSplitPart {
    <# PURE. Which part of -RowCount a row is in when a slice is split by row: a lossless partition of the slice's rows (the
       same row is always in the same part) -- the row's values in order, SHA-256, its first 4 bytes, modulo. #>
    param([Parameter(Mandatory)]$Row, [long]$RowCount = 1)
    if ($RowCount -le 1) { return 0L }
    $sb = New-Object System.Text.StringBuilder
    foreach ($p in $Row.PSObject.Properties) { [void]$sb.Append((ConvertTo-RAGpsKqlString $p.Value)).Append([char]31) }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sb.ToString())) } finally { $sha.Dispose() }
    $v = ([long]$h[0] -shl 24) -bor ([long]$h[1] -shl 16) -bor ([long]$h[2] -shl 8) -bor [long]$h[3]
    return ($v % $RowCount)
}

function Get-RAGpsHex {
    <# PURE. SHA-256 (hex, lower case) of a text. #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$Text)) } finally { $sha.Dispose() }
    return (([System.BitConverter]::ToString($h)) -replace '-', '').ToLowerInvariant()
}

# ------------------------------------------------------------------------------------------------------------------
#  THE WEIGHTS (the engine's generated block, read back and checked against its generator)
# ------------------------------------------------------------------------------------------------------------------
function ConvertFrom-RAGpsWeightBlock {
    <#
        PURE. The weighted-factor block the engine wrote into the query (Build-WeightedFactorsKql) read back into its config:
        @{ Combine; MaxMultiplier; Fields = @( @{ field; valueMap; default } ) }. $null when the text is not a block that
        generator writes. The caller builds the block again from this config and compares it with the text -- only an exact
        match is used (a block this cannot read back is never guessed at).
    #>
    param([AllowEmptyString()][string]$Block)
    $lines = @(([string]$Block -replace "`r", '') -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    $fields = New-Object System.Collections.Generic.List[object]
    $expr = $null
    $i = 0
    while ($i -lt $lines.Count) {
        $ln = $lines[$i]
        $m = [regex]::Match($ln, '^\| extend RF_W_(?<safe>[A-Za-z0-9_]+) = case\($')
        if ($m.Success) {
            $map = [ordered]@{}; $field = $null; $def = $null; $i++
            while ($i -lt $lines.Count) {
                $c = [regex]::Match($lines[$i], '^tolower\(trim\(" ", tostring\(column_ifexists\("(?<f>[^"]*)", ""\)\)\)\) == "(?<v>(?:[^"\\]|\\.)*)", (?<m>-?\d+),$')
                if ($c.Success) {
                    if ($null -eq $field) { $field = $c.Groups['f'].Value } elseif ($field -ne $c.Groups['f'].Value) { return $null }
                    $map[($c.Groups['v'].Value -replace '\\"', '"')] = [int]$c.Groups['m'].Value
                    $i++; continue
                }
                $d = [regex]::Match($lines[$i], '^(?<d>-?\d+)$')
                if ($d.Success -and $i + 1 -lt $lines.Count -and $lines[$i + 1] -eq ')') { $def = [int]$d.Groups['d'].Value; $i += 2; break }
                return $null
            }
            if ($null -eq $field -or $null -eq $def -or $map.Count -eq 0) { return $null }
            $vm = New-Object psobject
            foreach ($k in $map.Keys) { $vm | Add-Member -NotePropertyName $k -NotePropertyValue $map[$k] -Force }
            $fields.Add([pscustomobject]@{ field = $field; valueMap = $vm; default = $def })
            continue
        }
        $f = [regex]::Match($ln, '^\| extend RiskScore_Weight_Factor = (?<e>.+)$')
        if ($f.Success) { $expr = $f.Groups['e'].Value }
        $i++
    }
    if ($null -eq $expr) { return $null }
    $max = 0.0
    $cap = [regex]::Match($expr, '^min_of\((?<c>-?\d+), (?<x>.+)\)$')
    if ($cap.Success) { $max = [double]$cap.Groups['c'].Value; $expr = $cap.Groups['x'].Value }
    $combine = 'product'
    if ($expr.StartsWith('max_of(100,')) { $combine = 'max' }
    elseif ($expr.StartsWith('100 + (')) { $combine = 'sum-of-deltas' }
    return [pscustomobject]@{ Path = ''; Engine = ''; Combine = $combine; MaxMultiplier = $max; Fields = $fields.ToArray() }
}

function Get-RAGpsWeight {
    <# PURE. RiskScore_Weight_Factor (= RiskFactor_Weight) and RiskScore_Weight_Detailed of one row, as the generated KQL
       computes them (Build-WeightedFactorsKql): per field tolower(trim(" ", tostring(column_ifexists(field, "")))) looked up
       in its value map (else its default), combined in whole numbers (product / max / sum-of-deltas, then the cap); the
       detail names each field whose multiplier is not 100. #>
    param([Parameter(Mandatory)]$Row, $Config)
    if ($null -eq $Config -or @($Config.Fields).Count -eq 0) { return @{ Factor = [long]100; Detailed = '' } }
    $mults = New-Object System.Collections.Generic.List[long]
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($Config.Fields)) {
        $field = [string]$f.field
        $raw = ''
        if (Test-RAGpsHasColumn -Row $Row -Name $field) { $raw = ConvertTo-RAGpsKqlString (Get-RAGpsValue -Row $Row -Name $field) }
        $key = $raw.Trim(' ').ToLowerInvariant()
        $m = $null
        foreach ($p in $f.valueMap.PSObject.Properties) { if ([string]::Equals(([string]$p.Name).ToLowerInvariant(), $key, [System.StringComparison]::Ordinal)) { $m = [long][int]([double]$p.Value); break } }
        if ($null -eq $m) {
            $def = 100.0
            if ($null -ne $f.default -and -not [string]::IsNullOrWhiteSpace([string]$f.default)) { $def = [double]$f.default }
            $m = [long][int]$def
        }
        $mults.Add($m)
        if ($m -ne 100) { $parts.Add(('{0}={1}' -f $field, $raw)) }
    }
    $n = $mults.Count
    $x = [long]100
    switch ([string]$Config.Combine) {
        'max' { foreach ($m in $mults) { if ($m -gt $x) { $x = $m } } }
        'sum-of-deltas' { foreach ($m in $mults) { $x += ($m - 100) } }
        default {
            if ($n -eq 1) { $x = $mults[0] }
            elseif ($n -gt 1) {
                $prod = [System.Numerics.BigInteger]::One; foreach ($m in $mults) { $prod = $prod * [System.Numerics.BigInteger]$m }
                $div = [System.Numerics.BigInteger]::Pow([System.Numerics.BigInteger]100, $n - 1)
                $x = [long][System.Numerics.BigInteger]::Divide($prod, $div)   # whole-number division, toward zero (as KQL long / long)
            }
        }
    }
    if ([double]$Config.MaxMultiplier -gt 0) { $cap = [long][int]([double]$Config.MaxMultiplier); if ($cap -lt $x) { $x = $cap } }
    return @{ Factor = [long]$x; Detailed = ($parts -join ';') }
}

# ------------------------------------------------------------------------------------------------------------------
#  THE QUERY SHAPE -- is THIS the query the port was written for, and what does it ask?
# ------------------------------------------------------------------------------------------------------------------
# SHA-256 of the report query's text with the parts the engine writes per run taken out (Get-RAGpsShapeText): a locked query
# that changes, or a customer's own query of the same name, is not the one this port reproduces -- it runs as before.
# tests\pester\SIv3-RaGraphStage.Tests.ps1 pins these against the locked query file.
$script:RAGpsShapeHash = @{
    Detailed = '1cf1659f08f6772b556b83754b67595f8f52533c471b82684ae08a086ccea76a'
    Summary  = '27672b695d1b0000593e753e12863937765eb488bdc857ac5ae01df6690003dc'
}
$script:RAGpsMatchLine = '| graph-match (Device)-[devEdge]->(CredOrIdent)-[bridge*0..3]->(Principal)-[role]->(RoleScope)-[inherit*0..2]->(AzureAsset)'
# the columns a vulnerable-device row carries where the engine's slice filter reads its key (ExposureGraphNodes + the lets)
$script:RAGpsVdColumns = @('NodeId', 'NodeLabel', 'NodeName', 'Categories', 'NodeProperties', 'EntityIds', '_ids', 'MdeDeviceId', 'DeviceKey')

function Get-RAGpsRegion {
    <# PURE. The text between two markers (both left out), or $null. #>
    param([AllowEmptyString()][string]$Text, [string]$Begin, [string]$End)
    $a = $Text.IndexOf($Begin); if ($a -lt 0) { return $null }
    $b = $Text.IndexOf($End, $a + $Begin.Length); if ($b -lt 0) { return $null }
    return $Text.Substring($a + $Begin.Length, $b - $a - $Begin.Length)
}

function Get-RAGpsShapeText {
    <# PURE. The query text with what the engine writes per run replaced by a mark (the scope block, the CI lookups, the slice
       filter, the weights, the data-out comment block), the // comments out and the white space folded. #>
    param([AllowEmptyString()][string]$Query)
    $q = ([string]$Query) -replace "`r", ''
    foreach ($pair in @(@('//__SI_SCOPE_BEGIN__', '//__SI_SCOPE_END__'), @('//__SI_CI_LINK_BEGIN__', '//__SI_CI_LINK_END__'), @('//__SI_CI_PEER_BEGIN__', '//__SI_CI_PEER_END__'),
                        @('//__BUCKET_FILTER_BEGIN__', '//__BUCKET_FILTER_END__'), @('//__WEIGHTED_FACTORS_BEGIN__', '//__WEIGHTED_FACTORS_END__'), @('//__SI_OUT_BEGIN__', '//__SI_OUT_END__'))) {
        $a = $q.IndexOf($pair[0])
        if ($a -lt 0) { continue }
        $b = $q.IndexOf($pair[1], $a)
        if ($b -lt 0) { continue }
        $q = $q.Substring(0, $a) + ' <' + $pair[0].Substring(4).Trim('_') + '> ' + $q.Substring($b + $pair[1].Length)
    }
    $q = [regex]::Replace($q, '(?m)//[^\n]*$', '')
    return ([regex]::Replace($q, '\s+', ' ').Trim())
}

function Get-RAGpsShapeHash {
    <# PURE. SHA-256 (hex) of Get-RAGpsShapeText. #>
    param([AllowEmptyString()][string]$Query)
    return (Get-RAGpsHex -Text (Get-RAGpsShapeText -Query $Query))
}

function Get-RAGpsQueryShape {
    <#
        PURE. What one hunting call of the report asks, read from its text: @{ Ok; Why; Grain; Count; Index; RowCount;
        RowIndex; Kind ('rows' | 'count' | 'groups'); GroupColumns; Weights; FinalIds; Body }. Ok = $false (with Why) when
        it is not exactly the query this port reproduces -- it then runs as before. What the engine adds after the report,
        in its order: [the excluded configuration ids][a row split][a count].
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query)
    $r = @{ Ok = $false; Why = ''; Grain = ''; Count = 1L; Index = 0L; RowCount = 1L; RowIndex = 0L; Kind = 'rows'; GroupColumns = @(); Weights = $null; FinalIds = @(); Body = '' }
    if ($Query.IndexOf($script:RAGpsMatchLine) -lt 0) { $r.Why = 'not the attack-path query'; return $r }
    $q = ($Query -replace "`r", '').TrimEnd().TrimEnd(';').TrimEnd()
    $m = [regex]::Match($q, '\n\| project SIGroupHash = hash_sha256\(tolower\((?<e>.+)\)\)\n\| distinct SIGroupHash$')
    if ($m.Success) {
        $r.Kind = 'groups'
        $r.GroupColumns = @([regex]::Matches($m.Groups['e'].Value, 'tostring\((?<c>[A-Za-z_][A-Za-z0-9_]*)\)') | ForEach-Object { $_.Groups['c'].Value })
        if ($r.GroupColumns.Count -eq 0) { $r.Why = 'a group count this port does not read'; return $r }
        $q = $q.Substring(0, $m.Index).TrimEnd()
    } elseif ($q -match '\n\| count$') {
        $r.Kind = 'count'; $q = $q.Substring(0, $q.Length - '| count'.Length).TrimEnd()
    }
    $m = [regex]::Match($q, '\n\| where \(tolong\(strcat\("0x", substring\(hash_sha256\(tostring\(pack_all\(\)\)\), 0, 8\)\)\) % (?<n>\d+)\) == (?<i>\d+)$')
    if ($m.Success) { $r.RowCount = [long]$m.Groups['n'].Value; $r.RowIndex = [long]$m.Groups['i'].Value; $q = $q.Substring(0, $m.Index).TrimEnd() }
    $m = [regex]::Match($q, '\n\| where not\(tostring\(column_ifexists\("ConfigurationId", ""\)\) in \(dynamic\((?<ids>\[.*\])\)\)\)$')
    if ($m.Success) {
        try { $r.FinalIds = @(ConvertFrom-Json -InputObject $m.Groups['ids'].Value | ForEach-Object { [string]$_ }) } catch { $r.Why = 'the excluded configuration ids could not be read'; return $r }
        $q = $q.Substring(0, $m.Index).TrimEnd()
    }
    if ($q -match '\|\s*count\s*$' -or $q -match 'pack_all\(\)') { $r.Why = 'a form of the query this port does not answer'; return $r }
    $bf = Get-RAGpsRegion -Text $q -Begin '//__BUCKET_FILTER_BEGIN__' -End '//__BUCKET_FILTER_END__'
    if ($null -eq $bf) { $r.Why = 'no slice filter'; return $r }
    $bft = $bf.Trim()
    if ($bft -ne '| where 1 == 1') {
        $fm = [regex]::Match($bft, '(?s)^\| extend __bucket_key = coalesce\(\s*(?<cols>.*?)\s*\)\s*\| where isnotempty\(__bucket_key\)\s*\| extend __bucket = tolong\(strcat\("0x", substring\(hash_sha256\(__bucket_key\), 0, 8\)\)\) % (?<n>\d+)\s*\| where __bucket == (?<i>\d+)$')
        if (-not $fm.Success) { $r.Why = 'a slice filter this port does not read'; return $r }
        $cols = @([regex]::Matches($fm.Groups['cols'].Value, "tostring\(column_ifexists\('(?<c>[^']+)',''\)\)") | ForEach-Object { $_.Groups['c'].Value })
        $at = [Array]::IndexOf([string[]]$cols, 'DeviceKey')
        if ($at -lt 0) { $r.Why = 'the slices are not cut on the device key'; return $r }
        for ($k = 0; $k -lt $at; $k++) { if ($script:RAGpsVdColumns -contains $cols[$k]) { $r.Why = ('the slices are cut on {0}, not the device key' -f $cols[$k]); return $r } }
        $r.Count = [long]$fm.Groups['n'].Value; $r.Index = [long]$fm.Groups['i'].Value
        if ($r.Count -lt 1 -or $r.Index -lt 0 -or $r.Index -ge $r.Count) { $r.Why = 'a slice filter this port does not read'; return $r }
    }
    $wb = Get-RAGpsRegion -Text $q -Begin '//__WEIGHTED_FACTORS_BEGIN__' -End '//__WEIGHTED_FACTORS_END__'
    if ($null -eq $wb) { $r.Why = 'no weights block'; return $r }
    $cfg = ConvertFrom-RAGpsWeightBlock -Block $wb
    if ($null -eq $cfg -or -not (Get-Command -Name Build-WeightedFactorsKql -ErrorAction SilentlyContinue)) { $r.Why = 'weights this port does not read'; return $r }
    $again = (Build-WeightedFactorsKql -Config $cfg) -replace "`r", ''
    if ([regex]::Replace($again, '\s+', ' ').Trim() -ne [regex]::Replace(($wb -replace "`r", ''), '\s+', ' ').Trim()) { $r.Why = 'weights this port does not read'; return $r }
    $r.Weights = $cfg
    $h = Get-RAGpsShapeHash -Query $q
    foreach ($g in 'Detailed', 'Summary') { if ($h -eq [string]$script:RAGpsShapeHash[$g]) { $r.Grain = $g } }
    if (-not $r.Grain) { $r.Why = 'the query is not the one this port was written for'; return $r }
    $r.Body = $q
    $r.Ok = $true
    return $r
}

# ------------------------------------------------------------------------------------------------------------------
#  SQL
# ------------------------------------------------------------------------------------------------------------------
function Get-RAGpsSql {
    <# PURE. The fixed statements (every value a parameter). Walk: credential / identity -> principal (0..3 steps, walks:
       a node may be revisited, as the query engine does; only nodes from which a node with a "has role on" edge can still
       be reached in the steps left are kept -- that never drops a path) and role scope -> Azure target (0..2 steps) with
       the query's target tests: a storage account, or a microsoft.* resource (not resources/ or authorization/) under a
       subscription / resource group scope. #>
    $tables = @('RaGraphRun', 'RaGraphNode', 'RaGraphEdge', 'RaGraphCP', 'RaGraphST')
    $del = { param($t) "SET @n = 1; WHILE @n > 0 BEGIN DELETE TOP (50000) FROM sidata.$t WHERE RunNo IN (SELECT RunNo FROM @old); SET @n = @@ROWCOUNT; END;" }
    @{
        Exists = ("SELECT CASE WHEN " + (($tables | ForEach-Object { "OBJECT_ID('sidata.$_') IS NOT NULL" }) -join ' AND ') + " THEN 1 ELSE 0 END;")
        # an earlier run of this grain (a run that stopped half way), this run's own earlier attempt, anything older than two
        # days, and rows whose run row is gone -- in batches
        Sweep  = @"
SET NOCOUNT ON;
DECLARE @old TABLE (RunNo INT PRIMARY KEY);
INSERT @old (RunNo) SELECT RunNo FROM sidata.RaGraphRun WHERE RunKey = @RunKey OR Grain = @Grain OR CreatedAt < DATEADD(day, -2, SYSUTCDATETIME());
INSERT @old (RunNo) SELECT x.RunNo FROM (SELECT RunNo FROM sidata.RaGraphNode UNION SELECT RunNo FROM sidata.RaGraphEdge UNION SELECT RunNo FROM sidata.RaGraphCP UNION SELECT RunNo FROM sidata.RaGraphST) AS x
    WHERE NOT EXISTS (SELECT 1 FROM sidata.RaGraphRun AS r WHERE r.RunNo = x.RunNo) AND NOT EXISTS (SELECT 1 FROM @old AS o WHERE o.RunNo = x.RunNo);
DECLARE @n INT;
$(& $del 'RaGraphEdge')
$(& $del 'RaGraphNode')
$(& $del 'RaGraphCP')
$(& $del 'RaGraphST')
DELETE FROM sidata.RaGraphRun WHERE RunNo IN (SELECT RunNo FROM @old);
SELECT COUNT(*) FROM @old;
"@
        Begin  = "INSERT sidata.RaGraphRun (RunKey, Grain) VALUES (@RunKey, @Grain); SELECT CAST(SCOPE_IDENTITY() AS int);"
        Nodes  = @"
INSERT sidata.RaGraphNode (RunNo, K, Fl, NodeId, NodeName, NodeLabel, DeviceKey, Bh, Cvss, RiskFactorSet)
SELECT CONVERT(int, @RunNo), CONVERT(binary(16), j.K, 2), j.Fl, j.NodeId, j.NodeName, j.NodeLabel, j.DeviceKey, j.Bh, j.Cvss, j.Rf
FROM OPENJSON(@j) WITH (K varchar(32) '$.K', Fl int '$.Fl', NodeId nvarchar(max) '$.NodeId', NodeName nvarchar(max) '$.NodeName', NodeLabel nvarchar(max) '$.NodeLabel',
                        DeviceKey nvarchar(max) '$.DeviceKey', Bh bigint '$.Bh', Cvss float '$.Cvss', Rf nvarchar(max) '$.Rf' AS JSON) AS j;
SELECT @@ROWCOUNT;
"@
        Edges  = @"
INSERT sidata.RaGraphEdge (RunNo, S, T, L, Lt)
SELECT CONVERT(int, @RunNo), CONVERT(binary(16), j.S, 2), CONVERT(binary(16), j.T, 2), j.L, NULLIF(j.Lt, N'')
FROM OPENJSON(@j) WITH (S varchar(32) '$.S', T varchar(32) '$.T', L tinyint '$.L', Lt nvarchar(max) '$.Lt') AS j;
SELECT @@ROWCOUNT;
"@
        CountNodes = "SELECT COUNT_BIG(*) FROM sidata.RaGraphNode WHERE RunNo = CONVERT(int, @RunNo);"
        CountEdges = "SELECT COUNT_BIG(*) FROM sidata.RaGraphEdge WHERE RunNo = CONVERT(int, @RunNo);"
        # the one row of each node id the graph keeps (make-graph keeps one; the vulnerable-device row first, as the query's union)
        Pick   = @"
WITH n AS (SELECT Pk, rn = ROW_NUMBER() OVER (PARTITION BY K ORDER BY CASE WHEN (Fl & 16) = 16 THEN 0 ELSE 1 END, Seq) FROM sidata.RaGraphNode WHERE RunNo = CONVERT(int, @RunNo))
UPDATE n SET Pk = 1 WHERE rn = 1;
SELECT @@ROWCOUNT;
"@
        Walk   = @"
SET NOCOUNT ON;
DECLARE @r INT = CONVERT(int, @RunNo);
DELETE FROM sidata.RaGraphCP WHERE RunNo = @r;
DELETE FROM sidata.RaGraphST WHERE RunNo = @r;
CREATE TABLE #e (S BINARY(16) NOT NULL, T BINARY(16) NOT NULL, PRIMARY KEY (S, T));
INSERT #e (S, T) SELECT DISTINCT S, T FROM sidata.RaGraphEdge WHERE RunNo = @r;
CREATE TABLE #et (T BINARY(16) NOT NULL, S BINARY(16) NOT NULL, PRIMARY KEY (T, S));
INSERT #et (T, S) SELECT T, S FROM #e;
CREATE TABLE #r0 (X BINARY(16) NOT NULL PRIMARY KEY);
INSERT #r0 (X) SELECT DISTINCT S FROM sidata.RaGraphEdge WHERE RunNo = @r AND L = 1;
CREATE TABLE #r1 (X BINARY(16) NOT NULL PRIMARY KEY);
INSERT #r1 (X) SELECT X FROM #r0 UNION SELECT et.S FROM #r0 AS r JOIN #et AS et ON et.T = r.X;
CREATE TABLE #r2 (X BINARY(16) NOT NULL PRIMARY KEY);
INSERT #r2 (X) SELECT X FROM #r1 UNION SELECT et.S FROM #r1 AS r JOIN #et AS et ON et.T = r.X;
CREATE TABLE #r3 (X BINARY(16) NOT NULL PRIMARY KEY);
INSERT #r3 (X) SELECT X FROM #r2 UNION SELECT et.S FROM #r2 AS r JOIN #et AS et ON et.T = r.X;
CREATE TABLE #b0 (C BINARY(16) NOT NULL, X BINARY(16) NOT NULL, PRIMARY KEY (C, X));
INSERT #b0 (C, X)
SELECT DISTINCT e.T, e.T
FROM sidata.RaGraphEdge AS e
JOIN sidata.RaGraphNode AS d ON d.RunNo = @r AND d.K = e.S AND d.Pk = 1 AND (d.Fl & 16) = 16
JOIN sidata.RaGraphNode AS c ON c.RunNo = @r AND c.K = e.T AND c.Pk = 1 AND (c.Fl & 3) <> 0
JOIN #r3 AS q ON q.X = e.T
WHERE e.RunNo = @r AND e.L = 2;
CREATE TABLE #b1 (C BINARY(16) NOT NULL, X BINARY(16) NOT NULL, PRIMARY KEY (C, X));
INSERT #b1 (C, X) SELECT DISTINCT b.C, e.T FROM #b0 AS b JOIN #e AS e ON e.S = b.X JOIN #r2 AS q ON q.X = e.T;
CREATE TABLE #b2 (C BINARY(16) NOT NULL, X BINARY(16) NOT NULL, PRIMARY KEY (C, X));
INSERT #b2 (C, X) SELECT DISTINCT b.C, e.T FROM #b1 AS b JOIN #e AS e ON e.S = b.X JOIN #r1 AS q ON q.X = e.T;
CREATE TABLE #b3 (C BINARY(16) NOT NULL, X BINARY(16) NOT NULL, PRIMARY KEY (C, X));
INSERT #b3 (C, X) SELECT DISTINCT b.C, e.T FROM #b2 AS b JOIN #e AS e ON e.S = b.X JOIN #r0 AS q ON q.X = e.T;
INSERT sidata.RaGraphCP (RunNo, C, P)
SELECT @r, u.C, u.X FROM (SELECT C, X FROM #b0 UNION SELECT C, X FROM #b1 UNION SELECT C, X FROM #b2 UNION SELECT C, X FROM #b3) AS u JOIN #r0 AS q ON q.X = u.X;
DECLARE @cp BIGINT = @@ROWCOUNT;
CREATE TABLE #p (P BINARY(16) NOT NULL PRIMARY KEY);
INSERT #p (P) SELECT DISTINCT P FROM sidata.RaGraphCP WHERE RunNo = @r;
CREATE TABLE #s0 (S BINARY(16) NOT NULL, X BINARY(16) NOT NULL, PRIMARY KEY (S, X));
INSERT #s0 (S, X) SELECT DISTINCT e.T, e.T FROM sidata.RaGraphEdge AS e JOIN #p AS p ON p.P = e.S WHERE e.RunNo = @r AND e.L = 1;
CREATE TABLE #s1 (S BINARY(16) NOT NULL, X BINARY(16) NOT NULL, PRIMARY KEY (S, X));
INSERT #s1 (S, X) SELECT DISTINCT s.S, e.T FROM #s0 AS s JOIN #e AS e ON e.S = s.X;
CREATE TABLE #s2 (S BINARY(16) NOT NULL, X BINARY(16) NOT NULL, PRIMARY KEY (S, X));
INSERT #s2 (S, X) SELECT DISTINCT s.S, e.T FROM #s1 AS s JOIN #e AS e ON e.S = s.X;
INSERT sidata.RaGraphST (RunNo, S, T)
SELECT @r, u.S, u.X
FROM (SELECT S, X FROM #s0 UNION SELECT S, X FROM #s1 UNION SELECT S, X FROM #s2) AS u
JOIN sidata.RaGraphNode AS t ON t.RunNo = @r AND t.K = u.X AND t.Pk = 1 AND (t.Fl & 4) = 4
LEFT JOIN sidata.RaGraphNode AS s ON s.RunNo = @r AND s.K = u.S AND s.Pk = 1
WHERE (t.Fl & 32) = 32 OR ((ISNULL(s.Fl, 0) & 64) = 64 AND (t.Fl & 128) = 128);
DECLARE @st BIGINT = @@ROWCOUNT;
SELECT Cp = @cp, St = @st;
"@
        Ready  = "UPDATE sidata.RaGraphRun SET State = N'ready', Nodes = CONVERT(bigint, @Nodes), Edges = CONVERT(bigint, @Edges) WHERE RunNo = CONVERT(int, @RunNo); SELECT @@ROWCOUNT;"
        Drop   = @"
SET NOCOUNT ON;
DECLARE @old TABLE (RunNo INT PRIMARY KEY); INSERT @old (RunNo) VALUES (CONVERT(int, @RunNo));
DECLARE @n INT;
$(& $del 'RaGraphEdge')
$(& $del 'RaGraphNode')
$(& $del 'RaGraphCP')
$(& $del 'RaGraphST')
DELETE FROM sidata.RaGraphRun WHERE RunNo IN (SELECT RunNo FROM @old);
SELECT 1;
"@
    }
}

function Get-RAGpsSliceSql {
    <#
        PURE. One report slice's paths, in three reads on ONE connection (the slice's devices are kept in #temp tables
        between them -- the 'session' mode of the data seam): -Count / -Index = the engine's slice of the device key
        (the hash it cuts on, Bh), 1 / 0 = all. Every value is a whole number written into the text (a session batch runs
        without parameters).
          Paths   one row per device and target: the (credential / identity, device edge label) pairs, the principals, the
                  role scope picked for the row (the lowest name, then label, then key: the same scope every run -- the
                  query's take_any may give any of them)
          Nodes   the node row the graph keeps for every key in those rows
          Enrich  the slice's vulnerable-device rows of those devices (the query's _DeviceEnrichment join)
    #>
    param([Parameter(Mandatory)][int]$RunNo, [long]$Count = 1, [long]$Index = 0)
    $r = [int]$RunNo; $n = [long][Math]::Max(1, $Count); $i = [long]$Index
    @{
        Build = @"
SET NOCOUNT ON;
IF OBJECT_ID('tempdb..#x') IS NOT NULL DROP TABLE #x;
IF OBJECT_ID('tempdb..#dc') IS NOT NULL DROP TABLE #dc;
IF OBJECT_ID('tempdb..#d') IS NOT NULL DROP TABLE #d;
CREATE TABLE #d (K BINARY(16) NOT NULL PRIMARY KEY);
INSERT #d (K) SELECT DISTINCT K FROM sidata.RaGraphNode WHERE RunNo = $r AND Bh IS NOT NULL AND Bh % $n = $i;
CREATE TABLE #dc (D BINARY(16) NOT NULL, C BINARY(16) NOT NULL, Lt NVARCHAR(4000) COLLATE Latin1_General_100_BIN2 NOT NULL);
INSERT #dc (D, C, Lt)
SELECT DISTINCT e.S, e.T, ISNULL(CONVERT(NVARCHAR(4000), e.Lt), N'')
FROM #d AS d
JOIN sidata.RaGraphNode AS dn ON dn.RunNo = $r AND dn.K = d.K AND dn.Pk = 1 AND (dn.Fl & 16) = 16
JOIN sidata.RaGraphEdge AS e ON e.RunNo = $r AND e.S = d.K AND e.L = 2
JOIN sidata.RaGraphNode AS c ON c.RunNo = $r AND c.K = e.T AND c.Pk = 1 AND (c.Fl & 3) <> 0;
CREATE TABLE #x (D BINARY(16) NOT NULL, C BINARY(16) NOT NULL, P BINARY(16) NOT NULL, S BINARY(16) NOT NULL, T BINARY(16) NOT NULL);
INSERT #x (D, C, P, S, T)
SELECT DISTINCT dc.D, dc.C, cp.P, re.T, st.T
FROM (SELECT DISTINCT D, C FROM #dc) AS dc
JOIN sidata.RaGraphCP AS cp ON cp.RunNo = $r AND cp.C = dc.C
JOIN sidata.RaGraphEdge AS re ON re.RunNo = $r AND re.S = cp.P AND re.L = 1
JOIN sidata.RaGraphST AS st ON st.RunNo = $r AND st.S = re.T;
CREATE CLUSTERED INDEX cx ON #x (D, T);
"@
        Paths = @"
SET NOCOUNT ON;
WITH dt AS (SELECT DISTINCT D, T FROM #x),
pa AS (SELECT q.D, q.T, Pairs = STRING_AGG(CONVERT(NVARCHAR(MAX), CONCAT(CONVERT(VARCHAR(32), q.C, 2), N'|', q.Lt)), NCHAR(31))
       FROM (SELECT DISTINCT x.D, x.T, x.C, dc.Lt FROM (SELECT DISTINCT D, T, C FROM #x) AS x JOIN #dc AS dc ON dc.D = x.D AND dc.C = x.C) AS q GROUP BY q.D, q.T),
pp AS (SELECT q.D, q.T, Prins = STRING_AGG(CONVERT(NVARCHAR(MAX), CONVERT(VARCHAR(32), q.P, 2)), N',') FROM (SELECT DISTINCT D, T, P FROM #x) AS q GROUP BY q.D, q.T),
sc AS (SELECT z.D, z.T, z.S FROM (
        SELECT q.D, q.T, q.S, rn = ROW_NUMBER() OVER (PARTITION BY q.D, q.T ORDER BY ISNULL(n.NodeName, N'') COLLATE Latin1_General_100_BIN2, ISNULL(n.NodeLabel, N'') COLLATE Latin1_General_100_BIN2, q.S)
        FROM (SELECT DISTINCT D, T, S FROM #x) AS q LEFT JOIN sidata.RaGraphNode AS n ON n.RunNo = $r AND n.K = q.S AND n.Pk = 1) AS z WHERE z.rn = 1)
SELECT D = CONVERT(VARCHAR(32), dt.D, 2), T = CONVERT(VARCHAR(32), dt.T, 2), pa.Pairs, pp.Prins, S = CONVERT(VARCHAR(32), sc.S, 2)
FROM dt JOIN pa ON pa.D = dt.D AND pa.T = dt.T JOIN pp ON pp.D = dt.D AND pp.T = dt.T JOIN sc ON sc.D = dt.D AND sc.T = dt.T;
"@
        Nodes = @"
SET NOCOUNT ON;
SELECT K = CONVERT(VARCHAR(32), n.K, 2), n.Fl, n.NodeId, n.NodeName, n.NodeLabel, n.Bh, n.Cvss
FROM (SELECT D AS K FROM #x UNION SELECT C FROM #x UNION SELECT P FROM #x UNION SELECT S FROM #x UNION SELECT T FROM #x) AS k
JOIN sidata.RaGraphNode AS n ON n.RunNo = $r AND n.K = k.K AND n.Pk = 1;
"@
        Enrich = @"
SET NOCOUNT ON;
SELECT K = CONVERT(VARCHAR(32), n.K, 2), n.Seq, n.DeviceKey, n.RiskFactorSet
FROM (SELECT DISTINCT D FROM #x) AS d
JOIN sidata.RaGraphNode AS n ON n.RunNo = $r AND n.K = d.D AND n.Bh IS NOT NULL AND n.Bh % $n = $i
ORDER BY n.K, n.Seq;
"@
        Done = "DROP TABLE #x; DROP TABLE #dc; DROP TABLE #d;"
    }
}

# ------------------------------------------------------------------------------------------------------------------
#  S1 / S2 INTO SQL, ONCE PER RUN
# ------------------------------------------------------------------------------------------------------------------
function Get-RAGpsAnswerRows {
    <# The rows of a hunting answer, each a dictionary (the answer's own bag; odata annotations left out). #>
    param($Resp)
    if ($null -eq $Resp) { return , @() }
    if ($Resp -is [System.Collections.IEnumerable] -and -not ($Resp -is [string]) -and -not ($Resp -is [System.Collections.IDictionary])) { return , @($Resp) }
    if ($Resp.PSObject.Properties['_SIDirectRows']) { return , @($Resp._SIDirectRows) }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Resp.Results)) {
        if ($null -eq $r) { continue }
        if ($r.PSObject.Properties['AdditionalProperties'] -and $null -ne $r.AdditionalProperties) { $out.Add($r.AdditionalProperties) } else { $out.Add($r) }
    }
    return , $out.ToArray()
}

function Get-RAGpsCountValue {
    <# PURE. The Count of a count answer; $null when there is none. #>
    param([AllowEmptyCollection()][object[]]$Rows)
    if (@($Rows).Count -eq 0) { return 0L }
    foreach ($n in 'Count', 'count_') { $v = Get-RAGpsValue -Row $Rows[0] -Name $n; if ($null -ne $v) { return [long]$v } }
    return $null
}

function ConvertTo-RAGpsJsonText {
    <# PURE. A JSON string literal (null -> null). System.Text.Json where it is (PowerShell 7), else ConvertTo-Json. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($script:RAGpsStj) { return ('"' + [System.Text.Json.JsonEncodedText]::Encode([string]$Text).Value + '"') }
    return (ConvertTo-Json -InputObject ([string]$Text) -Compress)
}
$script:RAGpsStj = $null -ne ('System.Text.Json.JsonEncodedText' -as [type])
$script:RAGpsHexRx = [regex]'^[0-9A-Fa-f]{32}$'

function ConvertTo-RAGpsNodeItem {
    <# PURE. One S1 row -> the JSON object text sidata.RaGraphNode is written from (built as text: millions of rows). A key
       that is not 32 hex digits is refused (the load then fails: never a node stored under a wrong key). #>
    param([Parameter(Mandatory)]$Row)
    $k = [string](Get-RAGpsValue -Row $Row -Name 'K')
    if (-not $script:RAGpsHexRx.IsMatch($k)) { throw ('a node of the attack-path graph came without its key ({0})' -f $k) }
    $fl = [int](Get-RAGpsValue -Row $Row -Name 'Fl')
    $cv = ConvertTo-RAGpsDouble (Get-RAGpsValue -Row $Row -Name 'Cvss')
    $sb = New-Object System.Text.StringBuilder 256
    [void]$sb.Append('{"K":"').Append($k).Append('","Fl":').Append($fl.ToString([System.Globalization.CultureInfo]::InvariantCulture))
    [void]$sb.Append(',"NodeId":').Append((ConvertTo-RAGpsJsonText ([string](Get-RAGpsValue -Row $Row -Name 'NodeId'))))
    [void]$sb.Append(',"NodeName":').Append((ConvertTo-RAGpsJsonText ([string](Get-RAGpsValue -Row $Row -Name 'NodeName'))))
    [void]$sb.Append(',"NodeLabel":').Append((ConvertTo-RAGpsJsonText ([string](Get-RAGpsValue -Row $Row -Name 'NodeLabel'))))
    [void]$sb.Append(',"Cvss":'); if ($null -eq $cv) { [void]$sb.Append('null') } else { [void]$sb.Append(([double]$cv).ToString('R', [System.Globalization.CultureInfo]::InvariantCulture)) }
    if (($fl -band 16) -eq 16) {
        $bh = Get-RAGpsValue -Row $Row -Name 'Bh'
        [void]$sb.Append(',"DeviceKey":').Append((ConvertTo-RAGpsJsonText ([string](Get-RAGpsValue -Row $Row -Name 'DeviceKey'))))
        [void]$sb.Append(',"Bh":'); if ($null -eq $bh -or [string]$bh -eq '' -or $bh -is [System.Collections.IDictionary]) { [void]$sb.Append('null') } else { [void]$sb.Append(([long]$bh).ToString([System.Globalization.CultureInfo]::InvariantCulture)) }
        $rf = ConvertTo-RAGpsArray (Get-RAGpsValue -Row $Row -Name 'RiskFactorSet')
        [void]$sb.Append(',"Rf":')
        if ($null -eq $rf) { [void]$sb.Append('null') } else { [void]$sb.Append('[').Append((@($rf | ForEach-Object { ConvertTo-RAGpsJsonText ([string]$_) }) -join ',')).Append(']') }
    } else { [void]$sb.Append(',"DeviceKey":null,"Bh":null,"Rf":null') }
    return $sb.Append('}').ToString()
}

function ConvertTo-RAGpsEdgeItem {
    <# PURE. One S2 row -> the JSON object text sidata.RaGraphEdge is written from (built as text: millions of rows). Keys
       that are not 32 hex digits are refused (the load then fails). #>
    param([Parameter(Mandatory)]$Row)
    if ($Row -is [System.Collections.IDictionary]) { $s = [string]$Row['S']; $t = [string]$Row['T']; $l = $Row['L']; $lt = $Row['Lt'] }
    else { $s = [string](Get-RAGpsValue -Row $Row -Name 'S'); $t = [string](Get-RAGpsValue -Row $Row -Name 'T'); $l = Get-RAGpsValue -Row $Row -Name 'L'; $lt = Get-RAGpsValue -Row $Row -Name 'Lt' }
    if (-not $script:RAGpsHexRx.IsMatch($s) -or -not $script:RAGpsHexRx.IsMatch($t)) { throw ('an edge of the attack-path graph came without its keys ({0} -> {1})' -f $s, $t) }
    $ltText = 'null'; if ($null -ne $lt -and [string]$lt -ne '') { $ltText = ConvertTo-RAGpsJsonText ([string]$lt) }
    return ('{"S":"' + $s + '","T":"' + $t + '","L":' + ([int]$l).ToString([System.Globalization.CultureInfo]::InvariantCulture) + ',"Lt":' + $ltText + '}')
}

function Read-RAGpsStep {
    <#
        One read (S1 or S2) in parts, every part written as it comes: -Expected rows (the source's count) in parts of about
        -TargetRows. A part advanced hunting answers 504 twice, or one too large / too slow for it, is split in two (the same
        hash at twice the count: the halves are exactly the part); a throttled / busy part is asked again after the others
        (the hunting call itself waits on 429s); a query defect or a part that cannot be read after every round fails the
        read. Returns @{ Rows; Calls; Parts; Finest; Seconds }. -Hunt { param($Kql) rows }; -Write { param($Rows) written }.
    #>
    param([Parameter(Mandatory)][ValidateSet('Nodes', 'Edges')][string]$Step, [Parameter(Mandatory)][scriptblock]$Hunt, [Parameter(Mandatory)][scriptblock]$Write,
          [long]$Expected = 0, [double]$TargetRows = 30000, [int]$Rounds = 4, [scriptblock]$Log, [scriptblock]$Pause)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $start = [long][Math]::Max(1, [Math]::Ceiling([double]$Expected / [Math]::Max(1.0, $TargetRows)))
    $queue = New-Object System.Collections.Generic.Queue[object]
    for ($p = 0L; $p -lt $start; $p++) { $queue.Enqueue(@{ Mod = $start; Idx = $p; Seen = 0; Tries = 0 }) }
    $late = New-Object System.Collections.Generic.List[object]
    $rows = 0L; $calls = 0; $finest = $start; $parts = 0
    $kqlOf = { param($part) if ($Step -eq 'Nodes') { Get-RAGpsNodeKql -Pages $part.Mod -Page $part.Idx } else { Get-RAGpsEdgeKql -Pages $part.Mod -Page $part.Idx } }
    $round = 0
    while ($true) {
        while ($queue.Count -gt 0) {
            $part = $queue.Dequeue()
            $canSplit = (($part.Mod * 2) -le [long][int]::MaxValue)
            $script:RAGatewayTimeoutStopAt = Get-RAGatewayTimeoutStopAt -Seen $part.Seen -SplitAt 2 -Off:(-not $canSplit)
            $script:_LastGraphHuntingGatewayTimeouts = 0
            $calls++
            try {
                $got = & $Hunt (& $kqlOf $part)
                $script:RAGatewayTimeoutStopAt = 0
                $rows += [long](& $Write @($got))
                $parts++
            } catch {
                $script:RAGatewayTimeoutStopAt = 0
                $err = $_
                $act = Get-RABucketFailureAction -Err $err -AllTimedOut ([bool]$script:_LastGraphHuntingAllTimedOut)
                if ($act -eq 'Retry') {
                    # the hunting call's own count of its 504 answers; a call that reported none counts its own 504 once
                    $gw = [int]$script:_LastGraphHuntingGatewayTimeouts
                    if ($gw -le 0 -and (Test-RABucketGatewayTimeout -Err $err)) { $gw = 1 }
                    $part.Seen = [int]$part.Seen + [int][Math]::Max(0, $gw)
                    if ((Get-RAGatewayTimeoutAction -Err $err -Count $part.Seen -SplitAt 2 -CanSplit $canSplit) -eq 'Split') { $act = 'Split' }
                }
                if ($act -eq 'Split' -and $canSplit) {
                    $m2 = [long]$part.Mod * 2
                    $queue.Enqueue(@{ Mod = $m2; Idx = [long]$part.Idx; Seen = 0; Tries = 0 })
                    $queue.Enqueue(@{ Mod = $m2; Idx = [long]$part.Idx + [long]$part.Mod; Seen = 0; Tries = 0 })
                    if ($m2 -gt $finest) { $finest = $m2 }
                    if ($Log) { & $Log 'INFO' ('the attack-path graph read ({0}): part {1}/{2} was too heavy for advanced hunting -- read as two halves' -f $Step, ($part.Idx + 1), $part.Mod) }
                    continue
                }
                if ($act -eq 'Retry') { $part.Tries = [int]$part.Tries + 1; $late.Add($part); continue }
                throw ('the attack-path graph could not be read ({0}, part {1}/{2}): {3}' -f $Step, ($part.Idx + 1), $part.Mod, $err.Exception.Message)
            }
        }
        if ($late.Count -eq 0) { break }
        $round++
        if ($round -gt $Rounds) { throw ('the attack-path graph could not be read ({0}): {1} part(s) were still refused after {2} rounds -- {3}' -f $Step, $late.Count, $Rounds, 'advanced hunting was busy or throttled') }
        if ($Pause) { & $Pause $round } elseif (Get-Command -Name Get-RABucketRetryDelaySeconds -ErrorAction SilentlyContinue) { Start-Sleep -Seconds ([int](Get-RABucketRetryDelaySeconds -Attempt $round)) } else { Start-Sleep -Seconds (30 * $round) }
        foreach ($x in $late) { $queue.Enqueue($x) }
        $late.Clear()
    }
    $sw.Stop()
    return @{ Rows = $rows; Calls = $calls; Parts = $parts; Finest = $finest; Seconds = $sw.Elapsed.TotalSeconds }
}

function Invoke-RAGpsLoad {
    <#
        The run's graph into SQL: the earlier leftovers swept, both reads counted, read in parts and written, the stored
        rows checked against both counts, both counts asked again (a graph that changed while it was read is read once
        more, never mixed), then the one row per node id and the two walks. Returns @{ RunKey; RunNo; Nodes; Edges; Cp; St;
        Calls; Parts; Seconds }. Any shortfall throws (the caller makes it "lookup unavailable": the reports are not complete).
    #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][scriptblock]$Hunt, [double]$TargetRows = 30000, [scriptblock]$Log, [scriptblock]$Pause)
    $sql = Get-RAGpsSql
    $run = { param($s, $p, $mode) Invoke-RAStreamSql -Stream $Stream -Sql $s -Params $p -Mode $mode -What 'storing the attack-path graph of this run' }
    if ([int](& $run $sql.Exists @{} 'scalar') -ne 1) { throw 'the database does not have the tables for the attack-path graph yet (the updater adds them with the data schema)' }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $grain = [string]$Stream.Grain; if (-not $grain) { $grain = ([string]$Stream.RunKey -split '\|')[0] }
    $swept = [int](& $run $sql.Sweep @{ RunKey = [string]$Stream.RunKey; Grain = $grain } 'scalar')
    if ($swept -gt 0 -and $Log) { & $Log 'INFO' ('the attack-path graph: {0} graph(s) an earlier run left in the database were removed' -f $swept) }
    $count = { param($kql) $ans = & $Hunt $kql; $c = Get-RAGpsCountValue -Rows (Get-RAGpsRows $ans); if ($null -eq $c) { throw 'the count of the attack-path graph read returned no Count column' }; [long]$c }
    $calls = 0; $parts = 0
    $runNo = 0
    try {
    for ($attempt = 1; ; $attempt++) {
        $runNo = [int](& $run $sql.Begin @{ RunKey = [string]$Stream.RunKey; Grain = $grain } 'scalar')
        $nN = & $count (Get-RAGpsNodeKql -Count); $nE = & $count (Get-RAGpsEdgeKql -Count); $calls += 2
        $wstate = @{ Chunk = [long]0; RunNo = $runNo; Invoke = $Stream.Invoke; Sql = $sql }
        $writeOf = {
            param($what, $rowsIn)
            $items = New-Object System.Collections.Generic.List[string]
            foreach ($x in (Get-RAGpsRows $rowsIn)) { if ($null -eq $x) { continue }; if ($what -eq 'Nodes') { $items.Add((ConvertTo-RAGpsNodeItem -Row $x)) } else { $items.Add((ConvertTo-RAGpsEdgeItem -Row $x)) } }
            if ($items.Count -eq 0) { return 0L }
            $cref = [ref]([long]$wstate.Chunk)
            $stmt = $wstate.Sql.Edges; if ($what -eq 'Nodes') { $stmt = $wstate.Sql.Nodes }
            $w = [long](Write-SIDataJsonRows -Invoke $wstate.Invoke -Sql $stmt -Items $items.ToArray() -Params @{ RunNo = [string]$wstate.RunNo } -ChunkChars $cref -What 'the attack-path graph')
            $wstate.Chunk = [long]$cref.Value
            if ($w -ne $items.Count) { throw ('the attack-path graph: {0} row(s) read, {1} stored' -f $items.Count, $w) }
            $w
        }
        $rn = Read-RAGpsStep -Step Nodes -Hunt $Hunt -Write { param($r) & $writeOf 'Nodes' $r } -Expected $nN -TargetRows $TargetRows -Log $Log -Pause $Pause
        $re = Read-RAGpsStep -Step Edges -Hunt $Hunt -Write { param($r) & $writeOf 'Edges' $r } -Expected $nE -TargetRows $TargetRows -Log $Log -Pause $Pause
        $calls += $rn.Calls + $re.Calls; $parts += $rn.Parts + $re.Parts
        $sN = [long](& $run $sql.CountNodes @{ RunNo = [string]$runNo } 'scalar'); $sE = [long](& $run $sql.CountEdges @{ RunNo = [string]$runNo } 'scalar')
        $aN = & $count (Get-RAGpsNodeKql -Count); $aE = & $count (Get-RAGpsEdgeKql -Count); $calls += 2
        $ok = ($sN -eq $nN -and $sE -eq $nE -and $aN -eq $nN -and $aE -eq $nE -and $rn.Rows -eq $nN -and $re.Rows -eq $nE)
        if ($ok) { break }
        $null = & $run $sql.Drop @{ RunNo = [string]$runNo } 'scalar'
        $why = ('the source counted {0:N0} node(s) and {1:N0} edge(s) before the read and {2:N0} / {3:N0} after it; {4:N0} / {5:N0} were stored' -f $nN, $nE, $aN, $aE, $sN, $sE)
        if ($attempt -ge 2) { throw ('the attack-path graph could not be read whole -- ' + $why) }
        if ($Log) { & $Log 'INFO' ('the attack-path graph changed while it was read ({0}) -- it is read again' -f $why) }
    }
    $null = & $run $sql.Pick @{ RunNo = [string]$runNo } 'scalar'
    $wkAns = & $run $sql.Walk @{ RunNo = [string]$runNo } 'reader'
    $wk = Get-RAGpsRows $wkAns
    $cp = 0L; $st = 0L
    if ($wk.Count -gt 0) { $cp = [long](Get-RAGpsValue -Row $wk[0] -Name 'Cp'); $st = [long](Get-RAGpsValue -Row $wk[0] -Name 'St') }
    $null = & $run $sql.Ready @{ RunNo = [string]$runNo; Nodes = [string]$nN; Edges = [string]$nE } 'scalar'
    } catch {
        # nothing of a graph that was not read whole is left for a report to read (the next load sweeps it too)
        if ($runNo -gt 0) { try { $null = & $run $sql.Drop @{ RunNo = [string]$runNo } 'scalar' } catch { } }
        throw
    }
    $sw.Stop()
    return @{ RunKey = [string]$Stream.RunKey; RunNo = $runNo; Nodes = $nN; Edges = $nE; Cp = $cp; St = $st; Calls = $calls; Parts = $parts; Seconds = $sw.Elapsed.TotalSeconds }
}

function Sync-RAGraphStage {
    <# The run's graph in SQL, ONCE per run (a queue worker uses its producer's load and never loads itself). A failure is
       remembered for the run and thrown as "lookup unavailable": every report that needs the graph is NOT COMPLETE and
       keeps its last complete result -- never a smaller graph. -Hunt { param($Kql) rows } is a test seam. #>
    param([Parameter(Mandatory)]$Stream, [scriptblock]$Hunt, [double]$TargetRows = 0, [scriptblock]$Pause)
    if ($null -ne $script:RAGpsSet -and [string]$script:RAGpsSet.RunKey -eq [string]$Stream.RunKey) { return $script:RAGpsSet }
    if ($script:RAGpsSetFailed) { throw (New-RALookupUnavailableError -Message ([string]$script:RAGpsSetFailed)) }
    if ($script:RAGpsWorker) { throw (New-RALookupUnavailableError -Message 'a lookup this report needs could not be read -- the attack-path graph of this run was not loaded by its producer') }
    if (-not $Hunt) {
        $Hunt = {
            param($Kql)
            $mr = 4; if ([int]$global:GraphQueryMaxRetries -gt 0) { $mr = [int]$global:GraphQueryMaxRetries }
            $age = 45; if ([int]$global:GraphReconnectMaxAgeMinutes -gt 0) { $age = [int]$global:GraphReconnectMaxAgeMinutes }
            $resp = Invoke-GraphHuntingQuery -Query $Kql -ReconnectMaxAgeMinutes $age -MaxRetries $mr
            Get-RAGpsAnswerRows -Resp $resp
        }
    }
    if ($TargetRows -le 0) { $TargetRows = 30000; if (Get-Command -Name Get-SIRaPlanningRowLimit -ErrorAction SilentlyContinue) { $TargetRows = [double](Get-SIRaPlanningRowLimit -Backend 'hunting') } }
    $log = { param($l, $m) if ($l -eq 'WARN' -and (Get-Command -Name Write-Warn2 -ErrorAction SilentlyContinue)) { Write-Warn2 $m } elseif (Get-Command -Name Write-Info -ErrorAction SilentlyContinue) { Write-Info $m } }
    try {
        $set = Invoke-RAGpsLoad -Stream $Stream -Hunt $Hunt -TargetRows $TargetRows -Log $log -Pause $Pause
    } catch {
        $why = 'a lookup this report needs could not be read -- ' + [string]$_.Exception.Message
        $script:RAGpsSetFailed = $why
        & $log 'WARN' ('the attack-path graph could not be read for this run -- the attack-path reports from vulnerable devices to Azure are not complete this run and keep their last complete result: {0}' -f $_.Exception.Message)
        throw (New-RALookupUnavailableError -Message $why)
    }
    $script:RAGpsSet = $set
    & $log 'INFO' ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "the attack-path graph is in the database for this run: {0:N0} node(s) and {1:N0} edge(s), read in {2} part(s) ({3} request(s)) in {4:F1}s -- the attack-path reports from vulnerable devices to Azure are joined there, slice by slice", $set.Nodes, $set.Edges, $set.Parts, $set.Calls, $set.Seconds))
    return $set
}

function Complete-RAGraphStageRun {
    <# The run's end (the producer / the single job): the note on paths whose principal is a device read in another slice,
       and the run's graph removed from SQL (what a run that stopped leaves is removed by the next load). Never throws. #>
    Write-RAGraphStageNote
    if ($null -ne $script:RAGpsSet -and $script:RAStreamOn -and $null -ne $script:RAStream -and -not $script:RAGpsWorker) {
        try { $null = Invoke-RAStreamSql -Stream $script:RAStream -Sql (Get-RAGpsSql).Drop -Params @{ RunNo = [string]$script:RAGpsSet.RunNo } -Mode 'scalar' }
        catch { if (Get-Command -Name Write-Warn2 -ErrorAction SilentlyContinue) { Write-Warn2 ('the attack-path graph of this run could not be removed from the database (the next run removes it): {0}' -f $_.Exception.Message) } }
    }
    $script:RAGpsSet = $null
}

function Write-RAGraphStageNote {
    <# Once per run (per process): how many attack paths now name a principal that is a vulnerable device -- the query read
       such a device as a node without a name when it was in another slice. Said only when there are any. #>
    if ($null -eq $script:RAGpsRun -or $script:RAGpsRun.Said) { return }
    $n = 0L; foreach ($v in $script:RAGpsRun.OtherPart.Values) { $n += [long]$v }
    $script:RAGpsRun.Said = $true
    if ($n -gt 0 -and (Get-Command -Name Write-Info -ErrorAction SilentlyContinue)) {
        Write-Info ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "the attack-path report now names {0:N0} identit(ies) that are themselves vulnerable devices: earlier runs listed those paths with that name left empty when the device was read in another part of the report", $n))
    }
}

# ------------------------------------------------------------------------------------------------------------------
#  ONE SLICE: SQL -> the query's path rows -> the rest of the query
# ------------------------------------------------------------------------------------------------------------------
function Get-RAGpsSliceData {
    <# One slice's paths, nodes and device rows from SQL, on one connection (the data seam's 'session' mode). Returns
       @{ Paths; Nodes (key -> row); Enrich (key -> rows) }. -Session { param($Sql, $Mode) } is a test seam. #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][int]$RunNo, [long]$Count = 1, [long]$Index = 0)
    $q = Get-RAGpsSliceSql -RunNo $RunNo -Count $Count -Index $Index
    $inv = $Stream.Invoke
    if (-not ($inv.PSObject.Properties['SISqlSession'] -and [bool]$inv.SISqlSession)) { throw 'the database connection cannot hold one session for a slice (it is needed for the attack-path graph)' }
    $box = @{ P = @(); N = @(); E = @() }
    $step = {
        param($Run)
        $null = & $Run $q.Build 'nonquery'
        $a1 = & $Run $q.Paths 'reader'; $box.P = Get-RAGpsRows $a1
        $a2 = & $Run $q.Nodes 'reader'; $box.N = Get-RAGpsRows $a2
        $a3 = & $Run $q.Enrich 'reader'; $box.E = Get-RAGpsRows $a3
        $null = & $Run $q.Done 'nonquery'
        $true
    }   # not a closure: run from inside the seam, it still sees this function's $box / $q and the engine's functions
    $null = & $inv '' @{} 'session' $step
    $paths = @($box.P | Where-Object { $null -ne $_ })
    $nodes = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($x in @($box.N)) { if ($null -ne $x) { $nodes[[string](Get-RAGpsValue -Row $x -Name 'K')] = $x } }
    $enrich = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($x in @($box.E)) {
        if ($null -eq $x) { continue }
        $k = [string](Get-RAGpsValue -Row $x -Name 'K')
        if (-not $enrich.ContainsKey($k)) { $enrich[$k] = New-Object System.Collections.Generic.List[object] }
        $enrich[$k].Add($x)
    }
    return @{ Paths = $paths; Nodes = $nodes; Enrich = $enrich }
}

function ConvertTo-RAGpsPathRows {
    <#
        PURE. The query's _Paths rows of one slice from its SQL rows. Detailed: one row per device and target (the query's
        summarize: the entry vectors, device edges, credentials (at most 10, as make_set(..., 10)), first-hop labels,
        reached identities, a role scope, the device's CVSS). Summary: one row per device, target, first-hop label and
        device edge (the query keeps every match row; its summarize reads only sets / max / min / dcount, so the distinct
        rows give the same result). Each row carries _K (the device key) for the device-row join. Also returns OtherPart:
        the Detailed rows whose principal is a vulnerable device outside this slice (-Count / -Index).
    #>
    param([Parameter(Mandatory)][hashtable]$Data, [Parameter(Mandatory)][ValidateSet('Detailed', 'Summary')][string]$Grain, [long]$Count = 1, [long]$Index = 0)
    $nodes = $Data.Nodes
    $nd = { param($k) $o = $null; if ($k -and $nodes.TryGetValue([string]$k, [ref]$o)) { $o } else { $null } }
    $str = { param($row, $col) $v = Get-RAGpsValue -Row $row -Name $col; if ($null -eq $v) { '' } else { [string]$v } }
    $out = New-Object System.Collections.Generic.List[object]
    $other = 0L
    foreach ($row in @($Data.Paths)) {
        $dk = [string](Get-RAGpsValue -Row $row -Name 'D'); $tk = [string](Get-RAGpsValue -Row $row -Name 'T')
        $d = & $nd $dk; $t = & $nd $tk
        $tLabel = & $str $t 'NodeLabel'
        $tt = Get-RAGpsTargetType -TargetLabel $tLabel
        $cvss = ConvertTo-RAGpsDouble (Get-RAGpsValue -Row $d -Name 'Cvss')
        $pairs = New-Object System.Collections.Generic.List[object]
        foreach ($pr in ([string](Get-RAGpsValue -Row $row -Name 'Pairs')).Split([char]31)) {
            if ($pr -eq '') { continue }
            $bar = $pr.IndexOf('|')
            $c = & $nd $pr.Substring(0, $bar)
            $pairs.Add(@{ Lt = $pr.Substring($bar + 1); Label = (& $str $c 'NodeLabel'); Name = (& $str $c 'NodeName'); Secret = ((([int](Get-RAGpsValue -Row $c -Name 'Fl')) -band 1) -eq 1) })
        }
        if ($Grain -eq 'Summary') {
            $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
            foreach ($p in $pairs) {
                if (-not $seen.Add(([string]$p.Label + [char]31 + [string]$p.Lt))) { continue }
                $out.Add([ordered]@{ _K = $dk; EntryPointDeviceId = (& $str $d 'NodeId'); EntryPointDevice = (& $str $d 'NodeName'); MaxCvssScore = $cvss
                                     FirstHopLabel = [string]$p.Label; DeviceEdge = [string]$p.Lt
                                     TargetAzureAssetId = (& $str $t 'NodeId'); TargetAzureAsset = (& $str $t 'NodeName'); TargetLabel = $tLabel
                                     TargetType = $tt.Type; AttackPathName = $tt.Name })
            }
            continue
        }
        $prins = New-Object System.Collections.Generic.List[object]
        $isOther = $false
        foreach ($pk in ([string](Get-RAGpsValue -Row $row -Name 'Prins')).Split(',')) {
            if ($pk -eq '') { continue }
            $p = & $nd $pk
            $prins.Add((& $str $p 'NodeName'))
            if ($null -ne $p -and $Count -gt 1) {
                $fl = [int](Get-RAGpsValue -Row $p -Name 'Fl')
                if ((($fl -band 16) -eq 16) -and (($fl -band 7) -eq 0)) {
                    $bh = Get-RAGpsValue -Row $p -Name 'Bh'
                    if ($null -eq $bh -or ([long]$bh % $Count) -ne $Index) { $isOther = $true }
                }
            }
        }
        if ($isOther) { $other++ }
        $s = & $nd ([string](Get-RAGpsValue -Row $row -Name 'S'))
        $credSet = Get-RAGpsSortedSet -Values @($pairs | ForEach-Object { if ($_.Secret) { [string]$_.Name } else { '' } })
        $creds = @($credSet | Where-Object { $_ -ne '' })
        if ($creds.Count -gt 10) { $creds = @($creds[0..9]) }
        $out.Add([ordered]@{
            _K = $dk
            EntryPointDeviceId = (& $str $d 'NodeId'); EntryPointDevice = (& $str $d 'NodeName')
            TargetAzureAssetId = (& $str $t 'NodeId'); TargetAzureAsset = (& $str $t 'NodeName'); TargetLabel = $tLabel
            EntryVectors      = (Get-RAGpsSortedSet -Values @($pairs | ForEach-Object { Get-RAGpsEntryVector -DeviceEdge $_.Lt -FirstHopLabel $_.Label }))
            DeviceEdges       = (Get-RAGpsSortedSet -Values @($pairs | ForEach-Object { [string]$_.Lt }))
            CredentialNodes   = ([object[]]$creds)
            FirstHopLabels    = (Get-RAGpsSortedSet -Values @($pairs | ForEach-Object { [string]$_.Label }))
            ReachedIdentities = (Get-RAGpsSortedSet -Values $prins.ToArray())
            ViaRoleScope      = (& $str $s 'NodeName')
            ViaRoleScopeType  = (& $str $s 'NodeLabel')
            MaxCvssScore      = $cvss
            TargetType        = $tt.Type
            AttackPathName    = $tt.Name
        })
    }
    return @{ Rows = $out.ToArray(); OtherPart = $other }
}

function New-RAGpsCiIndex {
    <# PURE. A lookup's rows indexed by its key column (ordinal, as a KQL join compares), with its column names. #>
    param([AllowEmptyCollection()][object[]]$Rows, [Parameter(Mandatory)][string]$Key, [string[]]$Columns)
    $ix = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal)
    $cols = @($Columns | Where-Object { -not [string]::IsNullOrEmpty([string]$_) })
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        if ($cols.Count -eq 0) { $cols = @(if ($r -is [System.Collections.IDictionary]) { $r.Keys } else { $r.PSObject.Properties.Name }) }
        $k = Get-RAGpsValue -Row $r -Name $Key
        if (Test-RAGpsEmpty $k) { continue }
        if (-not $ix.ContainsKey([string]$k)) { $ix[[string]$k] = New-Object System.Collections.Generic.List[object] }
        $ix[[string]$k].Add($r)
    }
    return @{ Index = $ix; Columns = $cols }
}

function ConvertTo-RAGpsDetailedRows {
    <#
        PURE. The Detailed query after its _Paths, row for row: the device row (_DeviceEnrichment), the device's CI
        (_ciLink, kept when coalesce(si_in_scope_, true)), the target's CI (_ciPeer), the columns, the weights, the excluded
        configuration ids, the project and the sort. -Enrich: device key -> its slice rows (DeviceKey, RiskFactorSet).
    #>
    param([AllowEmptyCollection()][object[]]$Paths = @(), $Enrich, [Parameter(Mandatory)][hashtable]$Link, [Parameter(Mandatory)][hashtable]$Peer, $Weights, [string[]]$FinalIds = @())
    $out = New-Object System.Collections.Generic.List[object]
    $excluded = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($x in @($FinalIds)) { [void]$excluded.Add([string]$x) }
    foreach ($p in @($Paths)) {
        $enr = @($null); $l0 = $null
        if ($null -ne $Enrich -and $Enrich.TryGetValue([string]$p._K, [ref]$l0) -and $l0.Count -gt 0) { $enr = @($l0.ToArray()) }
        foreach ($e in $enr) {
            $base = [ordered]@{}
            foreach ($k in $p.Keys) { if ($k -ne '_K') { $base[$k] = $p[$k] } }
            if ($null -ne $e) { $base.NodeId = $p.EntryPointDeviceId; $base.DeviceKey = [string](Get-RAGpsValue -Row $e -Name 'DeviceKey'); $base.RiskFactorSet = (ConvertTo-RAGpsArray (Get-RAGpsValue -Row $e -Name 'RiskFactorSet')) }
            else { $base.NodeId = $null; $base.DeviceKey = $null; $base.RiskFactorSet = $null }
            $links = @($null); $l1 = $null
            if (-not (Test-RAGpsEmpty $base.DeviceKey) -and $Link.Index.TryGetValue([string]$base.DeviceKey, [ref]$l1)) { $links = @($l1.ToArray()) }
            foreach ($l in $links) {
                $r = [ordered]@{}; foreach ($k in $base.Keys) { $r[$k] = $base[$k] }
                foreach ($c in @($Link.Columns)) { $r[$c] = Get-RAGpsValue -Row $l -Name $c }
                $inScope = ConvertTo-RAGpsBool (Get-RAGpsValue -Row $l -Name 'si_in_scope_')
                if ($null -ne $inScope -and -not $inScope) { continue }
                $r.TargetKey = ([string]$r.TargetAzureAssetId).ToLowerInvariant()
                $peers = @($null); $l2 = $null
                if ($r.TargetKey -ne '' -and $Peer.Index.TryGetValue([string]$r.TargetKey, [ref]$l2)) { $peers = @($l2.ToArray()) }
                foreach ($pe in $peers) {
                    $w = [ordered]@{}; foreach ($k in $r.Keys) { $w[$k] = $r[$k] }
                    $w.Target_Tier = Get-RAGpsValue -Row $pe -Name 'peer_tier'
                    $w.Target_cmdbId = Get-RAGpsValue -Row $pe -Name 'peer_cmdb_id'
                    $w.Target_cmdbName = Get-RAGpsValue -Row $pe -Name 'peer_cmdb_name'
                    $w.Target_cmdbCriticality = Get-RAGpsValue -Row $pe -Name 'peer_cmdb_criticality'
                    $w.Target_cmdbDataSensitivity = Get-RAGpsValue -Row $pe -Name 'peer_cmdb_data_sensitivity'
                    $w.cmdbId = ConvertTo-RAGpsKqlString $w.Target_cmdbId
                    $w.cmdbName = ConvertTo-RAGpsKqlString $w.Target_cmdbName
                    $w.cmdbCriticality = ConvertTo-RAGpsKqlString $w.Target_cmdbCriticality
                    $w.cmdbDataSensitivity = ConvertTo-RAGpsKqlString $w.Target_cmdbDataSensitivity
                    $w.CriticalityTier = ConvertTo-RAGpsInt $w.Target_Tier
                    $w.CriticalityTierLevel = Get-RAGpsTierLevel $w.CriticalityTier
                    $w.SecurityDomain = 'Endpoint'
                    $w.Category = 'AttackPath_VulnerableDeviceToAzure'
                    $w.Subcategory = $w.TargetType
                    $w.ConfigurationName = $w.AttackPathName
                    $tgt = [string]$w.TargetAzureAssetId; if ($w.TargetType -eq 'Storage account') { $tgt = [string]$w.TargetAzureAsset }
                    $w.ConfigurationId = [string]$w.EntryPointDevice + '->' + $tgt
                    $an = ConvertTo-RAGpsKqlString $w.si_asset_name
                    $w.AssetName = $(if ($an -ne '') { $an } else { [string]$w.EntryPointDevice })
                    $ci = Get-RAGpsValue -Row $w -Name 'si_ci_id'
                    if (-not (Test-RAGpsEmpty $ci)) { $w.AssetId = [string]$ci }
                    elseif (-not (Test-RAGpsEmpty $w.DeviceKey)) { $w.AssetId = [string]$w.DeviceKey }
                    else { $w.AssetId = ([string]$w.EntryPointDeviceId).ToLowerInvariant() }
                    $w.AssetType = $(if ((ConvertTo-RAGpsKqlString $w.si_class) -ne '') { 'Endpoint' } else { 'Device' })
                    $w.Impact = $w.MaxCvssScore
                    $w.SecuritySeverity = Get-RAGpsSeverity $w.MaxCvssScore
                    $w.RiskFactor_Consequence = [long]0
                    $rfs = $w.RiskFactorSet
                    $w.RF_P_RiskFactorsCount = $(if ($null -ne $rfs) { [long]@($rfs).Count } else { $null })
                    $cf = ConvertTo-RAGpsArray $w.si_rf_p; if ($null -eq $cf) { $cf = @() }
                    $cn = ConvertTo-RAGpsArray $w.si_rf_names_; if ($null -eq $cn) { $cn = @() }
                    $w.RF_P_CiFactors = [object[]]@($cf)
                    $w.RF_P_CiFactorNames = [object[]]@($cn)
                    $w.RiskFactorIds = (@($cf | ForEach-Object { ConvertTo-RAGpsKqlString $_ }) -join ';')
                    $cnt = 0L; if ($null -ne $w.RF_P_RiskFactorsCount) { $cnt = [long]$w.RF_P_RiskFactorsCount }
                    $w.RiskFactor_Probability = [long]($cnt + @($cf).Count)
                    $all = New-Object System.Collections.Generic.List[string]
                    foreach ($v in @($rfs)) { if ($null -ne $v) { $all.Add((ConvertTo-RAGpsKqlString $v)) } }
                    foreach ($v in @($cn)) { if ($null -ne $v) { $all.Add((ConvertTo-RAGpsKqlString $v)) } }
                    $arr = $all.ToArray(); [System.Array]::Sort($arr, [System.StringComparer]::Ordinal)
                    $w.RiskFactor_Probability_Detailed = ($arr -join ';')
                    $wt = Get-RAGpsWeight -Row $w -Config $Weights
                    $w.RiskScore_Weight_Detailed = [string]$wt.Detailed
                    $w.RiskScore_Weight_Factor = [long]$wt.Factor
                    $w.RiskFactor_Weight = [long]$wt.Factor
                    if ($excluded.Contains([string]$w.ConfigurationId)) { continue }
                    $o = [ordered]@{}
                    foreach ($c in 'SecurityDomain', 'Category', 'Subcategory', 'ConfigurationName', 'ConfigurationId', 'AssetName', 'AssetId', 'AssetType', 'Impact', 'SecuritySeverity',
                                   'CriticalityTier', 'CriticalityTierLevel', 'RiskFactor_Consequence', 'RiskFactor_Probability', 'RiskFactor_Probability_Detailed', 'RiskFactorIds',
                                   'RiskScore_Weight_Detailed', 'RiskScore_Weight_Factor', 'RiskFactor_Weight', 'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity',
                                   'EntryPointDevice', 'EntryVectors', 'ReachedIdentities', 'TargetAzureAsset', 'ViaRoleScope', 'ViaRoleScopeType', 'MaxCvssScore', 'CredentialNodes') { $o[$c] = $w[$c] }
                    $out.Add([pscustomobject]$o)
                }
            }
        }
    }
    # sort by EntryPointDevice asc, TargetAzureAsset asc (ordinal, stable)
    $arr = $out.ToArray()
    $keys = New-Object 'string[]' $arr.Length
    for ($i = 0; $i -lt $arr.Length; $i++) { $keys[$i] = ('{0}{1}{2}{3}{4:D10}' -f $arr[$i].EntryPointDevice, [char]0, $arr[$i].TargetAzureAsset, [char]0, $i) }
    [System.Array]::Sort($keys, $arr, [System.StringComparer]::Ordinal)
    return , $arr
}

function ConvertTo-RAGpsSummaryRows {
    <#
        PURE. The Summary query after its _Paths, for one slice: the device row, the device's CI (_ciLink, kept when
        coalesce(si_in_scope_, true)), the per-path columns, the summarize by (domain, category, subcategory, name, id, tier,
        tier level, CMDB id / name / criticality / data sensitivity), the columns after it, the weights, the excluded
        configuration ids, the project and the sort. The engine merges the slices' groups afterwards, as it always has.
    #>
    param([AllowEmptyCollection()][object[]]$Paths = @(), $Enrich, [Parameter(Mandatory)][hashtable]$Link, $Weights, [string[]]$FinalIds = @())
    $groups = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal)
    $order = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($Paths)) {
        $enr = @($null); $l0 = $null
        if ($null -ne $Enrich -and $Enrich.TryGetValue([string]$p._K, [ref]$l0) -and $l0.Count -gt 0) { $enr = @($l0.ToArray()) }
        foreach ($e in $enr) {
            $dkey = $null; $rfs = $null
            if ($null -ne $e) { $dkey = [string](Get-RAGpsValue -Row $e -Name 'DeviceKey'); $rfs = ConvertTo-RAGpsArray (Get-RAGpsValue -Row $e -Name 'RiskFactorSet') }
            $links = @($null); $l1 = $null
            if (-not (Test-RAGpsEmpty $dkey) -and $Link.Index.TryGetValue([string]$dkey, [ref]$l1)) { $links = @($l1.ToArray()) }
            foreach ($l in $links) {
                $inScope = ConvertTo-RAGpsBool (Get-RAGpsValue -Row $l -Name 'si_in_scope_')
                if ($null -ne $inScope -and -not $inScope) { continue }
                $cf = ConvertTo-RAGpsArray (Get-RAGpsValue -Row $l -Name 'si_rf_p'); if ($null -eq $cf) { $cf = @() }
                $cn = ConvertTo-RAGpsArray (Get-RAGpsValue -Row $l -Name 'si_rf_names_'); if ($null -eq $cn) { $cn = @() }
                $rfIds = (@($cf | ForEach-Object { ConvertTo-RAGpsKqlString $_ }) -join ';')
                $cnt = 0L; if ($null -ne $rfs) { $cnt = [long]@($rfs).Count }
                $srcProb = [long]($cnt + @($cf).Count)
                $all = New-Object System.Collections.Generic.List[string]
                foreach ($v in @($rfs)) { if ($null -ne $v) { $all.Add((ConvertTo-RAGpsKqlString $v)) } }
                foreach ($v in @($cn)) { if ($null -ne $v) { $all.Add((ConvertTo-RAGpsKqlString $v)) } }
                $arr = $all.ToArray(); [System.Array]::Sort($arr, [System.StringComparer]::Ordinal)
                $srcDet = ($arr -join ';')
                $ci = Get-RAGpsValue -Row $l -Name 'si_ci_id'
                $srcAsset = $(if (-not (Test-RAGpsEmpty $ci)) { [string]$ci } elseif (-not (Test-RAGpsEmpty $dkey)) { $dkey } else { ([string]$p.EntryPointDeviceId).ToLowerInvariant() })
                $tier = ConvertTo-RAGpsInt (Get-RAGpsValue -Row $l -Name 'si_tier')
                $key = [ordered]@{
                    SecurityDomain = 'Endpoint'; Category = 'AttackPath_VulnerableDeviceToAzure'; Subcategory = [string]$p.TargetType
                    ConfigurationName = [string]$p.AttackPathName; ConfigurationId = [string]$p.AttackPathName
                    CriticalityTier = $tier; CriticalityTierLevel = (Get-RAGpsTierLevel $tier)
                    cmdbId = (ConvertTo-RAGpsKqlString (Get-RAGpsValue -Row $l -Name 'si_cmdb_id')); cmdbName = (ConvertTo-RAGpsKqlString (Get-RAGpsValue -Row $l -Name 'si_cmdb_name'))
                    cmdbCriticality = (ConvertTo-RAGpsKqlString (Get-RAGpsValue -Row $l -Name 'si_cmdb_criticality')); cmdbDataSensitivity = (ConvertTo-RAGpsKqlString (Get-RAGpsValue -Row $l -Name 'si_cmdb_data_sensitivity'))
                }
                $gk = (@($key.Values | ForEach-Object { if ($null -eq $_) { [char]1 } else { [string]$_ } }) -join [char]31)
                $g = $null
                if (-not $groups.TryGetValue($gk, [ref]$g)) {
                    $g = @{ Key = $key; Impact = $null; Targets = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal))
                            Assets = (New-Object System.Collections.Generic.List[object]); Pairs = (New-Object System.Collections.Generic.List[object]); Issues = (New-Object System.Collections.Generic.List[object])
                            AssetId = $null; Labels = (New-Object System.Collections.Generic.List[object]); Edges = (New-Object System.Collections.Generic.List[object])
                            MaxProb = $null; RfIds = (New-Object System.Collections.Generic.List[object]); Dets = (New-Object System.Collections.Generic.List[object]) }
                    $groups[$gk] = $g; $order.Add($gk)
                }
                if ($null -ne $p.MaxCvssScore -and ($null -eq $g.Impact -or [double]$p.MaxCvssScore -gt [double]$g.Impact)) { $g.Impact = [double]$p.MaxCvssScore }
                [void]$g.Targets.Add([string]$p.TargetAzureAssetId)
                $g.Assets.Add([string]$p.EntryPointDevice); $g.Pairs.Add(([string]$p.EntryPointDevice + '|' + $srcAsset)); $g.Issues.Add([string]$p.TargetAzureAsset)
                if ($null -eq $g.AssetId -or [string]::CompareOrdinal($srcAsset, [string]$g.AssetId) -lt 0) { $g.AssetId = $srcAsset }
                $g.Labels.Add([string]$p.FirstHopLabel); $g.Edges.Add([string]$p.DeviceEdge)
                if ($null -eq $g.MaxProb -or [int]$srcProb -gt [int]$g.MaxProb) { $g.MaxProb = [int]$srcProb }
                if ($rfIds -ne '') { $g.RfIds.Add($rfIds) }
                $g.Dets.Add($srcDet)
            }
        }
    }
    $excluded = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($x in @($FinalIds)) { [void]$excluded.Add([string]$x) }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($gk in $order) {
        $g = $groups[$gk]
        $w = [ordered]@{}; foreach ($k in $g.Key.Keys) { $w[$k] = $g.Key[$k] }
        $w.Impact = $g.Impact
        $w.UniqueIssues = [long]$g.Targets.Count
        $w.ImpactedAssetsList = Get-RAGpsSortedSet -Values $g.Assets.ToArray()
        $w.ImpactedAssetPairs = Get-RAGpsSortedSet -Values $g.Pairs.ToArray()
        $w.IssueList = Get-RAGpsSortedSet -Values $g.Issues.ToArray()
        $w.AssetId = $g.AssetId
        $w.EntryVectorTypes = Get-RAGpsSortedSet -Values $g.Labels.ToArray()
        $w.DeviceEdgeTypes = Get-RAGpsSortedSet -Values $g.Edges.ToArray()
        $w.Max_Source_RiskFactor_Probability = $g.MaxProb
        $rfSet = Get-RAGpsSortedSet -Values $g.RfIds.ToArray()
        $w.RiskFactorIds = ($rfSet -join ';')
        $w.All_Source_RiskFactor_Probability_Detailed = Get-RAGpsSortedSet -Values $g.Dets.ToArray()
        $w.ImpactedAssetCount = [long]@($w.ImpactedAssetsList).Count
        $w.SecuritySeverity = Get-RAGpsSeverity $w.Impact
        $w.AssetName = (@($w.ImpactedAssetsList) -join '; ')
        $w.AssetType = $w.Subcategory
        $w.RiskFactor_Consequence = [long]0
        $w.RiskFactor_Probability = $(if ($null -ne $g.MaxProb) { [long]$g.MaxProb } else { [long]0 })
        $w.RiskFactor_Probability_Detailed = (@($w.All_Source_RiskFactor_Probability_Detailed) -join ';')
        $wt = Get-RAGpsWeight -Row $w -Config $Weights
        $w.RiskScore_Weight_Detailed = [string]$wt.Detailed
        $w.RiskScore_Weight_Factor = [long]$wt.Factor
        $w.RiskFactor_Weight = [long]$wt.Factor
        if ($excluded.Contains([string]$w.ConfigurationId)) { continue }
        $o = [ordered]@{}
        foreach ($c in 'SecurityDomain', 'Category', 'Subcategory', 'ConfigurationName', 'ConfigurationId', 'AssetName', 'AssetId', 'AssetType', 'Impact', 'SecuritySeverity',
                       'CriticalityTier', 'CriticalityTierLevel', 'RiskFactor_Consequence', 'RiskFactor_Probability', 'RiskFactor_Probability_Detailed', 'RiskFactorIds',
                       'RiskScore_Weight_Detailed', 'RiskScore_Weight_Factor', 'RiskFactor_Weight', 'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity',
                       'ImpactedAssetCount', 'UniqueIssues', 'ImpactedAssetsList', 'ImpactedAssetPairs', 'IssueList') { $o[$c] = $w[$c] }
        $out.Add([pscustomobject]$o)
    }
    # sort by RiskScore_Weight_Factor desc, RiskFactor_Probability desc, CriticalityTier asc (no tier first), ImpactedAssetCount desc -- stable
    $arr = $out.ToArray()
    if ($arr.Length -gt 1) {
        $n = 0
        $arr = @($arr | ForEach-Object { [pscustomobject]@{ R = $_; N = ($n++) } } |
                 Sort-Object -Property @{ Expression = { [long]$_.R.RiskScore_Weight_Factor }; Descending = $true }, @{ Expression = { [long]$_.R.RiskFactor_Probability }; Descending = $true },
                                       @{ Expression = { if ($null -eq $_.R.CriticalityTier) { [long]::MinValue } else { [long]$_.R.CriticalityTier } }; Descending = $false },
                                       @{ Expression = { [long]$_.R.ImpactedAssetCount }; Descending = $true }, @{ Expression = { [long]$_.N }; Descending = $false } |
                 ForEach-Object { $_.R })
    }
    return , ([object[]]$arr)
}

# ------------------------------------------------------------------------------------------------------------------
#  THE HOOK: Invoke-GraphHuntingQuery asks here first
# ------------------------------------------------------------------------------------------------------------------
function Test-RAGraphStageNeeded {
    <# PURE. Whether any of -Queries is the attack-path query this port answers (the producer then loads the graph before
       its workers start). #>
    param([AllowEmptyCollection()][string[]]$Queries = @())
    foreach ($q in @($Queries)) { if ($q -and $q.IndexOf($script:RAGpsMatchLine) -ge 0) { return $true } }
    return $false
}

function Get-RAGpsLetRows {
    <# The rows of the query's lookup -Name (one of its CI blocks), read once per run through the engine's own lookup cache
       (Get-SIHybridLetRows -- the same rows the query would have carried). @{ Rows; Columns }. #>
    param([Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)][string]$Name)
    $rx = '(?ms)\blet\s+(?<var>' + [regex]::Escape($Name) + ')\s*=\s*(?<body>[^;]*?\bSI_[A-Za-z]+(?:_Profile)?_CL\b[^;]*?);'
    $m = [regex]::Match($Query, $rx)
    if (-not $m.Success) { throw (New-RALookupUnavailableError -Message ('a lookup this report needs could not be read -- {0} is not in the query' -f $Name)) }
    $ws = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId)) { [string]$global:SI_WorkspaceResourceId } else { [string]$global:WorkspaceResourceId }
    try { $got = Get-SIHybridLetRows -VarName $Name -BodyKql $m.Groups['body'].Value -WorkspaceResourceId $ws }
    catch { $e = ConvertTo-RALookupUnavailableError -What ('its lookup {0}' -f $Name) -Err $_; if ($e) { throw $e }; throw }
    $cols = @()
    if ($got.ColumnTypes -is [System.Collections.IDictionary] -and $got.ColumnTypes.Count -gt 0) { $cols = @($got.ColumnTypes.Keys) }
    return @{ Rows = @($got.Rows); Columns = $cols }
}

function Get-RAGraphStagePlan {
    <# Whether THIS hunting call is the attack-path report this port answers: $null = it runs as before. The shape is read
       from the text (Get-RAGpsQueryShape); a query that is not exactly the one this port reproduces is said once per report
       and runs as before. Needs the result in the database (it always is in v3). #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query)
    if ($Query.IndexOf($script:RAGpsMatchLine) -lt 0) { return $null }
    $shape = Get-RAGpsQueryShape -Query $Query
    if (-not $shape.Ok) {
        $key = [string]$shape.Why
        if (-not $script:RAGpsShapeSaid.ContainsKey($key) -and (Get-Command -Name Write-Info -ErrorAction SilentlyContinue)) {
            $script:RAGpsShapeSaid[$key] = $true
            Write-Info ('the attack-path query is asked of advanced hunting as before: {0}' -f $shape.Why)
        }
        return $null
    }
    if (-not $script:RAStreamOn -or $null -eq $script:RAStream) {
        if (-not $script:RAGpsShapeSaid.ContainsKey('nosql') -and (Get-Command -Name Write-Warn2 -ErrorAction SilentlyContinue)) {
            $script:RAGpsShapeSaid['nosql'] = $true
            Write-Warn2 'the attack-path query is asked of advanced hunting as before in this run: its graph is joined in the database, and this run keeps its result in memory'
        }
        return $null
    }
    return $shape
}

function Invoke-RAGraphStageAnswer {
    <#
        The hunting call answered from the run's graph in SQL: the slice's paths, then the rest of the query (the CI lookups
        are read through the engine's own lookup cache, once per run). A count is the count of the same rows; a group count
        the distinct groups of the same rows. Returns what the report loop reads ([pscustomobject]@{ _SIDirectRows }).
        -Data / -Link / -Peer are seams for tests.
    #>
    param([Parameter(Mandatory)][hashtable]$Plan, [string]$ReportName = '', $Data, $Link, $Peer)
    $set = $null
    if ($null -eq $Data) {
        $set = Sync-RAGraphStage -Stream $script:RAStream
        $Data = Get-RAGpsSliceData -Stream $script:RAStream -RunNo ([int]$set.RunNo) -Count $Plan.Count -Index $Plan.Index
    }
    $pr = ConvertTo-RAGpsPathRows -Data $Data -Grain $Plan.Grain -Count $Plan.Count -Index $Plan.Index
    if ($null -eq $Link) { $lr = Get-RAGpsLetRows -Query $Plan.Body -Name '_ciLink'; $Link = New-RAGpsCiIndex -Rows $lr.Rows -Key '_ciKey' -Columns $lr.Columns }
    if ($Plan.Grain -eq 'Detailed') {
        if ($null -eq $Peer) { $pp = Get-RAGpsLetRows -Query $Plan.Body -Name '_ciPeer'; $Peer = New-RAGpsCiIndex -Rows $pp.Rows -Key '_peerKey' -Columns $pp.Columns }
        $rows = ConvertTo-RAGpsDetailedRows -Paths $pr.Rows -Enrich $Data.Enrich -Link $Link -Peer $Peer -Weights $Plan.Weights -FinalIds $Plan.FinalIds
    } else {
        $rows = ConvertTo-RAGpsSummaryRows -Paths $pr.Rows -Enrich $Data.Enrich -Link $Link -Weights $Plan.Weights -FinalIds $Plan.FinalIds
    }
    if ([long]$Plan.RowCount -gt 1) { $rows = @($rows | Where-Object { (Get-RAGpsRowSplitPart -Row $_ -RowCount $Plan.RowCount) -eq [long]$Plan.RowIndex }) }
    if ($Plan.Kind -eq 'rows') {
        if ($null -eq $script:RAGpsRun) { $script:RAGpsRun = @{ OtherPart = @{}; Said = $false } }
        $script:RAGpsRun.OtherPart[('{0}|{1}|{2}|{3}|{4}' -f $ReportName, $Plan.Count, $Plan.Index, $Plan.RowCount, $Plan.RowIndex)] = [long]$pr.OtherPart
        return [pscustomobject]@{ _SIDirectRows = @($rows) }
    }
    if ($Plan.Kind -eq 'count') { return [pscustomobject]@{ _SIDirectRows = @([pscustomobject]@{ Count = [long]@($rows).Count }) } }
    $hs = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($r in @($rows)) {
        $t = (@($Plan.GroupColumns | ForEach-Object { ConvertTo-RAGpsKqlString (Get-RAGpsValue -Row $r -Name $_) }) -join '|~|').ToLowerInvariant()
        [void]$hs.Add((Get-RAGpsHex -Text $t))
    }
    return [pscustomobject]@{ _SIDirectRows = @($hs | ForEach-Object { [pscustomobject]@{ SIGroupHash = $_ } }) }
}
