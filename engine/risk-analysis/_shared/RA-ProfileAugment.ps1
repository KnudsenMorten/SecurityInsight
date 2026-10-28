#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  Profile-CL augmentation: workspace resolution, CL snapshot shadows and the augment plan.
#
#  How a report gets its asset ATTRIBUTES: resolve the workspace, convert rows to a KQL datatable,
#  build the per-domain let-blocks over the Profile_CL snapshot, work out which reports need
#  augmenting and apply it. The largest single concern left in the engine after scoring.
#
#  AUDIT #16: moved VERBATIM out of Invoke-RiskAnalysis.ps1 on 2026-08-05. Dot-sourced back in at
#  exactly the position it occupied, so load order is unchanged. Every function body is
#  byte-identical to before the move - verified with tests/Get-EngineFunctionInventory.ps1,
#  which compares a SHA-256 of each function's source text before and after.
#
#  Do NOT add $PSScriptRoot-dependent code here: in this file it resolves to _shared/, one level
#  deeper than the engine root the main script derives $siRoot from.
#######################################################################################################

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }
# #690 (37): the lookups are read through the parted reader (a result too large for one answer is read in parts)
if (-not (Get-Command -Name Invoke-LogAnalyticsKqlQueryParted -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'RA-LaPartedRead.ps1') }

function Resolve-WorkspaceCustomerId {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$WorkspaceResourceId)

    if (-not $script:_WorkspaceCustomerIdCache) { $script:_WorkspaceCustomerIdCache = @{} }
    if ($script:_WorkspaceCustomerIdCache.ContainsKey($WorkspaceResourceId)) {
        return $script:_WorkspaceCustomerIdCache[$WorkspaceResourceId]
    }

    if ($WorkspaceResourceId -notmatch '/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/[Mm]icrosoft\.[Oo]perational[Ii]nsights/workspaces/([^/]+)') {
        throw "Invalid WorkspaceResourceId: $WorkspaceResourceId"
    }
    $subId  = $matches[1]
    $rgName = $matches[2]
    $wsName = $matches[3]

    $curSubId = $null
    try { $curSubId = (Get-SIAzContext).Subscription.Id } catch {}
    if ($curSubId -and $curSubId -ne $subId) {
        $null = Set-SIAzContext -Subscription $subId -ErrorAction Stop
    }

    $ws = Get-SIAzOperationalInsightsWorkspace -ResourceGroupName $rgName -Name $wsName -ErrorAction Stop
    $custId = $ws.CustomerId.Guid

    if ($curSubId -and $curSubId -ne $subId) {
        try { $null = Set-SIAzContext -Subscription $curSubId -ErrorAction SilentlyContinue } catch {}
    }

    $script:_WorkspaceCustomerIdCache[$WorkspaceResourceId] = $custId
    return $custId
}

function _ExtractProjectColumns {
    <# Parse a KQL body to extract column names introduced by the LAST `project`
       clause. Used to build a schema-aware empty datatable when the hybrid
       CL-snapshot pre-fetch returns 0 rows -- without this, the empty-datatable
       had a single `__placeholder:string` column and the downstream join failed
       with `Failed to resolve column named '<expected_col>'`. v2.2.315. #>
    param([string]$BodyKql)
    if ([string]::IsNullOrWhiteSpace($BodyKql)) { return @() }
    $m = [regex]::Matches($BodyKql, '\bproject\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($m.Count -eq 0) { return @() }
    $lastProject = $m[$m.Count - 1]
    $tail = $BodyKql.Substring($lastProject.Index + $lastProject.Length)
    # Walk forward to find end of project clause (next | not in parens, or ;, or end-of-string)
    $depth = 0
    $end = $tail.Length
    for ($i = 0; $i -lt $tail.Length; $i++) {
        $c = $tail[$i]
        if     ($c -eq '(' -or $c -eq '[') { $depth++ }
        elseif ($c -eq ')' -or $c -eq ']') { $depth-- }
        elseif ($depth -eq 0 -and ($c -eq '|' -or $c -eq ';')) { $end = $i; break }
    }
    $projectBody = $tail.Substring(0, $end)
    # Split on top-level commas (depth 0) and extract column name
    $cols = New-Object System.Collections.Generic.List[string]
    $depth = 0
    $start = 0
    for ($i = 0; $i -le $projectBody.Length; $i++) {
        $c = if ($i -lt $projectBody.Length) { $projectBody[$i] } else { ',' }
        if     ($c -eq '(' -or $c -eq '[') { $depth++; continue }
        elseif ($c -eq ')' -or $c -eq ']') { $depth--; continue }
        if ($depth -eq 0 -and $c -eq ',') {
            $segment = $projectBody.Substring($start, $i - $start).Trim()
            $start = $i + 1
            if ($segment -match '^([A-Za-z_][A-Za-z0-9_]*)\s*=') {
                [void]$cols.Add($Matches[1])
            } elseif ($segment -match '^([A-Za-z_][A-Za-z0-9_]*)$') {
                [void]$cols.Add($Matches[1])
            }
        }
    }
    return $cols
}

function ConvertTo-SIKqlDatatableType {
    <# PURE. A declared Log Analytics column type -> the type a datatable() column is declared with (unknown -> string). #>
    param([string]$Type)
    switch (([string]$Type).Trim().ToLowerInvariant()) {
        'dynamic'  { 'dynamic' }   'bool'    { 'bool' }    'boolean' { 'bool' }
        'int'      { 'long' }      'int32'   { 'long' }    'long'    { 'long' }    'int64' { 'long' }
        'real'     { 'real' }      'double'  { 'real' }    'decimal' { 'real' }
        'datetime' { 'datetime' }  'timespan' { 'string' } 'guid'    { 'string' }
        default    { 'string' }
    }
}

function Test-SIKqlJsonTextValues {
    <# PURE. True when EVERY value is JSON text of an array or an object -- a dynamic column's cells as the query API hands
       them. A plain string that only starts with '[' (a bracketed name) does not parse and keeps the column a string. #>
    param([System.Collections.Generic.List[string]]$Values)
    if ($null -eq $Values -or $Values.Count -eq 0) { return $false }
    foreach ($s in $Values) {
        $t = ([string]$s).Trim()
        if (-not (($t.StartsWith('[') -and $t.EndsWith(']')) -or ($t.StartsWith('{') -and $t.EndsWith('}')))) { return $false }
        try { $d = [System.Text.Json.JsonDocument]::Parse($t); $d.Dispose() } catch { return $false }
    }
    return $true
}

function ConvertTo-SIKqlDynamicLiteral {
    <# PURE. One dynamic cell (JSON text) -> a KQL `dynamic(...)` literal on one line. Text that is not JSON becomes a
       dynamic STRING (never an unparsable literal that would fail the whole query). #>
    param($Value)
    if ($null -eq $Value) { return 'dynamic(null)' }
    $t = ([string]$Value).Trim()
    if ($t -eq '') { return 'dynamic(null)' }
    try {
        $d = [System.Text.Json.JsonDocument]::Parse($t)
        try {
            $ms = [System.IO.MemoryStream]::new()
            $w = [System.Text.Json.Utf8JsonWriter]::new($ms)
            $d.RootElement.WriteTo($w); $w.Flush()
            $json = [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
            $w.Dispose(); $ms.Dispose()
        } finally { $d.Dispose() }
        return ('dynamic({0})' -f $json)
    } catch {
        return ('dynamic({0})' -f (ConvertTo-Json -InputObject ([string]$Value) -Compress))
    }
}

function Convert-RowsToKqlDatatable {
    <# Serializes an array of PSCustomObject rows into a KQL `datatable(<schema>) [ <values> ]` literal.
       Column types inferred from the first row's .NET types. Used by the hybrid CL-snapshot path.

       v2.2.315 -- when $Rows is empty and -BodyKqlForSchemaHint is provided,
       parses the body's last `project` clause to emit a schema-matched empty
       datatable. Without the hint, falls back to the legacy single-placeholder
       schema which crashes downstream joins. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LetVarName,
        [object[]]$Rows,
        [string]$BodyKqlForSchemaHint,
        # 🔴 THE SCHEMA MUST BE THE SAME IN EVERY BUCKET OF ONE LET-BINDING, AND IT WAS NOT.
        # Types are inferred by scanning VALUES, and each bucket only ever saw its OWN slice, so
        # the same column could come out `long` in one bucket and `string` in another -- and for
        # an EMPTY bucket every column was forced to `:string` outright. A downstream `case()`
        # then mixed a string branch with a numeric one and Advanced Hunting rejected the query:
        #   case: return types are not compatible. Distinct types: StringBuffer,I8
        # That is a hard BadRequest, so the bucket returned nothing on every attempt and every
        # future run -- silent, permanent, partial data for the whole report.
        # Pass the FULL pre-bucketing snapshot here: types come from it, values still come from
        # $Rows. Empty buckets then emit a correctly-TYPED empty datatable instead of an all-string
        # one, and every bucket of the binding agrees on the schema.
        [object[]]$TypeReferenceRows,
        # 🔴 THE TYPES THE QUERY DECLARED, column name -> KQL type (the Log Analytics response's columns, recorded by
        # Invoke-LogAnalyticsKqlQuery). A DYNAMIC column (a list: the CI's factor ids si_rf_p / si_rf_c, the factor names,
        # the unknown fields) arrives as JSON TEXT, and the value scan below only knows bool / long / real / datetime -- so
        # it was inlined as `:string`, and every set_has_element / set_difference / strcat_array over it failed in advanced
        # hunting ("argument #1 must be a dynamic"): 12 Summary + 12 Detailed reports lost every bucket on one run.
        # A declared 'dynamic' wins; without declared types a column whose every value is a JSON array / object is dynamic.
        [hashtable]$ColumnTypes,
        # #730: stop and return $null as soon as the text is longer than this many characters (0 = no limit). A caller that
        # only asks "does the WHOLE lookup fit one request?" no longer builds a tenant-sized text to learn that it does not.
        [long]$MaxChars = 0
    )
    # Types from the reference set when given (the whole snapshot); otherwise from the rows at hand.
    $typeRows = if ($TypeReferenceRows -and $TypeReferenceRows.Count -gt 0) { $TypeReferenceRows } else { $Rows }

    if (-not $typeRows -or $typeRows.Count -eq 0) {
        # Nothing anywhere to infer from -- the declared types, else the name-only hint, then the placeholder.
        if ($ColumnTypes -and $ColumnTypes.Count -gt 0) {
            $schema = ((@($ColumnTypes.Keys) | ForEach-Object { '{0}:{1}' -f $_, (ConvertTo-SIKqlDatatableType ([string]$ColumnTypes[$_])) }) -join ',')
            # the declared order is lost in a hashtable; the hint's project order is used when it names the same columns
            if (-not [string]::IsNullOrWhiteSpace($BodyKqlForSchemaHint)) {
                $hc = @(_ExtractProjectColumns $BodyKqlForSchemaHint)
                if ($hc.Count -gt 0) { $schema = (($hc | ForEach-Object { '{0}:{1}' -f $_, (ConvertTo-SIKqlDatatableType ([string]$ColumnTypes[$_])) }) -join ',') }
            }
            return ('let {0} = datatable({1}) [];' -f $LetVarName, $schema)
        }
        if (-not [string]::IsNullOrWhiteSpace($BodyKqlForSchemaHint)) {
            $cols = _ExtractProjectColumns $BodyKqlForSchemaHint
            if ($cols.Count -gt 0) {
                $schema = (($cols | ForEach-Object { '{0}:string' -f $_ }) -join ',')
                return ('let {0} = datatable({1}) [];' -f $LetVarName, $schema)
            }
        }
        return ('let {0} = datatable(__placeholder:string)[];' -f $LetVarName)
    }
    $first = $typeRows[0]
    $colSpecs  = New-Object System.Collections.Generic.List[string]
    $colNames  = New-Object System.Collections.Generic.List[string]
    $colTypes  = New-Object System.Collections.Generic.List[string]
    foreach ($p in $first.PSObject.Properties) {
        # Az.OperationalInsightsQuery returns ALL values as strings regardless of
        # the underlying KQL column type. Inferring from .TypeNameOfValue is
        # therefore useless -- we need to scan VALUES across ALL rows and detect
        # the narrowest KQL type whose pattern matches every non-null value. Scanned over
        # $typeRows (the whole snapshot), NOT $Rows, so every bucket agrees on the schema.
        $values = New-Object System.Collections.Generic.List[string]
        # #711: plain member access ($r.<name>), never $r.PSObject per row -- that keeps a wrapper per row alive (measured
        # on the test VM: ~4 KB per row of a compact lookup row, ~3.6 KB per PSCustomObject row), for as long as the rows live
        $pn = $p.Name
        foreach ($r in $typeRows) {
            $v = $r.$pn
            if ($null -ne $v -and -not ([string]::IsNullOrEmpty([string]$v))) {
                [void]$values.Add([string]$v)
            }
        }
        $kqlType = 'string'
        $declared = if ($ColumnTypes -and $ColumnTypes.ContainsKey($p.Name)) { ([string]$ColumnTypes[$p.Name]).Trim().ToLowerInvariant() } else { '' }
        if ($declared -eq 'dynamic' -or ($values.Count -gt 0 -and -not $declared -and (Test-SIKqlJsonTextValues $values))) {
            $kqlType = 'dynamic'
        }
        elseif ($values.Count -gt 0) {
            # Detect bool/long/real/datetime only. GUID promotion is INTENTIONALLY
            # disabled -- the source query body typically casts ID columns via
            # `tostring(...)` to ensure string-typed joins downstream; auto-promoting
            # GUID-shaped strings to `guid` breaks join-key compatibility with the
            # AH side which projects the same columns as `string`.
            $allBool = $true; $allLong = $true; $allReal = $true; $allDate = $true
            foreach ($s in $values) {
                if ($allBool -and $s -notmatch '^(?i:true|false)$') { $allBool = $false }
                if ($allLong -and $s -notmatch '^-?\d+$')           { $allLong = $false }
                if ($allReal -and $s -notmatch '^-?\d+(\.\d+)?([eE][-+]?\d+)?$') { $allReal = $false }
                if ($allDate -and $s -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}') { $allDate = $false }
                if (-not ($allBool -or $allLong -or $allReal -or $allDate)) { break }
            }
            # Order matters: bool > long > real (long is subset of real).
            if     ($allBool) { $kqlType = 'bool' }
            elseif ($allLong) { $kqlType = 'long' }
            elseif ($allReal) { $kqlType = 'real' }
            elseif ($allDate) { $kqlType = 'datetime' }
        }
        [void]$colSpecs.Add(('{0}:{1}' -f $p.Name, $kqlType))
        [void]$colNames.Add($p.Name)
        [void]$colTypes.Add($kqlType)
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendFormat('let {0} = datatable({1}) [' + [Environment]::NewLine, $LetVarName, ($colSpecs -join ','))
    foreach ($r in $Rows) {
        $vals = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt $colNames.Count; $i++) {
            $cn = $colNames[$i]
            $v = $r.$cn
            $t = $colTypes[$i]
            if ($null -eq $v -or ($v -is [string] -and [string]::IsNullOrEmpty($v))) {
                # Untyped null literal isn't allowed inside datatable rows; cast per type.
                $lit = switch ($t) {
                    'string'   { '""' }
                    'bool'     { 'bool(null)' }
                    'long'     { 'long(null)' }
                    'real'     { 'real(null)' }
                    'datetime' { 'datetime(null)' }
                    'guid'     { 'guid(null)' }
                    'dynamic'  { 'dynamic(null)' }
                    default    { '""' }
                }
            } else {
                switch ($t) {
                    'dynamic'  { $lit = ConvertTo-SIKqlDynamicLiteral $v }
                    'string'   { $lit = '"' + (([string]$v) -replace '\\','\\' -replace '"','\"' -replace "`r",'\r' -replace "`n",'\n' -replace "`t",'\t') + '"' }
                    'bool'     {
                        # [bool]"false" returns $true in PowerShell (non-empty string).
                        # Compare the string value explicitly.
                        $sv = ([string]$v).ToLowerInvariant()
                        $lit = if ($sv -eq 'true' -or $sv -eq '1') { 'true' } else { 'false' }
                    }
                    'long'     { $lit = ([int64](([string]$v))).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
                    'real'     { $lit = ([double]::Parse(([string]$v), [System.Globalization.CultureInfo]::InvariantCulture)).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
                    'datetime' { $lit = 'datetime(' + ([datetime]$v).ToString('o') + ')' }
                    'guid'     { $lit = 'guid(' + ([guid]([string]$v)).ToString() + ')' }
                    default    { $lit = '"' + ([string]$v) + '"' }
                }
            }
            [void]$vals.Add($lit)
        }
        [void]$sb.AppendLine('  ' + ($vals -join ',') + ',')
        if ($MaxChars -gt 0 -and $sb.Length -gt $MaxChars) { return $null }
    }
    # Trim trailing comma+newline -- in the builder (#730): the text is made ONCE, not three times (the builder, its copy
    # and the trimmed copy of that); the same characters as TrimEnd(",`r`n") + newline + '];'.
    $len = $sb.Length
    while ($len -gt 0 -and ",`r`n".IndexOf($sb.Chars($len - 1)) -ge 0) { $len-- }
    $sb.Length = $len
    [void]$sb.Append([Environment]::NewLine + '];')
    if ($MaxChars -gt 0 -and $sb.Length -gt $MaxChars) { return $null }
    return $sb.ToString()
}

function Add-CLSnapshotShadows {
    <# UNIVERSAL CL-snapshot shadowing (Pattern 2 / table-shadow).
       Generalizes Resolve-ProfileCLLetBlocks beyond the `let _x = SI_*_CL | ...`
       pattern to ANY reference of an SI_*_Profile_CL table -- joins, unions,
       direct table position, or wrapped in let blocks. KQL's `let TableName = ...`
       shadows the real table at parse time, so every downstream reference
       resolves to the inlined datatable. Snapshots are pre-fetched once per
       run per unique CL table and cached in $script:_CLSnapshotsKql. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$WorkspaceResourceId
    )

    if (-not $script:_CLSnapshotsKql) { $script:_CLSnapshotsKql = @{} }

    # Strip strings/comments first so `where Category == "SI_Endpoint_Profile_CL"` doesn't false-match.
    $stripped = $Query
    $stripped = [regex]::Replace($stripped, '"[^"\r\n]*"', '""')
    $stripped = [regex]::Replace($stripped, "'[^'\r\n]*'", "''")
    $stripped = [regex]::Replace($stripped, '//[^\r\n]*', '')

    # Match ANY SI_*_CL custom Log Analytics table (Profile + VulnerabilityPIP + future).
    $clPattern = '\bSI_[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z][A-Za-z0-9]*)*_CL\b'
    $tables = @([regex]::Matches($stripped, $clPattern) | ForEach-Object { $_.Value } | Sort-Object -Unique)
    if ($tables.Count -eq 0) { return $Query }

    # Smart column projection: walk every `let <var> = <table> | ... | project ...`
    # block in the query and collect the source columns each block actually needs.
    # Pre-fetching only those columns shrinks the inlined datatable 5-20x and keeps
    # the AH body well under the 1MB nginx cap that bricked Azure_Recommendations +
    # all Attack_Paths reports on 2026-05-02. Falls back to `*` if no projection found.
    $kqlReserved = @('tostring','toint','tobool','todouble','todatetime','todynamic',
                     'column_ifexists','iif','iff','case','coalesce','isnotempty','isnull','isempty',
                     'int','long','real','bool','datetime','dynamic','null','true','false',
                     'parse_json','tolower','toupper','trim','strcat','strcat_array','split','extract',
                     'now','ago','make_set','make_list','make_bag','bag_pack','bag_merge','array_concat',
                     'datetime_diff','datetime_add','startofday','arg_max','arg_min','count','dcount','sum','min','max','any','avg')
    $colsByTable = @{}
    foreach ($tbl in $tables) {
        $set = New-Object 'System.Collections.Generic.HashSet[string]'
        # Always need these for the universal `where TimeGenerated > ago(...) | summarize arg_max(CollectionTime, *) by PrimaryEntityId` shape:
        [void]$set.Add('TimeGenerated'); [void]$set.Add('CollectionTime'); [void]$set.Add('PrimaryEntityId')
        $colsByTable[$tbl] = $set
    }
    # Match `let X = TBL | ... | project <body>` -- terminate <body> at next `;` or `| where isnotempty(`
    # which is the conventional tail after the project in our refactored YAML.
    $letProjectRx = '(?ms)\blet\s+\w+\s*=\s*(?<tbl>SI_[A-Za-z]+_Profile_CL)\b[^;]*?\|\s*project\s+(?<body>[^;]+?)(?=\s*\|\s*where\s+isnotempty|\s*;)'
    foreach ($pm in [regex]::Matches($stripped, $letProjectRx)) {
        $tbl = $pm.Groups['tbl'].Value
        if (-not $colsByTable.ContainsKey($tbl)) { continue }
        $body = $pm.Groups['body'].Value
        # 1. Extract column_ifexists("X", ...) first-arg string literals -- explicit source-col references.
        foreach ($cm in [regex]::Matches($body, 'column_ifexists\(\s*"([^"\r\n]+)"')) {
            [void]$colsByTable[$tbl].Add($cm.Groups[1].Value)
        }
        # 2. Extract bare identifier references in the project body (catches `tostring(PrimaryEntityId)`-style),
        # filter out KQL function names + literals.
        foreach ($idm in [regex]::Matches($body, '\b([A-Za-z_][A-Za-z0-9_]*)\b')) {
            $name = $idm.Groups[1].Value
            if ($name -in $kqlReserved) { continue }
            # Skip alias-LHS positions: `<Alias> = <expr>` -- the LHS is an output name not a source col.
            # Heuristic: if the next non-space char after this identifier is `=` (and not `==`), it's an alias.
            $idx = $idm.Index + $idm.Length
            while ($idx -lt $body.Length -and ($body[$idx] -eq ' ' -or $body[$idx] -eq "`t")) { $idx++ }
            if ($idx -lt $body.Length -and $body[$idx] -eq '=' -and ($idx + 1 -ge $body.Length -or $body[$idx+1] -ne '=')) { continue }
            [void]$colsByTable[$tbl].Add($name)
        }
    }

    $shadows = New-Object System.Collections.Generic.List[string]
    foreach ($tbl in $tables) {
        if (-not $script:_CLSnapshotsKql.ContainsKey($tbl)) {
            Write-Diag ("[shadow] pre-fetching {0} snapshot from LA workspace ..." -f $tbl)
            # Pre-summarize to latest-per-PrimaryEntityId so the shadow has one row per
            # asset. The original query's `| where TimeGenerated > ago(Nd) | summarize
            # arg_max(CollectionTime, *) by PrimaryEntityId` becomes a no-op against
            # the already-collapsed shadow. Smart projection narrows columns to only
            # those the query references.
            $cols = @($colsByTable[$tbl])
            if ($cols.Count -le 3) {
                # only the always-include trio -- no project found, fall back to all columns
                $projectClause = ''
                $colsLogTag = '*'
            } else {
                $projectClause = "`n| project " + (($cols | Sort-Object -Unique) -join ', ')
                $colsLogTag = ("{0} cols" -f ($cols | Sort-Object -Unique).Count)
            }
            $snapshotKql = ("{0}`n| where TimeGenerated > ago(8d){1}`n| summarize arg_max(CollectionTime, *) by PrimaryEntityId" -f $tbl, $projectClause)
            # #212: THIS install's rows before the arg_max (engine/_shared/SI-InstallRows.ps1)
            if (Get-Command -Name Add-SIInstallRowsFilter -ErrorAction SilentlyContinue) { $snapshotKql = Add-SIInstallRowsFilter -Query $snapshotKql -SolutionVersion $global:RA_SolutionVersion -LookbackDays 8 }
            try {
                # #690 (37): read in parts when one answer is too short for a limit
                $rows = Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $WorkspaceResourceId -Query $snapshotKql -What ("the table {0}" -f $tbl)
            } catch {
                Write-Err2 ("[shadow] {0} snapshot fetch failed: {1}" -f $tbl, $_.Exception.Message)
                throw
            }
            $rowArr = if ($rows) { @($rows) } else { @() }
            $datatableLet = Convert-RowsToKqlDatatable -LetVarName $tbl -Rows $rowArr -ColumnTypes $(if ($global:RA_LastLaQueryColumnTypes -is [hashtable]) { $global:RA_LastLaQueryColumnTypes.Clone() } else { @{} })
            $script:_CLSnapshotsKql[$tbl] = $datatableLet
            Write-Info ("caching {0} ({1} rows, {2}) to staging" -f $tbl, $rowArr.Count, $colsLogTag)
        }
        [void]$shadows.Add($script:_CLSnapshotsKql[$tbl])
    }
    return (($shadows -join [Environment]::NewLine) + [Environment]::NewLine + $Query)
}

function Get-SISha256Bucket {
    <# v2.2.325 -- SHA256-based bucket assignment, identical math on KQL + PS
       sides so CL-snapshot bucketing aligns with EG-side bucketing.
       KQL equivalent:  tolong(substring(hash_sha256(<key>), 0, 8), 16) % N
       Take first 4 bytes of SHA256(utf8(key)), interpret as big-endian
       UNSIGNED 32-bit (0..2^32-1, matching KQL `tolong(hex, 16)`), modulo N.
       v2.2.323 used signed Int32 + Abs(), which misaligned with KQL: bytes
       0x80..0xff produced PS=2^31-byte but KQL=2^31+byte. Same input, different
       bucket. With CL-bucketing inactive that drift never surfaced; activating
       in v2.2.325 forced the uint32 fix. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Key,
        [Parameter(Mandatory)][int]$BucketCount
    )
    if ($BucketCount -le 1) { return 0 }
    if ([string]::IsNullOrEmpty($Key)) { return 0 }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))
    } finally { $sha.Dispose() }
    # Big-endian UInt32 from first 4 bytes. BitConverter.ToUInt32 reads
    # little-endian, so reverse the slice first.
    $bytes = [byte[]]($hash[0..3])
    [Array]::Reverse($bytes)
    $u = [System.BitConverter]::ToUInt32($bytes, 0)
    return [int]($u % [uint32]$BucketCount)
}

function Get-SICLBucketKey {
    <# v2.2.323 -- mirror New-BucketFilterKql's column-coalesce on a CL row.
       First non-empty wins. Extended beyond device keys to cover Identity
       (EntraObjectId/UserId) and Azure (AzureResourceId_Guid) report shapes.
       v2.2.328 -- prefer EpJoinKey (the synthesized join key projected by the
       canonical `_ep` let-binding body: AadDeviceId || AssetName || PrimaryEntityId).
       v2.2.334 -- add projection-aliased keys used by cross-domain Attack_Paths +
       Identity_Admin_LogonTo_* reports: Target_AzureResourceId_Guid,
       Source_AadDeviceId, Source_AssetId, Target_AssetId_From_CL. Without these
       the 8 cross-domain reports had Get-SICLBucketKey returning '' for EVERY
       row -> all 15K rows landed in bucket 0 -> CL bucketing was a no-op ->
       2.7MB inline payload per bucket -> 413 -> escalation cap fired with zero
       data. With these aliases present, CL distributes evenly across buckets,
       body shrinks to ~42KB per bucket at N=8, AutoBucket settles fast, no cap. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Row)
    # v2.2.337 -- add _si_PrimaryEntityId for Identity_Admin_LogonTo_* reports
    # whose _IdentityCmdb let projects `_si_PrimaryEntityId = tostring(PrimaryEntityId)`
    # as the join key. Without it, all 15K rows hashed to bucket 0 and escalation
    # ran 2->4->8->...->131072 to no avail.
    # v2.2.404 -- when the active report declares crossDomainBucketCoalesce, hash the
    # CL row on the DECLARED column first. Its value equals the EG NodeId hex, so the
    # CL partition matches the EG-side partition (New-BucketFilterKql leads with the
    # same EgNativeKey) -> aligned, lossless, bounded. Falls through to the standard
    # ordered list when the declared column is absent on this row.
    # #505 -- '_ciKey' FIRST: the CI link binding (`_ciLink`, RA-CiKql.ps1) has one row per provider id, and a report
    # that joins it sets its DeviceKey to that same provider id, so the CI row and its findings hash into one bucket.
    $cdcCols = New-Object System.Collections.Generic.List[string]
    foreach ($_cdc in @($script:_CrossDomainBucketCoalesce)) {
        $_c = if ($_cdc -is [System.Collections.IDictionary]) { [string]$_cdc['ClColumn'] }
              elseif ($_cdc.PSObject.Properties['ClColumn'])   { [string]$_cdc.ClColumn }
              else { [string]$_cdc }
        if (-not [string]::IsNullOrWhiteSpace($_c) -and -not $cdcCols.Contains($_c)) { [void]$cdcCols.Add($_c) }
    }
    foreach ($col in $cdcCols) {
        $v = [string]$Row.$col
        if (-not [string]::IsNullOrWhiteSpace($v)) { return $v }
    }
    foreach ($col in '_ciKey','EpJoinKey','_si_PrimaryEntityId','DeviceKey','NodeId','DeviceNodeId','AadDeviceId','DeviceId','MachineId','Id','SourceNodeId','TargetNodeId','EntraObjectId','UserId','AzureResourceId_Guid','PrimaryEntityId','AssetId','Target_AzureResourceId_Guid','Source_AadDeviceId','Source_AssetId','Target_AssetId_From_CL','FinalTargetId','FinalSourceId') {
        # #711: plain member access -- a column the row does not have reads as nothing (no $Row.PSObject per row: it keeps
        # a wrapper per row alive)
        $v = [string]$Row.$col
        if (-not [string]::IsNullOrWhiteSpace($v)) { return $v }
    }
    return ''
}

# ---------------------------------------------------------------------------------------------------
# #711 -- A LOOKUP IS KEPT FOR THE REPORTS THAT USE IT, NOT FOR THE WHOLE RUN.
# The lookups a report reads from Log Analytics (its let-bindings over SI_CI_CL / SI_*_Profile_CL) were cached for the
# WHOLE run: the rows, the whole inline text, the per-slice groups and the key index -- and never let go. The catalog has
# 22 different CI lookups (_ciAsset / _ciLink / _ciPeer by class and factor set) and more over the profile tables, and at a
# large install each holds ~100,000 rows. So every report with a lookup of its own added a tenant-sized block to the
# process, the run grew report by report, and two hours in (large ring-1 install, 2026-10-15 23:27Z) the read of
# Identity_Admin_LogonTo_InternetExposedDevice_Summary's lookups failed with OutOfMemoryException.
# Now each lookup records the report that last used it. At the top of every report the lookups the PREVIOUS report did
# not use are let go (its rows, inline text, slice groups, key index, column types) -- so a lookup shared by reports in
# a row (the Summary and Detailed pair, the identity logon family) is still read once, and the process holds the lookups
# of at most two reports at a time, whatever the length of the run. Nothing is cut: a lookup let go is read again,
# whole, by the next report that needs it.
# ---------------------------------------------------------------------------------------------------
function Register-RALookupCacheUse {
    <# The report now running uses this lookup (its cache key: binding name | hash of its body). #>
    param([Parameter(Mandatory)][string]$CacheKey)
    if ($null -eq $script:_HybridCacheLastUse) { $script:_HybridCacheLastUse = @{} }
    $script:_HybridCacheLastUse[$CacheKey] = [int]$script:_HybridCacheReport
}

function Get-RALookupCacheBaseKey {
    <# PURE. The lookup a cache entry belongs to: the per-slice groups and key index are keyed '<lookup>::<more>'. #>
    param([AllowEmptyString()][string]$Key)
    $i = $Key.IndexOf('::')
    if ($i -ge 0) { return $Key.Substring(0, $i) }
    return $Key
}

function Get-RALookupCacheTables {
    <# Every run-wide table a lookup's rows (or something built from them) are kept in. #>
    return @('_HybridRowsCache', '_HybridSnapshotCache', '_HybridColumnTypesCache', '_HybridBucketGroupsCache', '_HybridBucketGroupsWhole', '_HybridKeyIndexCache')
}

function Remove-RALookupCacheEntries {
    <# Lets go of every cache entry whose lookup is not in -Keep (all of them when -Keep is empty). Returns the number of
       lookups let go. A GC runs when anything was let go, so the memory is free before the next report reads. #>
    param([AllowNull()][System.Collections.Generic.HashSet[string]]$Keep)
    $gone = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($name in (Get-RALookupCacheTables)) {
        $t = Get-Variable -Scope Script -Name $name -ValueOnly -ErrorAction SilentlyContinue
        if ($null -eq $t -or $t -isnot [System.Collections.IDictionary]) { continue }
        foreach ($k in @($t.Keys)) {
            $base = Get-RALookupCacheBaseKey -Key ([string]$k)
            if ($null -ne $Keep -and $Keep.Contains($base)) { continue }
            $t.Remove($k)
            [void]$gone.Add($base)
        }
    }
    if ($script:_HybridCacheLastUse) {
        foreach ($k in @($script:_HybridCacheLastUse.Keys)) { if ($null -eq $Keep -or -not $Keep.Contains([string]$k)) { $script:_HybridCacheLastUse.Remove($k) } }
    }
    if ($gone.Count -gt 0) {
        try { [System.Runtime.GCSettings]::LargeObjectHeapCompactionMode = [System.Runtime.GCLargeObjectHeapCompactionMode]::CompactOnce } catch { }
        [System.GC]::Collect()
    }
    return $gone.Count
}

function Start-RALookupCacheReport {
    <# #711. Called at the top of every report: lets go of the lookups the previous report did not use. Returns
       @{ Released; Kept } (lookups). #>
    $prev = [int]$script:_HybridCacheReport
    $script:_HybridCacheReport = $prev + 1
    $keep = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    if ($script:_HybridCacheLastUse) {
        foreach ($k in @($script:_HybridCacheLastUse.Keys)) { if ([int]$script:_HybridCacheLastUse[$k] -ge $prev) { [void]$keep.Add([string]$k) } }
    }
    $released = Remove-RALookupCacheEntries -Keep $keep
    if ($released -gt 0 -and (Get-Command -Name Write-Diag -ErrorAction SilentlyContinue)) {
        Write-Diag ("lookups: {0} lookup(s) no longer used were let go, {1} kept for this report" -f $released, $keep.Count)
    }
    return @{ Released = [int]$released; Kept = [int]$keep.Count }
}

function Clear-RALookupCaches {
    <# #711. Lets go of EVERY cached lookup (after an out-of-memory: the run goes on with the memory free). #>
    $n = Remove-RALookupCacheEntries -Keep $null
    return [int]$n
}

function Get-SIHybridLetRows {
    <# The CL rows of one hybrid let-binding: fetched from Log Analytics once per (binding, body) and run, then
       served from the run-wide cache. Moved out of Resolve-ProfileCLLetBlocks unchanged (#401) so the pre-pass
       there can read EVERY binding of a query before it decides how any of them is inlined. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$VarName, [Parameter(Mandatory)][string]$BodyKql, [Parameter(Mandatory)][string]$WorkspaceResourceId)
        # Snapshot cache keyed on let-var name + hash of body KQL. v2.2.183 had
        # NO cache here -- a single report with 960 AutoBucket buckets fetched
        # the same 176KB _ep snapshot 960 times in a row (~3 hours of wasted LA
        # round-trips per report). The body never changes across buckets within
        # one report, AND most reports use the same _ep / _TargetCmdb let-binding
        # bodies, so a run-wide cache eliminates the duplication entirely.
        if (-not $script:_HybridSnapshotCache)     { $script:_HybridSnapshotCache     = @{} }
        if (-not $script:_HybridRowsCache)         { $script:_HybridRowsCache         = @{} }   # v2.2.323 -- raw rows for per-bucket re-serialize
        if (-not $script:_HybridBucketGroupsCache) { $script:_HybridBucketGroupsCache = @{} }   # v2.2.360 -- pre-grouped rows by bucket index, one-time SHA256 pass
        $bodyHash = [BitConverter]::ToString([System.Security.Cryptography.MD5]::Create().ComputeHash(
                        [System.Text.Encoding]::UTF8.GetBytes($bodyKql))).Replace('-','')
        $cacheKey = $varName + '|' + $bodyHash
        # #711: this report uses this lookup (Start-RALookupCacheReport keeps it for the next report, lets go of the rest)
        Register-RALookupCacheUse -CacheKey $cacheKey

        # v2.2.327 -- raw-rows fetch + simulation padding happens ONCE per
        # (let-binding body, run). Both bucketing and non-bucketing paths read
        # the same shared $script:_HybridRowsCache so the simulation knob
        # (`$global:SI_SimulateCLRowCount`) takes effect regardless of which
        # path serializes. v2.2.323-.326 only padded in the legacy else branch,
        # so activating CL-bucketing in v2.2.325 silently disabled simulation
        # padding -- a 66-row tenant tested bucketing on 11/66 rows instead of
        # the intended 15000-row stress test.
        if (-not $script:_HybridRowsCache.ContainsKey($cacheKey)) {
            Write-Info ("[hybrid] pre-fetching CL snapshot for let-binding '{0}' from LA workspace ..." -f $varName)
            # #711: the rows are kept while reports use them -- read as COMPACT rows (one small object per row, the same
            # columns and values; SI-AzRest.ps1 Get-SILaCompactRowType). Not while the simulation knob below clones rows.
            $__simOn = 0
            [void][int]::TryParse([string]$global:SI_SimulateCLRowCount, [ref]$__simOn)
            $__compactBefore = $global:SI_LaCompactRows
            $global:SI_LaCompactRows = ($__simOn -le 0)
            try {
                # #690 (37): read in parts when one answer is too short for a limit (more query slices never shrink this
                # read: the snapshot is fetched whole once and cut per slice here)
                $clRows = Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $WorkspaceResourceId -Query $bodyKql -What ("the lookup '{0}'" -f $varName)
            } catch {
                Write-Err2 ("[hybrid] CL snapshot fetch failed for '{0}': {1}" -f $varName, $_.Exception.Message)
                throw
            } finally { $global:SI_LaCompactRows = $__compactBefore }
            $rowCount = if ($clRows) { @($clRows).Count } else { 0 }

            # SIMULATION knob. When operator sets $global:SI_SimulateCLRowCount,
            # pad the snapshot to <target> rows by cloning existing rows with
            # "_sim<N>" suffix on the FIRST non-empty bucket-key column. Clones'
            # fake keys won't match any EG-side row so they're filtered out at
            # the join (no output pollution), but they DO bloat the inline
            # payload so operators can validate scale + bucketing behaviour on
            # small tenants without waiting for a real 50K-asset customer.
            $simTarget = 0
            [void][int]::TryParse([string]$global:SI_SimulateCLRowCount, [ref]$simTarget)
            if ($simTarget -gt 0 -and $rowCount -gt 0 -and $rowCount -lt $simTarget) {
                # v2.2.328+.334 -- mirror Get-SICLBucketKey order so simulation
                # mutates the SAME column the hasher reads. Includes cross-domain
                # aliases (Target_*/Source_*/FinalTargetId/FinalSourceId) so the
                # simulation knob distributes its clones across buckets correctly
                # for those reports too.
                $bucketKeyCols = @('_ciKey','EpJoinKey','_si_PrimaryEntityId','DeviceKey','NodeId','DeviceNodeId','AadDeviceId','DeviceId','MachineId','Id','SourceNodeId','TargetNodeId','EntraObjectId','UserId','AzureResourceId_Guid','PrimaryEntityId','AssetId','Target_AzureResourceId_Guid','Source_AadDeviceId','Source_AssetId','Target_AssetId_From_CL','FinalTargetId','FinalSourceId')
                $needed = $simTarget - $rowCount
                $clones = New-Object System.Collections.Generic.List[object]
                $simIdx = 0
                while ($clones.Count -lt $needed) {
                    foreach ($r in $clRows) {
                        if ($clones.Count -ge $needed) { break }
                        $copy = $r.PSObject.Copy()
                        foreach ($col in $bucketKeyCols) {
                            $p = $copy.PSObject.Properties[$col]
                            if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) {
                                $p.Value = ('{0}_sim{1}' -f [string]$p.Value, $simIdx)
                                break
                            }
                        }
                        [void]$clones.Add($copy)
                        $simIdx++
                    }
                }
                $clRows = @($clRows) + $clones.ToArray()
                $rowCount = @($clRows).Count
                Write-Warn2 ("[hybrid] SIMULATION ACTIVE -- '{0}' padded from {1} real rows to {2} total (+{3} ballast clones with `_sim<n>` suffixed bucket-key). Disable by clearing `$global:SI_SimulateCLRowCount." -f $varName, ($rowCount - $clones.Count), $rowCount, $clones.Count)
            }

            $script:_HybridRowsCache[$cacheKey] = @($clRows)
            # the declared column types of this snapshot: a dynamic column stays dynamic when it is inlined
            if (-not $script:_HybridColumnTypesCache) { $script:_HybridColumnTypesCache = @{} }
            $script:_HybridColumnTypesCache[$cacheKey] = if ($global:RA_LastLaQueryColumnTypes -is [hashtable]) { $global:RA_LastLaQueryColumnTypes.Clone() } else { @{} }
            if ($null -eq $script:_LastHybridSnapshotRowCount -or $rowCount -gt [int]$script:_LastHybridSnapshotRowCount) {
                $script:_LastHybridSnapshotRowCount = [int]$rowCount
            }
        }

        $allRows = $script:_HybridRowsCache[$cacheKey]
        $colTypes = if ($script:_HybridColumnTypesCache -and $script:_HybridColumnTypesCache.ContainsKey($cacheKey)) { $script:_HybridColumnTypesCache[$cacheKey] } else { @{} }
        return @{ CacheKey = $cacheKey; Rows = $allRows; ColumnTypes = $colTypes }
}

function Set-SIHybridCrossDomainFlag {
    <# Sets $script:_SkipEGBucketForCrossDomain when this binding's bucket key is cross-domain. Moved out of
       Resolve-ProfileCLLetBlocks unchanged (#401); called from its pre-pass for every binding. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$VarName, [AllowNull()][AllowEmptyCollection()][object[]]$AllRows, [bool]$ClBucketingActive)
        # v2.2.334 -- cross-domain detection. If this let's CL rows carry a
        # bucket key whose column name isn't in New-BucketFilterKql's EG-side
        # coalesce list (DeviceKey/NodeId/DeviceNodeId/AadDeviceId/DeviceId/
        # MachineId/Id/SourceNodeId/TargetNodeId), the EG-side bucket filter
        # would partition EG rows on a column UNRELATED to the join key -- so
        # per-bucket joins would miss most matches (lossy). Set a per-report
        # script flag so Replace-BucketFilterBlock leaves the EG-side filter
        # as the no-op `| where 1 == 1`. Each per-bucket query then scans
        # ALL EG rows joined to the bucket's CL subset -- lossless, just
        # heavier on EG compute. Cheap insurance vs producing wrong data.
        if ($clBucketingActive -and -not $script:_SkipEGBucketForCrossDomain) {
            # v2.2.336 -- EpJoinKey is the designed-alignment case (CL.EpJoinKey value
            # equals EG.DeviceKey value for matched rows because the EG side extends
            # DeviceKey = iif(isnotempty(AadDeviceId), AadDeviceId, NodeNameNorm) and
            # the CL projection sets EpJoinKey = coalesce(AadDeviceId, AssetName, ...) ).
            # Keep EpJoinKey OUT of the cross-domain trigger so Endpoint single-let
            # reports keep using the EG bucket filter (faster: per-bucket EG scan,
            # not full EG scan per bucket).
            $egStdCols = @{'_ciKey'=$true; 'DeviceKey'=$true; 'NodeId'=$true; 'DeviceNodeId'=$true; 'AadDeviceId'=$true; 'DeviceId'=$true; 'MachineId'=$true; 'Id'=$true; 'SourceNodeId'=$true; 'TargetNodeId'=$true; 'EpJoinKey'=$true}
            # v2.2.404 -- treat report-declared crossDomainBucketCoalesce CL columns as
            # EG-aligned (designed-alignment, same as EpJoinKey). The CL bucket-key value
            # for these columns IS the EG NodeId hex, so SHA256-partitioning the EG side
            # (on NodeId) and the CL side (on the declared column) yields identical
            # buckets -> the EG-side bucket filter can stay ACTIVE and bound EG work
            # without losing any join match. Adding the column here keeps it OUT of the
            # cross-domain suppression trigger below.
            foreach ($_cdc in @($script:_CrossDomainBucketCoalesce)) {
                $_col = if ($_cdc -is [System.Collections.IDictionary]) { [string]$_cdc['ClColumn'] }
                        elseif ($_cdc.PSObject.Properties['ClColumn'])   { [string]$_cdc.ClColumn }
                        else { [string]$_cdc }
                if (-not [string]::IsNullOrWhiteSpace($_col)) { $egStdCols[$_col] = $true }
            }
# 🪤 '_SIName' (the key of the name-keyed _epByName / _apByName bindings) WAS ADDED HERE ON
            # 2026-08-29 AND REVERTED THE SAME DAY. The reasoning looked sound -- that binding hashes
            # every row into bucket 0, so left rows processed in bucket 2 see an empty lookup, and four
            # Key Vaults that ARE in SI_Azure_Profile_CL came back with no id. Naming it here does
            # suppress the EG-side filter and does recover them.
            # 🔴 AND IT DUPLICATES ROWS, because the suppression's "lossless" claim assumes ONE CL
            # binding. These reports have TWO: `_ep` bucketed on EpJoinKey and `_epByName` entirely in
            # bucket 0. With the EG filter off, every bucket scans ALL EG rows, so an EG row that
            # matches `_ep` in bucket 1 and `_epByName` in bucket 0 is emitted by BOTH bucket queries.
            # Measured on full runs of the same estate: 597 rows -> 716, and
            # Device_Recommendations_Summary went from 1 misaligned row to 47. Double-counted findings
            # are far worse than four assets with an honest empty id.
            # ◻ The real fix is to bucket the name binding on a key the EG side also partitions on, or
            # to teach the suppression about multiple CL bindings. Neither is a one-line change.
            # ✅ #401 (2026-10-07) taught it: with the filter off, Resolve-ProfileCLLetBlocks now REPLICATES
            # every binding (budget permitting) and the bucket loop keeps one complete bucket. Adding
            # '_SIName' here would therefore no longer duplicate -- but it would turn the EG-side filter off
            # for those reports too, so it stays out until someone measures that cost.
            $crossDomainCols = @('Target_AzureResourceId_Guid','Source_AadDeviceId','Source_AssetId','Target_AssetId_From_CL','FinalTargetId','FinalSourceId','_si_PrimaryEntityId')
            $firstRow = if (@($allRows).Count -gt 0) { @($allRows)[0] } else { $null }
            if ($firstRow) {
                foreach ($cdCol in $crossDomainCols) {
                    $p = $firstRow.PSObject.Properties[$cdCol]
                    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) {
                        if (-not $egStdCols.ContainsKey($cdCol)) {
                            $script:_SkipEGBucketForCrossDomain = $true
                            Write-Info ("[hybrid] cross-domain let '{0}' uses '{1}' (not in EG bucket coalesce list) -- suppressing EG-side bucket filter so per-bucket joins stay lossless." -f $varName, $cdCol)
                        }
                        break
                    }
                }
            }
        }
}

# ---------------------------------------------------------------------------------------------------
# A LOOKUP THAT IS NEEDED WHOLE IN EVERY SLICE CAN BE LARGER THAN ONE REQUEST -- AND NO SLICE COUNT FIXES THAT.
#
# Splitting a report into more slices shrinks only the lookups that are split WITH it (keyed on the same id
# the Exposure-Graph side is sliced on). A lookup without such a key is copied whole into every slice, and
# so is the query text. That part is the same at 2 slices and at 100,000. Measured 2026-10-13 at a customer:
# one lookup of 43,124 rows = 1,137,605 bytes, copied whole, against a request body of about 1 MB. The
# engine escalated 2 -> 1,024 slices and then tried each of the 1,024 three times: about 34 hours of
# requests that could not be accepted, and every report after it never ran.
#
# So the size of the part that does NOT shrink is measured before a request goes out. Two decisions:
#   CERTAIN   -- that part alone is at or over what one request can carry: decided before anything is sent.
#   MEASURED  -- a request was refused for its size and what more slices could still remove from it is a
#                sliver of it: decided on that first refusal, not after every slice has been tried.
# Either way the report is failed as a whole (its findings are unknown, never "none") and the run goes on.
# ---------------------------------------------------------------------------------------------------
function Get-RAHuntingRequestCapBytes {
    <# What one advanced-hunting request can carry: the proxy in front of it refuses a body over 1 MB.
       A fact about the service, not a tuning value; the global exists so a test can use small data. #>
    $v = 0
    [void][int]::TryParse([string]$global:SI_HuntingRequestCapBytes, [ref]$v)
    if ($v -gt 0) { return $v }
    return [int]1MB
}

function Get-RARequestWireBytes {
    <# PURE. The bytes a piece of query text takes in the request body: UTF-8, plus one byte for every
       character JSON has to escape. Never an over-estimate -- the decision built on it must be certain. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return 0 }
    return ([System.Text.Encoding]::UTF8.GetByteCount($Text) + [regex]::Matches($Text, '["\\\r\n\t]').Count)
}

function Format-RAByteSize {
    <# PURE. 1137605 -> "1.1 MB", 81571 -> "80 KB". Invariant culture: this goes into a log line. #>
    param([long]$Bytes)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if ($Bytes -ge 1MB) { return ([string]::Format($inv, '{0:0.0} MB', ($Bytes / 1MB))) }
    if ($Bytes -ge 1KB) { return ([string]::Format($inv, '{0:0} KB', [Math]::Round($Bytes / 1KB))) }
    return ([string]::Format($inv, '{0} bytes', $Bytes))
}

function Get-RAWholeLookupText {
    <# PURE. Names what is copied whole into every part of the query, largest first:
       "the lookup _dfcPairs (43,124 rows, 1.1 MB) is needed whole in every part of the query". #>
    param([AllowNull()][object[]]$Lookups)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $whole = @(@($Lookups) | Where-Object { $null -ne $_ -and [bool]$_.Whole } | Sort-Object -Property @{ Expression = { [long]$_.WireBytes }; Descending = $true })
    $names = @($whole | ForEach-Object { [string]::Format($inv, '{0} ({1:N0} rows, {2})', [string]$_.Name, [int]$_.Rows, (Format-RAByteSize -Bytes ([long]$_.WireBytes))) })
    if ($names.Count -eq 0) { return 'the query text is needed whole in every part of the query' }
    if ($names.Count -eq 1) { return ('the lookup {0} is needed whole in every part of the query' -f $names[0]) }
    $head = @($names[0..($names.Count - 2)]) -join ', '
    return ('the lookups {0} and {1} are needed whole in every part of the query' -f $head, $names[$names.Count - 1])
}

function New-RALookupTooLargeError {
    <# The error that says "no slice count can make this report fit". Marked in its Data so the bucket loop
       recognises it without reading the text; the text itself is what the customer's log shows. #>
    param([Parameter(Mandatory)][string]$Message)
    $ex = New-Object System.InvalidOperationException($Message)
    $ex.Data['SIRALookupTooLarge'] = $true
    return $ex
}

function Test-RALookupTooLargeError {
    <# PURE. True for the error New-RALookupTooLargeError makes (an ErrorRecord, an exception or its text). #>
    param([AllowNull()][object]$Err)
    if ($null -eq $Err) { return $false }
    $ex = $null
    if ($Err -is [System.Management.Automation.ErrorRecord]) { $ex = $Err.Exception } elseif ($Err -is [System.Exception]) { $ex = $Err }
    while ($null -ne $ex) {
        if ($ex.Data -and $ex.Data.Contains('SIRALookupTooLarge')) { return $true }
        $ex = $ex.InnerException
    }
    $msg = if ($Err -is [System.Management.Automation.ErrorRecord]) { [string]$Err.Exception.Message } else { [string]$Err }
    return ($msg -match 'more than a query to Microsoft Defender can carry')
}

# ---------------------------------------------------------------------------------------------------
# #674 FAIL CLOSED: A LOOKUP THE REPORT NEEDS THAT CANNOT BE READ MAKES THE REPORT NOT COMPLETE.
#
# A report that joins SecurityInsight's own Log Analytics tables (SI_*_CL) with the Exposure Graph gets those tables
# from Log Analytics and sends them with the query. When that read failed, the engine used to go on without them: the
# lookup was left for a "whole table copy" fallback, and when that failed too the query went as it was -- to
# Microsoft Defender, which does not have these tables, where `union isfuzzy` quietly made the lookup EMPTY. The report
# then came back Complete: with every recommendation the Defender recommendation report also lists (the hand-off list
# was empty), or with the CMDB / CI values missing (the enrichment was empty). Nothing said so.
# Now such a read failing makes THAT report not complete, with a plain reason; the run goes on with the next report.
# A table that does not exist at all in Log Analytics is not a failure: that table has no data in this install (the
# existing "not applicable" rule, Test-RANoDataSource), so its error is passed on unchanged.
# ---------------------------------------------------------------------------------------------------
function New-RALookupUnavailableError {
    <# The error that says "a lookup this report needs could not be read". Marked in its Data so the bucket loop
       recognises it without reading the text; the text is what the customer's log shows. #>
    param([Parameter(Mandatory)][string]$Message)
    $ex = New-Object System.InvalidOperationException($Message)
    $ex.Data['SIRALookupUnavailable'] = $true
    return $ex
}

function Test-RALookupUnavailableError {
    <# PURE. True for the error New-RALookupUnavailableError makes (an ErrorRecord, an exception or its text). #>
    param([AllowNull()][object]$Err)
    if ($null -eq $Err) { return $false }
    $ex = $null
    if ($Err -is [System.Management.Automation.ErrorRecord]) { $ex = $Err.Exception } elseif ($Err -is [System.Exception]) { $ex = $Err }
    while ($null -ne $ex) {
        if ($ex.Data -and $ex.Data.Contains('SIRALookupUnavailable')) { return $true }
        $ex = $ex.InnerException
    }
    $msg = if ($Err -is [System.Management.Automation.ErrorRecord]) { [string]$Err.Exception.Message } else { [string]$Err }
    return ($msg -match 'a lookup this report needs could not be read|SI-RA lookup unavailable')
}

function Test-RAReportCannotRunError {
    <# PURE. The two errors that end a report in one decision, before a retry, a re-size or a sub-slice is spent on it:
       the request can never fit (Test-RALookupTooLargeError) or a lookup it needs cannot be read (#674). #>
    param([AllowNull()][object]$Err)
    return ((Test-RALookupTooLargeError -Err $Err) -or (Test-RALookupUnavailableError -Err $Err))
}

function Test-RAOutOfMemoryError {
    <# PURE. Did this error come from the process running out of memory? A .NET OutOfMemoryException anywhere in the chain
       (also wrapped: "Exception calling ... : Exception of type 'System.OutOfMemoryException' was thrown"), or its text.
       (The same test as SI-ErrorClass.ps1's Test-SIOutOfMemoryText, kept here so this file loads on its own.) #>
    param([AllowNull()][object]$Err)
    if ($null -eq $Err) { return $false }
    $ex = $null
    if ($Err -is [System.Management.Automation.ErrorRecord]) { $ex = $Err.Exception } elseif ($Err -is [System.Exception]) { $ex = $Err }
    while ($null -ne $ex) {
        if ($ex -is [System.OutOfMemoryException]) { return $true }
        if ($ex.Data -and $ex.Data.Contains('SIRAOutOfMemory')) { return $true }
        $ex = $ex.InnerException
    }
    $msg = if ($Err -is [System.Management.Automation.ErrorRecord]) { [string]$Err.Exception.Message } elseif ($Err -is [System.Exception]) { [string]$Err.Message } else { [string]$Err }
    return [bool]($msg -match '(?i)OutOfMemoryException|\bOOMKilled\b|\bout of memory\b')
}

function New-RALookupOutOfMemoryError {
    <# #711 -- si-ra-0303. The "lookup unavailable" error (the report ends at once, not complete, its findings unknown) for
       a read that ran the process out of memory. Marked SIRALookupUnavailable (the report loop's existing path),
       SIRAOutOfMemory and SIRACode. The text says "out of memory" (the run health END carries it, which is what raises the
       job one size band at the next update) and the code. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$What, [AllowEmptyString()][string]$Line = '', [int]$Freed = 0)
    $msg = "a lookup this report needs could not be read from Log Analytics ({0}): Risk Analysis ran out of memory reading it (si-ra-0303) -- the report is not run without it, its findings are unknown for this run, not resolved; the lookups held in memory were let go ({1}) and the run goes on: {2}" -f $What, $Freed, $Line
    $ex = New-Object System.InvalidOperationException($msg)
    $ex.Data['SIRALookupUnavailable'] = $true
    $ex.Data['SIRAOutOfMemory'] = $true
    $ex.Data['SIRACode'] = 'si-ra-0303'
    return $ex
}

function ConvertTo-RALookupUnavailableError {
    <# What a failed read of a report's lookup becomes: the original error when the table simply does not exist in Log
       Analytics (no data source here -- unchanged behaviour), else the "lookup unavailable" error naming the lookup. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$What, [AllowNull()][object]$Err)
    $msg = if ($Err -is [System.Management.Automation.ErrorRecord]) { [string]$Err.Exception.Message } elseif ($Err -is [System.Exception]) { [string]$Err.Message } else { [string]$Err }
    $line = ($msg -split "`n" | Select-Object -First 1)
    if ((Get-Command -Name Test-RANoDataSource -ErrorAction SilentlyContinue) -and (Test-RANoDataSource -Message $msg)) { return $null }
    if (Test-RALookupUnavailableError -Err $Err) { return $null }
    # #690 (37): a read no number of parts makes fit (si-ra-0302) is passed on as it is -- it already ends the report
    if (Test-RALookupTooLargeError -Err $Err) { return $null }
    # #711: out of memory is its own cause (si-ra-0303), never "the lookup could not be read" alone. Every cached lookup is
    # let go first, so the rest of the run has its memory back; this report ends not complete, as for any lookup it lacks.
    if (Test-RAOutOfMemoryError -Err $Err) {
        $freed = 0
        try { $freed = Clear-RALookupCaches } catch { }
        return (New-RALookupOutOfMemoryError -What $What -Line $line -Freed $freed)
    }
    return (New-RALookupUnavailableError -Message ("a lookup this report needs could not be read from Log Analytics ({0}) -- the report is not run without it, because it would then list findings twice or without their CI and CMDB values: {1}" -f $What, $line))
}

function Get-RAHandoffLookupBinding {
    <# PURE. The hand-off lookup of a query (#147 / #278): the let-binding between //__DEFENDER_HANDOFF_BEGIN__ and
       //__DEFENDER_HANDOFF_END__ that reads a SecurityInsight table. $null when the query has no such block, or the
       block was emptied because the receiving report is not in the run (#278 -- an intentionally empty hand-off).
       @{ Var; Body; Table } -- Body is the exact text Resolve-ProfileCLLetBlocks fetches (the same run-wide cache). #>
    param([AllowNull()][AllowEmptyString()][string]$Query)
    if ([string]::IsNullOrEmpty($Query)) { return $null }
    $m = [regex]::Match($Query, '//__DEFENDER_HANDOFF_BEGIN__(?<block>.*?)//__DEFENDER_HANDOFF_END__', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $m.Success) { return $null }
    $lm = [regex]::Match($m.Groups['block'].Value, '(?ms)\blet\s+(?<var>\w+)\s*=\s*(?<body>[^;]*?\bSI_[A-Za-z]+(?:_Profile)?_CL\b[^;]*?);')
    if (-not $lm.Success) { return $null }
    $tm = [regex]::Match($lm.Groups['body'].Value, '\b(?<t>SI_[A-Za-z]+(?:_Profile)?_CL)\b')
    return @{ Var = $lm.Groups['var'].Value; Body = $lm.Groups['body'].Value; Table = $tm.Groups['t'].Value }
}

function Get-RAHandoffSourceVerdict {
    <# PURE. What an EMPTY hand-off lookup means, from one count of its source table over a longer window than the
       lookup reads (-Rows; $null with -CountError when the count failed). Returns @{ State; Reason }:
         Absent   -- the table does not exist in Log Analytics: no list was ever written (no Defender for Cloud
                     recommendation in this install, or the collection of them is off). Nothing to hand off: the report
                     keeps every finding, as when the receiving report is not in the run.
         Stale    -- the table has rows, but none in the window the lookup reads: there is no current list to hand off
                     to (the receiving report reads the same window and finds none either). Kept as it is, said.
         NotReady -- the table exists but none of its rows can be read: a new table (an install's first run) takes up to
                     about 45 minutes in Log Analytics before its rows can be read. The receiving report may already see
                     them, so this report could list the same recommendations twice -> NOT complete.
         Unknown  -- the count itself failed: not knowable -> NOT complete. #>
    param($Rows, [string]$CountError = '', [string]$Table = '')
    if ($CountError) {
        if ($CountError -match ("Failed to resolve table (?:or column )?expression named '{0}'" -f [regex]::Escape($Table)) -or ($Table -eq '' -and $CountError -match "Failed to resolve table (?:or column )?expression named 'SI_[A-Za-z0-9_]+_CL'")) {
            return @{ State = 'Absent'; Reason = ('{0} does not exist in Log Analytics -- no Defender recommendation list was ever written, so there is nothing to hand off' -f $Table) }
        }
        return @{ State = 'Unknown'; Reason = ('the Defender recommendation list ({0}) reads empty and Log Analytics could not say whether that is right: {1}' -f $Table, (($CountError -split "`n") | Select-Object -First 1)) }
    }
    if ($null -ne $Rows -and [long]$Rows -gt 0) {
        return @{ State = 'Stale'; Reason = ('{0} holds no Defender recommendation list from the last 8 days (only older ones) -- there is no current list to hand off' -f $Table) }
    }
    return @{ State = 'NotReady'; Reason = ('the Defender recommendation list ({0}) exists but none of its rows can be read yet -- a new table in Log Analytics takes up to about 45 minutes; without the list this report would also list the recommendations the Defender recommendation report lists' -f $Table) }
}

function Assert-RAHandoffLookupReadable {
    <# #674. When the query hands findings to another report (its hand-off block reads a SecurityInsight table) and the
       hand-off list reads EMPTY, finds out whether that is right (Get-RAHandoffSourceVerdict, one count per table and
       run) and throws the "lookup unavailable" error when it is not. A list with rows, an emptied hand-off (#278), an
       absent table and an only-older list return quietly. -Fetch / -Count are seams for tests. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query, [Parameter(Mandatory)][string]$WorkspaceResourceId,
          [scriptblock]$Fetch, [scriptblock]$Count)
    $b = Get-RAHandoffLookupBinding -Query $Query
    if ($null -eq $b) { return }
    try {
        $rows = if ($Fetch) { @(& $Fetch $b) } else { @((Get-SIHybridLetRows -VarName $b.Var -BodyKql $b.Body -WorkspaceResourceId $WorkspaceResourceId).Rows) }
    } catch {
        $e = ConvertTo-RALookupUnavailableError -What ('the hand-off list {0}' -f $b.Var) -Err $_
        if ($e) { throw $e }
        throw
    }
    $rows = @($rows | Where-Object { $null -ne $_ })
    if ($rows.Count -gt 0) { return }
    if (-not $script:_RAHandoffVerdicts) { $script:_RAHandoffVerdicts = @{} }
    if (-not $script:_RAHandoffVerdicts.ContainsKey($b.Table)) {
        $lookback = 90; $lb = 0
        if ([int]::TryParse([string]$global:SI_RA_HandoffSourceLookbackDays, [ref]$lb) -and $lb -gt 8) { $lookback = $lb }
        $n = $null; $err = ''
        try {
            if ($Count) { $n = & $Count $b $lookback }
            else {
                $cq = ("{0}`n| where TimeGenerated > ago({1}d)`n| summarize SIRows = count()" -f $b.Table, $lookback)
                # assigned first: the reader answers ONE array (`return ,@(...)`) -- @() around the call would make that
                # array a single row and the count would read as 0
                $crRaw = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $WorkspaceResourceId -Query $cq
                $cr = @($crRaw)
                $n = 0L
                if ($cr.Count -gt 0 -and $null -ne $cr[0] -and $cr[0].PSObject.Properties['SIRows']) { $n = [long]$cr[0].SIRows }
            }
        } catch { $err = [string]$_.Exception.Message; if (-not $err) { $err = 'the count failed' } }
        $v = Get-RAHandoffSourceVerdict -Rows $n -CountError $err -Table $b.Table
        $script:_RAHandoffVerdicts[$b.Table] = $v
        if ($v.State -in 'Absent', 'Stale') { Write-Info ("the hand-off list {0} is empty and that is right: {1}. Every recommendation stays in this report." -f $b.Var, $v.Reason) }
    }
    $v = $script:_RAHandoffVerdicts[$b.Table]
    if ($v.State -in 'Absent', 'Stale') {
        # remembered for the receiving report's check (Test-RAHandoffContradiction): if IT finds rows in this same run,
        # the list appeared after this report ran and this report is not complete after all
        if (-not $script:_RAHandoffEmptyGivers) { $script:_RAHandoffEmptyGivers = @{} }
        $rn = [string](Get-Variable -Name ReportName -ValueOnly -ErrorAction SilentlyContinue)
        if ($rn) { $script:_RAHandoffEmptyGivers[$rn] = $v.Reason }
        return
    }
    throw (New-RALookupUnavailableError -Message ('a lookup this report needs could not be read -- {0}' -f $v.Reason))
}

function Get-RAHandoffContradiction {
    <# PURE. #674: the receiving report -ReportName retrieved -Retrieved rows in this run; a report that handed findings to
       it while its hand-off list read empty (-EmptyGivers: giver -> why it looked right) listed them itself. Returns the
       givers to mark NOT complete, each @{ Report; Why }. #>
    param([Parameter(Mandatory)][string]$ReportName, [long]$Retrieved, [hashtable]$EmptyGivers, [hashtable]$Successors)
    $out = [System.Collections.Generic.List[object]]::new()
    if ($Retrieved -le 0 -or $null -eq $EmptyGivers -or $EmptyGivers.Count -eq 0) { return @() }
    if ($null -eq $Successors) { $Successors = Get-RAReportSuccessorMap }
    foreach ($g in @($EmptyGivers.Keys)) {
        if (-not $Successors.ContainsKey($g)) { continue }
        if (@($Successors[$g]) -notcontains $ReportName) { continue }
        $out.Add(@{ Report = [string]$g; Why = ("its hand-off list read empty when it ran ({0}), but {1} found {2} row(s) later in this run -- it may list the same recommendations as that report" -f [string]$EmptyGivers[$g], $ReportName, $Retrieved) })
    }
    return $out.ToArray()
}

function Get-RAHybridRequestShape {
    <# The request that was just built, split into what more slices can shrink and what they cannot.
       -Query is the FINAL text (lookups and whole-table copies inlined). The part that shrinks is the sum of
       the lookups Resolve-ProfileCLLetBlocks split per slice; everything else is the same in every slice. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query, [int]$BucketCount = 0)
    $lookups = @(@($script:_RAHybridLookups) | Where-Object { $null -ne $_ })
    $shrinks = [long]0
    foreach ($l in $lookups) { if (-not [bool]$l.Whole) { $shrinks += [long]$l.WireBytes } }
    $body  = [long](Get-RARequestWireBytes -Text $Query)
    $fixed = [long][Math]::Max(0, $body - $shrinks)
    return @{ BodyBytes = $body; FixedBytes = $fixed; BucketCount = [int]$BucketCount; Lookups = $lookups }
}

function Assert-RAHybridQueryFits {
    <# CERTAIN decision, before anything is sent. Records the shape of this request for the MEASURED decision
       (Get-RARefusedRequestVerdict) and throws when the part no slice count can shrink is by itself at or over
       what one request can carry. Only for a sliced query: an unsliced one is sent and answered as before. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query, [int]$BucketCount = 0)
    $shape = Get-RAHybridRequestShape -Query $Query -BucketCount $BucketCount
    $script:_RAHybridLastRequest = $shape
    if ($BucketCount -le 1) { return }
    $cap = [long](Get-RAHuntingRequestCapBytes)
    if ([long]$shape.FixedBytes -lt $cap) { return }
    $what = Get-RAWholeLookupText -Lookups $shape.Lookups
    throw (New-RALookupTooLargeError -Message ("{0} -- with the query text that is {1} in every part, more than a query to Microsoft Defender can carry ({2}), so splitting the query into more parts cannot make it fit" -f `
        $what, (Format-RAByteSize -Bytes ([long]$shape.FixedBytes)), (Format-RAByteSize -Bytes $cap)))
}

function Get-RARefusedRequestVerdict {
    <# MEASURED decision, after the service REFUSED a request for its size (413). Returns the reason when
       more slices cannot help, else $null.
       What more slices can remove is the split lookups' share of the refused request. When that share is a
       sliver (2% or less), the request that would be left is the refused one again -- the same answer at any
       slice count. A larger share keeps escalating exactly as before: this never stops a report that
       splitting can still shrink. Only the request-size refusal counts; a RESULT that is too large or a
       query that ran out of time is a different condition and is not judged here. #>
    param([AllowNull()][object]$Err, [double]$SliverShare = 0.02)
    if ($null -eq $Err) { return $null }
    $msg = if ($Err -is [System.Management.Automation.ErrorRecord]) { [string]$Err.Exception.Message + ' ' + [string]$Err.ErrorDetails } else { [string]$Err }
    if ($msg -notmatch '(?i)\b413\b|request entity too large') { return $null }
    $r = $script:_RAHybridLastRequest
    if ($null -eq $r -or [long]$r.BodyBytes -le 0 -or [int]$r.BucketCount -le 1) { return $null }
    $shrinks = [long]$r.BodyBytes - [long]$r.FixedBytes
    if ([double]$shrinks -gt ([double]$r.BodyBytes * $SliverShare)) { return $null }
    $what = Get-RAWholeLookupText -Lookups $r.Lookups
    return ("{0} -- Microsoft Defender refused the query at {1} as too large, and {2} of that is the same in every part, more than a query to Microsoft Defender can carry, so splitting the query into more parts cannot make it fit" -f `
        $what, (Format-RAByteSize -Bytes ([long]$r.BodyBytes)), (Format-RAByteSize -Bytes ([long]$r.FixedBytes)))
}

# ---------------------------------------------------------------------------------------------------
# A LOOKUP WITHOUT A PER-ASSET KEY, CUT PER SLICE ANYWAY: SEND ONLY THE ROWS THE SLICE CAN MATCH.
#
# A lookup is split with the slices when it carries the id the slices are cut on (Get-SICLBucketKey). The
# hand-off lookup of the Azure recommendation reports cannot: it is one column of hashes of three kinds of
# pair (name + recommendation, resource id + recommendation, resource + assessment key), and only the middle
# one names the asset the slice is cut on. Splitting it on any id would lose the matches of the other two.
#
# What a slice needs of such a lookup is exactly the rows whose key one of ITS graph rows has. So the report
# declares (field LookupNeededKeys) how those keys are computed and where in its query they are known (the
# line //__SI_LOOKUP_KEYS_HERE__, after the slice filter). For each slice the engine first sends the query up
# to that line, ending in the keys, and gets back the keys that slice can have; then it inlines only the lookup
# rows with one of those keys. An anti-join or join against those rows gives the same result as against the
# whole lookup -- the report's own query text is not changed by this at all.
#
# 🔒 ONLY WHEN THE LOOKUP DOES NOT FIT WHOLE (the part of the request no slice count can shrink is over the
# size the engine plans a request to). Where it fits, nothing is asked and nothing changes. A key query that
# fails is a failed slice like any other (retried, re-sized or recorded lost by the bucket loop).
# ---------------------------------------------------------------------------------------------------
function Get-RAHuntingPlanningBudgetBytes {
    <# The request size the engine plans to (75% of what one request carries; the rest is headroom for headers,
       the token and what the size estimate cannot see). The same share the slice-count escalation uses. #>
    return [long]([double](Get-RAHuntingRequestCapBytes) * 0.75)
}

function Get-RALookupNeededKeyDeclarations {
    <# The report's LookupNeededKeys entries that apply to THIS query: the lookup is one of its lookups and the
       cut point is in it. Each: @{ Lookup; Column; Keys }. The report loop puts the entries in
       $script:_RALookupNeededKeys; a query without the cut point (any other report, any helper query) gets none. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query)
    $out = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrEmpty($Query) -or $Query.IndexOf('//__SI_LOOKUP_KEYS_HERE__') -lt 0) { return @() }
    foreach ($d in @($script:_RALookupNeededKeys)) {
        if ($null -eq $d) { continue }
        $get = { param($n) if ($d -is [System.Collections.IDictionary]) { [string]$d[$n] } elseif ($d.PSObject.Properties[$n]) { [string]$d.$n } else { '' } }
        $lookup = (& $get 'Lookup').Trim(); $column = (& $get 'Column').Trim(); $keys = (& $get 'Keys').Trim()
        if (-not $lookup -or -not $column -or -not $keys) { continue }
        if ($Query -notmatch ('(?m)\blet\s+{0}\s*=' -f [regex]::Escape($lookup))) { continue }
        $out.Add(@{ Lookup = $lookup; Column = $column; KeysKql = $keys })
    }
    return @($out.ToArray())
}

function Get-RALookupKeyQuery {
    <# PURE. The key query of one slice: the (already inlined) query up to the cut point, then the report's own
       key lines, then one row per distinct key. $null when the cut point is not in the query. #>
    param([Parameter(Mandatory)][string]$ResolvedQuery, [Parameter(Mandatory)][string]$KeysKql)
    $m = [regex]::Match($ResolvedQuery, '(?m)^[ \t]*//__SI_LOOKUP_KEYS_HERE__[ \t]*\r?$')
    if (-not $m.Success) { return $null }
    $nl = [Environment]::NewLine
    $head = $ResolvedQuery.Substring(0, $m.Index).TrimEnd()
    $q = $head + $nl + $KeysKql.Trim() + $nl +
         '| mv-expand __siNeeded to typeof(string)' + $nl + '| where isnotempty(__siNeeded)' + $nl + '| summarize by __siNeeded'
    # #677: the cut point may sit INSIDE a let-binding (an attack-path report builds its rows in a let and ends in a
    # summary over it). The keys are then that binding's value: it is closed and named as the query's result.
    $let = Get-RALookupCutLetName -Head $head
    if ($let) { $q = $q + ';' + $nl + $let }
    return $q
}

function Get-RALookupCutLetName {
    <# PURE. The let-binding the text ends inside of (the statement after the last top-level ';' is `let <name> =`), or
       '' when the text ends in the query's final statement. String literals and // comments are blanked first, so a ';'
       inside them (an inlined datatable value, a comment) does not count. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Head)
    $s = [regex]::Replace($Head, '//[^\r\n]*', { param($x) ' ' * $x.Value.Length })
    $s = [regex]::Replace($s, '@?"(?:[^"\\\r\n]|\\.)*"', { param($x) ' ' * $x.Value.Length })
    $s = [regex]::Replace($s, "@?'(?:[^'\\\r\n]|\\.)*'", { param($x) ' ' * $x.Value.Length })
    $tail = $s.Substring($s.LastIndexOf(';') + 1)
    $lm = [regex]::Match($tail, '\A\s*let\s+(\w+)\s*=')
    if ($lm.Success) { return $lm.Groups[1].Value }
    return ''
}

function Get-RALookupReductionId {
    <# PURE. One id per declared reduction, for "this lookup did not fit whole in this run". #>
    param([Parameter(Mandatory)][hashtable]$Declaration)
    return ('{0}|{1}|{2}' -f [string]$Declaration['Lookup'], [string]$Declaration['Column'], (Get-RARequestWireBytes -Text ([string]$Declaration['KeysKql'])))
}

function Invoke-RALookupKeyDiscovery {
    <# Asks the graph, for THIS slice, which keys each declared lookup can be matched on, and leaves the answer in
       $script:_RALookupNeededKeySets for the inlining that follows. The key query is the report's query up to its
       cut point, with every other lookup inlined as usual and the declared ones EMPTY (they are not read before
       the cut point). Its errors are not caught here: a key query that is refused, times out or is throttled is
       a failed slice, and the bucket loop already knows what to do with each of those. #>
    param(
        [Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [int]$BucketCount = 0, [int]$BucketIndex = 0, [Parameter(Mandatory)][object[]]$Declarations, [int]$ReconnectMaxAgeMinutes = 45
    )
    $empty = @{}
    # #751: EVERY lookup the report declares for this query is empty in the key query -- not only the ones asked for now.
    # Live 2026-10-18 (Identity_Admin_LogonTo_LowTierDevice_Summary, a large install): _ciPeer was already cut for the run
    # (an earlier report declares it with the same key lines), _deviceTierOwn not yet. The key query was asked for _ciPeer
    # alone and carried _deviceTierOwn WHOLE (1.4 MB) -- its size check refused it ("needed whole in every part") before the
    # engine could see that _deviceTierOwn does not fit and cut it too. A declared lookup is by contract not read before
    # the cut point, so the key query is the same question with it empty; the one that is not cut yet goes whole only
    # into the report query, where the size decision that turns its cut on is made.
    $__allDecl = @(@($Declarations) + @(Get-RALookupNeededKeyDeclarations -Query $Query))
    # ('KeySet', read with ['KeySet']: a hashtable's own .Keys is its list of entry names)
    foreach ($d in $__allDecl) {
        if ($null -eq $d -or $empty.ContainsKey([string]$d['Lookup'])) { continue }
        $empty[[string]$d['Lookup']] = @{ Column = [string]$d['Column']; KeySet = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)) }
    }
    $script:_RALookupNeededKeySets = $empty
    # #697 (3): the key query carries the declared lookups EMPTY on purpose (they are not read before the cut point). The
    # inlining must not say "0 of its rows can match this part" for that: it is not this part's answer, and it read in the
    # run log (2026-10-15) as if the part had nothing to match -- the part's real answer is the line after the ask.
    $script:_RALookupKeyQueryBuilding = $true
    try {
        $resolved = Resolve-ProfileCLLetBlocks -Query $Query -WorkspaceResourceId $WorkspaceResourceId -BucketCount $BucketCount -BucketIndex $BucketIndex
    } finally { $script:_RALookupKeyQueryBuilding = $false }
    $resolved = Add-CLSnapshotShadows -Query $resolved -WorkspaceResourceId $WorkspaceResourceId
    # how many rows each lookup holds in all (read while the key query was built)
    $totals = @{}
    foreach ($l in @(@($script:_RAHybridLookups) | Where-Object { $null -ne $_ })) { if ($l.ContainsKey('TotalRows')) { $totals[[string]$l.Name] = [int]$l.TotalRows } }

    $sets = @{}
    foreach ($d in $Declarations) {
        $kq = Get-RALookupKeyQuery -ResolvedQuery $resolved -KeysKql ([string]$d['KeysKql'])
        if (-not $kq) { throw ("the cut point for the lookup {0} is not in the query" -f [string]$d['Lookup']) }
        # #697 (3) A LOOKUP WITH NO ROWS AT ALL: no row of it can match any part, so nothing is asked -- the part is sent
        # with it empty (its columns kept) at once, which is exactly what an ask answered by any keys would have sent.
        if ($totals.ContainsKey([string]$d['Lookup']) -and [int]$totals[[string]$d['Lookup']] -eq 0) {
            $sets[[string]$d['Lookup']] = @{ Column = [string]$d['Column']; KeySet = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)) }
            Write-Info ("the lookup {0} has no rows, so no row of it can match this part of the query -- it is sent with it empty, nothing is asked" -f [string]$d['Lookup'])
            continue
        }
        # #697 (3) THE SAME PART ASKED AGAIN: the key query is the report's text up to the cut point with this part's slice
        # filter and lookups inlined, so the SAME text is the SAME question. Measured 2026-10-15: every part was asked
        # twice in a row (its rows, then its own '| count' check, whose text before the cut point is identical) and the
        # probe's part was asked again as bucket 1 -- 33 asks, 331 s, on one report of 25 rows. The answer to the text
        # asked just before is used again; any other text is asked. Remembered for ONE text only (the last), so nothing
        # grows and a part asked later in the run is asked again. Clear-RALookupKeyAnswerMemo forgets it (the bucket loop
        # does that before a short part is asked again, so that ask gets a fresh answer).
        $kqHash = Get-RALookupKeyQueryHash -Text $kq
        $memo = $script:_RALookupKeyAnswerMemo
        # #741 (2): the answer is the TEXT's, not the lookup's -- two lookups declared with the same key lines (the device's CI
        # and the device's own tier, both on the device key) ask one question, so the second uses the first's answer
        if ($null -ne $memo -and [string]$memo.Hash -eq $kqHash -and $memo.Sets.Count -gt 0) {
            if ($memo.Sets.ContainsKey([string]$d['Lookup'])) { $prev = $memo.Sets[[string]$d['Lookup']] } else { $prev = @($memo.Sets.Values)[0] }
            $copy = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
            foreach ($k in $prev) { [void]$copy.Add([string]$k) }
            $sets[[string]$d['Lookup']] = @{ Column = [string]$d['Column']; KeySet = $copy }
            Write-Info ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "the lookup {0} is cut to this part of the query: the graph rows of this part can have {1:N0} different key(s) (the same part was asked just before -- its answer is used again)", [string]$d.Lookup, [int]$copy.Count))
            continue
        }
        # the same size check as any request: it records this request's shape for a size refusal, too
        Assert-RAHybridQueryFits -Query $kq -BucketCount $BucketCount
        if (Get-Command -Name Save-RARenderedQuery -ErrorAction SilentlyContinue) { [void](Save-RARenderedQuery -Query $kq -Tag 'lookup-keys') }
        Ensure-GraphAuth -MaxAgeMinutes $ReconnectMaxAgeMinutes
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $resp = Invoke-SIHuntingQueryRest -Query $kq -Token $script:GraphAccessToken -TimeoutSec 900
        $sw.Stop()
        $rows = if ($null -ne $resp -and $null -ne $resp.Results) { @($resp.Results) } else { @() }
        # Advanced hunting answers at most 100,000 rows and does not say when it stopped there. A key list cut short
        # would leave pairs out, so it is treated as a result that is too large: the slice is made smaller.
        if ($rows.Count -ge 100000) { throw ("the key list for the lookup {0} has {1} rows or more -- it exceeded the allowed result size for one answer" -f $d.Lookup, $rows.Count) }
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($r in $rows) {
            $v = $null
            if ($null -ne $r.AdditionalProperties) { $v = $r.AdditionalProperties['__siNeeded'] }
            elseif ($r.PSObject.Properties['__siNeeded']) { $v = $r.__siNeeded }
            if ($null -ne $v -and -not [string]::IsNullOrEmpty([string]$v)) { [void]$set.Add([string]$v) }
        }
        $sets[[string]$d['Lookup']] = @{ Column = [string]$d['Column']; KeySet = $set }
        Write-Info ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "the lookup {0} is cut to this part of the query: the graph rows of this part can have {1:N0} different key(s) (asked in {2:F1}s)", [string]$d.Lookup, [int]$set.Count, [double]$sw.Elapsed.TotalSeconds))
        # remembered for the text asked (one text only: a different text replaces it)
        if ($null -eq $script:_RALookupKeyAnswerMemo -or [string]$script:_RALookupKeyAnswerMemo.Hash -ne $kqHash) { $script:_RALookupKeyAnswerMemo = @{ Hash = $kqHash; Sets = @{} } }
        $keep = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($k in $set) { [void]$keep.Add([string]$k) }
        $script:_RALookupKeyAnswerMemo.Sets[[string]$d['Lookup']] = $keep
    }
    $script:_RALookupNeededKeySets = $sets
}

function Get-RALookupKeyQueryHash {
    <# PURE. A short fingerprint of one key query's full text (SHA-256, hex): what makes two asks the same question. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))) -replace '-', '') }
    finally { $sha.Dispose() }
}

function Clear-RALookupKeyAnswerMemo {
    <# Forgets the remembered key answer: the next ask of any part goes to advanced hunting again. #>
    $script:_RALookupKeyAnswerMemo = $null
}

function Get-RALookupRowsForKeys {
    <# The rows of a lookup whose key column has one of the given keys. The rows are indexed by that column once
       per lookup and run, so a slice costs its own keys, not the whole lookup. #>
    param([Parameter(Mandatory)][string]$CacheKey, [AllowNull()][AllowEmptyCollection()][object[]]$AllRows, [Parameter(Mandatory)][string]$Column, [AllowNull()][AllowEmptyCollection()]$Keys)
    if (-not $script:_HybridKeyIndexCache) { $script:_HybridKeyIndexCache = @{} }
    $ik = $CacheKey + '::' + $Column
    if (-not $script:_HybridKeyIndexCache.ContainsKey($ik)) {
        $idx = New-Object 'System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[object]]' ([System.StringComparer]::Ordinal)
        foreach ($row in @($AllRows)) {
            # #711: plain member access (a missing column reads as ''), no $row.PSObject per row
            $k = [string]$row.$Column
            if (-not $idx.ContainsKey($k)) { $idx[$k] = New-Object 'System.Collections.Generic.List[object]' }
            $idx[$k].Add($row)
        }
        $script:_HybridKeyIndexCache[$ik] = $idx
    }
    $idx = $script:_HybridKeyIndexCache[$ik]
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Keys) { foreach ($k in $Keys) { if ($idx.ContainsKey([string]$k)) { $out.AddRange($idx[[string]$k]) } } }
    return , $out.ToArray()
}

function Resolve-ProfileCLLetBlocks {
    <# HYBRID CL-snapshot inlining. When a query references both
       SI_*_Profile_CL AND ExposureGraph*, the data-lake API is the only surface
       that sees both, but it doesn't accept SPN auth (Microsoft documented gap).
       Workaround: replace each `let <var> = SI_*_Profile_CL | ... ;` block with
       an inline `let <var> = datatable(...) [...];` literal pre-fetched from LA
       (where SPN works), then send the modified query through AH-via-Graph
       (where EG resolves natively). Same KQL semantics, different transport.

       2026-05-02: scoped pre-fetch attempt reverted -- regex-based KQL splitting
       produced bad discovery queries on real reports (zero IDs / syntax errors).
       Restoring the simple full-snapshot fetch; the proper fix is the 2-phase
       post-process model (run pure-EG query, augment with cmdb in PowerShell). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        # v2.2.323 -- CL-snapshot bucketing. When both are passed AND the
        # detected let-binding count == 1 (single-domain report), the inline
        # datatable is filtered to rows whose SHA256-bucket assignment matches
        # $BucketIndex. Each bucket query then carries ~1/N of the snapshot
        # instead of the full payload, making bucketing genuinely effective
        # for tenants whose CL snapshot blew the AH 1MB nginx cap. Skipped
        # for multi-let-binding (cross-domain Attack_Paths) reports because
        # bucket-key alignment across multiple CL sources isn't trivially
        # solvable -- those fall back to the existing full-inline path.
        [int]$BucketCount = 0,
        [int]$BucketIndex = 0
    )
    # What THIS call inlined, lookup by lookup, and whether each was split per slice or copied whole
    # (Assert-RAHybridQueryFits reads it). Cleared first, so a query without lookups leaves nothing behind.
    # (A plain array on purpose: wrapping a generic list in @() throws "Argument types do not match".)
    $script:_RAHybridLookups = @()

    # Strip strings/comments first to avoid false-positive `;` inside literals.
    $stripped = $Query
    $stripped = [regex]::Replace($stripped, '"[^"\r\n]*"', '""')
    $stripped = [regex]::Replace($stripped, "'[^'\r\n]*'", "''")
    $stripped = [regex]::Replace($stripped, '//[^\r\n]*', '')

    # let-binding pattern: `let <var> = ... SI_*_Profile_CL ... ;` -- multiline,
    # non-greedy, terminates at first `;` (already safe vs. string literals).
    # #147 -- also a single-word SI table (SI_AzureRecommendation_CL). Such a binding is a LOOKUP the query
    # reduces in its own body (e.g. to one key column); run here, only that result is inlined. Left to the
    # whole-table shadow below, it was collapsed "latest row per PrimaryEntityId" and every column inlined --
    # and when that fetch failed the query went to advanced hunting as-is, where the table does not exist,
    # so `union isfuzzy` quietly made the lookup EMPTY and the de-duplication it feeds removed nothing.
    $letRx = '(?ms)\blet\s+(?<var>\w+)\s*=\s*(?<body>[^;]*?\bSI_[A-Za-z]+(?:_Profile)?_CL\b[^;]*?);'
    $matches2 = [regex]::Matches($stripped, $letRx)
    if ($matches2.Count -eq 0) { return $Query }

    # v2.2.323 -- CL-snapshot bucketing required exactly ONE let-binding because
    # the original design relied on EG-side bucket-filter alignment with the let's
    # join key (impossible to align ONE EG filter with multiple lets' different keys).
    # v2.2.335 lifts that restriction: with v2.2.334's EG-bucket-skip mechanism the
    # EG side stops trying to filter when the CL key is cross-domain -- so each
    # let-binding can be bucketed INDEPENDENTLY (each rows-cache filtered to its
    # own bucket), EG sees all rows, joins stay lossless. Multi-let cross-domain
    # reports (Attack_Paths_*_Device_with_high_sev with _SourceCmdb + _TargetCmdb,
    # _Github_to_Azure with _TargetCmdb only, etc.) all get bucketed now.
    $clBucketingActive = ($BucketCount -gt 1)

    $modified = $Query
    # v2.2.364 -- accumulate inline bytes across all let-blocks processed in this
    # call so we can derive the surrounding-KQL body overhead (= modified.Length
    # - totalInlineBytes) at the end. The escalation formula uses this to budget
    # the FULL query body under nginx's 1MB cap, not just the inline portion --
    # v2.2.362 targeted 90% of 1MB for inline alone but the full body (inline +
    # surrounding KQL + URL params) still 413'd at 91 buckets / 931KB inline.
    $_thisCallInlineBytes = 0

    # 🔑 #401 -- PRE-PASS: READ EVERY BINDING, THEN DECIDE HOW TO INLINE ANY OF THEM.
    # With the EG-side bucket filter OFF, every bucket query processes EVERY Exposure-Graph row. A CL lookup
    # that is still PARTITIONED then holds a given key in ONE bucket only, so a `leftouter` join emits the
    # same EG row enriched in that bucket and UNenriched in all the others -- and the two versions differ in
    # the very columns the de-duplication keys on. MEASURED live (rc6, 2026-10-07):
    # Attack_Paths_Detailed_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure,
    # 8 buckets, `_SourceCmdb` 17 rows split 2/1/3/2/1/4/1/3 -- a device's path came back once with its SI
    # asset id (AssetType Endpoint, from the one bucket holding its profile row) and once with its Entra
    # device id (AssetType Device, from the other seven): 189 rows where 147 are real, and which device was
    # doubled changed from run to run. The suppression's "lossless" claim only ever held for ONE
    # inner-joined binding.
    # So when the filter is off the lookups are REPLICATED -- every bucket gets every row of every binding
    # -- which makes each bucket query the complete, unbucketed query; the bucket loop then keeps the first
    # complete bucket and skips the rest ($script:_RACrossDomainReplicated). The decision needs ALL
    # bindings: the flag is raised by whichever binding carries a cross-domain key (here `_TargetCmdb`,
    # processed BEFORE `_SourceCmdb`), and a binding inlined before the flag went up was partitioned.
    # 🪤 Replication is bounded by the request body: every bucket carries the full snapshots, and a larger
    # bucket count can no longer shrink them. When they do not fit, the old partitioned path runs and says so.
    $replicateCrossDomain = $false
    if ($clBucketingActive) {
        $_ppQuery = $Query
        $_ppBindings = New-Object System.Collections.Generic.List[object]
        foreach ($_ppm in $matches2) {
            $_ppMatch = [regex]::Match($_ppQuery, $letRx)
            if (-not $_ppMatch.Success) { break }
            $_ppVar  = $_ppMatch.Groups['var'].Value
            $_ppBody = $_ppMatch.Groups['body'].Value
            $_ppQuery = $_ppQuery.Replace($_ppMatch.Value, ('let {0} = __si_prepass__;' -f $_ppVar))
            $_ppRows = Get-SIHybridLetRows -VarName $_ppVar -BodyKql $_ppBody -WorkspaceResourceId $WorkspaceResourceId
            Set-SIHybridCrossDomainFlag -VarName $_ppVar -AllRows @($_ppRows.Rows) -ClBucketingActive $true
            $_ppBindings.Add(@{ Var = $_ppVar; Body = $_ppBody; CacheKey = $_ppRows.CacheKey; Rows = @($_ppRows.Rows); ColumnTypes = $_ppRows.ColumnTypes })
        }
        if ([bool]$script:_SkipEGBucketForCrossDomain) {
            if (-not $script:_HybridSnapshotCache) { $script:_HybridSnapshotCache = @{} }
            # Same budget the AutoBucket escalation sizes buckets to: 75% of the 1MB request-body cap, less
            # the measured surrounding-KQL overhead.
            $_budget = [int][Math]::Max(64KB, [int](1MB * 0.75) - [int]$script:_LastHybridQueryBodyOverheadBytes)
            # #730: the whole texts are built only as far as the budget -- a tenant-sized lookup that cannot be replicated
            # is no longer turned into one tenant-sized text (and kept) just to measure that it does not fit. The decision
            # is the same: the bindings are replicated exactly when their whole texts together fit the budget.
            $_fullBytes = 0; $_over = $false
            foreach ($_pb in $_ppBindings) {
                if (-not $script:_HybridSnapshotCache.ContainsKey($_pb.CacheKey)) {
                    $_whole = Convert-RowsToKqlDatatable -LetVarName $_pb.Var -Rows @($_pb.Rows) -BodyKqlForSchemaHint $_pb.Body -ColumnTypes $_pb.ColumnTypes -MaxChars ([long][Math]::Max(1, $_budget - $_fullBytes))
                    if ($null -eq $_whole) { $_over = $true; break }
                    $script:_HybridSnapshotCache[$_pb.CacheKey] = $_whole
                    $_whole = $null
                }
                $_fullBytes += [int]$script:_HybridSnapshotCache[$_pb.CacheKey].Length
                if ($_fullBytes -gt $_budget) { $_over = $true; break }
            }
            if (-not $_over -and $_fullBytes -le $_budget) {
                $replicateCrossDomain = $true
                Write-Info ("[hybrid] EG-side bucket filter is off -- replicating all {0} CL binding(s) ({1} bytes) into the query instead of splitting them per bucket, so every row resolves to the same asset in every bucket " -f $_ppBindings.Count, $_fullBytes)
            } else {
                Write-Warn2 ("[hybrid] EG-side bucket filter is off and the full CL bindings (more than {0} bytes) exceed the request budget ({0} bytes) -- splitting them per bucket; a left-joined lookup can then list one row twice, enriched and not " -f $_budget)
            }
        }
    }
    $script:_RACrossDomainReplicated = $replicateCrossDomain
    # 659fb78a (decide before building): a lookup the report declares (LookupNeededKeys) that would go WHOLE into a part is
    # first measured with the #730 bounded build -- over the planning budget, its whole text is never built: a typed empty
    # placeholder stands in and the lookup is named in $script:_RALookupCutWanted, so Invoke-GraphHuntingQuery turns its cut on
    # and builds the part again with only the rows its keys can match. A placeholder is never sent (it throws there).
    if ($null -eq $script:_RALookupCutWanted) { $script:_RALookupCutWanted = @{} }
    $_declared = @{}
    if (Get-Command -Name Get-RALookupNeededKeyDeclarations -ErrorAction SilentlyContinue) {
        foreach ($_dd in @(Get-RALookupNeededKeyDeclarations -Query $Query)) { if ($null -ne $_dd) { $_declared[[string]$_dd['Lookup']] = $true } }
    }
    $_budgetWhole = [long](Get-RAHuntingPlanningBudgetBytes)

    foreach ($m in $matches2) {
        $varName = $m.Groups['var'].Value
        # Re-extract body from the ORIGINAL query (string-stripped version has placeholders)
        $origMatch = [regex]::Match($modified, $letRx)
        if (-not $origMatch.Success) { continue }
        $bodyKql = $origMatch.Groups['body'].Value
        $fullBlock = $origMatch.Value

        $_letRows = Get-SIHybridLetRows -VarName $varName -BodyKql $bodyKql -WorkspaceResourceId $WorkspaceResourceId
        $cacheKey = $_letRows.CacheKey
        $allRows  = $_letRows.Rows
        $colTypes = $_letRows.ColumnTypes
        # Copied whole unless the branch below splits it per slice on a key.
        $_lookupWhole = $true
        $_lookupRows  = @($allRows).Count
        $_ph = @{ On = $false }
        # the declared lookup, whole: built only when it is within the planning budget, else a typed empty placeholder
        $_buildDeclaredWhole = {
            param([object[]]$R)
            $t = Convert-RowsToKqlDatatable -LetVarName $varName -Rows $R -BodyKqlForSchemaHint $bodyKql -TypeReferenceRows @($allRows) -ColumnTypes $colTypes -MaxChars $_budgetWhole
            if ($null -ne $t) { return $t }
            $script:_RALookupCutWanted[$varName] = @($allRows).Count
            $_ph.On = $true
            Write-Info ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "[hybrid] '{0}': {1:N0} row(s) would go whole into this part and are over the request budget -- not built; the part is first asked which of its keys it can match", $varName, @($allRows).Count))
            Convert-RowsToKqlDatatable -LetVarName $varName -Rows @() -BodyKqlForSchemaHint $bodyKql -TypeReferenceRows @($allRows) -ColumnTypes $colTypes
        }

        # A lookup without a per-asset key that did not fit whole: only the rows this slice's graph rows can match
        # (Invoke-RALookupKeyDiscovery asked which keys those are). Types still come from the whole lookup, so every
        # slice agrees on the schema, an empty one included.
        $_needed = if ($script:_RALookupNeededKeySets -and $script:_RALookupNeededKeySets.ContainsKey($varName)) { $script:_RALookupNeededKeySets[$varName] } else { $null }
        if ($null -ne $_needed) {
            # assigned as it is, NOT wrapped in @(): the function returns the rows as ONE array, and @() around that
            # is an array holding the array -- one "row" that is not a row
            [object[]]$bucketRows = Get-RALookupRowsForKeys -CacheKey $cacheKey -AllRows @($allRows) -Column ([string]$_needed['Column']) -Keys $_needed['KeySet']
            if ($null -eq $bucketRows) { [object[]]$bucketRows = @() }
            $datatableLet = Convert-RowsToKqlDatatable -LetVarName $varName -Rows $bucketRows -BodyKqlForSchemaHint $bodyKql -TypeReferenceRows @($allRows) -ColumnTypes $colTypes
            $_lookupWhole = $false
            $_lookupRows  = $bucketRows.Count
            # (not while the key query is built: the lookup is empty there on purpose -- Invoke-RALookupKeyDiscovery)
            if (-not [bool]$script:_RALookupKeyQueryBuilding) {
                Write-Info ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "the lookup {0}: {1:N0} of its {2:N0} row(s) can match this part of the query and are sent with it ({3})", [string]$varName, [int]$bucketRows.Count, [int]@($allRows).Count, [string](Format-RAByteSize -Bytes ([long]$datatableLet.Length))))
            }
        }
        # #401 -- replicated (EG-side filter off): the full snapshot, exactly as an unbucketed query inlines it.
        elseif ($clBucketingActive -and -not $replicateCrossDomain) {
            # v2.2.360 -- pre-group the snapshot ONCE per (cacheKey, BucketCount).
            # Pre-this-fix every bucket iteration rescanned $allRows and called
            # SHA256 twice per row (Get-SICLBucketKey + Get-SISha256Bucket) --
            # O(N x BucketCount). At 500K rows / 1000 buckets that's ~1B SHA256
            # calls and ~211s of pure local overhead per bucket. With the cache,
            # the first bucket pays one O(N) hash pass and all subsequent buckets
            # do an O(1) dictionary lookup.
            $groupCacheKey = '{0}::{1}' -f $cacheKey, $BucketCount
            if (-not $script:_HybridBucketGroupsCache.ContainsKey($groupCacheKey)) {
                $_groups = New-Object 'System.Collections.Generic.Dictionary[int, System.Collections.Generic.List[object]]'
                for ($_b = 0; $_b -lt $BucketCount; $_b++) {
                    $_groups[$_b] = New-Object 'System.Collections.Generic.List[object]'
                }
                $_t0 = [datetime]::UtcNow
                # v2.2.458 (RA-1) -- count the rows Get-SICLBucketKey cannot key. A binding whose join
                # column is not in that function's recognised list returns '' for EVERY row, and ''
                # hashes to bucket 0, so the WHOLE snapshot lands in bucket 0 and every other bucket
                # receives an EMPTY lookup. A leftouter against an empty table still returns each left
                # row, so this is silent: the report simply reports no id for anything processed in a
                # bucket other than the first. Measured on '_apByName': 429/429 rows in bucket 1 and
                # 0/429 in bucket 2, and four Key Vaults that ARE in SI_Azure_Profile_CL came back with
                # no id purely because their EG rows were processed in bucket 2.
                $_unkeyed = 0
                foreach ($_row in $allRows) {
                    $_k = Get-SICLBucketKey -Row $_row
                    if ([string]::IsNullOrWhiteSpace($_k)) { $_unkeyed++ }
                    $_idx = Get-SISha256Bucket -Key $_k -BucketCount $BucketCount
                    $_groups[$_idx].Add($_row)
                }
                # 🔑 UNKEYABLE => REPLICATE, don't partition. If no row can be keyed, partitioning is
                # not merely useless, it is lossy. Give every bucket the FULL snapshot instead: the
                # lookup is then complete in each bucket while the EG-side bucket filter stays ACTIVE,
                # so each left row is still processed exactly once.
                # 🪤 THIS IS THE SAFE HALF OF A FIX THAT WAS TRIED THE OTHER WAY ROUND AND REVERTED.
                # Registering the key in $crossDomainCols instead SUPPRESSES the EG-side filter, and
                # that duplicates rows whenever a report has more than one CL binding -- measured,
                # 598 rows -> 716. Replicating the lookup cannot duplicate anything, because it does
                # not change which left rows a bucket sees.
                if ($_unkeyed -eq @($allRows).Count -and @($allRows).Count -gt 0 -and $BucketCount -gt 1) {
                    for ($_b = 0; $_b -lt $BucketCount; $_b++) {
                        $_groups[$_b] = New-Object 'System.Collections.Generic.List[object]'
                        $_groups[$_b].AddRange([object[]]@($allRows))
                    }
                    Write-Info ("[hybrid] '{0}' has no bucketable key -- replicating all {1} row(s) into each of {2} bucket(s) so no bucket sees an empty lookup (EG-side bucket filter stays active, so rows cannot duplicate)" -f $varName, @($allRows).Count, $BucketCount)
                    if (-not $script:_HybridBucketGroupsWhole) { $script:_HybridBucketGroupsWhole = @{} }
                    $script:_HybridBucketGroupsWhole[$groupCacheKey] = $true
                }
                $script:_HybridBucketGroupsCache[$groupCacheKey] = $_groups
                Write-Info ("[hybrid] '{0}' pre-grouped {1} rows into {2} buckets in {3:N1}s (one-time O(N) hash pass; subsequent buckets are O(1) lookups)" -f $varName, @($allRows).Count, $BucketCount, ([datetime]::UtcNow - $_t0).TotalSeconds)
            }
            $bucketRows = @($script:_HybridBucketGroupsCache[$groupCacheKey][$BucketIndex])
            $_lookupWhole = [bool]($script:_HybridBucketGroupsWhole -and $script:_HybridBucketGroupsWhole.ContainsKey($groupCacheKey))
            $_lookupRows  = $bucketRows.Count
            if ($_lookupWhole -and $_declared.ContainsKey($varName)) { $datatableLet = & $_buildDeclaredWhole $bucketRows }
            else { $datatableLet = Convert-RowsToKqlDatatable -LetVarName $varName -Rows $bucketRows -BodyKqlForSchemaHint $bodyKql -TypeReferenceRows @($allRows) -ColumnTypes $colTypes }
            if (-not $_ph.On) { Write-Info ("[hybrid] '{0}' bucket {1}/{2}: {3}/{4} row(s) inlined ({5} bytes; CL-bucketed via SHA256)" -f $varName, ($BucketIndex + 1), $BucketCount, $bucketRows.Count, $allRows.Count, $datatableLet.Length) }
            # v2.2.361 -- record measured bytes-per-row so the AutoBucket escalation
            # handler can size buckets to ~70% of the nginx 1MB cap empirically,
            # instead of using the hardcoded 500 rows/bucket which was 8-10x too
            # conservative for typical ~170 bytes/row CL payloads.
            # v2.2.362 -- track the MAX bytes-per-row seen during this report's
            # bucket inlines (not just the most recent). Reasoning: row width
            # varies per bucket because CL Profile rows have variable-length
            # string columns; under-estimating bytes-per-row leads to oversized
            # buckets and a wasted 413'd XDR query. Max-tracking biases toward
            # safer-smaller buckets at the cost of slightly more buckets than
            # theoretically optimal -- a worthwhile tradeoff (avoiding a single
            # 413 round-trip is far more expensive than one extra bucket).
            if ($bucketRows.Count -gt 0 -and -not $_ph.On) {
                $_measured = [double]$datatableLet.Length / [double]$bucketRows.Count
                if ($_measured -gt $script:_LastHybridBytesPerRow) {
                    $script:_LastHybridBytesPerRow = $_measured
                }
            }
        }
        elseif ($script:_HybridSnapshotCache.ContainsKey($cacheKey)) {
            $datatableLet = $script:_HybridSnapshotCache[$cacheKey]
            Write-Info ("[hybrid] '{0}' snapshot reused from cache ({1} bytes)" -f $varName, $datatableLet.Length)
        }
        elseif ($_declared.ContainsKey($varName)) {
            # 659fb78a: the declared lookup in an unsliced query (or replicated): measured first, never built whole over the budget
            $datatableLet = & $_buildDeclaredWhole @($allRows)
            if (-not $_ph.On) {
                Write-Info ("[hybrid] '{0}' snapshot: {1} row(s) inlined as datatable ({2} bytes)" -f $varName, @($allRows).Count, $datatableLet.Length)
                $script:_HybridSnapshotCache[$cacheKey] = $datatableLet
            }
        }
        else {
            $datatableLet = Convert-RowsToKqlDatatable -LetVarName $varName -Rows @($allRows) -BodyKqlForSchemaHint $bodyKql -ColumnTypes $colTypes
            Write-Info ("[hybrid] '{0}' snapshot: {1} row(s) inlined as datatable ({2} bytes)" -f $varName, @($allRows).Count, $datatableLet.Length)
            $script:_HybridSnapshotCache[$cacheKey] = $datatableLet
        }
        $modified = $modified.Replace($fullBlock, $datatableLet)
        $_thisCallInlineBytes += [int]$datatableLet.Length
        $script:_RAHybridLookups += , @{ Name = $varName; Rows = [int]$_lookupRows; WireBytes = [long](Get-RARequestWireBytes -Text $datatableLet); Whole = [bool]$_lookupWhole; TotalRows = [int]@($allRows).Count; Placeholder = [bool]$_ph.On }
    }
    # v2.2.364 -- record the SURROUNDING-KQL body overhead seen by this call so
    # the AutoBucket escalation formula can budget the FULL request body under
    # nginx's 1MB cap. Track MAX for the same reason bytesPerRow tracks max:
    # under-estimating overhead leads to oversized buckets and a 413'd query.
    if ($_thisCallInlineBytes -gt 0) {
        $_overhead = [int]$modified.Length - $_thisCallInlineBytes
        if ($_overhead -gt 0 -and $_overhead -gt [int]$script:_LastHybridQueryBodyOverheadBytes) {
            $script:_LastHybridQueryBodyOverheadBytes = [int]$_overhead
        }
    }
    # AUDIT #24 futility signal. Unlike the overhead tracker above this is the CURRENT
    # call's inline size, NOT a max -- the AutoBucket probe reads it after a rung fails to
    # tell a PAYLOAD-BOUND report (large inline body; splitting is the right answer) from
    # an EG-BOUND one (body already tiny, yet still hitting the 900s ceiling; splitting
    # cannot help). Assigned unconditionally so a 0 means "no inline payload this call"
    # rather than a stale value from the previous report.
    $script:_LastHybridInlineBytes = [int]$_thisCallInlineBytes
    return $modified
}

function Resolve-ProfileAugmentPlan {
    <# 2026-05-02 -- 2-phase post-augmentation. Detects the canonical CL-enrichment
       pattern in a query:

           let <var> = SI_*_Profile_CL | ... | project <Projection> | where isnotempty(<RightKey>);
           // ... pure EG / per-row pipeline ...
           | join kind=<Kind> (<var>) on $left.<LeftKey> == $right.<RightKey>
           | extend <newCol> = <var-projected-col>, <newCol2> = <var-projected-col2>, ...

       When the post-extend alias columns are NOT referenced by a downstream
       `summarize ... by ...` clause (typical for Detailed reports â€” and Attack_Paths
       Detailed in particular), the join can be removed from the query entirely:
       the rows still have the alias columns, but populated post-hoc by Invoke-
       CmdbAugment from a single LA fetch + in-memory hashtable.

       Returns @{
           Query = <modified query, let+join+extend stripped>
           Plans = [@{ Var; TableName; ProjectionKql; LeftKey; RightKey;
                       ColumnAliases = @{ newCol = sourceCol; ... } }, ...]
       }

       If no augmentable plan was detected, returns @{ Query = $Query; Plans = @() }
       and the caller should keep the existing inline-datatable path. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Query)

    $stripped = $Query
    $stripped = [regex]::Replace($stripped, '"[^"\r\n]*"', '""')
    $stripped = [regex]::Replace($stripped, "'[^'\r\n]*'", "''")
    $stripped = [regex]::Replace($stripped, '//[^\r\n]*', '')

    # 1. Find every `let <var> = SI_*_Profile_CL | ... | project <body> | where <RightKey-test>;` let block.
    # v2.2.332 -- accept THREE shapes for the terminating where-clause that
    # filters out empty join keys:
    #   bare-isnotempty: `where isnotempty(EpJoinKey)`
    #   defensive:       `where isnotempty(tostring(column_ifexists("Target_AzureResourceId_Guid", "")))`
    #   inequality:      `where Target_AzureResourceId_Guid != ""`
    # The Attack_Paths cross-domain reports (Github_to_Azure, Device_with_high_sev_*,
    # Identity_Group_Membership, Data_Sensitivity, Credential_Based_Lateral) all
    # use the inequality form. Without matching it, those reports skip 2-phase
    # and fall back to inline-datatable, exploding the body on 15K-row tenants.
    # 🔴 THE SEGMENT BEFORE `| project` IS GREEDY (`[^;]*`), NOT LAZY -- audit #104, and it is the whole
    # fix. Lazy anchored the capture on the FIRST `| project` after the table name. That is the wrong
    # one whenever the let-block contains a NESTED `| join kind=leftouter ( ... )` -- which the v3
    # asset-identity backfill authors into the catalog to carry `_v3Pk` / `_v3Name` / `_v3Id`. The first
    # project then belongs to the INNER subquery, and `<proj>` ran straight past that subquery's closing
    # bracket, so the fetch built at step 6 contained a bare
    #     ) on $left.PrimaryEntityId == $right._v3Pk
    # with nothing that opened it. Log Analytics answered `SYN0002 -- could not be parsed at ')'`.
    # Greedy takes the LAST project before the terminating where-clause, which is the OUTER one -- the
    # projection the YAML author actually wrote for this let-block.
    #
    # 🪤 THE FAILURE WAS ALL BUT INVISIBLE, WHICH IS WHY IT SURVIVED. `Invoke-ProfileAugment` catches the
    # error, warns once, and carries on with an EMPTY lookup -- and that lookup is CACHED per
    # (TableName, RightKey). MEASURED on the 2026-09-02 chain: the Detailed grain built **20 plans, all
    # sharing SI_Azure_Profile_CL | Target_AzureResourceId_Guid**, so ONE failed fetch emptied every one
    # of them while the log said `CL fetch failed` exactly once. Every augment line read `0 hits`.
    # The ColumnFillGuard passed on the same run, because the columns were already empty the run before:
    # it detects a REGRESSION, and a defect stable across runs is indistinguishable from steady state.
    #
    # 🔬 VALIDATED AGAINST THE REAL INPUT, and getting that input is most of the story. The query handed
    # to this function is not persisted anywhere -- `staging/risk-analysis/ra-rendered-*.kql` is written
    # AFTER the legacy path inlines the CL snapshot as a `datatable(...)`, i.e. it is the OUTPUT of the
    # decision below, never its input. MEASURED: the unmodified resolver returns **0 plans on all 79** of
    # those files, so they cannot serve as a control and any fix "verified" against them is verified
    # against nothing. `$global:SI_RA_DumpAugmentInput` (RA-GraphHunting.ps1) captures the real string.
    # Control on that capture: lazy yields 1 plan whose fetch carries the orphaned `) on $left`; greedy
    # yields 1 plan whose fetch opens with the correct outer `| project Target_AzureResourceId_Guid ...`.
    $letRx = '(?ms)\blet\s+(?<var>\w+)\s*=\s*(?<bodyAll>[^;]*?\bSI_(?<table>[A-Za-z]+_Profile)_CL\b[^;]*\|\s*project\s+(?<proj>[^;]*?)\|\s*where\s+(?:isnotempty\(\s*(?:tostring\(\s*column_ifexists\(\s*"(?<rkey>\w+)"\s*,[^)]*\)\s*\)|(?<rkey2>\w+))\s*\)|(?<rkey3>\w+)\s*!=\s*"")\s*);'

    $plans = New-Object System.Collections.Generic.List[hashtable]
    $modified = $Query
    $cumulativeMatches = [regex]::Matches($modified, $letRx)
    if ($cumulativeMatches.Count -eq 0) { return @{ Query = $Query; Plans = @() } }

    foreach ($m in $cumulativeMatches) {
        $varName  = $m.Groups['var'].Value
        $tableTag = $m.Groups['table'].Value      # e.g. "Azure_Profile" -> SI_Azure_Profile_CL
        $tableNm  = "SI_" + $tableTag + "_CL"
        # v2.2.332 -- rkey can be captured by any of three alternatives in the where-clause:
        #   rkey  = column_ifexists("X", ...) inside isnotempty(tostring(...))
        #   rkey2 = bare identifier inside isnotempty(...)
        #   rkey3 = bare identifier on the LHS of `!= ""`
        # The three are mutually exclusive at match time; whichever fired holds the column name.
        $rkey     = if ($m.Groups['rkey'].Success -and $m.Groups['rkey'].Value) { $m.Groups['rkey'].Value }
                    elseif ($m.Groups['rkey2'].Success -and $m.Groups['rkey2'].Value) { $m.Groups['rkey2'].Value }
                    else { $m.Groups['rkey3'].Value }
        # Re-extract projection body from the original query (avoids placeholder issues from the strip pass).
        $origMatch = [regex]::Match($modified, $letRx)
        if (-not $origMatch.Success) { continue }
        $projBody = $origMatch.Groups['proj'].Value
        $fullLetBlock = $origMatch.Value

        # 2. Find the corresponding `| join kind=<kind> (<var>) on $left.<lk> == $right.<rk>` line (operands either order).
        $joinRx = ('(?ms)\|\s*join\s+(?:kind\s*=\s*\w+\s+)?\(\s*' + [regex]::Escape($varName) + '\s*\)\s+on\s+(?:\$left\.(?<lk>\w+)\s*==\s*\$right\.' + [regex]::Escape($rkey) + '|\$right\.' + [regex]::Escape($rkey) + '\s*==\s*\$left\.(?<lk2>\w+))')
        $jm = [regex]::Match($modified, $joinRx)
        if (-not $jm.Success) { continue }
        $leftKey = if ($jm.Groups['lk'].Success -and $jm.Groups['lk'].Value) { $jm.Groups['lk'].Value } else { $jm.Groups['lk2'].Value }
        $fullJoinLine = $jm.Value

        # 3. Find the post-join `| extend <newCol> = <oldCol>, ...` block IMMEDIATELY after the join.
        # \A anchor + optional comment lines means the extend MUST be the first KQL operator after
        # the join (intervening `| where ...` or any non-comment pipe op disqualifies the match).
        # Without this anchor we'd false-match downstream extends -- like the engine-substituted
        # weighted-factors block `| extend RiskFactor_Weight = RiskScore_Weight_Factor` which has
        # the same `id = id` shape but is NOT a let-block alias rename.
        # Additionally, every alias's RHS must reference a column actually projected by the let-block;
        # otherwise the match isn't a join-projection rename. Both gates are needed because the engine
        # substitutes the weighted-factors block AFTER YAML load but BEFORE this regex runs.
        $afterJoinIdx = $modified.IndexOf($fullJoinLine) + $fullJoinLine.Length
        $tail = $modified.Substring($afterJoinIdx)
        $extendRx = '(?ms)\A(?:\s*//[^\r\n]*[\r\n]+)*\s*\|\s*extend(?<body>(?:\s+[A-Za-z_]\w*\s*=\s*[A-Za-z_]\w*\s*,?)+)\s*(?=\||\s*$)'
        $em = [regex]::Match($tail, $extendRx)
        $columnAliases = @{}
        $fullExtendBlock = ''
        if ($em.Success) {
            # Build the set of column names the let-block actually projects (LHS of each `<name> = <expr>` in $projBody).
            $projectedCols = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($pm in [regex]::Matches($projBody, '(?ms)([A-Za-z_]\w*)\s*=')) {
                [void]$projectedCols.Add($pm.Groups[1].Value)
            }
            $body = $em.Groups['body'].Value
            $candidates = @{}
            $allRhsValid = $true
            foreach ($am in [regex]::Matches($body, '([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)')) {
                $rhs = $am.Groups[2].Value
                if (-not $projectedCols.Contains($rhs)) { $allRhsValid = $false; break }
                $candidates[$am.Groups[1].Value] = $rhs
            }
            if ($allRhsValid -and $candidates.Count -gt 0) {
                $fullExtendBlock = $em.Value
                $columnAliases = $candidates
            }
        }
        if ($columnAliases.Count -eq 0) { continue }

        # 4. SAFETY GATE: if any of the new cmdb columns are used in a downstream `summarize ... by ...`
        # clause, we CAN'T strip them -- the bucketing depends on having them in the data BEFORE summarize.
        # In that case skip this plan -- the inline-datatable path will handle it.
        $aliasNames = @($columnAliases.Keys)
        $summRx = '(?ms)\|\s*summarize\b[^|]*\bby\b[^|]*'
        $cmdbInSummarize = $false
        foreach ($sm in [regex]::Matches($stripped, $summRx)) {
            $byClause = $sm.Value
            foreach ($ali in $aliasNames) {
                if ($byClause -match ('\b' + [regex]::Escape($ali) + '\b')) { $cmdbInSummarize = $true; break }
            }
            if ($cmdbInSummarize) { break }
        }
        if ($cmdbInSummarize) {
            Write-Info ("[2phase] '{0}' SKIPPED -- alias cols ({1}) used in a downstream summarize-by; falling back to inline-datatable hybrid path" -f $varName, ($aliasNames -join ','))
            continue
        }

        # 5. Strip let-block + join-line + post-extend block from the query.
        # Replace the join with a PLACEHOLDER `| extend alias="", ...` line so
        # downstream `| project ... cmdbId, cmdbName, ...` references resolve
        # in the AH query. The post-AH augment then OVERWRITES these placeholder
        # values with the real CMDB lookups.
        $placeholderExtend = '| extend ' + (($aliasNames | ForEach-Object { '{0}=""' -f $_ }) -join ', ')
        $modified = $modified.Replace($fullLetBlock, '')
        $modified = $modified.Replace($fullJoinLine, $placeholderExtend)
        if ($fullExtendBlock) { $modified = $modified.Replace($fullExtendBlock, '') }

        # 6. Build the projection KQL the augment function will run against LA to fetch the CL snapshot.
        # Use the same project body the YAML author wrote, plus the raw RightKey if not in the alias set.
        $projectionKql = ("{0}`n| where TimeGenerated > ago(8d)`n| summarize arg_max(CollectionTime, *) by PrimaryEntityId`n| project {1}`n| where isnotempty({2})" -f $tableNm, $projBody.Trim(), $rkey)
        # #212: THIS install's rows before the arg_max (engine/_shared/SI-InstallRows.ps1)
        if (Get-Command -Name Add-SIInstallRowsFilter -ErrorAction SilentlyContinue) { $projectionKql = Add-SIInstallRowsFilter -Query $projectionKql -SolutionVersion $global:RA_SolutionVersion -LookbackDays 8 }

        $plans.Add(@{
            Var            = $varName
            TableName      = $tableNm
            ProjectionKql  = $projectionKql
            LeftKey        = $leftKey
            RightKey       = $rkey
            ColumnAliases  = $columnAliases
        }) | Out-Null

        Write-Info ("[2phase] '{0}' plan: leftKey={1}, rightKey={2}, alias-cols=[{3}]" -f $varName, $leftKey, $rkey, ($aliasNames -join ','))
    }

    # v2.2.344 -- VERIFY all stripped letvars are no longer referenced anywhere
    # in the modified query. If any plan's letvar still appears (e.g., the report
    # has a SECOND join referencing the same letvar that our regex didn't strip,
    # or a downstream projection that uses the let), the strip is incomplete and
    # AH will 400 with "Failed to resolve table or column expression named '_X'".
    # Abort 2-phase entirely and let the hybrid path handle ALL let-blocks via
    # inline datatable substitution -- which is correct because it replaces the
    # let-block in place rather than removing it, so downstream references resolve.
    # Triggered by Attack_Paths_Detailed_Device_with_high_severity_vulnerabilities_*
    # which has additional `_SourceCmdb` references the augment-plan regex missed.
    foreach ($plan in $plans) {
        $varName = $plan.Var
        if ($modified -match ('\b' + [regex]::Escape($varName) + '\b')) {
            Write-Warn2 ("[2phase] '{0}' SKIPPED -- letvar still referenced after strip (incomplete: report has additional joins/projections beyond the canonical pattern). Falling back to inline-datatable hybrid path for this entire report." -f $varName)
            return @{ Query = $Query; Plans = @() }
        }
    }

    return @{ Query = $modified; Plans = @($plans.ToArray()) }
}

function Invoke-ProfileAugment {
    <# 2026-05-02 -- post-query in-memory augmentation. Given the rows the EG query
       returned + the plans Resolve-ProfileAugmentPlan extracted, fetch each plan's CL
       snapshot from LA once (cached), build a hashtable on the right-side join key,
       and stamp the aliased columns onto every row.

       Performance notes (32-64 GB VM, 100K rows):
         - Hashtable lookup is O(1)
         - Direct Add-Member is slow (~30-60s for 100K) -- AVOIDED
         - We mutate the existing PSCustomObject's NoteProperty values in place
           (or add via .Properties.Add) which is ~5x faster than Add-Member -Force #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()]$Rows,
        [Parameter()][AllowNull()]$Plans,
        [Parameter(Mandatory)][string]$WorkspaceResourceId
    )

    if (-not $Rows -or $Rows.Count -eq 0) { return ,@($Rows) }
    if (-not $Plans -or @($Plans).Count -eq 0) { return ,@($Rows) }
    if (-not $script:_ProfileAugmentLookups) { $script:_ProfileAugmentLookups = @{} }

    foreach ($plan in $Plans) {
        $cacheKey = "{0}|{1}" -f $plan.TableName, $plan.RightKey
        if (-not $script:_ProfileAugmentLookups.ContainsKey($cacheKey)) {
            try {
                $clRows = Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $WorkspaceResourceId -Query $plan.ProjectionKql -What ("the lookup '{0}'" -f $plan.Var)   # #690 (37)
            } catch {
                # #674 FAIL CLOSED: the CI / CMDB values of every row would be empty and the report Complete. Not cached,
                # so the next report reads again. A table that does not exist is passed on as before (no data source).
                $e = ConvertTo-RALookupUnavailableError -What ("the lookup '{0}'" -f $plan.Var) -Err $_
                if ($e) { Write-Err2 ("[2phase] {0}" -f $e.Message); throw $e }
                Write-Warn2 ("[2phase] '{0}' has no table in Log Analytics; its columns stay empty: {1}" -f $plan.Var, $_.Exception.Message)
                $clRows = @()
            }
            $lookup = New-Object 'System.Collections.Generic.Dictionary[string,object]'
            foreach ($r in @($clRows)) {
                if ($null -eq $r) { continue }
                if ($r.PSObject.Properties[$plan.RightKey]) {
                    $k = [string]$r.PSObject.Properties[$plan.RightKey].Value
                    if (-not [string]::IsNullOrWhiteSpace($k) -and -not $lookup.ContainsKey($k)) {
                        $lookup[$k] = $r
                    }
                }
            }
            $script:_ProfileAugmentLookups[$cacheKey] = $lookup
            Write-Info ("[2phase] '{0}' lookup built: {1} CL rows -> hashtable on {2}" -f $plan.Var, @($clRows).Count, $plan.RightKey)
        }
        $lookup = $script:_ProfileAugmentLookups[$cacheKey]

        $hits = 0; $misses = 0
        foreach ($row in $Rows) {
            if ($null -eq $row) { continue }
            $lk = ''
            if ($row.PSObject.Properties[$plan.LeftKey]) { $lk = [string]$row.PSObject.Properties[$plan.LeftKey].Value }
            $clRow = $null
            if (-not [string]::IsNullOrWhiteSpace($lk) -and $lookup.TryGetValue($lk, [ref]$clRow)) {
                $hits++
            } else {
                $misses++
            }
            foreach ($alias in $plan.ColumnAliases.Keys) {
                $sourceCol = $plan.ColumnAliases[$alias]
                $val = ''
                if ($null -ne $clRow -and $clRow.PSObject.Properties[$sourceCol]) {
                    $val = $clRow.PSObject.Properties[$sourceCol].Value
                }
                if ($row.PSObject.Properties[$alias]) {
                    $row.PSObject.Properties[$alias].Value = $val
                } else {
                    $row | Add-Member -NotePropertyName $alias -NotePropertyValue $val -Force
                }
            }
        }
        Write-Info ("[2phase] '{0}' augmented {1} rows ({2} hits, {3} misses)" -f $plan.Var, $Rows.Count, $hits, $misses)
    }

    return ,@($Rows)
}
