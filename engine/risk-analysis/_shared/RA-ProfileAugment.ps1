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
    try { $curSubId = (Get-AzContext).Subscription.Id } catch {}
    if ($curSubId -and $curSubId -ne $subId) {
        $null = Set-AzContext -Subscription $subId -ErrorAction Stop
    }

    $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rgName -Name $wsName -ErrorAction Stop
    $custId = $ws.CustomerId.Guid

    if ($curSubId -and $curSubId -ne $subId) {
        try { $null = Set-AzContext -Subscription $curSubId -ErrorAction SilentlyContinue } catch {}
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
        [object[]]$TypeReferenceRows
    )
    # Types from the reference set when given (the whole snapshot); otherwise from the rows at hand.
    $typeRows = if ($TypeReferenceRows -and $TypeReferenceRows.Count -gt 0) { $TypeReferenceRows } else { $Rows }

    if (-not $typeRows -or $typeRows.Count -eq 0) {
        # Nothing anywhere to infer from -- fall back to the name-only hint, then the placeholder.
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
        foreach ($r in $typeRows) {
            $v = $r.PSObject.Properties[$p.Name].Value
            if ($null -ne $v -and -not ([string]::IsNullOrEmpty([string]$v))) {
                [void]$values.Add([string]$v)
            }
        }
        $kqlType = 'string'
        if ($values.Count -gt 0) {
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
            $v = $r.PSObject.Properties[$colNames[$i]].Value
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
                    default    { '""' }
                }
            } else {
                switch ($t) {
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
    }
    # Trim trailing comma+newline.
    $out = $sb.ToString().TrimEnd(",`r`n".ToCharArray()) + [Environment]::NewLine + '];'
    return $out
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
            try {
                $rows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $WorkspaceResourceId -Query $snapshotKql
            } catch {
                Write-Err2 ("[shadow] {0} snapshot fetch failed: {1}" -f $tbl, $_.Exception.Message)
                throw
            }
            $rowArr = if ($rows) { @($rows) } else { @() }
            $datatableLet = Convert-RowsToKqlDatatable -LetVarName $tbl -Rows $rowArr
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
    $cdcCols = New-Object System.Collections.Generic.List[string]
    foreach ($_cdc in @($script:_CrossDomainBucketCoalesce)) {
        $_c = if ($_cdc -is [System.Collections.IDictionary]) { [string]$_cdc['ClColumn'] }
              elseif ($_cdc.PSObject.Properties['ClColumn'])   { [string]$_cdc.ClColumn }
              else { [string]$_cdc }
        if (-not [string]::IsNullOrWhiteSpace($_c) -and -not $cdcCols.Contains($_c)) { [void]$cdcCols.Add($_c) }
    }
    foreach ($col in $cdcCols) {
        $p = $Row.PSObject.Properties[$col]
        if ($p) {
            $v = [string]$p.Value
            if (-not [string]::IsNullOrWhiteSpace($v)) { return $v }
        }
    }
    foreach ($col in 'EpJoinKey','_si_PrimaryEntityId','DeviceKey','NodeId','DeviceNodeId','AadDeviceId','DeviceId','MachineId','Id','SourceNodeId','TargetNodeId','EntraObjectId','UserId','AzureResourceId_Guid','PrimaryEntityId','AssetId','Target_AzureResourceId_Guid','Source_AadDeviceId','Source_AssetId','Target_AssetId_From_CL','FinalTargetId','FinalSourceId') {
        $p = $Row.PSObject.Properties[$col]
        if ($p) {
            $v = [string]$p.Value
            if (-not [string]::IsNullOrWhiteSpace($v)) { return $v }
        }
    }
    return ''
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
    # Strip strings/comments first to avoid false-positive `;` inside literals.
    $stripped = $Query
    $stripped = [regex]::Replace($stripped, '"[^"\r\n]*"', '""')
    $stripped = [regex]::Replace($stripped, "'[^'\r\n]*'", "''")
    $stripped = [regex]::Replace($stripped, '//[^\r\n]*', '')

    # let-binding pattern: `let <var> = ... SI_*_Profile_CL ... ;` -- multiline,
    # non-greedy, terminates at first `;` (already safe vs. string literals).
    $letRx = '(?ms)\blet\s+(?<var>\w+)\s*=\s*(?<body>[^;]*?\bSI_[A-Za-z]+_Profile_CL\b[^;]*?);'
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
    foreach ($m in $matches2) {
        $varName = $m.Groups['var'].Value
        # Re-extract body from the ORIGINAL query (string-stripped version has placeholders)
        $origMatch = [regex]::Match($modified, $letRx)
        if (-not $origMatch.Success) { continue }
        $bodyKql = $origMatch.Groups['body'].Value
        $fullBlock = $origMatch.Value

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
            try {
                $clRows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $WorkspaceResourceId -Query $bodyKql
            } catch {
                Write-Err2 ("[hybrid] CL snapshot fetch failed for '{0}': {1}" -f $varName, $_.Exception.Message)
                throw
            }
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
                $bucketKeyCols = @('EpJoinKey','_si_PrimaryEntityId','DeviceKey','NodeId','DeviceNodeId','AadDeviceId','DeviceId','MachineId','Id','SourceNodeId','TargetNodeId','EntraObjectId','UserId','AzureResourceId_Guid','PrimaryEntityId','AssetId','Target_AzureResourceId_Guid','Source_AadDeviceId','Source_AssetId','Target_AssetId_From_CL','FinalTargetId','FinalSourceId')
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
            if ($null -eq $script:_LastHybridSnapshotRowCount -or $rowCount -gt [int]$script:_LastHybridSnapshotRowCount) {
                $script:_LastHybridSnapshotRowCount = [int]$rowCount
            }
        }

        $allRows = $script:_HybridRowsCache[$cacheKey]

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
            $egStdCols = @{'DeviceKey'=$true; 'NodeId'=$true; 'DeviceNodeId'=$true; 'AadDeviceId'=$true; 'DeviceId'=$true; 'MachineId'=$true; 'Id'=$true; 'SourceNodeId'=$true; 'TargetNodeId'=$true; 'EpJoinKey'=$true}
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

        if ($clBucketingActive) {
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
                foreach ($_row in $allRows) {
                    $_idx = Get-SISha256Bucket -Key (Get-SICLBucketKey -Row $_row) -BucketCount $BucketCount
                    $_groups[$_idx].Add($_row)
                }
                $script:_HybridBucketGroupsCache[$groupCacheKey] = $_groups
                Write-Info ("[hybrid] '{0}' pre-grouped {1} rows into {2} buckets in {3:N1}s (one-time O(N) hash pass; subsequent buckets are O(1) lookups)" -f $varName, @($allRows).Count, $BucketCount, ([datetime]::UtcNow - $_t0).TotalSeconds)
            }
            $bucketRows = @($script:_HybridBucketGroupsCache[$groupCacheKey][$BucketIndex])
            $datatableLet = Convert-RowsToKqlDatatable -LetVarName $varName -Rows $bucketRows -BodyKqlForSchemaHint $bodyKql -TypeReferenceRows @($allRows)
            Write-Info ("[hybrid] '{0}' bucket {1}/{2}: {3}/{4} row(s) inlined ({5} bytes; CL-bucketed via SHA256)" -f $varName, ($BucketIndex + 1), $BucketCount, $bucketRows.Count, $allRows.Count, $datatableLet.Length)
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
            if ($bucketRows.Count -gt 0) {
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
        else {
            $datatableLet = Convert-RowsToKqlDatatable -LetVarName $varName -Rows @($allRows) -BodyKqlForSchemaHint $bodyKql
            Write-Info ("[hybrid] '{0}' snapshot: {1} row(s) inlined as datatable ({2} bytes)" -f $varName, @($allRows).Count, $datatableLet.Length)
            $script:_HybridSnapshotCache[$cacheKey] = $datatableLet
        }
        $modified = $modified.Replace($fullBlock, $datatableLet)
        $_thisCallInlineBytes += [int]$datatableLet.Length
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
    $letRx = '(?ms)\blet\s+(?<var>\w+)\s*=\s*(?<bodyAll>[^;]*?\bSI_(?<table>[A-Za-z]+_Profile)_CL\b[^;]*?\|\s*project\s+(?<proj>[^;]*?)\|\s*where\s+(?:isnotempty\(\s*(?:tostring\(\s*column_ifexists\(\s*"(?<rkey>\w+)"\s*,[^)]*\)\s*\)|(?<rkey2>\w+))\s*\)|(?<rkey3>\w+)\s*!=\s*"")\s*);'

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
                $clRows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $WorkspaceResourceId -Query $plan.ProjectionKql
            } catch {
                Write-Warn2 ("[2phase] '{0}' CL fetch failed; augment cols will be empty: {1}" -f $plan.Var, $_.Exception.Message)
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
