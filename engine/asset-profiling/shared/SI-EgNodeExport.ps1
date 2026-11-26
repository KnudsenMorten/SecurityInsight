#Requires -Version 5.1
<#
    #1398 THE EXPOSURE GRAPH TABLES READ ONCE PER RUN (owner 2026-10-21: "memory issues must not be a problem in any step.
    env must work in millions of assets env"; review of 4ad683ccf: per-part key lists meant ~500 hunting queries at 300,000
    identities, past Defender's ~45 a minute).

    THE READ. One streamed hunting read of the whole table per run -- identity nodes, Azure nodes, Azure access edges --
    each part of the answer (a hash bucket of a cut answer) taken as it arrives (Invoke-SIHuntingQueryResult -OnRows).
    Kusto projects only the fields the readers use and CASTS them (tobool / toreal / tostring): the hunting API hands a
    dynamic column out as text, and [bool]'false' is $true. Calls = the buckets of one answer, never parts x key lists.

    THE LOOKUP. In a run collected in parts the producer (Invoke-Discover, discover phase) writes the rows to the run's
    state store as JSON lines in chunks -- collect/<engine>/<runId>/eg-<kind>/chunk-NNNNN.jsonl, then done.json (Ok, Rows,
    Chunks, Error) -- and every part opens them. Each line is "<key>\t<key>...\t<json>": the row's lookup keys first
    (lower case, ASCII white space trimmed), so a part parses ONLY the lines one of its own keys is on; memory is one chunk
    plus the part's rows. A run in one process reads Defender itself, the same streamed read, filtered the same way.
    A failed export / read is SAID: the part's Exposure Graph values are unknown this run, never "none".
    PowerShell 5.1 / 7, REST only.
#>

if (-not (Get-Command -Name Invoke-SIHuntingQueryResult -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'HuntingQuery.ps1') }

$script:SIEgExportChunkRows = 5000

# the readers' kinds: the query, the fields and their types, the lookup keys of a row
$script:SIEgKinds = @{
    'identity-nodes' = @{
        Bools   = @('hasAdLeakedCredentials', 'hasLeakedCredentials', 'isActive', 'hasServicePrincipalName', 'isCompromisedRecently', 'externalUser', 'onPremSyncEnabled', 'isMfaCapable', 'isMfaRegistered')
        Strings = @('identityType', 'accountDomain', 'primaryProvider', 'adSid', 'distinguishedName', 'criticalityLevel', 'accountObjectId', 'accountUpn')
        Reals   = @()
    }
    'azure-nodes' = @{
        Bools   = @('handlesSensitiveData')
        Strings = @('criticality', 'businessApplicationName')
        Reals   = @('exposureScore')
    }
}

function ConvertTo-SIEgKey {
    <# PURE. A lookup key: lower case, ASCII white space trimmed (the same on both sides of a match); '' for none. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    # tab / CR / LF inside a key become a space -- the same on both sides, so an export line's key cells never break the line
    ([string]$Value).Trim([char[]]@(' ', "`t", "`r", "`n", [char]11, [char]12)).Replace("`t", ' ').Replace("`r", ' ').Replace("`n", ' ').ToLowerInvariant()
}

function Get-SIEgFields {
    <# PURE. Every rawData field of a node kind, in a stable order. #>
    param([Parameter(Mandatory)][string]$Kind)
    $k = $script:SIEgKinds[$Kind]
    @($k.Bools) + @($k.Strings) + @($k.Reals)
}

function Get-SIEgExportQuery {
    <# PURE. The whole-table query of a kind, each field cast in Kusto (the API's text form of a dynamic column never reaches the readers). #>
    param([Parameter(Mandatory)][ValidateSet('identity-nodes', 'azure-nodes', 'azure-edges')][string]$Kind, [string]$LabelList = '', [string]$EdgeFilter = '')
    if ($Kind -eq 'azure-edges') {
        return @"
ExposureGraphEdges
$EdgeFilter
| project SourceNodeId = tostring(SourceNodeId), SourceNodeName = tostring(SourceNodeName), SourceNodeLabel = tostring(SourceNodeLabel),
          TargetNodeId = tostring(TargetNodeId), TargetNodeName = tostring(TargetNodeName), TargetNodeLabel = tostring(TargetNodeLabel), EdgeLabel = tostring(EdgeLabel)
"@
    }
    $k = $script:SIEgKinds[$Kind]
    $all = Get-SIEgFields -Kind $Kind
    $fieldList = ($all | ForEach-Object { '"' + $_ + '"' }) -join ','
    $proj = New-Object System.Collections.Generic.List[string]
    foreach ($f in $k.Bools)   { $proj.Add(('rd_{0} = tobool(__rd.{0})' -f $f)) }
    foreach ($f in $k.Strings) { $proj.Add(('rd_{0} = tostring(__rd.{0})' -f $f)) }
    foreach ($f in $k.Reals)   { $proj.Add(('rd_{0} = toreal(__rd.{0})' -f $f)) }
    @"
ExposureGraphNodes
| where NodeLabel in~ ($LabelList)
| extend __p = NodeProperties
| extend __rd = iff(isnotempty(__p.rawData), __p.rawData, __p)
| project NodeId = tostring(NodeId), NodeName = tostring(NodeName), NodeLabel = tostring(NodeLabel), HasRawData = isnotempty(__rd),
          RdKeys = tostring(set_intersect(bag_keys(__rd), dynamic([$fieldList]))), $($proj -join ', ')
"@
}

function ConvertTo-SIEgBool {
    <# PURE. A projected boolean as the old reader's [bool] of the parsed JSON value: text 'true' / 'false' / '' read as such. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    # live (internal 2026-11-26): a null cell of a tobool() column came back as an EMPTY object -- it is none, not $true
    if ($Value -is [System.Management.Automation.PSCustomObject] -and @($Value.PSObject.Properties).Count -eq 0) { return $null }
    # live: tobool() came back as 0 / 1 (Int64, '@odata.type' #SByte) -- [bool] of the number, as the old reader's [bool] of true / false
    if ($Value -is [string]) {
        $t = $Value.Trim().ToLowerInvariant()
        if ($t -eq 'true' -or $t -eq '1') { return $true }
        if ($t -eq 'false' -or $t -eq '0' -or $t -eq '' -or $t -eq 'null') { return $false }
        return [bool]$Value
    }
    [bool]$Value
}

function ConvertTo-SIEgText {
    <#
        PURE. A projected text cell as the old reader's [string] of the parsed value. Live (internal 2026-11-26): a field can
        hold an OBJECT (criticalityLevel = {type, criticalityLevel, ruleNames ...}); tostring() hands it out as JSON text, and
        3.1.51 read it parsed -- so JSON object / array text is parsed back first (the same ConvertFrom-Json), then [string].
        An empty object cell (a null) is none.
    #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Management.Automation.PSCustomObject] -and @($Value.PSObject.Properties).Count -eq 0) { return $null }
    if ($Value -is [string]) {
        $t = $Value.TrimStart()
        if ($t.StartsWith('{') -or $t.StartsWith('[')) { try { return [string](ConvertFrom-Json -InputObject $Value -ErrorAction Stop) } catch { return $Value } }
        return $Value
    }
    [string]$Value
}

function ConvertTo-SIEgReal {
    <# PURE. A projected number (text or number) as a double; $null when it is none. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Management.Automation.PSCustomObject] -and @($Value.PSObject.Properties).Count -eq 0) { return $null }
    if ($Value -is [string]) {
        $d = 0.0
        if ([double]::TryParse($Value.Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
        return $null
    }
    [double]$Value
}

function ConvertFrom-SIEgNodeRow {
    <#
        PURE. One projected node row (as the API or the export hands it: casts, or their text) -> @{ HasRawData; RawData }:
        the rawData with only the fields the node HAS, each in its type; RawData $null when the node has no properties.
    #>
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][string]$Kind)
    $k = $script:SIEgKinds[$Kind]
    $has = $Row.HasRawData
    if ($has -is [string]) { $has = (ConvertTo-SIEgBool $has) }
    $keys = $Row.RdKeys
    if ($keys -is [string]) { $t = $keys.Trim(); if ($t.StartsWith('[')) { try { $keys = @(ConvertFrom-Json -InputObject $t) } catch { $keys = @() } } else { $keys = @() } }
    if ($null -eq $has) { $has = (@($keys | Where-Object { $_ }).Count -gt 0) }
    if (-not [bool]$has) { return [pscustomobject]@{ HasRawData = $false; RawData = $null } }
    $o = [ordered]@{}
    foreach ($f in @($keys)) {
        if (-not $f) { continue }
        $f = [string]$f
        $p = $Row.PSObject.Properties[('rd_' + $f)]
        $v = if ($p) { $p.Value } else { $null }
        if ($k.Bools -contains $f) { $v = ConvertTo-SIEgBool $v }
        elseif ($k.Reals -contains $f) { $v = ConvertTo-SIEgReal $v }
        else { $v = ConvertTo-SIEgText $v }
        $o[$f] = $v
    }
    [pscustomobject]@{ HasRawData = $true; RawData = [pscustomobject]$o }
}

function Get-SIEgRowKeys {
    <# PURE. The lookup keys of one row of a kind (ConvertTo-SIEgKey, empty ones left out). #>
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][string]$Kind)
    $vals = switch ($Kind) {
        'identity-nodes' { @($Row.NodeName, $Row.NodeId, $Row.rd_accountObjectId, $Row.rd_accountUpn) }
        'azure-nodes'    { @($Row.NodeName) }
        'azure-edges'    { @($Row.TargetNodeId, $Row.TargetNodeName) }
    }
    foreach ($v in $vals) { $s = ConvertTo-SIEgKey $v; if ($s) { $s } }
}

function Get-SIEgExportPath {
    <# PURE. Where a run's export of a kind is kept (-Chunk -1 = its done marker). #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$Kind, [int]$Chunk = -1)
    $base = 'collect/{0}/{1}/eg-{2}' -f $Engine.ToLowerInvariant(), $RunId, $Kind
    if ($Chunk -lt 0) { return "$base/done.json" }
    '{0}/chunk-{1:D5}.jsonl' -f $base, $Chunk
}

function ConvertTo-SIEgExportLine {
    <# PURE. One row as an export line: its keys, a tab each, then the row as compact JSON (control characters escaped by JSON). #>
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][string]$Kind)
    $keys = @(Get-SIEgRowKeys -Row $Row -Kind $Kind)   # (ConvertTo-SIEgKey: no tab / line break left in a key -- a key never breaks its line)
    (($keys + @(ConvertTo-Json -InputObject $Row -Compress -Depth 4)) -join "`t")
}

function Invoke-SIEgRead {
    <#
        The whole-table read of a kind from Defender, each row to -OnRow { param($Row) } as its part of the answer arrives.
        Returns @{ Ok; Error; Defect; Rows }. -Ask: the test seam of one hunting request.
    #>
    param([Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)][scriptblock]$OnRow, [scriptblock]$Ask)
    $egReadN = @{ N = 0L }
    $hqArgs = @{ Query = $Query; OnRows = { param($egPart) foreach ($egR in @($egPart)) { if ($null -ne $egR) { $egReadN.N++; $null = & $OnRow $egR } } } }
    if ($Ask) { $hqArgs['Ask'] = $Ask }
    $hr = Invoke-SIHuntingQueryResult @hqArgs
    [pscustomobject]@{ Ok = [bool]$hr.Ok; Error = [string]$hr.Error; Defect = [bool]$hr.Defect; Rows = $egReadN.N }
}

function Export-SIEgRows {
    <#
        THE PRODUCER: the whole-table read of -Kind -> the run's state store, JSON lines in chunks of
        $script:SIEgExportChunkRows, then done.json. Never throws: a failed read or write writes done.json with Ok = $false
        and the reason (the parts then say their Exposure Graph values are unknown). Returns the done document.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId,
          [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Query, [scriptblock]$Ask)
    $egx = @{ Chunk = 0; Buf = (New-Object System.Text.StringBuilder); Lines = 0; Rows = 0L }
    $flush = {
        if ($egx.Lines -eq 0) { return }
        & $Store.Write (Get-SIEgExportPath -Engine $Engine -RunId $RunId -Kind $Kind -Chunk $egx.Chunk) $egx.Buf.ToString()
        $egx.Chunk++; [void]$egx.Buf.Clear(); $egx.Lines = 0
    }
    $done = [ordered]@{ Schema = 1; Kind = $Kind; Ok = $false; Rows = 0L; Chunks = 0; Error = '' }
    try {
        $r = Invoke-SIEgRead -Query $Query -Ask $Ask -OnRow {
            param($row)
            [void]$egx.Buf.Append((ConvertTo-SIEgExportLine -Row $row -Kind $Kind)).Append("`n")
            $egx.Lines++; $egx.Rows++
            if ($egx.Lines -ge $script:SIEgExportChunkRows) { & $flush }
        }
        if ($r.Ok) { & $flush; $done.Ok = $true } else { $done.Error = $(if ($r.Defect) { 'the query was refused and must be fixed -- ' } else { '' }) + [string]$r.Error }
    } catch { $done.Error = [string]$_.Exception.Message }
    $done.Rows = $egx.Rows; $done.Chunks = $egx.Chunk
    try { & $Store.Write (Get-SIEgExportPath -Engine $Engine -RunId $RunId -Kind $Kind) (ConvertTo-Json -InputObject $done -Compress) } catch { $done.Ok = $false; $done.Error = ('the export could not be written: {0}' -f $_.Exception.Message) }
    [pscustomobject]$done
}

function Read-SIEgRowsForKeys {
    <#
        THE PARTS' READ: every row of -Kind one of -Keys is on, to -OnRow { param($Row) } -- from the run's export when the
        run is collected in parts and the producer exported it, else from Defender (the same streamed whole-table read).
        Only the lines a key is on are parsed. Returns @{ Ok; Error; Defect; Rows; Source }.
          -Store / -RunId / -Engine  the export (default: the run's state store when SI_COLLECT_PHASE = parts)
          -Query / -Ask              the direct read (no export)
    #>
    param([Parameter(Mandatory)][string]$Kind, [AllowNull()][AllowEmptyCollection()][string[]]$Keys = @(), [Parameter(Mandatory)][scriptblock]$OnRow,
          [string]$Query, [scriptblock]$Ask, $Store, [string]$RunId = '', [string]$Engine = '')
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($k in @($Keys)) { $s = ConvertTo-SIEgKey $k; if ($s) { [void]$set.Add($s) } }
    $res = [pscustomobject]@{ Ok = $true; Error = ''; Defect = $false; Rows = 0L; Source = 'none' }
    if ($set.Count -eq 0) { return $res }
    # A PART of a run collected in parts reads the producer's export -- by the run id the producer handed every part
    # (SI_COLLECT_ENGINE_RUN = the producer's engine run id, Start-SIInContainer) -- and never asks Defender itself: an export
    # that is not there is SAID (the part's Exposure Graph values unknown), never a silent fallback of every part to Defender.
    $isPart = ([string][Environment]::GetEnvironmentVariable('SI_COLLECT_PHASE') -eq 'parts')
    if ($isPart -and -not $RunId) { $RunId = [string][Environment]::GetEnvironmentVariable('SI_COLLECT_ENGINE_RUN') }
    if ($isPart -and -not $Store) {
        if ($global:SI_CollectStateStore) { $Store = $global:SI_CollectStateStore }   # test seam (the state store of a test)
        elseif ($global:SI_StorageAccount) {
            if (-not (Get-Command -Name New-SICollectBlobStore -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-CollectParts.ps1')) }
            try { $Store = New-SICollectBlobStore -Account ([string]$global:SI_StorageAccount) } catch { $Store = $null }
        }
    }
    if ($isPart -and (-not $Store -or -not $RunId -or -not $Engine)) {
        $res.Ok = $false; $res.Source = 'export'
        $res.Error = ('this part cannot open the run''s export of the Exposure Graph ({0}): {1}' -f $Kind, $(if (-not $RunId) { 'no run id (SI_COLLECT_ENGINE_RUN)' } elseif (-not $Store) { 'no state store' } else { 'no engine' }))
        return $res
    }
    if ($Store -and $RunId -and $Engine) {
        # R2-1: ANY failure of the export read (a store error, a corrupt line) is this read's failure -- Ok = $false with the
        # reason (the callers say the part's Exposure Graph values are unknown); it never takes the part down with it
        try {
            $doneTxt = & $Store.Read (Get-SIEgExportPath -Engine $Engine -RunId $RunId -Kind $Kind)
            if ($doneTxt) {
                $res.Source = 'export'
                $done = ConvertFrom-Json -InputObject ([string]$doneTxt)
                if (-not [bool]$done.Ok) { $res.Ok = $false; $res.Error = ('the run''s export of the Exposure Graph ({0}) did not complete: {1}' -f $Kind, [string]$done.Error); return $res }
                for ($c = 0; $c -lt [int]$done.Chunks; $c++) {
                    $txt = & $Store.Read (Get-SIEgExportPath -Engine $Engine -RunId $RunId -Kind $Kind -Chunk $c)
                    if ($null -eq $txt) { $res.Ok = $false; $res.Error = ('chunk {0} of {1} of the run''s export of the Exposure Graph ({2}) is not there' -f ($c + 1), $done.Chunks, $Kind); return $res }
                    foreach ($line in ([string]$txt).Split([char]10)) {
                        if (-not $line) { continue }
                        $cells = $line.Split([char]9)
                        $hit = $false
                        for ($i = 0; $i -lt $cells.Length - 1; $i++) { if ($set.Contains($cells[$i])) { $hit = $true; break } }
                        if (-not $hit) { continue }
                        $null = & $OnRow (ConvertFrom-Json -InputObject $cells[$cells.Length - 1] -ErrorAction Stop); $res.Rows++
                    }
                    $txt = $null
                }
                return $res
            }
        } catch {
            $res.Ok = $false; $res.Source = 'export'
            $res.Error = ('the run''s export of the Exposure Graph ({0}) could not be read: {1}' -f $Kind, $_.Exception.Message)
            return $res
        }
        if ($isPart) { $res.Ok = $false; $res.Source = 'export'; $res.Error = ('the run''s export of the Exposure Graph ({0}) is not there (run {1}) -- the producer did not hand it over' -f $Kind, $RunId); return $res }
    }
    if (-not $Query) { $res.Ok = $false; $res.Error = 'no export of this run and no query to read'; return $res }
    $res.Source = 'defender'
    $egRowsN = @{ N = 0L }
    # (the caller's block under its own name: inside Invoke-SIEgRead, $OnRow is the block below)
    $egCallerOnRow = $OnRow
    try {
    $r = Invoke-SIEgRead -Query $Query -Ask $Ask -OnRow {
        param($row)
        foreach ($rk in (Get-SIEgRowKeys -Row $row -Kind $Kind)) { if ($set.Contains($rk)) { $egRowsN.N++; $null = & $egCallerOnRow $row; break } }
    }
    } catch { $res.Ok = $false; $res.Error = ('the Exposure Graph ({0}) could not be read: {1}' -f $Kind, $_.Exception.Message); return $res }
    $res.Ok = [bool]$r.Ok; $res.Error = [string]$r.Error; $res.Defect = [bool]$r.Defect; $res.Rows = $egRowsN.N
    $res
}
