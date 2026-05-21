#Requires -Version 5.1
<#
    Schema-driven row builder for the publicip engine. Reads
    profiles/public-ip.schema.json (cached + locked+custom merge), then
    for each declared field looks up the value via its source/sourcePath or
    derivation and emits a row whose columns EXACTLY match the schema.

    Sources:
      azure         -- IP_* fields stamped by discovery from ARG publicIPAddresses
      shodan        -- whole /host JSON parsed once per row, walked by Resolve-SISourceValue
      exposureGraph -- EG_RawData blob walked the same way
      derived       -- Get-SIDerivedValue dispatch

    Mirrors Build-IdentityProfileRow.ps1 / Build-EndpointProfileRow.ps1 shape:
    same Get-SISchemaWithCustomMerge consumer, same comma-operator returns
    in resolvers (PS 5.1 single-element-array unwrap fix), same Properties
    JSON column with classify.proofs + collect.<source> blocks.
#>

if (-not (Get-Variable -Name _SISchemaCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:_SISchemaCache = @{}
}

function Get-SIPublicIpSchema {
    if ($script:_SISchemaCache.ContainsKey('PublicIpSchema')) { return $script:_SISchemaCache['PublicIpSchema'] }
    . (Join-Path $PSScriptRoot 'Get-SISchemaWithCustomMerge.ps1')
    $schema = Get-SISchemaWithCustomMerge -Engine publicip
    $script:_SISchemaCache['PublicIpSchema'] = $schema
    return $schema
}

# ---------------------------------------------------------------------------
# SOURCE EXTRACTORS
# ---------------------------------------------------------------------------

# Maps schema field -> location on $Record.Metadata. Discovery emits the
# IP_* / EG_* / SHODAN_* prefixed keys; the row builder hides the prefix.
$script:_SIPublicIpKeyMap = @{
    'IpAddress'             = 'IP_Address'
    'IpVersion'             = 'IP_Version'
    'AzureResourceId'       = 'IP_AzureResourceId'
    'BoundToResourceId'     = 'IP_BoundToResourceId'
    'Fqdn'                  = 'IP_Fqdn'
    'AllocationMethod'      = 'IP_AllocationMethod'
    'DdosProtectionMode'    = 'IP_DdosProtectionMode'
}

function Get-SIShodanParsed {
    # Parse the cached Shodan JSON ONCE per record + memoize on the metadata
    # blob. Subsequent field resolves walk the parsed object via dot paths.
    param([Parameter(Mandatory)]$Meta)
    if ($Meta -is [System.Collections.IDictionary]) {
        if ($Meta.Contains('_ShodanParsed')) { return $Meta['_ShodanParsed'] }
        $raw = if ($Meta.Contains('SHODAN_RawJson')) { [string]$Meta['SHODAN_RawJson'] } else { '' }
    } else {
        if ($Meta.PSObject.Properties['_ShodanParsed']) { return $Meta._ShodanParsed }
        $raw = if ($Meta.PSObject.Properties['SHODAN_RawJson']) { [string]$Meta.SHODAN_RawJson } else { '' }
    }
    if ([string]::IsNullOrWhiteSpace($raw)) {
        $parsed = $null
    } else {
        try { $parsed = $raw | ConvertFrom-Json } catch { $parsed = $null }
    }
    if ($Meta -is [System.Collections.IDictionary]) { $Meta['_ShodanParsed'] = $parsed }
    else { $Meta | Add-Member -NotePropertyName _ShodanParsed -NotePropertyValue $parsed -Force }
    return $parsed
}

function Get-SIEgParsed {
    param([Parameter(Mandatory)]$Meta)
    if ($Meta -is [System.Collections.IDictionary]) {
        if ($Meta.Contains('_EgParsed')) { return $Meta['_EgParsed'] }
        $raw = if ($Meta.Contains('EG_RawData')) { [string]$Meta['EG_RawData'] } else { '' }
    } else {
        if ($Meta.PSObject.Properties['_EgParsed']) { return $Meta._EgParsed }
        $raw = if ($Meta.PSObject.Properties['EG_RawData']) { [string]$Meta.EG_RawData } else { '' }
    }
    if ([string]::IsNullOrWhiteSpace($raw)) { $parsed = $null }
    else {
        try {
            $obj = $raw | ConvertFrom-Json
            $parsed = if ($obj.PSObject.Properties['rawData'] -and $obj.rawData) { $obj.rawData } else { $obj }
        } catch { $parsed = $null }
    }
    if ($Meta -is [System.Collections.IDictionary]) { $Meta['_EgParsed'] = $parsed }
    else { $Meta | Add-Member -NotePropertyName _EgParsed -NotePropertyValue $parsed -Force }
    return $parsed
}

function _ResolveDottedPath {
    # Walks a dotted path like 'foo.bar.baz' against a parsed JSON object.
    # Returns the value, or $null when any segment is missing.
    param([object]$Object, [string]$Path)
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Path)) { return $null }
    $cur = $Object
    foreach ($seg in ($Path -split '\.')) {
        if ($null -eq $cur) { return $null }
        $clean = $seg -replace '\[\*\]$', ''
        if ($cur -is [System.Collections.IDictionary]) {
            if ($cur.Contains($clean)) { $cur = $cur[$clean] } else { return $null }
        } elseif ($cur.PSObject.Properties[$clean]) {
            $cur = $cur.$clean
        } else { return $null }
    }
    return $cur
}

function Resolve-SISourceValue {
    param([Parameter(Mandatory)] $Field, [Parameter(Mandatory)] $Record)
    $meta = if ($Record.Metadata) { $Record.Metadata } else { @{} }

    # PS 5.1 unwrap fix -- comma operator preserves array shape across return.

    if ($Field.source -eq 'shodan') {
        $parsed = Get-SIShodanParsed -Meta $meta
        if ($null -eq $parsed) { return $null }
        $sp = [string]$Field.sourcePath
        # sourcePath patterns we honor:
        #   'ip_str'                    -- top-level scalar
        #   'ports[*]'                  -- top-level array
        #   'data[*].port'              -- iterate data[], collect .port
        #   'data[*].vulns'             -- iterate data[], collect .vulns (each is dict of CVE)
        if ($sp -notmatch '\[\*\]') {
            return ,(_ResolveDottedPath -Object $parsed -Path $sp)
        }
        # Iterator path -- split at first [*]
        $iter = $sp.IndexOf('[*]')
        $before = $sp.Substring(0, $iter)
        $after  = $sp.Substring($iter + 3).TrimStart('.')
        $arr = _ResolveDottedPath -Object $parsed -Path $before
        if ($null -eq $arr -or $arr -isnot [System.Collections.IEnumerable] -or $arr -is [string]) { return ,@() }
        $vals = New-Object System.Collections.ArrayList
        foreach ($el in $arr) {
            $v = if ($after) { _ResolveDottedPath -Object $el -Path $after } else { $el }
            if ($null -ne $v) { [void]$vals.Add($v) }
        }
        return ,$vals.ToArray()
    }

    if ($Field.source -eq 'exposureGraph') {
        $parsed = Get-SIEgParsed -Meta $meta
        if ($null -eq $parsed) { return $null }
        $sp = [string]$Field.sourcePath
        $sp = $sp -replace '^eg\.node\.NodeProperties\.rawData\.', ''
        return ,(_ResolveDottedPath -Object $parsed -Path $sp)
    }

    # azure / derived-via-keymap (IP_*, etc.)
    $key = $script:_SIPublicIpKeyMap[$Field.name]
    if (-not $key) { return $null }
    if ($meta -is [System.Collections.IDictionary]) {
        if ($meta.Contains($key)) { return ,$meta[$key] }
    } else {
        if ($meta.PSObject.Properties[$key]) { return ,$meta.$key }
    }
    return $null
}

# ---------------------------------------------------------------------------
# DERIVED-VALUE DISPATCH
# ---------------------------------------------------------------------------

if (-not (Get-Variable -Name _SIDerivedSeen -Scope Script -ErrorAction SilentlyContinue)) { $script:_SIDerivedSeen = @{} }

$script:_SIAdminPorts = @{
    22=$true; 23=$true; 135=$true; 139=$true; 445=$true; 1433=$true; 2375=$true;
    3306=$true; 3389=$true; 5432=$true; 5900=$true; 5985=$true; 5986=$true;
    6379=$true; 9200=$true; 11211=$true; 27017=$true; 1521=$true
}
$script:_SIDbPorts = @{ 1433=$true; 3306=$true; 5432=$true; 27017=$true; 6379=$true; 9200=$true; 5984=$true; 11211=$true; 1521=$true }

function _GetOpenPortsArray {
    param([Parameter(Mandatory)]$Meta)
    $parsed = Get-SIShodanParsed -Meta $Meta
    if ($null -eq $parsed -or -not $parsed.PSObject.Properties['ports']) { return @() }
    return @($parsed.ports | Where-Object { $_ })
}

function Get-SIDerivedValue {
    param([Parameter(Mandatory)] $Field, [Parameter(Mandatory)] $Context)
    $meta    = if ($Context.Record.Metadata) { $Context.Record.Metadata } else { @{} }
    $verdict = $Context.Verdict

    switch ($Field.name) {
        'PrimaryEntityId'   { return $Context.PrimaryEntityId }
        'PrimaryEntityType' { return 'IpAddress' }
        'EntityIds'         { return ,$Context.EntityIds }
        'RunId'             { return $Context.Record.SI_RunId }
        'CollectionTime'    { return $Context.RunContext.CollectionTime }
        # SIRules carries the AssetProfileBy* YAML rule matches
        # produced by Stage Profile (Verdict.SI_RuleMatches). Always an array.
        'SIRules' {
            if ($verdict -and $verdict.PSObject.Properties['SI_RuleMatches']) { return ,@($verdict.SI_RuleMatches) }
            return ,@()
        }
        # IsEnabledActive = IP is bound to an active Azure resource
        # OR Shodan returned data within $global:SI_ActiveStaleDays. An IP that
        # ARG/EG knows about (IP_AzureResourceId set) is by definition still
        # allocated; an IP that Shodan answered about recently is reachable.
        'IsEnabledActive' {
            $stale = if ($global:SI_ActiveStaleDays) { [int]$global:SI_ActiveStaleDays } else { 30 }
            $azId = if ($meta.IP_AzureResourceId) { [string]$meta.IP_AzureResourceId } else { '' }
            if (-not [string]::IsNullOrWhiteSpace($azId)) { return $true }
            $parsed = Get-SIShodanParsed -Meta $meta
            if ($null -eq $parsed) { return $false }
            $lastUpdate = $null
            if ($parsed.PSObject.Properties['last_update']) { $lastUpdate = [string]$parsed.last_update }
            if ([string]::IsNullOrWhiteSpace($lastUpdate)) { return ($null -ne $parsed) }
            try {
                $dt = [datetime]::Parse($lastUpdate)
                $age = ([datetime]::UtcNow - $dt.ToUniversalTime()).TotalDays
                return ($age -le $stale)
            } catch { return ($null -ne $parsed) }
        }

        'InShodan' {
            $parsed = Get-SIShodanParsed -Meta $meta
            return ($null -ne $parsed -and $parsed.PSObject.Properties['ip_str'])
        }
        'OpenPortCount' {
            return ([array](_GetOpenPortsArray -Meta $meta)).Count
        }
        'HasRdpOpen'             { return ((_GetOpenPortsArray -Meta $meta) -contains 3389) }
        'HasSshOpen'             { return ((_GetOpenPortsArray -Meta $meta) -contains 22) }
        'HasSmbOpen'             { return ((_GetOpenPortsArray -Meta $meta) -contains 445) }
        'HasDbOpen' {
            foreach ($p in (_GetOpenPortsArray -Meta $meta)) { if ($script:_SIDbPorts.ContainsKey([int]$p)) { return $true } }
            return $false
        }
        'HasManagementPortOpen' {
            foreach ($p in (_GetOpenPortsArray -Meta $meta)) { if ($script:_SIAdminPorts.ContainsKey([int]$p)) { return $true } }
            return $false
        }

        'VulnCount' {
            $parsed = Get-SIShodanParsed -Meta $meta
            if ($null -eq $parsed) { return 0 }
            $set = New-Object System.Collections.Generic.HashSet[string]
            if ($parsed.PSObject.Properties['vulns']) {
                foreach ($v in @($parsed.vulns)) { if ($v) { [void]$set.Add([string]$v) } }
            }
            if ($parsed.PSObject.Properties['data']) {
                foreach ($d in @($parsed.data)) {
                    if ($d.PSObject.Properties['vulns'] -and $d.vulns) {
                        foreach ($p in $d.vulns.PSObject.Properties) { [void]$set.Add($p.Name) }
                    }
                }
            }
            return $set.Count
        }
        'MaxCvssScore' {
            $parsed = Get-SIShodanParsed -Meta $meta
            if ($null -eq $parsed -or -not $parsed.PSObject.Properties['data']) { return $null }
            $best = -1.0
            foreach ($d in @($parsed.data)) {
                if (-not ($d.PSObject.Properties['vulns'] -and $d.vulns)) { continue }
                foreach ($p in $d.vulns.PSObject.Properties) {
                    $node = $p.Value
                    if ($node -and $node.PSObject.Properties['cvss'] -and $null -ne $node.cvss) {
                        $score = [double]$node.cvss
                        if ($score -gt $best) { $best = $score }
                    }
                }
            }
            if ($best -lt 0) { return $null } else { return $best }
        }
        'HasCriticalCve' {
            $score = Get-SIDerivedValue -Field ([pscustomobject]@{ name='MaxCvssScore' }) -Context $Context
            return ($null -ne $score -and $score -ge 9.0)
        }
        'ShodanLastSeenDays' {
            $parsed = Get-SIShodanParsed -Meta $meta
            if ($null -eq $parsed -or -not $parsed.PSObject.Properties['last_update']) { return -1 }
            try {
                $ts = [datetime]::Parse([string]$parsed.last_update)
                return [int]([math]::Floor(([datetime]::UtcNow - $ts.ToUniversalTime()).TotalDays))
            } catch { return -1 }
        }

        'AssetType'       { return 'PublicIP' }
        'Tier'            { return $Context.AggregatedTier }
        'Group'           { return [string]$verdict.SI_Group }
        'Verdict'         { return ('Tier {0}' -f $Context.AggregatedTier) }

        default {
            if (-not $script:_SIDerivedSeen[$Field.name]) {
                Write-Verbose ('  [derive-gap] no dispatch for derived field "{0}"' -f $Field.name)
                $script:_SIDerivedSeen[$Field.name] = $true
            }
            return $null
        }
    }
}

# ---------------------------------------------------------------------------
# HASH HELPERS
# ---------------------------------------------------------------------------

function Get-SICanonicalJson {
    param([object]$Bag)
    if ($Bag -is [System.Collections.IDictionary]) {
        $sorted = [ordered]@{}
        foreach ($k in ($Bag.Keys | Sort-Object)) { $sorted[$k] = $Bag[$k] }
        return ($sorted | ConvertTo-Json -Compress -Depth 20)
    }
    return ($Bag | ConvertTo-Json -Compress -Depth 20)
}

function Get-SIRowHash {
    param([object]$FieldBag)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes((Get-SICanonicalJson $FieldBag))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hex = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
        $hex.Substring(0, 16)
    } finally { $sha.Dispose() }
}

function _SIHashBag { param($Names, $Row); $h = @{}; foreach ($n in $Names) { if ($Row.Contains($n)) { $h[$n] = $Row[$n] } }; return $h }

# ---------------------------------------------------------------------------
# MAIN ENTRY: Build-SIPublicIpProfileRow
# ---------------------------------------------------------------------------

function Build-SIPublicIpProfileRow {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $RunContext
    )

    $schema  = Get-SIPublicIpSchema
    $meta    = if ($Record.Metadata) { $Record.Metadata } else { @{} }
    $verdict = $Record.Verdict

    $aggTier = if ($null -ne $verdict.SI_Tier) { try { [int]$verdict.SI_Tier } catch { 3 } } else { 3 }

    # PrimaryEntityId = the IP itself (stripped of 'ip:' prefix when present)
    $ip = if ($meta -is [System.Collections.IDictionary] -and $meta.Contains('IP_Address')) { [string]$meta['IP_Address'] }
          elseif ($meta.PSObject.Properties['IP_Address']) { [string]$meta.IP_Address }
          else { '' }
    if (-not $ip) {
        $ip = [string]$Record.AssetId
        if ($ip -match '^ip:(.+)$') { $ip = $matches[1] }
    }

    $entityIds = @( @{ type='IpAddress'; id=$ip; source='shodan' } )
    $azId = if ($meta -is [System.Collections.IDictionary] -and $meta.Contains('IP_AzureResourceId')) { [string]$meta['IP_AzureResourceId'] }
            elseif ($meta.PSObject.Properties['IP_AzureResourceId']) { [string]$meta.IP_AzureResourceId }
            else { '' }
    if ($azId) { $entityIds += @{ type='AzureResourceId'; id=$azId; source='azure'; relation='bound_to' } }
    $egId = if ($meta -is [System.Collections.IDictionary] -and $meta.Contains('EG_NodeId')) { [string]$meta['EG_NodeId'] }
            elseif ($meta.PSObject.Properties['EG_NodeId']) { [string]$meta.EG_NodeId }
            else { '' }
    if ($egId) { $entityIds += @{ type='ExposureGraphNodeId'; id=$egId; source='exposureGraph' } }

    # Properties.collect.{azure,exposureGraph,shodan} -- mirror the same blocks
    # the identity engine uses. Each carries the verbatim source payload so KQL
    # consumers can parse_json() out arbitrary detail not yet schema-flattened.
    $collectAzure = @{}
    $collectShodan = $null
    $collectEg     = $null
    $collectCmdb   = @{}
    if ($meta -is [System.Collections.IDictionary]) {
        foreach ($k in $meta.Keys) {
            if ($k -eq 'SHODAN_RawJson')   { $collectShodan = $meta[$k]; continue }
            if ($k -eq 'EG_RawData')        { $collectEg     = $meta[$k]; continue }
            if ($k -like 'IP_*')            { $collectAzure[$k.Substring(3)] = $meta[$k] }
            elseif ($k -like 'CMDB_*')      { $collectCmdb[$k.Substring(5)]  = $meta[$k] }
        }
    } else {
        foreach ($p in $meta.PSObject.Properties) {
            if ($p.Name -eq 'SHODAN_RawJson') { $collectShodan = $p.Value; continue }
            if ($p.Name -eq 'EG_RawData')      { $collectEg     = $p.Value; continue }
            if ($p.Name -like 'IP_*')           { $collectAzure[$p.Name.Substring(3)] = $p.Value }
            elseif ($p.Name -like 'CMDB_*')     { $collectCmdb[$p.Name.Substring(5)]  = $p.Value }
        }
    }

    # strip *@odata.type keys recursively from EG rawData blob,
    # and drop classify.proofs from Properties (already exposed as Tier_Proofs
    # JSON column + flat verdict columns).
    if (-not (Get-Command -Name ConvertTo-SICleanedEgBlob -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'Convert-EgBlob.ps1')
    }
    $collectEg = ConvertTo-SICleanedEgBlob -Value $collectEg

    $properties = @{
        meta = @{
            schema_version   = [string]$schema.schemaVersion
            schema_authority = 'v2.2/asset-profiling-schema/public-ip.schema.locked.json'
        }
        collect = @{
            azure         = $collectAzure
            exposureGraph = $collectEg
            shodan        = $collectShodan
            cmdb          = $collectCmdb   # matched CMDB service record (all CSV columns)
        }
    }

    $ctx = @{
        Record            = $Record
        Verdict           = $verdict
        EntityIds         = $entityIds
        PrimaryEntityId   = $ip
        AggregatedTier    = $aggTier
        RunContext        = $RunContext
    }

    $row = [ordered]@{}
    $row['TimeGenerated'] = $Record.TimeGenerated
    foreach ($f in $schema.fields) {
        if ($f.PSObject.Properties['emit'] -and $f.emit -eq $false) { continue }
        if ($f.purpose -in 'enrichment','forensic','raw') { continue }
        if ($f.name -in 'CollectHash','EnrichHash','PostureHash','ClassifyHash') { continue }

        $val = if ($f.source -eq 'derived') {
            Get-SIDerivedValue -Field $f -Context $ctx
        } else {
            Resolve-SISourceValue -Field $f -Record $Record
        }
        $row[$f.name] = $val
    }

    $row['Properties'] = $properties

    # ---- CMDB / Reconcile flat columns ----
    # v2.2.348 -- also read from Metadata for the publicip engine: Profile_CL
    # discovery stamps cmdb* on the discovery row's TOP-LEVEL keys + as CMDB_*
    # in Metadata. Read TOP-LEVEL first (matches endpoint/identity/azure
    # Reconcile path), fall back to Metadata top-level when missing.
    foreach ($f in @('cmdbId','cmdbName','cmdbCriticality','cmdbDataSensitivity',
                     'CmdbMatchPhase','CmdbMatchState','CmdbMatchRule','CmdbMatchConfidence','LastSeenInCmdb')) {
        $v = $null
        if ($Record.PSObject.Properties[$f] -and $Record.$f) { $v = $Record.$f }
        elseif ($meta -is [System.Collections.IDictionary] -and $meta.Contains($f) -and $meta[$f]) { $v = $meta[$f] }
        elseif ($meta.PSObject.Properties[$f] -and $meta.$f) { $v = $meta.$f }
        $row[$f] = $v
    }

    # ---- v2.2.348 LEGACY-COMPAT ALIAS COLUMNS (SI_VulnerabilityPIP_CL) ----
    # Older RA YAML queries (PublicIP_OpenPorts_*, PublicIP_Vulnerabilities_*)
    # were written against the legacy Invoke-PublicIpScanner.ps1 row shape.
    # Emit alias columns so those queries keep working after the engine flip:
    #   HasShodanRecord  = InShodan  (bool)
    #   AssetTier        = Tier      (string; LA convention -- legacy was [string][int])
    #   AssetEngine      = endpoint/azure/extra/eg  (from discovery row, top-level)
    #   Org              = OrgName   (shodan.org)
    #   ISP              = Isp       (shodan.isp)
    #   LastShodanUpdate = ShodanLastSeen  (shodan.last_update raw)
    if ($row.Contains('InShodan'))       { $row['HasShodanRecord']  = [bool]$row['InShodan'] }
    if ($row.Contains('Tier'))           { $row['AssetTier']        = [string]([int]$row['Tier']) }
    $assetEngineMeta = $null
    if ($meta -is [System.Collections.IDictionary] -and $meta.Contains('AssetEngine')) { $assetEngineMeta = [string]$meta['AssetEngine'] }
    elseif ($meta.PSObject.Properties['AssetEngine']) { $assetEngineMeta = [string]$meta.AssetEngine }
    if ($assetEngineMeta) { $row['AssetEngine'] = $assetEngineMeta }
    if ($row.Contains('OrgName'))        { $row['Org']              = [string]$row['OrgName'] }
    if ($row.Contains('Isp'))            { $row['ISP']              = [string]$row['Isp'] }
    if ($row.Contains('ShodanLastSeen')) { $row['LastShodanUpdate'] = [string]$row['ShodanLastSeen'] }

    $collectFieldNames  = @($schema.fields | Where-Object { $_.stage.writtenBy -eq 'collect'         -and $_.purpose -notin 'enrichment','forensic','raw' } | ForEach-Object { $_.name })
    $enrichFieldNames   = @($schema.fields | Where-Object { $_.stage.writtenBy -eq 'enrich'          -and $_.purpose -notin 'enrichment','forensic','raw' } | ForEach-Object { $_.name })
    $postureFieldNames  = @($schema.fields | Where-Object { $_.stage.writtenBy -eq 'posture_analyze' -and $_.purpose -notin 'enrichment','forensic','raw' } | ForEach-Object { $_.name })
    $classifyFieldNames = @($schema.fields | Where-Object { $_.stage.writtenBy -eq 'classify'        -and $_.name -notmatch '^(CollectHash|EnrichHash|PostureHash|ClassifyHash)$' } | ForEach-Object { $_.name })

    $row['CollectHash']  = Get-SIRowHash (_SIHashBag $collectFieldNames  $row)
    $row['EnrichHash']   = Get-SIRowHash (_SIHashBag $enrichFieldNames   $row)
    $row['PostureHash']  = Get-SIRowHash (_SIHashBag $postureFieldNames  $row)
    $row['ClassifyHash'] = Get-SIRowHash (_SIHashBag $classifyFieldNames $row)

    return [pscustomobject]$row
}
