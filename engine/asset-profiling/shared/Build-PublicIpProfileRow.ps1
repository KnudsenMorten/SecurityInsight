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

# The default tier is a RULE (asset-profiling-enrichment/shared/AssetProfileByDefaultTier.locked.yaml), not a constant.
if (-not (Get-Command -Name Get-SIDefaultTierValue -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Resolve-SIDefaultTier.ps1') }
# #562 the asset type / subtype come from the ONE classification (the CI build's rows and value maps).
if (-not (Get-Command -Name Get-SIProfileAssetClassification -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '..\..\data-model\SI-ProfileClassification.ps1') }

if (-not (Get-Variable -Name _SISchemaCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:_SISchemaCache = @{}
}

function Get-SIPublicIpFieldRequiredKeys {
    <# v2.2.374 -- mirror of the Azure helper. Given a schema field, return the
       list of metadata keys whose presence is REQUIRED for the field to
       possibly resolve to non-null. Empty list = no fast-null possible. #>
    param($Field)
    $src  = [string]$Field.source
    $name = [string]$Field.name
    $keys = New-Object System.Collections.Generic.List[string]
    if ($script:_SIPublicIpKeyMap.ContainsKey($name)) {
        [void]$keys.Add([string]$script:_SIPublicIpKeyMap[$name])
    }
    if ($src -eq 'shodan')        { [void]$keys.Add('SHODAN_RawJson') }
    if ($src -eq 'exposureGraph') { [void]$keys.Add('EG_RawData') }
    return $keys
}

function Get-SIPublicIpSchema {
    if ($script:_SISchemaCache.ContainsKey('PublicIpSchema')) { return $script:_SISchemaCache['PublicIpSchema'] }
    . (Join-Path $PSScriptRoot 'Get-SISchemaWithCustomMerge.ps1')
    $schema = Get-SISchemaWithCustomMerge -Engine publicip
    $script:_SISchemaCache['PublicIpSchema'] = $schema
    # v2.2.374 -- pre-filter emit-able fields once + annotate each with
    # _SIRequiredKeys so per-row iteration can fast-null fields whose required
    # source data isn't present. Same pattern as Azure v2.2.371/372.
    $script:_SISchemaCache['PublicIpEmitFields'] = @(
        $schema.fields | Where-Object {
            $fn = [string]$_.name
            $fn -and `
            (-not $_.PSObject.Properties['emit'] -or $_.emit -ne $false) -and `
            ([string]$_.purpose -notin 'enrichment','forensic','raw') -and `
            ($fn -notin 'CollectHash','EnrichHash','PostureHash','ClassifyHash')
        } | ForEach-Object {
            $reqKeys = Get-SIPublicIpFieldRequiredKeys -Field $_
            Add-Member -InputObject $_ -MemberType NoteProperty -Name '_SIRequiredKeys' -Value $reqKeys -Force
            $_
        }
    )
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

# 🔒 MAKE A DECLARED sourcePath SAFE TO WALK -- added 2026-08-28 after ALL SEVEN source=shodan fields
# were measured resolving EMPTY on a payload that contained every value they ask for.
#
# Two independent authoring habits killed them, and either alone is fatal:
#   1. THE ROOT PREFIX. Paths were written 'shodan.isp', but the object handed to the walker IS the
#      parsed Shodan payload -- so it looked for a property literally named 'shodan' and returned null.
#   2. PROSE. 'country_code (ISO 3166-1 alpha-2)' and 'data[*] -- per-port {...}' carry an explanation
#      in the same string, which becomes part of the segment name (or of the [*] remainder).
#
# 🪤 THE FAILURE MODE IS THE DANGEROUS ONE: no exception, no warning -- just an empty field. The
# neighbouring COUNT fields had their own working implementations, so rows shipped OpenPortCount=3
# beside OpenPorts=[] and read as "nothing found" rather than "nothing worked".
#
# The schema paths are now correct; this normaliser exists so the same authoring slip cannot silently
# cost a field again. It is deliberately narrow: take the first whitespace-delimited token, and drop a
# leading '<root>.' if present. Anything else is left alone.
function _NormalizeSourcePath {
    param([string]$Path, [string]$Root)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $p = $Path.Trim()
    # prose always begins at the first space ('isp', 'country_code (ISO ...)', 'data[*] -- per-port')
    $sp = ($p -split '\s+')[0]
    if ($Root -and $sp.StartsWith($Root + '.', [StringComparison]::OrdinalIgnoreCase)) {
        $sp = $sp.Substring($Root.Length + 1)
    }
    return $sp
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
    # 🪤 `,$cur` -- PRESERVE ARRAY SHAPE ACROSS THE RETURN. Without the comma, PowerShell unwraps a
    # SINGLE-ELEMENT array, so `hostnames: ["one.host"]` comes back as a STRING. The caller then hits
    # its own `-is [string]` guard (which exists so a scalar is not iterated character by character)
    # and discards the value entirely. Measured 2026-08-28: a one-element hostnames array resolved to
    # @() while a two-element one worked -- a data-dependent disappearance, invisible in review.
    # 📌 Same PS 5.1 unwrap this solution has been bitten by before; it is in the notes and it still
    # cost a field.
    return ,$cur
}

function Resolve-SISourceValue {
    param([Parameter(Mandatory)] $Field, [Parameter(Mandatory)] $Record)
    $meta = if ($Record.Metadata) { $Record.Metadata } else { @{} }

    # PS 5.1 unwrap fix -- comma operator preserves array shape across return.

    if ($Field.source -eq 'shodan') {
        $parsed = Get-SIShodanParsed -Meta $meta
        if ($null -eq $parsed) { return $null }
        $sp = _NormalizeSourcePath -Path ([string]$Field.sourcePath) -Root 'shodan'
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

# 🔒 THE CVE SET, IN ONE PLACE. Shodan reports vulnerabilities in TWO shapes -- a top-level `vulns`
# array, and a per-service `data[].vulns` DICTIONARY keyed by CVE id -- so this is a union, not a path.
# Extracted 2026-08-28 from the VulnCount case so the ARRAY and the COUNT come from the same code and
# cannot disagree. See the 'OpenPorts' / 'Vulns' block below for why that mattered.
function _GetVulnsArray {
    param([Parameter(Mandatory)]$Meta)
    $parsed = Get-SIShodanParsed -Meta $Meta
    if ($null -eq $parsed) { return @() }
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
    return @($set | Sort-Object)
}

function Get-SIDerivedValue {
    param([Parameter(Mandatory)] $Field, [Parameter(Mandatory)] $Context)
    $meta    = if ($Context.Record.Metadata) { $Context.Record.Metadata } else { @{} }
    $verdict = $Context.Verdict

    switch ($Field.name) {
        'PrimaryEntityId'   { return $Context.PrimaryEntityId }
        # v3 step 1 -- see Build-EndpointProfileRow. Declared, never wired, 0% live.
        'SI_AssetId'        { return $Context.PrimaryEntityId }
        'PrimaryEntityType' { return 'IpAddress' }
        # v2.2.349 -- IpAddress is a 'derived' field per the schema ("the public IP itself").
        # It aliases PrimaryEntityId. Without this case the schema-iterated IpAddress column
        # came through empty in the pre-ingest audit (0% [EMPTY]) even though PrimaryEntityId
        # was populated 100% with the same value.
        'IpAddress'         { return $Context.PrimaryEntityId }
        # 🔒 SI_AssetName -- the authored name for this engine. Same rule as the other three: walk the
        # candidates, SKIP anything equal to PrimaryEntityId because an identifier is not a name, and
        # fall back to a MARKED SYNTHETIC rather than the bare id.
        #
        # 🔴 THIS PREVIOUSLY RETURNED $Context.PrimaryEntityId UNCONDITIONALLY, on the premise that "a
        # public IP has no name and needs none: the address IS the name". MEASURED 2026-08-27 on a real
        # run, that premise was false on 11 of 11 rows. The default discovery mode is 'profile-cl',
        # which reads public IPs OUT of SI_Endpoint_Profile_CL / SI_Azure_Profile_CL -- so every row
        # descends from an asset SI has already named, and 3 of those 11 were Tier 0. The engine knew
        # the owner all along: AssetEngine and AssetTier arrived 11/11 and only the name they travelled
        # with was dropped (Invoke-Collect.ps1 excludes the row's top-level 'Name' from metadata).
        #
        # ⚠️ WHY THIS MATTERS BEYOND COSMETICS: four RA reports aggregate this table "per asset". With
        # the IP in the name column, every public IP becomes its own asset -- a Tier 0 open-port finding
        # rendered as a bare address where every other engine renders a server name, and the
        # cross-engine join v3 exists to enable could not put an asset's endpoint row and its public-IP
        # row under one name.
        #
        # 📌 The IP is NOT lost by this change: it remains in IpAddress and in PrimaryEntityId. The name
        # column holds names; the id columns hold ids.
        'SI_AssetName' {
            $ownerName = if ($meta -is [System.Collections.IDictionary]) {
                             if ($meta.Contains('IP_AssetName')) { [string]$meta['IP_AssetName'] } else { '' }
                         } elseif ($meta.PSObject.Properties['IP_AssetName']) {
                             [string]$meta.IP_AssetName
                         } else { '' }
            $pe = [string]$Context.PrimaryEntityId
            # Discovery falls back to the IP for its own 'Name', so IP_AssetName can legitimately
            # arrive equal to PrimaryEntityId. That is the identifier again -- skip it.
            if (-not [string]::IsNullOrWhiteSpace($ownerName) -and $ownerName -ne $pe) { return $ownerName }
            if (-not [string]::IsNullOrWhiteSpace($pe)) {
                if (-not (Get-Command Get-SISyntheticAssetName -ErrorAction SilentlyContinue)) {
                    . (Join-Path $PSScriptRoot 'SI-AssetName.ps1')
                }
                return (Get-SISyntheticAssetName -Engine 'publicip' -Id $pe)
            }
            return $null
        }
        'IpVersion'         { if ($Context.PrimaryEntityId -like '*:*') { return 'IPv6' } else { return 'IPv4' } }
        'EntityIds'         { return ,$Context.EntityIds }
        # v3 step 2 -- $egId is already extracted below and pushed into EntityIds; emit it as a column
        # too, so the correlation key does not require unpacking a dynamic.
        'ExposureGraphNodeId' { return $Context.EgNodeId }
        'RunId'             { return $Context.Record.SI_RunId }
        # V3-6 -- stamp WHICH RELEASE produced this row. si-v3 and main/prod write this SAME table and
        # the nightly runs the released code, so without this a profile row cannot be attributed to the
        # code that produced it. Risk Analysis has stamped it since v2.1 -- which is exactly why the two
        # trees interleaving was visible in the RA tables and invisible here.
        'SolutionVersion'   { if (-not (Get-Command Get-SISolutionVersion -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-SolutionVersion.ps1') }; return (Get-SISolutionVersion) }
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
                # v2.2.373 -- InvariantCulture parse so non-en-US boxes don't fail on M/d/yyyy strings.
                $dt = [datetime]::Parse($lastUpdate, [System.Globalization.CultureInfo]::InvariantCulture)
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

        # 🔴 OpenPorts / Vulns ARE RESOLVED HERE, NOT THROUGH THE SCHEMA sourcePath -- AND THAT IS THE
        # FIX FOR A DEFECT THAT MADE BOTH EMPTY FOR EVERY CUSTOMER, ALWAYS (2026-08-28).
        #
        # Their declared sourcePaths are not paths at all; they are PROSE:
        #     OpenPorts : "shodan.ports[*] (sorted ascending, deduped)"
        #     Vulns     : "union(shodan.vulns[*], shodan.data[*].vulns) -- CVE id list"
        # Resolve-SISourceValue splits on '[*]', so it looked up `shodan.ports` (wrong -- the parsed
        # object IS the Shodan payload, the path is `ports`) and carried " (sorted ascending, deduped)"
        # as the remainder. Either mistake alone returns @(). PROVEN OFFLINE against a payload holding
        # 3 ports and 1 CVE: both fields resolved to 0 items while _GetOpenPortsArray returned 3.
        #
        # ⚠️ WHY IT WAS INVISIBLE: OpenPortCount and VulnCount have their OWN working implementations
        # reading the parsed bag directly, so a row could read OpenPortCount=3 next to OpenPorts=[].
        # Measured live on 108.143.47.209. The RA reports mv-expand the ARRAY, so they returned zero
        # rows on an internet-facing asset while the count said three ports were open -- a clean, empty,
        # WRONG report rather than an error. And it means "no CVEs in this estate" was never a
        # measurement: Vulns could not have been populated regardless.
        #
        # 🔑 THE SHAPE OF THE FIX: one fact, one code path. The array and its count now come from the
        # same helper, so they cannot disagree again -- which the old two-path arrangement guaranteed
        # they eventually would.
        'OpenPorts' { return ,@(_GetOpenPortsArray -Meta $meta) }
        'Vulns'     { return ,@(_GetVulnsArray     -Meta $meta) }
        'VulnCount' { return ([array](_GetVulnsArray -Meta $meta)).Count }
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
                # v2.2.373 -- InvariantCulture parse so non-en-US boxes don't fail on M/d/yyyy strings.
                $ts = [datetime]::Parse([string]$parsed.last_update, [System.Globalization.CultureInfo]::InvariantCulture)
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

    # 🔒 Tier = THE CRITICALITY TIER OF THE ASSET THIS PUBLIC IP BELONGS TO.
    #
    # Same meaning as `Tier` on the other three profile tables, which is the point: RA derives
    # `CriticalityTier = toint(coalesce(Tier, ...))` in ~76 reports and read `AssetTier` in exactly
    # 4 -- the publicip ones. publicip was the outlier, so publicip moved.
    #
    # 🪤 WHY THIS IS NOT "BENDING A CLASSIFICATION TO FIX A REPORT". A public IP has no criticality of
    # its own; it matters because of what it exposes. And publicip's own tier was never a real
    # classification: there are NO publicip tiering rules (no asset-profiling-enrichment/publicip), the
    # classify stage returns SI_Tier = null with proof "Tier left null for Stage Profile to compute via
    # MIN-of-SIRules", and 0 SIRules match -- so every row fell to the hardcoded 3 below. A constant.
    # Measured 2026-08-27: Tier = 3 on all 11 rows while the owners included three Tier 0 servers.
    #
    # Precedence: the owning asset's tier (from discovery) > the classification verdict > 3.
    $ownerTierMeta = $null
    if ($meta -is [System.Collections.IDictionary] -and $meta.Contains('AssetTier')) { $ownerTierMeta = [string]$meta['AssetTier'] }
    elseif ($meta.PSObject.Properties['AssetTier']) { $ownerTierMeta = [string]$meta.AssetTier }

    $aggTier = if (-not [string]::IsNullOrWhiteSpace($ownerTierMeta)) {
                   # 99 is discovery's explicit "no owner tier known" marker and is preserved: the RA
                   # queries map a missing tier to 99 too, so replacing it would invent a criticality
                   # no source claimed.
                   try { [int]$ownerTierMeta } catch { Get-SIDefaultTierValue -Engine publicip }
               }
               elseif ($null -ne $verdict.SI_Tier) { try { [int]$verdict.SI_Tier } catch { Get-SIDefaultTierValue -Engine publicip } }
               else { Get-SIDefaultTierValue -Engine publicip }   # the default tier RULE (Resolve-SIDefaultTier.ps1); $null = Unclassified

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
        EgNodeId          = $egId          # v3 step 2 -- emitted as ExposureGraphNodeId
        AggregatedTier    = $aggTier
        RunContext        = $RunContext
    }

    # v2.2.374 -- use cached emit-fields + per-row availKeys fast-null path.
    # Same pattern as Build-AzureProfileRow v2.2.371/372.
    $row = [ordered]@{}
    $row['TimeGenerated'] = $Record.TimeGenerated
    $availKeys = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    if ($meta -is [System.Collections.IDictionary]) {
        foreach ($k in $meta.Keys) {
            $v = $meta[$k]
            if ($null -ne $v -and "$v" -ne '') { [void]$availKeys.Add([string]$k) }
        }
    } else {
        foreach ($p in $meta.PSObject.Properties) {
            if ($null -ne $p.Value -and "$p.Value" -ne '') { [void]$availKeys.Add([string]$p.Name) }
        }
    }
    foreach ($f in $script:_SISchemaCache['PublicIpEmitFields']) {
        $fname = [string]$f.name
        # Fast-null path: if field requires source keys and NONE are populated, emit null directly.
        $reqKeys = $f._SIRequiredKeys
        $skipResolve = $false
        if ($f.source -ne 'derived' -and $reqKeys -and $reqKeys.Count -gt 0) {
            $hasAny = $false
            foreach ($rk in $reqKeys) { if ($availKeys.Contains($rk)) { $hasAny = $true; break } }
            if (-not $hasAny) { $skipResolve = $true }
        }
        if ($skipResolve) { $row[$fname] = $null; continue }
        $val = if ($f.source -eq 'derived') {
            Get-SIDerivedValue -Field $f -Context $ctx
        } else {
            Resolve-SISourceValue -Field $f -Record $Record
        }
        $row[$fname] = $val
    }

    $row['Properties'] = $properties

    # ---- CMDB / Reconcile flat columns ----
    # v2.2.348 -- also read from Metadata for the publicip engine: Profile_CL
    # discovery stamps cmdb* on the discovery row's TOP-LEVEL keys + as CMDB_*
    # in Metadata. Read TOP-LEVEL first (matches endpoint/identity/azure
    # Reconcile path), fall back to Metadata top-level when missing.
    foreach ($f in @('cmdbId','cmdbName','cmdbCriticality','cmdbDataSensitivity',
                     'CmdbMatchPhase','CmdbMatchState','CmdbMatchRule','CmdbMatchConfidence','LastSeenInCmdb','CmdbSource')) {
        $v = $null
        if ($Record.PSObject.Properties[$f] -and $Record.$f) { $v = $Record.$f }
        elseif ($meta -is [System.Collections.IDictionary] -and $meta.Contains($f) -and $meta[$f]) { $v = $meta[$f] }
        elseif ($meta.PSObject.Properties[$f] -and $meta.$f) { $v = $meta.$f }
        $row[$f] = $v
    }

    # ---- AssetEngine -- which engine owns the asset this IP belongs to ----
    # The ONLY row column not derived from a schema field. It carries a fact no other column does:
    # whether discovery matched this IP to an endpoint, an azure resource, an EG node or a customer
    # extras entry. Declared in public-ip.schema.locked.json so it is not an undeclared column.
    #
    # 🔒 THE LEGACY ALIAS BLOCK THAT USED TO LIVE HERE IS GONE (operator, 2026-08-28: "i dont see
    # purpose of assettier. we dont use that name in the other 3. consistence is very importsant").
    # It emitted five columns that DUPLICATED declared ones under the retired standalone scanner's
    # names, and NONE of the five was declared in any of the four engine schemas:
    #
    #     HasShodanRecord  -> InShodan          LastShodanUpdate -> ShodanLastSeen
    #     Org              -> OrgName           ISP              -> Isp
    #     AssetTier        -> Tier
    #
    # The RA queries were moved to the declared names in the same change. AssetTier went last and had
    # nothing left to lose: it is declared in no schema, was emitted by no other builder, and its only
    # column consumers were the four publicip reports, which now read Tier like the other ~76 reports.
    # (The 62 remaining "AssetTier" hits in the RA catalog are `tagsBag1.AssetTier` -- an Azure/Entra
    # TAG key, unrelated to this column.)
    $assetEngineMeta = $null
    if ($meta -is [System.Collections.IDictionary] -and $meta.Contains('AssetEngine')) { $assetEngineMeta = [string]$meta['AssetEngine'] }
    elseif ($meta.PSObject.Properties['AssetEngine']) { $assetEngineMeta = [string]$meta.AssetEngine }
    if ($assetEngineMeta) { $row['AssetEngine'] = $assetEngineMeta }

    # ---- #244: WHICH source set this public IP's tier (SI_TierSetBy / SI_TierReason / SI_TierClaims) ----
    # The tier above is the OWNING asset's tier when discovery knows the owner (precedence owner > verdict > 3, not a MIN),
    # so the owner is then the one and only source: 'owner', with the owner's name as the evidence. Otherwise the rules /
    # classification verdict, as for the other engines. DEGRADE, DO NOT DIE: an audit surface is never worth the row.
    if (-not (Get-Command -Name Set-SIProfileTierAttribution -ErrorAction SilentlyContinue)) {
        try { . (Join-Path $PSScriptRoot 'Get-SITierAttribution.ps1') } catch {
            Write-Warning ("tier attribution unavailable ({0}) -- SI_TierSetBy/Reason/Claims will be empty for this run; the tier itself is unaffected." -f $_.Exception.Message)
        }
    }
    if (Get-Command -Name Set-SIProfileTierAttribution -ErrorAction SilentlyContinue) {
        $tierClaimSources = @{}
        try {
            if (-not [string]::IsNullOrWhiteSpace($ownerTierMeta)) {
                $ownerName = ''
                if ($meta -is [System.Collections.IDictionary] -and $meta.Contains('IP_AssetName')) { $ownerName = [string]$meta['IP_AssetName'] }
                elseif ($meta.PSObject.Properties['IP_AssetName']) { $ownerName = [string]$meta.IP_AssetName }
                if ($ownerName -eq $ip) { $ownerName = '' }   # discovery falls back to the IP itself -- not an owner name
                $ev = (@($assetEngineMeta, $ownerName) | Where-Object { $_ }) -join ' '
                $tierClaimSources = @{ OwnerAssetTier = [pscustomobject]@{ Tier = $aggTier; TopMatch = $ev; MatchCount = 1 } }
            } else {
                $classifyStatus = if ($Record.PSObject.Properties['SI_Classify_Status']) { [string]$Record.SI_Classify_Status } else { '' }
                $tierClaimSources = Get-SIProfileTierSources -Verdict $verdict -ClassifyStatus $classifyStatus
            }
        } catch { $tierClaimSources = @{} }
        Set-SIProfileTierAttribution -Row $row -FinalTier $aggTier -Sources $tierClaimSources -DefaultTier (Get-SIDefaultTierValue -Engine publicip)
    } else {
        $row['SI_TierSetBy'] = ''; $row['SI_TierReason'] = ''; $row['SI_TierClaims'] = '[]'
    }

    # ---- #562 AssetType / AssetSubtype FROM THE ONE CLASSIFICATION -- 'Public IP', the dimension's spelling (was 'PublicIP') ----
    $row['AssetSubtype'] = ''
    if (Get-Command -Name ConvertTo-SIPublicIpClassificationItem -ErrorAction SilentlyContinue) {
        $cls = Get-SIProfileAssetClassification -Item (ConvertTo-SIPublicIpClassificationItem)
        if ($null -ne $cls) { $row['AssetType'] = $cls.Type; $row['AssetSubtype'] = $cls.Subtype }
    }
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
