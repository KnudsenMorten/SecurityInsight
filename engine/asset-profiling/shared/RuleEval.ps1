#Requires -Version 5.1
<#
    RuleEval.ps1

    `detect.kind` registry + per-asset evaluator for the AssetProfileBy*
    rule shape (ARCHITECTURE.md §§ 7, 9). Companion to Get-SIRuleSet.ps1.

    Two-layer design:

      LAYER 1 -- Per-kind handler functions
        Each handler implements one `detect.kind`. Signature:
          handler -Asset <pscustomobject> -Args <hashtable> -> [bool]
        Asset is the row from Stage Collect (engine-specific shape, but
        common fields like PrimaryEntityId, Name, Hostname, MDE_*,
        ENTRA_*, AZ_* available). Args is the kind's parameter hashtable
        from the YAML (e.g. for nameMatches: @{ namePatterns = [...] }).

      LAYER 2 -- Detection / rule evaluator
        Invoke-SIDetect -Asset $a -Detect $d -> [bool]
          Walks $d.any[] (true if ANY kind handler returns true) or
          $d.all[] (true only if ALL handlers return true). Per ARCHITECTURE
          .md § 7 each detection has an `any:` or `all:` array.

        Invoke-SIRuleEval -Asset $a -Rule $r -> [pscustomobject] | $null
          Walks $r.Detections in array order. Returns the FIRST detection
          whose Detect block matches, with its Set values bundled. Returns
          $null when no detection matches (asset doesn't fit this rule).

    Performance contract (ARCHITECTURE.md § 9):

      Per-asset handlers MUST NOT make external network calls. They read
      either from the asset row itself or from a pre-built bulk index.
      Index builders for kinds that need external data (hasSoftwareInstalled,
      groupMembership, hasAzureTagDirectOrParent, egKustoQuery, entraKustoQuery)
      live in companion files added in .

    4 kinds implemented (asset-row-only, no bulk fetch):
      * nameMatches
      * hasMdeMachineGroupTag
      * egDetectedRoles
      * hasEntraExtensionAttributeTag

    4 kinds STUBBED (throw 'not yet implemented'):
      * hasSoftwareInstalled       <- needs DeviceTvmSoftwareInventory bulk index
      * groupMembership            <- needs Entra group-member bulk index
      * hasAzureTagDirectOrParent  <- needs sub/MG hierarchy bulk index
      * egKustoQuery               <- needs per-rule pre-fetch

    Stage integration is NOT done in . Use Test-SIRuleEval to
    exercise this against a sample asset object; engine integration ships
    in behind $global:SI_UseNewRuleEngine opt-in.
#>

# ----------------------------------------------------------------------------
# Helpers (asset-row reader + safe regex match)
# ----------------------------------------------------------------------------

function Get-SIAssetField {
    <#
        Reads a field from an asset, tolerating both [hashtable] and
        [pscustomobject] shapes (assets can arrive as either depending on
        the stage -- post-staging-blob round-trip they're PSCustomObject).
        Returns $null when the field doesn't exist.

        also walks $Asset.Metadata.<Name> as a fallback. Azure
        records (and endpoint records cross-source merge)
        carry AZ_*/MDE_*/ENTRA_*/EG_* fields under .Metadata, not at top
        level. Without this fallback, Test-SIKind_hasAzureTagDirectOrParent
        and other rule kinds saw $null for AZ_ResourceId on every asset and
        no rules ever matched.
    #>
    param(
        [Parameter(Mandatory)]$Asset,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $Asset) { return $null }

    # Top-level lookup
    $val = $null
    if ($Asset -is [System.Collections.IDictionary]) {
        if ($Asset.Contains($Name)) { $val = $Asset[$Name] }
    } else {
        $prop = $Asset.PSObject.Properties[$Name]
        if ($prop) { $val = $prop.Value }
    }
    if ($null -ne $val -and "$val" -ne '') { return $val }

    # Metadata-bag fallback
    $meta = $null
    if ($Asset -is [System.Collections.IDictionary]) {
        if ($Asset.Contains('Metadata')) { $meta = $Asset['Metadata'] }
    } else {
        $mp = $Asset.PSObject.Properties['Metadata']
        if ($mp) { $meta = $mp.Value }
    }
    if ($null -ne $meta) {
        if ($meta -is [System.Collections.IDictionary]) {
            if ($meta.Contains($Name)) { return $meta[$Name] }
        } else {
            $mp2 = $meta.PSObject.Properties[$Name]
            if ($mp2) { return $mp2.Value }
        }
    }
    return $null
}

function Test-SIPatternMatch {
    <#
        Tests $Value against an array of regex patterns. Returns $true on
        first hit. Empty/null Value or empty pattern array -> $false.
        Regex compile failures are logged and swallowed (one bad pattern
        in a 500-rule set must not stop evaluation).
    #>
    param(
        [string]$Value,
        [string[]]$Patterns
    )
    if ([string]::IsNullOrEmpty($Value) -or -not $Patterns -or $Patterns.Count -eq 0) {
        return $false
    }
    foreach ($p in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        try {
            if ([System.Text.RegularExpressions.Regex]::IsMatch($Value, $p)) { return $true }
        } catch {
            Write-Verbose ('Test-SIPatternMatch: invalid regex {0} -- {1}' -f $p, $_.Exception.Message)
        }
    }
    return $false
}

# ----------------------------------------------------------------------------
# Implemented handlers (asset-row-only, no bulk fetch needed)
# ----------------------------------------------------------------------------

function Test-SIKind_osPlatform {
    <#
        kind: osPlatform
          osPatterns:                      # any-match (regex; case-insensitive)
            - '(?i)^Windows10$'
            - '(?i)^Windows11$'
            - '(?i)^macOS'
        Reads MDE_OSPlatform / ENTRA_OS / EG.osPlatform / EG.osPlatformFriendlyName.
    #>
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Args)
    $patterns = @($Args.osPatterns)
    if (-not $patterns) { $patterns = @($Args.patterns) }
    if (-not $patterns -or $patterns.Count -eq 0) { return $false }
    foreach ($field in @('MDE_OSPlatform','ENTRA_OS','EG_OS')) {
        $val = [string](Get-SIAssetField -Asset $Asset -Name $field)
        if ($val -and (Test-SIPatternMatch -Value $val -Patterns $patterns)) { return $true }
    }
    return $false
}

function Get-SIAssetOsClass {
    <#
    .SYNOPSIS
        Coarse OS classification for fast per-rule scope filtering in Stage Profile.

    .DESCRIPTION
        Returns one of: WindowsServer, WindowsClient, Linux, macOS, iOS, Android,
        IoT, Other. Reads the same MDE_OSPlatform / ENTRA_OS / EG_OS fields the
        existing osPlatform rule kind uses. First non-empty wins.

        Used by Invoke-Profile.ps1 to short-circuit rule evaluation when a rule
        declares `osPlatformScope: [WindowsServer,...]` and the asset's class
        isn't in the list. Avoids running ~589 server-app rules against
        workstations / IoT / mobile and similar wasted permutations.

        Match table (case-insensitive prefix on the raw OS string):
          WindowsServer  : Windows Server, WindowsServer
          WindowsClient  : Windows10, Windows11, Windows7, Windows8
          Linux          : Linux, Ubuntu, Debian, RHEL, CentOS, Fedora, SUSE,
                           Oracle, AmazonLinux, AlmaLinux, Rocky
          macOS          : macOS, Mac OS, OSX
          iOS            : iOS, iPadOS
          Android        : Android
          IoT            : TvOS, WatchOS, IoT, Embedded, ChromeOS
          Other          : nothing matched (empty / unknown OS)
    #>
    param([Parameter(Mandatory)]$Asset)
    $os = $null
    foreach ($field in @('MDE_OSPlatform','ENTRA_OS','EG_OS')) {
        $v = [string](Get-SIAssetField -Asset $Asset -Name $field)
        if (-not [string]::IsNullOrWhiteSpace($v)) { $os = $v; break }
    }
    if ([string]::IsNullOrWhiteSpace($os)) { return 'Other' }
    switch -Regex ($os) {
        '(?i)windows[\s_-]*server'                                                 { return 'WindowsServer' }
        '(?i)^windowsserver'                                                       { return 'WindowsServer' }
        '(?i)^windows(7|8|8\.1|10|11)$'                                            { return 'WindowsClient' }
        '(?i)^windows[\s_-]?(10|11)'                                               { return 'WindowsClient' }
        '(?i)^(linux|ubuntu|debian|rhel|redhat|centos|fedora|suse|oracle|amazonlinux|almalinux|rocky)' { return 'Linux' }
        '(?i)^(macos|mac os|osx)'                                                  { return 'macOS' }
        '(?i)^(ios|ipados)'                                                        { return 'iOS' }
        '(?i)^android'                                                             { return 'Android' }
        '(?i)^(tvos|watchos|iot|embedded|chromeos)'                                { return 'IoT' }
        default                                                                    { return 'Other' }
    }
}

function Test-SIKind_nameMatches {
    <#
        kind: nameMatches
          namePatterns:
            - '(?i)^dc\d'
            - '(?i)domain.controller'
        Reads asset Name / Hostname / DisplayName fields and tests each
        regex pattern. Hits any -> true.
    #>
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Args)
    $patterns = @($Args.namePatterns)
    if (-not $patterns) { $patterns = @($Args.patterns) }   # accept either spelling
    if (-not $patterns -or $patterns.Count -eq 0) { return $false }

    foreach ($field in @('Name','Hostname','DisplayName','Fqdn','MDE_DeviceName','ENTRA_DisplayName','AZ_Name')) {
        $val = [string](Get-SIAssetField -Asset $Asset -Name $field)
        if ($val -and (Test-SIPatternMatch -Value $val -Patterns $patterns)) { return $true }
    }
    return $false
}

function Test-SIKind_hasMdeMachineGroupTag {
    <#
        kind: hasMdeMachineGroupTag
          machineTagPatterns: [ '(?i)domain.controller', '(?i)tier.?0' ]
        Reads asset MDE_MachineGroup (a string, comma- or semicolon-
        separated when multiple groups) and tests each regex against it.
    #>
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Args)
    $patterns = @($Args.machineTagPatterns)
    if (-not $patterns) { $patterns = @($Args.patterns) }
    if (-not $patterns -or $patterns.Count -eq 0) { return $false }

    $val = [string](Get-SIAssetField -Asset $Asset -Name 'MDE_MachineGroup')
    if (-not $val) { return $false }
    return (Test-SIPatternMatch -Value $val -Patterns $patterns)
}

function Test-SIKind_egDetectedRoles {
    <#
        kind: egDetectedRoles
          egSignals: [ 'isDomainController' ]
        Reads asset EG_DetectedRoles (semicolon-joined string from
        ExposureGraphNodes confidenceHigh/confidenceLow arrays) AND
        EG_RawData (full JSON blob) for properties like isDomainController.
    #>
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Args)
    $signals = @()
    if ($Args.egSignals) { $signals = @($Args.egSignals) }
    elseif ($Args.roles) { $signals = @($Args.roles) }
    if ($signals.Count -eq 0) { return $false }

    $detectedRoles = [string](Get-SIAssetField -Asset $Asset -Name 'EG_DetectedRoles')
    foreach ($s in $signals) {
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        # Two match modes:
        #   1) substring match against EG_DetectedRoles string
        #   2) boolean property match against EG_RawData (e.g. isDomainController=true)
        if ($detectedRoles -and $detectedRoles -match [regex]::Escape($s)) { return $true }

        $rawData = Get-SIAssetField -Asset $Asset -Name 'EG_RawData'
        if ($rawData) {
            $propVal = if ($rawData -is [System.Collections.IDictionary]) {
                if ($rawData.ContainsKey($s)) { $rawData[$s] } else { $null }
            } else {
                $p = $rawData.PSObject.Properties[$s]
                if ($p) { $p.Value } else { $null }
            }
            if ($propVal -eq $true -or $propVal -eq 'true') { return $true }
        }
    }
    return $false
}

function Test-SIKind_hasEntraExtensionAttributeTag {
    <#
        kind: hasEntraExtensionAttributeTag
          attribute: extensionAttribute6
          value:     'Internal_User'
          match:     exact
        Reads ENTRA_ExtensionAttributes (a JSON blob or hashtable with
        extensionAttribute1..15 keys). 'exact' requires full string match;
        anything else allows substring (case-insensitive).
    #>
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Args)
    $attrName = [string]$Args.attribute
    $value    = [string]$Args.value
    $matchKind = if ($Args.match) { [string]$Args.match } else { 'exact' }
    if ([string]::IsNullOrWhiteSpace($attrName) -or [string]::IsNullOrWhiteSpace($value)) { return $false }

    # First try direct flat field (some collectors flatten extensionAttributeN to top-level)
    $direct = [string](Get-SIAssetField -Asset $Asset -Name ('ENTRA_' + $attrName))
    if ($direct) {
        # PS 5.1 has no ternary -- explicit if/else (ternary lands in PS 7+).
        if ($matchKind -eq 'exact') { return ($direct -ceq $value) }
        return ($direct -like ('*' + $value + '*'))
    }

    # Fallback to nested ENTRA_ExtensionAttributes / ExtensionAttributes object
    foreach ($container in @('ENTRA_ExtensionAttributes','ExtensionAttributes','extensionAttributes')) {
        $obj = Get-SIAssetField -Asset $Asset -Name $container
        if ($null -eq $obj) { continue }
        $val = if ($obj -is [System.Collections.IDictionary]) {
            if ($obj.ContainsKey($attrName)) { $obj[$attrName] } else { $null }
        } else {
            $p = $obj.PSObject.Properties[$attrName]
            if ($p) { $p.Value } else { $null }
        }
        if ($null -ne $val) {
            $sval = [string]$val
            if ($matchKind -eq 'exact') { if ($sval -ceq $value) { return $true } }
            else                        { if ($sval -like ('*' + $value + '*')) { return $true } }
        }
    }
    return $false
}

# ----------------------------------------------------------------------------
# Bulk-index handlers
# ----------------------------------------------------------------------------

function Test-SIKind_hasSoftwareInstalled {
    <# Looks up MDE_DeviceId in tvmSoftware index. Pattern '<vendor>/<name>'
       allows wildcards via -like. Returns true on first match. #>
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Args)
    $patterns = @($Args.tvmSoftwareNames)
    if (-not $patterns -or $patterns.Count -eq 0) { return $false }

    $devId = [string](Get-SIAssetField -Asset $Asset -Name 'MDE_DeviceId')
    if (-not $devId) { $devId = [string](Get-SIAssetField -Asset $Asset -Name 'PrimaryEntityId') }
    if (-not $devId) { return $false }

    $idx = if (Get-Variable -Name SIRuleIndexes -Scope Script -ErrorAction SilentlyContinue) { $script:SIRuleIndexes.tvmSoftware } else { $null }
    if (-not $idx) { Write-Verbose 'hasSoftwareInstalled: tvmSoftware index not built (call Build-SIRuleIndexes first)'; return $false }
    $pairs = $idx[$devId.ToLower()]
    if (-not $pairs) { return $false }

    foreach ($pair in $pairs) {
        foreach ($p in $patterns) {
            $glob = ([string]$p).ToLower()
            if ($pair -like $glob -or $pair -like ('*/' + $glob)) { return $true }
        }
    }
    return $false
}

function Test-SIKind_groupMembership {
    <# renamed from adGroupMember. Looks up identity object id
       in GroupMembership index (sourced from ENTRA_Groups field on the asset row).
       Exact (case-insensitive) group-name match.
       index renamed adGroups -> GroupMembership; align key
       candidates with Build-SIGroupMembershipIndex --
       discovery emits ENTRA_UserId (not AccountObjectId; that's IdentityInfo's
       field name). PrimaryEntityId is only set by the row-builder at Output
       stage, NOT during Profile when this matcher runs. Without ENTRA_UserId
       in the candidate list, the lookup misses every identity even when the
       index correctly contains them -> SIRules ends up empty. Last-resort
       fallback also added: extract from AssetId 'entra-user:<guid>'. #>
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Args)
    $target = [string]$Args.group
    if ([string]::IsNullOrWhiteSpace($target)) { return $false }

    # short-circuit for non-user assets. SPs/MIs are not members
    # of org-finance / org-hr / etc. for tier-classification purposes -- the
    # builder doesn't index them (would always miss anyway). This skips the
    # AssetId regex + Get-SIAssetField calls per non-user iteration.
    $aid = [string](Get-SIAssetField -Asset $Asset -Name 'AssetId')
    if ($aid -and $aid -notmatch '^entra-user:') { return $false }

    $key = $null
    foreach ($f in @('PrimaryEntityId','AccountObjectId','ENTRA_UserId','ENTRA_ObjectId')) {
        $v = [string](Get-SIAssetField -Asset $Asset -Name $f)
        if ($v) { $key = $v.ToLower(); break }
    }
    if (-not $key) {
        $aid = [string](Get-SIAssetField -Asset $Asset -Name 'AssetId')
        if ($aid -match '^entra-user:(?<id>.+)$') { $key = $matches.id.ToLower() }
    }
    if (-not $key) { return $false }

    $idx = if (Get-Variable -Name SIRuleIndexes -Scope Script -ErrorAction SilentlyContinue) { $script:SIRuleIndexes.GroupMembership } else { $null }
    if (-not $idx) { Write-Verbose 'groupMembership: GroupMembership index not built'; return $false }
    $groups = $idx[$key]
    if (-not $groups) { return $false }
    # case-insensitive end-to-end. Both sides .ToLowerInvariant()
    # (locale-safe -- ToLower() in tr-TR locale would map "I" -> "i_" not "i").
    # -icontains is explicit case-insensitive (-contains is also CI but the
    # explicit form documents intent).
    return ($groups -icontains $target.ToLowerInvariant())
}

function Test-SIMatchOperator {
    <# shared match-operator helper. Used by tag-related detect kinds
       so YAML rules can express richer comparisons than raw equality.
       Operators (case-insensitive on operator name AND value):
         equal   (default) -- exact string match
         like              -- PowerShell -like wildcard ('*foo*', 'bar?')
         has               -- contains substring (case-insensitive)
         regex / matches   -- .NET regex match (caller can write '(?i)' inline for case)
         in                -- value appears in a list/array
         startswith        -- prefix match
         endswith          -- suffix match
       Returns $false on $null Actual or unknown operator. #>
    param([string]$Actual, $Expected, [string]$Op = 'equal')
    if ($null -eq $Actual) { return $false }
    $opLc = if ($Op) { $Op.ToLowerInvariant() } else { 'equal' }
    switch ($opLc) {
        'equal'      { return ([string]$Actual -ieq [string]$Expected) }
        'like'       { return ([string]$Actual -ilike [string]$Expected) }
        'has'        { return ([string]$Actual -imatch [regex]::Escape([string]$Expected)) }
        'startswith' { return ([string]$Actual).ToLowerInvariant().StartsWith(([string]$Expected).ToLowerInvariant()) }
        'endswith'   { return ([string]$Actual).ToLowerInvariant().EndsWith(([string]$Expected).ToLowerInvariant()) }
        'regex'      { try { return ([string]$Actual -imatch [string]$Expected) } catch { return $false } }
        'matches'    { try { return ([string]$Actual -imatch [string]$Expected) } catch { return $false } }
        'in' {
            $list = if ($Expected -is [System.Collections.IEnumerable] -and $Expected -isnot [string]) { @($Expected) } else { @($Expected) }
            foreach ($v in $list) { if ([string]$Actual -ieq [string]$v) { return $true } }
            return $false
        }
        default {
            Write-Verbose ("Test-SIMatchOperator: unknown operator '{0}', defaulting to 'equal'" -f $Op)
            return ([string]$Actual -ieq [string]$Expected)
        }
    }
}

function Test-SIKind_hasAzureTagDirectOrParent {
    <# Checks an Azure tag directly on the resource, OR inherited from any parent
       container (RG -> subscription -> management group). Consults the parentChain
       index built once per run by Build-SIParentResourceChainIndex.
       optional `match` arg supports equal|like|has|regex|matches|in|
       startswith|endswith. Default 'equal'. Tag KEY is always exact (case-insensitive). #>
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Args)
    $tagKey = [string]$Args.tag
    $tagVal = $Args.value
    $op     = if ($Args.match) { [string]$Args.match } else { 'equal' }
    if ([string]::IsNullOrWhiteSpace($tagKey)) { return $false }

    $resourceId = [string](Get-SIAssetField -Asset $Asset -Name 'AZ_ResourceId')
    if (-not $resourceId) { $resourceId = [string](Get-SIAssetField -Asset $Asset -Name 'PrimaryEntityId') }
    if (-not $resourceId) { return $false }

    $idx = if (Get-Variable -Name SIRuleIndexes -Scope Script -ErrorAction SilentlyContinue) { $script:SIRuleIndexes.parentChain } else { $null }
    if (-not $idx) { Write-Verbose 'hasAzureTagDirectOrParent: parentChain index not built'; return $false }

    $chain = @()
    $rid = $resourceId.ToLower()
    if ($idx.ContainsKey($rid)) { $chain += $idx[$rid] }
    if ($rid -match '^(/subscriptions/[^/]+/resourcegroups/[^/]+)') {
        $rgKey = $matches[1].ToLower()
        if ($idx.ContainsKey($rgKey)) { $chain += $idx[$rgKey] }
    }
    if ($rid -match '^(/subscriptions/[^/]+)') {
        $subKey = $matches[1].ToLower()
        if ($idx.ContainsKey($subKey)) { $chain += $idx[$subKey] }
    }

    foreach ($t in $chain) {
        if ([string]$t.tag -ieq $tagKey) {
            # No value supplied -> presence-only check (any non-empty value matches)
            if ($null -eq $tagVal -or ($tagVal -is [string] -and [string]::IsNullOrEmpty([string]$tagVal))) { return $true }
            if (Test-SIMatchOperator -Actual ([string]$t.value) -Expected $tagVal -Op $op) { return $true }
        }
    }
    return $false
}

function Test-SIIpInCidr {
    <# Returns $true if $Ip is inside the IPv4 / IPv6 $Cidr ('a.b.c.d/N').
       Pure byte-mask compare so it works in PS 5.1. Bad input -> $false. #>
    param([string]$Ip, [string]$Cidr)
    if ([string]::IsNullOrWhiteSpace($Ip) -or [string]::IsNullOrWhiteSpace($Cidr)) { return $false }
    $parts = $Cidr -split '/'
    if ($parts.Count -ne 2) { return $false }
    try {
        $ipObj  = [System.Net.IPAddress]::Parse($Ip.Trim())
        $netObj = [System.Net.IPAddress]::Parse($parts[0].Trim())
        if ($ipObj.AddressFamily -ne $netObj.AddressFamily) { return $false }
        $ipBytes  = $ipObj.GetAddressBytes()
        $netBytes = $netObj.GetAddressBytes()
        $bits = [int]$parts[1]
        for ($i = 0; $i -lt $ipBytes.Length; $i++) {
            $byteBits = [Math]::Min(8, [Math]::Max(0, $bits - ($i * 8)))
            if ($byteBits -eq 0) { return $true }
            $mask = [byte](256 - [Math]::Pow(2, 8 - $byteBits))
            if (($ipBytes[$i] -band $mask) -ne ($netBytes[$i] -band $mask)) { return $false }
        }
        return $true
    } catch { return $false }
}

function Test-SIKind_ipInRange {
    <# detect kind: matches when ANY of the asset's IP-bearing
       fields falls within ANY of the supplied CIDR ranges. Cross-engine:
       walks well-known endpoint AND azure IP carriers.

         - kind: ipInRange
           cidrs: ['10.100.1.0/24', '10.100.2.0/24']
           # Optional: restrict which fields to read
           # fields: ['MDE_EffectiveIpAddresses','MDE_PublicIp']

       Default fields scanned (in order):
         endpoint:  MDE_EffectiveIpAddresses, MDE_PublicIp,
                    MDE_LastIpAddress, EG_PublicIp, EG_PrivateIp
         azure:     AZ_PropertiesJson.ipAddress (publicIPAddress),
                    AZ_PropertiesJson.ipConfigurations[*].properties.privateIPAddress
                    (network interface; walked at runtime via JSON parse)

       Field values may be a single IP string, a comma-separated string,
       a JSON string array, or a [string[]] array -- all flattened. #>
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Args)

    $cidrs = @(if ($Args.cidrs) { @($Args.cidrs) } elseif ($Args.cidr) { @($Args.cidr) } else { @() })
    $cidrs = $cidrs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($cidrs.Count -eq 0) { return $false }

    # scan ALL SOURCES OF TRUTH, not just MDE. Order = priority but
    # ANY hit suffices. MDE_EffectiveIpAddresses is already a UNION of MDE
    # DeviceInfo + EG internalIpAddresses + EG lastIpAddress + Entra + ARG NIC +
    # AD + CMDB (Collect stage merges them per record, see contract).
    # The per-source backstops below catch records where the union didn't run --
    # e.g. EG-only assets or azure-engine resources.
    $defaultFields = @(
        # MDE (Microsoft Defender for Endpoint -- machine + DeviceInfo)
        'MDE_EffectiveIpAddresses','MDE_PublicIp','MDE_LastIpAddress',
        # Exposure Graph (Microsoft Security Exposure Management -- security view)
        'EG_PublicIp','EG_PrivateIp','EG_LastIpAddress','EG_InternalIpAddresses',
        # Entra (Entra ID joined device record)
        'ENTRA_PrivateIp','ENTRA_PublicIp','ENTRA_IpAddress',
        # Azure (ARG: VM NIC private IPs / PIP ipAddress)
        'AZ_PrivateIp','AZ_PrivateIpAddresses','AZ_PublicIp',
        # AD (on-prem Active Directory computer object -- enrichment coming)
        'AD_IpAddress','AD_IpAddresses',
        # CMDB (matched CI's IP fields -- folded by Reconcile from CMDB.csv columns)
        'CMDB_PrivateIp','CMDB_IpAddresses','CMDB_ip','CMDB_private_ip'
    )
    $fields = if ($Args.fields) { @($Args.fields) } else { $defaultFields }

    # Collect candidate IP strings
    $ips = New-Object System.Collections.Generic.List[string]
    foreach ($f in $fields) {
        $v = Get-SIAssetField -Asset $Asset -Name $f
        if ($null -eq $v) { continue }
        # Flatten: single IP, comma-list, JSON array, or [string[]] array
        if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
            foreach ($x in $v) { if ($x) { $ips.Add([string]$x) } }
            continue
        }
        $s = [string]$v
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        # JSON array string?
        if ($s.StartsWith('[')) {
            try { foreach ($x in ($s | ConvertFrom-Json)) { if ($x) { $ips.Add([string]$x) } } } catch { $ips.Add($s) }
            continue
        }
        # Comma / semicolon list
        foreach ($p in ($s -split '[,;]\s*')) { if ($p) { $ips.Add($p.Trim()) } }
    }

    # Azure VM/NIC fallback -- pull privateIP / ipAddress from AZ_PropertiesJson
    $azPropsJson = [string](Get-SIAssetField -Asset $Asset -Name 'AZ_PropertiesJson')
    if ($azPropsJson) {
        try {
            $p = $azPropsJson | ConvertFrom-Json
            if ($p.PSObject.Properties['ipAddress']) { $ips.Add([string]$p.ipAddress) }
            if ($p.PSObject.Properties['ipConfigurations']) {
                foreach ($cfg in $p.ipConfigurations) {
                    if ($cfg.properties -and $cfg.properties.PSObject.Properties['privateIPAddress']) {
                        $ips.Add([string]$cfg.properties.privateIPAddress)
                    }
                }
            }
        } catch {}
    }

    if ($ips.Count -eq 0) { return $false }
    foreach ($ip in $ips) {
        if ([string]::IsNullOrWhiteSpace($ip)) { continue }
        foreach ($cidr in $cidrs) {
            if (Test-SIIpInCidr -Ip $ip -Cidr $cidr) { return $true }
        }
    }
    return $false
}

function Get-SIAssetTagPairs {
    <# cross-source-of-truth tag carrier walker. Returns a flat
       list of @{ Key=<string|null>; Value=<string>; Source=<string> } pairs
       for an asset by walking every supported tag carrier on its Metadata.

       Carriers walked (works for endpoint, identity, AND azure assets --
       absent fields just don't contribute):

         MDE   value-only:  MDE_MachineTags
         EG    value-only:  EG_RawData.deviceDynamicTags / deviceManualTags
         EG    key:value:   EG_RawData.tags (some node types)
         Entra key:value:   ENTRA_ExtensionAttribute1..15
         Entra key:value:   ENTRA_OnPremisesExtensionAttributes (dict)
         ARM   key:value:   AZ_TagsJson (parsed) -- direct on the resource
         ARM   key:value:   parentChain index lookup (sub/RG inheritance)
         CMDB  key:value:   Metadata.CMDB_<col> (Reconcile-folded CSV columns)
         AD    value-only:  AD_GroupMemberships (placeholder, when present)

       Pairs with $null Key are "value-only" (presence in a list); pairs with
       a non-null Key are "key:value". The matcher in Test-SIKind_hasTag
       handles both shapes, including the convention where a value-only list
       carries a literal "key:value" or "key=value" string. #>
    param([Parameter(Mandatory)]$Asset)
    $pairs = New-Object System.Collections.Generic.List[object]

    $meta = $null
    if ($Asset -is [System.Collections.IDictionary]) { if ($Asset.Contains('Metadata')) { $meta = $Asset['Metadata'] } }
    elseif ($Asset.PSObject.Properties['Metadata'])  { $meta = $Asset.PSObject.Properties['Metadata'].Value }

    function _flattenList($v) {
        if ($null -eq $v) { return @() }
        if ($v -is [string]) {
            $s = [string]$v
            if ($s.StartsWith('[')) { try { return @($s | ConvertFrom-Json -ErrorAction Stop) } catch { return @($s -split '[,;]\s*') } }
            return @($s -split '[,;]\s*')
        }
        if ($v -is [System.Collections.IEnumerable]) { return @($v) }
        return @($v)
    }
    function _flattenDict($obj) {
        # Returns @( @{k=..; v=..}, ... ) for a hashtable / pscustomobject / JSON-string dict.
        if ($null -eq $obj) { return @() }
        if ($obj -is [string]) { try { $obj = $obj | ConvertFrom-Json -ErrorAction Stop } catch { return @() } }
        $out = @()
        if ($obj -is [System.Collections.IDictionary]) {
            foreach ($k in $obj.Keys) { $out += @{ k=[string]$k; v=[string]$obj[$k] } }
        } elseif ($obj.PSObject -and $obj.PSObject.Properties) {
            foreach ($p in $obj.PSObject.Properties) { $out += @{ k=[string]$p.Name; v=[string]$p.Value } }
        }
        return $out
    }

    # MDE machine tags (value-only)
    foreach ($t in (_flattenList (Get-SIAssetField -Asset $Asset -Name 'MDE_MachineTags'))) {
        if ($t) { [void]$pairs.Add(@{ Key=$null; Value=[string]$t; Source='mde' }) }
    }

    # EG rawData.deviceDynamicTags / deviceManualTags / tags (mix shapes)
    $egRaw = Get-SIAssetField -Asset $Asset -Name 'EG_RawData'
    if (-not $egRaw) {
        $egRawJson = Get-SIAssetField -Asset $Asset -Name 'AZ_PropertiesRawJson'
        if ($egRawJson -is [string]) {
            try {
                $parsed = $egRawJson | ConvertFrom-Json -ErrorAction Stop
                $egRaw = if ($parsed.PSObject.Properties['rawData']) { $parsed.rawData } else { $parsed }
            } catch {}
        }
    }
    if ($egRaw) {
        foreach ($f in @('deviceDynamicTags','deviceManualTags')) {
            if ($egRaw.PSObject.Properties[$f]) {
                foreach ($t in @($egRaw.$f)) { if ($t) { [void]$pairs.Add(@{ Key=$null; Value=[string]$t; Source='eg' }) } }
            }
        }
        if ($egRaw.PSObject.Properties['tags']) {
            foreach ($p in (_flattenDict $egRaw.tags)) { [void]$pairs.Add(@{ Key=$p.k; Value=$p.v; Source='eg' }) }
        }
    }

    # Entra extensionAttribute1..15
    for ($i = 1; $i -le 15; $i++) {
        $v = Get-SIAssetField -Asset $Asset -Name ("ENTRA_ExtensionAttribute$i")
        if ($v) { [void]$pairs.Add(@{ Key=("extensionAttribute$i"); Value=[string]$v; Source='entra' }) }
    }
    # Entra onPremisesExtensionAttributes (key:value dict)
    foreach ($p in (_flattenDict (Get-SIAssetField -Asset $Asset -Name 'ENTRA_OnPremisesExtensionAttributes'))) {
        [void]$pairs.Add(@{ Key=$p.k; Value=$p.v; Source='entra' })
    }

    # ARM tags directly on the resource (azure engine)
    foreach ($p in (_flattenDict (Get-SIAssetField -Asset $Asset -Name 'AZ_TagsJson'))) {
        [void]$pairs.Add(@{ Key=$p.k; Value=$p.v; Source='arm' })
    }

    # ARM tags via parent chain (cross-engine: endpoint linked to Azure VM, etc.)
    $resId = Get-SIAssetField -Asset $Asset -Name 'AZ_ResourceId'
    if (-not $resId) { $resId = Get-SIAssetField -Asset $Asset -Name 'MDE_AzureResourceId' }
    if (-not $resId) { $resId = Get-SIAssetField -Asset $Asset -Name 'AzureResourceId' }
    if ($resId) {
        $idx = if (Get-Variable -Name SIRuleIndexes -Scope Script -ErrorAction SilentlyContinue) { $script:SIRuleIndexes.parentChain } else { $null }
        if ($idx) {
            $rid = ([string]$resId).ToLower()
            $chain = @()
            if ($idx.ContainsKey($rid)) { $chain += $idx[$rid] }
            if ($rid -match '^(/subscriptions/[^/]+/resourcegroups/[^/]+)') {
                $rgKey = $matches[1].ToLower()
                if ($idx.ContainsKey($rgKey)) { $chain += $idx[$rgKey] }
            }
            if ($rid -match '^(/subscriptions/[^/]+)') {
                $subKey = $matches[1].ToLower()
                if ($idx.ContainsKey($subKey)) { $chain += $idx[$subKey] }
            }
            foreach ($t in $chain) { [void]$pairs.Add(@{ Key=[string]$t.tag; Value=[string]$t.value; Source=('arm:' + $t.level) }) }
        }
    }

    # CMDB-folded fields (Reconcile stamps Metadata.CMDB_<col> = value)
    if ($meta) {
        $cmdbKeys = if ($meta -is [System.Collections.IDictionary]) { @($meta.Keys) } else { @($meta.PSObject.Properties.Name) }
        foreach ($k in $cmdbKeys) {
            if ($k -like 'CMDB_*') {
                $val = if ($meta -is [System.Collections.IDictionary]) { $meta[$k] } else { $meta.$k }
                if ($val) { [void]$pairs.Add(@{ Key=$k.Substring(5); Value=[string]$val; Source='cmdb' }) }
            }
        }
    }

    # AD security-group memberships (placeholder for the AD enricher -- value-only)
    foreach ($t in (_flattenList (Get-SIAssetField -Asset $Asset -Name 'AD_GroupMemberships'))) {
        if ($t) { [void]$pairs.Add(@{ Key=$null; Value=[string]$t; Source='ad' }) }
    }

    return $pairs
}

function Test-SIKind_hasTag {
    <# unified cross-source tag matcher. Three modes (per
       user-direction "tags are defined in 2 ways - value (only) and
       key:value"):

         tag only           -> key presence (any source has that key with non-empty value)
         value only         -> value presence (any list contains it OR any dict has it as a value)
         tag + value        -> exact pair (key:value carrier) OR literal "key:value" /
                                "key=value" string in a value-only carrier

       Refusal: plain `value: '<single-string>'` with no `match:` operator
       is too broad (would match any 'cmdb:1' / 'Tier:1' / etc. lookalike
       in any source). Author must use match: in/regex/like, OR pair with
       `tag:`. Value alone with match: in [list] is allowed.

       Operator support: equal | like | has | regex | matches |
       in | startswith | endswith. Default 'equal'. All comparisons are
       case-insensitive on both key and value.

       Optional: `sources: ['mde','eg','entra','arm','cmdb','ad']` -- restrict
       which carriers contribute. Default: all. #>
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Args)

    $tagKey = if ($Args.tag)   { [string]$Args.tag }   else { $null }
    $hasVal = $false
    $tagVal = $null
    if ($Args -is [System.Collections.IDictionary]) {
        if ($Args.Contains('value')) { $hasVal = $true; $tagVal = $Args['value'] }
    } elseif ($Args.PSObject.Properties['value']) {
        $hasVal = $true; $tagVal = $Args.value
    }
    $op = if ($Args.match) { [string]$Args.match } else { 'equal' }

    if ([string]::IsNullOrWhiteSpace($tagKey) -and -not $hasVal) {
        Write-Verbose 'hasTag: refusing rule with neither tag nor value'
        return $false
    }
    # Refuse value-only with op=equal AND value is a single scalar -- too broad
    if ([string]::IsNullOrWhiteSpace($tagKey) -and $op -eq 'equal' -and $hasVal -and -not ($tagVal -is [System.Collections.IEnumerable] -and -not ($tagVal -is [string]))) {
        Write-Verbose 'hasTag: refusing value-only equal rule (use match: in/regex/like or pair with tag:)'
        return $false
    }

    $pairs = Get-SIAssetTagPairs -Asset $Asset
    if ($pairs.Count -eq 0) { return $false }

    # Optional source restriction
    if ($Args.sources) {
        $allow = @($Args.sources | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $pairs = @($pairs | Where-Object {
            $src = ([string]$_.Source).ToLowerInvariant()
            $base = $src.Split(':')[0]
            ($src -in $allow) -or ($base -in $allow)
        })
    }

    foreach ($p in $pairs) {
        $pKey = [string]$p.Key
        $pVal = [string]$p.Value
        $isValueOnly = [string]::IsNullOrWhiteSpace($pKey)

        if ($tagKey -and $hasVal) {
            # MODE 3: exact key:value pair
            if (-not $isValueOnly -and ($pKey -ieq $tagKey) -and (Test-SIMatchOperator -Actual $pVal -Expected $tagVal -Op $op)) { return $true }
            # MODE 3 fallback: literal "key:value" or "key=value" inside a value-only list
            if ($isValueOnly -and ($tagVal -isnot [System.Collections.IEnumerable] -or $tagVal -is [string])) {
                $literal1 = ('{0}:{1}' -f $tagKey, $tagVal)
                $literal2 = ('{0}={1}' -f $tagKey, $tagVal)
                if (($pVal -ieq $literal1) -or ($pVal -ieq $literal2)) { return $true }
            }
        } elseif ($tagKey) {
            # MODE 1: key presence
            if (-not $isValueOnly -and ($pKey -ieq $tagKey) -and -not [string]::IsNullOrWhiteSpace($pVal)) { return $true }
            # value-only carrier: literal "key:" / "key=" prefix
            if ($isValueOnly) {
                $prefixColon = ($tagKey + ':')
                $prefixEqual = ($tagKey + '=')
                if ($pVal.StartsWith($prefixColon, [StringComparison]::OrdinalIgnoreCase) -or
                    $pVal.StartsWith($prefixEqual, [StringComparison]::OrdinalIgnoreCase)) { return $true }
            }
        } else {
            # MODE 2: value presence anywhere (with operator -- usually 'in' or 'regex')
            if (Test-SIMatchOperator -Actual $pVal -Expected $tagVal -Op $op) { return $true }
        }
    }
    return $false
}

function Test-SIKind_mostFrequentUserTier {
    <# Reads MostFrequentUserTier from asset Metadata (stamped by Enrich/
       Get-SIBulkDeviceUserCorrelation from logon-graph + SI_Identity_Profile_CL).
       Returns $true when the value is in the rule's tierValues list.
       Used by AssetProfileByLogonUser to inherit endpoint tier from frequent
       logon user (admin's PC -> T1, T2 user -> T2, T3 user -> T3). #>
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Args)
    $v = Get-SIAssetField -Asset $Asset -Name 'MostFrequentUserTier'
    if ($null -eq $v -or "$v" -eq '') { return $false }
    try { $userTier = [int]$v } catch { return $false }
    $vals = @($Args.tierValues)
    if ($vals.Count -eq 0) { return $false }
    foreach ($t in $vals) { if ([int]$t -eq $userTier) { return $true } }
    return $false
}

function Test-SIKind_egKustoQuery {
    <# Consults per-rule kustoSets (built by Build-SIEgKustoQuerySets at IN).
       Caller (Invoke-SIDetect) injects __ruleId into Args so we know which set. #>
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Args)
    $ruleId = [string]$Args.__ruleId
    if ([string]::IsNullOrWhiteSpace($ruleId)) { return $false }

    $sets = if (Get-Variable -Name SIRuleIndexes -Scope Script -ErrorAction SilentlyContinue) { $script:SIRuleIndexes.kustoSets } else { $null }
    if (-not $sets -or -not $sets.ContainsKey($ruleId)) { return $false }
    $set = $sets[$ruleId]

    foreach ($f in @('PrimaryEntityId','EG_NodeId','MDE_DeviceId','AccountObjectId')) {
        $v = [string](Get-SIAssetField -Asset $Asset -Name $f)
        if ($v -and $set.Contains($v.ToLower())) { return $true }
    }
    return $false
}

# ----------------------------------------------------------------------------
# Registry (kind name -> handler function name)
# ----------------------------------------------------------------------------

$script:SIKindRegistry = @{
    # Implemented in 'nameMatches'                   = 'Test-SIKind_nameMatches'
    'osPlatform'                    = 'Test-SIKind_osPlatform'
    'hasMdeMachineGroupTag'         = 'Test-SIKind_hasMdeMachineGroupTag'
    'egDetectedRoles'               = 'Test-SIKind_egDetectedRoles'
    'hasEntraExtensionAttributeTag' = 'Test-SIKind_hasEntraExtensionAttributeTag'

    # Stubbed -- implemented in alongside their bulk-source builders:
    'hasSoftwareInstalled'          = 'Test-SIKind_hasSoftwareInstalled'
    'groupMembership'               = 'Test-SIKind_groupMembership'
    'hasAzureTagDirectOrParent'     = 'Test-SIKind_hasAzureTagDirectOrParent'
    'egKustoQuery'                  = 'Test-SIKind_egKustoQuery'
    'mostFrequentUserTier'          = 'Test-SIKind_mostFrequentUserTier'

    # IP-subnet match for CMDB / role mapping
    'ipInRange'                     = 'Test-SIKind_ipInRange'

    # cross-source-of-truth tag matcher (works on endpoint, identity,
    # azure -- walks MDE / EG / Entra / ARM / CMDB / AD carriers in one shot)
    'hasTag'                        = 'Test-SIKind_hasTag'
}

function Get-SIKindRegistry { $script:SIKindRegistry }

# ----------------------------------------------------------------------------
# Detection + rule evaluators
# ----------------------------------------------------------------------------

function Invoke-SIDetect {
    <#
        Walks the `any` (OR-semantics) or `all` (AND-semantics) list of
        kind specifications inside one detection. Returns $true on first
        match (any) or first non-match (all).

        $RuleId is optional context -- injected into each handler's Args
        as `__ruleId` so per-rule index handlers (egKustoQuery) can look
        up their pre-fetched set.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Asset,
        [Parameter(Mandatory)]$Detect,
        [Parameter()][string]$RuleId
    )

    # Detect comes from YAML as @{ any = [...] } or @{ all = [...] }
    $any = $false
    $all = $false
    $list = $null
    if ($Detect.any) { $list = @($Detect.any); $any = $true }
    elseif ($Detect.all) { $list = @($Detect.all); $all = $true }
    if (-not $list) { return $false }

    foreach ($spec in $list) {
        $kind = [string]$spec.kind
        if ([string]::IsNullOrWhiteSpace($kind)) { continue }
        if (-not $script:SIKindRegistry.ContainsKey($kind)) {
            Write-Verbose ('Invoke-SIDetect: unknown kind {0} -- skipping' -f $kind)
            if ($all) { return $false }   # all-mode: unknown kind = AND-failure
            continue
        }
        $handler = $script:SIKindRegistry[$kind]
        $argsHash = @{}
        # Strip 'kind' from the spec; everything else flows to the handler as Args
        if ($spec -is [System.Collections.IDictionary]) {
            foreach ($k in $spec.Keys) { if ($k -ne 'kind') { $argsHash[$k] = $spec[$k] } }
        } else {
            foreach ($p in $spec.PSObject.Properties) { if ($p.Name -ne 'kind') { $argsHash[$p.Name] = $p.Value } }
        }
        if ($RuleId) { $argsHash['__ruleId'] = $RuleId }
        try {
            $hit = & $handler -Asset $Asset -Args $argsHash
        } catch {
            Write-Verbose ('Invoke-SIDetect: handler {0} threw: {1}' -f $handler, $_.Exception.Message)
            $hit = $false
        }
        if ($any -and $hit) { return $true }
        if ($all -and -not $hit) { return $false }
    }
    return ($all)   # all-mode: reaching the end means every spec matched
}

function Invoke-SIRuleEval {
    <#
        Evaluates a single rule (one [pscustomobject] from Get-SIRuleSet)
        against one asset. Walks $Rule.Detections in array order (first
        match wins per ARCHITECTURE.md § 7). Returns either:
          $null                        when no detection matched
          [pscustomobject] @{          when a detection matched
              RuleId        = $Rule.Id
              DetectionId   = $matchedDet.Id
              Set           = $matchedDet.Set      # tier / purpose / category / cmdb*
              MatchedKinds  = @( ... )             # which kinds inside the match fired
          }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Asset,
        [Parameter(Mandatory)]$Rule
    )

    if ($Rule.Mode -eq 'disable') { return $null }
    if (-not $Rule.Detections -or @($Rule.Detections).Count -eq 0) { return $null }

    # Asset name used for per-detection ExcludeAssets matching. Pulled
    # once outside the detection loop because the asset is constant for
    # this call. Fallbacks (DeviceName -> FQDN -> ComputerName) cover
    # the schema differences across MDE / EG / Entra / ARM inputs.
    $assetName = $null
    foreach ($f in 'Name','DeviceName','FQDN','ComputerName','HostName') {
        $v = Get-SIAssetField -Asset $Asset -Name $f
        if (-not [string]::IsNullOrWhiteSpace([string]$v)) { $assetName = [string]$v; break }
    }

    foreach ($det in $Rule.Detections) {
        # Per-detection ExcludeAssets: device names / wildcards that
        # should be skipped by THIS detection even if the detect block
        # would match. Use when you can't remove the signal (legacy
        # software installed for compatibility reasons, etc.) but want
        # the asset out-of-scope for THIS specific detection. CI -like
        # match supports * and ? wildcards. Exact strings work too.
        if ($det.ExcludeAssets -and @($det.ExcludeAssets).Count -gt 0 -and $assetName) {
            $skip = $false
            foreach ($pat in $det.ExcludeAssets) {
                if ($assetName -like $pat) { $skip = $true; break }
            }
            if ($skip) { continue }
        }

        $hit = Invoke-SIDetect -Asset $Asset -Detect $det.Detect -RuleId $Rule.Id
        if ($hit) {
            return [pscustomobject]@{
                RuleId      = $Rule.Id
                DetectionId = $det.Id
                Set         = $det.Set
            }
        }
    }
    return $null
}

# ----------------------------------------------------------------------------
# Test harness (no engine integration -- run interactively)
# ----------------------------------------------------------------------------

function Test-SIRuleEval {
    <#
        Quick validator: loads all rules for an engine via Get-SIRuleSet,
        evaluates each against the supplied $Asset, returns matching rules
        as a list. Useful for "would this asset get tagged?" pre-flight.

        Usage:
          $sample = @{ Name='dc01'; MDE_MachineGroup='DomainControllers' }
          Test-SIRuleEval -Engine endpoint -Asset $sample
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('endpoint','identity','azure','publicip')]
        [string]$Engine,

        [Parameter(Mandatory)]
        $Asset
    )
    . (Join-Path $PSScriptRoot 'Get-SIRuleSet.ps1')
    $rules = Get-SIRuleSet -Engine $Engine
    $hits = New-Object System.Collections.ArrayList
    foreach ($r in $rules) {
        $hit = Invoke-SIRuleEval -Asset $Asset -Rule $r
        if ($hit) { [void]$hits.Add($hit) }
    }
    Write-Verbose ('Test-SIRuleEval: {0} rules evaluated, {1} matched' -f $rules.Count, $hits.Count)
    return $hits.ToArray()
}
