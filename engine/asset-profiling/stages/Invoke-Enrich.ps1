#Requires -Version 5.1
<#
    Enrich stage.

    For each asset that proceeded out of Collect: run the locked + custom
    posture-rule YAMLs as Kusto queries, fold in "has-access-to" + sign-in
    relationships, and run external enrichment plug-ins
    (disabled by default). Compute fp_enrich from the aggregated proof set;
    cached match -> Classify reuses prior verdict instead of calling AI.

    Real-Azure mode: each posture rule runs ONCE against MDE Advanced
    Hunting (one round-trip per rule, not per asset), then results are
    indexed by DeviceId and joined with the asset list.

    Mock mode: keeps the synthetic Hint-driven posture hits from so unit tests still work.
#>

function Expand-SIRuleParameters {
    <#
        Substitutes {{Name}} placeholders in a Query string with values from
        the rule's Parameters block. Unresolved placeholders trigger a
        warning + return the original Query untouched (safer than emitting
        a broken KQL string).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        $Parameters
    )

    if (-not $Parameters -or $Query -notmatch '{{') { return $Query }

    $expanded = $Query
    foreach ($k in @($Parameters.Keys)) {
        $token = '{{' + $k + '}}'
        $val   = [string]$Parameters[$k]
        $expanded = $expanded.Replace($token, $val)
    }
    if ($expanded -match '{{[^}]+}}') {
        Write-Warning ('Expand-SIRuleParameters: unresolved placeholder(s) remain in Query: {0}' -f ($matches[0]))
    }
    $expanded
}

function Get-SIPostureRules {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Engine)

    if (-not (Get-Module -Name 'powershell-yaml')) {
        Import-Module 'powershell-yaml' -Force -ErrorAction Stop
    }

    $v22Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $rules = New-Object System.Collections.ArrayList

    # Three folders, in order: locked (engine-shipped), custom (per-customer),
    # pending (AI-proposed drafts from schema-discovery -- NOT loaded by
    # default; opt-in via $global:SI_LoadPendingRules so AI-hallucinated
    # rules don't auto-spam).
    $folders = @('posture-rules-locked', 'posture-rules-custom')
    if ($global:SI_LoadPendingRules) { $folders += 'posture-rules-pending' }

    foreach ($folder in $folders) {
        $path = Join-Path $v22Root (Join-Path $folder $Engine)
        if (-not (Test-Path $path)) { continue }
        Get-ChildItem -Path $path -Filter '*.yaml' -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $y = Get-Content -Raw $_.FullName | ConvertFrom-Yaml -ErrorAction Stop   # surface yaml parse errors to outer try-catch instead of silently skipping the rule
                if ($y.AppliesTo -and $y.AppliesTo -ne $Engine) { return }

                # PostureRuleVersion default 1 (legacy schema). 2 = the v2
                # schema with Mode / QueryEngine / TargetTier / Parameters.
                $ver = if ($null -ne $y.PostureRuleVersion) { [int]$y.PostureRuleVersion } else { 1 }

                # RuleType selector (orthogonal to version):
                #   * KqlHunting   -- Query runs against a hunting/LA backend;
                #                     output indexed by DeviceId/AccountObjectId
                #   * AssetMetadata -- per-asset MatchOn eval against metadata
                #   * AssetTag     -- (block D) Query output is tag-apply instructions
                #   * Both         -- ClassificationProof + AssetTag from one query
                $ruleType = if ($y.RuleType) { [string]$y.RuleType } else { 'KqlHunting' }

                if ($ruleType -in 'KqlHunting','AssetTag','Both' -and [string]::IsNullOrWhiteSpace($y.Query)) { return }
                if ($ruleType -eq 'AssetMetadata' -and -not $y.MatchOn) { return }

                # v2 fields (default behaviour for v1 rules: Mode=Production,
                # QueryEngine=DefenderGraph, no TargetTier short-circuit).
                $mode        = if ($y.Mode)        { [string]$y.Mode }        else { 'Production' }
                $queryEngine = if ($y.QueryEngine) { [string]$y.QueryEngine } else { 'DefenderGraph' }
                $targetTier  = $null
                if ($null -ne $y.TargetTier) {
                    # Accept '0' / 'T0' / 0 forms.
                    $tt = [string]$y.TargetTier
                    if ($tt -match '^[0-9]$') { $targetTier = ('T' + $tt) }
                    elseif ($tt -match '^[Tt][0-9]$') { $targetTier = $tt.ToUpperInvariant() }
                    # TE dropped. T3 absorbs. Reject TE TargetTier
                    # in posture rules with a clear warning so authors update.
                    elseif ($tt -match '^[Tt][Ee]$')  {
                        Write-Warning ("Posture rule '{0}' uses TargetTier=TE which was dropped in . Coercing to T3." -f $y.Name)
                        $targetTier = 'T3'
                    }
                }

                # Customer-tunable Parameters override per-rule via convention:
                #   $global:SI_PostureRule_<RuleId>_<ParamName>
                # where RuleId = AssetTagName ?? Name. Lets a customer change
                # a threshold without forking the YAML.
                $parameters = $y.Parameters
                $ruleId     = if ($y.AssetTagName) { [string]$y.AssetTagName } else { [string]$y.Name }
                if ($parameters) {
                    foreach ($k in @($parameters.Keys)) {
                        $globalName = ('SI_PostureRule_{0}_{1}' -f ($ruleId -replace '[^A-Za-z0-9]','_'), $k)
                        $override   = (Get-Variable -Name $globalName -ValueOnly -Scope Global -ErrorAction SilentlyContinue)
                        if ($null -ne $override) { $parameters[$k] = $override }
                    }
                }

                [void]$rules.Add([pscustomobject]@{
                    Name               = if ($y.Name) { [string]$y.Name } else { $ruleId }
                    AssetTagName       = $ruleId
                    PostureRuleVersion = $ver
                    Mode               = $mode
                    QueryEngine        = $queryEngine
                    TargetTier         = $targetTier
                    ProofLabel         = $y.ProofLabel
                    ProofWeight        = if ($null -ne $y.ProofWeight) { [int]$y.ProofWeight } else { 50 }
                    RuleType           = $ruleType
                    Query              = if ($parameters) { Expand-SIRuleParameters -Query $y.Query -Parameters $parameters } else { $y.Query }
                    Parameters         = $parameters
                    MatchOn            = $y.MatchOn
                    AppliesToAssetType = $y.AppliesToAssetType
                    Folder             = $folder
                    File               = $_.Name
                })
            } catch {
                Write-Warning ('Skipping posture rule {0}: {1}' -f $_.Name, $_.Exception.Message)
            }
        }
    }
    $rules
}

function Test-SIAssetMatchesRule {
    <#
        Evaluates a rule's MatchOn block against the asset's metadata. All
        conditions are AND-ed. Operators:
          Equals, NotEquals, GreaterThan, GreaterThanOrEqual, LessThan,
          LessThanOrEqual, In, NotIn, Contains, StartsWith, EndsWith,
          IsNull, IsNotNull, IsTrue, IsFalse
        Returns $true when ALL conditions match. Empty MatchOn = no match
        (defensive). Unknown operator = warn + skip = no match.
    #>
    [CmdletBinding()]
    param(
        # fix: relax hashtable constraint -- records arrive as
        # PSCustomObject after staging-blob JSON round-trip.
        [Parameter(Mandatory)]$Metadata,
        [Parameter(Mandatory)]$MatchOn
    )

    if (-not $MatchOn -or @($MatchOn).Count -eq 0) { return $false }

    # Walk dotted Field path against $Metadata (works for nested EG rawData like
    # "EgRawData.isDomainController" or "EgRawData.managedIdentityMetadata.accountType").
    # Shape-tolerant: $Metadata + intermediate nodes may be hashtable OR pscustomobject.
    $resolveDottedPath = {
        param($Root, [string]$Path)
        if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
        $cur = $Root
        foreach ($seg in ($Path -split '\.')) {
            if ($null -eq $cur) { return $null }
            if ($cur -is [System.Collections.IDictionary]) {
                if ($cur.Contains($seg)) { $cur = $cur[$seg] } else { return $null }
            } elseif ($cur -is [psobject] -and $cur.PSObject.Properties[$seg]) {
                $cur = $cur.$seg
            } else { return $null }
        }
        return $cur
    }

    foreach ($cond in @($MatchOn)) {
        $field = [string]$cond.Field
        $op    = if ($cond.Op) { [string]$cond.Op } else { 'Equals' }
        $val   = $cond.Value
        $cur   = & $resolveDottedPath $Metadata $field

        $matched = switch ($op) {
            'Equals'             { $cur -eq $val }
            'NotEquals'          { $cur -ne $val }
            'GreaterThan'        { ($cur -as [double]) -gt ($val -as [double]) }
            'GreaterThanOrEqual' { ($cur -as [double]) -ge ($val -as [double]) }
            'LessThan'           { ($cur -as [double]) -lt ($val -as [double]) }
            'LessThanOrEqual'    { ($cur -as [double]) -le ($val -as [double]) }
            'In'                 { @($val) -contains $cur }
            'NotIn'              { -not (@($val) -contains $cur) }
            'Contains'           { ([string]$cur) -like ('*{0}*' -f [string]$val) }
            'ContainsAny'        {
                # $val is array of strings; $cur may be string OR array. True if any
                # value appears in the haystack(s).
                $hay = @($cur) | ForEach-Object { [string]$_ }
                $needles = @($val) | ForEach-Object { [string]$_ }
                $found = $false
                foreach ($n in $needles) {
                    foreach ($h in $hay) { if ($h -like ('*{0}*' -f $n)) { $found = $true; break } }
                    if ($found) { break }
                }
                $found
            }
            'StartsWith'         { ([string]$cur).StartsWith([string]$val, [System.StringComparison]::OrdinalIgnoreCase) }
            'EndsWith'           { ([string]$cur).EndsWith([string]$val, [System.StringComparison]::OrdinalIgnoreCase) }
            'RegexMatch'         {
                # .NET regex; $val is the pattern (can carry inline (?i) for case-insensitive).
                # Handles array-valued $cur (any element matches = true).
                $pattern = [string]$val
                $any = $false
                foreach ($item in @($cur)) {
                    if ([string]$item -match $pattern) { $any = $true; break }
                }
                $any
            }
            'IsNull'             { $null -eq $cur -or [string]::IsNullOrWhiteSpace([string]$cur) }
            'IsNotNull'          { $null -ne $cur -and -not [string]::IsNullOrWhiteSpace([string]$cur) }
            'IsTrue'             { [bool]$cur }
            'IsFalse'            { -not [bool]$cur }
            default              { Write-Warning ("Unknown MatchOn operator '{0}' -- treating as no-match" -f $op); $false }
        }
        if (-not $matched) { return $false }
    }
    return $true
}

# Invoke-SIHuntingQuery extracted to ../shared/HuntingQuery.ps1
# so the schema-discovery pipeline can dot-source it without pulling in
# all of Stage Enrich. This block dot-sources the shared file so existing
# Stage Enrich callers keep working unchanged.
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\HuntingQuery.ps1')

function Get-SIEndpointTierMap {
    <#
        Cross-engine reference -- pulls the latest tier per endpoint from the
        SI_Endpoint_Classification_CL table written by the endpoint engine.
        Returns a map: lowercased DeviceName -> @{ Tier; ServiceType; ServiceName; AssetId }.
        Empty map on failure (table doesn't exist yet, no perms, ...) -- the
        identity engine continues without the cross-reference.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$WorkspaceResourceId)

    if ([string]::IsNullOrWhiteSpace($WorkspaceResourceId)) { return @{} }
    $workspaceGuid = $null
    try {
        # parse ARM ID + use -ResourceGroupName -Name (PS 5.1 doesn't accept -ResourceId)
        if ($WorkspaceResourceId -notmatch '^/subscriptions/(?<sub>[^/]+)/resourceGroups/(?<rg>[^/]+)/providers/Microsoft\.OperationalInsights/workspaces/(?<name>[^/]+)$') {
            throw "WorkspaceResourceId malformed: $WorkspaceResourceId"
        }
        $sub = $matches.sub; $rg = $matches.rg; $name = $matches.name
        $prevCtx = Get-AzContext
        if (-not $prevCtx -or $prevCtx.Subscription.Id -ne $sub) {
            Set-AzContext -SubscriptionId $sub -WarningAction SilentlyContinue | Out-Null
        }
        $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $name -ErrorAction Stop
        $workspaceGuid = $ws.CustomerId.Guid
    } catch {
        Write-Warning ('Get-SIEndpointTierMap: workspace lookup failed -- {0}' -f $_.Exception.Message)
        return @{}
    }

    # Endpoint engine writes to SI_Endpoint_Profile_CL (default SI_ prefix).
    # Schema columns are unprefixed (Tier, AssetType, Hostname) -- driven by
    # endpoint.schema.json. arg_max key is PrimaryEntityId (schema-driven row
    # builder doesn't emit AssetId; PrimaryEntityId is the canonical id).
    $kql = @"
SI_Endpoint_Profile_CL
| where TimeGenerated > ago(7d)
| where isnotnull(Tier)
| summarize arg_max(TimeGenerated, *) by PrimaryEntityId
| project PrimaryEntityId,
          DeviceNameLower = tolower(coalesce(Hostname, PrimaryEntityId)),
          Tier, AssetType
"@
    try {
        $resp = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceGuid -Query $kql -ErrorAction Stop
    } catch {
        # same existence-probe pattern as the identity counterpart.
        $msg = $_.Exception.Message
        $tableName = 'SI_Endpoint_Profile_CL'
        $tableMissing = $false
        try {
            Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceGuid -Query ($tableName + ' | take 0') -ErrorAction Stop | Out-Null
        } catch {
            $tableMissing = $true
        }
        if ($tableMissing) {
            Write-SIInfo ('[x-engine] {0} not yet present -- run endpoint engine first to populate cross-engine endpoint tier lookups (skipping)' -f $tableName)
        } else {
            Write-Warning ('Get-SIEndpointTierMap: table {0} exists but the cross-engine KQL failed -- {1}. Continuing without endpoint-tier overlay.' -f $tableName, $msg)
        }
        return @{}
    }

    $map = @{}
    foreach ($r in $resp.Results) {
        $key = $r.DeviceNameLower
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        $tierInt = $null
        $ts = [string]$r.Tier
        if ($ts -match '^(\d)$' -and [int]$matches[1] -in 0..3) { $tierInt = [int]$matches[1] }
        $map[$key] = @{
            AssetId     = $r.PrimaryEntityId
            Tier        = $tierInt
            ServiceType = $r.AssetType
        }
    }
    return $map
}

function Get-SIIdentityTierMap {
    <#
        Cross-engine reference for the AZURE engine -- pulls latest tier per
        identity from SI_Identity_Classification_CL. Returns a map keyed by
        lowercased UPN / displayName / objectId so a downstream join with
        EG edge SourceNodeName has a chance regardless of which form EG
        uses for that source identity.

        Empty map on any failure (table missing, no perms, ...).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$WorkspaceResourceId)

    if ([string]::IsNullOrWhiteSpace($WorkspaceResourceId)) { return @{} }
    $workspaceGuid = $null
    try {
        # parse ARM ID + use -ResourceGroupName -Name (PS 5.1 doesn't accept -ResourceId)
        if ($WorkspaceResourceId -notmatch '^/subscriptions/(?<sub>[^/]+)/resourceGroups/(?<rg>[^/]+)/providers/Microsoft\.OperationalInsights/workspaces/(?<name>[^/]+)$') {
            throw "WorkspaceResourceId malformed: $WorkspaceResourceId"
        }
        $sub = $matches.sub; $rg = $matches.rg; $name = $matches.name
        $prevCtx = Get-AzContext
        if (-not $prevCtx -or $prevCtx.Subscription.Id -ne $sub) {
            Set-AzContext -SubscriptionId $sub -WarningAction SilentlyContinue | Out-Null
        }
        $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $name -ErrorAction Stop
        $workspaceGuid = $ws.CustomerId.Guid
    } catch {
        Write-Warning ('Get-SIIdentityTierMap: workspace lookup failed -- {0}' -f $_.Exception.Message)
        return @{}
    }

    # Identity engine writes to SI_Identity_Profile_CL (default SI_ prefix).
    # Schema columns are unprefixed -- driven by identity.schema.json.
    # PrimaryEntityId is the canonical AAD GUID (schema-driven row builder
    # strips the entra-user:/sp: prefix before emit) and is the arg_max key
    # (no AssetId column emitted).
    # identity schema has IdentityType (User|ServicePrincipal|
    # ManagedIdentity), NOT AssetType (which is endpoint-only). Referencing
    # AssetType triggered a KQL SemanticError => "BadRequest" wrapper from the
    # LA SDK. The downstream consumer expected AssetType, so we alias here.
    $kql = @"
SI_Identity_Profile_CL
| where TimeGenerated > ago(7d)
| where isnotnull(Tier)
| summarize arg_max(TimeGenerated, *) by PrimaryEntityId
| project PrimaryEntityId,
          ObjectId   = tolower(PrimaryEntityId),
          NameKey    = tolower(coalesce(DisplayName, Upn, PrimaryEntityId)),
          Tier,
          AssetType  = IdentityType
"@
    try {
        $resp = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceGuid -Query $kql -ErrorAction Stop
    } catch {
        # the LA SDK wraps real errors as "Operation returned an
        # invalid status code 'BadRequest'" without the inner reason. Distinguish
        # "table missing" from "query bug" via a cheap existence probe (`<table>
        # | take 0`) -- returns instantly without scanning data. If THAT also
        # fails, the table really is missing (friendly skip). If it succeeds,
        # our complex query has a bug (warn so we can see + fix).
        $msg = $_.Exception.Message
        $tableName = 'SI_Identity_Profile_CL'
        $tableMissing = $false
        try {
            Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceGuid -Query ($tableName + ' | take 0') -ErrorAction Stop | Out-Null
        } catch {
            $tableMissing = $true
        }
        if ($tableMissing) {
            Write-SIInfo ('[x-engine] {0} not yet present -- run identity engine first to populate cross-engine identity tier lookups (skipping)' -f $tableName)
        } else {
            Write-Warning ('Get-SIIdentityTierMap: table {0} exists but the cross-engine KQL failed -- {1}. Continuing without identity-tier overlay.' -f $tableName, $msg)
        }
        return @{}
    }

    $map = @{}
    foreach ($r in $resp.Results) {
        $tierInt = $null
        $ts = [string]$r.Tier
        if ($ts -match '^(\d)$' -and [int]$matches[1] -in 0..3) { $tierInt = [int]$matches[1] }
        $info = @{
            AssetId     = $r.PrimaryEntityId
            Tier        = $tierInt
            ServiceType = $r.AssetType
        }
        # Index by both display-name and object-id form so EG SourceNodeName
        # can be either.
        if ($r.NameKey)  { $map[$r.NameKey]  = $info }
        if ($r.ObjectId) { $map[$r.ObjectId] = $info }
    }
    return $map
}

function Get-SIDeviceLogonsByUserObjectId {
    <#
        For every user ObjectId, returns the set of devices they signed into
        in the last 30 days (interactive + remote interactive only -- noisy
        network/service logons excluded).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$UserObjectIds)

    if ($UserObjectIds.Count -eq 0) { return @{} }
    $idList = ($UserObjectIds | ForEach-Object { "'$($_.ToLowerInvariant())'" }) -join ','
    # DeviceLogonEvents in Defender XDR Adv Hunting has NO
    # AccountObjectId column. Join with IdentityInfo to translate ObjectId <->
    # SID before filtering DeviceLogonEvents.
    # IdentityInfo SID column case varies across tenants (AccountSID vs
    # AccountSid). column_ifexists picks whichever exists; "" default keeps
    # the schema stable and gets filtered out by the AccountSid != '' clause.
    $kql = @"
let users = IdentityInfo
    | summarize arg_max(Timestamp, *) by AccountObjectId
    | where tolower(AccountObjectId) in ($idList)
    | extend AccountSid = coalesce(column_ifexists("AccountSid", ""), column_ifexists("AccountSID", ""))
    | project AccountObjectId, AccountSid;
DeviceLogonEvents
| where Timestamp > ago(30d)
| where LogonType in ('Interactive','RemoteInteractive')
| where AccountSid != ''
| join kind=inner users on AccountSid
| summarize Devices = make_set(tolower(DeviceName), 100) by AccountObjectId
"@
    $rows = Invoke-SIHuntingQuery -Query $kql
    $byUser = @{}
    foreach ($r in $rows) {
        if ($r.AccountObjectId) {
            $byUser[([string]$r.AccountObjectId).ToLowerInvariant()] = $r.Devices
        }
    }
    return $byUser
}

function Get-SIBulkTvmSoftwareInventory {
    <#
        ONE bulk hunting query returns the installed-software set per device
        ID. Output: hashtable keyed by DeviceId (lower-case) -> array of
        @{ Vendor; Name; Version }. Capped at 200 distinct apps per device by
        the KQL make_set arg to avoid blob bloat. Devices with no rows in
        DeviceTvmSoftwareInventory simply don't appear in the result map; the
        caller treats that as "no installed-app match" rather than a failure.

        DeviceTvmSoftwareInventory is populated by MDE Defender Vulnerability
        Management. Devices without MDE coverage will be absent. The caller
        should not assume every input DeviceId comes back.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$DeviceIds)

    if ($null -eq $DeviceIds -or $DeviceIds.Count -eq 0) { return @{} }

    # De-dupe + lower-case for the IN-clause. Matches the same pattern
    # Get-SIDeviceLogonsByUserObjectId uses for ObjectIds.
    $unique = @($DeviceIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    if ($unique.Count -eq 0) { return @{} }

    $idList = ($unique | ForEach-Object { "'$_'" }) -join ','
    $kql = @"
DeviceTvmSoftwareInventory
| where tolower(DeviceId) in ($idList)
| summarize Software = make_set(strcat(SoftwareVendor, '|', SoftwareName, '|', SoftwareVersion), 200) by DeviceId
"@

    $rows = Invoke-SIHuntingQuery -Query $kql
    $byDevice = @{}
    if ($null -eq $rows) { return $byDevice }
    foreach ($r in $rows) {
        if (-not $r.DeviceId) { continue }
        $devKey = ([string]$r.DeviceId).ToLowerInvariant()
        $apps = New-Object System.Collections.Generic.List[object]
        $sw = $r.Software
        if ($null -ne $sw) {
            # make_set returns an array (after Graph round-trip via JSON it
            # stays an array). Defensive: tolerate string + scalar shapes too.
            if ($sw -is [string]) {
                $sw = @($sw)
            } elseif (-not ($sw -is [System.Collections.IEnumerable])) {
                $sw = @($sw)
            }
            foreach ($entry in $sw) {
                $s = [string]$entry
                if ([string]::IsNullOrWhiteSpace($s)) { continue }
                $parts = $s -split '\|', 3
                if ($parts.Count -lt 2) { continue }
                $vendor  = $parts[0]
                $name    = $parts[1]
                $version = if ($parts.Count -ge 3) { $parts[2] } else { '' }
                if ([string]::IsNullOrWhiteSpace($vendor) -or [string]::IsNullOrWhiteSpace($name)) { continue }
                [void]$apps.Add(@{
                    Vendor  = $vendor
                    Name    = $name
                    Version = $version
                })
            }
        }
        $byDevice[$devKey] = $apps.ToArray()
    }
    return $byDevice
}

function Get-SIBulkDeviceUserCorrelation {
    <#
        Cross-engine join: for each device, find frequent logon users from
        Exposure Graph "frequently logged in" edges, then look up their tier
        in SI_Identity_Profile_CL.

        REWRITTEN to use Exposure Graph instead of DeviceLogonEvents.
        EG already computes the user-device "frequently logged in" relationship
        as a graph edge -- no SID->AAD join, no AccountSid filter, no
        cloud-vs-onprem split. One query against ExposureGraphEdges/Nodes.

        Input keys CHANGED: now AAD device IDs (was MdeDeviceId). EG indexes
        on AAD device id; the caller must pass that. The output hashtable is
        keyed by AAD device id (lower-case).

        Returns: @{ <aadDeviceId-lower> = @{
            MostFrequentUserTier   = <int 0-3 or $null>
            MostFrequentUsers      = @( @{ Upn; Tier; LogonCount } )
            MostFrequentUsersCount = <distinct user count>
        }}

        LogonCount is always 1 (EG snapshot has one edge per user-device
        relationship, no per-event count). Field name kept for API stability.

        Identity engine MUST have run before this -- otherwise SI_Identity_Profile_CL
        is empty / stale and every device gets MostFrequentUserTier=$null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$AadDeviceIds,
        [int]$LookbackDays = 3,   # ignored for EG (snapshot, not time-series); kept for API stability
        [int]$TopN         = 5
    )

    $null = $LookbackDays   # explicit unused-but-kept-for-API
    if ($AadDeviceIds.Count -eq 0) { return @{} }
    $clean = $AadDeviceIds | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Select-Object -Unique
    if (@($clean).Count -eq 0) { return @{} }

    # ---- Query 1: EG "frequently logged in" / "signed in" edges (Defender XDR) ----
    # Schema-defensive: parse_json(NodeProperties).rawData covers both shapes
    # (string vs object) and we coalesce across known field-name variants for
    # AadObjectId / UPN per the canonical query the user validated 2026-04-30.
    $idList = ($clean | ForEach-Object { "'$_'" }) -join ','
    $logonKql = @"
let deviceNodes = ExposureGraphNodes
    | where Categories has "device"
    | extend rd = parse_json(NodeProperties).rawData
    | extend AadDeviceId = tolower(tostring(coalesce(
        rd.aadDeviceId, rd.azureAdDeviceId, rd.deviceId, rd.aadId
      )))
    | where isnotempty(AadDeviceId) and AadDeviceId in ($idList)
    | project DeviceNodeId = NodeId, AadDeviceId, DeviceName = NodeName;
let userNodes = ExposureGraphNodes
    | where Categories has_any ("identity", "user")
    | extend rd = parse_json(NodeProperties).rawData
    | extend
        AadObjectId = tolower(tostring(coalesce(
            rd.aadObjectId, rd.azureAdObjectId, rd.objectId, rd.accountObjectId, rd.aadId
          ))),
        UserUpn = tostring(coalesce(
            rd.accountUpn, rd.userPrincipalName, rd.upn, rd.accountName
          )),
        UserDisplayName = tostring(coalesce(
            rd.accountDisplayName, rd.displayName, rd.name
          ))
    | where isnotempty(AadObjectId)
    | project UserNodeId = NodeId, AadObjectId, UserUpn, UserDisplayName, UserName = NodeName;
let logonEdges = ExposureGraphEdges
    | where EdgeLabel has_any ("logged", "logon", "signed in")
    | project EdgeLabel, SourceNodeId, TargetNodeId;
logonEdges
| join kind=inner deviceNodes on `$left.SourceNodeId == `$right.DeviceNodeId
| join kind=inner userNodes   on `$left.TargetNodeId == `$right.UserNodeId
| union (
    logonEdges
    | join kind=inner deviceNodes on `$left.TargetNodeId == `$right.DeviceNodeId
    | join kind=inner userNodes   on `$left.SourceNodeId == `$right.UserNodeId
)
| summarize EdgeLabels = make_set(EdgeLabel) by AadDeviceId, AccountObjectId = AadObjectId, AccountUpn = coalesce(UserUpn, UserDisplayName, UserName)
| extend LogonCount = 1
"@
    $logonRows = @()
    try {
        $logonRows = @(Invoke-SIHuntingQuery -Query $logonKql)
    } catch {
        Write-Warning ('Get-SIBulkDeviceUserCorrelation: ExposureGraph query failed -- {0}. MostFrequentUser* fields will be empty for this run.' -f $_.Exception.Message)
        return @{}
    }
    if ($logonRows.Count -eq 0) { return @{} }

    # ---- Query 2: current user-tier snapshot from Identity_Profile_CL (LA) ----
    $userObjectIds = $logonRows | ForEach-Object { ([string]$_.AccountObjectId).ToLowerInvariant() } | Select-Object -Unique
    $userIdList    = ($userObjectIds | ForEach-Object { "'$_'" }) -join ','
    $userTierMap   = @{}
    if ($userIdList) {
        # SI_Identity_Profile_CL lives in the SENTINEL workspace
        # (it's a custom log written by SI's identity engine), NOT the Defender
        # XDR workspace. Previously this used $SI_DefenderWorkspaceResourceId
        # which targeted the wrong workspace -> 0 rows -> every MostFrequentUsers
        # entry had Tier=null -> LogonByMostFrequentUser rule never fired in
        # Profile. Always use $SI_WorkspaceResourceId (the Sentinel workspace).
        $sentinelWs = $global:SI_WorkspaceResourceId
        $idTierKql = @"
SI_Identity_Profile_CL
| where TimeGenerated > ago(7d)
| where tolower(PrimaryEntityId) in ($userIdList)
| summarize arg_max(TimeGenerated, *) by PrimaryEntityId
| project AccountObjectId = tolower(PrimaryEntityId), Tier = toint(Tier), Upn
"@
        try {
            # Lazy-load Resolve-SIWorkspaceFromResourceId (lives in IdentityRoleFetcher.ps1).
            # Enrich's dot-source order doesn't always pull it in; load on demand.
            if (-not (Get-Command Resolve-SIWorkspaceFromResourceId -ErrorAction SilentlyContinue)) {
                . (Join-Path $PSScriptRoot '..\shared\IdentityRoleFetcher.ps1')
            }
            $ws = Resolve-SIWorkspaceFromResourceId -ResourceId $sentinelWs
            $resp = Invoke-AzOperationalInsightsQuery -WorkspaceId $ws.CustomerId.Guid -Query $idTierKql -ErrorAction Stop
            $rowCount = if ($resp -and $resp.Results) { @($resp.Results).Count } else { 0 }

            foreach ($row in $resp.Results) {
                # Defensive read: rows may arrive as PSCustomObject OR IDictionary
                # depending on Az.OperationalInsights version. Walk both shapes.
                $oid = $null; $tierRaw = $null; $upn = $null
                if ($row -is [System.Collections.IDictionary]) {
                    if ($row.Contains('AccountObjectId')) { $oid = $row['AccountObjectId'] }
                    if ($row.Contains('Tier'))            { $tierRaw = $row['Tier'] }
                    if ($row.Contains('Upn'))             { $upn = $row['Upn'] }
                } else {
                    if ($row.PSObject.Properties['AccountObjectId']) { $oid = $row.PSObject.Properties['AccountObjectId'].Value }
                    if ($row.PSObject.Properties['Tier'])            { $tierRaw = $row.PSObject.Properties['Tier'].Value }
                    if ($row.PSObject.Properties['Upn'])             { $upn = $row.PSObject.Properties['Upn'].Value }
                }
                if ([string]::IsNullOrWhiteSpace([string]$oid)) { continue }

                # Defensive int conversion -- KQL may return long/decimal/string
                $tierInt = $null
                if ($null -ne $tierRaw -and "$tierRaw" -ne '') {
                    try { $tierInt = [int][string]$tierRaw } catch { $tierInt = $null }
                }
                $userTierMap[[string]$oid] = @{
                    Tier = $tierInt
                    Upn  = [string]$upn
                }
            }
            if ($userTierMap.Count -eq 0 -and $rowCount -gt 0) {
                # Rows came back but none made it into the map -- shape mismatch.
                # Surface the column names so the operator can fix the row reader.
                $first = @($resp.Results)[0]
                $cols = if ($first -is [System.Collections.IDictionary]) { ($first.Keys -join ',') } else { ($first.PSObject.Properties.Name -join ',') }
                Write-Warning ('CL lookup returned {0} row(s) but 0 mapped. First row columns=[{1}]' -f $rowCount, $cols)
            }
            Write-SIInfo ('[perms] identity tier lookup: queried {0} user(s), resolved {1} to a known tier from SI_Identity_Profile_CL' -f $userObjectIds.Count, $userTierMap.Count)
        } catch {
            Write-Warning ('Get-SIBulkDeviceUserCorrelation: SI_Identity_Profile_CL lookup failed -- {0}. MostFrequentUser* will be empty (run identity engine first).' -f $_.Exception.Message)
            # Continue with empty map -- per-device matcher will report MostFrequentUserTier=$null.
        }
    }

    # ---- Per-device join: walk top-N users, find MIN tier, build proofs ----
    $byDevice = @{}
    foreach ($r in $logonRows) {
        $devKey = ([string]$r.AadDeviceId).ToLowerInvariant()
        if (-not $byDevice.ContainsKey($devKey)) {
            $byDevice[$devKey] = @{
                MostFrequentUserTier   = $null
                MostFrequentUsers      = New-Object System.Collections.ArrayList
                MostFrequentUsersCount = 0
            }
        }
        $bucket = $byDevice[$devKey]
        $userKey = ([string]$r.AccountObjectId).ToLowerInvariant()
        $userInfo = $userTierMap[$userKey]
        $tier = if ($userInfo) { $userInfo.Tier } else { $null }
        $upn  = if ($userInfo -and $userInfo.Upn) { $userInfo.Upn } else { [string]$r.AccountUpn }

        [void]$bucket.MostFrequentUsers.Add(@{
            Upn        = $upn
            Tier       = $tier
            LogonCount = [int]$r.LogonCount
        })
        $bucket.MostFrequentUsersCount++

        # Track MIN tier across all frequent users (only when user has a known tier)
        if ($null -ne $tier) {
            if ($null -eq $bucket.MostFrequentUserTier -or $tier -lt $bucket.MostFrequentUserTier) {
                $bucket.MostFrequentUserTier = $tier
            }
        }
    }

    # Convert ArrayList to regular array for downstream JSON serialisation
    foreach ($k in @($byDevice.Keys)) {
        $byDevice[$k].MostFrequentUsers = $byDevice[$k].MostFrequentUsers.ToArray()
    }
    return $byDevice
}

function Get-SISignInsByUserObjectId {
    <#
        Per-user sign-in stat enrichment for identity Profile rows.
        Outputs (per AccountObjectId): SignInCount, Successful/FailedSignIns,
        LastSignIn, DistinctApps/IPs/Countries, Apps[]. These flow into
        ENTRA_SignIn* columns on SI_Identity_Profile_CL and feed RA Identity
        reports.

        scaling + cascade hardening for very large tenants.
          - Escape hatch: $global:SI_EnableSignInEnrich = $false  -> skip entirely
            (Graph signInActivity still gives LastSignIn separately).
          - Configurable lookback: $global:SI_SignInLookbackDays (default 30).
          - IN-clause batched (default 200 IDs/batch via $global:SI_SignInBatchSize)
            to dodge per-query memory + 8MB body limits.
          - Project early so dcount/make_set don't carry full ~50-col rows.
          - Source cascade per batch:
              1. EntraIdSignInEvents (Defender XDR -- GA)
              2. AADSignInEventsBeta (Defender XDR -- legacy)
              3. SigninLogs (Sentinel/LA -- last resort)
            Errors only surface when all three fail for that batch.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$UserObjectIds)

    if ($UserObjectIds.Count -eq 0) { return @{} }

    if ($global:SI_EnableSignInEnrich -eq $false) {
        Write-SIInfo '[perms] sign-in enrichment SKIPPED ($global:SI_EnableSignInEnrich=$false). LastSignIn still flows via Graph signInActivity.'
        return @{}
    }

    # huge-tenant guardrail. SigninLogs in tenants > ~10k users
    # is typically billions of rows over 30d -- scanning it 2500+ times for
    # batched IN-clauses will time out OR hit memory limits OR cost a fortune.
    # Above this threshold we skip the per-user enrichment and rely on Graph
    # signInActivity for LastSignIn. Operators can:
    #   (a) raise $global:SI_SignInEnrichMax if their tenant is fast/small,
    #   (b) pre-filter the userIds list to only ACTIVE users (Graph
    #       signInActivity.lastSignInDateTime within lookback), which is
    #       typically 10-30% of the population in big tenants, OR
    #   (c) accept the gap -- counts/distincts/apps just won't populate.
    $maxUsers = if ($global:SI_SignInEnrichMax) { [int]$global:SI_SignInEnrichMax } else { 25000 }
    if ($UserObjectIds.Count -gt $maxUsers) {
        Write-SIWarn ('[perms] sign-in enrichment SKIPPED -- {0} users exceeds threshold {1} ($global:SI_SignInEnrichMax). For tenants this size, pre-filter userIds to only ACTIVE users (Graph signInActivity within lookback) before calling, OR set $global:SI_EnableSignInEnrich=$false to silence this warning.' -f $UserObjectIds.Count, $maxUsers)
        return @{}
    }

    $lookback  = if ($global:SI_SignInLookbackDays) { [int]$global:SI_SignInLookbackDays } else { 7 }
    $batchSize = if ($global:SI_SignInBatchSize)    { [int]$global:SI_SignInBatchSize }    else { 200 }

    $batches = New-Object System.Collections.ArrayList
    for ($s = 0; $s -lt $UserObjectIds.Count; $s += $batchSize) {
        $end = [Math]::Min($s + $batchSize - 1, $UserObjectIds.Count - 1)
        [void]$batches.Add(@($UserObjectIds[$s..$end]))
    }

    $byId   = @{}
    $errors = New-Object System.Collections.Generic.List[string]
    Write-SIInfo ('[perms] sign-in enrichment: {0} users in {1} batch(es), lookback={2}d' -f $UserObjectIds.Count, $batches.Count, $lookback)
    Reset-SIProgress -Label 'SignInBatches' -ErrorAction SilentlyContinue

    for ($bi = 0; $bi -lt $batches.Count; $bi++) {
        try { Write-SIProgress -Label 'SignInBatches' -Index ($bi + 1) -Total $batches.Count } catch { }
        $batch  = $batches[$bi]
        $idList = ($batch | ForEach-Object { "'$($_.ToLowerInvariant())'" }) -join ','

        # XDR tail: project early so dcount/make_set don't carry full ~50-col rows.
        $xdrTail = @"
| where Timestamp > ago($($lookback)d)
| where tolower(AccountObjectId) in ($idList)
| project AccountObjectId, Timestamp, ErrorCode, ApplicationId, IPAddress, Country, Application
| summarize
    SignInCount       = count(),
    SuccessfulSignIns = countif(ErrorCode == 0),
    FailedSignIns     = countif(ErrorCode != 0),
    LastSignIn        = max(Timestamp),
    DistinctApps      = dcount(ApplicationId),
    DistinctIPs       = dcount(IPAddress),
    DistinctCountries = dcount(Country),
    Apps              = make_set_if(Application, isnotempty(Application), 10)
  by AccountObjectId
"@
        $laQuery = @"
SigninLogs
| where TimeGenerated > ago($($lookback)d)
| where tolower(UserId) in ($idList)
| project UserId, TimeGenerated, ResultType, AppId, AppDisplayName, IPAddress, LocationDetails
| summarize
    SignInCount       = count(),
    SuccessfulSignIns = countif(ResultType == 0),
    FailedSignIns     = countif(ResultType != 0),
    LastSignIn        = max(TimeGenerated),
    DistinctApps      = dcount(AppId),
    DistinctIPs       = dcount(IPAddress),
    DistinctCountries = dcount(tostring(LocationDetails.countryOrRegion)),
    Apps              = make_set_if(AppDisplayName, isnotempty(AppDisplayName), 10)
  by UserId
| extend AccountObjectId = UserId
| project-away UserId
"@

        $attempts = @(
            @{ Label = 'EntraIdSignInEvents (XDR GA)';     Engine = 'DefenderGraph'; Query = "EntraIdSignInEvents`n$xdrTail" },
            @{ Label = 'AADSignInEventsBeta (XDR legacy)'; Engine = 'DefenderGraph'; Query = "AADSignInEventsBeta`n$xdrTail" },
            @{ Label = 'SigninLogs (Sentinel/LA)';         Engine = 'LogAnalytics';  Query = $laQuery }
        )

        $batchOk = $false
        foreach ($a in $attempts) {
            $w = $null
            $r = $null
            try {
                $r = @(Invoke-SIHuntingQuery -Query $a.Query -QueryEngine $a.Engine -WarningVariable w -WarningAction SilentlyContinue)
            } catch {
                $errors.Add(("batch {0}/{1} {2}: {3}" -f ($bi + 1), $batches.Count, $a.Label, $_.Exception.Message))
                continue
            }
            if ($w -and $w.Count -gt 0) {
                $errors.Add(("batch {0}/{1} {2}: {3}" -f ($bi + 1), $batches.Count, $a.Label, ($w -join ' | ')))
                continue
            }
            foreach ($row in $r) {
                if ($row.AccountObjectId) { $byId[([string]$row.AccountObjectId).ToLowerInvariant()] = $row }
            }
            $batchOk = $true
            break
        }
        if (-not $batchOk) {
            Write-SIWarn ("[perms] sign-in batch {0}/{1} failed across all sources" -f ($bi + 1), $batches.Count)
        }
    }

    if ($byId.Count -eq 0 -and $errors.Count -gt 0) {
        Write-SIWarn '[perms] sign-in lookup produced 0 rows; sign-in fields will be empty for this run'
        foreach ($e in $errors) { Write-SIWarn ("  - {0}" -f $e) }
    }
    Write-SIInfo ('[perms] sign-in enrichment: {0} principals matched' -f $byId.Count)
    return $byId
}

function Get-SILogonsByDeviceName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$DeviceNames)

    if ($DeviceNames.Count -eq 0) { return @{} }

    # Same ASCII-only filter as Get-SIDeviceInfoByName -- non-ASCII names
    # break the round-trip and 400 the whole batch.
    $cleanNames = $DeviceNames | Where-Object { $_ -match '^[\x20-\x7E]+$' }
    if ($cleanNames.Count -eq 0) { return @{} }

    # pass BOTH the FQDN AND the short-name -- MDE_DeviceName
    # returns FQDN ('dc1.2linkit.local') while DeviceLogonEvents.DeviceName
    # uses short name ('dc1'). Without both forms the IN-clause never matches
    # and the logon-tier promotion ("primary user") signal stays empty for
    # every device. Build a set of variants per input.
    $variants = New-Object System.Collections.Generic.HashSet[string]
    foreach ($n in $cleanNames) {
        $low = ([string]$n).ToLowerInvariant()
        [void]$variants.Add($low)
        if ($low.Contains('.')) {
            [void]$variants.Add($low.Substring(0, $low.IndexOf('.')))
        }
    }
    $nameList = (@($variants) | ForEach-Object { "'$($_ -replace '''', '''''')'" }) -join ','
    # Interactive logon types ONLY (Interactive / RemoteInteractive /
    # CachedInteractive). Non-interactive logons (Network, Service, Batch,
    # Unlock, NetworkClearText, NewCredentials) don't represent a user
    # actually USING the device -- they're machine-account chatter and
    # service auth that pollute the "primary users" signal we use to drive
    # device tier classification.
    $kql = @"
DeviceLogonEvents
| where Timestamp > ago(30d)
| where tolower(DeviceName) in ($nameList)
| where LogonType in ('Interactive','RemoteInteractive','CachedInteractive')
| where ActionType == 'LogonSuccess'
| where AccountName != '' and AccountName != 'system'
| summarize
    LogonCount    = count(),
    LastLogon     = max(Timestamp),
    Accounts      = make_set(AccountName, 50),
    LogonTypes    = make_set(LogonType, 10)
  by DeviceName
"@

    $rows = Invoke-SIHuntingQuery -Query $kql
    $byName = @{}
    # index returned rows under BOTH DeviceLogonEvents' short
    # name AND -- if any of the input FQDNs share that short prefix -- the
    # FQDN form, so the caller's lookup by either form hits.
    $shortToFqdn = @{}
    foreach ($n in $cleanNames) {
        $low = ([string]$n).ToLowerInvariant()
        if ($low.Contains('.')) {
            $shrt = $low.Substring(0, $low.IndexOf('.'))
            if (-not $shortToFqdn.ContainsKey($shrt)) { $shortToFqdn[$shrt] = New-Object System.Collections.ArrayList }
            [void]$shortToFqdn[$shrt].Add($low)
        }
    }
    foreach ($r in $rows) {
        if (-not $r.DeviceName) { continue }
        $key = ([string]$r.DeviceName).ToLowerInvariant()
        $byName[$key] = $r
        if ($shortToFqdn.ContainsKey($key)) {
            foreach ($fqdn in $shortToFqdn[$key]) { $byName[$fqdn] = $r }
        }
    }
    return $byName
}

# --- Signal-map AI cache ---
# AI per (engine, assetType) decides which fields drive criticality + how
# much. Cached in sitypeprofiles partition='signalmap'. Stage Enrich
# computes XENG_CriticalityScore = sum of (active signal value -> weight
# contribution). One AI call per uncached (engine, assetType, promptVersion).
$script:SI_SignalMap_DefaultVersion = 'v1'

$script:SI_SignalMap_SystemPrompt = @'
You analyze ASSETS for a security-posture engine. Given ONE sample asset
of a given engine + asset type, return JSON listing the FIELDS in the
sample that meaningfully indicate CRITICALITY (= "if this signal is
active, push the asset toward higher tier classification") AND/OR TRUST
(= "if this signal is active, the asset is safer than baseline").

Return ONLY JSON (no commentary, no markdown fences) with EXACTLY:

  Signals     -- ARRAY of { path, weight, reason } where:
                  path    = dot-path into the metadata hashtable (e.g.
                            'ENTRA_HasAdLeakedCredentials', 'AZ_PublicNetworkAccess',
                            'MDE_PublicIP'). Use the EXACT key names visible
                            in the sample.
                  weight  = INTEGER -100..+100. Positive = risk signal
                            (higher = more critical). Negative = trust
                            signal (more negative = more trustworthy).
                            Examples:
                              ENTRA_HasAdLeakedCredentials = true   -> +95
                              ENTRA_HasLeakedCredentials   = true   -> +90
                              SP.publisherVerified         = true   -> -25
                              MFA_Registered               = true   -> -20
                              AZ_PublicNetworkAccess       = Enabled -> +60
                  reason  = ONE short sentence justifying the weight.

  Reasoning   -- ONE sentence describing your selection logic.

Only include fields that move the criticality needle. Skip cosmetic /
informational fields (displayName, location, lastModified). Skip fields
whose value-shape requires complex evaluation (the engine just checks
truthiness or non-empty for non-bool values). Cap at 30 signals.

For non-boolean fields, the engine evaluates as "active" when value is
truthy AND not empty AND not 'False'/'Disabled'/'None'/'Off'. So returning
weight on a numeric or string field still works -- engine treats any
populated value as "signal active".
'@

function Invoke-SISignalMapAI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$AssetType,
        # fix: relax hashtable constraint
        [Parameter(Mandatory)]$SampleMetadata
    )

    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\Test-SIAIEnabled.ps1')
    if (-not (Test-SIAIEnabled -Engine $Engine)) { return $null }

    $payload = @{
        Engine    = $Engine
        AssetType = $AssetType
        Sample    = $SampleMetadata
    }
    $body = @{
        messages = @(
            @{ role = 'system'; content = $script:SI_SignalMap_SystemPrompt },
            @{ role = 'user';   content = ($payload | ConvertTo-Json -Depth 10 -Compress) }
        )
        temperature     = 0.0
        response_format = @{ type = 'json_object' }
    } | ConvertTo-Json -Depth 8 -Compress

    $url = ('{0}/openai/deployments/{1}/chat/completions?api-version={2}' -f `
            $global:OpenAI_endpoint.TrimEnd('/'),
            $global:OpenAI_deployment,
            $global:OpenAI_apiVersion)
    try {
        $resp = Invoke-RestMethod -Method Post -Uri $url `
            -Headers @{ 'api-key' = $global:OpenAI_apiKey; 'Content-Type' = 'application/json' } `
            -Body $body -ErrorAction Stop
        return ($resp.choices[0].message.content | ConvertFrom-Json)
    } catch {
        Write-Warning ('SignalMap AI call failed for {0}/{1}: {2}' -f $Engine, $AssetType, $_.Exception.Message)
        return $null
    }
}

function Get-SISignalMapCached {
    <#
        Cache-or-call. Returns @{Signals=[..]; Reasoning='...'; FromCache=bool}.
        On AI miss + budget exhausted, returns empty signals -- engine still
        runs but XENG_CriticalityScore stays at 0.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$TypeProfileTable,
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$AssetType,
        # fix: relax hashtable constraint
        [Parameter(Mandatory)]$SampleMetadata,
        [string]$PromptVersion
    )
    if (-not $PromptVersion) {
        $PromptVersion = if ($global:SI_SignalMap_PromptVersion) { $global:SI_SignalMap_PromptVersion } else { $script:SI_SignalMap_DefaultVersion }
    }

    $cached = Get-SISignalMapRecord -Context $Context -TableName $TypeProfileTable `
                                     -Engine $Engine -AssetType $AssetType -PromptVersion $PromptVersion
    if ($null -ne $cached) {
        $signals = @()
        try { $signals = @(($cached.signals_json | ConvertFrom-Json)) } catch { }
        return @{ Signals = $signals; Reasoning = [string]$cached.reasoning; FromCache = $true; PromptVersion = $PromptVersion }
    }

    $ai = Invoke-SISignalMapAI -Engine $Engine -AssetType $AssetType -SampleMetadata $SampleMetadata
    if ($null -eq $ai) {
        return @{ Signals = @(); Reasoning = 'AI unavailable'; FromCache = $false; PromptVersion = $PromptVersion }
    }
    $signals = @($ai.Signals)
    Set-SISignalMapRecord -Context $Context -TableName $TypeProfileTable `
                           -Engine $Engine -AssetType $AssetType -PromptVersion $PromptVersion `
                           -Signals $signals -Reasoning ([string]$ai.Reasoning)
    return @{ Signals = $signals; Reasoning = [string]$ai.Reasoning; FromCache = $false; PromptVersion = $PromptVersion }
}

function Get-SICriticalityScore {
    <#
        Sum of weights for active signals on this asset's metadata. Active =
        truthy && not empty && not 'False'/'Disabled'/'None'/'Off' (string
        canonicalised lowercase). Returns @{ Score=int; ActiveSignals=[...] }
        so Stage Classify can cite the specific signals in proofs.
    #>
    [CmdletBinding()]
    param(
        # fix: relax hashtable constraint
        [Parameter(Mandatory)]$Metadata,
        [Parameter(Mandatory)]$Signals
    )

    $score = 0
    $active = New-Object System.Collections.ArrayList
    foreach ($sig in @($Signals)) {
        if (-not $sig.path) { continue }
        $val = $Metadata[[string]$sig.path]
        if ($null -eq $val) { continue }
        $isActive = $false
        if ($val -is [bool]) { $isActive = [bool]$val }
        else {
            $s = ([string]$val).Trim().ToLowerInvariant()
            $isActive = -not [string]::IsNullOrWhiteSpace($s) -and $s -notin @('false','disabled','none','off','0','no')
        }
        if ($isActive) {
            $w = [int]$sig.weight
            $score += $w
            [void]$active.Add(@{
                Path   = [string]$sig.path
                Weight = $w
                Reason = [string]$sig.reason
                Value  = "$val"
            })
        }
    }
    @{ Score = $score; ActiveSignals = $active.ToArray() }
}

# --- Asset clustering (generalized from azure ) -------------
# Per-engine cluster-key strategies + AI-qualified app/group names.
# Cached in sitypeprofiles partition='appgroup' (existing).
$script:SI_AssetGroup_Prompts = @{
    azure = @'
You receive a CLUSTER of Azure resources from one resource group. Identify
the application or workload they collectively represent. Return ONLY JSON:
  AppName, AppType, Confidence (0..1), Reasoning
AppType in: WebApplication, Database, ApiBackend, ContainerWorkload,
  MachineLearning, IdentityInfra, NetworkingEdge, Backup, Monitoring,
  MessageBroker, SecretsVault, DataLake, Mixed, Other
'@
    endpoint = @'
You receive a CLUSTER of endpoint devices that share a naming prefix or
subnet. Identify the FUNCTIONAL group they form. Return ONLY JSON:
  AppName, AppType, Confidence (0..1), Reasoning
AppType in: DomainControllerCluster, WebTier, DatabaseTier, AppServerTier,
  WorkstationFleet, JumpHostBastion, BuildAgentPool, PrintFleet,
  IoTSegment, KioskFleet, Mixed, Other
Prefer naming-prefix as the cluster signal (dc-*, web-*, db-prod-*, etc.).
'@
    identity = @'
You receive a CLUSTER of identities sharing a department / OU / license
pattern. Identify the GROUP they form. Return ONLY JSON:
  AppName, AppType, Confidence (0..1), Reasoning
AppType in: Department, RegionalOrg, AdminGroup, ServiceAccountPool,
  ManagedIdentityPool, B2BGuestPool, BreakGlassGroup, Contractor,
  Mixed, Other
Prefer existing department/OU tags as the cluster signal.
'@
}

function Get-SIAssetClusterKeys {
    <#
        Returns hashtable @{ ClusterId -> @{ Members=@(...); KeyComponent=string } }
        using engine-specific cluster strategies:
          azure    -- group by AZ_RG (already shipped)
          endpoint -- group by lowercased naming prefix (first alphanumeric
                      run of length >= 3, e.g. 'dc-prod-01' -> 'dc')
          identity -- group by ENTRA_Department (or extract OU from
                      ENTRA_DistinguishedName when department empty)
        Singletons (clusters of size 1) are returned too -- caller
        decides whether to AI-qualify them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)]$Records
    )

    $byCluster = @{}
    foreach ($r in $Records) {
        $key = $null
        switch ($Engine) {
            'azure' {
                $rg = $r.Metadata.AZ_RG
                if (-not [string]::IsNullOrWhiteSpace($rg)) { $key = ('rg:{0}' -f $rg) }
            }
            'endpoint' {
                $name = if ($r.Metadata.MDE_DeviceName) { $r.Metadata.MDE_DeviceName }
                        elseif ($r.Metadata.EG_Name)    { $r.Metadata.EG_Name }
                        elseif ($r.Name)                { $r.Name }
                        else                            { $null }
                if ($name) {
                    $low = ([string]$name).ToLowerInvariant()
                    if ($low -match '^([a-z]{2,8})[-_0-9]') {
                        $key = ('prefix:{0}' -f $matches[1])
                    } elseif ($low -match '^([a-z]{2,8})') {
                        $key = ('prefix:{0}' -f $matches[1])
                    }
                }
            }
            'identity' {
                $dept = $r.Metadata.ENTRA_Department
                if ($dept) {
                    $key = ('dept:{0}' -f ([string]$dept).ToLowerInvariant())
                } elseif ($r.Metadata.ENTRA_DistinguishedName) {
                    $dn = [string]$r.Metadata.ENTRA_DistinguishedName
                    if ($dn -match 'OU=([^,]+)') { $key = ('ou:{0}' -f $matches[1].ToLowerInvariant()) }
                }
            }
        }
        if (-not $key) { continue }
        if (-not $byCluster.ContainsKey($key)) {
            $byCluster[$key] = @{ KeyComponent = $key; Members = New-Object System.Collections.ArrayList }
        }
        [void]$byCluster[$key].Members.Add($r)
    }
    return $byCluster
}

function Invoke-SIAssetGroupAI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][hashtable]$ClusterPayload
    )
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\Test-SIAIEnabled.ps1')
    if (-not (Test-SIAIEnabled -Engine $Engine)) { return $null }
    $sys = if ($script:SI_AssetGroup_Prompts.ContainsKey($Engine)) { $script:SI_AssetGroup_Prompts[$Engine] } else { $script:SI_AssetGroup_Prompts['azure'] }
    $body = @{
        messages = @(
            @{ role = 'system'; content = $sys },
            @{ role = 'user';   content = ($ClusterPayload | ConvertTo-Json -Depth 8 -Compress) }
        )
        temperature     = 0.0
        response_format = @{ type = 'json_object' }
    } | ConvertTo-Json -Depth 8 -Compress
    $url = ('{0}/openai/deployments/{1}/chat/completions?api-version={2}' -f `
            $global:OpenAI_endpoint.TrimEnd('/'),
            $global:OpenAI_deployment,
            $global:OpenAI_apiVersion)
    try {
        $resp = Invoke-RestMethod -Method Post -Uri $url `
            -Headers @{ 'api-key' = $global:OpenAI_apiKey; 'Content-Type' = 'application/json' } `
            -Body $body -ErrorAction Stop
        return ($resp.choices[0].message.content | ConvertFrom-Json)
    } catch {
        Write-Warning ('AssetGroup AI call failed: {0}' -f $_.Exception.Message)
        return $null
    }
}

# --- Azure app-group clustering (AI-qualified) ---
# After per-asset enrichment, group resources by RG, ask AI to qualify
# each cluster (AppName + AppType). Cached per (RG + sorted-member-names)
# in sitypeprofiles partition='appgroup'. Re-AI only when membership
# changes (rename, add, remove).
$script:SI_AppGroupSystemPrompt = @'
You receive a CLUSTER of Azure resources from one resource group. Identify
the application or workload they collectively represent. Return ONLY JSON
(no commentary, no markdown fences) with EXACTLY:

  AppName     -- short hyphenated identifier ("CustomerPortal-Prod",
                 "DataPlatform-Dev"). Prefer existing resource naming
                 prefix when one is shared. Skip generic resource-group
                 names like "rg-infra".
  AppType     -- one of: WebApplication, Database, ApiBackend,
                 ContainerWorkload, MachineLearning, IdentityInfra,
                 NetworkingEdge, Backup, Monitoring, MessageBroker,
                 SecretsVault, DataLake, Mixed, Other
  Confidence  -- 0.0 to 1.0; use < 0.3 when the cluster looks accidental
                 (e.g. only an NSG and a public IP)
  Reasoning   -- ONE short sentence explaining the call

Inputs include resource Name, Type, Hint, Tags. Use them all. If tags
already include an "Application" or "Service" tag, prefer that as AppName.
'@

function Invoke-SIAzureAppGroupAI {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$ClusterPayload)

    # Azure-only helper; gate via the centralized AI-enabled check.
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\Test-SIAIEnabled.ps1')
    if (-not (Test-SIAIEnabled -Engine 'azure')) { return $null }

    $body = @{
        messages = @(
            @{ role = 'system'; content = $script:SI_AppGroupSystemPrompt },
            @{ role = 'user';   content = ($ClusterPayload | ConvertTo-Json -Depth 8 -Compress) }
        )
        temperature     = 0.0
        response_format = @{ type = 'json_object' }
    } | ConvertTo-Json -Depth 8 -Compress

    $url = ('{0}/openai/deployments/{1}/chat/completions?api-version={2}' -f `
            $global:OpenAI_endpoint.TrimEnd('/'),
            $global:OpenAI_deployment,
            $global:OpenAI_apiVersion)

    try {
        $resp = Invoke-RestMethod -Method Post -Uri $url `
            -Headers @{ 'api-key' = $global:OpenAI_apiKey; 'Content-Type' = 'application/json' } `
            -Body $body -ErrorAction Stop
        return ($resp.choices[0].message.content | ConvertFrom-Json)
    } catch {
        Write-Warning ('AzureAppGroup AI call failed: {0}' -f $_.Exception.Message)
        return $null
    }
}

function Get-SIAzureClusterKey {
    <#
        Stable hash of (RG + sorted resource short names). Used as the
        cache key so adding/removing a member naturally invalidates the
        prior verdict.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string[]]$MemberNames
    )

    $sorted = ($MemberNames | Sort-Object -Unique) -join '|'
    $bytes  = [System.Text.Encoding]::UTF8.GetBytes(($ResourceGroup + '||' + $sorted))
    $sha    = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hex = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','').Substring(0, 16).ToLowerInvariant()
    } finally { $sha.Dispose() }
    return ('rg:{0}:{1}' -f $ResourceGroup.ToLowerInvariant(), $hex)
}

function Add-SIAssetGroups {
    <#
        Generalized clustering. Replaces 's
        Add-SIAzureAppGroups. Engine-aware:
          azure    -- group by AZ_RG
          endpoint -- group by lowercased naming prefix (dc-*, web-*, ...)
          identity -- group by ENTRA_Department (or extracted OU from DN)
        For each cluster of >=2 members: cluster-key cache lookup; cache
        miss = one AI call per cluster returning AppName + AppType +
        Confidence + Reasoning. Singleton clusters skip AI (deterministic
        XENG_AppGroup with confidence 0).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$RunContext,
        [Parameter(Mandatory)][System.Collections.IList]$Enriched,
        [Parameter(Mandatory)][string]$TypeProfileTable
    )

    $engine = $RunContext.Engine
    $clusters = Get-SIAssetClusterKeys -Engine $engine -Records $Enriched
    if ($clusters.Count -eq 0) {
        return @{ AiCalls = 0; CacheHits = 0; Singletons = 0 }
    }

    $aiCalls    = 0
    $cacheHits  = 0
    $singletons = 0

    foreach ($clusterKeyShort in $clusters.Keys) {
        $members = @($clusters[$clusterKeyShort].Members)
        if ($members.Count -lt 2) {
            $singletons++
            $only = $members[0]
            $only.Enrichment['XENG_AppGroup']           = $clusterKeyShort
            $only.Enrichment['XENG_AppType']            = 'Other'
            $only.Enrichment['XENG_AppGroupConfidence'] = 0.0
            continue
        }

        $memberNames = $members | ForEach-Object {
            if ($_.Metadata.Name) { [string]$_.Metadata.Name }
            elseif ($_.Name)      { [string]$_.Name }
            else                  { [string]$_.AssetId }
        }
        # Cluster cache key includes engine + cluster-key + sorted members
        # so renaming/adding flips the key naturally and triggers re-AI.
        $sorted = ($memberNames | Sort-Object -Unique) -join '|'
        $bytes  = [System.Text.Encoding]::UTF8.GetBytes(($engine + '||' + $clusterKeyShort + '||' + $sorted))
        $sha    = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hex = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','').Substring(0,16).ToLowerInvariant()
        } finally { $sha.Dispose() }
        $clusterKey = ('{0}:{1}:{2}' -f $engine, $clusterKeyShort, $hex)

        $cached = Get-SIAppGroupRecord -Context $RunContext.StorageContext `
                                        -TableName $TypeProfileTable `
                                        -ClusterKey $clusterKey

        if ($null -ne $cached) {
            $cacheHits++
            $appName = [string]$cached.app_name
            $appType = [string]$cached.app_type
            $conf    = [double]$cached.confidence
        } else {
            # Build engine-appropriate cluster payload for the AI prompt
            $payload = switch ($engine) {
                'azure' {
                    @{
                        ResourceGroup = ($clusterKeyShort -replace '^rg:','')
                        Resources = @($members | ForEach-Object {
                            @{
                                Name = $_.Metadata.Name
                                Type = $_.Metadata.AZ_Type
                                Hint = $_.Metadata.AZ_Hint
                                Tags = @{ Environment = $_.Metadata.AZ_EnvTag; Owner = $_.Metadata.AZ_OwnerTag }
                            }
                        })
                    }
                }
                'endpoint' {
                    @{
                        NamingPrefix = ($clusterKeyShort -replace '^prefix:','')
                        Devices = @($members | ForEach-Object {
                            @{
                                Name = if ($_.Metadata.MDE_DeviceName) { $_.Metadata.MDE_DeviceName } else { $_.Name }
                                OS   = if ($_.Metadata.MDE_OSPlatform) { $_.Metadata.MDE_OSPlatform } elseif ($_.Metadata.EG_OS) { $_.Metadata.EG_OS } else { $null }
                                Hint = $_.Hint
                            }
                        })
                    }
                }
                'identity' {
                    @{
                        ClusterKey = $clusterKeyShort
                        Identities = @($members | ForEach-Object {
                            @{
                                Name        = if ($_.Metadata.ENTRA_DisplayName) { $_.Metadata.ENTRA_DisplayName } else { $_.Name }
                                UPN         = $_.Metadata.ENTRA_UPN
                                Type        = $_.Metadata.ENTRA_AssetType
                                Department  = $_.Metadata.ENTRA_Department
                                JobTitle    = $_.Metadata.ENTRA_JobTitle
                                LicenseCount= $_.Metadata.ENTRA_LicenseCount
                            }
                        })
                    }
                }
                default { @{ Members = @($memberNames) } }
            }
            $aiCalls++
            $aiResult = Invoke-SIAssetGroupAI -Engine $engine -ClusterPayload $payload
            if ($null -eq $aiResult) {
                $appName = $clusterKeyShort
                $appType = 'Mixed'
                $conf    = 0.0
            } else {
                $appName = if ($aiResult.AppName) { [string]$aiResult.AppName } else { $clusterKeyShort }
                $appType = if ($aiResult.AppType) { [string]$aiResult.AppType } else { 'Mixed' }
                $conf    = if ($null -ne $aiResult.Confidence) { [double]$aiResult.Confidence } else { 0.5 }
                Set-SIAppGroupRecord -Context $RunContext.StorageContext `
                                      -TableName $TypeProfileTable `
                                      -ClusterKey $clusterKey `
                                      -ResourceGroup $clusterKeyShort `
                                      -AppName $appName `
                                      -AppType $appType `
                                      -Confidence $conf `
                                      -Reasoning ([string]$aiResult.Reasoning) `
                                      -MemberAssetIds @($members | ForEach-Object { $_.AssetId })
            }
        }

        foreach ($m in $members) {
            $m.Enrichment['XENG_AppGroup']           = $appName
            $m.Enrichment['XENG_AppType']            = $appType
            $m.Enrichment['XENG_AppGroupConfidence'] = $conf
        }
    }

    @{ AiCalls = $aiCalls; CacheHits = $cacheHits; Singletons = $singletons }
}

function Invoke-SIEnrich {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$RunContext)

    $records = Read-SIStageShards -Context $RunContext.StorageContext `
                                   -ContainerName $RunContext.StagingContainer `
                                   -RunId $RunContext.RunId `
                                   -Stage 'Collect' `
                                   -ReplicaIndex ([int]$RunContext.ShardIndex)

    # Build an asset-key -> [posture-hits] index by running each rule's
    # KQL exactly once. Posture-rule queries project DeviceId (endpoint)
    # OR AccountObjectId (identity); auto-detect which is present and key
    # the index by that. Plus build a behaviour-correlation index per
    # engine: DeviceName -> logons (endpoint) or UserObjectId -> sign-ins
    # (identity). In Mock mode all indexes stay empty.
    $hitsByKey       = @{}
    $rulesRun        = 0
    $logonsByName    = @{}
    $signInsByUserId = @{}
    $endpointTierMap = @{}
    $userDevices     = @{}
    $identityTierMap = @{}
    $azureEgEdges    = @{}
    $tvmByDeviceId   = @{}   # endpoint engine: bulk TVM software fan-out
    $userTierByDevice= @{}   # endpoint engine: cross-engine logon-user-tier fan-out

    # Signal-map per-run state. Reset per invocation so the
    # summary line reports this run's criticality density. Type-profile
    # table handle is lazy-initialized on first asset-loop iteration.
    $script:SI_SignalMap_RunCache    = @{}
    $script:SI_SignalMap_TotalActive = 0
    $script:SI_SignalMap_ScoreSum    = 0
    $script:SI_SignalMap_AssetCount  = 0
    $signalMapTpTable                = $null

    # Split rules: KQL queries run once globally, metadata rules evaluate
    # per-asset in the loop below.
    $allRules        = if ($RunContext.StorageContext.Mode -ne 'Mock') { Get-SIPostureRules -Engine $RunContext.Engine } else { @() }
    $kqlRules        = @($allRules | Where-Object { $_.RuleType -eq 'KqlHunting' })
    $metadataRules   = @($allRules | Where-Object { $_.RuleType -eq 'AssetMetadata' })
    $metadataRuleHits = 0

    if ($RunContext.StorageContext.Mode -ne 'Mock') {
        $_kqlTotal = $kqlRules.Count; $_kqlIdx = 0
        if ($_kqlTotal -gt 0) { Write-SIInfo ('running {0} KQL posture-rule hunting queries...' -f $_kqlTotal) }
        Reset-SIProgress -Label 'KqlPostureRules' -ErrorAction SilentlyContinue
        foreach ($rule in $kqlRules) {
            $_kqlIdx++
            $_ruleStart = [System.Diagnostics.Stopwatch]::StartNew()
            # v2: route per QueryEngine. v1 rules default to DefenderGraph.
            $rows = Invoke-SIHuntingQuery -Query $rule.Query -QueryEngine $rule.QueryEngine
            $_ruleStart.Stop()
            Write-SIInfo ('  [{0,3}/{1}] rule="{2}" engine={3} rows={4} took={5:N1}s' -f $_kqlIdx, $_kqlTotal, $rule.Name, $rule.QueryEngine, @($rows).Count, $_ruleStart.Elapsed.TotalSeconds)
            try { Write-SIProgress -Label 'KqlPostureRules' -Index $_kqlIdx -Total $_kqlTotal } catch { }
            $rulesRun++
            foreach ($row in $rows) {
                $key = if ($row.DeviceId)        { [string]$row.DeviceId }
                       elseif ($row.AccountObjectId) { ([string]$row.AccountObjectId).ToLowerInvariant() }
                       elseif ($row.UserId)      { ([string]$row.UserId).ToLowerInvariant() }
                       else { $null }
                if (-not $key) { continue }
                if (-not $hitsByKey.ContainsKey($key)) {
                    $hitsByKey[$key] = New-Object System.Collections.ArrayList
                }
                # v2 rules carry TargetTier + Mode forward into the proof
                # entry. Stage Classify uses these to short-circuit the AI
                # call when Mode=Production AND a TargetTier wins.
                $proofEntry = @{
                    Rule        = $rule.Name
                    Label       = $rule.ProofLabel
                    Weight      = $rule.ProofWeight
                    TargetTier  = $rule.TargetTier
                    Mode        = $rule.Mode
                }
                if ($rule.Mode -eq 'Test') {
                    $proofEntry['Reason'] = ('[TEST MODE] {0}' -f $rule.AssetTagName)
                }
                [void]$hitsByKey[$key].Add($proofEntry)
            }
        }

        if ($RunContext.Engine -eq 'endpoint') {
            # Logon correlation -- one round-trip for all device assets
            $names = New-Object System.Collections.ArrayList
            foreach ($r in $records) {
                $n = $null
                if ($r.Metadata.MDE_DeviceName) { $n = $r.Metadata.MDE_DeviceName }
                elseif ($r.Metadata.EG_Name)    { $n = $r.Metadata.EG_Name }
                if ($n) { [void]$names.Add([string]$n) }
            }
            if ($names.Count -gt 0) {
                $logonsByName = Get-SILogonsByDeviceName -DeviceNames $names.ToArray()
            }

            # TVM software bulk fetch -- ONE hunting query against
            # DeviceTvmSoftwareInventory for all endpoint assets in this run.
            # Per-asset Get-SITierFromInstalledApplications match below in the
            # asset loop just slices into the resulting hashtable.
            . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\EndpointCatalogTierComputer.ps1')
            $null = Initialize-SIServerAppCatalog
            $deviceIds = New-Object System.Collections.ArrayList
            foreach ($r in $records) {
                if ($r.Metadata.MDE_DeviceId) { [void]$deviceIds.Add([string]$r.Metadata.MDE_DeviceId) }
            }
            if ($deviceIds.Count -gt 0) {
                try {
                    $tvmByDeviceId = Get-SIBulkTvmSoftwareInventory -DeviceIds $deviceIds.ToArray()
                } catch {
                    Write-Warning ('Get-SIBulkTvmSoftwareInventory failed -- {0}' -f $_.Exception.Message)
                    $tvmByDeviceId = @{}
                }
                $distinctApps = 0
                foreach ($k in $tvmByDeviceId.Keys) {
                    $arr = $tvmByDeviceId[$k]
                    if ($null -ne $arr) { $distinctApps += @($arr).Count }
                }
                Write-SIInfo ('[perms] TVM software bulk fetch: {0} devices, {1} distinct apps detected against SecurityInsight application catalog' -f $tvmByDeviceId.Count, $distinctApps)

                # Cross-engine join: for each device, find frequent logon users
                # via Exposure Graph "frequently logged in" edges, then look up
                # their tier in Identity_Profile_CL. Feeds the LogonByMostFrequentUser
                # virtual rule in Stage Profile.
                # now keyed on AAD device id (not MdeDeviceId) since
                # EG indexes on AAD device id.
                $aadDeviceIds = New-Object System.Collections.ArrayList
                foreach ($r in $records) {
                    $a = $null
                    if ($r.Metadata -is [System.Collections.IDictionary]) {
                        if ($r.Metadata.Contains('EG_AadDeviceId')) { $a = $r.Metadata['EG_AadDeviceId'] }
                        elseif ($r.Metadata.Contains('MDE_AzureADDeviceId')) { $a = $r.Metadata['MDE_AzureADDeviceId'] }
                    } elseif ($r.Metadata.PSObject.Properties['EG_AadDeviceId']) { $a = $r.Metadata.EG_AadDeviceId }
                    elseif ($r.Metadata.PSObject.Properties['MDE_AzureADDeviceId']) { $a = $r.Metadata.MDE_AzureADDeviceId }
                    if ($a) { [void]$aadDeviceIds.Add([string]$a) }
                }
                if ($aadDeviceIds.Count -gt 0) {
                    try {
                        $userTierByDevice = Get-SIBulkDeviceUserCorrelation -AadDeviceIds $aadDeviceIds.ToArray() -TopN 5
                    } catch {
                        Write-Warning ('Get-SIBulkDeviceUserCorrelation failed -- {0}' -f $_.Exception.Message)
                        $userTierByDevice = @{}
                    }
                    $devicesWithUserTier = 0
                    foreach ($k in $userTierByDevice.Keys) {
                        if ($null -ne $userTierByDevice[$k].MostFrequentUserTier) { $devicesWithUserTier++ }
                    }
                    Write-SIInfo ('[perms] Device-user logon correlation (EG): {0} devices have frequent users, {1} resolved to a known identity tier' -f $userTierByDevice.Count, $devicesWithUserTier)
                } else {
                    Write-SIInfo '[perms] Device-user logon correlation (EG): 0 endpoints have AAD device id; skipping'
                }
            }
        }
        elseif ($RunContext.Engine -eq 'identity') {
            # Sign-in correlation -- one round-trip for all user assets
            $userIds = New-Object System.Collections.ArrayList
            foreach ($r in $records) {
                if ($r.Metadata.ENTRA_UserId) { [void]$userIds.Add([string]$r.Metadata.ENTRA_UserId) }
            }
            if ($userIds.Count -gt 0) {
                $signInsByUserId = Get-SISignInsByUserObjectId -UserObjectIds $userIds.ToArray()
                # Cross-engine: which devices does each user sign into, and
                # what tier are those devices? Two queries: one to LA for the
                # endpoint tier map, one to Defender hunting for user->device
                # logons. Both fail gracefully (return empty) if endpoint
                # engine hasn't run yet OR if perms are missing.
                $endpointTierMap = Get-SIEndpointTierMap -WorkspaceResourceId $global:SI_WorkspaceResourceId
                $userDevices    = Get-SIDeviceLogonsByUserObjectId -UserObjectIds $userIds.ToArray()
            }
        }
        elseif ($RunContext.Engine -eq 'azure') {
            # Cross-engine: which identities reach this resource (per EG edges)
            # and what tier are they? Identity tier map from LA + EG edges from
            # Defender hunting. Both fail gracefully -- azure engine still
            # classifies via metaprofile + posture rules alone.
            # discovery moved from v2.2/engine/discovery/ to v2.2/engine/asset-profiling/discovery/
            . (Join-Path (Split-Path -Parent $PSScriptRoot) 'discovery\Get-DiscoveryFromAzureExposureGraph.ps1')
            $identityTierMap = Get-SIIdentityTierMap -WorkspaceResourceId $global:SI_WorkspaceResourceId
            $azureEgEdges    = Get-AzureExposureGraphAccessEdges
        }
    }

    $enriched   = New-Object System.Collections.ArrayList
    $skipAi     = 0
    $hitAssets  = 0

    $totalToEnrich = $records.Count
    $progressEvery = if ($totalToEnrich -lt 30) { 5 } elseif ($totalToEnrich -lt 200) { 25 } else { 50 }
    $progressIdx   = 0
    $stageStart    = [datetime]::UtcNow

    foreach ($r in $records) {
        $progressIdx++
        if ($progressIdx -eq 1 -or $progressIdx % $progressEvery -eq 0 -or $progressIdx -eq $totalToEnrich) {
            $elapsed = ([datetime]::UtcNow - $stageStart).TotalSeconds
            Write-SIInfo ('[{0,4}/{1}] elapsed={2,5:N1}s  hits={3}' -f $progressIdx, $totalToEnrich, $elapsed, $hitAssets)
        }
        $postureHits = New-Object System.Collections.ArrayList

        if ($RunContext.StorageContext.Mode -eq 'Mock') {
            # Mock fallback
            if ($r.Hint -eq 'exchange-server') {
                [void]$postureHits.Add(@{ Rule='ExchangeServerDetection'; Label='ServiceType=ExchangeServer'; Weight=90 })
            }
            if ($r.Hint -eq 'domain-controller') {
                [void]$postureHits.Add(@{ Rule='DomainControllerDetection'; Label='ServiceType=DomainController'; Weight=99 })
            }
        }
        else {
            # Real-Azure path -- look up by engine-appropriate key
            $assetKey = if ($r.EgNodeId)               { [string]$r.EgNodeId }
                        elseif ($r.Metadata.ENTRA_UserId) { ([string]$r.Metadata.ENTRA_UserId).ToLowerInvariant() }
                        else { $null }
            if ($assetKey -and $hitsByKey.ContainsKey($assetKey)) {
                foreach ($h in $hitsByKey[$assetKey]) { [void]$postureHits.Add($h) }
            }

            # Evaluate metadata rules per-asset. Optional AppliesToAssetType
            # gates rules to specific shapes (e.g. SP-only rules skip Users).
            $assetType = if ($r.Metadata.ENTRA_AssetType) { [string]$r.Metadata.ENTRA_AssetType }
                         elseif ($r.Metadata.AZ_AssetType) { [string]$r.Metadata.AZ_AssetType }
                         else { $null }
            foreach ($rule in $metadataRules) {
                if ($rule.AppliesToAssetType -and $assetType -and $rule.AppliesToAssetType -ne $assetType) { continue }
                if (Test-SIAssetMatchesRule -Metadata $r.Metadata -MatchOn $rule.MatchOn) {
                    $proof = @{
                        Rule       = $rule.Name
                        Label      = $rule.ProofLabel
                        Weight     = $rule.ProofWeight
                        TargetTier = $rule.TargetTier
                        Mode       = $rule.Mode
                    }
                    if ($rule.Mode -eq 'Test') {
                        $proof['Reason'] = ('[TEST MODE] {0}' -f $rule.AssetTagName)
                    }
                    [void]$postureHits.Add($proof)
                    $metadataRuleHits++
                }
            }
        }

        if ($postureHits.Count -gt 0) { $hitAssets++ }

        # Behaviour correlation -- per-engine source
        $logonRow  = $null
        $signInRow = $null
        if ($RunContext.Engine -eq 'endpoint') {
            $nameKey = $null
            if ($r.Metadata.MDE_DeviceName) { $nameKey = ([string]$r.Metadata.MDE_DeviceName).ToLowerInvariant() }
            elseif ($r.Metadata.EG_Name)    { $nameKey = ([string]$r.Metadata.EG_Name).ToLowerInvariant() }
            if ($nameKey -and $logonsByName.ContainsKey($nameKey)) { $logonRow = $logonsByName[$nameKey] }

            # Server-app catalog match per device. Pull this device's TVM
            # software set (from the bulk fetch above), stash it on the
            # asset Metadata for downstream consumers, and record the
            # lowest-tier match plus all proofs so Stage Classify can see
            # WHY we tagged a Tier 0 / 1 server-app role.
            if ($r.Metadata.MDE_DeviceId) {
                $devKey = ([string]$r.Metadata.MDE_DeviceId).ToLowerInvariant()
                $tvmList = @()
                if ($tvmByDeviceId.ContainsKey($devKey)) { $tvmList = @($tvmByDeviceId[$devKey]) }
                # Shape-tolerant write: $r.Metadata is [hashtable] when in-process
                # (single-process VM mode) or [pscustomobject] after JSON round-trip
                # via staging blob. Hashtable supports indexer; pscustomobject does
                # not -- use Add-Member -Force which works on both shapes.
                if ($r.Metadata -is [System.Collections.IDictionary]) {
                    $r.Metadata['TvmSoftware'] = $tvmList
                } else {
                    $r.Metadata | Add-Member -NotePropertyName TvmSoftware -NotePropertyValue $tvmList -Force
                }
                if ($tvmList.Count -gt 0) {
                    $matcherResult = Get-SITierFromInstalledApplications -InstalledApps $tvmList
                    if ($r.Metadata -is [System.Collections.IDictionary]) {
                        $r.Metadata['ServerAppCatalogMatch'] = $matcherResult
                    } else {
                        $r.Metadata | Add-Member -NotePropertyName ServerAppCatalogMatch -NotePropertyValue $matcherResult -Force
                    }
                }

                # User-based tier (cross-engine join via Exposure Graph).
                # $userTierByDevice is now keyed by AAD device id
                # (was MdeDeviceId), since EG indexes on AAD device id.
                $aadDevKey = $null
                if ($r.Metadata -is [System.Collections.IDictionary]) {
                    if ($r.Metadata.Contains('EG_AadDeviceId')) { $aadDevKey = [string]$r.Metadata['EG_AadDeviceId'] }
                    elseif ($r.Metadata.Contains('MDE_AzureADDeviceId')) { $aadDevKey = [string]$r.Metadata['MDE_AzureADDeviceId'] }
                } elseif ($r.Metadata.PSObject.Properties['EG_AadDeviceId']) { $aadDevKey = [string]$r.Metadata.EG_AadDeviceId }
                elseif ($r.Metadata.PSObject.Properties['MDE_AzureADDeviceId']) { $aadDevKey = [string]$r.Metadata.MDE_AzureADDeviceId }
                if ($aadDevKey) { $aadDevKey = $aadDevKey.ToLowerInvariant() }

                if ($aadDevKey -and $userTierByDevice.ContainsKey($aadDevKey)) {
                    $u = $userTierByDevice[$aadDevKey]
                    if ($r.Metadata -is [System.Collections.IDictionary]) {
                        $r.Metadata['MostFrequentUserTier']   = $u.MostFrequentUserTier
                        $r.Metadata['MostFrequentUsers']      = $u.MostFrequentUsers
                        $r.Metadata['MostFrequentUsersCount'] = $u.MostFrequentUsersCount
                    } else {
                        $r.Metadata | Add-Member -NotePropertyName MostFrequentUserTier   -NotePropertyValue $u.MostFrequentUserTier   -Force
                        $r.Metadata | Add-Member -NotePropertyName MostFrequentUsers      -NotePropertyValue $u.MostFrequentUsers      -Force
                        $r.Metadata | Add-Member -NotePropertyName MostFrequentUsersCount -NotePropertyValue $u.MostFrequentUsersCount -Force
                    }
                }
            }
        }
        elseif ($RunContext.Engine -eq 'identity') {
            $uid = $null
            if ($r.Metadata.ENTRA_UserId) { $uid = ([string]$r.Metadata.ENTRA_UserId).ToLowerInvariant() }
            if ($uid -and $signInsByUserId.ContainsKey($uid)) { $signInRow = $signInsByUserId[$uid] }
        }

        $enrichmentInputs = @{
            SI_PostureRuleHitsCount = $postureHits.Count
            SI_PostureRuleLabels    = ($postureHits | ForEach-Object { $_.Label })
        }
        if ($logonRow) {
            $enrichmentInputs['MDE_LogonCount']          = $logonRow.LogonCount
            $enrichmentInputs['MDE_LastLogon']           = $logonRow.LastLogon
            $enrichmentInputs['MDE_LogonAccounts']       = $logonRow.Accounts
            $enrichmentInputs['MDE_InteractiveAccounts'] = $logonRow.InteractiveAccounts
            $enrichmentInputs['MDE_LogonTypes']          = $logonRow.LogonTypes
        }
        if ($signInRow) {
            $enrichmentInputs['ENTRA_SignInCount']       = $signInRow.SignInCount
            $enrichmentInputs['ENTRA_SuccessfulSignIns'] = $signInRow.SuccessfulSignIns
            $enrichmentInputs['ENTRA_FailedSignIns']     = $signInRow.FailedSignIns
            $enrichmentInputs['ENTRA_LastSignIn']        = $signInRow.LastSignIn
            $enrichmentInputs['ENTRA_DistinctApps']      = $signInRow.DistinctApps
            $enrichmentInputs['ENTRA_DistinctIPs']       = $signInRow.DistinctIPs
            $enrichmentInputs['ENTRA_DistinctCountries'] = $signInRow.DistinctCountries
            $enrichmentInputs['ENTRA_Apps']              = $signInRow.Apps
        }

        # Cross-engine reference: which IDENTITIES reach this azure resource
        # (per EG edges) and what tier are they? Mirror of the identity
        # engine's "which devices does this user touch" pattern, inverted:
        # for resources, we look at INCOMING access from already-classified
        # identities and inherit tier hints.
        if ($RunContext.Engine -eq 'azure' -and $r.Metadata.AZ_ResourceId -and $r.Name) {
            $resKey = ([string]$r.Name).ToLowerInvariant()
            if ($azureEgEdges.ContainsKey($resKey)) {
                $accessEdges = @($azureEgEdges[$resKey])
                # tier is INT 0-3 now. Counts keyed by int.
                $tierAccessCounts = @{ 0=0; 1=0; 2=0; 3=0 }
                $highTierAccessors = New-Object System.Collections.ArrayList
                $accessedByCount = 0
                foreach ($edge in $accessEdges) {
                    $sname = ([string]$edge.SourceName).ToLowerInvariant()
                    if (-not $sname) { continue }
                    $accessedByCount++
                    if ($identityTierMap.ContainsKey($sname)) {
                        $info = $identityTierMap[$sname]
                        if ($null -eq $info.Tier) { continue }
                        $tierAccessCounts[$info.Tier]++
                        if ($info.Tier -in @(0,1)) {
                            [void]$highTierAccessors.Add(@{
                                IdentityName = $edge.SourceName
                                IdentityType = $edge.SourceLabel
                                Tier         = $info.Tier
                                EdgeLabel    = $edge.EdgeLabel
                            })
                            [void]$postureHits.Add(@{
                                Rule   = 'CrossEngine_AccessedByTieredIdentity'
                                Label  = ('AccessedByTier{0}=true' -f $info.Tier)
                                Weight = if ($info.Tier -eq 0) { 90 } else { 70 }
                                Reason = ('Reachable by tier-{0} identity {1} via "{2}"' -f $info.Tier, $edge.SourceName, $edge.EdgeLabel)
                            })
                        }
                    }
                }
                $enrichmentInputs['XENG_AccessedByCount']        = $accessedByCount
                $enrichmentInputs['XENG_AccessedByT0Count']      = $tierAccessCounts[0]
                $enrichmentInputs['XENG_AccessedByT1Count']      = $tierAccessCounts[1]
                $enrichmentInputs['XENG_AccessedByT2Count']      = $tierAccessCounts[2]
                $enrichmentInputs['XENG_HighTierAccessorDetails']= $highTierAccessors.ToArray()
            }
        }

        # Cross-engine reference: which endpoints does this identity touch,
        # and what tier are they? Adds tier-touch counters AND posture proofs
        # so the AI Classify can spot "user signs into 3 T0 DCs" -> T0 user.
        if ($RunContext.Engine -eq 'identity' -and $r.Metadata.ENTRA_UserId) {
            $uid = ([string]$r.Metadata.ENTRA_UserId).ToLowerInvariant()
            if ($userDevices.ContainsKey($uid)) {
                $accessedDevices = @($userDevices[$uid])
                $tierTouchCounts = @{ 0=0; 1=0; 2=0; 3=0 }
                $accessedTierDetails = New-Object System.Collections.ArrayList
                foreach ($devName in $accessedDevices) {
                    if ($endpointTierMap.ContainsKey($devName)) {
                        $info = $endpointTierMap[$devName]
                        if ($null -eq $info.Tier) { continue }
                        $tierTouchCounts[$info.Tier]++
                        if ($info.Tier -in @(0,1)) {
                            [void]$accessedTierDetails.Add(@{
                                DeviceName  = $devName
                                Tier        = $info.Tier
                                ServiceType = $info.ServiceType
                                ServiceName = $info.ServiceName
                            })
                            [void]$postureHits.Add(@{
                                Rule   = 'CrossEngine_DeviceTouch'
                                Label  = ('AccessesTier{0}=true' -f $info.Tier)
                                Weight = if ($info.Tier -eq 0) { 90 } else { 70 }
                                Reason = ('Signs into tier-{0} device {1} ({2})' -f $info.Tier, $devName, $info.ServiceType)
                            })
                        }
                    }
                }
                $enrichmentInputs['XENG_DevicesAccessedCount'] = $accessedDevices.Count
                $enrichmentInputs['XENG_T0DevicesAccessed']    = $tierTouchCounts[0]
                $enrichmentInputs['XENG_T1DevicesAccessed']    = $tierTouchCounts[1]
                $enrichmentInputs['XENG_T2DevicesAccessed']    = $tierTouchCounts[2]
                $enrichmentInputs['XENG_T3DevicesAccessed']    = $tierTouchCounts[3]
                $enrichmentInputs['XENG_HighTierDeviceDetails'] = $accessedTierDetails.ToArray()
            }
        }

        # ---- AI signal-map criticality score ---------------
        # One AI call per (engine, assetType) cached forever per prompt
        # version. Score is sum of weights for active signals. Adds
        # XENG_CriticalityScore + XENG_ActiveSignals[] to enrichmentInputs
        # so AI Classify can anchor tier on the precomputed signal sum.
        if ($RunContext.StorageContext.Mode -ne 'Mock' -and $RunContext.Engine -in 'endpoint','identity','azure') {
            # Asset-type discriminator. Identity has User vs SP; endpoint +
            # azure each have one type.
            $assetTypeForSignals = switch ($RunContext.Engine) {
                'identity' {
                    if ($r.Metadata.ENTRA_AssetType) { [string]$r.Metadata.ENTRA_AssetType } else { 'User' }
                }
                'azure'    { 'AzureResource' }
                default    { 'Device' }
            }
            $signalMapKey = ('{0}|{1}' -f $RunContext.Engine, $assetTypeForSignals)
            if (-not $script:SI_SignalMap_RunCache) { $script:SI_SignalMap_RunCache = @{} }
            if (-not $script:SI_SignalMap_RunCache.ContainsKey($signalMapKey)) {
                if (-not $signalMapTpTable) {
                    . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'asset-profiling\storage\TypeProfileCache.ps1')
                    $signalMapTpTable = Initialize-SITypeProfileTable -Context $RunContext.StorageContext
                }
                $script:SI_SignalMap_RunCache[$signalMapKey] = Get-SISignalMapCached `
                    -Context $RunContext.StorageContext `
                    -TypeProfileTable $signalMapTpTable `
                    -Engine $RunContext.Engine `
                    -AssetType $assetTypeForSignals `
                    -SampleMetadata $r.Metadata
            }
            $smap = $script:SI_SignalMap_RunCache[$signalMapKey]
            $crit = Get-SICriticalityScore -Metadata $r.Metadata -Signals $smap.Signals
            $enrichmentInputs['XENG_CriticalityScore'] = $crit.Score
            $enrichmentInputs['XENG_ActiveSignals']    = $crit.ActiveSignals
            $script:SI_SignalMap_TotalActive += $crit.ActiveSignals.Count
            $script:SI_SignalMap_ScoreSum    += $crit.Score
            $script:SI_SignalMap_AssetCount++
        }

        # dropped fp_enrich verdict-reuse short-circuit. Every
        # asset that proceeded through Stage Collect (= cadence elapsed)
        # gets a fresh AI Classify call (or deterministic v2-rule path).
        # Cache table is still updated by Stage Classify with si_tier +
        # si_verdict + last_seen_at so the cadence skip in the NEXT run
        # can read the latest known tier.
        [void]$enriched.Add(@{
            AssetId      = $r.AssetId
            Source       = $r.Source
            Sources      = $r.Sources
            Metadata     = $r.Metadata
            Enrichment   = $enrichmentInputs
            PostureHits  = $postureHits.ToArray()
            Hint         = $r.Hint
        })
    }

    # All-engines final pass: AI asset-group clustering for
    # endpoint/identity/azure. Stamps XENG_AppGroup + XENG_AppType +
    # XENG_AppGroupConfidence onto every enriched record. Per-engine
    # cluster strategy (azure=RG, endpoint=naming-prefix, identity=dept/OU).
    # Cached per cluster -- re-AI only on membership change.
    $appGroupStats = $null
    if ($enriched.Count -gt 0 -and $RunContext.StorageContext.Mode -ne 'Mock' -and $RunContext.Engine -in 'endpoint','identity','azure') {
        . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'asset-profiling\storage\TypeProfileCache.ps1')
        $tpTable = Initialize-SITypeProfileTable -Context $RunContext.StorageContext
        $appGroupStats = Add-SIAssetGroups -RunContext $RunContext -Enriched $enriched -TypeProfileTable $tpTable
    }

    if ($enriched.Count -gt 0) {
        Write-SIStageShard -Context $RunContext.StorageContext `
                            -ContainerName $RunContext.StagingContainer `
                            -RunId $RunContext.RunId `
                            -Stage 'Enrich' `
                            -ShardIndex 0 `
                            -ReplicaIndex ([int]$RunContext.ShardIndex) `
                            -Records $enriched.ToArray() | Out-Null
    }

    $behaviourHits  = switch ($RunContext.Engine) {
        'identity' { $signInsByUserId.Count }
        'endpoint' { $logonsByName.Count }
        default    { 0 }
    }
    $behaviourLabel = switch ($RunContext.Engine) {
        'identity' { 'have sign-ins' }
        'endpoint' { 'have logons' }
        default    { 'n/a' }
    }

    $crossEngineNote = ''
    if ($RunContext.Engine -eq 'identity' -and $endpointTierMap.Count -gt 0) {
        $crossEngineNote = (', x-eng tier map: {0} endpoints' -f $endpointTierMap.Count)
    }
    if ($RunContext.Engine -eq 'azure' -and ($identityTierMap.Count -gt 0 -or $azureEgEdges.Count -gt 0)) {
        $crossEngineNote = (', x-eng identity tiers: {0}, EG access-edges: {1}' -f $identityTierMap.Count, $azureEgEdges.Count)
    }
    if ($appGroupStats) {
        $crossEngineNote += (', asset-groups AI: {0} new / {1} cached / {2} singletons' -f $appGroupStats.AiCalls, $appGroupStats.CacheHits, $appGroupStats.Singletons)
    }
    if ($script:SI_SignalMap_AssetCount -gt 0) {
        $avgScore = [int]($script:SI_SignalMap_ScoreSum / [Math]::Max(1, $script:SI_SignalMap_AssetCount))
        $crossEngineNote += (', signal-map: {0} active signals (avg score {1})' -f $script:SI_SignalMap_TotalActive, $avgScore)
    }

    [pscustomobject]@{
        Stage         = 'Enrich'
        Count         = $enriched.Count
        ReuseVerdict  = $skipAi
        RulesRun      = $rulesRun
        HitAssets     = $hitAssets
        BehaviourHits = $behaviourHits
        XEngEndpoints = $endpointTierMap.Count
        XEngUsers     = $userDevices.Count
        Summary       = ('{0} enriched -- {1} kql rules ran, {2} metadata-rule hits, {3} matched, {4} {5}, {6} reuse cached{7}' -f $enriched.Count, $rulesRun, $metadataRuleHits, $hitAssets, $behaviourHits, $behaviourLabel, $skipAi, $crossEngineNote)
    }
}
