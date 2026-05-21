#Requires -Version 5.1
<#
    Discovery source for the publicip engine.

    v2.2.348 -- consolidated discovery: the legacy standalone
    Invoke-PublicIpScanner.ps1 (Tier 0-3 servers from SI_*_Profile_CL +
    fresh-scan submit/wait state machine + cmdb passthrough) is folded
    into this single function. Same pipeline now handles internal-vm /
    community-vm / container, and the standalone scanner is retired.

    Candidate IP sources (configurable via $global:SI_PublicIP_DiscoverySource):
      'profile-cl' (DEFAULT) -- only Profile_CL + extras. Preserves the
                                legacy "scan IPs attached to our Tier 0-3
                                servers we already classified" behaviour.
      'arg-eg'              -- ARG publicIPAddresses + EG NodeLabel +
                                extras. Broader coverage; no per-IP
                                tier/cmdb context.
      'union'               -- All sources merged + deduped. Maximum
                                coverage; Profile_CL metadata wins on
                                same-IP collisions.

    Per-IP enrichment policy (unchanged):
      - Cache hit AND age <= $global:SI_ShodanCacheAgeDays (default 7) -> use cached JSON
      - Otherwise call GET https://api.shodan.io/shodan/host/{ip}?key=...
      - 404 from Shodan = IP not in their index -> emit row with InShodan=false
      - Other failure -> log warning, emit row with InShodan=false
      - Optional /scan rescan triggered by either:
          * -ForceShodanRescan switch (per-IP, credit-gated)
          * $global:SI_Shodan_ForceFreshScan = $true (batch, with pending-scan
            state machine for cron-staggered 02:00/03:00/04:00 runs)

    Asset shape (one per IP):
      AssetId, Source, Hint, Name, NormalizedKey,
      IP_Address, IP_Version, IP_AzureResourceId, IP_BoundToResourceId,
      IP_Fqdn, IP_AllocationMethod, IP_DdosProtectionMode,
      EG_NodeId, EG_RawData,
      SHODAN_RawJson, SHODAN_InCache, SHODAN_AgeDays, SHODAN_HttpStatus,
      AssetEngine (endpoint/azure/extra/arg/eg),  AssetTier (from Profile_CL),
      cmdbId, cmdbName, cmdbCriticality, cmdbDataSensitivity (top-level for
      Build-PublicIpProfileRow.ps1; ALSO mirrored as CMDB_* metadata for the
      Properties.collect.cmdb block).
#>

# ============================================================================
# Fresh-scan flow helpers (POST /shodan/scan -> wait/defer -> read host info)
# Ported from legacy Invoke-PublicIpScanner.ps1 so the new pipeline preserves
# the daily 02:00 + 03:00 + 04:00 belt-and-braces cron pattern (first run
# submits + waits, later runs pick up pending state without re-burning credits).
# ============================================================================

function _SIShodanRepoDataDir {
    # discovery/ -> asset-profiling/ -> engine/ -> SecurityInsight/
    return Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'data'
}
function _SIShodanPendingPath {
    if ($global:SI_Shodan_PendingScansPath) { return [string]$global:SI_Shodan_PendingScansPath }
    return Join-Path (_SIShodanRepoDataDir) 'shodan-pending-scans.json'
}
function _SIShodanLastScanPath {
    if ($global:SI_Shodan_LastFreshScanPath) { return [string]$global:SI_Shodan_LastFreshScanPath }
    return Join-Path (_SIShodanRepoDataDir) 'shodan-last-fresh-scan.json'
}

function Submit-SIShodanScan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Ips, [Parameter(Mandatory)][string]$ApiKey)
    $uri  = 'https://api.shodan.io/shodan/scan?key=' + [uri]::EscapeDataString($ApiKey)
    $body = 'ips=' + [uri]::EscapeDataString(($Ips -join ','))
    $timeoutSec = if ($global:SI_Shodan_TimeoutSec) { [int]$global:SI_Shodan_TimeoutSec } else { 15 }
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body `
                    -ContentType 'application/x-www-form-urlencoded' `
                    -TimeoutSec $timeoutSec -ErrorAction Stop
        Write-SIInfo ('scan submitted: id={0} count={1} credits_left={2}' -f $resp.id, $resp.count, $resp.credits_left)
        return [string]$resp.id
    } catch {
        Write-SIWarn ('Shodan scan submit failed: {0}' -f $_.Exception.Message)
        return $null
    }
}

function Get-SIShodanScanStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ScanId, [Parameter(Mandatory)][string]$ApiKey)
    $uri = ('https://api.shodan.io/shodan/scan/{0}?key={1}' -f $ScanId, [uri]::EscapeDataString($ApiKey))
    try { return Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 30 -ErrorAction Stop }
    catch { Write-SIWarn ('scan-status fetch failed: {0}' -f $_.Exception.Message); return $null }
}

function Save-SIShodanPendingScan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ScanId, [Parameter(Mandatory)][string[]]$Ips)
    $p = _SIShodanPendingPath
    $dir = Split-Path -Parent $p
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    [pscustomobject]@{ ScanId=$ScanId; SubmittedAt=([datetime]::UtcNow).ToString('o'); Ips=@($Ips) } |
        ConvertTo-Json -Depth 5 | Out-File -LiteralPath $p -Encoding UTF8 -Force
    Write-SIInfo ('pending scan persisted: {0} ({1} IPs)' -f $ScanId, $Ips.Count)
}

function Load-SIShodanPendingScan {
    $p = _SIShodanPendingPath
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    try { return (Get-Content -LiteralPath $p -Raw | ConvertFrom-Json) }
    catch { Write-SIWarn ('could not parse pending-scans state: {0}' -f $_.Exception.Message); return $null }
}

function Clear-SIShodanPendingScan {
    $p = _SIShodanPendingPath
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
}

function Save-SIShodanLastFreshScan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ScanId, [Parameter(Mandatory)][int]$IpCount)
    $p = _SIShodanLastScanPath
    $dir = Split-Path -Parent $p
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    [pscustomobject]@{ ScanId=$ScanId; CompletedAt=([datetime]::UtcNow).ToString('o'); IpCount=$IpCount } |
        ConvertTo-Json -Depth 5 | Out-File -LiteralPath $p -Encoding UTF8 -Force
}

function Test-SIShodanRecentScan {
    # Returns $true when the last successful fresh-scan completed within the
    # configured interval. Multiple daily runs (02:00 / 03:00 / 04:00) then
    # become safely idempotent: only the first run that finds no recent record
    # actually submits + waits.
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$IntervalHours)
    $p = _SIShodanLastScanPath
    if (-not (Test-Path -LiteralPath $p)) { return $false }
    try {
        $rec = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
        if (-not $rec.CompletedAt) { return $false }
        # Parse as UTC -- saved timestamp is ISO 8601 with 'Z' / offset; [datetime]::Parse
        # silently coerces to local kind and produces negative ages on machines whose
        # local clock is ahead of UTC.
        $completedUtc = ([datetimeoffset]::Parse($rec.CompletedAt)).UtcDateTime
        $age = ([datetime]::UtcNow - $completedUtc).TotalHours
        if ($age -lt [double]$IntervalHours) {
            Write-SIInfo ('recent fresh-scan {0} completed {1:n1}h ago (within {2}h window) -- skipping new submission' -f $rec.ScanId, $age, $IntervalHours)
            return $true
        }
        return $false
    } catch {
        Write-SIWarn ('could not parse last-fresh-scan state: {0}' -f $_.Exception.Message)
        return $false
    }
}

function Invoke-SIShodanFreshScanFlow {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Ips, [Parameter(Mandatory)][string]$ApiKey)
    if ($Ips.Count -eq 0) { return $true }

    $intervalH = if ($global:SI_Shodan_FreshScanIntervalHours) { [int]$global:SI_Shodan_FreshScanIntervalHours } else { 20 }
    $maxWait   = if ($global:SI_Shodan_ScanWaitMaxSec)         { [int]$global:SI_Shodan_ScanWaitMaxSec }         else { 300 }
    $pollSec   = if ($global:SI_Shodan_ScanPollIntervalSec)    { [int]$global:SI_Shodan_ScanPollIntervalSec }    else { 30 }

    # 1. Pending scan from a prior run? Always honor it before considering anything else.
    $pending = Load-SIShodanPendingScan
    if ($pending -and $pending.ScanId) {
        Write-SIStep ('found pending scan {0} (submitted {1}); polling ...' -f $pending.ScanId, $pending.SubmittedAt)
        $st = Get-SIShodanScanStatus -ScanId $pending.ScanId -ApiKey $ApiKey
        if ($null -ne $st -and $st.status -eq 'DONE') {
            Write-SIOk 'pending scan completed -- proceeding to read host info.'
            Save-SIShodanLastFreshScan -ScanId $pending.ScanId -IpCount @($pending.Ips).Count
            Clear-SIShodanPendingScan
            return $true
        }
        $statusVal = if ($st) { [string]$st.status } else { '<no-response>' }
        Write-SIWarn ('pending scan still processing (status={0}). Skipping fresh-scan submit; next run will re-poll.' -f $statusVal)
        return $false
    }

    # 2. Skip-if-recent: don't burn scan credits if a fresh scan finished within the window.
    if (Test-SIShodanRecentScan -IntervalHours $intervalH) { return $true }

    # 3. No pending, no recent -- submit a fresh scan.
    Write-SIStep ('submitting fresh Shodan scan for {0} IP(s) ...' -f $Ips.Count)
    $scanId = Submit-SIShodanScan -Ips $Ips -ApiKey $ApiKey
    if (-not $scanId) {
        Write-SIWarn 'scan submission failed; falling back to read-only host info.'
        return $true
    }
    Save-SIShodanPendingScan -ScanId $scanId -Ips $Ips

    Write-SIInfo ('waiting up to {0}s for scan to complete (poll every {1}s) ...' -f $maxWait, $pollSec)
    $deadline = (Get-Date).AddSeconds($maxWait)
    while ((Get-Date) -lt $deadline) {
        $st = Get-SIShodanScanStatus -ScanId $scanId -ApiKey $ApiKey
        if ($null -ne $st) {
            Write-SIInfo ('scan {0} status={1}' -f $scanId, $st.status)
            if ($st.status -eq 'DONE') {
                Write-SIOk 'scan finished within sync deadline -- proceeding.'
                Save-SIShodanLastFreshScan -ScanId $scanId -IpCount $Ips.Count
                Clear-SIShodanPendingScan
                return $true
            }
        }
        Start-Sleep -Seconds $pollSec
    }
    Write-SIWarn 'scan deadline reached; exiting. Next run will pick up the pending scan from state file.'
    return $false
}

# ============================================================================
# Profile_CL discovery (legacy primary source -- Tier 0-N servers + cmdb)
# Ported from Invoke-PublicIpScanner.ps1::Get-PublicIpsFromProfileTables.
# Returns hashtable keyed on lowercased IP -> {AssetName, AssetEngine,
# AssetTier, cmdbId, cmdbName, cmdbCriticality, cmdbDataSensitivity}.
# ============================================================================

function Get-SIPublicIpsFromProfileCL {
    [CmdletBinding()]
    param()
    $tierMax      = if ($null -ne $global:SI_Shodan_TierMax)        { [int]$global:SI_Shodan_TierMax }        else { 3 }
    $lookbackDays = if ($global:SI_Shodan_LookbackDays)             { [int]$global:SI_Shodan_LookbackDays }   else { 8 }
    $serverOnly   = if ($null -ne $global:SI_Shodan_ServerOnly)     { [bool]$global:SI_Shodan_ServerOnly }    else { $true }

    if ([string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId)) {
        Write-SIWarn 'Profile_CL discovery: $global:SI_WorkspaceResourceId not set -- skipping (no Tier/server filter possible).'
        return @{}
    }

    # Endpoint filter: DeviceType =~ "Server" by default. PublicIp on a workstation
    # = user's home/cafe/cellular ISP NAT, not a scannable asset the customer owns.
    $endpointDeviceFilter = if ($serverOnly) { '    | where tostring(column_ifexists("DeviceType", "")) =~ "Server"' } else { '' }

    $kql = @"
union isfuzzy=true
(
    SI_Endpoint_Profile_CL
    | where TimeGenerated > ago(${lookbackDays}d)
    | summarize arg_max(CollectionTime, *) by PrimaryEntityId
    | where toint(coalesce(Tier, 99)) <= $tierMax
$endpointDeviceFilter
    | extend _ip = tostring(coalesce(
                       column_ifexists("PublicIp", ""),
                       column_ifexists("PublicIpAddress", ""),
                       column_ifexists("ExternalIp", "")))
    | where isnotempty(_ip)
    | project AssetName, AssetEngine = "endpoint", AssetTier = toint(coalesce(Tier, 99)),
              cmdbId              = tostring(column_ifexists("cmdbId", "")),
              cmdbName            = tostring(column_ifexists("cmdbName", "")),
              cmdbCriticality     = tostring(column_ifexists("cmdbCriticality", "")),
              cmdbDataSensitivity = tostring(column_ifexists("cmdbDataSensitivity", "")),
              IpAddress = _ip
),
(
    SI_Azure_Profile_CL
    | where TimeGenerated > ago(${lookbackDays}d)
    | summarize arg_max(CollectionTime, *) by PrimaryEntityId
    | where toint(coalesce(Tier, 99)) <= $tierMax
    | extend _ip = tostring(coalesce(
                       column_ifexists("PipAddress", ""),
                       column_ifexists("PublicIpAddress", ""),
                       column_ifexists("IpAddress", "")))
    | where isnotempty(_ip)
    | project AssetName, AssetEngine = "azure", AssetTier = toint(coalesce(Tier, 99)),
              cmdbId              = tostring(column_ifexists("cmdbId", "")),
              cmdbName            = tostring(column_ifexists("cmdbName", "")),
              cmdbCriticality     = tostring(column_ifexists("cmdbCriticality", "")),
              cmdbDataSensitivity = tostring(column_ifexists("cmdbDataSensitivity", "")),
              IpAddress = _ip
)
| where IpAddress matches regex @"^(?:\d{1,3}\.){3}\d{1,3}`$"
| summarize arg_min(AssetTier, *) by IpAddress
"@

    try {
        if ($global:SI_WorkspaceResourceId -notmatch '^/subscriptions/(?<sub>[^/]+)/resourceGroups/(?<rg>[^/]+)/providers/Microsoft\.OperationalInsights/workspaces/(?<name>[^/]+)$') {
            Write-SIWarn ("Profile_CL discovery: bad SI_WorkspaceResourceId '{0}' -- skipping." -f $global:SI_WorkspaceResourceId)
            return @{}
        }
        $wsSub  = $matches.sub; $wsRg = $matches.rg; $wsName = $matches.name
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $ctx -or $ctx.Subscription.Id -ne $wsSub) {
            Set-AzContext -SubscriptionId $wsSub -ErrorAction Stop | Out-Null
        }
        $wsCustomerId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $wsRg -Name $wsName -ErrorAction Stop).CustomerId
        $resp = Invoke-AzOperationalInsightsQuery -WorkspaceId $wsCustomerId -Query $kql -ErrorAction Stop
    } catch {
        $errBody = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errBody = $_.ErrorDetails.Message }
        Write-SIWarn ('Profile_CL discovery: LA query failed -- {0}' -f $_.Exception.Message)
        if ($errBody) { Write-SIWarn ('  detail: {0}' -f $errBody) }
        Write-SIInfo '  hint: typical cause is Endpoint + Azure engines have not created Profile_CL tables yet. Run those first.'
        return @{}
    }

    $byIp = @{}
    foreach ($r in @($resp.Results)) {
        if (-not $r.IpAddress) { continue }
        $byIp[([string]$r.IpAddress).ToLowerInvariant()] = $r
    }
    $modeLabel = if ($serverOnly) { 'servers' } else { 'all device types' }
    Write-SIInfo ('   [publicip] Profile_CL Tier 0-{0} {1}: {2}' -f $tierMax, $modeLabel, $byIp.Count)
    return $byIp
}

# ============================================================================
# MAIN DISCOVERY ENTRY POINT
# ============================================================================

function Get-DiscoveryFromShodan {
    [CmdletBinding()]
    param(
        [Parameter()][object]$RunContext,
        [switch]$AllowEmptyOnStub,
        [switch]$ForceShodanRescan
    )

    if ($AllowEmptyOnStub) {
        Write-Warning 'Shodan discovery stubbed off via -AllowEmptyOnStub. Returning 0 assets.'
        return @()
    }

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIShodanKey.ps1")
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'storage/ShodanCache.ps1')
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/HuntingQuery.ps1')

    $apiKey      = Get-SIShodanKey
    $cacheCtx    = if ($RunContext -and $RunContext.StorageContext) { $RunContext.StorageContext } else { $null }
    $cacheAgeMax = if ($global:SI_ShodanCacheAgeDays) { [int]$global:SI_ShodanCacheAgeDays } else { 7 }
    $creditCap   = if ($global:SI_ShodanMonthlyCreditCap) { [int]$global:SI_ShodanMonthlyCreditCap } else { 4000 }
    $throttleMs  = if ($global:SI_Shodan_ThrottleMs) { [int]$global:SI_Shodan_ThrottleMs } else { 1100 }
    $timeoutSec  = if ($global:SI_Shodan_TimeoutSec) { [int]$global:SI_Shodan_TimeoutSec } else { 15 }

    if ($cacheCtx) { Initialize-SIShodanCacheTables -Context $cacheCtx }

    # Discovery source policy: 'profile-cl' (DEFAULT, legacy parity) | 'arg-eg' | 'union'.
    $discMode = if ($global:SI_PublicIP_DiscoverySource) { [string]$global:SI_PublicIP_DiscoverySource } else { 'profile-cl' }
    $discMode = $discMode.ToLowerInvariant()
    if ($discMode -notin @('profile-cl','arg-eg','union')) {
        Write-SIWarn ("Unknown SI_PublicIP_DiscoverySource '{0}' -- falling back to 'profile-cl'." -f $discMode)
        $discMode = 'profile-cl'
    }
    Write-SIInfo ('   [publicip] discovery source mode: {0}' -f $discMode)

    # ---------------------------------------------------------------------
    # 1. Profile_CL  (legacy primary -- Tier 0-N servers + cmdb)
    # ---------------------------------------------------------------------
    $profileIps = @{}
    if ($discMode -in @('profile-cl','union')) {
        $profileIps = Get-SIPublicIpsFromProfileCL
    }

    # ---------------------------------------------------------------------
    # 2. Azure Resource Graph (publicIPAddresses)
    # ---------------------------------------------------------------------
    $argIps = @{}
    if ($discMode -in @('arg-eg','union')) {
        try {
            $argQuery = @"
resources
| where type =~ 'microsoft.network/publicipaddresses'
| where isnotnull(properties.ipAddress)
| project Ip                  = tolower(tostring(properties.ipAddress)),
          AzureResourceId     = id,
          BoundToResourceId   = tostring(properties.ipConfiguration.id),
          Fqdn                = tostring(properties.dnsSettings.fqdn),
          AllocationMethod    = tostring(properties.publicIPAllocationMethod),
          DdosProtectionMode  = tostring(properties.ddosSettings.protectionMode),
          IpVersion           = tostring(properties.publicIPAddressVersion),
          ResourceGroup       = resourceGroup,
          SubscriptionId      = subscriptionId
"@
            $resp = Search-AzGraph -Query $argQuery -First 1000 -ErrorAction Stop
            foreach ($r in $resp) {
                if (-not $r.Ip) { continue }
                $argIps[$r.Ip] = $r
            }
        } catch {
            Write-SIWarn ('PublicIP discovery: ARG query failed -- {0}; continuing with EG + extras only' -f $_.Exception.Message)
        }
        Write-SIInfo ('   [publicip] ARG public IPs: {0}' -f $argIps.Count)
    }

    # ---------------------------------------------------------------------
    # 3. Defender Exposure Graph
    # ---------------------------------------------------------------------
    $egIps = @{}
    if ($discMode -in @('arg-eg','union')) {
        try {
            $egKql = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.network/publicipaddresses'
| extend rawData = parse_json(NodeProperties).rawData
| extend Ip = tolower(tostring(rawData.ipAddress))
| where isnotempty(Ip)
| project Ip, NodeId, NodeLabel, NodeName, NodePropertiesJson = tostring(NodeProperties)
"@
            $egRows = @(Invoke-SIHuntingQuery -Query $egKql -QueryEngine DefenderGraph)
            foreach ($r in $egRows) {
                if (-not $r.Ip) { continue }
                $egIps[$r.Ip] = $r
            }
        } catch {
            Write-SIWarn ('PublicIP discovery: EG query failed -- {0}; continuing without EG enrichment' -f $_.Exception.Message)
        }
        Write-SIInfo ('   [publicip] EG public IP nodes: {0}' -f $egIps.Count)
    }

    # ---------------------------------------------------------------------
    # 4. Customer-supplied extras  ($global:SI_PublicIP_ExtraTargets simple list,
    #    or asset-profiling-schema/public-ip.schema.custom.json extraIPs.entries[]
    #    rich form -- name + tier + cmdb*)
    # ---------------------------------------------------------------------
    $extraIps = @{}
    $extraEnriched = @{}    # ip -> {AssetName, AssetTier, cmdbId, ...}
    if ($global:SI_PublicIP_ExtraTargets) {
        foreach ($x in @($global:SI_PublicIP_ExtraTargets)) {
            if ($x) { $extraIps[([string]$x).ToLowerInvariant()] = $true }
        }
    }
    # Rich form from schema overlay JSON
    $repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $customSchema = Join-Path $repoRoot 'asset-profiling-schema/public-ip.schema.custom.json'
    if (Test-Path -LiteralPath $customSchema) {
        try {
            $body = Get-Content -LiteralPath $customSchema -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($body.PSObject.Properties['extraIPs'] -and $body.extraIPs.PSObject.Properties['entries']) {
                # Case-insensitive scalar getter (PS 5.1 doesn't allow `if` as expression
                # inside [string]() cast -- parses 'if' as a command name -- so use a
                # helper that returns the value explicitly and cast outside.
                $_get = {
                    param($Entry, [string]$Key)
                    if ($null -eq $Entry) { return $null }
                    foreach ($p in $Entry.PSObject.Properties) {
                        if ([string]::Equals($p.Name, $Key, [System.StringComparison]::OrdinalIgnoreCase)) { return $p.Value }
                    }
                    return $null
                }
                foreach ($e in @($body.extraIPs.entries)) {
                    if (-not $e) { continue }
                    $ipRaw = [string](& $_get $e 'ipAddress')
                    if ([string]::IsNullOrWhiteSpace($ipRaw)) { continue }
                    $ipKey = $ipRaw.ToLowerInvariant()
                    $extraIps[$ipKey] = $true
                    $_tierRaw = & $_get $e 'tier'
                    $_tier    = if ($null -ne $_tierRaw -and -not [string]::IsNullOrWhiteSpace([string]$_tierRaw)) { [int]$_tierRaw } else { 99 }
                    $extraEnriched[$ipKey] = [pscustomobject]@{
                        AssetName           = [string](& $_get $e 'assetName')
                        AssetTier           = $_tier
                        cmdbId              = [string](& $_get $e 'cmdbId')
                        cmdbName            = [string](& $_get $e 'cmdbName')
                        cmdbCriticality     = [string](& $_get $e 'cmdbCriticality')
                        cmdbDataSensitivity = [string](& $_get $e 'cmdbDataSensitivity')
                    }
                }
            }
        } catch { Write-SIWarn ('Failed to parse {0}: {1}' -f $customSchema, $_.Exception.Message) }
    }
    Write-SIInfo ('   [publicip] Customer-supplied extras: {0}' -f $extraIps.Count)

    # ---------------------------------------------------------------------
    # Merge candidate set
    # ---------------------------------------------------------------------
    $allIps = New-Object System.Collections.Generic.HashSet[string]
    foreach ($k in $profileIps.Keys) { [void]$allIps.Add($k) }
    foreach ($k in $argIps.Keys)     { [void]$allIps.Add($k) }
    foreach ($k in $egIps.Keys)      { [void]$allIps.Add($k) }
    foreach ($k in $extraIps.Keys)   { [void]$allIps.Add($k) }
    Write-SIInfo ('   [publicip] unique candidate IPs: {0}' -f $allIps.Count)
    if ($allIps.Count -eq 0) { return @() }

    # AssetLimit cap (legacy $global:SI_Shodan_AssetLimit; 0 = no cap)
    $assetLimit = if ($null -ne $global:SI_Shodan_AssetLimit) { [int]$global:SI_Shodan_AssetLimit } else { 0 }
    if ($assetLimit -gt 0 -and $allIps.Count -gt $assetLimit) {
        Write-SIWarn ('AssetLimit cap: trimming {0} -> {1}' -f $allIps.Count, $assetLimit)
        $allIps = New-Object 'System.Collections.Generic.HashSet[string]' (,([string[]]@($allIps | Select-Object -First $assetLimit)))
    }

    # ---------------------------------------------------------------------
    # FRESH-SCAN FLOW (POST /shodan/scan, wait or defer). Legacy
    # multi-host belt-and-braces pattern: 02:00 submits, 03:00 polls,
    # 04:00 polls again. Skip-if-recent gate prevents redundant credit burn.
    # Gated by $global:SI_Shodan_ForceFreshScan (default $false).
    # ---------------------------------------------------------------------
    if ([bool]$global:SI_Shodan_ForceFreshScan) {
        if ([string]::IsNullOrWhiteSpace($apiKey)) {
            Write-SIWarn 'ForceFreshScan requested but Shodan API key not available -- skipping submit.'
        } else {
            $proceed = Invoke-SIShodanFreshScanFlow -Ips ([string[]]@($allIps)) -ApiKey $apiKey
            if (-not $proceed) {
                Write-SIWarn 'deferring read until scan completes (state file persisted). Returning 0 rows; next run will retry.'
                return @()
            }
        }
    }

    # ---------------------------------------------------------------------
    # Per-IP Shodan enrichment (cache hit -> live /host -> optional /scan)
    # ---------------------------------------------------------------------
    $rows = New-Object System.Collections.ArrayList
    $shodanHits = 0; $shodanCacheHits = 0; $shodan404 = 0; $shodanErrs = 0; $shodanScans = 0
    $creditsAtStart = if ($cacheCtx) { Get-SIShodanCreditsUsedThisMonth -Context $cacheCtx } else { 0 }

    $total = $allIps.Count
    $progressStep = [Math]::Max(1, [int]($total / 20))
    $i = 0
    foreach ($ip in $allIps) {
        $i++
        if ($i -eq 1 -or ($i % $progressStep -eq 0) -or $i -eq $total) {
            Write-SIInfo ('   shodan: {0,4}/{1,-4}  current={2}' -f $i, $total, $ip)
        }

        $rawJson    = ''
        $httpStatus = 0
        $inCache    = $false
        $ageDays    = -1
        $shodanLastUpdate = ''

        # 1. Cache check
        if ($cacheCtx) {
            $hit = Get-SIShodanHostFromCache -Context $cacheCtx -Ip $ip
            if ($hit -and $hit.AgeDays -le $cacheAgeMax) {
                $rawJson    = $hit.Json
                $httpStatus = 200
                $inCache    = $true
                $ageDays    = $hit.AgeDays
                $shodanCacheHits++
            }
        }

        # 2. Live fetch when no fresh cache
        if (-not $inCache -and $apiKey) {
            $url = ('https://api.shodan.io/shodan/host/{0}?key={1}&minify=false' -f $ip, $apiKey)
            try {
                $resp = Invoke-WebRequest -UseBasicParsing -Uri $url -Method Get -TimeoutSec $timeoutSec -ErrorAction Stop
                $httpStatus = [int]$resp.StatusCode
                $rawJson    = [string]$resp.Content
                if ($cacheCtx) {
                    try {
                        $parsed = $rawJson | ConvertFrom-Json
                        if ($parsed.PSObject.Properties['last_update']) { $shodanLastUpdate = [string]$parsed.last_update }
                    } catch { }
                    Set-SIShodanHostCache -Context $cacheCtx -Ip $ip -JsonResponse $rawJson -ShodanLastUpdate $shodanLastUpdate
                }
                $shodanHits++
            } catch {
                $code = 0
                if ($_.Exception.Response) { try { $code = [int]$_.Exception.Response.StatusCode } catch {} }
                $httpStatus = $code
                if ($code -eq 404) {
                    $shodan404++
                    if ($cacheCtx) { Set-SIShodanHostCache -Context $cacheCtx -Ip $ip -JsonResponse '' }
                } else {
                    $shodanErrs++
                }
            }
            # Shodan rate limit: 1 call/sec free tier. Throttle BETWEEN live calls,
            # not on cache hits (those don't touch the API).
            if ($i -lt $total -and $throttleMs -gt 0) { Start-Sleep -Milliseconds $throttleMs }
        }

        # 3. Optional on-demand /scan (rare, opt-in, credit-gated). Per-IP
        # request -- separate from the batch fresh-scan flow above.
        if ($ForceShodanRescan -and $apiKey -and $cacheCtx) {
            $used = Get-SIShodanCreditsUsedThisMonth -Context $cacheCtx
            if ($used -lt $creditCap) {
                $scanUrl = ('https://api.shodan.io/shodan/scan?key={0}' -f $apiKey)
                try {
                    Invoke-WebRequest -UseBasicParsing -Uri $scanUrl -Method Post -Body ('ips={0}' -f $ip) -ErrorAction Stop | Out-Null
                    Add-SIShodanCreditsUsed -Context $cacheCtx -Delta 1
                    $shodanScans++
                } catch {
                    Write-SIWarn ('Shodan /scan failed for {0}: {1}' -f $ip, $_.Exception.Message)
                }
            } else {
                Write-SIWarn ('Shodan /scan skipped for {0}: monthly credit cap reached ({1}/{2})' -f $ip, $used, $creditCap)
            }
        }

        # Build the row. Profile_CL data wins for AssetName/AssetTier/cmdb*
        # (richest context). Falls back to ARG entry for IP_*, then extras enriched.
        $profEntry  = $profileIps[$ip]
        $argEntry   = $argIps[$ip]
        $egEntry    = $egIps[$ip]
        $extraEntry = $extraEnriched[$ip]

        # AssetEngine + Hint precedence (richest source wins). Used for the
        # AssetEngine column in SI_VulnerabilityPIP_CL (legacy RA queries
        # filter / display by this).
        $assetEngine = if ($profEntry)  { [string]$profEntry.AssetEngine }
                       elseif ($argEntry)   { 'azure' }
                       elseif ($egEntry)    { 'eg' }
                       elseif ($extraEntry) { 'extra' }
                       else                 { 'unknown' }
        $hint = if ($profEntry)  { 'profile-cl' }
                 elseif ($argEntry)   { 'azure-pip' }
                 elseif ($egEntry)    { 'eg-exposed' }
                 elseif ($extraEntry) { 'extra' }
                 else                 { 'unknown' }

        # AssetName: Profile_CL > extras-enriched > IP (last resort)
        $assetName = if ($profEntry -and $profEntry.AssetName)        { [string]$profEntry.AssetName }
                     elseif ($extraEntry -and $extraEntry.AssetName)  { [string]$extraEntry.AssetName }
                     else                                              { $ip }

        # AssetTier: Profile_CL > extras-enriched > 99 (unknown)
        $assetTier = if ($profEntry -and $null -ne $profEntry.AssetTier)         { [int]$profEntry.AssetTier }
                     elseif ($extraEntry -and $null -ne $extraEntry.AssetTier)   { [int]$extraEntry.AssetTier }
                     else                                                         { 99 }

        # cmdb*: Profile_CL > extras-enriched > empty
        $cmdbId   = if ($profEntry)  { [string]$profEntry.cmdbId }              elseif ($extraEntry) { [string]$extraEntry.cmdbId }              else { '' }
        $cmdbName = if ($profEntry)  { [string]$profEntry.cmdbName }            elseif ($extraEntry) { [string]$extraEntry.cmdbName }            else { '' }
        $cmdbCrit = if ($profEntry)  { [string]$profEntry.cmdbCriticality }     elseif ($extraEntry) { [string]$extraEntry.cmdbCriticality }     else { '' }
        $cmdbSens = if ($profEntry)  { [string]$profEntry.cmdbDataSensitivity } elseif ($extraEntry) { [string]$extraEntry.cmdbDataSensitivity } else { '' }

        $row = @{
            AssetId               = 'ip:' + $ip
            Source                = 'PublicIP'
            Hint                  = $hint
            Name                  = $assetName
            NormalizedKey         = $ip
            IP_Address            = $ip
            IP_Version            = if ($ip -like '*:*') { 'IPv6' } else { 'IPv4' }
            IP_AzureResourceId    = if ($argEntry) { [string]$argEntry.AzureResourceId } else { '' }
            IP_BoundToResourceId  = if ($argEntry) { [string]$argEntry.BoundToResourceId } else { '' }
            IP_Fqdn               = if ($argEntry) { [string]$argEntry.Fqdn } else { '' }
            IP_AllocationMethod   = if ($argEntry) { [string]$argEntry.AllocationMethod } else { '' }
            IP_DdosProtectionMode = if ($argEntry) { [string]$argEntry.DdosProtectionMode } else { '' }
            EG_NodeId             = if ($egEntry)  { [string]$egEntry.NodeId } else { '' }
            EG_RawData            = if ($egEntry)  { [string]$egEntry.NodePropertiesJson } else { '' }
            SHODAN_RawJson        = $rawJson
            SHODAN_InCache        = $inCache
            SHODAN_AgeDays        = $ageDays
            SHODAN_HttpStatus     = $httpStatus
            # Legacy passthrough -- promoted to top-level so the row builder
            # can emit them as flat SI_VulnerabilityPIP_CL columns matching
            # what the RA YAML queries expect (HasShodanRecord, AssetTier,
            # AssetEngine, cmdb*).
            AssetEngine           = $assetEngine
            AssetTier             = $assetTier
            cmdbId                = $cmdbId
            cmdbName              = $cmdbName
            cmdbCriticality       = $cmdbCrit
            cmdbDataSensitivity   = $cmdbSens
            # CMDB_* mirror lands inside Properties.collect.cmdb via
            # Build-PublicIpProfileRow.ps1's existing 'CMDB_*' substring(5) handler.
            CMDB_Id               = $cmdbId
            CMDB_Name             = $cmdbName
            CMDB_Criticality      = $cmdbCrit
            CMDB_DataSensitivity  = $cmdbSens
        }
        [void]$rows.Add($row)
    }

    $creditsAtEnd = if ($cacheCtx) { Get-SIShodanCreditsUsedThisMonth -Context $cacheCtx } else { 0 }
    Write-SIInfo ('   [publicip] Shodan: live={0} cache-hit={1} 404={2} err={3} scans={4} | credits this month: {5}' -f `
        $shodanHits, $shodanCacheHits, $shodan404, $shodanErrs, $shodanScans, $creditsAtEnd)
    if ($creditsAtEnd -ge ($creditCap * 0.8) -and $creditCap -gt 0) {
        Write-Warning ('  Shodan scan credits at {0}/{1} ({2}%) -- approaching cap' -f $creditsAtEnd, $creditCap, [int](100 * $creditsAtEnd / $creditCap))
    }
    return $rows.ToArray()
}
