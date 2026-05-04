#Requires -Version 5.1
<#
    Discovery source for the publicip engine.

    Pulls IP candidates from THREE places, dedupes, then enriches each with
    a Shodan /host/{ip} lookup (free; uses the customer's monthly query
    quota, NOT the scan-credit budget).

    Candidate IP sources:
      1. Azure Resource Graph (microsoft.network/publicipaddresses)         -- per-tenant
      2. Defender Exposure Graph (NodeLabel = microsoft.network/publicipaddresses
         OR rawData.exposedToInternet contains an IP)                        -- per-tenant
      3. Customer-supplied list ($global:SI_PublicIP_ExtraTargets)           -- partner / supply-chain

    Per-IP enrichment policy:
      - Cache hit AND age <= $global:SI_ShodanCacheAgeDays (default 7) -> use cached JSON
      - Otherwise call GET https://api.shodan.io/shodan/host/{ip}?key=...
      - 404 from Shodan = IP not in their index -> emit row with InShodan=false
      - Other failure -> log warning, emit row with InShodan=false
      - Optional -ForceShodanRescan triggers POST /shodan/scan (1 credit each,
        gated by $global:SI_ShodanMonthlyCreditCap)

    Asset shape (one per IP):
      AssetId             -- 'ip:' + lowercased IP
      Source              -- 'PublicIP'
      Hint                -- 'azure-pip' / 'eg-exposed' / 'extra'
      Name                -- the IP itself
      NormalizedKey       -- lowercased IP (for dedup across sources)
      IP_Address          -- the IP
      IP_Version          -- 'IPv4' / 'IPv6'
      IP_AzureResourceId  -- ARM ID when azure-pip source, else null
      IP_BoundToResourceId
      IP_Fqdn
      IP_AllocationMethod
      IP_DdosProtectionMode
      EG_NodeId           -- when EG source
      EG_RawData          -- whole NodeProperties.rawData blob (cross-engine join)
      SHODAN_RawJson      -- whole /host response JSON string (or empty)
      SHODAN_InCache      -- bool
      SHODAN_AgeDays      -- int
      SHODAN_HttpStatus   -- 200 / 404 / 0 (=no call made)
#>

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

    if ($cacheCtx) { Initialize-SIShodanCacheTables -Context $cacheCtx }

    # ---------------------------------------------------------------------
    # 1. Pull candidate IPs from Azure Resource Graph (publicIPAddresses)
    # ---------------------------------------------------------------------
    $argIps = @{}
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
        Write-Warning ('PublicIP discovery: ARG query failed -- {0}; continuing with EG + extras only' -f $_.Exception.Message)
    }
    Write-SIInfo ('   [publicip] ARG public IPs: {0}' -f $argIps.Count)

    # ---------------------------------------------------------------------
    # 2. Pull candidate IPs from Defender Exposure Graph
    # ---------------------------------------------------------------------
    $egIps = @{}
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
        Write-Warning ('PublicIP discovery: EG query failed -- {0}; continuing without EG enrichment' -f $_.Exception.Message)
    }
    Write-SIInfo ('   [publicip] EG public IP nodes: {0}' -f $egIps.Count)

    # ---------------------------------------------------------------------
    # 3. Customer-supplied extras
    # ---------------------------------------------------------------------
    $extraIps = @{}
    if ($global:SI_PublicIP_ExtraTargets) {
        foreach ($x in @($global:SI_PublicIP_ExtraTargets)) {
            if ($x) { $extraIps[([string]$x).ToLowerInvariant()] = $true }
        }
    }
    Write-SIInfo ('   [publicip] Customer-supplied extras: {0}' -f $extraIps.Count)

    # ---------------------------------------------------------------------
    # Merge candidate set
    # ---------------------------------------------------------------------
    $allIps = New-Object System.Collections.Generic.HashSet[string]
    foreach ($k in $argIps.Keys)   { [void]$allIps.Add($k) }
    foreach ($k in $egIps.Keys)    { [void]$allIps.Add($k) }
    foreach ($k in $extraIps.Keys) { [void]$allIps.Add($k) }
    Write-SIInfo ('   [publicip] unique candidate IPs: {0}' -f $allIps.Count)

    if ($allIps.Count -eq 0) { return @() }

    # ---------------------------------------------------------------------
    # Per-IP Shodan enrichment (cached)
    # ---------------------------------------------------------------------
    $rows = New-Object System.Collections.ArrayList
    $shodanHits = 0; $shodanCacheHits = 0; $shodan404 = 0; $shodanErrs = 0; $shodanScans = 0
    $creditsAtStart = if ($cacheCtx) { Get-SIShodanCreditsUsedThisMonth -Context $cacheCtx } else { 0 }

    foreach ($ip in $allIps) {
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
                $resp = Invoke-WebRequest -UseBasicParsing -Uri $url -Method Get -ErrorAction Stop
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
        }

        # 3. Optional on-demand /scan (rare, opt-in, credit-gated)
        if ($ForceShodanRescan -and $apiKey -and $cacheCtx) {
            $used = Get-SIShodanCreditsUsedThisMonth -Context $cacheCtx
            if ($used -lt $creditCap) {
                $scanUrl = ('https://api.shodan.io/shodan/scan?key={0}' -f $apiKey)
                try {
                    Invoke-WebRequest -UseBasicParsing -Uri $scanUrl -Method Post -Body ('ips={0}' -f $ip) -ErrorAction Stop | Out-Null
                    Add-SIShodanCreditsUsed -Context $cacheCtx -Delta 1
                    $shodanScans++
                } catch {
                    Write-Warning ('Shodan /scan failed for {0}: {1}' -f $ip, $_.Exception.Message)
                }
            } else {
                Write-Warning ('Shodan /scan skipped for {0}: monthly credit cap reached ({1}/{2})' -f $ip, $used, $creditCap)
            }
        }

        $argEntry = $argIps[$ip]
        $egEntry  = $egIps[$ip]
        $hint = if ($argEntry) { 'azure-pip' } elseif ($egEntry) { 'eg-exposed' } else { 'extra' }

        $row = @{
            AssetId               = 'ip:' + $ip
            Source                = 'PublicIP'
            Hint                  = $hint
            Name                  = $ip
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
