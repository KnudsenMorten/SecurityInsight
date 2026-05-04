#Requires -Version 5.1
<#
    EndpointAzureCorrelationCache.ps1

    Cross-engine cache: AzureResourceId -> MdeDeviceId.

    Lets the AZURE engine row builder discover the endpoint side's MDE device
    that corresponds to an Azure VM / Azure Arc resource and append it to the
    azure row's EntityIds[] so customers can KQL-join Azure_Profile_CL with
    Endpoint_Profile_CL on a shared MdeDeviceId.

    Source-of-truth: SI_Endpoint_Profile_CL rows from PRIOR endpoint runs.
    The endpoint engine carries AzureResourceId in its row when MDE has the
    machine onboarded with an Azure-hosted source.

    Per-run singleton:
      - Cache initialises lazily on FIRST lookup attempt during a run.
      - Stored in script-scoped hashtable keyed by lowercased AzureResourceId.
      - On any LA query failure (workspace not configured, query throws,
        zero rows) -> empty cache. Engine row build never fails because of
        a missing correlation; the row simply ships without the MdeDeviceId
        EntityIds entry.

    Memory cost: ~1 KB per endpoint -> < 5 MB for the largest tenants seen.
    Acceptable for a single per-run lookup.

    Lookup helper returns $null when:
      - cache disabled ($global:SI_DisableEndpointAzureCorrelation = $true)
      - LA workspace not configured
      - resource id not present in Endpoint_Profile_CL
#>

if (-not (Get-Variable -Name _SIEndpointAzureCorrelation -Scope Script -ErrorAction SilentlyContinue)) {
    $script:_SIEndpointAzureCorrelation = @{
        Initialized = $false
        Map         = @{}    # lowercased AzureResourceId -> MdeDeviceId
        Source      = $null  # 'la' | 'empty' | 'disabled' (diagnostic)
        Count       = 0
    }
}

function Reset-SIEndpointAzureCorrelationCache {
    <# Test / Get-DiscoveryFromARG re-run helper. NOT called from production
       code paths -- they intentionally reuse the per-run singleton. #>
    [CmdletBinding()]
    param()
    $script:_SIEndpointAzureCorrelation = @{
        Initialized = $false
        Map         = @{}
        Source      = $null
        Count       = 0
    }
}

function Initialize-SIEndpointAzureCorrelationCache {
    <#
        Lazy initialiser. Pulls one LA query against SI_Endpoint_Profile_CL
        for the LATEST snapshot, projects (AzureResourceId, MdeDeviceId),
        and builds the lookup hashtable.

        Idempotent + safe -- second call is a no-op.
    #>
    [CmdletBinding()]
    param(
        [string]$EndpointTableName = 'SI_Endpoint_Profile_CL'
    )
    if ($script:_SIEndpointAzureCorrelation.Initialized) { return }
    $script:_SIEndpointAzureCorrelation.Initialized = $true   # set EARLY so a failing init doesn't loop on every row

    if ($global:SI_DisableEndpointAzureCorrelation) {
        $script:_SIEndpointAzureCorrelation.Source = 'disabled'
        Write-Verbose 'EndpointAzureCorrelation: DISABLED via $global:SI_DisableEndpointAzureCorrelation.'
        return
    }
    if ([string]::IsNullOrWhiteSpace($global:SI_WorkspaceResourceId)) {
        $script:_SIEndpointAzureCorrelation.Source = 'empty'
        Write-Verbose 'EndpointAzureCorrelation: $global:SI_WorkspaceResourceId not set; cache empty.'
        return
    }

    # Load shared LA query helper (engine/asset-profiling/shared/HuntingQuery.ps1).
    if (-not (Get-Command -Name Invoke-SIHuntingQuery -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'HuntingQuery.ps1')
    }

    # KQL: take the LATEST snapshot only (one row per device, not per CollectionTime).
    # Project early to avoid moving the full row payload across the wire.
    # use column_ifexists for AzureResourceId_s + PrimaryEntityId_s
    # because those _s string-mirror columns only exist when AzLogDcrIngestPS
    # detected a type conflict; on cleanly-typed dynamic columns they don't
    # exist at all and `isnotempty(AzureResourceId_s)` BadRequests the query.
    $kql = @"
$EndpointTableName
| extend _azidStr  = column_ifexists('AzureResourceId_s', '')
| extend _mdeidStr = column_ifexists('PrimaryEntityId_s', '')
| extend _azid  = coalesce(_azidStr, tostring(AzureResourceId))
| extend _mdeid = coalesce(_mdeidStr, tostring(PrimaryEntityId))
| where isnotempty(_azid) and isnotempty(_mdeid)
| summarize arg_max(CollectionTime, _mdeid) by _azid
| project AzureResourceId = tolower(_azid), MdeDeviceId = _mdeid
"@

    try {
        $rows = @(Invoke-SIHuntingQuery -Query $kql -QueryEngine 'LogAnalytics' -ErrorAction Stop)
    } catch {
        Write-Warning ('EndpointAzureCorrelation: LA query failed -- {0}. Cache stays empty.' -f $_.Exception.Message)
        $script:_SIEndpointAzureCorrelation.Source = 'empty'
        return
    }

    foreach ($r in $rows) {
        $azId = [string]$r.AzureResourceId
        $mde  = [string]$r.MdeDeviceId
        if ([string]::IsNullOrWhiteSpace($azId) -or [string]::IsNullOrWhiteSpace($mde)) { continue }
        $key = $azId.ToLowerInvariant()
        # Last-write-wins -- duplicates would only happen mid-rollover and the
        # arg_max() above already picked the freshest CollectionTime per id.
        $script:_SIEndpointAzureCorrelation.Map[$key] = $mde
    }
    $script:_SIEndpointAzureCorrelation.Source = 'la'
    $script:_SIEndpointAzureCorrelation.Count  = $script:_SIEndpointAzureCorrelation.Map.Count
    Write-Verbose ('EndpointAzureCorrelation: {0} azure->mde mappings cached from {1}.' -f $script:_SIEndpointAzureCorrelation.Count, $EndpointTableName)
}

function Get-SIEndpointMdeDeviceIdForAzureResource {
    <#
        Returns the MdeDeviceId that the endpoint engine is using for the given
        AzureResourceId, or $null when there's no match.

        Initialises the cache on first call. Lookup is case-insensitive on the
        AzureResourceId (ARM ids are case-insensitive in practice; the source
        rows are tolowered at write time).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$AzureResourceId
    )
    if ([string]::IsNullOrWhiteSpace($AzureResourceId)) { return $null }
    if (-not $script:_SIEndpointAzureCorrelation.Initialized) {
        Initialize-SIEndpointAzureCorrelationCache
    }
    $key = $AzureResourceId.ToLowerInvariant()
    if ($script:_SIEndpointAzureCorrelation.Map.ContainsKey($key)) {
        return [string]$script:_SIEndpointAzureCorrelation.Map[$key]
    }
    return $null
}

function Get-SIEndpointAzureCorrelationStats {
    <# Diagnostic accessor -- callers can log how many mappings the cache has. #>
    [CmdletBinding()]
    param()
    return [pscustomobject]@{
        Initialized = $script:_SIEndpointAzureCorrelation.Initialized
        Source      = $script:_SIEndpointAzureCorrelation.Source
        Count       = $script:_SIEndpointAzureCorrelation.Count
    }
}
