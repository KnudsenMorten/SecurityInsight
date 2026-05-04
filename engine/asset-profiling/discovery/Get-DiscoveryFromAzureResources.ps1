#Requires -Version 5.1
<#
    Discovery source for the AZURE engine.

    Returns EVERY Azure resource the calling principal can read via ARG --
    not a curated allowlist. Per-type schema variation is handled downstream
    by the type-profile cache (Stage Collect asks AI once per resource type
    "which props are stable for fp_meta, which are security-relevant" and
    caches the answer in sitypeprofiles).

    Optional knobs:
      $global:SI_AzureResourceTypes        -- if set, RESTRICTS to those types
                                              (back-compat with behaviour; leave unset for full
                                              tenant inventory).
      $global:SI_AzureExcludeTypes         -- exclude noisy types (insights/
                                              alertinstances etc.). Defaults
                                              filter the worst offenders.
      $global:SI_AzureMaxResources         -- safety cap on total rows pulled
                                              (default 0 = unlimited, ARG's
                                              own 100k cap still applies).

    Asset shape (returned as hashtable):
      AssetId       -- 'az:<lowercased-resource-id>'
      Source        -- 'AzureResource'
      Hint          -- short type-derived label (e.g. 'key-vault', 'storage-
                       account', 'sql-server'); falls back to the last segment
                       of the resource type (e.g. 'recoveryservices/vaults' ->
                       'vaults') for types we haven't named.
      Name          -- resource short name
      NormalizedKey -- lowercased FULL resource id (resource IDs are unique
                       tenant-wide; using just .Name would collide on shared
                       names across subs)
      AZ_Type             -- full lowercased ARM type (microsoft.foo/bars)
      AZ_PropertiesJson   -- raw properties blob as JSON string. Stage Collect
                             projects FROM this using the cached type-profile.
      AZ_Tags             -- raw tags as JSON string
      AZ_Identity         -- identity block as JSON string (managed identity
                             type/principal/clientId)
      AZ_Sku              -- sku block as JSON string
      AZ_Kind             -- kind string (only relevant for some types)
      AZ_RG, AZ_Subscription, AZ_Location -- standard ARM scope fields
      AZ_EnvTag, AZ_OwnerTag -- extracted from tags for fast access (the
                                full tags blob is in AZ_Tags)
#>

# Default exclude list -- types that are pure noise (alert instances,
# scheduled query rules instances, recovery points). Customers can extend
# via $global:SI_AzureExcludeTypes (additive) or override the default list
# entirely by setting their own array.
$script:SI_AzureExcludeTypes_Default = @(
    'microsoft.alertsmanagement/alerts',
    'microsoft.insights/alertinstances',
    'microsoft.insights/scheduledqueryrulesinstances',
    'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems/recoverypoints',
    'microsoft.security/assessments',
    'microsoft.policyinsights/policystates',
    'microsoft.advisor/recommendations'
)

function Get-DiscoveryFromAzureResources {
    [CmdletBinding()]
    param(
        [Parameter()][string[]]$SubscriptionIds = @()    # empty = all visible subs
    )

    # Optional restriction: if customer set
    # $global:SI_AzureResourceTypes, narrow the query to those types.
    # Default (unset): every type the principal can read.
    $allowedTypes = @()
    if ($global:SI_AzureResourceTypes) {
        $allowedTypes = @($global:SI_AzureResourceTypes)
    }

    $excludedTypes = $script:SI_AzureExcludeTypes_Default
    if ($global:SI_AzureExcludeTypes) {
        # Customer's list either replaces (when they want full control) or
        # extends -- we accept either intent by unioning with our default.
        $excludedTypes = ($excludedTypes + @($global:SI_AzureExcludeTypes)) | Select-Object -Unique
    }
    $excludeList = ($excludedTypes | ForEach-Object { "'$_'" }) -join ','

    $maxResources = if ($global:SI_AzureMaxResources -gt 0) { [int]$global:SI_AzureMaxResources } else { 0 }

    # Single ARG query. Project the raw JSON blobs verbatim -- Stage Collect
    # handles per-type property selection via the type-profile cache.
    $whereType = if ($allowedTypes.Count -gt 0) {
        $typeList = ($allowedTypes | ForEach-Object { "'$_'" }) -join ','
        "| where type in~ ($typeList)"
    } else {
        ''
    }

    $kql = @"
Resources
$whereType
| where type !in~ ($excludeList)
| extend
    EnvTag      = tostring(coalesce(tags.Environment, tags.environment, tags.env, '')),
    OwnerTag    = tostring(coalesce(tags.Owner, tags.owner, tags.team, ''))
| project
    ResourceId      = tolower(id),
    Type            = tolower(type),
    Name            = name,
    Location        = location,
    RG              = resourceGroup,
    Subscription    = subscriptionId,
    PropertiesJson  = tostring(properties),
    TagsJson        = tostring(tags),
    IdentityJson    = tostring(identity),
    SkuJson         = tostring(sku),
    Kind            = tostring(coalesce(kind, '')),
    EnvTag, OwnerTag
| order by ResourceId asc
"@

    $rows = New-Object System.Collections.ArrayList
    $skipToken = $null
    $_pageNo = 0
    $_argStart = [datetime]::UtcNow
    Write-SIInfo "   AzureResources: paging Resource Graph (1000 rows/page; this can take 5-30s/page on large estates) ..."
    do {
        $params = @{ Query = $kql; First = 1000 }
        if ($SubscriptionIds.Count -gt 0) { $params['Subscription'] = $SubscriptionIds }
        if ($skipToken)                    { $params['SkipToken']    = $skipToken }
        try {
            $page = Search-AzGraph @params
        } catch {
            Write-Warning ('AzureResources discovery: Search-AzGraph failed -- {0}' -f $_.Exception.Message)
            return @()
        }
        foreach ($r in $page) { [void]$rows.Add($r) }
        $skipToken = $page.SkipToken
        $_pageNo++
        Write-SIInfo ("   AzureResources: page {0} -> {1,5} cumulative rows  ({2:n1}s)" -f $_pageNo, $rows.Count, ([datetime]::UtcNow - $_argStart).TotalSeconds)
        if ($maxResources -gt 0 -and $rows.Count -ge $maxResources) {
            Write-SIInfo ("   -- safety cap {0} reached, stopping pagination (set `$global:SI_AzureMaxResources to raise)" -f $maxResources)
            break
        }
    } while ($skipToken)

    # Type -> short hint mapping. Used for AI-prompt context + grouping.
    # Falls back to the last segment of the type when not in the table
    # (so 'microsoft.recoveryservices/vaults' -> 'vaults' rather than 'unknown').
    $hintByType = @{
        'microsoft.keyvault/vaults'                    = 'key-vault'
        'microsoft.storage/storageaccounts'            = 'storage-account'
        'microsoft.sql/servers'                        = 'sql-server'
        'microsoft.sql/managedinstances'               = 'sql-managed-instance'
        'microsoft.documentdb/databaseaccounts'        = 'cosmos-db'
        'microsoft.dbformysql/flexibleservers'         = 'mysql-flexible'
        'microsoft.dbforpostgresql/flexibleservers'    = 'postgresql-flexible'
        'microsoft.containerservice/managedclusters'   = 'aks-cluster'
        'microsoft.web/sites'                          = 'app-service'
        'microsoft.network/applicationgateways'        = 'application-gateway'
        'microsoft.network/loadbalancers'              = 'load-balancer'
        'microsoft.network/networksecuritygroups'      = 'network-security-group'
        'microsoft.cache/redis'                        = 'redis-cache'
        'microsoft.eventhub/namespaces'                = 'event-hub'
        'microsoft.servicebus/namespaces'              = 'service-bus'
        'microsoft.compute/virtualmachines'            = 'virtual-machine'
        'microsoft.compute/disks'                      = 'disk'
        'microsoft.network/virtualnetworks'            = 'vnet'
        'microsoft.network/publicipaddresses'          = 'public-ip'
        'microsoft.containerregistry/registries'       = 'container-registry'
        'microsoft.machinelearningservices/workspaces' = 'ml-workspace'
    }

    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'AzureResources' -ErrorAction SilentlyContinue
    foreach ($r in $rows) {
        $_i++
        try { Write-SIProgress -Label 'AzureResources' -Index $_i -Total $_total } catch { }
        $hint = if ($hintByType.ContainsKey($r.Type)) {
            $hintByType[$r.Type]
        } elseif ($r.Type -match '/([^/]+)$') {
            $matches[1]
        } else {
            'azure-resource'
        }

        @{
            AssetId             = 'az:' + $r.ResourceId
            Source              = 'AzureResource'
            Hint                = $hint
            Name                = $r.Name
            NormalizedKey       = $r.ResourceId
            AZ_ResourceId       = $r.ResourceId
            AZ_Type             = $r.Type
            AZ_Hint             = $hint
            AZ_Location         = $r.Location
            AZ_RG               = $r.RG
            AZ_Subscription     = $r.Subscription
            AZ_EnvTag           = $r.EnvTag
            AZ_OwnerTag         = $r.OwnerTag
            AZ_Kind             = $r.Kind
            AZ_PropertiesJson   = $r.PropertiesJson
            AZ_TagsJson         = $r.TagsJson
            AZ_IdentityJson     = $r.IdentityJson
            AZ_SkuJson          = $r.SkuJson
        }
    }
}
