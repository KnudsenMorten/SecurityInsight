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

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }
# #412 one pull per source -- see shared\SI-FullAssetProperties.ps1. Nothing changes at the security level.
if (-not (Get-Command -Name Add-SIFullSourceObject -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/SI-FullAssetProperties.ps1') }

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
        [Parameter()][string[]]$SubscriptionIds = @(),    # empty = all visible subs
        # #475: only the number of resources this source would return (the same filters), or $null when it cannot be read
        [switch]$CountOnly
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

    if ($CountOnly) {
        try {
            $cp = @{ Query = ("Resources {0} | where type !in~ ({1}) | count" -f $whereType, $excludeList); First = 1 }
            if ($SubscriptionIds.Count -gt 0) { $cp['Subscription'] = $SubscriptionIds }
            $cpage = Search-SIAzGraph @cp -ErrorAction Stop
            # the page is one object holding its rows (as the paging loop reads it): the first row is the count
            $n = 0L
            foreach ($row in $cpage) { if ([long]::TryParse([string]$row.Count, [ref]$n)) { return $n }; break }
        } catch { }
        return $null
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
    # #412 full asset metadata: the SAME query, also projecting the rest of the ARM envelope (managedBy, plan, zones, ...)
    # so each resource is kept whole from this one pull. The columns above, and so the record below, are unchanged.
    if (Test-SIFullAssetPropertiesOn) { $kql = Get-SIFullArgKql -SecurityKql $kql }

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

    # The asset of ONE Resource Graph row -- shared by the whole-set loop below and the streaming pages (#475).
    $buildRes = {
        param($r)
        # every level: the record capture needs each resource (the full metadata keeps it only at the full level)
        if ($true) { Add-SIFullSourceObject -SourceSystem 'arm' -Object (ConvertTo-SIFullArmObject -Row $r) -AnchorColumn 'AzureResourceId' -AnchorValue ([string]$r.ResourceId) }
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

    $stream = $global:SI_DiscoverStream
    $streamTaken = 0
    $rows = New-Object System.Collections.ArrayList
    $skipToken = $null
    $_pageNo = 0
    $_argStart = [datetime]::UtcNow
    Write-SIInfo "   AzureResources: paging Resource Graph (1000 rows/page; this can take 5-30s/page on large estates) ..."
    . (Join-Path $PSScriptRoot 'Invoke-SIArgPaged.ps1')   # Test-SIArgTransientError
    do {
        $params = @{ Query = $kql; First = 1000 }
        if ($SubscriptionIds.Count -gt 0) { $params['Subscription'] = $SubscriptionIds }
        if ($skipToken)                    { $params['SkipToken']    = $skipToken }
        # A throttle is RETRIED, and a page that still fails no longer throws away the pages already
        # collected (#125). This used to `return @()` on ANY page failure -- a throttle on page 9 made
        # the whole Azure estate look empty. Same contract as Invoke-SIPagedRest: keep what we have,
        # say loudly that it is partial.
        $page = $null; $attempt = 0; $pageErr = $null
        while ($true) {
            $attempt++
            try { $page = Search-SIAzGraph @params -ErrorAction Stop; break }
            catch {
                $pageErr = [string]$_.Exception.Message
                if (-not (Test-SIArgTransientError -Message $pageErr) -or $attempt -ge 4) { $page = $null; break }
                $delay = [int](5 * [Math]::Pow(3, $attempt - 1))   # 5, 15, 45s
                Write-SIInfo ("   AzureResources: Resource Graph throttled/transient on page {0} -- retry {1}/4 in {2}s" -f ($_pageNo + 1), $attempt, $delay)
                Start-Sleep -Seconds $delay
            }
        }
        if ($null -eq $page -and $pageErr) {
            Write-Warning ('AzureResources discovery: INCOMPLETE -- page {0} failed after {1} attempt(s); keeping the {2} resource(s) already collected. Resources missing from this run are UNKNOWN, not removed. {3}' -f ($_pageNo + 1), $attempt, $rows.Count, $pageErr)
            break
        }
        if ($stream) {
            # #475 STREAMING: the page becomes assets and goes straight into the parts -- the estate is never all held
            $batch = New-Object System.Collections.Generic.List[object]
            foreach ($r in $page) { $batch.Add((& $buildRes $r)) }
            $null = Add-SIDiscoverStreamAssets -Stream $stream -Assets $batch.ToArray()
            $streamTaken += $batch.Count
        } else { foreach ($r in $page) { [void]$rows.Add($r) } }
        $skipToken = $page.SkipToken
        $_pageNo++
        Write-SIInfo ("   AzureResources: page {0} -> {1,5} cumulative rows  ({2:n1}s)" -f $_pageNo, ($rows.Count + $streamTaken), ([datetime]::UtcNow - $_argStart).TotalSeconds)
        if ($maxResources -gt 0 -and ($rows.Count + $streamTaken) -ge $maxResources) {
            Write-SIInfo ("   -- safety cap {0} reached, stopping pagination (set `$global:SI_AzureMaxResources to raise)" -f $maxResources)
            break
        }
    } while ($skipToken)
    Set-SIFullSourcePull -SourceSystem 'arm' -Complete (-not ($null -eq $page -and $pageErr)) -ErrorText ([string]$pageErr)

    # THE RECORDS FIRST. Everything below (the management groups, the subscription names, backup, access, policy, changes,
    # updates, the Defender plan) is ADDED TO the Azure records this run captured -- so every resource must be a record
    # before those reads run. A streamed run captures them page by page above; a run that holds the rows builds them here.
    # They were built after the reads, which then found no record to add to: only the resources another source had already
    # named (a virtual machine, a network, a SQL server ...) carried their subscription name, and none its backup or access.
    $built = New-Object System.Collections.Generic.List[object]
    if (-not $stream) {
        $_total = $rows.Count; $_i = 0
        Reset-SIProgress -Label 'AzureResources' -ErrorAction SilentlyContinue
        foreach ($r in $rows) {
            $_i++
            try { Write-SIProgress -Label 'AzureResources' -Index $_i -Total $_total } catch { }
            $built.Add((& $buildRes $r))
        }
    }

    # #527 (7): Defender for Cloud's internet-exposure assessments -> provider 'mdc' records (si_internet_exposed); never fails the run
    if (-not (Get-Command -Name Invoke-SIMdcExposureCapture -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIMdcExposure.ps1') }
    try { $mdcN = Invoke-SIMdcExposureCapture -SubscriptionIds $SubscriptionIds; if ($mdcN -gt 0) { Write-SIInfo ("   Defender for Cloud: {0} internet-exposed resource(s)" -f $mdcN) } } catch { Write-Warning ('Defender for Cloud exposure: ' + $_.Exception.Message) }
    # DEFENDER FOR CLOUD RECORD CAPTURE, summarised per resource (Get-SIMdcAssessmentSummary.ps1): how many assessments are
    # unhealthy and per severity, the top ones with id + name, oldest / newest dates -- ONE Resource Graph query, never a
    # record per assessment; the findings themselves keep arriving through Risk Analysis. Never fails the run.
    if (-not (Get-Command -Name Invoke-SIMdcAssessmentSummaryCapture -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIMdcAssessmentSummary.ps1') }
    try { $mdcSumN = Invoke-SIMdcAssessmentSummaryCapture -SubscriptionIds $SubscriptionIds; if ($mdcSumN -gt 0) { Write-SIInfo ("   Defender for Cloud: assessment summary of {0} resource(s)" -f $mdcSumN) } } catch { Write-Warning ('Defender for Cloud assessment summary: ' + $_.Exception.Message) }
    # #500 the AWS / GCP resources Defender for Cloud's multicloud connectors report -> cloud_resource records (no connector: the source is not present)
    if (-not (Get-Command -Name Invoke-SIMulticloudCapture -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIMulticloudResources.ps1') }
    try { $mc = Invoke-SIMulticloudCapture -SubscriptionIds $SubscriptionIds; Write-SIInfo ('   ' + $mc.Text) } catch { Write-Warning ('Other clouds (AWS / GCP): ' + $_.Exception.Message) }
    # the management-group chain of every subscription -> each Azure record's 'mg' part (derived.managementGroupPath); never fails the run
    if (-not (Get-Command -Name Invoke-SIManagementGroupCapture -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIDerivedSources.ps1') }
    try { $null = Invoke-SIManagementGroupCapture -SubscriptionIds $SubscriptionIds } catch { Write-Warning ('Management groups: ' + $_.Exception.Message) }
    # what Azure knows about each resource beyond its own properties -> parts on its record: backup, who has privileged access
    # at the resource / resource group, policy non-compliance, the last change, pending updates, the Defender plan, and what
    # a public IP address is attached to (each summarised in its query; read only; never fails the run)
    if (-not (Get-Command -Name Invoke-SIAzureContextCapture -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIAzureContext.ps1') }
    try { $null = Invoke-SIAzureContextCapture -SubscriptionIds $SubscriptionIds -Log { param($l, $m) if ($l -eq 'WARN') { Write-Warning $m } else { Write-SIInfo ('   ' + $m) } } } catch { Write-Warning ('Azure context: ' + $_.Exception.Message) }

    if ($stream) {
        if ($global:SI_DiscoverStreamCounts) { $global:SI_DiscoverStreamCounts['AzureResources'] = $streamTaken }
        Write-SIInfo ("   AzureResources: {0} resource(s) streamed into {1} part(s), page by page" -f $streamTaken, $stream.Parts)
        return
    }


    # the assets, built above -- handed on one by one, as before
    foreach ($a in $built) { $a }
}
