#Requires -Version 5.1
<#
    Discovery sidecar for the AZURE engine: pulls relationship edges from
    Microsoft Defender's Exposure Graph (XDR Advanced Hunting tables
    ExposureGraphNodes + ExposureGraphEdges).

    Two outputs (exposed as separate functions, one round-trip each):
      Get-AzureExposureGraphResourceNodes -- enriches resource records with
        EG-side metadata (exposure score, criticality, business application
        name -- whatever Defender already inferred). Joined to discovered
        resources by NodeName == AZ_Name + NodeLabel matching.

      Get-AzureExposureGraphAccessEdges -- 'has access to' / 'has permission'
        edges where SOURCE is an identity (user / SP) and TARGET is an Azure
        resource. Used by Stage Enrich's cross-engine block to derive
        XENG_AccessedByT0/T1 counters.

    Failure modes are non-fatal -- empty maps are returned on Graph error,
    license missing, schema drift. Azure engine still classifies via ARG
    + AI metaprofile alone.

    #1398 THE PART'S NODES AND EDGES ONLY (owner 2026-10-21: "memory issues must not be a problem in any step. env must work
    in millions of assets env"). Both reads took the WHOLE graph in every part: the nodes in one unpaged hunting query (cut at
    Microsoft's 100,000 rows without a word) with each node's raw NodeProperties text, the edges as one list. Now each asks
    only for what the PART's resources look up -- the nodes by the part's resource names (-Names: the key Invoke-Collect joins
    on), the edges by the part's node ids and resource names (-Keys: the keys Invoke-Enrich joins on) -- in key lists sized by
    their text, through the product's hunting request (retried; a cut answer read whole in hash parts), each part of an answer
    taken as it arrives. Kusto projects only the four rawData fields Collect reads (with which of them the node HAS).
    IDENTICAL FOR THE PART: every node / edge that gives a key the part looks up carries that key, so it is in the answer; a
    name two nodes share is counted on the same nodes; a row in two lists' answers is taken once.
#>

# Node labels that identify Azure resources in the EG schema. Customer can
# extend via $global:SI_AzureExposureGraph_ResourceLabels.
$script:SI_AzureEG_ResourceLabels_Default = @(
    'storageaccount',
    'keyvault',
    'sqldatabase',
    'sqlmanagedinstance',
    'cosmosdb',
    'webapp',
    'functionapp',
    'aksdeployment',
    'aksserviceaccount',
    'containerregistry',
    'eventhub',
    'servicebus',
    'redis',
    'azureresource',
    'azureappgateway',
    'azureloadbalancer'
)

# Node labels that identify identities (sources of has-access-to edges).
$script:SI_AzureEG_IdentityLabels_Default = @(
    'user',
    'serviceprincipal',
    'managedidentity',
    'group'
)

# Edge labels meaning "this identity has reach into this resource". XDR
# names these in lowercase with spaces; coerce both sides for matching.
$script:SI_AzureEG_AccessEdgeLabels_Default = @(
    'has access to',
    'can authenticate as',
    'can authenticate to',
    'has permissions to',
    'has role on',
    'has data action on'
)

function Get-SIAzureEgLabelList {
    $labels = if ($global:SI_AzureExposureGraph_ResourceLabels) { @($global:SI_AzureExposureGraph_ResourceLabels) } else { $script:SI_AzureEG_ResourceLabels_Default }
    ($labels | ForEach-Object { "'$_'" }) -join ','
}

function Get-SIAzureEgNodeQuery {
    <# PURE. The Azure resource node table's whole-table query (shared\SI-EgNodeExport.ps1: the fields cast in Kusto). #>
    Get-SIEgExportQuery -Kind 'azure-nodes' -LabelList (Get-SIAzureEgLabelList)
}

function Get-SIAzureEgEdgeQuery {
    <# PURE. The access-edge table's whole-table query: identity -> Azure resource edges of the access labels. #>
    $resourceLabels = if ($global:SI_AzureExposureGraph_ResourceLabels) { @($global:SI_AzureExposureGraph_ResourceLabels) } else { $script:SI_AzureEG_ResourceLabels_Default }
    $identityLabels = if ($global:SI_AzureExposureGraph_IdentityLabels) { @($global:SI_AzureExposureGraph_IdentityLabels) } else { $script:SI_AzureEG_IdentityLabels_Default }
    $edgeLabels     = if ($global:SI_AzureExposureGraph_AccessEdgeLabels) { @($global:SI_AzureExposureGraph_AccessEdgeLabels) } else { $script:SI_AzureEG_AccessEdgeLabels_Default }
    $rList = ($resourceLabels | ForEach-Object { "'$_'" }) -join ','
    $iList = ($identityLabels | ForEach-Object { "'$_'" }) -join ','
    $eList = ($edgeLabels     | ForEach-Object { "'$_'" }) -join ','
    # The live graph labels Azure resources by ARM TYPE ('microsoft.storage/storageaccounts',
    # 'microsoft.keyvault/vaults', ...), not by the short names in the default list -- so this query
    # matched nothing, on every run, and XENG_AccessedBy* stayed empty (measured: hundreds of
    # identity -> storage / key vault 'has permissions to' edges in a tenant that reported 0).
    # Unless the customer has set their own resource labels, any ARM-typed resource is a target;
    # role-assignment nodes are the MECHANISM of access, not a resource, so they are excluded.
    $targetFilter = if ($global:SI_AzureExposureGraph_ResourceLabels) {
        "TargetNodeLabel in~ ($rList)"
    } else {
        "(TargetNodeLabel in~ ($rList) or (TargetNodeLabel startswith 'microsoft.' and TargetNodeLabel !startswith 'microsoft.authorization/'))"
    }
    Get-SIEgExportQuery -Kind 'azure-edges' -EdgeFilter ("| where EdgeLabel in~ ($eList)`n| where SourceNodeLabel in~ ($iList) and $targetFilter")
}

function Get-AzureExposureGraphResourceNodes {
    [CmdletBinding()]
    # -Names: the part's resource short names (Get-SIAzureEgLookupKeys); none = no read. -Ask / -Store / -RunId: test seams.
    param([AllowNull()][AllowEmptyCollection()][string[]]$Names = @(), [scriptblock]$Ask, $Store, [string]$RunId = '')

    # (not $rows: the block runs inside the hunting split, whose -Rows is a number)
    $egAzNodeRows = New-Object System.Collections.Generic.List[object]
    $rd = Read-SIEgRowsForKeys -Kind 'azure-nodes' -Keys @($Names) -Query (Get-SIAzureEgNodeQuery) -Ask $Ask -Store $Store -RunId $RunId -Engine 'azure' -OnRow { param($r) $egAzNodeRows.Add($r) }
    if (-not $rd.Ok) {
        $kind = if ($rd.Defect) { 'the query was refused and must be fixed (running it again gives the same answer)' } else { 'the read failed after it was asked again' }
        Write-Warning ('AzureExposureGraph nodes: query failed -- {0} -- {1}. The Exposure Graph enrichment of this part''s resources is unknown this run (not "none").' -f $kind, $rd.Error)
        return @{}
    }

    # Map keyed by lowercased NodeName for join with AZ_Name (resource short
    # name). #642: a name two nodes share is no key at all -- the first node of a name answered for every same-named
    # resource (one per subscription is common), so they all took its values.
    $nameCount = @{}
    foreach ($r in $egAzNodeRows) { if ($r.NodeName) { $nk = ([string]$r.NodeName).ToLowerInvariant(); $nameCount[$nk] = 1 + [int]$nameCount[$nk] } }
    $byName = @{}
    foreach ($r in $egAzNodeRows) {
        if (-not $r.NodeName) { continue }
        $key = ([string]$r.NodeName).ToLowerInvariant()
        if ([int]$nameCount[$key] -eq 1 -and -not $byName.ContainsKey($key)) {
            $raw = ConvertFrom-SIEgNodeRow -Row $r -Kind 'azure-nodes'
            $byName[$key] = @{
                NodeId     = $r.NodeId
                NodeName   = $r.NodeName
                NodeLabel  = $r.NodeLabel
                # the node's rawData as Collect reads it: only the fields it has; HasRawData = the node has properties at all
                HasRawData = [bool]$raw.HasRawData
                RawData    = $raw.RawData
            }
        }
    }
    return $byName
}

function Get-SIAzureEgAccessEdgeKeys {
    <#
        PURE. #1398 The keys THIS part's Azure records look their access edges up by (Invoke-Enrich): the Exposure Graph node
        id and the resource name from the ARM id, lower case, for every record with an ARM id.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Records = @())
    $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($r in @($Records)) {
        if ($null -eq $r -or $null -eq $r.Metadata -or -not $r.Metadata.AZ_ResourceId) { continue }
        if ($r.Metadata.AZ_NodeId) { [void]$keys.Add(([string]$r.Metadata.AZ_NodeId).ToLowerInvariant()) }
        $nameFromId = (([string]$r.Metadata.AZ_ResourceId).TrimEnd('/') -split '/')[-1]
        if ($nameFromId) { [void]$keys.Add($nameFromId.ToLowerInvariant()) }
    }
    [string[]]@($keys)
}

function Get-AzureExposureGraphAccessEdges {
    [CmdletBinding()]
    # -Keys: the part's target keys (Get-SIAzureEgAccessEdgeKeys -- node ids and resource names); none = no read.
    # -Ask { param($Query) } -> @{ Ok; Rows; Error }: the test seam of one hunting request (default: Graph, retried); -Store / -RunId: the run's export
    param([AllowNull()][AllowEmptyCollection()][string[]]$Keys = @(), [scriptblock]$Ask, $Store, [string]$RunId = '')

    # Map: lowercased TargetNodeName -> ArrayList of @{ SourceName; SourceLabel; EdgeLabel }
    $byTargetName = @{}
    $onEdge = {
        param($r)
        if (-not $r.TargetNodeName -and -not $r.TargetNodeId) { return }
        $edge = @{
            SourceName  = $r.SourceNodeName
            SourceId    = $r.SourceNodeId
            SourceLabel = $r.SourceNodeLabel
            EdgeLabel   = $r.EdgeLabel
        }
        # Indexed by BOTH the node id ("nodeid:<id>", exact) and the name. The enrich stage matches the id
        # first -- a name can repeat across resource groups; an Exposure Graph node id cannot.
        $edgeKeys = @()
        if ($r.TargetNodeId)   { $edgeKeys += ('nodeid:' + ([string]$r.TargetNodeId).ToLowerInvariant()) }
        if ($r.TargetNodeName) { $edgeKeys += ([string]$r.TargetNodeName).ToLowerInvariant() }
        foreach ($key in $edgeKeys) {
            if (-not $byTargetName.ContainsKey($key)) {
                $byTargetName[$key] = New-Object System.Collections.ArrayList
            }
            [void]$byTargetName[$key].Add($edge)
        }
    }

    # the product's hunting request (Invoke-SIHuntingQueryResult): throttled / busy / 5xx / no answer asked again with a
    # growing wait, a cut answer (Microsoft's 100,000 rows) read whole in parts, a refused query (400) not asked again. A read
    # that still fails is said: the access edges are UNKNOWN this run (not "no identity has access").
    $rd = Read-SIEgRowsForKeys -Kind 'azure-edges' -Keys @($Keys) -Query (Get-SIAzureEgEdgeQuery) -Ask $Ask -Store $Store -RunId $RunId -Engine 'azure' -OnRow $onEdge
    if (-not $rd.Ok) {
        $kind = if ($rd.Defect) { 'the query was refused and must be fixed (running it again gives the same answer)' } else { 'the read failed after it was asked again' }
        Write-Warning ('AzureExposureGraph edges: query failed -- {0} -- {1}. Which identities can reach which Azure resources is not known this run (not "none").' -f $kind, $rd.Error)
        return @{}
    }
    return $byTargetName
}

if (-not (Get-Command -Name Read-SIEgRowsForKeys -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/SI-EgNodeExport.ps1') }