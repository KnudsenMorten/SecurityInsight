#Requires -Version 5.1
<#
    Identity-side Exposure Graph enrichment connector.

    Pulls EG nodes labeled 'user', 'serviceprincipal', 'group',
    'managedidentity'. Returns a name+id-keyed map ready for join with
    EntraUsers / EntraServicePrincipals discovered from Graph (master).

    Master vs enrichment contract:
      Entra is the SOURCE OF TRUTH for identity existence + canonical
      attributes (UPN, displayName, accountEnabled, etc.). EG is OPTIONAL
      enrichment: when present, contributes high-signal fields like
      hasAdLeakedCredentials, hasLeakedCredentials, isActive, identityType,
      adSid. When absent (new identity Entra knows about but EG hasn't seen
      yet), the asset still flows through with Entra fields populated and
      EG fields null -- no exception, no block.

    Enrichment fields we extract (from NodeProperties.rawData):
      ENTRA_HasAdLeakedCredentials   (high-criticality signal)
      ENTRA_HasLeakedCredentials     (high-criticality signal)
      ENTRA_IsActive                 (active in last 30d)
      ENTRA_IdentityType             (User|ServiceAccount|Computer)
      ENTRA_AccountDomain            (on-prem AD domain when synced)
      ENTRA_PrimaryProvider          (ActiveDirectory|AzureAD)
      ENTRA_AdSid                    (on-prem AD SID when synced)
      ENTRA_DistinguishedName        (on-prem AD DN)
      ENTRA_HasServicePrincipalName  (SPN-bearing user/computer account)
      EG_NodeId                      (for cross-engine joins)

    #1398 THE PART'S NODES ONLY, FROM ONE READ PER RUN (owner 2026-10-21: "memory issues must not be a problem in any step.
    env must work in millions of assets env"). Every identity part read the WHOLE node table -- one unpaged hunting query
    (silently cut at Microsoft's 100,000 rows), each node's raw NodeProperties text kept beside its parsed object and 4 index
    keys -- and every part of a run did it again. Now (shared\SI-EgNodeExport.ps1):
      * the node table is read ONCE per run, streamed (a cut answer read whole in hash parts -- no silent cut): by the
        producer into the run's export in a run collected in parts, by this function itself in a run in one process;
      * Kusto projects only the rawData fields read here, CAST (tobool / tostring) -- with which of them the node HAS (a
        field that is there with no value is still "there": [bool] of it is $false, as before); never the raw text
        (EG_NodePropertiesRaw was read by nothing and is gone);
      * the part keeps only the nodes its identities can match (-Keys: their object ids, UPNs and names -- the keys
        Find-SIIdentityEgHit tries).
    IDENTICAL MAP FOR THE PART: every node that gives a key the part looks up has that key, so it is kept; a name two nodes
    share is counted on the same nodes as before (all nodes of a looked-up name are kept). A read that fails: the
    enrichment is unknown this run (said), never a part map.
#>

$script:SIIdentityEgLabels = "'user','serviceprincipal','managedidentity','group'"

function Get-SIIdentityEgQuery {
    <# PURE. The identity node table's whole-table query (shared\SI-EgNodeExport.ps1: the fields cast in Kusto). #>
    Get-SIEgExportQuery -Kind 'identity-nodes' -LabelList $script:SIIdentityEgLabels
}
function Get-DiscoveryFromIdentityExposureGraph {
    [CmdletBinding()]
    param(
        [switch]$AllowEmptyOnStub,
        # the keys the part's identities are looked up by (Get-SIIdentityEgLookupKeys, Invoke-Collect.ps1); none = no read
        [AllowNull()][AllowEmptyCollection()][string[]]$Keys = @(),
        # test seams: one hunting request { param($Query) } -> @{ Ok; Rows; Error } (default: Graph, retried); the run's export
        [scriptblock]$Ask, $Store, [string]$RunId = ''
    )

    if ($AllowEmptyOnStub) {
        Write-Warning 'IdentityExposureGraph stubbed off via -AllowEmptyOnStub. Returning empty map.'
        return @{}
    }
    # the part's nodes (Read-SIEgRowsForKeys: the run's export, or the one streamed read of Defender), each converted
    # (not $rows: the block runs inside the hunting split, whose -Rows is a number)
    $egNodeRows = New-Object System.Collections.Generic.List[object]
    $rd = Read-SIEgRowsForKeys -Kind 'identity-nodes' -Keys @($Keys) -Query (Get-SIIdentityEgQuery) -Ask $Ask -Store $Store -RunId $RunId -Engine 'identity' -OnRow { param($r) $egNodeRows.Add($r) }
    if (-not $rd.Ok) {
        $kind = if ($rd.Defect) { 'the query was refused and must be fixed (running it again gives the same answer)' } else { 'the read failed after it was asked again' }
        Write-Warning ('IdentityExposureGraph: the Exposure Graph identity nodes could not be read -- {0} -- {1}. The Exposure Graph enrichment of this part''s identities is unknown this run (not "none").' -f $kind, $rd.Error)
        return @{}
    }
    # Build a multi-keyed map so the join in Stage Collect can hit by
    # any of: lowercased UPN, lowercased displayName, EG NodeId.
    # Entra-master record carries UPN + displayName + objectId; the EG
    # NodeName usually matches displayName (best-effort match).
    $byKey = @{}
    # #642 A NAME TWO NODES SHARE IS NO KEY. Several service principals can share one display name (e.g. one Defender service
    # principal per subscription); the first node of the name answered for all of them, and its node id fused them into one
    # asset. A name is kept only when exactly one node has it (and a name hit never gives an identifier -- Invoke-Collect).
    $nameCount = @{}
    foreach ($r in $egNodeRows) { if ($r.NodeName) { $nk = ([string]$r.NodeName).ToLowerInvariant(); $nameCount[$nk] = 1 + [int]$nameCount[$nk] } }
    foreach ($r in $egNodeRows) {
        $rawData = (ConvertFrom-SIEgNodeRow -Row $r -Kind 'identity-nodes').RawData

        $enrichment = @{
            ENTRA_HasAdLeakedCredentials  = if ($rawData -and $rawData.PSObject.Properties['hasAdLeakedCredentials']) { [bool]$rawData.hasAdLeakedCredentials } else { $null }
            ENTRA_HasLeakedCredentials    = if ($rawData -and $rawData.PSObject.Properties['hasLeakedCredentials'])   { [bool]$rawData.hasLeakedCredentials }   else { $null }
            ENTRA_IsActive                = if ($rawData -and $rawData.PSObject.Properties['isActive'])                { [bool]$rawData.isActive }                else { $null }
            ENTRA_IdentityType            = if ($rawData -and $rawData.PSObject.Properties['identityType'])            { [string]$rawData.identityType }          else { $null }
            ENTRA_AccountDomain           = if ($rawData -and $rawData.PSObject.Properties['accountDomain'])           { [string]$rawData.accountDomain }         else { $null }
            ENTRA_PrimaryProvider         = if ($rawData -and $rawData.PSObject.Properties['primaryProvider'])         { [string]$rawData.primaryProvider }       else { $null }
            ENTRA_AdSid                   = if ($rawData -and $rawData.PSObject.Properties['adSid'])                   { [string]$rawData.adSid }                 else { $null }
            ENTRA_DistinguishedName       = if ($rawData -and $rawData.PSObject.Properties['distinguishedName'])       { [string]$rawData.distinguishedName }     else { $null }
            ENTRA_HasServicePrincipalName = if ($rawData -and $rawData.PSObject.Properties['hasServicePrincipalName']) { [bool]$rawData.hasServicePrincipalName } else { $null }
            EG_NodeId                     = $r.NodeId
            EG_NodeLabel                  = $r.NodeLabel
            # Audit-gap-fill: MS-computed risk + identity-context signals
            EG_MsCriticalityLevel         = if ($rawData -and $rawData.PSObject.Properties['criticalityLevel'])      { [string]$rawData.criticalityLevel }      else { $null }
            EG_IsCompromisedRecently      = if ($rawData -and $rawData.PSObject.Properties['isCompromisedRecently']) { [bool]$rawData.isCompromisedRecently }   else { $null }
            EG_IsExternalUser             = if ($rawData -and $rawData.PSObject.Properties['externalUser'])          { [bool]$rawData.externalUser }            else { $null }
            EG_OnPremSyncEnabled          = if ($rawData -and $rawData.PSObject.Properties['onPremSyncEnabled'])     { [bool]$rawData.onPremSyncEnabled }       else { $null }
            EG_IsMfaCapable               = if ($rawData -and $rawData.PSObject.Properties['isMfaCapable'])          { [bool]$rawData.isMfaCapable }            else { $null }
            EG_IsMfaRegistered            = if ($rawData -and $rawData.PSObject.Properties['isMfaRegistered'])       { [bool]$rawData.isMfaRegistered }         else { $null }
            EG_AccountObjectId            = if ($rawData -and $rawData.PSObject.Properties['accountObjectId'])       { [string]$rawData.accountObjectId }       else { $null }
        }

        if ($r.NodeName) {
            $key = ([string]$r.NodeName).ToLowerInvariant()
            if ([int]$nameCount[$key] -eq 1 -and -not $byKey.ContainsKey($key)) { $byKey[$key] = $enrichment }
        }
        if ($r.NodeId) {
            $byKey[[string]$r.NodeId] = $enrichment
        }
        # Also key by AccountUpn/AccountObjectId when available in the rawData
        if ($rawData -and $rawData.PSObject.Properties['accountObjectId'] -and $rawData.accountObjectId) {
            $byKey[([string]$rawData.accountObjectId).ToLowerInvariant()] = $enrichment
        }
        if ($rawData -and $rawData.PSObject.Properties['accountUpn'] -and $rawData.accountUpn) {
            $byKey[([string]$rawData.accountUpn).ToLowerInvariant()] = $enrichment
        }
    }
    return $byKey
}

if (-not (Get-Command -Name Read-SIEgRowsForKeys -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/SI-EgNodeExport.ps1') }
