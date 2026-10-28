#Requires -Version 5.1
<#
    SI v3 -- FULL ASSET PROPERTIES: resolving a source object to SI's own identity.

    DESIGN: docs/V3-ARCHITECTURE.md 3.6b / 2.4.

    A wide payload with no SI identity on it is unusable -- a payload nobody can attribute to an object is
    a JSON blob nobody can join. So every wide row is resolved through the ANCHOR the source already
    carries. #412: the index is built IN MEMORY from the profile rows the same profiler run just built
    (New-SIAssetPropertiesIdentityIndex over $flat) -- no Log Analytics read and no correlation post-pass;
    readers map SI_AssetId to the CI through the correlation map themselves.

    🪤 TRAP #83, AND IT HAS NOW BITTEN TWICE -- ONCE IN THE CMDB DRIVER. `arg_max` THEN filter is not
    the same query as filter THEN `arg_max`. Both editions write the profile tables; v2.2 emits no
    `SI_` columns, so `summarize max(CollectionTime)` over the raw table frequently picks a v2.2
    snapshot, and every v3 column then reads empty. Measured on the same data: 40 assets vs 238.
    Get-SIAssetPropertiesIdentityKql filters FIRST, and the test asserts the clause order.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

# 🔑 THE VOCABULARY IS SHARED, AND THIS FILE MUST NOT DECLARE A FOURTH COPY OF IT.
# `engine/_shared/SI-AssetIdentity.ps1` exists because three files independently ranked identifiers
# for one question and disagreed -- and worse, the endpoint builder's chain ended in a HOSTNAME, a
# type this codebase classifies as WEAK and forbids joining on. One module's safety rule was bypassed
# by another, silently, with nothing in any output looking wrong.
# 📌 What is shared is the VOCABULARY (which types exist, which are joinable, which spellings are the
# same fact). What is NOT shared is the ORDER -- correlation asks "which id best names this GROUP",
# profiling asks "which id names THIS row". This file asks a third question again: "which id links one
# SOURCE SYSTEM's object to a profile row". So it declares its own MAPPING and borrows the vocabulary,
# which is exactly the split that header prescribes.
. (Join-Path (Split-Path -Parent $PSScriptRoot) '..\_shared\SI-AssetIdentity.ps1')
# The snapshot READER is shared too -- see SI-V3Snapshot.ps1's header. Finding #83 (filter before
# arg_max) had already been re-learned in three separate files; a fourth private copy of that clause
# order is how it gets re-learned a fourth time.
. (Join-Path (Split-Path -Parent $PSScriptRoot) '..\_shared\SI-V3Snapshot.ps1')

# Which anchor links one source system's object to a profile row, and where each side keeps it.
#
# 🔒 EVERY ONE OF THESE IS A JOINABLE (globally unique) IDENTIFIER, and that is now ASSERTED against
# the shared vocabulary rather than believed -- see Test-SIAssetPropertyAnchorVocabulary below. None is
# a hostname, a UPN or a display name. Keying on a weak id FUSES two assets into one object, which is
# strictly worse than failing to resolve: a duplicate is visible and annoying, a fusion silently
# attributes one machine's properties to another and hides the second machine completely.
# 🪤 `IdType` AND `ProfileColumn` ARE TWO DIFFERENT THINGS, AND CONFLATING THEM COST A LIVE RUN.
# `IdType` is the vocabulary name from SI-AssetIdentity (what the guard below validates as joinable).
# `ProfileColumn` is what the column is actually CALLED in that engine's schema. For three of the five
# they happen to be the same string, which is exactly why the first version used one field for both --
# and then identity resolved **0 of 1614 objects** on the first live run, because the identity engine
# names its column `EntraAccountObjectId` while the vocabulary type is `AadObjectId`.
# 📌 That is `EgNodeId`/`ExposureGraphNodeId` again, in a third place: one fact, two spellings. The
# tell was a 100% unresolved rate against a source that plainly had the data.
$script:SIAssetPropertyAnchors = @(
    @{ SourceSystem = 'mde';                    Engine = 'endpoint'; SourceField = 'id';       IdType = 'MdeDeviceId';     ProfileColumn = 'MdeDeviceId' }
    @{ SourceSystem = 'entra-device';           Engine = 'endpoint'; SourceField = 'deviceId'; IdType = 'AadDeviceId';     ProfileColumn = 'AadDeviceId' }
    @{ SourceSystem = 'entra-user';             Engine = 'identity'; SourceField = 'id';       IdType = 'AadObjectId';     ProfileColumn = 'EntraAccountObjectId' }
    @{ SourceSystem = 'entra-serviceprincipal'; Engine = 'identity'; SourceField = 'id';       IdType = 'AadObjectId';     ProfileColumn = 'EntraAccountObjectId' }
    @{ SourceSystem = 'arm';                    Engine = 'azure';    SourceField = 'id';       IdType = 'AzureResourceId'; ProfileColumn = 'AzureResourceId' }
    # #301 -- the metadata additions. Same rule: every anchor is a JOINABLE id (asserted below).
    # A VM extension is a CHILD row: it resolves to its VM through the parent id the split stamps on it
    # (Split-SIAssetPropertiesArmExtensions), never through its own id, which no profile row carries.
    @{ SourceSystem = 'arm-vm-extension';       Engine = 'azure';    SourceField = '_siParentResourceId'; IdType = 'AzureResourceId'; ProfileColumn = 'AzureResourceId' }
    # The AD computer object resolves to the identity engine's machine-account row (OnPremObjectGuid).
    @{ SourceSystem = 'ad-computer';            Engine = 'identity'; SourceField = 'ObjectGUID'; IdType = 'OnPremObjectGuid'; ProfileColumn = 'OnPremObjectGuid' }
    # Exposure Graph nodes resolve on the node id the profilers publish -- in the column ExposureGraphNodeId.
    # 🔴 #412: this said ProfileColumn = 'EgNodeId', a column NO profile schema has (the vocabulary type is EgNodeId, the
    # column is ExposureGraphNodeId -- the EntraAccountObjectId trap below, a third time), so no Exposure Graph node ever
    # resolved. Found when the resolution moved into memory; SIv3-AssetPropertiesProfiler now asserts every ProfileColumn
    # is a real column of the engine's schema.
    @{ SourceSystem = 'exposure-graph';         Engine = 'endpoint'; SourceField = 'NodeId';   IdType = 'EgNodeId';        ProfileColumn = 'ExposureGraphNodeId' }
    # Intune managed devices resolve on the Entra device id, like entra-device.
    @{ SourceSystem = 'intune-device';          Engine = 'endpoint'; SourceField = 'azureADDeviceId'; IdType = 'AadDeviceId'; ProfileColumn = 'AadDeviceId' }
)

function Get-SIAssetPropertyAnchor {
    param([Parameter(Mandatory)][string]$SourceSystem)
    $k = $SourceSystem.Trim().ToLowerInvariant()
    foreach ($a in $script:SIAssetPropertyAnchors) {
        if ($a.SourceSystem -eq $k) { return $a }
    }
    $null
}

function Test-SIAssetPropertyAnchorVocabulary {
    <#
        Every anchor column must be a JOINABLE type in the shared vocabulary.

        🔴 THIS IS A REAL GUARD, NOT A TAUTOLOGY. The precedent is in SI-AssetIdentity.ps1's own
        header: the endpoint builder's identity chain ended in a hostname -- a type the correlation
        engine refuses to join on -- and nothing failed. Adding `Hostname` or `Upn` here would be the
        same mistake in a new file, and it would present as a *better* match rate, because weak ids
        match more often. They match things that are not the same asset.

        Returns the offenders so a test names them rather than reporting a boolean.
    #>
    [CmdletBinding()]
    param()
    # Validates `IdType` -- the VOCABULARY name -- not `ProfileColumn`, which is a per-engine schema
    # name that the vocabulary has no opinion about (`EntraAccountObjectId` is the identity engine's
    # spelling of the type `AadObjectId`).
    $bad = New-Object System.Collections.ArrayList
    foreach ($a in $script:SIAssetPropertyAnchors) {
        $canon = Get-SICanonicalIdType -Type ([string]$a.IdType)
        if (-not (Test-SIIdTypeJoinable -Type $canon)) {
            [void]$bad.Add([pscustomobject]@{ SourceSystem = $a.SourceSystem; IdType = $a.IdType; ProfileColumn = $a.ProfileColumn })
        }
    }
    @($bad.ToArray())
}

function Get-SIAssetPropertiesIdentityKql {
    <#
        The identity index for one engine: SI_AssetId, SI_AssetName and the anchor columns of the
        CURRENT v3 snapshot.

        🔴 THE `where` COMES BEFORE THE `summarize`. See trap #83 at the top of this file. The v3 test
        is `isnotempty(SI_AssetId)` because that column is the thing v2.2 does not emit -- a
        SolutionVersion filter would be more direct but the four PROFILE tables carry no version stamp
        (V3-6), so it is not available here.

        column_ifexists on every anchor: the four schemas do NOT carry the same identifier columns
        (identity has no AzureResourceId), and a plain project against a missing column fails the whole
        query rather than degrading to "this engine does not know that id".
    #>
    param(
        [Parameter(Mandatory)][string]$TableName,
        [int]$RowLimit = 0
    )

    # 🔑 THE CLAUSE ORDER IS NOT THIS FILE'S TO DECIDE. Get-SIV3SnapshotKql owns it, because it is the
    # same fact for every engine and it has been re-learned three times already (#83). What IS this
    # file's business is WHICH columns to ask for -- the anchors -- and that is what it passes.
    $anchors = @($script:SIAssetPropertyAnchors | ForEach-Object { $_.ProfileColumn } | Sort-Object -Unique)
    Get-SIV3SnapshotKql -TableName $TableName -Column $anchors -RowLimit $RowLimit -LowerCaseColumns
}

function Get-SIAssetPropertiesCorrelationKql {
    <#
        SI_CorrelationId per SI_AssetId, from the correlation map -- AND `SI_IdSource` with it.

        📌 This join is the reason V3-HANDOFF #89 exists: SI_CorrelationId is on NO profile table -- it
        lives only in SI_ObjectMap_CL, keyed on SI_AssetId. A connector that expects to find it on the
        row skips 100% of assets while reporting a clean run (measured: 144 of 144 Skipped). Doing the
        join HERE means the wide payload carries the correlation id, so the CMDB connector reads one
        table instead of performing the join it currently does not perform at all.

        🔴 `SI_IdSource` IS NOT OPTIONAL AND IT IS THE COLUMN THIS JOIN ORIGINALLY DROPPED.
        The correlation engine already publishes, per row, whether the id is `ledger` (minted once and
        stored -- durable for the life of the asset) or `derived-provisional` (today's seed, which MOVES
        when a group member joins or leaves: measured `...:aaa` -> `...:000`). `SI-ObjectLedgerStore.ps1`
        states the consequence outright -- *"a connector is already forbidden from creating CIs from
        those"* -- and that rule lived only in prose until this column was carried through.
        🔑 The distinction is not cosmetic: **enriching a matched CI with a provisional id is harmless
        (it is an update to a CI that already exists), CREATING one from it is not.** An id that can
        change produces a second CI on the next run, and a duplicate CI is effectively permanent once
        incidents and changes point at it.

        `take_any` is safe for both columns because the map emits one row per
        (correlation id, member, identifier type) -- every row for a given SI_AssetId carries the SAME
        correlation id and the SAME id source. Taking them together in one `summarize` keeps that true;
        taking them in two would allow a value pair that never co-occurred on any row.
    #>
    param([int]$RowLimit = 0)
    # Delegated to the shared reader. `SI_IdSource` and the single-`summarize` pairing are the same
    # fact for every consumer of the map -- the CMDB connector needs them for exactly the same reason
    # this add-on does -- so they are not this add-on's private opinion to hold.
    Get-SIV3ObjectMapKql -RowLimit $RowLimit
}

function New-SIAssetPropertiesIdentityIndex {
    <#
        Build the anchor -> identity lookup from the profile rows.

        Returns a hashtable keyed `<anchorColumn>|<lowercased value>`, so one index serves every
        source system and a value that happens to appear in two different anchor columns cannot
        cross-match.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ProfileRows,
        # Keyed on SI_AssetId. Each value may be a plain correlation-id string (the older shape) or an
        # object carrying SI_CorrelationId + SI_IdSource. Both are accepted so a caller that has not
        # been updated degrades to "unknown id source", which the create gate treats as NOT durable --
        # the safe direction.
        [Parameter()][hashtable]$CorrelationByAssetId = @{}
    )

    $index = @{}
    $anchors = @($script:SIAssetPropertyAnchors | ForEach-Object { $_.ProfileColumn } | Sort-Object -Unique)

    foreach ($r in @($ProfileRows)) {
        if ($null -eq $r) { continue }
        $assetId = [string]$r.SI_AssetId
        if ([string]::IsNullOrWhiteSpace($assetId)) { continue }
        $corr = ''
        $idSrc = ''
        if ($CorrelationByAssetId.ContainsKey($assetId)) {
            $v = $CorrelationByAssetId[$assetId]
            if ($v -is [string]) {
                $corr = [string]$v
            } elseif ($null -ne $v) {
                $corr  = [string](Get-SIRowValue -Row $v -Name 'SI_CorrelationId')
                $idSrc = [string](Get-SIRowValue -Row $v -Name 'SI_IdSource')
            }
        }

        $identity = [pscustomobject]@{
            SI_AssetId       = $assetId
            SI_AssetName     = [string]$r.SI_AssetName
            SI_CorrelationId = $corr
            # 🔴 CARRIED, NOT DERIVED. `ledger` = minted once and stored, durable for the life of the
            # asset. `derived-provisional` = today's seed, which moves when group membership changes.
            # Empty = the map did not say, which the create gate must treat as provisional.
            SI_IdSource      = $idSrc
        }

        foreach ($col in $anchors) {
            if (-not $r.PSObject.Properties[$col]) { continue }
            $v = [string]$r.$col
            if ([string]::IsNullOrWhiteSpace($v)) { continue }
            $key = ('{0}|{1}' -f $col, $v.Trim().ToLowerInvariant())
            # 🔴 FIRST WRITER WINS, AND A COLLISION IS NOT OVERWRITTEN. Two profile rows carrying the
            # same strong anchor is a correlation defect, not a fact about the world; silently letting
            # the last one win would attribute the payload to whichever row the query happened to
            # return second -- non-deterministic, and invisible.
            if (-not $index.ContainsKey($key)) { $index[$key] = $identity }
        }
    }
    $index
}

function Resolve-SIAssetPropertyIdentity {
    <#
        Look one source object up in the index. Returns $null when it does not resolve -- and the
        caller must COUNT those rather than drop them quietly. An unresolved rate that climbs is how a
        renamed anchor field announces itself, and it is the only announcement there will be.
    #>
    param(
        [Parameter(Mandatory)][string]$SourceSystem,
        [Parameter(Mandatory)][AllowNull()]$SourceObject,
        [Parameter(Mandatory)][hashtable]$Index
    )
    if ($null -eq $SourceObject) { return $null }
    $anchor = Get-SIAssetPropertyAnchor -SourceSystem $SourceSystem
    if (-not $anchor) { return $null }
    if (-not $SourceObject.PSObject.Properties[$anchor.SourceField]) { return $null }
    $v = [string]$SourceObject.($anchor.SourceField)
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    $key = ('{0}|{1}' -f $anchor.ProfileColumn, $v.Trim().ToLowerInvariant())
    if ($Index.ContainsKey($key)) { return $Index[$key] }
    $null
}

# ---------------------------------------------------------------------------------------------------
# Workspace ARM id -> the customer (workspace) GUID the query API wants.
#
# 🔒 Deliberately NOT dot-sourced from asset-correlation or risk-analysis. Those files sit on paths
# that ship to ~30 customers, and an OPTIONAL add-on must not be able to break them by loading. A
# distinct function name also means all three can coexist in one process without shadowing -- one
# fact, two spellings is a trap in code as much as in data.
# ---------------------------------------------------------------------------------------------------
$script:_SIApWsCache = @{}

function Resolve-SIAssetPropertiesWorkspaceId {
    param([string]$WorkspaceResourceId = [string]$global:SI_WorkspaceResourceId)

    if ($script:_SIApWsCache.ContainsKey($WorkspaceResourceId)) { return $script:_SIApWsCache[$WorkspaceResourceId] }

    if ($WorkspaceResourceId -notmatch '/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/[Mm]icrosoft\.[Oo]perational[Ii]nsights/workspaces/([^/]+)') {
        throw "asset-properties: invalid WorkspaceResourceId -- $WorkspaceResourceId"
    }
    $subId = $matches[1]; $rgName = $matches[2]; $wsName = $matches[3]

    # Restore the caller's subscription afterwards. Az context on this machine is shared state and
    # another stage may depend on it -- leaving it moved is how a later engine deploys to the wrong
    # subscription, which has already happened here in four tools at once.
    $curSubId = $null
    try { $curSubId = (Get-SIAzContext).Subscription.Id } catch { }
    if ($curSubId -and $curSubId -ne $subId) { $null = Set-SIAzContext -Subscription $subId -ErrorAction Stop }
    try {
        $ws = Get-SIAzOperationalInsightsWorkspace -ResourceGroupName $rgName -Name $wsName -ErrorAction Stop
        $custId = $ws.CustomerId.Guid
    } finally {
        if ($curSubId -and $curSubId -ne $subId) {
            try { $null = Set-SIAzContext -Subscription $curSubId -ErrorAction SilentlyContinue } catch { }
        }
    }

    $script:_SIApWsCache[$WorkspaceResourceId] = $custId
    $custId
}
