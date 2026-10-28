#Requires -Version 5.1
<#
    SI v3 -- THE ASSET IDENTITY VOCABULARY. One list, one home, both layers.

    🔒 THE TWO FIELDS ARE `SI_AssetName` AND `SI_AssetId`. There is no third, and nothing here mints a
    new column name (operator, 2026-08-28: "we have the 2 names today"). This file holds the SHARED
    RULES those two fields are built from, so profiling and correlation stop answering the same
    question differently.

    🔴 WHY IT EXISTS -- three files independently ranked identifiers for one question and disagreed:
      correlation  SISeedPriority        MdeDeviceId is FIFTH   (EG node id first)
      profiling    Build-EndpointProfileRow  MdeDeviceId is FIRST
      discovery    $sourcePriority       MDEDevice is THIRD
    And worse than the disagreement: the endpoint builder's chain ends in a HOSTNAME, a type this very
    codebase classifies as WEAK and forbids joining on. So the profiler used as its asset id precisely
    the value the correlation engine says is too weak to key on -- one module's safety rule bypassed by
    another, silently, with nothing in any output looking wrong.

    🔑 THE SPLIT THAT SETTLES IT (operator, 2026-08-28: "correlation is to merge all records into one,
    where the profiling is about building the raw data"):
      * PROFILING builds raw rows. It can guarantee the two fields are POPULATED.
      * The POST-PASS holds the whole snapshot. Only it can guarantee they are UNIQUE.
    Profiling is SHARDED (`Invoke-Discover.ps1` -- hash mod ShardCount), so a row builder sees ONE SLICE
    and cannot know whether a value collides with a row it will never see. Uniqueness is therefore not
    a property a per-row builder is able to assert; population is. Asserting it there would be a test
    that passes because it cannot see the counter-example.

    🔑 WHAT IS SHARED AND WHAT DELIBERATELY IS NOT. The VOCABULARY is shared -- which types exist,
    which are strong enough to identify an asset, and which spellings are the same fact. The ORDER is
    not, and that is not an oversight:
      * correlation asks "which id best names this GROUP" -> prefers the exposure-graph node id,
        because it is cross-engine BY CONSTRUCTION.
      * profiling asks "which id names THIS row from THIS engine" -> prefers the engine's own native
        key, because EG is 77.5% on endpoint and is the source that vanishes on a timeout.
    Forcing one order would put EG first on endpoint rows and make them LESS stable. Same mechanism,
    two questions, two declared orders -- both drawn from the single vocabulary below, with a test
    pinning that neither order contains a weak type.

    NO Set-StrictMode HERE, deliberately -- it leaks into the caller's scope (measured 2026-08-12), and
    both Invoke-RiskAnalysis.ps1 and Invoke-SICorrelation.ps1 open with Set-StrictMode -Off on purpose.
    A library must not change the strictness of whoever loads it.
#>

# ---------------------------------------------------------------------------------------------------
# JOINABLE -- globally unique. A shared value genuinely means "the same object", so these may key an
# asset and may join. Kept in the order correlation declared them; ORDER HERE CARRIES NO MEANING --
# priority is declared by each layer, see the header.
#
# 🔑 THE WORD IS "JOINABLE", NOT "STRONG". This codebase already had the vocabulary
# (SIJoinableIdTypes / Test-SIIdTypeJoinable, in SI-CorrelationCore.ps1 since Phase 3); the first
# draft of this file invented "strong" alongside it, which is one fact with two spellings -- the exact
# defect the alias table below exists to prevent. The established name wins.
# ---------------------------------------------------------------------------------------------------
$script:SIJoinableIdTypes = @(
    'AadDeviceId'               # modern device anchor
    'MdeDeviceId'
    'EgNodeId'; 'ExposureGraphNodeId'
    'AzureResourceId'
    'AadObjectId'               # identity anchor
    'ActiveDirectoryObjectGuid' # hybrid identity / AD tie
    'SecurityIdentifier'
    'OnPremObjectGuid'
    'AzureVmId'
)

# ---------------------------------------------------------------------------------------------------
# WEAK -- NOT unique. Two machines share a hostname; two users share a display name; an IP is
# reassigned weekly. Evidence for a human, never a decision.
#
# 🔴 THE FAILURE IS ASYMMETRIC AND THE WEAK SIDE IS THE WORSE ONE. Keying on a non-unique value FUSES
# two different assets into one. A duplicate is visible and annoying; a fused object silently
# attributes one machine's vulnerabilities to another and hides the second machine completely -- and
# nothing in the output looks wrong. `AssetName` is on this list for exactly that reason, and it is
# why a report must never group by name alone (measured: Endpoint_ConflictingTierTags_Summary merged
# two DISTINCT machines sharing a hostname into one row).
# ---------------------------------------------------------------------------------------------------
$script:SIWeakIdTypes = @('Hostname', 'Upn', 'Mail', 'IpAddress', 'DisplayName', 'AssetName')

# ---------------------------------------------------------------------------------------------------
# 🔴 ONE FACT MUST NOT HAVE TWO SPELLINGS. The exposure-graph node id is `EgNodeId` inside EntityIds
# and `ExposureGraphNodeId` as a flat column. Keying on the raw name therefore failed to link an
# endpoint row to its azure row through the very identifier that exists to link them -- caught by a
# transitive test, not by reading the code. Canonicalise BEFORE keying; add every new alias HERE.
# ---------------------------------------------------------------------------------------------------
$script:SIIdTypeAliases = @{
    'egnodeid'            = 'ExposureGraphNodeId'
    'exposuregraphnodeid' = 'ExposureGraphNodeId'
}

function Get-SIJoinableIdTypes { @($script:SIJoinableIdTypes) }
function Get-SIWeakIdTypes     { @($script:SIWeakIdTypes) }

# ---------------------------------------------------------------------------------------------------
# PRIMITIVES. They live HERE, with the vocabulary, because the identity resolvers below depend on them.
# They were briefly declared in SI-AssetNameUniqueness.ps1 instead, which pointed the dependency the
# wrong way -- and it PARSED CLEANLY and failed only on execution. A parse check cannot prove code runs.
# ---------------------------------------------------------------------------------------------------

# 🪤 STRIP TO ALPHANUMERICS **BEFORE** TRUNCATING. Ids here include ARM paths and IP addresses; taking
# the first 8 characters raw yields '/subscri' for every Azure resource on earth -- a shared
# placeholder wearing a unique name.
# 🪤 AND TAKE THE **TAIL**, NOT THE HEAD. An ARM id's entropy is the resource name at the end; its
# first characters are the subscription guid shared by every resource in that subscription.
function Get-SIIdFragment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Id,
        [Parameter()][int]$Length = 8
    )
    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
    $clean = ($Id -replace '[^A-Za-z0-9]', '')
    if ([string]::IsNullOrWhiteSpace($clean)) { return $null }
    $take = [Math]::Min($Length, $clean.Length)
    $clean.Substring($clean.Length - $take, $take).ToLowerInvariant()
}

function Get-SIRowValue {
    <# Read one property off a row, which may be a hashtable OR a PSCustomObject. Both shapes occur:
       the builders produce hashtables, and rows that travel through the staging blob come back
       DESERIALISED. Probing only one shape is what hid the identity scope-filter bug -- its unit tests
       passed hashtables while the engine passed deserialised JSON. #>
    param([Parameter()]$Row, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Row) { return '' }
    if ($Row -is [System.Collections.IDictionary]) {
        if ($Row.Contains($Name)) { return [string]$Row[$Name] } else { return '' }
    }
    $p = $Row.PSObject.Properties[$Name]
    if ($p) { return [string]$p.Value }
    ''
}

function Set-SIRowValue {
    param(
        [Parameter()]$Row,
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][AllowEmptyString()][string]$Value
    )
    if ($null -eq $Row) { return }
    if ($Row -is [System.Collections.IDictionary]) { $Row[$Name] = $Value; return }
    if ($Row.PSObject.Properties[$Name]) { $Row.$Name = $Value }
    else { Add-Member -InputObject $Row -MemberType NoteProperty -Name $Name -Value $Value -Force }
}

function Get-SICanonicalIdType {
    <# Collapse alias spellings to the one canonical type name. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Type)
    if ([string]::IsNullOrWhiteSpace($Type)) { return '' }
    $k = $Type.ToLowerInvariant()
    if ($script:SIIdTypeAliases.ContainsKey($k)) { return $script:SIIdTypeAliases[$k] }
    $Type
}

function Test-SIIdTypeJoinable {
    <# May this identifier type identify an asset -- i.e. key SI_AssetId, and join? #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Type)
    if ([string]::IsNullOrWhiteSpace($Type)) { return $false }
    foreach ($t in $script:SIJoinableIdTypes) { if ($Type -ieq $t) { return $true } }
    $false
}

function Test-SINameIsIdentifier {
    <#
        Is this name candidate simply the asset's own identifier wearing a name's clothes?

        🔴 WHY IT IS A FUNCTION RATHER THAN A COMPARISON AT EACH SITE. The rule already existed twice
        and the second copy did not have it: `Resolve-SIAssetNameForSource` refuses such a candidate
        (measured 2026-08-27 -- 78 of 198 endpoint rows carried a 40-hex MDE machine id in the name
        column, because Get-DiscoveryFromMDE substitutes `$m.id` when MDE has no computerDnsName), and
        the `DisplayName` chain in Build-EndpointProfileRow does not -- so on 2026-09-01 the SAME 78
        rows of that SAME estate still published the machine id, in the column beside the one that was
        fixed. One rule, one home, so a future third caller inherits it instead of re-deciding.

        🪤 THE COMPARISON MUST STRIP LEADING `token:` SEGMENTS -- fixed 2026-08-31 in the original
        copy and carried here. The azure engine's PrimaryEntityId for an exposure-graph-only node is
        `eg:az:<nodeid>` while the candidate is the BARE `<nodeid>`: not equal, so an exact guard
        accepted it, and 123 of 123 anchorless azure rows published a 32-hex GUID as their name.
        Case-insensitive for the same reason -- a hex id differing only in case is the same id.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowEmptyString()][string]$Name,
        [Parameter()][AllowEmptyString()][string]$Id
    )
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ([string]::IsNullOrWhiteSpace($Id))   { return $false }
    if ($Name -ieq $Id) { return $true }
    $idNorm = $Id
    if ($idNorm -match '^(?:[A-Za-z0-9_-]+:)+(.+)$') { $idNorm = $matches[1] }
    return ($Name -ieq $idNorm)
}

function Resolve-SIAssetIdentityPair {
    <#
        🔒 OPERATOR, 2026-08-28 -- the requirement AND the direction:
          "it must be 100% populated for both fields - and they must be consistent, so fx if eg node
           name is used in assetname - then eg node id must be used in assetid"
          "do the pair properly - name drives id AS ID CAN CHANGE fx if client is known in entra id as
           device, then later it comes in mde, so id could change"

        🔑 WHY THE NAME DRIVES, and it is a STABILITY argument rather than a cosmetic one. Under the old
        model the ID picked first (mdeId -> egNodeId -> aadId -> hostname) and the name walked its own
        separate list. A device first seen in Entra was keyed on its AadDeviceId; the day MDE onboarded
        it, MDE outranked Entra and the SAME DEVICE SILENTLY CHANGED ITS SI_AssetId. Nothing errored --
        the id simply moved, taking every downstream join with it.
        Driving from the NAME inverts that: the name source is chosen first, its id comes along, and the
        arrival of a higher-priority ID source no longer re-keys the asset.

        THE ALGORITHM. Walk -SourceChain in order. The first source that yields BOTH a usable name and
        an id wins, and BOTH fields come from it. If no source names the asset, fall back to
        -FallbackId with a MARKED SYNTHETIC name -- never a name borrowed from another source, because
        borrowing is exactly the inconsistency this exists to end.

        🔴 A NAME EQUAL TO ITS OWN ID IS NOT A NAME. MEASURED 2026-08-27: 78 of 198 endpoint rows
        carried a 40-hex MDE machine id in the name column, because Get-DiscoveryFromMDE substitutes
        $m.id when MDE has no computerDnsName. Such a candidate is skipped so a real name below it can
        win -- and the pair then takes THAT source's id, which is the whole point.

        -SourceChain: ordered @( @{ NameKeys=@('ENTRA_DisplayName'); IdType='AadDeviceId'; Source='entra' }, ... )
        -EntityIds:   the row's typed identifiers, @( @{ type=..; id=..; source=.. } )
        Returns @{ Name; Id; IdType; Source; Synthetic } -- or $null when there is nothing at all.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]$Meta,
        [Parameter()][AllowEmptyCollection()][object[]]$EntityIds = @(),
        [Parameter(Mandatory)][object[]]$SourceChain,
        [Parameter()][AllowEmptyString()][string]$FallbackId = '',
        [Parameter()][AllowEmptyString()][string]$FallbackIdType = '',
        [Parameter(Mandatory)][string]$Engine
    )

    # Index the typed identifiers once. Canonicalise the TYPE so EgNodeId / ExposureGraphNodeId -- one
    # fact with two spellings -- cannot cause a miss here the way they already did inside the join.
    $idByType = @{}
    foreach ($e in @($EntityIds)) {
        if ($null -eq $e) { continue }
        $t = Get-SICanonicalIdType -Type ([string](Get-SIRowValue -Row $e -Name 'type'))
        $v = [string](Get-SIRowValue -Row $e -Name 'id')
        if ([string]::IsNullOrWhiteSpace($t) -or [string]::IsNullOrWhiteSpace($v)) { continue }
        if (-not $idByType.ContainsKey($t)) { $idByType[$t] = $v }
    }

    foreach ($s in @($SourceChain)) {
        $idType = Get-SICanonicalIdType -Type ([string](Get-SIRowValue -Row $s -Name 'IdType'))
        if (-not $idByType.ContainsKey($idType)) { continue }   # this source did not identify the asset
        $id = [string]$idByType[$idType]

        foreach ($nk in @((Get-SIRowValue -Row $s -Name 'NameKeys') -split ';')) {
            if ([string]::IsNullOrWhiteSpace($nk)) { continue }
            $n = [string](Get-SIRowValue -Row $Meta -Name $nk.Trim())
            if ([string]::IsNullOrWhiteSpace($n)) { continue }
            if ($n -eq $id) { continue }                        # an identifier is not a name
            return @{
                Name = $n; Id = $id; IdType = $idType
                Source = [string](Get-SIRowValue -Row $s -Name 'Source'); Synthetic = $false
            }
        }
    }

    # Nothing named it. Keep the highest-priority id (so the row stays identifiable and 100% populated)
    # and MARK the name, rather than letting a bare identifier read like a hostname in a customer's Excel.
    if ([string]::IsNullOrWhiteSpace($FallbackId)) { return $null }
    # Get-SIIdFragment is declared above in this same file.
    $frag = Get-SIIdFragment -Id $FallbackId
    $name = if ($frag) { 'unnamed-{0}-{1}' -f $Engine.ToLowerInvariant(), $frag } else { $null }
    @{ Name = $name; Id = $FallbackId; IdType = $FallbackIdType; Source = 'fallback'; Synthetic = $true }
}

function Resolve-SIAssetNameForSource {
    <#
        🔒 OPERATOR REQUIREMENT, 2026-08-28: "it must be 100% populated for both fields -- and they must
        be CONSISTENT, so fx if eg node name is used in assetname, then eg node id must be used in
        assetid."

        🔴 THE INVARIANT THIS ENFORCES: SI_AssetName and SI_AssetId describe the asset AS SEEN BY ONE
        SOURCE. Before this, the two walked SEPARATE priority lists and routinely disagreed --
        Build-EndpointProfileRow took its id from MDE (mdeId first) while its name walked
        ENTRA_DisplayName first, so a row could carry Entra's name beside MDE's id. Nothing errored,
        and the pair silently described two different views of the asset. An operator tracing a name
        back to its id then lands on a source that never produced that name.

        🔑 THE ID DRIVES, NOT THE NAME. The id's source is chosen first and the name follows it. Doing
        it the other way would let a better name MOVE the id -- and the id is the stable, 100%-unique
        anchor that correlation ledger anchors, report joins and the CMDB key all hang off. Changing an
        id to improve a display string is the wrong trade in every direction.

        WHEN THE WINNING SOURCE HAS NO NAME the value becomes the MARKED SYNTHETIC, deliberately, and
        NOT a name borrowed from a different source -- borrowing is precisely the inconsistency this
        exists to end. `unnamed-<engine>-<frag>` says the true thing: the source that identifies this
        asset does not name it.

        -NameKeyByType maps PrimaryEntityType -> the metadata key holding THAT source's name.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]$Meta,
        [Parameter()][AllowEmptyString()][string]$EntityType,
        [Parameter(Mandatory)][hashtable]$NameKeyByType,
        [Parameter()][AllowEmptyString()][string]$PrimaryEntityId = '',
        [Parameter(Mandatory)][string]$Engine
    )

    # 🪤 THE GUARD BELOW COMPARED EXACTLY, AND A PREFIX WALKED STRAIGHT PAST IT -- fixed 2026-08-31.
    # The azure engine's PrimaryEntityId for an exposure-graph-only node is `eg:az:<nodeid>`, while the
    # name candidate is the BARE `<nodeid>`. Not equal, so the guard accepted it: MEASURED on the live
    # estate, **123 of 123** anchorless azure rows published a 32-hex GUID as `SI_AssetName`. Exactly
    # the defect this guard exists to prevent, defeated by three characters of prefix -- and the same
    # shape as public-ip finding 1b, where the name was the IP address.
    # ✅ So normalise the id by stripping any leading `token:` segments before comparing, and compare
    # case-insensitively. A candidate that IS the identifier in any of its spellings is refused, and
    # the caller falls through to the MARKED synthetic `unnamed-<engine>-<8>` -- which tells an operator
    # nothing knows this asset's name, instead of handing them a hash that reads like data.
    # 📌 The rule itself now lives in `Test-SINameIsIdentifier` above, because a SECOND name chain --
    # the endpoint `DisplayName` column -- did not have it and was still publishing the machine id.

    $val = ''
    if (-not [string]::IsNullOrWhiteSpace($EntityType)) {
        foreach ($k in $NameKeyByType.Keys) {
            if ($EntityType -ieq $k) {
                foreach ($mk in @($NameKeyByType[$k])) {
                    $v = Get-SIRowValue -Row $Meta -Name $mk
                    # 🔴 A candidate identical to PrimaryEntityId is an IDENTIFIER, not a name. MEASURED
                    # 2026-08-27: 78 of 198 endpoint rows carried a 40-hex MDE machine id in the name
                    # column, because Get-DiscoveryFromMDE substitutes $m.id when MDE has no
                    # computerDnsName -- and it reached a customer's Excel reading like a hostname.
                    if (-not [string]::IsNullOrWhiteSpace($v) -and -not (Test-SINameIsIdentifier -Name $v -Id $PrimaryEntityId)) { $val = $v; break }
                }
                break
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($val)) { return $val }
    if ([string]::IsNullOrWhiteSpace($PrimaryEntityId)) { return $null }
    # Get-SIIdFragment is declared above in this same file.
    $frag = Get-SIIdFragment -Id $PrimaryEntityId
    if (-not $frag) { return $null }
    ('unnamed-{0}-{1}' -f $Engine.ToLowerInvariant(), $frag)
}

function Resolve-SIAssetIdValue {
    <#
        THE ONE RULE FOR WHAT SI_AssetId MAY BE.

        🔴 THE DEFECT THIS CLOSES. Build-EndpointProfileRow picks PrimaryEntityId as the first non-null
        of mdeId -> egNodeId -> aadId -> HOSTNAME, and SI_AssetId is that value verbatim. The first
        three are joinable; the fourth is in SIWeakIdTypes, which this codebase defines as "NOT unique
        -- must never join on these alone". So when the chain reaches its last rung the profiler uses
        as its asset id exactly the type the correlation engine forbids keying on -- and nothing errors,
        because the two rules lived in two modules that could not see each other.

        A weak value is MARKED rather than dropped: the row keeps a populated, stable id (the operator
        requirement is 100% population), and `weak:<type>:<value>` says out loud that nothing durable
        identifies this asset -- the same reasoning as the `unnamed-<engine>-<frag>` synthetic name.
        A bare hostname reads like a real id and silently is not.

        ⚠️ A HOSTNAME IS NOT UNIQUE EITHER, so marking does not make it so -- two machines can share
        one. What marking buys is that the weakness is VISIBLE and machine-testable
        (Test-SIWeakAssetId) instead of being indistinguishable from a durable id.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Id,
        [Parameter()][AllowEmptyString()][string]$Type = ''
    )
    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
    if (Test-SIIdTypeWeak -Type $Type) { return ('weak:{0}:{1}' -f $Type.ToLowerInvariant(), $Id) }
    $Id
}

function Test-SIWeakAssetId {
    <# Is this SI_AssetId built on a weak identifier? A contract a consumer can test without parsing. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value -like 'weak:*')
}

function Test-SIIdTypeWeak {
    <# Explicitly classified as NOT unique. Note this is not merely "not strong": an unknown type is
       neither -- and an unknown type must be treated as unsafe, which is what callers do. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Type)
    if ([string]::IsNullOrWhiteSpace($Type)) { return $false }
    foreach ($t in $script:SIWeakIdTypes) { if ($Type -ieq $t) { return $true } }
    $false
}

# ---------------------------------------------------------------------------------------------------
# MOVED HERE 2026-08-28 from engine/asset-correlation/_shared/SI-CorrelationCore.ps1. Risk Analysis
# needs the SAME ordinal sort -- RA-RiskScore.ps1 built ImpactedAssetsList with a culture-sensitive
# `Sort-Object -Unique`, so the list ORDER a customer reads differed between a Danish and an English
# host. Correlation is OPTIONAL, so RA cannot dot-source it; copying the function would have been a
# second implementation of a rule that exists BECAUSE two implementations disagree.
# ---------------------------------------------------------------------------------------------------
function Sort-SIOrdinal {
    <#
        Sort strings by ORDINAL comparison, never by culture.

        🔴 WHY THIS EXISTS -- found 2026-08-12, and it is a correctness bug, not tidiness.
        `Sort-Object` compares strings using the CURRENT CULTURE. This machine runs da-DK, where "aa"
        collates as "å" -- the LAST letter of the Danish alphabet -- so `@('zzz','aaa') | Sort-Object`
        correctly returns `zzz, aaa`, the exact opposite of the en-US result.

        SI_CorrelationId is seeded by taking the FIRST value after sorting (Get-SICorrelationId). Under
        culture-sensitive sort, the same asset group can therefore seed from a DIFFERENT identifier on a
        Danish host than on an English one -- a different correlation id for the same real-world object.
        A connector binding to that id would create a second CI for a machine it already knew about, and
        duplicate CIs are effectively permanent once incidents point at them.

        It also silently destroys the property the whole design leans on: that an object recomputes to
        the SAME id on every run with no memory of the previous one, which is what makes SQL an
        optimisation rather than a prerequisite. "Deterministic" has to mean deterministic ACROSS HOSTS,
        and SI ships to ~6,000 community installs whose locale we do not choose.

        Hostnames and GUIDs make this worse, not better: an asset literally named `AAU-SRV01` or a GUID
        beginning `aa` is ordinary, so the divergence is not a contrived edge case.
    #>
    param([Parameter(ValueFromPipeline)][AllowEmptyCollection()][string[]]$Value)
    end {
        $all = @($input | ForEach-Object { $_ })
        if ($all.Count -eq 0) { $all = @($Value) }
        $arr = [string[]]@($all | Where-Object { $null -ne $_ })
        if ($arr.Count -eq 0) { return @() }
        [Array]::Sort($arr, [System.StringComparer]::Ordinal)
        # 🪤 RETURNED PLAINLY, NOT AS `,$arr`. Comma-protection here nests the array once the caller
        # wraps with @(), so `@(Sort-SIOrdinal ...)[0]` yields the WHOLE ARRAY instead of its first
        # element -- and the SI_CorrelationId seed is exactly such a call. It produced the literal id
        # "exposuregraphnodeid:System.String[]" before this line changed. That is the THIRD time this
        # codebase has been bitten by comma-protection (handoff trap 6.1 records the first two, in two
        # different files). Return the collection plainly and let the caller wrap.
        $arr
    }
}
