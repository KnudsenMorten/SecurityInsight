#Requires -Version 5.1
<#
    SI v3 Phase 4, step 2 -- THE SOURCE TRUST LIST.

    Operator ruling (e), verbatim in shape: "the list shows the priority and trust-level: we trust or we
    don't trust". Exactly two things, and no third:

        POSITION  -- who wins a CONTRADICTION (same question, different answers: a stale tag says
                     workstation, graph detection says domain controller).
        trusted   -- a boolean. May this source set the tier at all. No middle state.

    NO NUMBERS. The weights were deleted, not renamed, and the reason is decisive: they produced TIES,
    and a tie has no defined outcome. In the shipped default three contributors shared 1.0 and three
    shared 0.7 -- six of ten had undefined precedence, which is why the aggregator that consumed them
    was declared and never implemented. An ordered list cannot tie.

    🔴 THIS LIST DOES NOT DECIDE THE TIER. Ruling (f) and the resolution in (k): MIN still decides across
    INDEPENDENT facts -- SQL installed AND a GA logs in gives Tier 0, and a GA logon must always be able
    to set T0. Position settles only the case where two sources answer the SAME question differently.
    Step 3 builds that reducer; this file only produces the list it will consult.

    ⚠️ THE DEFAULT IS A STARTING POINT, NOT A TRUTH. Trust is (signal x that customer's process). Tags
    are excellent where tagging is automated and worthless where it is manual and abandoned; logon is
    excellent under good admin hygiene and weakly discriminating where everyone is a GA. SI cannot know
    which from inside the tenant, which is why the customer overlay exists and why the measurement
    reports matter more than the shipped order.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>

# Ordering principle, applied when seeding from the old weights: OBSERVED BEATS ASSERTED. Something the
# estate demonstrates outranks something a human wrote down, because the written thing is only ever as
# good as the process that maintains it.
# Two deliberate edits the operator called out, both away from the pure weight order:
#   * endpoint_user_based_tier moved UP   -- "logon detects actual permission to a user".
#   * tenant_si_manual_tag     moved DOWN from 1.0 -- a tag depends on a maintenance process.
# And 3.4c: CAPABILITY BEATS CONTEXT, so capability/software detection outranks environment tags -- the
# certificate authority in a Tier-2 subscription must not read Tier 2.

function Get-SITierTrustList {
    <#
        The ordered, normalised trust list for one engine.

        Accepts the MERGED schema (locked + customer overlay) -- Get-SISchemaWithCustomMerge already
        merges aggregator.contributors[*] by id. Consumption was the missing half, which is this.

        🪤 THE MERGE REPLACES BY ID, IT DOES NOT DEEP-MERGE. A customer who writes only
        {"id": "tenant_si_manual_tag", "trusted": false} REPLACES the locked entry outright and loses
        its `order`. The design says silence in the customer file inherits the default, so the locked
        defaults are re-applied here per field. Without this, the most natural customer edit -- name a
        source, distrust it, say nothing else -- would silently drop that source to the bottom of the
        list instead of leaving its precedence alone.
    #>
    param(
        [Parameter(Mandatory)]$Aggregator,
        [Parameter()][hashtable]$LockedDefaults,
        [Parameter()][hashtable]$LockedQuestions,
        [Parameter()][hashtable]$LockedKinds
    )

    $contributors = @()
    if ($Aggregator -and $Aggregator.PSObject.Properties['contributors'] -and $Aggregator.contributors) {
        $contributors = @($Aggregator.contributors)
    }
    if ($contributors.Count -eq 0) { return @() }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in $contributors) {
        if ($null -eq $c) { continue }
        $id = if ($c.PSObject.Properties['id']) { [string]$c.id } else { '' }
        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        $order = $null
        if ($c.PSObject.Properties['order'] -and $null -ne $c.order -and "$($c.order)" -ne '') {
            try { $order = [int]$c.order } catch { $order = $null }
        }
        # Inherit the locked position when the customer entry omitted it (see the REPLACE trap above).
        if ($null -eq $order -and $LockedDefaults -and $LockedDefaults.ContainsKey($id)) {
            $order = [int]$LockedDefaults[$id]
        }

        # trusted defaults TRUE. A source is trusted unless someone says otherwise -- and note that
        # `trusted: false` never stops COLLECTION (ruling i): the claim is still recorded in
        # SI_TierClaims, it simply may not set the tier. Withdrawing trust must never blind the
        # customer to the source.
        $trusted = $true
        if ($c.PSObject.Properties['trusted'] -and $null -ne $c.trusted) { $trusted = [bool]$c.trusted }

        # Which question this source answers. Empty = unclassified = INDEPENDENT, which is what keeps
        # the step-3 reducer inert until an operator declares groupings. Treating two independent facts
        # as contradicting would SUPPRESS a true signal -- the mistake corrected twice already here.
        $question = ''
        if ($c.PSObject.Properties['question'] -and $c.question) { $question = [string]$c.question }
        if ([string]::IsNullOrWhiteSpace($question) -and $LockedQuestions -and $LockedQuestions.ContainsKey($id)) {
            $question = [string]$LockedQuestions[$id]
        }

        # ASSERTED vs OBSERVED -- the asymmetry the operator's rule actually needs.
        #
        # An ASSERTED claim is something a human wrote down (a manual tier tag). An OBSERVED claim is
        # something the estate demonstrated (a catalog match, a posture rule, a logon). The rule is
        # "observed beats asserted": an assertion yields when observation disagrees with it, and
        # observed detections NEVER suppress each other -- they are independent facts and go to MIN.
        #
        # 🔴 THIS REPLACES THE `question` GROUPING FOR THIS RULE, because grouping was measured wrong
        # TWICE (see V3-HANDOFF Phase 4 step 3). Sharing a question label makes every member able to
        # suppress every other, so the catalog silently outranked posture rules and EG criticality --
        # a posture rule that DETECTED Tier 0 was discarded because the catalog outranks it, which is
        # ruling (f) inverted. No grouping fixes that, because the coarseness IS the model: catalog,
        # posture rules and EG criticality are independent DETECTIONS that happen to describe the same
        # subject, not competing answers to one question.
        #
        # 🔒 UNKNOWN => observed. That is the inert, safe direction: an observed claim is never
        # suppressed and never suppresses, so an unclassified source reduces exactly as plain MIN.
        # Defaulting to `asserted` would let a source be silently suppressed by any disagreement.
        $kind = ''
        if ($c.PSObject.Properties['kind'] -and $c.kind) { $kind = ([string]$c.kind).Trim().ToLowerInvariant() }
        if ([string]::IsNullOrWhiteSpace($kind) -and $LockedKinds -and $LockedKinds.ContainsKey($id)) {
            $kind = ([string]$LockedKinds[$id]).Trim().ToLowerInvariant()
        }
        if ($kind -ne 'asserted') { $kind = 'observed' }

        [void]$out.Add([pscustomobject]@{
            Id       = $id
            Order    = $order
            Trusted  = $trusted
            Question = $question
            Kind     = $kind
            # Never silently reinstated. A weight surviving here means someone re-added the model that
            # produced undefined ties, and a consumer should be able to see that rather than guess.
            HasLegacyWeight = [bool]($c.PSObject.Properties['weight'])
        })
    }

    # Unordered entries sort AFTER ordered ones rather than to the front -- a source nobody positioned
    # must not silently outrank one that was positioned deliberately. Id is the tie-break so the list is
    # deterministic; ties should not exist, but a non-deterministic order would be worse than a tie.
    # ORDINAL tie-break, not Sort-Object's culture-sensitive string compare. This host runs da-DK, where
    # "aa" collates as "å" and therefore sorts LAST -- so a culture-sensitive tie-break would order the
    # list differently on a Danish host than an English one. The list decides which source wins a
    # contradiction, so a locale-dependent order means a locale-dependent TIER. Same defect class as the
    # SI_CorrelationId seed (see Sort-SIOrdinal in SI-CorrelationCore.ps1).
    # Decorate-sort-undecorate on a single composite key, compared ORDINALLY. One zero-padded integer
    # then the id, so a plain ordinal string sort yields "by position, then by id" in one pass -- no
    # multi-key Sort-Object (whose tie-break silently does not apply here) and no overload ambiguity.
    $keyed = @{}
    foreach ($e in $out) {
        $pos = if ($null -eq $e.Order) { [int]::MaxValue } else { [int]$e.Order }
        $keyed[('{0:D10}|{1}' -f $pos, $e.Id)] = $e
    }
    $keys = [string[]]@($keyed.Keys)
    if ($keys.Count -eq 0) { return @() }
    [Array]::Sort($keys, [System.StringComparer]::Ordinal)
    @($keys | ForEach-Object { $keyed[$_] })
}

function Get-SITierTrustRank {
    <#
        Position of one source, for the step-3 reducer. Returns [int]::MaxValue for an unknown or
        unpositioned source, so "I have never heard of this" loses every contradiction rather than
        accidentally winning one.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$TrustList,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Id
    )
    foreach ($e in @($TrustList)) {
        if ($e.Id -ieq $Id) { if ($null -eq $e.Order) { return [int]::MaxValue } else { return [int]$e.Order } }
    }
    [int]::MaxValue
}

function Get-SITierClaimKind {
    <#
        `asserted` (a human wrote it down) or `observed` (the estate demonstrated it).

        Unknown sources answer `observed`, matching the list builder's default and for the same reason:
        observed claims are never suppressed and never suppress, so an unrecognised source behaves
        exactly as it does under plain MIN rather than becoming silently suppressible.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$TrustList,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Id
    )
    foreach ($e in @($TrustList)) {
        if ($e.Id -ieq $Id) {
            if ($e.PSObject.Properties['Kind'] -and $e.Kind) { return ([string]$e.Kind).ToLowerInvariant() }
            return 'observed'
        }
    }
    'observed'
}

function Test-SITierSourceTrusted {
    <#
        May this source set the tier? Unknown sources are NOT trusted -- the safe answer to "I do not
        recognise this" is to record the claim and let something recognised decide.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$TrustList,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Id
    )
    foreach ($e in @($TrustList)) { if ($e.Id -ieq $Id) { return [bool]$e.Trusted } }
    $false
}
