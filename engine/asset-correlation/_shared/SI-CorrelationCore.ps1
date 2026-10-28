#Requires -Version 5.1
<#
    SI v3 -- THE CORRELATION STAGE, as pure functions.

    PROMOTED from diagnostics/SICorrelationEngine.ps1 in Phase 3. The join logic below is unchanged from the PoC
    its 30 tests proved -- only this header differs, and the CONFIDENCE layer is appended at the end.
    Deliberately still pure: Invoke-SICorrelation.ps1 does every bit of the I/O, so the matching logic
    stays provable offline without a workspace.

    NAMING, settled: the id is SI_CorrelationId. `ResolvedObjectId` appears in older design text and was
    explicitly "a placeholder, not a decision" (docs/REQUIREMENTS.md:7363). One fact, one spelling --
    that is the trap that already cost a silent split when EgNodeId and ExposureGraphNodeId diverged.

    Turns rows from several engines into ONE object per real-world asset, and assigns each a stable
    SI_CorrelationId. Pure: no I/O, no SQL, no Azure, so the matching logic can be proven before any
    store is chosen.

    WHY THIS EXISTS. SI_AssetId is unique per ROW but engine-scoped: the same server is an MDE device id
    on its endpoint row and an ARM path on its azure row. Feed both to a connector and you get TWO CIs
    for one machine -- and duplicate CIs are effectively permanent once incidents point at them. Many
    customers are hybrid, so this is the common case, not an edge case.

    🔑 IT IS A KEYED JOIN, NOT FUZZY MATCHING. Operator facts: identities are hybrid and originate in AD;
    devices are mostly modern. So the anchors are AadDeviceId for devices, the Entra object id (with
    OnPremSid / OnPremObjectGuid for the AD tie) for identities, and AzureResourceId for cloud resources
    -- all of which SI already collects.

    🔴 THE FAILURE THIS GUARDS AGAINST IS THE MIRROR OF DUPLICATE CIs, AND IT IS WORSE.
    Joining on a NON-UNIQUE identifier FUSES two different assets into one object. Two machines can share
    a hostname; two users can share a display name; an IP is reassigned weekly. A duplicate CI is visible
    and annoying. A fused object silently attributes one machine's vulnerabilities to another and hides
    the second machine completely -- and nothing in the output looks wrong.
    So identifier types are explicitly classified, and ONLY globally-unique ones may join.
#>

# NO Set-StrictMode HERE, deliberately, and this is not laziness -- it is a scoping hazard.
# MEASURED 2026-08-12: Set-StrictMode in a dot-sourced file LEAKS INTO THE CALLER'S SCOPE. This file is
# dot-sourced by Invoke-SICorrelation.ps1, which sets Set-StrictMode -Off on its first lines; a
# StrictMode line here silently overrode that for the rest of the engine. If this ever gets dot-sourced
# into the shared chassis it would make THAT code strict too -- and Invoke-RiskAnalysis.ps1 opens with
# Set-StrictMode -Off and the comment "script designed for non-StrictMode environments". A library must
# not change the strictness of whoever loads it.
# What StrictMode was buying is kept by other means: script-scope state is declared at file scope (never
# lazily inside a function, which is the idiom that threw), heterogeneous records are read through
# explicit PSObject.Properties / IDictionary probes because Log Analytics rows genuinely vary column to
# column, and 60 tests cover the behaviour.

# 🔒 THE IDENTIFIER VOCABULARY NOW LIVES IN ONE PLACE -- engine/_shared/SI-AssetIdentity.ps1 -- and is
# dot-sourced here rather than declared here. It supplies $script:SIJoinableIdTypes,
# $script:SIWeakIdTypes, $script:SIIdTypeAliases, Get-SIJoinableIdTypes, Get-SIWeakIdTypes,
# Test-SIIdTypeJoinable, Test-SIIdTypeWeak and Get-SICanonicalIdType.
#
# 🔴 WHY IT MOVED. These lists were known ONLY to correlation, and correlation is optional -- so the
# PROFILING layer, which is not, had no access to the one rule that says which identifiers may key an
# asset. The consequence was measurable: Build-EndpointProfileRow's PrimaryEntityId chain ends in a
# HOSTNAME, and SI_AssetId is that value -- i.e. the profiler used as its asset id precisely the type
# this file classifies as WEAK and forbids joining on. One module's safety rule, silently bypassed by
# another, with nothing in any output looking wrong.
#
# 📌 The dot-source runs at FILE SCOPE, so the $script: variables land in the same scope they were
# declared in before and every reference below keeps working unchanged. Names are identical -- this is
# a move, not a rename, and there is deliberately no second spelling.
. (Join-Path $PSScriptRoot '..\..\_shared\SI-AssetIdentity.ps1')

# Priority for choosing the id that SEEDS a group's SI_CorrelationId. Highest first. Deterministic, so
# the same group produces the same id on every run without needing to remember the previous one.
$script:SISeedPriority = @(
    'ExposureGraphNodeId'; 'EgNodeId'   # cross-engine by construction -- the best seed
    'AzureResourceId'
    'AadDeviceId'
    'AadObjectId'
    'MdeDeviceId'
    'ActiveDirectoryObjectGuid'
    'SecurityIdentifier'
    'OnPremObjectGuid'
    'AzureVmId'
)

# 📌 Get-SIJoinableIdTypes / Get-SIWeakIdTypes and the $script:SIIdTypeAliases table (the "one fact
# must not have two spellings" canonicaliser for EgNodeId / ExposureGraphNodeId) now come from
# engine/_shared/SI-AssetIdentity.ps1, dot-sourced above. They are NOT redefined here: a definition
# after the dot-source would silently WIN, leaving the shared module loaded but dead -- the
# declared-but-never-wired shape this codebase has already found eight times.

# 📌 Sort-SIOrdinal MOVED to engine/_shared/SI-AssetIdentity.ps1 (dot-sourced at the top of this file).
# Risk Analysis needs the same ordinal rule and cannot depend on this OPTIONAL engine. Not redefined
# here: a definition after the dot-source would silently win and leave the shared copy dead.

function Get-SIMemberIdentifiers {
    <#
        A member's identifiers, ALWAYS as a clean array, never a null element.

        🪤 WHY THIS EXISTS. `foreach ($id in @($m.Identifiers))` looks safe and is not: when
        `Identifiers` is absent or $null, `@($null)` is an array containing ONE $null, so the loop runs
        once with $id = $null and the next line -- `$id.Type.ToLowerInvariant()` -- throws
        "You cannot call a method on a null-valued expression". Found 2026-08-13 by calling
        Get-SICorrelationGroups with a hand-built member, which is exactly how the tests and any future
        caller use it.

        Not reachable through ConvertTo-SICorrelationInput today (it always sets @()), but these are
        PUBLIC pure functions in a library whose whole point is being callable without the I/O layer.
        An entry point that throws on a shape it was handed is a defect regardless of who calls it.
    #>
    param($Member)
    if ($null -eq $Member) { return @() }
    $ids = $null
    if ($Member -is [System.Collections.IDictionary]) {
        if ($Member.Contains('Identifiers')) { $ids = $Member['Identifiers'] }
    } elseif ($Member.PSObject.Properties['Identifiers']) {
        $ids = $Member.Identifiers
    }
    if ($null -eq $ids) { return @() }
    @($ids | Where-Object { $null -ne $_ })
}

# 📌 Get-SICanonicalIdType and Test-SIIdTypeJoinable also come from engine/_shared/SI-AssetIdentity.ps1
# (dot-sourced at the top of this file), for the same reason as the lists above: profiling needs the
# SAME answer correlation gives, and a second copy here is what let the two layers disagree.

function ConvertTo-SICorrelationInput {
    <#
        Normalise one profile row into: its engine, its SI_AssetId, and its JOINABLE identifiers.
        Weak identifiers are deliberately dropped here so they cannot leak into the join by accident.
    #>
    param(
        [Parameter(Mandatory)] $Row,
        [Parameter(Mandatory)] [string] $Engine
    )
    $ids = New-Object System.Collections.ArrayList
    $get = {
        param($o, $n)
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { return $o[$n] } ; return $null }
        if ($o.PSObject.Properties[$n]) { return $o.$n }
        $null
    }

    # flat identifier columns
    foreach ($t in $script:SIJoinableIdTypes) {
        $v = & $get $Row $t
        if (-not [string]::IsNullOrWhiteSpace([string]$v)) {
            [void]$ids.Add([pscustomobject]@{ Type = (Get-SICanonicalIdType -Type $t); Value = ([string]$v).ToLowerInvariant() })
        }
    }

    # EntityIds[] -- may arrive as a JSON string from Log Analytics
    $e = & $get $Row 'EntityIds'
    if ($null -ne $e) {
        if ($e -is [string]) { try { $e = $e | ConvertFrom-Json -ErrorAction Stop } catch { $e = $null } }
        foreach ($x in @($e)) {
            if ($null -eq $x) { continue }
            $t = & $get $x 'type'; $v = & $get $x 'id'
            if ((Test-SIIdTypeJoinable -Type ([string]$t)) -and -not [string]::IsNullOrWhiteSpace([string]$v)) {
                [void]$ids.Add([pscustomobject]@{ Type = (Get-SICanonicalIdType -Type ([string]$t)); Value = ([string]$v).ToLowerInvariant() })
            }
        }
    }

    [pscustomobject]@{
        Engine     = $Engine
        SIAssetId  = [string](& $get $Row 'SI_AssetId')
        Identifiers = @($ids | Sort-Object Type, Value -Unique)
    }
}

function Get-SICorrelationGroups {
    <#
        Connected components over shared JOINABLE identifiers. Two rows land in the same group when they
        share at least one globally-unique identifier value; transitively, A~B and B~C puts all three
        together, which is what links an endpoint row to an azure row through a shared EG node id.

        Union-find, so the result does not depend on input order -- important, because engines run
        staggered and rows arrive in whatever sequence the snapshot happens to hold.

        #61.4 -- OPERATOR DECISIONS. -Plan carries never-merge / force-merge / pin-id from
        correlation-decisions.custom.yaml (see SI-CorrelationDecisions.ps1). Absent or empty, this
        function behaves EXACTLY as before: every decision path is skipped, not merely satisfied, so
        an install with no decisions file cannot be affected by this feature at all.

        WHY never-merge IS ENFORCED AT UNION TIME, NOT AFTER GROUPING. Splitting a finished connected
        component means choosing which members go which way, and there is no non-arbitrary rule for
        that -- it is the same "one run cannot tell a split from a failed source" problem 2.3a refuses
        to guess at. Refusing the JOIN is decidable: at the moment two components would fuse we know
        exactly which anchors each side carries, so we can decline and say which decision declined it.

        A REFUSED JOIN IS REPORTED, NEVER SILENT. It is recorded on the returned group as
        RefusedJoins so the run summary can name it. An operator whose decision fired and saw nothing
        would have no way to tell it from one that never loaded -- #61's recurring failure.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Inputs,
        [Parameter()][AllowNull()] $Plan
    )

    $n = @($Inputs).Count
    if ($n -eq 0) { return @() }

    $hasPlan = ($null -ne $Plan -and -not $Plan.IsEmpty)

    $parent = @(0..([math]::Max($n - 1, 0)))
    $find = {
        param($i)
        while ($parent[$i] -ne $i) { $parent[$i] = $parent[$parent[$i]]; $i = $parent[$i] }
        $i
    }

    # Which DECISION-MENTIONED anchors each component currently carries. Only anchors the operator
    # named are tracked, so this stays a handful of keys however large the estate is.
    $compAnchors = @{}
    $refusals    = New-Object System.Collections.Generic.List[object]

    if ($hasPlan) {
        for ($i = 0; $i -lt $n; $i++) {
            $mine = @{}
            foreach ($id in (Get-SIMemberIdentifiers -Member $Inputs[$i])) {
                $k = '{0}|{1}' -f (Get-SICanonicalIdType -Type $id.Type).ToLowerInvariant(), ([string]$id.Value).ToLowerInvariant()
                if ($Plan.Forbid.ContainsKey($k) -or $Plan.Pinned.ContainsKey($k)) { $mine[$k] = $true }
                else {
                    foreach ($f in $Plan.Force) { if (@($f.AnchorKeys) -contains $k) { $mine[$k] = $true; break } }
                }
            }
            if ($mine.Keys.Count -gt 0) { $compAnchors[$i] = $mine }
        }
    }

    # Would fusing these two components put a forbidden pair in one object?
    $wouldViolate = {
        param($ra, $rb)
        if (-not $hasPlan) { return $null }
        $A = if ($compAnchors.ContainsKey($ra)) { $compAnchors[$ra] } else { $null }
        $B = if ($compAnchors.ContainsKey($rb)) { $compAnchors[$rb] } else { $null }
        if ($null -eq $A -or $null -eq $B) { return $null }
        foreach ($a in $A.Keys) {
            if (-not $Plan.Forbid.ContainsKey($a)) { continue }
            foreach ($b in $B.Keys) { if ($Plan.Forbid[$a].ContainsKey($b)) { return @($a, $b) } }
        }
        $null
    }

    $union = {
        param($a, $b, $why)
        $ra = & $find $a; $rb = & $find $b
        if ($ra -eq $rb) { return $true }
        $v = & $wouldViolate $ra $rb
        if ($null -ne $v) {
            [void]$refusals.Add([pscustomobject]@{ AnchorA = $v[0]; AnchorB = $v[1]; Via = $why })
            return $false
        }
        $parent[$rb] = $ra
        if ($hasPlan) {
            # The surviving root inherits both sides' anchors, or the next union would not see them.
            if ($compAnchors.ContainsKey($rb)) {
                if (-not $compAnchors.ContainsKey($ra)) { $compAnchors[$ra] = @{} }
                foreach ($k in $compAnchors[$rb].Keys) { $compAnchors[$ra][$k] = $true }
                [void]$compAnchors.Remove($rb)
            }
        }
        $true
    }

    # index: identifier "type|value" -> first row index that carried it
    $seen = @{}
    for ($i = 0; $i -lt $n; $i++) {
        foreach ($id in (Get-SIMemberIdentifiers -Member $Inputs[$i])) {
            $k = '{0}|{1}' -f $id.Type.ToLowerInvariant(), $id.Value
            if ($seen.ContainsKey($k)) { [void](& $union $seen[$k] $i $k) } else { $seen[$k] = $i }
        }
    }

    # force-merge LAST, so an operator assertion is applied to whatever the data produced rather than
    # to a half-built partition. It is still subject to never-merge, and a force-merge that a
    # never-merge blocks is a contradiction the plan has already dropped and reported.
    if ($hasPlan -and @($Plan.Force).Count -gt 0) {
        $byAnchor = @{}
        for ($i = 0; $i -lt $n; $i++) {
            foreach ($id in (Get-SIMemberIdentifiers -Member $Inputs[$i])) {
                $k = '{0}|{1}' -f (Get-SICanonicalIdType -Type $id.Type).ToLowerInvariant(), ([string]$id.Value).ToLowerInvariant()
                if (-not $byAnchor.ContainsKey($k)) { $byAnchor[$k] = $i }
            }
        }
        foreach ($f in $Plan.Force) {
            $present = @(@($f.AnchorKeys) | Where-Object { $byAnchor.ContainsKey($_) })
            # An anchor nobody carries is not an error -- the asset may simply be absent from this
            # snapshot. It is also not a success, so it must not read as one; the caller reports it.
            for ($x = 1; $x -lt $present.Count; $x++) {
                [void](& $union $byAnchor[$present[0]] $byAnchor[$present[$x]] ('force-merge:' + $present[$x]))
            }
        }
    }

    $byRoot = @{}
    for ($i = 0; $i -lt $n; $i++) {
        $r = & $find $i
        if (-not $byRoot.ContainsKey($r)) { $byRoot[$r] = New-Object System.Collections.ArrayList }
        [void]$byRoot[$r].Add($Inputs[$i])
    }

    # #61.4 -- WHICH IDENTIFIER VALUES ARE NO LONGER IDENTIFYING.
    # An identifier value present in two DISTINCT final groups can only occur because a never-merge
    # blocked their union: without a plan the union-find would have fused them on exactly that value.
    # So the set is derivable from the result rather than tracked through the algorithm, and it is
    # empty by construction whenever no decision fired -- which is why the no-plan path cannot be
    # affected by this at all. See Get-SICorrelationId for the live collision that made it necessary.
    $ambiguousIdKeys = $null
    if ($refusals.Count -gt 0) {
        $seenInGroup = @{}
        $ambiguousIdKeys = @{}
        foreach ($r in $byRoot.Keys) {
            foreach ($m in @($byRoot[$r])) {
                foreach ($id in (Get-SIMemberIdentifiers -Member $m)) {
                    $k = '{0}|{1}' -f (Get-SICanonicalIdType -Type $id.Type).ToLowerInvariant(), ([string]$id.Value).ToLowerInvariant()
                    if ($seenInGroup.ContainsKey($k)) {
                        if ($seenInGroup[$k] -ne $r) { $ambiguousIdKeys[$k] = $true }
                    } else { $seenInGroup[$k] = $r }
                }
            }
        }
        if ($ambiguousIdKeys.Keys.Count -eq 0) { $ambiguousIdKeys = $null }
    }

    $out = foreach ($r in $byRoot.Keys) {
        $members = @($byRoot[$r])
        $basis   = @(Get-SICorrelationJoinBasis -Members $members)
        $cid     = Get-SICorrelationId -Members $members -AmbiguousIdKeys $ambiguousIdKeys
        $pinnedBy = $null

        $groupIsSeparated = $false
        if ($null -ne $ambiguousIdKeys) {
            foreach ($m in $members) {
                foreach ($id in (Get-SIMemberIdentifiers -Member $m)) {
                    $ak = '{0}|{1}' -f (Get-SICanonicalIdType -Type $id.Type).ToLowerInvariant(), ([string]$id.Value).ToLowerInvariant()
                    if ($ambiguousIdKeys.ContainsKey($ak)) { $groupIsSeparated = $true; break }
                }
                if ($groupIsSeparated) { break }
            }
        }

        if ($hasPlan -and $Plan.Pinned.Keys.Count -gt 0) {
            # Which pins this group carries. Two DIFFERENT pins in one group is a contradiction the
            # plan could not see -- it only becomes visible once the data decides what is one object.
            $hits = @{}
            foreach ($m in $members) {
                foreach ($id in (Get-SIMemberIdentifiers -Member $m)) {
                    $k = '{0}|{1}' -f (Get-SICanonicalIdType -Type $id.Type).ToLowerInvariant(), ([string]$id.Value).ToLowerInvariant()
                    if ($Plan.Pinned.ContainsKey($k)) { $hits[$Plan.Pinned[$k]] = $k }
                }
            }
            if ($hits.Keys.Count -eq 1) {
                $cid = @($hits.Keys)[0]
                $pinnedBy = $hits[$cid]
            } elseif ($hits.Keys.Count -gt 1) {
                # KEEP THE COMPUTED ID. Choosing one operator's pin over another's would honour a
                # decision they cannot predict; the computed id is at least deterministic and is what
                # every previous run used. Reported, never silent.
                [void]$refusals.Add([pscustomobject]@{
                    AnchorA = (@($hits.Values) -join ', '); AnchorB = $null
                    Via = ('pin-id conflict: this object carries {0} different pinned ids ({1}) -- none applied, computed id kept' -f $hits.Keys.Count, ((@($hits.Keys) | Sort-Object) -join ', '))
                })
            }
        }

        [pscustomobject]@{
            Members          = $members
            Engines          = @($members.Engine | Sort-Object -Unique)
            SIAssetIds       = @($members.SIAssetId | Where-Object { $_ } | Sort-Object -Unique)
            SICorrelationId  = $cid
            IsCrossEngine    = ((@($members.Engine | Sort-Object -Unique)).Count -gt 1)
            JoinBasis        = $basis
            Confidence       = (Get-SICorrelationConfidence -Members $members -JoinBasis $basis)
            PinnedBy         = $pinnedBy
            # #61.4 -- this group carries an identifier another group also carries, which can only
            # happen because a never-merge blocked their union. The identity layer needs to know:
            # it is the ONE case where reassigning a ledger id is safe, because the operator supplied
            # the fact that one run could not have inferred. See Resolve-SIObjectIdentity.
            SeparatedByDecision = $groupIsSeparated
        }
    }
    $out = @($out)

    # Refusals belong to the RUN, not to any one group -- a refused join is precisely the case where
    # there is no single group to hang it on. Attached to every group so whichever one the caller
    # inspects can report them, and so the count cannot be lost by a group being filtered out.
    if ($refusals.Count -gt 0) {
        $arr = $refusals.ToArray()
        foreach ($g in $out) { Add-Member -InputObject $g -NotePropertyName 'RefusedJoins' -NotePropertyValue $arr -Force }
    }
    # The identity layer needs the same set: a contested anchor must be excluded from the ledger
    # lookup, the birth anchor and the write-back, or the ledger re-fuses what this just separated.
    # Same hashtable by reference -- it is small (only keys an operator named) and read-only downstream.
    if ($null -ne $ambiguousIdKeys) {
        foreach ($g in $out) { Add-Member -InputObject $g -NotePropertyName 'AmbiguousIdKeys' -NotePropertyValue $ambiguousIdKeys -Force }
    }
    $out
}

function Get-SICorrelationId {
    <#
        The group's stable id. Chosen DETERMINISTICALLY from the strongest identifier present, so the
        same real-world object yields the same id on every run without consulting a previous run --
        which is what keeps the id stable while MergedDeviceIds / MergedToDeviceId rotate MDE ids.

        Falls back to the lowest SI_AssetId so a single-engine object still gets an id: most assets
        appear in exactly one engine, and they must not be left without one.

        -AmbiguousIdKeys (#61.4) -- identifier "type|value" keys that appear in MORE THAN ONE object,
        which can only happen when a never-merge blocked a union. Such a value is BY DEFINITION not
        identifying any more: the operator has said it describes two different machines, so it cannot
        name either of them.

        🔴 FOUND ON A LIVE RUN, 2026-08-20, and the offline tests could not have found it. A real
        never-merge split a genuine azure+endpoint object whose two halves BOTH carry the shared
        ExposureGraphNodeId -- which is precisely why they joined, and precisely why the operator had
        to separate them. The groups separated correctly and then both seeded from that same shared
        node id, so two distinct objects published ONE SI_CorrelationId:

            COLLISION exposuregraphnodeid:1fe344af...  engines=azure/endpoint  memberCounts=1

        A downstream connector reads that as one CI, which is the fused-CI outcome this whole design
        exists to prevent -- reached, ironically, through the mechanism for preventing it. The
        synthetic test rows gave each half its own identifiers and so could never reproduce it.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Members,
        [Parameter()][AllowNull()][hashtable] $AmbiguousIdKeys
    )

    $hasAmbiguous = ($null -ne $AmbiguousIdKeys -and $AmbiguousIdKeys.Keys.Count -gt 0)

    foreach ($type in $script:SISeedPriority) {
        $vals = @()
        foreach ($m in $Members) {
            foreach ($id in (Get-SIMemberIdentifiers -Member $m)) {
                if (-not ($id.Type -ieq $type)) { continue }
                if ($hasAmbiguous) {
                    $k = '{0}|{1}' -f (Get-SICanonicalIdType -Type $id.Type).ToLowerInvariant(), ([string]$id.Value).ToLowerInvariant()
                    # Skip, do not fall back wholesale: the group may still hold an unshared value of
                    # this same type, and that one is a perfectly good seed.
                    if ($AmbiguousIdKeys.ContainsKey($k)) { continue }
                }
                $vals += $id.Value
            }
        }
        # ORDINAL, not Sort-Object: the seed must not depend on the host's locale. See Sort-SIOrdinal.
        if ($vals.Count -gt 0) { return ('{0}:{1}' -f $type.ToLowerInvariant(), (@(Sort-SIOrdinal -Value $vals)[0])) }
    }
    # ORDINAL for the same reason -- this branch also decides an SI_CorrelationId.
    $fallback = @(Sort-SIOrdinal -Value @($Members.SIAssetId | Where-Object { $_ }))
    if ($fallback.Count -gt 0) { return ('assetid:{0}' -f $fallback[0].ToLowerInvariant()) }
    $null
}

# The exposure graph is itself a correlation PRODUCT -- Microsoft's inference, not a native key the
# source system owns. Joining through it is legitimate (it is cross-engine by construction, which is why
# it seeds the id), but a link that rests ONLY on it is an inference we inherited rather than a fact we
# verified. Everything else in SIJoinableIdTypes is a native id its own source is authoritative for.
$script:SIGraphInferredIdTypes = @('ExposureGraphNodeId')

function Get-SICorrelationJoinBasis {
    <#
        WHICH identifier types actually did the joining for this group -- not merely which are present.

        Computed after the fact from the members rather than instrumented into the union-find, so the
        proven join logic is untouched. The definition is the same either way: a type joined when two
        DISTINCT members carry the same value of it. A single-member group has no basis, because there
        was no join to be right or wrong about.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Members)

    $m = @($Members)
    if ($m.Count -lt 2) { return @() }

    # "type|value" -> the set of member INDEXES carrying it. Index, not object identity: two members can
    # be value-equal PSCustomObjects and -contains would then wrongly collapse them.
    $carriers = @{}
    for ($i = 0; $i -lt $m.Count; $i++) {
        foreach ($id in (Get-SIMemberIdentifiers -Member $m[$i])) {
            $k = '{0}|{1}' -f $id.Type.ToLowerInvariant(), $id.Value
            if (-not $carriers.ContainsKey($k)) { $carriers[$k] = @{} }
            $carriers[$k][$i] = $true
        }
    }

    $types = @{}
    foreach ($k in $carriers.Keys) {
        if ($carriers[$k].Keys.Count -ge 2) { $types[($k -split '\|', 2)[0]] = $true }
    }

    # Report the canonical spelling, so the basis of a join can never disagree with the join.
    @($types.Keys | ForEach-Object { Get-SICanonicalIdType -Type $_ } | Sort-Object -Unique)
}

function Get-SICorrelationConfidence {
    <#
        Can a connector trust this object enough to CREATE a CI from it?

        Required by the design: "some links are deterministic and some are inferred from the graph, and a
        connector creating CIs must be able to tell which" (V3-ARCHITECTURE.md 2.4). It is a statement
        about the JOIN, not about the data quality of the rows.

          single-source  -- one row. Nothing was joined, so nothing can have been fused. Trivially safe.
          deterministic  -- at least one NATIVE unique id linked the members. The source system itself
                            asserts these are the same object.
          graph-inferred -- the members are held together ONLY by an exposure-graph node id. Very likely
                            right, and it is still someone else's inference. In this tenant the device to
                            Azure-VM link rests almost entirely on it (ARM id measured 0% on endpoint
                            rows), so this is the common case here, not a rare one.

        Deliberately three named states and no number. A 0.85 would invite arithmetic nobody defined --
        the same failure that killed the tier weights, where 5 of 10 contributors ended up tied.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Members,
        [Parameter()][AllowEmptyCollection()][string[]] $JoinBasis
    )

    if (@($Members).Count -lt 2) { return 'single-source' }
    if ($null -eq $JoinBasis) { $JoinBasis = @(Get-SICorrelationJoinBasis -Members $Members) }
    $basis = @($JoinBasis)

    # A multi-member group that reports no basis would mean union-find linked rows that share nothing.
    # That cannot happen by construction -- so if it ever does, say so rather than rate it confident.
    if ($basis.Count -eq 0) { return 'unexplained' }

    foreach ($t in $basis) {
        $inferred = $false
        foreach ($g in $script:SIGraphInferredIdTypes) { if ($t -ieq $g) { $inferred = $true } }
        if (-not $inferred) { return 'deterministic' }
    }
    'graph-inferred'
}

function Get-SICorrelationReport {
    <#
        What a run should print, and what the #57.1(d)-style guard should watch. A correlation stage that
        silently fuses or splits objects is the same silent-loss class as everything else here, so the
        numbers must be visible every run rather than discoverable on request.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Groups)
    $g = @($Groups)
    [pscustomobject]@{
        Objects          = $g.Count
        Rows             = @($g | ForEach-Object { @($_.Members).Count } | Measure-Object -Sum).Sum
        CrossEngine      = @($g | Where-Object { $_.IsCrossEngine }).Count
        LargestGroup     = if ($g.Count -gt 0) { (@($g | ForEach-Object { @($_.Members).Count } | Measure-Object -Maximum).Maximum) } else { 0 }
        Unseeded         = @($g | Where-Object { -not $_.SICorrelationId }).Count
        # Confidence split. GraphInferred is the number a connector operator actually needs before
        # turning creation on: those objects are held together by someone else's inference.
        SingleSource     = @($g | Where-Object { $_.Confidence -eq 'single-source'  }).Count
        Deterministic    = @($g | Where-Object { $_.Confidence -eq 'deterministic'  }).Count
        GraphInferred    = @($g | Where-Object { $_.Confidence -eq 'graph-inferred' }).Count
        # Must stay 0. Anything here means a group was linked by something the basis cannot explain.
        Unexplained      = @($g | Where-Object { $_.Confidence -eq 'unexplained'    }).Count
    }
}
