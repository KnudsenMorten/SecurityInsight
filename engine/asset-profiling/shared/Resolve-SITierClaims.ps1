#Requires -Version 5.1
<#
    SI v3 Phase 4, step 3 -- THE REDUCER.

    Four stages, in this order (ruling (k), and the order is not negotiable):

      1. ADMISSIBILITY   -- a claim from an untrusted source may not set the tier. It is still RECORDED
                            (ruling (i): "untrusted claims are LOGGED, never discarded"), so withdrawing
                            trust never blinds the customer to the source.
      2. CONTRADICTION   -- when two admissible sources answer the SAME QUESTION differently, the one
                            higher in the trust list wins. Retained because it is the right shape for a
                            genuine same-question contradiction -- but it is NOT the shape of the
                            operator's rule, and it stays unused by default. See stage 2b.
      2b. OBSERVED BEATS ASSERTED -- an ASSERTED claim (a human wrote it down) yields when an OBSERVED
                            claim (the estate demonstrated it) disagrees. Observed claims NEVER suppress
                            each other. This is the operator's actual rule.
      3. MIN             -- across INDEPENDENT facts, the lowest tier wins, unchanged. SQL installed AND
                            a GA logging in are different questions, both true, and the asset is Tier 0
                            because of the pair. Ruling (f): a GA logon MUST be able to set T0.

    🔑 WHY STAGE 2b EXISTS AND STAGE 2 DOES NOT CARRY THIS RULE. Modelling "observed beats asserted" as
    a shared `question` was built, measured and rejected TWICE on 2026-08-12:

      * The broad grouping ("what kind of machine is this" = catalog + posture + EG + tag) changed 78 of
        720 enumerated combinations and ALL 78 were LESS critical, including
        `endpoint_catalog_match(T2) vs posture_rule_target_tier(T0) -> T2`. A posture rule that DETECTED
        Tier 0, discarded because the catalog outranks it -- ruling (f) inverted.
      * The narrow grouping (tag + the three observed sources) still let `endpoint_eg_criticality` (12)
        and `posture_rule_target_tier` (6) be suppressed.

    The defect is that a shared question label is SYMMETRIC: every member can suppress every other. The
    operator's rule is ASYMMETRIC -- only the assertion yields. Catalog, posture rules and EG criticality
    are independent DETECTIONS that happen to describe the same subject, not competing answers to one
    question, so they must stay independent and reach MIN.

    🔒 INERT UNTIL THE SCHEMA DECLARES KINDS. `Kind` defaults to `observed` for every contributor, and an
    observed claim is never suppressed and never suppresses -- so with nothing declared this reduces
    byte-identically to today's plain MIN. Arming = declaring `"kind": "asserted"` on the sources that
    are assertions. RUN `diagnostics/Measure-SITierReducerImpact.ps1` BEFORE AND AFTER ANY SUCH CHANGE.

    🔒 THE ACCEPTANCE BAR, corrected: NOT "zero less-critical changes" -- that would forbid the feature
    outright, since the stale-tag case (tag asserts T0, observation says T3 workstation) is inherently a
    less-critical change and is the entire point. The bar is: **every less-critical change must have the
    ASSERTED claim as the suppressed one.** The measurement script reports the suppressed source per
    change, which is the number to check.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>

function Resolve-SITierClaims {
    <#
        Reduce tier claims to one tier, and explain the reduction.

        Returns the tier plus the trail: which claims were admitted, which were suppressed as
        contradicted, and which were excluded as untrusted. The trail is the point -- a reducer whose
        output cannot be explained is exactly what the aggregator was, and why it was never trusted
        enough to implement.
    #>
    param(
        # Each: @{ SourceId; Tier; Evidence }  -- SourceId matches a trust-list Id.
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Claims,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$TrustList,
        [Parameter()][int]$DefaultTier = 3
    )

    $all = @($Claims | Where-Object { $null -ne $_ })
    if ($all.Count -eq 0) {
        return [pscustomobject]@{
            Tier = $DefaultTier; SetBy = @(); Admitted = @(); Untrusted = @(); Contradicted = @()
            Explanation = ('No claim -- default tier {0}.' -f $DefaultTier)
        }
    }

    # ---- stage 1: admissibility -------------------------------------------------------------------
    $untrusted = New-Object System.Collections.Generic.List[object]
    $admitted  = New-Object System.Collections.Generic.List[object]
    foreach ($c in $all) {
        if (Test-SITierSourceTrusted -TrustList $TrustList -Id ([string]$c.SourceId)) { [void]$admitted.Add($c) }
        else { [void]$untrusted.Add($c) }
    }

    # ---- stage 2: contradiction, by declared question ---------------------------------------------
    # Sources with no declared question are INDEPENDENT by definition -- which is why the inert default
    # (no questions declared) reduces to plain MIN.
    $contradicted = New-Object System.Collections.Generic.List[object]
    $survivors    = New-Object System.Collections.Generic.List[object]
    $byQuestion   = @{}
    foreach ($c in $admitted) {
        $q = Get-SITierClaimQuestion -TrustList $TrustList -Id ([string]$c.SourceId)
        if ([string]::IsNullOrWhiteSpace($q)) { [void]$survivors.Add($c); continue }
        if (-not $byQuestion.ContainsKey($q)) { $byQuestion[$q] = New-Object System.Collections.Generic.List[object] }
        [void]$byQuestion[$q].Add($c)
    }
    foreach ($q in @($byQuestion.Keys)) {
        $group = $byQuestion[$q].ToArray()      # .ToArray(), not @() -- see the trap note below
        if ($group.Count -eq 1) { [void]$survivors.Add($group[0]); continue }
        # All claims agreeing is NOT a contradiction -- it is corroboration, and suppressing the
        # duplicates would lose the fact that several sources concurred.
        $distinctTiers = @($group.Tier | Sort-Object -Unique)
        if ($distinctTiers.Count -le 1) { foreach ($g in $group) { [void]$survivors.Add($g) } ; continue }
        # Genuine contradiction: same question, different answers. Position decides -- lowest rank wins.
        $best = $null; $bestRank = [int]::MaxValue
        foreach ($g in $group) {
            $rank = Get-SITierTrustRank -TrustList $TrustList -Id ([string]$g.SourceId)
            if ($rank -lt $bestRank) { $bestRank = $rank; $best = $g }
        }
        foreach ($g in $group) {
            if ($g -eq $best) { [void]$survivors.Add($g) } else { [void]$contradicted.Add($g) }
        }
    }

    # ---- stage 2b: OBSERVED BEATS ASSERTED --------------------------------------------------------
    # The operator's actual rule, and the only contradiction the rulings genuinely name: a stale tag
    # says "workstation", graph detection says "domain controller". The tag is an ASSERTION -- only ever
    # as good as the process that maintains it -- and it YIELDS when observation disagrees.
    #
    # 🔑 THE ASYMMETRY IS THE WHOLE POINT. Observed detections never suppress each other: a catalog
    # match, a posture rule and an EG criticality are independent facts that happen to describe the same
    # machine, so they stay independent and go to MIN. Modelling this as a shared `question` was
    # measured wrong twice, because a shared label is SYMMETRIC -- it let the catalog suppress a posture
    # rule that had detected Tier 0, which is ruling (f) inverted.
    #
    # An assertion is suppressed only when some observed claim DISAGREES with it. Agreement is
    # corroboration, not contradiction, and suppressing a corroborating tag would lose the fact that the
    # operator's own label concurred.
    #
    # 🔒 Note where this can and cannot move the tier. If the assertion is not the minimum, MIN already
    # ignores it and suppression changes nothing. The only outcome that moves is "the tag alone was
    # holding the tier down" -- tag says T0, observation says T3 workstation -- which is exactly the
    # stale-tag case the rule exists for, and it is inherently a LESS-critical change. That is why the
    # acceptance bar is not "zero less-critical changes" (which would forbid the feature outright) but
    # "every less-critical change must have the ASSERTED claim as the suppressed one".
    $observedClaims = New-Object System.Collections.Generic.List[object]
    $assertedClaims = New-Object System.Collections.Generic.List[object]
    foreach ($s in $survivors) {
        if ((Get-SITierClaimKind -TrustList $TrustList -Id ([string]$s.SourceId)) -eq 'asserted') { [void]$assertedClaims.Add($s) }
        else { [void]$observedClaims.Add($s) }
    }
    if ($assertedClaims.Count -gt 0 -and $observedClaims.Count -gt 0) {
        $survivors = New-Object System.Collections.Generic.List[object]
        foreach ($o in $observedClaims) { [void]$survivors.Add($o) }
        foreach ($a in $assertedClaims) {
            $disagrees = $false
            foreach ($o in $observedClaims) {
                if ([int]$o.Tier -ne [int]$a.Tier) { $disagrees = $true; break }
            }
            if ($disagrees) { [void]$contradicted.Add($a) } else { [void]$survivors.Add($a) }
        }
    }

    # ---- stage 3: MIN across whatever survived ----------------------------------------------------
    # UNCHANGED, and deliberately so. Ruling (f): "Better to set all servers to tier 0 ... we cannot
    # overrule that, as we need to prioritise tier 0 over tier 1." Trust decides who gets a VOTE and
    # settles contradictions; SEVERITY still decides across independent facts.
    if ($survivors.Count -eq 0) {
        $tier = $DefaultTier
        $setBy = @()
    } else {
        $tier  = (@($survivors.Tier | Measure-Object -Minimum).Minimum)
        $setBy = @($survivors | Where-Object { $_.Tier -eq $tier } | ForEach-Object { [string]$_.SourceId } | Sort-Object -Unique)
    }

    $bits = New-Object System.Collections.Generic.List[string]
    [void]$bits.Add(('Tier {0} by MIN across {1} admissible claim(s)' -f $tier, $survivors.Count))
    if ($contradicted.Count -gt 0) { [void]$bits.Add(('{0} suppressed as contradicted' -f $contradicted.Count)) }
    if ($untrusted.Count -gt 0)    { [void]$bits.Add(('{0} excluded as untrusted (still recorded)' -f $untrusted.Count)) }

    # 🪤 .ToArray(), NOT @(...). Wrapping a List[object] of PSCustomObjects with @() throws
    # "ArgumentException: Argument types do not match" -- a known trap in this codebase that has now
    # bitten a third component. Same failure hid inside the trust list earlier in this session.
    [pscustomobject]@{
        Tier         = $tier
        SetBy        = $setBy
        Admitted     = $survivors.ToArray()
        Untrusted    = $untrusted.ToArray()
        Contradicted = $contradicted.ToArray()
        Explanation  = (($bits -join '; ') + '.')
    }
}

function Get-SITierClaimQuestion {
    <#
        Which question does this source answer? Empty means "not classified", which means INDEPENDENT --
        the safe default, because treating two independent facts as contradicting would SUPPRESS a true
        signal, and that is the mistake the operator has already had to correct twice in this area.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$TrustList,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Id
    )
    foreach ($e in @($TrustList)) {
        if ($e.Id -ieq $Id) {
            if ($e.PSObject.Properties['Question'] -and $e.Question) { return [string]$e.Question }
            return ''
        }
    }
    ''
}
