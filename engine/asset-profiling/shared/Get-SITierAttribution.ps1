#Requires -Version 5.1
<#
    SI v3 Phase 4, step 1 -- WHY does this asset have the tier it has?

    Today the answer is unavailable. The engine reduces tier by plain MIN across whatever matched, emits
    the number, and discards the reasoning: the per-source proofs are built in memory during Classify,
    never declared in the schema, and therefore never emitted. SIRules lists what MATCHED but not what
    WON, which is a different question -- an asset with a Tier-2 software hit and a Tier-0 logon hit
    shows both, and nothing says the logon is the reason it reads Tier 0.

    WHY THIS SHIPS BEFORE THE TIER REWORK, not after. The operator's ruling (g) is that an all-Tier-0
    estate loses prioritisation unless the tier carries its reason, so reports can slice "T0 by role" vs
    "T0 by logon". None of the later Phase 4 steps -- the trust list, the reducer, retiring
    trueTierClamp -- can be reviewed by a human until the CURRENT behaviour is explainable. You cannot
    judge a change to a decision you cannot see.

    SCOPE, deliberately narrow: this DESCRIBES today's reduction. It does not change it. MIN still
    decides, exactly as before (ruling (f): a GA logon must be able to set T0). Trust ordering and the
    contradiction reducer are steps 2 and 3, and they will consume these columns rather than replace
    them.

    NO Set-StrictMode here -- measured 2026-08-12, it leaks into the caller's scope, and the profiler
    chassis chooses its own. See engine/asset-correlation/_shared/SI-CorrelationCore.ps1.
#>

# Where a tier claim can come from. ORDER MATTERS ONLY FOR TIE-BREAKING THE `SetBy` LABEL when two
# sources independently claim the same winning tier -- it is NOT a trust ranking and must not be read as
# one. The trust list is ruling (e), it is an ordered list with a `trusted` boolean, and it is step 2.
# Naming it Order rather than Weight on purpose: the numeric weights were dropped precisely because
# their semantics were undefined, which is why the aggregator was never implemented.
# The tier an endpoint gets when genuinely nothing matched. Named rather than inlined so the "is the
# default" sentence and the divergence check below cannot drift apart -- they are the same fact.
$script:SIEndpointDefaultTier = 3

$script:SITierClaimSources = @(
    # SIRules ADDED 2026-08-21, and it is the source that decides most tiers. Measured on a live
    # snapshot BEFORE it was wired: 142 of 150 endpoint rows carried SI_TierClaims = "[]" and read
    # "Tier N is the default -- no tier source matched this asset", while Stage Profile had just
    # evaluated 549 rules against those same assets. Attribution could see three legacy sources and
    # was blind to the rule engine, so it reported "nothing matched" when a rule had set the tier.
    # THREE of those rows said it while reporting TIER 0 -- and the reason branch below states the
    # endpoint default is tier 3, so the sentence contradicted itself in the same cell.
    # FeedsTier -- DOES THIS SOURCE ACTUALLY REACH THE ENGINE'S REDUCTION? It is not decoration: a
    # claim from a source nothing consumes can never equal the final tier except by coincidence, and
    # calling that "reduction and attribution have diverged" would put a false sentence on every tagged
    # asset in the estate. `$true` means the engine's MIN sees this signal; `$false` means the claim is
    # ADVISORY -- recorded, explained, and honestly labelled as not having set anything.
    @{ Key = 'SIRules';               Label = 'rule';     FeedsTier = $true;  Why = 'asset-profiling rule matched (AssetProfileBy*)' }
    # 🪤 `EndpointCatalogMatch` WAS HERE, and it could never appear. Its value came from the v2.2
    # `TierSources.EndpointCatalog` blob, and nothing in the product has written that key since the
    # class-catalog matcher was deleted -- verified by whole-repo grep: one reference, the consumer.
    # So attribution advertised a source that no asset could ever be attributed to. Removed rather
    # than demoted to FeedsTier=$false, because that flag answers "does this reach the reduction",
    # not "can this appear at all", and a source that cannot appear should not be listed.
    # 📌 It is NOT the same thing as the `endpoint_catalog_match` CONTRIBUTOR in the schema, which is
    # live and is fed by the rule engine (`SI_RuleTier`) -- that one is the `SIRules` row above. The
    # shared word "catalog" in two different places is exactly what made this hard to see.
    @{ Key = 'InstalledApplications'; Label = 'software'; FeedsTier = $true;  Why = 'privileged software detected on the asset' }
    @{ Key = 'PostureRuleTargetTier'; Label = 'posture';  FeedsTier = $true;  Why = 'posture rule target tier' }
    @{ Key = 'MostFrequentUserTier';  Label = 'logon';    FeedsTier = $true;  Why = 'tier of the most frequent interactive user' }
    # tenant_si_manual_tag ADDED 2026-08-25. The operator's tier tag, and it is LAST here for the same
    # reason it is order 10 in the trust list.
    # 🔒 OPERATOR, 2026-08-25 -- READ THIS BEFORE GROWING ANYTHING AROUND IT: *"tags are part of the
    # priority list as any other detection rule. tag is nothing special"*; *"these tags are old and NOT
    # maintained. exactly why tags have low prio"*; *"tags must continue to be used, just low prio"*.
    # So: USED, RANKED LAST, and NOT a special citizen. It gets no bespoke asymmetry and no new rule
    # files. An earlier draft of this block treated its empty column as a defect blocking Phase 4 --
    # it was not. An empty column was the ACCURATE reading of unmaintained data.
    # WHY IT PRODUCED NOTHING BEFORE: the only code that ever emitted this id lives in
    # EndpointCatalogTierComputer's Get-SITierFromEndpointDevice, which has NO production caller, so the
    # id came exclusively from dead code and diagnostics/ scripts. A real never-wired gap, but a small one.
    # The locked schema already declares the algorithm (`tag_based_tier`), the signal field
    # (`MachineTags`) and the pattern. Get-SITierFromAssetTags below implements exactly that and nothing
    # more. The Key is the SCHEMA CONTRIBUTOR ID verbatim, not a friendly name, because the trust list
    # and the reducer both key on that id -- a friendly name here would silently fail to match.
    # ✅ FeedsTier FLIPPED TO $true, 2026-08-25, in the same commit that put the reducer on the
    # production path -- which is the rule this flag exists to enforce. Build-EndpointProfileRow now
    # reduces BEFORE $ctx is built, so the tag genuinely participates in the tier: it loses to any
    # observed claim that disagrees, and sets the tier only where nothing observed has an opinion.
    # That is what "used, low prio" means operationally.
    # IDENTITY / AZURE / PUBLICIP SOURCES -- added 2026-10-04 (#244). Until then only the endpoint profiler recorded who
    # set a tier, so on the Pro tier board every identity, Azure resource and public IP read "set by (not recorded)" and
    # every wire went to that one chip. Each key below is the per-source verdict the profile row builder already holds
    # (Build-IdentityProfileRow's $perSource, the public IP's owner tier, the classification verdict); nothing is
    # recomputed here, the claims only DESCRIBE what the engine decided.
    @{ Key = 'EntraRolesPermanent';      Label = 'entra-role';      FeedsTier = $true; Why = 'a permanent Entra ID directory role' }
    @{ Key = 'EntraRolesEligible';       Label = 'entra-role';      FeedsTier = $true; Why = 'an eligible (PIM) Entra ID directory role' }
    @{ Key = 'EntraApiPermsApplication'; Label = 'api-permission';  FeedsTier = $true; Why = 'an application permission on an API (Microsoft Graph and others)' }
    @{ Key = 'AdBuiltinGroups';          Label = 'ad-group';        FeedsTier = $true; Why = 'membership of a privileged on-premises AD group' }
    @{ Key = 'AzureRoles';               Label = 'azure-role';      FeedsTier = $true; Why = 'an Azure RBAC role assignment' }
    @{ Key = 'OwnerAssetTier';           Label = 'owner';           FeedsTier = $true; Why = 'the tier of the asset this public IP belongs to' }
    @{ Key = 'ClassifyVerdict';          Label = 'classification';  FeedsTier = $true; Why = 'the classification stage verdict' }
    @{ Key = 'tenant_si_manual_tag';  Label = 'tag';      FeedsTier = $true;  Why = 'operator tier tag on the asset (MDE machine tag / EG device tag)' }
)

# The locked schema's own default for the tenant_si_manual_tag contributor, restated here so the
# fallback and the schema cannot drift apart silently when the schema cannot be read. This file is an
# AUDIT surface: it explains the tier, it never decides it, so it degrades rather than dies.
$script:SIDefaultTierTagPattern = '(?i)tier[_-]?(?<tier>[0-3])(--SI)?'

function Get-SITierFromAssetTags {
    <#
        The `tag_based_tier` algorithm the locked schema has declared since 2.3.6 and nothing ever
        implemented: read the asset's operator tags, match the declared pattern, take the tier out of
        the named capture group.

        RETURNS $null WHEN NO TAG CARRIES A TIER. "no opinion" and "claimed tier 3" are different
        statements -- returning 3 here would fabricate an asserted claim on every untagged asset in the
        estate and hand the reducer 150 assertions no human ever made.

        MIN across tags, matching the engine everywhere else (house rule: tier is MIN, and a T0 tag must
        be able to say T0). Every claimed tier is also reported so a reader can see when a tag set
        disagrees with ITSELF -- 16 of the 19 tagged assets here do.
        🔒 THAT IS TAG HYGIENE, NOT A TIER FINDING. Operator, 2026-08-25: *"these tags are old and NOT
        maintained. exactly why tags have low prio"* and *"tag is nothing special"*. Contradictory tags
        are what unmaintained data looks like -- report them, do not escalate them, and do not let this
        grow into a feature. This is ONE low-priority contributor among a dozen.

        ⚠️ THE SHIPPED PATTERN IS DELIBERATELY LOOSE, and that is not an oversight to tighten silently.
        `--SI` is OPTIONAL, so a customer's own `tier0` machine tag counts as an operator assertion too,
        which is correct: SI's tagging convention is not the only way an operator writes a tier down.
        The cost is that an unrelated tag containing the substring (`Tier2Support`) also matches. A
        customer who wants the strict form overrides `tagPattern` on the contributor in
        endpoint.schema.custom.json -- that overlay path already exists and merges contributors by id.
    #>
    param(
        # ';'-joined string (the AssetTags column shape) or an array of strings. Both occur: AssetTags
        # is a flat string, MDE_MachineTags arrives as an array before it is flattened.
        [Parameter()][AllowNull()]$Tags,
        [Parameter()][AllowNull()][string]$TagPattern
    )

    if ([string]::IsNullOrWhiteSpace($TagPattern)) { $TagPattern = $script:SIDefaultTierTagPattern }

    $list = New-Object System.Collections.Generic.List[string]
    if ($null -ne $Tags) {
        if ($Tags -is [string]) {
            foreach ($t in ($Tags -split ';')) { if (-not [string]::IsNullOrWhiteSpace($t)) { $list.Add($t.Trim()) } }
        } elseif ($Tags -is [System.Collections.IEnumerable]) {
            foreach ($t in $Tags) {
                if ($null -eq $t) { continue }
                $s = [string]$t
                if (-not [string]::IsNullOrWhiteSpace($s)) { $list.Add($s.Trim()) }
            }
        } else {
            $s = [string]$Tags
            if (-not [string]::IsNullOrWhiteSpace($s)) { $list.Add($s.Trim()) }
        }
    }
    if ($list.Count -eq 0) { return $null }

    $minTier = $null; $topMatch = ''; $count = 0
    $tiers = New-Object System.Collections.Generic.List[int]
    foreach ($tag in $list) {
        # A customer-supplied pattern that is not a valid regex must not take the run down -- and must
        # not be swallowed either, because "pattern is broken" and "no tag carries a tier" produce the
        # same empty result and only one of them is a defect.
        $m = $null
        try { $m = [regex]::Match($tag, $TagPattern) } catch {
            Write-Warning ("tier tag pattern '{0}' is not a valid regex ({1}) -- no tag claim for this asset." -f $TagPattern, $_.Exception.Message)
            return $null
        }
        if (-not $m.Success) { continue }
        $g = $m.Groups['tier']
        if (-not $g -or -not $g.Success) { continue }
        $t = $null
        try { $t = [int]$g.Value } catch { continue }
        if ($t -lt 0 -or $t -gt 3) { continue }
        $count++
        [void]$tiers.Add($t)
        if ($null -eq $minTier -or $t -lt $minTier) { $minTier = $t; $topMatch = $tag }
    }
    if ($null -eq $minTier) { return $null }

    # .ToArray() before the pipeline, never @($list) -- @() over a List[object] of PSCustomObjects
    # throws on PS 5.1 (bit TenantManager twice). Sort-Object -Unique over ints is safe.
    $distinct = @($tiers.ToArray() | Sort-Object -Unique)
    [pscustomobject]@{
        Tier         = $minTier
        TopMatch     = $topMatch
        MatchCount   = $count
        ClaimedTiers = $distinct
        # Two tags on one asset asking for two different tiers. MIN makes this SAFE today and INVISIBLE
        # tomorrow, which is why it is carried ON the claim rather than resolved away here.
        Conflicting  = ($distinct.Count -gt 1)
    }
}

function Get-SITierTagPatternFromSchema {
    <#
        The `tagPattern` the merged (locked + customer overlay) schema declares for the
        tenant_si_manual_tag contributor. Read from the schema rather than hardcoded so a customer who
        overrides it gets their pattern -- the overlay merges contributors by id and already exists.
        Falls back to the shipped default whenever the schema cannot be read.
    #>
    param([Parameter()][AllowNull()]$Schema)
    $pattern = $script:SIDefaultTierTagPattern
    try {
        if ($Schema -and $Schema.PSObject.Properties['aggregator'] -and $Schema.aggregator -and
            $Schema.aggregator.PSObject.Properties['contributors'] -and $Schema.aggregator.contributors) {
            foreach ($c in @($Schema.aggregator.contributors)) {
                if ($null -eq $c) { continue }
                if (-not $c.PSObject.Properties['id']) { continue }
                if ([string]$c.id -ne 'tenant_si_manual_tag') { continue }
                if ($c.PSObject.Properties['tagPattern'] -and -not [string]::IsNullOrWhiteSpace([string]$c.tagPattern)) {
                    $pattern = [string]$c.tagPattern
                }
                break
            }
        }
    } catch { }
    return $pattern
}

function ConvertTo-SITierClaim {
    <#
        Normalise one source's verdict into a claim: which source, what tier it asked for, and the
        evidence behind it. Returns $null when the source made no claim -- "no opinion" and "claimed
        tier 3" are different statements and must not collapse into each other.
    #>
    param(
        [Parameter(Mandatory)][string]$SourceKey,
        [Parameter()]$Verdict
    )
    if ($null -eq $Verdict) { return $null }

    $def   = @($script:SITierClaimSources | Where-Object { $_.Key -eq $SourceKey })
    $label = if ($def.Count -gt 0) { [string]$def[0].Label } else { $SourceKey }
    $why   = if ($def.Count -gt 0) { [string]$def[0].Why   } else { 'unclassified tier source' }
    # An unregistered source defaults to FEEDING. That is the direction that preserves the old
    # behaviour for anything not in the list, and it keeps a caller that passes a new key from silently
    # having its claim demoted to advisory without anyone deciding that.
    $feeds = if ($def.Count -gt 0 -and $def[0].ContainsKey('FeedsTier')) { [bool]$def[0].FeedsTier } else { $true }

    # A bare int (MostFrequentUserTier) and a verdict object (catalog/posture) both arrive here.
    $tier = $null; $top = ''; $count = 0
    if ($Verdict -is [int] -or $Verdict -is [long] -or $Verdict -is [string]) {
        if ("$Verdict" -ne '') { try { $tier = [int]$Verdict } catch { $tier = $null } }
    } else {
        if ($Verdict.PSObject.Properties['Tier'] -and $null -ne $Verdict.Tier -and "$($Verdict.Tier)" -ne '') {
            try { $tier = [int]$Verdict.Tier } catch { $tier = $null }
        }
        if ($Verdict.PSObject.Properties['TopMatch'])   { $top   = [string]$Verdict.TopMatch }
        if ($Verdict.PSObject.Properties['MatchCount']) { $count = [int]$Verdict.MatchCount }
    }
    if ($null -eq $tier) { return $null }

    # Carried through only when the source supplies them (today: tenant_si_manual_tag). A source that
    # can contradict ITSELF -- two operator tags on one asset asking for two different tiers -- is the
    # only kind that needs these. Reported as tag HYGIENE, never escalated -- the tags are unmaintained
    # and ranked last for that reason (operator, 2026-08-25).
    $claimedTiers = @()
    $conflicting  = $false
    if ($Verdict -isnot [int] -and $Verdict -isnot [long] -and $Verdict -isnot [string]) {
        if ($Verdict.PSObject.Properties['ClaimedTiers'] -and $Verdict.ClaimedTiers) { $claimedTiers = @($Verdict.ClaimedTiers) }
        if ($Verdict.PSObject.Properties['Conflicting']) { $conflicting = [bool]$Verdict.Conflicting }
    }

    [pscustomobject]@{
        Source       = $label
        SourceKey    = $SourceKey
        Tier         = $tier
        Evidence     = $top
        MatchCount   = $count
        Why          = $why
        FeedsTier    = $feeds
        ClaimedTiers = $claimedTiers
        Conflicting  = $conflicting
        # Every claim is RECORDED, including ones a future trust list will refuse (ruling (i):
        # "untrusted claims are LOGGED, never discarded"). Until step 2 exists nothing is untrusted, so
        # this is true for all of them -- but the column shape is already right, so withdrawing trust
        # later never blinds the customer to the source.
        Trusted    = $true
    }
}

function Get-SITierAttribution {
    <#
        The three "why" values for one asset.

          SI_TierSetBy   -- the source(s) whose claim equals the final tier. Plural on purpose: when a
                            catalog hit and a logon hit both say Tier 0, BOTH set it, and reporting one
                            would invent a precedence that does not exist yet.
          SI_TierReason  -- one human sentence, readable in a report cell without opening JSON.
          SI_TierClaims  -- every claim, as JSON. The audit surface, and what step 2's trust list and
                            step 3's reducer will consume.

        FinalTier is passed in rather than recomputed. Recomputing it here would create a second
        implementation of the tier decision that could silently disagree with the engine's -- the exact
        defect pattern this file exists to make visible.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$FinalTier,
        [Parameter()][hashtable]$Sources = @{},
        # An operator override replaced the computed tier (#61): who / when / why, and the tier the engine computed.
        # The override IS what set the final tier, so it is the source -- the claims stay recorded beside it.
        [Parameter()][AllowNull()][AllowEmptyString()][string]$OverrideBy,
        [Parameter()][AllowNull()]$ComputedTier,
        # The tier the default tier RULE gives this asset (Resolve-SIDefaultTier.ps1). Not passed = the shipped default.
        [Parameter()][AllowNull()]$DefaultTier = $script:SIEndpointDefaultTier
    )

    $claims = New-Object System.Collections.Generic.List[object]
    foreach ($def in $script:SITierClaimSources) {
        if (-not $Sources.ContainsKey($def.Key)) { continue }
        $c = ConvertTo-SITierClaim -SourceKey $def.Key -Verdict $Sources[$def.Key]
        if ($c) { [void]$claims.Add($c) }
    }

    $final = $null
    if ($null -ne $FinalTier -and "$FinalTier" -ne '') { try { $final = [int]$FinalTier } catch { $final = $null } }

    # 🔴 A CLAIM IS NOT NECESSARILY AN INPUT TO THE TIER, and conflating the two would put a FALSE
    # sentence on all 19 tier-tagged assets in this estate, 11 of which assert a tier the engine never
    # gave them. `tenant_si_manual_tag` is declared in the locked schema and
    # read by nothing on the production path, so an operator tag claiming T0 on an asset the engine
    # left at T3 is not a divergence between reduction and attribution -- it is an assertion the engine
    # never consumed, which is a completely different (and more useful) statement. Splitting the claims
    # keeps "who could have set this tier" separate from "who has an opinion about it".
    # Both halves are still RECORDED in SI_TierClaims (ruling (i): never discarded).
    $feeding  = @($claims | Where-Object { $_.FeedsTier })
    $advisory = @($claims | Where-Object { -not $_.FeedsTier })

    $winners = @($feeding | Where-Object { $null -ne $final -and $_.Tier -eq $final })

    $setBy = if ($winners.Count -gt 0) { (@($winners.Source | Sort-Object -Unique) -join '+') }
             elseif ($feeding.Count -eq 0) { 'default' }
             else { 'unattributed' }

    # The asserted tag that disagrees with the tier the estate actually got. This is the single most
    # useful sentence this column can carry for a security reader: it names a machine whose operator
    # label and whose observed tier do not agree.
    $advisoryNote = ''
    if ($advisory.Count -gt 0) {
        $disagreeing = @($advisory | Where-Object { $null -eq $final -or $_.Tier -ne $final })
        if ($disagreeing.Count -gt 0) {
            $a  = $disagreeing[0]
            $ev = if ($a.Evidence) { (" '{0}'" -f $a.Evidence) } else { '' }
            $advisoryNote = ' An operator {0}{1} asserts Tier {2}, which the engine does not consume -- it did not set this tier.' -f `
                $a.Source, $ev, $a.Tier
        }
    }
    # An asset whose own tags ask for two different tiers. MIN hides this completely (a T0 tag wins and
    # nothing breaks), which is why 16 of the 19 tagged assets here contradict themselves unnoticed.
    # Hygiene, not a tier finding: unmaintained tags are exactly why the tag is ranked last.
    $conflictNote = ''
    $conflicted = @($claims | Where-Object { $_.Conflicting })
    if ($conflicted.Count -gt 0) {
        $c0 = $conflicted[0]
        $conflictNote = ' CONFLICT: the {0} source claims {1} different tiers on this asset ({2}) -- the tags contradict each other.' -f `
            $c0.Source, @($c0.ClaimedTiers).Count, (@($c0.ClaimedTiers) -join ', ')
    }

    $reason =
        if ($winners.Count -gt 0) {
            $w = $winners[0]
            $ev = if ($w.Evidence) { (" ({0})" -f $w.Evidence) } else { '' }
            if ($winners.Count -gt 1) {
                'Tier {0} set by {1} -- {2}{3}; {4} independent source(s) agreed on this tier.' -f `
                    $final, $setBy, $w.Why, $ev, $winners.Count
            } else {
                'Tier {0} set by {1} -- {2}{3}.' -f $final, $setBy, $w.Why, $ev
            }
        }
        elseif ($feeding.Count -eq 0) {
            # Endpoints deliberately default to tier 3 when nothing matches, and saying so is the
            # difference between "nothing applied" and "something applied and I cannot tell what".
            #
            # 🪤 BUT "no claim was registered" IS NOT "no source matched", and asserting the second
            # from the first is how this line came to contradict itself. Before SIRules was wired in
            # (2026-08-21) three assets read "Tier 0 is the default -- no tier source matched" while
            # the default is tier 3 -- self-evidently something HAD matched and simply had no claim
            # source. A tier that is not the default proves a source acted, so say that instead of
            # inventing the negative.
            if ($null -eq $final) {
                'No tier source matched this asset and no default tier rule applies to it -- it is Unclassified until it is given a tier.'
            } elseif ($null -ne $DefaultTier -and "$DefaultTier" -ne '' -and $final -ne [int]$DefaultTier) {
                'Tier {0} was set by a source that registered no claim -- it is not the tier {1} default, so something matched and could not be attributed. Report this.' -f `
                    $final, $DefaultTier
            } else {
                'Tier {0} is the default -- no tier source matched this asset, so the default tier rule set it.' -f $final
            }
        }
        else {
            # Should not happen while MIN decides: the final tier must equal some claim. If it ever does,
            # it means the engine's reduction and the recorded claims have diverged, and saying that
            # plainly beats inventing an explanation.
            # Counts FEEDING claims, not all claims: an advisory claim not matching the tier is normal
            # and expected (it is the whole point of recording it), so including it here would report a
            # divergence that is not one.
            'Tier {0} does not match any recorded claim ({1} tier-setting claim(s) seen) -- reduction and attribution have diverged.' -f `
                $final, $feeding.Count
        }

    $reason = ($reason + $advisoryNote + $conflictNote)

    if (-not [string]::IsNullOrWhiteSpace($OverrideBy)) {
        $setBy = 'override'
        $was = ''
        if ($null -ne $ComputedTier -and "$ComputedTier" -ne '') { $was = (' The engine computed Tier {0}.' -f $ComputedTier) }
        $reason = ('Tier {0} set by an operator override ({1}).{2}' -f $final, $OverrideBy.Trim(), $was)
    }

    [pscustomobject]@{
        SI_TierSetBy  = $setBy
        SI_TierReason = $reason
        # 🪤 -InputObject over .ToArray(), NOT the pipeline. Measured on PS 5.1 (the engine host):
        # `$list | ConvertTo-Json` emits `{...}` for ONE claim and `[...]` for two or more, so this
        # column had THREE shapes -- `[]` empty, a bare object, an array -- and the single-claim shape
        # was the COMMON one (20 of 151 rows carried a claim, most of them exactly one). Any consumer
        # doing todynamic() then mv-expand breaks on the majority case. It is a JSON array or it is
        # nothing.
        SI_TierClaims = if ($claims.Count -gt 0) { (ConvertTo-Json -InputObject ([object[]]$claims.ToArray()) -Depth 4 -Compress) } else { '[]' }
        ClaimCount    = $claims.Count
        WinnerCount   = $winners.Count
    }
}

function Get-SITierVerdictValue {
    <# One property of a verdict that may be a hashtable (Classify writes one) or a PSCustomObject (read back from staging). #>
    param([Parameter()][AllowNull()]$Verdict, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Verdict) { return $null }
    if ($Verdict -is [System.Collections.IDictionary]) { if ($Verdict.Contains($Name)) { return $Verdict[$Name] } return $null }
    $p = $Verdict.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-SIProfileTierSources {
    <#
        #244 -- the tier sources of ONE identity / Azure / public IP profile row, as the -Sources map Get-SITierAttribution
        reads. Built ONLY from what the row builder already holds; nothing here decides a tier:

          SIRules          the profile rules (Verdict.SI_RuleTier = MIN across matched rules, Verdict.SI_RuleMatches),
                           with the rule that claimed the winning tier as evidence -- exactly as the endpoint builder does
          -PerSource       the engine's per-source verdicts ({ Tier; TopMatch; MatchCount }), passed through when they
                           claimed a tier (identity: Entra roles, API permissions, AD groups, Azure roles)
          ClassifyVerdict  the classification stage's own tier, ONLY where it can be told apart from the rules: the rules
                           claimed nothing, or a lower tier than the rules (Profile stage: SI_Tier = MIN(classify, rules)).
                           Skipped when -ClassifyStatus is 'catalog': the per-source verdicts ARE that classification.
          -Extra           anything else the builder knows (the public IP's owner tier)

        An absent claim stays absent: "no opinion" and "claimed tier 3" are different statements, and the T3 default is
        the absence of every claim (SI_TierSetBy = 'default').
        PS 5.1 safe. Never throws for a missing piece -- it is an audit surface.
    #>
    param(
        [Parameter()][AllowNull()]$Verdict,
        [Parameter()][hashtable]$PerSource = @{},
        [Parameter()][AllowNull()][AllowEmptyString()][string]$ClassifyStatus,
        [Parameter()][hashtable]$Extra = @{}
    )
    $sources = @{}

    $ruleTier = Get-SITierVerdictValue -Verdict $Verdict -Name 'SI_RuleTier'
    $ruleInt = $null
    if ($null -ne $ruleTier -and "$ruleTier" -ne '') { try { $ruleInt = [int]$ruleTier } catch { $ruleInt = $null } }
    if ($null -ne $ruleInt) {
        $ruleMatches = @()
        $rm = Get-SITierVerdictValue -Verdict $Verdict -Name 'SI_RuleMatches'
        if ($null -ne $rm) { $ruleMatches = @($rm) }
        $topRule = ''
        foreach ($m in $ruleMatches) {
            if ($null -eq $m) { continue }
            $mt = Get-SITierVerdictValue -Verdict $m -Name 'Tier'
            if ($null -eq $mt -or "$mt" -eq '') { continue }
            if ([int]$mt -eq $ruleInt) {
                $topRule = [string](Get-SITierVerdictValue -Verdict $m -Name 'RuleId')
                $det = [string](Get-SITierVerdictValue -Verdict $m -Name 'DetectionId')
                if ($det) { $topRule = '{0}/{1}' -f $topRule, $det }
                break
            }
        }
        $sources['SIRules'] = [pscustomobject]@{ Tier = $ruleInt; TopMatch = $topRule; MatchCount = $ruleMatches.Count }
    }

    foreach ($k in @($PerSource.Keys)) {
        $v = $PerSource[$k]
        if ($null -eq $v) { continue }
        $t = Get-SITierVerdictValue -Verdict $v -Name 'Tier'
        if ($null -eq $t -or "$t" -eq '') { continue }
        $sources[[string]$k] = $v
    }

    if ([string]$ClassifyStatus -ne 'catalog') {
        $siTier = Get-SITierVerdictValue -Verdict $Verdict -Name 'SI_Tier'
        $ct = $null
        if ($null -ne $siTier -and "$siTier" -ne '') { try { $ct = [int]$siTier } catch { $ct = $null } }
        if ($null -ne $ct -and ($null -eq $ruleInt -or $ct -lt $ruleInt)) {
            $sources['ClassifyVerdict'] = [pscustomobject]@{ Tier = $ct; TopMatch = [string]$ClassifyStatus; MatchCount = 1 }
        }
    }

    foreach ($k in @($Extra.Keys)) { if ($null -ne $Extra[$k]) { $sources[[string]$k] = $Extra[$k] } }
    $sources
}

function Set-SIProfileTierAttribution {
    <#
        #244 -- writes SI_TierSetBy / SI_TierReason / SI_TierClaims onto one profile row (an ordered hashtable), from
        Get-SITierAttribution over -Sources. The columns are ALWAYS written ('' / '' / '[]' when attribution fails):
        a column that sometimes exists breaks consumers at query time. Never lets the explanation cost the row.
    #>
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Row,
        [Parameter(Mandatory)][AllowNull()]$FinalTier,
        [Parameter()][hashtable]$Sources = @{},
        # the default tier rule's tier for this asset (Resolve-SIDefaultTier.ps1); not passed = the shipped default
        [Parameter()][AllowNull()]$DefaultTier = $script:SIEndpointDefaultTier
    )
    $Row['SI_TierSetBy']  = ''
    $Row['SI_TierReason'] = ''
    $Row['SI_TierClaims'] = '[]'
    try {
        $attr = Get-SITierAttribution -FinalTier $FinalTier -Sources $Sources -DefaultTier $DefaultTier
        $Row['SI_TierSetBy']  = [string]$attr.SI_TierSetBy
        $Row['SI_TierReason'] = [string]$attr.SI_TierReason
        $Row['SI_TierClaims'] = [string]$attr.SI_TierClaims
    } catch {
        Write-Warning ("tier attribution failed for this asset ({0}) -- columns left empty; the tier itself is unaffected." -f $_.Exception.Message)
    }
}
