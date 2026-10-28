#Requires -Version 5.1
<#
    SI v3 Phase 4 -- THE OPERATOR'S TIER TAG. One low-priority contributor among a dozen.

    🔒 OPERATOR, 2026-08-25 -- the framing that governs this whole file: *"tags are part of the priority
    list as any other detection rule. tag is nothing special, why do we talk so much about it?"*;
    *"these tags are old and NOT maintained. exactly why tags have low prio"*; *"tags must continue to
    be used, just low prio"*.
    So the tag is USED and RANKED LAST. It is not a special citizen, it gets no bespoke mechanism, and
    it needs no new rule files.

    `tenant_si_manual_tag` has been declared in endpoint.schema.locked.json since 2.3.6 -- algorithm
    (`tag_based_tier`), signal field (`MachineTags`), regex -- and nothing on the production path ever
    produced it: its only producer lived inside Get-SITierFromEndpointDevice, which had no caller and was DELETED as #87 on 2026-08-31. A
    real never-wired gap, and a SMALL one.

    🪤 AN EARLIER DRAFT OF THIS FILE GOT THE SIGNIFICANCE WRONG, and that is worth keeping. It read the
    empty column as a defect blocking Phase 4, and wrote up the contradictions as a customer-facing
    data-quality finding. Neither is true: an empty column was the ACCURATE reading of unmaintained
    data, and contradictory tags are what decay looks like in a signal nobody maintains -- which is the
    reason it is ranked last, not a reason to escalate it.

    📌 SCALE, measured read-only against the live snapshot 2026-08-25 (162 rows). 105 assets carry SOME
    `--SI` tag, but 87 are `--Excluded--SI` -- the RA opt-out, nothing to do with tiering. **19** carry
    a tier tag; the earlier "90 of 150" counted the wrong tag and overstated it about five-fold.

    🔒 THIS LAYER DOES NOT DECIDE THE TIER, and several tests below exist only to pin that. The claim is
    recorded and explained; MIN still decides, and the tag is marked FeedsTier=$false because no
    production code consumes it yet -- that describes today, not the destination.
#>

BeforeAll {
    $root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    . (Join-Path $root '..\engine\asset-profiling\shared\Get-SITierAttribution.ps1')
    $script:SIRootDir = (Resolve-Path (Join-Path $root '..')).Path
}

Describe 'Get-SITierFromAssetTags -- the tag_based_tier algorithm the schema declared and nobody built' {

    It 'reads the tier out of an --SI tag' {
        $r = Get-SITierFromAssetTags -Tags 'AutomationServer--tier0--SI'
        $r.Tier        | Should -Be 0
        $r.TopMatch    | Should -BeExactly 'AutomationServer--tier0--SI'
        $r.MatchCount  | Should -Be 1
        $r.Conflicting | Should -BeFalse
    }

    It 'accepts the AssetTags column shape -- a semicolon-joined string' {
        # AssetTags is the deduped union of MDE machine tags + EG manual + EG dynamic, flattened to one
        # string. That is the shape the row builder actually holds, so it is the shape under test.
        $r = Get-SITierFromAssetTags -Tags 'Finance;EmployeeWorkstations--tier2--SI;Managed'
        $r.Tier | Should -Be 2
    }

    It 'accepts an array of tags too -- MDE_MachineTags arrives unflattened' {
        $r = Get-SITierFromAssetTags -Tags @('Managed', 'PAWDevices--tier0--SI')
        $r.Tier | Should -Be 0
    }

    It '🔑 returns null when NO tag carries a tier -- "no opinion" is not "tier 3"' {
        # The single most important behaviour here. Returning 3 would fabricate an asserted claim on
        # every ordinary asset in the estate and hand the reducer 150 assertions no human ever made.
        Get-SITierFromAssetTags -Tags 'Finance;Managed;Windows' | Should -BeNullOrEmpty
        Get-SITierFromAssetTags -Tags ''                        | Should -BeNullOrEmpty
        Get-SITierFromAssetTags -Tags $null                     | Should -BeNullOrEmpty
        Get-SITierFromAssetTags -Tags @()                       | Should -BeNullOrEmpty
    }

    It 'MIN across tags, and TopMatch names the tag that won' {
        $r = Get-SITierFromAssetTags -Tags 'ServerBusinessServices--tier2--SI;DomainControllerDNS--tier0--SI'
        $r.Tier     | Should -Be 0
        $r.TopMatch | Should -BeExactly 'DomainControllerDNS--tier0--SI'
    }

    It 'flags an asset whose OWN TAGS claim two different tiers -- 16 of 19 tagged assets do' {
        # MIN hides this completely: a T0 tag wins and nothing breaks. The conflict rides on the claim so
        # a reader can see it.
        # 🔒 TAG HYGIENE, NOT A TIER FINDING (operator, 2026-08-25: the tags are old and unmaintained,
        # which is exactly why the tag is ranked last). Do not grow a report out of this.
        $r = Get-SITierFromAssetTags -Tags 'PAWDevices--tier0--SI;EmployeeWorkstations--tier3--SI'
        $r.Tier            | Should -Be 0
        $r.Conflicting     | Should -BeTrue
        @($r.ClaimedTiers) | Should -Be @(0, 3)
        $r.MatchCount      | Should -Be 2
    }

    It 'agreeing tags are corroboration, not conflict' {
        $r = Get-SITierFromAssetTags -Tags 'DomainControllerDNS--tier0--SI;EntraSyncService--tier0--SI'
        $r.Conflicting           | Should -BeFalse
        @($r.ClaimedTiers).Count | Should -Be 1
        $r.MatchCount            | Should -Be 2
    }

    It 'the --SI suffix is OPTIONAL -- a customer who writes their own tier tag is asserting too' {
        (Get-SITierFromAssetTags -Tags 'tier0').Tier  | Should -Be 0
        (Get-SITierFromAssetTags -Tags 'Tier-1').Tier | Should -Be 1
        (Get-SITierFromAssetTags -Tags 'TIER_2').Tier | Should -Be 2
    }

    It '⚠️ pins the KNOWN looseness of the shipped pattern rather than pretending it is tight' {
        # `Tier2Support` matching is a real consequence of an optional `--SI`, it is deliberate, and it
        # is overridable per customer via the contributor overlay. Pinning it means a future tightening
        # is a decision someone makes, not a silent behaviour change.
        (Get-SITierFromAssetTags -Tags 'Tier2Support').Tier | Should -Be 2
    }

    It 'ignores an out-of-range capture instead of emitting a nonsense tier' {
        Get-SITierFromAssetTags -Tags 'tier9' | Should -BeNullOrEmpty
    }

    It 'a custom pattern is honoured' {
        # The strict form a customer would write to stop `Tier2Support` matching.
        $strict = '(?i)--tier(?<tier>[0-3])--SI\b'
        (Get-SITierFromAssetTags -Tags 'EmployeeWorkstations--tier3--SI' -TagPattern $strict).Tier | Should -Be 3
        Get-SITierFromAssetTags -Tags 'Tier2Support' -TagPattern $strict | Should -BeNullOrEmpty
    }

    It '🔴 a broken customer regex WARNS and yields no claim -- it never takes the run down' {
        # Attribution is an audit surface. Throwing here would trade a complete endpoint inventory for
        # an explanatory column, which is never the right trade.
        $r = Get-SITierFromAssetTags -Tags 'x--tier0--SI' -TagPattern '(?<tier>[0-3]' -WarningAction SilentlyContinue
        $r | Should -BeNullOrEmpty
    }

    It 'a valid pattern with no tier capture group yields no claim, and does not throw' {
        { Get-SITierFromAssetTags -Tags 'x--tier0--SI' -TagPattern 'tier[0-3]' } | Should -Not -Throw
        Get-SITierFromAssetTags -Tags 'x--tier0--SI' -TagPattern 'tier[0-3]' | Should -BeNullOrEmpty
    }
}

Describe 'Get-SITierTagPatternFromSchema -- the pattern comes from the schema, not from a constant' {

    It 'reads tagPattern off the tenant_si_manual_tag contributor' {
        $schema = [pscustomobject]@{ aggregator = [pscustomobject]@{ contributors = @(
            [pscustomobject]@{ id = 'endpoint_catalog_match' },
            [pscustomobject]@{ id = 'tenant_si_manual_tag'; tagPattern = '(?i)ZZZ(?<tier>[0-3])' }
        ) } }
        Get-SITierTagPatternFromSchema -Schema $schema | Should -BeExactly '(?i)ZZZ(?<tier>[0-3])'
    }

    It 'falls back to the shipped default when the schema cannot be read' {
        Get-SITierTagPatternFromSchema -Schema $null                | Should -Match 'tier'
        Get-SITierTagPatternFromSchema -Schema ([pscustomobject]@{}) | Should -Match 'tier'
    }

    It '🔑 THE SHIPPED DEFAULT AND THE LOCKED SCHEMA AGREE -- they are two copies of one fact' {
        # The constant in Get-SITierAttribution.ps1 exists only as a degrade-do-not-die fallback. If it
        # drifts from the schema, the fallback silently applies a DIFFERENT rule than the declared one.
        $locked = Get-Content (Join-Path $script:SIRootDir 'asset-profiling-schema\endpoint.schema.locked.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $c = @($locked.aggregator.contributors | Where-Object { $_.id -eq 'tenant_si_manual_tag' })
        $c.Count | Should -Be 1
        Get-SITierTagPatternFromSchema -Schema $null | Should -BeExactly ([string]$c[0].tagPattern)
    }

    It 'the locked contributor is still declared asserted -- the reducer keys on that' {
        $locked = Get-Content (Join-Path $script:SIRootDir 'asset-profiling-schema\endpoint.schema.locked.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $c = @($locked.aggregator.contributors | Where-Object { $_.id -eq 'tenant_si_manual_tag' })
        [string]$c[0].kind | Should -BeExactly 'asserted'
    }
}

Describe 'the tag claim inside attribution -- recorded, explained, and NOT credited with the tier' {

    It '✅ ARMED -- an AGREEING tag is credited alongside the rule, because it does not yield to agreement' {
        # Before arming this asserted SetBy = 'rule' alone, since nothing consumed the tag. Now both
        # claim Tier 0 and neither is suppressed: stage 2b only makes an assertion yield when an
        # observation DISAGREES with it. The schema's own contributor comment says the same --
        # "It does NOT yield to agreement."
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{
            SIRules              = [pscustomobject]@{ Tier = 0; TopMatch = 'ADDomainController'; MatchCount = 1 }
            tenant_si_manual_tag = (Get-SITierFromAssetTags -Tags 'DomainControllerDNS--tier0--SI')
        }
        $a.SI_TierSetBy  | Should -BeExactly 'rule+tag'
        $a.WinnerCount   | Should -Be 2
        $a.SI_TierClaims | Should -Match 'tenant_si_manual_tag'
    }

    It '✅ ARMED 2026-08-25 -- a tag-only asset is now attributed TO THE TAG' {
        # Before arming, the tag was recorded and not consumed, so this same case read "Tier 3 is the
        # default" plus an advisory note. Now the reducer runs on the production path: with no observed
        # claim to disagree, the tag SETS the tier, and attribution says so.
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{
            tenant_si_manual_tag = (Get-SITierFromAssetTags -Tags 'AutomationServer--tier0--SI')
        }
        $a.SI_TierSetBy  | Should -BeExactly 'tag'
        $a.SI_TierReason | Should -Not -Match 'diverged'
        $a.SI_TierReason | Should -Match 'AutomationServer--tier0--SI'
    }

    It '🔴 an OBSERVED claim that disagrees keeps the credit -- the tag yields, and is not named as setter' {
        # observed-beats-asserted, seen from the attribution side. STRV-MOK-LT-06 is the live case:
        # tagged --tier2--SI, logon observed T0. The tag must not appear as a setter of Tier 0.
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{
            MostFrequentUserTier = 0
            tenant_si_manual_tag = (Get-SITierFromAssetTags -Tags 'EmployeeWorkstations--tier2--SI')
        }
        $a.SI_TierSetBy  | Should -BeExactly 'logon'
        $a.SI_TierClaims | Should -Match 'tenant_si_manual_tag'   # still RECORDED (ruling (i))
    }

    It 'the divergence sentence still fires on a GENUINE inconsistency' {
        # Now that every claim source feeds the tier, a final tier matching no claim really is a
        # divergence between the engine and the recorded claims -- which is what the branch is for.
        $a = Get-SITierAttribution -FinalTier 1 -Sources @{
            tenant_si_manual_tag = (Get-SITierFromAssetTags -Tags 'x--tier2--SI')
        }
        $a.SI_TierReason | Should -Match 'diverged'
    }

    It 'names the contradiction when the tags disagree with each other' {
        $a = Get-SITierAttribution -FinalTier 3 -Sources @{
            tenant_si_manual_tag = (Get-SITierFromAssetTags -Tags 'PAWDevices--tier0--SI;EmployeeWorkstations--tier3--SI')
        }
        $a.SI_TierReason | Should -Match 'CONFLICT'
        $a.SI_TierReason | Should -Match '0, 3'
    }

    It 'an agreeing single tag produces no CONFLICT noise' {
        $a = Get-SITierAttribution -FinalTier 3 -Sources @{
            tenant_si_manual_tag = (Get-SITierFromAssetTags -Tags 'EmployeeWorkstations--tier3--SI')
        }
        $a.SI_TierReason | Should -Not -Match 'CONFLICT'
    }

    It 'a genuine divergence is still reported -- the FeedsTier split did not disarm it' {
        $a = Get-SITierAttribution -FinalTier 1 -Sources @{
            SIRules = [pscustomobject]@{ Tier = 2; TopMatch = 'SomeRule'; MatchCount = 1 }
        }
        $a.SI_TierReason | Should -Match 'diverged'
    }
}

Describe '🪤 SI_TierClaims IS A JSON ARRAY -- in every case, including one claim' {
    <#
        Measured on PS 5.1, the engine host: `$list | ConvertTo-Json` emits `{...}` for ONE element and
        `[...]` for two or more. The column therefore had THREE shapes -- `[]`, a bare object, an array
        -- and the single-claim shape was the COMMON one (20 of 151 rows carried a claim, most exactly
        one). Any consumer doing todynamic() then mv-expand breaks on the majority case.

        🪤 AND THE FIRST DRAFT OF THESE TESTS PROVED NOTHING. `@($json | ConvertFrom-Json).Count` is
        ALWAYS 1 on PS 5.1: ConvertFrom-Json emits a JSON array as a SINGLE object instead of
        enumerating it, so @() wraps one item however many elements it holds. The one-claim case passed
        for a reason unrelated to what it guards. Count off the parsed value directly --
        (ConvertFrom-Json $x).Count -- never off a pipeline-wrapped one.
    #>

    It 'one claim still serialises as an array' {
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{ MostFrequentUserTier = 0 }
        $a.ClaimCount    | Should -Be 1
        $a.SI_TierClaims | Should -Match '^\['
        (ConvertFrom-Json $a.SI_TierClaims).Count | Should -Be 1
    }

    It 'two claims serialise as an array' {
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{
            MostFrequentUserTier = 0
            SIRules              = [pscustomobject]@{ Tier = 0; TopMatch = 'R'; MatchCount = 1 }
        }
        $a.SI_TierClaims | Should -Match '^\['
        (ConvertFrom-Json $a.SI_TierClaims).Count | Should -Be 2
    }

    It 'no claim is the empty array, not null and not an empty object' {
        (Get-SITierAttribution -FinalTier 3 -Sources @{}).SI_TierClaims | Should -BeExactly '[]'
    }
}

Describe 'IS THIS ON THE PRODUCTION PATH? -- the question six never-wired defects went unasked' {
    <#
        AssetName, $zeroSkipCount, #61's loader, the row-builder override, the endpoint class catalog
        and tenant_si_manual_tag itself: all declared, all green in their own tests, none reachable.
        Wiring is not a property of the unit under test, so it is asserted here separately. This is the
        template from SIv3-EndpointCatalogMerge.Tests.ps1, inverted: that one pins that dead code is
        still dead, this one pins that live code is still live.
    #>

    BeforeAll {
        $script:ProdPs1 = @(Get-ChildItem -Path (Join-Path $script:SIRootDir 'engine') -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue)
        function script:CallersOf {
            param([string]$Name, [string]$ExcludeLeaf)
            $hits = @()
            foreach ($f in $script:ProdPs1) {
                if ($ExcludeLeaf -and $f.Name -eq $ExcludeLeaf) { continue }
                $code = (Get-Content $f.FullName -Raw) -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }
                if (($code -join "`n") -match [regex]::Escape($Name)) { $hits += $f.Name }
            }
            $hits
        }
    }

    It '🔑 Get-SITierFromAssetTags HAS a production caller' {
        $callers = script:CallersOf -Name 'Get-SITierFromAssetTags' -ExcludeLeaf 'Get-SITierAttribution.ps1'
        $callers | Should -Contain 'Build-EndpointProfileRow.ps1'
    }

    It '🔑 the caller passes the SCHEMA pattern, not the hardcoded fallback' {
        $code = Get-Content (Join-Path $script:SIRootDir 'engine\asset-profiling\shared\Build-EndpointProfileRow.ps1') -Raw
        $code | Should -Match 'Get-SITierFromAssetTags\s+-Tags\s+\$row\[.AssetTags.\]\s+-TagPattern\s+\(Get-SITierTagPatternFromSchema'
    }

    It 'the source is registered under the SCHEMA CONTRIBUTOR ID, or the trust list will never match it' {
        @($script:SITierClaimSources | Where-Object { $_.Key -eq 'tenant_si_manual_tag' }).Count | Should -Be 1
    }

    It '✅ ARMED -- the tag now FEEDS the tier (FeedsTier true)' {
        # This test previously asserted $false and was written to FAIL the day the reducer reached
        # production, so the flag could not be left behind. It did exactly that; this is the other half.
        $d = @($script:SITierClaimSources | Where-Object { $_.Key -eq 'tenant_si_manual_tag' })[0]
        $d.FeedsTier | Should -BeTrue
    }

    It '🔑 THE REDUCER IS ON THE PRODUCTION PATH -- its only caller used to be dead code' {
        # Resolve-SITierClaims had exactly one caller, Get-SITierFromEndpointDevice, which had no caller
        # of its own -- so the reducer could never execute. Build-EndpointProfileRow now calls it.
        script:CallersOf -Name 'Resolve-SITierClaims' -ExcludeLeaf 'Resolve-SITierClaims.ps1' |
            Should -Contain 'Build-EndpointProfileRow.ps1'
    }

    It '🔴 the reduction happens BEFORE $ctx is built -- not as a row override' {
        # THE POSITION IS THE DESIGN. $ctx.AggregatedTier feeds the field loop that emits `Tier`, so
        # reducing afterwards would mean overwriting $row['Tier'] -- the exact defect shape this codebase
        # already shipped (an override that moved $aggTier while the published row kept the old tier).
        # Asserted textually because it is an ORDERING property: no unit test of either half can see it.
        $code = Get-Content (Join-Path $script:SIRootDir 'engine\asset-profiling\shared\Build-EndpointProfileRow.ps1') -Raw
        $iReduce = $code.IndexOf('Resolve-SITierClaims -Claims $rClaims')
        $iCtx    = $code.IndexOf('AggregatedTier    = $aggTier')
        $iReduce | Should -BeGreaterThan 0
        $iCtx    | Should -BeGreaterThan 0
        $iReduce | Should -BeLessThan $iCtx -Because 'the reduction must run before $ctx captures the tier'
    }

    It '🔴 the REDUCER does not overwrite $row[Tier] -- and the one place that does still pairs it with $aggTier' {
        # The negative half the earlier override defect needed. There IS exactly one legitimate late
        # write to $row['Tier'] -- #61's operator decision override -- and it is legitimate precisely
        # BECAUSE it moves $aggTier and the row together. The defect was updating one without the other.
        # The reducer must add no second one: it runs before $ctx, so it has nothing to correct.
        $code = Get-Content (Join-Path $script:SIRootDir 'engine\asset-profiling\shared\Build-EndpointProfileRow.ps1') -Raw
        $writes = [regex]::Matches($code, "\`$row\['Tier'\]\s*=")
        $writes.Count | Should -Be 1 -Because 'only the operator-decision override may write Tier late'

        # And that single write must sit inside the override block, next to its $aggTier assignment --
        # asserted by proximity because the pairing is what makes it safe, not the assignment itself.
        $i = $code.IndexOf("`$row['Tier'] = `$newTier")
        $i | Should -BeGreaterThan 0
        $window = $code.Substring([Math]::Max(0, $i - 1200), [Math]::Min(1200, $i))
        $window | Should -Match '\$aggTier\s*=\s*\$newTier'
    }

    It 'the tag union has ONE definition -- the reduction and the AssetTags column read the same tags' {
        # Two copies would let the emitted column and the tier disagree about which tags an asset has,
        # which is not debuggable from the output.
        $code = Get-Content (Join-Path $script:SIRootDir 'engine\asset-profiling\shared\Build-EndpointProfileRow.ps1') -Raw
        ([regex]::Matches($code, 'function Get-SIAssetTagUnion')).Count | Should -Be 1
        ([regex]::Matches($code, 'Get-SIAssetTagUnion -Meta')).Count    | Should -BeGreaterThan 1
    }
}
