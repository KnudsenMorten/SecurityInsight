#Requires -Version 5.1
<#
    SI v3 Phase 4 step 3 -- the reducer: admissibility, then contradiction, then MIN.

    The two tests that matter most are the ones pinning what must NOT change:
      * MIN still decides across INDEPENDENT facts (ruling (f) -- a GA logon must be able to set T0).
      * The reducer ships INERT: with the locked default, which declares no questions, the result is
        identical to today's plain MIN.
    Two earlier drafts of this area were corrected by the operator -- one clamped the logon signal, one
    made it advisory -- and both suppressed a true signal. These tests exist so a third attempt fails
    here rather than in a customer's tier histogram.
#>

BeforeAll {
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $root 'engine\asset-profiling\shared\Get-SITierTrustList.ps1')
    . (Join-Path $root 'engine\asset-profiling\shared\Resolve-SITierClaims.ps1')
    $script:Schema = Get-Content (Join-Path $root 'asset-profiling-schema\endpoint.schema.locked.json') -Raw | ConvertFrom-Json
    $script:Shipped = Get-SITierTrustList -Aggregator $script:Schema.aggregator

    function Claim { param([string]$Id, [int]$Tier, [string]$Ev = '') [pscustomobject]@{ SourceId=$Id; Tier=$Tier; Evidence=$Ev } }
    # A trust list built by hand, for the armed cases.
    function TL {
        param([object[]]$Entries)
        $agg = [pscustomobject]@{ contributors = @($Entries) }
        Get-SITierTrustList -Aggregator $agg
    }
}

Describe 'the locked default -- ARMED via `kind`, and what must still not move' {
    # 🔴 STATUS CHANGE 2026-08-12: this block used to assert the reducer was INERT. It is now armed --
    # `tenant_si_manual_tag` is declared `kind: asserted` in the locked schema, and an assertion yields
    # when an observed detection disagrees. What is pinned here is the set of outcomes that must be
    # IDENTICAL to plain MIN anyway, because the rule is deliberately narrow: it can only move the tier
    # when the assertion alone was holding it down.

    It 'still declares no question -- the `question` model was measured wrong TWICE and is not used' {
        # Retained in the code as the right shape for a genuine same-question contradiction, but the
        # operator rule is an asymmetry, not a grouping. A question appearing here means someone
        # re-introduced the symmetric model that let the catalog suppress a posture rule.
        @($script:Shipped | Where-Object { $_.Question }).Count | Should -Be 0
    }

    It 'exactly ONE contributor is asserted -- everything else is an observed detection' {
        $asserted = @($script:Shipped | Where-Object { $_.Kind -eq 'asserted' })
        @($asserted).Count      | Should -Be 1
        @($asserted)[0].Id      | Should -BeExactly 'tenant_si_manual_tag'
        @($script:Shipped | Where-Object { $_.Kind -ne 'asserted' -and $_.Kind -ne 'observed' }).Count | Should -Be 0
    }

    It 'reduces to the same tier plain MIN would give' -ForEach @(
        @{ Claims = @(@{i='endpoint_catalog_match';t=2}, @{i='endpoint_user_based_tier';t=0}); Expect = 0 }
        @{ Claims = @(@{i='endpoint_catalog_match';t=1}, @{i='tenant_si_manual_tag';t=3});      Expect = 1 }
        @{ Claims = @(@{i='endpoint_port_risk';t=3});                                           Expect = 3 }
        @{ Claims = @(@{i='endpoint_catalog_match';t=0}, @{i='tenant_si_manual_tag';t=0});      Expect = 0 }
    ) {
        $c = @($Claims | ForEach-Object { Claim $_.i $_.t })
        $r = Resolve-SITierClaims -Claims $c -TrustList $script:Shipped
        $r.Tier | Should -Be $Expect
    }

    It '🔑 no OBSERVED detection is ever suppressed by the locked default' {
        # The acceptance bar, as a test rather than a script run. Both rejected models failed exactly
        # here: the broad grouping suppressed posture rules and EG criticality, the narrow one still
        # suppressed 12 + 6. Anything but zero means a true signal is being discarded.
        $ids = @($script:Shipped.Id)
        $violations = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt $ids.Count; $i++) {
            for ($j = $i + 1; $j -lt $ids.Count; $j++) {
                foreach ($ta in 0..3) { foreach ($tb in 0..3) {
                    $r = Resolve-SITierClaims -TrustList $script:Shipped -Claims @((Claim $ids[$i] $ta), (Claim $ids[$j] $tb))
                    foreach ($s in @($r.Contradicted)) {
                        if ((Get-SITierClaimKind -TrustList $script:Shipped -Id ([string]$s.SourceId)) -ne 'asserted') {
                            [void]$violations.Add([string]$s.SourceId)
                        }
                    }
                }}
            }
        }
        @($violations) -join ',' | Should -BeExactly ''
    }

    It '🔑 a GA logon still sets T0 against a Tier-2 catalog hit -- ruling (f), never clamp it' {
        $r = Resolve-SITierClaims -TrustList $script:Shipped -Claims @(
            (Claim 'endpoint_catalog_match' 2 'File Server')
            (Claim 'endpoint_user_based_tier' 0 'GA logon')
        )
        $r.Tier  | Should -Be 0
        $r.SetBy | Should -Contain 'endpoint_user_based_tier'
    }

    It '🎓 the certificate-authority case -- capability and context are INDEPENDENT, so T0 (3.4c)' {
        # A VM running Certificate Services (T0 by capability) inside a Tier-2 subscription. The
        # alternative reading ships a Tier 2 certificate authority.
        $r = Resolve-SITierClaims -TrustList $script:Shipped -Claims @(
            (Claim 'endpoint_catalog_match' 0 'Root CA')
            (Claim 'tenant_si_manual_tag'   2 'env--tier2--SI')
        )
        $r.Tier | Should -Be 0
    }
}

Describe 'stage 1 -- admissibility' {

    It 'an untrusted source cannot set the tier' {
        $tl = TL @(
            [pscustomobject]@{ id='trusted_src';   order=1; trusted=$true  }
            [pscustomobject]@{ id='distrusted_src';order=2; trusted=$false }
        )
        $r = Resolve-SITierClaims -TrustList $tl -Claims @((Claim 'trusted_src' 2), (Claim 'distrusted_src' 0))
        $r.Tier | Should -Be 2
    }

    It '🔑 but the untrusted claim is still RECORDED -- ruling (i), never discarded' {
        $tl = TL @([pscustomobject]@{ id='distrusted_src'; order=1; trusted=$false })
        $r = Resolve-SITierClaims -TrustList $tl -Claims @((Claim 'distrusted_src' 0))
        $r.Untrusted.Count | Should -Be 1
        $r.Explanation | Should -Match 'still recorded'
    }

    It 'an unknown source is not trusted -- the safe answer to "I do not recognise this"' {
        $r = Resolve-SITierClaims -TrustList $script:Shipped -Claims @((Claim 'never_heard_of_this' 0))
        $r.Tier | Should -Be 3          # falls to default, not to the unknown claim's 0
        $r.Untrusted.Count | Should -Be 1
    }
}

Describe 'stage 2 -- contradiction, only when armed' {

    It 'same question + different answers => the higher-positioned source wins' {
        $tl = TL @(
            [pscustomobject]@{ id='graph_detection'; order=1; trusted=$true; question='what_is_this_machine' }
            [pscustomobject]@{ id='stale_tag';       order=9; trusted=$true; question='what_is_this_machine' }
        )
        # The operator's own example: a stale tag says workstation (3), graph says domain controller (0).
        $r = Resolve-SITierClaims -TrustList $tl -Claims @((Claim 'stale_tag' 3), (Claim 'graph_detection' 0))
        $r.Tier | Should -Be 0
        $r.Contradicted.Count | Should -Be 1
        @($r.Contradicted)[0].SourceId | Should -BeExactly 'stale_tag'
    }

    It '🔴 the loser is suppressed EVEN WHEN IT WOULD HAVE WON ON MIN -- that is the whole point' {
        # Reverse the tiers: the stale tag claims 0, graph says 2. Position, not severity, settles a
        # contradiction -- otherwise a stale tag could never be overruled.
        $tl = TL @(
            [pscustomobject]@{ id='graph_detection'; order=1; trusted=$true; question='what_is_this_machine' }
            [pscustomobject]@{ id='stale_tag';       order=9; trusted=$true; question='what_is_this_machine' }
        )
        $r = Resolve-SITierClaims -TrustList $tl -Claims @((Claim 'stale_tag' 0), (Claim 'graph_detection' 2))
        $r.Tier | Should -Be 2
        @($r.Contradicted)[0].SourceId | Should -BeExactly 'stale_tag'
    }

    It 'agreement is CORROBORATION, not contradiction -- nothing is suppressed' {
        $tl = TL @(
            [pscustomobject]@{ id='a'; order=1; trusted=$true; question='q' }
            [pscustomobject]@{ id='b'; order=2; trusted=$true; question='q' }
        )
        $r = Resolve-SITierClaims -TrustList $tl -Claims @((Claim 'a' 0), (Claim 'b' 0))
        $r.Contradicted.Count | Should -Be 0
        @($r.SetBy).Count     | Should -Be 2
    }

    It '🔑 DIFFERENT questions never contradict -- MIN decides, ruling (k)' {
        $tl = TL @(
            [pscustomobject]@{ id='software'; order=1; trusted=$true; question='what_is_installed' }
            [pscustomobject]@{ id='logon';    order=9; trusted=$true; question='who_uses_it' }
        )
        # SQL installed (T2) AND a GA logs in (T0): independent facts, both true -> T0.
        $r = Resolve-SITierClaims -TrustList $tl -Claims @((Claim 'software' 2), (Claim 'logon' 0))
        $r.Tier | Should -Be 0
        $r.Contradicted.Count | Should -Be 0
    }

    It 'an unclassified source is INDEPENDENT, never contradicting' {
        $tl = TL @(
            [pscustomobject]@{ id='classified';   order=1; trusted=$true; question='q' }
            [pscustomobject]@{ id='unclassified'; order=2; trusted=$true }
        )
        $r = Resolve-SITierClaims -TrustList $tl -Claims @((Claim 'classified' 2), (Claim 'unclassified' 0))
        $r.Tier | Should -Be 0
        $r.Contradicted.Count | Should -Be 0
    }
}

Describe 'stage 2b -- OBSERVED BEATS ASSERTED, and the asymmetry is the point' {
    # The operator rule, as finally modelled. `question` was the wrong shape because it is SYMMETRIC:
    # every member of a group can suppress every other, so the catalog silently outranked a posture
    # rule that had DETECTED Tier 0 -- ruling (f) inverted, and the third wrong turn in this area.

    BeforeAll {
        $script:AO = TL @(
            [pscustomobject]@{ id='detection'; order=1; trusted=$true; kind='observed' }
            [pscustomobject]@{ id='detection2';order=2; trusted=$true; kind='observed' }
            [pscustomobject]@{ id='tag';       order=9; trusted=$true; kind='asserted' }
        )
    }

    It 'a stale assertion yields to a disagreeing detection -- the case the rule exists for' {
        # Tag asserts T0; observation says this is a T3 workstation. Plain MIN would return 0 and keep
        # a wrong Tier 0 forever. THIS is the less-critical change the corrected acceptance bar allows.
        $r = Resolve-SITierClaims -TrustList $script:AO -Claims @((Claim 'tag' 0), (Claim 'detection' 3))
        $r.Tier | Should -Be 3
        @($r.Contradicted)[0].SourceId | Should -BeExactly 'tag'
    }

    It '🔑 an OBSERVED detection is NEVER suppressed by another observed detection' {
        # Catalog says T2, a posture rule DETECTED T0. Both are independent detections that happen to
        # describe the same machine. MIN must decide, and the T0 detection must survive.
        $r = Resolve-SITierClaims -TrustList $script:AO -Claims @((Claim 'detection' 2), (Claim 'detection2' 0))
        $r.Tier | Should -Be 0
        $r.Contradicted.Count | Should -Be 0
    }

    It 'the assertion survives when observation AGREES -- corroboration, not contradiction' {
        $r = Resolve-SITierClaims -TrustList $script:AO -Claims @((Claim 'tag' 1), (Claim 'detection' 1))
        $r.Contradicted.Count | Should -Be 0
        @($r.SetBy) | Should -Contain 'tag'
    }

    It '🔒 the assertion still sets the tier outright when NOTHING observed has an opinion' {
        # Withdrawing an assertion because nothing contradicts it would delete the operator's own
        # deliberate tag on an asset no detection covers -- strictly worse than plain MIN.
        $r = Resolve-SITierClaims -TrustList $script:AO -Claims @((Claim 'tag' 0))
        $r.Tier | Should -Be 0
        $r.Contradicted.Count | Should -Be 0
    }

    It 'one disagreeing detection is enough, even when another agrees' {
        # The assertion is contradicted by the estate, so it yields; MIN then decides across what is
        # left. It must NOT survive merely because one detection happened to concur.
        $r = Resolve-SITierClaims -TrustList $script:AO -Claims @(
            (Claim 'tag' 0), (Claim 'detection' 0), (Claim 'detection2' 3))
        @($r.Contradicted).SourceId | Should -Contain 'tag'
        $r.Tier | Should -Be 0     # detection still claims 0 on its own merits
    }

    It 'an untrusted assertion never reaches this stage at all' {
        $tl = TL @(
            [pscustomobject]@{ id='detection'; order=1; trusted=$true;  kind='observed' }
            [pscustomobject]@{ id='tag';       order=9; trusted=$false; kind='asserted' }
        )
        $r = Resolve-SITierClaims -TrustList $tl -Claims @((Claim 'tag' 0), (Claim 'detection' 2))
        $r.Tier | Should -Be 2
        $r.Untrusted.Count    | Should -Be 1
        $r.Contradicted.Count | Should -Be 0    # excluded, not contradicted -- different reasons
    }

    It 'assertions do not suppress each OTHER -- only observation may overrule an assertion' {
        $tl = TL @(
            [pscustomobject]@{ id='tagA'; order=1; trusted=$true; kind='asserted' }
            [pscustomobject]@{ id='tagB'; order=9; trusted=$true; kind='asserted' }
        )
        $r = Resolve-SITierClaims -TrustList $tl -Claims @((Claim 'tagA' 0), (Claim 'tagB' 3))
        $r.Tier | Should -Be 0
        $r.Contradicted.Count | Should -Be 0
    }

    It '🔒 an unclassified source defaults to OBSERVED -- unknown must never be suppressible' {
        # The inert, safe direction. Defaulting to `asserted` would let any disagreement silently
        # discard a source nobody had got round to classifying.
        $tl = TL @([pscustomobject]@{ id='mystery'; order=1; trusted=$true })
        (Get-SITierClaimKind -TrustList $tl -Id 'mystery') | Should -BeExactly 'observed'
        (Get-SITierClaimKind -TrustList $tl -Id 'never_declared') | Should -BeExactly 'observed'
    }

    It 'an unrecognised kind string is treated as observed, not as asserted' {
        $tl = TL @([pscustomobject]@{ id='odd'; order=1; trusted=$true; kind='probably' })
        (Get-SITierClaimKind -TrustList $tl -Id 'odd') | Should -BeExactly 'observed'
    }

    It 'kind is case- and whitespace-insensitive -- a schema edit must not silently disarm it' {
        $tl = TL @([pscustomobject]@{ id='t'; order=1; trusted=$true; kind='  ASSERTED ' })
        (Get-SITierClaimKind -TrustList $tl -Id 't') | Should -BeExactly 'asserted'
    }

    It 'the customer overlay inherits the locked kind when it omits one -- the REPLACE trap' {
        # Same trap as `order`: the merge REPLACES a contributor by id rather than deep-merging, so
        # "distrust this source, say nothing else" would otherwise silently reclassify it as observed
        # and quietly disarm the rule.
        $agg = [pscustomobject]@{ contributors = @([pscustomobject]@{ id='tenant_si_manual_tag'; trusted=$false }) }
        $tl  = Get-SITierTrustList -Aggregator $agg -LockedKinds @{ 'tenant_si_manual_tag' = 'asserted' }
        (Get-SITierClaimKind -TrustList $tl -Id 'tenant_si_manual_tag') | Should -BeExactly 'asserted'
    }
}

Describe 'the reduction explains itself' {

    It 'no claims at all reads as the default tier, stated as such' {
        $r = Resolve-SITierClaims -Claims @() -TrustList $script:Shipped
        $r.Tier | Should -Be 3
        $r.Explanation | Should -Match 'default'
    }

    It 'names how many were suppressed and how many were excluded' {
        $tl = TL @(
            [pscustomobject]@{ id='hi';  order=1; trusted=$true;  question='q' }
            [pscustomobject]@{ id='lo';  order=9; trusted=$true;  question='q' }
            [pscustomobject]@{ id='out'; order=5; trusted=$false }
        )
        $r = Resolve-SITierClaims -TrustList $tl -Claims @((Claim 'hi' 2), (Claim 'lo' 0), (Claim 'out' 0))
        $r.Explanation | Should -Match 'contradicted'
        $r.Explanation | Should -Match 'untrusted'
        $r.Tier | Should -Be 2
    }

    It 'does not throw on an empty trust list' {
        { Resolve-SITierClaims -Claims @((Claim 'x' 0)) -TrustList @() } | Should -Not -Throw
    }
}

# ---------------------------------------------------------------------------------------------------
# 🔴 TWO DESCRIBE BLOCKS WERE REMOVED HERE ON 2026-08-31 (finding #87), NOT SKIPPED.
#
#   'WIRED -- the endpoint class match now applies observed-beats-asserted'
#   'BUG FIX -- the explanation must not contradict the tier it explains'
#
# Both drove `Get-SITierFromEndpointDevice` + `Initialize-SIEndpointCatalog`, the endpoint-CLASS
# catalog half of EndpointCatalogTierComputer.ps1 -- 16 functions with no production caller, deleted
# in the same change.
#
# 🔑 THE COVERAGE THEY PROVIDED IS NOT LOST, and that is why removing them is safe rather than merely
# convenient. What they actually asserted about is `Resolve-SITierClaims` -- observed beats asserted,
# and the explanation matching the tier it explains -- and the Describes ABOVE test that function
# DIRECTLY, on the path `Build-EndpointProfileRow` really calls. These two reached it through a second
# implementation that nothing ran, so they were testing the reducer through a corpse.
#
# 🪤 The trap worth remembering: 25 green tests over that half were what made it look maintained. A
# test suite is evidence that code WORKS, never evidence that anything CALLS it.
# ---------------------------------------------------------------------------------------------------
