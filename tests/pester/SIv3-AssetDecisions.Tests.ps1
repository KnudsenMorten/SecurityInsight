#Requires -Version 5.1
<#
    SI #61 -- override / exception / exemption.

    NOTE -- NO EMOJI IN THIS FILE. These .ps1 files carry no BOM, so PowerShell 5.1 decodes them as
    Windows-1252 and a four-byte emoji lands as four Latin-1 characters, several of which the parser
    treats as STRING DELIMITERS. An emoji inside a single-quoted test name closes it early and the rest
    of the file parses as garbage. Cost a real debugging detour 2026-08-13.

    Written as the ways the model can be ABUSED, because that is what it has to survive: the whole
    point is that a scope decision must not be smuggled in as a tier change, and that an expiry nobody
    enforces is decoration.
#>

BeforeAll {
    $root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    . (Join-Path $root '..\engine\asset-profiling\shared\Resolve-SIAssetDecisions.ps1')

    function D {
        param($asset,$kind,$tier,$by='mok@2linkit.net',$at='2026-08-01',$expires,$reason='because')
        $h = @{ asset=$asset; kind=$kind; by=$by; at=$at; reason=$reason }
        if ($PSBoundParameters.ContainsKey('tier'))    { $h['tier']    = $tier }
        if ($PSBoundParameters.ContainsKey('expires')) { $h['expires'] = $expires }
        [pscustomobject]$h
    }
    $script:Now = [datetime]'2026-08-13'
}

Describe 'THE LINE THAT MATTERS -- only an override may change the tier' {

    It 'an exemption that tries to set a tier is REJECTED' {
        # This is how a scope decision gets smuggled in as a tier change and becomes unauditable.
        $v = Test-SIAssetDecision -Entry (D 'A' 'exemption' -tier 3 -expires '2026-12-01')
        $v.Valid | Should -BeFalse
        ($v.Problems -join ' ') | Should -Match "must NOT set 'tier'"
    }

    It 'an exception that tries to set a tier is REJECTED too' {
        (Test-SIAssetDecision -Entry (D 'A' 'exception' -tier 1 -expires '2026-12-01')).Valid | Should -BeFalse
    }

    It 'an override MUST state a tier -- otherwise it corrects nothing' {
        (Test-SIAssetDecision -Entry (D 'A' 'override')).Valid | Should -BeFalse
    }

    It 'a valid override passes' {
        (Test-SIAssetDecision -Entry (D 'A' 'override' -tier 1)).Valid | Should -BeTrue
    }
}

Describe 'expiry -- mandatory where it matters, forbidden where it does not' {

    It 'an <Kind> without expires is REJECTED -- a permanent hole' -ForEach @(
        @{ Kind = 'exception' }, @{ Kind = 'exemption' }
    ) {
        (Test-SIAssetDecision -Entry (D 'A' $Kind)).Valid | Should -BeFalse
    }

    It 'an override with expires is REJECTED, and the message suggests what they meant' {
        # An expiry on an override means someone meant `exception`. Refuse rather than guess.
        $v = Test-SIAssetDecision -Entry (D 'A' 'override' -tier 1 -expires '2026-12-01')
        $v.Valid | Should -BeFalse
        ($v.Problems -join ' ') | Should -Match 'Did you mean kind: exception'
    }

    It 'tier must be 0-3' {
        (Test-SIAssetDecision -Entry (D 'A' 'override' -tier 9)).Valid | Should -BeFalse
    }
}

Describe 'provenance is mandatory -- an unattributed decision is the stale tag we are replacing' {

    It 'no `by` is rejected' {
        (Test-SIAssetDecision -Entry (D 'A' 'override' -tier 1 -by '')).Valid | Should -BeFalse
    }

    It 'no `at` is rejected' {
        (Test-SIAssetDecision -Entry (D 'A' 'override' -tier 1 -at '')).Valid | Should -BeFalse
    }

    It 'and that applies to exemptions too, not just tier-changing entries' {
        (Test-SIAssetDecision -Entry (D 'A' 'exemption' -expires '2026-12-01' -by '')).Valid | Should -BeFalse
    }
}

Describe 'EXPIRY FAILS CLOSED -- a lapsed entry stops applying and is reported' {

    It 'an expired exemption does NOT exempt' {
        $r = Resolve-SIAssetDecisions -Decisions @((D 'SRV-1' 'exemption' -expires '2026-01-01')) -Asset 'SRV-1' -Now $script:Now
        $r.IsExempt | Should -BeFalse
    }

    It 'and it is REPORTED as lapsed, not silently dropped' {
        # Silently dropping is the worse half: the operator believes it is in force and nothing says
        # otherwise. A lapse makes assets REAPPEAR, which must be visible.
        $r = Resolve-SIAssetDecisions -Decisions @((D 'SRV-1' 'exemption' -expires '2026-01-01')) -Asset 'SRV-1' -Now $script:Now
        @($r.Lapsed).Count | Should -Be 1
    }

    It 'an entry expiring in the future still applies' {
        $r = Resolve-SIAssetDecisions -Decisions @((D 'SRV-1' 'exemption' -expires '2026-12-01')) -Asset 'SRV-1' -Now $script:Now
        $r.IsExempt | Should -BeTrue
        @($r.Lapsed).Count | Should -Be 0
    }

    It 'an override never lapses -- it carries no expiry by construction' {
        $r = Resolve-SIAssetDecisions -Decisions @((D 'SRV-1' 'override' -tier 0)) -Asset 'SRV-1' -Now ([datetime]'2099-01-01')
        $r.Override | Should -Not -BeNullOrEmpty
    }

    It 'an unparseable expires is REJECTED, not treated as never-expiring' {
        # Failing open here would turn a typo into a permanent exemption.
        $r = Resolve-SIAssetDecisions -Decisions @((D 'SRV-1' 'exemption' -expires 'soon')) -Asset 'SRV-1' -Now $script:Now
        $r.IsExempt | Should -BeFalse
        @($r.Rejected).Count | Should -Be 1
    }
}

Describe 'selectors' {

    It 'matches exactly' {
        (Test-SIAssetSelectorMatch -Selector 'SRV-1' -Asset 'SRV-1') | Should -BeTrue
    }

    It 'matches a wildcard' {
        (Test-SIAssetSelectorMatch -Selector 'LAB-*' -Asset 'LAB-07') | Should -BeTrue
    }

    It 'is case-insensitive' {
        (Test-SIAssetSelectorMatch -Selector 'srv-1' -Asset 'SRV-1') | Should -BeTrue
    }

    It 'a short selector matches an FQDN -- which form reaches SI depends on the merge, not on intent' {
        (Test-SIAssetSelectorMatch -Selector 'SRV-1' -Asset 'srv-1.contoso.local') | Should -BeTrue
    }

    It 'does not match a different host' {
        (Test-SIAssetSelectorMatch -Selector 'SRV-1' -Asset 'SRV-10') | Should -BeFalse
    }
}

Describe 'precedence -- most specific, then most recent' {

    It 'an EXACT match beats a wildcard' {
        $r = Resolve-SIAssetDecisions -Asset 'LAB-07' -Now $script:Now -Decisions @(
            (D 'LAB-*'  'override' -tier 3 -at '2026-08-10')
            (D 'LAB-07' 'override' -tier 0 -at '2026-08-01')
        )
        $r.Override.tier | Should -Be 0
    }

    It 'among equals the most RECENT wins -- so someone can correct themselves' {
        $r = Resolve-SIAssetDecisions -Asset 'SRV-1' -Now $script:Now -Decisions @(
            (D 'SRV-1' 'override' -tier 3 -at '2026-08-01')
            (D 'SRV-1' 'override' -tier 1 -at '2026-08-11')
        )
        $r.Override.tier | Should -Be 1
    }

    It 'exceptions do NOT compete -- they are per-control, so all live ones apply' {
        $r = Resolve-SIAssetDecisions -Asset 'SRV-1' -Now $script:Now -Decisions @(
            (D 'SRV-1' 'exception' -expires '2026-12-01')
            (D 'SRV-1' 'exception' -expires '2026-12-02')
        )
        @($r.Exceptions).Count | Should -Be 2
    }
}

Describe 'invalid entries are rejected LOUDLY, never silently dropped' {

    It 'an unknown kind is rejected with a reason' {
        $r = Resolve-SIAssetDecisions -Asset 'SRV-1' -Decisions @((D 'SRV-1' 'ignore-this')) -Now $script:Now
        @($r.Rejected).Count | Should -Be 1
        (@($r.Rejected)[0].Problems -join ' ') | Should -Match 'kind'
    }

    It 'a rejected entry does NOT take effect' {
        $r = Resolve-SIAssetDecisions -Asset 'SRV-1' -Now $script:Now -Decisions @(
            (D 'SRV-1' 'exemption' -expires '2026-12-01' -by '')   # unattributed
        )
        $r.IsExempt | Should -BeFalse
    }

    It 'one bad entry does not discard the good ones' {
        $r = Resolve-SIAssetDecisions -Asset 'SRV-1' -Now $script:Now -Decisions @(
            (D 'SRV-1' 'nonsense')
            (D 'SRV-1' 'override' -tier 1)
        )
        $r.Override.tier    | Should -Be 1
        @($r.Rejected).Count | Should -Be 1
    }

    It 'a null entry in the list is skipped, not iterated' {
        { Resolve-SIAssetDecisions -Asset 'SRV-1' -Decisions @($null, (D 'SRV-1' 'override' -tier 1)) -Now $script:Now } | Should -Not -Throw
    }

    It 'no decisions at all is normal, not an error' {
        $r = Resolve-SIAssetDecisions -Asset 'SRV-1' -Decisions @() -Now $script:Now
        $r.Override  | Should -BeNullOrEmpty
        $r.IsExempt  | Should -BeFalse
    }
}

Describe 'the run report -- decisions must be visible every run' {

    It 'counts overrides, exemptions, lapses and rejects' {
        $a = Resolve-SIAssetDecisions -Asset 'A' -Now $script:Now -Decisions @((D 'A' 'override' -tier 1))
        $b = Resolve-SIAssetDecisions -Asset 'B' -Now $script:Now -Decisions @((D 'B' 'exemption' -expires '2026-12-01'))
        $c = Resolve-SIAssetDecisions -Asset 'C' -Now $script:Now -Decisions @((D 'C' 'exemption' -expires '2026-01-01'))
        $d = Resolve-SIAssetDecisions -Asset 'E' -Now $script:Now -Decisions @((D 'E' 'bogus'))
        $rep = Get-SIAssetDecisionReport -Resolutions @($a,$b,$c,$d)
        $rep.AssetsWithOverride | Should -Be 1
        $rep.AssetsExempt       | Should -Be 1
        $rep.LapsedEntries      | Should -Be 1
        $rep.RejectedEntries    | Should -Be 1
    }

    It 'handles an empty run without throwing' {
        (Get-SIAssetDecisionReport -Resolutions @()).AssetsExempt | Should -Be 0
    }
}

Describe 'WIRING -- an override must change the EMITTED row, not just a variable' {
    # This block exists because the first draft of the wiring was INERT. `Tier` is resolved from
    # $Context.AggregatedTier during the schema iteration, which runs BEFORE the override block, so
    # updating only $aggTier left $row['Tier'] holding the computed value. The log would have claimed an
    # override was applied while the published row disagreed -- the same defect class as MatchedClass
    # contradicting its own reduced tier: the variable moved and the OUTPUT did not.
    #
    # Asserted against the source text rather than by building a row, because Build-EndpointProfileRow
    # needs a full schema + context to execute and these are the two lines that can silently regress.

    BeforeAll {
        $script:RowBuilder = Get-Content -Raw (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) `
                                '..\engine\asset-profiling\shared\Build-EndpointProfileRow.ps1')
    }

    It 'the override assigns the ROW, not only $aggTier' {
        $script:RowBuilder | Should -Match "\`$row\['Tier'\]\s*=\s*\`$newTier"
    }

    It 'and it preserves the computed tier rather than discarding it' {
        # "why is this asset Tier 1" must stay answerable with BOTH numbers visible.
        $script:RowBuilder | Should -Match "SI_TierBeforeOverride'\]\s*=\s*\[string\]\`$aggTier"
    }

    It 'the override records WHO and WHEN on the row' {
        $script:RowBuilder | Should -Match "SI_TierOverrideBy"
    }

    It 'both override columns are ALWAYS emitted, empty when no override applies' {
        # A column that sometimes exists and sometimes does not breaks consumers at query time; the
        # same rule the SI_TierSetBy columns already follow.
        $script:RowBuilder | Should -Match "\`$row\['SI_TierBeforeOverride'\]\s*=\s*''"
        $script:RowBuilder | Should -Match "\`$row\['SI_TierOverrideBy'\]\s*=\s*''"
    }

    It 'a missing decisions file must NOT take down the row build' {
        # Same trade as the attribution columns: never cost the customer their inventory for an
        # explanatory field.
        $script:RowBuilder | Should -Match 'operator decisions unavailable'
    }
}
