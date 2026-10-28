#Requires -Version 5.1
<#
    SI v3 Phase 4 step 2 -- the source trust list.

    Ruling (e): ONE ordered list carrying exactly two things -- position settles a contradiction,
    `trusted` is a boolean saying whether the source may set the tier at all. No numbers, no middle
    state. These tests pin that shape, the shipped default order, and the customer-overlay semantics.

    They do NOT test tier selection. MIN still decides across independent facts (rulings (f) and (k));
    the reducer that consults this list is step 3.
#>

BeforeAll {
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $root 'engine\asset-profiling\shared\Get-SITierTrustList.ps1')
    $script:Schema = Get-Content (Join-Path $root 'asset-profiling-schema\endpoint.schema.locked.json') -Raw | ConvertFrom-Json
    $script:Locked = @{}
    foreach ($c in $script:Schema.aggregator.contributors) { $script:Locked[$c.id] = $c.order }
}

Describe '🔴 the weights are GONE, not renamed' {
    # They produced ties, and a tie has no defined outcome -- which is why the aggregator that consumed
    # them was declared and never implemented. Three contributors shared 1.0 and three shared 0.7.

    It 'no contributor carries a weight any more' {
        @($script:Schema.aggregator.contributors | Where-Object { $_.PSObject.Properties['weight'] }).Count | Should -Be 0
    }

    It 'every contributor carries an order and a trusted flag instead' {
        foreach ($c in $script:Schema.aggregator.contributors) {
            $c.PSObject.Properties.Name | Should -Contain 'order'
            $c.PSObject.Properties.Name | Should -Contain 'trusted'
        }
    }

    It '🔑 the order has NO TIES -- that is the entire point of replacing weights' {
        $orders = @($script:Schema.aggregator.contributors.order)
        @($orders | Sort-Object -Unique).Count | Should -Be $orders.Count
    }

    It 'the aggregator mode no longer claims a weighted model that was never built' {
        $script:Schema.aggregator.mode | Should -Not -Match 'weighted'
    }
}

Describe 'the shipped default order encodes the operator rulings' {

    It 'observed capability ranks FIRST -- capability beats context (3.4c)' {
        # The certificate authority in a Tier-2 subscription must not read Tier 2. Catalog detection
        # observes what the machine IS; an environment tag asserts where it sits.
        (Get-SITierTrustRank -TrustList (Get-SITierTrustList -Aggregator $script:Schema.aggregator) -Id 'endpoint_catalog_match') | Should -Be 1
    }

    It '🔑 logon outranks the manual tag -- "logon detects actual permission to a user"' {
        $l = Get-SITierTrustList -Aggregator $script:Schema.aggregator
        $logon = Get-SITierTrustRank -TrustList $l -Id 'endpoint_user_based_tier'
        $tag   = Get-SITierTrustRank -TrustList $l -Id 'tenant_si_manual_tag'
        $logon | Should -BeLessThan $tag
    }

    It 'the manual tag was moved DOWN from its old 1.0 -- a tag is only as good as its process' {
        $l = Get-SITierTrustList -Aggregator $script:Schema.aggregator
        $tag = Get-SITierTrustRank -TrustList $l -Id 'tenant_si_manual_tag'
        $tag | Should -Be 10
        foreach ($id in 'endpoint_catalog_match','posture_rule_target_tier','endpoint_user_based_tier') {
            (Get-SITierTrustRank -TrustList $l -Id $id) | Should -BeLessThan $tag
        }
    }

    It 'everything is trusted by default -- distrust is an explicit customer act' {
        @((Get-SITierTrustList -Aggregator $script:Schema.aggregator) | Where-Object { -not $_.Trusted }).Count | Should -Be 0
    }
}

Describe '🪤 the customer overlay REPLACES by id -- silence must still inherit' {
    # Get-SISchemaWithCustomMerge replaces a contributor outright when the ids match; it does not deep
    # merge. So the most natural customer edit -- name a source, distrust it, say nothing else -- would
    # drop that source's position entirely unless the locked default is re-applied per field.

    It 'a customer entry with ONLY trusted:false keeps its locked position' {
        $agg = [pscustomobject]@{ contributors = @([pscustomobject]@{ id = 'tenant_si_manual_tag'; trusted = $false }) }
        $l = Get-SITierTrustList -Aggregator $agg -LockedDefaults $script:Locked
        $e = @($l | Where-Object { $_.Id -eq 'tenant_si_manual_tag' })[0]
        $e.Trusted | Should -BeFalse
        $e.Order   | Should -Be $script:Locked['tenant_si_manual_tag']   # inherited, not lost
    }

    It 'a customer may reposition a source explicitly' {
        $agg = [pscustomobject]@{ contributors = @([pscustomobject]@{ id = 'tenant_si_manual_tag'; order = 1 }) }
        $l = Get-SITierTrustList -Aggregator $agg -LockedDefaults $script:Locked
        (Get-SITierTrustRank -TrustList $l -Id 'tenant_si_manual_tag') | Should -Be 1
    }

    It 'distrust does not remove the source from the list -- ruling (i), claims are still logged' {
        $agg = [pscustomobject]@{ contributors = @([pscustomobject]@{ id = 'tenant_si_manual_tag'; trusted = $false }) }
        $l = Get-SITierTrustList -Aggregator $agg -LockedDefaults $script:Locked
        @($l | Where-Object { $_.Id -eq 'tenant_si_manual_tag' }).Count | Should -Be 1
    }

    It 'surfaces a legacy weight rather than silently ignoring it' {
        $agg = [pscustomobject]@{ contributors = @([pscustomobject]@{ id = 'x'; order = 1; weight = 0.7 }) }
        @(Get-SITierTrustList -Aggregator $agg)[0].HasLegacyWeight | Should -BeTrue
    }
}

Describe 'unknown and unpositioned sources lose safely' {

    It 'an unpositioned source sorts AFTER positioned ones, never in front' {
        $agg = [pscustomobject]@{ contributors = @(
            [pscustomobject]@{ id = 'nopos' }
            [pscustomobject]@{ id = 'positioned'; order = 5 }
        ) }
        @(Get-SITierTrustList -Aggregator $agg)[0].Id | Should -BeExactly 'positioned'
    }

    It 'an unknown source ranks last and is NOT trusted' {
        $l = Get-SITierTrustList -Aggregator $script:Schema.aggregator
        (Get-SITierTrustRank -TrustList $l -Id 'never_heard_of_this') | Should -Be ([int]::MaxValue)
        (Test-SITierSourceTrusted -TrustList $l -Id 'never_heard_of_this') | Should -BeFalse
    }

    It 'an empty or absent aggregator returns an empty list without throwing' {
        { Get-SITierTrustList -Aggregator ([pscustomobject]@{}) } | Should -Not -Throw
        @(Get-SITierTrustList -Aggregator ([pscustomobject]@{})).Count | Should -Be 0
    }

    It '🔴 ties break ORDINALLY, so the list does not depend on the host locale' {
        # This is not hypothetical. mgmt1 runs da-DK, where "aa" collates as "å" -- the LAST letter of
        # the Danish alphabet -- so `@("zzz","aaa") | Sort-Object` correctly returns zzz,aaa here and
        # aaa,zzz on an en-US host. The list decides which source wins a contradiction, so a
        # culture-sensitive tie-break would mean a locale-dependent TIER. These exact values are chosen
        # because they diverge between the two collations; a "safer" pair would not test anything.
        $agg = [pscustomobject]@{ contributors = @(
            [pscustomobject]@{ id = 'zzz'; order = 1 }
            [pscustomobject]@{ id = 'aaa'; order = 1 }
        ) }
        @(Get-SITierTrustList -Aggregator $agg)[0].Id | Should -BeExactly 'aaa'
    }

    It 'proves the hazard is real on this host -- culture sort disagrees with ordinal' {
        # If this ever fails, the machine locale changed and the ordinal guards above became untested
        # rather than unnecessary. Kept as evidence, not decoration.
        $cultureFirst = (@('zzz','aaa') | Sort-Object)[0]
        $ord = [string[]]@('zzz','aaa'); [Array]::Sort($ord, [System.StringComparer]::Ordinal)
        $ord[0] | Should -BeExactly 'aaa'
        if ([System.Globalization.CultureInfo]::CurrentCulture.Name -eq 'da-DK') {
            $cultureFirst | Should -BeExactly 'zzz' -Because 'da-DK collates aa as the final letter'
        }
    }
}
