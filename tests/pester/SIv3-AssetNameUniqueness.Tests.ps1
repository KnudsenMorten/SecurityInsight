#Requires -Version 5.1
<#
    SI v3 -- SI_AssetName UNIQUENESS.

    🔒 OPERATOR REQUIREMENT, 2026-08-28: "all assets must have a unique name and identifier. 100%",
    then, once the measurement was in: "qualify only where it collides".

    📊 MEASURED THAT DAY -- per-snapshot and uncontaminated, against the live workspace:

        table                     rows   unique SI_AssetId   unique SI_AssetName
        SI_Endpoint_Profile_CL     198   198  (100%)          196
        SI_Identity_Profile_CL     765   765  (100%)          395   <- 370 duplicates
        SI_Azure_Profile_CL        769   769  (100%)          302   <- 467 duplicates
        SI_PublicIP_Profile_CL      11    11  (100%)           11

    So SI_AssetId ALREADY meets the requirement and needs nothing. SI_AssetName is 100% POPULATED and
    badly non-unique, and azure's 302 independently reproduces the "303 distinct name-keys" the RA
    catalog recorded from the other direction while chasing a broken dedup.

    🪤 AND THE MEASUREMENT ONLY MEANS ANYTHING SNAPSHOT-SCOPED. si-v3 and prod write the SAME tables,
    and prod (v2.2.460) emits neither column -- zero occurrences in its builders and schemas. A
    cross-snapshot read therefore mixes rows that structurally cannot carry the field with rows that
    do, and every empty collapses into ONE bucket. That is precisely how "781 rows / 771 distinct" was
    produced and then misread as a builder defect; the builder cannot produce it, because
    Build-AzureProfileRow sets SI_AssetId and PrimaryEntityId on adjacent lines from one expression
    and $alreadySet stops the emit loop touching it.

    🔑 WHY THIS IS NOT A ROW-BUILDER TEST. A collision is a property of the SNAPSHOT, not of a row. A
    builder handed one asset cannot know another asset shares its name, so a per-row uniqueness
    assertion would pass because it cannot see the counter-example. The pass under test runs once over
    the complete built row set.

    🔴 TWO OF THESE CASES FAILED FIRST, and both were real defects in the first draft:
      * a bare `@{}` groups CASE-INSENSITIVELY, so 'Server1' and 'server1' were reported as a collision
        that Log Analytics -- which compares case-sensitively -- does not have;
      * `Sort-Object` compares by CURRENT CULTURE, and on this da-DK host 'aa' collates as 'å', so the
        member that keeps the bare name differed by locale. That is the identical defect already
        recorded for SI_CorrelationId's seed, reproduced in a function whose own comment warned about
        it. A test that only asserted "the group got qualified" would have gone green over both.
#>

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\..\engine\_shared\SI-AssetNameUniqueness.ps1'
    . $script:ModulePath
}

Describe 'SI_AssetName uniqueness -- qualify only where it collides' {

    It 'leaves an already-unique name completely untouched' {
        $rows = @(
            @{ SI_AssetName = 'alone';  SI_AssetId = 'az:/subs/x/rg/a/vm1' }
            @{ SI_AssetName = 'other';  SI_AssetId = 'az:/subs/x/rg/a/vm2' }
        )
        $r = Resolve-SIAssetNameCollisions -Rows $rows
        $rows[0].SI_AssetName | Should -BeExactly 'alone'
        $rows[1].SI_AssetName | Should -BeExactly 'other'
        $r.Groups             | Should -Be 0
        $r.Qualified          | Should -Be 0
    }

    It 'keeps the bare name on exactly ONE member of a colliding group' {
        $rows = @(
            @{ SI_AssetName = 'web-01'; SI_AssetId = 'az:/subs/x/rg/prod/w1'; AzResourceGroup = 'rg-prod' }
            @{ SI_AssetName = 'web-01'; SI_AssetId = 'az:/subs/x/rg/test/w2'; AzResourceGroup = 'rg-test' }
        )
        Resolve-SIAssetNameCollisions -Rows $rows -Discriminators @('AzResourceGroup') | Out-Null
        @($rows | Where-Object { $_.SI_AssetName -ceq 'web-01' }).Count | Should -Be 1
    }

    It 'prefers a MEANINGFUL discriminator over the opaque id tail' {
        $rows = @(
            @{ SI_AssetName = 'web-01'; SI_AssetId = 'az:/subs/x/rg/prod/w1'; AzResourceGroup = 'rg-prod' }
            @{ SI_AssetName = 'web-01'; SI_AssetId = 'az:/subs/x/rg/test/w2'; AzResourceGroup = 'rg-test' }
        )
        $r = Resolve-SIAssetNameCollisions -Rows $rows -Discriminators @('AzResourceGroup')
        $rows[1].SI_AssetName            | Should -BeExactly 'web-01 (rg-test)'
        $r.ByDiscriminator['AzResourceGroup'] | Should -Be 1
        $r.ById                          | Should -Be 0
    }

    It 'falls back to the id tail when no discriminator separates the group' {
        $rows = @(
            @{ SI_AssetName = 'nic'; SI_AssetId = 'az:/subs/x/rg/q/nic-aaaa1111' }
            @{ SI_AssetName = 'nic'; SI_AssetId = 'az:/subs/x/rg/q/nic-bbbb2222' }
        )
        $r = Resolve-SIAssetNameCollisions -Rows $rows
        $rows[1].SI_AssetName | Should -BeExactly 'nic (bbbb2222)'
        $r.ById               | Should -Be 1
    }

    It 'NEVER produces a name that already exists elsewhere in the set' {
        # A resource genuinely named 'web-01 (rg-test)' already exists, so qualifying by resource group
        # would fuse two distinct assets under one name. The candidate must fall through to the id tail.
        $rows = @(
            @{ SI_AssetName = 'web-01 (rg-test)'; SI_AssetId = 'az:/real/one' }
            @{ SI_AssetName = 'web-01';           SI_AssetId = 'az:/subs/x/rg/a/w1'; AzResourceGroup = 'rg-prod' }
            @{ SI_AssetName = 'web-01';           SI_AssetId = 'az:/subs/x/rg/b/w2'; AzResourceGroup = 'rg-test' }
        )
        $r = Resolve-SIAssetNameCollisions -Rows $rows -Discriminators @('AzResourceGroup')
        $rows[2].SI_AssetName | Should -BeExactly 'web-01 (bsxrgbw2)'
        $r.UniqueAfter        | Should -Be 3
    }

    It 'treats names differing only by CASE as distinct, because Log Analytics does' {
        # 🔴 Failed first: a bare @{} groups case-insensitively and reported a collision the table
        # does not have, which would have renamed a perfectly unique asset.
        $rows = @(
            @{ SI_AssetName = 'Server1'; SI_AssetId = 'mde:aaa1' }
            @{ SI_AssetName = 'server1'; SI_AssetId = 'mde:bbb2' }
        )
        $r = Resolve-SIAssetNameCollisions -Rows $rows
        $r.Groups             | Should -Be 0
        $rows[1].SI_AssetName | Should -BeExactly 'server1'
    }

    It 'assigns the SAME qualified name regardless of input order (ordinal, not culture)' {
        # 🔴 Failed first: Sort-Object is culture-sensitive and this host is da-DK, where 'aa' collates
        # LAST. The member keeping the bare name therefore depended on the machine's locale.
        $mk = { param($n1,$i1,$n2,$i2) @( @{ SI_AssetName=$n1; SI_AssetId=$i1 }, @{ SI_AssetName=$n2; SI_AssetId=$i2 } ) }
        $a = & $mk 'dup' 'id-aaa' 'dup' 'id-zzz'
        $b = & $mk 'dup' 'id-zzz' 'dup' 'id-aaa'
        Resolve-SIAssetNameCollisions -Rows $a | Out-Null
        Resolve-SIAssetNameCollisions -Rows $b | Out-Null
        $aByIdAaa = @($a | Where-Object { $_.SI_AssetId -ceq 'id-aaa' })[0].SI_AssetName
        $bByIdAaa = @($b | Where-Object { $_.SI_AssetId -ceq 'id-aaa' })[0].SI_AssetName
        $aByIdAaa | Should -BeExactly $bByIdAaa
    }

    It 'handles PSCustomObject rows, not only hashtables' {
        # Rows that travel through the staging blob come back DESERIALISED. Passing only hashtables is
        # exactly the fixture convenience that hid the identity-scope filter bug.
        $rows = @(
            [pscustomobject]@{ SI_AssetName = 'dup'; SI_AssetId = 'mde:cccc3333' }
            [pscustomobject]@{ SI_AssetName = 'dup'; SI_AssetId = 'mde:dddd4444' }
        )
        $r = Resolve-SIAssetNameCollisions -Rows $rows
        $rows[1].SI_AssetName | Should -BeExactly 'dup (dddd4444)'
        $r.UniqueAfter        | Should -Be 2
    }

    It 'reports rather than invents when a row has no id and no discriminator' {
        $rows = @(
            @{ SI_AssetName = 'dup'; SI_AssetId = '' }
            @{ SI_AssetName = 'dup'; SI_AssetId = '' }
        )
        $r = Resolve-SIAssetNameCollisions -Rows $rows
        $r.Unqualifiable      | Should -BeGreaterThan 0
        $rows[1].SI_AssetName | Should -BeExactly 'dup'
    }

    It 'survives a NULL discriminator element -- the shape [string[]]$null actually binds to' {
        # 🔴 REGRESSION. This crashed the identity engine on a real run:
        #   "Cannot bind argument to parameter 'Name' because it is an empty string"
        # The caller built its list with `switch { ... default { @() } }`, and a switch EMITS its
        # branch value -- an empty array unrolls to NOTHING, so the variable was $null, which binds to
        # [string[]] as a ONE-element array containing $null. Offline tests passed @() literally and
        # never saw the shape the engine actually produced. Same family as `,$hits.ToArray()` counting
        # 1 for zero matches, and `@($json | ConvertFrom-Json).Count` always being 1 on PS 5.1.
        $rows = @(
            @{ SI_AssetName = 'dup'; SI_AssetId = 'mde:eeee5555' }
            @{ SI_AssetName = 'dup'; SI_AssetId = 'mde:ffff6666' }
        )
        { Resolve-SIAssetNameCollisions -Rows $rows -Discriminators ([string[]]$null) } | Should -Not -Throw
        $rows[1].SI_AssetName | Should -BeExactly 'dup (ffff6666)'
    }

    It 'declares uniqueness SHARD-LOCAL when the run is sharded' {
        # A replica holds only its slice (Invoke-Discover, hash mod ShardCount), so it cannot see a
        # collision another replica owns. The claim must shrink out loud rather than quietly go false.
        $r = Resolve-SIAssetNameCollisions -Rows @(@{ SI_AssetName='a'; SI_AssetId='1' }) -ShardCount 4
        $r.ShardLocal | Should -BeTrue
    }
}

Describe 'the id fragment rule' {

    It 'strips punctuation BEFORE truncating' {
        # Taking the first 8 characters raw yields '/subscri' for every Azure resource on earth -- a
        # shared placeholder wearing a unique name.
        Get-SIIdFragment -Id '/subscriptions/aaa/rg/x/vm-42' | Should -BeExactly 'argxvm42'
    }

    It 'takes the TAIL, not the head' {
        # An ARM id's entropy is the resource name at the end; the head is the subscription guid shared
        # by every resource in that subscription.
        $a = Get-SIIdFragment -Id '/subscriptions/0000/resourceGroups/rg/providers/x/alpha'
        $b = Get-SIIdFragment -Id '/subscriptions/0000/resourceGroups/rg/providers/x/bravo'
        $a | Should -Not -BeExactly $b
    }

    It 'returns null rather than guessing when there is nothing to build from' {
        Get-SIIdFragment -Id ''      | Should -BeNullOrEmpty
        Get-SIIdFragment -Id '///--' | Should -BeNullOrEmpty
    }
}

Describe 'WIRING -- is any of this on the production path?' {

    # 🔑 A green unit suite never proves a feature is REACHABLE. This codebase has found EIGHT
    # "declared but never wired" shapes, two of which survived a fix AND a full green test file,
    # because every test exercised the unit directly and none asked "does anything call this".
    It 'is called from the profiling Output stage' {
        $out = Join-Path $PSScriptRoot '..\..\engine\asset-profiling\stages\Invoke-Output.ps1'
        Test-Path $out | Should -BeTrue
        $src = Get-Content $out -Raw
        # Strip comment lines first: counting a call in an explanatory comment is how an earlier guard
        # in this repo reported two calls where there was one.
        $code = ($src -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Match 'Resolve-SIAssetNameCollisions'
    }

    It 'runs AFTER the row builder has produced the complete set, and BEFORE the ingest' {
        $out  = Join-Path $PSScriptRoot '..\..\engine\asset-profiling\stages\Invoke-Output.ps1'
        $src  = Get-Content $out -Raw
        $built = $src.IndexOf('row builder: built')
        $call  = $src.IndexOf('Resolve-SIAssetNameCollisions')
        $built | Should -BeGreaterThan 0
        $call  | Should -BeGreaterThan $built
    }
}
