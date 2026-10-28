#Requires -Version 5.1
<#
    SI v3 Phase 4 step 1 -- "why is this asset Tier 0" must be answerable per asset.

    The operator's ruling (g): an all-Tier-0 estate loses prioritisation unless the tier carries its
    reason, so reports can slice "T0 by role" from "T0 by logon". These tests pin the ATTRIBUTION only.
    They deliberately do NOT test the tier decision itself -- MIN still decides (ruling (f)), and this
    layer describes that decision rather than making it.
#>

BeforeAll {
    . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\asset-profiling\shared\Get-SITierAttribution.ps1')
    function V { param([int]$Tier, [string]$Top = '', [int]$Count = 1) [pscustomobject]@{ Tier=$Tier; TopMatch=$Top; MatchCount=$Count } }
}

Describe 'the winning source is named' {

    It 'attributes the tier to the source that actually claimed it' {
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{
            SIRules = V 0 'Domain Controller'
            PostureRuleTargetTier = V 2 'SomeRule'
        }
        $a.SI_TierSetBy | Should -BeExactly 'rule'
        $a.SI_TierReason | Should -Match 'Domain Controller'
    }

    It '🔑 names BOTH sources when two independently claim the winning tier' {
        # A rule hit and a GA logon can both say Tier 0. Reporting only one would invent a
        # precedence that does not exist until the trust list (step 2) is built.
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{
            SIRules = V 0 'Certificate Authority'
            MostFrequentUserTier = 0
        }
        $a.SI_TierSetBy | Should -BeExactly 'logon+rule'
        $a.WinnerCount  | Should -Be 2
        $a.SI_TierReason | Should -Match '2 independent source'
    }

    It 'a losing claim does not get the credit' {
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{
            MostFrequentUserTier = 0
            SIRules = V 2 'File Server'
        }
        $a.SI_TierSetBy | Should -BeExactly 'logon'
        $a.SI_TierReason | Should -Not -Match 'File Server'
    }

    It '🎓 the T0-by-logon vs T0-by-role split is answerable -- the whole point of ruling (g)' {
        $byRole  = Get-SITierAttribution -FinalTier 0 -Sources @{ SIRules = V 0 'Root CA' }
        $byLogon = Get-SITierAttribution -FinalTier 0 -Sources @{ MostFrequentUserTier = 0 }
        $byRole.SI_TierSetBy  | Should -BeExactly 'rule'
        $byLogon.SI_TierSetBy | Should -BeExactly 'logon'
        $byRole.SI_TierSetBy  | Should -Not -Be $byLogon.SI_TierSetBy
    }
}

Describe 'every claim is recorded, including the ones that lost' {
    # Ruling (i): "untrusted claims are LOGGED, never discarded". Nothing is untrusted yet, but the
    # column shape must already be right so withdrawing trust later never blinds the customer.

    It 'keeps losing claims in SI_TierClaims' {
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{
            MostFrequentUserTier  = 0
            SIRules  = V 2 'File Server'
            PostureRuleTargetTier = V 1 'ExposedRule'
        }
        $claims = $a.SI_TierClaims | ConvertFrom-Json
        @($claims).Count | Should -Be 3
        @($claims.Source | Sort-Object) | Should -Be @('logon','posture','rule')
    }

    It 'every claim carries a Trusted flag, so a future trust list has somewhere to land' {
        $claims = (Get-SITierAttribution -FinalTier 0 -Sources @{ MostFrequentUserTier = 0 }).SI_TierClaims | ConvertFrom-Json
        @($claims)[0].PSObject.Properties.Name | Should -Contain 'Trusted'
    }

    It 'records the evidence, not just the tier' {
        $claims = (Get-SITierAttribution -FinalTier 0 -Sources @{ SIRules = V 0 'Root CA' 3 }).SI_TierClaims | ConvertFrom-Json
        @($claims)[0].Evidence   | Should -BeExactly 'Root CA'
        @($claims)[0].MatchCount | Should -Be 3
    }
}

Describe '🔴 "no opinion" and "claimed tier 3" must not collapse into each other' {

    It 'a source that made no claim produces NO claim' {
        $a = Get-SITierAttribution -FinalTier 3 -Sources @{ SIRules = V 3 'Workstation'; PostureRuleTargetTier = $null }
        @($a.SI_TierClaims | ConvertFrom-Json).Count | Should -Be 1
    }

    It 'an empty-tier verdict is not read as tier 0 -- [int]$null silently coerces to 0' {
        # This exact coercion is guarded against elsewhere in the row builder. A verdict with no tier
        # must not become the most critical claim on the asset.
        $a = Get-SITierAttribution -FinalTier 3 -Sources @{ SIRules = [pscustomobject]@{ Tier=$null; TopMatch=''; MatchCount=0 } }
        # 🪤 ASSERT THE JSON, NOT @(ConvertFrom-Json).Count. On PS 5.1 -- the runtime this ships on --
        # `'[]' | ConvertFrom-Json` emits NOTHING, so the pipeline yields $null and @($null).Count is 1.
        # This assertion read `Should -Be 0` against a value that was ALWAYS 1, so it failed while the
        # code was correct all along (verified: SI_TierClaims is '[]' and SI_TierSetBy is 'default').
        # Found 2026-08-12. The guard it protects is real, so the fix is a working assertion, not a
        # deleted test.
        $a.SI_TierClaims | Should -BeExactly '[]'
        $a.SI_TierSetBy  | Should -BeExactly 'default'
    }

    It 'no sources at all reads as the DEFAULT tier, stated as such' {
        # Endpoints deliberately default to tier 3 when nothing matches. "Nothing applied" and
        # "something applied and I cannot tell what" are different answers.
        $a = Get-SITierAttribution -FinalTier 3 -Sources @{}
        $a.SI_TierSetBy  | Should -BeExactly 'default'
        $a.SI_TierReason | Should -Match 'default'
        $a.SI_TierClaims | Should -BeExactly '[]'
    }
}

Describe 'the attribution says so when it disagrees with the engine' {

    It 'reports divergence rather than inventing an explanation' {
        # Cannot happen while MIN decides -- the final tier must equal some claim. If it ever does, the
        # reduction and the attribution have drifted apart, and a confident wrong sentence would be
        # worse than none.
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{ SIRules = V 2 'File Server' }
        $a.SI_TierSetBy  | Should -BeExactly 'unattributed'
        $a.SI_TierReason | Should -Match 'diverged'
    }

    It 'does not throw on a null final tier' {
        { Get-SITierAttribution -FinalTier $null -Sources @{ MostFrequentUserTier = 0 } } | Should -Not -Throw
    }
}

Describe 'the emitted shape is stable' {

    It 'always returns all three columns, whatever the input' -ForEach @(
        @{ Final = 0;     Src = @{ MostFrequentUserTier = 0 } }
        @{ Final = 3;     Src = @{} }
        @{ Final = $null; Src = @{} }
    ) {
        $a = Get-SITierAttribution -FinalTier $Final -Sources $Src
        foreach ($c in 'SI_TierSetBy','SI_TierReason','SI_TierClaims') {
            $a.PSObject.Properties.Name | Should -Contain $c
            [string]$a.$c | Should -Not -BeNullOrEmpty
        }
    }

    It 'SI_TierClaims is always valid JSON, so a consumer can parse it unconditionally' -ForEach @(
        @{ Src = @{} }
        @{ Src = @{ MostFrequentUserTier = 1 } }
        @{ Src = @{ SIRules = [pscustomobject]@{ Tier=0; TopMatch='X'; MatchCount=1 }; MostFrequentUserTier = 0 } }
    ) {
        { (Get-SITierAttribution -FinalTier 0 -Sources $Src).SI_TierClaims | ConvertFrom-Json } | Should -Not -Throw
    }
}

# =====================================================================================================
Describe 'THE RULE ENGINE IS A CLAIM SOURCE -- it decides most tiers and was invisible here' {
    <#
        Added 2026-08-21 after measuring a live snapshot: 142 of 150 endpoint rows carried
        SI_TierClaims = "[]" and read "Tier N is the default -- no tier source matched this asset",
        while Stage Profile had just evaluated 549 rules against those very assets. Attribution knew
        three legacy sources and was blind to the one that actually sets the tier.

        Three of those rows said "no tier source matched" while reporting TIER 0 -- and the endpoint
        default is tier 3, so the sentence contradicted itself in the same cell. That is the tell this
        file's own "attribution has diverged" branch was written for, but that branch only fires when
        claims EXIST; an empty claim list was being read as proof that nothing matched.

        After wiring: default 131 . rule 12 . logon+rule 8, and no row reaches the divergence branch.
    #>

    It 'attributes the tier to the rule engine when a rule claimed it' {
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{ SIRules = V 0 'EntraConnectADConnectServer' 3 }
        $a.SI_TierSetBy  | Should -BeExactly 'rule'
        $a.SI_TierReason | Should -Match 'EntraConnectADConnectServer'
    }

    It 'names BOTH when a rule and a logon independently claim the winning tier' {
        # Measured on MGMT1: "logon+rule ... 2 independent source(s) agreed on this tier".
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{
            SIRules             = V 0 'AssetProfileByLogonUser/LogonByT0User' 2
            MostFrequentUserTier = 0
        }
        $a.SI_TierSetBy | Should -BeExactly 'logon+rule'
    }

    It 'records the rule claim even when it LOSES' {
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{ SIRules = V 2 'SomeRule'; MostFrequentUserTier = 0 }
        $a.SI_TierSetBy | Should -BeExactly 'logon'
        ($a.SI_TierClaims | ConvertFrom-Json).SourceKey | Should -Contain 'SIRules'
    }

    It 'a tier that is NOT the default with no claim is reported as divergence, not as "default"' {
        # The exact live shape: Tier 0, zero claims. Saying "no tier source matched" there is false --
        # the endpoint default is 3, so something matched and simply could not be attributed.
        $a = Get-SITierAttribution -FinalTier 0 -Sources @{}
        $a.SI_TierSetBy  | Should -BeExactly 'default'
        $a.SI_TierReason | Should -Match 'registered no claim'
        $a.SI_TierReason | Should -Not -Match 'no tier source matched'
    }

    It 'but a genuine default still reads as the default' {
        $a = Get-SITierAttribution -FinalTier 3 -Sources @{}
        $a.SI_TierReason | Should -Match 'is the default -- no tier source matched'
    }
}
