#Requires -Version 5.1
<#
    v2.2.442 -- KQL DYNAMIC PROPERTY ACCESS IS CASE-SENSITIVE, AND AN EMPTY KEY MUST NEVER JOIN.

    NOTE -- NO EMOJI IN THIS FILE. These .ps1 files carry no BOM, so PowerShell 5.1 decodes them as
    Windows-1252 and a four-byte emoji lands as four Latin-1 characters, several of which the parser
    treats as STRING DELIMITERS.

    WHAT HAPPENED. Identity_SPN_OwnsResourcePublicAccess (both variants) read the role scope as
    `_role.scope`. The property is `Scope`. KQL dynamic access is case-sensitive, so it evaluated to
    null on EVERY row -- measured on a live estate: 148 of 148 blank with the shipped spelling, 8 of
    148 blank with the correct one, across 39 distinct real scopes.

    WHY A TYPO BECAME FALSE FINDINGS. The blank scope was then used as a JOIN KEY:

        | join kind=inner _publicResources on $left._scope == $right.LinkedAzureResourceId

    148 blank scopes matched the 2 public resources whose AzureResourceId was also blank -- an inner
    join on empty == empty -- producing 148 x 2 = 296 rows in which no service principal owned
    anything. Corrected, the report returns 0 rows on that estate, which is the true answer.

    This is the shape that makes it dangerous rather than merely wrong: the report is a Tier 0
    "maximum blast radius" finding, it produced a confident non-empty result, and nothing about a
    populated report suggests every row is fabricated. A report that returns nothing gets
    investigated; a report that returns 12 findings gets acted on.

    These guards are deliberately CATALOG-WIDE rather than about this one report.
#>

BeforeAll {
    $script:SIRoot = Join-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..') ''
    $script:LockedYaml = Get-Content -Raw -LiteralPath (Join-Path (Join-Path $script:SIRoot 'risk-analysis-detection') 'RiskAnalysis_Queries_Locked.yaml')
}

Describe 'the role-scope property is spelled the way the data spells it' {

    # 🪤 -CMatch, NOT -Match. `Should -Match` is CASE-INSENSITIVE, so a guard against a lowercase
    # spelling written with -Match also matches the corrected uppercase one -- a case-sensitivity
    # test that cannot tell the two cases apart. The first version of this file did exactly that and
    # failed against the FIXED yaml, which is the only reason it was caught.
    It 'no report reads _role.scope (lowercase) -- the data property is Scope' {
        $script:LockedYaml | Should -Not -CMatch '_role\.scope\b'
    }

    It 'SELF-CHECK: the pattern really does match the expression it forbids' {
        # A guard that cannot fire reads as coverage while the defect sits in the file.
        '| extend _scope = tostring(_role.scope)' | Should -CMatch '_role\.scope\b'
    }

    It 'SELF-CHECK: and it does NOT match the corrected spelling' {
        '| extend _scope = tostring(_role.Scope)' | Should -Not -CMatch '_role\.scope\b'
    }

    It 'and the corrected spelling is actually present, so the fix was applied not just deleted' {
        $script:LockedYaml | Should -CMatch '_role\.Scope\b'
    }
}

Describe 'an empty value must never be used as a join key' {

    It 'every _scope join is guarded by isnotempty' {
        # The casing fix alone is not enough: 8 rows still have a legitimately blank scope, and a
        # blank key would pair with any blank id on the other side.
        $joins = [regex]::Matches($script:LockedYaml, '\$left\._scope\s*==\s*\$right\.LinkedAzureResourceId')
        @($joins).Count | Should -BeGreaterThan 0 -Because 'if the join disappears this guard is vacuous'
        foreach ($m in $joins) {
            $before = $script:LockedYaml.Substring([Math]::Max(0, $m.Index - 600), [Math]::Min(600, $m.Index))
            $before | Should -Match 'where isnotempty\(_scope\)' -Because 'a blank scope must be filtered out BEFORE the join'
        }
    }

    It 'and the right-hand side drops blank resource ids too' {
        # Both sides, because either blank alone is enough to manufacture a match.
        $script:LockedYaml | Should -Match 'where isnotempty\(tostring\(AzureResourceId\)\)'
    }
}

Describe 'the report can say WHICH service principal it is reporting on' {

    It 'the Detailed variant projects AssetName, which its OutputPropertyOrder declares' {
        # It was declared and never emitted, so every row identified nothing -- and the engine dedup,
        # which keys on AssetName, then collapsed 296 rows to 12.
        # Bound the block by the NEXT report rather than a character count -- a fixed window silently
        # stops short of the projection, which is where the assertion actually lives.
        $i = $script:LockedYaml.IndexOf('ReportName: Identity_SPN_OwnsResourcePublicAccess_Detailed')
        $i | Should -BeGreaterThan 0
        $j = $script:LockedYaml.IndexOf('- ReportName:', $i + 20)
        if ($j -lt 0) { $j = $script:LockedYaml.Length }
        $block = $script:LockedYaml.Substring($i, $j - $i)
        $block | Should -Match 'AssetName=coalesce'
    }
}
