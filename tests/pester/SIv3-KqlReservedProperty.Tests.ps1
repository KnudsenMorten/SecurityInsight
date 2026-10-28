#Requires -Version 7.0
<#
    GATE -- no report reads a property whose name is a KQL KEYWORD with dot notation (2026-10-15: Identity_SPN_OwnerMismatch
    Summary + Detailed read `tostring(_ow.of)` -- `of` is a keyword, Log Analytics answered SYN0002 "Query could not be parsed
    at 'of'" and both reports returned 0 rows on internal). Such a property is read as `x["of"]`. Comments do not count.
#>

BeforeAll {
    $script:Yaml = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..\..\risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')
    # the KQL keywords that can follow a dot by mistake as a property name (a dynamic bag's key). NOT 'kind': x.kind is
    # accepted by Log Analytics AND advanced hunting -- measured 2026-10-16 with the exact pattern of the LowTierDevice
    # reports (tostring(_dtClaim.kind) == "rule" returned the right tiers in both); 'of' is refused (SYN0002), measured the same day.
    $script:Words = @('of', 'to', 'on', 'by', 'in', 'as', 'and', 'or', 'not', 'with', 'let', 'where', 'project', 'extend', 'summarize', 'join', 'typeof', 'between', 'has', 'contains', 'step', 'from', 'set', 'range')
}

Describe 'no KQL keyword is read as a property with dot notation' {
    It 'every query line outside a comment reads a keyword-named property as x["name"], never x.name' {
        $rx = '(?<![A-Za-z0-9_"''])[A-Za-z_][A-Za-z0-9_]*\.(' + ($script:Words -join '|') + ')\b(?!\s*\()'
        $bad = foreach ($line in ($script:Yaml -split "`r?`n")) {
            $code = ($line -split '//', 2)[0]
            if ($code -match '^\s*-?\s*[A-Za-z]+:\s' -and $code -notmatch '[|(]') { continue }   # YAML keys / descriptions
            foreach ($m in [regex]::Matches($code, $rx)) { '{0}  <- {1}' -f $m.Value, $line.Trim() }
        }
        @($bad) | Should -BeNullOrEmpty -Because 'Log Analytics refuses the whole query (SYN0002) -- read it as x["keyword"]'
    }
    It 'control: the owner side of Identity_SPN_OwnerMismatch is read with brackets' {
        $script:Yaml | Should -Match ([regex]::Escape('tostring(_ow["of"]) == "service principal"'))
    }
}
