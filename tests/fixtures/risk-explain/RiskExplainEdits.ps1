#Requires -Version 7.0
<#
    THE EXPLAINED RISK SCORE (REQUIREMENTS #910) -- the engine edit, as text pairs (old text -> new text).

    The edit is ADDITIVE: it stamps four new columns on every scored row and changes nothing else. Keeping it as pairs lets
    two suites prove that:
      * tests\pester\SIv3-RiskExplainColumns.Tests.ps1 takes the pairs out of the current engine files, checks the result is
        the files as they were before the edit (a recorded hash), and runs the same synthetic slice through both: every
        column that existed before must come out identical; only the four new columns are added.
      * tests\fixtures\ra-perf\RaPerfFixture.ps1 applies the same pairs to its old copies (a feature that came after the
        speed-up, applied to both sides, as its other "later" edits are).
    Each text occurs exactly once in its file. Synthetic data only.
#>

function Get-RiskExplainEdits {
    $nl = "`r`n"
    [ordered]@{
        'RA-FactorKeys.ps1' = @(
            , @('    $aSum = 0; $vSum = 0',
                ('    $aSum = 0; $vSum = 0' + $nl +
                 '    # #910 each counted factor with its impact ("Name=impact"), in the order of the names -- the explained score' + $nl +
                 '    $aX = [System.Collections.Generic.List[string]]::new(); $vX = [System.Collections.Generic.List[string]]::new()'))
            , @("if (`$m.Side -eq 'vulnerability') { `$vT.Add(`$m.ShortName); `$vI.Add(`$m.Id); `$vSum += [int]`$m.Impact }",
                "if (`$m.Side -eq 'vulnerability') { `$vT.Add(`$m.ShortName); `$vI.Add(`$m.Id); `$vSum += [int]`$m.Impact; `$vX.Add(`$m.ShortName + '=' + [int]`$m.Impact) }")
            , @('else { $aT.Add($m.ShortName); $aI.Add($m.Id); $aSum += [int]$m.Impact }',
                'else { $aT.Add($m.ShortName); $aI.Add($m.Id); $aSum += [int]$m.Impact; $aX.Add($m.ShortName + ''='' + [int]$m.Impact) }')
            , @("if (`$w[0] -eq 'vulnerability') { `$vT.Add(`$tok); `$vSum += [int]`$rs.Impact } else { `$aT.Add(`$tok); `$aSum += [int]`$rs.Impact }",
                "if (`$w[0] -eq 'vulnerability') { `$vT.Add(`$tok); `$vSum += [int]`$rs.Impact; `$vX.Add(`$tok + '=' + [int]`$rs.Impact) } else { `$aT.Add(`$tok); `$aSum += [int]`$rs.Impact; `$aX.Add(`$tok + '=' + [int]`$rs.Impact) }")
            , @('if ($UnnamedAssetCount -gt 0 -and $rs.Enabled) { $aSum += ($UnnamedAssetCount * [int]$rs.Impact) }',
                'if ($UnnamedAssetCount -gt 0 -and $rs.Enabled) { $aSum += ($UnnamedAssetCount * [int]$rs.Impact); for ($u = 0; $u -lt $UnnamedAssetCount; $u++) { $aX.Add(''ReportFactor='' + [int]$rs.Impact) } }')
            , @('AssetIds = $aI.ToArray(); VulnerabilityIds = $vI.ToArray() }',
                'AssetIds = $aI.ToArray(); VulnerabilityIds = $vI.ToArray(); AssetImpacts = $aX.ToArray(); VulnerabilityImpacts = $vX.ToArray() }')
        )
        'RA-RiskScore.ps1' = @(
            , @('        # MoreDetails: collect raw URLs (one per line, no labels) so the cell',
                ('        # #910 THE EXPLAINED SCORE -- additive, nothing above changes: each side''s base and each counted factor''s impact,' + $nl +
                 '        # so a reader sees base + factors = side and side x side = score. RiskConsequenceBase / RiskProbabilityBase = the' + $nl +
                 '        # bases _setScores used (its normalisation); RiskFactor_*_Impacts = "Name=impact;..." in the order of the _Detailed' + $nl +
                 '        # names, then one "ReportFactor=<impact>" per factor a report gave as a number only. base + sum(impacts) = the side.' + $nl +
                 '        $__xb = $consBase.Score' + $nl +
                 '        $tmp[''RiskConsequenceBase''] = $(if ($null -eq $__xb) { 0.0 } elseif ($__xb -is [double]) { [double]$__xb } else { try { [double]$__xb } catch { 0.0 } })' + $nl +
                 '        $__xb = $probBase.Score' + $nl +
                 '        $tmp[''RiskProbabilityBase''] = $(if ($null -eq $__xb) { 0.0 } elseif ($__xb -is [double]) { [double]$__xb } else { try { [double]$__xb } catch { 0.0 } })' + $nl +
                 '        $tmp[''RiskFactor_Consequence_Impacts''] = (@($mf.AssetImpacts) -join '';'')' + $nl +
                 '        $tmp[''RiskFactor_Probability_Impacts''] = (@($mf.VulnerabilityImpacts) -join '';'')' + $nl + $nl +
                 '        # MoreDetails: collect raw URLs (one per line, no labels) so the cell'))
        )
    }
}

# the four columns the edit adds (and nothing else)
$script:RiskExplainColumns = @('RiskConsequenceBase', 'RiskProbabilityBase', 'RiskFactor_Consequence_Impacts', 'RiskFactor_Probability_Impacts')
function Get-RiskExplainColumns { , $script:RiskExplainColumns }

function Invoke-RiskExplainEdit {
    <#
        PURE. One file's text with its pairs applied (-Reverse: taken out). Line ends are made CRLF first (the pairs are
        written with CRLF; a checkout may hand the file over with LF). Throws when a text is not there exactly once.
    #>
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][string]$File, [switch]$Reverse)
    $pairs = @((Get-RiskExplainEdits)[$File])
    if ($pairs.Count -eq 0) { return $Text }
    $Text = $Text.Replace("`r`n", "`n").Replace("`n", "`r`n")
    if ($Reverse) { [array]::Reverse($pairs) }
    foreach ($p in $pairs) {
        $from = $p[0]; $to = $p[1]
        if ($Reverse) { $from = $p[1]; $to = $p[0] }
        $n = ([regex]::Matches($Text, [regex]::Escape($from))).Count
        if ($n -ne 1) { throw ("{0}: the text to {1} occurs {2} time(s), not once: {3}" -f $File, $(if ($Reverse) { 'take out' } else { 'change' }), $n, $from) }
        $Text = $Text.Replace($from, $to)
    }
    $Text
}
