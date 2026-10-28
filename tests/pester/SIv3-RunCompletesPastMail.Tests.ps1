#Requires -Version 5.1
<#
    NOTHING AT SCRIPT SCOPE MAY END A RISK ANALYSIS RUN AFTER ITS START HEARTBEAT (#120).

    Invoke-RiskAnalysis.ps1 is one long script. With mail enabled and no From address configured, the
    mail block did `return` -- at SCRIPT scope, so it ended the whole run: the bucket-loss roll-up, the
    row-count and column-fill guards and Send-RARunHealthEnd were all skipped. SI_RunHealth_CL then held
    a START row with no END row, which reads as a crash, on a run that had completed.

    The fix resolves the From address before the send decision and turns mail OFF (with a warning)
    instead. This file asserts the general property through the AST, so the next script-scope
    `return` or `exit` added anywhere after the Start heartbeat fails here too -- not only this one.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Engine = Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    $t = $null; $e = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Engine, [ref]$t, [ref]$e)
    $script:ParseErrors = $e
}

Describe 'a Risk Analysis run always reaches its END heartbeat' {

    It 'the engine parses' {
        @($script:ParseErrors).Count | Should -Be 0
    }

    It '#450: a START that found no identity (the internal launcher signs in later) is sent again right after the sign-in, once' {
        $src = Get-Content -LiteralPath $script:Engine -Raw
        $src | Should -Match '\$script:_RAStartPending = \[bool\]\$global:SI_RunHealthFailWarned'
        $first = $src.IndexOf("try { Send-SIRunHealthRow -RunContext `$script:_RunHealthCtx -Phase 'Start' } catch {}")
        $signIn = $src.IndexOf('throw "Missing SPN globals')
        $again = $src.IndexOf('if ($script:_RAStartPending) {', $signIn)
        $first | Should -BeGreaterThan 0
        $again | Should -BeGreaterThan $signIn
        $src.Substring($again, 200) | Should -Match "\`$script:_RAStartPending = \`$false"
    }

    It 'the START heartbeat and the END call both exist at script scope' {
        $src = Get-Content -LiteralPath $script:Engine -Raw
        $src | Should -Match "(?m)^(if \(\`$script:RAScaleRole -ne 'worker'\) \{ )?try \{ Send-SIRunHealthRow -RunContext \`$script:_RunHealthCtx -Phase 'Start' \} catch \{\}"
        $src | Should -Match "(?m)^Send-RARunHealthEnd -ExitReason 'success'"
    }

    It 'no script-scope return or exit exists after the START heartbeat' {
        $src = Get-Content -LiteralPath $script:Engine
        $startLine = 0
        for ($i = 0; $i -lt $src.Count; $i++) {
            # (#742: a queue worker sends no START -- the run's own START is the producer's / the single job's)
            if ($src[$i] -match "^(if \(\`$script:RAScaleRole -ne 'worker'\) \{ )?try \{ Send-SIRunHealthRow -RunContext .* -Phase 'Start'") { $startLine = $i + 1; break }
        }
        $startLine | Should -BeGreaterThan 0

        $hits = @($script:Ast.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.ReturnStatementAst] -or
            $n -is [System.Management.Automation.Language.ExitStatementAst]
        }, $true) | Where-Object {
            $p = $_.Parent; $inner = $false
            while ($p) {
                if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst] -or
                    $p -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) { $inner = $true; break }
                # #742: a queue worker's own exits -- it sent no START (a worker never has a run of its own to end)
                if ($p -is [System.Management.Automation.Language.IfStatementAst] -and $p.Clauses[0].Item1.Extent.Text -match "^\`$script:RAScaleRole -eq 'worker'") { $inner = $true; break }
                $p = $p.Parent
            }
            (-not $inner) -and $_.Extent.StartLineNumber -gt $startLine
        } | ForEach-Object { '{0}: {1}' -f $_.Extent.StartLineNumber, $_.Extent.Text })

        $hits.Count | Should -Be 0 -Because ("a script-scope return/exit ends the run before its END heartbeat: " + ($hits -join '; '))
    }

    It 'a missing From address turns mail OFF rather than leaving the run' {
        $src = Get-Content -LiteralPath $script:Engine -Raw
        $src | Should -Match '(?s)if \(\[bool\]\$global:Report_SendMail -eq \$true -and \[string\]::IsNullOrWhiteSpace\(\$from\)\) \{.{0,400}\$global:Report_SendMail = \$false'
    }
}
