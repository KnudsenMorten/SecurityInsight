#Requires -Version 5.1
<#
    PURE (static, nothing is run). Find-SIArrayAppendInLoop: every `$x += ...` inside the body of a loop (foreach / for /
    while / do) where $x is an ARRAY -- assigned @() / @(...) / a comma list in the same function (or at the file's top
    level), or appended to as `+= ,...` -- in one PowerShell file. `+=` on an array copies the whole array on every append,
    so in a loop over a slice's rows it is O(n^2) (owner 2026-10-14: "do we have other places in the code with += instead
    of using hash tables or similar"). A number or a text added to is not an array and is not reported.
    Returns @{ Line; Text; Variable; Function } per finding.
#>
function Find-SIArrayAppendInLoop {
    param([Parameter(Mandatory)][string]$Path)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    $isLoop = { param($n) $n -is [System.Management.Automation.Language.LoopStatementAst] }
    $scopeOf = {
        param($n)
        $p = $n.Parent
        while ($null -ne $p -and $p -isnot [System.Management.Automation.Language.FunctionDefinitionAst] -and $p -isnot [System.Management.Automation.Language.ScriptBlockExpressionAst]) { $p = $p.Parent }
        if ($null -eq $p) { $ast } else { $p }
    }
    $nameOf = {
        param($left)
        $l = $left
        if ($l -is [System.Management.Automation.Language.ConvertExpressionAst]) { $l = $l.Child }
        if ($l -is [System.Management.Automation.Language.VariableExpressionAst]) { return $l.VariablePath.UserPath.ToLowerInvariant() -replace '^(script|global|local|private):', '' }
        $null
    }
    $isArrayValue = {
        param($e)
        if ($e -is [System.Management.Automation.Language.CommandExpressionAst]) { $e = $e.Expression }
        if ($e -is [System.Management.Automation.Language.PipelineAst] -and $e.PipelineElements.Count -eq 1 -and $e.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) { $e = $e.PipelineElements[0].Expression }
        ($e -is [System.Management.Automation.Language.ArrayExpressionAst]) -or ($e -is [System.Management.Automation.Language.ArrayLiteralAst])
    }
    # the variables assigned an array, per scope (function / script block / file)
    $arrays = @{}
    foreach ($a in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Operator -eq 'Equals' }, $true)) {
        $nm = & $nameOf $a.Left
        if (-not $nm) { continue }
        if (& $isArrayValue $a.Right) { $s = & $scopeOf $a; $k = '{0}|{1}' -f $s.Extent.StartOffset, $nm; $arrays[$k] = $true }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($a in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Operator -eq 'PlusEquals' }, $true)) {
        $nm = & $nameOf $a.Left
        if (-not $nm) { continue }
        # inside a loop body, within the same function
        $inLoop = $false; $p = $a.Parent
        while ($null -ne $p -and $p -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { if (& $isLoop $p) { $inLoop = $true; break }; $p = $p.Parent }
        if (-not $inLoop) { continue }
        $rhs = $a.Right
        $commaAppend = $rhs.Extent.Text.TrimStart().StartsWith(',')
        $s = & $scopeOf $a
        if (-not $commaAppend -and -not $arrays.ContainsKey(('{0}|{1}' -f $s.Extent.StartOffset, $nm))) { continue }
        $fn = $a.Parent; while ($null -ne $fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
        $out.Add([pscustomobject]@{ Line = $a.Extent.StartLineNumber; Text = $a.Extent.Text; Variable = $nm; Function = $(if ($fn) { $fn.Name } else { '' }) })
    }
    , $out.ToArray()
}
