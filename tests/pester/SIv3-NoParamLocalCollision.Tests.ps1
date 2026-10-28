#Requires -Version 5.1
<#
    NO PARAMETER IS REUSED AS A LOCAL OF ANOTHER KIND (#394).

    PowerShell variable names are case-insensitive, and a parameter's type constraint stays on the variable for the whole
    scope. So `param([object[]]$Rows)` followed by `$rows = New-Object System.Collections.ArrayList` does not create a
    second variable: it converts the list into a FIXED object[] (`.Add` throws "Collection was of a fixed size") and it
    overwrites the caller's input before the body reads it. That is how the risk trend was never written in 3.0 -- the
    job threw on every run, and the end-of-Risk-Analysis trend saw "0 rows".

    An AST guard over every shipped runtime script (engine/**, launcher/**, container/**, auth/**). For every script and
    function parameter it looks at each assignment to the same name (any case) in the same scope -- nested functions and
    script blocks with their own param block are their own scopes -- and fails when the value is of another KIND than the
    parameter:
      * an array parameter ([x[]] / [array]) given a list / set / dictionary or a hashtable;
      * a hashtable parameter given an array or a list;
      * a scalar parameter ([string], [int], [datetime] ...) or a switch given an array, a hashtable or a list;
      * a list-typed parameter given an array or a hashtable;
      * ANY parameter, typed or not, given `New-Object <list>` / `[<list>]::new()` -- a parameter is never the working
        list (rename the local instead).
    Same-kind normalisations stay allowed: `$Rows = @($Rows)`, `$Bound = @{}`, `$RunId = [guid]::NewGuid().ToString()`.

    OFFLINE. AST only. PS 5.1 + pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:RuntimeDirs = 'engine', 'launcher', 'container', 'auth'

    function Get-SIPlcKind {
        param([AllowNull()][AllowEmptyString()][string]$TypeName)
        $t = "$TypeName".Trim()
        if (-not $t -or $t -match '^(?i)(System\.)?(object|psobject|Management\.Automation\.PSObject)$') { return 'any' }
        if ($t -match '\[\]$' -or $t -match '^(?i)(System\.)?array$') { return 'array' }
        if ($t -match '^(?i)((System\.Collections\.)?hashtable|ordered|(System\.Collections\.Specialized\.)?OrderedDictionary|(System\.Collections\.)?IDictionary)$') { return 'hashtable' }
        if ($t -match '(?i)(^|\.)(ArrayList|List|HashSet|SortedSet|Dictionary|SortedDictionary|Queue|Stack|ConcurrentBag|ConcurrentDictionary|ConcurrentQueue|Collection|ObservableCollection|LinkedList)(`\d+)?(\[|$)') { return 'collection' }
        if ($t -match '^(?i)(System\.Management\.Automation\.)?scriptblock$') { return 'scriptblock' }
        if ($t -match '^(?i)(System\.Management\.Automation\.)?(switch|SwitchParameter)$') { return 'switch' }
        return 'scalar'
    }

    function Get-SIPlcValueKind {
        <# The kind of value an assignment's right-hand side certainly produces, or $null when it cannot be told. #>
        param($Right)
        $A = [System.Management.Automation.Language.Ast]
        if ($Right -is [System.Management.Automation.Language.CommandExpressionAst]) {
            $e = $Right.Expression
            if ($e -is [System.Management.Automation.Language.ArrayExpressionAst] -or $e -is [System.Management.Automation.Language.ArrayLiteralAst]) { return 'array' }
            if ($e -is [System.Management.Automation.Language.HashtableAst]) { return 'hashtable' }
            if ($e -is [System.Management.Automation.Language.ConvertExpressionAst]) {
                $k = Get-SIPlcKind $e.Type.TypeName.FullName
                if ($k -eq 'any') { return $null }
                return $k
            }
            if ($e -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $e.Static -and
                $e.Expression -is [System.Management.Automation.Language.TypeExpressionAst] -and
                $e.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $e.Member.Value -eq 'new') {
                $k = Get-SIPlcKind $e.Expression.TypeName.FullName
                if ($k -in 'collection', 'hashtable', 'array') { return $k }
            }
            return $null
        }
        if ($Right -is [System.Management.Automation.Language.PipelineAst] -and $Right.PipelineElements.Count -eq 1 -and
            $Right.PipelineElements[0] -is [System.Management.Automation.Language.CommandAst]) {
            $c = $Right.PipelineElements[0]
            if ($c.GetCommandName() -ne 'New-Object') { return $null }
            $typeArg = $null; $els = $c.CommandElements
            for ($i = 1; $i -lt $els.Count; $i++) {
                $el = $els[$i]
                if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
                    if ($el.ParameterName -match '^(?i)t(y(p(e(n(a(m(e)?)?)?)?)?)?)?$') {
                        $typeArg = if ($el.Argument) { $el.Argument } elseif ($i + 1 -lt $els.Count) { $els[$i + 1] } else { $null }
                        break
                    }
                    if (-not $el.Argument -and $el.ParameterName -match '^(?i)(ArgumentList|Property|ComObject)$') { $i++ }
                    continue
                }
                if (-not $typeArg) { $typeArg = $el; break }
            }
            if ($typeArg -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $k = Get-SIPlcKind $typeArg.Value
                if ($k -in 'collection', 'hashtable', 'array') { return $k }
            }
            return $null
        }
        return $null
    }

    function Test-SIPlcConflict {
        param([string]$ParamKind, [string]$ValueKind)
        if (-not $ValueKind) { return $false }
        switch ($ParamKind) {
            'array'       { return $ValueKind -in 'collection', 'hashtable' }
            'hashtable'   { return $ValueKind -in 'array', 'collection' }
            'scalar'      { return $ValueKind -in 'array', 'hashtable', 'collection' }
            'switch'      { return $ValueKind -in 'array', 'hashtable', 'collection' }
            'collection'  { return $ValueKind -in 'array', 'hashtable' }
            'scriptblock' { return $ValueKind -in 'array', 'hashtable', 'collection' }
            'any'         { return $ValueKind -eq 'collection' }
        }
        return $false
    }

    function Find-SIParamLocalCollision {
        <# Every collision in one parsed script: @{ Where; Line; Param; ParamType; Local; Value }. #>
        param([Parameter(Mandatory)]$Ast, [string]$Label = '<script>')
        $out = New-Object System.Collections.Generic.List[object]
        $scopes = @($Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ScriptBlockAst] }, $true))
        foreach ($sb in $scopes) {
            $params = New-Object System.Collections.Generic.List[object]
            if ($sb.ParamBlock) { foreach ($p in $sb.ParamBlock.Parameters) { $params.Add($p) } }
            if ($sb.Parent -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $sb.Parent.Parameters) {
                foreach ($p in $sb.Parent.Parameters) { $params.Add($p) }
            }
            if ($params.Count -eq 0) { continue }
            $pmap = @{}
            foreach ($p in $params) {
                $tc = @($p.Attributes | Where-Object { $_ -is [System.Management.Automation.Language.TypeConstraintAst] } | Select-Object -First 1)
                $tn = if ($tc.Count) { $tc[0].TypeName.FullName } else { '' }
                $pmap[$p.Name.VariablePath.UserPath.ToLowerInvariant()] = [pscustomobject]@{ Name = $p.Name.VariablePath.UserPath; Type = $tn; Kind = (Get-SIPlcKind $tn) }
            }
            $assigns = $sb.FindAll({ param($n)
                $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)
            foreach ($a in $assigns) {
                # only this scope: not inside a nested function or a nested script block with its own param block
                $par = $a.Parent; $own = $true
                while ($par -and -not [object]::ReferenceEquals($par, $sb)) {
                    if ($par -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $own = $false; break }
                    if ($par -is [System.Management.Automation.Language.ScriptBlockAst] -and $par.ParamBlock) { $own = $false; break }
                    $par = $par.Parent
                }
                if (-not $own) { continue }
                $vp = $a.Left.VariablePath
                $vn = [string]$vp.UserPath
                if ($vn -match '^(?i)(global|script|env|using):') { continue }
                $vn = $vn -replace '^(?i)local:', ''
                $p = $pmap[$vn.ToLowerInvariant()]
                if (-not $p) { continue }
                if ($a.Operator -ne [System.Management.Automation.Language.TokenKind]::Equals) { continue }
                $vk = Get-SIPlcValueKind $a.Right
                if (Test-SIPlcConflict -ParamKind $p.Kind -ValueKind $vk) {
                    $fn = $sb.Parent
                    $where = if ($fn -is [System.Management.Automation.Language.FunctionDefinitionAst]) { '{0} {1}' -f $Label, $fn.Name } else { $Label }
                    $out.Add([pscustomobject]@{ Where = $where; Line = $a.Extent.StartLineNumber; Param = $p.Name; ParamType = $p.Type
                                                Local = $vn; Value = $vk; Text = ($a.Extent.Text -replace '\s+', ' ') })
                }
            }
        }
        $out.ToArray()   # callers wrap in @()
    }

    function Find-SIPlcInText {
        param([Parameter(Mandatory)][string]$Text)
        $tok = $null; $err = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tok, [ref]$err)
        Find-SIParamLocalCollision -Ast $ast
    }

    $script:Files = @(foreach ($d in $script:RuntimeDirs) {
        $p = Join-Path $script:SIRoot $d
        if (Test-Path -LiteralPath $p) { Get-ChildItem -LiteralPath $p -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' } }
    })
}

Describe 'SIv3-NoParamLocalCollision -- no parameter is reused as a local of another kind (#394)' {
    It 'scans the runtime (engine, launcher, container, auth)' {
        $script:Files.Count | Should -BeGreaterThan 100
        @($script:Files | Where-Object { $_.FullName -match '[\\/]engine[\\/]asset-trend[\\/]Invoke-SITrend\.ps1$' }).Count | Should -Be 1
    }

    It 'no runtime script or function overwrites a parameter with a value of another kind' {
        $found = New-Object System.Collections.Generic.List[string]
        foreach ($f in $script:Files) {
            $tok = $null; $err = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
            $rel = $f.FullName.Substring($script:SIRoot.Length + 1)
            foreach ($h in @(Find-SIParamLocalCollision -Ast $ast -Label $rel)) {
                $found.Add(('{0}:{1} -- parameter [{2}]${3} is assigned a {4} as ${5}: {6}' -f $h.Where, $h.Line, $h.ParamType, $h.Param, $h.Value, $h.Local, $h.Text))
            }
        }
        $found | Should -BeNullOrEmpty -Because 'a parameter keeps its type constraint for the whole scope, and names are case-insensitive -- rename the local'
    }

    It 'catches the exact #394 shape (script parameter [object[]]$Rows, local $rows = New-Object ArrayList)' {
        $h = @(Find-SIPlcInText -Text "param([AllowEmptyCollection()][object[]]`$Rows)`n`$rows = New-Object System.Collections.ArrayList`n[void]`$rows.Add(1)")
        $h.Count | Should -Be 1
        $h[0].Param | Should -Be 'Rows'; $h[0].Local | Should -Be 'rows'; $h[0].Value | Should -Be 'collection'
    }

    It 'catches the other kinds: function parameters, ::new(), -TypeName, a hashtable into an array, a list into an untyped parameter' {
        @(Find-SIPlcInText -Text 'function A { param([string[]]$Names) $names = [System.Collections.Generic.List[string]]::new() }').Count | Should -Be 1
        @(Find-SIPlcInText -Text 'function B([object[]]$Items) { $items = New-Object -TypeName ''System.Collections.Generic.List[object]'' }').Count | Should -Be 1
        @(Find-SIPlcInText -Text 'function C { param([object[]]$Rows) $Rows = @{} }').Count | Should -Be 1
        @(Find-SIPlcInText -Text 'function D { param([string]$Name) $name = @(1, 2) }').Count | Should -Be 1
        @(Find-SIPlcInText -Text 'function E { param($Cache) $cache = New-Object System.Collections.Generic.HashSet[string] }').Count | Should -Be 1
        @(Find-SIPlcInText -Text 'function F { param([hashtable]$Map) $map = @() }').Count | Should -Be 1
        @(Find-SIPlcInText -Text 'function G { param([object[]]$Rows) $x = { $rows = New-Object System.Collections.ArrayList } }').Count | Should -Be 1 -Because 'a script block without its own param block shares the scope (ForEach-Object, dot-sourcing)'
    }

    It 'allows same-kind normalisations and other scopes' {
        $ok = @(
            'function A { param([object[]]$Rows) $rows = @($Rows | Where-Object { $_ }) }',
            'function B { param([hashtable]$Bound) if (-not $Bound) { $Bound = @{} } }',
            'function C { param([string]$RunId) if (-not $RunId) { $RunId = [guid]::NewGuid().ToString() } }',
            'function D { param([string[]]$Kinds) $Kinds = [string[]]@($Kinds) }',
            'function E { param([object[]]$Rows) $trendRows = New-Object System.Collections.ArrayList }',
            'function F { param([object[]]$Rows) $sb = { param($Other) $rows = New-Object System.Collections.ArrayList } }',
            'function G { param([object[]]$Rows) function Inner { $rows = New-Object System.Collections.ArrayList } }',
            'function H { param([System.Collections.Generic.List[string]]$Out) if ($null -eq $Out) { $Out = New-Object System.Collections.Generic.List[string] } }',
            'function I { param([object[]]$Rows) $global:rows = New-Object System.Collections.ArrayList; $script:rows = @{} }'
        )
        foreach ($t in $ok) { @(Find-SIPlcInText -Text $t).Count | Should -Be 0 -Because $t }
    }

    It 'the shape really breaks at run time (why this guard exists): the list becomes a fixed array and the input is gone' {
        $sb = [scriptblock]::Create("param([object[]]`$Rows) `$rows = New-Object System.Collections.ArrayList; try { [void]`$rows.Add(1); 'added' } catch { 'threw: ' + `$_.Exception.Message }; 'type=' + `$Rows.GetType().Name; 'count=' + @(`$Rows).Count")
        $r = @(& $sb -Rows @(1, 2, 3))
        ($r -join ' | ') | Should -Match 'fixed size'
        ($r -join ' | ') | Should -Match 'type=Object\[\]'
        ($r -join ' | ') | Should -Match 'count=0'
    }
}
