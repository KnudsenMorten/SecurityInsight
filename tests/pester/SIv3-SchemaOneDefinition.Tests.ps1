#Requires -Version 7.0
<#
    ONE UNCONDITIONAL DEFINITION PER MODULE (2026-11-26, 3.1.52 gate: SIv3-WebDuringUpdate "the shipped schema twice").
    sql\si-data-schema.sql made sidata.StatisticsRefresh twice in every apply -- the v1 gate (no @Only) and, appended by
    #1372, the v2 gate (@Only) -- both as module-guarded EXEC ('CREATE OR ALTER ...'), so every update made v1 over v2 and
    v2 again (the gate flipped once per update; the procedure was re-created under a schema-modify lock and its
    modify_date moved on every update). The fix guards the v1 EXEC (made only while no newer gate is there); its body text
    is unchanged (the #1372 append convention).
    THE LINT (a read of the shipped files, no runtime effect): no module (procedure / trigger / function / view) of
    sql\*.sql has two UNCONDITIONAL definitions. A definition is a literal EXEC (N'CREATE OR ALTER ...') or -- #1412 (a) --
    an EXEC (@x) / EXEC sp_executesql @x whose variable was last given a text starting CREATE OR ALTER <module> before it.
    #1412 (b): CONDITIONAL is read from the T-SQL itself, not guessed from the line before: the statement the EXEC is part
    of starts with IF / ELSE / WHILE, or a BEGIN ... END block around it is governed by one. Strings, comments and
    bracketed names are masked first (a definition inside another definition's text, or in a comment, is not one).
    OFFLINE: text only. NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Kinds = '(?:PROCEDURE|PROC|TRIGGER|FUNCTION|VIEW)'
    $script:NameRx = '((?:\[[^\]'']+\]|\w+)\.(?:\[[^\]'']+\]|\w+))'
    $script:Rx = [regex]("(?i)\bEXEC(?:UTE)?\s*\(\s*N?'\s*CREATE\s+OR\s+ALTER\s+{0}\s+{1}" -f $script:Kinds, $script:NameRx)
    # strings ('' escapes), -- and /* */ comments, [bracketed] and "quoted" names -> spaces (line breaks and the quotes kept),
    # so every offset is the same as in the text
    $script:MaskRx = [regex]"(?s)'(?:[^']|'')*'|--[^\r\n]*|/\*.*?\*/|\[[^\]\r\n]*\]|`"[^`"\r\n]*`""
    function script:Get-SISqlCodeMask([string]$Text) {
        $script:MaskRx.Replace($Text, [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $v = $m.Value
            $blank = [regex]::Replace($v, '[^\r\n]', ' ')
            if ($v.StartsWith("'")) { "'" + $blank.Substring(1, $blank.Length - 2) + "'" } else { $blank }
        })
    }
    function script:Get-SIUnconditionalDefinitions([string]$Text, [string]$File) {
        $mask = Get-SISqlCodeMask $Text
        $defs = New-Object System.Collections.Generic.List[object]
        $norm = { param($n) $n.ToLowerInvariant().Replace('[', '').Replace(']', '') }
        # literal definitions -- only where the EXEC is code (not inside a comment or another text)
        foreach ($m in $script:Rx.Matches($Text)) {
            if ($mask.Substring($m.Index, 4) -ne $Text.Substring($m.Index, 4)) { continue }
            $defs.Add([pscustomobject]@{ Pos = $m.Index; Name = (& $norm $m.Groups[1].Value) })
        }
        # #1412 (a): EXEC (@x) / EXEC sp_executesql @x -- a definition when @x was last given a CREATE OR ALTER text before it
        $sites = @([regex]::Matches($mask, '(?i)\bEXEC(?:UTE)?\s*\(\s*@(\w+)\s*\)')) + @([regex]::Matches($mask, '(?i)\bEXEC(?:UTE)?\s+(?:sys\.)?sp_executesql\s+@(\w+)'))
        foreach ($s in $sites) {
            $v = [regex]::Escape($s.Groups[1].Value)
            $assign = @([regex]::Matches($mask.Substring(0, $s.Index), ('(?i)(?:\bDECLARE\s+|\bSET\s+|\bSELECT\s+|,\s*)@{0}\b(?:\s+n?varchar\s*\(\s*(?:max|\d+)\s*\))?\s*=(?!=)' -f $v)))
            if (-not $assign.Count) { continue }
            $a = $assign[-1]
            $after = $Text.Substring($a.Index + $a.Length, [Math]::Min(400, $Text.Length - $a.Index - $a.Length))
            $dm = [regex]::Match($after, ("(?i)^\s*N?'\s*CREATE\s+OR\s+ALTER\s+{0}\s+{1}" -f $script:Kinds, $script:NameRx))
            if ($dm.Success) { $defs.Add([pscustomobject]@{ Pos = $s.Index; Name = (& $norm $dm.Groups[1].Value) }) }
        }
        # #1412 (b): ONE forward pass over the code -- statement starts (; / BEGIN / END of a block / GO) and the blocks open
        $tokRx = [regex]'(?im)^[ \t]*GO[ \t]*$|;|(?<![@#.\w])(?:BEGIN(?:\s+(?:TRAN|TRANSACTION|DIALOG|CONVERSATION|DISTRIBUTED)\b)?|END|CASE)(?![\w])'
        $toks = $tokRx.Matches($mask)
        $out = New-Object System.Collections.Generic.List[object]
        $stmt = 0
        $stack = New-Object System.Collections.Generic.List[object]
        $ti = 0
        $condRx = '(?i)^(?:IF|ELSE|WHILE)\b'
        foreach ($d in @($defs | Sort-Object Pos)) {
            while ($ti -lt $toks.Count -and $toks[$ti].Index -lt $d.Pos) {
                $t = $toks[$ti]; $w = $t.Value.Trim().ToUpperInvariant(); $ti++
                if ($w -eq ';') { $stmt = $t.Index + 1 }
                elseif ($w -eq 'GO') { $stack.Clear(); $stmt = $t.Index + $t.Length }
                elseif ($w -match '^BEGIN\s') { }
                elseif ($w -eq 'BEGIN') { $head = $mask.Substring($stmt, $t.Index - $stmt).Trim(); $stack.Add([pscustomobject]@{ Kind = 'B'; Cond = ($head -match $condRx) }); $stmt = $t.Index + $t.Length }
                elseif ($w -eq 'CASE') { $stack.Add([pscustomobject]@{ Kind = 'C'; Cond = $false }) }
                elseif ($w -eq 'END') {
                    if ($stack.Count) { $top = $stack[$stack.Count - 1]; $stack.RemoveAt($stack.Count - 1); if ($top.Kind -eq 'B') { $stmt = $t.Index + $t.Length } }
                }
            }
            $head = $mask.Substring($stmt, $d.Pos - $stmt).Trim()
            $conditional = ($head -match $condRx) -or (@($stack | Where-Object { $_.Kind -eq 'B' -and $_.Cond }).Count -gt 0)
            if (-not $conditional) {
                $line = ([regex]::Matches($Text.Substring(0, $d.Pos), "`n")).Count + 1
                $out.Add([pscustomobject]@{ Name = $d.Name; File = $File; Line = $line })
            }
        }
        $out.ToArray()
    }
}

Describe 'the shipped schema defines each module once unconditionally' {
    It 'the lint catches what it is for (samples)' {
        $two = "EXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 1');`nEXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 2');"
        @(Get-SIUnconditionalDefinitions -Text $two -File 's' | Group-Object Name | Where-Object Count -gt 1).Count | Should -Be 1
        $guarded = "EXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 1');`nIF CHARINDEX(N'v2', ISNULL(OBJECT_DEFINITION(OBJECT_ID(N'x.P')), N'')) = 0`nEXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 2');"
        @(Get-SIUnconditionalDefinitions -Text $guarded -File 's' | Group-Object Name | Where-Object Count -gt 1).Count | Should -Be 0
        $variable = "EXEC (@SIStatsProc);`nEXEC (@SIStatsProc2);"
        @(Get-SIUnconditionalDefinitions -Text $variable -File 's').Count | Should -Be 0 -Because 'a variable never given a definition text is no definition'
        $comment = "-- EXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 1');`nEXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 2');"
        @(Get-SIUnconditionalDefinitions -Text $comment -File 's').Count | Should -Be 1
    }
    It '#1412 (a): a definition built in a variable counts -- by the module named in the text it was last given' {
        $v = "DECLARE @p nvarchar(max) = N'CREATE OR ALTER PROCEDURE x.P AS SELECT 1';`nEXEC (@p);`nEXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 2');"
        @(Get-SIUnconditionalDefinitions -Text $v -File 's' | Group-Object Name | Where-Object Count -gt 1).Count | Should -Be 1
        $sp = "SET @q = N'CREATE OR ALTER VIEW [x].[V] AS SELECT 1 AS A';`nEXEC sp_executesql @q;`nEXEC (N'CREATE OR ALTER VIEW x.V AS SELECT 2 AS A');"
        @(Get-SIUnconditionalDefinitions -Text $sp -File 's' | Group-Object Name | Where-Object Count -gt 1).Count | Should -Be 1 -Because 'sp_executesql and a bracketed name are the same module'
        # the variable re-used: each EXEC is the module of the text given LAST before it
        $reuse = "SET @h = N'CREATE OR ALTER FUNCTION x.A () RETURNS TABLE AS RETURN SELECT 1 AS A'; EXEC (@h);`nSET @h = N'CREATE OR ALTER FUNCTION x.B () RETURNS TABLE AS RETURN SELECT 1 AS B'; EXEC (@h);"
        @(Get-SIUnconditionalDefinitions -Text $reuse -File 's' | ForEach-Object Name) | Should -Be @('x.a', 'x.b')
        $other = "SELECT @s = Stmt FROM @todo WHERE N = @i; EXEC (@s);"
        @(Get-SIUnconditionalDefinitions -Text $other -File 's').Count | Should -Be 0
    }
    It '#1412 (b): the IF that GOVERNS the EXEC decides -- a block, a condition over lines; never the line before' {
        # an IF before a BEGIN block, the EXEC further down inside it: conditional (the line before is a PRINT)
        $block = "IF NOT EXISTS (SELECT 1`n    FROM sys.objects`n    WHERE name = N'P')`nBEGIN`n    PRINT 'making it';`n    EXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 1');`nEND;`nEXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 2');"
        @(Get-SIUnconditionalDefinitions -Text $block -File 's' | Group-Object Name | Where-Object Count -gt 1).Count | Should -Be 0
        # an IF line that governs ANOTHER statement does not make the next EXEC conditional
        $ended = "IF 1 = 1 PRINT 'a';`nEXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 1');`nEXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 2');"
        @(Get-SIUnconditionalDefinitions -Text $ended -File 's' | Group-Object Name | Where-Object Count -gt 1).Count | Should -Be 1
        # after an IF ... BEGIN ... END block the next statement is no longer governed by it
        $after = "IF 1 = 1`nBEGIN`n    PRINT 'a';`nEND`nEXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 1');`nEXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 2');"
        @(Get-SIUnconditionalDefinitions -Text $after -File 's' | Group-Object Name | Where-Object Count -gt 1).Count | Should -Be 1
        # a CASE ... END inside the block does not end the block; an ELSE branch is conditional
        $case = "IF 1 = 1`nBEGIN`n    DECLARE @k int = CASE WHEN 1 = 1 THEN 1 END;`n    EXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 1');`nEND`nELSE`n    EXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 2');"
        @(Get-SIUnconditionalDefinitions -Text $case -File 's').Count | Should -Be 0
        # a definition inside another definition's text is not one of its own
        $nested = "EXEC (N'CREATE OR ALTER PROCEDURE x.Q AS EXEC (N''CREATE OR ALTER PROCEDURE x.P AS SELECT 1'')');`nEXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 2');"
        @(Get-SIUnconditionalDefinitions -Text $nested -File 's' | Where-Object Name -eq 'x.p').Count | Should -Be 1
    }
    It 'no module of sql\*.sql has two unconditional CREATE OR ALTER definitions' {
        $all = foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'sql') -Filter '*.sql' -File) { Get-SIUnconditionalDefinitions -Text ([IO.File]::ReadAllText($f.FullName)) -File $f.Name }
        $dups = @($all | Group-Object Name | Where-Object Count -gt 1 | ForEach-Object { '{0}: {1}' -f $_.Name, (($_.Group | ForEach-Object { '{0}:{1}' -f $_.File, $_.Line }) -join ', ') })
        ($dups -join ' ;; ') | Should -BeNullOrEmpty -Because 'a module made twice in one apply flips on every re-apply -- guard the older one (made only while no newer one is there)'
        @($all).Count | Should -BeGreaterThan 20 -Because 'the lint must see the shipped definitions (control: it cannot pass by reading nothing)'
        # control (#1412 (a)): the variable-built definitions of the shipped schema are seen
        @($all | Where-Object { $_.Name -in 'sidata.historystampof', 'sidata.findinghistoryserves', 'sidata.vfinding' }).Count | Should -Be 3
    }
    It 'sidata.StatisticsRefresh: the v1 gate is made only while no newer gate (@Only) is there; its body is the released v1 text' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-data-schema.sql'))
        $i1 = $t.IndexOf("EXEC (N'CREATE OR ALTER PROCEDURE sidata.StatisticsRefresh @After")
        $i2 = $t.IndexOf("EXEC (N'CREATE OR ALTER PROCEDURE sidata.StatisticsRefresh @After", $i1 + 10)
        $i1 | Should -BeGreaterThan 0; $i2 | Should -BeGreaterThan $i1
        $guardLine = ($t.Substring(0, $i1).TrimEnd() -split "`r?`n")[-1]
        $guardLine | Should -Match "^IF CHARINDEX\(N'@Only', ISNULL\(OBJECT_DEFINITION\(OBJECT_ID\(N'sidata\.StatisticsRefresh'\)\), N''\)\) = 0$"
        # v1's text has no @Only, v2's has it: the guard tells them apart
        $v1 = $t.Substring($i1, $t.IndexOf("');", $i1) - $i1); $v2 = $t.Substring($i2, $t.IndexOf("');", $i2) - $i2)
        $v1 | Should -Not -Match '@Only'; $v2 | Should -Match '@Only nvarchar\(300\)'
        # #1412 (c): the guard keys on @Only -- the rule that every later gate keeps it is written beside it
        $t.Substring([Math]::Max(0, $i1 - 1200), [Math]::Min(1200, $i1)) | Should -Match 'EVERY later gate keeps @Only'
    }
}
