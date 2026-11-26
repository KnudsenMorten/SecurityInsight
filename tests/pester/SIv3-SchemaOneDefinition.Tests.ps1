#Requires -Version 7.0
<#
    ONE UNCONDITIONAL DEFINITION PER MODULE (2026-11-26, 3.1.52 gate: SIv3-WebDuringUpdate "the shipped schema twice").
    sql\si-data-schema.sql made sidata.StatisticsRefresh twice in every apply -- the v1 gate (no @Only) and, appended by
    #1372, the v2 gate (@Only) -- both as module-guarded EXEC ('CREATE OR ALTER ...'), so every update made v1 over v2 and
    v2 again (the gate flipped once per update; between the two a caller passing @Only failed). The fix guards the v1 EXEC
    (made only while no newer gate is there); its body text is unchanged (the #1372 append convention).
    THE LINT (a read of the shipped files, no runtime effect): no module (procedure / trigger / function / view) of
    sql\*.sql has two UNCONDITIONAL literal EXEC (N'CREATE OR ALTER ...') definitions. A definition preceded by an IF line
    is conditional (a version marker / newer-text check); a text built in a variable (EXEC (@x)) is not a literal one.
    OFFLINE: text only. NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Rx = [regex]"(?i)\bEXEC(?:UTE)?\s*\(\s*N?'\s*CREATE\s+OR\s+ALTER\s+(?:PROCEDURE|PROC|TRIGGER|FUNCTION|VIEW)\s+((?:\[[^\]']+\]|\w+)\.(?:\[[^\]']+\]|\w+))"
    function script:Get-SIUnconditionalDefinitions([string]$Text, [string]$File) {
        $lines = $Text -split "`r?`n"
        $out = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]
            $code = ($l -split '--', 2)[0]
            foreach ($m in $script:Rx.Matches($code)) {
                # the statement's own line before the EXEC, then the previous code line: an IF there makes it conditional
                $before = $code.Substring(0, $m.Index).Trim()
                $prev = ''
                for ($j = $i - 1; $j -ge 0; $j--) { $p = (($lines[$j] -split '--', 2)[0]).Trim(); if ($p) { $prev = $p; break } }
                $conditional = ($before -match '(?i)^IF\b') -or ($prev -match '(?i)^(IF|OR|AND)\b') -or ($prev -match '(?i)\)\s*$' -and $prev -match '(?i)^\s*(WHERE|OR|AND)\b')
                if (-not $conditional) { $out.Add([pscustomobject]@{ Name = $m.Groups[1].Value.ToLowerInvariant().Replace('[', '').Replace(']', ''); File = $File; Line = $i + 1 }) }
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
        @(Get-SIUnconditionalDefinitions -Text $variable -File 's').Count | Should -Be 0
        $comment = "-- EXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 1');`nEXEC (N'CREATE OR ALTER PROCEDURE x.P AS SELECT 2');"
        @(Get-SIUnconditionalDefinitions -Text $comment -File 's').Count | Should -Be 1
    }
    It 'no module of sql\*.sql has two unconditional CREATE OR ALTER definitions' {
        $all = foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'sql') -Filter '*.sql' -File) { Get-SIUnconditionalDefinitions -Text ([IO.File]::ReadAllText($f.FullName)) -File $f.Name }
        $dups = @($all | Group-Object Name | Where-Object Count -gt 1 | ForEach-Object { '{0}: {1}' -f $_.Name, (($_.Group | ForEach-Object { '{0}:{1}' -f $_.File, $_.Line }) -join ', ') })
        ($dups -join ' ;; ') | Should -BeNullOrEmpty -Because 'a module made twice in one apply flips on every re-apply -- guard the older one (made only while no newer one is there)'
        @($all).Count | Should -BeGreaterThan 20 -Because 'the lint must see the shipped definitions (control: it cannot pass by reading nothing)'
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
    }
}
