#Requires -Version 5.1
<#
    SECURITYINSIGHT'S OWN YAML READER (engine/_shared/SI-Yaml.ps1) -- no powershell-yaml module.

      * PARITY: every shipped YAML file reads deep-equal to powershell-yaml's ConvertFrom-Yaml (same
        dictionary/list types, same scalar types and values, same key order with -Ordered), on LF and
        CRLF text. Runs when powershell-yaml is installed; skipped (not failed) when it is not.
      * GOLDEN FIXTURES (always run): every YAML feature SecurityInsight's files use, with the exact
        expected structure -- including the traps: colons inside // comments in |- blocks, KQL with |
        and # inside block scalars, keys with dots.
      * REFUSAL: anything outside that subset fails loudly with <file>:<line>.
      * SPEED: the whole shipped tree and the Risk Analysis catalogue load inside a generous bound.
      * WIRING: no ConvertFrom-Yaml / ConvertTo-Yaml / Import-Module powershell-yaml left in engine/,
        setup/, launcher/, container/ (AST), and powershell-yaml in no module list or image.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')

    function script:Compare-SIYamlDeep {
        <# First difference between two parsed structures, or $null when deep-equal (types included). #>
        param($A, $B, [string]$Path = '$')
        if ($null -eq $A -and $null -eq $B) { return $null }
        if ($null -eq $A -or $null -eq $B) { return ('{0}: one side is null (<{1}> vs <{2}>)' -f $Path, $A, $B) }
        if ($A.GetType() -ne $B.GetType()) { return ('{0}: type {1} vs {2}' -f $Path, $A.GetType().FullName, $B.GetType().FullName) }
        if ($A -is [System.Collections.IDictionary]) {
            $ka = @($A.Keys); $kb = @($B.Keys)
            if ($ka.Count -ne $kb.Count) { return ('{0}: {1} keys vs {2}' -f $Path, $ka.Count, $kb.Count) }
            if ($A -is [System.Collections.Specialized.OrderedDictionary]) {
                for ($i = 0; $i -lt $ka.Count; $i++) { if (-not [string]::Equals([string]$ka[$i], [string]$kb[$i], [StringComparison]::Ordinal)) { return ('{0}: key order {1} vs {2}' -f $Path, $ka[$i], $kb[$i]) } }
            }
            foreach ($k in $ka) {
                if (-not @($kb | Where-Object { [string]::Equals([string]$_, [string]$k, [StringComparison]::Ordinal) }).Count) { return ('{0}: key {1} missing' -f $Path, $k) }
                $d = Compare-SIYamlDeep -A $A[$k] -B $B[$k] -Path ($Path + '.' + $k); if ($d) { return $d }
            }
            return $null
        }
        if ($A -is [System.Collections.IList]) {
            if ($A.Count -ne $B.Count) { return ('{0}: {1} items vs {2}' -f $Path, $A.Count, $B.Count) }
            for ($i = 0; $i -lt $A.Count; $i++) { $d = Compare-SIYamlDeep -A $A[$i] -B $B[$i] -Path ('{0}[{1}]' -f $Path, $i); if ($d) { return $d } }
            return $null
        }
        if ($A -is [double] -and [double]::IsNaN($A) -and [double]::IsNaN($B)) { return $null }
        if (-not $A.Equals($B)) { return ('{0}: <{1}> vs <{2}>' -f $Path, $A, $B) }
        return $null
    }

    function script:Get-SIShippedYaml {
        @(Get-ChildItem -LiteralPath $script:SIRoot -Recurse -File |
          Where-Object { $_.Name -match '\.ya?ml$' -and $_.FullName -notmatch '[\\/](tests|node_modules|bin|obj)[\\/]' })
    }

    function script:L { param([object[]]$Items) $l = New-Object 'System.Collections.Generic.List[object]'; foreach ($x in $Items) { $l.Add($x) }; , $l }
}

Describe 'parity with powershell-yaml on every shipped YAML file' {
    BeforeAll {
        $script:HasRef = [bool](Get-Module -ListAvailable -Name powershell-yaml)
        if ($script:HasRef) { Import-Module powershell-yaml -ErrorAction Stop }
        $script:Shipped = Get-SIShippedYaml
    }

    It 'there are shipped YAML files to compare (the rule tree, the report catalogue, tagging, decisions)' {
        $script:Shipped.Count | Should -BeGreaterThan 1000
    }

    It 'every file reads deep-equal (hashtables, LF)' {
        if (-not $script:HasRef) { Set-ItResult -Skipped -Because 'powershell-yaml is not installed (the reference parser); the golden fixtures below still run'; return }
        $diffs = New-Object System.Collections.Generic.List[string]; $equal = 0
        foreach ($f in $script:Shipped) {
            $t = [IO.File]::ReadAllText($f.FullName).Replace("`r`n", "`n")
            $ref = ConvertFrom-Yaml -Yaml $t
            try { $mine = ConvertFrom-SIYaml -Yaml $t -SourceName $f.Name } catch { $diffs.Add(('{0}: refused: {1}' -f $f.Name, $_.Exception.Message)); continue }
            $d = Compare-SIYamlDeep -A $ref -B $mine
            if ($d) { $diffs.Add(('{0}: {1}' -f $f.Name, $d)) } else { $equal++ }
        }
        Write-Host ('      parity (hashtables, LF): {0} / {1} files equal' -f $equal, $script:Shipped.Count)
        ($diffs | Select-Object -First 20) -join "`n" | Should -BeNullOrEmpty
        $equal | Should -Be $script:Shipped.Count
    }

    It 'every file reads deep-equal with -Ordered, on CRLF text (key order included)' {
        if (-not $script:HasRef) { Set-ItResult -Skipped -Because 'powershell-yaml is not installed'; return }
        $diffs = New-Object System.Collections.Generic.List[string]; $equal = 0
        foreach ($f in $script:Shipped) {
            $t = [IO.File]::ReadAllText($f.FullName).Replace("`r`n", "`n").Replace("`n", "`r`n")
            $ref = ConvertFrom-Yaml -Yaml $t -Ordered
            try { $mine = ConvertFrom-SIYaml -Yaml $t -SourceName $f.Name -Ordered } catch { $diffs.Add(('{0}: refused: {1}' -f $f.Name, $_.Exception.Message)); continue }
            $d = Compare-SIYamlDeep -A $ref -B $mine
            if ($d) { $diffs.Add(('{0}: {1}' -f $f.Name, $d)) } else { $equal++ }
        }
        Write-Host ('      parity (-Ordered, CRLF): {0} / {1} files equal' -f $equal, $script:Shipped.Count)
        ($diffs | Select-Object -First 20) -join "`n" | Should -BeNullOrEmpty
    }

    It 'a JSON document (how SecurityInsight Pro materialises its catalogues in *.yaml files) reads deep-equal' {
        if (-not $script:HasRef) { Set-ItResult -Skipped -Because 'powershell-yaml is not installed'; return }
        foreach ($rel in 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml', 'asset-profiling-enrichment\endpoint\AssetTagging.locked.yaml', 'config\asset-decisions.custom.sample.yaml') {
            $src = ConvertFrom-SIYaml -Path (Join-Path $script:SIRoot $rel) -Ordered
            foreach ($json in @(($src | ConvertTo-Json -Depth 30), ($src | ConvertTo-Json -Depth 30 -Compress))) {
                foreach ($ord in $false, $true) {
                    $d = Compare-SIYamlDeep -A (ConvertFrom-Yaml -Yaml $json -Ordered:$ord) -B (ConvertFrom-SIYaml -Yaml $json -Ordered:$ord)
                    $d | Should -BeNullOrEmpty -Because "$rel as JSON (ordered=$ord)"
                }
            }
        }
        $t = '{"a": 1, "b": 1.5, "c": [true, null, "x", 3000000000, -2.0e3], "d": {}, "e": [], "f": "1", "g": "a\"b\\c\u00e6"}'
        Compare-SIYamlDeep -A (ConvertFrom-Yaml -Yaml $t) -B (ConvertFrom-SIYaml -Yaml $t) | Should -BeNullOrEmpty
        $t = '[{"x": 1}]'
        Compare-SIYamlDeep -A (ConvertFrom-Yaml -Yaml $t) -B (ConvertFrom-SIYaml -Yaml $t) | Should -BeNullOrEmpty
    }

    It 'the scalar typing matches powershell-yaml value for value' {
        if (-not $script:HasRef) { Set-ItResult -Skipped -Because 'powershell-yaml is not installed'; return }
        $t = @(
            'a: 1', 'b: -7', 'c: 1.0', 'd: 1.5', 'e: .5', 'f: 1e3', 'g: 3000000000', 'h: 99999999999999999999',
            'i: NaN', 'j: Infinity', 'k: -Infinity', 'l: true', 'm: False', 'n: TRUE', 'o: yes', 'p: ~', 'q: null',
            'r: Null', 's: NULL', 't:', 'u: 007', 'v: 0x10', 'w: 1_000', 'x: +5', 'y: 12abc', 'z: nan', 'aa: tRuE',
            'ab: infinity', 'ac: 1.2.3', 'ad: -', 'ae: 1e', 'af: e5', 'ag: ''3''', 'ah: "true"', 'ai: [1, 1.5, true, ~, x, null]'
        ) -join "`n"
        $t = $t.Replace("ad: -`n", "ad: '-'`n")
        Compare-SIYamlDeep -A (ConvertFrom-Yaml -Yaml $t -Ordered) -B (ConvertFrom-SIYaml -Yaml $t -Ordered) | Should -BeNullOrEmpty
    }
}

Describe 'golden fixtures -- the YAML subset SecurityInsight uses' {
    It 'block mappings, nested mappings, keys with dots, plain and quoted values' {
        $y = "id:        Rule.One`npurpose:   'Domain: Controller'`nnested:`n  inner.key: value`n  deeper:`n    x: ""dq"""
        $o = ConvertFrom-SIYaml -Yaml $y
        $o | Should -BeOfType [hashtable]
        $o.id | Should -BeExactly 'Rule.One'
        $o.purpose | Should -BeExactly 'Domain: Controller'
        $o.nested['inner.key'] | Should -BeExactly 'value'
        $o.nested.deeper.x | Should -BeExactly 'dq'
    }
    It 'a sequence at its key''s indentation, a sequence of maps, a nested sequence, null items' {
        $y = "list:`n- a`n- b`nmaps:`n  - id: one`n    tier: 0`n  - id: two`n    set:`n      Tier: 3`nouter:`n  -`n    - x`n  -`nlast: z"
        $o = ConvertFrom-SIYaml -Yaml $y
        $o.list.GetType().Name | Should -Be 'List`1'
        @($o.list) | Should -Be @('a', 'b')
        $o.maps[0].id | Should -Be 'one'; $o.maps[0].tier | Should -Be 0; $o.maps[0].tier | Should -BeOfType [int]
        $o.maps[1].set.Tier | Should -Be 3
        $o.outer.Count | Should -Be 2
        @($o.outer[0]) | Should -Be @('x')
        $null -eq $o.outer[1] | Should -BeTrue
        $o.last | Should -Be 'z'
    }
    It 'flow sequences: plain, single-quoted with an escaped quote, empty, a trailing comma, a trailing comment' {
        $o = ConvertFrom-SIYaml -Yaml "a: [WindowsServer, Linux]`nb: ['it''s', 'x, y']`nc: []`nd: [1, two,]   # note"
        @($o.a) | Should -Be @('WindowsServer', 'Linux')
        @($o.b) | Should -Be @("it's", 'x, y')
        $o.c.Count | Should -Be 0; $o.c.GetType().Name | Should -Be 'List`1'
        $o.d[0] | Should -BeOfType [int]; $o.d[1] | Should -Be 'two'; $o.d.Count | Should -Be 2
    }
    It 'comments: full-line at any indentation, trailing after plain / quoted values, inside nothing else' {
        $y = "# head`na: 1   # one`n   # indented comment`nb: 'x'  # two`nc: d#not-a-comment"
        $o = ConvertFrom-SIYaml -Yaml $y
        $o.a | Should -Be 1; $o.b | Should -Be 'x'; $o.c | Should -BeExactly 'd#not-a-comment'
    }
    It 'single quotes ('''' escape) and double quotes (backslash escapes) stay strings, never typed' {
        $bs = [string][char]92   # a backslash, kept out of this file's own escapes
        $o = ConvertFrom-SIYaml -Yaml ("a: 'it''s'`nb: ""tab" + $bs + "there " + $bs + """q" + $bs + """ " + $bs + "u00e6""`nc: '3'`nd: ""true""")
        $o.a | Should -BeExactly "it's"
        $o.b | Should -BeExactly ("tab`there ""q"" " + [char]0xE6)
        $o.c | Should -BeOfType [string]; $o.d | Should -BeOfType [string]
    }
    It 'plain scalars over several lines fold with spaces; a blank line becomes a line break' {
        $y = "ReportPurpose: This report highlights`n  overdue CVEs,`n  prioritised.`n`n  Second paragraph.`nnext: 1"
        (ConvertFrom-SIYaml -Yaml $y).ReportPurpose | Should -BeExactly "This report highlights overdue CVEs, prioritised.`nSecond paragraph."
    }
    It 'KQL in a |- block keeps | # : and // comments with colons verbatim' {
        $y = "ReportQuery:`n- |-`n    // Note: colons: in comments are fine`n    let x = 1; // #hash`n    T | where a == ""b: c"" # not a comment`n`n    | project a`nnext: 1"
        $o = ConvertFrom-SIYaml -Yaml $y
        $o.ReportQuery[0] | Should -BeExactly ("// Note: colons: in comments are fine`nlet x = 1; // #hash`nT | where a == ""b: c"" # not a comment`n`n| project a")
        $o.next | Should -Be 1
    }
    It 'literal | keeps one final line break; |- strips it; more-indented lines keep their extra spaces' {
        $o = ConvertFrom-SIYaml -Yaml "a: |`n  one`n    two`n`n`nb: |-`n  x`nc: 1"
        $o.a | Should -BeExactly "one`n  two`n"
        $o.b | Should -BeExactly 'x'
    }
    It 'folded > and >- join lines with spaces, keep blank lines and more-indented lines' {
        $o = ConvertFrom-SIYaml -Yaml "a: >-`n  one`n  two`n`n  three`n    more`n  four`nb: >`n  x`n  y`nc: 1"
        $o.a | Should -BeExactly "one two`nthree`n  more`nfour"
        $o.b | Should -BeExactly "x y`n"
    }
    It 'scalar typing: int, long, decimal, double, bool, null -- the way powershell-yaml types them' {
        $o = ConvertFrom-SIYaml -Yaml "a: 3`nb: 3000000000`nc: 1.5`nd: NaN`ne: true`nf: ~`ng:`nh: null`ni: 007`nj: 1.0`nk: v1.2"
        $o.a | Should -BeOfType [int]; $o.b | Should -BeOfType [long]; $o.c | Should -BeOfType [decimal]
        [double]::IsNaN($o.d) | Should -BeTrue; $o.e | Should -BeOfType [bool]
        $null -eq $o.f | Should -BeTrue; $null -eq $o.g | Should -BeTrue; $null -eq $o.h | Should -BeTrue
        $o.i | Should -Be 7; $o.j | Should -BeOfType [int]; $o.k | Should -BeExactly 'v1.2'
    }
    It 'CRLF, a UTF-8 BOM and one leading --- read the same as plain LF' {
        $lf = ConvertFrom-SIYaml -Yaml "a: 1`nb:`n  - x"
        $crlf = ConvertFrom-SIYaml -Yaml ([string][char]0xFEFF + "---`r`na: 1`r`nb:`r`n  - x`r`n")
        Compare-SIYamlDeep -A $lf -B $crlf | Should -BeNullOrEmpty
    }
    It 'returns the powershell-yaml shapes: [hashtable], [ordered] with -Ordered (key order kept), List[object] at the root' {
        (ConvertFrom-SIYaml -Yaml "b: 1`na: 2") | Should -BeOfType [hashtable]
        $o = ConvertFrom-SIYaml -Yaml "b: 1`na: 2`nc: 3" -Ordered
        $o | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
        @($o.Keys) | Should -Be @('b', 'a', 'c')
        $r = ConvertFrom-SIYaml -Yaml "- a`n- b"
        $r.GetType().FullName | Should -BeLike 'System.Collections.Generic.List*'
        $r.Count | Should -Be 2
    }
    It 'keys are case-insensitive like a PowerShell hashtable (a case variant overwrites, as in powershell-yaml)' {
        $o = ConvertFrom-SIYaml -Yaml "Tier: 1`ntier: 2"
        $o.Count | Should -Be 1; $o.TIER | Should -Be 2
    }
    It 'empty text and comment-only text give nothing' {
        $null -eq (ConvertFrom-SIYaml -Yaml '') | Should -BeTrue
        $null -eq (ConvertFrom-SIYaml -Yaml "# only`n   # comments`n") | Should -BeTrue
    }
    It 'pipeline input is joined with line breaks, -Path reads a file and names it in errors' {
        $o = @('a: 1', 'b: 2') | ConvertFrom-SIYaml
        $o.a | Should -Be 1; $o.b | Should -Be 2
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-yaml-{0}.yaml' -f [guid]::NewGuid())
        try {
            [IO.File]::WriteAllText($tmp, "ok: 1`nbad: &anchor x`n")
            { ConvertFrom-SIYaml -Path $tmp } | Should -Throw ('*' + [IO.Path]::GetFileName($tmp) + ':2:*')
        } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
    }
}

Describe 'anything outside the subset is refused with <file>:<line>' {
    It '<Name> is refused at line <Line>' -ForEach @(
        @{ Name = 'an anchor';                        Yaml = "a: 1`nb: &x 2";                 Line = 2 }
        @{ Name = 'an alias';                         Yaml = "a: 1`nb: *x";                   Line = 2 }
        @{ Name = 'a tag';                            Yaml = "a: !!str 1";                    Line = 1 }
        @{ Name = 'a flow mapping';                   Yaml = "a: 1`nb: {c: 1}";               Line = 2 }
        @{ Name = 'a flow mapping inside a list';     Yaml = "a: [x, {c: 1}]";                Line = 1 }
        @{ Name = 'a multi-line single-quoted string'; Yaml = "a: 'one`n  two'";               Line = 1 }
        @{ Name = 'a multi-line double-quoted string'; Yaml = "a: ""one`n  two""";             Line = 1 }
        @{ Name = 'a multi-line [ ] list';            Yaml = "a: [x,`n  y]";                  Line = 1 }
        @{ Name = 'keep chomping |+';                 Yaml = "a: |+`n  x";                    Line = 1 }
        @{ Name = 'an indentation indicator |2';      Yaml = "a: |2`n  x";                    Line = 1 }
        @{ Name = 'a second document';                Yaml = "a: 1`n---`nb: 2";               Line = 2 }
        @{ Name = 'a document end marker';            Yaml = "a: 1`n...";                     Line = 2 }
        @{ Name = 'a directive';                      Yaml = "%YAML 1.2`na: 1";               Line = 1 }
        @{ Name = 'tab indentation';                  Yaml = "a:`n`tb: 1";                    Line = 2 }
        @{ Name = 'a quoted key';                     Yaml = "'a': 1";                        Line = 1 }
        @{ Name = 'a duplicate key';                  Yaml = "a: 1`nb: 2`na: 3";              Line = 3 }
        @{ Name = 'a nested - - sequence';            Yaml = "a:`n  - - x";                   Line = 2 }
        @{ Name = 'a key without a space (id:Broken)'; Yaml = "id:Broken`nx: 1";              Line = 1 }
        @{ Name = 'a plain value holding ": "';       Yaml = "a: b: c";                       Line = 1 }
        @{ Name = 'a continuation line holding ": "'; Yaml = "a: b`n  c: d";                  Line = 2 }
        @{ Name = 'a misaligned key';                 Yaml = "a:`n    b: 1`n  c: 2";          Line = 3 }
        @{ Name = 'a "- item" where a key belongs';   Yaml = "a: 1`n- x";                     Line = 2 }
        @{ Name = 'a complex key';                    Yaml = "? a`n: b";                      Line = 1 }
    ) {
        { ConvertFrom-SIYaml -Yaml $Yaml -SourceName 'fixture.yaml' } | Should -Throw ("fixture.yaml:{0}:*" -f $Line)
    }
}

Describe 'speed' {
    It 'loads the whole shipped YAML tree and the Risk Analysis catalogue inside a generous bound' {
        $files = Get-SIShippedYaml
        $texts = @($files | ForEach-Object { [IO.File]::ReadAllText($_.FullName) })
        $sw = [Diagnostics.Stopwatch]::StartNew()
        foreach ($t in $texts) { $null = ConvertFrom-SIYaml -Yaml $t }
        $all = $sw.Elapsed.TotalSeconds
        $ra = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        $sw.Restart(); $null = ConvertFrom-SIYaml -Yaml $ra; $raT = $sw.Elapsed.TotalSeconds
        Write-Host ('      {0} files in {1:N1}s; Risk Analysis catalogue in {2:N2}s ({3})' -f $texts.Count, $all, $raT, $PSVersionTable.PSVersion)
        # Measured on PS 5.1: powershell-yaml 33 s / 10 s, this reader ~5 s / ~0.7 s. The bound catches a regression
        # to the old order of magnitude without failing on a slow CI runner.
        $all | Should -BeLessThan 30
        $raT | Should -BeLessThan 6
    }
}

Describe 'wiring: nothing reads YAML through powershell-yaml any more' {
    BeforeAll {
        $script:CodeFiles = @(
            foreach ($d in 'engine', 'setup', 'launcher', 'container') {
                Get-ChildItem -LiteralPath (Join-Path $script:SIRoot $d) -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.ps1', '.psm1' }
            }
            Get-ChildItem -LiteralPath $script:SIRoot -File -Filter '*.ps1'
        )
    }
    It 'no ConvertFrom-Yaml / ConvertTo-Yaml call and no Import-Module / Install-Module powershell-yaml (AST)' {
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($f in $script:CodeFiles) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $name = $c.GetCommandName()
                if ($name -in 'ConvertFrom-Yaml', 'ConvertTo-Yaml') { $hits.Add(('{0}:{1} {2}' -f $f.Name, $c.Extent.StartLineNumber, $name)) }
                if ($name -in 'Import-Module', 'Install-Module', 'Ensure-Module' -and $c.Extent.Text -match 'powershell-yaml') { $hits.Add(('{0}:{1} {2}' -f $f.Name, $c.Extent.StartLineNumber, $c.Extent.Text)) }
            }
        }
        $hits -join "`n" | Should -BeNullOrEmpty
    }
    It 'every engine file that reads YAML loads the reader it calls' {
        # Found, not listed: a list here would have to name the Pro-only engines, which the Community copy does not have.
        $readers = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'engine') -Recurse -File -Filter '*.ps1' |
                     Where-Object { $_.Name -ne 'SI-Yaml.ps1' -and (Get-Content -Raw -LiteralPath $_.FullName) -match 'ConvertFrom-SIYaml' })
        $readers.Count | Should -BeGreaterThan 7
        foreach ($f in $readers) {
            (Get-Content -Raw -LiteralPath $f.FullName) | Should -Match 'SI-Yaml\.ps1' -Because "$($f.Name) must load the reader it calls"
        }
        @($readers | Where-Object { $_.Name -in 'Get-SIRuleSet.ps1', 'Invoke-Enrich.ps1', 'AssetTagging.ps1', 'Invoke-RiskAnalysis.ps1' }).Count | Should -Be 4
    }
    It 'powershell-yaml is in no module list and not in the container image' {
        # the engines carry no module installer any more (#305), and since setup signs in without modules neither does setup:
        # its module list (setup\_shared\Ensure-Module.ps1) is gone. Nothing under setup installs or imports the module.
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'setup\_shared\Ensure-Module.ps1') | Should -BeFalse
        foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'setup') -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' }) {
            $code = ((Get-Content -LiteralPath $f.FullName) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            $code | Should -Not -Match "(Install|Import)-Module[^`n]*powershell-yaml" -Because $f.Name
        }
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\Dockerfile')) | Should -Not -Match 'powershell-yaml'
    }
    It 'a running engine does not load the powershell-yaml module (the rule loader on a real tree)' {
        # the engine's own log helpers, as a run loads them: a tree with operator *.custom.yaml files makes the loader
        # report its locked/custom de-duplication through Write-SIInfo
        . (Join-Path $script:SIRoot 'engine\asset-profiling\_shared\Write-SIStyle.ps1')
        . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Get-SIRuleSet.ps1')
        $rules = Get-SIRuleSet -Engine endpoint 3>$null 6>$null; $rules = @($rules)
        $rules.Count | Should -BeGreaterThan 500
        # (the parity Describe above may have imported it on purpose; the loader itself never asks for it)
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Get-SIRuleSet.ps1')) | Should -Not -Match 'Import-Module\s+.?powershell-yaml'
    }
}
