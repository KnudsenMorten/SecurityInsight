#Requires -Version 7.0
<#
    THE JOB ENTRY POINTS' LOAD CHAIN (SUP-2026-00687) -- helpers for SIv3-EntryPointLoads.Tests.ps1. Static (AST), no run.

    Get-SIJobEntryPoints   every script a caj-si-* job starts: the dispatch table (container\_shared\SI-ContainerConfig.ps1,
                           Script = '...') + the container start scripts (container\Start-*.ps1, container\Invoke-*.ps1).
    Get-SIFileLoads        the SI files one file dot-sources: `. (Join-Path ... 'x.ps1')`, `. ([IO.Path]::Combine(..., 'x.ps1'))`,
                           `. $var` (the .ps1 its assignment names) -- at the top or inside a function (a load on use).
    Get-SILoadClosure      an entry point + every file it loads, transitively, dependencies first.
    Get-SICalledSICommands the Verb-SI* commands a file calls, minus the ones it only calls behind Get-Command -Name <it>.
#>

function Get-SIRelPath([string]$Root, [string]$Path) { [IO.Path]::GetRelativePath($Root, $Path).Replace('\', '/') }

function Get-SIJobEntryPoints {
    param([Parameter(Mandatory)][string]$Root)
    $cfg = Get-Content -Raw -LiteralPath (Join-Path $Root 'container/_shared/SI-ContainerConfig.ps1')
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($cfg, "(?:Script\s*=\s*|\`$script\s*=\s*)'((?:engine|container|setup)/[^']+\.ps1)'")) { $list.Add($m.Groups[1].Value) }
    foreach ($f in Get-ChildItem -LiteralPath (Join-Path $Root 'container') -File -Filter '*.ps1') {
        if ($f.Name -match '^(Start|Invoke)-') { $list.Add('container/' + $f.Name) }
    }
    @($list | Where-Object { Test-Path -LiteralPath (Join-Path $Root $_) } | Sort-Object -Unique)
}

$script:SIFileIndex = $null
function Get-SIFileIndex([string]$Root) {
    if ($null -eq $script:SIFileIndex) {
        $script:SIFileIndex = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter '*.ps1' |
            Where-Object { $_.FullName -notmatch '[\\/](tests|\.git|node_modules|bin|obj)[\\/]' } |
            ForEach-Object { Get-SIRelPath $Root $_.FullName })
    }
    $script:SIFileIndex
}

function Resolve-SILoadTarget {
    <# the repo file a load names: the literal path segments after the last '..', matched as a path TAIL; several = the
       one nearest the loading file #>
    param([string]$Root, [string]$From, [string[]]$Segments)
    $parts = @(foreach ($s in $Segments) { foreach ($p in ($s -split '[\\/]')) { if ($p) { $p } } })
    $last = [Array]::LastIndexOf($parts, '..')
    if ($last -ge 0) { $parts = @($parts | Select-Object -Skip ($last + 1)) }
    if (-not $parts.Count -or $parts[-1] -notlike '*.ps1') { return $null }
    $tail = ($parts -join '/').ToLowerInvariant()
    $hits = @(Get-SIFileIndex $Root | Where-Object { $_.ToLowerInvariant() -eq $tail -or $_.ToLowerInvariant().EndsWith('/' + $tail) })
    if ($hits.Count -le 1) { return $hits | Select-Object -First 1 }
    $dir = ($From -replace '/[^/]+$', '').ToLowerInvariant()
    $hits | Sort-Object { $h = $_.ToLowerInvariant(); $n = 0; while ($n -lt [Math]::Min($h.Length, $dir.Length) -and $h[$n] -eq $dir[$n]) { $n++ }; -$n } | Select-Object -First 1
}

$script:SIAstCache = @{}
function Get-SIFileAst([string]$Root, [string]$Rel) {
    if (-not $script:SIAstCache.ContainsKey($Rel)) {
        $tok = $null; $err = $null
        $script:SIAstCache[$Rel] = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $Rel), [ref]$tok, [ref]$err)
    }
    $script:SIAstCache[$Rel]
}

$script:SILoadsCache = @{}
function Get-SIFileLoads {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Rel)
    if ($script:SILoadsCache.ContainsKey($Rel)) { return $script:SILoadsCache[$Rel] }
    $script:SILoadsCache[$Rel] = @(Get-SIFileLoadsUncached -Root $Root -Rel $Rel)
    $script:SILoadsCache[$Rel]
}

function Get-SIFileLoadsUncached {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Rel)
    $ast = Get-SIFileAst $Root $Rel
    # the path's literal segments (a command name such as Join-Path is a bare word, never a segment)
    $consts = { param($a) @($a.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.StringConstantType -ne [System.Management.Automation.Language.StringConstantType]::BareWord }, $true) | ForEach-Object { $_.Value }) }
    $out = [System.Collections.Generic.List[string]]::new()
    $dots = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot }, $true)
    foreach ($d in $dots) {
        $e = $d.CommandElements[0]
        $segs = @(& $consts $e)
        if (-not ($segs | Where-Object { $_ -like '*.ps1' }) -and $e -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $vn = $e.VariablePath.UserPath
            $asg = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.Left.VariablePath.UserPath -eq $vn }, $true)
            foreach ($a in $asg) { $s2 = @(& $consts $a.Right); if ($s2 | Where-Object { $_ -like '*.ps1' }) { $segs = $s2; break } }
        }
        $i = -1; for ($k = $segs.Count - 1; $k -ge 0; $k--) { if ($segs[$k] -like '*.ps1') { $i = $k; break } }
        if ($i -lt 0) { continue }
        $t = Resolve-SILoadTarget -Root $Root -From $Rel -Segments @($segs[0..$i])
        if ($t -and $t -ne $Rel) { $out.Add($t) }
    }
    @($out | Select-Object -Unique)
}

function Get-SILoadClosure {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Entry)
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $order = [System.Collections.Generic.List[string]]::new()
    $visit = $null
    $visit = {
        param($f)
        if (-not $seen.Add($f)) { return }
        foreach ($c in Get-SIFileLoads -Root $Root -Rel $f) { & $visit $c }
        $order.Add($f)
    }
    & $visit $Entry
    @($order)
}

$script:SICalledCache = @{}
function Get-SICalledSICommands {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Rel)
    if ($script:SICalledCache.ContainsKey($Rel)) { return $script:SICalledCache[$Rel] }
    $ast = Get-SIFileAst $Root $Rel
    $text = $ast.Extent.Text
    $names = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Dot }, $true) |
        ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -cmatch '^[A-Z][a-z]+-SI[A-Za-z0-9]+$' } | Select-Object -Unique)
    # a call behind Get-Command -Name <it> -- or behind Test-Path function:<it>, the same guard at 0.08 ms instead of 8 ms
    # (#1389) -- is optional by design (the file says what it does without it)
    $script:SICalledCache[$Rel] = @($names | Where-Object {
            $q = [regex]::Escape($_)
            $text -notmatch ("Get-Command\s+(-Name\s+)?['""]?" + $q + "\b") -and $text -notmatch ("Test-Path\s+(-Path\s+)?['""]?function:" + $q + "\b")
        })
    $script:SICalledCache[$Rel]
}

function Get-SITopFunctions {
    <# the functions a file defines at its TOP (not nested in a function or a script block): what dot-sourcing it defines #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Rel)
    @((Get-SIFileAst $Root $Rel).FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object {
        $p = $_.Parent; $nested = $false
        while ($p) { if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst] -or $p -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) { $nested = $true; break }; $p = $p.Parent }
        -not $nested
    } | ForEach-Object { $_.Name -replace '^(script|global|local):', '' } | Select-Object -Unique)
}

$script:SIDefinedCache = @{}
function Get-SIDefinedFunctions {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Rel)
    if ($script:SIDefinedCache.ContainsKey($Rel)) { return $script:SIDefinedCache[$Rel] }
    $script:SIDefinedCache[$Rel] = @((Get-SIFileAst $Root $Rel).FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        ForEach-Object { $_.Name -replace '^(script|global|local):', '' } | Select-Object -Unique)
    $script:SIDefinedCache[$Rel]
}
