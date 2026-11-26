#Requires -Version 5.1
<#
    #1403 (review of 3.1.51) THE ROW BUILDERS' HELPERS REACH EVERY ENGINE IMAGE. Since #1389 the four profile row builders
    (engine/asset-profiling/shared/Build-*ProfileRow.ps1) load their helpers ONCE, when the builder file is loaded -- so one
    helper file missing from an image fails EVERY row of that builder, not one. Like the #1385 updater check
    (SIv3-HistoryIndexQueue.Tests.ps1): every helper file a builder names is
      * in the repository (tracked),
      * carried by each engine Dockerfile that carries the builder (a COPY of the file, of a folder holding it, or of the
        whole build context), and not left out of the build context by .dockerignore,
      * in the Community payload whenever the builder is (solution.publish.json excludePaths).
    Offline, static. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Shared = Join-Path $script:SIRoot 'engine\asset-profiling\shared'
    $script:Builders = @(Get-ChildItem -LiteralPath $script:Shared -Filter 'Build-*ProfileRow.ps1' | Sort-Object Name)

    function script:ConvertTo-SIRelPath([string]$Full) {
        $root = [IO.Path]::GetFullPath($script:SIRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        $f = [IO.Path]::GetFullPath($Full)
        if (-not $f.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { return $null }
        $f.Substring($root.Length).Replace('\', '/')
    }

    # every helper file one builder names: the $__siRowHelper list (File = '...') and each Join-Path $PSScriptRoot '<file>'
    function script:Get-SIRowBuilderHelpers([string]$Path) {
        $src = [IO.File]::ReadAllText($Path)
        $dir = Split-Path -Parent $Path
        $rel = New-Object System.Collections.Generic.List[string]
        foreach ($m in [regex]::Matches($src, "File\s*=\s*'([^']+\.ps1)'")) { $rel.Add($m.Groups[1].Value) }
        foreach ($m in [regex]::Matches($src, "Join-Path\s+\`$PSScriptRoot\s+'([^']+\.(?:ps1|json))'")) { $rel.Add($m.Groups[1].Value) }
        @($rel | Select-Object -Unique | ForEach-Object { ConvertTo-SIRelPath ([IO.Path]::Combine($dir, ($_ -replace '[\\/]', [string][IO.Path]::DirectorySeparatorChar))) } | Where-Object { $_ } | Select-Object -Unique)
    }

    # what one Dockerfile's COPY lines carry from the build context (multi-stage --from copies are not the context)
    function script:Get-SIDockerCopySources([string]$Text) {
        $out = New-Object System.Collections.Generic.List[string]
        foreach ($m in [regex]::Matches($Text, '(?m)^\s*COPY\s+(.+?)\s*$')) {
            $tok = @(($m.Groups[1].Value -split '\s+') | Where-Object { $_ })
            if (@($tok | Where-Object { $_ -like '--from*' }).Count) { continue }
            $tok = @($tok | Where-Object { -not $_.StartsWith('--') })
            if ($tok.Count -lt 2) { continue }
            foreach ($s in $tok[0..($tok.Count - 2)]) { $out.Add($s.Trim('"')) }
        }
        , $out.ToArray()
    }
    function script:Test-SIDockerCarries([string[]]$Sources, [string]$Path) {
        foreach ($s in @($Sources)) {
            $n = $s.TrimStart('.', '/'); if ($s -eq '.' -or $s -eq './') { return $true }
            if ($n -eq $Path) { return $true }
            if ($n.EndsWith('/') -and $Path.StartsWith($n)) { return $true }
            if (-not [IO.Path]::HasExtension($n) -and $Path.StartsWith($n.TrimEnd('/') + '/')) { return $true }
        }
        $false
    }

    # the minimal .dockerignore evaluator of SI-ContainerTranscript.Tests.ps1 (duplicated: a test file stands alone)
    function script:Test-SIDockerContextIncludes([string[]]$Patterns, [string]$Path) {
        $segments = $Path -split '/'
        $probes = @(); for ($i = 0; $i -lt $segments.Count; $i++) { $probes += ($segments[0..$i] -join '/') }
        $included = $true
        foreach ($raw in $Patterns) {
            $line = $raw.Trim()
            if (-not $line -or $line.StartsWith('#')) { continue }
            $negate = $line.StartsWith('!'); if ($negate) { $line = $line.Substring(1).Trim() }
            $line = $line.TrimEnd('/'); if (-not $line) { continue }
            $rx = [regex]::Escape($line) -replace '\\\*\\\*', '<<GLOBSTAR>>' -replace '\\\*', '[^/]*' -replace '\\\?', '[^/]'
            $rx = $rx -replace '^<<GLOBSTAR>>/', '(?:.*/)?'; $rx = $rx -replace '<<GLOBSTAR>>', '.*'; $rx = '^' + $rx + '$'
            foreach ($probe in $probes) { if ($probe -match $rx) { if ($negate) { $included = $true } else { $included = $false } } }
        }
        $included
    }

    $ig = Join-Path $script:SIRoot '.dockerignore'
    $script:Ignore = @(); if (Test-Path -LiteralPath $ig) { $script:Ignore = @(Get-Content -LiteralPath $ig) }
    # the engine images built from the solution root
    $script:EngineDockerfiles = @('container/Dockerfile', 'container/updater/Dockerfile') | Where-Object { Test-Path -LiteralPath (Join-Path $script:SIRoot $_) }
    $script:Exclude = @((Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'solution.publish.json') | ConvertFrom-Json).excludePaths)
    function script:Test-SIExcludedFromCommunity([string]$Path) { foreach ($e in $script:Exclude) { $x = ([string]$e).TrimEnd('/'); if ($Path -eq $x -or $Path.StartsWith($x + '/')) { return $true } }; $false }
}

Describe '#1403 the row builders'' helpers reach every engine image' {
    It 'the four builders are found and each names its helpers' {
        @($script:Builders.Name) | Should -Be @('Build-AzureProfileRow.ps1', 'Build-EndpointProfileRow.ps1', 'Build-IdentityProfileRow.ps1', 'Build-PublicIpProfileRow.ps1')
        foreach ($b in $script:Builders) {
            $h = @(Get-SIRowBuilderHelpers $b.FullName)
            $h.Count | Should -BeGreaterThan 3 -Because "$($b.Name) loads its helpers at file load (#1389)"
            $h | Should -Contain 'engine/asset-profiling/shared/SI-SolutionVersion.ps1'
        }
        @(Get-SIRowBuilderHelpers (Join-Path $script:Shared 'Build-AzureProfileRow.ps1')) | Should -Contain 'engine/_shared/SI-AssetIdentity.ps1'
    }
    It 'every helper is in the repository' {
        $tracked = @(& git -C $script:SIRoot ls-files -- engine 2>$null | ForEach-Object { ($_ -replace '^SOLUTIONS/SecurityInsight/', '') })
        foreach ($b in $script:Builders) {
            foreach ($h in @(Get-SIRowBuilderHelpers $b.FullName)) {
                Test-Path -LiteralPath (Join-Path $script:SIRoot $h) | Should -BeTrue -Because "$($b.Name) loads $h"
                if ($tracked.Count -gt 0) { $tracked | Should -Contain $h -Because "$h must be committed, or no image carries it" }
            }
        }
    }
    It 'each engine Dockerfile that carries a builder carries every helper it loads, and .dockerignore never leaves one out' {
        $script:EngineDockerfiles | Should -Contain 'container/Dockerfile'
        foreach ($df in $script:EngineDockerfiles) {
            $src = Get-SIDockerCopySources ([IO.File]::ReadAllText((Join-Path $script:SIRoot $df)))
            foreach ($b in $script:Builders) {
                $bp = ConvertTo-SIRelPath $b.FullName
                if (-not (Test-SIDockerCarries $src $bp)) { continue }
                foreach ($h in @(Get-SIRowBuilderHelpers $b.FullName)) {
                    Test-SIDockerCarries $src $h | Should -BeTrue -Because "$df carries $bp, so it must carry $h (one missing helper fails every row since #1389)"
                    Test-SIDockerContextIncludes -Patterns $script:Ignore -Path $h | Should -BeTrue -Because "$h must survive .dockerignore"
                }
            }
        }
        # the orchestrator runs the profiling: it carries every builder
        $o = Get-SIDockerCopySources ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'container/Dockerfile')))
        foreach ($b in $script:Builders) { Test-SIDockerCarries $o (ConvertTo-SIRelPath $b.FullName) | Should -BeTrue }
    }
    It 'the check bites: an image that copies the builders folder but not a helper elsewhere fails it' {
        $src = Get-SIDockerCopySources "FROM x`nCOPY engine/asset-profiling/shared/ /app/engine/asset-profiling/shared/`nCOPY --from=build /out /app/out`n"
        Test-SIDockerCarries $src 'engine/asset-profiling/shared/Build-AzureProfileRow.ps1' | Should -BeTrue
        Test-SIDockerCarries $src 'engine/_shared/SI-AssetIdentity.ps1' | Should -BeFalse
        Test-SIDockerCarries (Get-SIDockerCopySources "COPY . /app/") 'engine/_shared/SI-AssetIdentity.ps1' | Should -BeTrue
        Test-SIDockerContextIncludes -Patterns @('engine/_shared/') -Path 'engine/_shared/SI-AssetIdentity.ps1' | Should -BeFalse
    }
    It 'a builder in the Community payload never loads a helper the Community payload leaves out' {
        foreach ($b in $script:Builders) {
            $bp = ConvertTo-SIRelPath $b.FullName
            if (Test-SIExcludedFromCommunity $bp) { continue }
            foreach ($h in @(Get-SIRowBuilderHelpers $b.FullName)) {
                Test-SIExcludedFromCommunity $h | Should -BeFalse -Because "$bp ships in the Community edition and loads $h"
            }
        }
    }
}
