#Requires -Version 5.1
<#
    EVERY RUN BANNER POINTS AT THE PUBLIC SUPPORT ROUTE.

    Found by the live 2.2 -> 3.0 upgrade test: the Community launchers' banner read
    "Support: GitHub Issues on the public repo, or <a personal address> (internal)" -- an internal marker in
    customer-facing output, and not the route README's Support section gives. Now: GitHub issues for Community,
    invardia.com for Pro, in every launcher banner and in the engines' own banners.

    SI_TEST_ROOT (optional) points the tests at another tree, e.g. an export of the code before the fix.
#>

BeforeDiscovery {
    $root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    if ($env:SI_TEST_ROOT) { $root = $env:SI_TEST_ROOT }
    $script:Launchers = @(Get-ChildItem -Path (Join-Path $root 'launcher') -Recurse -Filter 'launcher.*-vm.ps1' |
        ForEach-Object { @{ Name = ('{0}\{1}' -f $_.Directory.Name, $_.Name); Path = $_.FullName } })
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    if ($env:SI_TEST_ROOT) { $script:SIRoot = $env:SI_TEST_ROOT }
    function script:Get-SupportLines([string]$Path) {
        @(Get-Content -LiteralPath $Path | Where-Object { $_ -match '(?i)Write-Host.*Support' -or $_ -match '\$Support\s*=' })
    }
}

Describe 'launcher banner: <Name>' -ForEach $script:Launchers {
    It 'no internal marker in the support line' {
        @(Get-SupportLines $Path | Where-Object { $_ -match '\(internal\)' }).Count | Should -Be 0
    }
    It 'names the public route (GitHub issues) when it names one at all' {
        foreach ($l in (Get-SupportLines $Path)) {
            if ($l -match 'Support:\s') { $l | Should -Match 'github\.com/KnudsenMorten/SecurityInsight|GitHub Issues' }
        }
    }
}

Describe 'the engines'' own banners' {
    It 'the shared banner''s default support is the public issues page, with Pro at invardia.com' {
        $l = @(Get-SupportLines (Join-Path $script:SIRoot 'engine\asset-profiling\_shared\Write-SIStyle.ps1'))
        $l.Count | Should -BeGreaterThan 0
        ($l -join "`n") | Should -Match 'github\.com/KnudsenMorten/SecurityInsight/issues'
        ($l -join "`n") | Should -Match 'invardia\.com'
    }
    It 'every Community launcher states the Pro route too' {
        $missing = @(Get-ChildItem -Path (Join-Path $script:SIRoot 'launcher') -Recurse -Filter 'launcher.community-vm.ps1' | Where-Object {
            $s = @(Get-SupportLines $_.FullName) -join "`n"
            ($s -match 'Support:') -and ($s -match '@') })
        $missing.Count | Should -Be 0 -Because 'a personal mail address is not the support route'
    }
}
