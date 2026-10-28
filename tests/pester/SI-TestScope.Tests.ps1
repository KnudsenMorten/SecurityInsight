#Requires -Version 5.1
<#
    WHERE THE GATE THINKS IT IS RUNNING (2026-09-30).

    The gate leaves out checks of the PRIVATE repository when it runs in a public (Community) copy --
    see _SITestScope.ps1. That is only safe while the decision is right: if the private repository ever
    read as a public copy, those checks would switch themselves off and the gate would still say READY.
    These tests pin the decision, and they run in BOTH places.
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '_SITestScope.ps1')
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

    # A fake tree: <root>\repo\SOLUTIONS\SecurityInsight, with the two markers switchable.
    function script:New-FakeTree([bool]$Manifest, [bool]$Sync) {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('si-scope-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $si   = Join-Path $root 'repo\SOLUTIONS\SecurityInsight'
        New-Item -ItemType Directory -Force -Path $si | Out-Null
        if ($Manifest) { Set-Content -LiteralPath (Join-Path $si 'solution.publish.json') -Value '{}' }
        if ($Sync) {
            New-Item -ItemType Directory -Force -Path (Join-Path $root 'repo\sync') | Out-Null
            Set-Content -LiteralPath (Join-Path $root 'repo\sync\Sync-AutomateIT.ps1') -Value '#'
        }
        return @{ Root = $root; SI = $si }
    }
}

Describe 'the gate knows which tree it is in' {

    It 'THIS tree reads as what it is -- a tree with a publish manifest is never taken for a public copy' {
        $scope = Get-SITestScope -SIRoot $script:SIRoot
        $scope | Should -Not -Be 'Ambiguous'
        if (Test-Path -LiteralPath (Join-Path $script:SIRoot 'solution.publish.json')) {
            $scope | Should -Be 'PrivateRepo' -Because 'the private repository must run every check'
        } else {
            $scope | Should -Be 'PublicCopy'
        }
    }

    It 'both markers = the private repository; neither = a public copy' {
        $t = New-FakeTree $true $true
        try { Get-SITestScope -SIRoot $t.SI | Should -Be 'PrivateRepo' } finally { Remove-Item -Recurse -Force $t.Root }
        $t = New-FakeTree $false $false
        try { Get-SITestScope -SIRoot $t.SI | Should -Be 'PublicCopy' } finally { Remove-Item -Recurse -Force $t.Root }
    }

    It 'one marker without the other is refused as Ambiguous, never guessed' {
        $t = New-FakeTree $true $false
        try { Get-SITestScope -SIRoot $t.SI | Should -Be 'Ambiguous' } finally { Remove-Item -Recurse -Force $t.Root }
        $t = New-FakeTree $false $true
        try { Get-SITestScope -SIRoot $t.SI | Should -Be 'Ambiguous' } finally { Remove-Item -Recurse -Force $t.Root }
    }

    It 'a public clone at a drive root (no grandparent folder) is a public copy, not an error' {
        # C:\SecurityInsight: Split-Path gives C:\ and then '' -- the shape that crashed four suites.
        { Get-SITestScope -SIRoot ([IO.Path]::GetPathRoot($env:SystemRoot) + 'SecurityInsight-not-here') } | Should -Not -Throw
        Get-SITestScope -SIRoot ([IO.Path]::GetPathRoot($env:SystemRoot) + 'SecurityInsight-not-here') | Should -Be 'PublicCopy'
    }
}

Describe 'the private-repository marker' {

    It 'is read from the file head and nowhere else' {
        $f = Join-Path ([IO.Path]::GetTempPath()) ('si-scope-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.Tests.ps1')
        try {
            Set-Content -LiteralPath $f -Value @('#Requires -Version 5.1', '# SI-TestScope: PrivateRepo', 'Describe x {}')
            Test-SITestFilePrivateRepoOnly -Path $f | Should -BeTrue
            Set-Content -LiteralPath $f -Value (@('#Requires -Version 5.1') + @(1..25 | ForEach-Object { '#' }) + @('# SI-TestScope: PrivateRepo'))
            Test-SITestFilePrivateRepoOnly -Path $f | Should -BeFalse
        } finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }

    It 'this suite is NOT marked -- it must run in both places' {
        Test-SITestFilePrivateRepoOnly -Path $PSCommandPath | Should -BeFalse
    }
}
