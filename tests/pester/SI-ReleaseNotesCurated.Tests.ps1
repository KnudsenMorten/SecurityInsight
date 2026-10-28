#Requires -Version 5.1
# SI-TestScope: PrivateRepo
<#
    THE PUBLIC RELEASE NOTES ARE THE CURATED FILE, NOT THE MONOREPO'S COMMIT LOG.

    The 2.2 -> 3.0 upgrade rehearsal built the public payload with the real publish script: the public
    RELEASENOTES.md began with "Latest 30 commits" of the private monorepo -- internal numbers, lane branch names,
    SecurityInsight Pro work -- before the curated 3.0.0 section. The publish script supports
    "releaseNotesAutoLog": false (ships RELEASENOTES.md verbatim); SecurityInsight's own solution.publish.json sets it.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Pub = Get-Content -Raw (Join-Path $script:SIRoot 'solution.publish.json') | ConvertFrom-Json
}

Describe 'the public release notes' {
    It 'solution.publish.json turns the commit-log prefix OFF (releaseNotesAutoLog = false, a real boolean)' {
        $script:Pub.PSObject.Properties.Name | Should -Contain 'releaseNotesAutoLog'
        $script:Pub.releaseNotesAutoLog | Should -BeOfType [bool]
        $script:Pub.releaseNotesAutoLog | Should -BeFalse
    }
    It 'the curated RELEASENOTES.md exists and is shipped (the publish refuses releaseNotesAutoLog=false without it)' {
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'RELEASENOTES.md') | Should -BeTrue
        @($script:Pub.excludePaths) | Should -Not -Contain 'RELEASENOTES.md'
    }
    It 'the curated 3.0.0 section names no internal audit number' {
        $rn = Get-Content -Raw (Join-Path $script:SIRoot 'RELEASENOTES.md')
        $i = $rn.IndexOf('3.0.0')
        $i | Should -BeGreaterThan -1
        $j = $rn.IndexOf("`n## ", $i + 10)
        $sec = if ($j -gt $i) { $rn.Substring($i, $j - $i) } else { $rn.Substring($i) }
        $sec | Should -Not -Match '(?i)\baudit\s*#\s*\d+'
    }
}
