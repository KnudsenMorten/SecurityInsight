#Requires -Version 5.1
# SI-TestScope: PrivateRepo
#   checks solution.publish.json, which a public copy does not carry (see _SITestScope.ps1)
<#
    THE v3 DESIGN DOCS NEVER REACH THE PUBLIC MIRROR (#109).

    docs/ holds two public files (FEATURES.md, DESIGN.md) beside six internal v3/ServiceNow design docs that
    carry tenant data, and the publish strip matched names only (REQUIREMENTS/TESTS/CLAUDE). Operator ruling
    2026-09-29: strip them at publish. SI lists them in `excludePaths` in its own solution.publish.json -- the
    framework's opt-in per-solution exclusion (PUB-5, built on main 2026-09-14 and honoured by
    .github/scripts/publish-stage.ps1). Entries are EXACT paths, not globs, so this test is what keeps a new
    internal doc from silently publishing: it fails until the new file is listed.
#>

BeforeAll {
    $script:SIRoot   = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $script:SIRoot)
    $script:Manifest = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'solution.publish.json') | ConvertFrom-Json
    $script:Excluded = @($script:Manifest.excludePaths | ForEach-Object { ("$_" -replace '\\', '/').Trim('/') })
}

Describe 'SI internal design docs are excluded at publish' {
    It 'every docs/V3-*.md and docs/SERVICENOW-*.md present is listed in excludePaths' {
        $docs = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'docs') -File |
            Where-Object { $_.Name -like 'V3-*.md' -or $_.Name -like 'SERVICENOW-*.md' })
        $docs.Count | Should -BeGreaterThan 0
        foreach ($d in $docs) {
            $script:Excluded | Should -Contain ('docs/' + $d.Name) -Because "docs/$($d.Name) would publish"
        }
    }
    It 'the public docs are NOT excluded' {
        foreach ($pub in 'docs/FEATURES.md', 'docs/DESIGN.md', 'docs') {
            $script:Excluded | Should -Not -Contain $pub -Because "$pub must publish"
        }
    }
    It 'every excludePaths entry exists (a stale entry hides a rename that now publishes)' {
        foreach ($e in $script:Excluded) {
            Test-Path -LiteralPath (Join-Path $script:SIRoot $e) | Should -BeTrue -Because "$e is listed but missing"
        }
    }
    It 'the staging script consumes excludePaths (the manifest field is not decorative)' {
        $stage = Join-Path $script:RepoRoot '.github\scripts\publish-stage.ps1'
        if (-not (Test-Path -LiteralPath $stage)) { Set-ItResult -Skipped -Because 'repo-level staging script not in this checkout'; return }
        (Get-Content -Raw -LiteralPath $stage) | Should -Match "PSObject\.Properties\.Name -contains 'excludePaths'"
    }
}
