#Requires -Version 5.1
<#
.SYNOPSIS
    Where is this test suite running: the private AutomateIT repository, or a public (Community) copy?
.DESCRIPTION
    The same tests ship in both. Some of them check the PRIVATE repository itself -- the publish
    manifest, sync/, the repo-root .gitignore, git history, the internal-vm launchers -- none of which
    a public copy contains, because publish-stage.ps1 removes them. Run in a public copy, those checks
    have nothing to check, and they failed there by the hundred (2026-09-30), which buried the checks
    that DO apply to the copy people download.

    So a check that is about the private repository says so, in one of two ways:
      * a whole suite file: a line   # SI-TestScope: PrivateRepo   in its first 20 lines;
      * a single Describe / Context / It:   -Tag 'PrivateRepo'.
    Invoke-PrePublishGate.ps1 leaves both out in a PUBLIC copy, names every file it left out, and
    runs everything in the private repository.

    🔒 The two markers are read from the SAME two files publish-stage.ps1 is known to remove, and they
    must AGREE. One present without the other is neither a private checkout nor a public copy (a
    half-copied tree, a moved folder) -- that is refused, never guessed, because guessing "public"
    inside the private repository would silently switch checks off. A gate that is not running looks
    exactly like a gate with nothing to complain about.
#>

function Get-SITestScope {
    <#
      'PrivateRepo' | 'PublicCopy' | 'Ambiguous'.  -SIRoot is the SecurityInsight folder.
    #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $manifest = Test-Path -LiteralPath (Join-Path $SIRoot 'solution.publish.json')
    # SOLUTIONS\SecurityInsight -> SOLUTIONS -> repo root. A public clone sits at e.g. C:\SecurityInsight,
    # where there is no grandparent at all: Split-Path returns '' and must not be joined.
    $sync = $false
    $solutions = Split-Path -Parent $SIRoot
    if ($solutions) {
        $repo = Split-Path -Parent $solutions
        if ($repo) { $sync = Test-Path -LiteralPath (Join-Path $repo 'sync\Sync-AutomateIT.ps1') }
    }
    if ($manifest -and $sync)             { return 'PrivateRepo' }
    if (-not $manifest -and -not $sync)   { return 'PublicCopy' }
    return 'Ambiguous'
}

function Test-SITestFilePrivateRepoOnly {
    <# True when a suite file declares itself private-repository-only (see above). #>
    param([Parameter(Mandatory)][string]$Path)
    $head = @(Get-Content -LiteralPath $Path -TotalCount 20 -ErrorAction SilentlyContinue)
    return [bool]($head | Where-Object { $_ -match '^\s*#\s*SI-TestScope:\s*PrivateRepo\s*$' })
}
