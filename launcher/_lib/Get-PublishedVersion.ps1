#Requires -Version 5.1
<#
.SYNOPSIS
    Resolves the running release version for the launcher banner.

.DESCRIPTION
    Each launcher dot-sources this file early (before Write-Banner) and calls:

        $versionStamp = Get-PublishedVersion -RepoRoot $InstallPath -Solution 'SecurityInsight'

    Resolution order:
      1. <RepoRoot>/VERSION.txt    -- the publish workflow stamps this when
                                      shipping to a public/community repo.
      2. `git describe --tags`     -- works when running from the monorepo or
                                      any other clone of the source repo.
      3. '(dev)'                   -- fallback (no git, no VERSION.txt).

    This gives the same banner experience in BOTH community installs (where
    VERSION.txt is present) and internal/dev runs from the monorepo (where
    git describe fills in).

.NOTES
    Function     : Get-PublishedVersion
    Solution     : All
    Developed by : Morten Knudsen, Microsoft MVP
#>

function Get-PublishedVersion {
    [CmdletBinding()]
    param(
        [string]$RepoRoot,
        [string]$Solution = 'SecurityInsight'
    )
    if (-not $RepoRoot) { return '(dev)' }

    # Layer 1: per-solution VERSION file -- canonical for monorepo + internal
    # AutomateIT_InstallUpdate installs (where root VERSION.txt holds the
    # AutomateIT install marker, NOT the SI release). Banner shows e.g.
    # "SecurityInsight-v2.2.17" which is what operators care about.
    $solVerFile = Join-Path $RepoRoot ("SOLUTIONS\{0}\VERSION" -f $Solution)
    if (Test-Path -LiteralPath $solVerFile) {
        $raw = Get-Content -Raw -LiteralPath $solVerFile -ErrorAction SilentlyContinue
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            return ('{0}-v{1}' -f $Solution, $raw.Trim())
        }
    }

    # Layer 2: VERSION.txt at repo root -- written by the publish workflow
    # when shipping to a public/community repo (e.g.
    # "AutomateIT-internal-main-<sha> ..." or just "v2.2.17").
    $verFile = Join-Path $RepoRoot 'VERSION.txt'
    if (Test-Path -LiteralPath $verFile) {
        $raw = Get-Content -Raw -LiteralPath $verFile -ErrorAction SilentlyContinue
        if (-not [string]::IsNullOrWhiteSpace($raw)) { return $raw.Trim() }
    }

    # Layer 3: git describe -- last-resort for plain dev clones with no
    # VERSION files at all.
    if (Test-Path (Join-Path $RepoRoot '.git')) {
        try {
            $tag = & git -C $RepoRoot describe --tags --match "$Solution-v*" --abbrev=0 2>$null
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($tag)) {
                return $tag.Trim()
            }
        } catch {
            # swallow -- fall through to (dev)
        }
    }

    return '(dev)'
}
