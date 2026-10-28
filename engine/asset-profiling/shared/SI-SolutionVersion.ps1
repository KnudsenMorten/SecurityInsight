#Requires -Version 5.1
<#
    WHICH RELEASE OF SecurityInsight PRODUCED THIS ROW.

    🔴 WHY THIS EXISTS (V3-HANDOFF task V3-6, operator 2026-08-28: *"it saves the version per row"* →
    *"add them, that makes good value"*). `si-v3` and `main`/prod write to the **same Log Analytics
    workspace and the same tables**, and the nightly runs the RELEASED code. Risk Analysis already
    stamped `SolutionVersion`, and that stamp is what proved the two trees were interleaving: version
    2.2.460 at 13:58, then 2.2.457 at 23:22 — **the version running BACKWARDS as time runs forwards.**

    🪤 The four PROFILE tables had no stamp at all, so the same contamination there was undetectable.
    Every profile-table measurement taken before this — the coverage tables, the `SI_AssetName` /
    `SI_AssetId` percentages — read `max(CollectionTime)` with no way to know which tree wrote the rows.
    They happened to be right; "happened to be right" is not attributable.

    🔑 THE RESOLUTION ORDER IS THE POINT, and it is RA's, deliberately — one rule, not two.
    Walk UP from this file first, so the per-solution `SOLUTIONS/SecurityInsight/VERSION` ("2.2.457")
    wins before the walk reaches the repo-root `VERSION.txt`. That root file is stamped by the bootstrap
    with a COMPOUND sync label:

        AutomateIT-internal-main-<sha> (solutions: PlatformConfiguration, PlatformMonitoring,
        SecurityInsight-v2.2.221) @ 2026-05-13T01:10:20

    which leaked into RA's stamp once already and confused operators who wanted "2.2.225". Root
    `VERSION.txt` is therefore the FALLBACK, never the first candidate.

    📌 Returns `(dev)` when no VERSION file is found — the same sentinel RA uses. A row stamped `(dev)`
    means "ran from a tree without a VERSION file", which is itself worth seeing in the data rather than
    hiding behind an empty string.
#>

# Resolved once per process. The value cannot change mid-run, and every row in a run asks for it.
$script:_SISolutionVersion = $null

function Get-SISolutionVersion {
    <#
        .SYNOPSIS
        The SecurityInsight release that is producing the current run's rows, e.g. '2.2.457'.

        .DESCRIPTION
        Walks up from this file looking for VERSION (then VERSION.txt) at each level, and returns the
        first value found. Cached for the life of the process.

        .PARAMETER Refresh
        Re-resolve rather than returning the cached value. Only useful in tests.
    #>
    [CmdletBinding()]
    param([switch]$Refresh)

    if (-not $Refresh -and $script:_SISolutionVersion) { return $script:_SISolutionVersion }

    $resolved = '(dev)'
    try {
        $cur = $PSScriptRoot
        while ($cur) {
            foreach ($name in @('VERSION', 'VERSION.txt')) {
                $file = Join-Path $cur $name
                if (Test-Path -LiteralPath $file) {
                    $raw = $null
                    try { $raw = (Get-Content -LiteralPath $file -Raw -ErrorAction Stop) } catch { }
                    if ($raw) {
                        $raw = $raw.Trim()
                        # 🪤 Reject the bootstrap's compound sync label. A bare version is what belongs
                        # in a row; the compound form is sync bookkeeping and is never the answer to
                        # "which release produced this data".
                        if ($raw -and $raw -notmatch '^AutomateIT-' -and $raw -notmatch '\s') {
                            $resolved = $raw
                            break
                        }
                    }
                }
            }
            if ($resolved -ne '(dev)') { break }
            $parent = Split-Path -Parent $cur
            if (-not $parent -or $parent -eq $cur) { break }
            $cur = $parent
        }
    } catch {
        # Never let version resolution fail a run: an unstamped row is a small loss, a failed
        # profiling run is a large one.
        $resolved = '(dev)'
    }

    # 🔒 THE EDITION MARKER (operator 2026-08-31: *"same scope always so we can track progress"*,
    # *"this la has both v3 and v2.2 runs"*, *"version is in rows"*).
    #
    # 🔴 THE STAMP ABOVE CANNOT ACTUALLY SEPARATE THE TWO TREES, WHICH IS THE JOB IT WAS ADDED FOR.
    # The header's own evidence -- 2.2.460 at 13:58 then 2.2.457 at 23:22 -- works only while the two
    # trees sit on DIFFERENT versions. `si-v3` and `main` both on 2.2.460 stamp the identical string,
    # and the contamination becomes undetectable again exactly when the branch is closest to shipping.
    # Measured on the shared workspace 2026-08-31: every recent RA snapshot reported ONE
    # SolutionVersion, the same one, for both editions.
    #
    # 🔑 A SUFFIX, NOT A BUMP. The VERSION *file* is the customer-sync contract -- customers pull on a
    # VERSION check, so bumping it for v3 work ships v3 to ~30 customers. The stamped *value* is data
    # in an existing column: no schema change, no ~25-minute ingest wait, no per-customer approval.
    # Matches what Invoke-RiskAnalysis.ps1 does, so ONE rule spans RA and the four profile tables
    # rather than two rules that agree until they don't.
    #
    # 🪤 The marker is a v3-ONLY FILE, so this cannot be true on a v2.2 install. Do not "simplify" it
    # to a version-string comparison: the whole defect is that the version strings are equal.
    if ($resolved -ne '(dev)' -and $resolved -notmatch '\+v3$') {
        try {
            # engine/asset-profiling/shared -> engine/_shared/SI-V3Snapshot.ps1
            $v3Marker = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-V3Snapshot.ps1'
            if (Test-Path -LiteralPath $v3Marker) { $resolved = '{0}+v3' -f $resolved }
        } catch {
            # An unmarked row is a small loss; a failed profiling run is a large one.
        }
    }

    $script:_SISolutionVersion = $resolved
    return $resolved
}
