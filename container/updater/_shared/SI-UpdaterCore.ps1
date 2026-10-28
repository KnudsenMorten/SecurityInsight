#Requires -Version 5.1
<#
    SecurityInsight -- the container UPDATER's decisions (pure; no Azure, no network).

    WHY (#160, operator ruling 2026-09-29: "Updater job"). A container-only customer has no machine that
    runs the sync, so ring promotions could never reach its engine jobs. The updater job (caj-si-updater)
    makes the SAME decision the VM sync makes -- the framework's Get-AitSyncPlan against the live
    release-map, then Test-AitDeployAllowedByPlan for SI's engine-image hook -- and, when the ring allows it,
    builds the engine image from exactly the approved ref and rolls the jobs (setup/Invoke-SIContainerUpdate.ps1).

    🔑 NO FILE-COPY INSTALL IN A CONTAINER. The image IS the install, and every build starts from a fresh
    extract of one ref, so a container can never carry a mixed tree (RING-5 cannot happen here).
#>

function Get-SIDeployedVersionFromJobs {
    <#
        The version the jobs run now, from their image tags (v<VERSION>-<hash>, as Invoke-SIContainerUpdate
        tags them). The HIGHEST across SI jobs wins, so a half-rolled estate never reads as older than it is
        (that would let a ring move it backward). '' when no SI job carries a readable tag -- the forward-only
        guard is then simply not applied, which is today's behaviour.
        -Recorded: the RELEASE the updater recorded when it last applied one (the si-installed tag on the updater job,
        written after every roll and by a manual deploy, e.g. 3.0.0.202610142040). The engine images are tagged by content
        (v3.0.0-<hash>), so the tag alone only knows the base version -- the update record then read "3.0.0 -> ..." for an
        install that ran a later build of 3.0.0. The record wins when it is a version and not older than the tags say;
        the image tag is the fallback (no record, or a record older than what the images carry).
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Jobs,     # @{ Name; Image }
        [Parameter(Mandatory)][string]$LoginServer,
        [AllowEmptyString()][AllowNull()][string]$Recorded = ''
    )
    $repo = ('{0}/si-orchestrator:' -f $LoginServer).ToLowerInvariant()
    $best = ''
    foreach ($j in $Jobs) {
        $img = ([string]$j.Image).ToLowerInvariant()
        if (-not $img.StartsWith($repo)) { continue }
        $tag = $img.Substring($repo.Length)
        if ($tag -notmatch '^v(\d+(?:\.\d+){1,3})-[0-9a-f]{12}$') { continue }
        $v = $Matches[1]
        if (-not $best -or (Compare-SIUpdaterVersionText $v $best) -gt 0) { $best = $v }
    }
    $rec = "$Recorded".Trim()
    if ($rec -match '^\d+(?:\.\d+){1,3}$' -and (-not $best -or (Compare-SIUpdaterVersionText $rec $best) -ge 0)) { return $rec }
    return $best
}

function Compare-SIUpdaterVersionText {
    <# PURE. -1 / 0 / 1, numeric per part, 64-bit (a release carries a yyyyMMddHHmm build part that [version] cannot hold). #>
    param([AllowEmptyString()][string]$A, [AllowEmptyString()][string]$B)
    $pa = @("$A".Trim().Split('.') | Where-Object { $_ -ne '' }); $pb = @("$B".Trim().Split('.') | Where-Object { $_ -ne '' })
    for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
        $x = [long]0; $y = [long]0
        if ($i -lt $pa.Count) { [void][long]::TryParse($pa[$i], [ref]$x) }
        if ($i -lt $pb.Count) { [void][long]::TryParse($pb[$i], [ref]$y) }
        if ($x -ne $y) { if ($x -lt $y) { return -1 } else { return 1 } }
    }
    0
}

# The ring-plan -> action decision for the managed updater is Get-SIUpdaterFeedDecision (SI-UpdateFeed.ps1).
# The GitHub-era Get-SIUpdaterDecision (main vs a tag) was removed with the repository token (#171).
