#Requires -Version 5.1
<#
    caj-si-updater -- THE UPDATER UPDATES ITSELF, LAST (#350 (c); PIM4EntraPS's ca-pim-update rolls itself last as well).

    The engine jobs, the web app and the MCP server move to a new release; the updater job kept running the image it was
    installed with, so a fix to the updater itself never reached an install. Now, after everything else is rolled and
    healthy, the run builds the updater image from the SAME verified release (container/updater/Dockerfile, the SecurityInsight
    folder as the context -- as setup/Install-SIUpdaterJob.ps1 builds it) and points its OWN job at it, as the very last step.

    WHY LAST, AND WHY IT IS SAFE INSIDE THE RUN: a Container Apps job's template is read when an execution STARTS. Changing
    the image of caj-si-updater does not touch the execution that is running now -- it finishes on the image it started
    with, and the NEXT run starts on the new one. Done first, this run would roll everything else with a definition it had
    already replaced; done last, nothing that follows depends on it.

    A FAILED SELF-ROLL NEVER FAILS THE UPDATE. The product is updated and healthy; only the image the next run starts from is
    left as it was. The job is marked (tag si-updater-pending = the wanted image tag), the run's UpdateState says so, and the
    next run -- even one that finds the product up to date -- tries again (rebuilding the image from the same verified
    archive when the registry does not have it yet). SI_UPDATER_SELF_UPDATE = 0 switches the step off (visible in every run).

    What is recorded on the job (tags, a merge: no new job revision): si-updater-image (the tag it now runs),
    si-updater-previous (the tag it ran before -- the image to point it back at by hand if the new one cannot start),
    si-updater-pending (empty when nothing is owed).
#>

function New-SIUpdaterBuildTag {
    <# PURE. The tag a release's images carry in the install's registry: v<build version>-<commit, 12> ('build' when unknown). #>
    param([Parameter(Mandatory)][string]$Version, [AllowEmptyString()][string]$Commit = '')
    $c = "$Commit".Trim().ToLowerInvariant()
    'v{0}-{1}' -f $Version, $(if ($c) { $c.Substring(0, [Math]::Min(12, $c.Length)) } else { 'build' })
}

function Test-SIUpdaterSelfDisabled {
    <# PURE. SI_UPDATER_SELF_UPDATE: 0 / false / off / no switches the self-update off; anything else (or unset) = on. #>
    param([AllowEmptyString()][AllowNull()][string]$Value)
    "$Value".Trim() -match '^(?i)(0|false|off|no)$'
}

function Get-SIUpdaterSelfDecision {
    <#
      PURE. What the last step does to the updater's own job.
        Action: off (switched off) | current (already runs the image) | roll (the image is in the registry) |
                build (build it from the release, then roll) | skipped (not in the registry, and no release to build it from).
      Returns @{ Act; Build; Action; Reason }.
    #>
    param([AllowEmptyString()][string]$CurrentImage, [Parameter(Mandatory)][string]$TargetImage, [bool]$InRegistry, [bool]$HasDockerfile, [bool]$Disabled)
    $o = { param($act, $build, $a, $why) [pscustomobject]@{ Act = [bool]$act; Build = [bool]$build; Action = $a; Reason = $why } }
    $tag = ($TargetImage -split ':')[-1]
    if ($Disabled) { return (& $o $false $false 'off' 'the updater does not update itself (SI_UPDATER_SELF_UPDATE is off) -- it keeps its current image') }
    if ($CurrentImage -and $CurrentImage -ieq $TargetImage) { return (& $o $false $false 'current' ("the updater already runs {0}" -f $tag)) }
    if ($InRegistry) { return (& $o $true $false 'roll' ("the updater moves to {0} (in the registry)" -f $tag)) }
    if ($HasDockerfile) { return (& $o $true $true 'build' ("the updater image {0} is built from this release, then the updater moves to it" -f $tag)) }
    & $o $false $false 'skipped' ("this release carries no updater image definition (container/updater/Dockerfile) -- the updater keeps {0}" -f $(if ($CurrentImage) { ($CurrentImage -split '/')[-1] } else { 'its image' }))
}

function Invoke-SIUpdaterAcrBuild {
    <#
      One image built in the registry from an extracted release (-SIRoot = the build context, as every SI image is built) --
      the registry's own build over ARM (#521: no az). A release with the fast roll builds through it; otherwise the image's
      own REST build (/si/setup/_shared/SI-AcrBuild.ps1: packed, uploaded, scheduled, followed). On a Windows host with a
      deep path the context is a short copy (#350, the release's SI-BuildStage.ps1); in the updater container (Linux) the
      folder is used as it is. Throws when the build does not succeed (the end of its log is printed first).
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$File, [string]$LoginServer = '', [int]$TimeoutMinutes = 30)
    # #416 (the fast roll): a build this run QUEUED already (Start-SIUpdaterPrebuilds, in parallel with the engine roll) is
    # waited for, never built twice; a release that carries the fast roll builds a two-layer image (cached base + thin code).
    if (Get-Command -Name Invoke-SIUpdaterFastBuild -ErrorAction SilentlyContinue) {
        if (Invoke-SIUpdaterFastBuild -SIRoot $SIRoot -AcrName $AcrName -SubscriptionId $SubscriptionId -Image $Image -File $File -LoginServer $LoginServer -TimeoutMinutes $TimeoutMinutes) { return }
    }
    $rest = Get-SIUpdaterRest
    $script:SIUpdaterPlainBuild = $null
    $act = { param($ctx) $script:SIUpdaterPlainBuild = Invoke-SIAcrQueueBuild -Rest $rest -SubscriptionId $SubscriptionId -AcrName $AcrName -ContextPath ((Get-Location).ProviderPath) -Image $Image -DockerfilePath $File }
    $stageHelper = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-BuildStage.ps1')
    if (Test-Path -LiteralPath $stageHelper) {
        . $stageHelper
        Invoke-SIInBuildContext -Path $SIRoot -Log { param($m) Write-UpdLog $m } -Action $act
    } else {
        Push-Location -LiteralPath $SIRoot
        try { & $act $SIRoot } finally { Pop-Location }
    }
    $q = $script:SIUpdaterPlainBuild
    if (-not $q -or -not $q.RunId) { throw ("the image build of {0} was not queued (no run id)" -f $Image) }
    $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes); $status = 'Queued'
    while ($status -notin @('Succeeded', 'Failed', 'Canceled', 'Cancelled', 'Error', 'Timeout')) {
        if ([datetime]::UtcNow -ge $deadline) { $status = 'Timeout'; break }
        Start-Sleep -Seconds 15
        $s = Get-SIAcrRunStatus -Rest $rest -Registry $q.Registry -RunId $q.RunId
        if ($s) { $status = $s }
    }
    if ($status -ne 'Succeeded') {
        foreach ($l in @(Get-SIAcrRunLogTail -Rest $rest -Registry $q.Registry -RunId $q.RunId)) { Write-UpdLog ('  | ' + $l) }
        throw ("the image build of {0} ended {1}" -f $Image, $status)
    }
}

function Save-SIUpdaterSelfRecord {
    <# The self-update's record as tags on the updater job (a MERGE; no new revision). Retried while an operation is in flight. Never fails the run. #>
    param([AllowEmptyString()][string]$ResourceId, [Parameter(Mandatory)][hashtable]$Tags, [Parameter(Mandatory)][string]$SubscriptionId, [int[]]$Waits = @(0, 10, 20))
    if (-not $ResourceId) { return $false }
    $err = ''
    foreach ($w in $Waits) {
        if ($w) { Start-Sleep -Seconds $w }
        try {
            Update-SIUpdaterTags -ResourceId $ResourceId -Tags $Tags
            return $true
        } catch { $err = $_.Exception.Message; if ($err -notmatch '(?i)OperationInProgress|in progress|\b409\b') { break } }
    }
    Write-UpdLog ("WARNING: the updater's own record could not be written on its job: {0}" -f $err)
    $false
}

function Invoke-SIUpdaterSelfRoll {
    <#
      THE LAST STEP of a run: the updater's own job (-JobName) onto the updater image of the release now installed (-Tag).
      -SIRoot: the extracted, verified release (to build the image from); '' when only an image already in the registry may be
      used. -Waits: the back-off while another operation on the job is still in flight (409), as PIM's self-stamp.
      Returns @{ Action = off | current | skipped | rolled | failed; Image; Previous; Reason }. Never throws.
    #>
    param([AllowEmptyString()][string]$SIRoot = '', [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$Tag,
          [string]$JobName = 'caj-si-updater', [AllowEmptyString()][string]$JobId = '', [AllowEmptyString()][string]$CurrentImage = '',
          [switch]$Disabled, [int[]]$Waits = @(0, 10, 20, 40, 60))
    $target = '{0}/si-updater:{1}' -f $LoginServer, $Tag
    $prevTag = if ($CurrentImage) { ($CurrentImage -split ':')[-1] } else { '' }
    $res = { param($a, $why) [pscustomobject]@{ Action = $a; Image = $target; Previous = $CurrentImage; Reason = $why } }
    try {
        $inReg = $false
        if (-not $Disabled -and $CurrentImage -ine $target) {
            $inReg = Test-SIUpdaterImageTag -LoginServer $LoginServer -Repo 'si-updater' -Tag $Tag
        }
        $hasDf = [bool]($SIRoot -and (Test-Path -LiteralPath ([IO.Path]::Combine($SIRoot, 'container', 'updater', 'Dockerfile'))))
        $d = Get-SIUpdaterSelfDecision -CurrentImage $CurrentImage -TargetImage $target -InRegistry $inReg -HasDockerfile $hasDf -Disabled ([bool]$Disabled)
        Write-UpdLog ("updater: {0}" -f $d.Reason)
        if (-not $d.Act) { return (& $res $d.Action $d.Reason) }
        if ($d.Build) {
            Write-UpdLog ("building si-updater:{0}" -f $Tag)
            try { Invoke-SIUpdaterAcrBuild -SIRoot $SIRoot -AcrName $AcrName -SubscriptionId $SubscriptionId -Image ('si-updater:{0}' -f $Tag) -File 'container/updater/Dockerfile' }
            catch { throw ("the updater image could not be built: {0}" -f $_.Exception.Message) }
        }
        # the roll just before this one may still be in flight on the same environment: a 409 is a wait, not a failure
        $err = ''; $ok = $false
        foreach ($w in $Waits) {
            if ($w) { Write-UpdLog ("updater: an operation is still in flight -- retrying in {0}s" -f $w); Start-Sleep -Seconds $w }
            try {
                # one read-modify-write ARM PATCH of the job's template (#521: was `az containerapp job update --image`)
                # and its size: at least 4 CPU / 8 GiB (owner 2026-10-10: the image build ran out of memory on 0.5 / 1 GiB)
                Set-SIUpdaterImage -Kind jobs -Name $JobName -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -Image $target -MinCpu 4 -MinMemoryGi 8
                $ok = $true; break
            } catch { $err = $_.Exception.Message; if ($err -notmatch '(?i)OperationInProgress|active provisioning operation|in progress|\b409\b') { break } }
        }
        # read back: the job must now carry the image (an update that reported a failure but landed counts as landed)
        $now = ''
        try { $now = [string](Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/jobs/' + $JobName))).properties.template.containers[0].image } catch { $now = '' }
        if ($now -ine $target) { throw $(if ($err) { "the updater job could not be pointed at {0}: {1}" -f $Tag, $err } else { "the updater job reads back '{0}', expected {1}" -f $now, $Tag }) }
        $null = Save-SIUpdaterSelfRecord -ResourceId $JobId -SubscriptionId $SubscriptionId -Tags @{ 'si-updater-image' = $Tag; 'si-updater-previous' = $prevTag; 'si-updater-pending' = '' }
        $why = "the updater moves to {0} from its next run (this run finishes on {1})" -f $Tag, $(if ($prevTag) { $prevTag } else { 'its current image' })
        Write-UpdLog ("updater: {0}" -f $why)
        return (& $res 'rolled' $why)
    } catch {
        $msg = $_.Exception.Message
        $null = Save-SIUpdaterSelfRecord -ResourceId $JobId -SubscriptionId $SubscriptionId -Tags @{ 'si-updater-pending' = $Tag }
        $why = "{0} -- SecurityInsight IS updated; the updater keeps {1} and tries again on its next run" -f $msg, $(if ($prevTag) { $prevTag } else { 'its current image' })
        Write-UpdLog ("NOTE: updater: {0}" -f $why)
        return (& $res 'failed' $why)
    }
}
