#Requires -Version 5.1
<#
    caj-si-updater -- THE FAST ROLL ON THE UPDATE PATH (#416, operator 2026-10-06: "release must comedown to 10 min", "we
    solved the updater yesterday by the changes you made like paralle", "where did those learning go").

    Measured 2026-10-06: one update took 22 min -- the engine image, then 16 jobs one by one (one CLI job update each,
    ~40 s each), then the web image, the MCP image and the updater's own image (apt + the Azure CLI then, from scratch),
    each built only when the step before it was done. (#521: the updater image carries no Azure CLI any more; every build
    is the registry's own over ARM, through the REST seam of this run -- Get-SIUpdaterRest.) Every install still builds its OWN images in its OWN registry from the
    signed source package (operator, same day: "i dont ike that we deiver a image out"); what changes is the order and
    what is rebuilt:
      * every image this release needs is QUEUED at once, before the engine roll starts (Start-SIUpdaterPrebuilds): the
        web app and the MCP server only when THEIR sources changed (tag src-<hash>, setup/_shared/SI-FastRoll.ps1), the
        updater as a thin code layer on its cached base (si-updater-base:<hash>; apt rebuilt weekly or when its
        Dockerfile changes);
      * the engine jobs swap in parallel (the release's setup/Invoke-SIContainerUpdate.ps1);
      * the web app / MCP roll and the self-roll then WAIT for the build already running (Invoke-SIUpdaterFastBuild)
        instead of starting their own; the web app and the MCP server are updated together.
    The ORDER of the update is unchanged: the database step (#352) first, the template gate, the engine jobs, the web app
    + MCP server (health-gated, restored on failure), the installed record, the updater's own job LAST.

    The fast-roll code itself is the RELEASE's (setup/_shared/SI-FastRoll.ps1), loaded from the extracted release; a release
    without it is built and rolled the old way. Never throws (a prebuild that fails is simply built again later).
#>

$script:SIUpdaterQueued = @{}

function Get-SIUpdaterFastRollPath {
    <# The release's fast-roll library, or '' when this release has none (built and rolled the old way). #>
    param([AllowEmptyString()][string]$SIRoot)
    if (-not $SIRoot) { return '' }
    $p = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-FastRoll.ps1')
    if (Test-Path -LiteralPath $p) { return $p }
    ''
}

function Invoke-SIUpdaterBuildInContext {
    <# Runs -Action in the release folder as the build context (a short copy on a deep Windows path -- the release's own SI-BuildStage.ps1). #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][scriptblock]$Action)
    $stageHelper = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-BuildStage.ps1')
    if (Test-Path -LiteralPath $stageHelper) {
        . $stageHelper
        Invoke-SIInBuildContext -Path $SIRoot -Log { param($m) Write-UpdLog $m } -Action $Action
        return
    }
    Push-Location -LiteralPath $SIRoot
    try { & $Action $SIRoot } finally { Pop-Location }
}

function Get-SIUpdaterLoginServer {
    param([Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId)
    try { [string](Get-SIUpdaterRegistry -AcrName $AcrName -SubscriptionId $SubscriptionId).loginServer } catch { '' }
}

function Start-SIUpdaterPrebuilds {
    <#
        Queues, in parallel with the engine roll, every OTHER image this release needs: the web app and the MCP server (only
        when their sources changed and the app exists here), and the updater's own image (thin layer on its cached base).
        Records each queued build in $script:SIUpdaterQueued (image -> build) for Invoke-SIUpdaterFastBuild. Returns the
        queued image names. Never throws.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName,
          [Parameter(Mandatory)][string]$SubscriptionId, [string]$UpdaterTag = '', [string]$WebApp = 'ca-si-management', [string]$McpApp = 'ca-si-mcp',
          [string]$UpdaterJob = 'caj-si-updater', [switch]$SelfOff)
    $lib = Get-SIUpdaterFastRollPath -SIRoot $SIRoot
    if (-not $lib) { return @() }
    $queued = New-Object System.Collections.Generic.List[string]
    $temp = New-Object System.Collections.Generic.List[string]
    try {
        . $lib
        # #521: the run's REST seam -- the release's build functions take it (no az)
        $bArgs = @{ Rest = (Get-SIUpdaterRest); AcrName = $AcrName; SubscriptionId = $SubscriptionId }
        $login = Get-SIUpdaterLoginServer -AcrName $AcrName -SubscriptionId $SubscriptionId
        if (-not $login) { return @() }
        $want = New-Object System.Collections.Generic.List[object]
        # Pro: the web app and the MCP server -- only when THEIR sources changed (container/updater/_shared/SI-UpdaterWebApp.ps1)
        if (Get-Command -Name Get-SIUpdaterAppPrebuilds -ErrorAction SilentlyContinue) {
            foreach ($w in @(Get-SIUpdaterAppPrebuilds -SIRoot $SIRoot -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -LoginServer $login -Rest $bArgs.Rest -WebApp $WebApp -McpApp $McpApp)) { if ($w) { $want.Add($w) } }
        }
        if ($UpdaterTag -and -not $SelfOff -and (Test-Path -LiteralPath ([IO.Path]::Combine($SIRoot, 'container', 'updater', 'Dockerfile')))) {
            if (-not (Test-SIAcrTag @bArgs -Repo 'si-updater' -Tag $UpdaterTag -LoginServer $login)) {
                $plan = Get-SIImageLayerPlan -DockerfilePath ([IO.Path]::Combine($SIRoot, 'container', 'updater', 'Dockerfile')) -BaseRepo 'si-updater-base' -LoginServer $login
                if ($plan.HasBase -and -not (Test-SIAcrTag @bArgs -Repo $plan.BaseRepo -Tag $plan.BaseTag -LoginServer $login)) {
                    # the base (apt) first; the thin updater layer is built on it at the self-roll
                    $work = Join-Path ([IO.Path]::GetTempPath()) ('si-upd-base-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
                    New-Item -ItemType Directory -Force -Path $work | Out-Null; $temp.Add($work)
                    $ctx = Join-Path $work 'ctx'; New-Item -ItemType Directory -Force -Path $ctx | Out-Null
                    $bf = Join-Path $work 'Dockerfile.base'; [IO.File]::WriteAllText($bf, $plan.BaseDockerfile)
                    Push-Location -LiteralPath $ctx
                    try { $b = Start-SIAcrBuild @bArgs -Image $plan.BaseImage -File $bf } finally { Pop-Location }
                    $script:SIUpdaterQueued[$plan.BaseImage] = $b; $queued.Add($plan.BaseImage)
                } else {
                    $f = 'container/updater/Dockerfile'
                    if ($plan.HasBase) {
                        $work = Join-Path ([IO.Path]::GetTempPath()) ('si-upd-app-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
                        New-Item -ItemType Directory -Force -Path $work | Out-Null; $temp.Add($work)
                        $f = Join-Path $work 'Dockerfile.app'; [IO.File]::WriteAllText($f, $plan.AppDockerfile)
                    }
                    $want.Add([pscustomobject]@{ Image = ('si-updater:{0}' -f $UpdaterTag); File = $f })
                }
            }
        }
        if ($want.Count) {
            Invoke-SIUpdaterBuildInContext -SIRoot $SIRoot -Action {
                foreach ($w in $want) {
                    try { $b = Start-SIAcrBuild @bArgs -Image $w.Image -File $w.File; $script:SIUpdaterQueued[$w.Image] = $b; $queued.Add($w.Image) }
                    catch { Write-UpdLog ("NOTE: {0} could not be queued ({1}) -- it is built when it is needed" -f $w.Image, $_.Exception.Message) }
                }
            }
        }
        if ($queued.Count) { Write-UpdLog ("queued in parallel with the engine roll: {0}" -f ($queued -join ', ')) }
    } catch { Write-UpdLog ("NOTE: the parallel builds could not be queued ({0}) -- each image is built when it is needed" -f $_.Exception.Message) }
    # a queued build has uploaded its context and Dockerfile already
    foreach ($w in $temp) { Remove-Item -LiteralPath $w -Recurse -Force -ErrorAction SilentlyContinue }
    $queued.ToArray()
}

function Invoke-SIUpdaterFastBuild {
    <#
        One image of the release (-Image repo:tag from -File), the fast way: a build this run queued already is WAITED FOR;
        otherwise a two-layer build (cached base + thin code layer) or the Dockerfile as it is -- queued and waited for.
        Returns $true when the image is in the registry now, $false when the release has no fast roll (the caller builds
        the old way). Throws when the build fails.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$File, [string]$LoginServer = '', [int]$TimeoutMinutes = 30)
    $lib = Get-SIUpdaterFastRollPath -SIRoot $SIRoot
    $q = $script:SIUpdaterQueued[$Image]
    if (-not $lib) { return $false }
    . $lib
    # #521: the run's REST seam -- the release's build functions take it (no az)
    $bArgs = @{ Rest = (Get-SIUpdaterRest); AcrName = $AcrName; SubscriptionId = $SubscriptionId }
    $log = { param($m) Write-UpdLog $m }
    if ($q) {
        Write-UpdLog ("{0}: waiting for the build queued at the start of this run" -f $Image)
        $q = @(Wait-SIAcrBuilds @bArgs -Builds @($q) -TimeoutMinutes $TimeoutMinutes -Log $log)[0]
        $script:SIUpdaterQueued.Remove($Image)
        if ($q.Status -eq 'Succeeded') { return $true }
        Write-UpdLog ("{0}: the queued build ended {1} -- building it once more" -f $Image, $q.Status)
    }
    if (-not $LoginServer) { $LoginServer = Get-SIUpdaterLoginServer -AcrName $AcrName -SubscriptionId $SubscriptionId }
    $repo = ($Image -split ':')[0]
    $plan = Get-SIImageLayerPlan -DockerfilePath ([IO.Path]::Combine($SIRoot, ($File -replace '/', [IO.Path]::DirectorySeparatorChar))) -BaseRepo ($repo + '-base') -LoginServer $LoginServer
    $work = Join-Path ([IO.Path]::GetTempPath()) ('si-upd-build-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    try {
        $buildFile = $File
        if ($plan.HasBase -and $LoginServer) {
            $bq = $script:SIUpdaterQueued[$plan.BaseImage]
            if ($bq) {
                $bq = @(Wait-SIAcrBuilds @bArgs -Builds @($bq) -TimeoutMinutes $TimeoutMinutes -Log $log)[0]
                $script:SIUpdaterQueued.Remove($plan.BaseImage)
            }
            if (-not (Test-SIAcrTag @bArgs -Repo $plan.BaseRepo -Tag $plan.BaseTag -LoginServer $LoginServer)) {
                Write-UpdLog ("building the base {0} (only when its Dockerfile lines, FROM image or week change)" -f $plan.BaseImage)
                $bf = Join-Path $work 'Dockerfile.base'; [IO.File]::WriteAllText($bf, $plan.BaseDockerfile)
                $ctx = Join-Path $work 'base-ctx'; New-Item -ItemType Directory -Force -Path $ctx | Out-Null
                Push-Location -LiteralPath $ctx
                try { $b = Start-SIAcrBuild @bArgs -Image $plan.BaseImage -File $bf } finally { Pop-Location }
                $b = @(Wait-SIAcrBuilds @bArgs -Builds @($b) -TimeoutMinutes $TimeoutMinutes -Log $log)[0]
                if ($b.Status -ne 'Succeeded') { throw ("the base image {0} build ended {1}" -f $plan.BaseImage, $b.Status) }
            }
            $buildFile = Join-Path $work 'Dockerfile.app'; [IO.File]::WriteAllText($buildFile, $plan.AppDockerfile)
        }
        $script:SIUpdaterFastBuild = $null
        Invoke-SIUpdaterBuildInContext -SIRoot $SIRoot -Action { $script:SIUpdaterFastBuild = Start-SIAcrBuild @bArgs -Image $Image -File $buildFile }
        $r = @(Wait-SIAcrBuilds @bArgs -Builds @($script:SIUpdaterFastBuild) -TimeoutMinutes $TimeoutMinutes -Log $log)[0]
        if ($r.Status -ne 'Succeeded') { throw ("the image build of {0} ended {1}" -f $Image, $r.Status) }
        $true
    } finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
