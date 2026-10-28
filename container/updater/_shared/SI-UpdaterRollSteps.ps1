#Requires -Version 5.1
<#
    caj-si-updater -- THE ROLL STEPS BOTH EDITIONS SHARE (SI #750 (b), 2026-10-27). Moved here unchanged from
    _shared/SI-UpdaterInvardia.ps1 (SecurityInsight Pro, which dot-sources this file), so the Community edition's updater
    (_shared/SI-UpdaterCommunity.ps1, the signed community channel) rolls a verified release EXACTLY as Pro does:
      Resolve-SIUpdaterRunningRelease    the release the jobs run (the recorded applied version when it is a build of it)
      Get-SIUpdaterNeedsQuiet            a release that must be installed while no SI job runs (UPDATE-NEEDS-QUIET.txt)
      Invoke-SIUpdaterInvardiaPreRoll    the manual-deploy mark + the quiet wait, before a roll (name kept: Pro tests call it)
      Invoke-SIUpdaterInvardiaPostRoll   the web app, the installed record, then the updater itself LAST
      Invoke-SIUpdaterInvardiaSelfRetry  an earlier self-roll that is owed
      Save-SIUpdaterInvardiaStateRow     the compact update state into cfg.InstallState 'UpdateState' (the Settings page)
    Nothing here reads the Invardia update client (the Pro-only engine client). PS 5.1 and 7.
#>
function Resolve-SIUpdaterRunningRelease {
    <#
        PURE. The release the jobs run, for the forward-only guard and the update record's from-version. -Deployed is what
        the environment says (the recorded release, else the image tags' base version, e.g. '3.0.0'); -AppliedVersion is
        what this updater recorded when it last applied an Invardia release (e.g. '3.0.0.202610142040'). The applied
        version is taken ONLY when it is a build OF the deployed version (it starts with it plus a dot) -- the deployed
        one stays for anything else (a manual deploy of another release, no record, a record of an older release).
    #>
    param([AllowEmptyString()][AllowNull()][string]$Deployed, [AllowEmptyString()][AllowNull()][string]$AppliedVersion)
    $d = "$Deployed".Trim(); $a = "$AppliedVersion".Trim()
    if ($d -and $a -match '^\d+(?:\.\d+){1,3}$' -and $a.StartsWith($d + '.', [StringComparison]::Ordinal)) { return $a }
    $d
}

function Get-SIUpdaterNeedsQuiet {
    <#
        PURE (reads one file). Must this release be installed while NO SecurityInsight job runs? Only when the release says
        so itself: a file UPDATE-NEEDS-QUIET.txt at its root, holding the reason in plain words (a database change the
        version before it cannot run against). Returns the reason, '' = no (the normal case: it installs at once).
    #>
    param([string]$SIRoot = '')
    if (-not $SIRoot) { return '' }
    $f = Join-Path $SIRoot 'UPDATE-NEEDS-QUIET.txt'
    if (-not (Test-Path -LiteralPath $f)) { return '' }
    $t = ''; try { $t = "$([IO.File]::ReadAllText($f))".Trim() } catch { }
    if ($t) { ($t -split "`r?`n")[0].Trim() } else { 'the release asks for it' }
}

function Invoke-SIUpdaterInvardiaPreRoll {
    <#
        Before a code roll from Invardia: a manual deploy in progress (tag si-deploy-running on the updater job) = do not
        roll now. A PIPELINE RUN IN PROGRESS HOLDS THE UPDATE (owner 2026-10-23: "Should the rolls skip installs that are
        mid-run (large installs pick up the new build at their next run)?" -> "yes to both"; this REPLACES the rule of
        2026-10-12, "an SI run in progress does not hold the update"): that is decided AFTER this check, from the install's
        state store, by the run gate (SI-UpdaterRunGate.ps1) -- the update waits, and the pipeline runner starts it again
        between the run and the next one. The SI jobs' executions read here are only said in the log. A release that says
        it must be installed while nothing runs at all (Get-SIUpdaterNeedsQuiet) still waits for the running jobs, up to
        -WaitMinutes, then for the next updater run (what an updater image without the run gate honours).
        Returns @{ Go; Reason; Environment } (Environment = Get-SIUpdaterEnvironment, for the post-roll). A machine
        without the channel helpers (an older image) = Go with no environment. Never throws.
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId,
          [string]$UpdaterJob = 'caj-si-updater', [int]$WaitMinutes = 60, [string]$SIRoot = '')
    if (-not (Get-Command -Name Get-SIUpdaterEnvironment -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ Go = $true; Reason = ''; Environment = $null } }
    try {
        $envNow = Get-SIUpdaterEnvironment -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -UpdaterJob $UpdaterJob
        $lock = Test-SIUpdaterDeployLock -Value $envNow.DeployLock
        if ($lock.Reason) { Write-UpdLog $lock.Reason }
        if ($lock.Locked) { return [pscustomobject]@{ Go = $false; Reason = $lock.Reason; Environment = $envNow } }
        $quiet = Get-SIUpdaterNeedsQuiet -SIRoot $SIRoot
        if ($quiet) {
            Write-UpdLog ("this release is installed only while no SecurityInsight job runs: {0}" -f $quiet)
            if (-not (Wait-SIUpdaterPipelineIdle -JobNames @($envNow.JobNames) -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -Minutes $WaitMinutes)) {
                return [pscustomobject]@{ Go = $false; Reason = ("an SI run was in progress and this release must be installed while nothing runs ({0}) -- the update waits for the next updater run" -f $quiet); Environment = $envNow }
            }
        } else {
            $busy = @(); try { $busy = @(Get-SIUpdaterBusyJobs -JobNames @($envNow.JobNames) -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId) } catch { }
            if ($busy.Count) { Write-UpdLog ("SI jobs are running ({0}) -- whether a pipeline run is going is read from the state store next (the run gate)" -f ($busy -join ', ')) }
        }
        [pscustomobject]@{ Go = $true; Reason = ''; Environment = $envNow }
    } catch { [pscustomobject]@{ Go = $true; Reason = ("the environment could not be read ({0}) -- rolling without the deploy-lock check" -f $_.Exception.Message); Environment = $null } }
}

function Invoke-SIUpdaterInvardiaPostRoll {
    <#
        After the engine jobs rolled to a release from Invardia -- what the ring channel does after its roll (#350), so an
        environment that takes its updates from Invardia (Pro customers, and ring 1 once it moves there) gets the SAME update:
          1. Pro: the web app + MCP server onto the release (Invoke-SIUpdaterAppRoll: build, roll, health-check, restore);
          2. what now runs, as tags on the updater job (si-installed / si-installed-commit);
          3. LAST, the updater's own job onto the release's updater image (Invoke-SIUpdaterSelfRoll; SI_UPDATER_SELF_UPDATE=0 = off).
        Returns @{ Code (0 ok / 1 the web app failed); Text }. A failure of 3. never fails the run (retried next run).
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$Version, [string]$Commit = '', $Environment,
          [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId,
          [string]$UpdaterJob = 'caj-si-updater', [string]$WebApp = 'ca-si-management', [string]$McpApp = 'ca-si-mcp', [switch]$SelfOff)
    if (-not $Environment -or -not (Get-Command -Name New-SIUpdaterBuildTag -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ Code = 0; Text = 'no environment record -- the web app and the updater itself were not rolled' } }
    $tag = New-SIUpdaterBuildTag -Version $Version -Commit $Commit
    $apps = if (Get-Command -Name Invoke-SIUpdaterAppRoll -ErrorAction SilentlyContinue) {
        Invoke-SIUpdaterAppRoll -SIRoot $SIRoot -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -LoginServer $Environment.LoginServer -Tag $tag -WebApp $WebApp -McpApp $McpApp
    } else { [pscustomobject]@{ Code = 0; Text = 'no web app in this edition' } }
    Write-UpdLog ("web app: {0}" -f $apps.Text)
    if ($apps.Code -ne 0) { return [pscustomobject]@{ Code = 1; Text = ("the engine jobs run {0}, but the web app was NOT updated: {1}" -f $Version, $apps.Text) } }
    if (Get-Command -Name Save-SIUpdaterInstalledRecord -ErrorAction SilentlyContinue) { $null = Save-SIUpdaterInstalledRecord -ResourceId $Environment.UpdaterId -Version $Version -Commit $Commit -SubscriptionId $SubscriptionId }
    $self = $null
    if (Get-Command -Name Invoke-SIUpdaterSelfRoll -ErrorAction SilentlyContinue) {
        $self = Invoke-SIUpdaterSelfRoll -SIRoot $SIRoot -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -LoginServer $Environment.LoginServer `
                    -Tag $tag -JobName $UpdaterJob -JobId $Environment.UpdaterId -CurrentImage $Environment.UpdaterImage -Disabled:$SelfOff
        Write-UpdLog ("updater: {0} -- {1}" -f $self.Action, $self.Reason)
    }
    # SelfAction 'rolled' = the updater now runs this release's image: its update steps run in the second update
    [pscustomobject]@{ Code = 0; Text = ("this environment now runs SecurityInsight {0}" -f $Version); SelfAction = $(if ($self) { [string]$self.Action } else { '' }) }
}

function Invoke-SIUpdaterInvardiaSelfRetry {
    <#
        #350 (c): an earlier run updated SecurityInsight but could not move the updater's own job (tag si-updater-pending =
        the image tag it owes). Retried with the image already in the registry; when it is not there (its build failed) the
        updater keeps its image until the next release, which builds it. Returns the self-roll result, or $null when nothing
        is owed. Never throws.
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId,
          [string]$UpdaterJob = 'caj-si-updater')
    if (-not (Get-Command -Name Get-SIUpdaterEnvironment -ErrorAction SilentlyContinue)) { return $null }
    try {
        $envNow = Get-SIUpdaterEnvironment -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -UpdaterJob $UpdaterJob
        $pending = "$($envNow.SelfPending)".Trim()
        if (-not $pending) { return $null }
        Write-UpdLog ("updater: an earlier run could not move the updater to {0} -- trying again" -f $pending)
        Invoke-SIUpdaterSelfRoll -SIRoot '' -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -LoginServer $envNow.LoginServer `
            -Tag $pending -JobName $UpdaterJob -JobId $envNow.UpdaterId -CurrentImage $envNow.UpdaterImage
    } catch { Write-UpdLog ("NOTE: updater: the pending self-update could not be retried ({0}) -- next run" -f $_.Exception.Message); $null }
}

function Save-SIUpdaterInvardiaStateRow {
    <# The compact update state into cfg.InstallState 'UpdateState' (the web app's Settings page reads it). #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Json)
    $sql = @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'UpdateState')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'UpdateState';
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'UpdateState', @Value, NULL, @By);
    COMMIT;
END
'@
    & $Store.Invoke $sql ([ordered]@{ Value = $Json; By = 'caj-si-updater' }) 'nonquery'
}
