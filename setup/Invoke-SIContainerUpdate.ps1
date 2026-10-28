<#
.SYNOPSIS
    SecurityInsight -- bring a CONTAINER-hosted install up to the code the sync just pulled:
    detect -> build -> roll -> verify -> roll back on failure. A VM install is a clean no-op.

.DESCRIPTION
    Same flow as PIM4EntraPS's update hook (operator ruling 2026-09-29), run by the sync engine through
    solution.deploy.json after a sync that changed SecurityInsight:

      1. DETECT   -- is this a container install? (SI_Bootstrap_ResourceGroupName + SI_Bootstrap_AcrName in
                     config\SecurityInsight.custom.ps1, or parameters). No -> "nothing to update", exit 0.
                     Which jobs run this registry's si-orchestrator image, and is any not on the image
                     built from THIS tree (tag = v<VERSION>-<content hash>)?
      2. BUILD    -- the registry builds the image from this solution folder (never a fixed path), only when the tag
                     is not already in the registry: packed here (.dockerignore applied), uploaded, built by ARM
                     scheduleRun and followed to its end (setup/_shared/SI-AcrBuild.ps1).
      3. ROLL     -- point each job at the new image, capturing its previous image first. #416: ONE ARM PATCH of its
                     template per job, all sent at once (never a PUT, never one job update after another).
      4. VERIFY   -- read every job back (one job list per poll); each must now carry the new image, and nothing else
                     on it may have changed (trigger, secrets, env, resources, identity, tags ...).
      5. ROLLBACK -- on any failure after a job changed, every changed job returns to its previous image,
                     and the script exits 1 so the sync reports the solution as failed.
      6. TEMPLATES -- SecurityInsight Pro (the Pro database is configured): once the jobs run this tree, the default
                     templates are installed or kept current as template pack 1.0 (#250, setup\Publish-SITemplates.ps1
                     -InstallDefault: the schema, names and CMDB ownership as configuration, the pack staged and
                     recorded). A template change that needs a review is never written here -- it waits on the Template
                     releases page. Never fails the update: a problem is reported, and the next run tries again.
      7. SQL SIZE -- (#507, setup/_shared/SI-SqlTier.ps1) the install's SI databases are raised to the size the rule gives
                     (never Basic: the Pro database S3, the identity ledger S1 -- #509) by one online ARM PATCH of the sku. Never
                     lowers by itself, never touches a database above S3 / Premium / vCore / in an elastic pool, never
                     fails the update; one line per database. A size the customer set (SI_Bootstrap_SqlServiceObjective,
                     the Pro database's setting first) applies both ways, never below S1. -DetectOnly: the plan only.
      9. QUEUE SCALING -- (#519, setup/_shared/SI-KedaConvert.ps1) identity / endpoint / Azure still running as one scheduled
                     job (an install made before queue scaling) move to a producer + queue-scaled workers, as a new install
                     gets them -- only a job SI's setup made that signs in with the managed identity, unless the install
                     switched queue scaling off. The old job loses its timer only after both new jobs are read back, and
                     is kept; any failure leaves it running. Never fails the update. -DetectOnly: the plan only.
     9b. RISK ANALYSIS WORKERS -- (#742, setup/_shared/SI-RaWorkerJobs.ps1) ON BY DEFAULT where they can run (owner
                     2026-10-18): the Detailed Risk Analysis job gets its queue-scaled worker job (caj-si-raworker-detailed)
                     as a new install gets it, read back, and only then is told to hand its reports to it (SI_RA_SCALE_OUT /
                     SI_RA_WORKER_JOB). Only a job SI's setup made that signs in with the managed identity; queue scaling
                     switched off keeps it as it is (one line says why). SI_Bootstrap_RaScaleOut = $false (or
                     SI_UPDATER_RA_SCALE_OUT = off on the updater job): no worker is made, and a Risk Analysis job still
                     told it is a producer is told it is not (read back). Any failure leaves it running its reports itself.
                     Never fails the update. -DetectOnly: the plan only.
     9a. MISSING JOBS -- (#685, setup/_shared/SI-MissingJobs.ps1) a job this version needs that the install does not have
                     (caj-si-verification; #714 the mail job caj-si-close-loop-mail, with the SMTP relay password a Risk
                     Analysis job carries; #715 the ServiceNow connectors' caj-si-asset-vulns-servicenow and caj-si-asset-cmdb,
                     only where a ServiceNow connector of that direction is in the Pro database or a setting says ServiceNow
                     is used) is created as a new install gets it -- from a Pro job of the install (image,
                     sign-in, settings, secrets), in flow mode as a step of the pipeline -- and read back; one that does not
                     read back right is removed again. A job that exists is never touched. Never fails the update.
     10. PERMISSIONS -- (setup/_shared/SI-PermissionNote.ps1) read only: what SecurityInsight's collection identity holds is
                     compared with config\permissions.locked.json. Per read-only permission that is not granted yet: one
                     line (what it is for, what stays empty without it) and the two lines that grant them. Nothing is
                     granted or changed here, nothing is said when all are granted, and the update never fails on it.
     9c. NIGHTLY SCHEDULE -- (setup/_shared/SI-NightlySchedule.ps1) ONCE per install: the update at 23:00 and the pipeline at
                     23:30 in the time zone of the install's Azure region (an unknown region: Danish time, said in one line).
                     The updater job on a shipped timer (the old 03:00 UTC, or the Danish-time ticks '0 21,22 * * *') gets the
                     region zone's UTC ticks; a pipeline start on a shipped value (23:30 Europe/Copenhagen, or the old 22:00)
                     gets 23:30 in the region's zone (Pro: the settings and the stored pipeline, with their change-log rows; a
                     folder install: its config files). A time the customer chose is kept. Never fails the update.
                     -DetectOnly: the plan only.
     9d. PIPELINE LAYOUT -- (#754, #748, setup/_shared/SI-PipelineLayout.ps1) the stored pipeline (cfg.JobFlow) as a new
                     install gets it: Risk Analysis Summary and Detailed side by side (layout level 3) on a pipeline still on
                     the default layout of its level, the verification service (the daily data health check) added where its
                     job is installed and the pipeline lacks it. Written only while nobody saved it meanwhile, read back, and
                     reading it again changes nothing. A pipeline a person changed is never re-laid. #636 (level 4): the Risk
                     Analysis Summary step switched off on a pipeline still the default of its level with every step on (one a
                     person changed keeps it, said in one line); then the scheduled management summary reports of the Summary
                     report's data show the Detailed report's (one line each). Never fails the update.
                     -DetectOnly: the plan only.
     9e. REPORT ROW COPY -- (#830, setup/_shared/SI-ReportCopyDefault.ps1) ONCE per install (cfg.InstallState
                     'ReportRowCopyDefault'): the copy of the Risk Analysis report rows to Log Analytics (SendToLogAnalytics,
                     SI_RiskAnalysis_Detailed_CL) is off, as in a new install (owner 2026-10-20: an optional output, off by
                     default). A value setup wrote (an import of the generated config file, setup, an update) is set off with
                     its change-log row; a value a person set on the Settings page is kept (one line); no stored value = the
                     solution-wide value off, which the jobs read after their environment. Never fails the update.
                     -DetectOnly: the plan only.
     9f. SUMMARY VIEWS -- (#842, setup/_shared/SI-SummaryGroupsRebuild.ps1) Pro: when collections hold Summary views written
                     from another definition than this release ships (data-model\summary-groupings.locked.json changed), ONE
                     run of the data sync step is queued in the pipeline's queue (cfg.PipelineQueue, the same statement and
                     dedup as Run now) -- it waits until no pipeline run is going -- so the views are written again now, not
                     on the next nightly run. A pipeline run or data sync already waiting, an install on its own job
                     schedules, or a pipeline without the data sync: nothing queued (one line says when they come). Nothing
                     to write again: nothing queued, nothing said. Never fails the update. -DetectOnly: the plan only.
     9i. KEY FIGURES -- (#855, engine/pro-data/_shared/SI-DataKeyFigures.ps1) Pro: the newest complete collections whose key
                     figures lack this release's marker are worked out again HERE with the engine's own statement and the
                     install's own protection-score settings -- no pipeline run, no data sync. Bounded (the newest 4, a time
                     budget). Nothing to do: nothing said. Never fails the update. -DetectOnly: how many would be.
     9j. PUBLISHED COPIES -- (engine/_shared/data-sql/SI-DataPublishedRun.ps1, Invoke-SIPublishedCopyCatchUp) Pro: a
                     published run whose copies of the merged assets (sidata.CiPub, AssetPub, ...) are older than it
                     (CopiedAt NULL or before PublishedAt) is refreshed now in the data database by sidata.PublishedCopyCatchUp
                     (only what changed). Current copies: nothing done, nothing said. Never fails the update. -DetectOnly:
                     only whether they are stale.
     9g. SIGN-IN FRONT STORE -- (#852, pro-management/deploy/SI-SigninFrontStore.ps1) Pro: what the shared sign-in front
                     1.3.0 needs before it starts, as a new install gets it -- the RSA key signin-front-dp in the install's Key
                     Vault (SI_UPDATER_KEY_VAULT, else SI_KeyVaultName), "Key Vault Crypto Service Encryption User" for the
                     web app's managed identity on THAT key only, the identity's contained user in the Pro database, the schema
                     signin owned by it and GRANT CREATE TABLE. Each piece only when missing, one line each, read back. Only
                     when ALL read back are the front's settings (SIGNIN_SQL_SERVER, SIGNIN_SQL_DATABASE,
                     SIGNIN_KEYVAULT_KEY_ID, SIGNIN_STATE_MI_CLIENT_ID) handed to the web app's front roll in this run
                     ($global:SI_SigninFrontStoreEnv): the front container gets them with every other setting kept. A piece
                     this update may not make is one customer action (setup\Set-SISigninFront.ps1 -Apply through the Support
                     app); a front 1.3.0 is then not rolled in -- the front keeps what it runs. An install that chose its own
                     sign-in is left alone. Never fails the update. -DetectOnly: the plan only.
     9k. OWN SQL TARGET -- (#865, setup/_shared/SI-OwnSqlConnector.ps1) Pro: SecurityInsight's own SQL vulnerability target
                     (cfg.Connector kind sql + direction vulnerability, `vulnerability-sql`) is always apply with create
                     and close -- one that is in test mode is set so, with its cfg.ChangeLog row, read back. A connector to
                     a customer system (ServiceNow, REST) and the SQL CMDB hand-off keep their own mode. On every update
                     (nothing to do: nothing said). Never fails the update. -DetectOnly: the plan only.
     9l. NIGHTLY 19:00 -- (setup/_shared/SI-NightlySchedule.ps1; owner 2026-10-21: "move the start time for all si jobs to
                     7pm on all sites" / "so they are done next morning") ONCE per install, right AFTER each part of 9c: the
                     updater on the region step's value (the zone's 23:00 ticks, tag '23:00 <zone>') gets the zone's 18:30
                     ticks and the tag '18:30 <zone>' (one PATCH of trigger + tags, read back; tag si-nightly-1900); a
                     pipeline start on the region step's value (23:30 in the region's zone) becomes 19:00 in the same zone
                     (Pro: the settings and the stored pipeline with their change-log rows, cfg.InstallState
                     'NightlySchedule1900'; a folder install: its config files, .si-update\nightly-schedule-1900.json). The
                     updater still runs before the pipeline the same evening. A time the customer chose is kept, said in
                     one line. Never fails the update. -DetectOnly: the plan only.
     9m. SERVICENOW DATA OUT -- (#903, setup/_shared/SI-SnowDataOutConnector.ps1) Pro: ONE ServiceNow connector (direction
                     data-out, always apply) feeds both ServiceNow Import Set outputs. While none exists, the connector the
                     data out used before becomes it (or one is created from the secret NAMES in use) -- keeping exactly
                     what is sent: switched on only where a ServiceNow output is on in SI_DataOut_Outputs, left off and said
                     where the outputs went to different instances; a table named only in its settings moves to its setting.
                     One transaction per connector with its cfg.ChangeLog row, guarded by RowVersion and the one-on rule,
                     read back. Never a delete, a secret value, an output switch, a close-loop / sql / rest row or a job.
                     Never fails the update. -DetectOnly: the plan only.
     9n. SERVICENOW STAGING STATUS -- (#912, setup/_shared/SI-SnowStagingStatus.ps1) Pro: a new install leaves
                     SI_DataOut_ServiceNowStagingStatusTable unset (= u_si_staging_status: every push is one batch, and nothing
                     is sent while that table cannot be written). The table is in the customer's ServiceNow, so an install that
                     ALREADY sends there (an Import Set table setting is set) gets the setting EMPTY, once, only while it has no
                     row: the rows go as before and the ServiceNow page warns until the customer's team creates the table and
                     the setting names it. With its cfg.ChangeLog row, read back. Never fails the update. -DetectOnly: the plan.
     9o. SERVICENOW ONE ROUTE -- (#914, setup/_shared/SI-SnowOneRoute.ps1) Pro: the older ServiceNow push was removed. ONCE per
                     install (cfg.InstallState 'SnowOneRoute') a setting of the older push that still holds a value is named
                     in one line of this log; nothing is deleted -- the rows stay and the code no longer reads them. Never
                     fails the update. -DetectOnly: the plan.
     11. SUPPORT ACCESS TO THE DATABASES -- NOT a step of the update: the Invardia Support app's database access (framework
                     section 4.1b: its place in the admin group and its own database user) is never removed and never
                     changed by an update. SecurityInsight reports both parts, read only, on the identified heartbeat;
                     Invardia repairs a missing part (owner 2026-10-18).
     12. DISPLAY NAMES -- (setup/_shared/SI-DisplayNames.ps1) the names people read, as a new install has them: the engine's
                     application "SecurityInsight" -> "SecurityInsight Engine", the web app's sign-in application "SecurityInsight
                     Management" -> "SecurityInsight", the SQL admin group shown as "SecurityInsight SQL admins" -- only from
                     SecurityInsight's earlier default, found by id, read back, put back on failure, never twice. Azure resources
                     keep their names. SI_Update_RenameDisplayNames (ON by default; the Pro setting first): off = the plan only.
                     Without the rights: one line, and setup\Set-SIDisplayNames.ps1 for an administrator. Never fails the update.

    -SizingOnly (#756): ONLY the size steps that read the customer's settings -- 7 (SQL database size), 8 (job size) and 8d
                     (web app size) -- for a run where the code is current already (caj-si-updater: the ring's release is
                     applied, so nothing is built or rolled). No image is built, no job is rolled, no template, config file or
                     customisation file is written; each step is idempotent and never fails the update; exit 0.

    -DetectOnly is the default (reports, changes nothing). -Apply performs the update.
    -Save records the resource group / registry / subscription you pass in config\SecurityInsight.custom.ps1,
    once, so every later sync finds the containers: the way an install made before 3.0.0 -- when setup never
    saved them -- is brought under automatic updates (#166).
    Authentication (#521, no az CLI, no PowerShell module): SecurityInsight's own REST token client, signed in ONCE
    (setup/_shared/SI-UpdateRest.ps1) -- the updater job's identity (SI_UPDATER_AUTH / SI_UPDATER_CLIENT_ID: its managed
    identity or its certificate), else the run's own sign-in from the config (the SI_SPN_* app or managed identity, as
    the engines sign in). Every ARM call names its subscription in the URL.

.LINK
    https://invardia.com/docs/si/scripts/Invoke-SIContainerUpdate/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Apply,
    [switch]$DetectOnly,
    [string]$ResourceGroupName,
    [string]$AcrName,
    [string]$SubscriptionId,
    [switch]$Save,
    # Roll by hand even though an updater job owns this install's rollout (Upgrade-SIToPro.ps1). The job will
    # move the containers back to the version your ring approves on its next run.
    [switch]$Force,
    [int]$BuildTimeoutMinutes = 30,
    # #405: RING 1 (internal) -- the templates shipped with this tree installed DIRECTLY (Publish-SITemplates
    # -InstallCurrent): no pack number, no gate, no pack recorded as a release. The ring 1 deploy passes it.
    [switch]$InstallTemplatesDirect,
    # #756: the code is current -- only the sizes the customer's settings set (steps 7, 8, 8d); nothing built or rolled.
    # The updater passes it on a run with no new code to install.
    [switch]$SizingOnly
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Invoke-SIContainerUpdate' -Quiet:($false)
if ($WhatIfPreference) { $Apply = [switch]$false; if ($Save) { $Save = [switch]$false; Write-Host '-WhatIf: the container hosting is not saved to config\SecurityInsight.custom.ps1.' -ForegroundColor Yellow } }   # -WhatIf = detect + plan: nothing is built or rolled
try {

$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot '_shared/SI-ContainerUpdate.ps1')
# #350: a deep install path is built from a short copy (a Windows host cannot read paths over 260 characters everywhere)
. (Join-Path $PSScriptRoot '_shared/SI-BuildStage.ps1')
# #521: Azure over REST only -- the one sign-in, the one seam (SI-UpdateRest.ps1) and the registry's own build (SI-AcrBuild.ps1)
. (Join-Path $PSScriptRoot '_shared/SI-UpdateRest.ps1')
. (Join-Path $PSScriptRoot '_shared/SI-AcrBuild.ps1')
# #416: the fast roll -- two-layer builds, queued builds, the parallel job swap
. (Join-Path $PSScriptRoot '_shared/SI-FastRoll.ps1')
# #911 (e): a step with no log line for 20 minutes says "still working: <step>" -- started here unless the updater runs one
$updWatchLib = Join-Path $PSScriptRoot '_shared/SI-UpdateWatch.ps1'
$script:SIUpdateWatchOwn = $false
if (Test-Path -LiteralPath $updWatchLib) {
    if (-not (Get-Command -Name Start-SIUpdateWatch -ErrorAction SilentlyContinue)) { . $updWatchLib }
    if (-not $global:SI_UpdateWatch) { try { $null = Start-SIUpdateWatch -QuietMinutes 20; $script:SIUpdateWatchOwn = $true } catch { } }
}

# #427: the stage and the first warning are left for the updater (caj-si-updater), which reports a failed update to
# Invardia with the step it stopped in (build / roll / restore) and its first error (the 400 "imageType" of 2026-10-06)
# #911 (d) / (e): every step beats the install's lock (when the updater holds it -- Invoke-SIUpdaterLockBeat, the updater's
# run gate), and every line tells the watch, so a long step says "still working" and is never mistaken for a hang
function Step([string]$m) { $global:SI_UpdateStage = $m; Write-Host "==> $m" -ForegroundColor Cyan
    if (Get-Command -Name Set-SIUpdateWatchLine -ErrorAction SilentlyContinue) { Set-SIUpdateWatchLine -Step $m }
    if (Get-Command -Name Invoke-SIUpdaterLockBeat -ErrorAction SilentlyContinue) { $null = Invoke-SIUpdaterLockBeat -What $m -Force }
}
function Info([string]$m) { Write-Host "    $m"; if (Get-Command -Name Set-SIUpdateWatchLine -ErrorAction SilentlyContinue) { Set-SIUpdateWatchLine } }
function Warn([string]$m) { if (-not "$global:SI_UpdateFirstWarn".Trim()) { $global:SI_UpdateFirstWarn = $m }; Write-Host "    $m" -ForegroundColor Yellow; if (Get-Command -Name Set-SIUpdateWatchLine -ErrorAction SilentlyContinue) { Set-SIUpdateWatchLine } }

# ---- 1. DETECT --------------------------------------------------------------------------------
Step '1. DETECT'
$customFile = Join-Path $solRoot 'config/SecurityInsight.custom.ps1'
$globals = @{}
if (Test-Path -LiteralPath $customFile) {
    # Read the customer's values in a child scope and keep only the names this script needs.
    # #182: a line in the customer's config that fails HERE (a Key Vault read this identity cannot make, say)
    # must not fail the update: the four names below are plain assignments, and everything the file set before
    # the failure is already in place. Say it once and carry on.
    try { & { . $customFile } 3>$null } catch { Warn ("config\SecurityInsight.custom.ps1 did not load completely here ({0}) -- continuing with what it set." -f $_.Exception.Message) }
    foreach ($n in 'SI_Bootstrap_ResourceGroupName', 'SI_Bootstrap_AcrName', 'SI_Bootstrap_SubscriptionId', 'SI_WorkspaceResourceId', 'SI_Bootstrap_UpdaterJob',
                   # #507: the SQL databases this install uses, and a database size the customer set (step 7)
                   'SI_ProSqlServer', 'SI_ProSqlDatabase', 'SI_LedgerSqlServer', 'SI_LedgerDatabase', 'SI_Pro_DataSqlServer', 'SI_Pro_DataSqlDatabase',
                   'SI_Bootstrap_SqlServiceObjective',
                   # the web app's size the customer set (step 8d; owner 2026-10-18)
                   'SI_Bootstrap_WebAppCpu', 'SI_Bootstrap_WebAppMemory',
                   # #519: queue scaling switched off by the customer, its worker cap, and the account of the shard queues (step 9)
                   'SI_Bootstrap_UseKEDA', 'SI_Bootstrap_KedaMaxReplicas', 'SI_StorageAccount',
                   # #742: the Risk Analysis workers -- on unless the customer switched them off -- and their cap (step 9b)
                   'SI_Bootstrap_RaScaleOut', 'SI_Bootstrap_RaMaxWorkers',
                   # #685: the timer a job this update creates gets in schedules mode (step 9a)
                   'SI_Bootstrap_ScheduleVerification',
                   # #714: the mail job's timer in schedules mode (its own setting, else the customer's send time)
                   'SI_Bootstrap_ScheduleCloseLoopMail', 'Mail_CloseLoop_Daily_SendTimeUtc',
                   # #715: whether ServiceNow is used (the settings Bootstrap reads) and the ServiceNow vulnerability job's timer
                   'SI_VulnSync_Target', 'SI_VulnSync_ServiceNowTable', 'SI_Bootstrap_ServiceNowVulnerabilities', 'SI_Bootstrap_ServiceNowCmdb',
                   'SI_EnableServiceNowCmdb', 'SI_Cmdb_Run', 'SI_Bootstrap_ScheduleVulnerabilitiesServiceNow',
                   # #723: the status report's own timer -- set = the customer's, never moved to the 15-minute timer
                   'SI_Bootstrap_ScheduleHeartbeat',
                   # the display names at an existing install (step 12): the switch, and the engine application's client id
                   'SI_Update_RenameDisplayNames', 'SI_SPN_AppId',
                   # #852: the install's Key Vault -- the sign-in front's key (step 9g)
                   'SI_KeyVaultName') {
        $v = Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction Ignore
        if ($null -ne $v) { $globals[$n] = $v }
    }
    # #509: a job size the customer set (step 8 keeps it)
    foreach ($gvar in @(Get-Variable -Scope Global -ErrorAction Ignore | Where-Object { $_.Name -match '^SI_Bootstrap_(Cpu|Memory|ReplicaTimeout)_' })) {
        if ($null -ne $gvar.Value) { $globals[$gvar.Name] = $gvar.Value }
    }
}
# THE NIGHTLY SCHEDULE, the folder's part (setup/_shared/SI-NightlySchedule.ps1): a pipeline start time in this folder's config
# files on a shipped value (23:30 Europe/Copenhagen, or the old 22:00) becomes 23:30 in the time zone of the install's Azure
# region, once -- before the files are shared with the container jobs below (after the sign-in, which reads the region; with no
# container hosting there is no region: Danish time). Only where the folder has its own config (an extracted release has
# none). Never fails the update.
$nightlyLib = Join-Path $PSScriptRoot '_shared/SI-NightlySchedule.ps1'
$script:SINightlyRegion = $null
if (Test-Path -LiteralPath $nightlyLib) { . $nightlyLib }
# #830 the report-row copy's one-time step (9e)
$reportCopyLib = Join-Path $PSScriptRoot '_shared/SI-ReportCopyDefault.ps1'
if (Test-Path -LiteralPath $reportCopyLib) { . $reportCopyLib }
# #865 SI's own SQL close-loop target always on (9k)
$ownSqlConnectorLib = Join-Path $PSScriptRoot '_shared/SI-OwnSqlConnector.ps1'
if (Test-Path -LiteralPath $ownSqlConnectorLib) { . $ownSqlConnectorLib }
# #903 one ServiceNow data-out connector for both outputs (9m)
$snowDataOutLib = Join-Path $PSScriptRoot '_shared/SI-SnowDataOutConnector.ps1'
if (Test-Path -LiteralPath $snowDataOutLib) { . $snowDataOutLib }
# #912 the ServiceNow staging status table: an install that already sends keeps sending (9n)
$snowStagingStatusLib = Join-Path $PSScriptRoot '_shared/SI-SnowStagingStatus.ps1'
if (Test-Path -LiteralPath $snowStagingStatusLib) { . $snowStagingStatusLib }
# #914 one route into ServiceNow: the older push's settings are named once and left in place (9o)
$snowOneRouteLib = Join-Path $PSScriptRoot '_shared/SI-SnowOneRoute.ps1'
if (Test-Path -LiteralPath $snowOneRouteLib) { . $snowOneRouteLib }
function Invoke-SIUpdateNightlyFiles {
    # -NoHosting: no container hosting, so no Azure region -- Danish time. With hosting, a region that could not be read leaves
    # the files for the next update (never records Danish time for an install whose region is simply not read yet).
    param([switch]$NoHosting)
    if ($SizingOnly) { return }   # #756: the settings-only size check writes no config file
    if (-not (Get-Command -Name Invoke-SINightlyPipelineFiles -ErrorAction SilentlyContinue)) { return }
    if (-not $NoHosting -and -not ($script:SINightlyRegion -and "$($script:SINightlyRegion.Region)".Trim())) { return }
    $rz = if ($script:SINightlyRegion) { $script:SINightlyRegion } else { Get-SINightlyRegionZone '' }
    $nf = Invoke-SINightlyPipelineFiles -Root $solRoot -Zone $rz.Zone -Region $rz.Region -WhatIf:(-not $Apply -or $DetectOnly)
    if (@($nf.Lines).Count -and $rz.Line) { Info $rz.Line }
    foreach ($l in @($nf.Lines)) { if ($nf.Action -eq 'failed') { Warn $l } else { Info $l } }
    # 9l: the 19:00 move of the folder's pipeline start, once, after the region step's files (owner 2026-10-21)
    if (Get-Command -Name Invoke-SINightly1900PipelineFiles -ErrorAction SilentlyContinue) {
        $n9 = Invoke-SINightly1900PipelineFiles -Root $solRoot -Zone $rz.Zone -Region $rz.Region -WhatIf:(-not $Apply -or $DetectOnly)
        if (@($n9.Lines).Count -and $rz.Line -and -not @($nf.Lines).Count) { Info $rz.Line }
        foreach ($l in @($n9.Lines)) { if ($n9.Action -eq 'failed') { Warn $l } else { Info $l } }
    }
}
$target =Resolve-SIContainerUpdateTarget -ResourceGroupName $ResourceGroupName -AcrName $AcrName -SubscriptionId $SubscriptionId -Globals $globals
if (-not $target) {
    if ($Save) { throw '-Save needs the containers to save: pass -ResourceGroupName and -AcrName (and -SubscriptionId unless the config has SI_WorkspaceResourceId).' }
    Invoke-SIUpdateNightlyFiles -NoHosting
    Info 'No container hosting is configured for this install -- nothing to update (the engines run from this folder).'
    exit 0
}
$sub = $target.SubscriptionId
Info ("resource group {0}, registry {1}" -f $target.ResourceGroupName, $target.AcrName)
if ($Save) {
    $saved = Save-SIContainerHostingConfig -ConfigPath $customFile -SubscriptionId $sub `
        -ResourceGroupName $target.ResourceGroupName -AcrName $target.AcrName
    Info ("saved in config\SecurityInsight.custom.ps1 ({0}) -- every later sync finds these containers." -f $(if ($saved.Changed) { 'written' } else { 'already there' }))
}

# #521: THE ONE SIGN-IN of this update -- SecurityInsight's own REST token client, no az, no module. The updater job's
# identity (SI_UPDATER_*: managed identity or certificate), else the run's own sign-in from the config. A sign-in the
# updater already made in this process is kept.
$rest = $null; $signInError = ''
try { $who = Connect-SIUpdateRest -SubscriptionId $sub; $rest = New-SIUpdateRestSeam; Info ("signed in to Azure over REST as {0}" -f $who) }
catch { $signInError = $_.Exception.Message }
# the install's Azure region (its Container Apps environment, else its resource group) -> the nightly schedule's time zone
# (#756 -SizingOnly: no config file is written, so neither the region nor the folder's schedule is read)
if ($rest -and -not $SizingOnly -and (Get-Command -Name Get-SINightlyInstallRegion -ErrorAction SilentlyContinue)) {
    $script:SINightlyRegion = Get-SINightlyRegionZone (Get-SINightlyInstallRegion -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName)
}
Invoke-SIUpdateNightlyFiles

# The install's customisation files (CMDB.csv, custom queries, exclusions, enrichment rules...) reach the container jobs
# through its storage account, never through the image -- so a change made here since the last sync is shared now, whoever
# rolls the image. Not on an install that keeps its configuration in the Pro settings database. Never fails the update.
$ovAccount = [string](Get-Variable -Name SI_StorageAccount -Scope Global -ValueOnly -ErrorAction Ignore)
$ovPro = (Get-Variable -Name SI_ProSqlServer -Scope Global -ValueOnly -ErrorAction Ignore) -and (Get-Variable -Name SI_ProSqlDatabase -Scope Global -ValueOnly -ErrorAction Ignore) -and
         (Test-Path -LiteralPath (Join-Path $solRoot 'engine/pro-settings/SI-ProSettings.ps1'))
$ovLib = Join-Path $solRoot 'container/_shared/SI-ContainerRunState.ps1'
if ($ovAccount -and -not $ovPro -and -not $SizingOnly -and (Test-Path -LiteralPath $ovLib)) {
    . $ovLib
    if ($Apply -and -not $DetectOnly) {
        if ($rest) {
            $ov = Publish-SIContainerOverlay -Root $solRoot -AccountName $ovAccount -Rest $rest
            if (@($ov.Failed).Count) { Warn $ov.Message } else { Info $ov.Message }
        } else { Warn ("the customisation files were not shared: no Azure sign-in ({0})" -f $signInError) }
    } else {
        Info ("{0} customisation file(s) would be shared with the container jobs (re-run with -Apply)." -f @(Get-SIContainerOverlayFiles -Root $solRoot).Count)
    }
}
# Pro: once Upgrade-SIToPro.ps1 has installed the updater job, the JOB rolls these containers -- to what this
# customer's ring approves. A roll from here would put them on whatever this folder holds instead.
# #250: Pro -- the default templates (template pack 1.0), installed or kept current once the jobs run this tree.
$proTemplates = $ovPro -and (Test-Path -LiteralPath (Join-Path $solRoot 'setup/Publish-SITemplates.ps1'))
function Install-SIUpdateDefaultTemplates {
    if (-not $proTemplates) { return 0 }
    if (-not $Apply -or $DetectOnly) { Info 'Pro: the default templates (template pack 1.0) are installed or kept current on -Apply.'; return 0 }
    Step '6. TEMPLATES (Pro)'
    try {
        if ($InstallTemplatesDirect) {
            # #405: ring 1 -- every template of this tree, directly (no pack, no gate)
            $r = & (Join-Path $solRoot 'setup/Publish-SITemplates.ps1') -InstallCurrent -PassThru | Where-Object { $_ -and $_.PSObject.Properties['Mode'] } | Select-Object -Last 1
        } else {
        $r = & (Join-Path $solRoot 'setup/Publish-SITemplates.ps1') -InstallDefault -PassThru | Where-Object { $_ -and $_.PSObject.Properties['Mode'] } | Select-Object -Last 1
        }
        if ($r -and $r.Mode -eq 'blocked') { Info ("default templates: waiting for a review on the Template releases page -- {0}" -f $r.Reason) }
        else { Info ("default templates: {0}" -f $(if ($r) { $r.Reason } else { 'done' })) }
    } catch {
        Warn ("The default templates were not installed: {0} -- the jobs run on; the next setup or update run tries again." -f $_.Exception.Message)
    }
    0
}
# A SIZE THE CUSTOMER SET, as the update reads it (owner 2026-10-18: support sets it per install through the product's settings
# path): the Pro database's value (cfg.Setting, solution scope -- the Settings page, setup\Set-SIProSetting.ps1) first, then the
# install's config, then the updater job's variable (-EnvName). '' when none is set. The Pro database is read ONCE per update,
# every name below in one parameterised statement, signed in with this update's own token; a database that cannot be read is
# one line, and the config and the variable still count.
$script:SIUpdateProSettings = $null
$script:SIUpdateProSettingNames = @('SI_Bootstrap_SqlServiceObjective', 'SI_Bootstrap_WebAppCpu', 'SI_Bootstrap_WebAppMemory')
function ConvertFrom-SIUpdateSettingJson {
    <# PURE. A cfg.Setting ValueJson ('"S2"', '2.5', 'null') -> its text ('' for none); text that is not JSON is taken as it is. #>
    param([AllowNull()]$Json)
    if ($null -eq $Json -or $Json -is [DBNull]) { return '' }
    $raw = "$Json".Trim()
    if (-not $raw) { return '' }
    $v = $raw; try { $v = ConvertFrom-Json -InputObject $raw } catch { $v = $raw }
    if ($null -eq $v) { return '' }
    if ($v -is [double] -or $v -is [decimal] -or $v -is [single]) { return $v.ToString([Globalization.CultureInfo]::InvariantCulture) }
    "$v".Trim()
}
function Get-SIUpdateSetting {
    param([Parameter(Mandatory)][string]$Name, [string]$EnvName)
    if ($null -eq $script:SIUpdateProSettings) {
        $script:SIUpdateProSettings = @{}
        $proSrv = "$([Environment]::GetEnvironmentVariable('SI_UPDATER_PRO_SQL_SERVER'))".Trim(); if (-not $proSrv -and $globals.ContainsKey('SI_ProSqlServer')) { $proSrv = "$($globals['SI_ProSqlServer'])".Trim() }
        $proDb = "$([Environment]::GetEnvironmentVariable('SI_UPDATER_PRO_SQL_DATABASE'))".Trim(); if (-not $proDb -and $globals.ContainsKey('SI_ProSqlDatabase')) { $proDb = "$($globals['SI_ProSqlDatabase'])".Trim() }
        if ($proSrv -and $proDb -and (Get-Command -Name Get-SIAzureToken -ErrorAction SilentlyContinue)) {
            if ($proSrv -notmatch '\.') { $proSrv = $proSrv + '.database.windows.net' }
            $cn = $null
            try {
                $tok = ([string](Get-SIAzureToken -Resource 'https://database.windows.net/')).Trim()
                if (-not $tok) { throw 'no access token for the database' }
                $cn = New-Object System.Data.SqlClient.SqlConnection
                $cn.ConnectionString = "Server=tcp:$proSrv,1433;Database=$proDb;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
                $cn.AccessToken = $tok
                $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandTimeout = 0
                $ps = @(); $i = 0
                foreach ($n in $script:SIUpdateProSettingNames) { $p = '@n{0}' -f $i; $null = $cmd.Parameters.AddWithValue($p, $n); $ps += $p; $i++ }
                $cmd.CommandText = "IF OBJECT_ID('cfg.Setting') IS NOT NULL SELECT Name, ValueJson FROM cfg.Setting WHERE Scope = N'solution' AND Name IN ({0});" -f ($ps -join ', ')
                $rd = $cmd.ExecuteReader()
                try { while ($rd.Read()) { $script:SIUpdateProSettings[[string]$rd.GetValue(0)] = ConvertFrom-SIUpdateSettingJson $rd.GetValue(1) } } finally { $rd.Dispose() }
            } catch { Info ("settings: the Pro database's settings could not be read ({0}) -- the config and the job's variables count" -f $_.Exception.Message) }
            finally { if ($cn) { $cn.Dispose() } }
        }
    }
    if ($script:SIUpdateProSettings.ContainsKey($Name) -and "$($script:SIUpdateProSettings[$Name])".Trim()) { return "$($script:SIUpdateProSettings[$Name])".Trim() }
    if ($globals.ContainsKey($Name) -and "$($globals[$Name])".Trim()) { return "$($globals[$Name])".Trim() }
    if ($EnvName) { $v = [Environment]::GetEnvironmentVariable($EnvName); if ("$v".Trim()) { return "$v".Trim() } }
    ''
}
# #507: THE SQL DATABASE SIZE (setup/_shared/SI-SqlTier.ps1) -- every update raises a Basic (or smaller-than-the-rule)
# SI database to its size (#509: the Pro database S3, the identity ledger S1), by one online ARM PATCH of its sku. Without a
# size the customer set it never lowers, and never touches a database above S3, on Premium, on vCore or in an elastic pool.
# A size the customer set (SI_Bootstrap_SqlServiceObjective: the Pro database's setting, then the config, then the updater
# job's SI_UPDATER_SQL_SERVICE_OBJECTIVE) applies in BOTH directions (owner 2026-10-18: S2 on an S3 database lowers it),
# never below S1. One line per database in this log; the updater records the summary (cfg.InstallState 'SqlTier'). Never
# fails the update.
function Invoke-SIUpdateSqlTier {
    $lib = Join-Path $PSScriptRoot '_shared/SI-SqlTier.ps1'
    if (-not (Test-Path -LiteralPath $lib) -or -not $rest) { return }
    try {
        . $lib
        Step '7. SQL DATABASE SIZE'
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        # the tenant's size: Graph $count as this identity; else the collection jobs setup sized for it; else S1
        $objects = Get-SISqlTierObjectCount -Counts (Get-SISqlTierTenantCounts -Rest $rest -SubscriptionId $sub)
        $sizeFrom = 'the directory'
        if ($null -eq $objects) { $objects = Get-SISqlTierObjectsFromJobs -Jobs @($script:SISqlTierJobs); $sizeFrom = 'the collection jobs'' size' }
        Info ("tenant size: {0}" -f $(if ($null -ne $objects) { '{0:N0}+ directory objects (from {1})' -f $objects, $sizeFrom } else { 'not readable by this identity (no directory read, no sized collection job)' }))
        $override = Get-SIUpdateSetting -Name 'SI_Bootstrap_SqlServiceObjective' -EnvName 'SI_UPDATER_SQL_SERVICE_OBJECTIVE'
        $servers = @((& $envOr 'SI_UPDATER_PRO_SQL_SERVER'), (& $gv 'SI_ProSqlServer'), (& $gv 'SI_LedgerSqlServer'), (& $gv 'SI_Pro_DataSqlServer')) | Where-Object { $_ }
        $dbs = @((& $envOr 'SI_UPDATER_PRO_SQL_DATABASE'), (& $gv 'SI_ProSqlDatabase'), (& $gv 'SI_Pro_DataSqlDatabase')) | Where-Object { $_ }
        # the identity ledger: S1 at any tenant size (identifiers only; the record writes are in the Pro database)
        $ledger = @((& $gv 'SI_LedgerDatabase')) | Where-Object { $_ }
        $up = Invoke-SISqlTierUpgrade -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -ServerFqdns @($servers) -DatabaseNames @($dbs) -LedgerDatabaseNames @($ledger) `
                -Objects $objects -Override $override -WhatIf:(-not $Apply -or $DetectOnly)
        foreach ($l in @($up.Lines)) { if ($l -match 'NOT raised|NOT lowered|may not change|refused this identity|was not found') { Warn $l } else { Info $l } }
        $global:SI_UpdateSqlTier = Get-SISqlTierSummaryLine -Upgrade $up
    } catch { Warn ("SQL database size: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# #509: THE JOB SIZE (setup/_shared/SI-JobSizing.ps1) -- every update re-applies the sizing rule setup uses at install
# (Get-SITenantSizedJobResources) to the identity / endpoint / CI build / Risk Analysis jobs, and raises a job whose last run
# ran out of memory or hit its replica timeout one band. The run limit is not sized: every engine job has the longest one
# Azure takes (the job floor, step 8c, sets it; this step applies the same value), and the pipeline job itself 7 days.
# Raises only, never above 4 CPU / 8 GiB; a size the customer
# set (SI_Bootstrap_Cpu_ / _Memory_ / _ReplicaTimeout_<Engine>) wins. One line per job changed. Never fails the update.
function Invoke-SIUpdateJobSizing {
    $lib = Join-Path $PSScriptRoot '_shared/SI-JobSizing.ps1'
    if (-not (Test-Path -LiteralPath $lib) -or -not @($script:SISqlTierJobs).Count -or -not $rest) { return }
    try {
        . $lib
        Step '8. JOB SIZE'
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        # the Pro database (the records the last collection wrote): signed in with this update's own token (REST client)
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        $sqlRows = $null
        if ($proSrv -and $proDb) {
            $sqlRows = {
                param([string]$Sql)
                $tok = ''; try { $tok = [string](Get-SIAzureToken -Resource 'https://database.windows.net/') } catch { $tok = '' }
                if (-not $tok.Trim()) { return @() }
                $cn = New-Object System.Data.SqlClient.SqlConnection
                $cn.ConnectionString = "Server=tcp:$proSrv,1433;Database=$proDb;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
                $cn.AccessToken = $tok.Trim()
                try {
                    $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $Sql; $cmd.CommandTimeout = 0
                    $rd = $cmd.ExecuteReader()
                    try { while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $rd.GetValue($i) }; [pscustomobject]$o } } finally { $rd.Dispose() }
                } finally { $cn.Dispose() }
            }   # dynamic scope: $proSrv, $proDb come from this function
        }
        $ws = & $envOr 'SI_UPDATER_WORKSPACE_RESOURCE_ID'; if (-not $ws) { $ws = & $gv 'SI_WorkspaceResourceId' }
        $js = Invoke-SIJobSizing -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Jobs @($script:SISqlTierJobs) -Globals $globals `
                -SqlRows $sqlRows -WorkspaceResourceId $ws -WhatIf:(-not $Apply -or $DetectOnly)
        foreach ($l in @($js.Lines)) { if ($l -match 'NOT raised|not checked') { Warn $l } else { Info $l } }
    } catch { Warn ("job size: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# #519: QUEUE SCALING FOR EXISTING INSTALLS (setup/_shared/SI-KedaConvert.ps1) -- an install made before queue scaling still
# runs identity / endpoint / Azure as one scheduled job each. Every update moves such a job to what setup gives a new
# install: a producer + queue-scaled workers, built by Bootstrap's own job definitions from the old job (image, settings,
# identity, size, schedule). Only a job SI's setup made, signed in with the managed identity, not switched off
# (SI_Bootstrap_UseKEDA = $false / SI_UPDATER_USE_KEDA = false). The old job loses its timer only after both new jobs are
# read back, and before the producer gets it; it is kept. Any failure: the old job runs on. Never fails the update.
function Invoke-SIUpdateKedaConvert {
    $lib = Join-Path $PSScriptRoot '_shared/SI-KedaConvert.ps1'
    if (-not (Test-Path -LiteralPath $lib) -or -not @($script:SISqlTierJobs).Count) { return }
    try {
        . $lib
        Step '9. QUEUE SCALING'
        # ON for every install (owner 2026-10-10: "live for r1 and r2"); SI_UPDATER_KEDA_CONVERT = off on an install's updater
        # job keeps that install on the PLAN only ("would move ..."), nothing changes there
        $kcOn = -not ("$([Environment]::GetEnvironmentVariable('SI_UPDATER_KEDA_CONVERT'))".Trim() -match '^(?i)(0|false|off|no)$')
        if ($Apply -and -not $DetectOnly -and -not $kcOn) { Info 'queue scaling: the plan only -- queue scaling is switched off for this install''s updater.' }
        $kcWhatIf = (-not $Apply -or $DetectOnly -or -not $kcOn)
        if (-not $rest) { $kcWhatIf = $true }   # no Azure sign-in here: the plan only
        $kcJobs = @($script:SISqlTierJobs)
        if (-not $kcWhatIf) {
            # NO az CLI here (operator: "pure rest or arm only"): ARM and the queue data plane through this update's REST seam
            # (setup/_shared/SI-UpdateRest.ps1 over engine/_shared/SI-AzRest.ps1); every 4xx but 401 is an ANSWER for the
            # caller (409 = the queue exists, 404 = not there)
            $kcRest = $rest
            # the jobs as they are NOW (the roll and the job size above may have changed them): the new jobs take over their image and size
            try { $v = @(Get-SIArmJobList -Rest $kcRest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName); if ($v.Count) { $kcJobs = $v } } catch { }
        } else { $kcRest = { param($Method, $Uri, $Body, $Resource, $Headers) [pscustomobject]@{ Status = 0; Body = '-WhatIf' } } }
        $kc = Invoke-SIKedaConvert -Rest $kcRest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Jobs $kcJobs -Globals $globals `
                -UpdaterUseKeda ([string][Environment]::GetEnvironmentVariable('SI_UPDATER_USE_KEDA')) -WhatIf:$kcWhatIf
        foreach ($l in @($kc.Lines)) { if ($l -match 'NOT moved|not checked|could not') { Warn $l } else { Info $l } }
    } catch { Warn ("queue scaling: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# #742: THE RISK ANALYSIS WORKERS FOR EXISTING INSTALLS (setup/_shared/SI-RaWorkerJobs.ps1) -- ON BY DEFAULT where they can
# run (owner 2026-10-18: "pls dont turn off things that improve time, why do that"; rule: existing installs reach new-install
# state): the update gives the install the worker job a new install gets, built from the Risk Analysis job (image, settings,
# identity, size), read back, and only then tells the Risk Analysis job (SI_RA_SCALE_OUT / SI_RA_WORKER_JOB). Only a job SI's
# setup made, signed in with the managed identity, queue scaling not switched off -- otherwise nothing changes and one line
# says why. The customer's SI_Bootstrap_RaScaleOut = $false (or SI_UPDATER_RA_SCALE_OUT = off): no worker is made, and a Risk
# Analysis job still told it is a producer is told it is not (read back). Idempotent: a second run finds 'present'. Any
# failure: the job runs its reports itself, as before; the next update tries again. Never fails the update.
function Invoke-SIUpdateRaWorkers {
    $lib = Join-Path $PSScriptRoot '_shared/SI-RaWorkerJobs.ps1'
    if (-not (Test-Path -LiteralPath $lib) -or -not @($script:SISqlTierJobs).Count) { return }
    try {
        . $lib
        $rwJobs = @($script:SISqlTierJobs)
        if (-not @($rwJobs | Where-Object { [string]$_.name -eq 'caj-si-risk-analysis-detailed' }).Count) { return }
        Step '9b. RISK ANALYSIS WORKERS'
        $rwWhatIf = (-not $Apply -or $DetectOnly)
        if (-not $rest) { $rwWhatIf = $true }
        if (-not $rwWhatIf) { try { $v = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName); if ($v.Count) { $rwJobs = $v } } catch { } }
        $rwRest = if ($rwWhatIf) { { param($Method, $Uri, $Body, $Resource, $Headers) [pscustomobject]@{ Status = 0; Body = '-WhatIf' } } } else { $rest }
        $rw = Invoke-SIRaWorkerJobs -Rest $rwRest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Jobs $rwJobs -Globals $globals `
                -UpdaterUseKeda ([string][Environment]::GetEnvironmentVariable('SI_UPDATER_USE_KEDA')) -UpdaterRaScaleOut ([string][Environment]::GetEnvironmentVariable('SI_UPDATER_RA_SCALE_OUT')) -WhatIf:$rwWhatIf
        foreach ($l in @($rw.Lines)) { if ($l -match 'NOT |not checked|could not') { Warn $l } else { Info $l } }
    } catch { Warn ("risk analysis workers: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# THE UPDATER'S OWN SIZE (owner 2026-10-10: the registry build ran out of memory on 0.5 CPU / 1 GiB): every update raises the
# updater job to at least 4 CPU / 8 GiB -- what setup gives a new install -- keeping its image and everything else (one
# read-modify-write PATCH of its template). Raises only; a bigger size is kept. The NEXT run uses it (this execution keeps
# the size it started with). Never fails the update.
function Invoke-SIUpdateUpdaterSize {
    if (-not $rest) { return }
    try {
        $name = [string](Get-SIUpdaterManagedJob -Globals $globals)
        if (-not $name.Trim()) { $name = [string][Environment]::GetEnvironmentVariable('CONTAINER_APP_JOB_NAME') }
        if (-not $name.Trim()) { return }
        Step '8b. UPDATER SIZE'
        $uri = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}?api-version=2025-07-01' -f $sub, $target.ResourceGroupName, $name.Trim()
        $g = & $rest 'GET' $uri $null 'https://management.azure.com' @{}
        if (-not $g -or [int]$g.Status -ne 200) { Warn ("updater size: {0} could not be read (HTTP {1}) -- the next update tries again" -f $name, $(if ($g) { $g.Status } else { 0 })); return }
        $job = [string]$g.Body | ConvertFrom-Json
        $first = @($job.properties.template.containers | Where-Object { $_ }) | Select-Object -First 1
        if (-not $first) { return }
        # THE UPDATER'S RUN LIMIT (owner 2026-10-22: "i accept no limits" / "remove those stupid breaks"): the updater works out
        # key figures, published copies and schema batches over every row of a large install -- it gets the run limit every
        # engine job gets (Get-SIJobRunLimit, the longest Azure takes; a refusal above 24 hours is sent again as 24 hours by
        # Invoke-SIJobSizePatch). Raises only; the next updater run has it.
        $jsLib = Join-Path $PSScriptRoot '_shared/SI-JobSizing.ps1'
        if (-not (Get-Command -Name Invoke-SIJobSizePatch -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $jsLib)) { . $jsLib }
        if ((Get-Command -Name Get-SIJobRunLimit -ErrorAction SilentlyContinue) -and (Get-Command -Name Invoke-SIJobSizePatch -ErrorAction SilentlyContinue)) {
            $rtNow = 0; try { $rtNow = [int]"$($job.properties.configuration.replicaTimeout)" } catch { $rtNow = 0 }
            $rtWant = [int](Get-SIJobRunLimit)
            if ($rtNow -gt 0 -and $rtNow -lt $rtWant) {
                if (-not $Apply -or $DetectOnly) { Info ("updater run limit: {0} would be raised from {1} s to {2} s (re-run with -Apply)" -f $name, $rtNow, $rtWant) }
                else {
                    $rl = Invoke-SIJobSizePatch -Rest $rest -JobUri $uri -JobName $name.Trim() -ReplicaTimeout $rtWant -CurrentReplicaTimeout $rtNow
                    foreach ($l in @($rl.Lines)) { Info $l }
                    if ($rl.Ok) { Info ("updater run limit: {0} raised from {1} s to {2} s -- the next run uses it" -f $name, $rtNow, $rl.ReplicaTimeout) }
                    else { Warn ("updater run limit: {0} was NOT raised ({1}) -- the next update tries again" -f $name, $rl.Why) }
                    # the size below is worked out on the job as it is now
                    $g = & $rest 'GET' $uri $null 'https://management.azure.com' @{}
                    if ($g -and [int]$g.Status -eq 200) { $job = [string]$g.Body | ConvertFrom-Json; $first = @($job.properties.template.containers | Where-Object { $_ }) | Select-Object -First 1 }
                }
            }
        }
        $body = New-SITemplateImagePatchBody -Resource $job -Image ([string]$first.image) -MinCpu 4 -MinMemoryGi 8
        $want = ($body | ConvertFrom-Json).properties.template.containers[0].resources
        $cur = '{0} CPU / {1}' -f $first.resources.cpu, $first.resources.memory
        if ([string]$want.cpu -eq [string]$first.resources.cpu -and [string]$want.memory -eq [string]$first.resources.memory) { Info ("updater size: {0} runs {1} -- nothing to raise" -f $name, $cur); return }
        if (-not $Apply -or $DetectOnly) { Info ("updater size: {0} would be raised from {1} to {2} CPU / {3} (re-run with -Apply)" -f $name, $cur, $want.cpu, $want.memory); return }
        $r = & $rest 'PATCH' $uri $body 'https://management.azure.com' @{ 'Content-Type' = 'application/json' }
        if (-not $r -or [int]$r.Status -lt 200 -or [int]$r.Status -ge 300) { Warn ("updater size: {0} was NOT raised (HTTP {1}) -- the next update tries again" -f $name, $(if ($r) { $r.Status } else { 0 })); return }
        Info ("updater size: {0} raised from {1} to {2} CPU / {3} -- the next run uses it" -f $name, $cur, $want.cpu, $want.memory)
    } catch { Warn ("updater size: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# THE JOB FLOOR (setup/_shared/SI-JobSizing.ps1, Invoke-SIJobFloor). Every update raises EVERY caj-si-* job (not the
# updater -- its own step gives it 4 / 8) to at least 2 CPU / 4 GiB (owner 2026-10-10: "money must not be the case", "time
# is critical"), a queue producer to at least its engine's single job, and gives it THE RUN LIMIT EVERY ENGINE JOB GETS:
# the longest one Azure takes (Get-SIJobRunLimit; owner 2026-10-13: "we are not to judge that and it breaks the whole
# solution") -- SecurityInsight chooses no run limit. It needs no run history: a job that never finished a run is raised
# like any other (a customer's CI build was stopped at 2 hours three runs in a row and four updates left it there). The
# pipeline job keeps its own rule; a run limit the customer set is left alone. Raises only. One line per job. The job list
# is read again afterwards, so the steps after this one see what the jobs have now. Never fails the update.
function Invoke-SIUpdateJobFloor {
    $lib = Join-Path $PSScriptRoot '_shared/SI-JobSizing.ps1'
    if (-not (Test-Path -LiteralPath $lib) -or -not $rest) { return }
    try {
        . $lib
        $all = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName)
        if (-not @($all | Where-Object { [string]$_.name -like 'caj-si-*' }).Count) { return }
        Step ('8c. JOB FLOOR (2 CPU / 4 GiB; run limit {0}, the longest Azure takes)' -f (Format-SIJobTimeout -Seconds ([int](Get-SIJobRunLimit))))
        $fl = Invoke-SIJobFloor -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Jobs $all -Globals $globals `
                -UpdaterName ([string](Get-SIUpdaterManagedJob -Globals $globals)) -WhatIf:(-not $Apply -or $DetectOnly)
        foreach ($l in @($fl.Lines)) { if ($l -match 'NOT raised|not checked') { Warn $l } else { Info $l } }
        if (@($fl.Results | Where-Object { $_.Action -eq 'raised' }).Count) {
            try { $v = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName); if ($v.Count) { $script:SISqlTierJobs = $v } } catch { }
        }
    } catch { Warn ("job floor: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# THE ENGINE JOBS' RETRY LIMIT (2026-10-16 for Risk Analysis, every engine job since 2026-10-23; setup/_shared/SI-JobSizing.ps1
# Invoke-SIEngineJobRetryLimit): every job the pipeline starts gets replicaRetryLimit 0 -- a failed run is never restarted by
# Azure inside the same execution (the pipeline decides). The runner (caj-si-flow), the updater and the jobs that are no step
# keep theirs. One read-modify-write PATCH per job, read back; one line per job. The first time
# this reaches an install it also says, once, that the detailed Excel workbook is now off by default. Never fails the update.
function Invoke-SIUpdateEngineRetryLimit {
    $lib = Join-Path $PSScriptRoot '_shared/SI-JobSizing.ps1'
    if (-not (Test-Path -LiteralPath $lib) -or -not $rest) { return }
    try {
        . $lib
        $all = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName)
        $res = @(Invoke-SIEngineJobRetryLimit -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Jobs $all -WhatIf:(-not $Apply -or $DetectOnly))
        if (-not $res.Count) { return }
        Step '8e. ENGINE JOB RETRY LIMIT (0: a failed run is not restarted by Azure; the pipeline decides)'
        foreach ($r in $res) { if ($r.Action -eq 'failed') { Warn $r.Line } else { Info $r.Line } }
        if (@($res | Where-Object { $_.Action -eq 'set' -and [string]$_.Job -eq 'caj-si-risk-analysis-detailed' }).Count) {
            Info 'excel export: the detailed Risk Analysis workbook is now off by default (SI_RA_ExcelExport_Detailed) -- an install that set it keeps its choice; every row is in the web app. The summary workbook stays on.'
        }
    } catch { Warn ("retry limit: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# #873 E -- THE RISK ANALYSIS JOBS' .NET GEN0 BUDGET (setup/_shared/SI-RaGcSetting.ps1): every Risk Analysis job, its extra
# report jobs and its queue workers get DOTNET_GCgen0size (256 MB) when it is missing -- what a new install gets
# (Get-SIRaJobEnvArgs). One read-modify-write PATCH of the first container's environment per job, read back; one line per
# job. A job that has the variable keeps its value. SI_Bootstrap_RaGcGen0Size = off: not added. Never fails the update.
function Invoke-SIUpdateRaGcSetting {
    $lib = Join-Path $PSScriptRoot '_shared/SI-RaGcSetting.ps1'
    if (-not (Test-Path -LiteralPath $lib) -or -not $rest) { return }
    try {
        . $lib
        if (-not (Get-Command -Name Get-SIArmJobList -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '_shared/SI-FastRoll.ps1') }
        $all = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName)
        $res = @(Invoke-SIRaGcSetting -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Jobs $all -Globals $globals -WhatIf:(-not $Apply -or $DetectOnly))
        if (-not $res.Count) { return }
        Step '8f. RISK ANALYSIS GC (a 256 MB gen0 budget for the scoring; no row changes)'
        foreach ($r in $res) { if ($r.Action -eq 'failed') { Warn $r.Line } else { Info $r.Line } }
    } catch { Warn ("risk analysis GC: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# "NEITHER MODE" (found live on a ring 2 install 2026-10-10: caj-si-flow had no timer and no job of the pipeline had its own
# -- nothing ran for 14 h): every update puts it back to the pipeline (flow mode), by the same plan and PATCH as
# setup\Switch-SIJobOrchestration.ps1 -Mode flow (engine\_shared\SI-JobFlow.ps1 Invoke-SIJobOrchestrationRepair), one plain
# warning line. -DetectOnly: the plan only. Any other state is left exactly as it is. Never fails the update.
function Invoke-SIUpdateOrchestration {
    if (-not $rest) { return }
    try {
        . (Join-Path $solRoot 'engine/_shared/SI-JobFlow.ps1')
        Step '9b. PIPELINE SCHEDULE'
        $all = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName)
        # #732 (live 2026-10-17: one install's caj-si-flow was Manual and never ran; a queued run waited 6 h): the pipeline
        # runner of an existing install gets the schedule a new install gets ("*/5 * * * *") -- one read-modify-write PATCH
        # (whole template, run limit kept, no secret sent back), read back, one plain line. Never fails the update.
        try {
            $fr = Invoke-SIFlowRunnerSchedule -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Jobs $all -WhatIf:(-not $Apply -or $DetectOnly)
            if ($fr.State -eq 'failed') { Warn $fr.Line } else { Info $fr.Line }
            if ($fr.State -eq 'patched') { try { $v = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName); if ($v.Count) { $all = $v } } catch { } }
            $global:SI_UpdateFlowRunner = $fr
        } catch { Warn ("pipeline runner: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
        # #732 (owner 2026-10-17: ONE method everywhere): an install that runs its jobs on their own timers is moved to the
        # pipeline -- only when nothing runs (else one line, the next update tries again), everything read back, put back on
        # its timers if a step fails, one run queued when today's start would otherwise be skipped. -DetectOnly: the plan only.
        if ($fr -and $fr.State -eq 'schedules-mode') {
            try {
                $migSql = $null
                $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
                $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
                $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
                $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
                if ($proSrv -and $proDb) {
                    if ($proSrv -notmatch '\.') { $proSrv = $proSrv + '.database.windows.net' }
                    # parameterised statements on the Pro database, signed in with this update's own token (a new connection per call)
                    $migSql = {
                        param([string]$Query, $Params, [string]$Mode)
                        $tok = ([string](Get-SIAzureToken -Resource 'https://database.windows.net/')).Trim()
                        if (-not $tok) { throw 'no access token for the database' }
                        $cn = New-Object System.Data.SqlClient.SqlConnection
                        $cn.ConnectionString = "Server=tcp:$proSrv,1433;Database=$proDb;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
                        $cn.AccessToken = $tok
                        try {
                            $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0
                            if ($Params) { foreach ($k in @($Params.Keys)) { $pv = $Params[$k]; $null = $cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $pv) { [DBNull]::Value } else { $pv })) } }
                            if ($Mode -eq 'nonquery') { return $cmd.ExecuteNonQuery() }
                            $rd = $cmd.ExecuteReader()
                            try { while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $rd.GetValue($i) }; [pscustomobject]$o } } finally { $rd.Dispose() }
                        } finally { $cn.Dispose() }
                    }   # dynamic scope: $proSrv, $proDb come from this function
                }
                $mig = Invoke-SIJobFlowMigration -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Jobs $all -Sql $migSql -WhatIf:(-not $Apply -or $DetectOnly)
                foreach ($l in @($mig.Lines)) { if ($mig.State -in @('failed', 'reverted')) { Warn $l } else { Info $l } }
                $global:SI_UpdateFlowMigration = $mig
                if (@($mig.Changed).Count) { try { $v = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName); if ($v.Count) { $all = $v } } catch { } }
            } catch { Warn ("switch to the pipeline: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
        }
        $arm = {
            param($Method, $Path, $Body)
            $u = 'https://management.azure.com{0}?api-version={1}' -f $Path, $script:SIFastRollArmApi
            Invoke-SIRestJson -Rest $rest -Method $Method -Uri $u -Body $(if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 10 -Compress } else { $null }) `
                -Headers @{ 'Content-Type' = 'application/json' } -What ('{0} {1}' -f $Method, ($Path -split '/')[-1])
        }
        $r = Invoke-SIJobOrchestrationRepair -Jobs $all -Arm $arm -WhatIf:(-not $Apply -or $DetectOnly) -Log { param($l, $m) if ($l -eq 'WARN') { Warn $m } else { Info $m } }
        $global:SI_UpdateOrchestration = $r
    } catch { Warn ("pipeline schedule: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# THE WEB APP'S SIZE (owner 2026-10-18: "reduce web app to 2cpus 4 gb ram" -- 7 days of telemetry: at most 0.1 CPU / 0.5 GiB
# used of 4 CPU / 8 GiB): every update SETS the Pro web app's own container (the name the install record gives, else
# ca-si-management) to 2 CPU / 4 GiB -- what setup gives a new install -- by one read-modify-write PATCH of its template
# (setup/_shared/SI-JobSizing.ps1, Invoke-SIWebAppSize): a smaller one is raised, one on the product's earlier 4 CPU / 8 GiB is
# lowered, any other larger size is the customer's and kept. A size the customer set (SI_Bootstrap_WebAppCpu /
# SI_Bootstrap_WebAppMemory: the Pro database's setting, then the config) wins, both ways. The sign-in front sidecar and the
# MCP server are not touched. No web app (Community): nothing to do. Waits for the new revision and reads the size back, so
# the web app roll after it is not refused as an operation in flight. Never fails the update.
function Invoke-SIUpdateWebAppSize {
    $lib = Join-Path $PSScriptRoot '_shared/SI-JobSizing.ps1'
    if (-not (Test-Path -LiteralPath $lib) -or -not $rest) { return }
    try {
        . $lib
        # CR5 step 1 (#655): the install record the updater resolved ($global:SI_InstallNames), then SI_UPDATER_WEB_APP, then
        # today's name (engine/_shared/SI-InstallNames.ps1); a release without that file: the variable, then today's name
        $namesLib = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'engine', '_shared', 'SI-InstallNames.ps1')
        if (Test-Path -LiteralPath $namesLib) { . $namesLib; $name = Get-SIInstallName -Role web }
        else { $name = "$([Environment]::GetEnvironmentVariable('SI_UPDATER_WEB_APP'))".Trim(); if (-not $name) { $name = 'ca-si-management' } }
        Step '8d. WEB APP SIZE (2 CPU / 4 GiB)'
        $webCpu = Get-SIUpdateSetting -Name 'SI_Bootstrap_WebAppCpu'; $webMem = Get-SIUpdateSetting -Name 'SI_Bootstrap_WebAppMemory'
        $r = Invoke-SIWebAppSize -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Name $name -Cpu $webCpu -Memory $webMem -WhatIf:(-not $Apply -or $DetectOnly)
        foreach ($l in @($r.Lines)) { if ($l -match 'NOT raised|NOT lowered|could not') { Warn $l } else { Info $l } }
    } catch { Warn ("web app size: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# THE PERMISSIONS AN EXISTING INSTALL HAS NOT GRANTED YET (setup/_shared/SI-PermissionNote.ps1; owner 2026-10-11: SecurityInsight
# may ask for more read-only permissions, "customers grant on their next permission setup run"). Every update compares what
# the collection identity holds with config/permissions.locked.json and says, per missing permission, ONE plain line (what
# it is for, read-only, what stays empty) and the two lines that grant them. READ ONLY: it grants nothing, changes nothing,
# never fails or holds the update, and says nothing when every permission is granted. A sign-in that may not read the
# directory: the collection engines' own check on their newest run (exact when that run checked this very list), else one
# line that it could not check -- never a guess.
function Invoke-SIUpdatePermissionNote {
    $lib = Join-Path $PSScriptRoot '_shared/SI-PermissionNote.ps1'
    if (-not (Test-Path -LiteralPath $lib) -or -not $rest) { return }
    try {
        . $lib
        $ws = "$([Environment]::GetEnvironmentVariable('SI_UPDATER_WORKSPACE_RESOURCE_ID'))".Trim()
        $n = Invoke-SIPermissionNote -Rest $rest -Jobs @($script:SISqlTierJobs) -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Globals $globals -WorkspaceResourceId $ws
        if (-not @($n.Lines).Count) { return }
        Step '10. PERMISSIONS (read only)'
        foreach ($l in @($n.Lines)) { Info $l }
    } catch { Info ("permissions: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# #685: THE JOBS A NEWER VERSION NEEDS (setup/_shared/SI-MissingJobs.ps1; rule: existing installs reach new-install state).
# caj-si-verification (the verification service and the daily data health check it runs) was created by no setup and no
# update until 2026-10-15. Every update creates such a job where it is missing -- from a Pro job of the install (its image,
# sign-in, settings and secrets), with the trigger Bootstrap gives a new install (in flow mode a step of the pipeline, no
# timer) -- and reads it back; a job that does not read back right is removed again. A job that exists is never touched.
# After the job floor and the queue scaling (it takes the donor's floored size and run limit), before the pipeline-schedule
# check (which then sees the new step). Never fails the update. -DetectOnly: the plan only.
function Invoke-SIUpdateMissingJobs {
    $lib = Join-Path $PSScriptRoot '_shared/SI-MissingJobs.ps1'
    if (-not (Test-Path -LiteralPath $lib) -or -not $rest) { return }
    try {
        . $lib
        $all = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName)
        if (-not @($all | Where-Object { [string]$_.name -like 'caj-si-*' }).Count) { return }
        Step '9a. MISSING JOBS'
        # #715: the ServiceNow connectors the Pro database holds (cfg.Connector: what the web app's Connectors / Get Started
        # pages write) -- a ServiceNow job is made only where the install uses ServiceNow. Not readable = the settings alone, said.
        $connectors = @()
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        if ($proSrv -and $proDb) {
            if ($proSrv -notmatch '\.') { $proSrv = $proSrv + '.database.windows.net' }
            try {
                $tok = ([string](Get-SIAzureToken -Resource 'https://database.windows.net/')).Trim()
                if (-not $tok) { throw 'no access token for the database' }
                $cn = New-Object System.Data.SqlClient.SqlConnection
                $cn.ConnectionString = "Server=tcp:$proSrv,1433;Database=$proDb;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
                $cn.AccessToken = $tok
                try {
                    $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandTimeout = 0
                    $cmd.CommandText = (Get-SIMissingJobConnectorSql)
                    $rd = $cmd.ExecuteReader()
                    try { while ($rd.Read()) { $connectors += [pscustomobject]@{ Kind = [string]$rd.GetValue(0); Direction = [string]$rd.GetValue(1) } } } finally { $rd.Dispose() }
                } finally { $cn.Dispose() }
            } catch { Info ("missing jobs: the connectors could not be read from the Pro database ({0}) -- a ServiceNow job is made only where a setting says ServiceNow is used; the next update reads them again." -f $_.Exception.Message) }
        }
        $conditions = Get-SIMissingJobConditions -Globals $globals -Connectors $connectors
        $mj = Invoke-SIMissingJobs -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Root $solRoot -Jobs $all -Globals $globals -WhatIf:(-not $Apply -or $DetectOnly) -Conditions $conditions
        foreach ($l in @($mj.Lines)) { if ($l -match 'NOT created|NOT moved|not checked') { Warn $l } else { Info $l } }
        # review B1 (2026-10-22): an existing job gets the secret only another kind of job carries -- the data sync sends the
        # Risk Analysis Detailed mail, so it needs the SMTP relay password as the mail jobs have it (a new install: Bootstrap)
        $jb = Invoke-SIJobSecretBorrow -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Jobs $all -WhatIf:(-not $Apply -or $DetectOnly)
        foreach ($l in @($jb.Lines)) { if ($l -match 'did NOT|not checked') { Warn $l } else { Info $l } }
        if (@($mj.Results | Where-Object { $_.Action -eq 'created' }).Count) {
            try { $v = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName); if ($v.Count) { $script:SISqlTierJobs = $v } } catch { }
        }
    } catch { Warn ("missing jobs: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# THE NIGHTLY SCHEDULE (setup/_shared/SI-NightlySchedule.ps1; owner 2026-10-15: "complete by 8am" / "11pm local time for region"),
# ONCE per install, in the time zone of the install's Azure region: (a) the updater job's timer -- on a shipped timer (the old
# '0 3 * * *', or the Danish-time '0 21,22 * * *' with its tag '23:00 Europe/Copenhagen' or none) -> the UTC hours that are 23:00
# in the region's zone (the updater ends the other tick itself), one read-modify-write PATCH of its trigger, read back, the zone
# recorded on the job (tags si-nightly-schedule + si-nightly-region); a timer the customer chose is kept. (b) Pro: a pipeline
# start on a shipped value (23:30 Europe/Copenhagen, or the old 22:00 where the Danish-time step never ran; cfg.Setting at any
# scope, and the stored pipeline cfg.JobFlow) becomes 23:30 in the region's zone, in one transaction with its change-log rows,
# recorded in cfg.InstallState 'NightlyScheduleRegion'. One plain line each. Never fails the update.
function Invoke-SIUpdateNightlySchedule {
    if (-not (Get-Command -Name Invoke-SINightlyUpdaterSchedule -ErrorAction SilentlyContinue)) { return }
    $wi = (-not $Apply -or $DetectOnly)
    $rz = if ($script:SINightlyRegion) { $script:SINightlyRegion } else { Get-SINightlyRegionZone '' }
    $regionSaid = $false
    try {
        if ($rest) {
            $name = [string](Get-SIUpdaterManagedJob -Globals $globals)
            if (-not $name.Trim()) { $name = [string][Environment]::GetEnvironmentVariable('CONTAINER_APP_JOB_NAME') }
            if (-not $name.Trim() -and @($script:SISqlTierJobs | Where-Object { [string]$_.name -eq 'caj-si-updater' }).Count) { $name = 'caj-si-updater' }
            if ($name.Trim()) {
                $u = Invoke-SINightlyUpdaterSchedule -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -JobName $name.Trim() -Region $rz.Region -WhatIf:$wi
                if (@($u.Lines).Count) { Step '9c. NIGHTLY SCHEDULE' }
                foreach ($l in @($u.Lines)) { if ($u.Action -eq 'failed') { Warn $l } else { Info $l } }
                if ($rz.Line -and @($u.Lines) -contains $rz.Line) { $regionSaid = $true }
                # no region was read: the job's own location decided the zone -- the pipeline follows it
                if (-not $rz.Known -and "$($u.Region)".Trim()) { $rz = Get-SINightlyRegionZone $u.Region }
                # 9l (owner 2026-10-21): the region step's 23:00 -> 18:30 in the same zone, once (tag si-nightly-1900)
                if (Get-Command -Name Get-SINightly1900UpdaterPlan -ErrorAction SilentlyContinue) {
                    $u9 = Invoke-SINightlyUpdaterSchedule -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -JobName $name.Trim() -Region $rz.Region -WhatIf:$wi -Step '1900'
                    if (@($u9.Lines).Count) { Step '9l. NIGHTLY 19:00 (the nightly update)' }
                    foreach ($l in @($u9.Lines)) { if ($u9.Action -eq 'failed') { Warn $l } elseif (-not ($regionSaid -and $l -eq $rz.Line)) { Info $l } }
                }
            }
        }
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        if (-not $proSrv -or -not $proDb) { return }
        if (-not "$($rz.Region)".Trim()) { Warn "nightly schedule: the install's Azure region could not be read -- the daily pipeline's start time is checked on the next update."; return }
        if ($proSrv -notmatch '\.') { $proSrv = $proSrv + '.database.windows.net' }
        # parameterised statements on the Pro database, signed in with this update's own token (a new connection per call)
        $sql = {
            param([string]$Query, $Params, [string]$Mode)
            $tok = ([string](Get-SIAzureToken -Resource 'https://database.windows.net/')).Trim()
            if (-not $tok) { throw 'no access token for the database' }
            $cn = New-Object System.Data.SqlClient.SqlConnection
            $cn.ConnectionString = "Server=tcp:$proSrv,1433;Database=$proDb;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
            $cn.AccessToken = $tok
            try {
                $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0
                if ($Params) { foreach ($k in @($Params.Keys)) { $pv = $Params[$k]; $null = $cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $pv) { [DBNull]::Value } else { $pv })) } }
                if ($Mode -eq 'nonquery') { return $cmd.ExecuteNonQuery() }
                $rd = $cmd.ExecuteReader()
                try { while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $rd.GetValue($i) }; [pscustomobject]$o } } finally { $rd.Dispose() }
            } finally { $cn.Dispose() }
        }   # dynamic scope: $proSrv, $proDb come from this function
        $p = Invoke-SINightlyPipelineStart -Sql $sql -Zone $rz.Zone -Region $rz.Region -WhatIf:$wi
        if (@($p.Lines).Count) { Step '9c. NIGHTLY SCHEDULE (the daily pipeline)' }
        if (@($p.Lines).Count -and $rz.Line -and -not $regionSaid) { Info $rz.Line }
        foreach ($l in @($p.Lines)) { if ($p.Action -eq 'failed') { Warn $l } else { Info $l } }
        # 9l (owner 2026-10-21): the region step's 23:30 -> 19:00 in the same zone, once (cfg.InstallState 'NightlySchedule1900')
        if (Get-Command -Name Invoke-SINightly1900PipelineStart -ErrorAction SilentlyContinue) {
            $p9 = Invoke-SINightly1900PipelineStart -Sql $sql -Zone $rz.Zone -Region $rz.Region -WhatIf:$wi
            if (@($p9.Lines).Count) { Step '9l. NIGHTLY 19:00 (the daily pipeline)' }
            foreach ($l in @($p9.Lines)) { if ($p9.Action -eq 'failed') { Warn $l } else { Info $l } }
        }
    } catch { Warn ("nightly schedule: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# #830 THE REPORT-ROW COPY (setup/_shared/SI-ReportCopyDefault.ps1): the copy of the Risk Analysis report rows to Log Analytics
# reaches the new-install state (off) once -- what setup wrote is set off, what a person chose is kept. One plain line. Never
# fails the update.
function Invoke-SIUpdateReportCopy {
    if (-not (Get-Command -Name Invoke-SIReportCopyDefault -ErrorAction SilentlyContinue)) { return }
    try {
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        if (-not $proSrv -or -not $proDb) { return }
        if ($proSrv -notmatch '\.') { $proSrv = $proSrv + '.database.windows.net' }
        # parameterised statements on the Pro database, signed in with this update's own token (a new connection per call)
        $sql = {
            param([string]$Query, $Params, [string]$Mode)
            $tok = ([string](Get-SIAzureToken -Resource 'https://database.windows.net/')).Trim()
            if (-not $tok) { throw 'no access token for the database' }
            $cn = New-Object System.Data.SqlClient.SqlConnection
            $cn.ConnectionString = "Server=tcp:$proSrv,1433;Database=$proDb;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
            $cn.AccessToken = $tok
            try {
                $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0
                if ($Params) { foreach ($k in @($Params.Keys)) { $pv = $Params[$k]; $null = $cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $pv) { [DBNull]::Value } else { $pv })) } }
                if ($Mode -eq 'nonquery') { return $cmd.ExecuteNonQuery() }
                $rd = $cmd.ExecuteReader()
                try { while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $rd.GetValue($i) }; [pscustomobject]$o } } finally { $rd.Dispose() }
            } finally { $cn.Dispose() }
        }   # dynamic scope: $proSrv, $proDb come from this function
        $r = Invoke-SIReportCopyDefault -Sql $sql -WhatIf:(-not $Apply -or $DetectOnly)
        if (@($r.Lines).Count) { Step '9e. REPORT ROW COPY' }
        foreach ($l in @($r.Lines)) { if ($r.Action -eq 'failed') { Warn $l } else { Info $l } }
    } catch { Warn ("report rows: the copy to Log Analytics was not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}

# #842 THE SUMMARY VIEWS WRITTEN AGAIN AFTER AN UPDATE THAT CHANGED THEM (setup/_shared/SI-SummaryGroupsRebuild.ps1): collections
# whose Summary views were written from another definition than this release ships get ONE data sync queued in the pipeline's
# queue (it waits until no run is going), instead of waiting for the nightly run. Pro only. One plain line. Never fails the
# update; idempotent (nothing to write again = nothing queued, nothing said).
function Invoke-SIUpdateSummaryRebuild {
    $lib = Join-Path $PSScriptRoot '_shared/SI-SummaryGroupsRebuild.ps1'
    $defLib = Join-Path $solRoot 'engine/_shared/SI-SummaryGroupings.ps1'
    if (-not (Test-Path -LiteralPath $lib) -or -not (Test-Path -LiteralPath $defLib)) { return }
    try {
        . $lib
        if (-not (Get-Command -Name Get-SISummaryGroupingDefinition -ErrorAction SilentlyContinue)) { . $defLib }
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        if (-not $proSrv -or -not $proDb) { return }
        # the data lives in the Pro database unless the install keeps it in another one (as the data sync reads it)
        $dataSrv = & $gv 'SI_Pro_DataSqlServer'; $dataDb = & $gv 'SI_Pro_DataSqlDatabase'
        if (-not $dataSrv -or -not $dataDb) { $dataSrv = $proSrv; $dataDb = $proDb }
        if ($proSrv -notmatch '\.') { $proSrv = $proSrv + '.database.windows.net' }
        if ($dataSrv -notmatch '\.') { $dataSrv = $dataSrv + '.database.windows.net' }
        $jobs = @($script:SISqlTierJobs)
        if ($rest) { try { $v = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName); if ($v.Count) { $jobs = $v } } catch { } }
        $hasDataSync = [bool]@($jobs | Where-Object { [string]$_.name -eq 'caj-si-asset-datasync' }).Count
        # parameterised statements, signed in with this update's own token (a new connection per call)
        $open = {
            param([string]$Server, [string]$Database, [string]$Query, $Params)
            $tok = ([string](Get-SIAzureToken -Resource 'https://database.windows.net/')).Trim()
            if (-not $tok) { throw 'no access token for the database' }
            $cn = New-Object System.Data.SqlClient.SqlConnection
            $cn.ConnectionString = "Server=tcp:$Server,1433;Database=$Database;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
            $cn.AccessToken = $tok
            try {
                $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0
                if ($Params) { foreach ($k in @($Params.Keys)) { $pv = $Params[$k]; $null = $cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $pv) { [DBNull]::Value } else { $pv })) } }
                $rd = $cmd.ExecuteReader()
                try { while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $rd.GetValue($i) }; [pscustomobject]$o } } finally { $rd.Dispose() }
            } finally { $cn.Dispose() }
        }
        $sql = { param([string]$Query, $Params, [string]$Mode) & $open $proSrv $proDb $Query $Params }        # dynamic scope: this function's values
        $dataSql = { param([string]$Query, $Params, [string]$Mode) & $open $dataSrv $dataDb $Query $Params }
        $r = Invoke-SISummaryGroupsRebuild -DataSql $dataSql -Sql $sql -Hash ([string](Get-SISummaryGroupingDefinition).Hash) -DataSyncInstalled $hasDataSync -WhatIf:(-not $Apply -or $DetectOnly)
        if (@($r.Lines).Count) { Step '9f. SUMMARY VIEWS' }
        foreach ($l in @($r.Lines)) { if ($r.Action -eq 'failed') { Warn $l } else { Info $l } }
        $global:SI_UpdateSummaryRebuild = $r
    } catch { Warn ("summary views: whether they must be written again was not checked ({0}) -- the next data sync writes them; the next update checks again." -f $_.Exception.Message) }
}

# THE SHOWN RUN'S COPIES OF THE MERGED ASSETS CAUGHT UP (engine/_shared/data-sql/SI-DataPublishedRun.ps1, Invoke-SIPublishedCopyCatchUp;
# 2026-10-21: a publish that moved the pointer without refreshing the copies left the asset pages on a copy from before the CI
# lifecycle). A published run whose copies (sidata.CiPub, AssetPub, ...) are older than it is refreshed now by the database's
# own procedure (sidata.PublishedCopyCatchUp -> PublishedCopyRefreshAll: only what changed), in the data database -- existing
# installs correct themselves with no hand SQL. Pro only. One plain line only when they were stale. Never fails the update;
# idempotent (copies as new as the publish = nothing done, nothing said). No time limit on the statement: the refresh is as
# long as the data that changed.
function Invoke-SIUpdatePublishedCopy {
    $lib = Join-Path $solRoot 'engine/_shared/data-sql/SI-DataPublishedRun.ps1'
    if (-not (Test-Path -LiteralPath $lib)) { return }
    try {
        if (-not (Get-Command -Name Invoke-SIPublishedCopyCatchUp -ErrorAction SilentlyContinue)) { . $lib }
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        if (-not $proSrv -or -not $proDb) { return }
        # the data lives in the Pro database unless the install keeps it in another one (as the data sync and the web app read it)
        $dataSrv = & $gv 'SI_Pro_DataSqlServer'; $dataDb = & $gv 'SI_Pro_DataSqlDatabase'
        if (-not $dataSrv -or -not $dataDb) { $dataSrv = $proSrv; $dataDb = $proDb }
        if ($dataSrv -notmatch '\.') { $dataSrv = $dataSrv + '.database.windows.net' }
        # parameterised statements on the data database, signed in with this update's own token (a new connection per call)
        $dataSql = {
            param([string]$Query, $Params, [string]$Mode)
            $tok = ([string](Get-SIAzureToken -Resource 'https://database.windows.net/')).Trim()
            if (-not $tok) { throw 'no access token for the database' }
            $cn = New-Object System.Data.SqlClient.SqlConnection
            $cn.ConnectionString = "Server=tcp:$dataSrv,1433;Database=$dataDb;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
            $cn.AccessToken = $tok
            try {
                $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0
                if ($Params) { foreach ($k in @($Params.Keys)) { $pv = $Params[$k]; $null = $cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $pv) { [DBNull]::Value } else { $pv })) } }
                $rd = $cmd.ExecuteReader()
                try { while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $rd.GetValue($i) }; [pscustomobject]$o } } finally { $rd.Dispose() }
            } finally { $cn.Dispose() }
        }   # dynamic scope: $dataSrv, $dataDb come from this function
        $r = Invoke-SIPublishedCopyCatchUp -Invoke $dataSql -WhatIf:(-not $Apply -or $DetectOnly)
        if (@($r.Lines).Count) { Step '9j. PUBLISHED COPIES' }
        foreach ($l in @($r.Lines)) { if ($r.Action -in @('failed', 'held')) { Warn $l } else { Info $l } }
        $global:SI_UpdatePublishedCopy = $r
    } catch { Warn ("published copies: not checked ({0}) -- the update goes on; the pipeline runner checks them on its next wake-up." -f $_.Exception.Message) }
}

# #855 THE KEY FIGURES WORKED OUT AGAIN RIGHT AFTER AN UPDATE THAT CHANGED THEM (owner 2026-10-21: "can we then auto-fix the data
# ... without running the full pipe" / "the trust of devices, executive numbers etc are important"): the newest complete
# collections whose figures lack this release's marker (Get-SIDataUnfiguredSql) are figured again HERE, with the engine's own
# statement (engine/pro-data/_shared/SI-DataKeyFigures.ps1) and the install's own protection-score settings -- no pipeline
# run, no data sync. Pro only. Bounded (the newest 4, a time budget); what is left the next data sync figures. One plain line.
# Never fails the update; idempotent (every collection carries the marker = nothing to do, nothing said).
function Invoke-SIUpdateKeyFigures {
    $lib = Join-Path $solRoot 'engine/pro-data/_shared/SI-DataKeyFigures.ps1'
    $psLib = Join-Path $solRoot 'engine/_shared/SI-ProtectionScore.ps1'
    if (-not (Test-Path -LiteralPath $lib) -or -not (Test-Path -LiteralPath $psLib)) { return }
    try {
        . $psLib; . $lib
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        if (-not $proSrv -or -not $proDb) { return }
        $dataSrv = & $gv 'SI_Pro_DataSqlServer'; $dataDb = & $gv 'SI_Pro_DataSqlDatabase'
        if (-not $dataSrv -or -not $dataDb) { $dataSrv = $proSrv; $dataDb = $proDb }
        if ($proSrv -notmatch '\.') { $proSrv = $proSrv + '.database.windows.net' }
        if ($dataSrv -notmatch '\.') { $dataSrv = $dataSrv + '.database.windows.net' }
        # parameterised statements, signed in with this update's own token (a new connection per call); 'scalar' = the first
        # column of the first row, as the data sync's seam answers it
        $open = {
            param([string]$Server, [string]$Database, [string]$Query, $Params, [string]$Mode)
            $tok = ([string](Get-SIAzureToken -Resource 'https://database.windows.net/')).Trim()
            if (-not $tok) { throw 'no access token for the database' }
            $cn = New-Object System.Data.SqlClient.SqlConnection
            $cn.ConnectionString = "Server=tcp:$Server,1433;Database=$Database;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
            $cn.AccessToken = $tok
            try {
                $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0
                if ($Params) { foreach ($k in @($Params.Keys)) { $pv = $Params[$k]; $null = $cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $pv) { [DBNull]::Value } else { $pv })) } }
                if ($Mode -eq 'scalar') { $v = $cmd.ExecuteScalar(); if ($v -is [DBNull]) { return $null }; return $v }
                $rd = $cmd.ExecuteReader()
                try { while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; [pscustomobject]$o } } finally { $rd.Dispose() }
            } finally { $cn.Dispose() }
        }
        $dataSql = {
            param([string]$Query, $Params, [string]$Mode, [scriptblock]$OnRow)
            if ($Mode -ne 'session') { return (& $open $dataSrv $dataDb $Query $Params $Mode) }
            # NO TIME LIMIT (owner 2026-10-22: "i accept no limits"): the key figures of a large collection run as steps on ONE
            # connection (plain batches, so the #temp tables live between them), each step with no command time limit and a
            # progress line (Invoke-SIDataKeyFiguresStepped)
            $tok = ([string](Get-SIAzureToken -Resource 'https://database.windows.net/')).Trim()
            if (-not $tok) { throw 'no access token for the database' }
            $scn = New-Object System.Data.SqlClient.SqlConnection
            $scn.ConnectionString = "Server=tcp:$dataSrv,1433;Database=$dataDb;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
            $scn.AccessToken = $tok
            try {
                $scn.Open()
                $run = {
                    param([string]$StepSql, [string]$StepMode)
                    $sc = $scn.CreateCommand(); $sc.CommandText = $StepSql; $sc.CommandTimeout = 0
                    if ($StepMode -eq 'scalar') { $v = $sc.ExecuteScalar(); if ($v -is [DBNull]) { return $null }; return $v }
                    if ($StepMode -eq 'reader') {
                        $rd = $sc.ExecuteReader()
                        try { while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; [pscustomobject]$o } } finally { $rd.Dispose() }
                        return
                    }
                    [void]$sc.ExecuteNonQuery()
                }.GetNewClosure()
                & $OnRow $run
            } finally { $scn.Dispose() }
        }
        $dataSql | Add-Member -NotePropertyName SISqlSession -NotePropertyValue $true
        # the install's own protection-score settings (the Settings page's value, else the config's): a list is kept as one
        # comma-separated value, as the score's reader takes it
        $names = @('SI_ProtectionScore_TierWeights', 'SI_ProtectionScore_Severities', 'SI_ProtectionScore_GraceDays_Device', 'SI_ProtectionScore_GraceDays_Identity',
                   'SI_ProtectionScore_GraceDays_CloudResource', 'SI_ProtectionScore_GraceDays_PublicIp', 'SI_PatchCycle_CatchUpDays',
                   # #859: the key figures' windows (Get-SIKeyFigureWindowSettings) -- figured again with the install's own values
                   'SI_KeyFigures_RecentDays', 'SI_KeyFigures_MeanTimeToFixDays', 'SI_KeyFigures_StaleAdminDays', 'SI_KeyFigures_CveAgeBands',
                   # #860: the grace of the findings that are not patches (default 0) -- the refigure of existing installs uses them
                   'SI_ProtectionScore_OtherGraceDays_Device', 'SI_ProtectionScore_OtherGraceDays_Identity', 'SI_ProtectionScore_OtherGraceDays_CloudResource', 'SI_ProtectionScore_OtherGraceDays_PublicIp')
        $settings = @{}
        foreach ($n in $names) { $v = & $gv $n; if ($v) { $settings[$n] = $v } }
        try {
            $q = "IF OBJECT_ID('cfg.Setting') IS NOT NULL SELECT Name, ValueJson FROM cfg.Setting WHERE Scope = N'solution' AND Name IN (" + ((0..($names.Count - 1) | ForEach-Object { '@n' + $_ }) -join ', ') + ');'
            $p = @{}; for ($i = 0; $i -lt $names.Count; $i++) { $p['n' + $i] = $names[$i] }
            foreach ($r in @(& $open $proSrv $proDb $q $p 'reader')) {
                $raw = [string]$r.ValueJson; if (-not $raw.Trim()) { continue }
                $v = $raw; try { $v = ConvertFrom-Json -InputObject $raw } catch { $v = $raw }
                if ($null -eq $v) { continue }
                $t = if ($v -is [System.Array]) { (@($v) | ForEach-Object { "$_".Trim() }) -join ',' } elseif ($v -is [double] -or $v -is [decimal]) { $v.ToString([Globalization.CultureInfo]::InvariantCulture) } else { "$v".Trim() }
                if ($t) { $settings[[string]$r.Name] = $t }
            }
        } catch { Info ("key figures: the Settings page's protection-score values could not be read ({0}) -- the config's values count" -f $_.Exception.Message) }
        if ($settings.ContainsKey('SI_PatchCycle_CatchUpDays')) { $global:SI_PatchCycle_CatchUpDays = $settings['SI_PatchCycle_CatchUpDays'] }
        if (-not $Apply -or $DetectOnly) {
            $n = @(& $dataSql (Get-SIDataUnfiguredSql) @{} 'reader').Count
            if ($n) { Step '9i. KEY FIGURES'; Info ("key figures: {0} collection(s) would be figured again with this release's figures" -f $n) }
            return
        }
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataKeyFigures -Invoke $dataSql -Settings $settings -BudgetSeconds 900 -Log { param($l, $m) $lines.Add(('{0}|{1}' -f $l, $m)) }
        if ([string]$r.Status -eq 'ok' -and [int]$r.Collections -eq 0) { return }
        Step '9i. KEY FIGURES'
        foreach ($x in $lines) { $lv, $m = $x -split '\|', 2; if ($lv -eq 'WARN') { Warn $m } else { Info $m } }
        $global:SI_UpdateKeyFigures = $r
    } catch { Warn ("key figures: they were not worked out again ({0}) -- the update goes on; the next data sync works them out." -f $_.Exception.Message) }
}

# the update's parameterised statements on the Pro database, signed in with its own token (a new connection per call) --
# ONE definition for the steps that hand a -Sql seam on (9k, 9m, 9n, 9o); $proSrv / $proDb are the calling step's (dynamic scope)
$script:SIUpdateProSql = {
    param([string]$Query, $Params, [string]$Mode)
    $tok = ([string](Get-SIAzureToken -Resource 'https://database.windows.net/')).Trim()
    if (-not $tok) { throw 'no access token for the database' }
    $cn = New-Object System.Data.SqlClient.SqlConnection
    $cn.ConnectionString = "Server=tcp:$proSrv,1433;Database=$proDb;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
    $cn.AccessToken = $tok
    try {
        $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0
        if ($Params) { foreach ($k in @($Params.Keys)) { $pv = $Params[$k]; $null = $cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $pv) { [DBNull]::Value } else { $pv })) } }
        if ($Mode -eq 'nonquery') { return $cmd.ExecuteNonQuery() }
        $rd = $cmd.ExecuteReader()
        try { while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; [pscustomobject]$o } } finally { $rd.Dispose() }
    } finally { $cn.Dispose() }
}

# #865 SI'S OWN SQL CLOSE-LOOP TARGET ALWAYS ON (setup/_shared/SI-OwnSqlConnector.ps1; owner 2026-10-21: "for the sql it should
# be on always"): the connector of kind sql + direction vulnerability (`vulnerability-sql`, SecurityInsight's own record of every
# vulnerability's lifecycle -- Changes & trends) that is in test mode or cannot create / close is set to apply, create and
# close, with its cfg.ChangeLog row, read back. ServiceNow / REST connectors and the SQL CMDB hand-off are never touched.
# Pro only (the Pro database). On every update (nothing to do: nothing said). Never fails the update. -DetectOnly: the plan.
function Invoke-SIUpdateOwnSqlConnector {
    if (-not (Get-Command -Name Invoke-SIOwnSqlConnectorOn -ErrorAction SilentlyContinue)) { return }
    try {
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        if (-not $proSrv -or -not $proDb) { return }
        if ($proSrv -notmatch '\.') { $proSrv = $proSrv + '.database.windows.net' }
        # parameterised statements on the Pro database, signed in with this update's own token (a new connection per call)
        $sql = $script:SIUpdateProSql   # dynamic scope: $proSrv, $proDb come from this function
        $r = Invoke-SIOwnSqlConnectorOn -Sql $sql -WhatIf:(-not $Apply -or $DetectOnly)
        if (@($r.Lines).Count) { Step '9k. OWN SQL TARGET' }
        foreach ($l in @($r.Lines)) { if ($r.Action -eq 'failed') { Warn $l } else { Info $l } }
        $global:SI_UpdateOwnSqlConnector = $r
    } catch { Warn ("connectors: SecurityInsight's own SQL vulnerability target was not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}

# #903 ONE SERVICENOW CONNECTOR FEEDS BOTH DATA-OUT OUTPUTS (setup/_shared/SI-SnowDataOutConnector.ps1; owner 2026-10-26: "if
# active they should be part of the data out for both cmdb and vulnerability"): the connector the ServiceNow data out used
# before becomes the data-out connector (or one is made from the secret names in use) -- keeping exactly what is sent, said,
# with its cfg.ChangeLog rows, read back. Pro only. Never fails the update. -DetectOnly: the plan.
function Invoke-SIUpdateSnowDataOut {
    if (-not (Get-Command -Name Invoke-SISnowDataOutConnectorOn -ErrorAction SilentlyContinue)) { return }
    try {
        # the engine's own reading of a connector row (which connector data out used before), when this tree carries it
        $connLib = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine/asset-cmdb/_shared/SI-Connector.ps1'
        if (-not (Get-Command -Name ConvertFrom-SIConnectorRow -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $connLib)) { try { . $connLib } catch { } }
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        if (-not $proSrv -or -not $proDb) { return }
        if ($proSrv -notmatch '\.') { $proSrv = $proSrv + '.database.windows.net' }
        $sql = $script:SIUpdateProSql   # dynamic scope: $proSrv, $proDb come from this function
        $r = Invoke-SISnowDataOutConnectorOn -Sql $sql -WhatIf:(-not $Apply -or $DetectOnly)
        if (@($r.Lines).Count -or @($r.Warnings).Count) { Step '9m. SERVICENOW DATA OUT' }
        foreach ($l in @($r.Lines)) { if ($r.Action -eq 'failed') { Warn $l } else { Info $l } }
        foreach ($w in @($r.Warnings)) { Warn $w }
        $global:SI_UpdateSnowDataOut = $r
    } catch { Warn ("connectors: the ServiceNow data-out connector was not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}

# #912 THE SERVICENOW STAGING STATUS TABLE (setup/_shared/SI-SnowStagingStatus.ps1): an install that already sends to ServiceNow
# gets SI_DataOut_ServiceNowStagingStatusTable EMPTY, once (its rows go as before, with a warning) -- the table is created in the
# customer's ServiceNow first. Pro only. Never fails the update. -DetectOnly: the plan.
function Invoke-SIUpdateSnowStagingStatus {
    if (-not (Get-Command -Name Invoke-SISnowStagingStatusUpdate -ErrorAction SilentlyContinue)) { return }
    try {
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        if (-not $proSrv -or -not $proDb) { return }
        if ($proSrv -notmatch '\.') { $proSrv = $proSrv + '.database.windows.net' }
        $sql = $script:SIUpdateProSql   # dynamic scope: $proSrv, $proDb come from this function
        $r = Invoke-SISnowStagingStatusUpdate -Sql $sql -WhatIf:(-not $Apply -or $DetectOnly)
        if (@($r.Lines).Count -or @($r.Warnings).Count) { Step '9n. SERVICENOW STAGING STATUS' }
        foreach ($l in @($r.Lines)) { if ($r.Action -eq 'failed') { Warn $l } else { Info $l } }
        foreach ($w in @($r.Warnings)) { Warn $w }
        $global:SI_UpdateSnowStagingStatus = $r
    } catch { Warn ("ServiceNow: the staging status setting was not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}

# #914 ONE ROUTE INTO SERVICENOW (setup/_shared/SI-SnowOneRoute.ps1): the older push's settings are named ONCE in this log and
# left in place (never deleted). Pro only. Never fails the update. -DetectOnly: the plan.
function Invoke-SIUpdateSnowOneRoute {
    if (-not (Get-Command -Name Invoke-SISnowOneRouteUpdate -ErrorAction SilentlyContinue)) { return }
    try {
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        if (-not $proSrv -or -not $proDb) { return }
        if ($proSrv -notmatch '\.') { $proSrv = $proSrv + '.database.windows.net' }
        $sql = $script:SIUpdateProSql   # dynamic scope: $proSrv, $proDb come from this function
        $r = Invoke-SISnowOneRouteUpdate -Sql $sql -WhatIf:(-not $Apply -or $DetectOnly)
        if (@($r.Lines).Count -or @($r.Warnings).Count) { Step '9o. SERVICENOW ONE ROUTE' }
        foreach ($l in @($r.Lines)) { Info $l }
        foreach ($w in @($r.Warnings)) { Warn $w }
        $global:SI_UpdateSnowOneRoute = $r
    } catch { Warn ("ServiceNow: the older push's settings were not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}

# THE PIPELINE A NEW INSTALL GETS (#754, #748; setup/_shared/SI-PipelineLayout.ps1): the stored pipeline (cfg.JobFlow) gets
# the current layout -- Risk Analysis Summary and Detailed side by side -- where it is still on the default layout of its own
# level, and the verification service (the daily data health check) where its job is installed and the pipeline lacks it.
# One parameterised UPDATE only while nobody saved the pipeline meanwhile, read back, idempotent. Pro only (the database).
# Never fails the update.
function Invoke-SIUpdatePipelineLayout {
    $lib = Join-Path $PSScriptRoot '_shared/SI-PipelineLayout.ps1'
    if (-not (Test-Path -LiteralPath $lib)) { return }
    try {
        . $lib
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        if (-not $proSrv -or -not $proDb) { return }
        if ($proSrv -notmatch '\.') { $proSrv = $proSrv + '.database.windows.net' }
        # the install's jobs (after the missing jobs were made): the required step is added only where its job exists
        $jobs = @($script:SISqlTierJobs)
        if ($rest) { try { $v = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName); if ($v.Count) { $jobs = $v } } catch { } }
        $installed = @($jobs | ForEach-Object { [string]$_.name } | Where-Object { $_ -like 'caj-si-*' })
        if (-not $installed.Count) { return }
        # parameterised statements on the Pro database, signed in with this update's own token (a new connection per call)
        $sql = {
            param([string]$Query, $Params, [string]$Mode)
            $tok = ([string](Get-SIAzureToken -Resource 'https://database.windows.net/')).Trim()
            if (-not $tok) { throw 'no access token for the database' }
            $cn = New-Object System.Data.SqlClient.SqlConnection
            $cn.ConnectionString = "Server=tcp:$proSrv,1433;Database=$proDb;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
            $cn.AccessToken = $tok
            try {
                $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0
                if ($Params) { foreach ($k in @($Params.Keys)) { $pv = $Params[$k]; $null = $cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $pv) { [DBNull]::Value } else { $pv })) } }
                if ($Mode -eq 'nonquery') { return $cmd.ExecuteNonQuery() }
                $rd = $cmd.ExecuteReader()
                try { while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $rd.GetValue($i) }; [pscustomobject]$o } } finally { $rd.Dispose() }
            } finally { $cn.Dispose() }
        }   # dynamic scope: $proSrv, $proDb come from this function
        $r = Invoke-SIPipelineLayout -Sql $sql -Installed $installed -WhatIf:(-not $Apply -or $DetectOnly)
        if (@($r.Lines).Count) { Step '9d. PIPELINE LAYOUT' }
        foreach ($l in @($r.Lines)) { if ($r.Action -eq 'failed') { Warn $l } else { Info $l } }
        $global:SI_UpdatePipelineLayout = $r
        # #636: the scheduled management summary reports of the Summary report's data show the Detailed report's once the Summary step is off
        $m = Invoke-SIMgmtReportsDetailed -Sql $sql -WhatIf:(-not $Apply -or $DetectOnly)
        if (@($m.Lines).Count -and -not @($r.Lines).Count) { Step '9d. PIPELINE LAYOUT' }
        foreach ($l in @($m.Lines)) { if ($m.Action -eq 'failed') { Warn $l } else { Info $l } }
    } catch { Warn ("pipeline layout: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# THE NAMES PEOPLE READ (setup/_shared/SI-DisplayNames.ps1; framework 12.11c item 5, #655; owner: "if a resource can be renamed,
# we do that. if not, we keep for now, display names are updated"). An existing install's directory objects get the names a new
# install gets: the engine's application "SecurityInsight" -> "SecurityInsight Engine", the web app's sign-in application
# "SecurityInsight Management" -> "SecurityInsight", the SQL admin group "grp-si-sql-admins" shown as "SecurityInsight SQL
# admins" -- only from SecurityInsight's earlier default, each found by its id, read back, put back on failure, recorded (never
# twice). Azure resources keep their names. SI_Update_RenameDisplayNames is ON by default (owner 2026-10-18: "everything that we
# can rename, must follow agreed naming. consistent" -- every existing install reaches the names a new install gets): the Pro
# database's value (the Settings page) first, then the config, then the job's variable; $false = one line per rename it WOULD
# make, nothing changed. It renames only where the record of earlier renames can be kept and read (the Pro database): without
# it, the plan only. Without the rights (the update's identity usually may not change an application or a role-assignable
# group) it says so in one plain line and names setup\Set-SIDisplayNames.ps1 for an administrator -- no right is ever granted
# here. Never fails the update.
function Invoke-SIUpdateDisplayNames {
    $lib = Join-Path $PSScriptRoot '_shared/SI-DisplayNames.ps1'
    if (-not (Test-Path -LiteralPath $lib) -or -not $rest) { return }
    try {
        . $lib
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        $rg = $target.ResourceGroupName
        # the web app's sign-in application: the client id its web app signs in with (the install record's name, then today's, then the new)
        $webAppId = ''
        $namesLib = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'engine', '_shared', 'SI-InstallNames.ps1')
        $webNames = if (Test-Path -LiteralPath $namesLib) { . $namesLib; @(Get-SIInstallNameCandidates -Role web) } else { @('ca-si-management') }
        foreach ($wn in @(@($webNames) + @('ca-si-web') | Select-Object -Unique)) {
            $app = $null
            try { $app = Invoke-SIRestJson -Rest $rest -Uri (Get-SIArmUri -Path ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/containerApps/{2}' -f $sub, $rg, $wn) -ApiVersion '2025-07-01') -AllowNotFound -What 'reading the web app' } catch { $app = $null }
            if (-not $app) { continue }
            foreach ($c in @($app.properties.template.containers)) { foreach ($e in @($c.env)) { if ($e -and [string]$e.name -eq 'AzureAd__ClientId' -and [string]$e.value -match '^[0-9a-fA-F-]{36}$') { $webAppId = [string]$e.value } } }
            if ($webAppId) { break }
        }
        $engineAppId = & $envOr 'SI_SPN_AppId'; if (-not $engineAppId) { $engineAppId = & $gv 'SI_SPN_AppId' }
        if ($engineAppId -notmatch '^[0-9a-fA-F-]{36}$') { $engineAppId = '' }
        # the SQL admin group = the Pro SQL server's Entra admin (its sid)
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        $adminSid = ''
        if ($proSrv) {
            try {
                $srv = Invoke-SIRestJson -Rest $rest -Uri (Get-SIArmUri -Path ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Sql/servers/{2}' -f $sub, $rg, $proSrv.Split('.')[0]) -ApiVersion '2021-11-01') -AllowNotFound -What 'reading the database server'
                if ($srv -and $srv.properties -and $srv.properties.PSObject.Properties['administrators'] -and $srv.properties.administrators) { $adminSid = [string]$srv.properties.administrators.sid }
            } catch { }
        }
        if (-not $webAppId -and -not $engineAppId -and -not $adminSid) { return }
        $graph = {
            param([string]$Method, [string]$Uri, $Body)
            Invoke-SIRestJson -Rest $rest -Method $Method -Uri $Uri -Body $Body -Resource 'https://graph.microsoft.com/' -Headers @{ 'Content-Type' = 'application/json' }
        }
        # the record of earlier renames (never twice): cfg.InstallState 'DisplayNames' in the Pro database
        if ($proSrv -and $proSrv -notmatch '\.') { $proSrv = $proSrv + '.database.windows.net' }
        $sql = {
            param([string]$Query, $Params, [string]$Mode)
            $tok = ([string](Get-SIAzureToken -Resource 'https://database.windows.net/')).Trim()
            if (-not $tok) { throw 'no access token for the database' }
            $cn = New-Object System.Data.SqlClient.SqlConnection
            $cn.ConnectionString = "Server=tcp:$proSrv,1433;Database=$proDb;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
            $cn.AccessToken = $tok
            try {
                $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0
                if ($Params) { foreach ($k in @($Params.Keys)) { $null = $cmd.Parameters.AddWithValue('@' + $k, [string]$Params[$k]) } }
                if ($Mode -eq 'nonquery') { return $cmd.ExecuteNonQuery() }
                $cmd.ExecuteScalar()
            } finally { $cn.Dispose() }
        }   # dynamic scope: $proSrv, $proDb come from this function
        # the switch: the Pro database's value (the web app's Settings page) first, then the config, then the job's variable --
        # not set anywhere = ON (the default)
        $switchValues = @{}
        if ($globals.ContainsKey('SI_Update_RenameDisplayNames')) { $switchValues['SI_Update_RenameDisplayNames'] = $globals['SI_Update_RenameDisplayNames'] }
        if ($proSrv -and $proDb) { try { $sv = [string](& $sql (Get-SIDisplayNameSettingSql) $null 'scalar'); if ("$sv".Trim()) { $switchValues['SI_Update_RenameDisplayNames'] = $sv } } catch { } }
        $on = Test-SIDisplayNameRenameOn -Values $switchValues
        $wi = (-not $Apply -or $DetectOnly -or -not $on)
        $record = @{}; $recordRead = $false
        if ($on -and $proSrv -and $proDb) { try { $record = ConvertFrom-SIDisplayNamesRecord -Value ([string](& $sql (Get-SIDisplayNamesRecordSql -Read) $null 'scalar')); $recordRead = $true } catch { $record = @{} } }
        $plan = @(Get-SIDisplayNamePlan -Graph $graph -WebAppId $webAppId -EngineAppId $engineAppId -SqlAdminSid $adminSid -Done $record)
        # off: only what it WOULD rename (and what is held); a read this identity may not make is said only when the switch is on
        $shown = @('rename', 'held'); if ($on) { $shown += 'unchecked' }
        $todo = @($plan | Where-Object { $shown -contains $_.Action })
        if (-not $todo.Count) { return }
        Step '12. DISPLAY NAMES'
        if (-not $on) { Info 'SI_Update_RenameDisplayNames is off: nothing is renamed; this is what the update would do.' }
        # an install whose record could not be read is never renamed by the update (the record keeps it from renaming twice)
        if (-not $wi -and $proSrv -and $proDb -and -not $recordRead) { $wi = $true; Info 'the record of earlier renames could not be read from the Pro database -- nothing is renamed in this run.' }
        # no Pro database = no record: the update could rename an object twice, so it only says what it would rename
        if (-not $wi -and -not ($proSrv -and $proDb)) { $wi = $true; Info 'this install has no Pro database to record renames in -- nothing is renamed by the update; an administrator renames with setup\Set-SIDisplayNames.ps1 -Apply.' }
        $r = Invoke-SIDisplayNameRenames -Graph $graph -Plan $plan -Apply:(-not $wi)
        foreach ($it in @($r.Items | Where-Object { $_.Action -ne 'rename' -and $shown -contains $_.Action })) { Info $it.Line }
        # a missing right is the customer's action (one plain line), not a warning of the update
        foreach ($it in @($r.Items | Where-Object { $_.Action -eq 'rename' })) { if ($it.State -in 'failed', 'put-back-failed') { Warn $it.Line } else { Info $it.Line } }
        if ($r.Renamed -gt 0 -and $proSrv -and $proDb) {
            try { $null = & $sql (Get-SIDisplayNamesRecordSql) @{ Value = (Merge-SIDisplayNamesRecord -Current $record -Done $r.Done); By = 'update' } 'nonquery' }
            catch { Warn ("display names: renamed, but the record could not be written ({0}) -- the next update reads the new names and leaves them." -f $_.Exception.Message) }
        }
    } catch { Warn ("display names: not checked ({0}) -- the update goes on; the next update tries again." -f $_.Exception.Message) }
}
# #852 THE SIGN-IN FRONT'S STORE (pro-management/deploy/SI-SigninFrontStore.ps1; step 9g in the help above): the key, the
# identity's right on it, its database user, its schema and CREATE TABLE -- each only when missing, read back; the front's
# settings handed to this run's front roll only when everything reads back. Never fails the update.
function Invoke-SIUpdateSigninStore {
    $global:SI_SigninFrontStoreEnv = $null
    $planLib = [IO.Path]::Combine($solRoot, 'pro-management', 'deploy', 'SI-SigninFrontPlan.ps1')
    $storeLib = [IO.Path]::Combine($solRoot, 'pro-management', 'deploy', 'SI-SigninFrontStore.ps1')
    if (-not $rest -or -not (Test-Path -LiteralPath $planLib) -or -not (Test-Path -LiteralPath $storeLib)) { return $null }
    try {
        . $planLib
        if (-not (Get-Command -Name Invoke-SISigninFrontStore -ErrorAction SilentlyContinue)) { . $storeLib }
        $envOr = { param($n) $v = [Environment]::GetEnvironmentVariable($n); if ("$v".Trim()) { "$v".Trim() } else { '' } }
        $gv = { param($n) if ($globals.ContainsKey($n) -and "$($globals[$n])".Trim()) { "$($globals[$n])".Trim() } else { '' } }
        $proSrv = & $envOr 'SI_UPDATER_PRO_SQL_SERVER'; if (-not $proSrv) { $proSrv = & $gv 'SI_ProSqlServer' }
        $proDb = & $envOr 'SI_UPDATER_PRO_SQL_DATABASE'; if (-not $proDb) { $proDb = & $gv 'SI_ProSqlDatabase' }
        if (-not $proSrv -or -not $proDb) { return $null }   # Community / no Pro database: no web app, no front
        $proSrv = Get-SISigninStoreSqlFqdn -Server $proSrv
        $kvName = & $envOr 'SI_UPDATER_KEY_VAULT'; if (-not $kvName) { $kvName = & $gv 'SI_KeyVaultName' }
        $rg = $target.ResourceGroupName
        # the web app (the install record's name, then today's) and its identity -- the front's identity
        $namesLib = [IO.Path]::Combine($solRoot, 'engine', '_shared', 'SI-InstallNames.ps1')
        $webNames = if (Test-Path -LiteralPath $namesLib) { . $namesLib; @(Get-SIInstallNameCandidates -Role web) } else { @('ca-si-management') }
        $app = $null; $webName = ''
        foreach ($wn in @(@($webNames) + @('ca-si-management') | Where-Object { $_ } | Select-Object -Unique)) {
            try { $app = Invoke-SIRestJson -Rest $rest -Uri (Get-SIArmUri -Path ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/containerApps/{2}' -f $sub, $rg, $wn) -ApiVersion '2025-07-01') -AllowNotFound -What 'reading the web app' } catch { $app = $null }
            if ($app) { $webName = $wn; break }
        }
        if (-not $app) { return $null }
        if ((Get-SISigninFrontChoice -App $app) -eq 'own') { return $null }   # its own sign-in, chosen: no front to prepare for
        Step '9g. SIGN-IN FRONT STORE'
        if (-not $kvName) { Warn ('sign-in front store: the install''s Key Vault is not known here (SI_UPDATER_KEY_VAULT / SI_KeyVaultName) -- not checked; the front keeps what it runs.'); return $null }
        $id = Get-SISigninFrontWebIdentity -App $app
        if (-not $id) { Warn ('sign-in front store: {0} has no single user-assigned managed identity to give the store to -- not checked.' -f $webName); return $null }
        $arm = {
            param([string]$Method, [string]$Path, $Body)
            $u = if ($Path -match '^https://') { $Path } else { 'https://management.azure.com' + $Path }
            Invoke-SIRestJson -Rest $rest -Method $Method -Uri $u -Body $Body -AllowNotFound -What ('{0} {1}' -f $Method, ($Path -replace '\?.*$', ''))
        }
        # parameterised statements on the Pro database, signed in with this update's own token (a new connection per call)
        $sql = {
            param([string]$Query, $Params, [string]$Mode)
            $tok = ([string](Get-SIAzureToken -Resource 'https://database.windows.net/')).Trim()
            if (-not $tok) { throw 'no access token for the database' }
            $cn = New-Object System.Data.SqlClient.SqlConnection
            $cn.ConnectionString = "Server=tcp:$proSrv,1433;Database=$proDb;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
            $cn.AccessToken = $tok
            try {
                $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0
                if ($Params) { foreach ($k in @($Params.Keys)) { $pv = $Params[$k]; $null = $cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $pv) { [DBNull]::Value } else { [string]$pv })) } }
                if ($Mode -eq 'nonquery') { return $cmd.ExecuteNonQuery() }
                $rd = $cmd.ExecuteReader()
                try { while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $rd.GetValue($i) }; [pscustomobject]$o } } finally { $rd.Dispose() }
            } finally { $cn.Dispose() }
        }   # dynamic scope: $proSrv, $proDb come from this function
        $wi = (-not $Apply -or $DetectOnly)
        $r = Invoke-SISigninFrontStore -Arm $arm -Sql $sql -SubscriptionId $sub -ResourceGroup $rg -VaultName $kvName -SqlServer $proSrv -SqlDatabase $proDb `
                 -Identity $id -Apply:(-not $wi) -Log { param($m) Info $m }
        $global:SI_UpdateSigninStore = $r
        # the marker (cfg.InstallState 'SigninFrontStore'): when it was checked, ready or not, what was made -- read by
        # people and support; the step itself always decides from what it reads (idempotent), never from this record
        if (-not $wi) {
            try {
                $v = ConvertTo-Json -Compress -InputObject ([ordered]@{ at = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
                        ready = [bool]$r.Ok; made = @($r.Actions); failed = [string]$r.Failed; key = 'signin-front-dp' })
                $null = & $sql (Get-SISigninStoreRecordSql) ([ordered]@{ Value = $v; By = 'update' }) 'nonquery'
            } catch { Info ('sign-in front store: the record could not be written ({0}) -- the next update writes it' -f $_.Exception.Message) }
        }
        if ($r.Ok) {
            $storeEnv = @($r.Env)
            # 9h (#852, front 1.4.0 on): the web app's own API -- api://<client id>, the scope user_impersonation and the app's
            # organisation-wide consent to it (SI-SigninFrontApi.ps1), read back; ONLY then SIGNIN_UPSTREAM_SCOPE (an access
            # token for the app's own API). #905: three outcomes kept apart (Get-SISigninFrontApiUpdateOutcome) -- the update
            # could not READ them (its identity has no directory read): an Info line only, the front stays on the ID token;
            # read and in place (or added): the scope handed out here; read, missing, and the WRITE refused: the ONE customer
            # action, naming setup\Set-SISigninFront.ps1 and what else it does.
            $pinNow = $null; try { $pinNow = Get-SISigninFrontPin -SIRoot $solRoot } catch { $pinNow = $null }
            if ($pinNow -and (Get-Command -Name Test-SISigninFrontWantsScope -ErrorAction SilentlyContinue) -and (Test-SISigninFrontWantsScope -Pin $pinNow) -and (Get-Command -Name Get-SISigninFrontApiUpdateOutcome -ErrorAction SilentlyContinue)) {
                Step '9h. SIGN-IN FRONT API SCOPE'
                $clientId = (Get-SISigninFrontWebSetting -App $app -Name 'AzureAd__ClientId').Trim()
                $graph = { param([string]$Method, [string]$Uri, $Body) Invoke-SIRestJson -Rest $rest -Method $Method -Uri $Uri -Body $Body -Resource 'https://graph.microsoft.com/' -Headers @{ 'Content-Type' = 'application/json' } }
                $fa = Invoke-SISigninFrontApi -Graph $graph -ClientId $clientId -Apply:(-not $wi)
                $global:SI_UpdateSigninApi = $fa
                $fo = Get-SISigninFrontApiUpdateOutcome -Result $fa -WebApp $webName -WhatIf:$wi
                foreach ($l in @($fo.Info)) { Info $l }
                foreach ($l in @($fo.Warn)) { Warn $l }
                if ($fa.Ok) { $storeEnv += ('SIGNIN_UPSTREAM_SCOPE={0}' -f $fa.Scope) }
                if ($fo.Action -and (Get-Command -Name Add-SIUpdaterCustomerAction -ErrorAction SilentlyContinue)) { Add-SIUpdaterCustomerAction -Step 'post-roll' -Text $fo.Action -Class 'config-missing' }
            }
            $global:SI_SigninFrontStoreEnv = @($storeEnv)
            Info ('sign-in front store: the front gets {0} with its other settings kept' -f ((@($storeEnv) | ForEach-Object { ($_ -split '=', 2)[0] }) -join ', '))
            return $r
        }
        if ($wi) { return $r }
        $t = ('{0}: the shared sign-in front''s store is not ready ({1}). Run setup\Set-SISigninFront.ps1 -Apply through the Support app (as an administrator): it makes the key, the identity''s right on it and its database user, schema and grant, and reads them back. Until then a sign-in front that needs the store (1.3.0 on) is not rolled in -- the front keeps the version it runs.' -f $webName, $r.Why)
        Warn $t
        if (Get-Command -Name Add-SIUpdaterCustomerAction -ErrorAction SilentlyContinue) { Add-SIUpdaterCustomerAction -Step 'post-roll' -Text $t -Class 'config-missing' }
        $r
    } catch { Warn ("sign-in front store: not checked ({0}) -- the update goes on; the front keeps what it runs; the next update tries again." -f $_.Exception.Message); $null }
}
function Complete-SIUpdate { $null = Invoke-SIUpdateSqlTier; $null = Invoke-SIUpdateJobFloor; $null = Invoke-SIUpdateJobSizing; $null = Invoke-SIUpdateUpdaterSize; $null = Invoke-SIUpdateKedaConvert; $null = Invoke-SIUpdateRaWorkers; $null = Invoke-SIUpdateEngineRetryLimit; $null = Invoke-SIUpdateRaGcSetting; $null = Invoke-SIUpdateMissingJobs; $null = Invoke-SIUpdateNightlySchedule; $null = Invoke-SIUpdateReportCopy; $null = Invoke-SIUpdateOrchestration; $null = Invoke-SIUpdatePipelineLayout; $null = Invoke-SIUpdateSummaryRebuild; $null = Invoke-SIUpdatePublishedCopy; $null = Invoke-SIUpdateKeyFigures; $null = Invoke-SIUpdateOwnSqlConnector; $null = Invoke-SIUpdateSnowDataOut; $null = Invoke-SIUpdateSnowStagingStatus; $null = Invoke-SIUpdateSnowOneRoute; $null = Invoke-SIUpdateWebAppSize; $null = Invoke-SIUpdateSigninStore; $null = Invoke-SIUpdatePermissionNote; $null = Invoke-SIUpdateDisplayNames; Install-SIUpdateDefaultTemplates }
$script:SISqlTierJobs = @()

# #756 THE CODE IS CURRENT, THE SIZES STILL FOLLOW THE SETTINGS (live 2026-10-19: SI_Bootstrap_SqlServiceObjective = S2 set,
# the updater found its release applied already and the database stayed S3). -SizingOnly runs only the size steps that read
# the customer's settings -- the SQL database (7), the jobs (8) and the web app (8d) -- each idempotent and never fatal. The
# registry is not read, no image is built, no job is rolled: the one job list is the tenant-size fallback and the jobs sized.
if ($SizingOnly) {
    if (-not $rest) { Warn ("sizes: not checked -- no Azure sign-in ({0}); the next update tries again." -f $signInError); exit 0 }
    try { $script:SISqlTierJobs = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName) }
    catch { Info ("sizes: the jobs could not be listed ({0}) -- the job size is not checked this run" -f $_.Exception.Message) }
    $null = Invoke-SIUpdateSqlTier; $null = Invoke-SIUpdateJobSizing; $null = Invoke-SIUpdateWebAppSize
    Info 'sizes: the code is current -- the SQL database, job and web app sizes were checked against the settings; no image was built or rolled.'
    exit 0
}

$managedBy = Get-SIUpdaterManagedJob -Globals $globals
if ($managedBy -and -not $Force) {
    Info ("These containers are updated by the updater job '{0}' (SecurityInsight Pro), to the version your update ring approves -- nothing to do here." -f $managedBy)
    Info 'To roll this folder''s code by hand anyway, re-run with -Force; the job moves them back to the approved version on its next run.'
    exit 0
}

# #178 / #521: this needs a sign-in with rights on the registry and the jobs. When the sync runs this hook on a VM that
# manages container hosting and nothing here can sign in, say the cause, once, and how to fix it -- not a message about
# the registry.
$acr = $null
if ($rest) { try { $acr = Get-SIAcrRegistry -Rest $rest -SubscriptionId $sub -AcrName $target.AcrName -ResourceGroup $target.ResourceGroupName } catch { $signInError = $_.Exception.Message } }
if (-not $acr) {
    Warn ("Container hosting is configured ({0} / {1}) but this machine cannot reach Azure with access to subscription {2}: {3}" -f $target.ResourceGroupName, $target.AcrName, $sub, $signInError)
    Warn 'Give the identity that runs this sync a sign-in SecurityInsight can use (SI_SPN_AppId + SI_SPN_TenantId + SI_SPN_CertThumbprint in the config, or a managed identity), or -- if the containers'
    Warn 'are updated by their own updater job -- remove SI_Bootstrap_ResourceGroupName / SI_Bootstrap_AcrName from this machine''s config.'
    exit 1
}

$version = (Get-Content -LiteralPath (Join-Path $solRoot 'VERSION') -Raw).Trim()
$tag     = Get-SIContainerImageTag -Version $version -ContentHash (Get-SIContainerContentHash -SolutionRoot $solRoot)
$newImage = ('{0}/si-orchestrator:{1}' -f $acr.LoginServer, $tag)
Info "image for this tree: $newImage"

$jobsRaw = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName)
$script:SISqlTierJobs = @($jobsRaw)   # #507: the tenant-size fallback (the collection jobs setup sized for the tenant)
$jobs = foreach ($j in $jobsRaw) {
    $img = $null
    try { $img = [string]$j.properties.template.containers[0].image } catch { }
    [pscustomobject]@{ Name = [string]$j.name; Image = $img }
}
$plan = @(Get-SIContainerUpdatePlan -Jobs @($jobs) -LoginServer $acr.LoginServer -TargetImage $newImage)
if ($plan.Count -eq 0) {
    Warn ("No job in {0} runs {1}/si-orchestrator -- nothing to roll. Run the container setup to create the jobs first." -f $target.ResourceGroupName, $acr.LoginServer)
    exit 0
}
$toUpdate = @($plan | Where-Object { $_.Action -eq 'update' })
foreach ($p in $plan) { Info ("{0,-40} {1}  ({2})" -f $p.Name, $p.Action, $p.PreviousImage) }
if ($toUpdate.Count -eq 0) { Info 'Every job already runs this tree -- nothing to roll.'; exit (Complete-SIUpdate) }
if (-not $Apply -or $DetectOnly) { Info ("{0} job(s) would move to the new image. Re-run with -Apply to update." -f $toUpdate.Count); exit (Complete-SIUpdate) }

# ---- 2. BUILD ---------------------------------------------------------------------------------
# #416 (the fast roll, setup/_shared/SI-FastRoll.ps1): a Dockerfile with expensive lines before its first COPY is built in
# two layers -- the cached base (built only when its hash is missing) and the thin code layer per release.
# #521: the registry builds it over ARM (setup/_shared/SI-AcrBuild.ps1): packed here, uploaded, scheduled, followed; a
# failed build prints the end of its log.
Step '2. BUILD'
$bArgs = @{ Rest = $rest; AcrName = $target.AcrName; SubscriptionId = $sub; ResourceGroup = $acr.ResourceGroup }
if (Test-SIAcrTag @bArgs -Repo 'si-orchestrator' -Tag $tag -LoginServer $acr.LoginServer) {
    Info "tag $tag is already in the registry -- not rebuilding."
} else {
    $layer = Get-SIImageLayerPlan -DockerfilePath (Join-Path $solRoot 'container/Dockerfile') -BaseRepo 'si-base' -LoginServer $acr.LoginServer
    $work = Join-Path ([IO.Path]::GetTempPath()) ('si-build-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    try {
        $file = 'container/Dockerfile'
        if ($layer.HasBase) {
            Info $layer.Reason
            $file = Join-Path $work 'Dockerfile.app'
            [IO.File]::WriteAllText($file, $layer.AppDockerfile)
            if (Test-SIAcrTag @bArgs -Repo $layer.BaseRepo -Tag $layer.BaseTag -LoginServer $acr.LoginServer) { Info ("base {0} is in the registry -- reused" -f $layer.BaseImage) }
            else {
                $baseCtx = Join-Path $work 'base-ctx'; New-Item -ItemType Directory -Force -Path $baseCtx | Out-Null
                $baseFile = Join-Path $work 'Dockerfile.base'; [IO.File]::WriteAllText($baseFile, $layer.BaseDockerfile)
                Push-Location -LiteralPath $baseCtx
                try { $b = Start-SIAcrBuild @bArgs -Image $layer.BaseImage -File $baseFile } finally { Pop-Location }
                $b = @(Wait-SIAcrBuilds @bArgs -Builds @($b) -TimeoutMinutes $BuildTimeoutMinutes -Log { param($m) Info $m })[0]
                if ($b.Status -ne 'Succeeded') { throw "The base image build did not succeed ($($b.Status)). No job was changed." }
            }
        } else { Info $layer.Reason }
        # queued, then followed: one build run, polled until it ends
        $script:EngineBuild = $null
        Invoke-SIInBuildContext -Path $solRoot -Log { param($m) Info $m } -Action {
            $script:EngineBuild = Start-SIAcrBuild @bArgs -Image "si-orchestrator:$tag" -File $file
        }
        $eb = @(Wait-SIAcrBuilds @bArgs -Builds @($script:EngineBuild) -TimeoutMinutes $BuildTimeoutMinutes -Log { param($m) Info $m })[0]
        if ($eb.Status -ne 'Succeeded') { throw "The image build did not succeed ($($eb.Status)). No job was changed." }
    } finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

# ---- 3. ROLL / 4. VERIFY / 5. ROLLBACK ---------------------------------------------------------
# #416: every job by ONE ARM PATCH of its template (never a PUT -- secrets; never one job update after another -- 16 jobs
# took ~11 min), all sent at once, then every job read back: its image, and nothing else changed.
Step '3. ROLL (all jobs at once)'
$repoPrefix = ('{0}/si-orchestrator' -f $acr.LoginServer)
$rollLog = { param($m) Info $m }
$targets = @($toUpdate | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Image = $newImage } })
$results = @(Invoke-SIJobImageRoll -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Targets $targets -Jobs $jobsRaw -RepoPrefix $repoPrefix -Log $rollLog)
Step '4. VERIFY'
foreach ($r in $results) { if ($r.Ok) { Info ("{0} verified: {1}; nothing else changed" -f $r.Name, $tag) } else { Warn ("{0}: {1}" -f $r.Name, $r.Error) } }
$failed = @($results | Where-Object { -not $_.Ok })
$updated = @($toUpdate | Where-Object { $n = $_.Name; @($results | Where-Object { $_.Name -eq $n -and $_.Sent }).Count })

if ($failed.Count) {
    Warn ("Update failed: {0} of {1} job(s) -- {2}" -f $failed.Count, $toUpdate.Count, (($failed | ForEach-Object { $_.Name }) -join ', '))
    # SUP-2026-00198: each failure the updater reports is recorded with ITS step and its catalogue code -- the roll's own
    # failure is 'roll' (si-upd-0803 refused / si-upd-0805 not verified), and only a job that could not be PUT BACK is a
    # 'restore' failure (si-upd-0804). Until then a clean rollback was reported as "restore failed" with the roll's 400.
    $global:SI_UpdateFailures = New-Object System.Collections.Generic.List[object]
    foreach ($grp in @($failed | Group-Object -Property { Get-SIRollFailureCode -Result $_ })) {
        $first = $grp.Group[0]
        $global:SI_UpdateFailures.Add([pscustomobject]@{ Step = 'roll'; Code = $grp.Name
            Text = ("{0}: {1} of {2} job(s) not rolled to {3} ({4}); first: {5}: {6}" -f $grp.Name, $grp.Count, $toUpdate.Count, $tag, (($grp.Group | ForEach-Object { $_.Name }) -join ', '), $first.Name, $first.Error) })
    }
    # #350: restore only what still runs the image THIS update set -- a job someone else moved meanwhile keeps theirs.
    # The image each job goes back to is the one DETECT read BEFORE the roll (PreviousImage of the plan), never one read now.
    $nowList = @(); $nowImages = $null
    try {
        $nowList = @(Get-SIArmJobList -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName)
        $nowImages = @{}
        foreach ($j in $nowList) { if ($j) { try { $nowImages[[string]$j.name] = [string]$j.properties.template.containers[0].image } catch { } } }
    } catch { Warn ("the jobs could not be read before the rollback ({0}) -- every job this update sent is put back" -f $_.Exception.Message); $nowList = @($jobsRaw) }
    # a job whose PATCH answer was lost but which DOES run the new image now is put back too
    if ($nowImages) { $updated = @($toUpdate | Where-Object { $n = $_.Name; @($results | Where-Object { $_.Name -eq $n -and $_.Sent }).Count -or ($nowImages.ContainsKey($n) -and $nowImages[$n] -eq $newImage) }) }
    if ($updated.Count -eq 0) { Info 'no job runs the new image -- nothing to put back; every job runs the version it ran before' }
    else { Step '5. ROLLBACK' }
    $back = New-Object System.Collections.Generic.List[object]
    foreach ($r in @(Get-SIContainerRollbackPlan -Updated $updated -NewImage $newImage -Current $nowImages)) {
        if ($r.Action -eq 'skip') { Info ("{0} now runs {1} (changed by someone else since) -- left as it is" -f $r.Name, $r.Now); continue }
        $back.Add([pscustomobject]@{ Name = $r.Name; Image = $r.Image })
    }
    if ($back.Count) {
        foreach ($r in @(Invoke-SIJobImageRoll -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Targets $back.ToArray() -Jobs $nowList -RepoPrefix $repoPrefix -Log $rollLog)) {
            $prev = @($back | Where-Object { $_.Name -eq $r.Name })[0].Image
            if ($r.Ok) { Info ("{0} restored to {1}" -f $r.Name, $prev) }
            else {
                $rc = Get-SIRollFailureCode -Result $r -Restore
                Warn ("{0}: {1} could NOT be restored to {2}: {3} -- restore it by hand." -f $rc, $r.Name, $prev, $r.Error)
                $global:SI_UpdateFailures.Add([pscustomobject]@{ Step = 'restore'; Code = $rc; Text = ("{0}: {1} could not be put back on {2}: {3}" -f $rc, $r.Name, $prev, $r.Error) })
            }
        }
    }
    exit 1
}
Info ("{0} job(s) now run {1}." -f $toUpdate.Count, $tag)
# The update NEVER stops a running pipeline (owner 2026-10-16, reversing 2026-10-15: "i dont want it to stop it ... otherwise it
# will newer complete on large env where it takes more than 24 hr to complete"). A run in progress finishes: a job already
# running ends on the version it started with, every job started after the roll runs the new version.
exit (Complete-SIUpdate)
} finally {
    if ($script:SIUpdateWatchOwn -and (Get-Command -Name Stop-SIUpdateWatch -ErrorAction SilentlyContinue)) { Stop-SIUpdateWatch }
    Stop-SIScriptRun -Run $siRun
}
