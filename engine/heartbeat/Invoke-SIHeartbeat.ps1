#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight -- the heartbeat to Invardia, every half hour (#718; owner 2026-10-17: "like 30 min refresh").
.DESCRIPTION
    Runs as its own small container job (caj-si-heartbeat) on its OWN timer -- every 15 minutes since #723 (default
    "7,22,37,52 * * * *", SI_Bootstrap_ScheduleHeartbeat; the full heartbeat goes out ONCE per half hour (:00-:29, :30-:59 UTC),
    the half hour's claim decides, and every tick asks Invardia for the "update now" signal: engine\_shared\SI-UpdateNowSignal.ps1) --
    never a step of the pipeline: it runs whether or not a pipeline runs, so Invardia hears
    from the install every hour -- also during a 6-hour report or a 5-hour correlation, and also when the pipeline runner
    itself stopped. One identified heartbeat per half hour (engine\_shared\SI-HeartbeatJob.ps1, Send-SIHeartbeatTick):
    the same record as the end-of-run heartbeat; the pipeline's progress (runProgress) and the state of each collection
    (Collections) only where their switches say so (default off until Invardia confirms the fields).
    The same job in both editions. An anonymous install (no install key yet, either edition) sends no report from here; the
    support grant sweep and the outbox below run the same way in both.
    It reads only: the run record (cfg.FlowRun / cfg.FlowStepRun), the collection state (sidata.*, index reads) and one
    Graph count -- and on every tick it REVOKES an expired just-in-time grant of the Invardia Support app (#1021, the
    signed procedure cfg.SupportGrantSweep). LAST on every tick it sends again the run reports Invardia did not take at the
    end of their job (framework 8.4, the uplink outbox cfg.UplinkOutbox: oldest first, in rounds; a report taken is deleted
    from it). It never fails: anything that goes wrong is said once, and the job ends well (exit 0).
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
try { Set-StrictMode -Off } catch { }
$here = $PSScriptRoot
$siRoot = Split-Path -Parent (Split-Path -Parent $here)
$say = { param([string]$Level, [string]$Message) Write-Host ('[{0}] {1}' -f $Level, $Message) -ForegroundColor $(if ($Level -eq 'WARN') { 'Yellow' } else { 'Gray' }) }

& $say 'STEP' 'SecurityInsight -- Invardia support link (every half hour)'
try {
    . (Join-Path $siRoot 'engine/_shared/SI-HeartbeatJob.ps1')
    if (-not (Get-Command -Name Get-SILicense -ErrorAction SilentlyContinue)) { $cat = Join-Path $siRoot 'engine/SI-FeatureCatalog.ps1'; if (Test-Path -LiteralPath $cat) { try { . $cat } catch { } } }
    if (-not (Get-Command -Name Invoke-SIAzRestRequest -ErrorAction SilentlyContinue)) { $ar = Join-Path $siRoot 'engine/_shared/SI-AzRest.ps1'; if (Test-Path -LiteralPath $ar) { try { . $ar } catch { } } }
} catch {
    & $say 'WARN' ('the Invardia support link could not be loaded ({0}) -- nothing is sent this half hour' -f $_.Exception.Message)
    exit 0
}

# the Pro database: the half hour's claim, the release fields and the run record
$proInvoke = $null; $runStore = $null; $dataInvoke = $null
if ([string]$global:SI_ProSqlServer -and [string]$global:SI_ProSqlDatabase) {
    try {
        # the settings layer's own store (both editions ship it) -- the same sign-in the connector registry uses
        if (-not (Get-Command -Name New-SIProSettingsStore -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/pro-settings/SI-ProSettings.ps1') }
        $first = { param([object[]]$v) foreach ($x in $v) { if (-not [string]::IsNullOrWhiteSpace([string]$x)) { return [string]$x } }; '' }
        $pro = New-SIProSettingsStore -Server ([string]$global:SI_ProSqlServer) -Database ([string]$global:SI_ProSqlDatabase) `
            -AppId (& $first @($global:SI_SPN_AppId, $global:HighPriv_Modern_ApplicationID_Azure)) `
            -TenantId (& $first @($global:SI_SPN_TenantId, $global:AzureTenantId)) `
            -CertThumbprint (& $first @($global:SI_SPN_CertThumbprint, $global:HighPriv_Modern_CertificateThumbprint_Azure))
        if ($pro) { $proInvoke = $pro.Invoke }
        # the install's recorded facts (ring, update state, own links, environment) -- what the Pro settings layer reads for
        # every engine run at start (SI-ProSettings.ps1). Without them this job did not know its ring, so every per-ring
        # switch (Collections and the other new heartbeat fields) read as off (live 2026-10-16: the 19:07Z heartbeat went
        # without them).
        if ($pro -and -not $global:SI_InstallRingFacts) {
            if (-not (Get-Command -Name Read-SIInstallRingFacts -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-InstallRing.ps1') }
            $global:SI_InstallRingFacts = Read-SIInstallRingFacts -Store $pro
        }
        if ($proInvoke) {
            if (-not (Get-Command -Name New-SIJobFlowSqlStore -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-JobFlow.ps1') }
            $runStore = New-SIJobFlowSqlStore -Invoke $proInvoke
        }
    } catch { & $say 'INFO' ('the Pro database could not be opened ({0}) -- the report goes without the pipeline''s state' -f $_.Exception.Message); $proInvoke = $null; $runStore = $null }
    try {
        if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/data-model/SI-RecordSql.ps1') }
        $dSrv = if ([string]$global:SI_Pro_DataSqlServer) { [string]$global:SI_Pro_DataSqlServer } else { [string]$global:SI_ProSqlServer }
        $dDb = if ([string]$global:SI_Pro_DataSqlDatabase) { [string]$global:SI_Pro_DataSqlDatabase } else { [string]$global:SI_ProSqlDatabase }
        $dataInvoke = New-SIRecordSqlInvoke -Server $dSrv -Database $dDb
    } catch { $dataInvoke = $null }
}

$r = Send-SIHeartbeatTick -RunStore $runStore -DataInvoke $dataInvoke -ClaimInvoke $proInvoke
# ONE plain line per tick (live 2026-10-16: a tick that sent nothing must never be silent): what happened, the endpoint's
# host, the mode, Invardia's answer or the error, and which optional fields rode along (Get-SIHeartbeatTickLine)
& $say $(if ($r.Status -in @('failed', 'error')) { 'WARN' } else { 'INFO' }) ('Invardia support link: {0}' -f $(if ("$($r.Reason)".StartsWith("$($r.Status)")) { $r.Reason } else { '{0} -- {1}' -f $r.Status, $r.Reason }))

# #1021 THE SUPPORT GRANT SWEEP -- on EVERY tick: a just-in-time grant of the Invardia Support app that is past its maxUntil is
# revoked (the signed procedure cfg.SupportGrantSweep removes only what an EXPIRED grant added; never the read-only access).
# The grant job and the web app sweep too, so no one of them is the only revoker. Silent when there is nothing to do; a
# database the admin step has not reached yet is nothing to do. Never fails the job.
try {
    if ($proInvoke -and (Get-Command -Name Invoke-SISupportGrantSweep -ErrorAction SilentlyContinue)) {
        $sgDbs = Get-SISupportGrantDatabases
        if ($sgDbs.Count) {
            $sg = Invoke-SISupportGrantSweep -Databases $sgDbs -By 'caj-si-heartbeat'
            foreach ($l in @($sg.Lines)) { & $say $(if ($l -match 'failed|WARNING') { 'WARN' } else { 'INFO' }) ('support access: {0}' -f $l) }
        }
    }
} catch { & $say 'INFO' ('support access: the expired-grant sweep could not run ({0})' -f $_.Exception.Message) }

# #1151 (5) NAM-02 INVARDIA'S NAME FOR THIS ENVIRONMENT -- on the full heartbeat's tick (once per half hour): GET
# /api/enrollments/environment with the install key; the last GOOD name is kept in cfg.InstallState 'InvardiaEnvironment', a
# failed read never blanks it (engine\_shared\SI-InvardiaEnvironment.ps1). Silent when nothing changed. Never fails the job.
try {
    if ($r.Status -in @('sent', 'failed', 'error') -and (Get-Command -Name Invoke-SIInvardiaEnvironmentRead -ErrorAction SilentlyContinue)) {
        $en = Invoke-SIInvardiaEnvironmentRead -Invoke $proInvoke
        if ($en -and "$($en.Line)".Trim()) { & $say $(if ($en.Status -in @('kept', 'error')) { 'WARN' } else { 'INFO' }) $en.Line }
    }
} catch { & $say 'INFO' ('environment name: not read this time ({0})' -f $_.Exception.Message) }

# #723 THE "UPDATE NOW" SIGNAL -- asked on EVERY tick (the job runs every 15 minutes); the full heartbeat above went out only
# on the half hour's first tick (the half hour's claim). A newer version signalled by Invardia starts the updater ONCE per signal --
# never while it runs, never waiting for or stopping a pipeline run. Never fails the job.
try {
    $fullTick = ($r.Status -in @('sent', 'failed', 'error'))
    $u = Invoke-SIUpdateNowCheck -Invoke $proInvoke -RunStore $runStore -FullTick:$fullTick
    if ($u -and "$($u.Line)".Trim()) { & $say $(if ($u.Status -in @('start-failed', 'error')) { 'WARN' } else { 'INFO' }) $u.Line }
} catch { & $say 'INFO' ('update now: the signal could not be checked ({0})' -f $_.Exception.Message) }

# #985 THE PRE-RUN CHECK -- once a day, on the tick 30 minutes before the next scheduled run: the updater looks for a newer
# release when its last look is more than 15 minutes old (a release after the daily update is installed before the night's
# run). Not when the signal above started it already. Never fails the job.
try {
    if (-not ($u -and $u.Started)) {
        $pr = Invoke-SIUpdatePreRunCheck -Invoke $proInvoke -RunStore $runStore
        if ($pr -and "$($pr.Line)".Trim()) { & $say $(if ($pr.Status -in @('start-failed', 'error')) { 'WARN' } else { 'INFO' }) $pr.Line }
    }
} catch { & $say 'INFO' ('update check before the run: not done ({0})' -f $_.Exception.Message) }

# #757 THE PERFORMANCE PAGE'S SAMPLES -- once an hour (the first tick of the hour; the others read one row and stop): the load of
# the databases and the web app over the hours not stored yet, and the sizes the install runs, into cfg.PerfSample
# (engine\_shared\SI-PerfSample.ps1). The web app reads them; it has no Azure right of its own (CR8). Never fails the job.
try {
    if (-not (Get-Command -Name Invoke-SIPerfSample -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-PerfSample.ps1') }
    if (-not (Get-Command -Name Get-SIInstallName -ErrorAction SilentlyContinue)) { $nl = Join-Path $siRoot 'engine/_shared/SI-InstallNames.ps1'; if (Test-Path -LiteralPath $nl) { try { . $nl } catch { } } }
    # the web app's name from the install record (the updater writes it; ca-si-web after the move), not only this job's defaults
    if ($proInvoke -and $null -eq $global:SI_InstallNames -and (Get-Command -Name Read-SIInstallNamesRecord -ErrorAction SilentlyContinue)) {
        try { $global:SI_InstallNames = Read-SIInstallNamesRecord -Store ([pscustomobject]@{ Invoke = $proInvoke }) } catch { }
    }
    $ps = Invoke-SIPerfSample -Invoke $proInvoke
    if ($ps.Status -ne 'not-due' -and "$($ps.Line)".Trim()) { & $say $(if ($ps.Status -eq 'error') { 'WARN' } else { 'INFO' }) $ps.Line }
} catch { & $say 'INFO' ('performance samples: not recorded ({0})' -f $_.Exception.Message) }

# framework 8.4 THE UPLINK OUTBOX -- LAST on EVERY tick (the heartbeat above went FIRST): the run reports Invardia did not take at
# the end of their job (cfg.UplinkOutbox) are sent again, oldest first, in rounds of at most 20 with at least 65 s between rounds,
# at most 5 rounds; the first answer that is not ok stops it for this tick. Nothing from it when this tick's heartbeat was not
# taken. The kept rows are bounded (7 days, 5,000) and a drop is said once (engine\_shared\SI-UplinkOutbox.ps1). Never fails the job.
try {
    if ($proInvoke -and (Get-Command -Name Invoke-SIUplinkOutboxTick -ErrorAction SilentlyContinue)) {
        $ob = Invoke-SIUplinkOutboxTick -Invoke $proInvoke -HeartbeatStatus ([string]$r.Status)
        foreach ($l in @($ob.Lines)) { & $say $(if ($ob.Status -in @('stopped', 'error')) { 'WARN' } else { 'INFO' }) $l }
    }
} catch { & $say 'INFO' ('Invardia support link, run results: not sent this tick ({0})' -f $_.Exception.Message) }
# never a failed execution: a heartbeat that did not go out is said, and the next tick tries again
exit 0
