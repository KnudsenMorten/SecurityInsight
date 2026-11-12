#Requires -Version 5.1
<#
    SecurityInsight -- EXISTING INSTALLS GET THE JOBS A NEWER VERSION NEEDS (#685; rule: existing installs reach new-install
    state). Found 2026-10-15: the verification service's job caj-si-verification was created by NO setup and NO update, so
    engine\verification\Invoke-SIVerification.ps1 -- and the CR2 data health check it runs in its finally block
    (engine\data-health\Invoke-SIDataHealth.ps1) -- never ran at any install.
    Bootstrap-ContainerAppJob.ps1 now creates it at a new install; every update (setup\Invoke-SIContainerUpdate.ps1, the
    updater job and the VM sync hook both run it) creates it where it is missing:

      * WHEN (Get-SIMissingJobPlan, PURE): this tree carries the engine (and the Pro settings layer), the job does not
        exist, and a Pro job of the same kind exists to build it from (the DONOR: caj-si-asset-datasync, else
        caj-si-close-loop-mail, caj-si-asset-cmdb-sql, caj-si-asset-correlation) -- made by SI's setup (its si-build tag),
        on a timer or manual (never an event-triggered worker). No donor = nothing is created, one line says why (the
        container setup creates it).
      * WHAT (Get-SIMissingJobSpec, PURE): exactly what Bootstrap gives a new install -- the donor's image, registry,
        identity, Container Apps environment, sign-in and settings (its env, its SI_CFG_* settings, its secrets with their
        values or Key Vault references, read by ARM listSecrets), with SI_ENGINE = the new engine, one replica, the size of
        Get-SIContainerJobResources (never below the donor's), and Bootstrap's trigger (Get-SIBootstrapTriggerPlan): in
        flow mode (caj-si-flow on its timer) a step of the pipeline is MANUAL with its timer remembered in si-disabled-cron;
        in schedules mode it gets its own timer (the map's defaultCron, or SI_Bootstrap_Schedule<Engine>). What only the
        donor's engine needs (the SMTP password, the Shodan key, the vulnerability connector group, the queue settings) is
        left out, and so is a secret nothing then refers to.
      * HOW (Invoke-SIMissingJobs): one ARM PUT, then the job is READ BACK until its creation has finished (REST after
        create: wait and read back) -- it must exist, have succeeded, run the donor's image, carry SI_ENGINE and the planned
        trigger. A job that does not read back right is removed again (only a job this run created), one line says why, and
        the next update tries again. Idempotent: a job that exists is never touched.
      * Never throws; -WhatIf: the plan only, no Azure call at all.

    #714 (found 2026-10-16): the MAIL job caj-si-close-loop-mail was never created by the guided Pro
    install (Get-SIInstallProEngines left it out), so at installs made that way no mail of any kind was ever sent and the
    mail restriction was never verified ("'caj-si-close-loop-mail' is not one of this installation's jobs"). It is now in
    the catalog too: built the same way from a Pro job of the install, and -- where a Risk Analysis job of the install
    carries the SMTP relay password (an authenticated relay) -- with that same secret (BORROWED: its Key Vault reference,
    or its value) as SMTP_PASSWORD, exactly as Bootstrap wires it for a new install. Its timer in schedules mode:
    SI_Bootstrap_ScheduleCloseLoopMail, else Mail_CloseLoop_Daily_SendTimeUtc, else the map's 10:45.

    #715 (found 2026-10-16, same class as #714): the ServiceNow VULNERABILITY connector's job caj-si-asset-vulns-servicenow
    (and the ServiceNow CMDB connector's caj-si-asset-cmdb) was never made by the guided Pro install -- Bootstrap drops a
    ServiceNow job unless a setting or switch says ServiceNow is used, and the guided install passed none -- and no update
    added it, so a ServiceNow customer got "'caj-si-asset-vulns-servicenow' is not one of this installation's jobs". Both
    are in the catalog with a WHEN: created only where the install uses ServiceNow (#269: the ServiceNow jobs exist only
    where ServiceNow is used) -- a ServiceNow connector of that direction in the Pro database (the update reads
    cfg.Connector), or the setting Bootstrap reads (Get-SIMissingJobConditions). Not used = nothing created, nothing said.
    No secret is borrowed: the connector reads its ServiceNow credentials at run time from the install's Key Vault by the
    secret NAMES in its cfg.Connector row, as the job's managed identity.

    #718 (owner 2026-10-16: "it must sent outside of the pipeline"): the hourly status report to Invardia, caj-si-heartbeat,
    is in the catalog for every Pro install: on its OWN timer every hour ("7 * * * *", SI_Bootstrap_ScheduleHeartbeat) in
    both orchestration modes (never a step of the pipeline), with the floor size and its own 30-minute run limit -- never the
    donor's size or run limit (OwnSize).

    #723 (the "update now" signal): the heartbeat job now runs every 15 minutes ("7,22,37,52 * * * *"). An EXISTING job still
    on the timer an earlier version shipped ("7 * * * *", ShippedCrons) is moved to it by every update: ONE read-modify-write
    ARM PATCH of its trigger (triggerType, its run limit, the cron, its parallelism and completion count -- nothing else),
    then READ BACK until the cron is the new one (Get-SIMissingJobRetime, PURE + Invoke-SIMissingJobs). A timer the customer
    chose (anything else, or SI_Bootstrap_ScheduleHeartbeat set) is never touched; a job without a timer is left as it is.

    NO az CLI, no PowerShell module: every call goes through ONE seam,
    -Rest { param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers) } -> @{ Status; Body }.
    The job is built by translating Bootstrap's own job definition (the az arguments) into the ARM resource
    (ConvertFrom-SIJobCreateArgs, setup\_shared\SI-KedaConvert.ps1).
#>

$script:SIMissingJobsLibRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command ConvertFrom-SIJobCreateArgs -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIMissingJobsLibRoot, 'setup', '_shared', 'SI-KedaConvert.ps1')) }

$script:SIMissingJobsArmApi = '2025-07-01'

# The jobs a newer version needs that an older install may not have. Engine = SI_ENGINE; Code = the file under the solution
# root that must be in this tree; Donors = the Pro jobs (in order) whose sign-in, settings and image the new job takes.
$script:SIMissingJobCatalog = @(
    [pscustomobject]@{
        Engine = 'verification'; Code = @('engine/verification/Invoke-SIVerification.ps1', 'engine/pro-settings/SI-ProSettings.ps1')
        Donors = @('caj-si-asset-datasync', 'caj-si-close-loop-mail', 'caj-si-asset-cmdb-sql', 'caj-si-asset-correlation')
        What   = 'the verification service (the data-collection gaps and the daily data health check)'
    }
    # #714: the mail job. Borrow: a secret only another kind of job carries (the SMTP relay password lives on the Risk
    # Analysis jobs when their relay is authenticated) -- taken from the first of From that has it, as Env. CronSetting:
    # the customer's send time (HH:mm UTC), used in schedules mode when no SI_Bootstrap_Schedule<Engine> is set.
    [pscustomobject]@{
        Engine = 'close-loop-mail'; Code = @('engine/asset-cmdb/Invoke-SICloseLoopMail.ps1', 'engine/pro-settings/SI-ProSettings.ps1')
        Donors = @('caj-si-asset-datasync', 'caj-si-asset-cmdb-sql', 'caj-si-asset-correlation', 'caj-si-verification')
        What   = 'the mail job (every mail SecurityInsight sends, and the mail restriction check)'
        Borrow = @([pscustomobject]@{ Secret = 'smtp-password'; Env = 'SMTP_PASSWORD'; From = @('caj-si-risk-analysis', 'caj-si-risk-analysis-detailed') })
        CronSetting = 'Mail_CloseLoop_Daily_SendTimeUtc'
    }
    # #715: the two ServiceNow jobs -- ONLY where ServiceNow is used (#269, operator 2026-10-04: the ServiceNow jobs exist
    # only where ServiceNow is used). When: Get-SIMissingJobConditions -- a ServiceNow connector of that direction in the
    # Pro database (cfg.Connector, what the web app's Connectors / Get Started pages write), or the setting Bootstrap reads
    # (Get-SIServiceNowJobPlan). The web app starts caj-si-asset-vulns-servicenow for a ServiceNow vulnerability connector
    # (Run once, the send log, the guard releases) and caj-si-asset-cmdb for a ServiceNow CMDB connector. No secret: the
    # connector reads its ServiceNow credentials at run time from the install's Key Vault, by the secret NAMES its
    # cfg.Connector row holds, as the job's managed identity -- nothing to borrow. ScheduleSetting: Bootstrap's own name for
    # the job's timer where it is not SI_Bootstrap_Schedule<Engine>.
    [pscustomobject]@{
        Engine = 'asset-vulnerabilities-servicenow'; Code = @('engine/asset-cmdb/Invoke-SIVulnLoop.ps1', 'engine/pro-settings/SI-ProSettings.ps1')
        Donors = @('caj-si-asset-vulnerabilities', 'caj-si-asset-datasync', 'caj-si-asset-cmdb-sql', 'caj-si-asset-correlation')
        What   = 'the ServiceNow vulnerability connector'
        When   = 'ServiceNowVulnerabilities'
        ScheduleSetting = 'SI_Bootstrap_ScheduleVulnerabilitiesServiceNow'
    }
    [pscustomobject]@{
        Engine = 'asset-cmdb'; Code = @('engine/asset-cmdb/Invoke-SICmdb.ps1', 'engine/pro-settings/SI-ProSettings.ps1')
        Donors = @('caj-si-asset-cmdb-sql', 'caj-si-asset-datasync', 'caj-si-asset-correlation', 'caj-si-asset-vulnerabilities')
        What   = 'the ServiceNow CMDB connector'
        When   = 'ServiceNowCmdb'
    }
    # #718: the hourly status report to Invardia -- its OWN timer (Cron, every hour; never a step of the pipeline: neverInFlow
    # in the map, so a Schedule trigger in both modes), its own short run limit and the floor size, NOT the donor's
    # (OwnSize: a donor's 7-day limit would let one hung tick block every later hour). ScheduleSetting: Bootstrap's name.
    # #723: every 15 minutes (each tick asks Invardia for the "update now" signal; the full report still goes once an hour).
    # ShippedCrons: the timers an earlier version shipped -- an EXISTING job still on one of them is moved to Cron by the
    # update (Get-SIMissingJobRetime); any other timer is the customer's and is never touched.
    [pscustomobject]@{
        Engine = 'heartbeat'; Code = @('engine/heartbeat/Invoke-SIHeartbeat.ps1', 'engine/pro-settings/SI-ProSettings.ps1')
        Donors = @('caj-si-asset-datasync', 'caj-si-close-loop-mail', 'caj-si-asset-cmdb-sql', 'caj-si-asset-correlation', 'caj-si-verification')
        What   = 'the Invardia support link'
        Cron   = '7,22,37,52 * * * *'
        ShippedCrons = @('7 * * * *')
        OwnSize = $true
        ScheduleSetting = 'SI_Bootstrap_ScheduleHeartbeat'
    }
    # the users' sign-in methods read in the background (owner 2026-11-05: "same with caching as sep job") -- its OWN timer every
    # 15 minutes (never a step: neverInFlow in the map), the floor size and the status report's short run limit (OwnSize), the
    # engine identity of the donor (it holds UserAuthenticationMethod.Read.All). Every install with its code gets it; the
    # setting SI_Identity_SignInMethodsPerUser 'off' makes each run end at once.
    [pscustomobject]@{
        Engine = 'signin-methods'; Code = @('engine/signin-methods/Invoke-SISignInMethods.ps1', 'engine/asset-profiling/shared/SI-SignInMethodsChoice.ps1')
        Donors = @('caj-si-heartbeat', 'caj-si-asset-datasync', 'caj-si-close-loop-mail', 'caj-si-asset-cmdb-sql', 'caj-si-verification')
        What   = 'the background read of the users'' sign-in methods'
        Cron   = '3,18,33,48 * * * *'
        OwnSize = $true
    }
    # #1038 (1): the data-out job (the ServiceNow hand-off and the other outputs) -- MANUAL in both orchestration modes (the
    # map's manualOnly): the data sync starts it the moment it has stored the findings per CI, and a person starts it to
    # resend. Until it exists the install's data sync sends data out itself, so an install without it loses nothing.
    [pscustomobject]@{
        Engine = 'data-out'; Code = @('engine/data-out/Invoke-SIDataOutJob.ps1', 'engine/pro-data/Invoke-SIDataSync.ps1')
        Donors = @('caj-si-asset-datasync', 'caj-si-close-loop-mail', 'caj-si-asset-cmdb-sql', 'caj-si-asset-correlation', 'caj-si-verification')
        What   = 'the data-out job (the ServiceNow hand-off and the other outputs, started by the data sync)'
    }
    # #1021: the support grant job -- never a timer, never a step (the map's manualOnly); #1154: STARTED BY ITS QUEUE
    # si-support-requests (event trigger, the scaler signed in as the engine identity -- Get-SIMissingJobSpec), where the
    # Invardia Support session puts its request; the Support app holds no right on the job. The engine identity, the floor size, its own
    # short run limit (OwnSize: a donor's 7-day limit would hold a support request for days). The queue it reads is made by
    # the update's support grant step (setup\Invoke-SIContainerUpdate.ps1).
    # owner 2026-11-11 (every install tiers from a CURRENT classified catalog): the privilege tier classifier -- in earlier versions an
    # install without Azure OpenAI was made WITHOUT it (Select-SIBootstrapEngines left it out), so it never downloaded the daily
    # classified catalog and stayed on the shipped one. Every install with the download code gets it now, built from a
    # collection job of the install (same engine identity: Graph role definitions, ARM role definitions, the storage account).
    # A step of the pipeline (stage collect): in flow mode it is made MANUAL with its timer remembered, as Bootstrap does.
    [pscustomobject]@{
        Engine = 'privilege-tier-classifier'; Code = @('engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1', 'engine/_shared/SI-TierCatalogDownload.ps1')
        Donors = @('caj-si-identity', 'caj-si-identity-producer', 'caj-si-azure', 'caj-si-azure-producer', 'caj-si-endpoint', 'caj-si-publicip', 'caj-si-asset-correlation', 'caj-si-asset-datasync')
        What   = 'the privilege tier classifier (the tier catalog: built with AI, or the daily classified catalog downloaded)'
    }
    [pscustomobject]@{
        Engine = 'support-grant'; Code = @('engine/support-grant/Invoke-SISupportGrant.ps1', 'engine/pro-settings/SI-SupportGrantSql.ps1')
        Donors = @('caj-si-heartbeat', 'caj-si-asset-datasync', 'caj-si-close-loop-mail', 'caj-si-asset-cmdb-sql', 'caj-si-verification')
        What   = 'the support grant job (the Invardia Support app''s database access, just in time)'
        OwnSize = $true
    }
)

# Env a donor carries for ITS engine only -- never copied to a job of another engine.
# #986: SI_CFG_SI_Pipeline_StartTime / _TimeZone too -- only the pipeline runner reads them (never a job made here), and on a
# Pro install the database is their one source: a copy in a new job's environment is a stale copy waiting to mislead
$script:SIMissingJobDonorOnlyEnv = '^(SI_ENGINE|SI_SHARD_COUNT|SI_ROLE|SI_VULN_TARGET|SI_FLOW_SUBSCRIPTIONID|SI_FLOW_RESOURCEGROUP|SI_TRIGGER_FROM_QUEUE|SI_QUEUE_LEASE_SECONDS|SI_QUEUE_NAME|SMTP_PASSWORD|SHODAN_API_KEY|SI_RA_[A-Z0-9_]+|SI_CFG_SI_Pipeline_StartTime|SI_CFG_SI_Pipeline_TimeZone)='

# 2026-10-22 (review B1): a secret an EXISTING job needs and only another kind of job carries -- the data sync sends the Risk
# Analysis Detailed mail with its stored Protection Score (engine\_shared\data-sql\SI-RaMailOutbox.ps1), so it needs the SMTP
# relay password as the mail jobs have it. A new install gets it from Bootstrap; an existing one from the update
# (Invoke-SIJobSecretBorrow): the Key Vault reference (or value) under the same name, from the first of From that has it.
$script:SIJobBorrowCatalog = @(
    [pscustomobject]@{ Job = 'caj-si-asset-datasync'; Secret = 'smtp-password'; Env = 'SMTP_PASSWORD'
                       From = @('caj-si-risk-analysis-detailed', 'caj-si-risk-analysis', 'caj-si-close-loop-mail')
                       What = 'the data sync (it sends the Risk Analysis Detailed mail with its stored Protection Score)' }
)

function Get-SIJobBorrowPatch {
    <#
        PURE. The PATCH that gives an EXISTING job a secret it lacks and the env var that reads it -- or Action present when it
        has both. -Job: the job as ARM returns it; -Secrets: the job's own secrets with their values (listSecrets: name + value,
        or keyVaultUrl + identity); -Borrowed: the secret to add (the same shape). The secrets list and the containers are
        sent whole (ARM replaces an array): every secret of the job is kept, the env var is added (or set) on every container.
        Returns @{ Action = present | patch; Body }.
    #>
    param([Parameter(Mandatory)]$Job, [AllowEmptyCollection()][object[]]$Secrets = @(), $Borrowed, [Parameter(Mandatory)][string]$Secret, [Parameter(Mandatory)][string]$Env)
    $cfg = Get-SIKedaConvertProp $Job @('properties', 'configuration')
    $tpl = Get-SIKedaConvertProp $Job @('properties', 'template')
    $containers = @(Get-SIKedaConvertProp $tpl @('containers') | Where-Object { $_ })
    $hasSecret = @(Get-SIKedaConvertProp $cfg @('secrets') | Where-Object { $_ -and [string](Get-SIKedaConvertProp $_ @('name')) -eq $Secret }).Count -gt 0
    $hasEnv = $containers.Count -gt 0 -and @($containers | Where-Object { @(Get-SIKedaConvertProp $_ @('env') | Where-Object { $_ -and [string](Get-SIKedaConvertProp $_ @('name')) -eq $Env -and [string](Get-SIKedaConvertProp $_ @('secretRef')) -eq $Secret }).Count -eq 0 }).Count -eq 0
    if ($hasSecret -and $hasEnv) { return [pscustomobject]@{ Action = 'present'; Body = $null } }
    $sec = New-Object System.Collections.Generic.List[object]
    $one = {
        param($s)
        $n = [string](Get-SIKedaConvertProp $s @('name')); $kvu = [string](Get-SIKedaConvertProp $s @('keyVaultUrl'))
        if ($kvu) { $o = [ordered]@{ name = $n; keyVaultUrl = $kvu }; $id = [string](Get-SIKedaConvertProp $s @('identity')); if ($id) { $o.identity = $id }; return $o }
        [ordered]@{ name = $n; value = [string](Get-SIKedaConvertProp $s @('value')) }
    }
    foreach ($s in @($Secrets | Where-Object { $_ })) { if ([string](Get-SIKedaConvertProp $s @('name')) -ne $Secret) { $sec.Add((& $one $s)) } }
    if ($null -ne $Borrowed) { $b = & $one $Borrowed; $b.name = $Secret; $sec.Add($b) }
    $c = [ordered]@{ triggerType = [string](Get-SIKedaConvertProp $cfg @('triggerType')) }
    foreach ($k in 'replicaTimeout', 'replicaRetryLimit', 'scheduleTriggerConfig', 'manualTriggerConfig', 'eventTriggerConfig') { $v = Get-SIKedaConvertProp $cfg @($k); if ($null -ne $v) { $c[$k] = $v } }
    $c.secrets = $sec.ToArray()
    $newContainers = foreach ($ct in $containers) {
        $copy = [ordered]@{}; foreach ($p in $ct.PSObject.Properties) { $copy[$p.Name] = $p.Value }
        # (not "$env": that name is the environment drive -- a list assigned to it comes back as text)
        $newEnv = @(@(Get-SIKedaConvertProp $ct @('env') | Where-Object { $_ -and [string](Get-SIKedaConvertProp $_ @('name')) -ne $Env }) + @([ordered]@{ name = $Env; secretRef = $Secret }))
        $copy['env'] = $newEnv
        $copy
    }
    $t = [ordered]@{}; foreach ($p in $tpl.PSObject.Properties) { $t[$p.Name] = $p.Value }
    $t['containers'] = @($newContainers)
    [pscustomobject]@{ Action = 'patch'; Body = [ordered]@{ properties = [ordered]@{ configuration = $c; template = $t } } }
}

function Invoke-SIJobSecretBorrow {
    <#
        EXISTING INSTALLS (review B1, 2026-10-22): every job of $script:SIJobBorrowCatalog that is there and lacks its secret
        gets it from the first job of From that carries it (listSecrets: the Key Vault reference, or the value), with the env
        var that reads it -- one PATCH, then read back. No job carries the secret (a shared mailbox, an anonymous relay) =
        nothing to do. -WhatIf: the plan only. Returns @{ Results = @(@{ Job; Action = present | none | would-add | added |
        failed; Line }); Lines }. NEVER throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [object[]]$Jobs = @(), [switch]$WhatIf, [object[]]$Catalog = $script:SIJobBorrowCatalog, [int]$PollSeconds = 5, [int]$PollMax = 36)
    $results = New-Object System.Collections.Generic.List[object]
    $lines = New-Object System.Collections.Generic.List[string]
    $add = { param($j, $a, $l) $results.Add([pscustomobject]@{ Job = $j; Action = $a; Line = $l }); if ($l) { $lines.Add($l) } }
    try {
        $arm = 'https://management.azure.com/'
        $call = {
            param([string]$Method, [string]$Uri, $Body)
            $r = $null
            try { $r = & $Rest $Method $Uri $Body $arm @{ 'Content-Type' = 'application/json' } } catch { $r = [pscustomobject]@{ Status = 0; Body = $_.Exception.Message } }
            if (-not $r) { $r = [pscustomobject]@{ Status = 0; Body = 'no answer' } }
            $r
        }
        $isOk = { param($r) $r -and [int]$r.Status -ge 200 -and [int]$r.Status -lt 300 }
        $parse = { param($r) if (-not $r -or -not "$($r.Body)".Trim()) { return $null }; $o = $null; try { $o = ("$($r.Body)" | ConvertFrom-Json) } catch { $o = $null }; return $o }
        $why = { param($r) $t = ("$(if ($r) { $r.Body })" -replace '\s+', ' ').Trim(); if ($t.Length -gt 300) { $t = $t.Substring(0, 297) + '...' }; ('HTTP {0}{1}' -f $(if ($r) { [int]$r.Status } else { 0 }), $(if ($t) { ": $t" } else { '' })) }
        $jobUri = { param($n, [string]$Action) 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}{3}?api-version={4}' -f $SubscriptionId, $ResourceGroup, $n, $Action, $script:SIMissingJobsArmApi }
        $secretsOf = { param($n) $r = & $call 'POST' (& $jobUri $n '/listSecrets') $null; if (-not (& $isOk $r)) { return @{ Ok = $false; Why = (& $why $r); Value = @() } }; @{ Ok = $true; Value = @(Get-SIKedaConvertProp (& $parse $r) @('value') | Where-Object { $_ }) } }
        foreach ($row in @($Catalog)) {
            $target = @($Jobs | Where-Object { $_ -and [string](Get-SIKedaConvertProp $_ @('name')) -eq $row.Job })[0]
            if (-not $target) { & $add $row.Job 'none' ''; continue }
            $g = & $call 'GET' (& $jobUri $row.Job) $null
            $job = if (& $isOk $g) { & $parse $g } else { $target }
            $pre = Get-SIJobBorrowPatch -Job $job -Secret $row.Secret -Env $row.Env -Secrets @() -Borrowed $null
            if ($pre.Action -eq 'present') { & $add $row.Job 'present' ''; continue }
            $src = $null
            foreach ($fn in @($row.From)) {
                $cand = @($Jobs | Where-Object { $_ -and [string](Get-SIKedaConvertProp $_ @('name')) -eq $fn })[0]
                if ($cand -and @(Get-SIKedaConvertProp $cand @('properties', 'configuration', 'secrets') | Where-Object { $_ -and [string](Get-SIKedaConvertProp $_ @('name')) -eq $row.Secret }).Count) { $src = $fn; break }
            }
            if (-not $src) { & $add $row.Job 'none' ''; continue }
            if ($WhatIf) { & $add $row.Job 'would-add' ('job secrets: {0} ({1}) would get {2} from {3} (re-run with -Apply)' -f $row.Job, $row.What, $row.Env, $src); continue }
            $ss = & $secretsOf $src
            $b = @($ss.Value | Where-Object { [string](Get-SIKedaConvertProp $_ @('name')) -eq $row.Secret })[0]
            if (-not $ss.Ok -or -not $b) { & $add $row.Job 'failed' ('job secrets: {0} did NOT get {1} -- the secret of {2} could not be read ({3}); the next update tries again' -f $row.Job, $row.Env, $src, $ss.Why); continue }
            $ts = @{ Ok = $true; Value = @() }
            if (@(Get-SIKedaConvertProp $job @('properties', 'configuration', 'secrets') | Where-Object { $_ }).Count) { $ts = & $secretsOf $row.Job }
            if (-not $ts.Ok) { & $add $row.Job 'failed' ('job secrets: {0} did NOT get {1} -- its own secrets could not be read ({2}); the next update tries again' -f $row.Job, $row.Env, $ts.Why); continue }
            $plan = Get-SIJobBorrowPatch -Job $job -Secrets @($ts.Value) -Borrowed $b -Secret $row.Secret -Env $row.Env
            $r = & $call 'PATCH' (& $jobUri $row.Job) (ConvertTo-Json -InputObject $plan.Body -Depth 30 -Compress)
            if (-not (& $isOk $r)) { & $add $row.Job 'failed' ('job secrets: {0} did NOT get {1} ({2}) -- the next update tries again' -f $row.Job, $row.Env, (& $why $r)); continue }
            $done = $false
            for ($k = 1; $k -le [Math]::Max(1, $PollMax); $k++) {
                $gg = & $call 'GET' (& $jobUri $row.Job) $null
                $jj = if (& $isOk $gg) { & $parse $gg } else { $null }
                $ps = [string](Get-SIKedaConvertProp $jj @('properties', 'provisioningState'))
                if ($jj -and (Get-SIJobBorrowPatch -Job $jj -Secret $row.Secret -Env $row.Env).Action -eq 'present' -and (-not $ps -or $ps -eq 'Succeeded')) { $done = $true; break }
                if ($jj -and $ps -in @('Failed', 'Canceled')) { break }
                if ($k -lt $PollMax -and $PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
            }
            if (-not $done) { & $add $row.Job 'failed' ('job secrets: {0} did NOT get {1} (read back) -- the next update tries again' -f $row.Job, $row.Env); continue }
            & $add $row.Job 'added' ('job secrets: {0} ({1}) got {2} from {3} and read back' -f $row.Job, $row.What, $row.Env, $src)
        }
    } catch {
        $lines.Add(('job secrets: not checked ({0}) -- the update goes on; the next update tries again' -f $_.Exception.Message))
    }
    [pscustomobject]@{ Results = $results.ToArray(); Lines = $lines.ToArray() }
}

function Get-SIMissingJobMode {
    <#
        PURE. The install's orchestration mode as the jobs show it: 'flow' when caj-si-flow is on its timer, 'schedules'
        when there is no caj-si-flow or it waits while a job of the pipeline (here: the donor) runs on its own timer;
        otherwise 'flow' (the update's pipeline-schedule step puts an install in neither mode back to the pipeline).
    #>
    param([object[]]$Jobs = @(), $Donor)
    $flow = @($Jobs | Where-Object { $_ -and [string](Get-SIKedaConvertProp $_ @('name')) -eq 'caj-si-flow' })[0]
    if (-not $flow) { return 'schedules' }
    if ([string](Get-SIKedaConvertProp $flow @('properties', 'configuration', 'triggerType')) -eq 'Schedule') { return 'flow' }
    if ($Donor -and [string](Get-SIKedaConvertProp $Donor @('properties', 'configuration', 'triggerType')) -eq 'Schedule') { return 'schedules' }
    'flow'
}

function Get-SIMissingJobConnectorSql {
    <# PURE. #715: the ServiceNow connectors of the Pro database (Kind, Direction) -- read only; a database without the
       table (schema not updated yet) reads as no rows. #>
    @'
IF OBJECT_ID('cfg.Connector') IS NOT NULL
SELECT LOWER(LTRIM(RTRIM(Kind))) AS Kind, LOWER(LTRIM(RTRIM(Direction))) AS Direction FROM cfg.Connector WHERE LOWER(LTRIM(RTRIM(Kind))) = 'servicenow'
'@
}

function Get-SIMissingJobConditions {
    <#
        PURE. #715: whether this install uses what a job of the catalog exists for (its When). Today: the two ServiceNow
        jobs -- ServiceNowVulnerabilities (caj-si-asset-vulns-servicenow) and ServiceNowCmdb (caj-si-asset-cmdb). On when a
        ServiceNow connector of that direction is in the Pro database (-Connectors: the cfg.Connector rows, Kind +
        Direction -- what the web app's Connectors and Get Started pages write), or the setting Bootstrap reads says so
        (Get-SIServiceNowJobPlan: SI_VulnSync_Target = 'ServiceNow', SI_Bootstrap_ServiceNowVulnerabilities, ...).
        Returns @{ <When> = @{ On; Why } }.
    #>
    param([hashtable]$Globals = @{}, [object[]]$Connectors = @())
    $plan = Get-SIServiceNowJobPlan -Globals $Globals
    $count = {
        param([string]$Direction)
        @(@($Connectors) | Where-Object { $_ -and ([string](Get-SIKedaConvertProp $_ @('Kind'))).Trim() -ieq 'servicenow' -and ([string](Get-SIKedaConvertProp $_ @('Direction'))).Trim() -ieq $Direction }).Count
    }
    $out = @{}
    foreach ($d in @(@{ When = 'ServiceNowVulnerabilities'; Direction = 'vulnerability'; Plan = $plan.Vulnerabilities; Kind = 'vulnerability' },
                     @{ When = 'ServiceNowCmdb'; Direction = 'cmdb'; Plan = $plan.Cmdb; Kind = 'CMDB' })) {
        $n = & $count $d.Direction
        $on = ($n -gt 0) -or [bool]$d.Plan.Deploy
        $why = if ($n -gt 0) { 'a ServiceNow {0} connector is configured' -f $d.Kind } elseif ($d.Plan.Deploy) { [string]$d.Plan.Why } else { 'no ServiceNow {0} connector is configured' -f $d.Kind }
        $out[$d.When] = [pscustomobject]@{ On = $on; Why = $why }
    }
    $out
}

function Get-SIMissingJobPlan {
    <#
        PURE. Per job of the catalog: create | present | keep (Reason says why, in plain words) | none (this tree does not
        carry the engine, or -- #715 -- the install does not use what the job is for: its When is not On in -Conditions,
        Get-SIMissingJobConditions; no conditions given = not used). -Jobs: the job list (ARM shape). -Root: the solution
        root (the code must be there). Returns @(@{ Engine; Job; Action; Reason; Donor; What }).
    #>
    param([object[]]$Jobs = @(), [Parameter(Mandatory)][string]$Root, [object[]]$Catalog = $script:SIMissingJobCatalog, [hashtable]$Conditions = @{})
    $byName = @{}
    foreach ($j in @($Jobs)) { if ($j) { $n = [string](Get-SIKedaConvertProp $j @('name')); if ($n) { $byName[$n.ToLowerInvariant()] = $j } } }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($Catalog)) {
        $name = Get-SIBootstrapJobName -Engine $c.Engine
        $row = [ordered]@{ Engine = $c.Engine; Job = $name; Action = 'keep'; Reason = ''; Donor = $null; What = $c.What
                           Borrow = $(if ($c.PSObject.Properties['Borrow']) { @($c.Borrow) } else { @() })
                           CronSetting = $(if ($c.PSObject.Properties['CronSetting']) { [string]$c.CronSetting } else { '' })
                           ScheduleSetting = $(if ($c.PSObject.Properties['ScheduleSetting']) { [string]$c.ScheduleSetting } else { '' })
                           Cron = $(if ($c.PSObject.Properties['Cron']) { [string]$c.Cron } else { '' })
                           OwnSize = [bool]($c.PSObject.Properties['OwnSize'] -and $c.OwnSize)
                           # #723: the timers an earlier version shipped (an existing job on one moves to Cron); the job as it is
                           ShippedCrons = $(if ($c.PSObject.Properties['ShippedCrons']) { @($c.ShippedCrons) } else { @() }); Existing = $null }
        $missingCode = @(@($c.Code) | Where-Object { -not (Test-Path -LiteralPath (Join-Path $Root (([string]$_).Replace('/', [IO.Path]::DirectorySeparatorChar)))) })
        if ($missingCode.Count) { $row.Action = 'none'; $row.Reason = ('this version does not carry it ({0})' -f ($missingCode -join ', ')); $rows.Add([pscustomobject]$row); continue }
        if ($byName.ContainsKey($name)) { $row.Action = 'present'; $row.Reason = 'exists'; $row.Existing = $byName[$name]; $rows.Add([pscustomobject]$row); continue }
        # #715: a job only some installs need (the ServiceNow connectors) -- only where the install uses it
        $when = if ($c.PSObject.Properties['When']) { [string]$c.When } else { '' }
        if ($when) {
            $cond = if ($Conditions -and $Conditions.ContainsKey($when)) { $Conditions[$when] } else { $null }
            if (-not $cond -or -not [bool]$cond.On) {
                $row.Action = 'none'; $row.Reason = $(if ($cond -and "$($cond.Why)".Trim()) { [string]$cond.Why } else { 'not used at this install' })
                $rows.Add([pscustomobject]$row); continue
            }
        }
        $donor = $null; $why = ''
        foreach ($d in @($c.Donors)) {
            $j = $byName[$d.ToLowerInvariant()]
            if (-not $j) { continue }
            $tt = [string](Get-SIKedaConvertProp $j @('properties', 'configuration', 'triggerType'))
            if (-not (Test-SIBootstrapJobIsSI -Job $j)) { if (-not $why) { $why = ('{0} was not made by SecurityInsight''s setup (no si-build tag)' -f $d) }; continue }
            if ($tt -notin @('Schedule', 'Manual')) { if (-not $why) { $why = ('{0} is not a scheduled or manual job ({1})' -f $d, $(if ($tt) { $tt } else { 'no trigger' })) }; continue }
            $c0 = @(Get-SIKedaConvertProp $j @('properties', 'template', 'containers') | Where-Object { $_ })[0]
            if (-not $c0 -or -not [string](Get-SIKedaConvertProp $c0 @('image'))) { if (-not $why) { $why = ('{0} has no image to read' -f $d) }; continue }
            if (-not [string](Get-SIKedaConvertProp $j @('properties', 'environmentId'))) { if (-not $why) { $why = ('the Container Apps environment of {0} could not be read' -f $d) }; continue }
            $donor = $j; break
        }
        if (-not $donor) {
            $row.Reason = $(if ($why) { $why } else { 'no Pro job to build it from ({0}) -- run the container setup (Bootstrap-ContainerAppJob.ps1) to create it' -f (@($c.Donors) -join ', ') })
            $rows.Add([pscustomobject]$row); continue
        }
        $row.Action = 'create'; $row.Donor = $donor; $row.Reason = ('built from {0}' -f [string](Get-SIKedaConvertProp $donor @('name')))
        $rows.Add([pscustomobject]$row)
    }
    $rows.ToArray()
}

function Get-SIMissingJobSpec {
    <#
        PURE. The new job from its donor, as Bootstrap would create it (the az create arguments, translated to the ARM
        resource by ConvertFrom-SIJobCreateArgs). -SecretArgs: name=value / name=keyvaultref:<url>,identityref:<id> for
        the donor's secrets (the registry password excluded -- -RegistryPassword). -Mode: flow | schedules (the trigger,
        Get-SIBootstrapTriggerPlan). -Cron: the job's own timer (default: the map's defaultCron). -ExtraEnv: NAME=value /
        NAME=secretref:<secret> this job needs beyond the donor's (#714: the mail job's SMTP_PASSWORD, borrowed).
        Returns @{ Name; Args; Body; Image; Trigger; Cron; EnvArgs }.
    #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)]$Donor, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][ValidateSet('flow', 'schedules')][string]$Mode, [string]$Cron, [object[]]$SecretArgs = @(),
          [string]$RegistryPassword, [hashtable]$Globals = @{}, $Map, [string[]]$ExtraEnv = @(),
          # #718: the job's own size and run limit (Get-SIContainerJobResources), never raised to the donor's
          [switch]$OwnSize)
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $name = Get-SIBootstrapJobName -Engine $Engine
    $key = $name.Substring(7)
    if (-not $Cron) { $Cron = $(if ($Map.Jobs.Contains($key) -and $Map.Jobs[$key].DefaultCron) { [string]$Map.Jobs[$key].DefaultCron } else { '0 11 * * *' }) }
    $c = @(Get-SIKedaConvertProp $Donor @('properties', 'template', 'containers') | Where-Object { $_ })[0]
    $image = [string](Get-SIKedaConvertProp $c @('image'))
    $cfg = Get-SIKedaConvertProp $Donor @('properties', 'configuration')
    # the env: the donor's settings and sign-in, without what only its engine needs; this job's own SI_ENGINE / one replica / role
    $donorEnv = @(ConvertTo-SIKedaConvertEnvArgs -Env @(Get-SIKedaConvertProp $c @('env')))
    $jobEnv = Get-SIBootstrapJobEnvArgs -Engine $Engine
    $env = @(@(('SI_ENGINE=' + $jobEnv.SiEngine), 'SI_SHARD_COUNT=1') + @($donorEnv | Where-Object { [string]$_ -notmatch $script:SIMissingJobDonorOnlyEnv }) + @($jobEnv.EnvArgs) + @($ExtraEnv | Where-Object { $_ }) + @('SI_ROLE=worker'))
    # the secrets: only those the env still refers to (and the registry password, handled with the registry)
    $refs = @($env | ForEach-Object { $p = ([string]$_) -split '=', 2; if ($p.Count -eq 2 -and $p[1].StartsWith('secretref:')) { $p[1].Substring(10) } })
    $secrets = @(@($SecretArgs) | Where-Object { $refs -contains ((([string]$_) -split '=', 2)[0]) })
    # the size: Bootstrap's for this engine (a size the customer set wins), never below the donor's (the job floor raised it)
    $res = Get-SIContainerJobResources -Engine $Engine -Kind 'Schedule' -Globals $Globals
    if (-not $OwnSize) { $res = Get-SIJobResourcesNeverLower -Resources $res -ExistingJob $Donor -Engine $Engine -Globals $Globals }
    $timeout = [int]$res.ReplicaTimeout
    $dTo = [int](Get-SIKedaConvertProp $cfg @('replicaTimeout')); if ($dTo -gt $timeout -and -not $OwnSize) { $timeout = $dTo }
    # the registry, as the donor pulls
    $reg = @(Get-SIKedaConvertProp $cfg @('registries') | Where-Object { $_ })[0]
    $login = [string](Get-SIKedaConvertProp $reg @('server')); if (-not $login) { $login = ($image -split '/')[0] }
    $regArgs = @()
    $regIdentity = [string](Get-SIKedaConvertProp $reg @('identity')); $regUser = [string](Get-SIKedaConvertProp $reg @('username'))
    if ($regIdentity) { $regArgs = @(Get-SIRegistryPullArgs -Mode 'ManagedIdentity' -IdentityResourceId $regIdentity) }
    elseif ($regUser -and $RegistryPassword) { $regArgs = @('--registry-username', $regUser, '--registry-password', $RegistryPassword) }
    # the identities the donor carries (the sign-in and the registry pull)
    $ua = Get-SIKedaConvertProp $Donor @('identity', 'userAssignedIdentities')
    $mi = @(); if ($ua) { if ($ua -is [System.Collections.IDictionary]) { $mi = @($ua.Keys | ForEach-Object { [string]$_ }) } else { $mi = @($ua.PSObject.Properties | ForEach-Object { $_.Name }) } }
    # the trigger, as Bootstrap gives a NEW job
    $trig = Get-SIBootstrapTriggerPlan -Engine $Engine -Mode $Mode -Cron $Cron -Map $Map
    $a = @('containerapp', 'job', 'create', '--name', $name, '--resource-group', $ResourceGroup, '--environment', [string](Get-SIKedaConvertProp $Donor @('properties', 'environmentId')),
           '--trigger-type', 'Schedule', '--replica-timeout', "$timeout", '--replica-retry-limit', (Get-SIJobRetryLimitArg -Name $name), '--replica-completion-count', '1', '--parallelism', '1',
           '--cron-expression', $Cron, '--image', $image, '--registry-server', $login, '--cpu', [string]$res.Cpu, '--memory', [string]$res.Memory, '--output', 'none')
    if ($trig.Trigger -eq 'Manual') { $a = ConvertTo-SIManualCreateArgs -CreateArgs $a -RememberCron '' }   # assigned as it comes (leading comma)
    $tags = @()
    $build = [string](Get-SIKedaConvertProp $Donor @('tags', 'si-build')); if ($build) { $tags += "si-build=$build" }
    if ($trig.Trigger -eq 'Manual' -and $trig.RememberCron) { $tags += "si-disabled-cron=$($trig.RememberCron)" }
    $a = @($a) + $regArgs
    if ($tags.Count) { $a += @('--tags') + $tags }
    if ($mi.Count) { $a += @('--mi-user-assigned') + $mi }
    if ($secrets.Count) { $a += @('--secrets') + $secrets }
    $a += @('--env-vars') + $env
    # #1154 (framework §5.5): the support grant job is STARTED BY ITS QUEUE (the scaler signed in as the engine identity, the
    # donor's sign-in identity) -- as Bootstrap gives a new install. Without a storage account or that identity it is made
    # manual and the update's support step converts it once it can (and says why until then).
    $trigger = $trig.Trigger
    if ($Engine -eq 'support-grant') {
        if (-not (Get-Command -Name Select-SISupportGrantJobIdentity -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-SupportGrantUpdate.ps1') }
        $sgId = Select-SISupportGrantJobIdentity -Job $Donor
        try { $a = @(ConvertTo-SISupportGrantEventCreateArgs -CreateArgs $a -StorageAccount (Get-SIKedaConvertEnvValue -EnvArgs $env -Name 'SI_STORAGE_ACCOUNT') -IdentityResourceId $sgId); $trigger = 'Event' } catch { $trigger = $trig.Trigger }
    }
    $location = [string](Get-SIKedaConvertProp $Donor @('location'))
    [pscustomobject]@{ Name = $name; Args = $a; Body = (ConvertFrom-SIJobCreateArgs -CreateArgs $a -Location $location).Body; Image = $image
                       Trigger = $trigger; Cron = $Cron; EnvArgs = $env
                       # #1038 (1): Manual with no timer remembered = a job that is only ever started (the data-out job)
                       RememberCron = [string]$trig.RememberCron }
}

function Test-SIMissingJobManualOnly {
    <# PURE. #1038 (1): is the engine's job only ever STARTED (the job map's 'manualOnly': the data-out job)? #>
    param([Parameter(Mandatory)][string]$Engine, $Map)
    if (-not $Map) { return $false }
    $k = (Get-SIBootstrapJobName -Engine $Engine).Substring(7)
    [bool]($Map.Jobs.Contains($k) -and $Map.Jobs[$k].PSObject.Properties['ManualOnly'] -and $Map.Jobs[$k].ManualOnly)
}

function Get-SIMissingJobRetime {
    <#
        PURE. #723: an EXISTING job of the catalog still on a timer an earlier version shipped -> the PATCH that moves it to
        the timer this version ships. -Job: the job as ARM returns it; -Cron: this version's timer; -ShippedCrons: the earlier
        shipped timers; -Setting: the customer's own timer setting (SI_Bootstrap_Schedule<Engine>) -- set = never touched.
        Returns @{ Action = retime | keep | none; Cron (the job's timer now); Body (the PATCH: the trigger only -- triggerType,
        the job's run limit, the new cron, its parallelism and completion count); Why }.
          retime  on a shipped timer (whitespace ignored), a Schedule trigger, no timer setting of the customer's
          keep    a timer the customer chose (another cron, or the setting is set) -- never touched
          none    already on this version's timer, or not a timer job (a manual / event job is left as it is)
    #>
    param([Parameter(Mandatory)]$Job, [Parameter(Mandatory)][string]$Cron, [string[]]$ShippedCrons = @(), [AllowNull()][AllowEmptyString()][string]$Setting = '')
    $norm = { param($c) (("$c").Trim() -replace '\s+', ' ') }
    $cfg = Get-SIKedaConvertProp $Job @('properties', 'configuration')
    $tt = [string](Get-SIKedaConvertProp $cfg @('triggerType'))
    $cur = [string](Get-SIKedaConvertProp $cfg @('scheduleTriggerConfig', 'cronExpression'))
    $res = { param($a, $b, $w) [pscustomobject]@{ Action = $a; Cron = $cur; Body = $b; Why = $w } }
    if ($tt -ne 'Schedule') { return (& $res 'none' $null 'not on a timer') }
    if ((& $norm $cur) -eq (& $norm $Cron)) { return (& $res 'none' $null 'already on this version''s timer') }
    if ("$Setting".Trim()) { return (& $res 'keep' $null 'its timer is set by the install''s own setting') }
    if (-not @(@($ShippedCrons) | Where-Object { (& $norm $_) -eq (& $norm $cur) }).Count) { return (& $res 'keep' $null ('a timer of your own (''{0}'') -- kept' -f $cur)) }
    $par = Get-SIKedaConvertProp $cfg @('scheduleTriggerConfig', 'parallelism'); if (-not $par) { $par = 1 }
    $rcc = Get-SIKedaConvertProp $cfg @('scheduleTriggerConfig', 'replicaCompletionCount'); if (-not $rcc) { $rcc = 1 }
    $c = [ordered]@{ triggerType = 'Schedule' }
    $to = Get-SIKedaConvertProp $cfg @('replicaTimeout'); if ($to) { $c.replicaTimeout = $to }
    $c.scheduleTriggerConfig = [ordered]@{ cronExpression = $Cron; parallelism = $par; replicaCompletionCount = $rcc }
    & $res 'retime' ([ordered]@{ properties = [ordered]@{ configuration = $c } }) ('from ''{0}'' to ''{1}''' -f $cur, $Cron)
}

function Test-SIMissingJobReadBack {
    <# PURE. The new job as Azure returned it: created (provisioning succeeded), on the image, SI_ENGINE set, the planned
       trigger. Returns '' (good) or what is wrong. #>
    param($Job, [Parameter(Mandatory)]$Spec, [Parameter(Mandatory)][string]$Engine)
    if (-not $Job) { return 'it could not be read back' }
    $ps = [string](Get-SIKedaConvertProp $Job @('properties', 'provisioningState'))
    if ($ps -and $ps -ne 'Succeeded') { return ('it was not created (provisioning {0})' -f $ps) }
    $c = @(Get-SIKedaConvertProp $Job @('properties', 'template', 'containers') | Where-Object { $_ })[0]
    $img = [string](Get-SIKedaConvertProp $c @('image'))
    if ($img -ne $Spec.Image) { return ('it runs {0}, not {1}' -f $img, $Spec.Image) }
    $envArgs = @(ConvertTo-SIKedaConvertEnvArgs -Env @(Get-SIKedaConvertProp $c @('env')))
    # what makes the job THE job (Get-SIBootstrapJobEnvArgs): its SI_ENGINE, and e.g. the ServiceNow vulnerability job's
    # SI_VULN_TARGET=ServiceNow (#715: its SI_ENGINE is asset-vulnerabilities, not its catalog name)
    $want = Get-SIBootstrapJobEnvArgs -Engine $Engine
    $eng = Get-SIKedaConvertEnvValue -EnvArgs $envArgs -Name 'SI_ENGINE'
    if ($eng -ne $want.SiEngine) { return ('its SI_ENGINE is ''{0}'', not ''{1}''' -f $eng, $want.SiEngine) }
    foreach ($ea in @($want.EnvArgs)) {
        $p = ([string]$ea) -split '=', 2
        if ($p.Count -ne 2 -or -not $p[1]) { continue }
        $got = Get-SIKedaConvertEnvValue -EnvArgs $envArgs -Name $p[0]
        if ($got -ne $p[1]) { return ('its {0} is ''{1}'', not ''{2}''' -f $p[0], $got, $p[1]) }
    }
    $tt = [string](Get-SIKedaConvertProp $Job @('properties', 'configuration', 'triggerType'))
    if ($tt -ne $Spec.Trigger) { return ('its trigger is {0}, not {1}' -f $(if ($tt) { $tt } else { 'unknown' }), $Spec.Trigger) }
    ''
}

function Invoke-SIMissingJobs {
    <#
        EXISTING INSTALLS: create every job of the catalog that this version needs and the install does not have (the plan:
        Get-SIMissingJobPlan). -Jobs: the job list (ARM shape). -Rest: the REST seam (ARM, https://management.azure.com/).
        -WhatIf: the plan only, no call. -Conditions: what the install uses (#715, Get-SIMissingJobConditions; not given =
        from -Globals alone). Returns @{ Results = @(@{ Engine; Job; Action = created | would-create | present | keep |
        none | failed; Line }); Lines }. NEVER throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$Root, [object[]]$Jobs = @(), [hashtable]$Globals = @{}, [switch]$WhatIf,
          [object[]]$Catalog = $script:SIMissingJobCatalog, [int]$PollSeconds = 5, [int]$PollMax = 36, [hashtable]$Conditions)
    $results = New-Object System.Collections.Generic.List[object]
    $lines = New-Object System.Collections.Generic.List[string]
    $add = { param($r, $a, $l) $results.Add([pscustomobject]@{ Engine = $r.Engine; Job = $r.Job; Action = $a; Line = $l }); if ($l) { $lines.Add($l) } }
    try {
        if ($null -eq $Conditions) { $Conditions = Get-SIMissingJobConditions -Globals $Globals }
        $plan = @(Get-SIMissingJobPlan -Jobs $Jobs -Root $Root -Catalog $Catalog -Conditions $Conditions)
        $arm = 'https://management.azure.com/'
        $call = {
            param([string]$Method, [string]$Uri, $Body)
            $r = $null
            try { $r = & $Rest $Method $Uri $Body $arm @{ 'Content-Type' = 'application/json' } } catch { $r = [pscustomobject]@{ Status = 0; Body = $_.Exception.Message } }
            if (-not $r) { $r = [pscustomobject]@{ Status = 0; Body = 'no answer' } }
            $r
        }
        $isOk = { param($r) $r -and [int]$r.Status -ge 200 -and [int]$r.Status -lt 300 }
        $parse = { param($r) if (-not $r -or -not "$($r.Body)".Trim()) { return $null }; $o = $null; try { $o = ("$($r.Body)" | ConvertFrom-Json) } catch { $o = $null }; return $o }
        $why = { param($r) $t = ("$(if ($r) { $r.Body })" -replace '\s+', ' ').Trim(); if ($t.Length -gt 300) { $t = $t.Substring(0, 297) + '...' }; ('HTTP {0}{1}' -f $(if ($r) { [int]$r.Status } else { 0 }), $(if ($t) { ": $t" } else { '' })) }
        $jobUri = { param($n, [string]$Action) 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}{3}?api-version={4}' -f $SubscriptionId, $ResourceGroup, $n, $Action, $script:SIMissingJobsArmApi }
        $map = Get-SIJobFlowMap
        foreach ($row in $plan) {
            # #723: a job that exists but is still on a timer an earlier version shipped -> this version's timer (read-modify-
            # write PATCH of the trigger, then read back). A timer of the customer's own is never touched.
            if ($row.Action -eq 'present' -and @($row.ShippedCrons).Count -and $row.Cron -and $row.Existing) {
                $setting = ''
                foreach ($sn in @($row.ScheduleSetting, ('SI_Bootstrap_Schedule' + (Get-SIEngineSettingSuffix -Engine $row.Engine)))) {
                    if ($sn -and $Globals.ContainsKey($sn) -and "$($Globals[$sn])".Trim()) { $setting = "$($Globals[$sn])".Trim(); break }
                }
                $rt = Get-SIMissingJobRetime -Job $row.Existing -Cron $row.Cron -ShippedCrons @($row.ShippedCrons) -Setting $setting
                if ($rt.Action -ne 'retime') { & $add $row 'present' ''; continue }
                if ($WhatIf) { & $add $row 'would-retime' ('missing jobs: {0} ({1}) would be moved to its new timer {2} (re-run with -Apply)' -f $row.Job, $row.What, $rt.Why); continue }
                $r = & $call 'PATCH' (& $jobUri $row.Job) (ConvertTo-Json -InputObject $rt.Body -Depth 10 -Compress)
                if (-not (& $isOk $r)) { & $add $row 'failed' ('missing jobs: {0} ({1}) was NOT moved to its new timer ({2}) -- it keeps ''{3}''; the next update tries again' -f $row.Job, $row.What, (& $why $r), $rt.Cron); continue }
                $got = ''
                for ($k = 1; $k -le [Math]::Max(1, $PollMax); $k++) {
                    $g = & $call 'GET' (& $jobUri $row.Job) $null
                    $j = if (& $isOk $g) { & $parse $g } else { $null }
                    $ps = [string](Get-SIKedaConvertProp $j @('properties', 'provisioningState'))
                    $got = [string](Get-SIKedaConvertProp $j @('properties', 'configuration', 'scheduleTriggerConfig', 'cronExpression'))
                    if ($j -and (-not $ps -or $ps -in @('Succeeded', 'Failed', 'Canceled')) -and (($got -replace '\s+', ' ').Trim() -eq $row.Cron -or $ps -in @('Failed', 'Canceled'))) { break }
                    if ($k -lt $PollMax -and $PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
                }
                if (($got -replace '\s+', ' ').Trim() -ne $row.Cron) { & $add $row 'failed' ('missing jobs: {0} ({1}) was NOT moved to its new timer (read back: ''{2}'') -- the next update tries again' -f $row.Job, $row.What, $(if ($got) { $got } else { 'nothing' })); continue }
                & $add $row 'retimed' ('missing jobs: {0} ({1}) moved to its new timer {2} and read back' -f $row.Job, $row.What, $rt.Why)
                continue
            }
            if ($row.Action -eq 'none' -or $row.Action -eq 'present') { & $add $row $row.Action ''; continue }
            if ($row.Action -eq 'keep') { & $add $row 'keep' ('missing jobs: {0} ({1}) is not there and is NOT created by this update -- {2}' -f $row.Job, $row.What, $row.Reason); continue }
            if ($row.Action -ne 'create') { continue }
            $donorName = [string](Get-SIKedaConvertProp $row.Donor @('name'))
            $mode = Get-SIMissingJobMode -Jobs $Jobs -Donor $row.Donor
            $cron = ''
            $sfx = Get-SIEngineSettingSuffix -Engine $row.Engine
            # #715: Bootstrap's own name for the job's timer where it is not SI_Bootstrap_Schedule<Engine>
            # (SI_Bootstrap_ScheduleVulnerabilitiesServiceNow for caj-si-asset-vulns-servicenow)
            if ($row.ScheduleSetting -and $Globals.ContainsKey($row.ScheduleSetting) -and "$($Globals[$row.ScheduleSetting])".Trim()) { $cron = "$($Globals[$row.ScheduleSetting])".Trim() }
            elseif ($Globals.ContainsKey("SI_Bootstrap_Schedule$sfx") -and "$($Globals["SI_Bootstrap_Schedule$sfx"])".Trim()) { $cron = "$($Globals["SI_Bootstrap_Schedule$sfx"])".Trim() }
            # #714: the customer's send time (HH:mm UTC) -- as Bootstrap's ScheduleCloseLoopMail falls back to it
            elseif ($row.CronSetting -and $Globals.ContainsKey($row.CronSetting) -and "$($Globals[$row.CronSetting])".Trim() -and (Get-Command Get-SICloseLoopMailSchedule -ErrorAction SilentlyContinue)) {
                $cron = [string](Get-SICloseLoopMailSchedule -SendTimeUtc ("$($Globals[$row.CronSetting])".Trim())).Cron
            }
            # #718: a job with a timer of its own that is not a daily one (the hourly status report)
            elseif ($row.Cron) { $cron = $row.Cron }
            if ($WhatIf) {
                $wTrig = Get-SIBootstrapTriggerPlan -Engine $row.Engine -Mode $mode -Cron $cron -Map $map
                & $add $row 'would-create' ('missing jobs: {0} ({1}) would be created from {2} -- {3} (re-run with -Apply)' -f $row.Job, $row.What, $donorName, $(if ($wTrig.Trigger -eq 'Manual' -and (Test-SIMissingJobManualOnly -Engine $row.Engine -Map $map)) { 'started on demand (no timer)' } elseif ($wTrig.Trigger -eq 'Manual') { 'a step of the pipeline' } else { 'on its own timer' }))
                continue
            }
            $created = $false
            $fail = {
                param([string]$Reason)
                if ($created) { $null = & $call 'DELETE' (& $jobUri $row.Job) $null }
                & $add $row 'failed' ('missing jobs: {0} ({1}) was NOT created ({2}) -- the next update tries again' -f $row.Job, $row.What, $Reason)
            }
            try {
                # (1) the donor's secrets, with their values (Key Vault references as references): ARM listSecrets
                $secretArgs = @(); $regPassword = ''
                $reg = @(Get-SIKedaConvertProp $row.Donor @('properties', 'configuration', 'registries') | Where-Object { $_ })[0]
                $regPwRef = [string](Get-SIKedaConvertProp $reg @('passwordSecretRef'))
                if (@(Get-SIKedaConvertProp $row.Donor @('properties', 'configuration', 'secrets') | Where-Object { $_ }).Count) {
                    $r = & $call 'POST' (& $jobUri $donorName '/listSecrets') $null
                    if (-not (& $isOk $r)) { & $fail ('the secrets of {0} could not be read ({1})' -f $donorName, (& $why $r)); continue }
                    foreach ($s in @(Get-SIKedaConvertProp (& $parse $r) @('value'))) {
                        $sn = [string](Get-SIKedaConvertProp $s @('name')); if (-not $sn) { continue }
                        $kvu = [string](Get-SIKedaConvertProp $s @('keyVaultUrl')); $val = [string](Get-SIKedaConvertProp $s @('value'))
                        if ($sn -eq $regPwRef) { $regPassword = $val; continue }
                        if ($kvu) { $id = [string](Get-SIKedaConvertProp $s @('identity')); $secretArgs += $(if ($id) { '{0}=keyvaultref:{1},identityref:{2}' -f $sn, $kvu, $id } else { '{0}=keyvaultref:{1}' -f $sn, $kvu }) }
                        else { $secretArgs += ('{0}={1}' -f $sn, $val) }
                    }
                }
                if ($regPwRef -and -not $regPassword -and -not [string](Get-SIKedaConvertProp $reg @('identity'))) { & $fail ('the registry password of {0} could not be read' -f $donorName); continue }
                # (1b) #714: a secret only another kind of job carries (the mail job's SMTP relay password, on a Risk Analysis
                # job) -- its Key Vault reference (or value) under the same name, as Bootstrap wires it. Not found = the job
                # is made without it (a shared mailbox or an anonymous relay needs none); not readable = made without it, said.
                $extraEnv = @(); $notes = @()
                foreach ($b in @($row.Borrow)) {
                    if (-not $b) { continue }
                    $src = $null
                    foreach ($fn in @($b.From)) {
                        $cand = @($Jobs | Where-Object { $_ -and [string](Get-SIKedaConvertProp $_ @('name')) -eq $fn })[0]
                        if ($cand -and @(Get-SIKedaConvertProp $cand @('properties', 'configuration', 'secrets') | Where-Object { $_ -and [string](Get-SIKedaConvertProp $_ @('name')) -eq $b.Secret }).Count) { $src = $cand; break }
                    }
                    if (-not $src) { continue }
                    $srcName = [string](Get-SIKedaConvertProp $src @('name'))
                    $r = & $call 'POST' (& $jobUri $srcName '/listSecrets') $null
                    $s = $null
                    if (& $isOk $r) { $s = @(@(Get-SIKedaConvertProp (& $parse $r) @('value')) | Where-Object { $_ -and [string](Get-SIKedaConvertProp $_ @('name')) -eq $b.Secret })[0] }
                    if (-not $s) { $notes += ('without {0} (the secret {1} of {2} could not be read: {3})' -f $b.Env, $b.Secret, $srcName, (& $why $r)); continue }
                    $kvu = [string](Get-SIKedaConvertProp $s @('keyVaultUrl')); $val = [string](Get-SIKedaConvertProp $s @('value'))
                    $arg = if ($kvu) { $id = [string](Get-SIKedaConvertProp $s @('identity')); if ($id) { '{0}=keyvaultref:{1},identityref:{2}' -f $b.Secret, $kvu, $id } else { '{0}=keyvaultref:{1}' -f $b.Secret, $kvu } } else { '{0}={1}' -f $b.Secret, $val }
                    $secretArgs = @(@($secretArgs | Where-Object { ((([string]$_) -split '=', 2)[0]) -ne $b.Secret }) + @($arg))
                    $extraEnv += ('{0}=secretref:{1}' -f $b.Env, $b.Secret)
                    $notes += ('{0} from {1}' -f $b.Env, $srcName)
                }
                $spec = Get-SIMissingJobSpec -Engine $row.Engine -Donor $row.Donor -ResourceGroup $ResourceGroup -Mode $mode -Cron $cron -SecretArgs $secretArgs -RegistryPassword $regPassword -Globals $Globals -Map $map -ExtraEnv $extraEnv -OwnSize:([bool]$row.OwnSize)
                # (2) idempotent: the job may have been made since the list was read (another run, the setup) -- never overwritten
                $r = & $call 'GET' (& $jobUri $row.Job) $null
                if (& $isOk $r) { & $add $row 'present' ('missing jobs: {0} exists now (made meanwhile) -- left as it is' -f $row.Job); continue }
                # (3) the job -- a manual job starts nothing; a scheduled one runs at its time
                $r = & $call 'PUT' (& $jobUri $row.Job) (ConvertTo-Json -InputObject $spec.Body -Depth 30 -Compress)
                if (-not (& $isOk $r)) { & $fail ('Azure refused it: {0}' -f (& $why $r)); continue }
                $created = $true
                # (4) read back once its creation has finished (ARM creates a job asynchronously)
                $j = $null
                for ($k = 1; $k -le [Math]::Max(1, $PollMax); $k++) {
                    $g = & $call 'GET' (& $jobUri $row.Job) $null
                    $j = if (& $isOk $g) { & $parse $g } else { $null }
                    $ps = [string](Get-SIKedaConvertProp $j @('properties', 'provisioningState'))
                    if ($j -and (-not $ps -or $ps -in @('Succeeded', 'Failed', 'Canceled'))) { break }
                    if ($k -lt $PollMax -and $PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
                }
                $bad = Test-SIMissingJobReadBack -Job $j -Spec $spec -Engine $row.Engine
                if ($bad) { & $fail ('read back: {0}' -f $bad); continue }
                $how = if ($spec.Trigger -eq 'Event') { 'started by its queue (event trigger, the engine identity)' } elseif ($spec.Trigger -eq 'Manual' -and (Test-SIMissingJobManualOnly -Engine $row.Engine -Map $map)) { 'started on demand (manual, no timer)' } elseif ($spec.Trigger -eq 'Manual') { 'a step of the pipeline (no timer of its own; "{0}" remembered)' -f $spec.Cron } else { 'on its own timer "{0}"' -f $spec.Cron }
                & $add $row 'created' ('missing jobs: {0} ({1}) created from {2} and read back -- {3}{4}' -f $row.Job, $row.What, $donorName, $how, $(if ($notes.Count) { '; ' + ($notes -join '; ') } else { '' }))
            } catch { & $fail $_.Exception.Message }
        }
        if (-not @($results | Where-Object { $_.Line }).Count) { $lines.Add('missing jobs: none -- every job this version needs is there') }
    } catch {
        $lines.Add(('missing jobs: not checked ({0}) -- the update goes on; the next update tries again' -f $_.Exception.Message))
    }
    [pscustomobject]@{ Results = $results.ToArray(); Lines = $lines.ToArray() }
}
