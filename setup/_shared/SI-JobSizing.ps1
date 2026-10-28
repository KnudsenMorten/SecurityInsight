#Requires -Version 5.1
<#
    SecurityInsight -- THE CONTAINER JOB SIZE ON EVERY UPDATE (#509, operator 2026-10-09: "include these guidance rules for
    si and pim so you automatically adjust during installation. both si and pim are allowed to go to 4 cpu/8 gb if needed",
    and "it is very little money").

    Setup sizes the collection jobs from the tenant's Microsoft Graph counts ONCE, at install (Bootstrap-ContainerAppJob.ps1
    -> Get-SITenantSizedJobResources). An install made before that rule, or a tenant that grew, kept its first size. So
    every update (setup\Invoke-SIContainerUpdate.ps1, step 8 -- the updater job and the VM sync hook both run it) applies
    the SAME rule to the jobs that exist:

      * WHICH JOBS: identity, endpoint (scheduled, or the KEDA producer + worker), the CI build (asset-correlation) and the
        Risk Analysis jobs (risk-analysis, risk-analysis-detailed, ra-<name>). Objects: identity = users + groups + service
        principals; endpoint = devices; the CI build and Risk Analysis = all of them (Get-SITenantSizedJobResources).
      * THE COUNTS, the first that can be read, and the log says which: (1) Microsoft Graph $count as the updater's
        identity; (1b) the SAME Graph counts as the identity / endpoint collection read them with ITS directory rights,
        recorded in the Pro database (cfg.InstallState 'TenantSize', engine\_shared\SI-TenantSizeMark.ps1) -- the updater
        has no directory read, and needs none for this; (2) the records the last collection wrote, per provider, in the Pro database (sidata.CiRecord: Entra
        users / groups / service principals, the largest device count of any provider); (3) the asset counts the engines
        recorded in their run health (SI_RunHealth_CL, the largest run of the last 7 days). Without (1), each half -- the
        identity objects, the devices -- comes from the first of (2), the Graph counts SETUP read at install (kept on the
        jobs as si-tenant-* tags) and (3) that has it; a 0 is not known, never none (#720). A COUNT NOT KNOWN -- none
        readable, or the half a job counts missing -- sizes that job for a large tenant, 4 CPU / 8 GiB (owner 2026-10-16:
        reliability over cost, "we can always lower it later"), with one plain line; a known count below 5,000 keeps the
        job's size.
      * LEARN FROM FAILURES: when a job's LAST execution ended out of memory (Container Apps system log OOMKilled / exit
        137, an END that says OutOfMemory or carries the out-of-memory class si-col-0501 / si-ra-0303, or a run that
        started, recorded no end and stopped well before its timeout) or at its replica timeout, the job goes up one band
        even when the counts do not ask for it: CPU / memory 2 / 4 GiB, then 4 / 8 GiB. One plain line says why. A Failed or
        Stopped execution counts although ARM gives it no endTime (#720: it never does for a failed run).
      * THE RUN LIMIT (owner 2026-10-13: "we are not to judge that and it breaks the whole solution"): SecurityInsight
        chooses no run limit. EVERY engine job (every caj-si-* job but the updater) gets the longest run limit Azure takes
        -- Get-SIJobRunLimit, 7 days -- at install, and every update raises an existing job to it (Invoke-SIJobFloor, the
        update's step 8c; this file's sizing applies the same value, so neither ever writes a shorter one). It does not
        depend on the tenant's size, on how long a run took or on how a run ended. The only thing that watches a step is
        the pipeline's report of a step with no sign of progress, which reports and lets the step run on.
      * THE PIPELINE JOB ITSELF (caj-si-flow) waits for every step inside its own execution: it gets 7 days
        (Get-SIFlowJobReplicaTimeout), by its own rule (Invoke-SIFlowJobRunLimit).
      * NEVER LOWERS, NEVER ABOVE 4 CPU / 8 GiB (the largest consumption size). A size the customer set wins:
        SI_Bootstrap_Cpu_<Engine> / _Memory_<Engine> keep the job's CPU and memory, SI_Bootstrap_ReplicaTimeout_<Engine>
        its run time (as Get-SIContainerJobResources honours it at install: 300 s to 7 days, so it can only be SHORTER
        than what every job gets -- a customer's own choice, and the update then leaves that job's run limit alone).
      * THE CHANGE: ONE ARM read-modify-write PATCH per job (#521, no az CLI): the job is read at the PATCH's own
        api-version, its WHOLE template goes back with the first container's CPU / memory changed (a PATCH of a template
        fragment would replace the container list), and -- when the run time grows -- its configuration's trigger with the
        new replicaTimeout; the secrets are never sent back. One line per job changed. A KEDA worker whose timeout grows
        gets its queue lease with it (SI_QUEUE_LEASE_SECONDS = timeout + 300, as Bootstrap sets it). Never fails the update.

    Every Azure call goes through the REST seam -Rest { param($Method, $Uri, $Body, $Resource, $Headers) } -> @{ Status;
    Body } (setup/_shared/SI-UpdateRest.ps1) and the Pro database through -SqlRows { param([string]$Sql) -> rows }, so every
    decision is tested offline. PowerShell 5.1-compatible.
#>

# the rule itself (Get-SITenantSizedJobResources) and the per-engine setting names (Get-SIEngineSettingSuffix)
if (-not (Get-Command -Name Get-SITenantSizedJobResources -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'container', '_shared', 'SI-ContainerConfig.ps1'))
}
if (-not (Get-Command -Name Invoke-SIRestJson -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-UpdateRest.ps1')) }
# the directory counts the collections record (ConvertFrom-SITenantSizeMark) -- read when it is there, never required
if (-not (Get-Command -Name ConvertFrom-SITenantSizeMark -ErrorAction SilentlyContinue)) {
    $__tsMark = [IO.Path]::Combine($PSScriptRoot, '..', '..', 'engine', '_shared', 'SI-TenantSizeMark.ps1')
    if (Test-Path -LiteralPath $__tsMark) { . $__tsMark }
}
# Graph $count (Get-SISqlTierTenantCounts)
if (-not (Get-Command -Name Get-SISqlTierTenantCounts -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine($PSScriptRoot, 'SI-SqlTier.ps1'))
}

# The bands a job moves through (Container Apps consumption pairs). Level 0 = the job kind's own default (below 4 GiB).
$script:SIJobSizeBands = @{
    1 = [pscustomobject]@{ Cpu = '2.0'; Memory = '4.0Gi'; Text = '2 CPU / 4 GiB' }
    2 = [pscustomobject]@{ Cpu = '4.0'; Memory = '8.0Gi'; Text = '4 CPU / 8 GiB' }
}
$script:SIJobSizeMaxLevel = 2
# THE RUN LIMIT is ONE value for every engine job: Get-SIJobRunLimit (container/_shared/SI-ContainerConfig.ps1), the longest
# run limit Azure takes. Nothing here measures a run or picks a shorter limit. A value Azure refuses is said as a line by
# the update (Invoke-SIJobSizePatch: 24 hours instead), and the next update asks again.
$script:SIJobSizeArmApi = '2025-07-01'   # not 2024-03-01: that version drops a queue scale rule's identity when a job is read and written back (#616)
# the read-modify-write of a job reads and writes in ONE schema (the fast roll's, SI-FastRoll.ps1: live 2026-10-06)
$script:SIJobSizePatchApi = '2025-07-01'

function Get-SIJobSizingEngine {
    <#
        PURE. The engine a job is sized as, from its name, or $null when this sizing does not cover it.
        caj-si-identity / -identity-producer / -identity-worker -> identity; endpoint likewise; caj-si-asset-correlation;
        caj-si-risk-analysis, caj-si-risk-analysis-detailed, caj-si-ra-<name>. Returns @{ Engine; Role = job | producer | worker }.
    #>
    param([AllowEmptyString()][string]$JobName)
    $n = "$JobName".Trim().ToLowerInvariant()
    if (-not $n.StartsWith('caj-si-')) { return $null }
    $s = $n.Substring(7); $role = 'job'
    if ($s -match '^(.+)-(producer|worker)$') { $s = $Matches[1]; $role = $Matches[2] }
    # the jobs that load the whole Risk Analysis result (data sync, vulnerabilities) are sized as Risk Analysis
    # is: customer H 2026-10-10, ~49,000 Detailed rows ran the data sync out of memory at the 2 GiB default, twice
    # 'azure' since 2026-10-12: a new customer install ran its Azure worker out of memory at 4 GiB
    $ok = ($s -in @('identity', 'endpoint', 'azure', 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed', 'asset-datasync', 'asset-vulnerabilities')) -or ($s -match '^ra-[a-z0-9-]+$')
    if (-not $ok) { return $null }
    if ($role -ne 'job' -and $s -notin @('identity', 'endpoint', 'azure')) { return $null }
    [pscustomobject]@{ Engine = $s; Role = $role }
}

function Get-SIJobSizingStepKeys {
    <#
        The jobs that are steps of the pipeline, from the shipped map (config\job-flow.locked.json): every job with a
        stage that is not marked neverInFlow / ownSchedule (the updater) / retired. -Path: test seam. @() when the map
        cannot be read (a customer's run limit setting is then looked for under the job's own name only).
    #>
    param([string]$Path)
    if (-not $Path) { $Path = [IO.Path]::Combine($PSScriptRoot, '..', '..', 'config', 'job-flow.locked.json') }
    try {
        $raw = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
        $flag = { param($j, $n) [bool]($j.PSObject.Properties[$n] -and $j.$n) }
        return @(@($raw.jobs) | Where-Object { $_ -and (& $flag $_ 'stage') -and -not (& $flag $_ 'neverInFlow') -and -not (& $flag $_ 'ownSchedule') -and -not (& $flag $_ 'retired') } |
                 ForEach-Object { [pscustomobject]@{ Key = ([string]$_.key).ToLowerInvariant(); Engine = ([string]$_.engine).ToLowerInvariant() } })
    } catch { return @() }
}

function Get-SIJobRunLimitJob {
    <#
        PURE. Is this job a step of the pipeline (the pipeline's self-healing asks), and as what? Every job that is a step of the
        pipeline (-Steps: Get-SIJobSizingStepKeys), its producer / worker when it collects in parts, and every Risk
        Analysis report job (ra-<name>). Returns @{ Engine; Role = job | producer | worker; Sized = also sized for CPU and
        memory (Get-SIJobSizingEngine); Names = the engine names its SI_Bootstrap_ReplicaTimeout_<Engine> setting may be
        spelt with } or $null (the updater, the pipeline job, a job that is no step).
    #>
    param([AllowEmptyString()][string]$JobName, [object[]]$Steps = @())
    $sized = Get-SIJobSizingEngine -JobName $JobName
    $n = "$JobName".Trim().ToLowerInvariant()
    if (-not $n.StartsWith('caj-si-')) { return $null }
    $s = $n.Substring(7); $role = 'job'
    if ($s -match '^(.+)-(producer|worker)$') { $s = $Matches[1]; $role = $Matches[2] }
    $step = @(@($Steps) | Where-Object { $_ -and [string]$_.Key -eq $s }) | Select-Object -First 1
    if (-not $sized -and -not $step -and $s -notmatch '^ra-[a-z0-9-]+$') { return $null }
    $names = @($s); if ($step -and $step.Engine -and $step.Engine -ne $s) { $names += [string]$step.Engine }
    [pscustomobject]@{ Engine = $s; Role = $role; Sized = [bool]$sized; Names = $names }
}

function Get-SIJobRunLimitReason {
    <# PURE. The plain words for why a job's run limit was raised (the update's log line). #>
    'a step gets the longest run limit Azure takes ({0}); SecurityInsight sets no shorter one' -f (Format-SIJobTimeout -Seconds ([int](Get-SIJobRunLimit)))
}

function Get-SIJobRunLimitSetting {
    <#
        PURE. The customer's own run limit setting for a job, when one is set: the NAME of the setting
        (SI_Bootstrap_ReplicaTimeout_<Engine>, under any of the engine names in -Engines), else ''. A job with one keeps the
        run limit it has: the update never raises it.
    #>
    param([string[]]$Engines = @(), [hashtable]$Globals = @{})
    foreach ($e in @($Engines | Where-Object { $_ })) {
        $n = 'SI_Bootstrap_ReplicaTimeout_{0}' -f (Get-SIEngineSettingSuffix -Engine $e)
        if ($Globals -and $Globals.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace([string]$Globals[$n])) { return $n }
    }
    ''
}

function ConvertTo-SIJobMemoryGi {
    <# PURE. '4Gi' / '4.0Gi' / '0.5Gi' -> 4.0 (double); 0 when it is not a size. #>
    param([AllowNull()]$Memory)
    $m = 0.0
    $t = ("$Memory" -replace '(?i)\s*gi$', '').Trim()
    if ([double]::TryParse($t, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$m)) { return $m }
    0.0
}

function Get-SIJobCurrentSize {
    <# PURE. A job's CPU, memory and replica timeout from its ARM shape (the job list the update read). #>
    param([Parameter(Mandatory)]$Job)
    $c = $null; try { $c = @($Job.properties.template.containers)[0] } catch { $c = $null }
    $cpu = 0.0; $mem = ''
    if ($c -and $c.resources) {
        [void][double]::TryParse("$($c.resources.cpu)", [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$cpu)
        $mem = [string]$c.resources.memory
    }
    $to = 0; try { [void][int]::TryParse("$($Job.properties.configuration.replicaTimeout)", [ref]$to) } catch { }
    [pscustomobject]@{ Cpu = $cpu; Memory = $mem; MemoryGi = (ConvertTo-SIJobMemoryGi $mem); ReplicaTimeout = $to }
}

function Get-SIJobSizeLevel {
    <# PURE. The band a memory size is in: 0 below 4 GiB, 1 below 8 GiB, 2 at 8 GiB. #>
    param([double]$MemoryGi)
    if ($MemoryGi -ge 8) { return 2 }
    if ($MemoryGi -ge 4) { return 1 }
    0
}

function Format-SIJobTimeout {
    <# PURE. 14400 -> '4 h', 5400 -> '1.5 h', 1800 -> '30 min', 604800 -> '7 days'. #>
    param([int]$Seconds)
    if ($Seconds -lt 3600) { return ('{0} min' -f [int]($Seconds / 60)) }
    if ($Seconds -ge 604800 -and ($Seconds % 86400) -eq 0) { return ('{0} days' -f [int]($Seconds / 86400)) }
    ('{0} h' -f ([double]$Seconds / 3600).ToString('0.#', [Globalization.CultureInfo]::InvariantCulture))
}

function ConvertTo-SIJobSizingUtc {
    <# PURE. A time from ARM / Log Analytics -> UTC [datetime], or $null. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) { return $d }
    $null
}

function Get-SIJobFailureSignal {
    <#
        PURE. Did this job's LAST finished execution end out of memory or at its replica timeout?
        -Executions: the job's executions (ARM: name, properties.status / startTime / endTime). -SystemLogRows: Container Apps
        system log rows (Job, Exec, Reason, Msg, TimeGenerated) that mention OOMKilled / exit code 137. -RunHealthRows:
        SI_RunHealth_CL rows (Engine, Phase, ExitReason, ErrorMessage, TimeGenerated).
        Returns @{ Kind = oom | timeout; Execution; Reason } or $null (succeeded, failed for another reason, or not known).
    #>
    param([Parameter(Mandatory)][string]$JobName, [string]$Engine, [int]$ReplicaTimeout,
          [object[]]$Executions = @(), [object[]]$SystemLogRows = @(), [object[]]$RunHealthRows = @())
    $p = { param($o, $n) if ($null -eq $o) { return $null }; $pp = $o.PSObject.Properties[$n]; if ($pp) { $pp.Value } else { $null } }
    # #720 (live 2026-10-16, the large installs): ARM returns a FAILED (or Stopped) execution WITHOUT an endTime -- the
    # identity producer's out-of-memory run carried status Failed, a startTime and no endTime. Such a run is FINISHED: its
    # end is the run health's END record of that execution when there is one, else unknown (then its length is unknown:
    # no timeout is read from it, but every out-of-memory signal still is). Only a run still going is skipped.
    $finished = @('Succeeded', 'Failed', 'Stopped')
    $rhEndOf = {
        param([string]$Exec)
        $at = $null
        foreach ($r in @($RunHealthRows)) {
            if (-not $r -or [string](& $p $r 'Phase') -ne 'End' -or -not ([string](& $p $r 'Execution') -ieq $Exec)) { continue }
            $t = ConvertTo-SIJobSizingUtc (& $p $r 'TimeGenerated'); if ($t -and (-not $at -or $t -gt $at)) { $at = $t }
        }
        $at
    }
    $done = foreach ($e in @($Executions)) {
        if (-not $e) { continue }
        $props = & $p $e 'properties'; if (-not $props) { $props = $e }
        $st = [string](& $p $props 'status')
        $start = ConvertTo-SIJobSizingUtc (& $p $props 'startTime'); $end = ConvertTo-SIJobSizingUtc (& $p $props 'endTime')
        if (-not $start) { continue }
        if (-not $end) {
            if ($finished -notcontains $st) { continue }
            $end = & $rhEndOf ([string](& $p $e 'name'))
            $known = $false
        } else { $known = $true }
        if ($st -in @('Running', 'Processing', 'Pending', '')) { continue }
        [pscustomobject]@{ Name = [string](& $p $e 'name'); Status = $st; Start = $start; End = $end; EndKnown = $known }
    }
    $last = @($done | Sort-Object Start -Descending) | Select-Object -First 1
    if (-not $last) { return $null }
    # the window run-health / system-log rows of this run fall in: to its end (+15 min), or -- no end known -- to the run
    # limit after its start (7 days when the job's limit is not known)
    $winEnd = if ($last.End) { $last.End.AddMinutes(15) } else { $last.Start.AddSeconds($(if ($ReplicaTimeout -gt 0) { $ReplicaTimeout } else { 604800 })).AddMinutes(15) }
    # ... and never past the start of a later execution (one still running has its own START and no END yet)
    if (-not $last.End) {
        foreach ($e in @($Executions)) {
            if (-not $e) { continue }
            $props = & $p $e 'properties'; if (-not $props) { $props = $e }
            $s2 = ConvertTo-SIJobSizingUtc (& $p $props 'startTime')
            if ($s2 -and $s2 -gt $last.Start -and $s2 -lt $winEnd) { $winEnd = $s2 }
        }
    }
    # an out-of-memory end, in the engine's words or by its class (si-col-0501 a collection, si-ra-0303 a Risk Analysis
    # lookup, the uplink class out-of-memory)
    $oomRx = '(?i)OutOfMemory|out of memory|out-of-memory|\bOOM|si-col-0501|si-ra-0303'
    if ($last.Status -eq 'Succeeded') {
        # A run that ENDED "Succeeded" can still have run out of memory: a collection worker catches the error, records it
        # and ends cleanly, its part goes back on the queue and the next worker fails the same way (a new customer install
        # 2026-10-12: the Azure worker, 4 GiB, "System.OutOfMemoryException" in its Enrich step, again every two minutes).
        # The engine's own record says so -- that is a failure signal too.
        $normS = { param($s) ("$s".ToLowerInvariant() -replace '[^a-z0-9]', '') }
        $engS = & $normS $Engine
        $fromS = $last.Start.AddMinutes(-5); $toS = $winEnd
        foreach ($r in @($RunHealthRows)) {
            if (-not $r) { continue }
            # #711: a row that names this very execution is this job's own, whatever engine name it carries (every Risk
            # Analysis job -- risk-analysis-detailed, ra-<name> -- records itself as 'risk-analysis')
            $ownS = [bool]([string](& $p $r 'Execution') -and [string](& $p $r 'Execution') -ieq $last.Name)
            if (-not $ownS) {
                if (-not $engS) { continue }
                $re = & $normS (& $p $r 'Engine')
                if (-not ($re -eq $engS -or $re.StartsWith($engS))) { continue }
            }
            $at = ConvertTo-SIJobSizingUtc (& $p $r 'TimeGenerated')
            if (-not $at -or $at -lt $fromS -or $at -gt $toS) { continue }
            if (('{0} {1}' -f (& $p $r 'ExitReason'), (& $p $r 'ErrorMessage')) -match $oomRx) {
                $whenS = $last.Start.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + 'Z'
                return [pscustomobject]@{ Kind = 'oom'; Execution = $last.Name; Reason = ('its last run ({0}, {1}) ran out of memory (its run health says so), although the run itself ended without an error' -f $last.Name, $whenS) }
            }
        }
        return $null
    }
    $dur = if ($last.End) { ($last.End - $last.Start).TotalSeconds } else { -1 }
    $when = $last.Start.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + 'Z'
    $what = '{0}, {1}' -f $last.Name, $when
    $from = $last.Start.AddMinutes(-5); $to = $winEnd
    # 1. the Container Apps system log said so (OOMKilled, exit code 137)
    foreach ($r in @($SystemLogRows)) {
        if (-not $r) { continue }
        $ex = [string](& $p $r 'Exec'); $jn = [string](& $p $r 'Job'); $at = ConvertTo-SIJobSizingUtc (& $p $r 'TimeGenerated')
        $mine = ($ex -and $ex -ieq $last.Name) -or (-not $ex -and $jn -ieq $JobName -and $at -and $at -ge $from -and $at -le $to)
        $txt = '{0} {1}' -f (& $p $r 'Reason'), (& $p $r 'Msg')
        if ($mine -and $txt -match '(?i)OOMKilled|OutOfMemory|exit code ''?137') {
            return [pscustomobject]@{ Kind = 'oom'; Execution = $last.Name; Reason = ('its last run ({0}) was stopped out of memory (Container Apps: OOMKilled)' -f $what) }
        }
    }
    $norm = { param($s) ("$s".ToLowerInvariant() -replace '[^a-z0-9]', '') }
    $eng = & $norm $Engine
    $rh = @(@($RunHealthRows) | Where-Object {
        $_ -and ((([string](& $p $_ 'Execution')) -and ([string](& $p $_ 'Execution')) -ieq $last.Name) -or
                 ($eng -and ((& $norm (& $p $_ 'Engine')) -eq $eng -or (& $norm (& $p $_ 'Engine')).StartsWith($eng)))) -and
        ($at = ConvertTo-SIJobSizingUtc (& $p $_ 'TimeGenerated')) -and $at -ge $from -and $at -le $to })
    # 2. the engine recorded an out-of-memory end
    foreach ($r in @($rh | Where-Object { [string](& $p $_ 'Phase') -eq 'End' })) {
        if (('{0} {1}' -f (& $p $r 'ExitReason'), (& $p $r 'ErrorMessage')) -match $oomRx) {
            return [pscustomobject]@{ Kind = 'oom'; Execution = $last.Name; Reason = ('its last run ({0}) ended out of memory (its run health says so)' -f $what) }
        }
    }
    # 3. it ran until its replica timeout (only a run whose length is known)
    if ($ReplicaTimeout -gt 0 -and $dur -ge 0 -and $dur -ge ($ReplicaTimeout - [Math]::Max(120, $ReplicaTimeout * 0.02))) {
        return [pscustomobject]@{ Kind = 'timeout'; Execution = $last.Name; Reason = ('its last run ({0}) was stopped at its replica timeout after {1}' -f $what, (Format-SIJobTimeout -Seconds $ReplicaTimeout)) }
    }
    # 4. it started, recorded no end and was stopped well before its timeout: killed -- for memory
    $starts = @($rh | Where-Object { [string](& $p $_ 'Phase') -eq 'Start' }).Count
    $ends = @($rh | Where-Object { [string](& $p $_ 'Phase') -eq 'End' }).Count
    if ($starts -gt 0 -and $ends -lt $starts) {
        if ($dur -lt 0) {
            return [pscustomobject]@{ Kind = 'oom'; Execution = $last.Name; Reason = ('its last run ({0}) failed without recording its end (Azure gives the run no end time either) -- a run killed for memory' -f $what) }
        }
        return [pscustomobject]@{ Kind = 'oom'; Execution = $last.Name; Reason = ('its last run ({0}) failed after {1} without recording its end, well before its timeout -- a run killed for memory' -f $what, (Format-SIJobTimeout -Seconds ([int]$dur))) }
    }
    $null
}

function Get-SIJobSizingCountHalves {
    <# PURE. The halves of the tenant's counts a sized job counts: identity -> Identity; endpoint -> Devices; every other
       sized job (the Azure collection, the CI build, Risk Analysis, the data jobs) reads every object -> both. #>
    param([Parameter(Mandatory)][string]$Engine)
    switch ($Engine.Trim().ToLowerInvariant()) {
        'identity' { return @('Identity') }
        'endpoint' { return @('Devices') }
        default { return @('Identity', 'Devices') }
    }
}

function Test-SIJobSizingCountKnown {
    <#
        PURE. Is the count this job is sized by KNOWN? -Counts: Users, Groups, ServicePrincipals, Devices ($null = none).
        The identity half is known when Users > 0 (a tenant has users; a 0 is a collection that wrote none, #720), the
        device half when Devices > 0. A job is known when every half it counts is (Get-SIJobSizingCountHalves).
    #>
    param([Parameter(Mandatory)][string]$Engine, [hashtable]$Counts)
    if (-not $Counts) { return $false }
    $n = { param($k) $v = 0L; if ($Counts.ContainsKey($k) -and $null -ne $Counts[$k]) { [void][long]::TryParse("$($Counts[$k])", [ref]$v) }; $v }
    foreach ($h in @(Get-SIJobSizingCountHalves -Engine $Engine)) {
        if ($h -eq 'Identity' -and (& $n 'Users') -le 0) { return $false }
        if ($h -eq 'Devices' -and (& $n 'Devices') -le 0) { return $false }
    }
    $true
}

function Get-SIJobSizingUnknownReason {
    <# PURE. The plain words for a job sized for a large tenant because its count could not be read. #>
    'the tenant''s size could not be read -- sized for a large tenant'
}

function Get-SIJobSizeChange {
    <#
        PURE. What to do with ONE job. -Current: Get-SIJobCurrentSize. -Counts: the tenant's counts (Users, Groups,
        ServicePrincipals, Devices; $null = not known -- a job whose count is not known, Test-SIJobSizingCountKnown, gets
        4 CPU / 8 GiB) and -CountsFrom (the words for the log). -Failure:
        Get-SIJobFailureSignal. -Globals: the customer's settings (SI_Bootstrap_Cpu_ / _Memory_<Engine>).
        -NoResize: a job whose CPU and memory this sizing does not cover (a step of the pipeline that is no sized job).
        CPU AND MEMORY ONLY. The run limit is never changed here: every engine job has the one value the update's floor
        step gives it (Invoke-SIJobFloor); ReplicaTimeout in the answer is the job's own, as it is.
        Returns @{ Action = raise | keep; Cpu; Memory; ReplicaTimeout; Level; Reasons; Notes; Line }. Never lowers; never above
        4 CPU / 8 GiB; a size the customer set wins.
    #>
    param([Parameter(Mandatory)][string]$JobName, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)]$Current,
          [hashtable]$Counts, [string]$CountsFrom = 'the tenant', $Failure, [hashtable]$Globals = @{}, [switch]$NoResize)
    $sfx = Get-SIEngineSettingSuffix -Engine $Engine
    $gv = { param($n) if ($Globals -and $Globals.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace([string]$Globals[$n])) { "$($Globals[$n])".Trim() } else { $null } }
    $custRes = @(@(('SI_Bootstrap_Cpu_{0}' -f $sfx), ('SI_Bootstrap_Memory_{0}' -f $sfx)) | Where-Object { & $gv $_ })
    $curLevel = Get-SIJobSizeLevel -MemoryGi $Current.MemoryGi
    $curTo = [int]$Current.ReplicaTimeout
    $wantLevel = $curLevel
    $reasons = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]
    $inv = [Globalization.CultureInfo]::InvariantCulture
    # 1. the tenant's size (the rule setup applies at install)
    # A COUNT THAT IS NOT KNOWN sizes the job for a large tenant (owner 2026-10-16: reliability over cost, "we can always
    # lower it later"; live: customer I's 153,000 users ran every sized job on 2 CPU / 4 GiB, and at two more installs the
    # identity job alone, because no count could be read). Not known = no counts at all, or the half this job counts
    # (identity objects / devices; both for a job that reads every object) missing or 0 (Test-SIJobSizingCountKnown).
    if (-not $NoResize -and -not (Test-SIJobSizingCountKnown -Engine $Engine -Counts $Counts)) {
        if ($script:SIJobSizeMaxLevel -gt $wantLevel) { $wantLevel = $script:SIJobSizeMaxLevel; $reasons.Add((Get-SIJobSizingUnknownReason)) }
    } elseif ($Counts -and -not $NoResize) {
        $sized = Get-SITenantSizedJobResources -Engine $Engine -Counts $Counts
        if ($sized) {
            $lvl = Get-SIJobSizeLevel -MemoryGi (ConvertTo-SIJobMemoryGi $sized.Memory)
            if ($lvl -gt $wantLevel) { $wantLevel = $lvl; $reasons.Add(('{0} objects (from {1})' -f ([long]$sized.Objects).ToString('N0', $inv), $CountsFrom)) }
        }
    }
    # 2. learn from the last run (out of memory, or stopped at its run limit): one band up, even when the counts do not ask for it
    if ($Failure -and -not $NoResize) {
        $fl = [Math]::Min($script:SIJobSizeMaxLevel, $curLevel + 1)
        if ($fl -gt $wantLevel) { $wantLevel = $fl; $reasons.Add([string]$Failure.Reason) }
        elseif ($fl -gt $curLevel) { $reasons.Add([string]$Failure.Reason) }   # the failure is a reason for the raise too
        elseif ($curLevel -ge $script:SIJobSizeMaxLevel -and $Failure.Kind -eq 'oom') {
            $notes.Add(('{0}, but it is already at the largest CPU and memory Container Apps gives a job (4 CPU / 8 GiB) -- it needs the work split (queue scaling), not a bigger job' -f $Failure.Reason))
        }
    }
    # 3. the CPU / memory cap (the platform's largest pair), and a size the customer set wins
    if ($wantLevel -gt $script:SIJobSizeMaxLevel) { $wantLevel = $script:SIJobSizeMaxLevel }
    if ($custRes.Count -and $wantLevel -gt $curLevel) { $notes.Add(('{0} would get {1}, but {2} is set -- the customer''s size is kept' -f $JobName, $script:SIJobSizeBands[$wantLevel].Text, ($custRes -join ' / '))); $wantLevel = $curLevel }
    $raiseRes = $wantLevel -gt $curLevel
    $cpu = if ($raiseRes) { $script:SIJobSizeBands[$wantLevel].Cpu } else { $Current.Cpu.ToString('0.0#', $inv) }
    $mem = if ($raiseRes) { $script:SIJobSizeBands[$wantLevel].Memory } else { [string]$Current.Memory }
    $to = $curTo
    if (-not $raiseRes) {
        return [pscustomobject]@{ Action = 'keep'; Cpu = $cpu; Memory = $mem; ReplicaTimeout = $to; Level = $curLevel; Reasons = @(); Notes = $notes.ToArray(); Line = '' }
    }
    $fromTxt = '{0} CPU / {1}, {2}' -f $Current.Cpu.ToString('0.0#', $inv), $Current.Memory, (Format-SIJobTimeout -Seconds $curTo)
    $toTxt = '{0} CPU / {1}, {2}' -f $cpu, $mem, (Format-SIJobTimeout -Seconds $to)
    $line = 'job size: {0} raised {1} -> {2} -- {3}' -f $JobName, $fromTxt, $toTxt, ($reasons -join '; ')
    [pscustomobject]@{ Action = 'raise'; Cpu = $cpu; Memory = $mem; ReplicaTimeout = $to; Level = $wantLevel; Reasons = $reasons.ToArray(); Notes = $notes.ToArray(); Line = $line }
}

function Get-SIJobSizingCountsFromCiRecords {
    <#
        PURE. The tenant's counts from the records the last collection wrote (sidata.CiRecord grouped by Provider,
        RecordType -> Records): Users / Groups / ServicePrincipals from Entra, Devices = the largest device count of any
        provider (Entra, Defender, Intune and AD each see the same devices). $null when nothing was recorded.
    #>
    param([object[]]$Rows = @())
    $c = @{ Users = 0L; Groups = 0L; ServicePrincipals = 0L; Devices = 0L }; $any = $false
    foreach ($r in @($Rows)) {
        if (-not $r) { continue }
        $n = 0L; if (-not [long]::TryParse("$($r.Records)", [ref]$n) -or $n -le 0) { continue }
        $prov = "$($r.Provider)".ToLowerInvariant(); $type = "$($r.RecordType)".ToLowerInvariant()
        switch ($type) {
            'user' { if ($prov -eq 'entra') { $c.Users += $n; $any = $true } }
            'group' { if ($prov -eq 'entra') { $c.Groups += $n; $any = $true } }
            'service_principal' { if ($prov -eq 'entra') { $c.ServicePrincipals += $n; $any = $true } }
            'device' { if ($n -gt $c.Devices) { $c.Devices = $n }; $any = $true }
        }
    }
    if ($any) { $c } else { $null }
}

function Get-SIJobSizingCountsFromRunHealth {
    <#
        PURE. The tenant's counts from the engines' own run health (Engine, Assets = the largest run of the last 7 days):
        the identity engine's assets stand for its users + groups + service principals, the endpoint engine's for the
        devices. $null when neither engine recorded a run.
    #>
    param([object[]]$Rows = @())
    $id = 0L; $ep = 0L
    foreach ($r in @($Rows)) {
        if (-not $r) { continue }
        $n = 0L; if (-not [long]::TryParse("$($r.Assets)", [ref]$n) -or $n -le 0) { continue }
        $e = "$($r.Engine)".ToLowerInvariant()
        if ($e -match 'identity' -and $n -gt $id) { $id = $n }
        elseif ($e -match 'endpoint' -and $n -gt $ep) { $ep = $n }
    }
    if (-not $id -and -not $ep) { return $null }
    @{ Users = $id; Groups = 0L; ServicePrincipals = 0L; Devices = $ep }
}

function Get-SIJobSizingCountsFromTenantMark {
    <#
        PURE. The tenant's counts the collections recorded (cfg.InstallState 'TenantSize', engine\_shared\SI-TenantSizeMark.ps1:
        the identity / endpoint collection's own Microsoft Graph counts, read with the collection's directory rights) from
        the rows of $script:SIJobSizingTenantMarkSql (one row, Value). @{ Users; Groups; ServicePrincipals; Devices } or $null.
    #>
    param([object[]]$Rows = @())
    foreach ($r in @($Rows)) {
        if (-not $r) { continue }
        $v = if ($r -is [System.Collections.IDictionary]) { $r['Value'] } else { $r.Value }
        if ($null -eq $v -or $v -is [System.DBNull]) { continue }
        if (-not (Get-Command -Name ConvertFrom-SITenantSizeMark -ErrorAction SilentlyContinue)) { return $null }
        $m = ConvertFrom-SITenantSizeMark -Value ([string]$v)
        if ($m) { return @{ Users = [long]$m.Users; Groups = [long]$m.Groups; ServicePrincipals = [long]$m.ServicePrincipals; Devices = [long]$m.Devices } }
    }
    $null
}

function Resolve-SIJobSizingCounts {
    <#
        PURE. The tenant's counts and where they came from: @{ Counts; From }.
        Microsoft Graph, read now, is the whole answer when it can be read. Otherwise each half is taken from the first
        source that HAS it (#720, live 2026-10-16: the identity collection had written 0 users while the endpoint's records
        were there -- the rule read 0 users and kept the identity job small): the identity half (users, groups, service
        principals) from the first source with users, the devices from the first with devices, in the order: the directory
        counts the collections recorded (-Collected: cfg.InstallState 'TenantSize' -- Microsoft Graph's own counts, read by
        the identity / endpoint collection with ITS directory rights, so the updater needs none), the records the last
        collection wrote (sidata.CiRecord), the counts setup read from Microsoft Graph at install (the job tags, -Install),
        the engines' run health. A 0 is "not known", never "none". Neither half anywhere: Counts = $null.
    #>
    param([hashtable]$Graph, [hashtable]$CiRecords, [hashtable]$RunHealth, [hashtable]$Install, [hashtable]$Collected)
    if ($Graph) { return [pscustomobject]@{ Counts = $Graph; From = 'the directory (Microsoft Graph)' } }
    $srcs = @(
        [pscustomobject]@{ C = $Collected; From = 'the directory counts the collections recorded (cfg.InstallState TenantSize)' },
        [pscustomobject]@{ C = $CiRecords; From = 'the records the last collection wrote (sidata.CiRecord)' },
        [pscustomobject]@{ C = $Install; From = 'the directory counts setup read at install (the jobs'' si-tenant-* tags)' },
        [pscustomobject]@{ C = $RunHealth; From = 'the engines'' run health (SI_RunHealth_CL, last 7 days)' })
    $n = { param($h, $k) $v = 0L; if ($h -and $h.ContainsKey($k)) { [void][long]::TryParse("$($h[$k])", [ref]$v) }; $v }
    $id = @($srcs | Where-Object { $_.C -and (& $n $_.C 'Users') -gt 0 }) | Select-Object -First 1
    $dv = @($srcs | Where-Object { $_.C -and (& $n $_.C 'Devices') -gt 0 }) | Select-Object -First 1
    if (-not $id -and -not $dv) {
        # nothing with users or devices: a source that carries only groups / service principals still counts (as before)
        $any = @($srcs | Where-Object { $_.C }) | Select-Object -First 1
        if ($any) { return [pscustomobject]@{ Counts = $any.C; From = $any.From } }
        return [pscustomobject]@{ Counts = $null; From = '' }
    }
    $c = @{ Users = 0L; Groups = 0L; ServicePrincipals = 0L; Devices = 0L }
    if ($id) { $c.Users = & $n $id.C 'Users'; $c.Groups = & $n $id.C 'Groups'; $c.ServicePrincipals = & $n $id.C 'ServicePrincipals' }
    if ($dv) { $c.Devices = & $n $dv.C 'Devices' }
    $from = if ($id -and $dv -and $id.From -ne $dv.From) { 'users / groups / service principals from {0}; devices from {1}' -f $id.From, $dv.From }
            elseif ($id) { $id.From } else { $dv.From }
    [pscustomobject]@{ Counts = $c; From = $from }
}

function New-SIJobSizePatchBody {
    <#
        PURE. The ARM PATCH body that resizes a job (-Job: ARM shape, as just read), what `az containerapp job update --cpu
        --memory --replica-timeout [--set-env-vars]` did: { properties: { template: <the job's WHOLE template, the first
        container's resources.cpu / memory set, -SetEnv upserted into its env>, configuration: <only when -ReplicaTimeout
        differs: triggerType, replicaTimeout, replicaRetryLimit and the trigger's own config as read> } }. Never the secrets or
        registries (ARM returns secrets without values). The default imageType and the read-only ephemeralStorage are left
        out (the live 400 of 2026-10-06). Returns the JSON text; the input is not changed.
    #>
    # -ReplicaRetryLimit (export hotfix 2026-10-16): 0 or more = the job's retry limit set to it (the configuration is then
    # sent, its run limit as it is unless -ReplicaTimeout changes it); -1 (the default) = left as read.
    param([Parameter(Mandatory)]$Job, [Parameter(Mandatory)][string]$Cpu, [Parameter(Mandatory)][string]$Memory, [int]$ReplicaTimeout = 0, [hashtable]$SetEnv = @{}, [int]$ReplicaRetryLimit = -1)
    $tpl = ConvertTo-Json -InputObject $Job.properties.template -Depth 60 | ConvertFrom-Json
    $first = @($tpl.containers | Where-Object { $_ }) | Select-Object -First 1
    if (-not $first) { throw 'the job has no container to size' }
    $cpuNum = 0.0; [void][double]::TryParse($Cpu, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$cpuNum)
    if (-not $first.PSObject.Properties['resources'] -or -not $first.resources) { $first | Add-Member -NotePropertyName resources -NotePropertyValue ([pscustomobject]@{}) -Force }
    $first.resources | Add-Member -NotePropertyName cpu -NotePropertyValue $cpuNum -Force
    $first.resources | Add-Member -NotePropertyName memory -NotePropertyValue $Memory -Force
    if ($SetEnv.Count) {
        $envList = New-Object System.Collections.Generic.List[object]
        foreach ($e in @($first.env)) { if ($e -and -not $SetEnv.ContainsKey([string]$e.name)) { $envList.Add($e) } }
        foreach ($k in @($SetEnv.Keys | Sort-Object)) { $envList.Add([pscustomobject]@{ name = [string]$k; value = [string]$SetEnv[$k] }) }
        $first | Add-Member -NotePropertyName env -NotePropertyValue $envList.ToArray() -Force
    }
    foreach ($c in (@($tpl.containers) + @($tpl.initContainers))) {
        if (-not $c) { continue }
        if ($c.PSObject.Properties['imageType'] -and ([string]$c.imageType -in '', 'ContainerImage')) { $c.PSObject.Properties.Remove('imageType') }
        if ($c.PSObject.Properties['resources'] -and $c.resources -and $c.resources.PSObject.Properties['ephemeralStorage']) { $c.resources.PSObject.Properties.Remove('ephemeralStorage') }
    }
    $props = [ordered]@{ template = $tpl }
    $cfg = $Job.properties.configuration
    $toChange = ($ReplicaTimeout -gt 0 -and $cfg -and [int]"$($cfg.replicaTimeout)" -ne $ReplicaTimeout)
    $retryChange = ($ReplicaRetryLimit -ge 0 -and $cfg -and -not ($cfg.PSObject.Properties['replicaRetryLimit'] -and "$($cfg.replicaRetryLimit)" -ne '' -and [int]"$($cfg.replicaRetryLimit)" -eq $ReplicaRetryLimit))
    if ($toChange -or $retryChange) {
        $c2 = [ordered]@{ triggerType = [string]$cfg.triggerType; replicaTimeout = $(if ($toChange) { $ReplicaTimeout } else { [int]"$($cfg.replicaTimeout)" }) }
        if ($retryChange) { $c2.replicaRetryLimit = $ReplicaRetryLimit }
        elseif ($cfg.PSObject.Properties['replicaRetryLimit'] -and $null -ne $cfg.replicaRetryLimit) { $c2.replicaRetryLimit = $cfg.replicaRetryLimit }
        foreach ($k in 'scheduleTriggerConfig', 'manualTriggerConfig', 'eventTriggerConfig') { if ($cfg.PSObject.Properties[$k] -and $cfg.$k) { $c2[$k] = $cfg.$k } }
        $props.configuration = $c2
    }
    ConvertTo-Json -InputObject ([ordered]@{ properties = $props }) -Depth 60 -Compress
}

function ConvertFrom-SILaQueryAnswer {
    <# PURE. A Log Analytics query answer ({ tables: [ { columns: [ { name } ], rows: [ [..] ] } ] }) -> objects. #>
    param([AllowNull()]$Answer)
    if (-not $Answer -or -not $Answer.PSObject.Properties['tables']) { return @() }
    $t = @($Answer.tables)[0]; if (-not $t) { return @() }
    $cols = @($t.columns | ForEach-Object { [string]$_.name })
    foreach ($row in @($t.rows)) {
        $o = [ordered]@{}; $vals = @($row)
        for ($i = 0; $i -lt $cols.Count; $i++) { $o[$cols[$i]] = $(if ($i -lt $vals.Count) { $vals[$i] } else { $null }) }
        [pscustomobject]$o
    }
}

function Get-SIJobSizingKql {
    <# PURE. The three Log Analytics reads: RunHealthCounts | RunHealthRows | SystemLogs. #>
    param([Parameter(Mandatory)][ValidateSet('RunHealthCounts', 'RunHealthRows', 'SystemLogs')][string]$Kind)
    switch ($Kind) {
        'RunHealthCounts' { "SI_RunHealth_CL | where TimeGenerated > ago(7d) | extend Eng = tostring(column_ifexists('Engine', '')), Ph = tostring(column_ifexists('Phase', '')), Rid = tostring(column_ifexists('RunId', '')), Ac = toint(column_ifexists('AssetCount', int(-1))) | where Ph == 'End' and Ac > 0 | summarize A = sum(Ac) by Eng, Rid | summarize Assets = max(A) by Engine = Eng" }
        'RunHealthRows' { "SI_RunHealth_CL | where TimeGenerated > ago(3d) | project TimeGenerated, Engine = tostring(column_ifexists('Engine', '')), Phase = tostring(column_ifexists('Phase', '')), ExitReason = tostring(column_ifexists('ExitReason', '')), ErrorMessage = tostring(column_ifexists('ErrorMessage', '')), Execution = tostring(column_ifexists('Execution', '')) | where Phase in ('Start', 'End') | take 20000" }
        'SystemLogs' { "union isfuzzy=true ContainerAppSystemLogs_CL, ContainerAppSystemLogs | where TimeGenerated > ago(3d) | extend Job = coalesce(tostring(column_ifexists('JobName_s', '')), tostring(column_ifexists('JobName', ''))), Exec = coalesce(tostring(column_ifexists('ExecutionName_s', '')), tostring(column_ifexists('ExecutionName', ''))), Reason = coalesce(tostring(column_ifexists('Reason_s', '')), tostring(column_ifexists('Reason', ''))), Msg = coalesce(tostring(column_ifexists('Log_s', '')), tostring(column_ifexists('Log', ''))) | where Reason has 'OOMKilled' or Msg has 'OOMKilled' or Msg contains 'exit code 137' or Msg contains `"exit code '137'`" | project TimeGenerated, Job, Exec, Reason, Msg | take 500" }
    }
}

# the directory counts the identity / endpoint collections recorded (engine\_shared\SI-TenantSizeMark.ps1) -- in the Pro
# (settings) database the updater already reads; no directory right needed
$script:SIJobSizingTenantMarkSql = @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
    SELECT Value FROM cfg.InstallState WHERE Name = N'TenantSize';
ELSE
    SELECT CAST(NULL AS NVARCHAR(400)) AS Value WHERE 1 = 0;
'@

$script:SIJobSizingCiRecordSql = @'
IF OBJECT_ID('sidata.CiRecord') IS NOT NULL
    SELECT Provider, RecordType, COUNT_BIG(*) AS Records FROM sidata.CiRecord GROUP BY Provider, RecordType;
ELSE
    SELECT CAST(NULL AS NVARCHAR(32)) AS Provider, CAST(NULL AS NVARCHAR(32)) AS RecordType, CAST(0 AS BIGINT) AS Records WHERE 1 = 0;
'@

function Invoke-SIJobSizePatch {
    <#
        THE ONE WRITE of a job's size and run limit: the job read at the PATCH's own api-version, then ONE read-modify-write
        PATCH (New-SIJobSizePatchBody) with -Cpu / -Memory (neither given = as the job has them) and -ReplicaTimeout; a KEDA
        worker (-Worker) whose run limit grows gets its queue lease with it (limit + 300 s, at most 7 days).
        A RUN LIMIT ABOVE 24 HOURS THAT AZURE REFUSES (Test-SIRunLimitRefusal) is sent ONCE MORE as 24 hours with the same
        CPU and memory -- so a size raise is never lost -- and when that is accepted the refusal is remembered for the run
        (Set-SIRunLimitRefused: the next jobs ask for 24 hours at once) and said in one line. -CurrentReplicaTimeout: the
        job's run limit before the change. Returns @{ Ok; Why; ReplicaTimeout (what the job now has asked for); Lines }.
        Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$JobUri, [Parameter(Mandatory)][string]$JobName,
          [string]$Cpu, [string]$Memory, [Parameter(Mandatory)][int]$ReplicaTimeout, [int]$CurrentReplicaTimeout = 0, [switch]$Worker)
    $lines = New-Object System.Collections.Generic.List[string]
    $known = [int](Get-SIAzureKnownRunLimit)
    $to = [int](Get-SIRunLimitToSend -ReplicaTimeout $ReplicaTimeout)
    $why = ''
    try {
        $now = Invoke-SIRestJson -Rest $Rest -Uri $JobUri -What ('the job {0}' -f $JobName)
        # NEVER LOWERS: the job as it is NOW may have a longer run limit than the caller knew (the list an update read
        # before another step raised it) -- then that one is kept, and a KEDA worker's lease is not touched
        $haveNow = [int](Get-SIJobCurrentSize -Job $now).ReplicaTimeout
        if ($haveNow -gt $to) { $to = $haveNow }
        if ($haveNow -gt $CurrentReplicaTimeout) { $CurrentReplicaTimeout = $haveNow }
        if (-not $Cpu -or -not $Memory) {
            $size = Get-SIJobCurrentSize -Job $now
            if ($size.Cpu -le 0 -or -not $size.Memory) { throw 'its CPU and memory could not be read' }
            $Cpu = $size.Cpu.ToString('0.0#', [Globalization.CultureInfo]::InvariantCulture); $Memory = [string]$size.Memory
        }
        $send = {
            param([int]$Seconds)
            $setEnv = @{}
            if ($Worker -and $Seconds -gt $CurrentReplicaTimeout -and $Seconds -gt 3600) { $setEnv['SI_QUEUE_LEASE_SECONDS'] = [string]([Math]::Min(604800, $Seconds + 300)) }
            & $Rest 'PATCH' $JobUri (New-SIJobSizePatchBody -Job $now -Cpu $Cpu -Memory $Memory -ReplicaTimeout $Seconds -SetEnv $setEnv) 'https://management.azure.com/' @{ 'Content-Type' = 'application/json' }
        }
        $ok = { param($x) [bool]($x -and [int]$x.Status -ge 200 -and [int]$x.Status -lt 300) }
        $r = & $send $to
        if (-not (& $ok $r)) {
            $why = Format-SIRestFailure -Response $r
            $status = 0; try { $status = [int]$r.Status } catch { }
            # only a job that is not above 24 hours already can have been refused for it
            if ($CurrentReplicaTimeout -le $known -and (Test-SIRunLimitRefusal -ReplicaTimeout $to -Status $status -Text ([string]$r.Body))) {
                $r2 = & $send $known
                if (& $ok $r2) {
                    Set-SIRunLimitRefused
                    $lines.Add((Get-SIRunLimitRefusedLine -Job $JobName -ReplicaTimeout $to))
                    $to = $known; $why = ''
                }
            }
        }
    } catch { $why = $_.Exception.Message }
    if ($why) { $why = ("$why" -replace '\s+', ' ').Trim(); if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' } }
    [pscustomobject]@{ Ok = (-not $why); Why = $why; ReplicaTimeout = $to; Lines = $lines.ToArray() }
}

function Invoke-SIJobRunLimitHeal {
    <#
        SELF-HEALING IN THE SAME RUN (owner 2026-10-12: "si must self heal with limits"). The pipeline found that -JobName
        was stopped at its own run limit (-HitLimitSeconds) -- a job an update has not yet given the longest run limit
        Azure takes (Get-SIJobRunLimit). It gets that limit NOW, by the same value and the same write as the update's floor
        step -- Invoke-SIJobSizePatch (24 hours when Azure refuses a longer limit; a KEDA worker's queue lease in step) -- so
        the pipeline can start the step again in the same run. Only the run limit changes here, never CPU or memory.
        NO RAISE, NO RESTART: the customer's own SI_Bootstrap_ReplicaTimeout_<Engine> (-Globals) is kept; the job has the
        longest limit already; Azure took no longer limit; or this identity may not change the job (the reason says which right).
        The job's limit is ALREADY longer than the one that stopped the run (an update raised it meanwhile): nothing is
        written and the step may start again.
        Returns @{ Restart; Raised; OldSeconds; NewSeconds; Why; Lines }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$JobName, [Parameter(Mandatory)][int]$HitLimitSeconds, [hashtable]$Globals = @{}, [object[]]$Steps)
    $no = { param($why, $old) [pscustomobject]@{ Restart = $false; Raised = $false; OldSeconds = [int]$old; NewSeconds = [int]$old; Why = [string]$why; Lines = @() } }
    try {
        if (-not $PSBoundParameters.ContainsKey('Steps')) { $Steps = @(Get-SIJobSizingStepKeys) }
        $jobUri = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}?api-version={3}' -f $SubscriptionId, $ResourceGroup, $JobName, $script:SIJobSizePatchApi
        $job = Invoke-SIRestJson -Rest $Rest -Uri $jobUri -What ('the job {0}' -f $JobName)
        $cur = Get-SIJobCurrentSize -Job $job
        if ($cur.ReplicaTimeout -gt $HitLimitSeconds) {
            return [pscustomobject]@{ Restart = $true; Raised = $false; OldSeconds = $HitLimitSeconds; NewSeconds = [int]$cur.ReplicaTimeout; Why = ''; Lines = @() }
        }
        $e = Get-SIJobRunLimitJob -JobName $JobName -Steps $Steps
        $engine = if ($e) { [string]$e.Engine } else { ($JobName -replace '^(?i)caj-si-', '') -replace '-(producer|worker)$', '' }
        $limit = [int](Get-SIJobRunLimit)
        $own = Get-SIJobRunLimitSetting -Engines (@($engine) + $(if ($e) { @($e.Names) } else { @() })) -Globals $Globals
        if ($own) { return (& $no ('{0} would run for up to {1}, but {2} is set -- the customer''s run time is kept' -f $JobName, (Format-SIJobTimeout -Seconds $limit), $own) $cur.ReplicaTimeout) }
        if ($cur.ReplicaTimeout -ge $limit) { return (& $no ('{0} is the longest run limit Azure takes for a job -- the job cannot be given more time' -f (Format-SIJobTimeout -Seconds $limit)) $cur.ReplicaTimeout) }
        $p = Invoke-SIJobSizePatch -Rest $Rest -JobUri $jobUri -JobName $JobName -ReplicaTimeout $limit -CurrentReplicaTimeout $cur.ReplicaTimeout -Worker:([bool]($e -and $e.Role -eq 'worker'))
        if (-not $p.Ok) {
            return (& $no ('the pipeline could not change the job ({0}) -- its identity needs the right to change Container Apps jobs (the role "Container Apps Jobs Contributor" on the jobs'' resource group); the next update raises the limit' -f $p.Why) $cur.ReplicaTimeout)
        }
        if ($p.ReplicaTimeout -le $cur.ReplicaTimeout) {
            return [pscustomobject]@{ Restart = $false; Raised = $false; OldSeconds = [int]$cur.ReplicaTimeout; NewSeconds = [int]$cur.ReplicaTimeout; Lines = @($p.Lines)
                                      Why = ('Azure did not accept a run limit longer than {0} for this job' -f (Format-SIJobTimeout -Seconds $cur.ReplicaTimeout)) }
        }
        [pscustomobject]@{ Restart = $true; Raised = $true; OldSeconds = [int]$cur.ReplicaTimeout; NewSeconds = [int]$p.ReplicaTimeout; Why = ''; Lines = @($p.Lines) }
    } catch { & $no ('the job''s run limit could not be raised ({0})' -f $_.Exception.Message) 0 }
}

function Get-SIJobFloorChange {
    <#
        PURE. THE FLOOR every engine job is raised to on every update, for ONE job (-Job: ARM shape; -AllJobs: every job of
        the install): at least 2 CPU / 4 GiB -- a queue producer also at least its engine's single job (caj-si-<engine>) --
        and THE RUN LIMIT every engine job gets (Get-SIJobRunLimit, the longest Azure takes).
        The run limit is LEFT AS IT IS for the pipeline job (caj-si-flow: its own rule, Invoke-SIFlowJobRunLimit), for the
        hourly status report (caj-si-heartbeat, #718: 30 minutes, Get-SIHeartbeatJobRunLimit) and for a
        job whose run limit the customer set (SI_Bootstrap_ReplicaTimeout_<Engine> in -Globals; -Steps gives the engine's
        other name). Never lowers anything.
        Returns @{ Job; Action = raise | keep; Cpu; Memory; ReplicaTimeout; Was; Reasons; Line (the keep line) }.
    #>
    param([Parameter(Mandatory)]$Job, [object[]]$AllJobs = @(), [hashtable]$Globals = @{}, [object[]]$Steps = @())
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $name = [string]$Job.name
    $cur = Get-SIJobCurrentSize -Job $Job
    $was = '{0} CPU / {1}, {2}' -f $cur.Cpu.ToString('0.0#', $inv), $cur.Memory, (Format-SIJobTimeout -Seconds $cur.ReplicaTimeout)
    $fCpu = 2.0; $fMem = 4.0
    if ($name -like '*-producer') {
        $single = @(@($AllJobs) | Where-Object { $_ -and [string]$_.name -eq ($name -replace '-producer$', '') }) | Select-Object -First 1
        if ($single) { $s = Get-SIJobCurrentSize -Job $single; $fCpu = [Math]::Max($fCpu, [double]$s.Cpu); $fMem = [Math]::Max($fMem, [double]$s.MemoryGi) }
    }
    $reasons = New-Object System.Collections.Generic.List[string]
    $nCpu = [Math]::Max([double]$cur.Cpu, $fCpu); $nMem = [Math]::Max([double]$cur.MemoryGi, $fMem)
    $sizeUp = ($cur.Cpu -lt $fCpu -or $cur.MemoryGi -lt $fMem)
    if ($sizeUp) {
        if ($nMem -lt 2 * $nCpu) { $nMem = 2 * $nCpu }   # a consumption pair: memory = 2 x CPU
        $reasons.Add('every job runs with at least 2 CPU / 4 GiB')
    }
    # the run limit
    $limit = [int](Get-SIJobRunLimit); $nTo = [int]$cur.ReplicaTimeout; $kept = ''
    # #718: the hourly status report (caj-si-heartbeat) keeps its own short run limit (Get-SIHeartbeatJobRunLimit) -- a
    # 7-day limit would let one hung tick keep every later hour from reporting
    if ($name -notin @('caj-si-flow', 'caj-si-heartbeat') -and $cur.ReplicaTimeout -lt $limit) {
        $key = (($name -replace '^(?i)caj-si-', '') -replace '-(producer|worker)$', '').ToLowerInvariant()
        $names = @($key); $step = @(@($Steps) | Where-Object { $_ -and [string]$_.Key -eq $key }) | Select-Object -First 1
        if ($step -and $step.Engine -and [string]$step.Engine -ne $key) { $names += [string]$step.Engine }
        $own = Get-SIJobRunLimitSetting -Engines $names -Globals $Globals
        if ($own) { $kept = ' (its run limit is the customer''s own, {0} -- kept)' -f $own }
        else { $nTo = $limit; $reasons.Add((Get-SIJobRunLimitReason)) }
    }
    $cpuText = if ($sizeUp) { $nCpu.ToString('0.0#', $inv) } else { $cur.Cpu.ToString('0.0#', $inv) }
    $memText = if ($sizeUp) { '{0}Gi' -f $nMem.ToString($inv) } else { [string]$cur.Memory }
    $action = if ($sizeUp -or $nTo -gt $cur.ReplicaTimeout) { 'raise' } else { 'keep' }
    [pscustomobject]@{ Job = $name; Action = $action; Cpu = $cpuText; Memory = $memText; ReplicaTimeout = $nTo; SizeUp = [bool]$sizeUp; Was = $was; Reasons = $reasons.ToArray()
                       Line = ('job size: {0} runs {1}{2} -- nothing to raise' -f $name, $was, $kept) }
}

function Invoke-SIJobFloor {
    <#
        EVERY UPDATE, EVERY ENGINE JOB (every caj-si-* job of -Jobs but the updater, -UpdaterName): raised to the floor
        (Get-SIJobFloorChange) -- at least 2 CPU / 4 GiB and the run limit every engine job gets, the longest Azure takes --
        by ONE read-modify-write PATCH per job (Invoke-SIJobSizePatch: 24 hours when Azure refuses a longer run limit, said
        in one line; a KEDA worker's queue lease in step). It needs no run history and no count: a job that never finished
        a run is raised like any other. Raises only. -WhatIf: the plan only.
        ONE LINE PER JOB: "... runs 4 CPU / 8Gi, 7 days -- nothing to raise" or "... raised 2 CPU / 4Gi, 2 h -> 2 CPU /
        4Gi, 7 days -- <why>". Returns @{ Results = @(@{ Job; Action = raised | keep | would-raise | failed; Line }); Lines }.
        Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [object[]]$Jobs = @(), [string]$UpdaterName = '', [hashtable]$Globals = @{}, [switch]$WhatIf, [object[]]$Steps)
    $results = New-Object System.Collections.Generic.List[object]
    $lines = New-Object System.Collections.Generic.List[string]
    if (-not $PSBoundParameters.ContainsKey('Steps')) { $Steps = @(Get-SIJobSizingStepKeys) }
    $mine = @(@($Jobs) | Where-Object { $_ -and [string]$_.name -like 'caj-si-*' -and [string]$_.name -ne 'caj-si-updater' -and (-not $UpdaterName -or [string]$_.name -ne $UpdaterName) })
    $add = { param($job, $action, $line) $results.Add([pscustomobject]@{ Job = $job; Action = $action; Line = $line }); $lines.Add($line) }
    foreach ($j in $mine) {
        $name = [string]$j.name
        try {
            $ch = Get-SIJobFloorChange -Job $j -AllJobs $Jobs -Globals $Globals -Steps $Steps
            $cur = Get-SIJobCurrentSize -Job $j
            $text = { param([int]$Seconds) 'job size: {0} raised {1} -> {2} CPU / {3}, {4} -- {5}' -f $name, $ch.Was, $ch.Cpu, $ch.Memory, (Format-SIJobTimeout -Seconds $Seconds), ($ch.Reasons -join '; ') }
            # the run limit as it is written: 24 hours instead of a longer one once Azure refused that in this run
            $ask = [int](Get-SIRunLimitToSend -ReplicaTimeout $ch.ReplicaTimeout)
            if ($ch.Action -eq 'keep' -or (-not $ch.SizeUp -and $ask -le $cur.ReplicaTimeout)) { & $add $name 'keep' $ch.Line; continue }
            if ($WhatIf) { & $add $name 'would-raise' (((& $text ([Math]::Max($ask, $cur.ReplicaTimeout))) -replace ' raised ', ' would be raised ') + ' (re-run with -Apply)'); continue }
            $jobUri = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}?api-version={3}' -f $SubscriptionId, $ResourceGroup, $name, $script:SIJobSizePatchApi
            $p = Invoke-SIJobSizePatch -Rest $Rest -JobUri $jobUri -JobName $name -Cpu $ch.Cpu -Memory $ch.Memory -ReplicaTimeout $ch.ReplicaTimeout -CurrentReplicaTimeout $cur.ReplicaTimeout -Worker:($name -like '*-worker')
            foreach ($n in @($p.Lines)) { $lines.Add(('job size: {0}' -f $n)) }
            if (-not $p.Ok) { & $add $name 'failed' ('job size: {0} was NOT raised ({1}): {2} -- the next update tries again' -f $name, ($ch.Reasons -join '; '), $p.Why); continue }
            if (-not $ch.SizeUp -and $p.ReplicaTimeout -le $cur.ReplicaTimeout) { & $add $name 'keep' $ch.Line; continue }
            & $add $name 'raised' (& $text ([Math]::Max([int]$p.ReplicaTimeout, $cur.ReplicaTimeout)))
        } catch {
            & $add $name 'failed' ('job size: {0} was not checked ({1}) -- the next update tries again' -f $name, $_.Exception.Message)
        }
    }
    [pscustomobject]@{ Results = $results.ToArray(); Lines = $lines.ToArray() }
}

function Invoke-SIFlowJobRunLimit {
    <#
        EXISTING INSTALLS: the pipeline job (caj-si-flow, in -Jobs as the update read them) waits for every step inside its
        own execution -- its run limit is raised to Get-SIFlowJobReplicaTimeout (7 days) by ONE read-modify-write PATCH (its
        CPU and memory as they are). Raises only; SI_Bootstrap_ReplicaTimeout_Flow set by the customer: left alone; no such
        job (an install made before the pipeline): nothing. -WhatIf: the plan only.
        Returns @(@{ Job; Action = raised | would-raise | failed; Line }) -- empty when nothing is to do. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [object[]]$Jobs = @(), [hashtable]$Globals = @{}, [switch]$WhatIf)
    $name = 'caj-si-flow'
    $flow = @(@($Jobs) | Where-Object { $_ -and [string]$_.name -eq $name }) | Select-Object -First 1
    if (-not $flow) { return @() }
    try {
        if ($Globals -and $Globals.ContainsKey('SI_Bootstrap_ReplicaTimeout_Flow') -and "$($Globals['SI_Bootstrap_ReplicaTimeout_Flow'])".Trim()) { return @() }
        # 7 days -- or 24 hours once Azure refused a longer run limit in this run
        $want = [int](Get-SIRunLimitToSend -ReplicaTimeout ([int](Get-SIFlowJobReplicaTimeout)))
        $cur = Get-SIJobCurrentSize -Job $flow
        if ($cur.ReplicaTimeout -le 0 -or $cur.ReplicaTimeout -ge $want) { return @() }
        $text = { param([int]$Seconds) 'job size: {0} (the pipeline) may run for up to {1}, was {2} -- it waits for every step, so it must not end before a step does' -f $name, (Format-SIJobTimeout -Seconds $Seconds), (Format-SIJobTimeout -Seconds $cur.ReplicaTimeout) }
        if ($WhatIf) { return @([pscustomobject]@{ Job = $name; Action = 'would-raise'; Line = ((& $text $want) -replace ' may run ', ' would run ') + ' (re-run with -Apply)' }) }
        $jobUri = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}?api-version={3}' -f $SubscriptionId, $ResourceGroup, $name, $script:SIJobSizePatchApi
        $p = Invoke-SIJobSizePatch -Rest $Rest -JobUri $jobUri -JobName $name -ReplicaTimeout $want -CurrentReplicaTimeout $cur.ReplicaTimeout
        $out = @(@($p.Lines) | ForEach-Object { [pscustomobject]@{ Job = $name; Action = 'note'; Line = ('job size: {0}' -f $_) } })
        if ($p.Ok) {
            if ($p.ReplicaTimeout -gt $cur.ReplicaTimeout) { $out += [pscustomobject]@{ Job = $name; Action = 'raised'; Line = (& $text $p.ReplicaTimeout) } }
            return $out
        }
        $why = $p.Why
        return @([pscustomobject]@{ Job = $name; Action = 'failed'; Line = ('job size: {0} (the pipeline) was NOT raised to {1}: {2} -- the next update tries again' -f $name, (Format-SIJobTimeout -Seconds $want), $why) })
    } catch {
        return @([pscustomobject]@{ Job = $name; Action = 'failed'; Line = ('job size: {0} was not checked ({1}) -- the next update tries again' -f $name, $_.Exception.Message) })
    }
}

function Test-SIRaJobName {
    <# PURE. A Risk Analysis job: caj-si-risk-analysis, caj-si-risk-analysis-detailed, caj-si-ra-<name> (the extra templates). #>
    param([AllowEmptyString()][string]$Name)
    [bool]("$Name" -match '^(?i)caj-si-(risk-analysis|risk-analysis-detailed|ra-[a-z0-9-]+)$')
}

function Invoke-SIEngineJobRetryLimit {
    <#
        EVERY UPDATE, EVERY ENGINE JOB (Test-SIEngineJobName: the jobs the pipeline starts -- its steps, their producers and
        workers, every Risk Analysis job and its queue workers): the replica retry limit is 0. Live 2026-10-16: a Detailed
        run stored every report, then failed building its workbook; Azure restarted the replica in the same execution and a
        whole new 6-hour run began. Live 2026-10-23: Azure re-ran a failed data sync container in the same execution (852
        min = 504 + 347) and the vulnerability step twice (2 x 18 min). An engine run is never restarted by Azure: the
        pipeline decides what runs again. The runner (caj-si-flow), the updater and the jobs that are no step are not
        touched. -StepKeys: test seam (default the shipped map). One read-modify-write PATCH per job that still has another
        limit (New-SIJobSizePatchBody -ReplicaRetryLimit 0: its template, size and run limit as they are), then the job READ
        BACK. -WhatIf: the plan only. Returns @(@{ Job; Action = set | would-set | failed; Line }) -- empty when every job
        already has 0. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [object[]]$Jobs = @(), [string[]]$StepKeys, [switch]$WhatIf)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $StepKeys) { $StepKeys = @(Get-SIPipelineStepKeys) }
    foreach ($j in @(@($Jobs) | Where-Object { $_ -and (Test-SIEngineJobName -Name ([string]$_.name) -StepKeys $StepKeys) })) {
        $name = [string]$j.name
        try {
            $cfg = $j.properties.configuration
            $cur = if ($cfg -and $cfg.PSObject.Properties['replicaRetryLimit'] -and "$($cfg.replicaRetryLimit)" -ne '') { [int]"$($cfg.replicaRetryLimit)" } else { -1 }
            if ($cur -eq 0) { continue }
            $line = 'retry limit: {0} restarts a failed run {1} -> 0 -- an engine run is never started again by Azure; the pipeline decides' -f $name, $(if ($cur -lt 0) { '(not set)' } else { "$cur time(s)" })
            if ($WhatIf) { $out.Add([pscustomobject]@{ Job = $name; Action = 'would-set'; Line = ($line + ' (re-run with -Apply)') }); continue }
            $uri = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}?api-version={3}' -f $SubscriptionId, $ResourceGroup, $name, $script:SIJobSizePatchApi
            $now = Invoke-SIRestJson -Rest $Rest -Uri $uri -What ('the job {0}' -f $name)
            $size = Get-SIJobCurrentSize -Job $now
            if ($size.Cpu -le 0 -or -not $size.Memory) { throw 'its CPU and memory could not be read' }
            $body = New-SIJobSizePatchBody -Job $now -Cpu ($size.Cpu.ToString('0.0#', [Globalization.CultureInfo]::InvariantCulture)) -Memory ([string]$size.Memory) -ReplicaRetryLimit 0
            $r = & $Rest 'PATCH' $uri $body 'https://management.azure.com/' @{ 'Content-Type' = 'application/json' }
            if (-not ($r -and [int]$r.Status -ge 200 -and [int]$r.Status -lt 300)) { throw (Format-SIRestFailure -Response $r) }
            # read back: what Azure has now
            $back = Invoke-SIRestJson -Rest $Rest -Uri $uri -What ('the job {0}' -f $name)
            $bc = $back.properties.configuration
            $got = if ($bc -and $bc.PSObject.Properties['replicaRetryLimit'] -and "$($bc.replicaRetryLimit)" -ne '') { [int]"$($bc.replicaRetryLimit)" } else { -1 }
            if ($got -ne 0) { throw ('Azure accepted the change but the job reads back {0}' -f $(if ($got -lt 0) { 'no retry limit' } else { $got })) }
            $out.Add([pscustomobject]@{ Job = $name; Action = 'set'; Line = $line })
        } catch {
            $why = ("$($_.Exception.Message)" -replace '\s+', ' ').Trim(); if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
            $out.Add([pscustomobject]@{ Job = $name; Action = 'failed'; Line = ('retry limit: {0} was NOT set to 0 ({1}) -- the next update tries again' -f $name, $why) })
        }
    }
    $out.ToArray()   # unrolled: callers wrap the call in @()
}

function Invoke-SIJobSizing {
    <#
        EXISTING INSTALLS: apply the job sizing rule to the jobs of -ResourceGroup. -Jobs: the job list (ARM shape) the update
        already read. -Rest: the update's REST seam (setup/_shared/SI-UpdateRest.ps1). -SqlRows { param([string]$Sql) } -> rows
        from the Pro database ($null = no Pro database). -WorkspaceResourceId: the run health and the Container Apps system
        logs. -Globals: the customer's settings. -WhatIf: plan only.
        Covers the collection / CI build / Risk Analysis / data jobs (Get-SIJobSizingEngine) for CPU AND MEMORY, and the
        pipeline job itself for its run limit (7 days). An engine job's RUN LIMIT is not sized: the update's floor step
        gives every one of them the same value (Invoke-SIJobFloor).
        Returns @{ Results = @(@{ Job; Action = raised | keep | would-raise | failed; Line }); Lines; CountsFrom }. NEVER throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [object[]]$Jobs = @(), [hashtable]$Globals = @{}, [scriptblock]$SqlRows, [string]$WorkspaceResourceId, [switch]$WhatIf)
    $results = New-Object System.Collections.Generic.List[object]
    $lines = New-Object System.Collections.Generic.List[string]
    $cnt = [pscustomobject]@{ Counts = $null; From = '' }
    $arm = 'https://management.azure.com/'
    $flowDone = @(Invoke-SIFlowJobRunLimit -Rest $Rest -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Jobs $Jobs -Globals $Globals -WhatIf:$WhatIf)
    $sized = @(@($Jobs) | Where-Object { $_ -and (Get-SIJobSizingEngine -JobName ([string]$_.name)) })
    if (-not $sized.Count) {
        $lines.Add('job size: no collection, CI build or Risk Analysis job in this install -- nothing to size')
        foreach ($f in $flowDone) { $results.Add($f); $lines.Add([string]$f.Line) }
        return [pscustomobject]@{ Results = $results.ToArray(); Lines = $lines.ToArray(); CountsFrom = '' }
    }
    $la = {
        param([string]$Kql)
        if (-not $WorkspaceResourceId) { return @() }
        try {
            $url = 'https://management.azure.com{0}/api/query?api-version=2017-10-01' -f $WorkspaceResourceId.TrimEnd('/')
            return @(ConvertFrom-SILaQueryAnswer (Invoke-SIRestJson -Rest $Rest -Method POST -Uri $url -Body (ConvertTo-Json -InputObject ([ordered]@{ query = $Kql }) -Compress) -What 'the Log Analytics query'))
        } catch { return @() }
    }
    try {
        # ---- the tenant's counts: Graph, else the Pro database's records, else the run health ----
        $graph = $null; try { $graph = Get-SISqlTierTenantCounts -Rest $Rest -SubscriptionId $SubscriptionId } catch { $graph = $null }
        $ci = $null; $coll = $null
        if (-not $graph -and $SqlRows) {
            # the directory counts the collections recorded with their own directory rights (cfg.InstallState 'TenantSize')
            try { $coll = Get-SIJobSizingCountsFromTenantMark -Rows @(& $SqlRows $script:SIJobSizingTenantMarkSql) }
            catch { $coll = $null; $lines.Add(('job size: the tenant size the collections recorded could not be read from the Pro database ({0})' -f (("$($_.Exception.Message)" -replace '\s+', ' ').Trim()))) }
            # a read that fails is said (it was silent: an install whose records could not be read looked like one with none)
            try { $ci = Get-SIJobSizingCountsFromCiRecords -Rows @(& $SqlRows $script:SIJobSizingCiRecordSql) }
            catch { $ci = $null; $lines.Add(('job size: the records in the Pro database could not be read for the tenant''s size ({0})' -f (("$($_.Exception.Message)" -replace '\s+', ' ').Trim()))) }
        }
        # #720: the counts setup read at install, kept on the jobs (si-tenant-* tags) -- the list this update already read
        $inst = $null
        if (-not $graph) { try { $inst = ConvertFrom-SITenantSizeTags -Jobs $Jobs } catch { $inst = $null } }
        # each half (identity objects, devices) from the first source that has it -- the run health only when a half is missing
        $hasHalf = { param($h, $k) $v = 0L; [bool]($h -and $h.ContainsKey($k) -and [long]::TryParse("$($h[$k])", [ref]$v) -and $v -gt 0) }
        $rhc = $null
        $idKnown = (& $hasHalf $coll 'Users') -or (& $hasHalf $ci 'Users') -or (& $hasHalf $inst 'Users')
        $devKnown = (& $hasHalf $coll 'Devices') -or (& $hasHalf $ci 'Devices') -or (& $hasHalf $inst 'Devices')
        if (-not $graph -and -not ($idKnown -and $devKnown)) {
            $rhc = Get-SIJobSizingCountsFromRunHealth -Rows @(& $la (Get-SIJobSizingKql -Kind RunHealthCounts))
        }
        $cnt = Resolve-SIJobSizingCounts -Graph $graph -CiRecords $ci -RunHealth $rhc -Install $inst -Collected $coll
        if ($cnt.Counts) {
            $c = $cnt.Counts; $inv = [Globalization.CultureInfo]::InvariantCulture
            $lines.Add(('job size: tenant size from {0}: {1} users, {2} groups, {3} service principals, {4} devices' -f $cnt.From,
                ([long]$c.Users).ToString('N0', $inv), ([long]$c.Groups).ToString('N0', $inv), ([long]$c.ServicePrincipals).ToString('N0', $inv), ([long]$c.Devices).ToString('N0', $inv)))
            $miss = @()
            if (-not (Test-SIJobSizingCountKnown -Engine identity -Counts $c)) { $miss += 'users' }
            if (-not (Test-SIJobSizingCountKnown -Engine endpoint -Counts $c)) { $miss += 'devices' }
            if ($miss.Count) { $lines.Add(('job size: the tenant''s {0} could not be read -- the jobs that count them are sized for a large tenant (4 CPU / 8 GiB)' -f ($miss -join ' and '))) }
        } else {
            $lines.Add('job size: the tenant''s size could not be read (no directory read, no counts recorded by the collections, no records in the Pro database, no counts from setup on the jobs, no run health) -- every sized job is sized for a large tenant (4 CPU / 8 GiB)')
        }
        # ---- the last runs: Container Apps system logs + run health, read once ----
        $sysRows = @(& $la (Get-SIJobSizingKql -Kind SystemLogs))
        $rhRows = @(& $la (Get-SIJobSizingKql -Kind RunHealthRows))
        foreach ($j in $sized) {
            $name = [string]$j.name; $e = Get-SIJobSizingEngine -JobName $name
            try {
                $cur = Get-SIJobCurrentSize -Job $j
                # the job's executions: how its LAST run ended (CPU and memory go up one band after an out-of-memory run or a
                # run stopped at its run limit). A list that cannot be read is no signal -- the counts still size the job.
                $execs = New-Object System.Collections.Generic.List[object]
                $exUri = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}/executions?api-version={3}' -f $SubscriptionId, $ResourceGroup, $name, $script:SIJobSizeArmApi
                $pages = 0
                while ($exUri -and $pages -lt 20) {
                    $pages++; $ex = $null
                    try { $ex = Invoke-SIRestJson -Rest $Rest -Uri $exUri -What ('the executions of {0}' -f $name) } catch { $ex = $null }
                    if (-not $ex) { break }
                    if ($ex.PSObject.Properties['value']) { foreach ($x in @($ex.value)) { if ($x) { $execs.Add($x) } } }
                    $exUri = if ($ex.PSObject.Properties['nextLink'] -and $ex.nextLink) { [string]$ex.nextLink } else { '' }
                }
                $execs = $execs.ToArray()
                $fail = Get-SIJobFailureSignal -JobName $name -Engine $e.Engine -ReplicaTimeout $cur.ReplicaTimeout -Executions $execs -SystemLogRows $sysRows -RunHealthRows $rhRows
                $ch = Get-SIJobSizeChange -JobName $name -Engine $e.Engine -Current $cur -Counts $cnt.Counts -CountsFrom $cnt.From -Failure $fail -Globals $Globals
                foreach ($n in @($ch.Notes)) { $lines.Add(('job size: {0}' -f $n)) }
                if ($ch.Action -eq 'keep') { $results.Add([pscustomobject]@{ Job = $name; Action = 'keep'; Line = '' }); continue }
                if ($WhatIf) { $l = $ch.Line -replace ' raised ', ' would be raised '; $l += ' (re-run with -Apply)'; $results.Add([pscustomobject]@{ Job = $name; Action = 'would-raise'; Line = $l }); $lines.Add($l); continue }
                # READ-MODIFY-WRITE at ONE api-version: the job as it is now, its whole template back with the new CPU and
                # memory. The run limit is not changed here (Invoke-SIJobSizePatch keeps what the job has now).
                $jobUri = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}?api-version={3}' -f $SubscriptionId, $ResourceGroup, $name, $script:SIJobSizePatchApi
                $p = Invoke-SIJobSizePatch -Rest $Rest -JobUri $jobUri -JobName $name -Cpu $ch.Cpu -Memory $ch.Memory -ReplicaTimeout $cur.ReplicaTimeout -CurrentReplicaTimeout $cur.ReplicaTimeout -Worker:($e.Role -eq 'worker')
                foreach ($n in @($p.Lines)) { $lines.Add(('job size: {0}' -f $n)) }
                if ($p.Ok) { $results.Add([pscustomobject]@{ Job = $name; Action = 'raised'; Line = $ch.Line }); $lines.Add($ch.Line) }
                else {
                    $l = ('job size: {0} was NOT raised ({1}): {2} -- the next update tries again' -f $name, ($ch.Reasons -join '; '), [string]$p.Why)
                    $results.Add([pscustomobject]@{ Job = $name; Action = 'failed'; Line = $l }); $lines.Add($l)
                }
            } catch {
                $l = ('job size: {0} was not checked ({1}) -- the next update tries again' -f $name, $_.Exception.Message)
                $results.Add([pscustomobject]@{ Job = $name; Action = 'failed'; Line = $l }); $lines.Add($l)
            }
        }
        if (-not @($results | Where-Object { $_.Action -ne 'keep' }).Count) { $lines.Add(('job size: every sized job ({0}) already has the CPU and memory the rule gives -- nothing changed' -f $sized.Count)) }
    } catch {
        $lines.Add(('job size: not checked ({0}) -- the update goes on; the next update tries again' -f $_.Exception.Message))
    }
    foreach ($f in $flowDone) { $results.Add($f); $lines.Add([string]$f.Line) }
    [pscustomobject]@{ Results = $results.ToArray(); Lines = $lines.ToArray(); CountsFrom = $cnt.From }
}

# THE WEB APP'S SIZE. What setup gives a new install (pro-management/deploy/Deploy-SIManagement.ps1 -Cpu / -Memory), and what
# every update SETS an existing install's web app to. History: 0.5 CPU / 1 GiB; 1 CPU / 2 GiB (owner 2026-10-11: "why is the
# performance so bad"); 4 CPU / 8 GiB (owner 2026-10-12: "make sure al ring 1+2 customers are running on web app 4 cpu/8 gb");
# 2 CPU / 4 GiB since 2026-10-18 (owner: "reduce web app to 2cpus 4 gb ram" -- 7 days of telemetry: the web app used at most
# 0.1 CPU / 0.5 GiB of its 4 CPU / 8 GiB).
# The update raises a smaller web app and LOWERS one on the product's own earlier default (4 CPU / 8 GiB, or 3.75 / 7.5 GiB:
# that default less the sign-in front's share); any other larger size is the customer's and is kept. A size the customer set
# (SI_Bootstrap_WebAppCpu / SI_Bootstrap_WebAppMemory) wins in both directions. Only the web app's own container (the first) is
# sized: the sign-in front sidecar (0.25 CPU / 0.5 GiB) and the MCP server keep theirs.
$script:SIWebAppCpu = 2.0
$script:SIWebAppMemoryGi = 4.0
# the product's own earlier defaults that the update lowers (CPU, GiB) -- the 4 / 8 of 2026-10-12, alone or behind the front
$script:SIWebAppEarlierDefaults = @(@(4.0, 8.0), @(3.75, 7.5))
# what one revision of a Consumption container app may hold (all its containers together)
$script:SIWebAppMaxCpu = 4.0
$script:SIWebAppMaxMemoryGi = 8.0
$script:SIWebAppArmApi = '2025-07-01'

function Get-SIWebAppSizeSetting {
    <#
        PURE. The web app size the customer set: -Cpu (SI_Bootstrap_WebAppCpu, '1.5') and/or -Memory (SI_Bootstrap_WebAppMemory,
        '3Gi' or '3'). One of them is enough: the other is the pair Container Apps takes (memory = 2 x CPU). CPU from 0.5 to 4
        in steps of 0.25. Returns @{ Set; Cpu; MemoryGi; Note } -- Set = $false (with a Note when something unusable was set)
        means: the product's rule.
    #>
    param([AllowNull()]$Cpu, [AllowNull()]$Memory)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $ct = "$Cpu".Trim().Trim('"').Trim(); $mt = "$Memory".Trim().Trim('"').Trim()
    $none = { param($n) [pscustomobject]@{ Set = $false; Cpu = 0.0; MemoryGi = 0.0; Note = $n } }
    if (-not $ct -and -not $mt) { return (& $none '') }
    $c = 0.0; $m = 0.0
    if ($ct -and -not [double]::TryParse($ct, [Globalization.NumberStyles]::Float, $inv, [ref]$c)) { $c = -1.0 }
    if ($mt) { $m = ConvertTo-SIJobMemoryGi $mt; if ($m -le 0) { $m = -1.0 } }
    if ($c -lt 0 -or $m -lt 0) { return (& $none ("the web app size that was set (CPU '{0}', memory '{1}') is not a number -- the product's size applies" -f $ct, $mt)) }
    if ($c -le 0) { $c = $m / 2 }
    if ($m -le 0) { $m = 2 * $c }
    # a pair Container Apps takes: the larger of the two decides
    if ($m -lt 2 * $c) { $m = 2 * $c } elseif ($c -lt $m / 2) { $c = $m / 2 }
    if ($c -lt 0.5 -or $c -gt $script:SIWebAppMaxCpu -or ([Math]::Round($c * 4) -ne $c * 4)) {
        return (& $none ("the web app size that was set ({0} CPU / {1} GiB) is not one Container Apps takes (0.5 to 4 CPU in steps of 0.25, memory 2 x CPU) -- the product's size applies" -f $c.ToString($inv), $m.ToString($inv)))
    }
    [pscustomobject]@{ Set = $true; Cpu = $c; MemoryGi = $m; Note = '' }
}

function New-SIWebAppSizePatchBody {
    <#
        PURE. The ARM PATCH body that sizes a container app's web container (-App: ARM shape, as just read; the FIRST container):
        its WHOLE template as read (a template PATCH replaces the container list) with the first container's cpu / memory set,
        the revision suffix dropped (a reused suffix is refused), the default imageType and the read-only ephemeralStorage left
        out. Never the configuration (ARM returns secrets without values). Every other container (the sign-in front) is sent
        exactly as read.
        The size: -CustomerSet = exactly -Cpu / -MemoryGi, both ways. Otherwise the product's rule: a smaller web container is
        raised to at least -Cpu / -MemoryGi (memory = 2 x CPU), one on the product's earlier default ($script:SIWebAppEarlierDefaults)
        is lowered to it, any other larger size is the customer's and kept. All containers together stay within one revision's
        4 CPU / 8 GiB (the web container gives up what the others take). $null when nothing changes.
    #>
    param([Parameter(Mandatory)]$App, [Alias('MinCpu')][double]$Cpu = $script:SIWebAppCpu, [Alias('MinMemoryGi')][double]$MemoryGi = $script:SIWebAppMemoryGi,
          [switch]$CustomerSet)
    # (the current size is $have / $haveMem: PowerShell names are case-insensitive, $cpu would overwrite -Cpu)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $tpl = ConvertTo-Json -InputObject $App.properties.template -Depth 60 | ConvertFrom-Json
    $first = @($tpl.containers | Where-Object { $_ }) | Select-Object -First 1
    if (-not $first) { throw 'the web app has no container to size' }
    $have = 0.0; $haveMem = 0.0
    if ($first.PSObject.Properties['resources'] -and $first.resources) {
        try { $have = [double]::Parse([string]$first.resources.cpu, $inv) } catch { $have = 0.0 }
        $haveMem = ConvertTo-SIJobMemoryGi ([string]$first.resources.memory)
    }
    # CR7: a second container in the same revision (the shared sign-in front) keeps its own size; the web container takes
    # what is left of one revision when the total would pass it (a revision of 4.25 CPU is refused on Consumption)
    $oCpu = 0.0; $oMem = 0.0
    foreach ($o in @(@($tpl.containers | Where-Object { $_ }) | Select-Object -Skip 1)) {
        if (-not ($o.PSObject.Properties['resources'] -and $o.resources)) { continue }
        try { $oCpu += [double]::Parse([string]$o.resources.cpu, $inv) } catch { }
        $oMem += ConvertTo-SIJobMemoryGi ([string]$o.resources.memory)
    }
    $tCpu = [Math]::Max(0.25, [Math]::Min($Cpu, $script:SIWebAppMaxCpu - $oCpu)); $tMem = [Math]::Max(0.5, [Math]::Min($MemoryGi, $script:SIWebAppMaxMemoryGi - $oMem))
    if ($CustomerSet) {
        if ($have -eq $tCpu -and $haveMem -eq $tMem) { return $null }
        $nCpu = $tCpu; $nMem = $tMem
    } elseif ($have -lt $tCpu -or $haveMem -lt $tMem) {
        # raise: the larger of now and the rule, as a pair Container Apps takes
        $nCpu = [Math]::Max($have, $tCpu); $nMem = [Math]::Max($haveMem, $tMem)
        if ($nMem -lt 2 * $nCpu) { $nMem = 2 * $nCpu }
        if ($nCpu -lt $nMem / 2) { $nCpu = $nMem / 2 }
    } elseif (($have -gt $tCpu -or $haveMem -gt $tMem) -and @($script:SIWebAppEarlierDefaults | Where-Object { $have -eq $_[0] -and $haveMem -eq $_[1] }).Count) {
        # lower: the product's own earlier default only
        $nCpu = $tCpu; $nMem = $tMem
    } else { return $null }
    if (-not $first.PSObject.Properties['resources'] -or -not $first.resources) { $first | Add-Member -NotePropertyName resources -NotePropertyValue ([pscustomobject]@{}) -Force }
    $first.resources | Add-Member -NotePropertyName cpu -NotePropertyValue $nCpu -Force
    $first.resources | Add-Member -NotePropertyName memory -NotePropertyValue ('{0}Gi' -f $nMem.ToString($inv)) -Force
    foreach ($c in (@($tpl.containers) + @($tpl.initContainers))) {
        if (-not $c) { continue }
        if ($c.PSObject.Properties['imageType'] -and ([string]$c.imageType -in '', 'ContainerImage')) { $c.PSObject.Properties.Remove('imageType') }
        if ($c.PSObject.Properties['resources'] -and $c.resources -and $c.resources.PSObject.Properties['ephemeralStorage']) { $c.resources.PSObject.Properties.Remove('ephemeralStorage') }
    }
    if ($tpl.PSObject.Properties['revisionSuffix']) { $tpl.PSObject.Properties.Remove('revisionSuffix') }
    ConvertTo-Json -InputObject ([ordered]@{ properties = [ordered]@{ template = $tpl } }) -Depth 60 -Compress
}

function Invoke-SIWebAppSize {
    <#
        Every update: the Pro web app (-Name, a container app in -ResourceGroup) set to the product's size (2 CPU / 4 GiB:
        a smaller one raised, one on the product's earlier 4 CPU / 8 GiB lowered, any other larger size kept) -- or to the size
        the customer set (-Cpu / -Memory: SI_Bootstrap_WebAppCpu / SI_Bootstrap_WebAppMemory, both ways) -- by ONE
        read-modify-write ARM PATCH of the web container only, then its new revision waited for (up to -WaitSeconds) so the web
        app roll that follows is not refused as an operation in flight, and the size read back. No such app (Community, or not
        deployed yet): nothing to do. -WhatIf: the plan only. Returns @{ Action = raise | lower | keep | none | plan | failed;
        Lines }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$Name = 'ca-si-management', [AllowNull()]$Cpu, [AllowNull()]$Memory, [int]$WaitSeconds = 300, [int]$PollSeconds = 10, [switch]$WhatIf)
    $lines = New-Object System.Collections.Generic.List[string]
    $uri = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/containerApps/{2}?api-version={3}' -f $SubscriptionId, $ResourceGroup, $Name, $script:SIWebAppArmApi
    try {
        $want = Get-SIWebAppSizeSetting -Cpu $Cpu -Memory $Memory
        if ($want.Note) { $lines.Add(('web app size: {0}' -f $want.Note)) }
        $app = Invoke-SIRestJson -Rest $Rest -Uri $uri -AllowNotFound -What ('the web app {0}' -f $Name)
        if (-not $app) { $lines.Add(('web app size: no web app {0} in this install -- nothing to size' -f $Name)); return [pscustomobject]@{ Action = 'none'; Lines = $lines.ToArray() } }
        $first = @($app.properties.template.containers | Where-Object { $_ }) | Select-Object -First 1
        $cur = '{0} CPU / {1}' -f $first.resources.cpu, $first.resources.memory
        $whose = if ($want.Set) { 'the size this install set' } else { 'the product''s size' }
        $body = if ($want.Set) { New-SIWebAppSizePatchBody -App $app -Cpu $want.Cpu -MemoryGi $want.MemoryGi -CustomerSet } else { New-SIWebAppSizePatchBody -App $app }
        if (-not $body) { $lines.Add(('web app size: {0} runs {1} -- kept ({2})' -f $Name, $cur, $(if ($want.Set) { $whose } else { 'the product''s size, or a size the customer chose' }))); return [pscustomobject]@{ Action = 'keep'; Lines = $lines.ToArray() } }
        $res = ($body | ConvertFrom-Json).properties.template.containers[0].resources
        $to = '{0} CPU / {1}' -f $res.cpu, $res.memory
        $inv = [Globalization.CultureInfo]::InvariantCulture
        $curCpu = 0.0; try { $curCpu = [double]::Parse([string]$first.resources.cpu, $inv) } catch { }
        $down = ([double]$res.cpu -lt $curCpu -or (ConvertTo-SIJobMemoryGi ([string]$res.memory)) -lt (ConvertTo-SIJobMemoryGi ([string]$first.resources.memory)))
        $verb = if ($down) { 'lowered' } else { 'raised' }
        if ($WhatIf) { $lines.Add(('web app size: {0} would be {1} from {2} to {3}, {4} (re-run with -Apply)' -f $Name, $verb, $cur, $to, $whose)); return [pscustomobject]@{ Action = 'plan'; Lines = $lines.ToArray() } }
        $r = & $Rest 'PATCH' $uri $body 'https://management.azure.com' @{ 'Content-Type' = 'application/json' }
        $code = 0; try { $code = [int]$r.Status } catch { }
        if ($code -lt 200 -or $code -ge 300) {
            $lines.Add(('web app size: {0} was NOT {1} ({2}) -- the next update tries again' -f $Name, $verb, (Format-SIRestFailure -Response $r)))
            return [pscustomobject]@{ Action = 'failed'; Lines = $lines.ToArray() }
        }
        # the new revision: provisioned before the web app roll patches the app again; then the size read back
        $state = ''; $now = $null
        $deadline = [datetime]::UtcNow.AddSeconds([Math]::Max(0, $WaitSeconds))
        do {
            try { $now = Invoke-SIRestJson -Rest $Rest -Uri $uri -What ('the web app {0}' -f $Name); $state = [string]$now.properties.provisioningState } catch { $state = '' }
            if ($state -in 'Succeeded', 'Failed', 'Canceled') { break }
            if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
        } while ([datetime]::UtcNow -lt $deadline)
        $back = ''
        try {
            $nf = @($now.properties.template.containers | Where-Object { $_ }) | Select-Object -First 1
            if ($nf -and $nf.resources -and ([double]::Parse([string]$nf.resources.cpu, $inv) -ne [double]$res.cpu -or (ConvertTo-SIJobMemoryGi ([string]$nf.resources.memory)) -ne (ConvertTo-SIJobMemoryGi ([string]$res.memory)))) {
                $back = (' -- read back {0} CPU / {1}, the next update checks again' -f $nf.resources.cpu, $nf.resources.memory)
            }
        } catch { }
        $lines.Add(('web app size: {0} {1} from {2} to {3}, {4}{5}{6}' -f $Name, $verb, $cur, $to, $whose, $(if ($state -eq 'Succeeded') { '' } else { " -- its new revision is still $(if ($state) { $state } else { 'provisioning' })" }), $back))
        [pscustomobject]@{ Action = $(if ($down) { 'lower' } else { 'raise' }); Lines = $lines.ToArray() }
    } catch {
        $lines.Add(('web app size: {0} could not be checked ({1}) -- the update goes on; the next update tries again' -f $Name, $_.Exception.Message))
        [pscustomobject]@{ Action = 'failed'; Lines = $lines.ToArray() }
    }
}
