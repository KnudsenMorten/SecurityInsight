#Requires -Version 5.1
<#
    Per-shard heartbeat to LA. Emits one row to SI_RunHealth_CL at the
    Start of every replica run, and a second row at End -- success or
    failure. The MISSING end-row is itself the signal that a replica
    OOM'd / got killed before it could finish (KQL: where Phase=='Start'
    | join kind=leftanti (... where Phase=='End') on RunId, ShardIndex).

    Best-effort: any failure to ship the heartbeat is swallowed (silent),
    because telemetry must NEVER kill the run it's measuring.

    Schema:
      RunId, Engine, ShardIndex, ShardCount, Phase=Start|End,
      AssetCount, PeakWorkingSetMB, DurationSec, ExitReason,
      ErrorMessage, Computer, CollectionTime
#>
# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

# SI's log-ingest wrappers (Send-SILogData, Update-SILogTableSchema, Get-SIDceList, ...): plain REST,
# no PowerShell modules. Loaded once; a caller that already has them keeps its own.
if (-not (Get-Command -Name Send-SILogData -ErrorAction SilentlyContinue)) {
    . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared/SI-LogIngest.ps1')
}

# #226 -- the telemetry run report goes out at this same END moment (Send-SITelemetryRunEnd, from the finally below).
# Loading it must never break the run-health record: a missing or broken file only means no telemetry.
if (-not (Get-Command -Name Send-SITelemetryRunEnd -ErrorAction SilentlyContinue)) {
    try { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared/SI-TelemetrySend.ps1') } catch { }
}
# #277 -- the guard events (Send-SIGuardEvent): every engine that records its run health can report a tripped guard.
if (-not (Get-Command -Name Send-SIGuardEvent -ErrorAction SilentlyContinue)) {
    try { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared/SI-Guard.ps1') } catch { }
}

# #532 -- THROTTLE-IS-NORMAL (framework §12.18): a run that failed ONLY because Microsoft throttled it (429 / 5xx /
# timeouts) and wrote nothing ends 'throttled', not 'error'; the one "stuck" alert. Loading it must never break the record.
if (-not (Get-Command -Name Resolve-SIThrottledExitReason -ErrorAction SilentlyContinue)) {
    try { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared/SI-Throttle.ps1') } catch { }
}

function Resolve-SIRunHealthExitReason {
    <# PURE. The END record's ExitReason (#532): 'error' becomes 'throttled' when every failure the message names is
       throttling / service-side, and the run wrote nothing:
         * a COLLECTING engine (it reads Microsoft's services and writes its result in one output stage at the end:
           the profilers, the tier classifier, schema discovery, the trend) that did not fail in a stage that writes
           (RunContext.FailedStep) and did not say it wrote part of its result (RunContext.WrotePartial);
         * any other engine (one that APPLIES changes -- SQL, ServiceNow, Defender, the data sync) ONLY when it says so
           itself (RunContext.WroteNothing = $true): a partial apply is a real failure, so it is never assumed.
       Risk Analysis is not in the list: it publishes report by report, and a throttled query already ends its run
       'success-partial' (a warning, its findings unknown). Every other value is returned as given. #>
    param([AllowNull()]$RunContext, [AllowEmptyString()][string]$ExitReason, [AllowEmptyString()][string]$ErrorMessage)
    if (-not (Get-Command -Name Resolve-SIThrottledExitReason -ErrorAction SilentlyContinue)) { return $ExitReason }
    $step = ''; $partial = $false; $nothing = $false; $engine = ''
    if ($RunContext) {
        if ($RunContext.PSObject.Properties['Engine']) { $engine = ([string]$RunContext.Engine).Trim().ToLowerInvariant() }
        if ($RunContext.PSObject.Properties['FailedStep']) { $step = [string]$RunContext.FailedStep }
        if ($RunContext.PSObject.Properties['WrotePartial']) { $partial = [bool]$RunContext.WrotePartial }
        if ($RunContext.PSObject.Properties['WroteNothing']) { $nothing = [bool]$RunContext.WroteNothing }
    }
    $collecting = @('endpoint', 'identity', 'azure', 'publicip', 'privilege-tier-classifier', 'schema-discovery', 'asset-trend', 'trend') -contains $engine
    if (-not $collecting -and -not $nothing) { return $ExitReason }
    Resolve-SIThrottledExitReason -ExitReason $ExitReason -ErrorMessage $ErrorMessage -FailedStep $step -WrotePartial:$partial
}

# #276 -- the dry-run lines (Get-SIDryRunNoticeText). Loading it must never break the run-health record either.
if (-not (Get-Command -Name Get-SIDryRunNoticeText -ErrorAction SilentlyContinue)) {
    try { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared/SI-FirstRun.ps1') } catch { }
}

function Get-SIRunHealthDryRunRow {
    <#
        PURE. #276: what a DRY RUN's run-health row says. A dry run publishes nothing, but its health row IS written so the
        run-health views show that the run happened and was a dry run: the End record's ExitReason is 'dry-run' when the
        run itself went well (success / success-partial / nothing given), and a failure keeps its own reason so a broken
        dry run is still a failure. The message always starts with 'dry run'.
    #>
    param([Parameter(Mandatory)][ValidateSet('Start', 'End')][string]$Phase, [AllowEmptyString()][string]$ExitReason, [AllowEmptyString()][string]$ErrorMessage)
    $x = "$ExitReason".Trim()
    $reason = $x
    if ($Phase -eq 'End' -and ($x -eq '' -or $x -in @('success', 'success-partial'))) { $reason = 'dry-run' }
    $msg = 'dry run -- nothing was published or sent'
    if ("$ErrorMessage".Trim()) { $msg = $msg + '; ' + "$ErrorMessage".Trim() }
    [pscustomobject]@{ ExitReason = $reason; ErrorMessage = $msg }
}

function Test-SIRunHealthDcrReachable {
    <#
        Pre-flight: verify the SI_RunHealth DCR's dataCollectionEndpointId
        matches the DCE the engine is configured to use. Returns:

          $true  -- safe to post (association OK, DCR not yet created,
                    DCR uses workspace-default ingestion, or pre-flight
                    inconclusive for any reason).
          $false -- CONFIRMED mismatch; skip the post to avoid the
                    PS>TerminatingError(...) transcript markers that the
                    AzLogDcrIngestPS module's Invoke-WebRequest would
                    otherwise emit when the Log Ingestion API rejects
                    the post with "DCE FQDN is not associated with DCR".

        v2.2.382 -- added because the actual post failure is caught
        engine-side (Send-SIRunHealthRow has try/catch + Write-Verbose),
        but PowerShell 7's transcript engine writes the terminating-error
        marker BEFORE the catch handler runs, so it cannot be suppressed
        from inside Send-SIRunHealthRow. Detecting the mismatch up-front
        via Az.Accounts/Invoke-AzRestMethod (which never throws on non-2xx)
        lets us skip the noisy call cleanly. Pre-flight failures
        (network/auth/anything) return $true so we never suppress
        telemetry for the wrong reason.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$DcrResourceGroup,
        [Parameter(Mandatory)][string]$DcrName,
        [string]$DceResourceGroup,
        [string]$DceName
    )

    # Engine config incomplete (no DCE known) -> can't compare. Proceed.
    if ([string]::IsNullOrWhiteSpace($DceName) -or [string]::IsNullOrWhiteSpace($DceResourceGroup)) { return $true }

    try {
        $dcrPath = ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Insights/dataCollectionRules/{2}?api-version=2023-03-11' -f `
                        $SubscriptionId, $DcrResourceGroup, $DcrName)
        $resp = Invoke-SIAzRestMethod -Path $dcrPath -Method GET -ErrorAction SilentlyContinue 4>$null 2>$null
        if (-not $resp -or [int]$resp.StatusCode -ne 200) {
            # DCR not reachable / does not exist yet / RBAC drift -- let the
            # actual call attempt creation via CheckCreateUpdate-TableDcr-Structure.
            return $true
        }
        $dcrBody = $null
        try { $dcrBody = $resp.Content | ConvertFrom-Json -ErrorAction Stop } catch { return $true }
        $boundDceId = [string]$dcrBody.properties.dataCollectionEndpointId
        if ([string]::IsNullOrWhiteSpace($boundDceId)) {
            # DCR uses workspace-default ingestion (no explicit DCE) -- post will work.
            return $true
        }
        $expectedDceId = ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Insights/dataCollectionEndpoints/{2}' -f `
                            $SubscriptionId, $DceResourceGroup, $DceName)
        if ($boundDceId -ieq $expectedDceId) { return $true }

        # #198 -- SAID ONCE, OUT LOUD. This was Write-Verbose, so a mismatched rule dropped every run-health
        # record silently: measured 2026-10-01, SI_RunHealth_CL held 0 rows in 30 days, and nothing that reads
        # it (crash detection, "was the run complete") could work. The post is still skipped -- it would fail --
        # but the run now says so, once, with the fix.
        if (-not $global:SI_RunHealthMismatchWarned) {
            $global:SI_RunHealthMismatchWarned = $true
            Write-Warning ("Run-health records are not being saved: the data collection rule '{0}' sends to a different data collection endpoint ({1}) than this install uses ({2}). Point `$global:SI_RunHealth_DcrName at a rule on this install's endpoint (a new name is created automatically), or rebind the rule." -f `
                            $DcrName, $boundDceId, $expectedDceId)
        }
        return $false
    } catch {
        # Pre-flight itself errored -- don't suppress telemetry on a false negative.
        Write-Verbose ('Send-SIRunHealthRow: pre-flight error (proceeding anyway) -- {0}' -f $_.Exception.Message)
        return $true
    }
}

function Select-SIRunHealthIngestTarget {
    <#
    .SYNOPSIS
        Narrows $global:AzDceDetails / $global:AzDcrDetails to THIS install's endpoint and rule (subscription +
        resource group + name) before AzLogDcrIngestPS sees them.
    .DESCRIPTION
        #198. AzLogDcrIngestPS resolves the endpoint by NAME ONLY -- the first match in its cache, or in a
        tenant-wide Resource Graph query when the cache is empty. With several endpoints sharing a name (measured
        2026-10-01: three called dce-securityinsight in two subscriptions), CheckCreateUpdate-TableDcr-Structure
        re-bound the run-health rule to the wrong one on every run, and every post after that was refused.
        Returns $true when the endpoint is pinned AND, when a rule is named, the rule is in the cache too (the
        caller may create/update/post); $false otherwise -- the caller rebuilds the cache rather than let the
        module guess. -AllowMissingDcr accepts a pinned endpoint whose rule does not exist YET (first run: the
        create step makes it).
        🪤 The cache is SHARED with the engine's other publishers: SI-LogIngest's Select-SIIngestTarget narrows
        $global:AzDcrDetails to ITS rule. Measured 2026-10-02: after the azure engine's Defender for Cloud publish
        the run-health rule was gone from the cache, the post ran with an empty immutable id, and every azure run
        left a Start with no End -- crash detection would call each one a crash.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$DceResourceGroup,
        [Parameter(Mandatory)][string]$DceName,
        [string]$DcrResourceGroup,
        [string]$DcrName,
        [switch]$AllowMissingDcr
    )
    $dce = @($global:AzDceDetails | Where-Object {
        $_ -and $_.name -eq $DceName -and
        [string]$_.id -like "/subscriptions/$SubscriptionId/resourceGroups/$DceResourceGroup/*"
    }) | Select-Object -First 1
    if (-not $dce) {
        # One endpoint of that name anywhere is unambiguous -- an endpoint outside the rules' resource group.
        $same = @($global:AzDceDetails | Where-Object { $_ -and $_.name -eq $DceName })
        if ($same.Count -ne 1) { return $false }
        $dce = $same[0]
    }
    $global:AzDceDetails = @($dce)
    if ($DcrName -and $DcrResourceGroup) {
        $dcr = @($global:AzDcrDetails | Where-Object {
            $_ -and $_.name -eq $DcrName -and
            [string]$_.id -like "/subscriptions/$SubscriptionId/resourceGroups/$DcrResourceGroup/*"
        }) | Select-Object -First 1
        if ($dcr) { $global:AzDcrDetails = @($dcr) }
        elseif (-not $AllowMissingDcr) { return $false }
        else {
            # #281 -- the rule does not exist HERE yet: a rule of the same name in another resource group or subscription
            # (another install in the tenant; the module's rule list is tenant-wide) must not stand in for it. The
            # module's create step looks the rule up by NAME in this cache, so with the foreign one left in, it reports
            # "rule exists", creates nothing, and every post after it is lost. The other publishers' rules stay.
            $global:AzDcrDetails = @($global:AzDcrDetails | Where-Object { $_ -and $_.name -ne $DcrName })
        }
    }
    return $true
}

function Resolve-SIRunHealthSubscriptionId {
    <#
        #281. The subscription the run-health rule and endpoint are looked up in. The first that has one:
        SI_AzSubscriptionId, the subscription in SI_WorkspaceResourceId, the job's SI_WORKSPACE_RESOURCEID,
        SI_JOBS_SUBSCRIPTIONID / SI_FLOW_SUBSCRIPTIONID, the signed-in Az context. '' when none.
        The container entry points set SI_AzSubscriptionId (Initialize-SIContainerIngestGlobals); this is the defensive
        second line for any host or entry that did not -- live 2026-10-05 no container had it, and every profiler run lost
        its record to "Cannot bind argument to parameter 'SubscriptionId' because it is an empty string".
    #>
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_AzSubscriptionId)) { return ([string]$global:SI_AzSubscriptionId).Trim() }
    foreach ($w in @([string]$global:SI_WorkspaceResourceId, [string]$env:SI_WORKSPACE_RESOURCEID)) {
        if ($w -match '/subscriptions/([^/]+)/') { return $Matches[1] }
    }
    foreach ($j in @([string]$env:SI_JOBS_SUBSCRIPTIONID, [string]$env:SI_FLOW_SUBSCRIPTIONID)) {
        if (-not [string]::IsNullOrWhiteSpace($j)) { return $j.Trim() }
    }
    try {
        if (Get-Command -Name Get-SIAzContext -ErrorAction SilentlyContinue) {
            $s = [string](Get-SIAzContext -ErrorAction SilentlyContinue).Subscription.Id
            if ($s) { return $s }
        }
    } catch { }
    return ''
}

function Get-SIRunHealthDcrFromArm {
    <#
        #281. The run-health rule read straight from Azure (by its id: subscription + resource group + name), shaped as the
        ingest module's rule cache holds it (name, id, location, properties) -- or $null. Used when the rule list does
        not have it yet: the module's list is Azure Resource Graph, which shows a rule created seconds ago only after a
        delay, so the first post after the create found nothing and was lost. Never throws.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name)
    try {
        $p = ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Insights/dataCollectionRules/{2}?api-version=2023-03-11' -f $SubscriptionId, $ResourceGroup, $Name)
        $r = Invoke-SIAzRestMethod -Path $p -Method GET -ErrorAction SilentlyContinue 4>$null 2>$null
        if (-not $r -or [int]$r.StatusCode -ne 200) { return $null }
        $o = $r.Content | ConvertFrom-Json -ErrorAction Stop
        if (-not $o -or -not $o.id) { return $null }
        return $o
    } catch { return $null }
}

function ConvertTo-SIRunHealthUtc {
    <#
        PURE. A run's CollectionTime as a [datetime] of kind Utc. The callers hand it over in UTC -- Risk Analysis and
        the tier classifier as an un-zoned 'yyyy-MM-dd HH:mm:ss' string, the profiling engines as a Utc [datetime].
        A plain [datetime] cast of the string gives kind Unspecified, which the serializer treats as LOCAL time and
        converts again: measured 2026-10-02 on a UTC+2 host, every risk-analysis record was stamped 2 h early, so
        no record covered its own snapshot and the vulnerability close-loop (#195) could never close anything.
    #>
    param([Parameter(Mandatory)][object]$Value)
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc)
    }
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, $styles)
}

function Get-SIRunHealthExecution {
    <#
        PURE over -RunContext / -Environment. The Container Apps job EXECUTION this run is (#269): the run context's
        Execution when it carries one, else CONTAINER_APP_JOB_EXECUTION_NAME (Azure sets it in every job execution),
        else '' (a VM). The flow runner reads it back from the START record to tell a container that never ran the engine
        (an Azure platform failure, started again) from an engine that failed (never started again).
    #>
    param($RunContext, [System.Collections.IDictionary]$Environment)
    if ($RunContext -and $RunContext.PSObject.Properties['Execution'] -and "$($RunContext.Execution)") { return [string]$RunContext.Execution }
    $v = if ($Environment) { $Environment['CONTAINER_APP_JOB_EXECUTION_NAME'] } else { [Environment]::GetEnvironmentVariable('CONTAINER_APP_JOB_EXECUTION_NAME') }
    if ($v) { [string]$v } else { '' }
}

function Get-SIRunHealthBuild {
    <#
        The build this run is (BUILD.json, stamped at build/package time -- engine\_shared\SI-BuildInfo.ps1): Version is
        the display version ("3.0.0-rc.12", or the VERSION file when nothing was stamped), Build the short commit ('' when
        unknown). -SolutionRoot is a test seam. Cached per process; never throws, never asks git.
    #>
    param([string]$SolutionRoot)
    if (-not $SolutionRoot -and $script:SIRunHealthBuild) { return $script:SIRunHealthBuild }
    $out = [pscustomobject]@{ Version = ''; Build = '' }
    try {
        $root = if ($SolutionRoot) { $SolutionRoot } else { Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) }
        if (-not (Get-Command -Name Read-SIBuildInfo -ErrorAction SilentlyContinue)) {
            . ([System.IO.Path]::Combine($root, 'engine', '_shared', 'SI-BuildInfo.ps1'))
        }
        $b = Read-SIBuildInfo -SolutionRoot $root
        if ($b.source -ne 'none') { $out.Version = [string]$b.display }
        $out.Build = [string]$b.shortCommit
    } catch { }
    if (-not $SolutionRoot) { $script:SIRunHealthBuild = $out }
    $out
}

function Send-SIRunHealthRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$RunContext,
        # #277: 'Guard' = a tripped guard (Send-SIGuardEvent). Every reader of run health filters Phase == 'End'.
        [Parameter(Mandatory)][ValidateSet('Start','End','Guard')][string]$Phase,
        [int]$AssetCount = -1,
        [string]$ExitReason = '',
        [string]$ErrorMessage = '',
        # #269: a flow STEP's record -- the flow reports one telemetry run for the whole flow, not one per step
        [switch]$NoTelemetry
    )

    # UNCONDITIONAL silence of the AzLogDcrIngestPS / Az SDK VERBOSE
    # storm for the duration of the heartbeat. Per-call -Verbose:$false isn't
    # enough -- the module reads $global:VerbosePreference internally. Heartbeat
    # call traces are never useful, so silence regardless of operator -Verbose.
    $_savedVerbosePreference = $global:VerbosePreference
    $global:VerbosePreference = 'SilentlyContinue'

    # #532 THROTTLE-IS-NORMAL: an END that failed only because Microsoft throttled it is 'throttled' -- in the record, in the
    # telemetry report (Outcome warning, no fix request) and for the stuck check below. Decided before anything is written.
    if ($Phase -eq 'End') {
        try {
            $resolved = Resolve-SIRunHealthExitReason -RunContext $RunContext -ExitReason $ExitReason -ErrorMessage $ErrorMessage
            if ($resolved -eq 'throttled' -and $ExitReason -ne 'throttled') {
                $ExitReason = 'throttled'
                # only a real throttling answer gets here (Get-SITransientKind via Resolve-SIThrottledExitReason): a timeout or an
                # unreachable service stays 'error' with its own text
                $why = Get-SIThrottleText
                $ErrorMessage = '{0} | {1}' -f $why, $ErrorMessage
                try { Write-Host (' [INFO] {0}' -f $why) -ForegroundColor Yellow } catch { }
            }
        } catch { }
    }

    try {
        # A dry run (-WhatIfMode, #257) publishes no results -- but it is SAID, loudly, at its start and at its end, and
        # its health row is written as a dry run so the run-health views show it (#276). Once per process per moment.
        $rowExit = $ExitReason; $rowMsg = $ErrorMessage
        if ([bool]$global:WhatIfMode) {
            $flag = if ($Phase -eq 'Start') { 'SI_DryRunStartSaid' } else { 'SI_DryRunEndSaid' }
            if (-not (Get-Variable -Name $flag -Scope Global -ValueOnly -ErrorAction SilentlyContinue)) {
                Set-Variable -Name $flag -Scope Global -Value $true
                $txt = if (Get-Command -Name Get-SIDryRunNoticeText -ErrorAction SilentlyContinue) { Get-SIDryRunNoticeText -Moment $Phase } else { 'DRY RUN -- nothing was published or sent.' }
                try { Write-Host $txt -ForegroundColor Yellow -BackgroundColor DarkRed } catch { }
            }
            $dry = Get-SIRunHealthDryRunRow -Phase $Phase -ExitReason $ExitReason -ErrorMessage $ErrorMessage
            $rowExit = $dry.ExitReason; $rowMsg = $dry.ErrorMessage
        }

        # Engine bootstrap may have failed before LA globals were set; bail silently
        # if we don't have what we need to ship.
        if (-not $global:SI_WorkspaceResourceId -or -not $global:SI_DceName -or -not $global:SI_DcrResourceGroup) {
            # #198 -- said once, not silent: a run that never has these never records its health at all. Only when a
            # workspace IS configured -- no workspace at all is a deliberate file-only setup, not a fault.
            if ($global:SI_WorkspaceResourceId -and -not $global:SI_RunHealthFailWarned) {
                $global:SI_RunHealthFailWarned = $true
                Write-Warning 'Run-health record not saved: SI_WorkspaceResourceId, SI_DceName or SI_DcrResourceGroup is not set.'
            }
            return
        }

        # #281 -- the subscription, resolved in every host (a container had none: live 2026-10-05, every profiler and flow
        # run failed here with "Cannot bind argument to parameter 'SubscriptionId' because it is an empty string").
        # Filled back into SI_AzSubscriptionId so the rest of the run has it too. None at all: said once, not saved.
        $subId = Resolve-SIRunHealthSubscriptionId
        if (-not $subId) {
            if (-not $global:SI_RunHealthFailWarned) {
                $global:SI_RunHealthFailWarned = $true
                Write-Warning 'Run-health record not saved: no subscription is known for the Log Analytics workspace (set SI_AzSubscriptionId, or a full SI_WorkspaceResourceId).'
            }
            return
        }
        if (-not $global:SI_AzSubscriptionId) { $global:SI_AzSubscriptionId = $subId }
        # The endpoint lives with the rules unless the install says otherwise (an empty value failed the same way).
        $dceRg = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_DceResourceGroup)) { [string]$global:SI_DceResourceGroup } else { [string]$global:SI_DcrResourceGroup }

        # Memory: PS 5.1 [System.Diagnostics.Process].WorkingSet64 is current process bytes.
        # Use PeakWorkingSet64 so a brief peak isn't lost between heartbeat reads.
        $peakMb = -1
        try {
            $proc = [System.Diagnostics.Process]::GetCurrentProcess()
            $peakMb = [int]([Math]::Round($proc.PeakWorkingSet64 / 1MB))
        } catch { }

        $duration = if ($RunContext.StartedAt) {
            [int]([datetime]::UtcNow - $RunContext.StartedAt).TotalSeconds
        } else { 0 }

        $hostName = $env:COMPUTERNAME
        if (-not $hostName) { $hostName = [System.Net.Dns]::GetHostName() }

        # v2.2.365 -- cast CollectionTime to [datetime] so AzLogDcrIngestPS derives
        # the column as DateTime in BOTH the streamDeclarations + transformKql when
        # auto-creating the DCR. Previously the runtime value was a string, which
        # caused AzLogDcrIngestPS's schema derivation to pick DateTime for one
        # side but String for the other -- the resulting DCR spec failed Azure's
        # InvalidPayload validation ('CollectionTime [produced:String, output:DateTime]')
        # and the DCR was never created. Engine-side cast forces consistent type.
        $siBuild = Get-SIRunHealthBuild
        $row = [pscustomobject]@{
            CollectionTime    = ConvertTo-SIRunHealthUtc $RunContext.CollectionTime
            RunId             = [string]$RunContext.RunId
            Engine            = [string]$RunContext.Engine
            ShardIndex        = [long]$RunContext.ShardIndex
            ShardCount        = [long]$RunContext.ShardCount
            Phase             = $Phase
            AssetCount        = [long]$AssetCount
            PeakWorkingSetMB  = [long]$peakMb
            DurationSec       = [long]$duration
            ExitReason        = $rowExit
            ErrorMessage      = $rowMsg
            Computer          = $hostName
            # #269: the job execution (a container; '' on a VM) -- a NEW column, added to the table by the schema
            # update below; readers that do not know it are unaffected (the flow reads it with column_ifexists)
            Execution         = [string](Get-SIRunHealthExecution -RunContext $RunContext)
            # the build that wrote this row (BUILD.json): additive columns, like Execution -- readers that do not know them
            # are unaffected
            SolutionVersion   = [string]$siBuild.Version
            Build             = [string]$siBuild.Build
            # the engine's own permission self-check (engine\_shared\SI-PermissionCheck.ps1), on its END record: the gaps and
            # what could not be checked, as JSON ('' = no check ran in this process). Additive like the columns above;
            # Get Started > Permissions reads it.
            PermissionGaps    = [string]$(if (Get-Command -Name Get-SIRunHealthPermissionGaps -ErrorAction SilentlyContinue) { Get-SIRunHealthPermissionGaps -RunContext $RunContext -Phase $Phase } else { '' })
        }

        # Auth resolution mirrors Invoke-Output.ps1: MI / SPN+Cert / SPN+Secret.
        # v2.2.237 -- cert path added (AzLogDcrIngestPS module accepts cert directly).
        # #281 -- then Risk Analysis' own names (Spn*): its container entry point kept the identity only there, and an
        # empty app id makes the ingest module skip the create SILENTLY (no rule, no error, every post lost).
        $spnAppId      = if ($global:SI_SPN_AppId)    { $global:SI_SPN_AppId }    elseif ($global:SI_LogIngest_AppId)    { $global:SI_LogIngest_AppId }    else { $global:SpnClientId }
        $spnSecret     = if ($global:SI_SPN_Secret)   { $global:SI_SPN_Secret }   elseif ($global:SI_LogIngest_Secret)   { $global:SI_LogIngest_Secret }   else { $global:SpnClientSecret }
        $spnTenantId   = if ($global:SI_SPN_TenantId) { $global:SI_SPN_TenantId } elseif ($global:SI_LogIngest_TenantId) { $global:SI_LogIngest_TenantId } else { $global:SpnTenantId }
        $spnObjectId   = if ($global:SI_SPN_ObjectId) { $global:SI_SPN_ObjectId } else { $global:SI_LogIngest_ObjectId }
        $spnCertThumb  = [string]$global:SI_SPN_CertThumbprint
        # v2.2.243 -- auto-detect cert store (LocalMachine vs CurrentUser).
        $spnCertStore  = if ($global:SI_SPN_CertStoreLocation) { [string]$global:SI_SPN_CertStoreLocation }
                         elseif ($spnCertThumb) {
                             $_clean = $spnCertThumb -replace '\s',''
                             if (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue) {
                                 $_resolved = 'LocalMachine'
                                 foreach ($_s in 'LocalMachine','CurrentUser') {
                                     $_c = Get-ChildItem "Cert:\$_s\My" -ErrorAction SilentlyContinue |
                                           Where-Object { $_.Thumbprint -eq $_clean -and $_.HasPrivateKey } |
                                           Select-Object -First 1
                                     if ($_c) { $_resolved = $_s; break }
                                 }
                                 $_resolved
                             } else {
                                 # #209: no Cert: drive (a Linux container) -- read the X509Store instead.
                                 if (-not (Get-Command Get-SICertStoreLocation -ErrorAction SilentlyContinue)) {
                                     . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'auth/Find-SICertificate.ps1')
                                 }
                                 Get-SICertStoreLocation -Thumbprint $_clean
                             }
                         } else { 'LocalMachine' }

        $useMi   = $global:SI_PreferUami -and -not [string]::IsNullOrWhiteSpace($global:SI_UAMI_ClientId)
        $useCert = -not $useMi -and -not [string]::IsNullOrWhiteSpace($spnCertThumb)
        $authParams = if ($useMi) {
            @{ UseManagedIdentity = $true; ManagedIdentityClientId = $global:SI_UAMI_ClientId }
        } elseif ($useCert) {
            @{
                AzAppId                       = $spnAppId
                AzAppCertificateThumbprint    = $spnCertThumb
                AzAppCertificateStoreLocation = $spnCertStore
                TenantId                      = $spnTenantId
            }
        } else {
            @{ AzAppId = $spnAppId; AzAppSecret = $spnSecret; TenantId = $spnTenantId }
        }
        # #281 -- an identity the ingest module would refuse WITHOUT saying so (no app id, or neither a certificate nor a
        # secret) is said once here instead of being found 30 days later as an empty table.
        if (-not $useMi -and ([string]::IsNullOrWhiteSpace([string]$spnAppId) -or ((-not $useCert) -and [string]::IsNullOrWhiteSpace([string]$spnSecret)))) {
            if (-not $global:SI_RunHealthFailWarned) {
                $global:SI_RunHealthFailWarned = $true
                Write-Warning 'Run-health record not saved: no sign-in identity for Log Analytics (an app id with a certificate or secret, or a managed identity).'
            }
            return
        }

        # Table is workspace-scoped (no cross-sub collision), so the name stays.
        # DCR is name-looked-up across all subs the SPN sees, so it MUST be
        # unique when one SPN spans internal + community tenants.
        $tableName = 'SI_RunHealth'
        $dcrName   = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RunHealth_DcrName)) { [string]$global:SI_RunHealth_DcrName } else { 'dcr-si-run-health' }

        # v2.2.382 -- pre-flight check the DCR/DCE association before calling
        # AzLogDcrIngestPS. The actual post failure is already caught by the
        # outer try/catch in this function, but PowerShell 7's transcript
        # engine writes PS>TerminatingError(...) markers BEFORE the catch
        # handler runs, so they cannot be suppressed from inside the catch.
        # Pre-flight via Invoke-AzRestMethod (non-throwing) lets us skip the
        # noisy call cleanly when we can confirm the DCR is bound to a
        # different DCE than the engine uses. ANY pre-flight failure (network,
        # auth, 404, ...) returns $true so telemetry is never suppressed for
        # the wrong reason.
        if (-not (Test-SIRunHealthDcrReachable `
                        -SubscriptionId   $subId `
                        -DcrResourceGroup $global:SI_DcrResourceGroup `
                        -DcrName          $dcrName `
                        -DceResourceGroup $dceRg `
                        -DceName          $global:SI_DceName)) {
            return
        }

        # #198 -- pin the endpoint BEFORE the module touches the rule. The module resolves the endpoint by name
        # only; unpinned, CheckCreateUpdate re-bound this rule to a same-named endpoint in another subscription.
        # An empty or foreign cache is rebuilt from this subscription; if the endpoint is still not found, the
        # module is not allowed to guess -- said once, and the post is skipped.
        if (-not (Select-SIRunHealthIngestTarget -SubscriptionId $subId `
                    -DceResourceGroup $dceRg -DceName $global:SI_DceName `
                    -DcrResourceGroup $global:SI_DcrResourceGroup -DcrName $dcrName)) {
            try { $global:AzDceDetails = Get-SIDceList @authParams -Verbose:$false 4>$null } catch { }
            try { $global:AzDcrDetails = Get-SIDcrList @authParams -Verbose:$false 4>$null } catch { }
            # After a rebuild a rule that does not exist yet is fine -- the create step below makes it.
            if (-not (Select-SIRunHealthIngestTarget -SubscriptionId $subId `
                        -DceResourceGroup $dceRg -DceName $global:SI_DceName `
                        -DcrResourceGroup $global:SI_DcrResourceGroup -DcrName $dcrName -AllowMissingDcr)) {
                if (-not $global:SI_RunHealthFailWarned) {
                    $global:SI_RunHealthFailWarned = $true
                    Write-Warning ("Run-health record not saved: the data collection endpoint '{0}' was not found in resource group '{1}' of subscription '{2}'." -f `
                                    $global:SI_DceName, $dceRg, $subId)
                }
                return
            }
        }

        # Provision/update DCR + table from the single-row schema sample. AzLogDcrIngestPS
        # is idempotent so the per-replica overhead after first-run is just a cache hit.
        # 4>$null on each call suppresses the AzLogDcrIngestPS / Az SDK VERBOSE storm
        # (POST/GET URLs + byte counts). Stream-redirect is needed because the Az SDK
        # writes via Write-Verbose internally and ignores the function-scoped preference
        # when called in nested module contexts.
        $null = Update-SILogTableSchema `
            -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
            @authParams `
            -DceName                                    $global:SI_DceName `
            -DcrName                                    $dcrName `
            -DcrResourceGroup                           $global:SI_DcrResourceGroup `
            -TableName                                  $tableName `
            -Data                                       @($row) `
            -LogIngestServicePricipleObjectId           $spnObjectId `
            -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
            -AzLogDcrTableCreateFromAnyMachine          $true `
            -AzLogDcrTableCreateFromReferenceMachine    @() 4>$null

        # Re-sync the DCE/DCR cache so a freshly-created DCR's immutableId is in
        # $global:AzDcrDetails before Post-* runs its name-only lookup. Without
        # this, AzLogDcrIngestPS falls back to the DCE's location field as a
        # bogus immutableId -> 404 'westeurope' from the Log Ingestion API.
        # Same pattern as Invoke-Output.ps1 (v2.2.65) and Invoke-RiskAnalysis.ps1.
        try {
            $ensureFn = Get-Command -Name 'Ensure-SecurityInsightAzDceDcrCache' -ErrorAction SilentlyContinue
            if ($ensureFn) {
                & $ensureFn `
                    @authParams `
                    -SubscriptionId   $subId `
                    -DceResourceGroup $dceRg `
                    -DcrResourceGroup $global:SI_DcrResourceGroup `
                    -Force 4>$null
            }
        } catch { }

        # Collision guard again after the cache refresh: endpoint AND rule pinned to (sub + RG + name) before
        # Post-* runs its name-only lookups. The refresh helper above lives with Risk Analysis and is absent in the
        # profiling engines -- so when the rule is still not in the cache, re-read the rules here; a post with no
        # rule in the cache goes out with an EMPTY immutable id and is lost.
        if (-not (Select-SIRunHealthIngestTarget -SubscriptionId $subId `
                    -DceResourceGroup $dceRg -DceName $global:SI_DceName `
                    -DcrResourceGroup $global:SI_DcrResourceGroup -DcrName $dcrName)) {
            try { $global:AzDceDetails = Get-SIDceList @authParams -Verbose:$false 4>$null } catch { }
            try { $global:AzDcrDetails = Get-SIDcrList @authParams -Verbose:$false 4>$null } catch { }
            $pinned = Select-SIRunHealthIngestTarget -SubscriptionId $subId `
                        -DceResourceGroup $dceRg -DceName $global:SI_DceName `
                        -DcrResourceGroup $global:SI_DcrResourceGroup -DcrName $dcrName
            if (-not $pinned) {
                # #281 -- the rule list (Azure Resource Graph) shows a rule created seconds ago only after a delay: read
                # it straight from Azure by its id. The endpoint is already pinned by the call above.
                $direct = Get-SIRunHealthDcrFromArm -SubscriptionId $subId -ResourceGroup $global:SI_DcrResourceGroup -Name $dcrName
                if ($direct) {
                    $global:AzDcrDetails = @($direct)
                    $pinned = Select-SIRunHealthIngestTarget -SubscriptionId $subId `
                                -DceResourceGroup $dceRg -DceName $global:SI_DceName `
                                -DcrResourceGroup $global:SI_DcrResourceGroup -DcrName $dcrName
                }
            }
            if (-not $pinned) {
                if (-not $global:SI_RunHealthFailWarned) {
                    $global:SI_RunHealthFailWarned = $true
                    Write-Warning ("Run-health record not saved: the data collection rule '{0}' was not found in resource group '{1}' of subscription '{2}'." -f `
                                    $dcrName, $global:SI_DcrResourceGroup, $subId)
                }
                return
            }
        }

        $data = @($row)
        $data = Repair-SILogColumnName -Data $data 4>$null
        $data = Format-SILogRowsToSchema -Data $data 4>$null
        $null = Send-SILogData `
            -DceName     $global:SI_DceName `
            -DcrName     $dcrName `
            -Data        $data `
            -TableName   $tableName `
            @authParams 4>$null
    }
    catch {
        # Telemetry must never kill the run -- and must never fail INVISIBLY (#198). This was Write-Verbose under a
        # verbose preference this function itself forces off, so no failure here could ever be seen; the table
        # stayed empty for 30 days. Once per run, as a warning; the run continues.
        if (-not $global:SI_RunHealthFailWarned) {
            $global:SI_RunHealthFailWarned = $true
            Write-Warning ('Run-health record could not be saved: {0}' -f $_.Exception.Message)
        }
    }
    finally {
        # #226 -- the telemetry `run` report (and the daily heartbeat), at the run-health END moment. Independent of
        # whether the Log Analytics record above could be saved. Send-SITelemetryRunEnd never throws and gives up after
        # one short attempt; the extra try is so that even a missing function cannot reach the run.
        if ($Phase -eq 'End' -and -not $NoTelemetry) {
            try {
                if (Get-Command -Name Send-SITelemetryRunEnd -ErrorAction SilentlyContinue) {
                    $null = Send-SITelemetryRunEnd -RunContext $RunContext -ExitReason $ExitReason -ErrorMessage $ErrorMessage -AssetCount $AssetCount
                }
            } catch { }
        }
        # CR3 (#657) -- this run's components (collections per source, correlation, Risk Analysis, data out per channel) count
        # a good daily run, or start their count again after a failed one, while they are Testing after a release. Only the
        # engine's own END record (never a pipeline step record or a dry run), only with the Pro database the run has open.
        # Independent of telemetry; never throws.
        if ($Phase -eq 'End' -and -not [bool]$global:WhatIfMode -and -not ([string]$RunContext.Engine).StartsWith('flow', [System.StringComparison]::OrdinalIgnoreCase)) {
            try {
                if (Get-Command -Name Invoke-SIReleaseScopeRunEnd -ErrorAction SilentlyContinue) { $null = Invoke-SIReleaseScopeRunEnd -RunContext $RunContext -ExitReason $ExitReason }
            } catch { }
        }
        # #532 -- the ONE throttling alert: only when this job has not succeeded for a long stretch because of throttling
        # (SI_Throttle_StuckHours / SI_Throttle_StuckRuns). Once per episode; never throws; never for a flow record (the
        # engine of the step reports its own) and never for a dry run.
        if ($Phase -eq 'End' -and $ExitReason -eq 'throttled' -and -not [bool]$global:WhatIfMode -and [int]$RunContext.ShardIndex -eq 0 -and
            -not ([string]$RunContext.Engine).StartsWith('flow', [System.StringComparison]::OrdinalIgnoreCase)) {
            try {
                if (Get-Command -Name Invoke-SIThrottleStuckCheck -ErrorAction SilentlyContinue) {
                    $null = Invoke-SIThrottleStuckCheck -Engine ([string]$RunContext.Engine).ToLowerInvariant() -RunId ([string]$RunContext.RunId)
                }
            } catch { }
        }
        # Restore caller's verbose preference even on bail-out / exception.
        if ($null -ne $_savedVerbosePreference) { $global:VerbosePreference = $_savedVerbosePreference }
    }
}
