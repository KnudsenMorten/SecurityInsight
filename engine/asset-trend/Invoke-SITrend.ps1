#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight_Trend -- Phase 7's narrow daily rollup. Publishes SI_Trend_CL.

.DESCRIPTION
    §60.4b: trend is the one requirement that genuinely needs HISTORY, and the wide profile tables keep
    ~30 days. The answer is not a second store -- it is a second TABLE in the store the data already
    lives in, narrow enough that multi-year retention costs kilobytes a day instead of 174 columns a
    row. Trend does not need rows, it needs AGGREGATES.

    IT MUST RUN AFTER RISK ANALYSIS. It reads RA's published snapshot; run it before and it rolls up
    yesterday's numbers under today's date, which is the one error a trend line cannot survive because
    nothing downstream can tell.

    🔒 READ-ONLY EXCEPT FOR ITS OWN TABLE. This engine consumes Log Analytics and writes one narrow
    table. It touches no source system, no CMDB and no ticket.

.NOTES
    Solution : SecurityInsight
    Engine   : asset-trend
    Docs     : docs/REQUIREMENTS.md §60.4b (the narrow table) / §47.5c (rate over time)
#>
[CmdletBinding()]
param(
    # Compute and report, publish nothing. The honest first run.
    [switch]$DryRun,

    # Which RA grain to roll up. #636 (owner 2026-10-19: "detailed becomes the engine default and summary is optional"):
    # Detailed is the default -- the trend counts FINDINGS (one per issue per asset); the Summary step is off by default.
    # Summary stays available for an install that switched the Summary step on and wants its trend.
    [ValidateSet('Summary','Detailed')][string]$Grain = 'Detailed',

    # Also print the weekly rate view (§47.5c). Read-only; publishes nothing.
    [switch]$ShowWeeklyRate,
    [int]$Weeks = 12,

    # #306: Risk Analysis calls this at the end of its run with the rows it has just published to Log Analytics -- the
    # day's rollup is computed from THOSE rows, so it can never roll up yesterday's snapshot under today's date while the
    # new one is still being ingested. Without -PublishedRows the snapshot is read from Log Analytics (the job).
    # 🔴 #394: this was `-Rows`, and the body's `$rows` list was the SAME variable (PowerShell names are case-insensitive):
    # the [object[]] type turned the list into a fixed array, `.Add` threw, and the trend was never written. A parameter
    # name is never reused for a local (SIv3-NoParamLocalCollision.Tests.ps1).
    [AllowEmptyCollection()][object[]]$PublishedRows,
    # #638: the rollup Risk Analysis already computed in SQL from the rows it wrote (Dimension, DimensionValue, Findings, Assets, ScoreTotal)
    [AllowEmptyCollection()][object[]]$PublishedRollup
)

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-AzRest.ps1') }
# #639 lane 4: the reads below are read in parts when one Log Analytics answer cannot carry it (Read-SILaParts)
if (-not (Get-Command -Name Read-SILaParts -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-LaParts.ps1') }

$ErrorActionPreference = 'Stop'
try { Set-StrictMode -Off } catch { }

function Write-TrStep ($m) { Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Write-TrInfo ($m) { Write-Host "[INFO] $m" -ForegroundColor Gray }
function Write-TrOk   ($m) { Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-TrWarn ($m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }

. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-V3Snapshot.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-KqlError.ps1')     # #221: what a failed query really said
. (Join-Path $PSScriptRoot '_shared\SI-TrendRollup.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-LogIngest.ps1')   # Initialize-SIIngestGlobals (#174)

# ---- AUTH BRIDGE: HighPriv_Modern_* -> SI_SPN_* ---------------------------------------------------
# Duplicated from the sibling engines ON PURPOSE -- refactoring them onto a shared helper would edit
# the profiler's entry path, which ships to ~30 customers and works today.
if (-not $global:SI_SPN_TenantId       -and $global:HighPriv_Modern_TenantID)                    { $global:SI_SPN_TenantId       = [string]$global:HighPriv_Modern_TenantID }
if (-not $global:SI_SPN_AppId          -and $global:HighPriv_Modern_ApplicationID_Azure)         { $global:SI_SPN_AppId          = [string]$global:HighPriv_Modern_ApplicationID_Azure }
if (-not $global:SI_SPN_CertThumbprint -and $global:HighPriv_Modern_CertificateThumbprint_Azure) { $global:SI_SPN_CertThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }
if (-not $global:SI_SPN_ObjectId       -and $global:SpnObjectId)                                 { $global:SI_SPN_ObjectId       = [string]$global:SpnObjectId }

if ([string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId)) {
    throw 'asset-trend: $global:SI_WorkspaceResourceId is empty. Run this through its launcher so the layered config is loaded, not directly.'
}

$runId          = [guid]::NewGuid().ToString()
$collectionTime = [datetime]::UtcNow
$sourceTable    = if ($Grain -eq 'Detailed') { 'SI_RiskAnalysis_Detailed_CL' } else { 'SI_RiskAnalysis_Summary_CL' }
$solutionVersion = ''
try {
    $verFile = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'VERSION'
    if (Test-Path -LiteralPath $verFile) { $solutionVersion = (Get-Content -LiteralPath $verFile -Raw).Trim() }
} catch { }

# RUN HEALTH: a START and END record like every other engine (the END also sends the telemetry run report). A dry
# run publishes nothing, its health record included. The body below runs inside the try; END is in its finally.
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-RunHealthScope.ps1')
$rh = $null; $rhExit = 'success'; $rhMsg = ''; $rhCount = -1
if (-not $DryRun) { $rh = Start-SIRunHealth -Engine 'asset-trend' -RunId $runId }
try {
Write-TrStep 'SecurityInsight -- Trend (narrow daily rollup)'
Write-TrInfo ("workspace : {0}" -f $global:SI_WorkspaceResourceId)
Write-TrInfo ("source    : {0}  (grain {1})" -f $sourceTable, $Grain)
# 🪤 This claimed the profile tables "stay at the included ~30". We do not know a customer's workspace
# default and cannot assert it -- the internal estate's is 90. State only what this engine controls.
Write-TrInfo ("retention : this table is intended for {0} days total ({1} interactive) -- the wide profile tables keep the workspace default, whatever it is" -f `
    (Get-SITrendRetentionDays), (Get-SITrendInteractiveRetentionDays))
if ($DryRun) { Write-TrWarn 'DRY RUN -- computing and reporting only. Nothing is published.' }

# #830 (owner 2026-10-20): SI_Trend_CL is part of the optional copy of the Risk Analysis report rows to Log Analytics
# ("Copy Risk Analysis report rows to Log Analytics", SendToLogAnalytics), OFF by default -- SecurityInsight keeps the trend in
# its database (sidata.FindingDaily / AssetDaily, written by the data sync) and its pages read it there. Run as the job (not
# by Risk Analysis, which decides itself) with the copy off, there is nothing to copy: one line, nothing is read or written.
if (-not $PSBoundParameters.ContainsKey('PublishedRollup') -and -not $PSBoundParameters.ContainsKey('PublishedRows')) {
    if (-not (Get-Command -Name Test-SIRaReportCopyOn -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'risk-analysis', '_shared', 'RA-Findings.ps1')) }
    if (-not (Test-SIRaReportCopyOn)) {
        Write-TrInfo 'the copy of the Risk Analysis report rows to Log Analytics is off (the default): the trend is kept in the database and SecurityInsight''s pages read it there -- nothing is copied to SI_Trend_CL'
        return
    }
}

# ---- 1. ROLL UP -----------------------------------------------------------------------------------
Write-TrStep 'Aggregating the current Risk Analysis snapshot'
$ws = Resolve-SIV3WorkspaceId
$trLaLog = { param($l, $m) if ($l -eq 'WARN') { Write-TrWarn $m } else { Write-TrInfo $m } }
function Get-SITrendWeeklyRates {
    <# #639 lane 4: the weekly view over -Weeks weeks, its rows read in parts when one answer cannot carry them and added
       to the weekly state a part at a time (never all held). A part that fails fails the read (throws). #>
    param([int]$Weeks)
    $wState = New-SIWeeklyRateState
    $null = Read-SILaParts -WorkspaceId $ws -Query (Get-SIWeeklyRateKql -TableName $sourceTable -Weeks $Weeks) -What ('the weekly rows of {0}' -f $sourceTable) -Log $trLaLog `
                -OnRows { param($partRows) Add-SIWeeklyRateRows -State $wState -Rows $partRows }
    Complete-SIWeeklyRate -State $wState
}
$trendRows = New-Object System.Collections.ArrayList
try {
    # #306: the rows Risk Analysis just published, when it passes them; else the snapshot from Log Analytics
    $rolled = $null
    if ($PSBoundParameters.ContainsKey('PublishedRollup')) { Write-TrInfo 'source    : the rollup this Risk Analysis run computed from the rows it wrote'; $rolled = @($PublishedRollup) }
    elseif ($PSBoundParameters.ContainsKey('PublishedRows')) {
        Write-TrInfo ('source    : the {0} row(s) this Risk Analysis run published' -f @($PublishedRows).Count)
        $srcRows = @($PublishedRows)
        # #303: the query returns the snapshot's rows; the aggregate (Assets = distinct assets, not finding types) is built here.
        $rolled = @(ConvertTo-SITrendRollup -Rows $srcRows)
    } else {
        # #639 lane 4: the snapshot read IN PARTS when one answer cannot carry it (a cut answer is refused) and added to the
        # rollup a part at a time -- the rows are never all held. A part that fails fails the read (the refusal below).
        $rollState = New-SITrendRollupState
        $null = Read-SILaParts -WorkspaceId $ws -Query (Get-SITrendRollupKql -TableName $sourceTable) -What ('the Risk Analysis snapshot ({0})' -f $sourceTable) -Log $trLaLog `
                    -OnRows { param($partRows) Add-SITrendRollupRows -State $rollState -Rows $partRows }
        $rolled = @(Complete-SITrendRollup -State $rollState)
        $rollState = $null
    }
    foreach ($r in $rolled) {
        [void]$trendRows.Add((New-SITrendRow -CollectionTime $collectionTime -RunId $runId `
            -Dimension ([string]$r.Dimension) -DimensionValue ([string]$r.DimensionValue) `
            -Findings ([int]$r.Findings) -Assets ([int]$r.Assets) -ScoreTotal ([double]$r.ScoreTotal) `
            -SourceTable $sourceTable -SolutionVersion $solutionVersion))
    }
} catch {
    # #221: a table that does not exist yet is "no Risk Analysis has published here", not a read failure -- end with
    # nothing published and say so. Any other error still refuses loudly.
    if (Test-SIKqlTableMissing -ErrorRecord $_ -TableName $sourceTable) {
        Write-TrWarn ("{0} does not exist in this workspace yet -- Risk Analysis has not published here. Nothing to roll up; nothing published." -f $sourceTable)
        return
    }
    throw ("asset-trend: could not read '{0}' -- {1}. Refusing to publish a rollup from a source it could not read: a trend point that is silently wrong is worse than a missing one, because nothing downstream can tell." -f $sourceTable, (Get-SIKqlErrorText -ErrorRecord $_))
}

Write-SITrendReport -Rows $trendRows.ToArray()

# ---- 2. THE WEEKLY RATE VIEW (§47.5c) -------------------------------------------------------------
# 🔴 THIS IS COMPUTED AND PERSISTED ON EVERY RUN, AND ONLY THE PRINTING IS OPT-IN.
# Making the WRITE depend on -ShowWeeklyRate would have been the natural reading of the flag, and it
# would have quietly destroyed the feature: the scheduled run does not pass it, so the weekly history
# would accumulate only on the rare occasions a human ran the engine by hand, and every other week
# would read back as a measurement gap. The gaps would have been indistinguishable from real ones.
# The GUI's 365-day window exists only because these rows are written unconditionally -- the RA source
# retains ~90 days, so a week that is not captured while it is fresh can never be recovered.
$weeklyToCompute = Get-SITrendWeeklyComputeWeeks
Write-TrStep ("Weekly rate -- opened / closed per calendar week, computing {0} week(s)" -f $weeklyToCompute)
$weeklyOk = $false
try {
    # The query returns each week's first and last snapshot rows; the set difference over EVERY affected asset is taken here.
    # #639 lane 4: read in parts when one answer cannot carry it, each part added to the weekly state (Get-SITrendWeeklyRates)
    foreach ($r in @(Get-SITrendWeeklyRates -Weeks $weeklyToCompute)) {
        # 🪤 NEVER [bool] A VALUE THAT ARRIVES AS A STRING. Log Analytics returns a KQL bool as the
        # STRING "False", and in PS 5.1 `[bool]"False"` is $TRUE -- every non-empty string is. So the
        # gap branch inverted the moment it first had a gap to report: weeks with zero snapshots were
        # announced as "measured but not comparable". It stayed invisible while every week had data,
        # which is the same shape as the {2,>8} format bug in the very same branch. Snapshots is the
        # authority here -- it is a number, and a week with no snapshot is exactly Snapshots = 0.
        $snaps   = if ($null -eq $r.Snapshots) { 0 } else { [int]$r.Snapshots }
        $hasData = $snaps -gt 0
        # A gap week returns int(null) for opened/closed. PS 5.1 has no null-coalescing operator, and
        # [int]$null is 0 -- which is the value that must NOT be published for an unmeasured week, so
        # the null is resolved explicitly here and New-SITrendWeeklyRows drops the rows entirely.
        $opened = if ($null -eq $r.Opened) { 0 } else { [int]$r.Opened }
        $closed = if ($null -eq $r.Closed) { 0 } else { [int]$r.Closed }
        $comparedA = if ($null -eq $r.ComparedAssets) { 0 } else { [int]$r.ComparedAssets }
        $observedA = if ($null -eq $r.ObservedAssets) { 0 } else { [int]$r.ObservedAssets }
        # The week key as UTC (#135): `[datetime]"...Z"` converts to LOCAL time, so on a host west of UTC
        # the Monday 00:00Z week became Sunday and the published week key shifted a day.
        $weekUtc = if ($r.Week -is [datetime]) { $r.Week.ToUniversalTime() } else {
            [datetime]::Parse([string]$r.Week, [System.Globalization.CultureInfo]::InvariantCulture,
                ([System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)) }
        foreach ($wr in (New-SITrendWeeklyRows -CollectionTime $collectionTime -RunId $runId `
                            -Week $weekUtc -HasData $hasData `
                            -Snapshots $snaps `
                            -Opened $opened -Closed $closed `
                            -ComparedAssets $comparedA -ObservedAssets $observedA `
                            -SourceTable $sourceTable -SolutionVersion $solutionVersion)) {
            [void]$trendRows.Add($wr)
        }
    }
    $weeklyOk = $true
} catch {
    # 🔴 Absence is not remediation. A weekly view that silently loses a week reads as "nothing closed".
    Write-TrWarn ("weekly rate could not be computed -- {0}. These weeks are UNKNOWN, not zero; the rollup above is unaffected." -f $_.Exception.Message)
    # a run that could not compute the weekly view published only part of what it should: its health record says so
    $rhExit = 'success-partial'; $rhMsg = 'the weekly opened/closed view could not be computed this run -- those weeks are unknown, not zero'
}

if ($ShowWeeklyRate -and $weeklyOk) {
    Write-TrStep ("Weekly rate -- last {0} week(s)" -f $Weeks)
    try {
        $printed = @(Get-SITrendWeeklyRates -Weeks $Weeks)
        Write-TrInfo ("   {0,-12} {1,9} {2,8} {3,8} {4,6}  {5}" -f 'week', 'snapshots', 'opened', 'closed', 'net', 'assets compared')
        foreach ($r in $printed) {
            # 🪤 TWO BUGS LIVED IN THIS LOOP AND BOTH WERE INVISIBLE UNTIL THE EDITION FILTER CREATED
            # THE FIRST REAL GAP WEEKS.
            #  (1) `[bool]$r.HasData` -- Log Analytics returns a KQL bool as the STRING "False", and in
            #      PS 5.1 every non-empty string is $true, so the gap branch could never be reached.
            #  (2) `$snaps` was read here but only ASSIGNED in the persistence loop above, so every row
            #      printed the LAST value from that loop -- 13 weeks all reporting "1 snapshot".
            # Together they turned twelve zero-snapshot weeks into twelve confident "only one run this
            # week" lines. Each value is now derived from THIS row, and from the number, not the bool.
            $wSnaps = if ($null -eq $r.Snapshots) { 0 } else { [int]$r.Snapshots }
            if ($wSnaps -le 0) {
                # 🔴 A GAP, NOT A ZERO. A week with no snapshot and a week where nothing closed produce
                # the same number otherwise, and they are completely different conversations.
                # 🪤 THIS LINE READ `{2,>8}` UNTIL 2026-08-31 -- `>` is not valid .NET alignment syntax,
                # so it would have thrown a FormatException the FIRST time a week genuinely had no
                # snapshot. The branch that exists solely to handle the important case was the one that
                # could not run, and every estate with unbroken runs would keep it hidden indefinitely.
                Write-TrWarn ("   {0,-12} {1,9} {2,8} {3,8} {4,6} -- NO SNAPSHOT THIS WEEK: a measurement gap, not a quiet week." -f `
                    ([datetime]$r.Week).ToString('yyyy-MM-dd'), 0, '-', '-', '-')
            } elseif ($null -eq $r.Opened) {
                # 🔑 THREE REASONS, THREE MESSAGES. They have different remedies -- run more often,
                # or make the runs cover the same scope -- and one message for both sends the reader
                # to fix the wrong thing.
                $obsTxt = if ($null -eq $r.ObservedAssets) { "-" } else { ("0 of {0}" -f [int]$r.ObservedAssets) }
                $why = if ($wSnaps -le 1) {
                    'ONLY ONE RUN THIS WEEK: a single snapshot cannot show change, so opened/closed are UNKNOWN rather than zero.'
                } else {
                    'NOTHING COMPARABLE: the runs at the start and end of the week examined different assets, so opened/closed are UNKNOWN for this week.'
                }
                Write-TrWarn ("   {0,-12} {1,9} {2,8} {3,8} {4,6}  {5} -- {6}" -f `
                    ([datetime]$r.Week).ToString('yyyy-MM-dd'), $wSnaps, '-', '-', '-', `
                    $obsTxt, $why)
            } else {
                # 🔑 The denominator prints beside the number, always. The comparable population is
                # routinely a fraction of the estate, and a throughput figure over a fifth of it that
                # reads as the whole is the quiet version of the defect this query was fixed for.
                Write-TrInfo ("   {0,-12} {1,9} {2,8} {3,8} {4,6}  {5} of {6}" -f `
                    ([datetime]$r.Week).ToString('yyyy-MM-dd'), $r.Snapshots, $r.Opened, $r.Closed, $r.Net, `
                    $r.ComparedAssets, $r.ObservedAssets)
            }
        }
    } catch {
        Write-TrWarn ("weekly rate unavailable -- {0}" -f $_.Exception.Message)
    }
}

if ($DryRun) { Write-TrWarn 'DRY RUN -- not publishing. Re-run without -DryRun to write SI_Trend_CL.'; return }
if (@($trendRows).Count -eq 0) { Write-TrWarn 'Nothing to publish.'; return }

# ---- 3. PUBLISH ------------------------------------------------------------------------------------
Write-TrStep 'Publishing SI_Trend_CL'
# #209/#222: the managed identity first -- only when the run's identity switch is on (container, or a VM whose
# sign-in decision is the managed identity). The client id is optional: empty = the host's system-assigned identity.
$authParams = if ($global:SI_UseManagedIdentity) {
    $p = @{ AzAppId = [string]$global:SI_SPN_AppId; TenantId = [string]$global:SI_SPN_TenantId; UseManagedIdentity = $true }
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_UAMI_ClientId)) { $p['ManagedIdentityClientId'] = [string]$global:SI_UAMI_ClientId }
    $p
} elseif ($global:SI_SPN_CertThumbprint) {
    @{ AzAppId = [string]$global:SI_SPN_AppId; AzAppCertificateThumbprint = [string]$global:SI_SPN_CertThumbprint; TenantId = [string]$global:SI_SPN_TenantId }
} else {
    @{ AzAppId = [string]$global:SI_SPN_AppId; AzAppSecret = [string]$global:SI_SPN_Secret; TenantId = [string]$global:SI_SPN_TenantId }
}
$dcrName = if ($global:SI_Trend_DcrName) { [string]$global:SI_Trend_DcrName } else { $script:SITrendDcr }
$tableName = Get-SITrendTableName

$savedVerbose = $global:VerbosePreference
$global:VerbosePreference = 'SilentlyContinue'
try {
    # #174: the subscription / DCE resource group / SPN object id the DCR pinning and the LogIngest grant need.
    # Trend publishes without the profiling orchestrator, which is where these were backfilled until now.
    Initialize-SIIngestGlobals
    $spnObjectId = if ($global:SI_SPN_ObjectId) { $global:SI_SPN_ObjectId } else { $global:SI_LogIngest_ObjectId }
    $data = @($trendRows.ToArray())

    # #199 -- pin BEFORE the create/update, not only before the post.
    Select-SIIngestTarget -AuthParams $authParams -DcrName $dcrName

    # 🔴 THE WHOLE SET DECIDES THE SCHEMA, never a sample. AzLogDcrIngestPS declares the UNION of
    # property names across what it is handed, so one row would fix the column set for the life of the
    # table -- audit #48, and four call sites still had it as recently as today.
    $null = Update-SILogTableSchema `
        -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
        @authParams `
        -DceName                                    $global:SI_DceName `
        -DcrName                                    $dcrName `
        -DcrResourceGroup                           $global:SI_DcrResourceGroup `
        -TableName                                  $tableName `
        -Data                                       $data `
        -LogIngestServicePricipleObjectId           $spnObjectId `
        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
        -AzLogDcrTableCreateFromAnyMachine          $true `
        -AzLogDcrTableCreateFromReferenceMachine    @() 4>$null

    try {
        $ensureFn = Get-Command -Name 'Ensure-SecurityInsightAzDceDcrCache' -ErrorAction SilentlyContinue
        if ($ensureFn) {
            & $ensureFn @authParams -SubscriptionId $global:SI_AzSubscriptionId `
                -DceResourceGroup $global:SI_DceResourceGroup -DcrResourceGroup $global:SI_DcrResourceGroup -Force 4>$null
        }
    } catch { }

    # 🔒 PIN BOTH CACHES BEFORE POSTING -- finding #80. Three DCEs share a name in this tenant, and
    # Post-* resolves the DCE by NAME ONLY, so an unpinned post can send this workspace's DCR
    # immutableId to an endpoint in another subscription and be answered with HTTP 403 AFTER all the
    # real work is done.
    if ($global:AzDcrDetails -and $global:SI_AzSubscriptionId -and $global:SI_DcrResourceGroup) {
        $picked = @($global:AzDcrDetails | Where-Object {
            $_.name -eq $dcrName -and $_.id -like "*/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$($global:SI_DcrResourceGroup)/*" }) | Select-Object -First 1
        if ($picked) { $global:AzDcrDetails = @($picked) }
    }
    $_dceRg = if ($global:SI_DceResourceGroup) { [string]$global:SI_DceResourceGroup } else { [string]$global:SI_DcrResourceGroup }
    if ($global:AzDceDetails -and $global:SI_AzSubscriptionId -and $_dceRg) {
        $_pickedDce = @($global:AzDceDetails | Where-Object { $_.id -like "*/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$_dceRg/*" })
        if ($_pickedDce.Count -gt 0) { $global:AzDceDetails = @($_pickedDce) }
    }

    # #199 -- again before the post: the cache refresh above narrowed it to this install's endpoint, which is
    # not the rule's own when the rule is bound elsewhere.
    Select-SIIngestTarget -AuthParams $authParams -DcrName $dcrName
    $data = Repair-SILogColumnName -Data $data 4>$null
    $data = Format-SILogRowsToSchema -Data $data 4>$null
    $null = Send-SILogData `
        -DceName $global:SI_DceName -DcrName $dcrName -Data $data -TableName $tableName @authParams 4>$null

    Write-TrOk ("posted {0} row(s) to {1}_CL" -f @($data).Count, $tableName)
} finally {
    if ($null -ne $savedVerbose) { $global:VerbosePreference = $savedVerbose }
}

# ⏱️ A newly declared column needs ~25+ minutes before Log Analytics ingests it, and LA never
# backfills. Verify from the SECOND run.
Write-TrInfo 'First run on a new table: expect 0 rows to be queryable for ~25-30 minutes. Verify from the SECOND run.'
# 🪤 THIS PRINTED A BARE NUMBER (2555) UNTIL 2026-08-31 AND AZURE REFUSES IT -- beyond two years,
# total retention must be a full-year value. An instruction nobody had executed is not a verified
# instruction. It now prints the exact command, with both settings, because interactive retention
# caps at 730 days and the remainder is archive.
# RETENTION IS NOW SET BY THE ENGINE, not asked of the customer: this table's whole purpose is outliving the profile
# tables, and it does not inherit that by itself. Every run printed three [WARN] lines with a command to run by hand;
# now the run sets it when its identity may (never lowering a longer retention the customer chose), and only when it
# may not, ONE line says what to run. Never fails the run.
$retention = Set-SITrendTableRetention -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId) -TableName $tableName
switch ($retention.Outcome) {
    'set'  { Write-TrOk   ("retention on {0}_CL set to {1} days ({2} interactively queryable)" -f $tableName, $retention.TotalRetentionInDays, $retention.RetentionInDays) }
    'kept' { Write-TrInfo ("retention on {0}_CL is {1} days ({2} interactively queryable) -- kept" -f $tableName, $retention.TotalRetentionInDays, $retention.RetentionInDays) }
    default {
        Write-TrInfo ("retention on {0}_CL could not be set by this run ({1}). To keep a year of trend, run once: Update-AzOperationalInsightsTable -ResourceGroupName <rg> -WorkspaceName <ws> -TableName {0}_CL -RetentionInDays {2} -TotalRetentionInDays {3}" -f `
            $tableName, $retention.Reason, (Get-SITrendInteractiveRetentionDays), (Get-SITrendRetentionDays))
    }
}
} catch {
    # never an empty text (Invardia got si-trend failures with none): an exception without a message says its type and where
    $rhExit = 'error'; $rhMsg = if (Get-Command -Name Get-SIErrorRecordSummary -ErrorAction SilentlyContinue) { Get-SIErrorRecordSummary -ErrorRecord $_ } else { "$($_.Exception.Message)" }
    throw
} finally {
    if ($rh) { Stop-SIRunHealth -Context $rh -ExitReason $rhExit -ErrorMessage $rhMsg -AssetCount $rhCount }
}
