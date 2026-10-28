#Requires -Version 5.1
<#
    SI v3 -- FULL ASSET PROPERTIES: retention and the collection-change guard (#301, operator 2026-10-05).

    Operator: "we only need low retention of the full asset data and dont need to store them for long, 3 days should
    be sufficient, to compare for guards if asset collection suddenly changes more than 10%".

    RETENTION. SI_AssetProperties_RetentionDays (default 3, at least 1) is set on SI_AssetProperties_CL by the run
    itself -- the same mechanism the trend table uses (GET the table, PATCH retentionInDays / totalRetentionInDays),
    never failing the run, printing the one command to run by hand when this identity may not. Unlike the trend
    table, this one is LOWERED on purpose: low retention is the point. Log Analytics refuses an interactive retention
    below its platform minimum (4 days for an Analytics table), so the value is clamped up to it and the run says so.

    THE GUARD. Each run compares, per source system, how many objects it collected (and how many oversize markers)
    with the newest snapshot already in the table. #412: the PROFILER that read the source runs it (-Engine), against
    the newest snapshot of the same (profiler, source) -- each profiler publishes with its own CollectionTime. A change of more than SI_AssetProperties_ChangeGuardPercent
    (default 10) raises GUARD-1 `asset.properties.collection-change` and HOLDS that source's hand-off: the run
    re-publishes the previous good rows of that source (marked SI_HandoffHeld = true) instead of the new ones, so
    every reader of the newest snapshot -- the CMDB / vulnerability staging, the data sync -- keeps the previous good
    data for it. The hold lifts by itself on the next run whose collection is back within the limit, or ONCE by an
    Admin release (cfg.GuardRelease, the same mechanism as the vulnerability connector's held closes; on a VM also
    Invoke-SIAssetProperties.ps1 -ReleaseCollectionChange <runId>). A first run with nothing to compare against only
    records the baseline.

    PURE where it decides; every system call is a seam. PS 5.1 + 7. NO Set-StrictMode here.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

$script:SIAssetPropertiesPlatformMinRetentionDays = 4
$script:SIAssetPropertiesGuardId = 'asset.properties.collection-change'

function Get-SIAssetPropertiesIntSetting {
    <# A whole-number setting: the global (or -Globals) value when it is one and at least -Min, else -Default. #>
    param([Parameter(Mandatory)][string]$Name, [int]$Default, [int]$Min = 1, [System.Collections.IDictionary]$Globals)
    $v = if ($Globals) { if ($Globals.Contains($Name)) { $Globals[$Name] } else { $null } } else { Get-Variable -Name $Name -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
    if ($null -eq $v -or "$v".Trim() -eq '') { return $Default }
    $n = 0
    if (-not [int]::TryParse("$v".Trim(), [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return $Default }
    if ($n -lt $Min) { return $Min }
    $n
}

function Get-SIAssetPropertiesRetentionDays { param([System.Collections.IDictionary]$Globals) Get-SIAssetPropertiesIntSetting -Name 'SI_AssetProperties_RetentionDays' -Default 3 -Min 1 -Globals $Globals }
# CR4 (#654): the stricter period after a release that changed engine code (halved limits)
if (-not (Get-Command -Name Resolve-SIGuardLimit -ErrorAction SilentlyContinue)) {
    $sgs = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', '_shared', 'SI-GuardStrict.ps1')
    if ([System.IO.File]::Exists($sgs)) { . $sgs }
}
function Get-SIAssetPropertiesChangeGuardPercent {
    <# SI_AssetProperties_ChangeGuardPercent (default 10, at least 1) -- halved for 24 hours after a release that changed
       engine code (CR4, Resolve-SIGuardLimit; -Configured leaves the stricter period out: the configured value as such). #>
    param([System.Collections.IDictionary]$Globals, [switch]$Configured)
    $c = Get-SIAssetPropertiesIntSetting -Name 'SI_AssetProperties_ChangeGuardPercent' -Default 10 -Min 1 -Globals $Globals
    if ($Configured -or -not (Get-Command -Name Resolve-SIGuardLimit -ErrorAction SilentlyContinue)) { return $c }
    [int](Resolve-SIGuardLimit -GuardId $script:SIAssetPropertiesGuardId -Name 'changePercent' -Label 'Change at most (% of a source''s records)' -Configured $c -Unit '%').Effective
}

# =====================================================================================================================
#  RETENTION
# =====================================================================================================================

function Get-SIAssetPropertiesRetentionPlan {
    <#
        PURE. What to set on the table: @{ Action = 'keep' | 'set'; Wanted; Effective; Clamped; PlatformMin }.
        Effective = max(Wanted, the platform minimum). Both interactive and total retention are set to it (the data is
        not wanted beyond it, so there is no archive tail).
    #>
    param([int]$WantedDays = 3, [int]$CurrentRetentionInDays = 0, [int]$CurrentTotalRetentionInDays = 0,
          [int]$PlatformMin = $script:SIAssetPropertiesPlatformMinRetentionDays)
    if ($WantedDays -lt 1) { $WantedDays = 1 }
    $eff = [Math]::Max($WantedDays, $PlatformMin)
    $action = if ($CurrentRetentionInDays -eq $eff -and $CurrentTotalRetentionInDays -eq $eff) { 'keep' } else { 'set' }
    [pscustomobject]@{ Action = $action; Wanted = $WantedDays; Effective = $eff; Clamped = ($WantedDays -lt $PlatformMin); PlatformMin = $PlatformMin }
}

function Get-SIAssetPropertiesRetentionCommand {
    <# PURE. The one command to run by hand when the run may not set the retention itself. #>
    param([Parameter(Mandatory)][int]$Days, [string]$TableName = 'SI_AssetProperties_CL')
    "Update-AzOperationalInsightsTable -ResourceGroupName <rg> -WorkspaceName <workspace> -TableName $TableName -RetentionInDays $Days -TotalRetentionInDays $Days"
}

function Set-SIAssetPropertiesTableRetention {
    <#
        Sets SI_AssetProperties_CL's retention to the plan's Effective value when this identity may. NEVER throws and
        never fails the run: @{ Outcome = 'set' | 'kept' | 'failed'; Wanted; Effective; Clamped; Reason; Command }.
        -Rest { param($Path, $Method, $Payload) -> @{ StatusCode; Content } } -- default Invoke-SIAzRestMethod.
    #>
    param([Parameter(Mandatory)][string]$WorkspaceResourceId, [string]$TableName = 'SI_AssetProperties_CL', [int]$WantedDays = (Get-SIAssetPropertiesRetentionDays), [scriptblock]$Rest)
    if (-not $Rest) { $Rest = { param($Path, $Method, $Payload) if ($Payload) { Invoke-SIAzRestMethod -Path $Path -Method $Method -Payload $Payload -ErrorAction Stop } else { Invoke-SIAzRestMethod -Path $Path -Method $Method -ErrorAction Stop } } }
    $t = ($TableName -replace '_CL$', '') + '_CL'
    $path = ('{0}/tables/{1}?api-version=2022-10-01' -f $WorkspaceResourceId.TrimEnd('/'), $t)
    $plan = Get-SIAssetPropertiesRetentionPlan -WantedDays $WantedDays
    $out = [ordered]@{ Outcome = 'failed'; Wanted = $plan.Wanted; Effective = $plan.Effective; Clamped = $plan.Clamped; Reason = ''; Command = (Get-SIAssetPropertiesRetentionCommand -Days $plan.Effective -TableName $t) }
    try {
        $get = & $Rest $path 'GET' $null
        if (-not $get -or [int]$get.StatusCode -ne 200) { $out.Reason = ('the table could not be read (HTTP {0})' -f $(if ($get) { [int]$get.StatusCode } else { 0 })); return [pscustomobject]$out }
        $p = ($get.Content | ConvertFrom-Json -ErrorAction Stop).properties
        $curRet = 0; if ($null -ne $p.retentionInDays) { $curRet = [int]$p.retentionInDays }
        $curTot = 0; if ($null -ne $p.totalRetentionInDays) { $curTot = [int]$p.totalRetentionInDays }
        $plan = Get-SIAssetPropertiesRetentionPlan -WantedDays $WantedDays -CurrentRetentionInDays $curRet -CurrentTotalRetentionInDays $curTot
        if ($plan.Action -eq 'keep') { $out.Outcome = 'kept'; $out.Reason = 'already at the intended retention'; return [pscustomobject]$out }
        $body = @{ properties = @{ retentionInDays = $plan.Effective; totalRetentionInDays = $plan.Effective } } | ConvertTo-Json -Depth 4 -Compress
        $set = & $Rest $path 'PATCH' $body
        if ($set -and [int]$set.StatusCode -ge 200 -and [int]$set.StatusCode -lt 300) { $out.Outcome = 'set'; return [pscustomobject]$out }
        $out.Reason = ('the change was refused (HTTP {0}) -- this identity needs write access to the workspace' -f $(if ($set) { [int]$set.StatusCode } else { 0 }))
    } catch { $out.Reason = $_.Exception.Message }
    [pscustomobject]$out
}

function Get-SIAssetPropertiesRetentionText {
    <# PURE. The one line the run prints for a retention result (customer language). #>
    param([Parameter(Mandatory)]$Result)
    $clamp = if ($Result.Clamped) { (' -- {0} day(s) were asked for; Log Analytics keeps a table at least {1} days, so {1} is used' -f $Result.Wanted, $Result.Effective) } else { '' }
    switch ([string]$Result.Outcome) {
        'set'  { 'retention on SI_AssetProperties_CL set to {0} day(s){1}' -f $Result.Effective, $clamp }
        'kept' { 'retention on SI_AssetProperties_CL is {0} day(s){1} -- kept' -f $Result.Effective, $clamp }
        default { 'retention on SI_AssetProperties_CL could not be set by this run ({0}){1}. To keep the full asset metadata only briefly, run once: {2}' -f $Result.Reason, $clamp, $Result.Command }
    }
}

# =====================================================================================================================
#  THE COLLECTION-CHANGE GUARD
# =====================================================================================================================

function Get-SIAssetPropertiesPreviousCountsKql {
    <#
        The newest snapshot already in the table, counted per source system (rows, oversize markers) with its run id.
        #412: -Engine = ONE profiler's rows (its sources), and the newest snapshot PER SOURCE -- each profiler publishes its
        own sources with its own CollectionTime, so "the newest CollectionTime of the table" would be another profiler's.
        Without -Engine: the table's newest snapshot, as before (rows the retired add-on wrote).
    #>
    param([int]$LookbackDays = 8, [string]$Engine = '')
    if ($Engine) {
        $e = ($Engine -replace '[^A-Za-z0-9\-]', '').ToLowerInvariant()
        return @"
let src = SI_AssetProperties_CL | where TimeGenerated > ago($($LookbackDays)d)
| where tostring(column_ifexists("Engine", "")) == "$e"
| extend _src = tostring(column_ifexists("SourceSystem", ""));
src
| join kind=inner (src | summarize _snap = max(CollectionTime) by _src) on _src
| where CollectionTime == _snap
| summarize Rows = count(), Dropped = countif(tobool(column_ifexists("PropertiesDropped", false))), RunId = take_any(tostring(column_ifexists("SI_RunId", ""))), CollectionTime = max(CollectionTime)
    by SourceSystem = _src
"@
    }
    @"
let src = SI_AssetProperties_CL | where TimeGenerated > ago($($LookbackDays)d);
let snap = toscalar(src | summarize max(CollectionTime));
src
| where CollectionTime == snap
| summarize Rows = count(), Dropped = countif(tobool(column_ifexists("PropertiesDropped", false))), RunId = take_any(tostring(column_ifexists("SI_RunId", ""))), CollectionTime = max(CollectionTime)
    by SourceSystem = tostring(column_ifexists("SourceSystem", ""))
"@
}

function Get-SIAssetPropertiesCarryForwardKql {
    <# The previous snapshot's rows of ONE source system (#412: of ONE profiler with -Engine) -- what a held source re-publishes. #>
    param([Parameter(Mandatory)][string]$SourceSystem, [int]$LookbackDays = 8, [string]$Engine = '')
    $s = ($SourceSystem -replace '[^A-Za-z0-9\-]', '')
    $eng = ''
    if ($Engine) { $eng = ("`n| where tostring(column_ifexists(""Engine"", """")) == ""{0}""" -f ($Engine -replace '[^A-Za-z0-9\-]', '').ToLowerInvariant()) }
    @"
let src = SI_AssetProperties_CL | where TimeGenerated > ago($($LookbackDays)d)$eng
| where tostring(column_ifexists("SourceSystem", "")) == "$s";
let snap = toscalar(src | summarize max(CollectionTime));
src
| where CollectionTime == snap
| project-away TimeGenerated, CollectionTime, SI_RunId
"@
}

function Measure-SIAssetPropertiesCollection {
    <# PURE. This run's rows -> one count per source system: @{ SourceSystem; Rows; Dropped }. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $by = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $s = [string]$r.SourceSystem
        if (-not $by.ContainsKey($s)) { $by[$s] = [ordered]@{ SourceSystem = $s; Rows = 0; Dropped = 0 } }
        $by[$s].Rows++
        if ([bool]$r.PropertiesDropped) { $by[$s].Dropped++ }
    }
    @($by.Keys | Sort-Object | ForEach-Object { [pscustomobject]$by[$_] })
}

function Test-SIAssetPropertiesCollectionChange {
    <#
        PURE. Per source system, is this run's collection within -Percent of the previous snapshot's?
          -Previous   @{ SourceSystem; Rows; Dropped } per source (Get-SIAssetPropertiesPreviousCountsKql); empty = first run
          -Current    the same for this run (Measure-SIAssetPropertiesCollection)
          -Attempted  the sources this run pulled. A source pulled with NOTHING collected is compared (0 is a 100% drop);
                      a source this run did not pull at all is not compared and not held.
        Returns one verdict per compared source: @{ SourceSystem; PreviousRows; CurrentRows; ChangePercent; PreviousDropped;
        CurrentDropped; Trip; Baseline; Reason }. Trip when the row count OR the oversize-marker count moved by MORE than
        -Percent of the previous row count. A source with no previous rows is a baseline (nothing to compare).
    #>
    param([AllowEmptyCollection()][object[]]$Previous = @(), [AllowEmptyCollection()][object[]]$Current = @(),
          [string[]]$Attempted = @(), [int]$Percent = 10)
    $prev = @{}; foreach ($p in @($Previous)) { if ($p -and [string]$p.SourceSystem) { $prev[[string]$p.SourceSystem] = $p } }
    $cur = @{}; foreach ($c in @($Current)) { if ($c -and [string]$c.SourceSystem) { $cur[[string]$c.SourceSystem] = $c } }
    $sources = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($Attempted) + @($cur.Keys)) { if ($s -and -not $sources.Contains([string]$s)) { $sources.Add([string]$s) } }
    $first = ($prev.Count -eq 0)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($s in ($sources | Sort-Object)) {
        $pr = if ($prev.ContainsKey($s)) { [long]$prev[$s].Rows } else { 0L }
        $pd = if ($prev.ContainsKey($s)) { [long]$prev[$s].Dropped } else { 0L }
        $cr = if ($cur.ContainsKey($s)) { [long]$cur[$s].Rows } else { 0L }
        $cd = if ($cur.ContainsKey($s)) { [long]$cur[$s].Dropped } else { 0L }
        $v = [ordered]@{ SourceSystem = $s; PreviousRows = $pr; CurrentRows = $cr; ChangePercent = 0.0; PreviousDropped = $pd; CurrentDropped = $cd
                         Trip = $false; Baseline = $false; Released = $false; Reason = '' }
        if ($first -or $pr -le 0) {
            $v.Baseline = $true
            $v.Reason = if ($first) { 'first collection -- recorded as the baseline' } else { 'no previous collection of this source -- recorded as the baseline' }
            $out.Add([pscustomobject]$v); continue
        }
        $chg = [Math]::Round(100.0 * [Math]::Abs($cr - $pr) / $pr, 1)
        $dchg = [Math]::Round(100.0 * [Math]::Abs($cd - $pd) / $pr, 1)
        $v.ChangePercent = $chg
        if ($chg -gt $Percent) {
            $v.Trip = $true
            $v.Reason = ('{0}: {1} object(s) collected against {2} in the previous run ({3}% change, the limit is {4}%)' -f $s, $cr, $pr, $chg, $Percent)
        } elseif ($dchg -gt $Percent) {
            $v.Trip = $true
            $v.Reason = ('{0}: {1} object(s) too large to keep against {2} in the previous run ({3}% of the source, the limit is {4}%)' -f $s, $cd, $pd, $dchg, $Percent)
        } else {
            $v.Reason = ('{0}: {1} against {2} ({3}%) -- within the limit' -f $s, $cr, $pr, $chg)
        }
        $out.Add([pscustomobject]$v)
    }
    $out.ToArray()
}

function Test-SIAssetPropertiesSourceHeld {
    <#
        PURE. Is the hand-off of -SourceSystem held? Answered from either:
          -Verdicts  this run's guard verdicts (held = tripped and not released), or
          -Rows      rows read back from SI_AssetProperties_CL (held = the source's rows carry SI_HandoffHeld = true) --
                     how a reader in another job (the CMDB / vulnerability staging) tells it is looking at carried data.
    #>
    param([Parameter(Mandatory)][string]$SourceSystem, [AllowEmptyCollection()][object[]]$Verdicts, [AllowEmptyCollection()][object[]]$Rows)
    if ($PSBoundParameters.ContainsKey('Verdicts')) {
        foreach ($v in @($Verdicts)) { if ($v -and [string]$v.SourceSystem -eq $SourceSystem -and [bool]$v.Trip -and -not [bool]$v.Released) { return $true } }
        return $false
    }
    foreach ($r in @($Rows)) {
        if ($null -eq $r -or [string]$r.SourceSystem -ne $SourceSystem) { continue }
        $h = $r.PSObject.Properties['SI_HandoffHeld']
        if ($h -and ($h.Value -eq $true -or "$($h.Value)" -eq 'true' -or "$($h.Value)" -eq 'True')) { return $true }
    }
    $false
}

function ConvertTo-SIAssetPropertiesCarriedRow {
    <#
        PURE. One previous-snapshot row -> the row this run re-publishes for a HELD source: same identity and payload,
        this run's CollectionTime and run id, SI_HandoffHeld = true and the run it was carried from. Properties read
        back as a JSON string is parsed again, so the column stays dynamic.
    #>
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][datetime]$CollectionTime, [Parameter(Mandatory)][string]$RunId, [string]$HeldFromRunId = '')
    $o = [ordered]@{}
    foreach ($p in $Row.PSObject.Properties) {
        if ($p.Name -in 'TimeGenerated', 'CollectionTime', 'SI_RunId', 'TenantId', 'Type', '_ResourceId', 'SourceSystemTable') { continue }
        $o[$p.Name] = $p.Value
    }
    if ($o.Contains('Properties') -and $o['Properties'] -is [string] -and ([string]$o['Properties']).Trim() -match '^[\[{]') {
        try { $o['Properties'] = ConvertFrom-Json -InputObject ([string]$o['Properties']) } catch { }
    }
    $o['CollectionTime'] = $CollectionTime
    $o['SI_RunId'] = $RunId
    $o['SI_HandoffHeld'] = $true
    if (-not $HeldFromRunId -and $Row.PSObject.Properties['SI_HeldFromRunId'] -and [string]$Row.SI_HeldFromRunId) { $HeldFromRunId = [string]$Row.SI_HeldFromRunId }
    if (-not $HeldFromRunId -and $Row.PSObject.Properties['SI_RunId']) { $HeldFromRunId = [string]$Row.SI_RunId }
    $o['SI_HeldFromRunId'] = $HeldFromRunId
    [pscustomobject]$o
}

function Get-SIAssetPropertiesReleaseConnector {
    <#
        PURE. The release key of one source's hold: 'asset-properties/<profiler>/<source>' (#412: the profiler that read the
        source applies the release on its next run -- the web app starts that job); 'asset-properties/<source>' without
        -Engine (holds the retired add-on stored).
    #>
    param([Parameter(Mandatory)][string]$SourceSystem, [string]$Engine = '')
    if ($Engine) { return ('asset-properties/{0}/{1}' -f $Engine.Trim().ToLowerInvariant(), $SourceSystem) }
    'asset-properties/' + $SourceSystem
}

function New-SIAssetPropertiesHeldSet {
    <# PURE. A tripped verdict -> the release candidate cfg.GuardRelease stores (no item list: the whole source is held). #>
    param([Parameter(Mandatory)]$Verdict, [Parameter(Mandatory)][string]$RunId, [string]$Engine = '')
    $summary = [pscustomobject]@{ Source = [string]$Verdict.SourceSystem; PreviousRows = [long]$Verdict.PreviousRows; CurrentRows = [long]$Verdict.CurrentRows; ChangePercent = $Verdict.ChangePercent
                                  ByAsset = @([pscustomobject]@{ Name = 'previous run'; Count = [int]$Verdict.PreviousRows }, [pscustomobject]@{ Name = 'this run'; Count = [int]$Verdict.CurrentRows }); ByCve = @() }
    [pscustomobject]@{ GuardId = $script:SIAssetPropertiesGuardId; Connector = (Get-SIAssetPropertiesReleaseConnector -SourceSystem ([string]$Verdict.SourceSystem) -Engine $Engine); ConnectorKind = 'asset-properties'
                       RunId = $RunId; HeldCount = [int]$Verdict.CurrentRows; Items = @(); ItemsJson = '[]'; SummaryJson = (ConvertTo-Json -InputObject $summary -Compress -Depth 4) }
}

function Resolve-SIAssetPropertiesGuard {
    <#
        Applies one-time releases and records new holds. For every TRIPPED verdict:
          a RELEASED candidate exists for the source (an Admin released a previous hold) -> the new collection is
            accepted (Released = true, not held) and the release is marked applied;
          otherwise -> the hold is stored as a release candidate (once per source and run).
        -Store  New-SIVulnReleaseStore (-Invoke cfg.GuardRelease, or -Folder); $null = holds are not releasable here.
        -DryRun reads releases, stores and applies nothing.
        Returns the verdicts (same objects, Released set). Never throws: a store failure is logged and the hold stands.
    #>
    param([AllowEmptyCollection()][object[]]$Verdicts = @(), $Store, [Parameter(Mandatory)][string]$RunId, [switch]$DryRun, [scriptblock]$Log, [string]$Engine = '')
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    foreach ($v in @($Verdicts)) {
        if ($null -eq $v -or $null -eq $Store) { continue }
        $conn = Get-SIAssetPropertiesReleaseConnector -SourceSystem ([string]$v.SourceSystem) -Engine $Engine
        # #448 ONLY CURRENT HOLDS: a run back within the limit ends every older hold of this source (closed, audited)
        if (-not [bool]$v.Trip) {
            if (-not $DryRun -and $Store.PSObject.Methods['Supersede']) {
                try { [void]$Store.Supersede($conn, $script:SIAssetPropertiesGuardId, $RunId, $false, ('closed by the current rules: run {0} is back within the limit' -f $RunId), 'asset metadata') }
                catch { & $Log 'WARN' ('{0}: older holds could not be closed -- {1}' -f $v.SourceSystem, $_.Exception.Message) }
            }
            continue
        }
        try {
            $open = @($Store.Open($conn))
            $rel = @($open | Where-Object { $_ -and [string]$_.State -eq 'released' }) | Select-Object -First 1
            if ($rel) {
                $v.Released = $true
                if (-not $DryRun) { $Store.Finish($rel, 'applied', $RunId, ('released once: {0} object(s) accepted against {1} before' -f $v.CurrentRows, $v.PreviousRows)) }
                & $Log 'OK' ('{0}: the change was released by an Admin -- this collection is accepted and becomes the new baseline' -f $v.SourceSystem)
                continue
            }
            if (-not $DryRun) {
                $why = $Store.Save((New-SIAssetPropertiesHeldSet -Verdict $v -RunId $RunId -Engine $Engine))
                if ($why) { & $Log 'WARN' ('{0}: the hold could not be stored for release -- {1}' -f $v.SourceSystem, $why) }
                elseif ($Store.PSObject.Methods['Supersede']) { [void]$Store.Supersede($conn, $script:SIAssetPropertiesGuardId, $RunId, $false, ('superseded by the newer hold of run {0}' -f $RunId), 'asset metadata') }
            }
        } catch { & $Log 'WARN' ('{0}: the release store could not be read -- {1}. The hold stands.' -f $v.SourceSystem, $_.Exception.Message) }
    }
    @($Verdicts)
}

function Get-SIGuardCallsForAssetPropertiesChange {
    <#
        GUARD-1 calls: one 'held' event per source whose hand-off is held this run (Send-SIGuardEvent arguments).
        #412 -Engine: the profiler that read the source -- the event names its job (si-endpoint / si-identity / si-azure).
    #>
    param([AllowEmptyCollection()][object[]]$Verdicts = @(), [string]$RunId, [string]$Engine = '')
    $calls = New-Object System.Collections.Generic.List[object]
    foreach ($v in @($Verdicts)) {
        if (-not (Test-SIAssetPropertiesSourceHeld -SourceSystem ([string]$v.SourceSystem) -Verdicts @($v))) { continue }
        $c = @{ GuardId = $script:SIAssetPropertiesGuardId; Outcome = 'held'; Subject = [string]$v.SourceSystem; RunId = $RunId; HeldCount = [long]$v.CurrentRows
                      Detail = ([string]$v.Reason + '. The previous collection of this source is kept for the CMDB and vulnerability hand-off until the next run is back within the limit, or the change is released once.')
                      Values = @(@{ Name = 'previousObjects'; Label = 'Objects in the previous run'; Measured = [long]$v.PreviousRows },
                                 @{ Name = 'currentObjects'; Label = 'Objects in this run'; Measured = [long]$v.CurrentRows },
                                 @{ Name = 'changePercent'; Label = 'Change'; Measured = $v.ChangePercent; Limit = (Get-SIAssetPropertiesChangeGuardPercent); Unit = '%' }) }
        if ($Engine) { $c['Job'] = 'si-' + $Engine.Trim().ToLowerInvariant() }
        $calls.Add($c)
    }
    $calls.ToArray()
}
