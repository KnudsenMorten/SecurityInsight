#Requires -Version 5.1
<#
.SYNOPSIS
    Uniform visual output helpers for the v2.2 asset-profiling engine.

.DESCRIPTION
    Centralizes Write-Host calls so every stage uses the same banner /
    phase-separator / [OK]/[INFO]/[WARN]/[ERR] vocabulary and colors.
    Replaces the ad-hoc `       indented prose` pattern with a clearer
    bordered phase header so the visual rhythm of a 9-stage run is
    obvious at a glance.

    Output uses a single leading space instead of two, per
    user feedback that 2-char indent was too much.

    Color choices follow PS 5.1's Write-Host -ForegroundColor (no ANSI
    escapes -- works in legacy ConHost too):
      Cyan        section banners + phase headers
      Green       [OK] / [DONE]
      Yellow      [WARN]
      Red         [ERR]
      Gray        [INFO] + step bullets
      DarkGray    horizontal separator lines

    Invoke-SIQuietBlock wraps AzLogDcrIngestPS / Az SDK calls that emit
    a wall of `VERBOSE: GET https://...` traces. Honors a caller-set
    -Verbose by checking $VerbosePreference once on entry.
#>

function Write-SIBanner {
    [CmdletBinding(DefaultParameterSetName='Structured')]
    param(
        [Parameter(ParameterSetName='Message', Mandatory)][string]$Message,
        [Parameter(ParameterSetName='Structured')][string]$Solution = 'SecurityInsight',
        [Parameter(ParameterSetName='Structured')][string]$Engine,
        [Parameter(ParameterSetName='Structured')][string]$Version,
        [Parameter(ParameterSetName='Structured')][string]$RunId,
        [Parameter(ParameterSetName='Structured')][string]$Mode,
        [Parameter(ParameterSetName='Structured')][string]$Tenant,
        [Parameter(ParameterSetName='Structured')][string]$Subscription,
        [Parameter(ParameterSetName='Structured')][string]$Workspace,
        [Parameter(ParameterSetName='Structured')][string]$Author      = 'Morten Knudsen, Microsoft MVP',
        [Parameter(ParameterSetName='Structured')][string]$GitHub      = 'https://github.com/KnudsenMorten/SecurityInsight',
        [Parameter(ParameterSetName='Structured')][string]$Support     = 'mok@mortenknudsen.net',
        [Parameter(ParameterSetName='Structured')][hashtable]$Extra
    )
    $line = '=' * 88
    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    if ($PSCmdlet.ParameterSetName -eq 'Message') {
        Write-Host (" {0}" -f $Message) -ForegroundColor Cyan
    } else {
        $title = $Solution
        if ($Engine)  { $title += "  *  $Engine" }
        if ($Version) { $title += "  *  $Version" }
        Write-Host (" {0}" -f $title) -ForegroundColor Cyan
        Write-Host '' -ForegroundColor Cyan
        if ($RunId)        { Write-Host (" Run-ID         : {0}" -f $RunId)        -ForegroundColor White }
        if ($Mode)         { Write-Host (" Auth mode      : {0}" -f $Mode)         -ForegroundColor White }
        if ($Tenant)       { Write-Host (" Tenant         : {0}" -f $Tenant)       -ForegroundColor White }
        if ($Subscription) { Write-Host (" Subscription   : {0}" -f $Subscription) -ForegroundColor White }
        if ($Workspace)    { Write-Host (" LA workspace   : {0}" -f $Workspace)    -ForegroundColor White }
        if ($Extra) {
            foreach ($k in $Extra.Keys) {
                Write-Host (" {0,-14} : {1}" -f $k, $Extra[$k]) -ForegroundColor White
            }
        }
        Write-Host '' -ForegroundColor Cyan
        Write-Host (" Developed by : {0}" -f $Author)  -ForegroundColor White
        Write-Host (" GitHub       : {0}" -f $GitHub)  -ForegroundColor White
        Write-Host (" Support      : {0}" -f $Support) -ForegroundColor White
    }
    Write-Host $line -ForegroundColor Cyan
}

function Write-SIPhase {
    param(
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][int]$Total,
        [Parameter(Mandatory)][string]$Name
    )
    $line = '-' * 88
    Write-Host ''
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host (" PHASE {0}/{1} :: {2}" -f $Index, $Total, $Name.ToUpper()) -ForegroundColor Cyan
    Write-Host $line -ForegroundColor DarkCyan
}

function Write-SIStep { param([Parameter(Mandatory)][string]$Message) Write-Host (" - {0}"     -f $Message) -ForegroundColor Cyan  }
function Write-SIOk   { param([Parameter(Mandatory)][string]$Message) Write-Host (" [OK]   {0}" -f $Message) -ForegroundColor Green }
function Write-SIInfo { param([Parameter(Mandatory)][string]$Message) Write-Host (" [INFO] {0}" -f $Message) -ForegroundColor White }
function Write-SIWarn { param([Parameter(Mandatory)][string]$Message) Write-Host (" [WARN] {0}" -f $Message) -ForegroundColor Yellow }
function Write-SIErr  { param([Parameter(Mandatory)][string]$Message) Write-Host (" [ERR]  {0}" -f $Message) -ForegroundColor Red }
function Write-SIDone { param([Parameter(Mandatory)][string]$Message) Write-Host (" [DONE] {0}" -f $Message) -ForegroundColor Green }
# Diagnostic logger -- only emits when verbose mode is active
# ($global:SI_Verbose=$true OR -Verbose was passed). Used for internal merge stats,
# routing decisions, dedup / cache hits that clutter the screen during demos
# but help when debugging. Mirror of RA's Write-Diag.
function Write-SIDiag { param([Parameter(Mandatory)][string]$Message) if ($global:SI_Verbose -or $VerbosePreference -eq 'Continue') { Write-Host (" [DIAG] {0}" -f $Message) -ForegroundColor White } }

# periodic progress logger for long loops. Throttles to whichever
# comes first: a percentage milestone (default every 10%) or a time interval
# (default every 30s). Caller passes a stable Label to bucket throttle state
# across invocations -- first call per label starts the stopwatch.
#
# Usage in any long loop:
#   $total = $items.Count; $i = 0
#   foreach ($it in $items) {
#       $i++
#       Write-SIProgress -Label 'EntraSPs' -Index $i -Total $total
#       ... work ...
#   }
#   Reset-SIProgress -Label 'EntraSPs'   # optional -- clears between runs
function Write-SIProgress {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][int]$Total,
        [int]$PctStep      = 10,
        [int]$EverySeconds = 30
    )
    if (-not $script:_SIProgressState) { $script:_SIProgressState = @{} }
    if (-not $script:_SIProgressState.ContainsKey($Label)) {
        $script:_SIProgressState[$Label] = @{
            Stopwatch   = [System.Diagnostics.Stopwatch]::StartNew()
            NextPctMark = $PctStep
            LastLogSec  = 0.0
        }
    }
    $st = $script:_SIProgressState[$Label]
    if ($Total -le 0) { return }
    $pct      = [int]([math]::Floor(100.0 * $Index / $Total))
    $elapsed  = $st.Stopwatch.Elapsed.TotalSeconds
    $sinceLog = $elapsed - $st.LastLogSec
    $hitMark  = ($pct -ge $st.NextPctMark)
    $hitTime  = ($sinceLog -ge $EverySeconds)
    if ($hitMark -or $hitTime -or $Index -eq $Total) {
        Write-SIInfo ('  [{0}] {1}/{2} ({3}%) elapsed={4:N1}s' -f $Label, $Index, $Total, $pct, $elapsed)
        if ($hitMark) { $st.NextPctMark = $pct + $PctStep }
        $st.LastLogSec = $elapsed
    }
}
function Reset-SIProgress {
    param([string]$Label)
    if (-not $script:_SIProgressState) { return }
    if ($Label) { [void]$script:_SIProgressState.Remove($Label) }
    else        { $script:_SIProgressState.Clear() }
}

# Suppress the wall of `VERBOSE: GET https://...` traces emitted by
# AzLogDcrIngestPS + Az SDK when ingesting a single batch of rows. Honors
# the caller's -Verbose preference -- if they explicitly opted in upstream
# we keep emitting, otherwise we silence for the duration of the block.
#
# redirect verbose stream `4>$null` inside the block as a
# defense against modules that ignore $VerbosePreference.
function Invoke-SIQuietBlock {
    param([Parameter(Mandatory)][scriptblock]$ScriptBlock)
    $callerPref = $global:VerbosePreference
    if ($callerPref -eq 'Continue') { return & $ScriptBlock }
    try {
        $global:VerbosePreference = 'SilentlyContinue'
        & $ScriptBlock 4>$null
    } finally {
        $global:VerbosePreference = $callerPref
    }
}
