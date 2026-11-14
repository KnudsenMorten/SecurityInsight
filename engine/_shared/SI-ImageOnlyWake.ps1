#Requires -Version 5.1
<#
    SecurityInsight -- THE WAKE-UP START OF AN IMAGE-ONLY SECURITY RELEASE (framework SEC-LANE-1, owner 2026-11-14: "updated
    within 2 hr to ring 2-3"; the products' agreed change G5: "SI's pipeline runner (every 5 min) starts the updater when an
    image-only security release waits"). Every edition; the pipeline runner (engine\flow\Invoke-SIJobFlowRun.ps1) calls it on
    every wake-up of a container install.

    One check, read only at Invardia: the SAME update route the updater reads (engine\_shared\SI-InvardiaUpdate.ps1
    Request-SIInvardiaManifest: the install's own ring, the install key, the signed manifest verified) -- at most once every
    15 minutes (the time of the last ask is recorded). When the ring's release is an IMAGE PATCH of the release this install
    runs (engine\_shared\SI-ImageOnlyRelease.ps1 Test-SIImageOnlyVersion) and no updater execution runs, the updater job is
    started ONCE for that release (SI_UPDATER_MODE = image-only: its nightly-time check lets it go on; the updater itself
    decides again from the verified release and takes its short image-only path). One plain line when it starts the updater,
    nothing otherwise. A start Azure refused is said in one line and tried again by a later wake-up. The record:
    cfg.InstallState 'ImageOnlyWake' = { askedUtc, version, startedUtc, execution }.
    A code release is never started here (it waits for the install's own update time, as before). An install without a
    licence (the Community route) asks nothing here -- it takes an image-only release at its nightly update, by the same
    short path. NEVER throws. PowerShell 5.1 and 7. No PowerShell module.
#>

$script:SIImageOnlyWake = @{ StateName = 'ImageOnlyWake'; AskMinutes = 15; Mode = 'image-only' }
# the image patch rule and "is the updater running" (both every edition)
if (-not (Get-Command -Name Test-SIImageOnlyVersion -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-ImageOnlyRelease.ps1') }
if (-not (Get-Command -Name Test-SIUpdateNowUpdaterRunning -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-UpdaterStart.ps1') }

function ConvertFrom-SIImageOnlyWakeMark {
    <# PURE. The recorded mark (JSON) -> @{ AskedUtc; Version; StartedUtc; Execution } (empty fields when not readable). #>
    param([AllowNull()][AllowEmptyString()][string]$Json)
    $m = [ordered]@{ AskedUtc = $null; Version = ''; StartedUtc = $null; Execution = '' }
    if (-not "$Json".Trim()) { return [pscustomobject]$m }
    try {
        $o = $Json | ConvertFrom-Json -ErrorAction Stop
        $t = { param($v) if ("$v".Trim()) { try { [datetime]::Parse("$v", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { $null } } else { $null } }
        if ($o.PSObject.Properties['askedUtc']) { $m.AskedUtc = & $t $o.askedUtc }
        if ($o.PSObject.Properties['startedUtc']) { $m.StartedUtc = & $t $o.startedUtc }
        if ($o.PSObject.Properties['version']) { $m.Version = "$($o.version)".Trim() }
        if ($o.PSObject.Properties['execution']) { $m.Execution = "$($o.execution)".Trim() }
    } catch { }
    [pscustomobject]$m
}

function ConvertTo-SIImageOnlyWakeMark {
    <# PURE. The mark as the JSON row value (at most 400 characters). #>
    param([Parameter(Mandatory)]$Mark)
    $iso = { param($d) if ($d) { ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } else { $null } }
    $ex = "$($Mark.Execution)"; if ($ex.Length -gt 120) { $ex = $ex.Substring(0, 120) }
    [ordered]@{ askedUtc = (& $iso $Mark.AskedUtc); version = "$($Mark.Version)"; startedUtc = (& $iso $Mark.StartedUtc); execution = $ex } | ConvertTo-Json -Compress
}

function Get-SIImageOnlyWakeReadSql { "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'ImageOnlyWake'" }

function Get-SIImageOnlyWakeSaveSql {
    @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'ImageOnlyWake')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'ImageOnlyWake';
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'ImageOnlyWake', @Value, NULL, @By);
    COMMIT;
END
'@
}

function Invoke-SIImageOnlyWakeCheck {
    <#
        One check (the file header). Seams -- the runner gives the real ones, tests give fakes:
          -Ask        { } -> the verified code manifest result (Request-SIInvardiaManifest shape: Action, Version, Reason)
          -ReadMark   { } -> the recorded mark's JSON ('' = none)      -SaveMark { param($Json) }
          -Executions { } -> the updater job's executions (ARM shape)  -Start    { } -> the started execution's name
        -Installed: the release this install runs; -Ring: its update ring (none = nothing asked). Returns @{ Status; Line;
        Started } -- Status: no-ring | not-due | none | not-image-only | started-already | updater-running | started |
        start-failed | error. Line '' = say nothing.
    #>
    param([AllowEmptyString()][string]$Installed, [AllowNull()]$Ring, [Parameter(Mandatory)][scriptblock]$Ask, [Parameter(Mandatory)][scriptblock]$ReadMark,
          [Parameter(Mandatory)][scriptblock]$SaveMark, [Parameter(Mandatory)][scriptblock]$Executions, [Parameter(Mandatory)][scriptblock]$Start,
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$AskMinutes = $script:SIImageOnlyWake.AskMinutes)
    $out = { param($s, $l = '', [bool]$st = $false) [pscustomobject]@{ Status = $s; Line = $l; Started = $st } }
    try {
        $now = $NowUtc.ToUniversalTime()
        if ($null -eq $Ring -or "$Ring".Trim() -notmatch '^[0-3]$') { return (& $out 'no-ring') }
        $mark = ConvertFrom-SIImageOnlyWakeMark -Json ([string](& $ReadMark))
        if ($mark.AskedUtc -and ($now - [datetime]$mark.AskedUtc).TotalMinutes -lt $AskMinutes -and ($now -ge [datetime]$mark.AskedUtc)) { return (& $out 'not-due') }
        $r = & $Ask
        $mark.AskedUtc = $now
        $save = { try { $null = & $SaveMark (ConvertTo-SIImageOnlyWakeMark -Mark $mark) } catch { } }
        if (-not $r -or "$($r.Action)" -ne 'update') { & $save; return (& $out 'none') }
        $v = "$($r.Version)".Trim()
        $io = Test-SIImageOnlyVersion -Version $v -Running $Installed
        if (-not $io.Ok) { & $save; return (& $out 'not-image-only') }
        if ($mark.Version -and $mark.Version -eq $v -and $mark.StartedUtc) { & $save; return (& $out 'started-already') }
        $running = ''
        try { $running = [string](Test-SIUpdateNowUpdaterRunning -Executions @(& $Executions) -NowUtc $now) } catch { $running = '' }
        if ($running) { & $save; return (& $out 'updater-running') }
        $name = ''
        try { $name = [string](& $Start) }
        catch {
            & $save
            return (& $out 'start-failed' ('the image-only security update {0} waits for this install, but the updater could not be started ({1}) -- a later wake-up tries again' -f $v, $_.Exception.Message))
        }
        $mark.Version = $v; $mark.StartedUtc = $now; $mark.Execution = $name
        & $save
        & $out 'started' ('the image-only security update {0} waits for this install (it runs {1}) -- the updater is started now ({2}); it swaps the images without waiting for a running pipeline' -f $v, "$Installed".Trim(), $(if ($name) { "execution $name" } else { 'started' })) $true
    } catch { & $out 'error' ('whether an image-only security update waits could not be checked ({0}) -- the next wake-up looks again' -f $_.Exception.Message) }
}
