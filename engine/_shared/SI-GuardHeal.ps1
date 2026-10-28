#Requires -Version 5.1
<#
    SecurityInsight -- GUARDS HEAL THEMSELVES, SAY WHICH RELEASE THEY TRIPPED ON, AND CAN BE ACCEPTED (owner 2026-10-17:
    "can a guard autoheal itself if it was caused by bug in code and new release fix it. it must"; "can you make a way that
    i can accept an guard everywhere by email or support app").

    THREE THINGS, one file (loaded by SI-Guard.ps1; every function that talks to a store or a transport NEVER throws):

    1. AUTO-HEAL. A guard that held or warned is an OPEN EPISODE in the guard state (cfg.GuardState on Pro, else the small
       file / memory store of SI-Guard.ps1). Where a guard is checked, the caller names what it checked (Invoke-SIGuardCalls
       -Checked) and whether the run was COMPLETE. A checked guard that did not trip, in a complete run, whose measured
       values are within their limits again, CLEARS its episode (Get-SIGuardHealDecision, pure):
         * the episode keeps who cleared it and when (ClearedUtc / ClearedRunId / ClearedVersion / ClearedHow);
         * one cfg.GuardEvent row, Outcome 'cleared', "Back to normal in run <id> on version <v>";
         * one run-health row (Phase Guard, ExitReason guard-cleared);
         * Invardia gets the guard report GuardOutcome 'cleared', ClearedBy 'passed' (its receiver closes the ticket);
         * nothing is mailed.
       A run that is NOT complete never clears anything, and a run that trips again keeps the episode open. A held set
       (cfg.GuardRelease) is never applied by a heal: the newer complete run decides again under the current rules and the
       older held set is superseded by that run's own code (only current holds), so nothing is lost and no short
       collection is published.

    2. RELEASE ATTRIBUTION. Every trip carries the SecurityInsight version it happened on and the version before it, from
       the guard's VERSION MARKER (state key 'ver|<guard key>': the version this check last ran on, the one before, the
       first run on it, and whether that first run tripped). Get-SIGuardAttribution (pure) says it in plain words: "the
       first run after the update to <v> (from <p>)" (our update is the likely cause), or "this check has run on <v> since
       <time>" (a change in the source is more likely). A marker written by a passing check (kind 'check') is what makes
       "first run after the update" a claim; a guard whose caller names no checks only compares with its own last trip.

    3. ACCEPT EVERYWHERE. The owner accepts a guard situation at an install -- by guard id and a version range (or one
       guard key) -- through the procedure cfg.GuardAcceptSet (sql\si-pro-settings.sql; setup\Invoke-SIGuardAcceptEverywhere.ps1
       runs it through the Invardia Support app, one install at a time). The trips it covers are acknowledged, their
       episodes cleared (Invardia is told ClearedBy 'released' by the mail job), and a held set is released only through
       the release path with its checks (held, not expired, the plan the hash names). A later trip on a version inside an
       accepted range is still recorded, but not mailed and not reported again (Test-SIGuardAcceptCovers, pure).

    PS 5.1 and 7. No modules.
#>

$script:SIGuardHeal = @{
    MarkerPrefix = 'ver|'
    Hows         = @('passed', 'released', 'accepted', 'taken')
    AuditClear   = 'guard.event.clear'
}

function Get-SIGuardHealSettings {
    <#
        This file's constants (and the run version it caches), read ONLY through here. $script: is the script scope of
        the CALLER, not of this file: a script that runs after another one loaded this file (the vulnerability close-loop
        runs itself again as a new script; a launcher loads the guards first) has no $script:SIGuardHeal, and reading it
        failed every clear check with "You cannot call a method on a null-valued expression" (live 2026-10-19). A scope
        without it gets the same constants.
    #>
    if ($null -eq $script:SIGuardHeal) {
        $script:SIGuardHeal = @{ MarkerPrefix = 'ver|'; Hows = @('passed', 'released', 'accepted', 'taken'); AuditClear = 'guard.event.clear' }
    }
    $script:SIGuardHeal
}

# =====================================================================================================================
#  Small helpers -- PURE
# =====================================================================================================================
function Get-SIGuardField {
    <# PURE. One field of a hashtable / object / data row; $null when it is not there (DBNull reads $null). #>
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $v = $null
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { $v = $Object[$Name] } }
    elseif ($Object -is [System.Data.DataRow]) { if ($Object.Table.Columns.Contains($Name)) { $v = $Object[$Name] } }
    elseif ($Object.PSObject.Properties[$Name]) { $v = $Object.$Name }
    if ($v -is [System.DBNull]) { return $null }
    $v
}

function ConvertTo-SIGuardVersionParts {
    <# PURE. '3.0.0.2138' -> 3,0,0,2138; '3.0.0-rc.12+0dc9062' -> 3,0,0,0 (the numeric part, padded to four); '' or not a
       version -> $null. More than four parts -> $null. #>
    param([AllowNull()][AllowEmptyString()][string]$Version)
    $s = ([string]$Version).Trim()
    $m = [regex]::Match($s, '^[0-9]+(\.[0-9]+)*')
    if (-not $m.Success) { return $null }
    $parts = @($m.Value.Split('.'))
    if ($parts.Count -gt 4) { return $null }
    $out = New-Object System.Collections.Generic.List[long]
    foreach ($p in $parts) { $n = 0L; if (-not [long]::TryParse($p, [ref]$n)) { return $null }; $out.Add($n) }
    while ($out.Count -lt 4) { $out.Add(0) }
    , $out.ToArray()
}

function Compare-SIGuardVersion {
    <# PURE. -1 / 0 / 1 for A < = > B by their numeric parts; $null when either is not a version. #>
    param([AllowNull()][AllowEmptyString()][string]$A, [AllowNull()][AllowEmptyString()][string]$B)
    # (not $a / $b: PowerShell names are case-blind, and -A / -B are [string] -- the parts would turn back into text)
    $pa = ConvertTo-SIGuardVersionParts $A; $pb = ConvertTo-SIGuardVersionParts $B
    if ($null -eq $pa -or $null -eq $pb) { return $null }
    for ($i = 0; $i -lt 4; $i++) { if ($pa[$i] -lt $pb[$i]) { return -1 }; if ($pa[$i] -gt $pb[$i]) { return 1 } }
    0
}

function Test-SIGuardVersionInRange {
    <# PURE. Is -Version within [-From, -To] (either bound may be empty = open)? No bound at all = $true. A version that is
       not one (empty, unreadable) is never inside a range that has a bound. #>
    param([AllowNull()][AllowEmptyString()][string]$Version, [AllowNull()][AllowEmptyString()][string]$From, [AllowNull()][AllowEmptyString()][string]$To)
    $f = ([string]$From).Trim(); $t = ([string]$To).Trim()
    if (-not $f -and -not $t) { return $true }
    if ($f) { $c = Compare-SIGuardVersion $Version $f; if ($null -eq $c -or $c -lt 0) { return $false } }
    if ($t) { $c = Compare-SIGuardVersion $Version $t; if ($null -eq $c -or $c -gt 0) { return $false } }
    $true
}

function Get-SIGuardRunVersion {
    <# The SecurityInsight version this process runs (the release, e.g. 3.0.0.2138): $global:SI_GuardVersionOverride (a
       test's), else the telemetry's release version, else the VERSION file. Cached for the process. '' when unknown. #>
    if ($null -ne $global:SI_GuardVersionOverride) { return [string]$global:SI_GuardVersionOverride }
    $gh = Get-SIGuardHealSettings
    if ($gh.ContainsKey('Version') -and $null -ne $gh.Version) { return [string]$gh.Version }
    $v = ''
    try { if (Get-Command -Name Get-SITelemetryReleaseVersion -ErrorAction SilentlyContinue) { $v = [string](Get-SITelemetryReleaseVersion) } } catch { $v = '' }
    if (-not $v.Trim()) {
        try {
            $f = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'VERSION')
            if ([System.IO.File]::Exists($f)) { $v = ([System.IO.File]::ReadAllText($f)).Trim() }
        } catch { $v = '' }
    }
    $gh.Version = $v.Trim()
    $gh.Version
}

function Get-SIGuardKeyFor {
    <# PURE. The guard key of a guard id and subject -- the same rule as New-SIGuardEvent. #>
    param([Parameter(Mandatory)][string]$GuardId, [AllowNull()][AllowEmptyString()][string]$Subject)
    $sub = ([string]$Subject).Trim(); if ($sub.Length -gt 400) { $sub = $sub.Substring(0, 400) }
    if ($sub) { $GuardId + '|' + $sub.ToLowerInvariant() } else { $GuardId }
}

# =====================================================================================================================
#  2. RELEASE ATTRIBUTION -- PURE
# =====================================================================================================================
function Get-SIGuardVersionMarker {
    <# PURE. A stored marker row/object -> @{ Version; PreviousVersion; FirstRunId; SinceUtc; Kind; FirstRunTripped }, or
       $null when there is none (or it names no version). A marker row in cfg.GuardState keeps SinceUtc in FirstSeenUtc and
       FirstRunTripped in TripCount (1 / 0). #>
    param($Stored)
    if ($null -eq $Stored) { return $null }
    $v = [string](Get-SIGuardField $Stored 'Version')
    if (-not $v.Trim()) { return $null }
    $since = Get-SIGuardField $Stored 'SinceUtc'; if ($null -eq $since) { $since = Get-SIGuardField $Stored 'FirstSeenUtc' }
    $ft = Get-SIGuardField $Stored 'FirstRunTripped'
    if ($null -eq $ft) { $tc = 0; [void][int]::TryParse([string](Get-SIGuardField $Stored 'TripCount'), [ref]$tc); $ft = ($tc -gt 0) }
    $kind = [string](Get-SIGuardField $Stored 'MarkerKind'); if (-not $kind) { $kind = [string](Get-SIGuardField $Stored 'Kind') }
    [pscustomobject]@{ Version = $v.Trim(); PreviousVersion = ([string](Get-SIGuardField $Stored 'PreviousVersion')).Trim(); FirstRunId = [string](Get-SIGuardField $Stored 'FirstRunId')
                       SinceUtc = (ConvertTo-SIGuardHealUtc $since); Kind = $(if ($kind -eq 'check') { 'check' } else { 'trip' }); FirstRunTripped = [bool]$ft }
}

function ConvertTo-SIGuardHealUtc {
    <# PURE. A stored time as UTC, or $null. A text without a zone is read AS UTC. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [System.DBNull] -or "$Value".Trim() -eq '') { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }; return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse("$Value", [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    $null
}

function Update-SIGuardVersionMarker {
    <#
        PURE. The marker after this run's check of the guard. -Marker: the one before (Get-SIGuardVersionMarker) or $null;
        -Kind 'check' (the caller names its checks, so a pass is recorded) or 'trip'; -Tripped: this run tripped it.
          no marker / another version  a new marker: this version, the one before it, this run as the first on it
          the same version             kept; the first run's trip is remembered when this IS the first run
        A marker of kind 'check' stays 'check' (passes are recorded for this guard).
    #>
    param($Marker, [AllowEmptyString()][string]$Version, [string]$RunId, [Parameter(Mandatory)][datetime]$NowUtc, [ValidateSet('check', 'trip')][string]$Kind = 'trip', [bool]$Tripped = $false)
    $v = ([string]$Version).Trim()
    if (-not $v) { return $Marker }
    $kind = if ($Kind -eq 'check' -or ($Marker -and $Marker.Kind -eq 'check')) { 'check' } else { 'trip' }
    if (-not $Marker -or $Marker.Version -ne $v) {
        return [pscustomobject]@{ Version = $v; PreviousVersion = $(if ($Marker) { [string]$Marker.Version } else { '' }); FirstRunId = [string]$RunId
                                  SinceUtc = $NowUtc.ToUniversalTime(); Kind = $kind; FirstRunTripped = [bool]$Tripped }
    }
    $ft = [bool]$Marker.FirstRunTripped -or ($Tripped -and [string]$RunId -and [string]$RunId -eq [string]$Marker.FirstRunId)
    [pscustomobject]@{ Version = $Marker.Version; PreviousVersion = [string]$Marker.PreviousVersion; FirstRunId = [string]$Marker.FirstRunId
                       SinceUtc = $Marker.SinceUtc; Kind = $kind; FirstRunTripped = $ft }
}

function Get-SIGuardAttribution {
    <#
        PURE. Which release a trip happened on, in plain words. -Marker: the guard's marker BEFORE this run (or $null);
        -Version: the version this run is on; -RunId: this run. Returns @{ Version; PreviousVersion; FirstRunAfterUpdate;
        AfterUpdate (the update is the likely cause); Text }.
          the first run after an update (the check last ran on another version, a recorded pass or trip)
                                -> "This happened in the first run after the update to <v> (from <p>) ..."
          the same version, its first run tripped too
                                -> "It has tripped since the first run after the update to <v> (from <p>) ..."
          the same version, it ran on it before without tripping in its first run (passes recorded)
                                -> "This check has run on version <v> since <time> ... a change in the data source ..."
          nothing known         -> "This happened on version <v>."
        A marker made only by earlier TRIPS (the caller names no checks) never claims "first run after the update": it says
        on which version the check last tripped.
    #>
    param($Marker, [AllowEmptyString()][string]$Version, [string]$RunId)
    $v = ([string]$Version).Trim()
    $out = [ordered]@{ Version = $v; PreviousVersion = ''; FirstRunAfterUpdate = $false; AfterUpdate = $false; Text = '' }
    if (-not $v) { return [pscustomobject]$out }
    if (-not $Marker) { $out.Text = ('This happened on version {0}.' -f $v); return [pscustomobject]$out }
    if ($Marker.Version -ne $v) {
        $out.PreviousVersion = [string]$Marker.Version
        if ($Marker.Kind -eq 'check') {
            $out.FirstRunAfterUpdate = $true; $out.AfterUpdate = $true
            $out.Text = ('This happened in the first run after the update to {0} (from {1}). The update is the likely cause, not a change in your data source.' -f $v, $Marker.Version)
        } else {
            $out.Text = ('This happened on version {0}; the last time this check tripped, it was version {1}.' -f $v, $Marker.Version)
        }
        return [pscustomobject]$out
    }
    $out.PreviousVersion = [string]$Marker.PreviousVersion
    $first = [string]$RunId -and [string]$RunId -eq [string]$Marker.FirstRunId
    if ($Marker.PreviousVersion -and ($first -or $Marker.FirstRunTripped) -and $Marker.Kind -eq 'check') {
        $out.AfterUpdate = $true; $out.FirstRunAfterUpdate = [bool]$first
        $out.Text = if ($first) { ('This happened in the first run after the update to {0} (from {1}). The update is the likely cause, not a change in your data source.' -f $v, $Marker.PreviousVersion) }
                    else { ('This has tripped since the first run after the update to {0} (from {1}). The update is the likely cause, not a change in your data source.' -f $v, $Marker.PreviousVersion) }
        return [pscustomobject]$out
    }
    if ($Marker.Kind -eq 'check' -and $Marker.SinceUtc) {
        $out.Text = ('This happened on version {0}, which this check has run on since {1:yyyy-MM-dd HH:mm} UTC without tripping at first. A change in your data source is more likely than the update.' -f $v, ([datetime]$Marker.SinceUtc))
        return [pscustomobject]$out
    }
    $out.Text = ('This happened on version {0}.' -f $v)
    [pscustomobject]$out
}

# =====================================================================================================================
#  1. AUTO-HEAL -- PURE decision
# =====================================================================================================================
function Test-SIGuardValueWithinLimit {
    <# PURE. One measured value against its limit: a NEGATIVE limit is a floor (a drop of -30 %: within while the change is
       above it), any other limit a ceiling (within while at or below it). No limit or no measurement = within. #>
    param($Value)
    $m = Get-SIGuardField $Value 'Measured'; $l = Get-SIGuardField $Value 'Limit'
    if ($null -eq $m -or $null -eq $l -or "$m".Trim() -eq '' -or "$l".Trim() -eq '') { return $true }
    $md = 0.0; $ld = 0.0
    $ic = [System.Globalization.CultureInfo]::InvariantCulture
    if (-not [double]::TryParse("$m", [System.Globalization.NumberStyles]::Float, $ic, [ref]$md)) { return $true }
    if (-not [double]::TryParse("$l", [System.Globalization.NumberStyles]::Float, $ic, [ref]$ld)) { return $true }
    if ($ld -lt 0) { return ($md -gt $ld) }
    ($md -le $ld)
}

function Test-SIGuardEpisodeOpen {
    <# PURE. An episode (a cfg.GuardState row) is open when it has a trip that no clear came after. A version marker
       ('ver|') or a cause key ('cause|') is never an episode. #>
    param($Episode, [string]$Key = '')
    if ($null -eq $Episode) { return $false }
    if ($Key -match '^(ver|cause)\|') { return $false }
    $last = ConvertTo-SIGuardHealUtc (Get-SIGuardField $Episode 'LastSeenUtc')
    if ($null -eq $last) { return $false }
    $tc = 0; [void][int]::TryParse([string](Get-SIGuardField $Episode 'TripCount'), [ref]$tc)
    if ($tc -lt 1) { return $false }
    $cl = ConvertTo-SIGuardHealUtc (Get-SIGuardField $Episode 'ClearedUtc')
    -not ($cl -and $cl -ge $last)
}

function Get-SIGuardHealDecision {
    <#
        PURE. Does this run clear the guard's open episode? -Episode: its state (or $null); -Tripped: it tripped in this run;
        -Complete: the run was complete; -Values: this run's measured values against their limits (optional).
        Returns @{ Decision ('none' | 'stays' | 'cleared'); Reason }:
          none     no open episode (never tripped, or cleared already)
          stays    it tripped again; or the run was not complete (only a complete run shows the level is normal); or a
                   measured value is still outside its limit
          cleared  a complete run, no trip, every value within its limit -- whatever version it runs (the release that
                   fixed it, or the same one when the source came back)
    #>
    param($Episode, [string]$Key = '', [bool]$Tripped = $false, [bool]$Complete = $false, [object[]]$Values = @())
    if (-not (Test-SIGuardEpisodeOpen -Episode $Episode -Key $Key)) { return [pscustomobject]@{ Decision = 'none'; Reason = 'no open episode' } }
    if ($Tripped) { return [pscustomobject]@{ Decision = 'stays'; Reason = 'it tripped again in this run' } }
    if (-not $Complete) { return [pscustomobject]@{ Decision = 'stays'; Reason = 'this run was not complete -- only a complete run can show the level is normal again' } }
    foreach ($v in @($Values | Where-Object { $_ })) {
        if (-not (Test-SIGuardValueWithinLimit $v)) {
            $lb = [string](Get-SIGuardField $v 'Label'); if (-not $lb) { $lb = [string](Get-SIGuardField $v 'Name') }
            return [pscustomobject]@{ Decision = 'stays'; Reason = ('still outside its limit: {0} {1} (limit {2})' -f $lb, (Get-SIGuardField $v 'Measured'), (Get-SIGuardField $v 'Limit')) }
        }
    }
    [pscustomobject]@{ Decision = 'cleared'; Reason = 'a complete run is back at the normal level' }
}

function Format-SIGuardClearText {
    <# PURE. The plain sentence of a clear: "Back to normal in run <id> on version <v>." (+ the run's own words), or for an
       acceptance "Accepted by <who>: <reason>." #>
    param([ValidateSet('passed', 'released', 'accepted', 'taken')][string]$How = 'passed', [string]$RunId, [string]$Version, [string]$Detail, [string]$By, [string]$Reason)
    $t = switch ($How) {
        'accepted' { 'Accepted by {0}: {1}' -f $(if ($By) { $By } else { 'the owner' }), $(if ($Reason) { $Reason.Trim().TrimEnd('.') } else { 'no reason given' }) }
        'released' { 'Released by {0}' -f $(if ($By) { $By } else { 'an Admin' }) }
        # NOT a heal (owner review 2026-10-17): the lower level is real as far as SecurityInsight can tell
        'taken'    { 'Taken as the new level after 2 runs at the same level -- not back to normal; check the source if this drop is not expected' }
        default    { 'Back to normal in run {0} on version {1}' -f $(if ($RunId) { $RunId } else { '(unknown)' }), $(if ($Version) { $Version } else { '(unknown)' }) }
    }
    $t = $t.TrimEnd('.') + '.'
    if (([string]$Detail).Trim()) { $t += ' ' + ([string]$Detail).Trim() }
    $t
}

# =====================================================================================================================
#  3. ACCEPT -- PURE coverage
# =====================================================================================================================
function Test-SIGuardAcceptCovers {
    <#
        PURE. Does an owner's acceptance cover this trip? -Accepts: cfg.GuardAccept rows of the guard (GuardKey, FromVersion,
        ToVersion, AcceptedUtc, RevokedUtc). Covered = the same guard key (an acceptance without a key covers every key of
        the guard), the trip's version inside [FromVersion, ToVersion], and -- for an acceptance with NO upper bound -- only a
        trip at or before the acceptance (an open-ended acceptance never mutes the future). Returns the covering row or $null.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Accepts, [Parameter(Mandatory)][string]$GuardKey, [AllowEmptyString()][string]$Version, [Parameter(Mandatory)][datetime]$TimeUtc)
    foreach ($a in @($Accepts | Where-Object { $_ })) {
        if ($null -ne (Get-SIGuardField $a 'RevokedUtc')) { continue }
        $k = ([string](Get-SIGuardField $a 'GuardKey')).Trim()
        if ($k -and $k.ToLowerInvariant() -ne $GuardKey.ToLowerInvariant()) { continue }
        $from = [string](Get-SIGuardField $a 'FromVersion'); $to = [string](Get-SIGuardField $a 'ToVersion')
        if (-not (Test-SIGuardVersionInRange -Version $Version -From $from -To $to)) { continue }
        if (-not $to.Trim()) {
            $at = ConvertTo-SIGuardHealUtc (Get-SIGuardField $a 'AcceptedUtc')
            if ($null -eq $at -or $TimeUtc.ToUniversalTime() -gt $at) { continue }
        }
        return $a
    }
    $null
}

# =====================================================================================================================
#  The SQL (sql\si-pro-settings.sql: the #733 columns, cfg.GuardAccept). Every statement survives a database the
#  update has not reached yet: the new columns are written through a guarded dynamic statement.
# =====================================================================================================================
function Get-SIGuardHealSql {
    param([Parameter(Mandatory)][ValidateSet('StateExtra', 'EventInfo', 'AcceptRead')][string]$Name)
    switch ($Name) {
        'StateExtra' { @'
IF COL_LENGTH(N'cfg.GuardState', N'ClearedUtc') IS NOT NULL
    EXEC sp_executesql N'UPDATE cfg.GuardState SET Version = @v, PreviousVersion = @pv, FirstRunId = @fr, MarkerKind = @mk, ClearedUtc = @cu, ClearedRunId = @cr, ClearedVersion = @cv, ClearedHow = @ch WHERE GuardKey = @k',
        N'@k nvarchar(500), @v nvarchar(64), @pv nvarchar(64), @fr nvarchar(64), @mk nvarchar(16), @cu datetime2(0), @cr nvarchar(64), @cv nvarchar(64), @ch nvarchar(16)',
        @k = @GuardKey, @v = @Version, @pv = @PreviousVersion, @fr = @FirstRunId, @mk = @MarkerKind, @cu = @ClearedUtc, @cr = @ClearedRunId, @cv = @ClearedVersion, @ch = @ClearedHow;
'@ }
        'EventInfo' { @'
IF COL_LENGTH(N'cfg.GuardEvent', N'Attribution') IS NOT NULL
    EXEC sp_executesql N'UPDATE cfg.GuardEvent SET SiVersion = @v, PreviousVersion = @pv, Attribution = @a WHERE Id = @id',
        N'@id bigint, @v nvarchar(64), @pv nvarchar(64), @a nvarchar(400)', @id = @Id, @v = @SiVersion, @pv = @PreviousVersion, @a = @Attribution;
'@ }
        'AcceptRead' { "IF OBJECT_ID(N'cfg.GuardAccept') IS NULL SELECT CAST(NULL AS BIGINT) AS AcceptId WHERE 1 = 0; ELSE SELECT AcceptId, GuardKey, FromVersion, ToVersion, AcceptedBy, AcceptedUtc, RevokedUtc FROM cfg.GuardAccept WHERE GuardId = @GuardId;" }
    }
}

function Get-SIGuardStateExtraParams {
    <# PURE. The #733 fields of a state (episode or marker) as the 'StateExtra' statement's parameters. #>
    param([Parameter(Mandatory)][string]$Key, $State)
    $s = { param($n, $max) $x = [string](Get-SIGuardField $State $n); if ($x.Length -gt $max) { $x = $x.Substring(0, $max) }; if ($x) { $x } else { $null } }
    @{ GuardKey = $Key; Version = (& $s 'Version' 64); PreviousVersion = (& $s 'PreviousVersion' 64); FirstRunId = (& $s 'FirstRunId' 64)
       MarkerKind = (& $s 'MarkerKind' 16); ClearedUtc = (ConvertTo-SIGuardHealUtc (Get-SIGuardField $State 'ClearedUtc'))
       ClearedRunId = (& $s 'ClearedRunId' 64); ClearedVersion = (& $s 'ClearedVersion' 64); ClearedHow = (& $s 'ClearedHow' 16) }
}

function ConvertTo-SIGuardMarkerState {
    <# PURE. A marker as a state row (GuardState's columns): SinceUtc -> FirstSeenUtc, FirstRunTripped -> TripCount. #>
    param([Parameter(Mandatory)]$Marker, [Parameter(Mandatory)][datetime]$NowUtc)
    [pscustomobject]@{ FirstSeenUtc = $(if ($Marker.SinceUtc) { $Marker.SinceUtc } else { $NowUtc }); LastSeenUtc = $NowUtc; TripCount = $(if ($Marker.FirstRunTripped) { 1 } else { 0 }); LastMailUtc = $null
                       Version = $Marker.Version; PreviousVersion = $Marker.PreviousVersion; FirstRunId = $Marker.FirstRunId; MarkerKind = $Marker.Kind
                       SinceUtc = $Marker.SinceUtc; FirstRunTripped = [bool]$Marker.FirstRunTripped }
}

# =====================================================================================================================
#  Talking to the store -- never throws
# =====================================================================================================================
function Resolve-SIGuardStore {
    <# The (store, has-tables, invoke) a guard step uses: the -StateStore handed in, else the Pro database's when it has the
       guard tables, else (a test session) the process's memory store, else the file store. Never throws. #>
    param([scriptblock]$Invoke, $StateStore)
    $isTest = [bool](Get-Module -Name Pester)
    # #735: the same database the trips are written to -- a cleared episode shows on the Guards view next to its trip
    if (Get-Command -Name Resolve-SIGuardEventInvoke -ErrorAction SilentlyContinue) { $Invoke = Resolve-SIGuardEventInvoke -Invoke $Invoke -IsTest $isTest }
    elseif (-not $Invoke -and $global:SI_GuardInvoke -is [scriptblock] -and -not $isTest) { $Invoke = $global:SI_GuardInvoke }
    $has = $false
    if ($Invoke) { try { $has = ([int](& $Invoke (Get-SIGuardSql 'Exists') @{} 'scalar') -eq 1) } catch { $has = $false } }
    if (-not $StateStore) {
        if ($has) { $StateStore = New-SIGuardSqlStateStore -Invoke $Invoke }
        elseif ($isTest) { if (-not $global:SI_GuardTestStore) { $global:SI_GuardTestStore = New-SIGuardMemoryStateStore }; $StateStore = $global:SI_GuardTestStore }
        else { $StateStore = New-SIGuardFileStateStore -Directory (Get-SIGuardStateDirectory) }
    }
    [pscustomobject]@{ Store = $StateStore; HasTables = $has; Invoke = $Invoke; IsTest = $isTest }
}

function Read-SIGuardVersionMarker {
    param([Parameter(Mandatory)]$StateStore, [Parameter(Mandatory)][string]$GuardKey)
    try { return (Get-SIGuardVersionMarker (& $StateStore.Get ((Get-SIGuardHealSettings).MarkerPrefix + $GuardKey))) } catch { return $null }
}

function Save-SIGuardVersionMarker {
    param([Parameter(Mandatory)]$StateStore, [Parameter(Mandatory)][string]$GuardKey, [Parameter(Mandatory)][string]$GuardId, $Marker, [Parameter(Mandatory)][datetime]$NowUtc)
    if (-not $Marker) { return }
    try { & $StateStore.Set ((Get-SIGuardHealSettings).MarkerPrefix + $GuardKey) $GuardId (ConvertTo-SIGuardMarkerState -Marker $Marker -NowUtc $NowUtc) } catch { }
}

# =====================================================================================================================
#  The report to Invardia that a guard is cleared -- PURE builder (Invardia: GuardOutcome 'cleared', ClearedBy, ClearedUtc)
# =====================================================================================================================
function New-SIGuardClearTelemetryRecord {
    <#
        PURE. The guard report that says cleared (Invardia's receiver: the same report as a trip -- Schema 2, Kind guard,
        Product, GuardId -- with GuardOutcome 'cleared', ClearedBy 'passed' (the next run passed the guard) or 'released' (a
        person released or accepted it), ClearedUtc). No Severity, no numbers. ANONYMOUS adds only the InstallId; IDENTIFIED
        adds ClaimedTenantId, Host and the plain sentence as ActionText (at most 500 characters, redacted).
    #>
    param([Parameter(Mandatory)][string]$GuardId, [Parameter(Mandatory)]$Context, [ValidateSet('passed', 'released', 'accepted')][string]$How = 'passed',
          [Parameter(Mandatory)][datetime]$NowUtc, [string]$Job, [string]$Area, [string]$Text, [string]$HostName)
    $anon = ([string]$Context.Mode -eq 'anonymous')
    $iso = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $r = [ordered]@{ Schema = 2; Kind = 'guard'; Product = 'securityinsight' }
    $ver = "$($Context.Version)".Trim(); if ($ver) { $r.Version = $ver }
    if ($Context.PSObject.Properties['Ring'] -and $null -ne $Context.Ring -and "$($Context.Ring)" -ne '') { $r.Ring = [int]$Context.Ring }
    foreach ($k in 'Edition', 'Hosting', 'RuntimeIdentity', 'LicenceState') { if ($Context.PSObject.Properties[$k]) { $val = "$($Context.$k)".Trim(); if ($val) { $r[$k] = $val } } }
    if ($Job) { $r.Job = $Job }
    $r.GuardId = $GuardId
    $r.GuardOutcome = 'cleared'
    $r.ClearedBy = $(if ($How -eq 'passed') { 'passed' } else { 'released' })
    $r.ClearedUtc = $iso
    if ($Area) { $r.Area = $Area }
    if ($anon) { $r.InstallId = [string]$Context.InstallId }
    else {
        $r.ClaimedTenantId = [string]$Context.TenantId
        $r.Host = $(if ($HostName) { $HostName } else { [string][System.Environment]::MachineName })
        $t = [string]$Text
        if (Get-Command -Name ConvertTo-AitUplinkRedacted -ErrorAction SilentlyContinue) { try { $t = [string](ConvertTo-AitUplinkRedacted -Text $t) } catch { } }
        $t = $t.Trim(); if ($t.Length -gt 500) { $t = $t.Substring(0, 497) + '...' }
        if ($t) { $r.ActionText = $t }
    }
    $r.LastSeenUtc = $iso
    [pscustomobject]$r
}

# =====================================================================================================================
#  THE CLEAR -- one call, never throws
# =====================================================================================================================
function Send-SIGuardClear {
    <#
        Clears one guard episode: the state (ClearedUtc ...), one cfg.GuardEvent row Outcome 'cleared' (Pro), one run-health
        row 'guard-cleared', one audit event 'guard.event.clear' (Pro), and the report to Invardia (cleared). Nothing is
        mailed. NEVER throws. Returns @{ Status ('cleared' | 'error'); Text; Telemetry; Stored; RunHealth }.
        -Episode: the open episode (read by the caller); -How passed | released | accepted; seams as Send-SIGuardEvent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GuardId, [string]$Subject, [string]$RunId, [string]$Version, [string]$Engine, [string]$Job,
        [ValidateSet('passed', 'released', 'accepted', 'taken')][string]$How = 'passed', [string]$Detail, [object[]]$Values = @(), $Episode,
        [scriptblock]$Invoke, $StateStore, [scriptblock]$TelemetryTransport, $TelemetryContext, [scriptblock]$RunHealth,
        [System.Collections.IDictionary]$Globals, $Now, [switch]$NoTelemetry, [scriptblock]$Log, [string]$By, [string]$Reason
    )
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) if ($level -eq 'WARN') { Write-Warning $msg } else { Write-Host (' [{0}] {1}' -f $level, $msg) } } }
    $res = [ordered]@{ Status = 'error'; Text = ''; Telemetry = [pscustomobject]@{ State = 'not-tried'; Record = $null }; Stored = $false; RunHealth = 'not-tried'; Reason = '' }
    try {
        $nowUtc = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
        $def = Get-SIGuardDefinition -Id $GuardId
        if (-not $RunId) { $RunId = $(if ($global:SI_GuardRunId) { [string]$global:SI_GuardRunId } else { '' }) }
        if (-not $Version) { $Version = Get-SIGuardRunVersion }
        $key = Get-SIGuardKeyFor -GuardId $GuardId -Subject $Subject
        $text = Format-SIGuardClearText -How $How -RunId $RunId -Version $Version -Detail $Detail -By $By -Reason $Reason
        $res.Text = $text
        $rs = Resolve-SIGuardStore -Invoke $Invoke -StateStore $StateStore
        $store = $rs.Store; $Invoke = $rs.Invoke
        if (-not $Episode) { try { $Episode = & $store.Get $key } catch { $Episode = $null } }
        $job = if ($Job) { $Job } elseif ([string]$def.job) { [string]$def.job } elseif ($Engine -and (Get-Command -Name Resolve-SITelemetryJob -ErrorAction SilentlyContinue)) { [string](Resolve-SITelemetryJob -Engine $Engine) } else { '' }
        & $Log 'INFO' ('{0}{1}: {2}' -f $GuardId, $(if ($Subject) { ' (' + $Subject + ')' } else { '' }), $text)

        # ---- the episode, cleared ----
        $st = [pscustomobject]@{
            FirstSeenUtc = $(if ($Episode) { ConvertTo-SIGuardHealUtc (Get-SIGuardField $Episode 'FirstSeenUtc') } else { $nowUtc })
            LastSeenUtc  = $(if ($Episode -and (Get-SIGuardField $Episode 'LastSeenUtc')) { ConvertTo-SIGuardHealUtc (Get-SIGuardField $Episode 'LastSeenUtc') } else { $nowUtc })
            TripCount    = $(if ($Episode) { [int]('0' + [string](Get-SIGuardField $Episode 'TripCount')) } else { 0 })
            LastMailUtc  = $(if ($Episode) { ConvertTo-SIGuardHealUtc (Get-SIGuardField $Episode 'LastMailUtc') } else { $null })
            Version = $(if ($Episode) { [string](Get-SIGuardField $Episode 'Version') } else { '' }); PreviousVersion = $(if ($Episode) { [string](Get-SIGuardField $Episode 'PreviousVersion') } else { '' })
            ClearedUtc = $nowUtc; ClearedRunId = $RunId; ClearedVersion = $Version; ClearedHow = $How
        }
        if ($null -eq $st.FirstSeenUtc) { $st.FirstSeenUtc = $nowUtc }
        try { & $store.Set $key $GuardId $st } catch { & $Log 'WARN' ('the guard''s clear could not be saved: {0}' -f $_.Exception.Message) }

        # ---- the report to Invardia ----
        $telState = 'off'; $rec = $null
        try {
            # a level TAKEN is not a clear: Invardia is not told the guard cleared (its ticket stays for a person)
            if ($How -eq 'taken') { $telState = 'not-a-clear' }
            elseif ($NoTelemetry -or -not (Get-Command -Name Test-SITelemetryEnabled -ErrorAction SilentlyContinue)) { $telState = 'off' }
            elseif (-not $Globals -and -not (Test-SITelemetryEnabled)) { $telState = 'off' }
            elseif ($Globals -and -not (Test-SIGuardFlag -Value (Get-SIGuardSetting -Name 'SI_Telemetry_Enabled' -Globals $Globals) -Default $true)) { $telState = 'off' }
            elseif ($global:SI_TelemetryHalted -and -not $TelemetryTransport) { $telState = 'halted' }
            elseif (-not $TelemetryTransport -and $rs.IsTest) { $telState = 'test-session' }
            else {
                $ctx = if ($TelemetryContext) { $TelemetryContext } else { Get-SITelemetryContext }
                # Invardia's receiver does not take 'cleared' yet (2026-10-17): with SI_Uplink_SendGuardHealOutcomes off (the
                # default) the clear is recorded here and NOT reported -- TelemetryState 'off', never sent later in a burst
                $healOn = (Get-Command -Name Resolve-SIGuardHealOutcomesSwitch -ErrorAction SilentlyContinue) -and (Resolve-SIGuardHealOutcomesSwitch -Ring $ctx.Ring -Globals $Globals).On
                if (-not $healOn) { $telState = 'off' }
                else {
                $rec = New-SIGuardClearTelemetryRecord -GuardId $GuardId -Context $ctx -How $How -NowUtc $nowUtc -Job $job -Area ([string]$def.area) -Text $text
                if ([string]$ctx.Mode -eq 'anonymous' -and [string]$rec.InstallId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $telState = 'no-install-id'; $rec = $null }
                else {
                    if (-not $TelemetryTransport) { $TelemetryTransport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) if (Get-Command -Name Test-SITelemetryCommunitySendAllowed -ErrorAction SilentlyContinue) { $g = Test-SITelemetryCommunitySendAllowed -AccessCode $AccessCode; if (-not $g.Allowed) { return [pscustomobject]@{ Status = 'skipped'; Reason = $g.Reason; Sent = $false } } }; Send-AitUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec } }
                    $r = & $TelemetryTransport $rec $ctx.Endpoint $ctx.AccessCode 5
                    # a clear that was not accepted is said, not retried, and stops nothing else (the next clear or ok run closes it)
                    $telState = if ("$($r.Status)" -eq 'ok') { 'sent' } else { 'failed' }
                }
                }
            }
        } catch { $telState = 'failed'; & $Log 'INFO' ('the guard''s clear could not be reported to Invardia: {0}' -f $_.Exception.Message) }
        $res.Telemetry = [pscustomobject]@{ State = $telState; Record = $rec }

        # ---- the Guards view row (Pro) ----
        if ($rs.HasTables) {
            try {
                $vals = @($Values | Where-Object { $_ })
                $id = & $Invoke (Get-SIGuardSql 'Insert') @{
                    GuardId = $GuardId; GuardKey = $key; Area = [string]$def.area; Job = $job; Engine = $Engine; Source = 'job'
                    Outcome = $(if ($How -eq 'taken') { 'taken' } else { 'cleared' }); Severity = $(if ($How -eq 'taken') { 'warning' } else { 'info' }); Protected = [string]$def.protects; Subject = ([string]$Subject).Trim(); Detail = $text
                    MeasuredText = $(if ($vals.Count -and (Get-Command -Name Format-SIGuardValues -ErrorAction SilentlyContinue)) { try { Format-SIGuardValues -Values @(New-SIGuardEvent -GuardId $GuardId -Outcome warning -Values $vals).Values } catch { '' } } else { '' })
                    ValuesJson = $null; HeldCount = 0L; ActionText = $null; Link = $null; RunId = $RunId; TripCount = [int]$st.TripCount; FirstSeenUtc = $st.FirstSeenUtc
                    MailState = 'off'; MailTo = $null; TelemetryState = $telState } 'scalar'
                $res.Stored = $true
                $nid = 0L
                if ([long]::TryParse([string]$(if ($id -is [array]) { $id[0] } else { $id }), [ref]$nid) -and $nid -gt 0) {
                    try { $null = & $Invoke (Get-SIGuardHealSql 'EventInfo') @{ Id = $nid; SiVersion = $(if ($Version) { $Version } else { $null }); PreviousVersion = $null; Attribution = $null } 'nonquery' } catch { }
                }
            } catch { & $Log 'WARN' ('the guard''s clear could not be saved for the Guards view: {0}' -f $_.Exception.Message) }
        }

        # ---- run health ----
        try {
            $ctxRh = [pscustomobject]@{ RunId = $RunId; Engine = $(if ($Engine) { $Engine } else { 'guard' }); ShardIndex = 0; ShardCount = 1; CollectionTime = $nowUtc; StartedAt = $nowUtc }
            $msg = '{0}: {1}' -f $GuardId, $text
            if ($RunHealth) { $null = & $RunHealth $ctxRh $(if ($How -eq 'taken') { 'guard-taken' } else { 'guard-cleared' }) $msg 0L; $res.RunHealth = 'written' }
            elseif (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue) {
                Send-SIRunHealthRow -RunContext $ctxRh -Phase Guard -AssetCount 0 -ExitReason $(if ($How -eq 'taken') { 'guard-taken' } else { 'guard-cleared' }) -ErrorMessage $msg -NoTelemetry
                $res.RunHealth = 'written'
            } else { $res.RunHealth = 'unavailable' }
        } catch { $res.RunHealth = 'failed' }

        # ---- audit (Pro) ----
        if ($rs.HasTables -and (Get-Command -Name Write-SIAuditEvent -ErrorAction SilentlyContinue)) {
            try {
                $actor = if (Get-Command -Name Get-SIAuditActor -ErrorAction SilentlyContinue) { Get-SIAuditActor -Job $(if ($Engine) { $Engine } else { 'guard' }) } else { 'guard' }
                $null = Write-SIAuditEvent -Invoke $Invoke -Action (Get-SIGuardHealSettings).AuditClear -Actor $actor -ActorSource 'job' -Target $(if ($Subject) { '{0} ({1})' -f $GuardId, $Subject } else { $GuardId }) `
                        -Reason ([string]$def.protects) -Outcome 'ok' -OutcomeText $text -CorrelationId $RunId -After ([ordered]@{ guard = $GuardId; how = $How; version = $Version; run = $RunId; telemetry = $telState }) -Log { param($l, $m) }
            } catch { }
        }
        $res.Status = 'cleared'
        return [pscustomobject]$res
    } catch {
        $res.Status = 'error'; $res.Reason = [string]$_.Exception.Message
        try { & $Log 'WARN' ('a guard could not be cleared: {0}. The job itself is not affected.' -f $_.Exception.Message) } catch { }
        return [pscustomobject]$res
    }
}

function ConvertTo-SIGuardCheckList {
    <# PURE. -Checked as given (guard ids, or @{ GuardId; Subject; Values; Detail }) -> @(@{ GuardId; Subject; Key; Values;
       Detail }), each key once. -Subject is the default subject of a bare id. #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Checked, [string]$Subject)
    $seen = @{}
    foreach ($c in @($Checked | Where-Object { $_ })) {
        $gid = if ($c -is [string]) { $c } else { [string](Get-SIGuardField $c 'GuardId') }
        if (-not $gid) { continue }
        $sub = if ($c -is [string]) { $Subject } else { $s = Get-SIGuardField $c 'Subject'; if ($null -eq $s) { $Subject } else { [string]$s } }
        $key = Get-SIGuardKeyFor -GuardId $gid -Subject $sub
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [pscustomobject]@{ GuardId = $gid; Subject = ([string]$sub).Trim(); Key = $key
                           Values = $(if ($c -is [string]) { @() } else { @(Get-SIGuardField $c 'Values') | Where-Object { $_ } })
                           Detail = $(if ($c -is [string]) { '' } else { [string](Get-SIGuardField $c 'Detail') })
                           # 'taken' (a drop confirmed at its new level) closes the episode WITHOUT being a heal; default passed
                           How = $(if ($c -is [string]) { 'passed' } else { $h = [string](Get-SIGuardField $c 'How'); if ($h -in 'passed', 'taken') { $h } else { 'passed' } }) }
    }
}

function Invoke-SIGuardHeal {
    <#
        After a step's guard calls: every CHECKED guard (and subject) that did NOT trip in this run records that it ran on
        this version (its marker, kind 'check'), and -- when the run was -Complete and its values are within their limits --
        clears an open episode (Send-SIGuardClear, How 'passed'). -Calls: the trips this step sent (their keys are not
        cleared). -Common: the same extras the trips got (-Invoke, -Engine, -Job, -RunId, -Subject ...). NEVER throws.
        Returns the clears made.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Checked, [AllowNull()][AllowEmptyCollection()][object[]]$Calls = @(), [bool]$Complete = $false,
          [hashtable]$Common = @{}, [scriptblock]$Log)
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $defSub = if ($Common.ContainsKey('Subject')) { [string]$Common['Subject'] } else { '' }
        $list = @(ConvertTo-SIGuardCheckList -Checked $Checked -Subject $defSub)
        if (-not $list.Count) { return , $out.ToArray() }
        $tripped = @{}
        foreach ($c in @($Calls | Where-Object { $_ })) {
            $g = [string](Get-SIGuardField $c 'GuardId'); if (-not $g) { continue }
            $s = Get-SIGuardField $c 'Subject'; if ($null -eq $s) { $s = $defSub }
            $tripped[(Get-SIGuardKeyFor -GuardId $g -Subject ([string]$s))] = $true
        }
        $rs = Resolve-SIGuardStore -Invoke $(if ($Common.ContainsKey('Invoke')) { $Common['Invoke'] } else { $null }) -StateStore $(if ($Common.ContainsKey('StateStore')) { $Common['StateStore'] } else { $null })
        $nowUtc = if ($Common.ContainsKey('Now') -and $Common['Now']) { ([datetime]$Common['Now']).ToUniversalTime() } else { [datetime]::UtcNow }
        $runId = if ($Common.ContainsKey('RunId') -and $Common['RunId']) { [string]$Common['RunId'] } elseif ($global:SI_GuardRunId) { [string]$global:SI_GuardRunId } else { '' }
        $ver = Get-SIGuardRunVersion
        $globals = if ($Common.ContainsKey('Globals')) { $Common['Globals'] } else { $null }
        foreach ($c in $list) {
            if ($tripped.ContainsKey($c.Key)) { continue }
            # a guard switched off neither trips nor clears (its own line is said by the trip path)
            try { if (-not (Test-SIGuardOn -GuardId $c.GuardId -Globals $globals -Quiet)) { continue } } catch { }
            $m = Read-SIGuardVersionMarker -StateStore $rs.Store -GuardKey $c.Key
            Save-SIGuardVersionMarker -StateStore $rs.Store -GuardKey $c.Key -GuardId $c.GuardId -Marker (Update-SIGuardVersionMarker -Marker $m -Version $ver -RunId $runId -NowUtc $nowUtc -Kind check -Tripped $false) -NowUtc $nowUtc
            $ep = $null; try { $ep = & $rs.Store.Get $c.Key } catch { $ep = $null }
            $d = Get-SIGuardHealDecision -Episode $ep -Key $c.Key -Tripped $false -Complete $Complete -Values @($c.Values)
            if ($d.Decision -ne 'cleared') {
                if ($d.Decision -eq 'stays' -and $Log) { & $Log 'INFO' ('{0}{1} stays open: {2}' -f $c.GuardId, $(if ($c.Subject) { ' (' + $c.Subject + ')' } else { '' }), $d.Reason) }
                continue
            }
            $a = @{ GuardId = $c.GuardId; Subject = $c.Subject; RunId = $runId; Version = $ver; How = $(if ($c.How) { $c.How } else { 'passed' }); Detail = $c.Detail; Values = @($c.Values); Episode = $ep; StateStore = $rs.Store }
            if ($rs.Invoke) { $a['Invoke'] = $rs.Invoke }
            foreach ($k in 'Engine', 'Job', 'TelemetryTransport', 'TelemetryContext', 'RunHealth', 'Globals', 'Now', 'NoTelemetry') { if ($Common.ContainsKey($k) -and $null -ne $Common[$k]) { $a[$k] = $Common[$k] } }
            if ($Log) { $a['Log'] = $Log } elseif ($Common.ContainsKey('Log') -and $Common['Log']) { $a['Log'] = $Common['Log'] }
            $out.Add((Send-SIGuardClear @a))
        }
    } catch {
        try { if ($Log) { & $Log 'WARN' ('the guards could not be checked for a clear: {0}' -f $_.Exception.Message) } else { Write-Warning ('the guards could not be checked for a clear: {0}' -f $_.Exception.Message) } } catch { }
    }
    , $out.ToArray()
}
