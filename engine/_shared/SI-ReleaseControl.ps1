#Requires -Version 5.1
<#
    SecurityInsight -- RELEASE CONTROL (CR3, SI #657; framework DOCS/REQUIREMENTS.md 12.11e RELEASE-CONTROL; approved by the
    owner 2026-10-14). SecurityInsight's part:

    1. THE WAVE. Invardia may serve an install that the owner put in a pre-release wave a version already released to a lower
       ring, early, with no ring move; the signed manifest then carries "wave": "<name>". The updater keeps the wave of the
       release it applied (SI-InvardiaUpdate.ps1: appliedWave); the web app's header says "Ring 2 - Pre-release (<name>)" and
       the identified heartbeat carries wave { name, version, ring } (null = no wave). Leaving or stopping a wave NEVER moves
       the install back: it keeps its version until its ring reaches it.

    2. RELEASE MODE. After a release that changed engine code (the same trigger as the stricter safety checks, CR4: the
       engine fingerprint the updater records changed -- SI-GuardStrict.ps1) SecurityInsight reports every 30 minutes for
       12 hours, counts only: the identified heartbeat (users, guests, devices, the guard mode, the wave) with
       releaseMode { version, sinceUtc, untilUtc, everyMinutes } (null = not in release mode). The pipeline runner, which
       wakes every 5 minutes, sends it (Send-SIReleaseModeReport, SI-TelemetrySend.ps1); one report per half hour, claimed
       in the Pro database (cfg.InstallState 'ReleaseModeReport') so two processes never both send it.

    3. COMPONENTS: TESTING / STABLE. SecurityInsight's components are the collections per source, the correlation, Risk
       Analysis per report and data out per channel (config\release-scopes.locked.json maps each to its engine files; a core
       file belongs to every component). Each component has a fingerprint of its code:
         * the publish call says which components a release changed (changedScopes -- Get-SIReleaseChangedScopesFromGit);
         * the updater fingerprints the code it installed (Save-SIReleaseScopeRecords): a component whose fingerprint
           changed is TESTING from then;
         * a component is STABLE again after 3 good daily runs with no code change (Update-SIReleaseScopeRun, at the end of
           every engine run: a good run counts once per UTC day; a failed run starts the count again while it is Testing).
       The first fingerprints an install records mark nothing Testing (an older install never gets a state invented).
       The identified heartbeat carries them as components { total, testing, stable, testingIds, since, version }.

    4. THE EVIDENCE (framework 12.11e item 5(a), rule D): every identified heartbeat -- so at least daily, every ring -- carries
       evidence { day, version, sinceUtc, health { state, sinceUtc }, guardTrips { sinceRelease, before, windowHours,
       verdict }, components { total, testing, stable }, verdict ok | attention }: counts and verdicts only, read with the
       install's own (read-only) database access. NOT in it yet: the audit of changes made by SecurityInsight's own
       identities (a Graph audit read the heartbeat path does not have) -- see SI REQUIREMENTS #657.

    THE SWITCH (framework 12.22 3(b), owner 2026-10-14): wave and releaseMode are NEW FIELDS on the heartbeat. They go out
    only while SI_Telemetry_ReleaseControl (setting) / SI_TELEMETRY_RELEASECONTROL (job variable) allows it:
      on    always            off   never (the heartbeat is exactly as before; no release-mode reports)
      auto  (the default)     only on the rings in $script:SIReleaseControl.ConfirmedRings -- ring 0 first; every ring
                              since 2026-10-18 (Invardia's intake is live; PIM sends them on every ring).
    A heartbeat refused WITH the new fields is sent again once WITHOUT them; when that one is taken, the fields are held back
    for 24 hours (cfg.InstallState 'ReleaseControlHold').

    NEVER THROWS where a job calls it. PS 5.1 and 7. No PowerShell modules.
#>

if (-not (Get-Command -Name ConvertFrom-SIGuardStrictJson -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-GuardStrict.ps1')) }

function Get-SIReleaseControlState {
    <# The value of $script:SIReleaseControl, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SIReleaseControl) { $script:SIReleaseControl = @{
    ReleaseModeHours = 12
    EveryMinutes     = 30
    # framework 12.22 3(a): the new heartbeat fields went to ring 0 first; Invardia's wave / releaseMode intake is live and
    # PIM sends them on every ring (2.4.641) -- every ring takes them now (2026-10-18). A refused heartbeat is still resent
    # once without them and they are held 24 h; SI_Telemetry_ReleaseControl = off turns them off without a release.
    ConfirmedRings   = @(0, 1, 2, 3)
    StableGoodDays   = 3
    HoldHours        = 24
    CheckMinutes     = 4
    MaxScopesListed  = 30
    ScopeMapFile     = 'config/release-scopes.locked.json'
    ReportRow        = 'ReleaseModeReport'
    HoldRow          = 'ReleaseControlHold'
    SIRoot           = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    WaveName         = '^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,59}$'
    VersionText      = '^[0-9A-Za-z.+-]{1,50}$'
} }
    , $script:SIReleaseControl
}
$script:SIReleaseControl = $null; $null = Get-SIReleaseControlState

# =====================================================================================================================
#  The switch -- PURE
# =====================================================================================================================
function Resolve-SIReleaseControlSwitch {
    <#
        PURE. Do wave + releaseMode go out from this install? The setting wins when set (SI_Telemetry_ReleaseControl), then
        the job variable SI_TELEMETRY_RELEASECONTROL, else 'auto'. on / true / 1 / yes = on; off / false / 0 / no = off;
        anything else = auto. auto = on only for a ring in ConfirmedRings (-Ring; not known = off).
        Returns @{ On; Setting (on | off | auto); Reason }.
    #>
    param([AllowNull()]$Value = $global:SI_Telemetry_ReleaseControl, [AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_TELEMETRY_RELEASECONTROL,
          [AllowNull()]$Ring, [int[]]$ConfirmedRings = @((Get-SIReleaseControlState).ConfirmedRings))
    $set = ''
    foreach ($v in @($Value, $EnvValue)) {
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { $set = $(if ($v) { 'on' } else { 'off' }); break }
        $s = ([string]$v).Trim().Trim('$').ToLowerInvariant()
        if (-not $s) { continue }
        $set = if ($s -in @('on', 'true', '1', 'yes', 'enabled')) { 'on' } elseif ($s -in @('off', 'false', '0', 'no', 'disabled')) { 'off' } else { 'auto' }
        break
    }
    if (-not $set) { $set = 'auto' }
    if ($set -eq 'on') { return [pscustomobject]@{ On = $true; Setting = 'on'; Reason = 'switched on (SI_Telemetry_ReleaseControl)' } }
    if ($set -eq 'off') { return [pscustomobject]@{ On = $false; Setting = 'off'; Reason = 'switched off (SI_Telemetry_ReleaseControl)' } }
    $rn = -1
    if ($null -ne $Ring -and "$Ring".Trim() -ne '') { if (-not [int]::TryParse("$Ring", [ref]$rn)) { $rn = -1 } }
    $on = ($rn -ge 0 -and @($ConfirmedRings) -contains $rn)
    [pscustomobject]@{ On = $on; Setting = 'auto'
        Reason = $(if ($on) { "ring $rn takes the release fields" } elseif ($rn -lt 0) { 'the ring is not known -- the release fields wait' } else { "ring $rn takes the release fields once Invardia has confirmed them through ring 0" }) }
}

function ConvertTo-SIReleaseControlRing {
    <# PURE. 0..3 or -1. #>
    param([AllowNull()]$Ring)
    $n = -1
    if ($null -ne $Ring -and [int]::TryParse("$Ring", [ref]$n) -and $n -ge 0 -and $n -le 3) { return $n }
    -1
}

# =====================================================================================================================
#  The wave -- PURE over the update state the updater records
# =====================================================================================================================
function ConvertTo-SIReleaseWaveName {
    <# PURE. A wave name as the manifest gives it: trimmed, one line, at most 60 characters of the safe set; '' = none. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    if (-not ($Value -is [string]) -and -not ($Value -is [System.ValueType])) {
        # an object { name } is read for its name (a manifest that carries more than the name)
        $n = Get-SIGuardStrictField $Value 'name'
        if ($null -eq $n) { return '' }
        $Value = $n
    }
    $v = ("$Value" -replace '[\r\n\t]+', ' ').Trim()
    if ($v -notmatch (Get-SIReleaseControlState).WaveName) { return '' }
    $v
}

function Get-SIReleaseWaveFromUpdateState {
    <#
        PURE. The wave of the code this install runs, from the update state (-Json: the compact row cfg.InstallState
        'UpdateState', or the full Key Vault state). Returns @{ Known; Wave }:
          Known  $true when the state could be read (then Wave is the wave or $null = none); $false = nothing recorded / not
                 readable -> the heartbeat leaves the field out (an older install sends nothing new)
          Wave   [ordered]@{ name; version; ring } or $null
    #>
    param([AllowNull()][AllowEmptyString()][string]$Json)
    $none = [pscustomobject]@{ Known = $false; Wave = $null }
    $o = ConvertFrom-SIGuardStrictJson $Json
    if ($null -eq $o) { return $none }
    $code = Get-SIGuardStrictField $o 'code'
    $name = ''; $ver = ''; $ring = $null
    if ($code) {
        $w = Get-SIGuardStrictField $code 'wave'
        if ($null -ne $w -and -not ($w -is [string])) {
            $name = ConvertTo-SIReleaseWaveName (Get-SIGuardStrictField $w 'name')
            $ver = [string](Get-SIGuardStrictField $w 'version'); $ring = Get-SIGuardStrictField $w 'ring'
        } elseif ($w -is [string]) {
            $name = ConvertTo-SIReleaseWaveName $w
        }
        if (-not $name) {
            # the full state (Key Vault): appliedWave + appliedVersion + appliedRing
            $name = ConvertTo-SIReleaseWaveName (Get-SIGuardStrictField $code 'appliedWave')
            if ($name) { $ver = [string](Get-SIGuardStrictField $code 'appliedVersion'); $ring = Get-SIGuardStrictField $code 'appliedRing' }
        }
    }
    if (-not $name) { return [pscustomobject]@{ Known = $true; Wave = $null } }
    $ver = "$ver".Trim(); if ($ver -notmatch (Get-SIReleaseControlState).VersionText) { $ver = '' }
    $rn = ConvertTo-SIReleaseControlRing $ring
    [pscustomobject]@{ Known = $true; Wave = [ordered]@{ name = $name; version = $(if ($ver) { $ver } else { $null }); ring = $(if ($rn -ge 0) { $rn } else { $null }) } }
}

function Format-SIReleaseRingLabel {
    <# PURE. The header's words: "Ring 2 - Pre-release (Pre1)" in a wave, else "ring 2" (as today). #>
    param([AllowNull()]$Ring, [AllowEmptyString()][string]$Wave)
    $rn = ConvertTo-SIReleaseControlRing $Ring
    $w = ConvertTo-SIReleaseWaveName $Wave
    if ($rn -lt 0) { return '' }
    if ($w) { return ('Ring {0} - Pre-release ({1})' -f $rn, $w) }
    'ring {0}' -f $rn
}

# =====================================================================================================================
#  Release mode -- PURE over the engine fingerprint record (cfg.InstallState 'EngineFingerprint', CR4)
# =====================================================================================================================
function Get-SIReleaseModeFromFingerprint {
    <#
        PURE. Release mode from the fingerprint record the updater keeps: a release that CHANGED engine code sets strictFrom
        + strictVersion; release mode lasts -Hours (12) from strictFrom, reports every -EveryMinutes (30). A SuperAdmin ending
        the stricter safety checks early does NOT end release mode (it is about reporting, not about the limits).
        Returns @{ Known; Active; Since; Until; Version; Wire }:
          Known   a fingerprint is recorded (else: an older install -- the field is left out)
          Wire    [ordered]@{ version; sinceUtc; untilUtc; everyMinutes } while Active, else $null
    #>
    param([AllowNull()]$Fingerprint, [Parameter(Mandatory)][datetime]$NowUtc, [int]$Hours = (Get-SIReleaseControlState).ReleaseModeHours,
          [int]$EveryMinutes = (Get-SIReleaseControlState).EveryMinutes)
    $out = [ordered]@{ Known = $false; Active = $false; Since = $null; Until = $null; Version = ''; Wire = $null }
    $fp = if ($Fingerprint -is [string]) { ConvertFrom-SIGuardStrictJson $Fingerprint } else { $Fingerprint }
    $hash = ([string](Get-SIGuardStrictField $fp 'hash')).Trim().ToLowerInvariant()
    if ($hash -notmatch '^[0-9a-f]{64}$') { return [pscustomobject]$out }
    $out.Known = $true
    $from = ConvertTo-SIGuardStrictUtc (Get-SIGuardStrictField $fp 'strictFrom')
    if ($null -eq $from) { return [pscustomobject]$out }
    $now = $NowUtc.ToUniversalTime()
    $until = $from.AddHours($Hours)
    if ($now -ge $until -or $now -lt $from.AddMinutes(-5)) { return [pscustomobject]$out }
    $v = ([string](Get-SIGuardStrictField $fp 'strictVersion')).Trim()
    if ($v -notmatch (Get-SIReleaseControlState).VersionText) { $v = '' }
    $out.Active = $true; $out.Since = $from; $out.Until = $until; $out.Version = $v
    $out.Wire = [ordered]@{ version = $(if ($v) { $v } else { $null }); sinceUtc = (ConvertTo-SIGuardStrictIso $from); untilUtc = (ConvertTo-SIGuardStrictIso $until); everyMinutes = $EveryMinutes }
    [pscustomobject]$out
}

function Get-SIReleaseModeSlot {
    <# PURE. Which half hour of release mode -NowUtc is in (0 = the first); -1 when not in release mode. #>
    param([AllowNull()]$Mode, [Parameter(Mandatory)][datetime]$NowUtc, [int]$EveryMinutes = (Get-SIReleaseControlState).EveryMinutes)
    if ($null -eq $Mode -or -not $Mode.Active -or $null -eq $Mode.Since) { return -1 }
    $m = ($NowUtc.ToUniversalTime() - ([datetime]$Mode.Since)).TotalMinutes
    if ($m -lt 0) { return 0 }
    [int][Math]::Floor($m / [Math]::Max(1, $EveryMinutes))
}

function Test-SIReleaseControlHold {
    <# PURE. Is the hold (a refused heartbeat with the release fields) still on at -NowUtc? -Hold: the row's JSON. #>
    param([AllowNull()]$Hold, [Parameter(Mandatory)][datetime]$NowUtc)
    $h = if ($Hold -is [string]) { ConvertFrom-SIGuardStrictJson $Hold } else { $Hold }
    $u = ConvertTo-SIGuardStrictUtc (Get-SIGuardStrictField $h 'untilUtc')
    [bool]($null -ne $u -and $NowUtc.ToUniversalTime() -lt $u)
}

# =====================================================================================================================
#  The rows (cfg.InstallState) -- through the (sql, params, mode) seam
# =====================================================================================================================
function Get-SIReleaseControlRowsSql {
    "IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Name, Value FROM cfg.InstallState WHERE Name IN (N'EngineFingerprint', N'GuardStrictEnd', N'ReleaseControlHold', N'UpdateState');"
}

function Read-SIReleaseControlRows {
    <# The rows release control reads, as @{ EngineFingerprint; GuardStrictEnd; ReleaseControlHold; UpdateState } (text or
       $null). Throws on a failed read (the caller decides). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $h = [ordered]@{ EngineFingerprint = $null; GuardStrictEnd = $null; ReleaseControlHold = $null; UpdateState = $null }
    # the Pro store's reader answers ONE array of rows (New-SIProSettingsStore: , $out.ToArray()) -- flattened here, so the
    # rows are read whatever the seam's shape (live 2026-10-16: the same shape made the hourly heartbeat's claim read as 0)
    foreach ($r in @(& $Invoke (Get-SIReleaseControlRowsSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ })) {
        $n = [string](Get-SIGuardStrictField $r 'Name')
        if ($h.Contains($n)) { $h[$n] = [string](Get-SIGuardStrictField $r 'Value') }
    }
    [pscustomobject]$h
}

function Get-SIReleaseModeClaimSql {
    <#
        ONE statement: claim the half hour's report (-Slot of release mode -Since) in cfg.InstallState 'ReleaseModeReport' --
        taken only when no report of this slot (or a later one) of this release mode was claimed before. Returns Claimed 1/0.
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NULL
    SELECT CAST(0 AS int) AS Claimed;
ELSE
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    DECLARE @cur NVARCHAR(400) = NULL, @ok int = 0;
    SELECT @cur = Value FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'ReleaseModeReport';
    IF @cur IS NULL AND NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'ReleaseModeReport')
    BEGIN
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'ReleaseModeReport', @Value, @Version, @By);
        SET @ok = 1;
    END
    ELSE IF ISNULL(CASE WHEN ISJSON(@cur) = 1 THEN JSON_VALUE(@cur, '$.since') END, N'') <> @Since
         OR ISNULL(CASE WHEN ISJSON(@cur) = 1 THEN TRY_CAST(JSON_VALUE(@cur, '$.slot') AS int) END, -1) < @Slot
    BEGIN
        UPDATE cfg.InstallState SET Value = @Value, [Version] = @Version, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'ReleaseModeReport';
        SET @ok = 1;
    END
    COMMIT;
    SELECT @ok AS Claimed;
END
'@
}

function Invoke-SIReleaseModeClaim {
    <# Claim this half hour's release-mode report. $true = this process sends it. Throws on a failed write. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$Mode, [Parameter(Mandatory)][int]$Slot, [Parameter(Mandatory)][datetime]$NowUtc, [string]$By = 'release-mode report')
    $since = ConvertTo-SIGuardStrictIso $Mode.Since
    $value = ([ordered]@{ since = $since; slot = $Slot; sentUtc = (ConvertTo-SIGuardStrictIso $NowUtc) } | ConvertTo-Json -Compress)
    $ver = "$($Mode.Version)"; if ($ver.Length -gt 32) { $ver = $ver.Substring(0, 32) }
    $rows = @(& $Invoke (Get-SIReleaseModeClaimSql) ([ordered]@{ Value = $value; Version = $(if ($ver) { $ver } else { $null }); By = $By; Since = $since; Slot = $Slot }) 'reader' | ForEach-Object { $_ } | Where-Object { $_ })
    if (-not $rows.Count) { return $false }
    [int](Get-SIGuardStrictField $rows[0] 'Claimed') -eq 1
}

function Get-SIReleaseControlHoldSql {
    @'
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'ReleaseControlHold')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'ReleaseControlHold';
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'ReleaseControlHold', @Value, NULL, @By);
    COMMIT;
END
'@
}

function Save-SIReleaseControlHold {
    <# Hold the release fields back for 24 hours (Invardia refused a heartbeat that carried them). Never throws. #>
    param([scriptblock]$Invoke, [Parameter(Mandatory)][datetime]$NowUtc, [string]$Why = '')
    if (-not $Invoke) { return $false }
    try {
        $w = ("$Why" -replace '[\r\n\t]+', ' ').Trim(); if ($w.Length -gt 200) { $w = $w.Substring(0, 197) + '...' }
        $v = ([ordered]@{ untilUtc = (ConvertTo-SIGuardStrictIso $NowUtc.AddHours((Get-SIReleaseControlState).HoldHours)); why = $w } | ConvertTo-Json -Compress)
        $null = & $Invoke (Get-SIReleaseControlHoldSql) ([ordered]@{ Value = $v; By = 'telemetry' }) 'nonquery'
        $true
    } catch { $false }
}

function Get-SIReleaseControlInvoke {
    <# The Pro database seam a job already has: the settings layer's store, else the guard seam. $null = none (nothing read). #>
    try {
        if ($global:SI_ProSettingsStore -and $global:SI_ProSettingsStore.PSObject.Properties['Invoke'] -and $global:SI_ProSettingsStore.Invoke -is [scriptblock]) { return $global:SI_ProSettingsStore.Invoke }
        if ($global:SI_GuardInvoke -is [scriptblock]) { return $global:SI_GuardInvoke }
        if (Get-Command -Name Get-SIGuardProInvoke -ErrorAction SilentlyContinue) { $i = Get-SIGuardProInvoke; if ($i -is [scriptblock]) { return $i } }
    } catch { }
    $null
}

# =====================================================================================================================
#  Components: the scope map and the per-component fingerprints
# =====================================================================================================================
function Get-SIReleaseScopeMap {
    <# The component map (config\release-scopes.locked.json under -SIRoot, or -Json). Throws when it cannot be read. #>
    param([string]$SIRoot = (Get-SIReleaseControlState).SIRoot, [AllowEmptyString()][string]$Json)
    if (-not "$Json".Trim()) { $Json = [System.IO.File]::ReadAllText([System.IO.Path]::Combine($SIRoot, (Get-SIReleaseControlState).ScopeMapFile)) }
    $m = $Json.TrimStart([char]0xFEFF) | ConvertFrom-Json
    if (-not $m.scopes -or -not $m.raReports) { throw 'the component map has no scopes' }
    $m
}

function ConvertTo-SIReleaseGlobRegex {
    <# PURE. A map pattern as an anchored, case-blind regex: '**' any levels, '*' text inside one level. #>
    param([Parameter(Mandatory)][string]$Pattern)
    $p = $Pattern.Trim().Replace('\', '/')
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('^(?i)')
    for ($i = 0; $i -lt $p.Length; $i++) {
        $c = $p[$i]
        if ($c -eq '*') {
            if ($i + 1 -lt $p.Length -and $p[$i + 1] -eq '*') {
                $i++
                if ($i + 1 -lt $p.Length -and $p[$i + 1] -eq '/') { $i++; [void]$sb.Append('(?:.*/)?') } else { [void]$sb.Append('.*') }
            } else { [void]$sb.Append('[^/]*') }
        } else { [void]$sb.Append([regex]::Escape([string]$c)) }
    }
    [void]$sb.Append('$')
    $sb.ToString()
}

function Resolve-SIReleaseFileTarget {
    <#
        PURE. Where one engine file belongs: @{ Kind = none | scope | group | core | ra; Id }. Order: the Risk Analysis
        report file, 'none', 'scopes', 'groups', 'core'; nothing matched = core.
    #>
    param([Parameter(Mandatory)][string]$Rel, [Parameter(Mandatory)]$Map)
    $r = $Rel.Replace('\', '/').TrimStart('/')
    if ($r -ieq [string]$Map.raReports.file) { return [pscustomobject]@{ Kind = 'ra'; Id = [string]$Map.raReports.group } }
    $hit = { param($list) foreach ($p in @($list)) { if ($p -and $r -match (ConvertTo-SIReleaseGlobRegex $p)) { return $true } }; $false }
    if (& $hit $Map.none) { return [pscustomobject]@{ Kind = 'none'; Id = '' } }
    foreach ($s in @($Map.scopes)) { if (& $hit $s.patterns) { return [pscustomobject]@{ Kind = 'scope'; Id = [string]$s.id } } }
    foreach ($g in @($Map.groups)) { if (& $hit $g.patterns) { return [pscustomobject]@{ Kind = 'group'; Id = [string]$g.id } } }
    [pscustomobject]@{ Kind = 'core'; Id = '' }
}

function Split-SIReleaseRaReports {
    <#
        PURE. The Risk Analysis report file's text as its report blocks: @{ Reports = ordered name -> block text; Rest = the
        text outside every report block }. Inside the top-level section "Reports:" only, a block starts at a line
        "    - ReportName: <name>" (any indent) and runs until the next such line or a line that starts in column 0. The
        report TEMPLATES (section "ReportTemplates:") are not reports: they stay in Rest (they belong to every report).
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $reports = [ordered]@{}; $rest = New-Object System.Text.StringBuilder
    $cur = $null; $buf = $null; $section = ''
    foreach ($line in @("$Text" -split "`r?`n")) {
        $sm = [regex]::Match($line, '^(?<s>[A-Za-z_][\w-]*)\s*:')
        if ($sm.Success) { $section = $sm.Groups['s'].Value }
        $m = [regex]::Match($line, '^\s+-\s+ReportName:\s*(?<n>\S.*?)\s*$')
        if ($m.Success -and $section -ceq 'Reports') {
            if ($cur) { $reports[$cur] = $buf.ToString() }
            $cur = $m.Groups['n'].Value.Trim('''', '"'); $buf = New-Object System.Text.StringBuilder; [void]$buf.Append($line).Append("`n"); continue
        }
        if ($cur -and $line -match '^[^\s#]') { $reports[$cur] = $buf.ToString(); $cur = $null; $buf = $null }
        if ($cur) { [void]$buf.Append($line).Append("`n") } else { [void]$rest.Append($line).Append("`n") }
    }
    if ($cur) { $reports[$cur] = $buf.ToString() }
    [pscustomobject]@{ Reports = $reports; Rest = $rest.ToString() }
}

function Get-SIReleaseTextSha256 {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { -join @($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$Text")) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}

function Get-SIReleaseScopeHashes {
    <#
        PURE. The fingerprint of every component: -Entries = one @{ Rel; Id } per engine file (Id = the file's content id: a
        SHA-256 of its bytes on an install, its git blob id in the publish tooling -- only ever compared with the same kind),
        -RaText = the Risk Analysis report file's text, -Map = the component map. Returns an ordered map component id ->
        SHA-256 (lower-case hex), sorted ordinally. A component's fingerprint covers its own files, its group's files and
        the core files -- so a core change changes every component, a group change every component of the group.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries, [AllowNull()][AllowEmptyString()][string]$RaText, [Parameter(Mandatory)]$Map)
    $bucket = @{}
    $add = { param($k, $line) if (-not $bucket.ContainsKey($k)) { $bucket[$k] = New-Object System.Collections.Generic.List[string] }; $bucket[$k].Add($line) }
    foreach ($e in @($Entries | Where-Object { $_ })) {
        $rel = ([string]$e.Rel).Replace('\', '/').TrimStart('/')
        $t = Resolve-SIReleaseFileTarget -Rel $rel -Map $Map
        $line = '{0}|{1}' -f $rel, ([string]$e.Id).ToLowerInvariant()
        switch ($t.Kind) {
            'none' { }
            'scope' { & $add ('s:' + $t.Id) $line }
            'group' { & $add ('g:' + $t.Id) $line }
            'ra' { }
            default { & $add 'core' $line }
        }
    }
    $ra = Split-SIReleaseRaReports -Text $RaText
    $prefix = [string]$Map.raReports.prefix; $raGroup = [string]$Map.raReports.group
    & $add ('g:' + $raGroup) ('{0}#rest|{1}' -f [string]$Map.raReports.file, (Get-SIReleaseTextSha256 $ra.Rest))
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($Map.scopes)) { $ids.Add([string]$s.id) }
    foreach ($n in @($ra.Reports.Keys)) {
        $id = $prefix + [string]$n
        $ids.Add($id)
        & $add ('s:' + $id) ('{0}#{1}|{2}' -f [string]$Map.raReports.file, $n, (Get-SIReleaseTextSha256 $ra.Reports[$n]))
    }
    $joined = { param($k) if ($bucket.ContainsKey($k)) { $l = $bucket[$k].ToArray(); [Array]::Sort($l, [StringComparer]::Ordinal); ($l -join "`n") } else { '' } }
    $core = & $joined 'core'
    $groups = @(@($Map.groups) | ForEach-Object { [string]$_.id }) + @($raGroup) | Select-Object -Unique
    $arr = $ids.ToArray() | Select-Object -Unique
    $arr = [string[]]@($arr); [Array]::Sort($arr, [StringComparer]::Ordinal)
    $out = [ordered]@{}
    foreach ($id in $arr) {
        $g = @($groups | Where-Object { $_ -and $id.StartsWith($_, [StringComparison]::Ordinal) } | ForEach-Object { 'g ' + $_ + "`n" + (& $joined ('g:' + $_)) })
        $out[$id] = Get-SIReleaseTextSha256 ("core`n{0}`n--`n{1}`n--`nown`n{2}" -f $core, ($g -join "`n"), (& $joined ('s:' + $id)))
    }
    $out
}

function Get-SIReleaseScopeHashesFromDisk {
    <# The component fingerprints of the code under -SIRoot (an install: the release the updater just extracted). #>
    param([Parameter(Mandatory)][string]$SIRoot, $Map)
    if (-not $Map) { $Map = Get-SIReleaseScopeMap -SIRoot $SIRoot }
    $root = [System.IO.Path]::GetFullPath($SIRoot)
    $entries = New-Object System.Collections.Generic.List[object]
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        foreach ($f in @($Map.folders)) {
            $dir = [System.IO.Path]::Combine($root, [string]$f)
            if (-not [System.IO.Directory]::Exists($dir)) { continue }
            foreach ($p in [System.IO.Directory]::GetFiles($dir, '*', [System.IO.SearchOption]::AllDirectories)) {
                $rel = $p.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/'
                $id = -join @($sha.ComputeHash([System.IO.File]::ReadAllBytes($p)) | ForEach-Object { $_.ToString('x2') })
                $entries.Add([pscustomobject]@{ Rel = $rel; Id = $id })
            }
        }
    } finally { $sha.Dispose() }
    $raPath = [System.IO.Path]::Combine($root, ([string]$Map.raReports.file).Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    $raText = if ([System.IO.File]::Exists($raPath)) { [System.IO.File]::ReadAllText($raPath) } else { '' }
    Get-SIReleaseScopeHashes -Entries $entries.ToArray() -RaText $raText -Map $Map
}

function Invoke-SIReleaseGitText {
    <# #917: git text (show / log) read as UTF-8 whatever the console's encoding -- setup\_shared\SI-GitText.ps1's
       Invoke-SIGitText when this tree carries it (the release tooling), else git as before (an install's tree). #>
    param([Parameter(Mandatory)][string]$RepoRoot, [Parameter(Mandatory)][string[]]$Arguments)
    if (-not (Get-Command -Name Invoke-SIGitText -ErrorAction SilentlyContinue)) {
        $gt = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'setup', '_shared', 'SI-GitText.ps1')
        if ([System.IO.File]::Exists($gt)) { . $gt }
    }
    if (Get-Command -Name Invoke-SIGitText -ErrorAction SilentlyContinue) { return (Invoke-SIGitText -RepoRoot $RepoRoot -Arguments $Arguments) }
    & git -C $RepoRoot @Arguments 2>$null
}

function Get-SIReleaseScopeHashesFromGit {
    <# The component fingerprints of SOLUTIONS/SecurityInsight at -Ref of the clone -RepoRoot (git blob ids as content ids). Throws when git cannot read it. #>
    param([Parameter(Mandatory)][string]$RepoRoot, [Parameter(Mandatory)][string]$Ref, [Parameter(Mandatory)]$Map, [string]$SolutionPath = 'SOLUTIONS/SecurityInsight')
    $global:LASTEXITCODE = 0
    $paths = @(@($Map.folders) | ForEach-Object { '{0}/{1}' -f $SolutionPath, $_ })
    $lines = @(& git -C $RepoRoot ls-tree -r --full-tree $Ref -- @($paths) 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ("cannot list the engine files of '{0}': {1}" -f $Ref, ($lines -join ' ')) }
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($l in $lines) {
        $m = [regex]::Match([string]$l, '^\d+\s+blob\s+(?<id>[0-9a-f]{40,64})\t(?<p>.+)$')
        if (-not $m.Success) { continue }
        $p = $m.Groups['p'].Value.Trim('"')
        if (-not $p.StartsWith($SolutionPath + '/', [StringComparison]::Ordinal)) { continue }
        $entries.Add([pscustomobject]@{ Rel = $p.Substring($SolutionPath.Length + 1); Id = $m.Groups['id'].Value })
    }
    $global:LASTEXITCODE = 0
    $ra = @(Invoke-SIReleaseGitText -RepoRoot $RepoRoot -Arguments @('show', ('{0}:{1}/{2}' -f $Ref, $SolutionPath, [string]$Map.raReports.file)))
    $raText = if ($LASTEXITCODE -eq 0) { $ra -join "`n" } else { '' }
    $global:LASTEXITCODE = 0
    Get-SIReleaseScopeHashes -Entries $entries.ToArray() -RaText $raText -Map $Map
}

function Compare-SIReleaseScopeHashes {
    <#
        PURE. Which components changed from -Previous to -Current (both: component id -> fingerprint). A component that is
        new counts as changed; one that is gone is listed in Removed. No previous fingerprints at all = nothing changed
        (First = $true). Returns @{ First; Changed (sorted ids); Removed; All (every component changed); Total }.
    #>
    param([AllowNull()][System.Collections.IDictionary]$Previous, [Parameter(Mandatory)][System.Collections.IDictionary]$Current)
    $cur = @($Current.Keys | ForEach-Object { [string]$_ })
    if ($null -eq $Previous -or $Previous.Count -eq 0) { return [pscustomobject]@{ First = $true; Changed = @(); Removed = @(); All = $false; Total = $cur.Count } }
    $changed = New-Object System.Collections.Generic.List[string]
    foreach ($k in $cur) { if (-not $Previous.Contains($k) -or [string]$Previous[$k] -ne [string]$Current[$k]) { $changed.Add($k) } }
    $removed = @($Previous.Keys | ForEach-Object { [string]$_ } | Where-Object { -not $Current.Contains($_) })
    $c = $changed.ToArray(); [Array]::Sort($c, [StringComparer]::Ordinal)
    [pscustomobject]@{ First = $false; Changed = @($c); Removed = @($removed); All = ($cur.Count -gt 0 -and $c.Count -eq $cur.Count); Total = $cur.Count }
}

function Format-SIReleaseChangedScopes {
    <#
        PURE. The changedScopes value of a publish call: '*' when every component changed (a core file) or more than
        -Max did, else the ids joined with ','. '' when none changed. As a list for a JSON body: -AsList.
    #>
    param([Parameter(Mandatory)]$Comparison, [int]$Max = (Get-SIReleaseControlState).MaxScopesListed, [switch]$AsList)
    $c = @($Comparison.Changed)
    if (-not $c.Count) { if ($AsList) { return , @() } else { return '' } }
    $all = [bool]$Comparison.All -or $c.Count -gt $Max
    if ($AsList) { if ($all) { return , @('*') } else { return , @($c) } }
    if ($all) { return '*' }
    $c -join ','
}

function Get-SIReleaseChangedScopesFromGit {
    <#
        The publish tooling: the components a release changed between -SinceRef (the previous release's commit) and -Ref,
        judged with the component map of -Ref. Returns the Compare-SIReleaseScopeHashes result. Throws when git cannot compare
        them -- an unknown answer is never sent as "nothing changed".
    #>
    param([Parameter(Mandatory)][string]$RepoRoot, [Parameter(Mandatory)][string]$SinceRef, [Parameter(Mandatory)][string]$Ref, $Map, [string]$SolutionPath = 'SOLUTIONS/SecurityInsight')
    if (-not $Map) {
        $global:LASTEXITCODE = 0
        $mj = @(Invoke-SIReleaseGitText -RepoRoot $RepoRoot -Arguments @('show', ('{0}:{1}/{2}' -f $Ref, $SolutionPath, (Get-SIReleaseControlState).ScopeMapFile)))
        $Map = if ($LASTEXITCODE -eq 0 -and $mj.Count) { Get-SIReleaseScopeMap -Json ($mj -join "`n") } else { Get-SIReleaseScopeMap }
        $global:LASTEXITCODE = 0
    }
    $before = Get-SIReleaseScopeHashesFromGit -RepoRoot $RepoRoot -Ref $SinceRef -Map $Map -SolutionPath $SolutionPath
    $after = Get-SIReleaseScopeHashesFromGit -RepoRoot $RepoRoot -Ref $Ref -Map $Map -SolutionPath $SolutionPath
    $cmp = Compare-SIReleaseScopeHashes -Previous $before -Current $after
    # a commit before the components existed is still compared: its fingerprints are computed with today's map
    if ($cmp.First -and $after.Count) { $cmp = [pscustomobject]@{ First = $false; Changed = @($after.Keys); Removed = @(); All = $true; Total = $after.Count } }
    $cmp
}

function Resolve-SIPublishChangedScopesSwitch {
    <#
        PURE. framework 12.22 3(b): does the publish call carry changedScopes? SI_PUBLISH_CHANGEDSCOPES = off (never, the
        switch that turns the field off without a release) / on / auto (the default). auto = EVERY publish and ring call
        (owner 2026-10-18 "build pending"; Invardia's changedScopes intake is live and PIM sends it on every call since
        2026-10-16) -- -Ring only words the reason.
    #>
    param([AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_PUBLISH_CHANGEDSCOPES, [int]$Ring = -1)
    $s = "$EnvValue".Trim().ToLowerInvariant()
    if ($s -in @('on', 'true', '1', 'yes')) { return [pscustomobject]@{ On = $true; Reason = 'SI_PUBLISH_CHANGEDSCOPES is on' } }
    if ($s -in @('off', 'false', '0', 'no')) { return [pscustomobject]@{ On = $false; Reason = 'SI_PUBLISH_CHANGEDSCOPES is off' } }
    [pscustomobject]@{ On = $true; Reason = $(if ($Ring -ge 0) { "ring $Ring call" } else { 'the publish call (registered only)' }) }
}

# =====================================================================================================================
#  Components on the install: Testing / Stable (cfg.ReleaseScope)
# =====================================================================================================================
function Get-SIReleaseScopeReadSql {
    "IF OBJECT_ID(N'cfg.ReleaseScope') IS NOT NULL SELECT Scope, Hash, ChangedUtc, ChangedVersion, GoodDays, LastGoodDay FROM cfg.ReleaseScope;"
}

function Get-SIReleaseScopeState {
    <# PURE. One component row's state: Testing (its code changed and it has fewer than -GoodDays good daily runs since), else Stable. #>
    param([Parameter(Mandatory)]$Row, [int]$GoodDays = (Get-SIReleaseControlState).StableGoodDays)
    $ch = ConvertTo-SIGuardStrictUtc (Get-SIGuardStrictField $Row 'ChangedUtc')
    if ($null -eq $ch) { return 'Stable' }
    $n = 0; [void][int]::TryParse("$(Get-SIGuardStrictField $Row 'GoodDays')", [ref]$n)
    if ($n -ge $GoodDays) { 'Stable' } else { 'Testing' }
}

function New-SIReleaseScopePlan {
    <#
        PURE. What the updater writes after installing code whose component fingerprints are -Current, given the stored rows
        -Stored (Scope, Hash, ...). Returns @{ First; Rows (one @{ s; h; changed } per component of -Current); Changed (ids);
        Removed (ids) }. First = nothing stored before: every component is recorded with no change (Stable) -- an install that
        never recorded components gets no Testing state invented.
    #>
    param([AllowNull()][object[]]$Stored, [Parameter(Mandatory)][System.Collections.IDictionary]$Current)
    $prev = [ordered]@{}
    foreach ($r in @($Stored | Where-Object { $_ })) { $s = [string](Get-SIGuardStrictField $r 'Scope'); if ($s) { $prev[$s] = ([string](Get-SIGuardStrictField $r 'Hash')).Trim().ToLowerInvariant() } }
    $cmp = Compare-SIReleaseScopeHashes -Previous $prev -Current $Current
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($Current.Keys)) { $rows.Add([ordered]@{ s = [string]$k; h = [string]$Current[$k]; changed = [bool](@($cmp.Changed) -contains [string]$k) }) }
    [pscustomobject]@{ First = [bool]$cmp.First; Rows = $rows.ToArray(); Changed = @($cmp.Changed); Removed = @($cmp.Removed) }
}

function Get-SIReleaseScopeSaveSql {
    <# ONE transaction: the component rows of -Json ([{ s, h, changed }]) -- a changed one is Testing from @Now (good runs 0),
       an unchanged one keeps its state, a gone one is removed. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.ReleaseScope') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    DECLARE @j TABLE (Scope NVARCHAR(200) NOT NULL PRIMARY KEY, Hash CHAR(64) NOT NULL, Changed bit NOT NULL);
    INSERT @j (Scope, Hash, Changed) SELECT s, h, c FROM OPENJSON(@Json) WITH (s NVARCHAR(200) '$.s', h CHAR(64) '$.h', c bit '$.changed');
    DELETE r FROM cfg.ReleaseScope r WHERE NOT EXISTS (SELECT 1 FROM @j j WHERE j.Scope = r.Scope);
    UPDATE r SET Hash = j.Hash, ChangedUtc = @Now, ChangedVersion = @Version, GoodDays = 0, LastGoodDay = NULL, UpdatedAt = SYSUTCDATETIME()
      FROM cfg.ReleaseScope r JOIN @j j ON j.Scope = r.Scope WHERE j.Changed = 1;
    INSERT cfg.ReleaseScope (Scope, Hash, ChangedUtc, ChangedVersion, GoodDays)
      SELECT j.Scope, j.Hash, CASE WHEN j.Changed = 1 THEN @Now END, CASE WHEN j.Changed = 1 THEN @Version END, 0
      FROM @j j WHERE NOT EXISTS (SELECT 1 FROM cfg.ReleaseScope r WHERE r.Scope = j.Scope);
    COMMIT;
END
'@
}

function Save-SIReleaseScopeRecords {
    <#
        The UPDATER, after installing a release (-SIRoot: the extracted, verified code): the component fingerprints into
        cfg.ReleaseScope -- a changed component is Testing from now. Never throws: @{ Ok; First; Changed; Removed; Reason }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$SIRoot, [string]$Version = '', $NowUtc)
    try {
        $now = if ($NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow }
        $cur = Get-SIReleaseScopeHashesFromDisk -SIRoot $SIRoot
        if (-not $cur.Count) { return [pscustomobject]@{ Ok = $false; First = $false; Changed = @(); Removed = @(); Reason = 'no component found in this release' } }
        $stored = @(& $Invoke (Get-SIReleaseScopeReadSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ })
        $plan = New-SIReleaseScopePlan -Stored $stored -Current $cur
        $ver = "$Version".Trim(); if ($ver.Length -gt 50) { $ver = $ver.Substring(0, 50) }
        $json = ConvertTo-Json -InputObject @($plan.Rows) -Compress -Depth 3
        $null = & $Invoke (Get-SIReleaseScopeSaveSql) ([ordered]@{ Json = $json; Now = $now; Version = $(if ($ver) { $ver } else { $null }) }) 'nonquery'
        $why = if ($plan.First) { '{0} components recorded (the first time: none is marked Testing)' -f $cur.Count }
               elseif (@($plan.Changed).Count) { '{0} of {1} components changed and are Testing until 3 good daily runs: {2}' -f @($plan.Changed).Count, $cur.Count, (Format-SIReleaseScopeList @($plan.Changed)) }
               else { 'no component changed ({0} recorded)' -f $cur.Count }
        [pscustomobject]@{ Ok = $true; First = $plan.First; Changed = @($plan.Changed); Removed = @($plan.Removed); Reason = $why }
    } catch { [pscustomobject]@{ Ok = $false; First = $false; Changed = @(); Removed = @(); Reason = ("the components could not be recorded: {0}" -f $_.Exception.Message) } }
}

function Format-SIReleaseScopeList {
    <# PURE. A short plain list: the first 8 ids and "and N more". #>
    param([AllowNull()][object[]]$Ids)
    $a = @($Ids | Where-Object { $_ })
    if ($a.Count -le 8) { return ($a -join ', ') }
    '{0} and {1} more' -f (($a | Select-Object -First 8) -join ', '), ($a.Count - 8)
}

function Get-SIReleaseScopesForEngine {
    <# PURE. The components an engine run counts for: @{ Ids; Prefix } from the map's 'engines' lists (a group: every
       component whose id starts with its prefix). Empty = the engine is no component's. #>
    param([AllowEmptyString()][string]$Engine, [Parameter(Mandatory)]$Map)
    $e = "$Engine".Trim().ToLowerInvariant()
    $ids = @(); $prefix = ''
    if (-not $e -or $e.StartsWith('flow')) { return [pscustomobject]@{ Ids = @(); Prefix = '' } }
    foreach ($s in @($Map.scopes)) { if (@($s.engines | ForEach-Object { "$_".ToLowerInvariant() }) -contains $e) { $ids += [string]$s.id } }
    foreach ($g in @($Map.groups)) { if (@($g.engines | ForEach-Object { "$_".ToLowerInvariant() }) -contains $e) { $prefix = [string]$g.id } }
    [pscustomobject]@{ Ids = @($ids); Prefix = $prefix }
}

function Get-SIReleaseScopeRunSql {
    <#
        ONE statement for one engine run's components (-Count ids @s0..@sN and/or the prefix @Prefix):
          good   a run that started after the change counts once per UTC day while the component is Testing
          bad    a failed run starts the count again while it is Testing
    #>
    param([Parameter(Mandatory)][ValidateSet('good', 'bad')][string]$Kind, [int]$Count = 0, [switch]$HasPrefix)
    $parts = @()
    if ($Count -gt 0) { $parts += ('Scope IN ({0})' -f ((0..($Count - 1) | ForEach-Object { '@s' + $_ }) -join ', ')) }
    if ($HasPrefix) { $parts += "Scope LIKE @Prefix + N'%'" }
    $where = '(' + ($parts -join ' OR ') + ') AND ChangedUtc IS NOT NULL AND GoodDays < @Need'
    if ($Kind -eq 'good') {
        return ("IF OBJECT_ID(N'cfg.ReleaseScope') IS NOT NULL UPDATE cfg.ReleaseScope SET GoodDays = GoodDays + 1, LastGoodDay = @Today, UpdatedAt = SYSUTCDATETIME() WHERE {0} AND ChangedUtc <= @StartedAt AND (LastGoodDay IS NULL OR LastGoodDay < @Today);" -f $where)
    }
    "IF OBJECT_ID(N'cfg.ReleaseScope') IS NOT NULL UPDATE cfg.ReleaseScope SET GoodDays = 0, LastGoodDay = NULL, UpdatedAt = SYSUTCDATETIME() WHERE {0};" -f $where
}

function Update-SIReleaseScopeRun {
    <#
        One engine run ended (-Engine, -ExitReason success | error | ...): its components count a good daily run, or start
        their count again. Other outcomes (partial, throttled, skipped) change nothing. A Risk Analysis run with a report
        that is not complete (-ReportsIncomplete > 0) is not a good run. Returns $true when a statement ran. Throws on a
        failed write (the caller decides).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [AllowEmptyString()][string]$Engine, [AllowEmptyString()][string]$ExitReason, $StartedAt, $NowUtc,
          [long]$ReportsIncomplete = 0, $Map)
    if (-not $Map) { $Map = Get-SIReleaseScopeMap }
    $x = "$ExitReason".Trim().ToLowerInvariant()
    $kind = if ($x -eq 'success' -and $ReportsIncomplete -le 0) { 'good' } elseif ($x -in @('error', 'failure', 'failed', 'settings-error')) { 'bad' } else { '' }
    if (-not $kind) { return $false }
    $sc = Get-SIReleaseScopesForEngine -Engine $Engine -Map $Map
    $ids = @($sc.Ids)
    if (-not $ids.Count -and -not $sc.Prefix) { return $false }
    $now = if ($NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow }
    $start = if ($StartedAt) { try { ([datetime]$StartedAt).ToUniversalTime() } catch { $now } } else { $now }
    $p = [ordered]@{ Need = [int](Get-SIReleaseControlState).StableGoodDays }
    for ($i = 0; $i -lt $ids.Count; $i++) { $p[('s' + $i)] = [string]$ids[$i] }
    if ($sc.Prefix) { $p['Prefix'] = [string]$sc.Prefix }
    if ($kind -eq 'good') { $p['Today'] = $now.Date; $p['StartedAt'] = $start }
    $null = & $Invoke (Get-SIReleaseScopeRunSql -Kind $kind -Count $ids.Count -HasPrefix:([bool]$sc.Prefix)) $p 'nonquery'
    $true
}

function Invoke-SIReleaseScopeRunEnd {
    <#
        The run-health END moment (Send-SIRunHealthRow): this run's components count it. Only the engine's own END record
        (not a pipeline step record, not a shard other than the first), only with a Pro database the run has open, never in
        a test session (Pester) without -Invoke. NEVER throws; $true when counted.
    #>
    param([AllowNull()]$RunContext, [AllowEmptyString()][string]$ExitReason, [scriptblock]$Invoke, $NowUtc)
    try {
        if ($null -eq $RunContext) { return $false }
        $shard = 0; if ($RunContext.PSObject.Properties['ShardIndex']) { [void][int]::TryParse("$($RunContext.ShardIndex)", [ref]$shard) }
        if ($shard -gt 0) { return $false }
        if (-not $Invoke) {
            if (Get-Module -Name Pester) { return $false }
            $Invoke = Get-SIReleaseControlInvoke
        }
        if (-not $Invoke) { return $false }
        $inc = 0L
        if ($RunContext.PSObject.Properties['ReportsIncomplete']) { [void][long]::TryParse("$($RunContext.ReportsIncomplete)", [ref]$inc) }
        $st = if ($RunContext.PSObject.Properties['StartedAt']) { $RunContext.StartedAt } else { $null }
        Update-SIReleaseScopeRun -Invoke $Invoke -Engine ([string]$RunContext.Engine) -ExitReason $ExitReason -StartedAt $st -NowUtc $NowUtc -ReportsIncomplete $inc
    } catch { $false }
}

# =====================================================================================================================
#  The heartbeat's components + the daily evidence (framework 12.11e items 3 and 5(a); 2026-10-18)
# =====================================================================================================================
function ConvertTo-SIReleaseComponentWireId {
    <#
        PURE. One component id in the spelling Invardia's heartbeat takes for components.testingIds (its STABILITY_ID:
        ^[a-z][a-z0-9.-]{0,59}$): lower case, '_' and spaces as '-', anything else left out, at most 60 characters, never
        ending in '.' or '-'. '' when nothing is left (the id is then not listed; the counts still count it). The
        changedScopes of a publish call keep the component's own spelling (Invardia takes ^[A-Za-z0-9._-]{1,80}$ there).
    #>
    param([AllowNull()][AllowEmptyString()][string]$Id)
    $t = ("$Id".Trim().ToLowerInvariant() -replace '[_\s]+', '-') -replace '[^a-z0-9.-]', ''
    $t = $t -replace '^[^a-z]+', ''
    if ($t.Length -gt 60) { $t = $t.Substring(0, 60) }
    $t = $t.TrimEnd('.', '-')
    if ($t -notmatch '^[a-z][a-z0-9.-]{0,59}$') { return '' }
    $t
}

function ConvertTo-SIReleaseComponentsWire {
    <#
        PURE. Testing / Stable per component for the identified heartbeat (framework 12.11e item 3), counts + the ids of the
        components that are Testing (component ids are SecurityInsight's own names -- never a customer value):
          { total, testing, stable, testingIds: [ id, ... ] (at most MaxScopesListed, sorted), since, version }
        since / version: the newest code change of a component (cfg.ReleaseScope ChangedUtc / ChangedVersion); null when
        none was ever recorded. $null when no component is recorded (an older install: the field is left out).
    #>
    param([AllowNull()][object[]]$Rows)
    $rows = @($Rows | Where-Object { $_ })
    if (-not $rows.Count) { return $null }
    $s = Get-SIReleaseScopeSummary -Rows $rows
    # LIVE 2026-10-18: Invardia takes a testingIds entry only as ^[a-z][a-z0-9.-]{0,59}$ and drops the WHOLE components field
    # for one entry it does not take (only evidence.components arrived) -- a Risk Analysis report id carries capitals and
    # underscores, so every id goes in Invardia's spelling (ConvertTo-SIReleaseComponentWireId)
    $ids = [string[]]@(@($s.TestingIds | Where-Object { $_ } | ForEach-Object { ConvertTo-SIReleaseComponentWireId $_ } | Where-Object { $_ }) | Select-Object -Unique)
    [Array]::Sort($ids, [StringComparer]::Ordinal)
    $newest = $null; $ver = ''
    foreach ($r in $rows) {
        $c = ConvertTo-SIGuardStrictUtc (Get-SIGuardStrictField $r 'ChangedUtc')
        if ($null -ne $c -and ($null -eq $newest -or $c -gt $newest)) { $newest = $c; $ver = ([string](Get-SIGuardStrictField $r 'ChangedVersion')).Trim() }
    }
    if ($ver -notmatch (Get-SIReleaseControlState).VersionText) { $ver = '' }
    [ordered]@{ total = [int]$s.Total; testing = [int]$s.Testing; stable = [int]$s.Stable
        testingIds = @($ids | Select-Object -First (Get-SIReleaseControlState).MaxScopesListed)
        since = $(if ($newest) { ConvertTo-SIGuardStrictIso $newest } else { $null }); version = $(if ($ver) { $ver } else { $null }) }
}

function Get-SIReleaseEvidenceSql {
    <# ONE read: the data-health state and the guard trips (halted / held / refused -- a warning or a clear is no trip) in two windows ([@Before, @From) and [@From, now]). Read-only. #>
    @'
SET NOCOUNT ON;
SELECT
    (SELECT TOP (1) [State] FROM cfg.DataHealthState WHERE OBJECT_ID(N'cfg.DataHealthState') IS NOT NULL) AS HealthState,
    (SELECT TOP (1) Since FROM cfg.DataHealthState WHERE OBJECT_ID(N'cfg.DataHealthState') IS NOT NULL) AS HealthSince,
    (SELECT COUNT_BIG(*) FROM cfg.GuardEvent WHERE TsUtc >= @From AND Outcome IN (N'halted', N'held', N'refused')) AS TripsSince,
    (SELECT COUNT_BIG(*) FROM cfg.GuardEvent WHERE TsUtc >= @Before AND TsUtc < @From AND Outcome IN (N'halted', N'held', N'refused')) AS TripsBefore;
'@
}

function Get-SIReleaseEvidenceWindow {
    <#
        PURE. The release the evidence is about and its two windows: -Fingerprint (cfg.InstallState 'EngineFingerprint': the
        last release that changed engine code -- strictFrom / strictVersion), else the newest component change (-Components:
        ConvertTo-SIReleaseComponentsWire). @{ Known; Since; Version; Before; Hours } -- Before = Since minus the same length
        as Since -> now (at least 1 h, at most 30 days). Known $false = no release recorded: no evidence is sent.
    #>
    param([AllowNull()]$Fingerprint, [AllowNull()]$Components, [Parameter(Mandatory)][datetime]$NowUtc)
    $fp = if ($Fingerprint -is [string]) { ConvertFrom-SIGuardStrictJson $Fingerprint } else { $Fingerprint }
    $since = ConvertTo-SIGuardStrictUtc (Get-SIGuardStrictField $fp 'strictFrom')
    $ver = ([string](Get-SIGuardStrictField $fp 'strictVersion')).Trim()
    if ($null -eq $since -and $Components -and $Components['since']) { $since = ConvertTo-SIGuardStrictUtc $Components['since']; $ver = [string]$Components['version'] }
    if ($null -eq $since) { return [pscustomobject]@{ Known = $false; Since = $null; Version = ''; Before = $null; Hours = 0 } }
    if ("$ver" -notmatch (Get-SIReleaseControlState).VersionText) { $ver = '' }
    $now = $NowUtc.ToUniversalTime()
    $h = [Math]::Min(720.0, [Math]::Max(1.0, ($now - $since).TotalHours))
    [pscustomobject]@{ Known = $true; Since = $since; Version = $ver; Before = $since.AddHours(-$h); Hours = [int][Math]::Ceiling($h) }
}

function New-SIReleaseEvidence {
    <#
        PURE. The daily evidence of framework 12.11e item 5(a) -- counts and verdicts only, never a name, id or value:
          { day, version, sinceUtc, health: { state, sinceUtc } | null, guardTrips: { sinceRelease, before, windowHours,
            verdict: ok | more }, components: { total, testing, stable } | null, verdict: ok | attention }
        -Window: Get-SIReleaseEvidenceWindow; -Row: the Get-SIReleaseEvidenceSql row; -Components:
        ConvertTo-SIReleaseComponentsWire. verdict 'attention' = data health Unhealthy, or more guard trips since the release
        than in the same time before it. $null when -Window is not Known.
    #>
    param([Parameter(Mandatory)]$Window, [AllowNull()]$Row, [AllowNull()]$Components, [Parameter(Mandatory)][datetime]$NowUtc)
    if (-not $Window.Known) { return $null }
    $hs = ([string](Get-SIGuardStrictField $Row 'HealthState')).Trim()
    $health = $null
    if ($hs -in @('Healthy', 'Unhealthy')) {
        $hsi = ConvertTo-SIGuardStrictUtc (Get-SIGuardStrictField $Row 'HealthSince')
        $health = [ordered]@{ state = $hs; sinceUtc = $(if ($hsi) { ConvertTo-SIGuardStrictIso $hsi } else { $null }) }
    }
    $n = { param($v) $x = 0L; if ($null -ne $v) { [void][long]::TryParse("$v", [ref]$x) }; [Math]::Max(0L, $x) }
    $ts = & $n (Get-SIGuardStrictField $Row 'TripsSince'); $tb = & $n (Get-SIGuardStrictField $Row 'TripsBefore')
    $tripsVerdict = if ($ts -gt $tb) { 'more' } else { 'ok' }
    $comp = $null
    if ($Components) { $comp = [ordered]@{ total = [int]$Components['total']; testing = [int]$Components['testing']; stable = [int]$Components['stable'] } }
    [ordered]@{
        day        = $NowUtc.ToUniversalTime().ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        version    = $(if ($Window.Version) { $Window.Version } else { $null })
        sinceUtc   = ConvertTo-SIGuardStrictIso $Window.Since
        health     = $health
        guardTrips = [ordered]@{ sinceRelease = $ts; before = $tb; windowHours = [int]$Window.Hours; verdict = $tripsVerdict }
        components = $comp
        verdict    = $(if (($health -and $health.state -eq 'Unhealthy') -or $tripsVerdict -eq 'more') { 'attention' } else { 'ok' })
    }
}

function Read-SIReleaseEvidenceFields {
    <#
        The heartbeat's components + evidence from the Pro database (-Invoke), given the release-control rows (-Rows:
        Read-SIReleaseControlRows). Returns @{ Components; Evidence } (each $null = left out). Throws on a failed read (the
        caller leaves both out).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, $Rows, [Parameter(Mandatory)][datetime]$NowUtc)
    $scopeRows = @(& $Invoke (Get-SIReleaseScopeReadSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ })
    $comp = ConvertTo-SIReleaseComponentsWire -Rows $scopeRows
    $win = Get-SIReleaseEvidenceWindow -Fingerprint $(if ($Rows) { [string]$Rows.EngineFingerprint } else { $null }) -Components $comp -NowUtc $NowUtc
    $ev = $null
    if ($win.Known) {
        $row = @(& $Invoke (Get-SIReleaseEvidenceSql) ([ordered]@{ From = $win.Since; Before = $win.Before }) 'reader' | ForEach-Object { $_ } | Where-Object { $_ }) | Select-Object -First 1
        $ev = New-SIReleaseEvidence -Window $win -Row $row -Components $comp -NowUtc $NowUtc
    }
    [pscustomobject]@{ Components = $comp; Evidence = $ev }
}

function Get-SIReleaseScopeSummary {
    <# PURE. The component rows as @{ Testing; Stable; Total; TestingIds } (for the log and the web app's view). #>
    param([AllowNull()][object[]]$Rows)
    $t = @(); $s = 0
    foreach ($r in @($Rows | Where-Object { $_ })) { if ((Get-SIReleaseScopeState -Row $r) -eq 'Testing') { $t += [string](Get-SIGuardStrictField $r 'Scope') } else { $s++ } }
    [pscustomobject]@{ Testing = $t.Count; Stable = $s; Total = $t.Count + $s; TestingIds = @($t) }
}
