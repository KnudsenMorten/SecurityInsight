#Requires -Version 5.1
<#
    SecurityInsight -- STRICTER SAFETY CHECKS FOR 24 HOURS AFTER A RELEASE THAT CHANGED ENGINE CODE (CR4, SI #654; framework
    DOCS/REQUIREMENTS.md §12.11b GUARD-STRICT; approved by the owner 2026-10-14).

    THE TRIGGER -- the engine fingerprint. The updater computes a SHA-256 fingerprint over the engine folders of the release
    it has just installed (Get-SIEngineFingerprint: engine/, launcher/, risk-analysis-detection/ -- the same folders the
    publish call judges `engineChanged` by) and records it in the Pro database (cfg.InstallState 'EngineFingerprint'). A
    fingerprint that DIFFERS from the one recorded starts the stricter period; the same fingerprint (a template / text /
    web-only release) keeps it as it is. The FIRST fingerprint an install records starts nothing: an install that never
    recorded one (every install before this) behaves exactly as before -- no stricter period is invented.

    THE RULE -- every numbered damage brake (the limit a customer configures) is halved while the period lasts:
    effective = max(1, floor(configured x 0.5)), never above the configured value (a limit of 1 stays 1; 0 = "no limit"
    stays 0). Never lower than a limit a SuperAdmin approved for one run. The brakes (Resolve-SIGuardLimit at each one):
      vuln.connector.close-ceiling       SI_VulnSync_MaxClosePercent, SI_VulnSync_MaxCloseAbsolute
      asset.properties.collection-change SI_AssetProperties_ChangeGuardPercent
      cmdb.handoff.mass-change           the hand-off connector's changeGuardPercent (default the same setting)
      collection.source.asset-drop       SI_Pro_DataQuality_AssetDropPercent
      exemption.bulk.refused             SIWeb_Exemption_BulkMax (the web app, Guards\GuardMode.cs)

    THE PERIOD -- 24 hours from the time the updater recorded the changed fingerprint. A SuperAdmin may end it early with
    a reason (the web app, Operations > Guards (safety checks); audited guard.strict.end-early) -- cfg.InstallState 'GuardStrictEnd'.

    A STRICT TRIP is a normal trip: it holds as always and mails when its check mails (a check the catalog marks "mail": "never" does not); its numbers say the limit is halved, worded calmly
    ("stricter period after release X until <time>"), and its report to Invardia carries Strict, ConfiguredLimit and
    EffectiveLimit. The identified heartbeat carries guardMode { mode, until, startedBy, version, endedEarlyAt, endedBy }.

    NEVER THROWS where a job calls it: anything that cannot be read means Normal (the limits as configured -- as today).
    PS 5.1 and 7.
#>

function Get-SIGuardStrictState {
    <# The value of $script:SIGuardStrict, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SIGuardStrict) { $script:SIGuardStrict = @{
    Hours          = 24
    Folders        = @('engine', 'launcher', 'risk-analysis-detection')
    FingerprintRow = 'EngineFingerprint'
    EndRow         = 'GuardStrictEnd'
    CacheMinutes   = 5
} }
    , $script:SIGuardStrict
}
$script:SIGuardStrict = $null; $null = Get-SIGuardStrictState

# =====================================================================================================================
#  The engine fingerprint -- deterministic
# =====================================================================================================================
function Get-SIEngineFingerprintFolders {
    <# PURE. The engine folders (relative to the solution root), the same as the publish call's Get-SIEngineFolders. #>
    @((Get-SIGuardStrictState).Folders)
}

function Get-SIEngineFingerprint {
    <#
        The engine fingerprint of the code under -SIRoot: SHA-256 (lower-case hex) over one line pair per file of the engine
        folders -- "<path>`n<sha256 of the file's bytes>`n" -- with <path> relative to -SIRoot, '/' as separator, the list
        sorted ordinally. The same files give the same fingerprint on every machine; a renamed, added, removed or changed
        file gives another. '' when no engine folder exists under -SIRoot (nothing to judge).
    #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $root = [System.IO.Path]::GetFullPath($SIRoot)
    $files = New-Object System.Collections.Generic.List[object]
    foreach ($f in (Get-SIEngineFingerprintFolders)) {
        $dir = [System.IO.Path]::Combine($root, $f)
        if (-not [System.IO.Directory]::Exists($dir)) { continue }
        foreach ($p in [System.IO.Directory]::GetFiles($dir, '*', [System.IO.SearchOption]::AllDirectories)) {
            $rel = $p.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/'
            $files.Add([pscustomobject]@{ Rel = $rel; Path = $p })
        }
    }
    if ($files.Count -eq 0) { return '' }
    $sorted = $files.ToArray()
    $keys = [string[]]@($sorted | ForEach-Object { [string]$_.Rel })
    [Array]::Sort($keys, $sorted, [StringComparer]::Ordinal)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $sb = New-Object System.Text.StringBuilder
        foreach ($x in $sorted) {
            $bytes = [System.IO.File]::ReadAllBytes($x.Path)
            $h = -join @($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
            [void]$sb.Append($x.Rel).Append("`n").Append($h).Append("`n")
        }
        return (-join @($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sb.ToString())) | ForEach-Object { $_.ToString('x2') }))
    } finally { $sha.Dispose() }
}

function ConvertTo-SIGuardStrictUtc {
    <# PURE. A stored time as UTC, or $null. A text without a zone is read AS UTC. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [System.DBNull] -or "$Value".Trim() -eq '') { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }; return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse("$Value", [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    $null
}

function ConvertTo-SIGuardStrictIso {
    param([AllowNull()]$Value)
    $u = ConvertTo-SIGuardStrictUtc $Value
    if ($null -eq $u) { return $null }
    $u.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-SIGuardStrictJson {
    <# PURE. A stored JSON row as an object; $null for nothing / not JSON / not an object. #>
    param([AllowNull()][AllowEmptyString()][string]$Json)
    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    try { $o = ConvertFrom-Json -InputObject $Json -ErrorAction Stop } catch { return $null }
    if ($null -eq $o -or $o -is [string] -or $o -is [System.ValueType] -or $o -is [array]) { return $null }
    $o
}

function Get-SIGuardStrictField {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    if ($Object.PSObject.Properties[$Name]) { return $Object.$Name }
    $null
}

function New-SIEngineFingerprintRecord {
    <#
        PURE. The updater's record after installing code with -Hash (version -Version) at -NowUtc, given the record before
        (-Previous: its JSON). Returns @{ Record (ordered: hash, version, since, strictFrom, strictVersion); Changed; First }
        -- $null when -Hash is empty (nothing is recorded).
          no record before (or not readable)  recorded, NO stricter period (First = $true) -- an older install never gets
                                              one invented
          the same fingerprint                the record as it was (its period, if any, unchanged); the version updated
          another fingerprint                 strictFrom = -NowUtc, strictVersion = -Version: the stricter period starts
    #>
    param([AllowNull()][AllowEmptyString()][string]$Previous, [AllowEmptyString()][string]$Hash, [AllowEmptyString()][string]$Version, [Parameter(Mandatory)][datetime]$NowUtc)
    $h = "$Hash".Trim().ToLowerInvariant()
    if ($h -notmatch '^[0-9a-f]{64}$') { return $null }
    $now = ConvertTo-SIGuardStrictIso $NowUtc.ToUniversalTime()
    $ver = "$Version".Trim(); if ($ver.Length -gt 50) { $ver = $ver.Substring(0, 50) }
    $p = ConvertFrom-SIGuardStrictJson $Previous
    $ph = ([string](Get-SIGuardStrictField $p 'hash')).Trim().ToLowerInvariant()
    if ($ph -notmatch '^[0-9a-f]{64}$') {
        return [pscustomobject]@{ Record = [ordered]@{ hash = $h; version = $ver; since = $now; strictFrom = $null; strictVersion = '' }; Changed = $false; First = $true }
    }
    if ($ph -eq $h) {
        $rec = [ordered]@{ hash = $h; version = $(if ($ver) { $ver } else { [string](Get-SIGuardStrictField $p 'version') })
                           since = (ConvertTo-SIGuardStrictIso (Get-SIGuardStrictField $p 'since'))
                           strictFrom = (ConvertTo-SIGuardStrictIso (Get-SIGuardStrictField $p 'strictFrom'))
                           strictVersion = [string](Get-SIGuardStrictField $p 'strictVersion') }
        return [pscustomobject]@{ Record = $rec; Changed = $false; First = $false }
    }
    [pscustomobject]@{ Record = [ordered]@{ hash = $h; version = $ver; since = $now; strictFrom = $now; strictVersion = $ver }; Changed = $true; First = $false }
}

# =====================================================================================================================
#  The guard mode -- PURE over the two rows
# =====================================================================================================================
function Get-SIGuardModeFromState {
    <#
        PURE. The install's guard mode from its fingerprint record (-Fingerprint) and a SuperAdmin's early end (-StrictEnd),
        both JSON (or objects). Returns @{ Mode ('strict' | 'normal'); Recorded (a fingerprint is recorded); Until;
        Version (the release that started the period); StrictFrom; Hash; EndedEarlyAt; EndedBy; EndedByRole; Reason }.
        Strict = a period started (strictFrom), -NowUtc before its end (strictFrom + -Hours), and no early end OF THIS
        PERIOD (the end names the same fingerprint and start). An early end of an older period ends nothing.
    #>
    param([AllowNull()]$Fingerprint, [AllowNull()]$StrictEnd, [Parameter(Mandatory)][datetime]$NowUtc, [int]$Hours = (Get-SIGuardStrictState).Hours)
    $fp = if ($Fingerprint -is [string]) { ConvertFrom-SIGuardStrictJson $Fingerprint } else { $Fingerprint }
    $en = if ($StrictEnd -is [string]) { ConvertFrom-SIGuardStrictJson $StrictEnd } else { $StrictEnd }
    $now = $NowUtc.ToUniversalTime()
    $out = [ordered]@{ Mode = 'normal'; Recorded = $false; Until = $null; Version = ''; StrictFrom = $null; Hash = ''; EndedEarlyAt = $null; EndedBy = ''; EndedByRole = ''; Reason = '' }
    $hash = ([string](Get-SIGuardStrictField $fp 'hash')).Trim().ToLowerInvariant()
    if ($hash -notmatch '^[0-9a-f]{64}$') { return [pscustomobject]$out }
    $out.Recorded = $true; $out.Hash = $hash
    $from = ConvertTo-SIGuardStrictUtc (Get-SIGuardStrictField $fp 'strictFrom')
    if ($null -eq $from) { return [pscustomobject]$out }
    $until = $from.AddHours($Hours)
    if ($now -ge $until -or $now -lt $from.AddMinutes(-5)) { return [pscustomobject]$out }
    $out.StrictFrom = $from; $out.Until = $until; $out.Version = [string](Get-SIGuardStrictField $fp 'strictVersion')
    if ($en) {
        $eh = ([string](Get-SIGuardStrictField $en 'hash')).Trim().ToLowerInvariant()
        $ef = ConvertTo-SIGuardStrictUtc (Get-SIGuardStrictField $en 'strictFrom')
        $ea = ConvertTo-SIGuardStrictUtc (Get-SIGuardStrictField $en 'endedAt')
        if ($eh -eq $hash -and $ef -and [Math]::Abs(($ef - $from).TotalSeconds) -lt 1 -and $ea) {
            $out.EndedEarlyAt = $ea; $out.EndedBy = [string](Get-SIGuardStrictField $en 'by')
            $out.EndedByRole = $(if ([string](Get-SIGuardStrictField $en 'role')) { [string](Get-SIGuardStrictField $en 'role') } else { 'SuperAdmin' })
            $out.Reason = [string](Get-SIGuardStrictField $en 'reason')
            return [pscustomobject]$out
        }
    }
    $out.Mode = 'strict'
    [pscustomobject]$out
}

function ConvertTo-SIGuardModeWire {
    <#
        PURE. The heartbeat's guardMode (framework §12.11b item 5; Invardia's parseGuardMode): { mode ('strict' | 'normal'),
        until, startedBy (the release that started it), version (the same), endedEarlyAt, endedBy (a ROLE, never a person) }.
        $null when no fingerprint is recorded -- an older install sends nothing new.
    #>
    param([AllowNull()]$Mode)
    if ($null -eq $Mode -or -not $Mode.Recorded) { return $null }
    $v = "$($Mode.Version)".Trim()
    if ($v -and $v -notmatch '^[0-9A-Za-z.+-]{1,50}$') { $v = '' }
    $role = "$($Mode.EndedByRole)".Trim()
    if ($role -and $role -notmatch '^[A-Za-z][A-Za-z0-9 ._-]{0,39}$') { $role = 'SuperAdmin' }
    [ordered]@{
        mode         = [string]$Mode.Mode
        until        = (ConvertTo-SIGuardStrictIso $Mode.Until)
        startedBy    = $(if ($v) { $v } else { $null })
        version      = $(if ($v) { $v } else { $null })
        endedEarlyAt = (ConvertTo-SIGuardStrictIso $Mode.EndedEarlyAt)
        endedBy      = $(if ($Mode.EndedEarlyAt -and $role) { $role } else { $null })
    }
}

# =====================================================================================================================
#  The limit -- PURE
# =====================================================================================================================
function Get-SIGuardStrictLimit {
    <#
        PURE. One numbered limit while -Strict: effective = max(1, floor(-Configured x 0.5)), never above -Configured (a
        limit of 1 stays 1; 0 or less = "no limit" stays as it is); never below -ApprovedForRun (a limit a SuperAdmin
        approved for one run). Not strict = the configured value. Returns @{ Configured; Effective; Halved; Text }.
    #>
    param([AllowNull()]$Configured, [bool]$Strict, [AllowNull()]$ApprovedForRun)
    $c = 0.0
    $ok = ($null -ne $Configured) -and [double]::TryParse(("$Configured").Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$c) -and -not [double]::IsNaN($c) -and -not [double]::IsInfinity($c)
    if (-not $ok) { return [pscustomobject]@{ Configured = $Configured; Effective = $Configured; Halved = $false; Text = '' } }
    $e = $c
    if ($Strict -and $c -gt 0) {
        $e = [Math]::Max(1.0, [Math]::Floor($c * 0.5))
        if ($e -gt $c) { $e = $c }
        $a = 0.0
        if ($null -ne $ApprovedForRun -and [double]::TryParse(("$ApprovedForRun").Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$a) -and $a -gt $e) { $e = $a }
    }
    $num = { param($d) if ($d -eq [Math]::Floor($d) -and [Math]::Abs($d) -lt 9e15) { [long]$d } else { [Math]::Round($d, 4) } }
    $cv = & $num $c; $ev = & $num $e
    $halved = ($ev -ne $cv)
    [pscustomobject]@{ Configured = $cv; Effective = $ev; Halved = [bool]$halved; Text = $(if ($halved) { '{0} -> {1} while strict' -f $cv, $ev } else { '' }) }
}

# =====================================================================================================================
#  The guard mode NOW -- read once per process (5 minutes), never throws
# =====================================================================================================================
function Get-SIGuardModeSql {
    "IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Name, Value FROM cfg.InstallState WHERE Name IN (N'EngineFingerprint', N'GuardStrictEnd');"
}

function Read-SIGuardModeState {
    <# The two rows from the Pro database (-Invoke: the (sql, params, mode) seam) -> Get-SIGuardModeFromState. Throws on a
       failed read (the caller decides). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][datetime]$NowUtc)
    $fp = $null; $en = $null
    foreach ($r in @(& $Invoke (Get-SIGuardModeSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ })) {
        $n = [string](Get-SIGuardStrictField $r 'Name'); $v = [string](Get-SIGuardStrictField $r 'Value')
        if ($n -eq (Get-SIGuardStrictState).FingerprintRow) { $fp = $v } elseif ($n -eq (Get-SIGuardStrictState).EndRow) { $en = $v }
    }
    Get-SIGuardModeFromState -Fingerprint $fp -StrictEnd $en -NowUtc $NowUtc
}

function Get-SIGuardModeNow {
    <#
        The install's guard mode now. $global:SI_GuardModeOverride (a test's, or a run's own) wins; a test session (Pester
        loaded) never reads a database; else the Pro database (the guard seam $global:SI_GuardInvoke, else
        Get-SIGuardProInvoke), remembered for 5 minutes. Anything that cannot be read = normal. Never throws.
    #>
    param([switch]$Refresh, [scriptblock]$Invoke, $NowUtc)
    $now = if ($NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow }
    $normal = [pscustomobject]@{ Mode = 'normal'; Recorded = $false; Until = $null; Version = ''; StrictFrom = $null; Hash = ''; EndedEarlyAt = $null; EndedBy = ''; EndedByRole = ''; Reason = '' }
    try {
        if ($null -ne $global:SI_GuardModeOverride) { return $global:SI_GuardModeOverride }
        if (-not $Invoke -and (Get-Module -Name Pester)) { return $normal }
        $c = $script:SIGuardModeCache
        if (-not $Refresh -and -not $Invoke -and $c -and ($now - $c.At).TotalMinutes -lt (Get-SIGuardStrictState).CacheMinutes -and $now -ge $c.At) { return $c.Mode }
        $inv = $Invoke
        if (-not $inv -and $global:SI_GuardInvoke -is [scriptblock]) { $inv = $global:SI_GuardInvoke }
        if (-not $inv -and (Get-Command -Name Get-SIGuardProInvoke -ErrorAction SilentlyContinue)) { $inv = Get-SIGuardProInvoke }
        $m = if ($inv) { Read-SIGuardModeState -Invoke $inv -NowUtc $now } else { $normal }
        if (-not $Invoke) { $script:SIGuardModeCache = [pscustomobject]@{ At = $now; Mode = $m } }
        return $m
    } catch { return $normal }
}

function Format-SIGuardStrictUntil {
    <# PURE. "2026-10-15 14:00 UTC". #>
    param([AllowNull()]$Until)
    $u = ConvertTo-SIGuardStrictUtc $Until
    if ($null -eq $u) { return '' }
    '{0:yyyy-MM-dd HH:mm} UTC' -f $u
}

function Format-SIGuardStrictSentence {
    <# PURE. The calm sentence: "Stricter period after release 3.0.1 until 2026-10-15 14:00 UTC: ...". '' when not strict. #>
    param([AllowNull()]$Strict)
    if ($null -eq $Strict) { return '' }
    $after = if ("$($Strict.Version)".Trim()) { ' after release ' + "$($Strict.Version)".Trim() } else { ' after a recent release' }
    $until = Format-SIGuardStrictUntil $Strict.Until
    $u = if ("$($Strict.Unit)".Trim()) { ' ' + "$($Strict.Unit)".Trim() } else { '' }
    $nums = if ($null -ne $Strict.Effective -and $null -ne $Strict.Configured) { (' Here the limit is {0}{2} (normally {1}{2}).' -f $Strict.Effective, $Strict.Configured, $u) } else { '' }
    ('This safety check is in its stricter period{0}{1}: its limit is halved for 24 hours after a release that changed the engine, as planned.{2} After the period the normal limit applies again by itself.' -f `
        $after, $(if ($until) { ' until ' + $until } else { '' }), $nums)
}

function Resolve-SIGuardLimit {
    <#
        The limit a brake uses NOW: the configured value, halved while the install is in its stricter period
        (Get-SIGuardStrictLimit over Get-SIGuardModeNow). A halved limit is remembered for the guard's event
        ($global:SI_GuardStrictApplied[<guard id>]: the trip's report then carries strict + configured + effective) and
        said once per process and guard in one calm line. -Mode: a mode handed in (tests). Never throws: the configured
        value on any problem. Returns @{ Configured; Effective; Halved; Text; Strict (the remembered entry or $null) }.
    #>
    param([Parameter(Mandatory)][string]$GuardId, [string]$Name, [string]$Label, [AllowNull()]$Configured, [string]$Unit, [AllowNull()]$ApprovedForRun, $Mode, [scriptblock]$Log)
    try {
        $m = if ($Mode) { $Mode } else { Get-SIGuardModeNow }
        $strict = [string]$m.Mode -eq 'strict'
        $l = Get-SIGuardStrictLimit -Configured $Configured -Strict $strict -ApprovedForRun $ApprovedForRun
        $entry = $null
        if ($l.Halved) {
            $entry = [pscustomobject]@{ GuardId = $GuardId; Name = $Name; Label = $(if ($Label) { $Label } else { $Name }); Configured = $l.Configured; Effective = $l.Effective
                                        Unit = $Unit; Until = $m.Until; Version = [string]$m.Version }
            if ($null -eq $global:SI_GuardStrictApplied) { $global:SI_GuardStrictApplied = @{} }
            $first = -not $global:SI_GuardStrictApplied.ContainsKey(('{0}|{1}' -f $GuardId, $Name))
            $global:SI_GuardStrictApplied[('{0}|{1}' -f $GuardId, $Name)] = $entry
            $global:SI_GuardStrictApplied[$GuardId] = $entry
            if ($first) {
                $u = if ($Unit) { ' ' + $Unit } else { '' }
                $line = 'stricter period{0}{1}: {2} {3}{5} -> {4}{5} while it lasts (safety check {6})' -f `
                    $(if ("$($m.Version)".Trim()) { ' after release ' + "$($m.Version)".Trim() } else { '' }), $(if ($m.Until) { ' until ' + (Format-SIGuardStrictUntil $m.Until) } else { '' }),
                    $entry.Label, $l.Configured, $l.Effective, $u, $GuardId
                # the caller's -Log failing never drops the halved limit (it was caught below: the configured value)
                try { if ($Log) { & $Log 'INFO' $line } else { Write-Host (' [INFO] ' + $line) } } catch { Write-Host (' [INFO] ' + $line) }
            }
        }
        return [pscustomobject]@{ Configured = $l.Configured; Effective = $l.Effective; Halved = $l.Halved; Text = $l.Text; Strict = $entry }
    } catch {
        return [pscustomobject]@{ Configured = $Configured; Effective = $Configured; Halved = $false; Text = ''; Strict = $null }
    }
}

function Add-SIGuardStrictToEvent {
    <#
        PURE over the remembered entries. A guard event whose limit was halved by Resolve-SIGuardLimit in this process gets
        Strict = @{ Configured; Effective; Unit; Until; Version; Label } and, on its value with the same name, Configured
        (the configured limit beside the effective one -- a negative limit, the asset drop's, keeps its sign). -Applied: the
        remembered entries (default $global:SI_GuardStrictApplied). Returns the event.
    #>
    param([Parameter(Mandatory)]$Event, [System.Collections.IDictionary]$Applied = $global:SI_GuardStrictApplied)
    $gid = [string]$Event.GuardId
    if (-not $Applied -or -not $Applied.Contains($gid)) { return $Event }
    $first = $null
    foreach ($v in @($Event.Values)) {
        if ($null -eq $v -or $null -eq $v.Limit) { continue }
        $k = '{0}|{1}' -f $gid, [string]$v.Name
        if (-not $Applied.Contains($k)) { continue }
        $s = $Applied[$k]
        $cfg = if ([double]$v.Limit -lt 0) { -1 * [double]$s.Configured } else { [double]$s.Configured }
        if ($cfg -eq [Math]::Floor($cfg)) { $cfg = [long]$cfg }
        $v | Add-Member -NotePropertyName Configured -NotePropertyValue $cfg -Force
        if (-not $first) { $first = $s }
    }
    $Event | Add-Member -NotePropertyName Strict -NotePropertyValue $(if ($first) { $first } else { $Applied[$gid] }) -Force
    $Event
}
