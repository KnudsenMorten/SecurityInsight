#Requires -Version 5.1
<#
    SecurityInsight -- GUARD EVENTS (#277): every guard that holds, refuses or halts a step to protect data tells a person
    and Invardia, on by default.

    ONE CALL for every guard: Send-SIGuardEvent. It takes the guard id (stable, dotted, from config\guard-catalog.locked.json),
    the outcome (halted | refused | held | skipped | warning), the measured values against their limits, what was held, an
    optional subject (which connector / report / job), the detail sentence and a link -- and then, EACH STEP FAILURE-SAFE
    (nothing here ever throws to its caller, and nothing here can fail the job that tripped the guard):

      (a) RUN HEALTH   one row in SI_RunHealth_CL, Phase 'Guard', ExitReason 'guard-<outcome>' (the run's own Start / End
                       rows are untouched; every reader of run health filters on Phase == 'End');
      (b) AUDIT        one AUDIT-1 event 'guard.event.trip' on the Pro database's audit trail (Pro only: needs the database);
      (c) MAIL         one mail per guard per run to SI_GuardMail_To (else the install's report recipients, MailTo; else the
                       Pro SuperAdmins), through the Risk Analysis relay settings and transports. ON by default
                       (SI_GuardMail_Enabled). DE-DUPLICATED: a guard that keeps tripping mails again only after 24 hours,
                       and that mail says "still tripping (N times)". The trip state lives in the Pro database
                       (cfg.GuardState) when there is one, else in a small file (%ProgramData%\SecurityInsight\guards);
      (d) TELEMETRY    one GUARD-1 record (Schema 2, Kind 'guard' -- Invardia's receiver, 2026-10-04) posted through the
                       framework client's Send-AitUplink, following SI_Telemetry_Enabled (default ON). Self-sufficient for a
                       support ticket per environment + guard: GuardId, GuardOutcome, Severity, Area, Job, Measured /
                       Thresholds (numbers), HeldCount, TripCount, FirstSeenUtc, Version, Ring. ANONYMOUS adds only the random
                       InstallId -- no tenant, host, subject, detail, action text or link; IDENTIFIED adds ClaimedTenantId,
                       Host, ActionText (redacted, at most 500 characters) and Link (https). The framework's own record
                       builder (New-AitUplinkReport) knows heartbeat | run | install only; the guard record is built here.
      (e) THE GUARDS VIEW  one row in cfg.GuardEvent (Pro database) -- the web app's Operations > Guards (safety checks) view, and the
                       outbox the mail job reads for events the web app writes (Invoke-SIGuardOutbox).

    A TEST SESSION NEVER MAILS OR SENDS (Pester loaded, no transport handed in) and never writes state to the machine.

    Customer-facing words (subject, body) are plain language: what was protected, what happened, the numbers against the
    limit, what was held (nothing lost), what to do. No internal numbers, no jargon.

    PS 5.1 and 7.
#>

if (-not (Get-Command -Name Get-SITelemetryContext -ErrorAction SilentlyContinue)) {
    try { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-TelemetrySend.ps1')) } catch { }
}
# MAIL-1: the one mail transport (SI_Mail_Mode: sharedMailbox | smtp | none)
if (-not (Get-Command -Name Send-SIMail -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-MailTransport.ps1')) }
# CR4 (#654): the stricter period after a release that changed engine code -- halved limits, the guard mode
if (-not (Get-Command -Name Resolve-SIGuardLimit -ErrorAction SilentlyContinue)) {
    $sgs = [System.IO.Path]::Combine($PSScriptRoot, 'SI-GuardStrict.ps1')
    if ([System.IO.File]::Exists($sgs)) { . $sgs }
}
# owner 2026-10-17: guards heal themselves, say which release they tripped on, and can be accepted at every install
if (-not (Get-Command -Name Get-SIGuardHealDecision -ErrorAction SilentlyContinue)) {
    $sgh = [System.IO.Path]::Combine($PSScriptRoot, 'SI-GuardHeal.ps1')
    if ([System.IO.File]::Exists($sgh)) { . $sgh }
}

$script:SIGuard = @{
    SIRoot      = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    WindowHours = 24
    Catalog     = $null
    IdPattern   = '^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2}$'
    NamePattern = '^[a-z][A-Za-z0-9]{0,30}$'
    Sources     = @('job', 'web', 'setup', 'engine')
    AuditAction = 'guard.event.trip'
    Product     = 'securityinsight'
}
if ($null -eq $global:SI_GuardHealth) { $global:SI_GuardHealth = @{ Events = 0; Failed = 0; LastError = '' } }

# =====================================================================================================================
#  The catalog -- PURE (reads one shipped file)
# =====================================================================================================================
function Get-SIGuardCatalog {
    <# The closed list of guards (config\guard-catalog.locked.json): outcomes, severity per outcome, guards. Cached. #>
    param([string]$SIRoot = $script:SIGuard.SIRoot, [switch]$Refresh)
    if ($script:SIGuard.Catalog -and -not $Refresh -and -not $PSBoundParameters.ContainsKey('SIRoot')) { return $script:SIGuard.Catalog }
    $p = [System.IO.Path]::Combine($SIRoot, 'config', 'guard-catalog.locked.json')
    $c = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($p))
    if (-not $PSBoundParameters.ContainsKey('SIRoot')) { $script:SIGuard.Catalog = $c }
    $c
}

function Get-SIGuardDefinition {
    <# The catalog entry of one guard id; throws for an id that is not listed (a guard must be listed on purpose). #>
    param([Parameter(Mandatory)][string]$Id)
    $g = @((Get-SIGuardCatalog).guards | Where-Object { [string]$_.id -eq $Id }) | Select-Object -First 1
    if (-not $g) { throw ("guard '{0}' is not in config\guard-catalog.locked.json" -f $Id) }
    $g
}

function Get-SIGuardSeverity {
    <# PURE. halted / refused = critical (the step did not happen); held / skipped / warning = warning. #>
    param([Parameter(Mandatory)][string]$Outcome)
    switch ($Outcome) {
        'halted'  { return 'critical' }
        'refused' { return 'critical' }
        'held'    { return 'warning' }
        'skipped' { return 'warning' }
        'warning' { return 'warning' }
    }
    throw ("'{0}' is not a guard outcome (halted, refused, held, skipped, warning)" -f $Outcome)
}

# =====================================================================================================================
#  Settings -- PURE over the values handed in
# =====================================================================================================================
function Test-SIGuardFlag {
    <# PURE. A switch setting: the setting wins when set, then the environment value, else -Default. false/0/off/no = off. #>
    param([AllowNull()]$Value, [AllowNull()][AllowEmptyString()][string]$EnvValue, [bool]$Default = $true)
    foreach ($v in @($Value, $EnvValue)) {
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { return $v }
        $s = ([string]$v).Trim().Trim('$').ToLowerInvariant()
        if (-not $s) { continue }
        return -not ($s -in @('false', '0', 'off', 'no', 'disabled'))
    }
    $Default
}

function Get-SIGuardSetting {
    <# One setting: -Globals (a test's hashtable) when given, else the live global. #>
    param([Parameter(Mandatory)][string]$Name, [System.Collections.IDictionary]$Globals)
    if ($Globals) { if ($Globals.Contains($Name)) { return $Globals[$Name] }; return $null }
    Get-Variable -Name $Name -Scope Global -ValueOnly -ErrorAction SilentlyContinue
}

function Test-SIGuardMailEnabled {
    param([System.Collections.IDictionary]$Globals)
    $envV = if ($Globals) { $null } else { $env:SI_GUARDMAIL_ENABLED }
    Test-SIGuardFlag -Value (Get-SIGuardSetting -Name 'SI_GuardMail_Enabled' -Globals $Globals) -EnvValue $envV -Default $true
}

# =====================================================================================================================
#  #414 -- THE GUARD SWITCHES (operator, 2026-10-06: "give me settings for ALL gates, so I can turn them off and fine
#  tune them"). Every guard in config\guard-catalog.locked.json has two settings, both ON by default:
#    SI_Guard_<Token>_Enabled   off = the guard does not hold, refuse or halt: it logs ONE line "guard <id> is off
#                               (setting ...)" and the step goes on as if it had not tripped (no event, no mail). For a
#                               guard whose stop is not SecurityInsight's own choice (the source failed, the data has no
#                               key, the licence) off means: no event and no mail -- the catalog's 'whenOff' says which,
#                               in plain words, and the Settings page shows it.
#    SI_Guard_<Token>_Mail      off = the event is still recorded (Guards page, run health, audit), but not mailed.
#  plus ONE master switch SI_Guards_Enabled (off = every guard is off). <Token> = the id in PascalCase
#  ('vuln.connector.close-ceiling' -> 'VulnConnectorCloseCeiling'). Pro: the Settings page (cfg.Setting -> $global:);
#  Community / VM: the same names in the configuration file.
# =====================================================================================================================
function ConvertTo-SIGuardSettingToken {
    <# PURE. 'vuln.connector.close-ceiling' -> 'VulnConnectorCloseCeiling'. #>
    param([Parameter(Mandatory)][string]$GuardId)
    (@($GuardId -split '[.\-]' | Where-Object { $_ } | ForEach-Object { $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1) })) -join ''
}

function Get-SIGuardSwitchNames {
    <# PURE. The setting names of one guard's switches. #>
    param([Parameter(Mandatory)][string]$GuardId)
    $t = ConvertTo-SIGuardSettingToken -GuardId $GuardId
    [pscustomobject]@{ Master = 'SI_Guards_Enabled'; Enabled = ('SI_Guard_{0}_Enabled' -f $t); Mail = ('SI_Guard_{0}_Mail' -f $t) }
}

function Test-SIGuardDefaultOn {
    <#
        #448 (operator 2026-10-07: "turn off these in all env worldwide" -- "people are pissed of all these stupid blockers"):
        a guard is ON by default unless the catalog marks it "defaultOff": true. Those guards (a report that shrank, a
        collection of a not-complete run, the vulnerability connector after a not-complete run) neither hold, refuse nor
        mail until an install switches them ON (SI_Guard_<Token>_Enabled = true). Unreadable catalog: on (never throws).
    #>
    param([Parameter(Mandatory)][string]$GuardId)
    try {
        $g = @((Get-SIGuardCatalog).guards | Where-Object { [string]$_.id -eq $GuardId }) | Select-Object -First 1
        return -not ($g -and $g.PSObject.Properties['defaultOff'] -and [bool]$g.defaultOff)
    } catch { return $true }
}
function Test-SIGuardOn {
    <#
        Is this guard on? The master switch (SI_Guards_Enabled, env SI_GUARDS_ENABLED) AND the guard's own
        SI_Guard_<Token>_Enabled; the master defaults ON, a guard ON unless the catalog marks it "defaultOff". A guard that is
        off says so ONCE per process per guard, in one line: "guard <id> is off (setting <name>) -- the step goes on without
        it". That line is a WARN only when an install SWITCHED OFF a check that is on by default (or the master); a guard
        that is off because the catalog default says so (nothing set) is INFO -- the guard relief (owner 2026-10-11) turned
        all but two guards off by default, and 34 warnings a run would be noise. -Quiet says nothing. Never throws (on).
    #>
    param([Parameter(Mandatory)][string]$GuardId, [System.Collections.IDictionary]$Globals, [scriptblock]$Log, [switch]$Quiet)
    try {
        $n = Get-SIGuardSwitchNames -GuardId $GuardId
        $envM = if ($Globals) { $null } else { $env:SI_GUARDS_ENABLED }
        $master = Test-SIGuardFlag -Value (Get-SIGuardSetting -Name $n.Master -Globals $Globals) -EnvValue $envM -Default $true
        $ownValue = Get-SIGuardSetting -Name $n.Enabled -Globals $Globals
        $defaultOn = Test-SIGuardDefaultOn -GuardId $GuardId
        $own = Test-SIGuardFlag -Value $ownValue -Default $defaultOn
        if ($master -and $own) { return $true }
        if (-not $Quiet) {
            if ($null -eq $global:SI_GuardOffSaid) { $global:SI_GuardOffSaid = @{} }
            if (-not $global:SI_GuardOffSaid.ContainsKey($GuardId)) {
                $global:SI_GuardOffSaid[$GuardId] = $true
                # the guard's own switch is set (an empty value = not set)
                $explicit = -not ($null -eq $ownValue -or ($ownValue -isnot [bool] -and -not ([string]$ownValue).Trim().Trim('$')))
                $line = if ((-not $master) -or $explicit) { 'guard {0} is off (setting {1}) -- the step goes on without it' -f $GuardId, $(if (-not $master) { $n.Master } else { $n.Enabled }) }
                        else { 'guard {0} is off by default (switch it on with {1}) -- the step goes on without it' -f $GuardId, $n.Enabled }
                # WARN only when a protection that is on by default was switched off (the master, or a default-on guard's switch).
                # The caller's -Log failing never changes the answer: it was caught below as "on" -- a guard that is OFF read
                # as on (the SQL CMDB run of 2026-10-22: its logger recursed until the call depth overflowed)
                $warnLine = ((-not $master) -or ($explicit -and $defaultOn))
                try {
                    if ($warnLine) { if ($Log) { & $Log 'WARN' $line } else { Write-Warning $line } }
                    elseif ($Log) { & $Log 'INFO' $line } else { Write-Verbose $line }
                } catch { Write-Warning ('{0} (the step''s log could not take this line: {1})' -f $line, $_.Exception.Message) }
            }
        }
        return $false
    } catch { return $true }
}

function Test-SIGuardMailOn {
    <#
        The guard's own mail switch SI_Guard_<Token>_Mail. Not set = it follows the guard: on while the guard is on (a
        default-off guard an install switches on mails without a second switch), off while it is off. The install-wide
        SI_GuardMail_Enabled is separate.
    #>
    param([Parameter(Mandatory)][string]$GuardId, [System.Collections.IDictionary]$Globals)
    try { Test-SIGuardFlag -Value (Get-SIGuardSetting -Name (Get-SIGuardSwitchNames -GuardId $GuardId).Mail -Globals $Globals) -Default (Test-SIGuardOn -GuardId $GuardId -Globals $Globals -Quiet) } catch { $true }
}

function Get-SIGuardOffList {
    <# The ids of the guards that are off now (for a PURE planner that takes -GuardsOff). Each is said once (Test-SIGuardOn). #>
    param([string[]]$GuardIds, [System.Collections.IDictionary]$Globals, [scriptblock]$Log)
    $ids = if ($GuardIds) { $GuardIds } else { @((Get-SIGuardCatalog).guards | ForEach-Object { [string]$_.id }) }
    @($ids | Where-Object { -not (Test-SIGuardOn -GuardId $_ -Globals $Globals -Log $Log) })
}

function Get-SIGuardCauseKey {
    <# PURE. A short stable hash of one cause (SHA-256, first 16 hex characters), for Send-SIGuardEvent -CauseKeys. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $b = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text.Trim().ToLowerInvariant())) } finally { $sha.Dispose() }
    (-join @($b | Select-Object -First 8 | ForEach-Object { $_.ToString('x2') }))
}

function Split-SIGuardAddresses {
    <# PURE. A list, or text separated by ',' or ';' -> the addresses (something@something), trimmed, each once. #>
    param([AllowNull()]$Value)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        foreach ($p in ("$v" -split '[,;]')) {
            $t = $p.Trim()
            if ($t -match '^[^@\s]+@[^@\s]+$' -and -not ($out -contains $t)) { $out.Add($t) }
        }
    }
    # unrolled on purpose: callers wrap the call in @() (one address stays a one-element list, none an empty one)
    $out.ToArray()
}

function Get-SIGuardMailRecipients {
    <#
        PURE. Who the guard mails go to: SI_GuardMail_To, else the install's report recipients (MailTo), else the Pro
        SuperAdmins' mail addresses (-SuperAdminMails). Returns @{ To; Source }.
    #>
    param([System.Collections.IDictionary]$Globals, [AllowNull()][string[]]$SuperAdminMails)
    $to = @(Split-SIGuardAddresses (Get-SIGuardSetting -Name 'SI_GuardMail_To' -Globals $Globals))
    if ($to.Count) { return [pscustomobject]@{ To = $to; Source = 'SI_GuardMail_To' } }
    $to = @(Split-SIGuardAddresses (Get-SIGuardSetting -Name 'MailTo' -Globals $Globals))
    if ($to.Count) { return [pscustomobject]@{ To = $to; Source = 'MailTo' } }
    $to = @(Split-SIGuardAddresses $SuperAdminMails)
    if ($to.Count) { return [pscustomobject]@{ To = $to; Source = 'SuperAdmins' } }
    [pscustomobject]@{ To = @(); Source = '' }
}

function Get-SIGuardSmtp {
    <#
        PURE. How SecurityInsight sends -- the ONE mail setting set every mail uses (Get-SIMailSettings, MAIL-1):
        SI_Mail_Mode (sharedMailbox | smtp | none), SI_Mail_From, and for smtp SmtpServer, SMTPPort, SMTP_UseSSL,
        SMTPFrom / MailFrom / SMTPUser, SMTPUser + SMTPPassword or SecureCredentialsSMTP, Mail_SendAnonymous.
        Kept here by name so a Community install, which does not ship the Pro close-loop mail, mails its guards too.
        Returns @{ Mode; Off; Server; Port; UseSsl; From; Anonymous; User; Password; SharedMailbox; Problems; ... }.
    #>
    param([System.Collections.IDictionary]$Globals)
    Get-SIMailSettings -Globals $Globals
}

# =====================================================================================================================
#  The event -- PURE
# =====================================================================================================================
function ConvertTo-SIGuardNumber {
    <# PURE. A measured value / limit as a number ($null when it is not one). Whole numbers stay [long]. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return $null }
    $d = 0.0
    if (-not [double]::TryParse(("$Value".Trim() -replace '%$', ''), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $null }
    if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { return $null }
    if ($d -eq [Math]::Floor($d) -and [Math]::Abs($d) -lt 9e15) { return [long]$d }
    [Math]::Round($d, 4)
}

function New-SIGuardEvent {
    <#
        PURE. One guard event, checked against the catalog. -Values: @( @{ Name = 'closeShare'; Label = 'Share of open
        records to close'; Measured = 25.9; Limit = 10; Unit = '%' }, ... ) -- Name is camelCase (it becomes a telemetry
        field), Label is what a person reads. -Subject names WHICH connector / report / job (never sent anonymously).
        -Detail is one plain sentence of what happened (never sent anonymously). -Action overrides the catalog's text.
    #>
    param(
        [Parameter(Mandatory)][string]$GuardId,
        [Parameter(Mandatory)][string]$Outcome,
        [string]$Engine, [string]$Job, [string]$Subject, [string]$Detail,
        [object[]]$Values = @(), [long]$HeldCount = 0, [string]$Action, [string]$Link,
        [string]$RunId, [datetime]$NowUtc = [datetime]::UtcNow, [string]$Source = 'job'
    )
    if ($GuardId -notmatch $script:SIGuard.IdPattern) { throw ("'{0}' is not a guard id (area.object.what, lower-case)" -f $GuardId) }
    $def = Get-SIGuardDefinition -Id $GuardId
    $sev = Get-SIGuardSeverity -Outcome $Outcome
    if ($script:SIGuard.Sources -notcontains $Source) { throw ("'{0}' is not a guard source ({1})" -f $Source, ($script:SIGuard.Sources -join ', ')) }
    if ($HeldCount -lt 0) { $HeldCount = 0 }
    $vals = New-Object System.Collections.Generic.List[object]
    foreach ($v in @($Values)) {
        if ($null -eq $v) { continue }
        $name = [string]$(if ($v -is [System.Collections.IDictionary]) { $v['Name'] } else { $v.Name })
        if ($name -notmatch $script:SIGuard.NamePattern) { throw ("guard value name '{0}' must be camelCase letters and digits (it is a telemetry field)" -f $name) }
        $get = { param($k) if ($v -is [System.Collections.IDictionary]) { $v[$k] } elseif ($v.PSObject.Properties[$k]) { $v.$k } else { $null } }
        $label = [string](& $get 'Label'); if (-not $label) { $label = $name }
        $vo = [pscustomobject]@{ Name = $name; Label = $label; Measured = (ConvertTo-SIGuardNumber (& $get 'Measured')); Limit = (ConvertTo-SIGuardNumber (& $get 'Limit')); Unit = [string](& $get 'Unit') }
        # CR4 (#654): a limit halved in the stricter period after a release carries the configured one beside it
        $cfgL = ConvertTo-SIGuardNumber (& $get 'Configured')
        if ($null -ne $cfgL -and $null -ne $vo.Limit) { $vo | Add-Member -NotePropertyName Configured -NotePropertyValue $cfgL }
        $vals.Add($vo)
    }
    $job = if ($Job) { $Job } elseif ([string]$def.job) { [string]$def.job } elseif ($Engine -and (Get-Command -Name Resolve-SITelemetryJob -ErrorAction SilentlyContinue)) { [string](Resolve-SITelemetryJob -Engine $Engine) } else { '' }
    $sub = "$Subject".Trim(); if ($sub.Length -gt 400) { $sub = $sub.Substring(0, 400) }
    $det = "$Detail".Trim(); if ($det.Length -gt 2000) { $det = $det.Substring(0, 2000) }
    [pscustomobject]@{
        GuardId   = $GuardId
        GuardKey  = $(if ($sub) { $GuardId + '|' + $sub.ToLowerInvariant() } else { $GuardId })
        Area      = [string]$def.area
        Job       = $job
        Engine    = [string]$Engine
        Protected = [string]$def.protects
        Subject   = $sub
        Outcome   = $Outcome
        Severity  = $sev
        Values    = $vals.ToArray()
        HeldCount = $HeldCount
        Detail    = $det
        Action    = $(if ($Action) { $Action } else { [string]$def.action })
        Link      = [string]$Link
        RunId     = $(if ($RunId) { $RunId } else { [string]$global:SI_GuardRunId })
        Source    = $Source
        TimeUtc   = $NowUtc.ToUniversalTime()
    }
}

function Format-SIGuardNumber {
    <# PURE. A number for a person: thousands grouped and decimals in -Culture (default: the install's number format, else
       invariant). $null reads "unknown". #>
    param([AllowNull()]$Value, [System.Globalization.CultureInfo]$Culture = [System.Globalization.CultureInfo]::InvariantCulture)
    if ($null -eq $Value) { return 'unknown' }
    if ($Value -is [long] -or $Value -is [int]) { return ([long]$Value).ToString('N0', $Culture) }
    ([double]$Value).ToString('#,0.##', $Culture)
}

function Format-SIGuardValues {
    <# PURE. "Label: 25.9 % (limit 10 %)" per value, joined by '; '. #>
    param([object[]]$Values = @(), [System.Globalization.CultureInfo]$Culture = [System.Globalization.CultureInfo]::InvariantCulture)
    $parts = foreach ($v in @($Values)) {
        if ($null -eq $v) { continue }
        $u = if ($v.Unit) { ' ' + $v.Unit } else { '' }
        $t = '{0}: {1}{2}' -f $v.Label, (Format-SIGuardNumber $v.Measured $Culture), $(if ($null -ne $v.Measured) { $u } else { '' })
        if ($null -ne $v.Limit) {
            # CR4 (#654): the stricter period after a release -- the halved limit and the configured one, said calmly
            if ($v.PSObject.Properties['Configured'] -and $null -ne $v.Configured -and $v.Configured -ne $v.Limit) {
                $t += (' (limit {0}{2} in the stricter period after a release, normally {1}{2})' -f (Format-SIGuardNumber $v.Limit $Culture), (Format-SIGuardNumber $v.Configured $Culture), $u)
            } else { $t += (' (limit {0}{1})' -f (Format-SIGuardNumber $v.Limit $Culture), $u) }
        }
        $t
    }
    (@($parts) -join '; ')
}

# =====================================================================================================================
#  THE THREE PARTS (what happened / why / consequence + what to do) -- PURE, the catalog's templates filled from the event.
#  The SAME rules as the web app (Guards\GuardText.cs): {held} {detail} {subject} {when} {latest} {v:<name>}; {x|text}
#  uses text when x is empty; a [ ... ] part is left out when a placeholder in it is empty.
# =====================================================================================================================
function Format-SIGuardText {
    <# PURE. One catalog template filled from -Fields (name -> text; an empty or missing name reads empty). #>
    param([AllowEmptyString()][string]$Template, [hashtable]$Fields = @{})
    if (-not $Template) { return '' }
    $placeholder = '\{(held|detail|subject|when|latest|v:[A-Za-z0-9]+)(?:\|([^{}]*))?\}'
    $fill = {
        param([string]$s, [ref]$missing)
        [regex]::Replace($s, $placeholder, {
            param($m)
            $v = [string]$Fields[$m.Groups[1].Value]
            if ("$v".Trim()) { return "$v".Trim() }
            if ($m.Groups[2].Success) { return $m.Groups[2].Value }
            $missing.Value = $true
            ''
        })
    }
    $out = [regex]::Replace($Template, '\s?\[([^\[\]]*)\]', {
        param($m)
        $miss = $false
        $inner = & $fill $m.Groups[1].Value ([ref]$miss)
        if ($miss) { return '' }
        $(if ($m.Value.StartsWith(' ')) { ' ' } else { '' }) + $inner
    })
    $none = $false
    $out = & $fill $out ([ref]$none)
    ConvertTo-SIGuardPlurals ([regex]::Replace($out, '\s{2,}', ' ')).Trim()
}

function ConvertTo-SIGuardPlurals {
    <# PURE. Operator 2026-10-09 ("no (s) anywhere"): "1 job(s)" -> "1 job", "2 job(s)" -> "2 jobs", "report(s)" -> "reports"
       -- the same rule as the web app (GuardText.Plurals), so the page and the mail say the same words. #>
    param([AllowEmptyString()][string]$Text)
    if (-not $Text -or $Text.IndexOf('(s)') -lt 0) { return $Text }
    $many = { param([string]$w)
        if ($w.Length -gt 1 -and $w.EndsWith('y') -and 'aeiou'.IndexOf([char]::ToLowerInvariant($w[$w.Length - 2])) -lt 0) { return $w.Substring(0, $w.Length - 1) + 'ies' }
        if ($w.EndsWith('s') -or $w.EndsWith('x') -or $w.EndsWith('ch') -or $w.EndsWith('sh')) { return $w + 'es' }
        $w + 's' }
    $t = [regex]::Replace($Text, "(?<n>\d[\d,. ']*)\s+(?<w>[A-Za-z-]+)\(s\)", {
        param($m)
        $digits = (-join ($m.Groups['n'].Value.ToCharArray() | Where-Object { [char]::IsDigit($_) })).TrimStart('0')
        $one = ($digits -eq '1') -and ($m.Groups['n'].Value.IndexOf('.') -lt 0)
        $m.Groups['n'].Value + ' ' + $(if ($one) { $m.Groups['w'].Value } else { & $many $m.Groups['w'].Value })
    })
    [regex]::Replace($t, '(?<w>[A-Za-z-]+)\(s\)', { param($m) & $many $m.Groups['w'].Value })
}

function Get-SIGuardTextFields {
    <# PURE. The placeholder values of one event: held, detail, subject, when, v:<name> (numbers in -Culture). -NoDetail
       leaves out what never travels to Invardia (detail, subject). #>
    param([Parameter(Mandatory)]$Event, [System.Globalization.CultureInfo]$Culture = [System.Globalization.CultureInfo]::InvariantCulture, [switch]$NoDetail)
    $f = @{}
    if ([long]$Event.HeldCount -gt 0) { $f['held'] = Format-SIGuardNumber ([long]$Event.HeldCount) $Culture }
    if (-not $NoDetail) { $f['detail'] = [string]$Event.Detail; $f['subject'] = [string]$Event.Subject }
    if ($Event.PSObject.Properties['TimeUtc'] -and $Event.TimeUtc) { $f['when'] = ('{0:yyyy-MM-dd HH:mm} UTC' -f ([datetime]$Event.TimeUtc)) }
    foreach ($v in @($Event.Values)) { if ($v -and $null -ne $v.Measured) { $f['v:' + [string]$v.Name] = Format-SIGuardNumber $v.Measured $Culture } }
    $f
}

function Get-SIGuardParts {
    <#
        PURE. The three parts a person reads -- What (what happened), Why (the cause of THIS event), Consequence (what the user
        sees or misses) -- plus Steps (what to do) and Kind (what a release means), filled from the event. A guard listed
        without them (an older catalog) falls back to its 'action' text as the one step.
    #>
    param([Parameter(Mandatory)]$Event, [System.Globalization.CultureInfo]$Culture = [System.Globalization.CultureInfo]::InvariantCulture, [switch]$NoDetail)
    $def = Get-SIGuardDefinition -Id ([string]$Event.GuardId)
    $get = { param([string]$n) if ($def.PSObject.Properties[$n]) { $def.$n } else { $null } }
    $fields = Get-SIGuardTextFields -Event $Event -Culture $Culture -NoDetail:$NoDetail
    $steps = @(@(& $get 'steps') | Where-Object { "$_".Trim() } | ForEach-Object { Format-SIGuardText -Template ([string]$_) -Fields $fields } | Where-Object { $_ })
    if (-not $steps.Count) { $steps = @([string]$def.action) }
    [pscustomobject]@{
        Kind        = $(if (& $get 'kind') { [string](& $get 'kind') } else { 'info' })
        What        = (Format-SIGuardText -Template ([string](& $get 'what')) -Fields $fields)
        Why         = $(if ($NoDetail) { '' } else { Format-SIGuardText -Template ([string](& $get 'why')) -Fields $fields })
        Consequence = (Format-SIGuardText -Template ([string](& $get 'consequence')) -Fields $fields)
        IfRelease   = (Format-SIGuardText -Template ([string](& $get 'ifRelease')) -Fields $fields)
        Steps       = $steps
    }
}

function Format-SIGuardSteps {
    <# PURE. Numbered steps as one line: "1. ... 2. ..." #>
    param([string[]]$Steps = @())
    $i = 0
    (@($Steps | Where-Object { "$_".Trim() } | ForEach-Object { $i++; '{0}. {1}' -f $i, "$_".Trim() }) -join ' ')
}

function Get-SIGuardWhere {
    <# PURE. WHERE a guard event happened, in plain words: the job (else the engine) and what it was about (the report,
       connector, asset or jobs the caller named). "" only when the event names neither. #>
    param([Parameter(Mandatory)]$Event)
    $job = if ("$($Event.Job)".Trim()) { "$($Event.Job)".Trim() } elseif ("$($Event.Engine)".Trim()) { "$($Event.Engine)".Trim() } else { '' }
    $sub = "$($Event.Subject)".Trim()
    $parts = @()
    if ($job) { $parts += ('job {0}' -f $job) }
    if ($sub -and $sub -ine $job) { $parts += $sub }
    ($parts -join ', ')
}

function Format-SIGuardSummary {
    <#
        PURE. ONE plain line a person can act on (#425: "the context is so poor that nobody knows"): WHAT happened, WHERE
        (job and report / connector / asset), the NUMBERS (measured against the limit, how many were held) and WHAT TO DO.
        The same words as the Guards page and the mail (the catalog's parts); used for the run log and the run-health record.
    #>
    param([Parameter(Mandatory)]$Event, [System.Globalization.CultureInfo]$Culture = [System.Globalization.CultureInfo]::InvariantCulture)
    $parts = $null; try { $parts = Get-SIGuardParts -Event $Event -Culture $Culture } catch { $parts = $null }
    $what = if ($parts -and $parts.What) { $parts.What } elseif ("$($Event.Detail)".Trim()) { "$($Event.Detail)".Trim() } else { 'SecurityInsight protected {0}.' -f $Event.Protected }
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add(($what.TrimEnd('.') + '.'))
    # the cause of THIS event when the catalog's sentence did not already carry it
    if ("$($Event.Detail)".Trim() -and $what.IndexOf("$($Event.Detail)".Trim(), [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        $out.Add(('Cause: {0}' -f ("$($Event.Detail)".Trim().TrimEnd('.') + '.')))
    }
    $where = Get-SIGuardWhere -Event $Event
    if ($where) { $out.Add(('Where: {0}.' -f $where)) }
    $nums = New-Object System.Collections.Generic.List[string]
    $vals = Format-SIGuardValues -Values @($Event.Values) -Culture $Culture
    if ($vals) { $nums.Add($vals) }
    if ([long]$Event.HeldCount -gt 0) { $nums.Add(('{0} held' -f (Format-SIGuardNumber ([long]$Event.HeldCount) $Culture))) }
    if ($nums.Count) { $out.Add(('Numbers: {0}.' -f ($nums -join '; '))) }
    # CR4 (#654): the stricter period after a release, in one calm clause
    if ($Event.PSObject.Properties['Strict'] -and $Event.Strict) {
        $sv = "$($Event.Strict.Version)".Trim(); $su = if (Get-Command -Name Format-SIGuardStrictUntil -ErrorAction SilentlyContinue) { Format-SIGuardStrictUntil $Event.Strict.Until } else { '' }
        $out.Add(('Stricter period{0}{1}: the limit is halved for 24 hours after a release that changed the engine, as planned.' -f $(if ($sv) { ' after release ' + $sv } else { ' after a release' }), $(if ($su) { ' until ' + $su } else { '' })))
    }
    $def = $null; try { $def = Get-SIGuardDefinition -Id ([string]$Event.GuardId) } catch { }
    $own = $def -and "$($Event.Action)".Trim() -and [string]$Event.Action -ne [string]$def.action
    $todo = if ($parts -and @($parts.Steps).Count -and -not $own) { Format-SIGuardSteps -Steps $parts.Steps } else { "$($Event.Action)".Trim() }
    if ($todo) { $out.Add(('What to do: {0}' -f $todo)) }
    ConvertTo-SIGuardPlurals (($out -join ' ') -replace '\.\.', '.')
}

function Get-SIGuardTelemetryKey {
    <# PURE. The de-duplication key Invardia's receiver uses per install: the guard id, plus a short hash of the subject when
       there is one (the hash names no connector / report; two subjects of one guard stay two tickets). #>
    param([Parameter(Mandatory)]$Event)
    if (-not $Event.Subject) { return [string]$Event.GuardId }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(([string]$Event.Subject).ToLowerInvariant())) } finally { $sha.Dispose() }
    ('{0}#{1}' -f $Event.GuardId, (-join ($h[0..5] | ForEach-Object { $_.ToString('x2') })))
}

# =====================================================================================================================
#  De-duplication -- PURE decision + three stores
# =====================================================================================================================
function ConvertTo-SIGuardUtc {
    <# PURE. A stored time as UTC, or $null (null, DBNull, empty, not a time). A text without a zone is read AS UTC. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [System.DBNull] -or "$Value".Trim() -eq '') { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }; return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse("$Value", [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    $null
}

function Get-SIGuardTenantTag {
    <# PURE over the settings. The tenant as the mail shows it, from what the run already knows (never a network call). #>
    param([System.Collections.IDictionary]$Globals)
    foreach ($n in 'TenantShort', 'TenantNameOrganization', 'SI_TenantDisplayName') {
        $v = "$(Get-SIGuardSetting -Name $n -Globals $Globals)".Trim(); if ($v) { return $v }
    }
    ''
}

function Get-SIGuardTripState {
    <#
        PURE. The trip's place in its episode. -Previous: @{ FirstSeenUtc; LastSeenUtc; TripCount; LastMailUtc } or $null.
        A trip more than -WindowHours after the last one starts a NEW episode (count 1, mail). Within the window the count
        goes up; a mail goes out only when the last mail is at least -WindowHours old ("still tripping, N times").
        -MailEnabled $false never mails and keeps LastMailUtc. Returns @{ FirstSeenUtc; LastSeenUtc; TripCount; LastMailUtc;
        Mail; StillTripping }.
    #>
    param([AllowNull()]$Previous, [Parameter(Mandatory)][datetime]$NowUtc, [int]$WindowHours = 24, [bool]$MailEnabled = $true)
    $now = $NowUtc.ToUniversalTime()
    $t = { param($v) ConvertTo-SIGuardUtc $v }
    $prevLast = $null; $prevFirst = $null; $prevMail = $null; $prevCount = 0
    if ($Previous) {
        $prevLast = & $t $Previous.LastSeenUtc; $prevFirst = & $t $Previous.FirstSeenUtc; $prevMail = & $t $Previous.LastMailUtc
        $n = 0; if ([int]::TryParse("$($Previous.TripCount)", [ref]$n)) { $prevCount = $n }
    }
    # a guard that CLEARED (a later complete run was back at the normal level, or it was accepted) starts a new episode
    $prevCleared = $null
    if ($Previous -and $Previous.PSObject.Properties['ClearedUtc']) { $prevCleared = & $t $Previous.ClearedUtc }
    elseif ($Previous -is [System.Collections.IDictionary] -and $Previous.Contains('ClearedUtc')) { $prevCleared = & $t $Previous['ClearedUtc'] }
    $newEpisode = ($null -eq $prevLast) -or (($now - $prevLast).TotalHours -gt $WindowHours) -or ($prevCleared -and $prevCleared -ge $prevLast)
    if ($newEpisode) {
        $mail = [bool]$MailEnabled
        return [pscustomobject]@{ FirstSeenUtc = $now; LastSeenUtc = $now; TripCount = 1; LastMailUtc = $(if ($mail) { $now } else { $null }); Mail = $mail; StillTripping = $false }
    }
    $count = $prevCount + 1
    $first = if ($prevFirst) { $prevFirst } else { $prevLast }
    $mail = [bool]$MailEnabled -and (($null -eq $prevMail) -or (($now - $prevMail).TotalHours -ge $WindowHours))
    [pscustomobject]@{ FirstSeenUtc = $first; LastSeenUtc = $now; TripCount = $count; LastMailUtc = $(if ($mail) { $now } else { $prevMail }); Mail = $mail; StillTripping = $true }
}

function New-SIGuardMemoryStateStore {
    <# A state store in memory (tests; a container without a disk or a database). #>
    $h = @{}
    [pscustomobject]@{
        Kind = 'memory'
        Get  = { param([string]$Key) if ($h.ContainsKey($Key)) { $h[$Key] } else { $null } }.GetNewClosure()
        # every field of the state is kept (the episode's four, and the version / clear fields of SI-GuardHeal.ps1)
        Set  = { param([string]$Key, [string]$GuardId, $State)
                 $o = [ordered]@{ FirstSeenUtc = $State.FirstSeenUtc; LastSeenUtc = $State.LastSeenUtc; TripCount = $State.TripCount; LastMailUtc = $State.LastMailUtc }
                 if ($State -is [System.Collections.IDictionary]) { foreach ($k in @($State.Keys)) { if (-not $o.Contains([string]$k)) { $o[[string]$k] = $State[$k] } } }
                 else { foreach ($p in @($State.PSObject.Properties)) { if (-not $o.Contains($p.Name) -and $p.Name -notin 'Mail', 'StillTripping') { $o[$p.Name] = $p.Value } } }
                 $h[$Key] = [pscustomobject]$o }.GetNewClosure()
    }
}

function Get-SIGuardStateDirectory {
    <# SI_GUARD_STATE_DIR, else %ProgramData%\SecurityInsight\guards on Windows, else ~/.securityinsight/guards. #>
    $d = [string]$env:SI_GUARD_STATE_DIR
    if ($d.Trim()) { return $d.Trim() }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        return [System.IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'SecurityInsight', 'guards')
    }
    $h = [Environment]::GetFolderPath('UserProfile'); if (-not $h) { $h = [System.IO.Path]::GetTempPath() }
    [System.IO.Path]::Combine($h, '.securityinsight', 'guards')
}

function New-SIGuardFileStateStore {
    <# A state store in one JSON file (<dir>\guard-state.json): guard key -> state. A file that cannot be read starts empty. #>
    param([Parameter(Mandatory)][string]$Directory)
    $file = [System.IO.Path]::Combine($Directory, 'guard-state.json')
    # a closure (GetNewClosure) cannot see script-scope functions: the one it needs is captured
    $toUtc = ${function:ConvertTo-SIGuardUtc}
    $read = {
        $m = @{}
        try {
            if ([System.IO.File]::Exists($file)) {
                $o = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($file))
                foreach ($p in @($o.PSObject.Properties)) { $m[$p.Name] = $p.Value }
            }
        } catch { }
        $m
    }.GetNewClosure()
    [pscustomobject]@{
        Kind = 'file'
        Path = $file
        Get  = { param([string]$Key) $m = & $read; if ($m.ContainsKey($Key)) { $m[$Key] } else { $null } }.GetNewClosure()
        Set  = {
            param([string]$Key, [string]$GuardId, $State)
            $m = & $read
            $iso = { param($v) $u = & $toUtc $v; if ($null -eq $u) { $null } else { $u.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture) } }
            $m[$Key] = [ordered]@{ GuardId = $GuardId; FirstSeenUtc = (& $iso $State.FirstSeenUtc); LastSeenUtc = (& $iso $State.LastSeenUtc); TripCount = [int]$State.TripCount; LastMailUtc = (& $iso $State.LastMailUtc) }
            # the version / clear fields (SI-GuardHeal.ps1), when the state carries them
            foreach ($xn in 'Version', 'PreviousVersion', 'FirstRunId', 'MarkerKind', 'ClearedRunId', 'ClearedVersion', 'ClearedHow') {
                $xv = if ($State -is [System.Collections.IDictionary]) { $State[$xn] } elseif ($State.PSObject.Properties[$xn]) { $State.$xn } else { $null }
                if ($null -ne $xv -and "$xv" -ne '') { $m[$Key][$xn] = [string]$xv }
            }
            $xc = if ($State -is [System.Collections.IDictionary]) { $State['ClearedUtc'] } elseif ($State.PSObject.Properties['ClearedUtc']) { $State.ClearedUtc } else { $null }
            if ($null -ne $xc -and "$xc" -ne '') { $m[$Key]['ClearedUtc'] = (& $iso $xc) }
            # keep the file small: episodes older than 30 days are dropped
            $keep = [ordered]@{}
            foreach ($k in @($m.Keys | Sort-Object)) {
                $ls = $m[$k].LastSeenUtc
                $age = 0; try { $age = ([datetime]::UtcNow - ([datetime]$ls).ToUniversalTime()).TotalDays } catch { $age = 0 }
                if ($age -le 30) { $keep[$k] = $m[$k] }
            }
            $null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($file))
            [System.IO.File]::WriteAllText($file, (ConvertTo-Json -InputObject $keep -Depth 4))
        }.GetNewClosure()
    }
}

function Get-SIGuardSql {
    <# The guard statements against the Pro database (sql\si-pro-settings.sql: cfg.GuardEvent, cfg.GuardState). #>
    param([Parameter(Mandatory)][ValidateSet('Exists', 'StateGet', 'StateSet', 'Insert', 'SuperAdmins', 'OutboxRead', 'OutboxMark')][string]$Name)
    switch ($Name) {
        'Exists' { "SELECT CASE WHEN OBJECT_ID(N'cfg.GuardEvent') IS NOT NULL AND OBJECT_ID(N'cfg.GuardState') IS NOT NULL THEN 1 ELSE 0 END AS HasGuards;" }
        # every column: the episode's four, and the version / clear columns where the database has them (SI-GuardHeal.ps1)
        'StateGet' { "SELECT TOP (1) * FROM cfg.GuardState WHERE GuardKey = @GuardKey;" }
        'StateSet' { @'
MERGE cfg.GuardState WITH (HOLDLOCK) AS t
USING (SELECT @GuardKey AS GuardKey) AS s ON t.GuardKey = s.GuardKey
WHEN MATCHED THEN UPDATE SET GuardId = @GuardId, FirstSeenUtc = @FirstSeenUtc, LastSeenUtc = @LastSeenUtc, TripCount = @TripCount, LastMailUtc = @LastMailUtc
WHEN NOT MATCHED THEN INSERT (GuardKey, GuardId, FirstSeenUtc, LastSeenUtc, TripCount, LastMailUtc)
     VALUES (@GuardKey, @GuardId, @FirstSeenUtc, @LastSeenUtc, @TripCount, @LastMailUtc);
'@ }
        'Insert' { @'
INSERT cfg.GuardEvent (GuardId, GuardKey, Area, Job, Engine, Source, Outcome, Severity, Protected, Subject, Detail, MeasuredText, ValuesJson,
                       HeldCount, ActionText, Link, RunId, TripCount, FirstSeenUtc, MailState, MailTo, TelemetryState)
VALUES (@GuardId, @GuardKey, @Area, @Job, @Engine, @Source, @Outcome, @Severity, @Protected, @Subject, @Detail, @MeasuredText, @ValuesJson,
        @HeldCount, @ActionText, @Link, @RunId, @TripCount, @FirstSeenUtc, @MailState, @MailTo, @TelemetryState);
SELECT CAST(SCOPE_IDENTITY() AS BIGINT) AS Id;
'@ }
        'SuperAdmins' { "IF OBJECT_ID(N'cfg.AccessAssignment') IS NULL SELECT CAST(NULL AS NVARCHAR(256)) AS Mail WHERE 1 = 0; ELSE SELECT DisplayName AS Mail FROM cfg.AccessAssignment WHERE Role = N'SuperAdmin' AND PrincipalType = N'User' AND DisplayName LIKE N'%_@_%';" }
        'OutboxRead' { "SELECT TOP (50) Id, TsUtc, GuardId, GuardKey, Area, Job, Engine, Source, Outcome, Severity, Subject, Detail, ValuesJson, HeldCount, ActionText, Link, RunId, MailState, TelemetryState FROM cfg.GuardEvent WHERE MailState = N'pending' OR TelemetryState = N'pending' ORDER BY Id;" }
        'OutboxMark' { "UPDATE cfg.GuardEvent SET MailState = @MailState, MailTo = COALESCE(@MailTo, MailTo), TelemetryState = @TelemetryState, TripCount = COALESCE(@TripCount, TripCount), FirstSeenUtc = COALESCE(@FirstSeenUtc, FirstSeenUtc) WHERE Id = @Id;" }
    }
}

function New-SIGuardSqlStateStore {
    <# A state store in the Pro database (cfg.GuardState), over the (sql, params, mode) seam every Pro engine has. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $inv = $Invoke
    $getSql = Get-SIGuardSql 'StateGet'; $setSql = Get-SIGuardSql 'StateSet'   # captured: a closure cannot see script-scope functions
    # the version / clear fields of SI-GuardHeal.ps1, written only where the database has their columns
    $extraSql = if (Get-Command -Name Get-SIGuardHealSql -ErrorAction SilentlyContinue) { Get-SIGuardHealSql 'StateExtra' } else { '' }
    [pscustomobject]@{
        Kind = 'sql'
        Get  = { param([string]$Key) $rows = @(& $inv $getSql @{ GuardKey = $Key } 'reader'); if ($rows.Count -and $rows[0]) { $rows[0] } else { $null } }.GetNewClosure()
        Set  = { param([string]$Key, [string]$GuardId, $State)
                 $null = & $inv $setSql @{ GuardKey = $Key; GuardId = $GuardId; FirstSeenUtc = $State.FirstSeenUtc; LastSeenUtc = $State.LastSeenUtc; TripCount = [int]$State.TripCount; LastMailUtc = $State.LastMailUtc } 'nonquery'
                 if ($extraSql) {
                     $x = @{ GuardKey = $Key }
                     foreach ($n in 'Version', 'PreviousVersion', 'FirstRunId', 'MarkerKind', 'ClearedUtc', 'ClearedRunId', 'ClearedVersion', 'ClearedHow') {
                         $v = if ($State -is [System.Collections.IDictionary]) { $State[$n] } elseif ($State.PSObject.Properties[$n]) { $State.$n } else { $null }
                         if ($v -is [string]) { $v = $v.Trim(); if ($v.Length -gt 64) { $v = $v.Substring(0, 64) }; if (-not $v) { $v = $null } }
                         $x[$n] = $v
                     }
                     $null = & $inv $extraSql $x 'nonquery'
                 } }.GetNewClosure()
    }
}

# =====================================================================================================================
#  The mail -- PURE
# =====================================================================================================================
# owner 2026-10-11 ("dont stop my business with unnecessary guards"; a warn-only check mailed "action needed"): a check that
# only WARNS (it held, stopped or refused nothing) sends no mail -- it is recorded, shown on the Guards page and in the run
# report. A mail means something was stopped or held. The one exception: the licence grace period, which needs a renewal.
# #937 (owner 2026-10-28, "Stop the mail"): a check whose catalog entry says "mail": "never" sends no mail whatever its
# outcome -- collection.source.asset-drop accepts a real drop by itself on the next complete collection, so its mail asked
# nothing of anyone. Its event, the Guards page, the run report and the report to Invardia are unchanged.
$script:SIGuardWarningMails = @('licence.state.grace')
function Test-SIGuardNeverMails {
    <# PURE over the catalog. Does the guard's catalog entry say "mail": "never"? Unknown id / unreadable catalog: $false. #>
    param([AllowNull()][AllowEmptyString()][string]$GuardId)
    if (-not "$GuardId".Trim()) { return $false }
    try {
        $g = @((Get-SIGuardCatalog).guards | Where-Object { [string]$_.id -eq $GuardId }) | Select-Object -First 1
        return [bool]($g -and $g.PSObject.Properties['mail'] -and ([string]$g.mail -ieq 'never'))
    } catch { return $false }
}
function Test-SIGuardOutcomeMails {
    <# PURE. Whether this event's outcome sends a mail at all: every outcome but 'warning' (and the listed exceptions);
       never for a guard the catalog marks "mail": "never". #>
    param([Parameter(Mandatory)]$Event)
    if (Test-SIGuardNeverMails -GuardId ([string]$Event.GuardId)) { return $false }
    ([string]$Event.Outcome -ine 'warning') -or ($script:SIGuardWarningMails -contains [string]$Event.GuardId)
}

function ConvertTo-SIGuardTextHtml {
    <#
        PURE. One guard text as HTML a person can read: a run of 4 or more items joined by '; ' (a list of columns, reports,
        jobs) becomes an intro line and a bullet list of at most 10 items ("and N more"), never one run-on paragraph.
    #>
    param([AllowEmptyString()][string]$Text, [int]$MaxItems = 10)
    $enc = { param($s) if (Get-Command -Name ConvertTo-SIMailInlineHtml -ErrorAction SilentlyContinue) { ConvertTo-SIMailInlineHtml $s } else { [System.Net.WebUtility]::HtmlEncode([string]$s) } }
    $t = [string]$Text
    $segs = @($t -split ';\s+')
    if ($segs.Count -lt 4) { return (& $enc $t) }
    # the intro is what stands before the list: the text up to the last ': ' of the first segment
    $first = $segs[0]; $intro = ''
    $cut = $first.LastIndexOf(': ')
    if ($cut -gt 0) { $intro = $first.Substring(0, $cut + 1); $segs[0] = $first.Substring($cut + 2) }
    $items = @($segs | ForEach-Object { $_.Trim().TrimEnd('.') } | Where-Object { $_ })
    $shown = @($items | Select-Object -First $MaxItems)
    $li = @($shown | ForEach-Object { '<li style="margin:0 0 2px 0;">' + (& $enc $_) + '</li>' }) -join ''
    if ($items.Count -gt $shown.Count) { $li += '<li style="margin:0 0 2px 0;color:#59636e;">' + (& $enc ('and {0} more' -f ($items.Count - $shown.Count))) + '</li>' }
    (& $enc $intro) + '<ul style="margin:4px 0 0 18px;padding:0;">' + $li + '</ul>'
}

function Get-SIGuardCulture {
    <# The install's number format for mails: SIWeb_NumberFormatDefault when it names a culture, else invariant. #>
    param([System.Collections.IDictionary]$Globals)
    $c = "$(Get-SIGuardSetting -Name 'SIWeb_NumberFormatDefault' -Globals $Globals)".Trim()
    if ($c -and $c -ne 'auto') { try { return [System.Globalization.CultureInfo]::GetCultureInfo($c) } catch { } }
    [System.Globalization.CultureInfo]::InvariantCulture
}

function Get-SIGuardMailSeverity {
    <#
        PURE. The guard mail's severity word (MAIL-3, #653): 'Failed' for a guard that reports a failed step or update
        (an id ending in failed / interrupted), 'Warning' for an outcome 'warning' (recorded and shown, nothing held),
        'Action needed' for every trip that stopped, refused, held or skipped something -- a person decides what happens next.
    #>
    param([Parameter(Mandatory)]$Event)
    if ([string]$Event.GuardId -match '(?i)[.-](failed|interrupted)$') { return 'Failed' }
    if ([string]$Event.Outcome -ieq 'warning') { return 'Warning' }
    'Action needed'
}

function ConvertTo-SIGuardMail {
    <#
        PURE. The guard mail: subject "<severity word>: <what was protected>" (+ "still tripping, N times"),
        and a body with what happened, the numbers against the limit, what was held (nothing lost), what to do and the link.
        Returns @{ Subject; Html; Text }.
    #>
    param([Parameter(Mandatory)]$Event, [Parameter(Mandatory)]$Trip, [string]$TenantTag, [System.Globalization.CultureInfo]$Culture = [System.Globalization.CultureInfo]::InvariantCulture)
    $e = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    # MAIL-2 / #573: free text keeps its line breaks (encoded, a <br> per break) -- never collapsed into one run-on line
    $tx = { param($s) if (Get-Command -Name ConvertTo-SIMailInlineHtml -ErrorAction SilentlyContinue) { ConvertTo-SIMailInlineHtml $s } else { [System.Net.WebUtility]::HtmlEncode([string]$s) } }
    $what = ([string]$Event.Protected)
    # MAIL-3 (#653): '<severity word>: <what was protected>' -- the transport adds '[<environment>]' and '[SecurityInsight]'
    $subject = '{0}: {1}' -f (Get-SIGuardMailSeverity -Event $Event), $(if ($what) { $what.Substring(0, 1).ToUpperInvariant() + $what.Substring(1) } else { 'Your data' })
    if ($Trip.StillTripping) { $subject += (' (still tripping, {0} times since {1:yyyy-MM-dd HH:mm} UTC)' -f $Trip.TripCount, ([datetime]$Trip.FirstSeenUtc)) }
    if ($TenantTag) { $subject += (' | {0}' -f $TenantTag) }
    $verb = switch ([string]$Event.Outcome) {
        'halted'  { 'SecurityInsight stopped a step to protect {0}.' }
        'refused' { 'SecurityInsight refused a step to protect {0}.' }
        'held'    { 'SecurityInsight held back part of a step to protect {0}.' }
        'skipped' { 'SecurityInsight skipped a step to protect {0}.' }
        default   { 'SecurityInsight needs your attention to protect {0}.' }
    }
    $lead = $verb -f $what
    # #728 (no tables in mails): the numbers are "Topic: text" lines, one per measured value -- the label in bold, the
    # value, and the limit in brackets only when the value has one: "Rows: 1,060,000 (limit 2,000,000)"
    $rows = foreach ($v in @($Event.Values)) {
        $u = if ($v.Unit) { ' ' + $v.Unit } else { '' }
        $val = (Format-SIGuardNumber $v.Measured $Culture) + $(if ($null -ne $v.Measured) { $u } else { '' })
        $lim = if ($null -ne $v.Limit) { 'limit ' + (Format-SIGuardNumber $v.Limit $Culture) + $u + $(if ($v.PSObject.Properties['Configured'] -and $null -ne $v.Configured -and $v.Configured -ne $v.Limit) { ', normally {0}{1}' -f (Format-SIGuardNumber $v.Configured $Culture), $u } else { '' }) } else { '' }
        '<p style="margin:0 0 8px 0;line-height:1.5;"><strong>{0}:</strong> {1}{2}</p>' -f (& $e $v.Label), (& $e $val), $(if ($lim) { ' (' + (& $e $lim) + ')' } else { '' })
    }
    # CR4 (#654): a trip in the stricter period after a release says so calmly -- expected, temporary, with the numbers
    $strictText = if ($Event.PSObject.Properties['Strict'] -and $Event.Strict -and (Get-Command -Name Format-SIGuardStrictSentence -ErrorAction SilentlyContinue)) { Format-SIGuardStrictSentence -Strict $Event.Strict } else { '' }
    $table = if (@($rows).Count) { '<div data-guard-values style="margin:0 0 12px 0;font-size:14px;">' + (@($rows) -join '') + '</div>' } else { '' }
    $held = if ($Event.HeldCount -gt 0) { ('{0} item(s) were held back. Nothing was lost: they stay as they were and are processed again on the next good run.' -f (Format-SIGuardNumber ([long]$Event.HeldCount) $Culture)) }
            else { 'Nothing was changed by this step, so nothing was lost.' }
    $tripLine = if ($Trip.StillTripping) { ('This has happened {0} times since {1:yyyy-MM-dd HH:mm} UTC; you get at most one mail a day about it.' -f $Trip.TripCount, ([datetime]$Trip.FirstSeenUtc)) } else { '' }
    $font = 'font-family:Segoe UI,Arial,sans-serif;'
    $p = { param($s) '<p style="margin:0 0 12px 0;">' + $s + '</p>' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<html><body style="margin:0;padding:0;background:#f4f6f8;"><div style="' + $font + 'max-width:720px;margin:0 auto;background:#ffffff;border:1px solid #d0d7de;">')
    [void]$sb.Append('<div style="background:' + $(if ($Event.Severity -eq 'critical') { '#b42318' } else { '#9a6700' }) + ';color:#ffffff;padding:14px 22px;font-size:18px;"><strong>SecurityInsight</strong> &middot; action needed</div>')
    [void]$sb.Append('<div style="padding:18px 22px;font-size:14px;color:#1f2328;">')
    # #728: a summary block first -- what happened, what was held, whether the reader must act (not marked
    # data-mail-summary: the guard mail carries no portal link line, as before)
    $sumLines = @('<strong>' + (& $e $lead) + '</strong>')
    if ($Event.HeldCount -gt 0) { $sumLines += (& $e ('{0} item(s) held back; nothing was lost.' -f (Format-SIGuardNumber ([long]$Event.HeldCount) $Culture))) }
    $sumLines += ('<strong>' + (& $e (Get-SIGuardMailSeverity -Event $Event)) + ':</strong> see What to do below.')
    [void]$sb.Append('<div data-guard-summary style="background:#EEF3FE;border-left:4px solid #1B4FE4;border-radius:4px;padding:12px 16px;margin:0 0 18px 0;font-size:15px;line-height:1.55;color:#0B1633;"><p style="margin:0;">' + ($sumLines -join '<br>') + '</p></div>')
    # owner 2026-10-11 ("nobody understand what to do and the consequence"): three blocks in this order -- what happened (and
    # its cause), what it means for you, what to do -- each a heading over its text; a list is a bullet list; a part that
    # does not apply (nothing held, no release possible) is left out
    $h = { param($s) '<p style="margin:16px 0 4px 0;font-size:15px;"><strong>' + $s + '</strong></p>' }
    $parts = $null; try { $parts = Get-SIGuardParts -Event $Event -Culture $Culture } catch { $parts = $null }
    $releasable = $parts -and $parts.IfRelease -and ([string]$parts.IfRelease -notmatch '^This check cannot be released')
    [void]$sb.Append((& $h 'What happened'))
    if ($parts -and $parts.What) {
        [void]$sb.Append((& $p (& $tx $parts.What)))
        if ($parts.Why) { [void]$sb.Append('<div style="margin:0 0 12px 0;">' + (ConvertTo-SIGuardTextHtml -Text $parts.Why) + '</div>') }
    } elseif ($Event.Detail) { [void]$sb.Append('<div style="margin:0 0 12px 0;">' + (ConvertTo-SIGuardTextHtml -Text $Event.Detail) + '</div>') }
    if ($table) { [void]$sb.Append($table) }
    if ($strictText) { [void]$sb.Append((& $p (& $tx $strictText))) }
    # owner 2026-10-17: which release it tripped on, so "our update" is told from "your source changed"
    $attrText = if ($Event.PSObject.Properties['Attribution'] -and [string]$Event.Attribution) { [string]$Event.Attribution } else { '' }
    if ($attrText) { [void]$sb.Append((& $p (& $tx $attrText))) }
    [void]$sb.Append((& $h 'What it means for you'))
    if ($parts -and $parts.Consequence) { [void]$sb.Append((& $p (& $tx $parts.Consequence))) }
    if ($Event.HeldCount -gt 0) { [void]$sb.Append((& $p (& $tx $held))) }
    elseif (-not ($parts -and $parts.Consequence)) { [void]$sb.Append((& $p (& $tx $held))) }
    [void]$sb.Append((& $h 'What to do'))
    # an explicit -Action (the caller's own words) wins over the catalog's steps
    $def = $null; try { $def = Get-SIGuardDefinition -Id ([string]$Event.GuardId) } catch { }
    $own = $def -and [string]$Event.Action -and [string]$Event.Action -ne [string]$def.action
    if ($parts -and @($parts.Steps).Count -and -not $own) {
        $li = @($parts.Steps | ForEach-Object { '<li style="margin:0 0 4px 0;">' + (& $e $_) + '</li>' }) -join ''
        [void]$sb.Append('<ol style="margin:0 0 12px 18px;padding:0;">' + $li + '</ol>')
    } else { [void]$sb.Append((& $p (& $tx $Event.Action))) }
    if ($releasable) { [void]$sb.Append((& $p ('<strong>If you release it:</strong> ' + (& $tx $parts.IfRelease)))) }
    if ($tripLine) { [void]$sb.Append((& $p (& $tx $tripLine))) }
    if ($Event.Link) { [void]$sb.Append((& $p ('<a href="' + (& $e $Event.Link) + '" style="color:#0969da;">Open it in SecurityInsight</a>'))) }
    # #425: where = the job (else the engine) and what it was about -- in the footer with the time and the reference
    $whereText = Get-SIGuardWhere -Event $Event
    [void]$sb.Append('<p style="margin:20px 0 0 0;padding-top:10px;border-top:1px solid #d0d7de;font-size:12px;color:#59636e;">' + (& $e ('{0:yyyy-MM-dd HH:mm} UTC{1}{2} - reference {3}' -f ([datetime]$Event.TimeUtc), $(if ($whereText) { ' - ' + $whereText } else { '' }), $(if ($TenantTag) { ' - ' + $TenantTag } else { '' }), $Event.GuardId)) +
        '. To turn this check or its mail off, or to tune its limits: Settings &gt; Guards (safety checks).</p>')
    [void]$sb.Append('</div></div></body></html>')
    $todo = if ($parts -and @($parts.Steps).Count -and -not $own) { 'What to do: ' + (Format-SIGuardSteps -Steps $parts.Steps) } else { $Event.Action }
    $three = if ($parts -and $parts.What) { @(('What happened: ' + $parts.What), $(if ($parts.Why) { 'Cause: ' + $parts.Why }), $(if ($parts.Consequence) { 'What it means for you: ' + $parts.Consequence })) } else { @([string]$Event.Detail) }
    $heldText = if ($Event.HeldCount -gt 0 -or -not ($parts -and $parts.Consequence)) { $held } else { '' }
    $releaseText = if ($releasable) { 'If you release it: ' + $parts.IfRelease } else { '' }
    $text = @(@($lead) + $three + @((Format-SIGuardValues -Values $Event.Values -Culture $Culture), $strictText, $attrText, $heldText, $todo, $releaseText, $tripLine, [string]$Event.Link)) | Where-Object { "$_".Trim() }
    [pscustomobject]@{ Subject = $subject; Html = $sb.ToString(); Text = (@($text) -join "`r`n`r`n") }   # MAIL-2: CRLF, a blank line between paragraphs
}

# =====================================================================================================================
#  Telemetry -- PURE builder of the GUARD-1 record (Invardia's receiver: Schema 2, Kind 'guard')
# =====================================================================================================================
$script:SIGuardWire = @{
    GuardIdPattern  = '^[a-z0-9][a-z0-9.-]{0,99}$'
    KeyPattern      = '^[a-z][A-Za-z0-9]{0,30}$'
    Outcomes        = @('halted', 'refused', 'held', 'skipped', 'warning')   # 'warning': GUARD-1.3 (recorded and shown, no ticket, no release-health alert)
    Severities      = @('critical', 'warning')
    MaxValues       = 10
    ActionTextMax   = 500
    # every field the record may carry; anything else would land in the receiver's Detail
    Fields          = @('Schema', 'Kind', 'Product', 'Version', 'Ring', 'Edition', 'Hosting', 'RuntimeIdentity', 'LicenceState', 'Job', 'GuardId', 'GuardOutcome',
                        'Severity', 'Area', 'Measured', 'Thresholds', 'HeldCount', 'TripCount', 'FirstSeenUtc', 'InstallId', 'ClaimedTenantId', 'Host',
                        'ActionText', 'Link', 'LastSeenUtc',
                        # CR4 (#654, Invardia 1.0.445): a trip in the stricter period after a release; the identified guard mode
                        'Strict', 'ConfiguredLimit', 'EffectiveLimit', 'GuardMode',
                        # owner 2026-10-17 (Invardia DESIGN "A guard report that says cleared"): GuardOutcome 'cleared'
                        'ClearedBy', 'ClearedUtc')
    IdentifiedOnly  = @('ClaimedTenantId', 'Host', 'ActionText', 'Link')
}

function Resolve-SIGuardHealOutcomesSwitch {
    <#
        PURE. Do the guard-heal reports go to Invardia from this install? (Invardia 2026-10-17: its guard receiver takes only
        halted / refused / held / skipped / warning so far.) Switch SI_Uplink_SendGuardHealOutcomes (job variable
        SI_UPLINK_SENDGUARDHEALOUTCOMES), read like the other SI_Uplink_Send* switches: -Value (the setting) wins, then
        -EnvValue; on / true / yes = on; off / false / no = off; a ring list ("0", "0,1", "ring 1") = on for those rings;
        anything else = auto = the rings in -ConfirmedRings -- every ring since Invardia 1.0.512 (2026-10-17: its receiver takes
        'cleared' passed / released, 'taken', SiVersion / PreviousVersion / Attribution, "held (accepted range)"), so ON by default.
        OFF: no 'cleared' report is sent (Send-SIGuardClear, the outbox's clears: TelemetryState 'off', so a later switch-on
        never sends them in a burst) and a trip report keeps its earlier shape (no "held (accepted range)" words). Everything
        local -- the heal, the Guards page, run health, mail, audit -- is the same either way. Returns @{ On; Setting; Reason }.
        REMOVE-ME: once Invardia's receiver takes 'cleared' (ClearedBy / ClearedUtc), confirm the rings, then drop the switch.
    #>
    param([AllowNull()]$Value = $global:SI_Uplink_SendGuardHealOutcomes, [AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_UPLINK_SENDGUARDHEALOUTCOMES,
          [AllowNull()]$Ring, [int[]]$ConfirmedRings = @(0, 1, 2, 3), [System.Collections.IDictionary]$Globals)
    if ($Globals -and -not $PSBoundParameters.ContainsKey('Value')) { $Value = Get-SIGuardSetting -Name 'SI_Uplink_SendGuardHealOutcomes' -Globals $Globals }
    $name = 'SI_Uplink_SendGuardHealOutcomes'
    if (Get-Command -Name Resolve-SIUplinkFieldSwitch -ErrorAction SilentlyContinue) {
        return (Resolve-SIUplinkFieldSwitch -Name $name -Value $Value -EnvValue $EnvValue -Ring $Ring -ConfirmedRings $ConfirmedRings)
    }
    # the same rules as Resolve-SIUplinkFieldSwitch (SI-HeartbeatJob.ps1), for a process that has not loaded it
    $rn = -1
    if ($null -ne $Ring -and "$Ring".Trim() -ne '') { if (-not [int]::TryParse("$Ring", [ref]$rn)) { $rn = -1 } }
    $set = ''
    foreach ($v in @($Value, $EnvValue)) {
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { $set = $(if ($v) { 'on' } else { 'off' }); break }
        $s = ([string]$v).Trim().Trim('$').ToLowerInvariant()
        if (-not $s) { continue }
        $set = $s; break
    }
    if ($set -in @('on', 'true', 'yes', 'enabled')) { return [pscustomobject]@{ On = $true; Setting = 'on'; Reason = "$name is on" } }
    if ($set -in @('off', 'false', 'no', 'disabled')) { return [pscustomobject]@{ On = $false; Setting = 'off'; Reason = "$name is off" } }
    if ($set -match '^(ring\s*)?[0-3](\s*[,;]\s*(ring\s*)?[0-3])*$') {
        $rings = @([regex]::Matches($set, '[0-3]') | ForEach-Object { [int]$_.Value })
        return [pscustomobject]@{ On = ($rn -ge 0 -and $rings -contains $rn); Setting = $set; Reason = "$name is on for ring(s) $($rings -join ', ')" }
    }
    [pscustomobject]@{ On = ($rn -ge 0 -and @($ConfirmedRings) -contains $rn); Setting = 'auto'; Reason = "$name is auto (confirmed rings: $(if (@($ConfirmedRings).Count) { @($ConfirmedRings) -join ', ' } else { 'none' }))" }
}

function ConvertTo-SIGuardWireOutcome {
    <# PURE. The receiver's GuardOutcome (halted | refused | held | skipped | warning -- GUARD-1.3). A trip that HELD
       NOTHING -- SI's own 'warning' (a licence in grace, a report that lost findings), or a 'held' with no held count --
       travels as 'warning': recorded and shown, no ticket, no release-health alert. 'held' is kept for a trip that
       really held something (HeldCount > 0). #>
    param([Parameter(Mandatory)][string]$Outcome, [long]$HeldCount = 0)
    if ($Outcome -eq 'held' -and $HeldCount -le 0) { return 'warning' }
    if ($script:SIGuardWire.Outcomes -contains $Outcome) { return $Outcome }
    throw ("'{0}' is not a guard outcome" -f $Outcome)
}

function New-SIGuardTelemetryRecord {
    <#
        PURE. The GUARD-1 record (Invardia's receiver opens / updates ONE support ticket per environment + guard for Pro; for
        Community it counts installs per guard and version). -Context: a Get-SITelemetryContext result.
          always      Schema 2, Kind guard, Product, Version, Ring, Edition, Hosting, RuntimeIdentity, LicenceState, Job, GuardId,
                      GuardOutcome, Severity, Area, Measured / Thresholds (camelCase keys, numbers only, at most 10 each),
                      HeldCount, TripCount, FirstSeenUtc, LastSeenUtc
          anonymous   + InstallId. NO tenant, host, subject, detail, action text or link.
          identified  + ClaimedTenantId, Host, ActionText (at most 500 characters, redacted), Link (https only).
        A value outside the receiver's lists is refused here (it would reject the whole report).
    #>
    param([Parameter(Mandatory)]$Event, [Parameter(Mandatory)]$Trip, [Parameter(Mandatory)]$Context, [string]$HostName, $Now)
    $w = $script:SIGuardWire
    $anon = ([string]$Context.Mode -eq 'anonymous')
    $iso = { param($v) $u = ConvertTo-SIGuardUtc $v; if ($null -eq $u) { $null } else { $u.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) } }
    $gid = [string]$Event.GuardId
    if ($gid -notmatch $w.GuardIdPattern) { throw ("guard id '{0}' does not fit the receiver ({1})" -f $gid, $w.GuardIdPattern) }
    if ($w.Severities -notcontains [string]$Event.Severity) { throw ("severity '{0}' is not critical / warning" -f $Event.Severity) }
    $measured = [ordered]@{}; $limits = [ordered]@{}
    foreach ($v in @($Event.Values)) {
        if ($v.Name -notmatch $w.KeyPattern) { continue }
        if ($null -ne $v.Measured -and $measured.Count -lt $w.MaxValues) { $measured[$v.Name] = $v.Measured }
        if ($null -ne $v.Limit -and $limits.Count -lt $w.MaxValues) { $limits[$v.Name] = $v.Limit }
    }
    $r = [ordered]@{ Schema = 2; Kind = 'guard'; Product = $script:SIGuard.Product }
    $ver = "$($Context.Version)".Trim(); if ($ver) { $r.Version = $ver }
    if ($Context.PSObject.Properties['Ring'] -and $null -ne $Context.Ring -and "$($Context.Ring)" -ne '') { $r.Ring = [int]$Context.Ring }
    foreach ($k in 'Edition', 'Hosting', 'RuntimeIdentity', 'LicenceState') { $val = "$($Context.$k)".Trim(); if ($val) { $r[$k] = $val } }
    if ([string]$Event.Job) { $r.Job = [string]$Event.Job }
    $r.GuardId      = $gid
    $r.GuardOutcome = ConvertTo-SIGuardWireOutcome -Outcome ([string]$Event.Outcome) -HeldCount ([long]$Event.HeldCount)
    $r.Severity     = [string]$Event.Severity
    $r.Area         = [string]$Event.Area
    $r.Measured     = [pscustomobject]$measured
    $r.Thresholds   = [pscustomobject]$limits
    $r.HeldCount    = [long]$Event.HeldCount
    $r.TripCount    = [int]$Trip.TripCount
    $r.FirstSeenUtc = & $iso $Trip.FirstSeenUtc
    if ($anon) {
        $r.InstallId = [string]$Context.InstallId
    } else {
        $r.ClaimedTenantId = [string]$Context.TenantId
        $r.Host = $(if ($HostName) { $HostName } else { [string][System.Environment]::MachineName })
        $red = if (Get-Command -Name ConvertTo-AitUplinkRedacted -ErrorAction SilentlyContinue) { { param($s) ConvertTo-AitUplinkRedacted -Text $s } } else { { param($s) $s } }
        # the three parts WITHOUT the event's detail or subject (what happened, the consequence, what to do) -- the same
        # words as the mail and the Guards page; the caller's own -Action when it gave one
        $atText = [string]$Event.Action
        try {
            $def = Get-SIGuardDefinition -Id $gid
            if ($atText -eq [string]$def.action) {
                $pp = Get-SIGuardParts -Event $Event -NoDetail
                if ($pp.What) { $atText = (@($pp.What, $pp.Consequence, $(if (@($pp.Steps).Count) { 'What to do: ' + (Format-SIGuardSteps -Steps $pp.Steps) })) | Where-Object { "$_".Trim() }) -join ' ' }
            }
        } catch { }
        $at = (& $red $atText).Trim()
        if ($at.Length -gt $w.ActionTextMax) { $at = $at.Substring(0, $w.ActionTextMax - 3) + '...' }
        if ($at) { $r.ActionText = $at }
        if ([string]$Event.Link -match '^https://') { $r.Link = [string]$Event.Link }
    }
    # CR4 (#654): a trip in the stricter period after a release -- Strict, the customer's configured limit and the halved
    # one (whole numbers only: Invardia keeps nothing else); the guard mode on an identified report only
    $sv = @(@($Event.Values) | Where-Object { $_ -and $_.PSObject.Properties['Configured'] -and $null -ne $_.Configured -and $null -ne $_.Limit }) | Select-Object -First 1
    if ($sv -or ($Event.PSObject.Properties['Strict'] -and $Event.Strict)) {
        $r.Strict = $true
        $cl = if ($sv) { [Math]::Abs([double]$sv.Configured) } elseif ($null -ne $Event.Strict.Configured) { [Math]::Abs([double]$Event.Strict.Configured) } else { $null }
        $el = if ($sv) { [Math]::Abs([double]$sv.Limit) } elseif ($null -ne $Event.Strict.Effective) { [Math]::Abs([double]$Event.Strict.Effective) } else { $null }
        if ($null -ne $cl -and $cl -eq [Math]::Floor($cl) -and $cl -lt 2147483647) { $r.ConfiguredLimit = [long]$cl }
        if ($null -ne $el -and $el -eq [Math]::Floor($el) -and $el -lt 2147483647) { $r.EffectiveLimit = [long]$el }
        if (-not $anon -and $Event.PSObject.Properties['Strict'] -and $Event.Strict -and (Get-Command -Name ConvertTo-SIGuardModeWire -ErrorAction SilentlyContinue)) {
            $gm = ConvertTo-SIGuardModeWire -Mode ([pscustomobject]@{ Mode = 'strict'; Recorded = $true; Until = $Event.Strict.Until; Version = $Event.Strict.Version; EndedEarlyAt = $null; EndedByRole = '' })
            if ($gm) { $r.GuardMode = [pscustomobject]$gm }
        }
    }
    $r.LastSeenUtc = & $iso $(if ($Now) { $Now } else { $Trip.LastSeenUtc })
    [pscustomobject]$r
}

function ConvertTo-SIGuardWire {
    <# PURE. The record as it is posted: the GUARD-1 record itself (Send-AitUplink posts any record). $null when an
       anonymous record has no install id (the receiver needs one) -- then nothing is sent. Returns @{ Shape; Record }. #>
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)]$Context)
    if ([string]$Context.Mode -eq 'anonymous' -and [string]$Record.InstallId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        return [pscustomobject]@{ Shape = 'none'; Record = $null }
    }
    [pscustomobject]@{ Shape = 'guard'; Record = $Record }
}

# =====================================================================================================================
#  THE ONE CALL
# =====================================================================================================================
function Get-SIGuardCallerEngine {
    <# The engine folder of the script that called (engine\<name>\...), for a guard that is not told its engine. #>
    try {
        foreach ($f in @(Get-PSCallStack)) {
            $s = [string]$f.ScriptName
            if ($s -match '[\\/]engine[\\/]([a-z0-9-]+)[\\/]' -and $Matches[1] -ne '_shared') { return $Matches[1] }
        }
    } catch { }
    ''
}

function Send-SIGuardEvent {
    <#
        THE call every guard makes. NEVER throws. Returns @{ Status (recorded | duplicate | error); Event; Trip; Mail;
        Telemetry; Stored; RunHealth; Audit; Reason }.
        What: -GuardId, -Outcome, -Engine / -Job, -Subject, -Detail, -Values, -HeldCount, -Action, -Link, -RunId, -Source.
        Seams (tests; all optional):
          -Invoke             the Pro database (sql, params, mode) -- dedup state, the Guards view row, the audit event,
                              the SuperAdmins' mail. Default: $global:SI_GuardInvoke, else none.
          -StateStore         a dedup store (New-SIGuardMemoryStateStore / -FileStateStore / -SqlStateStore).
          -MailTransport      { param($To, $Subject, $Html, $Priority) } -> $true; default: the Risk Analysis transports.
          -TelemetryTransport { param($Record, $Endpoint, $AccessCode, $TimeoutSec) } -> @{ Status }; default Send-AitUplink.
          -TelemetryContext   a Get-SITelemetryContext result.
          -RunHealth          { param($RunContext, $ExitReason, $Message, $HeldCount) }; default Send-SIRunHealthRow.
          -Globals            settings as a hashtable instead of the live globals.
          -Now                the clock.
        -NoMail / -NoTelemetry: this call only (the settings decide otherwise).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GuardId,
        [Parameter(Mandatory)][string]$Outcome,
        [string]$Engine, [string]$Job, [string]$Subject, [string]$Detail,
        [object[]]$Values = @(), [long]$HeldCount = 0, [string]$Action, [string]$Link, [string]$RunId, [string]$Source = 'job',
        [scriptblock]$Invoke, $StateStore, [scriptblock]$MailTransport, [scriptblock]$TelemetryTransport, $TelemetryContext,
        [scriptblock]$RunHealth, [System.Collections.IDictionary]$Globals, $Now, [switch]$NoMail, [switch]$NoTelemetry,
        [scriptblock]$Log,
        # #414: the distinct causes this event is about (Get-SIGuardCauseKey). When EVERY one was reported before, the
        # event is not made again (Status 'already-reported': no row, no mail, no report) -- a cause fires ONCE, however
        # many runs still see it (ring 1, 2026-10-06: 14,624 rows of one broken run re-fired on every data sync).
        [string[]]$CauseKeys,
        # the SecurityInsight version this run is on (default: Get-SIGuardRunVersion) -- tests hand one in
        [string]$Version
    )
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) if ($level -eq 'WARN') { Write-Warning $msg } else { Write-Host (' [{0}] {1}' -f $level, $msg) } } }
    $res = [ordered]@{ Status = 'error'; Event = $null; Trip = $null; Mail = [pscustomobject]@{ State = 'not-tried'; To = @(); Subject = '' }
                       Telemetry = [pscustomobject]@{ State = 'not-tried'; Shape = ''; Record = $null }; Stored = $false; RunHealth = 'not-tried'; Audit = 'not-tried'; Reason = '' }
    if ($null -eq $global:SI_GuardHealth) { $global:SI_GuardHealth = @{ Events = 0; Failed = 0; LastError = '' } }
    # #414: a guard switched off makes no event and no mail (it says so once, Test-SIGuardOn)
    if (-not (Test-SIGuardOn -GuardId $GuardId -Globals $Globals -Log $Log)) {
        $res.Status = 'off'; $res.Reason = 'the guard is off (setting)'
        return [pscustomobject]$res
    }
    try {
        $nowUtc = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
        $isTest = [bool](Get-Module -Name Pester)
        if (-not $global:SI_GuardRunId) { $global:SI_GuardRunId = [guid]::NewGuid().ToString() }
        if (-not $Engine) { $Engine = Get-SIGuardCallerEngine }
        $ev = New-SIGuardEvent -GuardId $GuardId -Outcome $Outcome -Engine $Engine -Job $Job -Subject $Subject -Detail $Detail -Values $Values `
                -HeldCount $HeldCount -Action $Action -Link $Link -RunId $RunId -NowUtc $nowUtc -Source $Source
        # CR4 (#654): a limit halved in the stricter period after a release (Resolve-SIGuardLimit) rides on the event
        if (Get-Command -Name Add-SIGuardStrictToEvent -ErrorAction SilentlyContinue) { try { $ev = Add-SIGuardStrictToEvent -Event $ev } catch { } }
        if (-not $ev.Link) {
            $base = "$(Get-SIGuardSetting -Name 'SIWeb_PublicBaseUrl' -Globals $Globals)".Trim().TrimEnd('/')
            if ($base -match '^https://') { $ev.Link = $base + '/Admin/Guards' }
        }
        $res.Event = $ev

        # ---- one event per guard (and subject) per run ----
        if ($null -eq $global:SI_GuardSeenThisRun) { $global:SI_GuardSeenThisRun = @{} }
        $runKey = '{0}|{1}' -f $ev.RunId, $ev.GuardKey
        if ($global:SI_GuardSeenThisRun.ContainsKey($runKey)) {
            $res.Status = 'duplicate'; $res.Reason = 'this guard already reported in this run'
            return [pscustomobject]$res
        }
        $global:SI_GuardSeenThisRun[$runKey] = $true
        # A 'warning' is not prefixed: the console's own "WARNING:" already says it (it printed "WARNING: WARNING: ...").
        # #425: what, where, the numbers and what to do -- one line a person can act on (Format-SIGuardSummary)
        $summary = Format-SIGuardSummary -Event $ev
        & $Log 'WARN' ('{0}{1}' -f $(if ($ev.Outcome -ieq 'warning') { '' } else { $ev.Outcome.ToUpperInvariant() + ': ' }), $summary)

        # #735: every guard in ONE place -- a step that hands in no database (the collection's asset-drop guard, Risk
        # Analysis' row-count / column-fill / bucket-jump guards) still writes its row to cfg.GuardEvent when the install has a
        # Pro database (Resolve-SIGuardEventInvoke); run health and the uplink are written as before
        $Invoke = Resolve-SIGuardEventInvoke -Invoke $Invoke -IsTest $isTest
        $hasTables = $false
        if ($Invoke) {
            try { $hasTables = ([int](& $Invoke (Get-SIGuardSql 'Exists') @{} 'scalar') -eq 1) } catch { & $Log 'WARN' ('the guard tables could not be checked: {0}' -f $_.Exception.Message) }
        }

        # ---- the trip's episode (de-duplication) ----
        if (-not $StateStore) {
            if ($hasTables) { $StateStore = New-SIGuardSqlStateStore -Invoke $Invoke }
            elseif ($isTest) { if (-not $global:SI_GuardTestStore) { $global:SI_GuardTestStore = New-SIGuardMemoryStateStore }; $StateStore = $global:SI_GuardTestStore }
            else { $StateStore = New-SIGuardFileStateStore -Directory (Get-SIGuardStateDirectory) }
        }
        # #414: a cause reported before is not reported again
        $causes = @($CauseKeys | Where-Object { "$_".Trim() } | ForEach-Object { 'cause|{0}|{1}' -f $ev.GuardId, ([string]$_).Trim().ToLowerInvariant() })
        if ($causes.Count) {
            $newCauses = @($causes | Where-Object { $ck = $_; $known = $null; try { $known = & $StateStore.Get $ck } catch { $known = $null }; -not $known })
            if (-not $newCauses.Count) {
                & $Log 'INFO' ('{0}: already reported (the same cause) -- not reported again' -f $ev.GuardId)
                $res.Status = 'already-reported'; $res.Reason = 'every cause of this event was reported before'
                return [pscustomobject]$res
            }
        }
        $prev = $null
        try { $prev = & $StateStore.Get $ev.GuardKey } catch { & $Log 'WARN' ('the guard''s earlier trips could not be read ({0}) -- treated as a first trip' -f $_.Exception.Message) }
        # ---- WHICH RELEASE (owner 2026-10-17): the version it tripped on, the one before, "the first run after the update" ----
        $marker = $null; $newMarker = $null; $attr = $null
        if (Get-Command -Name Get-SIGuardAttribution -ErrorAction SilentlyContinue) {
            try {
                $ver = if ($Version) { $Version } else { Get-SIGuardRunVersion }
                $marker = Read-SIGuardVersionMarker -StateStore $StateStore -GuardKey $ev.GuardKey
                $attr = Get-SIGuardAttribution -Marker $marker -Version $ver -RunId $ev.RunId
                $newMarker = Update-SIGuardVersionMarker -Marker $marker -Version $ver -RunId $ev.RunId -NowUtc $nowUtc -Kind trip -Tripped $true
                $ev | Add-Member -NotePropertyName Version -NotePropertyValue ([string]$attr.Version) -Force
                $ev | Add-Member -NotePropertyName PreviousVersion -NotePropertyValue ([string]$attr.PreviousVersion) -Force
                $ev | Add-Member -NotePropertyName AfterUpdate -NotePropertyValue ([bool]$attr.AfterUpdate) -Force
                $ev | Add-Member -NotePropertyName Attribution -NotePropertyValue ([string]$attr.Text) -Force
            } catch { & $Log 'INFO' ('the version this guard tripped on could not be worked out: {0}' -f $_.Exception.Message) }
        }
        # ---- ACCEPTED BY THE OWNER (cfg.GuardAccept): still recorded, not mailed, not reported again ----
        $accepted = $null
        if ($hasTables -and (Get-Command -Name Test-SIGuardAcceptCovers -ErrorAction SilentlyContinue)) {
            try {
                $acc = @(& $Invoke (Get-SIGuardHealSql 'AcceptRead') @{ GuardId = $ev.GuardId } 'reader' | ForEach-Object { $_ } | Where-Object { $_ })
                $accepted = Test-SIGuardAcceptCovers -Accepts $acc -GuardKey $ev.GuardKey -Version $(if ($attr) { [string]$attr.Version } else { '' }) -TimeUtc $nowUtc
            } catch { $accepted = $null }
        }
        # owner review 2026-10-17: ONLY A WARNING is muted by an acceptance. A trip that HOLDS, refuses or stops something is
        # still mailed and reported -- with "inside a range the owner accepted" -- so held data is never silent.
        $acceptedHold = $false
        if ($accepted) {
            $wireOc = 'warning'; try { $wireOc = ConvertTo-SIGuardWireOutcome -Outcome ([string]$ev.Outcome) -HeldCount ([long]$ev.HeldCount) } catch { $wireOc = 'held' }
            if ($wireOc -ne 'warning') {
                $acceptedHold = $true
                $note = 'This version is inside a range the owner accepted ({0}), but this run still held or stopped something, so it is mailed and reported as usual.' -f [string](Get-SIGuardField $accepted 'AcceptedBy')
                $ev | Add-Member -NotePropertyName Attribution -NotePropertyValue ((@([string]$(if ($ev.PSObject.Properties['Attribution']) { $ev.Attribution } else { '' }), $note) | Where-Object { $_ }) -join ' ') -Force
                if ($attr) { $attr.Text = [string]$ev.Attribution }
                & $Log 'INFO' ('{0}: inside a range the owner accepted, but it held data -- mailed and reported as usual' -f $ev.GuardId)
                $accepted = $null
            } else { & $Log 'INFO' ('{0}: accepted by {1} for this version -- a warning only: recorded, not mailed and not reported again' -f $ev.GuardId, [string](Get-SIGuardField $accepted 'AcceptedBy')) }
        }
        if ($accepted) { $NoMail = $true }
        $mailOn = (Test-SIGuardMailEnabled -Globals $Globals) -and (Test-SIGuardMailOn -GuardId $ev.GuardId -Globals $Globals) -and -not $NoMail -and (Test-SIGuardOutcomeMails -Event $ev)
        $trip = Get-SIGuardTripState -Previous $prev -NowUtc $nowUtc -WindowHours $script:SIGuard.WindowHours -MailEnabled $mailOn
        $res.Trip = $trip

        # ---- (c) MAIL ----
        $mailState = 'off'; $mailTo = @(); $mailSubject = ''
        if (-not $mailOn) { $mailState = 'off' }
        elseif (-not $trip.Mail) { $mailState = 'deduped' }
        else {
            try {
                $admins = @()
                $rcp = Get-SIGuardMailRecipients -Globals $Globals
                if (-not @($rcp.To).Count -and $hasTables) {
                    try { $admins = @(& $Invoke (Get-SIGuardSql 'SuperAdmins') @{} 'reader' | ForEach-Object { [string]$_.Mail }) } catch { }
                    $rcp = Get-SIGuardMailRecipients -Globals $Globals -SuperAdminMails $admins
                }
                $mailTo = @($rcp.To)
                $tag = Get-SIGuardTenantTag -Globals $Globals
                $m = ConvertTo-SIGuardMail -Event $ev -Trip $trip -TenantTag $tag -Culture (Get-SIGuardCulture -Globals $Globals)
                $mailSubject = $m.Subject
                if (-not $mailTo.Count) {
                    # #277 (live: printed 24 times in one run): said ONCE per process; every guard row carries 'mail: no recipients'
                    $mailState = 'no-recipients'
                    if (-not $global:SI_GuardNoRecipientsWarned) { $global:SI_GuardNoRecipientsWarned = $true; & $Log 'WARN' 'the guard mail has no recipients (set SI_GuardMail_To, or MailTo) -- not sent' }
                }
                elseif (-not $MailTransport -and $isTest) { $mailState = 'test-session' }
                else {
                    $prio = if ($ev.Severity -eq 'critical') { 'High' } else { 'Normal' }
                    $smtp = if ($MailTransport) { $null } else { Get-SIGuardSmtp -Globals $Globals }
                    if (-not $MailTransport -and $smtp.Off) { $mailState = 'off' }
                    elseif (-not $MailTransport -and @($smtp.Problems).Count) { $mailState = 'no-relay'; & $Log 'WARN' ('the guard mail could not be sent: ' + (@($smtp.Problems) -join '; ')) }
                    else {
                        $ok = if ($MailTransport) { & $MailTransport $mailTo $m.Subject $m.Html $prio } else { Send-SIGuardMailDefault -Smtp $smtp -To $mailTo -Subject $m.Subject -Html $m.Html -Priority $prio }
                        $mailState = if (@($ok | Where-Object { $_ -is [bool] } | Select-Object -Last 1) -contains $false) { 'failed' } else { 'sent' }
                    }
                }
            } catch {
                $mailState = 'failed'
                & $Log 'WARN' ('the guard mail could not be sent: {0}. The job itself is not affected.' -f $_.Exception.Message)
            }
            # an undelivered mail is tried again on the next trip, not a day later
            if ($mailState -ne 'sent') { $trip.LastMailUtc = $(if ($prev) { ConvertTo-SIGuardUtc $prev.LastMailUtc } else { $null }) }
        }
        if ($accepted) { $mailState = 'accepted' }
        $res.Mail = [pscustomobject]@{ State = $mailState; To = $mailTo; Subject = $mailSubject }

        # ---- (d) TELEMETRY ----
        $telState = 'off'; $shape = ''; $wireRec = $null
        try {
            if ($accepted) { $telState = 'accepted' }
            elseif ($NoTelemetry -or -not (Get-Command -Name Test-SITelemetryEnabled -ErrorAction SilentlyContinue)) { $telState = 'off' }
            elseif (-not $Globals -and -not (Test-SITelemetryEnabled)) { $telState = 'off' }
            elseif ($Globals -and -not (Test-SIGuardFlag -Value (Get-SIGuardSetting -Name 'SI_Telemetry_Enabled' -Globals $Globals) -Default $true)) { $telState = 'off' }
            elseif ($global:SI_TelemetryHalted -and -not $TelemetryTransport) { $telState = 'halted' }
            elseif (-not $TelemetryTransport -and $isTest) { $telState = 'test-session' }
            else {
                $ctx = if ($TelemetryContext) { $TelemetryContext } else { Get-SITelemetryContext }
                $rec = New-SIGuardTelemetryRecord -Event $ev -Trip $trip -Context $ctx -Now $nowUtc
                # a trip that held inside a range the owner accepted says so to Invardia (identified: its words) -- only with
                # SI_Uplink_SendGuardHealOutcomes on (off: the report keeps its earlier shape)
                if ($acceptedHold -and $rec.PSObject.Properties['ActionText'] -and (Resolve-SIGuardHealOutcomesSwitch -Ring $ctx.Ring -Globals $Globals).On) {
                    $tx2 = 'held (accepted range): ' + [string]$rec.ActionText; if ($tx2.Length -gt 500) { $tx2 = $tx2.Substring(0, 497) + '...' }
                    $rec.ActionText = $tx2
                }
                $wire = ConvertTo-SIGuardWire -Record $rec -Context $ctx
                $shape = $wire.Shape; $wireRec = $wire.Record
                if ($null -eq $wire.Record) { $telState = 'no-install-id' }
                else {
                    if (-not $TelemetryTransport) { $TelemetryTransport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) if (Get-Command -Name Test-SITelemetryCommunitySendAllowed -ErrorAction SilentlyContinue) { $g = Test-SITelemetryCommunitySendAllowed -AccessCode $AccessCode; if (-not $g.Allowed) { return [pscustomobject]@{ Status = 'skipped'; Reason = $g.Reason; Sent = $false } } }; Send-AitUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec } }
                    $r = & $TelemetryTransport $wire.Record $ctx.Endpoint $ctx.AccessCode 5
                    if ("$($r.Status)" -eq 'ok') { $telState = 'sent' }
                    else {
                        $telState = 'failed'
                        $global:SI_TelemetryHalted = $true
                        & $Log 'WARN' ('the guard report to Invardia was not sent ({0}); the job is not affected' -f $(if (Get-Command -Name ConvertTo-AitUplinkRedacted -ErrorAction SilentlyContinue) { ConvertTo-AitUplinkRedacted -Text "$($r.Reason)" } else { "$($r.Reason)" }))
                    }
                }
            }
        } catch { $telState = 'failed'; & $Log 'WARN' ('the guard report to Invardia could not be prepared: {0}' -f $_.Exception.Message) }
        $res.Telemetry = [pscustomobject]@{ State = $telState; Shape = $shape; Record = $wireRec }

        # ---- the episode, saved (with the version it tripped on; a trip re-opens a cleared episode) ----
        $tripSave = $trip
        if ($attr) {
            $tripSave = [pscustomobject]@{ FirstSeenUtc = $trip.FirstSeenUtc; LastSeenUtc = $trip.LastSeenUtc; TripCount = $trip.TripCount; LastMailUtc = $trip.LastMailUtc
                                           Version = [string]$attr.Version; PreviousVersion = [string]$attr.PreviousVersion; ClearedUtc = $null; ClearedRunId = $null; ClearedVersion = $null; ClearedHow = $null }
        }
        try { & $StateStore.Set $ev.GuardKey $ev.GuardId $tripSave } catch { & $Log 'WARN' ('the guard''s trip count could not be saved: {0}' -f $_.Exception.Message) }
        foreach ($ck in $causes) { try { & $StateStore.Set $ck $ev.GuardId $trip } catch { } }
        if ($newMarker) { Save-SIGuardVersionMarker -StateStore $StateStore -GuardKey $ev.GuardKey -GuardId $ev.GuardId -Marker $newMarker -NowUtc $nowUtc }

        # ---- (e) the Guards view row ----
        if ($hasTables) {
            try {
                $vj = ConvertTo-Json -InputObject @($ev.Values) -Depth 3 -Compress
                $newId = & $Invoke (Get-SIGuardSql 'Insert') @{
                    GuardId = $ev.GuardId; GuardKey = $ev.GuardKey; Area = $ev.Area; Job = $ev.Job; Engine = $ev.Engine; Source = $ev.Source
                    Outcome = $ev.Outcome; Severity = $ev.Severity; Protected = $ev.Protected; Subject = $ev.Subject; Detail = $ev.Detail
                    MeasuredText = (Format-SIGuardValues -Values $ev.Values); ValuesJson = $vj; HeldCount = [long]$ev.HeldCount; ActionText = $ev.Action
                    Link = $ev.Link; RunId = $ev.RunId; TripCount = [int]$trip.TripCount; FirstSeenUtc = $trip.FirstSeenUtc
                    MailState = $mailState; MailTo = (@($mailTo) -join '; '); TelemetryState = $telState } 'scalar'
                $res.Stored = $true
                # the version it tripped on and the words of "which release" (only where the database has the columns)
                if ($attr) {
                    $nid = 0L
                    if ([long]::TryParse([string]$(if ($newId -is [array]) { $newId[0] } else { $newId }), [ref]$nid) -and $nid -gt 0) {
                        $at = [string]$attr.Text; if ($at.Length -gt 400) { $at = $at.Substring(0, 400) }
                        try { $null = & $Invoke (Get-SIGuardHealSql 'EventInfo') @{ Id = $nid; SiVersion = $(if ($attr.Version) { [string]$attr.Version } else { $null }); PreviousVersion = $(if ($attr.PreviousVersion) { [string]$attr.PreviousVersion } else { $null }); Attribution = $(if ($at) { $at } else { $null }) } 'nonquery' } catch { }
                    }
                }
            } catch { & $Log 'WARN' ('the guard event could not be saved for the Guards view: {0}' -f $_.Exception.Message) }
        }

        # ---- (a) RUN HEALTH ----
        try {
            $ctxRh = [pscustomobject]@{ RunId = $ev.RunId; Engine = $(if ($ev.Engine) { $ev.Engine } else { 'guard' }); ShardIndex = 0; ShardCount = 1; CollectionTime = $nowUtc; StartedAt = $nowUtc }
            $msg = '{0}: {1}' -f $ev.GuardId, $summary
            if ($attr -and [string]$attr.Text) { $msg += ' ' + [string]$attr.Text }
            if ($mailState -eq 'no-recipients') { $msg += ' | mail: no recipients' }
            if ($accepted) { $msg += ' | accepted by the owner for this version' }
            if ($RunHealth) { $null = & $RunHealth $ctxRh ('guard-' + $ev.Outcome) $msg ([long]$ev.HeldCount); $res.RunHealth = 'written' }
            elseif (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue) {
                Send-SIRunHealthRow -RunContext $ctxRh -Phase Guard -AssetCount ([int][Math]::Min([long]$ev.HeldCount, [int]::MaxValue)) -ExitReason ('guard-' + $ev.Outcome) -ErrorMessage $msg -NoTelemetry
                $res.RunHealth = 'written'
            } else { $res.RunHealth = 'unavailable' }
        } catch { $res.RunHealth = 'failed' }

        # ---- (b) AUDIT ----
        if ($Invoke -and (Get-Command -Name Write-SIAuditEvent -ErrorAction SilentlyContinue)) {
            $after = [ordered]@{ guard = $ev.GuardId; area = $ev.Area; outcome = $ev.Outcome; severity = $ev.Severity; held = [long]$ev.HeldCount
                                 measured = (Format-SIGuardValues -Values $ev.Values); trips = [int]$trip.TripCount; mail = $mailState; telemetry = $telState }
            $actor = if (Get-Command -Name Get-SIAuditActor -ErrorAction SilentlyContinue) { Get-SIAuditActor -Job $(if ($ev.Engine) { $ev.Engine } else { 'guard' }) } else { 'guard' }
            $ok = Write-SIAuditEvent -Invoke $Invoke -Action $script:SIGuard.AuditAction -Actor $actor -ActorSource $(if ($ev.Source -eq 'web') { 'web' } elseif ($ev.Source -eq 'setup') { 'setup' } else { 'job' }) `
                    -Target $(if ($ev.Subject) { '{0} ({1})' -f $ev.GuardId, $ev.Subject } else { $ev.GuardId }) -Reason $ev.Protected `
                    -Outcome $(if ($ev.Severity -eq 'critical') { 'refused' } else { 'held' }) -OutcomeText $(if ($ev.Detail) { $ev.Detail } else { $ev.Action }) `
                    -CorrelationId $ev.RunId -After $after -Log { param($l, $m) }
            $res.Audit = if ($ok) { 'written' } else { 'failed' }
        } else { $res.Audit = 'no-database' }

        $global:SI_GuardHealth.Events++
        $res.Status = 'recorded'
        return [pscustomobject]$res
    } catch {
        $global:SI_GuardHealth.Failed++; $global:SI_GuardHealth.LastError = [string]$_.Exception.Message
        $res.Status = 'error'; $res.Reason = [string]$_.Exception.Message
        try { & $Log 'WARN' ('a guard event could not be recorded: {0}. The job itself is not affected.' -f $_.Exception.Message) } catch { }
        return [pscustomobject]$res
    }
}

function Send-SIGuardMailDefault {
    <# The default mail path: the one transport (Send-SIMail, SI-MailTransport.ps1) with the mail settings (-Smtp, from
       Get-SIGuardSmtp). A plain function, not a closure: a closure cannot see functions dot-sourced into the engine's
       script scope. THROWS when the mail does not go out. #>
    param([Parameter(Mandatory)]$Smtp, [Parameter(Mandatory)][string[]]$To, [Parameter(Mandatory)][string]$Subject, [Parameter(Mandatory)][string]$Html, [string]$Priority = 'Normal',
          # MAIL-3 (#653): the subject's severity word (the guard mail writes it first in its subject itself)
          [AllowNull()][AllowEmptyString()][string]$Severity)
    $r = Send-SIMail -Settings $Smtp -To $To -Subject $Subject -BodyHtml $Html -Priority $Priority -Severity $Severity
    if (-not $r.Sent) { throw $(if ($r.Error) { [string]$r.Error } else { 'the mail was not accepted' }) }
    return $true
}

function Invoke-SIGuardOutbox {
    <#
        The mail job's step (Pro): the guard events the WEB APP wrote (cfg.GuardEvent, MailState / TelemetryState
        'pending') are mailed and reported here, with the same de-duplication as a job's guard. Never throws; returns
        @{ Read; Mailed; Reported; Failed }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, $StateStore, [scriptblock]$MailTransport, [scriptblock]$TelemetryTransport, $TelemetryContext,
          [System.Collections.IDictionary]$Globals, $Now, [switch]$DryRun, [scriptblock]$Log)
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host (' [{0}] {1}' -f $level, $msg) } }
    $out = [ordered]@{ Read = 0; Mailed = 0; Reported = 0; Failed = 0 }
    try {
        if ([int](& $Invoke (Get-SIGuardSql 'Exists') @{} 'scalar') -ne 1) { & $Log 'INFO' 'guards    : the Pro database has no guard tables yet -- nothing to send'; return [pscustomobject]$out }
        $rows = @(& $Invoke (Get-SIGuardSql 'OutboxRead') @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ })
        $out.Read = $rows.Count
        if (-not $rows.Count) { return [pscustomobject]$out }
        if (-not $StateStore) { $StateStore = New-SIGuardSqlStateStore -Invoke $Invoke }
        foreach ($row in $rows) {
            # owner 2026-10-17: a CLEAR another writer recorded (the owner's acceptance, cfg.GuardAcceptSet) -- only the report
            # to Invardia that the guard is cleared (ClearedBy 'released': a person decided); nothing is mailed
            if ([string]$row.Outcome -eq 'cleared') {
                try {
                    $telState = [string]$row.TelemetryState
                    if ($telState -eq 'pending' -and -not $DryRun) {
                        $enabled = if ($Globals) { Test-SIGuardFlag -Value (Get-SIGuardSetting -Name 'SI_Telemetry_Enabled' -Globals $Globals) -Default $true } else { Test-SITelemetryEnabled }
                        $ctx = $null
                        if ($enabled -and -not ($global:SI_TelemetryHalted -and -not $TelemetryTransport)) { $ctx = if ($TelemetryContext) { $TelemetryContext } else { Get-SITelemetryContext } }
                        if (-not $enabled) { $telState = 'off' }
                        elseif ($global:SI_TelemetryHalted -and -not $TelemetryTransport) { $telState = 'halted' }
                        # Invardia's receiver does not take 'cleared' yet: with SI_Uplink_SendGuardHealOutcomes off the clear is
                        # marked 'off' -- never sent, and never sent later in a burst when the switch goes on
                        elseif (-not (Resolve-SIGuardHealOutcomesSwitch -Ring $ctx.Ring -Globals $Globals).On) { $telState = 'off' }
                        else {
                            $def = Get-SIGuardDefinition -Id ([string]$row.GuardId)
                            $nowC = if ($row.TsUtc -and -not ($row.TsUtc -is [System.DBNull])) { ([datetime]$row.TsUtc).ToUniversalTime() } else { [datetime]::UtcNow }
                            $rec = New-SIGuardClearTelemetryRecord -GuardId ([string]$row.GuardId) -Context $ctx -How released -NowUtc $nowC -Job $(if ([string]$row.Job) { [string]$row.Job } else { [string]$def.job }) -Area ([string]$def.area) -Text ([string]$row.Detail)
                            if ([string]$ctx.Mode -eq 'anonymous' -and [string]$rec.InstallId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $telState = 'no-install-id' }
                            else {
                                if (-not $TelemetryTransport) { $TelemetryTransport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) if (Get-Command -Name Test-SITelemetryCommunitySendAllowed -ErrorAction SilentlyContinue) { $g = Test-SITelemetryCommunitySendAllowed -AccessCode $AccessCode; if (-not $g.Allowed) { return [pscustomobject]@{ Status = 'skipped'; Reason = $g.Reason; Sent = $false } } }; Send-AitUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec } }
                                $r = & $TelemetryTransport $rec $ctx.Endpoint $ctx.AccessCode 5
                                if ("$($r.Status)" -eq 'ok') { $telState = 'sent'; $out.Reported++ } else { $telState = 'failed' }
                            }
                        }
                        $null = & $Invoke (Get-SIGuardSql 'OutboxMark') @{ Id = [long]$row.Id; MailState = $(if ([string]$row.MailState -eq 'pending') { 'off' } else { [string]$row.MailState }); MailTo = $null; TelemetryState = $telState; TripCount = $null; FirstSeenUtc = $null } 'nonquery'
                    }
                } catch { $out.Failed++; & $Log 'WARN' ('guards    : the clear {0} could not be reported: {1}' -f $row.Id, $_.Exception.Message) }
                continue
            }
            try {
                $vals = @(); if ([string]$row.ValuesJson) { try { $vals = @(ConvertFrom-Json -InputObject ([string]$row.ValuesJson)) } catch { $vals = @() } }
                $ev = New-SIGuardEvent -GuardId ([string]$row.GuardId) -Outcome ([string]$row.Outcome) -Engine ([string]$row.Engine) -Job ([string]$row.Job) -Subject ([string]$row.Subject) `
                        -Detail ([string]$row.Detail) -Values $vals -HeldCount ([long]$row.HeldCount) -Action ([string]$row.ActionText) -Link ([string]$row.Link) -RunId ([string]$row.RunId) `
                        -NowUtc $(if ($row.TsUtc) { [datetime]$row.TsUtc } else { [datetime]::UtcNow }) -Source $(if ([string]$row.Source) { [string]$row.Source } else { 'web' })
                $nowUtc = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
                # CR4 (#654): a web app event whose limit was halved (its value carries Configured) -- the period's words
                $hv = @(@($ev.Values) | Where-Object { $_ -and $_.PSObject.Properties['Configured'] }) | Select-Object -First 1
                if ($hv -and (Get-Command -Name Get-SIGuardModeNow -ErrorAction SilentlyContinue)) {
                    try {
                        $gmo = Get-SIGuardModeNow -Invoke $Invoke
                        $ev | Add-Member -NotePropertyName Strict -NotePropertyValue ([pscustomobject]@{ GuardId = $ev.GuardId; Name = $hv.Name; Label = $hv.Label; Configured = [Math]::Abs([double]$hv.Configured)
                                                                                                       Effective = [Math]::Abs([double]$hv.Limit); Unit = $hv.Unit; Until = $gmo.Until; Version = [string]$gmo.Version }) -Force
                    } catch { }
                }
                $prev = $null; try { $prev = & $StateStore.Get $ev.GuardKey } catch { }
                $mailOn = (Test-SIGuardMailEnabled -Globals $Globals) -and (Test-SIGuardMailOn -GuardId $ev.GuardId -Globals $Globals) -and (Test-SIGuardOutcomeMails -Event $ev)
                $trip =Get-SIGuardTripState -Previous $prev -NowUtc $nowUtc -MailEnabled $mailOn
                $mailState = [string]$row.MailState; $telState = [string]$row.TelemetryState; $to = $null
                if ($mailState -eq 'pending') {
                    if (-not $mailOn) { $mailState = 'off' }
                    elseif (-not $trip.Mail) { $mailState = 'deduped' }
                    elseif ($DryRun) { $mailState = 'pending' }
                    else {
                        $rcp = Get-SIGuardMailRecipients -Globals $Globals -SuperAdminMails @(& $Invoke (Get-SIGuardSql 'SuperAdmins') @{} 'reader' | ForEach-Object { [string]$_.Mail })
                        $to = @($rcp.To)
                        if (-not $to.Count) { $mailState = 'no-recipients' }
                        else {
                            $smtp = if ($MailTransport) { $null } else { Get-SIGuardSmtp -Globals $Globals }
                            if (-not $MailTransport -and $smtp.Off) { $mailState = 'off' }
                            elseif (-not $MailTransport -and @($smtp.Problems).Count) { $mailState = 'no-relay' }
                            else {
                                $m = ConvertTo-SIGuardMail -Event $ev -Trip $trip -Culture (Get-SIGuardCulture -Globals $Globals)
                                $prio = if ($ev.Severity -eq 'critical') { 'High' } else { 'Normal' }
                                try { if ($MailTransport) { $null = & $MailTransport $to $m.Subject $m.Html $prio } else { $null = Send-SIGuardMailDefault -Smtp $smtp -To $to -Subject $m.Subject -Html $m.Html -Priority $prio }; $mailState = 'sent'; $out.Mailed++ }
                                catch { $mailState = 'failed'; $out.Failed++; & $Log 'WARN' ('guards    : the mail about {0} was not sent: {1}' -f $ev.GuardId, $_.Exception.Message) }
                            }
                        }
                    }
                    if ($mailState -ne 'sent') { $trip.LastMailUtc = $(if ($prev) { ConvertTo-SIGuardUtc $prev.LastMailUtc } else { $null }) }
                }
                if ($telState -eq 'pending' -and -not $DryRun) {
                    $enabled = if ($Globals) { Test-SIGuardFlag -Value (Get-SIGuardSetting -Name 'SI_Telemetry_Enabled' -Globals $Globals) -Default $true } else { Test-SITelemetryEnabled }
                    if (-not $enabled) { $telState = 'off' }
                    elseif ($global:SI_TelemetryHalted -and -not $TelemetryTransport) { $telState = 'halted' }
                    else {
                        $ctx = if ($TelemetryContext) { $TelemetryContext } else { Get-SITelemetryContext }
                        $rec = New-SIGuardTelemetryRecord -Event $ev -Trip $trip -Context $ctx -Now $nowUtc
                        $wire = ConvertTo-SIGuardWire -Record $rec -Context $ctx
                        if ($null -eq $wire.Record) { $telState = 'no-install-id' }
                        else {
                            if (-not $TelemetryTransport) { $TelemetryTransport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) if (Get-Command -Name Test-SITelemetryCommunitySendAllowed -ErrorAction SilentlyContinue) { $g = Test-SITelemetryCommunitySendAllowed -AccessCode $AccessCode; if (-not $g.Allowed) { return [pscustomobject]@{ Status = 'skipped'; Reason = $g.Reason; Sent = $false } } }; Send-AitUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec } }
                            $r = & $TelemetryTransport $wire.Record $ctx.Endpoint $ctx.AccessCode 5
                            if ("$($r.Status)" -eq 'ok') { $telState = 'sent'; $out.Reported++ } else { $telState = 'failed'; $global:SI_TelemetryHalted = $true }
                        }
                    }
                }
                if (-not $DryRun) {
                    try { & $StateStore.Set $ev.GuardKey $ev.GuardId $trip } catch { }
                    $null = & $Invoke (Get-SIGuardSql 'OutboxMark') @{ Id = [long]$row.Id; MailState = $mailState; MailTo = $(if ($to) { @($to) -join '; ' } else { $null }); TelemetryState = $telState; TripCount = [int]$trip.TripCount; FirstSeenUtc = $trip.FirstSeenUtc } 'nonquery'
                }
            } catch { $out.Failed++; & $Log 'WARN' ('guards    : event {0} could not be sent: {1}' -f $row.Id, $_.Exception.Message) }
        }
        & $Log 'INFO' ('guards    : {0} event(s) from the web app -- {1} mailed, {2} reported to Invardia' -f $out.Read, $out.Mailed, $out.Reported)
    } catch { $out.Failed++; & $Log 'WARN' ('guards    : the guard outbox could not be read: {0}' -f $_.Exception.Message) }
    [pscustomobject]$out
}

# =====================================================================================================================
#  ADAPTERS -- PURE: one area's result -> the guard events it tripped (each a hashtable of Send-SIGuardEvent arguments).
#  The engines call Invoke-SIGuardCalls with them, so "which guard tripped, with which numbers" is provable offline.
# =====================================================================================================================
function Invoke-SIGuardCalls {
    <#
        Sends each call (Send-SIGuardEvent arguments) with the shared extras (-Invoke, -Engine, ...). Never throws.
        AUTO-HEAL (owner 2026-10-17): -Checked names the guards this step CHECKED (guard ids, or @{ GuardId; Subject; Values;
        Detail }; a bare id takes -Subject) and -Complete whether the run was complete. Every checked guard that did not
        trip records that it ran on this version, and clears its open episode when the run was complete and its values are
        within their limits (Invoke-SIGuardHeal, SI-GuardHeal.ps1). Without -Checked nothing is cleared (as before).
        Returns the trips' results (the clears are not among them).
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Calls, [hashtable]$Common = @{}, [AllowNull()][AllowEmptyCollection()][object[]]$Checked, [bool]$Complete = $false, [string]$Subject)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($Calls)) {
        if ($null -eq $c) { continue }
        try {
            $a = @{}; foreach ($k in @($Common.Keys)) { if ($null -ne $Common[$k]) { $a[$k] = $Common[$k] } }
            foreach ($k in @($c.Keys)) { $a[$k] = $c[$k] }
            $out.Add((Send-SIGuardEvent @a))
        } catch { }
    }
    if ($PSBoundParameters.ContainsKey('Checked') -and @($Checked | Where-Object { $_ }).Count -and (Get-Command -Name Invoke-SIGuardHeal -ErrorAction SilentlyContinue)) {
        try {
            $hc = @{}; foreach ($k in @($Common.Keys)) { $hc[$k] = $Common[$k] }
            if ($Subject) { $hc['Subject'] = $Subject }
            $null = Invoke-SIGuardHeal -Checked $Checked -Calls @($Calls | Where-Object { $_ }) -Complete $Complete -Common $hc
        } catch { }
    }
    $out.ToArray()
}

function Resolve-SIGuardEventInvoke {
    <#
        #735 -- the database a guard event is written to (cfg.GuardEvent, the Operations > Guards (safety checks) view): the -Invoke the step
        handed in; else the process's guard seam ($global:SI_GuardInvoke); else the Pro database of this install
        (-ProInvoke, default Get-SIGuardProInvoke -- none without a Pro database). A test session (-IsTest) never opens one.
        $null = no database (Community): the event still goes to run health and the uplink. Never throws.
    #>
    param([scriptblock]$Invoke, [bool]$IsTest = $false, [scriptblock]$ProInvoke)
    try {
        if ($Invoke) { return $Invoke }
        if ($IsTest) { return $null }
        if ($global:SI_GuardInvoke -is [scriptblock]) { return $global:SI_GuardInvoke }
        if (-not $ProInvoke) {
            if (-not (Get-Command -Name Get-SIGuardProInvoke -ErrorAction SilentlyContinue)) { return $null }
            $ProInvoke = { Get-SIGuardProInvoke }
        }
        $p = & $ProInvoke
        if ($p -is [array]) { $p = @($p | Where-Object { $_ -is [scriptblock] }) | Select-Object -First 1 }
        if ($p -is [scriptblock]) { return $p }
    } catch { }
    $null
}

function Get-SIGuardProInvoke {
    <#
        The Pro SETTINGS database's (sql, params, mode) seam for the guard rows -- the engine's own -Default when it already
        points there (or no Pro database is configured), else one opened for SI_ProSqlServer / SI_ProSqlDatabase with the
        engine's sign-in (New-SIDataSqlInvoke; #735 loaded here when the engine has not loaded it -- a collection job writes
        its guard rows too). Remembered for the process. Never throws.
    #>
    param([scriptblock]$Default, [string]$Server, [string]$Database)
    try {
        $ps = [string]$global:SI_ProSqlServer; $pd = [string]$global:SI_ProSqlDatabase
        if ($ps -and $pd -and -not ($ps -eq $Server -and $pd -eq $Database) -and -not ($global:SI_GuardProInvoke -is [scriptblock]) -and -not (Get-Command -Name New-SIDataSqlInvoke -ErrorAction SilentlyContinue)) {
            $dsq = [System.IO.Path]::Combine($PSScriptRoot, 'data-sql', 'SI-DataSql.ps1')
            if ([System.IO.File]::Exists($dsq)) { try { . $dsq } catch { } }
        }
        if (-not $ps -or -not $pd -or ($ps -eq $Server -and $pd -eq $Database)) { $inv = $Default }
        elseif ($global:SI_GuardProInvoke -is [scriptblock]) { $inv = $global:SI_GuardProInvoke }
        elseif (Get-Command -Name New-SIDataSqlInvoke -ErrorAction SilentlyContinue) {
            $inv = New-SIDataSqlInvoke -Server $ps -Database $pd -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint
            $global:SI_GuardProInvoke = $inv
        } else { $inv = $null }
        if ($inv -and -not ($global:SI_GuardInvoke -is [scriptblock])) { $global:SI_GuardInvoke = $inv }
        return $inv
    } catch { return $Default }
}

function Get-SIGuardCallsForVulnPlan {
    <# The vulnerability connector: a halted plan (close ceiling, empty / collapsed snapshot, scope change, incomplete run)
       -> one 'halted' event; else results not known to be complete that held closes -> one 'held' event. #>
    param([Parameter(Mandatory)]$Plan, $Complete, [string]$Subject)
    if ($Plan.Halted) {
        $g = if ($Plan.PSObject.Properties['HaltGuard'] -and $Plan.HaltGuard) { [string]$Plan.HaltGuard } else { 'vuln.connector.run-incomplete' }
        $held = if ($Plan.PSObject.Properties['HaltHeld']) { [long]$Plan.HaltHeld } else { 0 }
        $vals = if ($Plan.PSObject.Properties['HaltValues']) { @($Plan.HaltValues) } else { @() }
        return @(@{ GuardId = $g; Outcome = 'halted'; Subject = $Subject; Detail = ([string]$Plan.HaltReason -replace '^\[[A-Za-z]+\]\s*', ''); Values = $vals; HeldCount = $held })
    }
    if ($Complete -and -not $Complete.Complete) {
        # #850: a paged run's plan carries the count (its pages' held records are never all held at once)
        $n = if ($Plan.PSObject.Properties['HeldIncompleteCount']) { [long]$Plan.HeldIncompleteCount } else { @($Plan.Held | Where-Object { [string]$_.Reason -like 'this run was not complete*' }).Count }
        if ($n -gt 0) {
            return @(@{ GuardId = 'vuln.connector.snapshot-incomplete'; Outcome = 'held'; Subject = $Subject; HeldCount = $n
                          Detail = ('The newest Risk Analysis results are not known to be complete ({0}), so {1} record(s) that would have closed stay open.' -f [string]$Complete.Reason, $n)
                          Values = @(@{ Name = 'heldCloses'; Label = 'Closes held back'; Measured = $n }) })
        }
    }
    @()
}

function Get-SIGuardCallsForCmdbSql {
    <# The SQL CMDB connector: a refused or stale run -> one event, its guard told apart by the refusal's reason. #>
    param([Parameter(Mandatory)]$Result)
    $o = [string]$Result.Outcome; $why = [string]$Result.Reason
    if ($o -eq 'stale') { return @(@{ GuardId = 'cmdb.sql.stale'; Outcome = 'skipped'; Detail = $why }) }
    # UPLINK-FIX (customer G 2026-10-07): a first run whose correlation map has no results yet -- shown, a WARNING (no
    # ticket, no critical mail), never a refusal: the CI table has nothing to protect yet and the next run fills it.
    if ($o -eq 'pending') { return @(@{ GuardId = $(if ($why -match 'profile snapshot') { 'cmdb.sql.snapshot-incomplete' } else { 'cmdb.sql.no-correlation-map' }); Outcome = 'warning'; Detail = $why }) }
    if ($o -ne 'refused') { return @() }
    $desired = 0; if ($Result.Plan -and $Result.Plan.Summary) { $desired = [long]$Result.Plan.Summary.Desired }
    $g = 'cmdb.sql.snapshot-incomplete'; $vals = @()
    if ($why -match 'correlation map') { $g = 'cmdb.sql.no-correlation-map' }
    elseif ($why -match 'holds no asset|no kind in scope') { $g = 'cmdb.sql.empty-snapshot'; $vals = @(@{ Name = 'assetsSeen'; Label = 'Assets seen'; Measured = 0 }) }
    elseif ($why -match '^(\w+): (\d+) asset\(s\) seen against (\d+) active CI\(s\) -- below (\d+)') {
        $g = 'cmdb.sql.collapse'
        $vals = @(@{ Name = 'assetsSeen'; Label = ('Assets seen ({0})' -f $Matches[1]); Measured = [long]$Matches[2] }, @{ Name = 'activeCis'; Label = 'Active CIs'; Measured = [long]$Matches[3] },
                  @{ Name = 'seenShare'; Label = 'Seen against active'; Measured = $(if ([long]$Matches[3]) { [Math]::Round(100.0 * [long]$Matches[2] / [long]$Matches[3], 1) } else { 0 }); Limit = [long]$Matches[4]; Unit = '%' })
    }
    @(@{ GuardId = $g; Outcome = 'refused'; Detail = $why; Values = $vals; HeldCount = $desired })
}

function Get-SIGuardCallsForServiceNowCmdb {
    <# The ServiceNow CMDB connector: the instance unreachable (halted), assets refused by the create / match gates (held),
       an incoherent service model (refused). #>
    param($Result, [int]$ModelProblems = 0, [string[]]$ModelText = @())
    $calls = New-Object System.Collections.Generic.List[object]
    if ($ModelProblems -gt 0) {
        $calls.Add(@{ GuardId = 'cmdb.servicenow.service-model'; Outcome = 'refused'; Detail = ('The service model has {0} problem(s): {1}' -f $ModelProblems, ((@($ModelText) | Select-Object -First 3) -join '; '))
                      Values = @(@{ Name = 'modelProblems'; Label = 'Problems in the service model'; Measured = $ModelProblems }) })
    }
    if ($Result) {
        if ($Result.Halted) { $calls.Add(@{ GuardId = 'cmdb.servicenow.unreachable'; Outcome = 'halted'; Detail = [string]$Result.HaltReason }) }
        $review = @($Result.Review | Where-Object { $_ })
        # #928: the data-out push hands in the reasons (a sample) and the COUNT of rows ServiceNow did not accept
        $n = if ($Result.PSObject.Properties['ReviewCount'] -and $null -ne $Result.ReviewCount) { [long]$Result.ReviewCount } else { [long]$review.Count }
        if ($n -gt 0) {
            $why = (@($review | ForEach-Object { [string]$_.Reason } | Group-Object | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { '{0} x {1}' -f $_.Count, $_.Name })) -join '; '
            $calls.Add(@{ GuardId = 'cmdb.servicenow.create-gate'; Outcome = 'held'; HeldCount = $n
                          Detail = ('{0} asset(s) were not written to ServiceNow{1}' -f $n, $(if ($why) { ': ' + $why } else { '' }))
                          Values = @(@{ Name = 'assetsHeld'; Label = 'Assets not written'; Measured = $n }, @{ Name = 'assetsSubmitted'; Label = 'Assets submitted'; Measured = [long]$Result.Submitted }) })
        }
    }
    $calls.ToArray()
}

function ConvertTo-SIGuardServiceNowPushResult {
    <#
        PURE. #928 (the ServiceNow push moved to ONE route, the data-out connector): the push result of one ServiceNow
        data-out session (Open-SIDataOutSnowSession ... Close-SIDataOutSnowSession) in the shape the ServiceNow CMDB guard
        reads (Get-SIGuardCallsForServiceNowCmdb -Result): @{ Halted; HaltReason; Review; ReviewCount; Submitted; Reached }.
          Halted     the check before the push could not reach the instance, or the instance refused the account (a
                     connection problem of KIND 'setup' -- no connector switched on, no credential -- is the install's
                     setup, said by the run and Data health, never "not reachable");
          Review     the reasons ServiceNow gave for the rows its import did not accept (at most 50), ReviewCount their number;
          Reached    the push reached ServiceNow (the guards' checks ran and may clear).
    #>
    param([Parameter(Mandatory)]$Session)
    $get = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $chk = & $get $Session 'Check'
    $conn = & $get $chk 'Connection'
    $halted = [bool]($conn -and ($conn.Ok -eq $false) -and ([string]$conn.Kind -ne 'setup'))
    $errs = @(@(& $get $Session 'Errors') | Where-Object { $_ } | Select-Object -First 50 | ForEach-Object { [pscustomobject]@{ Reason = [string]$_ } })
    $notAccepted = [long](& $get $Session 'NotAccepted')
    [pscustomobject]@{
        Halted      = $halted
        HaltReason  = $(if ($halted) { [string]$conn.Text } else { '' })
        Review      = $errs
        ReviewCount = $notAccepted
        Submitted   = [long](& $get $Session 'Sent')
        Reached     = [bool]($conn -and $conn.Ok -eq $true)
    }
}

function Get-SIGuardCallsForDataSync {
    <# The Pro data sync: collections held because their run is not known to be complete -> one 'held' event. #>
    param([Parameter(Mandatory)]$Result)
    $calls = New-Object System.Collections.Generic.List[object]
    $held = @($Result.Held)
    if ($held.Count) {
        $rows = 0L; foreach ($h in $held) { $rows += [long]$h.Rows }
        # per collection: when, how many findings, and WHAT was incomplete in the words of its run (its run-health message)
        $each = @($held | Sort-Object { $_.CollectionTime } | Select-Object -First 5 | ForEach-Object {
            $why = if ($_.PSObject.Properties['RunDetail'] -and [string]$_.RunDetail) { [string]$_.RunDetail } else { [string]$_.Reason }
            $when = if ($_.PSObject.Properties['CollectionTime'] -and $_.CollectionTime) { [string]::Format([Globalization.CultureInfo]::InvariantCulture, 'of {0:yyyy-MM-dd HH:mm} UTC ', [datetime]$_.CollectionTime) } else { '' }
            [string]::Format([Globalization.CultureInfo]::InvariantCulture, 'the collection {0}({1:N0} findings): {2}', $when, [long]$_.Rows, $why) })
        $calls.Add(@{ GuardId = 'datasync.collection.held'; Outcome = 'held'; HeldCount = $held.Count
               Detail = ('{0} collection(s) were not loaded because the Risk Analysis run that produced them did not finish completely -- {1}' -f $held.Count, ($each -join '; '))
               Values = @(@{ Name = 'collectionsHeld'; Label = 'Collections held'; Measured = $held.Count }, @{ Name = 'rowsHeld'; Label = 'Findings in them'; Measured = $rows }) })
    }
    # #294: snapshots that are never loaded -- rows without their finding id, or without a CollectionTime at all
    $refused = @(); if ($Result.PSObject.Properties['Refused']) { $refused = @($Result.Refused | Where-Object { $_ }) }
    $untimed = @(); if ($Result.PSObject.Properties['Untimed']) { $untimed = @($Result.Untimed | Where-Object { $_ }) }
    if ($refused.Count -or $untimed.Count) {
        $rRows = 0L; foreach ($r in $refused) { $rRows += [long]$r.Rows }
        $uRows = 0L; foreach ($u in $untimed) { $uRows += [long]$u.Rows }
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($r in $refused) { $parts.Add(('{0:yyyy-MM-dd HH:mm} UTC: {1}' -f $r.CollectionTime, [string]$r.Reason)) }
        if ($untimed.Count) {
            $hours = (@($untimed | Sort-Object { $_.Hour } | ForEach-Object { '{0:yyyy-MM-dd HH:00} UTC' -f ([datetime]$_.Hour) }) | Select-Object -First 5) -join ', '
            $parts.Add([string]::Format([Globalization.CultureInfo]::InvariantCulture, 'the Risk Analysis run around {0} wrote {1:N0} row(s) without their collection time (their key columns were lost on the way into Log Analytics), so they belong to no collection and cannot be placed in a day', $hours, $uRows))
        }
        # #414: ONE event per distinct cause -- each refused collection and each hour of rows without a collection time is a
        # cause; a sync that sees only causes reported before reports nothing (they stay until they age out of the window)
        $causeKeys = @(@($refused | ForEach-Object { Get-SIGuardCauseKey -Text ([string]::Format([Globalization.CultureInfo]::InvariantCulture, 'refused|{0:yyyy-MM-ddTHH:mm:ss}', [datetime]$_.CollectionTime)) }) +
                       @($untimed | ForEach-Object { Get-SIGuardCauseKey -Text ([string]::Format([Globalization.CultureInfo]::InvariantCulture, 'untimed|{0:yyyy-MM-ddTHH}', [datetime]$_.Hour)) }))
        $calls.Add(@{ GuardId = 'datasync.collection.refused'; Outcome = 'refused'; HeldCount = ($refused.Count + $untimed.Count); CauseKeys = $causeKeys
               Detail = ('Risk Analysis data that is not loaded as a day: {0}' -f ((@($parts) | Select-Object -First 5) -join '; '))
               Values = @(@{ Name = 'collectionsRefused'; Label = 'Collections refused'; Measured = $refused.Count }, @{ Name = 'rowsRefused'; Label = 'Findings in them'; Measured = $rRows },
                          @{ Name = 'rowsWithoutTime'; Label = 'Rows without a collection time'; Measured = $uRows }) })
    }
    # #428: an asset kind the findings imply that arrived as 0 CIs, or CIs with findings and no kind (the 2026-10-07
    # "azure (0)" class) -- one event per distinct cause (collection + kind), so a repeat sync reports nothing new
    $kc = @(); if ($Result.PSObject.Properties['Loaded']) { $kc = @($Result.Loaded | Where-Object { $_ -and $_.PSObject.Properties['KindCoverage'] -and $null -ne $_.KindCoverage }) }
    $kParts = New-Object System.Collections.Generic.List[string]; $kKeys = New-Object System.Collections.Generic.List[string]
    $kDropped = 0; $kKindless = 0L
    foreach ($l in $kc) {
        $c = $l.KindCoverage; $when = [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0:yyyy-MM-ddTHH:mm:ss}', [datetime]$l.CollectionTime)
        foreach ($k in @($c.Dropped)) {
            $kDropped++
            $kParts.Add([string]::Format([Globalization.CultureInfo]::InvariantCulture, 'the collection of {0:yyyy-MM-dd HH:mm} UTC has findings on {1:N0} {2} asset(s) but 0 CIs of kind {2}', [datetime]$l.CollectionTime, [long]$c.Implied[$k], $k))
            $kKeys.Add((Get-SIGuardCauseKey -Text ('kind|{0}|{1}' -f $when, $k)))
        }
        if ([long]$c.Kindless -gt 0) {
            $kKindless += [long]$c.Kindless
            $kParts.Add([string]::Format([Globalization.CultureInfo]::InvariantCulture, 'the collection of {0:yyyy-MM-dd HH:mm} UTC has {1:N0} asset(s) with findings and no asset kind', [datetime]$l.CollectionTime, [long]$c.Kindless))
            $kKeys.Add((Get-SIGuardCauseKey -Text ('kindless|{0}' -f $when)))
        }
    }
    if ($kParts.Count) {
        $calls.Add(@{ GuardId = 'datasync.asset.kind-dropped'; Outcome = 'warning'; HeldCount = $kParts.Count; CauseKeys = $kKeys.ToArray()
               Detail = ('Findings the web app''s asset kind filter cannot show: {0}' -f ((@($kParts) | Select-Object -First 5) -join '; '))
               Values = @(@{ Name = 'kindsDropped'; Label = 'Asset kinds stored as 0'; Measured = $kDropped }, @{ Name = 'assetsWithoutKind'; Label = 'Assets with no kind'; Measured = $kKindless }) })
    }
    $calls.ToArray()
}

function Get-SIGuardCallsForRowCount {
    <# Risk Analysis: the row-count guard's findings (LARGE-DROP / WENT-TO-ZERO / MISSING) -> ONE event per run, listing
       every report. #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Findings, [string]$Template)
    # HANDED-OFF is informational: the findings moved to the receiving report (the guard itself says "moved, not lost").
    # Measured in the 2.2 -> 3.0 upgrade test: it raised this warning on every upgraded install's first night.
    # BELOW-THRESHOLD (#407) is not a loss either: a one-row threshold report whose count fell to or below its threshold
    # (the run log carries it as a warning). Ring 1, 2026-10-06: it made the run partial after a PIM activation ended.
    $f = @($Findings | Where-Object { $_ -and [string]$_.Kind -ne 'HANDED-OFF' -and [string]$_.Kind -ne 'BELOW-THRESHOLD' })
    if (-not $f.Count) { return @() }
    $words = @{ 'LARGE-DROP' = 'far fewer findings'; 'WENT-TO-ZERO' = 'no findings any more'; 'MISSING' = 'no result at all'
                'HANDOFF-LOST' = 'left to a report that produced no result -- those findings are in no report' }
    $list = @($f | ForEach-Object { $k = [string]$_.Kind; $w = if ($words.ContainsKey($k)) { $words[$k] } else { $k.ToLowerInvariant() }; '{0}: {1} -> {2} ({3})' -f $_.Report, $_.Previous, $(if ($null -eq $_.Current) { 'none' } else { $_.Current }), $w })
    $prev = 0L; $curr = 0L; foreach ($x in $f) { $prev += [long]$x.Previous; if ($null -ne $x.Current) { $curr += [long]$x.Current } }
    @(@{ GuardId = 'ra.output.row-drop'; Outcome = 'warning'; Subject = $Template
           Detail = ('{0} report(s) produced far fewer findings than the previous run: {1}' -f $f.Count, ((@($list) | Select-Object -First 20) -join '; '))
           Values = @(@{ Name = 'reports'; Label = 'Reports affected'; Measured = $f.Count }, @{ Name = 'findingsBefore'; Label = 'Findings in them before'; Measured = $prev }, @{ Name = 'findingsNow'; Label = 'Findings in them now'; Measured = $curr }) })
}

function Get-SIGuardCallsForColumnFill {
    <# Risk Analysis: the column-fill guard's findings (COLUMN-EMPTIED / COLUMN-VANISHED) -> ONE event per run, listing
       every report and column. #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Findings, [string]$Template)
    $f = @($Findings | Where-Object { $_ })
    if (-not $f.Count) { return @() }
    $list = @($f | ForEach-Object { '{0}.{1} ({2})' -f $_.Report, $_.Column, $(if ([string]$_.Kind -eq 'COLUMN-VANISHED') { 'gone' } else { 'empty' }) })
    @(@{ GuardId = 'ra.output.column-emptied'; Outcome = 'warning'; Subject = $Template
           Detail = ('{0} column(s) lost their content since the previous run: {1}' -f $f.Count, ((@($list) | Select-Object -First 20) -join '; '))
           Values = @(@{ Name = 'columns'; Label = 'Columns affected'; Measured = $f.Count }, @{ Name = 'reports'; Label = 'Reports affected'; Measured = @($f | ForEach-Object { $_.Report } | Select-Object -Unique).Count }) })
}

function Get-SIGuardCallsForFlow {
    <# The daily job flow, for a run THIS wake-up started or resumed: a scheduled start that was missed (catch-up, held),
       dependent steps skipped after a failure (skipped), interrupted steps (held).
       NOT a trip: a wake-up while the flow is running (Busy -- the runner wakes every 5 minutes, so that is every wake-up
       of a long run), and not due (Wait / Done).
       NOT a trip either (owner 2026-10-12, "Quiet when runs are just long"): a start that was owed ONLY because the
       previous run was still going at its scheduled time and that was made as soon as that run ended -- every run of an
       install whose pipeline takes longer than its schedule's interval. The run's own note says so (the runner writes
       it at the start: Get-SIJobFlowLateStart, 'started late because the previous run was still going'), so it is in the
       run's record and on the pipeline page, and no guard event is raised.
       STILL a trip: a scheduled start missed for any other reason (the note says 'scheduled start was missed': no run
       was going and it started late all the same, or it did not start when the previous run ended), and a catch-up
       whose note does not say why (a record written before the note said it). #>
    param([Parameter(Mandatory)]$Result)
    $calls = New-Object System.Collections.Generic.List[object]
    if ($Result.PSObject.Properties['Outcome'] -and [string]$Result.Outcome -in @('Busy', 'Wait', 'Done')) { return @() }
    # #700: a run CANCELLED on purpose (a person, the updater) is not a trip -- the cancel is on the audit trail with who and why
    if ($Result.PSObject.Properties['State'] -and [string]$Result.State -eq 'Cancelled') { return @() }
    $flowNote =if ($Result.PSObject.Properties['Note'] -and $Result.Note) { [string]$Result.Note } else { '' }
    $onlyLongRun = $flowNote -match 'started late because the previous run'
    $missedStart = $flowNote -match 'scheduled start was missed'
    if ($missedStart -or ([string]$Result.Trigger -eq 'catch-up' -and -not $onlyLongRun)) {
        $calls.Add(@{ GuardId = 'flow.run.catch-up'; Outcome = 'held'; Detail = $(if ($flowNote) { $flowNote } else { 'A scheduled start was held until the previous flow run finished.' }) })
    }
    $steps = @($Result.Steps)
    # A step STOPPED FROM OUTSIDE (an update, a roll or a person stopped its execution: Interrupted, class 'stopped') is on
    # purpose, like a cancelled run -- not a trip, and neither are the jobs skipped because the flow stopped there (owner
    # 2026-10-23: no run may alert for nothing). Any other interruption or skip is still a trip.
    $stoppedOnPurpose = @($steps | Where-Object { [string]$_.State -eq 'Interrupted' -and [string]$_.ErrorClass -eq 'stopped' }).Count -gt 0
    # #306: 'stage-blocked' = a stage that did not start because the stage before it did not succeed
    $skipped = @($steps | Where-Object { [string]$_.State -eq 'Skipped' -and [string]$_.ErrorClass -in @('needs-failed', 'flow-stopped', 'stage-blocked') -and -not ($stoppedOnPurpose -and [string]$_.ErrorClass -eq 'flow-stopped') })
    # #532 THROTTLE-IS-NORMAL (framework §12.18): steps skipped because a step Microsoft THROTTLED did not complete are not a
    # trip -- throttling is normal and is never mailed; the engine raises the one "stuck" alert when it cannot catch up.
    # Every failure of the run throttled = none of its skips is mailed; else a skip that needed a throttled step is left out.
    $throttledJobs = @($steps | Where-Object { [string]$_.State -eq 'Failed' -and [string]$_.ErrorClass -eq 'throttled' } | ForEach-Object { [string]$_.Job })
    if ($throttledJobs.Count) {
        $realFailures = @($steps | Where-Object { [string]$_.State -in @('Failed', 'TimedOut', 'Interrupted') -and -not ([string]$_.State -eq 'Failed' -and [string]$_.ErrorClass -eq 'throttled') })
        if ($realFailures.Count -eq 0) { $skipped = @() }
        else {
            $skipped = @($skipped | Where-Object {
                $s = $_; $byThrottle = $false
                if ([string]$s.ErrorClass -eq 'needs-failed') { foreach ($j in $throttledJobs) { if ([string]$s.Error -like ('needs {0},*' -f $j)) { $byThrottle = $true; break } } }
                -not $byThrottle
            })
        }
    }
    if ($skipped.Count) {
        $calls.Add(@{ GuardId = 'flow.step.skipped'; Outcome = 'skipped'; HeldCount = $skipped.Count
                      Detail = ('{0} job(s) were skipped: {1}' -f $skipped.Count, ((@($skipped | ForEach-Object { '{0} ({1})' -f $_.Job, $_.Error })) -join '; '))
                      Values = @(@{ Name = 'stepsSkipped'; Label = 'Jobs skipped'; Measured = $skipped.Count }, @{ Name = 'steps'; Label = 'Jobs in the flow'; Measured = $steps.Count }) })
    }
    # working rule 4: a step whose container never ran the engine was started again; it did not start that time either.
    # 'halted' when steps that need it were skipped (or the flow stopped there), else 'skipped' (only this step is missing).
    $never = @($steps | Where-Object { [string]$_.State -eq 'Failed' -and [string]$_.ErrorClass -eq 'never-started' })
    if ($never.Count) {
        $jobs = @($never | ForEach-Object { [string]$_.Job })
        $after = New-Object System.Collections.Generic.List[object]
        foreach ($s in $steps) {
            if ([string]$s.State -ne 'Skipped') { continue }
            if ([string]$s.ErrorClass -eq 'flow-stopped') { $after.Add($s); continue }
            if ([string]$s.ErrorClass -ne 'needs-failed') { continue }
            foreach ($j in $jobs) { if ([string]$s.Error -like ('needs {0},*' -f $j)) { $after.Add($s); break } }
        }
        $calls.Add(@{ GuardId = 'flow.step.start-failed'; Outcome = $(if ($after.Count) { 'halted' } else { 'skipped' }); HeldCount = $never.Count; Subject = ($jobs -join ', ')
                      Detail = ('{0} job(s) did not start, also not when started again: {1}{2}' -f $never.Count, ((@($never | ForEach-Object { '{0} ({1} attempts)' -f $_.Job, $(if ($_.PSObject.Properties['Attempts']) { [int]$_.Attempts } else { 1 }) })) -join '; '), $(if ($after.Count) { ('; {0} job(s) after it were skipped' -f $after.Count) } else { '' }))
                      Values = @(@{ Name = 'stepsNotStarted'; Label = 'Jobs that did not start'; Measured = $never.Count }, @{ Name = 'stepsSkipped'; Label = 'Jobs skipped because of it'; Measured = $after.Count }) })
    }
    $int = @($steps | Where-Object { [string]$_.State -eq 'Interrupted' -and [string]$_.ErrorClass -ne 'stopped' })
    if ($int.Count) {
        $calls.Add(@{ GuardId = 'flow.step.interrupted'; Outcome = 'held'; HeldCount = $int.Count
                      Detail = ('{0} job(s) were interrupted and not started again: {1}' -f $int.Count, ((@($int | ForEach-Object { [string]$_.Job })) -join ', '))
                      Values = @(@{ Name = 'stepsInterrupted'; Label = 'Jobs interrupted'; Measured = $int.Count }) })
    }
    $calls.ToArray()
}

function Get-SIGuardHealth {
    <# How many guard events this process recorded, and how many could not be (with the last reason). #>
    if ($null -eq $global:SI_GuardHealth) { $global:SI_GuardHealth = @{ Events = 0; Failed = 0; LastError = '' } }
    [pscustomobject]@{ Events = [int]$global:SI_GuardHealth.Events; Failed = [int]$global:SI_GuardHealth.Failed; LastError = [string]$global:SI_GuardHealth.LastError }
}
