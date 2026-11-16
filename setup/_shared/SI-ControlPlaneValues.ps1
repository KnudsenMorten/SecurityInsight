#Requires -Version 5.1
<#
    SECURITYINSIGHT -- CONTROL-PLANE VALUES: what Invardia sets on the install's updater job, written into the Pro store by
    the update ITSELF (SI #1270; Invardia ruling 2026-11-15).

    THE RULE: install state is NEVER changed by an ops SQL write -- not even behind a just-in-time setup grant; the Support
    app's SQL is read-only. A change goes as a CONTROL-PLANE value: an environment variable on the install's updater job
    (caj-si-updater). SecurityInsight's own updater copies it into the store on its next run, audited (cfg.ChangeLog, which
    the trail's trigger copies into cfg.AuditEvent) and READ BACK. The env stays on the job: every later run finds the value
    already there and writes nothing (idempotent).

      SI_UPDATER_STATE_IDENTITYMOVEMODE  plan | apply | off  -> cfg.InstallState 'IdentityMoveMode' (the identity move's
                                         per-install approval: setup\_shared\SI-IdentityMove.ps1 Set-SIIdentityMoveMode,
                                         read back). The update writes it BEFORE its identity-names step in the same run.
      SI_UPDATER_SETTINGS                a compact JSON object { "<SettingName>": <value>, ... } for the settings on the
                                         ALLOW-LIST below ONLY (scope 'solution'). Each value is checked by the catalog
                                         (config\settings.catalog.locked.json: its type, limits, choices) and written by
                                         SI's ONE setting writer (engine\pro-settings\SI-ProSettingWrite.ps1
                                         Set-SIProSetting: the row and its cfg.ChangeLog entry in one transaction), then
                                         read back.
      SI_UPDATER_CONTROLPLANE_REASON     optional: the reason recorded with each change (else a standard one).

    ChangedBy = 'the update (control-plane value)'. NEVER a secret through this path: a setting the catalog marks secret is
    refused (a secret lives in Key Vault). Anything not on the allow-list, a value of the wrong type and JSON that does
    not parse are REFUSED, each said in one warning line -- a refusal is never a failed update. Each applied value is said
    in one line. PS 5.1 and 7; no module.
#>

function Get-SIControlPlaneSettingAllowList {
    <# PURE. THE settings an operator may set through SI_UPDATER_SETTINGS on the updater job. A constant: a setting is added
       here in code (with its reason in SI REQUIREMENTS #1270), never by configuration. #>
    @('OpenAI_endpoint', 'OpenAI_deployment', 'OpenAI_apiVersion', 'SI_EnableAI')
}

function Get-SIControlPlaneNames {
    <# PURE. The env names and the ChangedBy text of this path. #>
    [pscustomobject]@{
        IdentityMoveMode = 'SI_UPDATER_STATE_IDENTITYMOVEMODE'
        Settings         = 'SI_UPDATER_SETTINGS'
        Reason           = 'SI_UPDATER_CONTROLPLANE_REASON'
        ChangedBy        = 'the update (control-plane value)'
        Scope            = 'solution'
    }
}

function ConvertFrom-SIControlPlaneIdentityMode {
    <# PURE. The env's value -> @{ Mode ('' = not set: nothing to do | plan | apply | off); Refused (the warning, or '') }. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $v = "$Value".Trim().Trim('"').Trim()
    if (-not $v) { return [pscustomobject]@{ Mode = ''; Refused = '' } }
    $l = $v.ToLowerInvariant()
    if ($l -in 'plan', 'apply', 'off') { return [pscustomobject]@{ Mode = $l; Refused = '' } }
    $n = Get-SIControlPlaneNames
    [pscustomobject]@{ Mode = ''; Refused = ("{0}='{1}' is not plan, apply or off -- the identity move's mode is left as it is" -f $n.IdentityMoveMode, $(if ($v.Length -gt 40) { $v.Substring(0, 40) + '...' } else { $v })) }
}

function ConvertFrom-SIControlPlaneJson {
    <# PURE. ConvertFrom-Json that keeps a date-like text as TEXT (PowerShell 7 turns "2024-10-21" -- an Azure OpenAI API
       version -- into a DateTime unless -DateKind String; Windows PowerShell 5.1 never converts). Throws on bad JSON. #>
    param([Parameter(Mandatory)][string]$Text)
    $p = @{ InputObject = $Text; ErrorAction = 'Stop' }
    if ((Get-Command -Name ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $p['DateKind'] = 'String' }
    ConvertFrom-Json @p
}

function ConvertFrom-SIControlPlaneSettings {
    <#
        PURE. SI_UPDATER_SETTINGS -> @{ Items (@{ Name; Value; Json } per accepted setting, the catalog's own name); Refused
        (one line per refusal) }. -Catalog: the settings catalog's entries (Get-SISettingsCatalog). Refused: JSON that does
        not parse or is not ONE object (then nothing from it is applied), a secret, a setting not on the allow-list, one the
        catalog does not know, no value (null), a value of the wrong type (Test-SISettingValue's reason).
    #>
    param([AllowNull()][AllowEmptyString()][string]$Json, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Catalog)
    $n = Get-SIControlPlaneNames
    $items = New-Object System.Collections.Generic.List[object]
    $refused = New-Object System.Collections.Generic.List[string]
    $out = { [pscustomobject]@{ Items = $items.ToArray(); Refused = $refused.ToArray() } }
    $text = "$Json".Trim()
    if (-not $text) { return (& $out) }
    # ONE object: PowerShell 7 unrolls a one-item JSON array into its item, so the text itself must be an object
    if (-not $text.StartsWith('{')) { $refused.Add(('{0} must be ONE JSON object {{ "<SettingName>": <value> }} -- nothing from it is applied' -f $n.Settings)); return (& $out) }
    $obj = $null
    try { $obj = ConvertFrom-SIControlPlaneJson -Text $text } catch { $obj = $null; $refused.Add(('{0} is not valid JSON ({1}) -- nothing from it is applied' -f $n.Settings, (([string]$_.Exception.Message) -split "`n")[0].Trim())); return (& $out) }
    if ($null -eq $obj -or $obj -isnot [System.Management.Automation.PSCustomObject]) { $refused.Add(('{0} must be ONE JSON object {{ "<SettingName>": <value> }} -- nothing from it is applied' -f $n.Settings)); return (& $out) }
    $allow = @(Get-SIControlPlaneSettingAllowList)
    $byName = @{}; foreach ($s in $Catalog) { if ($s -and $s.name) { $byName[([string]$s.name).ToLowerInvariant()] = $s } }
    foreach ($p in @($obj.PSObject.Properties)) {
        $name = [string]$p.Name
        $s = $byName[$name.ToLowerInvariant()]
        # a secret first: whatever list it is on, a secret never travels in a job's environment
        if ($s -and $s.secret) { $refused.Add(('{0}: {1} is a secret -- never set this way (it lives in the install''s Key Vault); not applied' -f $n.Settings, [string]$s.name)); continue }
        $allowed = @($allow | Where-Object { $_ -ieq $name })
        if (-not $allowed.Count) { $refused.Add(('{0}: {1} may not be set this way (allowed: {2}); not applied' -f $n.Settings, $name, ($allow -join ', '))); continue }
        if (-not $s) { $refused.Add(('{0}: {1} is not a known setting of this release; not applied' -f $n.Settings, $name)); continue }
        $canon = [string]$s.name
        $value = $p.Value
        if ($null -eq $value) { $refused.Add(('{0}: {1} has no value (a reset is not done this way); not applied' -f $n.Settings, $canon)); continue }
        # the same lenient reading the Settings page applies before its type check: "true" / "false" for a switch, a
        # whole number as text for an int, a number as an invariant double
        switch ([string]$s.type) {
            'bool'   { if ($value -is [string] -and $value.Trim() -match '^(?i)(true|false)$') { $value = ($value.Trim() -ieq 'true') } }
            'int'    { if ($value -is [string]) { $i = 0L; if ([long]::TryParse($value.Trim(), [ref]$i)) { $value = [int]$i } } elseif ($value -is [long] -and $value -le [int]::MaxValue -and $value -ge [int]::MinValue) { $value = [int]$value } }
            'number' { if (Get-Command -Name ConvertTo-SISettingNumber -ErrorAction SilentlyContinue) { $d = ConvertTo-SISettingNumber $value; if ($null -ne $d) { $value = $d } } }
        }
        $why = Test-SISettingValue -Setting $s -Value $value
        if ($why) { $refused.Add(('{0}: {1} {2}; not applied' -f $n.Settings, $canon, $why)); continue }
        $items.Add([pscustomobject]@{ Name = $canon; Value = $value; Json = (ConvertTo-SIJsonText $value) })
    }
    & $out
}

function ConvertTo-SIControlPlaneJsonKey {
    <# PURE. A stored ValueJson in the writer's own form (ConvertTo-SIJsonText of its parsed value) -- so "x" and the same
       value written with other spacing compare equal. $null / unparsable = itself. #>
    param([AllowNull()][AllowEmptyString()][string]$ValueJson)
    if ($null -eq $ValueJson) { return $null }
    try { ConvertTo-SIJsonText (ConvertFrom-SIControlPlaneJson -Text $ValueJson) } catch { $ValueJson }
}

function Read-SIControlPlaneSetting {
    <# One setting's stored ValueJson (scope 'solution'), or $null when there is no row. Throws on a SQL error. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Name, [string]$Scope = 'solution')
    $rows = @(& $Store.Invoke "SET NOCOUNT ON; SELECT ValueJson FROM cfg.Setting WHERE Name = @Name AND Scope = @Scope;" ([ordered]@{ Name = $Name; Scope = $Scope }) 'reader' | ForEach-Object { $_ })
    $r = $rows | Where-Object { $_ } | Select-Object -First 1
    if (-not $r) { return $null }
    $v = if ($r -is [System.Collections.IDictionary]) { $r['ValueJson'] } else { $r.ValueJson }
    if ($null -eq $v -or $v -is [System.DBNull]) { $null } else { [string]$v }
}

function Invoke-SIControlPlaneIdentityMode {
    <#
        SI_UPDATER_STATE_IDENTITYMOVEMODE -> cfg.InstallState 'IdentityMoveMode' through the identity move's OWN writer
        (Set-SIIdentityMoveMode, read back), over -Store. Equal to the mode in force = nothing written. A change also gets
        its cfg.ChangeLog row (scope 'install-state'; the trail's trigger copies it). -IdentityMoveLib: the file
        (setup\_shared\SI-IdentityMove.ps1). Returns @{ Action (none | already | applied | refused | failed); Line }.
    #>
    param([Parameter(Mandatory)]$Store, [AllowEmptyString()][string]$Value, [Parameter(Mandatory)][string]$IdentityMoveLib, [string]$Reason)
    $n = Get-SIControlPlaneNames
    $m = ConvertFrom-SIControlPlaneIdentityMode -Value $Value
    if ($m.Refused) { return [pscustomobject]@{ Action = 'refused'; Line = 'WARNING: control-plane value: ' + $m.Refused } }
    if (-not $m.Mode) { return [pscustomobject]@{ Action = 'none'; Line = '' } }
    if (-not (Test-Path -LiteralPath $IdentityMoveLib)) { return [pscustomobject]@{ Action = 'failed'; Line = ('WARNING: control-plane value: {0}={1} not applied -- this release carries no identity move' -f $n.IdentityMoveMode, $m.Mode) } }
    . $IdentityMoveLib
    $siCpStore = $Store
    try {
        # the identity move's SQL seam over the Pro store: the update's own identity, never the Support app
        Set-SIIdentityMoveIo -Sql { param([string]$Server, [string]$Database, [string]$Query, [bool]$Change)
            $rows = & $siCpStore.Invoke $Query $null $(if ($Change) { 'nonquery' } else { 'reader' })
            foreach ($h in @($rows)) { if ($h) { [pscustomobject]$h } } }
        $script:SIMove.ChangedBy = $n.ChangedBy
        $ctx = @{ SqlServer = 'pro'; StateDatabase = 'pro'; Reason = $Reason }
        $cur = Read-SIIdentityMoveMode -Ctx $ctx
        if ($cur -eq $m.Mode) { return [pscustomobject]@{ Action = 'already'; Line = ('control-plane value: the identity move''s mode is already {0} ({1}) -- nothing written' -f $m.Mode, $n.IdentityMoveMode) } }
        if (-not (Set-SIIdentityMoveMode -Ctx $ctx -Mode $m.Mode)) { return [pscustomobject]@{ Action = 'failed'; Line = ('WARNING: control-plane value: {0}={1} was written but does not read back -- the next update tries again' -f $n.IdentityMoveMode, $m.Mode) } }
        $log = ''
        try {
            $null = & $Store.Invoke "SET NOCOUNT ON; INSERT cfg.ChangeLog (Name, Scope, Action, OldValue, NewValue, ChangedBy, Reason) VALUES (@Name, @Scope, N'Set', @Old, @New, @By, @Reason);" ([ordered]@{ Name = 'IdentityMoveMode'; Scope = 'install-state'; Old = $cur; New = $m.Mode; By = $n.ChangedBy; Reason = $Reason }) 'nonquery'
        } catch { $log = (' (its change-log row could not be written: {0})' -f (([string]$_.Exception.Message) -split "`n")[0]) }
        [pscustomobject]@{ Action = 'applied'; Line = ('control-plane value: the identity move''s mode {0} -> {1} (from {2}; read back){3}' -f $cur, $m.Mode, $n.IdentityMoveMode, $log) }
    } catch {
        [pscustomobject]@{ Action = 'failed'; Line = ('WARNING: control-plane value: {0}={1} not applied ({2}) -- the next update tries again' -f $n.IdentityMoveMode, $m.Mode, (([string]$_.Exception.Message) -split "`n")[0]) }
    } finally { if (Get-Command -Name Set-SIIdentityMoveIo -ErrorAction SilentlyContinue) { Set-SIIdentityMoveIo } }
}

function Invoke-SIControlPlaneSettings {
    <#
        SI_UPDATER_SETTINGS -> each accepted setting written by Set-SIProSetting (scope 'solution', ChangedBy 'the update
        (control-plane value)', -Reason) where the stored value differs, then READ BACK. Returns @{ Applied; Already;
        Refused; Failed; Lines }. Needs Set-SIProSetting / Test-SISettingValue / ConvertTo-SIJsonText loaded.
    #>
    param([Parameter(Mandatory)]$Store, [AllowEmptyString()][string]$Json, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Catalog, [string]$Reason)
    $n = Get-SIControlPlaneNames
    $lines = New-Object System.Collections.Generic.List[string]
    $res = [pscustomobject]@{ Applied = @(); Already = @(); Refused = @(); Failed = @(); Lines = @() }
    $plan = ConvertFrom-SIControlPlaneSettings -Json $Json -Catalog $Catalog
    $res.Refused = @($plan.Refused)
    foreach ($r in @($plan.Refused)) { $lines.Add('WARNING: control-plane value: ' + $r) }
    $applied = New-Object System.Collections.Generic.List[string]; $already = New-Object System.Collections.Generic.List[string]; $failed = New-Object System.Collections.Generic.List[string]
    foreach ($it in @($plan.Items)) {
        try {
            $before = Read-SIControlPlaneSetting -Store $Store -Name $it.Name -Scope $n.Scope
            if ($null -ne $before -and (ConvertTo-SIControlPlaneJsonKey $before) -ceq $it.Json) {
                $already.Add($it.Name); $lines.Add(('control-plane value: {0} is already {1} -- nothing written' -f $it.Name, $it.Json)); continue
            }
            $null = Set-SIProSetting -Store $Store -Catalog $Catalog -Name $it.Name -Scope $n.Scope -Action Set -Value $it.Value -ChangedBy $n.ChangedBy -Reason $Reason
            $back = Read-SIControlPlaneSetting -Store $Store -Name $it.Name -Scope $n.Scope
            if ($null -ne $back -and (ConvertTo-SIControlPlaneJsonKey $back) -ceq $it.Json) {
                $applied.Add($it.Name)
                $lines.Add(('control-plane value: {0} {1} -> {2} (from {3}; read back, in the change log)' -f $it.Name, $(if ($null -eq $before) { '(not set)' } else { $before }), $it.Json, $n.Settings))
            } else {
                $failed.Add($it.Name); $lines.Add(('WARNING: control-plane value: {0} was written but does not read back as {1} -- the next update tries again' -f $it.Name, $it.Json))
            }
        } catch {
            $failed.Add($it.Name); $lines.Add(('WARNING: control-plane value: {0} not applied ({1}) -- the next update tries again' -f $it.Name, (([string]$_.Exception.Message) -split "`n")[0]))
        }
    }
    $res.Applied = $applied.ToArray(); $res.Already = $already.ToArray(); $res.Failed = $failed.ToArray(); $res.Lines = $lines.ToArray()
    $res
}

function Invoke-SIControlPlaneValues {
    <#
        THE STEP: the identity move's mode first, then the settings. -Env: the job's environment (a hashtable; a name not in
        it is read from the process). -SIRoot: the SecurityInsight folder the update carries (/si in the updater image).
        -UpdaterJob: the job's name, for the standard reason. Returns @{ Mode (the identity-mode result); Settings; Lines }.
        NEVER throws; never fails the update.
    #>
    param([hashtable]$Env = @{}, [Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$SIRoot, [string]$UpdaterJob = 'caj-si-updater',
          [object[]]$Catalog, [scriptblock]$Log = { param($m) Write-Host $m })
    $n = Get-SIControlPlaneNames
    $out = [pscustomobject]@{ Mode = $null; Settings = $null; Lines = @() }
    $siCpStepLines = New-Object System.Collections.Generic.List[string]
    $say = { param($m) if ($m) { $siCpStepLines.Add([string]$m); try { $null = & $Log ([string]$m) } catch { } } }
    try {
        $read = { param($k) if ($Env.ContainsKey($k)) { "$($Env[$k])".Trim() } else { "$([Environment]::GetEnvironmentVariable($k))".Trim() } }
        $modeVal = & $read $n.IdentityMoveMode
        $setVal = & $read $n.Settings
        if (-not $modeVal -and -not $setVal) { $out.Lines = $siCpStepLines.ToArray(); return $out }
        $why = & $read $n.Reason
        $reason = if ($why) { $why } else { 'a control-plane value on the updater job {0}' -f $UpdaterJob }
        if ($reason.Length -gt 400) { $reason = $reason.Substring(0, 400) }
        if ($modeVal) {
            $out.Mode = Invoke-SIControlPlaneIdentityMode -Store $Store -Value $modeVal -IdentityMoveLib ([IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-IdentityMove.ps1')) -Reason $reason
            & $say $out.Mode.Line
        }
        if ($setVal) {
            if (-not (Get-Command -Name Set-SIProSetting -ErrorAction SilentlyContinue)) {
                $w = [IO.Path]::Combine($SIRoot, 'engine', 'pro-settings', 'SI-ProSettingWrite.ps1')
                if (-not (Test-Path -LiteralPath $w)) { & $say ('WARNING: control-plane value: {0} not applied -- this release carries no setting writer' -f $n.Settings); $out.Lines = $siCpStepLines.ToArray(); return $out }
                . $w
            }
            if ($null -eq $Catalog) { $Catalog = @(Get-SISettingsCatalog -SIRoot $SIRoot) }
            $out.Settings = Invoke-SIControlPlaneSettings -Store $Store -Json $setVal -Catalog $Catalog -Reason $reason
            foreach ($l in @($out.Settings.Lines)) { & $say $l }
        }
    } catch { & $say ('WARNING: control-plane values: not applied ({0}) -- the next update tries again' -f (([string]$_.Exception.Message) -split "`n")[0]) }
    $out.Lines = $siCpStepLines.ToArray()
    $out
}
