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
      SI_UPDATER_OUTPUTS                 a compact JSON object switching what an OUTPUT sends (owner 2026-11-16: the new
                                         ServiceNow columns / outputs are switched on per install through the updater):
                                           { "<output id>": { "on": [ "<column>", ... ], "off": [ "<column>", ... ],
                                                              "output": "on" | "off" }, ... }
                                         every part optional. A <column> is the column's target (u_si_category) or the
                                         field it reads (si_category). ALLOW-LIST, derived from what the release ships:
                                         a column may be switched only when data-model\outputs\<output>.locked.json ships
                                         it switched OFF ("off": true) -- every other column is always sent and is changed
                                         in the web app; an output only when config\data-out.locked.json lists it for Pro
                                         and not 'fixed'. A column is written through the web app's OWN statement
                                         (engine\pro-settings\SI-OutputColumnWrite.ps1: the cfg.ItemOverride row an
                                         Admin's change on Connectors > Fields sent writes -- on = the shipped column
                                         without "off" as an override, off = back to the shipped column); an output through
                                         Set-SIProSetting on SI_DataOut_Outputs, computed as the web app's output switch
                                         computes it (every other output keeps what it does now). Each read back.
                                         ONCE PER VALUE: the applied value's hash is kept (cfg.InstallState
                                         'ControlPlaneOutputs'); the same value on a later update writes nothing, so a
                                         column an Admin switches off in the web app stays off. "off" removes ONLY a column
                                         row the update itself wrote (UpdatedBy = the update) -- never an Admin's own row.
      SI_UPDATER_REPORTS                 a compact JSON object switching shipped Risk Analysis reports off or on again (owner
                                         2026-11-19: a report whose source the install has no licence for is switched off
                                         through the updater): { "<ReportName>": "off" | "on", ... }. ALLOW-LIST, derived
                                         from what the release ships: a report named in risk-analysis-detection\
                                         RiskAnalysis_Queries_Locked.yaml and not required by SecurityInsight (config\
                                         template-mandatory.locked.json). Written through the web app's OWN item statement
                                         (ItemOverrideRepository.WriteSql: the cfg.ItemOverride row of Kind 'rareport', key
                                         'report/<name>' that an Admin's "Report it" off writes -- State 'disable'), with
                                         its change-log row, and READ BACK. "on" removes ONLY a 'disable' row the update
                                         itself wrote -- an Admin's own row is kept. Needs a usable reason (as the outputs).
                                         ONCE PER VALUE (cfg.InstallState 'ControlPlaneReports').
      SI_UPDATER_LICENCE_PULL            request:pro-business | request:pro-enterprise | request:previous (Invardia
                                         2026-11-20): a licence request of that edition filed ONCE with the normal knock (no
                                         licence id is ever sent), then pulled on each update until Invardia delivers; or
                                         SI-License-Previous restored -- verified offline (a trusted signer, this tenant, valid
                                         today, the edition asked for), the one in force kept as SI-License-Previous, read
                                         back, audited, needs a usable reason, ONCE PER VALUE (cfg.InstallState
                                         'ControlPlaneLicencePullRequest' while it waits, 'ControlPlaneLicencePull' once
                                         done). Run by the updater's licence step, not
                                         here: container\updater\_shared\SI-UpdaterLicencePull.ps1.
      SI_UPDATER_SQL_LEAST_PRIVILEGE     plan | apply | off (framework section 12.23, Invardia 2026-11-20) -- NOT written by this
                                         step: the update hands it to the database setup job caj-si-dbinit, which does the
                                         work as the install's SQL admin (setup\_shared\SI-SqlLeastPrivilege.ps1; the
                                         updater's side: container\updater\_shared\SI-UpdaterDatabase.ps1
                                         Get-SIUpdaterSqlLpInput / Complete-SIUpdaterSqlLp). Needs a usable reason.
      SI_UPDATER_CONTROLPLANE_REASON     WHO asked and WHY -- Invardia sets it as '<person>: <why>'. REQUIRED for every
                                         change of what is sent (an output column on OR off, "output": on OR off): without a
                                         usable one (Test-SIControlPlaneReason: empty, one word, too short or a generic word
                                         like 'update', 'n/a', 'test', 'none', '-') those changes are refused in one warning
                                         line and nothing is written for them. Recorded in cfg.ChangeLog with each change; for the
                                         other values it stays optional.

    ChangedBy = 'the update (control-plane value)'. NEVER a secret through this path: a setting the catalog marks secret is
    refused (a secret lives in Key Vault). Anything not on the allow-list, a value of the wrong type and JSON that does
    not parse are REFUSED, each said in one warning line -- a refusal is never a failed update. Each applied value is said
    in one line. PS 5.1 and 7; no module.
#>

function Get-SIControlPlaneSettingAllowList {
    <# PURE. THE settings an operator may set through SI_UPDATER_SETTINGS on the updater job. A constant: a setting is added
       here in code (with its reason in SI REQUIREMENTS #1270), never by configuration. #>
    @('OpenAI_endpoint', 'OpenAI_deployment', 'OpenAI_apiVersion', 'SI_EnableAI') + @(Get-SIControlPlaneOffOnlyList)
}

function Get-SIControlPlaneOffOnlyList {
    <# PURE. #1304 (Invardia 2026-11-21): the AI switches the update may switch OFF through SI_UPDATER_SETTINGS -- never on.
       A value other than false is refused. Each is written false at EVERY scope where a stored row is not false (a
       per-engine switch lives at scope 'engine:<name>'); no row at all = already off (the default), nothing written. So
       the fleet is cleaned without an ops SQL write (#1270). A constant, changed in code only. #>
    @('BuildSummaryByAI', 'SI_EnableAI_azure', 'SI_EnableAI_endpoint', 'SI_EnableAI_identity', 'SI_PrivilegeTierClassifier_RunAI')
}

function Read-SIControlPlaneSettingRows {
    <# Every stored row of one setting, any scope: @{ Scope; ValueJson } each. Throws on a SQL error. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Name)
    foreach ($r in @(& $Store.Invoke "SET NOCOUNT ON; SELECT Scope, ValueJson FROM cfg.Setting WHERE Name = @Name;" ([ordered]@{ Name = $Name }) 'reader' | ForEach-Object { $_ })) {
        if (-not $r) { continue }
        $s = if ($r -is [System.Collections.IDictionary]) { $r['Scope'] } else { $r.Scope }
        $v = if ($r -is [System.Collections.IDictionary]) { $r['ValueJson'] } else { $r.ValueJson }
        [pscustomobject]@{ Scope = [string]$s; ValueJson = $(if ($null -eq $v -or $v -is [System.DBNull]) { $null } else { [string]$v }) }
    }
}

function Get-SIControlPlaneNames {
    <# PURE. The env names and the ChangedBy text of this path. #>
    [pscustomobject]@{
        IdentityMoveMode = 'SI_UPDATER_STATE_IDENTITYMOVEMODE'
        Settings         = 'SI_UPDATER_SETTINGS'
        Outputs          = 'SI_UPDATER_OUTPUTS'
        Reports          = 'SI_UPDATER_REPORTS'
        LicencePull      = 'SI_UPDATER_LICENCE_PULL'
        SqlLeastPrivilege = 'SI_UPDATER_SQL_LEAST_PRIVILEGE'
        OutputsSetting   = 'SI_DataOut_Outputs'
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
        # #1304: an AI switch may only be switched OFF this way
        $offOnly = @(@(Get-SIControlPlaneOffOnlyList) | Where-Object { $_ -ieq $canon }).Count -gt 0
        if ($offOnly -and -not ($value -is [bool] -and -not $value)) { $refused.Add(('{0}: {1} may only be switched off this way (false), never on; not applied' -f $n.Settings, $canon)); continue }
        $items.Add([pscustomobject]@{ Name = $canon; Value = $value; Json = (ConvertTo-SIJsonText $value); OffOnly = $offOnly })
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
        if ($it.OffOnly) {
            # #1304: switched off at every scope that holds it on; no row = off by default
            try {
                $on = @(Read-SIControlPlaneSettingRows -Store $Store -Name $it.Name | Where-Object { $null -eq $_.ValueJson -or (ConvertTo-SIControlPlaneJsonKey $_.ValueJson) -cne $it.Json })
                if (-not $on.Count) { $already.Add($it.Name); $lines.Add(('control-plane value: {0} is already off at every scope -- nothing written' -f $it.Name)); continue }
                $bad = @()
                foreach ($row in $on) {
                    $null = Set-SIProSetting -Store $Store -Catalog $Catalog -Name $it.Name -Scope $row.Scope -Action Set -Value $it.Value -ChangedBy $n.ChangedBy -Reason $Reason
                    $back = @(Read-SIControlPlaneSettingRows -Store $Store -Name $it.Name | Where-Object { $_.Scope -eq $row.Scope })[0]
                    if ($back -and (ConvertTo-SIControlPlaneJsonKey $back.ValueJson) -ceq $it.Json) {
                        $lines.Add(('control-plane value: {0} [{1}] {2} -> {3} (from {4}; read back, in the change log)' -f $it.Name, $row.Scope, $row.ValueJson, $it.Json, $n.Settings))
                    } else { $bad += $row.Scope; $lines.Add(('WARNING: control-plane value: {0} [{1}] was written but does not read back as {2} -- the next update tries again' -f $it.Name, $row.Scope, $it.Json)) }
                }
                if ($bad.Count) { $failed.Add($it.Name) } else { $applied.Add($it.Name) }
            } catch {
                $failed.Add($it.Name); $lines.Add(('WARNING: control-plane value: {0} not applied ({1}) -- the next update tries again' -f $it.Name, (([string]$_.Exception.Message) -split "`n")[0]))
            }
            continue
        }
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

# ---------------------------------------------------------------------------------------------------------------------
#  SI_UPDATER_OUTPUTS -- what an output sends (owner 2026-11-16)
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIControlPlaneOutputAllowList {
    <#
        What SI_UPDATER_OUTPUTS may switch -- DERIVED from what this release ships, never free text. -SIRoot: the release's
        SecurityInsight folder. Returns @{ Outputs (ordered: output id -> @{ Id; Kind; Fixed; Pro; Default; Columns (ordered:
        target -> the shipped column, ONLY the columns shipped "off": true); Targets (every target of the map); Fields (every
        field a column reads -> its targets) }); Entries (config\data-out.locked.json's outputs) }.
    #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $read = { param($p) ConvertFrom-SIControlPlaneJson -Text ([IO.File]::ReadAllText($p).TrimStart([char]0xFEFF)) }
    $cat = [IO.Path]::Combine($SIRoot, 'config', 'data-out.locked.json')
    $entries = @()
    if (Test-Path -LiteralPath $cat) { $entries = @((& $read $cat).outputs | Where-Object { $_ -and $_.output }) }
    $outs = [ordered]@{}
    foreach ($e in $entries) {
        $id = [string]$e.output
        $fixed = ([string]$e.kind -eq 'fixed')
        $cols = [ordered]@{}; $targets = @{}; $fields = @{}
        $mapFile = [IO.Path]::Combine($SIRoot, 'data-model', 'outputs', $id + '.locked.json')
        if (Test-Path -LiteralPath $mapFile) {
            foreach ($c in @((& $read $mapFile).columns)) {
                if (-not $c -or -not $c.target) { continue }
                $t = [string]$c.target
                $targets[$t.ToLowerInvariant()] = $t
                $f = [string]$c.from; if ($f.StartsWith('extra.')) { $f = $f.Substring(6) }
                if ($f -and -not $f.StartsWith('$')) {
                    $fk = $f.ToLowerInvariant()
                    if (-not $fields.ContainsKey($fk)) { $fields[$fk] = New-Object System.Collections.Generic.List[string] }
                    $fields[$fk].Add($t)
                }
                $offP = $c.PSObject.Properties['off']
                $isOff = ($null -ne $offP) -and (($offP.Value -is [bool] -and $offP.Value) -or ([string]$offP.Value -ieq 'true'))
                if ($isOff) { $cols[$t] = $c }
            }
        }
        $outs[$id] = [pscustomobject]@{ Id = $id; Kind = [string]$e.kind; Fixed = $fixed; Pro = (@($e.editions) -contains 'pro'); Default = [bool]$e.default
            Columns = $cols; Targets = $targets; Fields = $fields }
    }
    [pscustomobject]@{ Outputs = $outs; Entries = $entries }
}

function ConvertFrom-SIControlPlaneOutputs {
    <#
        PURE (over -Allow). SI_UPDATER_OUTPUTS -> @{ Columns (@{ Output; Target; On; Column } per accepted column switch);
        Outputs (@{ Output; On } per accepted output switch); Refused (one line per refusal) }. Refused: JSON that does not
        parse or is not ONE object (nothing from it is applied), an output this release does not list, a 'fixed' output, an
        output not written in Pro, a part other than on / off / output, a column the map does not have, a column the map
        always sends (only the columns shipped switched off are switched this way), a field two such columns read, a column
        named both on and off. What is accepted still applies.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Json, [Parameter(Mandatory)]$Allow)
    $n = Get-SIControlPlaneNames
    $cols = New-Object System.Collections.Generic.List[object]
    $outs = New-Object System.Collections.Generic.List[object]
    $refused = New-Object System.Collections.Generic.List[string]
    $result = { [pscustomobject]@{ Columns = $cols.ToArray(); Outputs = $outs.ToArray(); Refused = $refused.ToArray() } }
    $text = "$Json".Trim()
    if (-not $text) { return (& $result) }
    $shape = '{0} must be ONE JSON object {{ "<output>": {{ "on": [ "<column>" ], "off": [ "<column>" ], "output": "on" | "off" }} }} -- nothing from it is applied' -f $n.Outputs
    if (-not $text.StartsWith('{')) { $refused.Add($shape); return (& $result) }
    $obj = $null
    try { $obj = ConvertFrom-SIControlPlaneJson -Text $text } catch { $refused.Add(('{0} is not valid JSON ({1}) -- nothing from it is applied' -f $n.Outputs, (([string]$_.Exception.Message) -split "`n")[0].Trim())); return (& $result) }
    if ($null -eq $obj -or $obj -isnot [System.Management.Automation.PSCustomObject]) { $refused.Add($shape); return (& $result) }
    $ids = @($Allow.Outputs.Keys)
    foreach ($p in @($obj.PSObject.Properties)) {
        $id = ([string]$p.Name).Trim().ToLowerInvariant()
        if (-not $Allow.Outputs.Contains($id)) { $refused.Add(('{0}: {1} is not an output of this release (outputs: {2}); not applied' -f $n.Outputs, $p.Name, ($ids -join ', '))); continue }
        $o = $Allow.Outputs[$id]
        if ($o.Fixed) { $refused.Add(('{0}: {1} is written by another connector with fixed columns -- it is not switched this way; not applied' -f $n.Outputs, $id)); continue }
        if (-not $o.Pro) { $refused.Add(('{0}: {1} is not written in SecurityInsight Pro -- not switched this way; not applied' -f $n.Outputs, $id)); continue }
        $v = $p.Value
        if ($null -eq $v -or $v -isnot [System.Management.Automation.PSCustomObject]) { $refused.Add(('{0}: {1} must be an object {{ "on": [...], "off": [...], "output": "on" | "off" }}; not applied' -f $n.Outputs, $id)); continue }
        $want = @{}
        foreach ($part in @($v.PSObject.Properties)) {
            $pn = ([string]$part.Name).ToLowerInvariant()
            if ($pn -eq 'output') {
                $sw = $part.Value
                $on = $null
                if ($sw -is [bool]) { $on = [bool]$sw } elseif ("$sw".Trim() -match '^(?i)(on|true)$') { $on = $true } elseif ("$sw".Trim() -match '^(?i)(off|false)$') { $on = $false }
                if ($null -eq $on) { $refused.Add(('{0}: {1} "output" must be "on" or "off"; not applied' -f $n.Outputs, $id)); continue }
                $outs.Add([pscustomobject]@{ Output = $id; On = $on })
                continue
            }
            if ($pn -notin 'on', 'off') { $refused.Add(('{0}: {1} has "{2}" -- only "on", "off" and "output" are read; that part is not applied' -f $n.Outputs, $id, $part.Name)); continue }
            $names = @()
            if ($null -ne $part.Value) {
                if ($part.Value -is [string]) { $names = @($part.Value) }
                elseif ($part.Value -is [System.Collections.IEnumerable]) { $names = @($part.Value) }
                else { $names = @($part.Value) }
            }
            foreach ($nm in $names) {
                if ($nm -isnot [string] -or -not $nm.Trim()) { $refused.Add(('{0}: {1} "{2}" names a column that is not text; not applied' -f $n.Outputs, $id, $pn)); continue }
                $k = $nm.Trim().ToLowerInvariant(); if ($k.StartsWith('extra.')) { $k = $k.Substring(6) }
                $target = $null
                foreach ($t in $o.Columns.Keys) { if ($t.ToLowerInvariant() -eq $k) { $target = $t; break } }
                if (-not $target) {
                    $byField = @(foreach ($t in $o.Columns.Keys) { $f = [string]$o.Columns[$t].from; if ($f.StartsWith('extra.')) { $f = $f.Substring(6) }; if ($f.ToLowerInvariant() -eq $k) { $t } })
                    if ($byField.Count -gt 1) { $refused.Add(('{0}: {1} {2} is read by more than one column ({3}) -- name the column; not applied' -f $n.Outputs, $id, $nm.Trim(), ($byField -join ', '))); continue }
                    if ($byField.Count -eq 1) { $target = $byField[0] }
                }
                if (-not $target) {
                    if ($o.Targets.ContainsKey($k) -or $o.Fields.ContainsKey($k)) { $refused.Add(('{0}: {1} {2} is a column that is always sent -- only the columns shipped switched off are switched this way (others are changed on Connectors > Fields sent); not applied' -f $n.Outputs, $id, $nm.Trim())) }
                    else { $refused.Add(('{0}: {1} has no column {2} (switchable: {3}); not applied' -f $n.Outputs, $id, $nm.Trim(), $(if ($o.Columns.Count) { @($o.Columns.Keys) -join ', ' } else { 'none' }))) }
                    continue
                }
                if (-not $want.ContainsKey($target)) { $want[$target] = New-Object System.Collections.Generic.List[string] }
                if (-not $want[$target].Contains($pn)) { $want[$target].Add($pn) }
            }
        }
        foreach ($t in $o.Columns.Keys) {
            if (-not $want.ContainsKey($t)) { continue }
            if ($want[$t].Count -gt 1) { $refused.Add(('{0}: {1} {2} is named both on and off; not applied' -f $n.Outputs, $id, $t)); continue }
            $cols.Add([pscustomobject]@{ Output = $id; Target = $t; On = ($want[$t][0] -eq 'on'); Column = $o.Columns[$t] })
        }
    }
    & $result
}

function Test-SIControlPlaneBodyOff {
    <# PURE. Does a column body carry "off": true (a column switched off)? Unreadable = $false. #>
    param([AllowNull()][AllowEmptyString()][string]$Body)
    if ([string]::IsNullOrWhiteSpace($Body)) { return $false }
    try { $o = ConvertFrom-SIControlPlaneJson -Text $Body } catch { return $false }
    if ($o -isnot [System.Management.Automation.PSCustomObject]) { return $false }
    $p = $o.PSObject.Properties['off']
    ($null -ne $p) -and (($p.Value -is [bool] -and $p.Value) -or ([string]$p.Value -ieq 'true'))
}

function Get-SIControlPlaneOutputsOn {
    <#
        PURE. The outputs that run for SI_DataOut_Outputs -- the web app's OutputFieldsModel.OnOutputs: the setting's ids
        (comma / semicolon separated) when it names any, else each output's default; never a 'fixed' output.
    #>
    param([AllowEmptyCollection()][object[]]$Entries = @(), [AllowNull()][AllowEmptyString()][string]$Setting)
    $chosen = @("$Setting" -split '[,;]' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    @(foreach ($e in $Entries) {
        if ([string]$e.kind -eq 'fixed') { continue }
        $on = $(if ($chosen.Count) { $chosen -contains [string]$e.output } else { [bool]$e.default })
        if ($on) { [string]$e.output }
    })
}

function Get-SIControlPlaneOutputsSwitched {
    <#
        PURE. SI_DataOut_Outputs after one output is switched -- the web app's OutputFieldsModel.Switched: every other output
        keeps what it does now; a set that is exactly the defaults = $null (the setting is reset, so an output a later release
        adds follows its own default); else the ids in the catalog's order, ';' separated.
    #>
    param([AllowEmptyCollection()][object[]]$Entries = @(), [AllowNull()][AllowEmptyString()][string]$Setting, [Parameter(Mandatory)][string]$Output, [bool]$On)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($x in @(Get-SIControlPlaneOutputsOn -Entries $Entries -Setting $Setting)) { [void]$set.Add($x) }
    if ($On) { [void]$set.Add($Output) } else { [void]$set.Remove($Output) }
    $def = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($x in @(Get-SIControlPlaneOutputsOn -Entries $Entries -Setting $null)) { [void]$def.Add($x) }
    if ($set.SetEquals($def)) { return $null }
    (@(foreach ($e in $Entries) { if ($set.Contains([string]$e.output)) { [string]$e.output } }) -join ';')
}

function ConvertFrom-SIControlPlaneSettingText {
    <# PURE. A stored ValueJson as the form text the web app reads (a JSON text = itself, a list = comma joined); $null = $null. #>
    param([AllowNull()][AllowEmptyString()][string]$ValueJson)
    if ($null -eq $ValueJson) { return $null }
    try { $v = ConvertFrom-SIControlPlaneJson -Text $ValueJson } catch { return $ValueJson }
    if ($null -eq $v) { return $null }
    if ($v -is [string]) { return $v }
    if ($v -is [System.Collections.IEnumerable]) { return (@($v | ForEach-Object { [string]$_ }) -join ',') }
    [string]$v
}

function Test-SIControlPlaneReason {
    <#
        PURE. Does SI_UPDATER_CONTROLPLANE_REASON name WHO asked and WHY? '' = yes, else the reason it does not. Invardia sets
        it as '<person>: <why>'. THE RULE: after trimming, at least two words and at least 8 letters or digits, and not a
        generic word (update, updater, the update, n/a, na, none, null, test, testing, tbd, todo, change, fix, ok, yes, no,
        reason, default, auto, automatic, x, -, .) -- also not the standard text this path writes when no reason is set.
        Needed for every change of what is sent: a column or an output switched on OR off.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Reason)
    $t = "$Reason".Trim()
    if (-not $t) { return 'it is not set' }
    $flat = (($t.ToLowerInvariant() -replace '[^\p{L}\p{N}/ ]', ' ') -replace '\s+', ' ').Trim()
    $generic = @('update', 'updater', 'the update', 'n/a', 'na', 'none', 'null', 'test', 'testing', 'tbd', 'todo', 'change', 'changes', 'fix', 'ok', 'yes', 'no', 'reason', 'default', 'auto', 'automatic', 'x', '')
    if ($generic -contains $flat) { return ("'{0}' is a generic word" -f $t) }
    if ($t -match '^(?i)a control-plane value on the updater job') { return 'it is the standard text, not a person''s reason' }
    if (([regex]::Matches($t, '[\p{L}\p{N}]')).Count -lt 8) { return ("'{0}' is too short" -f $t) }
    if (@($flat -split ' ' | Where-Object { $_ }).Count -lt 2) { return ("'{0}' is one word -- it must say who asked and why" -f $t) }
    ''
}

function Get-SIControlPlaneValueHash {
    <# PURE. SHA-256 (hex) of a control-plane JSON value in the writer's own form (ConvertTo-SIControlPlaneJsonKey when it
       parses, else the trimmed text) -- the same value written with other spacing has the same hash. #>
    param([AllowNull()][AllowEmptyString()][string]$Json)
    $t = "$Json".Trim()
    $k = $t
    if ($t -and (Get-Command -Name ConvertTo-SIJsonText -ErrorAction SilentlyContinue)) { $k = [string](ConvertTo-SIControlPlaneJsonKey $t) }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($k))) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Read-SIControlPlaneInstallState {
    <# One cfg.InstallState value, or $null (no row, or no table). Throws on a SQL error. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Name)
    $rows = @(& $Store.Invoke "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = @Name;" ([ordered]@{ Name = $Name }) 'reader' | ForEach-Object { $_ })
    $r = $rows | Where-Object { $_ } | Select-Object -First 1
    if (-not $r) { return $null }
    $v = if ($r -is [System.Collections.IDictionary]) { $r['Value'] } else { $r.Value }
    if ($null -eq $v -or $v -is [System.DBNull]) { $null } else { [string]$v }
}

function Write-SIControlPlaneInstallState {
    <# One cfg.InstallState value (MERGE; UpdatedBy = the update). No table = nothing written. Throws on a SQL error. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Value)
    $n = Get-SIControlPlaneNames
    $null = & $Store.Invoke @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
MERGE cfg.InstallState AS t USING (SELECT @Name AS Name) AS s ON t.Name = s.Name
WHEN MATCHED THEN UPDATE SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
WHEN NOT MATCHED THEN INSERT (Name, Value, UpdatedBy) VALUES (@Name, @Value, @By);
'@ ([ordered]@{ Name = $Name; Value = $Value; By = $n.ChangedBy }) 'nonquery'
}

function Invoke-SIControlPlaneOutputs {
    <#
        SI_UPDATER_OUTPUTS -> each accepted column switch written through the web app's own output-column statement
        (Set-SIProOutputColumn: on = the shipped column without "off" as an 'override' row, off = the row removed, back to the
        shipped column), each accepted output switch through Set-SIProSetting on SI_DataOut_Outputs (computed as the web app's
        output switch computes it), ChangedBy 'the update (control-plane value)', -Reason; each READ BACK. Equal to what is in
        force = nothing written: a column already sent (an Admin's own change of it included -- never overwritten), a column
        already not sent, an output already on / off.
        ONCE PER VALUE: the applied value's hash is kept in cfg.InstallState 'ControlPlaneOutputs'; the same value on a later
        update does NOTHING -- an Admin who switches a column off in the web app is never switched back on by the next update.
        The hash is written when nothing failed and nothing waited for a reason (those are tried again); a part refused for good
        (not on the list) does not hold it back.
        WHO ASKED: EVERY change -- a column on or off, an output on or off -- needs -Reason to name who asked and why
        (Test-SIControlPlaneReason; Invardia sets '<person>: <why>') -- else nothing is written for it and it is refused in ONE
        warning line; the reason is recorded in cfg.ChangeLog with each change. What is in force already needs no reason (nothing
        is written).
        "OFF" REMOVES ONLY WHAT THE UPDATE WROTE: a column row an Admin wrote (UpdatedBy is not the update) is KEPT.
        Returns @{ Applied; Already; Kept; Refused; Failed; Lines }. Needs Set-SIProOutputColumn loaded, and Set-SIProSetting
        for an output switch.
    #>
    param([Parameter(Mandatory)]$Store, [AllowEmptyString()][string]$Json, [Parameter(Mandatory)]$Allow, [AllowEmptyCollection()][object[]]$Catalog, [string]$Reason,
          [string]$StandardReason = 'a control-plane value on the updater job')
    $n = Get-SIControlPlaneNames
    $lines = New-Object System.Collections.Generic.List[string]
    $applied = New-Object System.Collections.Generic.List[string]; $already = New-Object System.Collections.Generic.List[string]; $failed = New-Object System.Collections.Generic.List[string]
    $kept = New-Object System.Collections.Generic.List[string]; $needWho = New-Object System.Collections.Generic.List[string]
    $err = { param($e) (([string]$e.Exception.Message) -split "`n")[0] }
    # once per value: the same SI_UPDATER_OUTPUTS as the one applied = nothing to do
    $hash = Get-SIControlPlaneValueHash -Json $Json
    $stateName = 'ControlPlaneOutputs'
    $prev = $null
    try { $prev = Read-SIControlPlaneInstallState -Store $Store -Name $stateName } catch { $prev = $null; $lines.Add(('WARNING: control-plane value: whether {0} was applied before could not be read ({1}) -- it is applied now' -f $n.Outputs, (& $err $_))) }
    if ($prev -and $prev -ceq $hash) {
        $lines.Add(('control-plane value: {0} is the value already applied -- nothing written (a change made since in the web app is kept)' -f $n.Outputs))
        return [pscustomobject]@{ Applied = @(); Already = @('outputs'); Kept = @(); Refused = @(); Failed = @(); Lines = $lines.ToArray() }
    }
    $whoWhy = Test-SIControlPlaneReason -Reason $Reason
    $onReason = "$Reason".Trim(); if ($onReason.Length -gt 400) { $onReason = $onReason.Substring(0, 400) }
    $offReason = $onReason
    $plan = ConvertFrom-SIControlPlaneOutputs -Json $Json -Allow $Allow
    $refusedAll = New-Object System.Collections.Generic.List[string]; foreach ($r in @($plan.Refused)) { $refusedAll.Add([string]$r) }
    foreach ($r in @($plan.Refused)) { $lines.Add('WARNING: control-plane value: ' + $r) }
    foreach ($c in @($plan.Columns)) {
        $name = '{0}:{1}' -f $c.Output, $c.Target
        try {
            $key = Get-SIProOutputColumnKey -Output $c.Output -Target $c.Target
            $cur = Read-SIProOutputColumn -Store $Store -Key $key
            $rsn = $(if ($c.On) { $onReason } else { $offReason })
            if ($c.On) {
                if ($cur -and $cur.State -eq 'override' -and -not (Test-SIControlPlaneBodyOff $cur.BodyJson)) {
                    $already.Add($name); $lines.Add(('control-plane value: {0} column {1} is sent already{2} -- nothing written' -f $c.Output, $c.Target, $(if ($cur.UpdatedBy) { ' (switched on by ' + $cur.UpdatedBy + ')' } else { '' }))); continue
                }
                if ($whoWhy) { $needWho.Add(('{0} column {1} on' -f $c.Output, $c.Target)); continue }
                $body = Get-SIProOutputColumnBody -Column $c.Column
                if ((Set-SIProOutputColumn -Store $Store -Key $key -State override -Body $body -ChangedBy $n.ChangedBy -Reason $rsn) -eq 'Missing') {
                    $failed.Add($name); $lines.Add(('WARNING: control-plane value: {0} column {1} not switched on -- this database has no cfg.ItemOverride table yet; the next update tries again' -f $c.Output, $c.Target)); continue
                }
                $back = Read-SIProOutputColumn -Store $Store -Key $key
                if ($back -and $back.State -eq 'override' -and $back.BodyJson -ceq $body) {
                    $applied.Add($name); $lines.Add(('control-plane value: {0} column {1} switched ON (from {2}; read back, in the change log)' -f $c.Output, $c.Target, $n.Outputs))
                } else { $failed.Add($name); $lines.Add(('WARNING: control-plane value: {0} column {1} was switched on but does not read back -- the next update tries again' -f $c.Output, $c.Target)) }
            } else {
                if (-not $cur -or $cur.State -eq 'disable') {
                    $already.Add($name); $lines.Add(('control-plane value: {0} column {1} is not sent already -- nothing written' -f $c.Output, $c.Target)); continue
                }
                # "off" removes ONLY a row the update itself wrote -- an Admin's own row (Connectors > Fields sent) is kept
                if ([string]$cur.UpdatedBy -cne $n.ChangedBy) {
                    $kept.Add($name); $lines.Add(('control-plane value: {0} column {1} is kept -- it was switched on in the web app{2}, and "off" removes only a column the update switched on itself' -f $c.Output, $c.Target, $(if ($cur.UpdatedBy) { ' by ' + $cur.UpdatedBy } else { '' }))); continue
                }
                if ($whoWhy) { $needWho.Add(('{0} column {1} off' -f $c.Output, $c.Target)); continue }
                if ((Set-SIProOutputColumn -Store $Store -Key $key -State inherit -ChangedBy $n.ChangedBy -Reason $rsn) -eq 'Missing') {
                    $failed.Add($name); $lines.Add(('WARNING: control-plane value: {0} column {1} not switched off -- this database has no cfg.ItemOverride table yet; the next update tries again' -f $c.Output, $c.Target)); continue
                }
                $back = Read-SIProOutputColumn -Store $Store -Key $key
                if ($null -eq $back) {
                    $applied.Add($name); $lines.Add(('control-plane value: {0} column {1} switched OFF -- back to the shipped column, not sent (from {2}; read back, in the change log)' -f $c.Output, $c.Target, $n.Outputs))
                } else { $failed.Add($name); $lines.Add(('WARNING: control-plane value: {0} column {1} was switched off but does not read back -- the next update tries again' -f $c.Output, $c.Target)) }
            }
        } catch { $failed.Add($name); $lines.Add(('WARNING: control-plane value: {0} column {1} not switched ({2}) -- the next update tries again' -f $c.Output, $c.Target, (& $err $_))) }
    }
    # an output switched ON starts a data flow: it needs who asked and why
    $outPlan = @($plan.Outputs)
    $outReason = $onReason
    if ($outPlan.Count) {
        $todo = @($outPlan | ForEach-Object { 'output:' + $_.Output })
        try {
            $entries = @($Allow.Entries)
            $before = Read-SIControlPlaneSetting -Store $Store -Name $n.OutputsSetting -Scope $n.Scope
            $text = ConvertFrom-SIControlPlaneSettingText $before
            $on = @(Get-SIControlPlaneOutputsOn -Entries $entries -Setting $text)
            $value = $text; $changing = New-Object System.Collections.Generic.List[object]
            foreach ($o in $outPlan) {
                if (($on -contains $o.Output) -eq $o.On) { $already.Add('output:' + $o.Output); $lines.Add(('control-plane value: the output {0} is {1} already -- nothing written' -f $o.Output, $(if ($o.On) { 'on' } else { 'off' }))); continue }
                if ($whoWhy) { $needWho.Add(('the output {0} {1}' -f $o.Output, $(if ($o.On) { 'on' } else { 'off' }))); continue }
                $value = Get-SIControlPlaneOutputsSwitched -Entries $entries -Setting $value -Output $o.Output -On $o.On
                $on = @(Get-SIControlPlaneOutputsOn -Entries $entries -Setting $value)
                $changing.Add($o)
            }
            if ($changing.Count) {
                if ($null -eq $value) { $null = Set-SIProSetting -Store $Store -Catalog $Catalog -Name $n.OutputsSetting -Scope $n.Scope -Action Reset -ChangedBy $n.ChangedBy -Reason $outReason }
                else { $null = Set-SIProSetting -Store $Store -Catalog $Catalog -Name $n.OutputsSetting -Scope $n.Scope -Action Set -Value $value -ChangedBy $n.ChangedBy -Reason $outReason }
                $backOn = @(Get-SIControlPlaneOutputsOn -Entries $entries -Setting (ConvertFrom-SIControlPlaneSettingText (Read-SIControlPlaneSetting -Store $Store -Name $n.OutputsSetting -Scope $n.Scope)))
                foreach ($o in $changing) {
                    if (($backOn -contains $o.Output) -eq $o.On) {
                        $applied.Add('output:' + $o.Output)
                        $lines.Add(('control-plane value: the output {0} switched {1} ({2} {3}; from {4}; read back, in the change log)' -f $o.Output, $(if ($o.On) { 'ON' } else { 'OFF' }), $n.OutputsSetting, $(if ($null -eq $value) { 'back to the defaults' } else { '= ' + $value }), $n.Outputs))
                    } else { $failed.Add('output:' + $o.Output); $lines.Add(('WARNING: control-plane value: the output {0} was switched but does not read back -- the next update tries again' -f $o.Output)) }
                }
            }
        } catch {
            foreach ($t in $todo) { if (-not $already.Contains($t)) { $failed.Add($t) } }
            $lines.Add(('WARNING: control-plane value: the outputs not switched ({0}) -- the next update tries again' -f (& $err $_)))
        }
    }
    if ($needWho.Count) {
        $msg = ('{0}: {1} not switched -- every change of what is sent needs {2} to name who asked and why (''<person>: <why>''); {3}' -f $n.Outputs, ($needWho -join ', '), $n.Reason, $whoWhy)
        $refusedAll.Add($msg); $lines.Add('WARNING: control-plane value: ' + $msg)
    }
    # once per value: recorded when every part that CAN apply was done -- a failure or a missing reason leaves it unrecorded (tried
    # again next update); a part refused for good (not an output or a column of the list) is said once and the value is recorded,
    # so an Admin's later change in the web app is never undone by the same value on the next update
    if ($failed.Count -eq 0 -and $needWho.Count -eq 0) {
        try { Write-SIControlPlaneInstallState -Store $Store -Name $stateName -Value $hash }
        catch { $lines.Add(('WARNING: control-plane value: that {0} was applied could not be recorded ({1}) -- the next update compares again' -f $n.Outputs, (& $err $_))) }
    }
    [pscustomobject]@{ Applied = $applied.ToArray(); Already = $already.ToArray(); Kept = $kept.ToArray(); Refused = $refusedAll.ToArray(); Failed = $failed.ToArray(); Lines = $lines.ToArray() }
}

# =====================================================================================================================
#  SI_UPDATER_REPORTS -- a shipped report switched off / on again (owner 2026-11-19)
# =====================================================================================================================

function Get-SIControlPlaneReportAllowList {
    <#
        What SI_UPDATER_REPORTS may switch -- DERIVED from what this release ships, never free text. -SIRoot: the release's
        SecurityInsight folder. Returns @{ Reports (HashSet of the shipped report names, case-sensitive as shipped);
        Required (report name -> the reason SecurityInsight requires it: a 'rareport' control of
        config\template-mandatory.locked.json, which also refuses an Admin's switch-off) }.
    #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $yaml = [IO.Path]::Combine($SIRoot, 'risk-analysis-detection', 'RiskAnalysis_Queries_Locked.yaml')
    if (Test-Path -LiteralPath $yaml) {
        # the report entries sit under 'Reports:' as '  - ReportName: <name>'; the templates under 'ReportTemplates:'
        $section = ''
        foreach ($line in [IO.File]::ReadAllLines($yaml)) {
            if ($line -match '^(\S[^:]*):\s*$') { $section = $Matches[1].Trim(); continue }
            if ($section -ceq 'Reports' -and $line -match '^\s*-\s*ReportName:\s*[''"]?([A-Za-z0-9_]{1,100})[''"]?\s*$') { [void]$names.Add($Matches[1]) }
        }
    }
    $required = @{}
    $mfile = [IO.Path]::Combine($SIRoot, 'config', 'template-mandatory.locked.json')
    if (Test-Path -LiteralPath $mfile) {
        $doc = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($mfile))
        foreach ($c in @($doc.Controls)) {
            if ($c -and [string]$c.Kind -ceq 'rareport' -and [string]$c.ItemKey -like 'report/*') { $required[([string]$c.ItemKey).Substring(7)] = [string]$c.Reason }
        }
    }
    [pscustomobject]@{ Reports = $names; Required = $required }
}

function ConvertFrom-SIControlPlaneReports {
    <#
        PURE (over -Allow). SI_UPDATER_REPORTS -> @{ Items (@{ Report; On } per accepted switch); Refused (one line per
        refusal) }. Refused: JSON that does not parse or is not ONE object (nothing applied), a report this release does not
        ship, a report SecurityInsight requires (switched off), a value that is not "on" / "off".
    #>
    param([AllowNull()][AllowEmptyString()][string]$Json, [Parameter(Mandatory)]$Allow)
    $n = Get-SIControlPlaneNames
    $items = New-Object System.Collections.Generic.List[object]
    $refused = New-Object System.Collections.Generic.List[string]
    $out = { [pscustomobject]@{ Items = $items.ToArray(); Refused = $refused.ToArray() } }
    $text = "$Json".Trim()
    if (-not $text) { return (& $out) }
    $shape = '{0} must be ONE JSON object {{ "<ReportName>": "off" | "on" }} -- nothing from it is applied' -f $n.Reports
    if (-not $text.StartsWith('{')) { $refused.Add($shape); return (& $out) }
    $obj = $null
    try { $obj = ConvertFrom-SIControlPlaneJson -Text $text } catch { $refused.Add(('{0} is not valid JSON ({1}) -- nothing from it is applied' -f $n.Reports, (([string]$_.Exception.Message) -split "`n")[0].Trim())); return (& $out) }
    if ($null -eq $obj -or $obj -isnot [System.Management.Automation.PSCustomObject]) { $refused.Add($shape); return (& $out) }
    foreach ($p in @($obj.PSObject.Properties)) {
        $name = [string]$p.Name
        if (-not $Allow.Reports.Contains($name)) { $refused.Add(('{0}: {1} is not a report this release ships (a custom report is switched in the web app); not applied' -f $n.Reports, $name)); continue }
        $v = if ($p.Value -is [string]) { $p.Value.Trim().ToLowerInvariant() } else { '' }
        if ($v -notin 'on', 'off') { $refused.Add(('{0}: {1} must be "off" or "on"; not applied' -f $n.Reports, $name)); continue }
        if ($v -eq 'off' -and $Allow.Required.ContainsKey($name)) { $refused.Add(('{0}: {1} is required by SecurityInsight and cannot be switched off{2}; not applied' -f $n.Reports, $name, $(if ($Allow.Required[$name]) { ' -- ' + $Allow.Required[$name] } else { '' }))); continue }
        $items.Add([pscustomobject]@{ Report = $name; On = ($v -eq 'on') })
    }
    & $out
}

function Read-SIControlPlaneReportRow {
    <# One report's cfg.ItemOverride row (Kind 'rareport', key 'report/<name>'): @{ State; UpdatedBy } or $null. Throws on a SQL error. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Report)
    $rows = @(& $Store.Invoke (Get-SIProOutputColumnReadSql) ([ordered]@{ Kind = 'rareport'; Key = 'report/' + $Report }) 'reader' | ForEach-Object { $_ } | Where-Object { $_ })
    if (-not $rows.Count) { return $null }
    $r = $rows[0]
    $get = { param($k) if ($r -is [System.Collections.IDictionary]) { $r[$k] } else { $r.$k } }
    $s = & $get 'State'; $u = & $get 'UpdatedBy'
    if ($null -eq $s -or $s -is [System.DBNull]) { return $null }
    [pscustomobject]@{ State = [string]$s; UpdatedBy = $(if ($null -eq $u -or $u -is [System.DBNull]) { $null } else { [string]$u }) }
}

function Write-SIControlPlaneReportRow {
    <# The web app's own item statement (ItemOverrideRepository.WriteSql) for one report: 'disable' or 'inherit'. Returns 'Saved' | 'Missing'. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Report, [Parameter(Mandatory)][ValidateSet('disable', 'inherit')][string]$State, [string]$Reason = '')
    $n = Get-SIControlPlaneNames
    $p = [ordered]@{ Kind = 'rareport'; Key = 'report/' + $Report; State = $State; Body = $null; Format = 'json'; By = $n.ChangedBy; Reason = $Reason }
    $rows = @(& $Store.Invoke (Get-SIProOutputColumnWriteSql) $p 'reader' | ForEach-Object { $_ } | Where-Object { $_ })
    $o = $null
    if ($rows.Count) { $x = $rows[0]; $o = $(if ($x -is [System.Collections.IDictionary]) { $x['Outcome'] } else { $x.Outcome }) }
    if ([string]$o -eq 'Missing') { return 'Missing' }
    if ([string]$o -ne 'Saved') { throw 'the report write returned no outcome' }
    'Saved'
}

function Invoke-SIControlPlaneReports {
    <#
        SI_UPDATER_REPORTS -> each accepted switch written through the web app's own item statement, READ BACK:
          off  = State 'disable' (what an Admin's "Report it" off writes); a report switched off already = nothing written;
          on   = the update's own 'disable' row removed (back to the shipped report); a report that is on = nothing written;
                 a report an Admin switched off (UpdatedBy is not the update) is KEPT off.
        Every change needs -Reason naming who asked and why (Test-SIControlPlaneReason) -- else nothing is written for it,
        refused in ONE warning line. ONCE PER VALUE (cfg.InstallState 'ControlPlaneReports'), recorded when nothing failed and
        nothing waited for a reason. Returns @{ Applied; Already; Kept; Refused; Failed; Lines }. Needs Get-SIProOutputColumnWriteSql.
    #>
    param([Parameter(Mandatory)]$Store, [AllowEmptyString()][string]$Json, [Parameter(Mandatory)]$Allow, [string]$Reason)
    $n = Get-SIControlPlaneNames
    $lines = New-Object System.Collections.Generic.List[string]
    $applied = New-Object System.Collections.Generic.List[string]; $already = New-Object System.Collections.Generic.List[string]; $failed = New-Object System.Collections.Generic.List[string]
    $kept = New-Object System.Collections.Generic.List[string]; $needWho = New-Object System.Collections.Generic.List[string]
    $err = { param($e) (([string]$e.Exception.Message) -split "`n")[0] }
    $hash = Get-SIControlPlaneValueHash -Json $Json
    $stateName = 'ControlPlaneReports'
    $prev = $null
    try { $prev = Read-SIControlPlaneInstallState -Store $Store -Name $stateName } catch { $prev = $null; $lines.Add(('WARNING: control-plane value: whether {0} was applied before could not be read ({1}) -- it is applied now' -f $n.Reports, (& $err $_))) }
    if ($prev -and $prev -ceq $hash) {
        $lines.Add(('control-plane value: {0} is the value already applied -- nothing written (a change made since in the web app is kept)' -f $n.Reports))
        return [pscustomobject]@{ Applied = @(); Already = @('reports'); Kept = @(); Refused = @(); Failed = @(); Lines = $lines.ToArray() }
    }
    $whoWhy = Test-SIControlPlaneReason -Reason $Reason
    $rsn = "$Reason".Trim(); if ($rsn.Length -gt 400) { $rsn = $rsn.Substring(0, 400) }
    $plan = ConvertFrom-SIControlPlaneReports -Json $Json -Allow $Allow
    $refusedAll = New-Object System.Collections.Generic.List[string]; foreach ($r in @($plan.Refused)) { $refusedAll.Add([string]$r); $lines.Add('WARNING: control-plane value: ' + $r) }
    foreach ($it in @($plan.Items)) {
        $name = $it.Report
        try {
            $cur = Read-SIControlPlaneReportRow -Store $Store -Report $name
            $isOff = ($cur -and $cur.State -eq 'disable')
            if (-not $it.On) {
                if ($isOff) { $already.Add($name); $lines.Add(('control-plane value: the report {0} is switched off already -- nothing written' -f $name)); continue }
                if ($whoWhy) { $needWho.Add(('{0} off' -f $name)); continue }
                if ((Write-SIControlPlaneReportRow -Store $Store -Report $name -State disable -Reason $rsn) -eq 'Missing') { $failed.Add($name); $lines.Add(('WARNING: control-plane value: the report {0} not switched off -- this database has no cfg.ItemOverride table yet; the next update tries again' -f $name)); continue }
                $back = Read-SIControlPlaneReportRow -Store $Store -Report $name
                if ($back -and $back.State -eq 'disable') { $applied.Add($name); $lines.Add(('control-plane value: the report {0} switched OFF -- left out of every report template from the next run (from {1}; read back, in the change log)' -f $name, $n.Reports)) }
                else { $failed.Add($name); $lines.Add(('WARNING: control-plane value: the report {0} was switched off but does not read back -- the next update tries again' -f $name)) }
            } else {
                if (-not $isOff) { $already.Add($name); $lines.Add(('control-plane value: the report {0} is on already -- nothing written' -f $name)); continue }
                if ([string]$cur.UpdatedBy -cne $n.ChangedBy) { $kept.Add($name); $lines.Add(('control-plane value: the report {0} is kept off -- it was switched off in the web app{1}, and "on" removes only a switch-off the update wrote itself' -f $name, $(if ($cur.UpdatedBy) { ' by ' + $cur.UpdatedBy } else { '' }))); continue }
                if ($whoWhy) { $needWho.Add(('{0} on' -f $name)); continue }
                if ((Write-SIControlPlaneReportRow -Store $Store -Report $name -State inherit -Reason $rsn) -eq 'Missing') { $failed.Add($name); continue }
                $back = Read-SIControlPlaneReportRow -Store $Store -Report $name
                if ($null -eq $back) { $applied.Add($name); $lines.Add(('control-plane value: the report {0} switched ON again -- back to the shipped report (from {1}; read back, in the change log)' -f $name, $n.Reports)) }
                else { $failed.Add($name); $lines.Add(('WARNING: control-plane value: the report {0} was switched on but does not read back -- the next update tries again' -f $name)) }
            }
        } catch { $failed.Add($name); $lines.Add(('WARNING: control-plane value: the report {0} not switched ({1}) -- the next update tries again' -f $name, (& $err $_))) }
    }
    if ($needWho.Count) {
        $msg = ('{0}: {1} not switched -- every report switch needs {2} to name who asked and why (''<person>: <why>''); {3}' -f $n.Reports, ($needWho -join ', '), $n.Reason, $whoWhy)
        $refusedAll.Add($msg); $lines.Add('WARNING: control-plane value: ' + $msg)
    }
    if ($failed.Count -eq 0 -and $needWho.Count -eq 0) {
        try { Write-SIControlPlaneInstallState -Store $Store -Name $stateName -Value $hash }
        catch { $lines.Add(('WARNING: control-plane value: that {0} was applied could not be recorded ({1}) -- the next update compares again' -f $n.Reports, (& $err $_))) }
    }
    [pscustomobject]@{ Applied = $applied.ToArray(); Already = $already.ToArray(); Kept = $kept.ToArray(); Refused = $refusedAll.ToArray(); Failed = $failed.ToArray(); Lines = $lines.ToArray() }
}

function Invoke-SIDefaultTaskOutputs {
    <#
        THE TASK OUTPUTS ON BY DEFAULT (owner 2026-11-17), for an install made before: at an install that sends to ServiceNow (its
        SI_DataOut_Outputs switches on an output marked with the task outputs -- the CI hand-off or the vulnerable items), the outputs
        the catalog marks "onWithServiceNow" (the remediation tasks and their links) are switched on -- as a new install's "Switch
        on" of the data-out connector does -- through the one setting writer (ChangedBy the update, the reason in the change log)
        and READ BACK. ONCE per install (cfg.InstallState 'TaskOutputsOnByDefault'): an Admin who switches them off afterwards is
        never switched back on. An install that does not send to ServiceNow is left as it is (recorded, nothing written). A task
        output whose Import Set table is not set is "not set up" in the engine: nothing is sent to it, never a failure.
        Returns @{ Applied; Already; Failed; Lines }. NEVER throws.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)]$Allow, [AllowEmptyCollection()][object[]]$Catalog)
    $n = Get-SIControlPlaneNames
    $stateName = 'TaskOutputsOnByDefault'
    $lines = New-Object System.Collections.Generic.List[string]
    $res = [pscustomobject]@{ Applied = @(); Already = @(); Failed = @(); Lines = @() }
    try {
        $prev = Read-SIControlPlaneInstallState -Store $Store -Name $stateName
        if ($prev) { $res.Already = @('task outputs'); return $res }
        $entries = @($Allow.Entries)
        $flag = { param($e) $v = $(if ($e -is [System.Collections.IDictionary]) { $e['onWithServiceNow'] } elseif ($e.PSObject.Properties['onWithServiceNow']) { $e.onWithServiceNow } else { $null }); ($v -eq $true -or [string]$v -ieq 'true') }
        $with = @($entries | Where-Object { & $flag $_ } | ForEach-Object { [string]$_.output })
        $snow = @($entries | Where-Object { [string]$_.kind -eq 'servicenow-importset' -and $with -notcontains [string]$_.output } | ForEach-Object { [string]$_.output })
        $text = ConvertFrom-SIControlPlaneSettingText (Read-SIControlPlaneSetting -Store $Store -Name $n.OutputsSetting -Scope $n.Scope)
        $on = @(Get-SIControlPlaneOutputsOn -Entries $entries -Setting $text)
        if (@($on | Where-Object { $snow -contains $_ }).Count -eq 0) {
            $lines.Add('task outputs on by default: this install does not send to ServiceNow -- nothing switched')
            Write-SIControlPlaneInstallState -Store $Store -Name $stateName -Value 'not-servicenow'
            $res.Lines = $lines.ToArray(); return $res
        }
        $todo = @($with | Where-Object { $on -notcontains $_ })
        if ($todo.Count -eq 0) { $res.Already = $with; Write-SIControlPlaneInstallState -Store $Store -Name $stateName -Value 'on'; $res.Lines = $lines.ToArray(); return $res }
        $value = $text
        foreach ($o in $todo) { $value = Get-SIControlPlaneOutputsSwitched -Entries $entries -Setting $value -Output $o -On $true }
        $why = 'the remediation task outputs are on by default (owner 2026-11-17) -- switched on once by the update; an Admin may switch them off'
        if ($null -eq $value) { $null = Set-SIProSetting -Store $Store -Catalog $Catalog -Name $n.OutputsSetting -Scope $n.Scope -Action Reset -ChangedBy $n.ChangedBy -Reason $why }
        else { $null = Set-SIProSetting -Store $Store -Catalog $Catalog -Name $n.OutputsSetting -Scope $n.Scope -Action Set -Value $value -ChangedBy $n.ChangedBy -Reason $why }
        $backOn = @(Get-SIControlPlaneOutputsOn -Entries $entries -Setting (ConvertFrom-SIControlPlaneSettingText (Read-SIControlPlaneSetting -Store $Store -Name $n.OutputsSetting -Scope $n.Scope)))
        $missing = @($todo | Where-Object { $backOn -notcontains $_ })
        if ($missing.Count) {
            $res.Failed = $missing
            $lines.Add(('WARNING: task outputs on by default: {0} switched on but not read back -- the next update tries again' -f ($missing -join ', ')))
        } else {
            $res.Applied = $todo
            $lines.Add(('task outputs on by default: {0} switched ON ({1}; read back, in the change log)' -f ($todo -join ', '), $n.OutputsSetting))
            Write-SIControlPlaneInstallState -Store $Store -Name $stateName -Value 'on'
        }
    } catch { $res.Failed = @('task outputs'); $lines.Add(('WARNING: task outputs on by default: not applied ({0}) -- the next update tries again' -f (([string]$_.Exception.Message) -split "`n")[0])) }
    $res.Lines = $lines.ToArray()
    $res
}

function Invoke-SIDefaultTaskOutputsStep {
    <#
        THE UPDATER'S STEP (Start-SIUpdater, after the control-plane values): Invoke-SIDefaultTaskOutputs with the release's
        catalog and the one setting writer, each line logged. -SIRoot: the SecurityInsight folder the update carries. NEVER throws.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$SIRoot, [scriptblock]$Log = { param($m) Write-Host $m })
    try {
        if (-not (Get-Command -Name Set-SIProSetting -ErrorAction SilentlyContinue)) {
            $w = [IO.Path]::Combine($SIRoot, 'engine', 'pro-settings', 'SI-ProSettingWrite.ps1')
            if (-not (Test-Path -LiteralPath $w)) { & $Log 'WARNING: task outputs on by default: this release carries no setting writer -- not applied'; return $null }
            . $w
        }
        $cat = @(Get-SISettingsCatalog -SIRoot $SIRoot)
        $r = Invoke-SIDefaultTaskOutputs -Store $Store -Allow (Get-SIControlPlaneOutputAllowList -SIRoot $SIRoot) -Catalog $cat
        foreach ($l in @($r.Lines)) { & $Log $l }
        $r
    } catch { & $Log ('WARNING: task outputs on by default: not applied ({0}) -- the next update tries again' -f (([string]$_.Exception.Message) -split "`n")[0]); $null }
}
function Invoke-SIControlPlaneValues {
    <#
        THE STEP: the identity move's mode first, then the settings, then the outputs (SI_UPDATER_OUTPUTS). -Env: the job's environment (a hashtable; a name not in
        it is read from the process). -SIRoot: the SecurityInsight folder the update carries (/si in the updater image).
        -UpdaterJob: the job's name, for the standard reason. Returns @{ Mode (the identity-mode result); Settings; Outputs; Lines }.
        NEVER throws; never fails the update.
    #>
    param([hashtable]$Env = @{}, [Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$SIRoot, [string]$UpdaterJob = 'caj-si-updater',
          [object[]]$Catalog, [scriptblock]$Log = { param($m) Write-Host $m })
    $n = Get-SIControlPlaneNames
    $out = [pscustomobject]@{ Mode = $null; Settings = $null; Outputs = $null; Lines = @() }
    $siCpStepLines = New-Object System.Collections.Generic.List[string]
    $say = { param($m) if ($m) { $siCpStepLines.Add([string]$m); try { $null = & $Log ([string]$m) } catch { } } }
    try {
        $read = { param($k) if ($Env.ContainsKey($k)) { "$($Env[$k])".Trim() } else { "$([Environment]::GetEnvironmentVariable($k))".Trim() } }
        $modeVal = & $read $n.IdentityMoveMode
        $setVal = & $read $n.Settings
        $outVal = & $read $n.Outputs
        $repVal = & $read $n.Reports
        if (-not $modeVal -and -not $setVal -and -not $outVal -and -not $repVal) { $out.Lines = $siCpStepLines.ToArray(); return $out }
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
        if ($outVal) {
            # the output column writer (the web app's own statement) and, for an output switch, the one setting writer
            $ready = $true
            foreach ($w in @(@{ Fn = 'Set-SIProOutputColumn'; File = 'SI-OutputColumnWrite.ps1' }, @{ Fn = 'Set-SIProSetting'; File = 'SI-ProSettingWrite.ps1' })) {
                if (Get-Command -Name $w.Fn -ErrorAction SilentlyContinue) { continue }
                $f = [IO.Path]::Combine($SIRoot, 'engine', 'pro-settings', $w.File)
                if (-not (Test-Path -LiteralPath $f)) { $ready = $false; break }
                . $f
            }
            if (-not $ready) { & $say ('WARNING: control-plane value: {0} not applied -- this release carries no output column writer' -f $n.Outputs) }
            else {
                if ($null -eq $Catalog) { $Catalog = @(Get-SISettingsCatalog -SIRoot $SIRoot) }
                $out.Outputs = Invoke-SIControlPlaneOutputs -Store $Store -Json $outVal -Allow (Get-SIControlPlaneOutputAllowList -SIRoot $SIRoot) -Catalog $Catalog -Reason $why -StandardReason ('a control-plane value on the updater job {0}' -f $UpdaterJob)
                foreach ($l in @($out.Outputs.Lines)) { & $say $l }
            }
        }
        if ($repVal) {
            # owner 2026-11-19: a shipped report switched off / on again, through the web app's own item statement
            if (-not (Get-Command -Name Get-SIProOutputColumnWriteSql -ErrorAction SilentlyContinue)) {
                $f = [IO.Path]::Combine($SIRoot, 'engine', 'pro-settings', 'SI-OutputColumnWrite.ps1')
                if (Test-Path -LiteralPath $f) { . $f }
            }
            if (-not (Get-Command -Name Get-SIProOutputColumnWriteSql -ErrorAction SilentlyContinue)) { & $say ('WARNING: control-plane value: {0} not applied -- this release carries no item writer' -f $n.Reports) }
            else {
                $allowR = Get-SIControlPlaneReportAllowList -SIRoot $SIRoot
                if ($allowR.Reports.Count -eq 0) { & $say ('WARNING: control-plane value: {0} not applied -- this release carries no report catalog' -f $n.Reports) }
                else {
                    $out | Add-Member -NotePropertyName Reports -NotePropertyValue (Invoke-SIControlPlaneReports -Store $Store -Json $repVal -Allow $allowR -Reason $why) -Force
                    foreach ($l in @($out.Reports.Lines)) { & $say $l }
                }
            }
        }
    } catch { & $say ('WARNING: control-plane values: not applied ({0}) -- the next update tries again' -f (([string]$_.Exception.Message) -split "`n")[0]) }
    $out.Lines = $siCpStepLines.ToArray()
    $out
}
