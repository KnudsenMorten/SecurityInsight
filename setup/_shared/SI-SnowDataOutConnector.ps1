#Requires -Version 5.1
<#
    SecurityInsight -- #903 (owner 2026-10-26: "if active they should be part of the data out for both cmdb and
    vulnerability"): ONE SERVICENOW CONNECTOR FEEDS BOTH DATA-OUT OUTPUTS -- existing installs reach the new-install state.

    THE NEW-INSTALL STATE: the ServiceNow Import Set outputs (servicenow-ci, servicenow-vulnerable-item) send through the
    ONE switched-on connector of kind servicenow + direction 'data-out' (always apply; Enabled = sends). Before, data out
    took a ServiceNow connector of the output's direction (cmdb for the CIs, the close-loop's vulnerability connector for the
    vulnerable items) -- switched on or not, its Mode ignored -- else the install's own ServiceNow secrets.

    THE RULE OF THIS STEP: KEEP EXACTLY WHAT IS SENT TODAY, make it visible, NEVER send anywhere new.
      * "today's connector" of an output = what data out picked before (Get-SISnowDataOutTodayPick: a valid ServiceNow row
        of the output's old direction, switched on first, then by name; none = the install's own secrets);
      * only while NO data-out connector exists yet (once one exists, a person owns it -- the step then only keeps it apply);
      * the connector the CI output uses today, and every servicenow + cmdb row named data-out-*, become direction data-out,
        Mode apply (names, references and settings kept). The one that feeds the outputs is switched ON only when a
        ServiceNow output is on in SI_DataOut_Outputs (it was sending through it, although it said "off"); else its switch
        is left as it is. Others are switched off (at most one on -- today's pick is the one kept);
      * no such row but a ServiceNow output on: a connector `servicenow-data-out` is CREATED from the secret NAMES in use
        today (the close-loop connector's, or the install's own SI-ServiceNow-Instance / -User / -Password) -- no value is
        ever read;
      * the outputs that are on went to DIFFERENT instances today (the vulnerable items through the close-loop's connector
        on another instance): the connector is made, but left SWITCHED OFF, and said -- nothing goes to the wrong place;
      * a converted row that names no credential gets the names the install's own lookup read (it signed in with them);
      * a table key in a data-out connector's settings (SI_DataOut_ServiceNowCiTable / SI_DataOut_ServiceNowVulnTable) is
        not read by anything: setting empty -> the value is copied into the setting, then the key removed; the same value
        -> the key is removed; a different value -> nothing changes (the setting stays in force, as it always was), said;
      * a servicenow + cmdb row with no sign of data out is the ServiceNow CMDB job's connector -- never touched.
    GUARDS: one transaction per connector with its cfg.ChangeLog row (Name 'connector/<name>', By 'SecurityInsight update',
    the reason in words), only while the row is unchanged since it was read (RowVersion), the one-on rule inside the
    transaction; a setting with its own cfg.ChangeLog row, only while it is still what was read. READ BACK afterwards. Never a
    delete, never a secret value, never an output switch (SI_DataOut_Outputs) changed, never a sql / rest / close-loop row,
    never a job. Pro only (the Pro database). Never throws (Invoke-SISnowDataOutConnectorOn); -WhatIf (-DetectOnly) plans only.
    PURE planning (Get-SISnowDataOutPlan) over a SQL seam.
#>

$script:SISnowDataOut = @{
    By       = 'SecurityInsight update'
    NewName  = 'servicenow-data-out'
    Outputs  = @('servicenow-ci', 'servicenow-vulnerable-item')
    Tables   = [ordered]@{ 'servicenow-ci' = 'SI_DataOut_ServiceNowCiTable'; 'servicenow-vulnerable-item' = 'SI_DataOut_ServiceNowVulnTable' }
    # the names the install's own ServiceNow lookup read (auth\Get-SIVaultName.ps1, canonical names)
    InstallRefs = [ordered]@{ instance = 'SI-ServiceNow-Instance'; user = 'SI-ServiceNow-User'; password = 'SI-ServiceNow-Password' }
}

function ConvertFrom-SISnowDataOutJson {
    <# PURE. A JSON object text -> an ordered hashtable (keys as written); empty / unreadable -> empty. #>
    param([AllowEmptyString()][AllowNull()][string]$Json)
    $h = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($Json)) { return $h }
    try { $o = ConvertFrom-Json -InputObject $Json } catch { return $h }
    if ($null -eq $o -or $o -isnot [psobject]) { return $h }
    foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value }
    $h
}

function Get-SISnowDataOutValue {
    <# PURE. A row's column (hashtable or object); DBNull = $null. #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = if ($Row -is [System.Collections.IDictionary]) { $Row[$Name] } else { $p = $Row.PSObject.Properties[$Name]; if ($p) { $p.Value } else { $null } }
    if ($v -is [System.DBNull]) { $null } else { $v }
}

function Get-SISnowDataOutKey {
    <# PURE. Where a ServiceNow row sends to, for comparing two of them: its instance URL, else its instance secret NAME. #>
    param($Row)
    if ($null -eq $Row) { return ('ref:' + $script:SISnowDataOut.InstallRefs.instance).ToLowerInvariant() }
    $s = ConvertFrom-SISnowDataOutJson ([string](Get-SISnowDataOutValue $Row 'SettingsJson'))
    $r = ConvertFrom-SISnowDataOutJson ([string](Get-SISnowDataOutValue $Row 'SecretRefsJson'))
    $ref = @($r.Keys | Where-Object { $_ -ieq 'instance' })
    if ($ref.Count -and "$($r[$ref[0]])".Trim()) { return ('ref:' + "$($r[$ref[0]])".Trim()).ToLowerInvariant() }
    $ins = @($s.Keys | Where-Object { $_ -ieq 'instance' })
    if ($ins.Count -and "$($s[$ins[0]])".Trim()) { return ("$($s[$ins[0]])".Trim().TrimEnd('/') -replace '^(?i)https?://', '').ToLowerInvariant() }
    # no instance named: before #903 it used the install's own instance
    ('ref:' + $script:SISnowDataOut.InstallRefs.instance).ToLowerInvariant()
}

function Test-SISnowDataOutOn {
    <# PURE. The ServiceNow outputs on in SI_DataOut_Outputs (a list, comma / semicolon separated; empty = every output's default -- off for both). #>
    param([AllowEmptyString()][AllowNull()][string]$Setting)
    $chosen = @(([string]$Setting) -split '[,;]' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    $on = [ordered]@{}
    foreach ($o in $script:SISnowDataOut.Outputs) { $on[$o] = ($chosen -contains $o) }
    $on
}

function Get-SISnowDataOutTodayPick {
    <#
        PURE. What data out used BEFORE #903 for one output: the valid ServiceNow row of -Direction (cmdb for the CIs, the
        close-loop's vulnerability for the vulnerable items), switched on first, then by name; $null = the install's own
        ServiceNow secrets. Validity as the engine reads a row (ConvertFrom-SIConnectorRow) when it is loaded; else the
        row's kind and direction only.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory)][string]$Direction)
    $list = foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $kind = ([string](Get-SISnowDataOutValue $r 'Kind')).Trim().ToLowerInvariant()
        $dir = ([string](Get-SISnowDataOutValue $r 'Direction')).Trim().ToLowerInvariant(); if (-not $dir) { $dir = 'vulnerability' }
        if ($kind -ne 'servicenow' -or $dir -ne $Direction) { continue }
        if (Get-Command -Name ConvertFrom-SIConnectorRow -ErrorAction SilentlyContinue) {
            $c = ConvertFrom-SIConnectorRow -Row $r
            # the #903 credential rule is new: a row that names half a credential could not sign in before either
            if (@($c.Problems | Where-Object { $_ -notmatch 'a user needs a password' }).Count) { continue }
        }
        $r
    }
    @(@($list) | Sort-Object -Property @{ Expression = { -not ([string](Get-SISnowDataOutValue $_ 'Enabled') -match '^(?i)(1|true)$') } }, @{ Expression = { [string](Get-SISnowDataOutValue $_ 'Name') } }) | Select-Object -First 1
}

function Get-SISnowDataOutPlan {
    <#
        PURE. -Rows: the cfg.Connector rows (Name, Kind, Direction, Enabled, Mode, AllowCreate, AllowClose, SettingsJson,
        SecretRefsJson, Ver = the RowVersion as a number). -Settings: @{ SI_DataOut_Outputs; SI_DataOut_ServiceNowCiTable;
        SI_DataOut_ServiceNowVulnTable } (values as text, $null = not set; SettingVer = @{ name = the ValueJson read }).
        Returns @{ Updates (connector rows to write: Name, Expected, Direction, Enabled, Mode, SettingsJson, SecretRefsJson,
        Reason); Inserts (new connectors); Settings (Name, Expected (the ValueJson read), New (ValueJson), Reason);
        Lines (what is said); Warnings }.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$Settings = @{})
    $g = { param($n) if ($Settings.ContainsKey($n) -and $null -ne $Settings[$n]) { ([string]$Settings[$n]).Trim() } else { '' } }
    $bit = { param($v) [string]$v -match '^(?i)(1|true)$' }
    $updates = New-Object System.Collections.Generic.List[object]; $inserts = New-Object System.Collections.Generic.List[object]
    $sets = New-Object System.Collections.Generic.List[object]; $lines = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $on = Test-SISnowDataOutOn -Setting (& $g 'SI_DataOut_Outputs')
    $anyOn = [bool]($on['servicenow-ci'] -or $on['servicenow-vulnerable-item'])
    $snow = @(@($Rows) | Where-Object { $_ -and ([string](Get-SISnowDataOutValue $_ 'Kind')).Trim() -ieq 'servicenow' })
    $dirOf = { param($r) $d = ([string](Get-SISnowDataOutValue $r 'Direction')).Trim().ToLowerInvariant(); if ($d) { $d } else { 'vulnerability' } }
    $dataOut = @($snow | Where-Object { (& $dirOf $_) -eq 'data-out' })
    # the row as it will be written: start from what is there
    $final = [ordered]@{}
    $want = {
        param($r, [string]$why)
        $n = [string](Get-SISnowDataOutValue $r 'Name')
        if (-not $final.Contains($n)) {
            $final[$n] = [ordered]@{ Name = $n; Expected = (Get-SISnowDataOutValue $r 'Ver'); Direction = (& $dirOf $r); Enabled = (& $bit (Get-SISnowDataOutValue $r 'Enabled'))
                                     Mode = ([string](Get-SISnowDataOutValue $r 'Mode')).Trim().ToLowerInvariant(); SettingsJson = [string](Get-SISnowDataOutValue $r 'SettingsJson')
                                     SecretRefsJson = [string](Get-SISnowDataOutValue $r 'SecretRefsJson'); Reasons = (New-Object System.Collections.Generic.List[string]); Row = $r }
        }
        if ($why) { $final[$n].Reasons.Add($why) }
        $final[$n]
    }

    if ($dataOut.Count -eq 0) {
        $ciPick = Get-SISnowDataOutTodayPick -Rows $snow -Direction cmdb
        $viPick = Get-SISnowDataOutTodayPick -Rows $snow -Direction vulnerability
        $ciTable = & $g 'SI_DataOut_ServiceNowCiTable'
        # the rows that served data out: the CI output's connector (when the output is on or has a table), and every
        # servicenow + cmdb row named data-out-*
        $convert = New-Object System.Collections.Generic.List[object]
        if ($ciPick -and ($on['servicenow-ci'] -or $ciTable)) { $convert.Add($ciPick) }
        foreach ($r in @($snow | Where-Object { (& $dirOf $_) -eq 'cmdb' -and ([string](Get-SISnowDataOutValue $_ 'Name')) -like 'data-out-*' })) {
            if (-not @($convert | Where-Object { [string](Get-SISnowDataOutValue $_ 'Name') -eq [string](Get-SISnowDataOutValue $r 'Name') }).Count) { $convert.Add($r) }
        }
        # where each output that is on went today ($null row = the install's own secrets)
        $used = [ordered]@{}
        if ($on['servicenow-ci']) { $used['servicenow-ci'] = $ciPick }
        if ($on['servicenow-vulnerable-item']) { $used['servicenow-vulnerable-item'] = $viPick }
        $keys = @($used.Keys | ForEach-Object { Get-SISnowDataOutKey $used[$_] } | Select-Object -Unique)
        $mixed = $keys.Count -gt 1
        if ($convert.Count) {
            $primary = if ($ciPick -and @($convert | Where-Object { [string](Get-SISnowDataOutValue $_ 'Name') -eq [string](Get-SISnowDataOutValue $ciPick 'Name') }).Count) { $ciPick } else { $convert[0] }
            $pName = [string](Get-SISnowDataOutValue $primary 'Name')
            # the vulnerable items went elsewhere than this connector: they would move -- never; it stays off, said
            $moves = $on['servicenow-vulnerable-item'] -and ((Get-SISnowDataOutKey $viPick) -ne (Get-SISnowDataOutKey $primary))
            foreach ($r in $convert) {
                $n = [string](Get-SISnowDataOutValue $r 'Name')
                $f = & $want $r ''
                $f.Direction = 'data-out'; $f.Mode = 'apply'
                $f.Reasons.Add('one ServiceNow connector feeds both data-out outputs -- this connector served the ServiceNow data out, so its direction is now data-out (always apply; it is never run by the vulnerability close-loop)')
                # it signed in with the install's own credential when it named none
                $refs = ConvertFrom-SISnowDataOutJson $f.SecretRefsJson
                $named = @($refs.Keys | Where-Object { $_ -in @('apikey', 'user', 'password') }).Count
                if (-not $named) {
                    foreach ($k in @('user', 'password')) { $refs[$k] = $script:SISnowDataOut.InstallRefs[$k] }
                    $hasInst = @($refs.Keys | Where-Object { $_ -ieq 'instance' }).Count -or @((ConvertFrom-SISnowDataOutJson $f.SettingsJson).Keys | Where-Object { $_ -ieq 'instance' }).Count
                    if (-not $hasInst) { $refs['instance'] = $script:SISnowDataOut.InstallRefs.instance }
                    $f.SecretRefsJson = ConvertTo-Json -InputObject $refs -Compress
                    $f.Reasons.Add('it named no credential and signed in with the install''s own ServiceNow secrets -- those secret NAMES are now on the connector')
                }
                if ($n -eq $pName) {
                    if ($moves -or $mixed) {
                        if ($f.Enabled) { $f.Enabled = $false; $f.Reasons.Add('switched off: the ServiceNow outputs that are on went to different instances before -- switch it on on its page once its instance is the right one') }
                        $warnings.Add(("connectors: the ServiceNow data-out connector '{0}' is left SWITCHED OFF -- the vulnerable items went to another ServiceNow instance before (through the close-loop's connector), and this connector points elsewhere. Nothing is sent to ServiceNow until a person checks its instance and switches it on (Connectors > {0})." -f $n))
                    } elseif ($anyOn -and -not $f.Enabled) {
                        $f.Enabled = $true
                        $f.Reasons.Add('switched on: a ServiceNow output is on (SI_DataOut_Outputs) and this connector was what it sent through, although it said off -- what is sent does not change')
                    }
                } elseif ($f.Enabled) {
                    $f.Enabled = $false
                    $f.Reasons.Add(('switched off: at most one ServiceNow data-out connector is on, and data out sent through {0} -- what is sent does not change' -f $pName))
                }
                $lines.Add(("connectors: '{0}' is now the ServiceNow data-out connector{1}" -f $n, $(if ($n -eq $pName) { $(if ($f.Enabled) { ' (switched on -- it feeds both ServiceNow outputs)' } else { ' (switched off)' }) } else { ' (switched off)' })))
            }
        } elseif ($anyOn) {
            # no row served data out: a connector from the names in use today
            $src = if ($on['servicenow-vulnerable-item'] -and $viPick) { $viPick } elseif ($on['servicenow-ci'] -and $ciPick) { $ciPick } else { $null }
            $refs = [ordered]@{}; $set = [ordered]@{}
            if ($src) {
                $sr = ConvertFrom-SISnowDataOutJson ([string](Get-SISnowDataOutValue $src 'SecretRefsJson'))
                foreach ($k in @($sr.Keys)) { if ($k -in @('instance', 'apikey', 'user', 'password')) { $refs[$k] = $sr[$k] } }
                $ss = ConvertFrom-SISnowDataOutJson ([string](Get-SISnowDataOutValue $src 'SettingsJson'))
                foreach ($k in @($ss.Keys)) { if ($k -ieq 'instance') { $set['instance'] = $ss[$k] } }
            }
            if (-not @($refs.Keys | Where-Object { $_ -in @('apikey', 'user', 'password') }).Count) { foreach ($k in @('user', 'password')) { $refs[$k] = $script:SISnowDataOut.InstallRefs[$k] } }
            if (-not $refs.Contains('instance') -and -not $set.Contains('instance')) { $refs['instance'] = $script:SISnowDataOut.InstallRefs.instance }
            $name = $script:SISnowDataOut.NewName
            if (@($Rows | Where-Object { [string](Get-SISnowDataOutValue $_ 'Name') -eq $name }).Count) { $name = $name + '-1' }
            $from = if ($src) { ('the secret names of the connector {0}' -f (Get-SISnowDataOutValue $src 'Name')) } else { 'the install''s own ServiceNow secret names' }
            $reason = ('one ServiceNow connector feeds both data-out outputs -- created from {0}, which the ServiceNow data out signed in with before' -f $from)
            if ($mixed) { $reason += '; left SWITCHED OFF: the ServiceNow outputs that are on went to different instances before' }
            $inserts.Add([pscustomobject]@{ Name = $name; Kind = 'servicenow'; Direction = 'data-out'; Enabled = (-not $mixed); Mode = 'apply'
                                            SettingsJson = $(if ($set.Count) { ConvertTo-Json -InputObject $set -Compress } else { $null }); SecretRefsJson = (ConvertTo-Json -InputObject $refs -Compress); Reason = $reason })
            if ($mixed) { $warnings.Add(("connectors: the ServiceNow data-out connector '{0}' was created SWITCHED OFF -- the ServiceNow outputs that are on went to different ServiceNow instances before. Nothing is sent to ServiceNow until a person checks its instance and switches it on (Connectors > {0})." -f $name)) }
            else { $lines.Add(("connectors: '{0}' was created from {1} -- the ServiceNow data-out connector, switched on; it feeds both ServiceNow outputs (what is sent does not change)" -f $name, $from)) }
        }
        foreach ($r in @($snow | Where-Object { (& $dirOf $_) -eq 'cmdb' })) {
            $n = [string](Get-SISnowDataOutValue $r 'Name')
            if (-not $final.Contains($n)) { $lines.Add(("connectors: '{0}' (servicenow, cmdb) is the ServiceNow CMDB job's connector -- not touched; the ServiceNow data out no longer reads it" -f $n)) }
        }
    }

    # every data-out connector (existing, or converted above): always apply, and no table key in its settings
    $doNames = @($dataOut | ForEach-Object { [string](Get-SISnowDataOutValue $_ 'Name') })
    $doRows = @($dataOut) + @($final.Values | Where-Object { $_.Direction -eq 'data-out' -and $doNames -notcontains $_.Name } | ForEach-Object { $_.Row })
    foreach ($r in $doRows) {
        $f = & $want $r ''
        if ($f.Mode -ne 'apply') { $f.Mode = 'apply'; $f.Reasons.Add('a ServiceNow data-out connector is always apply -- data out has no test mode (it always sent; the mode was never read)') }
        $s = ConvertFrom-SISnowDataOutJson $f.SettingsJson
        $changed = $false
        foreach ($o in $script:SISnowDataOut.Outputs) {
            $setting = $script:SISnowDataOut.Tables[$o]
            $k = @($s.Keys | Where-Object { $_ -ieq $setting }) | Select-Object -First 1
            if (-not $k) { continue }
            $val = ([string]$s[$k]).Trim(); $cur = & $g $setting
            if (-not $val -or $val -eq $cur) {
                $s.Remove($k); $changed = $true
                $f.Reasons.Add(('the key {0} in its settings was never read (the table is the setting {0}, which holds the same value) -- removed' -f $setting))
            } elseif (-not $cur) {
                $exp = if ($Settings.ContainsKey('SettingVer') -and $Settings['SettingVer'] -and $Settings['SettingVer'].Contains($setting)) { $Settings['SettingVer'][$setting] } else { $null }
                $sets.Add([pscustomobject]@{ Name = $setting; Expected = $exp; New = (ConvertTo-Json -InputObject $val -Compress)
                                             Reason = ('the Import Set table was named only in the ServiceNow data-out connector {0}''s settings, where nothing read it -- now in the setting, which is where the table is read from' -f $f.Name) })
                $lines.Add(("connectors: the Import Set table {0} named in '{1}' is now the setting {2} (the next update removes the unread key)" -f $val, $f.Name, $setting))
            } else {
                $warnings.Add(("connectors: '{0}' names the Import Set table {1} in its settings, but the setting {2} is {3} -- the setting is what is used (as always); nothing was changed. Remove the key on the connector, or change the setting." -f $f.Name, $val, $setting, $cur))
            }
        }
        if ($changed) { $f.SettingsJson = $(if ($s.Count) { ConvertTo-Json -InputObject $s -Compress -Depth 10 } else { $null }) }
    }
    foreach ($f in $final.Values) {
        $r = $f.Row
        $same = ($f.Direction -eq (& $dirOf $r)) -and ($f.Enabled -eq (& $bit (Get-SISnowDataOutValue $r 'Enabled'))) -and ($f.Mode -eq ([string](Get-SISnowDataOutValue $r 'Mode')).Trim().ToLowerInvariant()) -and
                ("$($f.SettingsJson)" -eq "$(Get-SISnowDataOutValue $r 'SettingsJson')") -and ("$($f.SecretRefsJson)" -eq "$(Get-SISnowDataOutValue $r 'SecretRefsJson')")
        if ($same) { continue }
        $updates.Add([pscustomobject]@{ Name = $f.Name; Expected = $f.Expected; Direction = $f.Direction; Enabled = [bool]$f.Enabled; Mode = $f.Mode
                                        SettingsJson = $(if ("$($f.SettingsJson)".Trim()) { $f.SettingsJson } else { $null }); SecretRefsJson = $(if ("$($f.SecretRefsJson)".Trim()) { $f.SecretRefsJson } else { $null })
                                        Reason = ((@($f.Reasons) | Select-Object -Unique) -join '; ') })
    }
    $onAfter = @(@($final.Values | Where-Object { $_.Direction -eq 'data-out' -and $_.Enabled } | ForEach-Object { $_.Name }) + @($dataOut | Where-Object { -not $final.Contains([string](Get-SISnowDataOutValue $_ 'Name')) -and (& $bit (Get-SISnowDataOutValue $_ 'Enabled')) } | ForEach-Object { [string](Get-SISnowDataOutValue $_ 'Name') }) + @($inserts | Where-Object { $_.Enabled } | ForEach-Object { $_.Name }))
    if ($onAfter.Count -gt 1) { $warnings.Add(("connectors: {0} ServiceNow data-out connectors are switched on ({1}) -- nothing is sent to ServiceNow until one is switched off (Connectors)" -f $onAfter.Count, ($onAfter -join ', '))) }
    # switch-offs first, so the one-on rule holds after every single write
    $ordered = @(@($updates | Where-Object { -not $_.Enabled }) + @($updates | Where-Object { $_.Enabled }))
    [pscustomobject]@{ Updates = $ordered; Inserts = $inserts.ToArray(); Settings = $sets.ToArray(); Lines = $lines.ToArray(); Warnings = $warnings.ToArray() }
}

function Get-SISnowDataOutSql {
    <#
        The Pro database's statements. 'Read': the connectors (none when the table does not exist); 'ReadSettings': the
        three settings; 'Update' (-Item): ONE transaction -- the row written with its cfg.ChangeLog row, only while it is
        unchanged since it was read (RowVersion), refused when two data-out connectors would be on; 'Insert' (-Item): the
        new connector, only while no row has the name; 'Setting' (-Item): the setting with its cfg.ChangeLog row, only while
        it is still what was read. Each returns Outcome 'changed' | 'stale' | 'conflict'. Returns @{ Sql; Params }.
    #>
    param([Parameter(Mandatory)][ValidateSet('Read', 'ReadSettings', 'Update', 'Insert', 'Setting')][string]$Statement, $Item, [string]$By = $script:SISnowDataOut.By)
    $guard = @'
IF (SELECT COUNT(*) FROM cfg.Connector WHERE LOWER(Kind) = N'servicenow' AND LOWER(Direction) = N'data-out' AND Enabled = 1) > 1
BEGIN
    ROLLBACK;
    SELECT N'conflict' AS Outcome;
    RETURN;
END;
'@
    $json = 'SELECT c.Name, c.Kind, c.Direction, c.Enabled, c.Mode, c.AllowCreate, c.AllowClose, c.SettingsJson, c.SecretRefsJson, c.MappingJson'
    switch ($Statement) {
        'Read' {
            return [pscustomobject]@{ Params = @{}; Sql = @'
IF OBJECT_ID(N'cfg.Connector') IS NOT NULL
SELECT Name, Kind, Direction, CONVERT(int, Enabled) AS Enabled, Mode, CONVERT(int, AllowCreate) AS AllowCreate, CONVERT(int, AllowClose) AS AllowClose,
       SettingsJson, SecretRefsJson, CONVERT(bigint, RowVersion) AS Ver
FROM cfg.Connector ORDER BY Name;
'@ }
        }
        'ReadSettings' {
            return [pscustomobject]@{ Params = @{}; Sql = @'
IF OBJECT_ID(N'cfg.Setting') IS NOT NULL
SELECT Name, ValueJson FROM cfg.Setting
WHERE Scope = N'solution' AND Name IN (N'SI_DataOut_Outputs', N'SI_DataOut_ServiceNowCiTable', N'SI_DataOut_ServiceNowVulnTable');
'@ }
        }
        'Update' {
            return [pscustomobject]@{ Params = [ordered]@{ Name = [string]$Item.Name; Expected = $Item.Expected; Direction = [string]$Item.Direction; Enabled = [bool]$Item.Enabled; Mode = [string]$Item.Mode
                                                          SettingsJson = $Item.SettingsJson; SecretRefsJson = $Item.SecretRefsJson; By = $By; Reason = [string]$Item.Reason }; Sql = @"
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = ($json
    FROM cfg.Connector c WITH (UPDLOCK, HOLDLOCK)
    WHERE c.Name = @Name AND LOWER(c.Kind) = N'servicenow' AND CONVERT(bigint, c.RowVersion) = @Expected
    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER);
IF @old IS NULL
BEGIN
    COMMIT;
    SELECT N'stale' AS Outcome;
    RETURN;
END;
UPDATE cfg.Connector SET Direction = @Direction, Enabled = @Enabled, Mode = @Mode, SettingsJson = @SettingsJson, SecretRefsJson = @SecretRefsJson,
       UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
WHERE Name = @Name;
$guard
DECLARE @new nvarchar(max) = ($json FROM cfg.Connector c WHERE c.Name = @Name FOR JSON PATH, WITHOUT_ARRAY_WRAPPER);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (N'connector/' + @Name, N'connector', N'connector', N'Set', @old, @new, @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'changed' AS Outcome;
"@ }
        }
        'Insert' {
            return [pscustomobject]@{ Params = [ordered]@{ Name = [string]$Item.Name; Enabled = [bool]$Item.Enabled; SettingsJson = $Item.SettingsJson; SecretRefsJson = $Item.SecretRefsJson; By = $By; Reason = [string]$Item.Reason }; Sql = @"
SET XACT_ABORT ON;
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM cfg.Connector WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name)
BEGIN
    COMMIT;
    SELECT N'stale' AS Outcome;
    RETURN;
END;
INSERT cfg.Connector (Name, Kind, Direction, Enabled, Mode, AllowCreate, AllowClose, SettingsJson, SecretRefsJson, MappingJson, CreatedBy, UpdatedBy)
VALUES (@Name, N'servicenow', N'data-out', @Enabled, N'apply', 0, 0, @SettingsJson, @SecretRefsJson, NULL, @By, @By);
$guard
DECLARE @new nvarchar(max) = ($json FROM cfg.Connector c WHERE c.Name = @Name FOR JSON PATH, WITHOUT_ARRAY_WRAPPER);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (N'connector/' + @Name, N'connector', N'connector', N'Set', NULL, @new, @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'changed' AS Outcome;
"@ }
        }
        'Setting' {
            return [pscustomobject]@{ Params = [ordered]@{ N = [string]$Item.Name; Expected = $Item.Expected; V = [string]$Item.New; By = $By; Reason = [string]$Item.Reason }; Sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT ValueJson FROM cfg.Setting WITH (UPDLOCK, HOLDLOCK) WHERE Name = @N AND Scope = N'solution');
IF NOT ((@old IS NULL AND @Expected IS NULL) OR (@old IS NOT NULL AND @Expected IS NOT NULL AND @old = @Expected))   -- never NULL-unknown: a value read as NULL that is set now is stale
BEGIN
    COMMIT;
    SELECT N'stale' AS Outcome;
    RETURN;
END;
IF EXISTS (SELECT 1 FROM cfg.Setting WHERE Name = @N AND Scope = N'solution')
    UPDATE cfg.Setting SET ValueJson = @V, KeyVaultSecretName = NULL, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @N AND Scope = N'solution';
ELSE
    INSERT cfg.Setting (Name, Scope, ValueJson, KeyVaultSecretName, UpdatedBy) VALUES (@N, N'solution', @V, NULL, @By);
INSERT cfg.ChangeLog (Name, Scope, Action, OldValue, NewValue, ChangedBy, Reason) VALUES (@N, N'solution', N'Set', @old, @V, @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'changed' AS Outcome;
'@ }
        }
    }
}

function Read-SISnowDataOutState {
    <# The connectors and the three settings, through the seam. Returns @{ Rows; Settings }. #>
    param([Parameter(Mandatory)][scriptblock]$Sql)
    $norm = { param($x) @($x | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } }) }
    $q = Get-SISnowDataOutSql -Statement Read
    $rows = & $norm (& $Sql $q.Sql $q.Params 'reader')
    $qs = Get-SISnowDataOutSql -Statement ReadSettings
    $set = @{ SettingVer = @{} }
    foreach ($s in (& $norm (& $Sql $qs.Sql $qs.Params 'reader'))) {
        $n = [string]$s.Name; $vj = $s.ValueJson; if ($vj -is [System.DBNull]) { $vj = $null }
        $set['SettingVer'][$n] = $vj
        $v = $null
        if ($null -ne $vj -and "$vj".Trim()) { try { $v = ConvertFrom-Json -InputObject ([string]$vj) } catch { $v = [string]$vj } }
        $set[$n] = $(if ($v -is [array]) { ($v -join ';') } elseif ($null -ne $v) { [string]$v } else { $null })
    }
    [pscustomobject]@{ Rows = $rows; Settings = $set }
}

function Invoke-SISnowDataOutConnectorOn {
    <#
        The Pro database's part. -Sql { param($Query, $Params, $Mode) } ('reader' -> rows). Never throws.
        Returns @{ Action = none | changed | plan | failed; Changed = @(names); Lines; Warnings }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [switch]$WhatIf)
    $norm = { param($x) @($x | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } }) }
    $out = { param($a, $c, $l, $w) [pscustomobject]@{ Action = $a; Changed = @($c); Lines = @($l); Warnings = @($w) } }
    try {
        $st = Read-SISnowDataOutState -Sql $Sql
        $plan = Get-SISnowDataOutPlan -Rows $st.Rows -Settings $st.Settings
        $todo = @($plan.Updates).Count + @($plan.Inserts).Count + @($plan.Settings).Count
        if (-not $todo) { return (& $out 'none' @() @() @($plan.Warnings)) }
        if ($WhatIf) { return (& $out 'plan' @() @($plan.Lines | ForEach-Object { '{0} (re-run with -Apply)' -f $_ }) @($plan.Warnings)) }
        $done = New-Object System.Collections.Generic.List[string]; $warn = New-Object System.Collections.Generic.List[string]
        foreach ($w in @($plan.Warnings)) { $warn.Add($w) }
        $run = {
            param($stmt, $item)
            $q = Get-SISnowDataOutSql -Statement $stmt -Item $item
            $o = [string](@(& $norm (& $Sql $q.Sql $q.Params 'reader')) | ForEach-Object { $_.Outcome } | Select-Object -First 1)
            if ($o -eq 'changed') { $done.Add([string]$item.Name) }
            elseif ($o -eq 'conflict') { $warn.Add(("connectors: '{0}' was not changed -- two ServiceNow data-out connectors would have been switched on" -f $item.Name)) }
            else { $warn.Add(("connectors: '{0}' changed while the update read it -- not touched; the next update looks again" -f $item.Name)) }
        }
        # 1. the settings first (a table key is removed only once its setting holds the value)
        foreach ($s in @($plan.Settings)) { & $run 'Setting' $s }
        if (@($plan.Settings).Count) { $st = Read-SISnowDataOutState -Sql $Sql; $plan = Get-SISnowDataOutPlan -Rows $st.Rows -Settings $st.Settings }
        # 2. the connectors: switch-offs first, then the rest, then the new one
        foreach ($u in @($plan.Updates)) { & $run 'Update' $u }
        foreach ($i in @($plan.Inserts)) { & $run 'Insert' $i }
        # READ BACK: nothing the plan wanted is left undone
        $after = Read-SISnowDataOutState -Sql $Sql
        $left = Get-SISnowDataOutPlan -Rows $after.Rows -Settings $after.Settings
        $still = @(@($left.Updates | ForEach-Object { $_.Name }) + @($left.Inserts | ForEach-Object { $_.Name }) + @($left.Settings | ForEach-Object { $_.Name }))
        if ($still.Count) {
            $warn.Add(('connectors: {0} did not reach the new state after the update wrote it -- check Connectors; the next update tries again' -f (($still | Select-Object -Unique | ForEach-Object { "'$_'" }) -join ', ')))
            return (& $out 'failed' $done.ToArray() @($plan.Lines) $warn.ToArray())
        }
        & $out 'changed' $done.ToArray() @($plan.Lines) $warn.ToArray()
    } catch {
        & $out 'failed' @() @() @(('connectors: the ServiceNow data-out connector was not checked ({0}) -- the update goes on; the next update tries again' -f $_.Exception.Message))
    }
}
