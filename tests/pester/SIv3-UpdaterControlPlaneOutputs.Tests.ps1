#Requires -Version 5.1
<#
    SI_UPDATER_OUTPUTS -- WHAT AN OUTPUT SENDS, SWITCHED PER INSTALL THROUGH THE UPDATER (owner 2026-11-16: the new
    ServiceNow columns / outputs are switched on per install through the updater, never an ops SQL write; Invardia ruling
    2026-11-15). setup\_shared\SI-ControlPlaneValues.ps1 (Invoke-SIControlPlaneOutputs) + engine\pro-settings\
    SI-OutputColumnWrite.ps1 (the web app's own output-column statement):
      * PARSE + ALLOW-LIST: the list is DERIVED from the release (the columns an output map ships "off": true, the outputs
        config\data-out.locked.json lists for Pro, not 'fixed'); bad JSON / not one object / an unknown output / an unknown
        column / a column always sent / a fixed output / a column named on and off are each refused in ONE warning line,
        the rest still applies; a column is named by its target or by the field it reads;
      * THE SAME ROW AS AN ADMIN'S CHANGE: the statement is ItemOverrideRepository.WriteSql character for character, the
        parameters are its WriteAsync parameters, the body is OutputMapRules.Body -- the row the update writes equals the
        row the admin path writes through the same store; ChangedBy 'the update (control-plane value)', the reason, the
        change-log row; READ BACK;
      * IDEMPOTENT: an equal state = nothing written (an Admin's own change of a column that is on is never overwritten);
      * THE OUTPUT ITSELF: SI_DataOut_Outputs through Set-SIProSetting, as the web app's switch computes it (the defaults
        again = the row reset);
      * EFFECT: switched on, the run's data model (template + override through the real merge and the run folder) sends the
        column -- the push row carries the mapper's value and the hand-off view gets the column; switched off again, or the
        env absent, nothing changes;
      * WIRING: Invoke-SIControlPlaneValues runs it after the settings; the real Start-SIUpdater step reaches it; the updater
        image carries the writer, the output maps and the data-out catalog.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Lib = [IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-ControlPlaneValues.ps1')
    . ([IO.Path]::Combine($script:SIRoot, 'engine', 'pro-settings', 'SI-ProSettingWrite.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', 'pro-settings', 'SI-OutputColumnWrite.ps1'))
    . $script:Lib
    $script:Catalog = @(Get-SISettingsCatalog -SIRoot $script:SIRoot)
    $script:Allow = Get-SIControlPlaneOutputAllowList -SIRoot $script:SIRoot
    $script:VI = 'servicenow-vulnerable-item'
    $script:ViMap = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'data-model', 'outputs', 'servicenow-vulnerable-item.locked.json')))
    $script:ShippedOff = @($script:ViMap.columns | Where-Object { $_.PSObject.Properties['off'] -and $_.off -eq $true } | ForEach-Object { [string]$_.target })
    $script:CsRepo = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'pro-management', 'src', 'SI.Management.Web', 'Changes', 'ItemOverrideRepository.cs'))
    function script:Norm([string]$t) { ($t -replace "`r`n", "`n").Trim() }
    function script:CsConst([string]$name) {
        $m = [regex]::Match($script:CsRepo, ('public const string {0} = """\r?\n(.*?)\r?\n""";' -f $name), [System.Text.RegularExpressions.RegexOptions]::Singleline)
        $m.Success | Should -BeTrue -Because "ItemOverrideRepository.$name is a raw string constant"
        Norm $m.Groups[1].Value
    }

    # An in-memory Pro store: cfg.ItemOverride + cfg.Template (BaseVersion / BaseHash) + cfg.Setting + cfg.ChangeLog, for
    # exactly the statements this path sends (the web app's override statement is EMULATED as T-SQL would run it).
    function script:New-OutStore {
        param([hashtable]$Templates = @{})
        $W = @{ Items = @{}; Settings = @{}; Templates = $Templates; ChangeLog = (New-Object System.Collections.Generic.List[object]); Writes = 0; Sql = (New-Object System.Collections.Generic.List[string]); State = @{} }
        $writeSql = Norm (Get-SIProOutputColumnWriteSql); $readSql = Norm (Get-SIProOutputColumnReadSql)
        $inv = {
            param([string]$sql, $p, [string]$mode)
            $W.Sql.Add($sql)
            $t = ($sql -replace "`r`n", "`n").Trim()
            if ($t -ceq $readSql) {
                $k = '{0}|{1}' -f $p.Kind, $p.Key
                if ($W.Items.ContainsKey($k)) { $r = $W.Items[$k]; return , @(@{ Kind = $r.Kind; ItemKey = $r.ItemKey; State = $r.State; BodyJson = $r.BodyJson; Format = $r.Format; BaseVersion = $r.BaseVersion; BaseHash = $r.BaseHash; UpdatedBy = $r.UpdatedBy }) }
                return , @()
            }
            if ($t -ceq $writeSql) {
                $k = '{0}|{1}' -f $p.Kind, $p.Key
                $old = $null; if ($W.Items.ContainsKey($k)) { $o = $W.Items[$k]; $old = $o.State + $(if ($null -ne $o.BodyJson) { ':' + $o.BodyJson } else { '' }) }
                $bv = $null; $bh = $null
                if ($W.Templates.ContainsKey($p.Key)) { $bv = $W.Templates[$p.Key].Version; $bh = $W.Templates[$p.Key].Hash }
                if ($p.State -eq 'inherit') { $null = $W.Items.Remove($k) }
                else { $W.Items[$k] = [pscustomobject]@{ Kind = $p.Kind; ItemKey = $p.Key; State = $p.State; BodyJson = $p.Body; Format = $p.Format; BaseVersion = $bv; BaseHash = $bh; UpdatedBy = $p.By } }
                $W.ChangeLog.Add([pscustomobject]@{ Name = $p.Key; Scope = 'item'; Kind = $p.Kind; Action = $(if ($p.State -eq 'inherit') { 'Reset' } else { 'Set' }); Old = $old
                    New = $p.State + $(if ($null -ne $p.Body) { ':' + $p.Body } else { '' }); By = $p.By; Reason = $p.Reason })
                $W.Writes++
                return , @(@{ Outcome = 'Saved' })
            }
            if ($sql -match 'SELECT ValueJson FROM cfg\.Setting') {
                $k = '{0}|{1}' -f $p.Name, $p.Scope
                if ($W.Settings.ContainsKey($k)) { return , @(@{ ValueJson = $W.Settings[$k] }) }
                return , @()
            }
            if ($sql -match 'INSERT cfg\.Setting') {
                $k = '{0}|{1}' -f $p.Name, $p.Scope
                $old = if ($W.Settings.ContainsKey($k)) { $W.Settings[$k] } else { $null }
                if ($p.Action -eq 'Reset') { $null = $W.Settings.Remove($k) } else { $W.Settings[$k] = $p.ValueJson }
                $W.ChangeLog.Add([pscustomobject]@{ Name = $p.Name; Scope = $p.Scope; Kind = $null; Action = $p.Action; Old = $old; New = $p.ValueJson; By = $p.By; Reason = $p.Reason }); $W.Writes++; return
            }
            # cfg.InstallState: the applied value's hash (once per value) -- not counted as a write of the outputs
            if ($sql -match 'SELECT Value FROM cfg\.InstallState') {
                if ($W.State.ContainsKey($p.Name)) { return , @(@{ Value = $W.State[$p.Name].Value }) }
                return , @()
            }
            if ($sql -match 'MERGE cfg\.InstallState') { $W.State[$p.Name] = [pscustomobject]@{ Value = $p.Value; By = $p.By }; return }
            throw ('the fake store does not know this statement: ' + $sql)
        }.GetNewClosure()
        [pscustomobject]@{ Invoke = $inv; W = $W }
    }
    function script:Row($st, [string]$target, [string]$output = 'servicenow-vulnerable-item') { $st.W.Items[('datamodel|outputs/{0}:{1}' -f $output, $target)] }
    $script:Quiet = { param($m) }
    # who asked and why, as Invardia sets it
    $script:Who = 'Owner: new ServiceNow columns approved'
}

Describe 'the allow-list is derived from what the release ships' {
    It 'the vulnerable items: exactly the columns its map ships switched off; a contract column is never on it' {
        $script:ShippedOff.Count | Should -BeGreaterThan 0
        @($script:Allow.Outputs[$script:VI].Columns.Keys) | Should -Be $script:ShippedOff
        $script:Allow.Outputs[$script:VI].Columns.Contains('u_vulnerability') | Should -BeFalse
        $script:Allow.Outputs[$script:VI].Columns.Contains('u_si_category') | Should -BeTrue
    }
    It 'every output of the data-out catalog is listed; the fixed one is marked fixed' {
        $cat = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'config', 'data-out.locked.json')))
        @($script:Allow.Outputs.Keys) | Should -Be @($cat.outputs | ForEach-Object { [string]$_.output })
        $script:Allow.Outputs['sql-vulnerability-target'].Fixed | Should -BeTrue
    }
    It 'a map that ships a column off is picked up without a code change (a release adds one)' {
        $root = Join-Path $TestDrive 'rel'
        $null = New-Item -ItemType Directory -Force -Path ([IO.Path]::Combine($root, 'config')), ([IO.Path]::Combine($root, 'data-model', 'outputs'))
        [IO.File]::WriteAllText([IO.Path]::Combine($root, 'config', 'data-out.locked.json'), '{"outputs":[{"output":"servicenow-remediation-task","kind":"servicenow-importset","editions":["pro"],"default":false}]}')
        [IO.File]::WriteAllText([IO.Path]::Combine($root, 'data-model', 'outputs', 'servicenow-remediation-task.locked.json'), '{"kind":"output-map","id":"servicenow-remediation-task","columns":[{"target":"u_a","from":"si_ci_id"},{"target":"u_b","from":"extra.si_tier","off":true}]}')
        $a = Get-SIControlPlaneOutputAllowList -SIRoot $root
        @($a.Outputs['servicenow-remediation-task'].Columns.Keys) | Should -Be @('u_b')
        $p = ConvertFrom-SIControlPlaneOutputs -Json '{"servicenow-remediation-task":{"output":"on","on":["si_tier"]}}' -Allow $a
        @($p.Refused).Count | Should -Be 0
        $p.Outputs[0].Output | Should -Be 'servicenow-remediation-task'; $p.Outputs[0].On | Should -BeTrue
        $p.Columns[0].Target | Should -Be 'u_b'
    }
}

Describe 'the env is parsed; what may not be switched this way is refused in one line each' {
    It 'a column by its target or by the field it reads (extra. optional, any case); the output on / off' {
        $p = ConvertFrom-SIControlPlaneOutputs -Json '{"servicenow-vulnerable-item":{"on":["si_security_domain","u_si_category","extra.si_tier","SI_RISK_SCORE"],"off":["u_si_report"]},"servicenow-ci":{"output":"on"}}' -Allow $script:Allow
        @($p.Refused).Count | Should -Be 0
        @($p.Columns | Where-Object On | ForEach-Object Target) | Should -Be @('u_si_security_domain', 'u_si_category', 'u_si_risk_score', 'u_si_tier')
        @($p.Columns | Where-Object { -not $_.On } | ForEach-Object Target) | Should -Be @('u_si_report')
        $p.Outputs[0].Output | Should -Be 'servicenow-ci'; $p.Outputs[0].On | Should -BeTrue
        (ConvertFrom-SIControlPlaneOutputs -Json '{"servicenow-ci":{"output":false}}' -Allow $script:Allow).Outputs[0].On | Should -BeFalse
    }
    It 'bad JSON / not ONE object: refused, nothing from it applied' {
        foreach ($j in '{"servicenow-vulnerable-item": {"on": [', '[{"servicenow-vulnerable-item":{}}]', '5', '"x"', '{"servicenow-vulnerable-item": ["u_si_category"]}') {
            $p = ConvertFrom-SIControlPlaneOutputs -Json $j -Allow $script:Allow
            @($p.Columns).Count + @($p.Outputs).Count | Should -Be 0 -Because $j
            @($p.Refused).Count | Should -Be 1 -Because $j
            $p.Refused[0] | Should -Match '^SI_UPDATER_OUTPUTS' -Because $j
        }
    }
    It 'an unknown output, an unknown column, a column always sent, a fixed output, an unknown part: refused; the rest applies' {
        $p = ConvertFrom-SIControlPlaneOutputs -Json '{"no-such-output":{"output":"on"},"sql-vulnerability-target":{"output":"on"},"servicenow-vulnerable-item":{"on":["u_no_such","u_vulnerability","si_category"],"rename":{}}}' -Allow $script:Allow
        @($p.Columns.Target) | Should -Be @('u_si_category')
        @($p.Outputs).Count | Should -Be 0
        @($p.Refused).Count | Should -Be 5
        $all = $p.Refused -join "`n"
        $all | Should -Match 'no-such-output is not an output of this release'
        $all | Should -Match 'sql-vulnerability-target is written by another connector with fixed columns'
        $all | Should -Match 'servicenow-vulnerable-item has no column u_no_such \(switchable: u_si_security_domain'
        $all | Should -Match 'u_vulnerability is a column that is always sent'
        $all | Should -Match 'has "rename" -- only "on", "off" and "output" are read'
    }
    It 'a column named both on and off is refused; a bad output word is refused; a name that is not text is refused' {
        $p = ConvertFrom-SIControlPlaneOutputs -Json '{"servicenow-vulnerable-item":{"on":["u_si_tier",5],"off":["si_tier"],"output":"maybe"}}' -Allow $script:Allow
        @($p.Columns).Count | Should -Be 0
        @($p.Outputs).Count | Should -Be 0
        ($p.Refused -join "`n") | Should -Match 'u_si_tier is named both on and off'
        ($p.Refused -join "`n") | Should -Match '"output" must be "on" or "off"'
        ($p.Refused -join "`n") | Should -Match 'names a column that is not text'
    }
    It 'empty = nothing' {
        $p = ConvertFrom-SIControlPlaneOutputs -Json '  ' -Allow $script:Allow
        @($p.Columns).Count + @($p.Outputs).Count + @($p.Refused).Count | Should -Be 0
    }
}

Describe 'the row is the one an Admin''s change writes (the web app''s own statement and parameters)' {
    It 'the write and read statements are ItemOverrideRepository.WriteSql / ReadSql, character for character' {
        Norm (Get-SIProOutputColumnWriteSql) | Should -BeExactly (CsConst 'WriteSql')
        Norm (Get-SIProOutputColumnReadSql) | Should -BeExactly (CsConst 'ReadSql')
    }
    It 'the parameters are WriteAsync''s, Format json, Kind datamodel' {
        $m = [regex]::Match($script:CsRepo, 'public async Task<WriteResult> WriteAsync\(ItemOverrideWrite w.*?QueryAsync\(WriteSql, new Dictionary<string, object\?>\s*\{(.*?)\}, ct\)', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        $m.Success | Should -BeTrue
        $csNames = @([regex]::Matches($m.Groups[1].Value, '\["(\w+)"\]') | ForEach-Object { $_.Groups[1].Value })
        $seen = $null
        $st = [pscustomobject]@{ Invoke = { param($sql, $p, $mode) $script:seen = $p; , @(@{ Outcome = 'Saved' }) } }
        Set-SIProOutputColumn -Store $st -Key 'outputs/servicenow-vulnerable-item:u_si_category' -State override -Body '{"target":"u_si_category","from":"extra.si_category"}' -ChangedBy 'x' -Reason $script:Who | Should -Be 'Saved'
        @($script:seen.Keys) | Should -Be $csNames
        $script:seen.Kind | Should -Be 'datamodel'; $script:seen.Format | Should -Be 'json'
        $script:CsRepo | Should -Match ([regex]::Escape('public const string Format = "json";'))
    }
    It 'the body is OutputMapRules.Body of the shipped column: target, from (op / as / position when set) -- never "off"' {
        $c = $script:ViMap.columns | Where-Object target -eq 'u_si_category'
        Get-SIProOutputColumnBody -Column $c | Should -BeExactly '{"target":"u_si_category","from":"extra.si_category"}'
        Get-SIProOutputColumnBody -Column ([pscustomobject]@{ target = 'u_x'; from = 'si_class'; op = 'enum:servicenow_class_hint'; as = 'X'; position = 3; off = $true }) | Should -BeExactly '{"target":"u_x","from":"si_class","op":"enum:servicenow_class_hint","as":"X","position":3}'
        $cs = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'pro-management', 'src', 'SI.Management.Core', 'ProData', 'OutputMaps.cs'))
        $cs | Should -Match ([regex]::Escape('var o = new JsonObject { ["target"] = c.Target, ["from"] = c.From };'))
        $cs | Should -Match ([regex]::Escape('if (p.Name is not ("target" or "from" or "op" or "as" or "position"))'))
    }
    It 'a refused write sends nothing' {
        $st = New-OutStore
        { Set-SIProOutputColumn -Store $st -Key 'outputs/servicenow-vulnerable-item:u_si_category' -State override -Body '{"target":"u_other","from":"x"}' -ChangedBy 'x' } | Should -Throw '*the target must be*'
        { Set-SIProOutputColumn -Store $st -Key 'rules/x' -State override -Body '{}' -ChangedBy 'x' } | Should -Throw '*not an output column*'
        { Set-SIProOutputColumn -Store $st -Key 'outputs/servicenow-vulnerable-item:u_si_category' -State override -Body '{"target":"u_si_category","from":"extra.si_category","off":true}' -ChangedBy 'x' } | Should -Throw '*not part of a column*'
        $st.W.Sql.Count | Should -Be 0
    }
    It 'switched on by the update = the SAME row the admin path writes through the same store (bar who and why)' {
        $tpl = @{ 'outputs/servicenow-vulnerable-item:u_si_category' = @{ Version = '3.1.23'; Hash = ('a' * 64) } }
        $upd = New-OutStore -Templates $tpl
        $r = Invoke-SIControlPlaneOutputs -Store $upd -Json '{"servicenow-vulnerable-item":{"on":["si_category"]}}' -Allow $script:Allow -Catalog $script:Catalog -Reason 'owner approved'
        @($r.Applied) | Should -Be @('servicenow-vulnerable-item:u_si_category')
        # the admin path: ItemOverrideRepository.WriteAsync(new ItemOverrideWrite("datamodel", key, "override", OutputMapRules.Body(column), reason)) -- its parameters
        $adm = New-OutStore -Templates $tpl
        $null = & $adm.Invoke (Get-SIProOutputColumnWriteSql) ([ordered]@{ Kind = 'datamodel'; Key = 'outputs/servicenow-vulnerable-item:u_si_category'; State = 'override'; Body = '{"target":"u_si_category","from":"extra.si_category"}'; Format = 'json'; By = 'admin@contoso.test'; Reason = 'owner approved' }) 'reader'
        $a = Row $adm 'u_si_category'; $u = Row $upd 'u_si_category'
        foreach ($f in 'Kind', 'ItemKey', 'State', 'BodyJson', 'Format', 'BaseVersion', 'BaseHash') { $u.$f | Should -BeExactly $a.$f -Because $f }
        $u.BaseHash | Should -Be ('a' * 64)
        $u.UpdatedBy | Should -Be 'the update (control-plane value)'
        $cl = $upd.W.ChangeLog.ToArray()[0]; $acl = $adm.W.ChangeLog.ToArray()[0]
        foreach ($f in 'Name', 'Scope', 'Kind', 'Action', 'Old', 'New', 'Reason') { $cl.$f | Should -BeExactly $acl.$f -Because $f }
        $cl.By | Should -Be 'the update (control-plane value)'
        # nothing else was touched
        $upd.W.Items.Count | Should -Be 1
        ($r.Lines -join "`n") | Should -Match 'servicenow-vulnerable-item column u_si_category switched ON \(from SI_UPDATER_OUTPUTS; read back, in the change log\)'
    }
}

Describe 'applied, read back, idempotent; never a failed update' {
    It 'on, then the same env again: nothing written; off: back to the shipped column (the row removed); off again: nothing' {
        $st = New-OutStore
        $j = '{"servicenow-vulnerable-item":{"on":["u_si_category","u_si_security_domain"]}}'
        $r1 = Invoke-SIControlPlaneOutputs -Store $st -Json $j -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        @($r1.Applied).Count | Should -Be 2
        $w = $st.W.Writes
        $r2 = Invoke-SIControlPlaneOutputs -Store $st -Json $j -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        $st.W.Writes | Should -Be $w
        @($r2.Already) | Should -Be @('outputs') -Because 'the same value as the one applied: nothing is even compared'
        @($r2.Applied).Count | Should -Be 0
        # a different value that asks for what is in force: compared column by column, nothing written
        $r2b = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-vulnerable-item":{"on":["u_si_security_domain","u_si_category"]}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        $st.W.Writes | Should -Be $w
        @($r2b.Already) | Should -Be @('servicenow-vulnerable-item:u_si_security_domain', 'servicenow-vulnerable-item:u_si_category')
        $r3 = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-vulnerable-item":{"off":["u_si_category"]}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        @($r3.Applied) | Should -Be @('servicenow-vulnerable-item:u_si_category')
        Row $st 'u_si_category' | Should -BeNullOrEmpty
        (Row $st 'u_si_security_domain').State | Should -Be 'override' -Because 'a column that is not named is never touched'
        $st.W.ChangeLog.ToArray()[-1].Action | Should -Be 'Reset'
        $w = $st.W.Writes
        $r4 = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-vulnerable-item":{"off":["u_si_category"]}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        $st.W.Writes | Should -Be $w
        @($r4.Already) | Should -Be @('outputs')
    }
    It 'an Admin''s own change of a column that is on (a rename) is never overwritten; a column an Admin removed is switched on' {
        $st = New-OutStore
        $st.W.Items['datamodel|outputs/servicenow-vulnerable-item:u_si_tier'] = [pscustomobject]@{ Kind = 'datamodel'; ItemKey = 'outputs/servicenow-vulnerable-item:u_si_tier'; State = 'override'; BodyJson = '{"target":"u_si_tier","from":"extra.si_tier","as":"u_tier"}'; Format = 'json'; UpdatedBy = 'admin@contoso.test' }
        $st.W.Items['datamodel|outputs/servicenow-vulnerable-item:u_si_report'] = [pscustomobject]@{ Kind = 'datamodel'; ItemKey = 'outputs/servicenow-vulnerable-item:u_si_report'; State = 'disable'; BodyJson = $null; Format = 'json'; UpdatedBy = 'admin@contoso.test' }
        $r = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-vulnerable-item":{"on":["u_si_tier","u_si_report"]}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        @($r.Already) | Should -Be @('servicenow-vulnerable-item:u_si_tier')
        (Row $st 'u_si_tier').BodyJson | Should -Match '"as":"u_tier"'
        ($r.Lines -join "`n") | Should -Match 'u_si_tier is sent already \(switched on by admin@contoso\.test\)'
        @($r.Applied) | Should -Be @('servicenow-vulnerable-item:u_si_report')
        (Row $st 'u_si_report').State | Should -Be 'override'
    }
    It 'a write that does not read back, or a store that throws: a warning line, never a throw; no table yet: a warning' {
        $st = New-OutStore
        $real = $st.Invoke
        $wsql = Get-SIProOutputColumnWriteSql
        $lost = [pscustomobject]@{ Invoke = { param($sql, $p, $mode) if ($sql -ceq $wsql) { return , @(@{ Outcome = 'Saved' }) }; & $real $sql $p $mode }.GetNewClosure(); W = $st.W }
        $r = Invoke-SIControlPlaneOutputs -Store $lost -Json '{"servicenow-vulnerable-item":{"on":["u_si_category"]}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        @($r.Failed) | Should -Be @('servicenow-vulnerable-item:u_si_category')
        ($r.Lines -join "`n") | Should -Match 'WARNING: control-plane value: servicenow-vulnerable-item column u_si_category was switched on but does not read back'
        $missing = [pscustomobject]@{ Invoke = { param($sql, $p, $mode) if ($sql -ceq $wsql) { return , @(@{ Outcome = 'Missing' }) }; , @() }.GetNewClosure() }
        $r2 = Invoke-SIControlPlaneOutputs -Store $missing -Json '{"servicenow-vulnerable-item":{"on":["u_si_category"]}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        ($r2.Lines -join "`n") | Should -Match 'no cfg\.ItemOverride table yet'
        $boom = [pscustomobject]@{ Invoke = { param($sql, $p, $mode) throw 'SQL down' } }
        { $script:rb = Invoke-SIControlPlaneOutputs -Store $boom -Json '{"servicenow-vulnerable-item":{"on":["u_si_category"]},"servicenow-ci":{"output":"on"}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who } | Should -Not -Throw
        @($script:rb.Failed) | Should -Be @('servicenow-vulnerable-item:u_si_category', 'output:servicenow-ci')
    }
}

Describe 'an Admin''s choice is never undone by the update: "off" removes only what the update wrote; once per value' {
    It '"off" keeps a column an Admin switched on (UpdatedBy is not the update); it removes the one the update switched on' {
        $st = New-OutStore
        $st.W.Items['datamodel|outputs/servicenow-vulnerable-item:u_si_tier'] = [pscustomobject]@{ Kind = 'datamodel'; ItemKey = 'outputs/servicenow-vulnerable-item:u_si_tier'; State = 'override'; BodyJson = '{"target":"u_si_tier","from":"extra.si_tier"}'; Format = 'json'; UpdatedBy = 'admin@contoso.test' }
        $null = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-vulnerable-item":{"on":["u_si_category"]}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        $w = $st.W.Writes
        $r = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-vulnerable-item":{"off":["u_si_tier","u_si_category"]}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        @($r.Kept) | Should -Be @('servicenow-vulnerable-item:u_si_tier')
        @($r.Applied) | Should -Be @('servicenow-vulnerable-item:u_si_category')
        (Row $st 'u_si_tier').UpdatedBy | Should -Be 'admin@contoso.test' -Because 'the Admin''s own row is never removed by the update'
        Row $st 'u_si_category' | Should -BeNullOrEmpty
        $st.W.Writes | Should -Be ($w + 1) -Because 'only the update''s own row was written'
        ($r.Lines -join "`n") | Should -Match 'u_si_tier is kept -- it was switched on in the web app by admin@contoso\.test'
        @($r.Failed).Count | Should -Be 0
    }
    It 'ONCE PER VALUE: switched on, then an Admin switches it off in the web app -- the next update with the same env does nothing' {
        $st = New-OutStore
        $j = '{"servicenow-vulnerable-item":{"on":["u_si_category"]}}'
        $r1 = Invoke-SIControlPlaneOutputs -Store $st -Json $j -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        @($r1.Applied) | Should -Be @('servicenow-vulnerable-item:u_si_category')
        $st.W.State['ControlPlaneOutputs'].Value | Should -Be (Get-SIControlPlaneValueHash -Json $j)
        $st.W.State['ControlPlaneOutputs'].By | Should -Be 'the update (control-plane value)'
        # the Admin switches it off on Connectors > Fields sent (the same statement, back to the shipped column)
        $null = & $st.Invoke (Get-SIProOutputColumnWriteSql) ([ordered]@{ Kind = 'datamodel'; Key = 'outputs/servicenow-vulnerable-item:u_si_category'; State = 'inherit'; Body = $null; Format = 'json'; By = 'admin@contoso.test'; Reason = 'not wanted' }) 'reader'
        $w = $st.W.Writes; $sql = $st.W.Sql.Count
        # the next updates: the same env (other spacing too)
        foreach ($again in $j, ' { "servicenow-vulnerable-item" : { "on" : [ "u_si_category" ] } } ') {
            $r = Invoke-SIControlPlaneOutputs -Store $st -Json $again -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
            @($r.Already) | Should -Be @('outputs')
            @($r.Applied).Count | Should -Be 0
        }
        Row $st 'u_si_category' | Should -BeNullOrEmpty -Because 'the Admin''s choice stays'
        $st.W.Writes | Should -Be $w
        ($st.W.Sql.Count - $sql) | Should -Be 2 -Because 'one read of the applied value per update, nothing else'
    }
    It 'not recorded when a part failed or waited for a reason: the next update tries again' {
        $st = New-OutStore
        $real = $st.Invoke; $wsql = Get-SIProOutputColumnWriteSql
        $lost = [pscustomobject]@{ Invoke = { param($sql, $p, $mode) if ($sql -ceq $wsql) { return , @(@{ Outcome = 'Saved' }) }; & $real $sql $p $mode }.GetNewClosure(); W = $st.W }
        $j = '{"servicenow-vulnerable-item":{"on":["u_si_category"]}}'
        $null = Invoke-SIControlPlaneOutputs -Store $lost -Json $j -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        $st.W.State.ContainsKey('ControlPlaneOutputs') | Should -BeFalse
        $null = Invoke-SIControlPlaneOutputs -Store $st -Json $j -Allow $script:Allow -Catalog $script:Catalog -Reason ''
        $st.W.State.ContainsKey('ControlPlaneOutputs') | Should -BeFalse
        $r = Invoke-SIControlPlaneOutputs -Store $st -Json $j -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        @($r.Applied) | Should -Be @('servicenow-vulnerable-item:u_si_category')
        $st.W.State.ContainsKey('ControlPlaneOutputs') | Should -BeTrue
    }
}

Describe 'every change of what is sent names WHO asked (SI_UPDATER_CONTROLPLANE_REASON)' {
    It 'the rule: empty, whitespace, one word, too short or a generic word is refused; "<person>: <why>" is accepted' {
        foreach ($bad in $null, '', '   ', 'update', 'Update.', 'the update', 'n/a', 'N/A', 'na', 'test', 'TEST', 'none', '-', '.', 'x', 'ok', 'tbd', 'fix', 'Owner', 'a b c', 'a control-plane value on the updater job caj-si-updater') {
            Test-SIControlPlaneReason -Reason $bad | Should -Not -BeNullOrEmpty -Because "'$bad' names nobody"
        }
        foreach ($good in 'Owner: new ServiceNow columns approved', 'Owner: ServiceNow team asked for the tier', 'Service desk lead: wants the category column') {
            Test-SIControlPlaneReason -Reason $good | Should -BeExactly '' -Because $good
        }
    }
    It 'EVERY change without a usable reason -- a column on or off, an output on or off: refused in ONE warning line, nothing written' {
        $st = New-OutStore
        $st.W.Items['datamodel|outputs/servicenow-vulnerable-item:u_si_report'] = [pscustomobject]@{ Kind = 'datamodel'; ItemKey = 'outputs/servicenow-vulnerable-item:u_si_report'; State = 'override'; BodyJson = '{"target":"u_si_report","from":"extra.si_report"}'; Format = 'json'; UpdatedBy = 'the update (control-plane value)' }
        foreach ($why in '', 'n/a', 'test') {
            $r = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-vulnerable-item":{"on":["u_si_category","u_si_tier"],"off":["u_si_report"]},"servicenow-ci":{"output":"on"}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $why
            $warn = @($r.Lines | Where-Object { $_ -match 'needs SI_UPDATER_CONTROLPLANE_REASON' })
            $warn.Count | Should -Be 1 -Because "one line, reason '$why'"
            $warn[0] | Should -Match 'servicenow-vulnerable-item column u_si_category on, servicenow-vulnerable-item column u_si_report off, servicenow-vulnerable-item column u_si_tier on, the output servicenow-ci on not switched'
            Row $st 'u_si_category' | Should -BeNullOrEmpty
            Row $st 'u_si_report' | Should -Not -BeNullOrEmpty -Because '"off" needs who and why too: nothing is removed without it'
            $st.W.Settings.ContainsKey('SI_DataOut_Outputs|solution') | Should -BeFalse
            $st.W.State.ContainsKey('ControlPlaneOutputs') | Should -BeFalse -Because 'a refused change is tried again on the next update'
        }
        $st.W.ChangeLog.Count | Should -Be 0 -Because 'nothing was changed'
        # an output switched OFF without a reason is refused too (the output is on first, with who and why)
        $null = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-ci":{"output":"on"}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        $r2 = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-ci":{"output":"off"}}' -Allow $script:Allow -Catalog $script:Catalog -Reason 'n/a'
        @($r2.Lines | Where-Object { $_ -match 'the output servicenow-ci off not switched' }).Count | Should -Be 1
        (Read-SIControlPlaneSetting -Store $st -Name 'SI_DataOut_Outputs' -Scope 'solution') | Should -Match 'servicenow-ci'
        # with who and why, "off" applies and records that reason
        $r3 = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-vulnerable-item":{"off":["u_si_report"]}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        @($r3.Applied) | Should -Be @('servicenow-vulnerable-item:u_si_report')
        $cl = @($st.W.ChangeLog | Where-Object { $_.Name -eq 'outputs/servicenow-vulnerable-item:u_si_report' })
        $cl.Count | Should -Be 1
        $cl[0].By | Should -Be 'the update (control-plane value)'; $cl[0].Reason | Should -Be $script:Who
    }
    It 'with who and why: every change carries the reason in the change log, ChangedBy the update' {
        $st = New-OutStore
        $r = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-vulnerable-item":{"on":["u_si_category","u_si_tier"]},"servicenow-ci":{"output":"on"}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        @($r.Applied).Count | Should -Be 3
        $st.W.ChangeLog.Count | Should -Be 3
        foreach ($c in $st.W.ChangeLog) { $c.Reason | Should -Be $script:Who; $c.By | Should -Be 'the update (control-plane value)' }
    }
}

Describe 'the output itself: SI_DataOut_Outputs as the web app''s switch computes it' {
    It 'the twin of OnOutputs / Switched: defaults, a named list, the defaults again = reset' {
        $e = @($script:Allow.Entries)
        $def = @(Get-SIControlPlaneOutputsOn -Entries $e -Setting $null)
        $def | Should -Not -Contain 'sql-vulnerability-target'
        Get-SIControlPlaneOutputsSwitched -Entries $e -Setting $null -Output 'servicenow-ci' -On $true | Should -Be (@($e | Where-Object { [string]$_.kind -ne 'fixed' -and ($_.default -or $_.output -eq 'servicenow-ci') } | ForEach-Object output) -join ';')
        Get-SIControlPlaneOutputsSwitched -Entries $e -Setting 'servicenow-ci' -Output 'servicenow-ci' -On $false | Should -BeNullOrEmpty -Because 'nothing on and no default on = the defaults: the row is reset'
        # the C# it twins
        $cs = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'pro-management', 'src', 'SI.Management.Web', 'Pages', 'Reports', 'OutputFields.cshtml.cs'))
        $cs | Should -Match ([regex]::Escape('if (set.SetEquals(OnOutputs(catalog, null))) return null;'))
        $cs | Should -Match ([regex]::Escape('return string.Join(";", catalog.Where(e => set.Contains(e.Output)).Select(e => e.Output));'))
    }
    It 'switched on: written with Set-SIProSetting (its change-log row), read back; again: nothing; off: reset; unknown / fixed refused' {
        $st = New-OutStore
        $r = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-ci":{"output":"on"},"servicenow-vulnerable-item":{"output":"on"}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        @($r.Applied) | Should -Be @('output:servicenow-ci', 'output:servicenow-vulnerable-item')
        $st.W.Settings['SI_DataOut_Outputs|solution'] | Should -Be '"servicenow-ci;servicenow-vulnerable-item"'
        $st.W.ChangeLog.Count | Should -Be 1
        $st.W.ChangeLog.ToArray()[0].By | Should -Be 'the update (control-plane value)'
        $w = $st.W.Writes
        $r2 = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-ci":{"output":"on"}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        $st.W.Writes | Should -Be $w
        @($r2.Already) | Should -Be @('output:servicenow-ci')
        $null = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-vulnerable-item":{"output":"off"}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        $st.W.Settings['SI_DataOut_Outputs|solution'] | Should -Be '"servicenow-ci"' -Because 'every other output keeps what it does now'
        $r4 = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-ci":{"output":"off"}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        $st.W.Settings.ContainsKey('SI_DataOut_Outputs|solution') | Should -BeFalse -Because 'the defaults again = the row reset'
        $st.W.ChangeLog.ToArray()[-1].Action | Should -Be 'Reset'
        ($r4.Lines -join "`n") | Should -Match 'SI_DataOut_Outputs back to the defaults'
    }
}

Describe 'the effect: switched on, the output sends the column; the env absent changes nothing' {
    BeforeAll {
        . ([IO.Path]::Combine($script:SIRoot, 'engine', 'pro-settings', 'SI-ProSettings.ps1'))
        if (-not (Get-Command -Name Get-SITemplateRows -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIRoot, 'engine', 'pro-settings', 'SI-ProConfig.ps1')) }
        . ([IO.Path]::Combine($script:SIRoot, 'engine', 'data-model', 'SI-OutputMapper.ps1'))
        # the hand-off view's columns = the map's columns that read extra.<field> (its builder is proven on the same map in SIv3-FieldMapperSnowSame; a Pro file, not loaded here)
        function script:ExtraCols($m) { @($m.columns | Where-Object { [string]$_.from -like 'extra.*' } | ForEach-Object { [string]$_.target }) }
        $script:Ctx = Get-SIProConfigContext -SIRoot $script:SIRoot
        $script:Tpl = @((Get-SITemplateRows -SIRoot $script:SIRoot -Families @('datamodel')).Rows | ForEach-Object {
            [pscustomobject]@{ Kind = $_.Kind; ItemKey = $_.ItemKey; TemplateVersion = $_.TemplateVersion; BodyJson = $_.BodyJson; Format = 'json'; SortOrder = $_.SortOrder; BodyHash = $_.BodyHash; ContentHash = $_.ContentHash; Source = $_.Source; RetiredAt = $null } })
        # the fake store's cfg.Template: the shipped rows' version and content hash (what the statement reads as the base)
        $script:TplIdx = @{}; foreach ($t in $script:Tpl) { $script:TplIdx[$t.ItemKey] = @{ Version = $t.TemplateVersion; Hash = $t.ContentHash } }
        function script:Export-Run($st) {
            $ovr = @(if ($st) { $st.W.Items.Values })
            $m = Merge-SIProItems -Templates $script:Tpl -Overrides $ovr -Context $script:Ctx
            $run = Join-Path $TestDrive ([guid]::NewGuid().ToString('N').Substring(0, 8))
            $x = Export-SIProConfig -Items @($m.Items | Where-Object { $_.Kind -ne 'naming' }) -Families $m.Families -RunFolder $run -Context $script:Ctx
            [pscustomobject]@{ Merge = $m; Model = (Get-SIDataModel -Root $x.DataModelRoot) }
        }
        $script:Item = [pscustomobject]@{ si_ci_id = 'ci-1'; si_finding_key = 'CVE-2026-1000'; si_finding_state = 'open'; si_severity = 'High'; item_key = 'ci-1|CVE-2026-1000'
            extra = [pscustomobject]@{ si_category = 'Browser'; si_security_domain = 'Endpoint'; si_tier = 1 } }
    }
    It 'nothing switched: the run''s map sends none of the columns shipped off (today''s output)' {
        $x = Export-Run $null
        $targets = @($x.Model.Outputs[$script:VI].columns | ForEach-Object target)
        foreach ($t in $script:ShippedOff) { $targets | Should -Not -Contain $t }
        @(ExtraCols $x.Model.Outputs[$script:VI]).Count | Should -Be 0
    }
    It 'switched on by the update: the real merge applies the override (no refusal, no upgrade flag), the map sends the column, the push row carries the value, the view gets the column' {
        $st = New-OutStore -Templates $script:TplIdx
        $r = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-vulnerable-item":{"on":["si_category","si_security_domain"]}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        @($r.Applied).Count | Should -Be 2
        (Row $st 'u_si_category').BaseHash | Should -Be $script:TplIdx['outputs/servicenow-vulnerable-item:u_si_category'].Hash
        $x = Export-Run $st
        @($x.Merge.Refused | Where-Object { $_.Name -like 'datamodel/outputs/*' }) | Should -BeNullOrEmpty
        @($x.Merge.Notes | Where-Object { $_ -match 'outputs/servicenow-vulnerable-item' }) | Should -BeNullOrEmpty -Because 'made against the live template: not UpgradeAvailable'
        $map = $x.Model.Outputs[$script:VI]
        $targets = @($map.columns | ForEach-Object target)
        $targets | Should -Contain 'u_si_category'; $targets | Should -Contain 'u_si_security_domain'
        $targets | Should -Not -Contain 'u_si_tier' -Because 'a column that is not named stays off'
        $row = @(Invoke-SIOutputMap -Map $map -Items @($script:Item) -ValueMaps $x.Model['value-maps'].maps -Context @{ RunId = 'r1' })[0]
        $row.u_si_category | Should -Be 'Browser'
        $row.u_si_security_domain | Should -Be 'Endpoint'
        $row.PSObject.Properties['u_si_tier'] | Should -BeNullOrEmpty
        $ex = ExtraCols $map
        @($ex) | Should -Be @('u_si_security_domain', 'u_si_category')
        # switched off again: today's map
        $null = Invoke-SIControlPlaneOutputs -Store $st -Json '{"servicenow-vulnerable-item":{"off":["si_category","si_security_domain"]}}' -Allow $script:Allow -Catalog $script:Catalog -Reason $script:Who
        $st.W.Items.Count | Should -Be 0
        @(ExtraCols (Export-Run $st).Model.Outputs[$script:VI]).Count | Should -Be 0
    }
    It 'the env absent (or empty): the step reads and writes nothing' {
        $st = New-OutStore
        $r = Invoke-SIControlPlaneValues -Env @{ SI_UPDATER_STATE_IDENTITYMOVEMODE = ''; SI_UPDATER_SETTINGS = ''; SI_UPDATER_OUTPUTS = ' ' } -Store $st -SIRoot $script:SIRoot -Catalog $script:Catalog -Log $script:Quiet
        $st.W.Sql.Count | Should -Be 0
        $r.Outputs | Should -BeNullOrEmpty
        @($r.Lines).Count | Should -Be 0
    }
}

Describe 'WIRING: the step runs it, the real updater reaches it, the image carries it' {
    It 'Invoke-SIControlPlaneValues: after the settings, with the reason; a refusal is a warning line' {
        $st = New-OutStore
        $seen = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIControlPlaneValues -Env @{ SI_UPDATER_SETTINGS = '{"SI_EnableAI":true}'; SI_UPDATER_OUTPUTS = '{"servicenow-vulnerable-item":{"on":["u_si_category","u_nope"]}}'; SI_UPDATER_CONTROLPLANE_REASON = 'new ServiceNow columns, owner 2026-11-16' } -Store $st -SIRoot $script:SIRoot -Catalog $script:Catalog -Log { param($m) $seen.Add($m) }
        @($r.Outputs.Applied) | Should -Be @('servicenow-vulnerable-item:u_si_category')
        ($st.W.ChangeLog | Where-Object Kind -eq 'datamodel').Reason | Should -Be 'new ServiceNow columns, owner 2026-11-16'
        $iS = [array]::IndexOf($seen.ToArray(), ($seen | Where-Object { $_ -match 'SI_EnableAI' } | Select-Object -First 1))
        $iO = [array]::IndexOf($seen.ToArray(), ($seen | Where-Object { $_ -match 'u_si_category switched ON' } | Select-Object -First 1))
        $iS | Should -BeLessThan $iO
        @($seen | Where-Object { $_ -match '^WARNING: control-plane value: SI_UPDATER_OUTPUTS: servicenow-vulnerable-item has no column u_nope' }).Count | Should -Be 1
        # a part refused for good (a column that is not on the list) does not hold the value back: it is recorded, so an Admin's
        # later change in the web app is not undone by the same value on the next update
        $st.W.State.ContainsKey('ControlPlaneOutputs') | Should -BeTrue
    }
    It 'the real Start-SIUpdater step (dot-sourced in its own scope) switches the column' {
        $src = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'container', 'updater', 'Start-SIUpdater.ps1'))
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-SIUpdaterControlPlaneStep' }, $true)
        . ([scriptblock]::Create($fn.Extent.Text))
        function script:Write-UpdLog([string]$m) { $script:UpdLines.Add($m) }
        function script:Get-SIUpdaterInstallName { param($Role, $Env) 'caj-si-updater' }
        $script:UpdLines = New-Object System.Collections.Generic.List[string]
        $st = New-OutStore
        # no reason: switching ON is refused in one warning line, nothing written
        $null = Invoke-SIUpdaterControlPlaneStep -Env @{ SI_UPDATER_OUTPUTS = '{"servicenow-vulnerable-item":{"on":["si_tier"]}}'; SI_UPDATER_CONTROLPLANE_REASON = '' } -Store $st -Lib $script:Lib
        Row $st 'u_si_tier' | Should -BeNullOrEmpty
        @($script:UpdLines | Where-Object { $_ -match 'WARNING: control-plane value: SI_UPDATER_OUTPUTS: servicenow-vulnerable-item column u_si_tier on not switched -- every change of what is sent needs SI_UPDATER_CONTROLPLANE_REASON' }).Count | Should -Be 1
        # who and why: switched on, the reason in the change log
        $null = Invoke-SIUpdaterControlPlaneStep -Env @{ SI_UPDATER_OUTPUTS = '{"servicenow-vulnerable-item":{"on":["si_tier"]}}'; SI_UPDATER_CONTROLPLANE_REASON = 'Owner: tier column for the CMDB team' } -Store $st -Lib $script:Lib
        (Row $st 'u_si_tier').State | Should -Be 'override'
        (Row $st 'u_si_tier').UpdatedBy | Should -Be 'the update (control-plane value)'
        $st.W.ChangeLog.ToArray()[0].Reason | Should -Be 'Owner: tier column for the CMDB team'
        ($script:UpdLines -join "`n") | Should -Match 'u_si_tier switched ON'
    }
    It 'the writer loads on its own (no settings layer, no data model) -- as in the updater image' {
        $ps = [powershell]::Create()
        try {
            $null = $ps.AddScript(". '$([IO.Path]::Combine($script:SIRoot, 'engine', 'pro-settings', 'SI-OutputColumnWrite.ps1').Replace("'", "''"))'; [bool](Get-Command Set-SIProOutputColumn -ErrorAction SilentlyContinue); [bool](Get-Command Merge-SIProItems -ErrorAction SilentlyContinue); [bool](Get-Command Get-SIDataModelTemplate -ErrorAction SilentlyContinue)")
            @($ps.Invoke()) | Should -Be @($true, $false, $false)
        } finally { $ps.Dispose() }
    }
    It 'the updater image carries the writer, the output maps and the data-out catalog' {
        $df = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'container', 'updater', 'Dockerfile'))
        $df | Should -Match 'COPY engine/pro-settings/SI-OutputColumnWrite\.ps1 /si/engine/pro-settings/'
        $df | Should -Match 'COPY data-model/outputs/ /si/data-model/outputs/'
        $df | Should -Match 'COPY config/data-out\.locked\.json /si/config/'
        $df | Should -Not -Match 'COPY engine/pro-settings/ '
    }
}
