#Requires -Version 5.1
<#
    SI_UPDATER_REPORTS -- A SHIPPED REPORT SWITCHED OFF (OR ON AGAIN) PER INSTALL THROUGH THE UPDATER (owner 2026-11-19: a
    report whose source the install has no licence for is switched off by support, never an ops SQL write; Invardia ruling
    2026-11-15). setup\_shared\SI-ControlPlaneValues.ps1 (Invoke-SIControlPlaneReports) over the web app's own item statement
    (engine\pro-settings\SI-OutputColumnWrite.ps1 = ItemOverrideRepository.WriteSql):
      * ALLOW-LIST derived from the release: the reports RiskAnalysis_Queries_Locked.yaml ships (never a template, never a
        custom report), minus a report SecurityInsight requires (template-mandatory, 'rareport');
      * THE SAME ROW AS AN ADMIN'S "Report it" OFF: Kind 'rareport', key 'report/<name>', State 'disable', no body;
      * READ BACK; idempotent; "on" removes only the update's own switch-off (an Admin's is kept); once per value;
      * WHO ASKED: every switch needs SI_UPDATER_CONTROLPLANE_REASON;
      * WIRING: Invoke-SIControlPlaneValues runs it; the updater image carries the report catalog and the mandatory controls.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Lib = [IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-ControlPlaneValues.ps1')
    . ([IO.Path]::Combine($script:SIRoot, 'engine', 'pro-settings', 'SI-ProSettingWrite.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', 'pro-settings', 'SI-OutputColumnWrite.ps1'))
    . $script:Lib
    $script:Allow = Get-SIControlPlaneReportAllowList -SIRoot $script:SIRoot
    function script:Norm([string]$t) { ($t -replace "`r`n", "`n").Trim() }
    # an in-memory Pro store: cfg.ItemOverride + cfg.ChangeLog + cfg.InstallState, for exactly the statements this path sends
    function script:New-RepStore {
        $W = @{ Items = @{}; ChangeLog = (New-Object System.Collections.Generic.List[object]); Writes = 0; State = @{}; Params = (New-Object System.Collections.Generic.List[object]) }
        $writeSql = Norm (Get-SIProOutputColumnWriteSql); $readSql = Norm (Get-SIProOutputColumnReadSql)
        $inv = {
            param([string]$sql, $p, [string]$mode)
            $t = ($sql -replace "`r`n", "`n").Trim()
            $k = if ($p -and $p.Contains('Kind')) { '{0}|{1}' -f $p.Kind, $p.Key } else { '' }
            if ($t -ceq $readSql) {
                if ($W.Items.ContainsKey($k)) { $r = $W.Items[$k]; return , @(@{ Kind = $r.Kind; ItemKey = $r.ItemKey; State = $r.State; BodyJson = $r.BodyJson; UpdatedBy = $r.UpdatedBy }) }
                return , @()
            }
            if ($t -ceq $writeSql) {
                # a plain copy of the parameters (the ordered dictionary itself is not read back member by member)
                $W.Params.Add([pscustomobject]@{ Kind = [string]$p.Kind; Key = [string]$p.Key; State = [string]$p.State; Body = $p.Body; Format = [string]$p.Format; By = [string]$p.By; Reason = [string]$p.Reason })
                $old = $null; if ($W.Items.ContainsKey($k)) { $old = $W.Items[$k].State }
                if ($p.State -eq 'inherit') { $null = $W.Items.Remove($k) } else { $W.Items[$k] = [pscustomobject]@{ Kind = $p.Kind; ItemKey = $p.Key; State = $p.State; BodyJson = $p.Body; UpdatedBy = $p.By } }
                $W.ChangeLog.Add([pscustomobject]@{ Name = $p.Key; Kind = $p.Kind; Action = $(if ($p.State -eq 'inherit') { 'Reset' } else { 'Set' }); Old = $old; New = $p.State; By = $p.By; Reason = $p.Reason })
                $W.Writes++
                return , @(@{ Outcome = 'Saved' })
            }
            if ($sql -match 'SELECT Value FROM cfg\.InstallState') { if ($W.State.ContainsKey($p.Name)) { return , @(@{ Value = $W.State[$p.Name] }) }; return , @() }
            if ($sql -match 'MERGE cfg\.InstallState') { $W.State[$p.Name] = $p.Value; return }
            throw ('the fake store does not know this statement: ' + $sql)
        }.GetNewClosure()
        [pscustomobject]@{ Invoke = $inv; W = $W }
    }
    function script:Rep($st, [string]$name) { $st.W.Items['rareport|report/' + $name] }
    $script:Who = 'Owner: no Defender Vulnerability Management licence at this install'
    $script:Off2 = '{"Device_Certificates_Detailed":"off","Device_BrowserExtensions_Detailed":"off"}'
}

Describe 'the allow-list is derived from what the release ships' {
    It 'every shipped report is on it (the two licence-bound reports included); a report template never is' {
        $script:Allow.Reports.Count | Should -BeGreaterThan 100
        $script:Allow.Reports.Contains('Device_Certificates_Detailed') | Should -BeTrue
        $script:Allow.Reports.Contains('Device_BrowserExtensions_Detailed') | Should -BeTrue
        $yaml = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'risk-analysis-detection', 'RiskAnalysis_Queries_Locked.yaml'))
        $tpl = [regex]::Match($yaml.Substring($yaml.IndexOf("`nReportTemplates:")), '-\s*ReportName:\s*([A-Za-z0-9_]+)').Groups[1].Value
        $tpl | Should -Not -BeNullOrEmpty
        $script:Allow.Reports.Contains($tpl) | Should -BeFalse
    }
}

Describe 'the env is parsed; what may not be switched is refused in one line each' {
    It 'bad JSON / not one object: refused, nothing applied' {
        foreach ($bad in '[1]', '{nope', '"off"') { (ConvertFrom-SIControlPlaneReports -Json $bad -Allow $script:Allow).Items.Count | Should -Be 0 }
        @((ConvertFrom-SIControlPlaneReports -Json '{nope' -Allow $script:Allow).Refused).Count | Should -Be 1
    }
    It 'an unknown report, a bad value and a required report are refused; the rest applies' {
        $allow = [pscustomobject]@{ Reports = $script:Allow.Reports; Required = @{ 'Device_Certificates_Detailed' = 'the test needs it' } }
        $p = ConvertFrom-SIControlPlaneReports -Json '{"Device_Certificates_Detailed":"off","MyOwnReport":"off","Device_BrowserExtensions_Detailed":"maybe","Identity_NoMFA_Detailed":"on"}' -Allow $allow
        @($p.Items | ForEach-Object { '{0}={1}' -f $_.Report, $_.On }) | Should -Be @('Identity_NoMFA_Detailed=True')
        @($p.Refused).Count | Should -Be 3
        ($p.Refused -join "`n") | Should -Match 'required by SecurityInsight'
        ($p.Refused -join "`n") | Should -Match 'MyOwnReport is not a report this release ships'
    }
    It 'empty = nothing' { (ConvertFrom-SIControlPlaneReports -Json '' -Allow $script:Allow).Items.Count | Should -Be 0 }
}

Describe 'the row is the one an Admin''s "Report it" off writes' {
    It 'the web app''s own statement with its parameters: Kind rareport, key report/<name>, State disable, no body, Format json' {
        $st = New-RepStore
        $r = Invoke-SIControlPlaneReports -Store $st -Json $script:Off2 -Allow $script:Allow -Reason $script:Who
        @($r.Applied) | Should -Be @('Device_Certificates_Detailed', 'Device_BrowserExtensions_Detailed')
        $p = $st.W.Params[0]
        $p.Kind | Should -Be 'rareport'; $p.Key | Should -Be 'report/Device_Certificates_Detailed'; $p.State | Should -Be 'disable'
        $p.Body | Should -BeNullOrEmpty; $p.Format | Should -Be 'json'; $p.By | Should -Be 'the update (control-plane value)'; $p.Reason | Should -Be $script:Who
        # the same row the web app's ItemWrites.For writes for "Report it" off of a shipped report: State disable, no body
        $cs = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'pro-management', 'src', 'SI.Management.Core', 'ProData', 'ReportDesigner.cs'))
        $cs | Should -Match 'if \(!enabled\) state = templateBody is null \? "inherit" : "disable";'
        (Rep $st 'Device_Certificates_Detailed').State | Should -Be 'disable'
        $st.W.ChangeLog.Count | Should -Be 2
    }
}

Describe 'applied, read back, idempotent; an Admin''s choice is kept; never a failed update' {
    It 'off, the same env again: nothing written; a report switched off already: nothing written' {
        $st = New-RepStore
        $null = Invoke-SIControlPlaneReports -Store $st -Json $script:Off2 -Allow $script:Allow -Reason $script:Who
        $st.W.State['ControlPlaneReports'] | Should -Not -BeNullOrEmpty
        $w = $st.W.Writes
        $again = Invoke-SIControlPlaneReports -Store $st -Json $script:Off2 -Allow $script:Allow -Reason $script:Who
        $st.W.Writes | Should -Be $w
        @($again.Already) | Should -Be @('reports')
        $st.W.State.Clear()
        $third = Invoke-SIControlPlaneReports -Store $st -Json $script:Off2 -Allow $script:Allow -Reason $script:Who
        $st.W.Writes | Should -Be $w
        @($third.Already).Count | Should -Be 2
    }
    It '"on" removes the update''s own switch-off; an Admin''s own switch-off is kept off' {
        $st = New-RepStore
        $null = Invoke-SIControlPlaneReports -Store $st -Json '{"Device_Certificates_Detailed":"off"}' -Allow $script:Allow -Reason $script:Who
        $st.W.Items['rareport|report/Device_BrowserExtensions_Detailed'] = [pscustomobject]@{ Kind = 'rareport'; ItemKey = 'report/Device_BrowserExtensions_Detailed'; State = 'disable'; BodyJson = $null; UpdatedBy = 'admin@example.test' }
        $r = Invoke-SIControlPlaneReports -Store $st -Json '{"Device_Certificates_Detailed":"on","Device_BrowserExtensions_Detailed":"on"}' -Allow $script:Allow -Reason $script:Who
        @($r.Applied) | Should -Be @('Device_Certificates_Detailed')
        @($r.Kept) | Should -Be @('Device_BrowserExtensions_Detailed')
        Rep $st 'Device_Certificates_Detailed' | Should -BeNullOrEmpty
        (Rep $st 'Device_BrowserExtensions_Detailed').State | Should -Be 'disable'
    }
    It 'no usable reason: nothing written, ONE warning line, not recorded (the next update tries again)' {
        foreach ($why in '', 'update', 'x') {
            $st = New-RepStore
            $r = Invoke-SIControlPlaneReports -Store $st -Json $script:Off2 -Allow $script:Allow -Reason $why
            $st.W.Writes | Should -Be 0
            @($r.Lines | Where-Object { $_ -match '^WARNING: control-plane value: SI_UPDATER_REPORTS: .* not switched -- every report switch needs SI_UPDATER_CONTROLPLANE_REASON' }).Count | Should -Be 1
            $st.W.State.ContainsKey('ControlPlaneReports') | Should -BeFalse
        }
    }
    It 'a store that throws: a warning line, never a throw' {
        $st = [pscustomobject]@{ Invoke = { param($s, $p, $m) throw 'the database is away' } }
        $r = Invoke-SIControlPlaneReports -Store $st -Json $script:Off2 -Allow $script:Allow -Reason $script:Who
        @($r.Failed).Count | Should -Be 2
        @($r.Lines | Where-Object { $_ -match 'not switched \(the database is away\)' }).Count | Should -Be 2
    }
}

Describe 'WIRING: the step runs it; the image carries what it needs' {
    It 'Invoke-SIControlPlaneValues switches the reports with the reason' {
        $st = New-RepStore
        $seen = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIControlPlaneValues -Env @{ SI_UPDATER_REPORTS = $script:Off2; SI_UPDATER_CONTROLPLANE_REASON = $script:Who } -Store $st -SIRoot $script:SIRoot -Log { param($m) $seen.Add($m) }
        @($r.Reports.Applied).Count | Should -Be 2
        @($seen | Where-Object { $_ -match 'the report Device_Certificates_Detailed switched OFF' }).Count | Should -Be 1
        $st.W.ChangeLog[0].Reason | Should -Be $script:Who
    }
    It 'the env absent: nothing read, nothing written' {
        $st = New-RepStore
        $null = Invoke-SIControlPlaneValues -Env @{ SI_UPDATER_REPORTS = ''; SI_UPDATER_SETTINGS = ''; SI_UPDATER_OUTPUTS = ''; SI_UPDATER_STATE_IDENTITYMOVEMODE = '' } -Store $st -SIRoot $script:SIRoot -Log { param($m) }
        $st.W.Writes | Should -Be 0
    }
    It 'the updater image carries the item writer, the report catalog and the mandatory controls' {
        $df = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'container', 'updater', 'Dockerfile'))
        $df | Should -Match 'COPY engine/pro-settings/SI-OutputColumnWrite\.ps1 /si/engine/pro-settings/'
        $df | Should -Match 'COPY risk-analysis-detection/RiskAnalysis_Queries_Locked\.yaml /si/risk-analysis-detection/'
        $df | Should -Match 'COPY config/template-mandatory\.locked\.json /si/config/'
    }
}
