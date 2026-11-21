#Requires -Version 5.1
<#
    framework section 12.23 SQL-ACCESS (OPEN-05; Invardia decision 2026-11-20) -- SQL LEAST PRIVILEGE SWITCHED ON THROUGH THE UPDATER:
    setup\_shared\SI-SqlLeastPrivilege.ps1 (the job's step + the updater's decision), its wiring in setup\_shared\
    SI-DbInitJob.ps1 (Read-SIDbInitInput, Invoke-SIDbInit, Start-SIDbInitRun), the updater's side in container\updater\
    _shared\SI-UpdaterDatabase.ps1 (Get-SIUpdaterSqlLpInput, Complete-SIUpdaterSqlLp, Invoke-SIUpdaterDbJob) and the
    heartbeat's setup step sql-least-privilege (engine\_shared\SI-SetupSteps.ps1).

    INVARDIA'S RULES, each one tested:
      1. ONLY db_datareader / db_datawriter / db_ddladmin of SI's OWN job identities, ONLY after the replacement reads back;
         never the Support app, never the SQL admin group, never a person, never anything not on the list.
      2. plan first (the list + the replacement grants in the log and the record); apply only on the SAME planned state;
         snapshot BEFORE, diff AFTER, RESTORE at once on any loss (a permission or membership that is not a planned removal).
      3. audited: the run record, the updater's line, the heartbeat's step; read back per identity.
      4. off = the way back, read back.
      + a usable SI_UPDATER_CONTROLPLANE_REASON; never fails the update; GAP 1: an update never adds the broad roles back.
    OFFLINE: SQL / ARM are fakes holding a world (role memberships + permissions). REAL SQL (the runner's SQL Server,
    SI_TEST_LOCALSQL): the snapshot, the removal transaction, the diff and the restore against real catalog views. The
    runner's SQL Server is NOT the proof for Azure SQL -- the live proof on Azure SQL comes before ring 1 (docs\TESTS.md).
#>

BeforeDiscovery {
    $script:HasSql = [bool]($env:SI_TEST_LOCALSQL)
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-DbInitJob.ps1'))
    . Import-SIDbInitSqlSources -SIRoot $script:SIRoot
    . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-ControlPlaneValues.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-SetupSteps.ps1'))
    $script:Eng = '11111111-0000-0000-0000-000000000001'; $script:Upd = '11111111-0000-0000-0000-000000000002'
    $script:Web = '11111111-0000-0000-0000-000000000003'; $script:Sup = '11111111-0000-0000-0000-000000000006'
    $script:Mi = 'dbdbdbdb-0000-0000-0000-000000000001'; $script:Alice = '22222222-0000-0000-0000-000000000009'
    $script:Grp = '33333333-0000-0000-0000-000000000001'; $script:Other = '44444444-0000-0000-0000-000000000001'
    $script:SidE = Get-SISqlLpSid -ClientId $script:Eng; $script:SidU = Get-SISqlLpSid -ClientId $script:Upd
    $script:SidW = Get-SISqlLpSid -ClientId $script:Web; $script:SidS = Get-SISqlLpSid -ClientId $script:Sup
    $script:SidA = Get-SISqlLpSid -ClientId $script:Alice; $script:SidG = Get-SISqlLpSid -ClientId $script:Grp
    $script:SidO = Get-SISqlLpSid -ClientId $script:Other
    $script:Who = 'Owner via Invardia: SQL least privilege, decision 2026-11-20'
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-11-20T10:00:00', 'Utc')

    function script:New-LpPrincipals {
        @([pscustomobject]@{ Component = 'engine'; Name = 'id-si-engine'; ClientId = $script:Eng }
          [pscustomobject]@{ Component = 'updater'; Name = 'id-si-updater'; ClientId = $script:Upd }
          [pscustomobject]@{ Component = 'web'; Name = 'id-si-web'; ClientId = $script:Web })
    }
    # THE WORLD: one database's memberships and permissions (NOT a closure: the fake finds it in $script:W)
    function script:New-LpWorld([hashtable]$Opt = @{}) {
        $m = New-Object System.Collections.Generic.List[object]
        foreach ($x in @(
            @('si_engine', 'id-si-engine', $script:SidE, 'E'), @('db_datareader', 'id-si-engine', $script:SidE, 'E'), @('db_datawriter', 'id-si-engine', $script:SidE, 'E'), @('db_ddladmin', 'id-si-engine', $script:SidE, 'E'),
            @('db_owner', 'id-si-engine', $script:SidE, 'E'),
            @('db_datareader', 'id-si-updater', $script:SidU, 'E'), @('db_datawriter', 'id-si-updater', $script:SidU, 'E'), @('db_ddladmin', 'id-si-updater', $script:SidU, 'E'),
            @('db_datareader', 'id-si-web', $script:SidW, 'E'),
            @('db_datareader', 'Invardia Support', $script:SidS, 'E'), @('db_datawriter', 'Invardia Support', $script:SidS, 'E'),
            @('db_datareader', 'grp-si-sql-admins', $script:SidG, 'X'),
            @('db_datawriter', 'alice@contoso.com', $script:SidA, 'E'),
            @('db_datareader', 'id-si-stranger', $script:SidO, 'E'))) {
            $m.Add([pscustomobject]@{ Role = $x[0]; Member = $x[1]; Sid = $x[2]; Type = $x[3] })
        }
        $p = New-Object System.Collections.Generic.List[object]
        foreach ($x in @(@(3, 'sidata', $null, 'SELECT', 'G', 'si_engine'), @(1, 'cfg', 'Setting', 'SELECT', 'G', 'si_engine'), @(1, 'cfg', 'WebKeyRing', 'SELECT', 'D', 'si_engine'),
                         @(1, 'cfg', 'Setting', 'UPDATE', 'W', 'id-si-web'), @(0, $null, $null, 'CONNECT', 'G', 'id-si-engine'))) {
            $p.Add([pscustomobject]@{ Class = $x[0]; Schema = $x[1]; Object = $x[2]; Permission = $x[3]; State = $x[4]; Grantee = $x[5] })
        }
        $script:W = @{ Members = $m; Perms = $p; Rows = @{}; Opt = $Opt; Sent = (New-Object System.Collections.Generic.List[string]); NotReady = [bool]$Opt.NotReady }
        if ($Opt.SupportRecorded) { $script:W.Rows['SupportApp'] = $script:Sup }
        $script:W.Sql = {
            param([string]$Database, [string]$Query, $Params, [string]$Mode)
            $W = $script:W
            if ($Mode -eq 'nonquery') {
                $W.Sent.Add($Query)
                if ($Query -match "cfg\.InstallState WHERE Name = N'(\w+)'") { $W.Rows[$Matches[1]] = [string]$Params.Value; return }
                if ($Query -match 'DROP MEMBER') {
                    if ($W.Opt.RemoveFails) { throw 'The statement was refused (fake): rolled back' }
                    $cur = ''
                    foreach ($l in ($Query -split "`n")) {
                        if ($l -match 'sid = (0x[0-9A-Fa-f]+)') { $cur = $Matches[1] }
                        if ($l -match 'ALTER ROLE \[(\w+)\] DROP MEMBER') { $r = $Matches[1]; for ($i = $W.Members.Count - 1; $i -ge 0; $i--) { if ($W.Members[$i].Role -eq $r -and $W.Members[$i].Sid -eq $cur) { $W.Members.RemoveAt($i) } } }
                    }
                    return
                }
                if ($Query -match 'ADD MEMBER') {
                    if ($W.Opt.RestoreFails) { throw 'refused (fake)' }
                    foreach ($l in ($Query -split "`n")) {
                        if ($l -match 'sid = (0x[0-9A-Fa-f]+)' -and $l -match "DATABASE_PRINCIPAL_ID\(N'(\w+)'\)") {
                            $s = ([regex]::Match($l, 'sid = (0x[0-9A-Fa-f]+)')).Groups[1].Value; $r = ([regex]::Match($l, "DATABASE_PRINCIPAL_ID\(N'(\w+)'\)")).Groups[1].Value
                            if (-not @($W.Members | Where-Object { $_.Role -eq $r -and $_.Sid -eq $s }).Count) {
                                $who = @($W.Members | Where-Object { $_.Sid -eq $s })[0]
                                $W.Members.Add([pscustomobject]@{ Role = $r; Member = $(if ($who) { $who.Member } else { 'id-si-engine' }); Sid = $s; Type = 'E' })
                            }
                        }
                    }
                    return
                }
                if ($Query -match '^(GRANT|DENY) (\w+)(?: \(\[(\w+)\]\))?(?: ON (\w+)::\[(\w+)\](?:\.\[(\w+)\])?)? TO \[([^\]]+)\]( WITH GRANT OPTION)?;') {
                    if ($W.Opt.RestoreFails) { throw 'refused (fake)' }
                    $cls = switch ($Matches[4]) { 'OBJECT' { 1 } 'SCHEMA' { 3 } default { 0 } }
                    $W.Perms.Add([pscustomobject]@{ Class = $cls; Schema = $Matches[5]; Object = $Matches[6]; Permission = $Matches[2]; State = $(if ($Matches[1] -eq 'DENY') { 'D' } elseif ($Matches[8]) { 'W' } else { 'G' }); Grantee = $Matches[7] })
                    return
                }
                return
            }
            if ($W.Opt.SnapshotFails -and $Query -match 'FROM sys\.database_permissions AS p;') { throw 'snapshot read refused (fake)' }
            if ($Query -match 'FROM sys\.database_permissions AS p;') {
                $rows = New-Object System.Collections.Generic.List[object]
                foreach ($x in $W.Members) { $rows.Add(@{ Kind = 'member'; RoleName = $x.Role; Member = $x.Member; Sid = $x.Sid; MemberType = $x.Type }) }
                foreach ($x in $W.Perms) { $rows.Add(@{ Kind = 'perm'; Class = $x.Class; SchemaName = $x.Schema; ObjectName = $x.Object; ColumnName = $null; Permission = $x.Permission; State = $x.State; Grantee = $x.Grantee; TargetType = $null }) }
                return , $rows.ToArray()
            }
            if ($Query -match "SELECT Value FROM cfg\.InstallState WHERE Name = N'(\w+)'") { $v = $W.Rows[$Matches[1]]; if ($v) { return , @(@{ Value = $v }) }; return , @() }
            , @()
        }
        $script:W.Ready = { param($Component, $UserName) [pscustomobject]@{ Ok = (-not $script:W.NotReady); Lines = @($(if ($script:W.NotReady) { 'the role si_engine would refuse 3 statement(s) the engine runs' })); Grants = 120 } }
        $script:W
    }
    function script:New-LpInput([string]$Mode, [hashtable]$Extra = @{}) {
        $o = [pscustomobject]@{ Ok = $true; Database = 'sqldb-si-pro'; Run = 'run-lp-1'; By = 'updater'; MiClientId = $script:Mi; Principals = @(New-LpPrincipals)
                                Support = $null; StandingOff = ''; SqlLp = $Mode; SqlLpNames = @(); SqlLpReason = $script:Who }
        foreach ($k in $Extra.Keys) { $o | Add-Member -NotePropertyName $k -NotePropertyValue $Extra[$k] -Force }
        $o
    }
    function script:Invoke-Lp([string]$Mode, [hashtable]$Extra = @{}, [scriptblock]$AfterChange) {
        $a = @{ DbInput = (New-LpInput $Mode $Extra); Sql = $script:W.Sql; Ready = $script:W.Ready; Now = { $script:T0 } }
        if ($AfterChange) { $a.AfterChange = $AfterChange }
        Invoke-SIDbInitSqlLeastPrivilege @a
    }
    function script:Get-LpRoles([string]$Sid) { @($script:W.Members | Where-Object { $_.Sid -eq $Sid } | ForEach-Object Role | Sort-Object) }
    function script:Get-LpRecord { $script:W.Rows['DbJobSqlLeastPrivilege'] | ConvertFrom-Json }
}

Describe 'RULE 1 -- the exact list: only the broad roles of SI''s own job identities, only after the replacement reads back' {
    BeforeEach { $null = New-LpWorld @{ SupportRecorded = $true } }
    It 'removes ONLY the engine''s db_datareader / db_datawriter / db_ddladmin -- never db_owner, never the updater, the web app, the Support app, the SQL admin group, a person or a stranger' {
        $before = ConvertFrom-SISqlLpSnapshot -Rows (& $script:W.Sql 'x' (Get-SISqlLpSnapshotSql) @{} 'rows')
        $p = Get-SISqlLpPlan -Before $before -Principals @(New-LpPrincipals) -NeverSids @($script:SidS, (Get-SISqlLpSid -ClientId $script:Mi)) -Ready @{ engine = [pscustomobject]@{ Ok = $true; Lines = @(); Grants = 1 } }
        @($p.Removals | ForEach-Object { '{0}:{1}' -f $_.Member, $_.Role }) | Should -Be @('id-si-engine:db_datareader', 'id-si-engine:db_datawriter', 'id-si-engine:db_ddladmin')
        @($p.Removals | ForEach-Object Replacement | Select-Object -Unique) | Should -Be @('si_engine')
        $never = $p.Never -join "`n"
        $never | Should -Match 'Invardia Support in db_datareader -- the Invardia Support app'
        $never | Should -Match 'grp-si-sql-admins in db_datareader -- a group'
        $never | Should -Match 'alice@contoso\.com in db_datawriter -- a person'
        $never | Should -Match 'id-si-stranger in db_datareader -- not one of SecurityInsight''s own job identities'
        ($p.Kept -join "`n") | Should -Match 'id-si-updater in db_ddladmin \(updater\) -- kept: the update''s schema step needs them'
        ($p.Kept -join "`n") | Should -Match 'id-si-web in db_datareader \(web\) -- kept'
        @($p.Removals | Where-Object { $_.Role -notin 'db_datareader', 'db_datawriter', 'db_ddladmin' }).Count | Should -Be 0 -Because 'db_owner is not a broad role of the list (never touched by this path)'
    }
    It 'NOTHING is removed while the replacement role is not ready (its grants do not read back)' {
        $before = ConvertFrom-SISqlLpSnapshot -Rows (& $script:W.Sql 'x' (Get-SISqlLpSnapshotSql) @{} 'rows')
        $p = Get-SISqlLpPlan -Before $before -Principals @(New-LpPrincipals) -Ready @{ engine = [pscustomobject]@{ Ok = $false; Lines = @('the role si_engine would refuse 3 statement(s)'); Grants = 0 } }
        @($p.Removals).Count | Should -Be 0
        ($p.NotReady -join ' ') | Should -Match 'its role si_engine is not ready: the role si_engine would refuse 3'
        (Get-SISqlLpPlan -Before $before -Principals @(New-LpPrincipals) -Ready @{}).Removals.Count | Should -Be 0 -Because 'no read-back at all = not ready'
    }
    It 'a principal of the input whose SID is the Support app''s, or the job''s own, is NEVER touched' {
        $before = ConvertFrom-SISqlLpSnapshot -Rows (& $script:W.Sql 'x' (Get-SISqlLpSnapshotSql) @{} 'rows')
        $pr = @([pscustomobject]@{ Component = 'engine'; Name = 'Invardia Support'; ClientId = $script:Sup })
        $p = Get-SISqlLpPlan -Before $before -Principals $pr -NeverSids @($script:SidS) -Ready @{ engine = [pscustomobject]@{ Ok = $true; Lines = @(); Grants = 1 } }
        @($p.Removals).Count | Should -Be 0
    }
    It 'a name that is neither id-si-* nor recorded is never touched; a name the install recorded is' {
        foreach ($x in $script:W.Members) { if ($x.Sid -eq $script:SidE) { $x.Member = 'uami-securityinsight-engine' } }
        $before = ConvertFrom-SISqlLpSnapshot -Rows (& $script:W.Sql 'x' (Get-SISqlLpSnapshotSql) @{} 'rows')
        $pr = @([pscustomobject]@{ Component = 'engine'; Name = 'id-si-engine'; ClientId = $script:Eng })
        $rd = @{ engine = [pscustomobject]@{ Ok = $true; Lines = @(); Grants = 1 } }
        (Get-SISqlLpPlan -Before $before -Principals $pr -Ready $rd).Removals.Count | Should -Be 0
        (Get-SISqlLpPlan -Before $before -Principals $pr -Ready $rd -AllowedNames @('uami-securityinsight-engine')).Removals.Count | Should -Be 3
    }
    It 'only an Entra user (type E) by default -- a SQL user or a group of the same SID is never touched' {
        foreach ($x in $script:W.Members) { if ($x.Sid -eq $script:SidE) { $x.Type = 'S' } }
        $before = ConvertFrom-SISqlLpSnapshot -Rows (& $script:W.Sql 'x' (Get-SISqlLpSnapshotSql) @{} 'rows')
        (Get-SISqlLpPlan -Before $before -Principals @(New-LpPrincipals) -Ready @{ engine = [pscustomobject]@{ Ok = $true; Lines = @(); Grants = 1 } }).Removals.Count | Should -Be 0
    }
    It 'the removal SQL checks the replacement role INSIDE its one transaction and drops only the planned memberships, by SID' {
        $sql = Get-SISqlLpRemoveSql -Removals @([pscustomobject]@{ Component = 'engine'; Member = 'id-si-engine'; Sid = $script:SidE; Role = 'db_datareader'; Replacement = 'si_engine' })
        $sql | Should -Match 'SET XACT_ABORT ON'
        $sql | Should -Match 'BEGIN TRANSACTION'
        $sql | Should -Match ("sid = {0}" -f $script:SidE)
        $sql.IndexOf('is not in its replacement role si_engine') | Should -BeLessThan $sql.IndexOf('DROP MEMBER')
        $sql | Should -Match 'ROLLBACK TRANSACTION; THROW'
        @([regex]::Matches($sql, 'DROP MEMBER')).Count | Should -Be 1
        { Get-SISqlLpRemoveSql -Removals @([pscustomobject]@{ Sid = $script:SidE; Role = 'db_owner'; Replacement = 'si_engine'; Member = 'x' }) } | Should -Throw '*not a broad role*'
        { Get-SISqlLpRemoveSql -Removals @([pscustomobject]@{ Sid = "0x01'; DROP TABLE x; --"; Role = 'db_datareader'; Replacement = 'si_engine'; Member = 'x' }) } | Should -Throw '*not a SID*'
    }
}

Describe 'RULE 2 -- plan first; apply only on the planned state; snapshot, diff and restore on any loss' {
    BeforeEach { $null = New-LpWorld @{ SupportRecorded = $true } }
    It 'plan: the exact list and the replacement grants in the log and the record -- NOTHING changes' {
        $r = Invoke-Lp 'plan'
        $r.State | Should -Be 'planned'
        ($r.Lines -join "`n") | Should -Match 'WOULD REMOVE: id-si-engine \(engine\) in db_datareader -- replaced by si_engine'
        ($r.Lines -join "`n") | Should -Match 'the replacement of engine: ready -- its role holds 120 grant\(s\) / deny\(s\), read back'
        @($script:W.Sent | Where-Object { $_ -match 'DROP MEMBER|ADD MEMBER|^GRANT|^DENY' }).Count | Should -Be 0
        (Get-LpRoles $script:SidE) | Should -Contain 'db_datareader'
        $rec = Get-LpRecord
        $rec.state | Should -Be 'planned'; $rec.mode | Should -Be 'plan'; $rec.n | Should -Be 3; $rec.run | Should -Be 'run-lp-1'
        $rec.list | Should -Match 'id-si-engine:db_datareader,db_datawriter,db_ddladmin'
        $rec.why | Should -Match 'asked: Owner via Invardia'
        ($script:W.Rows['DbJobSqlLeastPrivilegePlan'] | ConvertFrom-Json).hash | Should -Be $rec.hash
    }
    It 'apply WITHOUT a plan is refused -- nothing is removed' {
        $r = Invoke-Lp 'apply'
        $r.State | Should -Be 'refused'
        (Get-LpRecord).why | Should -Match 'no plan has run for this install'
        @($script:W.Sent | Where-Object { $_ -match 'DROP MEMBER' }).Count | Should -Be 0
        (Get-LpRoles $script:SidE) | Should -Contain 'db_datawriter'
    }
    It 'apply on ANOTHER state than the plan''s is refused -- nothing is removed' {
        $null = Invoke-Lp 'plan'
        # the state moves after the plan (someone took the engine's db_ddladmin off): the planned list is no longer the state
        foreach ($i in ($script:W.Members.Count - 1)..0) { if ($script:W.Members[$i].Role -eq 'db_ddladmin' -and $script:W.Members[$i].Sid -eq $script:SidE) { $script:W.Members.RemoveAt($i) } }
        $r = Invoke-Lp 'apply'
        $r.State | Should -Be 'refused'
        (Get-LpRecord).why | Should -Match 'is not the one planned'
        @($script:W.Sent | Where-Object { $_ -match 'DROP MEMBER' }).Count | Should -Be 0
    }
    It 'apply after the plan: the planned memberships go, NOTHING else changes, each identity read back, the removals recorded' {
        $null = Invoke-Lp 'plan'
        $snapBefore = ConvertFrom-SISqlLpSnapshot -Rows (& $script:W.Sql 'x' (Get-SISqlLpSnapshotSql) @{} 'rows')
        $r = Invoke-Lp 'apply'
        $r.State | Should -Be 'applied'
        (Get-LpRoles $script:SidE) | Should -Be @('db_owner', 'si_engine')
        (Get-LpRoles $script:SidU) | Should -Be @('db_datareader', 'db_datawriter', 'db_ddladmin')
        (Get-LpRoles $script:SidS) | Should -Be @('db_datareader', 'db_datawriter')
        (Get-LpRoles $script:SidA) | Should -Be @('db_datawriter')
        (Get-LpRoles $script:SidG) | Should -Be @('db_datareader')
        $after = ConvertFrom-SISqlLpSnapshot -Rows (& $script:W.Sql 'x' (Get-SISqlLpSnapshotSql) @{} 'rows')
        $d = Compare-SISqlLpSnapshot -Before $snapBefore -After $after -Planned @('db_datareader', 'db_datawriter', 'db_ddladmin' | ForEach-Object { Get-SISqlLpMemberKey -Role $_ -Sid $script:SidE })
        $d.Lost.Count | Should -Be 0; $d.Removed.Count | Should -Be 3
        ($r.Lines -join "`n") | Should -Match 'read back: engine -- db_datareader, db_datawriter, db_ddladmin gone; its role si_engine holds 120 grant'
        (Get-LpRecord).state | Should -Be 'applied'
        @(($script:W.Rows['DbJobSqlLeastPrivilegeRemoved'] | ConvertFrom-Json).items | ForEach-Object role | Sort-Object) | Should -Be @('db_datareader', 'db_datawriter', 'db_ddladmin')
        # the same value on the next update: nothing left to remove -- 'already', no statement
        $script:W.Sent.Clear()
        (Invoke-Lp 'apply').State | Should -Be 'already'
        @($script:W.Sent | Where-Object { $_ -match 'DROP MEMBER' }).Count | Should -Be 0
    }
    It 'THE DIFF: a planned removal is not a loss; anything else that disappeared is' {
        $b = ConvertFrom-SISqlLpSnapshot -Rows (& $script:W.Sql 'x' (Get-SISqlLpSnapshotSql) @{} 'rows')
        $k = Get-SISqlLpMemberKey -Role 'db_datareader' -Sid $script:SidE
        foreach ($i in ($script:W.Members.Count - 1)..0) { if ($script:W.Members[$i].Role -eq 'db_datareader' -and $script:W.Members[$i].Sid -eq $script:SidE) { $script:W.Members.RemoveAt($i) } }
        $script:W.Perms.RemoveAt(0)
        $a = ConvertFrom-SISqlLpSnapshot -Rows (& $script:W.Sql 'x' (Get-SISqlLpSnapshotSql) @{} 'rows')
        $d = Compare-SISqlLpSnapshot -Before $b -After $a -Planned @($k)
        @($d.Removed | ForEach-Object Key) | Should -Be @($k)
        @($d.Lost).Count | Should -Be 1
        (Format-SISqlLpItem $d.Lost[0]) | Should -Be 'GRANT SELECT on SCHEMA::sidata to si_engine'
        (Compare-SISqlLpSnapshot -Before $b -After $a).Lost.Count | Should -Be 2 -Because 'without the plan the membership is a loss too'
    }
    It 'A LOSS AFTER THE CHANGE (an ownership change elsewhere dropped grants): EVERYTHING is restored at once -- the lost grants and the planned removals -- read back equal to BEFORE' {
        $null = Invoke-Lp 'plan'
        $b = ConvertFrom-SISqlLpSnapshot -Rows (& $script:W.Sql 'x' (Get-SISqlLpSnapshotSql) @{} 'rows')
        # the side effect: two grants (one WITH GRANT OPTION) and a DENY vanish with the change
        $r = Invoke-Lp 'apply' -AfterChange { $script:W.Perms.RemoveAt(4); $script:W.Perms.RemoveAt(3); $script:W.Perms.RemoveAt(2) }
        $r.State | Should -Be 'restored'
        $a = ConvertFrom-SISqlLpSnapshot -Rows (& $script:W.Sql 'x' (Get-SISqlLpSnapshotSql) @{} 'rows')
        (Compare-SISqlLpSnapshot -Before $b -After $a).Lost.Count | Should -Be 0 -Because 'nothing is half-applied: every key of BEFORE is there again'
        (Get-LpRoles $script:SidE) | Should -Contain 'db_datareader'
        @($script:W.Perms | Where-Object { $_.Grantee -eq 'id-si-web' -and $_.State -eq 'W' }).Count | Should -Be 1 -Because 'WITH GRANT OPTION is restored as it was'
        @($script:W.Perms | Where-Object { $_.Object -eq 'WebKeyRing' -and $_.State -eq 'D' }).Count | Should -Be 1 -Because 'a DENY is restored as a DENY'
        (Get-LpRecord).why | Should -Match '3 item\(s\) disappeared that were not planned'
        ($r.Lines -join "`n") | Should -Match 'read back: every permission and membership is as it was before the change'
        $script:W.Rows.ContainsKey('DbJobSqlLeastPrivilegeRemoved') | Should -BeFalse -Because 'nothing counts as removed after a restore'
    }
    It 'the replacement does not read back AFTER the change: restored' {
        $null = Invoke-Lp 'plan'
        $r = Invoke-Lp 'apply' -AfterChange { $script:W.NotReady = $true }
        $r.State | Should -Be 'restored'
        (Get-LpRoles $script:SidE) | Should -Contain 'db_datawriter'
        (Get-LpRecord).why | Should -Match 'the replacement of engine did not read back after the change'
    }
    It 'the removal fails (the transaction rolled back): nothing changed, said as restored' {
        $null = Invoke-Lp 'plan'
        $script:W.Opt.RemoveFails = $true
        $r = Invoke-Lp 'apply'
        $r.State | Should -Be 'restored'
        (Get-LpRecord).why | Should -Match 'the removal failed \(rolled back\)'
        (Get-LpRoles $script:SidE) | Should -Contain 'db_datareader'
    }
    It 'a restore that does not read back is restore-incomplete, said loudly' {
        $null = Invoke-Lp 'plan'
        $script:W.Opt.RestoreFails = $true
        $r = Invoke-Lp 'apply' -AfterChange { $script:W.Perms.RemoveAt(0) }
        $r.State | Should -Be 'restore-incomplete'
        ($r.Lines -join "`n") | Should -Match 'STILL MISSING after the restore'
        Get-SISqlLpRecordLine -Record (Get-LpRecord) | Should -Match '^WARNING: .*restore did NOT read back complete'
    }
    It 'the restore statements: membership by SID, GRANT / DENY / WITH GRANT OPTION, a column grant' {
        $items = @(
            [pscustomobject]@{ Key = 'm|db_datareader|' + $script:SidE; Role = 'db_datareader'; Member = 'id-si-engine'; Sid = $script:SidE }
            [pscustomobject]@{ Key = 'p|x'; Class = 1; Schema = 'cfg'; Object = 'Setting'; Column = 'Value'; Permission = 'SELECT'; State = 'W'; Grantee = 'id-si-web' }
            [pscustomobject]@{ Key = 'p|y'; Class = 3; Schema = 'cfg'; Object = ''; Column = ''; Permission = 'DELETE'; State = 'D'; Grantee = 'si_engine' }
            [pscustomobject]@{ Key = 'p|z'; Class = 0; Schema = ''; Object = ''; Column = ''; Permission = 'VIEW DATABASE PERFORMANCE STATE'; State = 'G'; Grantee = 'si_engine' }
            [pscustomobject]@{ Key = 'p|q'; Class = 99; Schema = ''; Object = 'x'; Column = ''; Permission = 'SELECT'; State = 'G'; Grantee = 'si_engine' })
        $rs = Get-SISqlLpRestoreStatements -Items $items
        $rs.Statements[0].Sql | Should -Match ("ADD MEMBER ' \+ QUOTENAME\(USER_NAME\(@m\)\)")
        $rs.Statements[0].Sql | Should -Match ("sid = {0}" -f $script:SidE)
        $rs.Statements[1].Sql | Should -Be 'GRANT SELECT ([Value]) ON OBJECT::[cfg].[Setting] TO [id-si-web] WITH GRANT OPTION;'
        $rs.Statements[2].Sql | Should -Be 'DENY DELETE ON SCHEMA::[cfg] TO [si_engine];'
        $rs.Statements[3].Sql | Should -Be 'GRANT VIEW DATABASE PERFORMANCE STATE TO [si_engine];'
        @($rs.Unrestorable).Count | Should -Be 1
    }
}

Describe 'RULE 3 + 4 -- audited, read back; off = the way back' {
    BeforeEach { $null = New-LpWorld @{ SupportRecorded = $true } }
    It 'off puts the broad memberships back -- the ones this path removed (db_ddladmin too) and today''s two -- read back, the removed list cleared' {
        $null = Invoke-Lp 'plan'; $null = Invoke-Lp 'apply'
        (Get-LpRoles $script:SidE) | Should -Not -Contain 'db_datareader'
        $r = Invoke-Lp 'off'
        $r.State | Should -Be 'back'
        (Get-LpRoles $script:SidE) | Should -Be @('db_datareader', 'db_datawriter', 'db_ddladmin', 'db_owner', 'si_engine')
        (Get-LpRoles $script:SidS) | Should -Be @('db_datareader', 'db_datawriter') -Because 'off never touches the Support app either'
        ($r.Lines -join "`n") | Should -Match 'read back: id-si-engine in db_ddladmin'
        @(($script:W.Rows['DbJobSqlLeastPrivilegeRemoved'] | ConvertFrom-Json).items).Count | Should -Be 0
        Get-SISqlLpRecordLine -Record (Get-LpRecord) | Should -Match '^SQL least privilege OFF: the broad memberships are back'
    }
    It 'the record and its line for every state; it fits the 400-character row' {
        $v = New-SISqlLpRecordValue -Mode apply -State applied -Run 'r1' -Count 2 -Hash 'abc' -List 'id-si-engine:db_datareader,db_datawriter' -Why ('x' * 900)
        $v.Length | Should -BeLessOrEqual 400
        foreach ($s in 'planned', 'applied', 'already', 'back') { Get-SISqlLpRecordLine -Record ([pscustomobject]@{ mode = 'apply'; state = $s; n = 1; list = 'a:b' }) | Should -Not -Match '^WARNING' }
        foreach ($s in 'refused', 'not-ready', 'restored', 'restore-incomplete', 'failed') { Get-SISqlLpRecordLine -Record ([pscustomobject]@{ mode = 'apply'; state = $s; why = 'w' }) | Should -Match '^WARNING' }
    }
    It 'the heartbeat''s setup step sql-least-privilege (applied / already = ok, planned / restored = missing, off = n/a; no row = left out)' {
        $row = { param($st) @([pscustomobject]@{ Name = 'DbJobSqlLeastPrivilege'; Value = (New-SISqlLpRecordValue -Mode apply -State $st -Count 3 -NowUtc $script:T0) }) }
        foreach ($c in @(@('applied', 'ok'), @('already', 'ok'), @('planned', 'missing'), @('restored', 'missing'), @('restore-incomplete', 'missing'), @('refused', 'missing'), @('back', 'n/a'), @('failed', 'unknown'))) {
            $s = @(Get-SISetupSteps -StateRows (& $row $c[0]) -SupportGrant $null | Where-Object key -eq 'sql-least-privilege')[0]
            $s.state | Should -Be $c[1] -Because $c[0]
            $s.checkedAt | Should -Be '2026-11-20T10:00:00Z'
        }
        @(Get-SISetupSteps -StateRows @() -SupportGrant $null | Where-Object key -eq 'sql-least-privilege').Count | Should -Be 0
        (Get-SISetupStepsContract).StateNames | Should -Contain 'DbJobSqlLeastPrivilege'
    }
    It 'NEVER throws: a failed read is the state failed, recorded' {
        $null = New-LpWorld @{ SnapshotFails = $true }
        { $script:LpR = Invoke-Lp 'apply' } | Should -Not -Throw
        $script:LpR.State | Should -Be 'failed'
        (Get-LpRecord).why | Should -Match 'snapshot read refused'
    }
}

Describe 'the job''s input and run: the mode is per execution, never a refused run, never part of the verdict' {
    BeforeAll {
        function script:New-JobEnv([hashtable]$Extra = @{}) {
            $p = @(@{ component = 'engine'; name = 'id-si-engine'; clientId = $script:Eng }, @{ component = 'updater'; name = 'id-si-updater'; clientId = $script:Upd })
            $e = @{ SI_DBINIT_SERVER = 'sqlserver.example'; SI_DBINIT_DATABASE = 'sqldb-si-pro'; SI_DBINIT_LEDGER_DATABASE = ''; SI_DBINIT_MI_CLIENT_ID = $script:Mi
                    SI_DBINIT_PRINCIPALS = (ConvertTo-Json -InputObject $p -Compress); SI_DBINIT_SIGNED_GRANTS = '0'; SI_DBINIT_ENGINE_ROLE_ONLY = '1'; SI_DBINIT_RUN = 'run000000001'; SI_DBINIT_BY = 'updater' }
            foreach ($k in $Extra.Keys) { $e[$k] = $Extra[$k] }
            $e
        }
        # the job's other reads answered (the users with the roles the read-back expects), the rest by the least-privilege world
        function script:New-JobSql {
            $script:JobCalls = New-Object System.Collections.Generic.List[string]
            {
                param([string]$Database, [string]$Query, $Params, [string]$Mode)
                $script:JobCalls.Add($Query)
                if ($Query -eq 'SELECT 1') { return , @(@{ x = 1 }) }
                if ($Query -match 'FROM sys\.database_principals AS p') { return , @(@{ Name = 'id-si-engine'; ClientId = $script:Eng; RoleName = 'si_engine' }, @{ Name = 'id-si-updater'; ClientId = $script:Upd; RoleName = 'db_datareader' }, @{ Name = 'id-si-updater'; ClientId = $script:Upd; RoleName = 'db_datawriter' }, @{ Name = 'id-si-updater'; ClientId = $script:Upd; RoleName = 'db_ddladmin' }, @{ Name = 'id-si-updater'; ClientId = $script:Upd; RoleName = 'db_securityadmin' }) }
                & $script:W.Sql $Database $Query $Params $Mode
            }
        }
    }
    It 'SI_DBINIT_SQLLP / _NAMES / _REASON are read; a value that is not a mode is said, and the run is NOT refused' {
        $in = Read-SIDbInitInput -Env (New-JobEnv @{ SI_DBINIT_SQLLP = 'Apply'; SI_DBINIT_SQLLP_NAMES = 'uami-si-engine; bad name;id-si-engine'; SI_DBINIT_SQLLP_REASON = "Owner:`n least privilege" })
        $in.Ok | Should -BeTrue; $in.SqlLp | Should -Be 'apply'
        @($in.SqlLpNames) | Should -Be @('uami-si-engine', 'id-si-engine')
        $in.SqlLpReason | Should -Be 'Owner: least privilege'
        $bad = Read-SIDbInitInput -Env (New-JobEnv @{ SI_DBINIT_SQLLP = 'remove-everything' })
        $bad.Ok | Should -BeTrue; $bad.SqlLp | Should -Be ''; $bad.SqlLpNote | Should -Match 'is not plan, apply or off'
        (Read-SIDbInitInput -Env (New-JobEnv)).SqlLp | Should -Be ''
    }
    It 'Invoke-SIDbInit runs the step after its batches and before its read-back; a refused step leaves the verdict ok (exit 0)' {
        $in = Read-SIDbInitInput -Env (New-JobEnv @{ SI_DBINIT_SQLLP = 'apply' })
        $null = New-LpWorld
        $sql = New-JobSql
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDbInit -DbInput $in -Sql $sql -Log { param($m) $lines.Add($m) } -LoginWaitSeconds 0 -Sleep { param($s) } -SqlLpRequired @() -SqlLpReady $script:W.Ready
        $r.ExitCode | Should -Be 0 -Because ('a least-privilege refusal is never the job''s verdict. Lines: ' + ($lines -join ' | '))
        ($lines -join "`n") | Should -Match 'WARNING: SQL least privilege \(apply\) refused, nothing changed: no plan has run'
        $snapAt = $script:JobCalls.FindIndex([Predicate[string]] { param($q) $q -match 'FROM sys\.database_permissions AS p;' })
        $engAt = $script:JobCalls.FindIndex([Predicate[string]] { param($q) $q -match 'CREATE ROLE \[si_engine\]' })
        $engAt | Should -BeGreaterThan -1; $snapAt | Should -BeGreaterThan $engAt -Because 'the replacement grants are applied first, then proven, then anything is removed'
    }
    It 'Start-SIDbInitRun passes the least-privilege variables on (and nothing it does not know)' {
        $script:StartBody = $null
        $arm = { param($Method, $Path, $Body) if ($Path -match '/start\?') { $script:StartBody = $Body; return [pscustomobject]@{ name = 'e1' } }; [pscustomobject]@{ properties = [pscustomobject]@{ status = 'Succeeded' } } }
        $job = [pscustomobject]@{ properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'dbinit'; image = 'i'; env = @() }) } } }
        $null = Start-SIDbInitRun -Arm $arm -JobId '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-dbinit' -Job $job -By updater -Sleep { param($s) } -Extra @{ SI_DBINIT_SQLLP = 'plan'; SI_DBINIT_SQLLP_NAMES = 'a;b'; SI_DBINIT_SQLLP_REASON = 'r r r'; SI_DBINIT_SOMETHING = 'x' }
        $env = @{}; foreach ($e in $script:StartBody.containers[0].env) { $env[$e.name] = $e.value }
        $env.SI_DBINIT_SQLLP | Should -Be 'plan'; $env.SI_DBINIT_SQLLP_NAMES | Should -Be 'a;b'; $env.SI_DBINIT_SQLLP_REASON | Should -Be 'r r r'
        $env.ContainsKey('SI_DBINIT_SOMETHING') | Should -BeFalse
    }
    It 'gap 1: the guided install''s run with a switch on records the switches for the updater (merged: on stays on)' {
        $in = Read-SIDbInitInput -Env (New-JobEnv @{ SI_DBINIT_BY = 'installer' })
        $null = New-LpWorld
        $sql = New-JobSql
        $r = Invoke-SIDbInit -DbInput $in -Sql $sql -Log { param($m) } -LoginWaitSeconds 0 -Sleep { param($s) }
        $r.ExitCode | Should -Be 0
        $sw = ConvertFrom-SISqlLpSwitches -Value $script:W.Rows['SqlLeastPrivilege']
        $sw.Present | Should -BeTrue; $sw.EngineRoleOnly | Should -BeTrue; $sw.SignedGrants | Should -BeFalse; $sw.By | Should -Be 'installer'
    }
}

Describe 'the updater''s decision: a usable reason, the switches kept (gap 1), off the way back' {
    It 'a mode needs SI_UPDATER_CONTROLPLANE_REASON naming who asked and why -- else refused, nothing handed on' {
        foreach ($bad in '', 'update', 'x', 'test') {
            $d = Get-SISqlLpDecision -ModeValue 'apply' -ReasonProblem (Test-SIControlPlaneReason -Reason $bad)
            $d.Mode | Should -Be '' -Because "reason '$bad'"
            $d.EngineRoleOnly | Should -BeFalse
            ($d.Lines -join ' ') | Should -Match 'WARNING: control-plane value: SI_UPDATER_SQL_LEAST_PRIVILEGE=apply not handed on -- every change of SQL least privilege needs SI_UPDATER_CONTROLPLANE_REASON'
        }
        (Get-SISqlLpDecision -ModeValue 'apply' -ReasonProblem (Test-SIControlPlaneReason -Reason $script:Who)).Mode | Should -Be 'apply'
        (Get-SISqlLpDecision -ModeValue 'drop all' -ReasonProblem '').Refused | Should -Match 'is not plan, apply or off'
    }
    It 'engine role only = a switch ON, or the row in force, or apply; only off turns it off; signed grants likewise' {
        $on = ConvertFrom-SISqlLpSwitches -Value (New-SISqlLpSwitchesValue -EngineRoleOnly $true -SignedGrants $true)
        (Get-SISqlLpDecision).EngineRoleOnly | Should -BeFalse
        (Get-SISqlLpDecision -EnvEngineOn $true).EngineRoleOnly | Should -BeTrue
        $d = Get-SISqlLpDecision -Switches $on
        $d.EngineRoleOnly | Should -BeTrue; $d.SignedGrants | Should -BeTrue -Because 'the job''s environment lost the switch, the row keeps it'
        ($d.Lines -join ' ') | Should -Match 'the update adds no broad role back'
        (Get-SISqlLpDecision -ModeValue 'apply').EngineRoleOnly | Should -BeTrue
        (Get-SISqlLpDecision -ModeValue 'plan').EngineRoleOnly | Should -BeFalse
        $off = Get-SISqlLpDecision -ModeValue 'off' -Switches $on -EnvEngineOn $true -EnvSignedOn $true
        $off.Mode | Should -Be 'off'; $off.EngineRoleOnly | Should -BeFalse; $off.SignedGrants | Should -BeFalse
        # an off WITHOUT a reason changes nothing: the switches stay on
        (Get-SISqlLpDecision -ModeValue 'off' -ReasonProblem 'it is not set' -Switches $on).EngineRoleOnly | Should -BeTrue
    }
    It 'the row after a run: an apply that read back sets it; a refused apply does not; off clears it; a switch on keeps it; nothing new = no write' {
        $none = ConvertFrom-SISqlLpSwitches -Value ''
        $n1 = Get-SISqlLpNextSwitches -Decision (Get-SISqlLpDecision -ModeValue 'apply') -Switches $none -JobState 'applied'
        $n1.Write | Should -BeTrue; $n1.EngineRoleOnly | Should -BeTrue
        (Get-SISqlLpNextSwitches -Decision (Get-SISqlLpDecision -ModeValue 'apply') -Switches $none -JobState 'refused').Write | Should -BeFalse
        $on = ConvertFrom-SISqlLpSwitches -Value (New-SISqlLpSwitchesValue -EngineRoleOnly $true -SignedGrants $false)
        $n2 = Get-SISqlLpNextSwitches -Decision (Get-SISqlLpDecision -ModeValue 'off') -Switches $on -JobState 'back'
        $n2.Write | Should -BeTrue; $n2.EngineRoleOnly | Should -BeFalse
        $n3 = Get-SISqlLpNextSwitches -Decision (Get-SISqlLpDecision -EnvSignedOn $true) -Switches $none -EnvSignedOn $true
        $n3.Write | Should -BeTrue; $n3.SignedGrants | Should -BeTrue
        (Get-SISqlLpNextSwitches -Decision (Get-SISqlLpDecision) -Switches $none).Write | Should -BeFalse
        (Get-SISqlLpNextSwitches -Decision (Get-SISqlLpDecision -Switches $on) -Switches $on).Write | Should -BeFalse
    }
}

Describe 'the updater end to end (fake ARM + store): the switches reach the job, the mode is handed on, the result said and kept' {
    BeforeAll {
        function script:Write-UpdLog { param($m) $script:UpdLines.Add([string]$m) }
        . ([IO.Path]::Combine($script:SIRoot, 'container', 'updater', '_shared', 'SI-UpdaterDatabase.ps1'))
        function script:New-LpUpdWorld([hashtable]$Opt = @{}) {
            $script:UW = @{ Rows = @{}; Opt = $Opt; Job = $null; StartEnv = $null; Starts = 0 }
            $script:UW.Rows['DbJob'] = (New-SIDbInitRecordValue -State ok -Run 'earlier' -By installer)
            if ($Opt.Switches) { $script:UW.Rows['SqlLeastPrivilege'] = $Opt.Switches }
            $script:UW.ArmSeam = {
                param($Method, $Path, $Body)
                $W = $script:UW
                if ($Path -match 'userAssignedIdentities/id-si-dbinit') { return [pscustomobject]@{ id = '/x/id-si-dbinit'; properties = [pscustomobject]@{ clientId = 'c-db'; principalId = 'p-db' } } }
                if ($Path -match '/start\?') {
                    $W.Starts++
                    $env = @{}; foreach ($e in $Body.containers[0].env) { $env[$e.name] = $e.value }
                    $W.StartEnv = $env
                    $run = $env['SI_DBINIT_RUN']
                    $W.Rows['DbJob'] = New-SIDbInitRecordValue -State ok -Run $run -By updater -Count 5
                    $W.Rows['DbJobUpdater'] = $W.Rows['DbJob']
                    if ($env['SI_DBINIT_SQLLP'] -and $W.Opt.JobState) { $W.Rows['DbJobSqlLeastPrivilege'] = New-SISqlLpRecordValue -Mode $env['SI_DBINIT_SQLLP'] -State $W.Opt.JobState -Run $(if ($W.Opt.OldJob) { 'other' } else { $run }) -Count 3 -List 'id-si-engine:db_datareader,db_datawriter' }
                    return [pscustomobject]@{ name = 'caj-si-dbinit-e1' }
                }
                if ($Path -match '/executions/') { return [pscustomobject]@{ properties = [pscustomobject]@{ status = 'Succeeded' } } }
                if ($Path -match '/jobs/caj-si-dbinit\?') { if ($Method -eq 'PUT') { $W.Job = $Body }; return [pscustomobject]@{ properties = [pscustomobject]@{ provisioningState = 'Succeeded'; template = [pscustomobject]$W.Job.properties.template } } }
                $null
            }
            $script:UW.Lists = { param($Kind) switch ($Kind) { 'jobs' { @($script:LpEngJob) } 'apps' { @() } default { @([pscustomobject]@{ name = 'id-si-engine'; id = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-engine'; properties = [pscustomobject]@{ clientId = $script:Eng } }) } } }
            $script:UW.Store = [pscustomobject]@{ Server = 'sqlserver.example'; Database = 'sqldb-si-pro'
                Invoke = { param($Sql, $Params, $Mode) $W = $script:UW
                    if ($Sql -match "Name = N'(\w+)'") { $nm = $Matches[1] } else { $nm = '' }
                    if ($Mode -eq 'nonquery') { if ($nm) { $W.Rows[$nm] = [string]$Params.Value }; return }
                    if ($nm -and $W.Rows[$nm]) { return , @(@{ Value = $W.Rows[$nm] }) }
                    , @() } }
            $script:UW
        }
        $script:LpEngJob = [pscustomobject]@{ name = 'caj-si-flow'; location = 'westeurope'
            properties = [pscustomobject]@{ environmentId = 'env'
                configuration = [pscustomobject]@{ registries = @([pscustomobject]@{ server = 'acr.azurecr.io'; identity = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-engine' }) }
                template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'flow'; image = 'acr.azurecr.io/si-orchestrator:v3'; env = @([pscustomobject]@{ name = 'SI_UAMI_ClientId'; value = $script:Eng }) }) } } }
        function script:Invoke-LpUpd([hashtable]$Env) {
            $e = @{ SI_Setup_EngineLeastPrivilege = ''; SI_Setup_SignedGrantProcedure = ''; SI_UPDATER_SQL_LEAST_PRIVILEGE = ''; SI_UPDATER_CONTROLPLANE_REASON = '' }
            foreach ($k in $Env.Keys) { $e[$k] = $Env[$k] }
            Invoke-SIUpdaterDbJob -SIRoot $script:SIRoot -Store $script:UW.Store -ResourceGroup 'rg' -SubscriptionId 's' -Arm $script:UW.ArmSeam -Lists $script:UW.Lists -Sleep { param($s) } -Env $e
        }
        function script:Get-JobBodyEnv { $h = @{}; foreach ($e in $script:UW.Job.properties.template.containers[0].env) { $h[$e.name] = $e.value }; $h }
    }
    BeforeEach { $script:UpdLines = New-Object System.Collections.Generic.List[string]; $global:SI_UpdaterSqlLp = $null }
    It 'GAP 1: the job''s environment has NO switch, the row says engine role only -- the job is still handed SI_DBINIT_ENGINE_ROLE_ONLY=1 (no broad role added back)' {
        $null = New-LpUpdWorld @{ Switches = (New-SISqlLpSwitchesValue -EngineRoleOnly $true -SignedGrants $true) }
        $r = Invoke-LpUpd @{}
        $r.Ok | Should -BeTrue -Because ($script:UpdLines -join ' | ')
        (Get-JobBodyEnv).SI_DBINIT_ENGINE_ROLE_ONLY | Should -Be '1'
        (Get-JobBodyEnv).SI_DBINIT_SIGNED_GRANTS | Should -Be '1'
        $script:UW.StartEnv.ContainsKey('SI_DBINIT_SQLLP') | Should -BeFalse
        ($script:UpdLines -join "`n") | Should -Match 'the update adds no broad role back'
    }
    It 'GAP 1: a switch ON on the job is kept in the row (read back), so a later job environment without it changes nothing' {
        $null = New-LpUpdWorld
        $null = Invoke-LpUpd @{ SI_Setup_EngineLeastPrivilege = 'true' }
        (Get-JobBodyEnv).SI_DBINIT_ENGINE_ROLE_ONLY | Should -Be '1'
        (ConvertFrom-SISqlLpSwitches -Value $script:UW.Rows['SqlLeastPrivilege']).EngineRoleOnly | Should -BeTrue
        ($script:UpdLines -join "`n") | Should -Match 'the switches in force are now engine role only True.*read back'
        $null = Invoke-LpUpd @{}
        (Get-JobBodyEnv).SI_DBINIT_ENGINE_ROLE_ONLY | Should -Be '1'
    }
    It 'apply with a reason: handed to the job with engine role only; the job''s result said; an apply that read back keeps the switch on' {
        $null = New-LpUpdWorld @{ JobState = 'applied' }
        $r = Invoke-LpUpd @{ SI_UPDATER_SQL_LEAST_PRIVILEGE = 'apply'; SI_UPDATER_CONTROLPLANE_REASON = $script:Who }
        $r.Ok | Should -BeTrue
        $script:UW.StartEnv.SI_DBINIT_SQLLP | Should -Be 'apply'
        $script:UW.StartEnv.SI_DBINIT_SQLLP_REASON | Should -Be $script:Who
        $script:UW.StartEnv.SI_DBINIT_SQLLP_NAMES | Should -Match 'id-si-engine'
        (Get-JobBodyEnv).SI_DBINIT_ENGINE_ROLE_ONLY | Should -Be '1'
        ($script:UpdLines -join "`n") | Should -Match 'SQL least privilege APPLIED: 3 broad membership\(s\) removed'
        $global:SI_UpdaterSqlLp.State | Should -Be 'applied'
        (ConvertFrom-SISqlLpSwitches -Value $script:UW.Rows['SqlLeastPrivilege']).EngineRoleOnly | Should -BeTrue
    }
    It 'apply WITHOUT a usable reason: one warning, nothing handed on, the update goes on' {
        $null = New-LpUpdWorld @{ JobState = 'applied' }
        $r = Invoke-LpUpd @{ SI_UPDATER_SQL_LEAST_PRIVILEGE = 'apply'; SI_UPDATER_CONTROLPLANE_REASON = 'update' }
        $r.Ok | Should -BeTrue
        $script:UW.StartEnv.ContainsKey('SI_DBINIT_SQLLP') | Should -BeFalse
        (Get-JobBodyEnv).SI_DBINIT_ENGINE_ROLE_ONLY | Should -Be '0'
        @($script:UpdLines | Where-Object { $_ -match '^WARNING: control-plane value: SI_UPDATER_SQL_LEAST_PRIVILEGE=apply not handed on' }).Count | Should -Be 1
    }
    It 'a refused apply (no plan) is a warning and never a failed update; the switch is not set by it' {
        $null = New-LpUpdWorld @{ JobState = 'refused' }
        $r = Invoke-LpUpd @{ SI_UPDATER_SQL_LEAST_PRIVILEGE = 'apply'; SI_UPDATER_CONTROLPLANE_REASON = $script:Who }
        $r.Ok | Should -BeTrue; $r.Action | Should -Be 'ok'
        ($script:UpdLines -join "`n") | Should -Match 'WARNING: SQL least privilege \(apply\) refused'
        $script:UW.Rows.ContainsKey('SqlLeastPrivilege') | Should -BeFalse
    }
    It 'the installed job does not know it yet (no row for this run): said, the update goes on' {
        $null = New-LpUpdWorld @{ JobState = 'applied'; OldJob = $true }
        $r = Invoke-LpUpd @{ SI_UPDATER_SQL_LEAST_PRIVILEGE = 'plan'; SI_UPDATER_CONTROLPLANE_REASON = $script:Who }
        $r.Ok | Should -BeTrue
        ($script:UpdLines -join "`n") | Should -Match 'recorded no result for this run -- the installed version''s job does not do it yet'
    }
    It 'off: the switches go to 0 for the job (the broad roles are added back by it), the row cleared' {
        $null = New-LpUpdWorld @{ Switches = (New-SISqlLpSwitchesValue -EngineRoleOnly $true -SignedGrants $true); JobState = 'back' }
        $r = Invoke-LpUpd @{ SI_UPDATER_SQL_LEAST_PRIVILEGE = 'off'; SI_UPDATER_CONTROLPLANE_REASON = $script:Who; SI_Setup_EngineLeastPrivilege = 'true' }
        $r.Ok | Should -BeTrue
        (Get-JobBodyEnv).SI_DBINIT_ENGINE_ROLE_ONLY | Should -Be '0'
        (Get-JobBodyEnv).SI_DBINIT_SIGNED_GRANTS | Should -Be '0'
        $script:UW.StartEnv.SI_DBINIT_SQLLP | Should -Be 'off'
        $sw = ConvertFrom-SISqlLpSwitches -Value $script:UW.Rows['SqlLeastPrivilege']
        $sw.EngineRoleOnly | Should -BeFalse; $sw.SignedGrants | Should -BeFalse
        ($script:UpdLines -join "`n") | Should -Match 'SQL least privilege OFF: the broad memberships are back'
    }
}

Describe 'the images carry every file' {
    It 'the database setup job (the engine image: COPY . /app/) loads the step; the updater image carries setup/ and loads it from the release' {
        $eng = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'container', 'Dockerfile'))
        $eng | Should -Match '(?m)^COPY \. /app/'
        $ign = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, '.dockerignore'))
        $ign | Should -Not -Match '(?m)^(setup/|setup/_shared/|\*\*/SI-SqlLeastPrivilege)'
        $upd = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'container', 'updater', 'Dockerfile'))
        $upd | Should -Match '(?m)^COPY setup/ /si/setup/'
        $upd | Should -Match '(?m)^COPY container/updater/_shared/ \./_shared/'
        $db = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-DbInitJob.ps1'))
        $db | Should -Match "'setup/_shared/SI-SqlLeastPrivilege\.ps1'"
        $ud = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'container', 'updater', '_shared', 'SI-UpdaterDatabase.ps1'))
        $ud | Should -Match "'SI-SqlLeastPrivilege\.ps1', 'SI-ControlPlaneValues\.ps1'"
        [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'container', 'Start-SIDbInit.ps1')) | Should -Match 'Invoke-SIDbInit -DbInput \$dbInput -Sql \$sql -Version \$version -SIRoot \$siRoot'
        Test-Path -LiteralPath ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-SqlLeastPrivilege.ps1')) | Should -BeTrue
    }
}

Describe 'REAL SQL: the snapshot, the removal transaction, the diff and the restore against the catalog views' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:DbName = 'si_sqllp_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$($script:DbName)]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $global:SIPesterLpCn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$($script:DbName);$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
        $global:SIPesterLpCn.Open()
        # the job's seam on one connection: rows of the LAST result set as hashtables
        $script:RSql = {
            param([string]$Database, [string]$Query, $Params, [string]$Mode)
            $c = $global:SIPesterLpCn.CreateCommand(); $c.CommandText = $Query; $c.CommandTimeout = 300
            if ($Params) { foreach ($k in @($Params.Keys)) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $Params[$k]) { [DBNull]::Value } else { $Params[$k] })) } }
            if ($Mode -eq 'nonquery') { [void]$c.ExecuteNonQuery(); return }
            $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
            try { do { if ($rd.FieldCount -gt 0) { $out = New-Object System.Collections.Generic.List[object]; while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) } } } while ($rd.NextResult()) } finally { $rd.Close() }
            , $out.ToArray()
        }
        & $script:RSql '' 'CREATE SCHEMA cfg;' @{} 'nonquery'
        & $script:RSql '' @'
CREATE TABLE cfg.InstallState (Name nvarchar(128) NOT NULL PRIMARY KEY, Value nvarchar(400) NULL, [Version] nvarchar(32) NULL, UpdatedAt datetime2 NOT NULL DEFAULT SYSUTCDATETIME(), UpdatedBy nvarchar(128) NULL);
CREATE TABLE cfg.T (Id int NOT NULL PRIMARY KEY, Note nvarchar(40) NULL);
CREATE ROLE si_engine;
GRANT SELECT ON SCHEMA::cfg TO si_engine;
DENY UPDATE ON OBJECT::cfg.InstallState TO si_engine;
CREATE USER [id-si-engine] WITHOUT LOGIN; ALTER ROLE si_engine ADD MEMBER [id-si-engine]; ALTER ROLE db_datareader ADD MEMBER [id-si-engine]; ALTER ROLE db_datawriter ADD MEMBER [id-si-engine];
CREATE USER [id-si-updater] WITHOUT LOGIN; ALTER ROLE db_datareader ADD MEMBER [id-si-updater]; ALTER ROLE db_datawriter ADD MEMBER [id-si-updater]; ALTER ROLE db_ddladmin ADD MEMBER [id-si-updater];
CREATE USER [id-si-web] WITHOUT LOGIN; ALTER ROLE db_datareader ADD MEMBER [id-si-web]; GRANT SELECT (Note) ON OBJECT::cfg.T TO [id-si-web] WITH GRANT OPTION;
CREATE USER [Invardia Support] WITHOUT LOGIN; ALTER ROLE db_datareader ADD MEMBER [Invardia Support]; ALTER ROLE db_datawriter ADD MEMBER [Invardia Support];
CREATE USER [alice@contoso.com] WITHOUT LOGIN; ALTER ROLE db_datawriter ADD MEMBER [alice@contoso.com];
'@ @{} 'nonquery'
        $sids = @{}; foreach ($r in @(& $script:RSql '' "SELECT name, CONVERT(varchar(200), sid, 1) AS Sid FROM sys.database_principals WHERE name IN (N'id-si-engine', N'id-si-updater', N'id-si-web', N'Invardia Support', N'alice@contoso.com')" @{} 'rows' | ForEach-Object { $_ })) { $sids[[string]$r.name] = [string]$r.Sid }
        $script:RSids = $sids
        # the principals by their REAL SIDs (users without login cannot carry an Entra client id); the Support app's SID is a never-SID
        $script:RIn = [pscustomobject]@{ Ok = $true; Database = $script:DbName; Run = 'run-real-1'; By = 'updater'; MiClientId = ''; Support = $null; StandingOff = ''; SqlLp = 'plan'; SqlLpNames = @(); SqlLpReason = $script:Who
            Principals = @([pscustomobject]@{ Component = 'engine'; Name = 'id-si-engine'; ClientId = $script:Eng; Sid = $sids['id-si-engine'] }
                           [pscustomobject]@{ Component = 'updater'; Name = 'id-si-updater'; ClientId = $script:Upd; Sid = $sids['id-si-updater'] }
                           [pscustomobject]@{ Component = 'web'; Name = 'id-si-web'; ClientId = $script:Web; Sid = $sids['id-si-web'] }) }
        $script:RReq = @([pscustomobject]@{ Object = 'cfg.T'; Permission = 'SELECT'; Sites = @('engine/x.ps1:1') })
        function script:Invoke-RLp([string]$Mode, [scriptblock]$After) {
            $script:RIn.SqlLp = $Mode
            $a = @{ DbInput = $script:RIn; Sql = $script:RSql; Required = $script:RReq; AllowedTypes = @('S'); Now = { [datetime]::UtcNow } }
            if ($After) { $a.AfterChange = $After }
            Invoke-SIDbInitSqlLeastPrivilege @a
        }
        function script:Get-RRoles([string]$User) { @(& $script:RSql '' ("SELECT r.name AS R FROM sys.database_role_members rm JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id JOIN sys.database_principals m ON m.principal_id = rm.member_principal_id WHERE m.name = N'{0}' ORDER BY r.name" -f $User.Replace("'", "''")) @{} 'rows' | ForEach-Object { $_.R }) }
        function script:Get-RSnap { ConvertFrom-SISqlLpSnapshot -Rows @(& $script:RSql '' (Get-SISqlLpSnapshotSql) @{} 'rows' | ForEach-Object { $_ }) }
        function script:Get-RRow([string]$Name) { @(& $script:RSql '' ("SELECT Value FROM cfg.InstallState WHERE Name = N'{0}'" -f $Name) @{} 'rows' | ForEach-Object { $_ })[0].Value }
    }
    AfterAll {
        try { $global:SIPesterLpCn.Dispose() } catch { }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$($script:DbName)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:DbName)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    It 'plan changes nothing; apply removes only the engine''s broad roles in one transaction; every permission is unchanged; the replacement reads back' {
        $b = Get-RSnap
        $p = Invoke-RLp 'plan'
        $p.State | Should -Be 'planned' -Because ($p.Lines -join ' | ')
        (Compare-SISqlLpSnapshot -Before $b -After (Get-RSnap)).Lost.Count | Should -Be 0
        $a = Invoke-RLp 'apply'
        $a.State | Should -Be 'applied' -Because ($a.Lines -join ' | ')
        (Get-RRoles 'id-si-engine') | Should -Be @('si_engine')
        (Get-RRoles 'id-si-updater') | Should -Be @('db_datareader', 'db_datawriter', 'db_ddladmin')
        (Get-RRoles 'Invardia Support') | Should -Be @('db_datareader', 'db_datawriter')
        (Get-RRoles 'alice@contoso.com') | Should -Be @('db_datawriter')
        $d = Compare-SISqlLpSnapshot -Before $b -After (Get-RSnap) -Planned @('db_datareader', 'db_datawriter' | ForEach-Object { Get-SISqlLpMemberKey -Role $_ -Sid $script:RSids['id-si-engine'] })
        $d.Lost.Count | Should -Be 0; $d.Removed.Count | Should -Be 2
        @($d.Gained).Count | Should -Be 0
        (Get-RRow 'DbJobSqlLeastPrivilege' | ConvertFrom-Json).state | Should -Be 'applied'
    }
    It 'a REAL loss during the change (grants revoked elsewhere): everything restored at once -- the column grant WITH GRANT OPTION, the DENY and the memberships -- equal to BEFORE' {
        & $script:RSql '' 'ALTER ROLE db_datareader ADD MEMBER [id-si-engine]; ALTER ROLE db_datawriter ADD MEMBER [id-si-engine];' @{} 'nonquery'
        $b = Get-RSnap
        (Invoke-RLp 'plan').State | Should -Be 'planned'
        $r = Invoke-RLp 'apply' { & $script:RSql '' 'REVOKE SELECT (Note) ON OBJECT::cfg.T FROM [id-si-web] CASCADE; REVOKE UPDATE ON OBJECT::cfg.InstallState FROM si_engine;' @{} 'nonquery' }
        $r.State | Should -Be 'restored' -Because ($r.Lines -join ' | ')
        $d = Compare-SISqlLpSnapshot -Before $b -After (Get-RSnap)
        $d.Lost.Count | Should -Be 0 -Because ('still lost: ' + ((@($d.Lost) | ForEach-Object { Format-SISqlLpItem $_ }) -join '; '))
        (Get-RRoles 'id-si-engine') | Should -Be @('db_datareader', 'db_datawriter', 'si_engine')
        @(& $script:RSql '' "SELECT state FROM sys.database_permissions WHERE grantee_principal_id = USER_ID(N'id-si-web') AND major_id = OBJECT_ID(N'cfg.T') AND permission_name = N'SELECT'" @{} 'rows' | ForEach-Object { $_.state }) | Should -Be @('W')
        @(& $script:RSql '' "SELECT state FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID(N'si_engine') AND major_id = OBJECT_ID(N'cfg.InstallState')" @{} 'rows' | ForEach-Object { $_.state }) | Should -Be @('D')
    }
    It 'a removal the database refuses inside the transaction leaves NOTHING half-applied (the replacement role missing: THROW before any drop)' {
        & $script:RSql '' 'ALTER ROLE si_engine DROP MEMBER [id-si-engine];' @{} 'nonquery'
        $b = Get-RSnap
        $rm = @([pscustomobject]@{ Component = 'engine'; Member = 'id-si-engine'; Sid = $script:RSids['id-si-engine']; Role = 'db_datareader'; Replacement = 'si_engine' }
                [pscustomobject]@{ Component = 'engine'; Member = 'id-si-engine'; Sid = $script:RSids['id-si-engine']; Role = 'db_datawriter'; Replacement = 'si_engine' })
        { & $script:RSql '' (Get-SISqlLpRemoveSql -Removals $rm) @{} 'nonquery' } | Should -Throw '*not in its replacement role si_engine*'
        (Compare-SISqlLpSnapshot -Before $b -After (Get-RSnap)).Lost.Count | Should -Be 0
        & $script:RSql '' 'ALTER ROLE si_engine ADD MEMBER [id-si-engine];' @{} 'nonquery'
    }
    It 'off puts the broad memberships back, read back' {
        (Invoke-RLp 'plan').State | Should -Be 'planned'
        (Invoke-RLp 'apply').State | Should -Be 'applied'
        (Get-RRoles 'id-si-engine') | Should -Be @('si_engine')
        $o = Invoke-RLp 'off'
        $o.State | Should -Be 'back' -Because ($o.Lines -join ' | ')
        (Get-RRoles 'id-si-engine') | Should -Be @('db_datareader', 'db_datawriter', 'si_engine')
    }
}
