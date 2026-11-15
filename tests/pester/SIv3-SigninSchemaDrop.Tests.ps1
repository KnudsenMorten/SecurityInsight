#Requires -Version 5.1
<#
    THE EARLIER SIGN-IN FRONT'S DATABASE STORE, DROPPED (framework SECURE-WEB-1 "no leftovers"; Invardia never touches an
    install's SQL, so SecurityInsight drops it in its own code):
      * the job's side -- setup\_shared\SI-DbInitJob.ps1: Read-SIDbInitInput (SI_DBINIT_SIGNIN_DROP), Get-SIDbInitPlan (the
        store is no longer made), Get-SIDbInitSigninDropSql (guarded by the exact schema name [signin]),
        Invoke-SIDbInitSigninDrop, New-SIDbInitSigninDropRecordValue, Start-SIDbInitRun (the variable is passed);
      * the updater's side -- container\updater\_shared\SI-UpdaterDatabase.ps1: Test-SIUpdaterWebSwitched,
        Invoke-SIUpdaterSigninSchemaDrop, and Invoke-SIUpdaterDbJob passing the switched fact to its run; the call from the
        built-in sign-in step (container\updater\Start-SIUpdater.ps1, Invoke-SIUpdaterBuiltInAuthStep), next to the key-ring move.
    FULLY OFFLINE: ARM, the database and the job are fakes that record what they were asked.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    . (Join-Path $script:SIRoot 'setup\_shared\SI-BuiltInAuth.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-DbInitJob.ps1')
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterDatabase.ps1')
    # defined in the SAME scope as the dot-sourced updater (a script: one would sit behind the updater's own Write-UpdLog)
    function Write-UpdLog { param($m) $script:Lines.Add([string]$m) }
    $script:Lines = New-Object System.Collections.Generic.List[string]
    $script:WebId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/containerApps/ca-si-management'

    # THE FAKE WORLD (in $script:SW -- not a closure). Opt: Setting ('1' = SI_Web_BuiltInAuth=1), Front (a signin-front
    # container), Platform (authConfig platform enabled), Drop (what the job's drop records: removed | none | kept | refused;
    # $null = a job image that does not know it -- no row), NoJob.
    function script:New-SdWorld([hashtable]$Opt = @{}) {
        $o = @{ Setting = '1'; Front = $false; Platform = $true; Drop = 'removed'; NoJob = $false }
        foreach ($k in $Opt.Keys) { $o[$k] = $Opt[$k] }
        $script:SW = @{ Opt = $o; Calls = New-Object System.Collections.Generic.List[string]; Starts = New-Object System.Collections.Generic.List[object]; Row = $null; Sql = New-Object System.Collections.Generic.List[string] }
        $script:SW.Arm = {
            param($Method, $Path, $Body)
            $W = $script:SW
            $W.Calls.Add("$Method $Path")
            if ($Method -eq 'GET' -and $Path -match '/containerApps/ca-si-management/authConfigs/current\?') {
                return [pscustomobject]@{ properties = [pscustomobject]@{ platform = [pscustomobject]@{ enabled = [bool]$W.Opt.Platform } } }
            }
            if ($Method -eq 'GET' -and $Path -match '/containerApps/ca-si-management\?') {
                $env = @(); if ($W.Opt.Setting) { $env = @([pscustomobject]@{ name = 'SI_Web_BuiltInAuth'; value = $W.Opt.Setting }) }
                $cs = @([pscustomobject]@{ name = 'web'; image = 'acr/si-web:3'; env = $env })
                if ($W.Opt.Front) { $cs = @([pscustomobject]@{ name = 'signin-front'; image = 'acr/signin-front:1'; env = @() }) + $cs }
                return [pscustomobject]@{ name = 'ca-si-management'; properties = [pscustomobject]@{ configuration = [pscustomobject]@{ ingress = [pscustomobject]@{ targetPort = $(if ($W.Opt.Front) { 8443 } else { 8080 }) } }; template = [pscustomobject]@{ containers = $cs } } }
            }
            if ($Method -eq 'GET' -and $Path -match '/jobs/caj-si-dbinit\?') {
                if ($W.Opt.NoJob) { return $null }
                return [pscustomobject]@{ name = 'caj-si-dbinit'; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'dbinit'; image = 'acr/si-orchestrator:3'; env = @([pscustomobject]@{ name = 'SI_DBINIT_SERVER'; value = 'sqlserver.example' }) }) } } }
            }
            if ($Method -eq 'POST' -and $Path -match '/jobs/caj-si-dbinit/start\?') {
                $env = @{}; foreach ($e in @($Body.containers[0].env)) { $env[[string]$e.name] = [string]$e.value }
                $W.Starts.Add($env)
                if ($W.Opt.Drop) { $W.Row = New-SIDbInitSigninDropRecordValue -State $W.Opt.Drop -Run $env['SI_DBINIT_RUN'] -Tables $(if ($W.Opt.Drop -eq 'removed') { 1 } else { 0 }) -Why $(if ($W.Opt.Drop -eq 'refused') { 'The specified schema name "signin" either does not exist or you do not have permission to use it.' } else { '' }) }
                return [pscustomobject]@{ name = 'caj-si-dbinit-sd1' }
            }
            if ($Method -eq 'GET' -and $Path -match '/executions/') { return [pscustomobject]@{ properties = [pscustomobject]@{ status = 'Succeeded' } } }
            $null
        }
        $script:SW.Store = [pscustomobject]@{ Server = 'sqlserver.example'
            Invoke = { param($Sql, $Params, $Mode) $W = $script:SW; $W.Sql.Add([string]$Sql)
                if ($Sql -match "N'DbJobSigninDrop'" -and $W.Row) { return , @(@{ Value = $W.Row }) }
                , @() } }
        $script:SW
    }
    function script:Invoke-Sd([hashtable]$Opt = @{}) {
        $w = New-SdWorld $Opt
        Invoke-SIUpdaterSigninSchemaDrop -SIRoot $script:SIRoot -Store $w.Store -Arm $w.Arm -SubscriptionId 's' -ResourceGroup 'rg' -WebAppId $script:WebId -Sleep { param($s) }
    }
}

Describe 'the job''s side: the store is no longer made, and dropped -- by the exact schema name only' {
    It 'SI_DBINIT_SIGNIN_DROP=1 is read; anything else is off' {
        $base = @{ SI_DBINIT_SERVER = 'sqlserver.example'; SI_DBINIT_PRINCIPALS = '[{"component":"engine","name":"id-si-engine","clientId":"11111111-0000-0000-0000-000000000001"}]' }
        (Read-SIDbInitInput -Env ($base + @{ SI_DBINIT_SIGNIN_DROP = '1' })).SigninDrop | Should -BeTrue
        (Read-SIDbInitInput -Env ($base + @{ SI_DBINIT_SIGNIN_DROP = '' })).SigninDrop | Should -BeFalse
        (Read-SIDbInitInput -Env ($base + @{ SI_DBINIT_SIGNIN_DROP = 'maybe' })).SigninDrop | Should -BeFalse
    }
    It 'switched: the plan makes NO part of the sign-in front''s store (the job would make it again otherwise); not switched: as before' {
        function script:Get-SISigninStoreSql { param($Action) "-- $Action" }
        try {
            $p = @(
                [pscustomobject]@{ Component = 'engine'; Name = 'id-si-engine'; ClientId = '11111111-0000-0000-0000-000000000001' }
                [pscustomobject]@{ Component = 'web'; Name = 'id-si-web'; ClientId = '11111111-0000-0000-0000-000000000003' })
            $in = [pscustomobject]@{ Ok = $true; Database = 'sqldb-si-pro'; LedgerDatabase = ''; Principals = $p; Support = $null; SignedGrants = $false; EngineRoleOnly = $false; Steps = 'all'; SigninDrop = $false }
            @((Get-SIDbInitPlan -DbInput $in).Batches | Where-Object { $_.Step -like 'signin-*' }).Count | Should -Be 3
            $in.SigninDrop = $true
            @((Get-SIDbInitPlan -DbInput $in).Batches | Where-Object { $_.Step -like 'signin-*' }).Count | Should -Be 0
        } finally { Remove-Item -Path Function:\Get-SISigninStoreSql -ErrorAction SilentlyContinue }
    }
    It 'the statement drops ONLY the schema [signin] and its own tables -- no parameter, no other schema, no other object' {
        $q = Get-SIDbInitSigninDropSql
        $drops = [regex]::Matches($q, '(?i)\bDROP\s+(\w+)\s+([^\s;'']+)')
        $drops.Count | Should -BeGreaterThan 0
        foreach ($d in $drops) {
            $kind = $d.Groups[1].Value.ToUpperInvariant(); $what = $d.Groups[2].Value
            switch ($kind) {
                'TABLE'      { $what | Should -Be '[signin].' -Because 'a table is dropped only in the schema [signin]' }
                'SCHEMA'     { $what | Should -Be '[signin]' }
                'CONSTRAINT' { $q | Should -Match "ALTER TABLE \[signin\]\.' \+ QUOTENAME\(OBJECT_NAME\(parent_object_id\)\) \+ N' DROP CONSTRAINT" -Because 'only a key of a table in [signin]' }
                default      { throw "an unexpected DROP $kind" }
            }
        }
        $vars = @([regex]::Matches($q, '@[A-Za-z]+') | ForEach-Object { $_.Value } | Sort-Object -Unique)
        foreach ($v in $vars) { @('@sch', '@existed', '@dropped', '@s', '@why') | Should -Contain $v -Because 'only its own variables -- no caller-given value reaches it' }
        $q | Should -Match "IF @sch IS NOT NULL" -Because 'idempotent: nothing to do when the schema is not there'
        $q | Should -Match 'fk\.schema_id <> @sch' -Because 'a table OUTSIDE the schema that refers to it stops it'
        $q | Should -Not -Match '(?i)DROP\s+(USER|ROLE|DATABASE|PROCEDURE|VIEW|FUNCTION|LOGIN)'
    }
    It 'the job judges the read-back: <Want>' -ForEach @(
        @{ Row = @{ Existed = 1; TablesDropped = 2; SchemaLeft = 0; TablesLeft = 0; Why = '' }; Want = 'removed'; Line = 'the earlier sign-in''s database tables are removed' }
        @{ Row = @{ Existed = 0; TablesDropped = 0; SchemaLeft = 0; TablesLeft = 0; Why = '' }; Want = 'none';    Line = 'none left' }
        @{ Row = @{ Existed = 1; TablesDropped = 0; SchemaLeft = 1; TablesLeft = 1; Why = 'a table outside the schema signin refers to one of its tables -- nothing was dropped' }; Want = 'kept'; Line = 'support step' }
    ) {
        $row = $Row
        $r = Invoke-SIDbInitSigninDrop -Sql { param($db, $q, $p, $m) , @($row) }.GetNewClosure() -Database 'sqldb-si-pro'
        $r.State | Should -Be $Want
        $r.Line | Should -Match ([regex]::Escape($Line))
    }
    It 'a refusal is "refused" with a support step in plain words -- never a throw, never a failure of the run' {
        $r = Invoke-SIDbInitSigninDrop -Sql { param($db, $q, $p, $m) throw 'Cannot drop the schema ''signin'', because it does not exist or you do not have permission.' } -Database 'sqldb-si-pro'
        $r.State | Should -Be 'refused'
        $r.Line | Should -Match 'could not be removed .*the update goes on; support step: the support partner removes them through the Support app'
        $r.Line | Should -Not -Match '#\d|SECURE-WEB|G5' -Because 'plain words, no internal numbers'
        $v = New-SIDbInitSigninDropRecordValue -State refused -Run 'r1' -Why ('x' * 600)
        $v.Length | Should -BeLessOrEqual 400
        (ConvertFrom-SIDbInitRecordValue -Value $v).state | Should -Be 'refused'
    }
    It 'the run passes the switched fact to the job (Start-SIDbInitRun keeps SI_DBINIT_SIGNIN_DROP)' {
        $w = New-SdWorld
        $job = & $w.Arm 'GET' '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-dbinit?api-version=x' $null
        $null = Start-SIDbInitRun -Arm $w.Arm -JobId '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-dbinit' -Job $job -By updater -Sleep { param($s) } -Extra @{ SI_DBINIT_SIGNIN_DROP = '1'; SI_DBINIT_SOMETHING_ELSE = 'x' }
        $w.Starts[0]['SI_DBINIT_SIGNIN_DROP'] | Should -Be '1'
        $w.Starts[0].ContainsKey('SI_DBINIT_SOMETHING_ELSE') | Should -BeFalse
    }
    It 'the job runs the drop only when named, never in a grants-only run, and records it in its own row' {
        $t = (Get-Command Invoke-SIDbInit).ScriptBlock.ToString()
        $t | Should -Match "if \(\[bool\]\(Get-SIDbInitProp \`$in @\('SigninDrop'\)\)\)"
        $t | Should -Match "-eq 'grants'\) \{ \[pscustomobject\]@\{ State = 'skipped'"
        $t | Should -Match 'Get-SIDbInitRecordSql -Name \(Get-SIDbInitNames\)\.SigninDropRecord'
        (Get-SIDbInitNames).SigninDropRecord | Should -Be 'DbJobSigninDrop'
    }
}

Describe 'the updater''s side: only where the web app reads back switched' {
    BeforeEach { $script:Lines.Clear(); $global:SI_UpdaterSigninDrop = $null }
    AfterAll { $global:SI_UpdaterSigninDrop = $null }
    It 'switched and dropped: the job is started with SI_DBINIT_SIGNIN_DROP=1 and the one plain line says "removed"' {
        $r = Invoke-Sd
        $r.State | Should -Be 'removed'
        $r.Line | Should -Be 'the earlier sign-in''s database tables are removed'
        $r.Support | Should -BeNullOrEmpty
        $script:SW.Starts.Count | Should -Be 1
        $script:SW.Starts[0]['SI_DBINIT_SIGNIN_DROP'] | Should -Be '1'
        $script:SW.Starts[0]['SI_DBINIT_BY'] | Should -Be 'updater'
        @($script:SW.Sql | Where-Object { $_ -match '(?i)\bDROP\b' }) | Should -BeNullOrEmpty -Because 'the updater sends no DROP itself: the job does it'
    }
    It 'not switched (<Why>): NOTHING is touched -- no job started, no statement sent' -ForEach @(
        @{ Why = 'SI_Web_BuiltInAuth is not 1';            Opt = @{ Setting = '' } }
        @{ Why = 'the signin-front container is there';    Opt = @{ Front = $true } }
        @{ Why = 'the authConfig platform is not enabled'; Opt = @{ Platform = $false } }
    ) {
        $r = Invoke-Sd $Opt
        $r.State | Should -Be 'not-switched'
        $r.Line | Should -Match 'tables are kept: the web app does not read back on Microsoft''s built-in sign-in'
        $script:SW.Starts.Count | Should -Be 0
        @($script:SW.Calls | Where-Object { $_ -notmatch '^GET ' }) | Should -BeNullOrEmpty
        $script:SW.Sql.Count | Should -Be 0
    }
    It 'already gone: "none left", nothing else to do' {
        $r = Invoke-Sd @{ Drop = 'none' }
        $r.State | Should -Be 'none'; $r.Line | Should -Be 'the earlier sign-in''s database tables: none left'; $r.Support | Should -BeNullOrEmpty
    }
    It 'a refusal: a warning line and a support step, never a failure' {
        $r = Invoke-Sd @{ Drop = 'refused' }
        $r.State | Should -Be 'refused'
        $r.Line | Should -Match 'could not be removed'
        $r.Support | Should -Match 'the support partner removes the earlier sign-in''s database tables .*through the Support app'
    }
    It 'this update''s database setup run already did it: its result is said and no second run is started' {
        $global:SI_UpdaterSigninDrop = [pscustomobject]@{ Run = 'pre1'; State = 'removed' }
        $r = Invoke-Sd
        $r.State | Should -Be 'removed'; $script:SW.Starts.Count | Should -Be 0
    }
    It 'a job image that does not know the drop yet: said, the next update does it; no job at all: said too' {
        (Invoke-Sd @{ Drop = $null }).State | Should -Be 'not-run'
        (Invoke-Sd @{ NoJob = $true }).State | Should -Be 'not-run'
    }
    It 'Invoke-SIUpdaterDbJob passes the switched fact to its run before the database step (so the job never makes the store again)' {
        $t = (Get-Command Invoke-SIUpdaterDbJob).ScriptBlock.ToString()
        $t | Should -Match "Test-SIUpdaterWebSwitched -Arm \`$Arm -WebAppId"
        $t | Should -Match "if \(\`$webSw\.Switched -eq \`$true\) \{ \`$extra\['SI_DBINIT_SIGNIN_DROP'\] = '1' \}"
        $t.IndexOf("SI_DBINIT_SIGNIN_DROP") | Should -BeLessThan $t.IndexOf('Start-SIDbInitRun -Arm')
    }
}

Describe 'the built-in sign-in step calls it ONLY after a switch that read back, next to the key-ring move' {
    BeforeEach { $script:Lines.Clear(); $global:SI_UpdaterFailures = $null }
    AfterAll { $global:SI_UpdaterFailures = $null }
    It 'off, plan, a failed or rolled-back apply: never called; apply applied / in-place: called with the web app''s id; a support step is recorded' {
        $script:sdCalls = New-Object System.Collections.Generic.List[object]
        $script:sdAnswer = [pscustomobject]@{ State = 'refused'; Line = 'the earlier sign-in''s database tables could not be removed (x)'; Support = 'the support partner removes the earlier sign-in''s database tables (the schema signin) through the Support app' }
        $sd = { param($a) $script:sdCalls.Add($a); $script:sdAnswer }
        $e = @{ SI_UPDATER_WEB_APP = 'ca-si-management' }
        foreach ($case in @(@{ Mode = 'plan'; State = 'in-place'; Ok = $true }, @{ Mode = 'apply'; State = 'failed'; Ok = $false }, @{ Mode = 'apply'; State = 'rolled-back'; Ok = $false })) {
            $st = $case.State; $ok = $case.Ok
            $conv = { param($a) [pscustomobject]@{ Ok = $ok; State = $st; Lines = @() } }.GetNewClosure()
            $null = Invoke-SIUpdaterBuiltInAuthStep -Env ($e + @{ SI_Updater_BuiltInAuth = $case.Mode }) -SubscriptionId 's' -ResourceGroup 'rg' -Converge $conv -Arm { } -Graph { } -SigninDrop $sd -Standard { param($a) $null } -SIRoot $script:SIRoot
        }
        $script:sdCalls.Count | Should -Be 0
        foreach ($st in 'applied', 'in-place') {
            $conv = { param($a) [pscustomobject]@{ Ok = $true; State = $st; Lines = @() } }.GetNewClosure()
            $r = Invoke-SIUpdaterBuiltInAuthStep -Env ($e + @{ SI_Updater_BuiltInAuth = 'apply' }) -SubscriptionId 's' -ResourceGroup 'rg' -Converge $conv -Arm { } -Graph { } -SigninDrop $sd -Standard { param($a) $null } -SIRoot $script:SIRoot
            $r.SigninDrop.State | Should -Be 'refused'
        }
        $script:sdCalls.Count | Should -Be 2
        $script:sdCalls[0].WebAppId | Should -BeLike '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/containerApps/*'
        $script:sdCalls[0].SIRoot | Should -Be $script:SIRoot
        ($script:Lines -join "`n") | Should -Match 'WARNING: the earlier sign-in''s database tables could not be removed'
        @($global:SI_UpdaterFailures | Where-Object { $_.Kind -eq 'customer-action' -and $_.Text -match '^Support-app step: the support partner removes the earlier sign-in' }).Count | Should -Be 1 -Because 'the same step twice is one entry'
        $src = (Get-Command Invoke-SIUpdaterBuiltInAuthStep).ScriptBlock.ToString()
        $src.IndexOf('KeyRingMove $args2') | Should -BeLessThan $src.IndexOf('& $SigninDrop')
    }
}
