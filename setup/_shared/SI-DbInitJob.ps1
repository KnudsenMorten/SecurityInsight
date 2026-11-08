#Requires -Version 5.1
<#
    SecurityInsight -- THE DATABASE SETUP JOB caj-si-dbinit (framework SEC-08 "no person needs database admin rights at an
    install"; Invardia DESIGN ch 12 binding spec points 1-10, agreed by SI, PIM and EPS 2026-11-03; SI REQUIREMENTS #1072).

    WHAT IT IS
      * ONE Container Apps job per install, caj-si-dbinit, MANUAL trigger, running the install's own engine image (the
        si-orchestrator image every engine job runs -- no new image to sign) with its own entry point
        container/Start-SIDbInit.ps1.
      * It runs as its OWN user-assigned identity id-si-dbinit, a STANDING member of the install's SQL admin group (the group
        that is the SQL server's Entra administrator: grp-si-sql-admins, or the install's own group). The server's
        administrator is never switched for it.
      * It does the database work that needed a person in that group: every product identity's contained user by its client
        id (engine, web, MCP, updater, asset tagging) with its roles and grants, the updater's rights, the signed grant
        procedure, the web app's sign-in front schema, and -- only when the caller names the Invardia Support app -- that
        app's own database user and the support grant procedures. Every statement is the SQL the person-run script already
        sends (Get-SIEngineDatabaseAccessSql, Get-SIUpdaterDatabaseAccessSql, Get-SIGrantProcedureAdminSql,
        Get-SIManagementUserSql, Get-SITaggingDatabaseAccessSql, Get-SISigninStoreSql, Get-SISupportAppDatabaseAccessSql,
        Get-SISupportGrantAdminSteps) -- never a second copy of it.
      * Every principal and grant is READ BACK; the job writes ONE result row (cfg.InstallState 'DbJob', Value <= 400
        characters) and exits non-zero on any failure.

    WHO STARTS IT
      * the guided install (step db-job): makes the identity, adds it to the admin group and READS THE MEMBERSHIP BACK from
        the identity's side (memberOf -- a group's /members list hides service principals from many callers, EPS 2.0.59),
        only THEN makes and starts the job (a managed identity's token is cached for hours: a run before the membership exists
        keeps a token without the group), waits, and reads the execution's result;
      * the updater, on every update, BEFORE the database step: keeps the identity and the job present; framework §4.5
        SQL-ADMIN-GROUP G2-G5: it CONVERGES and RENEWS the identity's membership (Sync-SIDbInitMembership, the same path as
        setup) with its own G5 Graph permissions (three PIM-for-Groups + GroupMember.Read.All + Application.Read.All), which setup grants (Grant-SIDbInitUpdaterGraphRoles) and
        the updater only checks (Test-SIDbInitUpdaterGraphRoles); it starts the job once the membership reads back or a run
        of it proved it (a 'DbJob' row the job itself wrote) -- until then the update keeps today's path and the heartbeat's
        setup step db-job asks for the one membership; a failed run holds the update (nothing is rolled, the old version
        keeps running), and so does a proven membership that is gone and cannot be made again;
      * Invardia support for a repair (setup\Start-SIDbInitJob.ps1).

    Seams (callers hand them in, tests pass fakes):
      -Sql   { param([string]$Database, [string]$Query, $Params, [string]$Mode) }  Mode nonquery | rows; rows = hashtables
      -Arm   { param([string]$Method, [string]$Path, $Body) }  parsed answer; $null = not found on a GET; throws otherwise
      -Graph { param([string]$Method, [string]$Uri, $Body) }   parsed answer; throws on an error
    The SQL builders above must be loaded by the caller (Import-SIDbInitSqlSources does it from a SecurityInsight root).
    PS 5.1 safe; no module.
#>

function Get-SIDbInitNames {
    <# PURE. The fixed names (a function, not a $script: value: a caller that dot-sources this file inside a function sees it). #>
    [ordered]@{
        Job            = 'caj-si-dbinit'
        Identity       = 'id-si-dbinit'
        Record         = 'DbJob'
        Container      = 'dbinit'
        Entry          = '/app/container/Start-SIDbInit.ps1'
        TagName        = 'si-component'
        TagValue       = 'dbinit'
        ProDatabase    = 'sqldb-si-pro'
        LedgerDatabase = 'sqldb-si-identity'
        AppApi         = '2025-07-01'
        MiApi          = '2023-01-31'
        RecordMax      = 400
        # framework §4.5 SQL-ADMIN-GROUP G2-G4: the membership's own row (the updater's last check of it) and the renewal window
        MembershipRecord = 'DbJobMembership'
        RenewWindowDays  = 30
        SqlApi           = '2021-11-01'
        # #1146: a statement chosen as a DEADLOCK victim (SQL 1205) is sent again after these waits (seconds), said each time
        DeadlockWaits    = @(2, 5, 10)
        # #1146: an updater execution counts as running for at most this long when its job names no run limit (seconds)
        UpdaterLimitSeconds = 21600
        UpdaterLockStaleMinutes = 15
    }
}

function Get-SIDbInitCallerRecordName {
    <# PURE. #1146: the result row of ONE caller (installer | updater | support | job): 'DbJobUpdater' ... -- written by the
       job next to the shared row 'DbJob', so a run started beside another (a support setup beside an update) can never
       overwrite the result the other caller waits for. #>
    param([AllowEmptyString()][string]$By = '')
    $b = "$By".Trim().ToLowerInvariant()
    if ($b -notin 'installer', 'updater', 'support', 'job') { $b = 'job' }
    (Get-SIDbInitNames).Record + $b.Substring(0, 1).ToUpperInvariant() + $b.Substring(1)
}

function Test-SIDbInitDeadlock {
    <# PURE. #1146: is this SQL error a DEADLOCK victim (SQL 1205) -- a statement SQL rolled back so another could finish, which
       may be sent again? (live 2026-11-07, install-a: "Transaction ... was deadlocked ... and has been chosen as the deadlock victim".) #>
    param([AllowNull()][AllowEmptyString()][string]$Message)
    [bool]("$Message" -match '(?i)chosen as the deadlock victim|was deadlocked on|\bdeadlock victim\b|\b1205\b')
}

function Get-SIDbInitComponents { <# PURE. The product identities the job makes users for, in order. #> @('engine', 'updater', 'web', 'mcp', 'tagging') }

function Import-SIDbInitSqlSources {
    <# Dot-sources the SQL builders the job reuses, from -SIRoot, into the CALLER's scope (call it dot-sourced:
       . Import-SIDbInitSqlSources -SIRoot $r). A file a package does not carry is left out; its steps are then not planned. #>
    param([Parameter(Mandatory)][string]$SIRoot)
    foreach ($rel in @('engine/pro-settings/SI-EngineGrants.ps1', 'engine/pro-settings/SI-ProSchema.ps1', 'engine/pro-settings/SI-GrantProcedure.ps1',
                       'engine/pro-settings/SI-SupportGrantSql.ps1', 'pro-management/deploy/SI-ManagementGrants.ps1', 'pro-management/deploy/SI-SigninFrontStore.ps1',
                       'setup/_shared/SI-SupportAppDatabase.ps1', 'setup/_shared/SI-SupportGrantUpdate.ps1', 'setup/_shared/SI-IdentityMoveSql.ps1')) {
        $p = [IO.Path]::Combine($SIRoot, $rel)
        if (Test-Path -LiteralPath $p) { . $p }
    }
}

function Get-SIDbInitSid {
    <# PURE. An Entra principal's database SID from its client id: 0x + the 16 bytes in [guid]::ToByteArray() order. #>
    param([Parameter(Mandatory)][string]$ClientId)
    '0x' + ((([guid]$ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-SIDbInitProp {
    <# PURE. A nested property (PSCustomObject, hashtable or DataRow); $null when any step is missing. #>
    param($Object, [string[]]$Names)
    $o = $Object
    foreach ($n in $Names) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Data.DataRow]) { if ($o.Table.Columns.Contains($n)) { $o = $o[$n]; if ($o -is [System.DBNull]) { $o = $null } } else { return $null }; continue }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o = $o[$n] } else { return $null }; continue }
        $p = $o.PSObject.Properties[$n]
        if (-not $p) { return $null }
        $o = $p.Value
    }
    $o
}

# =====================================================================================================================
#  THE JOB'S SIDE (container/Start-SIDbInit.ps1)
# =====================================================================================================================

function Read-SIDbInitInput {
    <#
        PURE. The job's inputs (its environment; -Env first, then the process), checked. Returns @{ Ok; Reason; Server;
        Database; LedgerDatabase; MiClientId; Principals (@{ Component; Name; ClientId }); Support (@{ ClientId; UserName } or
        $null); SignedGrants; EngineRoleOnly; Run; By }. Refused: a principal list that is not JSON, an unknown component, a
        name that is not safe, a client id that is not a GUID, two entries for one component, no engine identity.
          SI_DBINIT_SERVER / SI_DBINIT_DATABASE / SI_DBINIT_LEDGER_DATABASE   the server and the databases
          SI_DBINIT_MI_CLIENT_ID      the job's own identity (the token is asked for THIS identity)
          SI_DBINIT_PRINCIPALS        JSON [{ "component": "engine", "name": "id-si-engine", "clientId": "<guid>" }, ...]
          SI_DBINIT_SIGNED_GRANTS     1 = the signed grant procedure model (SI_Setup_SignedGrantProcedure)
          SI_DBINIT_ENGINE_ROLE_ONLY  1 = the engine gets its role si_engine only (SI_Setup_EngineLeastPrivilege)
          per execution: SI_DBINIT_RUN (the caller's run id), SI_DBINIT_BY (installer | updater | support),
                         SI_DBINIT_SUPPORT ('<client id>|<user name>': the Invardia Support app -- installer / support only)
                         SI_DBINIT_SUPPORT_STANDING_OFF ('<client id>': #1151 SEC-01 -- the updater names the recorded Support
                         app; the job takes its STANDING db_owner off in each product database where the just-in-time path
                         reads back in the same batch, Get-SISupportStandingOffSql; never the group, never a user)
                         SI_DBINIT_STEPS (all | grants: users, role memberships and grants only -- no procedure, schema or
                         database setting is created or changed, so it may run beside a pipeline run; anything else = all)
    #>
    param([hashtable]$Env = @{})
    $e = { param($k) if ($Env.ContainsKey($k)) { [string]$Env[$k] } else { [string][Environment]::GetEnvironmentVariable($k) } }
    $no = { param($r) [pscustomobject]@{ Ok = $false; Reason = $r } }
    $names = Get-SIDbInitNames
    $server = (& $e 'SI_DBINIT_SERVER').Trim()
    if ($server -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{1,253}$') { return (& $no 'SI_DBINIT_SERVER is not a server name') }
    $db = (& $e 'SI_DBINIT_DATABASE').Trim(); if (-not $db) { $db = $names.ProDatabase }
    $ledger = (& $e 'SI_DBINIT_LEDGER_DATABASE').Trim()
    foreach ($d in @($db, $ledger) | Where-Object { $_ }) { if ($d -notmatch '^[A-Za-z0-9_.-]{1,128}$') { return (& $no ("the database name '{0}' is not safe" -f $d)) } }
    $mi = (& $e 'SI_DBINIT_MI_CLIENT_ID').Trim()
    $g = [guid]::Empty
    if ($mi -and -not [guid]::TryParse($mi, [ref]$g)) { return (& $no 'SI_DBINIT_MI_CLIENT_ID is not a client id') }
    $json = (& $e 'SI_DBINIT_PRINCIPALS').Trim()
    if (-not $json) { return (& $no 'SI_DBINIT_PRINCIPALS is not set') }
    $list = $null
    try { $list = @($json | ConvertFrom-Json -ErrorAction Stop) } catch { return (& $no 'SI_DBINIT_PRINCIPALS is not JSON') }
    $known = Get-SIDbInitComponents
    $p = New-Object System.Collections.Generic.List[object]
    foreach ($x in $list) {
        if ($null -eq $x) { continue }
        $c = ([string](Get-SIDbInitProp $x @('component'))).Trim().ToLowerInvariant()
        $n = ([string](Get-SIDbInitProp $x @('name'))).Trim()
        $cid = ([string](Get-SIDbInitProp $x @('clientId'))).Trim()
        if ($known -notcontains $c) { return (& $no ("unknown component '{0}' (known: {1})" -f $c, ($known -join ', '))) }
        if ($n -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { return (& $no ("the {0} identity's name '{1}' is not safe" -f $c, $n)) }
        $g = [guid]::Empty
        if (-not [guid]::TryParse($cid, [ref]$g) -or $g -eq [guid]::Empty) { return (& $no ("the client id of the {0} identity is not a GUID" -f $c)) }
        if (@($p | Where-Object { $_.Component -eq $c }).Count) { return (& $no ("the {0} identity is listed twice" -f $c)) }
        $p.Add([pscustomobject]@{ Component = $c; Name = $n; ClientId = $g.ToString() })
    }
    if (-not @($p | Where-Object { $_.Component -eq 'engine' }).Count) { return (& $no 'the principal list names no engine identity') }
    $sup = $null
    $s = (& $e 'SI_DBINIT_SUPPORT').Trim()
    if ($s) {
        $parts = $s.Split('|')
        $g = [guid]::Empty
        if ($parts.Count -ne 2 -or -not [guid]::TryParse($parts[0], [ref]$g) -or $parts[1] -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$') { return (& $no 'SI_DBINIT_SUPPORT is not "<client id>|<user name>"') }
        $sup = [pscustomobject]@{ ClientId = $g.ToString(); UserName = $parts[1] }
    }
    # #1151 SEC-01: the Support app whose STANDING db_owner the job takes off (where the just-in-time path reads back)
    $off = (& $e 'SI_DBINIT_SUPPORT_STANDING_OFF').Trim()
    if ($off) { $g = [guid]::Empty; if (-not [guid]::TryParse($off, [ref]$g) -or $g -eq [guid]::Empty) { return (& $no 'SI_DBINIT_SUPPORT_STANDING_OFF is not a client id') }; $off = $g.ToString() }
    $run = (& $e 'SI_DBINIT_RUN').Trim(); if ($run -notmatch '^[A-Za-z0-9-]{1,40}$') { $run = '' }
    $by = (& $e 'SI_DBINIT_BY').Trim().ToLowerInvariant(); if ($by -notin 'installer', 'updater', 'support') { $by = 'job' }
    $on = { param($k) (& $e $k).Trim() -match '^(?i)(1|true|yes|on)$' }
    $steps = if ((& $e 'SI_DBINIT_STEPS').Trim() -ieq 'grants') { 'grants' } else { 'all' }
    # THE IDENTITY MOVE (framework §5.5 names; setup\_shared\SI-IdentityMove.ps1), per execution only:
    #   SI_DBINIT_MOVES  [{ "component": "web", "from": "<old client id>", "to": "<new client id>", "toName": "id-si-web" }]
    #   SI_DBINIT_DROPS  [{ "component": "web", "clientId": "<old>", "keepClientId": "<new>", "keepName": "id-si-web" }]
    $mv = Read-SIDbInitMoveList -Json (& $e 'SI_DBINIT_MOVES') -Kind moves -MiClientId $mi -Support $sup
    if (-not $mv.Ok) { return (& $no $mv.Reason) }
    $dr = Read-SIDbInitMoveList -Json (& $e 'SI_DBINIT_DROPS') -Kind drops -MiClientId $mi -Support $sup -InUse @($p | ForEach-Object { $_.ClientId })
    if (-not $dr.Ok) { return (& $no $dr.Reason) }
    [pscustomobject]@{ Ok = $true; Reason = ''; Server = $server; Database = $db; LedgerDatabase = $ledger; MiClientId = $mi; Principals = $p.ToArray()
                       Support = $sup; SignedGrants = (& $on 'SI_DBINIT_SIGNED_GRANTS'); EngineRoleOnly = (& $on 'SI_DBINIT_ENGINE_ROLE_ONLY'); Run = $run; By = $by; Steps = $steps
                       Moves = @($mv.Items); Drops = @($dr.Items); StandingOff = $off }
}

function Read-SIDbInitMoveList {
    <#
        PURE. One identity-move list of the job's input (SI_DBINIT_MOVES / SI_DBINIT_DROPS), checked. '' = none. Refused: not
        JSON, an unknown component, a client id that is not a GUID, an unsafe name, a move onto itself -- and a DROP of the
        job's own identity, of the Invardia Support app, of an identity an app or job of the install still signs in as
        (-InUse: the principal list), or one whose kept identity is the same. Returns @{ Ok; Reason; Items }.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Json, [Parameter(Mandatory)][ValidateSet('moves', 'drops')][string]$Kind, [string]$MiClientId = '', $Support = $null, [string[]]$InUse = @())
    $ok = { param($items) [pscustomobject]@{ Ok = $true; Reason = ''; Items = @($items) } }
    $no = { param($r) [pscustomobject]@{ Ok = $false; Reason = $r; Items = @() } }
    $var = if ($Kind -eq 'moves') { 'SI_DBINIT_MOVES' } else { 'SI_DBINIT_DROPS' }
    if (-not "$Json".Trim()) { return (& $ok @()) }
    $list = $null
    try { $list = @("$Json" | ConvertFrom-Json -ErrorAction Stop) } catch { return (& $no ('{0} is not JSON' -f $var)) }
    $guid = { param($v) $g = [guid]::Empty; if ([guid]::TryParse("$v".Trim(), [ref]$g) -and $g -ne [guid]::Empty) { $g.ToString() } else { '' } }
    $known = Get-SIDbInitComponents
    $used = @($InUse | Where-Object { $_ } | ForEach-Object { "$_".ToLowerInvariant() })
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($x in $list) {
        if ($null -eq $x) { continue }
        $c = ([string](Get-SIDbInitProp $x @('component'))).Trim().ToLowerInvariant()
        if ($known -notcontains $c) { return (& $no ("{0}: unknown component '{1}'" -f $var, $c)) }
        if ($Kind -eq 'moves') {
            $f = & $guid (Get-SIDbInitProp $x @('from')); $t = & $guid (Get-SIDbInitProp $x @('to')); $n = ([string](Get-SIDbInitProp $x @('toName'))).Trim()
            if (-not $f -or -not $t) { return (& $no ('{0}: the {1} move needs the old and the new client id' -f $var, $c)) }
            if ($f -eq $t) { return (& $no ('{0}: the {1} move names the same identity twice' -f $var, $c)) }
            if ($n -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$') { return (& $no ("{0}: the {1} identity's name '{2}' is not safe" -f $var, $c, $n)) }
            $out.Add([pscustomobject]@{ Component = $c; From = $f; To = $t; ToName = $n })
        } else {
            $d = & $guid (Get-SIDbInitProp $x @('clientId')); $k = & $guid (Get-SIDbInitProp $x @('keepClientId')); $n = ([string](Get-SIDbInitProp $x @('keepName'))).Trim()
            if (-not $d -or -not $k) { return (& $no ('{0}: the {1} drop needs the old and the kept client id' -f $var, $c)) }
            if ($d -eq $k) { return (& $no ('{0}: the {1} drop would drop the identity it keeps' -f $var, $c)) }
            if ($n -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$') { return (& $no ("{0}: the kept {1} identity's name '{2}' is not safe" -f $var, $c, $n)) }
            if ($MiClientId -and $d -ieq $MiClientId) { return (& $no ('{0}: the job never drops its own identity' -f $var)) }
            if ($Support -and $d -ieq [string]$Support.ClientId) { return (& $no ('{0}: the job never drops the Invardia Support app' -f $var)) }
            if ($used -contains $d.ToLowerInvariant()) { return (& $no ('{0}: the {1} identity {2} is still what an app or job of the install signs in as -- it is not dropped' -f $var, $c, $d)) }
            $out.Add([pscustomobject]@{ Component = $c; ClientId = $d; KeepClientId = $k; KeepName = $n })
        }
    }
    & $ok $out.ToArray()
}

function Invoke-SIDbInitMoves {
    <#
        THE IDENTITY MOVE's database side, as the SQL admin (setup\_shared\SI-IdentityMoveSql.ps1 -- the move's own builders):
          moves  per database (-Databases: the Pro database, the identity ledger, every other product database): the old
                 user's roles and explicit permissions copied to the new identity's user (made from its client id), then
                 READ AGAIN -- the copy must be empty. A right the builders cannot copy is a problem, never skipped.
          drops  per database: the old user dropped ONLY where a read made just before shows the kept identity's user
                 holding every role and permission of it (Test-SIIdentityMoveSqlCovered); then read again -- gone.
        Returns @{ Problems; Lines; States (component -> ok | none | dropped | failed) }. -Sql: the job's seam.
    #>
    param([Parameter(Mandatory)]$DbInput, [Parameter(Mandatory)][scriptblock]$Sql, [string[]]$Databases = @())
    $problems = New-Object System.Collections.Generic.List[string]; $lines = New-Object System.Collections.Generic.List[string]; $states = @{}
    $rowsOf = { param($d, $o, $n) @(& $Sql $d (Get-SIIdentityMoveSqlReadSql -OldClientId $o -NewClientId $n) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
    $mark = { param($c, $v) if ($states[$c] -ne 'failed') { if ($v -eq 'failed' -or -not $states.ContainsKey($c) -or $states[$c] -eq 'none') { $states[$c] = $v } } }
    if (-not (Get-Command -Name Get-SIIdentityMoveSqlCopy -ErrorAction SilentlyContinue)) {
        foreach ($m in @($DbInput.Moves) + @($DbInput.Drops)) { if ($m) { $states[$m.Component] = 'failed' } }
        if (@($DbInput.Moves).Count -or @($DbInput.Drops).Count) { $problems.Add('this package carries no identity move SQL (setup\_shared\SI-IdentityMoveSql.ps1)') }
        return [pscustomobject]@{ Problems = $problems.ToArray(); Lines = $lines.ToArray(); States = $states }
    }
    foreach ($m in @($DbInput.Moves)) {
        foreach ($d in @($Databases | Where-Object { $_ })) {
            try {
                $c = Get-SIIdentityMoveSqlCopy -Rows (& $rowsOf $d $m.From $m.To) -NewName $m.ToName -NewClientId $m.To
                if (-not $c.OldUser) { & $mark $m.Component 'none'; $lines.Add(('{0}: the old {1} identity has no user here -- nothing to copy' -f $d, $m.Component)); continue }
                if (@($c.Unsupported).Count) { & $mark $m.Component 'failed'; $problems.Add(('{0}: the {1} identity''s user holds a right the move cannot copy ({2}) -- nothing copied' -f $d, $m.Component, (@($c.Unsupported) -join '; '))); continue }
                if ($c.Sql) { $null = & $Sql $d $c.Sql @{} 'nonquery'; $lines.Add(('done: {0}: {1} -> {2}: {3}' -f $d, $c.OldUser, $m.ToName, (@($c.Items) -join '; '))) }
                $again = Get-SIIdentityMoveSqlCopy -Rows (& $rowsOf $d $m.From $m.To) -NewName $m.ToName -NewClientId $m.To
                if ($again.Sql -or @($again.Unsupported).Count -or -not $again.NewUser) { & $mark $m.Component 'failed'; $problems.Add(('{0}: the {1} identity {2} does not read back holding every right of {3}' -f $d, $m.Component, $m.ToName, $c.OldUser)); continue }
                & $mark $m.Component 'ok'
                $lines.Add(('read back: {0}: {1} holds every role and permission of {2}' -f $d, $again.NewUser, $c.OldUser))
            } catch { & $mark $m.Component 'failed'; $problems.Add(('{0}: the {1} move: {2}' -f $d, $m.Component, $_.Exception.Message)) }
        }
    }
    foreach ($x in @($DbInput.Drops)) {
        foreach ($d in @($Databases | Where-Object { $_ })) {
            try {
                $cov = Test-SIIdentityMoveSqlCovered -Rows (& $rowsOf $d $x.ClientId $x.KeepClientId) -KeepName $x.KeepName -KeepClientId $x.KeepClientId
                if (-not $cov.OldUser) { & $mark $x.Component 'none'; continue }
                if (-not $cov.Drop) { & $mark $x.Component 'failed'; $problems.Add(('{0}: KEPT: {1}' -f $d, $cov.Why)); continue }
                $null = & $Sql $d (Get-SIIdentityMoveSqlDropSql -OldClientId $x.ClientId) @{} 'nonquery'
                $gone = Get-SIIdentityMoveSqlCopy -Rows (& $rowsOf $d $x.ClientId $x.KeepClientId) -NewName $x.KeepName -NewClientId $x.KeepClientId
                if ($gone.OldUser) { & $mark $x.Component 'failed'; $problems.Add(('{0}: the old {1} user {2} is still there after the drop' -f $d, $x.Component, $gone.OldUser)); continue }
                & $mark $x.Component 'dropped'
                $lines.Add(('done: {0}: the old {1} user {2} dropped ({3})' -f $d, $x.Component, $cov.OldUser, $cov.Why))
            } catch { & $mark $x.Component 'failed'; $problems.Add(('{0}: the {1} drop: {2}' -f $d, $x.Component, $_.Exception.Message)) }
        }
    }
    [pscustomobject]@{ Problems = $problems.ToArray(); Lines = $lines.ToArray(); States = $states }
}

function New-SIDbInitMovesRecordValue {
    <# PURE. The identity move's own result row (cfg.InstallState 'DbJobMoves', <= 400 characters): the run and each
       component's state. #>
    param([string]$Run = '', [hashtable]$States = @{}, [datetime]$NowUtc = [datetime]::UtcNow)
    $o = [ordered]@{ run = $Run; at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); c = [ordered]@{} }
    foreach ($k in @($States.Keys | Sort-Object)) { $o.c[[string]$k] = [string]$States[$k] }
    ConvertTo-Json -InputObject $o -Compress -Depth 4
}

function Get-SIDbInitUsersSql {
    <# PURE. READ ONLY: the database's Entra users with their client ids and roles (one row per role; RoleName NULL = none). #>
@'
SELECT p.name AS Name, LOWER(CONVERT(varchar(36), CONVERT(uniqueidentifier, p.sid))) AS ClientId, r.name AS RoleName
FROM sys.database_principals AS p
LEFT JOIN sys.database_role_members AS m ON m.member_principal_id = p.principal_id
LEFT JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id
WHERE p.[type] IN ('E', 'X') AND DATALENGTH(p.sid) = 16;
'@
}

function ConvertFrom-SIDbInitUsers {
    <# PURE. Rows of Get-SIDbInitUsersSql -> @{ <client id lower> = @{ Name; Roles[] } }. #>
    param([object[]]$Rows = @())
    $h = @{}
    foreach ($r in @($Rows | Where-Object { $null -ne $_ })) {
        $cid = ([string](Get-SIDbInitProp $r @('ClientId'))).Trim().ToLowerInvariant()
        if (-not $cid) { continue }
        if (-not $h.ContainsKey($cid)) { $h[$cid] = [pscustomobject]@{ Name = [string](Get-SIDbInitProp $r @('Name')); Roles = (New-Object System.Collections.Generic.List[string]) } }
        $role = [string](Get-SIDbInitProp $r @('RoleName'))
        if ($role -and -not $h[$cid].Roles.Contains($role)) { $h[$cid].Roles.Add($role) }
    }
    $h
}

function Get-SIDbInitLedgerEngineSql {
    <# PURE. The identity ledger (its own database): the engine identity's contained user by its client id (reused whatever
       its name) with db_datareader + db_datawriter -- what the guided install's schema step gives it. #>
    param([Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$ClientId)
    $sid = Get-SIDbInitSid -ClientId $ClientId
    $n = $UserName.Replace(']', ']]'); $q = $UserName.Replace("'", "''")
    @"
DECLARE @n sysname = (SELECT name FROM sys.database_principals WHERE sid = $sid);
IF @n IS NULL BEGIN CREATE USER [$n] WITH SID = $sid, TYPE = E; SET @n = N'$q'; END
DECLARE @s nvarchar(400);
SET @s = N'ALTER ROLE db_datareader ADD MEMBER ' + QUOTENAME(@n); EXEC (@s);
SET @s = N'ALTER ROLE db_datawriter ADD MEMBER ' + QUOTENAME(@n); EXEC (@s);
"@
}

function Get-SIDbInitDatabasesSql {
    <# PURE. READ ONLY, run in master (the job is the server's administrator through the group): the server's user databases. #>
    'SELECT name AS Name FROM sys.databases WHERE database_id > 4 AND name <> N''master'' ORDER BY name;'
}

function Get-SIDbInitSupportDbSql {
    <#
        PURE. #1021 (found live at an install 2026-11-04): the support grant's procedures are in EVERY product database (the
        Pro database, the identity ledger, the data database) and each checks ITS OWN cfg.SupportConsent. So in a product
        database OTHER than the Pro one -- only where the support grant's tables are (cfg.SupportConsent) -- the job makes what
        Move-SIEngineToLeastPrivilege makes in the Pro database: the role si_engine, the engine's user (by its client id) in
        it and EXECUTE on cfg.SupportGrantOpen / Close / Sweep / Status; and for the updater (it mirrors the Pro database's
        consent there): the role si_updater, its user in it, and SELECT / INSERT / UPDATE / DELETE on cfg.SupportConsent (the
        consent trigger lets si_updater write only a row from the Invardia portal, or remove it). Idempotent; only adds.
    #>
    param([Parameter(Mandatory)][string]$EngineUser, [Parameter(Mandatory)][string]$EngineClientId, [string]$UpdaterUser = '', [string]$UpdaterClientId = '')
    $u = { param($var, $name, $cid, $role)
        $sid = Get-SIDbInitSid -ClientId $cid; $n = $name.Replace(']', ']]').Replace("'", "''"); $q = $name.Replace("'", "''")
        @"
    SET $var = (SELECT TOP (1) name FROM sys.database_principals WHERE sid = $sid AND principal_id > 4);
    IF $var IS NULL BEGIN EXEC (N'CREATE USER [$n] WITH SID = $sid, TYPE = E'); SET $var = N'$q'; END
    IF ISNULL(IS_ROLEMEMBER(N'$role', $var), 0) = 0 BEGIN SET @s = N'ALTER ROLE [$role] ADD MEMBER ' + QUOTENAME($var); EXEC (@s); END
"@ }
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add("IF OBJECT_ID(N'cfg.SupportConsent') IS NOT NULL")
    $l.Add('BEGIN')
    $l.Add('    DECLARE @s nvarchar(400), @e sysname, @u sysname;')
    $l.Add("    IF DATABASE_PRINCIPAL_ID(N'si_engine') IS NULL EXEC (N'CREATE ROLE [si_engine] AUTHORIZATION [dbo]');")
    $l.Add((& $u '@e' $EngineUser $EngineClientId 'si_engine').TrimEnd())
    foreach ($p in 'Open', 'Close', 'Sweep', 'Status') { $l.Add("    IF OBJECT_ID(N'cfg.SupportGrant$p') IS NOT NULL GRANT EXECUTE ON OBJECT::cfg.SupportGrant$p TO [si_engine];") }
    if ($UpdaterUser -and $UpdaterClientId) {
        $l.Add("    IF DATABASE_PRINCIPAL_ID(N'si_updater') IS NULL EXEC (N'CREATE ROLE [si_updater] AUTHORIZATION [dbo]');")
        $l.Add((& $u '@u' $UpdaterUser $UpdaterClientId 'si_updater').TrimEnd())
        $l.Add('    GRANT SELECT, INSERT, UPDATE, DELETE ON OBJECT::cfg.SupportConsent TO [si_updater];')
    }
    $l.Add('END')
    $l.ToArray() -join "`n"
}

function Get-SIDbInitSupportDbStateSql {
    <# PURE. READ ONLY, one row: the support grant's table here, the engine's user in si_engine with EXECUTE on the four
       procedures that are here, the updater's user in si_updater with its four rights on cfg.SupportConsent. #>
    param([Parameter(Mandatory)][string]$EngineClientId, [string]$UpdaterClientId = '')
    $es = Get-SIDbInitSid -ClientId $EngineClientId
    $us = if ($UpdaterClientId) { Get-SIDbInitSid -ClientId $UpdaterClientId } else { 'NULL' }
    @"
DECLARE @e sysname = (SELECT TOP (1) name FROM sys.database_principals WHERE sid = $es), @u sysname = (SELECT TOP (1) name FROM sys.database_principals WHERE sid = $us);
SELECT CASE WHEN OBJECT_ID(N'cfg.SupportConsent') IS NULL THEN 0 ELSE 1 END AS ConsentTable,
       CASE WHEN @e IS NULL THEN 0 ELSE ISNULL(IS_ROLEMEMBER(N'si_engine', @e), 0) END AS EngineInRole,
       (SELECT COUNT(*) FROM (VALUES (N'cfg.SupportGrantOpen'), (N'cfg.SupportGrantClose'), (N'cfg.SupportGrantSweep'), (N'cfg.SupportGrantStatus')) AS v(n) WHERE OBJECT_ID(v.n) IS NOT NULL) AS Procedures,
       (SELECT COUNT(*) FROM (VALUES (N'cfg.SupportGrantOpen'), (N'cfg.SupportGrantClose'), (N'cfg.SupportGrantSweep'), (N'cfg.SupportGrantStatus')) AS v(n)
         JOIN sys.database_permissions AS dp ON dp.class = 1 AND dp.major_id = OBJECT_ID(v.n) AND dp.permission_name = N'EXECUTE' AND dp.[state] IN ('G', 'W')
         WHERE dp.grantee_principal_id = DATABASE_PRINCIPAL_ID(N'si_engine')) AS EngineExecute,
       CASE WHEN @u IS NULL THEN 0 ELSE ISNULL(IS_ROLEMEMBER(N'si_updater', @u), 0) END AS UpdaterInRole,
       (SELECT COUNT(DISTINCT dp.permission_name) FROM sys.database_permissions AS dp WHERE dp.class = 1 AND dp.major_id = OBJECT_ID(N'cfg.SupportConsent')
         AND dp.grantee_principal_id = DATABASE_PRINCIPAL_ID(N'si_updater') AND dp.[state] IN ('G', 'W') AND dp.permission_name IN (N'SELECT', N'INSERT', N'UPDATE', N'DELETE')) AS UpdaterConsentRights;
"@
}

function Test-SIDbInitSupportDbState {
    <# PURE. The row of Get-SIDbInitSupportDbStateSql -> @{ Applies; Problems[] }. A database without the support grant's
       table is not one this applies to. -Updater: the updater's part was asked for. #>
    param($Row, [bool]$Updater = $true)
    $i = { param($k) $v = Get-SIDbInitProp $Row @($k); $n = 0; [void][int]::TryParse("$v", [ref]$n); $n }
    $p = New-Object System.Collections.Generic.List[string]
    if ((& $i 'ConsentTable') -ne 1) { return [pscustomobject]@{ Applies = $false; Problems = @() } }
    if ((& $i 'EngineInRole') -ne 1) { $p.Add('the engine''s user is not in si_engine') }
    if ((& $i 'EngineExecute') -lt (& $i 'Procedures')) { $p.Add(('si_engine may EXECUTE {0} of the {1} support grant procedures' -f (& $i 'EngineExecute'), (& $i 'Procedures'))) }
    if ($Updater) {
        if ((& $i 'UpdaterInRole') -ne 1) { $p.Add('the updater''s user is not in si_updater') }
        if ((& $i 'UpdaterConsentRights') -lt 4) { $p.Add('si_updater may not read and write cfg.SupportConsent') }
    }
    [pscustomobject]@{ Applies = $true; Problems = $p.ToArray() }
}

function Get-SIDbInitConsentReadSql {
    <# PURE. READ ONLY: the consent row (Level, Source, ConsentedBy, AppId) -- none when the table or the row is not there. #>
    "IF OBJECT_ID(N'cfg.SupportConsent') IS NOT NULL SELECT [Level], Source, ConsentedBy, CONVERT(nvarchar(36), AppId) AS AppId FROM cfg.SupportConsent WHERE Id = 1;"
}

function Get-SIDbInitConsentCopySql {
    <# PURE. The Pro database's consent row copied into this database as it is (@AppId, @Level, @Source, @By) -- run by the
       job as the database's owner (the trigger lets the owner write any row); only where the table is. #>
@'
IF OBJECT_ID(N'cfg.SupportConsent') IS NOT NULL
BEGIN
    IF NOT EXISTS (SELECT 1 FROM cfg.SupportConsent WHERE Id = 1)
        INSERT cfg.SupportConsent (Id, AppId, [Level], Source, ConsentedBy) VALUES (1, CONVERT(uniqueidentifier, @AppId), @Level, @Source, LEFT(@By, 256));
    ELSE IF NOT EXISTS (SELECT 1 FROM cfg.SupportConsent WHERE Id = 1 AND AppId = CONVERT(uniqueidentifier, @AppId) AND [Level] = @Level AND Source = @Source AND ConsentedBy = LEFT(@By, 256))
        UPDATE cfg.SupportConsent SET AppId = CONVERT(uniqueidentifier, @AppId), [Level] = @Level, Source = @Source, ConsentedBy = LEFT(@By, 256), ConsentedUtc = SYSUTCDATETIME() WHERE Id = 1;
END
'@
}

function Get-SIDbInitDatabasesRecordSql {
    <# PURE. The product databases with the support grant's table, OTHER than the Pro one (cfg.InstallState
       'SupportGrantDatabases', @Value = 'a;b', <= 400) -- the updater mirrors the Pro database's consent into them. #>
@'
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'SupportGrantDatabases')
        UPDATE cfg.InstallState SET Value = LEFT(@Value, 400), UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'caj-si-dbinit' WHERE Name = N'SupportGrantDatabases';
    ELSE INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N'SupportGrantDatabases', LEFT(@Value, 400), N'caj-si-dbinit');
END
'@
}

function Get-SIDbInitStatsAsyncSql {
    <# PURE. The database's setting that a stale statistic is updated in the background; idempotent (on already = a read only).
       A lock that does not come within 10 seconds is an error the job says as a warning; the next update tries again. #>
    @'
IF (SELECT d.is_auto_update_stats_async_on FROM sys.databases AS d WHERE d.database_id = DB_ID()) = 0
BEGIN
    SET LOCK_TIMEOUT 10000;
    ALTER DATABASE CURRENT SET AUTO_UPDATE_STATISTICS_ASYNC ON;
    SET LOCK_TIMEOUT -1;
END
'@
}

function Get-SIDbInitSupportUserReplaceSql {
    <#
        PURE. support-user-replace (Invardia, framework owner, 2026-11-05; found live at an install: the Support app's user
        was made from ANOTHER tenant's Support app client id, and a run with the right id could not CREATE it -- the name
        was taken). Drops ONE user, and only when ALL hold: it carries the Support app's user NAME, it is an Entra user
        (-PrincipalTypes; E / X -- 'S' only for the offline real-SQL test, which has no Entra), its SID is NOT the SID of
        -ClientId (this run's Support app), and NO user carries the right SID under another name. Its role memberships go
        with it. Any other case touches nothing. Ends with one row: OldSid (the wrong SID as hex, NULL = none), Dropped.
    #>
    param([Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$ClientId, [ValidateSet('E', 'X', 'S')][string[]]$PrincipalTypes = @('E', 'X'))
    $sid = Get-SIDbInitSid -ClientId $ClientId
    if ($UserName -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$') { throw ("the Support app's user name '{0}' is not safe" -f $UserName) }
    $q = $UserName.Replace("'", "''")
    $types = (@($PrincipalTypes | Select-Object -Unique | ForEach-Object { "'$_'" })) -join ', '
    @"
DECLARE @old varbinary(85) = (SELECT TOP (1) sid FROM sys.database_principals WHERE name = N'$q' AND principal_id > 4 AND [type] IN ($types) AND sid <> $sid);
DECLARE @drop nvarchar(400) = N'DROP USER ' + QUOTENAME(N'$q');
IF @old IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE sid = $sid AND principal_id > 4)
    EXEC (@drop);
SELECT CONVERT(varchar(70), @old, 1) AS OldSid, CASE WHEN @old IS NOT NULL AND DATABASE_PRINCIPAL_ID(N'$q') IS NULL THEN 1 ELSE 0 END AS Dropped;
"@
}

function Get-SIDbInitPlan {
    <#
        PURE apart from Get-Command (a builder a package does not carry is left out, said in Skipped). The batches the job
        runs, in order, each @{ Step; Database; Name; Sql; Params; Required }. -Users / -LedgerUsers: ConvertFrom-SIDbInitUsers
        of each database BEFORE (a user that is there under another name is used by that name). -ProcedureInstalled: the signed
        grant procedure is in the Pro database already (it is then kept current also with the switch off). -Consent: the Pro
        database's support consent ('<level>|<source>', '' = none). A batch with Required = $false that fails is a warning.
    #>
    param([Parameter(Mandatory)]$DbInput, [hashtable]$Users = @{}, [hashtable]$LedgerUsers = @{}, [bool]$ProcedureInstalled = $false, [string]$Consent = '',
          # #1021: the product databases OTHER than the Pro one (the ledger, the data database) and the Pro database's consent row
          [string[]]$SupportDatabases = @(), $ProConsent = $null)
    $b = New-Object System.Collections.Generic.List[object]
    $skipped = New-Object System.Collections.Generic.List[string]
    $pro = $DbInput.Database; $led = $DbInput.LedgerDatabase
    $has = { param($f) [bool](Get-Command -Name $f -CommandType Function -ErrorAction SilentlyContinue) }
    $add = { param($step, $dbn, $name, $sql, $params, $req) $b.Add([pscustomobject]@{ Step = $step; Database = $dbn; Name = $name; Sql = $sql; Params = $(if ($params) { $params } else { @{} }); Required = [bool]$req }) }
    $of = { param($c) @($DbInput.Principals | Where-Object { $_.Component -eq $c })[0] }
    $nameIn = { param($users, $p) $k = $p.ClientId.ToLowerInvariant(); if ($users.ContainsKey($k) -and $users[$k].Name) { $users[$k].Name } else { $p.Name } }

    $eng = & $of 'engine'
    if (& $has 'Get-SIEngineDatabaseAccessSql') {
        & $add 'engine' $pro ('the engine identity {0}: its user, the role si_engine and its grants{1}' -f $eng.Name, $(if ($DbInput.EngineRoleOnly) { ' (the role only)' } else { ' (and db_datareader + db_datawriter)' })) `
            (Get-SIEngineDatabaseAccessSql -UserName $eng.Name -ClientId $eng.ClientId -KeepBroadRoles:(-not $DbInput.EngineRoleOnly)) $null $true
    } else { $skipped.Add('engine (this package has no engine grant list)') }
    if (& $has 'Get-SIEngineDatabaseGrantSql') { & $add 'engine-load' $pro 'the engine role''s read right on the database''s own load' (Get-SIEngineDatabaseGrantSql) $null $false }

    $upd = & $of 'updater'
    $procWanted = $false
    if ($upd) {
        if (& $has 'Get-SIUpdaterDatabaseAccessSql') {
            & $add 'updater' $pro ('the updater identity {0}: its user, db_datareader, db_datawriter, db_ddladmin{1}' -f $upd.Name, $(if ($DbInput.SignedGrants) { '' } else { ', db_securityadmin' })) `
                (Get-SIUpdaterDatabaseAccessSql -UserName $upd.Name -ClientId $upd.ClientId -NoSecurityAdmin:([bool]$DbInput.SignedGrants)) $null $true
        } else { $skipped.Add('updater (this package has no updater grant list)') }
        $procWanted = ([bool]$DbInput.SignedGrants -or $ProcedureInstalled) -and (& $has 'Get-SIGrantProcedureAdminSql')
        if ($procWanted) {
            $un = & $nameIn $Users $upd
            foreach ($x in @(Get-SIGrantProcedureAdminSql -UpdaterUser $un)) { & $add ('procedure-' + $x.Step) $pro ('the signed grant procedure: ' + $x.Purpose) $x.Sql $null $true }
        }
    }

    foreach ($w in @(@{ C = 'web'; Writer = $true }, @{ C = 'mcp'; Writer = $false })) {
        $p = & $of $w.C
        if (-not $p) { continue }
        if (& $has 'Get-SIManagementUserSql') {
            $nm = & $nameIn $Users $p
            & $add $w.C $pro ('the {0} identity {1}: its user, db_datareader and its grants' -f $(if ($w.Writer) { 'web app' } else { 'MCP server' }), $nm) `
                (Get-SIManagementUserSql -Identity ([pscustomobject]@{ Name = $nm; ClientId = $p.ClientId }) -Writer:$w.Writer) $null $true
        } else { $skipped.Add(('{0} (this package has no web app grant list)' -f $w.C)) }
    }
    $web = & $of 'web'
    if ($web -and (& $has 'Get-SISigninStoreSql')) {
        foreach ($a in 'sql-user', 'sql-schema', 'sql-grant') {
            & $add ('signin-' + $a.Substring(4)) $pro ('the sign-in front''s store: ' + $(switch ($a) { 'sql-user' { 'the web identity''s user' } 'sql-schema' { 'the schema signin owned by the web identity' } default { 'CREATE TABLE for the web identity' } })) `
                (Get-SISigninStoreSql -Action $a) @{ ClientId = $web.ClientId; UserName = (& $nameIn $Users $web) } $true
        }
    }
    $tag = & $of 'tagging'
    if ($tag) {
        if (& $has 'Get-SITaggingDatabaseAccessSql') {
            & $add 'tagging' $pro ('asset tagging''s identity {0}: its user, db_datareader, INSERT on the audit trail' -f $tag.Name) (Get-SITaggingDatabaseAccessSql -UserName $tag.Name -ClientId $tag.ClientId) $null $true
        } else { $skipped.Add('tagging (this package has no tagging grant)') }
    }
    if ($led) { & $add 'ledger-engine' $led ('the identity ledger: the engine identity {0} reads and writes it' -f $eng.Name) (Get-SIDbInitLedgerEngineSql -UserName $eng.Name -ClientId $eng.ClientId) $null $true }

    # 2026-11-05 (framework §12.27 SQL-STATS): every product database updates a stale statistic in the background, so a page read
    # never waits for one. Only this job may change a database setting (the server's admin group); the update runs it on every
    # update, so an existing install reaches what a new one has. Not required: a setting that cannot change now is a warning.
    foreach ($d in @(@($pro) + @($(if ($led) { $led })) + @($SupportDatabases) | Where-Object { $_ } | Select-Object -Unique)) {
        & $add 'stats-async' $d ('{0}: statistics updated in the background (a page never waits for one)' -f $d) (Get-SIDbInitStatsAsyncSql) $null $false
    }

    # the Invardia Support app: only when the caller names it (the install's Support setting, or a support repair) -- the
    # update never touches it (owner 2026-10-18: Invardia repairs a missing part itself)
    if ($DbInput.Support) {
        $dbs = @($pro) + @($(if ($led) { $led }))
        # support-user-replace (Invardia, framework owner, 2026-11-05): a user under the Support app's NAME whose SID is not
        # the SID of THIS run's Support app (another tenant's Support app id typed by hand) blocks the CREATE below. Only
        # then -- and only when no user carries the right SID under another name -- that one user is dropped (its role
        # memberships go with it) and the next step makes the right one. Both SIDs are said in the job's lines.
        if (& $has 'Get-SIDbInitSupportUserReplaceSql') {
            $want = $DbInput.Support.ClientId.ToLowerInvariant()
            foreach ($d in $dbs) {
                $uu = if ($d -eq $pro) { $Users } else { $LedgerUsers }
                if (-not $uu -or $uu.ContainsKey($want)) { continue }
                $wrong = @($uu.Keys | Where-Object { $_ -ne $want -and [string]$uu[$_].Name -ieq $DbInput.Support.UserName })[0]
                if (-not $wrong) { continue }
                & $add 'support-user-replace' $d ('the Invardia Support app''s user {0} in {1} was made for client id {2} (SID {3}), not for this install''s Support app {4} (SID {5}): dropped with its role memberships, made again with the right SID by the next step' -f `
                    $DbInput.Support.UserName, $d, $wrong, (Get-SIDbInitSid -ClientId $wrong), $DbInput.Support.ClientId, (Get-SIDbInitSid -ClientId $DbInput.Support.ClientId)) `
                    (Get-SIDbInitSupportUserReplaceSql -UserName $DbInput.Support.UserName -ClientId $DbInput.Support.ClientId) $null $true
            }
        }
        if (& $has 'Get-SISupportAppDatabaseAccessSql') {
            foreach ($d in $dbs) { & $add 'support-user' $d ('the Invardia Support app''s own user ({0}) in {1}' -f $DbInput.Support.UserName, $d) (Get-SISupportAppDatabaseAccessSql -UserName $DbInput.Support.UserName -ClientId $DbInput.Support.ClientId) $null $true }
        } else { $skipped.Add('support-user (this package has no Support app access)') }
        # the install records WHICH Support app this is (cfg.InstallState 'SupportApp' = its client id: the heartbeat reports its
        # access by it, the updater knows it as an owner of the web sign-in app) -- the same write the person-run path makes
        # (setup\_shared\SI-SupportAppDatabase.ps1 Get-SISupportAppRecordSql: insert, or update when different), Pro database only
        if (& $has 'Get-SISupportAppRecordSql') {
            & $add 'support-record' $pro ('the install records the Invardia Support app {0} (cfg.InstallState SupportApp)' -f $DbInput.Support.ClientId) (Get-SISupportAppRecordSql -ClientId $DbInput.Support.ClientId -By 'the database setup job') $null $true
        } else { $skipped.Add('support-record (this package does not record the Support app)') }
        if (& $has 'Get-SISupportGrantAdminSteps') {
            $lv = ''; $src = 'derived'
            if ($Consent -and $Consent -ne '-') { $lv, $src = $Consent -split '\|', 2; if ($lv -notin 'troubleshoot', 'setup') { $lv = '' }; if ($src -ne 'customer') { $src = 'derived' } }
            foreach ($d in $dbs) {
                foreach ($x in @(Get-SISupportGrantAdminSteps -ClientId $DbInput.Support.ClientId -UserName $DbInput.Support.UserName -Level $lv -Source $src -By 'the database setup job')) {
                    & $add ('support-grant-' + $x.Step) $d ('the support grant ({0}): {1}' -f $d, $x.Purpose) $x.Sql $null $true
                }
            }
        } else { $skipped.Add('support-grant (this package has no support grant)') }
    }

    # #1021: every OTHER product database where the support grant is: the engine may run its procedures there, the updater
    # may mirror the consent there; the Pro database's consent row copied as it is (the job is the owner there).
    # AFTER the support grant steps (2026-11-06, seen at a customer install): this statement acts only where cfg.SupportConsent is, and a run
    # that names the Support app makes that table in the identity ledger only above -- before, a first run left the engine
    # outside si_engine there and its read-back failed until a second run.
    $upd2 = & $of 'updater'
    foreach ($d in @($SupportDatabases | Where-Object { $_ -and $_ -ne $pro } | Select-Object -Unique)) {
        & $add 'support-db' $d ('{0}: the role si_engine with EXECUTE on the support grant procedures, {1} in it{2}' -f $d, $eng.Name, $(if ($upd2) { ('; si_updater with its rights on cfg.SupportConsent, {0} in it' -f $upd2.Name) } else { '' })) `
            (Get-SIDbInitSupportDbSql -EngineUser $eng.Name -EngineClientId $eng.ClientId -UpdaterUser $(if ($upd2) { $upd2.Name } else { '' }) -UpdaterClientId $(if ($upd2) { $upd2.ClientId } else { '' })) $null $true
        $pl = [string](Get-SIDbInitProp $ProConsent @('Level'))
        if ($pl -in 'troubleshoot', 'setup') {
            & $add 'consent-copy' $d ('{0}: the Pro database''s support consent ({1}) copied' -f $d, $pl) (Get-SIDbInitConsentCopySql) `
                @{ AppId = [string](Get-SIDbInitProp $ProConsent @('AppId')); Level = $pl; Source = [string](Get-SIDbInitProp $ProConsent @('Source')); By = [string](Get-SIDbInitProp $ProConsent @('ConsentedBy')) } $true
        }
    }
    # SI_DBINIT_STEPS=grants (Invardia 2026-11-06, framework §8.18): beside a running pipeline run only users, role memberships
    # and grants -- the batches that create or change a procedure (the signed grant procedure, the support grant), a schema
    # (signin-schema), a database setting (stats-async) or drop a user (support-user-replace) are left out and said
    if ([string](Get-SIDbInitProp $DbInput @('Steps')) -eq 'grants') {
        $ddl = '^(procedure-|support-grant-|signin-schema$|stats-async$|support-user-replace$)'
        foreach ($x in @($b | Where-Object { $_.Step -match $ddl } | Select-Object -ExpandProperty Step -Unique)) { $skipped.Add(('{0} (grants only: it changes a procedure, a schema or a database setting)' -f $x)) }
        $keep = @($b | Where-Object { $_.Step -notmatch $ddl })
        return [pscustomobject]@{ Batches = $keep; Skipped = $skipped.ToArray(); Procedure = $false }
    }
    [pscustomobject]@{ Batches = $b.ToArray(); Skipped = $skipped.ToArray(); Procedure = [bool]$procWanted }
}

function Get-SIDbInitExpectations {
    <# PURE. What the read-back must find: @{ Database; Component; Name; ClientId; Roles[] } per principal and database. #>
    param([Parameter(Mandatory)]$DbInput, [bool]$Procedure = $false, [hashtable]$PlannedSteps = @{})
    $x = New-Object System.Collections.Generic.List[object]
    $pro = $DbInput.Database; $led = $DbInput.LedgerDatabase
    foreach ($p in $DbInput.Principals) {
        if (-not $PlannedSteps.ContainsKey($p.Component)) { continue }
        $roles = switch ($p.Component) {
            'engine'  { @('si_engine') + @($(if (-not $DbInput.EngineRoleOnly) { 'db_datareader', 'db_datawriter' })) }
            'updater' { @('db_datareader', 'db_datawriter', 'db_ddladmin') + @($(if (-not $DbInput.SignedGrants) { 'db_securityadmin' })) + @($(if ($Procedure) { 'si_updater' })) }
            default   { @('db_datareader') }
        }
        $x.Add([pscustomobject]@{ Database = $pro; Component = $p.Component; Name = $p.Name; ClientId = $p.ClientId; Roles = @($roles | Where-Object { $_ }) })
        if ($p.Component -eq 'engine' -and $led -and $PlannedSteps.ContainsKey('ledger-engine')) { $x.Add([pscustomobject]@{ Database = $led; Component = 'engine'; Name = $p.Name; ClientId = $p.ClientId; Roles = @('db_datareader', 'db_datawriter') }) }
    }
    if ($DbInput.Support -and $PlannedSteps.ContainsKey('support-user')) {
        foreach ($d in @($pro) + @($(if ($led) { $led }))) { $x.Add([pscustomobject]@{ Database = $d; Component = 'support'; Name = $DbInput.Support.UserName; ClientId = $DbInput.Support.ClientId; Roles = @('db_owner') }) }
    }
    $x.ToArray()
}

function Test-SIDbInitReadBack {
    <#
        PURE. The verdict of the read-back. -Users: database -> ConvertFrom-SIDbInitUsers AFTER the run. -Signin: the sign-in
        store's state (ConvertFrom-SISigninStoreStateRow) or $null when not planned. -Procedure: Test-SIGrantProcedureReady's
        answer or $null. -SupportGrant: database -> ConvertFrom-SISupportGrantState, or @{}. Returns @{ Ok; Problems; Lines;
        Count (principals read back) }. A missing consent is a line, never a problem (the customer gives it).
    #>
    param([object[]]$Expect = @(), [hashtable]$Users = @{}, $Signin = $null, $Procedure = $null, [hashtable]$SupportGrant = @{})
    $problems = New-Object System.Collections.Generic.List[string]; $lines = New-Object System.Collections.Generic.List[string]
    $n = 0
    foreach ($e in $Expect) {
        $u = $null
        if ($Users.ContainsKey($e.Database)) { $h = $Users[$e.Database]; $k = $e.ClientId.ToLowerInvariant(); if ($h -and $h.ContainsKey($k)) { $u = $h[$k] } }
        if (-not $u) { $problems.Add(('{0}: the {1} identity {2} has no user (by its client id)' -f $e.Database, $e.Component, $e.Name)); continue }
        $miss = @($e.Roles | Where-Object { -not $u.Roles.Contains($_) })
        if ($miss.Count) { $problems.Add(('{0}: {1} ({2}) is not in {3}' -f $e.Database, $u.Name, $e.Component, ($miss -join ', '))); continue }
        $n++
        $lines.Add(('read back: {0}: {1} ({2}) in {3}' -f $e.Database, $u.Name, $e.Component, ($e.Roles -join ', ')))
    }
    if ($null -ne $Signin) {
        if ($Signin.SchemaOk -and $Signin.CreateTable) { $lines.Add(('read back: the schema signin belongs to {0}, who may create tables' -f $Signin.User)) }
        else { $problems.Add(('the sign-in front''s store is not complete (schema signin {0}, CREATE TABLE {1})' -f $(if ($Signin.SchemaOk) { 'ok' } else { 'not owned by the web identity' }), $(if ($Signin.CreateTable) { 'granted' } else { 'missing' }))) }
    }
    if ($null -ne $Procedure) {
        if ($Procedure.Ok) { $lines.Add('read back: the signed grant procedure is in place and the updater may run it') }
        else { foreach ($l in @($Procedure.Lines)) { $problems.Add(('the signed grant procedure: {0}' -f $l)) } }
    }
    foreach ($d in @($SupportGrant.Keys)) {
        $st = $SupportGrant[$d]
        foreach ($l in @($st.Lines)) { if ($l -match 'no consent is recorded') { $lines.Add(('{0}: {1} (the customer gives it)' -f $d, $l)) } else { $problems.Add(('{0}: the support grant: {1}' -f $d, $l)) } }
        if ($st.Ok) { $lines.Add(('read back: {0}: the support grant is in place' -f $d)) }
    }
    [pscustomobject]@{ Ok = ($problems.Count -eq 0); Problems = $problems.ToArray(); Lines = $lines.ToArray(); Count = $n }
}

function New-SIDbInitRecordValue {
    <# PURE. The result row's value: compact JSON, at most 400 characters (the column is NVARCHAR(400)); the reason is cut
       first. -State ok | failed | waiting. #>
    param([Parameter(Mandatory)][ValidateSet('ok', 'failed', 'waiting')][string]$State, [string]$Run = '', [string]$By = '', [int]$Count = 0,
          [string]$Why = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $max = (Get-SIDbInitNames).RecordMax
    $o = [ordered]@{ state = $State; at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Run) { $o.run = $Run }
    if ($By) { $o.by = $By }
    $o.n = $Count
    $w = [regex]::Replace([regex]::Replace("$Why", '[\x00-\x1F]', ' '), '\s+', ' ').Trim()
    $o.why = ''
    $base = (ConvertTo-Json -InputObject $o -Compress).Length
    $room = $max - $base - 8
    if ($w.Length -gt $room) { $w = $(if ($room -gt 3) { $w.Substring(0, $room - 3).TrimEnd() + '...' } else { '' }) }
    $o.why = $w
    $v = ConvertTo-Json -InputObject $o -Compress
    # an escaped character can still push it over: cut the reason until it fits (it still ends with '...')
    while ($v.Length -gt $max -and $w.Length -gt 0) {
        $w = $w.Substring(0, [Math]::Max(0, $w.Length - 10))
        $o.why = $(if ($w.Length -gt 3) { $w.Substring(0, $w.Length - 3).TrimEnd() + '...' } else { '' })
        $v = ConvertTo-Json -InputObject $o -Compress
    }
    if (-not $o.why) { $o.Remove('why'); $v = ConvertTo-Json -InputObject $o -Compress }
    $v
}

function ConvertFrom-SIDbInitRecordValue {
    <# PURE. The result row's value as an object (@{ state; at; run; by; n; why }), or $null. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if (-not "$Value".Trim()) { return $null }
    try { $o = "$Value" | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    if (-not ($o -is [System.Management.Automation.PSCustomObject]) -or -not $o.PSObject.Properties['state']) { return $null }
    $o
}

function Get-SIDbInitRecordSql {
    <# PURE. The ONE write of the result: cfg.InstallState 'DbJob' (@Value, @Version, @By), written or replaced. -Name: another
       row of the job's (the membership's own row, 'DbJobMembership'). #>
    param([ValidatePattern('^[A-Za-z]{1,40}$')][string]$Name = '')
    $n = if ($Name) { $Name } else { (Get-SIDbInitNames).Record }
    @"
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'$n')
        UPDATE cfg.InstallState SET Value = @Value, [Version] = @Version, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'$n';
    ELSE INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'$n', @Value, @Version, @By);
END
"@
}

function Get-SIDbInitRecordReadSql {
    <# PURE. READ ONLY: the result row's value ('' = none, or no table). -Name: another row of the job's (#1146: the row of
       one caller, Get-SIDbInitCallerRecordName). #>
    param([ValidatePattern('^$|^[A-Za-z]{1,40}$')][string]$Name = '')
    $n = if ($Name) { $Name } else { (Get-SIDbInitNames).Record }
    "IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'$n';"
}

function Test-SIDbInitLoginRefused {
    <# PURE. Is this SQL error a refused sign-in (the membership is new or still replicating) -- waited for, never a stop? #>
    param([AllowEmptyString()][string]$Message)
    [bool]("$Message" -match '(?i)Login failed|18456|token-identified principal|not allowed to access|40615')
}

function Get-SIDbInitStandingOffNames {
    <# PURE. #1151 SEC-01: the job's row of the standing-off result (cfg.InstallState), read by the updater. #>
    @{ Record = 'DbJobSupportStanding' }
}

function Invoke-SIDbInitStandingOff {
    <#
        #1151 (1) SEC-01 / OPEN-01, THE JOB'S SIDE: in each of -Databases, Get-SISupportStandingOffSql (engine\pro-settings\
        SI-SupportGrantSql.ps1) -- db_owner off the Support app's own user ONLY where the just-in-time path reads back in that
        database, in the same batch. Nothing else is changed: no user dropped, no group, no server administrator. A database
        that cannot be read or is not ready keeps what it has. Never throws. -Sql: the job's seam. Returns @{ State (off =
        no product database holds the Support app's standing db_owner any more | kept = at least one still does | unknown =
        the statement is not in this package); Databases (ordered db -> off | none | absent | kept); Why; Lines }.
    #>
    param([Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][scriptblock]$Sql, [string[]]$Databases = @())
    $lines = New-Object System.Collections.Generic.List[string]
    $per = [ordered]@{}; $why = New-Object System.Collections.Generic.List[string]
    if (-not (Get-Command -Name Get-SISupportStandingOffSql -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ State = 'unknown'; Databases = $per; Why = 'this package cannot take the standing access off'; Lines = @('not in this package: the Support app''s standing db_owner off (support-standing-off)') }
    }
    foreach ($d in @($Databases | Where-Object { $_ } | Select-Object -Unique)) {
        try {
            $r = ConvertFrom-SISupportStandingOffRow -Row (@(& $Sql $d (Get-SISupportStandingOffSql -ClientId $ClientId) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1)
        } catch { $r = [pscustomobject]@{ State = 'kept'; Roles = @(); Why = ('could not be read ({0})' -f $_.Exception.Message) } }
        $per[$d] = $r.State
        switch ($r.State) {
            'off'    { $lines.Add(('support standing access: {0}: db_owner taken off the Invardia Support app''s own user -- the just-in-time path read back first; read back after: {1}' -f $d, $(if (@($r.Roles).Count) { @($r.Roles) -join ', ' } else { '(no role)' }))) }
            'none'   { $lines.Add(('support standing access: {0}: the Invardia Support app holds no standing db_owner here' -f $d)) }
            'absent' { $lines.Add(('support standing access: {0}: the Invardia Support app has no user here' -f $d)) }
            default  { $why.Add(('{0}: {1}' -f $d, $r.Why)); $lines.Add(('support standing access: {0}: db_owner KEPT, nothing changed -- {1}' -f $d, $r.Why)) }
        }
    }
    $state = if (-not $per.Count) { 'unknown' } elseif (@($per.Values | Where-Object { $_ -eq 'kept' }).Count) { 'kept' } else { 'off' }
    [pscustomobject]@{ State = $state; Databases = $per; Why = ($why.ToArray() -join '; '); Lines = $lines.ToArray() }
}

function New-SIDbInitStandingOffRecordValue {
    <# PURE. The row DbJobSupportStanding: compact JSON { state, at, run, dbs: 'db:off;db2:none', why }, at most 400 characters
       (the reason is cut first). #>
    param([Parameter(Mandatory)][ValidateSet('off', 'kept', 'unknown')][string]$State, [string]$Run = '', [System.Collections.IDictionary]$Databases = @{},
          [string]$Why = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $max = (Get-SIDbInitNames).RecordMax
    $o = [ordered]@{ state = $State; at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Run) { $o.run = $Run }
    $o.dbs = ((@($Databases.Keys) | ForEach-Object { '{0}:{1}' -f $_, $Databases[$_] }) -join ';')
    if ($o.dbs.Length -gt 200) { $o.dbs = $o.dbs.Substring(0, 197) + '...' }
    $w = [regex]::Replace([regex]::Replace("$Why", '[\x00-\x1F]', ' '), '\s+', ' ').Trim()
    $room = $max - (ConvertTo-Json -InputObject $o -Compress).Length - 16
    if ($w.Length -gt $room) { $w = $(if ($room -gt 3) { $w.Substring(0, $room - 3).TrimEnd() + '...' } else { '' }) }
    if ($w) { $o.why = $w }
    $v = ConvertTo-Json -InputObject $o -Compress
    while ($v.Length -gt $max -and $o.Contains('why') -and ([string]$o.why).Length -gt 16) { $o.why = ([string]$o.why).Substring(0, ([string]$o.why).Length - 13) + '...'; $v = ConvertTo-Json -InputObject $o -Compress }
    $v
}

function Invoke-SIDbInit {
    <#
        THE JOB'S RUN. -DbInput: Read-SIDbInitInput. -Sql: the seam (see the file's help) -- each call gets a fresh token from
        the caller. -Log { param($m) } prints a line. Returns @{ ExitCode (0 = every principal read back; 1 = a step or the
        read-back failed; 2 = refused inputs); Verdict; Lines; Record }. A refused sign-in is waited for (-LoginTries x
        -LoginWaitSeconds, a fresh token each time); a database that is not there (the ledger on an older install) is a line.
    #>
    param([Parameter(Mandatory)]$DbInput, [Parameter(Mandatory)][scriptblock]$Sql, [scriptblock]$Log = { param($m) Write-Host $m },
          [string]$Version = '', [int]$LoginTries = 16, [int]$LoginWaitSeconds = 20, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          [scriptblock]$Now = { [datetime]::UtcNow }, [int[]]$DeadlockWaits = (Get-SIDbInitNames).DeadlockWaits)
    $out = New-Object System.Collections.Generic.List[string]
    $say = { param($m) $out.Add([string]$m); $null = & $Log $m }
    $res = { param($code, $verdict, $rec) [pscustomobject]@{ ExitCode = $code; Verdict = $verdict; Lines = $out.ToArray(); Record = $rec } }
    if (-not $DbInput.Ok) { & $say ('refused: {0}' -f $DbInput.Reason); return (& $res 2 'refused' '') }
    $pro = $DbInput.Database; $led = $DbInput.LedgerDatabase
    & $say ('the database setup job: {0}/{1}{2}; identities {3}{4}' -f $DbInput.Server, $pro, $(if ($led) { ' + ' + $led } else { '' }),
        ((@($DbInput.Principals | ForEach-Object { '{0}={1}' -f $_.Component, $_.Name })) -join ', '), $(if ($DbInput.Support) { '; the Invardia Support app ' + $DbInput.Support.UserName } else { '' }))
    # 1. the sign-in: the job's identity is the admin only through the group
    $ok = $false
    for ($i = 1; $i -le $LoginTries; $i++) {
        try { $null = & $Sql $pro 'SELECT 1' @{} 'rows'; $ok = $true; break }
        catch {
            $m = [string]$_.Exception.Message
            if (-not (Test-SIDbInitLoginRefused -Message $m)) { & $say ('the database could not be reached: {0}' -f $m); return (& $res 1 'failed' '') }
            & $say ('the sign-in was refused (try {0} of {1}) -- the identity''s membership of the SQL admin group may still be replicating: {2}' -f $i, $LoginTries, $m)
            if ($i -lt $LoginTries) { & $Sleep $LoginWaitSeconds }
        }
    }
    if (-not $ok) { & $say ('the job''s identity could not sign in to the database as a member of the SQL admin group after {0} tries -- is it a member of the group that is the server''s administrator?' -f $LoginTries); return (& $res 1 'failed' '') }
    # #1146: ONE statement that changes something, sent again when SQL chose it as a DEADLOCK victim (1205: rolled back so
    # another session could finish -- nothing of it stayed) after a short growing wait, said each time; any other error, or a
    # deadlock after the last wait, is thrown as it was
    $dlWaits = @($DeadlockWaits | Where-Object { $_ -ge 0 })
    $send = {
        param([string]$db, [string]$q, $p, [string]$what)
        $try = 0
        while ($true) {
            try { $null = & $Sql $db $q $p 'nonquery'; return }
            catch {
                $m = [string]$_.Exception.Message
                if (-not (Test-SIDbInitDeadlock -Message $m) -or $try -ge $dlWaits.Count) { throw }
                $w = [int]$dlWaits[$try]; $try++
                & $say ('{0}: chosen as a deadlock victim by SQL (1205: another session held the same rows; nothing of this statement stayed) -- sent again in {1} s (try {2} of {3})' -f $what, $w, ($try + 1), ($dlWaits.Count + 1))
                & $Sleep $w
            }
        }
    }
    $writeRecord = {
        param($state, $count, $why)
        $v = New-SIDbInitRecordValue -State $state -Run $DbInput.Run -By $DbInput.By -Count $count -Why $why -NowUtc (& $Now)
        $rp = @{ Value = $v; Version = $(if ($Version) { $Version.Substring(0, [Math]::Min(32, $Version.Length)) } else { $null }); By = (Get-SIDbInitNames).Job }
        try { & $send $pro (Get-SIDbInitRecordSql) $rp 'the result row'; & $say ('result recorded: {0}' -f $v) }
        catch { & $say ('WARNING: the result could not be recorded: {0}' -f $_.Exception.Message) }
        # #1146: the same result in the row of THIS caller (DbJobUpdater / DbJobSupport / DbJobInstaller): a run started beside
        # another one never overwrites the result the other caller waits for
        $own = Get-SIDbInitCallerRecordName -By $DbInput.By
        try { & $send $pro (Get-SIDbInitRecordSql -Name $own) $rp ('the result row ' + $own) }
        catch { & $say ('WARNING: the result could not be recorded in {0}: {1}' -f $own, $_.Exception.Message) }
        $v
    }
    $usersOf = { param($d) ConvertFrom-SIDbInitUsers -Rows @(& $Sql $d (Get-SIDbInitUsersSql) @{} 'rows' | ForEach-Object { $_ }) }
    try {
        # 2. what is there BEFORE: the users (a user under another name is used by that name), the procedure, the consent
        $ledOk = $false
        if ($led) {
            try { $null = & $Sql $led 'SELECT 1' @{} 'rows'; $ledOk = $true }
            catch { & $say ('the identity ledger {0} could not be opened ({1}) -- its steps are left out' -f $led, $_.Exception.Message) }
        }
        $in = $DbInput
        if (-not $ledOk -and $led) { $in = $DbInput.PSObject.Copy(); $in.LedgerDatabase = '' }
        $users = & $usersOf $pro
        $ledUsers = if ($in.LedgerDatabase) { & $usersOf $in.LedgerDatabase } else { @{} }
        $procInstalled = $false
        if (Get-Command -Name Get-SIGrantProcedureStateSql -ErrorAction SilentlyContinue) {
            $st = ConvertFrom-SIGrantProcedureState -Row (@(& $Sql $pro (Get-SIGrantProcedureStateSql) @{} 'rows' | ForEach-Object { $_ }) | Select-Object -First 1)
            $procInstalled = [bool]$st.Installed
        }
        $consent = ''
        if ($in.Support -and (Get-Command -Name Get-SISupportGrantConsentReadSql -ErrorAction SilentlyContinue)) {
            $row = @(& $Sql $pro (Get-SISupportGrantConsentReadSql) @{} 'rows' | ForEach-Object { $_ }) | Select-Object -First 1
            $consent = ([string](Get-SIDbInitProp $row @('Consent'))).Trim()
        }
        # #1021: the OTHER product databases (the server is SecurityInsight's own: its user databases, read in master; the
        # ledger as given) and the Pro database's consent row -- what the support grant needs in each of them
        $others = New-Object System.Collections.Generic.List[string]
        if ($in.LedgerDatabase) { $others.Add($in.LedgerDatabase) }
        try {
            foreach ($r in @(& $Sql 'master' (Get-SIDbInitDatabasesSql) @{} 'rows' | ForEach-Object { $_ })) {
                $dn = [string](Get-SIDbInitProp $r @('Name'))
                if ($dn -and $dn -ne $pro -and $dn -match '^[A-Za-z0-9_.-]{1,128}$' -and -not $others.Contains($dn)) { $others.Add($dn) }
            }
        } catch { & $say ('the server''s other databases could not be listed ({0}) -- only the identity ledger is checked for the support grant' -f $_.Exception.Message) }
        $proConsent = $null
        try { $proConsent = @(& $Sql $pro (Get-SIDbInitConsentReadSql) @{} 'rows' | ForEach-Object { $_ }) | Select-Object -First 1 } catch { $proConsent = $null }
        # 3. the batches, in order
        $plan = Get-SIDbInitPlan -DbInput $in -Users $users -LedgerUsers $ledUsers -ProcedureInstalled $procInstalled -Consent $consent -SupportDatabases $others.ToArray() -ProConsent $proConsent
        foreach ($s in $plan.Skipped) { & $say ('not in this package: {0}' -f $s) }
        $planned = @{}
        foreach ($bt in $plan.Batches) {
            try { & $send $bt.Database $bt.Sql $bt.Params $bt.Name; & $say ('done: {0}' -f $bt.Name); $planned[$bt.Step] = $true }
            catch {
                if (-not $bt.Required) { & $say ('WARNING: {0}: {1}' -f $bt.Name, $_.Exception.Message); continue }
                throw ('{0}: {1}' -f $bt.Name, $_.Exception.Message)
            }
        }
        # 3b. THE IDENTITY MOVE (only when this execution names moves / drops): copy and read back, then drop only what the
        # kept identity reads back holding -- in the Pro database, the identity ledger and every other product database
        $mvRes = $null
        if (@($in.Moves).Count -or @($in.Drops).Count) {
            $mvDbs = @(@($pro) + @($others.ToArray()) | Where-Object { $_ } | Select-Object -Unique)
            $mvRes = Invoke-SIDbInitMoves -DbInput $in -Sql $Sql -Databases $mvDbs
            foreach ($l in $mvRes.Lines) { & $say $l }
            $mvVal = New-SIDbInitMovesRecordValue -Run $in.Run -States $mvRes.States -NowUtc (& $Now)
            try { $null = & $Sql $pro (Get-SIDbInitRecordSql -Name 'DbJobMoves') @{ Value = $mvVal; Version = $null; By = (Get-SIDbInitNames).Job } 'nonquery'; & $say ('identity move recorded: {0}' -f $mvVal) }
            catch { & $say ('WARNING: the identity move''s result could not be recorded: {0}' -f $_.Exception.Message) }
        }
        # 3c. #1151 SEC-01: the Support app's STANDING db_owner taken off (only when the updater names it, only where the
        # just-in-time path reads back in the same batch) -- never part of the verdict: a database that is not ready keeps it
        if ([string](Get-SIDbInitProp $in @('StandingOff'))) {
            $soDbs = @(@($pro) + @($others.ToArray()) | Where-Object { $_ } | Select-Object -Unique)
            $so = Invoke-SIDbInitStandingOff -ClientId ([string]$in.StandingOff) -Sql $Sql -Databases $soDbs
            foreach ($l in $so.Lines) { & $say $l }
            $soVal = New-SIDbInitStandingOffRecordValue -Run $in.Run -State $so.State -Databases $so.Databases -Why $so.Why -NowUtc (& $Now)
            try { $null = & $Sql $pro (Get-SIDbInitRecordSql -Name (Get-SIDbInitStandingOffNames).Record) @{ Value = $soVal; Version = $null; By = (Get-SIDbInitNames).Job } 'nonquery'; & $say ('support standing access recorded: {0}' -f $soVal) }
            catch { & $say ('WARNING: the support standing access result could not be recorded: {0}' -f $_.Exception.Message) }
        }
        # 4. THE READ-BACK (read only)
        $after = @{}; $after[$pro] = & $usersOf $pro
        if ($in.LedgerDatabase) { $after[$in.LedgerDatabase] = & $usersOf $in.LedgerDatabase }
        $signin = $null
        $web = @($in.Principals | Where-Object { $_.Component -eq 'web' })[0]
        if ($web -and $planned.ContainsKey('signin-schema') -and (Get-Command -Name Get-SISigninStoreStateSql -ErrorAction SilentlyContinue)) {
            $signin = ConvertFrom-SISigninStoreStateRow -Row (@(& $Sql $pro (Get-SISigninStoreStateSql) @{ ClientId = $web.ClientId; UserName = $web.Name } 'rows' | ForEach-Object { $_ }) | Select-Object -First 1)
        }
        $proc = $null
        if ($plan.Procedure) {
            $upd = @($in.Principals | Where-Object { $_.Component -eq 'updater' })[0]
            $un = if ($after[$pro].ContainsKey($upd.ClientId.ToLowerInvariant())) { $after[$pro][$upd.ClientId.ToLowerInvariant()].Name } else { $upd.Name }
            $proc = Test-SIGrantProcedureReady -State (ConvertFrom-SIGrantProcedureState -Row (@(& $Sql $pro (Get-SIGrantProcedureStateSql -UpdaterUser $un) @{} 'rows' | ForEach-Object { $_ }) | Select-Object -First 1)) -RequireUpdaterMember
        }
        $sg = @{}
        if ($in.Support -and $planned.ContainsKey('support-grant-schema') -and (Get-Command -Name Get-SISupportGrantStateSql -ErrorAction SilentlyContinue)) {
            foreach ($d in @($pro) + @($(if ($in.LedgerDatabase) { $in.LedgerDatabase }))) {
                $sg[$d] = ConvertFrom-SISupportGrantState -Row (@(& $Sql $d (Get-SISupportGrantStateSql -ClientId $in.Support.ClientId) @{} 'rows' | ForEach-Object { $_ }) | Select-Object -First 1)
            }
        }
        $expect = @(Get-SIDbInitExpectations -DbInput $in -Procedure ([bool]$plan.Procedure) -PlannedSteps $planned)
        $t = Test-SIDbInitReadBack -Expect $expect -Users $after -Signin $signin -Procedure $proc -SupportGrant $sg
        # #1021: each other product database, read back (only where the support grant is); the list recorded for the updater
        $engP = @($in.Principals | Where-Object { $_.Component -eq 'engine' })[0]; $updP = @($in.Principals | Where-Object { $_.Component -eq 'updater' })[0]
        $sgDbs = New-Object System.Collections.Generic.List[string]
        $more = New-Object System.Collections.Generic.List[string]
        foreach ($d in $others) {
            try {
                $st = Test-SIDbInitSupportDbState -Row (@(& $Sql $d (Get-SIDbInitSupportDbStateSql -EngineClientId $engP.ClientId -UpdaterClientId $(if ($updP) { $updP.ClientId } else { '' })) @{} 'rows' | ForEach-Object { $_ }) | Select-Object -First 1) -Updater ([bool]$updP)
                if (-not $st.Applies) { continue }
                $sgDbs.Add($d)
                if ($st.Problems.Count) { foreach ($x in $st.Problems) { $more.Add(('{0}: {1}' -f $d, $x)) } } else { & $say ('read back: {0}: the engine may run the support grant procedures; the updater may mirror the consent' -f $d) }
            } catch { $more.Add(('{0}: the support grant''s rights could not be read back ({1})' -f $d, $_.Exception.Message)) }
        }
        if ($mvRes -and @($mvRes.Problems).Count) { foreach ($x in $mvRes.Problems) { $more.Add(('identity move: {0}' -f $x)) } }
        if ($more.Count) { $t = [pscustomobject]@{ Ok = $false; Problems = @($t.Problems) + $more.ToArray(); Lines = $t.Lines; Count = $t.Count } }
        try { $null = & $Sql $pro (Get-SIDbInitDatabasesRecordSql) @{ Value = ($sgDbs.ToArray() -join ';') } 'nonquery' } catch { & $say ('WARNING: the list of the other product databases could not be recorded: {0}' -f $_.Exception.Message) }
        foreach ($l in $t.Lines) { & $say $l }
        foreach ($p in $t.Problems) { & $say ('NOT OK: {0}' -f $p) }
        if (-not $t.Ok) {
            $rec = & $writeRecord 'failed' $t.Count (($t.Problems | Select-Object -First 2) -join '; ')
            & $say 'verdict: FAILED -- see the lines above'
            return (& $res 1 'failed' $rec)
        }
        $rec = & $writeRecord 'ok' $t.Count ''
        & $say ('verdict: every identity read back ({0})' -f $t.Count)
        return (& $res 0 'ok' $rec)
    } catch {
        $why = [string]$_.Exception.Message
        & $say ('failed: {0}' -f $why)
        $rec = & $writeRecord 'failed' 0 $why
        return (& $res 1 'failed' $rec)
    }
}

# =====================================================================================================================
#  THE CALLERS' SIDE (the guided install, the updater, the support repair): the identity, the membership, the job, a run
# =====================================================================================================================

function Get-SIDbInitTemplateJob {
    <# PURE. The engine job whose environment, image and pull identity the database job takes: a job of the install that is
       not the updater, asset tagging, a one-time support job or this job itself, and that pulls its image with a
       user-assigned identity. Returns @{ Ok; Problem; Name; EnvironmentId; Location; Image; RegistryServer; PullIdentityId }. #>
    param([object[]]$Jobs = @())
    $n = Get-SIDbInitNames
    $cand = @($Jobs | Where-Object { $_ -and [string](Get-SIDbInitProp $_ @('name')) -notmatch '(?i)updater|tagging|supportsql|supportread|support-grant|dbinit|index-build' -and -not [string](Get-SIDbInitProp $_ @('tags', 'si-one-time-job')) -and [string](Get-SIDbInitProp $_ @('tags', $n.TagName)) -ne $n.TagValue })
    foreach ($j in $cand) {
        $c0 = @(Get-SIDbInitProp $j @('properties', 'template', 'containers'))[0]
        $img = [string](Get-SIDbInitProp $c0 @('image'))
        $reg = @(Get-SIDbInitProp $j @('properties', 'configuration', 'registries') | Where-Object { $_ })[0]
        $pull = [string](Get-SIDbInitProp $reg @('identity'))
        if (-not $img -or $img -notmatch '/si-orchestrator[:@]') { continue }
        if ($pull -notmatch '(?i)/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/') { continue }
        # the install's SI workspace, as the engine job names it (where the environment's console lines must go)
        $ws = @(@(Get-SIDbInitProp $c0 @('env')) | Where-Object { $_ -and [string](Get-SIDbInitProp $_ @('name')) -ieq 'SI_WorkspaceResourceId' } | ForEach-Object { ([string](Get-SIDbInitProp $_ @('value'))).Trim() } | Where-Object { $_ })[0]
        return [pscustomobject]@{ Ok = $true; Problem = ''; Name = [string](Get-SIDbInitProp $j @('name')); EnvironmentId = [string](Get-SIDbInitProp $j @('properties', 'environmentId'))
                                  Location = [string](Get-SIDbInitProp $j @('location')); Image = $img; RegistryServer = [string](Get-SIDbInitProp $reg @('server')); PullIdentityId = $pull
                                  WorkspaceResourceId = [string]$ws }
    }
    [pscustomobject]@{ Ok = $false; Problem = 'no engine job runs the SecurityInsight image with a managed identity for its registry -- the database job takes its image and environment from one' }
}

function Get-SIDbInitPrincipals {
    <#
        PURE. The product identities from the install's own Azure resources: -Identities (the resource group's user-assigned
        identities, ARM shape), -Jobs and -Apps (ARM shape). Engine = the identity whose client id the engine jobs carry
        (SI_UAMI_ClientId); web / MCP = the identity of the container app named -WebApp / -McpApp; updater = the identity of
        the job -UpdaterJob; asset tagging = the identity named -TaggingIdentity. One that is not there is left out.
        Returns the list for SI_DBINIT_PRINCIPALS (@{ component; name; clientId }).
    #>
    param([object[]]$Identities = @(), [object[]]$Jobs = @(), [object[]]$Apps = @(), [string[]]$WebApp = @('ca-si-management', 'ca-si-web'), [string[]]$McpApp = @('ca-si-mcp'),
          [string[]]$UpdaterJob = @('caj-si-updater'), [string[]]$TaggingIdentity = @('uami-securityinsight-tagging', 'id-si-tagging'), [string]$EngineClientId = '')
    $out = New-Object System.Collections.Generic.List[object]
    $byId = @{}; $byCid = @{}; $byName = @{}
    foreach ($m in @($Identities | Where-Object { $_ })) {
        $o = [pscustomobject]@{ Name = [string](Get-SIDbInitProp $m @('name')); ClientId = [string](Get-SIDbInitProp $m @('properties', 'clientId')); Id = ([string](Get-SIDbInitProp $m @('id'))).ToLowerInvariant() }
        if (-not $o.ClientId) { continue }
        $byId[$o.Id] = $o; $byCid[$o.ClientId.ToLowerInvariant()] = $o; $byName[$o.Name.ToLowerInvariant()] = $o
    }
    # The identity an app / job SIGNS IN AS: the attached identity whose client id its own containers' settings name
    # (Identity__ManagedIdentityClientId, AZURE_CLIENT_ID, SI_UPDATER_CLIENT_ID, ...). During an identity move the old
    # and the new identity are both attached until the clean-up -- the first attached one was the OLD one (live at the
    # internal install 2026-11-05). Only when no setting names one: the first attached identity, as before.
    $firstUa = { param($r) $ua = Get-SIDbInitProp $r @('identity', 'userAssignedIdentities'); if (-not $ua) { return $null }
        $keys = if ($ua -is [System.Collections.IDictionary]) { @($ua.Keys) } else { @($ua.PSObject.Properties | ForEach-Object { $_.Name }) }
        $att = @(foreach ($k in $keys) { $kk = ([string]$k).ToLowerInvariant(); if ($byId.ContainsKey($kk)) { $byId[$kk] } })
        foreach ($c in @(Get-SIDbInitProp $r @('properties', 'template', 'containers'))) {
            foreach ($e in @(Get-SIDbInitProp $c @('env'))) {
                $v = ([string](Get-SIDbInitProp $e @('value'))).Trim().ToLowerInvariant()
                if ($v -match '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$') { $hit = @($att | Where-Object { $_.ClientId.ToLowerInvariant() -eq $v })[0]; if ($hit) { return $hit } }
            }
        }
        @($att)[0] }
    $put = { param($c, $o) if ($o -and $o.ClientId -and -not @($out | Where-Object { $_.component -eq $c -or $_.clientId -eq $o.ClientId }).Count) { $out.Add([ordered]@{ component = $c; name = $o.Name; clientId = $o.ClientId }) } }
    $ecid = "$EngineClientId".Trim()
    if (-not $ecid) {
        foreach ($j in @($Jobs | Where-Object { $_ -and [string](Get-SIDbInitProp $_ @('name')) -notmatch '(?i)updater|tagging|dbinit' })) {
            foreach ($c in @(Get-SIDbInitProp $j @('properties', 'template', 'containers'))) {
                foreach ($e in @(Get-SIDbInitProp $c @('env'))) { if ([string](Get-SIDbInitProp $e @('name')) -eq 'SI_UAMI_ClientId') { $v = ([string](Get-SIDbInitProp $e @('value'))).Trim(); if ($v) { $ecid = $v; break } } }
                if ($ecid) { break }
            }
            if ($ecid) { break }
        }
    }
    if ($ecid -and $byCid.ContainsKey($ecid.ToLowerInvariant())) { & $put 'engine' $byCid[$ecid.ToLowerInvariant()] }
    $named = { param($list, $names) $l = @($names | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() }); @($list | Where-Object { $_ -and $l -contains ([string](Get-SIDbInitProp $_ @('name'))).ToLowerInvariant() })[0] }
    $u = & $named $Jobs $UpdaterJob; if ($u) { & $put 'updater' (& $firstUa $u) }
    $w = & $named $Apps $WebApp; if ($w) { & $put 'web' (& $firstUa $w) }
    $m2 = & $named $Apps $McpApp; if ($m2) { & $put 'mcp' (& $firstUa $m2) }
    foreach ($tn in @($TaggingIdentity | Where-Object { $_ })) { if ($byName.ContainsKey(([string]$tn).ToLowerInvariant())) { & $put 'tagging' $byName[([string]$tn).ToLowerInvariant()]; break } }
    $out.ToArray()
}

function Get-SIDbInitJobBody {
    <# PURE. caj-si-dbinit: manual trigger, one replica, no retry, 30 minutes, the engine image with the job's own entry
       point, its OWN identity (+ the pull identity of the engine jobs, for the image only), tagged; no secret. The
       execution-only inputs (the run id, who started it, the Support app) are given per start, never stored here. #>
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$EnvironmentId, [Parameter(Mandatory)][string]$Image,
          [Parameter(Mandatory)][string]$RegistryServer, [Parameter(Mandatory)][string]$PullIdentityId, [Parameter(Mandatory)][string]$IdentityId,
          [Parameter(Mandatory)][string]$IdentityClientId, [Parameter(Mandatory)][string]$Server, [string]$Database = 'sqldb-si-pro',
          [string]$LedgerDatabase = 'sqldb-si-identity', [object[]]$Principals = @(), [bool]$SignedGrants = $false, [bool]$EngineRoleOnly = $false)
    $n = Get-SIDbInitNames
    $ua = [ordered]@{}; $ua[$IdentityId] = [ordered]@{}
    if ($PullIdentityId.ToLowerInvariant() -ne $IdentityId.ToLowerInvariant()) { $ua[$PullIdentityId] = [ordered]@{} }
    $tags = [ordered]@{ product = 'securityinsight' }; $tags[$n.TagName] = $n.TagValue
    $env = @(
        [ordered]@{ name = 'SI_DBINIT_SERVER'; value = $Server }
        [ordered]@{ name = 'SI_DBINIT_DATABASE'; value = $Database }
        [ordered]@{ name = 'SI_DBINIT_LEDGER_DATABASE'; value = $LedgerDatabase }
        [ordered]@{ name = 'SI_DBINIT_MI_CLIENT_ID'; value = $IdentityClientId }
        [ordered]@{ name = 'SI_DBINIT_PRINCIPALS'; value = (ConvertTo-Json -InputObject @($Principals) -Compress -Depth 5) }
        [ordered]@{ name = 'SI_DBINIT_SIGNED_GRANTS'; value = $(if ($SignedGrants) { '1' } else { '0' }) }
        [ordered]@{ name = 'SI_DBINIT_ENGINE_ROLE_ONLY'; value = $(if ($EngineRoleOnly) { '1' } else { '0' }) }
    )
    [ordered]@{
        location = $Location; tags = $tags
        identity = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $ua }
        properties = [ordered]@{
            environmentId = $EnvironmentId
            configuration = [ordered]@{
                triggerType = 'Manual'; replicaTimeout = 1800; replicaRetryLimit = 0
                manualTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 }
                registries = @([ordered]@{ server = $RegistryServer; identity = $PullIdentityId })
            }
            template = [ordered]@{ containers = @([ordered]@{
                name = $n.Container; image = $Image; command = @('pwsh', '-NoProfile', '-NonInteractive', '-File', $n.Entry)
                resources = [ordered]@{ cpu = 0.5; memory = '1Gi' }; env = $env }) }
        }
    }
}

function Get-SIDbInitLogSettingBody {
    <# PURE. The environment's diagnostic setting si-environment-logs: console + system lines to the install's SI workspace
       (the same setting the container setup makes, #220 -- written out here so the job's callers need no other file). #>
    param([Parameter(Mandatory)][string]$WorkspaceResourceId)
    [ordered]@{ properties = [ordered]@{ workspaceId = $WorkspaceResourceId; logs = @(
        [ordered]@{ category = 'ContainerAppConsoleLogs'; enabled = $true },
        [ordered]@{ category = 'ContainerAppSystemLogs'; enabled = $true }) } }
}

function Test-SIDbInitEnvironmentLogs {
    <#
        PURE. Do the console lines of a job in -Environment (ARM shape) reach a Log Analytics workspace? 'log-analytics' =
        written there directly (its workspace named); 'azure-monitor' = only through a diagnostic setting of the environment
        (-Settings, ARM shape) that sends ContainerAppConsoleLogs (or allLogs) to a workspace. Any other destination (none,
        or not set) = the lines are in the portal's console view only. Returns @{ Ok; Destination; How }.
    #>
    param($Environment, [object[]]$Settings = @())
    $dest = [string](Get-SIDbInitProp $Environment @('properties', 'appLogsConfiguration', 'destination'))
    if ($dest -eq 'log-analytics') {
        $cid = [string](Get-SIDbInitProp $Environment @('properties', 'appLogsConfiguration', 'logAnalyticsConfiguration', 'customerId'))
        if ($cid) { return [pscustomobject]@{ Ok = $true; Destination = $dest; How = ('written directly to Log Analytics workspace {0}' -f $cid) } }
        return [pscustomobject]@{ Ok = $false; Destination = $dest; How = 'the environment names Log Analytics but no workspace' }
    }
    if ($dest -eq 'azure-monitor') {
        foreach ($s in @($Settings | Where-Object { $_ })) {
            $ws = [string](Get-SIDbInitProp $s @('properties', 'workspaceId'))
            if (-not $ws) { continue }
            $on = @(@(Get-SIDbInitProp $s @('properties', 'logs')) | Where-Object { $_ -and [string](Get-SIDbInitProp $_ @('enabled')) -match '^(?i)true$' -and
                    ([string](Get-SIDbInitProp $_ @('category')) -eq 'ContainerAppConsoleLogs' -or [string](Get-SIDbInitProp $_ @('categoryGroup')) -eq 'allLogs') })
            if ($on.Count) { return [pscustomobject]@{ Ok = $true; Destination = $dest; How = ('through the diagnostic setting {0} to {1}' -f [string](Get-SIDbInitProp $s @('name')), ($ws -split '/')[-1]) } }
        }
        return [pscustomobject]@{ Ok = $false; Destination = $dest; How = 'the environment sends its logs through Azure Monitor, but no diagnostic setting sends its console lines to a workspace' }
    }
    [pscustomobject]@{ Ok = $false; Destination = $dest; How = ('the environment sends its logs nowhere (destination {0})' -f $(if ($dest) { $dest } else { 'not set' })) }
}

function Set-SIDbInitEnvironmentLogs {
    <#
        The job's lines reach Log Analytics at EVERY install (found live 2026-11-05: a run wrote nothing to the workspace, so
        its failing line could not be read). Reads the environment the job runs in (-EnvironmentId: the engine jobs' one)
        and its diagnostic settings; an environment that logs through Azure Monitor without a setting for its console lines
        gets si-environment-logs to -WorkspaceResourceId (the install's SI workspace, as the engine jobs name it), READ BACK.
        Never throws and never stops the job (a warning only: the run's lines then stay in the portal's console view).
        Returns @{ Ok; Changed; Line }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [string]$EnvironmentId, [string]$WorkspaceResourceId)
    $api = '2021-05-01-preview'
    $res = { param($ok, $ch, $l) [pscustomobject]@{ Ok = [bool]$ok; Changed = [bool]$ch; Line = [string]$l } }
    if (-not "$EnvironmentId".Trim()) { return (& $res $false $false 'WARNING: the job''s environment is not known, so where its lines go was not checked') }
    $envName = ($EnvironmentId.TrimEnd('/') -split '/')[-1]
    try {
        $envObj = & $Arm 'GET' ('{0}?api-version={1}' -f $EnvironmentId.TrimEnd('/'), (Get-SIDbInitNames).AppApi) $null
        $readSettings = { @(Get-SIDbInitProp (& $Arm 'GET' ('{0}/providers/Microsoft.Insights/diagnosticSettings?api-version={1}' -f $EnvironmentId.TrimEnd('/'), $api) $null) @('value') | Where-Object { $_ }) }
        $set = if ([string](Get-SIDbInitProp $envObj @('properties', 'appLogsConfiguration', 'destination')) -eq 'azure-monitor') { & $readSettings } else { @() }
        $t = Test-SIDbInitEnvironmentLogs -Environment $envObj -Settings $set
        if ($t.Ok) { return (& $res $true $false ('the job''s lines reach Log Analytics: the environment {0} -- {1}' -f $envName, $t.How)) }
        if ($t.Destination -ne 'azure-monitor') { return (& $res $false $false ('WARNING: the job''s lines do not reach Log Analytics: {0} ({1}) -- they are in the portal''s console view of each run only' -f $t.How, $envName)) }
        if (-not "$WorkspaceResourceId".Trim()) { return (& $res $false $false ('WARNING: the job''s lines do not reach Log Analytics: {0} ({1}), and the engine jobs name no SI workspace to send them to' -f $t.How, $envName)) }
        $null = & $Arm 'PUT' ('{0}/providers/Microsoft.Insights/diagnosticSettings/si-environment-logs?api-version={1}' -f $EnvironmentId.TrimEnd('/'), $api) (Get-SIDbInitLogSettingBody -WorkspaceResourceId $WorkspaceResourceId.Trim())
        $t2 = Test-SIDbInitEnvironmentLogs -Environment $envObj -Settings (& $readSettings)
        if ($t2.Ok) { return (& $res $true $true ('the job''s lines now reach Log Analytics: the environment {0} -- {1} (made, read back)' -f $envName, $t2.How)) }
        & $res $false $true ('WARNING: the diagnostic setting si-environment-logs was sent for the environment {0}, but reading it back did not show the console lines going to a workspace' -f $envName)
    } catch {
        & $res $false $false ('WARNING: where the job''s lines go could not be checked or set ({0}) -- they are in the portal''s console view of each run' -f $_.Exception.Message)
    }
}

function Get-SIDbInitStartBody {
    <# PURE. The body of ONE start: the job's own container (name, image, command, resources) and ITS environment with -Env
       added or replacing a variable of the same name (an execution template REPLACES the environment, so everything is
       carried). #>
    param([Parameter(Mandatory)]$Job, [System.Collections.IDictionary]$Env = @{})
    $c = @(Get-SIDbInitProp $Job @('properties', 'template', 'containers'))[0]
    $vars = New-Object System.Collections.Generic.List[object]
    foreach ($e in @(Get-SIDbInitProp $c @('env'))) {
        if (-not $e) { continue }
        $nm = [string](Get-SIDbInitProp $e @('name'))
        if (-not $nm -or $Env.Contains($nm)) { continue }
        $vars.Add([ordered]@{ name = $nm; value = [string](Get-SIDbInitProp $e @('value')) })
    }
    foreach ($k in $Env.Keys) { $vars.Add([ordered]@{ name = [string]$k; value = [string]$Env[$k] }) }
    $o = [ordered]@{ name = [string](Get-SIDbInitProp $c @('name')); image = [string](Get-SIDbInitProp $c @('image')); env = $vars.ToArray() }
    $cmd = @(Get-SIDbInitProp $c @('command') | Where-Object { $null -ne $_ }); if ($cmd.Count) { $o.command = $cmd }
    $r = Get-SIDbInitProp $c @('resources')
    if ($r) { $o.resources = [ordered]@{ cpu = [double](Get-SIDbInitProp $r @('cpu')); memory = [string](Get-SIDbInitProp $r @('memory')) } }
    [ordered]@{ containers = @($o) }
}

function Test-SIDbInitMember {
    <# Is the identity's service principal (-PrincipalId) a member of -GroupId? Read from the IDENTITY's side (its memberOf):
       a group's /members list leaves service principals out for a caller without directory read rights (EPS 2.0.59, live at
       an install 2026-11-04). THROWS when the directory cannot be asked. #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$GroupId)
    $next = 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}/memberOf?$select=id' -f $PrincipalId
    for ($i = 0; $next -and $i -lt 20; $i++) {
        $page = & $Graph 'GET' $next $null
        foreach ($v in @(Get-SIDbInitProp $page @('value'))) { if ($v -and ([string](Get-SIDbInitProp $v @('id'))) -ieq $GroupId) { return $true } }
        $next = [string](Get-SIDbInitProp $page @('@odata.nextLink'))
    }
    $false
}

function Add-SIDbInitMember {
    <# The job's identity into the SQL admin group, READ BACK from the identity's side before anything starts the job (spec
       point 7). Idempotent. Returns @{ State = already | added | refused | unchecked | notfound; Detail }. Needs
       setup\_shared\SI-GroupMemberAdd.ps1 (the one add-and-wait policy). #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$GroupId,
          [scriptblock]$Sleep, [scriptblock]$Print, [int]$LimitSeconds = 300, [datetime]$NowUtc = [datetime]::UtcNow)
    try { if (Test-SIDbInitMember -Graph $Graph -PrincipalId $PrincipalId -GroupId $GroupId) { return [pscustomobject]@{ State = 'already'; Detail = ('{0} is a member of the SQL admin group (read from its memberOf)' -f (Get-SIDbInitNames).Identity) } } } catch { }
    $siDbGraph = $Graph; $siDbPid = $PrincipalId; $siDbGid = $GroupId
    $r = Invoke-SIGroupMemberAddRetry -What ((Get-SIDbInitNames).Identity) -Sleep $Sleep -Print $Print -LimitSeconds $LimitSeconds `
            -Add { $null = & $siDbGraph 'POST' ('https://graph.microsoft.com/v1.0/groups/{0}/members/$ref' -f $siDbGid) @{ '@odata.id' = ('https://graph.microsoft.com/v1.0/directoryObjects/{0}' -f $siDbPid) } } `
            -Test { Test-SIDbInitMember -Graph $siDbGraph -PrincipalId $siDbPid -GroupId $siDbGid }
    if ([string]$r.State -ne 'refused') { return [pscustomobject]@{ State = [string]$r.State; Detail = [string]$r.Detail } }
    # 2026-11-05 (owner: "why is this not in setup"): a direct add refused (the caller may not change the group's members) --
    # an ACTIVE PIM-for-Groups member assignment instead, the route the framework already accepts as membership. Permanent
    # when the group's PIM policy allows it, else the longest the policy gives (180 days; said, so the renewal is known).
    $pim = Add-SIDbInitPimMember -Graph $Graph -PrincipalId $PrincipalId -GroupId $GroupId -Sleep $Sleep -Print $Print -LimitSeconds $LimitSeconds -NowUtc $NowUtc
    if ($pim.State -eq 'added') { return $pim }
    [pscustomobject]@{ State = 'refused'; Detail = ('{0}; the PIM-for-Groups assignment was refused too: {1}' -f [string]$r.Detail, [string]$pim.Detail) }
}

function Get-SIDbInitPimMemberBody {
    <# PURE. The ACTIVE PIM-for-Groups member assignment of -PrincipalId to -GroupId. -Days 0 = permanent (noExpiration).
       -Action: adminAssign (a new one), adminExtend (an active one that ends soon), adminUpdate (its schedule changed),
       adminRenew (one that has ended) -- Microsoft Graph's privilegedAccessGroupAssignmentScheduleRequest actions. #>
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$GroupId, [int]$Days = 0, [datetime]$Now = [datetime]::UtcNow,
          [ValidateSet('adminAssign', 'adminExtend', 'adminUpdate', 'adminRenew')][string]$Action = 'adminAssign')
    $exp = if ($Days -gt 0) { [ordered]@{ type = 'afterDuration'; duration = ('P{0}D' -f $Days) } } else { [ordered]@{ type = 'noExpiration' } }
    [ordered]@{
        accessId      = 'member'
        principalId   = $PrincipalId
        groupId       = $GroupId
        action        = $Action
        justification = 'SecurityInsight database setup job: member of the SQL server''s admin group (no person needs database admin rights)'
        scheduleInfo  = [ordered]@{ startDateTime = $Now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); expiration = $exp }
    }
}

function ConvertFrom-SIDbInitIsoDays {
    <# PURE. An ISO 8601 duration (P180D, P1Y, PT8H) as whole days; 0 when it is not one. #>
    param($Value)
    if (-not "$Value".Trim()) { return 0 }
    try { [int][Math]::Floor(([System.Xml.XmlConvert]::ToTimeSpan("$Value".Trim())).TotalDays) } catch { 0 }
}

function ConvertTo-SIDbInitUtc {
    <# PURE. A Graph time (text, or the DateTime ConvertFrom-Json made of it) as a UTC DateTime; $null when it is none. #>
    param($Value)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq 'Unspecified') { return [datetime]::SpecifyKind($Value, 'Utc') }; return $Value.ToUniversalTime() }
    try { [datetime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { $null }
}

function Get-SIDbInitPimPolicyLimit {
    <#
        Framework §4.5 SQL-ADMIN-GROUP G3: what the group's PIM policy allows for an ACTIVE member assignment made by an admin
        (its rule Expiration_Admin_Assignment): @{ Known; Permanent; Days; Detail }. Read with RoleManagementPolicy.Read.AzureADGroup
        (the updater's) or a person's sign-in. Never throws: a policy that cannot be read is Known = $false (then permanent is
        tried first and 180 days after it, as before).
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$GroupId)
    $no = [pscustomobject]@{ Known = $false; Permanent = $false; Days = 0; Detail = 'the group''s PIM policy could not be read' }
    try {
        $uri = ("https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '{0}' and scopeType eq 'Group' and roleDefinitionId eq 'member'&`$expand=policy(`$expand=rules)" -f $GroupId)
        $r = & $Graph 'GET' $uri $null
        $a = @(Get-SIDbInitProp $r @('value') | Where-Object { $_ })[0]
        $rule = @(Get-SIDbInitProp $a @('policy', 'rules') | Where-Object { $_ -and [string](Get-SIDbInitProp $_ @('id')) -eq 'Expiration_Admin_Assignment' })[0]
        if (-not $rule) { return $no }
        $req = [bool](Get-SIDbInitProp $rule @('isExpirationRequired'))
        $days = ConvertFrom-SIDbInitIsoDays (Get-SIDbInitProp $rule @('maximumDuration'))
        if ($req -and $days -le 0) { return $no }
        [pscustomobject]@{ Known = $true; Permanent = (-not $req); Days = $days
                           Detail = $(if (-not $req) { 'the group''s PIM policy allows a permanent active assignment' } else { 'the group''s PIM policy allows an active assignment of at most {0} days' -f $days }) }
    } catch { $no }
}

function Get-SIDbInitPimAssignment {
    <#
        Framework §4.5 SQL-ADMIN-GROUP G4: the identity's ACTIVE PIM-for-Groups member assignment to the group, read from
        /identityGovernance/privilegedAccess/group/assignmentScheduleInstances (PrivilegedAssignmentSchedule.Read.AzureADGroup).
        Returns @{ Found; Permanent; End (UTC, $null = permanent); Start; MemberType; AssignmentType } -- the one that lasts
        longest when there are several. THROWS when the directory cannot be asked.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$GroupId)
    $uri = ("https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '{0}' and principalId eq '{1}'" -f $GroupId, $PrincipalId)
    $r = & $Graph 'GET' $uri $null
    $best = $null
    foreach ($i in @(Get-SIDbInitProp $r @('value') | Where-Object { $_ })) {
        if ([string](Get-SIDbInitProp $i @('accessId')) -ne 'member') { continue }
        $end = ConvertTo-SIDbInitUtc (Get-SIDbInitProp $i @('endDateTime'))
        $o = [pscustomobject]@{ Found = $true; Permanent = ($null -eq $end); End = $end; Start = (ConvertTo-SIDbInitUtc (Get-SIDbInitProp $i @('startDateTime')))
                                MemberType = [string](Get-SIDbInitProp $i @('memberType')); AssignmentType = [string](Get-SIDbInitProp $i @('assignmentType')) }
        if (-not $best -or $o.Permanent -or (-not $best.Permanent -and $o.End -gt $best.End)) { $best = $o }
        if ($best.Permanent) { break }
    }
    if ($best) { return $best }
    [pscustomobject]@{ Found = $false; Permanent = $false; End = $null; Start = $null; MemberType = ''; AssignmentType = '' }
}

function Test-SIDbInitMembership {
    <#
        Is the job's identity a member of the SQL admin group? Asked two ways, so that an identity without directory read
        rights (the updater: framework §4.5 G5 gives it only the PIM-for-Groups rights) still gets an answer:
          * the identity's own memberOf (Test-SIDbInitMember), and
          * its ACTIVE PIM-for-Groups assignment (Get-SIDbInitPimAssignment) -- an active assignment is a membership.
        Returns @{ Member = $true | $false | $null (neither could be asked, or memberOf could not and there is no PIM
        assignment: a direct membership is then not known); Via = memberOf | pim | ''; Pim (the assignment or $null);
        MemberOfError; PimError }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$GroupId, [datetime]$NowUtc = [datetime]::UtcNow)
    $mo = $null; $moErr = ''
    try { $mo = [bool](Test-SIDbInitMember -Graph $Graph -PrincipalId $PrincipalId -GroupId $GroupId) } catch { $moErr = [string]$_.Exception.Message }
    $pa = $null; $paErr = ''
    try { $pa = Get-SIDbInitPimAssignment -Graph $Graph -PrincipalId $PrincipalId -GroupId $GroupId } catch { $paErr = [string]$_.Exception.Message }
    $active = [bool]($pa -and $pa.Found -and ($pa.Permanent -or ($pa.End -and $pa.End -gt $NowUtc.ToUniversalTime())))
    $member = if ($mo -eq $true -or $active) { $true } elseif ($mo -eq $false) { $false } else { $null }
    [pscustomobject]@{ Member = $member; Via = $(if ($mo -eq $true) { 'memberOf' } elseif ($active) { 'pim' } else { '' }); Pim = $pa; MemberOfError = $moErr; PimError = $paErr }
}

function Add-SIDbInitPimMember {
    <# The active PIM-for-Groups assignment, then READ BACK (the identity's memberOf, or its active PIM assignment: an active
       assignment is a membership). Framework §4.5 G3: permanent first -- when the group's PIM policy says it is not allowed,
       the policy's own limit at once (unknown policy: permanent, then 180 days); the end date is SAID. An assignment
       already there counts as made. Returns @{ State = added | refused; Detail; End }. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$GroupId,
          [scriptblock]$Sleep, [scriptblock]$Print, [int]$LimitSeconds = 300, [datetime]$NowUtc = [datetime]::UtcNow)
    $uri = 'https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests'
    $lim = Get-SIDbInitPimPolicyLimit -Graph $Graph -GroupId $GroupId
    $limDays = if ($lim.Known -and $lim.Days -gt 0) { $lim.Days } else { 180 }
    $tries = if ($lim.Known -and -not $lim.Permanent) { @($limDays) } else { @(0, $limDays) }
    $made = ''; $err = ''; $end = $null
    foreach ($days in $tries) {
        try {
            $null = & $Graph 'POST' $uri (Get-SIDbInitPimMemberBody -PrincipalId $PrincipalId -GroupId $GroupId -Days $days -Now $NowUtc)
            if ($days) { $end = $NowUtc.ToUniversalTime().AddDays($days); $made = ('for {0} days, until {1:yyyy-MM-dd} -- {2}' -f $days, $end, $(if ($lim.Known) { $lim.Detail } else { 'a permanent one was refused' })) } else { $made = 'permanent' }
            break
        }
        catch {
            $m = [string]$_.Exception.Message
            if ($m -match 'RoleAssignmentExists|already exists') { $made = 'already assigned'; break }
            $err = $m
            if ($m -notmatch 'Expiration|PolicyValidation|ExpirationRule|noExpiration|permanent') { break }   # not a policy limit: no second try
        }
    }
    if (-not $made) { return [pscustomobject]@{ State = 'refused'; Detail = $err; End = $null } }
    if ($Print) { & $Print ('   PIM-for-Groups: {0} assigned to the SQL admin group as an active member ({1}); waiting until it reads back' -f (Get-SIDbInitNames).Identity, $made) }
    $waited = 0
    while ($true) {
        $mm = Test-SIDbInitMembership -Graph $Graph -PrincipalId $PrincipalId -GroupId $GroupId -NowUtc $NowUtc
        if ($mm.Member -eq $true) {
            if ($mm.Pim -and $mm.Pim.Found -and -not $mm.Pim.Permanent) { $end = $mm.Pim.End }
            return [pscustomobject]@{ State = 'added'; End = $end; Detail = ('{0} is an active PIM-for-Groups member of the SQL admin group ({1}), read back from its {2}' -f (Get-SIDbInitNames).Identity, $made, $(if ($mm.Via -eq 'pim') { 'PIM assignment' } else { 'memberOf' })) }
        }
        if ($waited -ge $LimitSeconds) { return [pscustomobject]@{ State = 'refused'; End = $null; Detail = ('the PIM-for-Groups assignment was made ({0}) but the membership did not show within {1} s -- run again later' -f $made, $LimitSeconds) } }
        if ($Sleep) { & $Sleep 15 }; $waited += 15
    }
}

function Get-SIDbInitPimRenewPlan {
    <# PURE. Framework §4.5 G4: does the membership need a renewal? -Assignment: Get-SIDbInitPimAssignment. Action = none (no
       PIM assignment -- a direct member -- or a permanent one) | current (it ends after the window) | renew (it is still
       valid and ends within -WindowDays) | expired (it has ended). Returns @{ Action; End; DaysLeft; Detail }. #>
    param($Assignment, [datetime]$NowUtc = [datetime]::UtcNow, [int]$WindowDays = 30)
    $now = $NowUtc.ToUniversalTime()
    if (-not $Assignment -or -not $Assignment.Found) { return [pscustomobject]@{ Action = 'none'; End = $null; DaysLeft = $null; Detail = 'no PIM-for-Groups assignment (a direct member)' } }
    if ($Assignment.Permanent -or -not $Assignment.End) { return [pscustomobject]@{ Action = 'none'; End = $null; DaysLeft = $null; Detail = 'a permanent PIM-for-Groups assignment' } }
    $left = [Math]::Round(($Assignment.End - $now).TotalDays, 1)
    $endText = $Assignment.End.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    if ($left -le 0) { return [pscustomobject]@{ Action = 'expired'; End = $Assignment.End; DaysLeft = $left; Detail = ('the PIM-for-Groups assignment ended {0}' -f $endText) } }
    if ($left -le $WindowDays) { return [pscustomobject]@{ Action = 'renew'; End = $Assignment.End; DaysLeft = $left; Detail = ('the PIM-for-Groups assignment ends {0} (in {1} days)' -f $endText, $left) } }
    [pscustomobject]@{ Action = 'current'; End = $Assignment.End; DaysLeft = $left; Detail = ('the PIM-for-Groups assignment ends {0} (in {1} days)' -f $endText, $left) }
}

function Invoke-SIDbInitPimRenew {
    <#
        Framework §4.5 G4: the active PIM-for-Groups assignment RENEWED -- adminExtend (Graph's action for an assignment that
        is about to end), else adminUpdate (its schedule set again); for one that has ended adminRenew, else a new
        adminAssign. The new end follows the group's policy (permanent when allowed, else its limit; 180 days when the
        policy cannot be read). READ BACK: the assignment must end later than before (or be permanent). Returns @{ Ok; Action;
        End; Detail }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$GroupId,
          $Assignment, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$Expired, [scriptblock]$Sleep, [int[]]$ReadBackWaits = @(5, 15, 30))
    $uri = 'https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests'
    $lim = Get-SIDbInitPimPolicyLimit -Graph $Graph -GroupId $GroupId
    $days = if ($lim.Known -and $lim.Permanent) { 0 } elseif ($lim.Known -and $lim.Days -gt 0) { $lim.Days } else { 180 }
    $actions = if ($Expired) { @('adminRenew', 'adminAssign') } else { @('adminExtend', 'adminUpdate') }
    $errs = New-Object System.Collections.Generic.List[string]
    $done = ''
    foreach ($a in $actions) {
        try { $null = & $Graph 'POST' $uri (Get-SIDbInitPimMemberBody -PrincipalId $PrincipalId -GroupId $GroupId -Days $days -Now $NowUtc -Action $a); $done = $a; break }
        catch { $errs.Add(('{0}: {1}' -f $a, [string]$_.Exception.Message)) }
    }
    if (-not $done) { return [pscustomobject]@{ Ok = $false; Action = ''; End = $(if ($Assignment) { $Assignment.End } else { $null }); Detail = ('the renewal was refused ({0})' -f ($errs -join '; ')) } }
    $before = if ($Assignment -and $Assignment.End) { $Assignment.End } else { [datetime]::MinValue }
    $last = ''
    foreach ($w in @(0) + @($ReadBackWaits)) {
        if ($w -gt 0 -and $Sleep) { & $Sleep $w }
        try {
            $after = Get-SIDbInitPimAssignment -Graph $Graph -PrincipalId $PrincipalId -GroupId $GroupId
            if ($after.Found -and ($after.Permanent -or ($after.End -and $after.End -gt $before))) {
                return [pscustomobject]@{ Ok = $true; Action = $done; End = $after.End
                                          Detail = ('renewed ({0}): the PIM-for-Groups assignment now {1}, read back' -f $done, $(if ($after.Permanent) { 'is permanent' } else { 'ends ' + $after.End.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) })) }
            }
        } catch { $last = [string]$_.Exception.Message }
    }
    [pscustomobject]@{ Ok = $false; Action = $done; End = $(if ($Assignment) { $Assignment.End } else { $null }); Detail = ('the renewal ({0}) was accepted, but the assignment does not read back with a later end{1}' -f $done, $(if ($last) { ' (' + $last + ')' } else { '' })) }
}

function Sync-SIDbInitMembership {
    <#
        Framework §4.5 SQL-ADMIN-GROUP G2-G4 -- THE ONE PATH setup (the guided install, setup\Start-SIDbInitJob.ps1) and the
        updater use for the job identity's membership of the SQL admin group:
          1. READ it (Test-SIDbInitMembership: memberOf, or an active PIM-for-Groups assignment);
          2. not a member -> CONVERGED (Add-SIDbInitMember: direct members/$ref, else an active PIM-for-Groups assignment,
             permanent first, else the policy's limit with the end date said), read back;
          3. a member through a PIM assignment that ends within -WindowDays (30) -> RENEWED (Invoke-SIDbInitPimRenew), read
             back. A renewal that fails while the assignment is still valid is Renewal.State 'failed' -- the CALLER says it as a
             warning; it never stops anything on its own.
        Returns @{ State = already | added | refused; Member ($true | $false | $null); JustAdded; Via; End; Renewal @{ State =
        none | current | renewed | failed | unknown; End; Detail }; Detail }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$GroupId,
          [scriptblock]$Sleep, [scriptblock]$Print, [int]$LimitSeconds = 300, [int]$WindowDays = -1, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($WindowDays -lt 0) { $WindowDays = (Get-SIDbInitNames).RenewWindowDays }
    $id = (Get-SIDbInitNames).Identity
    $ren = { param($st, $end, $d) [pscustomobject]@{ State = $st; End = $end; Detail = [string]$d } }
    try {
        $m = Test-SIDbInitMembership -Graph $Graph -PrincipalId $PrincipalId -GroupId $GroupId -NowUtc $NowUtc
        $state = 'already'; $just = $false; $detail = ''
        if ($m.Member -ne $true) {
            $a = Add-SIDbInitMember -Graph $Graph -PrincipalId $PrincipalId -GroupId $GroupId -Sleep $Sleep -Print $Print -LimitSeconds $LimitSeconds -NowUtc $NowUtc
            if ([string]$a.State -notin 'already', 'added') {
                return [pscustomobject]@{ State = 'refused'; Member = $m.Member; JustAdded = $false; Via = ''; End = $null; Renewal = (& $ren 'unknown' $null 'not a member'); Detail = [string]$a.Detail }
            }
            $state = [string]$a.State; $just = ($state -eq 'added'); $detail = [string]$a.Detail
            $m2 = Test-SIDbInitMembership -Graph $Graph -PrincipalId $PrincipalId -GroupId $GroupId -NowUtc $NowUtc
            if ($m2.Member -eq $true) { $m = $m2 } else { $m = [pscustomobject]@{ Member = $true; Via = 'added'; Pim = $m2.Pim; MemberOfError = $m2.MemberOfError; PimError = $m2.PimError } }
        } else {
            $detail = '{0} is a member of the SQL admin group (read from its {1})' -f $id, $(if ($m.Via -eq 'pim') { 'active PIM-for-Groups assignment' } else { 'memberOf' })
        }
        # 3. the renewal (only a PIM assignment ends; a direct or permanent membership needs none)
        $plan = Get-SIDbInitPimRenewPlan -Assignment $m.Pim -NowUtc $NowUtc -WindowDays $WindowDays
        $r = switch ($plan.Action) {
            'renew' {
                $x = Invoke-SIDbInitPimRenew -Graph $Graph -PrincipalId $PrincipalId -GroupId $GroupId -Assignment $m.Pim -NowUtc $NowUtc -Sleep $Sleep
                & $ren $(if ($x.Ok) { 'renewed' } else { 'failed' }) $x.End ('{0}; {1}' -f $plan.Detail, $x.Detail)
            }
            'expired' {
                # memberOf still shows it (replication) but the assignment has ended: renewed as one that has ended
                $x = Invoke-SIDbInitPimRenew -Graph $Graph -PrincipalId $PrincipalId -GroupId $GroupId -Assignment $m.Pim -NowUtc $NowUtc -Sleep $Sleep -Expired
                & $ren $(if ($x.Ok) { 'renewed' } else { 'failed' }) $x.End ('{0}; {1}' -f $plan.Detail, $x.Detail)
            }
            'current' { & $ren 'current' $plan.End $plan.Detail }
            default   { & $ren $(if ($m.PimError -and -not $m.Pim) { 'unknown' } else { 'none' }) $null $(if ($m.PimError -and -not $m.Pim) { 'its PIM-for-Groups assignment could not be read: ' + $m.PimError } else { $plan.Detail }) }
        }
        [pscustomobject]@{ State = $state; Member = $true; JustAdded = $just; Via = [string]$m.Via; End = $r.End; Renewal = $r; Detail = $detail }
    } catch {
        [pscustomobject]@{ State = 'refused'; Member = $null; JustAdded = $false; Via = ''; End = $null; Renewal = (& $ren 'unknown' $null ''); Detail = ('the membership could not be checked: {0}' -f $_.Exception.Message) }
    }
}

function New-SIDbInitMembershipRecordValue {
    <# PURE. The membership's own row (cfg.InstallState 'DbJobMembership', <= 400 characters): { state ok | renewal-failed |
       gone | missing, at, end?, via?, why? } -- the heartbeat's setup step db-job reads it (Get-SISetupSteps). #>
    param([Parameter(Mandatory)][ValidateSet('ok', 'renewal-failed', 'gone', 'missing')][string]$State, $End = $null, [string]$Via = '', [string]$Why = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $o = [ordered]@{ state = $State; at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $inv) }
    if ($End -is [datetime]) { $o.end = $End.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $inv) }
    if ($Via) { $o.via = $Via }
    $w = [regex]::Replace([regex]::Replace("$Why", '[\x00-\x1F]', ' '), '\s+', ' ').Trim()
    if ($w.Length -gt 250) { $w = $w.Substring(0, 247).TrimEnd() + '...' }
    if ($w) { $o.why = $w }
    $v = ConvertTo-Json -InputObject $o -Compress
    while ($v.Length -gt (Get-SIDbInitNames).RecordMax -and $w.Length -gt 10) { $w = $w.Substring(0, $w.Length - 20).TrimEnd() + '...'; $o.why = $w; $v = ConvertTo-Json -InputObject $o -Compress }
    $v
}

# ---------------------------------------------------------------------------------------------------------------------
#  Framework §4.5 SQL-ADMIN-GROUP G5: the UPDATER identity's Microsoft Graph application permissions -- exactly the three
#  PIM-for-Groups rights, granted by SETUP (the person or app running it holds the right to grant application permissions)
#  and only CHECKED by the updater (it cannot grant itself). The directory-wide role-management write right is refused by
#  name (least privilege, decided): it is never asked for, never granted here.
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDbInitGraphAppId { <# PURE. Microsoft Graph's application id (the same in every tenant). #> '00000003-0000-0000-c000-000000000000' }

function Get-SIDbInitUpdaterGraphRoleNames {
    <# PURE. G5: the updater identity's Microsoft Graph application permissions, by VALUE (their ids are read from Graph's own
       service principal at run time -- never written here). Required = $false: taken only when Graph has it. #>
    @(
        [pscustomobject]@{ Value = 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup'; Required = $true;  Why = 'make and renew the database setup job identity''s active PIM-for-Groups membership' }
        [pscustomobject]@{ Value = 'PrivilegedAssignmentSchedule.Read.AzureADGroup';      Required = $false; Why = 'read that membership and its end date' }
        [pscustomobject]@{ Value = 'RoleManagementPolicy.Read.AzureADGroup';              Required = $true;  Why = 'read the group''s PIM policy (permanent, or its longest duration)' }
        # framework §4.5 G5 (added 2026-11-05): read only -- without it the read-back of the membership (the identity's
        # memberOf) is refused and reads "unknown"
        [pscustomobject]@{ Value = 'GroupMember.Read.All';                                Required = $true;  Why = 'read the membership back (the identity''s memberOf)' }
        # framework §4.5 G5 (added 2026-11-05): read only -- servicePrincipals/{id}/memberOf (the member side of the read-back)
        # needs it on top of GroupMember.Read.All
        [pscustomobject]@{ Value = 'Application.Read.All';                                Required = $true;  Why = 'read the identity''s own memberOf back (the member side)' }
    )
}

function Get-SIDbInitRefusedGraphRoleNames {
    <# PURE. G5 (decided, least privilege): application permissions the updater identity is NEVER given by SecurityInsight. #>
    @('RoleManagement.ReadWrite.Directory')
}

function Resolve-SIDbInitUpdaterGraphRoles {
    <# PURE. -GraphSp: Microsoft Graph's service principal with its appRoles. Each G5 permission with its id found BY VALUE
       among the roles an application may hold (allowedMemberTypes Application) -- @{ Value; Id; Required; Found; Why }.
       -Roles: a subset of the G5 list (a test seam); anything outside it -- above all a refused one -- THROWS. #>
    param([Parameter(Mandatory)]$GraphSp, [string[]]$Roles = @())
    $all = @(Get-SIDbInitUpdaterGraphRoleNames)
    $want = if (@($Roles | Where-Object { $_ }).Count) {
        foreach ($r in $Roles) {
            if ((Get-SIDbInitRefusedGraphRoleNames) -contains $r) { throw ("'{0}' is never given to the updater identity (least privilege: only the PIM-for-Groups permissions)" -f $r) }
            if (-not @($all | Where-Object { $_.Value -eq $r }).Count) { throw ("'{0}' is not one of the updater identity's Microsoft Graph permissions" -f $r) }
        }
        @($all | Where-Object { $Roles -contains $_.Value })
    } else { $all }
    $appRoles = @(Get-SIDbInitProp $GraphSp @('appRoles') | Where-Object { $_ })
    foreach ($w in $want) {
        $hit = @($appRoles | Where-Object { [string](Get-SIDbInitProp $_ @('value')) -ceq $w.Value -and @(Get-SIDbInitProp $_ @('allowedMemberTypes')) -contains 'Application' })[0]
        [pscustomobject]@{ Value = $w.Value; Id = $(if ($hit) { [string](Get-SIDbInitProp $hit @('id')) } else { '' }); Required = [bool]$w.Required; Found = [bool]$hit; Why = $w.Why }
    }
}

function Get-SIDbInitHeldAppRoleIds {
    <# The appRoleIds -PrincipalId holds on -ResourceId (its appRoleAssignments, every page). THROWS when they cannot be read. #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$ResourceId)
    $out = New-Object System.Collections.Generic.List[string]
    $next = 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments' -f $PrincipalId
    for ($i = 0; $next -and $i -lt 20; $i++) {
        $page = & $Graph 'GET' $next $null
        foreach ($a in @(Get-SIDbInitProp $page @('value') | Where-Object { $_ })) {
            if ([string](Get-SIDbInitProp $a @('resourceId')) -eq $ResourceId) { $out.Add(([string](Get-SIDbInitProp $a @('appRoleId'))).ToLowerInvariant()) }
        }
        $next = [string](Get-SIDbInitProp $page @('@odata.nextLink'))
    }
    $out.ToArray()   # enumerated: wrap the call in @( )
}

function Grant-SIDbInitUpdaterGraphRoles {
    <#
        SETUP (the guided install's step db-job, setup\Start-SIDbInitJob.ps1): the updater identity (-PrincipalId, its service
        principal's object id) given the G5 Microsoft Graph application permissions -- ids resolved from Graph's own service
        principal by value, only what is missing granted (POST servicePrincipals/{id}/appRoleAssignments), every one READ
        BACK. A "not found" on an identity made minutes ago is tried again (-NotYetWaits). Returns @{ Ok; Granted; Present;
        Missing; Lines; Detail }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$PrincipalId, [string[]]$Roles = @(),
          [scriptblock]$Sleep, [int[]]$NotYetWaits = @(10, 20, 30, 45, 60))
    $lines = New-Object System.Collections.Generic.List[string]
    $granted = New-Object System.Collections.Generic.List[string]; $present = New-Object System.Collections.Generic.List[string]; $missing = New-Object System.Collections.Generic.List[string]
    $out = { param($ok, $d) [pscustomobject]@{ Ok = [bool]$ok; Granted = $granted.ToArray(); Present = $present.ToArray(); Missing = $missing.ToArray(); Lines = $lines.ToArray(); Detail = [string]$d } }
    try {
        $sp = @(Get-SIDbInitProp (& $Graph 'GET' ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,appId,appRoles" -f (Get-SIDbInitGraphAppId)) $null) @('value') | Where-Object { $_ })[0]
        if (-not $sp -or -not [string](Get-SIDbInitProp $sp @('id'))) { return (& $out $false 'Microsoft Graph''s service principal was not found in this tenant') }
        $want = @(Resolve-SIDbInitUpdaterGraphRoles -GraphSp $sp -Roles $Roles)
        foreach ($w in @($want | Where-Object { -not $_.Found })) {
            if ($w.Required) { $missing.Add($w.Value); $lines.Add(('Microsoft Graph has no application permission {0} -- it cannot be granted' -f $w.Value)) }
            else { $lines.Add(('Microsoft Graph has no separate application permission {0} -- not needed (the read-write one reads too)' -f $w.Value)) }
        }
        $want = @($want | Where-Object { $_.Found })
        foreach ($w in $want) { if ((Get-SIDbInitRefusedGraphRoleNames) -contains $w.Value) { throw ('{0} is never granted to the updater identity' -f $w.Value) } }
        $spId = [string](Get-SIDbInitProp $sp @('id'))
        $held = @(Get-SIDbInitHeldAppRoleIds -Graph $Graph -PrincipalId $PrincipalId -ResourceId $spId)
        foreach ($w in $want) {
            if ($held -contains $w.Id.ToLowerInvariant()) { $present.Add($w.Value); continue }
            $tries = 0; $done = $false; $why = ''
            while (-not $done) {
                try {
                    $null = & $Graph 'POST' ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments' -f $PrincipalId) ([ordered]@{ principalId = $PrincipalId; resourceId = $spId; appRoleId = $w.Id })
                    $done = $true; $granted.Add($w.Value)
                } catch {
                    $why = [string]$_.Exception.Message
                    if ($why -match '(?i)already exist') { $done = $true; $present.Add($w.Value); break }
                    $notYet = ($why -match '(?i)\b404\b|Request_ResourceNotFound|does not exist|not found') -and ($why -notmatch '(?i)\b403\b|Authorization_RequestDenied|Insufficient privileges|Forbidden')
                    if (-not $notYet -or $tries -ge @($NotYetWaits).Count) { break }
                    if ($Sleep) { & $Sleep ([int]$NotYetWaits[$tries]) }; $tries++
                }
            }
            if (-not $done) { $missing.Add($w.Value); $lines.Add(('{0}: not granted ({1})' -f $w.Value, $why)) }
        }
        # READ BACK: what the directory HAS, not the requests it accepted
        if ($granted.Count) {
            $back = @(Get-SIDbInitHeldAppRoleIds -Graph $Graph -PrincipalId $PrincipalId -ResourceId $spId)
            foreach ($w in @($want | Where-Object { $granted -contains $_.Value })) {
                if ($back -notcontains $w.Id.ToLowerInvariant()) { $missing.Add($w.Value); $lines.Add(('{0}: granted, but it does not read back' -f $w.Value)) }
            }
        }
        $ok = ($missing.Count -eq 0)
        $d = if ($ok) { 'the updater identity holds the Microsoft Graph application permissions {0} (read back{1})' -f ((@($want | ForEach-Object Value)) -join ', '), $(if ($granted.Count) { '; granted now: ' + ($granted -join ', ') } else { '' }) }
             else { 'the updater identity does not hold {0} -- an Entra administrator grants them (Privileged Role Administrator, or the right to grant application permissions); then run setup again' -f ($missing -join ', ') }
        & $out $ok $d
    } catch {
        $missing.Add('(not read)')
        & $out $false ('the updater identity''s Microsoft Graph permissions could not be read or granted: {0}' -f $_.Exception.Message)
    }
}

function Get-SIDbInitTokenRoles {
    <# PURE. The application permissions (roles claim) and object id (oid) in an access token -- what the token's holder may do,
       read without any directory right. $null when it is not a token. #>
    param([AllowEmptyString()][string]$Token)
    $p = ("$Token" -split '\.')
    if ($p.Count -lt 2 -or -not $p[1]) { return $null }
    $s = $p[1].Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    $o = $null
    try { $o = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    [pscustomobject]@{ Roles = @(@(Get-SIDbInitProp $o @('roles')) | Where-Object { $_ } | ForEach-Object { [string]$_ }); ObjectId = [string](Get-SIDbInitProp $o @('oid')) }
}

function Test-SIDbInitUpdaterGraphRoles {
    <# PURE. G5, the UPDATER's side: the permissions its own Graph token carries (-Held, the roles claim) against the G5 list.
       Missing = a required one it does not hold. A refused one it holds is said too (more than it needs). Returns @{ Ok;
       Missing; Extra; Lines }. The updater cannot grant itself: every line names who grants it. #>
    param([AllowNull()][string[]]$Held)
    $h = @($Held | Where-Object { $_ })
    $missing = @(Get-SIDbInitUpdaterGraphRoleNames | Where-Object { $_.Required -and $h -notcontains $_.Value } | ForEach-Object Value)
    $extra = @(Get-SIDbInitRefusedGraphRoleNames | Where-Object { $h -contains $_ })
    $lines = New-Object System.Collections.Generic.List[string]
    if ($missing.Count) { $lines.Add(('WARNING: the updater identity does not hold the Microsoft Graph application permission(s) {0}, so it cannot keep the database setup job''s membership of the SQL admin group current -- setup grants them (the guided install, or setup\Start-SIDbInitJob.ps1 through the Support app); the update goes on' -f ($missing -join ', '))) }
    if ($extra.Count) { $lines.Add(('WARNING: the updater identity holds {0}, more than it needs -- an Entra administrator removes it (it needs only the PIM-for-Groups permissions)' -f ($extra -join ', '))) }
    [pscustomobject]@{ Ok = ($missing.Count -eq 0); Missing = $missing; Extra = $extra; Lines = $lines.ToArray() }
}

function Get-SIDbInitAdminGroupId {
    <# PURE. The SQL server's Entra administrator as a group id ('' when it is not a group: then no identity can be an admin
       through it -- setup\Set-SISqlAdminGroup.ps1 makes the group the administrator). -Server: the server as ARM returns it. #>
    param($Server)
    $a = Get-SIDbInitProp $Server @('properties', 'administrators')
    if (-not $a) { return '' }
    $t = [string](Get-SIDbInitProp $a @('principalType'))
    if ($t -and $t -ne 'Group') { return '' }
    [string](Get-SIDbInitProp $a @('sid'))
}

function Wait-SIDbInitExecution {
    <# ARM: the execution's own status until it ends (Succeeded / Failed / Stopped / Degraded) or -TimeoutSeconds. Returns
       @{ Status; Seconds }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$JobId, [Parameter(Mandatory)][string]$Execution,
          [int]$TimeoutSeconds = 1500, [int]$PollSeconds = 15, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $waited = 0
    while ($true) {
        $e = $null
        try { $e = & $Arm 'GET' ('{0}/executions/{1}?api-version={2}' -f $JobId, $Execution, (Get-SIDbInitNames).AppApi) $null } catch { $e = $null }
        $st = [string](Get-SIDbInitProp $e @('properties', 'status'))
        if ($st -in 'Succeeded', 'Failed', 'Stopped', 'Degraded') { return [pscustomobject]@{ Status = $st; Seconds = $waited } }
        if ($waited -ge $TimeoutSeconds) { return [pscustomobject]@{ Status = 'TimedOut'; Seconds = $waited } }
        & $Sleep $PollSeconds; $waited += $PollSeconds
    }
}

function New-SIDbInitRunId { <# A short run id the job records, so a caller knows the row is from ITS start. #> ([guid]::NewGuid().ToString('N')).Substring(0, 12) }

function Set-SIDbInitIdentity {
    <# The job's identity in the install's resource group: read, made when it is not there (ARM PUT), read back until it has
       its client and principal id. Returns @{ Ok; Made; Id; ClientId; PrincipalId; Problem }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$Location, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $n = Get-SIDbInitNames
    $path = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{2}?api-version={3}' -f $SubscriptionId, $ResourceGroup, $n.Identity, $n.MiApi
    $made = $false
    $mi = & $Arm 'GET' $path $null
    if (-not $mi) {
        $tags = [ordered]@{ product = 'securityinsight' }; $tags[$n.TagName] = $n.TagValue
        $mi = & $Arm 'PUT' $path ([ordered]@{ location = $Location; tags = $tags })
        $made = $true
    }
    for ($i = 0; $i -lt 6 -and -not ([string](Get-SIDbInitProp $mi @('properties', 'clientId')) -and [string](Get-SIDbInitProp $mi @('properties', 'principalId'))); $i++) {
        & $Sleep 5; $mi = & $Arm 'GET' $path $null
    }
    $cid = [string](Get-SIDbInitProp $mi @('properties', 'clientId')); $pid_ = [string](Get-SIDbInitProp $mi @('properties', 'principalId'))
    if (-not $cid -or -not $pid_) { return [pscustomobject]@{ Ok = $false; Made = $made; Id = ''; ClientId = ''; PrincipalId = ''; Problem = ('the identity {0} has no client / principal id yet' -f $n.Identity) } }
    [pscustomobject]@{ Ok = $true; Made = $made; Id = [string](Get-SIDbInitProp $mi @('id')); ClientId = $cid; PrincipalId = $pid_; Problem = '' }
}

function Set-SIDbInitJob {
    <# The job made or brought to -Body (ARM PUT -- idempotent), read back until it is provisioned. Returns @{ Ok; JobId; Job;
       Problem }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)]$Body, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $n = Get-SIDbInitNames
    $id = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}' -f $SubscriptionId, $ResourceGroup, $n.Job
    $path = '{0}?api-version={1}' -f $id, $n.AppApi
    $null = & $Arm 'PUT' $path $Body
    $job = $null
    for ($i = 0; $i -lt 30; $i++) {
        $job = & $Arm 'GET' $path $null
        $ps = [string](Get-SIDbInitProp $job @('properties', 'provisioningState'))
        if ($job -and ($ps -in 'Succeeded', 'Failed', 'Canceled' -or -not $ps)) { break }
        & $Sleep 10
    }
    $ps = [string](Get-SIDbInitProp $job @('properties', 'provisioningState'))
    if (-not $job -or $ps -in 'Failed', 'Canceled') { return [pscustomobject]@{ Ok = $false; JobId = $id; Job = $job; Problem = ('the job {0} was not made (Azure shows: {1})' -f $n.Job, $(if ($ps) { $ps } else { 'nothing' })) } }
    [pscustomobject]@{ Ok = $true; JobId = $id; Job = $job; Problem = '' }
}

# ---------------------------------------------------------------------------------------------------------------------
#  (live 2026-11-07, install-a): a support start of the job BESIDE a running update overwrote the result the update waited for,
#  and its grants met the update's in a deadlock. Every support start of the job (setup\Start-SIDbInitJob.ps1, its
#  grants-only run, and Grant-SISupportAppDatabase.ps1 which sends the same kind of grants itself) REFUSES while the updater
#  runs -- a running execution of the updater job, or a lock row the updater beats -- and says to start it after the update.
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDbInitUpdaterLockSql {
    <# PURE. READ ONLY, one scalar: the lock row an updater run beats now ('<lock>|<holder>|<last beat>'; NULL = none, or no
       lock table). An updater run holds the 'updater' row from its start, and the 'install' row from its run gate on. #>
    $m = [int](Get-SIDbInitNames).UpdaterLockStaleMinutes
    "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.PipelineLock') IS NULL SELECT CAST(NULL AS nvarchar(400)) AS Held; ELSE SELECT TOP (1) LockId + N'|' + Holder + N'|' + ISNULL(CONVERT(nvarchar(19), HeartbeatUtc, 126) + N'Z', N'') AS Held FROM cfg.PipelineLock WHERE Holder LIKE N'caj-si-updater%' AND HeartbeatUtc >= DATEADD(minute, -$m, SYSUTCDATETIME()) ORDER BY HeartbeatUtc DESC;"
}

function Get-SIDbInitUpdaterRunning {
    <# PURE. The updater execution that runs now among -Executions (ARM shape: name, properties.status / startTime / endTime):
       Running / Processing, no end, started within -LimitSeconds (an older one is a leftover). @{ Name; StartedUtc } or $null. #>
    param([object[]]$Executions = @(), [Parameter(Mandatory)][datetime]$NowUtc, [int]$LimitSeconds = 0)
    if ($LimitSeconds -le 0) { $LimitSeconds = [int](Get-SIDbInitNames).UpdaterLimitSeconds }
    $styles = [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal'
    foreach ($e in @($Executions | Where-Object { $_ })) {
        $st = [string](Get-SIDbInitProp $e @('properties', 'status'))
        if ($st -notin 'Running', 'Processing') { continue }
        if ([string](Get-SIDbInitProp $e @('properties', 'endTime'))) { continue }
        $s = $null; $t = [string](Get-SIDbInitProp $e @('properties', 'startTime'))
        if ($t) { $d = [datetime]::MinValue; if ([datetime]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { $s = $d } }
        if ($s -and ($NowUtc.ToUniversalTime() - $s).TotalSeconds -gt ($LimitSeconds + 900)) { continue }
        return [pscustomobject]@{ Name = [string](Get-SIDbInitProp $e @('name')); StartedUtc = $s }
    }
    $null
}

function Test-SIDbInitUpdaterBusy {
    <#
        #1146: does the updater run now? (1) -LockText: what Get-SIDbInitUpdaterLockSql answered ('' = no row, $null = not
        read here); (2) ARM, when -Arm is given: the updater job(s) of the resource group (caj-si-updater, or a job named
        *-updater) and their executions. Returns @{ Busy; Why; Read (what was looked at) }. A part that cannot be read is said
        in Read and does not count as busy (a support repair is never blocked by a read that failed).
    #>
    param([scriptblock]$Arm, [string]$SubscriptionId = '', [string]$ResourceGroup = '', [AllowNull()][AllowEmptyString()][string]$LockText = $null,
          [datetime]$NowUtc = [datetime]::UtcNow)
    $n = Get-SIDbInitNames
    $read = New-Object System.Collections.Generic.List[string]
    $busy = { param($why) [pscustomobject]@{ Busy = $true; Why = $why; Read = $read.ToArray() } }
    if ($null -ne $LockText) {
        $parts = "$LockText".Split('|')
        if ("$LockText".Trim() -and $parts.Count -ge 2) {
            return (& $busy ('the updater runs now: it holds the install''s lock row ''{0}'' ({1}, last sign of life {2})' -f $parts[0], $parts[1], $(if ($parts.Count -ge 3 -and $parts[2]) { $parts[2] } else { '?' })))
        }
        $read.Add('the lock rows: no updater holds one')
    }
    if ($Arm -and $SubscriptionId -and $ResourceGroup) {
        try {
            $base = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs' -f $SubscriptionId, $ResourceGroup
            $jobs = New-Object System.Collections.Generic.List[object]
            $next = '{0}?api-version={1}' -f $base, $n.AppApi
            for ($i = 0; $next -and $i -lt 20; $i++) {
                $page = & $Arm 'GET' $next $null
                if (-not $page) { break }
                foreach ($j in @(Get-SIDbInitProp $page @('value'))) { if ($j) { $jobs.Add($j) } }
                $next = [string](Get-SIDbInitProp $page @('nextLink'))
            }
            $upd = @($jobs | Where-Object { [string](Get-SIDbInitProp $_ @('name')) -match '(?i)^caj-si-updater$|-updater$' })
            if (-not $upd.Count) { $read.Add('the updater job: not found in the resource group') }
            foreach ($u in $upd) {
                $un = [string](Get-SIDbInitProp $u @('name'))
                $limit = 0; try { $limit = [int](Get-SIDbInitProp $u @('properties', 'configuration', 'replicaTimeout')) } catch { $limit = 0 }
                $ex = & $Arm 'GET' ('{0}/{1}/executions?api-version={2}' -f $base, $un, $n.AppApi) $null
                $hit = Get-SIDbInitUpdaterRunning -Executions @(Get-SIDbInitProp $ex @('value')) -NowUtc $NowUtc -LimitSeconds $limit
                if ($hit) {
                    return (& $busy ('the updater runs now: {0} execution {1}{2}' -f $un, $hit.Name, $(if ($hit.StartedUtc) { ' (started {0:yyyy-MM-dd HH:mm}Z)' -f $hit.StartedUtc } else { '' })))
                }
                $read.Add(('the updater job {0}: no execution runs' -f $un))
            }
        } catch { $read.Add(('the updater''s executions could not be read ({0})' -f $_.Exception.Message)) }
    }
    [pscustomobject]@{ Busy = $false; Why = ''; Read = $read.ToArray() }
}

function Get-SIDbInitUpdaterBusyText {
    <# PURE. The refusal's one line (the same words in every script that starts the job). #>
    param([Parameter(Mandatory)][string]$Why, [string]$What = 'the database setup job')
    ('REFUSED: {0} -- {1} is not started beside it (a run beside the update overwrites the result the update waits for, and its grants can meet the update''s in a deadlock). Start it again after the update has ended. Nothing was changed.' -f $Why, $What)
}

function Start-SIDbInitRun {
    <# ONE run: started with -Env on top of the job's own environment (the run id, who started it, the Support app), waited
       for. Returns @{ Ok (the execution Succeeded -- the job exits 0 only when every identity read back); Status; Execution;
       Run; Seconds; Why }. #1146: a SUPPORT start is refused while the updater runs (Test-SIDbInitUpdaterBusy over the job's
       resource group): Status 'Refused', nothing started, Why says it. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$JobId, [Parameter(Mandatory)]$Job, [Parameter(Mandatory)][ValidateSet('installer', 'updater', 'support')][string]$By,
          [string]$Support = '', [int]$TimeoutSeconds = 1500, [int]$PollSeconds = 15, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          [ValidateSet('all', 'grants')][string]$Steps = 'all',
          # more per-execution variables (the identity move: SI_DBINIT_MOVES / SI_DBINIT_DROPS and today's SI_DBINIT_PRINCIPALS)
          [System.Collections.IDictionary]$Extra = @{})
    if ($By -eq 'support' -and $JobId -match '^/subscriptions/(?<s>[^/]+)/resourceGroups/(?<g>[^/]+)/') {
        $b = Test-SIDbInitUpdaterBusy -Arm $Arm -SubscriptionId $Matches['s'] -ResourceGroup $Matches['g']
        if ($b.Busy) { return [pscustomobject]@{ Ok = $false; Status = 'Refused'; Execution = ''; Run = ''; Seconds = 0; Why = (Get-SIDbInitUpdaterBusyText -Why $b.Why) } }
    }
    $run = New-SIDbInitRunId
    $env = [ordered]@{ SI_DBINIT_RUN = $run; SI_DBINIT_BY = $By; SI_DBINIT_STEPS = $Steps }
    if ($Support) { $env.SI_DBINIT_SUPPORT = $Support }
    foreach ($k in @($Extra.Keys)) { if ([string]$k -match '^SI_DBINIT_(MOVES|DROPS|PRINCIPALS|SUPPORT_STANDING_OFF)$') { $env[[string]$k] = [string]$Extra[$k] } }
    $start = & $Arm 'POST' ('{0}/start?api-version={1}' -f $JobId, (Get-SIDbInitNames).AppApi) (Get-SIDbInitStartBody -Job $Job -Env $env)
    $exec = [string](Get-SIDbInitProp $start @('name')); if (-not $exec) { $exec = (([string](Get-SIDbInitProp $start @('id'))) -split '/')[-1] }
    if (-not $exec) { return [pscustomobject]@{ Ok = $false; Status = 'NotStarted'; Execution = ''; Run = $run; Seconds = 0; Why = '' } }
    $w = Wait-SIDbInitExecution -Arm $Arm -JobId $JobId -Execution $exec -TimeoutSeconds $TimeoutSeconds -PollSeconds $PollSeconds -Sleep $Sleep
    [pscustomobject]@{ Ok = ($w.Status -eq 'Succeeded'); Status = $w.Status; Execution = $exec; Run = $run; Seconds = $w.Seconds; Why = '' }
}

function Resolve-SIDbInitSupportAppId {
    <#
        PURE. Which Support app a support run of the job gives database access to (found live 2026-11-05: a client id typed
        by hand was ANOTHER tenant's Support app -- the Invardia Support app has a different client id in every customer
        tenant; the open Support session knows this tenant's). -Typed: what the caller gave ('' = nothing). -SessionAppId:
        the Support session's AppId ('' = no session, or it names none). No typed id -> the session's. A typed id that is
        not the session's -> REFUSED. A typed id without a session to compare with -> as typed. Returns @{ Ok; AppId; Why }.
    #>
    param([AllowEmptyString()][string]$Typed = '', [AllowEmptyString()][string]$SessionAppId = '')
    $g = [guid]::Empty; $t = [guid]::Empty
    $sess = if ([guid]::TryParse("$SessionAppId".Trim(), [ref]$g) -and $g -ne [guid]::Empty) { $g.ToString() } else { '' }
    $typedId = "$Typed".Trim()
    if (-not $typedId) { return [pscustomobject]@{ Ok = $true; AppId = $sess; Why = $(if ($sess) { 'the Support session''s own Support app' } else { '' }) } }
    if (-not [guid]::TryParse($typedId, [ref]$t)) { return [pscustomobject]@{ Ok = $false; AppId = ''; Why = ('-SupportAppId {0} is not a client id' -f $typedId) } }
    if ($sess -and $t.ToString() -ne $sess) {
        return [pscustomobject]@{ Ok = $false; AppId = ''; Why = ('-SupportAppId {0} is not the Support app of this tenant''s Support session ({1}). The Invardia Support app has a different client id in every tenant, and a user made from another tenant''s id is a user nobody can sign in as. Leave -SupportAppId out (the session''s own is used) or give {1}.' -f $t.ToString(), $sess) }
    }
    [pscustomobject]@{ Ok = $true; AppId = $t.ToString(); Why = $(if ($sess) { 'the Support session''s own Support app' } else { 'as given (no Support session to compare it with)' }) }
}

function Get-SIDbInitLogText {
    <# PURE. Where a run's lines are, in plain words (a portal path; never a command). #>
    param([string]$ResourceGroup, [string]$Execution)
    'Azure portal: Container Apps jobs > {0} (resource group {1}) > Execution history > {2} > Console logs' -f (Get-SIDbInitNames).Job, $ResourceGroup, $(if ($Execution) { $Execution } else { 'the latest run' })
}

# ---------------------------------------------------------------------------------------------------------------------
#  Framework §4.5 SQL-ADMIN-GROUP G3a: a managed identity's token keeps its old group claims for up to ~24 hours. Moving the
#  SQL server's administrator from one GROUP to ANOTHER (setup\Set-SISqlAdminGroup.ps1 -ReplaceCurrentAdminGroup) would lock
#  the database setup job out until its token is renewed. So such a move is PROVEN: right after it the job must sign in
#  THROUGH the new group (one run, started again after a growing wait); otherwise the server's administrator is put back
#  automatically, as it was, and read back. A membership of the new group that is 24 hours old needs no proof.
# ---------------------------------------------------------------------------------------------------------------------

function Get-SISqlAdminMovePlan {
    <# PURE. G3a: does this change of the SQL server's administrator need the proof? Action = none (not a move from one group
       to another, or no database setup job at this install) | settled (the job identity has been a member of the new group
       for -SettleHours) | verify (a run of the job must sign in through the new group, else the move is rolled back).
       -MemberSince: when the job identity's membership of the new group began (its PIM assignment's start); $null = not
       known. Returns @{ Action; Detail }. #>
    param([AllowEmptyString()][string]$CurrentSid = '', [AllowEmptyString()][string]$CurrentKind = '', [Parameter(Mandatory)][string]$NewGroupId,
          [bool]$JobExists = $false, $MemberSince = $null, [datetime]$NowUtc = [datetime]::UtcNow, [int]$SettleHours = 24)
    $o = { param($a, $d) [pscustomobject]@{ Action = $a; Detail = $d } }
    if (-not $CurrentSid -or $CurrentSid -eq $NewGroupId) { return (& $o 'none' 'not a move: the server''s administrator is the group already, or none') }
    if ($CurrentKind -ne 'group') { return (& $o 'none' 'the server''s administrator today is not a group: the database setup job does not sign in through it') }
    if (-not $JobExists) { return (& $o 'none' 'no database setup job at this install: nothing signs in through the old group') }
    if ($MemberSince -is [datetime] -and ($NowUtc.ToUniversalTime() - $MemberSince.ToUniversalTime()).TotalHours -ge $SettleHours) {
        return (& $o 'settled' ('the database setup job''s identity has been a member of the new group since {0:yyyy-MM-dd HH:mm}Z (at least {1} hours): its token carries it' -f $MemberSince.ToUniversalTime(), $SettleHours))
    }
    & $o 'verify' ('the database setup job''s identity is a member of the new group for less than {0} hours (or since a time not known): its token may still carry only the old group -- a run of the job must sign in through the new group, else the move is rolled back' -f $SettleHours)
}

function Test-SISqlAdminMoveSignIn {
    <# G3a, after the move: the database setup job started (SI_DBINIT_BY installer) and waited for; it ends successfully only
       when it signed in through the server's administrator group and read every identity back. A run that does not
       succeed is started again after each -SettleWaits (the new membership reaching the token); none succeeds = Ok $false.
       Returns @{ Ok; Execution; Tries; Detail }. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int[]]$SettleWaits = @(300, 600), [int]$TimeoutSeconds = 1500)
    $n = Get-SIDbInitNames
    $jobId = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}' -f $SubscriptionId, $ResourceGroup, $n.Job
    $tries = 0; $last = ''
    try {
        $job = & $Arm 'GET' ('{0}?api-version={1}' -f $jobId, $n.AppApi) $null
        if (-not $job) { return [pscustomobject]@{ Ok = $false; Execution = ''; Tries = 0; Detail = ('the job {0} is not there' -f $n.Job) } }
        $waits = @($SettleWaits | Where-Object { $_ -gt 0 })
        while ($true) {
            $tries++
            $r = Start-SIDbInitRun -Arm $Arm -JobId $jobId -Job $job -By 'installer' -TimeoutSeconds $TimeoutSeconds -Sleep $Sleep
            if ($r.Ok) { return [pscustomobject]@{ Ok = $true; Execution = $r.Execution; Tries = $tries; Detail = ('the job {0} signed in through the new group (execution {1}, run {2})' -f $n.Job, $r.Execution, $tries) } }
            $last = '{0}: {1}' -f $(if ($r.Execution) { $r.Execution } else { '(not started)' }), $r.Status
            if ($tries -gt $waits.Count) { break }
            & $Sleep ([int]$waits[$tries - 1])
        }
        [pscustomobject]@{ Ok = $false; Execution = ''; Tries = $tries; Detail = ('the job {0} did not sign in through the new group in {1} run(s) (last {2})' -f $n.Job, $tries, $last) }
    } catch { [pscustomobject]@{ Ok = $false; Execution = ''; Tries = $tries; Detail = ('the job {0} could not be run: {1}' -f $n.Job, $_.Exception.Message) } }
}

function Restore-SISqlAdminBlock {
    <# G3a ROLLBACK: the server's administrators block (as read BEFORE the move: sid, login, kind, tenant, the Entra-only
       setting) written back whole in one PATCH, then READ BACK until the server shows it. Returns @{ Ok; Detail }. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ServerPath, [Parameter(Mandatory)]$Previous,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$Tries = 36, [int]$PollSeconds = 5)
    try {
        $api = (Get-SIDbInitNames).SqlApi
        $block = [ordered]@{ administratorType = 'ActiveDirectory' }
        foreach ($k in 'principalType', 'login', 'sid', 'tenantId', 'azureADOnlyAuthentication') {
            $v = Get-SIDbInitProp $Previous @($k)
            if ($null -ne $v -and "$v" -ne '') { $block[$k] = $v }
        }
        if (-not $block.Contains('sid')) { return [pscustomobject]@{ Ok = $false; Detail = 'the administrator before the move is not known -- nothing to put back' } }
        $null = & $Arm 'PATCH' ('{0}?api-version={1}' -f $ServerPath, $api) ([ordered]@{ properties = [ordered]@{ administrators = $block } })
        for ($i = 0; $i -lt $Tries; $i++) {
            $s = $null; try { $s = & $Arm 'GET' ('{0}?api-version={1}' -f $ServerPath, $api) $null } catch { $s = $null }
            $a = Get-SIDbInitProp $s @('properties', 'administrators')
            if ($a -and [string](Get-SIDbInitProp $a @('sid')) -eq [string]$block.sid -and (-not $block.Contains('principalType') -or [string](Get-SIDbInitProp $a @('principalType')) -ieq [string]$block.principalType)) {
                return [pscustomobject]@{ Ok = $true; Detail = ('the server''s administrator is {0} again (read back)' -f [string]$block.login) }
            }
            & $Sleep $PollSeconds
        }
        [pscustomobject]@{ Ok = $false; Detail = ('the server''s administrator was written back to {0}, but it does not read back yet -- check the server' -f [string]$block.login) }
    } catch { [pscustomobject]@{ Ok = $false; Detail = ('putting the administrator back failed: {0}' -f $_.Exception.Message) } }
}
