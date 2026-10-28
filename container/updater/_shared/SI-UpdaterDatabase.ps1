#Requires -Version 5.1
<#
    caj-si-updater -- SecurityInsight Pro: THE DATABASE STEP OF AN UPDATE (#352, framework UPDATE-1.6 (j)). Loaded by
    Start-SIUpdater.ps1 when present (the Community edition has no Pro database and does not carry this file).

    🔒 NEVER RUN NEW CODE ON AN OLD SCHEMA. Invoke-SIUpdaterRoll calls Invoke-SIUpdaterDatabase FIRST -- before the template
    gate, before any image is built or any job / app is rolled -- and a failure here STOPS the update (nothing is rolled;
    the run records why in cfg.InstallState 'UpdateState' and trips a guard). In order:
      1. THE SCHEMA: the APPROVED RELEASE's own engine\pro-settings\SI-ProSchema.ps1 applies the release's own sql\ files --
         the same list, order, batching and additive gate as setup (one function, so they cannot drift); one non-additive
         file refuses the whole set; each file in its own transaction;
      2. THE GRANTS the new code needs: the release's pro-management\deploy\SI-ManagementGrants.ps1 (the list
         Deploy-SIManagement -GrantSql uses) for the principals of THIS install -- the web app's and the MCP server's
         identities, found on the container apps (the install record's names, else SI_UPDATER_WEB_APP / SI_UPDATER_MCP_APP,
         else ca-si-management / ca-si-mcp) and their database users found by SID; never a hard-coded name, never a CREATE USER;
      3. THE RECORD: cfg.InstallState 'SchemaVersion' (fingerprint of the schema files + the grants, the release, the time).
         A fingerprint equal to the record = "schema current", nothing sent -- visible and fast.
    The updater's identity needs db_ddladmin + db_securityadmin on the Pro database for 1 and 2 (setup\Grant-SIUpdaterDatabase.ps1).
    #672 (framework §12.23 P4 / P9 "five years without contact"): when the CERTIFICATE-SIGNED GRANT PROCEDURE
    cfg.ApplyComponentGrants is installed and signed and this identity may EXECUTE it (role si_updater), step 2 applies the
    release's whole shipped grant list THROUGH it (engine\pro-settings\SI-GrantProcedure.ps1 Get-SIReleaseGrantRows) and the
    schema files' own GRANT / DENY lines are skipped by their guard -- db_securityadmin is then not needed (the cut-over's
    later -RemoveSecurityAdmin removes it). Without the procedure, today's path stays. A row the procedure refuses is a
    WARNING (the release's list is checked statically, so it never should be); a row that FAILS stops the update, as today.
#>

function Get-SIUpdaterAppIdentity {
    <# The user-assigned identity of one container app: @{ Name; ClientId; ResourceId }, or $null (no such app / no identity). #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$App, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId)
    if (-not $App) { return $null }
    $a = $null
    try { $a = Get-SIUpdaterContainerApp -App $App -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId } catch { $a = $null }
    if (-not $a -or -not $a.identity -or -not $a.identity.userAssignedIdentities) { return $null }
    $p = @($a.identity.userAssignedIdentities.PSObject.Properties) | Select-Object -First 1
    if (-not $p) { return $null }
    [pscustomobject]@{ Name = (([string]$p.Name) -split '/')[-1]; ClientId = [string]$p.Value.clientId; ResourceId = [string]$p.Name }
}

function Resolve-SIUpdaterDbUser {
    <# The database user of an Entra identity, found by its SID (the client id) -- whatever the install named it. '' = none. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$ClientId)
    # The SID is the GUID's bytes; SQL builds them itself from the TEXT client id (CAST to uniqueidentifier, then varbinary
    # = the same byte order as Guid.ToByteArray). A byte[] parameter is unrolled to Object[] on its way through the store's
    # parameter hashtable and refused by SqlClient ("No mapping exists from object type System.Object[]") -- found live on
    # ring 1, 2026-10-06, on the first real update through Invardia.
    $null = [guid]$ClientId
    $rows = @(& $Invoke 'SELECT name FROM sys.database_principals WHERE sid = CONVERT(varbinary(16), CAST(@ClientId AS uniqueidentifier))' @{ ClientId = [string]$ClientId } 'reader' | ForEach-Object { $_ })
    if (-not $rows.Count) { return '' }
    $r = $rows[0]
    if ($r -is [System.Collections.IDictionary]) { [string]$r['name'] } else { [string]$r.name }
}

function Send-SIUpdaterDatabaseGuard {
    <# A guard trip from the database step, through the RELEASE's SI-Guard.ps1 (mail + telemetry + Guards view). Never throws. #>
    param([Parameter(Mandatory)][string]$SIRoot, $Store, [Parameter(Mandatory)][string]$GuardId, [Parameter(Mandatory)][string]$Outcome,
          [string]$Subject, [string]$Detail)
    try {
        if (-not (Get-Command -Name Send-SIGuardEvent -ErrorAction SilentlyContinue)) {
            $g = [IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-Guard.ps1')
            if (-not (Test-Path -LiteralPath $g)) { return $null }
            . $g
        }
        $a = @{ GuardId = $GuardId; Outcome = $Outcome; Source = 'updater'; Engine = 'updater'; Job = 'caj-si-updater'; Subject = $Subject; Detail = $Detail }
        if ($Store -and $Store.Invoke) { $a.Invoke = $Store.Invoke }
        Send-SIGuardEvent @a
    } catch { Write-UpdLog ("WARNING: the guard could not be reported: {0}" -f $_.Exception.Message); $null }
}

function Invoke-SIUpdaterEngineDatabaseGrant {
    <#
        #881 (a data sync failed at one install: "VIEW DATABASE PERFORMANCE STATE permission denied"): the engine role's read
        right on the database's own load (the RELEASE's Get-SIEngineDatabaseGrantSql), so an EXISTING install reaches what a
        new install gets. A batch of its OWN, after the schema's transaction and the grants -- never inside one: a refused
        GRANT is caught in the batch and said as one warning (the engine then paces on its own measured statement time).
        Never a stop, never throws. Returns the answer (Granted 0..3) or $null.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, $Store)
    try {
        if (-not $Store -or -not $Store.Invoke) { return $null }
        $file = [IO.Path]::Combine($SIRoot, 'engine', 'pro-settings', 'SI-EngineGrants.ps1')
        if (-not (Test-Path -LiteralPath $file)) { return $null }
        . $file
        if (-not (Get-Command -Name Get-SIEngineDatabaseGrantSql -ErrorAction SilentlyContinue)) { return $null }
        $row = @(& $Store.Invoke (Get-SIEngineDatabaseGrantSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        if ($null -eq $row) { return $null }
        $g = if ($row -is [System.Collections.IDictionary]) { $row['Granted'] } else { $row.Granted }
        $why = [string]$(if ($row -is [System.Collections.IDictionary]) { $row['Reason'] } else { $row.Reason })
        $line = Format-SIEngineDatabaseGrantLine -Granted $g -Reason $why
        if ($line) { Write-UpdLog $line }
        $g
    } catch { Write-UpdLog ('WARNING: engine database rights: the read right on the database''s own load could not be granted: {0}' -f $_.Exception.Message); $null }
}

function Invoke-SIUpdaterEngineAccessCheck {
    <#
        #672 (framework §12.23 P8): THE UPDATER CHANGES NO SECURITY -- it only CHECKS that the engine identity has exactly
        the agreed rights (the release's engine\pro-settings\SI-EngineGrants.ps1: the role si_engine, and every statement of
        THIS release's engine code allowed by it) and says a drift in plain words. A warning in the run's log; never a
        block, never a grant, never throws. The engine user = every Entra user of the database in si_engine or
        db_datawriter other than the updater itself and the web app / MCP server (-Exclude). Returns the results.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, $Store, [string[]]$Exclude = @())
    try {
        if (-not $Store -or -not $Store.Invoke) { return @() }
        $file = [IO.Path]::Combine($SIRoot, 'engine', 'pro-settings', 'SI-EngineGrants.ps1')
        if (-not (Test-Path -LiteralPath $file)) { return @() }
        . $file
        $users = @(& $Store.Invoke "SELECT DISTINCT u.name AS name FROM sys.database_principals AS u JOIN sys.database_role_members AS m ON m.member_principal_id = u.principal_id JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id WHERE r.name IN (N'si_engine', N'db_datawriter') AND u.type IN ('E', 'X') AND u.principal_id <> DATABASE_PRINCIPAL_ID()" @{} 'reader' | ForEach-Object { $_ } |
            ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [string]$_['name'] } else { [string]$_.name } } | Where-Object { $_ -and $Exclude -notcontains $_ })
        if (-not $users.Count) { Write-UpdLog 'engine database rights: no engine identity found in the Pro database -- nothing to check'; return @() }
        $req = Get-SIEngineRequiredPermission -References (Get-SIEngineSqlReference -SIRoot $SIRoot)
        $out = foreach ($u in $users) {
            $state = ConvertFrom-SIEngineAccessRows -Rows @(& $Store.Invoke (Get-SIEngineAccessStateSql -UserName $u) @{} 'reader' | ForEach-Object { $_ })
            $d = Get-SIEngineAccessDrift -State $state -Required $req -UserName $u
            foreach ($l in @($d.Lines)) { Write-UpdLog ('{0}engine database rights: {1}' -f $(if ($d.Status -eq 'drift') { 'WARNING: ' } else { '' }), $l) }
            [pscustomobject]@{ User = $u; Status = $d.Status; Lines = @($d.Lines) }
        }
        $global:SI_UpdaterEngineAccess = @($out)
        @($out)
    } catch { Write-UpdLog ('WARNING: the engine identity''s database rights could not be checked: {0}' -f $_.Exception.Message); @() }
}

function Get-SIUpdaterGrantProcedurePlan {
    <#
        #672 (framework §12.23 P4 / P9): does THIS install apply grants through the certificate-signed procedure? Loads the
        RELEASE's engine\pro-settings\SI-GrantProcedure.ps1 and reads the database (read-only): the procedure is there, it
        is signed, and this identity may EXECUTE it. Returns @{ Use; Reason; Rows; Json } -- Use = $false (today's path,
        nothing changes) when the release carries no such file, the procedure is not installed / not signed, or the read
        fails. Never throws.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, $Store, [string]$WebUser = '', [string]$McpUser = '')
    $no = { param($why) [pscustomobject]@{ Use = $false; Reason = $why; Rows = @(); Json = '' } }
    try {
        if (-not $Store -or -not $Store.Invoke) { return (& $no 'no Pro database') }
        # loaded by Invoke-SIUpdaterDatabase from the RELEASE (a function dot-sourced here would vanish with this scope)
        if (-not (Get-Command -Name Get-SIGrantProcedureStateSql -ErrorAction SilentlyContinue)) { return (& $no 'this release carries no grant procedure') }
        $st = ConvertFrom-SIGrantProcedureState -Row (@(& $Store.Invoke (Get-SIGrantProcedureStateSql) @{} 'reader' | ForEach-Object { $_ }) | Select-Object -First 1)
        if (-not $st.Installed) { Write-UpdLog 'grants: the signed grant procedure is not installed on this database -- today''s grant path (db_securityadmin)'; return (& $no 'not installed') }
        if (-not $st.Signed) { Write-UpdLog 'WARNING: grants: the grant procedure cfg.ApplyComponentGrants is NOT signed (it has no rights) -- today''s grant path; an admin signs it again (setup\Install-SIGrantProcedure.ps1 through the Support app)'; return (& $no 'not signed') }
        if (-not $st.CallerExecute) { Write-UpdLog 'WARNING: grants: the updater may not EXECUTE the grant procedure (not in si_updater) -- today''s grant path'; return (& $no 'no EXECUTE') }
        if (-not $st.Current) { Write-UpdLog ('grants: the installed grant procedure is another version than this release''s ({0}) -- it is used as it is (its rules are frozen)' -f $script:SIGrantProcMarker) }
        $rows = Get-SIReleaseGrantRows -SIRoot $SIRoot -WebUser $WebUser -McpUser $McpUser
        [pscustomobject]@{ Use = $true; Reason = 'signed procedure'; Rows = $rows; Json = (ConvertTo-SIGrantRowsJson -Rows $rows) }
    } catch { Write-UpdLog ('WARNING: grants: the grant procedure could not be read ({0}) -- today''s grant path' -f $_.Exception.Message); & $no 'read failed' }
}

function Save-SIUpdaterGrantProcedureRecord {
    <#
        #672: the proof the cut-over's -RemoveSecurityAdmin waits for -- cfg.InstallState 'GrantProcedureLastApply' = {"at",
        "version","applied","skipped","refused","failed"} after every update that applied grants through the procedure.
        A failure to record is a warning, never a stop.
    #>
    param($Store, $Result, [string]$Version = '')
    try {
        $v = ConvertTo-Json -Compress -InputObject ([ordered]@{ at = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
            version = $Version; applied = [int]$Result.Applied; skipped = [int]$Result.Skipped; refused = @($Result.Refused).Count; failed = @($Result.Failed).Count })
        $sql = @'
IF EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'GrantProcedureLastApply')
    UPDATE cfg.InstallState SET Value = @Value, [Version] = @Version, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'caj-si-updater' WHERE Name = N'GrantProcedureLastApply';
ELSE INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'GrantProcedureLastApply', @Value, @Version, N'caj-si-updater');
'@
        & $Store.Invoke $sql ([ordered]@{ Value = $v; Version = $(if ($Version) { $Version.Substring(0, [Math]::Min(32, $Version.Length)) } else { $null }) }) 'nonquery'
    } catch { Write-UpdLog ('WARNING: the grant procedure''s result could not be recorded: {0}' -f $_.Exception.Message) }
}

function Invoke-SIUpdaterDatabase {
    <#
        The database step of one update, from an EXTRACTED, verified release (-SIRoot) to the install's Pro database (-Store:
        @{ Name; Invoke; Server; Database; GetToken }). Returns @{ Ok; Action = applied | noop | skipped | refused | failed;
        Reason; Hash; Principals }. Ok = $false means: STOP, roll nothing.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, $Store, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId,
          [string]$WebApp, [string]$McpApp)
    $res = { param($ok, $a, $why, $hash = '', $pr = @()) [pscustomobject]@{ Ok = $ok; Action = $a; Reason = $why; Hash = $hash; Principals = @($pr) } }
    if (-not $Store) { return (& $res $true 'skipped' 'no Pro database on this install -- no schema step') }
    $schemaFile = [IO.Path]::Combine($SIRoot, 'engine', 'pro-settings', 'SI-ProSchema.ps1')
    if (-not (Test-Path -LiteralPath $schemaFile)) { return (& $res $true 'skipped' 'this release carries no Pro schema step') }
    . $schemaFile
    # #672: the release's signed-grant-procedure code (absent in an older release: today's path)
    $gpFile = [IO.Path]::Combine($SIRoot, 'engine', 'pro-settings', 'SI-GrantProcedure.ps1')
    if (Test-Path -LiteralPath $gpFile) { . $gpFile }
    $version = ''
    $vf = [IO.Path]::Combine($SIRoot, 'VERSION')
    if (Test-Path -LiteralPath $vf) { $version = ([IO.File]::ReadAllText($vf)).Trim() }
    # CR5 step 1 (#655): the install record this run resolved, then the job's variable, then today's name (Get-SIUpdaterInstallName)
    if (-not $WebApp -and (Get-Command -Name Get-SIUpdaterInstallName -ErrorAction SilentlyContinue)) { $WebApp = Get-SIUpdaterInstallName -Role web }
    if (-not $McpApp -and (Get-Command -Name Get-SIUpdaterInstallName -ErrorAction SilentlyContinue)) { $McpApp = Get-SIUpdaterInstallName -Role mcp }
    if (-not $WebApp) { $WebApp = [Environment]::GetEnvironmentVariable('SI_UPDATER_WEB_APP'); if (-not $WebApp) { $WebApp = 'ca-si-management' } }
    if (-not $McpApp) { $McpApp = [Environment]::GetEnvironmentVariable('SI_UPDATER_MCP_APP'); if (-not $McpApp) { $McpApp = 'ca-si-mcp' } }

    # ---- the principals and their grants (built first: the grants are part of the fingerprint) ----
    $grantSql = ''; $principals = New-Object System.Collections.Generic.List[string]
    $webUser = ''; $mcpUser = ''
    $grantsFile = [IO.Path]::Combine($SIRoot, 'pro-management', 'deploy', 'SI-ManagementGrants.ps1')
    if (Test-Path -LiteralPath $grantsFile) {
        . $grantsFile
        foreach ($p in @(@{ App = $WebApp; Writer = $true; Role = 'web app' }, @{ App = $McpApp; Writer = $false; Role = 'MCP server' })) {
            $id = Get-SIUpdaterAppIdentity -App $p.App -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId
            if (-not $id) { continue }
            $user = ''
            try { $user = Resolve-SIUpdaterDbUser -Invoke $Store.Invoke -ClientId $id.ClientId }
            catch { return (& $res $false 'failed' ("the database user of the {0} ({1}) could not be looked up: {2} -- nothing was applied or rolled" -f $p.Role, $id.Name, $_.Exception.Message)) }
            if (-not $user) { Write-UpdLog ("WARNING: the {0}'s identity {1} has no user in the Pro database -- its grants are skipped (run Deploy-SIManagement -GrantSql once as the server's admin)" -f $p.Role, $id.Name); continue }
            $grantSql += (Get-SIManagementGrantSql -UserName $user -Writer:$p.Writer)
            $principals.Add($user)
            if ($p.Writer) { $webUser = $user } else { $mcpUser = $user }
        }
    }

    # ---- #672: the signed grant procedure, when this install has it (decided BEFORE the schema: it is part of the fingerprint) ----
    $proc = Get-SIUpdaterGrantProcedurePlan -SIRoot $SIRoot -Store $Store -WebUser $webUser -McpUser $mcpUser
    if ($proc.Use) { $grantSql += "`n-- through cfg.ApplyComponentGrants`n" + $proc.Json }

    # ---- 1. the schema ----
    $runFile = $null
    if ($Store.PSObject.Properties['GetToken'] -and $Store.GetToken -and $Store.PSObject.Properties['Server'] -and $Store.Server) {
        $runFile = New-SIProSchemaRunner -Server $Store.Server -Database $Store.Database -GetToken $Store.GetToken
    }
    $apply = Invoke-SIProSchemaApply -SIRoot $SIRoot -Invoke $Store.Invoke -RunFile $runFile -ExtraFingerprint $grantSql -SkipWhenRecorded -Log { param($m) Write-UpdLog $m }
    switch ($apply.Action) {
        'refused' {
            $null = Send-SIUpdaterDatabaseGuard -SIRoot $SIRoot -Store $Store -GuardId 'schema.gate.refused' -Outcome 'refused' -Subject $apply.FailedFile -Detail $apply.Reason
            return (& $res $false 'refused' $apply.Reason $apply.Hash $principals)
        }
        'failed' {
            $null = Send-SIUpdaterDatabaseGuard -SIRoot $SIRoot -Store $Store -GuardId 'update.schema.failed' -Outcome 'halted' -Subject $apply.FailedFile -Detail $apply.Reason
            return (& $res $false 'failed' ("{0} -- the update stopped before rolling any code" -f $apply.Reason) $apply.Hash $principals)
        }
        # #881's read right also on an update whose schema is current: it was granted only when the schema changed, so an
        # install whose schema was already recorded never got it (idempotent: "held already" says nothing)
        'noop' { $null = Invoke-SIUpdaterEngineDatabaseGrant -SIRoot $SIRoot -Store $Store; $null = Invoke-SIUpdaterEngineAccessCheck -SIRoot $SIRoot -Store $Store -Exclude $principals.ToArray(); return (& $res $true 'noop' $apply.Reason $apply.Hash $principals) }
    }

    # ---- 2. the grants: through the signed procedure when this install has it (#672), else today's transaction ----
    if ($proc.Use) {
        $g = $null
        try { $g = Invoke-SIGrantProcedureApply -Invoke $Store.Invoke -Rows $proc.Rows }
        catch {
            $why = "the schema was applied, but the grant procedure could not be run ({0}) -- the update stopped before rolling any code" -f $_.Exception.Message
            $null = Send-SIUpdaterDatabaseGuard -SIRoot $SIRoot -Store $Store -GuardId 'update.schema.failed' -Outcome 'halted' -Subject 'grants' -Detail $why
            return (& $res $false 'failed' $why $apply.Hash $principals)
        }
        foreach ($x in @($g.Refused)) { Write-UpdLog ('WARNING: grant procedure: {0}' -f (Format-SIGrantOutcome -Row $x)) }
        Save-SIUpdaterGrantProcedureRecord -Store $Store -Result $g -Version $version
        if (-not $g.Used -or @($g.Failed).Count) {
            $why = if (-not $g.Used) { "the schema was applied, but the grant procedure was not usable at the grant step ({0}) -- the update stopped before rolling any code" -f $g.Reason }
                   else { "the schema was applied, but {0} grant(s) failed in the grant procedure ({1}) -- the update stopped before rolling any code" -f @($g.Failed).Count, ((@($g.Failed) | Select-Object -First 3 | ForEach-Object { Format-SIGrantOutcome -Row $_ }) -join '; ') }
            $null = Send-SIUpdaterDatabaseGuard -SIRoot $SIRoot -Store $Store -GuardId 'update.schema.failed' -Outcome 'halted' -Subject 'grants' -Detail $why
            return (& $res $false 'failed' $why $apply.Hash $principals)
        }
        Write-UpdLog ('grants: {0} -- {1} applied, {2} unchanged or not there yet, {3} refused' -f $g.Reason, $g.Applied, $g.Skipped, @($g.Refused).Count)
    }
    elseif ($grantSql) {
        try { & $Store.Invoke ("SET XACT_ABORT ON;`nBEGIN TRANSACTION;`n{0}`nCOMMIT TRANSACTION;" -f $grantSql) @{} 'nonquery' }
        catch {
            $why = "the schema was applied, but the grants for {0} were not ({1}) -- the update stopped before rolling any code" -f ($principals -join ', '), $_.Exception.Message
            $null = Send-SIUpdaterDatabaseGuard -SIRoot $SIRoot -Store $Store -GuardId 'update.schema.failed' -Outcome 'halted' -Subject 'grants' -Detail $why
            return (& $res $false 'failed' $why $apply.Hash $principals)
        }
    }

    # ---- #881: the engine role's read right on the database's own load -- a batch of its own, a warning when refused ----
    $null = Invoke-SIUpdaterEngineDatabaseGrant -SIRoot $SIRoot -Store $Store

    # ---- #672: the engine identity's rights CHECKED (never changed here: framework §12.23 P8) -- a warning, never a stop ----
    $null = Invoke-SIUpdaterEngineAccessCheck -SIRoot $SIRoot -Store $Store -Exclude $principals.ToArray()

    # ---- 3. the record (visibility; a failure here is reported, the next run applies again -- idempotent) ----
    $recorded = $true
    try { Save-SIProSchemaState -Invoke $Store.Invoke -Hash $apply.Hash -Version $version -Files $apply.Files -Grants $principals.ToArray() -By 'caj-si-updater' }
    catch { $recorded = $false; Write-UpdLog ("WARNING: the applied schema could not be recorded: {0}" -f $_.Exception.Message) }
    $why = '{0}; grants {1}; schema {2} {3}' -f $apply.Reason, $(if ($principals.Count) { 'applied for ' + ($principals -join ', ') } else { 'none (no web app on this install)' }), $apply.Hash.Substring(0, 12), $(if ($recorded) { 'recorded' } else { 'NOT recorded' })
    & $res $true 'applied' $why $apply.Hash $principals
}
