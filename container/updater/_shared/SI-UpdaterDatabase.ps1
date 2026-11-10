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
      2b. ASSET TAGGING'S DATABASE ACCESS (framework SEC-08, every update, a current schema too): what a person once ran
         setup\Grant-SITaggingDatabase.ps1 for -- given by the product and read back (Invoke-SIUpdaterTaggingDatabaseAccess);
         what this install's updater may not give is one warning naming that script. Never a stop;
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
    $p = Select-SIUpdaterAppSqlIdentity -App $a
    if (-not $p) { return $null }
    [pscustomobject]@{ Name = (([string]$p.Name) -split '/')[-1]; ClientId = [string]$p.Value.clientId; ResourceId = [string]$p.Name }
}

function Select-SIUpdaterAppSqlIdentity {
    <#
        PURE. Of the user-assigned identities on one container app, the one the app SIGNS IN TO SQL WITH: the identity whose
        client id the app's AZURE_CLIENT_ID names, else Identity__ManagedIdentityClientId, else the only one, else the first.
        An app can carry two (an identity move in progress, 2026-11-07 internal: the grant went to the first one listed while
        the app signed in as the other). Returns the identity's property (Name = resource id, Value.clientId) or $null.
    #>
    param([Parameter(Mandatory)]$App)
    if (-not $App.identity -or -not $App.identity.userAssignedIdentities) { return $null }
    $all = @($App.identity.userAssignedIdentities.PSObject.Properties)
    if (-not $all.Count) { return $null }
    if ($all.Count -eq 1) { return $all[0] }
    foreach ($n in 'AZURE_CLIENT_ID', 'Identity__ManagedIdentityClientId') {
        $want = ''
        foreach ($c in @($App.properties.template.containers)) {
            if (-not $c) { continue }
            foreach ($e in @($c.env)) { if ($e -and [string]$e.name -eq $n -and [string]$e.value) { $want = [string]$e.value; break } }
            if ($want) { break }
        }
        if ($want) {
            $hit = @($all | Where-Object { [string]$_.Value.clientId -ieq $want }) | Select-Object -First 1
            if ($hit) { return $hit }
        }
    }
    $all[0]
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

function Get-SIUpdaterNamedIdentity {
    <# A user-assigned identity of the install's resource group by its name: @{ Name; ClientId }, or $null (not there). Throws on any other ARM answer. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId)
    $r = Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.ManagedIdentity/userAssignedIdentities/' + $Name)) -ApiVersion '2023-01-31' -AllowNotFound
    if (-not $r -or -not $r.PSObject.Properties['properties'] -or -not $r.properties -or -not "$($r.properties.clientId)".Trim()) { return $null }
    [pscustomobject]@{ Name = [string]$r.name; ClientId = ([string]$r.properties.clientId).Trim() }
}

function Invoke-SIUpdaterTaggingDatabaseAccess {
    <#
        Framework SEC-08 (no person needs database admin rights at an install; existing installs reach the new-install state
        through the update): ASSET TAGGING'S DATABASE ACCESS, checked on every update and given by the product -- what a
        person ran setup\Grant-SITaggingDatabase.ps1 for as the SQL server's admin. The identity (the install record's
        taggingIdentity, else uami-securityinsight-tagging) found in the install's resource group; none = this install has
        no asset tagging, nothing said. Its state read (the RELEASE's Get-SITaggingDatabaseStateSql), the plan made (the
        release's Get-SITaggingDatabaseUpdatePlan): through the signed grant procedure when this install has it
        (-UseProcedure), else the one GRANT today's grant path may give; whatever this update may not give is ONE plain
        warning naming the customer action. Every change is read back. Never a stop, never throws. -FindIdentity: a test
        seam { param($Name) } -> @{ Name; ClientId } or $null. Returns @{ Action; Ok; Line } or $null.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, $Store, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId,
          [switch]$UseProcedure, [scriptblock]$FindIdentity)
    try {
        if (-not $Store -or -not $Store.Invoke) { return $null }
        # an older release carries no plan: nothing done (the next update brings it)
        if (-not (Get-Command -Name Get-SITaggingDatabaseUpdatePlan -ErrorAction SilentlyContinue)) { return $null }
        $name = ''
        if (Get-Command -Name Get-SIInstallName -ErrorAction SilentlyContinue) { try { $name = [string](Get-SIInstallName -Role taggingIdentity) } catch { $name = '' } }
        if (-not "$name".Trim()) { $name = 'uami-securityinsight-tagging' }
        $id = $null
        try { $id = if ($FindIdentity) { & $FindIdentity $name } else { Get-SIUpdaterNamedIdentity -Name $name -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId } }
        catch { Write-UpdLog ("asset tagging's database access: its identity {0} could not be read ({1}) -- checked again at the next update" -f $name, $_.Exception.Message); return $null }
        if (-not $id -or -not "$($id.ClientId)".Trim()) { return $null }
        $read = { @(& $Store.Invoke (Get-SITaggingDatabaseStateSql -ClientId ([string]$id.ClientId)) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1 }
        $schemas = if ($script:SIGrantSchemas) { @($script:SIGrantSchemas) } else { @('sidata', 'cfg', 'vuln', 'cmdbsync', 'snowstage') }
        $planOf = { param($row) Get-SITaggingDatabaseUpdatePlan -State $row -UserName $name -ClientId ([string]$id.ClientId) -Procedure:([bool]$UseProcedure) -Schemas $schemas }
        $state = $null
        try { $state = & $read } catch { $state = $null }
        $plan = & $planOf $state
        switch ($plan.Action) {
            'current' { return [pscustomobject]@{ Action = 'current'; Ok = $true; Line = '' } }
            'unknown' { Write-UpdLog $plan.Line; return [pscustomobject]@{ Action = 'unknown'; Ok = $false; Line = $plan.Line } }
            'task'    { Write-UpdLog $plan.Line; return [pscustomobject]@{ Action = 'task'; Ok = $false; Line = $plan.Line } }
        }
        if ($plan.Action -eq 'procedure') {
            $g = Invoke-SIGrantProcedureApply -Invoke $Store.Invoke -Rows $plan.Rows
            foreach ($x in @($g.Refused) + @($g.Failed)) { if ($x) { Write-UpdLog ("WARNING: asset tagging's database access: {0}" -f (Format-SIGrantOutcome -Row $x)) } }
        } else {
            & $Store.Invoke $plan.Sql @{} 'nonquery'
        }
        # the read-back: the change counts only when the database says so
        $after = $null
        try { $after = & $read } catch { $after = $null }
        $check = & $planOf $after
        if ($check.Action -eq 'current') {
            $line = '{0} (read back)' -f $plan.Line
            Write-UpdLog $line
            return [pscustomobject]@{ Action = $plan.Action; Ok = $true; Line = $line }
        }
        $still = if (@($check.Missing).Count) { 'still missing after this update: ' + (@($check.Missing) -join ', ') } else { 'the change could not be read back' }
        $line = "WARNING: asset tagging's database access: {0}. One time, as the SQL server's admin (or through the Support app): setup\Grant-SITaggingDatabase.ps1 -Apply" -f $still
        Write-UpdLog $line
        [pscustomobject]@{ Action = $plan.Action; Ok = $false; Line = $line }
    } catch {
        Write-UpdLog ("WARNING: asset tagging's database access could not be checked: {0}" -f $_.Exception.Message)
        $null
    }
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
    # #1050: the install's lock is beaten while an index builds (a long build never leaves it looking abandoned: a runner takes
    # over a lock 15 minutes old) -- through the lock this update registered at its run gate
    $ixBeat = { param($what) if (Get-Command -Name Invoke-SIUpdaterLockBeat -ErrorAction SilentlyContinue) { $null = Invoke-SIUpdaterLockBeat -What $what -MinSeconds 30 } }
    $applyArgs = @{ SIRoot = $SIRoot; Invoke = $Store.Invoke; RunFile = $runFile; ExtraFingerprint = $grantSql; SkipWhenRecorded = $true; Log = { param($m) Write-UpdLog $m } }
    # (a release before #1050 has no -Beat: its apply runs as it always did)
    if ((Get-Command -Name Invoke-SIProSchemaApply).Parameters.ContainsKey('Beat')) { $applyArgs.Beat = $ixBeat }
    $applyParams = (Get-Command -Name Invoke-SIProSchemaApply).Parameters
    # #1112: the database window -- the install's lock says "database schema" while the files' transactions run, so the web
    # app answers "SecurityInsight is being updated" at once instead of waiting behind their locks. A release before #1112
    # has no -Window: the whole apply is the window (its no-op and its online index builds too -- the safe side).
    $hasWindow = (Get-Command -Name Set-SIUpdaterDatabaseWindow -ErrorAction SilentlyContinue)
    $outerWindow = $false
    if ($hasWindow) {
        if ($applyParams.ContainsKey('Window')) { $applyArgs.Window = { param([bool]$On) $null = Set-SIUpdaterDatabaseWindow -On $On } }
        else { $outerWindow = $true }
    }
    if ($outerWindow) { $null = Set-SIUpdaterDatabaseWindow -On $true }
    try { $apply = Invoke-SIProSchemaApply @applyArgs }
    finally { if ($outerWindow -or ($hasWindow -and $global:SI_UpdaterDbWindow)) { $null = Set-SIUpdaterDatabaseWindow -On $false } }
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
        'noop' { $null = Invoke-SIUpdaterEngineDatabaseGrant -SIRoot $SIRoot -Store $Store; $null = Invoke-SIUpdaterEngineAccessCheck -SIRoot $SIRoot -Store $Store -Exclude $principals.ToArray()
                 # SEC-08: asset tagging's database access, also on an update whose schema is current (idempotent: current = nothing said)
                 $null = Invoke-SIUpdaterTaggingDatabaseAccess -SIRoot $SIRoot -Store $Store -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -UseProcedure:([bool]$proc.Use)
                 return (& $res $true 'noop' $apply.Reason $apply.Hash $principals) }
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

    # ---- SEC-08: asset tagging's database access given by the product (no person; a warning when it may not) ----
    $null = Invoke-SIUpdaterTaggingDatabaseAccess -SIRoot $SIRoot -Store $Store -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -UseProcedure:([bool]$proc.Use)

    # ---- #672: the engine identity's rights CHECKED (never changed here: framework §12.23 P8) -- a warning, never a stop ----
    $null = Invoke-SIUpdaterEngineAccessCheck -SIRoot $SIRoot -Store $Store -Exclude $principals.ToArray()

    # ---- 3. the record (visibility; a failure here is reported, the next run applies again -- idempotent) ----
    $recorded = $true
    try { Save-SIProSchemaState -Invoke $Store.Invoke -Hash $apply.Hash -Version $version -Files $apply.Files -Grants $principals.ToArray() -By 'caj-si-updater' }
    catch { $recorded = $false; Write-UpdLog ("WARNING: the applied schema could not be recorded: {0}" -f $_.Exception.Message) }
    $why = '{0}; grants {1}; schema {2} {3}' -f $apply.Reason, $(if ($principals.Count) { 'applied for ' + ($principals -join ', ') } else { 'none (no web app on this install)' }), $apply.Hash.Substring(0, 12), $(if ($recorded) { 'recorded' } else { 'NOT recorded' })
    & $res $true 'applied' $why $apply.Hash $principals
}

function Test-SIUpdaterGraphRights {
    <#
        Framework §4.5 SQL-ADMIN-GROUP G5, the updater's side: the Microsoft Graph application permissions its own Graph token
        carries (the roles claim -- read with no directory right) checked against the G5 list (the release's
        Test-SIDbInitUpdaterGraphRoles). The updater cannot grant itself: what is missing is ONE warning naming what and who
        grants it (setup). Never a hold, never throws. -GraphRoles { } -> Get-SIDbInitTokenRoles' answer (a test seam).
        Returns @{ Ok ($null = not known); Missing; Lines }.
    #>
    param([scriptblock]$GraphRoles)
    try {
        if (-not (Get-Command -Name Test-SIDbInitUpdaterGraphRoles -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ Ok = $null; Missing = @(); Lines = @() } }
        if (-not $GraphRoles) {
            $GraphRoles = { if (Get-Command -Name Get-SIAzureToken -ErrorAction SilentlyContinue) { Get-SIDbInitTokenRoles -Token ([string](Get-SIAzureToken -Resource 'https://graph.microsoft.com/')) } else { $null } }
        }
        $t = & $GraphRoles
        if ($null -eq $t) {
            $l = 'the updater identity''s Microsoft Graph permissions could not be read from its token -- checked again at the next update'
            Write-UpdLog $l
            return [pscustomobject]@{ Ok = $null; Missing = @(); Lines = @($l) }
        }
        $c = Test-SIDbInitUpdaterGraphRoles -Held @($t.Roles)
        foreach ($l in $c.Lines) { Write-UpdLog $l }
        [pscustomobject]@{ Ok = [bool]$c.Ok; Missing = @($c.Missing); Lines = @($c.Lines) }
    } catch {
        $l = 'WARNING: the updater identity''s Microsoft Graph permissions could not be checked ({0}) -- checked again at the next update' -f $_.Exception.Message
        Write-UpdLog $l
        [pscustomobject]@{ Ok = $null; Missing = @(); Lines = @($l) }
    }
}

function Invoke-SIUpdaterDbJobMembership {
    <#
        Framework §4.5 SQL-ADMIN-GROUP G2-G4, the updater's side: the database setup job identity's membership of the SQL
        server's admin group, CONVERGED and RENEWED on every update through the release's Sync-SIDbInitMembership (the same
        path setup uses). The group = the SQL server's Entra administrator (ARM: the server in the install's resource group).
        With the G5 rights the updater reads the active PIM-for-Groups assignment and makes / extends it; a direct add
        (members/$ref) is tried first and is refused for a role-assignable group without directory rights, as decided.
        Returns @{ Member ($true | $false | $null = not known); JustAdded; State; Renewal; End; Detail }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$PrincipalId,
          [scriptblock]$Sleep, [datetime]$NowUtc = [datetime]::UtcNow)
    $unknown = { param($d) [pscustomobject]@{ Member = $null; JustAdded = $false; State = 'unknown'; Renewal = $null; End = $null; Detail = [string]$d } }
    try {
        if (-not (Get-Command -Name Sync-SIDbInitMembership -ErrorAction SilentlyContinue)) { return (& $unknown 'this release does not keep the membership') }
        $n = Get-SIDbInitNames
        $name = (($Server -split '\.')[0]).Trim()
        if ($name -notmatch '^[a-z0-9][a-z0-9-]{0,62}$') { return (& $unknown ('the database server ''{0}'' is not a server name' -f $Server)) }
        $srv = $null
        try { $srv = & $Arm 'GET' ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Sql/servers/{2}?api-version={3}' -f $SubscriptionId, $ResourceGroup, $name, $n.SqlApi) $null }
        catch { return (& $unknown ('the database server {0} could not be read ({1})' -f $name, $_.Exception.Message)) }
        if (-not $srv) { return (& $unknown ('the database server {0} is not in the install''s resource group' -f $name)) }
        $gid = Get-SIDbInitAdminGroupId -Server $srv
        if (-not $gid) { return (& $unknown ('the database server {0}''s administrator is not a group' -f $name)) }
        $s = Sync-SIDbInitMembership -Graph $Graph -PrincipalId $PrincipalId -GroupId $gid -Sleep $Sleep -NowUtc $NowUtc -Print { param($t) Write-UpdLog ([string]$t).Trim() }
        [pscustomobject]@{ Member = $s.Member; JustAdded = [bool]$s.JustAdded; State = [string]$s.State; Renewal = $s.Renewal; End = $s.End; Detail = [string]$s.Detail }
    } catch { & $unknown ('the membership could not be checked: {0}' -f $_.Exception.Message) }
}

function Save-SIUpdaterDbJobMembership {
    <# The membership's own row (cfg.InstallState 'DbJobMembership') -- what the heartbeat's setup step db-job says next to the
       job's result. A failure to write is a log line, never a stop. #>
    param($Store, [Parameter(Mandatory)][string]$State, $End = $null, [string]$Via = '', [string]$Why = '', [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        $v = New-SIDbInitMembershipRecordValue -State $State -End $End -Via $Via -Why $Why -NowUtc $NowUtc
        & $Store.Invoke (Get-SIDbInitRecordSql -Name (Get-SIDbInitNames).MembershipRecord) @{ Value = $v; Version = $null; By = 'caj-si-updater' } 'nonquery'
    } catch { Write-UpdLog ('the membership''s record could not be written: {0}' -f $_.Exception.Message) }
}

function Test-SIUpdaterDbJobSignInFailure {
    <# PURE. Did a run fail because its identity could not sign in yet (no row for this run -- the job writes none when it
       cannot sign in -- or a row whose reason is a refused sign-in)? Only such a run is started again after a NEW membership. #>
    param([bool]$Mine, $Record)
    if (-not $Mine) { return $true }
    $why = if ($Record -and $Record.PSObject.Properties['why']) { [string]$Record.why } else { '' }
    [bool]((Test-SIDbInitLoginRefused -Message $why) -or $why -match '(?i)could not sign in')
}

function Invoke-SIUpdaterDbJob {
    <#
        Framework SEC-08 (Invardia DESIGN ch 12, points 2, 5, 7, 9, 10) and §4.5 SQL-ADMIN-GROUP G2-G5: THE DATABASE SETUP JOB
        caj-si-dbinit on every update, BEFORE the database step (the release's setup\_shared\SI-DbInitJob.ps1 holds the
        design). In order:
          1. the job's identity id-si-dbinit and the job itself are kept present (ARM, Contributor on the resource group): the
             identity made when it is not there, the job PUT with the engine jobs' image, environment and pull identity and
             today's list of product identities (existing installs reach the new-install state through the update);
          1b. G5: the updater's own Microsoft Graph permissions CHECKED (its token's roles) -- a missing one is a warning naming
             who grants it; never a hold;
          1c. G2-G4: the job identity's membership of the SQL admin group CONVERGED (direct, else an active PIM-for-Groups
             assignment, read back) and RENEWED when it ends within 30 days. A renewal that fails while the assignment is
             still valid is a WARNING (and the membership's own row, which the heartbeat's db-job step says); the membership
             is written as its own row cfg.InstallState 'DbJobMembership';
          2. is the membership proven? A row the JOB wrote (state ok / failed), or the membership read in 1c. Neither: a
             'waiting' row is written, the heartbeat's setup step db-job asks for the one membership, and the update goes on
             on today's path (point 10). A membership that a run of the job PROVED, now GONE and not restorable, HOLDS the
             update (the job could not run: the installed version keeps running);
          3. the job is started (SI_DBINIT_BY updater, its own run id) and waited for; the run counts only when the execution
             Succeeded AND the row it wrote carries THIS run's id with state ok. A membership made in THIS run may not have
             reached the identity's token yet (live 2026-11-05: a run minutes after the PIM assignment failed, one 20 minutes
             later succeeded): a run that could not sign in is started again after a growing wait (-SettleWaits, said in the
             log); when they are used up the update goes on on today's path ('waiting'). Any other failed run HOLDS THE UPDATE
             (Ok = $false: nothing is rolled, the old version keeps running -- point 9).
        Anything the updater may not do itself (an ARM refusal, no engine job to take the image from) is one warning and the
        update goes on. Never throws. -Arm / -Lists / -Graph / -GraphRoles / -Sleep / -Now are test seams.
        Returns @{ Ok; Action = skipped | waiting | not-ready | ok | failed; Reason }.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, $Store, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId,
          [scriptblock]$Arm, [scriptblock]$Lists, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$TimeoutSeconds = 1500,
          [scriptblock]$Graph, [scriptblock]$GraphRoles, [int[]]$SettleWaits = @(300, 600, 900), [scriptblock]$Now = { [datetime]::UtcNow })
    $res = { param($ok, $a, $why) [pscustomobject]@{ Ok = $ok; Action = $a; Reason = $why } }
    try {
        if (-not $Store -or -not $Store.Invoke) { return (& $res $true 'skipped' 'no Pro database on this install') }
        $file = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-DbInitJob.ps1')
        if (-not (Test-Path -LiteralPath $file)) { return (& $res $true 'skipped' 'this release carries no database setup job') }
        . $file
        # framework §4.5 G2: the one add-and-wait policy the membership's direct add uses (Add-SIDbInitMember)
        $gm = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-GroupMemberAdd.ps1'); if (Test-Path -LiteralPath $gm) { . $gm }
        # the release's two install switches (SI_Setup_SignedGrantProcedure, SI_Setup_EngineLeastPrivilege) -- pure files
        foreach ($f in 'SI-GrantProcedure.ps1', 'SI-EngineGrants.ps1') { $p = [IO.Path]::Combine($SIRoot, 'engine', 'pro-settings', $f); if (Test-Path -LiteralPath $p) { . $p } }
        $n = Get-SIDbInitNames
        if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) Invoke-SIUpdaterArm -Method $Method -Path $Path -Body $Body -AllowNotFound:($Method -eq 'GET') } }
        if (-not $Lists) {
            $Lists = {
                param([string]$Kind)
                $prov = switch ($Kind) { 'jobs' { 'Microsoft.App/jobs' } 'apps' { 'Microsoft.App/containerApps' } default { 'Microsoft.ManagedIdentity/userAssignedIdentities' } }
                $api = if ($Kind -eq 'identities') { $n.MiApi } else { $n.AppApi }
                @(Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider $prov) -ApiVersion $api -List | Where-Object { $_ })
            }
        }
        # ---- 1. the identity and the job, kept present ----
        $jobs = @(& $Lists 'jobs'); $apps = @(& $Lists 'apps'); $ids = @(& $Lists 'identities')
        $tpl = Get-SIDbInitTemplateJob -Jobs $jobs
        if (-not $tpl.Ok) { $why = 'WARNING: the database setup job: {0} -- it is checked again at the next update' -f $tpl.Problem; Write-UpdLog $why; return (& $res $true 'not-ready' $why) }
        $mi = Set-SIDbInitIdentity -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Location $tpl.Location -Sleep $Sleep
        if (-not $mi.Ok) { $why = 'WARNING: the database setup job: {0} -- checked again at the next update' -f $mi.Problem; Write-UpdLog $why; return (& $res $true 'not-ready' $why) }
        if ($mi.Made) { Write-UpdLog ('the database setup job: its identity {0} was made' -f $n.Identity) }
        $nm = { param($role, $def) $v = ''; if (Get-Command -Name Get-SIInstallName -ErrorAction SilentlyContinue) { try { $v = [string](Get-SIInstallName -Role $role) } catch { $v = '' } }; if ("$v".Trim()) { "$v".Trim() } else { $def } }
        $principals = @(Get-SIDbInitPrincipals -Identities $ids -Jobs $jobs -Apps $apps -WebApp @((& $nm 'web' 'ca-si-management')) -McpApp @((& $nm 'mcp' 'ca-si-mcp')) `
                            -UpdaterJob @((& $nm 'updater' 'caj-si-updater')) -TaggingIdentity @((& $nm 'taggingIdentity' 'uami-securityinsight-tagging'), 'id-si-tagging'))
        if (-not @($principals | Where-Object { $_.component -eq 'engine' }).Count) { $why = 'WARNING: the database setup job: the engine identity was not found on the engine jobs -- checked again at the next update'; Write-UpdLog $why; return (& $res $true 'not-ready' $why) }
        $signed = $false; $roleOnly = $false
        try { if (Get-Command -Name Test-SIGrantProcedureSetup -ErrorAction SilentlyContinue) { $signed = [bool](Test-SIGrantProcedureSetup) } } catch { }
        try { if (Get-Command -Name Test-SIEngineLeastPrivilegeSetup -ErrorAction SilentlyContinue) { $roleOnly = [bool](Test-SIEngineLeastPrivilegeSetup) } } catch { }
        $server = if ($Store.PSObject.Properties['Server'] -and $Store.Server) { [string]$Store.Server } else { '' }
        if (-not $server) { $why = 'WARNING: the database setup job: the database server is not known to this run -- checked again at the next update'; Write-UpdLog $why; return (& $res $true 'not-ready' $why) }
        $db = if ($Store.PSObject.Properties['Database'] -and $Store.Database) { [string]$Store.Database } else { $n.ProDatabase }
        # the job's lines reach the install's Log Analytics workspace (a warning only, never a hold)
        if (Get-Command -Name Set-SIDbInitEnvironmentLogs -ErrorAction SilentlyContinue) { Write-UpdLog ((Set-SIDbInitEnvironmentLogs -Arm $Arm -EnvironmentId $tpl.EnvironmentId -WorkspaceResourceId $tpl.WorkspaceResourceId).Line) }
        $body = Get-SIDbInitJobBody -Location $tpl.Location -EnvironmentId $tpl.EnvironmentId -Image $tpl.Image -RegistryServer $tpl.RegistryServer -PullIdentityId $tpl.PullIdentityId `
                    -IdentityId $mi.Id -IdentityClientId $mi.ClientId -Server $server -Database $db -LedgerDatabase $n.LedgerDatabase -Principals $principals -SignedGrants $signed -EngineRoleOnly $roleOnly
        $job = Set-SIDbInitJob -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Body $body -Sleep $Sleep
        if (-not $job.Ok) { $why = 'WARNING: the database setup job: {0} -- checked again at the next update' -f $job.Problem; Write-UpdLog $why; return (& $res $true 'not-ready' $why) }
        # ---- 1b. G5: the updater's own Graph permissions, checked (never granted here; never a hold) ----
        $null = Test-SIUpdaterGraphRights -GraphRoles $GraphRoles
        # ---- 1c. G2-G4: the job identity's membership of the SQL admin group, converged and renewed ----
        $nowUtc = & $Now
        if (-not $Graph) { $Graph = { param([string]$Method, [string]$Uri, $Body) Invoke-SIRestJson -Rest (Get-SIUpdaterRest) -Method $Method -Uri $Uri -Body $Body -Resource 'https://graph.microsoft.com/' } }
        $mem = Invoke-SIUpdaterDbJobMembership -Arm $Arm -Graph $Graph -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Server $server -PrincipalId $mi.PrincipalId -Sleep $Sleep -NowUtc $nowUtc
        $ren = $mem.Renewal
        if ($mem.Member -eq $true) {
            Write-UpdLog ('the database setup job {0}: {1}' -f $n.Job, $mem.Detail)
            if ($ren -and [string]$ren.State -eq 'failed') {
                Write-UpdLog ('WARNING: the database setup job {0}: its membership of the SQL admin group could not be renewed ({1}) -- it is still valid, so the update goes on; tried again at the next update' -f $n.Job, $ren.Detail)
                Save-SIUpdaterDbJobMembership -Store $Store -State 'renewal-failed' -End $ren.End -Via $mem.State -Why $ren.Detail -NowUtc $nowUtc
            } else {
                if ($ren -and [string]$ren.State -in 'renewed', 'current') { Write-UpdLog ('the database setup job {0}: {1}' -f $n.Job, $ren.Detail) }
                Save-SIUpdaterDbJobMembership -Store $Store -State 'ok' -End $(if ($ren) { $ren.End } else { $null }) -Via $mem.State -NowUtc $nowUtc
            }
        } elseif ($mem.State -eq 'unknown') {
            Write-UpdLog ('the database setup job {0}: its membership of the SQL admin group was not checked ({1}) -- the job''s own last result decides' -f $n.Job, $mem.Detail)
        } else {
            Write-UpdLog ('the database setup job {0}: its identity {1} is not a member of the SQL admin group and could not be made one ({2})' -f $n.Job, $n.Identity, $mem.Detail)
        }
        # ---- 2. is the membership proven (a row the JOB wrote, or read above)? ----
        $row = @(& $Store.Invoke (Get-SIDbInitRecordReadSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        $rec = ConvertFrom-SIDbInitRecordValue -Value ([string](Get-SIDbInitProp $row @('Value')))
        $proven = [bool]($rec -and [string]$rec.state -in 'ok', 'failed')
        if ($proven -and $mem.Member -eq $false) {
            # a membership a run of the job PROVED is gone, and it could not be made again: the job cannot sign in -- held
            Save-SIUpdaterDbJobMembership -Store $Store -State 'gone' -Why $mem.Detail -NowUtc $nowUtc
            $why = 'the database setup job {0}: its identity {1} is no longer a member of the SQL admin group and could not be made one again ({2}) -- the update is held, the installed version keeps running; Invardia is told, and the next update run tries to make it again and runs the job by itself' -f $n.Job, $n.Identity, $mem.Detail
            Write-UpdLog ('WARNING: ' + $why)
            return (& $res $false 'failed' $why)
        }
        if (-not $proven -and $mem.Member -ne $true) {
            if ($mem.Member -eq $false) { Save-SIUpdaterDbJobMembership -Store $Store -State 'missing' -Why $mem.Detail -NowUtc $nowUtc }
            if (-not $rec) {
                try { & $Store.Invoke (Get-SIDbInitRecordSql) @{ Value = (New-SIDbInitRecordValue -State 'waiting' -By 'updater' -Why 'not run yet: the identity of the job must be added once to the SQL admin group'); Version = $null; By = 'caj-si-updater' } 'nonquery' } catch { }
            }
            $why = 'the database setup job {0} is ready, but has not run yet: its identity {1} must be added once to the SQL admin group (Invardia support, or the customer); until then this update keeps today''s path' -f $n.Job, $n.Identity
            Write-UpdLog $why
            return (& $res $true 'waiting' $why)
        }
        # ---- 3. the run (a failure holds the update; a run after a NEW membership is given time to reach the token) ----
        Write-UpdLog ('the database setup job {0}: started ({1})' -f $n.Job, $(if ($mem.JustAdded) { 'its identity became a member of the SQL admin group in this run' } elseif ($mem.Member -eq $true) { 'its identity is a member of the SQL admin group, read back' } else { 'its identity is a member of the SQL admin group since its run of ' + [string]$rec.at }))
        # #1151 (1) SEC-01: the recorded Support app named to the run, so the job takes its STANDING db_owner off where the
        # just-in-time path reads back (setup\_shared\SI-SupportStandingUpdate.ps1); never after a deliberate rollback
        $so = Get-SIUpdaterSupportStandingInput -SIRoot $SIRoot -Store $Store
        $extra = @{}; if ($so.ClientId) { $extra['SI_DBINIT_SUPPORT_STANDING_OFF'] = $so.ClientId }
        if ($so.Why) { Write-UpdLog $so.Why }
        $settle = @($SettleWaits | Where-Object { $_ -gt 0 })
        $try = 0
        while ($true) {
            $r = Start-SIDbInitRun -Arm $Arm -JobId $job.JobId -Job $job.Job -By 'updater' -TimeoutSeconds $TimeoutSeconds -Sleep $Sleep -Extra $extra
            # #1146: THIS run's result -- the updater's own row first (DbJobUpdater: a support run started beside this update
            # writes its own row and can never overwrite it), else the shared row; a row of another run is never taken
            $after = $null; $other = $null
            $readRow = { param($nm) try { $x = @(& $Store.Invoke (Get-SIDbInitRecordReadSql -Name $nm) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1; ConvertFrom-SIDbInitRecordValue -Value ([string](Get-SIDbInitProp $x @('Value'))) } catch { $null } }
            foreach ($nm in @($(if (Get-Command -Name Get-SIDbInitCallerRecordName -ErrorAction SilentlyContinue) { Get-SIDbInitCallerRecordName -By 'updater' }), '') | Select-Object -Unique) {
                $cand = & $readRow $nm
                if ($cand -and $cand.PSObject.Properties['run'] -and [string]$cand.run -eq $r.Run) { $after = $cand; break }
                if (-not $nm -and $cand) { $other = $cand }
            }
            if (-not $after) { $after = $other }
            $mine = [bool]($after -and $after.PSObject.Properties['run'] -and [string]$after.run -eq $r.Run)
            if ($r.Ok -and $mine -and [string]$after.state -eq 'ok') {
                Write-UpdLog ('the database setup job {0}: every identity read back ({1}; execution {2})' -f $n.Job, [string]$after.n, $r.Execution)
                if ($so.ClientId) { $null = Invoke-SIUpdaterSupportStanding -Store $Store -Graph $Graph -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Server $server -ClientId $so.ClientId -Run $r.Run -NowUtc (& $Now) -SIRoot $SIRoot }
                return (& $res $true 'ok' ('every identity read back (execution {0})' -f $r.Execution))
            }
            if (-not ($mem.JustAdded -and (Test-SIUpdaterDbJobSignInFailure -Mine $mine -Record $after))) { break }
            if ($try -ge $settle.Count) {
                $why = 'the database setup job {0}: its identity became a member of the SQL admin group in this run, but after {1} runs the membership has still not reached its sign-in (last execution {2}) -- this update keeps today''s path; the next update runs it again' -f $n.Job, ($try + 1), $(if ($r.Execution) { $r.Execution } else { 'not started' })
                Write-UpdLog ('WARNING: ' + $why)
                return (& $res $true 'waiting' $why)
            }
            $w = [int]$settle[$try]; $try++
            Write-UpdLog ('the database setup job {0}: run {1} could not sign in yet -- its identity became a member of the SQL admin group only in this run and the membership has not reached its token; started again in {2} s (try {3} of {4})' -f $n.Job, $(if ($r.Execution) { $r.Execution } else { '(not started)' }), $w, ($try + 1), ($settle.Count + 1))
            & $Sleep $w
        }
        $why = 'the database setup job {0} did not complete (execution {1}: {2}{3}) -- the update is held, the installed version keeps running; Invardia is told, and the next update run starts the job again by itself; {4}' -f $n.Job, $(if ($r.Execution) { $r.Execution } else { 'not started' }), $r.Status,
                   $(if ($mine -and $after.PSObject.Properties['why'] -and [string]$after.why) { '; ' + [string]$after.why } elseif (-not $mine -and $after -and $after.PSObject.Properties['run'] -and [string]$after.run) { '; it recorded no result for this run -- the last result is of another run of the job ({0}{1}), started beside this update' -f [string]$after.run, $(if ($after.PSObject.Properties['by'] -and [string]$after.by) { ', by ' + [string]$after.by } else { '' }) } elseif (-not $mine) { '; it recorded no result for this run' } else { '' }), (Get-SIDbInitLogText -ResourceGroup $ResourceGroup -Execution $r.Execution)
        Write-UpdLog ('WARNING: ' + $why)
        & $res $false 'failed' $why
    } catch {
        $why = 'WARNING: the database setup job could not be checked ({0}) -- checked again at the next update' -f $_.Exception.Message
        Write-UpdLog $why
        & $res $true 'not-ready' $why
    }
}

function Get-SIUpdaterSupportStandingInput {
    <#
        #1151 (1) SEC-01, step 1 (setup\_shared\SI-SupportStandingUpdate.ps1): the Support app the updater names to its run of
        the database setup job -- the one recorded on the install, never after a deliberate rollback. Returns @{ ClientId
        ('' = none); Why }. Never throws: anything unreadable = none (the job then changes nothing of the Support app).
        The file is dot-sourced into THIS function's scope; the step-3 call loads it again in its own (pure functions only).
    #>
    param([Parameter(Mandatory)][string]$SIRoot, $Store)
    try {
        $lib = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-SupportStandingUpdate.ps1')
        if (-not $Store -or -not $Store.Invoke -or -not (Test-Path -LiteralPath $lib)) { return [pscustomobject]@{ ClientId = ''; Why = '' } }
        . $lib
        $row = @(& $Store.Invoke (Get-SISupportStandingInputSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        $get = { param($k) if ($null -eq $row) { '' } elseif ($row -is [System.Collections.IDictionary]) { [string]$row[$k] } elseif ($row -is [System.Data.DataRow]) { $x = $row[$k]; if ($x -is [System.DBNull]) { '' } else { [string]$x } } elseif ($row.PSObject.Properties[$k]) { [string]$row.$k } else { '' } }
        Get-SISupportStandingOffInput -SupportApp (& $get 'SupportApp') -Cutover (& $get 'Cutover')
    } catch { [pscustomobject]@{ ClientId = ''; Why = ('support standing access: not checked ({0}) -- checked again at the next update' -f $_.Exception.Message) } }
}

function Invoke-SIUpdaterSupportStanding {
    <#
        #1151 (1) SEC-01, step 3 (setup\_shared\SI-SupportStandingUpdate.ps1, Invoke-SISupportStandingCheck): after THIS run of
        the database setup job -- its standing-off row read, the Support app's membership of the SQL admin group read from the
        member's side (the updater's read-only Graph rights), the state row and the cut-over record written, every line said.
        The group = the SQL server's Entra administrator (ARM). The update never removes a member and never touches the
        server's administrator. Never throws, never holds the update.
        -Recheck: step 4, the read-only re-check of every run (Invoke-SIUpdaterSupportStandingRecheck) -- no job run behind it.
    #>
    param([Parameter(Mandatory)]$Store, [scriptblock]$Graph, [scriptblock]$Arm, [string]$SubscriptionId, [string]$ResourceGroup, [string]$Server,
          [Parameter(Mandatory)][string]$ClientId, [string]$Run = '', [datetime]$NowUtc = [datetime]::UtcNow, [string]$SIRoot = '', [switch]$Recheck)
    try {
        $lib =if ($SIRoot) { [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-SupportStandingUpdate.ps1') } else { '' }
        if ($lib -and (Test-Path -LiteralPath $lib)) { . $lib }
        if (-not (Get-Command -Name Invoke-SISupportStandingCheck -ErrorAction SilentlyContinue)) { return $null }
        $gid = ''; $gname = 'the SQL admin group'
        try {
            $name = (($Server -split '\.')[0]).Trim()
            if ($Arm -and $name -match '^[a-z0-9][a-z0-9-]{0,62}$') {
                $srv = & $Arm 'GET' ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Sql/servers/{2}?api-version={3}' -f $SubscriptionId, $ResourceGroup, $name, (Get-SIDbInitNames).SqlApi) $null
                $gid = [string](Get-SIDbInitAdminGroupId -Server $srv)
                $login = [string](Get-SIDbInitProp $srv @('properties', 'administrators', 'login')); if ($login) { $gname = $login }
            }
        } catch { $gid = '' }
        $v = Invoke-SISupportStandingCheck -Store $Store -Graph $Graph -ClientId $ClientId -Run $Run -GroupId $gid -GroupName $gname -ResourceGroup $ResourceGroup -NowUtc $NowUtc -Recheck:$Recheck
        foreach ($l in @($v.Lines)) { Write-UpdLog $l }
        $v
    } catch { Write-UpdLog ('support standing access: not checked ({0}) -- checked again at the next update' -f $_.Exception.Message); $null }
}

function Invoke-SIUpdaterSupportStandingRecheck {
    <#
        #1151 (1) SEC-01, step 4 (setup\_shared\SI-SupportStandingUpdate.ps1): the state row 'SupportStanding' re-checked on
        EVERY updater run -- also one that installs nothing (live 2026-11-09: the row stayed 'missing' for hours after Invardia
        support removed the standing admin, because only an update that installed a release, after its database setup job,
        refreshed it). READ ONLY and WITHOUT the database setup job: the membership of the SQL admin group read now (the
        updater's read-only Graph rights), db_owner from the newest read-back on record. Only for the Support app recorded on
        the install; never after a deliberate rollback (Get-SIUpdaterSupportStandingInput names none then). The update never
        removes a member, never touches a role or the server's administrator. Never throws, never holds the update.
        -Arm / -Graph are test seams (the updater's own REST calls otherwise).
    #>
    param([Parameter(Mandatory)][string]$SIRoot, $Store, [string]$SubscriptionId, [string]$ResourceGroup, [string]$Server,
          [scriptblock]$Arm, [scriptblock]$Graph, [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        if (-not $Store -or -not $Store.Invoke) { return $null }
        $so = Get-SIUpdaterSupportStandingInput -SIRoot $SIRoot -Store $Store
        if ($so.Why) { Write-UpdLog $so.Why }
        if (-not $so.ClientId) { return $null }
        # the server's Entra administrator group is read with the database setup job's pure helpers (no job is run)
        $dj = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-DbInitJob.ps1'); if (Test-Path -LiteralPath $dj) { . $dj }
        if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) Invoke-SIUpdaterArm -Method $Method -Path $Path -Body $Body -AllowNotFound:($Method -eq 'GET') } }
        if (-not $Graph) { $Graph = { param([string]$Method, [string]$Uri, $Body) Invoke-SIRestJson -Rest (Get-SIUpdaterRest) -Method $Method -Uri $Uri -Body $Body -Resource 'https://graph.microsoft.com/' } }
        Invoke-SIUpdaterSupportStanding -Store $Store -Graph $Graph -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Server $Server -ClientId $so.ClientId -NowUtc $NowUtc -SIRoot $SIRoot -Recheck
    } catch { Write-UpdLog ('support standing access: not re-checked ({0}) -- checked again at the next update' -f $_.Exception.Message); $null }
}

function Invoke-SIUpdaterSupportAppRecord {
    <#
        #1161 (agreed with Invardia 2026-11-10): on EVERY run of a Pro install, the Invardia Support app's client id is
        recorded (cfg.InstallState 'SupportApp') where that record is missing -- read from the install's own Support app
        database user (its SID), checked, written once (insert only), read back (setup\_shared\SI-SupportAppRecordUpdate.ps1).
        RECORDS ONLY: never a role, a grant, a user or a group membership (the just-in-time cut-over holds). Runs before the
        standing re-check, which reads that record. A Community install (no Pro database) = nothing done, nothing said.
        -ExpectedClientId: an id Invardia names for the install -- Invardia sends none to the updater today, so Start-SIUpdater
        passes none. Never throws, never holds the update.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, $Store, [string]$Edition = [string]$global:SI_UpdaterEdition, [string]$ExpectedClientId = '')
    try {
        if ($Edition -ieq 'community' -or -not $Store -or -not $Store.Invoke) { return $null }
        $lib = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-SupportAppRecordUpdate.ps1')
        if (-not (Test-Path -LiteralPath $lib)) { return $null }
        . $lib
        $r = Invoke-SISupportAppRecordStep -Store $Store -ExpectedClientId $ExpectedClientId
        foreach ($l in @($r.Lines)) { Write-UpdLog $l }
        $r
    } catch { Write-UpdLog ('support app record: not checked ({0}) -- checked again at the next update' -f $_.Exception.Message); $null }
}

function Invoke-SIUpdaterIndexBuildJob {
    <#
        #1111 (owner 2026-11-05: "why not split this into 2 jobs" / "we cannot have env that doesnt upd suddently"): THE INDEX
        BUILD JOB caj-si-index-build kept present on every Pro run -- new installs and existing ones alike -- and READ BACK
        (engine\index-build\SI-IndexBuildJob.ps1, Invoke-SIIndexBuildJobEnsure): the engine jobs' image, environment and pull
        identity, THIS updater's own managed identity (the identity the index builds have always run as: no new grant), the
        Pro database. The pipeline runner's idle wake-up starts it; the updater itself never builds a waiting index and has
        run mode for it -- an update never waits for an index build (the run gate takes that job's lock at once).
        One line; never throws, never fails or holds the update. -Arm / -Lists / -Sleep are test seams.
    #>
    param([string]$SIRoot, $Store, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [string]$UpdaterJob = 'caj-si-updater',
          [scriptblock]$Arm, [scriptblock]$Lists, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    try {
        if (-not $Store) { return [pscustomobject]@{ Ok = $true; Action = 'skipped'; Reason = 'no Pro database on this install' } }
        foreach ($rel in @('engine/_shared/SI-IndexBuild.ps1', 'setup/_shared/SI-DbInitJob.ps1', 'engine/index-build/SI-IndexBuildJob.ps1')) {
            $f = if ($SIRoot) { [IO.Path]::Combine($SIRoot, $rel) } else { '' }
            if (-not $f -or -not (Test-Path -LiteralPath $f)) { return [pscustomobject]@{ Ok = $true; Action = 'skipped'; Reason = 'this release carries no index build job' } }
            . $f
        }
        $api = (Get-SIIndexBuildJobNames).AppApi
        # (the paths carry their api-version, as the database setup job's do)
        if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) Invoke-SIUpdaterArm -Method $Method -Path $Path -Body $Body -AllowNotFound:($Method -eq 'GET') } }
        if (-not $Lists) { $Lists = { param([string]$Kind) @(Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider 'Microsoft.App/jobs') -ApiVersion $api -List | Where-Object { $_ }) } }
        $server = if ($Store.PSObject.Properties['Server'] -and $Store.Server) { [string]$Store.Server } else { '' }
        $db = if ($Store.PSObject.Properties['Database'] -and $Store.Database) { [string]$Store.Database } else { '' }
        $r = Invoke-SIIndexBuildJobEnsure -Arm $Arm -Lists $Lists -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Server $server -Database $db -UpdaterJob $UpdaterJob -Sleep $Sleep
        Write-UpdLog $r.Reason
        $r
    } catch {
        $why = 'WARNING: the index build job could not be checked ({0}) -- checked again at the next update' -f $_.Exception.Message
        Write-UpdLog $why
        [pscustomobject]@{ Ok = $false; Action = 'failed'; Reason = $why }
    }
}
