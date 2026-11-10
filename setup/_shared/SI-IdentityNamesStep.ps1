#Requires -Version 5.1
<#
    SecurityInsight -- THE UPDATER'S STEP 'identity-names' (framework §5.5: every SI identity carries its standard name at every
    install -- id-si-engine / id-si-web / id-si-mcp / id-si-updater / id-si-tagging, id-si-dbinit already; owner 2026-11-04,
    critical; SI REQUIREMENTS #1145). A managed identity cannot be renamed, so the update MOVES each role to a new identity
    with the identity move (setup\_shared\SI-IdentityMove.ps1, Ctx.Mode 'updater'), on every run, idempotent and resumable:
    each run carries every role as far as it can and stops a role at the first step that is not done -- nothing is lost,
    the old identity keeps working until the very end.

      roles, in order   engine, web, mcp, tagging, then the updater ITSELF LAST: its switch waits until every other role is
                        proven, the next update runs as the new identity and proves it with its own token, and only an update
                        running AS the new identity removes the old one
      per role          inventory -> ensure (id-si-<role>) -> copy-rights (Azure / Graph / Key Vault / federated credential as
                        the updater may; the SQL users, roles and grants in EVERY product database through the database setup
                        job caj-si-dbinit, read back) -> switch (environment client ids, the web app's sign-in client id, Key
                        Vault references, the registry pull identity; never during a pipeline run) -> prove (the next real
                        run, a healthy revision) -> clean-up (only when every role is proven; the old SQL user dropped only
                        where the new one reads back holding all of it) -> the report (cfg.InstallState 'IdentityNames')
      what it may not   a right the updater may not READ or GRANT (an Azure scope above its resource group, Graph app roles,
                        Entra roles, Exchange) is a SUPPORT STEP -- the same move through the Invardia Support app, per install,
                        with a reason (ops identity move); never a customer action line. The role waits for it.
      tagging           an install without asset tagging's identity gets id-si-tagging only when asset tagging is on
                        (SI_AssetTagging_Enabled); its rights are Grant-SIIdentity -Tagging (a support step)
      mode              cfg.InstallState 'IdentityMoveMode': plan (DEFAULT -- the per-install plan in the log and the report,
                        nothing changed) | apply (set through the Support app once the install's plan is approved) | off

    Never throws; never fails the update. The seams are handed in by the caller (container\updater\Start-SIUpdater.ps1) and
    by the tests: -Arm / -Graph { param($Method, $Uri, $Body) -> @{ StatusCode; Content } }, -Sql { param($Server, $Database,
    $Query, [bool]$Change) -> rows }, -JobArm (SI-DbInitJob's ARM shape: parsed, $null on a GET 404, throws otherwise),
    -Sleep. PS 5.1 and 7; no module.
#>

function Get-SIIdentityNamesRoleOrder { <# PURE. The order the update moves the roles in: the updater itself last. #> @('engine', 'web', 'mcp', 'tagging', 'updater') }

function Get-SIIdentityNamesLogLine {
    <# PURE. One line of a step for the update's log: a warning keeps WARNING at the start of the line, where a reader looks. #>
    param([Parameter(Mandatory)][string]$Role, [Parameter(Mandatory)][string]$Step, [AllowEmptyString()][string]$Line = '')
    if ($Line -like 'WARNING: *') { return ('WARNING: identity names [{0}/{1}] {2}' -f $Role, $Step, $Line.Substring(9)) }
    'identity names [{0}/{1}] {2}' -f $Role, $Step, $Line
}

function Test-SIIdentityNamesTaggingOn {
    <# PURE. Is asset tagging on (the customer setting SI_AssetTagging_Enabled, cfg.Setting scope 'solution')? Only a real
       true -- the same reading as the engine's (container\_shared\SI-ContainerConfig.ps1). -Rows: cfg.Setting rows. #>
    param([object[]]$Rows = @())
    $r = @($Rows | Where-Object { $_ -and [string](Get-SIMoveProp $_ @('Name')) -eq 'SI_AssetTagging_Enabled' })[0]
    if (-not $r) { return $false }
    $v = [string](Get-SIMoveProp $r @('ValueJson'))
    try { $v = [string]($v | ConvertFrom-Json -ErrorAction Stop) } catch { }
    "$v".Trim() -match '^(?i)(true|1|yes|on)$'
}

function Get-SIIdentityNamesSummary {
    <# PURE. One line per role from its step results: the last step and its state (done = moved / nothing to do). #>
    param([Parameter(Mandatory)][string]$Role, [object[]]$Results = @())
    $r = @($Results | Where-Object { $_ })
    if (-not $r.Count) { return [pscustomobject]@{ Role = $Role; Step = ''; State = 'n/a'; Line = ('{0}: nothing to do' -f $Role) } }
    $last = $r[-1]
    $bad = @($r | Where-Object { $_.State -notin 'done', 'n/a', 'planned' })[0]
    $at = if ($bad) { $bad } else { $last }
    [pscustomobject]@{ Role = $Role; Step = [string]$at.Step; State = [string]$at.State; Line = ('{0}: {1} {2}' -f $Role, $at.Step, $at.State) }
}

function Invoke-SIIdentityNamesTaggingEnsure {
    <# Asset tagging's own identity at an install that has none, only when asset tagging is on: id-si-tagging made in the
       install's resource group (the engine identity's location), read back. Its rights are a support step (Grant-SIIdentity
       -Tagging through the Support app; its database user comes with the database setup job's next run). #>
    param([Parameter(Mandatory)][hashtable]$Ctx)
    $std = (Get-SIIdentityMoveRoleTable)['tagging'].Standard
    $ref = @($Ctx.Identities | Where-Object { $_ -and $_.Location })[0]
    $loc = if ($ref) { [string]$ref.Location } else { '' }
    $path = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{2}?api-version={3}' -f $Ctx.SubscriptionId, $Ctx.ResourceGroup, $std, $script:SIMove.MiApi
    $cust = New-SIIdentityMoveCustomerStep -Role tagging -Kind tagging-rights -Key 'tagging-rights' -What ('Asset tagging is on and its own identity {0} needs its rights (Grant-SIIdentity.ps1 -IdentityName {0} -Tagging).' -f $std) -How 'x'
    if (-not $loc) { return New-SIIdentityMoveStepResult -Step ensure -State stop -Lines @(('asset tagging is on but {0} cannot be made: no identity of the install shows the location' -f $std)) }
    if (-not $Ctx.Apply) { return New-SIIdentityMoveStepResult -Step ensure -State planned -Lines @(('plan: asset tagging is on and the install has no identity of its own for it: PUT {0} in {1} ({2}); its rights through the Support app' -f $std, $Ctx.ResourceGroup, $loc)) -CustomerSteps @($cust) }
    $w = Invoke-SIMoveArm -Method PUT -Path $path -Body ([ordered]@{ location = $loc; tags = [ordered]@{ product = 'securityinsight'; 'si-component' = 'tagging' } }) -Reason $Ctx.Reason
    if ($w.Status -notin 200, 201) { return New-SIIdentityMoveStepResult -Step ensure -State stop -Lines @(('{0} could not be made: HTTP {1}' -f $std, $w.Status)) }
    $made = $null
    for ($i = 0; $i -lt $script:SIMove.Waits.Tries; $i++) {
        $g = Invoke-SIMoveArm -Path $path -Reason $Ctx.Reason
        if ($g.Status -eq 200) { $made = ConvertTo-SIIdentityMoveIdentity $g.Body; if ($made.ClientId -and $made.PrincipalId) { break } }
        Invoke-SIMoveSleep -Seconds $script:SIMove.Waits.Seconds
    }
    if (-not $made -or -not $made.ClientId) { return New-SIIdentityMoveStepResult -Step ensure -State waits -Lines @(('{0} was made but does not read back with its client id yet -- the next update checks it' -f $std)) }
    $Ctx.Identities = @(@($Ctx.Identities) + @($made))
    New-SIIdentityMoveStepResult -Step ensure -State customer -Lines @(('made: {0} (client id {1}, read back) -- asset tagging''s own identity; its rights through the Support app' -f $std, $made.ClientId)) -CustomerSteps @($cust)
}

function Invoke-SIIdentityNamesDbJob {
    <#
        The identity move's SQL through the database setup job caj-si-dbinit (it is the SQL admin; the update's own identity may
        not make users): ONE grants-only execution (it may run beside a pipeline run) with SI_DBINIT_MOVES / SI_DBINIT_DROPS and
        today's SI_DBINIT_PRINCIPALS (the identity each app / job signs in as NOW), waited for; the answer is the row the job
        wrote for THIS run (cfg.InstallState 'DbJobMoves'). No job at the install yet = 'waits:' (an update's database step makes
        it). Returns @{ Ok; States; Why }. -JobArm: SI-DbInitJob's ARM seam; -ReadRow { param($Name) } -> the row's value.
    #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [object[]]$Moves = @(), [object[]]$Drops = @(), [Parameter(Mandatory)][scriptblock]$JobArm,
          [Parameter(Mandatory)][scriptblock]$ReadRow, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$TimeoutSeconds = 1500)
    $no = { param($w) [pscustomobject]@{ Ok = $false; States = @{}; Why = $w } }
    try {
        if (-not (Get-Command -Name Start-SIDbInitRun -ErrorAction SilentlyContinue)) { return (& $no 'waits: this release carries no database setup job') }
        $n = Get-SIDbInitNames
        $jobId = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}' -f $Ctx.SubscriptionId, $Ctx.ResourceGroup, $n.Job
        $job = & $JobArm 'GET' ('{0}?api-version={1}' -f $jobId, $n.AppApi) $null
        if (-not $job) { return (& $no 'waits: the database setup job is not at this install yet (an update''s database step makes it)') }
        $raw = @($Ctx.Identities | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ name = $_.Name; id = $_.Id; properties = [pscustomobject]@{ clientId = $_.ClientId; principalId = $_.PrincipalId } } })
        $nm = { param($role, $def) $v = ''; if (Get-Command -Name Get-SIInstallName -ErrorAction SilentlyContinue) { try { $v = [string](Get-SIInstallName -Role $role) } catch { $v = '' } }; if ("$v".Trim()) { @("$v".Trim(), $def) } else { @($def) } }
        $principals = @(Get-SIDbInitPrincipals -Identities $raw -Jobs @($Ctx.Jobs) -Apps @($Ctx.Apps) -WebApp @((& $nm 'web' 'ca-si-management') + 'ca-si-web') -McpApp @(& $nm 'mcp' 'ca-si-mcp') `
                            -UpdaterJob @(& $nm 'updater' 'caj-si-updater') -TaggingIdentity @('id-si-tagging', 'uami-securityinsight-tagging'))
        $extra = [ordered]@{}
        if (@($principals | Where-Object { $_.component -eq 'engine' }).Count) { $extra.SI_DBINIT_PRINCIPALS = (ConvertTo-Json -InputObject @($principals) -Compress -Depth 5) }
        if (@($Moves).Count) { $extra.SI_DBINIT_MOVES = (ConvertTo-Json -InputObject @($Moves) -Compress -Depth 5) }
        if (@($Drops).Count) { $extra.SI_DBINIT_DROPS = (ConvertTo-Json -InputObject @($Drops) -Compress -Depth 5) }
        $r = Start-SIDbInitRun -Arm $JobArm -JobId $jobId -Job $job -By 'updater' -Steps 'grants' -Extra $extra -TimeoutSeconds $TimeoutSeconds -Sleep $Sleep
        $val = ''; try { $val = [string](& $ReadRow 'DbJobMoves') } catch { $val = '' }
        $rec = $null; try { if ($val) { $rec = $val | ConvertFrom-Json -ErrorAction Stop } } catch { $rec = $null }
        if (-not $rec -or [string](Get-SIMoveProp $rec @('run')) -ne [string]$r.Run) {
            return (& $no ('the database setup job recorded no identity move result for its run (execution {0}: {1})' -f $(if ($r.Execution) { $r.Execution } else { 'not started' }), $r.Status))
        }
        $states = @{}
        $c = Get-SIMoveProp $rec @('c')
        if ($c) { foreach ($p in @($c.PSObject.Properties)) { $states[[string]$p.Name] = [string]$p.Value } }
        $bad = @($states.Keys | Where-Object { $states[$_] -eq 'failed' })
        [pscustomobject]@{ Ok = (-not $bad.Count); States = $states; Why = $(if ($bad.Count) { 'the database setup job could not copy or read back: {0} (execution {1})' -f ($bad -join ', '), $r.Execution } else { 'execution {0}' -f $r.Execution }) }
    } catch { & $no ('the database setup job could not be run: {0}' -f $_.Exception.Message) }
}

function Invoke-SIUpdaterIdentityNames {
    <#
        THE STEP (see the file's header). -SIRoot: the SecurityInsight folder the update carries (/si in the updater image).
        Returns @{ Mode; Roles (summaries); Lines; Support (support-step texts); Failed (a step that stopped: Invardia hears it);
        Ran }. Never throws.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$TenantId = '', [string]$SelfClientId = '', [string]$SelfExecution = '', [ValidateSet('ManagedIdentity', 'Certificate')][string]$SelfAuth = 'ManagedIdentity',
          [Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][scriptblock]$Sql,
          [scriptblock]$JobArm, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Log = { param($m) Write-Host $m },
          [int]$DbJobTimeoutSeconds = 1500)
    $out = [pscustomobject]@{ Mode = 'plan'; Roles = @(); Lines = @(); Support = @(); Failed = @(); Ran = $false }
    $lines = New-Object System.Collections.Generic.List[string]; $support = New-Object System.Collections.Generic.List[string]; $failed = New-Object System.Collections.Generic.List[string]
    $say = { param($m) $lines.Add([string]$m); try { $null = & $Log ([string]$m) } catch { } }
    try {
        $lib = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-IdentityMove.ps1')
        if (-not (Test-Path -LiteralPath $lib)) { & $say 'identity names: this release carries no identity move -- nothing checked'; $out.Lines = $lines.ToArray(); return $out }
        . $lib
        $dbLib = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-DbInitJob.ps1')
        if ((Test-Path -LiteralPath $dbLib) -and -not (Get-Command -Name Start-SIDbInitRun -ErrorAction SilentlyContinue)) { . $dbLib }
        $script:SIMove.ChangedBy = 'caj-si-updater (identity names)'
        # the step's own I/O: ARM / Graph / SQL as the updater; the database side through the database setup job
        $siInDbJob = $null
        if ($JobArm) {
            $siInJobArm = $JobArm; $siInSleep = $Sleep; $siInTimeout = $DbJobTimeoutSeconds; $siInSqlSeam = $Sql
            $siInDbJob = {
                param($Ctx, [object[]]$Moves, [object[]]$Drops)
                $read = { param($Name) $q = "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'$Name';"; $row = @(& $siInSqlSeam $Ctx.SqlServer $Ctx.StateDatabase $q $false)[0]; if ($row) { [string](Get-SIMoveProp $row @('Value')) } else { '' } }
                Invoke-SIIdentityNamesDbJob -Ctx $Ctx -Moves $Moves -Drops $Drops -JobArm $siInJobArm -ReadRow $read -Sleep $siInSleep -TimeoutSeconds $siInTimeout
            }
        }
        Set-SIIdentityMoveIo -Arm $Arm -Graph $Graph -Sql $Sql -DbJob $siInDbJob -Sleep $Sleep
        $ctx = @{
            Handle = 'install'; Role = ''; Reason = 'SecurityInsight update: identity names'; Apply = $false; OldName = ''
            TenantId = $TenantId; Subscriptions = @($SubscriptionId); SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup
            Mode = 'updater'; SqlVia = $(if ($JobArm) { 'dbjob' } else { 'none' }); SelfClientId = "$SelfClientId".Trim().ToLowerInvariant(); SelfExecution = "$SelfExecution".Trim(); SelfAuth = $SelfAuth
        }
        $init = Initialize-SIMoveInstall -Ctx $ctx
        if ($init) { & $say ('identity names: the install could not be read ({0}) -- checked again at the next update' -f $init); $out.Lines = $lines.ToArray(); return $out }
        $mode = 'plan'
        try { $mode = Read-SIIdentityMoveMode -Ctx $ctx } catch { $mode = 'plan' }
        $out.Mode = $mode
        $ctx.Apply = ($mode -eq 'apply')
        $summaries = New-Object System.Collections.Generic.List[object]
        if ($mode -eq 'off') { & $say 'identity names: the move is off for this install (IdentityMoveMode) -- only the names are checked and reported' }
        else {
        & $say ('identity names: {0} (the standard names id-si-engine / -web / -mcp / -tagging / -updater; the updater last)' -f $(if ($ctx.Apply) { 'APPLY' } else { 'PLAN -- the per-install plan, nothing is changed (IdentityMoveMode apply, set through the Support app, lets the update act)' }))
        $out.Ran = $true
        try {
        $tagOn = $false
        try { if ($ctx.StateDatabase) { $tagOn = Test-SIIdentityNamesTaggingOn -Rows @(Invoke-SIMoveSql -Server $ctx.SqlServer -Database $ctx.StateDatabase -Query "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.Setting') IS NOT NULL SELECT Name, ValueJson FROM cfg.Setting WHERE Name = N'SI_AssetTagging_Enabled' AND Scope = N'solution';" -Reason $ctx.Reason) } } catch { $tagOn = $false }
        $steps = @(Get-SIIdentityMoveStepOrder -Step 'all' | Where-Object { $_ -ne 'report' })
        foreach ($role in (Get-SIIdentityNamesRoleOrder)) {
            $ctx.Role = $role
            $sel = Select-SIIdentityMoveIdentities -Identities $ctx.Identities -Role $role
            $results = @()
            if ($role -eq 'tagging' -and $sel.State -eq 'none') {
                if ($tagOn) { $results = @(Invoke-SIIdentityNamesTaggingEnsure -Ctx $ctx) }
                else { $results = @(New-SIIdentityMoveStepResult -Step inventory -State 'n/a' -Lines @('tagging: asset tagging is off and the install has no identity for it -- none is made')) }
            } else {
                $run = Invoke-SIIdentityMove -Ctx $ctx -Steps $steps -HoldHandles @() -Initialized
                $results = @($run.Results)
            }
            foreach ($r in $results) {
                foreach ($l in @($r.Lines)) { & $say (Get-SIIdentityNamesLogLine -Role $role -Step $r.Step -Line $l) }
                foreach ($c in @($r.CustomerSteps)) { if ($c) { $support.Add(('{0}: {1}' -f $role, $c.What)) } }
                if ($r.State -eq 'stop') { $failed.Add(('{0} {1}: {2}' -f $role, $r.Step, (@($r.Lines) | Select-Object -Last 1))) }
            }
            $sum = Get-SIIdentityNamesSummary -Role $role -Results $results
            $summaries.Add($sum)
            & $say ('identity names: {0}' -f $sum.Line)
        }
        # a SECOND PASS of prove + clean-up when this run recorded a proof: the clean-up waits for EVERY role, and the updater --
        # moved last -- is proven only at the end of the pass (an update that runs as its new identity); without this pass the
        # other roles' clean-up would wait for the next update. The install is read again first (the first pass changed it).
        $proofNow = @($lines | Where-Object { $_ -match '\] recorded: \w+ proven at ' }).Count
        if ($ctx.Apply -and $proofNow -and -not (Initialize-SIMoveInstall -Ctx $ctx)) {
            foreach ($role in (Get-SIIdentityNamesRoleOrder)) {
                $ctx.Role = $role
                if ((Select-SIIdentityMoveIdentities -Identities $ctx.Identities -Role $role).State -ne 'move') { continue }
                $run = Invoke-SIIdentityMove -Ctx $ctx -Steps @('inventory', 'prove', 'clean-up') -HoldHandles @() -Initialized
                foreach ($r in @($run.Results)) {
                    foreach ($l in @($r.Lines)) { & $say (Get-SIIdentityNamesLogLine -Role $role -Step $r.Step -Line $l) }
                    foreach ($c in @($r.CustomerSteps)) { if ($c -and -not $support.Contains(('{0}: {1}' -f $role, $c.What))) { $support.Add(('{0}: {1}' -f $role, $c.What)) } }
                    if ($r.State -eq 'stop') { $failed.Add(('{0} {1}: {2}' -f $role, $r.Step, (@($r.Lines) | Select-Object -Last 1))) }
                }
            }
        }
        } catch { & $say ('WARNING: identity names: the move stopped ({0}) -- the next update carries on' -f $_.Exception.Message); $failed.Add($_.Exception.Message) }
        # THE SQL ADMIN GROUP, renamed IN PLACE to its standard name (framework 12.11c; same mode as the move): the group and the
        # SQL server's admin login text, both read back; a refusal = one support step; membership and the admin binding untouched
        try {
            $ctx.Role = ''
            $g = Invoke-SIMoveSqlAdminGroup -Ctx $ctx
            foreach ($l in @($g.Lines)) { & $say ('identity names [sql-admin-group] ' + $l) }
            foreach ($c in @($g.CustomerSteps)) { if ($c) { $support.Add(('sql-admin-group: {0} -- {1}' -f $c.What, $c.How)) } }
            if ($g.State -eq 'stop') { $failed.Add(('sql-admin-group: {0}' -f (@($g.Lines) | Select-Object -Last 1))) }
            $summaries.Add([pscustomobject]@{ Role = 'sql-admin-group'; Step = 'sql-admin-group'; State = [string]$g.State; Line = ('sql-admin-group: {0}' -f $g.State) })
        } catch { & $say ('WARNING: identity names: the SQL admin group was not checked ({0})' -f $_.Exception.Message) }
        }
        # THE REPORT, on EVERY update and in every mode (plan, apply, off; also after a move that stopped): the identity-names
        # setup step the heartbeat sends -- a read-only check of the identity each role's apps / jobs sign in as (a status row,
        # not a change), from a fresh read of the install
        try {
            if ($ctx.Apply) { $null = Initialize-SIMoveInstall -Ctx $ctx }
            $ctx.Role = ''
            $rctx = $ctx.Clone(); $rctx.Apply = $true
            $rep = Invoke-SIMoveReport -Ctx $rctx
            foreach ($l in @($rep.Lines)) { & $say ('identity names [report] ' + $l) }
        } catch { & $say ('identity names: the report could not be written ({0})' -f $_.Exception.Message) }
        foreach ($t in $support) { & $say ('NOTE: identity names: support step (Invardia, through the Support app): ' + $t) }
        $out.Roles = $summaries.ToArray()
    } catch { & $say ('WARNING: identity names: not checked ({0}) -- the next update tries again' -f $_.Exception.Message); $failed.Add($_.Exception.Message) }
    finally { if (Get-Command -Name Set-SIIdentityMoveIo -ErrorAction SilentlyContinue) { Set-SIIdentityMoveIo } }
    $out.Lines = $lines.ToArray(); $out.Support = $support.ToArray(); $out.Failed = $failed.ToArray()
    $out
}
