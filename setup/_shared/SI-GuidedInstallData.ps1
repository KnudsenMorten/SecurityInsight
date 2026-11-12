#Requires -Version 5.1
<#
.SYNOPSIS
    The guided install's database and web app steps -- in BOTH versions (owner 2026-10-18: the free version has the
    database and the web app; paid features are switched off by the licence, never left out as files).

.DESCRIPTION
    Loaded by setup\Install-SecurityInsight.ps1 next to SI-GuidedInstall.ps1, in every package. Every step calls the
    product's own, live-proven script, in the order the ring-1 Pro build proved:
      preflight-sql-region  the region accepts a new Azure SQL server
      pro-sql        the SQL server, Entra-only, created with the person installing as its admin; then
                     Set-SISqlAdminGroup makes the role-assignable 'grp-si-sql-admins' the admin (that person a member)
      pro-schema     Initialize-SIVulnTargetSql, Initialize-SIDataSql, the identity ledger through the SCHEMA-1 gate
                     (SI-SchemaGate.ps1), and the managed identity's database users
      pro-templates  Publish-SITemplates -InstallDefault          -- BEFORE the settings: the importer compares with
                                                                    the published templates
      pro-settings   Import-SIProSettings -Apply -CreateSchema
      web-app        New-SIManagementAppRegistration + Deploy-SIManagement, the MCP server included in every edition (it answers only with a Pro licence on record -- its licence gate, owner 2026-10-27)
      updater-job    Install-SIUpdaterJob -Source invardia -UpdateRing <updateRing> -UseManagedIdentity -GrantSql (#417).
                     Only where the package carries the Invardia update client: the free version's update channel is
                     built separately, and until then the step says so and is skipped.
      db-job         framework SEC-08: the database setup job caj-si-dbinit (setup\_shared\SI-DbInitJob.ps1) -- its own
                     identity id-si-dbinit made, added to the SQL admin group and READ BACK from its memberOf, the job made
                     and started once, waited for, its result read (Invoke-SIInstallDbJob).
    The step ids keep their names (pro-sql, pro-schema, ...): the status page and support tickets refer to them.

    The engine jobs of every install (Get-SIInstallProEngines: the paid engines' jobs too -- each asks the licence when it
    runs) and the Invardia Support app's database access are here, the same in both editions (framework
    PRO-COMMUNITY-SAME). Only the licence steps (the licence, the v2.2 CMDB migration) stay in SI-GuidedInstallPro.ps1.

    The SQL scripts reach the database as the engine identity. In a guided install that is the person signed in to
    Cloud Shell: the install lends them a token through the same hook the container uses (Get-SIManagedIdentityToken),
    for the length of the call only.
#>

$script:SIInstallProDatabase    = 'sqldb-si-pro'
# asset tagging's own identity (#236) -- TODAY's name, Bootstrap-ContainerAppJob.ps1's -TaggingIdentityName default; the
# install steps read the install's own name from the names table (Get-SISetupComponentName -Key TaggingIdentity: the CR5
# name id-si-tagging on a new install with SI_Setup_NewInstallNames on), this stays for older callers
$script:SIInstallTaggingIdentityName = 'uami-securityinsight-tagging'
$script:SIInstallLedgerDatabase = 'sqldb-si-identity'
# #507 / #509: the databases' size (never Basic: the Pro database S3 -- S2 until 2026-10-11 -- the identity ledger S1) -- Get-SISqlDatabaseTier
. ([IO.Path]::Combine($PSScriptRoot, 'SI-SqlTier.ps1'))
# #695: a new database administrator is waited for before the first sign-in (Invoke-SISqlLoginRetry, Test-SISqlLoginNotReady)
. ([IO.Path]::Combine($PSScriptRoot, 'SI-SqlAdminReady.ps1'))
# framework SEC-08: the database setup job caj-si-dbinit (step db-job) and the one add-and-wait policy for a group member
. ([IO.Path]::Combine($PSScriptRoot, 'SI-DbInitJob.ps1'))
if (-not (Get-Command -Name Invoke-SIGroupMemberAddRetry -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-GroupMemberAdd.ps1')) }

# ---- PRO-COMMUNITY-SAME (owner 2026-11-11): the engine jobs of every install, and the Invardia Support app's database
# access at install -- the SAME in both editions (moved here from SI-GuidedInstallPro.ps1, which keeps only the licence and
# the v2.2 CMDB migration). A paid engine's job is made in both editions and asks the licence when it runs.
# the Invardia Support app's database access: its own database user and its place in the admin group (framework 4.1b, kept after the install)
if (-not (Get-Command -Name Invoke-SISupportAppDatabaseAccess -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-SupportAppDatabase.ps1')) }

function Get-SIInstallProEngines {
    <# PURE. The paid engines that get a container job in EVERY install, both editions (framework PRO-COMMUNITY-SAME, Invardia
       C6 2026-11-11: the job set is the same; each paid engine asks the licence when it runs and ends with one line without
       it; a package that does not carry a paid engine's code ends that job with one line too -- container\Start-SIInContainer.ps1).
       (The ServiceNow connector only when an instance was given.) The CI
       build (asset-correlation) and asset tagging (#236) are NOT here any more: they are in the Community edition and every
       install gets them (SI-GuidedInstall.ps1 $SIInstallCommunityEngines; owner 2026-10-27, #750 (1) and (2)). The template
       release job (#235/#250, caj-si-templates) always: the web app's Template releases page starts it. No asset-properties
       job (#412): the profilers publish the full asset metadata themselves. The mail job (#714, caj-si-close-loop-mail)
       always: it sends every mail SecurityInsight sends (the test mail, department sign-ins, governance, tasks,
       exemptions, management summaries, the daily close-loop mail) and records the mail restriction check -- the web app
       starts it for each of them. Until 2026-10-16 this list left it out, so no guided Pro install had it and no mail
       was ever sent (the web app: "'caj-si-close-loop-mail' is not one of this installation's jobs").
       #715: with a ServiceNow instance given, BOTH ServiceNow connectors' jobs -- the CMDB connector (caj-si-asset-cmdb)
       and the vulnerability connector (caj-si-asset-vulns-servicenow, which the web app starts for a ServiceNow
       vulnerability connector: Run once, the send log, the guard releases). The instance URL does not say which
       direction the customer will set up in the web app afterwards, so both; without an instance neither (#269: the
       ServiceNow jobs exist only where ServiceNow is used -- a connector set up later gets its job from the next update).
       Bootstrap drops a ServiceNow job no setting asks for, so the install also passes -ServiceNowCmdb and
       -ServiceNowVulnerabilities (Get-SIInstallServiceNowSwitches).
       #718: the hourly status report to Invardia (caj-si-heartbeat) always -- its own timer, never a pipeline step, so the
       install reports every hour whether or not a pipeline runs (Bootstrap also adds it whatever the engine list). #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)
    # (the data sync, asset-datasync, is in every install: SI-GuidedInstall.ps1's engine list)
    $e = @('asset-vulnerabilities', 'asset-cmdb-sql', 'close-loop-mail', 'templates-publish', 'heartbeat')
    if ("$($Values['serviceNowUrl'])".Trim()) { $e += @('asset-cmdb', 'asset-vulnerabilities-servicenow') }
    $e
}

function Get-SIInstallServiceNowSwitches {
    <# PURE. #715: the Bootstrap switches that keep the ServiceNow jobs of -Engines -- Bootstrap's Select-SIBootstrapServiceNowEngines
       drops asset-cmdb / asset-vulnerabilities-servicenow unless a setting or these switches say ServiceNow is used, and
       the guided install writes no such setting (the connectors live in the Pro database, which setup does not read).
       Returns an ordered hashtable of the switches to pass (empty when the list has no ServiceNow job). #>
    param([string[]]$Engines = @())
    $s = [ordered]@{}
    if (@($Engines) -contains 'asset-cmdb') { $s['ServiceNowCmdb'] = $true }
    if (@($Engines) -contains 'asset-vulnerabilities-servicenow') { $s['ServiceNowVulnerabilities'] = $true }
    $s
}

function Get-SIInstallSupportAppAdminGroupId {
    <# The database server's admin group for this install: the customer's own group (the sqlAdminGroupId answer), else
       the group named grp-si-sql-admins. '' when the directory has none (or more than one) of that name. THROWS when
       the directory cannot be read. #>
    param([Parameter(Mandatory)]$Ctx)
    $given = ([string]$Ctx.Values['sqlAdminGroupId']).Trim()
    if ($given) { return $given }
    # CR5 (#655 item 5): by ANY of its names -- grp-si-sql-admins, "SecurityInsight SQL admins", its mailNickname
    if (-not (Get-Command -Name Find-SISqlAdminGroup -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-DisplayNames.ps1')) }
    $fg = Find-SISqlAdminGroup -Graph { param($m, $u, $b) Invoke-SIInstallGraph -Ctx $Ctx -Uri $u } -GroupName 'grp-si-sql-admins'
    if (-not $fg.Group) { return '' }
    [string]$fg.Group.Id
}

function Set-SIInstallSupportAppDatabase {
    <#
        THE INVARDIA SUPPORT APP KEEPS ITS DATABASE ACCESS AFTER THE INSTALL -- BOTH PARTS, PERMANENTLY (framework section
        4.1b; owner 2026-10-18: "make sure it never gets removed again") -- whoever runs the install: a person in Azure
        Cloud Shell, or the Support app itself. Only when the answers name a Support app (supportAppId); without one NOTHING
        is done and nothing is reported ($null).
          1. ITS OWN DATABASE USER in the Pro database and the identity ledger, from its client id (WITH SID, TYPE = E, no
             directory lookup), with db_owner. Made while the install is still the server's administrator, read back,
             never removed by the end of the install.
          2. membership of the server's admin group: added, read back, LEFT THERE -- no step of the install takes it away.
             The end of the install makes that group the server's administrator, as a group (setup\Set-SISqlAdminGroup.ps1).
          3. the client id is recorded in the Pro database, so the heartbeat knows which application to report on.
        -CheckOnly reads only (the end-of-install check). Never throws. Returns @{ Ok; Member; Databases; Message; Unchecked }.
    #>
    param([Parameter(Mandatory)]$Ctx, [switch]$CheckOnly)
    $app = ''; try { $app = ([string]$Ctx.Values['supportAppId']).Trim() } catch { }
    if (-not $app) { return $null }
    $out = [ordered]@{ Ok = $false; Member = $null; Databases = @(); Message = ''; Unchecked = '' }
    try {
        if (-not [string]$Ctx.Facts['sqlServerId']) {
            $out.Unchecked = 'could not be checked: this install has no Pro database server yet'; $out.Message = 'The Invardia Support app''s database access ' + $out.Unchecked + '.'
            return [pscustomobject]$out
        }
        $__siSupCtx = $Ctx; $__siSupFqdn = Get-SIInstallSqlFqdn -Ctx $Ctx
        # NOT closures: a GetNewClosure() block cannot see the functions of a dot-sourced file; these run inside the calls
        # below and find the two variables above in this function's scope
        $graph = { param([string]$Method, [string]$Uri, $Body) Invoke-SIInstallGraph -Ctx $__siSupCtx -Method $Method -Uri $Uri -Body $Body }
        $sql = { param([string]$Database, [string]$Query) Invoke-SIInstallSql -Ctx $__siSupCtx -Server $__siSupFqdn -Database $Database -Query $Query -Mode 'scalar' }
        # ---- the application in this tenant (its name for the database user; its object id for the group) ----
        $sp = $null; $spWhy = ''
        try { $sp = Get-SISupportAppServicePrincipal -Graph $graph -ClientId $app } catch { $spWhy = 'could not be checked: the directory did not answer ({0})' -f $_.Exception.Message }
        if (-not $sp -and -not $spWhy) { $spWhy = 'the tenant has no service principal for the application {0}' -f $app }
        # ---- 1. its own database user with db_owner (needs no directory: the SID is the client id) ----
        $dbs = @($script:SIInstallProDatabase, $script:SIInstallLedgerDatabase)
        $name = $(if ($sp -and $sp.DisplayName) { $sp.DisplayName } else { 'invardia-support-app' })
        $script:SIInstallSupportDbResult = @()
        Use-SIInstallUserSqlToken -Ctx $Ctx -Action {
            $script:SIInstallSupportDbResult = @(Invoke-SISupportAppDatabaseAccess -Sql $sql -Databases $dbs -ClientId $app -UserName $name -Apply:(-not $CheckOnly))
            if (-not $CheckOnly) {
                # 3. recorded for the heartbeat; a record that cannot be written is a line, never a failed step
                try { $null = & $sql $script:SIInstallProDatabase (Get-SISupportAppRecordSql -ClientId $app -By 'guided install') }
                catch { Write-SIInstallConsole -Ctx $Ctx -Text ('      the Support app''s client id could not be recorded in the Pro database ({0})' -f $_.Exception.Message) -Color 'Yellow' }
                # #1021: the JUST-IN-TIME support grant, made NOW while the install is the databases' owner -- the tables, the
                # standing read-only role, the customer's consent at the chosen level and the four signed procedures, in each
                # product database (only ADDS; today's access above stays). A step that fails is a line, never a failed install:
                # setup\Install-SISupportGrantProcedure.ps1 puts it in place later through a Support session.
                try {
                    if (-not (Get-Command -Name Get-SISupportGrantAdminSteps -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', 'pro-settings', 'SI-SupportGrantSql.ps1')) }
                    $sgLevel = if ($Ctx.Values['supportAccess']) { [string]$Ctx.Values['supportAccess'] } else { 'troubleshoot' }
                    foreach ($sgDb in $dbs) {
                        foreach ($sgStep in @(Get-SISupportGrantAdminSteps -ClientId $app -UserName $name -Level $sgLevel -Source customer -By 'guided install')) {
                            try { $null = & $sql $sgDb $sgStep.Sql }
                            catch { Write-SIInstallConsole -Ctx $Ctx -Text ('      the support grant ({0}) could not be put in place in {1}: {2} -- setup\Install-SISupportGrantProcedure.ps1 does it later' -f $sgStep.Step, $sgDb, $_.Exception.Message) -Color 'Yellow'; break }
                        }
                    }
                } catch { Write-SIInstallConsole -Ctx $Ctx -Text ('      the support grant was not put in place ({0})' -f $_.Exception.Message) -Color 'Yellow' }
            }
        }
        $res = @($script:SIInstallSupportDbResult); $script:SIInstallSupportDbResult = $null
        $out.Databases = $res
        $dbOk = [bool]($res.Count -gt 0 -and @($res | Where-Object { $_.State -in 'present', 'granted' }).Count -eq $res.Count)
        # ---- 2. a member of the admin group ----
        $member = $null
        if ($sp -and $sp.Id) {
            $gid = ''; $gWhy = ''
            try { $gid = Get-SIInstallSupportAppAdminGroupId -Ctx $Ctx } catch { $gWhy = 'could not be checked: the directory did not answer ({0})' -f $_.Exception.Message }
            if ($gid) { $member = Set-SISupportAppGroupMember -Graph $graph -GroupId $gid -ServicePrincipalId $sp.Id -Apply:(-not $CheckOnly) -Sleep $Ctx.Seams.Sleep }
            else { $member = [pscustomobject]@{ State = $(if ($gWhy) { 'unchecked' } else { 'failed' }); Detail = $(if ($gWhy) { $gWhy } else { 'the database admin group was not found in the directory' }) } }
        } else { $member = [pscustomobject]@{ State = $(if ($spWhy -like 'could not be checked*') { 'unchecked' } else { 'failed' }); Detail = $spWhy } }
        $out.Member = $member
        $out.Ok = [bool]($dbOk -and $member.State -in 'present', 'added')
        if ($out.Ok) { $Ctx.Facts['supportAppDatabase'] = 'ok' } elseif (-not $CheckOnly) { $Ctx.Facts['supportAppDatabase'] = 'not in place' }
        $out.Unchecked = (@(@($res | Where-Object { $_.State -eq 'unchecked' } | ForEach-Object { '{0}: {1}' -f $_.Database, $_.Detail }) + @($(if ($member.State -eq 'unchecked') { 'the admin group: ' + $member.Detail })) | Where-Object { $_ }) -join '; ')
        $out.Message = ('The Invardia Support app''s database access, kept after the install -- its own database user: {0}. Member of the database admin group: {1}.' -f
            ((@($res | ForEach-Object { '{0}: {1}' -f $_.Database, $_.Detail })) -join '; '), $member.Detail)
    } catch {
        $out.Ok = $false; $out.Unchecked = 'could not be checked: {0}' -f $_.Exception.Message
        $out.Message = 'The Invardia Support app''s database access ' + $out.Unchecked + '.'
    }
    [pscustomobject]$out
}
function Get-SIInstallSupportAppDatabaseCommand {
    <# PURE apart from reading $Ctx. The command that puts both parts of the Support app's database access in place on an install that is there. #>
    param([Parameter(Mandatory)]$Ctx)
    './setup/Grant-SISupportAppDatabase.ps1 -AppId {0} -Apply' -f ([string]$Ctx.Values['supportAppId'])
}

function Confirm-SIInstallSupportAppSignIn {
    <#
        THE END OF THE INSTALL, once the admin group has the server back: does the Support app still get in?
          * READ BACK from the server: its administrator is the admin group, and the server records it as kind Group.
          * THE PROOF, WHERE IT CAN BE MADE: an install that ran AS the Support app signs in to each product database
            with the Support app's own token and asks who it is there -- dbo (through the group) or its own database user,
            either with the owner role (framework 4.1b holds both). One try per
            database: a server whose administrator changed a moment ago may not answer yet, and that is said as "could
            not be checked", never as "missing". A person's install cannot make this proof (it has no token of the
            Support app); it says what it read back and that the sign-in was not made.
        Reads only. Never throws. Returns $null (nothing to say here), or @{ Proven; Text }.
    #>
    param([Parameter(Mandatory)]$Ctx)
    try {
        $facts = $null; try { $facts = $Ctx.Facts } catch { }
        if (-not ($facts -is [System.Collections.IDictionary])) { return $null }
        $app = ([string]$Ctx.Values['supportAppId']).Trim()
        if (-not $app -or [string]$facts['supportAppDatabase'] -ne 'ok' -or [bool]$facts['supportAppSignInProven']) { return $null }
        $asSupportApp = (Test-SIInstallSignedInAsApp -Ctx $Ctx) -and ([string]$facts['account'] -ieq $app)
        if ($asSupportApp -and [bool]$facts['sqlAdminIsInstallApp']) {
            return [pscustomobject]@{ Proven = $false; Text = 'A database sign-in as the Invardia Support app could not be checked: it is still the database server''s administrator.' }
        }
        # ---- the server's administrator, read back: the admin group, as a group ----
        $adminOk = $false; $adminText = ''
        $cur = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SISqlServerEntraAdmin' -Arguments ([ordered]@{ ResourceGroupName = $Ctx.Names.ResourceGroup; Name = $Ctx.Names.SqlServer })
        $sid = ''; $kind = ''; $login = ''
        if ($cur.Ok -and $cur.Value) { $sid = [string](Get-SIInstallProp $cur.Value 'Sid'); $kind = [string](Get-SIInstallProp $cur.Value 'PrincipalType'); $login = [string](Get-SIInstallProp $cur.Value 'Login') }
        $gid = ''; try { $gid = [string](Get-SIInstallSupportAppAdminGroupId -Ctx $Ctx) } catch { $gid = '' }
        if ($sid -and $gid) {
            if ($sid -ieq $gid -and $kind -ieq 'Group') { $adminOk = $true; $adminText = 'the database server''s administrator is the admin group, recorded as a group (read back)' }
            elseif ($sid -ieq $gid) { $adminText = 'the database server names its admin group as "{0}", not as a group' -f $kind }
            else { $adminText = 'the database server''s administrator is {0}, not the admin group' -f $login }
        }
        if (-not $asSupportApp) {
            # a person's install: nothing is said unless the server's administrator could be read
            if (-not $adminText) { return $null }
            return [pscustomobject]@{ Proven = $adminOk; Text = ('The Invardia Support app''s database access: {0}; the Support app is a member of that group and has its own database user in each product database. A database sign-in as the Support app was not made (this install was not run as it).' -f $adminText) }
        }
        $fqdn = Get-SIInstallSqlFqdn -Ctx $Ctx; $said = New-Object System.Collections.Generic.List[string]; $all = $true
        foreach ($db in $script:SIInstallProDatabase, $script:SIInstallLedgerDatabase) {
            try {
                $tok = [string](& $Ctx.Seams.Token 'https://database.windows.net/' $true)
                $who = ([string](& $Ctx.Seams.Sql $fqdn $db (Get-SISupportAppWhoAmISql) 'scalar' $tok)).Trim()
                $p = ConvertFrom-SISupportAppDatabaseAnswer $who
                if ($p.User -and $p.Owner) { $said.Add(('{0}: signed in as {1}, with the owner role' -f $db, (Get-SISupportAppSignedInName $p.User))) }
                else { $all = $false; $said.Add(('{0}: signed in as {1}, WITHOUT the owner role' -f $db, (Get-SISupportAppSignedInName $p.User))) }
            } catch { $all = $false; $said.Add(('{0}: could not be checked: {1}' -f $db, $_.Exception.Message)) }
        }
        if ($all) { $facts['supportAppSignInProven'] = $true }
        [pscustomobject]@{ Proven = $all; Text = ('A database sign-in as the Invardia Support app, after the admin group took the server back{0} -- {1}.' -f $(if ($adminText) { ' (' + $adminText + ')' } else { '' }), ($said.ToArray() -join '; ')) }
    } catch { $null }
}

function Get-SIInstallSupportEndCheck {
    <# THE END-OF-INSTALL CHECK's support part (Get-SIInstallEndCheck calls it where this file is loaded): the Invardia
       Support app's database access, BOTH parts (framework 4.1b) -- its own database user with the owner role READ from
       each product database, its membership of the database admin group READ from the directory. Missing = said
       ('support-app-access|...': its step runs again). What could not be read is kept as a note for the health check
       ("could not be checked: ..."), never reported as missing. No Support app in the answers = nothing checked, nothing
       said. Never throws. #>
    param([Parameter(Mandatory)]$Ctx)
    $bad = New-Object System.Collections.Generic.List[string]
    try {
        $v = $Ctx.Values
        $done = @($Ctx.State['completed']) + @($Ctx.State['pending'].Keys)
        # The Invardia Support app's database access, BOTH parts (framework 4.1b; only when the answers name a Support app
        # and its step ran): its own database user with the owner role is READ from each product database, and its
        # membership of the database admin group from the directory. Missing = said, and its step runs again. What could
        # not be read is kept as a note for the health check ("could not be checked: ..."), never reported as missing.
        # No Support app in the answers = nothing checked, nothing said.
        $from = 'support-app-access'
        try { $Ctx.Facts.Remove('supportAppDatabaseNote') } catch { }
        if ($done -contains 'support-app-access' -and $done -contains 'pro-schema' -and ([string]$v['supportAppId']).Trim()) {
            $sd = Set-SIInstallSupportAppDatabase -Ctx $Ctx -CheckOnly
            if ($sd) {
                foreach ($d in @($sd.Databases | Where-Object { $_.State -eq 'missing' })) { $bad.Add($from + '|' + ('the Invardia Support app cannot run the setup scripts against the database {0}: {1}' -f $d.Database, $d.Detail)) }
                if ($sd.Member -and $sd.Member.State -eq 'planned') { $bad.Add($from + '|the Invardia Support app is not a member of the database admin group') }
                $Ctx.Facts['supportAppDatabaseNote'] = $(if ($sd.Unchecked) { 'The Invardia Support app''s database access -- ' + [string]$sd.Unchecked + '.' }
                                                         elseif ($sd.Ok) { 'The Invardia Support app''s own database user, with the owner role, was read back from both databases, and its membership of the database admin group from the directory.' } else { '' })
            }
        }
    } catch { }
    $bad.ToArray()
}

function Set-SIInstallSqlAdminSetAt {
    <# #695: the moment the database server's Entra administrator was set by this install (UTC, round-trip text), so the
       first sign-in after it may wait out a server that does not know its new administrator yet. #>
    param([Parameter(Mandatory)]$Ctx)
    try {
        $now = $(if ($Ctx.Seams -and $Ctx.Seams.Now) { & $Ctx.Seams.Now } else { [datetime]::UtcNow })
        $Ctx.Facts['sqlAdminSetAt'] = ([datetime]$now).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    } catch { }
}

function Invoke-SIInstallSqlScriptAfterAdmin {
    <# #695 (customer B 2026-10-15): a database script that signs in right after the server's administrator was set. The
       refusal of a token sign-in ("Login failed for user '<token-identified principal>'") that arrives within the first
       minutes after the administrator was set is waited out (30 s at a time, up to 5 minutes, one plain line); every other
       error comes back at once. Returns the script's result. #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$RelativePath, [System.Collections.IDictionary]$Arguments = @{})
    $__siLoginCtx = $Ctx; $__siLoginRel = $RelativePath; $__siLoginArgs = $Arguments
    $setAt = $null; try { $setAt = $Ctx.Facts['sqlAdminSetAt'] } catch { }
    $nowFn = $null; try { $nowFn = $Ctx.Seams.Now } catch { }
    # NOT closures: they run inside Invoke-SISqlLoginRetry and find the variables above in this function's scope
    Invoke-SISqlLoginRetry -Action { Invoke-SIInstallScript -Ctx $__siLoginCtx -RelativePath $__siLoginRel -Arguments $__siLoginArgs } `
        -AdminSetAt $setAt -Now $nowFn -Sleep $Ctx.Seams.Sleep -Print { param([string]$Text) Write-SIInstallConsole -Ctx $__siLoginCtx -Text $Text -Color 'DarkYellow' } `
        -WaitSec 300 -StepSec 30 -WindowSec 900
}

function Get-SIInstallSqlTier {
    <#
        #507: the size the Pro databases are created at. The tenant's directory counts (Graph $count: users, groups, service
        principals, devices -- the counts setup sizes the collection jobs by) through the install's Graph seam; a count that
        cannot be read = S1, said in the step's message. A size the customer gives a database later (the portal) is kept:
        the update step never lowers one (Invoke-SISqlTierUpgrade).
    #>
    param([Parameter(Mandatory)]$Ctx)
    $counts = @{}
    foreach ($k in @(@{ N = 'Users'; P = 'users' }, @{ N = 'Groups'; P = 'groups' }, @{ N = 'ServicePrincipals'; P = 'servicePrincipals' }, @{ N = 'Devices'; P = 'devices' })) {
        try {
            $r = Invoke-SIInstallGraph -Ctx $Ctx -Uri ('https://graph.microsoft.com/v1.0/{0}/$count' -f $k.P)
            $n = 0L
            if ($null -ne $r -and [long]::TryParse(("$r" -replace '[^\d]', ''), [ref]$n)) { $counts[$k.N] = $n } else { $counts = $null; break }
        } catch { $counts = $null; break }
    }
    Get-SISqlDatabaseTier -Objects (Get-SISqlTierObjectCount -Counts $counts)
}

function Invoke-SIInstallSqlTierRestCall {
    <#
        #521: the -Rest seam of SI-SqlTier.ps1 (param($Method, $Uri, $Body, $Resource, $Headers) -> @{ Status; Body; Headers },
        setup/_shared/SI-UpdateRest.ps1's contract) answered over ARM through the install's Az seam (Invoke-SIArm) -- so the
        size step of an existing database runs as the person installing (or the support session), and the fake world answers
        it through the seam. ARM only: any other audience is refused (Status 0, said). Never throws: Azure's refusal comes back
        as its HTTP status and message.
    #>
    param([Parameter(Mandatory)]$Ctx, [string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body, [AllowEmptyString()][string]$Resource = 'https://management.azure.com/', [hashtable]$Headers)
    if ("$Resource" -notlike 'https://management.*' -or $Uri -notlike 'https://management.azure.com/*') {
        return [pscustomobject]@{ Status = 0; Body = ('not an Azure Resource Manager call: {0}' -f $Uri); Headers = @{} }
    }
    $x = [ordered]@{ Method = $Method.ToUpperInvariant(); Path = $Uri }
    if ($null -ne $Body) { $x['Body'] = $(if ($Body -is [string]) { $Body } else { ConvertTo-Json -InputObject $Body -Depth 30 -Compress }) }
    try {
        $o = Invoke-SIInstallAz -Ctx $Ctx -Command 'Invoke-SIArm' -Arguments $x
        [pscustomobject]@{ Status = 200; Body = $(if ($null -ne $o) { ConvertTo-Json -InputObject $o -Depth 30 -Compress } else { '' }); Headers = @{} }
    } catch {
        $st = 0; $resp = $_.Exception.PSObject.Properties['Response']
        if ($resp -and $resp.Value -and $resp.Value.PSObject.Properties['StatusCode']) { try { $st = [int]$resp.Value.StatusCode } catch { $st = 0 } }
        if (-not $st -and "$($_.Exception.Message)" -match 'HTTP Status: (\d{3})') { $st = [int]$Matches[1] }
        [pscustomobject]@{ Status = $st; Body = [string]$_.Exception.Message; Headers = @{} }
    }
}

function Test-SIInstallConnectToInvardia {
    <# PURE. Did this install say yes to "Connect this install to Invardia: health reports + updates on request"? Pro: always
       (its licence is the agreement); Community: the answer connectToInvardia (-ConnectToInvardia), off by default. #>
    param([Parameter(Mandatory)]$Ctx)
    if ([string]$Ctx.Edition -eq 'pro') { return $true }
    [bool]($Ctx.Values -and $Ctx.Values.Contains('connectToInvardia') -and [bool]$Ctx.Values['connectToInvardia'])
}

function Invoke-SIInstallInvardiaKey {
    <#
        #240 -- the install's Invardia install key, at install time. NEVER fails the install; never echoes the key. The SAME
        step for both editions (framework PRO-COMMUNITY-SAME): a Pro install claims with its licence; a Community install claims
        ONLY when its user said yes to "Connect this install to Invardia: health reports + updates on request"
        (connectToInvardia / -ConnectToInvardia) -- { product, tenantId, edition: 'community' }, no licence; without the yes
        NOTHING is sent (no call at all) and the install stays anonymous.
          * the bundle carried installKey -> the key-vault step stored it; no claim;
          * otherwise CLAIM it with the licence: POST /api/install-keys/claim { product, tenantId, licence }, the tenant being
            the 'tid' of the installing person's own Azure token (never config). Stored in the Key Vault (SI-Invardia-InstallKey);
            the returned updates endpoint/header go into the update state (SI-Update-State) for the updater.
        A refused claim is reported (a 409 = ask Invardia support for a reset); the updater also claims a key when none is stored.
        Seams (tests): $ctx.Seams.InvardiaClaimHttp { param($Uri, $Body) } replaces the HTTP call.
        Returns @{ Message; Warn }.
    #>
    param([Parameter(Mandatory)]$Ctx)
    # a Community install without the yes: no call at all (framework PRO-COMMUNITY-SAME, opt-in)
    if ([string]$Ctx.Edition -ne 'pro' -and -not (Test-SIInstallConnectToInvardia -Ctx $Ctx)) {
        return [pscustomobject]@{ Message = 'Not connected to Invardia (the default): nothing that identifies this install is sent; it still takes the release of its update ring every night. Connect it later with the setting SI_Invardia_Connect.'; Warn = $false; Skipped = $true }
    }
    if ($Ctx.InstallKey) {
        if ($Ctx.Facts['installKeyStored']) { return [pscustomobject]@{ Message = 'The Invardia install key from your installation page is in the Key Vault; no key was claimed.'; Warn = $false } }
        return [pscustomobject]@{ Message = 'The Invardia install key from your installation page was not stored (see the Key Vault step).'; Warn = $true }
    }
    try {
        $client = [IO.Path]::Combine($Ctx.SIRoot, 'engine', '_shared', 'SI-InvardiaUpdate.ps1')
        if (-not (Test-Path -LiteralPath $client)) { return [pscustomobject]@{ Message = 'This package has no Invardia update client; no install key was claimed.'; Warn = $false } }
        . $client
        $vault = $Ctx.Names.KeyVault
        $c = $Ctx
        $s = @{
            ReadSecret  = {
                param([string]$Name)
                $sec = Invoke-SIInstallAz -Ctx $c -Command 'Get-SIAzKeyVaultSecret' -Arguments ([ordered]@{ VaultName = $vault; Name = $Name; ErrorAction = 'SilentlyContinue' })
                $v = Get-SIInstallProp $sec 'SecretValue'
                if ($v -is [System.Security.SecureString]) { return (New-Object System.Net.NetworkCredential('', $v)).Password }
                $null
            }
            WriteSecret = {
                param([string]$Name, [string]$Value)
                $null = Invoke-SIInstallAz -Ctx $c -Command 'Set-SIAzKeyVaultSecret' -Arguments ([ordered]@{ VaultName = $vault; Name = $Name; SecretValue = (ConvertTo-SecureString -String $Value -AsPlainText -Force); ErrorAction = 'Stop' })
            }
            # the REAL tenant: the 'tid' of the installing person's own token, never config
            TenantId    = {
                $tok = [string](& $c.Seams.Token 'https://management.azure.com/')
                try { $p = $tok.Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }; [string](([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json).tid) } catch { $null }
            }
        }
        if ($Ctx.Seams['InvardiaClaimHttp']) { $s.ClaimHttp = $Ctx.Seams['InvardiaClaimHttp'] }
        $community = ([string]$Ctx.Edition -ne 'pro')
        $lic = if ($community) { '' } else { [IO.File]::ReadAllText($Ctx.LicencePath).Trim() }
        $state = ConvertFrom-SIInvardiaUpdateState -Json (& $s.ReadSecret 'SI-Update-State')
        $r = Request-SIInvardiaInstallKey -State $state -Seams $s -Licence $lic -Community:$community -NowUtc (& $Ctx.Seams.Now)
        $lic = $null
        if ($r.Action -ne 'present') { try { & $s.WriteSecret 'SI-Update-State' (ConvertTo-SIInvardiaUpdateStateJson -State $state) } catch { } }
        $Ctx.Facts['installKeyClaim'] = $r.Action
        switch ($r.Action) {
            'claimed' { return [pscustomobject]@{ Message = 'The Invardia install key was claimed and stored in the Key Vault; updates come from Invardia.'; Warn = $false } }
            'present' { return [pscustomobject]@{ Message = 'The Invardia install key is in the Key Vault already.'; Warn = $false } }
            'tenant-known' { return [pscustomobject]@{ Message = ('This install was not connected to Invardia: {0}.' -f $r.Reason); Warn = $true } }
            'exists' { return [pscustomobject]@{ Message = ('{0}.' -f $r.Reason); Warn = (-not $r.HasKey) } }
            'waiting' { return [pscustomobject]@{ Message = 'Invardia asked to try the connection again later -- the updater claims the install key on a later run.'; Warn = $false } }
            { $_ -in 'conflict', 'forbidden', 'invalid' } { return [pscustomobject]@{ Message = ('The Invardia install key was NOT claimed: {0}' -f $r.Reason); Warn = $true } }
            default { return [pscustomobject]@{ Message = ('The Invardia install key was not claimed now ({0}); the updater claims it on its first run.' -f $r.Reason); Warn = $false } }
        }
    } catch {
        [pscustomobject]@{ Message = ('The Invardia install key was not claimed now ({0}); the updater claims it on its first run.' -f (Protect-SIInstallText $_.Exception.Message)); Warn = $false }
    }
}

function Get-SIInstallUpdateSource {
    <# The updater job's -Source: ONE update client for both editions (framework PRO-COMMUNITY-SAME) -- the package carries it
       (container\updater\_shared\SI-UpdaterInvardia.ps1, Test-Path only, never loaded here) and -Edition only records which
       manifest address an unlicensed install asks: 'community' for a Community install, 'invardia' otherwise; '' when the
       package carries no update client. Never decided by which other files the package carries. #>
    param([Parameter(Mandatory)][string]$SIRoot, [AllowEmptyString()][string]$Edition = '')
    if (-not (Test-Path -LiteralPath ([IO.Path]::Combine($SIRoot, 'container', 'updater', '_shared', 'SI-UpdaterInvardia.ps1')))) { return '' }
    if ("$Edition".Trim().ToLowerInvariant() -eq 'community') { return 'community' }
    'invardia'
}

function Test-SIInstallUpdateClientPresent {
    <# Does this package carry the update client (one for both editions)? Install-SIUpdaterJob refuses without it. Looked up with Test-Path only -- never loaded here. #>
    param([Parameter(Mandatory)][string]$SIRoot)
    [bool](Get-SIInstallUpdateSource -SIRoot $SIRoot)
}

function Get-SIInstallSqlFqdn { param([Parameter(Mandatory)]$Ctx) '{0}.database.windows.net' -f $Ctx.Names.SqlServer }

function Get-SIInstallProConfigSettings {
    <# PURE apart from reading $ctx. The Pro database settings in the install's config (names are known before the server exists). #>
    param([Parameter(Mandatory)]$Ctx)
    $fqdn = Get-SIInstallSqlFqdn -Ctx $Ctx
    $s = [ordered]@{
        SI_ProSqlServer         = $fqdn
        SI_ProSqlDatabase       = $script:SIInstallProDatabase
        SI_LedgerSqlServer      = $fqdn
        SI_LedgerDatabase       = $script:SIInstallLedgerDatabase
        SI_VulnSync_Target      = 'Sql'
        SI_VulnSync_SqlServer   = $fqdn
        SI_VulnSync_SqlDatabase = $script:SIInstallProDatabase
    }
    if ($Ctx.Facts['webAppId']) { $s['SI_Management_AppId'] = [string]$Ctx.Facts['webAppId'] }
    # #417: the update ring the install follows (the wizard's updateRing; none = 3), and the updater job once it exists
    $s['SI_UpdateRing'] = Get-SIInstallUpdateRing -Values $Ctx.Values
    if ($Ctx.Facts['updaterJob']) { $s['SI_Bootstrap_UpdaterJob'] = [string]$Ctx.Facts['updaterJob'] }
    # framework PRO-COMMUNITY-SAME (opt-in, owner 2026-11-11): "Connect this install to Invardia: health reports + updates on
    # request" -- ON for a Pro install (its licence is the agreement), for a Community install only when the answers say yes
    # (connectToInvardia: the installer's question, -ConnectToInvardia unattended). Off = nothing that
    # identifies the install leaves it (engine\_shared\SI-InvardiaConnect.ps1).
    # the edition this install IS (the reports name it; the database alone no longer tells the editions apart)
    $s['SI_Edition'] = $(if ([string]$Ctx.Edition -eq 'pro') { 'pro' } else { 'community' })
    $s['SI_Invardia_Connect'] = $(if ([string]$Ctx.Edition -eq 'pro' -or ($Ctx.Values -and $Ctx.Values.Contains('connectToInvardia') -and [bool]$Ctx.Values['connectToInvardia'])) { 'on' } else { 'off' })
    $s
}

function Get-SIInstallUpdateRing {
    <# PURE. #417: the release ring this install follows -- the wizard's updateRing (1, 2 or 3); no answer = 3 (broad). #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)
    $r = $Values['updateRing']
    if ($null -eq $r -or "$r".Trim() -eq '') { return 3 }
    [int]$r
}

function Get-SIInstallUpdateRingNote {
    <#
        PURE apart from reading $Ctx. #564 (PIM's install at customer I: a managed install silently fell to ring 3): the update ring
        comes from the CLAIMED install's configuration (config.json from Invardia: the installation page's answer). When it
        carried none, ring 3 is used and every step that records it SAYS so -- never a silent default. '' when it was given.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $given = @($Ctx.Explicit) -contains 'updateRing' -and "$($Ctx.Values['updateRing'])".Trim()
    if ($given) { return '' }
    ' The installation''s configuration carried no update ring, so ring 3 (broad) is used -- change it on the Settings page (Update ring) if this install should get releases earlier.'
}

function Get-SIInstallSqlSid {
    <# PURE. An Entra principal's SQL SID from its client id: the 16 bytes in [guid]::ToByteArray() order, as hex. #>
    param([Parameter(Mandatory)][string]$ClientId)
    '0x' + ((([guid]$ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Set-SIInstallSqlAppAdmin {
    <#
        #616 (a new install through the Invardia Support app, 2026-10-12). An install signed in as an APPLICATION is made
        the database server's Entra administrator ITSELF for the install's database steps. Azure SQL did not accept the
        application as administrator through the admin GROUP it had just been added to: it signed in to master as an
        ordinary principal and every product database answered "Login failed for user '<token-identified principal>'",
        20 minutes on, with the group in the token. The group is made the administrator again when the last database
        step is done (Restore-SIInstallSqlAdminGroup). A person installing is not touched (a person signs in through the
        group). Safe to repeat; a server that cannot be read is left as it is.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $facts = $null; try { $facts = $Ctx.Facts } catch { }
    if (-not ($facts -is [System.Collections.IDictionary]) -or -not $Ctx.Names) { return }
    if (-not (Test-SIInstallSignedInAsApp -Ctx $Ctx)) { return }
    $acct = [string]$Ctx.Facts['account']
    if ($acct -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return }
    $n = $Ctx.Names
    $cur = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SISqlServerEntraAdmin' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; Name = $n.SqlServer })
    if (-not $cur.Ok) {
        # "could not read" is not "none set": said, and the server is left as it is
        Write-SIInstallConsole -Ctx $Ctx -Text ('      the administrator of the database server {0} could not be read ({1}) -- it is left as it is' -f $n.SqlServer, $cur.Error) -Color 'Yellow'
        return
    }
    if (-not $cur.Value) { return }
    # the application by its client id AND recorded as an application (a server that names it under another kind is set again)
    $kind = [string](Get-SIInstallProp $cur.Value 'PrincipalType')
    if ([string]$cur.Value.Sid -ieq $acct -and (-not $kind -or $kind -ieq 'Application')) { $Ctx.Facts['sqlAdminIsInstallApp'] = $true; return }
    $upn = [string]$Ctx.Facts['userPrincipalName']
    $r = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Set-SISqlServerEntraAdmin' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; Name = $n.SqlServer
            AdminName = $(if ($upn) { $upn } else { $acct }); AdminSid = $acct; AdminType = 'Application' })
    if (-not $r.Ok) {
        throw (New-SIInstallFailure -Message ('The application this install runs as could not be made the administrator of the database server {0} for the install''s database steps: {1}' -f $n.SqlServer, $r.Error) `
            -ActionText 'Run the install command again: it continues from this step.' -Command $Ctx.ResumeCommand)
    }
    $Ctx.Facts['sqlAdminIsInstallApp'] = $true
    Set-SIInstallSqlAdminSetAt -Ctx $Ctx   # #695
    Write-SIInstallConsole -Ctx $Ctx -Text ('      the application this install runs as is the administrator of {0} for the install''s database steps (was {1}); the admin group is the administrator again when they are done' -f $n.SqlServer, [string]$cur.Value.Login)
    # the server takes a moment to know its new administrator
    & $Ctx.Seams.Sleep 30
}

function Set-SIInstallSqlAzureServicesRule {
    <#
        #616: the database server's rule that lets Azure services in (AllowAllWindowsAzureIps, 0.0.0.0) -- the install's
        own jobs and its web app reach the database through it; there is no public rule for anything else. SET AND
        CHECKED: its result used to be thrown away, and on a new customer install it was sent while the server was still
        being made -- no rule existed, the web app answered "Something went wrong" (SQL 40615, "Client with IP address
        ... is not allowed") and every job failed on its settings. Safe to repeat; throws with the reason when it cannot
        be set.
    #>
    param([Parameter(Mandatory)]$Ctx)
    # #866 (owner: "we will not allow fw option or exceptions"): a PRIVATE install's database has no public access and gets
    # NO firewall rule -- its jobs and web app reach it through its private endpoint
    if ([bool]$Ctx.Values['privateNetwork']) { return }
    $n = $Ctx.Names
    $a = [ordered]@{ ResourceGroupName = $n.ResourceGroup; ServerName = $n.SqlServer; Name = 'AllowAllWindowsAzureIps'; StartIpAddress = '0.0.0.0'; EndIpAddress = '0.0.0.0'
                     SubscriptionId = [string]$Ctx.Values['subscriptionId'] }
    $r = $null; $why = ''
    for ($try = 1; $try -le 4; $try++) {
        $r = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Set-SISqlFirewallRule' -Arguments $a
        if ($r.Ok) {
            # READ BACK: the rule Azure HAS, not the request it accepted
            $back = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SISqlFirewallRule' -Arguments ([ordered]@{ ResourceGroupName = $a.ResourceGroupName; ServerName = $a.ServerName; Name = $a.Name; SubscriptionId = $a.SubscriptionId })
            if ($back.Ok -and [string](Get-SIInstallProp (Get-SIInstallProp $back.Value 'properties') 'startIpAddress') -eq '0.0.0.0') { return }
            $why = $(if ($back.Ok) { 'Azure accepted the rule, but it is not there when read back' } else { 'the rule could not be read back: ' + $back.Error })
        } else {
            $why = [string]$r.Error
            # a refusal is not waited for: only a server that is not there yet / still busy is tried again
            if ($why -match '(?i)AuthorizationFailed|does not have authorization|HTTP Status: 40[13]\b|RequestDisallowedByPolicy') { break }
        }
        if ($try -lt 4) { & $Ctx.Seams.Sleep 15 }
    }
    throw (New-SIInstallFailure -Message ('The database server {0} could not be opened to the install''s own jobs and web app (the rule AllowAllWindowsAzureIps): {1}' -f $n.SqlServer, $why) `
        -ActionText 'Run the install command again: it continues from this step.' -Command $Ctx.ResumeCommand)
}

function Get-SIInstallSqlPrivateShapeCheck {
    <#
        #1091: the end-of-install check of a PRIVATE install's database server -- the private shape, never the public rule:
          * NO AllowAllWindowsAzureIps rule (its presence lets every Azure address in -- owner: "we cannot have anything public");
          * public network access Disabled, and a private endpoint whose connection is Approved (once the private-network
            step has run: before it, the server is still open by design).
        -RuleRead = the result of the rule's read (Invoke-SIInstallArmTry Get-SISqlFirewallRule). Each problem is
        'private-network|<sentence>' -- that step closes the server and takes the rule away. Something that could not be
        READ is not reported. Never throws.
    #>
    param([Parameter(Mandatory)]$Ctx, $RuleRead, [string[]]$Done = @())
    $out = New-Object System.Collections.Generic.List[string]
    try {
        $n = $Ctx.Names; $srv = [string]$n.SqlServer
        if ($RuleRead -and $RuleRead.Ok -and $RuleRead.Value) {
            $out.Add('private-network|' + ('the database server {0} has the rule AllowAllWindowsAzureIps, which lets every Azure address in -- a private install must not have it (its jobs and web app reach the database through its private endpoint)' -f $srv))
        }
        if (@($Done) -contains 'private-network') {
            $s = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SISqlServerNetworkShape' -Arguments ([ordered]@{ ResourceGroupName = [string]$n.ResourceGroup; ServerName = $srv })
            if ($s.Ok -and $s.Value) {
                $pna = [string](Get-SIInstallProp $s.Value 'PublicNetworkAccess')
                if ($pna -ne 'Disabled') { $out.Add('private-network|' + ('the database server {0} still accepts connections from outside your network (public network access {1}) -- a private install has it Disabled' -f $srv, $(if ($pna) { $pna } else { 'not set, which Azure takes as Enabled' }))) }
                $ok = @(@(Get-SIInstallProp $s.Value 'PrivateEndpoints') | Where-Object { $_ -and [string](Get-SIInstallProp $_ 'Status') -eq 'Approved' })
                if (-not $ok.Count) { $out.Add('private-network|' + ('the database server {0} has no approved private endpoint -- the install''s jobs and web app cannot reach it from inside your network' -f $srv)) }
            }
        }
    } catch { }
    $out.ToArray()
}

function Remove-SIInstallSqlAzureServicesRule {
    <#
        #1091: a PRIVATE install's database server carries NO AllowAllWindowsAzureIps rule. The install never makes it on a
        private install (Set-SIInstallSqlAzureServicesRule, the web app's deploy, the updater: none of them); one that is
        there anyway (left from before the install went private) is taken away by the private-network step once the
        server's public access is closed, and READ BACK. Returns a line for the step's result ('' = nothing to do); a
        removal that fails says so -- never throws.
    #>
    param([Parameter(Mandatory)]$Ctx)
    try {
        if (-not [bool]$Ctx.Values['privateNetwork']) { return '' }
        $a = [ordered]@{ ResourceGroupName = [string]$Ctx.Names.ResourceGroup; ServerName = [string]$Ctx.Names.SqlServer; Name = 'AllowAllWindowsAzureIps' }
        $have = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SISqlFirewallRule' -Arguments $a
        if (-not $have.Ok) { return ('the database server''s rule AllowAllWindowsAzureIps could not be read: {0}' -f $have.Error) }
        if (-not $have.Value) { return '' }
        $rm = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Remove-SISqlFirewallRule' -Arguments $a
        $back = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SISqlFirewallRule' -Arguments $a
        if ($rm.Ok -and $back.Ok -and -not $back.Value) { return ('the database server {0}: the rule AllowAllWindowsAzureIps removed (read back) -- a private install has no public rule' -f $a.ServerName) }
        ('the database server {0} still has the rule AllowAllWindowsAzureIps -- it could not be removed{1}' -f $a.ServerName, $(if (-not $rm.Ok) { ': ' + $rm.Error } else { '' }))
    } catch { [string]$_.Exception.Message }
}

function Get-SIInstallSqlAdminGroupArgs {
    <# The arguments of setup/Set-SISqlAdminGroup.ps1 for this install: the admin group (grp-si-sql-admins, or the
       customer's own group by its id) with the installing identity as a member. Throws when a named group is not found. #>
    param([Parameter(Mandatory)]$Ctx)
    $v = $Ctx.Values; $n = $Ctx.Names
    $ga = [ordered]@{ SqlServerName = $n.SqlServer; ResourceGroupName = $n.ResourceGroup; SubscriptionId = [string]$v['subscriptionId']; MemberObjectIds = @([string]$Ctx.Facts['userObjectId']) }
    if ($v['sqlAdminGroupId']) {
        $g = $null; try { $g = Invoke-SIInstallGraph -Ctx $Ctx -Uri ('https://graph.microsoft.com/v1.0/groups/{0}?$select=id,displayName' -f $v['sqlAdminGroupId']) } catch { }
        if (-not $g) { throw (New-SIInstallFailure -Message ('The database admin group {0} was not found (or your account cannot read it).' -f $v['sqlAdminGroupId']) -ActionText 'Check the group id in the wizard, or leave it empty to use grp-si-sql-admins.') }
        $ga.GroupName = [string](Get-SIInstallProp $g 'displayName')
    }
    # framework §5.5 / §12.11c (Invardia ruling 2026-11-07): a NEW group is created under its STANDARD name from the start --
    # grp-si-sql-admins in both editions (framework PRO-COMMUNITY-SAME) -- never a display name of its own. A display name
    # is passed only when an install record carries one that differs (an install from before keeps what it has).
    elseif ($n -is [System.Collections.IDictionary]) {
        # the names table's group (an existing Community install recorded grp-si-community-sql-admins and keeps it)
        $gn = Get-SIInstallSqlAdminGroupName -Names $n
        if ($gn -cne 'grp-si-sql-admins') { $ga.GroupName = $gn }
        if ($n.Contains('SqlAdminGroupDisplayName') -and [string]$n['SqlAdminGroupDisplayName'] -and [string]$n['SqlAdminGroupDisplayName'] -cne $gn) { $ga.DisplayName = [string]$n['SqlAdminGroupDisplayName'] }
    }
    $ga
}

function Get-SIInstallSqlAdminGroupName {
    <# PURE. The name this install's SQL admin group is looked up and created by: the names table's SqlAdminGroupName
       (grp-si-sql-admins for every new install, both editions -- framework PRO-COMMUNITY-SAME; an existing Community install's
       record keeps grp-si-community-sql-admins), else grp-si-sql-admins (a table made before the key existed). #>
    param([AllowNull()]$Names)
    $g = ''
    if ($Names -is [System.Collections.IDictionary]) { if ($Names.Contains('SqlAdminGroupName')) { $g = [string]$Names['SqlAdminGroupName'] } }
    elseif ($null -ne $Names -and $Names.PSObject.Properties['SqlAdminGroupName']) { $g = [string]$Names.SqlAdminGroupName }
    if ("$g".Trim()) { "$g".Trim() } else { 'grp-si-sql-admins' }
}

function Restore-SIInstallSqlAdminGroup {
    <# #616: after the last database step of an install that ran as an application, the admin GROUP is the database
       server's administrator again (Set-SISqlAdminGroup, safe to repeat). Returns '' when done or not needed, else the
       reason it could not be done -- the install does not fail on it; the application stays the administrator until
       the command is run again. #>
    param([Parameter(Mandatory)]$Ctx)
    $facts = $null; try { $facts = $Ctx.Facts } catch { }
    if (-not ($facts -is [System.Collections.IDictionary])) { return '' }
    if (-not (Test-SIInstallSignedInAsApp -Ctx $Ctx)) { return '' }
    # only when this install (this run or an earlier one -- the fact is kept in the state) made the application the administrator
    if (-not [bool]$facts['sqlAdminIsInstallApp']) { return '' }
    try {
        $r = Invoke-SIInstallScript -Ctx $Ctx -RelativePath 'setup/Set-SISqlAdminGroup.ps1' -Arguments (Get-SIInstallSqlAdminGroupArgs -Ctx $Ctx)
        if ($r.Error) { return [string]$r.Error }
        $Ctx.Facts['sqlAdminIsInstallApp'] = $false
        ''
    } catch { [string]$_.Exception.Message }
}

function Get-SIInstallEndCheck {
    <#
        THE END-OF-INSTALL CHECK (Pro): what the steps reported is READ BACK from Azure once more, so an install is never
        "in place" on something that is not there -- the two databases, the rule that lets the install's own jobs and web
        app reach the database server, the web app's address and its reply address on the sign-in registration, the updater
        job and its right to change the install, and the identity on every worker job's queue rule (without it the workers
        never start). Reads only. Returns the problems as plain sentences (none = @()); something that could not be READ
        is not reported as missing. Never throws.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $bad = New-Object System.Collections.Generic.List[string]
    try {
        $n = $Ctx.Names; $v = $Ctx.Values; $rg = [string]$n.ResourceGroup
        $done = @($Ctx.State['completed']) + @($Ctx.State['pending'].Keys)
        # each problem is '<the step that makes it>|<the sentence>': the install runs that step again on the next run
        $from = 'pro-sql'
        if ($done -contains 'pro-sql') {
            foreach ($db in 'sqldb-si-pro', 'sqldb-si-identity') {
                # $true / $false; a read that fails throws (Ok = $false) and is then NOT taken for "missing"
                $r = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Test-SISqlDatabasePresent' -Arguments ([ordered]@{ ResourceGroupName = $rg; ServerName = $n.SqlServer; DatabaseName = $db })
                if ($r.Ok -and $r.Value -eq $false) { $bad.Add($from + '|' + ('the database {0} is not on {1}' -f $db, $n.SqlServer)) }
            }
            $r = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SISqlFirewallRule' -Arguments ([ordered]@{ ResourceGroupName = $rg; ServerName = $n.SqlServer; Name = 'AllowAllWindowsAzureIps' })
            if ([bool]$v['privateNetwork']) {
                # #1091 (a private Pro install on 3.0.31): a PRIVATE install's database has its public access closed and its
                # jobs and web app reach it through its private endpoint -- the rule must NOT be there (owner: "we cannot have
                # anything public"). Its PRESENCE is the problem; the private-network step takes it away.
                foreach ($x in @(Get-SIInstallSqlPrivateShapeCheck -Ctx $Ctx -RuleRead $r -Done $done)) { $bad.Add([string]$x) }
            }
            elseif ($r.Ok -and -not $r.Value) { $bad.Add($from + '|' + ('the database server {0} has no rule that lets the install''s own jobs and web app in (AllowAllWindowsAzureIps)' -f $n.SqlServer)) }
        }
        $from = 'web-app'
        if ($done -contains 'web-app' -and [bool]$v['webApp']) {
            $r = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SIContainerApp' -Arguments ([ordered]@{ ResourceGroupName = $rg; Name = (Get-SISetupComponentName -Names $n -Key WebApp) })
            $fqdn = ([string](Get-SIInstallProp (Get-SIInstallProp (Get-SIInstallProp (Get-SIInstallProp $r.Value 'properties') 'configuration') 'ingress') 'fqdn')).Trim()
            if ($r.Ok -and -not $fqdn) { $bad.Add($from + '|the web app has no address') }
            if ($fqdn -and [string]$Ctx.Facts['webAppId']) {
                $reg = $null; try { $reg = Invoke-SIInstallGraph -Ctx $Ctx -Uri ("https://graph.microsoft.com/v1.0/applications(appId='{0}')?`$select=web" -f $Ctx.Facts['webAppId']) } catch { $reg = $null }
                $web = Get-SIInstallProp $reg 'web'
                if ($web -and $null -ne (Get-SIInstallProp $web 'redirectUris')) {
                    $want = 'https://{0}/signin-oidc' -f $fqdn
                    if (@(@(Get-SIInstallProp $web 'redirectUris') | Where-Object { [string]$_ -ieq $want }).Count -eq 0) { $bad.Add($from + '|' + ('the web app''s sign-in registration does not list its reply address {0} -- nobody can sign in' -f $want)) }
                }
            }
        }
        $from = 'updater-job'
        if ($done -contains 'updater-job') {
            $r = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SIContainerAppJob' -Arguments ([ordered]@{ ResourceGroupName = $rg; Name = (Get-SISetupComponentName -Names $n -Key UpdaterJob) })
            if ($r.Ok -and -not $r.Value) { $bad.Add($from + '|' + ('the updater job {0} is not there' -f (Get-SISetupComponentName -Names $n -Key UpdaterJob))) }
            elseif ($r.Ok) {
                $ua = Get-SIInstallProp (Get-SIInstallProp $r.Value 'identity') 'userAssignedIdentities'
                $first = $null
                if ($ua -is [System.Collections.IDictionary]) { $first = @($ua.Values)[0] } elseif ($ua) { $first = @($ua.PSObject.Properties | ForEach-Object { $_.Value })[0] }
                $pid_ = [string](Get-SIInstallProp $first 'principalId')
                if ($pid_) {
                    $scope = '/subscriptions/{0}/resourceGroups/{1}' -f [string]$v['subscriptionId'], $rg
                    $ra = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Test-SIRoleAssignmentPresent' -Arguments ([ordered]@{ ObjectId = $pid_; Scope = $scope; RoleDefinitionName = 'Contributor' })
                    if ($ra.Ok -and $ra.Value -eq $false) { $bad.Add($from + '|' + ('the updater''s identity has no Contributor right on {0} -- it cannot update this install' -f $rg)) }
                }
            }
        }
        $from = 'container-jobs'
        if ($done -contains 'container-jobs') {
            $jobs = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SIContainerAppJobList' -Arguments ([ordered]@{ ResourceGroupName = $rg })
            foreach ($j in @($jobs.Value | Where-Object { $_ })) {
                $rules = @(Get-SIInstallProp (Get-SIInstallProp (Get-SIInstallProp (Get-SIInstallProp (Get-SIInstallProp $j 'properties') 'configuration') 'eventTriggerConfig') 'scale') 'rules' | Where-Object { $_ })
                foreach ($rule in $rules) {
                    if ([string](Get-SIInstallProp $rule 'type') -match '(?i)queue' -and -not ([string](Get-SIInstallProp $rule 'identity')).Trim() -and -not @(Get-SIInstallProp $rule 'auth' | Where-Object { $_ }).Count) {
                        $bad.Add($from + '|' + ('the worker job {0} has a queue rule without an identity -- its workers never start' -f [string](Get-SIInstallProp $j 'name')))
                    }
                }
            }
        }
        # The Invardia Support app's database access (both editions: Get-SIInstallSupportEndCheck)
        if (Get-Command -Name Get-SIInstallSupportEndCheck -ErrorAction SilentlyContinue) { foreach ($x in @(Get-SIInstallSupportEndCheck -Ctx $Ctx)) { if ($x) { $bad.Add([string]$x) } } }
    } catch { }
    $bad.ToArray()
}

function Start-SIInstallUpdaterOnce {
    <# THE END OF A FINISHED INSTALL: the updater job is started ONCE (as the first run is), so the licence record the web
       app reads exists now and not only after the night's run -- until then the Licence page said "Community". Only when
       the updater was installed and was not started by an earlier run. A start that fails is a line; the nightly schedule
       runs it. Returns $true when it was started now. Never throws. #>
    param([Parameter(Mandatory)]$Ctx)
    try {
        $job = [string]$Ctx.Facts['updaterJob']
        if (-not $job -or [string]$Ctx.Facts['updaterStarted']) { return $false }
        $r = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Start-SIContainerAppJob' -Arguments ([ordered]@{ ResourceGroupName = [string]$Ctx.Names.ResourceGroup; Name = $job })
        if (-not $r.Ok) {
            Write-SIInstallConsole -Ctx $Ctx -Text ('The updater job {0} could not be started now ({1}); it runs tonight on its own schedule. Until then the Licence page of the web app can say "Community".' -f $job, $r.Error) -Color Yellow
            return $false
        }
        $exec = [string](Get-SIInstallProp $r.Value 'name')
        $Ctx.Facts['updaterStarted'] = $(if ($exec) { $exec } else { $job })
        Write-SIInstallConsole -Ctx $Ctx -Text ('The updater job {0} was started once, so the licence is recorded for the web app now.' -f $job) -Color Green
        return $true
    } catch { return $false }
}

function Complete-SIInstallSqlAdmin {
    <# THE END OF THE RUN (a finished install AND a failed step): an install that ran as an application hands the database
       server's administration back to the admin group -- whichever database step ran last. A hand-back that fails is a
       WARNING with the command to run again, never a failed install; the fact stays in the state, so the next run tries
       again. Returns $true when the group is the administrator (or nothing was to do). Never throws. #>
    param([Parameter(Mandatory)]$Ctx)
    try {
        $back = Restore-SIInstallSqlAdminGroup -Ctx $Ctx
        if (-not $back) { return $true }
        $null = Send-SIInstallEvent -Ctx $Ctx -StepId 'pro-sql' -State 'warning' `
            -Message ('The database server''s administrator is still the application this install runs as, not the admin group: {0}' -f $back) `
            -Action ([ordered]@{ text = 'Run the install command again: it sets the admin group at its end.'; command = $Ctx.ResumeCommand })
        return $false
    } catch { return $false }
}

function Use-SIInstallUserSqlToken {
    <#
        Runs -Action with the SQL scripts' token hook pointing at the signed-in person (the Token seam). The scripts take
        the managed-identity path ($global:SI_UseManagedIdentity) and ask Get-SIManagedIdentityToken for the token; both
        are restored afterwards, so nothing outlives the call.
    #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][scriptblock]$Action)
    # #564: the scripts below reach the database from THIS machine -- the install-owned AllowSetupHost rule first
    Open-SIInstallSqlHostWindow -Ctx $Ctx
    # #616: an install that runs as an APPLICATION does its database steps as the server's own administrator
    Set-SIInstallSqlAppAdmin -Ctx $Ctx
    $tok = $Ctx.Seams.Token
    $oldFn = $null
    $have = Get-Command -Name Get-SIManagedIdentityToken -CommandType Function -ErrorAction SilentlyContinue
    if ($have) { $oldFn = $have.ScriptBlock }
    $hadVar = Test-Path -Path 'variable:global:SI_UseManagedIdentity'; $oldVar = $null; if ($hadVar) { $oldVar = $global:SI_UseManagedIdentity }
    $hook = { param([string]$Resource, [string]$ClientId, [switch]$ForceRefresh, [scriptblock]$Invoke, [scriptblock]$ReadFile) & $tok $Resource }.GetNewClosure()
    Set-Item -Path 'function:global:Get-SIManagedIdentityToken' -Value $hook
    $global:SI_UseManagedIdentity = $true
    # Live 2026-10-06 (customer I ring-2 Pro, AzContext sign-in, on an Azure VM): the global hook above is NOT enough. SI-SetupAzure.ps1
    # dot-sources auth/SI-ManagedIdentity.ps1 into the install's own scope, and that Get-SIManagedIdentityToken SHADOWS the
    # global hook for every script the install runs -- the SQL token came from the VM's IMDS identity ("Login failed for
    # user '<token-identified principal>'"). THE explicit provider: Get-SIManagedIdentityToken (every copy) and the az-token
    # grant scripts ask $global:SI_InstallTokenProvider FIRST, so no helper probes an identity endpoint during the install.
    $hadProv = Test-Path -Path 'variable:global:SI_InstallTokenProvider'; $oldProv = $null; if ($hadProv) { $oldProv = $global:SI_InstallTokenProvider }
    $global:SI_InstallTokenProvider = { param([string]$Resource) & $tok $Resource }.GetNewClosure()
    try { & $Action }
    finally {
        if ($hadProv) { $global:SI_InstallTokenProvider = $oldProv } else { Remove-Variable -Name SI_InstallTokenProvider -Scope Global -ErrorAction SilentlyContinue }
        # ('function:global:X' is a valid path for Set-Item but NOT for Remove-Item, which then silently removes nothing)
        if ($oldFn) { Set-Item -Path 'function:global:Get-SIManagedIdentityToken' -Value $oldFn } else { Remove-Item -Path 'function:Get-SIManagedIdentityToken' -Force -ErrorAction SilentlyContinue }
        if ($hadVar) { $global:SI_UseManagedIdentity = $oldVar } else { Remove-Variable -Name SI_UseManagedIdentity -Scope Global -ErrorAction SilentlyContinue }
    }
}

function Get-SIInstallSqlArgs {
    <# The arguments the Pro SQL scripts take. They check that an identity is named; the token comes from the hook, so the thumbprint is a label only. #>
    param([Parameter(Mandatory)]$Ctx, [string]$Database = $script:SIInstallProDatabase)
    [ordered]@{ Server = (Get-SIInstallSqlFqdn -Ctx $Ctx); Database = $Database; AppId = [string]$Ctx.Facts['identityClientId']
                TenantId = [string]$Ctx.Values['tenantId']; CertThumbprint = 'signed-in-user' }
}

function Assert-SIInstallScriptOk {
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$What)
    if ($Result.Error) {
        $hint = if ($Result.Error -match '(?i)firewall|not allowed to access the server|40615') {
            # #564: the install sets the rule itself (AllowSetupHost, this machine's current address); the hand step is the portal
            ('This shell cannot reach the database. The install sets the firewall rule {0} for this machine''s address itself; if that was not possible here, add it -- {1} > Add your client IPv4 address -- then run the install command again.' -f $script:SIInstallSqlHostRule, (Get-SIInstallSqlHostPortalText -Ctx $Ctx))
        } else { 'Fix the cause, then run the install command again: it continues from this step.' }
        throw (New-SIInstallFailure -Message ('{0} failed: {1}' -f $What, $Result.Error) -ActionText $hint -Command $Ctx.ResumeCommand -Detail @{ log = (Get-SIInstallTail $Result.Text) })
    }
}

function Get-SIInstallArmError {
    <# PURE. "<code>: <message>" from an ARM error response (Invoke-SIAzRestMethod shape), or '' when it carries none. #>
    param($Response)
    $b = $null; try { $b = [string](Get-SIInstallProp $Response 'Content') | ConvertFrom-Json } catch { }
    $e = Get-SIInstallProp $b 'error'
    if (-not $e) { return '' }
    $code = [string](Get-SIInstallProp $e 'code'); $msg = [string](Get-SIInstallProp $e 'message')
    (@($code, $msg) | Where-Object { $_ }) -join ': '
}

function Test-SIInstallArmUnregistered {
    <# PURE. True when ARM refused a provider call because the resource provider is not registered on the subscription
       (MissingSubscriptionRegistration / SubscriptionNotRegistered; SubscriptionNotFound is what a name check answers then). #>
    param($Response)
    if ([int](Get-SIInstallProp $Response 'StatusCode') -lt 400) { return $false }
    (Get-SIInstallArmError -Response $Response) -match '^(MissingSubscriptionRegistration|SubscriptionNotRegistered|SubscriptionNotFound)\b'
}

function Test-SIInstallSqlUnregistered {
    <# True when preflight-providers found Microsoft.Sql not registered yet (the install registers it before pro-sql). #>
    param($Ctx)
    @($Ctx.Facts['providersToRegister'] | Where-Object { $_ }) -contains 'Microsoft.Sql'
}

function Get-SIInstallDbJobAdminGroup {
    <# The SQL admin group's object id for the database setup job: the server's Entra administrator when it is a group, else
       the install's own group (the answer sqlAdminGroupId, else the group by the name the install gave it). '' = not found. #>
    param([Parameter(Mandatory)]$Ctx)
    $cur = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SISqlServerEntraAdmin' -Arguments ([ordered]@{ ResourceGroupName = $Ctx.Names.ResourceGroup; Name = $Ctx.Names.SqlServer })
    if ($cur.Ok -and $cur.Value -and [string](Get-SIInstallProp $cur.Value 'PrincipalType') -ieq 'Group' -and [string](Get-SIInstallProp $cur.Value 'Sid')) { return [string](Get-SIInstallProp $cur.Value 'Sid') }
    $gid = ([string]$Ctx.Values['sqlAdminGroupId']).Trim()
    if ($gid) { return $gid }
    $names = @((Get-SIInstallSqlAdminGroupName -Names $Ctx.Names))
    if ($Ctx.Names -is [System.Collections.IDictionary] -and $Ctx.Names.Contains('SqlAdminGroupDisplayName') -and [string]$Ctx.Names['SqlAdminGroupDisplayName']) { $names += [string]$Ctx.Names['SqlAdminGroupDisplayName'] }
    foreach ($nm in @($names | Select-Object -Unique)) {
        try {
            $g = Invoke-SIInstallGraph -Ctx $Ctx -Uri ("https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '{0}'&`$select=id,displayName" -f $nm.Replace("'", "''"))
            $one = @(Get-SIInstallProp $g 'value' | Where-Object { $_ })
            if ($one.Count -eq 1) { return [string](Get-SIInstallProp $one[0] 'id') }
        } catch { }
    }
    ''
}

function Invoke-SIInstallDbJob {
    <#
        framework SEC-08 (Invardia DESIGN ch 12 points 1-3, 7, 8): the guided install's database setup job.
          1. the job's OWN identity id-si-dbinit in the install's resource group (made, read back);
          2. a member of the install's SQL admin group (the server's Entra administrator) -- added with the person's sign-in
             (an Entra step, not SQL: the one rights step a person does) and READ BACK from the identity's memberOf BEFORE
             the job is started (a managed identity's token is cached for hours: started too early, it would keep a token
             without the group);
          3. the job caj-si-dbinit made with the engine jobs' image, environment and pull identity and the install's
             product identities, started ONCE (SI_DBINIT_BY installer, the Invardia Support app when the install names one),
             waited for; its result = the execution's own status (the job exits 0 only when every identity read back).
        Returns a step result. Anything that could not be done is a WARNING with what to do, never a failed install: the
        steps before it gave the same database rights with the person's sign-in on this version.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names; $nn = Get-SIDbInitNames
    $sub = [string]$Ctx.Values['subscriptionId']; $rg = [string]$n.ResourceGroup
    # NOT closures: they run inside the shared functions and find $__siDbCtx in this function's scope
    $__siDbCtx = $Ctx
    $arm = { param([string]$Method, [string]$Path, $Body)
        $a = [ordered]@{ Method = $Method; Path = $Path }
        if ($null -ne $Body) { $a['Body'] = $Body }
        if ($Method -eq 'GET') { $a['AllowNotFound'] = $true }
        Invoke-SIInstallAz -Ctx $__siDbCtx -Command 'Invoke-SIArm' -Arguments $a }
    $graph = { param([string]$Method, [string]$Uri, $Body) Invoke-SIInstallGraph -Ctx $__siDbCtx -Method $Method -Uri $Uri -Body $Body }
    $sleep = $Ctx.Seams.Sleep
    $warn = { param($msg, $what) New-SIInstallResult -State 'warning' -Message ('The database setup job: {0}' -f $msg) -Action ([ordered]@{ text = $what; command = $Ctx.ResumeCommand }) }
    try {
        # an install signed in as an application made itself the server's administrator for its own steps (#616): the job
        # signs in through the GROUP, so the group is the administrator again first (a later step sets the app again)
        if ([bool]$Ctx.Facts['sqlAdminIsInstallApp']) { $back = Restore-SIInstallSqlAdminGroup -Ctx $Ctx; if ($back) { return (& $warn ('the admin group could not be made the database server''s administrator again ({0}), so the job was not started' -f $back) 'Run the install command again: it continues from this step.') } }
        # 1. the identity
        $jobs = @((Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SIContainerAppJobList' -Arguments ([ordered]@{ ResourceGroupName = $rg })).Value | Where-Object { $_ })
        $tpl = Get-SIDbInitTemplateJob -Jobs $jobs
        if (-not $tpl.Ok) { return (& $warn $tpl.Problem 'Run the install command again once the engine jobs are there; or the next update makes the job.') }
        $mi = Set-SIDbInitIdentity -Arm $arm -SubscriptionId $sub -ResourceGroup $rg -Location $tpl.Location -Sleep $sleep
        if (-not $mi.Ok) { return (& $warn $mi.Problem 'Run the install command again: it continues from this step.') }
        # 2. the membership, read back from the identity's side
        $gid = Get-SIInstallDbJobAdminGroup -Ctx $Ctx
        if (-not $gid) { return (& $warn ('the SQL admin group of {0} was not found, so its identity {1} could not be made a member' -f $n.SqlServer, $nn.Identity) 'Make the admin group the database server''s administrator (setup\Set-SISqlAdminGroup.ps1), then run the install command again.') }
        # framework §4.5 SQL-ADMIN-GROUP G2-G4: converged (direct, else an active PIM-for-Groups assignment) and renewed when it
        # ends within 30 days -- the same path the updater runs on every update
        $m = Sync-SIDbInitMembership -Graph $graph -PrincipalId $mi.PrincipalId -GroupId $gid -Sleep $sleep -Print { param($t) Write-SIInstallConsole -Ctx $__siDbCtx -Text $t -Color 'DarkGray' }
        if ($m.State -notin 'already', 'added') {
            return (& $warn ('its identity {0} is not a member of the SQL admin group ({1}), so the job was not started -- the product starts it once the membership is there' -f $nn.Identity, $m.Detail) `
                ('An Entra administrator (Privileged Role Administrator for a role-assignable group) adds the managed identity {0} to the SQL admin group; then run the install command again.' -f $nn.Identity))
        }
        if ($m.Renewal -and [string]$m.Renewal.State -in 'renewed', 'failed') { Write-SIInstallConsole -Ctx $__siDbCtx -Text ('   {0}' -f $m.Renewal.Detail) -Color $(if ($m.Renewal.State -eq 'failed') { 'Yellow' } else { 'DarkGray' }) }
        # 3. the job, one run, its result
        $principals = New-Object System.Collections.Generic.List[object]
        $addP = { param($c, $name, $cid) if ($name -and "$cid" -match '^[0-9a-fA-F-]{36}$' -and -not @($principals | Where-Object { $_.clientId -ieq $cid -or $_.component -eq $c }).Count) { $principals.Add([ordered]@{ component = $c; name = [string]$name; clientId = [string]$cid }) } }
        & $addP 'engine' ([string]$n.ManagedIdentity) ([string]$Ctx.Facts['identityClientId'])
        $updPid = ''
        foreach ($k in @(@{ C = 'updater'; K = 'UpdaterIdentity' }, @{ C = 'web'; K = 'WebIdentity' }, @{ C = 'mcp'; K = 'McpIdentity' }, @{ C = 'tagging'; K = 'TaggingIdentity' })) {
            $idName = Get-SISetupComponentName -Names $n -Key $k.K
            $r = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SIUserAssignedIdentity' -Arguments ([ordered]@{ ResourceGroupName = $rg; Name = $idName; ErrorAction = 'SilentlyContinue' })
            if ($r.Ok -and $r.Value) {
                & $addP $k.C $idName ([string](Get-SIInstallProp $r.Value 'ClientId'))
                if ($k.C -eq 'updater') { $updPid = [string](Get-SIInstallProp $r.Value 'PrincipalId') }
            }
        }
        # framework §4.5 G5: the updater identity's Microsoft Graph permissions -- the three PIM-for-Groups rights + GroupMember.Read.All + Application.Read.All (read only), granted
        # here with the person's sign-in (the updater cannot grant itself) and read back
        $g5 = $null
        if ($updPid) {
            $g5 = Grant-SIDbInitUpdaterGraphRoles -Graph $graph -PrincipalId $updPid -Sleep $sleep
            Write-SIInstallConsole -Ctx $__siDbCtx -Text ('   {0}' -f $g5.Detail) -Color $(if ($g5.Ok) { 'DarkGray' } else { 'Yellow' })
        }
        if (-not @($principals | Where-Object { $_.component -eq 'engine' }).Count) { return (& $warn 'the engine identity''s client id is not known to this run' 'Run the install command again: it continues from this step.') }
        . ([IO.Path]::Combine($Ctx.SIRoot, 'engine', 'pro-settings', 'SI-GrantProcedure.ps1'))
        . ([IO.Path]::Combine($Ctx.SIRoot, 'engine', 'pro-settings', 'SI-EngineGrants.ps1'))
        # the job's lines reach the install's Log Analytics workspace (a warning only, never a stop)
        $wsId = $tpl.WorkspaceResourceId; if (-not $wsId) { try { $wsId = [string](Get-SIInstallInfra -Ctx $Ctx)['WorkspaceResourceId'] } catch { $wsId = '' } }
        $lg = Set-SIDbInitEnvironmentLogs -Arm $arm -EnvironmentId $tpl.EnvironmentId -WorkspaceResourceId $wsId
        Write-SIInstallConsole -Ctx $Ctx -Text ('   ' + $lg.Line) -Color $(if ($lg.Ok) { 'DarkGray' } else { 'Yellow' })
        $body = Get-SIDbInitJobBody -Location $tpl.Location -EnvironmentId $tpl.EnvironmentId -Image $tpl.Image -RegistryServer $tpl.RegistryServer -PullIdentityId $tpl.PullIdentityId `
                    -IdentityId $mi.Id -IdentityClientId $mi.ClientId -Server (Get-SIInstallSqlFqdn -Ctx $Ctx) -Database $script:SIInstallProDatabase -LedgerDatabase $script:SIInstallLedgerDatabase `
                    -Principals $principals.ToArray() -SignedGrants ([bool](Test-SIGrantProcedureSetup -Values $Ctx.Values)) -EngineRoleOnly ([bool](Test-SIEngineLeastPrivilegeSetup -Values $Ctx.Values))
        $job = Set-SIDbInitJob -Arm $arm -SubscriptionId $sub -ResourceGroup $rg -Body $body -Sleep $sleep
        if (-not $job.Ok) { return (& $warn $job.Problem 'Run the install command again: it continues from this step.') }
        $app = ''; try { $app = ([string]$Ctx.Values['supportAppId']).Trim() } catch { $app = '' }
        $support = if ($app -match '^[0-9a-fA-F-]{36}$') { '{0}|{1}' -f $app, 'invardia-support-app' } else { '' }
        $run = Start-SIDbInitRun -Arm $arm -JobId $job.JobId -Job $job.Job -By 'installer' -Support $support -Sleep $sleep
        $Ctx.Facts['dbJobExecution'] = $run.Execution
        if (-not $run.Ok) {
            return (& $warn ('the run {0} ended {1} -- its lines: {2}' -f $(if ($run.Execution) { $run.Execution } else { '(not started)' }), $run.Status, (Get-SIDbInitLogText -ResourceGroup $rg -Execution $run.Execution)) `
                'Fix the cause the job''s lines name, then run the install command again; the next update also runs it.')
        }
        if ($g5 -and -not $g5.Ok) {
            return (& $warn ('it ran (execution {0}), but {1} -- without them the updater cannot keep the job identity''s membership of the SQL admin group current' -f $run.Execution, $g5.Detail) `
                'An Entra administrator grants the updater identity those Microsoft Graph application permissions (or run the install command again with that right).')
        }
        New-SIInstallResult -Message ('The database setup job {0} ran as its own identity {1} (a member of the SQL admin group, read back): every database user of the install was made and read back (execution {2}). Updates run it again; nobody needs database admin rights for it.' -f $nn.Job, $nn.Identity, $run.Execution)
    } catch {
        & $warn ('it could not be set up: {0}' -f $_.Exception.Message) 'Run the install command again: it continues from this step.'
    }
}

function Get-SIInstallDataStepTable {
    $t = @{}

    $t['preflight-names-pro'] = {
        param($ctx)
        $n = $ctx.Names
        $srv = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SISqlServer' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; ServerName = $n.SqlServer; ErrorAction = 'SilentlyContinue' })
        if ($srv) { $ctx.Facts['sqlServerExisted'] = $true; return @() }
        # Before Microsoft.Sql is registered ARM refuses the name check (MissingSubscriptionRegistration): the name is
        # checked when the server is created, after the install registers the provider (preflight-names lists it).
        if (Test-SIInstallSqlUnregistered -Ctx $ctx) { return @() }
        $chk = Invoke-SIInstallAz -Ctx $ctx -Command 'Invoke-SIAzRestMethod' -Arguments ([ordered]@{ Method = 'POST'
            Path = ('/subscriptions/{0}/providers/Microsoft.Sql/checkNameAvailability?api-version=2021-11-01' -f $ctx.Values['subscriptionId'])
            Payload = (@{ name = $n.SqlServer; type = 'Microsoft.Sql/servers' } | ConvertTo-Json -Compress) })
        $body = $null; try { $body = [string](Get-SIInstallProp $chk 'Content') | ConvertFrom-Json } catch { }
        # SQL server names are DNS names (<name>.database.windows.net): unique across ALL of Azure, so say whose it is
        if (Test-SIInstallArmUnregistered -Response $chk) { return @() }
        # only a real answer ({"available":false}) says the name is taken -- an ARM error body is not one
        if ($body -and $null -ne (Get-SIInstallProp $body 'available') -and -not [bool](Get-SIInstallProp $body 'available')) { return @((Get-SIInstallNameTakenText -Ctx $ctx -What 'database server' -Name $n.SqlServer -Type 'Microsoft.Sql/servers')) }
        @()
    }

    $t['preflight-sql-region'] = {
        param($ctx)
        $loc = [string]$ctx.Values['sqlLocation']
        if ([bool]$ctx.Facts['sqlServerExisted']) { return (New-SIInstallResult -Message ('The database server {0} already exists.' -f $ctx.Names.SqlServer)) }
        # Live 2026-10-07 (a fresh subscription): before Microsoft.Sql is registered ARM refuses the capabilities call
        # (MissingSubscriptionRegistration) -- that says nothing about the region. The install registers the provider
        # itself, so the region is checked when the server is created (pro-sql names the region if Azure refuses it).
        $later = 'The region {0} is checked when the database server is created, after the install registers Microsoft.Sql.' -f $loc
        if (Test-SIInstallSqlUnregistered -Ctx $ctx) { return (New-SIInstallResult -Message $later) }
        $r = Invoke-SIInstallAz -Ctx $ctx -Command 'Invoke-SIAzRestMethod' -Arguments ([ordered]@{ Method = 'GET'
            Path = ('/subscriptions/{0}/providers/Microsoft.Sql/locations/{1}/capabilities?api-version=2021-11-01' -f $ctx.Values['subscriptionId'], $loc) })
        if (Test-SIInstallArmUnregistered -Response $r) { return (New-SIInstallResult -Message $later) }
        $cap = $null; try { $cap = [string](Get-SIInstallProp $r 'Content') | ConvertFrom-Json } catch { }
        $status = [string](Get-SIInstallProp $cap 'status')
        # No real capabilities answer (another ARM error, an empty body): the region could not be checked -- not a refusal.
        if ([int](Get-SIInstallProp $r 'StatusCode') -ge 400 -or -not $status) {
            $err = Get-SIInstallArmError -Response $r
            return (New-SIInstallResult -State 'warning' -Message ('The region {0} could not be checked now{1}; it is checked when the database server is created.' -f $loc, $(if ($err) { " ($err)" } else { '' })))
        }
        # Only a real answer refuses: a status other than Available/Default/Visible, or a reason that says so.
        $reason = [string](Get-SIInstallProp $cap 'reason')
        if ($status -notin 'Available', 'Default', 'Visible' -or $reason -match '(?i)not available|restricted|not allowed|not accept|disabled') {
            throw (New-SIInstallFailure -Message ('Azure SQL does not accept new servers in {0} for this subscription{1}.' -f $loc, $(if ($reason) { " ($reason)" } else { " (status $status)" })) `
                -ActionText 'Choose another region for the database in the wizard -- another region in the same geography works.')
        }
        New-SIInstallResult -Message ('{0} accepts the database.' -f $loc)
    }

    $t['pro-sql'] = {
        param($ctx)
        $v = $ctx.Values; $n = $ctx.Names; $sub = [string]$v['subscriptionId']
        $oid = [string]$ctx.Facts['userObjectId']; $upn = [string]$ctx.Facts['userPrincipalName']
        $created = @()
        $srv = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SISqlServer' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; ServerName = $n.SqlServer; ErrorAction = 'SilentlyContinue' })
        if (-not $srv) {
            # Entra-only from the first second. The person installing is the first admin so the next steps can build the
            # schema; Set-SISqlAdminGroup below hands the admin to the group, with that person a member. An install signed
            # in as an application (#413, the Invardia Support app) is the first admin AS an Application -- SQL names an
            # app by its client id -- and a member of the group the same way (a group may contain service principals).
            $asApp = Test-SIInstallSignedInAsApp -Ctx $ctx
            $acct = [string]$ctx.Facts['account']
            $sid = if ($asApp -and $acct -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { $acct } else { $oid }
            # #521: ARM PUT, Entra-only from the first second (New-SISqlServerEntraOnly) -- no az CLI
            $r = Invoke-SIInstallArmTry -Ctx $ctx -Command 'New-SISqlServerEntraOnly' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; Name = $n.SqlServer
                Location = [string]$v['sqlLocation']; AdminType = $(if ($asApp) { 'Application' } else { 'User' }); AdminName = $(if ($upn) { $upn } else { $oid }); AdminSid = $sid; SubscriptionId = $sub
                # #866: a private install CREATES the server with no public access; its private endpoint follows at once
                PublicNetworkAccess = $(if ([bool]$v['privateNetwork']) { 'Disabled' } else { 'Enabled' }) })
            if (-not $r.Ok) {
                # The region check deferred from preflight (Microsoft.Sql was not registered yet) lands here: say it plainly.
                if ([string]$r.Error -match '(?i)RegionDoesNotAllowProvisioning|ProvisioningDisabled|LocationNotAvailable|not accepting creation|is not available for (this )?subscription|provisioning is restricted') {
                    throw (New-SIInstallFailure -Message ('Azure SQL does not accept new servers in {0} for this subscription: {1}' -f $v['sqlLocation'], $r.Error) `
                        -ActionText 'Choose another region for the database in the wizard -- another region in the same geography works -- and run the install command again.' -Command $ctx.ResumeCommand)
                }
                throw (New-SIInstallFailure -Message ('The database server could not be created: {0}' -f $r.Error) `
                    -ActionText 'If the region does not accept new servers, choose another database region in the wizard; otherwise run the install command again.' -Command $ctx.ResumeCommand)
            }
            # a server that was there after all (its read above failed) is waited for, never created over
            if (-not [bool](Get-SIInstallProp $r.Value 'SIExisted')) {
                $created += 'server'
                # recorded (and kept for a resume): the security baseline below touches only a server THIS install created
                $ctx.Facts['sqlServerCreatedAt'] = (& $ctx.Seams.Now).ToString('o')
            }
        }
        # Azure services (Cloud Shell, the jobs, the web app) reach it; there is no public rule for anything else.
        Set-SIInstallSqlAzureServicesRule -Ctx $ctx
        # #507 / #509: never Basic -- the Pro database S3 at any size (S2 until 2026-10-11), the ledger S1 (2026-10-09, a 23,000-user tenant: Basic's log writes peaked at 98 %)
        # the identity ledger (identifiers only) is S1 at any tenant size; the Pro database takes the record writes
        $sizes = New-Object System.Collections.Generic.List[string]
        $existing = 0
        foreach ($db in $script:SIInstallProDatabase, $script:SIInstallLedgerDatabase) {
            $have = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SISqlDatabase' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; ServerName = $n.SqlServer; DatabaseName = $db; ErrorAction = 'SilentlyContinue' })
            if ($have) { $existing++; continue }
            $sqlTier = if ($db -eq $script:SIInstallLedgerDatabase) { Get-SISqlDatabaseTier -Objects $null -Role Ledger } else { Get-SIInstallSqlTier -Ctx $ctx }
            # #521: ARM PUT at the tier's size (sku + maxSizeBytes), local backup redundancy (New-SISqlDatabaseArm -Target)
            $r = Invoke-SIInstallArmTry -Ctx $ctx -Command 'New-SISqlDatabaseArm' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; ServerName = $n.SqlServer
                Name = $db; Target = $sqlTier; Location = [string]$v['sqlLocation']; SubscriptionId = $sub })
            if (-not $r.Ok) { throw (New-SIInstallFailure -Message ('The database {0} could not be created: {1}' -f $db, $r.Error) -Command $ctx.ResumeCommand -ActionText 'Run the install command again: it continues from this step.') }
            # New-SISqlDatabaseArm never creates over a database that exists: one that was there after all (its read
            # above failed) keeps its size and gets the size rule of an existing database below
            if ([bool](Get-SIInstallProp $r.Value 'SIExisted')) { $existing++; continue }
            $created += $db
            $sizes.Add(('{0} is {1}' -f $db, $sqlTier.Reason))
        }
        # #511: a database that ALREADY exists (a re-run, a resume, an install over an older one) gets the same size rule as
        # every update -- never Basic, S0 at least, 250 GB -- instead of being left as it is (customer G / customer A 2026-10-09:
        # Basic, 2 GB). Raises only; never throws: a database that cannot be changed is a line, and the install goes on.
        if ($existing) {
            # #521: SI-SqlTier's -Rest seam answered over ARM, every call through the Az seam (no az process).
            # NOT a closure: a GetNewClosure() block cannot see the functions of a dot-sourced (script-scope) file; this one
            # runs inside Invoke-SISqlTierUpgrade's call and finds the variable below in this step's scope.
            $__siSqlTierCtx = $ctx
            $sqlRest = { param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers) Invoke-SIInstallSqlTierRestCall -Ctx $__siSqlTierCtx -Method $Method -Uri $Uri -Body $Body -Resource $Resource -Headers $Headers }
            try {
                $up = Invoke-SISqlTierUpgrade -Rest $sqlRest -SubscriptionId $sub -ResourceGroup $n.ResourceGroup -ServerFqdns @(('{0}.database.windows.net' -f $n.SqlServer)) `
                        -DatabaseNames @($script:SIInstallProDatabase) -LedgerDatabaseNames @($script:SIInstallLedgerDatabase) -Objects (Get-SIInstallSqlTier -Ctx $ctx).Objects
                foreach ($x in @($up.Results)) { if ($x.Database -and $x.Action -ne 'keep') { $sizes.Add(($x.Line -replace '^SQL database size: ', '')) } }
            } catch { $sizes.Add(('the size of the existing databases was not checked ({0}) -- the next update checks it' -f $_.Exception.Message)) }
        }
        $ctx.Facts['sqlServerId'] = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Sql/servers/{2}' -f $sub, $n.ResourceGroup, $n.SqlServer
        # #866: a PRIVATE install -- the server's private endpoint and zone RIGHT AFTER it is made, then the DNS check from
        # this machine BEFORE any statement is sent to it (the install waits for the hub's DNS record otherwise)
        if ([bool]$v['privateNetwork'] -and (Get-Command -Name Invoke-SIInstallPrivateDataGate -ErrorAction SilentlyContinue)) {
            $null = Invoke-SIInstallPrivateDataGate -Ctx $ctx -SqlServerId ([string]$ctx.Facts['sqlServerId']) -What 'the Pro database server'
        }
        # The admin = ONE role-assignable group (grp-si-sql-admins, or the customer's own group), never a person.
        $ga = [ordered]@{ SqlServerName = $n.SqlServer; ResourceGroupName = $n.ResourceGroup; SubscriptionId = $sub; MemberObjectIds = @($oid) }
        if ($v['sqlAdminGroupId']) {
            $g = $null; try { $g = Invoke-SIInstallGraph -Ctx $ctx -Uri ('https://graph.microsoft.com/v1.0/groups/{0}?$select=id,displayName' -f $v['sqlAdminGroupId']) } catch { }
            if (-not $g) { throw (New-SIInstallFailure -Message ('The database admin group {0} was not found (or your account cannot read it).' -f $v['sqlAdminGroupId']) -ActionText 'Check the group id in the wizard, or leave it empty to use grp-si-sql-admins.') }
            $ga.GroupName = [string](Get-SIInstallProp $g 'displayName')
        } else {
            # SI #750: a new Community edition install creates / finds ITS OWN group, under its own names -- never the group of a
            # Pro install in the same tenant (an install with today's names keeps grp-si-sql-admins: nothing is passed)
            $gn = Get-SIInstallSqlAdminGroupName -Names $n
            if ($gn -cne 'grp-si-sql-admins') {
                $ga.GroupName = $gn
                if ([string]$n['SqlAdminGroupDisplayName'] -and [string]$n['SqlAdminGroupDisplayName'] -cne $gn) { $ga.DisplayName = [string]$n['SqlAdminGroupDisplayName'] }
            }
        }
        $r = Invoke-SIInstallScript -Ctx $ctx -RelativePath 'setup/Set-SISqlAdminGroup.ps1' -Arguments $ga
        # A group created seconds ago is not yet known everywhere: a "not found" (404) is waited for and tried again -- the
        # script is idempotent (customer H 2026-10-08: 404 on the first try, set without trouble on the resume).
        for ($try = 1; $r.Error -and "$($r.Error)" -match '(?i)\b404\b|not found|does not exist' -and $try -le 6; $try++) {
            & $ctx.Seams.Sleep 30
            $r = Invoke-SIInstallScript -Ctx $ctx -RelativePath 'setup/Set-SISqlAdminGroup.ps1' -Arguments $ga
        }
        # #695: the first sign-in after this may wait out a server that does not know its new administrator yet
        if (-not $r.Error) { Set-SIInstallSqlAdminSetAt -Ctx $ctx }
        $msg ='Database server {0} ({1}), Entra sign-in only{2}.' -f $n.SqlServer, $v['sqlLocation'], $(if ($created.Count) { '; created ' + ($created -join ', ') } else { '' })
        if ($sizes.Count) { $msg += (' ' + ($sizes -join '; ') + '.') }
        # SECURITY BASELINE (setup\_shared\SI-SecurityBaseline.ps1; ON by default since 2026-10-31,
        # SI_SECURITY_BASELINE_NEW_INSTALL=0 turns it off): SQL auditing of the server to the install's workspace, 90 days --
        # ONLY for a server THIS install created (sqlServerCreatedAt, kept for a resume): running the install command again
        # over a live install never changes its server (2026-11-01). Never fails the step -- a refusal is one line, and
        # setup\Set-SISecurityBaseline.ps1 turns it on later (an existing install: one environment at a time).
        if (Test-SISecurityBaselineAppliesTo -CreatedByThisInstall ([bool][string]$ctx.Facts['sqlServerCreatedAt'])) {
            $wsId = [string]$ctx.Facts['workspaceResourceId']
            if (-not $wsId) { $wsId = [string](Get-SIInstallInfra -Ctx $ctx)['WorkspaceResourceId'] }
            $au = Invoke-SIInstallArmTry -Ctx $ctx -Command 'Set-SISqlServerAuditSetup' -Arguments ([ordered]@{ ServerId = [string]$ctx.Facts['sqlServerId']; WorkspaceResourceId = $wsId })
            $msg += $(if ($au.Ok -and $au.Value -and $au.Value.Ok) { ' SQL auditing is on to the install''s workspace.' } else { (' SQL auditing is NOT on yet ({0}).' -f $(if ($au.Ok -and $au.Value) { @($au.Value.Lines) -join '; ' } else { $au.Error })) })
        }
        if ($r.Error) {
            $cmd = './setup/Set-SISqlAdminGroup.ps1 -SqlServerName {0} -ResourceGroupName {1} -SubscriptionId {2} -MemberObjectIds {3}{4}' -f $n.SqlServer, $n.ResourceGroup, $sub, $oid, $(if ($ga.Contains('GroupName')) { " -GroupName '" + $ga.GroupName + "'" } else { '' })
            return (New-SIInstallResult -State 'warning' -Message ($msg + (' Until the admin group is set, {0} the database''s administrator: {1}' -f $(if (Test-SIInstallSignedInAsApp -Ctx $ctx) { 'the application this install runs as ({0}) is' -f $(if ($upn) { $upn } else { $oid }) } else { 'you are' }), $r.Error)) `
                -Action ([ordered]@{ text = 'Ask a Privileged Role Administrator to run, in Azure Cloud Shell in this install''s folder:'; command = $cmd }) -Detail @{ log = (Get-SIInstallTail $r.Text) })
        }
        New-SIInstallResult -Message ($msg + (' Its administrator is the group {0}.' -f $(if ($ga.Contains('GroupName')) { $ga.GroupName } else { 'grp-si-sql-admins' })))
    }

    $t['pro-schema'] = {
        param($ctx)
        $n = $ctx.Names; $fqdn = Get-SIInstallSqlFqdn -Ctx $ctx
        # #616: the tables go into databases that EXIST. A database the server step reported and Azure never made (its
        # create was rejected after it was accepted) is made here, so a resume repairs it. A sign-in to a database that
        # is not there answers "Login failed" -- never chase the administrator before this is known.
        $sub = [string]$ctx.Values['subscriptionId']
        # the same for the rule that lets the install's own jobs and web app reach the server: set again and checked
        Set-SIInstallSqlAzureServicesRule -Ctx $ctx
        foreach ($db in $script:SIInstallProDatabase, $script:SIInstallLedgerDatabase) {
            $have = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SISqlDatabase' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; ServerName = $n.SqlServer; DatabaseName = $db; ErrorAction = 'SilentlyContinue' })
            if ($have) { continue }
            # created only when Azure says "not found" twice (New-SISqlDatabaseArm); never over a database that is there
            Write-SIInstallConsole -Ctx $ctx -Text ('      the database {0} was not found on {1} -- it is created if it really is not there' -f $db, $n.SqlServer)
            $sqlTier = if ($db -eq $script:SIInstallLedgerDatabase) { Get-SISqlDatabaseTier -Objects $null -Role Ledger } else { Get-SIInstallSqlTier -Ctx $ctx }
            $r = Invoke-SIInstallArmTry -Ctx $ctx -Command 'New-SISqlDatabaseArm' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; ServerName = $n.SqlServer
                Name = $db; Target = $sqlTier; Location = [string]$ctx.Values['sqlLocation']; SubscriptionId = $sub })
            if (-not $r.Ok) { throw (New-SIInstallFailure -Message ('The database {0} could not be created: {1}' -f $db, $r.Error) -Command $ctx.ResumeCommand -ActionText 'Run the install command again: it continues from this step.') }
        }
        Use-SIInstallUserSqlToken -Ctx $ctx -Action {
            # #695: the first sign-ins after the administrator was set wait out a server that does not know it yet
            Assert-SIInstallScriptOk -Ctx $ctx -What 'The vulnerability tables' -Result (Invoke-SIInstallSqlScriptAfterAdmin -Ctx $ctx -RelativePath 'setup/Initialize-SIVulnTargetSql.ps1' -Arguments (Get-SIInstallSqlArgs -Ctx $ctx))
            Assert-SIInstallScriptOk -Ctx $ctx -What 'The data tables' -Result (Invoke-SIInstallSqlScriptAfterAdmin -Ctx $ctx -RelativePath 'setup/Initialize-SIDataSql.ps1' -Arguments (Get-SIInstallSqlArgs -Ctx $ctx))
        }
        # The identity ledger, through the SCHEMA-1 gate. The approval is the person running this install, now, for this
        # tenant and this schema version -- recorded in the database next to the version it approved.
        . ([IO.Path]::Combine($ctx.SIRoot, 'engine', '_shared', 'SI-SchemaGate.ps1'))
        $sqlText = [IO.File]::ReadAllText([IO.Path]::Combine($ctx.SIRoot, 'sql', 'si-identity-schema.sql'))
        $who = if ($ctx.Facts['userPrincipalName']) { [string]$ctx.Facts['userPrincipalName'] } else { [string]$ctx.Facts['userObjectId'] }
        $approval = [pscustomobject]@{ TenantId = [string]$ctx.Values['tenantId']; SchemaVersion = $ctx.Version
            ApprovedAt = (& $ctx.Seams.Now).ToString('yyyy-MM-dd'); ApprovedBy = ('{0} (guided install {1})' -f $who, $ctx.InstallId) }
        $applied = @()
        try {
            $agg = [string](Invoke-SIInstallSql -Ctx $ctx -Server $fqdn -Database $script:SIInstallLedgerDatabase -Query "IF OBJECT_ID('si.SchemaVersion') IS NULL SELECT '' ELSE SELECT STRING_AGG(SchemaVersion, ',') FROM si.SchemaVersion")
            $applied = @($agg -split ',' | Where-Object { $_ })
        } catch { throw (New-SIInstallFailure -Message ('The identity ledger database cannot be reached: {0}' -f $_.Exception.Message) -ActionText ('The install sets the firewall rule {0} for this machine''s address itself; if that was not possible here, add it -- {1} > Add your client IPv4 address -- then run the install command again.' -f $script:SIInstallSqlHostRule, (Get-SIInstallSqlHostPortalText -Ctx $ctx)) -Command $ctx.ResumeCommand) }
        $plan = Get-SISchemaApplyPlan -Sql $sqlText -TenantId ([string]$ctx.Values['tenantId']) -SchemaVersion $ctx.Version -Approvals @($approval) -AppliedVersions $applied
        if ($plan.Action -eq 'refuse') {
            # #277: a refused schema is a guard trip (mail + telemetry; never instead of the refusal)
            try { if (-not (Get-Command -Name Send-SIGuardEvent -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($ctx.SIRoot, 'engine', '_shared', 'SI-Guard.ps1')) }; $null = Send-SIGuardEvent -GuardId 'schema.gate.refused' -Outcome 'refused' -Source 'setup' -Engine 'setup' -Subject 'sql/si-identity-schema.sql' -Detail $plan.Reason } catch { }
        }
        if ($plan.Action -eq 'refuse') { throw (New-SIInstallFailure -Message $plan.Reason -ActionText 'Contact Invardia support (support@invardia.com, or https://portal.invardia.com/ > Support) with this message; nothing was applied.') }
        $ledger = 'already up to date'
        if ($plan.Action -eq 'apply') {
            $k = 0
            foreach ($batch in ($sqlText -split '(?m)^\s*$') | Where-Object { ($_ -replace '(?m)^\s*--.*$', '').Trim() }) { $null = Invoke-SIInstallSql -Ctx $ctx -Server $fqdn -Database $script:SIInstallLedgerDatabase -Query $batch -Mode 'nonquery'; $k++ }
            $q = { param($s) "N'" + ([string]$s).Replace("'", "''") + "'" }
            $null = Invoke-SIInstallSql -Ctx $ctx -Server $fqdn -Database $script:SIInstallLedgerDatabase -Mode 'nonquery' -Query ("IF NOT EXISTS (SELECT 1 FROM si.SchemaVersion WHERE SchemaVersion = {0}) INSERT si.SchemaVersion (SchemaVersion, AppliedAt, AppliedBy, ApprovedBy, ApprovalRef) VALUES ({0}, SYSUTCDATETIME(), N'SecurityInsight guided install', {1}, {2})" -f (& $q $ctx.Version), (& $q $approval.ApprovedBy), (& $q ('guided install ' + $ctx.InstallId)))
            $ledger = ('applied ({0} batches) and recorded' -f $k)
        }
        # The engine identity's users (from its client id -- the server needs no directory identity).
        $mi = $n.ManagedIdentity.Replace(']', ']]'); $sid = Get-SIInstallSqlSid -ClientId ([string]$ctx.Facts['identityClientId'])
        # #672 (framework §12.23 P3): in the Pro database the engine gets its least-privilege role si_engine. REMOVE-ME: until a
        # fresh test install has proven the role alone, SI_Setup_EngineLeastPrivilege is OFF by default and the engine ALSO
        # keeps today's db_datareader + db_datawriter (the role is then harmless and prepares the cut-over); ON = si_engine
        # only. The cfg tables come with the settings step: it applies the same grants again.
        . ([IO.Path]::Combine($ctx.SIRoot, 'engine', 'pro-settings', 'SI-EngineGrants.ps1'))
        $engineRoleOnly = Test-SIEngineLeastPrivilegeSetup -Values $ctx.Values
        $null = Invoke-SIInstallSql -Ctx $ctx -Server $fqdn -Database $script:SIInstallProDatabase -Mode 'nonquery' -Query (Get-SIEngineDatabaseAccessSql -UserName $n.ManagedIdentity -ClientId ([string]$ctx.Facts['identityClientId']) -KeepBroadRoles:(-not $engineRoleOnly))
        # the identity ledger (its own database, si.*): not in #672's first step -- its rights stay as they were
        $null = Invoke-SIInstallSql -Ctx $ctx -Server $fqdn -Database $script:SIInstallLedgerDatabase -Mode 'nonquery' -Query ("IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'{0}') CREATE USER [{0}] WITH SID = {1}, TYPE = E; ALTER ROLE db_datareader ADD MEMBER [{0}]; ALTER ROLE db_datawriter ADD MEMBER [{0}];" -f $mi, $sid)
        # Asset tagging runs under its OWN identity (#236) and reads its settings from the Pro database like every Pro
        # engine: a read-only user for it (fix request 85bd728f -- without it the daily run stops at the settings check).
        $tagName = Get-SISetupComponentName -Names $n -Key TaggingIdentity
        $tagId = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIUserAssignedIdentity' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; Name = $tagName; ErrorAction = 'SilentlyContinue' })
        $tagNote = ''
        if ($tagId) {
            . ([IO.Path]::Combine($ctx.SIRoot, 'engine', 'pro-settings', 'SI-ProSchema.ps1'))
            $null = Invoke-SIInstallSql -Ctx $ctx -Server $fqdn -Database $script:SIInstallProDatabase -Mode 'nonquery' -Query (Get-SITaggingDatabaseAccessSql -UserName $tagName -ClientId ([string](Get-SIInstallProp $tagId 'ClientId')))
            $tagNote = ('; {0} (asset tagging) reads its settings' -f $tagName)
        }
        New-SIInstallResult -Message ('Vulnerability and data tables ready; identity ledger {0}; {1} works in the database {2} and reads and writes the identity ledger{3}.' -f $ledger, $n.ManagedIdentity, $(if ($engineRoleOnly) { 'through its least-privilege role si_engine only' } else { 'with db_datareader + db_datawriter and the role si_engine (prepared for the cut-over)' }), $tagNote)
    }

    $t['pro-templates'] = {
        param($ctx)
        # #250: the schema (cfg.TemplatePackStaged included), names and CMDB ownership carried over to configuration (#251),
        # and the default templates installed -- or adopted -- as template pack 1.0, so the web app shows what runs.
        $res = $null
        Use-SIInstallUserSqlToken -Ctx $ctx -Action {
            $a = Get-SIInstallSqlArgs -Ctx $ctx; $a.InstallDefault = $true; $a.PassThru = $true
            $r = Invoke-SIInstallScript -Ctx $ctx -RelativePath 'setup/Publish-SITemplates.ps1' -Arguments $a
            Assert-SIInstallScriptOk -Ctx $ctx -What 'Installing the default templates' -Result $r
            $script:SIInstallTemplateResult = @($r.Objects | Where-Object { $_ -and $_.PSObject.Properties['Mode'] }) | Select-Object -Last 1
        }
        $res = $script:SIInstallTemplateResult; $script:SIInstallTemplateResult = $null
        $name = if ($res -and [string]$res.PackName) { [string]$res.PackName } else { 'The default templates' }
        $msg = switch ([string]$(if ($res) { $res.Decision } else { '' })) {
            'adopt-customised' { '{0}: your templates differ from it, so they are kept -- it is offered on the Template releases page.' -f $name }
            'newer-installed'  { 'Template pack {0} is installed (newer than {1}) -- nothing to change.' -f $res.InstalledPack, $name }
            'shipped-differs'  { '{0} is installed; your templates are kept.' -f $name }
            default            { '{0} {1} installed -- shown as installed on the Template releases page.' -f $name, $(if ($res -and $res.Decision -eq 'adopt') { 'is recorded as' } else { 'is' }) }
        }
        New-SIInstallResult -Message $msg
    }

    $t['pro-settings'] = {
        param($ctx)
        Use-SIInstallUserSqlToken -Ctx $ctx -Action {
            $a = Get-SIInstallSqlArgs -Ctx $ctx; $a.Apply = $true; $a.CreateSchema = $true
            Assert-SIInstallScriptOk -Ctx $ctx -What 'Importing the settings' -Result (Invoke-SIInstallScript -Ctx $ctx -RelativePath 'setup/Import-SIProSettings.ps1' -Arguments $a)
        }
        # #672: the cfg tables exist now -- the engine role's grants once more (idempotent), so si_engine reaches them too
        . ([IO.Path]::Combine($ctx.SIRoot, 'engine', 'pro-settings', 'SI-EngineGrants.ps1'))
        $null = Invoke-SIInstallSql -Ctx $ctx -Server (Get-SIInstallSqlFqdn -Ctx $ctx) -Database $script:SIInstallProDatabase -Mode 'nonquery' -Query (Get-SIEngineGrantSql -UserName $ctx.Names.ManagedIdentity)
        # asset tagging's identity once more, now that cfg.AuditEvent exists: its INSERT there (the settings layer's audit rows)
        try {
            $tagName = Get-SISetupComponentName -Names $ctx.Names -Key TaggingIdentity
            $tagId = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIUserAssignedIdentity' -Arguments ([ordered]@{ ResourceGroupName = $ctx.Names.ResourceGroup; Name = $tagName; ErrorAction = 'SilentlyContinue' })
            if ($tagId) {
                . ([IO.Path]::Combine($ctx.SIRoot, 'engine', 'pro-settings', 'SI-ProSchema.ps1'))
                $null = Invoke-SIInstallSql -Ctx $ctx -Server (Get-SIInstallSqlFqdn -Ctx $ctx) -Database $script:SIInstallProDatabase -Mode 'nonquery' -Query (Get-SITaggingDatabaseAccessSql -UserName $tagName -ClientId ([string](Get-SIInstallProp $tagId 'ClientId')))
            }
        } catch { Write-SIInstallConsole -Ctx $ctx -Text ('Asset tagging''s audit right was not granted ({0}) -- setup\Grant-SITaggingDatabase.ps1 -Apply grants it.' -f $_.Exception.Message) -Color Yellow }
        # #881 the role's read right on the database's own load: a batch of its own; refused = said, never a stop
        try {
            $dg = Invoke-SIInstallSql -Ctx $ctx -Server (Get-SIInstallSqlFqdn -Ctx $ctx) -Database $script:SIInstallProDatabase -Mode 'scalar' -Query ((Get-SIEngineDatabaseGrantSql).Replace('SELECT @g AS Granted, @why AS Reason;', 'SELECT CONVERT(nvarchar(10), @g) + N''|'' + @why;'))
            $dgp = ([string]$dg) -split '\|', 2
            $dgl = Format-SIEngineDatabaseGrantLine -Granted $dgp[0] -Reason $(if ($dgp.Count -gt 1) { $dgp[1] } else { '' })
            if ($dgl -like 'WARNING:*') { Write-SIInstallConsole -Ctx $ctx -Text $dgl -Color Yellow }
        } catch { Write-SIInstallConsole -Ctx $ctx -Text ('The engine''s read right on the database''s own load was not granted ({0}) -- it paces its large writes on its own measured time.' -f $_.Exception.Message) -Color Yellow }
        # the nightly schedule: the settings above carry 19:00 in the region's zone already (Update-SIInstallConfigFile) -- the
        # markers say so, so the first update's one-time steps have nothing to move (SI-NightlySchedule.ps1). Never fails the install.
        try {
            $nz = Get-SINightlyNewInstallSchedule -Region ([string]$ctx.Values['location'])
            $null = Invoke-SIInstallSql -Ctx $ctx -Server (Get-SIInstallSqlFqdn -Ctx $ctx) -Database $script:SIInstallProDatabase -Mode 'nonquery' -Query (Get-SINightlyInstallMarkerSql -Marker $nz.Marker)
        } catch { Write-SIInstallConsole -Ctx $ctx -Text ('The nightly schedule was not recorded in the database ({0}) -- the first update checks it.' -f $_.Exception.Message) -Color Yellow }
        # #830: a new install has the copy of the report rows to Log Analytics off already (the default) -- the marker says so,
        # so the first update's one-time step has nothing to move (SI-ReportCopyDefault.ps1). Never fails the install.
        try {
            if (-not (Get-Command -Name Get-SIReportCopyInstallMarkerSql -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($ctx.SIRoot, 'setup', '_shared', 'SI-ReportCopyDefault.ps1')) }
            $null = Invoke-SIInstallSql -Ctx $ctx -Server (Get-SIInstallSqlFqdn -Ctx $ctx) -Database $script:SIInstallProDatabase -Mode 'nonquery' -Query (Get-SIReportCopyInstallMarkerSql)
        } catch { Write-SIInstallConsole -Ctx $ctx -Text ('The report-row copy default was not recorded in the database ({0}) -- the first update checks it.' -f $_.Exception.Message) -Color Yellow }
        # #308 / #417: the install's update ring, recorded now (cfg.InstallState 'Ring') so the web app shows it before the
        # first update: the wizard's updateRing (no answer = 3), given as -Ring so it always writes. Never fails the install.
        $script:SIInstallRingResult = $null
        Use-SIInstallUserSqlToken -Ctx $ctx -Action {
            $a = Get-SIInstallSqlArgs -Ctx $ctx; $a.Ring = [string](Get-SIInstallUpdateRing -Values $ctx.Values)
            # rings 0-3 for both editions (framework PRO-COMMUNITY-SAME, SI #1207): the ring answered is recorded as given;
            # the channel recorded is the install's edition (the one update client reads the Community route for a Community
            # install without a licence, the install route otherwise)
            $viaInvardia = ("$($ctx.Edition)".Trim() -ine 'community')
            $a.ResourceGroupName = [string]$ctx.Names.ResourceGroup; $a.Channel = $(if ($viaInvardia) { 'invardia' } else { 'community' }); $a.SetBy = 'guided install'; $a.PassThru = $true
            $r = Invoke-SIInstallScript -Ctx $ctx -RelativePath 'setup/Set-SIInstallRing.ps1' -Arguments $a
            $script:SIInstallRingResult = @($r.Objects | Where-Object { $_ -and $_.PSObject.Properties['Ring'] }) | Select-Object -Last 1
        }
        $ring = $script:SIInstallRingResult; $script:SIInstallRingResult = $null
        # the tenant's own name (Entra organization through Microsoft Graph, as the person installing), recorded so the web
        # app's header shows TENANT by name -- never typed by hand. Never fails the install: the header then shows the
        # tenant's domain or "not recorded".
        try {
            Use-SIInstallUserSqlToken -Ctx $ctx -Action {
                $a = Get-SIInstallSqlArgs -Ctx $ctx; $a.SetBy = 'guided install'; $a.PassThru = $true
                [void](Invoke-SIInstallScript -Ctx $ctx -RelativePath 'setup/Set-SIInstallTenant.ps1' -Arguments $a)
            }
        } catch { Write-SIInstallConsole -Ctx $ctx -Text ('The tenant name was not recorded: {0}' -f $_.Exception.Message) -Color Yellow }
        # #750 (7), owner 2026-10-27: a Pro install VERIFIES AND RECORDS ITS LICENCE ITSELF (cfg.InstallState 'Licence', the
        # record the web app's licence gate and the MCP server read), so its paid pages are on at once -- not only after the
        # updater's first run. Pro package only (SI-GuidedInstallPro.ps1); never fails the install.
        if ($ctx.Pro -and -not $ctx.AwaitLicence -and (Get-Command -Name Save-SIInstallLicenceRecord -ErrorAction SilentlyContinue)) {
            $lr = Save-SIInstallLicenceRecord -Ctx $ctx
            Write-SIInstallConsole -Ctx $ctx -Text $lr.Text -Color $(if ($lr.Ok) { 'Gray' } else { 'Yellow' })
        }
        if (-not $ring -or $null -eq $ring.Ring) {
            # UPDATE-1.7: SI decides the ring -- the updater asks Invardia for nothing until one is set (it no longer learns it from Invardia)
            return (New-SIInstallResult -Message 'The settings are in the database; change them in the web app. No update ring is set yet: set "Update ring" on the Settings page (or run setup\Set-SIInstallRing.ps1 -Ring <0-3>) -- until then the updater asks Invardia for no update.')
        }
        New-SIInstallResult -Message (('The settings are in the database; change them in the web app. Update ring {0} recorded.' -f $ring.Ring) + (Get-SIInstallUpdateRingNote -Ctx $ctx))
    }

    $t['web-app'] = {
        param($ctx)
        $v = $ctx.Values; $n = $ctx.Names
        if (-not [bool]$v['webApp']) { return (New-SIInstallResult -State 'skipped' -Message 'The web app was not chosen; it can be installed later.') }
        # the person who runs setup is the web app's first SuperAdmin (the bootstrap: a SuperAdmin assigns every other role
        # and scope in the web app); the administrators named in the install are Admins.
        # An install signed in as an APPLICATION (#413: the Invardia Support app, a service principal, a managed identity)
        # cannot sign in to the web app -- live 2026-10-06, customer I ring-2 Pro: the Support app's object id as SuperAdmin ->
        # Graph 400 "Not a valid reference update". It is never given a web app role: the administrators named in the
        # install become the SuperAdmins (the bootstrap still needs one), and naming none stops here, before any write.
        $named = @(@($v['webAppAdmins']) | Where-Object { $_ } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if (Test-SIInstallSignedInAsApp -Ctx $ctx) {
            if (-not $named.Count) {
                throw (New-SIInstallFailure -Message 'Name at least one web app administrator (webAppAdmins): the install runs as an application, which cannot sign in to the web app.' `
                    -ActionText 'Add the people who administer the web app under "Web app administrators" (webAppAdmins in config.json), then run the install command again:' -Command $ctx.ResumeCommand)
            }
            $superAdmins = $named; $admins = @()
        }
        else {
            $installer = if ($ctx.Facts['userPrincipalName']) { [string]$ctx.Facts['userPrincipalName'] } else { [string]$ctx.Facts['userObjectId'] }
            $superAdmins = @(@($installer) | Where-Object { $_ })
            $admins = @($named | Where-Object { $superAdmins -notcontains $_ })
        }
        $reg = [ordered]@{ TenantId = [string]$v['tenantId']; DisplayName = $n.WebAppDisplayName; SuperAdminUser = $superAdmins; AdminUser = $admins; Apply = $true }
        # The name is product-level (the same for every install), so a resumed run names the app by the id it recorded.
        if ([string]$ctx.Facts['webAppId']) { $reg['AppId'] = [string]$ctx.Facts['webAppId'] }
        $regResult = Invoke-SIInstallScript -Ctx $ctx -RelativePath 'pro-management/deploy/New-SIManagementAppRegistration.ps1' -Arguments $reg
        Assert-SIInstallScriptOk -Ctx $ctx -What 'The web app''s sign-in registration' -Result $regResult
        # the app id from the script's own result -- never a second look-up by the (shared) name
        $appId = [string](@($regResult.Objects | Where-Object { $_ -and $_.PSObject.Properties['AppId'] -and "$($_.AppId)" -match '^[0-9a-fA-F-]{36}$' } | Select-Object -Last 1 | ForEach-Object { $_.AppId }) | Select-Object -First 1)
        if (-not $appId) { throw (New-SIInstallFailure -Message ('The app registration "{0}" did not report its id.' -f $n.WebAppDisplayName) -Command $ctx.ResumeCommand -ActionText 'Run the install command again: it continues from this step.') }
        $ctx.Facts['webAppId'] = $appId
        $ws = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIAzOperationalInsightsWorkspace' -Arguments ([ordered]@{ ResourceGroupName = $n.WorkspaceResourceGroup; Name = $n.Workspace; ErrorAction = 'Stop' })
        $dep = [ordered]@{
            SubscriptionId = [string]$v['subscriptionId']; ResourceGroup = $n.ResourceGroup; RegistryName = $n.Acr; EnvironmentName = $n.ContainerEnv
            Location = [string]$v['location']; TenantId = [string]$v['tenantId']; SignInClientId = $appId
            SqlServer = (Get-SIInstallSqlFqdn -Ctx $ctx); SqlDatabase = $script:SIInstallProDatabase
            WorkspaceId = [string](Get-SIInstallProp $ws 'CustomerId'); WorkspaceResourceId = [string](Get-SIInstallProp $ws 'ResourceId')
            # #681: in an INTERNAL environment (private networking) "External" ingress is reachable from the customer's
            # virtual network only -- there is no public address; "Internal" would be reachable from nowhere
            SqlAllowAzureServices = (-not [bool]$v['privateNetwork']); GrantSql = $true; Ingress = $(if ([bool]$v['privateNetwork']) { 'External' } elseif ([string]$v['webAppAccess'] -eq 'internal') { 'Internal' } else { 'External' })
            JobsResourceGroup = $n.ResourceGroup; Apply = $true
            # CR5 step 1 (#655): the components' names from the install's names table, never a literal in this step
            AppName = (Get-SISetupComponentName -Names $n -Key WebApp); IdentityName = (Get-SISetupComponentName -Names $n -Key WebIdentity)
            McpAppName = (Get-SISetupComponentName -Names $n -Key McpApp); McpIdentityName = (Get-SISetupComponentName -Names $n -Key McpIdentity)
            # CR5 step 2: the web app's Jobs page knows the install's own updater job (Jobs__UpdaterJob)
            UpdaterJobName = (Get-SISetupComponentName -Names $n -Key UpdaterJob)
            # #852: the shared sign-in front's store (its key in the install's vault, its schema in the Pro database), made
            # here with the installer's rights -- the front 1.3.0 then finds everything when the update moves the web app
            SigninStoreKeyVaultName = [string]$n.KeyVault
        }
        # the MCP server (AI tools over the data) is Pro by its LICENCE GATE, not by the install (owner 2026-10-27, SI #750 (3)):
        # every install deploys it, and it answers /mcp only while the licence the updater verified (cfg.InstallState 'Licence')
        # names a Pro edition in force -- a licence bought later switches it on, a removed one off, with no redeploy
        # (pro-management/src/SI.Management.Core/Licensing/McpLicenceGate.cs). No edition check here.
        if ([bool]$v['aiClassification'] -and $v['openAiEndpoint']) { $dep.ChatEndpoint = [string]$v['openAiEndpoint']; $dep.ChatDeployment = [string]$v['openAiDeployment'] }
        $script:SIInstallLastDeployResult = $null
        Use-SIInstallUserSqlToken -Ctx $ctx -Action {
            $script:SIInstallLastDeployResult = Invoke-SIInstallScript -Ctx $ctx -RelativePath 'pro-management/deploy/Deploy-SIManagement.ps1' -Arguments $dep
            Assert-SIInstallScriptOk -Ctx $ctx -What 'Deploying the web app' -Result $script:SIInstallLastDeployResult
        }
        $depResult = $script:SIInstallLastDeployResult
        # #1098: what the web app's sign-in key step could not do with the installer's rights (a refused role write on the key
        # = not known) -- a CUSTOMER TASK at the end of this step, never a stop
        $keyRingTasks = @(@($(if ($depResult) { $depResult.Objects })) | Where-Object { $_ -and $_.PSObject.Properties['WebKeyRingTasks'] } | ForEach-Object { @($_.WebKeyRingTasks) } | Where-Object { $_ } | ForEach-Object { [string]$_ })
        # #521: ARM reads (Get-SIContainerApp, Get-SIUserAssignedIdentity) -- no az CLI
        # The web app's ADDRESS is what the sign-in registration needs next: without it nobody can sign in. It is read until
        # Azure shows it (6 tries, 10 s apart); no address is NOT a finished step -- the step stops, and a resume runs it again.
        $fqdn = ''; $appRead = $null
        foreach ($try in 1..6) {
            $appRead = Invoke-SIInstallArmTry -Ctx $ctx -Command 'Get-SIContainerApp' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; Name = (Get-SISetupComponentName -Names $n -Key WebApp) })
            $fqdn = ([string](Get-SIInstallProp (Get-SIInstallProp (Get-SIInstallProp (Get-SIInstallProp $appRead.Value 'properties') 'configuration') 'ingress') 'fqdn')).Trim()
            if ($fqdn) { break }
            if ($try -lt 6) { & $ctx.Seams.Sleep 10 }
        }
        if (-not $fqdn) {
            throw (New-SIInstallFailure -Message ('The web app is deployed, but its address could not be read{0} -- so its sign-in address is not registered yet and nobody can sign in.' -f $(if ($appRead -and -not $appRead.Ok) { ' (' + $appRead.Error + ')' } else { ' (Azure shows none yet)' })) `
                -ActionText 'Run the install command again: it continues from this step and registers the address.' -Command $ctx.ResumeCommand)
        }
        # #443 (a): the app registration trusts the web app's identity (a federated credential, no secret) -- the Set up mail
        # click flow; the guard below turns the web app's credential settings on only once that credential reads back.
        $wp = (Invoke-SIInstallArmTry -Ctx $ctx -Command 'Get-SIUserAssignedIdentity' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; Name = (Get-SISetupComponentName -Names $n -Key WebIdentity); ErrorAction = 'SilentlyContinue' })).Value
        $webPrincipal = ([string](Get-SIInstallProp $wp 'PrincipalId')).Trim()
        if ($webPrincipal -match '^[0-9a-fA-F-]{36}$') { $reg.WebIdentityPrincipalId = $webPrincipal }
        $reg.Fqdn = $fqdn
        $regResult2 = Invoke-SIInstallScript -Ctx $ctx -RelativePath 'pro-management/deploy/New-SIManagementAppRegistration.ps1' -Arguments $reg
        Assert-SIInstallScriptOk -Ctx $ctx -What 'The web app''s sign-in address' -Result $regResult2
        $ctx.Facts['portalUrl'] = 'https://{0}/' -f $fqdn
        # what the registration says about itself (its last result object): the organisation-wide consent, the credential
        $regInfo = @(@($regResult2.Objects) + @($regResult.Objects) | Where-Object { $_ -and $_.PSObject.Properties['SignInConsent'] }) | Select-Object -First 1
        $consentFailed = [string](Get-SIInstallProp $regInfo 'SignInConsent') -eq 'failed'
        $notes = New-Object System.Collections.Generic.List[string]
        if ($reg.Contains('WebIdentityPrincipalId')) {
            # not fatal: without it the mail page hands over setup\Set-SIMail.ps1, and sign-in is never put at risk.
            # -ExpectCredential: the registration just made (or found) the credential -- a list that does not show it yet
            # is read again, instead of leaving the Set up mail button off without a word
            $credArgs = [ordered]@{ TenantId = [string]$v['tenantId']; SubscriptionId = [string]$v['subscriptionId']; ResourceGroup = $n.ResourceGroup; SignInClientId = $appId; Apply = $true
                # CR5 step 2 (#655): the web app and its identity by the install's names table (its defaults are today's names)
                AppName = (Get-SISetupComponentName -Names $n -Key WebApp); IdentityName = (Get-SISetupComponentName -Names $n -Key WebIdentity) }
            if ([bool](Get-SIInstallProp $regInfo 'WebFederatedCredential')) { $credArgs.ExpectCredential = $true }
            $cred = Invoke-SIInstallScript -Ctx $ctx -RelativePath 'pro-management/deploy/Set-SIManagementSignInCredential.ps1' -Arguments $credArgs
            $credInfo = @($cred.Objects | Where-Object { $_ -and $_.PSObject.Properties['ClickFlow'] }) | Select-Object -Last 1
            if ($cred.ExitCode -or $cred.Error -or ($credInfo -and -not [bool]$credInfo.ClickFlow)) {
                Write-SIInstallConsole -Ctx $ctx -Text 'The Set up mail button could not be turned on now (the mail page hands over setup\Set-SIMail.ps1 instead).' -Color Yellow
                $notes.Add('The Set up mail button is off (the mail page hands over setup\Set-SIMail.ps1 instead).')
            }
        }
        # #446: the web app reads people's names, finds a person by name and lists who holds a role in Entra -- read-only
        # Microsoft Graph on its own identity. The lookup is switched on only once every grant is in place.
        $grant = Invoke-SIInstallScript -Ctx $ctx -RelativePath 'setup/Grant-SIIdentity.ps1' -Arguments ([ordered]@{
            IdentityName = (Get-SISetupComponentName -Names $n -Key WebIdentity); IdentityResourceGroup = $n.ResourceGroup; SubscriptionId = [string]$v['subscriptionId']; WebApp = $true; Apply = $true })
        # (the setting's result below is kept: one that could not be written is said, not dropped)
        if (-not $grant.ExitCode) {
            $look = Invoke-SIInstallArmTry -Ctx $ctx -Command 'Set-SIContainerAppEnvVar' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; Name = (Get-SISetupComponentName -Names $n -Key WebApp); SetEnv = @('Access__GraphLookup=true') })
            if (-not $look.Ok) {
                Write-SIInstallConsole -Ctx $ctx -Text ('Finding people by name could not be switched on in the web app ({0}); run the install command again to switch it on.' -f $look.Error) -Color Yellow
                $notes.Add('Finding people by name is off (the setting could not be written to the web app).')
            }
        }
        else { Write-SIInstallConsole -Ctx $ctx -Text 'Finding people by name stays off until the web app may read names in Entra (setup\Grant-SIIdentity.ps1 -WebApp, by an Entra admin).' -Color Yellow }
        Update-SIInstallConfigFile -Ctx $ctx -BlockOnly
        $msg = 'The web app runs at https://{0}/ ({1}, Entra sign-in).' -f $fqdn, $(if ([bool]$v['privateNetwork']) { 'from your network only' } else { $dep.Ingress.ToLowerInvariant() })
        if ($dep.Ingress -eq 'External' -and -not [bool]$v['privateNetwork']) { $msg += ' Add a Conditional Access policy for it.' }
        if ($notes.Count) { $msg += ' ' + ($notes.ToArray() -join ' ') }
        if ($consentFailed) {
            # a tenant that does not let users consent stops the first sign-in at "Approval required": said as a WARNING
            # (a resume runs the step again and tries the consent again), with what an administrator does
            return (New-SIInstallResult -State 'warning' -Message ($msg + (' The web app''s sign-in permissions could NOT be consented to for the organisation ({0}): if your tenant does not let users consent, the first sign-in says "Approval required".' -f [string](Get-SIInstallProp $regInfo 'SignInConsentError'))) `
                -Action ([ordered]@{ text = ('An administrator grants it once -- Entra admin center > Enterprise applications > {0} > Permissions > Grant admin consent. Or, after the support app has the permission to consent, run the install command again:' -f $n.WebAppDisplayName); command = $ctx.ResumeCommand }))
        }
        if ($keyRingTasks.Count) {
            return (New-SIInstallResult -State 'warning' -Message ($msg + ' The web app''s sign-in keys are not protected with its Key Vault key yet: you may not give the web app its role on the key.') `
                -Action ([ordered]@{ text = ($keyRingTasks -join "`n"); command = $ctx.ResumeCommand }))
        }
        New-SIInstallResult -Message $msg
    }

    $t['updater-job'] = {
        param($ctx)
        # The updater takes its releases from Invardia through the update client (Pro), or -- the Community edition (#750 (b))
        # -- from the signed Community channel, in the cloud as Pro. A package without either installs no updater -- said,
        # never a failed step; the next run of the install command installs it once the package carries a client.
        $src = Get-SIInstallUpdateSource -SIRoot $ctx.SIRoot -Edition ([string]$ctx.Edition)
        if (-not $src) {
            return (New-SIInstallResult -State 'skipped' -Message 'This package does not carry an update client, so no updater job was installed. Update with the install command of a newer release.')
        }
        # #417: a Pro install UPDATES ITSELF through Invardia -- the updater job (caj-si-updater) on the install's ring, signed
        # in as its own managed identity, with the Pro database it applies each release's schema to. After the licence (the
        # vault holds SI-License), the install key (stored from the bundle, or claimed with the licence) and the ring
        # (pro-settings). A bundle key that is not in the vault yet is stored now; until it is, NO updater is installed --
        # its first run would claim a second key, and a bundle key is never replaced by a claim.
        $v = $ctx.Values; $n = $ctx.Names
        if ($src -eq 'invardia' -and $ctx.InstallKey -and -not [bool]$ctx.Facts['installKeyStored']) {
            if (-not (Save-SIInstallBundleKey -Ctx $ctx)) {
                throw (New-SIInstallFailure -Message ('The Invardia install key from your installation page is not in Key Vault {0} yet, so the updater was not installed (it would claim another key).' -f $n.KeyVault) `
                    -ActionText 'Wait a minute for your Key Vault access to take effect, then run the install command again: it continues from this step.' -Command $ctx.ResumeCommand)
            }
        }
        $ring = Get-SIInstallUpdateRing -Values $v
        # framework PRO-COMMUNITY-SAME: a Community install that said yes to "Connect this install to Invardia" gets its own install
        # key now (the same claim as Pro, without a licence) -- BEFORE the updater, which then uses it; no yes = no call at all
        $connectText = ''
        if ([string]$ctx.Edition -ne 'pro' -and (Test-SIInstallConnectToInvardia -Ctx $ctx)) { try { $connectText = ' ' + [string](Invoke-SIInstallInvardiaKey -Ctx $ctx).Message } catch { $connectText = '' } }
        # rings 0-3 for both editions (framework PRO-COMMUNITY-SAME): the ring answered is the ring used
        $ringNote = ''
        $job = Get-SISetupComponentName -Names $n -Key UpdaterJob
        $a = [ordered]@{
            SubscriptionId = [string]$v['subscriptionId']; ResourceGroupName = $n.ResourceGroup; AcrName = $n.Acr; EnvName = $n.ContainerEnv
            KeyVaultName = $n.KeyVault; TenantId = [string]$v['tenantId']; Source = $src; UpdateRing = $ring
            ProSqlServer = (Get-SIInstallSqlFqdn -Ctx $ctx); ProSqlDatabase = $script:SIInstallProDatabase; JobName = $job
            UseManagedIdentity = $true; GrantSpnRoles = $true; GrantSql = $true; Apply = $true
            # CR5 step 1 (#655): the names the job records for the install (SI_UPDATER_WEB_APP / _MCP_APP / _JOB_NAME)
            IdentityName = (Get-SISetupComponentName -Names $n -Key UpdaterIdentity); WebAppName = (Get-SISetupComponentName -Names $n -Key WebApp)
            McpAppName = (Get-SISetupComponentName -Names $n -Key McpApp)
            # the nightly update at 23:00 in the local time of the install's Azure region, from the start (owner 2026-10-15)
            Region = [string]$v['location']
        }
        # -GrantSql opens the Pro database as the person installing: the install's sign-in, never this host's identity
        $r = Use-SIInstallUserSqlToken -Ctx $ctx -Action { Invoke-SIInstallScript -Ctx $ctx -RelativePath 'setup/Install-SIUpdaterJob.ps1' -Arguments $a }
        if ($r.Error -or $r.ExitCode -ne 0) {
            $why = if ($r.Error) { $r.Error } else { 'exit code {0}' -f $r.ExitCode }
            throw (New-SIInstallFailure -Message ('The updater job was not installed: {0}' -f $why) `
                -ActionText 'Fix the cause, then run the install command again: it continues from this step (the updater setup is safe to repeat).' -Command $ctx.ResumeCommand -Detail @{ log = (Get-SIInstallTail $r.Text) })
        }
        $ctx.Facts['updaterJob'] = $job; $ctx.Facts['updateRing'] = $ring
        # recorded in the install's own block, so Update-SecurityInsight / Invoke-SIContainerUpdate leave the containers to the job
        Update-SIInstallConfigFile -Ctx $ctx -BlockOnly
        $key = if ([bool]$ctx.Facts['installKeyStored']) { 'the install key from your installation page' }
               elseif ([string]$ctx.Facts['installKeyClaim'] -in 'claimed', 'present') { 'the install key claimed with your licence' }
               else { 'an install key it claims on its first run' }
        $nz = Get-SINightlyNewInstallSchedule -Region ([string]$v['location'])
        $done = if ($src -eq 'community') {
            ('{0} keeps SecurityInsight up to date from Invardia''s signed release of update ring {1} (the same updater as every install), daily at {2}, as its own managed identity (no licence).' -f $job, $ring, (Get-SINightlyScheduleText -Zone $nz.Zone -Known $nz.Known)) + $ringNote + (Get-SIInstallUpdateRingNote -Ctx $ctx)
        } else {
            ('{0} keeps SecurityInsight up to date from Invardia on update ring {1}, daily at {3}, as its own managed identity, with {2}.' -f $job, $ring, $key, (Get-SINightlyScheduleText -Zone $nz.Zone -Known $nz.Known)) + (Get-SIInstallUpdateRingNote -Ctx $ctx)
        }        $done += $connectText

        # The database server's administration goes back to the admin group at the END OF THE RUN (Complete-SIInstallSqlAdmin,
        # called by the install next to where it closes its database firewall rule) -- not here: a resume that runs
        # another database step and skips this one would leave the application as the administrator.
        New-SIInstallResult -Message $done
    }

    # framework SEC-08: the database setup job (its identity in the SQL admin group, read back; one run; its result)
    $t['db-job'] = {
        param($ctx)
        Invoke-SIInstallDbJob -Ctx $ctx
    }
    $t
}
