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
    The step ids keep their names (pro-sql, pro-schema, ...): the status page and support tickets refer to them.

    The paid steps (the licence, the v2.2 CMDB migration) and the Invardia Support app's database access stay in
    SI-GuidedInstallPro.ps1, which only the paid package carries.

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

function Get-SIInstallUpdateSource {
    <# Which update client this package carries for the updater job (Test-Path only -- never loaded here): 'invardia' (the
       Invardia client, SecurityInsight Pro), 'community' (#750 (b): the signed Community channel -- the updater's Community
       hook and the client it uses), or '' (neither). #>
    param([Parameter(Mandatory)][string]$SIRoot)
    if (Test-Path -LiteralPath ([IO.Path]::Combine($SIRoot, 'container', 'updater', '_shared', 'SI-UpdaterInvardia.ps1'))) { return 'invardia' }
    if ((Test-Path -LiteralPath ([IO.Path]::Combine($SIRoot, 'container', 'updater', '_shared', 'SI-UpdaterCommunity.ps1'))) -and
        (Test-Path -LiteralPath ([IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-CommunityUpdate.ps1')))) { return 'community' }
    ''
}

function Test-SIInstallUpdateClientPresent {
    <# Does this package carry an update client for the updater job -- Invardia's (Pro) or the signed Community channel's
       (#750 (b))? Install-SIUpdaterJob refuses without either. Looked up with Test-Path only -- never loaded here. #>
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
    # CR5 (#655): a NEW group is created under the name people read ("SecurityInsight SQL admins" with the new-install names);
    # its mailNickname follows grp-si-sql-admins, so every later run finds it under either name. An existing group keeps its name.
    elseif ($n -is [System.Collections.IDictionary] -and $n.Contains('SqlAdminGroupDisplayName') -and [string]$n['SqlAdminGroupDisplayName'] -and [string]$n['SqlAdminGroupDisplayName'] -cne 'grp-si-sql-admins') {
        $ga.DisplayName = [string]$n['SqlAdminGroupDisplayName']
        # SI #750: a new Community edition install's own group (grp-si-community-sql-admins), never the Pro install's
        $gn = Get-SIInstallSqlAdminGroupName -Names $n
        if ($gn -cne 'grp-si-sql-admins') { $ga.GroupName = $gn }
    }
    $ga
}

function Get-SIInstallSqlAdminGroupName {
    <# PURE. The name this install's SQL admin group is looked up and created by: the names table's SqlAdminGroupName
       (grp-si-community-sql-admins for a new Community edition install, so it never shares a Pro install's group in the same
       tenant -- SI #750; setup\_shared\SI-SetupNaming.ps1), else grp-si-sql-admins (a table made before the key existed). #>
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
            if ($r.Ok -and -not $r.Value) { $bad.Add($from + '|' + ('the database server {0} has no rule that lets the install''s own jobs and web app in (AllowAllWindowsAzureIps)' -f $n.SqlServer)) }
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
        # The Invardia Support app's database access (the Pro package only: Get-SIInstallSupportEndCheck)
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
            if (-not [bool](Get-SIInstallProp $r.Value 'SIExisted')) { $created += 'server' }
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
        # SECURITY BASELINE, only while SI_SECURITY_BASELINE_NEW_INSTALL is on (setup\_shared\SI-SecurityBaseline.ps1, default
        # OFF until a fresh test install proves it): SQL auditing of the server to the install's workspace, 90 days. Never
        # fails the step -- a refusal is one line, and setup\Set-SISecurityBaseline.ps1 turns it on later.
        if (Test-SISecurityBaselineNewInstall) {
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
            # SI #750 (b): a Community edition install updates on the Community channel, rings 2 / 3 only (3 = broad, the
            # default; rings 0 / 1 are internal) -- any other answer is recorded as 3
            if (-not $ctx.Pro -and $a.Ring -notin '2', '3') { $a.Ring = '3' }
            $a.ResourceGroupName = [string]$ctx.Names.ResourceGroup; $a.Channel = $(if ($ctx.Pro) { 'invardia' } else { 'community' }); $a.SetBy = 'guided install'; $a.PassThru = $true
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
        if ($ctx.Pro -and (Get-Command -Name Save-SIInstallLicenceRecord -ErrorAction SilentlyContinue)) {
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
        Use-SIInstallUserSqlToken -Ctx $ctx -Action {
            Assert-SIInstallScriptOk -Ctx $ctx -What 'Deploying the web app' -Result (Invoke-SIInstallScript -Ctx $ctx -RelativePath 'pro-management/deploy/Deploy-SIManagement.ps1' -Arguments $dep)
        }
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
        New-SIInstallResult -Message $msg
    }

    $t['updater-job'] = {
        param($ctx)
        # The updater takes its releases from Invardia through the update client (Pro), or -- the Community edition (#750 (b))
        # -- from the signed Community channel, in the cloud as Pro. A package without either installs no updater -- said,
        # never a failed step; the next run of the install command installs it once the package carries a client.
        $src = Get-SIInstallUpdateSource -SIRoot $ctx.SIRoot
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
        # the Community channel has rings 2 (early release) and 3 (broad): any other answer takes ring 3
        $ringNote = ''
        if ($src -eq 'community' -and $ring -notin 2, 3) { $ringNote = (' Ring {0} is not a Community ring, so ring 3 (broad) is used.' -f $ring); $ring = 3 }
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
            ('{0} keeps SecurityInsight up to date from the signed Community channel on update ring {1}, daily at {2}, as its own managed identity (no install key, no licence).' -f $job, $ring, (Get-SINightlyScheduleText -Zone $nz.Zone -Known $nz.Known)) + $ringNote + (Get-SIInstallUpdateRingNote -Ctx $ctx)
        } else {
            ('{0} keeps SecurityInsight up to date from Invardia on update ring {1}, daily at {3}, as its own managed identity, with {2}.' -f $job, $ring, $key, (Get-SINightlyScheduleText -Zone $nz.Zone -Known $nz.Known)) + (Get-SIInstallUpdateRingNote -Ctx $ctx)
        }
        # The database server's administration goes back to the admin group at the END OF THE RUN (Complete-SIInstallSqlAdmin,
        # called by the install next to where it closes its database firewall rule) -- not here: a resume that runs
        # another database step and skips this one would leave the application as the administrator.
        New-SIInstallResult -Message $done
    }
    $t
}
