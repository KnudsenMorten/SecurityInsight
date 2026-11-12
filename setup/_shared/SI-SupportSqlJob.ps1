#Requires -Version 5.1
<#
    #681 (owner 2026-10-19: "same config as pim. when we say it is private, it stays that way") -- the Invardia Support
    app's database user on an install whose database is PRIVATE (public network access off), given FROM INSIDE: a one-time
    Container Apps job in the install's own private environment. PIM's design, the same way (PIM docs/DESIGN.md §27.11
    "From inside: a private database", its Invoke-PimSupportSqlAccessJob.ps1; framework DOCS/REQUIREMENTS.md §4.1b):

      * NOTHING IS OPENED: no firewall rule, no public access, no jump host. The grant runs where the route already is.
      * WHICH IDENTITY: the in-network SQL identity id-si-sql (setup\_shared\SI-PrivateNetwork.ps1; PIM: id-pim-sql-<token>),
        a member of the database server's admin group -- given that membership when the install went private, never by this
        job. The one-time job carries THAT identity and the identity the install's engine job pulls its image with, and
        nothing else. No role, no group membership, no permission is given to any identity here. When the install has no
        such identity, or it is not a member of the admin group, or the engine job pulls with a password or its own system
        identity, the run STOPS before anything is changed and says the options.
      * WHAT THE JOB RUNS is not a second implementation: its script is BUILT from the functions of
        setup\_shared\SI-SupportAppDatabase.ps1 / engine\_shared\SI-SupportSqlAccess.ps1 loaded in this process (their own
        text, taken with Get-Command): the SID from the client id, the statements, the read, the read-back. It is handed to
        the container as its start command and needs nothing from the image but PowerShell 7 and its SQL client, so it
        works on an install of any version.
      * THE RUN: plan -> create the job (tagged as a one-time job) -> start it once -> wait (bounded) -> read the result ->
        ALWAYS (finally) remove the job and read back that it is gone. PASS needs the execution Succeeded, which the job
        reaches only after the user and its role were READ BACK in every database. Run twice: one read per database, no
        statement.
      * What it does NOT do: add the Support app to the admin group (that is given from outside the network, before the
        close), touch the install's own jobs, the SQL server, its firewall or its administrator, or sign in to the database
        from the machine it runs on.

    Seams (the caller hands them in; tests pass fakes):
      -Arm   { param([string]$Method, [string]$Path, $Body) }   ARM; $null = not found on a GET; throws otherwise
      -Graph { param([string]$Method, [string]$Uri, $Body) }    Microsoft Graph (reads, and the member-side check)
    Needs SI-PrivateNetwork.ps1 and SI-SupportAppDatabase.ps1 loaded first. PS 5.1 safe; no module, no az, no native exe.
#>

$script:SISsjAppApi = '2025-07-01'
$script:SISsjSqlApi = '2021-11-01'
$script:SISsjMiApi  = '2023-01-31'

function Get-SISupportSqlJobTag { [ordered]@{ Name = 'si-one-time-job'; Value = 'support-sql-access' } }

function Get-SISupportSqlJobFunctionNames {
    <# PURE. The functions the job carries, word for word, in load order. Nothing else runs inside. #>
    @('ConvertTo-SISqlSidFromClientId', 'Get-SISupportAppDatabaseCheckSql', 'ConvertFrom-SISupportAppDatabaseAnswer',
      'Get-SISupportAppDatabaseAccessSql', 'Get-SISupportAppRightHint', 'Invoke-SISupportAppDatabaseAccess')
}

function Get-SISupportSqlJobScript {
    <#
        PURE (reads only the functions loaded in this process). The PowerShell the one-time job runs: the grant functions
        word for word, a token from the container's managed-identity endpoint for the identity SI_SUPPORTSQL_MI_CLIENT_ID,
        the SQL client of PowerShell 7, ONE call of Invoke-SISupportAppDatabaseAccess -Apply over SI_SUPPORTSQL_DATABASES,
        and ONE result line "[supportsql] RESULT {json}". Exit 0 only when every database READ BACK its user with db_owner.
    #>
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add('$ErrorActionPreference = ''Stop''')
    foreach ($n in (Get-SISupportSqlJobFunctionNames)) {
        $c = Get-Command -Name $n -CommandType Function -ErrorAction SilentlyContinue
        if (-not $c) { throw ('Get-SISupportSqlJobScript: the function {0} is not loaded -- load setup\_shared\SI-SupportAppDatabase.ps1 first.' -f $n) }
        $l.Add(('function {0} {{{1}}}' -f $n, $c.ScriptBlock.ToString()))
    }
    $l.Add(@'
$server = [string]$env:SI_SUPPORTSQL_SERVER; $app = [string]$env:SI_SUPPORTSQL_APP_ID; $user = [string]$env:SI_SUPPORTSQL_USER
$mi = [string]$env:SI_SUPPORTSQL_MI_CLIENT_ID
$dbs = @(([string]$env:SI_SUPPORTSQL_DATABASES) -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
function Get-SISsjToken {
    $u = '{0}?resource={1}&api-version=2019-08-01&client_id={2}' -f $env:IDENTITY_ENDPOINT, [uri]::EscapeDataString('https://database.windows.net/'), $mi
    [string](Invoke-RestMethod -Method GET -Uri $u -Headers @{ 'X-IDENTITY-HEADER' = [string]$env:IDENTITY_HEADER }).access_token
}
$sql = {
    param([string]$Database, [string]$Query)
    $c = New-Object System.Data.SqlClient.SqlConnection(('Server=tcp:{0},1433;Database={1};Encrypt=True;TrustServerCertificate=False;Connect Timeout=30' -f $server, $Database))
    $c.AccessToken = Get-SISsjToken
    try { $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0; [string]$cmd.ExecuteScalar() } finally { $c.Dispose() }
}
$rows = @()
$ok = $false
try {
    if (-not $server -or -not $app -or -not $mi -or -not $dbs.Count) { throw 'the job was not told the server, the databases, the Support app or the identity' }
    $rows = @(Invoke-SISupportAppDatabaseAccess -Sql $sql -Databases $dbs -ClientId $app -UserName $user -Apply)
    $ok = ($rows.Count -eq $dbs.Count) -and -not @($rows | Where-Object { $_.State -notin 'present', 'granted' }).Count
    $state = if (-not $ok) { 'failed' } elseif (@($rows | Where-Object { $_.State -eq 'granted' }).Count) { 'granted' } else { 'unchanged' }
    Write-Output ('[supportsql] RESULT ' + ([ordered]@{ state = $state; databases = @($rows | ForEach-Object { [ordered]@{ database = $_.Database; state = $_.State; detail = $_.Detail } }) } | ConvertTo-Json -Depth 5 -Compress))
} catch {
    Write-Output ('[supportsql] RESULT ' + ([ordered]@{ state = 'failed'; reason = [string]$_.Exception.Message } | ConvertTo-Json -Compress))
}
if ($ok) { exit 0 } else { exit 1 }
'@)
    $l -join "`n"
}

function ConvertTo-SISupportSqlJobCommand {
    <# PURE. The container's start command: pwsh with the script as an encoded command (UTF-16LE, base64) -- no file in
       the image, nothing quoted wrong. #>
    param([Parameter(Mandatory)][string]$Script)
    @('pwsh', '-NoProfile', '-NonInteractive', '-EncodedCommand', [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script)))
}

function Get-SISupportSqlJobBody {
    <# PURE. The one-time job: in -EnvironmentId, manual trigger, one replica, no retry, the two identities only, the image
       pulled the way the engine job pulls it, tagged as a one-time job. #>
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$EnvironmentId, [Parameter(Mandatory)][string]$Image,
          [Parameter(Mandatory)][string]$RegistryServer, [Parameter(Mandatory)][string]$PullIdentityId, [Parameter(Mandatory)][string]$SqlIdentityId,
          [Parameter(Mandatory)][string]$SqlIdentityClientId, [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string[]]$Databases,
          [Parameter(Mandatory)][string]$SupportAppId, [string]$UserName = 'invardia-support-app', [int]$TimeoutSeconds = 600, [string]$Script = '')
    if (-not $Script) { $Script = Get-SISupportSqlJobScript }
    $t = Get-SISupportSqlJobTag
    $ua = [ordered]@{}; $ua[$SqlIdentityId] = [ordered]@{}; if (-not (Test-SIPnSameId $PullIdentityId $SqlIdentityId)) { $ua[$PullIdentityId] = [ordered]@{} }
    $tags = [ordered]@{}; $tags[$t.Name] = $t.Value
    [ordered]@{
        location = $Location; tags = $tags
        identity = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $ua }
        properties = [ordered]@{
            environmentId = $EnvironmentId
            configuration = [ordered]@{
                triggerType = 'Manual'; replicaTimeout = $TimeoutSeconds; replicaRetryLimit = 0
                manualTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 }
                registries = @([ordered]@{ server = $RegistryServer; identity = $PullIdentityId })
            }
            template = [ordered]@{ containers = @([ordered]@{
                name = 'supportsql'; image = $Image; command = @(ConvertTo-SISupportSqlJobCommand -Script $Script)
                resources = [ordered]@{ cpu = 0.5; memory = '1Gi' }
                env = @(
                    [ordered]@{ name = 'SI_SUPPORTSQL_SERVER'; value = $Server }
                    [ordered]@{ name = 'SI_SUPPORTSQL_DATABASES'; value = ($Databases -join ';') }
                    [ordered]@{ name = 'SI_SUPPORTSQL_APP_ID'; value = $SupportAppId }
                    [ordered]@{ name = 'SI_SUPPORTSQL_USER'; value = $UserName }
                    [ordered]@{ name = 'SI_SUPPORTSQL_MI_CLIENT_ID'; value = $SqlIdentityClientId }) }) }
        }
    }
}

function Test-SISupportSqlJobOneTime {
    <# PURE. Is -Job (as ARM returns it) one this script made (its tag)? Only such a job is ever removed. #>
    param($Job)
    $t = Get-SISupportSqlJobTag
    [string](Get-SIPnProp $Job @('tags', $t.Name)) -eq $t.Value
}

function Get-SISupportSqlJobPlan {
    <#
        READ ONLY. What the one-time job needs, read from the install: the private environment, the in-network SQL identity
        and its membership of the server's admin group (member side), the image and the pull identity of an engine job, the
        server's product databases, the Support app in this tenant, a job of the one-time name. Returns @{ Ok; Problems[];
        Lines[]; and every value the job body takes }. Never changes anything.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)]$Shape,
          [Parameter(Mandatory)][string]$SupportAppId, [string]$JobName = '', [string]$SqlIdentityName = '')
    $n = Get-SIPrivateNetworkNames
    if (-not $JobName) { $JobName = $n.SupportSqlJob }
    if (-not $SqlIdentityName) { $SqlIdentityName = $n.SqlIdentity }
    $rgId = '/subscriptions/{0}/resourceGroups/{1}' -f $Shape.SubscriptionId, $Shape.ResourceGroup
    $p = [ordered]@{ Ok = $false; Problems = New-Object System.Collections.Generic.List[string]; Lines = New-Object System.Collections.Generic.List[string]
                     JobName = $JobName; JobId = ('{0}/providers/Microsoft.App/jobs/{1}' -f $rgId, $JobName); Leftover = $false
                     EnvironmentId = ''; Location = ''; Image = ''; RegistryServer = ''; PullIdentityId = ''; SqlIdentityId = ''; SqlIdentityClientId = ''
                     Server = [string]$Shape.SqlFqdn; Databases = @(); SupportAppId = $SupportAppId }
    # 1. the database server and its admin group
    if (-not $Shape.SqlServerId) { $p.Problems.Add('the install''s database server was not found (give -SqlServerName)') }
    $gid = if ($Shape.EntraAdmin -and [string]$Shape.EntraAdmin.Type -eq 'Group') { [string]$Shape.EntraAdmin.Sid } else { '' }
    if ($Shape.SqlServerId -and -not $gid) { $p.Problems.Add('the database server''s administrator is not a group -- the in-network identity has no way to be an administrator (setup\Set-SISqlAdminGroup.ps1 first)') }
    $pna = [string](Get-SIPnProp $Shape.SqlServer @('properties', 'publicNetworkAccess'))
    if ($pna -ne 'Disabled') { $p.Lines.Add(('note: the database server''s public network access is {0} -- this job is for a PRIVATE database; with public access, setup\Grant-SISupportAppDatabase.ps1 does the same from outside' -f $(if ($pna) { $pna } else { 'not set (Enabled)' }))) }
    # 2. the databases: every user database on the server (it is SecurityInsight's own server)
    if ($Shape.SqlServerId) {
        $dbs = @(Get-SIPnArmList -Arm $Arm -Path ('{0}/databases?api-version={1}' -f $Shape.SqlServerId, $script:SISsjSqlApi) | ForEach-Object { [string](Get-SIPnProp $_ @('name')) } | Where-Object { $_ -and $_ -ne 'master' } | Sort-Object -Unique)
        $p.Databases = $dbs
        if (-not $dbs.Count) { $p.Problems.Add('no database was found on the server') } else { $p.Lines.Add(('databases: {0}' -f ($dbs -join ', '))) }
    }
    # 3. the in-network SQL identity, a member of the admin group (asked from the member's side)
    $mi = & $Arm 'GET' ('{0}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{1}?api-version={2}' -f $rgId, $SqlIdentityName, $script:SISsjMiApi) $null
    if (-not $mi) { $p.Problems.Add(('the install has no in-network SQL identity {0} -- it is made when the install goes private (setup\Set-SIPrivateNetworking.ps1 -Steps sql-identity); this script never makes one' -f $SqlIdentityName)) }
    else {
        $p.SqlIdentityId = [string](Get-SIPnProp $mi @('id')); $p.SqlIdentityClientId = [string](Get-SIPnProp $mi @('properties', 'clientId'))
        $mpid = [string](Get-SIPnProp $mi @('properties', 'principalId'))
        if ($gid -and $mpid) {
            try {
                if (Test-SISupportAppGroupMember -Graph $Graph -GroupId $gid -ServicePrincipalId $mpid) { $p.Lines.Add(('identity: {0} (client {1}), a member of the database server''s admin group' -f $SqlIdentityName, $p.SqlIdentityClientId)) }
                else { $p.Problems.Add(('the in-network SQL identity {0} is not a member of the database server''s admin group -- it is added when the install goes private (setup\Set-SIPrivateNetworking.ps1 -Steps sql-identity); this script never gives a membership' -f $SqlIdentityName)) }
            } catch { $p.Problems.Add(('whether {0} is a member of the admin group could not be read: {1}' -f $SqlIdentityName, $_.Exception.Message)) }
        }
    }
    # 4. the environment, the image and the pull identity: those of an engine job (never an identity it does not carry)
    $eng = @(@($Shape.Jobs) | Where-Object { [string](Get-SIPnProp $_ @('name')) -notmatch '(?i)updater|tagging|supportsql' -and -not (Test-SISupportSqlJobOneTime $_) })
    $tpl = $eng | Select-Object -First 1
    if (-not $tpl) { $p.Problems.Add('no engine job was found to take the environment, the image and the pull identity from') }
    else {
        $p.EnvironmentId = [string](Get-SIPnProp $tpl @('properties', 'environmentId')); $p.Location = [string](Get-SIPnProp $tpl @('location'))
        $p.Image = [string](Get-SIPnProp @(Get-SIPnProp $tpl @('properties', 'template', 'containers'))[0] @('image'))
        $reg = @(Get-SIPnProp $tpl @('properties', 'configuration', 'registries') | Where-Object { $_ })[0]
        $p.RegistryServer = [string](Get-SIPnProp $reg @('server'))
        $pull = [string](Get-SIPnProp $reg @('identity'))
        if ([string](Get-SIPnProp $reg @('passwordSecretRef'))) { $p.Problems.Add(('{0} pulls its image with a password -- the one-time job copies no secret' -f [string]$tpl.name)) }
        elseif ($pull -notmatch '(?i)/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/') { $p.Problems.Add(('{0} pulls its image with {1} -- the one-time job carries a user-assigned identity only' -f [string]$tpl.name, $(if ($pull) { $pull } else { 'no identity' }))) }
        else { $p.PullIdentityId = $pull }
        $env = if ($p.EnvironmentId) { & $Arm 'GET' ('{0}?api-version={1}' -f $p.EnvironmentId, $script:SISsjAppApi) $null } else { $null }
        if (-not (Test-SIEnvironmentPrivate -Environment $env)) { $p.Lines.Add(('note: {0} is not an internal environment in a virtual network' -f ($p.EnvironmentId -split '/')[-1])) }
        if (-not $p.Image) { $p.Problems.Add(('{0} names no image' -f [string]$tpl.name)) }
        $p.Lines.Add(('job: {0} in {1}, image {2}' -f $JobName, ($p.EnvironmentId -split '/')[-1], $p.Image))
    }
    # 5. the Support app is in this tenant
    try {
        $sp = & $Graph 'GET' ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,displayName" -f $SupportAppId) $null
        $one = @(Get-SIPnProp $sp @('value') | Where-Object { $_ })[0]
        if (-not $one) { $p.Problems.Add(('the Support app {0} is not in this tenant' -f $SupportAppId)) } else { $p.Lines.Add(('Support app: {0} ({1})' -f [string]$one.displayName, $SupportAppId)) }
    } catch { $p.Problems.Add(('the Support app could not be looked up: {0}' -f $_.Exception.Message)) }
    # 6. a job of the one-time name: a leftover of this script is removed first; any other job of that name stops the run
    $have = & $Arm 'GET' ('{0}?api-version={1}' -f $p.JobId, $script:SISsjAppApi) $null
    if ($have) {
        if (Test-SISupportSqlJobOneTime $have) { $p.Leftover = $true; $p.Lines.Add(('a leftover {0} of an earlier run is removed first' -f $JobName)) }
        else { $p.Problems.Add(('a job named {0} is there that this script did not make -- it is not touched; give -JobName' -f $JobName)) }
    }
    $p.Ok = -not $p.Problems.Count
    $p
}

function Get-SISupportSqlJobOptions {
    <# PURE. What can be done when the plan stops (printed). #>
    @('make the install''s in-network SQL identity (Invardia support: setup\Set-SIPrivateNetworking.ps1 -Apply -Steps sql-identity), then run this again',
      'or run setup\Grant-SISupportAppDatabase.ps1 -Apply from a machine INSIDE the install''s network (it reaches the private endpoint)',
      'the public endpoint is NOT opened for this -- a private install stays private')
}

function Invoke-SISupportSqlJob {
    <#
        The one-time job: -Plan from Get-SISupportSqlJobPlan (Ok). Creates it, starts it once, waits (at most
        -TimeoutSeconds), reads the execution's state -- and in a FINALLY removes the job and reads back that it is gone.
        Returns @{ Ok; Verdict = PASS | FAIL; Lines[]; Execution; Removed }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)]$Plan, [string]$UserName = 'invardia-support-app',
          [int]$TimeoutSeconds = 600, [int]$PollSeconds = 10, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $lines = New-Object System.Collections.Generic.List[string]
    $path = '{0}?api-version={1}' -f $Plan.JobId, $script:SISsjAppApi
    $exec = ''; $status = ''; $removed = $false; $made = $false
    try {
        if ($Plan.Leftover) {
            $null = & $Arm 'DELETE' $path $null
            $g = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 30 -PauseSeconds 10 -Test { param($o) $null -eq $o }
            if ($g) { throw ('the leftover {0} is still there after its removal' -f $Plan.JobName) }
            $lines.Add(('leftover {0} removed (read back)' -f $Plan.JobName))
        }
        $body = Get-SISupportSqlJobBody -Location $Plan.Location -EnvironmentId $Plan.EnvironmentId -Image $Plan.Image -RegistryServer $Plan.RegistryServer `
                    -PullIdentityId $Plan.PullIdentityId -SqlIdentityId $Plan.SqlIdentityId -SqlIdentityClientId $Plan.SqlIdentityClientId -Server $Plan.Server `
                    -Databases @($Plan.Databases) -SupportAppId $Plan.SupportAppId -UserName $UserName -TimeoutSeconds $TimeoutSeconds
        $null = & $Arm 'PUT' $path $body
        $made = $true
        $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 30 -PauseSeconds 10 -Test { param($o) [string](Get-SIPnProp $o @('properties', 'provisioningState')) -in 'Succeeded', 'Failed', 'Canceled' }
        if (-not (Test-SIPnSucceeded $back)) { throw ('the one-time job {0} was not made (Azure shows: {1})' -f $Plan.JobName, [string](Get-SIPnProp $back @('properties', 'provisioningState'))) }
        $lines.Add(('one-time job {0} made in {1} (read back)' -f $Plan.JobName, ($Plan.EnvironmentId -split '/')[-1]))
        $start = & $Arm 'POST' ('{0}/start?api-version={1}' -f $Plan.JobId, $script:SISsjAppApi) ([ordered]@{})
        $exec = [string](Get-SIPnProp $start @('name')); if (-not $exec) { $exec = (([string](Get-SIPnProp $start @('id'))) -split '/')[-1] }
        if (-not $exec) { throw 'the job was started but Azure named no execution' }
        $lines.Add(('started: execution {0}' -f $exec))
        $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds + 120)
        while ($true) {
            $e = & $Arm 'GET' ('{0}/executions/{1}?api-version={2}' -f $Plan.JobId, $exec, $script:SISsjAppApi) $null
            $status = [string](Get-SIPnProp $e @('properties', 'status'))
            if ($status -in 'Succeeded', 'Failed', 'Stopped', 'Degraded') { break }
            if ([datetime]::UtcNow -ge $deadline) { $status = 'TimedOut'; break }
            & $Sleep $PollSeconds
        }
        $lines.Add(('execution {0}: {1}' -f $exec, $status))
    } catch { $lines.Add(('FAILED: {0}' -f $_.Exception.Message)) }
    finally {
        if ($made -or $Plan.Leftover) {
            try {
                $null = & $Arm 'DELETE' $path $null
                $g = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 30 -PauseSeconds 10 -Test { param($o) $null -eq $o }
                $removed = ($null -eq $g)
            } catch { $removed = $false; $lines.Add(('the job could not be removed: {0}' -f $_.Exception.Message)) }
            $lines.Add($(if ($removed) { 'one-time job {0} removed (read back: gone)' -f $Plan.JobName } else { 'the one-time job {0} is STILL THERE -- delete it in the resource group' -f $Plan.JobName }))
        } else { $removed = $true }
    }
    $pass = ($status -eq 'Succeeded') -and $removed
    @{ Ok = $pass; Verdict = $(if ($pass) { 'PASS' } else { 'FAIL' }); Lines = $lines.ToArray(); Execution = $exec; Removed = $removed; Status = $status }
}
