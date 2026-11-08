#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight: makes the install's database setup job caj-si-dbinit ready and runs it once -- for an EXISTING install
    (its first run) or a repair. Invardia support runs it through the Support app; nobody needs database admin rights.

.DESCRIPTION
    Framework SEC-08 ("no person needs database admin rights at an install"). The database work that needed a person in the
    SQL admin group -- every product identity's database user and rights, the updater's rights, the signed grant procedure,
    the sign-in front's schema and, when asked, the Invardia Support app's own database access -- is done by the install's
    own job caj-si-dbinit, as its own identity id-si-dbinit, a member of the SQL admin group. The guided install sets it up
    on a new install and every update keeps it present and runs it. An EXISTING install needs the job's identity added to the
    SQL admin group ONCE, or the updater's Microsoft Graph permissions (three PIM-for-Groups + GroupMember.Read.All + Application.Read.All) (framework §4.5 G5; the updater
    cannot grant them to itself): this script does both, then it starts the first run -- after which every update keeps the
    membership current (renewed before it ends) and runs the job on its own.

    Run inside the environment's Support session (. Connect-InvardiaSupport.ps1 -Environment <handle> -Reason ...): every
    Azure and directory call goes through Invardia's recorder. It never signs in to the database itself.

    PLAN BY DEFAULT: reads the install (its jobs, apps, identities, the SQL server and its admin group) and says what it would
    do. -Apply, in order:
      1. the identity id-si-dbinit (made when it is not there, read back);
      2. its membership of the SQL admin group -- added when it is not there (directly, else as an active PIM-for-Groups
         member) and READ BACK from the identity's side (a group's member list hides service principals from many callers)
         BEFORE the job is started; a PIM assignment that ends within 30 days is renewed (framework §4.5 G2-G4); the updater
         identity is given its Microsoft Graph permissions (three PIM-for-Groups + GroupMember.Read.All + Application.Read.All), read back (G5);
      3. the job (made or brought up to date with the engine jobs' image and the install's identities);
      4. ONE run (the Invardia Support app's own database access is part of this run only: the Support session's own app,
         or -SupportAppId -- refused when it is not the session's), waited for; the verdict is the run's own status: the job
         ends successfully only when every identity was read back. A user under the Support app's name made from ANOTHER
         client id is replaced by the run (support-user-replace); both SIDs are in the job's lines.
      -Steps grants: the run makes users, role memberships and grants only -- no procedure, schema or database setting is
      created or changed and no user is dropped -- so it may run beside a pipeline run (framework §8.18); -Steps all (the
      default) is the whole job.
      Before step 3 the job's environment is checked to send its console lines to the install's Log Analytics workspace
      (a diagnostic setting si-environment-logs is made when missing, read back) -- a warning only, never a stop.
    While the install's updater runs (a running execution of its updater job), -Apply REFUSES before anything is changed and
    says to start it again after the update (a run beside an update overwrites the result the update waits for, and its
    grants can meet the update's in a deadlock); the plan says it as a warning.
    It never removes a member or an identity, and never changes the SQL server's administrator; the only database user the
    run may drop is a Support app user made from the wrong client id, which it makes again with the right one.

.EXAMPLE
    . Connect-InvardiaSupport.ps1 -Environment <handle> -Reason 'SI database setup job'
    .\setup\Start-SIDbInitJob.ps1 -ResourceGroup <rg>
    .\setup\Start-SIDbInitJob.ps1 -ResourceGroup <rg> -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.()-]{1,90}$')][string]$ResourceGroup,
    [string]$SubscriptionId,
    [switch]$Apply,
    # the Invardia Support app's client id: its own database user and the support grant are part of THIS run only. Default:
    # the Support session's own (this tenant's) Support app; a typed id that is not the session's is REFUSED, nothing changed
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SupportAppId = '',
    [string]$Reason = 'SecurityInsight database setup job',
    [int]$TimeoutSeconds = 1500,
    # TEST SEAMS (setup\_shared\SI-SupportCutover.ps1)
    [scriptblock]$Arm, [scriptblock]$Graph, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
    [switch]$PassThru,
    [ValidateSet('all', 'grants')][string]$Steps = 'all'
)
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportCutover.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-DbInitJob.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-GroupMemberAdd.ps1'))
foreach ($f in 'SI-GrantProcedure.ps1', 'SI-EngineGrants.ps1') { $p = [IO.Path]::Combine($siRoot, 'engine', 'pro-settings', $f); if (Test-Path -LiteralPath $p) { . $p } }

# the SQL seam is never used: this script does not sign in to the database
$seams = New-SICutoverSeams -Arm $Arm -Graph $Graph -Sql { param($Server, $Database, $Query, $Reason, $ReadOnly) throw 'this script sends no SQL' } -Reason $Reason
$sess = $null; if (Get-Command -Name Get-SISupportSession -ErrorAction SilentlyContinue) { try { $sess = Get-SISupportSession } catch { $sess = $null } }
$n = Get-SIDbInitNames
$result = [ordered]@{ Applied = [bool]$Apply; Ok = $false; Lines = New-Object System.Collections.Generic.List[string]; Execution = ''; Status = '' }
$say = { param([string]$c, [string]$t) Write-Host ('  ' + $t) -ForegroundColor $c; $result.Lines.Add($t) }
# The Support app: this tenant's own, from the Support session (its client id differs in every tenant). A typed id that is
# not the session's is REFUSED before anything is read or changed (live 2026-11-05: another tenant's id was typed by hand).
$supPick = Resolve-SIDbInitSupportAppId -Typed $SupportAppId -SessionAppId $(if ($sess) { [string]$sess.AppId } else { '' })
if (-not $supPick.Ok) {
    & $say 'Red' ('REFUSED: {0}' -f $supPick.Why); & $say 'Yellow' 'Nothing was read or changed.'
    if ($PassThru) { return [pscustomobject]$result }; exit 1
}
$SupportAppId = $supPick.AppId
if (-not $SubscriptionId) { $SubscriptionId = if ($sess) { [string]$sess.SubscriptionId } else { '' } }
if (-not $SubscriptionId) { throw 'Give -SubscriptionId: the Support session names no subscription. Nothing was read or changed.' }
Write-Host ('SecurityInsight database setup job -- {0}{1}' -f $ResourceGroup, $(if ($Apply) { '' } else { ' -- PLAN (nothing is changed; add -Apply)' })) -ForegroundColor Cyan

# ---- the install, read ----
$shape = Get-SIInstallShape -Arm $seams.Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -FindSqlInResourceGroup
$rgPath = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup
$ids = @(Get-SICutoverArmList -Arm $seams.Arm -Path ('{0}/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version={1}' -f $rgPath, $n.MiApi))
$tpl = Get-SIDbInitTemplateJob -Jobs @($shape.Jobs)
$principals = @(Get-SIDbInitPrincipals -Identities $ids -Jobs @($shape.Jobs) -Apps @($shape.Apps) -EngineClientId ([string]$shape.EngineClientId))
$gid = Get-SIDbInitAdminGroupId -Server $shape.SqlServer
$stop = New-Object System.Collections.Generic.List[string]
if (-not $shape.SqlServerId) { $stop.Add(('the install''s database server was not found{0}' -f $(if ($shape.SqlProblem) { ': ' + $shape.SqlProblem } else { '' }))) }
elseif (-not $gid) { $stop.Add('the database server''s administrator is not a group -- make the admin group its administrator first (setup\Set-SISqlAdminGroup.ps1)') }
if (-not $tpl.Ok) { $stop.Add($tpl.Problem) }
if (-not @($principals | Where-Object { $_.component -eq 'engine' }).Count) { $stop.Add('the engine identity was not found on the engine jobs') }
& $say 'Gray' ('database: {0}/{1}; admin group {2}' -f $shape.SqlFqdn, $(if ($shape.Database) { $shape.Database } else { $n.ProDatabase }), $(if ($gid) { $gid } else { '(not a group)' }))
& $say 'Gray' ('identities: {0}' -f ((@($principals | ForEach-Object { '{0}={1}' -f $_.component, $_.name })) -join ', '))
if ($SupportAppId) { & $say 'Gray' ('this run also gives the Invardia Support app {0} its own database access' -f $SupportAppId) }
if ($stop.Count) { foreach ($s in $stop) { & $say 'Yellow' ('STOP: ' + $s) }; & $say 'Yellow' 'Nothing was changed.'; if ($PassThru) { return [pscustomobject]$result }; exit 1 }
# Never beside a running update -- a running execution of the updater job (this script never opens the database, so
# the updater's executions are what it reads; Start-SIDbInitRun checks them once more right before the start). The plan
# says it; -Apply refuses before anything is changed
$updBusy = Test-SIDbInitUpdaterBusy -Arm $seams.Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
if ($updBusy.Busy) {
    $txt = Get-SIDbInitUpdaterBusyText -Why $updBusy.Why
    if ($Apply) { & $say 'Red' $txt; $result.Status = 'Refused'; if ($PassThru) { return [pscustomobject]$result }; exit 1 }
    & $say 'Yellow' ('WARNING: {0} -- -Apply refuses until the update has ended' -f $updBusy.Why)
}
if (-not $Apply) {
    & $say 'Cyan' ('PLAN: the identity {0} (made when missing), its membership of the admin group (added, read back from its memberOf), the environment''s console lines to Log Analytics (a diagnostic setting when missing), the job {1} with the image {2}, one run, its verdict' -f $n.Identity, $n.Job, $tpl.Image)
    & $say 'Yellow' 'PLAN only -- nothing was changed. Re-run with -Apply.'
    $result.Ok = $true
    if ($PassThru) { return [pscustomobject]$result }; return
}

# ---- 1. the identity ----
$mi = Set-SIDbInitIdentity -Arm $seams.Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Location $tpl.Location -Sleep $Sleep
if (-not $mi.Ok) { & $say 'Red' $mi.Problem; if ($PassThru) { return [pscustomobject]$result }; exit 1 }
& $say 'Green' ('identity {0}: {1} (client id {2})' -f $n.Identity, $(if ($mi.Made) { 'made' } else { 'there' }), $mi.ClientId)
# ---- 2. the membership, converged and renewed (framework §4.5 G2-G4), read back BEFORE the job starts ----
$m = Sync-SIDbInitMembership -Graph $seams.Graph -PrincipalId $mi.PrincipalId -GroupId $gid -Sleep $Sleep
if ($m.State -notin 'already', 'added') {
    & $say 'Red' ('{0} -- the job is NOT started (a run before the membership exists would keep a token without the group). An Entra administrator adds the managed identity {1} to the SQL admin group; then run this again.' -f $m.Detail, $n.Identity)
    if ($PassThru) { return [pscustomobject]$result }; exit 1
}
& $say 'Green' $m.Detail
if ($m.Renewal -and [string]$m.Renewal.State -in 'renewed', 'current', 'failed') { & $say $(if ($m.Renewal.State -eq 'failed') { 'Yellow' } else { 'Green' }) $m.Renewal.Detail }
# ---- 2b. framework §4.5 G5: the updater identity's Microsoft Graph permissions (three PIM-for-Groups + GroupMember.Read.All + Application.Read.All), read back ----
$updP = @($principals | Where-Object { $_.component -eq 'updater' })[0]
$updPid = if ($updP) { [string](@($ids | Where-Object { [string](Get-SIDbInitProp $_ @('properties', 'clientId')) -ieq [string]$updP.clientId } | ForEach-Object { Get-SIDbInitProp $_ @('properties', 'principalId') })[0]) } else { '' }
if ($updPid) {
    $g5 = Grant-SIDbInitUpdaterGraphRoles -Graph $seams.Graph -PrincipalId $updPid -Sleep $Sleep
    & $say $(if ($g5.Ok) { 'Green' } else { 'Yellow' }) $g5.Detail
} else { & $say 'Yellow' 'the updater identity was not found -- its Microsoft Graph permissions are given when it is there (run this again)' }
# ---- 3. the job (its lines reach the install's Log Analytics workspace first) ----
$lg = Set-SIDbInitEnvironmentLogs -Arm $seams.Arm -EnvironmentId $tpl.EnvironmentId -WorkspaceResourceId $(if ($tpl.WorkspaceResourceId) { $tpl.WorkspaceResourceId } else { [string]$shape.WorkspaceResourceId })
& $say $(if ($lg.Ok) { 'Green' } else { 'Yellow' }) $lg.Line
$body = Get-SIDbInitJobBody -Location $tpl.Location -EnvironmentId $tpl.EnvironmentId -Image $tpl.Image -RegistryServer $tpl.RegistryServer -PullIdentityId $tpl.PullIdentityId `
            -IdentityId $mi.Id -IdentityClientId $mi.ClientId -Server $shape.SqlFqdn -Database $(if ($shape.Database) { $shape.Database } else { $n.ProDatabase }) -LedgerDatabase $n.LedgerDatabase `
            -Principals $principals -SignedGrants $(if (Get-Command -Name Test-SIGrantProcedureSetup -ErrorAction SilentlyContinue) { [bool](Test-SIGrantProcedureSetup) } else { $false }) `
            -EngineRoleOnly $(if (Get-Command -Name Test-SIEngineLeastPrivilegeSetup -ErrorAction SilentlyContinue) { [bool](Test-SIEngineLeastPrivilegeSetup) } else { $false })
$job = Set-SIDbInitJob -Arm $seams.Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Body $body -Sleep $Sleep
if (-not $job.Ok) { & $say 'Red' $job.Problem; if ($PassThru) { return [pscustomobject]$result }; exit 1 }
& $say 'Green' ('job {0}: made / up to date (image {1})' -f $n.Job, $tpl.Image)
# ---- 4. one run ----
$run = Start-SIDbInitRun -Arm $seams.Arm -JobId $job.JobId -Job $job.Job -By 'support' -Support $(if ($SupportAppId) { '{0}|invardia-support-app' -f $SupportAppId } else { '' }) -TimeoutSeconds $TimeoutSeconds -Sleep $Sleep -Steps $Steps
$result.Execution = $run.Execution; $result.Status = $run.Status; $result.Ok = [bool]$run.Ok
if ($run.Status -eq 'Refused') { & $say 'Red' ([string]$run.Why) }
elseif ($run.Ok) { & $say 'Green' ('run {0}: Succeeded -- every identity was read back; from now on every update runs the job' -f $run.Execution) }
else { & $say 'Red' ('run {0}: {1} -- its lines: {2}' -f $(if ($run.Execution) { $run.Execution } else { '(not started)' }), $run.Status, (Get-SIDbInitLogText -ResourceGroup $ResourceGroup -Execution $run.Execution)) }
if ($PassThru) { [pscustomobject]$result }
elseif (-not $result.Ok) { exit 1 }
