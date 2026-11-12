<#
.SYNOPSIS
    SecurityInsight Pro: gives the Invardia Support app its own database user on an install whose database is PRIVATE
    (public network access off) -- FROM INSIDE: a one-time job in the install's own private environment creates the user
    from the application's client id, adds it to the database owner role, reads both back, and the job is removed.
    Nothing is opened. PLAN by default.

.DESCRIPTION
    #681 (owner 2026-10-19: "same config as pim. when we say it is private, it stays that way"). PIM's way, the same:
    a private database has no route from outside, and none is made for this -- no firewall rule, no public access, no jump
    host. The grant runs where the route already is (setup\_shared\SI-SupportSqlJob.ps1 says how).

    What it does, in order:
      1. Reads the install (its jobs, the database server and its admin group, the in-network SQL identity id-si-sql and
         whether it is a member of that group -- from the member's side --, the engine job's image and pull identity, the
         databases on the server, the Support app in this tenant). PLAN ONLY without -Apply: nothing is made.
      2. With -Apply: creates the one-time job caj-si-supportsql (tagged as a one-time job) carrying id-si-sql and the pull
         identity, nothing else; starts it once; waits; prints PASS or FAIL.
      3. ALWAYS, also after a failed step: removes the one-time job and reads back that it is gone.
    When something is missing (no id-si-sql, not a member, a password pull) it STOPS before any change and prints the
    options. It never gives a role, a membership or a permission, and it never opens the public endpoint.

    Run by Invardia support inside the environment's Support session (every request recorded in your audit log). The
    membership of the admin group is not part of this script: it is given from outside before the database goes private.

.EXAMPLE
    . C:\claude-sessions\Invardia\tools\Connect-InvardiaSupport.ps1 -Environment <handle> -Reason 'support database access'
    .\setup\Invoke-SISupportSqlAccessJob.ps1 -ResourceGroup <rg>
    .\setup\Invoke-SISupportSqlAccessJob.ps1 -ResourceGroup <rg> -Apply

.LINK
    https://invardia.com/docs/si/scripts/Invoke-SISupportSqlAccessJob/
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.()-]{1,90}$')][string]$ResourceGroup,
    [string]$SubscriptionId,
    # the Invardia Support app's client id; in the Support app's own session it may be left out
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SupportAppId = '',
    [string]$DbUserName = 'invardia-support-app',
    [string]$SqlServerName = '',
    [ValidatePattern('^$|^[a-z][a-z0-9-]{0,30}[a-z0-9]$')][string]$JobName = '',
    [ValidateRange(60, 3600)][int]$TimeoutSeconds = 600,
    [switch]$Apply,
    [string]$Reason = 'SecurityInsight support database access from inside the network',
    # TEST SEAMS: replace the Support session
    [scriptblock]$Arm, [scriptblock]$Graph,
    [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$PollSeconds = 10
)

$ErrorActionPreference = 'Stop'
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportCutover.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-PrivateNetwork.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportAppDatabase.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportSqlJob.ps1'))

# the SQL seam is never used here (no database connection from this machine): a refusing stub keeps the seams complete
$seams = New-SICutoverSeams -Arm $Arm -Graph $Graph -Sql { param($a, $b, $c, $d, $e) throw 'this script opens no database connection' } -Reason $Reason
$sess = $null; if (Get-Command -Name Get-SISupportSession -ErrorAction SilentlyContinue) { try { $sess = Get-SISupportSession } catch { $sess = $null } }
if (-not $SubscriptionId) { $SubscriptionId = if ($sess) { [string]$sess.SubscriptionId } else { '' } }
if (-not $SubscriptionId) { throw 'Give -SubscriptionId: the Support session names no subscription.' }
if (-not $SupportAppId) { $SupportAppId = if ($sess) { [string]$sess.AppId } else { '' } }
if (-not $SupportAppId) { throw 'Give -SupportAppId: the Invardia Support app''s client id (the Support session names none).' }

$shape = Get-SIInstallShape -Arm $seams.Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -SqlServerName $SqlServerName -FindSqlInResourceGroup
if (-not @($shape.Jobs).Count) { throw ('No Container Apps job was found in {0} (subscription {1}) -- is this the install''s resource group? Nothing was changed.' -f $ResourceGroup, $SubscriptionId) }
$plan = Get-SISupportSqlJobPlan -Arm $seams.Arm -Graph $seams.Graph -Shape $shape -SupportAppId $SupportAppId -JobName $JobName
Write-Host ('== the Support app''s database user, from inside -- {0}' -f $ResourceGroup) -ForegroundColor Cyan
foreach ($l in $plan.Lines) { Write-Host ('   ' + $l) -ForegroundColor Gray }
if (-not $plan.Ok) {
    foreach ($l in $plan.Problems) { Write-Host ('   STOPPED: ' + $l) -ForegroundColor Red }
    Write-Host '   Nothing was changed. Options:' -ForegroundColor Yellow
    foreach ($o in (Get-SISupportSqlJobOptions)) { Write-Host ('     - ' + $o) -ForegroundColor Yellow }
    return [pscustomobject]@{ Mode = 'stopped'; Verdict = 'FAIL'; Plan = $plan; Result = $null }
}
if (-not $Apply) {
    Write-Host ('PLAN ONLY -- nothing was changed. -Apply makes the one-time job {0}, starts it once and removes it.' -f $plan.JobName) -ForegroundColor Yellow
    return [pscustomobject]@{ Mode = 'plan'; Verdict = ''; Plan = $plan; Result = $null }
}
$r = Invoke-SISupportSqlJob -Arm $seams.Arm -Plan $plan -UserName $DbUserName -TimeoutSeconds $TimeoutSeconds -PollSeconds $PollSeconds -Sleep $Sleep
foreach ($l in $r.Lines) { Write-Host ('   ' + $l) -ForegroundColor $(if ($r.Ok) { 'Green' } else { 'Red' }) }
Write-Host ('{0}: {1}' -f $r.Verdict, $(if ($r.Ok) { 'the Support app''s own database user, with the owner role, was read back inside the network' } else { 'see the lines above; the job''s own log (its console lines in the install''s workspace) says why' })) -ForegroundColor $(if ($r.Ok) { 'Green' } else { 'Red' })
[pscustomobject]@{ Mode = 'apply'; Verdict = $r.Verdict; Plan = $plan; Result = $r }
