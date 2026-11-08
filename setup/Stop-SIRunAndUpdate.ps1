<#
.SYNOPSIS
    SecurityInsight (container install) -- stop the running pipeline run, CONFIRM it stopped, then update. In that order,
    with a plan first and a read-back at every step.

.DESCRIPTION
    #1101 (owner 2026-11-04). A run that must not finish -- a hang, a run on the wrong release -- and an update that must
    land: cancelling the run and starting the updater at the same moment makes the updater find the run still going (the
    cancel takes minutes to stop the run's executions) and step aside. This script does it the one way that works:

      0. PLAN    always printed (and the only output without -Apply): the running pipeline run (id, trigger, step, age),
                 every running execution of the install's jobs, the installed version against the version the install's
                 ring serves (the updater's own last manifest check, read only), and what will happen.
      1. CANCEL  the product's way (#700): caj-si-flow started once with SI_FLOW_CANCEL=1, the reason and who asked -- the
                 pipeline runner marks the run Cancelled, stops its executions, releases the lock and writes the audit row.
      2. WAIT    until the stop is CONFIRMED: the cancel execution ended, the run reads Cancelled, and no job of the run
                 (steps, producers, workers, the data sync, the runner) executes. Up to -TimeoutMinutes; past it the script
                 STOPS, says what still runs, and does NOT start the updater.
      3. START   the updater once (update now), bound to its execution.
      4. WAIT    for it to end, then READ BACK the installed version: "updated a -> b", or the updater's own outcome.
      5. ONE summary line.
    It never starts a pipeline run or a step and never touches a run that is not running; when none is running, steps 1-2
    are skipped and it says so. -SkipUpdate stops after step 2. The cancel and the update start are written to the
    install's audit trail when its database can be reached from where this runs (a private install's database is never
    opened for it; the cancel execution writes its own audit row from inside the install). In an Invardia Support session
    at an install where support holds no standing database admin, each of those two rows opens the support grant first
    (just in time), is written, and the grant is closed again -- each said in one line; when the grant cannot be opened
    the row is not written, said as a warning, and the stop and the update go on.

    Runs from a customer admin's PowerShell 7 (browser sign-in, or Azure Cloud Shell) and inside an Invardia Support session
    (every request through the session's recorder). No PowerShell module. Plan by default; -Apply acts.

.PARAMETER Reason
    Why the run is stopped (required): kept with the cancelled run and on the audit trail.
.PARAMETER RunId
    Only this run (its id, as Operations > Jobs shows it). Default: the run that is running now. A run that is not running is
    never touched; when another run is running, nothing is done.
.PARAMETER SkipUpdate
    Only stop the run (steps 0-2).
.PARAMETER TimeoutMinutes
    How long the stop may take to be confirmed (default 30, said in the log). Past it nothing more is started.

.EXAMPLE
    .\setup\Stop-SIRunAndUpdate.ps1 -ResourceGroupName <rg> -SubscriptionId <sub> -Reason 'the run hangs on the old release'
    The plan only: what runs, the versions, what would happen.
.EXAMPLE
    .\setup\Stop-SIRunAndUpdate.ps1 -ResourceGroupName <rg> -SubscriptionId <sub> -Reason 'the run hangs on the old release' -Apply
.EXAMPLE
    .\setup\Stop-SIRunAndUpdate.ps1 -ResourceGroupName <rg> -SubscriptionId <sub> -Reason 'stop the stuck run' -SkipUpdate -Apply

.LINK
    https://invardia.com/docs/si/scripts/Stop-SIRunAndUpdate/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Reason,
    [string]$ResourceGroupName = $(if ($global:SI_Bootstrap_ResourceGroupName) { [string]$global:SI_Bootstrap_ResourceGroupName } else { '' }),
    [string]$SubscriptionId = $(if ($global:SI_Bootstrap_SubscriptionId) { [string]$global:SI_Bootstrap_SubscriptionId } else { [string]$global:SI_AzSubscriptionId }),
    [string]$RunId = '',
    [switch]$SkipUpdate,
    [ValidateRange(1, 720)][int]$TimeoutMinutes = 30,
    [ValidateRange(5, 600)][int]$PollSeconds = 30,
    [switch]$Apply,
    # TEST SEAMS (the script passes the real ones): ARM, the Pro database, the update state, the wait
    [Parameter(DontShow)][scriptblock]$Arm,
    [Parameter(DontShow)][scriptblock]$Sql,
    [Parameter(DontShow)][scriptblock]$ReadUpdateState,
    [Parameter(DontShow)][scriptblock]$Sleep,
    [Parameter(DontShow)][scriptblock]$Now,
    [Parameter(DontShow)][string]$By = '',
    # TEST SEAM: the support grant's open / close (a Support session passes Invardia's Open- / Close-InvardiaSupportGrant)
    [Parameter(DontShow)][System.Collections.IDictionary]$SupportGrant
)

#Requires -Version 7.0   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Stop-SIRunAndUpdate' -Quiet:([bool]$Arm)
if ($WhatIfPreference) { $Apply = $false }   # -WhatIf = the plan: nothing is started
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-StopRunAndUpdate.ps1'))
# the version the ring serves, as the updater last read it (Pro: the Invardia update client; absent in the Community edition)
$siUpdClient = [IO.Path]::Combine($siRoot, 'engine', '_shared', 'SI-InvardiaUpdate.ps1')
if (Test-Path -LiteralPath $siUpdClient) { . $siUpdClient }
if (-not $ResourceGroupName) { throw 'Give -ResourceGroupName: the resource group of the install''s caj-si-* jobs. Nothing was started.' }

$sqlWhy = ''
if (-not $Arm) {
    # setup's own REST sign-in: a sign-in of this process is reused; else the person signs in (browser / Cloud Shell); in an
    # Invardia Support session the session's identity, every request through its recorder. ARM directly, no az CLI.
    . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1'))
    . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupArm.ps1'))
    if (-not $SubscriptionId) { $sess = $null; try { $sess = Get-SISupportSession } catch { $sess = $null }; if ($sess -and $sess.SubscriptionId) { $SubscriptionId = [string]$sess.SubscriptionId } }
    if (-not $SubscriptionId) { throw 'Give -SubscriptionId: the subscription of the install. Nothing was started.' }
    if (-not (Get-SISetupAzureContext -SubscriptionId $SubscriptionId)) { $null = Connect-SISetupAzure -SubscriptionId $SubscriptionId }
    $ctx = Get-SISetupAzureContext -SubscriptionId $SubscriptionId
    $support = $ctx -and [string]$ctx.SignInMethod -eq 'Support'
    if (-not $By) {
        $By = if ($support) { 'Invardia support ({0})' -f (Get-SISupportSessionName (Get-SISupportSession)) } elseif ($ctx -and $ctx.Account -and $ctx.Account.Id) { [string]$ctx.Account.Id } else { [Environment]::UserName }
    }
    $armApi = $script:SIStopRun.ArmApi
    # a GetNewClosure block runs in its own module scope and does NOT see this script's functions: the function itself is
    # captured (found live at a support session 2026-11-04: "The term 'Invoke-SIArm' is not recognized")
    $siArm = ${function:Invoke-SIArm}
    $Arm = {
        param([string]$Method, [string]$Path, $Body)
        if ($Method -eq 'GET') { & $siArm -Method GET -Path $Path -ApiVersion $armApi -AllowNotFound }
        else { & $siArm -Method $Method -Path $Path -ApiVersion $armApi -Body $Body }
    }.GetNewClosure()
    $jobs = @(Get-SIStopRunArmList -Arm $Arm -Path ((Get-SIStopRunJobsPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroupName) + '?api-version=' + $armApi))
    if (-not $Sql) {
        # the install's database (where its run record and audit trail are), as its runner names it; reached only the
        # way it already answers from here -- never opened (a private install's database stays private)
        $db = Get-SIStopRunDatabase -Jobs $jobs -Flow (@($jobs | Where-Object { [string]$_.name -eq $script:SIStopRun.FlowJob })[0])
        if (-not $db.Server -or -not $db.Database) { $sqlWhy = 'the install names no Pro database (its runs are kept in its storage)' }
        else {
            try {
                $cand = if ($support -and (Get-Command -Name Invoke-InvardiaSupportSql -ErrorAction SilentlyContinue)) {
                    New-SIStopRunSupportSql -Server $db.Server -Database $db.Database -Reason ('Stop-SIRunAndUpdate: ' + $Reason)
                } else {
                    New-SIStopRunTokenSql -Server $db.Server -Database $db.Database -Token { param([bool]$Fresh) ([string](Get-SISetupAccessToken -Resource 'https://database.windows.net/' -ForceRefresh:$Fresh)).Trim() }
                }
                $null = & $cand 'SELECT 1 AS Ready;' @{} 'reader'
                $Sql = $cand
                # where the Support app is read-only in the database (just-in-time support access), each audit row opens
                # the support grant first and closes it again (Invardia's Open- / Close-InvardiaSupportGrant)
                if ($support -and -not $SupportGrant -and (Get-Command -Name Invoke-InvardiaSupportSql -ErrorAction SilentlyContinue)) {
                    $SupportGrant = New-SISupportGrantSeams -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroupName
                }
            } catch { $sqlWhy = ('the database {0} does not answer from here ({1}) -- it is not opened for this' -f $db.Server, ($_.Exception.Message -split "`n")[0]) }
        }
    }
    if (-not $ReadUpdateState) {
        $kv = ''
        foreach ($j in @($jobs)) { if ([string]$j.name -match '-updater$') { foreach ($e in @($j.properties.template.containers[0].env)) { if ($e -and [string]$e.name -eq 'SI_UPDATER_KEY_VAULT') { $kv = [string]$e.value } } } }
        $siKvRead = ${function:Get-SIKeyVaultSecretValue}
        if ($kv -and $siKvRead) { $ReadUpdateState = { & $siKvRead -VaultName $kv -Name 'SI-Update-State' }.GetNewClosure() }
    }
}
if (-not $SubscriptionId) { throw 'Give -SubscriptionId: the subscription of the install. Nothing was started.' }
if (-not $By) { $By = [Environment]::UserName }

$a = @{ Arm = $Arm; SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroupName; Reason = $Reason; RunId = $RunId; SkipUpdate = $SkipUpdate
        Apply = $Apply; TimeoutMinutes = $TimeoutMinutes; PollSeconds = $PollSeconds; By = $By; SqlWhy = $sqlWhy }
if ($Sql) { $a.Sql = $Sql }
if ($ReadUpdateState) { $a.ReadUpdateState = $ReadUpdateState }
if ($Sleep) { $a.Sleep = $Sleep }
if ($Now) { $a.Now = $Now }
if ($SupportGrant) { $a.SupportGrant = $SupportGrant }
$r = Invoke-SIStopRunAndUpdate @a
$global:LASTEXITCODE = $r.ExitCode
$r
} finally { Stop-SIScriptRun -Run $siRun }
