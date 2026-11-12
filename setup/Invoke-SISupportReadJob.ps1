<#
.SYNOPSIS
    SecurityInsight Pro: Invardia support READS an install's data -- one NAMED diagnostic query on its database, or the
    secret NAMES and metadata of its Key Vault -- FROM INSIDE the install's own network: a one-time job in the install's
    own environment reads it, prints the result to its log, and is removed. Nothing is opened. PLAN by default.

.DESCRIPTION
    #1060 (owner 2026-11-02). A Support session from outside cannot reach a private database or Key Vault, and by the
    owner's rule (#681: "when we say it is private, it stays that way"; 2026-11-02: "in #1060, we will never open the fw")
    no route is ever made for it.

    THE NETWORK RULE -- enforced, not only absent. This script and its job NEVER add a firewall rule, NEVER turn public
    network access on, NEVER add an IP or virtual-network exception, and NEVER change a network setting of the database
    server, the Key Vault, storage or the container registry -- on a private install AND on a public one. Every Azure
    request of a run goes through an allow-list (setup\_shared\SI-SupportReadJob.ps1, New-SISupportReadArmGuard): only the
    one-time job's own create / start / remove and a read-only query of the install's log workspace are let through; any
    other change is refused before it is sent. On a PUBLIC install the read runs inside in the same way -- it never falls
    back to a firewall window, even where the database could be reached from outside.

    What it does, in order:
      1. -List prints the named query set and stops (nothing is read).
      2. Reads the install (its jobs, the environment and its log workspace, the image and the pull identity of an engine
         job; for -Query the database server, the databases of the query and the in-network SQL identity id-si-sql, a
         member of the server's admin group; for -KeyVault the Key Vault and the engine identity). PLAN ONLY without -Apply.
      3. With -Apply: creates the one-time job caj-si-supportread (tagged as a one-time job) carrying the read identity and
         the pull identity only, starts it once, waits.
      4. ALWAYS, also after a failed step: removes the job and reads back that it is gone.
      5. Reads the job's result lines from the install's workspace (they arrive minutes later), scrubs and caps them again,
         and prints them here.

    WHAT IS READ. -Query <name> picks one entry of the named, read-only query set shipped in the product (-List shows it);
    there is no free-text SQL. Each query is one fixed SELECT with typed, bound parameters (-Top, -RunId). As the Support
    app's own read-only database user (#1021) is not built yet, the job reads as id-si-sql, inside a transaction that is
    always rolled back, behind a guard that refuses anything other than one SELECT (checked here AND in the job).
    -KeyVault lists secret NAMES with enabled, expiry, created and updated -- it never asks for a secret value.

    THE RESULT is capped (-MaxRows, -MaxBytes; each value cut at 512 characters) and scrubbed (connection-string secrets,
    keys, tokens, signatures, anything Key Vault-shaped) inside the job, so the workspace never holds a secret, and again
    here. Every request is sent through the Invardia Support session's recorder (the customer's audit log).

.EXAMPLE
    .\setup\Invoke-SISupportReadJob.ps1 -List
    . C:\claude-sessions\Invardia\tools\Connect-InvardiaSupport.ps1 -Environment <handle> -Reason 'support read'
    .\setup\Invoke-SISupportReadJob.ps1 -ResourceGroup <rg> -Query run-steps
    .\setup\Invoke-SISupportReadJob.ps1 -ResourceGroup <rg> -Query run-state -Top 5 -Apply
    .\setup\Invoke-SISupportReadJob.ps1 -ResourceGroup <rg> -KeyVault -Apply

.LINK
    https://invardia.com/docs/si/scripts/Invoke-SISupportReadJob/
#>
[CmdletBinding(DefaultParameterSetName = 'Query')]
param(
    [Parameter(Mandatory, ParameterSetName = 'List')][switch]$List,
    [Parameter(Mandatory, ParameterSetName = 'Query')][Parameter(Mandatory, ParameterSetName = 'KeyVault')][ValidatePattern('^[A-Za-z0-9_.()-]{1,90}$')][string]$ResourceGroup,
    [Parameter(Mandatory, ParameterSetName = 'Query')][string]$Query,
    [Parameter(ParameterSetName = 'Query')][int]$Top = 0,
    [Parameter(ParameterSetName = 'Query')][string]$RunId = '',
    [Parameter(Mandatory, ParameterSetName = 'KeyVault')][switch]$KeyVault,
    [Parameter(ParameterSetName = 'KeyVault')][ValidatePattern('^$|^[A-Za-z0-9-]{3,24}$')][string]$VaultName = '',
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][string]$SubscriptionId,
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][string]$SqlServerName = '',
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][ValidateRange(1, 500)][int]$MaxRows = 50,
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][ValidateRange(4096, 262144)][int]$MaxBytes = 65536,
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][ValidatePattern('^$|^[a-z][a-z0-9-]{0,30}[a-z0-9]$')][string]$JobName = '',
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][ValidateRange(60, 3600)][int]$TimeoutSeconds = 900,
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][ValidateRange(0, 7200)][int]$LogWaitSeconds = 1200,
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][switch]$Apply,
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][string]$Reason = '',
    # TEST SEAMS: replace the Support session
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][scriptblock]$Arm,
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][scriptblock]$Graph,
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][scriptblock]$Logs,
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][int]$PollSeconds = 10,
    [Parameter(ParameterSetName = 'Query')][Parameter(ParameterSetName = 'KeyVault')][string]$Nonce = ''
)

$ErrorActionPreference = 'Stop'
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportCutover.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-PrivateNetwork.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportAppDatabase.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportReadJob.ps1'))

if ($List) {
    Write-Host '== the named support queries (read only; one fixed SELECT each; no free-text SQL)' -ForegroundColor Cyan
    $all = @(Get-SISupportReadQueries)
    foreach ($q in $all) {
        $ps = @($q.Params.Keys | ForEach-Object { $d = $q.Params[$_]; if ($d.Type -eq 'int') { '-{0} {1}..{2} (default {3})' -f $_, $d.Min, $d.Max, $d.Default } else { '-{0} <text>' -f $_ } })
        Write-Host ('   {0,-16} {1} [{2}]{3}' -f $q.Name, $q.What, $(if ($q.Scope -eq 'each') { 'every product database' } else { 'the Pro database' }), $(if ($ps.Count) { '  ' + ($ps -join ', ') } else { '' })) -ForegroundColor Gray
    }
    Write-Host '   -KeyVault        the install''s Key Vault: secret NAMES, enabled, expiry, created, updated -- never a value' -ForegroundColor Gray
    return [pscustomobject]@{ Mode = 'list'; Queries = @($all | ForEach-Object { $_.Name }) }
}

$mode = if ($KeyVault) { 'keyvault' } else { 'sql' }
$q = $null; $params = [ordered]@{}
if ($mode -eq 'sql') {
    $q = Get-SISupportReadQuery -Name $Query          # free text / an unknown name: refused here, before anything is read
    $given = @{}
    if ($Top) { $given['Top'] = $Top }
    if ($RunId) { $given['RunId'] = $RunId }
    $params = Resolve-SISupportReadParams -Query $q -Given $given
}
$what = if ($mode -eq 'sql') { 'query ' + $q.Name } else { 'Key Vault names and metadata' }
if (-not $Reason) { $Reason = 'SecurityInsight support read from inside the network: ' + $what }

# the SQL seam is never used here (no database connection from this machine): a refusing stub keeps the seams complete
$seams = New-SICutoverSeams -Arm $Arm -Graph $Graph -Sql { param($a, $b, $c, $d, $e) throw 'this script opens no database connection' } -Reason $Reason
$sess = $null; if (Get-Command -Name Get-SISupportSession -ErrorAction SilentlyContinue) { try { $sess = Get-SISupportSession } catch { $sess = $null } }
if (-not $SubscriptionId) { $SubscriptionId = if ($sess) { [string]$sess.SubscriptionId } else { '' } }
if (-not $SubscriptionId) { throw 'Give -SubscriptionId: the Support session names no subscription.' }

# THE NETWORK RULE: every Azure request of this run through the allow-list (the job's own create / start / remove, a
# read-only log query); anything else is refused before it is sent
$jn = if ($JobName) { $JobName } else { Get-SISupportReadJobName }
$jobId = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}' -f $SubscriptionId, $ResourceGroup, $jn
$arm = New-SISupportReadArmGuard -Arm $seams.Arm -JobId $jobId

$shape = Get-SIInstallShape -Arm $arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -SqlServerName $SqlServerName -FindSqlInResourceGroup
if (-not @($shape.Jobs).Count) { throw ('No Container Apps job was found in {0} (subscription {1}) -- is this the install''s resource group? Nothing was changed.' -f $ResourceGroup, $SubscriptionId) }
$plan = Get-SISupportReadJobPlan -Arm $arm -Graph $seams.Graph -Shape $shape -Mode $mode -Query $q -Params $params -VaultName $VaultName -JobName $jn -MaxRows $MaxRows -MaxBytes $MaxBytes
Write-Host ('== support read from inside -- {0}: {1}' -f $ResourceGroup, $what) -ForegroundColor Cyan
if ($mode -eq 'sql' -and $params.Count) { Write-Host ('   parameters: {0}' -f ((@($params.Keys) | ForEach-Object { '{0}={1}' -f $_, $(if ($null -eq $params[$_]) { '(default)' } else { $params[$_] }) }) -join ', ')) -ForegroundColor Gray }
foreach ($l in $plan.Lines) { Write-Host ('   ' + $l) -ForegroundColor Gray }
Write-Host ('   caps: {0} rows, {1} bytes; values scrubbed in the job and here; nothing is opened (no firewall rule, no public access)' -f $MaxRows, $MaxBytes) -ForegroundColor Gray
if (-not $plan.Ok) {
    foreach ($l in $plan.Problems) { Write-Host ('   STOPPED: ' + $l) -ForegroundColor Red }
    Write-Host '   Nothing was changed. The install''s network is NOT opened for this -- a private install stays private.' -ForegroundColor Yellow
    return [pscustomobject]@{ Mode = 'stopped'; Verdict = 'FAIL'; Plan = $plan; Result = $null }
}
if (-not $Apply) {
    Write-Host ('PLAN ONLY -- nothing was changed. -Apply makes the one-time job {0}, starts it once, removes it and prints the result.' -f $plan.JobName) -ForegroundColor Yellow
    return [pscustomobject]@{ Mode = 'plan'; Verdict = ''; Plan = $plan; Result = $null }
}
$ja = @{ Arm = $arm; Plan = $plan; TimeoutSeconds = $TimeoutSeconds; PollSeconds = $PollSeconds; LogWaitSeconds = $LogWaitSeconds; Sleep = $Sleep; Nonce = $Nonce }
if ($Logs) { $ja['Logs'] = $Logs }
$r = Invoke-SISupportReadJob @ja
foreach ($l in $r.Lines) { Write-Host ('   ' + $l) -ForegroundColor $(if ($r.Ok) { 'Green' } else { 'Yellow' }) }
if ($r.Result) {
    Write-Host ('-- result ({0} row(s){1})' -f $r.Result.Rows.Count, $(if ($r.Result.Truncated -or ($r.Result.End -and $r.Result.End.truncated)) { ', CUT at the size cap' } else { '' })) -ForegroundColor Cyan
    foreach ($x in $r.Result.Rows) { Write-Host $x }
    foreach ($x in $r.Result.Notes) { Write-Host ('NOTE ' + $x) -ForegroundColor Yellow }
}
Write-Host ('{0}: {1}' -f $r.Verdict, $(if ($r.Ok) { 'read inside the network; the job is gone (read back)' } else { 'see the lines above' })) -ForegroundColor $(if ($r.Ok) { 'Green' } else { 'Red' })
Write-Host ('recorded: every request of this run went through the Invardia Support session''s recorder ({0})' -f $Reason) -ForegroundColor Gray
[pscustomobject]@{ Mode = 'apply'; Verdict = $r.Verdict; Plan = $plan; Result = $r }
