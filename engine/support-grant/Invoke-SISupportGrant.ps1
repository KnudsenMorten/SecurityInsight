#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight -- the SUPPORT GRANT JOB (caj-si-support-grant, REQUIREMENTS #1021): the Invardia Support app's database
    access, opened and closed JUST IN TIME on a request the Support session put on the queue si-support-requests.
.DESCRIPTION
    STARTED BY ITS QUEUE (#1154, framework 5.5: an event trigger, the queue read as the engine identity) when the Invardia
    Support session put ONE request on it -- the Support app holds no right on the job. An empty queue (another execution
    took the request) ends ok with no SUPPORT-GRANT line. The job
    revokes any expired grant first, reads and deletes the queue, takes the newest request that is not older than 15
    minutes, and opens or closes the grant through the signed procedures of every product database (the Pro database
    first). The request is a REQUEST: the customer's recorded consent decides the level, maxUntil is at most 8 hours.
    See SI-SupportGrant.ps1 for the whole design.

    It needs no pipeline, no licence, no heartbeat and no updater (framework 4b: consent means support always works): only
    the engine identity, the install's storage queue and the databases.

    ONE log line Invardia reads:  SUPPORT-GRANT action=<open|close|none> level=<granted|none> until=<UTC|none> result=<ok|reason>
    Exit: 0 ok, 2 could not, 3 no consent, 4 bad request.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
try { Set-StrictMode -Off } catch { }
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$say = { param([string]$Level, [string]$Message) Write-Host ('[{0}] {1}' -f $Level, $Message) -ForegroundColor $(if ($Level -eq 'WARN') { 'Yellow' } else { 'Gray' }) }

Write-Host '[STEP] SecurityInsight -- support access (just in time)' -ForegroundColor Cyan
try {
    if (-not (Get-Command -Name Invoke-SIAzRestRequest -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-AzRest.ps1') }
    if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/data-model/SI-RecordSql.ps1') }
    . (Join-Path $PSScriptRoot 'SI-SupportGrant.ps1')
} catch {
    & $say 'WARN' ('the support grant could not be loaded ({0})' -f $_.Exception.Message)
    Write-Host 'SUPPORT-GRANT action=none level=none until=none result=failed'
    exit 2
}

$nowUtc = [datetime]::UtcNow
$dbs = [ordered]@{}
try { $dbs = Get-SISupportGrantDatabases } catch { & $say 'WARN' ('the product databases could not be opened ({0})' -f $_.Exception.Message) }
if (-not $dbs.Count) {
    & $say 'WARN' 'this install has no Pro database (SI_ProSqlServer / SI_ProSqlDatabase) -- there is nothing to grant'
    Write-Host (Get-SISupportGrantLogLine -Action '' -Level '' -Until $null -Result 'not-prepared')
    exit (Get-SISupportGrantExitCode 'not-prepared')
}

$account = [string]$global:SI_StorageAccount
$queue = (Get-SISupportGrantJobContract).Queue
$receive = {
    if (-not $account.Trim()) { throw 'the install names no storage account (SI_StorageAccount)' }
    $all = [System.Collections.Generic.List[object]]::new()
    # up to 4 reads of 32 -- every message on the queue is read and deleted (each read on its own: a close wins, else the newest fresh open)
    for ($i = 0; $i -lt 4; $i++) {
        $r = Invoke-SIStorageRequest -Method GET -Uri (Get-SIStorageUri -Account $account -Service queue -Path ("$queue/messages") -Query 'numofmessages=32&visibilitytimeout=120') -Headers @{ Accept = 'application/xml' } -AllowNotFound -What ("Read the queue '{0}'" -f $queue)
        if ($null -eq $r) { break }
        # #1356: the read's batch opened up into one item per message (@( ) alone kept the batch as ONE item)
        $got = @(ConvertFrom-SISupportGrantQueueXml -Xml ([string]$r.Content) | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        foreach ($m in $got) { $all.Add($m) }
        if ($got.Count -lt 32) { break }
    }
    $all.ToArray()
}
$remove = { param($m) Remove-SIQueueMessage -Account $account -Queue $queue -MessageId ([string]$m.Id) -PopReceipt ([string]$m.PopReceipt) }

# Invardia 2026-11-20 (OPEN-01): after an open or a close the heartbeat's SupportAccess state must reach Invardia within a
# minute -- ONE extra execution of the heartbeat job, started the way the pipeline runner starts a job (SI_HEARTBEAT_EXTRA =
# support-access: it sends at once, outside the half hour's claim, with the state read from the install). Never fails the job.
$report = {
    param($Event)
    try {
        $hb = Start-SISupportAccessHeartbeat
        if ($hb.Started) { & $say 'INFO' ('support access: the heartbeat is sent now, so Invardia sees the change ({0})' -f $(if ($hb.Execution) { $hb.Execution } else { 'started' })) }
        else { & $say 'INFO' ('support access: the extra heartbeat was not started ({0}) -- the next half-hourly heartbeat carries the change' -f $hb.Why) }
    } catch { & $say 'INFO' ('support access: the extra heartbeat was not started ({0}) -- the next half-hourly heartbeat carries the change' -f $_.Exception.Message) }
}

$r = Invoke-SISupportGrantJob -Databases $dbs -Receive $receive -Remove $remove -NowUtc $nowUtc -Say $say -Report $report
# THE line Invardia reads (ARM may not report the exit code) -- none for an empty queue (#1154: no request to answer)
if ($r.Line) { Write-Host $r.Line }
exit $r.ExitCode
