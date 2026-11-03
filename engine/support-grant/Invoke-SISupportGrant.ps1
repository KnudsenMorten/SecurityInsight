#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight -- the SUPPORT GRANT JOB (caj-si-support-grant, REQUIREMENTS #1021): the Invardia Support app's database
    access, opened and closed JUST IN TIME on a request the Support session put on the queue si-support-requests.
.DESCRIPTION
    Started by the Invardia Support session with a plain start (no override), after it put ONE request on the queue. The job
    revokes any expired grant first, reads and deletes the queue, takes the newest request that is not older than 15
    minutes, and opens or closes the grant through the signed procedures of every product database (the Pro database
    first). The request is a REQUEST: the customer's recorded consent decides the level, maxUntil is at most 24 hours.
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
    # up to 4 reads of 32 -- every message on the queue is read and deleted (the newest fresh one is the request)
    for ($i = 0; $i -lt 4; $i++) {
        $r = Invoke-SIStorageRequest -Method GET -Uri (Get-SIStorageUri -Account $account -Service queue -Path ("$queue/messages") -Query 'numofmessages=32&visibilitytimeout=120') -Headers @{ Accept = 'application/xml' } -AllowNotFound -What ("Read the queue '{0}'" -f $queue)
        if ($null -eq $r) { break }
        $got = @(ConvertFrom-SISupportGrantQueueXml -Xml ([string]$r.Content))
        foreach ($m in $got) { $all.Add($m) }
        if ($got.Count -lt 32) { break }
    }
    $all.ToArray()
}
$remove = { param($m) Remove-SIQueueMessage -Account $account -Queue $queue -MessageId ([string]$m.Id) -PopReceipt ([string]$m.PopReceipt) }

# the uplink events: only where SI_Uplink_SendSupportGrant says so (OFF until Invardia has agreed them)
$report = $null
try {
    $ring = if ($global:SI_InstallRingFacts -and $global:SI_InstallRingFacts.PSObject.Properties['Ring']) { $global:SI_InstallRingFacts.Ring } else { $null }
    if ((Resolve-SIUplinkSupportGrantSwitch -Ring $ring).On) {
        $report = {
            param($Event)
            if (-not (Get-Command -Name Get-SITelemetryContext -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-TelemetrySend.ps1') }
            $ctx = Get-SITelemetryContext
            if ($ctx.Mode -ne 'identified') { return }
            $rec = ConvertTo-SITelemetryWire -Record (New-SITelemetryHeartbeat -Edition $ctx.Edition -Version $ctx.Version -Hosting $ctx.Hosting -RuntimeIdentity $ctx.RuntimeIdentity -LicenceState $ctx.LicenceState -Now ([datetime]::UtcNow) -TenantId $ctx.TenantId) -Mode $ctx.Mode -Now ([datetime]::UtcNow)
            if ($rec) { $rec | Add-Member -NotePropertyName 'supportGrant' -NotePropertyValue $Event -Force; $null = Send-SITelemetryUplink -Record $rec -Endpoint $ctx.Endpoint -AccessCode $ctx.AccessCode -TimeoutSec 10 }
        }
    }
} catch { $report = $null }

$r = Invoke-SISupportGrantJob -Databases $dbs -Receive $receive -Remove $remove -NowUtc $nowUtc -Say $say -Report $report
# THE line Invardia reads (ARM may not report the exit code)
Write-Host $r.Line
exit $r.ExitCode
