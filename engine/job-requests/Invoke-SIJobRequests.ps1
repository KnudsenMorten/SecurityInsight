#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight -- the JOB REQUEST JOB (caj-si-job-requests, REQUIREMENTS #1252): starts the job a person asked for in
    the web app (Run now, Stop, a schedule change's apply, a template release, a mail "send now"), as the ENGINE identity.
.DESCRIPTION
    STARTED BY ITS QUEUE si-job-requests (an event trigger, the queue read as the engine identity -- the web app holds only
    Storage Queue Data Message Sender on that one queue and no right on any job). Reads and deletes every message, answers
    each on its own (SI-JobRequests.ps1 for the whole design) and writes ONE line per message:
        JOB-REQUEST id=<id> job=<job> by=<who> result=<started|refused|failed> detail=<words>
    It needs no pipeline, no licence and no database: only the engine identity, the install's storage queue and ARM.
    Exit: 0 (every message answered, also when one was refused or failed), 2 the queue could not be read.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
try { Set-StrictMode -Off } catch { }
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$say = { param([string]$Level, [string]$Message) Write-Host ('[{0}] {1}' -f $Level, $Message) -ForegroundColor $(if ($Level -eq 'WARN') { 'Yellow' } else { 'Gray' }) }

Write-Host '[STEP] SecurityInsight -- the jobs people asked for in the web app' -ForegroundColor Cyan
try {
    if (-not (Get-Command -Name Invoke-SIAzRestRequest -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-AzRest.ps1') }
    if (-not (Get-Command -Name New-SIJobStartTemplate -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-UpdaterStart.ps1') }
    # the rest of the shared helpers' load chain (SUP-2026-00687: a function no loaded file defines fails the job at run time)
    if (-not (Get-Command -Name Get-SIKqlErrorSummary -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-KqlError.ps1') }
    if (-not (Get-Command -Name Get-SILogIngestToken -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-LogIngest.ps1') }
    if (-not (Get-Command -Name Get-SICertificateFromStore -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'auth/Find-SICertificate.ps1') }
    . (Join-Path $PSScriptRoot 'SI-JobRequests.ps1')
} catch {
    & $say 'WARN' ('the job requests could not be loaded ({0})' -f $_.Exception.Message)
    exit 2
}

$contract = Get-SIJobRequestsContract
$account = "$([string]$global:SI_StorageAccount)".Trim(); if (-not $account) { $account = "$([Environment]::GetEnvironmentVariable('SI_STORAGE_ACCOUNT'))".Trim() }
$sub = "$([Environment]::GetEnvironmentVariable('SI_JOBS_SUBSCRIPTIONID'))".Trim(); if (-not $sub) { $sub = "$([Environment]::GetEnvironmentVariable('SI_FLOW_SUBSCRIPTIONID'))".Trim() }
$rg = "$([Environment]::GetEnvironmentVariable('SI_JOBS_RESOURCEGROUP'))".Trim(); if (-not $rg) { $rg = "$([Environment]::GetEnvironmentVariable('SI_FLOW_RESOURCEGROUP'))".Trim() }
$armApi = '2025-07-01'
$queue = $contract.Queue

$receive = {
    if (-not $account) { throw 'the install names no storage account (SI_StorageAccount)' }
    $all = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt 4; $i++) {
        $r = Invoke-SIStorageRequest -Method GET -Uri (Get-SIStorageUri -Account $account -Service queue -Path ("$queue/messages") -Query 'numofmessages=32&visibilitytimeout=120') -Headers @{ Accept = 'application/xml' } -AllowNotFound -What ("Read the queue '{0}'" -f $queue)
        if ($null -eq $r) { break }
        # #1356: one item per message (never the batch as one)
        $got = @(ConvertFrom-SIJobRequestQueueXml -Xml ([string]$r.Content) | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        foreach ($m in $got) { $all.Add($m) }
        if ($got.Count -lt 32) { break }
    }
    $all.ToArray()
}
$remove = { param($m) Remove-SIQueueMessage -Account $account -Queue $queue -MessageId ([string]$m.Id) -PopReceipt ([string]$m.PopReceipt) }
$jobsPath = { '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs' -f $sub, $rg }
$installed = {
    if (-not $sub -or -not $rg) { throw 'where the install''s jobs are is not known (SI_JOBS_SUBSCRIPTIONID / SI_JOBS_RESOURCEGROUP)' }
    @(Invoke-SIArm -Method GET -Path (& $jobsPath) -ApiVersion $armApi -List | ForEach-Object { [string]$_.name } | Where-Object { $_ -like 'caj-si-*' })
}
$start = {
    param([string]$Job, [System.Collections.IDictionary]$Env)
    $path = '{0}/{1}' -f (& $jobsPath), $Job
    $body = [ordered]@{}
    if ($Env -and $Env.Count) {
        $j = Invoke-SIArm -Method GET -Path $path -ApiVersion $armApi
        if ($null -eq $j) { throw ('{0} is not a job of this install' -f $Job) }
        $body = New-SIJobRequestStartBody -Job $j -Env $Env -What $Job
    }
    $r = Invoke-SIArm -Method POST -Path ($path + '/start') -ApiVersion $armApi -Body $body
    $n = ''
    if ($r) { if ($r.PSObject.Properties['name']) { $n = [string]$r.name }; if (-not $n -and $r.PSObject.Properties['id'] -and $r.id) { $n = ([string]$r.id -split '/')[-1] } }
    $n
}

$r = Invoke-SIJobRequestsJob -Receive $receive -Remove $remove -Installed $installed -Start $start -NowUtc ([datetime]::UtcNow) -Say $say
exit $r.ExitCode
