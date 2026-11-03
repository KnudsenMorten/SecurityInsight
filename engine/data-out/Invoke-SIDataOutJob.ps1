#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight -- the DATA-OUT JOB (caj-si-data-out, REQUIREMENTS #1038 part 1): the ServiceNow hand-off, the vulnerable
    items and every other output, sent from the NEWEST collection the data sync marked ready for data out.
.DESCRIPTION
    The data sync marks a collection ready the moment its findings per CI are stored and starts this job (a plain start);
    a person or support starts it to send again (a resend). It runs Invoke-SIDataOut exactly as the data sync did -- each
    output's run, batches and items are recorded as before (cfg.ConnectorRun / DataOutBatch / DataOutItem) -- and never
    waits on the data sync's later phases (summaries, clean-up, views). A second start while one sends does nothing; a send
    whose outputs failed is tried again by the job itself. See SI-DataOutJob.ps1 for the whole design.

    Settings: as the data sync (SI_ProSqlServer / SI_ProSqlDatabase, or SI_Pro_DataSqlServer / SI_Pro_DataSqlDatabase).
    Sign-in: the container job's managed identity (the engine identity), else the engine SPN by certificate.
#>
[CmdletBinding()]
param()

if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-AzRest.ps1') }
$ErrorActionPreference = 'Stop'
try { Set-StrictMode -Off } catch { }

function Write-DoInfo ($m) { Write-Host "[INFO] $m" -ForegroundColor Gray }
function Write-DoOk   ($m) { Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-DoWarn ($m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }

$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $siRoot 'engine\_shared\data-sql\SI-DataModel.ps1')
. (Join-Path $siRoot 'engine\_shared\data-sql\SI-DataSql.ps1')
. (Join-Path $PSScriptRoot 'SI-DataOutJob.ps1')

Write-Host '[STEP] SecurityInsight -- data out (the ServiceNow hand-off and the other outputs)' -ForegroundColor Cyan
. (Join-Path $siRoot 'engine\SI-FeatureCatalog.ps1')
if (-not (Assert-SIFeatureOrSkip -Feature 'data-backend')) { return }

# the same auth bridge as the data sync: platform names -> SI_SPN_*
if (-not $global:SI_SPN_TenantId       -and $global:HighPriv_Modern_TenantID)                    { $global:SI_SPN_TenantId       = [string]$global:HighPriv_Modern_TenantID }
if (-not $global:SI_SPN_AppId          -and $global:HighPriv_Modern_ApplicationID_Azure)         { $global:SI_SPN_AppId          = [string]$global:HighPriv_Modern_ApplicationID_Azure }
if (-not $global:SI_SPN_CertThumbprint -and $global:HighPriv_Modern_CertificateThumbprint_Azure) { $global:SI_SPN_CertThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }

$g = @{}
foreach ($n in 'SI_ProSqlServer', 'SI_ProSqlDatabase', 'SI_Pro_DataSqlServer', 'SI_Pro_DataSqlDatabase', 'SI_Pro_DataRetentionDays', 'SI_Pro_DataLookbackDays', 'SI_AssetProperties', 'SI_AssetProperties_RetentionDays') {
    $g[$n] = Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue
}
$settings = Resolve-SIDataSettings -Globals $g
if (@($settings.Problems).Count) { throw ('data out: ' + (@($settings.Problems) -join '; ')) }
Write-DoInfo ("database  : {0}/{1}" -f $settings.Server, $settings.Database)
$invoke = New-SIDataSqlInvoke -Server $settings.Server -Database $settings.Database -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint -CommandTimeoutSec 0
$log = { param([string]$level, [string]$msg) switch ($level) { 'OK' { Write-DoOk $msg } 'WARN' { Write-DoWarn $msg } default { Write-DoInfo $msg } } }

# run health, as the data sync records its own: START now, END once in the finally (never fails the job)
$runContext = [pscustomobject]@{ RunId = [guid]::NewGuid().ToString(); Engine = 'data-out'; ShardIndex = 0; ShardCount = 1; StartedAt = [datetime]::UtcNow; CollectionTime = [datetime]::UtcNow }
$healthFile = Join-Path $siRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1'
if (-not (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $healthFile)) { try { . $healthFile } catch { Write-DoWarn ("run health is not recorded: {0}" -f $_.Exception.Message) } }
$sendHealth = { param([string]$phase, [string]$exit, [string]$err) if (-not (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue)) { return }; try { Send-SIRunHealthRow -RunContext $runContext -Phase $phase -ExitReason $exit -ErrorMessage $err -NoTelemetry } catch { } }
$rhEnd = @{ Exit = 'success'; Message = '' }
& $sendHealth 'Start' '' ''
try {
    # the outputs, exactly as the data sync ran them (engine\pro-data\Invoke-SIDataSync.ps1, its DATA OUT part)
    . (Join-Path $siRoot 'engine\data-out\SI-DataOut.ps1')
    $doStore = $null
    try { $doStore = New-SIConnectorRegistryStore } catch { Write-DoWarn ("data out  : the runs are not recorded -- {0}" -f $_.Exception.Message) }
    # CR2 (#656): while SecurityInsight's data is Unhealthy each output is held unless a SuperAdmin let its connector through
    $doHold = $null
    try {
        . (Join-Path $siRoot 'engine\_shared\SI-DataHealthHold.ps1')
        $doHold = { param([string]$Connector) Resolve-SIDataHealthHold -Channel $Connector }
    } catch { Write-DoWarn ("data out  : the data health hold could not be checked ({0}) -- the outputs run as configured" -f $_.Exception.Message) }
    $send = {
        param($Ready)
        # per report: the reports the marked run could not complete -- what they found is kept as last sent
        @(Invoke-SIDataOut -Invoke $invoke -Store $doStore -Edition 'pro' -Log $log -FrozenReports @($Ready.FrozenReports) -HoldCheck $doHold)
    }
    $global:SI_DataOutJobResult = Invoke-SIDataOutJobCore -Invoke $invoke -Send $send -Log $log
    $global:SI_DataOutResult = @($global:SI_DataOutJobResult.Results)
    $o = [string]$global:SI_DataOutJobResult.Outcome
    $issues = @(); if (Get-Command -Name Get-SIDataOutIssues -ErrorAction SilentlyContinue) { $issues = @(Get-SIDataOutIssues -Results @($global:SI_DataOutResult)) }
    foreach ($i in $issues) { if ($i) { Write-DoWarn ('{0,-9} : {1}' -f $i.Level, $i.Text) } }
    if ($o -eq 'failed') {
        $rhEnd.Exit = 'error'; $rhEnd.Message = [string]$global:SI_DataOutJobResult.Why
    } elseif (@($issues | Where-Object { $_ -and [string]$_.Level -eq 'FAILED' }).Count) {
        $rhEnd.Exit = 'success-partial'; $rhEnd.Message = (@($issues | ForEach-Object { [string]$_.Text }) -join ' | ')
    } elseif ($o -in @('held', 'no-tables')) {
        $rhEnd.Exit = 'success-partial'; $rhEnd.Message = [string]$global:SI_DataOutJobResult.Why
    } elseif ($o -in @('busy', 'nothing')) {
        $rhEnd.Message = [string]$global:SI_DataOutJobResult.Why
    }
    if ($o -eq 'failed') { throw ('data out did not deliver everything -- ' + [string]$global:SI_DataOutJobResult.Why) }
} catch {
    $rhEnd.Exit = 'error'; $rhEnd.Message = $_.Exception.Message
    throw
} finally {
    & $sendHealth 'End' $rhEnd.Exit $rhEnd.Message
}
