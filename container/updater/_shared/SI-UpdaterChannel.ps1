#Requires -Version 5.1
<#
    caj-si-updater -- THIS ENVIRONMENT, as the update sees it (#350): the SI jobs and their images, the record of what runs
    (tags si-installed / si-installed-commit on the updater job, written after every roll AND by a manual deploy), the
    manual-deploy mark, and "is an SI run in progress". Used by the Invardia path (_shared/SI-UpdaterInvardia.ps1) before
    and after a roll. Loaded by Start-SIUpdater.ps1; uses its ARM functions (#521: REST only, no az CLI).

    (The ring-channel run this file used to hold -- channel.json in SI's own storage feed -- is RETIRED, 2026-10-06.)
#>

function Get-SIUpdaterEnvironment {
    <# The SI jobs and container apps of the resource group: @{ LoginServer; Images; Record; Apps }. One ARM read per kind. #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId,
          [string]$UpdaterJob = 'caj-si-updater')
    $acr  = Get-SIUpdaterRegistry -AcrName $AcrName -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
    $jobs = @(Get-SIUpdaterJobs -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId) | Where-Object { $_ }
    $images = New-Object System.Collections.Generic.List[string]
    $names = New-Object System.Collections.Generic.List[string]
    $record = $null; $updaterId = ''; $deployLock = ''; $updaterImage = ''; $selfPending = ''
    foreach ($j in $jobs) {
        $img = ''; try { $img = [string]$j.properties.template.containers[0].image } catch { }
        if ([string]$j.name -eq $UpdaterJob) {
            $updaterId = [string]$j.id; $updaterImage = $img
            $t = $j.tags
            if ($t) { $record = [pscustomobject]@{ Version = "$($t.'si-installed')"; Commit = "$($t.'si-installed-commit')" }; $deployLock = "$($t.'si-deploy-running')"; $selfPending = "$($t.'si-updater-pending')".Trim() }
            continue
        }
        if ($img -and $img.ToLowerInvariant().StartsWith(("{0}/si-orchestrator:" -f $acr.loginServer).ToLowerInvariant())) { $images.Add($img); $names.Add([string]$j.name) }
    }
    [pscustomobject]@{ LoginServer = [string]$acr.loginServer; Images = $images.ToArray(); JobNames = $names.ToArray(); Record = $record; UpdaterId = $updaterId; DeployLock = $deployLock
        UpdaterImage = $updaterImage; SelfPending = $selfPending }
}

function Save-SIUpdaterInstalledRecord {
    <# What now runs, as tags on the updater job (a MERGE: no other tag changes, no new job revision). Never fails the run. #>
    param([Parameter(Mandatory)][string]$ResourceId, [Parameter(Mandatory)][string]$Version, [string]$Commit = '', [Parameter(Mandatory)][string]$SubscriptionId)
    if (-not $ResourceId) { return $false }
    try {
        $tags = @{ 'si-installed' = $Version; 'si-installed-utc' = ('{0:yyyy-MM-ddTHH:mm:ssZ}' -f [datetime]::UtcNow); 'si-installed-by' = 'caj-si-updater' }
        if ($Commit) { $tags['si-installed-commit'] = $Commit }
        Update-SIUpdaterTags -ResourceId $ResourceId -Tags $tags
        return $true
    } catch { Write-UpdLog ("WARNING: what now runs could not be recorded on the updater job: {0}" -f $_.Exception.Message); return $false }
}

function Get-SIUpdaterBusyJobs {
    <# The SI jobs with an execution in progress (Running / Processing) -- an update never rolls under a running pipeline. #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$JobNames, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId)
    $busy = New-Object System.Collections.Generic.List[string]
    foreach ($n in $JobNames) {
        $ex = $null
        try { $ex = @(Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/jobs/{0}/executions' -f $n)) -List) } catch { continue }
        if (@($ex | Where-Object { $_ -and "$($_.properties.status)" -in @('Running', 'Processing') }).Count) { $busy.Add($n) }
    }
    $busy.ToArray()
}

function Wait-SIUpdaterPipelineIdle {
    <# $true when no SI job runs (now, or within -Minutes); $false = still busy -> the update waits for the next run. #>
    param([string[]]$JobNames, [string]$ResourceGroup, [string]$SubscriptionId, [int]$Minutes = 60, [int]$PollSeconds = 120)
    $deadline = [datetime]::UtcNow.AddMinutes($Minutes)
    while ($true) {
        $busy = @(Get-SIUpdaterBusyJobs -JobNames $JobNames -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId)
        if (-not $busy.Count) { return $true }
        if ([datetime]::UtcNow -ge $deadline) { Write-UpdLog ("still running after {0} min: {1}" -f $Minutes, ($busy -join ', ')); return $false }
        Write-UpdLog ("an SI run is in progress ({0}) -- waiting before the update" -f ($busy -join ', '))
        Start-Sleep -Seconds $PollSeconds
    }
}

