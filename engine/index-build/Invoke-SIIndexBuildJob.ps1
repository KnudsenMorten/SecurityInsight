#Requires -Version 5.1
<#
.SYNOPSIS
    caj-si-index-build -- THE INDEX BUILD JOB's entry (REQUIREMENTS #1111; the design is in SI-IndexBuildJob.ps1).
.DESCRIPTION
    Started by the pipeline runner's idle wake-up (never by the updater, never as a pipeline step). Runs in SI's own image
    (container\Start-SIInContainer.ps1 hands SI_ROLE = index-build to this file) as the UPDATER's managed identity
    (SI_INDEXBUILD_MI_CLIENT_ID): the token for the Pro database and for Azure Resource Manager comes from the container's
    managed-identity endpoint. Builds ONE waiting or paused index; an update always goes first (the job pauses and ends).
    Its last line is always: INDEX-BUILD outcome=<built|paused|waiting|not-now|nothing|failed|stopped> index=<table/name>
    Exit: 0 (built, paused, waiting, not now, nothing to do), 1 (failed or stopped), 2 (refused inputs).
    No module: SI's shared seams -- Get-SIManagedIdentityToken, Open-SISqlConnectionRetry, Invoke-SIAzRestRequest.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
try { Set-StrictMode -Off } catch { }
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$log = { param([string]$m) Write-Host ('[{0:u}] {1}' -f [datetime]::UtcNow, $m) }

try {
    # SI's shared seams (no direct network call in this file): the managed-identity token (auth\SI-ManagedIdentity.ps1, which
    # loads engine\_shared\SI-AzRest.ps1 -- ARM with its retry rule), the database open with its retry (SI-SqlRetry.ps1).
    # The image carries them: container\Dockerfile copies the whole solution to /app.
    . ([IO.Path]::Combine($siRoot, 'auth', 'SI-ManagedIdentity.ps1'))
    if (-not (Get-Command -Name Invoke-SIAzRestRequest -ErrorAction Ignore)) { . ([IO.Path]::Combine($siRoot, 'engine', '_shared', 'SI-AzRest.ps1')) }
    . ([IO.Path]::Combine($siRoot, 'engine', '_shared', 'SI-SqlRetry.ps1'))
    . ([IO.Path]::Combine($siRoot, 'engine', '_shared', 'SI-IndexBuild.ps1'))
    . ([IO.Path]::Combine($siRoot, 'engine', '_shared', 'SI-UpdaterStart.ps1'))
    # the install's lock: the updater's own run gate (the same lock row, the same rules; the job never waits for it)
    . ([IO.Path]::Combine($siRoot, 'container', 'updater', '_shared', 'SI-UpdaterRunGate.ps1'))
    . ([IO.Path]::Combine($PSScriptRoot, 'SI-IndexBuildJob.ps1'))
} catch {
    & $log ('index build: the job could not be loaded ({0})' -f $_.Exception.Message)
    & $log 'INDEX-BUILD outcome=failed index=none'
    exit 1
}

$in = Read-SIIndexBuildJobInput
if (-not $in.Ok) {
    & $log ('index build: refused -- {0} (the next update sets the job up again)' -f $in.Reason)
    & $log 'INDEX-BUILD outcome=failed index=none'
    exit 2
}

# ---- tokens: the job's (the updater's) managed identity, from the container's endpoint (Get-SIManagedIdentityToken: the
# client id always sent, cached until shortly before the token's own expiry) ----
$miAuth = @{ Mode = 'ManagedIdentity'; ClientId = [string]$in.MiClientId }
$sqlToken = { param([bool]$Fresh) Get-SIManagedIdentityToken -Resource 'https://database.windows.net/' -ClientId ([string]$in.MiClientId) -ForceRefresh:$Fresh }

# ---- the Pro database: one connection per call; the build gets its own (Open). Opened by Open-SISqlConnectionRetry (a
# failover, a serverless resume or a just-changed sign-in is tried again with a fresh token); no statement time limit ----
$store = [pscustomobject]@{
    Server = $in.Server; Database = $in.Database
    Invoke = {
        param([string]$Sql, $Params, [string]$Mode)
        $c = Open-SISqlConnectionRetry -Server $in.Server -Database $in.Database -Token $sqlToken
        try {
            $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql; $cmd.CommandTimeout = 0
            if ($Params) { foreach ($k in @($Params.Keys)) { $v = $Params[$k]; [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $v) { [DBNull]::Value } else { $v })) } }
            if ($Mode -eq 'reader') {
                $rd = $cmd.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $rows.Add($h) } } finally { $rd.Close() }
                , $rows.ToArray()
            } elseif ($Mode -eq 'scalar') { $cmd.ExecuteScalar() } else { [void]$cmd.ExecuteNonQuery() }
        } finally { $c.Dispose() }
    }
    Open = { Open-SISqlConnectionRetry -Server $in.Server -Database $in.Database -Token $sqlToken }
}

# ---- Azure Resource Manager (SI-AzRest: 429 / 5xx retried, 401 refreshes the token once): the updater job (its wait
# mark and its executions) and this job's own executions ----
$arm = {
    param([string]$Path)
    $uri = 'https://management.azure.com{0}{1}api-version=2025-07-01' -f $Path, $(if ($Path.Contains('?')) { '&' } else { '?' })
    $r = Invoke-SIAzRestRequest -Method GET -Uri $uri -Audience Arm -Auth $miAuth -What ('Azure Resource Manager GET {0}' -f $Path)
    if (-not $r -or [string]::IsNullOrWhiteSpace([string]$r.Content)) { return $null }
    $r.Content | ConvertFrom-Json
}
$jobsBase = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs' -f $in.SubscriptionId, $in.ResourceGroup
$seams = @{
    UpdateFirst  = {
        if (-not $in.SubscriptionId -or -not $in.ResourceGroup) { return 'the job does not know where the updater is (SI_INDEXBUILD_SUBSCRIPTION_ID / _RESOURCE_GROUP)' }
        $j = & $arm ('{0}/{1}' -f $jobsBase, $in.UpdaterJob)
        $x = & $arm ('{0}/{1}/executions' -f $jobsBase, $in.UpdaterJob)
        Get-SIIndexBuildUpdateFirst -Job $j -Executions @($x.value) -NowUtc ([datetime]::UtcNow)
    }
    OtherRunning = {
        if (-not $in.SubscriptionId -or -not $in.ResourceGroup) { return '' }
        $x = & $arm ('{0}/{1}/executions' -f $jobsBase, (Get-SIIndexBuildJobNames).Job)
        Get-SIIndexBuildOtherRunning -Executions @($x.value) -Self $in.Execution -NowUtc ([datetime]::UtcNow)
    }
}

$r = Invoke-SIIndexBuildJob -Store $store -Holder (Get-SIIndexBuildJobHolder -Execution $in.Execution) -Request $in.Request -Seams $seams -Log $log
exit $r.ExitCode
