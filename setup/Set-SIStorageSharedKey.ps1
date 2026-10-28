<#
.SYNOPSIS
    Shows, or switches OFF, shared-key access on SecurityInsight's storage account -- after proving nothing uses a key.

.DESCRIPTION
    SecurityInsight reaches its storage account (the staging blobs, the cache tables, the shard queues) with its own
    identity only: the managed identity in a container, the app identity or a managed identity on a VM, each holding
    the Storage Blob / Queue / Table Data Contributor roles. A NEW install creates the account with shared-key access
    already OFF. An account created by an older release keeps it ON until you switch it off here -- nothing changes it
    automatically.

    Without -Disable the script only REPORTS: the account's current settings and anything that would stop working.
    With -Disable it switches shared-key access off (and makes Entra ID the default in the portal) ONLY when all of
    this holds, and otherwise changes nothing and says what to fix:
      * no request in the last -Days days (default 7) was signed with the account key or a key-signed SAS
        (the account's own Transactions metric -- this also sees a VM, a script or a tool outside SecurityInsight;
        a user-delegation SAS is signed in with Entra ID and keeps working);
      * every Container Apps job that uses the account: its queue scaler signs in with a managed identity, it carries
        no storage-key secret or setting of an older release, and the identity it signs in as holds the three
        Storage Data Contributor roles.

    -Enable switches shared-key access back ON -- the way back if something outside SecurityInsight turns out to need
    the key after all.

    Signs in with no PowerShell module (Azure Cloud Shell, the browser, or the sign-in already open in this session).
    Reading needs Reader + Monitoring Reader on the account; switching needs Storage Account Contributor (or
    Contributor) on it.

.EXAMPLE
    .\Set-SIStorageSharedKey.ps1                      # report only, from config\SecurityInsight.custom.ps1
.EXAMPLE
    .\Set-SIStorageSharedKey.ps1 -Disable
.EXAMPLE
    .\Set-SIStorageSharedKey.ps1 -StorageAccountName stsiprod01 -ResourceGroupName rg-securityinsight -SubscriptionId <id> -Disable

.LINK
    https://invardia.com/docs/si/scripts/Set-SIStorageSharedKey/
#>
[CmdletBinding(DefaultParameterSetName = 'Report', SupportsShouldProcess)]
param(
    [string]$StorageAccountName,
    [string]$ResourceGroupName,
    [string]$SubscriptionId,
    [string]$TenantId,
    [string]$ConfigPath,
    [ValidateRange(1, 90)][int]$Days = 7,
    [Parameter(ParameterSetName = 'Disable', Mandatory)][switch]$Disable,
    [Parameter(ParameterSetName = 'Enable', Mandatory)][switch]$Enable
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Set-SIStorageSharedKey' -Quiet:($false)
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $siRoot 'container\_shared\SI-ContainerConfig.ps1')
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-StorageSharedKey.ps1'))
if (-not (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1')) }

# ---- which account: the parameters, else the install's config ----
if (-not $StorageAccountName -or -not $ResourceGroupName -or -not $SubscriptionId) {
    if (-not $ConfigPath) { $ConfigPath = Join-Path $siRoot 'config\SecurityInsight.custom.ps1' }
    if (Test-Path -LiteralPath $ConfigPath) {
        . $ConfigPath
        $ws = [string]$global:SI_WorkspaceResourceId
        if (-not $StorageAccountName) { $StorageAccountName = [string]$global:SI_StorageAccount }
        if (-not $SubscriptionId) { $SubscriptionId = if ($global:SI_AzSubscriptionId) { [string]$global:SI_AzSubscriptionId } elseif ($ws) { ($ws -split '/')[2] } }
        if (-not $ResourceGroupName) {
            $ResourceGroupName = if ($global:SI_StorageResourceGroup) { [string]$global:SI_StorageResourceGroup } elseif ($global:SI_DcrResourceGroup) { [string]$global:SI_DcrResourceGroup } elseif ($ws) { ($ws -split '/')[4] }
        }
    }
}
foreach ($need in @(@{ V = $StorageAccountName; N = 'StorageAccountName (or SI_StorageAccount in the config)' },
                    @{ V = $ResourceGroupName; N = 'ResourceGroupName (or SI_StorageResourceGroup in the config)' })) {
    if ([string]::IsNullOrWhiteSpace([string]$need.V)) { throw ('Missing {0}.' -f $need.N) }
}

if (-not (Get-SISetupAzureContext)) { $null = Connect-SISetupAzure -TenantId $TenantId -SubscriptionId $SubscriptionId }
if (-not $SubscriptionId) { $SubscriptionId = Get-SISetupSubscriptionId }
$accountId = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Storage/storageAccounts/{2}' -f $SubscriptionId, $ResourceGroupName, $StorageAccountName

$acct = Invoke-SIArm -Path $accountId -ApiVersion '2023-01-01' -AllowNotFound
if (-not $acct) { throw ("The storage account '{0}' was not found in resource group '{1}'." -f $StorageAccountName, $ResourceGroupName) }
$state = Get-SIStorageSharedKeyState -Account $acct
$p = $acct.properties
Write-Host ''
Write-Host ('SecurityInsight storage account {0}' -f $StorageAccountName)
Write-Host ('  shared-key access     : {0}' -f $state)
Write-Host ('  Entra ID by default   : {0}' -f $(if ($p.PSObject.Properties['defaultToOAuthAuthentication'] -and $p.defaultToOAuthAuthentication) { 'yes' } else { 'no' }))
Write-Host ('  minimum TLS           : {0}' -f [string]$p.minimumTlsVersion)
Write-Host ('  public blob access    : {0}' -f $(if ($p.PSObject.Properties['allowBlobPublicAccess'] -and $p.allowBlobPublicAccess) { 'allowed' } else { 'off' }))

if ($Enable) {
    if ($state -eq 'On') { Write-Host '  Shared-key access is already on -- nothing to do.'; return [pscustomobject]@{ Account = $StorageAccountName; SharedKeyAccess = 'On'; Changed = $false; Blockers = @() } }
    if (-not $PSCmdlet.ShouldProcess($StorageAccountName, 'switch shared-key access ON')) {
        Write-Host '  -WhatIf: would switch shared-key access back ON (allowSharedKeyAccess = true). Nothing was changed.' -ForegroundColor Yellow
        return [pscustomobject]@{ Account = $StorageAccountName; SharedKeyAccess = $state; Changed = $false; Blockers = @() }
    }
    $null = Invoke-SIArm -Method PATCH -Path $accountId -ApiVersion '2023-01-01' -Body @{ properties = @{ allowSharedKeyAccess = $true } }
    Write-Host '  Shared-key access switched back ON.' -ForegroundColor Yellow
    return [pscustomobject]@{ Account = $StorageAccountName; SharedKeyAccess = 'On'; Changed = $true; Blockers = @() }
}

# ---- what would stop working ----
$end = [DateTime]::UtcNow; $start = $end.AddDays(-$Days)
$metricsPath = '{0}/providers/Microsoft.Insights/metrics?metricnames=Transactions&aggregation=Total&interval=PT1H&timespan={1}/{2}&$filter={3}' -f `
    $accountId, $start.ToString('yyyy-MM-ddTHH:mm:ssZ'), $end.ToString('yyyy-MM-ddTHH:mm:ssZ'), [uri]::EscapeDataString("Authentication eq '*'")
$traffic = $null
try { $traffic = ConvertFrom-SIStorageTransactionMetrics -Response (Invoke-SIArm -Path $metricsPath -ApiVersion '2023-10-01') } catch { Write-Verbose ("metrics: {0}" -f $_.Exception.Message) }
$jobs = @()
try { $jobs = @(Invoke-SIArm -Path ("/subscriptions/$SubscriptionId/providers/Microsoft.App/jobs") -ApiVersion '2025-07-01' -List -AllowNotFound) } catch { Write-Verbose ("jobs: {0}" -f $_.Exception.Message) }
$roles = @()
try { $roles = @(Invoke-SIArm -Path ($accountId + '/providers/Microsoft.Authorization/roleAssignments?$filter=atScope()') -ApiVersion '2022-04-01' -List) } catch { Write-Verbose ("roles: {0}" -f $_.Exception.Message) }

$usedBy = @(Get-SIStorageAccountJobs -Jobs $jobs -AccountName $StorageAccountName)
Write-Host ('  Container Apps jobs using it: {0}' -f $(if ($usedBy.Count) { (@($usedBy | ForEach-Object { [string]$_.name }) -join ', ') } else { 'none found' }))
if ($null -ne $traffic) {
    $parts = @($traffic.Keys | Sort-Object | ForEach-Object { '{0}={1}' -f $_, [int64]$traffic[$_] })
    Write-Host ('  requests in the last {0} day(s) by sign-in: {1}' -f $Days, $(if ($parts.Count) { $parts -join ', ' } else { 'none' }))
}
$blockers = @(Get-SIStorageSharedKeyBlockers -AccountName $StorageAccountName -KeyTraffic $traffic -Days $Days -Jobs $jobs -RoleAssignments $roles)
if ($blockers.Count) {
    Write-Host ''
    Write-Host ('  Still needs a key ({0}):' -f $blockers.Count) -ForegroundColor Yellow
    foreach ($b in $blockers) { Write-Host ('    * {0}: {1}' -f $b.Target, $b.Why); Write-Host ('      fix: {0}' -f $b.Fix) }
} else {
    Write-Host '  Nothing found that still uses a storage key.' -ForegroundColor Green
}

if (-not $Disable) {
    if ($state -eq 'On') { Write-Host ''; Write-Host '  Report only. To switch shared-key access off: .\Set-SIStorageSharedKey.ps1 -Disable' }
    return [pscustomobject]@{ Account = $StorageAccountName; SharedKeyAccess = $state; Changed = $false; Blockers = $blockers }
}
if ($blockers.Count) {
    throw ('Shared-key access was NOT switched off on {0}: {1} thing(s) above still need a key. Fix them and run again.' -f $StorageAccountName, $blockers.Count)
}
if ($state -eq 'Off' -and $p.defaultToOAuthAuthentication) {
    Write-Host '  Shared-key access is already off -- nothing to do.'
    return [pscustomobject]@{ Account = $StorageAccountName; SharedKeyAccess = 'Off'; Changed = $false; Blockers = @() }
}
if (-not $PSCmdlet.ShouldProcess($StorageAccountName, 'switch shared-key access OFF (Entra ID by default)')) {
    Write-Host '  -WhatIf: would switch shared-key access OFF and make Entra ID the default sign-in. Nothing was changed.' -ForegroundColor Yellow
    return [pscustomobject]@{ Account = $StorageAccountName; SharedKeyAccess = $state; Changed = $false; Blockers = @() }
}
$null = Invoke-SIArm -Method PATCH -Path $accountId -ApiVersion '2023-01-01' -Body @{ properties = @{ allowSharedKeyAccess = $false; defaultToOAuthAuthentication = $true } }
Write-Host '  Shared-key access switched OFF; Entra ID is the default sign-in. Way back: .\Set-SIStorageSharedKey.ps1 -Enable' -ForegroundColor Green
return [pscustomobject]@{ Account = $StorageAccountName; SharedKeyAccess = 'Off'; Changed = $true; Blockers = @() }
} finally { Stop-SIScriptRun -Run $siRun }
