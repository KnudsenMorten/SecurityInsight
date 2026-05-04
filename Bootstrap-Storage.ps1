#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.Resources, Az.Storage
<#
    SecurityInsight v2.2 -- one-shot Azure Storage bootstrap.

    Idempotent. Run once per customer to provision the v2.2 transient-state
    backend in their Azure subscription:

      * Storage account (Standard_LRS, Hot)
      * Table  : sifingerprint  (fingerprint cache)
      * Blob   : sistaging      (stage payload shards)
      * Lifecycle rule          (auto-delete blobs in staging/ after 7 days)
      * Queues : si-<engine>-discover / -collect / -enrich / -classify
                 (created for endpoint by default; identity / azure on demand)

    Outputs the storage account key. Paste into config/SecurityInsight.custom.ps1:
        $global:SI_StorageAccount = 'st2linkitsi'
        $global:SI_StorageKey     = '<the printed key>'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$StorageAccountName,
    [Parameter()][string]$Location = 'westeurope',
    [Parameter()][string[]]$Engines = @('endpoint'),
    [Parameter()][int]$StagingBlobRetentionDays = 7
)

$ErrorActionPreference = 'Stop'

Write-Host ''
Write-Host '=== SecurityInsight v2.2 Storage bootstrap ==='
Write-Host ('  Subscription : {0}' -f (Get-AzContext).Subscription.Name)
Write-Host ('  RG           : {0}' -f $ResourceGroupName)
Write-Host ('  Storage acct : {0}' -f $StorageAccountName)
Write-Host ('  Location     : {0}' -f $Location)
Write-Host ''

# ---- 1. Storage account ----
$sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-not $sa) {
    Write-Host '[1/5] Creating storage account ...'
    $sa = New-AzStorageAccount `
        -ResourceGroupName $ResourceGroupName `
        -Name $StorageAccountName `
        -Location $Location `
        -SkuName Standard_LRS `
        -Kind StorageV2 `
        -AccessTier Hot `
        -MinimumTlsVersion TLS1_2 `
        -AllowBlobPublicAccess $false
    Write-Host ('       created ({0})' -f $sa.PrimaryEndpoints.Blob)
} else {
    Write-Host ('[1/5] Storage account already exists -- reusing.')
}

$ctx = $sa.Context

# ---- 2. Fingerprint table ----
Write-Host '[2/5] Ensuring table sifingerprint ...'
$existingTable = Get-AzStorageTable -Name 'sifingerprint' -Context $ctx -ErrorAction SilentlyContinue
if (-not $existingTable) {
    New-AzStorageTable -Name 'sifingerprint' -Context $ctx | Out-Null
    Write-Host '       created.'
} else {
    Write-Host '       exists -- reusing.'
}

# ---- 3. Staging container ----
Write-Host '[3/5] Ensuring blob container sistaging ...'
$existingContainer = Get-AzStorageContainer -Name 'sistaging' -Context $ctx -ErrorAction SilentlyContinue
if (-not $existingContainer) {
    New-AzStorageContainer -Name 'sistaging' -Context $ctx -Permission Off | Out-Null
    Write-Host '       created.'
} else {
    Write-Host '       exists -- reusing.'
}

# ---- 4. Lifecycle rule ----
# idempotent. Get-AzStorageAccountManagementPolicy + check whether
# our 'si-staging-7day-delete' rule is already present with the right retention
# days; only Set when missing or the day count drifted. Avoids the nightly-
# noise pattern where every Bootstrap re-run rewrites the policy with a fresh
# timestamp.
Write-Host ('[4/5] Ensuring lifecycle rule (delete sistaging/staging/* after {0} days) ...' -f $StagingBlobRetentionDays)
$action = Add-AzStorageAccountManagementPolicyAction `
    -BaseBlobAction Delete `
    -DaysAfterModificationGreaterThan $StagingBlobRetentionDays
$filter = New-AzStorageAccountManagementPolicyFilter `
    -PrefixMatch 'sistaging/staging/' `
    -BlobType blockBlob
$rule = New-AzStorageAccountManagementPolicyRule `
    -Name 'si-staging-7day-delete' `
    -Action $action `
    -Filter $filter

$existingPolicy = Get-AzStorageAccountManagementPolicy -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ErrorAction SilentlyContinue
$existingRule   = if ($existingPolicy) { $existingPolicy.Rules | Where-Object { $_.Name -eq 'si-staging-7day-delete' } | Select-Object -First 1 } else { $null }
$existingDays   = if ($existingRule) { $existingRule.Definition.Actions.BaseBlob.Delete.DaysAfterModificationGreaterThan } else { $null }

if ($existingRule -and $existingDays -eq $StagingBlobRetentionDays) {
    Write-Host '       exists with matching retention -- no change.'
} else {
    Set-AzStorageAccountManagementPolicy `
        -ResourceGroupName $ResourceGroupName `
        -StorageAccountName $StorageAccountName `
        -Rule $rule | Out-Null
    Write-Host '       applied.'
}

# ---- 5. Queues ----
Write-Host '[5/5] Ensuring queues ...'
foreach ($engine in $Engines) {
    foreach ($stage in @('discover','collect','enrich','classify')) {
        $qName = "si-$engine-$stage"
        $existing = Get-AzStorageQueue -Name $qName -Context $ctx -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-AzStorageQueue -Name $qName -Context $ctx | Out-Null
            Write-Host ('       + {0}' -f $qName)
        } else {
            Write-Host ('       = {0} (exists)' -f $qName)
        }
    }
}

# ---- Output keys ----
$keys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
$primaryKey = $keys[0].Value

Write-Host ''
Write-Host '=== DONE -- paste these into config/SecurityInsight.custom.ps1 ==='
Write-Host ''
Write-Host ('$global:SI_StorageAccount = ''{0}''' -f $StorageAccountName)
Write-Host ('$global:SI_StorageKey     = ''{0}''' -f $primaryKey)
Write-Host ''

# Return as a hashtable so callers can pipe / capture
[pscustomobject]@{
    StorageAccountName = $StorageAccountName
    ResourceGroupName  = $ResourceGroupName
    Key                = $primaryKey
    BlobEndpoint       = $sa.PrimaryEndpoints.Blob
    TableEndpoint      = $sa.PrimaryEndpoints.Table
    QueueEndpoint      = $sa.PrimaryEndpoints.Queue
}
