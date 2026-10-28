#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- one-shot Azure Storage bootstrap.

    Idempotent. Run once per customer to provision the v2.2 transient-state
    backend in their Azure subscription:

      * Storage account (Standard_LRS, Hot; created with shared-key access OFF, Entra ID by default,
                         TLS 1.2, no public blob access -- an existing account is reused as it is)
      * Table  : sifingerprint  (fingerprint cache)
      * Blob   : sistaging      (stage payload shards)
      * Lifecycle rule          (auto-delete blobs in staging/ after 7 days)
      * Queues : si-<engine>-discover / -collect / -enrich / -classify
                 (created for endpoint by default; identity / azure on demand)

    Storage is reached only with the engine's signed-in identity: set in config/SecurityInsight.custom.ps1
        $global:SI_StorageAccount = '<storage-account-name>'
    and grant the engine identity the Storage Blob/Queue/Table Data Contributor roles on the account.

    The lifecycle rule is MERGED into the account's existing management policy -- other rules on
    the account are kept.

    No PowerShell modules: the account, table, container, queues and lifecycle policy are managed
    through Azure Resource Manager over plain REST (setup\_shared\SI-SetupAzure.ps1), so no storage
    data-plane role is needed to set it up, and no account key is ever read. You are signed in by this
    script when needed -- automatically in Azure Cloud Shell, otherwise in the browser.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$StorageAccountName,
    [Parameter()][string]$Location = 'westeurope',
    [Parameter()][string[]]$Engines = @('endpoint'),
    [Parameter()][int]$StagingBlobRetentionDays = 7,
    # The tenant and subscription to work in. Both optional: a sign-in already made in this
    # PowerShell session is reused, and its subscription is used when none is given.
    [Parameter()][string]$TenantId,
    [Parameter()][string]$SubscriptionId
)

$ErrorActionPreference = 'Stop'

. ([IO.Path]::Combine($PSScriptRoot, 'setup', '_shared', 'SI-SetupAzure.ps1'))
$azCtx = Connect-SISetupAzure -TenantId $TenantId -SubscriptionId $SubscriptionId
if (-not $azCtx -or -not $azCtx.Subscription) {
    throw 'No Azure subscription is selected. Run the same command again with -SubscriptionId <subscription id>.'
}

Write-Host ''
Write-Host '=== SecurityInsight v2.2 Storage bootstrap ==='
Write-Host ('  Subscription : {0}' -f $azCtx.Subscription.Name)
Write-Host ('  RG           : {0}' -f $ResourceGroupName)
Write-Host ('  Storage acct : {0}' -f $StorageAccountName)
Write-Host ('  Location     : {0}' -f $Location)
Write-Host ''

# ---- 1. Storage account ----
$sa = Get-SIAzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-not $sa) {
    Write-Host '[1/5] Creating storage account ...'
    # StorageV2 accounts default to the Hot access tier. Created with shared-key access OFF: storage is reached with
    # the signed-in identity only.
    $sa = New-SIAzStorageAccount `
        -ResourceGroupName $ResourceGroupName `
        -Name $StorageAccountName `
        -Location $Location `
        -SkuName Standard_LRS `
        -Kind StorageV2 `
        -MinimumTlsVersion TLS1_2 `
        -AllowBlobPublicAccess $false
    Write-Host ('       created ({0})' -f $sa.PrimaryEndpoints.Blob)
} else {
    Write-Host ('[1/5] Storage account already exists -- reusing.')
}

# Table, container and queues are created through Azure Resource Manager (idempotent PUTs) -- no
# storage data-plane role and no account key are needed for setup.
$armChild = @{ ResourceGroupName = $ResourceGroupName; AccountName = $StorageAccountName }

# ---- 2. Fingerprint table ----
Write-Host '[2/5] Ensuring table sifingerprint ...'
$existingTable = Get-SIStorageArmChild @armChild -Kind Table -Name 'sifingerprint' -ErrorAction SilentlyContinue
if (-not $existingTable) {
    New-SIStorageArmChild @armChild -Kind Table -Name 'sifingerprint' | Out-Null
    Write-Host '       created.'
} else {
    Write-Host '       exists -- reusing.'
}

# ---- 3. Staging container ----
Write-Host '[3/5] Ensuring blob container sistaging ...'
$existingContainer = Get-SIStorageArmChild @armChild -Kind Container -Name 'sistaging' -ErrorAction SilentlyContinue
if (-not $existingContainer) {
    # a private container (no public access)
    New-SIStorageArmChild @armChild -Kind Container -Name 'sistaging' | Out-Null
    Write-Host '       created.'
} else {
    Write-Host '       exists -- reusing.'
}

# ---- 4. Lifecycle rule ----
# idempotent. Read the account's management policy + check whether
# our 'si-staging-7day-delete' rule is already present with the right retention
# days; only Set when missing or the day count drifted. Avoids the nightly-
# noise pattern where every Bootstrap re-run rewrites the policy with a fresh
# timestamp.
Write-Host ('[4/5] Ensuring lifecycle rule (delete sistaging/staging/* after {0} days) ...' -f $StagingBlobRetentionDays)
$rule = New-SIStorageLifecycleDeleteRule `
    -Name 'si-staging-7day-delete' `
    -PrefixMatch 'sistaging/staging/' `
    -DaysAfterModification $StagingBlobRetentionDays

$existingPolicy = Get-SIStorageLifecyclePolicy @armChild
$existingRule   = if ($existingPolicy) { $existingPolicy.Rules | Where-Object { $_.name -eq 'si-staging-7day-delete' } | Select-Object -First 1 } else { $null }
$existingDays   = if ($existingRule) { Get-SIStorageLifecycleRuleDeleteDays -Rule $existingRule } else { $null }

if ($existingRule -and $existingDays -eq $StagingBlobRetentionDays) {
    Write-Host '       exists with matching retention -- no change.'
} else {
    # Writing the policy REPLACES the whole policy. Passing only our rule deleted
    # every other lifecycle rule on the account -- a customer's own retention rules included. Keep
    # them: our rule is swapped in by name, everything else is written back unchanged.
    $otherRules = @()
    if ($existingPolicy -and $existingPolicy.Rules) {
        $otherRules = @($existingPolicy.Rules | Where-Object { $_.name -ne 'si-staging-7day-delete' })
    }
    Set-SIStorageLifecyclePolicy @armChild `
        -Rules (@($otherRules) + @($rule)) | Out-Null
    Write-Host ('       applied ({0} other rule(s) on the account kept).' -f $otherRules.Count)
}

# ---- 5. Queues ----
Write-Host '[5/5] Ensuring queues ...'
foreach ($engine in $Engines) {
    foreach ($stage in @('discover','collect','enrich','classify')) {
        $qName = "si-$engine-$stage"
        $existing = Get-SIStorageArmChild @armChild -Kind Queue -Name $qName -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-SIStorageArmChild @armChild -Kind Queue -Name $qName | Out-Null
            Write-Host ('       + {0}' -f $qName)
        } else {
            Write-Host ('       = {0} (exists)' -f $qName)
        }
    }
}

# ---- Output ----
Write-Host ''
Write-Host '=== DONE -- set this in config/SecurityInsight.custom.ps1 ==='
Write-Host ''
Write-Host ('$global:SI_StorageAccount = ''{0}''' -f $StorageAccountName)
Write-Host '(Storage is reached with the engine identity -- grant it the Storage Blob/Queue/Table Data Contributor roles on this account.)'
Write-Host ''

# Return as an object so callers can pipe / capture
[pscustomobject]@{
    StorageAccountName = $StorageAccountName
    ResourceGroupName  = $ResourceGroupName
    BlobEndpoint       = $sa.PrimaryEndpoints.Blob
    TableEndpoint      = $sa.PrimaryEndpoints.Table
    QueueEndpoint      = $sa.PrimaryEndpoints.Queue
}
