#Requires -Version 5.1
<#
    SecurityInsight SETUP -- switching shared-key access OFF on an EXISTING storage account, safely.

    A NEW account is created with shared-key access off (engine/_shared/SI-AzRest.ps1,
    Get-SIStorageAccountCreateProperties). An account created by an older release keeps it on until the operator runs
    setup\Set-SIStorageSharedKey.ps1 -Disable, which first proves nothing still uses a key:

      * the account's own transaction metrics: no request signed with the account key or with a key-signed SAS in the
        last days (a user-delegation SAS is signed in with Entra ID and keeps working, so it does not count);
      * every Container Apps job that uses the account: its queue scaler signs in with a managed identity (no
        connection-string secret, never no sign-in at all), it carries no storage-key secret or setting from an older
        release, and the identity it signs in as holds the Storage Blob / Queue / Table Data Contributor roles.

    Everything here is PURE: the script reads Azure and hands the answers in, so the offline tests run the same
    decisions. Needs container\_shared\SI-ContainerConfig.ps1 (the retired setting / secret names).
    PS 5.1 safe; pwsh 7.
#>

# The data roles a SecurityInsight identity reaches its storage with, by role definition id (the same in every cloud).
# Owner is the wider form of Contributor and is accepted for the same service.
$script:SIStorageDataRoleIds = [ordered]@{
    'Storage Blob Data Contributor'  = @('ba92f5b4-2d11-453d-a403-e96b0029c9fe', 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b')
    'Storage Queue Data Contributor' = @('974c5e8b-45b9-4653-ba55-5f855dd0fb88')
    'Storage Table Data Contributor' = @('0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3')
}

# The kinds of request that stop working when shared-key access is off (the 'Authentication' dimension of the
# storage account's Transactions metric). 'DelegationSas' (a user-delegation SAS) and 'OAuth' keep working.
$script:SIStorageKeyAuthKinds = @('AccountKey', 'SAS')

function ConvertFrom-SIStorageTransactionMetrics {
    <#
        PURE. An Azure Monitor metrics answer for 'Transactions' split by 'Authentication' -> @{ <kind> = <total> }.
        $null in = $null out (the metrics could not be read -- which is NOT the same as "no key traffic").
    #>
    param([AllowNull()][object]$Response)
    if ($null -eq $Response) { return $null }
    $totals = @{}
    foreach ($metric in @($Response.value | Where-Object { $_ })) {
        foreach ($ts in @($metric.timeseries | Where-Object { $_ })) {
            $kind = ''
            foreach ($md in @($ts.metadatavalues | Where-Object { $_ })) {
                if ([string]$md.name.value -ieq 'Authentication') { $kind = [string]$md.value }
            }
            if (-not $kind) { $kind = 'Unknown' }
            $sum = 0.0
            foreach ($pt in @($ts.data | Where-Object { $_ })) {
                if ($pt.PSObject.Properties['total'] -and $null -ne $pt.total) { $sum += [double]$pt.total }
            }
            if ($totals.ContainsKey($kind)) { $totals[$kind] += $sum } else { $totals[$kind] = $sum }
        }
    }
    return $totals
}

function Get-SIJobEnvValue {
    <# PURE. The value of an environment variable on any container of a Container Apps job (name compared without case). #>
    param([object]$Job, [string]$Name)
    foreach ($c in @($Job.properties.template.containers | Where-Object { $_ })) {
        foreach ($e in @($c.env | Where-Object { $_ })) {
            if ([string]$e.name -ieq $Name) { return [string]$e.value }
        }
    }
    return $null
}

function Get-SIStorageAccountJobs {
    <#
        PURE. Of the Container Apps jobs in the subscription, the ones that use -AccountName: SI_StorageAccount names it,
        or a queue scaler reads its queues.
    #>
    param([object[]]$Jobs = @(), [Parameter(Mandatory)][string]$AccountName)
    foreach ($j in @($Jobs | Where-Object { $_ })) {
        $uses = ((Get-SIJobEnvValue -Job $j -Name 'SI_StorageAccount') -ieq $AccountName)
        if (-not $uses) {
            foreach ($r in @($j.properties.configuration.eventTriggerConfig.scale.rules | Where-Object { $_ })) {
                if ([string]$r.metadata.accountName -ieq $AccountName) { $uses = $true }
            }
        }
        if ($uses) { $j }
    }
}

function Get-SIStorageSharedKeyBlockers {
    <#
        PURE. Why shared-key access must NOT be switched off yet: one row per finding, @{ Target; Why; Fix }. Empty = safe.
          -KeyTraffic   ConvertFrom-SIStorageTransactionMetrics output; $null = the metrics could not be read (a blocker:
                        nothing proves the account key is unused).
          -Jobs         Container Apps jobs (ARM JSON); only the ones that use the account are looked at.
          -RoleAssignments  role assignments at the account's scope and above (ARM JSON, $filter=atScope()).
    #>
    param(
        [Parameter(Mandatory)][string]$AccountName,
        [AllowNull()][hashtable]$KeyTraffic,
        [int]$Days = 7,
        [object[]]$Jobs = @(),
        [object[]]$RoleAssignments = @()
    )
    $out = New-Object System.Collections.Generic.List[object]
    $add = { param($t, $w, $f) $out.Add([pscustomobject]@{ Target = $t; Why = $w; Fix = $f }) }

    # 1. The account's own traffic -- the only check that also sees a VM, a script or a tool outside SecurityInsight.
    if ($null -eq $KeyTraffic) {
        & $add $AccountName 'the account''s transaction metrics could not be read, so nothing proves the account key is unused' `
            'sign in with an account that has Monitoring Reader (or Reader) on the storage account, and run again'
    } else {
        foreach ($k in $script:SIStorageKeyAuthKinds) {
            $n = 0.0; if ($KeyTraffic.ContainsKey($k)) { $n = [double]$KeyTraffic[$k] }
            if ($n -gt 0) {
                $what = if ($k -eq 'AccountKey') { 'signed with the account key' } else { 'signed with a key-signed SAS' }
                & $add $AccountName ('{0} request(s) in the last {1} day(s) were {2}' -f [int64]$n, $Days, $what) `
                    'find the caller (storage account -> Insights / the StorageBlobLogs table, AuthenticationType) and move it to its identity, then run again'
            }
        }
    }

    # 2. Every Container Apps job that uses the account.
    $retiredEnv = @(Get-SIRetiredSettingNames | ForEach-Object { ([string]$_ -replace '_', '').ToUpperInvariant() })
    foreach ($j in @(Get-SIStorageAccountJobs -Jobs $Jobs -AccountName $AccountName)) {
        $jn = [string]$j.name
        foreach ($r in @($j.properties.configuration.eventTriggerConfig.scale.rules | Where-Object { $_ })) {
            if ([string]$r.type -ne 'azure-queue' -or [string]$r.metadata.accountName -ine $AccountName) { continue }
            if (@($r.auth | Where-Object { $_ }).Count) {
                & $add $jn ('the queue scaler ''{0}'' signs in with a connection secret (a storage key)' -f [string]$r.name) 'run Bootstrap-ContainerAppJob.ps1 again: the scaler then signs in as the jobs'' managed identity'
            } elseif ([string]::IsNullOrWhiteSpace([string]$r.identity)) {
                & $add $jn ('the queue scaler ''{0}'' has no managed identity to sign in with' -f [string]$r.name) 'run Bootstrap-ContainerAppJob.ps1 again: the scaler then signs in as the jobs'' managed identity'
            }
        }
        foreach ($s in @(Get-SIRetiredJobSecretNames -Job $j)) {
            & $add $jn ('the job still carries the storage-key secret ''{0}'' of an older release' -f $s) 'run Bootstrap-ContainerAppJob.ps1 again: it moves the job to the current release and removes the secret'
        }
        foreach ($c in @($j.properties.template.containers | Where-Object { $_ })) {
            foreach ($e in @($c.env | Where-Object { $_ })) {
                if ($retiredEnv -contains (([string]$e.name -replace '_', '').ToUpperInvariant())) {
                    & $add $jn ('the job still sets ''{0}'' of an older release' -f [string]$e.name) 'run Bootstrap-ContainerAppJob.ps1 again: it replaces the job''s settings'
                }
            }
        }
        # The identity the engine signs in as (the managed identity's principal, or the app's object id).
        $principal = Get-SIJobEnvValue -Job $j -Name 'SI_SPN_OBJECTID'
        if ([string]::IsNullOrWhiteSpace($principal)) { continue }
        $held = @($RoleAssignments | Where-Object { $_ -and [string]$_.properties.principalId -ieq $principal } |
                  ForEach-Object { ([string]$_.properties.roleDefinitionId -split '/')[-1].ToLowerInvariant() })
        foreach ($role in $script:SIStorageDataRoleIds.Keys) {
            if (-not @($script:SIStorageDataRoleIds[$role] | Where-Object { $held -contains $_ }).Count) {
                & $add $jn ('the identity it signs in as ({0}) does not hold {1} on the account' -f $principal, $role) `
                    'run Bootstrap-ContainerAppJob.ps1 -GrantIdentityRoles (container) or setup\Grant-SIIdentity.ps1 -Apply, then run again'
            }
        }
    }
    return $out.ToArray()
}

function Get-SIStorageSharedKeyState {
    <# PURE. 'Off' / 'On' from the account's properties -- an account that never set allowSharedKeyAccess allows it. #>
    param([Parameter(Mandatory)][object]$Account)
    $p = $Account.properties
    if ($p -and $p.PSObject.Properties['allowSharedKeyAccess'] -and $null -ne $p.allowSharedKeyAccess -and -not [bool]$p.allowSharedKeyAccess) { return 'Off' }
    return 'On'
}
