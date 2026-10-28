<#
.SYNOPSIS
    SecurityInsight: encrypts ONE existing install's data with the customer's own key -- the Pro database (TDE), the
    storage account and (optionally) Log Analytics -- through the Invardia Support app. Microsoft-managed keys stay the
    default; this is the customer's choice.

.DESCRIPTION
    A NEW install gets customer-managed keys from setup when it asks for them (customerManagedKeys in the guided install).
    An EXISTING install moves by this scripted cut-over, one environment at a time, inside that environment's Support
    session (the pattern of setup\_shared\SI-SupportCutover.ps1; the library is setup\_shared\SI-CustomerKeys.ps1).

    PLAN BY DEFAULT: prints the install's shape and what each step WOULD change. Nothing is changed.
      -Apply -Steps <list>   makes exactly those steps (in this order; each idempotent, each change read back):
        proof              read-only: the vault, the key, the resources the jobs name, their encryption today
        vault-protection   soft delete + purge protection ON for the key's vault -- Azure requires it. ONE-WAY.
        key                the key (-KeyName, default si-data) in the vault (-KeyVaultId, default the install's own):
                           created when it is not there (RSA 3072, rotated every year by Key Vault). Never removed.
        identity           the managed identity id-si-keys that uses the key
        key-access         that identity: "Key Vault Crypto Service Encryption User" on the KEY only
        storage            the storage account encrypted with the key (versionless: new versions are used automatically)
        sql                the database server's TDE protector = the key, automatic rotation on (every database on it)
        log-analytics      the workspace linked to a dedicated Log Analytics cluster with the key: -LogAnalytics
                           cluster-existing -ClusterId <id> (the customer's cluster), or cluster-new (a cluster with a
                           100 GB a day commitment, made in the install's resource group -- Azure takes up to two hours:
                           run the step again later to link). Data from before the link keeps Microsoft's keys.
      -Rollback <record> -Apply   back to Microsoft-managed keys (storage, database server; the workspace unlinked), the
                           access and the identity this run created removed. The key is KEPT (data and backups may be
                           encrypted with it); purge protection stays on (one-way); a cluster this run made is removed
                           only when no workspace is linked to it.
    ONE rollback record per run: a JSON file here and a short copy in the install (cfg.InstallState 'CustomerKeysCutover').
    After -Apply the script waits -ObserveMinutes (default 6), then counts the install's runs since the cut-over and the
    failures.

    Key rotation: docs/DESIGN.md, "Customer-managed keys".

.EXAMPLE
    . C:\claude-sessions\Invardia\tools\Connect-InvardiaSupport.ps1 -Environment <handle> -Reason 'customer-managed keys'
    .\Set-SICustomerManagedKeys.ps1 -ResourceGroup <rg>
    .\Set-SICustomerManagedKeys.ps1 -ResourceGroup <rg> -Apply -Steps vault-protection,key,identity,key-access
    .\Set-SICustomerManagedKeys.ps1 -ResourceGroup <rg> -Apply -Steps storage,sql
    .\Set-SICustomerManagedKeys.ps1 -ResourceGroup <rg> -LogAnalytics cluster-existing -ClusterId <id> -Apply -Steps log-analytics
    .\Set-SICustomerManagedKeys.ps1 -Rollback <record.json> -Apply

.LINK
    https://invardia.com/docs/si/scripts/Set-SICustomerManagedKeys/
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup,
    [string]$SubscriptionId,
    # the vault that holds the key (resource id); default: the install's own Key Vault
    [string]$KeyVaultId = '',
    [string]$KeyName = '',
    [ValidateSet('off', 'cluster-new', 'cluster-existing')][string]$LogAnalytics = 'off',
    [string]$ClusterId = '',
    [switch]$Apply,
    [string[]]$Steps = @(),
    [string]$Rollback = '',
    # overrides when the jobs do not name them (never guessed from a name pattern)
    [string]$KeyVaultName = '',
    [string]$StorageAccountName = '',
    [string]$SqlServerName = '',
    [string]$WorkspaceResourceId = '',
    [string]$Reason = 'SecurityInsight customer-managed keys',
    [string]$Environment = '',
    [string]$RecordDirectory = '',
    [ValidateRange(0, 30)][int]$ObserveMinutes = 6,
    [scriptblock]$Arm, [scriptblock]$Sql, [scriptblock]$Graph,
    [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }
)

$ErrorActionPreference = 'Stop'
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportCutover.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-PrivateNetwork.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-CustomerKeys.ps1'))
$script:SICmkSteps = @('proof', 'vault-protection', 'key', 'identity', 'key-access', 'storage', 'sql', 'log-analytics')

function Write-SICmkLine { param([string]$Text, [string]$Color = 'Gray') Write-Host $Text -ForegroundColor $Color }

$seams = New-SICutoverSeams -Arm $Arm -Sql $Sql -Graph $Graph -Reason $Reason
$A = $seams.Arm
$sess = $null; if (Get-Command -Name Get-SISupportSession -ErrorAction SilentlyContinue) { try { $sess = Get-SISupportSession } catch { $sess = $null } }
if (-not $Environment) { $Environment = if ($sess -and [string]$sess.Environment) { [string]$sess.Environment } else { 'environment' } }
if (-not $RecordDirectory) { $RecordDirectory = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'si', 'logs', 'cutover') }

function Remove-SICmkCreated {
    param([string]$Id, [string]$Api, [string]$Label)
    if (-not $Id) { return '' }
    $p = '{0}?api-version={1}' -f $Id, $Api
    try {
        $null = & $A 'DELETE' $p $null
        $gone = Read-SICmkBack -Arm $A -Path $p -Sleep $Sleep -Tries 12 -PauseSeconds 10 -Test { param($o) $null -eq $o }
        if ($null -eq $gone) { return ('{0} {1} removed (read back)' -f $Label, ($Id -split '/')[-1]) } else { return ('{0} {1} is still there' -f $Label, ($Id -split '/')[-1]) }
    } catch { return ('{0} {1} could not be removed: {2}' -f $Label, ($Id -split '/')[-1], $_.Exception.Message) }
}

# ---------------------------------------------------------------------------------------------------- ROLLBACK
if ($Rollback.Trim()) {
    $rb = [IO.File]::ReadAllText($Rollback) | ConvertFrom-Json
    Write-SICmkLine ('== ROLLBACK of {0} ({1}) from {2} -- applied: {3}' -f $rb.environment, $rb.resourceGroup, $Rollback, (@($rb.applied) -join ', ')) 'Yellow'
    if (-not $Apply) { Write-SICmkLine 'PLAN ONLY -- nothing was changed. Add -Apply to put the recorded values back.' 'Yellow'; return [pscustomobject]@{ Mode = 'rollback-plan'; Results = @() } }
    $results = New-Object System.Collections.Generic.List[object]
    $order = @($rb.applied); [array]::Reverse($order)
    foreach ($step in $order) {
        $b = $rb.before.$step
        $lines = New-Object System.Collections.Generic.List[string]; $ok = $true
        try {
            switch ([string]$step) {
                'storage' { $x = Set-SIStorageCustomerKey -Arm $A -StorageAccountId ([string]$b.storageAccountId) -Restore -Sleep $Sleep; $lines.Add($x.Line); $ok = $x.Ok }
                'sql' { $x = Set-SISqlCustomerKey -Arm $A -ServerId ([string]$b.serverId) -Restore -Sleep $Sleep; foreach ($l in $x.Lines) { $lines.Add($l) }; $ok = $x.Ok }
                'log-analytics' {
                    if ([bool]$b.linked) { $x = Set-SILogAnalyticsCustomerKey -Arm $A -WorkspaceId ([string]$b.workspaceId) -Restore -Sleep $Sleep; foreach ($l in $x.Lines) { $lines.Add($l) }; $ok = $x.Ok }
                    if ([string]$b.clusterCreated) {
                        $links = @(Get-SIPnArmList -Arm $A -Path ('{0}/workspaces?api-version={1}' -f [string]$b.clusterCreated, $script:SICmkLawApi))
                        if ($links.Count) { $lines.Add(('the cluster {0} still has linked workspaces -- it is not removed' -f ([string]$b.clusterCreated -split '/')[-1])) }
                        else { $lines.Add((Remove-SICmkCreated -Id ([string]$b.clusterCreated) -Api $script:SICmkLawApi -Label 'Log Analytics cluster')) }
                    }
                }
                'key-access' { if ([string]$b.assignmentCreated) { $lines.Add((Remove-SICmkCreated -Id ([string]$b.assignmentCreated) -Api $script:SICmkAuthApi -Label 'role assignment')) } else { $lines.Add('nothing this run made') } }
                'identity' { if ([string]$b.created) { $lines.Add((Remove-SICmkCreated -Id ([string]$b.created) -Api $script:SICmkMiApi -Label 'identity')) } else { $lines.Add('nothing this run made') } }
                'key' { $lines.Add('the key is KEPT: data and backups may be encrypted with it (remove it by hand only when nothing uses it)') }
                'vault-protection' { $lines.Add('purge protection is ONE-WAY: Azure never turns it off -- nothing to put back') }
                default { $ok = $false; $lines.Add('not a step of this script') }
            }
        } catch { $ok = $false; $lines.Add(('rollback FAILED: {0}' -f $_.Exception.Message)) }
        foreach ($l in @($lines | Where-Object { $_ })) { Write-SICmkLine ('{0,-17} {1}' -f $step, $l) $(if ($ok) { 'Green' } else { 'Red' }) }
        $results.Add([pscustomobject]@{ Step = [string]$step; Ok = [bool]$ok; Lines = @($lines | Where-Object { $_ }) })
    }
    return [pscustomobject]@{ Mode = 'rollback'; Results = $results.ToArray() }
}

# ---------------------------------------------------------------------------------------------------- SHAPE
if (-not $ResourceGroup) { throw 'Give -ResourceGroup: the install''s resource group (where its jobs are).' }
if (-not $SubscriptionId) { $SubscriptionId = if ($sess) { [string]$sess.SubscriptionId } else { '' } }
if (-not $SubscriptionId) { throw 'Give -SubscriptionId: the Support session names no subscription.' }
$want = @(Resolve-SICutoverSteps -Steps $Steps -Known $script:SICmkSteps)
if ($Apply -and -not $want.Count) { throw ('-Apply needs -Steps: name the steps to make ({0}). Nothing was changed.' -f ($script:SICmkSteps -join ', ')) }
if ($LogAnalytics -eq 'cluster-existing' -and -not $ClusterId) { throw '-LogAnalytics cluster-existing needs -ClusterId (the cluster''s resource id). Nothing was changed.' }

$shape = Get-SIInstallShape -Arm $A -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -SqlServerName $SqlServerName -FindSqlInResourceGroup
if (-not @($shape.Jobs).Count) { throw ('No Container Apps job was found in {0} (subscription {1}) -- is this the install''s resource group? Nothing was changed.' -f $ResourceGroup, $SubscriptionId) }
Write-SICmkLine ('== {0}' -f $Environment) 'Cyan'
foreach ($l in (Format-SIInstallShape -Shape $shape)) { Write-SICmkLine ('   ' + $l) $(if ($l -like 'NOT READ*') { 'Yellow' } else { 'Gray' }) }
$rgId = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup
$all = @($shape.Jobs) + @($shape.Apps)
function Find-SICmkOne {
    param([string]$Type, [string]$Api, [string]$Name)
    if ($Name) { return (& $A 'GET' ('{0}/providers/{1}/{2}?api-version={3}' -f $rgId, $Type, $Name, $Api) $null) }
    $l = @(Get-SIPnArmList -Arm $A -Path ('{0}/providers/{1}?api-version={2}' -f $rgId, $Type, $Api))
    if ($l.Count -eq 1) { return $l[0] }
    $null
}
$ownVault = Find-SICmkOne -Type 'Microsoft.KeyVault/vaults' -Api $script:SICmkKvApi -Name $(if ($KeyVaultName) { $KeyVaultName } else { $shape.KeyVaultName })
$vaultId = if ($KeyVaultId) { $KeyVaultId.TrimEnd('/') } else { [string](Get-SICmkProp $ownVault @('id')) }
$stN = if ($StorageAccountName) { $StorageAccountName } else { Get-SICutoverEnv -Resources $all -Name 'SI_StorageAccount' }
$storage = Find-SICmkOne -Type 'Microsoft.Storage/storageAccounts' -Api $script:SICmkStApi -Name $stN
$wsId = if ($WorkspaceResourceId) { $WorkspaceResourceId } else { [string]$shape.WorkspaceResourceId }
$location = [string](Get-SICmkProp @($shape.Jobs)[0] @('location'))

$plan = [ordered]@{}
$t = $null; $vault = $null; $key = $null
if (-not $vaultId) { foreach ($s in 'vault-protection', 'key', 'key-access', 'storage', 'sql', 'log-analytics') { $plan[$s] = @{ Action = 'skip'; Reason = 'the install''s Key Vault was not found (give -KeyVaultName, or -KeyVaultId for another vault)' } } }
else {
    $t = Get-SICustomerKeyTarget -KeyVaultId $vaultId -KeyName $KeyName
    $vault = & $A 'GET' ('{0}?api-version={1}' -f $t.VaultId, $script:SICmkKvApi) $null
    $vd = Get-SICmkVaultDecision -Vault $vault
    $plan['vault-protection'] = @{ Action = $(switch ($vd.Action) { 'protect' { 'change' } 'fail' { 'skip' } default { 'none' } }); Reason = $vd.Reason }
    $key = & $A 'GET' ('{0}?api-version={1}' -f $t.KeyId, $script:SICmkKvApi) $null
    $plan['key'] = @{ Action = $(if ($key) { 'none' } else { 'change' }); Reason = $(if ($key) { 'the key {0} in {1} is used as it is' -f $t.KeyName, $t.VaultName } else { 'the key {0} is created in {1} (RSA 3072, rotated every year)' -f $t.KeyName, $t.VaultName }) }
}
$idName = (Get-SICustomerKeyNames).Identity
$idId = '{0}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{1}' -f $rgId, $idName
$ident = & $A 'GET' ('{0}?api-version={1}' -f $idId, $script:SICmkMiApi) $null
$plan['identity'] = @{ Action = $(if ($ident) { 'none' } else { 'change' }); Reason = $(if ($ident) { 'the identity {0} is there' -f $idName } else { 'the identity {0} is made in the install''s resource group' -f $idName }) }
if ($t) {
    $plan['key-access'] = @{ Action = 'change'; Reason = ('{0}: Key Vault Crypto Service Encryption User on the key {1} only (kept when it is there)' -f $idName, $t.KeyName) }
    if ($storage) { $plan['storage'] = @{ Action = $(if (Test-SIStorageCustomerKey -Account $storage -VaultUri $t.VaultUri -KeyName $t.KeyName) { 'none' } else { 'change' }); Reason = ('storage account {0}: today {1}' -f [string]$storage.name, [string](Get-SICmkProp $storage @('properties', 'encryption', 'keySource'))) } }
    else { $plan['storage'] = @{ Action = 'skip'; Reason = 'the install''s storage account was not found (give -StorageAccountName)' } }
    if ($shape.SqlServerId) {
        $prot = & $A 'GET' ('{0}/encryptionProtector/current?api-version={1}' -f $shape.SqlServerId, $script:SICmkSqlApi) $null
        $plan['sql'] = @{ Action = $(if (Test-SISqlCustomerKey -Protector $prot -VaultName $t.VaultName -KeyName $t.KeyName) { 'none' } else { 'change' }); Reason = ('database server {0}: today {1}' -f ($shape.SqlServerId -split '/')[-1], $(if ($prot) { [string](Get-SICmkProp $prot @('properties', 'serverKeyType')) } else { 'unknown' })) }
    } else { $plan['sql'] = @{ Action = 'skip'; Reason = 'no database server (Community, or give -SqlServerName)' } }
    if ($LogAnalytics -eq 'off') { $plan['log-analytics'] = @{ Action = 'skip'; Reason = 'Log Analytics keeps Microsoft''s keys (-LogAnalytics cluster-existing -ClusterId <id>, or cluster-new: a dedicated cluster, a 100 GB a day commitment)' } }
    elseif (-not $wsId) { $plan['log-analytics'] = @{ Action = 'skip'; Reason = 'no job names the install''s workspace (give -WorkspaceResourceId)' } }
    else { $plan['log-analytics'] = @{ Action = 'change'; Reason = ('workspace {0} linked to {1}' -f ($wsId -split '/')[-1], $(if ($LogAnalytics -eq 'cluster-new') { 'a new cluster ' + (Get-SICustomerKeyNames).Cluster + ' (100 GB a day commitment; up to two hours)' } else { 'the cluster ' + ($ClusterId -split '/')[-1] })) } }
}
foreach ($k in @($script:SICmkSteps | Where-Object { $plan.Contains($_) })) {
    $d = $plan[$k]
    $what = switch ([string]$d.Action) { 'none' { 'nothing to do' } 'skip' { 'SKIPPED' } default { 'WOULD CHANGE' } }
    Write-SICmkLine ('{0,-17} {1}: {2}' -f $k, $what, $d.Reason) $(switch ([string]$d.Action) { 'none' { 'DarkGray' } 'skip' { 'Yellow' } default { 'White' } })
}
if (-not $Apply) {
    Write-SICmkLine ('PLAN ONLY -- nothing was changed. Apply: -Apply -Steps <{0}>' -f ($script:SICmkSteps[1..($script:SICmkSteps.Count - 1)] -join ',')) 'Yellow'
    return [pscustomobject]@{ Mode = 'plan'; Shape = $shape; Plan = $plan; RecordPath = $null; Results = @() }
}

# ---------------------------------------------------------------------------------------------------- APPLY
$started = [datetime]::UtcNow
$record = New-SICutoverRecord -Script 'Set-SICustomerManagedKeys' -Environment $Environment -Shape $shape -Now $started
$recPath = Get-SICutoverRecordPath -Directory $RecordDirectory -Script 'Set-SICustomerManagedKeys' -Environment $Environment -Now $started
$script:SICmkSaved = $null
$save = { $script:SICmkSaved = Save-SICutoverRecord -Record $record -Path $recPath -Sql $seams.Sql -StateName 'CustomerKeysCutover' }
$results = New-Object System.Collections.Generic.List[object]
foreach ($k in $want) {
    if ($k -eq 'proof') { continue }
    $d = $plan[$k]
    if ([string]$d.Action -in 'none', 'skip') { Write-SICmkLine ('{0,-17} nothing to do: {1}' -f $k, $d.Reason) 'DarkGray'; continue }
    $lines = New-Object System.Collections.Generic.List[string]; $ok = $true
    try {
        $bf = [ordered]@{}; $record.before[$k] = $bf; $record.applied = @($record.applied) + @($k); & $save
        # the pieces a step needs from the steps before it are READ here (a step run on its own finds them as they are)
        $needKey = { $kk = & $A 'GET' ('{0}?api-version={1}' -f $t.KeyId, $script:SICmkKvApi) $null; if (-not $kk) { throw ('the key {0} is not there -- run the key step first' -f $t.KeyName) }; $kk }
        $needId = { $ii = & $A 'GET' ('{0}?api-version={1}' -f $idId, $script:SICmkMiApi) $null; if (-not $ii) { throw ('the identity {0} is not there -- run the identity step first' -f $idName) }; $ii }
        switch ($k) {
            'vault-protection' { $bf['vaultId'] = $t.VaultId; $bf['oneWay'] = $true; & $save; $x = Set-SICmkVaultProtection -Arm $A -VaultId $t.VaultId -Sleep $Sleep; $lines.Add($x.Line); $ok = $x.Ok }
            'key' {
                $vv = & $A 'GET' ('{0}?api-version={1}' -f $t.VaultId, $script:SICmkKvApi) $null
                if ((Get-SICmkVaultDecision -Vault $vv).Action -ne 'none') { throw 'the vault''s purge protection is off -- run vault-protection first (Azure requires it for a customer-managed key)' }
                $x = Set-SICustomerKey -Arm $A -Target $t -Sleep $Sleep; $bf['created'] = [bool]$x.Created; $bf['keyUri'] = $x.KeyUri; & $save; $lines.Add($x.Line); $ok = $x.Ok
            }
            'identity' { $x = Set-SICustomerKeyIdentity -Arm $A -ResourceGroupId $rgId -Location $location -Sleep $Sleep; if ($x.Created) { $bf['created'] = $x.Id; & $save }; $lines.Add($x.Line); $ok = $x.Ok }
            'key-access' {
                $null = & $needKey; $ii = & $needId
                $x = Set-SICustomerKeyAccess -Arm $A -KeyId $t.KeyId -PrincipalId ([string]$ii.properties.principalId) -SubscriptionId $SubscriptionId -Sleep $Sleep
                if ($x.Created) { $bf['assignmentCreated'] = $x.AssignmentId; & $save }; $lines.Add($x.Line); $ok = $x.Ok
            }
            'storage' {
                $null = & $needKey; $null = & $needId
                $bf['storageAccountId'] = [string]$storage.id; $bf['keySource'] = [string](Get-SICmkProp $storage @('properties', 'encryption', 'keySource')); & $save
                $x = Set-SIStorageCustomerKey -Arm $A -StorageAccountId ([string]$storage.id) -IdentityId $idId -VaultUri $t.VaultUri -KeyName $t.KeyName -Sleep $Sleep; $lines.Add($x.Line); $ok = $x.Ok
            }
            'sql' {
                $kk = & $needKey; $null = & $needId
                $bf['serverId'] = [string]$shape.SqlServerId; & $save
                $x = Set-SISqlCustomerKey -Arm $A -ServerId ([string]$shape.SqlServerId) -IdentityId $idId -KeyUriWithVersion ([string]$kk.properties.keyUriWithVersion) -VaultName $t.VaultName -KeyName $t.KeyName -Sleep $Sleep
                foreach ($l in $x.Lines) { $lines.Add($l) }; $ok = $x.Ok
            }
            'log-analytics' {
                $null = & $needKey; $null = & $needId
                $bf['workspaceId'] = $wsId; $bf['linked'] = $false; $bf['clusterCreated'] = ''; & $save
                $x = Set-SILogAnalyticsCustomerKey -Arm $A -WorkspaceId $wsId -ClusterId $ClusterId -Create:($LogAnalytics -eq 'cluster-new') -ResourceGroupId $rgId -Location $location -IdentityId $idId -VaultUri $t.VaultUri -KeyName $t.KeyName -Sleep $Sleep
                if ($x.Created) { $bf['clusterCreated'] = $x.ClusterId }
                if ($x.Ok -and -not $x.Pending) { $bf['linked'] = $true }
                & $save; foreach ($l in $x.Lines) { $lines.Add($l) }; $ok = $x.Ok
            }
        }
    } catch { $ok = $false; $lines.Add(('FAILED: {0}' -f $_.Exception.Message)) }
    foreach ($l in @($lines | Where-Object { $_ })) { Write-SICmkLine ('{0,-17} {1}' -f $k, $l) $(if ($ok) { 'Green' } else { 'Red' }) }
    $results.Add([pscustomobject]@{ Step = $k; Ok = [bool]$ok; Lines = @($lines | Where-Object { $_ }) })
}
$obs = $null
if (@($record.applied).Count) {
    Write-SICmkLine ('rollback record: {0}{1}' -f $recPath, $(if ($script:SICmkSaved -and $script:SICmkSaved.InstallLine) { ' -- ' + $script:SICmkSaved.InstallLine } else { '' })) 'Cyan'
    Write-SICmkLine ('waiting {0} minute(s), then counting the runs since the cut-over ...' -f $ObserveMinutes) 'DarkGray'
    $obs = Wait-SICutoverObservation -Arm $A -Shape $shape -Since $started -Minutes $ObserveMinutes -Sleep $Sleep
    Write-SICmkLine $obs.Line $(if ($obs.Failed) { 'Red' } elseif ($obs.Runs) { 'Green' } else { 'Yellow' })
    foreach ($l in @($obs.Lines)) { Write-SICmkLine ('   ' + $l) 'Red' }
} else { Write-SICmkLine 'nothing was changed -- no rollback record was written.' 'DarkGray' }
[pscustomobject]@{ Mode = 'apply'; Shape = $shape; Plan = $plan; RecordPath = $(if (@($record.applied).Count) { $recPath } else { $null }); Results = $results.ToArray(); Observation = $obs }
