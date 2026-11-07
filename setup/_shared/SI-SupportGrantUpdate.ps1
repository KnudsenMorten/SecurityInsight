#Requires -Version 5.1
<#
    #1021 -- THE UPDATE'S HALF OF THE SUPPORT GRANT (rule: existing installs reach the new-install state through the update).
    What the updater's identity may do (Contributor on the resource group, its own user in the Pro database):

      1. THE QUEUE si-support-requests in the install's own storage account (control plane: an ARM PUT, read back) -- where
         the Invardia Support session puts its request for caj-si-support-grant. The job itself is made by the missing-jobs
         step (SI-MissingJobs.ps1).
      2. A DERIVED CONSENT (owner decision 2026-11-01), ONCE, into an empty cfg.SupportConsent: the Support app recorded on
         the install (cfg.InstallState 'SupportApp') and the level its Azure role on the install's Key Vault shows today --
         Key Vault Secrets Officer = setup, Key Vault Reader = troubleshoot (what Grant-SISupportAccess gives at each level);
         no such role = no consent (nothing is written; the customer's admin grants it with Grant-SISupportAccess). A
         consent that is there -- the customer's or an earlier derived one -- is never touched. The table's trigger lets the
         updater write exactly this and nothing else.
    What it can NOT do, and leaves to the one Support-session step per install (setup\Install-SISupportGrantProcedure.ps1):
    sign the procedures (needs db_owner), the Support app's read-only user, and its two Azure roles (needs role assignment
    rights). Every line says what was done or why not; nothing here fails the update.

    Seams: -Rest (setup\_shared\SI-UpdateRest.ps1: Invoke-SIRestJson / ARM + Graph), -Sql { param([string]$Query, $Params,
    [string]$Mode) } on the Pro database. PS 5.1 safe; no module.
#>

$script:SISupportGrantUpdate = [ordered]@{
    Queue         = 'si-support-requests'
    StorageApi    = '2023-01-01'
    VaultApi      = '2022-07-01'
    AuthApi       = '2022-04-01'
    # the built-in role definitions (their ids are the same in every tenant) -> the level they show
    LevelByRoleId = [ordered]@{ 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' = 'setup'; '21090545-7ca7-4776-b22c-e363652d74d2' = 'troubleshoot' }
}

function Get-SISupportGrantDerivedLevel {
    <# PURE. The level the Support app's role assignments on the Key Vault show: setup (Key Vault Secrets Officer) wins over
       troubleshoot (Key Vault Reader); '' = neither (no consent can be derived). -RoleDefinitionIds: full ids or GUIDs. #>
    param([AllowEmptyCollection()][string[]]$RoleDefinitionIds = @())
    $ids = @($RoleDefinitionIds | Where-Object { $_ } | ForEach-Object { ([string]$_ -split '/')[-1].ToLowerInvariant() })
    $map = $script:SISupportGrantUpdate.LevelByRoleId
    if (@($ids | Where-Object { $map.Contains($_) -and $map[$_] -eq 'setup' }).Count) { return 'setup' }
    if (@($ids | Where-Object { $map.Contains($_) -and $map[$_] -eq 'troubleshoot' }).Count) { return 'troubleshoot' }
    ''
}

function Get-SISupportGrantConsentReadSql {
    <# PURE. READ ONLY, one row: the recorded Support app, the consent row (if any) -- '' where the table is not there. #>
    @"
SELECT CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'SupportApp'), N'') END AS SupportApp,
       CASE WHEN OBJECT_ID(N'cfg.SupportConsent') IS NULL THEN N'-' ELSE ISNULL((SELECT [Level] + N'|' + Source FROM cfg.SupportConsent WHERE Id = 1), N'') END AS Consent,
       CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'SupportConsentPortal'), N'') END AS Portal;
"@
}

function Get-SISupportGrantDerivedConsentSql {
    <# PURE. The ONE write: a derived consent into an EMPTY table (parameters @AppId, @Level, @By), then the row read back. #>
    @"
IF NOT EXISTS (SELECT 1 FROM cfg.SupportConsent WHERE Id = 1)
    INSERT cfg.SupportConsent (Id, AppId, [Level], Source, ConsentedBy) VALUES (1, CONVERT(uniqueidentifier, @AppId), @Level, N'derived', LEFT(@By, 256));
SELECT ISNULL((SELECT [Level] + N'|' + Source FROM cfg.SupportConsent WHERE Id = 1), N'') AS Consent;
"@
}

function Invoke-SISupportGrantQueueEnsure {
    <# The queue si-support-requests in -Account: made when missing (ARM PUT), READ BACK. @{ Action (present | created |
       planned | failed); Line }. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [AllowEmptyString()][string]$Account, [switch]$WhatIf)
    $c = $script:SISupportGrantUpdate
    if (-not "$Account".Trim()) { return [pscustomobject]@{ Action = 'failed'; Line = 'support requests: the install names no storage account (SI_StorageAccount) -- the queue was not made' } }
    $uri = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Storage/storageAccounts/{2}/queueServices/default/queues/{3}?api-version={4}' -f $SubscriptionId, $ResourceGroup, $Account.Trim(), $c.Queue, $c.StorageApi
    try {
        if (Invoke-SIRestJson -Rest $Rest -Uri $uri -AllowNotFound -What 'the support request queue') { return [pscustomobject]@{ Action = 'present'; Line = '' } }
        if ($WhatIf) { return [pscustomobject]@{ Action = 'planned'; Line = ('support requests: the queue {0} would be made in {1}' -f $c.Queue, $Account) } }
        $null = Invoke-SIRestJson -Rest $Rest -Method PUT -Uri $uri -Body (@{ properties = @{} } | ConvertTo-Json -Compress) -What 'make the support request queue'
        if (Invoke-SIRestJson -Rest $Rest -Uri $uri -AllowNotFound -What 'the support request queue (read back)') { return [pscustomobject]@{ Action = 'created'; Line = ('support requests: the queue {0} was made in {1}, and read back' -f $c.Queue, $Account) } }
        [pscustomobject]@{ Action = 'failed'; Line = ('support requests: the queue {0} was sent but does not read back yet -- the next update checks it again' -f $c.Queue) }
    } catch { [pscustomobject]@{ Action = 'failed'; Line = ('support requests: the queue {0} was not made ({1}) -- the next update tries again' -f $c.Queue, $_.Exception.Message) } }
}

function Invoke-SISupportGrantDerivedConsent {
    <#
        The DERIVED CONSENT (see the header). @{ Action (present | none | derived | planned | failed); Level; Line }. Never
        throws. -VaultName: the install's Key Vault (SI_KeyVaultName), in -ResourceGroup.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][string]$ResourceGroup, [AllowEmptyString()][string]$VaultName, [switch]$WhatIf)
    $c = $script:SISupportGrantUpdate
    $out = { param($a, $lv, $l) [pscustomobject]@{ Action = $a; Level = $lv; Line = $l } }
    $val = { param($r, $k) if ($null -eq $r) { '' } elseif ($r -is [System.Collections.IDictionary]) { [string]$r[$k] } elseif ($r.PSObject.Properties[$k]) { [string]$r.$k } else { '' } }
    try {
        $row = @(& $Sql (Get-SISupportGrantConsentReadSql) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
        $app = (& $val $row 'SupportApp').Trim(); $have = (& $val $row 'Consent').Trim()
        if ($have -eq '-') { return (& $out 'failed' '' 'support consent: the Pro database has no cfg.SupportConsent yet (its schema step runs first) -- the next update derives it') }
        if ($have) { return (& $out 'present' (($have -split '\|')[0]) '') }
        # the level now comes from the Invardia portal (SI-SupportPortalConsent.ps1, applied by the updater): once Invardia has
        # answered, nothing is derived any more -- a level the portal took away (none) must never come back from a Key Vault role
        if ((& $val $row 'Portal').Trim()) { return (& $out 'none' '' '') }
        if ($app -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return (& $out 'none' '' '') }   # no Support app on this install: nothing to derive, nothing said
        if (-not "$VaultName".Trim()) { return (& $out 'none' '' 'support consent: not derived -- the install names no Key Vault (SI_KeyVaultName); the customer''s admin records it with Grant-SISupportAccess') }
        $sp = Invoke-SIRestJson -Rest $Rest -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id" -f $app) -Resource 'https://graph.microsoft.com/' -What 'the Support app in this tenant'
        $spId = [string](@($sp.value)[0].id)
        if (-not $spId) { return (& $out 'none' '' 'support consent: not derived -- the Support app recorded on the install is not in this tenant') }
        $scope = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.KeyVault/vaults/{2}' -f $SubscriptionId, $ResourceGroup, $VaultName.Trim()
        $list = @(Get-SIRestList -Rest $Rest -Uri ('https://management.azure.com{0}/providers/Microsoft.Authorization/roleAssignments?api-version={1}&$filter={2}' -f $scope, $c.AuthApi, [uri]::EscapeDataString("principalId eq '$spId'")) -What 'the Support app''s roles on the Key Vault')
        $level = Get-SISupportGrantDerivedLevel -RoleDefinitionIds @($list | ForEach-Object { [string]$_.properties.roleDefinitionId })
        if (-not $level) { return (& $out 'none' '' 'support consent: not derived -- the Support app has neither Key Vault Secrets Officer nor Key Vault Reader on the install''s Key Vault (no consent: the customer''s admin grants it with Grant-SISupportAccess)') }
        if ($WhatIf) { return (& $out 'planned' $level ('support consent: would be recorded as DERIVED, level {0} (from the Support app''s Key Vault role)' -f $level)) }
        $back = @(& $Sql (Get-SISupportGrantDerivedConsentSql) @{ AppId = $app; Level = $level; By = 'caj-si-updater (derived from the Support app''s Key Vault role)' } 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
        $got = (& $val $back 'Consent').Trim()
        if ($got -eq ('{0}|derived' -f $level)) { return (& $out 'derived' $level ('support consent: recorded as DERIVED, level {0} (from the Support app''s Key Vault role), and read back' -f $level)) }
        if ($got) { return (& $out 'present' (($got -split '\|')[0]) '') }
        & $out 'failed' $level 'support consent: the derived consent does not read back -- the next update tries again'
    } catch { & $out 'failed' '' ('support consent: not derived ({0}) -- the next update tries again' -f $_.Exception.Message) }
}
