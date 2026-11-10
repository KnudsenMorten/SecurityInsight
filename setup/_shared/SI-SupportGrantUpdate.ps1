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
    sign the procedures (needs db_owner), the Support app's read-only user, and its one Azure role -- Storage Queue Data
    Message Sender on the queue (needs role assignment rights). Every line says what was done or why not; nothing here fails
    the update.

      3. #1154 (framework §5.5, 2026-11-08) THE JOB IS STARTED BY ITS QUEUE, AND THE SUPPORT APP HOLDS NO RIGHT ON ANY JOB
         (Invoke-SISupportGrantQueueTrigger): Microsoft.App/jobs/start/action ALONE accepts a container override, so a start
         right on caj-si-support-grant let the Support app run its own command as the engine identity. In this order:
           a. caj-si-support-grant -> triggerType Event with the azure-queue scale rule on si-support-requests in the install's
              own storage account, the scaler signed in as the ENGINE identity (no key: shared-key access is off) -- one
              merge PATCH of the trigger only, READ BACK with retries (ARM reads are eventually consistent);
           b. ONLY when the trigger reads back as Event: every role assignment the Support app holds AT a caj-si-* job is
              removed (whatever its role -- no ARM right on any job), READ BACK -- by the Support-session step and the
              person-run update; THE UPDATER (-KeepJobRights, #1163) sends no delete: a right an earlier release gave is
              kept and said once. A right at the resource group or above is judged against the CONSENTED level (#1163:
              Setup's Contributor + User Access Administrator at the subscription expected; root User Access Administrator
              at rings 0-2 expected) -- anything above it is one note for the owner, never changed here.
         So support never loses its way in: the queue starts the job before the start right goes. The updater holds
         Contributor, which may not remove a role assignment: then the line says who can (the Support-session step or the
         customer's admin) and the next update checks again. Idempotent; never throws; a second run changes nothing.

    Seams: -Rest (setup\_shared\SI-UpdateRest.ps1: Invoke-SIRestJson / ARM + Graph), -Sql { param([string]$Query, $Params,
    [string]$Mode) } on the Pro database, -Arm { param([string]$Method, [string]$Path, $Body) } (a path with its api-version;
    the parsed answer, $null for a GET that is 404, throws on anything else). PS 5.1 safe; no module.
#>

$script:SISupportGrantUpdate = [ordered]@{
    Queue         = 'si-support-requests'
    StorageApi    = '2023-01-01'
    VaultApi      = '2022-07-01'
    AuthApi       = '2022-04-01'
    # #1154: the job, its trigger (the same values as container\_shared\SI-ContainerConfig.ps1 Get-SISupportGrantTriggerArgs --
    # a test holds them equal) and the jobs' api-version (the schema the fast roll reads and writes)
    Job           = 'caj-si-support-grant'
    JobsApi       = '2025-07-01'
    RuleName      = 'si-support-requests'
    MaxExecutions = 1
    PollingInterval = 10
    # the role names said in a line (a role assignment names its role only by id)
    RoleNames     = [ordered]@{ 'b9a307c4-5aa3-4b52-ba60-2b17c136cd7b' = 'Container Apps Jobs Operator'; '4e3d2b60-56ae-4dc6-a233-09c8e5a82e68' = 'Container Apps Jobs Contributor'
                                'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'; '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'; 'acdd72a7-3385-48ef-bd42-f606fba81ae7' = 'Reader'
                                '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'; '43d0d8ad-25c7-4714-9337-8ba259a9fe05' = 'Monitoring Reader'
                                '73c42c96-874c-492b-b04d-ab87d138a893' = 'Log Analytics Reader'; '39bc4728-0917-49c7-9d2c-d95423bc2eb4' = 'Security Reader'
                                '21090545-7ca7-4776-b22c-e363652d74d2' = 'Key Vault Reader' }
    # #1163 (agreed with Invardia 2026-11-10): the Support app's rights judged against the CONSENTED level (cfg.SupportConsent)
    # -- the reader set is expected at both levels; Setup adds Contributor + User Access Administrator at the install's
    # subscription; User Access Administrator at the tenant root management group is expected at rings 0-2 (framework
    # ROOT-RIGHTS-1; at ring 3 only with an approval Invardia records, which the update cannot read)
    ReaderRoles   = @('acdd72a7-3385-48ef-bd42-f606fba81ae7', '43d0d8ad-25c7-4714-9337-8ba259a9fe05', '73c42c96-874c-492b-b04d-ab87d138a893', '39bc4728-0917-49c7-9d2c-d95423bc2eb4', '21090545-7ca7-4776-b22c-e363652d74d2')
    SetupRoles    = @('b24988ac-6180-42a0-ab88-20f7382dd24c', '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9')
    RootUaaRole   = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
    LeftoverRow   = 'SupportLeftoverRights'
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

# ---- #1154: THE JOB IS STARTED BY ITS QUEUE; THE SUPPORT APP HOLDS NO RIGHT ON ANY JOB --------------------------------------

function Get-SISupportGrantProp {
    <# PURE. A property of a parsed ARM object, $null when absent (dictionary or PSObject; never throws on a missing level). #>
    param($Object, [string[]]$Path)
    $o = $Object
    foreach ($p in $Path) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($p)) { $o = $o[$p] } else { return $null }; continue }
        $pp = $o.PSObject.Properties[$p]; if (-not $pp) { return $null }; $o = $pp.Value
    }
    $o
}

function Get-SISupportGrantJobEnvValue {
    <# PURE. The value of env NAME (case-insensitive) on the job's first container that has it ('' when none). #>
    param($Job, [Parameter(Mandatory)][string]$Name)
    foreach ($c in @(Get-SISupportGrantProp $Job @('properties', 'template', 'containers'))) {
        foreach ($e in @(Get-SISupportGrantProp $c @('env'))) {
            if ($e -and [string](Get-SISupportGrantProp $e @('name')) -ieq $Name) { $v = [string](Get-SISupportGrantProp $e @('value')); if ($v.Trim()) { return $v.Trim() } }
        }
    }
    ''
}

function Select-SISupportGrantJobIdentity {
    <#
        PURE. The ENGINE identity a job signs in as -- the user-assigned identity whose client id is the job's SI_UAMI_CLIENTID,
        else the job's only user-assigned identity. '' when there is none or it cannot be told (several, none named).
    #>
    param($Job)
    $ua = Get-SISupportGrantProp $Job @('identity', 'userAssignedIdentities')
    if ($null -eq $ua) { return '' }
    $ids = @(if ($ua -is [System.Collections.IDictionary]) { foreach ($k in $ua.Keys) { [pscustomobject]@{ Id = [string]$k; ClientId = [string](Get-SISupportGrantProp $ua[$k] @('clientId')) } } }
             else { foreach ($p in $ua.PSObject.Properties) { [pscustomobject]@{ Id = [string]$p.Name; ClientId = [string](Get-SISupportGrantProp $p.Value @('clientId')) } } })
    $ids = @($ids | Where-Object { $_.Id.Trim() })
    $cid = Get-SISupportGrantJobEnvValue -Job $Job -Name 'SI_UAMI_CLIENTID'
    if ($cid) { $m = @($ids | Where-Object { $_.ClientId -and $_.ClientId -ieq $cid })[0]; if ($m) { return $m.Id } }
    if ($ids.Count -eq 1) { return $ids[0].Id }
    ''
}

function Get-SISupportGrantEventTriggerConfig {
    <# PURE. The eventTriggerConfig of caj-si-support-grant: one execution at a time, the azure-queue rule on si-support-requests
       in -StorageAccount, signed in as -IdentityResourceId. Exactly what Bootstrap's create arguments translate to. #>
    param([Parameter(Mandatory)][string]$StorageAccount, [Parameter(Mandatory)][string]$IdentityResourceId)
    $c = $script:SISupportGrantUpdate
    $rule = [ordered]@{ name = $c.RuleName; type = 'azure-queue'; metadata = [ordered]@{ queueName = $c.Queue; accountName = $StorageAccount.Trim(); queueLength = '1' }; identity = $IdentityResourceId.Trim() }
    [ordered]@{ parallelism = 1; replicaCompletionCount = 1
                scale = [ordered]@{ minExecutions = 0; maxExecutions = [int]$c.MaxExecutions; pollingInterval = [int]$c.PollingInterval; rules = @($rule) } }
}

function Get-SISupportGrantTriggerState {
    <#
        PURE. Where caj-si-support-grant stands (-Job as ARM returned it): @{ State; Account; Identity; Why }
          event    already started by its queue: Event, an azure-queue rule on si-support-requests in the account, signed in
                   as the engine identity
          convert  not yet (manual, another rule, no identity on the rule, another account)
          cannot   it cannot be: no storage account (-StorageAccount, else the job's SI_STORAGE_ACCOUNT), or no engine identity
    #>
    param([Parameter(Mandatory)]$Job, [AllowEmptyString()][string]$StorageAccount = '')
    $c = $script:SISupportGrantUpdate
    $acct = "$StorageAccount".Trim(); if (-not $acct) { $acct = Get-SISupportGrantJobEnvValue -Job $Job -Name 'SI_STORAGE_ACCOUNT' }
    $id = Select-SISupportGrantJobIdentity -Job $Job
    $out = { param($s, $w) [pscustomobject]@{ State = $s; Account = $acct; Identity = $id; Why = $w } }
    if (-not $acct) { return (& $out 'cannot' 'the install names no storage account (SI_STORAGE_ACCOUNT on the job)') }
    if (-not $id) { return (& $out 'cannot' 'the job has no managed identity the queue scaler could sign in as') }
    $cfg = Get-SISupportGrantProp $Job @('properties', 'configuration')
    $tt = [string](Get-SISupportGrantProp $cfg @('triggerType'))
    if ($tt -ne 'Event') { return (& $out 'convert' ('its trigger is {0}' -f $(if ($tt) { $tt } else { 'not known' }))) }
    $ok = @(@(Get-SISupportGrantProp $cfg @('eventTriggerConfig', 'scale', 'rules')) | Where-Object {
        $_ -and [string](Get-SISupportGrantProp $_ @('type')) -eq 'azure-queue' -and
        [string](Get-SISupportGrantProp $_ @('metadata', 'queueName')) -eq $c.Queue -and
        [string](Get-SISupportGrantProp $_ @('metadata', 'accountName')) -ieq $acct -and
        [string](Get-SISupportGrantProp $_ @('identity')) -ieq $id }).Count
    if ($ok) { return (& $out 'event' '') }
    & $out 'convert' ('its queue rule is not on {0} in {1} signed in as the engine identity' -f $c.Queue, $acct)
}

function Get-SISupportGrantTriggerPatch {
    <#
        PURE. The PATCH that makes caj-si-support-grant started by its queue. A Container Apps PATCH is a JSON MERGE patch: the
        body carries ONLY the trigger (triggerType, its run limit and retry limit as the job has them, eventTriggerConfig --
        whose rules array is replaced whole); the secrets, the template, the identity and the registry are not sent and stay.
    #>
    param([Parameter(Mandatory)]$Job, [Parameter(Mandatory)][string]$StorageAccount, [Parameter(Mandatory)][string]$IdentityResourceId)
    $cfg = Get-SISupportGrantProp $Job @('properties', 'configuration')
    $c = [ordered]@{ triggerType = 'Event' }
    $to = Get-SISupportGrantProp $cfg @('replicaTimeout'); if ($to) { $c.replicaTimeout = [int]$to }
    $rl = Get-SISupportGrantProp $cfg @('replicaRetryLimit'); if ($null -ne $rl) { $c.replicaRetryLimit = [int]$rl }
    $c.eventTriggerConfig = Get-SISupportGrantEventTriggerConfig -StorageAccount $StorageAccount -IdentityResourceId $IdentityResourceId
    [ordered]@{ properties = [ordered]@{ configuration = $c } }
}

function Get-SISupportGrantConsentLevel {
    <# PURE. The consented level from the consent read's 'Consent' column ('<level>|<source>', '' = none, '-' = no table):
       setup | troubleshoot | '' (none recorded, or not readable). #>
    param([AllowNull()][AllowEmptyString()][string]$Consent)
    $lv = ("$Consent".Trim() -split '\|')[0].Trim().ToLowerInvariant()
    if ($lv -in 'setup', 'troubleshoot') { return $lv }
    ''
}

function Resolve-SISupportGrantRightNotes {
    <#
        PURE. #1163: the Support app's rights at the install's resource group or above, judged against the consented level.
        -Assignments: its role assignments whose scope is the resource group or an ancestor of it. -ConsentLevel: setup |
        troubleshoot | '' (none recorded). -Ring: the install's ring (0-3; $null = not known). -TenantId: names the root
        management group. Returns the notes for the owner (plain lines; '' never) -- nothing is ever removed for a note:
          * the reader set: expected at both levels;
          * Contributor / User Access Administrator at the install's subscription or resource group: expected at Setup;
          * User Access Administrator at the tenant root management group: expected at rings 0-2; at ring 3 (or an unknown
            ring) a note -- it needs an approval Invardia records, which the update cannot read;
          * anything else: above the consented level -- a note.
    #>
    param([AllowEmptyCollection()][object[]]$Assignments = @(), [AllowEmptyString()][string]$ConsentLevel = '', [AllowNull()]$Ring = $null,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [AllowEmptyString()][string]$TenantId = '')
    $c = $script:SISupportGrantUpdate
    $sub = ('/subscriptions/{0}' -f $SubscriptionId).ToLowerInvariant()
    $rg = ('{0}/resourcegroups/{1}' -f $sub, $ResourceGroup).ToLowerInvariant()
    $root = if ("$TenantId".Trim()) { ('/providers/microsoft.management/managementgroups/{0}' -f "$TenantId".Trim()).ToLowerInvariant() } else { '' }
    $r = -1; $ringKnown = ($null -ne $Ring -and [int]::TryParse("$Ring", [ref]$r) -and $r -ge 0 -and $r -le 3)
    $lvWords = if ($ConsentLevel) { 'the consented level ({0})' -f $ConsentLevel } else { 'the consented level (no consent is recorded)' }
    $notes = New-Object System.Collections.Generic.List[string]
    foreach ($a in @($Assignments | Where-Object { $_ })) {
        $scope = ([string](Get-SISupportGrantProp $a @('properties', 'scope'))).TrimEnd('/').ToLowerInvariant()
        $rd = ([string](Get-SISupportGrantProp $a @('properties', 'roleDefinitionId')) -split '/')[-1].ToLowerInvariant()
        if ($c.ReaderRoles -contains $rd) { continue }
        $where = if ($scope -eq $sub) { 'the install''s subscription' } elseif ($scope -eq $rg) { 'the install''s resource group' } elseif ($root -and $scope -eq $root) { 'the tenant root management group' } else { [string](Get-SISupportGrantProp $a @('properties', 'scope')) }
        $role = Get-SISupportGrantRoleName $rd
        if ($ConsentLevel -eq 'setup' -and $c.SetupRoles -contains $rd -and $scope -in $sub, $rg) { continue }
        if ($root -and $scope -eq $root -and $rd -eq $c.RootUaaRole) {
            if ($ringKnown -and $r -le 2) { continue }
            $notes.Add(('support access: a note for the owner -- the Invardia Support app holds {0} at {1}; {2} it is expected only with an approval Invardia records, which the update cannot read; it is kept' -f $role, $where, $(if ($ringKnown) { "at ring $r" } else { 'with the ring not known,' })))
            continue
        }
        $notes.Add(('support access: a note for the owner -- the Invardia Support app holds {0} at {1}, above {2}; the update never removes it, the customer''s admin or Invardia decides' -f $role, $where, $lvWords))
    }
    $notes.ToArray()
}

function Get-SISupportGrantLeftoverKey {
    <# PURE. One short key for a set of role assignment ids (order and case do not matter): each assignment's NAME (the last
       part of its id, a GUID), sorted, joined by ','; '' for none. #>
    param([AllowEmptyCollection()][string[]]$Ids = @())
    $s = @($Ids | Where-Object { "$_".Trim() } | ForEach-Object { ("$_".Trim().TrimEnd('/') -split '/')[-1].ToLowerInvariant() } | Sort-Object -Unique)
    if (-not $s.Count) { return '' }
    [string]($s -join ',')
}

function Get-SISupportGrantLeftoverSql {
    <# PURE. -Read: the said-before key (column Value, '' none); else ONE row written or replaced (@Value) -- the key only. #>
    param([switch]$Read)
    $n = $script:SISupportGrantUpdate.LeftoverRow
    if ($Read) { return "SELECT CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'$n'), N'') END AS Value;" }
    @"
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'$n')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'caj-si-updater' WHERE Name = N'$n';
    ELSE INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N'$n', @Value, N'caj-si-updater');
END
"@
}

function Get-SISupportGrantRoleName {
    <# PURE. A role assignment's role in words: the built-in name where known, else 'the role <guid>'. #>
    param([AllowEmptyString()][string]$RoleDefinitionId)
    $g = ("$RoleDefinitionId" -split '/')[-1].ToLowerInvariant()
    if ($script:SISupportGrantUpdate.RoleNames.Contains($g)) { return [string]$script:SISupportGrantUpdate.RoleNames[$g] }
    'the role {0}' -f $g
}

function Get-SISupportGrantRecordedApp {
    <# READ ONLY. The Invardia Support app's client id recorded on the install (cfg.InstallState 'SupportApp'); '' when none.
       -Sql { param($Query, $Params, $Mode) } ('rows'). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Sql)
    try {
        $row = @(& $Sql "SELECT CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'SupportApp'), N'') END AS SupportApp;" @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
        $v = if ($null -eq $row) { '' } elseif ($row -is [System.Collections.IDictionary]) { [string]$row['SupportApp'] } elseif ($row.PSObject.Properties['SupportApp']) { [string]$row.SupportApp } else { '' }
        $v = $v.Trim()
        if ($v -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return $v }
    } catch { }
    ''
}

function Resolve-SISupportGrantPrincipal {
    <# The service principal (object id) of the Support app -AppId in this tenant, through Graph (-Rest). '' when none or
       not readable. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [AllowEmptyString()][string]$AppId)
    if ("$AppId".Trim() -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return '' }
    try {
        $sp = Invoke-SIRestJson -Rest $Rest -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id" -f $AppId.Trim()) -Resource 'https://graph.microsoft.com/' -What 'the Support app in this tenant'
        return [string](@($sp.value)[0].id)
    } catch { return '' }
}

function Invoke-SISupportGrantQueueTrigger {
    <#
        THE #1154 STEP (see the header, point 3). -Arm: the ARM seam (a path with its api-version). -SupportPrincipalId: the
        Invardia Support app's service principal (object id) in this tenant ('' = no Support app here: the trigger is still
        converted, nothing is removed). -RemoveHow: who can remove a right this identity may not (said in the line).
        -Tries / -WaitSeconds / -Sleep: the read-backs. -WhatIf: reads only, the plan said.
        #1163 (agreed with Invardia 2026-11-10): -ConsentLevel (setup | troubleshoot | '' none recorded), -Ring, -TenantId --
        the rights at the resource group or above are judged against the consented level (Resolve-SISupportGrantRightNotes):
        one note for the owner per right above it, NEVER removed. -KeepJobRights (THE UPDATER: it may not, and does not, remove
        a right in a customer tenant): a right an earlier release gave on a caj-si-* job is KEPT, no DELETE is sent -- ONE
        plain line, only when that set differs from -LeftoverSaid (the key said before; Get-SISupportGrantLeftoverKey).
        Returns @{ Trigger (none | present | converted | planned | failed | cannot); Removal (none | removed | planned | failed |
        held | skipped | kept); Removed = @(ids); Kept = @(ids); Notes = @(texts); LeftoverKey; Lines = @(@{ Level (info |
        warn); Text }) }. NEVER throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [AllowEmptyString()][string]$StorageAccount = '', [AllowEmptyString()][string]$SupportPrincipalId = '',
          [string]$RemoveHow = 'Invardia support removes it in its Support session (its support grant install step, roles), or the customer''s admin: Azure portal > the job > Access control (IAM) > Role assignments > remove the Invardia Support app',
          [int]$Tries = 12, [int]$WaitSeconds = 10, [scriptblock]$Sleep, [switch]$WhatIf,
          [AllowEmptyString()][string]$ConsentLevel = '', [AllowNull()]$Ring = $null, [AllowEmptyString()][string]$TenantId = '',
          [switch]$KeepJobRights, [AllowEmptyString()][string]$LeftoverSaid = '')
    $c = $script:SISupportGrantUpdate
    $res = [ordered]@{ Trigger = 'none'; Removal = 'none'; Removed = @(); Kept = @(); Notes = @(); LeftoverKey = ''; Lines = (New-Object System.Collections.Generic.List[object]) }
    $say = { param($lv, $t) $res.Lines.Add([pscustomobject]@{ Level = $lv; Text = $t }) }
    $done = { [pscustomobject]@{ Trigger = $res.Trigger; Removal = $res.Removal; Removed = @($res.Removed); Kept = @($res.Kept); Notes = @($res.Notes); LeftoverKey = [string]$res.LeftoverKey; Lines = $res.Lines.ToArray() } }
    if (-not $Sleep) { $Sleep = { param($s) if ($s -gt 0) { Start-Sleep -Seconds $s } } }
    $rg = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup
    $jobPath = '{0}/providers/Microsoft.App/jobs/{1}?api-version={2}' -f $rg, $c.Job, $c.JobsApi
    try {
        # ---- a. THE TRIGGER ----
        $job = $null
        try { $job = & $Arm 'GET' $jobPath $null } catch { & $say 'warn' ('support requests: the support grant job could not be read ({0}) -- the next update tries again' -f $_.Exception.Message); $res.Trigger = 'failed'; $res.Removal = 'held'; return (& $done) }
        if (-not $job) { return (& $done) }   # no support grant job at this install: nothing to do, nothing said
        $st = Get-SISupportGrantTriggerState -Job $job -StorageAccount $StorageAccount
        if ($st.State -eq 'cannot') {
            & $say 'warn' ('support requests: {0} cannot be started by its queue yet -- {1}; the Invardia Support app keeps its way in until it can' -f $c.Job, $st.Why)
            $res.Trigger = 'cannot'; $res.Removal = 'held'; return (& $done)
        }
        if ($st.State -eq 'event') { $res.Trigger = 'present' }
        elseif ($WhatIf) {
            & $say 'info' ('support requests: {0} would be started by its queue {1} (event trigger, the queue read as the engine identity); once that reads back, the Invardia Support app''s rights on the jobs would be removed' -f $c.Job, $c.Queue)
            $res.Trigger = 'planned'; $res.Removal = 'held'; return (& $done)
        } else {
            try { $null = & $Arm 'PATCH' $jobPath (Get-SISupportGrantTriggerPatch -Job $job -StorageAccount $st.Account -IdentityResourceId $st.Identity) }
            catch { & $say 'warn' ('support requests: {0} was not moved to its queue ({1}) -- the Invardia Support app keeps its way in; the next update tries again' -f $c.Job, $_.Exception.Message); $res.Trigger = 'failed'; $res.Removal = 'held'; return (& $done) }
            $back = $false
            for ($i = 1; $i -le [Math]::Max(1, $Tries); $i++) {
                $j = $null; try { $j = & $Arm 'GET' $jobPath $null } catch { $j = $null }
                # read back = the job says Event on the queue AND its change has finished (a PATCH of a job runs on: until it
                # has succeeded, the trigger shown may not be the one in force)
                $ps = [string](Get-SISupportGrantProp $j @('properties', 'provisioningState'))
                if ($j -and (-not $ps -or $ps -eq 'Succeeded') -and (Get-SISupportGrantTriggerState -Job $j -StorageAccount $st.Account).State -eq 'event') { $back = $true; break }
                if ($i -lt $Tries) { & $Sleep $WaitSeconds }
            }
            if (-not $back) {
                & $say 'warn' ('support requests: {0} was moved to its queue trigger but does not read back that way yet -- the Invardia Support app keeps its way in; the next update checks again' -f $c.Job)
                $res.Trigger = 'failed'; $res.Removal = 'held'; return (& $done)
            }
            & $say 'info' ('support requests: {0} is now started by its queue {1} (event trigger, the queue read as the engine identity), and read back' -f $c.Job, $c.Queue)
            $res.Trigger = 'converted'
        }

        # ---- b. NO RIGHT ON ANY JOB -- only now that the queue starts the job ----
        $spId = "$SupportPrincipalId".Trim()
        if (-not $spId) { $res.Removal = 'skipped'; return (& $done) }
        $listPath = '{0}/providers/Microsoft.Authorization/roleAssignments?api-version={1}&$filter={2}' -f $rg, $c.AuthApi, [uri]::EscapeDataString("principalId eq '$spId'")
        $list = {
            $page = & $Arm 'GET' $listPath $null
            @(@(Get-SISupportGrantProp $page @('value')) | Where-Object { $_ -and [string](Get-SISupportGrantProp $_ @('properties', 'principalId')) -ieq $spId })
        }
        $all = @()
        try { $all = @(& $list) } catch { & $say 'warn' ('support access: the Invardia Support app''s rights could not be read ({0}) -- the next update checks again' -f $_.Exception.Message); $res.Removal = 'failed'; return (& $done) }
        $jobRx = '(?i)^' + [regex]::Escape($rg) + '/providers/Microsoft\.App/jobs/caj-si-[^/]+$'
        $onJob = @($all | Where-Object { [string](Get-SISupportGrantProp $_ @('properties', 'scope')) -match $jobRx })
        # #1163: the rights at the resource group or above, judged against the CONSENTED level -- a note for the owner each,
        # never removed (Setup's Contributor + User Access Administrator at the subscription are expected, not "broader")
        $rgKey = $rg.ToLowerInvariant() + '/'
        # (a management group is no string prefix of the group's path: any management-group scope the list returns is inherited)
        $above = @($all | Where-Object { $sc = [string](Get-SISupportGrantProp $_ @('properties', 'scope')); $sc -and ($rgKey.StartsWith($sc.TrimEnd('/').ToLowerInvariant() + '/') -or $sc -match '(?i)^/providers/Microsoft\.Management/managementGroups/[^/]+/?$') })
        # (judged only where the caller read the consent -- the updater; a caller that did not is never told "no consent")
        if ($PSBoundParameters.ContainsKey('ConsentLevel')) { $res.Notes = @(Resolve-SISupportGrantRightNotes -Assignments $above -ConsentLevel $ConsentLevel -Ring $Ring -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -TenantId $TenantId) }
        foreach ($n in $res.Notes) { & $say 'info' $n }
        if (-not $onJob.Count) { return (& $done) }
        $what = { param($a) '{0} on {1}' -f (Get-SISupportGrantRoleName ([string](Get-SISupportGrantProp $a @('properties', 'roleDefinitionId')))), ([string](Get-SISupportGrantProp $a @('properties', 'scope')) -split '/')[-1] }
        if ($KeepJobRights) {
            # #1163: the updater sends NO delete -- a right an earlier release gave on a job is kept, said once per set
            [string[]]$keptIds = @($onJob | ForEach-Object { [string](Get-SISupportGrantProp $_ @('id')) })
            [string]$key = Get-SISupportGrantLeftoverKey -Ids $keptIds
            $res['Kept'] = $keptIds; $res['LeftoverKey'] = $key; $res['Removal'] = 'kept'
            if ($key -ne ([string]$LeftoverSaid).Trim()) {
                [string]$names = (@($onJob | ForEach-Object { [string](& $what $_) }) -join ', ')
                & $say 'info' ('support access: a right an earlier release gave is still there ({0}); it is not needed and is kept' -f $names)
            }
            return (& $done)
        }
        if ($WhatIf) {
            foreach ($a in $onJob) { & $say 'info' ('support access: the Invardia Support app''s {0} would be removed -- support asks through its queue only' -f (& $what $a)) }
            $res.Removal = 'planned'; return (& $done)
        }
        $sent = New-Object System.Collections.Generic.List[object]; $failed = 0
        foreach ($a in $onJob) {
            $aid = [string](Get-SISupportGrantProp $a @('id'))
            try { $null = & $Arm 'DELETE' ('{0}?api-version={1}' -f $aid, $c.AuthApi) $null; $sent.Add($a) }
            catch { $failed++; & $say 'warn' ('support access: the Invardia Support app''s {0} could not be removed ({1}) -- {2}; the next update checks again' -f (& $what $a), $_.Exception.Message, $RemoveHow) }
        }
        # THE READ-BACK: what was removed must be gone from the list (role assignments are eventually consistent: read again)
        $left = @($sent.ToArray())
        for ($i = 1; $left.Count -and $i -le [Math]::Max(1, $Tries); $i++) {
            $now = $null; try { $now = @(& $list) } catch { $now = $null }
            if ($null -ne $now) { $ids = @($now | ForEach-Object { [string](Get-SISupportGrantProp $_ @('id')) }); $left = @($left | Where-Object { $ids -icontains [string](Get-SISupportGrantProp $_ @('id')) }) }
            if ($left.Count -and $i -lt $Tries) { & $Sleep $WaitSeconds }
        }
        foreach ($a in $sent) {
            $aid = [string](Get-SISupportGrantProp $a @('id'))
            if (@($left | Where-Object { [string](Get-SISupportGrantProp $_ @('id')) -ieq $aid }).Count) { $failed++; & $say 'warn' ('support access: the Invardia Support app''s {0} was removed but still reads back -- the next update checks again' -f (& $what $a)) }
            else { $res.Removed += $aid; & $say 'info' ('support access: the Invardia Support app''s {0} was removed, and read back -- support asks through its queue only' -f (& $what $a)) }
        }
        $res.Removal = if ($failed) { 'failed' } else { 'removed' }
        & $done
    } catch {
        & $say 'warn' ('support requests: the queue trigger was not checked ({0}) -- the next update tries again' -f $_.Exception.Message)
        if ($res.Trigger -eq 'none') { $res.Trigger = 'failed' }
        if ($res.Removal -eq 'none') { $res.Removal = 'held' }
        & $done
    }
}
