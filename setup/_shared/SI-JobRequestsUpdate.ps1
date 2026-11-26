#Requires -Version 5.1
<#
    #1252 (SECURE-WEB-1 part 2) -- THE UPDATE'S HALF OF THE JOB REQUEST QUEUE (rule: existing installs reach the new-install state
    through the update; rights at installs change only through the updater / setup). Every update run, after the missing-jobs
    step made caj-si-job-requests (setup\_shared\SI-MissingJobs.ps1), in this order, each READ BACK:

      1. THE QUEUE si-job-requests in the install's storage account (the account the job's SI_STORAGE_ACCOUNT names, in the
         install's resource group -- as the support request queue): made when missing (control plane, ARM PUT).
      2. THE JOB IS STARTED BY THAT QUEUE: caj-si-job-requests -> triggerType Event, the azure-queue rule on si-job-requests
         signed in as the ENGINE identity (the same merge PATCH of the trigger only as the support grant job's).
      3. THE WEB APP'S ONE NEW RIGHT: "Storage Queue Data Message Sender" (c6a89b2d-59bc-44d0-9896-0f6e12d7b80a) on THAT QUEUE
         ONLY (scope .../storageAccounts/<account>/queueServices/default/queues/si-job-requests -- never the account, never the
         resource group), for every managed identity of the web app (ca-si-management or its recorded name). A PUT with a
         stable assignment name; refused (the updater's role-assignment right may not give this role) = one support-step
         line, nothing else changes.
      4. ONLY when 1-3 read back: cfg.InstallState 'JobRequestQueue' = the queue's address. The web app reads that row: set =
         its buttons put a request on the queue; not set (or '') = the buttons work as before. Anything not read back sets the
         row to '' -- the web app is never sent to a queue nobody reads.
    Never removes a right. NEVER throws; never fails the update (a refusal is one line, the next update tries again).

    Seams: -Arm { param([string]$Method, [string]$Path, $Body) } (a path WITH its api-version; the parsed answer; $null for a
    GET that is 404; throws on anything else), -Sql { param([string]$Query, $Params, [string]$Mode) } on the Pro database
    ('nonquery' / 'reader'), -Sleep { param([int]$Seconds) }. PS 5.1 safe; no module.
#>

if (-not (Get-Command -Name Get-SISupportGrantTriggerState -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-SupportGrantUpdate.ps1') }

$script:SIJobRequestsUpdate = [ordered]@{
    Job        = 'caj-si-job-requests'
    Queue      = 'si-job-requests'
    Row        = 'JobRequestQueue'
    SenderRole = 'c6a89b2d-59bc-44d0-9896-0f6e12d7b80a'   # Storage Queue Data Message Sender (built-in; the same id in every tenant)
    JobsApi    = '2025-07-01'
    AppsApi    = '2024-03-01'
    StorageApi = '2023-01-01'
    AuthApi    = '2022-04-01'
}

# THE one line said when the web app's right is missing and could not be given here (Invardia decision 2026-11-25; never reworded)
$script:SIJobRequestsNeedRightLine = "Run now / Stop / schedule changes / template release / mail send-now from the web app need one more right: ask your admin to re-run the Invardia Support app setup script, Setup level (it gives the web app 'Storage Queue Data Message Sender' on the queue si-job-requests only). Until then these buttons work as before."

function Get-SIJobRequestsUpdateContract { $script:SIJobRequestsUpdate }

function Get-SIJobRequestQueueUri {
    <# PURE. The queue's data-plane address the web app sends to: https://<account>.queue.core.windows.net/si-job-requests. #>
    param([Parameter(Mandatory)][string]$StorageAccount)
    'https://{0}.queue.core.windows.net/{1}' -f $StorageAccount.Trim().ToLowerInvariant(), $script:SIJobRequestsUpdate.Queue
}

function Get-SIJobRequestQueueScope {
    <# PURE. The ONE scope of the web app's right: the queue itself. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$StorageAccount)
    '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Storage/storageAccounts/{2}/queueServices/default/queues/{3}' -f $SubscriptionId, $ResourceGroup, $StorageAccount.Trim(), $script:SIJobRequestsUpdate.Queue
}

function Get-SIJobRequestAssignmentName {
    <# PURE. A stable role assignment name (a GUID) for (scope, principal, role) -- a second run PUTs the same one. #>
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$PrincipalId, [string]$RoleId = $script:SIJobRequestsUpdate.SenderRole)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { $b = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes(('{0}|{1}|{2}' -f $Scope.ToLowerInvariant(), $PrincipalId.ToLowerInvariant(), $RoleId.ToLowerInvariant()))) } finally { $md5.Dispose() }
    ([guid]::new([byte[]]$b)).ToString()
}

function Get-SIJobRequestWebPrincipals {
    <# PURE. Every managed identity principal id of the web app (-App as ARM returns it): system-assigned and user-assigned. #>
    param($App)
    $out = New-Object System.Collections.Generic.List[string]
    $id = Get-SISupportGrantProp $App @('identity')
    if (-not $id) { return @() }
    $sp = [string](Get-SISupportGrantProp $id @('principalId')); if ($sp.Trim()) { $out.Add($sp.Trim().ToLowerInvariant()) }
    $ua = Get-SISupportGrantProp $id @('userAssignedIdentities')
    if ($ua) {
        $vals = if ($ua -is [System.Collections.IDictionary]) { @($ua.Values) } else { @($ua.PSObject.Properties | ForEach-Object { $_.Value }) }
        foreach ($v in $vals) { $p = [string](Get-SISupportGrantProp $v @('principalId')); if ($p.Trim() -and -not $out.Contains($p.Trim().ToLowerInvariant())) { $out.Add($p.Trim().ToLowerInvariant()) } }
    }
    @($out.ToArray())
}

function Get-SIJobRequestRowSql {
    <# PURE. -Read: the row's value ('' none); else the ONE write of cfg.InstallState 'JobRequestQueue' (@Value). #>
    param([switch]$Read)
    $n = $script:SIJobRequestsUpdate.Row
    if ($Read) { return "SELECT CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'$n'), N'') END AS Value;" }
    @"
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'$n')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'caj-si-updater' WHERE Name = N'$n' AND Value <> @Value;
    ELSE INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N'$n', @Value, N'caj-si-updater');
END
"@
}

function Invoke-SIJobRequestsConverge {
    <#
        THE STEP (see the header). -WebApp: the web app's name. Returns @{ State (on | off | no-job); Queue; Trigger; Role;
        Row; Lines = @(@{ Level (info | warn); Text }) }. NEVER throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Sql, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$WebApp = 'ca-si-management', [int]$Tries = 12, [int]$WaitSeconds = 10, [scriptblock]$Sleep)
    $c = $script:SIJobRequestsUpdate
    if (-not $Sleep) { $Sleep = { param($s) if ($s -gt 0) { Start-Sleep -Seconds $s } } }
    $res = [ordered]@{ State = 'off'; Queue = 'none'; Trigger = 'none'; Role = 'none'; Row = 'none'; Lines = (New-Object System.Collections.Generic.List[object]) }
    $say = { param($lv, $t) $res.Lines.Add([pscustomobject]@{ Level = $lv; Text = $t }) }
    $rg = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup
    $setRow = {
        param([string]$value)
        if (-not $Sql) { $res.Row = 'not-written'; return }
        try {
            $now = [string](@(& $Sql (Get-SIJobRequestRowSql -Read) @{} 'reader' | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { $_['Value'] } elseif ($_.PSObject.Properties['Value']) { $_.Value } })[0])
            if ($now -ceq $value) { $res.Row = 'unchanged'; return }
            if (-not $value -and -not $now) { $res.Row = 'unchanged'; return }
            $null = & $Sql (Get-SIJobRequestRowSql) @{ Value = $value } 'nonquery'
            $back = [string](@(& $Sql (Get-SIJobRequestRowSql -Read) @{} 'reader' | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { $_['Value'] } elseif ($_.PSObject.Properties['Value']) { $_.Value } })[0])
            if ($back -ceq $value) {
                $res.Row = 'written'
                & $say 'info' $(if ($value) { ('job requests: the web app''s buttons now put their request on the queue {0} (cfg.InstallState ''{1}'', read back)' -f $c.Queue, $c.Row) } else { ('job requests: the web app''s buttons work as before (cfg.InstallState ''{0}'' cleared, read back)' -f $c.Row) })
            } else { $res.Row = 'failed'; & $say 'warn' ('job requests: cfg.InstallState ''{0}'' does not read back -- the next update tries again' -f $c.Row) }
        } catch { $res.Row = 'failed'; & $say 'warn' ('job requests: cfg.InstallState ''{0}'' could not be written ({1}) -- the next update tries again' -f $c.Row, $_.Exception.Message) }
    }
    $done = { [pscustomobject]@{ State = $res.State; Queue = $res.Queue; Trigger = $res.Trigger; Role = $res.Role; Row = $res.Row; Lines = $res.Lines.ToArray() } }
    $off = { param($why) & $say 'warn' ('job requests: {0} -- the web app''s buttons work as before; the next update tries again' -f $why); & $setRow ''; $res.State = 'off'; & $done }
    try {
        # ---- the job (made by the missing-jobs step) ----
        $jobPath = '{0}/providers/Microsoft.App/jobs/{1}?api-version={2}' -f $rg, $c.Job, $c.JobsApi
        $job = $null
        try { $job = & $Arm 'GET' $jobPath $null } catch { return (& $off ('{0} could not be read ({1})' -f $c.Job, $_.Exception.Message)) }
        if (-not $job) { $res.State = 'no-job'; & $say 'info' ('job requests: {0} is not at this install yet (the update''s missing-jobs step makes it) -- the web app''s buttons work as before' -f $c.Job); & $setRow ''; return (& $done) }
        $acct = Get-SISupportGrantJobEnvValue -Job $job -Name 'SI_STORAGE_ACCOUNT'
        if (-not $acct) { return (& $off ('{0} names no storage account (SI_STORAGE_ACCOUNT)' -f $c.Job)) }

        # ---- 1. the queue ----
        $qPath = '{0}/providers/Microsoft.Storage/storageAccounts/{1}/queueServices/default/queues/{2}?api-version={3}' -f $rg, $acct, $c.Queue, $c.StorageApi
        $q = $null; try { $q = & $Arm 'GET' $qPath $null } catch { return (& $off ('the queue {0} could not be read ({1})' -f $c.Queue, $_.Exception.Message)) }
        if ($q) { $res.Queue = 'present' } else {
            try { $null = & $Arm 'PUT' $qPath ([ordered]@{ properties = [ordered]@{} }) } catch { return (& $off ('the queue {0} was not made in {1} ({2})' -f $c.Queue, $acct, $_.Exception.Message)) }
            $q = $null; for ($i = 1; $i -le [Math]::Max(1, $Tries) -and -not $q; $i++) { try { $q = & $Arm 'GET' $qPath $null } catch { $q = $null }; if (-not $q -and $i -lt $Tries) { & $Sleep $WaitSeconds } }
            if (-not $q) { return (& $off ('the queue {0} was made but does not read back yet' -f $c.Queue)) }
            $res.Queue = 'created'; & $say 'info' ('job requests: the queue {0} was made in {1}, and read back' -f $c.Queue, $acct)
        }

        # ---- 2. the job started by that queue, signed in as the engine identity ----
        $st = Get-SISupportGrantTriggerState -Job $job -StorageAccount $acct -Queue $c.Queue
        if ($st.State -eq 'cannot') { return (& $off ('{0} cannot be started by its queue -- {1}' -f $c.Job, $st.Why)) }
        if ($st.State -eq 'event') { $res.Trigger = 'present' } else {
            try { $null = & $Arm 'PATCH' $jobPath (Get-SISupportGrantTriggerPatch -Job $job -StorageAccount $st.Account -IdentityResourceId $st.Identity -Queue $c.Queue) }
            catch { return (& $off ('{0} was not moved to its queue ({1})' -f $c.Job, $_.Exception.Message)) }
            $back = $false
            for ($i = 1; $i -le [Math]::Max(1, $Tries); $i++) {
                $j = $null; try { $j = & $Arm 'GET' $jobPath $null } catch { $j = $null }
                $ps = [string](Get-SISupportGrantProp $j @('properties', 'provisioningState'))
                if ($j -and (-not $ps -or $ps -eq 'Succeeded') -and (Get-SISupportGrantTriggerState -Job $j -StorageAccount $st.Account -Queue $c.Queue).State -eq 'event') { $back = $true; break }
                if ($i -lt $Tries) { & $Sleep $WaitSeconds }
            }
            if (-not $back) { return (& $off ('{0} was moved to its queue trigger but does not read back that way yet' -f $c.Job)) }
            $res.Trigger = 'converted'; & $say 'info' ('job requests: {0} is now started by its queue {1} (event trigger, the queue read as the engine identity), and read back' -f $c.Job, $c.Queue)
        }

        # ---- 3. the web app's ONE right: Storage Queue Data Message Sender on that queue only ----
        $app = $null
        try { $app = & $Arm 'GET' ('{0}/providers/Microsoft.App/containerApps/{1}?api-version={2}' -f $rg, $WebApp, $c.AppsApi) $null } catch { return (& $off ('the web app {0} could not be read ({1})' -f $WebApp, $_.Exception.Message)) }
        if (-not $app) { return (& $off ('the web app {0} is not in the resource group' -f $WebApp)) }
        $pids = @(Get-SIJobRequestWebPrincipals -App $app)
        if (-not $pids.Count) { return (& $off ('the web app {0} has no managed identity' -f $WebApp)) }
        $scope = Get-SIJobRequestQueueScope -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -StorageAccount $acct
        $roleDef = '/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions/{1}' -f $SubscriptionId, $c.SenderRole
        $made = 0
        foreach ($p in $pids) {
            $have = $false
            try {
                $list = & $Arm 'GET' ('{0}/providers/Microsoft.Authorization/roleAssignments?api-version={1}&$filter={2}' -f $scope, $c.AuthApi, [uri]::EscapeDataString("principalId eq '$p'")) $null
                $have = [bool]@(@(Get-SISupportGrantProp $list @('value')) | Where-Object {
                    $_ -and ([string](Get-SISupportGrantProp $_ @('properties', 'roleDefinitionId'))).ToLowerInvariant().EndsWith('/' + $c.SenderRole) -and
                    ([string](Get-SISupportGrantProp $_ @('properties', 'scope'))).TrimEnd('/') -ieq $scope }).Count
            } catch { return (& $off ('the web app''s rights on the queue could not be read ({0})' -f $_.Exception.Message)) }
            if ($have) { continue }
            $aPath = '{0}/providers/Microsoft.Authorization/roleAssignments/{1}?api-version={2}' -f $scope, (Get-SIJobRequestAssignmentName -Scope $scope -PrincipalId $p), $c.AuthApi
            try { $null = & $Arm 'PUT' $aPath ([ordered]@{ properties = [ordered]@{ roleDefinitionId = $roleDef; principalId = $p; principalType = 'ServicePrincipal' } }) }
            catch {
                $res.Role = 'refused'
                # Invardia 2026-11-25: at a customer the updater's condition does not cover this role -- the Invardia Support app gives it
                # (the customer's admin re-runs its setup script at the Setup level); every run checks again and turns the switch on once it is there
                & $say 'note' $script:SIJobRequestsNeedRightLine
                & $setRow ''; $res.State = 'off'; return (& $done)
            }
            $ok = $false
            for ($i = 1; $i -le [Math]::Max(1, $Tries); $i++) { $a = $null; try { $a = & $Arm 'GET' $aPath $null } catch { $a = $null }; if ($a) { $ok = $true; break }; if ($i -lt $Tries) { & $Sleep $WaitSeconds } }
            if (-not $ok) { return (& $off ('the web app''s "Storage Queue Data Message Sender" on {0} was given but does not read back yet' -f $c.Queue)) }
            $made++
            & $say 'info' ('job requests: the web app''s identity {0} holds "Storage Queue Data Message Sender" on the queue {1} only ({2}), read back' -f $p, $c.Queue, $scope)
        }
        $res.Role = if ($made) { 'granted' } else { 'present' }

        # ---- 4. the switch the web app reads ----
        & $setRow (Get-SIJobRequestQueueUri -StorageAccount $acct)
        $res.State = if ($res.Row -in 'written', 'unchanged') { 'on' } else { 'off' }
        & $done
    } catch { & $off ('not checked ({0})' -f $_.Exception.Message) }
}
