#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight Pro: installs the Invardia Support app's JUST-IN-TIME database grant on an EXISTING install -- the one
    Support-session step per install (#1021). PLAN by default. It only ADDS: today's access stays until the later,
    customer-run cut-over.

.DESCRIPTION
    THE PRODUCT DOES THIS NOW: the install's database setup job (caj-si-dbinit) makes the support grant's tables and signed procedures (in a run that names the Invardia Support app)
    as its own identity -- at the install and on every update -- so no person needs database admin rights for it. This
    script stays as a fallback: run it only when Invardia support asks for it.

    Run by Invardia support inside the environment's Support session (every statement through Invardia's audited
    Invoke-InvardiaSupportSql, every Azure call through its recorder):
        . Connect-InvardiaSupport.ps1 -Environment <handle> -Reason 'SI support grant' -Ticket <n>
        .\setup\Install-SISupportGrantProcedure.ps1 -ResourceGroup <rg> -Server <sql server> -Databases '<pro>;<ledger>'
        (the plan) -- then the same with -Apply

    Per product database (-Databases, ;-separated, the Pro database FIRST), in this order (-Steps, ;-separated, default all):
      schema   the support grant tables, the consent trigger and the four procedures (created once, never altered); a
               procedure whose text is exactly an earlier release's is replaced by this release's (then signed below)
      user     the Support app's own database user (if it has none) and the standing READ-ONLY role si_support_read --
               framework 4a: the read-only path exists BEFORE any admin right becomes just in time
      consent  the customer's consent: the Pro database's row when it has one (copied to the other databases), else
               DERIVED from the Support app's role on the install's Key Vault (Secrets Officer = setup, Reader =
               troubleshoot; owner 2026-11-01); no such role = no consent (nothing is written: the support grant then
               refuses, exit 3 -- the customer's admin grants it with Grant-SISupportAccess). Never a level given here.
      sign     the four procedures signed with a new in-database certificate in db_owner (2099, private key removed) --
               only a procedure whose text is this release's; only when unsigned
      grants   EXECUTE for the engine (and the web app's sweep); no product role may write the three tables
    and once for the install:
      roles    the Support app's ONE Azure role: Storage Queue Data Message Sender on the queue si-support-requests --
               nothing on any job. Then the job caj-si-support-grant is made STARTED BY ITS QUEUE (event trigger, the
               queue read as the engine identity), read back, and only then every role assignment the Support app holds
               on a caj-si-* job is REMOVED, read back (framework 5.5: the Support app holds no right on any job).
               Needs role assignment rights (the Support app has them at the setup level); without them the run says the
               task for the customer's admin and goes on.
    At an install where the Support app is already READ-ONLY in the databases (its standing admin taken away), -Apply runs
    the database steps under the support grant (setup level, at most 1 hour): opened first, read back, the steps made, the
    grant closed again -- each said in one line. When the grant cannot be opened, no database step is made and the run
    says why (NOT COMPLETE). Where the Support app still holds the right, no grant is asked.
    then THE READ-BACK (read only) per database: tables, procedures (this release's, signed, key removed, signer in db_owner),
    the user and its read-only role, the consent, the engine's EXECUTE.

    What it NEVER does: remove a role (except the Support app's own rights on the caj-si-* jobs, above), a user, a group
    member or an app owner; touch the server's administrator; give a
    level. The proof that follows (docs\TESTS.md, "#1021 live proof"): a JIT open with the heartbeat job disabled, a real
    sign-in as the Support app at its level, the close, the real sign-in again (read only).

#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.()-]{1,90}$')][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$Server,
    # ;-separated, the Pro database first (then the identity ledger, the data database where the install has them)
    [Parameter(Mandatory)][string]$Databases,
    [string]$SubscriptionId,
    # the Invardia Support app's client id; in the Support app's own session it may be left out
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SupportAppId = '',
    [string]$StorageAccount = '',
    [string]$KeyVaultName = '',
    [string]$Steps = 'schema;user;consent;sign;grants;roles',
    [switch]$Apply,
    [string]$Reason = 'SecurityInsight support grant (just in time): install',
    # TEST SEAMS: replace the Support session
    [scriptblock]$Arm, [scriptblock]$Graph, [scriptblock]$Sql,
    [switch]$PassThru,
    # TEST SEAM: the support grant's open / close (the Support session's Open- / Close-InvardiaSupportGrant)
    [System.Collections.IDictionary]$SupportGrant
)

$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportCutover.ps1'))
. ([IO.Path]::Combine($siRoot, 'engine', 'pro-settings', 'SI-SupportGrantSql.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportGrantUpdate.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportWrite.ps1'))
if (-not (Get-Command -Name Get-SISupportAppServicePrincipal -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($siRoot, 'engine', '_shared', 'SI-SupportSqlAccess.ps1')) }

$seams = New-SICutoverSeams -Arm $Arm -Graph $Graph -Sql $Sql -Reason $Reason
$sess = $null; if (Get-Command -Name Get-SISupportSession -ErrorAction SilentlyContinue) { try { $sess = Get-SISupportSession } catch { $sess = $null } }
if (-not $SubscriptionId) { $SubscriptionId = if ($sess) { [string]$sess.SubscriptionId } else { '' } }
if (-not $SubscriptionId) { throw 'Give -SubscriptionId: the Support session names no subscription. Nothing was sent.' }
if (-not $SupportAppId) { $SupportAppId = if ($sess) { [string]$sess.AppId } else { '' } }
if (-not $SupportAppId) { throw 'Give -SupportAppId: the Invardia Support app''s client id (the Support session names none). Nothing was sent.' }
$valid = @('schema', 'user', 'consent', 'sign', 'grants', 'roles')
$chosen = @($Steps -split '\s*;\s*' | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
$bad = @($chosen | Where-Object { $_ -notin $valid })
if ($bad.Count) { throw ("Refused: unknown step(s) {0} -- the steps are {1} (;-separated). Nothing was sent." -f ($bad -join ', '), ($valid -join ';')) }
$dbs = @($Databases -split '\s*;\s*' | Where-Object { $_ } | Select-Object -Unique)
if (-not $dbs.Count) { throw 'Give -Databases (the Pro database first). Nothing was sent.' }

$result = [ordered]@{ Applied = [bool]$Apply; Ok = $false; Lines = New-Object System.Collections.Generic.List[string]; Databases = @(); Roles = @(); Consent = '' }
$say = { param([string]$c, [string]$t) Write-Host ('  ' + $t) -ForegroundColor $c }
# each row on its own (callers take [0]), whatever shape the seam answers in
$call = { param([string]$Db, [string]$Purpose, [string]$Query, [bool]$ReadOnly) @(& $seams.Sql $Server $Db $Query ('SI support grant: ' + $Purpose) $ReadOnly | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
$val = { param($r, $k) if ($null -eq $r) { '' } elseif ($r -is [System.Collections.IDictionary]) { [string]$r[$k] } elseif ($r -is [System.Data.DataRow]) { [string]$r[$k] } elseif ($r.PSObject.Properties[$k]) { [string]$r.$k } else { '' } }
Write-Host ('SecurityInsight support grant (just in time) -- {0}: {1}{2}' -f $Server, ($dbs -join ', '), $(if ($Apply) { '' } else { ' -- PLAN (nothing is changed; add -Apply)' })) -ForegroundColor Cyan

# ---- the Support app in this tenant (its name for the database user; its object id for the roles) ----
$sp = $null
try { $sp = Get-SISupportAppServicePrincipal -Graph $seams.Graph -ClientId $SupportAppId } catch { & $say 'Yellow' ('the Support app could not be looked up ({0})' -f $_.Exception.Message) }
$userName = if ($sp -and $sp.DisplayName) { [string]$sp.DisplayName } else { 'invardia-support-app' }

# ---- the consent: the Pro database's own, else derived from the Key Vault role ----
$level = ''; $source = 'derived'
if ($chosen -contains 'consent') {
    try {
        $row = @(& $call $dbs[0] 'read the consent (read-only)' (Get-SISupportGrantConsentReadSql) $true)[0]
        $have = (& $val $row 'Consent').Trim()
        if ($have -and $have -ne '-') { $level, $source = $have -split '\|', 2; & $say 'Gray' ('consent on the Pro database: {0} ({1}) -- copied to the other databases' -f $level, $source) }
    } catch { & $say 'Yellow' ('the consent could not be read ({0})' -f $_.Exception.Message) }
    if (-not $level -and $sp -and $KeyVaultName) {
        try {
            $scope = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.KeyVault/vaults/{2}' -f $SubscriptionId, $ResourceGroup, $KeyVaultName
            $ra = & $seams.Arm 'GET' ('{0}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter={1}' -f $scope, [uri]::EscapeDataString("principalId eq '$($sp.Id)'")) $null
            $level = Get-SISupportGrantDerivedLevel -RoleDefinitionIds @(@($ra.value) | Where-Object { $_ } | ForEach-Object { [string]$_.properties.roleDefinitionId })
            $source = 'derived'
            if ($level) { & $say 'Gray' ('consent DERIVED from the Support app''s Key Vault role: {0}' -f $level) }
        } catch { & $say 'Yellow' ('the Support app''s Key Vault role could not be read ({0})' -f $_.Exception.Message) }
    }
    if (-not $level) { $result.Lines.Add('no consent: the Support app has no recorded consent and no Key Vault role that shows one -- the support grant will refuse (exit 3) until the customer''s admin runs Grant-SISupportAccess') }
    $result.Consent = $(if ($level) { '{0} ({1})' -f $level, $source } else { '' })
}

# ---- per database ----
$order = @('schema', 'user', 'consent', 'sign', 'grants')
$dbSteps = @($chosen | Where-Object { $order -contains $_ })
$runSteps = {
    foreach ($db in $dbs) {
        $plan = @(Get-SISupportGrantAdminSteps -ClientId $SupportAppId -UserName $userName -Level $(if ($chosen -contains 'consent') { $level } else { '' }) -Source $(if ($source -eq 'customer') { 'customer' } else { 'derived' }) -By ('Invardia support (Install-SISupportGrantProcedure)'))
        $plan = @($plan | Where-Object { $chosen -contains $_.Step } | Sort-Object { $order.IndexOf($_.Step) })
        $i = 0
        foreach ($p in $plan) {
            $i++
            $purpose = '{0}: step {1} of {2} ({3}) -- {4}' -f $db, $i, $plan.Count, $p.Step, $p.Purpose
            if (-not $Apply) { & $say 'Cyan' ('PLAN ' + $purpose); continue }
            try { $r = @(& $call $db $purpose $p.Sql $false)[0]; & $say 'Gray' ('{0} -> {1}' -f $purpose, (& $val $r 'Value')) }
            catch { & $say 'Red' ('{0} FAILED: {1}' -f $purpose, $_.Exception.Message); $result.Lines.Add(('{0}: step {1} failed: {2}' -f $db, $p.Step, $_.Exception.Message)); break }
        }
    }
}
if (-not $Apply -or -not $dbSteps.Count) { & $runSteps }
else {
    # where the Support app is read-only in the databases (just-in-time support access), the steps run under the support
    # grant (setup), opened for them and closed again; where it holds the right (an install not moved yet), as before.
    # A grant that cannot be opened = no step made, said plainly (an install without the signed procedures cannot open
    # one: there the database setup job caj-si-dbinit, or the customer's admin, runs this).
    $sg = $SupportGrant
    if (-not $sg) { $sg = New-SISupportGrantSeams -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -StorageAccount $StorageAccount }
    $ga = Get-SISupportGrantArgs -SupportGrant $sg -Say { param([string]$t, [string]$c) Write-Host ('  ' + $t) -ForegroundColor $(if ($c) { $c } else { 'Gray' }) }
    $ga['Purpose'] = ('the support grant''s database steps ({0}) in {1}' -f ($dbSteps -join ', '), ($dbs -join ', ')); $ga['Tool'] = 'Install-SISupportGrantProcedure'
    $ga['GrantLevel'] = 'setup'; $ga['WriteKind'] = 'setting'; $ga['Do'] = $runSteps
    $ga['Probe'] = { & $call $dbs[0] 'the Support app''s own rights (read-only)' (Get-SISupportAccessProbeSql) $true }
    try { $null = Invoke-SISupportWithGrant @ga }
    catch { & $say 'Red' ('NOT MADE: {0}' -f $_.Exception.Message); $result.Lines.Add(('the database steps failed: {0}' -f $_.Exception.Message)) }
}

# ---- the Support app's two Azure roles ----
if ($chosen -contains 'roles') {
    $rg = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup
    # the queue itself first (live 2026-11-04: the sender role had been given on a queue that was never made, so Invardia's
    # open failed with QueueNotFound at every install) -- made when missing, read back
    if ($StorageAccount) {
        $qPath = '{0}/providers/Microsoft.Storage/storageAccounts/{1}/queueServices/default/queues/si-support-requests?api-version=2023-05-01' -f $rg, $StorageAccount
        $qHave = $null; try { $qHave = & $seams.Arm 'GET' $qPath $null } catch { $qHave = $null }
        if ($qHave) { & $say 'Gray' 'the support request queue si-support-requests: present' }
        elseif (-not $Apply) { & $say 'Cyan' ('PLAN make the support request queue si-support-requests in {0}' -f $StorageAccount) }
        else {
            try {
                $null = & $seams.Arm 'PUT' $qPath @{ properties = @{} }
                $qBack = $null; try { $qBack = & $seams.Arm 'GET' $qPath $null } catch { $qBack = $null }
                if ($qBack) { & $say 'Green' ('the support request queue si-support-requests: made in {0}, read back' -f $StorageAccount) }
                else { $result.Lines.Add('the support request queue si-support-requests was sent but does not read back yet -- run again') }
            } catch { $result.Lines.Add(('the support request queue si-support-requests was not made ({0})' -f $_.Exception.Message)) }
        }
    }
    # #1154 (framework §5.5): the Support app's ONLY right for the support grant is the queue sender role -- the job is started
    # by its queue (below), never by an ARM start (jobs/start/action alone accepts a container override)
    $want = @()
    if ($StorageAccount) { $want += [pscustomobject]@{ Role = 'Storage Queue Data Message Sender'; Id = 'c6a89b2d-59bc-44d0-9896-0f6e12d7b80a'; Scope = ('{0}/providers/Microsoft.Storage/storageAccounts/{1}/queueServices/default/queues/si-support-requests' -f $rg, $StorageAccount) } }
    else { $result.Lines.Add('roles: give -StorageAccount (the install''s storage account) for the queue sender role') }
    foreach ($w in $want) {
        if (-not $sp) { $result.Lines.Add(('roles: {0} -- the Support app is not in this tenant' -f $w.Role)); continue }
        $defId = '/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions/{1}' -f $SubscriptionId, $w.Id
        try {
            $have = & $seams.Arm 'GET' ('{0}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter={1}' -f $w.Scope, [uri]::EscapeDataString("principalId eq '$($sp.Id)'")) $null
            if (@(@($have.value) | Where-Object { $_ -and ([string]$_.properties.roleDefinitionId -split '/')[-1] -ieq $w.Id -and [string]$_.properties.scope -ieq $w.Scope }).Count) { & $say 'Gray' ('{0} on {1}: present' -f $w.Role, ($w.Scope -split '/')[-1]); $result.Roles += $w.Role; continue }
            if (-not $Apply) { & $say 'Cyan' ('PLAN {0} for the Support app on {1}' -f $w.Role, ($w.Scope -split '/')[-1]); continue }
            $null = & $seams.Arm 'PUT' ('{0}/providers/Microsoft.Authorization/roleAssignments/{1}?api-version=2022-04-01' -f $w.Scope, [guid]::NewGuid()) @{ properties = @{ roleDefinitionId = $defId; principalId = [string]$sp.Id; principalType = 'ServicePrincipal' } }
            & $say 'Green' ('{0} on {1}: granted' -f $w.Role, ($w.Scope -split '/')[-1]); $result.Roles += $w.Role
        } catch {
            $result.Lines.Add(('roles: {0} on {1} was not granted ({2}) -- for the customer''s admin: Azure portal > the resource > Access control (IAM) > Add role assignment > {0} > the Invardia Support app' -f $w.Role, $w.Scope, $_.Exception.Message))
        }
    }
    # #1154: the support grant job started by its queue (read back), THEN every right the Support app holds on a caj-si-* job
    # removed (read back) -- the same step the update runs (setup\_shared\SI-SupportGrantUpdate.ps1); PLAN without -Apply
    $tr = Invoke-SISupportGrantQueueTrigger -Arm $seams.Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -StorageAccount $StorageAccount `
              -SupportPrincipalId $(if ($sp) { [string]$sp.Id } else { '' }) -WhatIf:(-not $Apply) `
              -RemoveHow 'for the customer''s admin: Azure portal > the job > Access control (IAM) > Role assignments > remove the Invardia Support app'
    foreach ($l in @($tr.Lines)) { if ($l.Level -eq 'warn') { $result.Lines.Add(('roles: {0}' -f $l.Text)) } else { & $say $(if ($Apply) { 'Green' } else { 'Cyan' }) $(if ($Apply) { $l.Text } else { 'PLAN ' + $l.Text }) } }
}

# ---- THE READ-BACK ----
$all = $true
foreach ($db in $dbs) {
    try {
        $st = ConvertFrom-SISupportGrantState -Row (@(& $call $db 'read-back (read-only)' (Get-SISupportGrantStateSql -ClientId $SupportAppId) $true)[0])
        $result.Databases += $st
        if ($st.Ok) { & $say 'Green' ('{0}: in place -- 4 procedures signed (2099, key removed), the read-only role, consent {1}, the engine may EXECUTE them' -f $db, $st.Consent) }
        else { $all = $false; foreach ($l in $st.Lines) { & $say 'Yellow' ('{0}: {1}' -f $db, $l) } }
    } catch { $all = $false; & $say 'Red' ('{0}: the read-back failed: {1}' -f $db, $_.Exception.Message) }
}
foreach ($l in $result.Lines) { & $say 'Yellow' $l }
$result.Ok = [bool]($Apply -and $all -and -not @($result.Lines | Where-Object { $_ -match 'failed' }).Count)
if (-not $Apply) { Write-Host 'PLAN only -- nothing was changed. Re-run with -Apply.' -ForegroundColor Yellow; $result.Ok = $true }
elseif ($result.Ok) { Write-Host 'PASS: the support grant is in place; nothing of today''s access was removed. Next: the live proof (a JIT open with the heartbeat disabled, a real sign-in, the close).' -ForegroundColor Green }
else { Write-Host 'NOT COMPLETE: see the lines above; nothing of today''s access was removed.' -ForegroundColor Yellow }
if ($PassThru) { [pscustomobject]$result } elseif (-not $result.Ok) { exit 1 }
