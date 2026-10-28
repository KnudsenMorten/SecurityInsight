#Requires -Version 5.1
<#
    SECURITY BASELINE QUICK WINS (framework DOCS/REQUIREMENTS.md §12.11f CR8 items 4 + 5, §12.23 P7 / P8; SI #659).
    ONE library for the three changes, used by BOTH ways they reach an install:
      - a NEW install: the setup scripts, ONLY while the switch below is on (default OFF -- REMOVE-ME, see
        Test-SISecurityBaselineNewInstall);
      - an EXISTING install: setup\Set-SICr8QuickWins.ps1, run through the Invardia Support app, one environment at a time
        (check first, a rollback record, read back after every change).
    The product updater changes NONE of this (§12.23 P8: "the updater changes no security; it only checks for drift").

      1. the container registry's admin user OFF -- a static user name + password that can PUSH the image every job runs;
         only when no job and no app pulls with it (a managed-identity install pulls as its identity). Reversible.
      2. Key Vault purge protection ON -- a deleted vault (and its secrets) cannot be purged before its retention ends.
         ONE-WAY: Azure never turns purge protection off again.
      3. SQL auditing ON for the install's database server (every database on it) to the install's own Log Analytics
         workspace (diagnostic setting -> table SQLSecurityAuditEvents), the table kept at least 90 days. Reversible (the
         auditing setting is put back, the diagnostic setting removed). The same model PIM uses.

    Every function that talks to Azure takes -Arm, a script block  { param([string]$Method, [string]$Path, $Body) }:
    -Path is '/subscriptions/...?api-version=...'; it returns the parsed answer, $null for "not found" on a GET, and
    THROWS on any other error. Setup passes Invoke-SIArm; the cut-over passes the Support session's recording
    Invoke-InvardiaSupportArm; the tests pass a fake. No module, no az.
    PS 5.1 safe.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

$script:SIBaselineAcrApi   = '2023-07-01'
$script:SIBaselineKvApi    = '2023-07-01'
$script:SIBaselineSqlApi   = '2021-11-01'
$script:SIBaselineDiagApi  = '2021-05-01-preview'
$script:SIBaselineLawApi   = '2022-10-01'
$script:SIBaselineAppApi   = '2025-07-01'
$script:SIBaselineAuditDiagName = 'si-sql-audit'
$script:SIBaselineAuditTable    = 'SQLSecurityAuditEvents'
$script:SIBaselineAuditDays     = 90

# REMOVE-ME once a fresh test install has proven all three on a new install: OFF by default. Customer sites are installed
# with today's setup while this is new (owner 2026-10-14, §12.23 P8): nothing may change what a new install builds until
# a fresh test install proves it. On: SI_SECURITY_BASELINE_NEW_INSTALL=1 in the environment of the install.
$script:SIBaselineNewInstallDefault = $false

function Test-SISecurityBaselineNewInstall {
    <# PURE over the switch. True when a new install builds the security baseline (the registry's admin user off, Key
       Vault purge protection on, SQL auditing on): SI_SECURITY_BASELINE_NEW_INSTALL = 1 / true / on / yes; anything
       else (unset included) = the built-in default (OFF, see above). #>
    param([AllowNull()][string]$Value = $env:SI_SECURITY_BASELINE_NEW_INSTALL, [bool]$Default = $script:SIBaselineNewInstallDefault)
    $v = ([string]$Value).Trim().ToLowerInvariant()
    if ($v -in '1', 'true', 'on', 'yes') { return $true }
    if ($v -in '0', 'false', 'off', 'no') { return $false }
    return [bool]$Default
}

function Get-SIBaselineProp {
    <# PURE. A nested property of an ARM object (PSCustomObject or hashtable), $null when any step is missing. #>
    param($Object, [string[]]$Names)
    $o = $Object
    foreach ($n in $Names) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o = $o[$n] } else { return $null }; continue }
        $p = $o.PSObject.Properties[$n]
        if (-not $p) { return $null }
        $o = $p.Value
    }
    $o
}

function Get-SIBaselineEnvValue {
    <# PURE. The first non-empty value of environment variable -Name on any container of the given jobs / apps (ARM shape:
       properties.template.containers[].env[]). '' when none carries it. #>
    param([object[]]$Resources = @(), [Parameter(Mandatory)][string]$Name)
    foreach ($r in @($Resources | Where-Object { $null -ne $_ })) {
        foreach ($c in @(Get-SIBaselineProp $r @('properties', 'template', 'containers'))) {
            foreach ($e in @(Get-SIBaselineProp $c @('env'))) {
                if ($null -eq $e) { continue }
                if ([string](Get-SIBaselineProp $e @('name')) -eq $Name) {
                    $val = [string](Get-SIBaselineProp $e @('value'))
                    if ($val.Trim()) { return $val.Trim() }
                }
            }
        }
    }
    ''
}

function Get-SIBaselineArmList {
    <# Every item of an ARM list (follows nextLink). -Path includes the api-version. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path)
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Path
    for ($i = 0; $next -and $i -lt 50; $i++) {
        $page = & $Arm 'GET' $next $null
        if (-not $page) { break }
        foreach ($v in @(Get-SIBaselineProp $page @('value'))) { if ($null -ne $v) { $items.Add($v) } }
        $nl = [string](Get-SIBaselineProp $page @('nextLink'))
        $next = if ($nl) { $nl -replace '^https://management\.azure\.com', '' } else { '' }
    }
    $items.ToArray()
}

function Read-SIBaselineBack {
    <# Reads -Path back until -Test is true about it (an ARM change may finish a moment after its answer), at most -Tries
       reads, -PauseSeconds apart. Returns the last read. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][scriptblock]$Test,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$Tries = 6, [int]$PauseSeconds = 5)
    $o = $null
    for ($i = 1; $i -le $Tries; $i++) {
        $o = & $Arm 'GET' $Path $null
        if ($o -and (& $Test $o)) { return $o }
        if ($i -lt $Tries) { & $Sleep $PauseSeconds }
    }
    $o
}

# ============================================================================================================== 1. REGISTRY

function Get-SIRegistryAdminDecision {
    <#
        PURE. -Registry: the registry as ARM returns it (properties.adminUserEnabled, properties.loginServer). -Apps: the
        jobs and container apps that may pull from it (properties.configuration.registries[]).
        @{ Action = 'none' | 'off' | 'keep'; Reason; Users = names still pulling with the password }.
        'keep' = a job or app still signs in to THIS registry with its password: turning it off would stop that pull.
    #>
    param($Registry, [object[]]$Apps = @())
    $p = Get-SIBaselineProp $Registry @('properties')
    if (-not $p) { return @{ Action = 'none'; Reason = 'no container registry was found'; Users = @() } }
    if (-not [bool](Get-SIBaselineProp $p @('adminUserEnabled'))) { return @{ Action = 'none'; Reason = 'the registry''s admin user is already off'; Users = @() } }
    $server = ([string](Get-SIBaselineProp $p @('loginServer'))).Trim().ToLowerInvariant()
    $users = New-Object System.Collections.Generic.List[string]
    foreach ($a in @($Apps | Where-Object { $null -ne $_ })) {
        foreach ($r in @(Get-SIBaselineProp $a @('properties', 'configuration', 'registries'))) {
            if ($null -eq $r) { continue }
            $rs = ([string](Get-SIBaselineProp $r @('server'))).Trim().ToLowerInvariant()
            $pw = ([string](Get-SIBaselineProp $r @('passwordSecretRef'))).Trim()
            if ($pw -and (-not $server -or -not $rs -or $rs -eq $server)) { $users.Add([string](Get-SIBaselineProp $a @('name'))); break }
        }
    }
    if ($users.Count) {
        return @{ Action = 'keep'; Users = $users.ToArray()
                  Reason = ('the registry''s admin user stays on: {0} still pull(s) the image with its password -- they must pull as their managed identity first (run setup again with the managed identity)' -f ($users -join ', ')) }
    }
    @{ Action = 'off'; Reason = 'every job and app pulls its image as its managed identity: the registry''s admin user (a password that can replace the image) can be turned off'; Users = @() }
}

function Get-SIRegistryAdminPatchBody {
    <# PURE. The PATCH body that switches the registry's admin user on or off. #>
    param([Parameter(Mandatory)][bool]$Enabled)
    @{ properties = @{ adminUserEnabled = $Enabled } }
}

function Set-SIRegistryAdmin {
    <# Switches the registry's admin user (-Enabled) and READS IT BACK. Returns @{ Ok; Line }. Never throws for a read-back
       that disagrees (Ok = $false, said); throws when Azure refuses the change. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$RegistryId, [Parameter(Mandatory)][bool]$Enabled, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $path = '{0}?api-version={1}' -f $RegistryId.TrimEnd('/'), $script:SIBaselineAcrApi
    $null = & $Arm 'PATCH' $path (Get-SIRegistryAdminPatchBody -Enabled $Enabled)
    $back = Read-SIBaselineBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) [bool](Get-SIBaselineProp $o @('properties', 'adminUserEnabled')) -eq $Enabled }
    $now = [bool](Get-SIBaselineProp $back @('properties', 'adminUserEnabled'))
    $name = ($RegistryId -split '/')[-1]
    if ($now -eq $Enabled) { return @{ Ok = $true; Line = ('the admin user of registry {0} is {1} (read back)' -f $name, $(if ($Enabled) { 'ON' } else { 'OFF' })) } }
    @{ Ok = $false; Line = ('the admin user of registry {0} still reads {1} after the change' -f $name, $(if ($now) { 'ON' } else { 'OFF' })) }
}

# ============================================================================================================== 2. KEY VAULT

function Get-SIKeyVaultPurgeDecision {
    <# PURE. -Vault: the vault as ARM returns it. @{ Action = 'none' | 'on'; Reason }. ONE-WAY: Azure never turns purge
       protection off again, so 'on' is said with that. #>
    param($Vault)
    $p = Get-SIBaselineProp $Vault @('properties')
    if (-not $p) { return @{ Action = 'none'; Reason = 'no Key Vault was found' } }
    if ([bool](Get-SIBaselineProp $p @('enablePurgeProtection'))) { return @{ Action = 'none'; Reason = 'purge protection is already on' } }
    $days = Get-SIBaselineProp $p @('softDeleteRetentionInDays')
    $d = if ($null -ne $days -and "$days" -ne '') { [int]$days } else { 90 }
    @{ Action = 'on'; Reason = ('purge protection can be turned on: a deleted vault and its secrets then cannot be purged for {0} days -- ONE-WAY, Azure never turns it off again; the vault''s name stays taken for those days after a delete' -f $d) }
}

function Set-SIKeyVaultPurgeProtection {
    <# Turns purge protection ON and READS IT BACK. ONE-WAY (there is no off). Returns @{ Ok; Line }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$VaultId, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $path = '{0}?api-version={1}' -f $VaultId.TrimEnd('/'), $script:SIBaselineKvApi
    $null = & $Arm 'PATCH' $path @{ properties = @{ enablePurgeProtection = $true } }
    $back = Read-SIBaselineBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) [bool](Get-SIBaselineProp $o @('properties', 'enablePurgeProtection')) }
    $name = ($VaultId -split '/')[-1]
    if ([bool](Get-SIBaselineProp $back @('properties', 'enablePurgeProtection'))) { return @{ Ok = $true; Line = ('Key Vault {0}: purge protection ON (read back; one-way)' -f $name) } }
    @{ Ok = $false; Line = ('Key Vault {0}: purge protection still reads off after the change' -f $name) }
}

# ============================================================================================================== 3. SQL AUDIT

function Get-SISqlAuditDiagnosticBody {
    <# PURE. The diagnostic setting on the server's master database that sends the audit to the workspace, into the
       resource-specific table SQLSecurityAuditEvents (Dedicated). #>
    param([Parameter(Mandatory)][string]$WorkspaceResourceId)
    @{ properties = @{ workspaceId = $WorkspaceResourceId; logAnalyticsDestinationType = 'Dedicated'
                       logs = @(@{ category = $script:SIBaselineAuditTable; enabled = $true }) } }
}

function Get-SISqlAuditSettingBody {
    <# PURE. The server's auditing setting: on, to Azure Monitor (the diagnostic setting above). The audited action groups
       are Azure's defaults (successful + failed sign-ins and every batch) -- the same as PIM. #>
    @{ properties = @{ state = 'Enabled'; isAzureMonitorTargetEnabled = $true } }
}

function Test-SISqlAuditDiagnosticMatch {
    <# PURE. Does diagnostic setting -Setting send SQLSecurityAuditEvents to -WorkspaceResourceId? #>
    param($Setting, [Parameter(Mandatory)][string]$WorkspaceResourceId)
    $ws = [string](Get-SIBaselineProp $Setting @('properties', 'workspaceId'))
    if ($ws.Trim().ToLowerInvariant() -ne $WorkspaceResourceId.Trim().ToLowerInvariant()) { return $false }
    foreach ($l in @(Get-SIBaselineProp $Setting @('properties', 'logs'))) {
        if ($null -eq $l) { continue }
        $cat = [string](Get-SIBaselineProp $l @('category')); $grp = [string](Get-SIBaselineProp $l @('categoryGroup'))
        if ([bool](Get-SIBaselineProp $l @('enabled')) -and ($cat -eq $script:SIBaselineAuditTable -or $grp -in 'audit', 'allLogs')) { return $true }
    }
    $false
}

function Get-SISqlAuditDecision {
    <#
        PURE. -Auditing: the server's auditingSettings/default; -DiagnosticSettings: the master database's diagnostic
        settings; -Table: the workspace's SQLSecurityAuditEvents table ($null = not there yet).
        @{ Action = 'none' | 'on' | 'retention'; Reason; NeedsAuditing; NeedsDiagnostic; NeedsRetention }.
        Retention is only ever RAISED to 90 days, never lowered.
    #>
    param($Auditing, [object[]]$DiagnosticSettings = @(), $Table, [Parameter(Mandatory)][string]$WorkspaceResourceId, [int]$Days = $script:SIBaselineAuditDays)
    $on = ([string](Get-SIBaselineProp $Auditing @('properties', 'state'))) -eq 'Enabled' -and [bool](Get-SIBaselineProp $Auditing @('properties', 'isAzureMonitorTargetEnabled'))
    $diag = [bool]@($DiagnosticSettings | Where-Object { $null -ne $_ -and (Test-SISqlAuditDiagnosticMatch -Setting $_ -WorkspaceResourceId $WorkspaceResourceId) }).Count
    $ret = $null
    if ($Table) {
        $r = Get-SIBaselineProp $Table @('properties', 'retentionInDays')
        if ($null -eq $r -or "$r" -eq '' -or [int]$r -lt 0) { $r = Get-SIBaselineProp $Table @('properties', 'totalRetentionInDays') }
        if ($null -ne $r -and "$r" -ne '') { $ret = [int]$r }
    }
    $needRet = ($null -eq $ret) -or ($ret -lt $Days)
    $ws = ($WorkspaceResourceId -split '/')[-1]
    if ($on -and $diag -and -not $needRet) { return @{ Action = 'none'; NeedsAuditing = $false; NeedsDiagnostic = $false; NeedsRetention = $false; Reason = ('SQL auditing is on to {0}; {1} is kept {2} days' -f $ws, $script:SIBaselineAuditTable, $ret) } }
    if ($on -and $diag) { return @{ Action = 'retention'; NeedsAuditing = $false; NeedsDiagnostic = $false; NeedsRetention = $true
                                    Reason = ('SQL auditing is on to {0}; {1} is kept {2} -- raise it to {3} days' -f $ws, $script:SIBaselineAuditTable, $(if ($null -eq $ret) { '(the table is not there yet)' } else { '{0} days' -f $ret }), $Days) } }
    @{ Action = 'on'; NeedsAuditing = -not $on; NeedsDiagnostic = -not $diag; NeedsRetention = $needRet
       Reason = ('SQL auditing can be turned on: every sign-in and statement on the database server is recorded in {0} ({1}, kept {2} days)' -f $ws, $script:SIBaselineAuditTable, $Days) }
}

function Set-SISqlServerAudit {
    <#
        Turns SQL auditing on for -ServerId to -WorkspaceResourceId and READS IT BACK: the Microsoft.Insights provider is
        registered when it is not (a diagnostic setting is refused without it -- PIM, 2026-10-14), the diagnostic setting on
        master, the server's auditing setting, then the table's retention raised to 90 days (best effort: the table may
        only appear with the first events -- said, never a failure). Returns @{ Ok; Lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ServerId, [Parameter(Mandatory)][string]$WorkspaceResourceId,
          [int]$Days = $script:SIBaselineAuditDays, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$ProviderWaitSeconds = 300,
          # a diagnostic setting that already sends the audit to the workspace is there (Azure refuses a second one to the
          # same workspace): only the auditing setting and the retention are set
          [switch]$SkipDiagnostic)
    $lines = New-Object System.Collections.Generic.List[string]
    $sub = ($ServerId -split '/')[2]
    $prov = '/subscriptions/{0}/providers/Microsoft.Insights?api-version=2021-04-01' -f $sub
    $p = & $Arm 'GET' $prov $null
    if ([string](Get-SIBaselineProp $p @('registrationState')) -ne 'Registered') {
        $null = & $Arm 'POST' ('/subscriptions/{0}/providers/Microsoft.Insights/register?api-version=2021-04-01' -f $sub) @{}
        $waited = 0
        do { & $Sleep 10; $waited += 10; $p = & $Arm 'GET' $prov $null } while ([string](Get-SIBaselineProp $p @('registrationState')) -ne 'Registered' -and $waited -lt $ProviderWaitSeconds)
        $lines.Add(('the Microsoft.Insights provider: {0}' -f [string](Get-SIBaselineProp $p @('registrationState'))))
    }
    $master = '{0}/databases/master' -f $ServerId.TrimEnd('/')
    $diagPath = '{0}/providers/Microsoft.Insights/diagnosticSettings/{1}?api-version={2}' -f $master, $script:SIBaselineAuditDiagName, $script:SIBaselineDiagApi
    $audPath = '{0}/auditingSettings/default?api-version={1}' -f $ServerId.TrimEnd('/'), $script:SIBaselineSqlApi
    if (-not $SkipDiagnostic) {
        # a provider that reads Registered can still refuse the setting for a while (409 "register the subscription with
        # Microsoft.Insights" -- PIM, 2026-10-14): tried again for up to -ProviderWaitSeconds, then said plainly
        $waited = 0
        while ($true) {
            try { $null = & $Arm 'PUT' $diagPath (Get-SISqlAuditDiagnosticBody -WorkspaceResourceId $WorkspaceResourceId); break }
            catch {
                $m = [string]$_.Exception.Message
                if ($m -notmatch '\b409\b' -or $m -notmatch '(?i)Microsoft\.Insights|register') { throw }
                if ($waited -ge $ProviderWaitSeconds) { throw ('the diagnostic setting is still refused after {0} s: Azure says the subscription is not registered with Microsoft.Insights although the provider reads {1} -- auditing was NOT turned on; try again later ({2})' -f $waited, [string](Get-SIBaselineProp $p @('registrationState')), $m) }
                & $Sleep 30; $waited += 30
            }
        }
    }
    $null = & $Arm 'PUT' $audPath (Get-SISqlAuditSettingBody)
    $diagOk = if ($SkipDiagnostic) {
        [bool]@(Get-SIBaselineArmList -Arm $Arm -Path ('{0}/providers/Microsoft.Insights/diagnosticSettings?api-version={1}' -f $master, $script:SIBaselineDiagApi) | Where-Object { Test-SISqlAuditDiagnosticMatch -Setting $_ -WorkspaceResourceId $WorkspaceResourceId }).Count
    } else { Test-SISqlAuditDiagnosticMatch -Setting (& $Arm 'GET' $diagPath $null) -WorkspaceResourceId $WorkspaceResourceId }
    $audBack = Read-SIBaselineBack -Arm $Arm -Path $audPath -Sleep $Sleep -Test { param($o) ([string](Get-SIBaselineProp $o @('properties', 'state'))) -eq 'Enabled' }
    $ok = $diagOk -and
          ([string](Get-SIBaselineProp $audBack @('properties', 'state'))) -eq 'Enabled' -and [bool](Get-SIBaselineProp $audBack @('properties', 'isAzureMonitorTargetEnabled'))
    $srv = ($ServerId -split '/')[-1]; $ws = ($WorkspaceResourceId -split '/')[-1]
    $lines.Add($(if ($ok) { 'SQL auditing of server {0} is ON to {1} (read back)' -f $srv, $ws } else { 'SQL auditing of server {0} does NOT read back as on to {1}' -f $srv, $ws }))
    $r = Set-SILaTableRetention -Arm $Arm -WorkspaceResourceId $WorkspaceResourceId -Days $Days
    $lines.Add($r.Line)
    @{ Ok = $ok; Lines = $lines.ToArray() }
}

function Set-SILaTableRetention {
    <# Raises the SQLSecurityAuditEvents table's retention to -Days (never lowers it) and reads it back. Best effort: a
       table that is not there yet is said (it appears with the first events; run the check again later). @{ Ok; Line }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$WorkspaceResourceId, [int]$Days = $script:SIBaselineAuditDays)
    $path = '{0}/tables/{1}?api-version={2}' -f $WorkspaceResourceId.TrimEnd('/'), $script:SIBaselineAuditTable, $script:SIBaselineLawApi
    try {
        $t = & $Arm 'GET' $path $null
        $cur = Get-SIBaselineProp $t @('properties', 'retentionInDays')
        if ($t -and $null -ne $cur -and "$cur" -ne '' -and [int]$cur -ge $Days) { return @{ Ok = $true; Line = ('{0} is kept {1} days' -f $script:SIBaselineAuditTable, [int]$cur) } }
        $null = & $Arm 'PATCH' $path @{ properties = @{ retentionInDays = $Days } }
        $back = & $Arm 'GET' $path $null
        $now = Get-SIBaselineProp $back @('properties', 'retentionInDays')
        if ($null -ne $now -and "$now" -ne '' -and [int]$now -ge $Days) { return @{ Ok = $true; Line = ('{0} is kept {1} days (read back)' -f $script:SIBaselineAuditTable, [int]$now) } }
        return @{ Ok = $false; Line = ('{0}: the retention reads {1} after the change -- run the check again later' -f $script:SIBaselineAuditTable, $now) }
    } catch {
        return @{ Ok = $false; Line = ('{0}: the {1}-day retention is set when the table exists (it appears with the first events -- run the check again later): {2}' -f $script:SIBaselineAuditTable, $Days, (([string]$_.Exception.Message) -split "`n")[0]) }
    }
}

function Restore-SISqlServerAudit {
    <# The rollback of Set-SISqlServerAudit: the auditing setting put back as it was (-Before = its properties), the
       diagnostic setting SI made removed (only when it was not there before). The table's retention is left (raising a
       retention loses nothing). Returns @{ Ok; Line }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ServerId, $Before, [bool]$DiagnosticExisted)
    $audPath = '{0}/auditingSettings/default?api-version={1}' -f $ServerId.TrimEnd('/'), $script:SIBaselineSqlApi
    $props = if ($Before) { $Before } else { @{ state = 'Disabled' } }
    $null = & $Arm 'PUT' $audPath @{ properties = $props }
    if (-not $DiagnosticExisted) {
        $diagPath = '{0}/databases/master/providers/Microsoft.Insights/diagnosticSettings/{1}?api-version={2}' -f $ServerId.TrimEnd('/'), $script:SIBaselineAuditDiagName, $script:SIBaselineDiagApi
        try { $null = & $Arm 'DELETE' $diagPath $null } catch { if ([string]$_.Exception.Message -notmatch '\b404\b') { throw } }
    }
    $back = & $Arm 'GET' $audPath $null
    $want = [string](Get-SIBaselineProp @{ properties = $props } @('properties', 'state'))
    $now = [string](Get-SIBaselineProp $back @('properties', 'state'))
    @{ Ok = ($now -eq $want); Line = ('SQL auditing of server {0}: {1} (read back; was {2})' -f ($ServerId -split '/')[-1], $now, $want) }
}

# ============================================================================================================== 4. JOBS ROLE (report only)

function Get-SIJobsRoleFinding {
    <# PURE. CR8 step 1 for SI (the web app's "Container Apps Jobs Contributor" on the resource group -> "Jobs Operator" on
       named jobs) is REPORTED here, never changed: the Jobs page still changes schedules, which Jobs Operator cannot.
       -Assignments: role assignments at the resource group (properties.roleDefinitionId, properties.principalId);
       -WebPrincipalId: the web app's identity. @{ Found; Line }. #>
    param([object[]]$Assignments = @(), [string]$WebPrincipalId)
    $contributor = '4e3d2b60-56ae-4dc6-a233-09c8e5a82e68'
    if (-not $WebPrincipalId) { return @{ Found = $false; Line = 'the web app''s identity was not found -- its jobs role was not checked' } }
    $hit = @($Assignments | Where-Object { $null -ne $_ -and ([string](Get-SIBaselineProp $_ @('properties', 'principalId'))) -eq $WebPrincipalId -and ([string](Get-SIBaselineProp $_ @('properties', 'roleDefinitionId'))) -match ('/' + $contributor + '$') })
    if ($hit.Count) { return @{ Found = $true; Line = 'the web app holds "Container Apps Jobs Contributor" on the resource group (it can change every job there) -- NOT changed here: start-only rights on named jobs would stop the Jobs page from changing job schedules' } }
    @{ Found = $false; Line = 'the web app holds no "Container Apps Jobs Contributor" on the resource group' }
}

# ============================================================================================================== 5. JOBS START-ONLY (CR8 item 1)

$script:SIBaselineRoleApi = '2022-04-01'
$script:SIBaselineJobsRoles = @{ Contributor = 'Container Apps Jobs Contributor'; Operator = 'Container Apps Jobs Operator'; Reader = 'Container Apps Jobs Reader' }
$script:SIBaselineChangeModeEnv = 'Jobs__ChangeMode'

function Get-SIBaselineRoleDefinitionIds {
    <# The role definition ids of the three Container Apps jobs roles, read from Azure BY NAME (never a guessed id).
       @{ Contributor; Operator; Reader } (lower-case GUIDs; '' when Azure does not know the name). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId)
    $out = @{}
    foreach ($k in $script:SIBaselineJobsRoles.Keys) {
        $f = [uri]::EscapeDataString(("roleName eq '{0}'" -f $script:SIBaselineJobsRoles[$k]))
        $l = @(Get-SIBaselineArmList -Arm $Arm -Path ('/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions?$filter={1}&api-version={2}' -f $SubscriptionId, $f, $script:SIBaselineRoleApi))
        $out[$k] = if ($l.Count) { ([string](Get-SIBaselineProp $l[0] @('name'))).ToLowerInvariant() } else { '' }
    }
    $out
}

function Get-SIWebChangeMode {
    <# PURE. The web app's Jobs__ChangeMode as its container says ('' when not set = direct). #>
    param($WebApp)
    Get-SIBaselineEnvValue -Resources @($WebApp) -Name $script:SIBaselineChangeModeEnv
}

function Get-SIJobsStartOnlyDecision {
    <#
        PURE. CR8 item 1 for SI: the web app's rights on the jobs.
          -Assignments  role assignments that apply in the resource group (at the group and at each job: properties.scope,
                        principalId, roleDefinitionId); -Jobs the install's jobs (ARM); -WebPrincipalId; -RoleIds
                        (Get-SIBaselineRoleDefinitionIds); -ChangeMode the web app's Jobs__ChangeMode; -ResourceGroupId.
        @{ Action = 'none' | 'start-only' | 'skip'; ContributorOff = 'none' | 'remove' | 'wait'; Reason; ContributorReason;
           NeedReader (bool); NeedOperator (job ids); Contributor (assignments to remove) }.
        start-only        = Jobs Reader on the group + Jobs Operator on every caj-si-* job + Jobs__ChangeMode=request.
        ContributorOff    = removing Jobs Contributor, ONLY once start-only is complete (a SECOND run, after the pipeline ran green).
    #>
    param([object[]]$Assignments = @(), [object[]]$Jobs = @(), [string]$WebPrincipalId, [hashtable]$RoleIds = @{}, [string]$ChangeMode = '', [string]$ResourceGroupId = '')
    $none = @{ Action = 'skip'; ContributorOff = 'none'; NeedReader = $false; NeedOperator = @(); Contributor = @(); ContributorReason = '' }
    if (-not $WebPrincipalId) { $none.Reason = 'the web app (or its identity) was not found -- nothing to do for the jobs role'; return $none }
    foreach ($k in 'Contributor', 'Operator', 'Reader') { if (-not [string]$RoleIds[$k]) { $none.Reason = ('Azure does not know the role "{0}" here -- not changed' -f $script:SIBaselineJobsRoles[$k]); return $none } }
    $mine = @($Assignments | Where-Object { $null -ne $_ -and ([string](Get-SIBaselineProp $_ @('properties', 'principalId'))) -eq $WebPrincipalId })
    $has = { param($roleKey, $scope) [bool]@($mine | Where-Object { ([string](Get-SIBaselineProp $_ @('properties', 'roleDefinitionId'))).ToLowerInvariant().EndsWith('/' + $RoleIds[$roleKey]) -and ([string](Get-SIBaselineProp $_ @('properties', 'scope'))).TrimEnd('/') -ieq $scope.TrimEnd('/') }).Count }
    $named = @($Jobs | Where-Object { $null -ne $_ -and [string](Get-SIBaselineProp $_ @('name')) -like 'caj-si-*' })
    $needReader = -not (& $has 'Reader' $ResourceGroupId)
    $needOp = @($named | Where-Object { -not (& $has 'Operator' ([string](Get-SIBaselineProp $_ @('id')))) } | ForEach-Object { [string](Get-SIBaselineProp $_ @('id')) })
    $modeOk = ([string]$ChangeMode).Trim().ToLowerInvariant() -eq 'request'
    # only an assignment IN the install's resource group (at the group or a job) -- one made higher up is not this install's to remove
    $contrib = @($mine | Where-Object { ([string](Get-SIBaselineProp $_ @('properties', 'roleDefinitionId'))).ToLowerInvariant().EndsWith('/' + $RoleIds['Contributor']) -and
                                        ([string](Get-SIBaselineProp $_ @('properties', 'scope'))).TrimEnd('/').StartsWith($ResourceGroupId.TrimEnd('/'), [StringComparison]::OrdinalIgnoreCase) })
    $complete = -not $needReader -and -not $needOp.Count -and $modeOk -and $named.Count
    $r = @{ NeedReader = $needReader; NeedOperator = $needOp; Contributor = $contrib }
    if ($complete) { $r.Action = 'none'; $r.Reason = ('the web app is start-only: Jobs Reader on the group, Jobs Operator on {0} job(s), its trigger changes are requests' -f $named.Count) }
    elseif (-not $named.Count) { $r.Action = 'skip'; $r.Reason = 'no caj-si-* job found -- nothing to do' }
    else {
        $r.Action = 'start-only'
        $r.Reason = ('the web app becomes start-only: {0}{1}{2} (its own rights stay until the second run)' -f $(if ($needReader) { 'Jobs Reader on the group; ' } else { '' }), $(if ($needOp.Count) { 'Jobs Operator on {0} job(s); ' -f $needOp.Count } else { '' }), $(if (-not $modeOk) { 'Jobs__ChangeMode=request on the web app' } else { 'its mode is already request' }))
    }
    if (-not $contrib.Count) { $r.ContributorOff = 'none'; $r.ContributorReason = 'the web app holds no Container Apps Jobs Contributor' }
    elseif ($complete) { $r.ContributorOff = 'remove'; $r.ContributorReason = ('Container Apps Jobs Contributor ({0} assignment(s)) can be removed: start-only is in place -- run this only after the pipeline ran green since the first run' -f $contrib.Count) }
    else { $r.ContributorOff = 'wait'; $r.ContributorReason = 'Container Apps Jobs Contributor stays until start-only is complete (the step web-jobs-start-only first, then a green pipeline)' }
    $r
}

function Get-SIRoleAssignmentPutBody {
    <# PURE. A role assignment body (principal type ServicePrincipal: a managed identity). #>
    param([Parameter(Mandatory)][string]$RoleDefinitionId, [Parameter(Mandatory)][string]$PrincipalId)
    @{ properties = @{ roleDefinitionId = $RoleDefinitionId; principalId = $PrincipalId; principalType = 'ServicePrincipal' } }
}

function Add-SIBaselineRoleAssignment {
    <# PUTs one role assignment (a new id) and READS IT BACK. Returns @{ Ok; Id; Line }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][string]$RoleGuid, [Parameter(Mandatory)][string]$PrincipalId, [string]$Label, [string]$AssignmentName = ([guid]::NewGuid().ToString()),
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $id = '{0}/providers/Microsoft.Authorization/roleAssignments/{1}' -f $Scope.TrimEnd('/'), $AssignmentName
    $def = '/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions/{1}' -f $SubscriptionId, $RoleGuid
    $path = '{0}?api-version={1}' -f $id, $script:SIBaselineRoleApi
    $null = & $Arm 'PUT' $path (Get-SIRoleAssignmentPutBody -RoleDefinitionId $def -PrincipalId $PrincipalId)
    $back = Read-SIBaselineBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) ([string](Get-SIBaselineProp $o @('properties', 'principalId'))) -eq $PrincipalId }
    $ok = ([string](Get-SIBaselineProp $back @('properties', 'principalId'))) -eq $PrincipalId
    @{ Ok = $ok; Id = $id; Line = ('{0} on {1}: {2}' -f $Label, ($Scope -split '/')[-1], $(if ($ok) { 'granted (read back)' } else { 'does NOT read back' })) }
}

function Remove-SIBaselineRoleAssignment {
    <# DELETEs one role assignment by id and reads back that it is gone. Absent = nothing to do. @{ Ok; Line }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$AssignmentId, [string]$Label)
    $path = '{0}?api-version={1}' -f $AssignmentId, $script:SIBaselineRoleApi
    try { $null = & $Arm 'DELETE' $path $null } catch { if ([string]$_.Exception.Message -notmatch '\b404\b') { throw } }
    $back = & $Arm 'GET' $path $null
    @{ Ok = (-not $back); Line = ('{0}: {1}' -f $Label, $(if (-not $back) { 'removed (read back)' } else { 'still there after the delete' })) }
}

function Get-SIAppEnvPatchBody {
    <# PURE. The PATCH body that sets (or, with -Value $null / '', removes) one environment variable on EVERY container of a
       container app as ARM returned it -- the WHOLE template is sent back (a template PATCH replaces the container array);
       nothing else of the app is in the body. #>
    param([Parameter(Mandatory)]$App, [Parameter(Mandatory)][string]$Name, [AllowNull()][string]$Value)
    $tpl = (Get-SIBaselineProp $App @('properties', 'template')) | ConvertTo-Json -Depth 30 | ConvertFrom-Json
    foreach ($c in @($tpl.containers)) {
        if ($null -eq $c) { continue }
        $env = @(@(Get-SIBaselineProp $c @('env')) | Where-Object { $null -ne $_ -and [string]$_.name -ne $Name })
        # (a [string] parameter turns $null into '': empty = remove the variable)
        if (-not [string]::IsNullOrEmpty($Value)) { $env += [pscustomobject]@{ name = $Name; value = $Value } }
        if ($c.PSObject.Properties['env']) { $c.env = $env } else { $c | Add-Member -NotePropertyName env -NotePropertyValue $env }
    }
    @{ properties = @{ template = $tpl } }
}

function Set-SIWebChangeMode {
    <# Sets the web app's Jobs__ChangeMode (-Value $null removes it) and READS IT BACK. @{ Ok; Line }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$AppId, [AllowNull()][string]$Value, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $path = '{0}?api-version={1}' -f $AppId.TrimEnd('/'), $script:SIBaselineAppApi
    $app = & $Arm 'GET' $path $null
    if (-not $app) { throw ('the web app {0} was not found' -f ($AppId -split '/')[-1]) }
    $null = & $Arm 'PATCH' $path (Get-SIAppEnvPatchBody -App $app -Name $script:SIBaselineChangeModeEnv -Value $Value)
    $want = [string]$Value
    $back = Read-SIBaselineBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) (Get-SIWebChangeMode -WebApp $o) -eq $want }
    $now = Get-SIWebChangeMode -WebApp $back
    @{ Ok = ($now -eq $want); Line = ('the web app''s {0}: {1} (read back{2})' -f $script:SIBaselineChangeModeEnv, $(if ($now) { $now } else { '(not set = direct)' }), $(if ($now -eq $want) { '' } else { '; WANTED ' + $(if ($want) { $want } else { '(not set)' }) })) }
}

# ============================================================================================================== 6. SECRETS IN SETTINGS (report)

$script:SIBaselineNotSecret = @('AI_MaxTokens', 'AI_MaxTokensPerRequest', 'OpenAI_MaxTokensPerRequest', 'SI_IdentityTokenTenantId', 'SI_CFG_AI_MaxTokens', 'SI_CFG_AI_MaxTokensPerRequest', 'SI_CFG_OpenAI_MaxTokensPerRequest')

function Get-SIPlainSecretFindings {
    <#
        PURE. CR8 item 4 ("no secret in plain settings"), READ-ONLY: on every job and app of the install --
          * an environment variable whose NAME looks like a credential and that carries a plain VALUE (not a secretRef);
          * a Container Apps secret held IN the app (no keyVaultUrl) instead of a Key Vault reference.
        Values are never read or printed (ARM does not return them). Returns @( @{ Resource; Kind = env | secret; Name } ).
    #>
    param([object[]]$Resources = @())
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Resources | Where-Object { $null -ne $_ })) {
        $rn = [string](Get-SIBaselineProp $r @('name'))
        foreach ($c in @(Get-SIBaselineProp $r @('properties', 'template', 'containers'))) {
            foreach ($e in @(Get-SIBaselineProp $c @('env'))) {
                if ($null -eq $e) { continue }
                $n = [string](Get-SIBaselineProp $e @('name')); $v = [string](Get-SIBaselineProp $e @('value'))
                if (-not $v -or [string](Get-SIBaselineProp $e @('secretRef'))) { continue }
                if ($script:SIBaselineNotSecret -contains $n) { continue }
                if ($n -match '(?i)(secret|password|passwd|pwd|apikey|api_key|token|credential|connectionstring|sas|privatekey|pfx|storagekey|accountkey|license)') { $out.Add(@{ Resource = $rn; Kind = 'env'; Name = $n }) }
            }
        }
        foreach ($s in @(Get-SIBaselineProp $r @('properties', 'configuration', 'secrets'))) {
            if ($null -eq $s) { continue }
            if (-not [string](Get-SIBaselineProp $s @('keyVaultUrl'))) { $out.Add(@{ Resource = $rn; Kind = 'secret'; Name = [string](Get-SIBaselineProp $s @('name')) }) }
        }
    }
    $out.ToArray()
}

function Set-SISqlServerAuditSetup {
    <# Setup's call (the guided install, behind the new-install switch): Set-SISqlServerAudit over setup's own ARM sign-in
       (Invoke-SIArm). Returns @{ Ok; Lines }. #>
    param([Parameter(Mandatory)][string]$ServerId, [Parameter(Mandatory)][string]$WorkspaceResourceId, [string]$SubscriptionId)
    $arm = { param([string]$Method, [string]$Path, $Body) if ($Method -eq 'GET') { Invoke-SIArm -Path $Path -AllowNotFound } else { Invoke-SIArm -Method $Method -Path $Path -Body $Body } }
    Set-SISqlServerAudit -Arm $arm -ServerId $ServerId -WorkspaceResourceId $WorkspaceResourceId
}
