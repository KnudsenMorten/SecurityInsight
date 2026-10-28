<#
.SYNOPSIS
    SecurityInsight: the security baseline quick wins on ONE existing install, through the Invardia Support app -- the
    container registry's admin user off, Key Vault purge protection on, SQL auditing to the install's Log Analytics.

.DESCRIPTION
    An EXISTING install gets these by a scripted cut-over per environment, run by Invardia support inside that
    environment's Support session (framework DOCS/REQUIREMENTS.md §12.23 P8). The pattern is setup\_shared\
    SI-SupportCutover.ps1: every Azure call goes through the session's recording commands (the customer's audit log); the
    product updater changes none of this. A NEW install gets the same from setup only while SI_SECURITY_BASELINE_NEW_INSTALL
    is on.

    PLAN BY DEFAULT: prints the install's shape (resource group, image, identities with client ids, the SQL server and its
    Entra admin, the database users with their roles, the admin group's members), the read-only proof, and what each step
    WOULD change. Nothing is changed.
      -Apply -Steps <list>    makes exactly those steps (string names, in this order):
        proof                       read-only: the registry's pullers, the vault the jobs name, the SQL server found from
                                    the jobs' own settings, the workspace; the web app's jobs role (reported, never changed)
        registry-admin-off          the registry's admin user (a password that can replace the image every job runs) OFF,
                                    only when no job and no app still pulls with it. Reversible.
        keyvault-purge-protection   purge protection ON for the vault the jobs name, in the install's resource group.
                                    ONE-WAY: Azure never turns it off -- -Rollback cannot undo it, and a deleted vault keeps
                                    its name for its retention days (90 by default).
        sql-audit                   SQL auditing ON for the install's database server (every database on it) to the install's
                                    workspace, table SQLSecurityAuditEvents kept at least 90 days. Reversible (the auditing
                                    setting put back, the diagnostic setting this script made removed; the retention stays).
        web-jobs-start-only         CR8 item 1: the web app gets START-ONLY rights -- "Container Apps Jobs Reader" on the
                                    resource group, "Container Apps Jobs Operator" on every caj-si-* job, and Jobs__ChangeMode=
                                    request (its trigger changes become requests the pipeline runner applies). Its Jobs
                                    Contributor STAYS. Needs a release that carries the request mode on the web app and the
                                    runner. Reversible (the roles it added removed, the setting put back).
        web-jobs-contributor-off    the SECOND run, after the pipeline ran green since web-jobs-start-only: the web app's
                                    "Container Apps Jobs Contributor" removed -- only when start-only is complete. Reversible.
    The proof also REPORTS (never changes) a secret held in plain settings: an environment variable that looks like a
    credential with a plain value, or a Container Apps secret that is not a Key Vault reference.
      -Rollback <record> -Apply   puts back what that record says was there before (newest first).
    A step with nothing to do says "nothing to do" and writes nothing. Every change is read back and the new state printed.
    ONE rollback record per run: a JSON file here (the path is printed) and a short copy in the install
    (cfg.InstallState 'SecurityBaselineCutover'). After -Apply the script waits -ObserveMinutes (default 6), then counts the
    install's runs since the cut-over and the failures. One environment at a time.
    No SQL statement changes a right here: the SQL calls only read the shape and keep the record.

.EXAMPLE
    . C:\claude-sessions\Invardia\tools\Connect-InvardiaSupport.ps1 -Environment <handle> -Reason 'security baseline'
    .\Set-SISecurityBaseline.ps1 -ResourceGroup <rg>
    .\Set-SISecurityBaseline.ps1 -ResourceGroup <rg> -Apply -Steps registry-admin-off,sql-audit
    .\Set-SISecurityBaseline.ps1 -Rollback <record.json> -Apply

.LINK
    https://invardia.com/docs/si/scripts/Set-SISecurityBaseline/
#>
[CmdletBinding()]
param(
    # the install's resource group (where its jobs are)
    [string]$ResourceGroup,
    # default: the Support session's first subscription
    [string]$SubscriptionId,
    [switch]$Apply,
    [string[]]$Steps = @(),
    # a rollback record written by an earlier -Apply: put back what it recorded (with -Apply; without it, only shown)
    [string]$Rollback = '',
    # overrides when the jobs do not name them (never guessed from a name pattern)
    [string]$WorkspaceResourceId = '',
    [string]$KeyVaultName = '',
    [string]$RegistryName = '',
    # the install's database server (a name or an FQDN) when the jobs do not name it; without it the server is found from
    # the jobs, then the web app's settings, then as the ONE database server in the install's resource group
    [string]$SqlServerName = '',
    [string]$Reason = 'SecurityInsight security baseline',
    [string]$Environment = '',
    [string]$RecordDirectory = '',
    # after -Apply: minutes to wait before counting the runs since the cut-over (0 = count at once)
    [ValidateRange(0, 30)][int]$ObserveMinutes = 6,
    # TEST SEAMS (setup\_shared\SI-SupportCutover.ps1): replace the Support session
    [scriptblock]$Arm, [scriptblock]$Sql, [scriptblock]$Graph,
    [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }
)

$ErrorActionPreference = 'Stop'
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportCutover.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SecurityBaseline.ps1'))
$script:SIBaselineSteps = @('proof', 'registry-admin-off', 'keyvault-purge-protection', 'sql-audit', 'web-jobs-start-only', 'web-jobs-contributor-off')

function Write-SIBaselineLine { param([string]$Text, [string]$Color = 'Gray') Write-Host $Text -ForegroundColor $Color }

$seams = New-SICutoverSeams -Arm $Arm -Sql $Sql -Graph $Graph -Reason $Reason
$A = $seams.Arm
$sess = $null; if (Get-Command -Name Get-SISupportSession -ErrorAction SilentlyContinue) { try { $sess = Get-SISupportSession } catch { $sess = $null } }
if (-not $Environment) { $Environment = if ($sess -and [string]$sess.Environment) { [string]$sess.Environment } else { 'environment' } }
if (-not $RecordDirectory) { $RecordDirectory = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'si', 'logs', 'cutover') }

# ---------------------------------------------------------------------------------------------------- ROLLBACK
if ($Rollback.Trim()) {
    $rb = [IO.File]::ReadAllText($Rollback) | ConvertFrom-Json
    Write-SIBaselineLine ('== ROLLBACK of {0} ({1}) from {2} -- applied: {3}' -f $rb.environment, $rb.resourceGroup, $Rollback, (@($rb.applied) -join ', ')) 'Yellow'
    if (-not $Apply) { Write-SIBaselineLine 'PLAN ONLY -- nothing was changed. Add -Apply to put the recorded values back.' 'Yellow'; return [pscustomobject]@{ Mode = 'rollback-plan'; Results = @() } }
    $results = New-Object System.Collections.Generic.List[object]
    $order = @($rb.applied); [array]::Reverse($order)
    foreach ($step in $order) {
        $b = $rb.before.$step
        try {
            $r = switch ([string]$step) {
                'registry-admin-off' { Set-SIRegistryAdmin -Arm $A -RegistryId ([string]$b.registryId) -Enabled ([bool]$b.adminUserEnabled) -Sleep $Sleep }
                'keyvault-purge-protection' { @{ Ok = $true; Line = 'purge protection is ONE-WAY: Azure never turns it off -- nothing to put back' } }
                'sql-audit' { Restore-SISqlServerAudit -Arm $A -ServerId ([string]$b.serverId) -Before $b.auditing -DiagnosticExisted ([bool]$b.diagnosticExisted) }
                'web-jobs-start-only' {
                    $lines = New-Object System.Collections.Generic.List[string]; $okAll = $true
                    if ([string]$b.webAppId) { $x = Set-SIWebChangeMode -Arm $A -AppId ([string]$b.webAppId) -Value $(if ([string]$b.changeMode) { [string]$b.changeMode } else { $null }) -Sleep $Sleep; $lines.Add($x.Line); if (-not $x.Ok) { $okAll = $false } }
                    foreach ($aid in @($b.added)) { if ([string]$aid) { $x = Remove-SIBaselineRoleAssignment -Arm $A -AssignmentId ([string]$aid) -Label 'added role'; $lines.Add($x.Line); if (-not $x.Ok) { $okAll = $false } } }
                    @{ Ok = $okAll; Line = ($lines -join '; ') }
                }
                'web-jobs-contributor-off' {
                    $lines = New-Object System.Collections.Generic.List[string]; $okAll = $true
                    foreach ($c in @($b.removed)) {
                        $path = '{0}?api-version=2022-04-01' -f [string]$c.id
                        $null = & $A 'PUT' $path (Get-SIRoleAssignmentPutBody -RoleDefinitionId ([string]$c.roleDefinitionId) -PrincipalId ([string]$c.principalId))
                        $ok = [bool](& $A 'GET' $path $null); $lines.Add(('Container Apps Jobs Contributor on {0}: {1}' -f (([string]$c.scope) -split '/')[-1], $(if ($ok) { 'back (read back)' } else { 'NOT back' }))); if (-not $ok) { $okAll = $false }
                    }
                    @{ Ok = $okAll; Line = ($lines -join '; ') }
                }
                default { @{ Ok = $false; Line = 'not a step of this script' } }
            }
            Write-SIBaselineLine ('{0,-26} {1}' -f $step, $r.Line) $(if ($r.Ok) { 'Green' } else { 'Red' })
            $results.Add([pscustomobject]@{ Step = [string]$step; Ok = [bool]$r.Ok; Line = $r.Line })
        } catch { Write-SIBaselineLine ('{0,-26} rollback FAILED: {1}' -f $step, $_.Exception.Message) 'Red'; $results.Add([pscustomobject]@{ Step = [string]$step; Ok = $false; Line = $_.Exception.Message }) }
    }
    return [pscustomobject]@{ Mode = 'rollback'; Results = $results.ToArray() }
}

# ---------------------------------------------------------------------------------------------------- SHAPE
if (-not $ResourceGroup) { throw 'Give -ResourceGroup: the install''s resource group (where its jobs are).' }
if (-not $SubscriptionId) { $SubscriptionId = if ($sess) { [string]$sess.SubscriptionId } else { '' } }
if (-not $SubscriptionId) { throw 'Give -SubscriptionId: the Support session names no subscription.' }
$want = @(Resolve-SICutoverSteps -Steps $Steps -Known $script:SIBaselineSteps)
if ($Apply -and -not $want.Count) { throw ('-Apply needs -Steps: name the steps to make ({0}). Nothing was changed.' -f ($script:SIBaselineSteps -join ', ')) }

$shape = Get-SIInstallShape -Arm $A -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -SqlServerName $SqlServerName -FindSqlInResourceGroup
if (-not @($shape.Jobs).Count) { throw ('No Container Apps job was found in {0} (subscription {1}) -- is this the install''s resource group? Nothing was changed.' -f $ResourceGroup, $SubscriptionId) }
$shape = Add-SIInstallSqlShape -Shape $shape -Sql $seams.Sql -Graph $seams.Graph -Reason ('{0}: read the install''s database users' -f $Reason)
Write-SIBaselineLine ('== {0}' -f $Environment) 'Cyan'
foreach ($l in (Format-SIInstallShape -Shape $shape)) { Write-SIBaselineLine ('   ' + $l) $(if ($l -like 'NOT READ*') { 'Yellow' } else { 'Gray' }) }
$all = @($shape.Jobs) + @($shape.Apps)
$rgPath = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup

# ---------------------------------------------------------------------------------------------------- PROOF + PLAN (read-only)
$plan = [ordered]@{}
$ctx = @{}
# registry: the one the jobs pull from (or -RegistryName in the install's resource group)
$reg = $null
if ($RegistryName) { $reg = & $A 'GET' ('{0}/providers/Microsoft.ContainerRegistry/registries/{1}?api-version={2}' -f $rgPath, $RegistryName, $script:SIBaselineAcrApi) $null }
$servers = @($all | ForEach-Object { @(Get-SIBaselineProp $_ @('properties', 'configuration', 'registries')) } | Where-Object { $_ } | ForEach-Object { ([string](Get-SIBaselineProp $_ @('server'))).ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
if (-not $reg -and $servers.Count -eq 1) {
    $reg = @(Get-SIBaselineArmList -Arm $A -Path ('/subscriptions/{0}/providers/Microsoft.ContainerRegistry/registries?api-version={1}' -f $SubscriptionId, $script:SIBaselineAcrApi) |
             Where-Object { ([string](Get-SIBaselineProp $_ @('properties', 'loginServer'))).ToLowerInvariant() -eq $servers[0] })[0]
}
if ($reg) { $ctx['registry'] = $reg; $plan['registry-admin-off'] = Get-SIRegistryAdminDecision -Registry $reg -Apps $all }
elseif ($servers.Count -gt 1) { $plan['registry-admin-off'] = @{ Action = 'skip'; Reason = ('the jobs pull from more than one registry ({0}) -- give -RegistryName' -f ($servers -join ', ')) } }
else { $plan['registry-admin-off'] = @{ Action = 'skip'; Reason = 'the install''s container registry was not found (give -RegistryName)' } }
# vault: the one the jobs name, and only in the install's resource group
$kvName = if ($KeyVaultName) { $KeyVaultName } else { $shape.KeyVaultName }
$kv = if ($kvName) { & $A 'GET' ('{0}/providers/Microsoft.KeyVault/vaults/{1}?api-version={2}' -f $rgPath, $kvName, $script:SIBaselineKvApi) $null } else { $null }
if ($kv) { $ctx['vault'] = $kv; $plan['keyvault-purge-protection'] = Get-SIKeyVaultPurgeDecision -Vault $kv }
elseif ($kvName) { $plan['keyvault-purge-protection'] = @{ Action = 'skip'; Reason = ('the Key Vault {0} is not in {1} -- only the install''s own vault is changed' -f $kvName, $ResourceGroup) } }
else { $plan['keyvault-purge-protection'] = @{ Action = 'skip'; Reason = 'no job names the install''s Key Vault (SI_KeyVaultName) -- give -KeyVaultName' } }
# SQL: the server the jobs use (found in the shape by its exact FQDN), the workspace the jobs write to
$ws = if ($WorkspaceResourceId) { $WorkspaceResourceId } else { $shape.WorkspaceResourceId }
if (-not $ws) { $plan['sql-audit'] = @{ Action = 'skip'; Reason = 'no job names the install''s Log Analytics workspace (SI_WorkspaceResourceId) -- give -WorkspaceResourceId' } }
elseif (-not $shape.SqlServerId) { $plan['sql-audit'] = @{ Action = 'skip'; Reason = $(if ($shape.SqlFqdn) { 'the database server ({0}, from {1}) was not found in subscription {2} -- give -SqlServerName' -f $shape.SqlFqdn, $shape.SqlSource, $SubscriptionId } elseif ($shape.SqlProblem) { $shape.SqlProblem } else { 'no database server was found: the jobs and the web app name none, and none is in {0} -- give -SqlServerName' -f $ResourceGroup }) } }
else {
    $sid = $shape.SqlServerId
    $aud = & $A 'GET' ('{0}/auditingSettings/default?api-version={1}' -f $sid, $script:SIBaselineSqlApi) $null
    $diags = @(Get-SIBaselineArmList -Arm $A -Path ('{0}/databases/master/providers/Microsoft.Insights/diagnosticSettings?api-version={1}' -f $sid, $script:SIBaselineDiagApi))
    $tbl = $null; try { $tbl = & $A 'GET' ('{0}/tables/{1}?api-version={2}' -f $ws.TrimEnd('/'), $script:SIBaselineAuditTable, $script:SIBaselineLawApi) $null } catch { $tbl = $null }
    $plan['sql-audit'] = Get-SISqlAuditDecision -Auditing $aud -DiagnosticSettings $diags -Table $tbl -WorkspaceResourceId $ws
    # "existed": a setting that already sends the audit to the workspace (ours or the customer's) is never removed by -Rollback
    $ctx['sql'] = @{ ServerId = $sid; Auditing = $aud; Workspace = $ws
                     DiagnosticExisted = [bool]@($diags | Where-Object { [string](Get-SIBaselineProp $_ @('name')) -eq $script:SIBaselineAuditDiagName -or (Test-SISqlAuditDiagnosticMatch -Setting $_ -WorkspaceResourceId $ws) }).Count }
}
# the web app's jobs role (CR8 item 1): start-only first, Jobs Contributor off in a second run
$web = @($shape.Apps | Where-Object { [string](Get-SIBaselineProp $_ @('name')) -notmatch '(?i)mcp' -and [string](Get-SIBaselineProp $_ @('name')) -match '(?i)management|web' })[0]
$webPid = ''
if ($web) { $ui = Get-SIBaselineProp $web @('identity', 'userAssignedIdentities'); if ($ui) { foreach ($u in @($ui.PSObject.Properties)) { $webPid = [string](Get-SIBaselineProp $u.Value @('principalId')); if ($webPid) { break } } } }
$webAssign = @()
try {
    $webAssign = if ($webPid) { @(Get-SIBaselineArmList -Arm $A -Path ('{0}/providers/Microsoft.Authorization/roleAssignments?$filter={1}&api-version=2022-04-01' -f $rgPath, [uri]::EscapeDataString(("principalId eq '{0}'" -f $webPid)))) } else { @() }
    $jr = Get-SIJobsRoleFinding -Assignments $webAssign -WebPrincipalId $webPid
    $roleIds = Get-SIBaselineRoleDefinitionIds -Arm $A -SubscriptionId $SubscriptionId
    $js = Get-SIJobsStartOnlyDecision -Assignments $webAssign -Jobs @($shape.Jobs) -WebPrincipalId $webPid -RoleIds $roleIds -ChangeMode (Get-SIWebChangeMode -WebApp $web) -ResourceGroupId $rgPath
    $ctx['jobs'] = @{ RoleIds = $roleIds; Decision = $js; WebId = [string](Get-SIBaselineProp $web @('id')); WebPid = $webPid; ChangeModeBefore = (Get-SIWebChangeMode -WebApp $web) }
    $plan['web-jobs-start-only'] = @{ Action = $js.Action; Reason = $js.Reason }
    $plan['web-jobs-contributor-off'] = @{ Action = $(switch ($js.ContributorOff) { 'remove' { 'remove' } 'wait' { 'keep' } default { 'none' } }); Reason = $js.ContributorReason }
    # #931: never before the release whose web app starts jobs with no override
    if ($plan['web-jobs-contributor-off'].Action -eq 'remove') {
        $sr = Test-SIBaselineStartRequestReady -Jobs @($shape.Jobs)
        if (-not $sr.Ready) { $plan['web-jobs-contributor-off'] = @{ Action = 'keep'; Reason = $sr.Line } }
    }
}
catch {
    $jr = @{ Found = $false; Line = ('the web app''s jobs role was not read: {0}' -f $_.Exception.Message) }
    $plan['web-jobs-start-only'] = @{ Action = 'skip'; Reason = $jr.Line }; $plan['web-jobs-contributor-off'] = @{ Action = 'skip'; Reason = $jr.Line }
}
# reported only (CR8 item 4): a secret in plain settings -- never changed here
$plainSecrets = @(Get-SIPlainSecretFindings -Resources $all)
$secretLine = if ($plainSecrets.Count) { ('{0} secret(s) not held as a Key Vault reference: {1}' -f $plainSecrets.Count, ((@($plainSecrets | ForEach-Object { '{0} {1} {2}' -f $_.Resource, $_.Kind, $_.Name })) -join '; ')) } else { 'no secret in plain settings: every credential is a Key Vault reference or a secret reference' }
Write-SIBaselineLine ('{0,-26} read-only: {1}' -f 'proof', $secretLine) $(if ($plainSecrets.Count) { 'Yellow' } else { 'DarkGray' })

Write-SIBaselineLine ('{0,-26} read-only: {1}' -f 'proof', $jr.Line) 'DarkGray'
foreach ($k in $plan.Keys) {
    $d = $plan[$k]
    $what = switch ([string]$d.Action) { 'none' { 'nothing to do' } 'skip' { 'SKIPPED' } 'keep' { 'NOT CHANGED' } default { 'WOULD CHANGE' } }
    Write-SIBaselineLine ('{0,-26} {1}: {2}' -f $k, $what, $d.Reason) $(switch ([string]$d.Action) { 'none' { 'DarkGray' } 'skip' { 'Yellow' } 'keep' { 'Yellow' } default { 'White' } })
}
if (-not $Apply) {
    Write-SIBaselineLine ('PLAN ONLY -- nothing was changed. Apply: -Apply -Steps <{0}>' -f ($script:SIBaselineSteps[1..($script:SIBaselineSteps.Count - 1)] -join ',')) 'Yellow'
    return [pscustomobject]@{ Mode = 'plan'; Shape = $shape; Plan = $plan; JobsRole = $jr; PlainSecrets = $plainSecrets; RecordPath = $null; Results = @() }
}

# ---------------------------------------------------------------------------------------------------- APPLY
$started = [datetime]::UtcNow
$record = New-SICutoverRecord -Script 'Set-SISecurityBaseline' -Environment $Environment -Shape $shape -Now $started
$recPath = Get-SICutoverRecordPath -Directory $RecordDirectory -Script 'Set-SISecurityBaseline' -Environment $Environment -Now $started
$script:SIBaselineSaved = $null
$results = New-Object System.Collections.Generic.List[object]
foreach ($k in $want) {
    if ($k -eq 'proof') { continue }
    $d = $plan[$k]
    if ([string]$d.Action -in 'none', 'skip', 'keep') { Write-SIBaselineLine ('{0,-26} nothing to do: {1}' -f $k, $d.Reason) 'DarkGray'; continue }
    try {
        # the before-value is written FIRST (a change that fails half-way is rolled back too)
        switch ($k) {
            'registry-admin-off' { $record.before[$k] = [ordered]@{ registryId = [string]$ctx['registry'].id; adminUserEnabled = $true } }
            'keyvault-purge-protection' { $record.before[$k] = [ordered]@{ vaultId = [string]$ctx['vault'].id; enablePurgeProtection = $false; oneWay = $true } }
            'sql-audit' { $s = $ctx['sql']; $record.before[$k] = [ordered]@{ serverId = $s.ServerId; auditing = (Get-SIBaselineProp $s.Auditing @('properties')); diagnosticExisted = ($s.DiagnosticExisted -or [string]$d.Action -eq 'retention'); workspaceResourceId = $s.Workspace } }
            # the assignments this step adds are written to the record AS THEY ARE MADE (names fixed up front), so a step that
            # fails half-way is rolled back too
            'web-jobs-start-only' { $jx = $ctx['jobs']; $jx.Added = New-Object System.Collections.Generic.List[string]
                                     $record.before[$k] = [ordered]@{ webAppId = $jx.WebId; changeMode = $jx.ChangeModeBefore; added = $jx.Added } }
            'web-jobs-contributor-off' { $jx = $ctx['jobs']; $record.before[$k] = [ordered]@{ removed = @($jx.Decision.Contributor | ForEach-Object { [ordered]@{ id = [string](Get-SIBaselineProp $_ @('id')); scope = [string](Get-SIBaselineProp $_ @('properties', 'scope')); roleDefinitionId = [string](Get-SIBaselineProp $_ @('properties', 'roleDefinitionId')); principalId = [string](Get-SIBaselineProp $_ @('properties', 'principalId')) } }) } }
        }
        $record.applied = @($record.applied) + @($k)
        $script:SIBaselineSaved = Save-SICutoverRecord -Record $record -Path $recPath -Sql $seams.Sql -StateName 'SecurityBaselineCutover'
        $r = switch ($k) {
            'registry-admin-off' { $x = Set-SIRegistryAdmin -Arm $A -RegistryId ([string]$ctx['registry'].id) -Enabled $false -Sleep $Sleep; @{ Ok = $x.Ok; Lines = @($x.Line) } }
            'keyvault-purge-protection' { $x = Set-SIKeyVaultPurgeProtection -Arm $A -VaultId ([string]$ctx['vault'].id) -Sleep $Sleep; @{ Ok = $x.Ok; Lines = @($x.Line) } }
            'sql-audit' {
                $s = $ctx['sql']
                if ([string]$d.Action -eq 'retention') { $x = Set-SILaTableRetention -Arm $A -WorkspaceResourceId $s.Workspace; @{ Ok = $x.Ok; Lines = @($x.Line) } }
                else { Set-SISqlServerAudit -Arm $A -ServerId $s.ServerId -WorkspaceResourceId $s.Workspace -Sleep $Sleep -SkipDiagnostic:(-not $d.NeedsDiagnostic) }
            }
            'web-jobs-start-only' {
                $jx = $ctx['jobs']; $dj = $jx.Decision; $lines = New-Object System.Collections.Generic.List[string]; $okAll = $true
                $grants = @(); if ($dj.NeedReader) { $grants += ,@($rgPath, 'Reader') }; foreach ($jid in @($dj.NeedOperator)) { $grants += ,@($jid, 'Operator') }
                foreach ($g in $grants) {
                    $name = [guid]::NewGuid().ToString()
                    $jx.Added.Add(('{0}/providers/Microsoft.Authorization/roleAssignments/{1}' -f ([string]$g[0]).TrimEnd('/'), $name))
                    $script:SIBaselineSaved = Save-SICutoverRecord -Record $record -Path $recPath -Sql $seams.Sql -StateName 'SecurityBaselineCutover'
                    $x = Add-SIBaselineRoleAssignment -Arm $A -Scope ([string]$g[0]) -SubscriptionId $SubscriptionId -RoleGuid ([string]$jx.RoleIds[[string]$g[1]]) -PrincipalId $jx.WebPid -Label $script:SIBaselineJobsRoles[[string]$g[1]] -AssignmentName $name -Sleep $Sleep
                    $lines.Add($x.Line); if (-not $x.Ok) { $okAll = $false }
                }
                if ($okAll -and ([string]$jx.ChangeModeBefore).Trim().ToLowerInvariant() -ne 'request') { $x = Set-SIWebChangeMode -Arm $A -AppId $jx.WebId -Value 'request' -Sleep $Sleep; $lines.Add($x.Line); if (-not $x.Ok) { $okAll = $false } }
                elseif (-not $okAll) { $lines.Add('the web app''s mode was NOT changed: a role did not read back (roll back with -Rollback, or run the step again)') }
                @{ Ok = $okAll; Lines = $lines.ToArray() }
            }
            'web-jobs-contributor-off' {
                $lines = New-Object System.Collections.Generic.List[string]; $okAll = $true
                foreach ($c in @($ctx['jobs'].Decision.Contributor)) { $x = Remove-SIBaselineRoleAssignment -Arm $A -AssignmentId ([string](Get-SIBaselineProp $c @('id'))) -Label 'Container Apps Jobs Contributor'; $lines.Add($x.Line); if (-not $x.Ok) { $okAll = $false } }
                @{ Ok = $okAll; Lines = $lines.ToArray() }
            }
        }
        foreach ($l in @($r.Lines)) { Write-SIBaselineLine ('{0,-26} {1}' -f $k, $l) $(if ($r.Ok) { 'Green' } else { 'Red' }) }
        $results.Add([pscustomobject]@{ Step = $k; Ok = [bool]$r.Ok; Lines = @($r.Lines) })
    } catch {
        Write-SIBaselineLine ('{0,-26} FAILED: {1}' -f $k, $_.Exception.Message) 'Red'
        $results.Add([pscustomobject]@{ Step = $k; Ok = $false; Lines = @($_.Exception.Message) })
    }
}
$obs = $null
if (@($record.applied).Count) {
    Write-SIBaselineLine ('rollback record: {0}{1}' -f $recPath, $(if ($script:SIBaselineSaved -and $script:SIBaselineSaved.InstallLine) { ' -- ' + $script:SIBaselineSaved.InstallLine } else { '' })) 'Cyan'
    Write-SIBaselineLine ('waiting {0} minute(s), then counting the runs since the cut-over ...' -f $ObserveMinutes) 'DarkGray'
    $obs = Wait-SICutoverObservation -Arm $A -Shape $shape -Since $started -Minutes $ObserveMinutes -Sleep $Sleep
    Write-SIBaselineLine $obs.Line $(if ($obs.Failed) { 'Red' } elseif ($obs.Runs) { 'Green' } else { 'Yellow' })
    foreach ($l in @($obs.Lines)) { Write-SIBaselineLine ('   ' + $l) 'Red' }
} else { Write-SIBaselineLine 'nothing was changed -- no rollback record was written.' 'DarkGray' }
[pscustomobject]@{ Mode = 'apply'; Shape = $shape; Plan = $plan; JobsRole = $jr; RecordPath = $(if (@($record.applied).Count) { $recPath } else { $null }); Results = $results.ToArray(); Observation = $obs }
