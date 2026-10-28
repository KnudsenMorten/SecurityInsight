#Requires -Version 5.1
<#
    THE INSTALL DIAGNOSTICS AS PRODUCT SCRIPTS: diagnostics/Test-SIInstall.ps1 (is the install healthy and isolated?) and
    diagnostics/Invoke-SIJobsOnce.ps1 (run every engine job once, in schedule order), on diagnostics/_SIInstallDiagnostics.ps1.

    FULLY OFFLINE. Every call that leaves the process goes through a seam (Arm, LaQuery, Graph, Now, Sleep, Print); here
    each is a fake over a small in-memory Azure: one install's resource group with its workspace, identity, DCRs and
    jobs, plus whatever a scenario adds (a write role outside, a duplicate DCR name, a failed run ...).

    Ships in both editions: no Pro path is named here.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'diagnostics', '_SIInstallDiagnostics.ps1'))
    $script:Sub = '22222222-2222-2222-2222-222222222222'
    $script:Rg = 'rg-si-test-community-ca'
    $script:RgId = "/subscriptions/$($script:Sub)/resourceGroups/$($script:Rg)"
    $script:WsId = "$($script:RgId)/providers/Microsoft.OperationalInsights/workspaces/log-si-test-community-ca"
    $script:Principal = '55555555-5555-5555-5555-555555555555'
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-03T12:00:00', 'Utc')

    $script:ConfigText = @'
# an install's config: constants, plus things a diagnostic must NOT run
$global:SI_AuthMethod              = 'ManagedIdentity'
$global:SI_AzSubscriptionId        = '22222222-2222-2222-2222-222222222222'
$global:SI_WorkspaceName           = 'log-si-test-community-ca'
$global:SI_WorkspaceResourceGroup  = 'rg-si-test-community-ca'
$global:SI_WorkspaceResourceId     = '/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-si-test-community-ca/providers/Microsoft.OperationalInsights/workspaces/log-si-test-community-ca'
$global:SI_DcrResourceGroup        = 'rg-si-test-community-ca'
$global:SI_DcrNamePattern          = 'dcr-si-test-community-ca-{0}'
$global:SI_Endpoint_DcrName        = 'dcr-si-test-community-ca-endpoint'
$global:SI_RunHealth_DcrName       = 'dcr-si-test-community-ca-run-health'
$global:SI_Trend_DcrName           = 'dcr-si-test-community-ca-trend'
$global:SI_StorageAccount          = 'stsitestcommunityca01'
$global:SI_Sinks_Endpoint          = @('LA','Excel')
$global:SI_ForceFullRun            = $true
$global:SI_Key                     = (Get-SIKvSecret -Name 'si-key')
throw 'the config file must never be RUN by a diagnostic'
$global:SI_Bootstrap_SubscriptionId    = '22222222-2222-2222-2222-222222222222'
$global:SI_Bootstrap_ResourceGroupName = 'rg-si-test-community-ca'
if ($false) { $global:SI_Bootstrap_ResourceGroupName = 'rg-conditional' }
'@
    $script:ConfigPath = Join-Path ([IO.Path]::GetTempPath()) ('si-diag-' + [guid]::NewGuid().ToString('N') + '.ps1')
    [IO.File]::WriteAllText($script:ConfigPath, $script:ConfigText)

    # ---- the fake Azure ----
    function script:New-World([hashtable]$Opt = @{}) {
        $W = @{ Opt = $Opt; Calls = New-Object System.Collections.Generic.List[string]; Queries = New-Object System.Collections.Generic.List[string]
                Printed = New-Object System.Collections.Generic.List[string]; T = $script:Now; Polls = @{}; Started = New-Object System.Collections.Generic.List[string] }
        $sub = $script:Sub; $rgId = $script:RgId; $wsId = $script:WsId; $pidv = $script:Principal
        $dcr = { param($name, $rg) [pscustomobject]@{ name = $name; id = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionRules/$name" } }
        $mineDcrs = @((& $dcr 'dcr-si-test-community-ca-endpoint' $script:Rg), (& $dcr 'dcr-si-test-community-ca-run-health' $script:Rg))
        $roleDef = @{ 'acdd72a7-3385-48ef-bd42-f606fba81ae7' = 'Reader'; '3913510d-42f4-4e42-8a64-420c390055eb' = 'Monitoring Metrics Publisher'
                      '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'; 'ba92f5b4-2d11-453d-a403-e96b0029c9fe' = 'Storage Blob Data Contributor'
                      '73c42c96-874c-492b-b04d-ab87d138a893' = 'Log Analytics Reader' }
        $ra = { param($role, $scope) $g = @($roleDef.Keys | Where-Object { $roleDef[$_] -eq $role })[0]
                [pscustomobject]@{ id = "$scope/providers/Microsoft.Authorization/roleAssignments/" + [guid]::NewGuid().ToString(); properties = [pscustomobject]@{ scope = $scope; principalId = $pidv; roleDefinitionId = "/subscriptions/$sub/providers/Microsoft.Authorization/roleDefinitions/$g" } } }
        $assign = @((& $ra 'Reader' "/subscriptions/$sub"), (& $ra 'Monitoring Metrics Publisher' $rgId), (& $ra 'Log Analytics Reader' $wsId),
                    (& $ra 'Storage Blob Data Contributor' "$rgId/providers/Microsoft.Storage/storageAccounts/stsitestcommunityca01"))
        foreach ($x in @($Opt.ExtraRoles)) { if ($x) { $assign += (& $ra $x.Role $x.Scope) } }
        $W.Seams = @{
            Arm = {
                param([string]$Method, [string]$Path, [string]$ApiVersion, [switch]$List, $Body)
                $W.Calls.Add(('{0} {1}' -f $Method, $Path))
                $o = $W.Opt
                if ($Method -eq 'POST' -and $Path -like '*/start') {
                    $job = ($Path -split '/')[-2]
                    if (@($o.StartFails) -contains $job) { throw 'Conflict: the job is busy' }
                    $W.Started.Add($job)
                    return [pscustomobject]@{ name = "$job-exec1"; id = "$Path/../executions/$job-exec1" }
                }
                if ($Path -like '*/executions/*') {
                    $job = ($Path -split '/')[-3]
                    $n = 1 + [int]$W.Polls[$job]; $W.Polls[$job] = $n
                    $final = if ($o.JobStatus -and $o.JobStatus.ContainsKey($job)) { $o.JobStatus[$job] } else { 'Succeeded' }
                    $st = if ($n -lt 2) { 'Running' } else { $final }
                    return [pscustomobject]@{ properties = [pscustomobject]@{ status = $st; startTime = '2026-10-03T12:00:00Z'; endTime = $(if ($st -eq 'Running') { $null } else { '2026-10-03T12:07:30Z' }) } }
                }
                if ($Path -eq $wsId) { if ($o.NoWorkspace) { throw 'ResourceNotFound' }; return [pscustomobject]@{ properties = [pscustomobject]@{ customerId = '77777777-7777-7777-7777-777777777777' } } }
                if ($Path -like '*/userAssignedIdentities') {
                    if ($o.NoIdentity) { return @() }
                    $ids = @([pscustomobject]@{ name = 'id-si-test-community-ca'; properties = [pscustomobject]@{ principalId = $pidv; clientId = '44444444-4444-4444-4444-444444444444' } })
                    if ($o.TwoIdentities) { $ids += [pscustomobject]@{ name = 'id-other'; properties = [pscustomobject]@{ principalId = 'p2'; clientId = 'c2' } } }
                    return $ids
                }
                if ($Path -like '*/roleAssignments?*') { return $assign }
                if ($Path -like '*/roleDefinitions/*') { return [pscustomobject]@{ properties = [pscustomobject]@{ roleName = $roleDef[($Path -split '/')[-1]] } } }
                if ($Path -like "$rgId/providers/Microsoft.Insights/dataCollectionRules") { return $mineDcrs }
                if ($Path -like '/subscriptions/*/providers/Microsoft.Insights/dataCollectionRules') {
                    $all = @($mineDcrs) + @((& $dcr 'dcr-other-app' 'rg-other'))
                    if ($o.DuplicateDcr) { $all += (& $dcr 'dcr-si-test-community-ca-endpoint' 'rg-another-si') }
                    return $all
                }
                if ($Path -like '*/providers/Microsoft.App/jobs') { return @($o.Jobs) }
                throw "unexpected ARM call: $Method $Path"
            }.GetNewClosure()
            LaQuery = {
                param([string]$WorkspaceId, [string]$Query)
                $W.Queries.Add($Query)
                $o = $W.Opt
                if ($Query -match '^union withsource') {
                    if ($o.NoData) { return [pscustomobject]@{ Results = @() } }
                    return [pscustomobject]@{ Results = @(
                        [pscustomobject]@{ SITable = 'SI_Endpoint_Profile_CL'; Rows = '1234'; LastSeen = '2026-10-03T04:12:00Z' }
                        [pscustomobject]@{ SITable = 'SI_RunHealth_CL'; Rows = '40'; LastSeen = '2026-10-03T09:30:00Z' }) }
                }
                if ($Query -match '^SI_RunHealth_CL') {
                    if ($o.NoRunHealth) { throw "Operation returned an invalid status code 'BadRequest' -- SemanticError: 'SI_RunHealth_CL' could not be resolved" }
                    $rows = @(
                        [pscustomobject]@{ Engine = 'endpoint'; Phase = 'Start'; At = '2026-10-03T04:00:05Z'; ExitReason = ''; DurationSec = '' }
                        [pscustomobject]@{ Engine = 'endpoint'; Phase = 'End'; At = '2026-10-03T04:11:00Z'; ExitReason = 'success'; DurationSec = '655' }
                        [pscustomobject]@{ Engine = 'risk-analysis'; Phase = 'Start'; At = '2026-10-03T06:00:05Z'; ExitReason = ''; DurationSec = '' }
                        [pscustomobject]@{ Engine = 'risk-analysis'; Phase = 'End'; At = '2026-10-03T06:40:00Z'; ExitReason = $(if ($o.RaFailed) { 'error' } else { 'success-partial' }); DurationSec = '2395' })
                    if ($o.Hung) { $rows += [pscustomobject]@{ Engine = 'identity'; Phase = 'Start'; At = '2026-10-03T04:30:00Z'; ExitReason = ''; DurationSec = '' } }
                    if ($o.Running) { $rows += [pscustomobject]@{ Engine = 'azure'; Phase = 'Start'; At = '2026-10-03T11:00:00Z'; ExitReason = ''; DurationSec = '' } }
                    return [pscustomobject]@{ Results = $rows }
                }
                throw "unexpected query: $Query"
            }.GetNewClosure()
            Graph = { param([string]$Query, [string[]]$Subscription) $W.Queries.Add($Query); if ($W.Opt.GraphFails) { throw 'Resource Graph: 403' }; @() }.GetNewClosure()
            Now   = { $W.T = $W.T.AddSeconds(5); $W.T }.GetNewClosure()
            Sleep = { param([int]$Seconds) $W.T = $W.T.AddSeconds($Seconds) }.GetNewClosure()
            Print = { param([string]$Text, [string]$Color) $W.Printed.Add($Text) }.GetNewClosure()
        }
        $W
    }
    function script:Invoke-Check($W) {
        $t = Get-SIInstallTargetFromConfig -Values (Read-SIInstallConfigValues -Path $script:ConfigPath)
        Invoke-SIInstallCheck -Target $t -Seams $W.Seams
    }
    function script:New-Job([string]$Name, [string]$Cron, [string]$Trigger = 'Schedule') {
        [pscustomobject]@{ name = $Name; id = "$($script:RgId)/providers/Microsoft.App/jobs/$Name"
            properties = [pscustomobject]@{ configuration = [pscustomobject]@{ triggerType = $Trigger; scheduleTriggerConfig = $(if ($Cron) { [pscustomobject]@{ cronExpression = $Cron } } else { $null }) } } }
    }
    $script:Jobs = @(
        (New-Job 'caj-si-risk-analysis' '0 6 * * *'), (New-Job 'caj-si-endpoint' '0 4 * * *'), (New-Job 'caj-si-ptc' '0 4 * * *'),
        (New-Job 'caj-si-identity' '30 4 * * *'), (New-Job 'caj-si-asset-trend' '0 9 * * *'), (New-Job 'caj-si-updater' '0 2 * * *'),
        (New-Job 'caj-si-shard-worker' '' 'Event'))
}
AfterAll { Remove-Item -LiteralPath $script:ConfigPath -Force -ErrorAction SilentlyContinue }

Describe 'the install''s config is read, never run' {
    It 'reads the constant settings: text, arrays, booleans; the last assignment wins' {
        $v = Read-SIInstallConfigValues -Path $script:ConfigPath
        $v['SI_WorkspaceName'] | Should -BeExactly 'log-si-test-community-ca'
        @($v['SI_Sinks_Endpoint']) | Should -Be @('LA', 'Excel')
        $v['SI_ForceFullRun'] | Should -BeTrue
        $v['SI_Bootstrap_ResourceGroupName'] | Should -BeExactly 'rg-si-test-community-ca' -Because 'an assignment inside an if is not read'
    }
    It 'skips what is computed at run time (a Key Vault lookup) and runs nothing (the throw in the file never fires)' {
        $v = Read-SIInstallConfigValues -Path $script:ConfigPath
        $v.ContainsKey('SI_Key') | Should -BeFalse
    }
    It 'the target: subscription, resource group, workspace, the configured DCR names (patterns left out)' {
        $t = Get-SIInstallTargetFromConfig -Values (Read-SIInstallConfigValues -Path $script:ConfigPath)
        $t.SubscriptionId | Should -BeExactly $script:Sub
        $t.ResourceGroup | Should -BeExactly $script:Rg
        $t.WorkspaceResourceId | Should -BeExactly $script:WsId
        $t.StorageAccountId | Should -Match '/storageAccounts/stsitestcommunityca01$'
        @($t.DcrNames) | Should -Be @('dcr-si-test-community-ca-endpoint', 'dcr-si-test-community-ca-run-health', 'dcr-si-test-community-ca-trend')
    }
    It 'a missing config file is a clear error' {
        { Read-SIInstallConfigValues -Path (Join-Path $TestDrive 'nope.ps1') } | Should -Throw '*config file was not found*'
    }
}

Describe 'Test-SIInstall: a healthy, isolated install' {
    BeforeAll { $script:W = New-World; $script:R = Invoke-Check $script:W }
    It 'is OK' {
        $script:R.Findings | Should -BeNullOrEmpty
        $script:R.Ok | Should -BeTrue
    }
    It 'reports rows and the last time per SI table' {
        @($script:R.Tables | ForEach-Object Table) | Should -Be @('SI_Endpoint_Profile_CL', 'SI_RunHealth_CL')
        ($script:R.Tables | Where-Object Table -eq 'SI_Endpoint_Profile_CL').Rows | Should -Be 1234
        ($script:R.Tables | Where-Object Table -eq 'SI_Endpoint_Profile_CL').LastSeen | Should -Be ([datetime]::SpecifyKind([datetime]'2026-10-03T04:12:00', 'Utc'))
    }
    It 'reports run health per engine: latest start, end, ExitReason' {
        $e = $script:R.Engines | Where-Object Engine -eq 'risk-analysis'
        $e.ExitReason | Should -Be 'success-partial'
        $e.LastStart.ToString('HH:mm') | Should -Be '06:00'
        $e.LastEnd.ToString('HH:mm') | Should -Be '06:40'
        $e.Problem | Should -BeNullOrEmpty
    }
    It 'lists the DCRs in its resource group, and notes a configured one not created yet' {
        @($script:R.Dcrs | ForEach-Object Name) | Should -Be @('dcr-si-test-community-ca-endpoint', 'dcr-si-test-community-ca-run-health')
        ($script:R.Notes -join ' ') | Should -Match 'dcr-si-test-community-ca-trend'
    }
    It 'finds the identity and classifies every role: read, inside the resource group' {
        $script:R.Identity.PrincipalId | Should -Be $script:Principal
        @($script:R.Assignments).Count | Should -Be 4
        ($script:W.Printed -join "`n") | Should -Match '\[read\s*\] Reader\s+on /subscriptions/22222222'
        ($script:W.Printed -join "`n") | Should -Match '\[inside\s*\] Monitoring Metrics Publisher'
    }
    It 'queries the Log Analytics DATA PLANE with the workspace id, and never uses "last" as an alias (a KQL reserved word)' {
        foreach ($q in $script:W.Queries) { $q | Should -Not -Match '(?-i)\blast\b' }
        @($script:W.Queries | Where-Object { $_ -match '^union withsource' }).Count | Should -Be 1
    }
    It 'Test-SIInstall.ps1 exits 0 and prints the summary' {
        $w = New-World
        & ([IO.Path]::Combine($script:SIRoot, 'diagnostics', 'Test-SIInstall.ps1')) -ConfigPath $script:ConfigPath -Seams $w.Seams | Out-Null
        $LASTEXITCODE | Should -Be 0
        ($w.Printed -join "`n") | Should -Match 'OK -- data arrives'
    }
}

Describe 'Test-SIInstall: what is wrong is found (exit 1)' {
    It '<Case>' -ForEach @(
        @{ Case = 'a write role outside the resource group';     Opt = @{ ExtraRoles = @(@{ Role = 'Monitoring Metrics Publisher'; Scope = '/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-dev-si' }) }; Expect = 'Monitoring Metrics Publisher on .*rg-dev-si -- a write role outside' }
        @{ Case = 'Owner on the subscription';                   Opt = @{ ExtraRoles = @(@{ Role = 'Owner'; Scope = '/subscriptions/22222222-2222-2222-2222-222222222222' }) }; Expect = 'Owner on /subscriptions/22222222-2222-2222-2222-222222222222 -- a write role outside' }
        @{ Case = 'a DCR name used by another install';          Opt = @{ DuplicateDcr = $true }; Expect = 'dcr-si-test-community-ca-endpoint is also used by .*rg-another-si' }
        @{ Case = 'an engine whose last run failed';             Opt = @{ RaFailed = $true }; Expect = "risk-analysis: its last run ended with 'error'" }
        @{ Case = 'an engine that started and never ended';      Opt = @{ Hung = $true }; Expect = 'identity: its last run started 2026-10-03 04:30Z and never ended' }
        @{ Case = 'no data in the window';                       Opt = @{ NoData = $true }; Expect = 'no SecurityInsight table received data' }
        @{ Case = 'no run-health table';                         Opt = @{ NoRunHealth = $true }; Expect = 'run-health table could not be read' }
        @{ Case = 'no identity found (access UNKNOWN, not fine)'; Opt = @{ NoIdentity = $true }; Expect = 'managed identity could not be found, so its access is UNKNOWN' }
        @{ Case = 'two identities and none named';               Opt = @{ TwoIdentities = $true; NoIdentityName = $true }; Expect = '' }
        @{ Case = 'the workspace cannot be read';                Opt = @{ NoWorkspace = $true }; Expect = 'the workspace could not be read' }
    ) {
        $w = New-World $Opt
        $r = Invoke-Check $w
        if ($Expect) {
            $r.Ok | Should -BeFalse
            (@($r.Findings | ForEach-Object Text) -join "`n") | Should -Match $Expect
        } else {
            # two identities: the config names none, so the one matching neither name nor client id is not guessed --
            # here the client id is not configured either, so the check must say UNKNOWN rather than pick one.
            $r.Ok | Should -BeFalse
            (@($r.Findings | ForEach-Object Text) -join "`n") | Should -Match 'UNKNOWN'
        }
    }
    It 'Test-SIInstall.ps1 exits 1 when anything is wrong' {
        $w = New-World @{ DuplicateDcr = $true }
        & ([IO.Path]::Combine($script:SIRoot, 'diagnostics', 'Test-SIInstall.ps1')) -ConfigPath $script:ConfigPath -Seams $w.Seams | Out-Null
        $LASTEXITCODE | Should -Be 1
        ($w.Printed -join "`n") | Should -Match 'WRONG \[isolation\]'
    }
}

Describe 'Test-SIInstall: what is NOT wrong' {
    It 'a run still going (started inside the grace period) is not a problem' {
        $r = Invoke-Check (New-World @{ Running = $true })
        $r.Ok | Should -BeTrue
    }
    It 'a documented write grant outside the resource group is allowed (the DCR resource group of a split install)' {
        $v = Read-SIInstallConfigValues -Path $script:ConfigPath
        $v['SI_DcrResourceGroup'] = 'rg-si-shared-dcr'
        $t = Get-SIInstallTargetFromConfig -Values $v
        $w = New-World @{ ExtraRoles = @(@{ Role = 'Monitoring Metrics Publisher'; Scope = "/subscriptions/$($script:Sub)/resourceGroups/rg-si-shared-dcr" }) }
        $r = Invoke-SIInstallCheck -Target $t -Seams $w.Seams
        @($r.Findings | Where-Object Area -eq 'isolation') | Should -BeNullOrEmpty
        ($w.Printed -join "`n") | Should -Match '\[documented\s*\] Monitoring Metrics Publisher'
    }
    It '-AllowedGrant allows a write grant on purpose' {
        $t = Get-SIInstallTargetFromConfig -Values (Read-SIInstallConfigValues -Path $script:ConfigPath)
        $scope = "/subscriptions/$($script:Sub)/resourceGroups/rg-dev-si"
        $w = New-World @{ ExtraRoles = @(@{ Role = 'Monitoring Metrics Publisher'; Scope = $scope }) }
        (Invoke-SIInstallCheck -Target $t -Seams $w.Seams -AllowedGrant @("Monitoring Metrics Publisher@$scope")).Ok | Should -BeTrue
    }
    It 'Resource Graph not readable is a note, not a failure (the subscription view was still checked)' {
        $r = Invoke-Check (New-World @{ GraphFails = $true })
        $r.Ok | Should -BeTrue
        ($r.Notes -join ' ') | Should -Match 'Resource Graph could not be read'
    }
    It 'the documented write grants are exactly the write rows of SecurityInsight''s identity plan (+ the first-run schema grants)' {
        . ([IO.Path]::Combine($script:SIRoot, 'container', '_shared', 'SI-ContainerConfig.ps1'))
        $t = Get-SIInstallTargetFromConfig -Values (Read-SIInstallConfigValues -Path $script:ConfigPath)
        $plan = @(Get-SIContainerIdentityGrantPlan -Mode ManagedIdentity -ReaderScopes $t.ReaderScopes -DcrResourceGroupId $t.DcrResourceGroupId `
                    -WorkspaceResourceId $t.WorkspaceResourceId -StorageAccountId $t.StorageAccountId | Where-Object { $_.Kind -eq 'AzureRole' -and $_.Role -match $script:SIDiagWriteRolePattern })
        $want = @($plan | ForEach-Object { '{0}@{1}' -f $_.Role, $_.Scope }) + @("Monitoring Contributor@$($t.DcrResourceGroupId)", "Log Analytics Contributor@$($t.WorkspaceResourceId)")
        $got = @(Get-SIInstallDocumentedWriteGrants -Target $t | ForEach-Object { '{0}@{1}' -f $_.Role, $_.Scope })
        ($got | Sort-Object) | Should -Be ($want | Sort-Object)
    }
}

Describe 'run health, pure' {
    It 'an END with error or settings-error is a problem; success and success-partial are not' {
        $rows = @(
            [pscustomobject]@{ Engine = 'a'; Phase = 'End'; At = '2026-10-03T05:00:00Z'; ExitReason = 'settings-error'; DurationSec = '1' }
            [pscustomobject]@{ Engine = 'b'; Phase = 'End'; At = '2026-10-03T05:00:00Z'; ExitReason = 'success'; DurationSec = '1' })
        $s = @(Get-SIRunHealthSummary -Rows $rows -NowUtc $script:Now)
        ($s | Where-Object Engine -eq 'a').Problem | Should -Match 'settings-error'
        ($s | Where-Object Engine -eq 'b').Problem | Should -BeNullOrEmpty
    }
    It 'a START newer than the last END, older than the grace period, never ended' {
        $rows = @(
            [pscustomobject]@{ Engine = 'a'; Phase = 'End'; At = '2026-10-02T05:00:00Z'; ExitReason = 'success'; DurationSec = '1' }
            [pscustomobject]@{ Engine = 'a'; Phase = 'Start'; At = '2026-10-03T04:00:00Z'; ExitReason = ''; DurationSec = '' })
        (@(Get-SIRunHealthSummary -Rows $rows -NowUtc $script:Now)[0]).Problem | Should -Match 'never ended'
        (@(Get-SIRunHealthSummary -Rows $rows -NowUtc $script:Now -RunningGraceHours 10)[0]).Problem | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-SIJobsOnce: the plan' {
    It 'cron -> minute of the day' {
        Get-SICronMinuteOfDay '30 4 * * *' | Should -Be 270
        Get-SICronMinuteOfDay '0 3 * * 0' | Should -Be 180
        Get-SICronMinuteOfDay 'nonsense' | Should -Be ([int]::MaxValue)
    }
    It 'groups jobs by start time, in schedule order; the updater and event-triggered jobs are left out' {
        $p = Get-SIJobRunPlan -Jobs $script:Jobs
        @($p.Groups | ForEach-Object At) | Should -Be @('04:00', '04:30', '06:00', '09:00')
        @($p.Groups[0].Jobs | ForEach-Object Name) | Should -Be @('caj-si-endpoint', 'caj-si-ptc')
        @($p.Skipped | ForEach-Object Name) | Should -Be @('caj-si-updater', 'caj-si-shard-worker')
    }
    It '-IncludeUpdater runs the updater first (02:00); -Only and -Exclude narrow the plan' {
        @((Get-SIJobRunPlan -Jobs $script:Jobs -IncludeUpdater).Groups[0].Jobs.Name) | Should -Be @('caj-si-updater')
        @((Get-SIJobRunPlan -Jobs $script:Jobs -Only 'caj-si-identity').Groups | ForEach-Object { $_.Jobs.Name }) | Should -Be @('caj-si-identity')
        @((Get-SIJobRunPlan -Jobs $script:Jobs -Exclude 'caj-si-ptc').Groups[0].Jobs.Name) | Should -Be @('caj-si-endpoint')
    }
}

Describe 'Invoke-SIJobsOnce: the run' {
    It 'starts every job once, group after group, and reports each outcome and duration' {
        $w = New-World @{ Jobs = $script:Jobs }
        $r = Invoke-SIJobRunOnce -Plan (Get-SIJobRunPlan -Jobs $script:Jobs) -Seams $w.Seams -PollSeconds 30
        $r.Ok | Should -BeTrue
        @($w.Started) | Should -Be @('caj-si-endpoint', 'caj-si-ptc', 'caj-si-identity', 'caj-si-risk-analysis', 'caj-si-asset-trend')
        @($r.Runs | ForEach-Object Status | Select-Object -Unique) | Should -Be @('Succeeded')
        ($r.Runs | Where-Object Job -eq 'caj-si-endpoint').DurationMin | Should -Be 7.5
    }
    It 'a group starts only after every execution of the group before it has finished' {
        $w = New-World @{ Jobs = $script:Jobs }
        $null = Invoke-SIJobRunOnce -Plan (Get-SIJobRunPlan -Jobs $script:Jobs) -Seams $w.Seams
        $calls = @($w.Calls)
        $lastPollG1 = [Math]::Max([array]::LastIndexOf($calls, ($calls | Where-Object { $_ -like '*caj-si-endpoint/executions/*' } | Select-Object -Last 1)),
                                  [array]::LastIndexOf($calls, ($calls | Where-Object { $_ -like '*caj-si-ptc/executions/*' } | Select-Object -Last 1)))
        $startG2 = [array]::IndexOf($calls, ($calls | Where-Object { $_ -like '*caj-si-identity/start' } | Select-Object -First 1))
        $startG2 | Should -BeGreaterThan $lastPollG1
    }
    It 'a failed execution, a job that cannot start, and a run past the timeout all fail the run' {
        $w = New-World @{ Jobs = $script:Jobs; JobStatus = @{ 'caj-si-identity' = 'Failed'; 'caj-si-asset-trend' = 'Running' }; StartFails = @('caj-si-ptc') }
        $r = Invoke-SIJobRunOnce -Plan (Get-SIJobRunPlan -Jobs $script:Jobs) -Seams $w.Seams -TimeoutMinutes 5
        $r.Ok | Should -BeFalse
        ($r.Runs | Where-Object Job -eq 'caj-si-identity').Status | Should -Be 'Failed'
        ($r.Runs | Where-Object Job -eq 'caj-si-ptc').Status | Should -Be 'NotStarted'
        ($r.Runs | Where-Object Job -eq 'caj-si-asset-trend').Status | Should -Be 'TimedOut'
        ($r.Runs | Where-Object Job -eq 'caj-si-risk-analysis').Status | Should -Be 'Succeeded' -Because 'a failure does not stop the later groups'
    }
    It 'Invoke-SIJobsOnce.ps1 -PlanOnly prints the order, starts nothing, exits 0' {
        $w = New-World @{ Jobs = $script:Jobs }
        & ([IO.Path]::Combine($script:SIRoot, 'diagnostics', 'Invoke-SIJobsOnce.ps1')) -ConfigPath $script:ConfigPath -PlanOnly -Seams $w.Seams | Out-Null
        $LASTEXITCODE | Should -Be 0
        $w.Started.Count | Should -Be 0
        ($w.Printed -join "`n") | Should -Match '1\. 04:00\s+caj-si-endpoint, caj-si-ptc'
        ($w.Printed -join "`n") | Should -Match 'left out: caj-si-updater'
    }
    It 'Invoke-SIJobsOnce.ps1 exits 1 when a run fails, 0 when all succeed' {
        $w = New-World @{ Jobs = $script:Jobs; JobStatus = @{ 'caj-si-endpoint' = 'Failed' } }
        & ([IO.Path]::Combine($script:SIRoot, 'diagnostics', 'Invoke-SIJobsOnce.ps1')) -ConfigPath $script:ConfigPath -Seams $w.Seams | Out-Null
        $LASTEXITCODE | Should -Be 1
        $w2 = New-World @{ Jobs = $script:Jobs }
        & ([IO.Path]::Combine($script:SIRoot, 'diagnostics', 'Invoke-SIJobsOnce.ps1')) -ConfigPath $script:ConfigPath -Seams $w2.Seams | Out-Null
        $LASTEXITCODE | Should -Be 0
    }
}

Describe 'sign-in without a module (#305)' {
    BeforeEach {
        $script:SavedEnv = @{}
        foreach ($n in 'SI_DIAGNOSTICS_APPID', 'SI_DIAGNOSTICS_TENANTID', 'SI_DIAGNOSTICS_CERTTHUMBPRINT') {
            $script:SavedEnv[$n] = [Environment]::GetEnvironmentVariable($n); [Environment]::SetEnvironmentVariable($n, $null)
        }
        (Get-SIAzRestState).Connection = $null
    }
    AfterEach {
        foreach ($n in $script:SavedEnv.Keys) { [Environment]::SetEnvironmentVariable($n, $script:SavedEnv[$n]) }
        (Get-SIAzRestState).Connection = $null
    }
    It 'AzContext is refused with the alternatives, never an Az session' {
        { Initialize-SIDiagnosticsSignIn -SignIn AzContext -Values @{} } | Should -Throw '*no longer uses an Az PowerShell session*SI_DIAGNOSTICS_APPID*'
        (Get-SIAzRestState).Connection | Should -BeNullOrEmpty
    }
    It 'Auto takes the SI_DIAGNOSTICS_* service principal certificate when all three are set' {
        [Environment]::SetEnvironmentVariable('SI_DIAGNOSTICS_APPID', 'app-1')
        [Environment]::SetEnvironmentVariable('SI_DIAGNOSTICS_TENANTID', 'ten-1')
        [Environment]::SetEnvironmentVariable('SI_DIAGNOSTICS_CERTTHUMBPRINT', 'AB CD')
        Initialize-SIDiagnosticsSignIn -SignIn Auto -Values @{ SI_AuthMethod = 'ManagedIdentity' } | Should -Be 'Certificate'
        $c = (Get-SIAzRestState).Connection
        $c.AppId | Should -Be 'app-1'; $c.TenantId | Should -Be 'ten-1'; $c.Thumbprint | Should -Be 'ABCD'
    }
    It 'Auto falls back to the install''s own identity; Config ignores the environment' {
        Initialize-SIDiagnosticsSignIn -SignIn Auto -Values @{ SI_SPN_AppId = 'a'; SI_SPN_TenantId = 't'; SI_SPN_CertThumbprint = 'th' } | Should -Be 'Certificate'
        [Environment]::SetEnvironmentVariable('SI_DIAGNOSTICS_APPID', 'app-1')
        [Environment]::SetEnvironmentVariable('SI_DIAGNOSTICS_TENANTID', 'ten-1')
        [Environment]::SetEnvironmentVariable('SI_DIAGNOSTICS_CERTTHUMBPRINT', 'AB')
        Initialize-SIDiagnosticsSignIn -SignIn Config -Values @{ SI_SPN_AppId = 'a'; SI_SPN_TenantId = 't'; SI_SPN_CertThumbprint = 'th' } | Should -Be 'Certificate'
        (Get-SIAzRestState).Connection.AppId | Should -Be 'a'
    }
    It 'nothing configured: says how to sign in, without Connect-AzAccount' {
        { Initialize-SIDiagnosticsSignIn -SignIn Auto -Values @{} } | Should -Throw '*SI_DIAGNOSTICS_APPID*'
        try { Initialize-SIDiagnosticsSignIn -SignIn Auto -Values @{} } catch { $_.Exception.Message | Should -Not -Match 'Connect-AzAccount' }
    }
}

Describe 'the diagnostics Azure helper (_DiagnosticsAzure.ps1, #305)' {
    BeforeAll {
        . ([IO.Path]::Combine($script:SIRoot, 'diagnostics', '_DiagnosticsAzure.ps1'))
    }
    BeforeEach {
        $script:SavedEnv = @{}
        foreach ($n in 'SI_DIAGNOSTICS_APPID', 'SI_DIAGNOSTICS_TENANTID', 'SI_DIAGNOSTICS_CERTTHUMBPRINT', 'SI_DIAGNOSTICS_MANAGEDIDENTITY') {
            $script:SavedEnv[$n] = [Environment]::GetEnvironmentVariable($n); [Environment]::SetEnvironmentVariable($n, $null)
        }
        foreach ($g in 'SI_SPN_AppId', 'SI_SPN_TenantId', 'SI_SPN_CertThumbprint', 'SI_SPN_Secret', 'SI_UseManagedIdentity', 'UseManagedIdentity', 'SpnClientId', 'SpnTenantId', 'SpnClientSecret', 'SpnCertificateThumbprint') {
            Remove-Variable -Scope Global -Name $g -ErrorAction SilentlyContinue
        }
        $global:SI_AzRestState = $null
        Mock Get-SIAzRestSubscriptionId { 'sub-1' }
    }
    AfterEach {
        foreach ($n in $script:SavedEnv.Keys) { [Environment]::SetEnvironmentVariable($n, $script:SavedEnv[$n]) }
        $global:SI_AzRestState = $null
    }
    It 'parameters name a service principal certificate' {
        Connect-SIDiagnosticsAzure -AppId 'app-1' -TenantId 'ten-1' -CertificateThumbprint 'AB CD' | Should -Be 'Certificate'
        $c = (Get-SIAzRestState).Connection
        $c.Mode | Should -Be 'Certificate'; $c.AppId | Should -Be 'app-1'; $c.Thumbprint | Should -Be 'ABCD'
    }
    It 'the environment names one when no parameter does' {
        [Environment]::SetEnvironmentVariable('SI_DIAGNOSTICS_APPID', 'app-2')
        [Environment]::SetEnvironmentVariable('SI_DIAGNOSTICS_TENANTID', 'ten-2')
        [Environment]::SetEnvironmentVariable('SI_DIAGNOSTICS_CERTTHUMBPRINT', 'EF')
        Connect-SIDiagnosticsAzure | Should -Be 'Certificate'
        (Get-SIAzRestState).Connection.AppId | Should -Be 'app-2'
    }
    It 'a client secret from a loaded config is not accepted' {
        $global:SI_SPN_AppId = 'a'; $global:SI_SPN_TenantId = 't'; $global:SI_SPN_Secret = 's'
        { Connect-SIDiagnosticsAzure } | Should -Throw '*certificate*managed identity*'
    }
    It 'secrets, the workspace id and queries go over REST' {
        Mock Get-SIKeyVaultSecretValue { if ($Name -eq 'present') { 'v' } else { $null } }
        Get-SIDiagnosticsSecret -VaultName 'kv' -Name 'present' | Should -Be 'v'
        { Get-SIDiagnosticsSecret -VaultName 'kv' -Name 'absent' } | Should -Throw '*not found*'
        Mock Invoke-SIArm { [pscustomobject]@{ properties = [pscustomobject]@{ customerId = 'cust-1' } } }
        Get-SIDiagnosticsWorkspaceId -WorkspaceResourceId '/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws' | Should -Be 'cust-1'
        Should -Invoke Invoke-SIArm -Times 1 -ParameterFilter { $Path -eq '/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws' }
        { Get-SIDiagnosticsWorkspaceId -WorkspaceResourceId '/subscriptions/s/resourceGroups/rg' } | Should -Throw '*not a Log Analytics workspace resource id*'
        Mock Invoke-SILaQuery { [pscustomobject]@{ Results = @([pscustomobject]@{ n = '1' }, [pscustomobject]@{ n = '2' }) } }
        @(Invoke-SIDiagnosticsKql -WorkspaceId 'cust-1' -Query 'T').Count | Should -Be 2
        Should -Invoke Invoke-SILaQuery -Times 1 -ParameterFilter { $WorkspaceId -eq 'cust-1' -and $Wait -eq 300 }
    }
}

Describe 'product-script hygiene' {
    It '<_> needs no Az module and holds no environment value' -ForEach @('diagnostics/Test-SIInstall.ps1', 'diagnostics/Invoke-SIJobsOnce.ps1', 'diagnostics/_SIInstallDiagnostics.ps1') {
        $src = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, ($_ -replace '/', [IO.Path]::DirectorySeparatorChar)))
        $code = (($src -replace '(?s)<#.*?#>', '') -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        # #305: no Az session is borrowed any more either, so Get-AzContext is no longer an exception
        $code | Should -Not -Match '\b(Get|Set|New|Invoke|Search|Remove|Start|Connect)-Az[A-Z]\w*' -Because 'Azure is reached over REST, with SecurityInsight''s own sign-in'
        $code | Should -Not -Match '(?i)\baz\s+(containerapp|monitor|role|resource|login)\b'
        $code | Should -Not -Match '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' -Because 'no tenant, subscription or object id'
    }

    # #305 -- "no ps modules in si v3, everything must run native rest & arm & .net": every diagnostics script and
    # internal tool, not only the two product diagnostics above.
    It 'no diagnostics script or internal tool calls a PowerShell module (<_>)' -ForEach @(
        @(Get-ChildItem -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'diagnostics')) -Filter *.ps1 -File) +
        @(Get-ChildItem -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'INTERNAL')) -Filter *.ps1 -File) |
            ForEach-Object { '{0}/{1}' -f $_.Directory.Name, $_.Name }
    ) {
        $src = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, ($_ -replace '/', [IO.Path]::DirectorySeparatorChar)))
        $code = (($src -replace '(?s)<#.*?#>', '') -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' } | ForEach-Object { $_ -replace '\s#\s.*$', '' }) -join "`n"
        $code | Should -Not -Match '\b(Get|Set|New|Invoke|Search|Remove|Start|Connect|Disconnect|Update)-(Az|Mg)[A-Z]\w*' -Because 'Azure and Graph are reached over REST (engine/_shared/SI-AzRest.ps1, diagnostics/_DiagnosticsAzure.ps1)'
        $code | Should -Not -Match '(?i)\b(Install|Import|Update)-Module\b|Get-Module\s+-ListAvailable' -Because 'nothing is installed or loaded from the PowerShell Gallery'
    }
}
