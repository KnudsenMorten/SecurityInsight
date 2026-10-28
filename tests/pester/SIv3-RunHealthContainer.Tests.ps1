#Requires -Version 5.1
<#
    RUN-HEALTH RECORDS ARE SAVED IN A CONTAINER (#281).

    Found live 2026-10-05 on ring 1, every run since at least 2026-10-04:
      * every profiler and the flow:  "Run-health record could not be saved: Cannot bind argument to parameter
        'SubscriptionId' because it is an empty string." -- no container ever set SI_AzSubscriptionId; on a VM it comes
        from the customer's config or the profilers' prestage backfill, and neither reaches a container.
      * Risk Analysis (both) and the trend: "the data collection rule 'dcr-si-run-health' was not found in resource
        group ...". Risk Analysis kept its identity only as Spn*, so the record signed in with an EMPTY app id, and the
        ingest module skips the create silently when it has no app id. And with the module's tenant-wide rule list, a
        same-named rule of ANOTHER install made the module believe the rule existed, so it created nothing.
    Every reader of SI_RunHealth_CL (the Pro Run health page, Risk Analysis' "profiler was partial" rule, guard rows, the
    flow's never-started retry) saw an empty table on containers.

    WHY THE EARLIER SUITES MISSED IT: they tested the pieces with a subscription handed in (Select-/Test-SIRunHealth*
    -SubscriptionId 'mine'), and the "missing settings" tests only ever cleared the workspace/endpoint names -- no test
    ran the sender with what a container actually HAS (workspace id, endpoint name, rule resource group, the jobs'
    subscription) and nothing else. These tests run the container's real env mapping, then the real sender, with only
    the network calls stubbed.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1')
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')

    $script:Sub     = '11111111-1111-1111-1111-111111111111'
    $script:JobsSub = '22222222-2222-2222-2222-222222222222'
    $script:Rg      = 'rg-si-r1-pro-ca'
    $script:Ws      = "/subscriptions/$($script:Sub)/resourceGroups/$($script:Rg)/providers/Microsoft.OperationalInsights/workspaces/log-si-r1"
    $script:DceId   = "/subscriptions/$($script:Sub)/resourceGroups/$($script:Rg)/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si-r1"
    $script:OurDcr  = [pscustomobject]@{ name = 'dcr-si-run-health'; id = "/subscriptions/$($script:Sub)/resourceGroups/$($script:Rg)/providers/Microsoft.Insights/dataCollectionRules/dcr-si-run-health"; location = 'westeurope'; properties = [pscustomobject]@{ immutableId = 'dcr-ours' } }
    # another install in the same tenant (the module's rule list is tenant-wide)
    $script:ForeignDcr = [pscustomobject]@{ name = 'dcr-si-run-health'; id = '/subscriptions/99999999-9999-9999-9999-999999999999/resourceGroups/rg-securityinsight/providers/Microsoft.Insights/dataCollectionRules/dcr-si-run-health'; location = 'westeurope'; properties = [pscustomobject]@{ immutableId = 'dcr-foreign' } }
    $script:OtherDcr   = [pscustomobject]@{ name = 'dcr-si-endpoint'; id = "/subscriptions/$($script:Sub)/resourceGroups/$($script:Rg)/providers/Microsoft.Insights/dataCollectionRules/dcr-si-endpoint" }

    # Exactly what a ring-1 job carries (Bootstrap-ContainerAppJob.ps1) -- and NO subscription anywhere else.
    $script:Ring1Env = @{
        SI_WORKSPACE_RESOURCEID = $script:Ws
        SI_JOBS_SUBSCRIPTIONID  = $script:JobsSub
        SI_DCE_NAME             = 'dce-si-r1'
        SI_DCR_RESOURCEGROUP    = $script:Rg
    }
    $script:GlobalNames = @('SI_AzSubscriptionId', 'SI_WorkspaceResourceId', 'SI_DceName', 'SI_DcrResourceGroup', 'SI_DceResourceGroup',
        'SI_SPN_AppId', 'SI_SPN_TenantId', 'SI_SPN_Secret', 'SI_SPN_ObjectId', 'SI_SPN_CertThumbprint', 'SI_SPN_CertStoreLocation',
        'SI_LogIngest_AppId', 'SI_LogIngest_TenantId', 'SI_LogIngest_Secret', 'SI_LogIngest_ObjectId', 'SpnClientId', 'SpnTenantId', 'SpnClientSecret',
        'SI_PreferUami', 'SI_UAMI_ClientId', 'SI_RunHealth_DcrName', 'SI_RunHealthFailWarned', 'SI_RunHealthMismatchWarned', 'SubscriptionId',
        'AzDceDetails', 'AzDcrDetails', 'WhatIfMode')
    $script:EnvNames = @('SI_WORKSPACE_RESOURCEID', 'SI_JOBS_SUBSCRIPTIONID', 'SI_FLOW_SUBSCRIPTIONID', 'SI_DCE_NAME', 'SI_DCR_RESOURCEGROUP', 'SI_DCE_RESOURCEGROUP', 'SI_SPN_OBJECTID')

    function script:Save-RHState {
        $s = @{ G = @{}; E = @{} }
        foreach ($n in $script:GlobalNames) { $s.G[$n] = Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
        foreach ($n in $script:EnvNames) { $s.E[$n] = [Environment]::GetEnvironmentVariable($n) }
        $s
    }
    function script:Restore-RHState { param($S)
        foreach ($n in $script:GlobalNames) { Set-Variable -Name $n -Scope Global -Value $S.G[$n] }
        foreach ($n in $script:EnvNames) { [Environment]::SetEnvironmentVariable($n, $S.E[$n]) }
    }
    function script:Clear-RHState {
        foreach ($n in $script:GlobalNames) { Set-Variable -Name $n -Scope Global -Value $null }
        foreach ($n in $script:EnvNames) { [Environment]::SetEnvironmentVariable($n, $null) }
    }
    function script:Set-Ring1Env { foreach ($k in $script:Ring1Env.Keys) { [Environment]::SetEnvironmentVariable($k, $script:Ring1Env[$k]) } }
    function script:New-RHContext { [pscustomobject]@{ RunId = 'r1'; Engine = 'identity'; ShardIndex = 0; ShardCount = 1; StartedAt = [datetime]::UtcNow; CollectionTime = [datetime]::UtcNow } }
}

Describe 'the container''s env -> ingest globals mapping (#281)' {
    BeforeEach { $script:st = Save-RHState; Clear-RHState; Set-Ring1Env }
    AfterEach  { Restore-RHState $script:st }

    It 'ring-1 env, no Az context: the subscription is the WORKSPACE''s, the endpoint lives with the rules' {
        Mock Get-SIAzContext { $null }
        $r = Initialize-SIContainerIngestGlobals
        $global:SI_AzSubscriptionId | Should -Be $script:Sub
        $r.SubscriptionId           | Should -Be $script:Sub
        $global:SI_DceName          | Should -Be 'dce-si-r1'
        $global:SI_DcrResourceGroup | Should -Be $script:Rg
        $global:SI_DceResourceGroup | Should -Be $script:Rg
    }
    It 'a value the customer''s settings already gave stands' {
        $global:SI_AzSubscriptionId = 'from-config'; $global:SI_DceResourceGroup = 'rg-dce-custom'
        $null = Initialize-SIContainerIngestGlobals
        $global:SI_AzSubscriptionId | Should -Be 'from-config'
        $global:SI_DceResourceGroup | Should -Be 'rg-dce-custom'
    }
    It 'no subscription in the workspace id: the jobs'' subscription, then the Az context' {
        Mock Get-SIAzContext { [pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 'from-context' } } }
        $fakeEnv = @{ SI_WORKSPACE_RESOURCEID = 'log-si-r1'; SI_JOBS_SUBSCRIPTIONID = $script:JobsSub }
        $reader = { param($n) $fakeEnv[$n] }.GetNewClosure()
        $null = Initialize-SIContainerIngestGlobals -GetEnv $reader
        $global:SI_AzSubscriptionId | Should -Be $script:JobsSub
        $global:SI_AzSubscriptionId = $null; $global:SI_WorkspaceResourceId = $null
        $fakeEnv.Remove('SI_JOBS_SUBSCRIPTIONID')
        $null = Initialize-SIContainerIngestGlobals -GetEnv $reader
        $global:SI_AzSubscriptionId | Should -Be 'from-context'
    }
    It 'Risk Analysis'' identity names (Spn*) become the names the run-health record signs in with' {
        $global:SpnClientId = 'app-ra'; $global:SpnTenantId = 'tenant-ra'
        [Environment]::SetEnvironmentVariable('SI_SPN_OBJECTID', 'obj-ra')
        $null = Initialize-SIContainerIngestGlobals
        $global:SI_SPN_AppId       | Should -Be 'app-ra'
        $global:SI_SPN_TenantId    | Should -Be 'tenant-ra'
        $global:SI_SPN_ObjectId    | Should -Be 'obj-ra'
        $global:SI_LogIngest_AppId | Should -Be 'app-ra'
    }
    It 'PURE resolver order: setting > workspace > jobs > context; nothing -> empty' {
        Resolve-SIContainerSubscriptionId -AzSubscriptionId 'a' -WorkspaceResourceId @($script:Ws) -JobsSubscriptionId @('j') -ContextSubscriptionId 'c' | Should -Be 'a'
        Resolve-SIContainerSubscriptionId -WorkspaceResourceId @('', $script:Ws) -JobsSubscriptionId @('j') -ContextSubscriptionId 'c' | Should -Be $script:Sub
        Resolve-SIContainerSubscriptionId -WorkspaceResourceId @('') -JobsSubscriptionId @('', 'j') -ContextSubscriptionId 'c' | Should -Be 'j'
        Resolve-SIContainerSubscriptionId -ContextSubscriptionId 'c' | Should -Be 'c'
        Resolve-SIContainerSubscriptionId | Should -Be ''
    }
}

Describe 'the run-health record reaches Log Analytics from a container (#281)' {
    BeforeEach {
        $script:st = Save-RHState; Clear-RHState; Set-Ring1Env
        $script:calls = @{ Reach = @(); Update = @(); Send = @(); CacheAtUpdate = $null }
        Mock Get-SIAzContext { $null }
        Mock Send-SITelemetryRunEnd { }
        Mock Repair-SILogColumnName { $Data }
        Mock Format-SILogRowsToSchema { $Data }
        # ARM: the pre-flight (404 -- no rule yet) and, after the create, the rule read by its id
        Mock Invoke-SIAzRestMethod {
            $script:calls.Reach += [string]$Path
            if ($script:ruleCreated -and $Path -like "*/resourceGroups/$($script:Rg)/providers/Microsoft.Insights/dataCollectionRules/dcr-si-run-health*") {
                return [pscustomobject]@{ StatusCode = 200; Content = ($script:OurDcr | ConvertTo-Json -Depth 5) }
            }
            [pscustomobject]@{ StatusCode = 404; Content = '' }
        }
        # the module's tenant-wide lists: our endpoint; another install's same-named rule; Resource Graph does not show
        # the rule created seconds ago yet
        Mock Get-SIDceList { @([pscustomobject]@{ name = 'dce-si-r1'; id = $script:DceId; location = 'westeurope' }) }
        Mock Get-SIDcrList { @($script:ForeignDcr, $script:OtherDcr) }
        Mock Update-SILogTableSchema {
            $script:calls.Update += [pscustomobject]@{ AzAppId = $AzAppId; DcrName = $DcrName; DcrResourceGroup = $DcrResourceGroup; DceName = $DceName; Ws = $AzLogWorkspaceResourceId; Thumb = $AzAppCertificateThumbprint }
            $script:calls.CacheAtUpdate = @($global:AzDcrDetails)
            $script:ruleCreated = $true
        }
        Mock Send-SILogData { $script:calls.Send += [pscustomobject]@{ DcrName = $DcrName; DceName = $DceName; Table = $TableName; AzAppId = $AzAppId; Rules = @($global:AzDcrDetails); Endpoints = @($global:AzDceDetails) } }
        $script:ruleCreated = $false
    }
    AfterEach { Restore-RHState $script:st }

    It 'a PROFILER job (Start-SIInContainer shape): the subscription is resolved, the rule is created in the job''s resource group, and the record is posted' {
        # what Start-SIInContainer.ps1 sets itself in certificate mode
        $global:SI_SPN_AppId = 'app-si'; $global:SI_SPN_TenantId = 'tenant'; $global:SI_SPN_CertThumbprint = 'ABC'; $global:SI_SPN_CertStoreLocation = 'CurrentUser'
        $global:SI_WorkspaceResourceId = $script:Ws; $global:SI_DceName = 'dce-si-r1'; $global:SI_DcrResourceGroup = $script:Rg
        $null = Initialize-SIContainerIngestGlobals
        $w = @()
        Send-SIRunHealthRow -RunContext (New-RHContext) -Phase Start -WarningVariable +w -WarningAction SilentlyContinue
        @($w).Count | Should -Be 0 -Because ([string]($w -join ' | '))
        @($script:calls.Reach)[0] | Should -Match ("/subscriptions/{0}/resourceGroups/{1}/" -f $script:Sub, $script:Rg)
        @($script:calls.Update).Count | Should -Be 1
        $script:calls.Update[0].DcrName          | Should -Be 'dcr-si-run-health'
        $script:calls.Update[0].DcrResourceGroup | Should -Be $script:Rg
        $script:calls.Update[0].AzAppId          | Should -Be 'app-si'
        @($script:calls.Send).Count | Should -Be 1
        $script:calls.Send[0].DcrName | Should -Be 'dcr-si-run-health'
        $script:calls.Send[0].Table   | Should -Be 'SI_RunHealth'
        @($script:calls.Send[0].Rules).Count | Should -Be 1
        $script:calls.Send[0].Rules[0].id | Should -Be $script:OurDcr.id -Because 'the post must go through THIS install''s rule, never the same-named one of another install'
        $script:calls.Send[0].Endpoints[0].id | Should -Be $script:DceId
    }
    It 'the rule of the same name in ANOTHER install is not in the cache when the module decides whether to create the rule' {
        $global:SI_SPN_AppId = 'app-si'; $global:SI_SPN_TenantId = 'tenant'; $global:SI_SPN_CertThumbprint = 'ABC'; $global:SI_SPN_CertStoreLocation = 'CurrentUser'
        $null = Initialize-SIContainerIngestGlobals
        Send-SIRunHealthRow -RunContext (New-RHContext) -Phase Start -WarningAction SilentlyContinue
        @($script:calls.CacheAtUpdate | Where-Object { $_.name -eq 'dcr-si-run-health' }).Count | Should -Be 0
        @($script:calls.CacheAtUpdate | Where-Object { $_.name -eq 'dcr-si-endpoint' }).Count | Should -Be 1 -Because 'the other publishers'' rules stay'
    }
    It 'a RISK ANALYSIS job (Start-RiskAnalysisInContainer shape -- identity only as Spn*): signs in with the app id, not an empty one' {
        $global:SpnClientId = 'app-ra'; $global:SpnTenantId = 'tenant'; $global:SI_SPN_CertThumbprint = 'ABC'; $global:SI_SPN_CertStoreLocation = 'CurrentUser'
        $global:SI_WorkspaceResourceId = $script:Ws; $global:SI_DceName = 'dce-si-r1'; $global:SI_DcrResourceGroup = $script:Rg
        $global:SI_AzSubscriptionId = $script:Sub; $global:SI_DceResourceGroup = $script:Rg   # RA's entry already set these
        $null = Initialize-SIContainerIngestGlobals
        Send-SIRunHealthRow -RunContext (New-RHContext) -Phase End -ExitReason success -WarningAction SilentlyContinue
        $script:calls.Update[0].AzAppId | Should -Be 'app-ra'
        $script:calls.Send[0].AzAppId   | Should -Be 'app-ra'
        $script:calls.Send[0].Rules[0].id | Should -Be $script:OurDcr.id
    }
    It 'DEFENSIVE: a host that never mapped anything (no SI_AzSubscriptionId, no SI_DceResourceGroup, Spn* identity) still posts' {
        $global:SpnClientId = 'app-x'; $global:SpnTenantId = 'tenant'; $global:SpnClientSecret = 's'
        $global:SI_WorkspaceResourceId = $script:Ws; $global:SI_DceName = 'dce-si-r1'; $global:SI_DcrResourceGroup = $script:Rg
        $w = @()
        Send-SIRunHealthRow -RunContext (New-RHContext) -Phase Start -WarningVariable +w -WarningAction SilentlyContinue
        @($w).Count | Should -Be 0 -Because ([string]($w -join ' | '))
        @($script:calls.Send).Count | Should -Be 1
        $global:SI_AzSubscriptionId | Should -Be $script:Sub -Because 'filled back so the rest of the run has it'
    }
    It 'no subscription anywhere: said once, never thrown, nothing posted' {
        $global:SI_SPN_AppId = 'a'; $global:SI_SPN_Secret = 's'
        $global:SI_WorkspaceResourceId = 'log-without-an-id'; $global:SI_DceName = 'dce-si-r1'; $global:SI_DcrResourceGroup = $script:Rg
        foreach ($n in $script:EnvNames) { [Environment]::SetEnvironmentVariable($n, $null) }
        $w = @()
        Send-SIRunHealthRow -RunContext (New-RHContext) -Phase Start -WarningVariable +w -WarningAction SilentlyContinue   # a throw fails the test
        Send-SIRunHealthRow -RunContext (New-RHContext) -Phase End   -WarningVariable +w -WarningAction SilentlyContinue
        @($w).Count | Should -Be 1
        [string]$w[0] | Should -Match 'no subscription'
        [string]$w[0] | Should -Not -Match 'Cannot bind argument'
        @($script:calls.Send).Count | Should -Be 0
    }
    It 'no sign-in identity: said once (the ingest module would skip the create SILENTLY), never thrown' {
        $global:SI_WorkspaceResourceId = $script:Ws; $global:SI_DceName = 'dce-si-r1'; $global:SI_DcrResourceGroup = $script:Rg
        $w = @()
        Send-SIRunHealthRow -RunContext (New-RHContext) -Phase Start -WarningVariable +w -WarningAction SilentlyContinue   # a throw fails the test
        @($w).Count | Should -Be 1
        [string]$w[0] | Should -Match 'no sign-in identity'
        @($script:calls.Update).Count | Should -Be 0
    }
    It 'the rule does exist and Resource Graph lists it: pinned straight away, no read by id needed' {
        Mock Get-SIDcrList { @($script:ForeignDcr, $script:OurDcr) }
        $global:SI_SPN_AppId = 'app-si'; $global:SI_SPN_Secret = 's'; $global:SI_SPN_TenantId = 't'
        $null = Initialize-SIContainerIngestGlobals
        Send-SIRunHealthRow -RunContext (New-RHContext) -Phase Start -WarningAction SilentlyContinue
        $script:calls.Send[0].Rules[0].id | Should -Be $script:OurDcr.id
    }
}

Describe 'the rule lookup the Risk Analysis and trend records go through (#281)' {
    BeforeEach { $script:dceSaved = $global:AzDceDetails; $script:dcrSaved = $global:AzDcrDetails }
    AfterEach  { $global:AzDceDetails = $script:dceSaved; $global:AzDcrDetails = $script:dcrSaved }

    It 'no rule HERE yet: the same-named rule of another install is dropped from the cache, every other rule stays' {
        $global:AzDceDetails = @([pscustomobject]@{ name = 'dce-si-r1'; id = $script:DceId })
        $global:AzDcrDetails = @($script:ForeignDcr, $script:OtherDcr)
        Select-SIRunHealthIngestTarget -SubscriptionId $script:Sub -DceResourceGroup $script:Rg -DceName 'dce-si-r1' -DcrResourceGroup $script:Rg -DcrName 'dcr-si-run-health' -AllowMissingDcr | Should -BeTrue
        @($global:AzDcrDetails | Where-Object { $_.name -eq 'dcr-si-run-health' }).Count | Should -Be 0
        @($global:AzDcrDetails).Count | Should -Be 1
    }
    It 'without -AllowMissingDcr the cache is left as it was (the caller rebuilds it)' {
        $global:AzDceDetails = @([pscustomobject]@{ name = 'dce-si-r1'; id = $script:DceId })
        $global:AzDcrDetails = @($script:ForeignDcr, $script:OtherDcr)
        Select-SIRunHealthIngestTarget -SubscriptionId $script:Sub -DceResourceGroup $script:Rg -DceName 'dce-si-r1' -DcrResourceGroup $script:Rg -DcrName 'dcr-si-run-health' | Should -BeFalse
        @($global:AzDcrDetails).Count | Should -Be 2
    }
    It 'the rule read by its id has the shape the module''s cache holds (id, location, properties.immutableId)' {
        Mock Invoke-SIAzRestMethod { [pscustomobject]@{ StatusCode = 200; Content = ($script:OurDcr | ConvertTo-Json -Depth 5) } }
        $armRule = Get-SIRunHealthDcrFromArm -SubscriptionId $script:Sub -ResourceGroup $script:Rg -Name 'dcr-si-run-health'
        $armRule.id | Should -Be $script:OurDcr.id
        $armRule.properties.immutableId | Should -Be 'dcr-ours'
        Mock Invoke-SIAzRestMethod { [pscustomobject]@{ StatusCode = 404; Content = '' } }
        Get-SIRunHealthDcrFromArm -SubscriptionId $script:Sub -ResourceGroup $script:Rg -Name 'dcr-si-run-health' | Should -BeNullOrEmpty
        Mock Invoke-SIAzRestMethod { throw 'network' }
        { Get-SIRunHealthDcrFromArm -SubscriptionId $script:Sub -ResourceGroup $script:Rg -Name 'x' } | Should -Not -Throw
    }
    It 'the trend / tagging records (SI-RunHealthScope) keep the configured rule name -- the profile-table rename (D4) never applies to run health' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1')
        $src | Should -Not -Match 'Resolve-SILogDcrNameForTable'
        $src | Should -Match "\`$dcrName\s+=\s+if \(-not \[string\]::IsNullOrWhiteSpace\(\[string\]\`$global:SI_RunHealth_DcrName\)\) \{ \[string\]\`$global:SI_RunHealth_DcrName \} else \{ 'dcr-si-run-health' \}"
    }
}

Describe 'WIRING: both container entry points run the mapping after sign-in, before any engine or record (#281)' {
    It '<_> calls Initialize-SIContainerIngestGlobals after Connect-SIAzAccount and before anything that sends a record' -ForEach @('Start-SIInContainer.ps1', 'Start-RiskAnalysisInContainer.ps1') {
        $src = Get-Content -Raw (Join-Path $script:SIRoot ('container\' + $_))
        $call = $src.IndexOf('$siIngest = Initialize-SIContainerIngestGlobals')
        $call | Should -BeGreaterThan 0
        $call | Should -BeGreaterThan $src.LastIndexOf('Connect-SIAzAccount')
        foreach ($later in @('Send-SIRunHealthRow -Phase', '& $engineScript', '& $classifierScript', '& $script @argsForEngine')) {
            $at = $src.IndexOf($later)
            if ($at -ge 0) { $call | Should -BeLessThan $at -Because "$later must see the mapped globals" }
        }
    }
    It 'the sender never hands the raw global subscription to a mandatory parameter (the 2026-10-05 failure)' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1')
        $body = $src.Substring($src.IndexOf('function Send-SIRunHealthRow'))
        $body | Should -Not -Match '-SubscriptionId\s+\$global:SI_AzSubscriptionId'
        $body | Should -Not -Match '-DceResourceGroup\s+\$global:SI_DceResourceGroup'
    }
}
