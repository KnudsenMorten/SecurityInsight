#Requires -Version 5.1
<#
    CONTAINER HOSTING RECEIVES THE CUSTOMER'S SETTINGS, RUNS TREND + THE PRO ENGINES, AND NO LONGER DEMANDS
    AZURE OPENAI OR A STORAGE KEY (#170, #184, #185, #187 -- operator decisions 2026-09-30).

    The container never loads config\SecurityInsight.custom.ps1 (the image must not carry tenant values), so
    each setting used to need its own env-var mapping -- ~45 never had one. One guarded channel now carries
    the customer's NON-SECRET settings as SI_CFG_<name>; secrets travel only as secrets.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    function script:Get-Code([string]$Rel) {
        ((Get-Content -LiteralPath (Join-Path $script:SIRoot $Rel)) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    }
}

Describe 'settings travel as SI_CFG_<name> -- and round-trip with their type' {

    It 'strings, numbers, booleans, arrays and null survive the trip' {
        $globals = @{ SI_Location = 'westeurope'; SI_ActiveStaleDays = 30; SI_IncludeFirstPartySpns = $true
                      SI_AzureSubscriptionExcludePatterns = @('*Visual Studio*', '*Students*'); SI_Cron = '0 4 * * *'; SI_Nothing = $null }
        $r = Get-SIConfigEnvArgs -Names @($globals.Keys) -Globals $globals
        $env = @{}; foreach ($a in $r.EnvArgs) { $k, $v = $a -split '=', 2; $env[$k] = $v }
        $env.Keys | ForEach-Object { $_ | Should -Match '^SI_CFG_' }
        try {
            $imp = Import-SIConfigFromEnv -Environment $env
            @($imp.Applied).Count | Should -Be 6
            $global:SI_Location | Should -BeExactly 'westeurope'
            $global:SI_ActiveStaleDays | Should -Be 30
            $global:SI_IncludeFirstPartySpns | Should -BeTrue
            @($global:SI_AzureSubscriptionExcludePatterns) -join '|' | Should -Be '*Visual Studio*|*Students*'
            $global:SI_Cron | Should -BeExactly '0 4 * * *'
            $global:SI_Nothing | Should -BeNullOrEmpty
        } finally {
            foreach ($n in $globals.Keys) { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
        }
    }

    It 'a single-element array stays an array' {
        $v = ConvertFrom-SIConfigEnvValue -Text (ConvertTo-SIConfigEnvValue -Value @('LA'))
        , $v | Should -BeOfType [object[]]
        @($v).Count | Should -Be 1
    }

    It 'a list whose quotes az.cmd dropped on Windows ([LA,Excel], live 2026-10-06 Community rehearsal) is read back as the list -- never as one unknown sink' {
        $v = ConvertFrom-SIConfigEnvValue -Text '[LA,Excel]'
        , $v | Should -BeOfType [object[]]
        @($v) | Should -Be @('LA', 'Excel')
        $v1 = ConvertFrom-SIConfigEnvValue -Text '[ LA ]'; @($v1) | Should -Be @('LA')
        $v2 = ConvertFrom-SIConfigEnvValue -Text '[*Visual Studio*, *Students*]'; @($v2) | Should -Be @('*Visual Studio*', '*Students*')
        $v3 = ConvertFrom-SIConfigEnvValue -Text '["LA","Excel"]'; @($v3) | Should -Be @('LA', 'Excel') -Because 'the intact form is unchanged'
        ConvertFrom-SIConfigEnvValue -Text '{x y}' | Should -BeExactly '{x y}' -Because 'what is not JSON and not a plain list stays text'
        ConvertFrom-SIConfigEnvValue -Text 'SI_{0}_Profile' | Should -BeExactly 'SI_{0}_Profile'
    }

    It 'secret-looking names are REFUSED on both ends; container-owned names too' {
        $globals = @{ SI_SPN_Secret = 'x'; SMTPPassword = 'x'; OpenAI_apiKey = 'x'; SI_ArchiveAccountKey = 'x'; SI_License = 'x'
                      SI_WorkspaceResourceId = '/subs/x'; SI_Keep = 'ok' }
        $r = Get-SIConfigEnvArgs -Names @($globals.Keys) -Globals $globals
        @($r.EnvArgs).Count | Should -Be 1
        $r.EnvArgs[0] | Should -Be 'SI_CFG_SI_Keep=ok'
        @($r.Refused).Count | Should -Be 6
        # container side: a crafted env var cannot override a credential either
        $imp = Import-SIConfigFromEnv -Environment @{ SI_CFG_SI_SPN_Secret = 'evil'; SI_CFG_SI_StorageAccount = 'evil'; SI_CFG_SI_Ok2 = 'fine' }
        try {
            @($imp.Applied) | Should -Be @('SI_Ok2')
            @($imp.Refused).Count | Should -Be 2
            (Get-Variable -Name SI_SPN_Secret -Scope Global -ValueOnly -ErrorAction SilentlyContinue) | Should -Not -Be 'evil'
        } finally { Remove-Variable -Name SI_Ok2 -Scope Global -ErrorAction SilentlyContinue }
    }

    It '🔴 the internal platform-framework switch never travels to a container, and a crafted one is not applied (live 2026-10-02)' {
        $r = Get-SIConfigEnvArgs -Names @('AutomationFramework', 'SI_Keep') -Globals @{ AutomationFramework = $true; SI_Keep = 'ok' }
        @($r.Refused) | Should -Contain 'AutomationFramework'
        @($r.EnvArgs) | Should -Not -Contain 'SI_CFG_AutomationFramework=True'
        $imp = Import-SIConfigFromEnv -Environment @{ SI_CFG_AutomationFramework = 'True' }
        @($imp.Refused) | Should -Contain 'AutomationFramework'
    }

    It '🔴 WIRING -- the Risk Analysis container sets the names its run-health record reads, before the engine runs (live 2026-10-02)' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'container\Start-RiskAnalysisInContainer.ps1')
        $run = $src.IndexOf('& $engineScript')
        $run | Should -BeGreaterThan 0
        foreach ($n in 'SI_DceName', 'SI_DcrResourceGroup', 'SI_AzSubscriptionId', 'SI_DceResourceGroup') {
            $i = $src.IndexOf(('if (-not $global:{0})' -f $n))
            $i | Should -BeGreaterThan 0 -Because "$n must be set by the entry point"
            $i | Should -BeLessThan $run
        }
    }

    It '🔴 WIRING -- BOTH container entry points apply the customer settings, before they sign in (live 2026-10-02: Risk Analysis ignored them)' {
        foreach ($f in 'container\Start-SIInContainer.ps1', 'container\Start-RiskAnalysisInContainer.ps1') {
            $src = Get-Content -Raw (Join-Path $script:SIRoot $f)
            $i = $src.IndexOf('= Import-SIConfigFromEnv')
            $i | Should -BeGreaterThan 0 -Because "$f must import the SI_CFG_ settings"
            $auth = $src.IndexOf('Resolve-SIContainerAuthMode')
            if ($auth -gt 0 -and $f -like '*RiskAnalysis*') { $i | Should -BeLessThan $auth }
        }
    }

    It 'a name that is not a valid variable name is refused, never evaluated' {
        $imp = Import-SIConfigFromEnv -Environment @{ 'SI_CFG_a;b' = '1'; 'SI_CFG_$(x)' = '1' }
        @($imp.Applied).Count | Should -Be 0
    }
}

Describe 'storage and AI are optional (#184)' {

    It 'storage has no key mode to resolve: the signed-in identity is the only way in (#307)' {
        Get-Command -Name Resolve-SIContainerStorageMode -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'AI is on only when Azure OpenAI is fully configured AND asked for' {
        $full = @{ apiKey = 'k'; endpoint = 'e'; deployment = 'd'; apiVersion = 'v' }
        (Resolve-SIContainerAi -OpenAi $full -Requested $true).Enabled | Should -BeTrue
        (Resolve-SIContainerAi -OpenAi $full -Requested $false).Enabled | Should -BeFalse
        $partial = Resolve-SIContainerAi -OpenAi @{ apiKey = 'k' } -Requested $true
        $partial.Enabled | Should -BeFalse
        $partial.Reason | Should -Match 'not configured .*endpoint'
        (Resolve-SIContainerAi -OpenAi @{} -Requested $false).Configured | Should -BeFalse
    }
}

Describe 'trend and the Pro engines are dispatched exactly as their VM launchers resolve them (#170)' {

    It 'asset-trend: Summary by default; a valid grain and DryRun are honoured' {
        $d = Get-SIContainerEngineDispatch -Engine 'asset-trend'
        $d.Script | Should -Be 'engine/asset-trend/Invoke-SITrend.ps1'
        $d.Args.Grain | Should -Be 'Summary'
        (Get-SIContainerEngineDispatch -Engine 'asset-trend' -Globals @{ SI_Trend_Grain = 'Detailed'; SI_Trend_DryRun = $true }).Args.DryRun | Should -BeTrue
        (Get-SIContainerEngineDispatch -Engine 'asset-trend' -Globals @{ SI_Trend_Grain = 'nonsense' }).Args.Grain | Should -Be 'Summary'
    }
    It 'asset-properties is RETIRED (#412): a job an existing install still starts ends successfully and says why, at both levels' {
        (Get-SIContainerEngineDispatch -Engine 'asset-properties').Skip | Should -Match 'retired'
        $on = Get-SIContainerEngineDispatch -Engine 'asset-properties' -Globals @{ SI_AssetProperties = 'full'; SI_AssetProperties_RowLimit = 50 }
        $on.Skip | Should -Match 'retired'
        $on.Skip | Should -Match 'profilers read each source once'
        $on.Args.Count | Should -Be 0
    }
    It 'asset-cmdb never runs in whatif: not switched on = nothing to do (owner 2026-10-23); Run = apply writes; unknown values stay off' {
        $d = Get-SIContainerEngineDispatch -Engine 'asset-cmdb'
        $d.Skip | Should -Match 'not switched on'
        $d.Args.ContainsKey('WhatIf') | Should -BeFalse
        (Get-SIContainerEngineDispatch -Engine 'asset-cmdb' -Globals @{ SI_Cmdb_Run = 'plan' }).Skip | Should -Match 'not switched on'
        (Get-SIContainerEngineDispatch -Engine 'asset-cmdb' -Globals @{ SI_Cmdb_Run = 'apply' }).Args.Mode | Should -Be 'match-only'
        $apply = Get-SIContainerEngineDispatch -Engine 'asset-cmdb' -Globals @{ SI_Cmdb_Run = 'apply'; SI_Cmdb_Mode = 'create-if-unmatched'; SI_Cmdb_AllowCreate = $true }
        $apply.Args.ContainsKey('WhatIf') | Should -BeFalse
        $apply.Args.Mode | Should -Be 'create-if-unmatched'
        $apply.Args.AllowCreate | Should -BeTrue
        (Get-SIContainerEngineDispatch -Engine 'asset-cmdb' -Globals @{ SI_Cmdb_Run = 'yolo'; SI_Cmdb_Mode = 'weird' }).Skip | Should -Match 'not switched on'
    }
    It 'asset-vulnerabilities (#216) is off without a target, PLANS by default, and arms opening and closing separately' {
        $off = Get-SIContainerEngineDispatch -Engine 'asset-vulnerabilities'
        $off.Skip | Should -Match 'SI_VulnSync_Target'
        $off.Script | Should -Be 'engine/asset-cmdb/Invoke-SIVulnLoop.ps1'
        $plan = Get-SIContainerEngineDispatch -Engine 'asset-vulnerabilities' -Globals @{ SI_VulnSync_Target = 'Sql' }
        $plan.Skip | Should -BeNullOrEmpty
        $plan.Args.WhatIf | Should -BeTrue
        $plan.Args.ContainsKey('AllowCreate') | Should -BeFalse
        $plan.Args.ContainsKey('AllowClose') | Should -BeFalse
        $armed = Get-SIContainerEngineDispatch -Engine 'asset-vulnerabilities' -Globals @{ SI_VulnSync_Target = 'Sql'; SI_VulnSync_Run = 'apply'; SI_VulnSync_AllowCreate = $true; SI_VulnSync_AllowClose = $true }
        $armed.Args.ContainsKey('WhatIf') | Should -BeFalse
        $armed.Args.AllowCreate | Should -BeTrue
        $armed.Args.AllowClose | Should -BeTrue
    }
    It 'asset-vulnerabilities: its own settings win over the CMDB connector''s, which are only the fallback' {
        $fb = Get-SIContainerEngineDispatch -Engine 'asset-vulnerabilities' -Globals @{ SI_VulnSync_Target = 'ServiceNow'; SI_Cmdb_Run = 'apply'; SI_Cmdb_AllowCreate = $true }
        $fb.Args.ContainsKey('WhatIf') | Should -BeFalse
        $fb.Args.AllowCreate | Should -BeTrue
        $own = Get-SIContainerEngineDispatch -Engine 'asset-vulnerabilities' -Globals @{ SI_VulnSync_Target = 'Sql'; SI_Cmdb_Run = 'apply'; SI_Cmdb_AllowCreate = $true; SI_VulnSync_Run = 'plan'; SI_VulnSync_AllowCreate = $false }
        $own.Args.WhatIf | Should -BeTrue
        $own.Args.ContainsKey('AllowCreate') | Should -BeFalse
        (Get-SIContainerEngineDispatch -Engine 'asset-vulnerabilities' -Globals @{ SI_VulnSync_Target = 'Sql'; SI_VulnSync_Run = 'yolo' }).Args.WhatIf | Should -BeTrue
    }
    It 'asset-vulnerabilities with a Pro database: the connectors'' own Mode decides -- the legacy target on the job never makes it whatif (live 2026-10-23)' {
        # every container job carries SI_CFG_SI_VulnSync_Target=Sql; with no SI_VulnSync_Run = 'apply' that sent every
        # customer install down the legacy path in WHATIF, while its SQL connector row said apply
        $pro = @{ SI_ProSqlServer = 's'; SI_ProSqlDatabase = 'd' }
        foreach ($t in 'Sql', 'ServiceNow', '') {
            $gl = $pro.Clone(); if ($t) { $gl['SI_VulnSync_Target'] = $t }
            $d = Get-SIContainerEngineDispatch -Engine 'asset-vulnerabilities' -Globals $gl
            $d.Skip | Should -BeNullOrEmpty -Because "target '$t'"
            $d.Args.ContainsKey('WhatIf') | Should -BeFalse -Because "target '$t': the connector rows carry their own mode"
            $d.Args.ContainsKey('AllowCreate') | Should -BeFalse -Because 'the job arms nothing itself'
        }
        $gl = $pro.Clone(); $gl['SI_VulnSync_Target'] = 'Sql'; $gl['SI_VulnSync_Run'] = 'plan'
        (Get-SIContainerEngineDispatch -Engine 'asset-vulnerabilities' -Globals $gl).Args.WhatIf | Should -BeTrue -Because 'only an explicit plan keeps every connector in whatif'
    }
    It 'asset-correlation passes DryRun and RowLimit; profiling engines are not dispatched here' {
        (Get-SIContainerEngineDispatch -Engine 'asset-correlation' -Globals @{ SI_Correlation_DryRun = $true; SI_Correlation_RowLimit = '10' }).Args.RowLimit | Should -Be 10
        Get-SIContainerEngineDispatch -Engine 'endpoint' | Should -BeNullOrEmpty
    }
    It 'every dispatched script exists and accepts every parameter it can be given' -ForEach @(
        @{ E = 'asset-trend';       G = @{ SI_Trend_DryRun = $true } }
        @{ E = 'asset-correlation'; G = @{ SI_Correlation_DryRun = $true; SI_Correlation_RowLimit = 5 } }
        @{ E = 'asset-properties';  G = @{ SI_AssetProperties = 'full'; SI_AssetProperties_DryRun = $true; SI_AssetProperties_Source = @('x'); SI_AssetProperties_RowLimit = 5 } }
        @{ E = 'asset-cmdb';        G = @{ SI_Cmdb_AllowCreate = $true; SI_Cmdb_RowLimit = 5 } }
        @{ E = 'asset-vulnerabilities'; G = @{ SI_VulnSync_Target = 'Sql'; SI_VulnSync_AllowCreate = $true; SI_VulnSync_AllowClose = $true } }
        @{ E = 'asset-tagging';     G = @{ SI_AssetTagging_Enabled = $true; SI_Pro_AssetTagging_Apply = $true } }
    ) {
        $d = Get-SIContainerEngineDispatch -Engine $E -Globals $G
        $path = Join-Path $script:SIRoot ($d.Script -replace '/', '\')
        if (-not (Test-Path -LiteralPath $path)) { Set-ItResult -Skipped -Because 'SecurityInsight Pro is not in this copy'; return }
        $params = (Get-Command -Name $path).Parameters.Keys
        foreach ($k in $d.Args.Keys) { $params | Should -Contain $k -Because "$E is dispatched with -$k" }
    }
}

Describe 'WIRING -- the entrypoints and Bootstrap actually use it' {

    It 'the worker entrypoint imports settings first, decides storage and AI, and dispatches trend + Pro' {
        $c = Get-Code 'container\Start-SIInContainer.ps1'
        $c | Should -Match 'Import-SIConfigFromEnv'
        $c | Should -Not -Match 'Resolve-SIContainerStorageMode|SI_STORAGE_KEY'
        $c | Should -Match 'Resolve-SIContainerAi'
        $c | Should -Match 'Get-SIContainerEngineDispatch'
        $c | Should -Match "'asset-trend', 'asset-correlation', 'asset-properties', 'asset-cmdb', 'asset-vulnerabilities'"
        $c | Should -Not -Match "Get-RequiredEnv 'SI_STORAGE_KEY'"
        $c | Should -Not -Match "Get-RequiredEnv 'OPENAI_"
        $c | Should -Match 'SHODAN_API_KEY'
        $c | Should -Match 'SI_LICENSE'
        # settings first, credentials after (so the credentials always win)
        $c.IndexOf('Import-SIConfigFromEnv') | Should -BeLessThan $c.IndexOf("Get-RequiredEnv 'SI_SPN_APPID'")
    }
    It 'the producer and the run-log upload reach storage with the identity, never a key' {
        Get-Code 'container\Invoke-ShardProducer.ps1' | Should -Not -Match "Get-RequiredEnv 'SI_STORAGE_KEY'"
        Get-Code 'launcher\_lib\Publish-LauncherTranscript.ps1' | Should -Match 'New-SIStorageContext -AccountName \$account\)'
    }
    It 'Bootstrap no longer requires a key or OpenAI, passes the config, the Shodan key and the licence, and schedules trend LAST' {
        $c = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        $req = [regex]::Match($c, '(?s)\$reqGlobals = @\((.*?)\)').Groups[1].Value
        $req | Should -Not -BeNullOrEmpty
        $req | Should -Not -Match 'SI_StorageKey' -Because 'storage is reached with the identity (#307)'
        $req | Should -Not -Match 'OpenAI_' -Because 'Azure OpenAI is optional (#184)'
        $c | Should -Match 'Get-SIConfigEnvArgs'
        $c | Should -Match 'SHODAN_API_KEY=secretref:shodan-key'
        $c | Should -Match 'SI_LICENSE=secretref:si-license'
        $c | Should -Match "'asset-trend'\s+\{ \`$ScheduleTrend \}"
        $t = [regex]::Match($c, "ScheduleTrend\s+=\s+'(\d+) (\d+)").Groups
        $ra = [regex]::Match($c, "ScheduleRiskAnalysisDetailed\s*=\s*'(\d+) (\d+)").Groups
        ([int]$t[2].Value * 60 + [int]$t[1].Value) | Should -BeGreaterThan ([int]$ra[2].Value * 60 + [int]$ra[1].Value) -Because 'trend rolls up what RA published'
    }
    It 'Bootstrap (#216) adds the close-loop job where its code exists, schedules it LAST, and gives it the licence' {
        $c = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        # #269: two jobs -- the SQL connector's and the ServiceNow connector's (the latter only where ServiceNow is configured)
        $c | Should -Match "engine\\asset-cmdb\\Invoke-SIVulnLoop\.ps1'\)\) \{ \`$Engines \+= @\('asset-vulnerabilities', 'asset-vulnerabilities-servicenow'\) \}"
        $c | Should -Match "'asset-vulnerabilities'\s+\{ \`$ScheduleVulnerabilities \}"
        $c | Should -Match "\`$licensedEngines = @\([^)]*'asset-cmdb', 'asset-vulnerabilities'"
        $minutes = { param($name) $m = [regex]::Match($c, "$name\s*=\s*'(\d+) (\d+)").Groups; [int]$m[2].Value * 60 + [int]$m[1].Value }
        $v = & $minutes 'ScheduleVulnerabilities'
        foreach ($other in 'ScheduleRiskAnalysisDetailed', 'ScheduleTrend', 'ScheduleCmdb') {
            $v | Should -BeGreaterThan (& $minutes $other) -Because "the close-loop needs the finished Detailed snapshot ($other runs before it)"
        }
    }
}

Describe 'Risk Analysis mail in containers (#218)' {
    It 'mail is wanted when any send switch is on, and needs the password unless anonymous' {
        (Get-SIContainerRaMailPlan -Globals @{}).Wanted | Should -BeFalse
        $p = Get-SIContainerRaMailPlan -Globals @{ RiskAnalysis_Summary_SendMail = $true }
        $p.Wanted | Should -BeTrue
        $p.NeedsPassword | Should -BeTrue
        (Get-SIContainerRaMailPlan -Globals @{ RiskAnalysis_Detailed_SendMail = $true; Mail_SendAnonymous = $true }).NeedsPassword | Should -BeFalse
        (Get-SIContainerRaMailPlan -Globals @{ Mail_SecurityInsight_Detailed_SendMail = $true }).Wanted | Should -BeTrue -Because 'the legacy name still switches it on'
        (Get-SIContainerRaMailPlan -Globals @{ SendMail = $true }).Wanted | Should -BeTrue
        (Get-SIContainerRaMailPlan -Globals @{ RiskAnalysis_Summary_SendMail = $false; SendMail = 'false' }).Wanted | Should -BeFalse
    }
    It 'the SMTP password itself never travels as a plain setting' {
        Test-SIConfigNameIsSecret -Name 'SMTPPassword' | Should -BeTrue
        $r = Get-SIConfigEnvArgs -Names @('SMTPPassword', 'SmtpServer') -Globals @{ SMTPPassword = 'x'; SmtpServer = 'smtp.example' }
        @($r.Refused) | Should -Contain 'SMTPPassword'
        @($r.EnvArgs) -join ' ' | Should -Match 'SI_CFG_SmtpServer=smtp.example'
    }
    It 'the identity is granted ONE Key Vault role when the SMTP password shares a vault with the OpenAI key' {
        $plan = Get-SIContainerIdentityGrantPlan -Mode 'ManagedIdentity' -OpenAIKeyVaultId '/kv/a' -SmtpKeyVaultId '/kv/a'
        @($plan | Where-Object { $_.Role -eq 'Key Vault Secrets User' }).Count | Should -Be 1
        $plan2 = Get-SIContainerIdentityGrantPlan -Mode 'ManagedIdentity' -SmtpKeyVaultId '/kv/mail'
        @($plan2 | Where-Object { $_.Role -eq 'Key Vault Secrets User' -and $_.Scope -eq '/kv/mail' }).Count | Should -Be 1
    }
    It 'WIRING -- Bootstrap gives the RA jobs the password as a Key Vault reference, and warns at setup when it cannot' {
        $c = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        $c | Should -Match '\$raMail = Get-SIContainerRaMailPlan -Globals \$cfgGlobals'
        $c | Should -Match "if \(\`$isRiskAnalysis -and \`$raMail\.NeedsPassword\)"
        $c | Should -Match "Resolve-SIJobKeyVaultSecret -Alias 'smtp-password'"
        $c | Should -Match 'SMTP_PASSWORD=secretref:smtp-password'
        $c | Should -Match '-SmtpKeyVaultId'
        $c | Should -Match "\[mail\] Risk Analysis mail is ON in the config, but no SMTP password reaches"
    }
    It 'WIRING -- the RA entry point maps the secret to the global the engine pre-flight checks, after the settings import' {
        $c = Get-Code 'container\Start-RiskAnalysisInContainer.ps1'
        $c | Should -Match "Get-OptionalEnv 'SMTP_PASSWORD'"
        $c | Should -Match '\$global:SMTPPassword = \$smtpPassword'
        $c.IndexOf('Import-SIConfigFromEnv') | Should -BeLessThan $c.IndexOf("Get-OptionalEnv 'SMTP_PASSWORD'")
        Get-Code 'engine\risk-analysis\Invoke-RiskAnalysis.ps1' | Should -Match 'IsNullOrWhiteSpace\(\[string\]\$global:SMTPPassword\)' -Because 'the pre-flight is what the password must satisfy'
    }
}

Describe 'the environment logs to the install''s own workspace (#220)' {
    It 'the diagnostic setting sends console + system logs to the given workspace' {
        $b = Get-SIEnvironmentLogSettingBody -WorkspaceResourceId '/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w' | ConvertFrom-Json
        $b.properties.workspaceId | Should -Match '/workspaces/w$'
        @($b.properties.logs | Where-Object enabled | ForEach-Object { $_.category }) | Should -Be @('ContainerAppConsoleLogs', 'ContainerAppSystemLogs')
    }
    It 'WIRING -- Bootstrap creates the environment with Azure Monitor logs and adds the setting into SI_WorkspaceResourceId' {
        $c = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        # #521: over ARM (setup\_shared\SI-SetupArm.ps1) -- the environment body carries the Azure Monitor destination
        # (Initialize-SIManagedEnvironment reads an existing one's state and creates through New-SIManagedEnvironment)
        $c | Should -Match 'Initialize-SIManagedEnvironment -ResourceGroupName \$ResourceGroupName -Name \$EnvName -Location \$Location'
        $c | Should -Match 'Set-SIEnvironmentLogSetting -EnvironmentId \(\[string\]\$cae\.id\) -WorkspaceResourceId \(\[string\]\$global:SI_WorkspaceResourceId\)'
        $arm = Get-Code 'setup\_shared\SI-SetupArm.ps1'
        $arm | Should -Match "appLogsConfiguration = \[ordered\]@\{ destination = 'azure-monitor' \}"
        $arm | Should -Match 'Get-SIEnvironmentLogSettingBody -WorkspaceResourceId \$WorkspaceResourceId'
        $arm | Should -Match 'diagnosticSettings/si-environment-logs'
    }
}
