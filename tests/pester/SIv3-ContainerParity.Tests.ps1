#Requires -Version 5.1
<#
    EVERY v2.2 VM-LAUNCHER FEATURE WORKS IN PURE CONTAINER MODE (#238).

    A read-only sweep (2026-10-03) compared every VM launcher switch and setting with the container jobs and found gaps
    where a container silently ran differently from a VM: Risk Analysis never sent to Log Analytics, the job's own env
    defaults overwrote the customer's config, the per-engine launcher configs never reached a container, the classifier
    and publicip ran on the endpoint schedule, per-engine limits/sinks/full-run settings were ignored, job sizes were
    fixed, the Detailed template was fixed, the bucket cache and the classifier's 24-hour skip never survived a run, the
    secret filter refused token LIMITS, and Community containers lost every customisation file on the first update.

    This suite PINS THE PARITY MATRIX (each launcher switch -> the container mechanism that carries it; a new switch
    fails the suite until it is mapped) and proves each fix, including the negative cases: an absent env var never
    overwrites a setting, secret names are still refused, a non-customisation file never travels in the overlay.
    Offline: no Azure, no network. Runs on Windows PowerShell 5.1 and PowerShell 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerRunState.ps1')
    function script:Get-Code([string]$Rel) {
        ((Get-Content -LiteralPath (Join-Path $script:SIRoot $Rel)) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    }
    # Runs a script in a FRESH runspace, so the globals a defaults file or a config import sets never leak into this
    # session (or into another suite). Returns what the script returns.
    function script:Invoke-Isolated([string]$Script, [object[]]$ArgumentList = @()) {
        $ps = [powershell]::Create()
        try {
            $null = $ps.AddScript($Script)
            foreach ($a in $ArgumentList) { $null = $ps.AddArgument($a) }
            $out = $ps.Invoke()
            if ($ps.Streams.Error.Count) { throw ($ps.Streams.Error | ForEach-Object { "$_" }) -join '; ' }
            return $out
        } finally { $ps.Dispose() }
    }
    # The container's whole Risk Analysis settings sequence, as Start-RiskAnalysisInContainer.ps1 runs it: VM defaults ->
    # SI_CFG_* -> the job's env vars that are PRESENT. Returns the resulting values.
    $script:RaSequence = @'
param($Root, $Cfg, $Env)
. ([IO.Path]::Combine($Root, 'container', '_shared', 'SI-ContainerConfig.ps1'))
$d = Get-SIContainerEngineDefaultsPath -Engine 'risk-analysis' -Root $Root
if ($d) { . $d }
$null = Import-SIConfigFromEnv -Environment $Cfg
$o = Get-SIContainerRaEnvOverrides -Environment $Env
foreach ($k in $o.Keys) { Set-Variable -Name $k -Scope Global -Value $o[$k] }
[pscustomobject]@{ SendToLogAnalytics = $global:SendToLogAnalytics; AutoBucketMax = $global:AutoBucketMax; AutoBucketCount = $global:AutoBucketCount
                   AutoBucketCache = $global:AutoBucketCache; BuildSummaryByAI = $global:BuildSummaryByAI; SendMail = $global:SendMail
                   TableSummary = $global:SI_RiskAnalysis_TableName_Summary; TableDetailed = $global:SI_RiskAnalysis_TableName_Detailed }
'@
}

# ======================================================================================================================
#  THE PARITY MATRIX -- each VM launcher switch, and the container mechanism that carries it
# ======================================================================================================================
Describe 'the parity matrix: every VM launcher switch has a container mechanism' {
    BeforeAll {
        # Kind: 'env' = a job env var Bootstrap sets; 'setting' = the same-named setting, carried as SI_CFG_<name>;
        #       'runopt' = Resolve-SIContainerRunOptions; 'fixed' = the image decides it; 'vm-only' = no meaning on a
        #       job (console / developer tool), with the reason.
        $script:Matrix = @(
            # ---- every engine ----
            @{ Engine = '*'; Switch = 'InstallPath';        Kind = 'fixed';   Container = '/app (the image root)' }
            @{ Engine = '*'; Switch = 'LauncherConfigPath'; Kind = 'setting'; Container = 'LauncherConfig.defaults.ps1 loaded by the entry point; LauncherConfig.custom.ps1 carried as SI_CFG_* per job' }
            @{ Engine = '*'; Switch = 'WhatIfMode';         Kind = 'setting'; Container = 'SI_CFG_WhatIfMode' }
            @{ Engine = '*'; Switch = 'SuppressErrors';     Kind = 'vm-only'; Container = 'console noise only; a job keeps its whole transcript in storage' }
            @{ Engine = '*'; Switch = 'SuppressWarnings';   Kind = 'vm-only'; Container = 'console noise only; a job keeps its whole transcript in storage' }
            # ---- the four profilers ----
            @{ Engine = 'profiler'; Switch = 'Mock';               Kind = 'vm-only'; Container = 'test-only provider mock; never on a scheduled job' }
            @{ Engine = 'profiler'; Switch = 'AssetLimit';         Kind = 'runopt';  Container = 'SI_ASSET_LIMIT, else SI_AssetLimit_<Engine>' }
            @{ Engine = 'profiler'; Switch = 'Sinks';              Kind = 'runopt';  Container = 'SI_SINKS, else SI_Sinks_<Engine>' }
            @{ Engine = 'profiler'; Switch = 'ForceFullRun';       Kind = 'runopt';  Container = 'SI_FORCE_FULL_RUN, else SI_ForceFullRun_<Engine>' }
            @{ Engine = 'profiler'; Switch = 'StorageAccountName'; Kind = 'env';     Container = 'SI_STORAGE_ACCOUNT (reached with the job''s identity)' }
            # ---- trend ----
            @{ Engine = 'asset-trend'; Switch = 'DryRun';         Kind = 'setting'; Container = 'SI_CFG_SI_Trend_DryRun' }
            @{ Engine = 'asset-trend'; Switch = 'Grain';          Kind = 'setting'; Container = 'SI_CFG_SI_Trend_Grain' }
            @{ Engine = 'asset-trend'; Switch = 'Weeks';          Kind = 'setting'; Container = 'SI_CFG_SI_Trend_Weeks' }
            @{ Engine = 'asset-trend'; Switch = 'ShowWeeklyRate'; Kind = 'vm-only'; Container = 'prints the weekly rate to the console; the rate itself is computed and written on every run' }
            # ---- Risk Analysis ----
            @{ Engine = 'risk-analysis'; Switch = 'ReportTemplate';        Kind = 'env';     Container = 'SI_RA_REPORT_TEMPLATE per job (Get-SIRiskAnalysisJobPlan; RiskAnalysis_ReportTemplate_Default_*; SI_Bootstrap_RiskAnalysisJobs)' }
            @{ Engine = 'risk-analysis'; Switch = 'Summary';               Kind = 'env';     Container = 'SI_RA_MODE=Summary' }
            @{ Engine = 'risk-analysis'; Switch = 'Detailed';              Kind = 'env';     Container = 'SI_RA_MODE=Detailed' }
            @{ Engine = 'risk-analysis'; Switch = 'BuildSummaryByAI';      Kind = 'setting'; Container = 'SI_RA_BUILD_SUMMARY_BY_AI when setup decided it, else SI_CFG_BuildSummaryByAI' }
            @{ Engine = 'risk-analysis'; Switch = 'AutoBucketCount';       Kind = 'setting'; Container = 'SI_RA_AUTO_BUCKET when present, else SI_CFG_AutoBucketCount, else on' }
            @{ Engine = 'risk-analysis'; Switch = 'AutoBucketCache';       Kind = 'setting'; Container = 'SI_RA_AUTO_BUCKET_CACHE when present, else SI_CFG_AutoBucketCache; the cache itself kept in storage' }
            @{ Engine = 'risk-analysis'; Switch = 'AutoBucketMax';         Kind = 'setting'; Container = 'SI_RA_AUTO_BUCKET_MAX when present, else SI_CFG_AutoBucketMax, else 131072' }
            @{ Engine = 'risk-analysis'; Switch = 'ResetCacheSwitch';      Kind = 'setting'; Container = 'SI_CFG_ResetCache' }
            @{ Engine = 'risk-analysis'; Switch = 'ShowConfig';            Kind = 'setting'; Container = 'SI_CFG_ShowConfig' }
            @{ Engine = 'risk-analysis'; Switch = 'DebugQueryHash';        Kind = 'setting'; Container = 'SI_CFG_DebugQueryHash' }
            @{ Engine = 'risk-analysis'; Switch = 'RunAssetSimulation';    Kind = 'vm-only'; Container = 'developer load simulation; never on a scheduled job' }
            @{ Engine = 'risk-analysis'; Switch = 'AssetSimulationAmount'; Kind = 'vm-only'; Container = 'developer load simulation; never on a scheduled job' }
            # ---- asset tagging (its own job and identity, #236) ----
            @{ Engine = 'asset-tagging'; Switch = 'Apply';        Kind = 'setting'; Container = 'Invoke-SIAssetTaggingJob -Apply, passed only when the Pro setting SI_Pro_AssetTagging_Apply is on (report only otherwise)' }
            @{ Engine = 'asset-tagging'; Switch = 'Scope';        Kind = 'setting'; Container = 'SI_CFG_Scope' }
            @{ Engine = 'asset-tagging'; Switch = 'SettingsPath'; Kind = 'setting'; Container = 'the asset-tagging job reads its rules from the Pro templates (SI_ProAssetTaggingPath)' }
        )
        $script:LauncherSwitches = foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'launcher') -Recurse -Filter 'launcher.community-vm.ps1') {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($p in @($ast.ParamBlock.Parameters)) { [pscustomobject]@{ Engine = $f.Directory.Name; Switch = $p.Name.VariablePath.UserPath } }
        }
    }

    It 'every switch of every VM launcher is in the matrix (a new switch fails here until it is mapped)' {
        $profilers = 'endpoint', 'identity', 'azure', 'publicip'
        $missing = foreach ($s in $script:LauncherSwitches) {
            $hit = $script:Matrix | Where-Object { $_.Switch -eq $s.Switch -and ($_.Engine -eq '*' -or $_.Engine -eq $s.Engine -or ($_.Engine -eq 'profiler' -and $profilers -contains $s.Engine)) }
            if (-not $hit) { '{0} -{1}' -f $s.Engine, $s.Switch }
        }
        @($missing) | Should -BeNullOrEmpty
        @($script:LauncherSwitches).Count | Should -BeGreaterThan 40
    }

    It 'every VM-only row says why' {
        foreach ($r in @($script:Matrix | Where-Object { $_.Kind -eq 'vm-only' })) { $r.Container | Should -Match '\w{4,}' -Because "$($r.Switch) needs its reason" }
    }

    It 'every setting-carried switch can travel: its setting name is not refused as a secret or container-owned' {
        foreach ($n in 'WhatIfMode', 'SI_Trend_DryRun', 'SI_Trend_Grain', 'SI_Trend_Weeks', 'BuildSummaryByAI', 'AutoBucketCount', 'AutoBucketCache',
                       'AutoBucketMax', 'ResetCache', 'ShowConfig', 'DebugQueryHash', 'Scope', 'SI_AssetLimit_Endpoint', 'SI_Sinks_PublicIp', 'SI_ForceFullRun_Azure') {
            $r = Get-SIConfigEnvArgs -Names @($n) -Globals @{ $n = 1 }
            @($r.EnvArgs).Count | Should -Be 1 -Because "$n must reach a container"
        }
    }

    It 'every engine with a launcher config has its defaults loaded by the container' {
        foreach ($e in 'endpoint', 'identity', 'azure', 'publicip', 'privilege-tier-classifier', 'asset-trend', 'risk-analysis', 'risk-analysis-detailed', 'ra-weekly') {
            Get-SIContainerEngineDefaultsPath -Engine $e -Root $script:SIRoot | Should -Not -BeNullOrEmpty -Because "$e has a VM launcher config"
        }
        Get-SIContainerEngineDefaultsPath -Engine 'asset-correlation' -Root $script:SIRoot | Should -BeNullOrEmpty
    }
}

# ======================================================================================================================
#  Risk Analysis: the copy of the report rows to Log Analytics OFF by default (#830), and the customer's config is never overwritten
# ======================================================================================================================
Describe 'Risk Analysis in a container copies its report rows to Log Analytics only when told to, as a VM does' {
    It 'the default (OFF, #830 -- an optional output) holds when neither setup nor the customer says otherwise' {
        $r = Invoke-Isolated $script:RaSequence @($script:SIRoot, @{}, @{})
        $r.SendToLogAnalytics | Should -BeFalse
    }
    It 'setup writes SI_RA_SEND_TO_LOG_ANALYTICS only when it decided it' {
        $a = Get-SIRaJobEnvArgs -Template 'RiskAnalysis_Summary' -Mode 'Summary'
        @($a | Where-Object { $_ -like 'SI_RA_SEND_TO_LOG_ANALYTICS=*' }) | Should -BeNullOrEmpty
        @($a | Where-Object { $_ -like 'SI_RA_BUILD_SUMMARY_BY_AI=*' }) | Should -BeNullOrEmpty
        (Get-SIRaJobEnvArgs -Template 'T' -Mode 'Summary' -SendToLogAnalytics $true) | Should -Contain 'SI_RA_SEND_TO_LOG_ANALYTICS=1'
        (Get-SIRaJobEnvArgs -Template 'T' -Mode 'Summary' -SendToLogAnalytics $false) | Should -Contain 'SI_RA_SEND_TO_LOG_ANALYTICS=0'
    }
    It 'appended the way Bootstrap does, every RA variable is its OWN argument (live 2026-10-04: they arrived as one)' {
        $envArgs = @('SI_ENGINE=risk-analysis')
        $envArgs += @(Get-SIRaJobEnvArgs -Template 'RiskAnalysis_Detailed' -Mode 'Detailed' -ExportDestination 'https://st.blob.core.windows.net/sistaging/risk-analysis/')
        $envArgs.Count | Should -Be 5
        foreach ($e in $envArgs) { $e | Should -BeOfType [string]; $e | Should -Not -Match '\s' }
        $envArgs | Should -Contain 'DOTNET_GCgen0size=10000000' -Because '#873 E: every Risk Analysis job gets the 256 MB gen0 budget'
        $envArgs | Should -Contain 'SI_RA_REPORT_TEMPLATE=RiskAnalysis_Detailed'
        $envArgs | Should -Contain 'SI_RA_MODE=Detailed'
    }
    It 'the customer''s own "off" is honoured when setup did not decide' {
        $r = Invoke-Isolated $script:RaSequence @($script:SIRoot, @{ SI_CFG_SendToLogAnalytics = 'false' }, @{})
        $r.SendToLogAnalytics | Should -BeFalse
    }
    It 'WIRING -- Bootstrap no longer writes the switch as 0 on every job' {
        $c = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        $c | Should -Not -Match "SI_RA_SEND_TO_LOG_ANALYTICS=\{0\}' -f \(\[int\]\[bool\]\`$RiskAnalysisSendToLogAnalytics\)"
        $c | Should -Match "\`$raSendToLaForJobs = if \(\`$cliBound\.ContainsKey\('RiskAnalysisSendToLogAnalytics'\) -or \`$null -ne \`$global:SI_RiskAnalysis_SendToLogAnalytics\)"
        $c | Should -Match 'Get-SIRaJobEnvArgs -Template \$raTemplateForJob -Mode \$raModeForJob -SendToLogAnalytics \$raSendToLaForJobs'
    }
}

Describe 'the job''s Risk Analysis env vars win only when present -- precedence env > customer setting > VM default' {
    It 'NEGATIVE -- no env var: nothing is overridden (an absent env var never overwrites the config)' {
        $o = Get-SIContainerRaEnvOverrides -Environment @{}
        @($o.Keys).Count | Should -Be 0
        $o = Get-SIContainerRaEnvOverrides -Environment @{ SI_RA_AUTO_BUCKET_MAX = '  '; SI_RA_SEND_MAIL = '' }
        @($o.Keys).Count | Should -Be 0
    }
    It 'with nothing set anywhere, the VM launcher''s defaults apply (cap 131072, bucketing + cache on, mail and AI off)' {
        $r = Invoke-Isolated $script:RaSequence @($script:SIRoot, @{}, @{})
        $r.AutoBucketMax | Should -Be 131072
        $r.AutoBucketCount | Should -BeTrue
        $r.AutoBucketCache | Should -BeTrue
        $r.SendMail | Should -BeFalse
        $r.BuildSummaryByAI | Should -BeFalse
        $r.TableSummary | Should -BeExactly 'SI_RiskAnalysis_Summary'
        $r.TableDetailed | Should -BeExactly 'SI_RiskAnalysis_Detailed'
    }
    It 'the customer''s config wins over the VM default' {
        $r = Invoke-Isolated $script:RaSequence @($script:SIRoot, @{ SI_CFG_AutoBucketMax = '2048'; SI_CFG_SendMail = 'true'; SI_CFG_BuildSummaryByAI = 'true'
                                                                     SI_CFG_SI_RiskAnalysis_TableName_Summary = 'SI_RA_Custom' }, @{})
        $r.AutoBucketMax | Should -Be 2048
        $r.SendMail | Should -BeTrue
        $r.BuildSummaryByAI | Should -BeTrue
        $r.TableSummary | Should -BeExactly 'SI_RA_Custom'
    }
    It 'a PRESENT job env var wins over the customer''s config' {
        $r = Invoke-Isolated $script:RaSequence @($script:SIRoot, @{ SI_CFG_AutoBucketMax = '2048'; SI_CFG_SendToLogAnalytics = 'false' },
                                                  @{ SI_RA_AUTO_BUCKET_MAX = '4096'; SI_RA_SEND_TO_LOG_ANALYTICS = '1'; SI_RA_TABLE_DETAILED = 'X_Detailed' })
        $r.AutoBucketMax | Should -Be 4096
        $r.SendToLogAnalytics | Should -BeTrue
        $r.TableDetailed | Should -BeExactly 'X_Detailed'
    }
    It 'a malformed bucket cap in the env is ignored, never turned into 0' {
        (Get-SIContainerRaEnvOverrides -Environment @{ SI_RA_AUTO_BUCKET_MAX = 'lots' }).Contains('AutoBucketMax') | Should -BeFalse
    }
    It 'WIRING -- the entry point loads the VM defaults, THEN the customer''s settings, THEN only the present env vars; the old 1024 fallback is gone' {
        $c = Get-Code 'container\Start-RiskAnalysisInContainer.ps1'
        $c | Should -Not -Match "SI_RA_AUTO_BUCKET_MAX' '1024'"
        $c | Should -Not -Match "Get-OptionalEnv 'SI_RA_SEND_TO_LOG_ANALYTICS' '0'"
        $c | Should -Not -Match "Get-OptionalEnv 'SI_RA_SEND_MAIL' '0'"
        $defaults = $c.IndexOf("Get-SIContainerEngineDefaultsPath -Engine 'risk-analysis'")
        $cfg = $c.IndexOf('Import-SIConfigFromEnv')
        $env = $c.IndexOf('Get-SIContainerRaEnvOverrides')
        $run = $c.IndexOf('& $engineScript')
        $defaults | Should -BeGreaterThan 0
        $defaults | Should -BeLessThan $cfg
        $cfg | Should -BeLessThan $env
        $env | Should -BeLessThan $run
    }
    It 'an AI summary switched on only in the config, without Azure OpenAI on the job, runs without it instead of failing' {
        $c = Get-Code 'container\Start-RiskAnalysisInContainer.ps1'
        $c | Should -Match "(?s)if \(\`$raEnv\.Contains\('BuildSummaryByAI'\)\) \{.{0,200}Get-RequiredEnv 'OPENAI_APIKEY'"
        $c | Should -Match '(?s)Resolve-SIContainerAi -OpenAi \$aiParts -Requested \$true.{0,600}\$global:BuildSummaryByAI = \$false'
    }
}

# ======================================================================================================================
#  The per-engine launcher configs reach a container
# ======================================================================================================================
Describe 'the engine launcher configs (defaults and custom) reach the container' {
    It 'the shipped defaults files carry no tenant value, no secret read and nothing the container owns' {
        foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'launcher') -Recurse -Filter 'LauncherConfig.defaults.ps1') {
            $code = ((Get-Content -LiteralPath $f.FullName) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            $code | Should -Not -Match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' -Because "$($f.Directory.Name): no tenant / app id"
            $code | Should -Not -Match '(?i)Get-SIKvSecret|Get-AzKeyVaultSecret|Get-PlatformSecret|https?://' -Because "$($f.Directory.Name): no secret read, no endpoint"
            # A container-owned name may at most get a fallback when NOTHING set it (the OpenAI API version); it is never
            # assigned outright, so the job's own value always stands.
            foreach ($n in $script:SIConfigProtected) {
                foreach ($line in @($code -split "`n" | Where-Object { $_ -match ('\$global:{0}\s*=[^=]' -f [regex]::Escape($n)) })) {
                    $line | Should -Match ('^\s*if \(-not \$global:{0}\)' -f [regex]::Escape($n)) -Because "$($f.Directory.Name) must not overwrite the container-owned $n"
                }
            }
        }
    }
    It 'the publicip defaults give the right table casing in a container' {
        $r = Invoke-Isolated @'
param($Root)
. ([IO.Path]::Combine($Root, 'container', '_shared', 'SI-ContainerConfig.ps1'))
. (Get-SIContainerEngineDefaultsPath -Engine 'publicip' -Root $Root)
$global:SI_PublicIp_TableName
'@ @($script:SIRoot)
        "$r" | Should -BeExactly 'SI_PublicIP_Profile'
    }
    It 'WIRING -- the collection entry point loads the engine''s defaults BEFORE the customer''s settings' {
        $c = Get-Code 'container\Start-SIInContainer.ps1'
        $d = $c.IndexOf('Get-SIContainerEngineDefaultsPath -Engine $engine')
        $d | Should -BeGreaterThan 0
        $d | Should -BeLessThan $c.IndexOf('Import-SIConfigFromEnv')
        # ...and storage has no mode a defaults file could flip: the job's identity is the only way in (#307).
        $c | Should -Not -Match 'UseStorageOAuth'
    }
    It 'a LauncherConfig.custom.ps1 is read in isolation: its settings come back, the caller''s globals are untouched' {
        $f = Join-Path $TestDrive 'LauncherConfig.custom.ps1'
        Set-Content -LiteralPath $f -Value "`$global:SI_Sinks_Endpoint = @('LA')`n`$global:SI_ParityProbe = 7`n`$global:SI_SPN_Secret = 'nope'`n`$global:SI_Bootstrap_Cpu_Endpoint = '2'`n`$local = 1"
        Remove-Variable -Name SI_ParityProbe -Scope Global -ErrorAction SilentlyContinue
        $r = Read-SILauncherCustomSettings -Path $f
        @($r.Errors) | Should -BeNullOrEmpty
        @($r.Settings['SI_Sinks_Endpoint']) | Should -Be @('LA')
        $r.Settings['SI_ParityProbe'] | Should -Be 7
        $r.Settings.ContainsKey('SI_Bootstrap_Cpu_Endpoint') | Should -BeFalse -Because 'setup knobs are not job settings'
        $r.Settings.ContainsKey('local') | Should -BeFalse
        (Get-Variable -Name SI_ParityProbe -Scope Global -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
        # NEGATIVE: the secret it sets is refused on the way to the job
        $pass = Get-SIConfigEnvArgs -Names @($r.Settings.Keys) -Globals $r.Settings
        @($pass.Refused) | Should -Contain 'SI_SPN_Secret'
        @($pass.EnvArgs | Where-Object { $_ -like 'SI_CFG_SI_SPN_Secret=*' }) | Should -BeNullOrEmpty
    }
    It 'a failing custom file returns what it set before the failure, with the error' {
        $f = Join-Path $TestDrive 'Broken.custom.ps1'
        Set-Content -LiteralPath $f -Value "`$global:SI_First = 'a'`nthrow 'boom'`n`$global:SI_Second = 'b'"
        $r = Read-SILauncherCustomSettings -Path $f
        $r.Settings['SI_First'] | Should -Be 'a'
        $r.Settings.ContainsKey('SI_Second') | Should -BeFalse
        (@($r.Errors) -join ' ') | Should -Match 'boom'
    }
    It 'the engine''s own value wins over the config''s, one entry per name' {
        $m = Merge-SIConfigEnvArgs -Base @('SI_CFG_A=1', 'SI_CFG_B=2') -Override @('SI_CFG_B=3', 'SI_CFG_C=4')
        @($m) | Should -Be @('SI_CFG_A=1', 'SI_CFG_B=3', 'SI_CFG_C=4')
        @(Merge-SIConfigEnvArgs -Base @('SI_CFG_A=1') -Override @()) | Should -Be @('SI_CFG_A=1')
    }
    It 'every Risk Analysis job shares the risk-analysis launcher folder; engines without one have none' {
        Get-SIContainerEngineLauncherFolder -Engine 'risk-analysis-detailed' | Should -Be 'risk-analysis'
        Get-SIContainerEngineLauncherFolder -Engine 'ra-weekly' | Should -Be 'risk-analysis'
        Get-SIContainerEngineLauncherFolder -Engine 'privilege-tier-classifier' | Should -Be 'privilege-tier-classifier'
        Get-SIContainerEngineLauncherFolder -Engine 'asset-cmdb' | Should -BeNullOrEmpty
    }
    It 'WIRING -- Bootstrap reads each engine''s LauncherConfig.custom.ps1 and merges it into that engine''s jobs only' {
        $c = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        $c | Should -Match "launcher\\\{0\}\\LauncherConfig\.custom\.ps1' -f \`$folder"
        $c | Should -Match 'Read-SILauncherCustomSettings -Path \$lcPath'
        $c | Should -Match 'Merge-SIConfigEnvArgs -Base \$cfgEnvArgs -Override'
        $c | Should -Not -Match '\) \+ \$cfgEnvArgs'
        # 2026-10-04 (r1-pro-ca): @( ) around the call wrapped an EMPTY result into one '' element and az refused the job.
        $c | Should -Not -Match '@\(Merge-SIConfigEnvArgs'
    }
    It 'an empty merged config adds NO element to the job''s env list (a Pro install keeps its settings in SQL)' {
        $env1 = @('SI_ENGINE=endpoint')
        $cfgMerged = Merge-SIConfigEnvArgs -Base @() -Override @()
        $env1 += @($cfgMerged | Where-Object { $_ })
        $env1.Count | Should -Be 1
        @($env1 | Where-Object { [string]::IsNullOrEmpty([string]$_) }).Count | Should -Be 0
    }
    It 'publicip publishes to SI_PublicIP_Profile even without the launcher default (robust casing)' {
        $c = Get-Code 'engine\asset-profiling\stages\Invoke-Output.ps1'
        $c | Should -Match "if \(\`$RunContext\.Engine -ieq 'publicip'\) \{ \`$engineCap = 'PublicIP' \}"
        $i = $c.IndexOf("`$engineCap = 'PublicIP'"); $i | Should -BeLessThan $c.IndexOf('$tableName = $tablePattern -f $engineCap')
        ('SI_{0}_Profile' -f 'PublicIP') | Should -BeExactly 'SI_PublicIP_Profile'
    }
}

# ======================================================================================================================
#  Schedules: the classifier before the profilers, publicip after them -- and no classifier without Azure OpenAI
# ======================================================================================================================
Describe 'the classifier and publicip have their own schedules' {
    BeforeAll {
        $c = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        $script:BootCode = $c
        $script:Min = { param($n) $m = [regex]::Match($c, "\`$$n\s*=\s*'(\d+) (\d+)"); [int]$m.Groups[2].Value * 60 + [int]$m.Groups[1].Value }
    }
    It 'the classifier runs before every profiler; publicip after endpoint and azure and before Risk Analysis' {
        $ptc = & $script:Min 'ScheduleClassifier'; $pip = & $script:Min 'SchedulePublicIp'
        foreach ($p in 'ScheduleEndpoint', 'ScheduleIdentity', 'ScheduleAzure') { $ptc | Should -BeLessThan (& $script:Min $p) -Because "the catalog must exist before $p" }
        $pip | Should -BeGreaterThan (& $script:Min 'ScheduleEndpoint')
        $pip | Should -BeGreaterThan (& $script:Min 'ScheduleAzure')
        $pip | Should -BeLessThan (& $script:Min 'ScheduleRiskAnalysis')
    }
    It 'each job picks its own schedule (not the endpoint fallback); both are settable in the config' {
        $script:BootCode | Should -Match "'privilege-tier-classifier' \{ \`$ScheduleClassifier \}"
        $script:BootCode | Should -Match "'publicip'\s+\{ \`$SchedulePublicIp \}"
        $script:BootCode | Should -Match "-ParamName 'ScheduleClassifier'\s+-GlobalName 'SI_Bootstrap_ScheduleClassifier'"
        $script:BootCode | Should -Match "-ParamName 'SchedulePublicIp'\s+-GlobalName 'SI_Bootstrap_SchedulePublicIp'"
    }
    It 'the guided install shifts both with the start hour, keeping the order' {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')
        $s4 = Get-SIInstallSchedules -RunHourUtc 4
        $s4.ScheduleClassifier | Should -Be '0 1 * * *'
        $s4.SchedulePublicIp | Should -Be '15 5 * * *'
        $s20 = Get-SIInstallSchedules -RunHourUtc 20
        $s20.ScheduleClassifier | Should -Be '0 17 * * *'
        $s20.SchedulePublicIp | Should -Be '15 21 * * *'
    }
    It 'without Azure OpenAI the classifier job is not deployed, and setup says why in one line' {
        $r = Select-SIBootstrapEngines -Engines @('endpoint', 'privilege-tier-classifier', 'risk-analysis') -HaveOpenAi $false
        @($r.Engines) | Should -Be @('endpoint', 'risk-analysis')
        $r.Note | Should -Match 'Tier 99'
        ($r.Note -split "`n").Count | Should -Be 1
    }
    It 'NEGATIVE -- with Azure OpenAI, or without a classifier in the list, nothing changes' {
        $r = Select-SIBootstrapEngines -Engines @('endpoint', 'privilege-tier-classifier') -HaveOpenAi $true
        @($r.Engines) | Should -Be @('endpoint', 'privilege-tier-classifier'); $r.Note | Should -BeNullOrEmpty
        $r = Select-SIBootstrapEngines -Engines @('endpoint') -HaveOpenAi $false
        @($r.Engines) | Should -Be @('endpoint'); $r.Note | Should -BeNullOrEmpty
    }
    It 'WIRING -- Bootstrap applies the selection after it knows whether Azure OpenAI is configured' {
        $i = $script:BootCode.IndexOf('Select-SIBootstrapEngines -Engines $Engines -HaveOpenAi ([bool]$haveOpenAiSettings)')
        $i | Should -BeGreaterThan $script:BootCode.IndexOf('$haveOpenAiSettings = ')
        $i | Should -BeLessThan $script:BootCode.IndexOf('foreach ($engine in $Engines)')
    }
}

# ======================================================================================================================
#  Per-engine asset limit / sinks / full run
# ======================================================================================================================
Describe 'the per-engine AssetLimit, Sinks and ForceFullRun settings reach a profiler job' {
    It 'the VM settings apply when the job sets no env var' {
        $r = Resolve-SIContainerRunOptions -Engine 'endpoint' -Environment @{} -Globals @{ SI_AssetLimit_Endpoint = 250; SI_Sinks_Endpoint = @('LA', 'Excel'); SI_ForceFullRun_Endpoint = $true }
        $r.AssetLimit | Should -Be 250
        @($r.Sinks) | Should -Be @('LA', 'Excel')
        $r.ForceFullRun | Should -BeTrue
        $r.Source.Sinks | Should -Be 'SI_Sinks_Endpoint'
    }
    It 'publicip reads SI_*_PublicIp, as its VM launcher does' {
        $r = Resolve-SIContainerRunOptions -Engine 'publicip' -Environment @{} -Globals @{ SI_Sinks_PublicIp = @('LA') }
        @($r.Sinks) | Should -Be @('LA')
    }
    It 'a PRESENT job env var wins' {
        $r = Resolve-SIContainerRunOptions -Engine 'identity' -Environment @{ SI_ASSET_LIMIT = '10'; SI_SINKS = 'JSON'; SI_FORCE_FULL_RUN = '0' } `
            -Globals @{ SI_AssetLimit_Identity = 250; SI_Sinks_Identity = @('LA'); SI_ForceFullRun_Identity = $true }
        $r.AssetLimit | Should -Be 10
        @($r.Sinks) | Should -Be @('JSON')
        $r.ForceFullRun | Should -BeFalse
    }
    It 'NEGATIVE -- nothing set: the VM defaults (all assets, JSON + Excel + LA, incremental); another engine''s setting is ignored' {
        $r = Resolve-SIContainerRunOptions -Engine 'azure' -Environment @{} -Globals @{ SI_AssetLimit_Endpoint = 5; SI_Sinks_Endpoint = @('LA') }
        $r.AssetLimit | Should -Be 0
        @($r.Sinks) | Should -Be @('JSON', 'Excel', 'LA')
        $r.ForceFullRun | Should -BeFalse
        $r.Source.AssetLimit | Should -Be 'default'
    }
    It 'WIRING -- the orchestrator gets the resolved options, resolved AFTER the Pro settings layer' {
        $c = Get-Code 'container\Start-SIInContainer.ps1'
        $c | Should -Match 'Sinks\s+= \$runOpts\.Sinks'
        $c | Should -Match 'AssetLimit\s+= \$runOpts\.AssetLimit'
        $c.IndexOf('Resolve-SIContainerRunOptions') | Should -BeGreaterThan $c.IndexOf('Invoke-SIProSettingsLayer')
        $c | Should -Not -Match "Get-OptionalEnv 'SI_SINKS' 'JSON,Excel,LA'"
    }
}

# ======================================================================================================================
#  Job sizes
# ======================================================================================================================
Describe 'replica timeout, CPU and memory are settings per engine' {
    It 'the defaults are the floor every SI job gets: 2 CPU / 4 GiB (owner 2026-10-10, "money must not be the case") and the longest run limit Azure takes, 7 days (owner 2026-10-13: SecurityInsight chooses none)' {
        $k = Get-SIContainerJobResources -Engine 'endpoint' -Kind Keda
        "$($k.ReplicaTimeout)/$($k.Cpu)/$($k.Memory)" | Should -Be '604800/2.0/4.0Gi'
        $r = Get-SIContainerJobResources -Engine 'risk-analysis' -Kind RiskAnalysis
        "$($r.ReplicaTimeout)/$($r.Cpu)/$($r.Memory)" | Should -Be '604800/2.0/4.0Gi'
        $m = Get-SIContainerJobResources -Engine 'templates-publish' -Kind Manual
        "$($m.ReplicaTimeout)/$($m.Cpu)/$($m.Memory)" | Should -Be '604800/2.0/4.0Gi'
        $s = Get-SIContainerJobResources -Engine 'identity' -Kind Schedule
        "$($s.ReplicaTimeout)/$($s.Cpu)/$($s.Memory)" | Should -Be '604800/2.0/4.0Gi'
        Get-SIJobRunLimit | Should -Be 604800
    }
    It 'SI_Bootstrap_ReplicaTimeout_ / _Cpu_ / _Memory_<Engine> override them' {
        $g = @{ SI_Bootstrap_ReplicaTimeout_RiskAnalysisDetailed = 14400; SI_Bootstrap_Cpu_RiskAnalysisDetailed = '4'; SI_Bootstrap_Memory_RiskAnalysisDetailed = '8Gi' }
        $r = Get-SIContainerJobResources -Engine 'risk-analysis-detailed' -Kind RiskAnalysis -Globals $g
        "$($r.ReplicaTimeout)/$($r.Cpu)/$($r.Memory)" | Should -Be '14400/4.0/8.0Gi'
        @($r.Notes) | Should -BeNullOrEmpty
        # another engine is not affected
        (Get-SIContainerJobResources -Engine 'risk-analysis' -Kind RiskAnalysis -Globals $g).Cpu | Should -Be '2.0'
    }
    It 'NEGATIVE -- an invalid value keeps the default and says so; setup does not fail' {
        $r = Get-SIContainerJobResources -Engine 'endpoint' -Kind Schedule -Globals @{ SI_Bootstrap_ReplicaTimeout_Endpoint = 'soon'; SI_Bootstrap_Cpu_Endpoint = '3.3'; SI_Bootstrap_Memory_Endpoint = '64Gi' }
        "$($r.ReplicaTimeout)/$($r.Cpu)/$($r.Memory)" | Should -Be '604800/2.0/4.0Gi'   # the defaults
        @($r.Notes).Count | Should -Be 3
    }
    It 'the customer''s own run limit may be shorter than the 7 days every job gets, never longer; above that it is refused with a note' {
        (Get-SIContainerJobResources -Engine 'asset-correlation' -Kind Schedule -Globals @{ SI_Bootstrap_ReplicaTimeout_AssetCorrelation = '300000' }).ReplicaTimeout | Should -Be 300000
        (Get-SIContainerJobResources -Engine 'asset-correlation' -Kind Schedule -Globals @{ SI_Bootstrap_ReplicaTimeout_AssetCorrelation = 604800 }).ReplicaTimeout | Should -Be 604800
        $r = Get-SIContainerJobResources -Engine 'asset-correlation' -Kind Schedule -Globals @{ SI_Bootstrap_ReplicaTimeout_AssetCorrelation = '604801' }
        $r.ReplicaTimeout | Should -Be 604800
        @($r.Notes)[0] | Should -Match 'between 300 and 604800 \(7 days\)'
    }
    It 'a KEDA worker''s queue lease outlives its replica and never passes 7 days (a storage queue refuses a longer lease)' {
        @(Get-SIKedaQueueLeaseEnvArgs -ReplicaTimeout 259200) | Should -Be @('SI_QUEUE_LEASE_SECONDS=259500')
        @(Get-SIKedaQueueLeaseEnvArgs -ReplicaTimeout 604800) | Should -Be @('SI_QUEUE_LEASE_SECONDS=604800')
        (Get-Code 'container\Start-SIInContainer.ps1') | Should -Match ([regex]::Escape('if ($leaseSeconds -gt 604800) { $leaseSeconds = 604800 }'))
    }
    It 'running setup again on an EXISTING job never lowers its run limit or its size; a value the customer set still wins, also downwards' {
        $job = [pscustomobject]@{ name = 'caj-si-asset-correlation'; properties = [pscustomobject]@{ configuration = [pscustomobject]@{ replicaTimeout = 43200 }
            template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'si'; resources = [pscustomobject]@{ cpu = 4.0; memory = '8Gi' } }) } } }
        $want = Get-SIContainerJobResources -Engine 'asset-correlation' -Kind Schedule
        "$($want.ReplicaTimeout)/$($want.Cpu)/$($want.Memory)" | Should -Be '604800/2.0/4.0Gi'
        # the job's run limit (12 h) is shorter than setup's: setup's is written; its larger size is kept
        $r = Get-SIJobResourcesNeverLower -Resources $want -ExistingJob $job -Engine 'asset-correlation'
        "$($r.ReplicaTimeout)/$($r.Cpu)/$($r.Memory)" | Should -Be '604800/4.0/8Gi' -Because 'the run limit goes up to what every job gets; the job keeps the size it was raised to'
        @($r.Notes).Count | Should -Be 1
        # a run limit the job has that is longer than what setup would write (a shorter one of the customer's, since removed) is kept
        $short = [pscustomobject]@{ ReplicaTimeout = 7200; Cpu = '2.0'; Memory = '4.0Gi'; Notes = @() }
        $kept = Get-SIJobResourcesNeverLower -Resources $short -ExistingJob $job -Engine 'asset-correlation'
        "$($kept.ReplicaTimeout)/$($kept.Cpu)/$($kept.Memory)" | Should -Be '43200/4.0/8Gi'; @($kept.Notes).Count | Should -Be 2
        # a new job (none exists) gets setup's values
        (Get-SIJobResourcesNeverLower -Resources $want -ExistingJob $null -Engine 'asset-correlation').ReplicaTimeout | Should -Be 604800
        # the customer's own setting wins, also downwards -- each value on its own
        $g = @{ SI_Bootstrap_ReplicaTimeout_AssetCorrelation = '3600' }
        $own = Get-SIJobResourcesNeverLower -Resources (Get-SIContainerJobResources -Engine 'asset-correlation' -Kind Schedule -Globals $g) -ExistingJob $job -Engine 'asset-correlation' -Globals $g
        "$($own.ReplicaTimeout)/$($own.Cpu)/$($own.Memory)" | Should -Be '3600/4.0/8Gi'
        $g2 = @{ SI_Bootstrap_Memory_AssetCorrelation = '4Gi'; SI_Bootstrap_Cpu_AssetCorrelation = '2' }
        $own2 = Get-SIJobResourcesNeverLower -Resources (Get-SIContainerJobResources -Engine 'asset-correlation' -Kind Schedule -Globals $g2) -ExistingJob $job -Engine 'asset-correlation' -Globals $g2
        "$($own2.ReplicaTimeout)/$($own2.Cpu)/$($own2.Memory)" | Should -Be '604800/2.0/4.0Gi'
        (Get-Code 'Bootstrap-ContainerAppJob.ps1') | Should -Match ([regex]::Escape('$jobRes = Get-SIJobResourcesNeverLower -Resources $jobRes -ExistingJob $existing -Engine $engine -Globals $bootGlobals'))
    }
    It 'the pipeline job itself gets 7 days: it waits for every step, so it never ends before a step does' {
        Get-SIFlowJobReplicaTimeout | Should -Be 604800
        (Get-Code 'Bootstrap-ContainerAppJob.ps1') | Should -Match ([regex]::Escape('$jobRes.ReplicaTimeout = Get-SIFlowJobReplicaTimeout'))
    }
    It 'WIRING -- no job size is hard-coded in Bootstrap any more, and an update applies the size too' {
        $c = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        $jobs = [regex]::Match($c, "(?s)\`$createArgs = if \(\`$effectiveUseKEDA\) \{.*?\`$createArgs \+= \`$engRegistry").Value
        $jobs | Should -Not -BeNullOrEmpty
        $jobs | Should -Not -Match "'--cpu','[0-9.]+'"
        $jobs | Should -Not -Match "'--memory','[0-9.]+Gi'"
        $jobs | Should -Not -Match "'--replica-timeout','\d+'"
        $c | Should -Match ([regex]::Escape('ReplicaTimeout = [int]$jobRes.ReplicaTimeout; Cpu = [string]$jobRes.Cpu; Memory = [string]$jobRes.Memory'))
    }
}

# ======================================================================================================================
#  Risk Analysis jobs: the default Detailed template, and extra report jobs
# ======================================================================================================================
Describe 'Risk Analysis jobs follow the customer''s templates, and extra report jobs can be added' {
    It 'by default: Summary and Detailed with the shipped templates' {
        $p = Get-SIRiskAnalysisJobPlan -Engines @('risk-analysis', 'risk-analysis-detailed')
        ($p.Jobs | ForEach-Object { '{0}|{1}|{2}' -f $_.Engine, $_.Mode, $_.Template }) | Should -Be @('risk-analysis|Summary|RiskAnalysis_Summary', 'risk-analysis-detailed|Detailed|RiskAnalysis_Detailed')
    }
    It 'RiskAnalysis_ReportTemplate_Default_Detailed / _Summary are honoured, as on a VM' {
        $p = Get-SIRiskAnalysisJobPlan -Engines @('risk-analysis', 'risk-analysis-detailed') -Globals @{
            RiskAnalysis_ReportTemplate_Default_Detailed = 'RiskAnalysis_Detailed_IdentityOnly'; RiskAnalysis_ReportTemplate_Default_Summary = 'RiskAnalysis_Summary_Lean' }
        ($p.Jobs | Where-Object Engine -eq 'risk-analysis-detailed').Template | Should -Be 'RiskAnalysis_Detailed_IdentityOnly'
        ($p.Jobs | Where-Object Engine -eq 'risk-analysis').Template | Should -Be 'RiskAnalysis_Summary_Lean'
        # the legacy short names too
        (Get-SIRiskAnalysisJobPlan -Engines @('risk-analysis-detailed') -Globals @{ ReportTemplate_Default_Detailed = 'Legacy_Detailed' }).Jobs[0].Template | Should -Be 'Legacy_Detailed'
    }
    It 'an explicit Summary template (-RiskAnalysisReportTemplate / SI_RiskAnalysis_ReportTemplate) still wins' {
        $p = Get-SIRiskAnalysisJobPlan -Engines @('risk-analysis') -SummaryTemplate 'MySummary' -Globals @{ RiskAnalysis_ReportTemplate_Default_Summary = 'Other_Summary' }
        $p.Jobs[0].Template | Should -Be 'MySummary'
    }
    It 'extra report jobs: name, mode, template and schedule; the job name fits Container Apps'' 32 characters' {
        $g = @{ SI_Bootstrap_RiskAnalysisJobs = @(
                    @{ Name = 'identity-weekly'; Template = 'RiskAnalysis_Detailed_IdentityOnly'; Cron = '0 12 * * 0' },
                    @{ Name = 'exec'; Mode = 'Summary'; Template = 'Board_Report'; Cron = '0 7 1 * *' },
                    [pscustomobject]@{ Name = 'abcdefghijklmnopqrstuv'; Mode = 'Detailed'; Schedule = '0 9 * * *' }) }
        $p = Get-SIRiskAnalysisJobPlan -Engines @() -Globals $g
        @($p.Refused) | Should -BeNullOrEmpty
        ($p.Jobs | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Engine, $_.Mode, $_.Template, $_.Cron }) | Should -Be @(
            'ra-identity-weekly|Detailed|RiskAnalysis_Detailed_IdentityOnly|0 12 * * 0', 'ra-exec|Summary|Board_Report|0 7 1 * *',
            'ra-abcdefghijklmnopqrstuv|Detailed|RiskAnalysis_Detailed|0 9 * * *')
        foreach ($j in $p.Jobs) { ('caj-si-{0}' -f $j.JobShort).Length | Should -BeLessOrEqual 32 }
    }
    It 'NEGATIVE -- an extra job that is not valid is refused with the reason, never deployed half-right' {
        $g = @{ SI_Bootstrap_RiskAnalysisJobs = @(
                    @{ Name = 'Bad Name'; Mode = 'Summary'; Cron = '0 1 * * *' },
                    @{ Name = 'nocron'; Mode = 'Summary' },
                    @{ Name = 'clash'; Mode = 'Summary'; Template = 'RiskAnalysis_Detailed'; Cron = '0 1 * * *' },
                    @{ Name = 'nomode'; Template = 'Board_Report'; Cron = '0 1 * * *' },
                    @{ Name = 'dup'; Mode = 'Summary'; Cron = '0 1 * * *' }, @{ Name = 'dup'; Mode = 'Summary'; Cron = '0 2 * * *' },
                    @{ Name = 'abcdefghijklmnopqrstuvw'; Mode = 'Summary'; Cron = '0 1 * * *' }) }
        $p = Get-SIRiskAnalysisJobPlan -Engines @() -Globals $g
        @($p.Jobs).Count | Should -Be 1
        $p.Jobs[0].Engine | Should -Be 'ra-dup'
        @($p.Refused).Count | Should -Be 6
    }
    It 'WIRING -- Bootstrap takes mode, template and schedule from the plan; the Detailed template is no longer fixed' {
        $c = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        $c | Should -Match 'Get-SIRiskAnalysisJobPlan -Engines \$Engines -Globals \$bootGlobals'
        $c | Should -Match '\$raTemplateForJob = if \(\$raJob\) \{ \$raJob\.Template \}'
        $c | Should -Match "default\s+\{ if \(\`$raJob\) \{ \`$raJob\.Cron \} else \{ \`$ScheduleEndpoint \} \}"
        $c | Should -Match '\$isRiskAnalysis\s+= \$raJobs\.ContainsKey\(\$engine\)'
    }
}

# ======================================================================================================================
#  The bucket cache survives the run
# ======================================================================================================================
Describe 'the Risk Analysis bucket cache is kept in storage between container runs' {
    BeforeEach {
        Mock New-SIAzStorageContext { [pscustomobject]@{ StorageAccountName = $StorageAccountName } }
    }
    It 'one blob per template, and the local path is the engine''s own' {
        Get-SIRaAutoBucketCacheBlobName -Template 'RiskAnalysis_Summary' | Should -Be 'risk-analysis/AutoBucketCache.RiskAnalysis_Summary.json'
        Get-SIRaAutoBucketCacheBlobName -Template 'a b/c' | Should -Be 'risk-analysis/AutoBucketCache.a_b_c.json'
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')
        Get-SIRaAutoBucketCacheLocalPath -SettingsPath $TestDrive | Should -Be (Get-AutoBucketCachePath -SettingsPath $TestDrive)
    }
    It 'saved after the run, loaded before the next (validated JSON swapped in)' {
        $local = Join-Path $TestDrive 'OUTPUT\AutoBucketCache.json'
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $local) | Out-Null
        '{"q1":8}' | Set-Content -LiteralPath $local
        Mock Get-SIAzStorageContainer { $true }
        Mock Set-SIAzStorageBlobContent { $script:SavedBlob = $Blob; $script:SavedFrom = $File }
        Save-SIRaAutoBucketCache -AccountName 'acct' -LocalPath $local -Template 'RiskAnalysis_Detailed' | Should -BeTrue
        $script:SavedBlob | Should -Be 'risk-analysis/AutoBucketCache.RiskAnalysis_Detailed.json'
        Remove-Item -LiteralPath $local
        Mock Get-SIAzStorageBlob { [pscustomobject]@{ Name = $Blob } }
        Mock Get-SIAzStorageBlobContent { '{"q1":16}' | Set-Content -LiteralPath $Destination }
        Restore-SIRaAutoBucketCache -AccountName 'acct' -LocalPath $local -Template 'RiskAnalysis_Detailed' | Should -Be 'storage'
        (Get-Content -LiteralPath $local -Raw | ConvertFrom-Json).q1 | Should -Be 16
    }
    It 'NEGATIVE -- nothing stored yet, or storage failing: a warning at most, never a failed run' {
        $local = Join-Path $TestDrive 'x\OUTPUT\AutoBucketCache.json'
        Mock Get-SIAzStorageBlob { throw 'BlobNotFound' }
        Restore-SIRaAutoBucketCache -AccountName 'acct' -LocalPath $local -Template 'T' | Should -Be 'none'
        Mock New-SIAzStorageContext { throw 'no identity' }
        { Restore-SIRaAutoBucketCache -AccountName 'acct' -LocalPath $local -Template 'T' -WarningAction SilentlyContinue } | Should -Not -Throw
        Restore-SIRaAutoBucketCache -AccountName 'acct' -LocalPath $local -Template 'T' -WarningAction SilentlyContinue | Should -Be 'none'
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $local) | Out-Null; '{}' | Set-Content -LiteralPath $local
        Save-SIRaAutoBucketCache -AccountName 'acct' -LocalPath $local -Template 'T' -WarningAction SilentlyContinue | Should -BeFalse
        Restore-SIRaAutoBucketCache -AccountName '' -LocalPath $local -Template 'T' | Should -Be 'none'
    }
    It 'WIRING -- loaded before the engine runs, saved after it' {
        $c = Get-Code 'container\Start-RiskAnalysisInContainer.ps1'
        $run = $c.IndexOf('& $engineScript')
        $c.IndexOf('Restore-SIRaAutoBucketCache') | Should -BeLessThan $run
        $c.IndexOf('Save-SIRaAutoBucketCache') | Should -BeGreaterThan $run
    }
}

# ======================================================================================================================
#  The secret filter lets token LIMITS through -- and nothing else
# ======================================================================================================================
Describe 'the secret-name filter lets known token limits through, and still refuses secrets' {
    It 'AI_MaxTokens, AI_MaxTokensPerRequest, OpenAI_MaxTokensPerRequest and SI_IdentityTokenTenantId travel' {
        foreach ($n in 'AI_MaxTokens', 'AI_MaxTokensPerRequest', 'OpenAI_MaxTokensPerRequest', 'SI_IdentityTokenTenantId') {
            Test-SIConfigNameIsSecret -Name $n | Should -BeFalse -Because "$n is not a secret"
        }
        $r = Get-SIConfigEnvArgs -Names @('OpenAI_MaxTokensPerRequest') -Globals @{ OpenAI_MaxTokensPerRequest = 16384 }
        @($r.EnvArgs) | Should -Be @('SI_CFG_OpenAI_MaxTokensPerRequest=16384')
        (Import-SIConfigFromEnv -Environment @{ SI_CFG_AI_MaxTokens = '4000' }).Applied | Should -Be @('AI_MaxTokens')
        Remove-Variable -Name AI_MaxTokens -Scope Global -ErrorAction SilentlyContinue
    }
    It 'NEGATIVE -- every secret-looking name is still refused, including other *Token* names' {
        foreach ($n in 'SI_SPN_Secret', 'OpenAI_apiKey', 'SMTPPassword', 'SI_StorageKey', 'SI_License', 'SI_GraphToken', 'AI_MaxTokensX', 'MyAccessToken', 'SI_SPN_CertThumbprint') {
            Test-SIConfigNameIsSecret -Name $n | Should -BeTrue -Because "$n must never travel as a plain setting"
        }
        $imp = Import-SIConfigFromEnv -Environment @{ SI_CFG_SI_GraphToken = 'x' }
        @($imp.Refused) | Should -Contain 'SI_GraphToken'
    }
}

# ======================================================================================================================
#  The classifier's 24-hour skip works in a container
# ======================================================================================================================
Describe 'the classifier skips a rebuild within 24 hours in a container too' {
    It 'with no local catalog, the shared copy is taken first -- and stamped with the time it was shared' {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-CatalogBlob.ps1')
        $local = Join-Path $TestDrive 'ptc\privilege-tier-catalog.custom.json'
        $shared = [datetimeoffset]::UtcNow.AddHours(-3)
        Mock New-SIAzStorageContext { [pscustomobject]@{} }
        Mock Get-SIAzStorageBlob { [pscustomobject]@{ Name = 'privilege-tier-catalog.custom.json'; LastModified = $shared } }
        Mock Get-SIAzStorageBlobContent { '{"EntraRoles":[]}' | Set-Content -LiteralPath $Destination }
        Update-SICatalogFromBlob -LocalPath $local -AccountName 'acct' | Should -Be 'storage'
        $age = ([datetime]::UtcNow - (Get-Item -LiteralPath $local).LastWriteTimeUtc).TotalHours
        $age | Should -BeGreaterThan 2.9
        $age | Should -BeLessThan 24 -Because 'the skip compares exactly this age'
    }
    It 'WIRING -- the classifier reads the shared copy only when it has none, and BEFORE the age check' {
        $c = Get-Code 'engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1'
        $refresh = $c.IndexOf('Update-SICatalogFromBlob -LocalPath $OutputFile')
        $skip = $c.IndexOf('if ($_ageHours -lt 24)')
        $refresh | Should -BeGreaterThan 0
        $refresh | Should -BeLessThan $skip
        # (#257: a dry run never fetches it -- the -not $script:PtcWhatIf guard in front)
        $c | Should -Match "if \((-not \`$script:PtcWhatIf -and )?-not \(Test-Path -LiteralPath \`$OutputFile\) -and -not \[string\]::IsNullOrWhiteSpace\(\[string\]\`$global:SI_StorageAccount\)\)"
    }
}

# ======================================================================================================================
#  Community customisation files reach every job, on day 1 and after every update
# ======================================================================================================================
Describe 'the install''s customisation files reach the container jobs through its storage account' {
    It 'only customisation files may travel' -ForEach @(
        @{ P = 'asset-profiling-providers/generic-cmdb/CMDB.csv'; Ok = $true }
        @{ P = 'asset-profiling-providers\servicenow-cmdb\CMDB.csv'; Ok = $true }
        @{ P = 'risk-analysis-detection/RiskAnalysis_Queries_Custom.yaml'; Ok = $true }
        @{ P = 'risk-analysis-detection/custom/RiskAnalysis_Queries_Custom.yaml'; Ok = $true }
        @{ P = 'risk-analysis-detection/Device_Missing_CVEs_Summary.exclude.json'; Ok = $true }
        @{ P = 'risk-analysis-detection/Device_Missing_CVEs_Summary.exclude.custom.json'; Ok = $true }
        @{ P = 'risk-analysis-detection/RiskAnalysisGlobalExclusions.custom.json'; Ok = $true }
        @{ P = 'risk-analysis-detection/Report.weighted.custom.json'; Ok = $true }
        @{ P = 'asset-profiling-enrichment/endpoint/AssetProfileByApplicationServiceDetection/Mine.custom.yaml'; Ok = $true }
        @{ P = 'asset-profiling-schema/endpoint.schema.custom.json'; Ok = $true }
        @{ P = 'config/asset-decisions.custom.yaml'; Ok = $true }
        @{ P = 'config/cmdb-source-ownership.custom.json'; Ok = $true }
        @{ P = 'config/SecurityInsight.custom.ps1'; Ok = $false }
        @{ P = 'launcher/endpoint/LauncherConfig.custom.ps1'; Ok = $false }
        @{ P = 'risk-analysis-detection/riskscore.index.custom.csv'; Ok = $true }    # #398: the customer's own risk rows
        @{ P = 'risk-analysis-detection/riskscore.index.locked.csv'; Ok = $false }
        @{ P = 'risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml'; Ok = $false }
        @{ P = 'risk-analysis-detection/Device_Missing_CVEs_Summary.exclude.json.sample'; Ok = $false }
        @{ P = 'asset-profiling-enrichment/_TEMPLATE.custom.sample.yaml'; Ok = $false }
        @{ P = 'privilege-tier-catalog/privilege-tier-catalog.custom.json'; Ok = $false }
        @{ P = 'engine/risk-analysis/Invoke-RiskAnalysis.ps1'; Ok = $false }
        @{ P = '../risk-analysis-detection/RiskAnalysis_Queries_Custom.yaml'; Ok = $false }
        @{ P = '/etc/RiskAnalysis_Queries_Custom.yaml'; Ok = $false }
        @{ P = 'config/connector-jira-issues.json'; Ok = $false }
    ) {
        Test-SIOverlayPath -RelativePath $P | Should -Be $Ok
    }
    It 'the install''s files are found where a VM keeps them; samples, scripts and run output are not' {
        $root = Join-Path $TestDrive 'install'
        foreach ($rel in 'asset-profiling-providers/generic-cmdb/CMDB.csv', 'asset-profiling-providers/generic-cmdb/sample/CMDB.csv',
                         'risk-analysis-detection/RiskAnalysis_Queries_Custom.yaml', 'risk-analysis-detection/RiskAnalysis_Queries_Custom.sample.yaml',
                         'risk-analysis-detection/A.exclude.json', 'config/SecurityInsight.custom.ps1', 'config/asset-decisions.custom.yaml',
                         'risk-analysis-detection/OUTPUT/AutoBucketCache.json') {
            $p = Join-Path $root $rel; New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null; 'x' | Set-Content -LiteralPath $p
        }
        @(Get-SIContainerOverlayFiles -Root $root | ForEach-Object RelativePath) | Should -Be @(
            'asset-profiling-providers/generic-cmdb/CMDB.csv', 'config/asset-decisions.custom.yaml',
            'risk-analysis-detection/A.exclude.json', 'risk-analysis-detection/RiskAnalysis_Queries_Custom.yaml')
    }
    It '#521 the update shares them over the blob data plane (REST, OAuth only) -- no az; removes only overlay names, every list page read' {
        $root = Join-Path $TestDrive 'install3'
        $p = Join-Path $root 'risk-analysis-detection/RiskAnalysis_Queries_Custom.yaml'; New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null; 'q' | Set-Content $p
        $script:RestCalls = New-Object System.Collections.Generic.List[object]
        $rest = { param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
            $script:RestCalls.Add([pscustomobject]@{ M = $Method; U = $Uri; R = $Resource; H = $Headers })
            if ($Method -eq 'PUT' -and $Uri -like '*restype=container') { return [pscustomobject]@{ Status = 409; Body = 'ContainerAlreadyExists' } }
            if ($Method -eq 'PUT') { return [pscustomobject]@{ Status = 201; Body = '' } }
            if ($Method -eq 'GET' -and $Uri -notlike '*marker=*') { return [pscustomobject]@{ Status = 200; Body = '<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs><Blob><Name>risk-analysis-detection/RiskAnalysis_Queries_Custom.yaml</Name></Blob><Blob><Name>someone-elses/file.txt</Name></Blob></Blobs><NextMarker>p2</NextMarker></EnumerationResults>' } }
            if ($Method -eq 'GET') { return [pscustomobject]@{ Status = 200; Body = '<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs><Blob><Name>asset-profiling-providers/generic-cmdb/CMDB.csv</Name></Blob></Blobs><NextMarker /></EnumerationResults>' } }
            if ($Method -eq 'DELETE') { return [pscustomobject]@{ Status = 202; Body = '' } }
            [pscustomobject]@{ Status = 400; Body = 'unexpected' } }
        $r = Publish-SIContainerOverlay -Root $root -AccountName 'stacct' -Rest $rest
        $r.Uploaded | Should -Be 1
        @($r.Removed) | Should -Be @('asset-profiling-providers/generic-cmdb/CMDB.csv') -Because 'the second list page is read too'
        @($script:RestCalls | Where-Object { $_.R -ne 'https://storage.azure.com/' }) | Should -BeNullOrEmpty -Because 'OAuth only (the storage audience), never an account key'
        $put = @($script:RestCalls | Where-Object { $_.M -eq 'PUT' -and $_.U -like '*RiskAnalysis_Queries_Custom.yaml' })[0]
        $put.U | Should -Be 'https://stacct.blob.core.windows.net/sioverlay/risk-analysis-detection/RiskAnalysis_Queries_Custom.yaml'
        $put.H['x-ms-blob-type'] | Should -Be 'BlockBlob'
        @($script:RestCalls | Where-Object { $_.U -like '*someone-elses*' }) | Should -BeNullOrEmpty
        # unreachable: one line, the run goes on
        $deny = { param($Method, $Uri, $Body, $Resource, $Headers) [pscustomobject]@{ Status = 403; Body = 'AuthorizationPermissionMismatch' } }
        $n = Publish-SIContainerOverlay -Root $root -AccountName 'stacct' -Rest $deny
        @($n.Failed) | Should -Be @('(container)'); $n.Message | Should -Match 'Storage Blob Data Contributor'
        { Publish-SIContainerOverlay -Root $root -AccountName 'stacct' } | Should -Throw '*pass -Rest*'
    }
    It 'NEGATIVE -- storage unreachable: setup carries on with one warning line; no storage account: nothing is attempted' {
        $deny = { param($Method, $Uri, $Body, $Resource, $Headers) [pscustomobject]@{ Status = 403; Body = 'AuthorizationPermissionMismatch' } }
        $r = Publish-SIContainerOverlay -Root $TestDrive -AccountName 'stacct' -Rest $deny
        @($r.Failed).Count | Should -BeGreaterThan 0
        $r.Message | Should -Match 'Storage Blob Data Contributor'
        $script:Called = $false
        $r = Publish-SIContainerOverlay -Root $TestDrive -AccountName '' -Rest { param($Method, $Uri, $Body, $Resource, $Headers) $script:Called = $true; [pscustomobject]@{ Status = 200; Body = '' } }
        $script:Called | Should -BeFalse
        (Get-Command Publish-SIContainerOverlay).Parameters.ContainsKey('Az') | Should -BeFalse -Because 'the az seam is gone (#521)'
    }
    It 'a job restores them where a VM has them; a name outside the allow-list is never written, whoever uploaded it' {
        $target = Join-Path $TestDrive 'app'
        Mock New-SIAzStorageContext { [pscustomobject]@{} }
        Mock Get-SIAzStorageBlob { @([pscustomobject]@{ Name = 'asset-profiling-providers/generic-cmdb/CMDB.csv' },
                                     [pscustomobject]@{ Name = 'engine/risk-analysis/Invoke-RiskAnalysis.ps1' },
                                     [pscustomobject]@{ Name = 'risk-analysis-detection/RiskAnalysis_Queries_Custom.yaml' }) }
        Mock Get-SIAzStorageBlobContent { ('content of ' + $Blob) | Set-Content -LiteralPath $Destination }
        $r = Restore-SIContainerOverlay -AccountName 'stacct' -TargetRoot $target -RunFolder (Join-Path $TestDrive 'run')
        @($r.Applied) | Should -Be @('asset-profiling-providers/generic-cmdb/CMDB.csv', 'risk-analysis-detection/RiskAnalysis_Queries_Custom.yaml')
        @($r.Skipped) | Should -Be @('engine/risk-analysis/Invoke-RiskAnalysis.ps1')
        Get-Content -LiteralPath (Join-Path $target 'asset-profiling-providers\generic-cmdb\CMDB.csv') | Should -Be 'content of asset-profiling-providers/generic-cmdb/CMDB.csv'
        Join-Path $target 'engine\risk-analysis\Invoke-RiskAnalysis.ps1' | Should -Not -Exist
        Should -Invoke Get-SIAzStorageBlobContent -Times 2 -Exactly
    }
    It 'NEGATIVE -- nothing shared yet, or storage failing: the run continues on the shipped files' {
        Mock New-SIAzStorageContext { [pscustomobject]@{} }
        Mock Get-SIAzStorageBlob { throw "Can not find the container 'sioverlay' (ContainerNotFound)." }
        $r = Restore-SIContainerOverlay -AccountName 'stacct' -TargetRoot $TestDrive
        $r.Source | Should -Be 'none'
        Mock Get-SIAzStorageBlob { throw 'This request is not authorized (403).' }
        { Restore-SIContainerOverlay -AccountName 'stacct' -TargetRoot $TestDrive -WarningAction SilentlyContinue } | Should -Not -Throw
        (Restore-SIContainerOverlay -AccountName '' -TargetRoot $TestDrive).Source | Should -Be 'none'
    }
    It 'the image carries none of them, so the first image and every update image are the same' {
        $di = Get-Content -LiteralPath (Join-Path $script:SIRoot '.dockerignore')
        $di | Should -Contain 'asset-profiling-providers/*/CMDB.csv'
        $di | Should -Contain '**/RiskAnalysis_Queries_Custom.yaml'
        $di | Should -Contain '**/*.exclude.json'
        # the shipped sample CMDB stays (it is two folders deep, so the rule does not match it)
        $di | Should -Not -Contain 'asset-profiling-providers/**/CMDB.csv'
    }
    It 'WIRING -- every job restores them only when no Pro settings layer is active; setup and the update hook share them' {
        foreach ($f in 'container\Start-SIInContainer.ps1', 'container\Start-RiskAnalysisInContainer.ps1') {
            $c = Get-Code $f
            $c | Should -Match '(?s)Invoke-SIProSettingsLayer.{0,1800}\} else \{.{0,400}Restore-SIContainerOverlay' -Because "$f restores the overlay only without the Pro layer"
            $c | Should -Not -Match 'Assert-SIFeatureOrSkip.{0,200}Restore-SIContainerOverlay' -Because 'Community needs no licence for its own files'
        }
        (Get-Code 'Bootstrap-ContainerAppJob.ps1') | Should -Match 'Publish-SIContainerOverlay -Root \$PSScriptRoot -AccountName'
        (Get-Code 'setup\Invoke-SIContainerUpdate.ps1') | Should -Match 'Publish-SIContainerOverlay -Root \$solRoot -AccountName \$ovAccount'
    }
}
