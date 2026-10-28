#Requires -Version 5.1
<#
    v3 ARRIVES SAFELY WITH NOBODY READING THE NOTES (#276).

    Many 2.2 installs pull 3.0 by themselves (2.2's updater pulls at once; the 2.2 README scheduled a daily git pull;
    internal installs sync from main). So every step that matters is done by 3.0 on its first run, or is harmless if
    skipped. Proven here, on the REAL loader in a child process of the current shell (run the suite on powershell.exe
    AND pwsh) and on the shared safety layer (engine\_shared\SI-FirstRun.ps1):

      * detection -- a fresh install gets no upgrade notice; an upgraded one gets it exactly once; no repeat;
      * no dry run from the configuration ("upgrade must work, no dryrun") -- a WhatIfMode in the config gives a
        normal publishing run plus one line; an explicit per-run request still gives a dry run; asset tagging keeps it;
      * a dry run says so loudly at its start and its end, every run, and its run-health row says dry run;
      * the retired Power BI line in the container entry points too;
      * the settings from a 2.2 configuration that now take effect, listed exactly, and saved under logs\;
      * the status-report notice once (on by default -- operator decision; no separate default for upgraded installs).
    Offline: no Azure, no network.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Exe    = [Diagnostics.Process]::GetCurrentProcess().Path
    . (Join-Path $script:SIRoot 'engine\_shared\SI-FirstRun.ps1')

    function script:New-Install {
        param([string]$Custom = '# nothing', [switch]$OldLogs, [switch]$V22Snapshot)
        $root = Join-Path ([IO.Path]::GetTempPath()) ('si276-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force (Join-Path $root 'config'), (Join-Path $root 'logs') | Out-Null
        [IO.File]::WriteAllText((Join-Path $root 'config\SecurityInsight.custom.ps1'), $Custom, [Text.UTF8Encoding]::new($true))
        [IO.File]::WriteAllText((Join-Path $root 'engine.custom.ps1'), '# none', [Text.UTF8Encoding]::new($true))
        if ($OldLogs) {
            $f = Join-Path $root 'logs\endpoint_community-vm_20260901-020000.log'
            Set-Content -LiteralPath $f -Value 'a 2.2 run' -Encoding UTF8
            (Get-Item -LiteralPath $f).LastWriteTime = (Get-Date).AddDays(-2)
        }
        if ($V22Snapshot) {
            $f = Join-Path $root 'logs\config-RiskAnalysis-20260901-020000-VM1.log'
            Set-Content -LiteralPath $f -Encoding UTF8 -Value @('Layer load trail:', 'Layer 3 - SecurityInsight.custom   loaded  x', 'Layer 4 - LauncherConfig.defaults   loaded  y')
            (Get-Item -LiteralPath $f).LastWriteTime = (Get-Date).AddDays(-1)
        }
        $root
    }

    # Runs the real loader for one engine on the given install; returns every line it wrote and the WhatIfMode after it.
    # -ExplicitWhatIf applies the launcher's own -WhatIfMode handling after the loader, exactly as the launchers do.
    function script:Invoke-Load {
        param([string]$Root, [string]$Engine = 'RiskAnalysis', [string]$LauncherFolder = 'risk-analysis', [string]$EngineCustom, [string]$Extra = '')
        if ($EngineCustom) { [IO.File]::WriteAllText((Join-Path $Root 'engine.custom.ps1'), $EngineCustom, [Text.UTF8Encoding]::new($true)) }
        $out = Join-Path $Root ('out-' + [guid]::NewGuid().ToString('N') + '.txt')
        $lib = Join-Path $script:SIRoot 'launcher\_lib\Initialize-LauncherConfig.ps1'
        $dir = Join-Path $script:SIRoot ('launcher\' + $LauncherFolder)
        $cmd = @"
`$ErrorActionPreference = 'Stop'
. '$lib'
`$o = Initialize-LauncherConfig -Solution 'SecurityInsight' -Engine '$Engine' -LauncherDir '$dir' -RepoRoot '$Root' -Mode 'community' -CustomConfigPath '$(Join-Path $Root 'engine.custom.ps1')' *>&1 | ForEach-Object { [string]`$_ }
$Extra
`$o += ('WHATIFMODE=' + [bool]`$global:WhatIfMode)
`$o | Set-Content -LiteralPath '$out' -Encoding UTF8
"@
        & $script:Exe -NoProfile -NonInteractive -Command $cmd | Out-Null
        @(Get-Content -LiteralPath $out -Encoding UTF8)
    }
    function script:Get-State([string]$Root) {
        $p = Join-Path $Root 'logs\state\install-state.json'
        if (Test-Path -LiteralPath $p) { Get-Content -Raw -LiteralPath $p | ConvertFrom-Json }
    }
    function script:Count-Match([string[]]$Lines, [string]$Re) { @($Lines | Where-Object { $_ -match $Re }).Count }
    $script:UpgradeRe   = 'SecurityInsight was updated to 3\.0'
    $script:TelemetryRe = 'sends short status reports to Invardia'
    $script:IgnoredRe   = 'WhatIfMode in your configuration is ignored for scheduled runs'
    $script:Roots = New-Object System.Collections.Generic.List[string]
}

AfterAll { foreach ($r in $script:Roots) { Remove-Item -Recurse -Force -LiteralPath $r -ErrorAction SilentlyContinue } }

# ======================================================================================================================
Describe 'detection: fresh install -> no upgrade notice; upgraded -> exactly once; never again' {
    It 'Get-SIFirstRunDecision: no state + no evidence = fresh; no state + evidence = upgraded; a state = seen' {
        (Get-SIFirstRunDecision -State $null -Evidence @()).Kind | Should -Be 'fresh'
        (Get-SIFirstRunDecision -State $null -Evidence @('', ' ')).Kind | Should -Be 'fresh'
        (Get-SIFirstRunDecision -State $null -Evidence @('earlier-run-logs')).Kind | Should -Be 'upgraded'
        $s = New-SIInstallState -Origin upgraded -Evidence @('x') -Version '3.0.0'
        $d = Get-SIFirstRunDecision -State $s -Evidence @('earlier-run-logs')
        $d.Kind | Should -Be 'seen'; $d.Origin | Should -Be 'upgraded'
    }

    It 'FRESH install (no earlier run, no 2.2 setting): no upgrade notice, the status-report notice once, state = fresh; second run: nothing' {
        $r = New-Install; $script:Roots.Add($r)
        $one = Invoke-Load -Root $r
        Count-Match $one $script:UpgradeRe | Should -Be 0
        Count-Match $one $script:TelemetryRe | Should -Be 1
        (Get-State $r).Origin | Should -Be 'fresh'
        $two = Invoke-Load -Root $r
        Count-Match $two $script:UpgradeRe | Should -Be 0
        Count-Match $two $script:TelemetryRe | Should -Be 0
        Count-Match $two '\[NOTICE\]' | Should -Be 0
    }

    It 'UPGRADED install (run logs older than this run): the upgrade notice exactly once; the second run repeats nothing' {
        $r = New-Install -OldLogs; $script:Roots.Add($r)
        $one = Invoke-Load -Root $r
        Count-Match $one $script:UpgradeRe | Should -Be 1
        $st = Get-State $r
        $st.Origin | Should -Be 'upgraded'
        @($st.Evidence) | Should -Contain 'earlier-run-logs'
        @($st.Shown) | Should -Contain 'upgrade'
        $two = Invoke-Load -Root $r
        Count-Match $two '\[NOTICE\]' | Should -Be 0
        # another engine's first run: its own settings list may come, the install-wide notices do not
        $three = Invoke-Load -Root $r -Engine 'AssetProfiling_Endpoint' -LauncherFolder 'endpoint'
        Count-Match $three $script:UpgradeRe | Should -Be 0
        Count-Match $three $script:TelemetryRe | Should -Be 0
    }

    It 'the 2.2 config snapshot and a setting only 2.2 read are evidence on their own' {
        $l = Join-Path ([IO.Path]::GetTempPath()) ('si276ev-' + [guid]::NewGuid().ToString('N').Substring(0, 8)); $script:Roots.Add($l)
        New-Item -ItemType Directory -Force $l | Out-Null
        $f = Join-Path $l 'config-Endpoint-1.log'
        Set-Content -LiteralPath $f -Value 'Layer 4 - LauncherConfig.defaults   loaded' -Encoding UTF8
        (Get-Item $f).LastWriteTime = (Get-Date).AddHours(-3)
        @(Get-SIUpgradeEvidenceVm -LogDir $l -Before (Get-Date)) | Should -Contain 'v2.2-config-snapshot'
        @(Get-SIUpgradeEvidenceVm -LogDir (Join-Path $l 'none') -SettingNames @('SendToPowerBI')) | Should -Be @('v2.2-settings')
        @(Get-SIUpgradeEvidenceVm -LogDir (Join-Path $l 'none') -SettingNames @('PowerBI_DatasetName')) | Should -Be @('v2.2-settings')
        # NEGATIVE: this run's own log (newer than the run start) is not evidence; nor is a 3.0 setting
        @(Get-SIUpgradeEvidenceVm -LogDir $l -Before (Get-Date).AddHours(-4) -SettingNames @('SI_Sinks_Endpoint')).Count | Should -Be 0
    }

    It 'an unreadable state store shows nothing and writes nothing (an unreadable store never repeats notices every run)' {
        $store = @{ Kind = 'memory'; Box = @{ json = '{ this is not json' } }
        $res = Invoke-SIFirstRunNotices -Hosting container -Engine 'endpoint' -Store $store -Evidence { @('earlier-run-logs') } -TelemetryOn $true 6>$null
        $res.Kind | Should -Be 'unknown'
        @($res.Shown).Count | Should -Be 0
        $store.Box['writes'] | Should -BeNullOrEmpty
    }
}

# ======================================================================================================================
Describe 'no dry run from the configuration ("upgrade must work, no dryrun"); a dry run is asked for per run' {
    It 'Resolve-SIConfigDryRun: a config value is set aside for every engine except asset tagging' {
        foreach ($e in 'RiskAnalysis', 'AssetProfiling_Endpoint', 'PrivilegeTierClassifier', 'endpoint', 'risk-analysis', 'Trend') {
            $r = Resolve-SIConfigDryRun -Engine $e -ConfigValue $true
            $r.Ignored | Should -BeTrue -Because $e
            $r.WhatIfMode | Should -BeFalse -Because $e
        }
        foreach ($e in 'AssetTagging', 'asset-tagging') { (Resolve-SIConfigDryRun -Engine $e -ConfigValue $true).WhatIfMode | Should -BeTrue -Because $e }
        (Resolve-SIConfigDryRun -Engine 'RiskAnalysis' -ConfigValue '$true').Ignored | Should -BeTrue
        (Resolve-SIConfigDryRun -Engine 'RiskAnalysis' -ConfigValue $false).Ignored | Should -BeFalse
        # a value the caller set itself (not a config layer) is not touched
        (Resolve-SIConfigDryRun -Engine 'RiskAnalysis' -ConfigValue $true -SetByConfig $false).WhatIfMode | Should -BeTrue
    }

    It 'config WhatIfMode = $true -> the loader leaves a NORMAL run (WhatIfMode false) and says so in one line; the upgrade notice records it' {
        $r = New-Install -OldLogs -Custom "`$global:WhatIfMode = `$true`r`n"; $script:Roots.Add($r)
        $one = Invoke-Load -Root $r
        $one | Should -Contain 'WHATIFMODE=False'
        Count-Match $one $script:IgnoredRe | Should -Be 1
        Count-Match $one 'Your configuration sets WhatIfMode\. It no longer stops or limits scheduled runs' | Should -Be 1
        # every run, not once
        $two = Invoke-Load -Root $r
        $two | Should -Contain 'WHATIFMODE=False'
        Count-Match $two $script:IgnoredRe | Should -Be 1
    }

    It 'the launcher''s explicit -WhatIfMode (applied after the loader, as every launcher does) still gives a dry run' {
        $r = New-Install -Custom "`$global:WhatIfMode = `$true`r`n"; $script:Roots.Add($r)
        $o = Invoke-Load -Root $r -Extra '$WhatIfMode = [switch]$true; $global:WhatIfMode = [bool]$WhatIfMode'
        $o | Should -Contain 'WHATIFMODE=True'
    }

    It 'asset tagging keeps the configuration value (report only) and prints no "ignored" line' {
        $r = New-Install -Custom "`$global:WhatIfMode = `$true`r`n"; $script:Roots.Add($r)
        $o = Invoke-Load -Root $r -Engine 'AssetTagging' -LauncherFolder 'asset-tagging'
        $o | Should -Contain 'WHATIFMODE=True'
        Count-Match $o $script:IgnoredRe | Should -Be 0
    }

    It 'NEGATIVE: no WhatIfMode in the configuration -> no "ignored" line' {
        $r = New-Install; $script:Roots.Add($r)
        Count-Match (Invoke-Load -Root $r) $script:IgnoredRe | Should -Be 0
    }

    It 'WIRING: every launcher applies its -WhatIfMode switch AFTER the loader (so the switch is the only way to a dry run)' {
        foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'launcher') -Recurse -Filter 'launcher.*.ps1') {
            $t = [IO.File]::ReadAllText($f.FullName)
            $sw = $t.IndexOf("PSBoundParameters.ContainsKey('WhatIfMode')")
            if ($sw -lt 0) { continue }
            $init = $t.IndexOf('Initialize-LauncherConfig ')
            $init | Should -BeGreaterThan 0 -Because $f.FullName
            $sw | Should -BeGreaterThan $init -Because $f.FullName
        }
    }

    Context 'profiling -- a real (mock-data) run after the loader, in a child process' {
        BeforeAll {
            $script:ProfRun = {
                param([bool]$Explicit)
                $r = New-Install -Custom "`$global:WhatIfMode = `$true`r`n`$global:SI_FingerprintCache_Enabled = `$true`r`n"; $script:Roots.Add($r)
                $res = Join-Path $r 'res.json'
                $engine = Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1'
                $sw = if ($Explicit) { '$global:WhatIfMode = $true' } else { '' }
                $extra = @"
$sw
`$global:SI_CustomConfigPath = Join-Path ([IO.Path]::GetTempPath()) ('no-si-config-' + [guid]::NewGuid().ToString('N') + '.ps1')
`$rr = & '$engine' -Engine endpoint -Mock -Sinks @('LA', 'JSON') *>&1
`$ctx = @(`$rr | Where-Object { `$_ -is [pscustomobject] -and `$_.PSObject.Properties['RunId'] }) | Select-Object -Last 1
`$o += @(`$rr | ForEach-Object { [string]`$_ })
[pscustomobject]@{ WhatIf = [bool]`$ctx.WhatIf; Sinks = @(`$ctx.Sinks) } | ConvertTo-Json -Compress | Set-Content -LiteralPath '$res' -Encoding UTF8
"@
                $lines = Invoke-Load -Root $r -Engine 'AssetProfiling_Endpoint' -LauncherFolder 'endpoint' -Extra $extra
                [pscustomobject]@{ Lines = $lines; Run = (Get-Content -Raw -LiteralPath $res | ConvertFrom-Json) }
            }
            $script:Scheduled = & $script:ProfRun $false
            $script:Explicit  = & $script:ProfRun $true
        }
        It 'config WhatIfMode = $true, scheduled run: publishes as normal (Log Analytics in the sinks) and says the value was ignored' {
            $script:Scheduled.Run.WhatIf | Should -BeFalse
            @($script:Scheduled.Run.Sinks) | Should -Contain 'LA'
            Count-Match $script:Scheduled.Lines $script:IgnoredRe | Should -Be 1
            Count-Match $script:Scheduled.Lines '^DRY RUN' | Should -Be 0
        }
        It 'explicit -WhatIfMode: a dry run (Log Analytics dropped) that says so at its start and at its end' {
            $script:Explicit.Run.WhatIf | Should -BeTrue
            @($script:Explicit.Run.Sinks) | Should -Not -Contain 'LA'
            Count-Match $script:Explicit.Lines '^DRY RUN -- this run publishes nothing and sends nothing' | Should -Be 1
            Count-Match $script:Explicit.Lines '^DRY RUN finished -- nothing was published or sent' | Should -Be 1
        }
    }
}

# ======================================================================================================================
Describe 'a dry run is loud on every run, and its run-health row says dry run' {
    BeforeAll { . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1') }

    It 'Get-SIRunHealthDryRunRow: a good dry run ends "dry-run"; a failed one keeps its failure; the message says dry run' {
        $e = Get-SIRunHealthDryRunRow -Phase End -ExitReason 'success' -ErrorMessage ''
        $e.ExitReason | Should -Be 'dry-run'; $e.ErrorMessage | Should -Be 'dry run -- nothing was published or sent'
        (Get-SIRunHealthDryRunRow -Phase End -ExitReason 'success-partial' -ErrorMessage '').ExitReason | Should -Be 'dry-run'
        $f = Get-SIRunHealthDryRunRow -Phase End -ExitReason 'error' -ErrorMessage 'boom'
        $f.ExitReason | Should -Be 'error'; $f.ErrorMessage | Should -Be 'dry run -- nothing was published or sent; boom'
        (Get-SIRunHealthDryRunRow -Phase Start -ExitReason '' -ErrorMessage '').ExitReason | Should -Be ''
    }

    It 'every run (each process) prints the start AND the end line once -- two runs, two of each' {
        $runner = Join-Path $TestDrive 'dry.ps1'
        Set-Content -LiteralPath $runner -Encoding UTF8 -Value @"
`$global:WhatIfMode = `$true
. '$(Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1')'
`$ctx = [pscustomobject]@{ RunId = 'r'; Engine = 'endpoint'; ShardIndex = 0; ShardCount = 1; StartedAt = [datetime]::UtcNow; CollectionTime = [datetime]::UtcNow }
Send-SIRunHealthRow -RunContext `$ctx -Phase Start 3>`$null
Send-SIRunHealthRow -RunContext `$ctx -Phase Start 3>`$null
Send-SIRunHealthRow -RunContext `$ctx -Phase End -ExitReason success 3>`$null
"@
        $all = @()
        foreach ($i in 1, 2) { $all += @(& $script:Exe -NoProfile -NonInteractive -File $runner *>&1 | ForEach-Object { [string]$_ }) }
        Count-Match $all '^DRY RUN -- this run publishes nothing' | Should -Be 2
        Count-Match $all '^DRY RUN finished' | Should -Be 2
        Count-Match $all 'run without -WhatIfMode|Run it without -WhatIfMode' | Should -Be 4
    }

    It 'the dry run''s row is now recorded (it reaches the save step -- here it says why it could not be saved); CONTROL: no dry-run line in a normal run' {
        $keep = @{}; foreach ($n in 'WhatIfMode', 'SI_WorkspaceResourceId', 'SI_DceName', 'SI_DcrResourceGroup', 'SI_RunHealthFailWarned', 'SI_DryRunStartSaid', 'SI_DryRunEndSaid') { $keep[$n] = Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
        try {
            $global:SI_WorkspaceResourceId = '/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/z'
            Remove-Variable -Name SI_DceName, SI_DcrResourceGroup, SI_RunHealthFailWarned, SI_DryRunStartSaid, SI_DryRunEndSaid -Scope Global -ErrorAction SilentlyContinue
            $ctx = [pscustomobject]@{ RunId = 'r'; Engine = 'endpoint'; ShardIndex = 0; ShardCount = 1; StartedAt = [datetime]::UtcNow; CollectionTime = [datetime]::UtcNow }
            $global:WhatIfMode = $true
            $w = $null; $info = Send-SIRunHealthRow -RunContext $ctx -Phase 'Start' -WarningVariable w -WarningAction SilentlyContinue 6>&1
            "$w" | Should -Match 'Run-health record not saved'
            "$info" | Should -Match 'DRY RUN'
            $global:WhatIfMode = $false
            Remove-Variable -Name SI_DryRunStartSaid -Scope Global -ErrorAction SilentlyContinue
            $info = Send-SIRunHealthRow -RunContext $ctx -Phase 'Start' -WarningAction SilentlyContinue 6>&1
            "$info" | Should -Not -Match 'DRY RUN'
        } finally {
            foreach ($n in $keep.Keys) { if ($null -ne $keep[$n]) { Set-Variable -Name $n -Scope Global -Value $keep[$n] } else { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue } }
        }
    }

    It 'the install check names a last run that was a dry run' {
        . (Join-Path $script:SIRoot 'diagnostics\_SIInstallDiagnostics.ps1')
        $now = [datetime]::UtcNow
        $rows = @([pscustomobject]@{ Engine = 'endpoint'; Phase = 'Start'; At = $now.AddMinutes(-10); ExitReason = ''; DurationSec = '' },
                  [pscustomobject]@{ Engine = 'endpoint'; Phase = 'End'; At = $now.AddMinutes(-5); ExitReason = 'dry-run'; DurationSec = '300' })
        (Get-SIRunHealthSummary -Rows $rows -NowUtc $now)[0].Problem | Should -Match 'dry run -- nothing was published'
    }
}

# ======================================================================================================================
Describe 'containers: the same safety layer (dry run, Power BI line, one-time notices)' {
    BeforeEach {
        foreach ($n in 'WhatIfMode', 'SendToPowerBI', 'SI_WhatIfModeConfigIgnored') { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
    }
    AfterAll {
        foreach ($n in 'WhatIfMode', 'SendToPowerBI', 'SI_WhatIfModeConfigIgnored') { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
    }

    It 'SendToPowerBI in the job''s settings -> the retired Power BI line, once' {
        $global:SendToPowerBI = $true
        $w = $null
        $null = Invoke-SIContainerRunSafety -Engine 'risk-analysis' -StorageAccount '' -GetEnv { param($n) $null } -WarningVariable w -WarningAction SilentlyContinue 6>$null
        @($w | Where-Object { "$_" -match 'Power BI refresh was retired in SecurityInsight 3\.0' }).Count | Should -Be 1
    }
    It 'NEGATIVE: no Power BI setting -> no line' {
        $w = $null
        $null = Invoke-SIContainerRunSafety -Engine 'risk-analysis' -StorageAccount '' -GetEnv { param($n) $null } -WarningVariable w -WarningAction SilentlyContinue 6>$null
        @($w | Where-Object { "$_" -match 'Power BI' }).Count | Should -Be 0
    }
    It 'a WhatIfMode from the job''s settings is set aside (normal run, one line); SI_WHATIF=1 on the execution asks for a dry run' {
        $global:WhatIfMode = $true
        $w = $null
        $null = Invoke-SIContainerRunSafety -Engine 'endpoint' -StorageAccount '' -GetEnv { param($n) $null } -WarningVariable w -WarningAction SilentlyContinue 6>$null
        $global:WhatIfMode | Should -BeFalse
        "$w" | Should -Match 'ignored for scheduled runs.*SI_WHATIF=1 on a single job execution'
        $null = Invoke-SIContainerRunSafety -Engine 'endpoint' -StorageAccount '' -GetEnv { param($n) if ($n -eq 'SI_WHATIF') { '1' } } -WarningAction SilentlyContinue 6>$null
        $global:WhatIfMode | Should -BeTrue
        # asset tagging keeps its own value
        $global:WhatIfMode = $true
        $null = Invoke-SIContainerRunSafety -Engine 'asset-tagging' -StorageAccount '' -GetEnv { param($n) $null } -WarningAction SilentlyContinue 6>$null
        $global:WhatIfMode | Should -BeTrue
    }
    It 'WIRING: both container entry points run the layer after the settings / customisation layer and before the engine starts' {
        foreach ($f in 'container\Start-SIInContainer.ps1', 'container\Start-RiskAnalysisInContainer.ps1') {
            $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f))
            $at = $t.IndexOf('Invoke-SIContainerRunSafety -Engine')
            $at | Should -BeGreaterThan 0 -Because $f
            $at | Should -BeGreaterThan $t.IndexOf('Restore-SIContainerOverlay -AccountName') -Because $f
            $t.IndexOf('. /app/engine/_shared/SI-FirstRun.ps1') | Should -BeLessThan $at
        }
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $s.IndexOf('Invoke-SIContainerRunSafety -Engine') | Should -BeLessThan $s.IndexOf('if ($dispatchClassifier) {')
        $s.IndexOf('Invoke-SIContainerRunSafety -Engine') | Should -BeLessThan $s.IndexOf('& $orchestrator @orchArgs')
        $ra = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-RiskAnalysisInContainer.ps1'))
        $ra.IndexOf('Invoke-SIContainerRunSafety -Engine') | Should -BeLessThan $ra.IndexOf('& $engineScript')
    }
    It 'the container state is kept in the install''s storage account: earlier run logs = upgraded, notice once, never again' {
        $global:SI276Blobs = @{}
        # SI-FirstRun.ps1 loads SI's real Azure wrappers (SI-AzRest.ps1) where this file loads it: the storage stubs are
        # defined HERE, in the test's own scope, so they are the nearest definitions when the safety layer calls them
        function global:Get-SIRunStateContext { param($AccountName) [pscustomobject]@{ Account = $AccountName } }
        function Get-SIAzStorageBlob { param($Container, $Blob, $Prefix, $Context, $ErrorAction)
            if ($Blob) { if ($global:SI276Blobs.ContainsKey("$Container/$Blob")) { return [pscustomobject]@{ Name = $Blob } } else { throw 'BlobNotFound' } }
            if ($Container -eq 'sistaging') { return @([pscustomobject]@{ Name = 'run-logs/endpoint/x.log'; LastModified = [DateTimeOffset]::UtcNow.AddDays(-3) }) }
            @() }
        function Get-SIAzStorageBlobContent { param($Container, $Blob, $Destination, $Context, [switch]$Force, $ErrorAction) [IO.File]::WriteAllText($Destination, $global:SI276Blobs["$Container/$Blob"]) }
        function Get-SIAzStorageContainer { param($Name, $Context, $ErrorAction) $true }
        function Set-SIAzStorageBlobContent { param($File, $Container, $Blob, $Context, [switch]$Force, $ErrorAction) $global:SI276Blobs["$Container/$Blob"] = [IO.File]::ReadAllText($File) }
        try {
            $one = Invoke-SIContainerRunSafety -Engine 'endpoint' -StorageAccount 'stsi' -GetEnv { param($n) $null } 6>$null
            $one.Kind | Should -Be 'upgraded'
            @($one.Shown) | Should -Contain 'upgrade'
            ($global:SI276Blobs['sistate/install/install-state.json'] | ConvertFrom-Json).Origin | Should -Be 'upgraded'
            $two = Invoke-SIContainerRunSafety -Engine 'risk-analysis' -StorageAccount 'stsi' -GetEnv { param($n) $null } 6>$null
            $two.Kind | Should -Be 'seen'
            @($two.Shown).Count | Should -Be 0
        } finally {
            foreach ($f in 'Get-SIRunStateContext', 'Get-SIAzStorageBlob', 'Get-SIAzStorageBlobContent', 'Get-SIAzStorageContainer', 'Set-SIAzStorageBlobContent') { Remove-Item -LiteralPath ("Function:\$f") -ErrorAction SilentlyContinue }
            Remove-Variable -Name SI276Blobs -Scope Global -ErrorAction SilentlyContinue
        }
    }
}

# ======================================================================================================================
Describe 'the settings from a 2.2 configuration that now take effect -- listed exactly, once, and saved for support' {
    BeforeAll {
        $script:Fixture22 = @'
# A 2.2.460-era config\SecurityInsight.custom.ps1 (values chosen to exercise every rule)
$global:ExportDestination = 'D:\SecurityInsight\Reports'
$global:AutoBucketMax = 4096
$global:OverwriteXlsx = $false
$global:SendToLogAnalytics = $true
$global:SI_RiskAnalysis_TableName_Summary = 'SI_RiskAnalysis_Summary'
$global:Scope = @('PROD','TEST')
$global:GraphQueryMaxRetries = 6
$global:MailTo = 'secops@example.com'
$global:WhatIfMode = $true
'@
        $script:R183 = New-Install -OldLogs -Custom $script:Fixture22
        $script:Roots.Add($script:R183)
        $script:L1 = Invoke-Load -Root $script:R183 -EngineCustom '$global:GraphQueryMaxRetries = 6'
        $script:L2 = Invoke-Load -Root $script:R183
    }
    It 'the console lists exactly the four settings that change, with the 2.2 value and the value now in effect' {
        $at = [array]::FindIndex([string[]]$script:L1, [Predicate[string]]{ param($x) $x -match 'These settings from your configuration now take effect for the risk-analysis engine' })
        $at | Should -BeGreaterOrEqual 0
        $rows = @($script:L1[($at + 1)..($at + 4)] | ForEach-Object { $_.Trim() })
        $rows | Should -Be @(
            'AutoBucketMax: was 131072, now 4096',
            "ExportDestination: was (not set), now 'D:\SecurityInsight\Reports'",
            'OverwriteXlsx: was $true, now $false',
            "Scope: was @('PROD'), now @('PROD', 'TEST')")
        $script:L1[$at + 5] | Should -Match 'saved in logs\\settings-now-in-effect-risk-analysis\.txt'
    }
    It 'NOT listed: a value equal to 2.2''s, a setting 2.2''s defaults never set, one the engine''s own file sets, and the ignored WhatIfMode' {
        $text = $script:L1 -join "`n"
        foreach ($n in 'SendToLogAnalytics:', 'SI_RiskAnalysis_TableName_Summary:', 'MailTo:', 'GraphQueryMaxRetries:', 'WhatIfMode:') { $text | Should -Not -Match ([regex]::Escape($n)) }
    }
    It 'the file in logs\ holds the same list, for support' {
        $f = Join-Path $script:R183 'logs\settings-now-in-effect-risk-analysis.txt'
        Test-Path -LiteralPath $f | Should -BeTrue
        $t = Get-Content -Raw -LiteralPath $f
        $t | Should -Match 'AutoBucketMax: was 131072, now 4096'
        $t | Should -Match 'Scope: was @\(''PROD''\), now @\(''PROD'', ''TEST''\)'
    }
    It 'the second run does not list them again' {
        Count-Match $script:L2 'now take effect for the risk-analysis engine' | Should -Be 0
    }
    It 'Get-SISettingsNowInEffect (pure): secrets are never shown; a fresh install gets no list at all' {
        $c = @(Get-SISettingsNowInEffect -V22Defaults @{ SI_SPN_Secret = 'x'; A = 1 } -CustomNames @('SI_SPN_Secret', 'A') -Current @{ SI_SPN_Secret = 'mine'; A = 2 })
        $c.Count | Should -Be 2
        (Get-SISettingsNowInEffectLines -Engine e -Changes $c) -join "`n" | Should -Match 'SI_SPN_Secret: was \(hidden\), now \(hidden\)'
        $f = New-Install -Custom $script:Fixture22; $script:Roots.Add($f)
        Count-Match (Invoke-Load -Root $f) 'now take effect' | Should -Be 0
        Test-Path -LiteralPath (Join-Path $f 'logs\settings-now-in-effect-risk-analysis.txt') | Should -BeFalse
    }
    It 'the 2.2.460 reference data is complete for the six engines 2.2 shipped defaults for' {
        $d = (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'launcher\_lib\v2.2-engine-defaults.locked.json') | ConvertFrom-Json).engines
        foreach ($e in 'azure', 'endpoint', 'identity', 'privilege-tier-classifier', 'publicip', 'risk-analysis') { $d.PSObject.Properties[$e] | Should -Not -BeNullOrEmpty -Because $e }
        @($d.'risk-analysis'.PSObject.Properties).Count | Should -Be 25
        $d.'risk-analysis'.AutoBucketMax | Should -Be 131072
    }
}

# ======================================================================================================================
Describe 'the status reports: one notice, once; on by default for every install (operator decision)' {
    It 'shown once while the reports are on, with what is sent and how to turn them off' {
        $store = @{ Kind = 'memory'; Box = @{} }
        $one = @(Invoke-SIFirstRunNotices -Hosting vm -Engine 'endpoint' -Store $store -TelemetryOn $true 6>&1)
        $txt = ($one | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { [string]$_ }) -join "`n"
        $txt | Should -Match 'one a day \(version, edition, how it is hosted, licence state\)'
        $txt | Should -Match 'anonymously, with a random installation id: no tenant, no host name, no error text'
        $txt | Should -Match ([regex]::Escape('set $global:SI_Telemetry_Enabled = $false in config\SecurityInsight.custom.ps1'))
        $txt | Should -Not -Match '#\d+'
        $two = @(Invoke-SIFirstRunNotices -Hosting vm -Engine 'endpoint' -Store $store -TelemetryOn $true 6>&1)
        (($two | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }) -join "`n") | Should -Not -Match 'status reports'
    }
    It 'NEGATIVE: reports turned off -> no notice' {
        $store = @{ Kind = 'memory'; Box = @{} }
        $o = @(Invoke-SIFirstRunNotices -Hosting vm -Engine 'endpoint' -Store $store -TelemetryOn $false 6>&1)
        (($o | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }) -join "`n") | Should -Not -Match 'status reports'
    }
    It 'the reports stay ON for an upgraded install when nothing is set (no separate default for upgraded installs)' {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
        $keep = $global:SI_InstallOrigin
        try {
            $global:SI_InstallOrigin = 'upgraded'
            Test-SITelemetryEnabled -Value $null -EnvValue '' | Should -BeTrue
            Test-SITelemetryEnabled -Value $false -EnvValue '' | Should -BeFalse
        } finally { $global:SI_InstallOrigin = $keep }
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-FirstRun.ps1')) | Should -Not -Match 'DefaultForUpgradedInstalls'
    }
    It 'no customer-facing text carries a tracking number or an internal term' {
        $all = @(Get-SIUpgradeNoticeLines -Hosting vm -WhatIfConfigIgnored $true) + @(Get-SIUpgradeNoticeLines -Hosting container) +
               @(Get-SITelemetryNoticeLines -Hosting vm) + @(Get-SITelemetryNoticeLines -Hosting container) +
               @(Get-SIConfigDryRunIgnoredText -Hosting vm) + @(Get-SIConfigDryRunIgnoredText -Hosting container) +
               @(Get-SIDryRunNoticeText -Moment Start) + @(Get-SIDryRunNoticeText -Moment End)
        foreach ($l in $all) { $l | Should -Not -Match '#\d+|\b(L[0-9]|G[0-9]+|R[0-9])\b|audit|lane' }
    }
}
