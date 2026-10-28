#Requires -Version 5.1
<#
    SAFE DEFAULTS ON EVERY ENTRY POINT (operator decision 2026-10-07, wizard: "Engine: report-only", "Internal launcher:
    report-only", "Server setup: managed identity"). SIv3-CommunityDefaults covers the Community launcher, the wizard and
    Bootstrap; this suite covers the rest:

      1. The asset-tagging ENGINE started directly (engine\asset-tagging\AssetTagging.ps1, no launcher) is report only
         unless told to write: -Apply, or $global:SI_AssetTagging_Apply = $true. -WhatIfMode wins; a WhatIfMode = $false
         never writes. A host that has decided (launcher, container job) passes -RunMode report|write.
      2. The AutomateIT framework launcher (launcher\asset-tagging\launcher.internal-vm.ps1) -- which WROTE tags on every
         run without -WhatIfMode up to 2.2 -- is report only by default, with the same switches and the same one-time
         notice saying how to switch writing back on.
      3. The server sign-in decision (setup\_shared\SI-ServerSignIn.ps1; the phased v2 server setup is retired in v3) offers a MANAGED IDENTITY first (Azure VM: a
         user-assigned identity created, attached to the VM and granted, as the wizard does; Arc: its own), then a
         certificate, then a secret; outside Azure it says a managed identity is not possible and offers a certificate
         first. An existing install keeps its sign-in. The unattended setup takes the same default when its JSON names
         no sign-in.

    The REAL engine and the REAL internal launcher run in a child process of the current shell (run the suite on
    powershell.exe AND pwsh) against a fake install whose Azure / Graph helpers are stubs -- nothing leaves the machine.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Exe    = [Diagnostics.Process]::GetCurrentProcess().Path
    . (Join-Path $script:SIRoot 'engine\_shared\SI-FirstRun.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-tagging\AssetTagging.Resolve.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupNaming.ps1')
    . (Join-Path $script:SIRoot 'setup\ConfigWizard\backend\SI-WizardSignIn.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-ServerSignIn.ps1')
    . (Join-Path $script:SIRoot 'auth\SI-AuthMethod.ps1')
    function script:Get-Code([string]$Rel) { [System.IO.File]::ReadAllText((Join-Path $script:SIRoot $Rel)) }
    function script:Count-Match([string[]]$Lines, [string]$Re) { @($Lines | Where-Object { $_ -match $Re }).Count }
    function script:New-TempDir([string]$Prefix) {
        $d = Join-Path ([IO.Path]::GetTempPath()) ($Prefix + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force $d | Out-Null
        $script:Roots.Add($d); $d
    }
    $script:Roots = New-Object System.Collections.Generic.List[string]

    # ---- 1. the REAL engine, its Azure / Graph / run-health helpers stubbed; the run stops right after the mode decision
    function script:New-EngineInstall {
        $root = New-TempDir 'siate-'
        foreach ($d in 'engine\_shared', 'engine\asset-tagging\_shared', 'rules') { New-Item -ItemType Directory -Force (Join-Path $root $d) | Out-Null }
        Copy-Item -LiteralPath (Join-Path $script:SIRoot 'engine\asset-tagging\AssetTagging.ps1') -Destination (Join-Path $root 'engine\asset-tagging')
        Copy-Item -LiteralPath (Join-Path $script:SIRoot 'engine\asset-tagging\AssetTagging.Resolve.ps1') -Destination (Join-Path $root 'engine\asset-tagging')
        $u = [Text.UTF8Encoding]::new($true)
        [IO.File]::WriteAllText((Join-Path $root 'engine\_shared\SI-AzRest.ps1'), "function Invoke-SIArm { throw 'no Azure in this test' }`r`n", $u)
        foreach ($f in 'engine\_shared\SI-Yaml.ps1', 'engine\_shared\SI-GraphRest.ps1', 'engine\asset-tagging\_shared\AT-GraphRest.ps1', 'engine\asset-tagging\_shared\AT-Activity.ps1') {
            [IO.File]::WriteAllText((Join-Path $root $f), "# stub`r`n", $u)
        }
        # the first thing the run body does: stop here -- the mode is decided by then
        [IO.File]::WriteAllText((Join-Path $root 'engine\_shared\SI-RunHealthScope.ps1'), "function Start-SIRunHealth { throw 'STOP-AFTER-MODE' }`r`n", $u)
        $root
    }
    function script:Invoke-Engine {
        param([string]$Root, [string]$Switches = '', [string]$Globals = '')
        $out = Join-Path $Root ('out-' + [guid]::NewGuid().ToString('N') + '.txt')
        $e = Join-Path $Root 'engine\asset-tagging\AssetTagging.ps1'
        $cmd = "`$global:SI_UseManagedIdentity = `$true; `$global:SettingsPath = '$(Join-Path $Root 'rules')'; $Globals; " +
               "`$o = & { try { & '$e' $Switches } catch { 'STOPPED: ' + `$_.Exception.Message } } *>&1 | ForEach-Object { [string]`$_ }; " +
               "@(`$o) + ('WHATIF=' + [bool]`$global:WhatIfMode) | Set-Content -LiteralPath '$out' -Encoding UTF8"
        & $script:Exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $cmd | Out-Null
        $lines = @(Get-Content -LiteralPath $out -Encoding UTF8 -ErrorAction SilentlyContinue)
        [pscustomobject]@{ Lines = $lines; Saw = [string]($lines | Where-Object { $_ -like 'WHATIF=*' } | Select-Object -Last 1) }
    }

    # ---- 2. the REAL AutomateIT framework launcher, in a monorepo-shaped fake install, with a STUB engine
    function script:New-InternalInstall {
        param([string]$Custom = '', [switch]$EarlierTaggingRun)
        $repo = New-TempDir 'siint-'
        $si = Join-Path $repo 'SOLUTIONS\SecurityInsight'
        foreach ($d in 'launcher\_lib', 'launcher\asset-tagging', 'engine\_shared', 'engine\asset-tagging', 'auth', 'config', 'logs') {
            New-Item -ItemType Directory -Force (Join-Path $si $d) | Out-Null
        }
        Copy-Item -Path (Join-Path $script:SIRoot 'launcher\_lib\*') -Destination (Join-Path $si 'launcher\_lib') -Recurse -Force
        Copy-Item -Path (Join-Path $script:SIRoot 'launcher\asset-tagging\*') -Destination (Join-Path $si 'launcher\asset-tagging') -Recurse -Force
        Copy-Item -Path (Join-Path $script:SIRoot 'engine\_shared\*') -Destination (Join-Path $si 'engine\_shared') -Recurse -Force
        Copy-Item -Path (Join-Path $script:SIRoot 'auth\*') -Destination (Join-Path $si 'auth') -Recurse -Force
        Copy-Item -LiteralPath (Join-Path $script:SIRoot 'engine\asset-tagging\AssetTagging.Resolve.ps1') -Destination (Join-Path $si 'engine\asset-tagging')
        Copy-Item -LiteralPath (Join-Path $script:SIRoot 'VERSION') -Destination $si
        # the stub engine records what it was told: the global AND the -RunMode the launcher passes
        [IO.File]::WriteAllText((Join-Path $si 'engine\asset-tagging\AssetTagging.ps1'),
            "param([string]`$RunMode = '')`r`nSet-Content -LiteralPath (Join-Path `$PSScriptRoot 'engine-saw.txt') -Value ('WHATIF=' + [bool]`$global:WhatIfMode + ' RUNMODE=' + `$RunMode) -Encoding UTF8`r`n",
            [Text.UTF8Encoding]::new($true))
        $cfg = "`$global:SI_Telemetry_Enabled = `$false`r`n" + $Custom
        [IO.File]::WriteAllText((Join-Path $si 'config\SecurityInsight.custom.ps1'), $cfg, [Text.UTF8Encoding]::new($true))
        if ($EarlierTaggingRun) {
            $f = Join-Path $si 'logs\asset-tagging_internal-vm_20260901T020000Z.log'
            Set-Content -LiteralPath $f -Value 'a 2.2 run that wrote tags' -Encoding UTF8
            (Get-Item -LiteralPath $f).LastWriteTime = (Get-Date).AddDays(-2)
        }
        [pscustomobject]@{ Repo = $repo; SI = $si }
    }
    function script:Invoke-Internal {
        param($Install, [string]$Switches = '')
        $out = Join-Path $Install.Repo ('out-' + [guid]::NewGuid().ToString('N') + '.txt')
        $l = Join-Path $Install.SI 'launcher\asset-tagging\launcher.internal-vm.ps1'
        # SI_PLATFORM_CONFIG=off: never this machine's platform sign-in
        $cmd = "`$env:SI_PLATFORM_CONFIG = 'off'; `$ErrorActionPreference = 'Stop'; & '$l' -InstallPath '$($Install.Repo)' $Switches *>&1 | ForEach-Object { [string]`$_ } | Set-Content -LiteralPath '$out' -Encoding UTF8"
        & $script:Exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $cmd | Out-Null
        $saw = Join-Path $Install.SI 'engine\asset-tagging\engine-saw.txt'
        $r = [pscustomobject]@{ Lines = @(Get-Content -LiteralPath $out -Encoding UTF8 -ErrorAction SilentlyContinue); Saw = $(if (Test-Path -LiteralPath $saw) { (Get-Content -Raw -LiteralPath $saw).Trim() } else { '' }) }
        Remove-Item -LiteralPath $saw -Force -ErrorAction SilentlyContinue
        $r
    }
    $script:NowReportOnlyRe = 'Asset tagging is now REPORT ONLY by default'
    $script:FreshNoticeRe   = 'Asset tagging is REPORT ONLY by default'

    function script:Write-Info($m) { $script:Said.Add("INFO $m") }
    function script:Write-Warn2($m) { $script:Said.Add("WARN $m") }
    function script:Write-Ok($m) { $script:Said.Add("OK $m") }
    function script:Write-Phase($n, $d) { }
    $script:Said = New-Object System.Collections.Generic.List[string]
}

AfterAll {
    foreach ($r in $script:Roots) { Remove-Item -Recurse -Force -LiteralPath $r -ErrorAction SilentlyContinue }
    Remove-Variable -Name SDCalls, SDn -Scope Global -ErrorAction SilentlyContinue
}

# ======================================================================================================================
Describe 'the asset-tagging ENGINE started directly is report only unless told to write (real engine, child process)' {
    BeforeAll { $script:Eng = New-EngineInstall }
    It 'nothing asked for = REPORT ONLY, and it says how to write' {
        $r = Invoke-Engine -Root $script:Eng
        $r.Saw | Should -Be 'WHATIF=True' -Because ($r.Lines -join [Environment]::NewLine)
        Count-Match $r.Lines 'REPORT ONLY -- nothing is changed.*-Apply.*SI_AssetTagging_Apply' | Should -Be 1
        Count-Match $r.Lines 'STOP-AFTER-MODE' | Should -Be 1 -Because 'the run reached the run body (the stub stops it there)'
    }
    It 'a $global:WhatIfMode = $false (the old default, left in a session or a wrapper) does NOT write' {
        (Invoke-Engine -Root $script:Eng -Globals '$global:WhatIfMode = $false').Saw | Should -Be 'WHATIF=True'
    }
    It '-Apply writes; SI_AssetTagging_Apply = $true writes; -WhatIfMode wins over both; WhatIfMode = $true in the config wins over the setting' {
        $a = Invoke-Engine -Root $script:Eng -Switches '-Apply' -Globals '$global:SI_AssetTagging_Enabled = $true'
        $a.Saw | Should -Be 'WHATIF=False'
        Count-Match $a.Lines 'WRITES ON' | Should -Be 1
        (Invoke-Engine -Root $script:Eng -Globals '$global:SI_AssetTagging_Enabled = $true; $global:SI_AssetTagging_Apply = $true').Saw | Should -Be 'WHATIF=False'
        # #643 asset tagging off (the shipped default): neither -Apply nor the setting writes
        (Invoke-Engine -Root $script:Eng -Switches '-Apply').Saw | Should -Be 'WHATIF=True'
        (Invoke-Engine -Root $script:Eng -Globals '$global:SI_AssetTagging_Apply = $true').Saw | Should -Be 'WHATIF=True'
        (Invoke-Engine -Root $script:Eng -Switches '-Apply -WhatIfMode').Saw | Should -Be 'WHATIF=True'
        (Invoke-Engine -Root $script:Eng -Switches '-WhatIfMode' -Globals '$global:SI_AssetTagging_Apply = $true').Saw | Should -Be 'WHATIF=True'
        (Invoke-Engine -Root $script:Eng -Globals '$global:SI_AssetTagging_Apply = $true; $global:WhatIfMode = $true').Saw | Should -Be 'WHATIF=True'
    }
    It 'a host''s decision (-RunMode) is final: report stays report even with the setting on; write writes' {
        (Invoke-Engine -Root $script:Eng -Switches '-RunMode report' -Globals '$global:SI_AssetTagging_Apply = $true').Saw | Should -Be 'WHATIF=True'
        (Invoke-Engine -Root $script:Eng -Switches '-RunMode write').Saw | Should -Be 'WHATIF=False'
        (Invoke-Engine -Root $script:Eng -Switches '-RunMode report' -Globals '$global:WhatIfMode = $false').Saw | Should -Be 'WHATIF=True'
    }
    It 'WIRING: every host passes its decision as -RunMode; the container job keeps deciding from -Apply only' {
        foreach ($rel in 'launcher\asset-tagging\launcher.community-vm.ps1', 'launcher\asset-tagging\launcher.internal-vm.ps1') {
            Get-Code $rel | Should -Match "& \`$engine -RunMode \`$\(if \(\`$tagMode\.Apply\) \{ 'write' \} else \{ 'report' \}\)" -Because $rel
        }
        $j = Get-Code 'engine\asset-tagging\Invoke-SIAssetTaggingJob.ps1'
        $j | Should -Match "AssetTagging\.ps1'\)\) -RunMode \`$\(if \(\`$Apply\) \{ 'write' \} else \{ 'report' \}\)"
        $j | Should -Match '\$global:WhatIfMode = -not \[bool\]\$Apply'
        $c = Get-Code 'engine\asset-tagging\AssetTagging.ps1'
        $c | Should -Match 'Resolve-SIAssetTaggingRunMode -ApplySwitch \$script:ATApplySwitch -WhatIfSwitch \$script:ATWhatIfSwitch'
        # the old "writes unless told otherwise" default is gone from the engine
        $c | Should -Not -Match "if \(\`$null -eq \`$global:WhatIfMode\) \{ \`$global:WhatIfMode = \`$false \}"
    }
}

# ======================================================================================================================
Describe 'the AutomateIT framework launcher (launcher.internal-vm.ps1) is report only by default (real launcher, child process)' {
    It 'DEFAULT: report only (the engine is told so); an install that wrote tags before is told ONCE how to switch writing back on' {
        $i = New-InternalInstall -EarlierTaggingRun
        $one = Invoke-Internal -Install $i
        $one.Saw | Should -Be 'WHATIF=True RUNMODE=report' -Because ($one.Lines -join [Environment]::NewLine)
        Count-Match $one.Lines $script:NowReportOnlyRe | Should -Be 1
        Count-Match $one.Lines 'SI_AssetTagging_Apply = \$true' | Should -BeGreaterThan 0
        Count-Match $one.Lines 'add -Apply' | Should -BeGreaterThan 0
        $st = Get-Content -Raw -LiteralPath (Join-Path $i.SI 'logs\state\install-state.json') | ConvertFrom-Json
        @($st.Shown) | Should -Contain 'asset-tagging-report-only'
        $two = Invoke-Internal -Install $i
        $two.Saw | Should -Be 'WHATIF=True RUNMODE=report'
        Count-Match $two.Lines $script:NowReportOnlyRe | Should -Be 0
    }
    It '-Apply writes; -Apply -WhatIfMode does not; -WhatIfMode alone still works' {
        $i = New-InternalInstall -Custom "`$global:SI_AssetTagging_Enabled = `$true`r`n"
        (Invoke-Internal -Install $i -Switches '-Apply').Saw | Should -Be 'WHATIF=False RUNMODE=write'
        (Invoke-Internal -Install (New-InternalInstall) -Switches '-Apply').Saw | Should -Be 'WHATIF=True RUNMODE=report' -Because '#643: asset tagging is off by default'
        (Invoke-Internal -Install $i -Switches '-Apply -WhatIfMode').Saw | Should -Be 'WHATIF=True RUNMODE=report'
        (Invoke-Internal -Install $i -Switches '-WhatIfMode').Saw | Should -Be 'WHATIF=True RUNMODE=report'
    }
    It 'SI_AssetTagging_Apply = $true in the config writes (no notice); WhatIfMode = $false in the config does not' {
        $i = New-InternalInstall -Custom "`$global:SI_AssetTagging_Enabled = `$true`r`n`$global:SI_AssetTagging_Apply = `$true`r`n" -EarlierTaggingRun
        $r = Invoke-Internal -Install $i
        $r.Saw | Should -Be 'WHATIF=False RUNMODE=write'
        Count-Match $r.Lines $script:NowReportOnlyRe | Should -Be 0
        $i2 = New-InternalInstall -Custom "`$global:WhatIfMode = `$false`r`n"
        (Invoke-Internal -Install $i2).Saw | Should -Be 'WHATIF=True RUNMODE=report'
    }
    It 'WIRING: the same switches and resolver as the Community launcher; the old default is gone' {
        $c = Get-Code 'launcher\asset-tagging\launcher.internal-vm.ps1'
        $c | Should -Match '\[switch\]\$Apply'
        $c | Should -Match "Resolve-SIAssetTaggingRunMode -ApplySwitch \(\`$PSBoundParameters\.ContainsKey\('Apply'\)"
        $c | Should -Match 'Invoke-SIAssetTaggingReportOnlyNotice -Mode \$tagMode'
        $c | Should -Not -Match "elseif \(\`$null -eq \`$global:WhatIfMode\) \{ \`$global:WhatIfMode = \`$false \}"
    }
    It 'RELEASENOTES says it plainly in the upgrade section: the framework launcher changes behaviour, and how to write again' {
        $n = Get-Code 'RELEASENOTES.md'
        $n | Should -Match '(?s)6b\. \*\*Asset tagging.{0,400}launcher\.internal-vm\.ps1.{0,400}This changes\s+what an existing scheduled task does'
        $n | Should -Match '(?s)6b\..{0,1200}SI_AssetTagging_Apply = \$true.{0,200}-Apply'
    }
}

# ======================================================================================================================
Describe 'server setup: the sign-in decision (pure)' {
    It 'nothing asked: Azure VM = a user-assigned managed identity, Arc = its own, outside Azure = a certificate (and why)' {
        $v = Resolve-SIServerSignIn -HostKind AzureVm
        $v.Method | Should -Be 'ManagedIdentity'; $v.Identity | Should -Be 'user-assigned'; $v.DefaultUsed | Should -BeTrue
        @($v.Offer) | Should -Be @('ManagedIdentity', 'Certificate', 'Secret')
        (Resolve-SIServerSignIn -HostKind Arc).Identity | Should -Be 'system-assigned'
        $o = Resolve-SIServerSignIn -HostKind Outside
        $o.Method | Should -Be 'Certificate'; $o.Note | Should -Match 'cannot have a managed identity'
        @($o.Offer) | Should -Be @('Certificate', 'Secret')
    }
    It 'a choice wins; a managed identity outside Azure is refused; a secret stays a supported choice' {
        (Resolve-SIServerSignIn -HostKind AzureVm -Choice Secret).Method | Should -Be 'Secret'
        (Resolve-SIServerSignIn -HostKind Outside -Choice Secret).Method | Should -Be 'Secret'
        (Resolve-SIServerSignIn -HostKind AzureVm -Choice Cert).Method | Should -Be 'Certificate'
        { Resolve-SIServerSignIn -HostKind Outside -Choice ManagedIdentity } | Should -Throw '*cannot have a managed identity*'
        { Resolve-SIServerSignIn -Choice Password } | Should -Throw
    }
    It 'a certificate / secret given on the run is used; an upgrade keeps what the install has' {
        (Resolve-SIServerSignIn -HostKind AzureVm -HasCertificateInput $true).Method | Should -Be 'Certificate'
        (Resolve-SIServerSignIn -HostKind AzureVm -HasSecretInput $true).Method | Should -Be 'Secret'
        $k = Resolve-SIServerSignIn -HostKind AzureVm -ExistingMethod Secret
        $k.Method | Should -Be 'Secret'; $k.Source | Should -Be 'existing'
        (Resolve-SIServerSignIn -HostKind Outside -ExistingMethod ManagedIdentity).Method | Should -Be 'ManagedIdentity'
    }
    It 'the question: managed identity first and ENTER takes the recommended one; a number or a name picks; nonsense is refused' {
        $v = Resolve-SIServerSignIn -HostKind AzureVm
        $menu = @(Get-SIServerSignInMenu -Decision $v)
        $menu[1] | Should -Match '1\) Managed identity \(recommended\).*\[ENTER\]'
        Select-SIServerSignIn -Decision $v -Answer '' | Should -Be 'ManagedIdentity'
        Select-SIServerSignIn -Decision $v -Answer '2' | Should -Be 'Certificate'
        Select-SIServerSignIn -Decision $v -Answer 'secret' | Should -Be 'Secret'
        { Select-SIServerSignIn -Decision $v -Answer '7' } | Should -Throw
        $o = Resolve-SIServerSignIn -HostKind Outside
        @(Get-SIServerSignInMenu -Decision $o)[1] | Should -Match '1\) Service principal with a certificate \(recommended here\).*\[ENTER\]'
        { Select-SIServerSignIn -Decision $o -Answer 'ManagedIdentity' } | Should -Throw '*cannot have a managed identity*'
    }
    It 'where this server runs: the Arc agent''s variables, the Azure metadata answer, or neither' {
        $env1 = @{ IDENTITY_ENDPOINT = 'http://localhost:40342/metadata/identity/oauth2/token'; IMDS_ENDPOINT = 'http://localhost:40342'; COMPUTERNAME = 'ARC01' }
        $a = Get-SIServerAzureHost -GetEnv { param($n) $env1[$n] } -Imds { throw 'not asked' }
        $a.Kind | Should -Be 'Arc'; $a.VmName | Should -Be 'ARC01'
        $vm = Get-SIServerAzureHost -GetEnv { param($n) $null } -Imds { [pscustomobject]@{ name = 'vm-si'; resourceGroupName = 'rg-vm'; subscriptionId = 'sub-9'; location = 'westeurope' } }
        $vm.Kind | Should -Be 'AzureVm'; $vm.VmName | Should -Be 'vm-si'; $vm.ResourceGroupName | Should -Be 'rg-vm'; $vm.SubscriptionId | Should -Be 'sub-9'
        (Get-SIServerAzureHost -GetEnv { param($n) $null } -Imds { throw 'timeout' }).Kind | Should -Be 'Outside'
        (Get-SIServerAzureHost -GetEnv { param($n) $null } -Imds { $null }).Kind | Should -Be 'Outside'
    }
    It 'the AUTH block says the sign-in explicitly, parses, and carries no secret for a managed identity or a certificate' {
        foreach ($case in @(
            @{ M = 'ManagedIdentity'; Must = @("SI_AuthMethod\s+= 'ManagedIdentity'", "SI_ManagedIdentityClientId = 'cid-1'", "SI_SPN_ObjectId = 'pid-1'"); MustNot = @('SI_SPN_AppId', 'SI_SPN_Secret') }
            @{ M = 'Certificate'; Must = @("SI_AuthMethod\s+= 'Certificate'", "SI_SPN_AppId\s+= 'app-1'", "SI_SPN_CertThumbprint = 'ABC123'"); MustNot = @('SI_SPN_Secret\s+=') }
            @{ M = 'Secret'; Must = @("SI_AuthMethod\s+= 'Secret'", "SI_SPN_Secret\s+= 'the-secret'"); MustNot = @('CertThumbprint') }
        )) {
            $t = (Get-SIServerSignInConfigLines -Method $case.M -TenantId 'ten' -AppId 'app-1' -CertificateThumbprint 'ABC123' -Secret 'the-secret' -ManagedIdentityClientId 'cid-1' -PrincipalId 'pid-1') -join "`n"
            $e = $null; $null = [System.Management.Automation.Language.Parser]::ParseInput($t, [ref]$null, [ref]$e); @($e).Count | Should -Be 0
            foreach ($m in $case.Must) { $t | Should -Match $m -Because $case.M }
            foreach ($m in $case.MustNot) { $t | Should -Not -Match $m -Because $case.M }
            $g = @{}; foreach ($l in ($t -split "`n")) { if ($l -match '^\$global:(\w+)\s*=\s*''([^'']*)''') { $g[$Matches[1]] = $Matches[2] } }
            (Resolve-SIAuthMethod -Globals $g).Mode | Should -Be $case.M -Because 'every engine reads the block the same way'
        }
        $kv = (Get-SIServerSignInConfigLines -Method Secret -TenantId 't' -AppId 'a' -KeyVaultName 'kv-si') -join "`n"
        $kv | Should -Match "SpnKeyVaultName = 'kv-si'"; $kv | Should -Match "SpnSecretName   = 'SecurityInsight-Secret'"; $kv | Should -Not -Match "SI_SPN_Secret\s+= '"
    }
    It 'the unattended JSON: no CredKind = the same default; a container install = the jobs'' identity; Cert / Secret stay' {
        (Resolve-SIUnattendedSignIn -HostKind AzureVm).CredKind | Should -Be 'ManagedIdentity'
        (Resolve-SIUnattendedSignIn -HostKind AzureVm).Identity | Should -Be 'user-assigned'
        (Resolve-SIUnattendedSignIn -ContainerEnabled $true).Identity | Should -Be 'container-jobs'
        $o = Resolve-SIUnattendedSignIn -HostKind Outside
        $o.CredKind | Should -Be 'Cert'; $o.CredStorage | Should -Be 'LocalCertStore'; $o.DefaultUsed | Should -BeTrue
        (Resolve-SIUnattendedSignIn -CredKind Secret -HostKind AzureVm).CredKind | Should -Be 'Secret'
        (Resolve-SIUnattendedSignIn -CredKind Secret -HostKind AzureVm).CredStorage | Should -Be 'Inline'
        (Resolve-SIUnattendedSignIn -CredKind Cert -CredStorage KeyVault -ContainerEnabled $true).CredStorage | Should -Be 'KeyVault'
        { Resolve-SIUnattendedSignIn -CredKind ManagedIdentity -HostKind Outside } | Should -Throw '*cannot have a managed identity*'
    }
}

Describe 'server setup: the Azure VM''s managed identity is made the wizard''s way' {
    BeforeAll {
        # the Azure calls, stubbed; dot-sourced INSIDE each It so they shadow anything loaded at file level
        $script:AzStubs = {
            function Get-SIAzResourceGroup { param($Name) $script:Calls.Add("get-rg $Name"); $null }
            function New-SIAzResourceGroup { param($Name, $Location, $Tag) $script:Calls.Add("new-rg $Name $Location") }
            function New-SIUserAssignedIdentity { param($ResourceGroupName, $Name, $Location, $SubscriptionId)
                $script:Calls.Add("new-id $Name")
                [pscustomobject]@{ Name = $Name; Id = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$Name"; ClientId = 'cid-1'; PrincipalId = 'pid-1' } }
            function Add-SIVmUserAssignedIdentity { param($ResourceGroupName, $VmName, $IdentityResourceId, $SubscriptionId) $script:Calls.Add("attach $ResourceGroupName/$VmName"); $true }
        }
    }
    BeforeEach {
        $script:Calls = New-Object System.Collections.Generic.List[string]; $global:SDCalls = $script:Calls   # the New-SISpn stub is a script file: it reaches the list through a global
        $script:SpnStub = Join-Path $TestDrive 'New-SISpn.ps1'
    }
    It 'resource group, identity, attached to the VM, granted as a managed identity (no app registration) -- in that order' {
        . $script:AzStubs
        Set-Content -LiteralPath $script:SpnStub -Value "param(`$TenantId, `$SubscriptionId, `$CredKind, `$ManagedIdentityClientId, `$DisplayName) `$global:SDCalls.Add(""grant `$CredKind `$ManagedIdentityClientId""); [pscustomobject]@{ ConsentStatus = 'granted' }"
        $r = Invoke-SIServerManagedIdentitySetup -TenantId t -SubscriptionId s -ResourceGroupName rg-si -Location westeurope -IdentityName id-si -VmName vm-si -VmResourceGroup rg-vm -NewSISpnPath $script:SpnStub -RetrySeconds 0
        @($script:Calls) | Should -Be @('get-rg rg-si', 'new-rg rg-si westeurope', 'new-id id-si', 'attach rg-vm/vm-si', 'grant ManagedIdentity cid-1')
        $r.ClientId | Should -Be 'cid-1'; $r.Attached | Should -Be 'attached'; $r.Grants | Should -Be 'ok'
    }
    It 'a new identity that Entra does not show yet is waited for; any other grant failure is final and keeps the identity' {
        . $script:AzStubs
        $global:SDn = 0
        Set-Content -LiteralPath $script:SpnStub -Value "param(`$TenantId, `$SubscriptionId, `$CredKind, `$ManagedIdentityClientId, `$DisplayName) `$global:SDn++; if (`$global:SDn -lt 3) { throw 'Managed Identity with client ID x not found' }; [pscustomobject]@{ ConsentStatus = 'granted' }"
        (Invoke-SIServerManagedIdentitySetup -TenantId t -SubscriptionId s -ResourceGroupName rg -Location l -IdentityName id -NewSISpnPath $script:SpnStub -RetrySeconds 0).Grants | Should -Be 'ok'
        $global:SDn | Should -Be 3
        Set-Content -LiteralPath $script:SpnStub -Value "param(`$TenantId, `$SubscriptionId, `$CredKind, `$ManagedIdentityClientId, `$DisplayName) `$global:SDn++; throw 'Insufficient privileges'"
        $global:SDn = 0
        $f = Invoke-SIServerManagedIdentitySetup -TenantId t -SubscriptionId s -ResourceGroupName rg -Location l -IdentityName id -NewSISpnPath $script:SpnStub -RetrySeconds 0
        $global:SDn | Should -Be 1
        $f.Grants | Should -Be 'failed'; $f.GrantError | Should -Match 'Insufficient'; $f.ClientId | Should -Be 'cid-1'; $f.Attached | Should -Be 'no'
    }
}

Describe 'the unattended server setup takes the same sign-in default' {
    It 'WIRING: the unattended setup decides the sign-in the same way (the phased v2 server setup is retired in v3)' {
        $u = Get-Code 'Setup-SecurityInsight-Unattended.ps1'
        $u | Should -Match 'Resolve-SIUnattendedSignIn -CredKind \$commKindIn'
        $u | Should -Match 'Invoke-SIServerManagedIdentitySetup -TenantId \$cfg\.Sub\.TenantId'
        $u | Should -Match "if \(\`$commSignIn -and \`$commSignIn\.Identity -eq 'container-jobs'\) \{ \`$containerArgs\.GrantIdentityRoles = \`$true \}"
        $u | Should -Match 'CredKind\s+= \$commSignIn\.CredKind'
        $j = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'config\setup-unattended.sample.json') | ConvertFrom-Json
        $j.Auth_Community.CredKind | Should -BeNullOrEmpty
        $j.Auth_Community.PSObject.Properties.Name | Should -Contain 'VmName'
    }
}