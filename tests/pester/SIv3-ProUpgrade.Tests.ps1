#Requires -Version 5.1
<#
    CONTAINER HOSTING IS FOR BOTH EDITIONS -- SI EXACTLY AS PIM (#164, operator 2026-10-02: "we must support community as
    well and we already have the same setup in pim ... only difference is the license and the features if paid or not").

    Community: Update-SecurityInsight.ps1 -Apply pulls and rolls the containers. Pro: an updater job takes what SecurityInsight
    released to the customer's ring from Invardia (SI's own feed is retired, 2026-10-06) and rolls them; setup\Upgrade-SIToPro.ps1 switches an install from the first to the
    second (PIM: Upgrade-PimToPro.ps1), and from then on the Community roll steps aside. The updater CODE ships in both
    editions (PIM ships its update job to Community too); the paid part is the Pro licence + Invardia's update platform.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-ContainerUpdate.ps1')
    function global:az { $global:AzCalls.Add((@($args) -join ' ')); $global:LASTEXITCODE = 0; '' }
    # #521: the container update reaches Azure over SecurityInsight's REST client only -- its two seams replaced here (every
    # call recorded, every answer a 404), so no test can reach a real tenant
    function global:Get-SIAzRestState { if (-not ($global:ProUpgRestState -is [hashtable])) { $global:ProUpgRestState = @{ Connection = @{ Mode = 'Fake' }; SubscriptionId = $null; TenantId = $null; Cache = @{} } }; $global:ProUpgRestState }
    function global:Invoke-SIAzRestRequest { param([string]$Method = 'GET', [string]$Uri, [string]$Audience, $Body, [string]$ContentType, [hashtable]$Headers, [switch]$AllowNotFound, [int[]]$AllowStatus, [switch]$AsBytes, [int]$TimeoutSec, [int]$MaxAttempts, [string]$What, [hashtable]$Auth)
        $global:AzCalls.Add(('{0} {1}' -f $Method, $Uri)); [pscustomobject]@{ StatusCode = 404; Content = '{"error":{"code":"NotFound","message":"fake"}}'; Headers = @{} } }
    function global:Invoke-SIAzRestHttp { param([string]$Method, [string]$Uri, [hashtable]$Headers, $Body, [string]$ContentType, [int]$TimeoutSec, [switch]$AsBytes)
        $global:AzCalls.Add(('{0} {1}' -f $Method, $Uri)); [pscustomobject]@{ StatusCode = 404; Content = ''; Headers = @{} } }
    $script:Names = 'SI_Bootstrap_SubscriptionId', 'SI_Bootstrap_ResourceGroupName', 'SI_Bootstrap_AcrName', 'SI_Bootstrap_EnvName',
                    'SI_Bootstrap_Location', 'SI_Bootstrap_UpdaterJob', 'SI_SPN_AppId', 'SI_SPN_TenantId', 'SI_KeyVaultName', 'SpnKeyVaultName', 'SI_WorkspaceResourceId'
    function script:Clear-ConfigGlobals { foreach ($n in $script:Names) { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue } }
    # A throwaway install: the real setup scripts + a stub Install-SIUpdaterJob.ps1 that records what it was given.
    function script:New-Install([string]$Config, [switch]$InstallFails) {
        $d = Join-Path ([IO.Path]::GetTempPath()) ('sipro-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force (Join-Path $d 'setup\_shared'), (Join-Path $d 'config') | Out-Null
        foreach ($f in 'setup\Upgrade-SIToPro.ps1', 'setup\Invoke-SIContainerUpdate.ps1', 'setup\_shared\SI-ContainerUpdate.ps1', 'setup\_shared\SI-BuildStage.ps1', 'setup\_shared\SI-FastRoll.ps1', 'setup\_shared\SI-ScriptRun.ps1',
                       'setup\_shared\SI-UpdateRest.ps1', 'setup\_shared\SI-AcrBuild.ps1', 'VERSION') {
            Copy-Item (Join-Path $script:SIRoot $f) (Join-Path $d $f)
        }
        $stub = 'param([string]$SubscriptionId,[string]$ResourceGroupName,[string]$AcrName,[string]$EnvName,[string]$KeyVaultName,[string]$CertSecretName,[string]$SpnClientId,[string]$TenantId,[string]$JobName,[int]$UpdateRing = -1,[switch]$UseManagedIdentity,[switch]$GrantSpnRoles,[switch]$Apply)' + "`r`n" +
                '$global:InstallCall = @{} + $PSBoundParameters' + "`r`n" + $(if ($InstallFails) { "throw 'the registry refused the build'" } else { '' })
        Set-Content -LiteralPath (Join-Path $d 'setup\Install-SIUpdaterJob.ps1') -Value $stub -Encoding ASCII
        if ($Config) { [IO.File]::WriteAllText((Join-Path $d 'config\SecurityInsight.custom.ps1'), $Config, [Text.UTF8Encoding]::new($true)) }
        $d
    }
    $script:Block = Get-SIContainerHostingBlock -SubscriptionId 'sub-1' -ResourceGroupName 'rg-x' -AcrName 'acrx' -EnvName 'cae-si' -Location 'westeurope'
    $script:Identity = "`$global:SI_SPN_AppId = 'app-1'`r`n`$global:SI_SPN_TenantId = 'ten-1'`r`n`$global:SI_KeyVaultName = 'kv-1'`r`n"
}
AfterAll {
    foreach ($f in 'az', 'Get-SIAzRestState', 'Invoke-SIAzRestRequest', 'Invoke-SIAzRestHttp') { Remove-Item -LiteralPath ("Function:\{0}" -f $f) -ErrorAction SilentlyContinue }
    Clear-ConfigGlobals; Remove-Variable InstallCall, AzCalls, ProUpgRestState -Scope Global -ErrorAction SilentlyContinue
}

Describe 'the saved hosting block carries who owns the rollout' {
    It 'a value reads back exactly (a quote included); absent is empty' {
        $b = Get-SIContainerHostingBlock -SubscriptionId 's' -ResourceGroupName 'r' -AcrName 'a' -UpdaterJob ("caj-o" + [char]0x27 + "x")
        Get-SIContainerHostingValue -Text $b -Name 'SI_Bootstrap_UpdaterJob' | Should -BeExactly ("caj-o" + [char]0x27 + "x")
        Get-SIContainerHostingValue -Text $script:Block -Name 'SI_Bootstrap_UpdaterJob' | Should -BeExactly ''
    }
    It '🔴 a re-run of container setup KEEPS the updater job -- it never hands a Pro install back to the Community update' {
        $f = Join-Path $TestDrive 'keep.ps1'
        Save-SIContainerHostingConfig -ConfigPath $f -SubscriptionId 'sub-1' -ResourceGroupName 'rg-x' -AcrName 'acrx' -UpdaterJob 'caj-si-updater' | Out-Null
        Save-SIContainerHostingConfig -ConfigPath $f -SubscriptionId 'sub-1' -ResourceGroupName 'rg-x' -AcrName 'acrx' -EnvName 'cae-2' | Out-Null
        $t = [IO.File]::ReadAllText($f)
        Get-SIContainerHostingValue -Text $t -Name 'SI_Bootstrap_UpdaterJob' | Should -Be 'caj-si-updater'
        Get-SIContainerHostingValue -Text $t -Name 'SI_Bootstrap_EnvName' | Should -Be 'cae-2'
    }
    It 'only an explicit value changes it' {
        $f = Join-Path $TestDrive 'clear.ps1'
        Save-SIContainerHostingConfig -ConfigPath $f -SubscriptionId 's' -ResourceGroupName 'r' -AcrName 'a' -UpdaterJob 'caj-si-updater' | Out-Null
        Save-SIContainerHostingConfig -ConfigPath $f -SubscriptionId 's' -ResourceGroupName 'r' -AcrName 'a' -UpdaterJob '' | Out-Null
        Get-SIContainerHostingValue -Text ([IO.File]::ReadAllText($f)) -Name 'SI_Bootstrap_UpdaterJob' | Should -Be ''
    }
    It 'managed = the job is named; nothing or blank = the Community update' {
        Get-SIUpdaterManagedJob -Globals @{ SI_Bootstrap_UpdaterJob = ' caj-si-updater ' } | Should -Be 'caj-si-updater'
        Get-SIUpdaterManagedJob -Globals @{ SI_Bootstrap_UpdaterJob = ' ' } | Should -BeNullOrEmpty
        Get-SIUpdaterManagedJob | Should -BeNullOrEmpty
    }
}

Describe 'the upgrade plan: saved values, nothing guessed' {
    It 'takes the saved hosting and identity; explicit values win; the vault falls back to the older name' {
        $g = @{ SI_Bootstrap_SubscriptionId = 'sub-1'; SI_Bootstrap_ResourceGroupName = 'rg-x'; SI_Bootstrap_AcrName = 'acrx'; SI_Bootstrap_EnvName = 'cae-si'
                SpnKeyVaultName = 'kv-old'; SI_SPN_AppId = 'app-1'; SI_SPN_TenantId = 'ten-1' }
        $p = Get-SIProUpgradePlan -Globals $g -CertSecretName 'cert' -EnvName 'cae-override'
        @($p.Missing).Count | Should -Be 0
        $p.Args.KeyVaultName | Should -Be 'kv-old'; $p.Args.EnvName | Should -Be 'cae-override'; $p.Args.SpnClientId | Should -Be 'app-1'
        @($p.Args.Keys) | Should -Be @('SubscriptionId', 'ResourceGroupName', 'AcrName', 'EnvName', 'KeyVaultName', 'CertSecretName', 'SpnClientId', 'TenantId')
    }
    It 'a missing value is NAMED, never invented; the subscription can come from the workspace id' {
        $p = Get-SIProUpgradePlan -Globals @{ SI_Bootstrap_ResourceGroupName = 'rg-x'; SI_Bootstrap_AcrName = 'acrx'; SI_WorkspaceResourceId = '/subscriptions/ws-sub/resourceGroups/r/x' } -CertSecretName 'cert'
        $p.Args.SubscriptionId | Should -Be 'ws-sub'
        @($p.Missing | Sort-Object) | Should -Be @('EnvName', 'KeyVaultName', 'SpnClientId', 'TenantId')
    }
}

Describe 'Upgrade-SIToPro.ps1, end to end on a throwaway install' {
    AfterEach { Clear-ConfigGlobals; Remove-Variable InstallCall -Scope Global -ErrorAction SilentlyContinue }
    It 'without -Apply: the plan only -- the installer is not called and the config is untouched' {
        $d = New-Install ($script:Identity + $script:Block + "`r`n")
        try {
            $before = [IO.File]::ReadAllText((Join-Path $d 'config\SecurityInsight.custom.ps1'))
            $out = & (Join-Path $d 'setup\Upgrade-SIToPro.ps1') -CertSecretName 'cert' *>&1 | Out-String
            $out | Should -Match 'nothing changed'
            $global:InstallCall | Should -BeNullOrEmpty
            [IO.File]::ReadAllText((Join-Path $d 'config\SecurityInsight.custom.ps1')) | Should -BeExactly $before
        } finally { Remove-Item -Recurse -Force $d }
    }
    It '-Apply: installs the job with the SAVED hosting + identity, then records it as the owner of the rollout' {
        $d = New-Install ($script:Identity + $script:Block + "`r`n")
        try {
            & (Join-Path $d 'setup\Upgrade-SIToPro.ps1') -CertSecretName 'cert' -Apply *>&1 | Out-Null
            $c = $global:InstallCall
            $c.SubscriptionId | Should -Be 'sub-1'; $c.ResourceGroupName | Should -Be 'rg-x'; $c.AcrName | Should -Be 'acrx'; $c.EnvName | Should -Be 'cae-si'
            $c.KeyVaultName | Should -Be 'kv-1'; $c.SpnClientId | Should -Be 'app-1'; $c.TenantId | Should -Be 'ten-1'
            $c.ContainsKey('SourceUrlSecretName') | Should -BeFalse; $c.CertSecretName | Should -Be 'cert'; $c.JobName | Should -Be 'caj-si-updater'; [bool]$c.Apply | Should -BeTrue
            $t = [IO.File]::ReadAllText((Join-Path $d 'config\SecurityInsight.custom.ps1'))
            Get-SIContainerHostingValue -Text $t -Name 'SI_Bootstrap_UpdaterJob' | Should -Be 'caj-si-updater'
            Get-SIContainerHostingValue -Text $t -Name 'SI_Bootstrap_Location' | Should -Be 'westeurope'
            $t | Should -Match ([regex]::Escape("`$global:SI_KeyVaultName = 'kv-1'"))
        } finally { Remove-Item -Recurse -Force $d }
    }
    It '-UseManagedIdentity -UpdateRing 3: no certificate or SPN asked for; the job gets its ring' {
        $d = New-Install ($script:Identity + $script:Block + "`r`n")
        try {
            & (Join-Path $d 'setup\Upgrade-SIToPro.ps1') -UseManagedIdentity -UpdateRing 3 -Apply *>&1 | Out-Null
            $c = $global:InstallCall
            [bool]$c.UseManagedIdentity | Should -BeTrue; $c.UpdateRing | Should -Be 3
            $c.ContainsKey('CertSecretName') | Should -BeFalse; $c.ContainsKey('SpnClientId') | Should -BeFalse
        } finally { Remove-Item -Recurse -Force $d }
        (Get-SIProUpgradePlan -Globals @{ SI_Bootstrap_SubscriptionId = 's'; SI_Bootstrap_ResourceGroupName = 'r'; SI_Bootstrap_AcrName = 'a'; SI_Bootstrap_EnvName = 'e'; SI_KeyVaultName = 'k'; SI_SPN_TenantId = 't' } -UseManagedIdentity).Missing.Count | Should -Be 0
    }
    It '🔴 a failed install records NOTHING -- the Community update keeps working' {
        $d = New-Install ($script:Identity + $script:Block + "`r`n") -InstallFails
        try {
            { & (Join-Path $d 'setup\Upgrade-SIToPro.ps1') -CertSecretName 'cert' -Apply *>&1 | Out-Null } | Should -Throw '*refused the build*'
            Get-SIContainerHostingValue -Text ([IO.File]::ReadAllText((Join-Path $d 'config\SecurityInsight.custom.ps1'))) -Name 'SI_Bootstrap_UpdaterJob' | Should -Be ''
        } finally { Remove-Item -Recurse -Force $d }
    }
    It 'refused with the reason: no container hosting saved (a VM install), or a value it cannot know' {
        $d = New-Install ($script:Identity)
        try { { & (Join-Path $d 'setup\Upgrade-SIToPro.ps1') -CertSecretName 'cert' -Apply *>&1 | Out-Null } | Should -Throw '*no container hosting saved*' }
        finally { Remove-Item -Recurse -Force $d }
        Clear-ConfigGlobals
        $d = New-Install ((Get-SIContainerHostingBlock -SubscriptionId 'sub-1' -ResourceGroupName 'rg-x' -AcrName 'acrx') + "`r`n")
        try {
            { & (Join-Path $d 'setup\Upgrade-SIToPro.ps1') -CertSecretName 'cert' -Apply *>&1 | Out-Null } | Should -Throw '*Missing: EnvName, KeyVaultName, SpnClientId, TenantId*'
            $global:InstallCall | Should -BeNullOrEmpty
        } finally { Remove-Item -Recurse -Force $d }
    }
}

Describe 'after the upgrade, the Community roll steps aside' {
    AfterEach { Clear-ConfigGlobals }
    It '🔴 the container update leaves job-managed containers alone: exit 0, says why, and makes no Azure call' {
        $d = New-Install ((Get-SIContainerHostingBlock -SubscriptionId 'sub-1' -ResourceGroupName 'rg-x' -AcrName 'acrx' -UpdaterJob 'caj-si-updater') + "`r`n")
        try {
            $global:AzCalls = New-Object System.Collections.Generic.List[string]
            $out = & (Join-Path $d 'setup\Invoke-SIContainerUpdate.ps1') -Apply *>&1 | Out-String
            $LASTEXITCODE | Should -Be 0
            $out | Should -Match "updater job 'caj-si-updater'"
            $out | Should -Match '-Force'
            $global:AzCalls.Count | Should -Be 0
        } finally { Remove-Item -Recurse -Force $d }
    }
    It '-Force still rolls by hand (it reaches Azure)' {
        $d = New-Install ((Get-SIContainerHostingBlock -SubscriptionId 'sub-1' -ResourceGroupName 'rg-x' -AcrName 'acrx' -UpdaterJob 'caj-si-updater') + "`r`n")
        try {
            $global:AzCalls = New-Object System.Collections.Generic.List[string]
            & (Join-Path $d 'setup\Invoke-SIContainerUpdate.ps1') -Force *>&1 | Out-Null
            @($global:AzCalls | Where-Object { $_ -like 'GET https://management.azure.com/subscriptions/sub-1/*Microsoft.ContainerRegistry/registries*' }).Count | Should -BeGreaterThan 0 -Because 'it reads the registry over ARM (#521: no az)'
            @($global:AzCalls | Where-Object { $_ -notlike 'GET *' -and $_ -notlike 'POST *' -and $_ -notlike 'PATCH *' -and $_ -notlike 'PUT *' -and $_ -notlike 'HEAD *' -and $_ -notlike 'DELETE *' }) | Should -BeNullOrEmpty -Because 'no az call at all'
        } finally { Remove-Item -Recurse -Force $d }
    }
    It 'container setup tells the customer how THIS install is updated' {
        $c = Get-SIContainerUpdateGuidance -UpdaterJob ''
        ($c -join ' ') | Should -Match 'Update-SecurityInsight\.ps1 -Apply'
        ($c -join ' ') | Should -Match 'Upgrade-SIToPro\.ps1'
        (Get-SIContainerUpdateGuidance -UpdaterJob 'caj-si-updater') -join ' ' | Should -Match "'caj-si-updater'.*nothing to run"
    }
}

Describe 'WIRING and editions' {
    It 'container setup prints the guidance after it saves the hosting; no setup path installs the updater except the upgrade' {
        $b = Get-Content -Raw (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        $b.IndexOf('Get-SIContainerUpdateGuidance') | Should -BeGreaterThan $b.IndexOf('Save-SIContainerHostingConfig -ConfigPath $siConfig')
        $callers = @(Get-ChildItem -LiteralPath $script:SIRoot -Recurse -File -Filter *.ps1 | Where-Object { $_.FullName -notmatch '\\tests\\' -and $_.Name -ne 'Install-SIUpdaterJob.ps1' } |
            Where-Object { (Get-Content -Raw -LiteralPath $_.FullName) -match "Install-SIUpdaterJob\.ps1'\)" } | ForEach-Object { $_.Name })
        $callers | Should -Be @('Upgrade-SIToPro.ps1')
    }
    It 'the upgrade records the job only AFTER the installer ran' {
        $u = Get-Content -Raw (Join-Path $script:SIRoot 'setup\Upgrade-SIToPro.ps1')
        $u.IndexOf('-UpdaterJob $JobName') | Should -BeGreaterThan $u.IndexOf("Install-SIUpdaterJob.ps1') @install -Apply")
    }
    It 'like PIM: the updater code and the upgrade ship in BOTH editions; only the maintainer''s feed tools stay internal' {
        $ex = (Get-Content -Raw (Join-Path $script:SIRoot 'solution.publish.json') | ConvertFrom-Json).excludePaths
        foreach ($p in 'container/updater', 'setup/Install-SIUpdaterJob.ps1', 'setup/Upgrade-SIToPro.ps1', 'tests/pester/SIv3-Updater.Tests.ps1') { $ex | Should -Not -Contain $p }
        # SI's own update feed is retired (2026-10-06): its maintainer tools are gone, not just kept internal
        foreach ($p in 'setup/Publish-SISourceArchive.ps1', 'setup/Update-SISourceAccess.ps1') { Test-Path -LiteralPath (Join-Path $script:SIRoot $p) | Should -BeFalse }
    }
}
