#Requires -Version 5.1
<#
    THE COMMUNITY DEFAULTS (operator decision 2026-10-07, wizard: "Tagging: report-only default" + "Sign-in: managed identity").

      1. Asset tagging on a server (launcher\asset-tagging\launcher.community-vm.ps1) is REPORT ONLY by default -- as the
         Pro container job already is. It writes only with -Apply or $global:SI_AssetTagging_Apply = $true; -WhatIfMode is
         kept (report only, wins over -Apply). An install that wrote tags before is told ONCE that tagging is now report
         only and how to switch writing back on -- no silent behaviour change.
      2. The sign-in: the local setup wizard (setup\ConfigWizard) and Bootstrap-ContainerAppJob.ps1 default to a MANAGED
         IDENTITY. A service principal with a client secret stays a supported, explicit choice (never removed); a
         certificate stays available. A server outside Azure cannot have a managed identity: certificate first, then
         secret. An existing install whose configuration carries a client secret keeps it under Bootstrap.

    Proven on the pure decisions AND on the REAL launcher in a child process of the current shell (run the suite on
    powershell.exe AND pwsh): a fake install with a stub engine that records what it was told. Offline: no Azure.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Exe    = [Diagnostics.Process]::GetCurrentProcess().Path
    . (Join-Path $script:SIRoot 'engine\_shared\SI-FirstRun.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-tagging\AssetTagging.Resolve.ps1')
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupNaming.ps1')
    . (Join-Path $script:SIRoot 'setup\ConfigWizard\backend\SI-WizardSignIn.ps1')
    function script:Get-Code([string]$Rel) { [System.IO.File]::ReadAllText((Join-Path $script:SIRoot $Rel)) }

    # A fake install: the real launcher, loader, shared helpers and resolver; a STUB engine that records the run mode.
    function script:New-TagInstall {
        param([string]$Custom = '', [switch]$EarlierTaggingRun)
        $root = Join-Path ([IO.Path]::GetTempPath()) ('sitag-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        foreach ($d in 'launcher\_lib', 'launcher\asset-tagging', 'engine\_shared', 'engine\asset-tagging', 'auth', 'config', 'logs') {
            New-Item -ItemType Directory -Force (Join-Path $root $d) | Out-Null
        }
        Copy-Item -Path (Join-Path $script:SIRoot 'launcher\_lib\*') -Destination (Join-Path $root 'launcher\_lib') -Recurse -Force
        Copy-Item -Path (Join-Path $script:SIRoot 'launcher\asset-tagging\*') -Destination (Join-Path $root 'launcher\asset-tagging') -Recurse -Force
        Copy-Item -Path (Join-Path $script:SIRoot 'engine\_shared\*') -Destination (Join-Path $root 'engine\_shared') -Recurse -Force
        Copy-Item -Path (Join-Path $script:SIRoot 'auth\*') -Destination (Join-Path $root 'auth') -Recurse -Force
        Copy-Item -LiteralPath (Join-Path $script:SIRoot 'engine\asset-tagging\AssetTagging.Resolve.ps1') -Destination (Join-Path $root 'engine\asset-tagging')
        Copy-Item -LiteralPath (Join-Path $script:SIRoot 'VERSION') -Destination $root
        # the stub engine: writes nothing anywhere but this file
        [IO.File]::WriteAllText((Join-Path $root 'engine\asset-tagging\AssetTagging.ps1'),
            "Set-Content -LiteralPath (Join-Path `$PSScriptRoot 'engine-saw.txt') -Value ('WHATIF=' + [bool]`$global:WhatIfMode) -Encoding UTF8`r`n",
            [Text.UTF8Encoding]::new($true))
        $cfg = "`$global:SI_AuthMethod = 'ManagedIdentity'`r`n`$global:SI_Telemetry_Enabled = `$false`r`n" + $Custom
        [IO.File]::WriteAllText((Join-Path $root 'config\SecurityInsight.custom.ps1'), $cfg, [Text.UTF8Encoding]::new($true))
        if ($EarlierTaggingRun) {
            $f = Join-Path $root 'logs\asset-tagging_community-vm_20260901T020000Z.log'
            Set-Content -LiteralPath $f -Value 'a run that wrote tags' -Encoding UTF8
            (Get-Item -LiteralPath $f).LastWriteTime = (Get-Date).AddDays(-2)
        }
        $root
    }
    # Runs the REAL launcher in a child process; returns its console lines and what the engine was told.
    function script:Invoke-Tagging {
        param([string]$Root, [string]$Switches = '')
        $out = Join-Path $Root ('out-' + [guid]::NewGuid().ToString('N') + '.txt')
        $l = Join-Path $Root 'launcher\asset-tagging\launcher.community-vm.ps1'
        $cmd = "`$ErrorActionPreference = 'Stop'; & '$l' -InstallPath '$Root' $Switches *>&1 | ForEach-Object { [string]`$_ } | Set-Content -LiteralPath '$out' -Encoding UTF8"
        & $script:Exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $cmd | Out-Null
        $saw = Join-Path $Root 'engine\asset-tagging\engine-saw.txt'
        $r = [pscustomobject]@{ Lines = @(Get-Content -LiteralPath $out -Encoding UTF8 -ErrorAction SilentlyContinue); Saw = $(if (Test-Path -LiteralPath $saw) { (Get-Content -Raw -LiteralPath $saw).Trim() } else { '' }) }
        Remove-Item -LiteralPath $saw -Force -ErrorAction SilentlyContinue
        $r
    }
    function script:Count-Match([string[]]$Lines, [string]$Re) { @($Lines | Where-Object { $_ -match $Re }).Count }
    $script:NowReportOnlyRe = 'Asset tagging is now REPORT ONLY by default'
    $script:FreshNoticeRe   = 'Asset tagging is REPORT ONLY by default'
    $script:Roots = New-Object System.Collections.Generic.List[string]
}

AfterAll { foreach ($r in $script:Roots) { Remove-Item -Recurse -Force -LiteralPath $r -ErrorAction SilentlyContinue } }

# ======================================================================================================================
Describe 'asset tagging: the run mode (pure)' {
    It 'nothing asked for = REPORT ONLY (the default)' {
        $m = Resolve-SIAssetTaggingRunMode
        $m.Apply | Should -BeFalse; $m.WhatIfMode | Should -BeTrue; $m.Source | Should -Be 'default'
    }
    It '-Apply on the run writes; SI_AssetTagging_Apply = $true writes' {
        (Resolve-SIAssetTaggingRunMode -ApplySwitch $true -EnabledSetting $true).Apply | Should -BeTrue
        (Resolve-SIAssetTaggingRunMode -ApplySwitch $true -EnabledSetting $true).Source | Should -Be 'switch-apply'
        (Resolve-SIAssetTaggingRunMode -ApplySetting $true -EnabledSetting $true).Apply | Should -BeTrue
        (Resolve-SIAssetTaggingRunMode -ApplySetting 'true' -EnabledSetting 'true').Apply | Should -BeTrue
        (Resolve-SIAssetTaggingRunMode -ApplySetting $true -EnabledSetting $true).Source | Should -Be 'setting'
    }
    It '-WhatIfMode wins over -Apply and over the setting; WhatIfMode = $true in the config means report only' {
        (Resolve-SIAssetTaggingRunMode -ApplySwitch $true -WhatIfSwitch $true).Apply | Should -BeFalse
        (Resolve-SIAssetTaggingRunMode -ApplySetting $true -WhatIfSwitch $true).Source | Should -Be 'switch-whatif'
        (Resolve-SIAssetTaggingRunMode -ApplySetting $true -ConfigWhatIf $true).Apply | Should -BeFalse
        (Resolve-SIAssetTaggingRunMode -ApplySetting $true -ConfigWhatIf $true).Source | Should -Be 'config-whatif'
        # a per-run -Apply still wins over a config WhatIfMode (the run asked for it explicitly)
        (Resolve-SIAssetTaggingRunMode -ApplySwitch $true -ConfigWhatIf $true -EnabledSetting $true).Apply | Should -BeTrue
    }
    It '#643 asset tagging OFF (SI_AssetTagging_Enabled not on, the shipped default): neither -Apply nor SI_AssetTagging_Apply writes' {
        foreach ($en in @($null, $false, 'false', '', 'maybe')) {
            $m = Resolve-SIAssetTaggingRunMode -ApplySwitch $true -EnabledSetting $en
            $m.Apply | Should -BeFalse -Because "Enabled '$en'"; $m.Source | Should -Be 'tagging-off'
            (Resolve-SIAssetTaggingRunMode -ApplySetting $true -EnabledSetting $en).Apply | Should -BeFalse
        }
        (Resolve-SIAssetTaggingRunMode -EnabledSetting $true).Source | Should -Be 'default' -Because 'on, but nothing asked to write: report only'
    }
    It 'NEVER writes by accident: WhatIfMode = $false in a config, a false-ish setting, odd values -- all report only' {
        foreach ($v in @($false, 'false', '0', '', 'no', 'off', $null, 'maybe', 0)) {
            (Resolve-SIAssetTaggingRunMode -ApplySetting $v -ConfigWhatIf $false).Apply | Should -BeFalse -Because "setting '$v'"
        }
    }
    It 'the run line says report only, and how to write, when the default decided' {
        Get-SIAssetTaggingRunModeLine -Mode (Resolve-SIAssetTaggingRunMode) | Should -Match 'REPORT ONLY.*-Apply.*SI_AssetTagging_Apply'
        Get-SIAssetTaggingRunModeLine -Mode (Resolve-SIAssetTaggingRunMode -ApplySetting $true -EnabledSetting $true) | Should -Match 'WRITES ON'
        Get-SIAssetTaggingRunModeLine -Mode (Resolve-SIAssetTaggingRunMode -ApplySetting $true) | Should -Match 'asset tagging is OFF.*SI_AssetTagging_Enabled'
    }
}

Describe 'asset tagging: the one-time notice (memory store)' {
    It 'an install that ran tagging before is told ONCE that it is now report only, with the switch; never again' {
        $store = @{ Kind = 'memory'; Box = @{} }
        $m = Resolve-SIAssetTaggingRunMode
        $one = Invoke-SIAssetTaggingReportOnlyNotice -Mode $m -Store $store -RanBefore { $true } 6>$null
        $one.Shown | Should -BeTrue; $one.RanBefore | Should -BeTrue
        ($one.Lines -join ' ') | Should -Match $script:NowReportOnlyRe
        ($one.Lines -join ' ') | Should -Match 'SI_AssetTagging_Apply = \$true'
        (Invoke-SIAssetTaggingReportOnlyNotice -Mode $m -Store $store -RanBefore { $true } 6>$null).Shown | Should -BeFalse
    }
    It 'a run that ASKED (report only or writing) is not told; an unreadable store shows nothing' {
        $store = @{ Kind = 'memory'; Box = @{} }
        (Invoke-SIAssetTaggingReportOnlyNotice -Mode (Resolve-SIAssetTaggingRunMode -WhatIfSwitch $true) -Store $store 6>$null).Shown | Should -BeFalse
        (Invoke-SIAssetTaggingReportOnlyNotice -Mode (Resolve-SIAssetTaggingRunMode -ApplySwitch $true) -Store $store 6>$null).Shown | Should -BeFalse
        (Invoke-SIAssetTaggingReportOnlyNotice -Mode (Resolve-SIAssetTaggingRunMode) -Store @{ Kind = 'nope' } 6>$null).Shown | Should -BeFalse
    }
}

Describe 'asset tagging: the REAL Community launcher, in a child process' {
    It 'DEFAULT: the engine is told report only; an install that wrote tags before gets the notice ONCE; the second run repeats nothing' {
        $r = New-TagInstall -EarlierTaggingRun; $script:Roots.Add($r)
        $one = Invoke-Tagging -Root $r
        $one.Saw | Should -Be 'WHATIF=True' -Because ($one.Lines -join [Environment]::NewLine)
        Count-Match $one.Lines $script:NowReportOnlyRe | Should -Be 1
        Count-Match $one.Lines 'REPORT ONLY -- nothing is changed' | Should -BeGreaterThan 0
        Count-Match $one.Lines 'This run WRITES tags' | Should -Be 0
        $st = Get-Content -Raw -LiteralPath (Join-Path $r 'logs\state\install-state.json') | ConvertFrom-Json
        @($st.Shown) | Should -Contain 'asset-tagging-report-only'
        $two = Invoke-Tagging -Root $r
        $two.Saw | Should -Be 'WHATIF=True'
        Count-Match $two.Lines $script:NowReportOnlyRe | Should -Be 0
        Count-Match $two.Lines $script:FreshNoticeRe | Should -Be 0
    }
    It 'a NEW install (no earlier tagging run) is told once that tagging is report only by default -- not "now"' {
        $r = New-TagInstall; $script:Roots.Add($r)
        $one = Invoke-Tagging -Root $r
        $one.Saw | Should -Be 'WHATIF=True'
        Count-Match $one.Lines $script:NowReportOnlyRe | Should -Be 0
        Count-Match $one.Lines $script:FreshNoticeRe | Should -Be 1
    }
    It '-Apply writes (the engine is told so); -Apply -WhatIfMode does not; -WhatIfMode alone still works' {
        $r = New-TagInstall -Custom "`$global:SI_AssetTagging_Enabled = `$true`r`n"; $script:Roots.Add($r)
        (Invoke-Tagging -Root $r -Switches '-Apply').Saw | Should -Be 'WHATIF=False'
        (Invoke-Tagging -Root $r -Switches '-Apply -WhatIfMode').Saw | Should -Be 'WHATIF=True'
        (Invoke-Tagging -Root $r -Switches '-WhatIfMode').Saw | Should -Be 'WHATIF=True'
    }
    It 'the setting SI_AssetTagging_Apply = $true writes, with no notice; a config WhatIfMode = $true keeps it report only' {
        $r = New-TagInstall -Custom "`$global:SI_AssetTagging_Enabled = `$true`r`n`$global:SI_AssetTagging_Apply = `$true`r`n" -EarlierTaggingRun; $script:Roots.Add($r)
        $one = Invoke-Tagging -Root $r
        $one.Saw | Should -Be 'WHATIF=False'
        Count-Match $one.Lines 'WRITES ON' | Should -BeGreaterThan 0
        Count-Match $one.Lines $script:NowReportOnlyRe | Should -Be 0
        $r2 = New-TagInstall -Custom "`$global:SI_AssetTagging_Apply = `$true`r`n`$global:WhatIfMode = `$true`r`n"; $script:Roots.Add($r2)
        (Invoke-Tagging -Root $r2).Saw | Should -Be 'WHATIF=True'
    }
    It '#643: with asset tagging off (no SI_AssetTagging_Enabled), -Apply and SI_AssetTagging_Apply = $true do NOT write' {
        $r = New-TagInstall -Custom "`$global:SI_AssetTagging_Apply = `$true`r`n"; $script:Roots.Add($r)
        $one = Invoke-Tagging -Root $r
        $one.Saw | Should -Be 'WHATIF=True' -Because ($one.Lines -join [Environment]::NewLine)
        (Invoke-Tagging -Root $r -Switches '-Apply').Saw | Should -Be 'WHATIF=True'
    }
    It 'a config that says WhatIfMode = $false (the old default, copied into configs) does NOT write' {
        $r = New-TagInstall -Custom "`$global:WhatIfMode = `$false`r`n"; $script:Roots.Add($r)
        (Invoke-Tagging -Root $r).Saw | Should -Be 'WHATIF=True'
    }
    It 'WIRING: the launcher decides through the shared resolver and keeps the bound-parameter check for -WhatIfMode' {
        $c = Get-Code 'launcher\asset-tagging\launcher.community-vm.ps1'
        $c | Should -Match '\[switch\]\$Apply'
        $c | Should -Match '\[switch\]\$WhatIfMode'
        $c | Should -Match "Resolve-SIAssetTaggingRunMode -ApplySwitch \(\`$PSBoundParameters\.ContainsKey\('Apply'\)"
        $c | Should -Match "PSBoundParameters\.ContainsKey\('WhatIfMode'\)"
        $c | Should -Match '\$global:WhatIfMode = \[bool\]\$tagMode\.WhatIfMode'
        # the old "writes unless -WhatIfMode" default is gone
        $c | Should -Not -Match "elseif \(\`$null -eq \`$global:WhatIfMode\) \{ \`$global:WhatIfMode = \`$false \}"
    }
}

# ======================================================================================================================
Describe 'sign-in: Bootstrap-ContainerAppJob.ps1 defaults to a managed identity (pure)' {
    It 'no switch, no config = the managed identity, said as the default' {
        $c = Resolve-SIBootstrapAuthChoice
        $c.Mode | Should -Be 'ManagedIdentity'; $c.Default | Should -BeTrue
    }
    It 'a client secret is a supported EXPLICIT choice: -UseClientSecret, or SI_AuthMethod = Secret' {
        (Resolve-SIBootstrapAuthChoice -UseClientSecret $true).Mode | Should -Be 'Secret'
        (Resolve-SIBootstrapAuthChoice -UseClientSecret $true).Default | Should -BeFalse
        (Resolve-SIBootstrapAuthChoice -ConfiguredMethod 'Secret').Mode | Should -Be 'Secret'
        (Resolve-SIBootstrapAuthChoice -ConfiguredMethod 'ManagedIdentity' -HasConfiguredSecret $true).Mode | Should -Be 'ManagedIdentity'
    }
    It 'an EXISTING install whose config carries a client secret keeps it (nothing changes under it by itself)' {
        $c = Resolve-SIBootstrapAuthChoice -HasConfiguredSecret $true
        $c.Mode | Should -Be 'Secret'; $c.Default | Should -BeTrue
        $c.Reason | Should -Match 'existing install keeps'
    }
    It 'the certificate stays; half of it, or two sign-ins at once, is an error' {
        (Resolve-SIBootstrapAuthChoice -CertificateKeyVaultName 'kv' -CertificateSecretName 'c').Mode | Should -Be 'Certificate'
        { Resolve-SIBootstrapAuthChoice -CertificateKeyVaultName 'kv' } | Should -Throw '*BOTH*'
        { Resolve-SIBootstrapAuthChoice -UseManagedIdentity $true -UseClientSecret $true } | Should -Throw '*ONE*'
        { Resolve-SIBootstrapAuthChoice -UseClientSecret $true -CertificateKeyVaultName 'kv' -CertificateSecretName 'c' } | Should -Throw '*ONE*'
    }
    It 'a chosen secret still produces exactly the secret job arguments it always did' {
        $a = Get-SIContainerJobAuthArgs -Mode (Resolve-SIBootstrapAuthMode -UseClientSecret $true) -SpnAppId 'app' -SpnSecret 's3cr3t' -SpnTenantId 'ten' -SpnObjectId 'obj'
        $a.Mode | Should -Be 'Secret'
        ($a.SecretArgs -join ' ') | Should -Match 'si-spn-secret'
        ($a.EnvArgs -join ' ') | Should -Match 'SI_SPN_SECRET=secretref:si-spn-secret'
    }
    It 'WIRING: Bootstrap has -UseClientSecret (+ its config switch) and passes the config''s method and secret to the decision' {
        $c = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        $c | Should -Match '\[Parameter\(\)\]\[switch\]\$UseClientSecret'
        $c | Should -Match "_Apply-CustomSwitch -ParamName 'UseClientSecret'\s+-GlobalName 'SI_Bootstrap_UseClientSecret'"
        $c | Should -Match '-UseClientSecret \(\[bool\]\$UseClientSecret\) -ConfiguredMethod \(\[string\]\$global:SI_AuthMethod\)'
        $c | Should -Match '\$authMode = \$authChoice\.Mode'
    }
}

Describe 'sign-in: the local setup wizard defaults to a managed identity' {
    It 'nothing chosen on an Azure VM / Arc server = a user-assigned managed identity; in Container Apps = the jobs'' identity' {
        $v = Resolve-SIWizardSignIn -HostType azureVMMI
        $v.CredKind | Should -Be 'ManagedIdentity'; $v.Identity | Should -Be 'user-assigned'; $v.DefaultUsed | Should -BeTrue
        (Resolve-SIWizardSignIn -HostType azureContainerMI).Identity | Should -Be 'container-jobs'
        (Resolve-SIWizardSignIn).CredKind | Should -Be 'ManagedIdentity'
    }
    It 'a server outside Azure: no managed identity -- certificate first, and it says why; asking for one there is refused' {
        $w = Resolve-SIWizardSignIn -HostType win
        $w.CredKind | Should -Be 'Cert'; $w.Note | Should -Match 'cannot have a managed identity'
        { Resolve-SIWizardSignIn -HostType win -CredKind ManagedIdentity } | Should -Throw '*cannot have a managed identity*'
    }
    It 'a secret still works when chosen (and a certificate); an existing SPN keeps its certificate' {
        (Resolve-SIWizardSignIn -HostType azureVMMI -CredKind Secret).CredKind | Should -Be 'Secret'
        (Resolve-SIWizardSignIn -HostType win -CredKind Secret).CredKind | Should -Be 'Secret'
        (Resolve-SIWizardSignIn -HostType azureContainerMI -CredKind Cert).CredKind | Should -Be 'Cert'
        (Resolve-SIWizardSignIn -HostType azureVMMI -ExistingAppId 'app').CredKind | Should -Be 'Cert'
        { Resolve-SIWizardSignIn -CredKind Password } | Should -Throw
    }
    It 'the identity name follows the resource group pattern, else the name earlier releases used' {
        Get-SIWizardIdentityName -ResourceGroupName 'rg-si-prod-community-vm' | Should -Be ((Get-SISetupNamesFromResourceGroup -ResourceGroupName 'rg-si-prod-community-vm').ManagedIdentity)
        Get-SIWizardIdentityName -ResourceGroupName 'rg-customer' | Should -Be 'uami-securityinsight'
        Get-SIWizardIdentityName -Name 'id-mine' -ResourceGroupName 'rg-si-prod-community-vm' | Should -Be 'id-mine'
    }
    It 'attaching the identity to a VM keeps its system-assigned and other identities; already attached = no change' {
        $id = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si'
        . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1')
        $b = Get-SIVmIdentityPatchBody -CurrentIdentity ([pscustomobject]@{ type = 'SystemAssigned' }) -IdentityResourceId $id
        $b.identity.type | Should -Be 'SystemAssigned, UserAssigned'
        @($b.identity.userAssignedIdentities.Keys) | Should -Be @($id)
        $other = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/other'
        $cur = [pscustomobject]@{ type = 'UserAssigned'; userAssignedIdentities = [pscustomobject]@{ $other = [pscustomobject]@{ clientId = 'c' } } }
        $b2 = Get-SIVmIdentityPatchBody -CurrentIdentity $cur -IdentityResourceId $id
        $b2.identity.type | Should -Be 'UserAssigned'
        @($b2.identity.userAssignedIdentities.Keys) | Should -Contain $other
        @($b2.identity.userAssignedIdentities.Keys) | Should -Contain $id
        (Get-SIVmIdentityPatchBody -CurrentIdentity $null -IdentityResourceId $id).identity.type | Should -Be 'UserAssigned'
        $cur3 = [pscustomobject]@{ type = 'UserAssigned'; userAssignedIdentities = [pscustomobject]@{ $id = [pscustomobject]@{} } }
        Get-SIVmIdentityPatchBody -CurrentIdentity $cur3 -IdentityResourceId $id | Should -BeNullOrEmpty
    }
    It 'the config the wizard writes says the sign-in explicitly: ManagedIdentity (no SPN app id) or Secret (with the secret)' {
        $infra = [pscustomobject]@{ SubscriptionId = 'sub-1'; ResourceGroupName = 'rg'; Location = 'westeurope'; WorkspaceName = 'ws'
                                    WorkspaceResourceId = '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
                                    DceName = 'dce'; DceIngestionUri = 'https://dce'; DcrResourceGroupName = 'rg'; StorageAccountName = 'st'; StorageResourceGroupName = 'rg' }
        $w = Join-Path $script:SIRoot 'setup\ConfigWizard\backend\Write-SICustomConfig.ps1'
        $p = Join-Path ([IO.Path]::GetTempPath()) ('si-cfg-' + [guid]::NewGuid().ToString('N') + '.ps1')
        try {
            $mi = New-SIWizardManagedIdentityResult -TenantId 'ten' -ClientId 'cid-1' -PrincipalId 'pid-1' -Name 'id-si'
            $null = & $w -OutputPath $p -Spn $mi -Infra $infra -Force 6>$null
            $t = [IO.File]::ReadAllText($p)
            $t | Should -Match "\`$global:SI_AuthMethod\s+= 'ManagedIdentity'"
            $t | Should -Match "\`$global:SI_ManagedIdentityClientId = 'cid-1'"
            $t | Should -Not -Match 'SI_SPN_AppId'
            $t | Should -Not -Match 'SI_SPN_Secret'
            Remove-Item -Path "$p*" -Force -ErrorAction SilentlyContinue
            $sec = [pscustomobject]@{ TenantId = 'ten'; AppId = 'app-1'; ObjectId = 'obj-1'; CredKind = 'Secret'; CredValue = 'the-secret'; KvName = $null }
            $null = & $w -OutputPath $p -Spn $sec -Infra $infra -Force 6>$null
            $t2 = [IO.File]::ReadAllText($p)
            $t2 | Should -Match "\`$global:SI_AuthMethod\s+= 'Secret'"
            $t2 | Should -Match "SI_SPN_Secret\s+= 'the-secret'"
        } finally { Remove-Item -Path "$p*" -Force -ErrorAction SilentlyContinue }
    }
    It 'WIRING: the wizard host decides with Resolve-SIWizardSignIn (no "Secret" fallback), creates the VM identity with the infrastructure and grants it' {
        $c = Get-Code 'setup\ConfigWizard\Start-SetupWizard.ps1'
        $c | Should -Match "\. \(Join-Path \`$backendDir 'SI-WizardSignIn\.ps1'\)"
        $c | Should -Match 'Resolve-SIWizardSignIn -HostType'
        $c | Should -Not -Match "else \{ 'Secret' \}"
        $c | Should -Match 'CredKind\s+= \$signIn\.CredKind'
        $c | Should -Match '\$infraArgs\.ManagedIdentityName\s+= \$miName'
        $c | Should -Match "CredKind = 'ManagedIdentity'"
        $c | Should -Match 'Add-SIVmUserAssignedIdentity'
        $c | Should -Match "if \(\`$signIn\.Identity -eq 'container-jobs'\) \{ \`$containerArgs\.GrantIdentityRoles = \`$true \}"
        $i = Get-Code 'setup\ConfigWizard\backend\Initialize-SIInfra.ps1'
        $i | Should -Match 'New-SIUserAssignedIdentity -ResourceGroupName \$ResourceGroupName -Name \$ManagedIdentityName'
        $i | Should -Not -Match '\[Parameter\(Mandatory\)\] \[string\]\$SpnObjectId'
        # a managed identity never gets an app registration created for it
        Get-Code 'setup\ConfigWizard\backend\New-SISpn.ps1' | Should -Match "elseif \(\`$CredKind -eq 'ManagedIdentity'\) \{\s+# A managed identity has no app registration"
    }
    It 'WIRING: the page defaults to a managed identity and snaps a server outside Azure to a certificate' {
        $js = Get-Code 'setup\ConfigWizard\app.js'
        $js | Should -Match "spnMode:\s+'managedIdentity'"
        $js | Should -Match "credType:\s+'certThumb'"
        $js | Should -Match "credKind:\s+d\.spnMode === 'managedIdentity' \? 'ManagedIdentity'"
        $js | Should -Match "state\.data\.hostType === 'win' && state\.data\.spnMode === 'managedIdentity'"
        $h = Get-Code 'setup\ConfigWizard\Setup-SecurityInsight.html'
        $h | Should -Match 'value="managedIdentity"'
        $h | Should -Match 'data-default="azureVMMI"'
    }
}
