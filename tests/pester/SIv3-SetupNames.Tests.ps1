#Requires -Version 5.1
<#
    SETUP WRITES THE NAMES THE ENGINES READ, AND NOTHING DEAD (#174 -- 2026-09-30 release review).

    The CLI setup wrote SubscriptionId / DceResourceGroup, while the v3 publishers (trend, Defender
    recommendations, the Pro engines) read SI_AzSubscriptionId / SI_DceResourceGroup / SI_SPN_ObjectId -- and only
    the profiling orchestrator backfilled them. So DCR/DCE pinning was skipped and a new DCR got no LogIngest
    principal. The wizard also offered a Shodan "licence tier" nothing read, and wrote a certificate name
    nothing read.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
    $script:Names = 'SI_AzSubscriptionId', 'SI_DceResourceGroup', 'SI_SPN_ObjectId', 'SI_WorkspaceResourceId', 'SubscriptionId',
                    'DceResourceGroup', 'SI_DcrResourceGroup', 'SpnObjectId', 'SI_LogIngest_ObjectId'
    function script:Clear-Names { foreach ($n in $script:Names) { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue } }
    function script:Get-Code([string]$Rel) { ((Get-Content -LiteralPath (Join-Path $script:SIRoot $Rel)) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n" }
}
AfterAll { Clear-Names }

Describe 'Initialize-SIIngestGlobals -- the publishers get the names they need' {
    BeforeEach { Clear-Names }

    It 'the subscription comes from the workspace resource id' {
        $global:SI_WorkspaceResourceId = '/subscriptions/1111-2222/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
        Initialize-SIIngestGlobals
        $global:SI_AzSubscriptionId | Should -Be '1111-2222'
    }
    It 'a config written by the 2.2.x CLI (older names only) is enough' {
        $global:SubscriptionId = 'sub-old'; $global:DceResourceGroup = 'rg-dce-old'; $global:SpnObjectId = 'obj-old'
        Initialize-SIIngestGlobals
        "$($global:SI_AzSubscriptionId)|$($global:SI_DceResourceGroup)|$($global:SI_SPN_ObjectId)" | Should -Be 'sub-old|rg-dce-old|obj-old'
    }
    It 'the DCE resource group falls back to the DCR resource group (same RG by default)' {
        $global:SI_DcrResourceGroup = 'rg-dcr'
        Initialize-SIIngestGlobals
        $global:SI_DceResourceGroup | Should -Be 'rg-dcr'
    }
    It 'a value the customer set is never overwritten' {
        $global:SI_AzSubscriptionId = 'mine'; $global:SubscriptionId = 'other'
        $global:SI_WorkspaceResourceId = '/subscriptions/ws-sub/resourceGroups/rg/providers/x/workspaces/w'
        Initialize-SIIngestGlobals
        $global:SI_AzSubscriptionId | Should -Be 'mine'
    }
    It 'nothing to go on = nothing set, no error' {
        { Initialize-SIIngestGlobals } | Should -Not -Throw
        $global:SI_AzSubscriptionId | Should -BeNullOrEmpty
    }
}

Describe 'WIRING' {
    It 'the publishers that bypass the profiling orchestrator call it' {
        Get-Code 'engine\_shared\SI-LogIngest.ps1' | Should -Match '\$authParams = Resolve-SICorrelationAuthParams\s+Initialize-SIIngestGlobals'
        Get-Code 'engine\asset-trend\Invoke-SITrend.ps1' | Should -Match 'Initialize-SIIngestGlobals'
    }
    It 'the wizard offers no setting that nothing reads' {
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\ConfigWizard\Setup-SecurityInsight.html')) | Should -Not -Match 'shodanLicenseTier'
        Get-Code 'setup\ConfigWizard\app.js' | Should -Not -Match "assignLine\('SI_Shodan_LicenseTier'"
        Get-Code 'setup\ConfigWizard\backend\Write-SICustomConfig.ps1' | Should -Not -Match 'global:SI_SPN_KvCertName'
    }
}

Describe 'the Tag Contributor opt-in is reachable from every setup path (#175)' {
    # The backend (New-SISpn -IncludeTagContributor) honoured it all along; the wizard page never sent it and the
    # unattended JSON had no field -- so Community asset-tagging could be enabled only from the CLI.
    It 'the wizard page offers it, and the state it posts carries it' {
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\ConfigWizard\Setup-SecurityInsight.html')) | Should -Match 'data-key="includeTagContributor"'
        Get-Code 'setup\ConfigWizard\app.js' | Should -Match 'includeTagContributor:\s*!!d\.includeTagContributor'
        Get-Code 'setup\ConfigWizard\Start-SetupWizard.ps1' | Should -Match 'st\.spn\.includeTagContributor\)\s*\{\s*\$spnArgs\.IncludeTagContributor = \$true'
    }
    It 'unattended setup reads it from the JSON, and the sample documents it (off by default)' {
        Get-Code 'Setup-SecurityInsight-Unattended.ps1' | Should -Match 'Auth_Community\.IncludeTagContributor'
        $j = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'config\setup-unattended.sample.json') | ConvertFrom-Json
        $j.Auth_Community.IncludeTagContributor | Should -BeFalse
    }
    It 'it stays OPT-IN: the backend grants Tag Contributor only when asked' {
        Get-Code 'setup\ConfigWizard\backend\New-SISpn.ps1' | Should -Match 'if \(\$IncludeTagContributor\)'
    }
}
