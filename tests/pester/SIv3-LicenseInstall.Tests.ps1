#Requires -Version 5.1
<#
    A PRO LICENCE IS INSTALLED BY A TOOL THAT VERIFIES IT FIRST, AND IS FOUND ON AN UPGRADED INSTALL (#173).

    Operator decision 2026-09-30: "Setter + docs". Until now nothing put the SI-License secret in Key Vault --
    it was stored by hand -- and licensing resolved the vault only from $global:SI_KeyVaultName, so an install
    configured under the 2.2.x name ($global:SpnKeyVaultName) looked unlicensed while its licence sat in the
    very vault it uses for its SPN secret. The first licence ever issued also granted feature ids no gate
    asks for ('SI.ServiceNow'), which enabled nothing, silently.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\SI-FeatureCatalog.ps1')
    $script:Known = @(Get-SIFeatureCatalog | ForEach-Object { $_.Name })
    function script:New-Status([string]$Status = 'Valid', [string[]]$Features = @('correlation'), [string[]]$Tenants = @(), [string]$Sku = 'Pro') {
        [pscustomobject]@{ Status = $Status; Reason = "reason-$Status"; Customer = 'Test Customer'; Sku = $Sku; Features = $Features; TenantIds = $Tenants }
    }
}

Describe 'Test-SILicenseForInstall -- what may be installed' {
    It 'the catalog is what the check compares against (correlation + servicenow-connector)' {
        $script:Known | Should -Contain 'correlation'
        $script:Known | Should -Contain 'servicenow-connector'
    }
    It 'a valid licence for known features installs' {
        (Test-SILicenseForInstall -License (New-Status) -KnownFeatures $script:Known).Ok | Should -BeTrue
        (Test-SILicenseForInstall -License (New-Status -Features '*') -KnownFeatures $script:Known).Ok | Should -BeTrue
        (Test-SILicenseForInstall -License (New-Status -Status 'Grace') -KnownFeatures $script:Known).Ok | Should -BeTrue
        (Test-SILicenseForInstall -License (New-Status -Status 'NotYetValid') -KnownFeatures $script:Known).Ok | Should -BeTrue
    }
    It 'a licence that does not verify is refused, with the reason' -ForEach @('Invalid', 'Expired', 'Missing') {
        $r = Test-SILicenseForInstall -License (New-Status -Status $_) -KnownFeatures $script:Known
        $r.Ok | Should -BeFalse
        $r.Problems[0] | Should -Match "does not verify: $_"
    }
    It '#510 the edition decides: a Pro licence with an empty or old features[] installs; unknown ids are a note, not a refusal' {
        $r = Test-SILicenseForInstall -License (New-Status -Features 'SI.ServiceNow', 'SI.Correlation') -KnownFeatures $script:Known
        $r.Ok | Should -BeTrue
        $r.Edition | Should -Be 'Pro'
        ($r.Notes -join ' ') | Should -Match 'SI\.ServiceNow, SI\.Correlation'
        (Test-SILicenseForInstall -License (New-Status -Features @()) -KnownFeatures $script:Known).Ok | Should -BeTrue
    }
    It '#510 a licence whose sku names no Pro edition (and lists no add-on) unlocks nothing and is refused' -ForEach @('Community', '', 'Core') {
        $r = Test-SILicenseForInstall -License (New-Status -Features '*' -Sku $_) -KnownFeatures $script:Known
        $r.Ok | Should -BeFalse
        ($r.Problems -join ' ') | Should -Match 'names no SecurityInsight Pro edition'
    }
    It 'a licence bound to another tenant is refused; unbound or matching tenants install' {
        (Test-SILicenseForInstall -License (New-Status -Tenants 'aaaa') -KnownFeatures $script:Known -TenantId 'bbbb').Ok | Should -BeFalse
        (Test-SILicenseForInstall -License (New-Status -Tenants 'AAAA') -KnownFeatures $script:Known -TenantId 'aaaa').Ok | Should -BeTrue
        (Test-SILicenseForInstall -License (New-Status) -KnownFeatures $script:Known -TenantId 'bbbb').Ok | Should -BeTrue
    }
}

Describe 'the licence is found in the vault an upgraded install already uses' {
    BeforeEach {
        foreach ($n in 'SI_License', 'SI_KeyVaultName', 'SpnKeyVaultName', 'Context') { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
        $script:AskedVault = $null
        function global:Get-SIKvSecret { param($VaultName, $SecretName) $script:AskedVault = $VaultName; return '{"payload":"x"}' }
    }
    AfterEach {
        Remove-Item Function:\Get-SIKvSecret -ErrorAction SilentlyContinue
        foreach ($n in 'SI_KeyVaultName', 'SpnKeyVaultName') { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
    }
    It 'a 2.2.x config with only SpnKeyVaultName reads SI-License from that vault' {
        $global:SpnKeyVaultName = 'kv-from-2-2'
        Get-SILicenseSecretText | Should -Be '{"payload":"x"}'
        $script:AskedVault | Should -Be 'kv-from-2-2'
    }
    It 'SI_KeyVaultName still wins when both are set' {
        $global:SpnKeyVaultName = 'kv-old'; $global:SI_KeyVaultName = 'kv-new'
        $null = Get-SILicenseSecretText
        $script:AskedVault | Should -Be 'kv-new'
    }
    It 'no vault configured = no read and no error (the Community edition)' {
        Get-SILicenseSecretText | Should -BeNullOrEmpty
        $script:AskedVault | Should -BeNullOrEmpty
    }
}

Describe 'WIRING' {
    It 'the setter verifies BEFORE writing and re-verifies what it reads back' {
        $p = Join-Path $script:SIRoot 'setup\Set-SILicense.ps1'
        if (-not (Test-Path -LiteralPath $p)) { Set-ItResult -Skipped -Because 'SecurityInsight Pro tooling is not in this copy'; return }
        $c = ((Get-Content -LiteralPath $p) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $c.IndexOf('Test-SILicenseForInstall') | Should -BeLessThan $c.IndexOf('Set-SIAzKeyVaultSecret')
        $c.IndexOf('Set-SIAzKeyVaultSecret') | Should -BeLessThan $c.LastIndexOf('Test-SILicenseForInstall')
        $c | Should -Match 'Get-SIVaultName'
        $c | Should -Match 'SupportsShouldProcess'
        $c | Should -Not -Match 'Write-Host[^\n]*\$text' -Because 'the licence content is never printed'
    }
    It 'unattended setup installs a named licence through the setter, and says so when it cannot' {
        $c = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'Setup-SecurityInsight-Unattended.ps1')
        $c | Should -Match "setup\\Set-SILicense\.ps1"
        $c | Should -Match 'Licence\.Path is set, but this copy has no licence tool'
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'config\setup-unattended.sample.json') | ConvertFrom-Json).PSObject.Properties.Name | Should -Contain 'Licence'
    }
}
