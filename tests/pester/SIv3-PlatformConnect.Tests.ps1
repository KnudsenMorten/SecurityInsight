#Requires -Version 5.1
<#
    THE INTERNAL INSTALL SIGNS IN TO THE PLATFORM WITHOUT ITS POWERSHELL MODULE (#305) -- auth/SI-PlatformConnect.ps1.

    The platform framework's own sign-in lives in a module that needs the Az / Microsoft Graph modules. SecurityInsight
    signs in itself, over REST, from the same bootstrap\platform-config.json, and sets the framework's public globals
    ($global:HighPriv_Modern_*, $global:Context, $global:KV_HighPriv_*, ...) exactly as the framework did.

    OFFLINE: every Key Vault read is mocked (Get-SIKeyVaultSecretValue); the certificate check and the managed-identity
    probe are seams. No tenant, no network, no module.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')
    . (Join-Path $script:SIRoot 'auth\SI-PlatformConnect.ps1')
    $script:GlobalNames = 'Context', 'AzureTenantId', 'HighPriv_Modern_ApplicationID_Azure', 'HighPriv_Modern_Secret_Azure', 'HighPriv_Modern_AuthMethod',
                          'HighPriv_Modern_CertificateThumbprint_Azure', 'KV_HighPriv_KeyVaultName', 'KV_HighPriv_SubscriptionId', 'AutomationFramework',
                          'SI_SPN_TenantId', 'SI_SPN_AppId', 'SI_SPN_Secret', 'SpnTenantId', 'SpnClientId', 'SpnClientSecret', 'SI_AzRestState', 'SI_LogIngestRunCache'
    function script:New-PlatformRoot([hashtable]$Cfg) {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ('lane305-plat-' + [guid]::NewGuid().ToString('N'))
        $boot = Join-Path $root 'bootstrap'; $deep = Join-Path $root 'SOLUTIONS\SecurityInsight\launcher\_lib'
        $null = New-Item -ItemType Directory -Force -Path $boot, $deep
        ($Cfg | ConvertTo-Json) | Set-Content -LiteralPath (Join-Path $boot 'platform-config.json') -Encoding UTF8
        return $root
    }
    $script:BaseCfg = @{ TenantId = 'ten-1'; SubscriptionId = 'sub-1'; KeyVaultName = 'kv-plat'; BootstrapAppId = 'boot-app'; BootstrapThumbprint = 'BB 00'; BootstrapAuth = 'Certificate' }
}

Describe 'the platform sign-in, without the platform module' {
    BeforeEach {
        $script:keep = @{}
        foreach ($n in $script:GlobalNames) { $script:keep[$n] = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue; Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue }
        $script:Reads = New-Object System.Collections.Generic.List[string]
        $script:Vault = @{ 'Modern-AppId' = 'modern-app'; 'Modern-Thumbprint' = 'AA11'; 'Modern-Secret' = 'm0dern' }
        Mock Get-SIKeyVaultSecretValue {
            $script:Reads.Add(('{0}|{1}|{2}' -f $VaultName, $Name, $(if ($Auth) { $Auth.Mode } else { 'run' })))
            if ($Auth -and $Auth.Mode -eq 'ManagedIdentity' -and $script:MiFails) { throw 'managed identity not available here' }
            if ($script:Vault.ContainsKey($Name)) { return $script:Vault[$Name] }
            return $null
        }
        $script:MiFails = $false
        $script:roots = @()
    }
    AfterEach {
        foreach ($n in $script:GlobalNames) { Set-Variable -Scope Global -Name $n -Value $script:keep[$n] }
        foreach ($r in $script:roots) { Remove-Item -LiteralPath $r -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'no platform configuration: nothing happens (a Community / standalone install) and no global is set' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ('lane305-none-' + [guid]::NewGuid().ToString('N')); $null = New-Item -ItemType Directory -Path $root; $script:roots += $root
        Connect-SIPlatform -Start $root | Should -BeNullOrEmpty
        $global:HighPriv_Modern_ApplicationID_Azure | Should -BeNullOrEmpty
        $script:Reads.Count | Should -Be 0
    }

    It 'the configuration is found walking up from the launcher, as the framework found it' {
        $root = New-PlatformRoot $script:BaseCfg; $script:roots += $root
        Find-SIPlatformConfigPath -Start (Join-Path $root 'SOLUTIONS\SecurityInsight\launcher\_lib') | Should -Be (Join-Path $root 'bootstrap\platform-config.json')
    }

    It 'certificate installed here: the Modern identity signs in by certificate, the secret is never read, the framework globals are set' {
        $root = New-PlatformRoot $script:BaseCfg; $script:roots += $root
        Mock Test-SIPlatformCertificateUsable { $Thumbprint -eq 'AA11' }
        $ctx = Connect-SIPlatform -ConfigPath (Join-Path $root 'bootstrap\platform-config.json')
        $global:HighPriv_Modern_ApplicationID_Azure | Should -Be 'modern-app'
        $global:HighPriv_Modern_CertificateThumbprint_Azure | Should -Be 'AA11'
        $global:HighPriv_Modern_Secret_Azure | Should -BeNullOrEmpty
        $global:HighPriv_Modern_AuthMethod | Should -Be 'Cert'
        $global:AzureTenantId | Should -Be 'ten-1'
        $global:KV_HighPriv_KeyVaultName | Should -Be 'kv-plat'
        $global:KV_HighPriv_SubscriptionId | Should -Be 'sub-1'
        $global:AutomationFramework | Should -BeTrue
        $global:SpnClientId | Should -Be 'modern-app'
        $ctx.Tenant.KeyVaultName | Should -Be 'kv-plat'
        $ctx.Providers.Secret | Should -Be 'KeyVault'
        $global:Context.Tenant.Id | Should -Be 'ten-1'
        @($script:Reads | Where-Object { $_ -like '*Modern-Secret*' }).Count | Should -Be 0 -Because 'the secret is not surfaced when the certificate signs in'
        @($script:Reads | Where-Object { $_ -like 'kv-plat|Modern-AppId|Certificate' }).Count | Should -Be 1 -Because 'the BOOTSTRAP identity reads the vault'
        # the run's REST sign-in is now the Modern identity, by certificate, in the platform subscription
        $c = (Get-SIAzRestState).Connection
        $c.Mode | Should -Be 'Certificate'; $c.AppId | Should -Be 'modern-app'; $c.Thumbprint | Should -Be 'AA11'; $c.TenantId | Should -Be 'ten-1'
        (Get-SIAzRestState).SubscriptionId | Should -Be 'sub-1'
    }

    It 'no usable certificate here: the client secret signs in (and the framework globals carry it)' {
        $root = New-PlatformRoot $script:BaseCfg; $script:roots += $root
        Mock Test-SIPlatformCertificateUsable { $false }
        $null = Connect-SIPlatform -ConfigPath (Join-Path $root 'bootstrap\platform-config.json') 3>$null
        $global:HighPriv_Modern_Secret_Azure | Should -Be 'm0dern'
        $global:HighPriv_Modern_CertificateThumbprint_Azure | Should -BeNullOrEmpty
        $global:HighPriv_Modern_AuthMethod | Should -Be 'Secret'
        $global:SI_SPN_Secret | Should -Be 'm0dern'
        $c = (Get-SIAzRestState).Connection
        $c.Mode | Should -Be 'Secret'; $c.AppId | Should -Be 'modern-app'; $c.Secret | Should -Be 'm0dern'
    }

    It 'no certificate and no secret: a clear error, nothing half signed in' {
        $root = New-PlatformRoot $script:BaseCfg; $script:roots += $root
        $script:Vault.Remove('Modern-Secret'); $script:Vault.Remove('Modern-Thumbprint')
        { Connect-SIPlatform -ConfigPath (Join-Path $root 'bootstrap\platform-config.json') } | Should -Throw '*no usable certificate*Modern-Secret*'
        $global:HighPriv_Modern_ApplicationID_Azure | Should -BeNullOrEmpty
    }

    It 'the vault cannot be read with any bootstrap sign-in: the error names every attempt' {
        $root = New-PlatformRoot ($script:BaseCfg.Clone() + @{}) ; $script:roots += $root
        Mock Get-SIKeyVaultSecretValue { throw 'HTTP 403 Forbidden' }
        { Connect-SIPlatform -ConfigPath (Join-Path $root 'bootstrap\platform-config.json') } | Should -Throw '*could not be read*Certificate: HTTP 403*'
    }

    It 'Auto on a host with a managed identity: the managed identity first; when it fails, the certificate (cross-tenant fall-through)' {
        $cfg = $script:BaseCfg.Clone(); $cfg.BootstrapAuth = 'Auto'
        $root = New-PlatformRoot $cfg; $script:roots += $root
        Mock Test-SIPlatformCertificateUsable { $true }
        function script:Get-SIManagedIdentityToken { 'not-used' }   # the helper counts as loaded: the mocked vault read answers
        $script:MiFails = $true
        $null = Connect-SIPlatform -ConfigPath (Join-Path $root 'bootstrap\platform-config.json') -ProbeManagedIdentity { $true }
        @($script:Reads | Where-Object { $_ -like '*|Modern-AppId|*' }) | Should -Be @('kv-plat|Modern-AppId|ManagedIdentity', 'kv-plat|Modern-AppId|Certificate')
        $global:HighPriv_Modern_ApplicationID_Azure | Should -Be 'modern-app'
    }

    It 'the bootstrap order follows BootstrapAuth' {
        $c = [pscustomobject]$script:BaseCfg
        $c.BootstrapAuth = 'Auto'
        @(Get-SIPlatformBootstrapAuths -Config $c -HasManagedIdentity $false | ForEach-Object { $_.Mode }) | Should -Be @('Certificate')
        @(Get-SIPlatformBootstrapAuths -Config $c -HasManagedIdentity $true | ForEach-Object { $_.Mode }) | Should -Be @('ManagedIdentity', 'Certificate')
        $c.BootstrapAuth = 'ManagedIdentity'
        @(Get-SIPlatformBootstrapAuths -Config $c -HasManagedIdentity $false | ForEach-Object { $_.Mode }) | Should -Be @('ManagedIdentity', 'Certificate')
        $c.BootstrapAuth = 'Certificate'
        $a = @(Get-SIPlatformBootstrapAuths -Config $c -HasManagedIdentity $true)
        @($a | ForEach-Object { $_.Mode }) | Should -Be @('Certificate')
        $a[0].Thumbprint | Should -Be 'BB00' -Because 'a thumbprint is used without spaces'
        $c.BootstrapAppId = ''
        { Get-SIPlatformBootstrapAuths -Config $c -HasManagedIdentity $false } | Should -Throw '*no usable bootstrap sign-in*'
    }

    It 'a configuration missing a required field is refused with the field named' {
        $root = New-PlatformRoot @{ TenantId = 't'; SubscriptionId = 's' }; $script:roots += $root
        { Connect-SIPlatform -ConfigPath (Join-Path $root 'bootstrap\platform-config.json') } | Should -Throw '*missing: KeyVaultName*'
    }
}

Describe 'platform secrets, read over REST' {
    BeforeEach {
        $script:keepCtx = $global:Context; $script:keepKv = $global:KV_HighPriv_KeyVaultName
        $global:Context = New-SIPlatformContext -TenantId 't' -SubscriptionId 's' -KeyVaultName 'kv-plat'
        Mock Get-SIKeyVaultSecretValue { if ($Name -eq 'SMTP-Password') { 'pw' } else { $null } }
    }
    AfterEach { $global:Context = $script:keepCtx; $global:KV_HighPriv_KeyVaultName = $script:keepKv }

    It 'Get-SIPlatformSecret reads the platform vault as the signed-in identity' {
        Get-SIPlatformSecret -Name 'SMTP-Password' -AsPlainText | Should -Be 'pw'
        [System.Net.NetworkCredential]::new('', (Get-SIPlatformSecret -Name 'SMTP-Password')).Password | Should -Be 'pw'
        Should -Invoke Get-SIKeyVaultSecretValue -ParameterFilter { $VaultName -eq 'kv-plat' -and -not $Auth }
    }
    It 'a missing secret THROWS with the wording an optional-secret catch in a configuration file recognises' {
        { Get-SIPlatformSecret -Name 'SI-StorageKey' -AsPlainText } | Should -Throw "*Get-PlatformSecret*secret 'SI-StorageKey' not found*"
    }
    It 'a configuration file written for the framework (Get-PlatformSecret -Context ...) is answered over REST' {
        (Get-Command -Name Get-PlatformSecret).CommandType | Should -Be 'Function'
        Get-PlatformSecret -Context $global:Context -Name 'SMTP-Password' -AsPlainText | Should -Be 'pw'
    }
    It 'no platform vault known in this run: a not-found error, never a sign-in prompt' {
        $global:Context = $null; $global:KV_HighPriv_KeyVaultName = $null
        { Get-SIPlatformSecret -Name 'X' } | Should -Throw '*not found*'
    }
}

Describe 'the platform sign-in file itself' {
    It 'parses on this shell, is PS 5.1 safe and loads no module' {
        $f = Join-Path $script:SIRoot 'auth\SI-PlatformConnect.ps1'
        $tok = $null; $err = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tok, [ref]$err)
        $err | Should -BeNullOrEmpty
        @($tok | Where-Object { $_.Kind -in 'QuestionDot', 'QuestionQuestion', 'QuestionQuestionEquals', 'QuestionLBracket' }).Count | Should -Be 0
        $names = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
        foreach ($n in 'Import-Module', 'Install-Module', 'Connect-AzAccount', 'Get-AzKeyVaultSecret', 'Connect-MgGraph', 'Connect-Platform') { $names | Should -Not -Contain $n }
    }
}
