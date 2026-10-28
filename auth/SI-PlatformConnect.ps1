#Requires -Version 5.1
<#
    SecurityInsight -- sign in on an INTERNAL (AutomateIT platform) install with no PowerShell module.

    The platform framework's own sign-in lives in a PowerShell module that uses the Az / Microsoft Graph modules.
    SecurityInsight runs with no modules, so it signs in to the platform itself, over plain REST, reading exactly what
    the framework reads and setting exactly what the framework sets:

      1. bootstrap\platform-config.json  (TenantId, SubscriptionId, KeyVaultName, BootstrapAppId, BootstrapThumbprint,
                                          BootstrapAuth = Auto | ManagedIdentity | Certificate)
      2. the BOOTSTRAP identity (managed identity when the host has one and it works, else its certificate) reads the
         platform Key Vault: Modern-AppId, Modern-Thumbprint (optional), Modern-Secret (only when the certificate path
         cannot be used)
      3. the run signs in as the MODERN identity: certificate when its thumbprint is in Key Vault AND the certificate is
         installed and valid here, else the secret
      4. the framework's public contract is populated -- $global:HighPriv_Modern_* , $global:AzureTenantId,
         $global:KV_HighPriv_*, $global:AutomationFramework, $global:Context, and the SI_SPN_* / Spn* aliases -- so every
         consumer of those globals keeps working unchanged.

    Get-SIPlatformSecret reads one platform Key Vault secret as the signed-in identity. A configuration file written for
    the framework calls Get-PlatformSecret; when the framework's module is not loaded (it never is, in SecurityInsight)
    a compatible Get-PlatformSecret is published that does the same over REST.

    PS 5.1 safe (no ?. / ??, no RSA.ImportFromPem); works on pwsh 7. Internal installs only -- never in the Community
    edition's code path (it runs only when bootstrap\platform-config.json exists).
#>

# NO Set-StrictMode HERE -- a dot-sourced file that sets it leaks into the caller's scope.

if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../engine/_shared/SI-AzRest.ps1') }
# The managed-identity helper is loaded only when the bootstrap sign-in is a managed identity (inside Connect-SIPlatform):
# the run's entry point owns that helper, and a run that never uses it never loads it.
$__siCertFile = Join-Path $PSScriptRoot 'Find-SICertificate.ps1'
if ((Test-Path -LiteralPath $__siCertFile) -and -not (Get-Command -Name Get-SICertificateFromStore -ErrorAction SilentlyContinue)) { . $__siCertFile }

function Test-SIPlatformConfigDisabled {
    <# True when this process must not use the machine's AutomateIT platform configuration: SI_PLATFORM_CONFIG = off
       (the guided install sets it for its run -- live 2026-10-06 on mgmt1 the platform's subscription was used). #>
    [string]([Environment]::GetEnvironmentVariable('SI_PLATFORM_CONFIG')) -match '^(?i)(off|0|false|no|disabled)$'
}

function Find-SIPlatformConfigPath {
    <# bootstrap\platform-config.json, walking up from -Start (the framework's own rule). $null when there is none. #>
    param([string]$Start = $PSScriptRoot)
    # SI_PLATFORM_CONFIG=off: this run must not use the machine's platform (the guided install sets it for its run)
    if (Test-SIPlatformConfigDisabled) { return $null }
    $cur = $Start
    while ($cur) {
        $p = [System.IO.Path]::Combine($cur, 'bootstrap', 'platform-config.json')
        if (Test-Path -LiteralPath $p) { return $p }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    return $null
}

function Read-SIPlatformConfig {
    <# The platform configuration; TenantId, SubscriptionId and KeyVaultName are required (as the framework requires). #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw ("The platform configuration was not found at {0}." -f $Path) }
    try { $cfg = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
    catch { throw ("The platform configuration {0} could not be read: {1}" -f $Path, $_.Exception.Message) }
    $missing = @('TenantId', 'SubscriptionId', 'KeyVaultName' | Where-Object { -not $cfg.PSObject.Properties[$_] -or [string]::IsNullOrWhiteSpace([string]$cfg.$_) })
    if ($missing.Count) { throw ("The platform configuration {0} is missing: {1}." -f $Path, ($missing -join ', ')) }
    return $cfg
}

function Test-SIPlatformManagedIdentityHost {
    <# Does this host have a managed-identity endpoint (a container, an Azure Arc server, or an Azure VM whose metadata
       endpoint answers within 3 seconds -- the framework's Auto probe)? -Probe is a test seam. #>
    param([scriptblock]$Probe)
    if ([Environment]::GetEnvironmentVariable('IDENTITY_ENDPOINT')) { return $true }
    if ($Probe) { return [bool](& $Probe) }
    try {
        $req = [System.Net.HttpWebRequest]::Create('http://169.254.169.254/metadata/instance?api-version=2021-02-01')
        $req.Method = 'GET'; $req.Timeout = 3000; $req.ReadWriteTimeout = 3000
        $req.Headers['Metadata'] = 'true'
        $resp = $req.GetResponse(); $resp.Close(); return $true
    } catch {
        $we = $_.Exception
        while ($we -and -not ($we -is [System.Net.WebException])) { $we = $we.InnerException }
        if ($we -and $we.Response) { try { $we.Response.Close() } catch { }; return $true }   # it answered: an endpoint exists
        return $false
    }
}

function Get-SIPlatformBootstrapAuths {
    <# PURE (given -HasManagedIdentity). The bootstrap sign-ins to try, in order: BootstrapAuth = ManagedIdentity ->
       the managed identity, then the certificate when the configuration has one (the framework's cross-tenant
       fall-through); Certificate -> the certificate; Auto -> the managed identity when the host has one, then the
       certificate. #>
    param([Parameter(Mandatory)]$Config, [bool]$HasManagedIdentity)
    $mode = if ($Config.PSObject.Properties['BootstrapAuth'] -and [string]$Config.BootstrapAuth) { [string]$Config.BootstrapAuth } else { 'Auto' }
    $appId = [string]$Config.BootstrapAppId; $thumb = ([string]$Config.BootstrapThumbprint) -replace '\s', ''
    $cert = if ($appId -and $thumb) { @{ Mode = 'Certificate'; AppId = $appId; TenantId = [string]$Config.TenantId; Thumbprint = $thumb } } else { $null }
    $mi = @{ Mode = 'ManagedIdentity'; ClientId = '' }
    $out = New-Object System.Collections.Generic.List[hashtable]
    switch -Regex ($mode) {
        '^(?i)managedidentity$' { [void]$out.Add($mi); if ($cert) { [void]$out.Add($cert) } }
        '^(?i)certificate$'     { if ($cert) { [void]$out.Add($cert) } }
        default                 { if ($HasManagedIdentity) { [void]$out.Add($mi) }; if ($cert) { [void]$out.Add($cert) } }
    }
    if ($out.Count -eq 0) {
        throw ("The platform configuration names no usable bootstrap sign-in (BootstrapAuth = {0}; BootstrapAppId / BootstrapThumbprint {1})." -f $mode, $(if ($cert) { 'set' } else { 'missing' }))
    }
    return $out.ToArray()
}

function Test-SIPlatformCertificateUsable {
    <# Is the certificate with -Thumbprint installed (LocalMachine\My or CurrentUser\My, read through X509Store -- no
       Cert: drive needed), with its private key, and valid today? -Find is a test seam returning what
       Get-SICertificateFromStore returns ({ Certificate; StoreLocation }) or a bare certificate, or $null.
       #395: Get-SICertificateFromStore returns a WRAPPER. Reading NotAfter on the wrapper gave $null, `$null -le (Get-Date)`
       is true, and every certificate -- valid until 2028 -- was reported EXPIRED: every internal install fell back to a
       client secret it does not have, and every run failed. The certificate's own properties are read, never the wrapper's. #>
    param([string]$Thumbprint, [scriptblock]$Find)
    $tp = ([string]$Thumbprint).Trim() -replace '\s', ''
    if (-not $tp) { return $false }
    $found = if ($Find) { & $Find $tp } else { Get-SICertificateFromStore -Thumbprint $tp }
    if (-not $found) { return $false }
    $c = $found
    if ($found.PSObject.Properties['Certificate'] -and $null -ne $found.Certificate) { $c = $found.Certificate }
    if (-not ($c -is [System.Security.Cryptography.X509Certificates.X509Certificate2])) {
        Write-Warning ("The platform certificate {0} could not be read from the certificate store. The client secret is used instead." -f $tp)
        return $false
    }
    if (-not $c.HasPrivateKey) {
        Write-Warning ("The platform certificate {0} is installed WITHOUT its private key, so it cannot sign in. Install it with the key; the client secret is used meanwhile." -f $tp)
        return $false
    }
    $now = Get-Date
    if ($c.NotAfter -le $now) {
        Write-Warning ("The platform certificate {0} is installed but EXPIRED on {1:yyyy-MM-dd}. Renew it; the client secret is used meanwhile." -f $tp, $c.NotAfter)
        return $false
    }
    if ($c.NotBefore -gt $now) {
        Write-Warning ("The platform certificate {0} is installed but not valid before {1:yyyy-MM-dd}. The client secret is used meanwhile." -f $tp, $c.NotBefore)
        return $false
    }
    return $true
}

function Read-SIPlatformBootstrapSecret {
    <# One platform Key Vault secret read as the BOOTSTRAP identity; $null when it does not exist. #>
    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][hashtable]$Auth)
    $v = Get-SIKeyVaultSecretValue -VaultName $VaultName -Name $Name -Auth $Auth
    if ($null -eq $v) { return $null }
    return ([string]$v).Trim()
}

function New-SIPlatformContext {
    <# The context object the framework's consumers read ($global:Context): Tenant.Id / SubscriptionId / KeyVaultName,
       Providers.Secret = 'KeyVault', Host.Kind = 'VM'. #>
    param([string]$TenantId, [string]$SubscriptionId, [string]$KeyVaultName)
    [pscustomobject]@{
        Schema       = 'AutomateIT.Context/1'
        StartedUtc   = [datetime]::UtcNow
        Host         = [pscustomobject]@{ Kind = 'VM'; ComputerName = $env:COMPUTERNAME; UserName = $env:USERNAME; PSVersion = $PSVersionTable.PSVersion.ToString() }
        Tenant       = [pscustomobject]@{ Id = $TenantId; SubscriptionId = $SubscriptionId; KeyVaultName = $KeyVaultName }
        Providers    = [pscustomobject]@{ Secret = 'KeyVault'; State = 'None'; Log = 'Stdout' }
        SignedInBy   = 'SecurityInsight'
    }
}

function Connect-SIPlatform {
    <#
        Sign in as the platform's Modern identity (see this file's header) and populate the framework's public globals.
        -ConfigPath: bootstrap\platform-config.json (default: found walking up from -Start). Returns the context, or $null
        when there is no platform configuration (a Community / standalone install -- nothing to do, as the framework's own
        back-compat entry point did). Throws when the configuration exists but the sign-in cannot be completed.
    #>
    [CmdletBinding()]
    param([string]$ConfigPath, [string]$Start = $PSScriptRoot, [scriptblock]$ProbeManagedIdentity)
    if (Test-SIPlatformConfigDisabled) { return $null }
    if (-not $ConfigPath) { $ConfigPath = Find-SIPlatformConfigPath -Start $Start }
    if (-not $ConfigPath -or -not (Test-Path -LiteralPath $ConfigPath)) { return $null }
    $cfg = Read-SIPlatformConfig -Path $ConfigPath
    $tenantId = [string]$cfg.TenantId; $subId = [string]$cfg.SubscriptionId; $kv = [string]$cfg.KeyVaultName

    $hasMi = Test-SIPlatformManagedIdentityHost -Probe $ProbeManagedIdentity
    $candidates = @(Get-SIPlatformBootstrapAuths -Config $cfg -HasManagedIdentity $hasMi)
    $boot = $null; $appId = $null; $errors = New-Object System.Collections.Generic.List[string]
    $miFile = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.ScriptBlock.File) 'SI-ManagedIdentity.ps1'
    foreach ($a in $candidates) {
        if ($a.Mode -eq 'ManagedIdentity' -and -not (Get-Command -Name Get-SIManagedIdentityToken -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $miFile)) {
            . $miFile
        }
        try {
            $appId = Read-SIPlatformBootstrapSecret -VaultName $kv -Name 'Modern-AppId' -Auth $a
            $boot = $a
            break
        } catch { [void]$errors.Add(('{0}: {1}' -f $a.Mode, $_.Exception.Message)) }
    }
    if (-not $boot) { throw ("The platform Key Vault '{0}' could not be read with the bootstrap sign-in ({1})." -f $kv, ($errors -join ' | ')) }
    if ([string]::IsNullOrWhiteSpace($appId)) { throw ("The platform Key Vault '{0}' has no 'Modern-AppId' secret (or it is empty)." -f $kv) }

    $thumb = $null
    try { $thumb = Read-SIPlatformBootstrapSecret -VaultName $kv -Name 'Modern-Thumbprint' -Auth $boot } catch { Write-Verbose ("Modern-Thumbprint not read: {0}" -f $_.Exception.Message) }
    $certOk = $false
    if ($thumb) {
        $certOk = Test-SIPlatformCertificateUsable -Thumbprint $thumb
        if (-not $certOk) { Write-Warning ("Key Vault names the platform certificate {0}, but it is not installed (and valid) on this host; signing in with the client secret instead." -f $thumb) }
    }
    $secret = $null
    if (-not $certOk) {
        $secret = Read-SIPlatformBootstrapSecret -VaultName $kv -Name 'Modern-Secret' -Auth $boot
        if ([string]::IsNullOrWhiteSpace($secret)) {
            throw ("The platform identity cannot sign in on this host: no usable certificate, and the platform Key Vault '{0}' has no 'Modern-Secret'." -f $kv)
        }
    }

    # sign in as the Modern identity (recorded; each REST call mints its token when it needs one)
    if ($certOk) {
        $null = Connect-SIAzAccount -ServicePrincipal -ApplicationId $appId -CertificateThumbprint $thumb -Tenant $tenantId -Subscription $subId
    } else {
        $cred = New-Object System.Management.Automation.PSCredential ($appId, ([System.Net.NetworkCredential]::new('', $secret).SecurePassword))
        $null = Connect-SIAzAccount -ServicePrincipal -Credential $cred -Tenant $tenantId -Subscription $subId
    }

    $ctx = New-SIPlatformContext -TenantId $tenantId -SubscriptionId $subId -KeyVaultName $kv
    # the framework's public contract -- the same names and values its own sign-in sets
    $global:Context                                     = $ctx
    $global:AzureTenantId                               = $tenantId
    $global:HighPriv_Modern_ApplicationID_Azure         = $appId
    $global:HighPriv_Modern_Secret_Azure                = $secret   # $null when the certificate signs in
    $global:HighPriv_Modern_AuthMethod                  = $(if ($certOk) { 'Cert' } else { 'Secret' })
    $global:HighPriv_Modern_CertificateThumbprint_Azure = $(if ($certOk) { $thumb } else { $null })
    $global:KV_HighPriv_KeyVaultName                    = $kv
    $global:KV_HighPriv_SubscriptionId                  = $subId
    $global:AutomationFramework                         = $true
    $global:SI_SPN_TenantId                             = $tenantId
    $global:SI_SPN_AppId                                = $appId
    $global:SI_SPN_Secret                               = $secret
    $global:SpnTenantId                                 = $tenantId
    $global:SpnClientId                                 = $appId
    $global:SpnClientSecret                             = $secret
    return $ctx
}

function Get-SIPlatformSecret {
    <# One secret from the platform Key Vault ($global:Context / $global:KV_HighPriv_KeyVaultName), read as the signed-in
       identity. THROWS when it does not exist (the framework's rule: a caller treats an optional secret as optional
       with try/catch). -AsPlainText returns a string, else a SecureString. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [switch]$AsPlainText, $Context)
    if (-not $Context) { $Context = $global:Context }
    $kv = $null
    if ($Context -and $Context.PSObject.Properties['Tenant'] -and $Context.Tenant) { $kv = [string]$Context.Tenant.KeyVaultName }
    if (-not $kv) { $kv = [string]$global:KV_HighPriv_KeyVaultName }
    if (-not $kv) { throw ("Get-PlatformSecret: no platform Key Vault is known in this run, so secret '{0}' was not found." -f $Name) }
    $v = Get-SIKeyVaultSecretValue -VaultName $kv -Name $Name
    if ($null -eq $v) { throw ("Get-PlatformSecret: secret '{0}' not found in vault '{1}'." -f $Name, $kv) }
    if ($AsPlainText) { return [string]$v }
    return [System.Net.NetworkCredential]::new('', [string]$v).SecurePassword
}

# A configuration file written for the framework calls Get-PlatformSecret -Context $global:Context -Name ... . The
# framework's module is never loaded by SecurityInsight, so the same call is answered here, over REST. Published
# globally and self-loading: configuration files are dot-sourced inside the launcher's configuration function, where
# this file's other functions may not be visible.
$global:SI_PlatformConnectFile = Join-Path $PSScriptRoot 'SI-PlatformConnect.ps1'
if (-not (Get-Command -Name Get-PlatformSecret -ErrorAction SilentlyContinue)) {
    function global:Get-PlatformSecret {
        [CmdletBinding()]
        param($Context, [Parameter(Mandatory)][string]$Name, [switch]$AsPlainText)
        if (-not (Get-Command -Name Get-SIPlatformSecret -ErrorAction SilentlyContinue)) { . $global:SI_PlatformConnectFile }
        Get-SIPlatformSecret -Name $Name -AsPlainText:$AsPlainText -Context $Context
    }
}