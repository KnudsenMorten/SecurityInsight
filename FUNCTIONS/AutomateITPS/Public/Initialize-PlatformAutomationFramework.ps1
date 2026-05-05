function Initialize-PlatformAutomationFramework {
<#
.SYNOPSIS
    v2 replacement for the v1 Connect_Azure.ps1 + Automation-ConnectDetails.psm1
    bootstrap chain. One call from the AutomationFramework branch of an engine
    (or from an internal-vm launcher) and the engine can rely on the v1-contract
    $global:HighPriv_* names and an authenticated Az context.

.DESCRIPTION
    Flow:
      1. Resolve configuration (params > environment variables > config file).
      2. Connect-AzAccount as the bootstrap (KV-read) SPN using its cert in the
         local Windows cert store.
      3. Set-AzContext to the KV subscription.
      4. Build a PlatformContext via New-PlatformContext.
      5. Call Initialize-PlatformIdentity to pull the Modern secrets from KV
         (Modern-{Azure,O365,ResourceOnBoarding,LogIngestion}).
      6. Populate the v1-contract $global:HighPriv_* names from the context so
         engines that reference those global names keep working -- without
         depending on any v1 module file.
      7. Reconnect as the Modern-Azure SPN (full platform access) so the engine
         has the right token identity when it starts doing work.

    Returns the PlatformContext so callers can use it directly.

.PARAMETER TenantId
    Entra tenant id. Falls back to $env:PLATFORM_TENANT_ID, then the config file.

.PARAMETER SubscriptionId
    Subscription that hosts the platform Key Vault. Falls back to
    $env:PLATFORM_SUBSCRIPTION_ID, then config file.

.PARAMETER KeyVaultName
    Name of the platform Key Vault (short name, not URI). Falls back to
    $env:PLATFORM_KEYVAULT, then config file.

.PARAMETER BootstrapAppId
    Client id of the bootstrap (KV-read-only) SPN. Falls back to
    $env:PLATFORM_BOOTSTRAP_APPID, then config file.

.PARAMETER BootstrapThumbprint
    Thumbprint of the bootstrap SPN cert in the LOCAL cert store (CurrentUser\My
    or LocalMachine\My). Falls back to $env:PLATFORM_BOOTSTRAP_THUMBPRINT, then
    config file.

.PARAMETER ConfigPath
    Path to a JSON config file holding the five values above. Defaults to
    $env:USERPROFILE\.automateit\platform-config.json.

.PARAMETER SkipModernReconnect
    Skip step 7 (the reconnect as Modern-Azure). Use this if the engine does its
    own Connect-AzAccount later.

.PARAMETER IgnoreMissingSecrets
    Passed through to Initialize-PlatformIdentity. Useful on tenants that do not
    have every Modern-* secret populated (e.g. no LogIngestion DCR yet).

.OUTPUTS
    PSCustomObject -- the PlatformContext (same shape as New-PlatformContext).

.EXAMPLE
    # Engine -- AutomationFramework branch (v2 pattern, no v1 imports):
    $ctx = Initialize-PlatformAutomationFramework
    $global:SpnTenantId     = $global:AzureTenantId
    $global:SpnClientId     = $global:HighPriv_Modern_ApplicationID_Azure
    $global:SpnClientSecret = $global:HighPriv_Modern_Secret_Azure
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$TenantId,
        [string]$SubscriptionId,
        [string]$KeyVaultName,
        [string]$BootstrapAppId,
        [string]$BootstrapThumbprint,
        [string]$ConfigPath,
        [switch]$SkipModernReconnect,
        [switch]$IgnoreMissingSecrets
    )

    # ---- 1. Resolve configuration --------------------------------------
    # Lookup order for the JSON config file (first existing wins):
    #   1. -ConfigPath param (explicit caller override)
    #   2. <install>/SOLUTIONS/PlatformConfiguration/config/platform-config.json
    #      -- derived from this script's location ($PSScriptRoot is
    #      <install>/FUNCTIONS/AutomateITPS/Public, walk up 3). Lives next to
    #      platform-defaults.ps1 -- canonical install-relative path that
    #      works under SYSTEM context, scheduled tasks, VisualCron, etc.
    #      (no per-user dependency).
    #   3. $env:USERPROFILE/.automateit/platform-config.json
    #      -- legacy per-user fallback. Works for interactive ops on a dev
    #      box; doesn't help SYSTEM-context jobs.
    if (-not $ConfigPath) {
        $candidates = @()
        try {
            $installRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
            $candidates += (Join-Path $installRoot 'SOLUTIONS\PlatformConfiguration\config\platform-config.json')
        } catch { }
        $candidates += (Join-Path $env:USERPROFILE '.automateit\platform-config.json')
        $ConfigPath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not $ConfigPath) { $ConfigPath = $candidates[0] }   # use first candidate in error messages
    }
    $fileCfg = $null
    if (Test-Path -LiteralPath $ConfigPath) {
        try {
            $fileCfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        } catch {
            Write-Warning "Initialize-PlatformAutomationFramework: could not parse '$ConfigPath': $($_.Exception.Message)"
        }
    }

    # PS 5.1-safe env-var lookup across Process + User + Machine scopes.
    # (Newly-set Machine scope values are not inherited by already-running
    # processes, so we must check scopes explicitly.)
    $GetEnv = {
        param([string]$Name)
        $v = [Environment]::GetEnvironmentVariable($Name, 'Process')
        if ($v) { return $v }
        $v = [Environment]::GetEnvironmentVariable($Name, 'User')
        if ($v) { return $v }
        [Environment]::GetEnvironmentVariable($Name, 'Machine')
    }

    # Inline resolution: param > env > file.
    if (-not $TenantId)            { $TenantId            = & $GetEnv 'PLATFORM_TENANT_ID' }
    if (-not $TenantId -and $fileCfg -and $fileCfg.PSObject.Properties.Name -contains 'TenantId') { $TenantId = [string]$fileCfg.TenantId }

    if (-not $SubscriptionId)      { $SubscriptionId      = & $GetEnv 'PLATFORM_SUBSCRIPTION_ID' }
    if (-not $SubscriptionId -and $fileCfg -and $fileCfg.PSObject.Properties.Name -contains 'SubscriptionId') { $SubscriptionId = [string]$fileCfg.SubscriptionId }

    if (-not $KeyVaultName)        { $KeyVaultName        = & $GetEnv 'PLATFORM_KEYVAULT' }
    if (-not $KeyVaultName -and $fileCfg -and $fileCfg.PSObject.Properties.Name -contains 'KeyVaultName') { $KeyVaultName = [string]$fileCfg.KeyVaultName }

    if (-not $BootstrapAppId)      { $BootstrapAppId      = & $GetEnv 'PLATFORM_BOOTSTRAP_APPID' }
    if (-not $BootstrapAppId -and $fileCfg -and $fileCfg.PSObject.Properties.Name -contains 'BootstrapAppId') { $BootstrapAppId = [string]$fileCfg.BootstrapAppId }

    if (-not $BootstrapThumbprint) { $BootstrapThumbprint = & $GetEnv 'PLATFORM_BOOTSTRAP_THUMBPRINT' }
    if (-not $BootstrapThumbprint -and $fileCfg -and $fileCfg.PSObject.Properties.Name -contains 'BootstrapThumbprint') { $BootstrapThumbprint = [string]$fileCfg.BootstrapThumbprint }

    $missing = @()
    if (-not $TenantId)            { $missing += 'TenantId' }
    if (-not $SubscriptionId)      { $missing += 'SubscriptionId' }
    if (-not $KeyVaultName)        { $missing += 'KeyVaultName' }
    if (-not $BootstrapAppId)      { $missing += 'BootstrapAppId' }
    if (-not $BootstrapThumbprint) { $missing += 'BootstrapThumbprint' }
    if ($missing.Count -gt 0) {
        throw ("Initialize-PlatformAutomationFramework: missing config -- {0}. Provide via parameters, env vars (PLATFORM_*), or {1}." -f ($missing -join ', '), $ConfigPath)
    }

    # ---- 2. Connect as bootstrap SPN (cert-based) ----------------------
    Import-Module Az.Accounts  -Global -Force:$false -WarningAction SilentlyContinue -ErrorAction Stop
    Import-Module Az.KeyVault  -Global -Force:$false -WarningAction SilentlyContinue -ErrorAction Stop

    Write-Verbose ("Connecting as bootstrap SPN {0} via cert {1}" -f $BootstrapAppId, $BootstrapThumbprint)
    Connect-AzAccount -ServicePrincipal `
        -ApplicationId         $BootstrapAppId `
        -CertificateThumbprint $BootstrapThumbprint `
        -TenantId              $TenantId `
        -WarningAction         SilentlyContinue `
        -ErrorAction           Stop | Out-Null

    # ---- 3. Set subscription context -----------------------------------
    Set-AzContext -SubscriptionId $SubscriptionId -Tenant $TenantId -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null

    # ---- 4. Build PlatformContext --------------------------------------
    $ctx = New-PlatformContext `
        -TenantId       $TenantId `
        -SubscriptionId $SubscriptionId `
        -KeyVaultName   $KeyVaultName `
        -HostKind       'VM'

    # ---- 5. Fetch Modern secrets from KV -------------------------------
    $ctx = Initialize-PlatformIdentity -Context $ctx -IgnoreMissing:$IgnoreMissingSecrets

    # ---- 6. Populate v1-contract $global:* names -----------------------
    $global:AzureTenantId                      = $TenantId
    $global:KV_HighPriv_SubscriptionId         = $SubscriptionId
    $global:KV_HighPriv_KeyVaultName           = $KeyVaultName

    # TenantNameOrganization is needed by Connect-ExchangeOnline -Organization
    # and by a few Graph helpers. Comes from env PLATFORM_TENANT_DOMAIN or
    # the platform-config.json TenantDomain field (Layer 1 may also override
    # later when platform-defaults.ps1 dot-sources).
    $tenantDomain = & $GetEnv 'PLATFORM_TENANT_DOMAIN'
    if (-not $tenantDomain -and $fileCfg -and $fileCfg.PSObject.Properties.Name -contains 'TenantDomain') { $tenantDomain = [string]$fileCfg.TenantDomain }
    if ($tenantDomain) {
        $global:TenantNameOrganization = $tenantDomain
        $global:TenantDomain           = $tenantDomain
    }

    # Helper: a Modern secret sits in $ctx.Identity.Modern.<Class>.Secret as
    # a SecureString. Marshal back to plain text (PS 5.1 compatible -- do not
    # use ConvertFrom-SecureString -AsPlainText which is PS7+).
    function _SecureToPlain([securestring]$ss) {
        if (-not $ss) { return $null }
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
        try   { [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }

    foreach ($pair in @(
        @{ Class = 'Azure';              Prefix = 'HighPriv_Modern'; Suffix = 'Azure' },
        @{ Class = 'O365';               Prefix = 'HighPriv_Modern'; Suffix = 'O365' },
        @{ Class = 'ResourceOnBoarding'; Prefix = 'HighPriv_Modern'; Suffix = 'ResourceOnBoarding' },
        @{ Class = 'LogIngestionDCR';    Prefix = 'HighPriv_Modern'; Suffix = 'LogIngestion_DCR' }
    )) {
        $node = $ctx.Identity.Modern.($pair.Class)
        if (-not $node) { continue }
        $appIdVar = ('{0}_ApplicationID_{1}' -f $pair.Prefix, $pair.Suffix)
        $thumbVar = ('{0}_CertificateThumbprint_{1}' -f $pair.Prefix, $pair.Suffix)
        $secVar   = ('{0}_Secret_{1}'   -f $pair.Prefix, $pair.Suffix)
        $secSecVar= ('{0}_Secret_{1}_Secure' -f $pair.Prefix, $pair.Suffix)

        if ($node.AppId)      { Set-Variable -Name $appIdVar -Scope Global -Value ([string]$node.AppId) }
        if ($node.Thumbprint) { Set-Variable -Name $thumbVar -Scope Global -Value ([string]$node.Thumbprint) }
        if ($node.Secret)     {
            Set-Variable -Name $secVar    -Scope Global -Value (_SecureToPlain $node.Secret)
            Set-Variable -Name $secSecVar -Scope Global -Value $node.Secret
        }
    }

    # ---- 6a. Fetch Legacy credentials + populate v1-contract globals ---
    # Many ported engines still read $global:HighPriv_Legacy_SecureCredentials_*
    # for on-prem AD / WinRM / RDP auth. Initialize-PlatformLegacyIdentity
    # fetches the user/password pairs from KV and writes them to
    # $Context.Identity.Legacy.*. Convert those into the v1-named globals.
    try {
        $ctx = Initialize-PlatformLegacyIdentity -Context $ctx -IgnoreMissing:$IgnoreMissingSecrets
    } catch {
        Write-Warning ("Initialize-PlatformLegacyIdentity failed (legacy creds unavailable): {0}" -f $_.Exception.Message)
    }

    # Legacy.Internal.Prod, Legacy.Internal.Dev, Legacy.Internal.Test,
    # Legacy.DMZ.Prod, Legacy.ResourceOnBoarding.InternalProd / DMZProd /
    # InternalDev / InternalTest, Legacy.ProvisionVMLocalAdmin
    $legacyMap = @(
        @{ Path = 'Internal.Prod';                     Var = 'HighPriv_Legacy_SecureCredentials_Internal_Prod' },
        @{ Path = 'Internal.Dev';                      Var = 'HighPriv_Legacy_SecureCredentials_Internal_Dev' },
        @{ Path = 'Internal.Test';                     Var = 'HighPriv_Legacy_SecureCredentials_Internal_Test' },
        @{ Path = 'DMZ.Prod';                          Var = 'HighPriv_Legacy_SecureCredentials_DMZ_Prod' },
        @{ Path = 'ResourceOnBoarding.InternalProd';   Var = 'HighPriv_Legacy_SecureCredentials_RessourceOnBoarding_Internal_Prod' },
        @{ Path = 'ResourceOnBoarding.DMZProd';        Var = 'HighPriv_Legacy_SecureCredentials_RessourceOnBoarding_DMZ_Prod' },
        @{ Path = 'ResourceOnBoarding.InternalDev';    Var = 'HighPriv_Legacy_SecureCredentials_RessourceOnBoarding_Internal_Dev' },
        @{ Path = 'ResourceOnBoarding.InternalTest';   Var = 'HighPriv_Legacy_SecureCredentials_RessourceOnBoarding_Internal_Test' },
        @{ Path = 'ProvisionVMLocalAdmin';             Var = 'HighPriv_Provision_Azure_VM_LocalAdmin_Credential' }
    )
    foreach ($mapping in $legacyMap) {
        $node = $ctx.Identity.Legacy
        foreach ($seg in ($mapping.Path -split '\.')) {
            if (-not $node) { break }
            $node = $node.$seg
        }
        if ($node -is [System.Management.Automation.PSCredential]) {
            # Skip gMSA-style usernames -- group Managed Service Accounts cannot
            # authenticate via a stored-password PSCredential. Their password is
            # rotated by AD every 30 days and is only retrievable by the host
            # that the gMSA is installed on, via Get-ADServiceAccount. Engines
            # that ran the v1 way (as a scheduled task running AS the gMSA)
            # got their auth from the calling token, not the -Credential
            # parameter. v2 leaves the global $null so engine code takes its
            # "no credential" branch (uses current user context, which is
            # appropriate for either gMSA-as-host or admin-interactive).
            if ($node.UserName -match '\\gMSA[-_]' -or $node.UserName -match '^gMSA[-_]') {
                Write-Verbose ("Skipping gMSA credential for {0} (username '{1}'); engine will use current user context." -f $mapping.Var, $node.UserName)
                continue
            }
            Set-Variable -Name $mapping.Var -Scope Global -Value $node
        }
    }

    # ---- 6a.bis Populate SMTP credentials from KV --------------------------
    # Mirrors the legacy v1 Connect_Azure.ps1 behaviour (lines 331-337): fetch
    # KV secrets 'SMTPuser' + 'SMTPpassword' and expose them as the globals
    # every mail-sending engine knows about:
    #   $global:HighPriv_SMTP_UserName / $global:HighPriv_SMTP_Password  (v1 names)
    #   $global:SMTPUser               / $global:SMTPPassword             (canonical)
    #   $global:SecureCredentialsSMTP                                     (PSCredential)
    # KV secret names are case-insensitive so 'SMTPuser' == 'SMTPUser'.
    #
    # IgnoreMissingSecrets semantics: if either secret is absent (dev tenant that
    # hasn't seeded SMTP), we leave the globals $null so downstream code can
    # fall back to $global:Mail_SendAnonymous or throw a clearer error.
    try {
        $__smtpUserSecret = $null
        $__smtpPassSecret = $null
        try { $__smtpUserSecret = Get-PlatformSecret -Context $ctx -Name 'SMTPuser'     -AsPlainText -ErrorAction Stop } catch { }
        try { $__smtpPassSecret = Get-PlatformSecret -Context $ctx -Name 'SMTPpassword' -AsPlainText -ErrorAction Stop } catch { }
        if ($__smtpUserSecret -and $__smtpPassSecret) {
            # v1 names (some legacy engines still read these)
            Set-Variable -Name 'HighPriv_SMTP_UserName' -Scope Global -Value $__smtpUserSecret
            Set-Variable -Name 'HighPriv_SMTP_Password' -Scope Global -Value $__smtpPassSecret
            # Canonical names (SecurityInsight engines + most v2 engines read these)
            Set-Variable -Name 'SMTPUser'     -Scope Global -Value $__smtpUserSecret
            Set-Variable -Name 'SMTPPassword' -Scope Global -Value $__smtpPassSecret
            # Pre-built PSCredential (engines that prefer a credential object)
            try {
                $__smtpSecure = ConvertTo-SecureString $__smtpPassSecret -AsPlainText -Force -ErrorAction Stop
                Set-Variable -Name 'SecureCredentialsSMTP' -Scope Global -Value (
                    New-Object System.Management.Automation.PSCredential($__smtpUserSecret, $__smtpSecure)
                )
            } catch { Write-Verbose "Could not build `$global:SecureCredentialsSMTP: $($_.Exception.Message)" }
            Write-Verbose "Populated SMTP globals from KV secrets 'SMTPuser' / 'SMTPpassword'."
        } elseif (-not $IgnoreMissingSecrets) {
            Write-Warning "SMTP credentials not found in KV (secrets 'SMTPuser' / 'SMTPpassword'). Engines that send mail with Mail_SendAnonymous=`$false will need them set another way."
        }
    } catch {
        Write-Warning ("Failed to populate SMTP globals from KV: {0}" -f $_.Exception.Message)
    }

    # ---- 6b. Load Layer-1 platform-wide defaults -----------------------
    # Dot-sources SOLUTIONS\PlatformConfiguration\CUSTOMDATA\platform-defaults.ps1
    # (customer-owned, gitignored) so every engine that called this bootstrap
    # automatically has the shared $global:Mail_*, $global:*LogAnalytics*,
    # $global:AD_*, $global:AzMGPolicy_*, ... available. Missing file is not
    # an error -- an engine that needs those values will fail later with a
    # clearer message.
    try {
        Initialize-PlatformDefaults -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Warning ("Initialize-PlatformDefaults failed: {0}" -f $_.Exception.Message)
    }

    # ---- 7. Reconnect as Modern-Azure SPN ------------------------------
    if (-not $SkipModernReconnect) {
        $modernAppId     = $ctx.Identity.Modern.Azure.AppId
        $modernThumb     = $ctx.Identity.Modern.Azure.Thumbprint
        $modernSecretSS  = $ctx.Identity.Modern.Azure.Secret
        if ($modernAppId -and $modernThumb) {
            Write-Verbose 'Reconnecting as Modern-Azure SPN via certificate'
            Disconnect-AzAccount -WarningAction SilentlyContinue | Out-Null
            Connect-AzAccount -ServicePrincipal `
                -ApplicationId         $modernAppId `
                -CertificateThumbprint $modernThumb `
                -TenantId              $TenantId `
                -WarningAction         SilentlyContinue `
                -ErrorAction           Stop | Out-Null
            Set-AzContext -SubscriptionId $SubscriptionId -Tenant $TenantId -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
        }
        elseif ($modernAppId -and $modernSecretSS) {
            Write-Verbose 'Reconnecting as Modern-Azure SPN via secret'
            Disconnect-AzAccount -WarningAction SilentlyContinue | Out-Null
            $cred = New-Object System.Management.Automation.PSCredential ($modernAppId, $modernSecretSS)
            Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred `
                -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
            Set-AzContext -SubscriptionId $SubscriptionId -Tenant $TenantId -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
        }
    }

    # ---- 8. Connect to Microsoft Graph (Modern-O365 SPN preferred) -----
    # Engines that use Get-Mg* / Get-MgBeta* cmdlets need an explicit
    # Connect-MgGraph. Prefer the Modern-O365 SPN (it is the one the v1
    # platform granted Graph permissions to). Fall back to Modern-Azure if
    # O365 secrets aren't set (some tenants only provision the Azure SPN).
    try {
        if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
            Write-Verbose 'Microsoft.Graph.Authentication not available; skipping Connect-MgGraph.'
        } else {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue

            $graphAppId  = $ctx.Identity.Modern.O365.AppId
            $graphThumb  = $ctx.Identity.Modern.O365.Thumbprint
            $graphSecret = $ctx.Identity.Modern.O365.Secret
            if (-not $graphAppId) {
                $graphAppId  = $ctx.Identity.Modern.Azure.AppId
                $graphThumb  = $ctx.Identity.Modern.Azure.Thumbprint
                $graphSecret = $ctx.Identity.Modern.Azure.Secret
            }

            if ($graphAppId -and $graphThumb) {
                Write-Verbose 'Connecting to Microsoft Graph via certificate'
                Connect-MgGraph -TenantId $TenantId `
                    -ClientId               $graphAppId `
                    -CertificateThumbprint  $graphThumb `
                    -NoWelcome `
                    -WarningAction          SilentlyContinue `
                    -ErrorAction            Stop | Out-Null
            }
            elseif ($graphAppId -and $graphSecret) {
                Write-Verbose 'Connecting to Microsoft Graph via secret'
                $cred = New-Object System.Management.Automation.PSCredential ($graphAppId, $graphSecret)
                Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $cred `
                    -NoWelcome -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
            }
        }
    } catch {
        Write-Warning ("Connect-MgGraph failed: {0}" -f $_.Exception.Message)
    }

    return $ctx
}
