function Connect-PlatformModern {
<#
.SYNOPSIS
    v2.3 Connect tier-2: pull Modern SPN credentials from KV (via active
    Bootstrap context) and reconnect Az + Mg as the high-priv Modern SPN.
    Idempotent.

.DESCRIPTION
    Second step in the v2.3 two-tier connect chain. PRESUMES
    Connect-PlatformBootstrap has already run (active Az context = Bootstrap
    SPN with KV-read access).

    Flow:
      1. Get Modern-AppId + Modern-Secret from the platform KV
      2. Build pscredential from AppId + Secret (NOT cert in v2.3 -- cert
         returns in v2.4+ once AzLogDcrIngestPS supports it)
      3. Connect-AzAccount -ServicePrincipal -Credential   (replaces Bootstrap
         context with Modern context)
      4. Connect-MgGraph -ClientSecretCredential            (Graph as Modern)
      5. Build PlatformContext via New-PlatformContext
      6. Populate v1-contract globals so existing engines keep working:
            $global:Context                                     (PlatformContext)
            $global:AzureTenantId                               (string)
            $global:HighPriv_Modern_ApplicationID_Azure         (string)
            $global:HighPriv_Modern_Secret_Azure                (string)
            $global:HighPriv_Modern_CertificateThumbprint_Azure (always $null in v2.3)
            $global:KV_HighPriv_KeyVaultName                    (string)
            $global:KV_HighPriv_SubscriptionId                  (string)
            $global:AutomationFramework                         (= $true)
      7. Optionally also seed $global:SI_SPN_* (no separate Bootstrap-Auth
         step needed -- engines call Connect-Platform via launcher Layer 1).

    Returns the PlatformContext object so callers can use it directly.

.PARAMETER ConfigPath
    Override path to platform-config.json. Default: walks up from $PSScriptRoot
    to find <repo>\bootstrap\platform-config.json. Same resolution as
    Connect-PlatformBootstrap.

.PARAMETER ModernAppIdSecretName
    KV secret name holding the Modern SPN AppId. Default: 'Modern-AppId'.

.PARAMETER ModernSecretSecretName
    KV secret name holding the Modern SPN client secret value. Default: 'Modern-Secret'.

.PARAMETER SkipMgGraph
    Skip Connect-MgGraph (when caller doesn't need Graph and wants to save the
    ~1s round-trip).

.OUTPUTS
    PSCustomObject -- the PlatformContext (same shape as New-PlatformContext output).

.EXAMPLE
    Connect-PlatformBootstrap | Out-Null
    $ctx = Connect-PlatformModern

    Two-step manual: bootstrap first, then modern. Returns PlatformContext.

.EXAMPLE
    $ctx = Connect-Platform                # one-call orchestrator (preferred)

    Recommended path -- Connect-Platform calls both tiers in order.

.NOTES
    Solution     : PlatformConfiguration / AutomateITPS
    Tier         : 2 of 2 (Modern)
    Designed by  : Morten Knudsen, 2linkIT
    Introduced   : v2.3.0
    Auth notes   : v2.3 uses CLIENT SECRET (not cert) because AzLogDcrIngestPS
                   1.6.2 only supports secret auth. v2.4+ adds cert-Modern as
                   opt-in once the LA module supports cert.
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [string]$ConfigPath,
        [Parameter()] [string]$ModernAppIdSecretName     = 'Modern-AppId',
        [Parameter()] [string]$ModernSecretSecretName    = 'Modern-Secret',
        [Parameter()] [string]$ModernThumbprintSecretName = 'Modern-Thumbprint',
        [Parameter()] [switch]$SkipMgGraph
    )

    # ---- 1. Resolve config path (same logic as Bootstrap) ----------------
    if (-not $ConfigPath) {
        $repoRoot = $PSScriptRoot
        while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'bootstrap'))) {
            $parent = Split-Path -Parent $repoRoot
            if ($parent -eq $repoRoot) { break }
            $repoRoot = $parent
        }
        if (-not $repoRoot) {
            throw "Connect-PlatformModern: cannot locate repo root from $PSScriptRoot. Pass -ConfigPath."
        }
        $ConfigPath = Join-Path $repoRoot 'bootstrap\platform-config.json'
    }

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Connect-PlatformModern: platform-config.json not found at $ConfigPath. Run Initialize-PlatformVm or Convert-V1ToPlatform first."
    }

    $cfg       = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $tenantId  = [string]$cfg.TenantId
    $subId     = [string]$cfg.SubscriptionId
    $kvName    = [string]$cfg.KeyVaultName

    # ---- 2. Verify we have an Az context (Bootstrap should have set one) -
    # No explicit Import-Module Az.Accounts / Az.KeyVault -- Get-AzContext /
    # Get-AzKeyVaultSecret auto-load on first call. Bootstrap step already
    # loaded them in nearly every code path anyway.
    $current = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $current) {
        throw "Connect-PlatformModern: no active Az context. Call Connect-PlatformBootstrap first (or use Connect-Platform orchestrator)."
    }

    # ---- 3. Pull Modern AppId (required) + try Modern-Thumbprint + Modern-Secret
    # Auth path is chosen below: CERT preferred when both the thumbprint
    # KV secret AND a matching local cert are available; secret fallback
    # only if cert path is unusable. Tenants that have run New-Platform-
    # ModernCert.ps1 -> cert path. Tenants still on the original v2.3
    # provisioning -> secret path until they migrate.
    Write-Verbose ("Connect-PlatformModern: pulling Modern identity from KV {0}" -f $kvName)

    try {
        $modernAppIdSecret = Get-AzKeyVaultSecret -VaultName $kvName -Name $ModernAppIdSecretName -ErrorAction Stop -WarningAction SilentlyContinue
    } catch {
        throw "Connect-PlatformModern: cannot read Modern-AppId from KV $kvName -- $($_.Exception.Message). Verify Bootstrap SPN has 'Key Vault Secrets User' role + that Modern-AppId exists."
    }
    if (-not $modernAppIdSecret) { throw "Connect-PlatformModern: KV secret '$ModernAppIdSecretName' not found in $kvName." }
    $modernAppId = $modernAppIdSecret.SecretValue | ForEach-Object { [System.Net.NetworkCredential]::new('', $_).Password }
    if ([string]::IsNullOrWhiteSpace($modernAppId)) { throw "Connect-PlatformModern: Modern-AppId KV secret value is empty." }

    # Try cert thumbprint (optional)
    $modernThumb = $null
    try {
        $modernThumbSecret = Get-AzKeyVaultSecret -VaultName $kvName -Name $ModernThumbprintSecretName -ErrorAction Stop -WarningAction SilentlyContinue
        if ($modernThumbSecret) {
            $modernThumb = $modernThumbSecret.SecretValue | ForEach-Object { [System.Net.NetworkCredential]::new('', $_).Password }
        }
    } catch {
        Write-Verbose ("Connect-PlatformModern: KV secret '{0}' not present -- considering secret fallback. {1}" -f $ModernThumbprintSecretName, $_.Exception.Message)
    }

    # Verify cert is installed locally + valid (cert path is only usable when
    # both conditions hold)
    #
    # 2026-08-05: the old warning said "no matching cert ... (or expired)" for EVERY failure,
    # which sent a real diagnosis down the wrong path. There are four distinct reasons this can
    # fail and they need completely different fixes:
    #   1. the cert genuinely is not installed          -> install it
    #   2. it is installed but EXPIRED                  -> renew it
    #   3. the store is not READABLE in this context    -> nothing is wrong with the cert
    #   4. KV holds a thumbprint with stray whitespace  -> fix the KV secret
    # Case 3 is the nasty one: a process that cannot see Cert:\LocalMachine\My gets an empty
    # store and an identical "no matching cert" message, so a perfectly valid cert looks missing.
    # (Observed for real: a sandboxed shell saw 0 certs while the same user in another shell saw 53.)
    # So report which case it actually is.
    $modernCertUsable = $false
    if ($modernThumb) {
        # A thumbprint with stray whitespace/newline from KV can never match a store path.
        $modernThumb = "$modernThumb".Trim()

        # 2026-08-13: a FIFTH case, and it is the one that actually cost time.
        # `Get-ChildItem Cert:\...` returns nothing for TWO different reasons: the store really is
        # empty, or the `Cert:` PROVIDER does not exist in this process. The second happens whenever
        # a Windows PowerShell 5.1 child inherits a pwsh 7 parent's PSModulePath -- it resolves
        # Microsoft.PowerShell.Security to the PS7 build, fails to load it, and loses the drive with
        # it. Measured on the dev host: Cert: drive ABSENT, Get-ChildItem 0, X509Store 121 certs,
        # same elevated user. The old code called that "stores read as EMPTY ... almost certainly a
        # context/permission problem", diagnosing a permissions problem that did not exist, and then
        # fell back to secret auth -- which a cert-only customer does not have, so the run died on
        # "Missing SPN globals" three layers away from the cause.
        # Fix: read the store through X509Store when the provider is unavailable, and name the case.
        $certProviderAvailable = [bool](Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)
        $storeReadable   = $false
        $usedX509Fallback = $false

        foreach ($store in @(
                @{ Root = 'Cert:\LocalMachine\My'; Name = 'My'; Location = 'LocalMachine' },
                @{ Root = 'Cert:\CurrentUser\My';  Name = 'My'; Location = 'CurrentUser'  })) {

            $all = @()
            if ($certProviderAvailable) {
                $all = @(Get-ChildItem -Path $store.Root -ErrorAction SilentlyContinue)
            }
            if ($all.Count -eq 0) {
                # Provider missing, or provider present but this store empty -- either way the
                # .NET store is the authority. Costs one cheap read and can only ADD certificates.
                try {
                    $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Store($store.Name, $store.Location)
                    $x509.Open('ReadOnly')
                    $all = @($x509.Certificates)
                    $x509.Close()
                    if ($all.Count -gt 0 -and -not $certProviderAvailable) { $usedX509Fallback = $true }
                } catch {
                    Write-Verbose ("Connect-PlatformModern: X509Store {0}\{1} unreadable -- {2}" -f $store.Location, $store.Name, $_.Exception.Message)
                }
            }
            if ($all.Count -gt 0) { $storeReadable = $true }
            $c = $all | Where-Object { $_.Thumbprint -eq $modernThumb } | Select-Object -First 1
            if ($c) {
                if ($c.NotAfter -gt (Get-Date)) { $modernCertUsable = $true; break }
                Write-Warning ("Connect-PlatformModern: cert {0} IS installed in {1} but EXPIRED on {2:yyyy-MM-dd}. Renew it; falling back to secret-based auth meanwhile." -f $modernThumb, $store.Root, $c.NotAfter)
            }
        }

        if ($modernCertUsable -and $usedX509Fallback) {
            Write-Warning ("Connect-PlatformModern: the 'Cert:' drive is not available in this process (typical when a Windows PowerShell 5.1 child inherits a pwsh 7 parent's PSModulePath), so the certificate stores were read via X509Store instead. Cert {0} WAS found and certificate auth proceeds -- nothing is wrong with the certificate or with this session's permissions." -f $modernThumb)
        }

        if (-not $modernCertUsable) {
            if (-not $storeReadable -and -not $certProviderAvailable) {
                Write-Warning ("Connect-PlatformModern: the 'Cert:' drive is MISSING in this process and X509Store returned no certificates either, so cert {0} could not be checked at all. The drive is normally lost when a Windows PowerShell 5.1 child inherits a pwsh 7 parent's PSModulePath -- set a 5.1 PSModulePath before launching the child. Falling back to secret-based auth." -f $modernThumb)
            } elseif (-not $storeReadable) {
                Write-Warning ("Connect-PlatformModern: BOTH certificate stores read as EMPTY in this process (the 'Cert:' drive IS available and X509Store was tried as well), so cert {0} could not be checked at all -- this is almost certainly a context/permission problem (sandboxed, restricted or non-interactive session), NOT a missing certificate. Verify with: Get-ChildItem Cert:\LocalMachine\My. Falling back to secret-based auth." -f $modernThumb)
            } else {
                Write-Warning ("Connect-PlatformModern: KV has Modern-Thumbprint = {0} but no certificate with that thumbprint exists in Cert:\LocalMachine\My or Cert:\CurrentUser\My (the stores ARE readable and were searched). Check the KV value matches an installed cert. Falling back to secret-based auth on this host." -f $modernThumb)
            }
        }
    }

    # Pull secret only if cert path won't be used (avoids surfacing the
    # secret value when cert auth is taking over)
    $modernSecret = $null
    if (-not $modernCertUsable) {
        try {
            $modernSecretSecret = Get-AzKeyVaultSecret -VaultName $kvName -Name $ModernSecretSecretName -ErrorAction Stop -WarningAction SilentlyContinue
        } catch {
            throw "Connect-PlatformModern: cert path unusable AND cannot read Modern-Secret from KV $kvName -- $($_.Exception.Message). Verify either (a) Modern-Thumbprint KV secret + local cert exists, or (b) Modern-Secret KV secret exists."
        }
        if (-not $modernSecretSecret) { throw "Connect-PlatformModern: cert path unusable AND KV secret '$ModernSecretSecretName' not found in $kvName." }
        $modernSecret = $modernSecretSecret.SecretValue | ForEach-Object { [System.Net.NetworkCredential]::new('', $_).Password }
        if ([string]::IsNullOrWhiteSpace($modernSecret)) { throw "Connect-PlatformModern: cert path unusable AND Modern-Secret KV secret value is empty." }
    }

    # ---- 4. Reconnect Az + Mg as Modern (cert preferred, secret fallback)
    if ($modernCertUsable) {
        Write-Verbose ("Connect-PlatformModern: AUTH=CERT (Modern AppId {0}, thumbprint {1})" -f $modernAppId, $modernThumb)

        $null = Connect-AzAccount `
                    -ServicePrincipal `
                    -ApplicationId         $modernAppId `
                    -CertificateThumbprint $modernThumb `
                    -TenantId              $tenantId `
                    -Subscription          $subId `
                    -ErrorAction Stop `
                    -WarningAction SilentlyContinue
        Write-Verbose "Connect-PlatformModern: Az reconnected as Modern SPN via cert"

        if (-not $SkipMgGraph) {
            # No explicit Import-Module Microsoft.Graph.Authentication --
            # Connect-MgGraph auto-loads it on first call. The previous
            # explicit import was redundant (and slow on cold sessions).
            try {
                Connect-MgGraph `
                    -TenantId              $tenantId `
                    -ClientId              $modernAppId `
                    -CertificateThumbprint $modernThumb `
                    -NoWelcome `
                    -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                Write-Verbose "Connect-PlatformModern: Mg connected as Modern SPN via cert"
            } catch {
                Write-Warning ("Connect-PlatformModern: Connect-MgGraph (cert) failed: {0}. Continuing -- engines that need Graph will fail at use time." -f $_.Exception.Message)
            }
        }
    }
    else {
        Write-Verbose ("Connect-PlatformModern: AUTH=SECRET (Modern AppId {0}, secret length {1})" -f $modernAppId, $modernSecret.Length)

        # Use [System.Net.NetworkCredential] to build the SecureString
        # directly -- avoids ConvertTo-SecureString, which lives in
        # Microsoft.PowerShell.Security and fails to load in constrained
        # runspaces (SYSTEM scheduled tasks, certain hosts) when its type
        # data is already half-registered.
        $secureSecret = [System.Net.NetworkCredential]::new('', $modernSecret).SecurePassword
        $modernCred   = [pscredential]::new($modernAppId, $secureSecret)

        $null = Connect-AzAccount `
                    -ServicePrincipal `
                    -Tenant     $tenantId `
                    -Credential $modernCred `
                    -Subscription $subId `
                    -ErrorAction Stop `
                    -WarningAction SilentlyContinue
        Write-Verbose "Connect-PlatformModern: Az reconnected as Modern SPN via secret"

        if (-not $SkipMgGraph) {
            # No explicit Import-Module Microsoft.Graph.Authentication --
            # Connect-MgGraph auto-loads it on first call. The previous
            # explicit import was redundant (and slow on cold sessions).
            try {
                Connect-MgGraph `
                    -TenantId             $tenantId `
                    -ClientSecretCredential $modernCred `
                    -NoWelcome `
                    -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                Write-Verbose "Connect-PlatformModern: Mg connected as Modern SPN via secret"
            } catch {
                Write-Warning ("Connect-PlatformModern: Connect-MgGraph (secret) failed: {0}. Continuing -- engines that need Graph will fail at use time." -f $_.Exception.Message)
            }
        }
    }

    # ---- 6. Build PlatformContext ----------------------------------------
    $ctx = New-PlatformContext `
              -TenantId       $tenantId `
              -SubscriptionId $subId `
              -KeyVaultName   $kvName `
              -SecretProvider 'KeyVault' `
              -HostKind       'VM'

    # ---- 7. Populate v1-contract globals (engines read these directly) ---
    $global:Context                                       = $ctx
    $global:AzureTenantId                                 = $tenantId
    $global:HighPriv_Modern_ApplicationID_Azure           = $modernAppId
    $global:HighPriv_Modern_Secret_Azure                  = $modernSecret  # $null when cert auth wins -- no leak when secret wasn't needed
    $global:HighPriv_Modern_AuthMethod                    = if ($modernCertUsable) { 'Cert' } else { 'Secret' }
    $global:KV_HighPriv_KeyVaultName                      = $kvName
    $global:KV_HighPriv_SubscriptionId                    = $subId
    $global:AutomationFramework                           = $true

    # ---- 7b. Cert thumbprint for cert-app-only consumers (e.g. EXO) ------
    # Set when the cert path was actually used for auth above. EXO etc read
    # this global to know whether cert-app-only is possible.
    $global:HighPriv_Modern_CertificateThumbprint_Azure = if ($modernCertUsable) { $modernThumb } else { $null }

    # SI-specific aliases (some engines read SI_SPN_* directly)
    $global:SI_SPN_TenantId                               = $tenantId
    $global:SI_SPN_AppId                                  = $modernAppId
    $global:SI_SPN_Secret                                 = $modernSecret
    $global:SpnTenantId                                   = $tenantId
    $global:SpnClientId                                   = $modernAppId
    $global:SpnClientSecret                               = $modernSecret

    Write-Verbose "Connect-PlatformModern: v1-contract globals populated"

    # Discard plain-text secret variable from local scope (still in $global:* though).
    Remove-Variable modernSecret, secureSecret, modernCred -ErrorAction SilentlyContinue

    return $ctx
}
