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
        [Parameter()] [string]$ModernAppIdSecretName  = 'Modern-AppId',
        [Parameter()] [string]$ModernSecretSecretName = 'Modern-Secret',
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
    Import-Module Az.Accounts -ErrorAction Stop -WarningAction SilentlyContinue
    Import-Module Az.KeyVault -ErrorAction Stop -WarningAction SilentlyContinue

    $current = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $current) {
        throw "Connect-PlatformModern: no active Az context. Call Connect-PlatformBootstrap first (or use Connect-Platform orchestrator)."
    }

    # ---- 3. Pull Modern AppId + Secret from KV ---------------------------
    Write-Verbose ("Connect-PlatformModern: pulling '{0}' + '{1}' from KV {2}" -f $ModernAppIdSecretName, $ModernSecretSecretName, $kvName)

    try {
        $modernAppIdSecret  = Get-AzKeyVaultSecret -VaultName $kvName -Name $ModernAppIdSecretName  -ErrorAction Stop -WarningAction SilentlyContinue
        $modernSecretSecret = Get-AzKeyVaultSecret -VaultName $kvName -Name $ModernSecretSecretName -ErrorAction Stop -WarningAction SilentlyContinue
    } catch {
        throw "Connect-PlatformModern: cannot read Modern-* secrets from KV $kvName -- $($_.Exception.Message). Verify Bootstrap SPN has 'Key Vault Secrets User' role + that Modern-AppId + Modern-Secret exist."
    }

    if (-not $modernAppIdSecret)  { throw "Connect-PlatformModern: KV secret '$ModernAppIdSecretName' not found in $kvName." }
    if (-not $modernSecretSecret) { throw "Connect-PlatformModern: KV secret '$ModernSecretSecretName' not found in $kvName." }

    $modernAppId  = $modernAppIdSecret.SecretValue  | ForEach-Object { [System.Net.NetworkCredential]::new('', $_).Password }
    $modernSecret = $modernSecretSecret.SecretValue | ForEach-Object { [System.Net.NetworkCredential]::new('', $_).Password }

    if ([string]::IsNullOrWhiteSpace($modernAppId))  { throw "Connect-PlatformModern: Modern-AppId KV secret value is empty." }
    if ([string]::IsNullOrWhiteSpace($modernSecret)) { throw "Connect-PlatformModern: Modern-Secret KV secret value is empty." }

    Write-Verbose ("Connect-PlatformModern: Modern AppId = {0}, secret length = {1}" -f $modernAppId, $modernSecret.Length)

    # ---- 4. Reconnect Az as Modern (secret-based) ------------------------
    # Use [System.Net.NetworkCredential] to build the SecureString directly --
    # avoids ConvertTo-SecureString, which lives in Microsoft.PowerShell.Security
    # and fails to load in constrained runspaces (SYSTEM scheduled tasks, certain
    # hosts) when its type data is already half-registered.
    $secureSecret = [System.Net.NetworkCredential]::new('', $modernSecret).SecurePassword
    $modernCred   = [pscredential]::new($modernAppId, $secureSecret)

    $null = Connect-AzAccount `
                -ServicePrincipal `
                -Tenant     $tenantId `
                -Credential $modernCred `
                -Subscription $subId `
                -ErrorAction Stop `
                -WarningAction SilentlyContinue
    Write-Verbose "Connect-PlatformModern: Az reconnected as Modern SPN"

    # ---- 5. Connect Mg as Modern (secret-based) --------------------------
    if (-not $SkipMgGraph) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
        try {
            Connect-MgGraph `
                -TenantId             $tenantId `
                -ClientSecretCredential $modernCred `
                -NoWelcome `
                -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            Write-Verbose "Connect-PlatformModern: Mg connected as Modern SPN"
        } catch {
            Write-Warning ("Connect-PlatformModern: Connect-MgGraph failed: {0}. Continuing -- engines that need Graph will fail at use time." -f $_.Exception.Message)
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
    $global:HighPriv_Modern_Secret_Azure                  = $modernSecret
    $global:HighPriv_Modern_CertificateThumbprint_Azure   = $null  # v2.3 = secret only
    $global:KV_HighPriv_KeyVaultName                      = $kvName
    $global:KV_HighPriv_SubscriptionId                    = $subId
    $global:AutomationFramework                           = $true

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
