function Connect-PlatformBootstrap {
<#
.SYNOPSIS
    v2.3 Connect tier-1: authenticate the Bootstrap identity to the platform
    Key Vault. Supports Managed Identity (Azure-hosted compute) and Certificate
    SPN (on-prem / anywhere). Idempotent. Returns the Az context.

.DESCRIPTION
    First step in the v2.3 two-tier connect chain:

      Connect-PlatformBootstrap   <-- THIS function (KV-read-only role)
            |
            v
      Connect-PlatformModern      (pulls Modern-AppId + Modern-Secret from KV,
                                   reconnects as the high-priv Modern SPN)

    Three auth methods (chosen via platform-config.json `BootstrapAuth` field
    or -AuthMethod parameter):

      'ManagedIdentity'  Connect-AzAccount -Identity. Requires Azure-hosted
                         compute (Azure VM / Container Apps Job / Function /
                         App Service / Arc-enabled server) with system-assigned
                         MI enabled and granted 'Key Vault Secrets User' on
                         the platform KV.

      'Certificate'      Connect-AzAccount -ServicePrincipal -CertificateThumb-
                         print. Cert must exist in LocalMachine\My or
                         CurrentUser\My. Works anywhere (on-prem VMs,
                         Hybrid Workers, anywhere with a cert store).

      'Auto' (default)   Probes IMDS endpoint (169.254.169.254) with 3s
                         timeout. Reachable = ManagedIdentity. Otherwise
                         falls back to Certificate (requires BootstrapAppId
                         + BootstrapThumbprint in platform-config.json).

    Bootstrap identity (whichever method) should have ONLY:
      - 'Key Vault Secrets User' role on the platform Key Vault
      - No other Azure RBAC, no Graph perms
    Min-privilege gate -- if the bootstrap creds leak, blast radius is "read
    all platform KV secrets," nothing else.

.PARAMETER ConfigPath
    Override path to platform-config.json. Default: <repo-root>\bootstrap\
    platform-config.json (auto-resolved by walking up from $PSScriptRoot).

.PARAMETER AuthMethod
    Override the BootstrapAuth from platform-config.json. Useful for testing
    a different auth on the same install. Values: 'Auto' (default),
    'ManagedIdentity', 'Certificate'.

.PARAMETER PassThru
    Return the Az.Accounts context object. Default: $true.

.OUTPUTS
    Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext when
    -PassThru is set (default). Otherwise $null.

.EXAMPLE
    Connect-PlatformBootstrap

    Reads platform-config.json, picks auth per the BootstrapAuth field
    ('Auto' = MI if available, else cert), connects, returns Az context.

.EXAMPLE
    Connect-PlatformBootstrap -AuthMethod ManagedIdentity

    Force MI mode (fails fast if IMDS unreachable / MI not granted on KV).

.NOTES
    Solution     : PlatformConfiguration / AutomateITPS
    Tier         : 1 of 2 (Bootstrap)
    Designed by  : Morten Knudsen, 2linkIT
    Introduced   : v2.3.0  (cert)
    Updated      : v2.3.1  (+ ManagedIdentity, + Auto)
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [ValidateSet('Auto','ManagedIdentity','Certificate')]
        [string]$AuthMethod,

        [Parameter()]
        [switch]$PassThru = $true
    )

    # ---- 1. Resolve config path -------------------------------------------
    if (-not $ConfigPath) {
        $repoRoot = $PSScriptRoot
        while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'bootstrap'))) {
            $parent = Split-Path -Parent $repoRoot
            if ($parent -eq $repoRoot) { break }
            $repoRoot = $parent
        }
        if (-not $repoRoot) {
            throw "Connect-PlatformBootstrap: cannot locate repo root (no 'bootstrap' folder up the tree from $PSScriptRoot). Pass -ConfigPath explicitly."
        }
        $ConfigPath = Join-Path $repoRoot 'bootstrap\platform-config.json'
    }

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Connect-PlatformBootstrap: platform-config.json not found at $ConfigPath. Run Initialize-PlatformVm or Convert-V1ToPlatform to generate it."
    }

    # ---- 2. Parse + validate (only TenantId/Sub/KV always required) ------
    try {
        $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    } catch {
        throw "Connect-PlatformBootstrap: failed to parse $ConfigPath -- $($_.Exception.Message)"
    }

    $alwaysRequired = 'TenantId','SubscriptionId','KeyVaultName'
    $missing = @()
    foreach ($k in $alwaysRequired) {
        $v = $cfg.PSObject.Properties[$k].Value
        if ([string]::IsNullOrWhiteSpace([string]$v)) { $missing += $k }
    }
    if ($missing.Count -gt 0) {
        throw "Connect-PlatformBootstrap: platform-config.json missing required fields: $($missing -join ', '). Path: $ConfigPath"
    }

    $tenantId  = [string]$cfg.TenantId
    $subId     = [string]$cfg.SubscriptionId
    $kvName    = [string]$cfg.KeyVaultName
    $appId     = [string]$cfg.BootstrapAppId
    $thumb     = [string]$cfg.BootstrapThumbprint

    # ---- 3. Resolve auth method -------------------------------------------
    if (-not $AuthMethod) {
        $AuthMethod = if ($cfg.PSObject.Properties['BootstrapAuth']) { [string]$cfg.BootstrapAuth } else { 'Auto' }
        if (-not $AuthMethod) { $AuthMethod = 'Auto' }
    }
    Write-Verbose ("Connect-PlatformBootstrap: requested AuthMethod = {0}" -f $AuthMethod)

    if ($AuthMethod -eq 'Auto') {
        # Probe BOTH MI metadata endpoints:
        #   - Azure VM/Container/Function IMDS:   169.254.169.254
        #   - Azure Arc-enabled on-prem (HIMDS):  localhost:40342
        # Either reachable = MI available.
        $miSource = $null

        # 1. Azure-native IMDS
        try {
            $null = Invoke-RestMethod `
                        -Method  Get `
                        -Uri     'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net' `
                        -Headers @{ Metadata = 'true' } `
                        -TimeoutSec 3 `
                        -ErrorAction Stop
            $miSource = 'IMDS (Azure-hosted)'
        } catch {
            # 2. Arc HIMDS (returns 401 with a WWW-Authenticate challenge -- which is success for "Arc agent is running here")
            try {
                $null = Invoke-WebRequest `
                            -Method   Get `
                            -Uri      'http://localhost:40342/metadata/identity/oauth2/token?api-version=2019-11-01&resource=https://vault.azure.net' `
                            -Headers  @{ Metadata = 'true' } `
                            -TimeoutSec 3 `
                            -UseBasicParsing `
                            -ErrorAction Stop
                $miSource = 'HIMDS (Arc on-prem)'
            } catch {
                # Arc returns 401 challenge intentionally on the first call -- treat 401 as "Arc agent present"
                if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) {
                    $miSource = 'HIMDS (Arc on-prem)'
                }
            }
        }

        if ($miSource) {
            $AuthMethod = 'ManagedIdentity'
            Write-Verbose ("Connect-PlatformBootstrap: MI metadata reachable via {0} -> Auto resolved to ManagedIdentity" -f $miSource)
        } else {
            $AuthMethod = 'Certificate'
            Write-Verbose "Connect-PlatformBootstrap: no IMDS/HIMDS reachable -> Auto resolved to Certificate"
        }
    }

    Import-Module Az.Accounts -ErrorAction Stop -WarningAction SilentlyContinue
    Import-Module Az.KeyVault -ErrorAction Stop -WarningAction SilentlyContinue

    # ---- 4. Connect per resolved method ----------------------------------
    # Certificate auth is hoisted into a script block so the MI branch can invoke
    # it as a cross-tenant fallback (Auto-mode contract: "MI if reachable AND
    # works; else cert"). Returns the Az context object.
    $connectCert = {
        if ([string]::IsNullOrWhiteSpace($appId) -or [string]::IsNullOrWhiteSpace($thumb)) {
            throw "Connect-PlatformBootstrap: AuthMethod=Certificate but BootstrapAppId / BootstrapThumbprint missing from $ConfigPath. Run Initialize-PlatformVm without -BootstrapAuth ManagedIdentity, or set BootstrapAuth='ManagedIdentity' in the config."
        }

        $certPath = "Cert:\LocalMachine\My\$thumb"
        $cert     = Get-Item -LiteralPath $certPath -ErrorAction SilentlyContinue
        if (-not $cert) {
            $certPath = "Cert:\CurrentUser\My\$thumb"
            $cert     = Get-Item -LiteralPath $certPath -ErrorAction SilentlyContinue
        }
        if (-not $cert) {
            throw "Connect-PlatformBootstrap: Bootstrap cert with thumbprint $thumb not found in LocalMachine\My or CurrentUser\My. Install the cert before connecting."
        }
        if ($cert.NotAfter -lt (Get-Date)) {
            throw "Connect-PlatformBootstrap: Bootstrap cert with thumbprint $thumb expired on $($cert.NotAfter.ToString('u')). Rotate via Update-PlatformBootstrapCert."
        }
        Write-Verbose ("Connect-PlatformBootstrap: cert OK ({0}, expires {1:u})" -f $cert.Subject, $cert.NotAfter)

        $ctx = Connect-AzAccount `
                    -ServicePrincipal `
                    -ApplicationId         $appId `
                    -CertificateThumbprint $thumb `
                    -TenantId              $tenantId `
                    -Subscription          $subId `
                    -ErrorAction Stop `
                    -WarningAction SilentlyContinue
        Write-Verbose ("Connect-PlatformBootstrap: Az context = {0} (cert, tenant {1}, sub {2})" -f $ctx.Context.Account.Id, $tenantId, $subId)
        return $ctx
    }

    switch ($AuthMethod) {

        'ManagedIdentity' {
            Write-Verbose "Connect-PlatformBootstrap: connecting via Managed Identity"
            $miFailed = $false ; $miError = $null
            try {
                $azContext = Connect-AzAccount `
                                -Identity `
                                -Tenant       $tenantId `
                                -Subscription $subId `
                                -ErrorAction Stop `
                                -WarningAction SilentlyContinue
            } catch {
                $miFailed = $true ; $miError = $_.Exception.Message
            }

            # Cross-tenant fall-through: IMDS reachable (Auto picked MI) but the
            # local VM's MI lives in a DIFFERENT tenant than $tenantId, so
            # Connect-AzAccount -Identity throws "does not have access to
            # subscription...". If the config has cert creds, retry as
            # Certificate -- Auto-mode contract: "MI if reachable AND works; else cert."
            if ($miFailed) {
                $canRetryCert = -not [string]::IsNullOrWhiteSpace($appId) -and -not [string]::IsNullOrWhiteSpace($thumb)
                if ($canRetryCert) {
                    Write-Verbose ("Connect-PlatformBootstrap: MI failed ($miError) -- BootstrapAppId+Thumbprint present, falling back to Certificate (cross-tenant scenario)")
                    $azContext = & $connectCert
                    $AuthMethod = 'Certificate'   # for KV smoke-test log line below
                } else {
                    throw @"
Connect-PlatformBootstrap: Connect-AzAccount -Identity failed -- $miError
Likely causes:
  - Host is NOT Azure-managed (on-prem VM without Arc). Use -AuthMethod Certificate.
  - VM's MI lives in a different tenant than the target tenant ($tenantId). Set
    'BootstrapAuth':'Certificate' in platform-config.json (with BootstrapAppId +
    BootstrapThumbprint), or pass -AuthMethod Certificate.
  - System-assigned Managed Identity not enabled on this VM/Container.
    Azure VM:           Update-AzVM -ResourceGroupName x -Name y -IdentityType SystemAssigned
    Container Apps Job: configure 'identity: { type: SystemAssigned }' in the job spec
    Function/App Svc:   Identity blade -> System assigned -> On
"@
                }
            } else {
                Write-Verbose ("Connect-PlatformBootstrap: Az context = {0} (MI, tenant {1}, sub {2})" -f $azContext.Context.Account.Id, $tenantId, $subId)
            }
        }

        'Certificate' {
            $azContext = & $connectCert
        }

        default { throw "Connect-PlatformBootstrap: unknown AuthMethod '$AuthMethod'." }
    }

    # ---- 5. Smoke-test KV reachability -----------------------------------
    try {
        $null = Get-AzKeyVault -VaultName $kvName -ErrorAction Stop -WarningAction SilentlyContinue
    } catch {
        throw "Connect-PlatformBootstrap: connected ($AuthMethod) but cannot reach KV '$kvName' -- $($_.Exception.Message). Check the bootstrap identity has 'Key Vault Secrets User' role on $kvName."
    }
    Write-Verbose ("Connect-PlatformBootstrap: KV {0} reachable ({1})" -f $kvName, $AuthMethod)

    if ($PassThru) {
        return $azContext.Context
    }
}
