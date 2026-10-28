#Requires -Version 5.1
<#
    Azure for the diagnostics scripts -- no PowerShell modules, only REST and .NET.

    SecurityInsight v3 uses no PowerShell modules (no Az.*, no Microsoft.Graph, no AzLogDcrIngestPS). These
    scripts reach Azure through SecurityInsight's own REST layer (engine/_shared/SI-AzRest.ps1): tokens from the
    Microsoft identity platform, Log Analytics queries on the data plane, Azure Resource Manager, Key Vault.

    WHO THE CALLS RUN AS (Connect-SIDiagnosticsAzure), first match wins:
      1. -AppId + -TenantId + -CertificateThumbprint                 a service principal with a certificate
      2. -ManagedIdentity [-ManagedIdentityClientId]                 the machine's managed identity (Azure VM / Arc)
      3. $env:SI_DIAGNOSTICS_APPID + _TENANTID + _CERTTHUMBPRINT      the same, from the environment
         ($env:SI_DIAGNOSTICS_MANAGEDIDENTITY = 'true' for a managed identity)
      4. the install's own identity from its config, when the script loaded it (SI_SPN_AppId + SI_SPN_TenantId +
         SI_SPN_CertThumbprint, or SI_UseManagedIdentity)
    The certificate's private key is read from the Windows certificate store (LocalMachine, then CurrentUser) by its
    thumbprint; it never leaves the store. No client secret, no interactive sign-in.

    PS 5.1 and PowerShell 7. Holds no environment value: every name and id comes from the caller.
#>

. ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'engine', '_shared', 'SI-AzRest.ps1'))

function Initialize-SIDiagnosticsManagedIdentity {
    if (-not (Get-Command -Name Get-SIManagedIdentityToken -ErrorAction SilentlyContinue)) {
        . ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'auth', 'SI-ManagedIdentity.ps1'))
        $f = Get-Command -Name Get-SIManagedIdentityToken -CommandType Function -ErrorAction SilentlyContinue
        if ($f) { Set-Item -Path 'function:global:Get-SIManagedIdentityToken' -Value $f.ScriptBlock }
    }
}

function Connect-SIDiagnosticsAzure {
    <# Records the identity the REST calls sign in as (see the header). Returns the mode: Certificate | ManagedIdentity. #>
    [CmdletBinding()]
    param(
        [string]$AppId,
        [string]$TenantId,
        [string]$CertificateThumbprint,
        [switch]$ManagedIdentity,
        [string]$ManagedIdentityClientId
    )
    $envMi = ([string]$env:SI_DIAGNOSTICS_MANAGEDIDENTITY -match '^(?i)(1|true|yes)$')
    $envApp = [string]$env:SI_DIAGNOSTICS_APPID; $envTid = [string]$env:SI_DIAGNOSTICS_TENANTID; $envThumb = [string]$env:SI_DIAGNOSTICS_CERTTHUMBPRINT
    $spn = $null
    if ($AppId -and $TenantId -and $CertificateThumbprint) { $spn = @($AppId, $TenantId, $CertificateThumbprint) }
    elseif (-not $ManagedIdentity -and $envApp -and $envTid -and $envThumb) { $spn = @($envApp, $envTid, $envThumb) }

    if ($spn) {
        $null = Connect-SIAzAccountRest -ServicePrincipal -ApplicationId $spn[0] -Tenant $spn[1] -CertificateThumbprint $spn[2]
        return 'Certificate'
    }
    if ($ManagedIdentity -or $envMi) {
        Initialize-SIDiagnosticsManagedIdentity
        $null = Connect-SIAzAccountRest -Identity -AccountId $ManagedIdentityClientId
        return 'ManagedIdentity'
    }
    # 4. the install's config (globals the script loaded); a client secret is not accepted here
    $auth = $null
    try { $auth = Resolve-SIAzRestAuth } catch { $auth = $null }
    if ($auth -and $auth.Mode -eq 'ManagedIdentity') { Initialize-SIDiagnosticsManagedIdentity; return 'ManagedIdentity' }
    if ($auth -and $auth.Mode -eq 'Certificate') { return 'Certificate' }
    throw ('No sign-in for Azure. Give a service principal with a certificate (-AppId, -TenantId, -CertificateThumbprint, ' +
           'or $env:SI_DIAGNOSTICS_APPID / _TENANTID / _CERTTHUMBPRINT; the certificate in the machine''s certificate store), ' +
           'or a managed identity (-ManagedIdentity, or $env:SI_DIAGNOSTICS_MANAGEDIDENTITY = ''true'').')
}

function Get-SIDiagnosticsSecret {
    <# One Key Vault secret as plain text, over REST. A missing secret is an error: these scripts cannot run without it. #>
    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$Name)
    $v = Get-SIKeyVaultSecretValue -VaultName $VaultName -Name $Name
    if ($null -eq $v) { throw ("Key Vault secret '{0}' was not found in vault '{1}'." -f $Name, $VaultName) }
    return $v
}

function Get-SIDiagnosticsWorkspaceId {
    <# The workspace (customer) id of a Log Analytics workspace resource id, read from Azure Resource Manager. The
       resource id names the subscription, so no "current subscription" is involved. #>
    param([Parameter(Mandatory)][string]$WorkspaceResourceId)
    $id = '/' + $WorkspaceResourceId.Trim().Trim('/')
    if ($id -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.OperationalInsights/workspaces/[^/]+$') {
        throw ("'{0}' is not a Log Analytics workspace resource id (/subscriptions/<id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>)." -f $WorkspaceResourceId)
    }
    $ws = Invoke-SIArm -Path $id -ApiVersion '2022-10-01'
    $cid = [string]$ws.properties.customerId
    if (-not $cid) { throw ("The workspace '{0}' returned no customer id." -f $id) }
    return $cid
}

function Invoke-SIDiagnosticsKql {
    <# A KQL query on the workspace (customer id): the rows of the primary table, every cell as text. #639 lane 4: read in
       parts when one Log Analytics answer cannot carry it (Read-SILaParts) -- a cut answer is refused, never measured from. #>
    param([Parameter(Mandatory)][string]$WorkspaceId, [Parameter(Mandatory)][string]$Query, [int]$Wait = 300)
    $r = Read-SILaParts -WorkspaceId $WorkspaceId -Query $Query -Wait $Wait -What 'the diagnostics query' -Log { param($l, $m) Write-Host ('  ' + $m) -ForegroundColor DarkGray }
    return @($r.Rows)
}
