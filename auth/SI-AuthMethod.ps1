#Requires -Version 5.1
<#
    SecurityInsight -- ONE sign-in decision for every host (#222, operator 2026-10-03):
    *"switch to use a mi (preferred) and spn (optional) ... configuration files must be supporting both methods,
    with default being mi"*.

    THE SETTING (config\SecurityInsight.custom.ps1, or the Pro settings database):
        $global:SI_AuthMethod              = 'ManagedIdentity' | 'Certificate' | 'Secret'
        $global:SI_ManagedIdentityClientId = '<client id>'   # optional: a USER-assigned identity; empty = the host's
                                                             # system-assigned identity (Azure VM, Azure Arc server)

    WHEN IT IS NOT SET (every install written before 3.0) -- nothing changes for it:
        an internal install (AutomationFramework)        -> its platform identity, exactly as before
        an SPN certificate / secret in the config         -> that SPN, exactly as before
        no SPN at all                                     -> the managed identity (the default for new installs)
    New installs get SI_AuthMethod written explicitly by setup.

    WHAT 'ManagedIdentity' SETS (the switches the rest of SI already reads -- one decision feeds all of them):
        $global:SI_UseManagedIdentity = $true      tokens (Graph, Defender, SQL, storage, Key Vault, ARM)
        $global:SI_UAMI_ClientId      = <id or ''>
        $global:SI_PreferUami         = $true      Log Analytics ingestion (-UseManagedIdentity, over REST)
        $global:UseManagedIdentity    = $true      the Community launchers' Connect-SIAzAccount -Identity
    The Invardia Support app is NEVER the engine identity: it signs in to a customer install for support only
    (its own tooling); nothing here selects it.

    PS 5.1 safe: no ?. / ??.
#>

function Resolve-SIAuthMethod {
    <# PURE. -Globals: name -> value. Returns @{ Mode; ClientId; Explicit; Reason }. Mode = ManagedIdentity |
       Certificate | Secret | AutomationFramework. Throws on an unknown SI_AuthMethod value. #>
    param([hashtable]$Globals = @{})
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    $cid = [string](& $g 'SI_ManagedIdentityClientId')
    if (-not $cid) { $cid = [string](& $g 'SI_UAMI_ClientId') }
    $explicit = ([string](& $g 'SI_AuthMethod')).Trim()
    if ($explicit) {
        $mode = switch -Regex ($explicit) {
            '^(?i)(ManagedIdentity|MI|Identity)$' { 'ManagedIdentity' }
            '^(?i)(Certificate|Cert|SpnCertificate)$' { 'Certificate' }
            '^(?i)(Secret|SpnSecret|ClientSecret)$' { 'Secret' }
            default { throw ("SI_AuthMethod = '{0}' is not a sign-in method -- use ManagedIdentity (default), Certificate or Secret." -f $explicit) }
        }
        return [pscustomobject]@{ Mode = $mode; ClientId = $cid; Explicit = $true; Reason = ("SI_AuthMethod = {0}" -f $mode) }
    }
    if ([bool](& $g 'AutomationFramework')) {
        return [pscustomobject]@{ Mode = 'AutomationFramework'; ClientId = ''; Explicit = $false; Reason = 'internal install: the platform identity (no SI_AuthMethod set)' }
    }
    $thumb = [string](& $g 'SI_SPN_CertThumbprint'); if (-not $thumb) { $thumb = [string](& $g 'SpnCertificateThumbprint') }
    $app   = [string](& $g 'SI_SPN_AppId');          if (-not $app)   { $app   = [string](& $g 'SpnClientId') }
    $sec   = [string](& $g 'SI_SPN_Secret');         if (-not $sec)   { $sec   = [string](& $g 'SpnClientSecret') }
    $kvSec = [string](& $g 'SpnSecretName')
    if ($app -and $thumb) { return [pscustomobject]@{ Mode = 'Certificate'; ClientId = ''; Explicit = $false; Reason = 'an SPN certificate is configured (no SI_AuthMethod set)' } }
    if ($app -and ($sec -or $kvSec)) { return [pscustomobject]@{ Mode = 'Secret'; ClientId = ''; Explicit = $false; Reason = 'an SPN secret is configured (no SI_AuthMethod set)' } }
    if ([bool](& $g 'UseManagedIdentity') -or [bool](& $g 'SI_PreferUami') -or [bool](& $g 'SI_UseManagedIdentity')) {
        return [pscustomobject]@{ Mode = 'ManagedIdentity'; ClientId = $cid; Explicit = $false; Reason = 'a managed identity switch is set' }
    }
    return [pscustomobject]@{ Mode = 'ManagedIdentity'; ClientId = $cid; Explicit = $false; Reason = 'default: no SPN is configured, so the host''s managed identity' }
}

function Set-SIAuthMethodGlobals {
    <# Applies Resolve-SIAuthMethod to the run: managed identity sets the switches every token site reads. Returns
       the decision. A container decides for itself from its own environment (Resolve-SIContainerAuthMode) and does
       not call this. #>
    param([hashtable]$Globals)
    if (-not $Globals) { $Globals = @{}; foreach ($v in (Get-Variable -Scope Global)) { $Globals[$v.Name] = $v.Value } }
    $d = Resolve-SIAuthMethod -Globals $Globals
    if ($d.Mode -eq 'ManagedIdentity') {
        $global:SI_UseManagedIdentity = $true
        $global:SI_UAMI_ClientId      = [string]$d.ClientId
        $global:SI_PreferUami         = $true
        $global:UseManagedIdentity    = $true
    } elseif ($d.Explicit) {
        # an explicit SPN choice switches a leftover managed-identity flag OFF, so the two never mix
        $global:SI_UseManagedIdentity = $false
        $global:SI_PreferUami         = $false
        $global:UseManagedIdentity    = $false
    }
    $global:SI_AuthMethodResolved = $d.Mode
    return $d
}
