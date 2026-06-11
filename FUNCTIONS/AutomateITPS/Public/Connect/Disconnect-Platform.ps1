function Disconnect-Platform {
<#
.SYNOPSIS
    v2.3 cleanup: disconnect Az + Mg sessions and null out the v1-contract
    globals populated by Connect-Platform.

.DESCRIPTION
    Use for test isolation, cert/secret rotation flows, or before exiting a
    long-lived ops shell. Idempotent -- safe to call when no session exists.

    Side effects:
      - Disconnect-AzAccount -ContextName <all>
      - Disconnect-MgGraph
      - $global:Context                                       = $null
      - $global:HighPriv_Modern_ApplicationID_Azure           = $null
      - $global:HighPriv_Modern_Secret_Azure                  = $null
      - $global:HighPriv_Modern_CertificateThumbprint_Azure   = $null
      - $global:SI_SPN_*                                      = $null
      - $global:Spn*                                          = $null
      - $global:AutomationFramework                           = $false

    AzureTenantId / KV_HighPriv_KeyVaultName left intact (informational, not
    credentials). Caller can null those manually if desired.

.PARAMETER KeepGlobals
    Don't reset $global:* values; just disconnect Az + Mg sessions. Useful
    when rotating but wanting to hold onto the session-state lookup info.

.EXAMPLE
    Disconnect-Platform

    Full cleanup -- safe to re-Connect-Platform afterwards.

.NOTES
    Solution     : PlatformConfiguration / AutomateITPS
    Designed by  : Morten Knudsen, 2linkIT
    Introduced   : v2.3.0
#>
    [CmdletBinding()]
    param(
        [Parameter()] [switch]$KeepGlobals
    )

    Import-Module Az.Accounts                 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    try { $null = Disconnect-AzAccount -ErrorAction SilentlyContinue -WarningAction SilentlyContinue } catch {}
    try { $null = Disconnect-MgGraph    -ErrorAction SilentlyContinue -WarningAction SilentlyContinue } catch {}

    if (-not $KeepGlobals) {
        $global:Context                                       = $null
        $global:HighPriv_Modern_ApplicationID_Azure           = $null
        $global:HighPriv_Modern_Secret_Azure                  = $null
        $global:HighPriv_Modern_CertificateThumbprint_Azure   = $null
        $global:HighPriv_Modern_AuthMethod                    = $null
        $global:SI_SPN_TenantId                               = $null
        $global:SI_SPN_AppId                                  = $null
        $global:SI_SPN_Secret                                 = $null
        $global:SI_SPN_CertThumbprint                         = $null
        $global:SI_SPN_ObjectId                               = $null
        $global:SpnTenantId                                   = $null
        $global:SpnClientId                                   = $null
        $global:SpnClientSecret                               = $null
        $global:SpnCertificateThumbprint                      = $null
        $global:AutomationFramework                           = $false
    }

    Write-Verbose "Disconnect-Platform: done"
}
