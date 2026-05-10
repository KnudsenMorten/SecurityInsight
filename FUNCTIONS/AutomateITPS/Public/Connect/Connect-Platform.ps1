function Connect-Platform {
<#
.SYNOPSIS
    v2.3 single-call auth orchestrator. Connects Bootstrap SPN (cert), pulls
    Modern credentials from KV, reconnects as Modern SPN (secret), populates
    v1-contract globals. Returns the PlatformContext.

.DESCRIPTION
    The one function engines + launchers + ops scripts call to "log in to the
    platform." Replaces v1's `Connect_Azure.ps1` chain and v2.2's
    `Initialize-PlatformAutomationFramework`. Idempotent.

    Flow (= Connect-PlatformBootstrap + Connect-PlatformModern in sequence):

      1. Read bootstrap\platform-config.json (5 fields)
      2. Cert-connect Bootstrap SPN to platform KV (KV-read-only role)
      3. Pull Modern-AppId + Modern-Secret from KV
      4. Secret-connect Modern SPN (full operational RBAC + Graph perms)
      5. Build PlatformContext + populate $global:HighPriv_Modern_* + friends
      6. Return PlatformContext

    After this returns, engine code that reads $global:HighPriv_Modern_* /
    $global:Context / $global:SI_SPN_* etc. all work. Az + Mg sessions are
    held as the Modern SPN.

.PARAMETER ConfigPath
    Override path to platform-config.json. Default: <repo>\bootstrap\platform-config.json
    auto-resolved.

.PARAMETER SkipMgGraph
    Skip the Mg connect (saves ~1s when caller doesn't need Graph).

.PARAMETER PassThru
    Default $true. Returns the PlatformContext. Set $false in scripts that
    just want the side-effect of populating globals.

.OUTPUTS
    PSCustomObject -- the PlatformContext (same as New-PlatformContext output).

.EXAMPLE
    $ctx = Connect-Platform

    Standard launcher Layer 1 call. Engines read $global:HighPriv_Modern_* etc.
    afterwards.

.EXAMPLE
    Connect-Platform -ConfigPath C:\test\platform-config.json -SkipMgGraph

    Run against a test config; skip Graph (faster smoke test).

.NOTES
    Solution     : PlatformConfiguration / AutomateITPS
    Designed by  : Morten Knudsen, 2linkIT
    Introduced   : v2.3.0 (replaces Initialize-PlatformAutomationFramework which
                   stays as a thin alias for one release for back-compat)
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [string]$ConfigPath,
        [Parameter()] [switch]$SkipMgGraph,
        [Parameter()] [switch]$PassThru = $true
    )

    $null = Connect-PlatformBootstrap -ConfigPath $ConfigPath -PassThru:$false

    $ctx = Connect-PlatformModern    -ConfigPath $ConfigPath -SkipMgGraph:$SkipMgGraph

    if ($PassThru) { return $ctx }
}
