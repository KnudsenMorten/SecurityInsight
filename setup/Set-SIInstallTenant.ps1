<#
.SYNOPSIS
    SecurityInsight Pro -- read the tenant's own name from Entra ID and record it in the Pro database, so the web app's
    header shows it (TENANT).

.DESCRIPTION
    The header shows the tenant this install serves by its NAME, beside its tenant id, as PIM Manager does. The name is
    never typed by hand: this reads the Entra organization through Microsoft Graph (GET /organization -- its display
    name and its onmicrosoft.com domain) and records both in the Pro database (cfg.InstallState 'Tenant'). The guided
    install and Bootstrap-ContainerAppJob.ps1 run this for you; run it yourself for an install built another way, or
    after the tenant was renamed.

    Where the Microsoft Graph token comes from, in order:
      -GraphToken                 when given
      the guided install          its own sign-in (the person installing)
      setup's own sign-in         the REST sign-in of this process, else a person in Cloud Shell / the browser (no az CLI)
    Reading the organization needs no extra permission for a signed-in person; an application needs Directory.Read.All
    (the engine identity has it) or Organization.Read.All.

    -Name / -InitialDomain record those words without asking Graph (an install that cannot reach Graph from here). The
    web app's setting "Tenant name (override)" (Settings > Environment) still wins over what is recorded.

    The database comes from SI_ProSqlServer / SI_ProSqlDatabase (load config\SecurityInsight.custom.ps1 first, or give
    -Server / -Database) and is reached as the engine identity, like the other setup\*.ps1 Pro tools.

.EXAMPLE
    . .\config\SecurityInsight.custom.ps1; .\setup\Set-SIInstallTenant.ps1
.EXAMPLE
    .\setup\Set-SIInstallTenant.ps1 -Name 'Contoso Ltd' -InitialDomain contoso.onmicrosoft.com    # without Graph

.LINK
    https://invardia.com/docs/si/scripts/Set-SIInstallTenant/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # The tenant's name to record without asking Microsoft Graph.
    [string]$Name,
    # The tenant's onmicrosoft.com domain to record without asking Microsoft Graph.
    [string]$InitialDomain,
    # A Microsoft Graph access token to read the organization with (default: the guided install's sign-in, else setup's own sign-in).
    [string]$GraphToken,
    # Who records it (shown in the web app's tooltip).
    [string]$SetBy = 'setup',
    [string]$Server = [string]$global:SI_ProSqlServer,
    [string]$Database = [string]$global:SI_ProSqlDatabase,
    [string]$AppId = [string]$global:SI_SPN_AppId,
    [string]$TenantId = [string]$global:SI_SPN_TenantId,
    [string]$CertThumbprint = [string]$global:SI_SPN_CertThumbprint,
    # The database, already open (New-SIProSettingsStore -Invoke ...): a test's fake, or a caller's store.
    $Store,
    # Returns the GET /organization response: a test's fake (no Graph call is made then).
    [scriptblock]$GraphGet,
    [switch]$PassThru
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Set-SIInstallTenant' -Quiet:([bool]$PSBoundParameters.ContainsKey('Store'))
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($siRoot, 'engine', '_shared', 'SI-InstallTenant.ps1'))

if ($WhatIfPreference) {
    # -WhatIf: neither Microsoft Graph nor the Pro database is opened -- recording the tenant is the only action
    Write-Host ('-WhatIf: would read the tenant''s name from Entra ID{0} and record it in the Pro database {1}/{2} (set by {3}). Nothing was read or written.' -f `
        $(if ($Name) { (' (given: ''{0}'')' -f $Name) } else { '' }), $Server, $Database, $SetBy) -ForegroundColor Yellow
    return
}
if (-not $Store) {
    if (-not $Server -or -not $Database) { throw 'the Pro database is not configured: load config\SecurityInsight.custom.ps1 first (SI_ProSqlServer / SI_ProSqlDatabase), or give -Server and -Database' }
    . ([IO.Path]::Combine($siRoot, 'engine', 'pro-settings', 'SI-ProSettings.ps1'))
    $Store = New-SIProSettingsStore -Server $Server -Database $Database -AppId $AppId -TenantId $TenantId -CertThumbprint $CertThumbprint
}
if (-not $GraphGet -and -not $Name) {
    # #564 (PIM's install at customer I): NOT a GetNewClosure() -- a closure cannot see the functions setup dot-sourced
    # (Connect-SISetupAzure, Get-SISetupAzureContext). A plain block runs in the caller's scope chain and reads this
    # script's values from one uniquely named variable (no parameter of Invoke-SIRecordInstallTenant can shadow it).
    $script:SIInstallTenantGraphArgs = @{ GraphToken = $GraphToken; TenantId = $TenantId; SIRoot = $siRoot }
    $GraphGet = {
        $GraphToken = $script:SIInstallTenantGraphArgs.GraphToken; $TenantId = $script:SIInstallTenantGraphArgs.TenantId; $siRoot = $script:SIInstallTenantGraphArgs.SIRoot
        $tok = $GraphToken
        if (-not $tok -and (Test-Path -Path 'variable:global:SI_InstallTokenProvider') -and $global:SI_InstallTokenProvider) { $tok = [string](& $global:SI_InstallTokenProvider 'https://graph.microsoft.com') }
        if (-not $tok) {
            # #521: setup's own REST sign-in (an existing one in this process is reused -- Bootstrap, the guided install, the
            # Invardia support session; else a person signs in: Cloud Shell or the browser). Never the az CLI.
            if (-not (Get-Command -Name Connect-SISetupAzure -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($siRoot, 'setup', '_shared', 'SI-SetupAzure.ps1')) }
            try {
                if (-not (Get-SISetupAzureContext)) { $ca = @{}; if ($TenantId) { $ca.TenantId = $TenantId }; $null = Connect-SISetupAzure @ca }
                $tok = [string](Get-SIAzureToken -Resource 'https://graph.microsoft.com')
            } catch { $tok = $null }
        }
        if (-not "$tok".Trim()) { throw 'no Microsoft Graph sign-in here (give -GraphToken, or run it where setup can sign in: Azure Cloud Shell or the browser)' }
        # #548: through the support recorder in a support session (Invoke-SIRestMethod), else Invoke-RestMethod
        $irm = if (Get-Command -Name Invoke-SIRestMethod -ErrorAction SilentlyContinue) { 'Invoke-SIRestMethod' } else { 'Invoke-RestMethod' }
        & $irm -Method Get -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains' -Headers @{ Authorization = ('Bearer {0}' -f "$tok".Trim()) } -TimeoutSec 30 -ErrorAction Stop
    }
}
$res = Invoke-SIRecordInstallTenant -Store $Store -TenantId $TenantId -Name $Name -InitialDomain $InitialDomain -GraphGet $GraphGet -SetBy $SetBy
if ($res.Written) { Write-Host ('[OK]   {0}' -f $res.Reason) -ForegroundColor Green }
else { Write-Host ('[WARN] {0}' -f $res.Reason) -ForegroundColor Yellow }
if ($PassThru) { $res }
} finally { Stop-SIScriptRun -Run $siRun }
