<#
.SYNOPSIS
    SecurityInsight Pro: put ONE existing install's web app behind the shared sign-in front -- or take it back (-Off).

.DESCRIPTION
    CR7 (framework DOCS/REQUIREMENTS.md 12.11g). The web app's users sign in through the ONE sign-in front SecurityInsight
    and PIM share (FRAMEWORK/signin-front, the version pro-management\signin-front.pin.json pins): code flow + PKCE, the
    web app's managed identity as a federated credential on the SAME app registration (no secret, no certificate), an 8 h
    session, the security headers. The front runs as a second container in the SAME revision as the web app and is the only
    one the ingress reaches; the web app listens on 127.0.0.1 only and verifies the front's token on every request.

    An existing install reaches the front through its product update: the updater moves a web app that has not chosen
    its own sign-in behind the front once the federated credential and the sign-in consent below read back -- it never
    writes to Microsoft Entra itself, so when either is missing the update result names THIS script as the customer
    action. -Apply here adds them (and moves the app at once). -Off is the way back and a CHOICE: it writes
    SI_Web_SigninFront=false on the web container, and the updater never moves that install behind the front again.

    PLAN BY DEFAULT: what each step would do. -Apply makes them, in order, each read back before the next
    (pro-management\deploy\SI-ManagementSigninFront.ps1, Invoke-SISigninFrontCutover):
      1. the pinned component's source must be in this release (else nothing changes);
     1b. the sign-in permissions the front asks for -- openid profile offline_access User.Read -- consented for the whole
         organisation (the same grant New-SIManagementAppRegistration.ps1 step 2b gives; an install registered before that
         step had only "openid profile", and its first sign-in through the front said "Approval required"). The plan shows
         it; -Apply adds what is missing and reads it back. Without DelegatedPermissionGrant.ReadWrite.All (or Cloud
         Application Administrator) a WARNING says what an administrator does;
      2. the federated credential for the web app's identity on the app registration (added when missing, read back);
     2b. (#852) the front's store: the key signin-front-dp in the install's Key Vault (-KeyVaultName, default the only
         vault in the resource group), the web identity's "Key Vault Crypto Service Encryption User" on that key only, its
         user in the Pro database, its schema signin and CREATE TABLE -- each when missing, read back. The update's step 9g
         names THIS script when it may not make one of them itself;
      3. the front's image built in the install's own registry from that source;
      4. the front added to the web app's revision, the web app on 127.0.0.1, the ingress on the front -- read back,
         /healthz answers, an anonymous request is refused; otherwise what ran before is PUT BACK and the run stops;
      5. Easy Auth off (SecurityInsight never used it);
      6. only then the app registration's client secrets deleted (-KeepClientSecrets leaves them).
    -Off -Apply: the way back -- the front removed, the web app signs users in itself again, read back.
    Safe to repeat: a step that is done already changes nothing. -WhatIf = the plan (same as without -Apply).
    It ships in the release package (it builds the front's image from the component source the release carries), run
    inside an install -- usually through the Invardia Support app.

.EXAMPLE
    .\setup\Set-SISigninFront.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -RegistryName <acr> -TenantId <tenant> -SignInClientId <app id>
    The plan: every step and what it would change. Nothing is changed.
.EXAMPLE
    .\setup\Set-SISigninFront.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -RegistryName <acr> -TenantId <tenant> -SignInClientId <app id> -Apply
.EXAMPLE
    .\setup\Set-SISigninFront.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -RegistryName <acr> -TenantId <tenant> -SignInClientId <app id> -Off -Apply

.LINK
    https://invardia.com/docs/si/scripts/Set-SISigninFront/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$RegistryName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
    # the web app's app registration (its client id): the front signs users in with it, the web app checks it as audience
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$SignInClientId,
    [string]$AppName = 'ca-si-management',
    [string]$IdentityName = 'uami-si-management',
    [switch]$Off,
    [switch]$KeepClientSecrets,
    # #852: the install's Key Vault for the front's key (default: the only Key Vault in the resource group)
    [string]$KeyVaultName = '',
    [switch]$Apply
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Set-SISigninFront' -Quiet:($false)
if ($WhatIfPreference) { $Apply = [switch]$false }   # -WhatIf = the plan: nothing is changed
try {
$ErrorActionPreference = 'Stop'

# The tenants this machine must never change (another company's; the retired test tenants).
# (an internal list next to the web app's deploy scripts -- publish strips it, so the public copy names no tenant)
$refusedList = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'pro-management', 'deploy', 'internal', 'SI-RefusedTenants.ps1')
$refused = @(if (Test-Path -LiteralPath $refusedList) { & $refusedList })
if ($refused -contains $TenantId.ToLowerInvariant()) { throw "Tenant $TenantId is refused for SecurityInsight changes." }

$siRoot = Split-Path -Parent $PSScriptRoot
$deploy = [IO.Path]::Combine($siRoot, 'pro-management', 'deploy')
. ([IO.Path]::Combine($deploy, 'SI-ManagementArm.ps1'))
. ([IO.Path]::Combine($deploy, 'SI-ManagementSigninFront.ps1'))

Write-Host ('SecurityInsight Pro -- the web app {0} the shared sign-in front: {1}' -f $(if ($Off) { 'taken out from behind' } else { 'behind' }), $(if ($Apply) { 'APPLY' } else { 'PLAN (nothing is changed; add -Apply)' })) -ForegroundColor White
$null = Connect-SIManagementRest -TenantId $TenantId -SubscriptionId $SubscriptionId
$r = Invoke-SISigninFrontCutover -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -TenantId $TenantId -SignInClientId $SignInClientId `
        -RegistryName $RegistryName -AppName $AppName -IdentityName $IdentityName -SIRoot $siRoot -Off:$Off -KeepClientSecrets:$KeepClientSecrets -Apply:$Apply -KeyVaultName $KeyVaultName `
        -Log { param($m) Write-Host ('  ' + $m) }
if (-not $Apply) { Write-Host 'Plan only -- nothing was changed. Re-run with -Apply.' -ForegroundColor Yellow }
$r
} finally { Stop-SIScriptRun -Run $siRun }
