#Requires -Version 5.1
<#
.SYNOPSIS
    Turns the web app's sign-in credential for the "Set up mail" click flow on -- ONLY when the app registration's
    federated credential for the web app's managed identity is there. PLAN BY DEFAULT; -Apply makes the change.

.DESCRIPTION
    #443 (a), MAIL-1. The guard between the federated credential (New-SIManagementAppRegistration.ps1
    -WebIdentityPrincipalId creates it) and the two web app settings that use it
    (AzureAd__ClientCredentials__0__SourceType = SignedAssertionFromManagedIdentity + the identity's client id).
    The settings switch EVERY user's sign-in to the code flow, redeemed with the identity's assertion; without the
    federated credential nobody could sign in. So:
      1. the web identity and the settings the web app has now (ARM reads);
      2. the app registration's federated credentials, READ BACK from Microsoft Graph;
      3. present and matching (issuer, subject, audience)  -> the settings are set (the click flow is on);
         absent, and the app carries the settings           -> they are REMOVED (sign-in keeps working; the page hands
                                                               over setup\Set-SIMail.ps1 instead);
         absent and not set                                 -> nothing changes;
         Graph could not be read                            -> nothing changes, and the run says so (exit 2).
    No secret, no certificate, no Key Vault. NO az CLI and no PowerShell module: ARM (Microsoft.App api 2025-07-01, the
    web app changed read-modify-write) and Microsoft Graph REST through SecurityInsight's own REST sign-in
    (SI-ManagementArm.ps1). Run by Deploy-SIManagement.ps1 and the guided install after the app registration; safe to
    repeat.

.EXAMPLE
    .\Set-SIManagementSignInCredential.ps1 -TenantId <tenant> -SubscriptionId <sub> -ResourceGroup rg-si-prod-pro-ca -SignInClientId <app id>
    .\Set-SIManagementSignInCredential.ps1 ... -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$SignInClientId,
    [string]$AppName = 'ca-si-management',
    [string]$IdentityName = 'uami-si-management',
    # The caller just made (or found) the credential for the web app's identity: a list that does not show it YET is read
    # again (6 tries, 10 s apart) instead of deciding "none" on a directory that has not caught up.
    [switch]$ExpectCredential,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'SI-ManagementSignInCredential.ps1')
# #521: ARM + Graph over SecurityInsight's own REST sign-in -- no az CLI, no module
. (Join-Path $PSScriptRoot 'SI-ManagementArm.ps1')

$mode = if ($Apply) { 'APPLY' } else { 'PLAN (nothing is changed; add -Apply)' }
Write-Host ('SecurityInsight Pro -- the web app''s sign-in credential (Set up mail) {0}' -f $mode) -ForegroundColor White

# an existing sign-in of this process is reused (the deploy's, the guided install's); its tenant must be -TenantId
$null = Connect-SIManagementRest -TenantId $TenantId -SubscriptionId $SubscriptionId
$id = Get-SIUserAssignedIdentity -ResourceGroupName $ResourceGroup -Name $IdentityName -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
if (-not $id) { throw ('The web app''s identity {0} was not found in {1}.' -f $IdentityName, $ResourceGroup) }
$app = Get-SIManagementContainerApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $AppName
if (-not $app) { throw ('The web app {0} was not found in {1}.' -f $AppName, $ResourceGroup) }
$first = @(@(Get-SIManagementProp $app @('properties', 'template', 'containers')) | Where-Object { $_ }) | Select-Object -First 1
$current = @(@(Get-SIManagementProp $first @('env')) | Where-Object { $_ } | ForEach-Object { [string](Get-SIManagementProp $_ @('name')) })

$creds = $null; $readFailed = $false
try {
    $tok = Get-SIManagementToken -Resource 'https://graph.microsoft.com'
    if (-not $tok) { throw 'the sign-in could not issue a Microsoft Graph token' }
    Assert-SIManagementTokenTenant -Token $tok -TenantId $TenantId -What 'The Microsoft Graph sign-in'
    $u = "https://graph.microsoft.com/v1.0/applications(appId='{0}')/federatedIdentityCredentials" -f $SignInClientId
    $creds = @((Invoke-SIRestMethod -Method Get -Uri $u -Headers @{ Authorization = 'Bearer ' + $tok } -ErrorAction Stop).value)   # #548
    if ($ExpectCredential) {
        $credWait = Get-Variable -Scope Global -Name SI_ManagementGraphRetrySeconds -ValueOnly -ErrorAction Ignore
        if ($null -eq $credWait) { $credWait = 10 }
        for ($credTry = 1; $credTry -lt 6 -and -not (Test-SIManagementFederatedCredential -Credentials $creds -TenantId $TenantId -PrincipalId ([string]$id.PrincipalId)); $credTry++) {
            Write-Host '  the new credential is not listed yet -- reading again' -ForegroundColor DarkGray
            if ([int]$credWait -gt 0) { Start-Sleep -Seconds ([int]$credWait) }
            $creds = @((Invoke-SIRestMethod -Method Get -Uri $u -Headers @{ Authorization = 'Bearer ' + $tok } -ErrorAction Stop).value)
        }
    }
} catch {
    $readFailed = $true
    Write-Warning ('The app registration''s federated credentials could not be read ({0}) -- nothing is changed.' -f $_.Exception.Message)
}

$decision = Get-SIManagementCredentialDecision -Credentials $creds -ReadFailed:$readFailed -TenantId $TenantId -PrincipalId ([string]$id.PrincipalId) -CurrentSettingNames $current
$result = [pscustomobject]@{ Decision = $decision; ClickFlow = ($decision -eq 'enable'); Applied = $false; IdentityClientId = [string]$id.ClientId }
switch ($decision) {
    'enable' {
        Write-Host '  the federated credential for the web app''s identity is there: the Set up mail click flow is turned on'
        $s = Get-SIManagementCredentialSettings -ManagedIdentityClientId ([string]$id.ClientId)
        foreach ($x in $s) { Write-Host ('    {0}' -f $x) -ForegroundColor DarkGray }
        Write-Host ('  PATCH {0}  (the whole template, settings set)' -f [string]$app.id) -ForegroundColor DarkGray
        if ($Apply) {
            try { $null = Set-SIManagementContainerAppEnv -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $AppName -SetEnv $s }
            catch { throw ('Setting the web app''s sign-in credential failed: {0}' -f $_.Exception.Message) }
            $result.Applied = $true
        }
    }
    'disable' {
        Write-Host '  NO federated credential for the web app''s identity, but the web app carries the credential settings: they are REMOVED, so sign-in keeps working' -ForegroundColor Yellow
        Write-Host ('  PATCH {0}  (the whole template, settings removed)' -f [string]$app.id) -ForegroundColor DarkGray
        if ($Apply) {
            try { $null = Set-SIManagementContainerAppEnv -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $AppName -RemoveEnv $script:SIManagementCredentialSettingNames }
            catch { throw ('Removing the web app''s sign-in credential failed: {0}' -f $_.Exception.Message) }
            $result.Applied = $true
        }
    }
    'none' { Write-Host '  no federated credential for the web app''s identity: the click flow stays off (the page hands over setup\Set-SIMail.ps1)' }
    default { Write-Host '  unknown: nothing changed' -ForegroundColor Yellow }
}
if (-not $Apply) { Write-Host 'Plan only -- nothing was changed. Re-run with -Apply.' -ForegroundColor Yellow }
$result
if ($decision -eq 'unknown') { exit 2 }
