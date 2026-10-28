#Requires -Version 5.1
<#
    SecurityInsight -- the local setup wizard's SIGN-IN decision (setup\ConfigWizard\Start-SetupWizard.ps1).

    Operator decision 2026-10-07: the wizard's default is a MANAGED IDENTITY (user-assigned, as the guided install does).
    A service principal stays a supported, explicit choice: by CERTIFICATE (recommended for an SPN) or by client SECRET
    (supported, never removed -- just not the default).

      Container Apps jobs            -> the jobs' user-assigned identity. The container setup (Bootstrap-ContainerAppJob
                                        -UseManagedIdentity -GrantIdentityRoles) creates and grants it.
      Azure VM / Azure Arc server    -> a user-assigned identity the wizard creates in the install's resource group, grants,
                                        and attaches to the VM when its name is given (an Arc server takes its own
                                        system-assigned identity instead: setup\Grant-SIIdentity.ps1 -ArcMachineName).
      A server outside Azure         -> NO managed identity can exist there. The wizard says so and offers a certificate
                                        first, then a secret.

    PURE functions only. PS 5.1 and 7.
#>

function Resolve-SIWizardSignIn {
    <#
        PURE. The sign-in the wizard sets up. -HostType: win | azureVMMI | azureContainerMI. -CredKind: what the page sent
        (ManagedIdentity | Cert | Secret; empty = nothing chosen). -ExistingAppId: an existing SPN was named.
        Returns @{ CredKind; Identity (container-jobs | user-assigned | none); DefaultUsed; Note }.
        Throws when a managed identity is asked for on a server outside Azure.
    #>
    param([AllowEmptyString()][string]$HostType = '', [AllowEmptyString()][string]$CredKind = '', [AllowEmptyString()][string]$ExistingAppId = '')
    $h = "$HostType".Trim(); if (-not $h) { $h = 'azureVMMI' }
    $k = "$CredKind".Trim()
    $k = switch -Regex ($k) {
        '^(?i)(ManagedIdentity|MI|Identity)$' { 'ManagedIdentity' }
        '^(?i)(Cert|Certificate)$'            { 'Cert' }
        '^(?i)(Secret|ClientSecret)$'         { 'Secret' }
        '^$'                                  { '' }
        default { throw ("'{0}' is not a sign-in the wizard sets up -- use ManagedIdentity, Cert or Secret." -f $CredKind) }
    }
    $noMiNote = 'A server outside Azure cannot have a managed identity, so SecurityInsight signs in as a service principal: by certificate (recommended), or by client secret. An Azure Arc-enabled server does have one -- pick "Azure VM or Azure Arc server" instead.'
    $o = { param($kind, $id, $def, $note) [pscustomobject]@{ CredKind = $kind; Identity = $id; DefaultUsed = [bool]$def; Note = $note } }
    if ($k -eq 'ManagedIdentity') {
        if ($h -eq 'win') { throw $noMiNote }
        if ($h -eq 'azureContainerMI') { return (& $o 'ManagedIdentity' 'container-jobs' $false 'the Container Apps jobs sign in as their user-assigned managed identity') }
        return (& $o 'ManagedIdentity' 'user-assigned' $false 'a user-assigned managed identity, attached to the server')
    }
    if ($k) { return (& $o $k 'none' $false $(if ($k -eq 'Secret') { 'a service principal by client secret (your explicit choice)' } else { 'a service principal by certificate' })) }
    # Nothing chosen: the default.
    if ("$ExistingAppId".Trim()) { return (& $o 'Cert' 'none' $true 'an existing service principal: by its certificate') }
    if ($h -eq 'win') { return (& $o 'Cert' 'none' $true $noMiNote) }
    if ($h -eq 'azureContainerMI') { return (& $o 'ManagedIdentity' 'container-jobs' $true 'the default: the Container Apps jobs sign in as their user-assigned managed identity') }
    & $o 'ManagedIdentity' 'user-assigned' $true 'the default: a user-assigned managed identity, attached to the server'
}

function Get-SIWizardIdentityName {
    <# PURE. The user-assigned identity's name: the one given, else the pattern name for an rg-si-<label> resource group
       (id-si-<label>, setup\_shared\SI-SetupNaming.ps1), else uami-securityinsight. #>
    param([AllowEmptyString()][string]$Name = '', [AllowEmptyString()][string]$ResourceGroupName = '')
    if ("$Name".Trim()) { return "$Name".Trim() }
    if (Get-Command -Name Get-SISetupNamesFromResourceGroup -ErrorAction SilentlyContinue) {
        $n = Get-SISetupNamesFromResourceGroup -ResourceGroupName $ResourceGroupName
        if ($n -and $n['ManagedIdentity']) { return [string]$n['ManagedIdentity'] }
    }
    'uami-securityinsight'
}

function New-SIWizardManagedIdentityResult {
    <# PURE. The identity phase's result, in the shape the config writer and the page read (as New-SISpn returns). #>
    param([Parameter(Mandatory)][string]$TenantId, [AllowEmptyString()][string]$ClientId = '', [AllowEmptyString()][string]$PrincipalId = '',
          [AllowEmptyString()][string]$Name = '', [AllowEmptyString()][string]$ResourceId = '')
    [pscustomobject]@{
        AppId = $ClientId; ObjectId = $PrincipalId; TenantId = $TenantId; DisplayName = $Name; CredKind = 'ManagedIdentity'
        CredValue = $null; CertThumbprint = $null; KvName = $null; KvSecretName = $null; KvCertName = $null
        ManagedIdentityId = $ClientId; ManagedIdentityName = $Name; ManagedIdentityResourceId = $ResourceId; ExpiresUtc = $null
        GraphPermissions = @(); GraphPermissionResults = @(); PendingPermissions = @(); ConsentStatus = 'granted'; ConsentUrl = $null
        AzureRbacScopes = @(); AzureRbacResults = @()
    }
}
