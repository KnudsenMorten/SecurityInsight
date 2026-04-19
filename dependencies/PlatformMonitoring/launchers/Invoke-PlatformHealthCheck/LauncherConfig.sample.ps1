#Requires -Version 5.1
<#
.SYNOPSIS
    Community-edition customer configuration for Invoke-PlatformHealthCheck.
.DESCRIPTION
    Copy this file to LauncherConfig.ps1 (same folder) and fill in the values.
    LauncherConfig.ps1 is .gitignore'd.

    AUTHENTICATION METHODS (pick ONE -- launcher resolves in priority order)
      1. Managed Identity
      2. SPN + Key Vault-stored secret
      3. SPN + certificate (thumbprint)
      4. SPN + plaintext secret   [TESTING ONLY]

.NOTES
    Solution       : PlatformMonitoring
    File           : LauncherConfig.sample.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>

# ================================================================================
#  METHOD 1 -- Managed Identity
# ================================================================================
# $global:UseManagedIdentity = $true
# $global:SpnTenantId         = '<your-tenant-id-guid>'

# ================================================================================
#  METHOD 2 -- SPN + Key Vault-stored secret
# ================================================================================
# $global:SpnTenantId         = '<your-tenant-id-guid>'
# $global:SpnClientId         = '<your-app-client-id-guid>'
# $global:SpnKeyVaultName     = '<kv-name>'
# $global:SpnSecretName       = 'PlatformMonitoring-Secret'

# ================================================================================
#  METHOD 3 -- SPN + certificate thumbprint
# ================================================================================
# $global:SpnTenantId              = '<your-tenant-id-guid>'
# $global:SpnClientId              = '<your-app-client-id-guid>'
# $global:SpnCertificateThumbprint = '<cert thumbprint, hex, no spaces>'

# ================================================================================
#  METHOD 4 -- SPN + plaintext secret  *** TESTING ONLY ***
# ================================================================================
# WARNING: plaintext secrets in a .ps1 are fine for a short-lived lab but NOT
# recommended for production. Switch to Method 1/2/3 once onboarding is done.
$global:SpnTenantId     = '<your-tenant-id-guid>'
$global:SpnClientId     = '<your-app-client-id-guid>'
$global:SpnClientSecret = '<your-client-secret>'


# ================================================================================
#  MONITORING-SPECIFIC SETTINGS
# ================================================================================
# Free-text label that goes into email subject / body so you can tell which
# customer or environment an alert is from.
$global:CustomerName      = '<your customer or environment name>'

# SMTP settings for the alert email (required when any check fails).
$global:SmtpServer        = 'smtp.office365.com'
$global:SmtpFrom          = 'alerts@yourcompany.com'
$global:SmtpUseSsl        = $true

# For authenticated SMTP, pre-build a PSCredential and assign it:
#   $secSec = ConvertTo-SecureString '<smtp-password>' -AsPlainText -Force
#   $global:SmtpCredential = [pscredential]::new('<smtp-username>', $secSec)

# Alert recipient. The engine default is mok@2linkit.net (internal convention).
# COMMUNITY USERS: override this to your own mailbox.
$global:AlertEmailTo      = '<your-mailbox@yourcompany.com>'

# Check toggles. Either set these globals here and run the launcher without
# parameters, or leave them commented and pass -CheckXxxx switches to the
# launcher. Launcher parameters win when both are set.
# $global:CheckSecretExpiry          = $true
# $global:DaysBeforeExpiry           = 14
# $global:CheckKeyVaultConnectivity  = $true
# $global:KeyVaultName               = 'kv-securityinsight-prod'
# $global:CheckAzureConnectivity     = $true
# $global:CheckGraphConnectivity     = $true
# $global:CheckFunctionAppAccess     = $true
# $global:FunctionAppHealthUrl       = 'https://fn-securityinsight-prod.azurewebsites.net/api/health'
# $global:CheckInternetConnectivity  = $true
