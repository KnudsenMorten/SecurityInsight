#Requires -Version 5.1
<#
.SYNOPSIS
    Community-edition customer test config for Deploy_OpenAI (Secondary).
.DESCRIPTION
    Copy to LauncherConfig.ps1 (same folder), fill in your TEST SPN values
    (a separate SPN with Cognitive Services Contributor on the target
    subscription is recommended). LauncherConfig.ps1 is .gitignore'd.
#>
$global:SpnTenantId     = '<test-tenant-id-guid>'
$global:SpnClientId     = '<test-app-client-id-guid>'
$global:SpnClientSecret = '<test-client-secret>'
