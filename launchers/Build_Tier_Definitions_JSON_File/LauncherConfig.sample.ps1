#Requires -Version 5.1
<#
.SYNOPSIS
    Community-edition customer configuration for Build_Tier_Definitions_JSON_File.
.DESCRIPTION
    Copy to LauncherConfig.ps1 (same folder) and fill in your SPN values.
    LauncherConfig.ps1 is .gitignore'd so the populated copy stays local.
#>
$global:SpnTenantId     = '<your-tenant-id-guid>'
$global:SpnClientId     = '<your-app-client-id-guid>'
$global:SpnClientSecret = '<your-client-secret>'
