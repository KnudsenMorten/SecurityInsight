#Requires -Version 5.1
<#
    SecurityInsight's guided install as a COMMAND: after extracting the SecurityInsight package,

        Import-Module <package>/setup/Install-SecurityInsight.psd1
        Install-SecurityInsight -ConfigPath <dir>/config.json -LicencePath <dir>/<file>.silicense -Reporter { param($e) ... } -StatePath <dir>

    makes "Get-Command Install-SecurityInsight" find it -- that is how invardia.com's bootstrap locates the entry point.
    The function only FORWARDS: every parameter goes unchanged to setup/Install-SecurityInsight.ps1 next to this file,
    and that script's exit code (0 installed, 1 a step failed, 2 a check failed, 3 config.json is not valid) is left in
    $LASTEXITCODE. Paths are built with [IO.Path]::Combine, so it works the same in Azure Cloud Shell (Linux).
#>

$script:SIInstallScript = [IO.Path]::Combine($PSScriptRoot, 'Install-SecurityInsight.ps1')

function Install-SecurityInsight {
    <#
    .SYNOPSIS
        Installs SecurityInsight from the guided install's answers (runs setup/Install-SecurityInsight.ps1).
    .DESCRIPTION
        See setup/Install-SecurityInsight.ps1. Exit code in $LASTEXITCODE: 0 installed (warnings included), 1 a step
        failed, 2 a check failed, 3 config.json is not valid.
    #>
    [CmdletBinding(SupportsShouldProcess)]   # -WhatIf goes to the script with the other parameters (the checks only)
    param(
        [string]$ConfigPath,
        # the common answers as parameters (setup/Install-SecurityInsight.ps1 writes config.json from them)
        [string]$TenantId,
        [string]$SubscriptionId,
        [string]$Location,
        [string]$ResourceGroup,
        [string[]]$MailTo,
        [ValidateSet('subscription', 'managementGroup', 'tenantRoot')][string]$CollectionScope,
        [string]$ManagementGroupId,
        [switch]$PrivateNetwork,
        [string]$VnetAddressPrefix,
        [string]$InstallId,
        [string]$LicencePath,
        [scriptblock]$Reporter,
        [switch]$PreflightOnly,
        [switch]$Resume,
        [string]$StatePath,
        # Tests only (forwarded unchanged): replacements for the calls that leave the process, and the config file path.
        [Parameter(DontShow)][System.Collections.IDictionary]$Seams,
        [Parameter(DontShow)][string]$SIConfigPath
    )
    $forward = @{}
    foreach ($k in $PSBoundParameters.Keys) { $forward[$k] = $PSBoundParameters[$k] }
    $global:LASTEXITCODE = 0
    & $script:SIInstallScript @forward
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 0 }
    $global:LASTEXITCODE = [int]$code
}

Export-ModuleMember -Function Install-SecurityInsight
