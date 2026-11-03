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
        # EVERY answer is a parameter, as on setup/Install-SecurityInsight.ps1 (one per key of setup/install-parameters.json)
        [string]$TenantId,
        [string]$SubscriptionId,
        [string]$Location,
        [string]$ResourceGroup,
        [string]$Owner,
        [ValidateSet('container')][string]$Hosting,
        [ValidateSet('new', 'existing')][string]$WorkspaceMode,
        [string]$WorkspaceName,
        [string]$WorkspaceId,
        [string]$SecurityWorkspaceId,
        [ValidateSet('subscription', 'managementGroup', 'tenantRoot')][string]$CollectionScope,
        [string]$ManagementGroupId,
        [switch]$AiClassification,
        [string]$OpenAiEndpoint,
        [string]$OpenAiDeployment,
        [switch]$Shodan,
        [ValidateRange(0, 20)][int]$RunHourUtc,
        [string]$PipelineStartTime,
        [string]$PipelineTimeZone,
        [ValidateSet('sharedMailbox', 'smtp', 'none')][string]$MailMode,
        [string]$MailFrom,
        [bool]$MailboxCreate,
        [string[]]$MailTo,
        [string]$SmtpServer,
        [ValidateRange(1, 65535)][int]$SmtpPort,
        [string]$SmtpUser,
        [string]$SmtpFrom,
        [string]$SqlLocation,
        [string]$SqlAdminGroupId,
        [bool]$WebApp,
        [ValidateSet('external', 'internal')][string]$WebAppAccess,
        [string[]]$WebAppAdmins,
        [switch]$AssetTaggingWrites,
        [ValidateSet(1, 2, 3)][int]$UpdateRing,
        [string]$ServiceNowUrl,
        [switch]$PrivateNetwork,
        [string]$VnetId,
        [string]$VnetAddressPrefix,
        [string]$VnetName,
        [string]$AppsSubnetName,
        [string]$AppsSubnetPrefix,
        [string]$EndpointsSubnetName,
        [string]$EndpointsSubnetPrefix,
        [string]$PrivateDnsZonesResourceGroupId,
        [string]$HubVnetId,
        [switch]$LinkZonesToHub,
        [switch]$PeerToHub,
        [switch]$CustomerManagedKeys,
        [string]$CmkKeyVaultId,
        [string]$CmkKeyName,
        [ValidateSet('off', 'cluster-existing', 'cluster-new')][string]$CmkLogAnalytics,
        [string]$LogAnalyticsClusterId,
        [string]$SupportAppId,
        [ValidateSet('troubleshoot', 'setup')][string]$SupportAccess,
        [switch]$ViaSupportApp,
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
