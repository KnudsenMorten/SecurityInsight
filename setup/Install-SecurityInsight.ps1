<#
.SYNOPSIS
    Installs SecurityInsight from the answers of the guided install on invardia.com -- unattended, step by step, with
    the status of every step reported as it happens.

.DESCRIPTION
    Runs in Azure Cloud Shell (PowerShell 7) as the person signed in there, and on Windows PowerShell 7 / 5.1. invardia.com's
    bootstrap calls it with the wizard's answers and the licence; it can also be run by hand.

      1. Checks first, changes nothing: the sign-in, the tenant and subscription, your permissions, the resource
         providers, that the names are free and that the region accepts the database.
      2. Installs, one step at a time, with the product's own proven setup scripts: resource group, workspace, data
         collection endpoint, storage, Key Vault, the licence (Pro), the container registry and image, the Container Apps
         environment, SecurityInsight's managed identity and its grants, the engine jobs, the database, its tables,
         templates and settings, the web app and the updater -- in both versions; the paid features are switched off by
         the licence -- then the Invardia Support access, the first run and a health check.
      3. Reports every step to -Reporter as it starts and ends. Nothing secret is ever reported.

    What your account cannot grant (read access outside the resource group, the read-only API permissions, support
    access) does not stop the install: the step ends as a warning with the exact command for the person who can, and
    the install completes. Only a problem nothing can work around stops it -- run the same command again with -Resume
    and it continues from that step.

    The keys a feature needs (Azure OpenAI, Shodan, the SMTP password) are never in config.json. When the feature is on
    you are asked for them here, and they go straight to the install's Key Vault; without a console they are left for
    later, with the command to add them.

.PARAMETER ConfigPath
    config.json -- the wizard's answers, keyed as in setup\install-parameters.json, plus installId. Not needed when the
    answers are given as parameters (-TenantId, -SubscriptionId ...).
.PARAMETER TenantId
    The tenant SecurityInsight assesses. With -SubscriptionId, all an install needs: every other answer has a default.
.PARAMETER SubscriptionId
    The subscription for SecurityInsight's own resources.
.PARAMETER Location
    The Azure region (default westeurope).
.PARAMETER ResourceGroup
    The resource group, created when it does not exist (default rg-si-prod-community-ca).
.PARAMETER MailTo
    Who receives the reports (default: you).
.PARAMETER CollectionScope
    What SecurityInsight reads in Azure: subscription (default), managementGroup (with -ManagementGroupId) or tenantRoot.
.PARAMETER ManagementGroupId
    The management group, with -CollectionScope managementGroup.
.PARAMETER PrivateNetwork
    SecurityInsight in a virtual network only, with private endpoints (give -VnetAddressPrefix for its own network).
.PARAMETER VnetAddressPrefix
    With -PrivateNetwork: a free address range for SecurityInsight's own network, e.g. 10.212.24.0/24.
.PARAMETER InstallId
    The install's name (default securityinsight): its state folder ~/clouddrive/invardia/<installId> keeps the answers,
    so the install continues with -Resume alone.
.PARAMETER LicencePath
    The SecurityInsight Pro licence file (.silicense). Without one the free version is installed -- with its database and
    web app; the paid features stay off until a licence is added.
.PARAMETER Reporter
    { param($event) ... } -- called at the start and end of every step. The event: installId, seq, step {id, title},
    state (started | ok | warning | failed | skipped | completed), at, durationMs, message, action {text, command},
    detail (at most 8 KB); 'completed' also carries outputs.
.PARAMETER PreflightOnly
    Run the checks only. Nothing is created, changed or written.
.PARAMETER Resume
    Continue an install that stopped: the steps already done are skipped.
.PARAMETER StatePath
    The folder for the install's state file. Default: ~/clouddrive/invardia/<installId> (kept by Cloud Shell).

.OUTPUTS
    Exit code: 0 installed (warnings included), 1 a step failed, 2 a check failed, 3 config.json is not valid.

.EXAMPLE
    ./setup/Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>'
    # the quickest install: every other answer has its default
.EXAMPLE
    ./setup/Install-SecurityInsight.ps1 -Resume
    # continue an install that stopped, with the answers of its first run
.EXAMPLE
    ./setup/Install-SecurityInsight.ps1 -ConfigPath ./config.json -LicencePath ./contoso.silicense -Reporter { param($e) $e | ConvertTo-Json -Compress -Depth 6 }
.EXAMPLE
    ./setup/Install-SecurityInsight.ps1 -ConfigPath ./config.json -PreflightOnly
.EXAMPLE
    Import-Module ./setup/Install-SecurityInsight.psd1
    Install-SecurityInsight -ConfigPath ./config.json -LicencePath ./contoso.silicense -Reporter { param($e) ... } -StatePath ./state
    # the same install as a command (how invardia.com's bootstrap calls it); the exit code is in $LASTEXITCODE

.LINK
    https://invardia.com/docs/si/scripts/Install-SecurityInsight/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath,
    # The common answers as parameters (no config.json to write by hand): the script writes config.json itself, in the
    # install's state folder, so -Resume alone finds it again. -ConfigPath is for every other setting.
    [string]$TenantId,
    [string]$SubscriptionId,
    [string]$Location,
    [string]$ResourceGroup,
    [string[]]$MailTo,
    [ValidateSet('subscription', 'managementGroup', 'tenantRoot')][string]$CollectionScope,
    [string]$ManagementGroupId,
    [switch]$PrivateNetwork,
    [string]$VnetAddressPrefix,
    [string]$InstallId = 'securityinsight',
    [string]$LicencePath,
    [scriptblock]$Reporter,
    [switch]$PreflightOnly,
    [switch]$Resume,
    [string]$StatePath,
    # Tests only: replacements for the calls that leave this process (Az, AzCli, Graph, Sql, Token, Script, ...).
    [Parameter(DontShow)][System.Collections.IDictionary]$Seams,
    # Tests only: where the install's config file is written (default: config\SecurityInsight.custom.ps1 of this copy).
    [Parameter(DontShow)][string]$SIConfigPath
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Install-SecurityInsight' -Quiet:([bool]$PSBoundParameters.ContainsKey('Seams'))
if ($WhatIfPreference) { $PreflightOnly = [switch]$true }   # -WhatIf = the checks only: nothing is created, changed or written
try {
$ErrorActionPreference = 'Stop'
# PowerShell hands a script parameter "~/x.json" over as the literal text; .NET then reads "<cwd>/~/x.json" (found on the
# first live install, 2026-10-04, Cloud Shell). Resolve ~ and relative paths against PowerShell's own location here.
foreach ($pn in 'ConfigPath', 'LicencePath', 'StatePath') {
    $pv = Get-Variable -Name $pn -ValueOnly
    if ("$pv".Trim()) { Set-Variable -Name $pn -Value $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath("$pv".Trim()) }
}
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($siRoot, 'setup', '_shared', 'SI-GuidedInstall.ps1'))
# The database and web app steps: in BOTH versions (owner 2026-10-18)
. ([IO.Path]::Combine($siRoot, 'setup', '_shared', 'SI-GuidedInstallData.ps1'))
# The paid steps (the licence, the v2.2 CMDB migration) ship only in the Pro package.
$proSteps = [IO.Path]::Combine($siRoot, 'setup', '_shared', 'SI-GuidedInstallPro.ps1')
if (Test-Path -LiteralPath $proSteps) { . $proSteps }

if (-not "$ConfigPath".Trim()) {
    $direct = Resolve-SIInstallDirectConfig -Bound $PSBoundParameters -InstallId $InstallId -StatePath $StatePath -PreflightOnly:$PreflightOnly -Resume:$Resume
    if (-not $direct.Ok) { Write-Host $direct.Message -ForegroundColor Red; exit 3 }
    $ConfigPath = $direct.ConfigPath
    if ($direct.Message) { Write-Host $direct.Message }
}

$code = Invoke-SIGuidedInstall -SIRoot $siRoot -ConfigPath $ConfigPath -LicencePath $LicencePath -Reporter $Reporter `
    -PreflightOnly:$PreflightOnly -Resume:$Resume -StatePath $StatePath -Seams $Seams -SIConfigPath $SIConfigPath
exit ([int]$code)
} finally { Stop-SIScriptRun -Run $siRun }
