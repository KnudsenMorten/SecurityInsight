#Requires -Version 5.1
<#
.SYNOPSIS
    Single-entry, SELF-CONTAINED setup orchestrator for SecurityInsight v2.2.
    Inlines the logic from Setup-SecurityInsight (Github phase)..Deploy-SIPowerBI (no external & invocations) and adds
    the v2.2-only phases (PrivilegeTier, Schemas, PublicIp, RA), gated by
    switches.

.DESCRIPTION
    Replaces the multi-script onboarding flow (Setup-SecurityInsight (Github phase)..Deploy-SIPowerBI + InitialDeployment)
    with a single parameter-driven entry point. Idempotent everywhere: each
    phase checks tenant state before acting, so re-running is safe.

    The phase set:

      Config          -> generate config + per-engine LauncherConfig stubs
      Github          -> pull/refresh repo                           (Setup-SecurityInsight (Github phase) inlined)
      Spn             -> SPN + API perms + Azure RBAC                (Validate-SIPermissions inlined)
      LA              -> workspace + DCE + DCRs + tables             (Validate-SILogAnalytics inlined)
      OpenAI          -> Azure OpenAI PAYG instance + model deploy   (Validate-SIOpenAI inlined)
      PrivilegeTier   -> regenerate privilege-tier-catalog.custom.json      (v2.2 NEW)
      Schemas         -> schema-drift detection report               (v2.2 NEW)
      PublicIp        -> Shodan API key + PublicIp DCR sanity        (v2.2 NEW)
      RA              -> RA reports template wiring sanity           (v2.2 NEW)
      PBI             -> Power BI dashboard deploy                   (Deploy-SIPowerBI inlined)
      Summary         -> end-of-run summary table                    (always)

.PARAMETER Phase
    One or more phase names (case-insensitive). Use 'All' to run every phase
    in canonical order. Default: prompts interactively.

.PARAMETER WhatIf
    Dry-run. Each phase prints its planned actions without executing.

.PARAMETER Force
    Re-run a phase even if its state suggests it's already complete (e.g.,
    regenerate privilege-tier-catalog when fresh).

.PARAMETER SkipShodan
    Skip the Shodan API key prompt during -Phase PublicIp.

.EXAMPLE
    .\Setup-SecurityInsight.ps1 -Phase All

.EXAMPLE
    .\Setup-SecurityInsight.ps1 -Phase LA, PrivilegeTier, PublicIp

.EXAMPLE
    .\Setup-SecurityInsight.ps1 -Phase All -WhatIf

.EXAMPLE
    .\Setup-SecurityInsight.ps1 -Wizard
    Opens the offline web GUI (setup/ConfigWizard/Setup-SecurityInsight.html)
    in your default browser so you can fill in tenant / workspace / DCE values
    and copy the generated snippets into your *.custom.* files. No phases run.

.NOTES
    Solution     : SecurityInsight v2.2
    Developed by : Morten Knudsen, Microsoft MVP
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(HelpMessage = "Phases to run (or 'All'). If empty, prompts interactively.")]
    [ValidateSet('All','Config','Github','Spn','LA','OpenAI','PrivilegeTier','Schemas','PublicIp','RA','PBI','Summary')]
    [string[]]$Phase,

    [switch]$Force,
    [switch]$SkipShodan,

    # Open the offline web GUI (setup/ConfigWizard/Setup-SecurityInsight.html)
    # in the default browser and exit. Mutually exclusive with -Phase.
    [switch]$Wizard,
    # With -Wizard: print the file:// URL but do NOT spawn a browser. Useful
    # for headless runs / docs / piping into another tool.
    [switch]$NoBrowser,

    # ----- Phase Config -- credential + workspace identity (used to generate
    # config/SecurityInsight.custom.ps1 + per-engine LauncherConfig.custom.ps1).
    # All optional -- if omitted, Config phase prompts interactively for missing values.
    [string]$SpnTenantId,
    [string]$SpnAppId,
    [string]$SpnClientSecret,             # plaintext, written to a gitignored file
    [string]$SpnKeyVaultName,             # OR use KV-stored secret instead of plaintext
    [string]$SpnSecretName,
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$WorkspaceName,
    [string]$WorkspaceResourceGroup,
    [string]$DceName,
    [string]$DcrResourceGroup,
    [string]$Region,
    [string]$ShodanApiKey,

    # ----- Phase Github (Setup-SecurityInsight (Github phase) inlined) -----
    [string]$GithubRepo            = 'KnudsenMorten/SecurityInsight',
    [string]$GithubDestinationPath = 'C:\SCRIPTS\SecurityInsight',
    [ValidateSet('stable','preview')][string]$GithubChannel = 'stable',
    [string]$GithubEngine          = '',
    [string[]]$GithubPreservePatterns = @(
        'launchers\*\LauncherConfig.ps1',
        'launchers\*\LauncherConfig.custom.ps1',
        'launchers\*\launcher.override.ps1',
        'config\*',
        'data\*_Custom.*',
        'DATA\*_Custom.*'
    ),

    # ----- Phase Spn (Validate-SIPermissions inlined) -----
    [string]$SpnDisplayName = 'sp-securityinsight',
    [string[]]$AzureSubscriptionIds,
    [string]$DefenderWorkspaceResourceId,
    [string]$DcrResourceId,
    [ValidateSet('TenantRoot','PerSubscription')]
    [string]$AzureRbacScope = 'TenantRoot',
    [ValidateSet('Interactive','ManagedIdentity','SpnSecret','SpnCertificate')]
    [string]$AuthMethod = 'Interactive',
    [string]$AuthTenantId,
    [string]$AuthClientId,
    [string]$AuthClientSecret,
    [string]$AuthCertificateThumbprint,

    # ----- Phase OpenAI (Validate-SIOpenAI inlined) -----
    [string]$OpenAIAccountName,
    [string]$OpenAIDeploymentName,
    [string]$OpenAIModelName,
    [string]$OpenAIModelVersion,
    [int]$OpenAICapacity,
    [ValidateSet('Enabled','Disabled')]
    [string]$OpenAIPublicNetworkAccess = 'Enabled',
    [string[]]$OpenAIDeploymentSkuOrder = @('GlobalStandard'),
    [switch]$OpenAIValidateOnly,

    # ----- Phase PBI (Deploy-SIPowerBI inlined) -----
    [string]$PbixPath,
    [string]$PowerBIWorkspaceName = 'SecurityInsight-Reports',
    [string]$PowerBIReportName    = 'SecurityInsight - Risk Analysis',
    [string]$LAWorkspaceId,
    [string]$LATenantId,
    [int]$PowerBIStalenessDays = 30,
    [int]$PowerBITopNFindings  = 25,
    [string]$PowerBIAccessGroupObjectId,
    [ValidateSet('Viewer','Member','Contributor','Admin')]
    [string]$PowerBIAccessGroupRole = 'Viewer',
    [switch]$PowerBITriggerInitialRefresh,
    [ValidateSet('Interactive','ManagedIdentity','SpnSecret','SpnCertificate')]
    [string]$PowerBIAuthMethod = 'SpnSecret'
)

$ErrorActionPreference = 'Stop'
$script:_t0 = [datetime]::UtcNow
$script:_log = New-Object System.Collections.Generic.List[hashtable]
$script:_setupRoot = $PSScriptRoot
$script:_v22Root   = Split-Path -Parent $script:_setupRoot

# ---------------------------------------------------------------------------
# -Wizard short-circuit: open the offline web GUI and exit. The wizard is
# 100% static HTML/CSS/JS -- no Node, no build, no remote fetches. State is
# persisted in localStorage; nothing leaves the workstation.
# ---------------------------------------------------------------------------
if ($Wizard) {
    # Setup-SecurityInsight.ps1 lives at the v2.2 root; the wizard is a sibling
    # of this script under setup\ConfigWizard\.
    $wizardHtml = Join-Path $PSScriptRoot 'setup\ConfigWizard\Setup-SecurityInsight.html'
    if (-not (Test-Path -LiteralPath $wizardHtml)) {
        Write-Error "Wizard not found at: $wizardHtml`nMake sure setup\ConfigWizard\ shipped with the solution."
        return
    }
    $wizardUrl = 'file:///' + ($wizardHtml -replace '\\', '/')
    if ($NoBrowser) {
        Write-Host "Wizard URL (paste into a browser): $wizardUrl" -ForegroundColor Cyan
    } else {
        Write-Host "Opening wizard: $wizardUrl" -ForegroundColor Cyan
        Start-Process $wizardUrl
    }
    return
}

# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------
function Write-Section($m) { Write-Host ''; Write-Host ('=' * 100) -ForegroundColor Cyan; Write-Host ("  $m") -ForegroundColor Cyan; Write-Host ('=' * 100) -ForegroundColor Cyan }
function Write-Phase($n,$d) { Write-Host ''; Write-Host ("--- PHASE :: $n :: $d ---") -ForegroundColor Yellow }
function Write-Step($m) { Write-Host ("[STEP]  $m") -ForegroundColor Cyan }
function Write-Info($m) { Write-Host ("[INFO]  $m") -ForegroundColor White }
function Write-Ok($m)   { Write-Host ("[OK]    $m") -ForegroundColor Green }
function Write-Warn2($m){ Write-Host ("[WARN]  $m") -ForegroundColor Yellow }
function Write-Err2($m) { Write-Host ("[ERR]   $m") -ForegroundColor Red }
function Write-Add($m)  { Write-Host ("[GRANTED] $m") -ForegroundColor Yellow }
function Write-Skip($m) { Write-Host ("[SKIP]  $m") -ForegroundColor DarkYellow }
function Write-Sep      { Write-Host ('-' * 88) -ForegroundColor White }

function Add-Result($name, $status, $start, $detail = '') {
    $script:_log.Add(@{
        Phase    = $name
        Status   = $status
        Duration = ('{0:n1}s' -f ([datetime]::UtcNow - $start).TotalSeconds)
        Detail   = $detail
    }) | Out-Null
}

# ---------------------------------------------------------------------------
# Phase canonical order (when -Phase All)
# ---------------------------------------------------------------------------
$script:_phaseOrder = @(
    'Config','Github','Spn','LA','OpenAI','PrivilegeTier','Schemas','PublicIp','RA','PBI'
)

# ---------------------------------------------------------------------------
# Phase implementations (each returns a status string)
# ---------------------------------------------------------------------------

function Get-OrPrompt([string]$current, [string]$prompt, [switch]$Mandatory) {
    if (-not [string]::IsNullOrWhiteSpace($current)) { return $current }
    $val = Read-Host $prompt
    if ($Mandatory -and [string]::IsNullOrWhiteSpace($val)) { throw "$prompt is required." }
    return $val
}

function Invoke-Phase-Config {
    Write-Phase 'Config' 'Generate config/SecurityInsight.custom.ps1 + per-engine LauncherConfig.custom.ps1'

    $solnRoot     = Split-Path -Parent $script:_v22Root
    $customDataDir = Join-Path $solnRoot 'config'
    $masterCustom  = Join-Path $customDataDir 'SecurityInsight.custom.ps1'
    if (-not (Test-Path $customDataDir)) { New-Item $customDataDir -ItemType Directory -Force | Out-Null }

    if ((Test-Path $masterCustom) -and -not $Force) {
        Write-Info "$masterCustom already exists -- skipping (use -Force to regenerate)."
    } else {
        Write-Info 'Collecting tenant + SPN config (press ENTER to skip optional fields).'
        $tenantId = Get-OrPrompt $SpnTenantId           'Tenant ID (GUID)'
        $appId    = Get-OrPrompt $SpnAppId              'SPN AppId / ClientId (GUID)'
        $kvName   = Get-OrPrompt $SpnKeyVaultName       'Key Vault name (optional, leave blank for plaintext secret)'
        $kvSecret = Get-OrPrompt $SpnSecretName         'KV secret name (optional, default SecurityInsight-Secret)'
        $secret   = if ($kvName) { '' } else { Get-OrPrompt $SpnClientSecret 'SPN Client Secret (plaintext, leave blank for KV)' }
        $subId    = Get-OrPrompt $SubscriptionId        'Subscription ID (GUID)'
        $rg       = Get-OrPrompt $ResourceGroup         'Default resource group (e.g. rg-securityinsight)'
        $wsName   = Get-OrPrompt $WorkspaceName         'Log Analytics workspace name'
        $wsRg     = Get-OrPrompt $WorkspaceResourceGroup ('Workspace resource group (default: ' + $rg + ')')
        if (-not $wsRg) { $wsRg = $rg }
        $dceName  = Get-OrPrompt $DceName               'DCE name (default: dce-securityinsight)'
        if (-not $dceName) { $dceName = 'dce-securityinsight' }
        $dcrRg    = Get-OrPrompt $DcrResourceGroup      ('DCE/DCR resource group (default: ' + $rg + ')')
        if (-not $dcrRg) { $dcrRg = $rg }

        $wsResId = "/subscriptions/$subId/resourceGroups/$wsRg/providers/Microsoft.OperationalInsights/workspaces/$wsName"

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('#Requires -Version 5.1')
        [void]$sb.AppendLine('# SecurityInsight customer config -- gitignored. Generated by Setup-SecurityInsight.ps1.')
        [void]$sb.AppendLine(('# Generated: {0}' -f ([datetime]::UtcNow).ToString('o')))
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('# ----- AUTH (single SPN handles Defender + LA ingest) -----')
        [void]$sb.AppendLine(("`$global:SI_SPN_TenantId = '{0}'" -f $tenantId))
        [void]$sb.AppendLine(("`$global:SI_SPN_AppId    = '{0}'" -f $appId))
        if ($kvName) {
            if (-not $kvSecret) { $kvSecret = 'SecurityInsight-Secret' }
            [void]$sb.AppendLine(("`$global:SpnKeyVaultName = '{0}'" -f $kvName))
            [void]$sb.AppendLine(("`$global:SpnSecretName   = '{0}'" -f $kvSecret))
        } elseif ($secret) {
            [void]$sb.AppendLine(("`$global:SI_SPN_Secret   = '{0}'" -f $secret))
        }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('# ----- AZURE WORKSPACE / DCE / DCR -----')
        [void]$sb.AppendLine(("`$global:SubscriptionId            = '{0}'" -f $subId))
        [void]$sb.AppendLine(("`$global:WorkspaceResourceId       = '{0}'" -f $wsResId))
        [void]$sb.AppendLine(("`$global:SI_WorkspaceResourceId    = '{0}'" -f $wsResId))
        [void]$sb.AppendLine(("`$global:SI_DceName                = '{0}'" -f $dceName))
        [void]$sb.AppendLine(("`$global:SI_DcrResourceGroup       = '{0}'" -f $dcrRg))
        [void]$sb.AppendLine(("`$global:DceName                   = '{0}'" -f $dceName))
        [void]$sb.AppendLine(("`$global:DceResourceGroup          = '{0}'" -f $dcrRg))
        [void]$sb.AppendLine(("`$global:DcrResourceGroup          = '{0}'" -f $dcrRg))

        if ($PSCmdlet.ShouldProcess($masterCustom, 'create config file')) {
            [System.IO.File]::WriteAllText($masterCustom, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
            Write-Ok "wrote $masterCustom"
        }
    }

    # ----- Per-engine LauncherConfig.custom.ps1 stubs -----
    $launcherDir = Join-Path $script:_v22Root 'launcher'
    if (Test-Path $launcherDir) {
        $engineDirs = Get-ChildItem $launcherDir -Directory | Where-Object { $_.Name -ne '_lib' }
        foreach ($d in $engineDirs) {
            $sample  = Join-Path $d.FullName 'LauncherConfig.custom.sample.ps1'
            $custom  = Join-Path $d.FullName 'LauncherConfig.custom.ps1'
            if (-not (Test-Path $sample)) { continue }
            if ((Test-Path $custom) -and -not $Force) { continue }
            if ($PSCmdlet.ShouldProcess($custom, 'stub from sample')) {
                Copy-Item $sample $custom -Force
                Write-Ok "stubbed $custom"
            }
        }
    }

    # ----- Shodan key into PublicIp launcher -----
    $publicIpCustom = Join-Path $script:_v22Root 'launcher\publicip\LauncherConfig.custom.ps1'
    if (Test-Path $publicIpCustom) {
        $raw = Get-Content $publicIpCustom -Raw
        if ($raw -notmatch '\$global:SI_Shodan_ApiKey\s*=\s*[''"][^''"]+[''"]') {
            $key = if ($ShodanApiKey) { $ShodanApiKey }
                   elseif ($SkipShodan) { '' }
                   else { Read-Host 'Shodan API key (paste, or ENTER to skip)' }
            if (-not [string]::IsNullOrWhiteSpace($key)) {
                if ($PSCmdlet.ShouldProcess($publicIpCustom, 'inject Shodan API key')) {
                    Add-Content -LiteralPath $publicIpCustom -Value ("`$global:SI_Shodan_ApiKey = '{0}'" -f $key)
                    Write-Ok 'Shodan API key written'
                }
            }
        }
    }

    return 'ok'
}

# ============================================================================
# Phase Github -- inlined from Setup-SecurityInsight.ps1 -Phase Github
# ============================================================================
function Invoke-Phase-Github {
    Write-Phase 'Github' 'Onboard / refresh SecurityInsight code from GitHub release'

    $repo            = $GithubRepo
    $destinationPath = $GithubDestinationPath
    $channel         = $GithubChannel
    $engine          = $GithubEngine
    $preservePatterns = $GithubPreservePatterns

    Write-Host ""
    Write-Host ("  Repo           : {0}" -f $repo)            -ForegroundColor White
    Write-Host ("  Destination    : {0}" -f $destinationPath) -ForegroundColor White
    Write-Host ("  Channel        : {0}" -f $channel)         -ForegroundColor White
    if ($engine) { Write-Host ("  Target launcher: {0}" -f $engine) -ForegroundColor White }

    if ($WhatIfPreference) {
        Write-Info "(WhatIf) would download $channel of $repo into $destinationPath"
        return 'whatif'
    }

    $staging = Join-Path $env:TEMP ("csol-" + [guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Force -Path $staging | Out-Null

    try {
        if ($channel -eq 'stable') {
            Write-Step "Resolving latest stable release"
            $rel   = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing
            $asset = $rel.assets | Where-Object name -Like '*.zip' | Select-Object -First 1
            if (-not $asset) { throw "No .zip asset on latest release of $repo." }
            $zip = Join-Path $env:TEMP $asset.name
            Write-Info ("tag    : {0}" -f $rel.tag_name)
            Write-Info ("asset  : {0}" -f $asset.name)
            Write-Step "Downloading"
            Invoke-WebRequest $asset.browser_download_url -OutFile $zip -UseBasicParsing
            Expand-Archive -Path $zip -DestinationPath $staging -Force
            Remove-Item $zip
            $version = $rel.tag_name
        } else {
            Write-Step "Downloading preview branch HEAD"
            $zip = Join-Path $env:TEMP ("$($repo -replace '.+/','')-preview.zip")
            Invoke-WebRequest "https://github.com/$repo/archive/refs/heads/preview.zip" -OutFile $zip -UseBasicParsing
            $tmp = Join-Path $env:TEMP ("expand-" + [guid]::NewGuid().ToString('N').Substring(0,8))
            Expand-Archive -Path $zip -DestinationPath $tmp -Force
            $inner = Get-ChildItem -Path $tmp -Directory | Select-Object -First 1
            Move-Item -Path (Join-Path $inner.FullName '*') -Destination $staging -Force
            Remove-Item $tmp -Recurse -Force
            Remove-Item $zip
            $version = 'preview HEAD'
        }
        Write-Ok ("downloaded: {0}" -f $version)

        Write-Step "Merging into $destinationPath (preserving customer files)"
        if (-not (Test-Path $destinationPath)) {
            New-Item -ItemType Directory -Force -Path $destinationPath | Out-Null
            Write-Info "created destination"
        }

        $copied = 0; $lockedUpdate = 0; $preserved = 0
        Get-ChildItem -Path $staging -Recurse -File | ForEach-Object {
            $rel = $_.FullName.Substring($staging.Length + 1)
            $dst = Join-Path $destinationPath $rel

            $shouldPreserve = $false
            foreach ($pat in $preservePatterns) {
                if ($rel -like $pat) { $shouldPreserve = $true; break }
            }
            if ($shouldPreserve -and (Test-Path -LiteralPath $dst)) {
                Write-Host ("[PRESERVE] {0}" -f $rel) -ForegroundColor White
                $preserved++
                return
            }

            $dstDir = Split-Path -Parent $dst
            if (-not (Test-Path -LiteralPath $dstDir)) {
                New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
            }
            Copy-Item -LiteralPath $_.FullName -Destination $dst -Force
            if ($rel -like '*_Locked.*') {
                Write-Host ("[UPDATE]   {0}  (locked content -- force-refreshed from release)" -f $rel) -ForegroundColor Green
                $lockedUpdate++
            }
            $copied++
        }
        Write-Ok ("copied: $copied files  ({0} of which are *_Locked.* force-refreshed)  |  preserved: $preserved customer file(s)" -f $lockedUpdate)

        # Optional: cd into a launcher folder so the operator lands ready to run.
        $launchersRoot = Get-ChildItem -Path $destinationPath -Directory |
                         Where-Object { $_.Name -ieq 'launchers' -or $_.Name -ieq 'LAUNCHERS' } |
                         Select-Object -First 1
        if ($launchersRoot) {
            $engineDirs = Get-ChildItem -Path $launchersRoot.FullName -Directory | Where-Object { $_.Name -ne '_lib' } | Sort-Object Name
            if ($engine) {
                $match = $engineDirs | Where-Object { $_.Name -ieq $engine } | Select-Object -First 1
                if ($match) {
                    Set-Location -LiteralPath $match.FullName
                    Write-Info ("Now in: {0}" -f $match.FullName)
                } else {
                    Write-Warn2 "Engine '$engine' not found under $($launchersRoot.FullName)."
                }
            }
        } else {
            Write-Warn2 "No launchers/ folder under $destinationPath."
        }
    }
    finally {
        if (Test-Path -LiteralPath $staging) { Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue }
    }

    return 'ok'
}

# ============================================================================
# Phase Spn -- inlined from Validate-SIPermissions.ps1
# ============================================================================
function Invoke-Phase-Spn {
    Write-Phase 'Spn' 'SPN + API permissions + Azure RBAC'

    # _shared/Ensure-Module.ps1 provides Ensure-SecurityInsightModules
    $ensureScript = Join-Path $script:_setupRoot '_shared\Ensure-Module.ps1'
    if (Test-Path $ensureScript) { . $ensureScript; Ensure-SecurityInsightModules }

    $whatIfMode = [bool]$WhatIfPreference

    # ---- catalogs ----
    $RequiredApiPermissions = @(
        @{
            ResourceDisplayName = 'Microsoft Graph'
            ResourceAppId       = '00000003-0000-0000-c000-000000000000'
            Permissions         = @(
                'User.Read.All','Group.Read.All','Directory.Read.All','Application.Read.All',
                'AuditLog.Read.All','Policy.Read.All','RoleManagement.Read.All',
                'RoleManagement.Read.Directory','RoleManagementPolicy.Read.Directory',
                'RoleEligibilitySchedule.Read.Directory','RoleAssignmentSchedule.Read.Directory',
                'IdentityRiskyUser.Read.All','IdentityRiskEvent.Read.All',
                'IdentityRiskyServicePrincipal.Read.All','ThreatHunting.Read.All'
            )
        }
        @{
            ResourceDisplayName = 'Microsoft Threat Protection'
            ResourceAppId       = '8ee8fdad-f234-4243-8f3b-15c294843740'
            Permissions         = @('AdvancedHunting.Read.All')
        }
        @{
            ResourceDisplayName = 'WindowsDefenderATP'
            ResourceAppId       = 'fc780465-2017-40d4-a0c5-307022471b92'
            Permissions         = @('Machine.ReadWrite.All')
        }
    )
    $RequiredAzureRoles = @{
        AzureRoles             = @('Reader', 'Tag Contributor')
        DefenderWorkspaceRoles = @('Log Analytics Reader')
        DcrRoles               = @('Monitoring Metrics Publisher')
    }

    $results = New-Object System.Collections.Generic.List[object]
    function Add-SpnResult {
        param([string]$Category, [string]$Item, [string]$Status, [string]$Detail = '')
        $results.Add([pscustomobject]@{ Category=$Category; Item=$Item; Status=$Status; Detail=$Detail }) | Out-Null
    }

    # ---- Connect to Azure FIRST (before Microsoft.Graph.Authentication loads) ----
    Write-Sep
    Write-Step ("Connecting to Azure  (AuthMethod={0})" -f $AuthMethod)
    try {
        Import-Module Az.Accounts  -ErrorAction Stop -WarningAction SilentlyContinue
        Import-Module Az.Resources -ErrorAction Stop -WarningAction SilentlyContinue
        switch ($AuthMethod) {
            'Interactive' {
                Connect-AzAccount -Force -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            }
            'ManagedIdentity' {
                if ($AuthClientId) {
                    Connect-AzAccount -Identity -AccountId $AuthClientId -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                } else {
                    Connect-AzAccount -Identity -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                }
            }
            'SpnSecret' {
                $sec  = ConvertTo-SecureString $AuthClientSecret -AsPlainText -Force
                $cred = [pscredential]::new($AuthClientId, $sec)
                Connect-AzAccount -ServicePrincipal -Tenant $AuthTenantId -Credential $cred -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            }
            'SpnCertificate' {
                Connect-AzAccount -ServicePrincipal -Tenant $AuthTenantId -ApplicationId $AuthClientId -CertificateThumbprint $AuthCertificateThumbprint -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            }
        }
        $azCtx = Get-AzContext
        Write-Ok ("Az connected as '{0}' (tenant {1})" -f $azCtx.Account, $azCtx.Tenant.Id)
    } catch {
        Write-Err2 ("Connect-AzAccount failed: {0}" -f $_.Exception.Message)
        Add-SpnResult -Category 'Azure RBAC' -Item 'Connect-AzAccount' -Status 'FAIL' -Detail $_.Exception.Message
        throw
    }

    # ---- Connect to Microsoft Graph ----
    Write-Sep
    Write-Step ("Connecting to Microsoft Graph  (AuthMethod={0})" -f $AuthMethod)
    $graphScopes = @(
        'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All',
        'Directory.ReadWrite.All','RoleManagement.ReadWrite.Directory'
    )
    try {
        switch ($AuthMethod) {
            'Interactive' {
                Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop | Out-Null
            }
            'ManagedIdentity' {
                if ($AuthClientId) {
                    Connect-MgGraph -Identity -ClientId $AuthClientId -NoWelcome -ErrorAction Stop | Out-Null
                } else {
                    Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop | Out-Null
                }
            }
            'SpnSecret' {
                if (-not $AuthTenantId -or -not $AuthClientId -or -not $AuthClientSecret) {
                    throw "AuthMethod=SpnSecret requires -AuthTenantId, -AuthClientId, and -AuthClientSecret."
                }
                $sec  = ConvertTo-SecureString $AuthClientSecret -AsPlainText -Force
                $cred = [pscredential]::new($AuthClientId, $sec)
                Connect-MgGraph -TenantId $AuthTenantId -ClientSecretCredential $cred -NoWelcome -ErrorAction Stop | Out-Null
            }
            'SpnCertificate' {
                if (-not $AuthTenantId -or -not $AuthClientId -or -not $AuthCertificateThumbprint) {
                    throw "AuthMethod=SpnCertificate requires -AuthTenantId, -AuthClientId, and -AuthCertificateThumbprint."
                }
                Connect-MgGraph -TenantId $AuthTenantId -ClientId $AuthClientId -CertificateThumbprint $AuthCertificateThumbprint -NoWelcome -ErrorAction Stop | Out-Null
            }
        }
        $ctx = Get-MgContext
        Write-Ok ("connected as '{0}' (tenant {1})" -f $ctx.Account, $ctx.TenantId)
    } catch {
        Write-Err2 ("Connect-MgGraph failed: {0}" -f $_.Exception.Message)
        throw
    }

    # ---- Find or create the SPN ----
    Write-Sep
    Write-Step "Resolving SecurityInsight SPN"

    $targetSp = $null
    if ($SpnAppId) {
        Write-Info "looking up by AppId: $SpnAppId"
        $resp = Invoke-MgGraphRequest -Method GET -Uri ("/v1.0/servicePrincipals?`$filter=appId eq '{0}'" -f $SpnAppId) -ErrorAction SilentlyContinue
        $targetSp = $resp.value | Select-Object -First 1
    } else {
        Write-Info "looking up by displayName: $SpnDisplayName"
        $resp = Invoke-MgGraphRequest -Method GET -Uri ("/v1.0/servicePrincipals?`$filter=displayName eq '{0}'" -f $SpnDisplayName) -ErrorAction SilentlyContinue
        $targetSp = $resp.value | Select-Object -First 1
    }

    if ($targetSp) {
        Write-Ok ("found SPN: '{0}' (objectId={1}, appId={2})" -f $targetSp.displayName, $targetSp.id, $targetSp.appId)
        Add-SpnResult -Category 'SPN' -Item $targetSp.displayName -Status 'OK' -Detail $targetSp.appId
    } elseif ($whatIfMode) {
        Write-Skip "SPN '$SpnDisplayName' not found. WhatIf -- would create it."
        Add-SpnResult -Category 'SPN' -Item $SpnDisplayName -Status 'SKIP' -Detail 'WhatIfMode'
    } else {
        Write-Step "SPN not found -- creating app registration + servicePrincipal"
        try {
            $appBody = @{ displayName = $SpnDisplayName; signInAudience = 'AzureADMyOrg' } | ConvertTo-Json
            $newApp  = Invoke-MgGraphRequest -Method POST -Uri '/v1.0/applications' -Body $appBody -ContentType 'application/json' -ErrorAction Stop
            Start-Sleep -Seconds 5
            $spBody  = @{ appId = $newApp.appId } | ConvertTo-Json
            $newSp   = Invoke-MgGraphRequest -Method POST -Uri '/v1.0/servicePrincipals' -Body $spBody -ContentType 'application/json' -ErrorAction Stop
            $targetSp = $newSp
            Write-Add ("created SPN: '{0}' (objectId={1}, appId={2})" -f $targetSp.displayName, $targetSp.id, $targetSp.appId)
            Add-SpnResult -Category 'SPN' -Item $SpnDisplayName -Status 'GRANTED' -Detail $targetSp.appId
        } catch {
            Write-Err2 ("could not create SPN: {0}" -f $_.Exception.Message)
            Add-SpnResult -Category 'SPN' -Item $SpnDisplayName -Status 'FAIL' -Detail $_.Exception.Message
            throw
        }
    }

    if (-not $targetSp -and -not $whatIfMode) { throw "Failed to resolve target SPN. Cannot continue." }

    # ---- API permissions ----
    Write-Sep
    Write-Step "Reconciling API permissions"

    foreach ($apiBlock in $RequiredApiPermissions) {
        Write-Info ("resource: {0}" -f $apiBlock.ResourceDisplayName)
        $resp = Invoke-MgGraphRequest -Method GET -Uri ("/v1.0/servicePrincipals?`$filter=appId eq '{0}'" -f $apiBlock.ResourceAppId) -ErrorAction SilentlyContinue
        $resourceSp = $resp.value | Select-Object -First 1
        if (-not $resourceSp) {
            Write-Err2 ("resource SP for '{0}' (appId={1}) not found in this tenant -- skipping" -f $apiBlock.ResourceDisplayName, $apiBlock.ResourceAppId)
            foreach ($perm in $apiBlock.Permissions) {
                Add-SpnResult -Category 'API Permission' -Item ("{0} / {1}" -f $apiBlock.ResourceDisplayName, $perm) -Status 'FAIL' -Detail 'resource SP not in tenant'
            }
            continue
        }

        $appRoleIdByValue = @{}
        foreach ($ar in $resourceSp.appRoles) {
            if ($ar.value) { $appRoleIdByValue[$ar.value] = $ar.id }
        }

        $currentGrants = @{}
        if ($targetSp) {
            $grantsResp = Invoke-MgGraphRequest -Method GET -Uri ("/v1.0/servicePrincipals/{0}/appRoleAssignments" -f $targetSp.id) -ErrorAction SilentlyContinue
            foreach ($g in $grantsResp.value) {
                if ($g.resourceId -eq $resourceSp.id) { $currentGrants[$g.appRoleId] = $true }
            }
        }

        foreach ($permValue in $apiBlock.Permissions) {
            $permKey = "{0} / {1}" -f $apiBlock.ResourceDisplayName, $permValue
            $appRoleId = $appRoleIdByValue[$permValue]
            if (-not $appRoleId) {
                Write-Err2 ("  {0} -- appRole value not found on resource SP" -f $permValue)
                Add-SpnResult -Category 'API Permission' -Item $permKey -Status 'FAIL' -Detail 'appRole value not defined by resource'
                continue
            }
            if ($currentGrants[$appRoleId]) {
                Write-Ok ("  {0}" -f $permValue)
                Add-SpnResult -Category 'API Permission' -Item $permKey -Status 'OK'
                continue
            }
            if ($whatIfMode) {
                Write-Skip ("  {0} -- would grant" -f $permValue)
                Add-SpnResult -Category 'API Permission' -Item $permKey -Status 'SKIP' -Detail 'WhatIfMode'
                continue
            }
            try {
                $body = @{
                    principalId = $targetSp.id
                    resourceId  = $resourceSp.id
                    appRoleId   = $appRoleId
                } | ConvertTo-Json
                Invoke-MgGraphRequest -Method POST -Uri ("/v1.0/servicePrincipals/{0}/appRoleAssignments" -f $targetSp.id) -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
                Write-Add ("  {0}" -f $permValue)
                Add-SpnResult -Category 'API Permission' -Item $permKey -Status 'GRANTED'
            } catch {
                Write-Err2 ("  {0} -- {1}" -f $permValue, $_.Exception.Message)
                Add-SpnResult -Category 'API Permission' -Item $permKey -Status 'FAIL' -Detail $_.Exception.Message
            }
        }
    }

    # ---- Azure RBAC ----
    Write-Sep
    Write-Step "Reconciling Azure RBAC grants"

    $subs = $AzureSubscriptionIds
    if (-not $subs -or $subs.Count -eq 0) {
        Write-Info "no -AzureSubscriptionIds provided -- enumerating all enabled subs the caller can see"
        $subs = @(Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' } | Select-Object -ExpandProperty Id)
        Write-Info ("found {0} enabled subscription(s)" -f $subs.Count)
    }

    function Grant-Role {
        param(
            [Parameter(Mandatory)][string]$ObjectId,
            [Parameter(Mandatory)][string]$RoleName,
            [Parameter(Mandatory)][string]$Scope,
            [string]$ItemLabel
        )
        if (-not $ItemLabel) { $ItemLabel = "{0} @ {1}" -f $RoleName, $Scope }
        try {
            $existing = Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Ok ("  {0}" -f $ItemLabel)
                Add-SpnResult -Category 'Azure RBAC' -Item $ItemLabel -Status 'OK'
                return
            }
            if ($whatIfMode) {
                Write-Skip ("  {0} -- would assign" -f $ItemLabel)
                Add-SpnResult -Category 'Azure RBAC' -Item $ItemLabel -Status 'SKIP' -Detail 'WhatIfMode'
                return
            }
            New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction Stop | Out-Null
            Write-Add ("  {0}" -f $ItemLabel)
            Add-SpnResult -Category 'Azure RBAC' -Item $ItemLabel -Status 'GRANTED'
        } catch {
            Write-Err2 ("  {0} -- {1}" -f $ItemLabel, $_.Exception.Message)
            Add-SpnResult -Category 'Azure RBAC' -Item $ItemLabel -Status 'FAIL' -Detail $_.Exception.Message
        }
    }

    if (-not $targetSp) {
        Write-Skip "SPN not yet created (WhatIfMode) -- skipping Azure RBAC reconciliation"
    } else {
        Write-Sep
        Write-Step ("Reconciling Azure RBAC for SPN objectId {0}  (scope = {1})" -f $targetSp.id, $AzureRbacScope)

        $tenantRootFailed = $false
        if ($AzureRbacScope -eq 'TenantRoot') {
            $tenantIdForMg = (Get-AzContext).Tenant.Id
            if (-not $tenantIdForMg -and $AuthTenantId) { $tenantIdForMg = $AuthTenantId }
            if (-not $tenantIdForMg) {
                Write-Err2 "Could not resolve tenant id for tenant-root scope -- falling back to per-subscription."
                $tenantRootFailed = $true
            } else {
                $rootScope = "/providers/Microsoft.Management/managementGroups/$tenantIdForMg"
                Write-Info ("tenant root MG scope: {0}" -f $rootScope)
                foreach ($role in $RequiredAzureRoles.AzureRoles) {
                    $label = "{0} @ tenant-root MG" -f $role
                    $before = @($results | Where-Object { $_.Item -eq $label -and $_.Status -eq 'FAIL' }).Count
                    Grant-Role -ObjectId $targetSp.id -RoleName $role -Scope $rootScope -ItemLabel $label
                    $after  = @($results | Where-Object { $_.Item -eq $label -and $_.Status -eq 'FAIL' }).Count
                    if ($after -gt $before) { $tenantRootFailed = $true }
                }
                if ($tenantRootFailed) {
                    Write-Err2 "Tenant-root grant failed -- common cause: caller lacks Owner / UAA at tenant root."
                    Write-Info "Fix: Entra admin center -> Properties -> 'Access management for Azure resources' toggle ON."
                    Write-Info "Falling back to per-subscription grants so the run still succeeds."
                }
            }
        }

        if ($AzureRbacScope -eq 'PerSubscription' -or $tenantRootFailed) {
            foreach ($subId in $subs) {
                $subScope = "/subscriptions/$subId"
                foreach ($role in $RequiredAzureRoles.AzureRoles) {
                    Grant-Role -ObjectId $targetSp.id -RoleName $role -Scope $subScope -ItemLabel ("{0} @ /subscriptions/{1}" -f $role, $subId)
                }
            }
        }

        if ($DefenderWorkspaceResourceId) {
            foreach ($role in $RequiredAzureRoles.DefenderWorkspaceRoles) {
                Grant-Role -ObjectId $targetSp.id -RoleName $role -Scope $DefenderWorkspaceResourceId -ItemLabel ("{0} @ DefenderWorkspace" -f $role)
            }
        } else {
            Write-Skip "no -DefenderWorkspaceResourceId provided -- skipping Log Analytics Reader grant on Defender workspace"
            Add-SpnResult -Category 'Azure RBAC' -Item 'Log Analytics Reader @ Defender workspace' -Status 'SKIP' -Detail 'DefenderWorkspaceResourceId not provided'
        }

        if ($DcrResourceId) {
            foreach ($role in $RequiredAzureRoles.DcrRoles) {
                Grant-Role -ObjectId $targetSp.id -RoleName $role -Scope $DcrResourceId -ItemLabel ("{0} @ DCR" -f $role)
            }
        } else {
            Write-Skip "no -DcrResourceId provided -- skipping Monitoring Metrics Publisher grant on DCR"
            Add-SpnResult -Category 'Azure RBAC' -Item 'Monitoring Metrics Publisher @ DCR' -Status 'SKIP' -Detail 'DcrResourceId not provided'
        }
    }

    # ---- Summary ----
    Write-Sep
    Write-Step "Summary"
    $grouped = $results | Group-Object Status
    foreach ($g in ($grouped | Sort-Object Name)) {
        $color = switch ($g.Name) {
            'OK'      { 'Green' }
            'GRANTED' { 'Yellow' }
            'SKIP'    { 'DarkYellow' }
            'FAIL'    { 'Red' }
            default   { 'Gray' }
        }
        Write-Host ("  {0,-9} {1}" -f $g.Name, $g.Count) -ForegroundColor $color
    }
    Write-Sep
    $results | Format-Table -AutoSize -Property Category, Item, Status, Detail | Out-Host
    Write-Sep

    $failCount = ($results | Where-Object Status -eq 'FAIL').Count
    if ($failCount -gt 0) {
        Write-Err2 "$failCount item(s) failed -- review above and re-run after fixing."
        return 'failed'
    }
    if ($whatIfMode) { return 'whatif' }
    Write-Ok "All required permissions and RBAC roles are in place."
    return 'ok'
}

# ============================================================================
# Phase LA -- inlined from Validate-SILogAnalytics.ps1
# ============================================================================
function Invoke-Phase-LA {
    Write-Phase 'LA' 'Workspace + DCE + DCRs + tables'

    $ensureScript = Join-Path $script:_setupRoot '_shared\Ensure-Module.ps1'
    if (Test-Path $ensureScript) { . $ensureScript; Ensure-SecurityInsightModules }

    if ($null -eq $global:AutomationFramework) { $global:AutomationFramework = $false }

    if (-not [bool]$global:AutomationFramework) {
        if ([string]::IsNullOrWhiteSpace([string]$global:SpnTenantId) -or
            [string]::IsNullOrWhiteSpace([string]$global:SpnClientId) -or
            [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)) {
            throw "Phase LA requires SPN globals (SpnTenantId/SpnClientId/SpnClientSecret) to be set, or `$global:AutomationFramework = `$true."
        }
    }

    if ([bool]$global:AutomationFramework) {
        $repoRoot = $script:_setupRoot
        while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'))) {
            $repoRoot = Split-Path -Parent $repoRoot
        }
        if (-not $repoRoot) {
            throw "AutomationFramework bootstrap: cannot find FUNCTIONS\AutomateITPS\AutomateITPS.psd1."
        }
        $global:PathScripts = $repoRoot
        Import-Module (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Global -Force -WarningAction SilentlyContinue
        $null = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets
        $global:SpnTenantId     = $global:AzureTenantId
        $global:SpnClientId     = $global:HighPriv_Modern_ApplicationID_Azure
        $global:SpnClientSecret = $global:HighPriv_Modern_Secret_Azure
    } else {
        if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
            $secretSecure = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
            $credential   = New-Object System.Management.Automation.PSCredential ($global:SpnClientId, $secretSecure)
            Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $credential -WarningAction SilentlyContinue | Out-Null
        }
    }

    $TenantId       = if ($global:AutomationFramework) { $Global:TenantID } else { $global:SpnTenantId }
    $SubIdLA        = if ($global:SubscriptionId) { $global:SubscriptionId } elseif ($global:MainLogAnalyticsWorkspaceSubId) { $global:MainLogAnalyticsWorkspaceSubId } else { (Get-AzContext).Subscription.Id }
    $ResourceGroupLA= if ($global:WorkspaceResourceGroup) { $global:WorkspaceResourceGroup } elseif ($global:ResourceGroup) { $global:ResourceGroup } else { 'rg-securityinsight' }
    $DceRgLA        = if ($global:DceResourceGroup) { $global:DceResourceGroup } else { 'rg-dce-securityinsight' }
    $DcrRgLA        = if ($global:DcrResourceGroup) { $global:DcrResourceGroup } else { 'rg-dcr-securityinsight' }
    $LocationLA     = if ($global:Location) { $global:Location } else { 'westeurope' }
    $WorkspaceNameLA= if ($global:WorkspaceName) { $global:WorkspaceName } else { 'log-platform-management-securityinsight' }
    $DceNameLA      = if ($global:DceName) { $global:DceName } else { 'dce-securityinsight' }
    $DcrNameLA      = if ($global:DcrName) { $global:DcrName } else { 'dcr-si-identity-assets' }
    $TableNameLA    = if ($global:TableName) { $global:TableName } else { 'SI_IdentityAssets' }
    $WorkspaceRetentionDays = if ($global:WorkspaceRetentionDays) { $global:WorkspaceRetentionDays } else { 90 }
    $IngestionSpnClientId   = if ($global:AutomationFramework) { $global:HighPriv_Modern_ApplicationID_Azure } else { $global:SpnClientId }

    function Invoke-LAWithRetry {
        param([Parameter(Mandatory)][scriptblock]$ScriptBlock,
              [int]$MaxAttempts = 5, [int]$InitialDelaySec = 3, [string]$OperationName = 'operation')
        $attempt = 0; $delay = $InitialDelaySec
        while ($true) {
            $attempt++
            try { return & $ScriptBlock }
            catch {
                if ($attempt -ge $MaxAttempts) {
                    Write-Err2 "$OperationName failed after $attempt attempts: $($_.Exception.Message)"; throw
                }
                Write-Warn2 "$OperationName attempt $attempt failed: $($_.Exception.Message) - retrying in ${delay}s"
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay * 2, 30)
            }
        }
    }

    function Ensure-LARoleAssignment {
        param([Parameter(Mandatory)][string]$ObjectId,
              [Parameter(Mandatory)][string]$RoleDefinitionName,
              [Parameter(Mandatory)][string]$Scope)
        $existing = Get-AzRoleAssignment -ObjectId $ObjectId -Scope $Scope -ErrorAction SilentlyContinue |
            Where-Object { $_.RoleDefinitionName -eq $RoleDefinitionName -and $_.Scope -eq $Scope }
        if ($existing) {
            Write-Info "Role '$RoleDefinitionName' already assigned at $Scope"; return $false
        }
        if ($WhatIfPreference) {
            Write-Skip "(WhatIf) would assign '$RoleDefinitionName' at $Scope"; return $false
        }
        Invoke-LAWithRetry -OperationName "Assign $RoleDefinitionName" -ScriptBlock {
            New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleDefinitionName -Scope $Scope -ErrorAction Stop | Out-Null
        }
        Write-Ok "Assigned '$RoleDefinitionName' at $Scope"
        return $true
    }

    Import-Module AzLogDcrIngestPS -Global -Force -DisableNameChecking -WarningAction SilentlyContinue

    Write-Sep; Write-Step 'Validating input variables'
    if ([string]::IsNullOrWhiteSpace($IngestionSpnClientId)) { throw "IngestionSpnClientId is empty" }
    if ([string]::IsNullOrWhiteSpace($TenantId))             { throw "TenantId is empty" }
    if ([string]::IsNullOrWhiteSpace($SubIdLA))              { throw "SubscriptionId is empty" }
    Write-Ok 'Variables validated'

    Write-Sep; Write-Step 'Setting Azure context'
    try {
        $currentCtx = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $currentCtx -or $currentCtx.Subscription.Id -ne $SubIdLA -or $currentCtx.Tenant.Id -ne $TenantId) {
            Set-AzContext -SubscriptionId $SubIdLA -TenantId $TenantId -ErrorAction Stop | Out-Null
        }
        $ctx = Get-AzContext -ErrorAction Stop
        if (-not $ctx) { throw 'No Azure context - run Connect-AzAccount first' }
        Write-Ok "Context: $($ctx.Account.Id) | Sub: $($ctx.Subscription.Name)"
    } catch { throw "Failed to set Azure context: $($_.Exception.Message)" }

    Write-Sep; Write-Step 'Resolving ingestion service principal'
    $spn = Invoke-LAWithRetry -OperationName 'Get SecurityInsight SPN' -ScriptBlock {
        Get-AzADServicePrincipal -ApplicationId $IngestionSpnClientId -ErrorAction Stop
    }
    if (-not $spn) { throw "Service principal with AppId '$IngestionSpnClientId' not found in tenant $TenantId" }
    $spnObjectId = $spn.Id
    Write-Ok "SPN ObjectId: $spnObjectId ($($spn.DisplayName))"

    Write-Sep; Write-Step 'Ensuring resource groups (workspace / DCE / DCR)'

    function Ensure-LARg {
        param([string]$Name, [string]$DesiredLocation)
        $rg = Get-AzResourceGroup -Name $Name -ErrorAction SilentlyContinue
        if (-not $rg) {
            if ($WhatIfPreference) {
                Write-Skip "(WhatIf) would create RG '$Name' in $DesiredLocation"; return $DesiredLocation
            }
            Invoke-LAWithRetry -OperationName "Create RG $Name" -ScriptBlock {
                New-AzResourceGroup -Name $Name -Location $DesiredLocation -ErrorAction Stop | Out-Null
            }
            Write-Ok "Created resource group: $Name ($DesiredLocation)"
            return $DesiredLocation
        } else {
            if ($rg.Location -ne $DesiredLocation) {
                Write-Warn2 "RG '$Name' exists in '$($rg.Location)' but requested '$DesiredLocation' - using existing location"
                return $rg.Location
            }
            Write-Info "RG exists: $Name ($($rg.Location))"
            return $rg.Location
        }
    }

    $LocationLA = Ensure-LARg -Name $ResourceGroupLA -DesiredLocation $LocationLA
    $null       = Ensure-LARg -Name $DceRgLA        -DesiredLocation $LocationLA
    $null       = Ensure-LARg -Name $DcrRgLA        -DesiredLocation $LocationLA

    Write-Sep; Write-Step "Ensuring Log Analytics workspace: $WorkspaceNameLA"
    $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupLA -Name $WorkspaceNameLA -ErrorAction SilentlyContinue
    if (-not $workspace) {
        if ($WhatIfPreference) {
            Write-Skip "(WhatIf) would create workspace $WorkspaceNameLA"
            return 'whatif'
        }
        Invoke-LAWithRetry -OperationName 'Create workspace' -ScriptBlock {
            New-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupLA -Name $WorkspaceNameLA -Location $LocationLA -Sku 'PerGB2018' -RetentionInDays $WorkspaceRetentionDays -ErrorAction Stop | Out-Null
        }
        $workspace = Invoke-LAWithRetry -OperationName 'Get workspace' -ScriptBlock {
            $w = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupLA -Name $WorkspaceNameLA -ErrorAction Stop
            if (-not $w -or -not $w.CustomerId -or -not $w.ResourceId) { throw 'Workspace not fully provisioned yet' }
            $w
        }
        Write-Ok "Created workspace: $WorkspaceNameLA"
    } else {
        Write-Info "Workspace exists: $WorkspaceNameLA"
    }

    $WorkspaceResourceId = $workspace.ResourceId
    $WorkspaceCustomerId = $workspace.CustomerId
    $WorkspaceLocation   = $workspace.Location
    if (-not $WorkspaceResourceId) { throw 'Could not resolve workspace ResourceId' }
    Write-Ok "ResourceId : $WorkspaceResourceId"
    Write-Ok "CustomerId : $WorkspaceCustomerId"
    Write-Ok "Location   : $WorkspaceLocation"

    Write-Sep; Write-Step "Building DCE/DCR global cache (filtered to sub: $SubIdLA)"
    $global:AzDceDetails = Invoke-LAWithRetry -OperationName 'List DCEs' -ScriptBlock { Get-AzDceListAll -TenantId $TenantId -Verbose:$false }
    $global:AzDcrDetails = Invoke-LAWithRetry -OperationName 'List DCRs' -ScriptBlock { Get-AzDcrListAll -TenantId $TenantId -Verbose:$false }
    $__filterToSub = {
        param($item, [string]$sub)
        $s = [string]$item.subscriptionId
        if ([string]::IsNullOrWhiteSpace($s) -and $item.id -match '/subscriptions/([^/]+)/') { $s = $Matches[1] }
        return ($s -eq $sub)
    }
    if ($global:AzDceDetails) { $global:AzDceDetails = @($global:AzDceDetails | Where-Object { & $__filterToSub $_ $SubIdLA }) }
    if ($global:AzDcrDetails) { $global:AzDcrDetails = @($global:AzDcrDetails | Where-Object { & $__filterToSub $_ $SubIdLA }) }
    Write-Ok "DCE cache: $(($global:AzDceDetails | Measure-Object).Count) | DCR cache: $(($global:AzDcrDetails | Measure-Object).Count)"

    Write-Sep; Write-Step "Ensuring Data Collection Endpoint: $DceNameLA (rg=$DceRgLA)"
    $dce = Get-AzDataCollectionEndpoint -ResourceGroupName $DceRgLA -Name $DceNameLA -ErrorAction SilentlyContinue
    if (-not $dce) {
        if ($WhatIfPreference) {
            Write-Skip "(WhatIf) would create DCE $DceNameLA"; return 'whatif'
        }
        $dce = Invoke-LAWithRetry -OperationName 'Create DCE' -ScriptBlock {
            New-AzDataCollectionEndpoint -ResourceGroupName $DceRgLA -Name $DceNameLA -Location $LocationLA -NetworkAclsPublicNetworkAccess 'Enabled' -ErrorAction Stop
        }
        Write-Ok "Created DCE: $DceNameLA"
    } else {
        Write-Info "DCE exists: $DceNameLA"
    }
    if (-not $dce.LogIngestionEndpoint) {
        throw "DCE exists but has no LogIngestionEndpoint - check provisioning state: $($dce.ProvisioningState)"
    }
    $DceResourceId   = $dce.Id
    $DceIngestionUri = $dce.LogIngestionEndpoint
    Write-Ok "DCE ResourceId    : $DceResourceId"
    Write-Ok "DCE Ingestion URI : $DceIngestionUri"

    Write-Sep; Write-Step 'Building sample data + sanitising schema'
    $sampleObject = [PSCustomObject]@{
        ObjectId='00000000-0000-0000-0000-000000000000'; ObjectType='User'
        DisplayName='Sample Identity'; UPN='sample@domain.com'
        AppId=''; SPType=''; AccountEnabled=$true
        IsExternal=$false; ExternalDomain=''; IsB2BCollaborator=$false
        OnPremSynced=$false; OnPremSamAccountName=''; OnPremDistinguishedName=''
        Department=''; JobTitle=''; Manager=''
        ExtensionAttribute1=''; ExtensionAttribute2=''; ExtensionAttribute3=''
        ExtensionAttribute4=''; ExtensionAttribute5=''; ExtensionAttribute6=''
        ExtensionAttribute7=''; ExtensionAttribute8=''; ExtensionAttribute9=''
        ExtensionAttribute10=''; ExtensionAttribute11=''; ExtensionAttribute12=''
        ExtensionAttribute13=''; ExtensionAttribute14=''; ExtensionAttribute15=''
        CreatedDateTime=[datetime]::UtcNow.ToString('o'); CreatedDays=0
        LastSignInDateTime=''; LastSignInDays=-1; LastNonInteractiveSignInDays=-1
        IsStale=$false; PasswordLastChangedDays=-1; IsPasswordNeverExpires=$false
        MFARegistered=$false; MFAMethodCount=0; MFAMethods=''; IsPasswordlessOnly=$false
        AssignedEntraRoles=''; EligibleEntraRoles=''
        IsPrivileged=$false; IsPrivilegedEligible=$false
        HasPermanentPrivilegedRole=$false; RequiresPIMReview=$false
        IsSensitive=$false; IsHighValueTarget=$false; IsBreakGlass=$false
        IsShadowAdmin=$false; IsOrphan=$false
        ApplicationPermissions=''; DelegatedPermissions=''; HighestRiskPermission=''
        HasWritePermissions=$false; HasDirectoryWriteAccess=$false
        HasRoleWriteAccess=$false; HasMailboxAccess=$false
        TargetAPICount=0; DerivedTierFromPermissions=-1
        HasClientSecret=$false; HasCertificate=$false; HasExpiredCredential=$false
        CredentialExpiryDays=-1; HasNoOwner=$false; OwnersCount=0; Owners=''
        IsManagedIdentity=$false; IsManagedIdentityUserAssigned=$false; ManagedIdentityResourceId=''
        IsMultiTenant=$false; PublisherVerified=$false; IsExternal_SPN=$false
        AssetTags=''; AssetTier=''; AssetTagType=''; EffectiveTier=-1
        CollectionTime=[datetime]::UtcNow.ToString('o')
    }
    $dataArray = @($sampleObject)
    $dataArray = Add-CollectionTimeToAllEntriesInArray            -Data $dataArray -Verbose:$false
    $dataArray = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $dataArray -Verbose:$false
    $dataArray = Build-DataArrayToAlignWithSchema                 -Data $dataArray -Verbose:$false
    $colCount = ($dataArray[0].PSObject.Properties | Measure-Object).Count
    Write-Ok "Schema prepared: $colCount columns"

    Write-Sep; Write-Step 'Creating/updating table + DCR'
    if ($WhatIfPreference) {
        Write-Skip "(WhatIf) would create/update table+DCR ${TableNameLA}_CL"
    } else {
        try {
            CheckCreateUpdate-TableDcr-Structure `
                -AzLogWorkspaceResourceId                   $WorkspaceResourceId `
                -TenantId                                   $TenantId `
                -DceName                                    $DceNameLA `
                -DcrName                                    $DcrNameLA `
                -DcrResourceGroup                           $DcrRgLA `
                -TableName                                  $TableNameLA `
                -Data                                       $dataArray `
                -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
                -AzLogDcrTableCreateFromAnyMachine          $true `
                -AzLogDcrTableCreateFromReferenceMachine    @() `
                -Verbose:$false | Out-Null
            Write-Ok "Table + DCR provisioned: ${TableNameLA}_CL (rg=$DcrRgLA)"
        } catch {
            Write-Err2 "Table/DCR provisioning failed: $($_.Exception.Message)"
            throw
        }
    }

    Write-Sep; Write-Step 'Assigning RBAC roles to SecurityInsight SPN'
    $rgWorkspaceScope = "/subscriptions/$SubIdLA/resourceGroups/$ResourceGroupLA"
    $rgDceScope       = "/subscriptions/$SubIdLA/resourceGroups/$DceRgLA"
    $rgDcrScope       = "/subscriptions/$SubIdLA/resourceGroups/$DcrRgLA"

    $roleChanges = @(
        (Ensure-LARoleAssignment -ObjectId $spnObjectId -RoleDefinitionName 'Contributor'                  -Scope $WorkspaceResourceId)
        (Ensure-LARoleAssignment -ObjectId $spnObjectId -RoleDefinitionName 'Monitoring Metrics Publisher' -Scope $rgDceScope)
        (Ensure-LARoleAssignment -ObjectId $spnObjectId -RoleDefinitionName 'Contributor'                  -Scope $rgDceScope)
        (Ensure-LARoleAssignment -ObjectId $spnObjectId -RoleDefinitionName 'Monitoring Metrics Publisher' -Scope $rgDcrScope)
        (Ensure-LARoleAssignment -ObjectId $spnObjectId -RoleDefinitionName 'Contributor'                  -Scope $rgDcrScope)
    )
    if ($ResourceGroupLA -ne $DceRgLA -and $ResourceGroupLA -ne $DcrRgLA) {
        $roleChanges += (Ensure-LARoleAssignment -ObjectId $spnObjectId -RoleDefinitionName 'Contributor' -Scope $rgWorkspaceScope)
    }
    if ($roleChanges -contains $true) {
        Write-Ok 'New role assignments made - waiting 60s for propagation...'
        Start-Sleep -Seconds 60
    }

    Write-Sep; Write-Sep
    Write-Host ''
    Write-Host '  [ADMIN] Paste the block below into LauncherConfig.custom.ps1 of the IdentityAssetsCollect launcher:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host  ("    `$global:BatchSize           = 300")                                              -ForegroundColor White
    Write-Host  ("    `$global:TableName           = `"{0}`""   -f $TableNameLA)                        -ForegroundColor White
    Write-Host  ("    `$global:WorkspaceResourceId = `"{0}`""   -f $WorkspaceResourceId.ToLower())      -ForegroundColor White
    Write-Host  ("    `$global:DcrResourceGroup    = `"{0}`""   -f $DcrRgLA.ToLower())                  -ForegroundColor White
    Write-Host  ("    `$global:DcrName             = `"{0}`""   -f $DcrNameLA.ToLower())                -ForegroundColor White
    Write-Host  ("    `$global:DceResourceGroup    = `"{0}`""   -f $DceRgLA.ToLower())                  -ForegroundColor White
    Write-Host  ("    `$global:DceName             = `"{0}`""   -f $DceNameLA.ToLower())                -ForegroundColor White
    Write-Host ''

    if ($WhatIfPreference) { return 'whatif' }
    return 'ok'
}

# ============================================================================
# Phase OpenAI -- inlined from Validate-SIOpenAI_OnboardValidate-SecurityInsight-OpenAI...
# ============================================================================
function Invoke-Phase-OpenAI {
    Write-Phase 'OpenAI' 'Azure OpenAI PAYG instance + model deploy'

    $ensureScript = Join-Path $script:_setupRoot '_shared\Ensure-Module.ps1'
    if (Test-Path $ensureScript) { . $ensureScript; Ensure-SecurityInsightModules }

    $ApiVersion = '2024-10-01'
    $InferenceApiVersion = '2025-01-01-preview'

    # Resolve customer-specific values: prefer Setup -OpenAI* params, then $global:*, then defaults.
    $subIdAI       = if ($SubscriptionId)        { $SubscriptionId }        elseif ($global:SubscriptionId)    { $global:SubscriptionId }    else { (Get-AzContext -ErrorAction SilentlyContinue).Subscription.Id }
    $rgAI          = if ($ResourceGroup)         { $ResourceGroup }         elseif ($global:ResourceGroupName) { $global:ResourceGroupName } elseif ($global:ResourceGroup) { $global:ResourceGroup } else { '' }
    $locationAI    = if ($Region)                { $Region }                elseif ($global:Location)          { $global:Location }          else { '' }
    $accountName   = if ($OpenAIAccountName)     { $OpenAIAccountName }     elseif ($global:AccountName)       { $global:AccountName }       else { '' }
    $deploymentName= if ($OpenAIDeploymentName)  { $OpenAIDeploymentName }  elseif ($global:DeploymentName)    { $global:DeploymentName }    else { '' }
    $modelName     = if ($OpenAIModelName)       { $OpenAIModelName }       elseif ($global:ModelName)         { $global:ModelName }         else { 'gpt-4.1-mini' }
    $modelVersion  = if ($OpenAIModelVersion)    { $OpenAIModelVersion }    elseif ($global:ModelVersion)      { $global:ModelVersion }      else { 'latest' }
    $capacity      = if ($PSBoundParameters.ContainsKey('OpenAICapacity') -and $OpenAICapacity -gt 0) { $OpenAICapacity } elseif ($global:Capacity) { [int]$global:Capacity } else { 100 }
    $publicNetwork = $OpenAIPublicNetworkAccess
    $skuOrder      = $OpenAIDeploymentSkuOrder
    $validateOnly  = [bool]$OpenAIValidateOnly

    foreach ($req in @{ SubscriptionId=$subIdAI; ResourceGroup=$rgAI; Location=$locationAI; AccountName=$accountName; DeploymentName=$deploymentName }.GetEnumerator()) {
        if ([string]::IsNullOrWhiteSpace([string]$req.Value)) {
            throw "Phase OpenAI: $($req.Key) must be supplied (Setup -param, `$global:* var, or via Az context)."
        }
    }
    if ($capacity -lt 1) { throw 'Capacity must be >= 1.' }
    if ($accountName -notmatch '^[a-z0-9-]{2,63}$') {
        throw "AccountName '$accountName' is invalid. Use 2-63 chars: lowercase letters, numbers, hyphen."
    }

    function _AI-Log([string]$Level, [string]$Message) {
        $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        switch ($Level) {
            'INFO'  { Write-Host "[$ts] [INFO ] $Message" }
            'WARN'  { Write-Host "[$ts] [WARN ] $Message" -ForegroundColor Yellow }
            'ERROR' { Write-Host "[$ts] [ERROR] $Message" -ForegroundColor Red }
            'DEBUG' { Write-Host "[$ts] [DEBUG] $Message" -ForegroundColor White }
        }
    }
    function _AI-Section([string]$Title) {
        Write-Host ''; Write-Host $Title; Write-Host ('-' * $Title.Length)
    }

    function Invoke-AIGet { param([string]$ResourceId, [string]$ApiVersion)
        $path = "${ResourceId}?api-version=${ApiVersion}"
        _AI-Log DEBUG "GET  $path"
        $res = Invoke-AzRestMethod -Method GET -Path $path -ErrorAction SilentlyContinue
        if ($res.StatusCode -eq 404) { return $null }
        if ($res.Content) { return ($res.Content | ConvertFrom-Json) }
    }
    function Invoke-AIPut { param([string]$ResourceId, [string]$ApiVersion, $Body)
        $json = $Body | ConvertTo-Json -Depth 80 -Compress
        $path = "${ResourceId}?api-version=${ApiVersion}"
        _AI-Log DEBUG "PUT  $path"
        $res = Invoke-AzRestMethod -Method PUT -Path $path -Payload $json
        if ($res.StatusCode -notin 200,201) { throw "PUT failed ($($res.StatusCode)): $($res.Content)" }
        if ($res.Content) { return ($res.Content | ConvertFrom-Json) }
    }
    function Invoke-AIPost { param([string]$Path, [string]$Payload)
        $res = Invoke-AzRestMethod -Method POST -Path $Path -Payload $Payload
        return $res
    }
    function Wait-AIProvisioning {
        param([string]$ResourceId, [string]$ApiVersion, [string]$DesiredState,
              [int]$IntervalSeconds = 5, [int]$TimeoutSeconds = 300)
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ($true) {
            $obj = Invoke-AIGet -ResourceId $ResourceId -ApiVersion $ApiVersion
            $state = $null
            if ($obj -and $obj.properties -and $obj.properties.provisioningState) { $state = [string]$obj.properties.provisioningState }
            _AI-Log INFO "ProvisioningState: $state (waiting for '$DesiredState')"
            if ($state -eq $DesiredState) { return $obj }
            if ((Get-Date) -ge $deadline) { throw "Timeout waiting for provisioningState='$DesiredState' (last state: '$state')." }
            Start-Sleep -Seconds $IntervalSeconds
        }
    }
    function Get-AIAccountKeys { param([string]$AccountId, [string]$ApiVersion)
        $path = "${AccountId}/listKeys?api-version=${ApiVersion}"
        $res = Invoke-AIPost -Path $path -Payload '{}'
        if ($res.StatusCode -notin 200,201) { throw "listKeys failed ($($res.StatusCode)): $($res.Content)" }
        return ($res.Content | ConvertFrom-Json)
    }
    function Try-AIParseError { param([string]$ExceptionMessage)
        if ($ExceptionMessage -match '"message"\s*:\s*"([^"]+)"') { return $matches[1] }
        return $ExceptionMessage
    }

    _AI-Section '1) Parameter Resolution'
    _AI-Log INFO "SubscriptionId   : $subIdAI"
    _AI-Log INFO "ResourceGroup    : $rgAI"
    _AI-Log INFO "Location         : $locationAI"
    _AI-Log INFO "AccountName      : $accountName"
    _AI-Log INFO "DeploymentName   : $deploymentName"
    _AI-Log INFO "Model            : $modelName ($modelVersion)"
    _AI-Log INFO "Capacity         : $capacity"
    _AI-Log INFO "SKU order        : $($skuOrder -join ', ')"
    _AI-Log INFO "ValidateOnly     : $validateOnly"

    _AI-Section '2) Azure Auth + Subscription'
    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        _AI-Log INFO 'No Azure context detected. Running Connect-AzAccount...'
        Connect-AzAccount | Out-Null
    }
    Select-AzSubscription -SubscriptionId $subIdAI | Out-Null

    _AI-Section '3) Resource Group'
    $statusRg = 'UNKNOWN'
    $rg = Get-AzResourceGroup -Name $rgAI -ErrorAction SilentlyContinue
    if (-not $rg) {
        if ($validateOnly) { _AI-Log WARN "[ValidateOnly] RG '$rgAI' NOT FOUND."; $statusRg = 'MISSING' }
        elseif ($WhatIfPreference) { _AI-Log WARN "(WhatIf) would create RG '$rgAI' in $locationAI"; $statusRg = 'WHATIF' }
        else {
            _AI-Log INFO "RG '$rgAI' not found. Creating in '$locationAI'..."
            New-AzResourceGroup -Name $rgAI -Location $locationAI | Out-Null
            $statusRg = 'CREATED'
        }
    } else {
        _AI-Log INFO "RG '$rgAI' already exists (location: $($rg.Location))."
        $statusRg = 'REUSED'
    }

    $accountId    = "/subscriptions/$subIdAI/resourceGroups/$rgAI/providers/Microsoft.CognitiveServices/accounts/$accountName"
    $deploymentId = "${accountId}/deployments/${deploymentName}"

    _AI-Section '4) Azure OpenAI Account (PAYG)'
    _AI-Log INFO "Account ResourceId: $accountId"
    $statusAccount = 'UNKNOWN'
    $account = Invoke-AIGet -ResourceId $accountId -ApiVersion $ApiVersion
    if (-not $account) {
        if ($validateOnly) { _AI-Log WARN "[ValidateOnly] account '$accountName' NOT FOUND."; $statusAccount = 'MISSING' }
        elseif ($WhatIfPreference) { _AI-Log WARN "(WhatIf) would create account '$accountName'"; $statusAccount = 'WHATIF' }
        else {
            _AI-Log INFO 'Account does not exist -> creating...'
            Invoke-AIPut -ResourceId $accountId -ApiVersion $ApiVersion -Body @{
                location = $locationAI
                kind     = 'OpenAI'
                sku      = @{ name = 'S0' }
                properties = @{
                    customSubDomainName = $accountName
                    publicNetworkAccess = $publicNetwork
                    networkAcls = @{ defaultAction='Allow'; ipRules=@(); virtualNetworkRules=@() }
                }
                tags = @{}
            } | Out-Null
            $statusAccount = 'CREATED'
        }
    } else {
        _AI-Log INFO 'Account already exists -> skipping create.'
        $statusAccount = 'REUSED'
    }

    if (-not $WhatIfPreference -and -not $validateOnly -or $account) {
        _AI-Section '4b) Wait for Account Ready'
        try {
            $account = Wait-AIProvisioning -ResourceId $accountId -ApiVersion $ApiVersion -DesiredState 'Succeeded'
        } catch {
            _AI-Log WARN "Wait-ForProvisioning failed: $($_.Exception.Message)"
        }
    }

    _AI-Section '5) Model Discovery'
    $candidatesAll = @()
    if ($account) {
        $rid = "${accountId}/models"
        $result = Invoke-AIGet -ResourceId $rid -ApiVersion $ApiVersion
        $models = @()
        if ($result -and $result.value) { $models = @($result.value) }
        _AI-Log INFO ("Account models returned: " + $models.Count)
        foreach ($m in $models) {
            $name = $m.PSObject.Properties['name'].Value
            $ver  = $m.PSObject.Properties['version'].Value
            $fmt  = $m.PSObject.Properties['format'].Value
            if ($name) {
                $candidatesAll += [pscustomobject]@{
                    Name=[string]$name; Version=if ($ver){[string]$ver}else{$null}
                    Format=if ($fmt){[string]$fmt}else{$null}
                }
            }
        }
    }

    _AI-Section '6) Model Selection + Deployment'

    $userForcedModel = $PSBoundParameters.ContainsKey('OpenAIModelName') -or $PSBoundParameters.ContainsKey('OpenAIModelVersion')
    if ($userForcedModel) {
        $ordered = @([pscustomobject]@{ Name=$modelName; Version=$modelVersion; Format='OpenAI' })
    } else {
        $preference = @('gpt-4.1-mini','gpt-4.1','gpt-4','gpt-35-turbo')
        $c = $candidatesAll
        $openAiFmt = $candidatesAll | Where-Object { $_.Format -and $_.Format -ieq 'OpenAI' }
        if ($openAiFmt -and $openAiFmt.Count -gt 0) { $c = $openAiFmt }
        $ordered = @()
        foreach ($p in $preference) {
            $hit = $c | Where-Object { $_.Name -ieq $p } | Select-Object -First 1
            if ($hit) { $ordered += $hit }
        }
        $restGpt = $c | Where-Object { $_.Name -match '^gpt' } | Where-Object { $ordered.Name -notcontains $_.Name }
        $ordered += $restGpt
        $restOther = $c | Where-Object { $ordered.Name -notcontains $_.Name }
        $ordered += $restOther
    }

    $statusDeployment = 'UNKNOWN'
    $deployExists = if ($account) { Invoke-AIGet -ResourceId $deploymentId -ApiVersion $ApiVersion } else { $null }
    if ($deployExists) {
        _AI-Log INFO 'Deployment already exists -> skipping create.'
        $statusDeployment = 'REUSED'
        try {
            $existingModel = $deployExists.properties.model
            if ($existingModel) {
                $modelName    = [string]$existingModel.name
                $modelVersion = [string]$existingModel.version
            }
        } catch {}
    } elseif ($validateOnly) {
        _AI-Log WARN "[ValidateOnly] Deployment '$deploymentName' NOT FOUND."
        $statusDeployment = 'MISSING'
    } elseif ($WhatIfPreference) {
        _AI-Log WARN "(WhatIf) would create deployment '$deploymentName'"
        $statusDeployment = 'WHATIF'
    } else {
        _AI-Log INFO 'Deployment does not exist -> creating with SKU/model fallback...'
        $deployed = $false
        :outer foreach ($skuName in $skuOrder) {
            foreach ($cand in $ordered) {
                $mn = $cand.Name
                $mv = $cand.Version
                if ([string]::IsNullOrWhiteSpace($mv)) { $mv = 'latest' }
                _AI-Log INFO "Attempting: sku=$skuName, model=$mn ($mv), capacity=$capacity"
                try {
                    Invoke-AIPut -ResourceId $deploymentId -ApiVersion $ApiVersion -Body @{
                        properties = @{
                            model = @{ format='OpenAI'; name=$mn; version=$mv }
                        }
                        sku = @{ name=$skuName; capacity=$capacity }
                    } | Out-Null
                    $modelName    = $mn
                    $modelVersion = $mv
                    $statusDeployment = 'CREATED'
                    _AI-Log INFO "Deployment succeeded! sku=$skuName, model=$mn ($mv)"
                    $deployed = $true
                    break outer
                } catch {
                    $azMsg = Try-AIParseError -ExceptionMessage $_.Exception.Message
                    if ($azMsg -match "SKU '.*'.*not supported" -or $azMsg -match 'not supported in this region' -or
                        $azMsg -match 'DeploymentModelNotSupported' -or $azMsg -match 'InvalidResourceProperties') {
                        _AI-Log WARN "Rejected (will try next): sku=$skuName, model=$mn ($mv) -- $azMsg"
                        continue
                    }
                    _AI-Log ERROR "Deployment failed (non-retryable): sku=$skuName, model=$mn ($mv) -- $azMsg"
                    throw
                }
            }
        }
        if (-not $deployed) { throw "No candidate model could be deployed with SKU order ($($skuOrder -join ', ')) in region '$locationAI'." }
    }

    _AI-Section '7) Output (Endpoint + Keys)'
    $account = Invoke-AIGet -ResourceId $accountId -ApiVersion $ApiVersion
    $keys = $null
    if ($account) {
        try { $keys = Get-AIAccountKeys -AccountId $accountId -ApiVersion $ApiVersion }
        catch { _AI-Log WARN "Could not fetch account keys: $($_.Exception.Message)" }
    } else {
        _AI-Log WARN 'Account not present -- skipping listKeys.'
    }

    $endpoint = if ($account -and $account.properties -and $account.properties.endpoint) { $account.properties.endpoint } else { '(not found)' }
    $key1     = if ($keys -and $keys.key1) { $keys.key1 } else { '(not available)' }

    $AI_endpoint   = if ($account -and $account.properties -and $account.properties.endpoint) { $account.properties.endpoint.TrimEnd('/') } else { '' }
    $AI_apiVersion = $InferenceApiVersion

    Write-Host ''
    Write-Host '  ========= SecurityInsight Phase OpenAI -- provisioning summary =========' -ForegroundColor Cyan
    Write-Host ("  Subscription   : {0}" -f $subIdAI)        -ForegroundColor White
    Write-Host ("  Resource Group : {0}  [{1}]" -f $rgAI, $statusRg)             -ForegroundColor White
    Write-Host ("  OpenAI account : {0}  [{1}]" -f $accountName, $statusAccount) -ForegroundColor White
    Write-Host ("  Deployment     : {0}  [{1}]" -f $deploymentName, $statusDeployment) -ForegroundColor White
    Write-Host ("  Model          : {0} ({1})"  -f $modelName, $modelVersion)    -ForegroundColor White
    Write-Host ("  Endpoint       : {0}" -f $endpoint)                            -ForegroundColor White
    Write-Host ("  Key1           : {0}" -f $key1)                                -ForegroundColor White
    Write-Host ''
    Write-Host '  Copy into LauncherConfig.custom.ps1 (SecurityInsight_RiskAnalysis):' -ForegroundColor Yellow
    Write-Host  "    `$Global:BuildSummaryByAI           = `$true"                 -ForegroundColor Green
    Write-Host ("    `$Global:OpenAI_apiKey              = `"{0}`"" -f $key1)      -ForegroundColor White
    Write-Host ("    `$Global:OpenAI_endpoint            = `"{0}`"" -f $AI_endpoint) -ForegroundColor White
    Write-Host ("    `$Global:OpenAI_deployment          = `"{0}`"" -f $deploymentName) -ForegroundColor White
    Write-Host ("    `$Global:OpenAI_apiVersion          = `"{0}`"" -f $AI_apiVersion) -ForegroundColor White
    Write-Host  "    `$Global:OpenAI_MaxTokensPerRequest = 16384"                  -ForegroundColor White
    Write-Host ''

    # Mirror Validate-SIOpenAI's $global:* publication so an in-process caller can pick them up.
    if ($keys) {
        $global:BuildSummaryByAI           = $true
        $global:OpenAI_apiKey              = $key1
        $global:OpenAI_endpoint            = $AI_endpoint
        $global:OpenAI_deployment          = $deploymentName
        $global:OpenAI_apiVersion          = $AI_apiVersion
        $global:OpenAI_MaxTokensPerRequest = 16384
    }

    if ($validateOnly) {
        $missing = @()
        if ($statusRg         -eq 'MISSING') { $missing += 'ResourceGroup' }
        if ($statusAccount    -eq 'MISSING') { $missing += 'Account' }
        if ($statusDeployment -eq 'MISSING') { $missing += 'Deployment' }
        if ($missing.Count -gt 0) {
            Write-Err2 ("[VALIDATE] {0} resource(s) missing: {1}" -f $missing.Count, ($missing -join ', '))
            return 'failed'
        }
        Write-Ok '[VALIDATE] All 3 resources present.'
        return 'ok'
    }

    if ($WhatIfPreference) { return 'whatif' }
    return 'ok'
}

function Invoke-Phase-PrivilegeTier {
    Write-Phase 'PrivilegeTier' 'Regenerate privilege-tier-catalog.custom.json'
    $catalog = Join-Path $script:_v22Root 'privilege-tier-catalog\privilege-tier-catalog.custom.json'
    $engine  = Join-Path $script:_v22Root 'engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1'

    if (-not (Test-Path $engine)) { Write-Warn2 'Privilege-tier engine missing; skipping'; return 'skipped' }

    $needsRebuild = $true
    if ((Test-Path $catalog) -and -not $Force) {
        try {
            $rec = Get-Content $catalog -Raw | ConvertFrom-Json
            if ($rec.Metadata -and $rec.Metadata.GeneratedAt) {
                $age = ([datetime]::UtcNow - [datetime]::Parse($rec.Metadata.GeneratedAt)).TotalDays
                if ($age -lt 90) {
                    Write-Info ("catalog age: {0:n1} days (under 90d threshold) -- skipping rebuild. Use -Force to override." -f $age)
                    $needsRebuild = $false
                }
            }
        } catch { Write-Warn2 "could not parse catalog metadata: $($_.Exception.Message)" }
    }

    if (-not $needsRebuild) { return 'fresh' }

    Write-Info '4 Azure OpenAI calls (one per provider category) will be made.'
    if ($PSCmdlet.ShouldProcess($engine, 'invoke privilege-tier-classifier')) {
        & $engine
        return 'rebuilt'
    }
    return 'whatif'
}

function Invoke-Phase-Schemas {
    Write-Phase 'Schemas' 'Detect schema drift between locked JSON and live LA tables'
    $schemaDir = Join-Path $script:_v22Root 'asset-profiling-schema'
    if (-not (Test-Path $schemaDir)) { Write-Warn2 "schema dir missing: $schemaDir"; return 'skipped' }

    $files = Get-ChildItem $schemaDir -Filter '*.schema.locked.json'
    foreach ($f in $files) {
        try {
            $j = Get-Content $f.FullName -Raw | ConvertFrom-Json
            $cols = @($j.fields | Select-Object -ExpandProperty name)
            Write-Info ("{0,-40} {1,3} columns -- {2}" -f $f.Name, $cols.Count, $j.table)
        } catch {
            Write-Warn2 "schema parse failed for $($f.Name): $($_.Exception.Message)"
        }
    }
    Write-Info 'NOTE: actual drift comparison vs LA requires Get-AzOperationalInsightsTable per workspace.'
    Write-Info 'The engines auto-add new columns on next ingest (Invoke-SchemaDiff). This phase is informational.'
    return 'reported'
}

function Invoke-Phase-PublicIp {
    Write-Phase 'PublicIp' 'PublicIp / Shodan engine readiness'
    $launcherCfg = Join-Path $script:_v22Root 'launcher\publicip\LauncherConfig.custom.ps1'
    $sample      = Join-Path $script:_v22Root 'launcher\publicip\LauncherConfig.custom.sample.ps1'

    if (-not (Test-Path $launcherCfg)) {
        if (Test-Path $sample) {
            Write-Info "stubbing LauncherConfig.custom.ps1 from sample ..."
            if ($PSCmdlet.ShouldProcess($launcherCfg, 'create from sample')) {
                Copy-Item $sample $launcherCfg -Force
                Write-Ok "created $launcherCfg"
            }
        } else {
            Write-Warn2 'no sample to copy; skipping stub.'
        }
    } else {
        Write-Info "$launcherCfg already exists."
    }

    if ($SkipShodan) { Write-Info '-SkipShodan set; not prompting for API key.'; return 'skipped' }

    $hasKey = $false
    if (Test-Path $launcherCfg) {
        $raw = Get-Content $launcherCfg -Raw -ErrorAction SilentlyContinue
        if ($raw -match '\$global:SI_Shodan_ApiKey\s*=\s*[''"][^''"]+[''"]') { $hasKey = $true }
    }
    if (-not $hasKey) {
        $key = Read-Host 'Shodan API key (paste, or press ENTER to skip)'
        if (-not [string]::IsNullOrWhiteSpace($key)) {
            if ($PSCmdlet.ShouldProcess($launcherCfg, 'inject Shodan API key')) {
                $line = "`$global:SI_Shodan_ApiKey = '$key'"
                Add-Content -LiteralPath $launcherCfg -Value $line
                Write-Ok 'API key written to LauncherConfig.custom.ps1'
            }
        } else {
            Write-Warn2 'no API key provided; PublicIp engine will throw on first run.'
        }
    } else {
        Write-Info 'Shodan API key already present in launcher config.'
    }
    return 'ok'
}

function Invoke-Phase-RA {
    Write-Phase 'RA' 'Risk Analysis report wiring sanity'
    $yaml = Join-Path $script:_v22Root 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    if (-not (Test-Path $yaml)) { Write-Warn2 "RA YAML missing: $yaml"; return 'skipped' }

    $reports = (Select-String -Path $yaml -Pattern '^\s+- ReportName:' | Measure-Object).Count
    $templates = (Select-String -Path $yaml -Pattern '^    - ReportName: RiskAnalysis_(Summary|Detailed)' | Measure-Object).Count
    Write-Info ("Reports: {0}, ReportTemplates: {1}" -f $reports, $templates)

    $publicIp4 = @('PublicIP_OpenPorts_Summary','PublicIP_OpenPorts_Detailed','PublicIP_Vulnerabilities_Summary','PublicIP_Vulnerabilities_Detailed')
    $missing = @()
    foreach ($r in $publicIp4) {
        if (-not (Select-String -Path $yaml -Pattern "^\s+- Name: $r\b" -Quiet)) { $missing += $r }
    }
    if ($missing.Count) {
        Write-Warn2 "missing from templates: $($missing -join ', ')"
        return 'drift'
    }
    Write-Ok 'all 4 PublicIp reports wired into Summary + Detailed templates.'
    return 'ok'
}

# ============================================================================
# Phase PBI -- inlined from Deploy-SIPowerBI.ps1
# ============================================================================
function Invoke-Phase-PBI {
    Write-Phase 'PBI' 'Power BI dashboard deploy'

    $whatIfMode = [bool]$WhatIfPreference

    $pbixPathLocal = $PbixPath
    if (-not $pbixPathLocal) {
        $candidate = Join-Path $script:_setupRoot '..\preview\PowerBI\SecurityInsight-RiskAnalysis.pbix'
        if (Test-Path -LiteralPath $candidate) { $pbixPathLocal = (Resolve-Path -LiteralPath $candidate).Path }
    }
    if (-not $pbixPathLocal -or -not (Test-Path -LiteralPath $pbixPathLocal)) {
        Write-Warn2 "Power BI .pbix not found. Expected at preview/PowerBI/SecurityInsight-RiskAnalysis.pbix or pass -PbixPath."
        return 'skipped'
    }
    $pbixFileName = [IO.Path]::GetFileName($pbixPathLocal)
    $pbixSizeMB   = [math]::Round((Get-Item $pbixPathLocal).Length / 1MB, 2)

    $laWsId = $LAWorkspaceId
    if (-not $laWsId) {
        if ($global:WorkspaceId) {
            $laWsId = [string]$global:WorkspaceId
        } elseif ($global:WorkspaceResourceId -match '/workspaces/([^/]+)$') {
            throw "LAWorkspaceId not supplied and can't be inferred. Pass -LAWorkspaceId '<GUID>'."
        } else {
            throw "LAWorkspaceId not supplied. Pass -LAWorkspaceId '<GUID>' or set `$global:WorkspaceId."
        }
    }
    $laTenant = $LATenantId
    if (-not $laTenant) {
        $laTenant = if ($AuthTenantId) { $AuthTenantId } else { $global:SpnTenantId }
        if (-not $laTenant) { throw "LATenantId not supplied. Pass -LATenantId or set `$global:SpnTenantId." }
    }

    Write-Host ''
    Write-Host ("  pbix          : {0} ({1} MB)"  -f $pbixFileName, $pbixSizeMB) -ForegroundColor White
    Write-Host ("  Workspace     : {0}"           -f $PowerBIWorkspaceName)      -ForegroundColor White
    Write-Host ("  Report        : {0}"           -f $PowerBIReportName)         -ForegroundColor White
    Write-Host ("  LA workspace  : {0}"           -f $laWsId)                    -ForegroundColor White
    Write-Host ("  LA tenant     : {0}"           -f $laTenant)                  -ForegroundColor White
    Write-Host ("  Auth method   : {0}"           -f $PowerBIAuthMethod)         -ForegroundColor White
    Write-Host ("  WhatIfMode    : {0}"           -f $whatIfMode)                -ForegroundColor White

    $pbiResource = 'https://analysis.windows.net/powerbi/api/.default'

    function Get-PBIToken {
        param([string]$Method, [string]$TenantId, [string]$ClientId, [string]$ClientSecret, [string]$CertificateThumbprint)
        if (-not $TenantId) { throw 'TenantId required for Power BI auth.' }
        switch ($Method) {
            'SpnSecret' {
                if (-not $ClientId -or -not $ClientSecret) { throw 'SpnSecret requires -AuthClientId + -AuthClientSecret.' }
                $body = @{ grant_type='client_credentials'; client_id=$ClientId; client_secret=$ClientSecret; scope=$pbiResource }
                $resp = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body -ContentType 'application/x-www-form-urlencoded'
                return $resp.access_token
            }
            'SpnCertificate' {
                if (-not $ClientId -or -not $CertificateThumbprint) { throw 'SpnCertificate requires -AuthClientId + -AuthCertificateThumbprint.' }
                $cert = Get-ChildItem "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
                if (-not $cert) { $cert = Get-ChildItem "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue }
                if (-not $cert) { throw "Cert '$CertificateThumbprint' not found in CurrentUser\My or LocalMachine\My." }
                $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                $jwtHeader  = @{ alg='RS256'; typ='JWT'; x5t=[Convert]::ToBase64String($cert.GetCertHash()) } | ConvertTo-Json -Compress
                $jwtPayload = @{ aud="https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"; iss=$ClientId; sub=$ClientId; jti=[guid]::NewGuid().ToString(); nbf=$now; exp=$now+600 } | ConvertTo-Json -Compress
                $enc1 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($jwtHeader)).TrimEnd('=').Replace('+','-').Replace('/','_')
                $enc2 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($jwtPayload)).TrimEnd('=').Replace('+','-').Replace('/','_')
                $toSign = "$enc1.$enc2"
                $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
                $sig = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($toSign), 'SHA256', 'Pkcs1')
                $enc3 = [Convert]::ToBase64String($sig).TrimEnd('=').Replace('+','-').Replace('/','_')
                $assertion = "$toSign.$enc3"
                $body = @{ grant_type='client_credentials'; client_id=$ClientId; client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer'; client_assertion=$assertion; scope=$pbiResource }
                $resp = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body -ContentType 'application/x-www-form-urlencoded'
                return $resp.access_token
            }
            'ManagedIdentity' {
                $imdsUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://analysis.windows.net/powerbi/api"
                if ($ClientId) { $imdsUri += "&client_id=$ClientId" }
                $resp = Invoke-RestMethod -Method GET -Uri $imdsUri -Headers @{ Metadata='true' }
                return $resp.access_token
            }
            'Interactive' {
                $appId = if ($ClientId) { $ClientId } else { '1950a258-227b-4e31-a9cf-717495945fc2' }
                $deviceBody = @{ client_id=$appId; scope=$pbiResource }
                $dev = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" -Body $deviceBody -ContentType 'application/x-www-form-urlencoded'
                Write-Host ''
                Write-Host '  Device code auth:' -ForegroundColor Yellow
                Write-Host ("    Open {0}" -f $dev.verification_uri) -ForegroundColor Yellow
                Write-Host ("    and enter code: {0}" -f $dev.user_code) -ForegroundColor Yellow
                $deadline = (Get-Date).AddSeconds($dev.expires_in)
                while ((Get-Date) -lt $deadline) {
                    Start-Sleep -Seconds ([math]::Max(5, $dev.interval))
                    try {
                        $pollBody = @{ grant_type='urn:ietf:params:oauth:grant-type:device_code'; client_id=$appId; device_code=$dev.device_code }
                        $resp = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $pollBody -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
                        if ($resp.access_token) { return $resp.access_token }
                    } catch {
                        $errBody = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                        if ($errBody.error -ne 'authorization_pending') { throw }
                    }
                }
                throw "Device code auth timed out after $($dev.expires_in) seconds."
            }
            default { throw "Unsupported AuthMethod '$Method'." }
        }
    }

    Write-Sep
    Write-Step "Acquiring Power BI access token (AuthMethod=$PowerBIAuthMethod)"
    try {
        $token = Get-PBIToken -Method $PowerBIAuthMethod -TenantId $AuthTenantId `
            -ClientId $AuthClientId -ClientSecret $AuthClientSecret `
            -CertificateThumbprint $AuthCertificateThumbprint
        Write-Ok ("token acquired ({0} chars)" -f $token.Length)
    } catch {
        throw "Failed to acquire Power BI token: $($_.Exception.Message)"
    }

    $pbiHeaders = @{ Authorization="Bearer $token"; 'Content-Type'='application/json' }
    $pbiBase = 'https://api.powerbi.com/v1.0/myorg'

    Write-Sep
    Write-Step "Resolving Power BI workspace: $PowerBIWorkspaceName"
    $groups = Invoke-RestMethod -Method GET -Uri "$pbiBase/groups?`$filter=name eq '$PowerBIWorkspaceName'" -Headers $pbiHeaders
    $targetGroup = $groups.value | Select-Object -First 1

    if (-not $targetGroup) {
        if ($whatIfMode) {
            Write-Skip "workspace '$PowerBIWorkspaceName' not found -- WOULD create (WhatIfMode)"
        } else {
            Write-Step "workspace '$PowerBIWorkspaceName' not found -- creating"
            $createBody = @{ name = $PowerBIWorkspaceName } | ConvertTo-Json -Compress
            $targetGroup = Invoke-RestMethod -Method POST -Uri "$pbiBase/groups?workspaceV2=true" -Headers $pbiHeaders -Body $createBody
            Write-Add ("created workspace  id={0}" -f $targetGroup.id)
        }
    } else {
        Write-Ok ("workspace found  id={0}" -f $targetGroup.id)
    }

    if (-not $targetGroup) {
        Write-Skip 'WhatIfMode + no existing workspace -- cannot evaluate downstream state.'
        return 'whatif'
    }
    $groupId = $targetGroup.id

    $datasetId = $null; $reportId = $null
    Write-Sep
    Write-Step "Uploading $pbixFileName to workspace"
    if ($whatIfMode) {
        Write-Skip "WOULD upload $pbixFileName to group $groupId (WhatIfMode)"
    } else {
        $importUri = "$pbiBase/groups/$groupId/imports?datasetDisplayName=$([uri]::EscapeDataString($PowerBIReportName))&nameConflict=CreateOrOverwrite"
        $boundary = '----SI-' + [guid]::NewGuid().ToString('N')
        $bytes = [System.IO.File]::ReadAllBytes($pbixPathLocal)
        $LF = "`r`n"
        $preamble = "--$boundary$LF" +
                    "Content-Disposition: form-data; name=""file""; filename=""$pbixFileName""$LF" +
                    "Content-Type: application/octet-stream$LF$LF"
        $postamble = "$LF--$boundary--$LF"
        $preambleBytes  = [Text.Encoding]::UTF8.GetBytes($preamble)
        $postambleBytes = [Text.Encoding]::UTF8.GetBytes($postamble)
        $body = New-Object byte[] ($preambleBytes.Length + $bytes.Length + $postambleBytes.Length)
        [Array]::Copy($preambleBytes, 0, $body, 0, $preambleBytes.Length)
        [Array]::Copy($bytes,         0, $body, $preambleBytes.Length, $bytes.Length)
        [Array]::Copy($postambleBytes, 0, $body, $preambleBytes.Length + $bytes.Length, $postambleBytes.Length)

        $importHeaders = @{ Authorization="Bearer $token"; 'Content-Type'="multipart/form-data; boundary=$boundary" }
        $importResp = Invoke-RestMethod -Method POST -Uri $importUri -Headers $importHeaders -Body $body
        $importId = $importResp.id

        Write-Info 'polling import status...'
        $deadline = (Get-Date).AddMinutes(5)
        $import = $null
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 3
            $import = Invoke-RestMethod -Method GET -Uri "$pbiBase/groups/$groupId/imports/$importId" -Headers $pbiHeaders
            if ($import.importState -eq 'Succeeded') { break }
            if ($import.importState -eq 'Failed')    { throw "Power BI import failed: $($import | ConvertTo-Json -Depth 5)" }
        }
        if ($import.importState -ne 'Succeeded') { throw "Power BI import timed out (state=$($import.importState))." }
        Write-Add ("imported  state={0}  reports={1}  datasets={2}" -f $import.importState, @($import.reports).Count, @($import.datasets).Count)

        $datasetId = $import.datasets[0].id
        $reportId  = $import.reports[0].id
        Write-Info ("datasetId: $datasetId")
        Write-Info ("reportId : $reportId")
    }

    if (-not $whatIfMode) {
        Write-Sep
        Write-Step 'Rebinding dataset parameters'
        $paramBody = @{
            updateDetails = @(
                @{ name='LA_WorkspaceId'; newValue=$laWsId },
                @{ name='LA_TenantId';    newValue=$laTenant },
                @{ name='StalenessDays';  newValue=[string]$PowerBIStalenessDays },
                @{ name='TopNFindings';   newValue=[string]$PowerBITopNFindings }
            )
        } | ConvertTo-Json -Depth 5 -Compress
        try {
            Invoke-RestMethod -Method POST `
                -Uri "$pbiBase/groups/$groupId/datasets/$datasetId/Default.UpdateParameters" `
                -Headers $pbiHeaders -Body $paramBody | Out-Null
            Write-Add 'parameters rebound'
        } catch {
            Write-Err2 ("UpdateParameters failed: {0}" -f $_.Exception.Message)
            Write-Info 'Continuing -- verify the .pbix defines LA_WorkspaceId / LA_TenantId / StalenessDays / TopNFindings parameters.'
        }
    }

    if ($PowerBIAccessGroupObjectId -and -not $whatIfMode) {
        Write-Sep
        Write-Step ("Granting {0} {1} on workspace to AAD group {2}" -f $PowerBIAccessGroupObjectId, $PowerBIAccessGroupRole, $PowerBIWorkspaceName)
        $accessBody = @{
            identifier             = $PowerBIAccessGroupObjectId
            principalType          = 'Group'
            groupUserAccessRight   = $PowerBIAccessGroupRole
        } | ConvertTo-Json -Compress
        try {
            Invoke-RestMethod -Method POST -Uri "$pbiBase/groups/$groupId/users" -Headers $pbiHeaders -Body $accessBody | Out-Null
            Write-Add 'access group granted'
        } catch {
            Write-Skip ("group already has access or grant failed: {0}" -f $_.Exception.Message)
        }
    }

    if ($PowerBITriggerInitialRefresh -and -not $whatIfMode) {
        Write-Sep
        Write-Step 'Triggering initial dataset refresh'
        try {
            Invoke-RestMethod -Method POST `
                -Uri "$pbiBase/groups/$groupId/datasets/$datasetId/refreshes" `
                -Headers $pbiHeaders -Body '{"notifyOption":"NoNotification"}' | Out-Null
            Write-Add 'refresh queued'
        } catch {
            Write-Err2 ("initial refresh failed: {0}" -f $_.Exception.Message)
            Write-Info "This usually means the dataset's LA credentials aren't bound yet. See PowerBI-Prerequisites.md."
        }
    }

    Write-Sep
    Write-Host ''
    if ($whatIfMode) {
        Write-Host '  ========= Phase PBI dry-run summary (no changes made) =========' -ForegroundColor Cyan
    } else {
        Write-Host '  ========= Phase PBI deployment summary =========' -ForegroundColor Cyan
        Write-Host ("  Workspace  : {0}  (id={1})" -f $PowerBIWorkspaceName, $groupId) -ForegroundColor White
        if ($reportId)  { Write-Host ("  Report     : {0}  (id={1})"  -f $PowerBIReportName, $reportId) -ForegroundColor White }
        if ($datasetId) { Write-Host ("  Dataset    : id={0}" -f $datasetId) -ForegroundColor White }
        Write-Host ("  Portal URL : https://app.powerbi.com/groups/{0}/reports/{1}" -f $groupId, $reportId) -ForegroundColor White
    }
    Write-Host ''
    Write-Host "  One-time post-deploy step in the Power BI portal (can't be automated today):" -ForegroundColor Yellow
    Write-Host "    1. Open https://app.powerbi.com/groups/$groupId/settings/datasets/$datasetId" -ForegroundColor Yellow
    Write-Host "    2. Dataset settings -> 'Take over' if prompted" -ForegroundColor Yellow
    Write-Host "    3. Data source credentials -> sign in to 'Azure Monitor Logs'" -ForegroundColor Yellow
    Write-Host '    4. (optional) Scheduled refresh -> set to 8x/day or match your RiskAnalysis cadence' -ForegroundColor Yellow
    Write-Host ''

    if ($whatIfMode) { return 'whatif' }
    return 'ok'
}

function Invoke-Phase-Summary {
    Write-Phase 'Summary' 'End-of-run summary'
    if ($script:_log.Count -eq 0) { Write-Info 'no phases ran.'; return }
    $script:_log | ForEach-Object {
        [pscustomobject]@{
            Phase    = $_.Phase
            Status   = $_.Status
            Duration = $_.Duration
            Detail   = $_.Detail
        }
    } | Format-Table -AutoSize | Out-Host
    $total = ([datetime]::UtcNow - $script:_t0).TotalSeconds
    Write-Ok ('Setup completed in {0:n1}s' -f $total)
}

# ---------------------------------------------------------------------------
# Phase resolver + dispatcher
# ---------------------------------------------------------------------------
function Resolve-Phases([string[]]$requested) {
    if (-not $requested -or $requested.Count -eq 0) {
        Write-Section 'INTERACTIVE PHASE SELECTION'
        Write-Host ('Available phases (in canonical order):') -ForegroundColor White
        for ($i = 0; $i -lt $script:_phaseOrder.Count; $i++) {
            Write-Host (' [{0}] {1}' -f ($i+1), $script:_phaseOrder[$i])
        }
        Write-Host ' [A] All'
        $sel = Read-Host 'Enter numbers comma-separated, or A for all'
        if ($sel -match '^\s*A\s*$') { return $script:_phaseOrder }
        $idx = ($sel -split '[\s,]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ - 1 })
        return @($idx | ForEach-Object { $script:_phaseOrder[$_] })
    }
    if ($requested -contains 'All') { return $script:_phaseOrder }
    return $requested
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Section 'SecurityInsight v2.2 Unified Setup'
Write-Info ("RepoRoot:        {0}" -f $script:_v22Root)
Write-Info ("WhatIf:          {0}" -f $WhatIfPreference.IsPresent)
Write-Info ("Force:           {0}" -f $Force.IsPresent)
Write-Info ("SkipShodan:      {0}" -f $SkipShodan.IsPresent)

$resolved = Resolve-Phases $Phase
Write-Info ("Phases to run:   {0}" -f ($resolved -join ', '))

foreach ($p in $resolved) {
    $start = [datetime]::UtcNow
    $status = 'error'
    try {
        $status = switch ($p) {
            'Config'        { Invoke-Phase-Config }
            'Github'        { Invoke-Phase-Github }
            'Spn'           { Invoke-Phase-Spn }
            'LA'            { Invoke-Phase-LA }
            'OpenAI'        { Invoke-Phase-OpenAI }
            'PrivilegeTier' { Invoke-Phase-PrivilegeTier }
            'Schemas'       { Invoke-Phase-Schemas }
            'PublicIp'      { Invoke-Phase-PublicIp }
            'RA'            { Invoke-Phase-RA }
            'PBI'           { Invoke-Phase-PBI }
            default         { Write-Warn2 "Unknown phase: $p"; 'skipped' }
        }
        Add-Result $p $status $start
    } catch {
        Write-Err2 ("Phase {0} failed: {1}" -f $p, $_.Exception.Message)
        Add-Result $p 'failed' $start $_.Exception.Message
    }
}

Invoke-Phase-Summary
