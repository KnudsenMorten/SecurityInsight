#Requires -Version 5.1
<#
.SYNOPSIS
    The guided install's engine: config validation, the step plan, events, state and resume, and the Community steps.

.DESCRIPTION
    setup\Install-SecurityInsight.ps1 is the entry point invardia.com's bootstrap calls. This file is what it runs:

      * Test-SIInstallConfig      the wizard's answers (config.json) checked against setup\install-parameters.json
      * Get-SIInstallStepPlan     the stable step ids, in order, for the Community or the Pro edition
      * New-SIInstallEvent        the event the reporter receives (installId, seq, step, state, at, durationMs,
                                  message, action, detail <= 8 KB), with secrets redacted
      * Invoke-SIGuidedInstall    preflight -> steps -> health check -> completed, with a resumable state file

    The steps are THIN. Each one calls the product's own, live-proven script (Initialize-SIInfra,
    Bootstrap-ContainerAppJob, Grant-SIIdentity, Grant-SISupportAccess, ...) and reports what it did. They never
    re-implement that work.

    EVERY external call goes through a seam ($ctx.Seams): Az (Azure over plain REST: a SecurityInsight REST function
    by name -- Get-SISetupAzureContext, Get-SIKeyVault, New-SIAzRoleAssignment, ... from setup\_shared\SI-SetupAzure.ps1
    and engine\_shared\SI-AzRest.ps1, and the Azure resources of setup\_shared\SI-SetupArm.ps1 -- container registry,
    Container Apps, Azure SQL; no PowerShell module and no az CLI, #521), Graph, Sql, Token, Script (a product script),
    ReadSecret, IsInteractive, Sleep, Now, Print. The defaults call the real thing; the offline tests pass fakes, so the
    whole flow runs with no Azure at all.

    SIGN-IN: the install signs the person in itself (Connect-SISetupAzure, through the Az seam): in Azure Cloud Shell
    with no prompt, on a workstation in the browser -- or, in an Invardia support shell, the support session's tokens.
    The az CLI is neither needed nor used (#521).

    The database and web app steps (the database server, its tables, templates and settings, the web app, the updater)
    live in SI-GuidedInstallData.ps1 and run in BOTH versions (owner 2026-10-18: the free version has the database and the
    web app; paid features are switched off by the licence). The paid steps (the licence, the v2.2 CMDB migration) live in
    SI-GuidedInstallPro.ps1, which only the Pro package carries. Without it a licence is refused in preflight.

    Windows PowerShell 5.1 and PowerShell 7 (Azure Cloud Shell is PowerShell 7 on Linux).
#>

# The default names and resource-group tags (framework 5.5).
. ([IO.Path]::Combine($PSScriptRoot, 'SI-SetupNaming.ps1'))
# Azure and Microsoft Graph over plain REST, and the setup sign-in (#305: no PowerShell modules).
. ([IO.Path]::Combine($PSScriptRoot, 'SI-SetupAzure.ps1'))
# #521: container registry, Container Apps and Azure SQL over ARM -- the install calls no az CLI
. ([IO.Path]::Combine($PSScriptRoot, 'SI-SetupArm.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, 'SI-GraphRest.ps1'))
# the nightly schedule: the update at 23:00 and the pipeline at 23:30 in the local time of the install's Azure region (pure)
. ([IO.Path]::Combine($PSScriptRoot, 'SI-NightlySchedule.ps1'))
# the security baseline for new installs (behind SI_SECURITY_BASELINE_NEW_INSTALL, default OFF)
. ([IO.Path]::Combine($PSScriptRoot, 'SI-SecurityBaseline.ps1'))
# #681 / #683: private networking and customer-managed keys -- OPTIONS (default off: the default install is unchanged)
. ([IO.Path]::Combine($PSScriptRoot, 'SI-PrivateNetwork.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, 'SI-CustomerKeys.ps1'))
# #427: a failed step reaches Invardia's uplink (engine/_shared/SI-TelemetrySend.ps1). A missing or broken file only means no report.
try {
    $siInstallTelemetryLib = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', '_shared', 'SI-TelemetrySend.ps1')
    if (-not (Get-Command -Name Send-SITelemetryFailure -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $siInstallTelemetryLib)) { . $siInstallTelemetryLib }
} catch { }

# ---------------------------------------------------------------------------------------------------------------
# The steps: stable ids (the status page and support tickets refer to them) and customer-language titles.
# ---------------------------------------------------------------------------------------------------------------
$script:SIInstallStepTitles = [ordered]@{
    'preflight-signin'         = 'Check your Azure sign-in'
    'preflight-target'         = 'Check the tenant and subscription'
    'preflight-rights'         = 'Check your permissions'
    'preflight-providers'      = 'Check the Azure resource providers'
    'preflight-names'          = 'Check that the names are free'
    'preflight-region'         = 'Check that the region accepts every resource'
    'preflight-quota'          = 'Check the subscription''s quota in the region'
    'preflight-sql-region'     = 'Check that the region accepts the database'
    'resource-group'           = 'Resource group'
    'private-network-subnets'  = 'Private network: the subnets in your virtual network'
    'workspace'                = 'Log Analytics workspace'
    'data-collection-endpoint' = 'Data collection endpoint'
    'storage'                  = 'Storage account'
    'private-network-data'     = 'Private network: the storage''s and the Key Vault''s private endpoints, and the DNS check'
    'key-vault'                = 'Key Vault and your keys'
    'licence'                  = 'SecurityInsight Pro licence'
    'container-registry-image' = 'Container registry and image'
    'container-environment'    = 'Container Apps environment'
    'runtime-identity'         = 'SecurityInsight''s managed identity'
    'grants-resource-group'    = 'Access inside the resource group'
    'grants-outside-rg'        = 'Read access outside the resource group'
    'api-permissions'          = 'Read-only Microsoft Graph and Defender permissions'
    'container-jobs'           = 'Scheduled engine jobs'
    'pro-sql'                  = 'Database server'
    'pro-schema'               = 'Database tables'
    'pro-templates'            = 'Configuration templates'
    'pro-cmdb'                 = 'Your v2.2 CMDB in the Pro database'
    'pro-settings'             = 'Settings in the database'
    'web-app'                  = 'SecurityInsight web app'
    'updater-job'              = 'Updates from Invardia'
    'customer-managed-keys'    = 'Your own encryption key: database, storage and Log Analytics'
    'support-app-access'       = 'Invardia Support access'
    'mail'                     = 'E-mail: the shared mailbox or your SMTP relay'
    'private-network'          = 'Private network: private endpoints, private DNS, public endpoints closed'
    'first-run'                = 'First run'
    'health-check'             = 'Health check'
    'completed'                = 'Installation complete'
    # #564: a terminating error OUTSIDE a step (after the last step's event) is still reported, under this id
    'installer'                = 'The installer'
}
# The paid steps: only in a Pro install (the licence step runs in both and says 'skipped' without one).
$script:SIInstallProStepIds = @('pro-cmdb')
# The database and web app steps (SI-GuidedInstallData.ps1): in EVERY install, both versions (owner 2026-10-18).
$script:SIInstallDataStepIds = @('preflight-sql-region', 'pro-sql', 'pro-schema', 'pro-templates', 'pro-settings', 'web-app', 'updater-job')
# #681 / #683: the steps of an OPTION are in the plan only when the install asks for the option (the answer that turns it
# on) -- an install without them runs exactly the steps it ran before.
$script:SIInstallOptionStepIds = [ordered]@{
    'private-network-subnets' = 'privateNetwork'
    'private-network-data'    = 'privateNetwork'
    'private-network'         = 'privateNetwork'
    'customer-managed-keys'   = 'customerManagedKeys'
}
$script:SIInstallStates = @('started', 'ok', 'warning', 'failed', 'skipped', 'completed')
$script:SIInstallOutputKeys = @('subscriptionId', 'resourceGroup', 'keyVaultId', 'logAnalyticsWorkspaceId', 'securityWorkspaceId',
    'sqlServerId', 'hosting', 'runtimeIdentity', 'runtimeIdentityClientId', 'version', 'portalUrl')
# The engines of every install get a container job each -- the data sync (asset-datasync) too: it loads each complete Risk
# Analysis collection into the database the web app reads, in both versions (owner 2026-10-18; #678). Cross-engine
# correlation -- the CI build, asset-correlation -- and asset tagging (its own identity; it reports only until its writes are
# granted and switched on, #236) are in the Community edition too (owner 2026-10-27, #750 (1) and (2)). The Pro package adds
# the paid engines (SI-GuidedInstallPro.ps1).
$script:SIInstallCommunityEngines = @('endpoint', 'identity', 'azure', 'publicip', 'privilege-tier-classifier', 'risk-analysis', 'risk-analysis-detailed', 'asset-trend', 'asset-datasync', 'asset-correlation', 'asset-tagging')
# Parameters that are required whenever the wizard shows them (the parameter file marks only the always-required ones).
$script:SIInstallRequiredWhenShown = @('workspaceId', 'managementGroupId', 'openAiEndpoint', 'openAiDeployment', 'smtpServer', 'smtpFrom', 'vnetId', 'logAnalyticsClusterId')
# A config key that looks like a secret is refused by NAME, so a wizard bug can never carry a key into config.json.
$script:SIInstallSecretKeyPattern = '(?i)(secret|password|passwd|pwd|apikey|api_key|token|credential|connectionstring|sas)|key$'
$script:SIInstallDetailMaxBytes = 8192
# #564: the mail step's wait for Exchange (per action and for the scope check) -- short; the rest is deferred to Get Started
$script:SIInstallMailTimeoutSeconds = 60

$script:SIInstallRoleWrite = @('Owner', 'Contributor')
$script:SIInstallRoleRbac  = @('Owner', 'User Access Administrator', 'Role Based Access Control Administrator')
$script:SIInstallDirectoryAdminRoles = @{
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
}
# The Microsoft Graph application permissions with which an APP (the install signed in as an app, #413) can grant app
# roles to SecurityInsight's identity: AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory.
$script:SIInstallGraphGrantAppRoles = @('06b708a9-e830-4db3-a914-8e69da51d44f', '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8')

# ---------------------------------------------------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------------------------------------------------
function ConvertTo-SIInstallHashtable {
    <# PURE. ConvertFrom-Json gives PSCustomObjects (5.1 has no -AsHashtable); the engine works on hashtables. #>
    param([AllowNull()]$InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}; foreach ($k in $InputObject.Keys) { $h[[string]$k] = ConvertTo-SIInstallHashtable $InputObject[$k] }; return $h
    }
    if ($InputObject -is [string]) { return $InputObject }
    if ($InputObject -is [System.Collections.IEnumerable]) { return , @($InputObject | ForEach-Object { ConvertTo-SIInstallHashtable $_ }) }
    # A JSON object -- also an EMPTY one ({} in a saved state file), which has no properties to detect it by.
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $h = [ordered]@{}; foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-SIInstallHashtable $p.Value }; return $h
    }
    $InputObject
}

function Get-SIInstallProp {
    <# PURE. A property or key of an object, or $null -- never throws on a missing one (Set-StrictMode safe). #>
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $null
}

function Test-SIInstallSignedInAsApp {
    <# PURE. $true when the install's signed-in identity is NOT a person -- a service principal or a managed identity
       (#524: the Invardia Support app, through its support session's tokens). The sign-in step records the account type;
       none recorded = a person (the long-standing default). An app cannot sign in to the web app and has no /me. #>
    param([Parameter(Mandatory)]$Ctx)
    $t = [string]$Ctx.Facts['accountType']
    [bool]($t -and $t -ne 'User')
}

function Protect-SIInstallText {
    <#
        PURE. Redacts what must never leave the customer's shell: JWTs, Bearer tokens, client_secret=..., connection-
        string secrets (Password=, AccountKey=, SharedAccessKey=) and SAS signatures (sig=). Applied to every message,
        action and detail before an event is built -- a product script's error text can carry any of them.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text
    $t = [regex]::Replace($t, 'eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*', '[redacted-jwt]')
    $t = [regex]::Replace($t, '(?i)\bbearer\s+[A-Za-z0-9\-\._~\+/=]+', 'Bearer [redacted]')
    $t = [regex]::Replace($t, '(?i)(client_secret\s*["'']?\s*[=:]\s*["'']?)[^&\s"'',;]+', '${1}[redacted]')
    $t = [regex]::Replace($t, '(?i)\b(password|pwd|accountkey|sharedaccesskey|sharedaccesssignature)\s*=\s*[^;"''\s]+', '${1}=[redacted]')
    $t = [regex]::Replace($t, '(?i)(\bsig=)[^&\s"'']+', '${1}[redacted]')
    $t = [regex]::Replace($t, '(?i)("?(?:api[-_]?key|x-api-key|ocp-apim-subscription-key)"?\s*[:=]\s*"?)[^"&\s,;]+', '${1}[redacted]')
    $t
}

function Protect-SIInstallValue {
    <# PURE. Protect-SIInstallText over every string inside a hashtable / array / object (for event detail). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return (Protect-SIInstallText $Value) }
    if ($Value -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}; foreach ($k in $Value.Keys) { $h[[string]$k] = Protect-SIInstallValue $Value[$k] }; return $h
    }
    if ($Value -is [System.Collections.IEnumerable]) { return , @($Value | ForEach-Object { Protect-SIInstallValue $_ }) }
    if ($Value -is [ValueType]) { return $Value }
    if ($Value -is [psobject] -and @($Value.PSObject.Properties).Count) {
        $h = [ordered]@{}; foreach ($p in $Value.PSObject.Properties) { $h[$p.Name] = Protect-SIInstallValue $p.Value }; return $h
    }
    Protect-SIInstallText ([string]$Value)
}

function Limit-SIInstallDetail {
    <# PURE. Detail is capped at 8 KB (UTF-8, as JSON). Over the cap it becomes { truncated = $true; text = <the start> }. #>
    param([AllowNull()]$Detail, [int]$MaxBytes = $script:SIInstallDetailMaxBytes)
    if ($null -eq $Detail) { return $null }
    $json = ConvertTo-Json -InputObject $Detail -Depth 8 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -le $MaxBytes) { return $Detail }
    $keep = [Math]::Min($json.Length, $MaxBytes - 200)
    while ($keep -gt 0) {
        $cut = [ordered]@{ truncated = $true; text = $json.Substring(0, $keep) }
        if ([Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $cut -Compress)) -le $MaxBytes) { return $cut }
        $keep = [int]($keep * 0.8)
    }
    [ordered]@{ truncated = $true; text = '' }
}

function New-SIInstallEvent {
    <#
        PURE. One event as the reporter receives it (GUIDED-INSTALL 4.3). Message, action and detail are redacted;
        detail is capped at 8 KB; message at 1,000 characters. 'completed' also carries the outputs.
    #>
    param(
        [Parameter(Mandatory)][string]$InstallId,
        [Parameter(Mandatory)][int]$Seq,
        [Parameter(Mandatory)][string]$StepId,
        [Parameter(Mandatory)][ValidateSet('started', 'ok', 'warning', 'failed', 'skipped', 'completed')][string]$State,
        [Parameter(Mandatory)][datetime]$At,
        [AllowNull()]$DurationMs,
        [AllowNull()][AllowEmptyString()][string]$Message,
        [AllowNull()]$Action,
        [AllowNull()]$Detail,
        [AllowNull()]$Outputs
    )
    $title = if ($script:SIInstallStepTitles.Contains($StepId)) { $script:SIInstallStepTitles[$StepId] } else { $StepId }
    $msg = Protect-SIInstallText ([string]$Message)
    if ($msg -and $msg.Length -gt 1000) { $msg = $msg.Substring(0, 997) + '...' }
    $act = $null
    if ($Action) {
        # (not $at: PowerShell names are case-insensitive, and -At is this function's [datetime] parameter)
        $actText = [string](Get-SIInstallProp $Action 'text'); $actCmd = [string](Get-SIInstallProp $Action 'command')
        $act = [ordered]@{ text = (Protect-SIInstallText $actText); command = $(if ($actCmd) { Protect-SIInstallText $actCmd } else { $null }) }
    }
    $ev = [ordered]@{
        installId  = $InstallId
        seq        = $Seq
        step       = [ordered]@{ id = $StepId; title = $title }
        state      = $State
        at         = $At.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        durationMs = $(if ($null -ne $DurationMs) { [long]$DurationMs } else { $null })
        message    = $msg
        action     = $act
        detail     = (Limit-SIInstallDetail (Protect-SIInstallValue $Detail))
    }
    if ($State -eq 'completed') { $ev['outputs'] = $Outputs }
    $ev
}

function New-SIInstallResult {
    <# PURE. What a step returns: ok | warning | skipped, a message, optionally an action and detail. #>
    param([ValidateSet('ok', 'warning', 'skipped')][string]$State = 'ok', [string]$Message = '', [AllowNull()]$Action, [AllowNull()]$Detail)
    [pscustomobject]@{ State = $State; Message = $Message; Action = $Action; Detail = $Detail }
}

function New-SIInstallFailure {
    <# PURE. A step's unworkable problem: throw this. It carries the message and the action for the customer. #>
    param([Parameter(Mandatory)][string]$Message, [string]$ActionText, [string]$Command, $Detail)
    $ex = New-Object System.Exception($Message)
    $ex.Data['SIInstallAction'] = $(if ($ActionText -or $Command) { [ordered]@{ text = $ActionText; command = $Command } } else { $null })
    $ex.Data['SIInstallDetail'] = $Detail
    $ex
}

function Get-SIInstallTail {
    <# PURE. The last lines of a script's output, for an event's detail (redacted later). #>
    param([AllowNull()][string[]]$Lines, [int]$Count = 40)
    $l = @($Lines | Where-Object { "$_".Trim() })
    if ($l.Count -le $Count) { return , $l }
    , @($l[($l.Count - $Count)..($l.Count - 1)])
}

# ---------------------------------------------------------------------------------------------------------------
# The parameter file and config.json
# ---------------------------------------------------------------------------------------------------------------
function Test-SIInstallValueType {
    <# PURE. $null when the value fits the parameter's type (and min / max / options); else the problem in words. #>
    param([Parameter(Mandatory)]$Param, [AllowNull()]$Value)
    $type = [string](Get-SIInstallProp $Param 'type')
    $guid = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    $email = '^[^@\s]+@[^@\s]+\.[^@\s]+$'
    switch ($type) {
        'guid'              { if ($Value -isnot [string] -or $Value -notmatch $guid) { return 'must be a GUID' } }
        'string'            { if ($Value -isnot [string]) { return 'must be text' } }
        # #240: the one secret config.json may carry (installKey, from Invardia's bundle). Never echoed in a message.
        'secret'            { if ($Value -isnot [string]) { return 'must be text' } }
        'enum'              {
            $opts = @(Get-SIInstallProp $Param 'options' | ForEach-Object { [string](Get-SIInstallProp $_ 'value') })
            if ($Value -isnot [string] -or $opts -notcontains $Value) { return ('must be one of: {0}' -f ($opts -join ', ')) }
        }
        'bool'              { if ($Value -isnot [bool]) { return 'must be true or false' } }
        'int'               {
            $isInt = ($Value -is [int] -or $Value -is [long] -or (($Value -is [double] -or $Value -is [decimal]) -and [Math]::Floor([double]$Value) -eq [double]$Value))
            if (-not $isInt) { return 'must be a whole number' }
            $min = Get-SIInstallProp $Param 'min'; $max = Get-SIInstallProp $Param 'max'
            if ($null -ne $min -and [double]$Value -lt [double]$min) { return ('must be at least {0}' -f $min) }
            if ($null -ne $max -and [double]$Value -gt [double]$max) { return ('must be at most {0}' -f $max) }
            # #417: an int may list its only allowed values (updateRing: 1, 2, 3)
            $choices = @(Get-SIInstallProp $Param 'choices' | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ })
            if ($choices.Count -and $choices -notcontains [double]$Value) { return ('must be one of: {0}' -f ($choices -join ', ')) }
        }
        'region'            { if ($Value -isnot [string] -or $Value -notmatch '^[a-z][a-z0-9]{2,40}$') { return 'must be an Azure region name, e.g. westeurope' } }
        'resourceGroupName' { if ($Value -isnot [string] -or $Value -notmatch '^[-\w\.\(\)]{1,90}$' -or $Value.EndsWith('.')) { return 'must be a valid resource group name (1-90 letters, digits, - _ . ( ), not ending in a dot)' } }
        'resourceId'        { if ($Value -isnot [string] -or $Value -notmatch '(?i)^/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/]+/providers/[^/]+/[^/]+/[^/]+') { return 'must be an Azure resource id (/subscriptions/.../resourceGroups/.../providers/...)' } }
        'cidr'              { if ($Value -isnot [string] -or $Value -notmatch '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') { return 'must be an address range, e.g. 10.0.0.0/24' } }
        'email'             { if ($Value -isnot [string] -or $Value -notmatch $email) { return 'must be an e-mail address' } }
        'upnList'           {
            $items = @($Value)
            if (-not $items.Count) { return 'must name at least one address' }
            foreach ($i in $items) { if ($i -isnot [string] -or $i -notmatch $email) { return ('must be a list of e-mail addresses / user names ("{0}" is not one)' -f $i) } }
        }
        default             { return ("has a type this installer does not know ('{0}')" -f $type) }
    }
    $pattern = [string](Get-SIInstallProp $Param 'pattern')
    if ($pattern -and $Value -is [string] -and $Value -notmatch $pattern) { return ('does not have the expected form ({0})' -f $pattern) }
    $null
}

function Test-SIInstallShowIf {
    <# PURE. Is the parameter shown, given the answers? showIf = { key: value, ... } -- every pair must match. #>
    param($Param, [System.Collections.IDictionary]$Values)
    $cond = Get-SIInstallProp $Param 'showIf'
    if ($null -eq $cond) { return $true }
    foreach ($p in (ConvertTo-SIInstallHashtable $cond).GetEnumerator()) {
        $v = if ($Values.Contains($p.Key)) { $Values[$p.Key] } else { $null }
        if ($p.Value -is [bool]) { if ([bool]$v -ne $p.Value) { return $false } }
        elseif ([string]$v -ne [string]$p.Value) { return $false }
    }
    $true
}

function Test-SIInstallConfig {
    <#
        PURE. The wizard's answers against the parameter file: types, required fields, patterns, min / max, options and
        showIf, plus installId. Returns Ok, Errors, Values (every shown parameter, defaults applied for the edition) and
        Explicit (the keys config.json set itself).
        A key the parameter file does not know is refused, and one that LOOKS like a secret is refused with its own
        message: secrets are never wizard answers.
    #>
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Spec, [ValidateSet('community', 'pro')][string]$Edition = 'community')
    $cfg = ConvertTo-SIInstallHashtable $Config
    if ($cfg -isnot [System.Collections.IDictionary]) { return [pscustomobject]@{ Ok = $false; Errors = @('config.json must be a JSON object'); Values = @{}; Explicit = @() } }
    $params = @(Get-SIInstallProp $Spec 'parameters')
    $known = @{}; foreach ($p in $params) { $known[[string](Get-SIInstallProp $p 'key')] = $p }
    $errors = New-Object System.Collections.Generic.List[string]
    # MAIL-1: the older bool 'mail' is still accepted (Invardia's wizard before mailMode): true = smtp, false = none.
    # mailMode, when given, wins; the old key is then dropped.
    if ($cfg.Contains('mail')) {
        $legacy = $cfg['mail']
        $cfg.Remove('mail')
        if (-not ($cfg.Contains('mailMode') -and "$($cfg['mailMode'])".Trim())) { $cfg['mailMode'] = $(if ($legacy -eq $true -or "$legacy" -match '^(?i)true|1$') { 'smtp' } else { 'none' }) }
    }

    # #479: an install from an ENROLLMENT KEY (Install-Invardia -EnrollmentKey). Invardia's bootstrap claimed the key ONCE
    # and hands over the claim's answers like any guided install; it adds the key itself (informational) and, for an MSP
    # managed tenant, the 'managing' block. The key is dropped here at once -- never validated as an answer, never stored,
    # logged or reported: the install never claims with it (the claim's installKey is in config.json). SecurityInsight
    # installs single tenants only: a managed-tenant enrollment is refused with its own message.
    $enrollment = $false
    if ($cfg.Contains('enrollmentKey')) {
        $enrollment = -not [string]::IsNullOrWhiteSpace([string]$cfg['enrollmentKey'])
        $cfg.Remove('enrollmentKey')
    }
    if ($cfg.Contains('managing')) {
        if ($null -ne $cfg['managing'] -and -not ($cfg['managing'] -is [string] -and [string]::IsNullOrWhiteSpace($cfg['managing']))) {
            $errors.Add('managing: this enrollment key is for a tenant managed by another company (MSP). SecurityInsight installs single tenants only -- ask Invardia for a single-tenant enrollment key.')
        }
        $cfg.Remove('managing')
    }

    $id = $cfg['installId']
    if (-not ($id -is [string]) -or $id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { $errors.Add('installId: required, 1-64 letters, digits, dot, dash or underscore') }
    foreach ($k in @($cfg.Keys)) {
        if ($k -eq 'installId' -or $known.ContainsKey($k)) { continue }
        if ($k -match $script:SIInstallSecretKeyPattern) { $errors.Add(("{0}: secrets are never part of config.json -- the installer asks for them in the shell, or they are added to the install's Key Vault afterwards. Remove it." -f $k)) }
        else { $errors.Add(("{0}: not a parameter of this SecurityInsight version" -f $k)) }
    }

    # Defaults first (edition-aware), then the answers; empty strings count as "not answered".
    $values = [ordered]@{}
    $explicit = New-Object System.Collections.Generic.List[string]
    foreach ($p in $params) {
        $key = [string](Get-SIInstallProp $p 'key')
        $byEd = Get-SIInstallProp $p 'defaultByEdition'
        $def = if ($byEd -and $null -ne (Get-SIInstallProp $byEd $Edition)) { Get-SIInstallProp $byEd $Edition } else { Get-SIInstallProp $p 'default' }
        $has = $cfg.Contains($key) -and $null -ne $cfg[$key] -and -not ($cfg[$key] -is [string] -and [string]::IsNullOrWhiteSpace($cfg[$key]))
        if ($has) { $values[$key] = $cfg[$key]; $explicit.Add($key) }
        elseif ($null -ne $def -and -not ($def -is [string] -and $def -eq '')) { $values[$key] = $def }
    }
    # Then what is shown, required, and well-formed. A hidden answer is dropped, never validated.
    foreach ($p in $params) {
        $key = [string](Get-SIInstallProp $p 'key')
        if (-not (Test-SIInstallShowIf -Param $p -Values $values)) { $values.Remove($key); continue }
        $required = [bool](Get-SIInstallProp $p 'required') -or ($script:SIInstallRequiredWhenShown -contains $key -and $null -ne (Get-SIInstallProp $p 'showIf'))
        # #866: a private install names its network (vnetId) OR gives SecurityInsight an address range to make its own (vnetAddressPrefix)
        if ($key -eq 'vnetId' -and $required -and "$($values['vnetAddressPrefix'])".Trim()) { $required = $false }
        if (-not $values.Contains($key)) { if ($required) { $errors.Add(("{0}: required" -f $key)) }; continue }
        $v = $values[$key]
        if ([string](Get-SIInstallProp $p 'type') -eq 'upnList' -and $v -is [string]) { $v = @($v -split '[,;\s]+' | Where-Object { $_ }); $values[$key] = $v }
        $why = Test-SIInstallValueType -Param $p -Value $v
        if ($why) { $errors.Add(("{0}: {1}" -f $key, $why)) }
    }
    [pscustomobject]@{ Ok = ($errors.Count -eq 0); Errors = $errors.ToArray(); Values = $values; Explicit = $explicit.ToArray(); InstallId = [string]$id; Enrollment = $enrollment }
}

# ---------------------------------------------------------------------------------------------------------------
# The plan, the names, the schedules
# ---------------------------------------------------------------------------------------------------------------
function Get-SIInstallChosenOptions {
    <# PURE. The options the answers turn on (#681 privateNetwork, #683 customerManagedKeys) -- none by default. #>
    param([System.Collections.IDictionary]$Values)
    @(@($script:SIInstallOptionStepIds.Values | Select-Object -Unique) | Where-Object { $Values -and $Values.Contains($_) -and [bool]$Values[$_] })
}

function Get-SIInstallStepPlan {
    <# PURE. The step ids, in order. The paid steps appear only for the Pro edition; the database and web app steps in both;
       the steps of an option only when it is in -Options (Get-SIInstallChosenOptions). #>
    param([ValidateSet('community', 'pro')][string]$Edition = 'community', [switch]$PreflightOnly, [string[]]$Options = @())
    # 'installer' is an event id only (#564: a terminating error outside a step), never a step of the plan
    $ids = @($script:SIInstallStepTitles.Keys | Where-Object { $_ -ne 'installer' -and ($Edition -eq 'pro' -or $script:SIInstallProStepIds -notcontains $_) })
    $ids = @($ids | Where-Object { -not $script:SIInstallOptionStepIds.Contains($_) -or @($Options) -contains $script:SIInstallOptionStepIds[$_] })
    if ($PreflightOnly) { $ids = @($ids | Where-Object { $_ -like 'preflight-*' }) }
    foreach ($id in $ids) {
        [pscustomobject]@{ Id = $id; Title = $script:SIInstallStepTitles[$id]; Preflight = ($id -like 'preflight-*') }
    }
}

# The steps that put THIS release's code into Azure: the engine image and jobs, the database tables, the templates, the web
# app and the updater. A resume that downloaded a different release than the run that completed them runs them again.
$script:SIInstallCodeStepIds = @('container-registry-image', 'container-jobs', 'pro-schema', 'pro-templates', 'web-app', 'updater-job')

function Get-SIInstallResumeRedoSteps {
    <#
        PURE. Of the steps an earlier run completed, the ones a resume must run again because that run installed a
        DIFFERENT release (its saved build commit differs from this one; the version only when neither side has a commit).
        Live 2026-10-07 (customer I, Pro): the install was resumed with 3.0.0.202610070203 (c7c7486) after earlier runs with an
        older release; the image and engine-job steps said "Done in an earlier run", so the first pipeline run ran the
        OLDER engines (ce14ce1) -- without the fix for the lost quotes in SI_CFG_SI_Sinks_* ("[LA,Excel]" -> 0/0 sinks),
        no profile reached Log Analytics and asset-correlation failed the run ("every profile table was empty or absent").
    #>
    param([AllowNull()]$Prior, [string]$Version = '', [string]$Commit = '', [AllowEmptyCollection()][string[]]$Completed = @())
    if ($null -eq $Prior) { return @() }
    $pb = $Prior['build']
    $pCommit = if ($pb -is [System.Collections.IDictionary]) { [string]$pb['commit'] } else { '' }
    $pVersion = [string]$Prior['version']
    # A commit on one side only cannot prove the same release: the code steps run again (each is safe to repeat).
    $same = if ($pCommit -or $Commit) { $pCommit.Substring(0, [Math]::Min(7, $pCommit.Length)) -eq $Commit.Substring(0, [Math]::Min(7, $Commit.Length)) }
            else { $pVersion -eq $Version }
    if ($same) { return @() }
    return @($script:SIInstallCodeStepIds | Where-Object { @($Completed) -contains $_ })
}

function Get-SIInstallNames {
    <#
        PURE. The names of what the install creates. A resource group following the pattern (rg-si-<ring>-<edition>-<hosting>)
        names everything inside it the same way; any other resource group gets the default names for the edition. The
        workspace is the wizard's answer when it gave one, or the existing workspace's.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values, [string[]]$Explicit = @(), [ValidateSet('community', 'pro')][string]$Edition = 'community')
    $rg = [string]$Values['resourceGroup']
    # Globally unique names (storage, Key Vault, registry, SQL server) carry the subscription's suffix; an EXISTING install
    # keeps the names it has (Resolve-SIInstallExistingNames, run by preflight-names before anything is checked or created).
    $sub = [string]$Values['subscriptionId']
    # CR5 (#655 step 2): the NEW-install names with SI_Setup_NewInstallNames on (REMOVE-ME, ON by default since 2026-10-18);
    # an existing install keeps today's names either way (Resolve-SIInstallExistingNames)
    $new = Test-SISetupNewInstallNames -Values $Values
    $n = Get-SISetupNamesFromResourceGroup -ResourceGroupName $rg -SubscriptionId $sub -NewNames:$new
    if (-not $n) { $n = Get-SISetupResourceNames -Ring 'prod' -Edition $Edition -Hosting 'ca' -SubscriptionId $sub -NewNames:$new; $n.ResourceGroup = $rg }
    $n.WorkspaceResourceGroup = $rg
    if ([string]$Values['workspaceMode'] -eq 'existing' -and $Values['workspaceId']) {
        $parts = ([string]$Values['workspaceId']).Trim('/') -split '/'
        $n.Workspace = $parts[-1]; $n.WorkspaceResourceGroup = $parts[3]
    } elseif ($Explicit -contains 'workspaceName' -and $Values['workspaceName']) { $n.Workspace = [string]$Values['workspaceName'] }
    $n
}

$script:SIInstallGlobalNameTypes = $script:SISetupGlobalNameTypes
$script:SIInstallGlobalNamePrefixes = $script:SISetupGlobalNamePrefixes

function Select-SIInstallExistingName {
    <# PURE. Select-SISetupExistingName (setup\_shared\SI-SetupNaming.ps1) with one older name; two or more candidates:
       none -- the new name is used, preflight checks it. #>
    param([AllowEmptyCollection()][string[]]$Existing = @(), [string]$Wanted, [string]$Legacy, [string]$Prefix = '^$')
    Select-SISetupExistingName -Existing $Existing -Wanted $Wanted -Legacy @($Legacy) -Prefix $Prefix
}

function Resolve-SIInstallExistingNames {
    <#
        An EXISTING install keeps its names (live 2026-10-07: the subscription suffix must never rename a customer's install, ring 1, ...).
        For each globally unique name: the name an earlier run of THIS install recorded (state facts.names), else the
        resource of that kind already in the install's resource group (Select-SIInstallExistingName), else the new
        suffixed name. The result is recorded in facts.names, so a resume uses the same names even before the group exists.
        A read that fails changes nothing: the new names stay and preflight checks them.
        CR5 (#655 step 2) -- the COMPONENT names (web app, MCP server, updater job, their identities, asset tagging's
        identity, the engine's identity) and the sign-in app's display name: the names an earlier run recorded (facts.names);
        else, when the resource group holds ANY of today's components (an existing install), TODAY's names for all of them
        and today's display name -- an existing install is never renamed, never half-renamed, and never gets a second
        identity or web app next to its own; else, when the group exists but could not be read, today's names too (an
        install setup could not see is treated as existing); else the names of the names table (the CR5 names with
        SI_Setup_NewInstallNames on, today's otherwise). With the setting off both are the same: nothing changes.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names; $sub = [string]$Ctx.Values['subscriptionId']
    $recorded = $Ctx.Facts['names']
    $legacy = Get-SISetupNamesFromResourceGroup -ResourceGroupName $n.ResourceGroup
    if (-not $legacy) { $legacy = Get-SISetupResourceNames -Ring 'prod' -Edition $Ctx.Edition -Hosting 'ca' }
    $inRg = $null; $readFailed = $false
    # the resource group's resources, read once (dot-sourced: sets $inRg / $readFailed here)
    $list = {
        if ($null -ne $inRg) { return }
        $inRg = @(); $rgObj = $null
        try {
            # a new install's group does not exist yet: nothing to keep, and no not-found error to show
            $rgObj = Invoke-SIInstallAz -Ctx $Ctx -Command 'Get-SIAzResourceGroup' -Arguments ([ordered]@{ Name = $n.ResourceGroup; ErrorAction = 'SilentlyContinue' })
            if ($rgObj) {
                $errBefore = $global:Error.Count
                $inRg = @(Invoke-SIInstallAz -Ctx $Ctx -Command 'Get-SIArmResource' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; SubscriptionId = $sub; ErrorAction = 'SilentlyContinue' }) | Where-Object { $_ })
                # a swallowed error on an EMPTY answer: the group's contents are unknown, not empty
                if (-not $inRg.Count -and $global:Error.Count -gt $errBefore) { $readFailed = $true }
            }
        } catch { $inRg = @(); if ($rgObj) { $readFailed = $true } }
    }
    $kept = @()
    foreach ($k in $script:SIInstallGlobalNameTypes.Keys) {
        if ($k -eq 'SqlServer' -and -not ($Ctx.Data -or $Ctx.Pro)) { continue }
        $rec = [string](Get-SIInstallProp $recorded $k)
        if ($rec) { if ($rec -ne $n[$k]) { $kept += $rec }; $n[$k] = $rec; continue }
        . $list
        $type = $script:SIInstallGlobalNameTypes[$k]
        $names = @($inRg | Where-Object { [string](Get-SIInstallProp $_ 'ResourceType') -eq $type -or [string](Get-SIInstallProp $_ 'Type') -eq $type } | ForEach-Object { [string](Get-SIInstallProp $_ 'Name') })
        $pick = Select-SIInstallExistingName -Existing $names -Wanted $n[$k] -Legacy $legacy[$k] -Prefix $script:SIInstallGlobalNamePrefixes[$k]
        if ($pick) { if ($pick -ne $n[$k]) { $kept += $pick }; $n[$k] = $pick }
    }
    # #681: an install moved onto private networking (setup\Set-SIPrivateNetworking.ps1) runs in cae-si-private: every later
    # setup run keeps using that environment (only when the install asks for private networking -- nothing is read otherwise)
    if ([bool]$Ctx.Values['privateNetwork'] -and (Get-Command -Name Get-SIPrivateNetworkNames -ErrorAction SilentlyContinue)) {
        . $list
        $pv = (Get-SIPrivateNetworkNames).PrivateEnvironment
        if (@($inRg | Where-Object { ([string](Get-SIInstallProp $_ 'ResourceType') -eq 'Microsoft.App/managedEnvironments' -or [string](Get-SIInstallProp $_ 'Type') -eq 'Microsoft.App/managedEnvironments') -and [string](Get-SIInstallProp $_ 'Name') -eq $pv }).Count) {
            if ($n['ContainerEnv'] -ne $pv) { $kept += $pv }; $n['ContainerEnv'] = $pv
        }
    }
    # CR5 step 2: the component names. Only when they differ from today's (SI_Setup_NewInstallNames on) is there anything to
    # decide -- with the setting off this block changes nothing and reads nothing.
    $keys = @($script:SIInstallComponentNameTypes.Keys)
    $recComp = @($keys | Where-Object { [string](Get-SIInstallProp $recorded $_) })
    if ($recComp.Count) {
        foreach ($k in $keys) { $rec = [string](Get-SIInstallProp $recorded $k); if ($rec) { if ($rec -ne $n[$k]) { $kept += $rec }; $n[$k] = $rec } }
        foreach ($dk in 'WebAppDisplayName', 'SqlAdminGroupDisplayName', 'SqlAdminGroupName') { $rd = [string](Get-SIInstallProp $recorded $dk); if ($rd) { $n[$dk] = $rd } }
    }
    elseif (@($keys | Where-Object { [string]$n[$_] -cne [string]$legacy[$_] }).Count) {
        . $list
        $existing = Test-SIInstallHasTodayComponents -InRg $inRg -Legacy $legacy
        if ($existing -or $readFailed) {
            foreach ($k in $keys) { if ([string]$n[$k] -cne [string]$legacy[$k]) { $kept += [string]$legacy[$k]; $n[$k] = [string]$legacy[$k] } }
            # the display names too: an existing install's directory objects are renamed by the update (SI-DisplayNames.ps1),
            # never by a setup run -- a setup run finds them under either name and leaves the name they have
            foreach ($dk in 'WebAppDisplayName', 'SqlAdminGroupDisplayName', 'SqlAdminGroupName') { $n[$dk] = [string]$legacy[$dk] }
        }
    }
    # the kept names, one per pipeline item (callers wrap the call in @())
    @($kept | Select-Object -Unique)
}

# CR5 step 2 (#655): the components inside the install's resource group, and the Azure type each one is
$script:SIInstallComponentNameTypes = [ordered]@{
    ManagedIdentity = 'Microsoft.ManagedIdentity/userAssignedIdentities'
    WebApp          = 'Microsoft.App/containerApps'
    McpApp          = 'Microsoft.App/containerApps'
    UpdaterJob      = 'Microsoft.App/jobs'
    WebIdentity     = 'Microsoft.ManagedIdentity/userAssignedIdentities'
    McpIdentity     = 'Microsoft.ManagedIdentity/userAssignedIdentities'
    UpdaterIdentity = 'Microsoft.ManagedIdentity/userAssignedIdentities'
    TaggingIdentity = 'Microsoft.ManagedIdentity/userAssignedIdentities'
}

function Test-SIInstallHasTodayComponents {
    <# PURE. Does the resource group (-InRg: its resources, Name + ResourceType / Type) hold any component under TODAY's name
       (-Legacy: today's names table)? Then it is an existing install, and it keeps today's names. The MCP server and the
       updater job carry the same name in both schemes, so they count too. #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$InRg = @(), [Parameter(Mandatory)][System.Collections.IDictionary]$Legacy)
    foreach ($k in $script:SIInstallComponentNameTypes.Keys) {
        $type = $script:SIInstallComponentNameTypes[$k]; $want = [string]$Legacy[$k]
        if (-not $want) { continue }
        $hit = @(@($InRg) | Where-Object { $_ -and ([string](Get-SIInstallProp $_ 'ResourceType') -eq $type -or [string](Get-SIInstallProp $_ 'Type') -eq $type) -and [string](Get-SIInstallProp $_ 'Name') -eq $want })
        if ($hit.Count) { return $true }
    }
    $false
}

function Save-SIInstallNames {
    <# Records the install's globally unique names in its state (facts.names) -- only once preflight found them free or
       already the install's, so a name that was taken is never pinned for the next run. CR5 step 2: the component names and
       the sign-in app's display name too, so a resume never switches an install between today's and the new names. #>
    param([Parameter(Mandatory)]$Ctx)
    $rec = [ordered]@{}
    foreach ($k in $script:SIInstallGlobalNameTypes.Keys) { if ($k -ne 'SqlServer' -or ($Ctx.Data -or $Ctx.Pro)) { $rec[$k] = [string]$Ctx.Names[$k] } }
    foreach ($k in @($script:SIInstallComponentNameTypes.Keys) + 'WebAppDisplayName' + 'SqlAdminGroupDisplayName' + 'SqlAdminGroupName') { if ([string]$Ctx.Names[$k]) { $rec[$k] = [string]$Ctx.Names[$k] } }
    $Ctx.Facts['names'] = $rec
}

function Get-SIInstallNameTakenText {
    <#
        The reason a free-looking global name is not free: used in ANOTHER resource group of this subscription, or (not
        found here at all) by another subscription or tenant -- names of this kind are unique across all of Azure.
    #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$What, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Type)
    $here = $null
    try { $here = @(Invoke-SIInstallAz -Ctx $Ctx -Command 'Get-SIArmResource' -Arguments ([ordered]@{ ResourceType = $Type; Name = $Name; SubscriptionId = [string]$Ctx.Values['subscriptionId']; ErrorAction = 'SilentlyContinue' }) | Where-Object { $_ }) } catch { }
    if ($here -and @($here).Count) {
        return ('the {0} name {1} is used by the resource group {2} in this subscription' -f $What, $Name, [string](Get-SIInstallProp @($here)[0] 'ResourceGroupName'))
    }
    'the {0} name {1} is taken by another Azure subscription or tenant ({0} names are unique across all of Azure)' -f $What, $Name
}

function Get-SIInstallReaderScopes {
    <# PURE. What SecurityInsight reads in Azure, as role-assignment scopes. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)
    switch ([string]$Values['collectionScope']) {
        'managementGroup' { @('/providers/Microsoft.Management/managementGroups/{0}' -f $Values['managementGroupId']) }
        'tenantRoot'      { @('/providers/Microsoft.Management/managementGroups/{0}' -f $Values['tenantId']) }
        default           { @('/subscriptions/{0}' -f $Values['subscriptionId']) }
    }
}

function Get-SIInstallSchedules {
    <#
        PURE. The container jobs' schedules for a daily start hour (UTC). Bootstrap's defaults start at 04:00; every job
        moves by the same number of hours, so the run ORDER (tier classifier -> profilers -> publicip -> correlation ->
        Risk Analysis -> trend -> close-loop -> data sync) is kept.
    #>
    param([ValidateRange(0, 23)][int]$RunHourUtc = 4)
    $shift = $RunHourUtc - 4
    $base = [ordered]@{
        ScheduleEndpoint = '0 4 * * *'; ScheduleIdentity = '30 4 * * *'; ScheduleAzure = '0 5 * * *'; ScheduleSchemaDiscovery = '0 3 * * 0'
        ScheduleRiskAnalysis = '0 6 * * *'; ScheduleRiskAnalysisDetailed = '0 8 * * *'; ScheduleCorrelation = '30 5 * * *'
        ScheduleAssetProperties = '45 5 * * *'; ScheduleCmdb = '0 7 * * *'; ScheduleTrend = '0 9 * * *'
        ScheduleVulnerabilities = '0 10 * * *'; ScheduleDataSync = '30 10 * * *'; ScheduleAssetTagging = '50 5 * * *'
        ScheduleClassifier = '0 1 * * *'; SchedulePublicIp = '15 5 * * *'
    }
    $out = [ordered]@{}
    foreach ($k in $base.Keys) {
        $f = $base[$k] -split ' '
        $f[1] = [string]((([int]$f[1] + $shift) % 24 + 24) % 24)
        $out[$k] = $f -join ' '
    }
    $out
}

function Get-SIInstallJobName {
    <# PURE. Bootstrap's job name for an engine (Container Apps job names are at most 32 characters). #>
    param([Parameter(Mandatory)][string]$Engine)
    # #715: the ServiceNow vulnerability connector's job is caj-si-asset-vulns-servicenow (Get-SIBootstrapJobName)
    $short = switch ($Engine) { 'privilege-tier-classifier' { 'ptc' } 'schema-discovery' { 'schema' } 'templates-publish' { 'templates' } 'asset-vulnerabilities-servicenow' { 'asset-vulns-servicenow' } default { $Engine } }
    'caj-si-{0}' -f $short
}

function Get-SIInstallEngineJobs {
    <#
        PURE. The jobs that carry one engine in the install, as Bootstrap made them: its scheduled job caj-si-<engine>, or
        -- with queue scaling (KEDA by design, #475) -- its producer AND worker. Returns @{ Present; Jobs; Start } with
        Start = the job to start for a run (the producer when the engine runs in parts); Present = $false when neither
        layout is complete.
    #>
    param([Parameter(Mandatory)][string]$Engine, [AllowEmptyCollection()][string[]]$Have = @())
    $j = Get-SIInstallJobName -Engine $Engine
    $p = "$j-producer"; $w = "$j-worker"
    if ($Have -contains $p -and $Have -contains $w) { return [pscustomobject]@{ Present = $true; Jobs = @($p, $w); Start = $p } }
    [pscustomobject]@{ Present = [bool]($Have -contains $j); Jobs = @($j); Start = $j }
}

function Test-SIInstallScopeInside {
    <# PURE. Is a role-assignment scope inside the install's resource group? #>
    param([string]$Scope, [string]$SubscriptionId, [string]$ResourceGroup)
    $rgId = ('/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup).ToLowerInvariant()
    $s = "$Scope".TrimEnd('/').ToLowerInvariant()
    ($s -eq $rgId) -or $s.StartsWith($rgId + '/')
}

function Read-SIInstallGrantReport {
    <#
        PURE. Reads Grant-SIIdentity's report into grants: Azure roles ("[state ] Role on /scope") and API permissions
        ("[state ] Permission (Resource)"), plus the ready-to-run tasks it prints for what it could not grant.
        The line formats are Grant-SIIdentity's own; SIv3-GuidedInstall.Tests.ps1 pins them so they cannot drift apart.
    #>
    param([AllowNull()][string[]]$Lines, [string]$SubscriptionId, [string]$ResourceGroup)
    $roles = New-Object System.Collections.Generic.List[object]
    $perms = New-Object System.Collections.Generic.List[object]
    $tasks = New-Object System.Collections.Generic.List[string]
    $permTasks = New-Object System.Collections.Generic.List[string]
    foreach ($raw in @($Lines)) {
        $l = "$raw"
        if ($l -match '^\s*\[(present|granted|FAILED|MISSING)\s*\]\s+(.+?)\s+on\s+(/\S+)\s*$') {
            $roles.Add([pscustomobject]@{ State = $Matches[1]; Role = $Matches[2].Trim(); Scope = $Matches[3]
                Inside = (Test-SIInstallScopeInside -Scope $Matches[3] -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup) })
        } elseif ($l -match '^\s*\[(present|granted|FAILED|MISSING|UNKNOWN|ABSENT)\s*\]\s+(\S+)\s+\(([^)]+)\)(\s+--.*)?\s*$') {
            $perms.Add([pscustomobject]@{ State = $Matches[1]; Permission = $Matches[2]; Resource = $Matches[3].Trim() })
        } elseif ($l -match '^\s*(# Azure role ".+?" on "[^"]+".*)$' -or $l -match '^\s*(az role assignment create .+)$') {
            # #564: the portal-path line (a release before it printed an az command; both are read)
            $tasks.Add($Matches[1].Trim())
        } elseif ($l -match '^\s*(# API permission .+)$') {
            $permTasks.Add($Matches[1].Trim())
        }
    }
    $missing = { param($x) $x.State -in 'FAILED', 'MISSING', 'UNKNOWN' }
    $insideTasks = @(); $outsideTasks = @()
    foreach ($t in $tasks) {
        $scope = if ($t -match '^# Azure role ".+?" on "([^"]+)"') { $Matches[1] } elseif ($t -match '--scope\s+"([^"]+)"') { $Matches[1] } else { '' }
        if (Test-SIInstallScopeInside -Scope $scope -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup) { $insideTasks += $t } else { $outsideTasks += $t }
    }
    [pscustomobject]@{
        Roles = $roles.ToArray(); Permissions = $perms.ToArray()
        InsideMissing  = @($roles | Where-Object { $_.Inside -and (& $missing $_) })
        OutsideMissing = @($roles | Where-Object { -not $_.Inside -and (& $missing $_) })
        PermissionsMissing = @($perms | Where-Object { & $missing $_ })
        InsideTasks = $insideTasks; OutsideTasks = $outsideTasks; PermissionTasks = $permTasks.ToArray()
    }
}

function Get-SIInstallTaskLines {
    <# PURE. The ready-to-run lines a product script prints for "someone with the rights": az ..., # ..., -- ..., .\setup\... #>
    param([AllowNull()][string[]]$Lines)
    @($Lines | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match '^(az |# |-- |\.[\\/]setup[\\/]|CREATE USER |ALTER ROLE )' })
}

# ---------------------------------------------------------------------------------------------------------------
# The config file the engines read (config\SecurityInsight.custom.ps1): the guided-install block
# ---------------------------------------------------------------------------------------------------------------
function ConvertTo-SIInstallPsLiteral {
    <# PURE. A value as PowerShell source: single-quoted text (quotes doubled, as Write-SICustomConfig does), $true/$false, numbers, @(...). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return "''" }
    if ($Value -is [bool]) { if ($Value) { return '$true' } else { return '$false' } }
    if ($Value -is [int] -or $Value -is [long]) { return [string]$Value }
    if ($Value -isnot [string] -and $Value -is [System.Collections.IEnumerable]) { return ('@({0})' -f ((@($Value) | ForEach-Object { ConvertTo-SIInstallPsLiteral $_ }) -join ',')) }
    $s = [string]$Value
    foreach ($q in @([char]0x27, [char]0x2018, [char]0x2019, [char]0x201A, [char]0x201B)) { $s = $s.Replace([string]$q, [string]$q + [string]$q) }
    "'" + $s + "'"
}

function Get-SIInstallConfigBlock {
    <# PURE. The marked block of settings the guided install owns in the config file. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Settings)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('# >>> SecurityInsight guided install >>>  (written by setup\Install-SecurityInsight.ps1; re-running the install rewrites this block)')
    foreach ($k in $Settings.Keys) { $null = $sb.AppendLine(('$global:{0} = {1}' -f $k, (ConvertTo-SIInstallPsLiteral $Settings[$k]))) }
    $null = $sb.Append('# <<< SecurityInsight guided install <<<')
    $sb.ToString()
}

function Set-SIInstallConfigBlock {
    <# Writes (or replaces) the guided-install block at the end of the config file. Everything else in the file is kept. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][System.Collections.IDictionary]$Settings)
    $block = Get-SIInstallConfigBlock -Settings $Settings
    $text = if (Test-Path -LiteralPath $Path) { [IO.File]::ReadAllText($Path) } else { '' }
    $re = '(?ms)^# >>> SecurityInsight guided install >>>.*?^# <<< SecurityInsight guided install <<<[^\r\n]*'
    if ([regex]::IsMatch($text, $re)) { $text = [regex]::Replace($text, $re, { param($m) $block }) }
    else { $text = $text.TrimEnd() + $(if ($text.Trim()) { [Environment]::NewLine + [Environment]::NewLine } else { '' }) + $block + [Environment]::NewLine }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    # UTF-8 with a BOM, like Write-SICustomConfig: Windows PowerShell 5.1 reads a file without one in the ANSI code page.
    [IO.File]::WriteAllText($Path, $text, (New-Object System.Text.UTF8Encoding($true)))
}

# ---------------------------------------------------------------------------------------------------------------
# Seams: every call that leaves this process
# ---------------------------------------------------------------------------------------------------------------
function Get-SIInstallDefaultSeams {
    <# The real implementations. Tests replace any of them; Invoke-SIGuidedInstall merges what it is given over these. #>
    @{
        # Azure over plain REST: a SecurityInsight REST function by name. -ErrorAction is honoured for every one of them:
        # a plain function (no common parameters) gets 'SilentlyContinue' as "on an error, return nothing" -- the error is
        # still recorded in $Error, so Invoke-SIInstallAz shows and logs it.
        Az            = {
            param([string]$Command, [System.Collections.IDictionary]$Arguments)
            $a = [ordered]@{}
            if ($Arguments) { foreach ($k in $Arguments.Keys) { $a[$k] = $Arguments[$k] } }
            $fn = Get-Command -Name $Command -ErrorAction Stop
            $ea = $null
            if ($a.Contains('ErrorAction') -and -not $fn.CmdletBinding) { $ea = [string]$a['ErrorAction']; $a.Remove('ErrorAction') }
            if ($ea -eq 'SilentlyContinue' -or $ea -eq 'Ignore') { try { & $Command @a } catch { $null } }
            else { & $Command @a }
        }
        Token         = {
            param([string]$Resource, [bool]$Fresh)
            # the signed-in person's token for that resource (setup's own sign-in, in memory); -Fresh asks for a new one
            $t = Get-SIAzureToken -Resource $Resource -ForceRefresh:$Fresh
            if ($t -is [System.Security.SecureString]) { $t = (New-Object System.Net.NetworkCredential('', $t)).Password }
            [string]$t
        }
        Graph         = {
            param([string]$Method, [string]$Uri, $Body, [string]$Token)
            $a = @{ Method = $Method; Uri = $Uri; Headers = @{ Authorization = 'Bearer ' + $Token }; ErrorAction = 'Stop' }
            # a /$count read (#507: the tenant's size for the database tier) needs Graph's advanced query header
            if ($Uri -match '/\$count(\?|$)') { $a.Headers['ConsistencyLevel'] = 'eventual' }
            if ($null -ne $Body) { $a.ContentType = 'application/json'; $a.Body = ($Body | ConvertTo-Json -Depth 6 -Compress) }
            # #548: through the support recorder in an Invardia support session (Invoke-SIRestMethod), else Invoke-RestMethod
            Invoke-SIRestMethod @a
        }
        Sql           = {
            param([string]$Server, [string]$Database, [string]$Query, [string]$Mode, [string]$Token)
            $cn = New-Object System.Data.SqlClient.SqlConnection(('Server=tcp:{0},1433;Database={1};Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;' -f $Server, $Database))
            $cn.AccessToken = $Token
            try {
                $cn.Open(); $c = $cn.CreateCommand(); $c.CommandText = $Query; $c.CommandTimeout = 0
                if ($Mode -eq 'nonquery') { [void]$c.ExecuteNonQuery() } else { $c.ExecuteScalar() }
            } finally { $cn.Dispose() }
        }
        Script        = {
            param([string]$Path, [System.Collections.IDictionary]$Arguments)
            if (-not $Arguments) { $Arguments = @{} }
            $text = New-Object System.Collections.Generic.List[string]
            $objects = New-Object System.Collections.Generic.List[object]
            $err = $null
            $global:LASTEXITCODE = 0
            try {
                & $Path @Arguments *>&1 | ForEach-Object {
                    $item = $_; $line = $null
                    if ($item -is [System.Management.Automation.InformationRecord]) { $line = [string]$item.MessageData }
                    elseif ($item -is [System.Management.Automation.WarningRecord]) { $line = 'WARNING: ' + $item.Message }
                    elseif ($item -is [System.Management.Automation.ErrorRecord]) { $line = 'ERROR: ' + $item.Exception.Message }
                    elseif ($item -is [System.Management.Automation.VerboseRecord] -or $item -is [System.Management.Automation.DebugRecord]) { return }
                    elseif ($item -is [string]) { $line = $item }
                    else { $objects.Add($item) }
                    if ($null -ne $line) {
                        foreach ($l in ($line -split "`r?`n")) {
                            $text.Add($l); Write-Host ('      ' + $l)
                            # #564: a product script's sub-step header becomes a 'started' event of the running step
                            if (Test-SIInstallSubStepLine -Line $l) { Send-SIInstallProgress -Message $l }
                        }
                    }
                }
            } catch { $err = $_.Exception.Message }
            [pscustomobject]@{ ExitCode = $(if ($err) { 1 } else { [int]$global:LASTEXITCODE }); Text = $text.ToArray(); Objects = $objects.ToArray(); Error = $err }
        }
        # #564: this machine's public IPv4 address (the install's SQL firewall rule AllowSetupHost); '' when unknown
        PublicIp      = {
            foreach ($u in 'https://api.ipify.org', 'https://ifconfig.me/ip') {
                try {
                    $r = Invoke-SIAzRestHttp -Method GET -Uri $u -Headers @{ Accept = 'text/plain' } -TimeoutSec 15
                    $t = ([string]$r.Content).Trim()
                    if ([int]$r.StatusCode -eq 200 -and $t -match '^\d{1,3}(\.\d{1,3}){3}$') { return $t }
                } catch { }
            }
            ''
        }
        ReadSecret    = { param([string]$Prompt) Read-Host -Prompt $Prompt -AsSecureString }
        IsInteractive = { try { [Environment]::UserInteractive -and -not [Console]::IsInputRedirected } catch { $false } }
        Sleep         = { param([int]$Seconds) Start-Sleep -Seconds $Seconds }
        Now           = { [datetime]::UtcNow }
        Print         = { param([string]$Text, [string]$Color) if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text } }
    }
}

function Invoke-SIInstallAz {
    <# An Az cmdlet through the seam. An error the call was told to swallow (-ErrorAction SilentlyContinue) is still SHOWN
       and logged (operator 2026-10-04: "let me get detailed error messages instead of stealing them"); the result is
       unchanged, so a check that expects "not found" still works. #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Command, [System.Collections.IDictionary]$Arguments = @{})
    $before = $global:Error.Count
    try { $out = & $Ctx.Seams.Az $Command $Arguments }
    catch {
        # a step may catch this itself and carry on -- the reason is shown and logged here first, then rethrown as before
        Write-SIInstallErrorDetail -Ctx $Ctx -Record $_ -Context ('{0} (failed)' -f $Command) -Quiet
        throw
    }
    $new = $global:Error.Count - $before
    if ($new -gt 0) {
        foreach ($er in @($global:Error[0..([Math]::Min($new, 5) - 1)])) {
            # finding H: a create-if-missing probe ("does it exist yet?") EXPECTS not-found -- one info line, no error block
            if ($er -is [System.Management.Automation.ErrorRecord] -and [string]$er.FullyQualifiedErrorId -like 'SIAzRestNotFound*') {
                Write-SIInstallConsole -Ctx $Ctx -Text ('      [INFO] {0}' -f $er.Exception.Message) -Color 'DarkGray'
                continue
            }
            Write-SIInstallErrorDetail -Ctx $Ctx -Record $er -Context ('{0} (continued)' -f $Command) -Quiet
        }
    }
    $out
}

function Get-SIInstallErrorText {
    <# PURE-ish. Everything an error says, as lines: the message chain, Azure's own error body (code, message, and for a
       policy denial the policy assignment / definition names), the command and the script position. Redacted. #>
    param([AllowNull()]$Record, [string]$Context)
    $lines = New-Object System.Collections.Generic.List[string]
    if ($Context) { $lines.Add("context  : $Context") }
    $ex = if ($Record -is [System.Management.Automation.ErrorRecord]) { $Record.Exception } elseif ($Record -is [Exception]) { $Record } else { $null }
    $depth = 0
    while ($ex -and $depth -lt 6) {
        $lines.Add(('{0}: {1}' -f $(if ($depth) { 'inner    ' } else { 'error    ' }), ('[{0}] {1}' -f $ex.GetType().Name, $ex.Message)))
        $ex = $ex.InnerException; $depth++
    }
    if ($Record -is [System.Management.Automation.ErrorRecord]) {
        $body = if ($Record.ErrorDetails) { [string]$Record.ErrorDetails.Message } else { '' }
        if ($body) {
            $json = $null; try { $json = $body | ConvertFrom-Json -ErrorAction Stop } catch { }
            $e = if ($json -and $json.PSObject.Properties['error']) { $json.error } else { $json }
            if ($e -and $e.PSObject.Properties['code']) {
                $lines.Add(('azure    : {0} -- {1}' -f $e.code, $e.message))
                foreach ($ai in @($e.additionalInfo)) {
                    if ($ai -and $ai.PSObject.Properties['info'] -and $ai.info) {
                        $i = $ai.info
                        $pn = @('policyAssignmentDisplayName', 'policyAssignmentName', 'policyDefinitionDisplayName', 'policyDefinitionName', 'policySetDefinitionDisplayName', 'policyAssignmentScope') |
                            Where-Object { $i.PSObject.Properties[$_] -and $i.$_ } | ForEach-Object { '{0}={1}' -f $_, $i.$_ }
                        if ($pn) { $lines.Add('policy   : ' + ($pn -join '; ')) }
                    }
                }
                foreach ($d in @($e.details)) { if ($d -and $d.PSObject.Properties['code']) { $lines.Add(('detail   : {0} -- {1}' -f $d.code, $d.message)) } }
            } else { $lines.Add('body     : ' + ($body -replace '\s+', ' ')) }
        }
        if ($Record.InvocationInfo -and $Record.InvocationInfo.MyCommand) { $lines.Add('command  : ' + $Record.InvocationInfo.MyCommand.Name) }
        if ($Record.InvocationInfo -and $Record.InvocationInfo.ScriptName) {
            $lines.Add(('at       : {0}:{1}' -f (Split-Path -Leaf $Record.InvocationInfo.ScriptName), $Record.InvocationInfo.ScriptLineNumber))
        }
        if ($Record.ScriptStackTrace) { foreach ($s in @(($Record.ScriptStackTrace -split "`n") | Select-Object -First 6)) { $lines.Add('stack    : ' + $s.Trim()) } }
    }
    @($lines | ForEach-Object { Protect-SIInstallText $_ })
}

function Write-SIInstallErrorDetail {
    <# Shows an error in full on the console (red for a failed step, grey for a swallowed call with -Quiet) and appends it
       to install-errors.log in the state folder. Never throws. #>
    param([Parameter(Mandatory)]$Ctx, [AllowNull()]$Record, [string]$Context, [switch]$Quiet)
    try {
        $text = @(Get-SIInstallErrorText -Record $Record -Context $Context)
        if (-not $text.Count) { return }
        foreach ($l in $text) { Write-SIInstallConsole -Ctx $Ctx -Text ('            ' + $l) -Color $(if ($Quiet) { 'DarkGray' } else { 'Red' }) }
        if ($Ctx.StateDirectory) {
            if (-not (Test-Path -LiteralPath $Ctx.StateDirectory)) { New-Item -ItemType Directory -Force -Path $Ctx.StateDirectory | Out-Null }
            $stamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
            Add-Content -LiteralPath (Join-Path $Ctx.StateDirectory 'install-errors.log') -Value (@("--- $stamp") + $text) -Encoding UTF8
        }
    } catch { }
}

function Invoke-SIInstallPrivateDataGate {
    <#
        #866 (owner 2026-10-21: "we will not allow fw option or exceptions, then we must wait until you are ready"): a data
        resource of a private install is CREATED private; RIGHT AFTER it, its private endpoint(s) and zone(s) are made, and
        its names must resolve to their private addresses FROM THIS MACHINE before anything reads or writes it. When they
        do not yet (the machine asks the hub's DNS resolver), the install STOPS with one customer action -- the exact A
        records for the hub -- and the install command continues from this step (it makes nothing twice and checks again).
        Returns @{ Message; Lines } when it passes; throws the install failure when it does not.
          $Ctx.Seams.Resolve { param([string]$Name) } -> addresses (optional; default the system resolver -- tests pass a fake)
    #>
    param([Parameter(Mandatory)]$Ctx, [string]$KeyVaultId = '', [string]$StorageAccountId = '', [string]$SqlServerId = '', [string]$What = 'the resource')
    $v = $Ctx.Values; $n = $Ctx.Names
    $rgId = '/subscriptions/{0}/resourceGroups/{1}' -f [string]$v['subscriptionId'], $n.ResourceGroup
    $target = Get-SIInstallPrivateNetworkTarget -Values $v -ResourceGroupId $rgId
    $loc = if ([string]$Ctx.Facts['vnetLocation']) { [string]$Ctx.Facts['vnetLocation'] } else { [string]$v['location'] }
    $a = [ordered]@{ Target = $target; Location = $loc; EndpointsSubnetId = [string]$Ctx.Facts['endpointsSubnetId']; KeyVaultId = $KeyVaultId; StorageAccountId = $StorageAccountId; SqlServerId = $SqlServerId }
    if ($Ctx.Seams -and $Ctx.Seams.Contains('Resolve') -and $Ctx.Seams['Resolve'] -is [scriptblock]) { $a['Resolve'] = $Ctx.Seams['Resolve'] }
    $r = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Invoke-SIPrivateNetworkDataEndpoints' -Arguments $a
    if (-not $r.Ok) {
        throw (New-SIInstallFailure -Message ('Private network: the private endpoints of {0} could not be made: {1}. Nothing reads or writes it until they are there.' -f $What, $r.Error) `
            -ActionText 'Fix the cause (the line above), then run the install command again: it continues from this step.' -Command $Ctx.ResumeCommand)
    }
    $lines = @($r.Value.Lines)
    if (-not $r.Value.EndpointsOk) {
        throw (New-SIInstallFailure -Message ('Private network: the private endpoints of {0} are not all in place -- {1}' -f $What, (@($lines | Select-Object -First 12) -join '; ')) `
            -ActionText 'Run the install command again: it continues from this step (what is there is kept).' -Command $Ctx.ResumeCommand -Detail @{ lines = $lines; handOff = @($r.Value.HandOff) })
    }
    if (-not $r.Value.Gate.Ok) {
        foreach ($l in $lines) { Write-SIInstallConsole -Ctx $Ctx -Text $l -Color Yellow }
        $recs = @($r.Value.Gate.Records | ForEach-Object { '{0}  A  {1}   (zone {2}, name {3})' -f $_.Fqdn, $_.Ip, $_.Zone, $_.Name })
        throw (New-SIInstallFailure -Message ('Private network: {0} {1} created private, with private endpoints -- but this machine does not resolve their names to the private addresses yet ({2}). The install waits here: nothing reads or writes them before it can.' -f $What, $(if ($What -like '* and *') { 'are' } else { 'is' }), (@($r.Value.Gate.Failed) -join ', ')) `
            -ActionText ('Ask your network team to add these DNS records where your network resolves (your hub''s private DNS zones of these names, or your DNS resolver), then run the install command again: it checks again from this machine and continues. ' + ($recs -join '; ')) `
            -Command $Ctx.ResumeCommand -Detail @{ lines = $lines; records = $recs })
    }
    @{ Message = ('Private network: {0} reached through private endpoints only (created with no public access); this machine resolves {1} to the private addresses.' -f $What, (@($r.Value.Gate.Names) -join ', ')); Lines = $lines }
}

function Invoke-SIInstallArmTry {
    <# #521: an ARM call through the Az seam that may fail without failing the step (a probe, a best-effort start): the
       error is shown and logged by Invoke-SIInstallAz; here it becomes @{ Ok = $false; Error = <message> }. Every call
       is pinned to the install's subscription. Returns @{ Ok; Value; Error }. #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Command, [System.Collections.IDictionary]$Arguments = @{})
    $a = [ordered]@{}; foreach ($k in $Arguments.Keys) { $a[$k] = $Arguments[$k] }
    # ... when the function TAKES a subscription: one that is given a full scope instead (Test-SIRoleAssignmentPresent) has
    # no such parameter, and handing it one made the call fail before it ran -- the end-of-install check of the updater's
    # right then never happened (the rehearsal of 2026-10-12). A command that is not there (a test's seam) gets it as before.
    $takesSub = $true
    $cmdInfo = Get-Command -Name $Command -ErrorAction SilentlyContinue
    if ($cmdInfo -and $cmdInfo.Parameters -and -not $cmdInfo.Parameters.ContainsKey('SubscriptionId')) { $takesSub = $false }
    if ($takesSub -and -not $a.Contains('SubscriptionId') -and $Ctx.Values['subscriptionId']) { $a['SubscriptionId'] = [string]$Ctx.Values['subscriptionId'] }
    try { $v = Invoke-SIInstallAz -Ctx $Ctx -Command $Command -Arguments $a; return [pscustomobject]@{ Ok = $true; Value = $v; Error = '' } }
    catch { return [pscustomobject]@{ Ok = $false; Value = $null; Error = [string]$_.Exception.Message } }
}

function Get-SIInstallJobNames {
    <# The names of the Container Apps jobs in -ResourceGroup (Get-SIContainerAppJobList over ARM); none readable = @(). #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$ResourceGroup)
    $r = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SIContainerAppJobList' -Arguments ([ordered]@{ ResourceGroupName = $ResourceGroup })
    # unrolled (callers take @( ... )): a leading comma would hand them ONE nested array, and -contains would never match
    @($r.Value) | Where-Object { $_ } | ForEach-Object { [string](Get-SIInstallProp $_ 'name') } | Where-Object { $_ }
}

function Invoke-SIInstallGraph {
    param([Parameter(Mandatory)]$Ctx, [string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body)
    # the token is asked for on EVERY call (the sign-in keeps it until shortly before it expires): one kept for the whole
    # run went stale on an install that took hours, and every later directory call was refused
    & $Ctx.Seams.Graph $Method $Uri $Body ([string](& $Ctx.Seams.Token 'https://graph.microsoft.com'))
}

function Invoke-SIInstallSql {
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][string]$Query, [ValidateSet('scalar', 'nonquery')][string]$Mode = 'scalar')
    # #564: this machine may reach the database (the install-owned AllowSetupHost rule, at the CURRENT public address)
    Open-SIInstallSqlHostWindow -Ctx $Ctx
    # A firewall rule set a moment ago, or a server whose administrator just changed, refuses the sign-in for a short
    # while: ONLY "Login failed" / 18456 / 40615 is waited for (6 x 20 s, a new token each time); anything else -- a
    # wrong statement, a database that is not there -- is thrown at once.
    $out = $null
    for ($try = 0; ; $try++) {
        $tok = [string](& $Ctx.Seams.Token 'https://database.windows.net/' ($try -gt 0))
        try { $out = & $Ctx.Seams.Sql $Server $Database $Query $Mode $tok; break }
        catch {
            if ($try -ge 6 -or -not (Test-SISqlNotYetAnswer -Text ([string]$_.Exception.Message))) { throw }
            Write-SIInstallConsole -Ctx $Ctx -Text ('      the database {0} does not accept this sign-in yet -- waiting 20 s and trying again ({1}/6)' -f $Database, ($try + 1)) -Color 'DarkGray'
            & $Ctx.Seams.Sleep 20
        }
    }
    $out
}

$script:SIInstallSqlHostRule = 'AllowSetupHost'

function Get-SIInstallSqlHostPortalText {
    <# PURE apart from reading $Ctx. Where a person finds the install's SQL firewall rule in the Azure portal. #>
    param([Parameter(Mandatory)]$Ctx)
    'Azure portal: SQL servers > {0} > Security > Networking > Firewall rules > {1}' -f [string]$Ctx.Names.SqlServer, $script:SIInstallSqlHostRule
}

function Open-SIInstallSqlHostWindow {
    <#
        #564 (PIM's install at customer I, 2026-10-10): the Pro database is reached FROM THIS MACHINE (the schema, the contained users,
        the templates, the settings, the web app's and the updater's grants). The install OWNS one firewall rule for it,
        AllowSetupHost, set to this machine's CURRENT public address -- on a resume from another network it moves there --
        and read back. Once per run (cached); the end of the run closes it (Close-SIInstallSqlHostWindow). Never throws: a
        machine whose address cannot be learned (or Azure Cloud Shell, which "Allow Azure services" covers) goes on, and a
        SQL step that cannot connect says how to add the rule in the portal.
          $Ctx.Seams.PublicIp { } -> 'a.b.c.d'   (default: an HTTPS "what is my address" answer; tests pass a fake)
    #>
    param([Parameter(Mandatory)]$Ctx)
    try {
        if (-not $Ctx.Facts -or -not [string]$Ctx.Facts['sqlServerId'] -or -not $Ctx.Names -or -not [string]$Ctx.Names.SqlServer) { return }
        if ($Ctx.Cache.Contains('sqlHostWindow')) { return }
        # #866 (owner: "we will not allow fw option or exceptions"): a PRIVATE install's database gets no firewall rule --
        # this machine reaches it through its private endpoint (checked by the DNS gate before any statement)
        if ($Ctx.Values -and [bool]$Ctx.Values['privateNetwork']) { return }
        $Ctx.Cache['sqlHostWindow'] = ''
        $seam = $null; if ($Ctx.Seams -and $Ctx.Seams.Contains('PublicIp')) { $seam = $Ctx.Seams['PublicIp'] }
        if (-not ($seam -is [scriptblock])) { return }
        $ip = ([string](& $seam)).Trim()
        if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            Write-SIInstallConsole -Ctx $Ctx -Text ('      [INFO] this machine''s public address could not be learned: no {0} rule is set (Azure Cloud Shell needs none). If a database step cannot connect: {1} > Add your client IPv4 address.' -f $script:SIInstallSqlHostRule, (Get-SIInstallSqlHostPortalText -Ctx $Ctx)) -Color 'DarkGray'
            return
        }
        $a = [ordered]@{ ResourceGroupName = [string]$Ctx.Names.ResourceGroup; ServerName = [string]$Ctx.Names.SqlServer; Name = $script:SIInstallSqlHostRule; StartIpAddress = $ip; EndIpAddress = $ip }
        $r = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Set-SISqlFirewallRule' -Arguments $a
        if (-not $r.Ok) {
            Write-SIInstallConsole -Ctx $Ctx -Text ('      [WARN] the {0} rule for {1} could not be set: {2} -- {3}' -f $script:SIInstallSqlHostRule, $ip, $r.Error, (Get-SIInstallSqlHostPortalText -Ctx $Ctx)) -Color 'Yellow'
            return
        }
        # read back: the rule Azure has is the one for THIS address
        $back = (Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Get-SISqlFirewallRule' -Arguments ([ordered]@{ ResourceGroupName = $a.ResourceGroupName; ServerName = $a.ServerName; Name = $a.Name })).Value
        $have = [string](Get-SIInstallProp (Get-SIInstallProp $back 'properties') 'startIpAddress')
        if ($have -and $have -ne $ip) { Write-SIInstallConsole -Ctx $Ctx -Text ('      [WARN] the {0} rule reads back {1}, not {2}' -f $script:SIInstallSqlHostRule, $have, $ip) -Color 'Yellow' }
        $Ctx.Cache['sqlHostWindow'] = $ip
        $Ctx.Facts['sqlHostWindowIp'] = $ip
        Send-SIInstallProgress -Ctx $Ctx -Message ('database firewall rule {0} opened for this machine ({1}) for the install''s database steps' -f $script:SIInstallSqlHostRule, $ip)
    } catch { }
}

function Close-SIInstallSqlHostWindow {
    <#
        #564: closes the install's AllowSetupHost rule at the end of the run (success or a failed step; a resume opens it
        again for its own address). A close that fails is a WARNING with the portal path -- never a failed install.
        Returns $true when the rule is gone or was never opened.
    #>
    param([Parameter(Mandatory)]$Ctx)
    try {
        if (-not $Ctx.Facts -or -not [string]$Ctx.Facts['sqlHostWindowIp']) { return $true }
        $r = Invoke-SIInstallArmTry -Ctx $Ctx -Command 'Remove-SISqlFirewallRule' -Arguments ([ordered]@{ ResourceGroupName = [string]$Ctx.Names.ResourceGroup; ServerName = [string]$Ctx.Names.SqlServer; Name = $script:SIInstallSqlHostRule })
        if ($r.Ok) {
            $Ctx.Facts.Remove('sqlHostWindowIp'); if ($Ctx.Cache.Contains('sqlHostWindow')) { $Ctx.Cache.Remove('sqlHostWindow') }
            return $true
        }
        $null = Send-SIInstallEvent -Ctx $Ctx -StepId 'pro-sql' -State 'warning' -Message ('The install''s database firewall rule {0} ({1}) could not be removed: {2}' -f $script:SIInstallSqlHostRule, $Ctx.Facts['sqlHostWindowIp'], $r.Error) `
            -Action ([ordered]@{ text = ('Delete it by hand -- {0} > Delete -- or run the install command again (it closes the rule at its end):' -f (Get-SIInstallSqlHostPortalText -Ctx $Ctx)); command = $Ctx.ResumeCommand })
        return $false
    } catch { return $false }
}

function Close-SIInstallDatabaseAccess {
    <#
        THE END OF A RUN, finished or stopped at a failed step: what the install opened on the database server for its own
        steps is closed again -- the admin group is the server's administrator again (an install that ran as an
        application was the administrator itself for its database steps; Complete-SIInstallSqlAdmin, Pro only), and the
        install's firewall rule for this machine is removed. Each is a WARNING when it fails, never a failed install.
        Returns $true when both are done. Never throws.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $ok = $true
    try { if (Get-Command -Name Complete-SIInstallSqlAdmin -ErrorAction SilentlyContinue) { if (-not (Complete-SIInstallSqlAdmin -Ctx $Ctx)) { $ok = $false } } } catch { $ok = $false }
    # The hand-back above never takes the Invardia Support app's database access away: its own database user and its place in the
    # admin group (framework 4.1b) were made before it (the Support access step) and nothing here removes either. Now the server's
    # administrator is read back (the admin group, recorded as a group), and where it can be PROVEN -- an install that
    # ran as the Support app, which is no longer the administrator now -- it signs in to the product databases once
    # and says who it is there (before the firewall rule for this machine is removed).
    try {
        if (Get-Command -Name Confirm-SIInstallSupportAppSignIn -ErrorAction SilentlyContinue) {
            $proof = Confirm-SIInstallSupportAppSignIn -Ctx $Ctx
            if ($proof) {
                $act = $null
                if (-not $proof.Proven) { $act = [ordered]@{ text = 'Run in this install''s folder as an administrator of the database server (it shows the plan without -Apply; it changes nothing that is already right):'; command = (Get-SIInstallSupportAppDatabaseCommand -Ctx $Ctx) } }
                $null = Send-SIInstallEvent -Ctx $Ctx -StepId 'support-app-access' -State $(if ($proof.Proven) { 'ok' } else { 'warning' }) -Message ([string]$proof.Text) -Action $act
            }
        }
    } catch { }
    if (-not (Close-SIInstallSqlHostWindow -Ctx $Ctx)) { $ok = $false }
    $ok
}

function Invoke-SIInstallScript {
    <# A product script through the seam, by its path under the SecurityInsight folder. #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$RelativePath, [System.Collections.IDictionary]$Arguments = @{})
    $path = [IO.Path]::Combine($Ctx.SIRoot, ($RelativePath -replace '[\\/]', [IO.Path]::DirectorySeparatorChar))
    $r = & $Ctx.Seams.Script $path $Arguments
    $Ctx.ScriptLog.Add([pscustomobject]@{ Script = (Split-Path -Leaf $path); ExitCode = $r.ExitCode; Error = $r.Error })
    $r
}

function Write-SIInstallConsole {
    param([Parameter(Mandatory)]$Ctx, [string]$Text, [string]$Color)
    try { & $Ctx.Seams.Print $Text $Color } catch { }
}

# ---------------------------------------------------------------------------------------------------------------
# State file and events
# ---------------------------------------------------------------------------------------------------------------
function Get-SIInstallStateDirectory {
    <# The state folder: -StatePath, or ~/clouddrive/invardia/<installId> (Cloud Shell keeps clouddrive between sessions). #>
    param([string]$StatePath, [Parameter(Mandatory)][string]$InstallId)
    if ($StatePath) { return $StatePath }
    $home_ = if ($HOME) { $HOME } else { [Environment]::GetFolderPath('UserProfile') }
    [IO.Path]::Combine($home_, 'clouddrive', 'invardia', $InstallId)
}

function Resolve-SIInstallDirectConfig {
    <#
        The install started with its answers as PARAMETERS instead of -ConfigPath (owner 2026-10-29: "make 4-5 samples,
        most common is interactive login"): -TenantId and -SubscriptionId, plus the optional -Location, -ResourceGroup,
        -MailTo, -CollectionScope, -ManagementGroupId, -PrivateNetwork and -VnetAddressPrefix; everything else keeps its
        default from install-parameters.json, as in a config.json that leaves it out.
        The answers are written as config.json in the install's state folder, so the same install continues with -Resume
        alone; a check-only run (-PreflightOnly) writes it to a temporary file, never to the state folder. No answers and
        -Resume: the state folder's config.json from the first run. -Bound: the script's $PSBoundParameters.
        @{ Ok; ConfigPath; Message }.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Bound, [Parameter(Mandatory)][string]$InstallId, [string]$StatePath,
          [switch]$PreflightOnly, [switch]$Resume)
    $map = [ordered]@{ TenantId = 'tenantId'; SubscriptionId = 'subscriptionId'; Location = 'location'; ResourceGroup = 'resourceGroup'
                       MailTo = 'mailTo'; CollectionScope = 'collectionScope'; ManagementGroupId = 'managementGroupId'
                       PrivateNetwork = 'privateNetwork'; VnetAddressPrefix = 'vnetAddressPrefix' }
    $boundKeys = @($Bound.Keys)   # $PSBoundParameters has no public Contains(); its Keys work for it and a hashtable alike
    $given = @($map.Keys | Where-Object { $boundKeys -contains $_ })
    $dir = Get-SIInstallStateDirectory -StatePath $StatePath -InstallId $InstallId
    $stored = [IO.Path]::Combine($dir, 'config.json')
    if (-not $given.Count) {
        if ($Resume -and (Test-Path -LiteralPath $stored)) { return @{ Ok = $true; ConfigPath = $stored; Message = ('Continuing the install with its answers from {0}' -f $stored) } }
        return @{ Ok = $false; ConfigPath = $null
                  Message = 'Tell the install where to go: -TenantId <tenant id> -SubscriptionId <subscription id> (or -ConfigPath <config.json> for every setting).' }
    }
    $missing = @('TenantId', 'SubscriptionId' | Where-Object { -not "$($Bound[$_])".Trim() })
    if ($missing.Count) { return @{ Ok = $false; ConfigPath = $null; Message = ('Also needed: {0}' -f ((@($missing) | ForEach-Object { '-' + $_ }) -join ' ')) } }
    if ("$($Bound['CollectionScope'])" -eq 'managementGroup' -and -not "$($Bound['ManagementGroupId'])".Trim()) {
        return @{ Ok = $false; ConfigPath = $null; Message = 'Also needed with -CollectionScope managementGroup: -ManagementGroupId <management group id>' }
    }
    $cfg = [ordered]@{ installId = $InstallId }
    foreach ($k in $given) {
        $v = $Bound[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) { $v = [bool]$v }
        elseif ($k -eq 'MailTo') { $v = @($v | ForEach-Object { "$_" -split '[,;\s]+' } | Where-Object { $_ }) }   # "a,b" from a command line too
        else { $v = "$v".Trim() }
        $cfg[$map[$k]] = $v
    }
    $json = ConvertTo-Json -InputObject $cfg -Depth 4
    if ($PreflightOnly) {
        $path = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('si-install-{0}-{1}.json' -f $InstallId, [guid]::NewGuid().ToString('N')))
    } else {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $path = $stored
    }
    [IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding $false))
    @{ Ok = $true; ConfigPath = $path; Message = $(if ($PreflightOnly) { '' } else { ('Your answers are kept in {0} (run the same install again with -Resume)' -f $path) }) }
}

function Read-SIInstallState {
    param([Parameter(Mandatory)][string]$Directory)
    $f = [IO.Path]::Combine($Directory, 'state.json')
    if (-not (Test-Path -LiteralPath $f)) { return $null }
    try { ConvertTo-SIInstallHashtable ([IO.File]::ReadAllText($f) | ConvertFrom-Json) } catch { $null }
}

function Save-SIInstallState {
    <# Written after every step (temp file + move), so a crash never leaves a half-written state. #>
    param([Parameter(Mandatory)]$Ctx)
    if ($Ctx.PreflightOnly) { return }
    $dir = $Ctx.StateDirectory
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $s = $Ctx.State
    $s['updatedAt'] = (& $Ctx.Seams.Now).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $json = ConvertTo-Json -InputObject $s -Depth 10
    $f = [IO.Path]::Combine($dir, 'state.json'); $tmp = $f + '.tmp'
    [IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
    Move-Item -LiteralPath $tmp -Destination $f
    # the install's settings file is kept with the state too (a product script a step ran may have changed it)
    $null = Save-SIInstallConfigCopy -Ctx $Ctx
}

# ---------------------------------------------------------------------------------------------------------------
# The install's settings file is KEPT WITH THE STATE. The install writes config\SecurityInsight.custom.ps1 into the
# package copy it runs from, and Invardia's bootstrap unpacks every release into its own folder
# (<installation folder>\package-<version>\...): a resume with a newer release starts in a copy that has no such file,
# although the state says the steps that wrote it are done. So every write is also saved next to state.json, and a
# resume takes it back from there -- or, for an install whose earlier runs kept no such copy, from the earlier package
# folder next to the state folder. The file carries names and ids only (the secrets are in the Key Vault).
# ---------------------------------------------------------------------------------------------------------------
function Get-SIInstallConfigCopyPath {
    <# PURE. Where the install's settings file is kept with its state. #>
    param([Parameter(Mandatory)][string]$StateDirectory)
    [IO.Path]::Combine($StateDirectory, 'SecurityInsight.custom.ps1')
}

function Write-SIInstallFileAtomic {
    <# Temp file + move, as the state file: a crash never leaves half a file. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $tmp = $Path + '.tmp'
    [IO.File]::WriteAllBytes($tmp, $Bytes)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    Move-Item -LiteralPath $tmp -Destination $Path
}

function Test-SIInstallSameBytes {
    <# PURE. #>
    param([AllowNull()][byte[]]$A, [AllowNull()][byte[]]$B)
    if ($null -eq $A -or $null -eq $B) { return $false }
    if ($A.Length -ne $B.Length) { return $false }
    [Convert]::ToBase64String($A) -ceq [Convert]::ToBase64String($B)
}

function Get-SIInstallConfigCopyBytes {
    <#
        What is kept with the state for the settings file at -Path: the file as it is. The install writes no secret into
        it (they go to the Key Vault); a value a person typed into it by hand under a secret's name (..Secret / ..Password /
        ..ApiKey / ..StorageKey / ..SasToken = '...') is NOT part of the copy.
    #>
    param([Parameter(Mandatory)][string]$Path)
    [byte[]]$bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length) {
        $secretLine = '(?im)^[ \t]*\$(global:)?\w*(Secret|Password|ApiKey|StorageKey|SasToken)[ \t]*=[ \t]*[''"][^''"\r\n]+[''"][^\r\n]*(\r?\n|$)'
        $text = [IO.File]::ReadAllText($Path)
        if ([regex]::IsMatch($text, $secretLine)) {
            $clean = [regex]::Replace($text, $secretLine, '')
            [byte[]]$body = (New-Object System.Text.UTF8Encoding($false)).GetBytes($clean)
            [byte[]]$bom = @(0xEF, 0xBB, 0xBF)
            $bytes = New-Object byte[] ($bom.Length + $body.Length)
            [Array]::Copy($bom, 0, $bytes, 0, $bom.Length)
            [Array]::Copy($body, 0, $bytes, $bom.Length, $body.Length)
        }
    }
    , $bytes
}

function Save-SIInstallConfigCopy {
    <#
        Saves the install's settings file next to state.json when it is there and differs from the copy kept. Never throws
        (a copy that cannot be written never stops a step) and writes nothing in a checks-only run. $true when it wrote.
    #>
    param([Parameter(Mandatory)]$Ctx)
    try {
        if ($Ctx.PreflightOnly) { return $false }
        $src = [string]$Ctx.ConfigPath
        $dir = [string]$Ctx.StateDirectory
        if (-not $src -or -not $dir -or -not (Test-Path -LiteralPath $src)) { return $false }
        $bytes = Get-SIInstallConfigCopyBytes -Path $src
        if (-not $bytes.Length) { return $false }
        $dst = Get-SIInstallConfigCopyPath -StateDirectory $dir
        if (Test-Path -LiteralPath $dst) {
            $have = [IO.File]::ReadAllBytes($dst)
            if (Test-SIInstallSameBytes -A $bytes -B $have) { return $false }
        }
        Write-SIInstallFileAtomic -Path $dst -Bytes $bytes
        return $true
    } catch { return $false }
}

function Find-SIInstallEarlierConfig {
    <#
        The settings file an EARLIER package copy of this install holds: the package-* folders next to the state folder are
        searched for SOLUTIONS\SecurityInsight\config\SecurityInsight.custom.ps1 (or this install's own
        SecurityInsight.custom.<installId>.ps1), at most six folders below the package folder; only a file that carries
        THIS install's id counts, never one in the copy that is running (-SIRoot) and never -ConfigPath itself. The most
        recently written one is returned (a file object), or nothing. Never throws.
    #>
    param([Parameter(Mandatory)][string]$StateDirectory, [Parameter(Mandatory)][string]$InstallId, [string]$SIRoot, [string]$ConfigPath)
    $best = $null
    try {
        $norm = { param($p) $t = "$p".TrimEnd('\', '/'); try { [IO.Path]::GetFullPath($t).TrimEnd('\', '/') } catch { $t } }
        $ic = [StringComparison]::OrdinalIgnoreCase
        $parent = Split-Path -Parent (& $norm $StateDirectory)
        if (-not $parent -or -not (Test-Path -LiteralPath $parent)) { return $null }
        $own = if ("$SIRoot".Trim()) { & $norm $SIRoot } else { '' }
        $target = if ("$ConfigPath".Trim()) { & $norm $ConfigPath } else { '' }
        $safe = ($InstallId -replace '[^A-Za-z0-9._-]', '_')
        $names = @('SecurityInsight.custom.ps1', ('SecurityInsight.custom.{0}.ps1' -f $safe))
        foreach ($pkg in @(Get-ChildItem -LiteralPath $parent -Directory -Filter 'package-*' -ErrorAction SilentlyContinue)) {
            $pkgPath = & $norm $pkg.FullName
            # never this run's own copy
            if ($own -and ($own.Equals($pkgPath, $ic) -or $own.StartsWith($pkgPath + '\', $ic) -or $own.StartsWith($pkgPath + '/', $ic))) { continue }
            $queue = New-Object System.Collections.Generic.Queue[object]
            $queue.Enqueue([pscustomobject]@{ Path = $pkg.FullName; Depth = 0 })
            while ($queue.Count) {
                $node = $queue.Dequeue()
                $cfgDir = [IO.Path]::Combine($node.Path, 'SOLUTIONS', 'SecurityInsight', 'config')
                if (Test-Path -LiteralPath $cfgDir) {
                    foreach ($nm in $names) {
                        $f = [IO.Path]::Combine($cfgDir, $nm)
                        if (-not (Test-Path -LiteralPath $f)) { continue }
                        if ($target -and $target.Equals((& $norm $f), $ic)) { continue }
                        $text = ''
                        try { $text = [IO.File]::ReadAllText($f) } catch { $text = '' }
                        if (-not "$text".Trim() -or -not (Test-SIInstallConfigIsOwn -Text $text -InstallId $InstallId)) { continue }
                        $fi = Get-Item -LiteralPath $f
                        if (-not $best -or $fi.LastWriteTimeUtc -gt $best.LastWriteTimeUtc) { $best = $fi }
                    }
                    continue
                }
                if ($node.Depth -ge 6) { continue }
                foreach ($d in @(Get-ChildItem -LiteralPath $node.Path -Directory -ErrorAction SilentlyContinue)) {
                    $queue.Enqueue([pscustomobject]@{ Path = $d.FullName; Depth = $node.Depth + 1 })
                }
            }
        }
    } catch { }
    $best
}

function Restore-SIInstallConfigFile {
    <#
        At the start of a resume, before any step: puts the install's settings file back into this copy when it is not
        here (or the copy kept with the state is newer and differs). Taken from, in this order: the copy kept with the
        state; an earlier package copy next to the state folder (which is then kept with the state too). Returns
        @{ Present; Source ('' | 'state' | 'package'); From } -- Present = the file is here now. Never throws.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $dst = [string]$Ctx.ConfigPath
    $out = [ordered]@{ Present = $false; Source = ''; From = '' }
    try {
        $hereBytes = $null
        if (Test-Path -LiteralPath $dst) { $hereBytes = [IO.File]::ReadAllBytes($dst) }
        $here = ($null -ne $hereBytes -and $hereBytes.Length -gt 0)
        $out.Present = $here
        # (a) the copy kept with the state
        $copy = Get-SIInstallConfigCopyPath -StateDirectory ([string]$Ctx.StateDirectory)
        if (Test-Path -LiteralPath $copy) {
            $copyBytes = [IO.File]::ReadAllBytes($copy)
            $copyText = [IO.File]::ReadAllText($copy)
            if ($copyBytes.Length -and (Test-SIInstallConfigIsOwn -Text $copyText -InstallId $Ctx.InstallId)) {
                $take = -not $here
                # compared as it would be kept: a secret typed in here by hand is never in the kept copy, and never a reason to replace this file
                if ($here -and -not (Test-SIInstallSameBytes -A (Get-SIInstallConfigCopyBytes -Path $dst) -B $copyBytes)) {
                    $take = ((Get-Item -LiteralPath $copy).LastWriteTimeUtc -gt (Get-Item -LiteralPath $dst).LastWriteTimeUtc)
                }
                if ($take) {
                    Write-SIInstallFileAtomic -Path $dst -Bytes $copyBytes
                    $out.Present = $true; $out.Source = 'state'; $out.From = $copy
                }
                return [pscustomobject]$out
            }
        }
        if ($here) { return [pscustomobject]$out }
        # (b) an earlier package copy of this install (a release that kept no copy with the state)
        $old = Find-SIInstallEarlierConfig -StateDirectory ([string]$Ctx.StateDirectory) -InstallId $Ctx.InstallId -SIRoot ([string]$Ctx.SIRoot) -ConfigPath $dst
        if ($old) {
            $oldBytes = [IO.File]::ReadAllBytes($old.FullName)
            Write-SIInstallFileAtomic -Path $dst -Bytes $oldBytes
            $out.Present = $true; $out.Source = 'package'; $out.From = $old.FullName
            $null = Save-SIInstallConfigCopy -Ctx $Ctx
        }
    } catch { }
    [pscustomobject]$out
}

function Send-SIInstallEvent {
    <# Builds the event, prints a line for the person at the shell, and hands it to the reporter. A failing reporter never stops the install. #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$StepId, [Parameter(Mandatory)][string]$State,
          $DurationMs, [string]$Message, $Action, $Detail, $Outputs)
    $Ctx.State['seq'] = 1 + [int]$Ctx.State['seq']
    $ev = New-SIInstallEvent -InstallId $Ctx.InstallId -Seq ([int]$Ctx.State['seq']) -StepId $StepId -State $State -At (& $Ctx.Seams.Now) `
        -DurationMs $DurationMs -Message $Message -Action $Action -Detail $Detail -Outputs $Outputs
    $Ctx.Events.Add($ev)
    $color = switch ($State) { 'ok' { 'Green' } 'warning' { 'Yellow' } 'failed' { 'Red' } 'completed' { 'Green' } 'skipped' { 'DarkGray' } default { 'Cyan' } }
    $line = '[{0,-9}] {1}{2}' -f $State, $ev.step.title, $(if ($ev.message) { ' -- ' + $ev.message } else { '' })
    Write-SIInstallConsole -Ctx $Ctx -Text $line -Color $color
    if ($ev.action) {
        if ($ev.action.text) { Write-SIInstallConsole -Ctx $Ctx -Text ('            ' + $ev.action.text) -Color $color }
        if ($ev.action.command) { foreach ($l in ($ev.action.command -split "`r?`n")) { Write-SIInstallConsole -Ctx $Ctx -Text ('              ' + $l) -Color $color } }
    }
    if ($Ctx.Reporter) {
        try { & $Ctx.Reporter $ev } catch { Write-SIInstallConsole -Ctx $Ctx -Text ('(the status could not be sent: {0})' -f $_.Exception.Message) -Color 'DarkYellow' }
    }
    $ev
}

function Send-SIInstallFailureTelemetry {
    <#
        #427 (framework UPLINK-FIX, owner 2026-10-07): a failed install step is reported to Invardia's uplink -- Job
        si-install, FailedStep = the step id, ErrorClass from the text, the version. Identified with the install key when the
        install has one (Pro, the key from the installation bundle; the tenant it installs into), anonymous otherwise (no
        tenant, no host, no text). The telemetry switch is honoured (SI_Telemetry_Enabled / SI_TELEMETRY_ENABLED = false:
        nothing is built or sent). The same reports and status page as before; this is in addition. NEVER throws.
          $Ctx.Seams.Telemetry  { param($Job, $Step, $Text, $Context) } -- the test seam (it gets $null as the context)
    #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$StepId, [AllowEmptyString()][string]$Message)
    try {
        $seam = $null; if ($Ctx.Seams -and $Ctx.Seams.Contains('Telemetry')) { $seam = $Ctx.Seams['Telemetry'] }
        if ($seam -is [scriptblock]) { return (& $seam 'install' $StepId $Message $null) }
        if ($WhatIfPreference) { return $null }   # -WhatIf (the checks only) sends nothing anywhere -- not even a failure report
        if (-not (Get-Command -Name Send-SITelemetryFailure -ErrorAction SilentlyContinue)) { return $null }
        if (-not (Test-SITelemetryEnabled)) { return $null }
        if (Get-Module -Name Pester) { return $null }   # a test session never builds a context or sends
        $key = [string]$Ctx.InstallKey
        $tid = ''; if ($Ctx.Values -and $Ctx.Values.Contains('tenantId')) { $tid = [string]$Ctx.Values['tenantId'] }
        # the ring the install follows (the wizard's answer, framework §8.4 / §8.7); no answer = the configuration's SI_UpdateRing
        $ringArg = @{}; if ($Ctx.Values -and $Ctx.Values.Contains('updateRing') -and "$($Ctx.Values['updateRing'])".Trim()) { $ringArg.UpdaterRing = $Ctx.Values['updateRing'] }
        $context = Get-SITelemetryContext -License $null -InstallKey $key -TenantId $tid -Edition $(if ($Ctx.Pro) { 'pro' } else { 'community' }) @ringArg
        Send-SITelemetryFailure -Job install -Step $StepId -ErrorMessage $Message -Context $context
    } catch { $null }
}

function Send-SIInstallProgress {
    <#
        #564 (Invardia + PIM, customer I 2026-10-10): a long step (the image build and the jobs, 20-35 minutes; the web app; the
        databases) posts its SUB-STEPS as 'started' events of the step that runs, with the sub-step in the message -- so the
        status page and support can tell work from a hang. Also the "waiting: sign-in required for <resource> in tenant <t>"
        line before a browser window opens. The event contract is unchanged (state 'started'). -Ctx: the install's context
        (default: the one that runs, $global:SI_InstallActiveContext). Never throws; nothing without a running step.
    #>
    param($Ctx, [Parameter(Mandatory)][string]$Message)
    try {
        if (-not $Ctx) { $Ctx = Get-Variable -Scope Global -Name SI_InstallActiveContext -ValueOnly -ErrorAction Ignore }
        if (-not ($Ctx -is [System.Collections.IDictionary]) -or -not $Ctx['CurrentStepId']) { return }
        $m = ("$Message" -replace '\s+', ' ').Trim()
        if (-not $m) { return }
        $null = Send-SIInstallEvent -Ctx $Ctx -StepId ([string]$Ctx['CurrentStepId']) -State 'started' -Message $m
    } catch { }
}

function Test-SIInstallSubStepLine {
    <# PURE. Is this output line of a product script a sub-step header ("[2/5] ...", "== 4. Container Apps ...", "STEP ...")? #>
    param([AllowEmptyString()][string]$Line)
    [bool]("$Line" -match '^\s*(\[\d+/\d+\]\s+\S|==\s+\S|STEP\s+\d)')
}

function Invoke-SIInstallStep {
    <# Runs one step: 'started', then ok / warning / skipped, or failed with message + action. Returns the end state. #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$StepId, [Parameter(Mandatory)][scriptblock]$Body)
    $t0 = & $Ctx.Seams.Now
    # #564: the step that runs now -- sub-step and sign-in events are posted under it (Send-SIInstallProgress)
    $Ctx['CurrentStepId'] = $StepId
    $null = Send-SIInstallEvent -Ctx $Ctx -StepId $StepId -State 'started'
    try {
        # #876: a hand-over sign-in that is about to run out stops the step BEFORE it starts -- never half a step
        # (a context without facts -- a test's, or one built before the facts are read -- is not a hand-over sign-in)
        if ($StepId -ne 'preflight-signin' -and $null -ne $Ctx.Facts -and [string]$Ctx.Facts['signInMethod'] -eq 'Handoff') {
            $hc = Get-SIInstallHandoffCheck -Ctx $Ctx
            if ($hc.Expired.Count) { throw (New-SIInstallFailure -Message (Get-SIHandoffExpiredText -Resource '') -ActionText 'Get a fresh code on the installation page, then run:' -Command $Ctx.ResumeCommand) }
        }
        # The step's RESULT is its last result object; anything else a step lets slip into the pipeline is ignored.
        $r = @(& $Body $Ctx) | Where-Object { $null -ne $_ -and $_.PSObject.Properties['State'] -and $_.PSObject.Properties['Message'] } | Select-Object -Last 1
        if ($null -eq $r) { $r = New-SIInstallResult -State 'ok' }
        $ms = [long]((& $Ctx.Seams.Now) - $t0).TotalMilliseconds
        # The status page's contract (Invardia): an action ALWAYS has both text and a command. A note without a command
        # is part of the message instead.
        $act = $r.Action; $msgOut = [string]$r.Message
        if ($act -and -not ([string](Get-SIInstallProp $act 'command')).Trim()) {
            $note = ([string](Get-SIInstallProp $act 'text')).Trim()
            if ($note) { $msgOut = (($msgOut.TrimEnd() + ' ' + $note).Trim()) }
            $act = $null
        } elseif ($act -and -not ([string](Get-SIInstallProp $act 'text')).Trim()) {
            $act = [ordered]@{ text = 'For someone with the rights to run:'; command = [string](Get-SIInstallProp $act 'command') }
        }
        $null = Send-SIInstallEvent -Ctx $Ctx -StepId $StepId -State $r.State -DurationMs $ms -Message $msgOut -Action $act -Detail $r.Detail
        if ($StepId -like 'preflight-*') { }
        elseif ($r.State -eq 'warning') {
            $Ctx.State['pending'][$StepId] = [ordered]@{ message = (Protect-SIInstallText ([string]$r.Message)); command = $(if ($r.Action) { Protect-SIInstallText ([string](Get-SIInstallProp $r.Action 'command')) } else { $null }) }
        } elseif ($Ctx.State['pending'].Contains($StepId)) { $Ctx.State['pending'].Remove($StepId) }
        return $r.State
    } catch {
        $ex = $_.Exception
        $errRecord = $_
        $ms = [long]((& $Ctx.Seams.Now) - $t0).TotalMilliseconds
        $action = $ex.Data['SIInstallAction']
        if (-not $action) { $action = [ordered]@{ text = 'Fix the cause above, then run the install command again: it continues from this step.'; command = $Ctx.ResumeCommand } }
        # A failure always tells the person what to run: with no command of its own, it is the resume command.
        if (-not ([string](Get-SIInstallProp $action 'command')).Trim()) {
            $txt = ([string](Get-SIInstallProp $action 'text')).Trim()
            if (-not $txt) { $txt = 'Fix the cause above, then run the install command again: it continues from this step.' }
            $action = [ordered]@{ text = $txt; command = $Ctx.ResumeCommand }
        } elseif (-not ([string](Get-SIInstallProp $action 'text')).Trim()) {
            $action = [ordered]@{ text = 'Run this, then run the install command again: it continues from this step.'; command = [string](Get-SIInstallProp $action 'command') }
        }
        $detail = $ex.Data['SIInstallDetail']
        # the WHOLE error, not only its summary line: Azure's error body, a policy denial's names, where it happened
        $full = @(Get-SIInstallErrorText -Record $errRecord -Context $StepId)
        if ($full.Count) {
            if ($null -eq $detail) { $detail = [ordered]@{} }
            if ($detail -is [System.Collections.IDictionary]) { $detail['error'] = $full }
        }
        $failMsg = $ex.Message
        # #876: a handed-over token ran out INSIDE the step (whatever the step made of the error): said in one plain line
        $hoExp = [string](Get-Variable -Scope Global -Name SI_SetupHandoffExpired -ValueOnly -ErrorAction Ignore)
        if ($hoExp) {
            $global:SI_SetupHandoffExpired = $null
            $failMsg = Get-SIHandoffExpiredText -Resource $hoExp
            $action = [ordered]@{ text = 'Get a fresh code on the installation page, then run:'; command = $Ctx.ResumeCommand }
        }
        $null = Send-SIInstallEvent -Ctx $Ctx -StepId $StepId -State 'failed' -DurationMs $ms -Message $failMsg -Action $action -Detail $detail
        Write-SIInstallErrorDetail -Ctx $Ctx -Record $errRecord -Context $StepId
        # #427: the failed step reaches Invardia's uplink too (step id, error class + text, version) -- never stops the install
        $null = Send-SIInstallFailureTelemetry -Ctx $Ctx -StepId $StepId -Message $ex.Message
        return 'failed'
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Lazily-run product scripts shared by several steps
# ---------------------------------------------------------------------------------------------------------------
function Test-SIInstallRegionRefused {
    <# PURE. Azure's answer says the REGION does not take new resources of this kind for this subscription (the first
       rehearsal of a customer-run install, 2026-10-12: a Log Analytics workspace in westeurope) -- not a missing right,
       not a policy of the customer's own. #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    [bool]("$Text" -match '(?i)RequestDisallowedByAzure|locationineligible|not accepting new customers|LocationNotAvailableForResourceType|RegionDoesNotAllowProvisioning|is not available in (the )?(location|region)')
}

function Get-SIInstallInfra {
    <#
        Initialize-SIInfra -- ONE proven script creates the workspace, the data collection endpoint, the storage account
        and the Key Vault (idempotent). The first of those four steps that runs calls it; the others report from its
        result. A resumed install calls it again (it re-uses what exists).
    #>
    param([Parameter(Mandatory)]$Ctx)
    if ($Ctx.Cache.Contains('infra')) { return $Ctx.Cache['infra'] }
    $v = $Ctx.Values; $n = $Ctx.Names
    $r = Invoke-SIInstallScript -Ctx $Ctx -RelativePath 'setup/ConfigWizard/backend/Initialize-SIInfra.ps1' -Arguments ([ordered]@{
        SpnObjectId = [string]$Ctx.Facts['userObjectId']; TenantId = [string]$v['tenantId']; SubscriptionId = [string]$v['subscriptionId']
        ResourceGroupName = $n.ResourceGroup; Location = [string]$v['location']; WorkspaceName = $n.Workspace; DceName = $n.Dce
        StorageAccountName = $n.StorageAccount; CreateKeyVault = $true; KeyVaultName = $n.KeyVault
        Ring = 'prod'; Edition = $Ctx.Edition; Hosting = 'ca'; Owner = [string]$v['owner']
        # #866: a private install creates its storage and Key Vault with no public access (their endpoints follow at once)
        PrivateNetwork = [bool]$v['privateNetwork'] })
    if ($r.Error) {
        # Azure does not take new resources of this kind in the chosen region for this subscription: said in plain words,
        # with what to change -- the raw answer alone ("RequestDisallowedByAzure") tells an installer nothing
        if (Test-SIInstallRegionRefused -Text ([string]$r.Error)) {
            throw (New-SIInstallFailure -Message ('Azure does not accept new resources of this kind in the region {0} for this subscription (its answer: the region is not accepting new customers). Nothing is wrong with your rights.' -f [string]$v['location']) `
                -ActionText ('Choose another region for this install -- on your installation page at invardia.com change Location (for example swedencentral or northeurope) -- then run the install command again: it continues from this step. The resource group {0} can stay where it is.' -f $n.ResourceGroup) `
                -Command $Ctx.ResumeCommand -Detail @{ log = (Get-SIInstallTail $r.Text) })
        }
        throw (New-SIInstallFailure -Message ('Creating the workspace, data collection endpoint, storage and Key Vault failed: {0}' -f $r.Error) `
            -ActionText 'Fix the cause, then run the install command again: it continues from this step.' -Command $Ctx.ResumeCommand -Detail @{ log = (Get-SIInstallTail $r.Text) })
    }
    $infra = @($r.Objects | Where-Object { Get-SIInstallProp $_ 'WorkspaceResourceId' }) | Select-Object -Last 1
    if (-not $infra) { throw (New-SIInstallFailure -Message 'The infrastructure step returned no result.' -Detail @{ log = (Get-SIInstallTail $r.Text) }) }
    $keep = [ordered]@{}
    foreach ($k in 'SubscriptionId', 'Location', 'ResourceGroupName', 'DcrResourceGroupName', 'StorageResourceGroupName', 'WorkspaceName', 'WorkspaceResourceId',
                   'DceName', 'DceIngestionUri', 'StorageAccountName', 'StorageAccountResourceId', 'KeyVaultName', 'KeyVaultUri') { $keep[$k] = Get-SIInstallProp $infra $k }
    $Ctx.Facts['infra'] = $keep
    $Ctx.Cache['infra'] = $keep
    $keep
}

function Invoke-SIInstallBootstrap {
    <#
        Bootstrap-ContainerAppJob -UseManagedIdentity -GrantIdentityRoles -- ONE proven script makes the registry, builds
        the image, makes the Container Apps environment, the identity and its grants, and the jobs. The image step runs it
        whole; later steps check their part and run it again (without the image build) only when their part is missing.
    #>
    param([Parameter(Mandatory)]$Ctx, [switch]$SkipImageBuild)
    $v = $Ctx.Values; $n = $Ctx.Names
    $a = [ordered]@{
        Engines = @($Ctx.Engines); ResourceGroupName = $n.ResourceGroup; Location = [string]$v['location']; AcrName = $n.Acr; EnvName = $n.ContainerEnv
        ImageTag = $Ctx.ImageTag; UseManagedIdentity = $true; ManagedIdentityName = $n.ManagedIdentity; GrantIdentityRoles = $true
        # the install's OWN answers and config file, explicitly: never a subscription from a global left in the session or
        # from a config file that is not this install's (live 2026-10-06 on mgmt1: ring 1's subscription was used)
        SubscriptionId = [string]$v['subscriptionId']; ConfigPath = $Ctx.ConfigPath
        IdentityReaderScopes = @(Get-SIInstallReaderScopes -Values $v)
        # #830: no RiskAnalysisSendToLogAnalytics -- the copy of the report rows to Log Analytics is an optional output, off by
        # default (the jobs follow the setting; a job env value would hold it on)
        # #250: the default templates are installed by the install's own 'pro-templates' step, as the person installing
        SkipTemplateInstall = $true
    }
    if ([bool]$v['aiClassification']) { $a.RiskAnalysisBuildSummaryByAI = $true }
    # #715: Bootstrap drops a ServiceNow job no setting asks for -- the ServiceNow jobs of the list are asked for here
    if (Get-Command Get-SIInstallServiceNowSwitches -ErrorAction SilentlyContinue) {
        $snow = Get-SIInstallServiceNowSwitches -Engines @($Ctx.Engines)
        foreach ($k in $snow.Keys) { $a[$k] = $snow[$k] }
    }
    # #236: asset tagging's own identity gets its WRITE grants only when the install asks for them (off by default).
    if (@($Ctx.Engines) -contains 'asset-tagging' -and [bool]$v['assetTaggingWrites']) { $a.GrantTaggingRoles = $true }
    # CR5 step 2 (#655): asset tagging's identity by the install's names table -- passed only when it is not today's name
    # (Bootstrap's own default), so an install on today's names runs exactly the command it ran before
    $tagName = Get-SISetupComponentName -Names $n -Key TaggingIdentity
    if ($tagName -cne [string](Get-SISetupComponentNames)['TaggingIdentity']) { $a.TaggingIdentityName = $tagName }
    if ($SkipImageBuild) { $a.SkipImageBuild = $true }
    # #681: private networking -- the environment is created in the customer's subnet, internal (the subnet step made it)
    if ([bool]$v['privateNetwork'] -and [string]$Ctx.Facts['appsSubnetId']) { $a.InfrastructureSubnetId = [string]$Ctx.Facts['appsSubnetId']; $a.EnvironmentInternal = $true }
    $sched = Get-SIInstallSchedules -RunHourUtc ([int]$v['runHourUtc'])
    foreach ($k in $sched.Keys) { $a[$k] = $sched[$k] }
    $r = Invoke-SIInstallScript -Ctx $Ctx -RelativePath 'Bootstrap-ContainerAppJob.ps1' -Arguments $a
    $Ctx.Cache['bootstrapRan'] = $true
    if ($r.Error) {
        if (Test-SIInstallRegionRefused -Text ([string]$r.Error)) {
            throw (New-SIInstallFailure -Message ('Azure does not accept new resources of this kind in the region {0} for this subscription: {1}' -f [string]$v['location'], $r.Error) `
                -ActionText 'Choose another region for this install -- on your installation page at invardia.com change Location -- then run the install command again: it continues from this step.' `
                -Command $Ctx.ResumeCommand -Detail @{ log = (Get-SIInstallTail $r.Text) })
        }
        throw (New-SIInstallFailure -Message ('The container setup failed: {0}' -f $r.Error) `
            -ActionText 'Fix the cause, then run the install command again: it continues from this step.' -Command $Ctx.ResumeCommand -Detail @{ log = (Get-SIInstallTail $r.Text) })
    }
    $r
}

function Get-SIInstallGrantReport {
    <# Grant-SIIdentity -AllowSchemaCreate -Apply, run once for the three grant steps (idempotent; a resumed install runs it again). #>
    param([Parameter(Mandatory)]$Ctx)
    if ($Ctx.Cache.Contains('grants')) { return $Ctx.Cache['grants'] }
    $v = $Ctx.Values; $n = $Ctx.Names
    $r = Invoke-SIInstallScript -Ctx $Ctx -RelativePath 'setup/Grant-SIIdentity.ps1' -Arguments ([ordered]@{
        IdentityName = $n.ManagedIdentity; IdentityResourceGroup = $n.ResourceGroup; ConfigPath = $Ctx.ConfigPath; SubscriptionId = [string]$v['subscriptionId']
        ReaderScopes = @(Get-SIInstallReaderScopes -Values $v); KeyVaultName = $n.KeyVault; AllowSchemaCreate = $true; Apply = $true })
    if ($r.Error) {
        throw (New-SIInstallFailure -Message ('Granting SecurityInsight''s identity its access failed: {0}' -f $r.Error) -Detail @{ log = (Get-SIInstallTail $r.Text) })
    }
    $rep = Read-SIInstallGrantReport -Lines $r.Text -SubscriptionId ([string]$v['subscriptionId']) -ResourceGroup $n.ResourceGroup
    $rep | Add-Member -NotePropertyName Log -NotePropertyValue (Get-SIInstallTail $r.Text) -Force
    $Ctx.Cache['grants'] = $rep
    $rep
}

function Get-SIInstallGrantCommand {
    <# The exact command that re-runs SecurityInsight's own grants -- for an admin, in a shell holding this install's files. #>
    param([Parameter(Mandatory)]$Ctx)
    $n = $Ctx.Names
    "./setup/Grant-SIIdentity.ps1 -IdentityName {0} -IdentityResourceGroup {1} -KeyVaultName {2} -ReaderScopes {3} -AllowSchemaCreate -Apply" -f $n.ManagedIdentity, $n.ResourceGroup, $n.KeyVault, ((Get-SIInstallReaderScopes -Values $Ctx.Values) -join ',')
}

function Get-SIInstallPipelineTimeZone {
    <#
        #306: the time zone the daily pipeline's start time is read in. The wizard's answer; else this machine's time zone
        (-Local, default [TimeZoneInfo]::Local -- a Windows id on Windows, an IANA id on Linux; both are accepted); else,
        when the machine runs on UTC (Azure Cloud Shell does), -Fallback: the time zone of the install's Azure region (Danish
        time, Europe/Copenhagen, when the region is not known).
    #>
    param([AllowEmptyString()][string]$Answer, [TimeZoneInfo]$Local = [TimeZoneInfo]::Local, [string]$Fallback = 'Europe/Copenhagen')
    if ($Answer.Trim()) { return $Answer.Trim() }
    $id = if ($Local) { [string]$Local.Id } else { '' }
    if (-not $id -or $id -in @('UTC', 'Etc/UTC', 'Coordinated Universal Time', 'Etc/GMT', 'GMT') -or ($Local -and $Local.BaseUtcOffset -eq [TimeSpan]::Zero -and -not $Local.SupportsDaylightSavingTime)) { return $(if ("$Fallback".Trim()) { "$Fallback".Trim() } else { 'Europe/Copenhagen' }) }
    # The jobs run on Linux: a Windows id (Romance Standard Time, from an install run on Windows) is written as its IANA
    # id where this PowerShell can convert it (.NET 6+) -- portable, and what the setting documents (live 2026-10-06).
    $conv = [TimeZoneInfo].GetMethod('TryConvertWindowsIdToIanaId', [Type[]]@([string], [string].MakeByRefType()))
    if ($conv -and $id -notmatch '/') {
        $iana = $null
        try { if ([TimeZoneInfo]::TryConvertWindowsIdToIanaId($id, [ref]$iana) -and $iana) { return [string]$iana } } catch { }
    }
    $id
}

function Get-SIInstallPipelineSchedule {
    <#
        PURE (over the machine's zone for a chosen time). The daily pipeline a new install writes (owner 2026-10-21: the update at 18:30, the pipeline at 19:00, done the next morning; before that 2026-10-15: the update
        at 23:00, the pipeline at 23:30, complete by 08:00 -- "11pm local time for region"): no start time answered, or the
        shipped default 19:00 = 19:00 in the time zone of -Region, the Azure region the install goes into
        (Get-SINightlyNewInstallSchedule; a region not known = Danish time, Europe/Copenhagen, and Line says so), whatever
        zone was answered; a start time of the customer's own = that time in the zone they gave (Get-SIInstallPipelineTimeZone).
        Returns @{ StartTime; TimeZone; Region; Known; Line }.
    #>
    param([AllowEmptyString()][string]$StartAnswer, [AllowEmptyString()][string]$ZoneAnswer, [TimeZoneInfo]$Local = [TimeZoneInfo]::Local,
          [AllowEmptyString()][string]$Region = '')
    $nz = Get-SINightlyNewInstallSchedule -Region $Region
    $t = "$StartAnswer".Trim()
    if (-not $t -or $t -eq $nz.PipelineStart) { return [pscustomobject]@{ StartTime = $nz.PipelineStart; TimeZone = $nz.PipelineZone; Region = $nz.Region; Known = $nz.Known; Line = $nz.Line } }
    [pscustomobject]@{ StartTime = $t; TimeZone = (Get-SIInstallPipelineTimeZone -Answer $ZoneAnswer -Local $Local -Fallback $nz.PipelineZone); Region = $nz.Region; Known = $nz.Known; Line = '' }
}

function Save-SIInstallBundleKey {
    <#
        #240 / #417: the Invardia install key from the bundle (config.json installKey) -> the install's Key Vault
        (SI-Invardia-InstallKey), retried while a new role assignment settles. Never echoed. Returns $true when stored
        (and sets the fact installKeyStored); $false otherwise -- a bundle key is NEVER replaced by a claim.
    #>
    param([Parameter(Mandatory)]$Ctx, [int]$Tries = 18)
    if (-not $Ctx.InstallKey) { return $false }
    $ok = $false; $last = ''
    $sec = ConvertTo-SecureString -String ([string]$Ctx.InstallKey) -AsPlainText -Force
    # ONLY the vault's refusal of a right granted a minute ago is waited for (20 s steps, about 6 minutes); any other
    # failure -- a vault that is not there, a bad name -- stops at once with its own reason
    foreach ($try in 1..$Tries) {
        try { $null = Invoke-SIInstallAz -Ctx $Ctx -Command 'Set-SIAzKeyVaultSecret' -Arguments ([ordered]@{ VaultName = $Ctx.Names.KeyVault; Name = 'SI-Invardia-InstallKey'; SecretValue = $sec; ErrorAction = 'Stop' }); $ok = $true; break }
        catch {
            $last = $_.Exception.Message
            if (-not (Test-SIAccessNotYetAnswer -Text $last)) { break }
            if ($try -lt $Tries) { & $Ctx.Seams.Sleep 20 }
        }
    }
    $sec = $null
    if ($ok) { $Ctx.Facts['installKeyStored'] = $true; $Ctx.Facts['installKeySha256'] = Get-SIInstallKeyHash ([string]$Ctx.InstallKey) }
    else { $Ctx.Facts['lastSecretError'] = (Protect-SIInstallText $last) }
    $ok
}

function Get-SIInstallKeyHash {
    <# PURE. #479: the SHA-256 (hex) of an install key -- kept in the state to tell a NEW key from the stored one, never the key. #>
    param([AllowEmptyString()][string]$Key)
    if (-not $Key) { return '' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Key)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}

function Get-SIInstallKeyRotation {
    <#
        #479: every enrollment claim issues a NEW install key and stops the previous one -- the install keeps only the
        LAST. On a resume whose config.json carries a different key than the one an earlier run stored (its hash in the
        state), the key is stored again: returns the completed steps to run again (key-vault) and clears installKeyStored.
        A key from before the hash was recorded counts as different (storing the same value again is harmless).
        Clears installKeyStored in -Facts when the key is new. Returns @{ Rotated; Completed }.
    #>
    param([AllowEmptyString()][string]$InstallKey, [AllowNull()][System.Collections.IDictionary]$Facts, [AllowEmptyCollection()][string[]]$Completed = @())
    $none = [pscustomobject]@{ Rotated = $false; Completed = @($Completed) }
    if (-not $InstallKey -or $null -eq $Facts -or -not [bool]$Facts['installKeyStored']) { return $none }
    if ([string]$Facts['installKeySha256'] -eq (Get-SIInstallKeyHash $InstallKey)) { return $none }
    $Facts['installKeyStored'] = $false
    [pscustomobject]@{ Rotated = $true; Completed = @($Completed | Where-Object { $_ -ne 'key-vault' }) }
}

function Get-SIInstallMailbox {
    <# PURE. The shared mailbox: the answer mailFrom, else SecurityInsight@<the installer's sign-in domain>; '' when unknown. #>
    param([Parameter(Mandatory)]$Ctx)
    $a = "$($Ctx.Values['mailFrom'])".Trim()
    if ($a) { return $a }
    $upn = "$($Ctx.Facts['userPrincipalName'])".Trim()
    if ($upn -match '@([^@\s]+\.[^@\s]+)$') { return ('SecurityInsight@{0}' -f $Matches[1]) }
    ''
}

function Get-SIInstallMailRecipients {
    <# PURE. The report recipients: the answer mailTo, else the person installing. #>
    param([Parameter(Mandatory)]$Ctx)
    $to = @(@($Ctx.Values['mailTo']) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if ($to.Count) { return $to }
    $upn = "$($Ctx.Facts['userPrincipalName'])".Trim()
    if ($upn -match '@') { return @($upn) }
    @()
}

function Update-SIInstallConfigFile {    <#
        config\SecurityInsight.custom.ps1 -- what the engines, Bootstrap and Grant-SIIdentity read. The body is written by
        the product's own Write-SICustomConfig (managed identity, no SPN, no secret; -Merge keeps every value an existing
        file already has); the guided-install block carries the rest (Key Vault, identity, Pro database, web app).
    #>
    param([Parameter(Mandatory)]$Ctx, [switch]$BlockOnly)
    $v = $Ctx.Values
    if (-not $BlockOnly) {
        $infra = Get-SIInstallInfra -Ctx $Ctx
        $a = [ordered]@{
            OutputPath = $Ctx.ConfigPath
            Spn   = [pscustomobject]@{ AppId = ''; TenantId = [string]$v['tenantId']; ObjectId = ''; CredKind = 'ManagedIdentity'; ManagedIdentityId = [string]$Ctx.Facts['identityClientId'] }
            Infra = [pscustomobject]$infra
        }
        if ($v['securityWorkspaceId']) { $a.DefenderWorkspaceResourceId = [string]$v['securityWorkspaceId'] }
        if ([bool]$v['aiClassification']) { $a.OpenAi = @{ Endpoint = [string]$v['openAiEndpoint']; Deployment = [string]$v['openAiDeployment'] } }
        if ([string]$v['mailMode'] -eq 'smtp') {
            $to = @(Get-SIInstallMailRecipients -Ctx $Ctx)
            $a.Smtp = @{ Server = [string]$v['smtpServer']; Port = [int]$v['smtpPort']; User = [string]$v['smtpUser']; From = [string]$v['smtpFrom']; MailTo = $to; SummaryTo = $to; DetailedTo = $to }
        }
        if (Test-Path -LiteralPath $Ctx.ConfigPath) { $a.Merge = $true }
        $r = Invoke-SIInstallScript -Ctx $Ctx -RelativePath 'setup/ConfigWizard/backend/Write-SICustomConfig.ps1' -Arguments $a
        if ($r.Error) { throw (New-SIInstallFailure -Message ('Writing the SecurityInsight configuration failed: {0}' -f $r.Error)) }
    }
    $s = [ordered]@{
        SI_InstallId                     = $Ctx.InstallId
        # The install's own answers, in the block at the END of the file, so they win over anything earlier in it: a
        # kept (merged) value from an older file never moves the subscription, the region or the sign-in.
        SI_AzSubscriptionId              = [string]$v['subscriptionId']
        SI_Bootstrap_SubscriptionId      = [string]$v['subscriptionId']
        SI_Location                      = [string]$v['location']
        AutomationFramework              = $false
        SI_KeyVaultName                  = $Ctx.Names.KeyVault
        SI_AuthMethod                    = 'ManagedIdentity'
        SI_Bootstrap_UseManagedIdentity  = $true
        SI_Bootstrap_ManagedIdentityName = $Ctx.Names.ManagedIdentity
        SI_Bootstrap_IdentityReaderScopes = @(Get-SIInstallReaderScopes -Values $v)
    }
    # CR5 step 2 (#655): a tagging identity that is not today's name is written down, so Bootstrap, the web app's permission
    # fix (Get Started) and every later setup run find it by the install's own setting; today's name stays unwritten
    $tagName = Get-SISetupComponentName -Names $Ctx.Names -Key TaggingIdentity
    if ($tagName -cne [string](Get-SISetupComponentNames)['TaggingIdentity']) { $s['SI_Bootstrap_TaggingIdentityName'] = $tagName }
    # #306: the daily pipeline's start time and time zone -- the default 23:30 in the local time of the install's Azure region
    # (owner 2026-10-15; a region not known: Danish time, said once); a time the customer chose, in the zone they gave
    # (pre-filled from this machine). The folder's marker says the nightly schedule is set, so the update moves nothing.
    $ps = Get-SIInstallPipelineSchedule -StartAnswer ([string]$v['pipelineStartTime']) -ZoneAnswer ([string]$v['pipelineTimeZone']) -Region ([string]$v['location'])
    $s['SI_Pipeline_StartTime'] = $ps.StartTime
    $s['SI_Pipeline_TimeZone'] = $ps.TimeZone
    if ($ps.Line -and -not $Ctx.Facts['nightlyRegionSaid']) { Write-SIInstallConsole -Ctx $Ctx -Text $ps.Line -Color Yellow; $Ctx.Facts['nightlyRegionSaid'] = $true }
    try {
        $cfgDir = Split-Path -Parent ([string]$Ctx.ConfigPath)
        if ($cfgDir -and (Split-Path -Leaf $cfgDir) -eq 'config') { $null = Set-SINightlyInstallMarkerFile -Root (Split-Path -Parent $cfgDir) -Marker (Get-SINightlyNewInstallSchedule -Region ([string]$v['location'])).Marker }
    } catch { }
    # MAIL-1: how every mail is sent (install parameter mailMode; the older 'mail' bool maps to smtp / none)
    $mm = if ([string]$v['mailMode']) { [string]$v['mailMode'] } else { 'none' }
    $s['SI_Mail_Mode'] = $mm
    if ($mm -eq 'sharedMailbox') {
        $box = Get-SIInstallMailbox -Ctx $Ctx
        if ($box) { $s['SI_Mail_From'] = $box }
        if ([string]$Ctx.Facts['userPrincipalName'] -and [string]$Ctx.Facts['userPrincipalName'] -ne $box -and -not (Test-SIInstallSignedInAsApp -Ctx $Ctx)) { $s['SI_Mail_ProbeMailbox'] = [string]$Ctx.Facts['userPrincipalName'] }
        $to = @(Get-SIInstallMailRecipients -Ctx $Ctx)
        if ($to.Count) { $s['SendMail'] = $true; $s['MailTo'] = $to; $s['RiskAnalysis_Summary_SendMail'] = $true; $s['RiskAnalysis_Summary_To'] = $to; $s['RiskAnalysis_Detailed_SendMail'] = $true; $s['RiskAnalysis_Detailed_To'] = $to }
    }
    if ($Ctx.Facts['identityClientId']) { $s['SI_ManagedIdentityClientId'] = [string]$Ctx.Facts['identityClientId']; $s['SI_SPN_ManagedIdentityClientId'] = [string]$Ctx.Facts['identityClientId'] }
    if (($Ctx.Data -or $Ctx.Pro) -and (Get-Command -Name Get-SIInstallProConfigSettings -ErrorAction SilentlyContinue)) {
        $pro = Get-SIInstallProConfigSettings -Ctx $Ctx
        foreach ($k in $pro.Keys) { $s[$k] = $pro[$k] }
    }
    Set-SIInstallConfigBlock -Path $Ctx.ConfigPath -Settings $s
    # every write of the settings file is also kept with the install's state (a resume in another package copy reads it there)
    $null = Save-SIInstallConfigCopy -Ctx $Ctx
}

# ---------------------------------------------------------------------------------------------------------------
# The steps of every install (the database and web app ones are in SI-GuidedInstallData.ps1, the paid ones in SI-GuidedInstallPro.ps1)
# ---------------------------------------------------------------------------------------------------------------
function Get-SIInstallFlowStartBody {
    <#
        PURE. The body of ARM's Container Apps job /start for ONE execution: the job's own container (name, image, command,
        args, cpu / memory) and ITS environment -- every variable kept, secret references included -- with -Env added or
        replacing a variable of the same name. Never only the new variables: an execution template REPLACES the container's
        environment.
    #>
    param([Parameter(Mandatory)]$Container, [System.Collections.IDictionary]$Env = @{})
    $vars = New-Object System.Collections.Generic.List[object]
    foreach ($e in @(Get-SIInstallProp $Container 'env')) {
        if (-not $e) { continue }
        $n = [string](Get-SIInstallProp $e 'name')
        if (-not $n -or $Env.Contains($n)) { continue }
        $sr = [string](Get-SIInstallProp $e 'secretRef')
        if ($sr) { $vars.Add([ordered]@{ name = $n; secretRef = $sr }) } else { $vars.Add([ordered]@{ name = $n; value = [string](Get-SIInstallProp $e 'value') }) }
    }
    foreach ($k in $Env.Keys) { $vars.Add([ordered]@{ name = [string]$k; value = [string]$Env[$k] }) }
    $c = [ordered]@{ name = [string](Get-SIInstallProp $Container 'name'); image = [string](Get-SIInstallProp $Container 'image'); env = $vars.ToArray() }
    $cmd = @(Get-SIInstallProp $Container 'command' | Where-Object { $null -ne $_ }); if ($cmd.Count) { $c.command = $cmd }
    $arg = @(Get-SIInstallProp $Container 'args' | Where-Object { $null -ne $_ }); if ($arg.Count) { $c.args = $arg }
    $res = Get-SIInstallProp $Container 'resources'
    if ($res) { $c.resources = [ordered]@{ cpu = Get-SIInstallProp $res 'cpu'; memory = [string](Get-SIInstallProp $res 'memory') } }
    [ordered]@{ containers = @($c) }
}

function Get-SIInstallStepTable {
    $t = @{}

    $t['preflight-signin'] = {
        param($ctx)
        $tid = [string]$ctx.Values['tenantId']; $sub = [string]$ctx.Values['subscriptionId']
        # An Azure sign-in already in this PowerShell session (same tenant) is reused; otherwise the install signs the
        # person in itself -- Azure Cloud Shell with no prompt, a workstation in the browser. No PowerShell module.
        $c = $null; try { $c = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SISetupAzureContext' } catch { }
        $cTid = [string](Get-SIInstallProp (Get-SIInstallProp $c 'Tenant') 'Id')
        $signedInNow = $false
        # #876: a FRESH hand-over from the installation page (SI_HANDOFF_TOKENS) always replaces an earlier sign-in of this
        # process (a resume in the same shell) -- an Invardia Support session in the shell still wins (Connect-SISetupAzure)
        $freshHandoff = [bool]("$([Environment]::GetEnvironmentVariable('SI_HANDOFF_TOKENS'))".Trim())
        if (-not $c -or -not (Get-SIInstallProp $c 'Account') -or ($cTid -and $tid -and $cTid -ne $tid) -or $freshHandoff) {
            $ca = [ordered]@{ TenantId = $tid; SubscriptionId = $sub; ErrorAction = 'Stop' }
            if ($freshHandoff) { $ca['Force'] = $true }
            try { $c = Invoke-SIInstallAz -Ctx $ctx -Command 'Connect-SISetupAzure' -Arguments $ca }
            catch {
                throw (New-SIInstallFailure -Message ('The Azure sign-in did not complete: {0}' -f $_.Exception.Message) `
                    -ActionText 'Run the same command again and complete the sign-in (in Azure Cloud Shell it is automatic; on a workstation a browser window opens):' -Command $ctx.ResumeCommand)
            }
            $signedInNow = $true
        }
        if (-not $c -or -not (Get-SIInstallProp $c 'Account')) {
            throw (New-SIInstallFailure -Message 'You are not signed in to Azure in this PowerShell session.' -ActionText 'Run the same command again: it signs you in (in Azure Cloud Shell automatically, on a workstation in the browser).' -Command $ctx.ResumeCommand)
        }
        $acct = Get-SIInstallProp $c 'Account'
        $ctx.Facts['account'] = [string](Get-SIInstallProp $acct 'Id'); $ctx.Facts['accountType'] = [string](Get-SIInstallProp $acct 'Type')
        # #524: the Invardia support app, through the support session's TOKENS (Get-InvardiaSupportToken; SignInMethod
        # 'Support', app + tenant read from the token) -- an app is fine here: the operator chose that session on purpose.
        # #524: an existing Azure session of the process (the old 'AzContext' mode) is never used; any other app is refused.
        $ctx.Facts['signInMethod'] = [string](Get-SIInstallProp $c 'SignInMethod')
        $sessionText = $null
        if ($ctx.Facts['signInMethod'] -eq 'Handoff') {
            # #876: the sign-in the installation page handed over (SI_HANDOFF_TOKENS) -- nothing was signed in here. Every
            # token the install needs must be in it, for long enough to start: said now, before anything is created.
            $who = if (Test-SIInstallSignedInAsApp -Ctx $ctx) { 'the application {0}' -f $ctx.Facts['account'] } else { [string]$ctx.Facts['account'] }
            $sessionText = 'Using the sign-in handed over by the installation page ({0}, tenant {1}) -- nothing is signed in here' -f $who, [string](Get-SIInstallProp (Get-SIInstallProp $c 'Tenant') 'Id')
            $hc = Get-SIInstallHandoffCheck -Ctx $ctx
            if ($hc.Missing.Count) {
                throw (New-SIInstallFailure -Message ('The sign-in handed over by the installation page holds no token for {0}, which the install needs. Nothing was changed.' -f ($hc.Missing -join ', ')) `
                    -ActionText 'Restart the install from the installation page with a hand-over that includes these (the install resumes where it stopped):' -Command $ctx.ResumeCommand)
            }
            if ($hc.Expired.Count) {
                throw (New-SIInstallFailure -Message ((Get-SIHandoffExpiredText -Resource '') + ' Nothing was changed.') -ActionText 'Get a fresh code on the installation page, then run:' -Command $ctx.ResumeCommand)
            }
            if (Test-SIInstallSignedInAsApp -Ctx $ctx) {
                $miss = @(Get-SIInstallSupportMissingRoles -Ctx $ctx)
                if ($miss.Count) {
                    throw (New-SIInstallFailure -Message ('The application the install runs as cannot set SecurityInsight up in this tenant: its Microsoft Graph permissions lack {0}. Nothing was changed.' -f ($miss -join ', ')) `
                        -ActionText 'Give the application these Microsoft Graph application permissions (an administrator of the tenant), then run the same command again:' -Command $ctx.ResumeCommand)
                }
            }
        }
        if ($ctx.Facts['signInMethod'] -eq 'Support') {
            $sessionText = 'Signed in as the Invardia support app {0} for tenant {1}' -f $ctx.Facts['account'], [string](Get-SIInstallProp (Get-SIInstallProp $c 'Tenant') 'Id')
            # #564 (Invardia, customer I 2026-10-10): the support app must have SETUP access before anything is written -- never a
            # half-done install. Its Microsoft Graph token's roles claim must hold the two permissions the grants need.
            $miss = @(Get-SIInstallSupportMissingRoles -Ctx $ctx)
            if ($miss.Count) {
                throw (New-SIInstallFailure -Message ('The Invardia support app has no Setup access in this tenant: its Microsoft Graph permissions lack {0}. Nothing was changed.' -f ($miss -join ', ')) `
                    -ActionText 'The support app needs Setup access: re-run New-InvardiaSupportApp -Access Setup in this tenant (an admin of the tenant), then run the same command again:' -Command $ctx.ResumeCommand)
            }
            # An Invardia Support session is accepted for ITS environment only: the install's tenant and subscription must be
            # the ones it was opened for. (#521: no az CLI profile is involved any more -- every call takes the session's tokens.)
            if ($env:INVARDIA_SUPPORT_ENVIRONMENT -and $ctx.Facts['accountType'] -ne 'User') {
                $why = @()
                if ($env:INVARDIA_SUPPORT_TENANT -and $tid -and $env:INVARDIA_SUPPORT_TENANT -ne $tid) { $why += ('the support session is for tenant {0}, the install is for {1}' -f $env:INVARDIA_SUPPORT_TENANT, $tid) }
                $subs = @(([string]$env:INVARDIA_SUPPORT_SUBSCRIPTIONS) -split '[,;\s]+' | Where-Object { $_ })
                if ($subs.Count -and $sub -and $subs -notcontains $sub) { $why += ('subscription {0} is not one the support session was opened for ({1})' -f $sub, ($subs -join ', ')) }
                if ($why.Count) {
                    throw (New-SIInstallFailure -Message ('The Invardia Support session ({0}) does not match this install: {1}.' -f $env:INVARDIA_SUPPORT_ENVIRONMENT, ($why -join '; ')) `
                        -ActionText 'Connect to the customer''s own support environment (Connect-InvardiaSupport -Environment <handle> -Reason ''<why>'' or -Ticket <id>) in this shell, then run the same command again:' -Command $ctx.ResumeCommand)
                }
            }
        }
        if ($ctx.Facts['accountType'] -and $ctx.Facts['accountType'] -ne 'User' -and -not $sessionText) {
            throw (New-SIInstallFailure -Message ('The guided install runs as a person, but this PowerShell session is signed in to Azure as an app or a managed identity ({0}).' -f $ctx.Facts['account']) `
                -ActionText 'Open a new PowerShell session (or Azure Cloud Shell) as yourself and run the same command again: it signs you in.' -Command $ctx.ResumeCommand)
        }
        # #521: nothing else to sign in -- the install calls no az CLI; every Azure call uses this one sign-in.
        if ($sessionText) {
            # the web app's sign-in permissions are consented to for the organisation by the install -- said NOW when the
            # support app cannot do that (a warning, never a stop: the web app step then says what an administrator does)
            if (($ctx.Data -or $ctx.Pro) -and [bool]$ctx.Values['webApp'] -and -not (Test-SIInstallSupportCanConsent -Ctx $ctx)) {
                $ctx.Facts['supportCannotConsent'] = $true
                return (New-SIInstallResult -State 'warning' -Message ($sessionText + '. It cannot consent to the web app''s sign-in permissions for the organisation (its Microsoft Graph permissions lack DelegatedPermissionGrant.ReadWrite.All): in a tenant that does not let users consent, the first sign-in to the web app will say "Approval required" until an administrator grants admin consent. The install goes on and says so again at the web app step.') `
                    -Action ([ordered]@{ text = 'Nothing to do now. To avoid it, give the support app that permission before the install (New-InvardiaSupportApp -Access Setup, by an admin of the tenant).'; command = $null }))
            }
            return (New-SIInstallResult -Message ($sessionText + '.'))
        }
        New-SIInstallResult -Message ('{0} to Azure (as a person).' -f $(if ($signedInNow) { 'Signed in' } else { 'Already signed in' }))
    }

    $t['preflight-target'] = {
        param($ctx)
        $tid = [string]$ctx.Values['tenantId']; $sub = [string]$ctx.Values['subscriptionId']
        $cannotOpen = New-SIInstallFailure -Message ('Your account cannot open subscription {0} in tenant {1}.' -f $sub, $tid) `
            -ActionText 'Sign in with an account that has access to it (a new PowerShell session, or Azure Cloud Shell as that account), then run the same command again:' -Command $ctx.ResumeCommand
        $s = $null
        try {
            $null = Invoke-SIInstallAz -Ctx $ctx -Command 'Set-SIAzContext' -Arguments ([ordered]@{ Tenant = $tid; Subscription = $sub; ErrorAction = 'Stop' })
            $s = @(Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIAzSubscription' -Arguments ([ordered]@{ SubscriptionId = $sub; TenantId = $tid; ErrorAction = 'Stop' })) | Select-Object -First 1
        } catch { throw $cannotOpen }
        if (-not $s) { throw $cannotOpen }
        if ([string](Get-SIInstallProp $s 'State') -and [string](Get-SIInstallProp $s 'State') -ne 'Enabled') {
            throw (New-SIInstallFailure -Message ('Subscription {0} is {1}, not enabled.' -f $sub, (Get-SIInstallProp $s 'State')) -ActionText 'Choose an enabled subscription in the wizard.')
        }
        if ($ctx.Edition -eq 'pro') {
            if (-not $ctx.Pro) {
                throw (New-SIInstallFailure -Message 'This package is the Community edition, but the install was given a SecurityInsight Pro licence.' -ActionText 'Start the install from your installation page on invardia.com: it downloads the Pro package.')
            }
            $null = & $ctx.ProSteps['preflight-licence'] $ctx
        }
        New-SIInstallResult -Message ('Tenant {0}, subscription {1}.' -f $tid, $sub)
    }

    $t['preflight-rights'] = {
        param($ctx)
        $v = $ctx.Values; $sub = [string]$v['subscriptionId']; $rg = $ctx.Names.ResourceGroup
        $me = $null
        if ([string]$ctx.Facts['accountType'] -and [string]$ctx.Facts['accountType'] -ne 'User') {
            # #524: the Invardia support app -- its object id comes from its own token (#876: a handed-over application
            # sign-in likewise: the token's oid IS the service principal's object id)
            if ([string]$ctx.Facts['signInMethod'] -in 'Support', 'Handoff') {
                $oidApp = $null; try { $oidApp = [string](Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SISetupSignedInObjectId') } catch { }
                if ($oidApp) { $me = [pscustomobject]@{ Id = $oidApp; UserPrincipalName = [string]$ctx.Facts['account'] } }
            }
        }
        else { try { $me = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIGraphUser' -Arguments ([ordered]@{ SignedIn = $true; ErrorAction = 'Stop' }) } catch { } }
        if (-not $me -or -not (Get-SIInstallProp $me 'Id')) {
            throw (New-SIInstallFailure -Message 'Your account could not be read from Microsoft Entra ID. The guided install runs as a signed-in user.' `
                -ActionText 'Open a new PowerShell session (or Azure Cloud Shell) as yourself -- a user, not an app -- and run the same command again: it signs you in.' -Command $ctx.ResumeCommand)
        }
        $oid = [string](Get-SIInstallProp $me 'Id'); $ctx.Facts['userObjectId'] = $oid
        $ctx.Facts['userPrincipalName'] = [string](Get-SIInstallProp $me 'UserPrincipalName')
        $subId = '/subscriptions/{0}' -f $sub; $rgId = '{0}/resourceGroups/{1}' -f $subId, $rg
        # what the person holds in the subscription, directly AND through their groups
        $all = @(Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIRoleAssignmentAssignedTo' -Arguments ([ordered]@{ ObjectId = $oid; Scope = $subId; ErrorAction = 'SilentlyContinue' }))
        $isAncestor = { param($scope, $of) $s = "$scope".TrimEnd('/').ToLowerInvariant(); $o = "$of".ToLowerInvariant(); ($s -eq '' -or $o -eq $s -or $o.StartsWith($s + '/') -or $s -like '/providers/microsoft.management/managementgroups/*') }
        $atRg  = @($all | Where-Object { & $isAncestor (Get-SIInstallProp $_ 'Scope') $rgId } | ForEach-Object { [string](Get-SIInstallProp $_ 'RoleDefinitionName') })
        $atSub = @($all | Where-Object { & $isAncestor (Get-SIInstallProp $_ 'Scope') $subId } | ForEach-Object { [string](Get-SIInstallProp $_ 'RoleDefinitionName') })
        $canWrite = @($atRg | Where-Object { $script:SIInstallRoleWrite -contains $_ }).Count -gt 0
        $canRbac  = @($atRg | Where-Object { $script:SIInstallRoleRbac -contains $_ }).Count -gt 0
        $canSub   = @($atSub | Where-Object { $script:SIInstallRoleWrite -contains $_ }).Count -gt 0
        $custom   = @($atRg | Where-Object { $script:SIInstallRoleWrite -notcontains $_ -and $script:SIInstallRoleRbac -notcontains $_ -and $_ -notmatch '(?i)reader' })
        $ctx.Facts['canRegisterProviders'] = $canSub
        $rgExists = $null -ne (Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIAzResourceGroup' -Arguments ([ordered]@{ Name = $rg; ErrorAction = 'SilentlyContinue' }))
        $ctx.Facts['resourceGroupExisted'] = $rgExists
        # #564: what an Owner does by hand is an Azure portal path -- a customer has no az CLI (Get-SIInstallPortalText)
        if (-not $rgExists -and -not $canSub) {
            throw (New-SIInstallFailure -Message ('Resource group {0} does not exist, and your account cannot create it.' -f $rg) -ActionText (Get-SIInstallPortalText -Kind 'CreateResourceGroup' -Ctx $ctx) -Command $ctx.ResumeCommand)
        }
        if ((-not $canWrite -or -not $canRbac) -and -not $custom.Count) {
            $miss = @(); if (-not $canWrite) { $miss += 'Contributor' }; if (-not $canRbac) { $miss += 'Role Based Access Control Administrator' }
            $txt = if ($rgExists) { Get-SIInstallPortalText -Kind 'GrantRgAccess' -Ctx $ctx -Roles $miss } else { Get-SIInstallPortalText -Kind 'CreateResourceGroup' -Ctx $ctx }
            throw (New-SIInstallFailure -Message ('Your account needs {0} on resource group {1}.' -f ($miss -join ' and '), $rg) -ActionText $txt -Command $ctx.ResumeCommand)
        }
        # What the install will hand to someone else (it does not stop for these).
        $handoff = @()
        $outsideScopes = @(Get-SIInstallReaderScopes -Values $v); if ($v['securityWorkspaceId']) { $outsideScopes += [string]$v['securityWorkspaceId'] }
        $canOutside = $true
        foreach ($sc in $outsideScopes) {
            $roles = @(Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIRoleAssignmentAssignedTo' -Arguments ([ordered]@{ ObjectId = $oid; Scope = $subId; ErrorAction = 'SilentlyContinue' }) |
                Where-Object { & $isAncestor (Get-SIInstallProp $_ 'Scope') $sc } | ForEach-Object { [string](Get-SIInstallProp $_ 'RoleDefinitionName') })
            if (-not @($roles | Where-Object { $script:SIInstallRoleRbac -contains $_ }).Count) { $canOutside = $false }
        }
        if (-not $canOutside) { $handoff += 'read access outside the resource group (an Owner or User Access Administrator there)' }
        $isAdmin = $false
        $isApp = Test-SIInstallSignedInAsApp -Ctx $ctx
        try {
            # A person: their directory roles. An app (#413, e.g. the Invardia Support app -- live 2026-10-06, Community
            # rehearsal: /me does not exist for an app, so the check always said "hand it to someone"): ITS directory roles.
            $drUri = if ($isApp) { 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}/transitiveMemberOf/microsoft.graph.directoryRole?$select=roleTemplateId' -f $oid } else { 'https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=roleTemplateId' }
            $dr = Invoke-SIInstallGraph -Ctx $ctx -Uri $drUri
            $isAdmin = @(@(Get-SIInstallProp $dr 'value') | Where-Object { $script:SIInstallDirectoryAdminRoles.ContainsKey([string](Get-SIInstallProp $_ 'roleTemplateId')) }).Count -gt 0
        } catch { }
        if (-not $isAdmin -and $isApp) {
            # ...or the Microsoft Graph application permission that grants app roles (AppRoleAssignment.ReadWrite.All,
            # or RoleManagement.ReadWrite.Directory) -- what Grant-SIIdentity needs to give SecurityInsight's identity
            # its read-only Graph and Defender permissions.
            try {
                $ar = Invoke-SIInstallGraph -Ctx $ctx -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments?$select=appRoleId,resourceId' -f $oid)
                $isAdmin = @(@(Get-SIInstallProp $ar 'value') | Where-Object { $script:SIInstallGraphGrantAppRoles -contains [string](Get-SIInstallProp $_ 'appRoleId') }).Count -gt 0
            } catch { }
        }
        if (-not $isAdmin) { $handoff += 'read-only Microsoft Graph and Defender permissions (a Privileged Role Administrator)' }
        $ctx.Facts['canGrantOutside'] = $canOutside; $ctx.Facts['isDirectoryAdmin'] = $isAdmin
        # #876: an install that runs as an APPLICATION has no person to make the web app's first administrator: the people
        # named for it must exist in the directory -- checked NOW, before anything is created (it used to stop at the web
        # app step, an hour into the install)
        $null = Assert-SIInstallWebAppAdmins -Ctx $ctx
        # #876: the shared mailbox needs Exchange Online -- read from the tenant's subscriptions now, so a tenant without it
        # is told plainly (information) instead of a mail step that warns at the end
        $exoNote = ''
        if ([string]$v['mailMode'] -eq 'sharedMailbox') {
            $exo = Get-SIInstallExchangeOnline -Ctx $ctx
            $ctx.Facts['exchangeOnline'] = $exo
            if ($exo -eq $false) { $exoNote = ' ' + (Get-SIInstallNoExchangeText) }
        }
        $msg = 'You can install SecurityInsight in {0}.' -f $rg
        if ($custom.Count -and (-not $canWrite -or -not $canRbac)) { $msg += ' Your access there comes from a custom role, so it could not be confirmed in advance.' }
        $msg += $exoNote
        if ($handoff.Count) {
            return (New-SIInstallResult -State 'warning' -Message ($msg + ' The install will hand these to someone else, with the exact command: ' + ($handoff -join '; ') + '.') `
                -Action ([ordered]@{ text = 'Nothing to do now: the install continues and shows the commands at the end.'; command = $null }))
        }
        New-SIInstallResult -Message $msg
    }

    $t['preflight-providers'] = {
        param($ctx)
        # #564: every resource provider the install WRITES to (one list, Get-SISetupResourceProviderList)
        # Azure SQL in every install with the database (both versions, owner 2026-10-18)
        $need = @(Get-SISetupResourceProviderList -Pro:([bool]$ctx.Data -or [bool]$ctx.Pro -or $ctx.Edition -eq 'pro'))
        $missing = @()
        foreach ($ns in $need) {
            $p = @(Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIResourceProvider' -Arguments ([ordered]@{ ProviderNamespace = $ns; ErrorAction = 'SilentlyContinue' }))
            if (-not @($p | Where-Object { [string](Get-SIInstallProp $_ 'RegistrationState') -eq 'Registered' }).Count) { $missing += $ns }
        }
        $ctx.Facts['providersToRegister'] = $missing
        if (-not $missing.Count) { return (New-SIInstallResult -Message 'Every resource provider SecurityInsight needs is registered.') }
        if ([bool]$ctx.Facts['canRegisterProviders']) { return (New-SIInstallResult -Message ('Not registered yet, the install registers them: {0}.' -f ($missing -join ', '))) }
        throw (New-SIInstallFailure -Message ('These resource providers are not registered, and your account cannot register them: {0}.' -f ($missing -join ', ')) `
            -ActionText (Get-SIInstallPortalText -Kind 'RegisterProviders' -Ctx $ctx -Names $missing) -Command $ctx.ResumeCommand)
    }

    $t['preflight-names'] = {
        param($ctx)
        $v = $ctx.Values; $sub = [string]$v['subscriptionId']
        # An existing install keeps its storage / Key Vault / registry / SQL server names; a new one gets the suffixed names.
        $keptNames = @(Resolve-SIInstallExistingNames -Ctx $ctx)
        $n = $ctx.Names
        $problems = @(); $cmds = @()
        # A name check is answered by its resource provider: before that provider is registered on the subscription, ARM
        # answers checkNameAvailability with "SubscriptionNotFound" (live 2026-10-06, the Community rehearsal in a fresh
        # tenant). The install registers the provider itself (preflight-providers), so such a name is checked when it is
        # created instead -- never a failed preflight.
        $unreg = @($ctx.Facts['providersToRegister'] | Where-Object { $_ })
        $later = @()
        if ($unreg -contains 'Microsoft.Storage') { $later += $n.StorageAccount }
        if ($unreg -contains 'Microsoft.KeyVault') { $later += $n.KeyVault }
        if ($unreg -contains 'Microsoft.ContainerRegistry') { $later += $n.Acr }
        if (($ctx.Data -or $ctx.Pro) -and $unreg -contains 'Microsoft.Sql') { $later += $n.SqlServer }
        # storage account
        $sa = $null
        if ($later -notcontains $n.StorageAccount) { $sa = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIAzStorageAccount' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; Name = $n.StorageAccount; ErrorAction = 'SilentlyContinue' }) }
        if (-not $sa -and $later -notcontains $n.StorageAccount) {
            $av = Invoke-SIInstallAz -Ctx $ctx -Command 'Test-SIStorageAccountNameAvailability' -Arguments ([ordered]@{ Name = $n.StorageAccount; SubscriptionId = $sub; ErrorAction = 'SilentlyContinue' })
            if ($av -and -not [bool](Get-SIInstallProp $av 'NameAvailable')) { $problems += (Get-SIInstallNameTakenText -Ctx $ctx -What 'storage account' -Name $n.StorageAccount -Type $script:SIInstallGlobalNameTypes.StorageAccount) }
        }
        # Key Vault (a deleted vault keeps its name until it is purged)
        $kv = $null
        if ($later -notcontains $n.KeyVault) { $kv = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIKeyVault' -Arguments ([ordered]@{ VaultName = $n.KeyVault; ErrorAction = 'SilentlyContinue' }) }
        if ($later -contains $n.KeyVault) { }
        elseif ($kv) {
            if ([string](Get-SIInstallProp $kv 'ResourceGroupName') -ne $n.ResourceGroup) { $problems += ('the Key Vault name {0} is used by another resource group' -f $n.KeyVault) }
        } else {
            $chk = Invoke-SIInstallAz -Ctx $ctx -Command 'Test-SIKeyVaultNameAvailability' -Arguments ([ordered]@{ Name = $n.KeyVault; SubscriptionId = $sub; ErrorAction = 'SilentlyContinue' })
            if ($chk -and -not [bool](Get-SIInstallProp $chk 'NameAvailable')) {
                $deleted = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIKeyVault' -Arguments ([ordered]@{ VaultName = $n.KeyVault; Location = [string]$v['location']; InRemovedState = $true; ErrorAction = 'SilentlyContinue' })
                if ($deleted) { $problems += ('a deleted Key Vault still holds the name {0}' -f $n.KeyVault); $cmds += $n.KeyVault }
                else { $problems += (Get-SIInstallNameTakenText -Ctx $ctx -What 'Key Vault' -Name $n.KeyVault -Type $script:SIInstallGlobalNameTypes.KeyVault) }
            }
        }
        # container registry
        $acr = $null
        if ($later -notcontains $n.Acr) { $acr = (Invoke-SIInstallArmTry -Ctx $ctx -Command 'Get-SIContainerRegistry' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; Name = $n.Acr })).Value }
        if (-not $acr -and $later -notcontains $n.Acr) {
            $chk = (Invoke-SIInstallArmTry -Ctx $ctx -Command 'Test-SIContainerRegistryName' -Arguments ([ordered]@{ Name = $n.Acr })).Value
            if ($chk -and -not [bool](Get-SIInstallProp $chk 'nameAvailable')) { $problems += (Get-SIInstallNameTakenText -Ctx $ctx -What 'container registry' -Name $n.Acr -Type $script:SIInstallGlobalNameTypes.Acr) }
        }
        # the existing workspace (v1: in SecurityInsight's resource group)
        if ([string]$v['workspaceMode'] -eq 'existing') {
            $ws = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIAzOperationalInsightsWorkspace' -Arguments ([ordered]@{ ResourceGroupName = $n.WorkspaceResourceGroup; Name = $n.Workspace; ErrorAction = 'SilentlyContinue' })
            if (-not $ws) { $problems += ('the workspace {0} was not found, or your account cannot read it' -f $v['workspaceId']) }
            elseif ($n.WorkspaceResourceGroup -ne $n.ResourceGroup) {
                $problems += ('an existing workspace must be in SecurityInsight''s resource group (it is in {0}): choose "Create a dedicated workspace", or set the resource group to {0}' -f $n.WorkspaceResourceGroup)
            }
        }
        if (($ctx.Data -or $ctx.Pro) -and $ctx.ProSteps.Contains('preflight-names-pro')) { $pp = & $ctx.ProSteps['preflight-names-pro'] $ctx; $problems += @($pp) }
        if ($problems.Count) {
            throw (New-SIInstallFailure -Message ('Names: {0}.' -f ($problems -join '; ')) `
                -ActionText $(if ($cmds.Count) { Get-SIInstallPortalText -Kind 'PurgeKeyVault' -Ctx $ctx -Names $cmds } else { 'Choose another resource group name in the wizard: the other names follow it.' }) `
                -Command $(if ($cmds.Count) { $ctx.ResumeCommand } else { $null }))
        }
        Save-SIInstallNames -Ctx $ctx
        $all = @($n.ResourceGroup, $n.StorageAccount, $n.KeyVault, $n.Acr) + @(if ($ctx.Data -or $ctx.Pro) { $n.SqlServer })
        $keptNote = if ($keptNames.Count) { (' Kept the names of the existing install: {0}.' -f ($keptNames -join ', ')) } else { '' }
        if ($later.Count) {
            $checked = @($all | Where-Object { $later -notcontains $_ })
            return (New-SIInstallResult -Message ('Names are free or already this install''s: {0}. Checked when they are created, after the install registers their resource provider: {1}.{2}' -f ($checked -join ', '), ($later -join ', '), $keptNote))
        }
        New-SIInstallResult -Message ('Names are free or already this install''s: {0}.{1}' -f ($all -join ', '), $keptNote)
    }

    # #876: the region is asked of Azure BEFORE anything is created (a workspace refused in the default region was found
    # only when it was created, 2026-10-12): every resource type SecurityInsight creates, from the providers' own location
    # lists, the storage SKUs' restrictions for this subscription and the regions the subscription may use. A refusal
    # stops here with one line -- which resource, which region, which regions would work. What Azure's metadata cannot
    # tell (a type it lists no regions for) is checked when that resource is created; that is said, never a stop.
    $t['preflight-region'] = {
        param($ctx)
        $sub = [string]$ctx.Values['subscriptionId']
        $needs = @(Get-SIInstallRegionNeeds -Ctx $ctx)
        $prov = @{}
        foreach ($ns in @($needs | ForEach-Object { $_.Namespace } | Select-Object -Unique)) {
            $d = Invoke-SIInstallArmGetJson -Ctx $ctx -Path ('/subscriptions/{0}/providers/{1}?api-version=2021-04-01' -f $sub, $ns)
            if ($d) { $prov[$ns] = $d }
        }
        $skus = @(); $sk = Invoke-SIInstallArmGetJson -Ctx $ctx -Path ('/subscriptions/{0}/providers/Microsoft.Storage/skus?api-version=2023-01-01' -f $sub); if ($sk) { $skus = @(Get-SIInstallProp $sk 'value') }
        $regs = @(); $rl = Invoke-SIInstallArmGetJson -Ctx $ctx -Path ('/subscriptions/{0}/locations?api-version=2022-12-01' -f $sub); if ($rl) { $regs = @(Get-SIInstallProp $rl 'value') }
        $r = Test-SIInstallRegionOffer -Needs $needs -Providers $prov -StorageSkus $skus -SubscriptionRegions $regs
        if ($r.Refused.Count) {
            $what = @($r.Refused | ForEach-Object { '{0} in {1}' -f $_.Label, $_.Location })
            $alt = if ($r.Alternatives.Count) { ' Regions that accept every SecurityInsight resource for this subscription: {0}.' -f ($r.Alternatives -join ', ') } else { '' }
            throw (New-SIInstallFailure -Message ('Azure does not accept {0} for this subscription.{1} Nothing was changed.' -f ($what -join '; '), $alt) `
                -ActionText 'Choose one of those regions on the installation page (Azure region), then run the install command again:' -Command $ctx.ResumeCommand)
        }
        $regions = @($needs | ForEach-Object { $_.Location } | Select-Object -Unique)
        if ($r.Unknown.Count) {
            return (New-SIInstallResult -Message ('{0} accepts what Azure lists for this subscription; checked when created: {1}.' -f ($regions -join ' and '), ($r.Unknown -join ', ')))
        }
        New-SIInstallResult -Message ('{0} accepts every resource SecurityInsight creates.' -f ($regions -join ' and '))
    }

    # #876: the subscription's quota in the region, before anything is created: one Container Apps environment more (when the
    # install has none yet) and, when it has one, enough cores in it for what SecurityInsight's own sizing sets.
    $t['preflight-quota'] = {
        param($ctx)
        $v = $ctx.Values; $n = $ctx.Names; $sub = [string]$v['subscriptionId']
        $loc = ConvertTo-SIInstallRegionKey ([string]$v['location'])
        $need = $null
        try { $need = Get-SIInstallQuotaNeed -SIRoot $ctx.SIRoot -Jobs (@($ctx.Engines).Count + 1) -WebApp:([bool](($ctx.Data -or $ctx.Pro) -and [bool]$v['webApp'])) } catch { $need = $null }
        $envPath = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/managedEnvironments/{2}' -f $sub, $n.ResourceGroup, $n.ContainerEnv
        $env = Invoke-SIInstallArmGetJson -Ctx $ctx -Path ($envPath + '?api-version=2024-03-01')
        $hasEnv = [bool]($env -and [string](Get-SIInstallProp $env 'id'))
        $lines = @()
        if (-not $hasEnv) {
            $u = Invoke-SIInstallArmGetJson -Ctx $ctx -Path ('/subscriptions/{0}/providers/Microsoft.App/locations/{1}/usages?api-version=2024-03-01' -f $sub, $loc)
            $row = @(@(Get-SIInstallProp $u 'value') | Where-Object { [string](Get-SIInstallProp (Get-SIInstallProp $_ 'name') 'value') -eq 'ManagedEnvironmentCount' }) | Select-Object -First 1
            if (-not $row) { $lines += 'Container Apps environments: the quota could not be read -- checked when the environment is created' }
            else {
                $cur = [double](Get-SIInstallProp $row 'currentValue'); $lim = [double](Get-SIInstallProp $row 'limit')
                if ($cur + 1 -gt $lim) {
                    throw (New-SIInstallFailure -Message ('The subscription has no room for another Container Apps environment in {0}: it uses {1} of its {2}, and SecurityInsight needs one more. Nothing was changed.' -f $loc, $cur, $lim) `
                        -ActionText ('Ask for a higher quota (Azure portal: Quotas > Container Apps > {0} > Managed environment count), or choose another region on the installation page, then run the install command again:' -f $loc) -Command $ctx.ResumeCommand)
                }
                $lines += ('Container Apps environments: {0} of {1} in use, one more fits' -f $cur, $lim)
            }
        }
        if ($need) {
            if ($hasEnv) {
                $u = Invoke-SIInstallArmGetJson -Ctx $ctx -Path ($envPath + '/usages?api-version=2024-03-01')
                $row = @(@(Get-SIInstallProp $u 'value') | Where-Object { [string](Get-SIInstallProp (Get-SIInstallProp $_ 'name') 'value') -match '(?i)ConsumptionCores|^Cores$' }) | Select-Object -First 1
                if ($row) {
                    $lim = [double](Get-SIInstallProp $row 'limit')
                    if ($lim -lt $need.Cores) {
                        throw (New-SIInstallFailure -Message ('The Container Apps environment {0} may use {1} cores, and SecurityInsight can use {2} at once ({3} jobs at {4} CPU each{5}). Nothing was changed.' -f $n.ContainerEnv, $lim, $need.Cores, $need.Jobs, $need.JobCpu, $(if ($need.WebAppCpu) { (', and the web app at {0}' -f $need.WebAppCpu) } else { '' })) `
                            -ActionText ('Ask for a higher quota (Azure portal: Quotas > Container Apps > {0} > Managed Environment Consumption Cores) of at least {1}, then run the install command again:' -f $loc, $need.Cores) -Command $ctx.ResumeCommand)
                    }
                    $lines += ('the environment''s cores: {0} allowed, SecurityInsight can use {1} at once' -f $lim, $need.Cores)
                } else { $lines += 'the environment''s cores: the quota could not be read -- checked when the jobs run' }
            } else {
                $lines += ('cores: SecurityInsight can use {0} at once; a new environment''s own quota is read once it is created' -f $need.Cores)
            }
        }
        New-SIInstallResult -Message (($lines -join '; ') + '.')
    }

    $t['resource-group'] = {
        param($ctx)
        $v = $ctx.Values; $n = $ctx.Names
        $reg = @($ctx.Facts['providersToRegister'] | Where-Object { $_ })
        foreach ($ns in $reg) { $null = Invoke-SIInstallAz -Ctx $ctx -Command 'Register-SIResourceProvider' -Arguments ([ordered]@{ ProviderNamespace = $ns; ErrorAction = 'Stop' }) }
        # #564 (PIM's install at customer I): registering is not done until Azure says Registered -- wait for it (about 4 minutes at
        # most) before the first resource of those providers. A provider still registering then is a WARNING, never a stop:
        # the step that creates its first resource reports the real error if it is still not ready.
        $pending = @(Wait-SIInstallProviderRegistration -Ctx $ctx -ProviderNamespace $reg)
        $note = if ($reg.Count) { (' Registered: {0}.' -f (@($reg | Where-Object { $pending -notcontains $_ }) -join ', ')) } else { '' }
        if ($pending.Count) { $note += (' Still registering (Azure finishes it in the background; the install goes on): {0}.' -f ($pending -join ', ')) }
        $state = if ($pending.Count) { 'warning' } else { 'ok' }
        $existing = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIAzResourceGroup' -Arguments ([ordered]@{ Name = $n.ResourceGroup; ErrorAction = 'SilentlyContinue' })
        if ($existing) { return (New-SIInstallResult -State $state -Message ('Using the existing resource group {0}.{1}' -f $n.ResourceGroup, $note)) }
        $tenantTag = [string]$v['tenantId']
        try { $tn = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SITenant' -Arguments ([ordered]@{ TenantId = [string]$v['tenantId']; ErrorAction = 'Stop' }); if ("$(Get-SIInstallProp $tn 'DefaultDomain')".Trim()) { $tenantTag = [string](Get-SIInstallProp $tn 'DefaultDomain') } } catch { }
        $tags = Get-SIResourceGroupTags -Ring 'prod' -Edition $ctx.Edition -Hosting 'ca' -Tenant $tenantTag -Owner ([string]$v['owner'])
        try {
            $null = Invoke-SIInstallAz -Ctx $ctx -Command 'New-SIAzResourceGroup' -Arguments ([ordered]@{ Name = $n.ResourceGroup; Location = [string]$v['location']; Tag = (ConvertTo-SIAzTagHashtable -Tags $tags); ErrorAction = 'Stop' })
        } catch {
            throw (New-SIInstallFailure -Message ('Resource group {0} could not be created: {1}' -f $n.ResourceGroup, $_.Exception.Message) `
                -ActionText (Get-SIInstallPortalText -Kind 'CreateResourceGroup' -Ctx $ctx) -Command $ctx.ResumeCommand)
        }
        New-SIInstallResult -State $state -Message ('Created {0} in {1}, tagged product, ring, edition, hosting, tenant, owner and purpose.{2}' -f $n.ResourceGroup, $v['location'], $note)
    }

    $t['workspace'] = {
        param($ctx)
        $i = Get-SIInstallInfra -Ctx $ctx
        $ctx.Facts['workspaceResourceId'] = [string]$i['WorkspaceResourceId']
        New-SIInstallResult -Message ('Log Analytics workspace {0}.' -f $i['WorkspaceName']) -Detail ([ordered]@{ workspaceResourceId = $i['WorkspaceResourceId'] })
    }
    $t['data-collection-endpoint'] = {
        param($ctx)
        $i = Get-SIInstallInfra -Ctx $ctx
        New-SIInstallResult -Message ('Data collection endpoint {0}; the data collection rules are made on the first run.' -f $i['DceName'])
    }
    $t['storage'] = {
        param($ctx)
        $i = Get-SIInstallInfra -Ctx $ctx
        New-SIInstallResult -Message ('Storage account {0} (sign-in only, no access key).' -f $i['StorageAccountName'])
    }

    $t['key-vault'] = {
        param($ctx)
        $v = $ctx.Values; $n = $ctx.Names
        $null = Get-SIInstallInfra -Ctx $ctx
        $kv = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIKeyVault' -Arguments ([ordered]@{ VaultName = $n.KeyVault; ErrorAction = 'Stop' })
        $kvId = [string](Get-SIInstallProp $kv 'ResourceId')
        if (-not $kvId) { throw (New-SIInstallFailure -Message ('Key Vault {0} was not found after it was created.' -f $n.KeyVault)) }
        $ctx.Facts['keyVaultId'] = $kvId
        # You (the installer) may write secrets to the install's own vault: the licence and the keys you are asked for.
        $oid = [string]$ctx.Facts['userObjectId']
        $have = @(Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIAzRoleAssignment' -Arguments ([ordered]@{ ObjectId = $oid; Scope = $kvId; RoleDefinitionName = 'Key Vault Secrets Officer'; ErrorAction = 'SilentlyContinue' }))
        if (-not $have.Count) {
            $null = Invoke-SIInstallAz -Ctx $ctx -Command 'New-SIAzRoleAssignment' -Arguments ([ordered]@{ ObjectId = $oid; Scope = $kvId; RoleDefinitionName = 'Key Vault Secrets Officer'; ErrorAction = 'Stop' })
            $ctx.Facts['kvOfficerGrantedAt'] = (& $ctx.Seams.Now).ToString('o')
        }
        Update-SIInstallConfigFile -Ctx $ctx
        # The keys -- never wizard answers: asked for here, only when the feature is on, and written straight to the vault.
        $want = @()
        if ([bool]$v['aiClassification']) { $want += [pscustomobject]@{ Name = 'OpenAI-ApiKey'; Label = 'Azure OpenAI key' } }
        if ([bool]$v['shodan'])           { $want += [pscustomobject]@{ Name = 'SI-Shodan-ApiKey'; Label = 'Shodan API key' } }
        if ([string]$v['mailMode'] -eq 'smtp' -and "$($v['smtpUser'])".Trim()) { $want += [pscustomobject]@{ Name = 'SI-Smtp-Password'; Label = ('SMTP password for {0}' -f $v['smtpUser']) } }
        $stored = @(); $already = @(); $later = @()
        foreach ($w in $want) {
            $s = $null; try { $s = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIAzKeyVaultSecret' -Arguments ([ordered]@{ VaultName = $n.KeyVault; Name = $w.Name; ErrorAction = 'SilentlyContinue' }) } catch { }
            if ($s) { $already += $w.Label; continue }
            if (-not [bool](& $ctx.Seams.IsInteractive)) { $later += $w; continue }
            $sec = & $ctx.Seams.ReadSecret ('{0} (not shown; Enter to skip)' -f $w.Label)
            if (-not $sec -or $sec.Length -eq 0) { $later += $w; continue }
            $ok = $false; $last = ''
            # A new role assignment needs a moment before the vault honours it.
            # only the vault's refusal of the new right is waited for (about 6 minutes); anything else stops at once
            foreach ($try in 1..18) {
                try { $null = Invoke-SIInstallAz -Ctx $ctx -Command 'Set-SIAzKeyVaultSecret' -Arguments ([ordered]@{ VaultName = $n.KeyVault; Name = $w.Name; SecretValue = $sec; ErrorAction = 'Stop' }); $ok = $true; break }
                catch {
                    $last = $_.Exception.Message
                    if (-not (Test-SIAccessNotYetAnswer -Text $last)) { break }
                    if ($try -lt 18) { & $ctx.Seams.Sleep 20 }
                }
            }
            if ($ok) { $stored += $w.Label } else { $later += $w; $ctx.Facts['lastSecretError'] = (Protect-SIInstallText $last) }
        }
        # #240: the Invardia install key from the installation bundle -- straight to the vault, never echoed. (No bundle key:
        # a Pro install claims one with its licence in the licence step; the updater also claims one when none is stored.)
        if ($ctx.InstallKey) {
            if (Save-SIInstallBundleKey -Ctx $ctx) { $stored += 'Invardia install key' }
            else {
                # NEVER a claim instead (#417): the updater-job step tries again and installs no updater until the key is in.
                return (New-SIInstallResult -State 'warning' -Message ('Key Vault {0}. The Invardia install key from your installation page could not be stored yet; the install tries again before it installs the updater, and no other key is claimed.' -f $n.KeyVault) `
                    -Action ([ordered]@{ text = 'If the install stops at "Updates from Invardia", run the install command again once the vault accepts your writes (a new role assignment takes a minute):'; command = $ctx.ResumeCommand }))
            }
        }
        $msg = 'Key Vault {0}.' -f $n.KeyVault
        if ($stored.Count) { $msg += (' Stored: {0}.' -f ($stored -join ', ')) }
        if ($already.Count) { $msg += (' Already in the vault: {0}.' -f ($already -join ', ')) }
        if ($later.Count) {
            # #564: a portal path (a customer has no az CLI), or the install itself in an interactive shell (a masked prompt)
            $where = ($later | ForEach-Object { '{0} (secret name {1})' -f $_.Label, $_.Name }) -join '; '
            return (New-SIInstallResult -State 'warning' -Message ($msg + (' Not stored yet: {0}. The feature waits until it is in the vault.' -f (($later | ForEach-Object { $_.Label }) -join ', '))) `
                -Action ([ordered]@{ text = ('Add it to Key Vault {0} as someone who may write secrets there -- Azure portal: Key vaults > {0} > Objects > Secrets > Generate/Import: {1} -- or run the install command again in an interactive PowerShell: it asks for the value at a masked prompt.' -f $n.KeyVault, $where); command = $ctx.ResumeCommand }))
        }
        New-SIInstallResult -Message $msg
    }

    $t['licence'] = {
        param($ctx)
        if ($ctx.Edition -ne 'pro') { return (New-SIInstallResult -State 'skipped' -Message 'No licence was given: the free version is installed, with its database and web app. A licence added later turns on the paid features of SecurityInsight Pro.') }
        & $ctx.ProSteps['licence'] $ctx
    }

    $t['container-registry-image'] = {
        param($ctx)
        $null = Invoke-SIInstallBootstrap -Ctx $ctx
        New-SIInstallResult -Message ('Container registry {0}, image si-orchestrator:{1}.' -f $ctx.Names.Acr, $ctx.ImageTag)
    }

    $t['container-environment'] = {
        param($ctx)
        $n = $ctx.Names
        $getEnv = { (Invoke-SIInstallArmTry -Ctx $ctx -Command 'Get-SIManagedEnvironment' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; Name = $n.ContainerEnv })).Value }
        $env = & $getEnv
        if (-not $env -and -not $ctx.Cache.Contains('bootstrapRan')) {
            $null = Invoke-SIInstallBootstrap -Ctx $ctx -SkipImageBuild
            $env = & $getEnv
        }
        if (-not $env) { throw (New-SIInstallFailure -Message ('The Container Apps environment {0} was not found after the container setup.' -f $n.ContainerEnv)) }
        $ctx.Facts['containerEnvironmentId'] = [string](Get-SIInstallProp $env 'id')
        # #681: an install that asks for private networking must not go on in an environment that is not in the network
        if ([bool]$ctx.Values['privateNetwork'] -and -not (Test-SIEnvironmentPrivate -Environment $env)) {
            return (New-SIInstallResult -State 'warning' -Message ('The Container Apps environment {0} existed before and is not in your virtual network: Azure cannot move it. The install goes on with it as it is.' -f $n.ContainerEnv) `
                -Action ([ordered]@{ text = 'After the install, move it into your network (Invardia support runs this through the Support app; it shows the plan first):'; command = ('./setup/Set-SIPrivateNetworking.ps1 -ResourceGroup {0} -VnetId {1}' -f $n.ResourceGroup, [string]$ctx.Values['vnetId']) }))
        }
        if ([bool]$ctx.Values['privateNetwork']) { return (New-SIInstallResult -Message ('Container Apps environment {0} in your virtual network, internal (no public address); its logs go to the SecurityInsight workspace.' -f $n.ContainerEnv)) }
        New-SIInstallResult -Message ('Container Apps environment {0}; its logs go to the SecurityInsight workspace.' -f $n.ContainerEnv)
    }

    $t['runtime-identity'] = {
        param($ctx)
        $n = $ctx.Names
        $get = { Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SIUserAssignedIdentity' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; Name = $n.ManagedIdentity; ErrorAction = 'SilentlyContinue' }) }
        $id = & $get
        if (-not $id -and -not $ctx.Cache.Contains('bootstrapRan')) { $null = Invoke-SIInstallBootstrap -Ctx $ctx -SkipImageBuild; $id = & $get }
        if (-not $id) { throw (New-SIInstallFailure -Message ('The managed identity {0} was not found after the container setup.' -f $n.ManagedIdentity)) }
        $ctx.Facts['identityClientId'] = [string](Get-SIInstallProp $id 'ClientId')
        $ctx.Facts['identityPrincipalId'] = [string](Get-SIInstallProp $id 'PrincipalId')
        $ctx.Facts['identityResourceId'] = [string](Get-SIInstallProp $id 'Id')
        Update-SIInstallConfigFile -Ctx $ctx -BlockOnly
        New-SIInstallResult -Message ('SecurityInsight runs as the managed identity {0} -- no password or certificate anywhere.' -f $n.ManagedIdentity)
    }

    $t['grants-resource-group'] = {
        param($ctx)
        $g = Get-SIInstallGrantReport -Ctx $ctx
        $inside = @($g.Roles | Where-Object { $_.Inside })
        if ($g.InsideMissing.Count) {
            throw (New-SIInstallFailure -Message ('{0} grant(s) inside the resource group could not be made: your account cannot assign roles there.' -f $g.InsideMissing.Count) `
                -ActionText ('Ask an Owner of {0} to make these grants (the Azure portal path is on each line) or to run SecurityInsight''s grant script below in this install''s folder, then run the install command again:' -f $ctx.Names.ResourceGroup) `
                -Command ((@($g.InsideTasks) + @(Get-SIInstallGrantCommand -Ctx $ctx)) -join "`n") `
                -Detail ([ordered]@{ missing = @($g.InsideMissing | ForEach-Object { '{0} on {1}' -f $_.Role, $_.Scope }) }))
        }
        New-SIInstallResult -Message ('{0} grant(s) inside the resource group are in place.' -f $inside.Count)
    }

    $t['grants-outside-rg'] = {
        param($ctx)
        $g = Get-SIInstallGrantReport -Ctx $ctx
        if ($g.OutsideMissing.Count) {
            $scopes = @($g.OutsideMissing | ForEach-Object { $_.Scope } | Select-Object -Unique)
            $cmd = (@($g.OutsideTasks) + @(Get-SIInstallGrantCommand -Ctx $ctx)) -join "`n"
            return (New-SIInstallResult -State 'warning' -Message ('Waiting for {0} read grant(s) outside the resource group; SecurityInsight cannot read that data until they are made.' -f $g.OutsideMissing.Count) `
                -Action ([ordered]@{ text = ('Ask an Owner or User Access Administrator of {0} to make these grants (the Azure portal path is on each line) or to run SecurityInsight''s grant script below in this install''s folder:' -f ($scopes -join ', ')); command = $cmd }) `
                -Detail ([ordered]@{ missing = @($g.OutsideMissing | ForEach-Object { '{0} on {1}' -f $_.Role, $_.Scope }) }))
        }
        New-SIInstallResult -Message ('{0} read grant(s) outside the resource group are in place.' -f @($g.Roles | Where-Object { -not $_.Inside }).Count)
    }

    $t['api-permissions'] = {
        param($ctx)
        $g = Get-SIInstallGrantReport -Ctx $ctx
        if ($g.PermissionsMissing.Count) {
            return (New-SIInstallResult -State 'warning' -Message ('Waiting for {0} read-only API permission(s) for SecurityInsight''s identity.' -f $g.PermissionsMissing.Count) `
                -Action ([ordered]@{ text = ('Ask a Privileged Role Administrator (or Global Administrator) to grant them -- in Azure Cloud Shell, in this install''s folder, run:'); command = (Get-SIInstallGrantCommand -Ctx $ctx) }) `
                -Detail ([ordered]@{ missing = @($g.PermissionsMissing | ForEach-Object { '{0} ({1})' -f $_.Permission, $_.Resource }); tasks = $g.PermissionTasks }))
        }
        $absent = @($g.Permissions | Where-Object { $_.State -eq 'ABSENT' })
        $msg = '{0} read-only API permission(s) are in place.' -f @($g.Permissions | Where-Object { $_.State -ne 'ABSENT' }).Count
        if ($absent.Count) {
            # e.g. no Defender for Endpoint in the tenant: nothing to grant there, and SecurityInsight reads nothing from it
            $msg += ' Not in this tenant, so nothing to grant: {0}.' -f ((@($absent | ForEach-Object { '{0} ({1})' -f $_.Permission, $_.Resource })) -join ', ')
        }
        New-SIInstallResult -Message $msg
    }

    $t['container-jobs'] = {
        param($ctx)
        $n = $ctx.Names
        $list = { Get-SIInstallJobNames -Ctx $ctx -ResourceGroup $n.ResourceGroup }
        # an engine is there with its scheduled job, or -- queue scaling, #475 -- with its producer AND worker
        $check = { param($have) $w = New-Object System.Collections.Generic.List[string]; $m = New-Object System.Collections.Generic.List[string]
            foreach ($e in @($ctx.Engines)) { $s = Get-SIInstallEngineJobs -Engine $e -Have $have; foreach ($x in $s.Jobs) { $w.Add($x) }; if (-not $s.Present) { $m.Add((Get-SIInstallJobName -Engine $e)) } }
            [pscustomobject]@{ Want = $w.ToArray(); Missing = $m.ToArray() } }
        $have = @(& $list)
        $c = & $check $have; $want = @($c.Want); $missing = @($c.Missing)
        if ($missing.Count -and -not $ctx.Cache.Contains('bootstrapRan')) {
            $null = Invoke-SIInstallBootstrap -Ctx $ctx -SkipImageBuild
            $have = @(& $list); $c = & $check $have; $want = @($c.Want); $missing = @($c.Missing)
        }
        if ($missing.Count) {
            throw (New-SIInstallFailure -Message ('These engine jobs were not created: {0}.' -f ($missing -join ', ')) -ActionText 'Run the install command again: it re-runs the container setup for the missing jobs.' -Command $ctx.ResumeCommand)
        }
        $ctx.Facts['jobs'] = $want
        $sched = Get-SIInstallSchedules -RunHourUtc ([int]$ctx.Values['runHourUtc'])
        New-SIInstallResult -Message ('{0} engine jobs, daily from {1:00}:00 UTC.' -f $want.Count, [int]$ctx.Values['runHourUtc']) -Detail ([ordered]@{ jobs = $want; firstSchedule = $sched['ScheduleEndpoint'] })
    }

    $t['support-app-access'] = {
        param($ctx)
        $app = [string]$ctx.Values['supportAppId']
        if (-not $app) { return (New-SIInstallResult -State 'skipped' -Message 'No Invardia Support app was given: no support access is granted.') }
        $level = if ($ctx.Values['supportAccess']) { [string]$ctx.Values['supportAccess'] } else { 'troubleshoot' }
        $r = Invoke-SIInstallScript -Ctx $ctx -RelativePath 'setup/Grant-SISupportAccess.ps1' -Arguments ([ordered]@{ AppId = $app; Level = $level; ConfigPath = $ctx.ConfigPath })
        $self = './setup/Grant-SISupportAccess.ps1 -AppId {0} -Level {1}' -f $app, $level
        # THE SUPPORT APP KEEPS ITS DATABASE ACCESS AFTER THE INSTALL (Pro; framework 4.1b, owner 2026-10-18) -- whoever runs the
        # install, and whatever the script above could do: its own database user with db_owner in the product databases and
        # its place in the server's admin group, made NOW (while the install is still the server's administrator) and read
        # back. Both stay; nothing removes them. Never fails the install:
        # what is not in place is a warning with the command that makes it.
        $sd = $null
        if ($ctx.Pro -and (Get-Command -Name Set-SIInstallSupportAppDatabase -ErrorAction SilentlyContinue)) { $sd = Set-SIInstallSupportAppDatabase -Ctx $ctx }
        $dbText = if ($sd) { ' ' + [string]$sd.Message } else { '' }
        $dbCmd = if ($sd -and -not $sd.Ok) { @(Get-SIInstallSupportAppDatabaseCommand -Ctx $ctx) } else { @() }
        if ($r.Error) {
            return (New-SIInstallResult -State 'warning' -Message (('Support access was not granted: {0}' -f $r.Error) + $dbText) `
                -Action ([ordered]@{ text = 'When the Invardia Support app exists in your tenant, run in this install''s folder:'; command = (@($self) + $dbCmd) -join "`n" }) -Detail @{ log = (Get-SIInstallTail $r.Text) })
        }
        if ($r.ExitCode -ne 0) {
            $tasks = @(Get-SIInstallTaskLines -Lines $r.Text)
            return (New-SIInstallResult -State 'warning' -Message (('Support access ({0}) is partly granted; the rest needs someone with more rights.' -f $level) + $dbText) `
                -Action ([ordered]@{ text = 'Ask an administrator to do the following (or to run the same command in this install''s folder):'; command = (@($tasks) + @($self) + $dbCmd) -join "`n" }) -Detail @{ log = (Get-SIInstallTail $r.Text) })
        }
        if ($dbCmd.Count) {
            return (New-SIInstallResult -State 'warning' -Message (('The Invardia Support app has {0} access, but its database access (its own database user and its place in the database admin group) is not in place.' -f $level) + $dbText) `
                -Action ([ordered]@{ text = 'Run in this install''s folder, as an administrator of the database server (it shows the plan without -Apply):'; command = $dbCmd -join "`n" }))
        }
        New-SIInstallResult -Message (('The Invardia Support app has {0} access.' -f $level) + $dbText)
    }

    # MAIL-1: the shared mailbox (default) -- created when asked, SecurityInsight's identities may send ONLY as it
    # (Exchange RBAC for Applications), verified. setup/Set-SIMail.ps1 does it; without Exchange rights it hands the
    # one command to the Exchange administrator. Never fails the install: mail can be set up afterwards (Settings >
    # E-mail > Set up mail, or the same command).
    $t['mail'] = {
        param($ctx)
        $mm = if ([string]$ctx.Values['mailMode']) { [string]$ctx.Values['mailMode'] } else { 'none' }
        if ($mm -eq 'none') { return (New-SIInstallResult -State 'skipped' -Message 'No e-mail: SecurityInsight sends no mail (Settings > E-mail sets it up later).') }
        if ($mm -eq 'smtp') { return (New-SIInstallResult -Message ('Mail goes through your SMTP relay {0}:{1}.' -f $ctx.Values['smtpServer'], $ctx.Values['smtpPort'])) }
        # #876: a tenant WITHOUT Exchange Online (the preflight read its subscriptions) has no mailbox to send from: that is
        # information, never a warning -- mail is set up later in Get Started (an SMTP relay, or once Exchange Online is there)
        if ($null -ne $ctx.Facts['exchangeOnline'] -and -not [bool]$ctx.Facts['exchangeOnline']) {
            return (New-SIInstallResult -State 'skipped' -Message (Get-SIInstallNoExchangeText))
        }
        $box = Get-SIInstallMailbox -Ctx $ctx
        $rg = $ctx.Names.ResourceGroup; $subId = [string]$ctx.Values['subscriptionId']
        $create = if ($null -ne $ctx.Values['mailboxCreate']) { [bool]$ctx.Values['mailboxCreate'] } else { $true }
        $cmd = './setup/Set-SIMail.ps1 -SharedMailbox {0} -SubscriptionId {1} -ResourceGroup {2} -UseSignedInAccount -Apply{3}' -f $box, $subId, $rg, $(if (-not $create) { ' -CreateMailbox $false' } else { '' })
        if (-not $box) {
            return (New-SIInstallResult -State 'warning' -Message 'No shared mailbox address is known (mailFrom), so mail is not set up yet.' `
                -Action ([ordered]@{ text = 'Your Exchange administrator sets it up with (in this install''s folder):'; command = ($cmd -replace '-SharedMailbox  ', '-SharedMailbox <address> ') }))
        }
        $out = Join-Path ([IO.Path]::GetTempPath()) ('si-install-mail-{0}.json' -f [guid]::NewGuid().ToString('n'))
        # #564 (PIM's install at customer I): a slow external readiness never holds the install -- Exchange gets a SHORT wait here
        # (Set-SIMail waits up to 15 minutes per action on its own); what is not ready yet is deferred to Get Started.
        $args_ = [ordered]@{ Mode = 'sharedMailbox'; TenantId = [string]$ctx.Values['tenantId']; SharedMailbox = $box; CreateMailbox = $create
                             SubscriptionId = $subId; ResourceGroup = $rg; UseSignedInAccount = $true; Apply = $true; OutFile = $out
                             TimeoutSeconds = $script:SIInstallMailTimeoutSeconds }
        # the installer's own mailbox is the "outside the scope" probe -- only when the installer is a PERSON: an
        # application has no mailbox (its "name" here is its client id)
        if ([string]$ctx.Facts['userPrincipalName'] -and -not (Test-SIInstallSignedInAsApp -Ctx $ctx)) { $args_.ProbeMailbox = [string]$ctx.Facts['userPrincipalName'] }
        $r = Invoke-SIInstallScript -Ctx $ctx -RelativePath 'setup/Set-SIMail.ps1' -Arguments $args_
        $res = $null; try { if (Test-Path -LiteralPath $out) { $res = [IO.File]::ReadAllText($out) | ConvertFrom-Json } } catch { }
        Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        $ctx.Facts['mailFrom'] = $box
        if (-not $r.Error -and $r.ExitCode -eq 0) { return (New-SIInstallResult -Message ('SecurityInsight sends as the shared mailbox {0}, and only as it (verified).' -f $box) -Detail ([ordered]@{ mailbox = $box })) }
        $cmds = @(@($res.commands) | Where-Object { $_ })
        $text = if ($r.ExitCode -eq 2) { 'Creating the mailbox and the Exchange permission needs an Exchange administrator (the Exchange Administrator role). Ask them to run, in this install''s folder:' }
                else { 'Mail is deferred -- finish it in Get Started (the web app), or run (or ask your Exchange administrator to run), in this install''s folder:' }
        New-SIInstallResult -State 'warning' -Message ('The shared mailbox {0} is not ready yet{1} The install goes on; mail is deferred -- finish it in Get Started.' -f $box, $(if ($res -and $res.reason) { ': ' + $res.reason + '.' } else { '.' })) `
            -Action ([ordered]@{ text = $text; command = (@($cmd) + $(if ($cmds.Count) { @('# or, in Exchange Online PowerShell:') + $cmds } else { @() })) -join "`n" }) `
            -Detail ([ordered]@{ mailbox = $box; log = $(if ($r.Text) { Get-SIInstallTail $r.Text } else { '' }) })
    }

    # #866: the storage account and the Key Vault were CREATED private (the infrastructure step): their private endpoints
    # and zones NOW, then the DNS check from this machine -- before the vault's first secret is written. Not resolving yet:
    # the install stops with the exact hub DNS records, and the install command continues from here.
    $t['private-network-data'] = {
        param($ctx)
        $v = $ctx.Values; $n = $ctx.Names
        $i = Get-SIInstallInfra -Ctx $ctx
        $rgId = '/subscriptions/{0}/resourceGroups/{1}' -f [string]$v['subscriptionId'], $n.ResourceGroup
        $kvId = '{0}/providers/Microsoft.KeyVault/vaults/{1}' -f $rgId, $n.KeyVault
        $g = Invoke-SIInstallPrivateDataGate -Ctx $ctx -KeyVaultId $kvId -StorageAccountId ([string]$i['StorageAccountResourceId']) -What 'the storage account and the Key Vault'
        New-SIInstallResult -Message $g.Message -Detail ([ordered]@{ lines = @($g.Lines) })
    }

    # #681: PRIVATE NETWORKING (an option). The subnets come BEFORE the container setup -- the environment is created in
    # the network -- and the private endpoints, private DNS and the closing of the public endpoints come at the END, after
    # every step that still reaches the database, the vault or the storage from this machine.
    $t['private-network-subnets'] = {
        param($ctx)
        $rgId = '/subscriptions/{0}/resourceGroups/{1}' -f [string]$ctx.Values['subscriptionId'], $ctx.Names.ResourceGroup
        $target = Get-SIInstallPrivateNetworkTarget -Values $ctx.Values -ResourceGroupId $rgId
        $r = Invoke-SIInstallArmTry -Ctx $ctx -Command 'Invoke-SIPrivateNetworkSubnets' -Arguments ([ordered]@{ Target = $target; Location = [string]$ctx.Values['location'] })
        if (-not $r.Ok) {
            throw (New-SIInstallFailure -Message ('The subnets in your virtual network could not be prepared: {0}' -f $r.Error) `
                -ActionText 'Give the address ranges for the subnets (appsSubnetPrefix: at least a /27, endpointsSubnetPrefix) -- or an address range for SecurityInsight''s own network (vnetAddressPrefix, at least a /25) -- or let your network team create them, then run the install command again: it continues from this step.' -Command $ctx.ResumeCommand)
        }
        $ctx.Facts['appsSubnetId'] = [string]$r.Value.AppsSubnetId; $ctx.Facts['endpointsSubnetId'] = [string]$r.Value.EndpointsSubnetId
        $ctx.Facts['vnetLocation'] = [string]$r.Value.Location
        if (-not $r.Value.Ok) { return (New-SIInstallResult -State 'warning' -Message ((@($r.Value.Lines) -join '; ') + '.') -Action ([ordered]@{ text = 'Run the install command again: it checks the subnets again.'; command = $ctx.ResumeCommand })) }
        # #866 item 5: the peering with the hub ONLY when the customer turned peerToHub on (their approval) and named the hub;
        # the rights are read before any change, and never half a peering. Otherwise it is on the network hand-off list.
        if ([bool]$target.PeerToHub) {
            $pr = Invoke-SIInstallArmTry -Ctx $ctx -Command 'Invoke-SIPrivateNetworkPeering' -Arguments ([ordered]@{ Target = $target })
            $pl = if ($pr.Ok) { @($pr.Value.Lines) } else { @(('the peering with the hub could not be made: {0}' -f $pr.Error)) }
            if (-not $pr.Ok -or -not $pr.Value.Ok) {
                return (New-SIInstallResult -State 'warning' -Message (((@($r.Value.Lines) + $pl) -join '; ') + '.') `
                    -Action ([ordered]@{ text = 'The install goes on without the peering: it is on the network hand-off list at the end of the install for your network team (or give the installing identity Network Contributor on both networks and run the install command again).'; command = $ctx.ResumeCommand }) `
                    -Detail ([ordered]@{ appsSubnetId = $ctx.Facts['appsSubnetId']; endpointsSubnetId = $ctx.Facts['endpointsSubnetId']; peering = $pl }))
            }
            return (New-SIInstallResult -Message (((@($r.Value.Lines) + $pl) -join '; ') + '.') -Detail ([ordered]@{ appsSubnetId = $ctx.Facts['appsSubnetId']; endpointsSubnetId = $ctx.Facts['endpointsSubnetId']; peering = $pl }))
        }
        New-SIInstallResult -Message ((@($r.Value.Lines) -join '; ') + '.') -Detail ([ordered]@{ appsSubnetId = $ctx.Facts['appsSubnetId']; endpointsSubnetId = $ctx.Facts['endpointsSubnetId'] })
    }

    $t['private-network'] = {
        param($ctx)
        $v = $ctx.Values; $n = $ctx.Names; $sub = [string]$v['subscriptionId']
        $rgId = '/subscriptions/{0}/resourceGroups/{1}' -f $sub, $n.ResourceGroup
        $target = Get-SIInstallPrivateNetworkTarget -Values $v -ResourceGroupId $rgId
        $infra = Get-SIInstallInfra -Ctx $ctx
        $peSubnet = [string]$ctx.Facts['endpointsSubnetId']
        if (-not $peSubnet) { $peSubnet = '{0}/subnets/{1}' -f $target.VnetId, $target.EndpointsSubnetName }
        $a = [ordered]@{ Target = $target; Location = $(if ([string]$ctx.Facts['vnetLocation']) { [string]$ctx.Facts['vnetLocation'] } else { [string]$v['location'] }); EndpointsSubnetId = $peSubnet
                         KeyVaultId = [string]$ctx.Facts['keyVaultId']; StorageAccountId = [string]$infra['StorageAccountResourceId']
                         RegistryId = ('{0}/providers/Microsoft.ContainerRegistry/registries/{1}' -f $rgId, $n.Acr); EnvironmentId = [string]$ctx.Facts['containerEnvironmentId'] }
        if (($ctx.Data -or $ctx.Pro) -and [string]$ctx.Facts['sqlServerId']) { $a.SqlServerId = [string]$ctx.Facts['sqlServerId'] }
        # #681 (owner 2026-10-19: "same config as pim"): the in-network SQL identity id-si-sql, a member of the admin group,
        # BEFORE the database closes -- after the close, support reaches the database only from inside, through a one-time job
        # signed in as it (setup\Invoke-SISupportSqlAccessJob.ps1). The Support app's own database user was made by the
        # install's support-access step, while this machine still reached the database.
        $miNote = ''
        if ($a.Contains('SqlServerId') -and (Get-Command -Name Get-SIInstallSupportAppAdminGroupId -ErrorAction SilentlyContinue)) {
            $mi = Invoke-SIInstallArmTry -Ctx $ctx -Command 'Invoke-SIPrivateNetworkSqlIdentity' -Arguments ([ordered]@{ ResourceGroupId = $rgId; Location = [string]$v['location'] })
            $gid = ''; try { $gid = Get-SIInstallSupportAppAdminGroupId -Ctx $ctx } catch { $gid = '' }
            if (-not $mi.Ok -or -not $mi.Value.Ok) { $miNote = (' The in-network SQL identity {0} is not ready ({1}) -- Invardia support makes it with setup\Set-SIPrivateNetworking.ps1 -Steps sql-identity.' -f (Get-SIPrivateNetworkNames).SqlIdentity, $(if ($mi.Error) { $mi.Error } else { (@($mi.Value.Line)) -join '' })) }
            elseif (-not $gid) { $miNote = (' The in-network SQL identity {0} is made, but the database admin group was not found to add it to.' -f (Get-SIPrivateNetworkNames).SqlIdentity) }
            else {
                # #564: NOT a GetNewClosure() -- a closure cannot see the helpers setup dot-sourced (Invoke-SIInstallGraph); the
                # block reads the install's context through this scope, under a name the callee does not use
                $siPnGraphCtx = $ctx
                $graph = { param($m, $u, $b) Invoke-SIInstallGraph -Ctx $siPnGraphCtx -Method $m -Uri $u -Body $b }
                $mm = Set-SISupportAppGroupMember -Graph $graph -GroupId $gid -ServicePrincipalId ([string]$mi.Value.PrincipalId) -Apply -Sleep $ctx.Seams.Sleep
                if ($mm.State -notin 'present', 'added') { $miNote = (' The in-network SQL identity {0} is not a member of the database admin group yet ({1}).' -f (Get-SIPrivateNetworkNames).SqlIdentity, $mm.Detail) }
            }
        }
        $r = Invoke-SIInstallArmTry -Ctx $ctx -Command 'Invoke-SIPrivateNetworkEndpoints' -Arguments $a
        $cmd = './setup/Set-SIPrivateNetworking.ps1 -ResourceGroup {0} -VnetId {1}' -f $n.ResourceGroup, $target.VnetId
        if (-not $r.Ok) {
            return (New-SIInstallResult -State 'warning' -Message ('The private endpoints could not be made: {0}. The install works as it is; its public endpoints are NOT closed.' -f $r.Error) `
                -Action ([ordered]@{ text = 'Run the install command again (this step is safe to repeat), or have Invardia support finish it with (it shows the plan first):'; command = $cmd }))
        }
        $lines = @($r.Value.Lines)
        if (-not $r.Value.Ok) {
            return (New-SIInstallResult -State 'warning' -Message ('Private network: not everything is in place -- {0}.' -f ($lines -join '; ')) `
                -Action ([ordered]@{ text = 'Run the install command again (this step is safe to repeat), or have Invardia support finish it with (it shows the plan first):'; command = $cmd }) -Detail ([ordered]@{ lines = $lines }))
        }
        # #866: THE NETWORK HAND-OFF -- the exact list for the customer's network team (read from Azure, never a write), and
        # the hub owner's script, written next to the install's state and recorded in this step's result for Invardia
        $ho = Invoke-SIInstallArmTry -Ctx $ctx -Command 'Invoke-SIPrivateNetworkHandOff' -Arguments ([ordered]@{
            Target = $target; EnvironmentId = [string]$ctx.Facts['containerEnvironmentId']; InsideNames = @($r.Value.InsideNames)
            Notes = @($r.Value.HandOff); CloseCommand = $(if ($r.Value.Closed) { '' } else { $ctx.ResumeCommand })
            Directory = $(if ([string]$ctx.StateDirectory) { [IO.Path]::Combine([string]$ctx.StateDirectory, 'network-hand-off') } else { '' }); TenantId = [string]$v['tenantId'] })
        $hoLines = if ($ho.Ok -and $ho.Value) { @($ho.Value.HandOff.Lines) } else { @(('the network hand-off could not be read: {0}' -f $ho.Error)) }
        $hoOpen = if ($ho.Ok -and $ho.Value) { [int]$ho.Value.HandOff.Open } else { 1 }
        $hoFiles = if ($ho.Ok -and $ho.Value) { @($ho.Value.ListPath, $ho.Value.ScriptPath) | Where-Object { $_ } } else { @() }
        if (Get-Command -Name Write-SIInstallConsole -ErrorAction SilentlyContinue) { foreach ($l in $hoLines) { Write-SIInstallConsole -Ctx $ctx -Text $l -Color Yellow } }
        $hoDetail = [ordered]@{ lines = $lines; networkHandOff = $hoLines; networkHandOffFiles = @($hoFiles); handOffOpen = $hoOpen }
        $hoText = 'Hand the network hand-off list to your network team{0}: SecurityInsight wrote nothing on your hub -- the peering and the DNS records there are theirs.' -f $(if (@($hoFiles).Count) { ' (' + (@($hoFiles) -join ', ') + ')' } else { ' (in this step''s detail)' })
        # #866 (PIM's verify-inside): the names did not resolve to private addresses from inside -- the public endpoints are
        # LEFT OPEN (never a closed resource nothing can reach) and the install ends with ONE customer action
        if (-not $r.Value.Closed) {
            $hoDetail['insideCheck'] = @($r.Value.InsideCheck.Lines)
            return (New-SIInstallResult -State 'warning' -Message ('Private network: the private endpoints and private DNS are in place, but the public endpoints of the database, the storage and the Key Vault are STILL OPEN -- the names do not resolve to private addresses from inside your network yet ({0}).' -f ((@($r.Value.InsideCheck.Failed) | Where-Object { $_ }) -join ', ')) `
                -Action ([ordered]@{ text = ($hoText + ' After your hub changes, run the install command again from a machine in that network: it checks again and closes the public endpoints.'); command = $ctx.ResumeCommand }) `
                -Detail $hoDetail)
        }
        $okMsg = ('Private network: {0} private endpoint(s), private DNS in place, the public endpoints of the database, the storage and the Key Vault closed. From now on SecurityInsight is reached from your network only, and it stays that way -- run later setup commands from a machine in that network.' -f @($lines | Where-Object { $_ -like 'private endpoint *' }).Count)
        if ($miNote) { return (New-SIInstallResult -State 'warning' -Message ($okMsg + $miNote) -Action ([ordered]@{ text = 'Have Invardia support finish it with (it shows the plan first):'; command = ($cmd + ' -Steps sql-identity') }) -Detail $hoDetail) }
        if ($hoOpen) { return (New-SIInstallResult -State 'warning' -Message ($okMsg + ' Your users reach the web app once your network team has done its part of the hand-off.') -Action ([ordered]@{ text = $hoText; command = '' }) -Detail $hoDetail) }
        New-SIInstallResult -Message $okMsg -Detail $hoDetail
    }

    # #683: CUSTOMER-MANAGED KEYS (an option): after the database and the updater, so every resource it encrypts is there.
    $t['customer-managed-keys'] = {
        param($ctx)
        $v = $ctx.Values; $n = $ctx.Names; $sub = [string]$v['subscriptionId']
        $rgId = '/subscriptions/{0}/resourceGroups/{1}' -f $sub, $n.ResourceGroup
        $infra = Get-SIInstallInfra -Ctx $ctx
        $vaultId = if ("$($v['cmkKeyVaultId'])".Trim()) { "$($v['cmkKeyVaultId'])".Trim() } else { [string]$ctx.Facts['keyVaultId'] }
        $la = if ("$($v['cmkLogAnalytics'])".Trim()) { "$($v['cmkLogAnalytics'])".Trim() } else { 'off' }
        $a = [ordered]@{ ResourceGroupId = $rgId; Location = [string]$v['location']; KeyVaultId = $vaultId; KeyName = [string]$v['cmkKeyName']
                         StorageAccountId = [string]$infra['StorageAccountResourceId']; WorkspaceId = [string]$infra['WorkspaceResourceId']; LogAnalytics = $la; ClusterId = [string]$v['logAnalyticsClusterId'] }
        if (($ctx.Data -or $ctx.Pro) -and [string]$ctx.Facts['sqlServerId']) { $a.SqlServerId = [string]$ctx.Facts['sqlServerId'] }
        $r = Invoke-SIInstallArmTry -Ctx $ctx -Command 'Invoke-SICustomerKeySetup' -Arguments $a
        $cmd = './setup/Set-SICustomerManagedKeys.ps1 -ResourceGroup {0}{1}' -f $n.ResourceGroup, $(if ($la -ne 'off') { ' -LogAnalytics ' + $la + $(if ($a.ClusterId) { ' -ClusterId ' + $a.ClusterId } else { '' }) } else { '' })
        if (-not $r.Ok) {
            return (New-SIInstallResult -State 'warning' -Message ('Your own encryption key could not be set up: {0}. Your data stays encrypted with Microsoft-managed keys.' -f $r.Error) `
                -Action ([ordered]@{ text = 'Run the install command again (this step is safe to repeat), or have Invardia support finish it with (it shows the plan first):'; command = $cmd }))
        }
        $lines = @($r.Value.Lines)
        if (-not $r.Value.Ok) {
            return (New-SIInstallResult -State 'warning' -Message ('Your own encryption key: not everything is in place -- {0}. What is not switched stays encrypted with Microsoft-managed keys.' -f ($lines -join '; ')) `
                -Action ([ordered]@{ text = 'Run the install command again (this step is safe to repeat), or have Invardia support finish it with:'; command = $cmd }) -Detail ([ordered]@{ lines = $lines }))
        }
        if ($r.Value.Pending) {
            return (New-SIInstallResult -State 'warning' -Message ('Your own encryption key is in use for the database and the storage. {0}' -f (@($lines | Where-Object { $_ -like '*still being made*' }) -join ' ')) `
                -Action ([ordered]@{ text = 'When the Log Analytics cluster is ready (up to two hours), link the workspace -- run the install command again, or:'; command = ($cmd + ' -Apply -Steps log-analytics') }) -Detail ([ordered]@{ lines = $lines }))
        }
        New-SIInstallResult -Message ('Your own encryption key is in use: {0}.' -f ($lines -join '; ')) -Detail ([ordered]@{ lines = $lines })
    }

    $t['first-run'] = {        param($ctx)
        $waiting = @($ctx.State['pending'].Keys | Where-Object { $_ -in 'grants-outside-rg', 'api-permissions' })
        $hour = [int]$ctx.Values['runHourUtc']
        if ($waiting.Count) {
            return (New-SIInstallResult -State 'skipped' -Message ('The first run waits for the grants above; the daily schedule ({0:00}:00 UTC) runs it once they are made.' -f $hour))
        }
        $rg = $ctx.Names.ResourceGroup; $subId = [string]$ctx.Values['subscriptionId']
        # A new install runs as ONE pipeline (caj-si-flow): the first run is "Run the pipeline now" -- the flow job started
        # once with SI_FLOW_FORCE=1 on top of its own environment (Collect, Correlate, Deliver, one after the other). The
        # start goes through ARM /start with the job's full container template: 'az containerapp job start --env-vars'
        # can REPLACE the container's environment. (Before 2026-10-06 the first run started the privilege-tier
        # classifier, a job that exists only with Azure OpenAI -- the Community rehearsal had none.)
        $flowJob = Get-SIInstallJobName -Engine 'flow'
        $fj = (Invoke-SIInstallArmTry -Ctx $ctx -Command 'Get-SIContainerAppJob' -Arguments ([ordered]@{ ResourceGroupName = $rg; Name = $flowJob })).Value
        $c0 = @(Get-SIInstallProp (Get-SIInstallProp (Get-SIInstallProp $fj 'properties') 'template') 'containers') | Select-Object -First 1
        if ($fj -and $c0) {
            $body = Get-SIInstallFlowStartBody -Container $c0 -Env ([ordered]@{ SI_FLOW_FORCE = '1'; SI_FLOW_TRIGGER = 'manual'; SI_AUDIT_STARTED_BY = 'installer' })
            # #521: ARM POST <job>/start with the execution's own template (Start-SIContainerAppJob -Template), no az rest
            $r = Invoke-SIInstallArmTry -Ctx $ctx -Command 'Start-SIContainerAppJob' -Arguments ([ordered]@{ ResourceGroupName = $rg; Name = $flowJob; Template = $body })
            if ($r.Ok) {
                $exec = $null; try { $exec = [string](Get-SIInstallProp $r.Value 'name') } catch { }
                $ctx.Facts['firstRunExecution'] = $exec; $ctx.Facts['firstRunStarted'] = $(if ($exec) { $exec } else { $flowJob })
                return (New-SIInstallResult -Message ('The first run started: the whole pipeline (Collect, Correlate, Deliver) runs now{0}, and then every day.' -f $(if ($exec) { ' -- execution ' + $exec } else { '' })) `
                    -Detail ([ordered]@{ job = $flowJob; execution = $exec; logs = ('Azure portal: Container Apps jobs > {0} (resource group {1}) > Execution history > {2} > Console logs' -f $flowJob, $rg, $exec) }))
            }
            # #564: a portal path or the install itself -- never an az command
            return (New-SIInstallResult -State 'warning' -Message ('The first run could not be started now; the daily pipeline runs it ({0}).' -f $flowJob) `
                -Action ([ordered]@{ text = ('To start it now, run the install command again (it starts the first run), or in the Azure portal: Container Apps jobs > {0} (resource group {1}) > Run now with SI_FLOW_FORCE = 1. Or wait for the daily run.' -f $flowJob, $rg); command = $ctx.ResumeCommand }))
        }
        # An install without the flow job (schedules mode): start the first collector; the others follow on their schedules.
        $firstEngine = $(if (@($ctx.Engines) -contains 'privilege-tier-classifier') { 'privilege-tier-classifier' } else { 'endpoint' })
        # an engine that runs in parts (#475) is started by its producer
        $jobsNow = @(Get-SIInstallJobNames -Ctx $ctx -ResourceGroup $rg)
        $job = (Get-SIInstallEngineJobs -Engine $firstEngine -Have @($jobsNow)).Start
        $r = Invoke-SIInstallArmTry -Ctx $ctx -Command 'Start-SIContainerAppJob' -Arguments ([ordered]@{ ResourceGroupName = $rg; Name = $job })
        if (-not $r.Ok) {
            return (New-SIInstallResult -State 'warning' -Message ('The first run could not be started now; the daily schedule ({0:00}:00 UTC) runs it.' -f $hour) `
                -Action ([ordered]@{ text = ('To start it now, run the install command again (it starts the first run), or in the Azure portal: Container Apps jobs > {0} (resource group {1}) > Run now.' -f $job, $rg); command = $ctx.ResumeCommand }))
        }
        $ctx.Facts['firstRunStarted'] = $job
        New-SIInstallResult -Message ('The first run started ({0}); the other engines follow on the daily schedule.' -f $job)
    }

    $t['health-check'] = {
        param($ctx)
        # THE END-OF-INSTALL CHECK (every install with the database, Get-SIInstallEndCheck): what the steps reported is read back from Azure once more.
        # Something that is not there is said here, and the step that makes it is run again by the next run of the
        # install command -- a finished step is otherwise skipped for good.
        $found = @()
        if (($ctx.Data -or $ctx.Pro) -and (Get-Command -Name Get-SIInstallEndCheck -ErrorAction SilentlyContinue)) { $found = @(Get-SIInstallEndCheck -Ctx $ctx | Where-Object { $_ }) }
        if ($found.Count) {
            $redo = New-Object System.Collections.Generic.List[string]
            $texts = New-Object System.Collections.Generic.List[string]
            foreach ($f in $found) {
                $parts = ([string]$f) -split '\|', 2
                $texts.Add($(if ($parts.Count -gt 1) { $parts[1] } else { $parts[0] }))
                if ($parts.Count -gt 1 -and $parts[0]) {
                    if (-not $redo.Contains($parts[0])) { $redo.Add($parts[0]) }
                    # a database that is made again needs its tables, templates and settings again
                    if ($parts[0] -eq 'pro-sql' -and $parts[1] -like 'the database *') { foreach ($x in 'pro-schema', 'pro-templates', 'pro-settings') { if (-not $redo.Contains($x)) { $redo.Add($x) } } }
                }
            }
            $ctx.State['completed'] = @(@($ctx.State['completed']) | Where-Object { $redo -notcontains $_ })
            return (New-SIInstallResult -State 'warning' -Message ('The check at the end found {0} thing(s) that are not as the steps reported: {1}.' -f $texts.Count, ($texts.ToArray() -join '; ')) `
                -Action ([ordered]@{ text = 'Run the install command again: it runs the steps that make them again, and this check again.'; command = $ctx.ResumeCommand }) `
                -Detail ([ordered]@{ notInPlace = $texts.ToArray(); stepsToRunAgain = $redo.ToArray() }))
        }
        $p = $ctx.State['pending']
        $keys = @($p.Keys | Where-Object { $_ -ne 'health-check' })
        if ($keys.Count) {
            $titles = @($keys | ForEach-Object { $script:SIInstallStepTitles[$_] })
            $cmds = @($keys | ForEach-Object { [string](Get-SIInstallProp $p[$_] 'command') } | Where-Object { $_ })
            return (New-SIInstallResult -State 'warning' -Message ('Installed. Waiting for {0} item(s): {1}.' -f $keys.Count, ($titles -join '; ')) `
                -Action ([ordered]@{ text = 'The commands for the right people (also shown at each step above):'; command = ($cmds -join "`n") }) `
                -Detail ([ordered]@{ waitingFor = $keys }))
        }
        # the Invardia Support app's database access: what the check above read back, or why it could not be checked
        $supNote = ''; try { $supNote = ([string]$ctx.Facts['supportAppDatabaseNote']).Trim() } catch { }
        if ($supNote -like '*could not be checked*') { return (New-SIInstallResult -Message ('Everything that could be checked is in place. ' + $supNote)) }
        New-SIInstallResult -Message ('Everything is in place.' + $(if ($supNote) { ' ' + $supNote } else { '' }))
    }
    $t
}

function Get-SIInstallOutputs {
    <# PURE apart from reading $ctx. The completed event's outputs (the support environment's fields). #>
    param([Parameter(Mandatory)]$Ctx)
    $v = $Ctx.Values; $n = $Ctx.Names; $f = $Ctx.Facts
    $portal = if ($f['portalUrl']) { [string]$f['portalUrl'] } else {
        'https://portal.azure.com/#@{0}/resource/subscriptions/{1}/resourceGroups/{2}/overview' -f $v['tenantId'], $v['subscriptionId'], $n.ResourceGroup
    }
    [ordered]@{
        subscriptionId          = [string]$v['subscriptionId']
        resourceGroup           = $n.ResourceGroup
        keyVaultId              = [string]$f['keyVaultId']
        logAnalyticsWorkspaceId = [string]$f['workspaceResourceId']
        securityWorkspaceId     = [string]$v['securityWorkspaceId']
        sqlServerId             = [string]$f['sqlServerId']
        hosting                 = 'container'
        runtimeIdentity         = 'mi-container'
        runtimeIdentityClientId = [string]$f['identityClientId']
        version                 = $Ctx.Version
        portalUrl               = $portal
    }
}

# ---------------------------------------------------------------------------------------------------------------
# The whole install
# ---------------------------------------------------------------------------------------------------------------
function Test-SIInstallConfigIsOwn {
    <# PURE. Is this config file text the guided install's OWN for -InstallId? Empty text (a new file) is; otherwise only a
       file carrying the guided-install block with this install's SI_InstallId. #>
    param([AllowEmptyString()][AllowNull()][string]$Text, [Parameter(Mandatory)][string]$InstallId)
    if (-not "$Text".Trim()) { return $true }
    $m = [regex]::Match($Text, '(?ms)^# >>> SecurityInsight guided install >>>.*?^# <<< SecurityInsight guided install <<<')
    if (-not $m.Success) { return $false }
    $id = [regex]::Match($m.Value, "(?m)^\`$global:SI_InstallId\s*=\s*'([^']*)'")
    $id.Success -and $id.Groups[1].Value -eq $InstallId
}

function Get-SIInstallOwnConfigPath {
    <#
        The config file THIS install writes and every script it runs reads: config\SecurityInsight.custom.ps1 when that is
        absent or already this install's own; otherwise (a file another install or the internal AutomateIT platform wrote --
        live 2026-10-06 on mgmt1 it carried ring 1's subscription) config\SecurityInsight.custom.<installId>.ps1, and the
        other file is left exactly as it is.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$InstallId)
    $default = [IO.Path]::Combine($SIRoot, 'config', 'SecurityInsight.custom.ps1')
    if (-not (Test-Path -LiteralPath $default)) { return $default }
    $text = ''
    try { $text = [IO.File]::ReadAllText($default) } catch { $text = $null }
    if ($null -ne $text -and (Test-SIInstallConfigIsOwn -Text $text -InstallId $InstallId)) { return $default }
    $safe = ($InstallId -replace '[^A-Za-z0-9._-]', '_')
    [IO.Path]::Combine($SIRoot, 'config', ('SecurityInsight.custom.{0}.ps1' -f $safe))
}

# The machine- and session-level state a guided install must never take a value from: the internal AutomateIT platform's
# public globals, and SecurityInsight settings left in the session by an earlier run (live 2026-10-06 on mgmt1). The
# setup sign-in's own state (SI_AzRestState, SI_TokenProvider, ...) is kept: the install reuses its own sign-in.
$script:SIInstallIsolatedGlobalPatterns = @('SI_*', 'AutomationFramework', 'Context', 'AzureTenantId', 'HighPriv_*', 'KV_HighPriv_*', 'Spn*', 'OpenAI_*', 'SHODAN_*')
$script:SIInstallKeptGlobals = @('SI_AzRestState', 'SI_TokenProvider', 'SI_LogIngestRunCache', 'SI_AzureAccess_Engine', 'SI_LogIngest_Engine', 'SI_PlatformConnectFile',
    # #427: the session's telemetry switch is honoured by the install's failure reports
    'SI_Telemetry_Enabled')

function Get-SIInstallIsolatedGlobalNames {
    <# The names of the session's globals the guided install sets aside for its run. #>
    @(Get-Variable -Scope Global | Where-Object {
        $n = $_.Name
        ($script:SIInstallKeptGlobals -notcontains $n) -and @($script:SIInstallIsolatedGlobalPatterns | Where-Object { $n -like $_ }).Count
    } | ForEach-Object { $_.Name })
}

function Invoke-SIGuidedInstall {
    <#
        Returns the exit code: 0 ok (warnings included), 1 a step failed, 2 preflight failed, 3 bad config.

        ISOLATED from the machine (live 2026-10-06, run on mgmt1): the install uses ONLY its own answers and its own config
        file. For its run the internal AutomateIT platform configuration (bootstrap\platform-config.json) is not discovered
        (SI_PLATFORM_CONFIG=off), and the session's platform globals and SecurityInsight settings are set aside; both are
        put back when the install ends.
    #>
    param(
        [Parameter(Mandatory)][string]$SIRoot,
        [Parameter(Mandatory)][string]$ConfigPath,
        [string]$LicencePath,
        [scriptblock]$Reporter,
        [switch]$PreflightOnly,
        [switch]$Resume,
        [string]$StatePath,
        [System.Collections.IDictionary]$Seams,
        [string]$SIConfigPath
    )
    $prevEnv = [Environment]::GetEnvironmentVariable('SI_PLATFORM_CONFIG')
    $saved = @{}
    foreach ($n in @(Get-SIInstallIsolatedGlobalNames)) {
        $saved[$n] = Get-Variable -Name $n -Scope Global -ValueOnly
        Remove-Variable -Name $n -Scope Global -Force -ErrorAction SilentlyContinue
    }
    [Environment]::SetEnvironmentVariable('SI_PLATFORM_CONFIG', 'off')
    try {
        # #564 (Invardia, customer I 2026-10-10): the WHOLE run is wrapped -- a terminating error outside a step (after the last
        # step's event: saving the state, the outputs, the final event) still posts a 'failed' event with its error lines,
        # so the status page never shows a run that silently stopped.
        try { $code = Invoke-SIGuidedInstallRun @PSBoundParameters }
        catch {
            $code = 1
            $errRecord = $_
            $c = Get-Variable -Scope Global -Name SI_InstallActiveContext -ValueOnly -ErrorAction Ignore
            if ($c -is [System.Collections.IDictionary] -and $c['Seams']) {
                $lines = @(Get-SIInstallErrorText -Record $errRecord -Context 'installer')
                $sid = 'installer'
                try {
                    $null = Send-SIInstallEvent -Ctx $c -StepId $sid -State 'failed' -Message ('The installer stopped: {0}' -f $errRecord.Exception.Message) `
                        -Action ([ordered]@{ text = 'Run the install command again: it continues where it stopped.'; command = [string]$c['ResumeCommand'] }) -Detail ([ordered]@{ error = $lines; step = [string]$c['CurrentStepId'] })
                } catch { }
                Write-SIInstallErrorDetail -Ctx $c -Record $errRecord -Context $sid
                $null = Send-SIInstallFailureTelemetry -Ctx $c -StepId $sid -Message $errRecord.Exception.Message
                try { Save-SIInstallState -Ctx $c } catch { }
            } else { Write-Host ('The installer stopped: {0}' -f $errRecord.Exception.Message) -ForegroundColor Red }
        }
        # #427: a configuration the install refused (exit 3) is reported too -- anonymously: it never got as far as a key or tenant
        if ($code -eq 3) { $null = Send-SIInstallFailureTelemetry -Ctx @{ Seams = $Seams; Pro = $false; Values = [ordered]@{}; InstallKey = '' } -StepId 'config' -Message 'the install configuration (config.json, the parameter file or the licence file) was refused' }
        $code
    } finally {
        [Environment]::SetEnvironmentVariable('SI_PLATFORM_CONFIG', $prevEnv)
        foreach ($n in @(Get-SIInstallIsolatedGlobalNames)) { Remove-Variable -Name $n -Scope Global -Force -ErrorAction SilentlyContinue }
        foreach ($n in $saved.Keys) { Set-Variable -Name $n -Scope Global -Value $saved[$n] -Force }
    }
}

function Get-SIInstallPortalText {
    <#
        PURE apart from reading $Ctx. #564 (owner, 2026-10-10: a customer has no az CLI any more): what a person does by hand
        is said as an AZURE PORTAL path (or "run the install command again") -- never an az command. One place for the
        texts the steps hand over, so none drifts back to az.
          CreateResourceGroup  an Owner creates the resource group and gives the installer access to it
          GrantRgAccess        an Owner gives the installer -Roles on the resource group
          RegisterProviders    a Contributor / Owner registers -Names on the subscription
          PurgeKeyVault        the deleted Key Vault -Names[0] is purged (or another resource group name chosen)
    #>
    param([Parameter(Mandatory)][ValidateSet('CreateResourceGroup', 'GrantRgAccess', 'RegisterProviders', 'PurgeKeyVault')][string]$Kind,
          [Parameter(Mandatory)]$Ctx, [string[]]$Names = @(), [string[]]$Roles = @())
    $v = $Ctx.Values; $n = $Ctx.Names
    $sub = [string]$v['subscriptionId']; $rg = [string]$n.ResourceGroup; $loc = [string]$v['location']
    $who = [string]$Ctx.Facts['userPrincipalName']; if (-not $who) { $who = [string]$Ctx.Facts['userObjectId'] }; if (-not $who) { $who = 'the person installing' }
    switch ($Kind) {
        'CreateResourceGroup' {
            "Ask an Owner of subscription $sub to create resource group $rg in $loc (Azure portal: Resource groups > Create) and to give $who Contributor and Role Based Access Control Administrator on it (the resource group > Access control (IAM) > Add > Add role assignment), then run the install command again:"
        }
        'GrantRgAccess' {
            $r = if ($Roles.Count) { $Roles -join ' and ' } else { 'Contributor and Role Based Access Control Administrator' }
            "Ask an Owner of subscription $sub (or of resource group $rg) to give $who $r on resource group $rg (Azure portal: the resource group > Access control (IAM) > Add > Add role assignment), then run the install command again:"
        }
        'RegisterProviders' {
            "Ask a Contributor or Owner of subscription $sub to register $(($Names | Where-Object { $_ }) -join ', ') (Azure portal: Subscriptions > the subscription > Settings > Resource providers > select each > Register), then run the install command again:"
        }
        'PurgeKeyVault' {
            $kv = @($Names | Where-Object { $_ }) | Select-Object -First 1
            "Purge the deleted Key Vault $kv if it is yours (Azure portal: Key vaults > Manage deleted vaults > subscription $sub > $kv > Purge), or choose another resource group name in the wizard -- the other names follow it. Then run the install command again:"
        }
    }
}

function Wait-SIInstallProviderRegistration {
    <#
        #564: waits until every one of -ProviderNamespace reads Registered (through the Az seam; -Ctx.Seams.Sleep between
        polls), at most -TimeoutSec. Returns the namespaces still not Registered (never throws: a slow registration is a
        warning of the step, not a stop).
    #>
    param([Parameter(Mandatory)]$Ctx, [string[]]$ProviderNamespace = @(), [int]$TimeoutSec = 240, [int]$PollSec = 10)
    $open = @($ProviderNamespace | Where-Object { $_ })
    $polls = [Math]::Max(1, [int][Math]::Ceiling($TimeoutSec / [Math]::Max(1, $PollSec)))
    for ($i = 0; $i -lt $polls -and $open.Count; $i++) {
        $still = @()
        foreach ($ns in $open) {
            $p = $null; try { $p = @(Invoke-SIInstallAz -Ctx $Ctx -Command 'Get-SIResourceProvider' -Arguments ([ordered]@{ ProviderNamespace = $ns; ErrorAction = 'SilentlyContinue' })) } catch { }
            if (-not @($p | Where-Object { [string](Get-SIInstallProp $_ 'RegistrationState') -eq 'Registered' }).Count) { $still += $ns }
        }
        $open = $still
        if ($open.Count -and $i -lt $polls - 1) {
            if ($i -eq 0) { Send-SIInstallProgress -Ctx $Ctx -Message ('waiting for Azure to finish registering {0} (this usually takes a few minutes)' -f ($open -join ', ')) }
            # #876: and again about once a minute, with what is still being registered and for how long
            elseif ((($i * $PollSec) % 60) -lt $PollSec) { Send-SIInstallProgress -Ctx $Ctx -Message ('still waiting for Azure to finish registering {0} -- {1} min so far' -f ($open -join ', '), [int][Math]::Floor($i * $PollSec / 60)) }
            try { & $Ctx.Seams.Sleep $PollSec } catch { }
        }
    }
    $open   # unrolled: callers take @( ... )
}

$script:SIInstallSupportSetupRoles = @('AppRoleAssignment.ReadWrite.All', 'Application.ReadWrite.All')

function Get-SIInstallNoExchangeText {
    <# PURE. #876: the one line said when the tenant has no Exchange Online (information, not a warning). #>
    'Mail is not set up: this tenant has no Exchange Online, so there is no shared mailbox to send from -- set mail up later in Get Started (an SMTP relay works without Exchange Online).'
}

function Test-SIInstallExchangeOnlineSkus {
    <#
        PURE. #876: does a tenant with these subscribed SKUs (Graph /subscribedSkus -> value) have Exchange Online? Yes when
        an ENABLED (or warned) subscription carries an Exchange Online mailbox plan that is provisioned: a service plan named
        EXCHANGE_S_* -- except EXCHANGE_S_FOUNDATION, which every Entra ID licence carries and which gives no mailbox (seen
        on a bare trial tenant: Entra ID P2 alone). Returns $true / $false.
    #>
    param([AllowNull()][object[]]$Skus)
    foreach ($s in @($Skus | Where-Object { $_ })) {
        if ([string](Get-SIInstallProp $s 'capabilityStatus') -notin 'Enabled', 'Warning') { continue }
        foreach ($p in @(Get-SIInstallProp $s 'servicePlans')) {
            $n = [string](Get-SIInstallProp $p 'servicePlanName')
            if ($n -notmatch '^EXCHANGE_S_' -or $n -eq 'EXCHANGE_S_FOUNDATION') { continue }
            if ([string](Get-SIInstallProp $p 'provisioningStatus') -in 'Success', 'PendingProvisioning', 'PendingActivation') { return $true }
        }
    }
    $false
}

function Get-SIInstallExchangeOnline {
    <# #876: $true / $false = the tenant has / has no Exchange Online (Graph subscribedSkus, read with the install's own
       sign-in: Directory.Read.All or Organization.Read.All); $null = it could not be read (then the mail step behaves as
       before). Never throws. #>
    param([Parameter(Mandatory)]$Ctx)
    try {
        $r = Invoke-SIInstallGraph -Ctx $Ctx -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuPartNumber,capabilityStatus,servicePlans'
        if ($null -eq $r) { return $null }
        $hasValue = if ($r -is [System.Collections.IDictionary]) { $r.Contains('value') } else { [bool]$r.PSObject.Properties['value'] }
        if (-not $hasValue) { return $null }
        return (Test-SIInstallExchangeOnlineSkus -Skus @(Get-SIInstallProp $r 'value'))
    } catch { return $null }
}

# ---------------------------------------------------------------------------------------------------------------
# #876: THE REGION AND THE QUOTA, asked of Azure before anything is created
# ---------------------------------------------------------------------------------------------------------------
function ConvertTo-SIInstallRegionKey {
    <# PURE. 'West Europe' / 'westeurope' / ' WestEurope ' -> 'westeurope'. #>
    param([AllowNull()][string]$Name)
    ("$Name" -replace '\s', '').ToLowerInvariant()
}

function Get-SIInstallRegionNeeds {
    <# PURE apart from reading $Ctx. #876: every resource type the install creates, with its label and the region it goes
       to (the Pro database goes to sqlLocation, everything else to location). #>
    param([Parameter(Mandatory)]$Ctx)
    $v = $Ctx.Values
    $loc = ConvertTo-SIInstallRegionKey ([string]$v['location'])
    $sqlLoc = ConvertTo-SIInstallRegionKey $(if ([string]$v['sqlLocation']) { [string]$v['sqlLocation'] } else { [string]$v['location'] })
    $n = @()
    if ([string]$v['workspaceMode'] -ne 'existing') { $n += [pscustomobject]@{ Namespace = 'Microsoft.OperationalInsights'; Type = 'workspaces'; Label = 'the Log Analytics workspace'; Location = $loc } }
    $n += [pscustomobject]@{ Namespace = 'Microsoft.Insights'; Type = 'dataCollectionEndpoints'; Label = 'the data collection endpoint'; Location = $loc }
    $n += [pscustomobject]@{ Namespace = 'Microsoft.Storage'; Type = 'storageAccounts'; Label = 'the storage account'; Location = $loc }
    $n += [pscustomobject]@{ Namespace = 'Microsoft.KeyVault'; Type = 'vaults'; Label = 'the Key Vault'; Location = $loc }
    $n += [pscustomobject]@{ Namespace = 'Microsoft.ContainerRegistry'; Type = 'registries'; Label = 'the container registry'; Location = $loc }
    $n += [pscustomobject]@{ Namespace = 'Microsoft.App'; Type = 'managedEnvironments'; Label = 'the Container Apps environment'; Location = $loc }
    $n += [pscustomobject]@{ Namespace = 'Microsoft.App'; Type = 'jobs'; Label = 'the Container Apps jobs'; Location = $loc }
    $n += [pscustomobject]@{ Namespace = 'Microsoft.ManagedIdentity'; Type = 'userAssignedIdentities'; Label = 'the managed identity'; Location = $loc }
    if ($Ctx.Data -or $Ctx.Pro) {
        $n += [pscustomobject]@{ Namespace = 'Microsoft.Sql'; Type = 'servers'; Label = 'the database server'; Location = $sqlLoc }
        $n += [pscustomobject]@{ Namespace = 'Microsoft.Sql'; Type = 'servers/databases'; Label = 'the database'; Location = $sqlLoc }
        if ([bool]$v['webApp']) { $n += [pscustomobject]@{ Namespace = 'Microsoft.App'; Type = 'containerApps'; Label = 'the web app'; Location = $loc } }
    }
    $n
}

function Test-SIInstallRegionOffer {
    <#
        PURE. #876: what Azure's own metadata says about -Needs. -Providers: namespace -> the provider document (GET
        /subscriptions/<id>/providers/<ns>: resourceTypes[].locations, display names). -StorageSkus: Microsoft.Storage/skus
        value (a 'Location' restriction NotAvailableForSubscription refuses the storage account there). -SubscriptionRegions:
        the regions the subscription may use (GET /subscriptions/<id>/locations: name, metadata.geographyGroup).
        Returns @{ Refused = @( @{ Label; Location } ); Unknown = @(<label>); Alternatives = @(<region>) }.
        A type whose metadata is missing is UNKNOWN (checked when it is created), never refused. Alternatives: the regions
        that accept every needed type, the same geography first, at most six.
    #>
    param([Parameter(Mandatory)][object[]]$Needs, [hashtable]$Providers = @{}, [object[]]$StorageSkus = @(), [object[]]$SubscriptionRegions = @())
    $refused = @(); $unknown = @(); $typeRegions = @{}
    $storageBlocked = @{}
    foreach ($s in @($StorageSkus | Where-Object { $_ })) {
        if ([string](Get-SIInstallProp $s 'kind') -ne 'StorageV2') { continue }
        foreach ($r in @(Get-SIInstallProp $s 'restrictions')) {
            if ([string](Get-SIInstallProp $r 'type') -ne 'Location' -or [string](Get-SIInstallProp $r 'reasonCode') -ne 'NotAvailableForSubscription') { continue }
            foreach ($l in @(Get-SIInstallProp $r 'values')) { $storageBlocked[(ConvertTo-SIInstallRegionKey $l)] = $true }
        }
    }
    $subRegions = @{}
    foreach ($r in @($SubscriptionRegions | Where-Object { $_ })) { $subRegions[(ConvertTo-SIInstallRegionKey ([string](Get-SIInstallProp $r 'name')))] = [string](Get-SIInstallProp (Get-SIInstallProp $r 'metadata') 'geographyGroup') }
    foreach ($nd in $Needs) {
        $doc = $Providers[$nd.Namespace]
        $rt = @(@(Get-SIInstallProp $doc 'resourceTypes') | Where-Object { $_ -and [string](Get-SIInstallProp $_ 'resourceType') -eq $nd.Type }) | Select-Object -First 1
        $locs = @(@(Get-SIInstallProp $rt 'locations') | Where-Object { "$_".Trim() } | ForEach-Object { ConvertTo-SIInstallRegionKey $_ })
        if (-not $locs.Count) { $unknown += $nd.Label; continue }
        $typeRegions[$nd.Namespace + '/' + $nd.Type] = $locs
        $no = ($locs -notcontains $nd.Location) -or ($subRegions.Count -and -not $subRegions.ContainsKey($nd.Location)) -or ($nd.Type -eq 'storageAccounts' -and $storageBlocked.ContainsKey($nd.Location))
        if ($no) { $refused += [pscustomobject]@{ Label = $nd.Label; Location = $nd.Location } }
    }
    $alt = @()
    if ($refused.Count -and $typeRegions.Count) {
        $cand = $null
        foreach ($k in $typeRegions.Keys) { $cand = if ($null -eq $cand) { @($typeRegions[$k]) } else { @($cand | Where-Object { $typeRegions[$k] -contains $_ }) } }
        $cand = @($cand | Where-Object { -not $storageBlocked.ContainsKey($_) -and (-not $subRegions.Count -or $subRegions.ContainsKey($_)) } | Select-Object -Unique)
        $geo = ''; $first = @($refused)[0].Location; if ($subRegions.ContainsKey($first)) { $geo = $subRegions[$first] }
        $same = @($cand | Where-Object { $geo -and $subRegions[$_] -eq $geo } | Sort-Object)
        $alt = @(@($same) + @($cand | Where-Object { $same -notcontains $_ } | Sort-Object) | Select-Object -First 6)
    }
    @{ Refused = $refused; Unknown = $unknown; Alternatives = $alt }
}

function Invoke-SIInstallArmGetJson {
    <# #876: a GET over ARM through the Az seam; the parsed body, or $null when it could not be read (never throws). #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Path)
    try {
        $r = Invoke-SIInstallAz -Ctx $Ctx -Command 'Invoke-SIAzRestMethod' -Arguments ([ordered]@{ Method = 'GET'; Path = $Path })
        if ($null -eq $r -or [int](Get-SIInstallProp $r 'StatusCode') -ge 400) { return $null }
        $c = [string](Get-SIInstallProp $r 'Content')
        if (-not $c.Trim()) { return $null }
        return ($c | ConvertFrom-Json)
    } catch { return $null }
}

function Get-SIInstallQuotaNeed {
    <#
        PURE apart from loading SecurityInsight's own sizing rules. #876: the Container Apps cores SecurityInsight can use
        at once, from the numbers its sizing sets (setup\_shared\SI-JobSizing.ps1): every engine job at the floor every
        job is raised to (Get-SIJobFloorChange), the pipeline job besides, and for Pro the web app at its largest size
        ($script:SIWebAppMaxCpu). Returns @{ Cores; Jobs; JobCpu; WebAppCpu }.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [int]$Jobs = 1, [switch]$WebApp)
    $lib = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-JobSizing.ps1')
    & {
        . $lib
        $floor = Get-SIJobFloorChange -Job ([pscustomobject]@{ name = 'caj-si-sizing-probe'; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ resources = [pscustomobject]@{ cpu = 0.25; memory = '0.5Gi' } }) }; configuration = [pscustomobject]@{ replicaTimeout = 1800 } } })
        $jobCpu = [double]::Parse([string]$floor.Cpu, [Globalization.CultureInfo]::InvariantCulture)
        $web = if ($WebApp) { [double]$script:SIWebAppMaxCpu } else { 0.0 }
        @{ Cores = ($jobCpu * $Jobs) + $web; Jobs = $Jobs; JobCpu = $jobCpu; WebAppCpu = $web }
    }
}

function Get-SIInstallHandoffResources {
    <# PURE. #876: the token audiences an install signed in by a hand-over needs from the start: Azure Resource Manager,
       Microsoft Graph, Key Vault (the install's keys) and Storage (the jobs' queues) -- and Azure SQL where the install has the database (both versions since 2026-10-18). #>
    param([Parameter(Mandatory)]$Ctx)
    $r = @('https://management.azure.com/', 'https://graph.microsoft.com/', 'https://vault.azure.net/', 'https://storage.azure.com/')
    if ($Ctx.Data -or $Ctx.Pro) { $r += 'https://database.windows.net/' }
    $r
}

function Get-SIInstallHandoffCheck {
    <# #876: which of the needed handed-over tokens are missing or about to run out. @{ Missing; Expired } -- both empty
       when the install did not sign in by a hand-over (or a Support session in the shell answers instead). #>
    param([Parameter(Mandatory)]$Ctx)
    $none = @{ Missing = @(); Expired = @() }
    if ([string]$Ctx.Facts['signInMethod'] -ne 'Handoff') { return $none }
    $h = $null; try { $h = Get-SISetupHandoff } catch { }
    if (-not ($h -is [hashtable])) { return $none }
    $s = Get-SISetupHandoffStatus -Handoff $h -Resources @(Get-SIInstallHandoffResources -Ctx $Ctx) -NowUtc ((& $Ctx.Seams.Now).ToUniversalTime())
    @{ Missing = @($s.Missing | ForEach-Object { $_.TrimEnd('/') }); Expired = @($s.Expired | ForEach-Object { $_.TrimEnd('/') }) }
}

function Assert-SIInstallWebAppAdmins {
    <#
        #876: an install that runs as an APPLICATION (the Invardia Support app, a handed-over app sign-in) needs the web app's
        administrators NAMED -- an application cannot sign in to the web app, so it is never made one -- and every name must
        be a user in the directory (read through Microsoft Graph with the install's own sign-in: Directory.Read.All). Throws
        the install failure with one plain line otherwise. A person installing, a package without the web app steps, or no web app: nothing
        to check. Returns the resolved users (Id, UserPrincipalName) and keeps their ids in Facts['webAppAdminIds'].
    #>
    param([Parameter(Mandatory)]$Ctx)
    $v = $Ctx.Values
    if (-not ($Ctx.Data -or $Ctx.Pro) -or -not [bool]$v['webApp'] -or -not (Test-SIInstallSignedInAsApp -Ctx $Ctx)) { return @() }
    $named = @(@($v['webAppAdmins']) | ForEach-Object { "$_" -split '[,;\s]+' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if (-not $named.Count) {
        throw (New-SIInstallFailure -Message 'Name at least one person who administers the web app (Web app administrators): the install runs as an application, which cannot sign in to the web app. Nothing was changed.' `
            -ActionText 'Add the people who administer the web app under "Web app administrators" on the installation page (webAppAdmins in config.json), then run the install command again:' -Command $Ctx.ResumeCommand)
    }
    $found = @(); $bad = @()
    foreach ($nm in $named) {
        $u = $null
        try { $u = Invoke-SIInstallGraph -Ctx $Ctx -Uri ('https://graph.microsoft.com/v1.0/users/{0}?$select=id,userPrincipalName,accountEnabled' -f [uri]::EscapeDataString($nm)) } catch { $u = $null }
        if ($u -and [string](Get-SIInstallProp $u 'id')) { $found += [pscustomobject]@{ Id = [string](Get-SIInstallProp $u 'id'); UserPrincipalName = [string](Get-SIInstallProp $u 'userPrincipalName') } }
        else { $bad += $nm }
    }
    if ($bad.Count) {
        throw (New-SIInstallFailure -Message ('These web app administrators are not users in this tenant (or could not be read): {0}. Nothing was changed.' -f ($bad -join ', ')) `
            -ActionText 'Correct "Web app administrators" on the installation page (a user principal name of this tenant, e.g. admin@contoso.onmicrosoft.com), then run the install command again:' -Command $Ctx.ResumeCommand)
    }
    $Ctx.Facts['webAppAdminIds'] = @($found | ForEach-Object { $_.Id })
    $found
}

function Get-SIInstallSupportMissingRoles {
    <#
        #564 (Invardia): the Microsoft Graph application permissions the Invardia support app needs for an install (Setup
        access) that its Graph token does NOT carry -- read from the token's 'roles' claim (the token the install already
        uses, through the Token seam; no extra call). An unreadable token = every one missing (said, never guessed).
    #>
    param([Parameter(Mandatory)]$Ctx)
    $roles = @()
    try {
        $tok = [string](& $Ctx.Seams.Token 'https://graph.microsoft.com')
        $claims = ConvertFrom-SIJwtPayload $tok
        if ($claims -and $claims.PSObject.Properties['roles']) { $roles = @($claims.roles | ForEach-Object { [string]$_ }) }
    } catch { $roles = @() }
    @($script:SIInstallSupportSetupRoles | Where-Object { $roles -notcontains $_ })
}

# Either of these lets the support app consent to the web app's sign-in permissions for the organisation (the step that
# keeps "Approval required" away in a tenant that does not let users consent).
$script:SIInstallSupportConsentRoles = @('DelegatedPermissionGrant.ReadWrite.All', 'Directory.ReadWrite.All')

function Test-SIInstallSupportCanConsent {
    <#
        Can the Invardia support app consent to the web app's sign-in permissions for the organisation? Read from the roles
        of its Microsoft Graph token (the Token seam; no extra call). $true / $false; an unreadable token = $false.
        NOT a stop: without it the install goes on and the web app step ends as a warning with what an administrator does.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $roles = @()
    try {
        $claims = ConvertFrom-SIJwtPayload ([string](& $Ctx.Seams.Token 'https://graph.microsoft.com'))
        if ($claims -and $claims.PSObject.Properties['roles']) { $roles = @($claims.roles | ForEach-Object { [string]$_ }) }
    } catch { $roles = @() }
    [bool](@('DelegatedPermissionGrant.ReadWrite.All', 'Directory.ReadWrite.All' | Where-Object { $roles -contains $_ }).Count)
}

function Resolve-SIInstallResumeFacts {
    <#
        #564 (PIM's install at customer I: a resume skipped the step that set a name, and a later step had none): on a resume, what
        a SKIPPED (done earlier) step would have set is DERIVED when the state does not carry it -- the Pro database
        server's id from the install's names, the managed identity's ids by reading it from the resource group. Never
        throws: a value that cannot be derived stays empty and the step that needs it says so.
    #>
    param([Parameter(Mandatory)]$Ctx)
    $done = @($Ctx.State['completed'])
    $n = $Ctx.Names; $sub = [string]$Ctx.Values['subscriptionId']
    try {
        if (($Ctx.Data -or $Ctx.Pro) -and -not [string]$Ctx.Facts['sqlServerId'] -and $done -contains 'pro-sql' -and [string]$n.SqlServer) {
            $Ctx.Facts['sqlServerId'] = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Sql/servers/{2}' -f $sub, $n.ResourceGroup, $n.SqlServer
        }
        if ((-not [string]$Ctx.Facts['identityClientId'] -or -not [string]$Ctx.Facts['identityPrincipalId']) -and $done -contains 'runtime-identity') {
            $id = Invoke-SIInstallAz -Ctx $Ctx -Command 'Get-SIUserAssignedIdentity' -Arguments ([ordered]@{ ResourceGroupName = $n.ResourceGroup; Name = $n.ManagedIdentity; ErrorAction = 'SilentlyContinue' })
            if ($id) {
                $Ctx.Facts['identityClientId'] = [string](Get-SIInstallProp $id 'ClientId')
                $Ctx.Facts['identityPrincipalId'] = [string](Get-SIInstallProp $id 'PrincipalId')
            }
        }
    } catch { }
}

function Test-SIInstallStartedByInvardia {
    <#
        Was this install started by Invardia's bootstrap (Install-Invardia)? It runs the product with its state in
        <installation folder>\product, next to the bootstrap's own state.json. PURE apart from one file check.
    #>
    param([AllowEmptyString()][string]$StateDirectory)
    if (-not "$StateDirectory".Trim()) { return $false }
    $leaf = Split-Path -Leaf ("$StateDirectory".TrimEnd('\', '/'))
    if ($leaf -ne 'product') { return $false }
    $parent = Split-Path -Parent ("$StateDirectory".TrimEnd('\', '/'))
    [bool]($parent -and (Test-Path -LiteralPath ([IO.Path]::Combine($parent, 'state.json'))))
}

function Get-SIInstallResumeCommand {
    <#
        #564 (Invardia, customer I 2026-10-10): the command every failure tells the person to run. An install Invardia's bootstrap
        started resumes THROUGH the bootstrap -- Install-Invardia -Resume -InstallId <id> downloads the NEWEST release of the
        install's ring, so a re-run after a hotfix picks the fix up and continues (the steps of another release are redone,
        Get-SIInstallResumeRedoSteps). A local run resumes this package.
    #>
    param([Parameter(Mandatory)][string]$ConfigPath, [string]$LicencePath, [Parameter(Mandatory)][string]$StateDirectory, [Parameter(Mandatory)][string]$InstallId)
    if (Test-SIInstallStartedByInvardia -StateDirectory $StateDirectory) { return ('Install-Invardia -Resume -InstallId {0}' -f $InstallId) }
    './setup/Install-SecurityInsight.ps1 -ConfigPath {0}{1} -Resume -StatePath {2}' -f $ConfigPath, $(if ($LicencePath) { ' -LicencePath ' + $LicencePath } else { '' }), $StateDirectory
}

function Invoke-SIGuidedInstallRun {
    <# The install itself; Invoke-SIGuidedInstall runs it isolated from the machine. #>
    param(
        [Parameter(Mandatory)][string]$SIRoot,
        [Parameter(Mandatory)][string]$ConfigPath,
        [string]$LicencePath,
        [scriptblock]$Reporter,
        [switch]$PreflightOnly,
        [switch]$Resume,
        [string]$StatePath,
        [System.Collections.IDictionary]$Seams,
        [string]$SIConfigPath
    )
    $seamSet = Get-SIInstallDefaultSeams
    if ($Seams) { foreach ($k in $Seams.Keys) { if ($Seams[$k] -is [scriptblock]) { $seamSet[$k] = $Seams[$k] } } }
    $say = { param($t, $c) try { & $seamSet.Print $t $c } catch { } }

    # ---- config + parameter file (exit 3) ----
    $specPath = [IO.Path]::Combine($SIRoot, 'setup', 'install-parameters.json')
    try { $spec = [IO.File]::ReadAllText($specPath) | ConvertFrom-Json } catch { & $say ('The parameter file could not be read: {0}' -f $_.Exception.Message) 'Red'; return 3 }
    if (-not (Test-Path -LiteralPath $ConfigPath)) { & $say ('config.json not found: {0}' -f $ConfigPath) 'Red'; return 3 }
    try { $cfg = [IO.File]::ReadAllText($ConfigPath) | ConvertFrom-Json } catch { & $say ('config.json is not valid JSON: {0}' -f $_.Exception.Message) 'Red'; return 3 }
    if ($LicencePath -and -not (Test-Path -LiteralPath $LicencePath)) { & $say ('Licence file not found: {0}' -f $LicencePath) 'Red'; return 3 }
    $edition = Resolve-SISetupEdition -LicencePath $LicencePath
    $check = Test-SIInstallConfig -Config $cfg -Spec $spec -Edition $edition
    if (-not $check.Ok) {
        & $say 'config.json does not match this version''s parameters:' 'Red'
        foreach ($e in $check.Errors) { & $say ('  ' + $e) 'Red' }
        return 3
    }

    # ---- the context ----
    $pro = [bool](Get-Command -Name Get-SIInstallProStepTable -ErrorAction SilentlyContinue)
    # the database and web app steps: every package carries them (SI-GuidedInstallData.ps1, both versions)
    $data = [bool](Get-Command -Name Get-SIInstallDataStepTable -ErrorAction SilentlyContinue)
    $steps = Get-SIInstallStepTable
    $proSteps = @{}
    if ($data) { $ds = Get-SIInstallDataStepTable; foreach ($k in $ds.Keys) { $proSteps[$k] = $ds[$k] } }
    if ($pro) { $ps = Get-SIInstallProStepTable; foreach ($k in $ps.Keys) { $proSteps[$k] = $ps[$k] } }
    $verFile = [IO.Path]::Combine($SIRoot, 'VERSION')
    $version = if (Test-Path -LiteralPath $verFile) { ([IO.File]::ReadAllText($verFile)).Trim() } else { '0.0.0' }
    $commitFile = [IO.Path]::Combine($SIRoot, 'SOURCE-COMMIT.txt')
    $commit = if (Test-Path -LiteralPath $commitFile) { (([IO.File]::ReadAllText($commitFile)).Trim() -split '\s+')[0] } else { '' }
    # the build this package is (BUILD.json, stamped when the package was built): printed at the start, kept in the state
    $buildInfo = $null
    try {
        $biLib = [IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-BuildInfo.ps1')
        if (-not (Get-Command -Name Read-SIBuildInfo -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $biLib)) { . $biLib }
        if (Get-Command -Name Read-SIBuildInfo -ErrorAction SilentlyContinue) { $buildInfo = Read-SIBuildInfo -SolutionRoot $SIRoot }
    } catch { $buildInfo = $null }
    if (-not $commit -and $buildInfo -and $buildInfo.commit) { $commit = [string]$buildInfo.commit }
    $buildLine = if ($buildInfo) { Format-SIBuildLine $buildInfo } else { '{0} (build unknown)' -f $version }
    $stateDir = Get-SIInstallStateDirectory -StatePath $StatePath -InstallId $check.InstallId
    $resumeCmd = Get-SIInstallResumeCommand -ConfigPath $ConfigPath -LicencePath $LicencePath -StateDirectory $stateDir -InstallId $check.InstallId
    $ctx = @{
        InstallId = $check.InstallId; Edition = $edition; Values = $check.Values; Explicit = $check.Explicit; Spec = $spec
        SIRoot = $SIRoot; ConfigPath = $(if ($SIConfigPath) { $SIConfigPath } else { Get-SIInstallOwnConfigPath -SIRoot $SIRoot -InstallId $check.InstallId })
        LicencePath = $LicencePath; Version = $version; ImageTag = ('v{0}{1}' -f $version, $(if ($commit) { '-' + $commit.Substring(0, [Math]::Min(12, $commit.Length)) } else { '' }))
        Seams = $seamSet; Reporter = $Reporter; PreflightOnly = [bool]$PreflightOnly; Pro = ($pro -and $edition -eq 'pro'); Data = $data; ProSteps = $proSteps
        StateDirectory = $stateDir; ResumeCommand = $resumeCmd
        Cache = [ordered]@{}; Events = New-Object System.Collections.Generic.List[object]; ScriptLog = New-Object System.Collections.Generic.List[object]
    }
    # #240: the install key (a secret from Invardia's bundle) leaves the answers at once: it is kept only on the context, stored
    # in the Key Vault by the key-vault step, and never reaches a script, the product config, the state file or an event.
    $ctx.InstallKey = ''
    foreach ($p in @(Get-SIInstallProp $spec 'parameters' | Where-Object { [string](Get-SIInstallProp $_ 'type') -eq 'secret' })) {
        $sk = [string](Get-SIInstallProp $p 'key')
        if ($ctx.Values.Contains($sk)) { if ($sk -eq 'installKey') { $ctx.InstallKey = [string]$ctx.Values[$sk] }; $ctx.Values.Remove($sk) }
        $ctx.Explicit = @($ctx.Explicit | Where-Object { $_ -ne $sk })
    }
    # #564: the context that runs (sub-step and sign-in events, the whole-run failure event) and the sign-in's
    # "waiting: sign-in required for <resource> in tenant <t>" line, posted BEFORE a browser window opens. Both SI_*
    # globals: Invoke-SIGuidedInstall removes them when the install ends. Not a closure (#564: a GetNewClosure() block
    # cannot see the functions this file defines).
    $global:SI_InstallActiveContext = $ctx
    $global:SI_SignInNotify = { param([string]$Resource, [string]$TenantId) Send-SIInstallProgress -Message ('waiting: sign-in required for {0} in tenant {1}' -f $Resource, $(if ("$TenantId".Trim()) { $TenantId } else { 'your organisation' })) }
    # #876: a long wait inside a step (a resource Azure is still making, the image build, the database) says what it waits
    # for, at most once a minute, as a progress event of the running step (SI-SetupArm.ps1 Send-SISetupWaitProgress)
    $global:SI_InstallWaitNotify = { param([string]$Message) Send-SIInstallProgress -Message $Message }
    $global:SI_InstallWaitLastAt = $null
    $ctx.Names = Get-SIInstallNames -Values $ctx.Values -Explicit $ctx.Explicit -Edition $edition
    $ctx.Engines = @($script:SIInstallCommunityEngines)
    # The privilege-tier classifier needs Azure OpenAI: without it Bootstrap leaves the job out on purpose (every role
    # would become Tier 99 and replace the shipped catalog -- Select-SIBootstrapEngines). An install without AI
    # classification therefore never expects that job (live 2026-10-06, Community rehearsal: "These engine jobs were not
    # created: caj-si-ptc").
    if (-not [bool]$ctx.Values['aiClassification']) { $ctx.Engines = @($ctx.Engines | Where-Object { $_ -ne 'privilege-tier-classifier' }) }
    if ($ctx.Pro) { $ctx.Engines += @(Get-SIInstallProEngines -Values $ctx.Values) }
    $ctx.Engines = @($ctx.Engines | Select-Object -Unique)
    foreach ($k in $proSteps.Keys) { if (($script:SIInstallProStepIds + $script:SIInstallDataStepIds) -contains $k) { $steps[$k] = $proSteps[$k] } }

    # ---- state (resume) ----
    $prior = Read-SIInstallState -Directory $stateDir
    if ($prior -and [string]$prior['installId'] -ne $ctx.InstallId) { $prior = $null }
    $ctx.State = [ordered]@{
        installId = $ctx.InstallId; edition = $edition; version = $version
        build = [ordered]@{
            display = $(if ($buildInfo) { [string]$buildInfo.display } else { $version })
            commit = $(if ($buildInfo) { [string]$buildInfo.commit } else { '' })
            builtUtc = $(if ($buildInfo) { [string]$buildInfo.builtUtc } else { '' })
            channel = $(if ($buildInfo) { $buildInfo.channel } else { $null })
        }
        seq = $(if ($prior) { [int]$prior['seq'] } else { 0 })
        completed = @(); pending = [ordered]@{}; failedStep = $null; facts = [ordered]@{}
        startedAt = (& $seamSet.Now).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Resume -and $prior) {
        $ctx.State['completed'] = @($prior['completed'] | Where-Object { $_ })
        if ($prior['pending']) { $ctx.State['pending'] = ConvertTo-SIInstallHashtable $prior['pending'] }
        if ($prior['facts'])   { $ctx.State['facts'] = ConvertTo-SIInstallHashtable $prior['facts'] }
        $redo = @(Get-SIInstallResumeRedoSteps -Prior $prior -Version $version -Commit $(if ($commit) { [string]$commit } else { [string]$ctx.State['build']['commit'] }) -Completed @($ctx.State['completed']))
        if ($redo.Count) {
            $ctx.State['completed'] = @($ctx.State['completed'] | Where-Object { $redo -notcontains $_ })
            & $say ('An earlier run installed another release; this run installs {0} again: {1}.' -f $buildLine, (($redo | ForEach-Object { $script:SIInstallStepTitles[$_] }) -join ', ')) 'Yellow'
        }
    }
    $ctx.Facts = $ctx.State['facts']
    if ($ctx.Facts['infra']) { $ctx.Cache['infra'] = $ctx.Facts['infra'] }
    # #479: a new install key (a new enrollment claim) replaces the stored one -- the vault keeps only the last
    $rot = Get-SIInstallKeyRotation -InstallKey $ctx.InstallKey -Facts $ctx.Facts -Completed @($ctx.State['completed'])
    if ($rot.Rotated) {
        $ctx.State['completed'] = @($rot.Completed)
        & $say 'This run carries a new Invardia install key: it replaces the one an earlier run stored.' 'Yellow'
    }

    & $say ('SecurityInsight {0} -- guided install {1} ({2} edition{3})' -f $buildLine, $ctx.InstallId, $edition, $(if ($PreflightOnly) { ', checks only' } else { '' })) 'Cyan'
    if (-not $SIConfigPath -and $ctx.ConfigPath -ne [IO.Path]::Combine($SIRoot, 'config', 'SecurityInsight.custom.ps1')) {
        & $say ('config\SecurityInsight.custom.ps1 here belongs to another install; this install keeps its own settings in {0} (the other file is not read or changed).' -f $ctx.ConfigPath) 'Yellow'
    }

    # ---- a resume in a package copy that does not hold the install's settings file: put it back BEFORE any step ----
    # (a first run, and a checks-only run, are untouched: nothing is restored, nothing is said)
    $priorDone = @()
    if ($Resume -and $prior) { $priorDone = @($prior['completed'] | Where-Object { $_ }) }
    if ($priorDone.Count -and -not $PreflightOnly) {
        $back = Restore-SIInstallConfigFile -Ctx $ctx
        if ($back.Source -eq 'state') {
            & $say ('The install''s settings file was not in this copy of SecurityInsight (or was older): it was taken from the install''s saved state, {0}.' -f $back.From) 'Yellow'
        } elseif ($back.Source -eq 'package') {
            & $say ('The install''s settings file was not in this copy of SecurityInsight: it was taken from the earlier copy an earlier run used, {0}, and is now kept with the install''s saved state too.' -f $back.From) 'Yellow'
        } elseif (-not $back.Present -and $priorDone -contains 'key-vault') {
            # The steps from the Key Vault on wrote that file and the later ones read it. Without it the only way on is to
            # write it again from what the state recorded (below, after the checks) -- and without that, NOT AT ALL.
            if ($ctx.Facts['infra']) {
                & $say 'The install''s settings file was not found in this copy of SecurityInsight, with the install''s saved state or in an earlier copy: it is written again from what the saved state recorded.' 'Yellow'
            } else {
                $null = Send-SIInstallEvent -Ctx $ctx -StepId 'installer' -State 'failed' `
                    -Message ('This install cannot continue here: {0} steps are done, but the settings file the earlier run wrote (config\SecurityInsight.custom.ps1) is not in this copy of SecurityInsight, not with the install''s saved state ({1}) and not in an earlier copy next to it. Nothing was changed.' -f $priorDone.Count, $stateDir) `
                    -Action ([ordered]@{ text = 'Run the install command on the same machine or cloud drive that ran the first part of the install, or contact Invardia support:'; command = $resumeCmd })
                return 2
            }
        }
    }

    # ---- #479: an enrollment install is always Pro -- without its licence it never falls back to Community (exit 2) ----
    if ($check.Enrollment -and -not $LicencePath) {
        $null = Send-SIInstallEvent -Ctx $ctx -StepId 'licence' -State 'failed' `
            -Message 'This install comes from an enrollment key, but its SecurityInsight Pro licence is not here yet -- Invardia is probably still signing it. Nothing was installed.' `
            -Action ([ordered]@{ text = 'Wait a few minutes, then run the install again (it continues where it stopped):'; command = 'Install-Invardia -Resume -InstallId ' + $ctx.InstallId })
        return 2
    }

    # ---- preflight (exit 2) ----
    $plan = @(Get-SIInstallStepPlan -Edition $(if ($ctx.Pro) { 'pro' } else { 'community' }) -PreflightOnly:$PreflightOnly -Options (Get-SIInstallChosenOptions -Values $ctx.Values))
    # a copy without the database steps' file (an older package layout) cannot run them: they are left out, never failed
    if (-not ($ctx.Data -or $ctx.Pro)) { $plan = @($plan | Where-Object { $script:SIInstallDataStepIds -notcontains $_.Id }) }
    $preFailed = $false; $stopChecks = $false
    foreach ($s in @($plan | Where-Object { $_.Preflight })) {
        if ($stopChecks) { $null = Send-SIInstallEvent -Ctx $ctx -StepId $s.Id -State 'skipped' -Message 'Not checked: the sign-in or the target failed first.'; continue }
        $state = Invoke-SIInstallStep -Ctx $ctx -StepId $s.Id -Body $steps[$s.Id]
        if ($state -eq 'failed') { $preFailed = $true; if ($s.Id -in 'preflight-signin', 'preflight-target', 'preflight-rights') { $stopChecks = $true } }
    }
    if ($preFailed) { Save-SIInstallState -Ctx $ctx; return 2 }
    if ($PreflightOnly) { & $say 'All checks passed. Nothing was changed.' 'Green'; return 0 }

    # ---- the install (exit 1) ----
    if ($Resume) {
        Resolve-SIInstallResumeFacts -Ctx $ctx
        # THE SETTINGS FILE IS WRITTEN AGAIN FROM THE SAVED STATE at the start of every resume: a resume that runs from a
        # newer package folder has none (the steps that write it are done and skipped), and the container setup and the
        # grants read it. Only once the infrastructure step recorded its values; a failure is said, the steps go on.
        if ($ctx.Facts['infra'] -and @($ctx.State['completed']) -contains 'key-vault') {
            try { Update-SIInstallConfigFile -Ctx $ctx }
            catch { & $say ('The install''s settings file could not be written again from the saved state ({0}); the steps that need it say so.' -f $_.Exception.Message) 'Yellow' }
        }
    }
    foreach ($s in @($plan | Where-Object { -not $_.Preflight -and $_.Id -ne 'completed' })) {
        # The first run is done only when it STARTED: a first run that waited for grants runs on the next resume, once they are
        # made (live 2026-10-06, Community rehearsal: the resume after the grants said "Done in an earlier run" and never ran it).
        $notStarted = ($s.Id -eq 'first-run' -and -not [string]$ctx.Facts['firstRunStarted'])
        if ($Resume -and @($ctx.State['completed']) -contains $s.Id -and -not $notStarted) {
            $null = Send-SIInstallEvent -Ctx $ctx -StepId $s.Id -State 'skipped' -Message 'Done in an earlier run.'
            continue
        }
        $state = Invoke-SIInstallStep -Ctx $ctx -StepId $s.Id -Body $steps[$s.Id]
        # #564: a failed step closes the install's SQL firewall rule too (the resume opens it again for its own address)
        # ...and an install that ran as an application hands the database server's administration back to the admin group
        if ($state -eq 'failed') { $null = Close-SIInstallDatabaseAccess -Ctx $ctx; $ctx.State['failedStep'] = $s.Id; Save-SIInstallState -Ctx $ctx; return 1 }
        if ($state -in 'ok', 'skipped' -and @($ctx.State['completed']) -notcontains $s.Id) { $ctx.State['completed'] = @($ctx.State['completed']) + $s.Id }
        $ctx.State['failedStep'] = $null
        Save-SIInstallState -Ctx $ctx
    }
    # #564: the install's own SQL firewall rule (AllowSetupHost) is closed at the end -- a close that fails is a warning;
    # the database server's administration goes back to the admin group here too (whichever database step ran last)
    $null = Close-SIInstallDatabaseAccess -Ctx $ctx
    # the updater job is started ONCE at the end of a finished install (as the first run is): the licence record the web
    # app reads then exists now, not only after the night's run (Start-SIInstallUpdaterOnce, Pro only; never fails the install)
    try { if (($ctx.Data -or $ctx.Pro) -and (Get-Command -Name Start-SIInstallUpdaterOnce -ErrorAction SilentlyContinue)) { $null = Start-SIInstallUpdaterOnce -Ctx $ctx } } catch { }
    $outputs = Get-SIInstallOutputs -Ctx $ctx
    $pendingCount = @($ctx.State['pending'].Keys).Count
    $null = Send-SIInstallEvent -Ctx $ctx -StepId 'completed' -State 'completed' -Outputs $outputs `
        -Message $(if ($pendingCount) { 'SecurityInsight is installed. Some grants are still waiting for the right person (see above).' } else { 'SecurityInsight is installed.' })
    $ctx.State['completedAt'] = (& $seamSet.Now).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $ctx.State['outputs'] = $outputs
    Save-SIInstallState -Ctx $ctx
    0
}
