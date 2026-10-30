#Requires -Version 5.1
<#
    SecurityInsight -- how CONTAINER hosting receives its configuration (pure; no Azure, no network).

    The container is deliberately its own configuration layer: it never loads config\SecurityInsight.custom.ps1
    (the image must not carry a tenant's values; see Start-SIInContainer.ps1). Each setting arrived as one
    hand-written env-var mapping, so ~45 of the settings a VM honours never reached a container at all
    (2026-09-30 config review, #187), and neither did trend or the Pro engines (#170).

    ONE GUARDED CHANNEL instead (#170/#187): Bootstrap-ContainerAppJob.ps1 passes named, NON-SECRET settings
    from the customer's config as  SI_CFG_<GlobalName>=<value>  (JSON when the value is not a plain string);
    the container restores each as $global:<GlobalName> with its type. Secrets never travel this way -- a
    name that looks like one is refused on both ends -- and nothing here may override the credentials the
    container's own env vars supply.

    Also here, because each is a decision the entrypoints must make identically:
      * AI: on only when Azure OpenAI is actually configured, and only if asked for (#184);
      * sign-in (#209): managed identity > certificate (PFX from Key Vault) > client secret -- how a job signs
        in (Resolve-SIContainerAuthMode), what Bootstrap gives each job for it (Get-SIContainerJobAuthArgs),
        and the managed identity's required grants (Get-SIContainerIdentityGrantPlan).
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../engine/_shared/SI-AzRest.ps1') }

$script:SIConfigEnvPrefix = 'SI_CFG_'

# Names the container's own env vars own. A passthrough value for any of these is ignored: the explicit
# credential / target a Container App Job was given must never be overridden by a copied config value.
$script:SIConfigProtected = @(
    'SI_SPN_AppId', 'SI_SPN_Secret', 'SI_SPN_TenantId', 'SI_SPN_ObjectId',
    # #209: the job's sign-in identity is decided by the container from its own env, never by a copied setting.
    'SI_UseManagedIdentity', 'SI_UAMI_ClientId', 'SI_PreferUami', 'SI_SPN_CertStoreLocation',
    'SI_StorageAccount',
    'SI_WorkspaceResourceId', 'SI_DceName', 'SI_DcrResourceGroup',
    'OpenAI_apiKey', 'OpenAI_endpoint', 'OpenAI_deployment', 'OpenAI_apiVersion',
    'SI_License', 'SHODAN_ApiKey', 'SI_Shodan_ApiKey',
    # The internal platform framework (FUNCTIONS\AutomateITPS) exists only on an internal VM -- never in a container.
    # Live 2026-10-02: an internal install's AutomationFramework = $true travelled as SI_CFG_AutomationFramework and
    # the tier classifier failed in the container looking for that module.
    'AutomationFramework'
)

# Known NON-secret settings whose names happen to match the secret filter below (a token LIMIT, a tenant id). Exact names
# only -- the filter stays broad for everything else, so a new name that looks like a credential is still refused.
$script:SIConfigNotSecret = @('AI_MaxTokens', 'AI_MaxTokensPerRequest', 'OpenAI_MaxTokensPerRequest', 'SI_IdentityTokenTenantId')

function Test-SIConfigNameIsSecret {
    <# A name that holds a credential never travels as a plain env var. Deliberately broad; only the exact names in
       $script:SIConfigNotSecret are let through. #>
    param([Parameter(Mandatory)][string]$Name)
    if ($script:SIConfigNotSecret -contains $Name) { return $false }
    return ($Name -match '(?i)(secret|password|passwd|pwd|apikey|api_key|token|credential|connectionstring|sas|privatekey|pfx|thumbprint|storagekey|accountkey|license)')
}

function ConvertTo-SIConfigEnvValue {
    <# PURE. A config value as an env-var string: plain strings as-is, everything else as compact JSON. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
    return (ConvertTo-Json -InputObject $Value -Compress -Depth 6)
}

function ConvertFrom-SIConfigEnvValue {
    <#
      PURE. The inverse. JSON arrays/objects/numbers/booleans/null are decoded; anything else stays a string,
      so a plain value such as 'westeurope' or '0 4 * * *' is never mangled.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return $null }
    $t = $Text.Trim()
    if ($t -eq 'null') { return $null }
    if ($t -eq 'true') { return $true }
    if ($t -eq 'false') { return $false }
    if ($t -match '^-?\d+$') { return [int64]$t }
    if ($t -match '^-?\d+\.\d+$') { return [double]::Parse($t, [Globalization.CultureInfo]::InvariantCulture) }
    if ($t.StartsWith('[') -or $t.StartsWith('{')) {
        # A list of plain words (no quotes, no nesting) is read without ConvertFrom-Json: decoding it would throw, and even
        # a caught throw writes a "TerminatingError(ConvertFrom-Json)" line into the run's transcript at every container
        # start -- the line that then stood as the failure text of a step that failed for another reason. A list of JSON
        # literals only (numbers, true / false / null) is valid JSON and still goes through ConvertFrom-Json.
        if ($t -match '^\[\s*\]$') { return , @() }
        if ($t -match '^\[\s*[^\[\]{}",]+(\s*,\s*[^\[\]{}",]+)*\s*\]$') {
            $words = @($t.Substring(1, $t.Length - 2).Split(',') | ForEach-Object { $_.Trim() })
            if (@($words | Where-Object { $_ -notmatch '^(-?\d+(\.\d+)?([eE][+-]?\d+)?|true|false|null)$' }).Count -gt 0) { return , $words }
        }
        try {
            $v = ConvertFrom-Json -InputObject $t
            if ($t.StartsWith('[')) { return , @($v) }
            return $v
        } catch {
            # A list whose quotes were lost on the way: Bootstrap run on WINDOWS passes the job's environment through
            # az.cmd, and its argument parsing drops the double quotes inside --env-vars, so ["LA","Excel"] arrives as
            # [LA,Excel] (live 2026-10-06, Community rehearsal from the support host: every profiler wrote to "0/0
            # sinks" -- nothing reached Log Analytics). A list of plain words is read back as that list.
            if ($t -match '^\[\s*[^\[\]{}",]+(\s*,\s*[^\[\]{}",]+)*\s*\]$') {
                return , @($t.Substring(1, $t.Length - 2).Split(',') | ForEach-Object { $_.Trim() })
            }
            if ($t -match '^\[\s*\]$') { return , @() }
            return $Text
        }
    }
    return $Text
}

function Get-SIConfigEnvArgs {
    <#
      PURE (Bootstrap side). For each requested global that the customer actually set, one
      'SI_CFG_<Name>=<value>' env arg. Secret-looking and container-owned names are REFUSED and reported.
      -Ignore: names skipped without a word -- settings that no longer exist (the settings catalog's "retired"
      list), so a value left for one in a configuration is neither passed nor reported.
      Returns @{ EnvArgs; Refused; Missing }.
    #>
    param(
        [AllowEmptyCollection()][string[]]$Names = @(),
        [Parameter(Mandatory)][hashtable]$Globals,
        [AllowEmptyCollection()][string[]]$Ignore = @()
    )
    $envArgs = New-Object System.Collections.Generic.List[string]
    $refused = New-Object System.Collections.Generic.List[string]
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($Names | Where-Object { $_ -and @($Ignore) -notcontains $_ } | Select-Object -Unique)) {
        if ((Test-SIConfigNameIsSecret -Name $n) -or ($script:SIConfigProtected -contains $n)) { $refused.Add($n); continue }
        if (-not $Globals.ContainsKey($n)) { $missing.Add($n); continue }
        $envArgs.Add(('{0}{1}={2}' -f $script:SIConfigEnvPrefix, $n, (ConvertTo-SIConfigEnvValue -Value $Globals[$n])))
    }
    [pscustomobject]@{ EnvArgs = $envArgs.ToArray(); Refused = $refused.ToArray(); Missing = $missing.ToArray() }
}

# Settings that no longer exist. A value left for one in a customer's configuration is ignored without a word. The
# same list is the settings catalog's "retired" list (a Pro file, so it is repeated here for both editions;
# SIv3-NoStorageKey.Tests.ps1 keeps the two equal).
$script:SIRetiredSettings = @('SI_PrestageInfra', 'SI_StorageKey', 'SI_UseStorageOAuth')
# #914: the older ServiceNow push's five settings are retired too
$script:SIRetiredSettings += @('SI_ServiceNow_DirectWrite', 'SI_ServiceNow_ImportSetMaxRows', 'SI_ServiceNow_ImportSetTable', 'SI_VulnSync_ServiceNowDirectWrite', 'SI_VulnSync_ServiceNowImportSetTable')

function Get-SIRetiredSettingNames {
    <# PURE. The settings that no longer exist (see $script:SIRetiredSettings). #>
    return @($script:SIRetiredSettings)
}

# Job secrets an older setup created that no current job uses. Bootstrap removes them from an existing job after its
# environment variables have been replaced (so nothing references them any more).
$script:SIRetiredJobSecrets = @('si-storage-key')

function Get-SIRetiredJobSecretNames {
    <# PURE. Of an existing Container App Job (az containerapp job show), the retired secrets it still carries. #>
    param([AllowNull()][object]$Job)
    if ($null -eq $Job -or -not $Job.PSObject.Properties['properties']) { return @() }
    $have = @($Job.properties.configuration.secrets | Where-Object { $_ } | ForEach-Object { [string]$_.name })
    return @($script:SIRetiredJobSecrets | Where-Object { $have -contains $_ })
}

function Get-SIUnwiredOptionalJobSecretNames {
    <#
        PURE. Of an existing job, the OPTIONAL secrets (Shodan, Azure OpenAI, SMTP) it carries that this run of setup did
        not wire (-SecretArgs, '<alias>=...'): the secret left the vault or the feature was switched off. The env vars were
        just replaced, so nothing references them -- and a Key Vault reference to a secret that is gone would make every
        later change to the job fail (2026-10-06).
    #>
    param([AllowNull()][object]$Job, [string[]]$SecretArgs = @())
    if ($null -eq $Job -or -not $Job.PSObject.Properties['properties']) { return @() }
    $have  = @($Job.properties.configuration.secrets | Where-Object { $_ } | ForEach-Object { [string]$_.name })
    $wired = @($SecretArgs | Where-Object { $_ } | ForEach-Object { ([string]$_ -split '=', 2)[0] })
    return @('shodan-key', 'openai-apikey', 'smtp-password' | Where-Object { $have -contains $_ -and $wired -notcontains $_ })
}

function Get-SIConfigFileSettingNames {
    <#
      PURE (Bootstrap side, #294). The settings a config file SETS: every `$global:<Name> = ...` assignment in it, read
      from the file's syntax tree -- nothing is run. Bootstrap passes these to every job as SI_CFG_<name>.
      Why not "the globals that appeared when the file was loaded": when the caller had loaded the config already (a
      deploy that imported the settings into the Pro database first, in the same session), every global existed before,
      so NONE appeared -- 0 settings went to every job, and on ring 1 (2026-10-04/05) the jobs ran without the customer's
      configuration: default rule names, no Pro settings database, and a Risk Analysis snapshot posted through a rule
      that dropped its key columns. A file that cannot be parsed returns nothing (the caller still has the other method).
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($null -eq $ast) { return @() }
    $assigns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($a in $assigns) {
        $left = $a.Left
        if ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) { $left = $left.Child }
        if ($left -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }
        $vp = $left.VariablePath
        if (-not $vp.IsGlobal) { continue }
        $name = $vp.UserPath.Substring($vp.UserPath.IndexOf(':') + 1)
        if ($name -match '^[A-Za-z_][A-Za-z0-9_]*$' -and $seen.Add($name)) { [void]$out.Add($name) }
    }
    return $out.ToArray()
}

function Import-SIConfigFromEnv {
    <#
      Container side. Sets $global:<Name> for every SI_CFG_<Name> env var, except secret-looking and
      container-owned names. -Environment is a name->value hashtable (the process environment by default,
      a test seam otherwise). Returns @{ Applied; Refused }.
    #>
    param([hashtable]$Environment)
    if (-not $Environment) {
        $Environment = @{}
        foreach ($e in [Environment]::GetEnvironmentVariables().GetEnumerator()) { $Environment[[string]$e.Key] = [string]$e.Value }
    }
    $applied = New-Object System.Collections.Generic.List[string]
    $refused = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($Environment.Keys | Sort-Object)) {
        if (-not ([string]$k).StartsWith($script:SIConfigEnvPrefix, [StringComparison]::OrdinalIgnoreCase)) { continue }
        $name = ([string]$k).Substring($script:SIConfigEnvPrefix.Length)
        if (-not $name -or $name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { $refused.Add($name); continue }
        if ((Test-SIConfigNameIsSecret -Name $name) -or ($script:SIConfigProtected -contains $name)) { $refused.Add($name); continue }
        Set-Variable -Name $name -Scope Global -Value (ConvertFrom-SIConfigEnvValue -Text ([string]$Environment[$k]))
        $applied.Add($name)
    }
    [pscustomobject]@{ Applied = $applied.ToArray(); Refused = $refused.ToArray() }
}

function Resolve-SIContainerAi {
    <#
      PURE (#184). Azure OpenAI is OPTIONAL: configured only when all four settings are present. AI is ON
      only when it is configured AND asked for (SI_ENABLE_AI, or $global:SI_EnableAI_<engine> passed through).
      Asked for but not configured -> OFF, with a reason the log states. Returns @{ Configured; Enabled; Reason }.
    #>
    param(
        [hashtable]$OpenAi = @{},
        [bool]$Requested = $false
    )
    $need = 'apiKey', 'endpoint', 'deployment', 'apiVersion'
    $have = @($need | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$OpenAi[$_]) })
    $configured = ($have.Count -eq $need.Count)
    if (-not $Requested) { return [pscustomobject]@{ Configured = $configured; Enabled = $false; Reason = 'AI classification is off (not requested)' } }
    if (-not $configured) {
        $missing = @($need | Where-Object { $have -notcontains $_ }) -join ', '
        return [pscustomobject]@{ Configured = $false; Enabled = $false; Reason = "AI classification was requested but Azure OpenAI is not configured (missing: $missing) -- running without it" }
    }
    [pscustomobject]@{ Configured = $true; Enabled = $true; Reason = 'AI classification is on' }
}

# ==================================================================================================================
#  CONTAINER PARITY WITH THE VM LAUNCHERS
# ==================================================================================================================
# A VM launcher layers: shipped defaults -> the customer's config -> launcher/<engine>/LauncherConfig.defaults.ps1 ->
# launcher/<engine>/LauncherConfig.custom.ps1 -> CLI switches. A container job gets the same layers this way:
#   * the engine's shipped LauncherConfig.defaults.ps1 is loaded by the entry point BEFORE the customer's settings;
#   * the customer's config AND the engine's LauncherConfig.custom.ps1 travel as SI_CFG_<name> (per job);
#   * a job env var the entry point owns wins only when it is PRESENT -- an absent one never overwrites a setting.

function Get-SIEngineSettingSuffix {
    <# PURE. The per-engine suffix of a setting name, as the VM launchers spell it: endpoint -> Endpoint, publicip ->
       PublicIp, risk-analysis-detailed -> RiskAnalysisDetailed, privilege-tier-classifier -> PrivilegeTierClassifier. #>
    param([Parameter(Mandatory)][string]$Engine)
    if ($Engine -ieq 'publicip') { return 'PublicIp' }
    $parts = @(($Engine -split '[-_]') | Where-Object { $_ } | ForEach-Object { $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1).ToLowerInvariant() })
    return ($parts -join '')
}

function Get-SIContainerEngineLauncherFolder {
    <# PURE. The launcher\<folder> whose LauncherConfig.defaults.ps1 / .custom.ps1 belong to a container engine; $null for an
       engine that has no launcher config of its own. Every Risk Analysis job (Summary, Detailed, extra) shares one. #>
    param([Parameter(Mandatory)][string]$Engine)
    $e = $Engine.ToLowerInvariant()
    if ($e -in 'endpoint', 'identity', 'azure', 'publicip', 'privilege-tier-classifier', 'asset-trend') { return $e }
    if ($e -in 'risk-analysis', 'risk-analysis-detailed' -or $e -like 'ra-*') { return 'risk-analysis' }
    return $null
}

function Get-SIContainerEngineDefaultsPath {
    <# The engine's shipped launcher\<folder>\LauncherConfig.defaults.ps1 under -Root, or $null (no such engine or file).
       The entry point dot-sources it BEFORE importing the customer's settings, so a customer value always wins. #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$Root)
    $folder = Get-SIContainerEngineLauncherFolder -Engine $Engine
    if (-not $folder) { return $null }
    $p = [IO.Path]::Combine($Root, 'launcher', $folder, 'LauncherConfig.defaults.ps1')
    if (Test-Path -LiteralPath $p) { return $p }
    return $null
}

$script:SIRunspaceNoise = @('?', '^', '$', '_', 'args', 'input', 'this', 'Error', 'LASTEXITCODE', 'Matches', 'MyInvocation', 'PSItem',
    'PWD', 'StackTrace', 'PSBoundParameters', 'PSCmdlet', 'PSCommandPath', 'PSScriptRoot', 'foreach', 'switch', 'ExecutionContext',
    'Host', 'PID', 'PSDebugContext', 'NestedPromptLevel', 'ConsoleFileName', 'ShellId')

function Read-SILauncherCustomSettings {
    <#
        Bootstrap side. The settings a launcher\<engine>\LauncherConfig.custom.ps1 sets, as name -> value -- read in its
        OWN runspace, so one engine's file never changes Bootstrap's globals or another job's settings. A file that fails
        part-way returns what it set before the failure, with the error. Returns @{ Settings; Errors }.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $settings = @{}
    $errors = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{ Settings = $settings; Errors = @() } }
    $ps = [powershell]::Create()
    try {
        $probe = {
            param($File, $Noise)
            # A fresh runspace holds only PowerShell's own variables, so every name the file adds is one of its settings.
            $before = @{}
            foreach ($v in (Get-Variable -Scope Global)) { $before[$v.Name] = $true }
            $failure = $null
            try { . $File } catch { $failure = $_.Exception.Message }
            $after = @{}
            foreach ($v in (Get-Variable -Scope Global)) {
                if ($before.ContainsKey($v.Name) -or $Noise -contains $v.Name -or $v.Name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { continue }
                $after[$v.Name] = $v.Value
            }
            [pscustomobject]@{ Settings = $after; Failure = $failure }
        }
        $null = $ps.AddScript($probe.ToString(), $true).AddArgument($Path).AddArgument($script:SIRunspaceNoise)
        $res = @($ps.Invoke())
        foreach ($e in @($ps.Streams.Error)) { $errors.Add([string]$e) }
        if ($res.Count) {
            if ($res[-1].Failure) { $errors.Add([string]$res[-1].Failure) }
            foreach ($k in @($res[-1].Settings.Keys)) { if ($k -notlike 'SI_Bootstrap_*') { $settings[$k] = $res[-1].Settings[$k] } }
        }
    } catch {
        $errors.Add($_.Exception.Message)
    } finally { $ps.Dispose() }
    [pscustomobject]@{ Settings = $settings; Errors = $errors.ToArray() }
}

function Merge-SIConfigEnvArgs {
    <# PURE. The job's SI_CFG_* list: -Base (the customer's config) with -Override (the engine's own launcher config) winning
       name by name -- one entry per name, so a job never carries the same variable twice. #>
    param([AllowEmptyCollection()][string[]]$Base = @(), [AllowEmptyCollection()][string[]]$Override = @())
    $over = @{}
    foreach ($a in @($Override | Where-Object { $_ })) { $over[($a -split '=', 2)[0]] = $true }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($a in @($Base | Where-Object { $_ })) { if (-not $over.ContainsKey(($a -split '=', 2)[0])) { $out.Add($a) } }
    foreach ($a in @($Override | Where-Object { $_ })) { $out.Add($a) }
    return , $out.ToArray()
}

function Test-SITruthy {
    <# PURE. $true, 1, 'true', '1', 'yes' (any case) -> $true; everything else -> $false. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    return ("$Value".Trim() -match '^(?i)(true|1|yes)$')
}

function Get-SIProcessEnvironment {
    $h = @{}
    foreach ($e in [Environment]::GetEnvironmentVariables().GetEnumerator()) { $h[[string]$e.Key] = [string]$e.Value }
    return $h
}

function Resolve-SIContainerRunOptions {
    <#
        PURE. What a profiler run collects and where it sends it -- the VM launcher's per-engine settings
        (SI_AssetLimit_<Engine>, SI_Sinks_<Engine>, SI_ForceFullRun_<Engine>, from the customer's config, the engine's
        launcher config or the Pro settings database) unless the job's own env var (SI_ASSET_LIMIT, SI_SINKS,
        SI_FORCE_FULL_RUN) is PRESENT. Neither -> the VM default (all assets, JSON + Excel + LA, incremental).
        Returns @{ AssetLimit; Sinks; ForceFullRun; Source } -- Source names where each came from.
    #>
    param([Parameter(Mandatory)][string]$Engine, [hashtable]$Globals = @{}, [hashtable]$Environment)
    if (-not $Environment) { $Environment = Get-SIProcessEnvironment }
    $sfx = Get-SIEngineSettingSuffix -Engine $Engine
    $ev = { param($n) if ($Environment.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace([string]$Environment[$n])) { ([string]$Environment[$n]).Trim() } else { $null } }
    $gv = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    $src = [ordered]@{}

    $limit = 0; $src.AssetLimit = 'default'
    $e = & $ev 'SI_ASSET_LIMIT'; $g = & $gv ('SI_AssetLimit_{0}' -f $sfx)
    if ($null -ne $e -and $e -match '^\d+$') { $limit = [int]$e; $src.AssetLimit = 'SI_ASSET_LIMIT' }
    elseif ($null -ne $g -and "$g".Trim() -match '^\d+$') { $limit = [int]"$g"; $src.AssetLimit = ('SI_AssetLimit_{0}' -f $sfx) }

    $sinks = @('JSON', 'Excel', 'LA'); $src.Sinks = 'default'
    $e = & $ev 'SI_SINKS'; $g = @(& $gv ('SI_Sinks_{0}' -f $sfx) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($null -ne $e) { $sinks = @($e.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }); $src.Sinks = 'SI_SINKS' }
    elseif ($g.Count) { $sinks = @($g | ForEach-Object { ([string]$_).Trim() }); $src.Sinks = ('SI_Sinks_{0}' -f $sfx) }

    # Same order as the VM launcher (#257): the job's env var, else the engine's own switch when it is ON, else the
    # tenant-wide SI_ForceFullRun, else an explicit engine OFF, else incremental. The tenant-wide switch used to be
    # ignored here, so a container job never did the full run the config asked for.
    $force = $false; $src.ForceFullRun = 'default'
    $e = & $ev 'SI_FORCE_FULL_RUN'; $g = & $gv ('SI_ForceFullRun_{0}' -f $sfx); $t = & $gv 'SI_ForceFullRun'
    if ($null -ne $e) { $force = Test-SITruthy $e; $src.ForceFullRun = 'SI_FORCE_FULL_RUN' }
    elseif ($null -ne $g -and (Test-SITruthy $g)) { $force = $true; $src.ForceFullRun = ('SI_ForceFullRun_{0}' -f $sfx) }
    elseif ($null -ne $t -and (Test-SITruthy $t)) { $force = $true; $src.ForceFullRun = 'SI_ForceFullRun' }
    elseif ($null -ne $g) { $force = $false; $src.ForceFullRun = ('SI_ForceFullRun_{0}' -f $sfx) }

    [pscustomobject]@{ AssetLimit = $limit; Sinks = $sinks; ForceFullRun = [bool]$force; Source = $src }
}

function Get-SIContainerRaEnvOverrides {
    <#
        PURE. The Risk Analysis settings a job's env vars set -- ONLY those whose env var is PRESENT. An absent env var
        returns nothing, so the customer's setting (or the VM launcher's default, loaded first) stands. Returns an ordered
        name -> value map of the globals to set.
    #>
    param([hashtable]$Environment)
    if (-not $Environment) { $Environment = Get-SIProcessEnvironment }
    $out = [ordered]@{}
    $map = [ordered]@{
        SI_RA_TABLE_SUMMARY = @('SI_RiskAnalysis_TableName_Summary', 'string'); SI_RA_TABLE_DETAILED = @('SI_RiskAnalysis_TableName_Detailed', 'string')
        SI_RA_SEND_TO_LOG_ANALYTICS = @('SendToLogAnalytics', 'bool'); SI_RA_SEND_MAIL = @('SendMail', 'bool')
        SI_RA_BUILD_SUMMARY_BY_AI = @('BuildSummaryByAI', 'bool'); SI_RA_AUTO_BUCKET = @('AutoBucketCount', 'bool')
        SI_RA_AUTO_BUCKET_MAX = @('AutoBucketMax', 'int'); SI_RA_AUTO_BUCKET_CACHE = @('AutoBucketCache', 'bool')
    }
    foreach ($k in $map.Keys) {
        if (-not $Environment.ContainsKey($k) -or [string]::IsNullOrWhiteSpace([string]$Environment[$k])) { continue }
        $v = ([string]$Environment[$k]).Trim()
        switch ($map[$k][1]) {
            'bool'   { $out[$map[$k][0]] = Test-SITruthy $v }
            'int'    { if ($v -match '^\d+$') { $out[$map[$k][0]] = [int]$v } }
            default  { $out[$map[$k][0]] = $v }
        }
    }
    return $out
}

# THE RETRY LIMIT (2026-10-23): every ENGINE job -- a job the pipeline starts -- has replicaRetryLimit 0. Live: Azure
# re-ran a failed data sync container inside the same execution (852 min = 504 + 347) and the vulnerability step twice
# (2 x 18 min); the pipeline runner decides what runs again (it also restarts a container that never started). At a new
# install (Bootstrap, the missing-jobs step, the queue worker / producer definitions) and on every update for an existing
# job (setup/_shared/SI-JobSizing.ps1 Invoke-SIEngineJobRetryLimit). The runner (caj-si-flow), the updater, the template
# publish, schema discovery, the configuration backup and the heartbeat are not engine jobs and keep what they have.
function Get-SIPipelineStepKeys {
    <#
        The jobs that are steps of the pipeline, from the shipped map (config\job-flow.locked.json): every job with a stage
        that is not marked neverInFlow / ownSchedule / retired, as its key (the job name without caj-si-). -Path: test seam.
        @() when the map cannot be read.
    #>
    param([string]$Path)
    if (-not $Path) { $Path = [IO.Path]::Combine($PSScriptRoot, '..', '..', 'config', 'job-flow.locked.json') }
    try {
        $raw = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
        $flag = { param($j, $n) [bool]($j.PSObject.Properties[$n] -and $j.$n) }
        return @(@($raw.jobs) | Where-Object { $_ -and (& $flag $_ 'stage') -and -not (& $flag $_ 'neverInFlow') -and -not (& $flag $_ 'ownSchedule') -and -not (& $flag $_ 'retired') } |
                 ForEach-Object { ([string]$_.key).ToLowerInvariant() })
    } catch { return @() }
}

function Test-SIEngineJobName {
    <#
        An ENGINE job: one the pipeline starts. caj-si-<step> for every step of the pipeline (-StepKeys, default
        Get-SIPipelineStepKeys), its -producer / -worker, every Risk Analysis job (caj-si-risk-analysis,
        caj-si-risk-analysis-detailed, caj-si-ra-<name>) and the Risk Analysis queue workers (caj-si-raworker-<grain>).
        Not the runner (caj-si-flow), the updater or any job that is no step.
    #>
    param([AllowEmptyString()][string]$Name, [string[]]$StepKeys)
    $n = "$Name".Trim().ToLowerInvariant()
    if (-not $n.StartsWith('caj-si-')) { return $false }
    $s = $n.Substring(7)
    if ($s -match '^(risk-analysis|risk-analysis-detailed|ra-[a-z0-9-]+|raworker-[a-z0-9-]+)$') { return $true }
    if ($s -match '^(.+)-(producer|worker)$') { $s = $Matches[1] }
    if ($s -in @('flow', 'updater')) { return $false }
    if ($null -eq $StepKeys) { $StepKeys = @(Get-SIPipelineStepKeys) }
    [bool](@($StepKeys) -contains $s)
}

function Get-SIJobRetryLimitArg {
    <# PURE. The --replica-retry-limit a NEW job is created with: '0' for an engine job (Test-SIEngineJobName), else '1'. #>
    param([AllowEmptyString()][string]$Name, [string[]]$StepKeys)
    if (Test-SIEngineJobName -Name $Name -StepKeys $StepKeys) { '0' } else { '1' }
}

# The container job sizes setup gives each kind of job unless the customer sets SI_Bootstrap_ReplicaTimeout_<Engine> /
# _Cpu_<Engine> / _Memory_<Engine> (seconds / cores / '<n>Gi'). These were the only values before they became settings.
# THE FLOOR (owner 2026-10-10: "money must not be the case", "time is critical" -> "Floor 2/4, tenant rule to 4/8"): every
# SI job runs with at least 2 CPU / 4 GiB; the tenant-size rule (Get-SITenantSizedJobResources) and the update's failure
# learning raise it to 4 CPU / 8 GiB. A job is paid only while it runs.
# THE RUN LIMIT (owner 2026-10-13: "we are not to judge that and it breaks the whole solution", "why have a limit, if the
# environment has 100000000000 objects"): SecurityInsight chooses NO run limit for a step. Azure makes every job carry
# one, so every engine job gets THE LONGEST ONE AZURE TAKES (Get-SIJobRunLimit) -- at a new install, and every update
# raises an existing job to it (setup/_shared/SI-JobSizing.ps1, Invoke-SIJobFloor). One value, at any tenant size.
function Get-SIJobRunLimit {
    <#
        PURE. The run limit of every engine job, in seconds: 604800 (7 days) -- the longest run limit Azure is PROVEN to
        take for a Container Apps job (the pipeline job has run with it on live installs since 2026-10-12). Microsoft
        documents no maximum for properties.configuration.replicaTimeout ("Maximum number of seconds a replica is allowed
        to run", an int, no upper bound stated), so no larger value is established; 7 days is also the longest lease a
        storage queue gives a collection worker's part. When a larger value is established, change it HERE only.
        Not the updater (its own limit). A limit the customer set (SI_Bootstrap_ReplicaTimeout_<Engine>) wins -- it can
        only be shorter or the same.
    #>
    604800
}
$script:SIJobResourceDefaults = @{
    Keda         = @{ ReplicaTimeout = (Get-SIJobRunLimit); Cpu = '2.0'; Memory = '4.0Gi' }
    RiskAnalysis = @{ ReplicaTimeout = (Get-SIJobRunLimit); Cpu = '2.0'; Memory = '4.0Gi' }
    Manual       = @{ ReplicaTimeout = (Get-SIJobRunLimit); Cpu = '2.0'; Memory = '4.0Gi' }
    Schedule     = @{ ReplicaTimeout = (Get-SIJobRunLimit); Cpu = '2.0'; Memory = '4.0Gi' }
}

# THE TENANT'S SIZE AS SETUP READ IT, KEPT ON EVERY JOB (2026-10-16, the large installs: the updater's identity has no
# directory read, the identity collection had written 0 users, so the update's size rule read 0 users and kept the job
# at 2 CPU / 4 GiB). Setup reads the counts from Microsoft Graph once (Get-SITenantDirectoryCounts) and tags every job it
# creates or updates with them; every update reads them back from the job list it already has. Plain digits only.
$script:SITenantSizeTagNames = [ordered]@{ Users = 'si-tenant-users'; Groups = 'si-tenant-groups'; ServicePrincipals = 'si-tenant-serviceprincipals'; Devices = 'si-tenant-devices' }

function Get-SITenantSizeTags {
    <# PURE. The counts (-Counts: Users / Groups / ServicePrincipals / Devices) as job tags 'si-tenant-users=22705' ...; @() when none were read. #>
    param([hashtable]$Counts)
    if (-not $Counts) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($script:SITenantSizeTagNames.Keys)) {
        $n = 0L
        if ($Counts.ContainsKey($k) -and [long]::TryParse("$($Counts[$k])", [ref]$n) -and $n -ge 0) { $out.Add(('{0}={1}' -f $script:SITenantSizeTagNames[$k], $n)) }
    }
    if (-not @($out | Where-Object { $_ -notmatch '=0$' }).Count) { return @() }
    $out.ToArray()
}

function ConvertFrom-SITenantSizeTags {
    <#
        PURE. The counts setup read, from the tags of the jobs (ARM shape: tags.si-tenant-*). The largest value of any job
        (setup tags every job it touches; an older job may carry an older count). @{ Users; Groups; ServicePrincipals;
        Devices } or $null when no job carries them.
    #>
    param([object[]]$Jobs = @())
    $c = @{ Users = 0L; Groups = 0L; ServicePrincipals = 0L; Devices = 0L }; $any = $false
    foreach ($j in @($Jobs)) {
        if (-not $j -or -not $j.PSObject.Properties['tags'] -or -not $j.tags) { continue }
        $t = $j.tags
        foreach ($k in @($script:SITenantSizeTagNames.Keys)) {
            $name = $script:SITenantSizeTagNames[$k]
            $v = $null
            if ($t -is [System.Collections.IDictionary]) { if ($t.Contains($name)) { $v = $t[$name] } }
            elseif ($t.PSObject.Properties[$name]) { $v = $t.$name }
            $n = 0L
            if ($null -ne $v -and "$v".Trim() -match '^\d+$' -and [long]::TryParse("$v".Trim(), [ref]$n)) { if ($n -gt $c[$k]) { $c[$k] = $n }; $any = $true }
        }
    }
    if ($any) { $c } else { $null }
}

function Get-SITenantSizedJobResources {
    <#
        PURE. A collection job's size for THIS tenant (customer H 2026-10-08: 22,705 users + 5,097 groups ran the identity
        job out of memory at the 2 GiB default). -Counts: Users, Groups, ServicePrincipals, Devices (Microsoft Graph $count;
        a missing count is 0). Container Apps takes only these CPU/memory pairs, so a size is one of them:
          < 5,000 objects   -> $null (the job kind's default stands)
          >= 5,000          -> 4.0 CPU / 8.0Gi (the largest a consumption job has)
        The run limit does not depend on the tenant's size: every engine job gets the longest run limit Azure takes
        (Get-SIJobRunLimit; the ReplicaTimeout returned here is that value).
        Objects: identity = users + groups + service principals; endpoint = devices; asset-correlation (the CI
        build) and the Risk Analysis jobs (risk-analysis*, ra-<name>; #509) = all of them; other engines are not sized
        here. The same rule runs at install (Bootstrap) and on every update (setup/_shared/SI-JobSizing.ps1, #509).
    #>
    param([Parameter(Mandatory)][string]$Engine, [hashtable]$Counts = @{})
    $g = { param($k) if ($Counts -and $Counts.ContainsKey($k) -and $null -ne $Counts[$k]) { [long]$Counts[$k] } else { 0L } }
    $n = switch ($Engine.Trim().ToLowerInvariant()) {
        'identity' { (& $g 'Users') + (& $g 'Groups') + (& $g 'ServicePrincipals') }
        'endpoint' { (& $g 'Devices') }
        # the CI build (PowerShell 7 enriches the CIs in parallel on the job's CPUs): every object of every kind
        'asset-correlation' { (& $g 'Users') + (& $g 'Groups') + (& $g 'ServicePrincipals') + (& $g 'Devices') }
        # the Azure collection: no count of Azure resources is known at install, so it is sized as the tenant is (a new
        # customer install 2026-10-12 ran its Azure worker out of memory at 4 GiB in the Enrich step)
        'azure' { (& $g 'Users') + (& $g 'Groups') + (& $g 'ServicePrincipals') + (& $g 'Devices') }
        # #509: the Risk Analysis jobs (Summary, Detailed and every extra report job ra-<name>) read every object too
        { $_ -like 'risk-analysis*' -or $_ -like 'ra-*' } { (& $g 'Users') + (& $g 'Groups') + (& $g 'ServicePrincipals') + (& $g 'Devices') }
        # the jobs that load the whole Risk Analysis result are sized as Risk Analysis is (customer H 2026-10-10: data sync OOM)
        { $_ -in @('asset-datasync', 'asset-vulnerabilities') } { (& $g 'Users') + (& $g 'Groups') + (& $g 'ServicePrincipals') + (& $g 'Devices') }
        default { -1L }
    }
    $n = @($n)[0]
    if ($n -lt 5000) { return $null }
    # 5,000 to 15,000 objects: 4 CPU / 8 GiB too since 2026-10-12 (it was 2 CPU / 4 GiB). A new customer install of about
    # 10,100 identity objects peaked at 3.2 GiB of 4 in its identity worker and ran its Azure worker out of memory on the
    # first collection. Owner: reliability over cost; "we can always lower it later".
    return [pscustomobject]@{ Cpu = '4.0'; Memory = '8.0Gi'; ReplicaTimeout = [int](Get-SIJobRunLimit); Objects = $n }
}

function Get-SIFlowJobReplicaTimeout {
    <#
        PURE. The run limit of the pipeline job itself (caj-si-flow), in seconds: 7 days. The pipeline runner starts each
        step and WAITS for it inside its own execution, so it must never end before a step does -- 7 days is the longest a
        customer may set a job's run limit to (SI_Bootstrap_ReplicaTimeout_<Engine>). A runner that does end early loses
        nothing: the next wake-up resumes the run and follows the running step. Bootstrap gives a new install this value
        and every update raises an existing install's pipeline job to it (setup/_shared/SI-JobSizing.ps1).
    #>
    604800
}

# A RUN LIMIT ABOVE 24 HOURS MAY BE REFUSED BY AZURE. 86400 s is the longest run limit Azure is KNOWN to take for a
# Container Apps job. Every place that sends a longer one (setup's job create / update, the update's job sizing, the
# pipeline job) tries it, and when Azure refuses the request it sends the SAME request once more with 24 hours -- the
# CPU / memory change in it is never lost and neither an install nor an update fails for it. The refusal is remembered for
# the rest of the run, so the other jobs are sent 24 hours at once.
function Get-SIAzureKnownRunLimit { 86400 }

function Test-SIRunLimitRefused {
    <# Did Azure refuse a run limit above 24 hours earlier in this run? (Read tolerant: this file is dot-sourced more than once.) #>
    [bool](Get-Variable -Name SIRunLimitRefused -Scope Script -ValueOnly -ErrorAction Ignore)
}

function Set-SIRunLimitRefused {
    <# Remember (or, in a test, forget) that Azure refused a run limit above 24 hours in this run. #>
    param([bool]$Value = $true)
    $script:SIRunLimitRefused = $Value
}

function Get-SIRunLimitToSend {
    <# PURE over the run's memory. The run limit to ask Azure for: -ReplicaTimeout, or 24 hours once a longer one was refused. #>
    param([int]$ReplicaTimeout)
    if ($ReplicaTimeout -gt (Get-SIAzureKnownRunLimit) -and (Test-SIRunLimitRefused)) { return [int](Get-SIAzureKnownRunLimit) }
    $ReplicaTimeout
}

function Test-SIRunLimitRefusal {
    <#
        PURE. Is this answer a refusal that the run limit may have caused? Only for a request that asked for MORE than 24
        hours: Azure's error names the replica timeout, or it is a 400 (-Status, or the words of one in -Text when only an
        error message is at hand). The caller then sends the same request with 24 hours; only when THAT is accepted was the
        run limit the cause.
    #>
    param([int]$ReplicaTimeout, [int]$Status = 0, [AllowEmptyString()][string]$Text = '')
    if ($ReplicaTimeout -le (Get-SIAzureKnownRunLimit)) { return $false }
    if ($Status -ge 500) { return $false }
    if ("$Text" -match '(?i)replica\s*-?\s*timeout') { return $true }
    if ($Status -eq 400) { return $true }
    [bool]($Status -eq 0 -and "$Text" -match '(?i)HTTP Status: 400|returned 400|Bad\s?Request|InvalidRequest|InvalidParameter|ValidationError|InvalidTemplate')
}

function Get-SIRunLimitRefusedLine {
    <# PURE. The one plain line for a run limit Azure did not take. #>
    param([Parameter(Mandatory)][string]$Job, [int]$ReplicaTimeout)
    'Azure did not accept a run limit of {0} hours for {1}; it keeps 24 hours.' -f ([double]$ReplicaTimeout / 3600).ToString('0.#', [Globalization.CultureInfo]::InvariantCulture), $Job
}

function Get-SIHeartbeatJobRunLimit {
    <# PURE. #718: the run limit of the hourly status report job (caj-si-heartbeat), in seconds -- 30 minutes. #>
    1800
}

function Get-SIContainerJobResources {
    <#
        PURE. A job's replica timeout, CPU and memory: SI_Bootstrap_ReplicaTimeout_<Engine>, SI_Bootstrap_Cpu_<Engine> and
        SI_Bootstrap_Memory_<Engine> when set and valid, else the defaults for the kind of job. An invalid value is ignored
        with a note (the default stands) -- a typo never fails setup half-way. Returns @{ ReplicaTimeout; Cpu; Memory; Notes }.
    #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][ValidateSet('Keda', 'RiskAnalysis', 'Manual', 'Schedule')][string]$Kind,
          [hashtable]$Globals = @{},
          # the tenant's directory counts (Get-SITenantSizedJobResources) -- a size the customer set still wins
          [hashtable]$TenantCounts)
    $d = $script:SIJobResourceDefaults[$Kind]
    $sfx = Get-SIEngineSettingSuffix -Engine $Engine
    $gv = { param($n) if ($Globals.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace([string]$Globals[$n])) { "$($Globals[$n])".Trim() } else { $null } }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $notes = New-Object System.Collections.Generic.List[string]
    $timeout = [int]$d.ReplicaTimeout; $cpu = [string]$d.Cpu; $mem = [string]$d.Memory
    # #718: the hourly status report is the one job with a SHORT run limit of its own (30 minutes): a tick that hangs must
    # never keep the next hour's tick from starting (the execution guard skips a tick while the previous one runs). Its size
    # is the floor every job gets (2 CPU / 4 GiB -- the update raises any job below it).
    if ($Engine -eq 'heartbeat') { $timeout = Get-SIHeartbeatJobRunLimit }
    if ($TenantCounts) {
        $sized = Get-SITenantSizedJobResources -Engine $Engine -Counts $TenantCounts
        if ($sized -and [double]($sized.Memory -replace 'Gi$', '') -gt [double]($mem -replace 'Gi$', '')) {
            $cpu = $sized.Cpu; $mem = $sized.Memory
            $notes.Add(('sized for this tenant: {0:N0} objects -> {1} CPU / {2}' -f $sized.Objects, $cpu, $mem))
        }
    }

    $n = 'SI_Bootstrap_ReplicaTimeout_{0}' -f $sfx; $v = & $gv $n
    if ($null -ne $v) {
        # the customer's own run limit wins: it can only be shorter than (or the same as) the 7 days every job gets
        if ($v -match '^\d{1,9}$' -and [int64]$v -ge 300 -and [int64]$v -le 604800) { $timeout = [int]$v }
        else { $notes.Add(("{0} = '{1}' is not a number of seconds between 300 and 604800 (7 days) -- using {2}" -f $n, $v, $timeout)) }
    }
    $n = 'SI_Bootstrap_Cpu_{0}' -f $sfx; $v = & $gv $n
    if ($null -ne $v) {
        $c = 0.0
        if ([double]::TryParse($v, [Globalization.NumberStyles]::Float, $inv, [ref]$c) -and $c -ge 0.25 -and $c -le 4 -and (($c * 4) % 1) -eq 0) { $cpu = $c.ToString('0.0#', $inv) }
        else { $notes.Add(("{0} = '{1}' is not a CPU size (0.25 to 4, in steps of 0.25) -- using {2}" -f $n, $v, $cpu)) }
    }
    $n = 'SI_Bootstrap_Memory_{0}' -f $sfx; $v = & $gv $n
    if ($null -ne $v) {
        $m = 0.0; $num = ($v -replace '(?i)\s*gi$', '')
        if ([double]::TryParse($num, [Globalization.NumberStyles]::Float, $inv, [ref]$m) -and $m -ge 0.5 -and $m -le 8 -and (($m * 2) % 1) -eq 0) { $mem = ('{0}Gi' -f $m.ToString('0.0#', $inv)) }
        else { $notes.Add(("{0} = '{1}' is not a memory size (0.5Gi to 8Gi, in steps of 0.5Gi) -- using {2}" -f $n, $v, $mem)) }
    }
    [pscustomobject]@{ ReplicaTimeout = $timeout; Cpu = $cpu; Memory = $mem; Notes = $notes.ToArray() }
}

function Get-SIJobResourcesNeverLower {
    <#
        PURE. Re-running setup on an EXISTING job never LOWERS it: its run limit may be longer than setup would write, its
        CPU / memory raised after an out-of-memory run. -Resources: what
        setup would write (Get-SIContainerJobResources); -ExistingJob: the job as Azure has it (ARM shape; $null = a new
        job, nothing changes). The LARGER of the two is written -- the run limit on its own, CPU and memory as a pair.
        A value the customer set (SI_Bootstrap_ReplicaTimeout_ / _Cpu_ / _Memory_<Engine> in -Globals) still wins, also
        downwards: that is their choice. Returns the same shape, with a note per value kept.
    #>
    param([Parameter(Mandatory)]$Resources, $ExistingJob, [Parameter(Mandatory)][string]$Engine, [hashtable]$Globals = @{})
    if (-not $ExistingJob) { return $Resources }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $sfx = Get-SIEngineSettingSuffix -Engine $Engine
    $set = { param($n) [bool]($Globals -and $Globals.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace([string]$Globals[$n])) }
    $notes = New-Object System.Collections.Generic.List[string]; foreach ($n in @($Resources.Notes)) { if ($n) { $notes.Add([string]$n) } }
    $timeout = [int]$Resources.ReplicaTimeout; $cpu = [string]$Resources.Cpu; $mem = [string]$Resources.Memory
    $haveTo = 0; $haveCpu = 0.0; $haveMem = 0.0; $haveMemText = ''
    try { [void][int]::TryParse("$($ExistingJob.properties.configuration.replicaTimeout)", [ref]$haveTo) } catch { $haveTo = 0 }
    try {
        $c = @($ExistingJob.properties.template.containers | Where-Object { $_ })[0]
        [void][double]::TryParse("$($c.resources.cpu)", [Globalization.NumberStyles]::Float, $inv, [ref]$haveCpu)
        $haveMemText = [string]$c.resources.memory
        [void][double]::TryParse(($haveMemText -replace '(?i)\s*gi$', ''), [Globalization.NumberStyles]::Float, $inv, [ref]$haveMem)
    } catch { $haveCpu = 0.0; $haveMem = 0.0 }
    if ($haveTo -gt $timeout -and -not (& $set ('SI_Bootstrap_ReplicaTimeout_{0}' -f $sfx))) {
        $notes.Add(('the job already runs for up to {0:N1} hours -- kept (setup never lowers a run limit; it would have set {1:N1})' -f ($haveTo / 3600), ($timeout / 3600)))
        $timeout = $haveTo
    }
    $wantMem = 0.0; [void][double]::TryParse(($mem -replace '(?i)\s*gi$', ''), [Globalization.NumberStyles]::Float, $inv, [ref]$wantMem)
    if ($haveMem -gt $wantMem -and $haveCpu -gt 0 -and -not (& $set ('SI_Bootstrap_Cpu_{0}' -f $sfx)) -and -not (& $set ('SI_Bootstrap_Memory_{0}' -f $sfx))) {
        $notes.Add(('the job already has {0} CPU / {1} -- kept (setup never lowers a job''s size; it would have set {2} CPU / {3})' -f $haveCpu.ToString('0.0#', $inv), $haveMemText, $cpu, $mem))
        $cpu = $haveCpu.ToString('0.0#', $inv); $mem = $haveMemText
    }
    [pscustomobject]@{ ReplicaTimeout = $timeout; Cpu = $cpu; Memory = $mem; Notes = $notes.ToArray() }
}

function Get-SIRaTemplateMode {
    <# PURE. The run mode a template's name states ('Detailed' / 'Summary'), or $null -- the same rule the RA entry point uses. #>
    param([AllowNull()][AllowEmptyString()][string]$Template)
    if ([string]::IsNullOrWhiteSpace($Template)) { return $null }
    if ($Template -match '(?i)detailed') { return 'Detailed' }
    if ($Template -match '(?i)summary') { return 'Summary' }
    return $null
}

function Get-SIRiskAnalysisJobPlan {
    <#
        PURE. Every Risk Analysis job setup deploys, with its mode, report template and schedule:
          risk-analysis           -- the Summary job: -SummaryTemplate when given explicitly, else the customer's
                                     RiskAnalysis_ReportTemplate_Default_Summary (or ReportTemplate_Default_Summary), else
                                     RiskAnalysis_Summary -- what the VM launcher runs when no template is named;
          risk-analysis-detailed  -- the Detailed job: RiskAnalysis_ReportTemplate_Default_Detailed (or
                                     ReportTemplate_Default_Detailed), else RiskAnalysis_Detailed;
          extra jobs              -- SI_Bootstrap_RiskAnalysisJobs: a list of @{ Name; Mode; Template; Cron } (Mode may be
                                     left out when the template's name states it). Job name caj-si-ra-<Name>.
        An extra job that is not valid is refused with the reason, never deployed half-right.
        Returns @{ Jobs = @(@{ Engine; JobShort; Mode; Template; Cron }); Refused = @(string) }.
    #>
    param([string[]]$Engines = @(), [hashtable]$Globals = @{}, [string]$SummaryTemplate, [string]$SummaryMode = 'Summary',
          [string]$ScheduleSummary = '0 6 * * *', [string]$ScheduleDetailed = '0 8 * * *')
    $gv = { param($n) if ($Globals.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace([string]$Globals[$n])) { ([string]$Globals[$n]).Trim() } else { $null } }
    $jobs = New-Object System.Collections.Generic.List[object]
    $refused = New-Object System.Collections.Generic.List[string]
    if (@($Engines) -contains 'risk-analysis') {
        $t = if (-not [string]::IsNullOrWhiteSpace($SummaryTemplate)) { $SummaryTemplate.Trim() }
             elseif (& $gv 'RiskAnalysis_ReportTemplate_Default_Summary') { & $gv 'RiskAnalysis_ReportTemplate_Default_Summary' }
             elseif (& $gv 'ReportTemplate_Default_Summary') { & $gv 'ReportTemplate_Default_Summary' }
             else { 'RiskAnalysis_Summary' }
        $m = Get-SIRaTemplateMode -Template $t; if (-not $m) { $m = if ($SummaryMode -ieq 'Detailed') { 'Detailed' } else { 'Summary' } }
        $jobs.Add([pscustomobject]@{ Engine = 'risk-analysis'; JobShort = 'risk-analysis'; Mode = $m; Template = $t; Cron = $ScheduleSummary })
    }
    if (@($Engines) -contains 'risk-analysis-detailed') {
        $t = if (& $gv 'RiskAnalysis_ReportTemplate_Default_Detailed') { & $gv 'RiskAnalysis_ReportTemplate_Default_Detailed' }
             elseif (& $gv 'ReportTemplate_Default_Detailed') { & $gv 'ReportTemplate_Default_Detailed' }
             else { 'RiskAnalysis_Detailed' }
        $jobs.Add([pscustomobject]@{ Engine = 'risk-analysis-detailed'; JobShort = 'risk-analysis-detailed'; Mode = 'Detailed'; Template = $t; Cron = $ScheduleDetailed })
    }
    $extra = if ($Globals.ContainsKey('SI_Bootstrap_RiskAnalysisJobs')) { @($Globals['SI_Bootstrap_RiskAnalysisJobs'] | Where-Object { $null -ne $_ }) } else { @() }
    $seen = @{}
    foreach ($j in $extra) {
        $get = { param($n) if ($j -is [System.Collections.IDictionary]) { if ($j.Contains($n)) { $j[$n] } else { $null } } else { $p = $j.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } } }
        $name = "$(& $get 'Name')".Trim().ToLowerInvariant()
        $tpl  = "$(& $get 'Template')".Trim()
        $mode = "$(& $get 'Mode')".Trim()
        $cron = "$(& $get 'Cron')".Trim(); if (-not $cron) { $cron = "$(& $get 'Schedule')".Trim() }
        if ($name -notmatch '^[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?$') { $refused.Add(("extra Risk Analysis job '{0}': the name must be 1 to 22 lower-case letters, digits or '-' (the job is caj-si-ra-<name>)" -f $name)); continue }
        if ($seen.ContainsKey($name)) { $refused.Add(("extra Risk Analysis job '{0}': the name is used twice" -f $name)); continue }
        if ($cron -notmatch '^\S+(\s+\S+){4}$') { $refused.Add(("extra Risk Analysis job '{0}': Cron '{1}' is not a five-field cron expression (UTC)" -f $name, $cron)); continue }
        $tplMode = Get-SIRaTemplateMode -Template $tpl
        $modeNorm = if (-not $mode) { $null } elseif ($mode -ieq 'Summary') { 'Summary' } elseif ($mode -ieq 'Detailed') { 'Detailed' } else { 'bad' }
        if ($modeNorm -eq 'bad') { $refused.Add(("extra Risk Analysis job '{0}': Mode '{1}' is not Summary or Detailed" -f $name, $mode)); continue }
        if ($tplMode -and $modeNorm -and $tplMode -ne $modeNorm) { $refused.Add(("extra Risk Analysis job '{0}': template '{1}' is a {2} template but Mode is {3}" -f $name, $tpl, $tplMode, $modeNorm)); continue }
        $final = if ($tplMode) { $tplMode } elseif ($modeNorm) { $modeNorm } else { $null }
        if (-not $final) { $refused.Add(("extra Risk Analysis job '{0}': set Mode (Summary or Detailed) -- template '{1}' does not say which" -f $name, $tpl)); continue }
        if (-not $tpl) { $tpl = 'RiskAnalysis_{0}' -f $final }
        $seen[$name] = $true
        $jobs.Add([pscustomobject]@{ Engine = ('ra-{0}' -f $name); JobShort = ('ra-{0}' -f $name); Mode = $final; Template = $tpl; Cron = $cron })
    }
    [pscustomobject]@{ Jobs = $jobs.ToArray(); Refused = $refused.ToArray() }
}

function Get-SIRaJobEnvArgs {
    <#
        PURE. A Risk Analysis job's own env vars. SI_RA_SEND_TO_LOG_ANALYTICS / SI_RA_BUILD_SUMMARY_BY_AI are written ONLY
        when setup was told (-RiskAnalysisSendToLogAnalytics / -RiskAnalysisBuildSummaryByAI, or SI_RiskAnalysis_* in the
        config): $null = not decided here, so the customer's own setting -- or the VM default (send to Log Analytics: ON)
        -- decides in the container.
    #>
    param([Parameter(Mandatory)][string]$Template, [Parameter(Mandatory)][string]$Mode,
          [AllowNull()][object]$SendToLogAnalytics = $null, [AllowNull()][object]$BuildSummaryByAI = $null, [string]$ExportDestination)
    $a = New-Object System.Collections.Generic.List[string]
    $a.Add("SI_RA_REPORT_TEMPLATE=$Template"); $a.Add("SI_RA_MODE=$Mode")
    if ($null -ne $SendToLogAnalytics) { $a.Add(('SI_RA_SEND_TO_LOG_ANALYTICS={0}' -f [int][bool]$SendToLogAnalytics)) }
    if ($null -ne $BuildSummaryByAI)   { $a.Add(('SI_RA_BUILD_SUMMARY_BY_AI={0}' -f [int][bool]$BuildSummaryByAI)) }
    if (-not [string]::IsNullOrWhiteSpace($ExportDestination)) { $a.Add("SI_RA_EXPORT_DESTINATION=$ExportDestination") }
    # #873 E: a 256 MB .NET gen0 budget (hex) -- fewer GC pauses while a slice's rows are scored; a runtime setting, no row
    # changes (setup\_shared\SI-RaGcSetting.ps1 gives existing installs the same on every update; its queue worker copies it)
    $a.Add('DOTNET_GCgen0size=10000000')
    # Unrolled, never ', $array': Bootstrap appends with $envArgs += @(Get-SIRaJobEnvArgs ...), and a wrapped array became
    # ONE element that az received as one argument joined by spaces -- the job's template read
    # 'RiskAnalysis_Detailed SI_RA_MODE=Detailed SI_RA_EXPORT_DESTINATION=...' and both RA jobs failed (live 2026-10-04).
    return $a.ToArray()
}

function Select-SIBootstrapEngines {
    <#
        PURE. The engines setup deploys. The privilege-tier classifier is left out when Azure OpenAI is not configured:
        without it every role it classifies becomes Tier 99 (manual review), and that catalog would replace the shipped
        one the profilers use. Returns @{ Engines; Note } -- Note is the one line setup prints, empty when nothing changed.
    #>
    param([string[]]$Engines = @(), [bool]$HaveOpenAi)
    $list = @($Engines)
    if (-not $HaveOpenAi -and $list -contains 'privilege-tier-classifier') {
        return [pscustomobject]@{ Engines = @($list | Where-Object { $_ -ne 'privilege-tier-classifier' })
            Note = 'The privilege-tier classifier job is not deployed: Azure OpenAI is not configured, and without it every role would be classified Tier 99 (manual review). The shipped tier catalog is used; configure Azure OpenAI and run setup again to add the job.' }
    }
    [pscustomobject]@{ Engines = $list; Note = '' }
}

function Test-SIAssetTaggingApply {
    <#
      PURE (#236). Does the setting switch asset tagging's WRITES on? Only a real true ($true, 'true', '1', 'yes',
      'apply', any letter case). Everything else -- not set, empty, $false, 'false', 'report', a typo -- is report only:
      a value nobody can read never writes to a customer's tenant.
    #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    return ("$Value".Trim() -match '^(?i)(true|1|yes|apply)$')
}

function Get-SIVulnConnectorGroup {
    <#
        PURE (#269). Which connectors THIS vulnerability job drives, from its environment (SI_VULN_TARGET, set by
        Bootstrap): 'Sql' (caj-si-asset-vulnerabilities -- the SQL connector, and REST connectors), 'ServiceNow'
        (caj-si-asset-vulns-servicenow), or '' (no variable: every connector, as before the split). Any other value is ''.
    #>
    param([hashtable]$Environment)
    $v = if ($Environment) { [string]$Environment['SI_VULN_TARGET'] } else { [string][Environment]::GetEnvironmentVariable('SI_VULN_TARGET') }
    switch -Regex ($v.Trim()) { '^(?i)sql$' { 'Sql' } '^(?i)servicenow$' { 'ServiceNow' } default { '' } }
}

function Get-SIContainerEngineDispatch {
    <#
      PURE (#170). For an engine the container dispatches directly -- asset-trend (free) and the Pro engines
      asset-correlation / asset-properties / asset-cmdb / asset-vulnerabilities / asset-datasync / close-loop-mail /
      asset-tagging -- the script and the parameters, resolved from the
      settings EXACTLY as each engine's VM launcher resolves them (same names, same defaults, same safe
      fallbacks). Returns $null for engines that go through the profiling orchestrator. Returns
      @{ Script; Args; Skip } -- Skip set when the engine is deliberately off (it then does nothing).
      A Pro engine without a licence refuses with one line itself (Assert-SIFeatureOrSkip), as on a VM.
      -Globals is a name -> value hashtable (the caller passes the live globals).
    #>
    param([Parameter(Mandatory)][string]$Engine, [hashtable]$Globals = @{}, [hashtable]$Environment)
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    $int = { param($n) $v = & $g $n; if ($null -ne $v -and "$v" -match '^\d+$') { [int]"$v" } else { 0 } }
    $a = @{}
    switch ($Engine.ToLowerInvariant()) {
        'asset-trend' {
            $grain = "$(& $g 'SI_Trend_Grain')".Trim()
            $a['Grain'] = if ($grain -in 'Summary', 'Detailed') { $grain } else { 'Summary' }
            if ([bool](& $g 'SI_Trend_DryRun')) { $a['DryRun'] = $true }
            return [pscustomobject]@{ Script = 'engine/asset-trend/Invoke-SITrend.ps1'; Args = $a; Skip = $null }
        }
        'asset-correlation' {
            if ([bool](& $g 'SI_Correlation_DryRun')) { $a['DryRun'] = $true }
            $rl = & $int 'SI_Correlation_RowLimit'; if ($rl -gt 0) { $a['RowLimit'] = $rl }
            return [pscustomobject]@{ Script = 'engine/asset-correlation/Invoke-SICorrelation.ps1'; Args = $a; Skip = $null }
        }
        'asset-properties' {
            # #412 RETIRED as a collection job: with SI_AssetProperties = 'full' the profilers read each source once and
            # publish the full asset metadata themselves. A job an existing install still starts ends successfully, said.
            return [pscustomobject]@{ Script = 'engine/asset-properties/Invoke-SIAssetProperties.ps1'; Args = $a
                Skip = "skipped: asset-properties is retired -- with SI_AssetProperties = 'full' the endpoint, identity and azure profilers read each source once and publish the full asset metadata themselves; this job can be removed" }
        }
        'asset-cmdb' {
            # Writing to a customer's CMDB is a deliberate act: only SI_Cmdb_Run = 'apply' switches it on. NO STEP OF THE FLOW
            # RUNS IN WHATIF (owner 2026-10-23: "all enabled must be working in the flow. no whatiff") -- a hand-off that is
            # not switched on has nothing to do, said plainly; it never plans in whatif as if it ran (live: the largest
            # install's step ran "-Mode match-only -WhatIf True" every night with its ServiceNow connector off).
            $run = "$(& $g 'SI_Cmdb_Run')".Trim().ToLowerInvariant()
            if ($run -ne 'apply') {
                return [pscustomobject]@{ Script = 'engine/asset-cmdb/Invoke-SICmdb.ps1'; Args = $a
                    Skip = "the CMDB hand-off to ServiceNow is not switched on at this install (SI_Cmdb_Run = 'apply' switches it on)" }
            }
            $mode = "$(& $g 'SI_Cmdb_Mode')".Trim().ToLowerInvariant()
            $a['Mode'] = if ($mode -in 'match-only', 'create-if-unmatched') { $mode } else { 'match-only' }
            if ([bool](& $g 'SI_Cmdb_AllowCreate')) { $a['AllowCreate'] = $true }
            $rl = & $int 'SI_Cmdb_RowLimit'; if ($rl -gt 0) { $a['RowLimit'] = $rl }
            return [pscustomobject]@{ Script = 'engine/asset-cmdb/Invoke-SICmdb.ps1'; Args = $a; Skip = $null }
        }
        'asset-vulnerabilities' {
            # The vulnerability close-loop (#216): the VM's `asset-cmdb launcher -Vulnerabilities`, as its own job, so
            # a SQL-only install never needs the optional ServiceNow CMDB connector. Same safe defaults as the VM:
            # 'plan' unless Run = apply; opening and closing are armed separately.
            $script = 'engine/asset-cmdb/Invoke-SIVulnLoop.ps1'
            # #269: TWO jobs drive the connectors -- caj-si-asset-vulnerabilities (SI_VULN_TARGET=Sql: the SQL connector,
            # and any REST connector) and caj-si-asset-vulns-servicenow (SI_VULN_TARGET=ServiceNow). A job without the
            # variable (an install not set up again since) drives every connector, exactly as before.
            $group = Get-SIVulnConnectorGroup -Environment $Environment
            if ($group) { $a['ConnectorGroup'] = $group }
            $legacy = "$(& $g 'SI_VulnSync_Target')".Trim()
            if ($group -and $legacy -in 'Sql', 'ServiceNow' -and $legacy -ne $group -and -not ("$(& $g 'SI_ProSqlServer')".Trim() -and "$(& $g 'SI_ProSqlDatabase')".Trim())) {
                return [pscustomobject]@{ Script = $script; Args = $a
                    Skip = ("this is the {0} connector's job, and this install's vulnerability target is {1} -- the {1} job runs it" -f $group, $legacy) }
            }
            if ("$(& $g 'SI_ProSqlServer')".Trim() -and "$(& $g 'SI_ProSqlDatabase')".Trim()) {
                # Phase E: connectors live in the Pro database (cfg.Connector) and each carries its own Mode and
                # AllowCreate / AllowClose, so the job arms nothing itself. Only an explicit SI_VulnSync_Run = 'plan'
                # keeps every connector in whatif. No rows there = the engine says there is no target.
                # The legacy SI_VulnSync_Target (still on every container job: SI_CFG_SI_VulnSync_Target=Sql) never decides
                # here (live 2026-10-23: it sent every install with a Pro database down the legacy path, where no
                # SI_VulnSync_Run = 'apply' meant WHATIF -- the connector said apply, nothing was ever written).
                if ("$(& $g 'SI_VulnSync_Run')".Trim().ToLowerInvariant() -eq 'plan') { $a['WhatIf'] = $true }
                return [pscustomobject]@{ Script = $script; Args = $a; Skip = $null }
            }
            if ("$(& $g 'SI_VulnSync_Target')".Trim() -notin 'Sql', 'ServiceNow') {
                return [pscustomobject]@{ Script = $script; Args = $a
                    Skip = "the vulnerability close-loop has no target: set SI_VulnSync_Target = 'Sql' or 'ServiceNow', or configure the Pro database (SI_ProSqlServer / SI_ProSqlDatabase) and add a connector, to enable it" }
            }
            $run = "$(& $g 'SI_VulnSync_Run')".Trim().ToLowerInvariant()
            if (-not $run) { $run = "$(& $g 'SI_Cmdb_Run')".Trim().ToLowerInvariant() }
            if ($run -ne 'apply') { $a['WhatIf'] = $true }
            $create = & $g 'SI_VulnSync_AllowCreate'
            if ($null -eq $create -or "$create" -eq '') { $create = & $g 'SI_Cmdb_AllowCreate' }
            if ([bool]$create) { $a['AllowCreate'] = $true }
            if ([bool](& $g 'SI_VulnSync_AllowClose')) { $a['AllowClose'] = $true }
            return [pscustomobject]@{ Script = $script; Args = $a; Skip = $null }
        }
        'asset-datasync' {
            # The Pro data backend (REQUIREMENTS §9.3.3 B): complete Risk Analysis collections -> the Pro database. Off,
            # with the reason, until a Pro database is configured. The retention is read by the engine itself.
            $script = 'engine/pro-data/Invoke-SIDataSync.ps1'
            $srv = "$(& $g 'SI_Pro_DataSqlServer')".Trim(); if (-not $srv) { $srv = "$(& $g 'SI_ProSqlServer')".Trim() }
            $db = "$(& $g 'SI_Pro_DataSqlDatabase')".Trim(); if (-not $db) { $db = "$(& $g 'SI_ProSqlDatabase')".Trim() }
            if (-not $srv -or -not $db) {
                return [pscustomobject]@{ Script = $script; Args = $a
                    Skip = 'the Pro data backend has no database: set SI_ProSqlServer and SI_ProSqlDatabase to enable it' }
            }
            if ([bool](& $g 'SI_Pro_DataSync_DryRun')) { $a['DryRun'] = $true }
            $lb = & $int 'SI_Pro_DataLookbackDays'; if ($lb -gt 0) { $a['LookbackDays'] = $lb }
            return [pscustomobject]@{ Script = $script; Args = $a; Skip = $null }
        }
        'asset-cmdb-sql' {
            # The SQL CMDB connector (#271): every CI into the Pro database's CI table. Off, with the reason, until a Pro
            # database is configured or when SI_Pro_CmdbSql_Enabled is false. Its other settings are read by the engine.
            $script = 'engine/asset-cmdb/Invoke-SICmdbSql.ps1'
            $srv = "$(& $g 'SI_Pro_DataSqlServer')".Trim(); if (-not $srv) { $srv = "$(& $g 'SI_ProSqlServer')".Trim() }
            $db = "$(& $g 'SI_Pro_DataSqlDatabase')".Trim(); if (-not $db) { $db = "$(& $g 'SI_ProSqlDatabase')".Trim() }
            if (-not $srv -or -not $db) {
                return [pscustomobject]@{ Script = $script; Args = $a
                    Skip = 'the SQL CMDB connector has no database: set SI_ProSqlServer and SI_ProSqlDatabase to enable it' }
            }
            if ("$(& $g 'SI_Pro_CmdbSql_Enabled')".Trim().Trim('$') -match '^(?i)(false|0|no|off)$') {
                return [pscustomobject]@{ Script = $script; Args = $a; Skip = 'the SQL CMDB connector is switched off (SI_Pro_CmdbSql_Enabled = false)' }
            }
            if ("$(& $g 'SI_Pro_CmdbSql_DryRun')".Trim().Trim('$') -match '^(?i)(true|1|yes|on)$') { $a['WhatIf'] = $true }
            return [pscustomobject]@{ Script = $script; Args = $a; Skip = $null }
        }
        'close-loop-mail' {
            # The close-loop's daily mail. Whether it sends (Mail_CloseLoop_Daily_SendMail / _To) is decided by the engine
            # itself, after its licence gate -- off or without recipients it says so in one line and ends successfully.
            return [pscustomobject]@{ Script = 'engine/asset-cmdb/Invoke-SICloseLoopMail.ps1'; Args = $a; Skip = $null }
        }
        'asset-tagging' {
            # #236: asset tagging as a Pro job, under its OWN identity. REPORT ONLY unless the Pro setting
            # SI_Pro_AssetTagging_Apply is on -- writing to the customer's Defender, Azure and Entra is a deliberate
            # act, exactly like the CMDB's 'apply'. Only a real true turns it on: an empty, unknown or 'false' value
            # keeps the run report-only.
            # #643 (owner 2026-10-13: "tagging must be disabled by default. customer must enable it in settings"): the job
            # runs at all only when the customer setting "Asset tagging" (SI_AssetTagging_Enabled) is a real true. Off = no
            # rule is evaluated, nothing is planned, nothing is written. Writing stays the separate opt-in above.
            if (-not (Test-SIAssetTaggingApply -Value (& $g 'SI_AssetTagging_Enabled'))) {
                return [pscustomobject]@{ Script = 'engine/asset-tagging/Invoke-SIAssetTaggingJob.ps1'; Args = $a; Skip = 'asset tagging is off (the setting "Asset tagging", SI_AssetTagging_Enabled, is not on)' }
            }
            if (Test-SIAssetTaggingApply -Value (& $g 'SI_Pro_AssetTagging_Apply')) { $a['Apply'] = $true }
            return [pscustomobject]@{ Script = 'engine/asset-tagging/Invoke-SIAssetTaggingJob.ps1'; Args = $a; Skip = $null }
        }
        'verification' {
            # The verification service (docs/V3-DATA-MODEL.md 2.11): data-collection gaps, read-only toward Defender, Entra and
            # Azure. Off, with the reason, until a Pro database is configured -- its findings and decisions live there.
            $script = 'engine/verification/Invoke-SIVerification.ps1'
            $srv = "$(& $g 'SI_Pro_DataSqlServer')".Trim(); if (-not $srv) { $srv = "$(& $g 'SI_ProSqlServer')".Trim() }
            $db = "$(& $g 'SI_Pro_DataSqlDatabase')".Trim(); if (-not $db) { $db = "$(& $g 'SI_ProSqlDatabase')".Trim() }
            if (-not $srv -or -not $db) {
                return [pscustomobject]@{ Script = $script; Args = $a; Skip = 'the verification service has no database: set SI_ProSqlServer and SI_ProSqlDatabase to enable it' }
            }
            return [pscustomobject]@{ Script = $script; Args = $a; Skip = $null }
        }
        'config-backup' {
            # #404 (CONFIG-1.3): the daily configuration backup (caj-si-config-backup), on its own timer outside the pipeline.
            # Off, with the reason, until a Pro database is configured. The retention settings are read by the engine.
            $script = 'engine/pro-settings/Invoke-SIConfigBackup.ps1'
            if (-not "$(& $g 'SI_ProSqlServer')".Trim() -or -not "$(& $g 'SI_ProSqlDatabase')".Trim()) {
                return [pscustomobject]@{ Script = $script; Args = $a; Skip = 'the configuration backup has no database: set SI_ProSqlServer and SI_ProSqlDatabase to enable it' }
            }
            return [pscustomobject]@{ Script = $script; Args = $a; Skip = $null }
        }
        'heartbeat' {
            # #718: the hourly status report to Invardia (caj-si-heartbeat), on its own timer outside the pipeline. It decides
            # itself what it may send (identified only; nothing from an anonymous install) and never fails.
            return [pscustomobject]@{ Script = 'engine/heartbeat/Invoke-SIHeartbeat.ps1'; Args = $a; Skip = $null }
        }
        'flow' {
            # #269: the daily job flow (caj-si-flow): starts the other jobs through ARM, one step after the other.
            # Env SI_FLOW_FORCE / SI_FLOW_FROM_STEP / SI_FLOW_TRIGGER are read by the runner itself.
            return [pscustomobject]@{ Script = 'engine/flow/Invoke-SIJobFlowRun.ps1'; Args = @{ HostKind = 'Container' }; Skip = $null }
        }
        'templates-publish' {
            # #235: caj-si-templates -- MANUAL trigger only. The web app starts it after an Admin accepted a template
            # release (or roll back) on Review & commit, with the EXACT accepted selection fingerprint in the execution's
            # environment. Without one it does nothing; with one the publish refuses any other (-StrictJob: a blocked
            # publish fails the job, so the page shows it as failed).
            $script = 'setup/Publish-SITemplates.ps1'
            if (-not $Environment) {
                $Environment = @{}
                foreach ($e in [Environment]::GetEnvironmentVariables().GetEnumerator()) { $Environment[[string]$e.Key] = [string]$e.Value }
            }
            $ev = { param($n) if ($Environment.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace([string]$Environment[$n])) { ([string]$Environment[$n]).Trim() } else { '' } }
            $fp = & $ev 'SI_TEMPLATES_ACCEPT_FINGERPRINT'; $mode = (& $ev 'SI_TEMPLATES_MODE').ToLowerInvariant(); $pack = & $ev 'SI_TEMPLATES_PACK'
            if ($fp -notmatch '^[0-9a-f]{64}$') {
                return [pscustomobject]@{ Script = $script; Args = $a
                    Skip = 'no accepted template release: this job is started from the web app''s Template releases page, with the fingerprint the Admin accepted' }
            }
            if ($mode -notin 'release', 'rollback' -or $pack -notmatch '^\d{1,6}(\.\d{1,12}){1,5}$') {
                return [pscustomobject]@{ Script = $script; Args = $a; Skip = ("the template release request is incomplete (mode '{0}', version '{1}') -- nothing was published" -f $mode, $pack) }
            }
            $a['Apply'] = $true; $a['StrictJob'] = $true; $a['PassThru'] = $true; $a['AcceptFingerprint'] = $fp
            if ($mode -eq 'rollback') { $a['RollbackToVersion'] = $pack } else { $a['FromStaged'] = $pack }
            $methods = @((& $ev 'SI_TEMPLATES_METHODS') -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne '*' })
            if ($methods.Count) { $a['Method'] = $methods }
            # #405: the one-click roll back of Microsoft content -- only that class's items
            $cls = @((& $ev 'SI_TEMPLATES_CLASS') -split ';' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -in 'fix', 'default', 'microsoft' })
            if ($cls.Count -and $mode -eq 'rollback') { $a['Class'] = $cls }
            $by = & $ev 'SI_TEMPLATES_REQUESTED_BY'; if ($by) { $a['RequestedBy'] = $by }
            return [pscustomobject]@{ Script = $script; Args = $a; Skip = $null }
        }
        default { return $null }
    }
}

# ==================================================================================================================
#  SIGN-IN (#209) -- managed identity > certificate (PFX from Key Vault) > client secret
# ==================================================================================================================
# An engine container could only sign in with an SPN client SECRET. Internal installs are certificate only and Pro is
# container only, so a certificate-only customer could not run Pro at all. PIM's containers sign in as the job's
# managed identity; SI now does the same, keeps the certificate (as the SI updater receives it), and KEEPS THE
# SECRET: it is a required Community capability, and a Community job that has only the secret runs exactly as before.

function Resolve-SIContainerAuthMode {
    <#
        PURE. How THIS container signs in, from its environment (-Environment: a name -> value hashtable; the
        process environment by default).
          ManagedIdentity -- IDENTITY_ENDPOINT (Container Apps injects it when the job has an identity) AND
                             SI_UAMI_CLIENTID (Bootstrap names the user-assigned identity to use);
          Certificate     -- SI_SPN_CERT_PFX_B64 (a Key Vault-referenced secret) + SI_SPN_APPID + SI_SPN_TENANTID;
          Secret          -- SI_SPN_SECRET (unchanged; the Community default);
          None            -- nothing usable (the entry point refuses with Reason).
        Returns @{ Mode; ClientId; Reason }.
    #>
    param([hashtable]$Environment)
    if (-not $Environment) {
        $Environment = @{}
        foreach ($e in [Environment]::GetEnvironmentVariables().GetEnumerator()) { $Environment[[string]$e.Key] = [string]$e.Value }
    }
    $get = { param($n) if ($Environment.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace([string]$Environment[$n])) { ([string]$Environment[$n]).Trim() } else { '' } }
    $endpoint = & $get 'IDENTITY_ENDPOINT'
    $uami     = & $get 'SI_UAMI_CLIENTID'
    if ($endpoint -and $uami) {
        return [pscustomobject]@{ Mode = 'ManagedIdentity'; ClientId = $uami; Reason = ("the job's user-assigned managed identity (client id {0})" -f $uami) }
    }
    $appId  = & $get 'SI_SPN_APPID'
    $tenant = & $get 'SI_SPN_TENANTID'
    if ((& $get 'SI_SPN_CERT_PFX_B64') -and $appId -and $tenant) {
        return [pscustomobject]@{ Mode = 'Certificate'; ClientId = $appId; Reason = ('the SPN {0} by certificate (PFX from Key Vault)' -f $appId) }
    }
    if (& $get 'SI_SPN_SECRET') {
        return [pscustomobject]@{ Mode = 'Secret'; ClientId = $appId; Reason = ('the SPN {0} by client secret' -f $appId) }
    }
    $why = if ($uami -and -not $endpoint) { 'SI_UAMI_CLIENTID is set but the job has no managed identity endpoint (IDENTITY_ENDPOINT) -- assign the identity to the job' }
           else { 'no credential: set SI_UAMI_CLIENTID (managed identity), SI_SPN_CERT_PFX_B64 + SI_SPN_APPID + SI_SPN_TENANTID (certificate), or SI_SPN_SECRET (client secret)' }
    [pscustomobject]@{ Mode = 'None'; ClientId = ''; Reason = $why }
}

function Resolve-SIBootstrapAuthChoice {
    <#
        PURE (Bootstrap side). Which sign-in the jobs get, and why. First match wins:
          1. -UseManagedIdentity                                   -> ManagedIdentity
          2. -CertificateKeyVaultName AND -CertificateSecretName   -> Certificate (half of it is an error, never a silent
                                                                      fall back to another sign-in)
          3. -UseClientSecret                                      -> Secret (a supported, explicit choice -- never removed)
          4. SI_AuthMethod in the config: ManagedIdentity / Secret -> that one
          5. the config carries an SPN client secret (an install set up with one -- SI_SPN_Secret, the 2.2 SI_Graph_Secret,
             or a Key Vault secret name) and no SI_AuthMethod      -> Secret: an existing install keeps what its jobs
                                                                      have; nothing changes under it by itself
          6. otherwise                                             -> ManagedIdentity (the DEFAULT since 2026-10-07,
                                                                      operator decision -- as the guided install does)
        -UseClientSecret with -UseManagedIdentity or with a certificate is an error: pick one.
        Returns @{ Mode; Reason; Default } -- Default $true when no switch and no SI_AuthMethod decided it.
    #>
    param([bool]$UseManagedIdentity = $false, [string]$CertificateKeyVaultName, [string]$CertificateSecretName,
          [bool]$UseClientSecret = $false, [AllowEmptyString()][string]$ConfiguredMethod = '', [bool]$HasConfiguredSecret = $false)
    $kv = -not [string]::IsNullOrWhiteSpace($CertificateKeyVaultName)
    $cs = -not [string]::IsNullOrWhiteSpace($CertificateSecretName)
    if ($kv -xor $cs) { throw 'Certificate sign-in needs BOTH -CertificateKeyVaultName and -CertificateSecretName (the Key Vault secret holding the SPN PFX).' }
    $cert = $kv -and $cs
    # -UseManagedIdentity wins over certificate settings (as it always has); a client secret next to either is an error.
    if ($UseClientSecret -and ($UseManagedIdentity -or $cert)) {
        throw 'Pick ONE sign-in for the jobs: -UseManagedIdentity, -UseClientSecret, or -CertificateKeyVaultName with -CertificateSecretName.'
    }
    $o = { param($m, $why, $def) [pscustomobject]@{ Mode = $m; Reason = $why; Default = [bool]$def } }
    if ($UseManagedIdentity) { return (& $o 'ManagedIdentity' '-UseManagedIdentity' $false) }
    if ($cert)               { return (& $o 'Certificate' '-CertificateKeyVaultName / -CertificateSecretName' $false) }
    if ($UseClientSecret)    { return (& $o 'Secret' '-UseClientSecret' $false) }
    $cfg = "$ConfiguredMethod".Trim()
    if ($cfg -match '^(?i)(ManagedIdentity|MI|Identity)$')          { return (& $o 'ManagedIdentity' 'SI_AuthMethod = ManagedIdentity in the config' $false) }
    if ($cfg -match '^(?i)(Secret|SpnSecret|ClientSecret)$')        { return (& $o 'Secret' 'SI_AuthMethod = Secret in the config' $false) }
    if ($HasConfiguredSecret) { return (& $o 'Secret' 'the config carries an SPN client secret (an existing install keeps its sign-in)' $true) }
    & $o 'ManagedIdentity' 'the default: a user-assigned managed identity' $true
}

# #475 -- KEDA BY DESIGN (operator 2026-10-08: "KEDA by design"; DESIGN.md 13): the collection engines that discover into
# parts run as a producer + queue-scaled workers. Only these three can: discovery writes their parts and their workers run
# from Collect on a part. Public IP (a handful of addresses), the classifier and the Pro engines stay one scheduled job each.
$script:SIKedaPartsEngines = @('identity', 'endpoint', 'azure')

function Test-SIKedaPartsEngine {
    <# PURE. Whether an engine runs as producer + workers when queue scaling is on. #>
    param([AllowEmptyString()][string]$Engine)
    $script:SIKedaPartsEngines -contains ([string]$Engine).Trim().ToLowerInvariant()
}

function Resolve-SIBootstrapKedaChoice {
    <#
        PURE (Bootstrap side). Whether the collection engines run as producer + workers (KEDA), and what that does to the
        jobs' sign-in. KEDA is ON BY DESIGN; the opt-out is explicit (-UseKEDA:$false, or SI_Bootstrap_UseKEDA = $false).
        Queue scaling runs on the jobs' MANAGED IDENTITY (operator 2026-10-08: "use managed identity" -- the scaler signs in
        with it, never with a storage key or a secret):
          managed identity / certificate (both have the identity)  -> KEDA
          a client secret the install merely CARRIES (no switch, no SI_AuthMethod -- Resolve-SIBootstrapAuthChoice
            Default)                                                -> KEDA, and the jobs MOVE to the managed identity with
                                                                       its grants applied (as -UseManagedIdentity
                                                                       -GrantIdentityRoles); if a grant cannot be made, the
                                                                       caller keeps the jobs as they are
          a client secret CHOSEN explicitly (-UseClientSecret, SI_AuthMethod = Secret) -> no KEDA (the choice stands;
                                                                       app-secret sign-in is a supported capability); an
                                                                       EXPLICIT -UseKEDA with it is refused, as before
        Returns @{ Keda; Explicit; MoveToManagedIdentity; Refuse; Message }.
    #>
    param([bool]$CliBound = $false, [bool]$CliValue = $false, $Configured, [Parameter(Mandatory)][string]$AuthMode, [bool]$AuthDefault = $false)
    $o = { param($k, $x, $mv, $rf, $msg) [pscustomobject]@{ Keda = [bool]$k; Explicit = [bool]$x; MoveToManagedIdentity = [bool]$mv; Refuse = [bool]$rf; Message = [string]$msg } }
    $cfgSet = ($null -ne $Configured -and "$Configured".Trim() -ne '')
    $cfgVal = $false
    if ($cfgSet) { if ($Configured -is [bool]) { $cfgVal = $Configured } else { $cfgVal = ("$Configured".Trim() -match '^(?i)(1|true|on|yes)$') } }
    $explicit = $CliBound -or $cfgSet
    $want = $true
    if ($CliBound) { $want = $CliValue } elseif ($cfgSet) { $want = $cfgVal }
    if (-not $want) {
        return (& $o $false $explicit $false $false '[parts] queue scaling is switched off for this install (SI_Bootstrap_UseKEDA = $false / -UseKEDA:$false): identity, endpoint and Azure run as one scheduled job each.')
    }
    if ($AuthMode -ne 'Secret') {
        return (& $o $true $explicit $false $false '[parts] identity, endpoint and Azure run as a producer and queue-scaled workers (KEDA), signed in as the jobs'' managed identity.')
    }
    if ($AuthDefault) {
        return (& $o $true $explicit $true $false '[parts] queue scaling runs on the jobs'' managed identity: these jobs move from the client secret to the managed identity, with its grants -- if a grant cannot be made here, nothing changes and the missing grant is listed.')
    }
    if ($explicit) {
        return (& $o $false $true $false $true 'Queue scaling (-UseKEDA) needs the jobs'' managed identity: the queue scaler signs in with it, never with a storage key. Use the managed identity or certificate sign-in (SI_AuthMethod), or leave -UseKEDA off.')
    }
    & $o $false $false $false $false '[parts] these jobs sign in with a client secret by choice (-UseClientSecret / SI_AuthMethod = Secret), and queue scaling needs the managed identity: identity, endpoint and Azure run as one scheduled job each.'
}

function Test-SIBootstrapJobIsSI {
    <# PURE. A job SI's setup created (its si-build tag) -- only such a job may be replaced or removed by setup. #>
    param($Job)
    if ($null -eq $Job -or $null -eq $Job.tags) { return $false }
    $names = @(); if ($Job.tags -is [System.Collections.IDictionary]) { $names = @($Job.tags.Keys) } else { $names = @($Job.tags.PSObject.Properties | ForEach-Object { $_.Name }) }
    [bool](@($names | Where-Object { [string]$_ -eq 'si-build' }).Count)
}

function Get-SIBootstrapReplacedJobs {
    <#
        PURE. The jobs of ONE engine that the chosen layout replaces: with queue scaling on, the engine's scheduled job
        caj-si-<engine> (the producer + worker take over); with it off, the engine's producer and worker. Never anything
        else. Returns the job NAMES; the caller removes only those that exist and carry SI's si-build tag.
    #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][bool]$Keda)
    $k = $Engine.Trim().ToLowerInvariant()
    if (-not (Test-SIKedaPartsEngine $k)) { return @() }
    if ($Keda) { return @("caj-si-$k") }
    @("caj-si-$k-producer", "caj-si-$k-worker")
}

function Resolve-SIBootstrapAuthMode {
    <# PURE (Bootstrap side). The jobs' sign-in mode (Resolve-SIBootstrapAuthChoice, Mode only). #>
    param([bool]$UseManagedIdentity = $false, [string]$CertificateKeyVaultName, [string]$CertificateSecretName,
          [bool]$UseClientSecret = $false, [AllowEmptyString()][string]$ConfiguredMethod = '', [bool]$HasConfiguredSecret = $false)
    (Resolve-SIBootstrapAuthChoice -UseManagedIdentity $UseManagedIdentity -CertificateKeyVaultName $CertificateKeyVaultName `
        -CertificateSecretName $CertificateSecretName -UseClientSecret $UseClientSecret -ConfiguredMethod $ConfiguredMethod `
        -HasConfiguredSecret $HasConfiguredSecret).Mode
}

function Get-SIBootstrapRequiredSpnGlobals {
    <# PURE. The SPN globals Bootstrap must find in the customer's config for a sign-in mode. #>
    param([Parameter(Mandatory)][ValidateSet('Secret', 'ManagedIdentity', 'Certificate')][string]$Mode)
    switch ($Mode) {
        'Secret'          { return @('SI_SPN_AppId', 'SI_SPN_Secret', 'SI_SPN_TenantId', 'SI_SPN_ObjectId') }
        'Certificate'     { return @('SI_SPN_AppId', 'SI_SPN_TenantId', 'SI_SPN_ObjectId') }
        'ManagedIdentity' { return @() }   # the identity is Bootstrap's own; the tenant comes from the Az context
    }
}

function Get-SIContainerJobAuthArgs {
    <#
        PURE (Bootstrap side). What each engine job carries to sign in. Returns @{ Mode; SecretArgs; EnvArgs;
        IdentityResourceId } -- IdentityResourceId is the identity to ASSIGN to the job ($null for Secret).
          Secret          -- si-spn-secret + SI_SPN_APPID / SI_SPN_SECRET=secretref / SI_SPN_TENANTID / SI_SPN_OBJECTID,
                             EXACTLY what every job carried before #209;
          ManagedIdentity -- no secret at all: SI_UAMI_CLIENTID + SI_SPN_TENANTID + SI_SPN_OBJECTID (the identity's
                             principal id -- the object the DCR grants are made to);
          Certificate     -- the SPN's PFX as a Key Vault REFERENCE (si-spn-cert, resolved by the assigned
                             identity -- Bootstrap never reads the value), as Install-SIUpdaterJob.ps1 does.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('Secret', 'ManagedIdentity', 'Certificate')][string]$Mode,
        [string]$SpnAppId, [string]$SpnSecret, [string]$SpnTenantId, [string]$SpnObjectId,
        [string]$IdentityClientId, [string]$IdentityPrincipalId, [string]$IdentityResourceId,
        [string]$KeyVaultUri, [string]$CertificateSecretName
    )
    $need = { param($v, $n) if ([string]::IsNullOrWhiteSpace([string]$v)) { throw ("{0} sign-in: {1} is empty." -f $Mode, $n) } }
    switch ($Mode) {
        'Secret' {
            return [pscustomobject]@{
                Mode = $Mode; IdentityResourceId = $null
                SecretArgs = @(('si-spn-secret={0}' -f $SpnSecret))
                EnvArgs    = @("SI_SPN_APPID=$SpnAppId", 'SI_SPN_SECRET=secretref:si-spn-secret', "SI_SPN_TENANTID=$SpnTenantId", "SI_SPN_OBJECTID=$SpnObjectId")
            }
        }
        'ManagedIdentity' {
            & $need $IdentityClientId 'the identity client id'; & $need $IdentityResourceId 'the identity resource id'; & $need $SpnTenantId 'the tenant id'
            return [pscustomobject]@{
                Mode = $Mode; IdentityResourceId = $IdentityResourceId
                SecretArgs = @()
                EnvArgs    = @("SI_UAMI_CLIENTID=$IdentityClientId", "SI_SPN_TENANTID=$SpnTenantId", "SI_SPN_OBJECTID=$IdentityPrincipalId")
            }
        }
        'Certificate' {
            & $need $SpnAppId 'SI_SPN_AppId'; & $need $SpnTenantId 'SI_SPN_TenantId'; & $need $KeyVaultUri 'the Key Vault URI'
            & $need $CertificateSecretName 'the certificate secret name'; & $need $IdentityResourceId 'the identity resource id'
            $vault = ([string]$KeyVaultUri).TrimEnd('/') + '/'
            return [pscustomobject]@{
                Mode = $Mode; IdentityResourceId = $IdentityResourceId
                SecretArgs = @(('si-spn-cert=keyvaultref:{0}secrets/{1},identityref:{2}' -f $vault, $CertificateSecretName, $IdentityResourceId))
                EnvArgs    = @("SI_SPN_APPID=$SpnAppId", 'SI_SPN_CERT_PFX_B64=secretref:si-spn-cert', "SI_SPN_TENANTID=$SpnTenantId", "SI_SPN_OBJECTID=$SpnObjectId")
            }
        }
    }
}

function Get-SIKedaQueueScaleArgs {
    <#
        PURE (Bootstrap side). The queue scale rule of a KEDA worker job (caj-si-<engine>-worker): the azure-queue
        scaler on SI's own storage account, signed in as the job's MANAGED IDENTITY (--scale-rule-identity). Storage
        is reached with an identity only -- a new account has shared-key access OFF -- so a scaler with no
        identity could never read the queue length and the worker would never start. Same arguments on create and
        on update, so an older worker gets the identity on the next run of setup.
        No identity (the Secret sign-in) = refused: there is nothing the scaler could sign in as.
    #>
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][AllowEmptyString()][string]$StorageAccount,
        [AllowEmptyString()][string]$IdentityResourceId,
        # #742: a queue other than the parts engine's shard queue (the Risk Analysis work items, Get-SIRaScaleOutQueueName)
        [string]$QueueName = ''
    )
    if ([string]::IsNullOrWhiteSpace($StorageAccount)) { throw 'Queue scaling needs SI_StorageAccount (the account that holds the shard queues).' }
    if ([string]::IsNullOrWhiteSpace($IdentityResourceId)) {
        throw 'Queue scaling (-UseKEDA) needs the jobs'' managed identity: the queue scaler signs in with it, never with a storage key. Use the managed identity or certificate sign-in (SI_AuthMethod), or leave -UseKEDA off.'
    }
    $q = if ($QueueName) { $QueueName } else { 'si-{0}-shards' -f $Engine }
    return @(
        '--scale-rule-name', 'si-shards-queue',
        '--scale-rule-type', 'azure-queue',
        '--scale-rule-metadata', ('queueName={0}' -f $q), ('accountName={0}' -f $StorageAccount), 'queueLength=1',
        '--scale-rule-identity', $IdentityResourceId
    )
}

# #742 -- RISK ANALYSIS ON QUEUE WORKERS (engine/risk-analysis/_shared/RA-ScaleOut.ps1). The Detailed Risk Analysis job is the
# run's PRODUCER; caj-si-raworker-detailed is its queue-scaled WORKER job (KEDA, the same identity, the producer's size). One
# definition, used by Bootstrap for a new install and by every update for an existing one (setup/_shared/SI-RaWorkerJobs.ps1).
$script:SIRaScaleOutEngines = @{ 'risk-analysis-detailed' = 'Detailed' }

function Get-SIRaScaleOutGrain {
    <# PURE. The grain whose reports run on queue workers for a Risk Analysis engine ('' = none: that job runs its reports
       itself). The Detailed job only, for now (#742 increment 1). #>
    param([AllowEmptyString()][string]$Engine)
    $k = ([string]$Engine).Trim().ToLowerInvariant()
    if ($script:SIRaScaleOutEngines.ContainsKey($k)) { return [string]$script:SIRaScaleOutEngines[$k] }
    ''
}

function Get-SIRaScaleOutQueueName {
    <# PURE. The work queue of a grain (RA-ScaleOut.ps1 Get-RAScaleOutQueueName -- the same name). #>
    param([Parameter(Mandatory)][ValidateSet('Detailed', 'Summary')][string]$Grain)
    'si-ra-{0}-items' -f $Grain.ToLowerInvariant()
}

function Get-SIRaWorkerJobName {
    <# PURE. The worker job of a grain: 32 characters at most, and outside the caj-si-ra-<name> namespace of the extra
       report jobs (RA-ScaleOut.ps1 Get-RAScaleOutWorkerJobName -- the same name). #>
    param([Parameter(Mandatory)][ValidateSet('Detailed', 'Summary')][string]$Grain)
    'caj-si-raworker-{0}' -f $Grain.ToLowerInvariant()
}

function Get-SIRaWorkerMaxExecutions {
    <# PURE. How many workers run at once: SI_Bootstrap_RaMaxWorkers, default 4 (the advanced hunting service limits a
       tenant's queries; four workers each running one report keep well inside them). #>
    param([hashtable]$Globals = @{})
    $n = 0
    if ($Globals -and $Globals.ContainsKey('SI_Bootstrap_RaMaxWorkers') -and [int]::TryParse("$($Globals['SI_Bootstrap_RaMaxWorkers'])", [ref]$n) -and $n -gt 0) { return [Math]::Min(30, $n) }
    4
}

function Get-SIRaScaleOutOptIn {
    <#
        PURE. THE RISK ANALYSIS WORKERS ARE ON BY DEFAULT WHERE THEY CAN RUN (owner 2026-10-18: "pls dont turn off things that
        improve time, why do that"). The config's SI_Bootstrap_RaScaleOut, else SI_UPDATER_RA_SCALE_OUT on the updater job
        (-UpdaterValue). Returns @{ On; Configured (a value was set -- on or off) }. Not set = ON: setup and every update give
        the install the workers where queue scaling and the managed identity let them run. Only an explicit $false / off /
        0 / no turns them off -- the customer's choice, always honoured.
    #>
    param([hashtable]$Globals = @{}, [AllowEmptyString()][string]$UpdaterValue = '')
    $v = $null
    if ($Globals -and $Globals.ContainsKey('SI_Bootstrap_RaScaleOut') -and $null -ne $Globals['SI_Bootstrap_RaScaleOut'] -and "$($Globals['SI_Bootstrap_RaScaleOut'])".Trim() -ne '') { $v = "$($Globals['SI_Bootstrap_RaScaleOut'])".Trim() }
    elseif ("$UpdaterValue".Trim()) { $v = "$UpdaterValue".Trim() }
    $off = ($null -ne $v -and $v -match '^(?i)(0|false|\$false|off|no|disabled?)$')
    [pscustomobject]@{ On = (-not $off); Configured = ($null -ne $v) }
}

function Resolve-SIRaScaleOutChoice {
    <#
        PURE. Whether a Risk Analysis job hands its reports to a worker job: its grain has workers (Get-SIRaScaleOutGrain), the
        install did not switch the workers off (SI_Bootstrap_RaScaleOut -- ON by default, Get-SIRaScaleOutOptIn), queue
        scaling is on for the install (the KEDA choice -- the same rule as the collection engines) and the jobs sign in with
        an identity the queue scaler can use. Returns @{ On; Grain; Reason; Configured }. Off = the job runs its reports
        itself, as before; Reason is the one plain line that says why. Configured = the setting was given (on or off);
        SwitchedOff = the customer switched the workers off (the only case in which setup removes a worker job).
    #>
    param([AllowEmptyString()][string]$Engine, [bool]$Keda, [AllowEmptyString()][string]$IdentityResourceId, [AllowEmptyString()][string]$StorageAccount, [hashtable]$Globals = @{})
    $g = Get-SIRaScaleOutGrain -Engine $Engine
    $opt = Get-SIRaScaleOutOptIn -Globals $Globals
    $o = { param($on, $why) [pscustomobject]@{ On = [bool]$on; Grain = $g; Reason = [string]$why; Configured = [bool]$opt.Configured; SwitchedOff = (-not $opt.On) } }
    if (-not $g) { return (& $o $false 'this Risk Analysis job runs its reports itself') }
    if (-not $opt.On) { return (& $o $false 'Risk Analysis workers are switched off for this install (SI_Bootstrap_RaScaleOut = $false)') }
    if (-not $Keda) { return (& $o $false 'queue scaling is off for this install, so the Risk Analysis reports run in their job') }
    if (-not "$IdentityResourceId".Trim()) { return (& $o $false 'the jobs have no managed identity for the queue scaler, so the Risk Analysis reports run in their job') }
    if (-not "$StorageAccount".Trim()) { return (& $o $false 'no storage account for the work queue, so the Risk Analysis reports run in their job') }
    & $o $true ('the {0} reports run on queue workers ({1})' -f $g, (Get-SIRaWorkerJobName -Grain $g))
}

function Get-SIRaProducerScaleOutEnvArgs {
    <# PURE. What makes a Risk Analysis job the producer of its worker job: SI_RA_SCALE_OUT=on and the worker job's name.
       -Workers (#831): how many workers may run at once -- the SAME SI_RA_WORKERS its workers get, so the producer plans the
       parts of a big report for the real worker count (none written when not given). #>
    param([Parameter(Mandatory)][ValidateSet('Detailed', 'Summary')][string]$Grain, [int]$Workers = 0)
    $w = @(); if ($Workers -gt 0) { $w = @('SI_RA_WORKERS={0}' -f $Workers) }
    @('SI_RA_SCALE_OUT=on', ('SI_RA_WORKER_JOB={0}' -f (Get-SIRaWorkerJobName -Grain $Grain))) + $w
}

function Get-SIRaWorkerEnvArgs {
    <#
        PURE. The worker's environment from its producer's: the same settings, sign-in and Risk Analysis switches (it runs the
        reports as the producer would), without the producer's own (SI_RA_SCALE_OUT / SI_RA_WORKER_JOB), with role ra and
        SI_RA_SCALEOUT_ROLE=worker, and a fallback hold on a report longer than its replica (Get-SIKedaQueueLeaseEnvArgs).
        -Workers: how many workers may run at once (SI_RA_WORKERS) -- each worker asks Defender for its SHARE of the parts one
        Risk Analysis job may ask at a time (engine/risk-analysis/_shared/RA-PartsInParallel.ps1 Get-RAPartsInParallelShare).
    #>
    param([object[]]$EnvArgs = @(), [int]$ReplicaTimeout = 0, [int]$Workers = 0)
    $w = @(); if ($Workers -gt 0) { $w = @('SI_RA_WORKERS={0}' -f $Workers) }
    @(@($EnvArgs | Where-Object { [string]$_ -notmatch '^(SI_RA_SCALE_OUT|SI_RA_WORKER_JOB|SI_RA_SCALEOUT_ROLE|SI_RA_WORKERS|SI_ROLE|SI_TRIGGER_FROM_QUEUE|SI_QUEUE_LEASE_SECONDS)=' }) +
      @('SI_ROLE=ra', 'SI_RA_SCALEOUT_ROLE=worker') + $w + @(Get-SIKedaQueueLeaseEnvArgs -ReplicaTimeout $ReplicaTimeout))
}

# #519 -- THE PRODUCER + WORKER JOBS, ONE DEFINITION: Bootstrap creates them for a new install, and every update
# (setup\_shared\SI-KedaConvert.ps1) creates the same jobs for an install made before queue scaling. Both call these.
function Get-SIKedaQueueName {
    <# PURE. The shard queue of a parts engine: what the producer writes, the workers read and the scaler counts. #>
    param([Parameter(Mandatory)][string]$Engine)
    'si-{0}-shards' -f $Engine.Trim().ToLowerInvariant()
}

function Get-SIKedaQueueLeaseEnvArgs {
    <# PURE. A KEDA worker's shard lease must outlive its replica, or a second worker takes a shard still being processed.
       Never above 7 days (604800 s): a storage queue refuses a longer lease. #>
    param([int]$ReplicaTimeout)
    if ($ReplicaTimeout -gt 3600) { return @(('SI_QUEUE_LEASE_SECONDS={0}' -f [Math]::Min(604800, $ReplicaTimeout + 300))) }
    return @()
}

function Get-SIKedaProducerEnvArgs {
    <#
        PURE. #475: the producer DISCOVERS once into parts (SI_PRODUCER_DISCOVERS=1), writes the manifest and one message per
        part, and hands discovery's records over -- it runs the engine, so it carries the worker's whole environment
        (configuration, sign-in, licence, guard), without the worker's queue-only settings, as role 'producer'.
    #>
    param([object[]]$EnvArgs = @(), [int]$Parallelism = 1)
    @(@($EnvArgs | Where-Object { [string]$_ -notmatch '^(SI_TRIGGER_FROM_QUEUE|SI_ROLE|SI_QUEUE_LEASE_SECONDS|SI_SHARD_COUNT)=' }) + @(
        'SI_ROLE=producer',
        'SI_PRODUCER_DISCOVERS=1',
        "SI_SHARD_COUNT=$Parallelism"
    ))
}

function Get-SIKedaWorkerCreateArgs {
    <#
        PURE. `az containerapp job create` for a KEDA worker (caj-si-<engine>-worker): event-triggered with the queue scale
        rule (Get-SIKedaQueueScaleArgs). --replica-completion-count 1: each replica is one work-item; --parallelism is the
        per-execution cap; KEDA polls and starts one execution per <queueLength> messages above 0, at most -MaxExecutions.
        The caller adds tags, registry, identity, secrets and env.
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Environment,
          [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][int]$ReplicaTimeout,
          [Parameter(Mandatory)][string]$Cpu, [Parameter(Mandatory)][string]$Memory, [int]$MaxExecutions = 30,
          [Parameter(Mandatory)][string]$Engine, [AllowEmptyString()][string]$StorageAccount, [AllowEmptyString()][string]$IdentityResourceId,
          [string]$QueueName = '')
    @(
        'containerapp','job','create',
        '--name',$Name,
        '--resource-group',$ResourceGroup,
        '--environment',$Environment,
        '--trigger-type','Event',
        '--replica-timeout',"$ReplicaTimeout",
        '--replica-retry-limit','0',
        '--replica-completion-count','1',
        '--parallelism','1',
        '--min-executions','0',
        '--max-executions',"$MaxExecutions",
        '--polling-interval','30',
        '--image',$Image,
        '--registry-server',$LoginServer,
        '--cpu',$Cpu,
        '--memory',$Memory,
        '--output','none'
    ) + @(Get-SIKedaQueueScaleArgs -Engine $Engine -StorageAccount $StorageAccount -IdentityResourceId $IdentityResourceId -QueueName $QueueName)
}

function Get-SIKedaProducerCreateArgs {
    <#
        PURE. `az containerapp job create` for a KEDA producer (caj-si-<engine>-producer): cron-triggered, one replica that
        discovers and queues the parts. The caller adds tags, registry, identity, secrets and env.
        SIZE: the ENGINE's size -- -Cpu / -Memory / -ReplicaTimeout as the tenant-sized rule gives the engine's job at install
        (Get-SIContainerJobResources: up to 4 CPU / 8 GiB, the longest run limit Azure takes), or the old job's at a conversion.
        Default (no size given) = the floor every SI job gets, 2 CPU / 4 GiB, that run limit -- NOT a small replica: the identity producer also
        runs the tenant-wide permission scan (role assignments, PIM for groups, transitive memberships) before it queues; on
        0.25 CPU / 0.5 GiB and 10 min it was killed out of memory (exit 137) on internal ring 1, 2026-10-10. The update's job
        sizing raises its CPU and memory further after an out-of-memory run (setup/_shared/SI-JobSizing.ps1).
        No run limit given = the one every engine job gets (Get-SIJobRunLimit); a limit given (the customer's own, the old job's) is used as it is.
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Environment,
          [Parameter(Mandatory)][string]$Cron, [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$LoginServer,
          [string]$Cpu = '2.0', [string]$Memory = '4.0Gi', [int]$ReplicaTimeout = 0)
    if (-not "$Cpu".Trim()) { $Cpu = '2.0' }; if (-not "$Memory".Trim()) { $Memory = '4.0Gi' }; if ($ReplicaTimeout -le 0) { $ReplicaTimeout = [int](Get-SIJobRunLimit) }
    @(
        'containerapp','job','create',
        '--name',$Name,
        '--resource-group',$ResourceGroup,
        '--environment',$Environment,
        '--trigger-type','Schedule',
        '--replica-timeout',"$ReplicaTimeout",
        '--replica-retry-limit','0',
        '--replica-completion-count','1',
        '--parallelism','1',
        '--cron-expression',$Cron,
        '--image',$Image,
        '--registry-server',$LoginServer,
        '--cpu',$Cpu,
        '--memory',$Memory,
        '--output','none'
    )
}

# The application permissions the engines USE, read only. Derived from the earlier permission script's catalog (the SPN's
# required catalog) and the engine code: /users, /devices, /groups/{id}/transitiveMembers, /servicePrincipals (+
# appRoleAssignments, oauth2PermissionGrants), /directoryObjects/getByIds, /directory/deletedItems,
# /roleManagement/directory/*, /identityGovernance/privilegedAccess/group/*, /reports/authenticationMethods/*,
# /users/{id}/authentication/methods (passwordless-only accounts, UserAuthenticationMethod.Read.All -- read only, #549),
# /security/runHuntingQuery, api.securitycenter.microsoft.com/api/machines, api.securitycenter.microsoft.com/api/vulnerabilities (the exploit
# details of a CVE for the vulnerability findings, Vulnerability.Read.All -- read only), api.securitycenter.microsoft.com/api/recommendations (the exposure impact
# and active alert of a Defender recommendation, SecurityRecommendation.Read.All -- read only), /deviceManagement/managedDevices (Intune serial numbers and
# MAC addresses for the full asset details, DeviceManagementManagedDevices.Read.All -- read only),
# /deviceManagement/deviceCompliancePolicies and /deviceManagement/deviceConfigurations (which compliance policies a device does
# not meet, its update ring, DeviceManagementConfiguration.Read.All -- read only),
# /identityGovernance/accessReviews/definitions (the last access review of a privileged role, group or application,
# AccessReview.Read.All -- read only), /security/alerts_v2 (the OPEN alerts per device: how many, the highest severity,
# the newest one -- SecurityAlert.Read.All -- read only), /security/secureScores (the latest Microsoft Secure Score for the
# hourly status report, SecurityEvents.Read.All -- read only, owner 2026-10-16) and api.securitycenter.microsoft.com/api/exposureScore
# (the Defender exposure score for the same report, Score.Read.All -- read only).
# LOCKED: READ ONLY AT COLLECTION. Machine.Read.All, never Machine.ReadWrite.All. Tag WRITES belong to the asset-tagging
# job (caj-si-asset-tagging, #236), which runs under its OWN user-assigned identity with its own, opt-in grant plan
# (Get-SIAssetTaggingIdentityGrantPlan below) -- never under this collection identity. Nothing here may contain Write.
$script:SIContainerIdentityAppRoles = @(
    [pscustomobject]@{ Resource = 'Microsoft Graph'; ResourceAppId = '00000003-0000-0000-c000-000000000000'; Roles = @(
        'User.Read.All', 'Group.Read.All', 'Directory.Read.All', 'Device.Read.All', 'Application.Read.All',
        'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.All', 'RoleManagement.Read.Directory',
        'RoleManagementPolicy.Read.Directory', 'RoleEligibilitySchedule.Read.Directory', 'RoleAssignmentSchedule.Read.Directory',
        'PrivilegedAccess.Read.AzureADGroup', 'IdentityRiskyUser.Read.All', 'IdentityRiskEvent.Read.All',
        'IdentityRiskyServicePrincipal.Read.All', 'ThreatHunting.Read.All', 'UserAuthenticationMethod.Read.All', 'DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All', 'AccessReview.Read.All', 'SecurityAlert.Read.All', 'SecurityEvents.Read.All') }
    [pscustomobject]@{ Resource = 'Microsoft Threat Protection'; ResourceAppId = '8ee8fdad-f234-4243-8f3b-15c294843740'; Roles = @('AdvancedHunting.Read.All') }
    [pscustomobject]@{ Resource = 'WindowsDefenderATP'; ResourceAppId = 'fc780465-2017-40d4-a0c5-307022471b92'; Roles = @('Machine.Read.All', 'Vulnerability.Read.All', 'SecurityRecommendation.Read.All', 'Score.Read.All') }
)

function Get-SIEnvironmentLogSettingBody {
    <#
        PURE (#220). The diagnostic setting that sends a Container Apps environment's console + system logs to the
        install's own SI workspace (the environment is created with --logs-destination azure-monitor, so no workspace
        key is ever handed to it, and Azure does not create a stray workspace of its own).
    #>
    param([Parameter(Mandatory)][string]$WorkspaceResourceId)
    @{ properties = @{ workspaceId = $WorkspaceResourceId; logs = @(
        @{ category = 'ContainerAppConsoleLogs'; enabled = $true },
        @{ category = 'ContainerAppSystemLogs'; enabled = $true }) } } | ConvertTo-Json -Depth 5 -Compress
}

function Get-SIContainerRaMailPlan {
    <#
        PURE (#218). Does the customer's config switch Risk Analysis mail ON, and does that mail need the SMTP password?
        Mail is wanted when any send switch is true -- the per-mode ones (RiskAnalysis_Summary_SendMail /
        RiskAnalysis_Detailed_SendMail, and their legacy Mail_SecurityInsight_* names) or the global SendMail.
        Authenticated SMTP (Mail_SendAnonymous not true) needs the password, which never travels as a plain setting:
        without it the Risk Analysis engine refuses to start ("SMTP PRE-FLIGHT FAILED").
        Returns @{ Wanted; NeedsPassword }.
    #>
    param([hashtable]$Globals = @{})
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    $wanted = $false
    foreach ($n in 'RiskAnalysis_Summary_SendMail', 'RiskAnalysis_Detailed_SendMail',
                   'Mail_SecurityInsight_Summary_SendMail', 'Mail_SecurityInsight_Detailed_SendMail', 'SendMail') {
        $v = & $g $n
        if ($null -ne $v -and "$v" -ne '' -and "$v" -notin '0', 'false', 'False', 'no') { if ([bool]$v) { $wanted = $true } }
    }
    $anon = & $g 'Mail_SendAnonymous'
    $isAnon = ($null -ne $anon -and "$anon" -in '1', 'true', 'True', 'yes') -or ($anon -is [bool] -and $anon)
    # MAIL-1: only an SMTP relay has a password; the shared mailbox (Graph, the job's identity) and 'none' never do
    $notSmtp = "$(& $g 'SI_Mail_Mode')".Trim() -match '^(?i)(sharedmailbox|shared|graph|none|off|disabled)$'
    [pscustomobject]@{ Wanted = $wanted; NeedsPassword = ($wanted -and -not $isAnon -and -not $notSmtp) }
}

function Get-SICloseLoopMailSchedule {
    <#
        PURE. The close-loop daily mail job's cron, from Mail_CloseLoop_Daily_SendTimeUtc (HH:mm, UTC). Empty -> 10:45,
        after the close-loop (10:00) and the data backend sync (10:30). A value that is not HH:mm -> 10:45 too, with the
        reason in Note so setup can say so. Returns @{ Cron; TimeUtc; Note }.
    #>
    param([AllowNull()][AllowEmptyString()][string]$SendTimeUtc)
    $t = "$SendTimeUtc".Trim()
    $note = ''
    if ($t -notmatch '^([01][0-9]|2[0-3]):([0-5][0-9])$') {
        if ($t) { $note = ("Mail_CloseLoop_Daily_SendTimeUtc '{0}' is not a time of day as HH:mm (UTC) -- using 10:45" -f $t) }
        $t = '10:45'
        [void]($t -match '^([01][0-9]|2[0-3]):([0-5][0-9])$')
    }
    $cron = '{0} {1} * * *' -f [int]$Matches[2], [int]$Matches[1]
    [pscustomobject]@{ Cron = $cron; TimeUtc = $t; Note = $note }
}

function Get-SIContainerCloseLoopMailPlan {
    <#
        PURE. What setup wires for the close-loop daily mail job, from the customer's config (-Globals).
          Wanted        -- Mail_CloseLoop_Daily_SendMail is on in the config. (The switch may also be turned on later in
                           the web app, which setup does not read -- so the relay is wired whenever it is configured.)
          NeedsPassword -- an SMTP server is configured and the relay is not anonymous: the job then gets the SMTP
                           password as a Key Vault reference, exactly as the Risk Analysis jobs do.
          Schedule      -- Get-SICloseLoopMailSchedule of Mail_CloseLoop_Daily_SendTimeUtc.
    #>
    param([hashtable]$Globals = @{})
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    $on = & $g 'Mail_CloseLoop_Daily_SendMail'
    $wanted = ($on -is [bool] -and $on) -or ("$on".Trim() -in '1', 'true', 'True', 'yes')
    $anon = & $g 'Mail_SendAnonymous'
    $isAnon = ($anon -is [bool] -and $anon) -or ("$anon".Trim() -in '1', 'true', 'True', 'yes')
    $hasSmtp = -not [string]::IsNullOrWhiteSpace([string](& $g 'SmtpServer'))
    # MAIL-1: only an SMTP relay has a password; the shared mailbox (Graph, the job's identity) and 'none' never do
    if ("$(& $g 'SI_Mail_Mode')".Trim() -match '^(?i)(sharedmailbox|shared|graph|none|off|disabled)$') { $hasSmtp = $false }
    [pscustomobject]@{ Wanted = [bool]$wanted; NeedsPassword = ($hasSmtp -and -not $isAnon)
                       Schedule = (Get-SICloseLoopMailSchedule -SendTimeUtc ([string](& $g 'Mail_CloseLoop_Daily_SendTimeUtc'))) }
}

function Get-SIKeyVaultSecretArg {
    <#
        PURE. A job secret '<Alias>=...': a Key Vault REFERENCE resolved by the job's identity when a vault and an
        identity are known -- the value never passes through setup; else the configured value, as before; else $null
        (the engine then runs without the feature and says so). Used for the Shodan key (#185) and the Azure OpenAI
        key (#215): setup cannot read either value -- the config pulls them through a platform context setup does not have.
    #>
    param([Parameter(Mandatory)][string]$Alias, [string]$VaultUri, [string]$SecretName, [string]$IdentityResourceId, [string]$Value)
    if (-not [string]::IsNullOrWhiteSpace($VaultUri) -and -not [string]::IsNullOrWhiteSpace($IdentityResourceId) -and -not [string]::IsNullOrWhiteSpace($SecretName)) {
        $u = if ($VaultUri.EndsWith('/')) { $VaultUri } else { $VaultUri + '/' }
        return ('{0}=keyvaultref:{1}secrets/{2},identityref:{3}' -f $Alias, $u, $SecretName, $IdentityResourceId)
    }
    if (-not [string]::IsNullOrWhiteSpace($Value)) { return ('{0}={1}' -f $Alias, $Value) }
    $null
}

function Get-SIShodanSecretArg {
    <# PURE. The publicip job's `shodan-key` secret (#185) -- see Get-SIKeyVaultSecretArg. #>
    param([string]$VaultUri, [string]$SecretName = 'SI-Shodan-ApiKey', [string]$IdentityResourceId, [string]$Value)
    Get-SIKeyVaultSecretArg -Alias 'shodan-key' -VaultUri $VaultUri -SecretName $SecretName -IdentityResourceId $IdentityResourceId -Value $Value
}

function Resolve-SIJobKeyVaultSecret {
    <#
        PURE. A job secret that is a Key Vault REFERENCE only when the secret is actually IN the vault. Container Apps
        resolves every reference when the job is created or updated, so a reference to a secret the vault does not hold
        fails the whole job (live 2026-10-06: a new install's vault had no Shodan key -- an optional paid entitlement --
        and caj-si-publicip was never created).
          -VaultSecretNames  the names the vault holds; $null = they could not be read from here (unknown).
          -Required          the job cannot run without it: absent = a clear failure (throw), never a broken job.
        Returns @{ SecretArg; Status = Reference | Value | Omitted; Message }. Omitted = the job runs without the
        feature and the engine says so in its log; Message says why, for setup to print.
    #>
    param([Parameter(Mandatory)][string]$Alias, [string]$VaultName, [string]$VaultUri, [string]$SecretName,
          [string]$IdentityResourceId, [string]$Value, [AllowNull()][string[]]$VaultSecretNames, [switch]$Required,
          [string]$Feature = $Alias)
    $haveRef = -not [string]::IsNullOrWhiteSpace($VaultUri) -and -not [string]::IsNullOrWhiteSpace($IdentityResourceId) -and -not [string]::IsNullOrWhiteSpace($SecretName)
    $haveValue = -not [string]::IsNullOrWhiteSpace($Value)
    $vaultLabel = if ($VaultName) { $VaultName } else { $VaultUri }
    $why = $null
    if ($haveRef) {
        # Key Vault secret names are case-insensitive; -contains on strings is too.
        $known = ($null -ne $VaultSecretNames)
        if ($known -and (@($VaultSecretNames) -contains $SecretName)) {
            return [pscustomobject]@{ SecretArg = (Get-SIKeyVaultSecretArg -Alias $Alias -VaultUri $VaultUri -SecretName $SecretName -IdentityResourceId $IdentityResourceId); Status = 'Reference'; Message = $null }
        }
        if (-not $known -and $Required) {
            # A required secret whose presence cannot be checked from here keeps its reference: the job's own
            # identity may read what setup cannot, and Container Apps reports the reference if it is wrong.
            return [pscustomobject]@{ SecretArg = (Get-SIKeyVaultSecretArg -Alias $Alias -VaultUri $VaultUri -SecretName $SecretName -IdentityResourceId $IdentityResourceId); Status = 'Reference'
                Message = ("could not list the secrets of Key Vault '{0}' from here -- '{1}' ({2}) is referenced unchecked." -f $vaultLabel, $SecretName, $Feature) }
        }
        $why = if ($known) { "Key Vault '{0}' holds no secret '{1}'" -f $vaultLabel, $SecretName }
               else { "the secrets of Key Vault '{0}' could not be listed from here, so '{1}' could not be confirmed" -f $vaultLabel, $SecretName }
    } else {
        $why = if ([string]::IsNullOrWhiteSpace($VaultUri)) { 'no Key Vault is known for it' } else { 'the jobs have no identity to read the Key Vault with' }
    }
    if ($haveValue) { return [pscustomobject]@{ SecretArg = ('{0}={1}' -f $Alias, $Value); Status = 'Value'; Message = $null } }
    if ($Required) {
        throw ("{0} is required, but {1} and no value is configured. Store it in Key Vault secret '{2}' (vault '{3}') and re-run setup." -f $Feature, $why, $SecretName, $vaultLabel)
    }
    [pscustomobject]@{ SecretArg = $null; Status = 'Omitted'
        Message = ("{0}: {1} -- the job is set up without it and runs without {0} (its log says so). Store the secret and re-run setup to add it." -f $Feature, $why) }
}

function Get-SIContainerIdentityGrantPlan {
    <#
        PURE. What the jobs' identity must hold. Returns one row per grant:
          @{ Kind = 'AzureRole'; Role; Scope; Why }  or  @{ Kind = 'AppRole'; Role; Resource; ResourceAppId; Why }
        ManagedIdentity -- the identity IS the engine: Reader at the collection scope(s), Monitoring Metrics Publisher
                           on the DCR resource group, Log Analytics Reader on the workspace(s), the storage data roles
                           on SI's own account, and the read-only application permissions above.
        Certificate     -- the identity only resolves the PFX reference: Key Vault Secrets User on that vault. The
                           SPN keeps the grants it already has.
        A scope that is not known is left out (and the caller says so).
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('ManagedIdentity', 'Certificate')][string]$Mode,
        [string[]]$ReaderScopes = @(),
        [string]$DcrResourceGroupId,
        [string]$WorkspaceResourceId,
        [string]$DefenderWorkspaceResourceId,
        [string]$StorageAccountId,
        [string]$KeyVaultId,
        [string]$AcrRegistryId,
        [string]$ShodanKeyVaultId,
        [string]$OpenAIKeyVaultId,
        [string]$SmtpKeyVaultId,
        [string]$LicenceKeyVaultId,
        # KEDA worker jobs: the queue scaler signs in as the identity, so in Certificate mode (where the identity
        # otherwise only resolves the PFX) it needs to read the shard queues too. ManagedIdentity already has it.
        [switch]$KedaQueueScaler
    )
    $plan = New-Object System.Collections.Generic.List[object]
    # #185 / #215 / #218: the identity resolves the Shodan key, the Azure OpenAI key and the SMTP password references
    # (both modes). One grant per vault: a vault that is also the certificate vault is granted below with it.
    # The licence: the Pro engines read the SI-License secret from the install's vault at run time, so a renewed or
    # replaced licence is in force on the next run (a copy in the job went stale -- found live 2026-10-03).
    $kvSeen = @($KeyVaultId)
    foreach ($kv in @(@{ Id = $ShodanKeyVaultId; Why = 'resolve the Shodan key (Key Vault reference) when the publicip job starts' },
                      @{ Id = $OpenAIKeyVaultId; Why = 'resolve the Azure OpenAI key (Key Vault reference) for AI classification' },
                      @{ Id = $SmtpKeyVaultId;   Why = 'resolve the SMTP password (Key Vault reference) for the Risk Analysis and close-loop mail' },
                      @{ Id = $LicenceKeyVaultId; Why = 'read the SecurityInsight licence (SI-License) when a job starts' })) {
        if ($kv.Id -and $kvSeen -notcontains $kv.Id) { $kvSeen += $kv.Id; $plan.Add([pscustomobject]@{ Kind = 'AzureRole'; Role = 'Key Vault Secrets User'; Scope = $kv.Id; Why = $kv.Why }) }
    }
    $grant = { param($role, $scope, $why) if (-not [string]::IsNullOrWhiteSpace($scope)) { $plan.Add([pscustomobject]@{ Kind = 'AzureRole'; Role = $role; Scope = $scope; Why = $why }) } }
    if ($Mode -eq 'Certificate') {
        & $grant 'Key Vault Secrets User' $KeyVaultId 'resolve the SPN certificate (Key Vault reference) when the job starts'
        if ($KedaQueueScaler) { & $grant 'Storage Queue Data Reader' $StorageAccountId 'the queue scaler reads the shard queue length (no storage key)' }
        return $plan.ToArray()
    }
    # The jobs pull their image AS the identity -- no registry password (admin access may be disabled).
    & $grant 'AcrPull' $AcrRegistryId 'pull the engine image from the registry'
    foreach ($s in @($ReaderScopes | Where-Object { $_ } | Select-Object -Unique)) { & $grant 'Reader' $s 'enumerate Azure resources (Resource Graph) and resolve the workspace / DCR / DCE' }
    & $grant 'Monitoring Metrics Publisher' $DcrResourceGroupId 'send rows through the SI data collection rules'
    & $grant 'Log Analytics Reader' $WorkspaceResourceId 'Risk Analysis, trend, correlation and properties query the SI tables'
    if ($DefenderWorkspaceResourceId -and $DefenderWorkspaceResourceId -ne $WorkspaceResourceId) {
        & $grant 'Log Analytics Reader' $DefenderWorkspaceResourceId 'query the Defender / Sentinel workspace'
    }
    foreach ($r in 'Storage Blob Data Contributor', 'Storage Queue Data Contributor', 'Storage Table Data Contributor') {
        & $grant $r $StorageAccountId "SI's own run state: fingerprint cache, staging, run logs, shard queue"
    }
    foreach ($res in $script:SIContainerIdentityAppRoles) {
        foreach ($role in $res.Roles) {
            $plan.Add([pscustomobject]@{ Kind = 'AppRole'; Role = $role; Resource = $res.Resource; ResourceAppId = $res.ResourceAppId; Why = 'read-only collection' })
        }
    }
    return $plan.ToArray()
}

# ==================================================================================================================
#  ASSET TAGGING'S OWN IDENTITY (#236)
# ==================================================================================================================
# The asset-tagging job is the ONE SecurityInsight job that writes to the customer's tenant, so it never runs as the
# collection identity above: it gets its own user-assigned identity (default 'uami-securityinsight-tagging') and this
# plan. Its WRITE permissions are exactly the three the engine uses, and nothing else:
#   * Defender for Endpoint Machine.ReadWrite.All -- machine tags (POST /api/machines/{id}/tags, AddOrRemoveTagForMultipleMachines)
#   * Tag Contributor at the configured tagging scope(s) -- Azure resource tags (a merge of the tags, over REST)
#   * Microsoft Graph CustomSecAttributeAssignment.ReadWrite.All -- Entra custom security attributes (PATCH on
#     /users/{id} and /servicePrincipals/{id}; the KustoCL rules)
# Its read permissions are what the rules' queries need: Resource Graph (Reader), advanced hunting
# (ThreatHunting.Read.All), the identities the attributes are set on (User.Read.All, Application.Read.All), and the SI
# workspace for KustoCL rules (Log Analytics Reader). Its activity rows and run log go to SI's OWN workspace and storage
# (Monitoring Metrics Publisher on the DCR resource group, Storage Blob Data Contributor on SI's storage account).
# OPT-IN: setup grants this plan only when asked (Bootstrap-ContainerAppJob.ps1 -GrantTaggingRoles,
# setup\Grant-SIIdentity.ps1 -Tagging -Apply); without it the job can only report.
$script:SIAssetTaggingIdentityAppRoles = @(
    [pscustomobject]@{ Resource = 'Microsoft Graph'; ResourceAppId = '00000003-0000-0000-c000-000000000000'
        Roles = @('ThreatHunting.Read.All', 'User.Read.All', 'Application.Read.All', 'CustomSecAttributeAssignment.ReadWrite.All') }
    [pscustomobject]@{ Resource = 'WindowsDefenderATP'; ResourceAppId = 'fc780465-2017-40d4-a0c5-307022471b92'; Roles = @('Machine.ReadWrite.All') }
)
# The write permissions in that plan -- the ONLY ones it may hold (the tests assert it, and that the collection plan holds none).
$script:SIAssetTaggingWriteGrants = @('Tag Contributor', 'Machine.ReadWrite.All', 'CustomSecAttributeAssignment.ReadWrite.All')

function Get-SIAssetTaggingIdentityGrantPlan {
    <#
        PURE (#236). What the asset-tagging job's OWN identity must hold -- the same row shape as
        Get-SIContainerIdentityGrantPlan. -TaggingScopes: where Azure tags may be written (Tag Contributor); default the
        -ReaderScopes. A scope that is not known is left out (the caller says so).
    #>
    param(
        [string[]]$ReaderScopes = @(),
        [string[]]$TaggingScopes = @(),
        [string]$DcrResourceGroupId,
        [string]$WorkspaceResourceId,
        [string]$StorageAccountId,
        [string]$AcrRegistryId,
        [string]$LicenceKeyVaultId
    )
    $plan = New-Object System.Collections.Generic.List[object]
    # Write = $true marks the rows that let the job WRITE (fix request 85bd728f): setup grants every other row always -- the
    # job reports what it would tag from day one -- and the writes only on request (-GrantTaggingRoles / Grant-SIIdentity -Tagging).
    $grant = { param($role, $scope, $why) if (-not [string]::IsNullOrWhiteSpace($scope)) { $plan.Add([pscustomobject]@{ Kind = 'AzureRole'; Role = $role; Scope = $scope; Why = $why; Write = ($script:SIAssetTaggingWriteGrants -contains $role) }) } }
    & $grant 'AcrPull' $AcrRegistryId 'pull the engine image from the registry'
    & $grant 'Key Vault Secrets User' $LicenceKeyVaultId 'asset tagging: read the SecurityInsight licence (SI-License) when the job starts'
    $readers = @($ReaderScopes | Where-Object { $_ } | Select-Object -Unique)
    foreach ($s in $readers) { & $grant 'Reader' $s 'asset tagging: run the Resource Graph rules' }
    $tagScopes = @($TaggingScopes | Where-Object { $_ } | Select-Object -Unique)
    if (-not $tagScopes.Count) { $tagScopes = $readers }
    foreach ($s in $tagScopes) { & $grant 'Tag Contributor' $s 'asset tagging: WRITE Azure resource tags (only when SI_Pro_AssetTagging_Apply is on)' }
    & $grant 'Log Analytics Reader' $WorkspaceResourceId 'asset tagging: run the KustoCL rules against the SI tables'
    & $grant 'Monitoring Metrics Publisher' $DcrResourceGroupId 'asset tagging: send the activity rows (planned and executed writes) to SI''s workspace'
    & $grant 'Storage Blob Data Contributor' $StorageAccountId 'asset tagging: keep the run log in SI''s own storage'
    foreach ($res in $script:SIAssetTaggingIdentityAppRoles) {
        foreach ($role in $res.Roles) {
            $why = if ($script:SIAssetTaggingWriteGrants -contains $role) { 'asset tagging: WRITE (only when SI_Pro_AssetTagging_Apply is on)' } else { 'asset tagging: read what the rules query' }
            $plan.Add([pscustomobject]@{ Kind = 'AppRole'; Role = $role; Resource = $res.Resource; ResourceAppId = $res.ResourceAppId; Why = $why; Write = ($script:SIAssetTaggingWriteGrants -contains $role) })
        }
    }
    return $plan.ToArray()
}

# #446: what the Pro web app's OWN identity (uami-si-management) reads in Entra -- READ ONLY: the names on the Access page,
# the people picker (users and groups by name), group membership when a sign-in token lists too many groups, and who
# holds a role on the enterprise application "SecurityInsight Management" (shown on Access, counted by Get Started).
$script:SIWebAppIdentityAppRoles = @(
    [pscustomobject]@{ Resource = 'Microsoft Graph'; ResourceAppId = '00000003-0000-0000-c000-000000000000'
        Roles = @('User.ReadBasic.All', 'GroupMember.Read.All', 'Application.Read.All') }
)

function Get-SIWebAppIdentityGrantPlan {
    <# PURE (#446). The Pro web app identity's Microsoft Graph application permissions -- the same row shape as
       Get-SIContainerIdentityGrantPlan; all read only. #>
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($res in $script:SIWebAppIdentityAppRoles) {
        foreach ($role in $res.Roles) {
            $why = switch ($role) { 'User.ReadBasic.All' { 'the web app: people''s names, and finding a person by name' } 'GroupMember.Read.All' { 'the web app: group names and members (sign-in, Access)' } default { 'the web app: who holds a role on the enterprise application' } }
            $plan.Add([pscustomobject]@{ Kind = 'AppRole'; Role = $role; Resource = $res.Resource; ResourceAppId = $res.ResourceAppId; Why = $why })
        }
    }
    return $plan.ToArray()
}

# ==================================================================================================================
#  #269 -- the ServiceNow jobs exist only where ServiceNow is configured; the daily job flow
# ==================================================================================================================
function Test-SIBootstrapTruthy { param($Value) if ($null -eq $Value) { return $false }; if ($Value -is [bool]) { return $Value }; ("$Value".Trim().Trim('$').ToLowerInvariant()) -in @('true', '1', 'yes', 'on') }

function Get-SIServiceNowJobPlan {
    <#
        PURE. Whether this install gets the two ServiceNow jobs (operator 2026-10-04: "i need service for ServiceNow CMDB
        Connector" / "one for sql connector and one for servicenow"):
          asset-cmdb                          -- the ServiceNow CMDB connector (creates / updates CIs): -Cmdb, or
                                                 SI_Bootstrap_ServiceNowCmdb, or SI_EnableServiceNowCmdb, or SI_Cmdb_Run = apply;
          asset-vulnerabilities-servicenow    -- the ServiceNow VULNERABILITY connector: -Vulnerabilities, or
                                                 SI_Bootstrap_ServiceNowVulnerabilities, or SI_VulnSync_Target = ServiceNow,
                                                 or SI_VulnSync_ServiceNowTable set.
        Setup does not read the Pro database, so a ServiceNow connector kept only in cfg.Connector is named with the switch
        (or the SI_Bootstrap_* setting). Returns @{ Cmdb = @{ Deploy; Why }; Vulnerabilities = @{ Deploy; Why } }.
    #>
    param([hashtable]$Globals = @{}, [bool]$Cmdb, [bool]$Vulnerabilities)
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    $c = if ($Cmdb) { 'asked for (-ServiceNowCmdb)' } elseif (Test-SIBootstrapTruthy (& $g 'SI_Bootstrap_ServiceNowCmdb')) { 'SI_Bootstrap_ServiceNowCmdb' }
         elseif (Test-SIBootstrapTruthy (& $g 'SI_EnableServiceNowCmdb')) { 'SI_EnableServiceNowCmdb' }
         elseif ("$(& $g 'SI_Cmdb_Run')".Trim().ToLowerInvariant() -eq 'apply') { "SI_Cmdb_Run = 'apply'" } else { '' }
    $v = if ($Vulnerabilities) { 'asked for (-ServiceNowVulnerabilities)' } elseif (Test-SIBootstrapTruthy (& $g 'SI_Bootstrap_ServiceNowVulnerabilities')) { 'SI_Bootstrap_ServiceNowVulnerabilities' }
         elseif ("$(& $g 'SI_VulnSync_Target')".Trim() -ieq 'ServiceNow') { "SI_VulnSync_Target = 'ServiceNow'" }
         elseif ("$(& $g 'SI_VulnSync_ServiceNowTable')".Trim()) { 'SI_VulnSync_ServiceNowTable' } else { '' }
    [pscustomobject]@{
        Cmdb            = [pscustomobject]@{ Deploy = [bool]$c; Why = $(if ($c) { $c } else { 'no ServiceNow CMDB connector is configured (SI_EnableServiceNowCmdb, -ServiceNowCmdb)' }) }
        Vulnerabilities = [pscustomobject]@{ Deploy = [bool]$v; Why = $(if ($v) { $v } else { "no ServiceNow vulnerability connector is configured (SI_VulnSync_Target = 'ServiceNow', -ServiceNowVulnerabilities)" }) }
    }
}

function Get-SIBootstrapJobName {
    <# PURE. The Container Apps job name of an engine (max 32 characters) -- the same short aliases Bootstrap uses. #>
    param([Parameter(Mandatory)][string]$Engine)
    $short = switch ($Engine) {
        'privilege-tier-classifier'        { 'ptc' }
        'schema-discovery'                 { 'schema' }
        'templates-publish'                { 'templates' }
        'asset-vulnerabilities-servicenow' { 'asset-vulns-servicenow' }
        default                            { $Engine }
    }
    'caj-si-' + $short
}

function Select-SIBootstrapServiceNowEngines {
    <#
        PURE. The engine list without the ServiceNow jobs this install does not use -- unless the job already exists (an
        install is never stripped of a job it has; Bootstrap never deletes). @{ Engines; Skipped = @(@{ Engine; Why }) }.
    #>
    param([string[]]$Engines = @(), [Parameter(Mandatory)]$Plan, [string[]]$ExistingJobs = @())
    $skipped = New-Object System.Collections.Generic.List[object]
    $keep = New-Object System.Collections.Generic.List[string]
    foreach ($e in $Engines) {
        $p = $null
        if ($e -eq 'asset-cmdb') { $p = $Plan.Cmdb } elseif ($e -eq 'asset-vulnerabilities-servicenow') { $p = $Plan.Vulnerabilities }
        if (-not $p -or $p.Deploy -or $ExistingJobs -contains (Get-SIBootstrapJobName -Engine $e)) { $keep.Add($e); continue }
        $skipped.Add([pscustomobject]@{ Engine = $e; Why = $p.Why })
    }
    [pscustomobject]@{ Engines = $keep.ToArray(); Skipped = $skipped.ToArray() }
}

function Get-SIBootstrapJobEnvArgs {
    <#
        PURE. The env vars that make one job THE job it is, beyond SI_ENGINE: the ServiceNow vulnerability job runs the
        vulnerability engine for the ServiceNow connectors, the SQL one for the SQL (and REST) connectors; the flow job
        knows where the jobs it starts are. Returns @{ SiEngine; EnvArgs }.
    #>
    param([Parameter(Mandatory)][string]$Engine, [string]$SubscriptionId, [string]$ResourceGroup)
    switch ($Engine) {
        'asset-vulnerabilities'            { return [pscustomobject]@{ SiEngine = 'asset-vulnerabilities'; EnvArgs = @('SI_VULN_TARGET=Sql') } }
        'asset-vulnerabilities-servicenow' { return [pscustomobject]@{ SiEngine = 'asset-vulnerabilities'; EnvArgs = @('SI_VULN_TARGET=ServiceNow') } }
        'flow'                             { return [pscustomobject]@{ SiEngine = 'flow'; EnvArgs = @(('SI_FLOW_SUBSCRIPTIONID={0}' -f $SubscriptionId), ('SI_FLOW_RESOURCEGROUP={0}' -f $ResourceGroup)) } }
        default                            { return [pscustomobject]@{ SiEngine = $Engine; EnvArgs = @() } }
    }
}

function Get-SIBootstrapJobGuardEnvArgs {
    <# PURE (SCHED-1.1). Where every job finds its own executions -- the execution guard asks ARM whether an earlier
       execution of the same job is still running. #>
    param([string]$SubscriptionId, [string]$ResourceGroup)
    @(('SI_JOBS_SUBSCRIPTIONID={0}' -f $SubscriptionId), ('SI_JOBS_RESOURCEGROUP={0}' -f $ResourceGroup))
}

function Get-SIBootstrapTriggerPlan {
    <#
        PURE. How Bootstrap CREATES a job's trigger. An EXISTING job's trigger is never changed by setup -- Operations > Jobs'
        mode switch and setup\Switch-SIJobOrchestration.ps1 own that.
          flow mode:      a job of the flow -> Manual, its timer remembered in the si-disabled-cron tag (leaving the flow
                          restores it); caj-si-flow -> Schedule at the flow's start time;
          schedules mode: every job on its own timer; caj-si-flow -> Manual with the flow's time remembered.
        A job that is never in the flow (templates, schema discovery, asset tagging) keeps its timer. @{ Trigger; RememberCron }.
    #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][ValidateSet('flow', 'schedules')][string]$Mode, [string]$Cron, $Map)
    $key = (Get-SIBootstrapJobName -Engine $Engine).Substring(7)
    if ($Engine -eq 'flow') {
        if ($Mode -eq 'flow') { return [pscustomobject]@{ Trigger = 'Schedule'; RememberCron = '' } }
        return [pscustomobject]@{ Trigger = 'Manual'; RememberCron = $Cron }
    }
    $inFlow = $false
    if ($Map -and $Map.Jobs.Contains($key)) { $inFlow = (-not $Map.Jobs[$key].NeverInFlow) -and ($Map.DefaultFlow -contains $key) }
    # #306: the risk trend is written by Risk Analysis while the jobs run as a pipeline -- its job waits (runnable by hand)
    if ($Map -and $Map.Jobs.Contains($key) -and $Map.Jobs[$key].PSObject.Properties['ManualInFlowMode'] -and $Map.Jobs[$key].ManualInFlowMode) { $inFlow = $true }
    if ($Mode -eq 'flow' -and $inFlow) { return [pscustomobject]@{ Trigger = 'Manual'; RememberCron = $Cron } }
    [pscustomobject]@{ Trigger = 'Schedule'; RememberCron = '' }
}

function ConvertTo-SIManualCreateArgs {
    <#
        PURE (#269). `az containerapp job create` arguments for a Schedule job turned into the same job with a MANUAL
        trigger: --trigger-type Manual, no --cron-expression, and the timer remembered in the si-disabled-cron tag (the
        tag the web app's Disable / Enable and the flow's leave-the-flow read). Everything else is kept as it was.
    #>
    param([Parameter(Mandatory)][object[]]$CreateArgs, [string]$RememberCron)
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $CreateArgs.Count; $i++) {
        $a = $CreateArgs[$i]
        if ($a -eq '--cron-expression') { $i++; continue }
        if ($a -eq '--trigger-type') { $out.Add('--trigger-type'); $out.Add('Manual'); $i++; continue }
        $out.Add($a)
    }
    if ($RememberCron) { $out.Add('--tags'); $out.Add(('si-disabled-cron={0}' -f $RememberCron)) }
    , $out.ToArray()
}

function Get-SIJobExecutionOverlap {
    <#
        PURE (SCHED-1.1, #269). A job started by its own cron fires on the clock, whatever the last run is doing: this is
        the EXECUTION GUARD. From the job's executions (ARM list: name, properties.status, properties.startTime) and this
        execution's name, the OTHER execution of the same job that is still active (Running / Processing) and started
        before this one -- then this execution starts nothing ("skipped: previous still running"). $null when there is
        none. An execution not in the list yet is fine: the list is only asked about the others.
    #>
    param([AllowEmptyCollection()][object[]]$Executions = @(), [Parameter(Mandatory)][string]$Self)
    $mine = @($Executions | Where-Object { $_ -and [string]$_.name -eq $Self })[0]
    $myStart = if ($mine -and $mine.properties.startTime) { ([datetime]$mine.properties.startTime).ToUniversalTime() } else { [datetime]::MaxValue }
    $others = @($Executions | Where-Object {
        $_ -and [string]$_.name -ne $Self -and ([string]$_.properties.status) -in @('Running', 'Processing') -and
        ((-not $_.properties.startTime) -or ([datetime]$_.properties.startTime).ToUniversalTime() -le $myStart)
    } | Sort-Object { if ($_.properties.startTime) { [datetime]$_.properties.startTime } else { [datetime]::MinValue } })
    if ($others.Count) { return $others[0] }
    $null
}

function Test-SIFlowGuardRequest {
    <#
        PURE (#946). Does this flow execution CARRY something the execution guard lets through beside a running flow
        execution? @{ Request; Cancel }: Request = a Run now (SI_FLOW_FORCE / SI_FLOW_STAGE / SI_FLOW_STEP / SI_FLOW_FROM_STEP)
        or a cancel (SI_FLOW_CANCEL); Cancel = SI_FLOW_CANCEL. A value of 0 / false / no is no request. -Get { param($Name) }:
        the environment (default: the process environment).
    #>
    param([scriptblock]$Get = { param($n) [Environment]::GetEnvironmentVariable($n) })
    $on = { param($n) $v = ([string](& $Get $n)).Trim(); [bool]($v -and $v.ToLowerInvariant() -notin @('0', 'false', 'no')) }
    $cancel = & $on 'SI_FLOW_CANCEL'
    $req = $cancel -or [bool](@('SI_FLOW_FORCE', 'SI_FLOW_STAGE', 'SI_FLOW_STEP', 'SI_FLOW_FROM_STEP') | Where-Object { & $on $_ })
    [pscustomobject]@{ Request = [bool]$req; Cancel = [bool]$cancel }
}

function Get-SIExecutionGuardDecision {
    <#
        PURE (#277 live finding, ring 1 2026-10-05). What the execution guard does with an overlap Get-SIJobExecutionOverlap
        found. @{ Action; Message }:
          Run       -- no earlier execution is running: the run goes on.
          FlowBusy  -- THE FLOW RUNNER (SI_ENGINE=flow / caj-si-flow) woke up while its previous execution still runs. It
                       wakes every 5 minutes, so this is every wake-up of a long flow run: normal operation, NOT a guard.
                       One plain INFO line; no run-health row, no guard event, no telemetry, no warning; exit 0. A start
                       that was really blocked shows up as the flow's catch-up when it runs.
          Skip      -- any other job started twice: the guard trips (skipped row + 'job.execution.previous-running').
        -FlowRequest: this flow execution CARRIES a request (Run the pipeline now / a stage / a step / from a step:
        SI_FLOW_FORCE, SI_FLOW_STAGE, SI_FLOW_STEP, SI_FLOW_FROM_STEP). It is never dropped here: it runs, and the runner's
        own lock puts the request in the queue while the other run holds the install (live 2026-10-06, Community
        rehearsal: the install's "Run the pipeline now" started 2 minutes after a 5-minute wake-up, which was still
        checking -- "this wake-up does nothing", and the first run never happened).
    #>
    param([string]$Engine, [string]$Job, $Other, [string]$Self, [switch]$FlowRequest, [switch]$FlowCancel)
    if (-not $Other) { return [pscustomobject]@{ Action = 'Run'; Message = '' } }
    $started = if ($Other.properties -and $Other.properties.startTime) { [string]$Other.properties.startTime } else { 'unknown' }
    if ($Engine -eq 'flow' -or $Job -eq 'caj-si-flow') {
        # #946 (live 2026-10-29, three installs): a CANCEL of the running run (SI_FLOW_CANCEL) is never dropped either -- it is
        # meant for the run the other execution holds; the runner's cancel stops that runner, marks the run Cancelled and
        # frees the lock (Invoke-SIPipelineCancelRun)
        if ($FlowCancel) {
            return [pscustomobject]@{ Action = 'Run'
                Message = ('[flow] another flow execution is running ({0}, started {1}); this one carries a cancel of the running run, so it goes on.' -f $Other.name, $started) }
        }
        if ($FlowRequest) {
            return [pscustomobject]@{ Action = 'Run'
                Message = ('[flow] another flow execution is running ({0}, started {1}); this one carries a request, so it goes on -- the pipeline lock queues it while that run holds the install.' -f $Other.name, $started) }
        }
        return [pscustomobject]@{ Action = 'FlowBusy'
            Message = ('[flow] the flow is still running (execution {0}, started {1}); this wake-up does nothing.' -f $Other.name, $started) }
    }
    [pscustomobject]@{ Action = 'Skip'
        Message = ('[guard] skipped: previous still running -- execution {0} of {1} (started {2}) has not finished; this execution ({3}) starts nothing.' -f $Other.name, $Job, $started, $Self) }
}

function Resolve-SIContainerSubscriptionId {
    <#
        PURE (#281). The subscription this install's Log Analytics ingest lives in -- the run-health record, the data
        collection rule and endpoint lookups. The first that has one:
          1. -AzSubscriptionId (the customer's SI_AzSubscriptionId, when a setting carried it)
          2. the subscription in -WorkspaceResourceId (/subscriptions/<sub>/resourceGroups/...) -- the global, else the
             job's SI_WORKSPACE_RESOURCEID. A new rule is created in the workspace's subscription, so this comes first.
          3. -JobsSubscriptionId (SI_JOBS_SUBSCRIPTIONID / SI_FLOW_SUBSCRIPTIONID: where the jobs run)
          4. -ContextSubscriptionId (the signed-in Az context)
        Returns '' when none has one.
    #>
    param([string]$AzSubscriptionId, [AllowEmptyCollection()][string[]]$WorkspaceResourceId = @(),
          [AllowEmptyCollection()][string[]]$JobsSubscriptionId = @(), [string]$ContextSubscriptionId)
    if (-not [string]::IsNullOrWhiteSpace($AzSubscriptionId)) { return $AzSubscriptionId.Trim() }
    foreach ($w in @($WorkspaceResourceId)) { if ("$w" -match '/subscriptions/([^/]+)/') { return $Matches[1] } }
    foreach ($j in @($JobsSubscriptionId)) { if (-not [string]::IsNullOrWhiteSpace($j)) { return $j.Trim() } }
    if (-not [string]::IsNullOrWhiteSpace($ContextSubscriptionId)) { return $ContextSubscriptionId.Trim() }
    return ''
}

function Initialize-SIContainerIngestGlobals {
    <#
        #281. THE container's env -> ingest-globals mapping, called by BOTH entry points (Start-SIInContainer.ps1,
        Start-RiskAnalysisInContainer.ps1) right after sign-in, before any engine runs or any run-health record is sent.
        Found live 2026-10-05 on ring 1: no container ever set SI_AzSubscriptionId -- on a VM it comes from the customer's
        config or the backfill at a profiler run's entry, and neither reaches a container -- so every profiler and flow run
        lost its run-health record ("Cannot bind argument to parameter 'SubscriptionId' because it is an empty string").
        And Risk Analysis kept its identity only under its own names (Spn*), so the record signed in with an EMPTY app
        id, which the ingest module answers by creating nothing ("the data collection rule ... was not found").
        Fills ONLY empty names; a value the customer's settings or the job already gave always stands. Never throws.
          SI_WorkspaceResourceId / SI_DceName / SI_DcrResourceGroup  <- SI_WORKSPACE_RESOURCEID / SI_DCE_NAME / SI_DCR_RESOURCEGROUP
          SI_AzSubscriptionId   <- Resolve-SIContainerSubscriptionId (workspace, then the jobs' subscription, then the Az context)
          SI_DceResourceGroup   <- SI_DCE_RESOURCEGROUP, else SI_DcrResourceGroup (the endpoint lives with the rules)
          SI_SPN_AppId / _TenantId / _Secret  <- SpnClientId / SpnTenantId / SpnClientSecret (Risk Analysis' names)
          SI_SPN_ObjectId       <- SI_SPN_OBJECTID
          SI_LogIngest_AppId / _TenantId / _ObjectId  <- the SI_SPN_* values
        -GetEnv: the env reader (tests pass their own); -ContextSubscriptionId: the signed-in context's subscription
        (read from Get-SIAzContext when not given). Returns what it resolved, for the run log.
    #>
    param([scriptblock]$GetEnv = { param($n) [Environment]::GetEnvironmentVariable($n) }, [string]$ContextSubscriptionId)
    $envOf = { param($n) $v = & $GetEnv $n; if ([string]::IsNullOrWhiteSpace([string]$v)) { $null } else { [string]$v } }
    try {
        if (-not $global:SI_WorkspaceResourceId) { $global:SI_WorkspaceResourceId = & $envOf 'SI_WORKSPACE_RESOURCEID' }
        if (-not $global:SI_DceName)             { $global:SI_DceName             = & $envOf 'SI_DCE_NAME' }
        if (-not $global:SI_DcrResourceGroup)    { $global:SI_DcrResourceGroup    = & $envOf 'SI_DCR_RESOURCEGROUP' }
        if (-not $global:SI_AzSubscriptionId) {
            $wsIds = @([string]$global:SI_WorkspaceResourceId, [string](& $envOf 'SI_WORKSPACE_RESOURCEID'))
            $jobSubs = @([string](& $envOf 'SI_JOBS_SUBSCRIPTIONID'), [string](& $envOf 'SI_FLOW_SUBSCRIPTIONID'))
            $sub = Resolve-SIContainerSubscriptionId -WorkspaceResourceId $wsIds -JobsSubscriptionId $jobSubs -ContextSubscriptionId $ContextSubscriptionId
            if (-not $sub) {
                # the Az context only as the last resort -- and only asked for when nothing else answered
                try {
                    if (Get-Command -Name Get-SIAzContext -ErrorAction SilentlyContinue) { $sub = [string](Get-SIAzContext -ErrorAction SilentlyContinue).Subscription.Id }
                } catch { }
            }
            if ($sub) { $global:SI_AzSubscriptionId = $sub }
        }
        if (-not $global:SI_DceResourceGroup) {
            $dceRg = & $envOf 'SI_DCE_RESOURCEGROUP'
            $global:SI_DceResourceGroup = if ($dceRg) { $dceRg } else { [string]$global:SI_DcrResourceGroup }
        }
        foreach ($p in @(@('SI_SPN_AppId', 'SpnClientId'), @('SI_SPN_TenantId', 'SpnTenantId'), @('SI_SPN_Secret', 'SpnClientSecret'))) {
            $cur = [string](Get-Variable -Name $p[0] -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
            $src = [string](Get-Variable -Name $p[1] -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
            if (-not $cur -and $src) { Set-Variable -Name $p[0] -Scope Global -Value $src }
        }
        if (-not $global:SI_SPN_ObjectId) { $o = & $envOf 'SI_SPN_OBJECTID'; if ($o) { $global:SI_SPN_ObjectId = $o } }
        if (-not $global:SI_LogIngest_AppId)    { $global:SI_LogIngest_AppId    = $global:SI_SPN_AppId }
        if (-not $global:SI_LogIngest_TenantId) { $global:SI_LogIngest_TenantId = $global:SI_SPN_TenantId }
        if (-not $global:SI_LogIngest_ObjectId) { $global:SI_LogIngest_ObjectId = $global:SI_SPN_ObjectId }
    } catch { Write-Warning ('[ingest] the Log Analytics target could not be fully resolved: {0}' -f $_.Exception.Message) }
    [pscustomobject]@{ SubscriptionId = [string]$global:SI_AzSubscriptionId; DceName = [string]$global:SI_DceName
                       DcrResourceGroup = [string]$global:SI_DcrResourceGroup; DceResourceGroup = [string]$global:SI_DceResourceGroup }
}
