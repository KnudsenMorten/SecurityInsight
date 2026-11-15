#Requires -Version 5.1
<#
    SecurityInsight -- #1257 AI WITHOUT A KEY: THE AI SETTINGS REACH THE WEB CHAT AND THE ENGINE JOBS.

    The customer turns AI on in the web app's Settings (cfg.Setting): SI_EnableAI = true, OpenAI_endpoint = the https address
    of their Azure OpenAI resource, OpenAI_deployment = the deployment name (OpenAI_apiVersion optional). No key: the web chat
    signs in as the web identity (pro-management/src/SI.Management.Core/ChatService.cs, a TokenCredential) and the engines as
    the engine identity (engine/_shared/SI-OpenAIAuth.ps1). Until this step, only setup's Deploy-SIManagement.ps1 put
    Chat__Endpoint / Chat__Deployment on the web app, and only setup put OPENAI_* on the jobs (the container never takes them
    from the database: container/_shared/SI-ContainerConfig.ps1 $script:SIConfigProtected) -- so the database settings never
    reached the chat or the engines.

    EVERY UPDATE (container/updater/Start-SIUpdater.ps1 Invoke-SIUpdaterAiSettingsStep, also in an apply-settings run):
      AI ON (SI_EnableAI true, endpoint an Azure OpenAI https address, deployment set)
        the web app      Chat__Endpoint / Chat__Deployment on its web container (the FIRST container; the sign-in front is
                         sent as read) = the settings;
        the engine jobs  (every job whose first container carries SI_ENGINE: the jobs setup gives OPENAI_*) OPENAI_ENDPOINT /
                         OPENAI_DEPLOYMENT / OPENAI_APIVERSION = the settings (the version: the setting, else the job's own,
                         else the engines' default).
      AI OFF (SI_EnableAI read and not true)
        the web app      Chat__Endpoint / Chat__Deployment removed (the chat then says "not configured");
        the engine jobs  left as they are (each engine's own switch decides there; nothing an operator set is taken away).
      AI ON BUT NOT COMPLETE (no endpoint / deployment, or an endpoint that is not an Azure OpenAI https address)
                         nothing changes; one line says what is missing.
      NOT KNOWN (the settings could not be read)
                         nothing changes; one line says so.
    Each resource: GET, the plan, ONE read-modify-write PATCH only when a value differs (so a new web revision only when the
    values change), READ BACK. Never a key, never a secret, never another variable. -WhatIf = the plan only (no PATCH).
    Never throws. ONE seam: -Arm { param([string]$Method, [string]$Path, [string]$ApiVersion, $Body) } -> the parsed answer
    (a 404 on GET: $null; anything else that is not a success THROWS). No PowerShell module.
#>

$script:SIAiSettingsArmApi = '2025-07-01'
# the engines' own fallback (engine/asset-profiling/shared/Test-SIAIEnabled.ps1 Get-SIOpenAIApiVersion)
$script:SIAiSettingsDefaultApiVersion = '2024-08-01-preview'
$script:SIAiSettingsNames = @('SI_EnableAI', 'OpenAI_endpoint', 'OpenAI_deployment', 'OpenAI_apiVersion')
$script:SIAiWebEnvNames = @('Chat__Endpoint', 'Chat__Deployment')
$script:SIAiJobEnvNames = @('OPENAI_ENDPOINT', 'OPENAI_DEPLOYMENT', 'OPENAI_APIVERSION')

if (-not (Get-Command -Name Test-SIOpenAIEndpoint -ErrorAction SilentlyContinue)) {
    $__siAiGate = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', 'asset-profiling', 'shared', 'Test-SIAIEnabled.ps1')
    if (Test-Path -LiteralPath $__siAiGate) { . $__siAiGate }
}

function Get-SIAiSettingNames { $script:SIAiSettingsNames }

function ConvertFrom-SIAiSettingValue {
    <# PURE. A cfg.Setting ValueJson ('"x"', 'true', 'null') -> its text ('' for none); text that is not JSON is taken as it is. #>
    param([AllowNull()]$Json)
    if ($null -eq $Json -or $Json -is [DBNull]) { return '' }
    $raw = "$Json".Trim()
    if (-not $raw) { return '' }
    $v = $raw; try { $v = ConvertFrom-Json -InputObject $raw -ErrorAction Stop } catch { $v = $raw }
    if ($null -eq $v) { return '' }
    "$v".Trim()
}

function ConvertFrom-SIAiSettingRows {
    <# PURE. cfg.Setting rows (Name / ValueJson; hashtables or objects) -> @{ <name> = text } for the AI settings only. #>
    param([object[]]$Rows = @())
    $out = @{}
    foreach ($r in @($Rows | Where-Object { $_ })) {
        $n = [string]$r.Name
        if ($script:SIAiSettingsNames -notcontains $n) { continue }
        $out[$n] = ConvertFrom-SIAiSettingValue $r.ValueJson
    }
    $out
}

function Get-SIAiSettingsWant {
    <#
        PURE. What the install's AI settings ask for. -Settings: @{ SI_EnableAI; OpenAI_endpoint; OpenAI_deployment;
        OpenAI_apiVersion } (text); -Known: $false when they could not be read.
        @{ State = on | off | incomplete | unknown; Endpoint; Deployment; ApiVersion; Why }.
    #>
    param([hashtable]$Settings = @{}, [bool]$Known = $true)
    if (-not $Known) { return [pscustomobject]@{ State = 'unknown'; Endpoint = ''; Deployment = ''; ApiVersion = ''; Why = 'the settings could not be read' } }
    $get = { param($n) if ($Settings.ContainsKey($n)) { "$($Settings[$n])".Trim() } else { '' } }
    $on = (& $get 'SI_EnableAI') -match '^(?i)(true|1|yes|on)$'
    $ep = & $get 'OpenAI_endpoint'; $dep = & $get 'OpenAI_deployment'; $ver = & $get 'OpenAI_apiVersion'
    if (-not $on) { return [pscustomobject]@{ State = 'off'; Endpoint = ''; Deployment = ''; ApiVersion = ''; Why = 'SI_EnableAI is not on' } }
    $miss = @()
    if (-not $ep) { $miss += 'OpenAI_endpoint' }
    if (-not $dep) { $miss += 'OpenAI_deployment' }
    if ($miss.Count) { return [pscustomobject]@{ State = 'incomplete'; Endpoint = $ep; Deployment = $dep; ApiVersion = $ver; Why = ('{0} not set' -f ($miss -join ' and ')) } }
    $why = if (Get-Command -Name Test-SIOpenAIEndpoint -ErrorAction SilentlyContinue) { [string](Test-SIOpenAIEndpoint -Endpoint $ep) } else { '' }
    if ($why) { return [pscustomobject]@{ State = 'incomplete'; Endpoint = $ep; Deployment = $dep; ApiVersion = $ver; Why = ('OpenAI_endpoint is not used: {0}' -f $why) } }
    [pscustomobject]@{ State = 'on'; Endpoint = $ep.TrimEnd('/'); Deployment = $dep; ApiVersion = $ver; Why = '' }
}

function Get-SIAiFirstContainerEnv {
    <# PURE. The env list of the first container of an app's / job's template (ARM shape), @() when none. #>
    param($Resource)
    if ($null -eq $Resource -or -not $Resource.PSObject.Properties['properties'] -or $null -eq $Resource.properties.template) { return @() }
    $c = @($Resource.properties.template.containers | Where-Object { $_ })[0]
    if ($null -eq $c -or -not $c.PSObject.Properties['env']) { return @() }
    @($c.env | Where-Object { $null -ne $_ })
}

function Test-SIAiEngineJob {
    <# PURE. An engine job: its first container carries SI_ENGINE (the jobs setup gives OPENAI_* to). #>
    param($Job)
    [bool](@(Get-SIAiFirstContainerEnv -Resource $Job | Where-Object { [string]$_.name -eq 'SI_ENGINE' }).Count)
}

function Get-SIAiEnvPlan {
    <#
        PURE. -Env: the current env list; -Want: @{ <name> = <value> | $null (remove) }. Every other variable (secret
        references included) is kept as it is and in its place; a variable to set that is missing is added at the end.
        @{ Env = the new list; Changes = @('set X' | 'remove X'); Changed }.
    #>
    param([object[]]$Env = @(), [Parameter(Mandatory)][System.Collections.IDictionary]$Want)
    $list = New-Object System.Collections.Generic.List[object]
    $changes = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($e in @($Env | Where-Object { $null -ne $_ })) {
        $n = [string]$e.name
        if (-not $Want.Contains($n)) { $list.Add($e); continue }
        $seen[$n] = $true
        $w = $Want[$n]
        if ($null -eq $w) { $changes.Add(('remove {0}' -f $n)); continue }
        $isPlain = -not ($e.PSObject.Properties['secretRef'] -and "$($e.secretRef)".Trim())
        if ($isPlain -and [string]$e.value -ceq [string]$w) { $list.Add($e); continue }
        $list.Add([pscustomobject]@{ name = $n; value = [string]$w }); $changes.Add(('set {0}' -f $n))
    }
    foreach ($n in @($Want.Keys)) {
        if ($seen.ContainsKey($n) -or $null -eq $Want[$n]) { continue }
        $list.Add([pscustomobject]@{ name = [string]$n; value = [string]$Want[$n] }); $changes.Add(('set {0}' -f $n))
    }
    [pscustomobject]@{ Env = $list.ToArray(); Changes = $changes.ToArray(); Changed = ($changes.Count -gt 0) }
}

function New-SIAiPatchBody {
    <#
        PURE. The ARM PATCH body for -Resource (an app or a job, as just read) with its first container's env set to -Env: its
        WHOLE template as read (a template PATCH replaces the container list), the revision suffix dropped (a reused suffix is
        refused), the default imageType and the read-only ephemeralStorage left out. Never the configuration (ARM returns
        secrets without values). Every other container is sent exactly as read.
    #>
    param([Parameter(Mandatory)]$Resource, [object[]]$Env = @())
    $tpl = ConvertTo-Json -InputObject $Resource.properties.template -Depth 60 | ConvertFrom-Json
    $first = @($tpl.containers | Where-Object { $_ })[0]
    if (-not $first) { throw 'it has no container' }
    $first | Add-Member -NotePropertyName env -NotePropertyValue @($Env) -Force
    foreach ($c in (@($tpl.containers) + @($(if ($tpl.PSObject.Properties['initContainers']) { $tpl.initContainers })))) {
        if (-not $c) { continue }
        if ($c.PSObject.Properties['imageType'] -and ([string]$c.imageType -in '', 'ContainerImage')) { $c.PSObject.Properties.Remove('imageType') }
        if ($c.PSObject.Properties['resources'] -and $c.resources -and $c.resources.PSObject.Properties['ephemeralStorage']) { $c.resources.PSObject.Properties.Remove('ephemeralStorage') }
    }
    if ($tpl.PSObject.Properties['revisionSuffix']) { $tpl.PSObject.Properties.Remove('revisionSuffix') }
    [ordered]@{ properties = [ordered]@{ template = $tpl } }
}

function Test-SIAiEnvReadBack {
    <# PURE. Whether -Resource's first container now carries exactly -Want (a $null = absent). #>
    param($Resource, [Parameter(Mandatory)][System.Collections.IDictionary]$Want)
    if ($null -eq $Resource) { return $false }
    $vars = @(Get-SIAiFirstContainerEnv -Resource $Resource)
    foreach ($n in @($Want.Keys)) {
        $have = @($vars | Where-Object { [string]$_.name -eq $n })
        if ($null -eq $Want[$n]) { if ($have.Count) { return $false }; continue }
        if ($have.Count -ne 1 -or [string]$have[0].value -cne [string]$Want[$n]) { return $false }
    }
    $true
}

function Invoke-SIAiSettingsOne {
    <# One app or job: GET, plan, PATCH when it differs, READ BACK. @{ Name; Kind; Action = set | would-set | in-place | none | failed; Line }. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, [string]$Kind = 'job',
          [Parameter(Mandatory)][System.Collections.IDictionary]$Want, [string]$What = '', [switch]$WhatIf, [int]$ReadBackTries = 6, [scriptblock]$Sleep)
    $label = if ($Kind -eq 'web') { 'the web app {0}' -f $Name } else { 'the job {0}' -f $Name }
    try {
        $now = & $Arm 'GET' $Path $script:SIAiSettingsArmApi $null
        if ($null -eq $now) { return [pscustomobject]@{ Name = $Name; Kind = $Kind; Action = 'none'; Line = ('AI settings: {0} is not in this install -- nothing to set' -f $label) } }
        $p = Get-SIAiEnvPlan -Env @(Get-SIAiFirstContainerEnv -Resource $now) -Want $Want
        if (-not $p.Changed) { return [pscustomobject]@{ Name = $Name; Kind = $Kind; Action = 'in-place'; Line = ('AI settings: {0} is as the settings say{1} -- nothing changed' -f $label, $(if ($What) { " ($What)" } else { '' })) } }
        $chg = ($p.Changes -join ', ')
        if ($WhatIf) { return [pscustomobject]@{ Name = $Name; Kind = $Kind; Action = 'would-set'; Line = ('AI settings: {0} would get: {1} (plan only)' -f $label, $chg) } }
        $null = & $Arm 'PATCH' $Path $script:SIAiSettingsArmApi (New-SIAiPatchBody -Resource $now -Env $p.Env)
        # read back; the web app also until its new revision is provisioned (the web app roll later in this update would be
        # refused while an operation is in flight)
        $ok = $false
        $tries = if ($Kind -eq 'web') { [Math]::Max(1, $ReadBackTries) * 5 } else { [Math]::Max(1, $ReadBackTries) }
        for ($i = 0; $i -lt $tries; $i++) {
            $back = & $Arm 'GET' $Path $script:SIAiSettingsArmApi $null
            $state = ''; try { $state = [string]$back.properties.provisioningState } catch { $state = '' }
            $settled = (-not $state) -or ($state -in 'Succeeded', 'Failed', 'Canceled')
            if ((Test-SIAiEnvReadBack -Resource $back -Want $Want) -and ($Kind -ne 'web' -or $settled)) { $ok = $true; break }
            if ($Sleep) { & $Sleep 10 } else { Start-Sleep -Seconds 10 }
        }
        if (-not $ok) { return [pscustomobject]@{ Name = $Name; Kind = $Kind; Action = 'failed'; Line = ('AI settings: {0} was changed ({1}) but does not read back with it -- the next update checks again' -f $label, $chg) } }
        [pscustomobject]@{ Name = $Name; Kind = $Kind; Action = 'set'; Line = ('AI settings: {0} {1} (read back){2}' -f $label, $chg, $(if ($Kind -eq 'web') { ' -- a new revision of the web app starts with them' } else { '' })) }
    } catch {
        $why = ("$($_.Exception.Message)" -replace '\s+', ' ').Trim(); if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
        [pscustomobject]@{ Name = $Name; Kind = $Kind; Action = 'failed'; Line = ('AI settings: {0} could not be set ({1}) -- it keeps what it has; the next update tries again' -f $label, $why) }
    }
}

function Invoke-SIAiSettings {
    <#
        EVERY UPDATE (see the header). -Settings: the AI settings (ConvertFrom-SIAiSettingRows), -Known: $false when they
        could not be read. -Jobs: the install's jobs (ARM shape, as listed). Returns @{ State; Results; Lines }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$WebAppName = 'ca-si-management', [object[]]$Jobs = @(), [hashtable]$Settings = @{}, [bool]$Known = $true,
          [switch]$WhatIf, [scriptblock]$Sleep, [int]$ReadBackTries = 6)
    $lines = New-Object System.Collections.Generic.List[string]
    $results = New-Object System.Collections.Generic.List[object]
    $want = Get-SIAiSettingsWant -Settings $Settings -Known $Known
    $rg = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App' -f $SubscriptionId, $ResourceGroup
    switch ($want.State) {
        'unknown'    { $lines.Add(('AI settings: not checked ({0}) -- nothing changed; the next update checks again' -f $want.Why)) }
        'incomplete' { $lines.Add(('AI settings: AI is on, but {0} -- the web chat and the engines are left as they are until it is set' -f $want.Why)) }
        'off' {
            $w = [ordered]@{}; foreach ($n in $script:SIAiWebEnvNames) { $w[$n] = $null }
            $r = Invoke-SIAiSettingsOne -Arm $Arm -Path ('{0}/containerApps/{1}' -f $rg, $WebAppName) -Name $WebAppName -Kind web -Want $w -What 'AI is off: no chat settings' -WhatIf:$WhatIf -Sleep $Sleep -ReadBackTries $ReadBackTries
            $results.Add($r); $lines.Add($r.Line)
        }
        'on' {
            $w = [ordered]@{ 'Chat__Endpoint' = $want.Endpoint; 'Chat__Deployment' = $want.Deployment }
            $r = Invoke-SIAiSettingsOne -Arm $Arm -Path ('{0}/containerApps/{1}' -f $rg, $WebAppName) -Name $WebAppName -Kind web -Want $w -What ('the chat uses {0}' -f $want.Deployment) -WhatIf:$WhatIf -Sleep $Sleep -ReadBackTries $ReadBackTries
            $results.Add($r); $lines.Add($r.Line)
            foreach ($j in @($Jobs | Where-Object { $_ -and (Test-SIAiEngineJob -Job $_) })) {
                $name = [string]$j.name
                $ver = $want.ApiVersion
                if (-not $ver) { $ver = [string]@(@(Get-SIAiFirstContainerEnv -Resource $j) | Where-Object { [string]$_.name -eq 'OPENAI_APIVERSION' -and "$($_.value)".Trim() } | ForEach-Object { "$($_.value)".Trim() })[0] }
                if (-not $ver) { $ver = $script:SIAiSettingsDefaultApiVersion }
                $jw = [ordered]@{ 'OPENAI_ENDPOINT' = $want.Endpoint; 'OPENAI_DEPLOYMENT' = $want.Deployment; 'OPENAI_APIVERSION' = $ver }
                $jr = Invoke-SIAiSettingsOne -Arm $Arm -Path ('{0}/jobs/{1}' -f $rg, $name) -Name $name -Kind job -Want $jw -WhatIf:$WhatIf -Sleep $Sleep -ReadBackTries $ReadBackTries
                $results.Add($jr)
                if ($jr.Action -ne 'in-place') { $lines.Add($jr.Line) }
            }
            $inPlace = @($results | Where-Object { $_.Kind -eq 'job' -and $_.Action -eq 'in-place' }).Count
            if ($inPlace) { $lines.Add(('AI settings: {0} engine job(s) already have them' -f $inPlace)) }
        }
    }
    [pscustomobject]@{ State = $want.State; Results = $results.ToArray(); Lines = $lines.ToArray() }
}
