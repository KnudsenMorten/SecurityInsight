#Requires -Version 5.1
<#
    SecurityInsight -- #873 E: THE RISK ANALYSIS JOBS RUN WITH A LARGER .NET GEN0 BUDGET (DOTNET_GCgen0size), ON BY DEFAULT.

    Measured (REQUIREMENTS #716, test VM): the per-row work of a Detailed slice allocates ~1.6 MB per row in PowerShell, and
    the default workstation GC stops every scoring runspace for each gen0 collection (~1,000 per slice, 7.3 s of a 17 s
    four-core run). DOTNET_GCgen0size=10000000 (hex: 256 MB) took the four-core run to 14.5 s. It is a runtime setting of the
    process: no row, no order and no verdict depends on it (tests\pester\SIv3-RaGcSetting.Tests.ps1 proves the stored rows
    identical with it set and unset, in child processes, and measures the memory peak).

      NEW INSTALL   Bootstrap gives every Risk Analysis job the variable (container\_shared\SI-ContainerConfig.ps1
                    Get-SIRaJobEnvArgs); its queue worker copies the producer's environment (Get-SIRaWorkerEnvArgs).
      EXISTING      every update (setup\Invoke-SIContainerUpdate.ps1 Invoke-SIUpdateRaGcSetting) gives each Risk Analysis job,
                    its extra report jobs and its queue workers the variable when it is missing: one read-modify-write PATCH
                    of the first container's environment (nothing else changes), READ BACK. A job that already has the
                    variable keeps its value (a value an operator set is never overwritten).
      OFF           SI_Bootstrap_RaGcGen0Size = off (false / no / 0) in the customer's settings: the variable is not added
                    (one line says so); a job that has it keeps it.
    Never throws; -WhatIf: the plan only, no Azure call. ONE seam, -Rest { param($Method, $Uri, $Body, $Resource, $Headers) }
    -> @{ Status; Body } (the update's REST seam). No az CLI, no PowerShell module.
#>

$script:SIRaGcName = 'DOTNET_GCgen0size'
$script:SIRaGcValue = '10000000'      # hexadecimal, as the .NET runtime reads GC settings: 0x10000000 = 256 MB
$script:SIRaGcArmApi = '2025-07-01'

function Get-SIRaGcEnvArg {
    <# PURE. The env var every Risk Analysis job gets ('DOTNET_GCgen0size=10000000'). #>
    '{0}={1}' -f $script:SIRaGcName, $script:SIRaGcValue
}

function Test-SIRaGcOn {
    <# PURE. Whether the setting is on: unset = ON; SI_Bootstrap_RaGcGen0Size off / false / no / 0 = off. #>
    param([hashtable]$Globals = @{})
    if ($null -eq $Globals -or -not $Globals.ContainsKey('SI_Bootstrap_RaGcGen0Size')) { return $true }
    $v = ([string]$Globals['SI_Bootstrap_RaGcGen0Size']).Trim()
    if (-not $v) { return $true }
    -not ($v -match '^(?i)(off|false|no|0|disabled?)$')
}

function Test-SIRaGcJobName {
    <# PURE. A Risk Analysis job: caj-si-risk-analysis-<grain>, an extra report job caj-si-ra-<name>, a queue worker
       caj-si-raworker-<grain>. #>
    param([string]$Name)
    ([string]$Name).ToLowerInvariant() -match '^caj-si-(risk-analysis-|ra-|raworker-)'
}

function Get-SIRaGcJobEnv {
    <# PURE. The first container's env list of a job (ARM shape), @() when none. #>
    param($Job)
    if ($null -eq $Job -or -not $Job.PSObject.Properties['properties'] -or $null -eq $Job.properties.template) { return @() }
    $c = @($Job.properties.template.containers)[0]
    if ($null -eq $c -or -not $c.PSObject.Properties['env']) { return @() }
    @($c.env | Where-Object { $null -ne $_ })
}

function Test-SIRaGcJobHas {
    <# PURE. Whether the job's first container already carries DOTNET_GCgen0size (any value). #>
    param($Job)
    [bool](@(Get-SIRaGcJobEnv -Job $Job | Where-Object { [string]$_.name -eq $script:SIRaGcName }).Count)
}

function Get-SIRaGcPatch {
    <# PURE. The PATCH that adds DOTNET_GCgen0size to the job's first container: its template as it is, the variable added
       at the end of the env list when it is missing; nothing else changes. Returns @{ Body; Changed }. #>
    param([Parameter(Mandatory)]$Job)
    $tpl = ConvertTo-Json -InputObject $Job.properties.template -Depth 30 | ConvertFrom-Json
    $c0 = @($tpl.containers)[0]
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($e in @(Get-SIRaGcJobEnv -Job ([pscustomobject]@{ properties = [pscustomobject]@{ template = $tpl } }))) { $list.Add($e) }
    $changed = $false
    if (-not @($list | Where-Object { [string]$_.name -eq $script:SIRaGcName }).Count) { $list.Add([ordered]@{ name = $script:SIRaGcName; value = $script:SIRaGcValue }); $changed = $true }
    $c0 | Add-Member -NotePropertyName env -NotePropertyValue $list.ToArray() -Force
    [pscustomobject]@{ Body = [ordered]@{ properties = [ordered]@{ template = $tpl } }; Changed = $changed }
}

function Invoke-SIRaGcSetting {
    <#
        EVERY UPDATE: each Risk Analysis job (Test-SIRaGcJobName) without DOTNET_GCgen0size gets it -- GET, PATCH, READ BACK.
        -Jobs: the job list (ARM shape) the update read. Returns @(@{ Job; Action = set | would-set | off | failed; Line }) --
        empty when every Risk Analysis job has it. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [object[]]$Jobs = @(), [hashtable]$Globals = @{}, [switch]$WhatIf)
    $out = New-Object System.Collections.Generic.List[object]
    $todo = @(@($Jobs) | Where-Object { $_ -and (Test-SIRaGcJobName -Name ([string]$_.name)) -and -not (Test-SIRaGcJobHas -Job $_) })
    if (-not $todo.Count) { return $out.ToArray() }
    if (-not (Test-SIRaGcOn -Globals $Globals)) {
        $out.Add([pscustomobject]@{ Job = ''; Action = 'off'; Line = ('risk analysis GC: switched off (SI_Bootstrap_RaGcGen0Size) -- {0} job(s) keep the default .NET gen0 budget' -f $todo.Count) })
        return $out.ToArray()
    }
    foreach ($j in $todo) {
        $name = [string]$j.name
        $line = 'risk analysis GC: {0} gets {1} (a 256 MB gen0 budget: fewer pauses while rows are scored; no row changes)' -f $name, (Get-SIRaGcEnvArg)
        if ($WhatIf) { $out.Add([pscustomobject]@{ Job = $name; Action = 'would-set'; Line = ($line + ' (re-run with -Apply)') }); continue }
        try {
            $uri = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}?api-version={3}' -f $SubscriptionId, $ResourceGroup, $name, $script:SIRaGcArmApi
            $g = & $Rest 'GET' $uri $null 'https://management.azure.com/' $null
            if (-not ($g -and [int]$g.Status -ge 200 -and [int]$g.Status -lt 300)) { throw ('the job could not be read (HTTP {0})' -f $(if ($g) { [int]$g.Status } else { 0 })) }
            $now = "$($g.Body)" | ConvertFrom-Json
            if (Test-SIRaGcJobHas -Job $now) { continue }
            $p = Get-SIRaGcPatch -Job $now
            $r = & $Rest 'PATCH' $uri (ConvertTo-Json -InputObject $p.Body -Depth 30 -Compress) 'https://management.azure.com/' @{ 'Content-Type' = 'application/json' }
            if (-not ($r -and [int]$r.Status -ge 200 -and [int]$r.Status -lt 300)) { throw ('Azure refused the change (HTTP {0})' -f $(if ($r) { [int]$r.Status } else { 0 })) }
            $b = & $Rest 'GET' $uri $null 'https://management.azure.com/' $null
            $back = $null; if ($b -and [int]$b.Status -ge 200 -and [int]$b.Status -lt 300) { $back = "$($b.Body)" | ConvertFrom-Json }
            if (-not (Test-SIRaGcJobHas -Job $back)) { throw 'Azure accepted the change but the job does not read back with it' }
            $out.Add([pscustomobject]@{ Job = $name; Action = 'set'; Line = $line })
        } catch {
            $why = ("$($_.Exception.Message)" -replace '\s+', ' ').Trim(); if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
            $out.Add([pscustomobject]@{ Job = $name; Action = 'failed'; Line = ('risk analysis GC: {0} did NOT get {1} ({2}) -- it runs as before; the next update tries again' -f $name, $script:SIRaGcName, $why) })
        }
    }
    $out.ToArray()
}
