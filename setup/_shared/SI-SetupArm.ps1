#Requires -Version 5.1
<#
    SecurityInsight SETUP -- the Azure resources setup creates and changes, over ARM / data-plane REST only (#521 phase 2:
    "pure rest or arm only", "want to not be dependent on it" -- the az CLI included). Every call goes through
    engine/_shared/SI-AzRest.ps1 (Invoke-SIArm / Invoke-SIAzRestRequest -> Invoke-SIAzRestHttp, the one HTTP seam), so it
    signs in exactly as setup does (Connect-SISetupAzure: a person in Cloud Shell or the browser, an app, a managed
    identity, or the Invardia support session's tokens) and the offline tests run it against a fake.

    Dot-source AFTER setup\_shared\SI-SetupAzure.ps1:
        . (Join-Path $PSScriptRoot '_shared\SI-SetupAzure.ps1')
        . (Join-Path $PSScriptRoot '_shared\SI-SetupArm.ps1')

    What replaces which az command:
        az containerapp job show / list / create / update / delete / start / secret set|remove / identity assign /
           registry set                            Get-/New-/Update-/Remove-/Start-SIContainerAppJob (READ-MODIFY-WRITE:
                                                  the whole job, secret values read back with listSecrets, ONE PUT)
        az containerapp show / update --set-env-vars    Get-SIContainerApp / Set-SIContainerAppEnvVar
        az containerapp env show / create / delete Get-/New-/Remove-SIManagedEnvironment; Initialize-SIManagedEnvironment
                                                  (an existing one's STATE decides: ready, waited for, or removed and
                                                  created again when Azure left it Failed and it holds nothing)
        az acr show / create / check-name / credential show   Get-/New-SIContainerRegistry, Test-SIContainerRegistryName,
                                                  Get-SIContainerRegistryCredential  (az acr build: setup\_shared\SI-AcrBuild.ps1)
        az keyvault show / secret list / secret show / secret set   Get-SIKeyVaultArm, Get-SIKeyVaultSecretNames,
                                                  Get-SIKeyVaultSecretValue (engine), Set-SIKeyVaultSecretText
        az storage account show                    Get-SIStorageAccountArm
        az identity show / create                  Get-/New-SIUserAssignedIdentity (SI-SetupAzure.ps1)
        az role assignment list / create           Test-SIRoleAssignmentPresent / New-SIRoleAssignment (SI-SetupAzure.ps1)
        az group show                              Get-SIResourceGroupArm
        az provider show / register                Get-/Register-SIResourceProvider (SI-SetupAzure.ps1)
        az sql server create / firewall-rule create / db create   New-SISqlServerEntraOnly, Set-SISqlFirewallRule,
                                                  New-SISqlDatabaseArm
        az account get-access-token --resource X   Get-SISetupAccessToken -Resource X
        az rest (ARM)                              Invoke-SIArm;   az rest (Graph $count)   Get-SITenantDirectoryCounts
    PS 5.1 safe; pwsh 7 on Windows, Linux (Azure Cloud Shell) and macOS.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

# 2025-07-01, NOT 2024-03-01 (#616, a new customer install 2026-10-12): the older version does not know the queue scale
# rule's `identity` and DROPS it without a word -- on a GET it is not returned, on a PUT it is not stored. A worker job
# written with it has a scaler that cannot read the queue (storage is identity-only), so the workers never start and the
# pipeline waits at its first collection. The same version the deploy of the web app and the release tool use.
$script:SIAppArmApi       = '2025-07-01'   # Microsoft.App (jobs, container apps, managed environments)
$script:SIAcrArmApi       = '2023-07-01'   # Microsoft.ContainerRegistry/registries
$script:SIKvArmApi        = '2023-07-01'
$script:SIStorageArmApi   = '2023-01-01'
$script:SISqlArmApi       = '2021-11-01'
$script:SIKvDataApi       = '7.4'

# =====================================================================================================================
#  Tokens and small helpers
# =====================================================================================================================

function Get-SISetupAccessToken {
    <# `az account get-access-token --resource <r> --query accessToken`: a bearer token for -Resource as whoever setup
       signed in as (Get-SIAzureToken -- the person, the app, the managed identity or the support session). #>
    param([Parameter(Mandatory)][string]$Resource, [switch]$ForceRefresh)
    $t = Get-SIAzureToken -Resource $Resource -ForceRefresh:$ForceRefresh
    if ($t -is [System.Security.SecureString]) { $t = (New-Object System.Net.NetworkCredential('', $t)).Password }
    [string]$t
}

function Get-SISetupArmPath {
    <# PURE. /subscriptions/<s>/resourceGroups/<rg>/providers/<Type>/<name>. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Type, [string]$Name)
    $p = '/subscriptions/{0}/resourceGroups/{1}/providers/{2}' -f $SubscriptionId, $ResourceGroupName, $Type
    if ($Name) { $p += '/' + $Name }
    $p
}

function Get-SISetupArmProp {
    <# PURE. A nested property of an ARM object (PSCustomObject or dictionary), $null when any step is missing. #>
    param($Object, [string[]]$Path)
    $o = $Object
    foreach ($p in $Path) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { $o = $(if ($o.Contains($p)) { $o[$p] } else { $null }); continue }
        $pp = $o.PSObject.Properties[$p]
        $o = $(if ($pp) { $pp.Value } else { $null })
    }
    $o
}

function ConvertTo-SISetupArmHashtable {
    <# PURE. An ARM object read back (PSCustomObject from ConvertFrom-Json) as ordered dictionaries + arrays, so it can be
       changed and written back whole. #>
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [ValueType]) { return $InputObject }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}; foreach ($k in @($InputObject.Keys)) { $h[[string]$k] = ConvertTo-SISetupArmHashtable $InputObject[$k] }; return $h
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $l = New-Object System.Collections.Generic.List[object]
        foreach ($i in $InputObject) { $l.Add((ConvertTo-SISetupArmHashtable $i)) }
        return , $l.ToArray()
    }
    $h = [ordered]@{}
    foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-SISetupArmHashtable $p.Value }
    $h
}

function Send-SISetupWaitProgress {
    <#
        #876 (owner: "make it very easy and info on progress"): a long wait says what it is waiting for, at most once a
        minute (one shared clock for every wait, so nothing floods): "still waiting for <what> (Azure shows: <state>) --
        <n> min so far". The guided install registers $global:SI_InstallWaitNotify = { param([string]$Message) ... } (it posts
        the line as a progress event of the running step, through the reporter); without it nothing is said (another
        script's own output is unchanged). Never throws.
    #>
    param([Parameter(Mandatory)][string]$What, [string]$State, [datetime]$SinceUtc = [datetime]::MinValue, [int]$EverySec = 55)
    try {
        $n = Get-Variable -Scope Global -Name SI_InstallWaitNotify -ValueOnly -ErrorAction Ignore
        if (-not ($n -is [scriptblock])) { return }
        $now = [datetime]::UtcNow
        $last = Get-Variable -Scope Global -Name SI_InstallWaitLastAt -ValueOnly -ErrorAction Ignore
        if ($last -is [datetime] -and ($now - $last).TotalSeconds -lt $EverySec) { return }
        $global:SI_InstallWaitLastAt = $now
        $mins = if ($SinceUtc -gt [datetime]::MinValue) { [int][Math]::Floor(($now - $SinceUtc).TotalMinutes) } else { -1 }
        $msg = 'still waiting for {0}{1}{2}' -f $What, $(if ("$State".Trim()) { ' (Azure shows: {0})' -f "$State".Trim() } else { '' }), $(if ($mins -ge 0) { ' -- {0} min so far' -f $mins } else { '' })
        & $n $msg
    } catch { }
}

function Wait-SIArmProvisioning {
    <# Polls an ARM resource until its provisioningState is terminal (Succeeded / Failed / Canceled). Returns the resource;
       a Failed resource throws with what Azure said. -Sleep: tests. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ApiVersion, [int]$TimeoutSec = 900, [int]$PollSec = 5, [scriptblock]$Sleep,
          # -WaitForResource (#616): a resource that is NOT THERE YET is waited for too. Without it a 404 right after the PUT
          # returned at once as if it were ready -- a new SQL server was "created" while Azure was still making it, and the
          # databases sent to it seconds later were rejected (2026-10-12, a new customer install).
          [switch]$WaitForResource)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $since = [datetime]::UtcNow
    while ($true) {
        $r = Invoke-SIArm -Path $Path -ApiVersion $ApiVersion -AllowNotFound
        $ps = [string](Get-SISetupArmProp $r @('properties', 'provisioningState'))
        # #876: a long wait says what it waits for, at most once a minute
        if (([datetime]::UtcNow - $since).TotalSeconds -ge 30) { Send-SISetupWaitProgress -What ((($Path -replace '\?.*$', '').TrimEnd('/') -split '/')[-1]) -State $(if ($r) { $ps } else { 'not there yet' }) -SinceUtc $since }
        if (-not $r -and $WaitForResource) {
            if ((Get-Date) -ge $deadline) { throw ('{0}: Azure did not show the resource within {1} seconds of creating it.' -f (($Path -split '/')[-1]), $TimeoutSec) }
            if ($Sleep) { & $Sleep $PollSec } else { Start-Sleep -Seconds $PollSec }
            continue
        }
        if (-not $r -or -not $ps -or $ps -in 'Succeeded', 'Failed', 'Canceled', 'Cancelled') {
            if ($ps -eq 'Failed') { throw ('{0}: Azure reports provisioning Failed.' -f (($Path -split '/')[-1])) }
            return $r
        }
        if ((Get-Date) -ge $deadline) { return $r }
        if ($Sleep) { & $Sleep $PollSec } else { Start-Sleep -Seconds $PollSec }
    }
}

# =====================================================================================================================
#  After a create: WAIT UNTIL IT EXISTS AND IS READY, and retry ONLY the "not there yet" answer
#  (the lessons of the first customer install through the Support app, 2026-10-12). Every value these read is written
#  out here -- never a script value of this file: a script that finds the functions defined does not load the file.
# =====================================================================================================================

function Get-SIArmReadiness {
    <#
        PURE. Is this resource, as Azure returned it, ready to be used? The property that says so differs per type:
          Microsoft.Sql/servers/<s>/databases/<d>   properties.status = Online
          Microsoft.Sql/servers/<s>                 properties.state  = Ready
          everything else                           properties.provisioningState = Succeeded (none at all = ready:
                                                    a firewall rule, a managed identity carry no state)
        Returns @{ State (the text Azure has); Ready; Failed; Why (Azure's own error text for a failed one, '' when it gave none) }.
    #>
    param([Parameter(Mandatory)][string]$Path, [AllowNull()]$Resource)
    $p = ($Path -replace '\?.*$', '').TrimEnd('/')
    $get = { param($o, [string[]]$names) foreach ($n in $names) { if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { $o = $(if ($o.Contains($n)) { $o[$n] } else { $null }) } else { $pp = $o.PSObject.Properties[$n]; $o = $(if ($pp) { $pp.Value } else { $null }) } }; $o }
    if ($null -eq $Resource) { return [pscustomobject]@{ State = ''; Ready = $false; Failed = $false; Why = '' } }
    if ($p -match '(?i)/providers/Microsoft\.Sql/servers/[^/]+/databases/[^/]+$') {
        $s = [string](& $get $Resource @('properties', 'status'))
        return [pscustomobject]@{ State = $s; Ready = ($s -eq 'Online'); Failed = $false; Why = '' }
    }
    if ($p -match '(?i)/providers/Microsoft\.Sql/servers/[^/]+$') {
        $s = [string](& $get $Resource @('properties', 'state'))
        return [pscustomobject]@{ State = $s; Ready = ($s -eq 'Ready'); Failed = $false; Why = '' }
    }
    $s = [string](& $get $Resource @('properties', 'provisioningState'))
    $failed = $s -in 'Failed', 'Canceled', 'Cancelled'
    $why = ''
    if ($failed) {
        # what Azure itself says on the resource (the names differ per provider); none = say where to look
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($n in 'provisioningError', 'provisioningErrors', 'statusMessage', 'statusDetails', 'deploymentErrors', 'errorMessage', 'error') {
            $v = & $get $Resource @('properties', $n)
            if ($null -eq $v) { continue }
            $t = if ($v -is [string]) { $v } else { try { ConvertTo-Json -InputObject $v -Depth 6 -Compress } catch { [string]$v } }
            if ("$t".Trim() -and "$t" -ne '{}' -and "$t" -ne '[]') { $parts.Add(('{0}: {1}' -f $n, "$t".Trim())) }
        }
        $why = ($parts.ToArray() -join '; ')
        if ($why.Length -gt 600) { $why = $why.Substring(0, 597) + '...' }
    }
    [pscustomobject]@{ State = $s; Ready = (-not $s -or $s -eq 'Succeeded'); Failed = $failed; Why = $why }
}

function Wait-SIArmResourceReady {
    <#
        After a create or a change: polls the resource until it EXISTS AND IS READY (Get-SIArmReadiness), and returns it.
        A 404 is "not there yet" and is polled through -- never "done". THROWS at the deadline (with the last state Azure
        showed) and on a failed resource (with Azure's own error text) -- it never returns something that is not ready.
        The deadline is -TimeoutSec, and at most TimeoutSec / PollSec polls (so a test's instant -Sleep ends too).
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ApiVersion, [int]$TimeoutSec = 900, [int]$PollSec = 10, [scriptblock]$Sleep, [string]$What)
    $name = (($Path -replace '\?.*$', '').TrimEnd('/') -split '/')[-1]
    if (-not $What) { $What = $name }
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $polls = [Math]::Max(1, [int][Math]::Ceiling($TimeoutSec / [double][Math]::Max(1, $PollSec)))
    $state = 'not there yet'
    $since = [datetime]::UtcNow
    for ($i = 0; $i -le $polls; $i++) {
        if ($i -gt 0) { Send-SISetupWaitProgress -What $What -State $state -SinceUtc $since }   # #876: at most once a minute
        $r = Invoke-SIArm -Path $Path -ApiVersion $ApiVersion -AllowNotFound
        if ($r) {
            $rd = Get-SIArmReadiness -Path $Path -Resource $r
            if ($rd.Failed) {
                throw ('{0}: Azure reports it {1}{2}' -f $What, $rd.State, $(if ($rd.Why) { ' -- ' + $rd.Why } else { ' and gives no reason on the resource -- see the activity log of the resource group for it' }))
            }
            if ($rd.Ready) { return $r }
            $state = $(if ($rd.State) { $rd.State } else { 'no state yet' })
        } else { $state = 'not there yet' }
        if ((Get-Date) -ge $deadline -or $i -ge $polls) { break }
        if ($Sleep) { & $Sleep $PollSec } else { Start-Sleep -Seconds $PollSec }
    }
    throw ('{0} is not ready {1} seconds after it was created or changed (Azure shows: {2}).' -f $What, $TimeoutSec, $state)
}

function Test-SIArmResourceAbsent {
    <#
        Is this resource DEFINITELY not there? $true only when Azure answers "not found" TWICE, with a pause between (a
        resource that is being scaled or moved can answer 404 for a few seconds). $false when it is there. Any other
        answer -- a refusal, a time-out, a server error -- THROWS: "could not read" is never "not there", and a create
        must never be sent over something that exists.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ApiVersion, [int]$PauseSec = 15, [scriptblock]$Sleep)
    if (Invoke-SIArm -Path $Path -ApiVersion $ApiVersion -AllowNotFound) { return $false }
    if ($Sleep) { & $Sleep $PauseSec } else { Start-Sleep -Seconds $PauseSec }
    if (Invoke-SIArm -Path $Path -ApiVersion $ApiVersion -AllowNotFound) { return $false }
    $true
}

function Test-SINotThereYetAnswer {
    <#
        PURE. Is this error text the "not there yet" answer of something created a moment ago -- HTTP 404 / "not found",
        Microsoft Graph's NoBackingApplicationObject / "does not reference a valid application object" /
        Request_ResourceNotFound, Azure's PrincipalNotFound? A REFUSAL (401 / 403, Authorization_RequestDenied,
        "Insufficient privileges", AuthorizationFailed) is never one, whatever else the text says.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    $t = "$Text"
    if ($t -match '(?i)Authorization_RequestDenied|Insufficient privileges|AuthorizationFailed|does not have authorization|\bForbidden\b|HTTP Status: 40[13]\b|HTTP 40[13]\b|\(40[13]\)') { return $false }
    [bool]($t -match '(?i)HTTP Status: 404\b|HTTP 404\b|\(404\)|\b404 \(Not ?Found\)|\bNotFound\b|Request_ResourceNotFound|ResourceNotFound|NoBackingApplicationObject|does not reference a valid application object|PrincipalNotFound|does not exist in the directory|does not exist or one of its queried reference-property objects')
}

function Test-SIAccessNotYetAnswer {
    <#
        PURE. Is this error text a data-plane REFUSAL of the kind a role assignment made a minute ago gives until it has
        reached the service (Key Vault / storage: HTTP 403, Forbidden, ForbiddenByRbac, AuthorizationPermissionMismatch)?
        Only for a call made right after the grant: the caller bounds the wait.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    [bool]("$Text" -match '(?i)HTTP Status: 403\b|HTTP 403\b|\(403\)|\bForbidden|ForbiddenByRbac|AuthorizationPermissionMismatch|not authorized|does not have secrets set permission')
}

function Invoke-SIRetryNotThereYet {
    <#
        Runs -Action; when it throws the "not there yet" answer (-Test, default Test-SINotThereYetAnswer: 404,
        NoBackingApplicationObject, PrincipalNotFound) it waits and runs it again -- -Waits seconds between tries
        (default 5, 10, 20, 30, 30, 30: about two minutes). ANY OTHER error is thrown at once, unchanged: a refusal is
        never waited for. The last "not there yet" error is thrown after the last wait. -Sleep: tests.
        The reason is read from the error's message AND its ErrorDetails (Invoke-RestMethod keeps the service's answer there).
    #>
    param([Parameter(Mandatory)][scriptblock]$Action, [int[]]$Waits = @(5, 10, 20, 30, 30, 30), [scriptblock]$Test, [scriptblock]$Sleep, [string]$What)
    $__siTry = 0; $__siOut = $null
    while ($true) {
        # no return inside the try: Windows PowerShell 5.1 can fail on one in a function it has compiled
        try { $__siOut = & $Action; break }
        catch {
            $__siText = '{0} {1}' -f [string]$_.Exception.Message, $(if ($_.ErrorDetails) { [string]$_.ErrorDetails.Message } else { '' })
            $__siYet = if ($Test) { [bool](& $Test $__siText) } else { Test-SINotThereYetAnswer -Text $__siText }
            if (-not $__siYet -or $__siTry -ge @($Waits).Count) { throw }
            $__siWait = [int]@($Waits)[$__siTry]; $__siTry++
            if ($What) { Write-Host ('       {0}: not there yet -- waiting {1} s and trying again ({2}/{3}) ...' -f $What, $__siWait, $__siTry, @($Waits).Count) -ForegroundColor DarkYellow }
            if ($__siWait -gt 0) { if ($Sleep) { & $Sleep $__siWait } else { Start-Sleep -Seconds $__siWait } }
        }
    }
    $__siOut
}

# The SQL connection retry (Open-SISqlConnectionRetry, Test-SISqlNotYetAnswer, Test-SISqlTransientError) lives in the ENGINE's
# shared layer now -- one implementation for setup, the updater and the engine (owner 2026-10-22: "why not use shared everywhere").
. ([IO.Path]::GetFullPath([IO.Path]::Combine($PSScriptRoot, '..', '..', 'engine', '_shared', 'SI-SqlRetry.ps1')))

# =====================================================================================================================
#  Container Apps jobs -- READ-MODIFY-WRITE of the whole job
# =====================================================================================================================

function Get-SIContainerAppJob {
    <# `az containerapp job show`: the job as ARM returns it; $null when it does not exist. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    Invoke-SIArm -Path (Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.App/jobs' $Name) -ApiVersion $script:SIAppArmApi -AllowNotFound
}

function Get-SIContainerAppJobList {
    <# `az containerapp job list --resource-group`: every job of the resource group (ARM objects). #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $items = @(Invoke-SIArm -Path (Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.App/jobs') -ApiVersion $script:SIAppArmApi -List -AllowNotFound)
    $items   # unrolled into the pipeline (a comma would hand the caller ONE array object)
}

function Get-SIContainerAppJobSecretValues {
    <# POST <job>/listSecrets: name -> @{ name; value | keyVaultUrl + identity }. ARM never returns secret values on GET,
       so a whole-job write must read them back first or it would blank every secret. $null-safe: no secrets = @{}. #>
    param([Parameter(Mandatory)][string]$JobId)
    $r = Invoke-SIArm -Method POST -Path ($JobId.TrimEnd('/') + '/listSecrets') -ApiVersion $script:SIAppArmApi -AllowNotFound
    $h = @{}
    foreach ($s in @(Get-SISetupArmProp $r @('value'))) { if ($s -and $s.name) { $h[[string]$s.name] = $s } }
    $h
}

function Get-SIJobSecretsWithoutValue {
    <#
        PURE. The names of the secrets a whole-job write would BLANK: declared by the job (-Job, as read) with a PLAIN
        value -- not a Key Vault reference, neither on the job nor in what listSecrets returned (-SecretValues) -- whose
        value is in neither, and that this write does not replace (-SetSecrets) or remove (-RemoveSecrets).
        A Key Vault reference never counts: it has no value to lose. None = @().
    #>
    param([Parameter(Mandatory)]$Job, [hashtable]$SecretValues = @{}, [object[]]$SetSecrets = @(), [string[]]$RemoveSecrets = @())
    $replaced = @($SetSecrets | Where-Object { $_ } | ForEach-Object { (([string]$_) -split '=', 2)[0] })
    foreach ($s in @(Get-SISetupArmProp $Job @('properties', 'configuration', 'secrets') | Where-Object { $_ })) {
        $n = [string](Get-SISetupArmProp $s @('name'))
        if (-not $n -or @($RemoveSecrets) -contains $n -or $replaced -contains $n) { continue }
        $known = $SecretValues[$n]
        if ([string](Get-SISetupArmProp $s @('keyVaultUrl')) -or ($known -and [string](Get-SISetupArmProp $known @('keyVaultUrl')))) { continue }
        $val = Get-SISetupArmProp $s @('value'); if ($null -eq $val -and $known) { $val = Get-SISetupArmProp $known @('value') }
        if ($null -eq $val) { $n }
    }
}

function ConvertTo-SIJobSecretEntry {
    <# PURE. One `--secrets` argument (name=value | name=keyvaultref:<url>,identityref:<id>) as an ARM secret. #>
    param([Parameter(Mandatory)][string]$Arg)
    $p = $Arg -split '=', 2
    $v = $(if ($p.Count -gt 1) { $p[1] } else { '' })
    if ($v.StartsWith('keyvaultref:')) {
        $ref = $v.Substring(12); $k = $ref.IndexOf(',identityref:')
        if ($k -ge 0) { return [ordered]@{ name = $p[0]; keyVaultUrl = $ref.Substring(0, $k); identity = $ref.Substring($k + 13) } }
        return [ordered]@{ name = $p[0]; keyVaultUrl = $ref }
    }
    [ordered]@{ name = $p[0]; value = $v }
}

function ConvertTo-SIJobEnvEntry {
    <# PURE. One `--env-vars` argument (N=V | N=secretref:S) as an ARM env entry. #>
    param([Parameter(Mandatory)][string]$Arg)
    $p = $Arg -split '=', 2
    $v = $(if ($p.Count -gt 1) { $p[1] } else { '' })
    if ($v.StartsWith('secretref:')) { return [ordered]@{ name = $p[0]; secretRef = $v.Substring(10) } }
    [ordered]@{ name = $p[0]; value = $v }
}

function ConvertFrom-SIScaleRuleArgs {
    <# PURE. Get-SIKedaQueueScaleArgs' arguments (--scale-rule-name/-type/-metadata k=v/-identity) as ONE ARM scale rule. #>
    param([object[]]$ScaleArgs = @())
    $rule = [ordered]@{ name = ''; type = ''; metadata = [ordered]@{} }
    $cur = $null
    foreach ($x in @($ScaleArgs | ForEach-Object { [string]$_ })) {
        if ($x.StartsWith('--')) { $cur = $x; continue }
        switch ($cur) {
            '--scale-rule-name'     { $rule.name = $x }
            '--scale-rule-type'     { $rule.type = $x }
            '--scale-rule-identity' { $rule.identity = $x }
            '--scale-rule-metadata' { $kv = $x -split '=', 2; $rule.metadata[$kv[0]] = $(if ($kv.Count -gt 1) { $kv[1] } else { '' }) }
        }
    }
    if (-not $rule.name) { return $null }
    $rule
}

function Merge-SIContainerAppJobUpdate {
    <#
        PURE. The job written back WHOLE, with what an `az containerapp job update` / `secret set` / `secret remove` /
        `identity assign` / `registry set` changed -- applied to the job as read (-Job, with its secret values from
        listSecrets in -SecretValues). Only what is given changes; everything else (command, args, probes, volumes, the
        trigger of a job the flow made Manual, other secrets, other identities) is kept as it is.
          -Image / -Cpu / -Memory      the job's (first) container          -Env      REPLACES its environment (N=V)
          -SetEnv                      adds / overwrites these (N=V)        -RemoveEnv  drops these names
          -Cron                        scheduleTriggerConfig.cronExpression (a Schedule job only)
          -ReplicaTimeout              configuration.replicaTimeout         -Tags     merged into the job's tags (k=v)
          -ScaleRule                   replaces the rule of that name (eventTriggerConfig.scale.rules)
          -SetSecrets                  adds / overwrites (name=value | keyvaultref)   -RemoveSecrets  drops these names
          -AddIdentity                 a user-assigned identity resource id (kept identities stay)
          -RegistryServer + -RegistryIdentity   the registry entry for that server pulls as the identity
        Returns the body (an ordered dictionary) for a PUT.
    #>
    param(
        [Parameter(Mandatory)]$Job, [hashtable]$SecretValues = @{},
        [string]$Image, [string]$Cpu, [string]$Memory, [object[]]$Env, [object[]]$SetEnv = @(), [string[]]$RemoveEnv = @(),
        [string]$Cron, [int]$ReplicaTimeout = 0, [object[]]$Tags = @(), $ScaleRule,
        [object[]]$SetSecrets = @(), [string[]]$RemoveSecrets = @(), [string]$AddIdentity, [string]$RegistryServer, [string]$RegistryIdentity
    )
    $b = ConvertTo-SISetupArmHashtable $Job
    foreach ($ro in 'systemData', 'etag') { if ($b.Contains($ro)) { $b.Remove($ro) } }
    if (-not $b.Contains('properties') -or $null -eq $b.properties) { $b.properties = [ordered]@{} }
    $p = $b.properties
    foreach ($ro in 'provisioningState', 'eventStreamEndpoint', 'outboundIpAddresses') { if ($p.Contains($ro)) { $p.Remove($ro) } }
    if (-not $p.Contains('configuration') -or $null -eq $p.configuration) { $p.configuration = [ordered]@{} }
    $cfg = $p.configuration
    if (-not $p.Contains('template') -or $null -eq $p.template) { $p.template = [ordered]@{ containers = @() } }

    # ---- secrets: the values read back, then the changes ----
    $secrets = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($cfg.secrets | Where-Object { $_ })) {
        $n = [string]$s.name
        if (@($RemoveSecrets) -contains $n) { continue }
        $e = [ordered]@{ name = $n }
        $known = $SecretValues[$n]
        $kv = [string](Get-SISetupArmProp $s @('keyVaultUrl')); if (-not $kv -and $known) { $kv = [string](Get-SISetupArmProp $known @('keyVaultUrl')) }
        if ($kv) {
            $e.keyVaultUrl = $kv
            $id = [string](Get-SISetupArmProp $s @('identity')); if (-not $id -and $known) { $id = [string](Get-SISetupArmProp $known @('identity')) }
            if ($id) { $e.identity = $id }
        } else {
            $val = Get-SISetupArmProp $s @('value'); if ($null -eq $val -and $known) { $val = Get-SISetupArmProp $known @('value') }
            # (a value that was not read back becomes '' here: this function only shapes the body. The WRITE is guarded --
            # Update-SIContainerAppJob stops before it when Get-SIJobSecretsWithoutValue names a secret.)
            $e.value = [string]$val
        }
        $secrets.Add($e)
    }
    foreach ($a in @($SetSecrets | Where-Object { $_ })) {
        $e = ConvertTo-SIJobSecretEntry -Arg ([string]$a)
        $i = -1; for ($k = 0; $k -lt $secrets.Count; $k++) { if ([string]$secrets[$k].name -eq [string]$e.name) { $i = $k } }
        if ($i -ge 0) { $secrets[$i] = $e } else { $secrets.Add($e) }
    }
    if ($secrets.Count) { $cfg.secrets = $secrets.ToArray() } elseif ($cfg.Contains('secrets')) { $cfg.secrets = @() }

    if ($ReplicaTimeout -gt 0) { $cfg.replicaTimeout = $ReplicaTimeout }
    if ($Cron -and [string]$cfg.triggerType -eq 'Schedule') {
        if (-not $cfg.Contains('scheduleTriggerConfig') -or $null -eq $cfg.scheduleTriggerConfig) { $cfg.scheduleTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 } }
        $cfg.scheduleTriggerConfig.cronExpression = $Cron
    }
    if ($ScaleRule) {
        if (-not $cfg.Contains('eventTriggerConfig') -or $null -eq $cfg.eventTriggerConfig) { $cfg.eventTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 } }
        $etc = $cfg.eventTriggerConfig
        if (-not $etc.Contains('scale') -or $null -eq $etc.scale) { $etc.scale = [ordered]@{ minExecutions = 0; maxExecutions = 10; pollingInterval = 30 } }
        $rules = @(@($etc.scale.rules) | Where-Object { $_ -and [string]$_.name -ne [string]$ScaleRule.name })
        $etc.scale.rules = @($rules) + @($ScaleRule)
    }
    if ($RegistryServer -and $RegistryIdentity) {
        $regs = @(@($cfg.registries) | Where-Object { $_ -and [string]$_.server -ne $RegistryServer })
        $cfg.registries = @($regs) + @([ordered]@{ server = $RegistryServer; identity = $RegistryIdentity })
    }

    # ---- identity ----
    if ($AddIdentity) {
        $idn = $b.identity
        if ($null -eq $idn) { $idn = [ordered]@{ type = 'UserAssigned' }; $b.identity = $idn }
        $ua = $idn.userAssignedIdentities
        $newUa = [ordered]@{}
        if ($ua -is [System.Collections.IDictionary]) { foreach ($k in @($ua.Keys)) { $newUa[[string]$k] = [ordered]@{} } }
        if (-not @($newUa.Keys | Where-Object { "$_" -ieq $AddIdentity }).Count) { $newUa[$AddIdentity] = [ordered]@{} }
        $idn.userAssignedIdentities = $newUa
        $t = [string]$idn.type
        $idn.type = $(if ($t -match '(?i)SystemAssigned') { 'SystemAssigned,UserAssigned' } else { 'UserAssigned' })
    }

    # ---- tags (merged) ----
    $tagList = @($Tags | Where-Object { $_ })
    if ($tagList.Count) {
        $tg = [ordered]@{}
        if ($b.tags -is [System.Collections.IDictionary]) { foreach ($k in @($b.tags.Keys)) { $tg[[string]$k] = $b.tags[$k] } }
        foreach ($t in $tagList) { $kv = ([string]$t) -split '=', 2; $tg[$kv[0]] = $(if ($kv.Count -gt 1) { $kv[1] } else { '' }) }
        $b.tags = $tg
    }

    # ---- the container ----
    $containers = @($p.template.containers | Where-Object { $_ })
    if ($containers.Count -eq 0 -and ($Image -or $Env -or $SetEnv.Count)) { $containers = @([ordered]@{ name = [string]$b.name; image = $Image; env = @() }) }
    if ($containers.Count) {
        $c = $containers[0]
        if ($Image) { $c.image = $Image }
        if ($Cpu -or $Memory) {
            if (-not $c.Contains('resources') -or $null -eq $c.resources) { $c.resources = [ordered]@{} }
            if ($Cpu) { $c.resources.cpu = [double]::Parse($Cpu, [Globalization.CultureInfo]::InvariantCulture) }
            if ($Memory) { $c.resources.memory = $Memory }
            if ($c.resources.Contains('ephemeralStorage') -and ($Cpu -or $Memory)) { $c.resources.Remove('ephemeralStorage') }
        }
        $envList = New-Object System.Collections.Generic.List[object]
        if ($null -ne $Env) { foreach ($x in @($Env | Where-Object { $_ })) { $envList.Add((ConvertTo-SIJobEnvEntry -Arg ([string]$x))) } }
        else { foreach ($x in @($c.env | Where-Object { $_ })) { $envList.Add($x) } }
        foreach ($x in @($SetEnv | Where-Object { $_ })) {
            $e = ConvertTo-SIJobEnvEntry -Arg ([string]$x)
            $i = -1; for ($k = 0; $k -lt $envList.Count; $k++) { if ([string]$envList[$k].name -eq [string]$e.name) { $i = $k } }
            if ($i -ge 0) { $envList[$i] = $e } else { $envList.Add($e) }
        }
        if (@($RemoveEnv).Count) { $keep = @($envList | Where-Object { @($RemoveEnv) -notcontains [string]$_.name }); $envList = New-Object System.Collections.Generic.List[object]; foreach ($x in $keep) { $envList.Add($x) } }
        $c.env = $envList.ToArray()
        $containers[0] = $c
        $p.template.containers = $containers
    }
    $b
}

function Test-SIContainerAppIdentityNotReady {
    <# PURE. A Container Apps create/update refused because a NEW managed identity's registry pull right has not reached the
       registry yet (the role assignment was made seconds before) -- a wait, not a failure. customer A, 2026-10-08. #>
    param([AllowEmptyString()][string]$Text)
    [bool]("$Text" -match '(?i)unable to pull image using Managed identity|identity .* (is not|has not been) (authorized|granted).*(pull|registry)|UNAUTHORIZED: authentication required')
}

function Test-SIContainerAppRegistryNotResolvable {
    <# PURE. A Container Apps create/update refused because Azure cannot resolve a container registry's name YET -- the
       registry was created minutes before and its name has not reached the resolver Container Apps uses
       (InvalidParameterValueInContainerTemplate ... "failed to resolve registry '<name>.azurecr.io' ... no such host").
       A wait, not a failure: the customer-run install at customer C stopped on it 2026-10-15 07:12Z (registry made
       07:08Z, its name resolving minutes later). #>
    param([AllowEmptyString()][string]$Text)
    [bool]("$Text" -match "(?i)failed to resolve registry\s+'?[a-z0-9.-]+\.azurecr\.io'?[^;]*no such host")
}

function Get-SIJobBodyRunLimit {
    <# PURE. The run limit (properties.configuration.replicaTimeout, seconds) a job body asks for; 0 when it names none.
       The body may be hashtables (a create) or objects (a job as read). #>
    param($Body)
    $get = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } else { $pp = $o.PSObject.Properties[$n]; if ($pp) { $pp.Value } else { $null } } }
    $v = & $get (& $get (& $get $Body 'properties') 'configuration') 'replicaTimeout'
    $n = 0; [void][int]::TryParse("$v", [ref]$n); $n
}

function Set-SIJobBodyRunLimit {
    <# The run limit of a job body set to -ReplicaTimeout, and a KEDA worker's queue lease (SI_QUEUE_LEASE_SECONDS on its
       first container) with it: the limit + 300 s. Changes -Body in place. #>
    param($Body, [Parameter(Mandatory)][int]$ReplicaTimeout)
    $get = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } else { $pp = $o.PSObject.Properties[$n]; if ($pp) { $pp.Value } else { $null } } }
    $set = { param($o, $n, $val) if ($o -is [System.Collections.IDictionary]) { $o[$n] = $val } else { $o | Add-Member -NotePropertyName $n -NotePropertyValue $val -Force } }
    $props = & $get $Body 'properties'
    $cfg = & $get $props 'configuration'
    if ($null -eq $cfg) { return }
    & $set $cfg 'replicaTimeout' $ReplicaTimeout
    $first = @(& $get (& $get $props 'template') 'containers' | Where-Object { $_ }) | Select-Object -First 1
    foreach ($e in @(& $get $first 'env')) {
        if ($e -and [string](& $get $e 'name') -eq 'SI_QUEUE_LEASE_SECONDS') { & $set $e 'value' ([string]($ReplicaTimeout + 300)) }
    }
}

function Set-SIContainerAppJob {
    <# PUT the WHOLE job (create or replace) and wait until Azure has provisioned it. A refusal because a new identity's
       registry pull right has not arrived yet is waited out (-IdentityWaitSeconds). A run limit above 24 hours that Azure
       refuses is sent once more as 24 hours -- the rest of the job unchanged -- with one plain line; the refusal is
       remembered for the run (container\_shared\SI-ContainerConfig.ps1, Get-SIRunLimitToSend). Returns the job as Azure has it. #>
    param([Parameter(Mandatory)][string]$JobId, [Parameter(Mandatory)]$Body, [int]$IdentityWaitSeconds = 600, [scriptblock]$Sleep, [switch]$NoWait)
    if (-not (Get-Command -Name Get-SIRunLimitToSend -ErrorAction Ignore)) { . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'container', '_shared', 'SI-ContainerConfig.ps1')) }
    $asked = Get-SIJobBodyRunLimit -Body $Body
    $limit = Get-SIRunLimitToSend -ReplicaTimeout $asked
    if ($limit -lt $asked) { Set-SIJobBodyRunLimit -Body $Body -ReplicaTimeout $limit }   # refused earlier in this run
    $lowered = $false
    $until = (Get-Date).AddSeconds($IdentityWaitSeconds)
    while ($true) {
        try { $null = Invoke-SIArm -Method PUT -Path $JobId -ApiVersion $script:SIAppArmApi -Body $Body; break }
        catch {
            $text = [string]$_.Exception.Message
            if (Test-SIContainerAppIdentityNotReady -Text $text) {
                if ((Get-Date) -ge $until) { throw }
                Write-Host '       the new identity''s registry pull right has not reached the registry yet -- waiting 30 s and trying again ...' -ForegroundColor DarkYellow
                if ($Sleep) { & $Sleep 30 } else { Start-Sleep -Seconds 30 }
                continue
            }
            if (Test-SIContainerAppRegistryNotResolvable -Text $text) {
                if ((Get-Date) -ge $until) { throw }
                Write-Host '       Azure cannot find the new container registry''s name yet (it was just created) -- waiting 30 s and trying again ...' -ForegroundColor DarkYellow
                if ($Sleep) { & $Sleep 30 } else { Start-Sleep -Seconds 30 }
                continue
            }
            # a run limit above 24 hours may be what Azure refused: the same job once more with 24 hours
            if ($lowered -or -not (Test-SIRunLimitRefusal -ReplicaTimeout $limit -Text $text)) { throw }
            $limit = [int](Get-SIAzureKnownRunLimit); $lowered = $true
            Set-SIJobBodyRunLimit -Body $Body -ReplicaTimeout $limit
        }
    }
    if ($lowered) {
        # accepted with 24 hours: the run limit was the cause -- said once, and the other jobs of this run ask for 24 hours
        Set-SIRunLimitRefused
        Write-Host ('       ' + (Get-SIRunLimitRefusedLine -Job (([string]$JobId -split '/')[-1]) -ReplicaTimeout $asked)) -ForegroundColor DarkYellow
    }
    if ($NoWait) { return (Invoke-SIArm -Path $JobId -ApiVersion $script:SIAppArmApi -AllowNotFound) }
    # until the job EXISTS and is provisioned: a 404 is "not yet", a deadline or a failed job throws with Azure's words
    Wait-SIArmResourceReady -Path $JobId -ApiVersion '2025-07-01' -TimeoutSec 900 -PollSec 5 -Sleep $Sleep -What ('the Container Apps job {0}' -f (([string]$JobId -split '/')[-1]))
}

function New-SIContainerAppJobFromArgs {
    <#
        `az containerapp job create <args>` over ARM: Bootstrap's job definition (the create arguments of
        container\_shared\SI-ContainerConfig.ps1 -- Get-SIKedaWorkerCreateArgs and friends -- plus tags, registry, identity,
        secrets and env) translated by ConvertFrom-SIJobCreateArgs (setup\_shared\SI-KedaConvert.ps1, the one translation
        the update uses too) into the Microsoft.App/jobs resource, and PUT whole. -EnvironmentId: the environment's
        resource id (the arguments may carry its name). Returns the job.
    #>
    param([Parameter(Mandatory)][object[]]$CreateArgs, [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$EnvironmentId,
          [string]$SubscriptionId, [scriptblock]$Sleep)
    if (-not (Get-Command -Name ConvertFrom-SIJobCreateArgs -ErrorAction Ignore)) { . (Join-Path $PSScriptRoot 'SI-KedaConvert.ps1') }
    $spec = ConvertFrom-SIJobCreateArgs -CreateArgs $CreateArgs -Location $Location
    $spec.Body.properties.environmentId = $EnvironmentId
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $id = Get-SISetupArmPath $sub $spec.ResourceGroup 'Microsoft.App/jobs' $spec.Name
    Set-SIContainerAppJob -JobId $id -Body $spec.Body -Sleep $Sleep
}

function Update-SIContainerAppJob {
    <#
        The az update family over ARM, READ-MODIFY-WRITE: GET the job, read its secret values back (listSecrets), apply the
        changes (Merge-SIContainerAppJobUpdate -- same parameters) and PUT the whole job once. A job that does not exist
        throws. Returns the job as Azure has it.
    #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId,
          [string]$Image, [string]$Cpu, [string]$Memory, [object[]]$Env, [object[]]$SetEnv = @(), [string[]]$RemoveEnv = @(),
          [string]$Cron, [int]$ReplicaTimeout = 0, [object[]]$Tags = @(), $ScaleRule,
          [object[]]$SetSecrets = @(), [string[]]$RemoveSecrets = @(), [string]$AddIdentity, [string]$RegistryServer, [string]$RegistryIdentity,
          $Job, [scriptblock]$Sleep)
    if (-not $Job) { $Job = Get-SIContainerAppJob -ResourceGroupName $ResourceGroupName -Name $Name -SubscriptionId $SubscriptionId }
    if (-not $Job) { throw ("The Container Apps job '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) }
    $vals = Get-SIContainerAppJobSecretValues -JobId ([string]$Job.id)
    # THE WRITE IS GUARDED: a secret the job declares with a plain value that was not read back would be written EMPTY by
    # the whole-job write, and the job would lose it without a word. Stop before the write instead.
    $noValue = @(Get-SIJobSecretsWithoutValue -Job $Job -SecretValues $vals -SetSecrets $SetSecrets -RemoveSecrets $RemoveSecrets)
    if ($noValue.Count) {
        throw ("The job {0} is NOT written: its secret(s) {1} have no value that could be read back (listSecrets did not return them), and writing the job would blank them. Check that this sign-in may read the job's secrets (Microsoft.App/jobs/listSecrets/action) and run the same command again." -f $Name, (($noValue | ForEach-Object { "'" + $_ + "'" }) -join ', '))
    }
    $m = @{ Job = $Job; SecretValues = $vals }
    foreach ($k in 'Image', 'Cpu', 'Memory', 'Env', 'SetEnv', 'RemoveEnv', 'Cron', 'ReplicaTimeout', 'Tags', 'ScaleRule', 'SetSecrets', 'RemoveSecrets', 'AddIdentity', 'RegistryServer', 'RegistryIdentity') {
        if ($PSBoundParameters.ContainsKey($k)) { $m[$k] = $PSBoundParameters[$k] }
    }
    $body = Merge-SIContainerAppJobUpdate @m
    Set-SIContainerAppJob -JobId ([string]$Job.id) -Body $body -Sleep $Sleep
}

function Remove-SIContainerAppJob {
    <# `az containerapp job delete --yes`. Absent = nothing to do. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $null = Invoke-SIArm -Method DELETE -Path (Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.App/jobs' $Name) -ApiVersion $script:SIAppArmApi -AllowNotFound
}

function Start-SIContainerAppJob {
    <# `az containerapp job start` (POST <job>/start). -Template: the execution's own template (e.g. the flow job started
       with SI_FLOW_FORCE=1). Returns @{ id; name } of the execution. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId, $Template)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $body = if ($null -ne $Template) { $Template } else { $null }
    Invoke-SIArm -Method POST -Path ((Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.App/jobs' $Name) + '/start') -ApiVersion $script:SIAppArmApi -Body $body
}

# =====================================================================================================================
#  Container apps (the Pro web app) and managed environments
# =====================================================================================================================

function Get-SIContainerApp {
    <# `az containerapp show`: the app as ARM returns it; $null when it does not exist. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    Invoke-SIArm -Path (Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.App/containerApps' $Name) -ApiVersion $script:SIAppArmApi -AllowNotFound
}

function Set-SIContainerAppEnvVar {
    <# `az containerapp update --set-env-vars N=V ...`, READ-MODIFY-WRITE: the app read whole, the variables set on its
       first container (others kept), the WHOLE template written back by PATCH (a template PATCH replaces the container
       array, so it carries every container as read; secrets are not part of it and stay). Returns $true when it changed. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$SetEnv, [string]$SubscriptionId)
    $app = Get-SIContainerApp -ResourceGroupName $ResourceGroupName -Name $Name -SubscriptionId $SubscriptionId
    if (-not $app) { throw ("The container app '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) }
    $tpl = ConvertTo-SISetupArmHashtable (Get-SISetupArmProp $app @('properties', 'template'))
    $cs = @($tpl.containers | Where-Object { $_ })
    if (-not $cs.Count) { throw ("The container app '{0}' has no container." -f $Name) }
    $env = New-Object System.Collections.Generic.List[object]; foreach ($x in @($cs[0].env | Where-Object { $_ })) { $env.Add($x) }
    $changed = $false
    foreach ($a in $SetEnv) {
        $e = ConvertTo-SIJobEnvEntry -Arg $a
        $i = -1; for ($k = 0; $k -lt $env.Count; $k++) { if ([string]$env[$k].name -eq [string]$e.name) { $i = $k } }
        if ($i -ge 0) { if ([string]$env[$i].value -ne [string]$e.value -or $env[$i].Contains('secretRef')) { $env[$i] = $e; $changed = $true } } else { $env.Add($e); $changed = $true }
    }
    if (-not $changed) { return $false }
    $cs[0].env = $env.ToArray(); $tpl.containers = $cs
    if ($tpl.Contains('revisionSuffix')) { $tpl.Remove('revisionSuffix') }
    $null = Invoke-SIArm -Method PATCH -Path ([string]$app.id) -ApiVersion $script:SIAppArmApi -Body ([ordered]@{ properties = [ordered]@{ template = $tpl } })
    $null = Wait-SIArmResourceReady -Path ([string]$app.id) -ApiVersion '2025-07-01' -TimeoutSec 900 -PollSec 5 -What ('the container app {0}' -f $Name)
    $true
}

function Get-SIManagedEnvironment {
    <# `az containerapp env show`: the environment as ARM returns it; $null when it does not exist. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    Invoke-SIArm -Path (Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.App/managedEnvironments' $Name) -ApiVersion $script:SIAppArmApi -AllowNotFound
}

function Get-SIManagedEnvironmentBody {
    <# PURE. A new Container Apps environment: logs through Azure Monitor (#220 -- no stray workspace; the diagnostic
       setting sends them to the SI workspace) and the Consumption workload profile (what az creates by default). #>
    param([Parameter(Mandatory)][string]$Location,
          # #681 (private networking, an option): the environment in the customer's subnet; -Internal = no public address
          [string]$InfrastructureSubnetId = '', [switch]$Internal)
    $b = [ordered]@{ location = $Location; properties = [ordered]@{
        appLogsConfiguration = [ordered]@{ destination = 'azure-monitor' }
        workloadProfiles     = @([ordered]@{ name = 'Consumption'; workloadProfileType = 'Consumption' }) } }
    if ("$InfrastructureSubnetId".Trim()) { $b.properties['vnetConfiguration'] = [ordered]@{ infrastructureSubnetId = "$InfrastructureSubnetId".Trim(); internal = [bool]$Internal } }
    $b
}

function New-SIManagedEnvironment {
    <# `az containerapp env create --logs-destination azure-monitor`: PUT, then waits until provisioned (minutes). #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Location, [string]$SubscriptionId, [scriptblock]$Sleep,
          [string]$InfrastructureSubnetId = '', [switch]$Internal)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $path = Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.App/managedEnvironments' $Name
    $null = Invoke-SIArm -Method PUT -Path $path -ApiVersion $script:SIAppArmApi -Body (Get-SIManagedEnvironmentBody -Location $Location -InfrastructureSubnetId $InfrastructureSubnetId -Internal:$Internal)
    Wait-SIArmResourceReady -Path $path -ApiVersion '2025-07-01' -TimeoutSec 1800 -PollSec 15 -Sleep $Sleep -What ('the Container Apps environment {0}' -f $Name)
}

function Wait-SIArmResourceGone {
    <#
        After a DELETE: polls the resource until Azure answers "not found", and returns $true. A resource that still
        answers is "not gone yet" whatever state it shows. THROWS at the deadline with the last state Azure showed -- it
        never returns while the resource is there. At most TimeoutSec / PollSec polls (so a test's instant -Sleep ends too).
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ApiVersion, [int]$TimeoutSec = 1800, [int]$PollSec = 15, [scriptblock]$Sleep, [string]$What)
    if (-not $What) { $What = (($Path -replace '\?.*$', '').TrimEnd('/') -split '/')[-1] }
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $polls = [Math]::Max(1, [int][Math]::Ceiling($TimeoutSec / [double][Math]::Max(1, $PollSec)))
    $state = ''
    for ($i = 0; $i -le $polls; $i++) {
        $r = Invoke-SIArm -Path $Path -ApiVersion $ApiVersion -AllowNotFound
        if (-not $r) { return $true }
        $state = [string](Get-SIArmReadiness -Path $Path -Resource $r).State
        if ((Get-Date) -ge $deadline -or $i -ge $polls) { break }
        if ($Sleep) { & $Sleep $PollSec } else { Start-Sleep -Seconds $PollSec }
    }
    throw ('{0} is still there {1} seconds after its removal was asked for (Azure shows: {2}).' -f $What, $TimeoutSec, $(if ($state) { $state } else { 'no state' }))
}

function Remove-SIManagedEnvironment {
    <# `az containerapp env delete --yes`: DELETE, then WAITS UNTIL IT IS GONE (Azure takes minutes; a create sent while
       the old one is still being removed is refused). Absent = nothing to do. The caller decides whether it may be
       removed (Get-SIManagedEnvironmentUse) -- this function removes what it is given. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId, [int]$TimeoutSec = 1800, [scriptblock]$Sleep)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $path = Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.App/managedEnvironments' $Name
    $null = Invoke-SIArm -Method DELETE -Path $path -ApiVersion '2025-07-01' -AllowNotFound
    $null = Wait-SIArmResourceGone -Path $path -ApiVersion '2025-07-01' -TimeoutSec $TimeoutSec -PollSec 15 -Sleep $Sleep -What ('the Container Apps environment {0}' -f $Name)
}

function Get-SIManagedEnvironmentUse {
    <#
        What runs in this environment: every Container Apps job and container app of the resource group that refers to it
        (properties.environmentId / properties.managedEnvironmentId), as 'the job <name>' / 'the container app <name>'.
        Nothing = an empty list. A list that cannot be read THROWS: "could not read" is never "empty", and an
        environment is only ever removed when it is known to hold nothing.
    #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$EnvironmentId, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $want = $EnvironmentId.Trim().TrimEnd('/')
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($kind in @(@{ Type = 'Microsoft.App/jobs'; Word = 'the job' }, @{ Type = 'Microsoft.App/containerApps'; Word = 'the container app' })) {
        $items = @(Invoke-SIArm -Path (Get-SISetupArmPath $sub $ResourceGroupName $kind.Type) -ApiVersion '2025-07-01' -List | Where-Object { $_ })
        foreach ($it in $items) {
            foreach ($prop in 'environmentId', 'managedEnvironmentId') {
                $v = ([string](Get-SISetupArmProp $it @('properties', $prop))).Trim().TrimEnd('/')
                if ($v -and [string]::Equals($v, $want, [System.StringComparison]::OrdinalIgnoreCase)) { $found.Add(('{0} {1}' -f $kind.Word, [string]$it.name)); break }
            }
        }
    }
    $found.ToArray()
}

function Initialize-SIManagedEnvironment {
    <#
        The Container Apps environment of an install, READY -- or a plain sentence why not. An environment that exists is
        not "fine" because it exists (a customer install, 2026-10-13: Azure left a new one Failed, and the next run went on
        with it). What Azure shows decides:
          not there                  created, waited for until it is ready
          ready                      returned as it is -- nothing is written
          still being made           waited for (the same limit as a new one); a second one is never created
          being removed              waited for until it is gone, then created
          Failed / Canceled          Azure does not repair it. EMPTY (no job and no container app of the resource group
                                     refers to it): removed, waited for until it is gone, created again -- ONCE per run.
                                     NOT empty: nothing is removed; it stops and says so (a support case).
        A create that Azure fails stops with what Azure said and what the person does next; it is not tried again in the
        same run (the failed one is removed by the next run). -Sleep: tests.
    #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Location, [string]$SubscriptionId, [scriptblock]$Sleep,
          # #681 (private networking, an option): a NEW environment is created in this subnet (-Internal: no public address).
          # An environment that exists is never changed: Azure cannot move one into a virtual network (setup\Set-SIPrivateNetworking.ps1).
          [string]$InfrastructureSubnetId = '', [switch]$Internal)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $path = Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.App/managedEnvironments' $Name
    $what = 'the Container Apps environment {0}' -f $Name
    $again = $false   # this run (or the one before it) already had a failed environment: the create below is a second try
    $cae = Get-SIManagedEnvironment -ResourceGroupName $ResourceGroupName -Name $Name -SubscriptionId $sub
    if ($cae) {
        $rd = Get-SIArmReadiness -Path $path -Resource $cae
        if ($rd.Ready -and "$InfrastructureSubnetId".Trim() -and -not [string](Get-SISetupArmProp $cae @('properties', 'vnetConfiguration', 'infrastructureSubnetId'))) {
            Write-Warning ('{0} exists and is not in the virtual network: it is kept as it is (Azure cannot move an environment into a network). An existing install moves with setup\Set-SIPrivateNetworking.ps1.' -f $what)
        }
        if ($rd.Ready) { return $cae }
        if (-not $rd.Failed -and [string]$rd.State -match '(?i)delet') {
            Write-Host ('       {0} is being removed by Azure ({1}) -- waiting until it is gone (this takes minutes), then it is created again ...' -f $what, $rd.State) -ForegroundColor DarkYellow
            $null = Wait-SIArmResourceGone -Path $path -ApiVersion '2025-07-01' -TimeoutSec 1800 -PollSec 15 -Sleep $Sleep -What $what
            $cae = $null; $again = $true
        } elseif (-not $rd.Failed) {
            Write-Host ('       {0} is still being made by Azure ({1}) -- waiting for it (this can take up to 30 minutes); a second one is not created ...' -f $what, $(if ($rd.State) { $rd.State } else { 'no state yet' })) -ForegroundColor DarkYellow
            $waitError = $null
            try { $ready = Wait-SIArmResourceReady -Path $path -ApiVersion '2025-07-01' -TimeoutSec 1800 -PollSec 15 -Sleep $Sleep -What $what } catch { $waitError = $_ }
            if (-not $waitError) { return $ready }
            # it did not get ready: only an environment Azure now shows as Failed goes on to the removal below
            $cae = Get-SIManagedEnvironment -ResourceGroupName $ResourceGroupName -Name $Name -SubscriptionId $sub
            $rd = Get-SIArmReadiness -Path $path -Resource $cae
            if (-not $cae -or -not $rd.Failed) { throw $waitError }
        }
        if ($cae) {
            $why = $(if ($rd.Why) { ([string]$rd.Why).TrimEnd('.', ' ') } else { 'Azure gives no reason on the resource' })
            $inUse = @()
            try { $inUse = @(Get-SIManagedEnvironmentUse -ResourceGroupName $ResourceGroupName -EnvironmentId ([string]$cae.id) -SubscriptionId $sub) }
            catch { throw ('{0} was left {1} by Azure ({2}). It is removed and created again only when it holds nothing, and what it holds could not be read: {3} Nothing was removed and nothing was changed. Run the same command again; if it stops here again, contact SecurityInsight support with this message.' -f $what, $rd.State, $why, [string]$_.Exception.Message) }
            if ($inUse.Count) {
                throw ('{0} was left {1} by Azure ({2}). Azure does not repair such an environment by itself; it has to be removed and created again -- but it is NOT empty: it holds {3}, and removing it would take them with it. Nothing was removed and nothing was changed. Contact SecurityInsight support with this message.' -f $what, $rd.State, $why, ($inUse -join ', '))
            }
            Write-Host ('       {0} was left {1} by Azure ({2}) -- it holds nothing, so it is removed and created again.' -f $what, $rd.State, $why) -ForegroundColor DarkYellow
            Write-Host '       Removing it -- Azure takes several minutes for this; waiting until it is gone (up to 30 minutes) ...'
            try { Remove-SIManagedEnvironment -ResourceGroupName $ResourceGroupName -Name $Name -SubscriptionId $sub -Sleep $Sleep }
            catch { throw ('{0} was left {1} by Azure ({2}) and could not be removed: {3} Nothing else was changed. Run the same command again later; if it stops here again, contact SecurityInsight support with this message.' -f $what, $rd.State, $why, [string]$_.Exception.Message) }
            Write-Host '       Removed.'
            $again = $true
        }
    }
    Write-Host $(if ($again) { '       Creating the Container Apps environment again (Consumption profile, ~$0 idle) ...' } else { '       Creating CAE (Consumption profile, ~$0 idle) ...' })
    $createError = $null; $new = $null
    try { $new = New-SIManagedEnvironment -ResourceGroupName $ResourceGroupName -Name $Name -Location $Location -SubscriptionId $sub -Sleep $Sleep -InfrastructureSubnetId $InfrastructureSubnetId -Internal:$Internal } catch { $createError = $_ }
    if (-not $createError) { return $new }
    # what did Azure leave? Only an environment it shows as Failed gets the plain sentence; anything else keeps its own error
    $left = $null; try { $left = Get-SIManagedEnvironment -ResourceGroupName $ResourceGroupName -Name $Name -SubscriptionId $sub } catch { $left = $null }
    $lrd = Get-SIArmReadiness -Path $path -Resource $left
    if (-not $left -or -not $lrd.Failed) { throw $createError }
    $lwhy = $(if ($lrd.Why) { ([string]$lrd.Why).TrimEnd('.', ' ') } else { 'Azure gives no reason on the resource -- see the activity log of the resource group' })
    # only Azure's own "could not make the cluster, retry later" is called what it is; any other reason stands as Azure gave it
    $cause = if ($lwhy -match '(?i)ManagedEnvironmentProvisioningError|retry later|managed cluster|capacity') {
        (' This is Azure''s own capacity in the region {0} at the moment -- nothing in this install is wrong and nothing has to be changed.' -f $Location)
    } else { '' }
    if ($again) {
        throw ('Azure could not make {0} this time either: {1}.{2} The failed environment holds nothing and is removed by the next run. Wait -- an hour is a good first wait -- and run the same command again; it continues from this step. If it still fails after several tries, contact SecurityInsight support with this message.' -f $what, $lwhy, $cause)
    }
    throw ('Azure could not make {0}: {1}.{2} Wait a while (15 minutes or more) and run the same command again: it removes the failed environment, which holds nothing, and creates it again.' -f $what, $lwhy, $cause)
}

function Set-SIEnvironmentLogSetting {
    <# #220: the diagnostic setting that sends the environment's console + system logs to the SI workspace (idempotent PUT). #>
    param([Parameter(Mandatory)][string]$EnvironmentId, [Parameter(Mandatory)][string]$WorkspaceResourceId)
    $body = Get-SIEnvironmentLogSettingBody -WorkspaceResourceId $WorkspaceResourceId
    $null = Invoke-SIArm -Method PUT -Path ($EnvironmentId.TrimEnd('/') + '/providers/Microsoft.Insights/diagnosticSettings/si-environment-logs') -ApiVersion '2021-05-01-preview' -Body $body
}

# =====================================================================================================================
#  Container registry
# =====================================================================================================================

function Get-SIContainerRegistry {
    <# `az acr show`: the registry as ARM returns it (id, properties.loginServer); $null when it does not exist. Adds
       loginServer at the top, as az did. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $r = Invoke-SIArm -Path (Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.ContainerRegistry/registries' $Name) -ApiVersion $script:SIAcrArmApi -AllowNotFound
    if ($r -and -not $r.PSObject.Properties['loginServer']) { $r | Add-Member -NotePropertyName loginServer -NotePropertyValue ([string](Get-SISetupArmProp $r @('properties', 'loginServer'))) }
    $r
}

function New-SIContainerRegistry {
    <# `az acr create --sku Basic --admin-enabled true`: PUT, waits until provisioned, returns Get-SIContainerRegistry. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Location,
          [string]$Sku = 'Basic', [bool]$AdminEnabled = $true, [string]$SubscriptionId, [scriptblock]$Sleep)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $path = Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.ContainerRegistry/registries' $Name
    $null = Invoke-SIArm -Method PUT -Path $path -ApiVersion $script:SIAcrArmApi -Body ([ordered]@{ location = $Location; sku = @{ name = $Sku }; properties = @{ adminUserEnabled = $AdminEnabled } })
    $null = Wait-SIArmResourceReady -Path $path -ApiVersion '2023-07-01' -TimeoutSec 900 -PollSec 5 -Sleep $Sleep -What ('the container registry {0}' -f $Name)
    Get-SIContainerRegistry -ResourceGroupName $ResourceGroupName -Name $Name -SubscriptionId $sub
}

function Test-SIContainerRegistryName {
    <# `az acr check-name`: @{ nameAvailable; reason; message }. #>
    param([Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    Invoke-SIArm -Method POST -Path ("/subscriptions/$sub/providers/Microsoft.ContainerRegistry/checkNameAvailability") -ApiVersion $script:SIAcrArmApi `
        -Body @{ name = $Name; type = 'Microsoft.ContainerRegistry/registries' }
}

function Get-SIContainerRegistryCredential {
    <# `az acr credential show`: @{ username; passwords = @(@{ name; value }) } -- $null when admin access is disabled. #>
    param([Parameter(Mandatory)][string]$RegistryId)
    try { Invoke-SIArm -Method POST -Path ($RegistryId.TrimEnd('/') + '/listCredentials') -ApiVersion $script:SIAcrArmApi } catch { $null }
}

# =====================================================================================================================
#  Key Vault, storage, resource group
# =====================================================================================================================

function Get-SIKeyVaultArm {
    <# `az keyvault show --name` (no resource group): the vault as ARM returns it (id, properties.vaultUri), found in the
       subscription; $null when not found or not readable. #>
    param([Parameter(Mandatory)][string]$Name, [string]$ResourceGroupName, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    try {
        if ($ResourceGroupName) { return (Invoke-SIArm -Path (Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.KeyVault/vaults' $Name) -ApiVersion $script:SIKvArmApi -AllowNotFound) }
        foreach ($v in @(Invoke-SIArm -Path "/subscriptions/$sub/providers/Microsoft.KeyVault/vaults" -ApiVersion $script:SIKvArmApi -List)) {
            if ([string]$v.name -eq $Name) {
                # the list carries no vaultUri on every api version: read the vault itself
                return (Invoke-SIArm -Path ([string]$v.id) -ApiVersion $script:SIKvArmApi -AllowNotFound)
            }
        }
    } catch { return $null }
    $null
}

function Get-SIKeyVaultSecretNames {
    <# `az keyvault secret list --query [].name`: the secret NAMES a vault holds (never a value), every page. $null = they
       could not be read from here (no data-plane right, the vault not reachable). #>
    param([Parameter(Mandatory)][string]$VaultName)
    $names = New-Object System.Collections.Generic.List[string]
    $next = 'https://{0}.vault.azure.net/secrets?api-version={1}&maxresults=25' -f $VaultName, $script:SIKvDataApi
    try {
        while ($next) {
            $r = Invoke-SIAzRestRequest -Method GET -Uri $next -Audience KeyVault -What ("Listing the secrets of Key Vault '{0}'" -f $VaultName)
            $j = $r.Content | ConvertFrom-Json
            foreach ($s in @($j.value)) { if ($s -and $s.id) { $names.Add(([string]$s.id).TrimEnd('/').Split('/')[-1]) } }
            $next = [string]$j.nextLink
        }
    } catch { return $null }
    , $names.ToArray()
}

function Set-SIKeyVaultSecretText {
    <# `az keyvault secret set --file <f> --encoding utf-8 [--content-type]`: one secret, its value as plain text. #>
    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][AllowEmptyString()][string]$Value, [string]$ContentType)
    $body = [ordered]@{ value = $Value }
    if ($ContentType) { $body.contentType = $ContentType }
    $uri = 'https://{0}.vault.azure.net/secrets/{1}?api-version={2}' -f $VaultName, [uri]::EscapeDataString($Name), $script:SIKvDataApi
    $r = Invoke-SIAzRestRequest -Method PUT -Uri $uri -Audience KeyVault -Body ($body | ConvertTo-Json -Compress) -What ("Writing secret '{0}' to Key Vault '{1}'" -f $Name, $VaultName)
    $r.Content | ConvertFrom-Json
}

function Get-SIStorageAccountArm {
    <# `az storage account show --name`: the account as ARM returns it (id); $null when not found. #>
    param([Parameter(Mandatory)][string]$Name, [string]$ResourceGroupName, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    if ($ResourceGroupName) { return (Invoke-SIArm -Path (Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.Storage/storageAccounts' $Name) -ApiVersion $script:SIStorageArmApi -AllowNotFound) }
    foreach ($s in @(Invoke-SIArm -Path "/subscriptions/$sub/providers/Microsoft.Storage/storageAccounts" -ApiVersion $script:SIStorageArmApi -List)) {
        if ([string]$s.name -eq $Name) { return $s }
    }
    $null
}

function Get-SIResourceGroupArm {
    <# `az group show`: the resource group (id, location); $null when it does not exist. #>
    param([Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    Invoke-SIArm -Path "/subscriptions/$sub/resourcegroups/$Name" -ApiVersion '2021-04-01' -AllowNotFound
}

# =====================================================================================================================
#  Role assignments
# =====================================================================================================================

function Test-SIScopeCovers {
    <# PURE. Does an assignment at -AssignedScope apply at -Scope (the same scope, or one above it)? #>
    param([string]$AssignedScope, [string]$Scope)
    $a = ([string]$AssignedScope).TrimEnd('/').ToLowerInvariant(); $s = ([string]$Scope).TrimEnd('/').ToLowerInvariant()
    ($a -eq '' -or $a -eq '/' -or $s -eq $a -or $s.StartsWith($a + '/'))
}

function Test-SIRoleAssignmentPresent {
    <# `az role assignment list --assignee <oid> --scope <s> --role <r>` is not empty: does -ObjectId hold
       -RoleDefinitionName (directly) at -Scope or above? #>
    param([Parameter(Mandatory)][string]$ObjectId, [Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$RoleDefinitionName)
    $subScope = if ($Scope -match '^(/subscriptions/[^/]+)') { $Matches[1] } else { $Scope }
    $def = @(Get-SIAzRestRoleDefinitions -Scope $subScope | Where-Object { [string]$_.properties.roleName -eq $RoleDefinitionName }) | Select-Object -First 1
    if (-not $def) { return $false }
    $rid = ([string]$def.name).ToLowerInvariant()
    $path = $Scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleAssignments?$filter=' + [uri]::EscapeDataString(("principalId eq '{0}'" -f $ObjectId))
    foreach ($a in @(Invoke-SIArm -Path $path -ApiVersion '2022-04-01' -List)) {
        if ((([string]$a.properties.roleDefinitionId) -split '/')[-1].ToLowerInvariant() -ne $rid) { continue }
        if (Test-SIScopeCovers -AssignedScope ([string]$a.properties.scope) -Scope $Scope) { return $true }
    }
    $false
}

function Resolve-SIPrincipalObjectId {
    <# `az role assignment create --assignee <appId>`: the object id of a service principal named by its app (client) id;
       a value that is already an object id of one is returned as it is. Graph. #>
    param([Parameter(Mandatory)][string]$Id)
    $r = Invoke-SIAzRestRequest -Method GET -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id" -f $Id) -Audience Graph -What 'Finding the service principal'
    $sp = @(($r.Content | ConvertFrom-Json).value)[0]
    if ($sp -and $sp.id) { return [string]$sp.id }
    $Id
}

# =====================================================================================================================
#  Azure SQL (Pro database)
# =====================================================================================================================

function Get-SISqlServerEntraOnlyBody {
    <# PURE. A new Azure SQL server with Entra-only sign-in from the first second (`az sql server create --enable-ad-only-auth
       --external-admin-principal-type/-name/-sid`). #>
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$AdminName, [Parameter(Mandatory)][string]$AdminSid,
          [ValidateSet('User', 'Group', 'Application')][string]$AdminType = 'User', [string]$TenantId,
          # #866 (a private install; owner: "we will not allow fw option or exceptions"): 'Disabled' CREATES the server with
          # no public access -- only its private endpoint, which setup makes right after it
          [ValidateSet('Enabled', 'Disabled')][string]$PublicNetworkAccess = 'Enabled')
    $adm = [ordered]@{ administratorType = 'ActiveDirectory'; principalType = $AdminType; login = $AdminName; sid = $AdminSid; azureADOnlyAuthentication = $true }
    if ($TenantId) { $adm.tenantId = $TenantId }
    [ordered]@{ location = $Location; properties = [ordered]@{ version = '12.0'; minimalTlsVersion = '1.2'; publicNetworkAccess = $PublicNetworkAccess; administrators = $adm } }
}

function New-SISqlServerEntraOnly {
    <# `az sql server create --enable-ad-only-auth ...`: PUT, waits until it is ready. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Location,
          [Parameter(Mandatory)][string]$AdminName, [Parameter(Mandatory)][string]$AdminSid, [ValidateSet('User', 'Group', 'Application')][string]$AdminType = 'User',
          [string]$SubscriptionId, [scriptblock]$Sleep, [ValidateSet('Enabled', 'Disabled')][string]$PublicNetworkAccess = 'Enabled')
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $path = Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.Sql/servers' $Name
    $tid = $null; try { $tid = Get-SIAzRestTenantId } catch { }
    # A create is NEVER sent over a server that exists (it would make the installer its administrator again): only when
    # Azure says "not found" twice. A read that fails for another reason throws (Test-SIArmResourceAbsent).
    $absent = Test-SIArmResourceAbsent -Path $path -ApiVersion '2021-11-01' -Sleep $Sleep
    if ($absent) {
        $null = Invoke-SIArm -Method PUT -Path $path -ApiVersion '2021-11-01' -Body (Get-SISqlServerEntraOnlyBody -Location $Location -AdminName $AdminName -AdminSid $AdminSid -AdminType $AdminType -TenantId $tid -PublicNetworkAccess $PublicNetworkAccess)
    }
    # until the server IS there and Ready -- its databases are sent right after this returns; not Ready in time THROWS
    $srv = Wait-SIArmResourceReady -Path $path -ApiVersion '2021-11-01' -TimeoutSec 1800 -PollSec 10 -Sleep $Sleep -What ('the database server {0}' -f $Name)
    $srv | Add-Member -NotePropertyName SIExisted -NotePropertyValue (-not $absent) -Force
    $srv
}

function Get-SISqlServerEntraAdmin {
    <# The server's Entra administrator as ARM has it on the server itself: @{ Sid; Login; PrincipalType }. $null = NONE IS
       SET. A server that cannot be read THROWS -- "could not read" is never "none set". #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $srv = Invoke-SIArm -Method GET -Path (Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.Sql/servers' $Name) -ApiVersion '2021-11-01'
    if (-not $srv) { throw ('the database server {0} could not be read (Azure returned nothing)' -f $Name) }
    $a = Get-SISetupArmProp $srv @('properties', 'administrators')
    if (-not $a -or -not [string](Get-SISetupArmProp $a @('sid'))) { return $null }
    [pscustomobject]@{ Sid = [string](Get-SISetupArmProp $a @('sid')); Login = [string](Get-SISetupArmProp $a @('login')); PrincipalType = [string](Get-SISetupArmProp $a @('principalType')) }
}

function Get-SISqlServerEntraAdminPatchBody {
    <# PURE. The PATCH of the SERVER that sets its Entra administrator WITH its kind (the administrators sub-resource has
       no field for the kind, so a change through it left "Group" on a server whose administrator was an application). #>
    param([Parameter(Mandatory)][string]$AdminName, [Parameter(Mandatory)][string]$AdminSid,
          [Parameter(Mandatory)][ValidateSet('User', 'Group', 'Application')][string]$AdminType, [string]$TenantId,
          # the server's OWN "Entra-only sign-in" setting, sent back as it is: the administrators block is written whole,
          # and one that leaves it out could switch it off. $null = not known = left out (never guessed).
          [AllowNull()]$EntraOnly)
    $adm = [ordered]@{ administratorType = 'ActiveDirectory'; principalType = $AdminType; login = $AdminName; sid = $AdminSid }
    if ($TenantId) { $adm.tenantId = [string]$TenantId }
    if ($null -ne $EntraOnly) { $adm.azureADOnlyAuthentication = [bool]$EntraOnly }
    [ordered]@{ properties = [ordered]@{ administrators = $adm } }
}

function Set-SISqlServerEntraAdmin {
    <# Makes -AdminSid (a person's or group's object id; an application's CLIENT id) the server's Entra administrator, AS
       -AdminType (User / Group / Application), through a PATCH of the server, and waits until the server shows that sid
       AND that kind. Throws when it does not change. Returns @{ Sid; Login; PrincipalType }. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$AdminName,
          [Parameter(Mandatory)][string]$AdminSid, [ValidateSet('User', 'Group', 'Application')][string]$AdminType = 'Application',
          [string]$SubscriptionId, [scriptblock]$Sleep)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $path = Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.Sql/servers' $Name
    $tid = $null; try { $tid = Get-SIAzRestTenantId } catch { }
    # THE SERVER IS READ FIRST: its "Entra-only sign-in" setting goes back in the same block exactly as it is. A server
    # that cannot be read is NOT changed (throws) -- the setting is never written blind.
    $srv = Invoke-SIArm -Method GET -Path $path -ApiVersion '2021-11-01'
    if (-not $srv) { throw ('the database server {0} could not be read (Azure returned nothing) -- its administrator was not changed' -f $Name) }
    $only = Get-SISetupArmProp $srv @('properties', 'administrators', 'azureADOnlyAuthentication')
    $onlyBefore = $(if ($null -ne $only -and "$only" -ne '') { [bool]$only } else { $null })
    $null = Invoke-SIArm -Method PATCH -Path $path -ApiVersion '2021-11-01' -Body (Get-SISqlServerEntraAdminPatchBody -AdminName $AdminName -AdminSid $AdminSid -AdminType $AdminType -TenantId $tid -EntraOnly $onlyBefore)
    $now = $null
    $since = [datetime]::UtcNow
    for ($i = 1; $i -le 36; $i++) {
        if ($i -gt 1) { Send-SISetupWaitProgress -What ('the database server {0} to take its new administrator' -f $Name) -SinceUtc $since }   # #876
        try { $now = Get-SISqlServerEntraAdmin -ResourceGroupName $ResourceGroupName -Name $Name -SubscriptionId $sub } catch { $now = $null }
        if ($now -and [string]$now.Sid -ieq $AdminSid -and [string]$now.PrincipalType -ieq $AdminType) { return $now }
        if ($Sleep) { & $Sleep 5 } else { Start-Sleep -Seconds 5 }
    }
    throw ("the Entra administrator of the database server {0} did not change to {1} as {2} (Azure shows: {3})" -f $Name, $AdminName, $AdminType,
        $(if ($now) { '{0} as {1}' -f $now.Login, $now.PrincipalType } else { 'none, or the server could not be read' }))
}

function Set-SISqlFirewallRule {
    <# `az sql server firewall-rule create` (idempotent PUT). 0.0.0.0-0.0.0.0 = Azure services. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$ServerName, [Parameter(Mandatory)][string]$Name,
          [string]$StartIpAddress = '0.0.0.0', [string]$EndIpAddress = '0.0.0.0', [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    Invoke-SIArm -Method PUT -Path ((Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.Sql/servers' $ServerName) + '/firewallRules/' + $Name) -ApiVersion $script:SISqlArmApi `
        -Body @{ properties = @{ startIpAddress = $StartIpAddress; endIpAddress = $EndIpAddress } }
}

function Get-SISqlFirewallRule {
    <# One firewall rule of an Azure SQL server (properties.startIpAddress / endIpAddress); $null when it does not exist. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$ServerName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    Invoke-SIArm -Path ((Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.Sql/servers' $ServerName) + '/firewallRules/' + $Name) -ApiVersion $script:SISqlArmApi -AllowNotFound
}

function Remove-SISqlFirewallRule {
    <# Deletes one firewall rule of an Azure SQL server. Absent = nothing to do. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$ServerName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $null = Invoke-SIArm -Method DELETE -Path ((Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.Sql/servers' $ServerName) + '/firewallRules/' + $Name) -ApiVersion $script:SISqlArmApi -AllowNotFound
}

function Test-SISqlDatabasePresent {
    <# Is this database on the server? $true / $false ("not found"). Any other failure of the read THROWS -- "could not
       read" is never "not there". (The end-of-install check.) #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$ServerName, [Parameter(Mandatory)][string]$DatabaseName, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    [bool](Invoke-SIArm -Path ((Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.Sql/servers' $ServerName) + '/databases/' + $DatabaseName) -ApiVersion '2021-11-01' -AllowNotFound)
}

function Get-SISqlDatabaseCreateBody {
    <# PURE. A new database at -Target (Get-SISqlDatabaseTier: Name / Tier / Capacity / MaxSizeBytes), local backup
       redundancy -- what `az sql db create --service-objective --max-size --backup-storage-redundancy Local` sent. #>
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)]$Target)
    $sku = [ordered]@{ name = [string]$Target.Name }
    if ([string]$Target.Tier) { $sku.tier = [string]$Target.Tier }
    if ([int]$Target.Capacity -gt 0) { $sku.capacity = [int]$Target.Capacity }
    $props = [ordered]@{ requestedBackupStorageRedundancy = 'Local' }
    if ([long]$Target.MaxSizeBytes -gt 0) { $props.maxSizeBytes = [long]$Target.MaxSizeBytes }
    [ordered]@{ location = $Location; sku = $sku; properties = $props }
}

function New-SISqlDatabaseArm {
    <# `az sql db create`: PUT at -Target's size, waits until it is online. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$ServerName, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)]$Target, [string]$Location, [string]$SubscriptionId, [scriptblock]$Sleep)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $srvPath = Get-SISetupArmPath $sub $ResourceGroupName 'Microsoft.Sql/servers' $ServerName
    if (-not $Location) { $Location = [string](Invoke-SIArm -Path $srvPath -ApiVersion $script:SISqlArmApi).location }
    $path = $srvPath + '/databases/' + $Name
    $body = Get-SISqlDatabaseCreateBody -Location $Location -Target $Target
    # A create is NEVER sent over a database that exists -- it carries a size, and would lower one the customer raised.
    # Only when Azure says "not found" TWICE (a database being resized can answer 404 for a few seconds); a read that
    # fails for another reason throws. One that is there is waited for until it is online, and returned as it is.
    if (-not (Test-SIArmResourceAbsent -Path $path -ApiVersion '2021-11-01' -Sleep $Sleep)) {
        $have = Wait-SIArmResourceReady -Path $path -ApiVersion '2021-11-01' -TimeoutSec 1800 -PollSec 10 -Sleep $Sleep -What ('the database {0}' -f $Name)
        $have | Add-Member -NotePropertyName SIExisted -NotePropertyValue $true -Force
        return $have
    }
    # a database create is ACCEPTED and made afterwards; Azure can still reject it then (a server not ready yet).
    # So: wait until the database EXISTS and is Online; when it is still not there after two minutes the request was
    # lost or rejected -- it is sent again (three times at most); never "created" on the accepted request alone.
    $deadline = (Get-Date).AddSeconds(1800)
    for ($send = 1; $send -le 3; $send++) {
        try { $null = Invoke-SIArm -Method PUT -Path $path -ApiVersion '2021-11-01' -Body $body }
        catch {
            # sent AGAIN while Azure still makes the first one: a conflict then means "being made" -- keep waiting for it
            if ($send -eq 1 -or "$($_.Exception.Message)" -notmatch '(?i)HTTP Status: 409\b|Conflict|OperationInProgress|in progress') { throw }
        }
        $until = (Get-Date).AddSeconds(120)
        $polls = 0
        while ($true) {
            $db = Invoke-SIArm -Path $path -ApiVersion '2021-11-01' -AllowNotFound
            if ($polls -gt 0) { Send-SISetupWaitProgress -What ('the database {0} to come online' -f $Name) -State $(if ($db) { [string](Get-SISetupArmProp $db @('properties', 'status')) } else { 'not there yet' }) }   # #876
            if ($db -and [string](Get-SISetupArmProp $db @('properties', 'status')) -eq 'Online') {
                $db | Add-Member -NotePropertyName SIExisted -NotePropertyValue $false -Force
                return $db
            }
            $polls++
            if (-not $db -and ((Get-Date) -ge $until -or $polls -ge 12)) { break }                 # not there: send it again
            if ((Get-Date) -ge $deadline -or $polls -ge 180) { throw ("the database {0} is not online {1} minutes after it was created (status '{2}')" -f $Name, 30, [string](Get-SISetupArmProp $db @('properties', 'status'))) }
            if ($Sleep) { & $Sleep 10 } else { Start-Sleep -Seconds 10 }
        }
    }
    throw ("Azure accepted the request to create the database {0} three times and did not create it -- see the activity log of the resource group for its reason" -f $Name)
}

# =====================================================================================================================
#  The image build (az acr build) -- phase 1's REST ACR build, ONE implementation for the updater and setup
# =====================================================================================================================

function Invoke-SIAcrRestBuild {
    <#
        `az acr build --registry <acr> --image <name:tag> --file <Dockerfile> <folder>` over REST, as setup's own sign-in:
        a thin wrapper over setup\_shared\SI-AcrBuild.ps1 (#521 phase 1 -- packs the folder with the .dockerignore honoured,
        uploads it to the registry's SAS without a bearer token, schedules the build, image names registry-relative) through
        the REST seam of setup\_shared\SI-UpdateRest.ps1 (New-SIUpdateRestSeam: every token from Get-SIAzureToken, i.e. the
        person / support session / app setup signed in as). Polls the run to its end unless -NoWait.
        Returns @{ Ok; Status; RunId; Seconds; Bytes; Files; Images }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$RegistryName,
          [Parameter(Mandatory)][string]$SourcePath, [Parameter(Mandatory)][string[]]$ImageNames, [Parameter(Mandatory)][string]$DockerFilePath,
          [int]$TimeoutSeconds = 1800, [switch]$NoWait, [scriptblock]$OnPoll, [scriptblock]$Sleep, [scriptblock]$Rest, [int]$PollSeconds = 15)
    if (-not (Get-Command -Name Invoke-SIAcrQueueBuild -ErrorAction Ignore)) { . (Join-Path $PSScriptRoot 'SI-AcrBuild.ps1') }
    if (-not $Rest) { $Rest = New-SIUpdateRestSeam }
    $started = Get-Date
    $q = Invoke-SIAcrQueueBuild -Rest $Rest -SubscriptionId $SubscriptionId -AcrName $RegistryName -ResourceGroup $ResourceGroup `
            -ContextPath $SourcePath -Image (@($ImageNames)[0]) -DockerfilePath $DockerFilePath -TimeoutSeconds $TimeoutSeconds
    if (-not $q.RunId) { throw ('The registry {0} accepted no build run for {1}.' -f $RegistryName, (@($ImageNames)[0])) }
    $out = [ordered]@{ Ok = $true; Status = 'Queued'; RunId = [string]$q.RunId; Seconds = 0; Bytes = $q.Bytes; Files = $q.Files; Images = @($q.Image) }
    if ($NoWait) { return [pscustomobject]$out }
    $deadline = $started.AddSeconds($TimeoutSeconds)
    $status = 'Queued'
    while ((Get-Date) -lt $deadline) {
        $s = Get-SIAcrRunStatus -Rest $Rest -Registry $q.Registry -RunId $q.RunId
        if ($s) { $status = $s }
        if ($OnPoll) { try { & $OnPoll $status } catch { } }
        Send-SISetupWaitProgress -What ('the container image build in the registry {0}' -f $RegistryName) -State $status -SinceUtc $started.ToUniversalTime()   # #876: at most once a minute
        if (@('Succeeded', 'Failed', 'Canceled', 'Cancelled', 'Error', 'Timeout') -contains $status) { break }
        if ($Sleep) { & $Sleep $PollSeconds } else { Start-Sleep -Seconds $PollSeconds }
    }
    $out.Status = $status; $out.Ok = ($status -eq 'Succeeded'); $out.Seconds = [int]((Get-Date) - $started).TotalSeconds
    [pscustomobject]$out
}

# =====================================================================================================================
#  Microsoft Graph
# =====================================================================================================================

function Get-SITenantDirectoryCounts {
    <# The tenant's size (Graph $count, ConsistencyLevel eventual): @{ Users; Groups; ServicePrincipals; Devices }, or $null
       when it cannot be read (no directory read right). #>
    $c = @{}
    try {
        foreach ($k in @(@{ N = 'Users'; P = 'users' }, @{ N = 'Groups'; P = 'groups' }, @{ N = 'ServicePrincipals'; P = 'servicePrincipals' }, @{ N = 'Devices'; P = 'devices' })) {
            $r = Invoke-SIAzRestRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/{0}/$count' -f $k.P) -Audience Graph -Headers @{ ConsistencyLevel = 'eventual' } -What 'Microsoft Graph count'
            $t = ([string]$r.Content).Trim().TrimStart([char]0xFEFF)
            $n = 0L
            if (-not [long]::TryParse($t, [ref]$n)) { return $null }
            $c[$k.N] = $n
        }
    } catch { return $null }
    $c
}
