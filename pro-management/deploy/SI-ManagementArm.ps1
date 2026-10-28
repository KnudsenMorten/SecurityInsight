#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE PRO WEB APP'S DEPLOY OVER REST (no az CLI, no PowerShell module; owner 2026-10-10: "we can NOT
    have any az cli or ps modules in si or pim", no exceptions). Dot-sourced by the scripts of pro-management\deploy\:
    Deploy-SIManagement.ps1, New-SIManagementAppRegistration.ps1, Set-SIManagementSignInCredential.ps1 and
    Test-SIManagementDeployment.ps1.

    It REUSES SecurityInsight's one REST layer -- nothing here talks HTTP itself:
      * setup\_shared\SI-SetupAzure.ps1   the ONE connect path (Connect-SISetupAzure: a person in Cloud Shell or the browser,
                                          the Invardia support session's TOKENS via Get-InvardiaSupportToken, an app with a
                                          certificate, a managed identity) and its token getter (Get-SIAzureToken);
      * setup\_shared\SI-SetupArm.ps1     Invoke-SIArm wrappers (identities, registry, role assignments, SQL firewall,
                                          provisioning waits) and Invoke-SIAcrRestBuild;
      * setup\_shared\SI-AcrBuild.ps1     the registry's own build over ARM (listBuildSourceUploadUrl -> SAS PUT ->
                                          scheduleRun -> poll), loaded by Invoke-SIAcrRestBuild;
      * engine\_shared\SI-AzRest.ps1      Invoke-SIArm / Invoke-SILaQuery (loaded by SI-SetupAzure.ps1).
    Each library is loaded only when it is not there yet: a caller (the guided install) or a test that already has it --
    or a test's mock of one of its functions -- is never replaced.

    What this file adds: the Container Apps of the web app and the MCP server on api 2025-07-01, READ-MODIFY-WRITE of whole
    objects (a template PATCH replaces the container ARRAY, so every container is sent as read; the configuration is a JSON
    merge patch, so its secrets stay), the probe job's body, the job log read from Log Analytics, and the token rule of the
    deploy scripts (the guided install's own sign-in first -- $global:SI_InstallTokenProvider -- else setup's sign-in).
    The body builders are PURE (tested offline). PS 5.1 safe; pwsh 7.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

if (-not (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::GetFullPath([IO.Path]::Combine($PSScriptRoot, '..', '..', 'setup', '_shared', 'SI-SetupAzure.ps1')))
}
# ALWAYS loaded, also when the caller has its functions already (#616, a new customer install 2026-10-12): SI-SetupArm.ps1
# keeps its API versions as script values, and a script started by the guided install has its own script scope -- with
# the functions inherited and the file not loaded here, the registry was read without an api-version (HTTP 400).
. ([IO.Path]::GetFullPath([IO.Path]::Combine($PSScriptRoot, '..', '..', 'setup', '_shared', 'SI-SetupArm.ps1')))

function Get-SIManagementAppApi {
    <# PURE. The Microsoft.App api version of the Pro web app's deploy (container apps, jobs, executions, environments). #>
    '2025-07-01'
}

# =====================================================================================================================
#  Sign-in and tokens
# =====================================================================================================================

function Connect-SIManagementRest {
    <#
        Signs this process in for a deploy script, over SecurityInsight's own REST sign-in: an existing sign-in of this
        process is reused (the guided install's, an earlier script's); else Connect-SISetupAzure (an Invardia support session
        gives its tokens; else a person -- Cloud Shell or the browser). Never az, never a module. A sign-in to ANOTHER tenant
        than -TenantId is refused. Returns the context (Get-SISetupAzureContext).
    #>
    param([string]$TenantId, [string]$SubscriptionId)
    $ctx = Get-SISetupAzureContext
    if (-not $ctx) {
        $a = @{}
        if ($TenantId) { $a.TenantId = $TenantId }
        if ($SubscriptionId) { $a.SubscriptionId = $SubscriptionId }
        $ctx = Connect-SISetupAzure @a
    }
    $tid = ''
    if ($ctx -and $ctx.Tenant) { $tid = [string]$ctx.Tenant.Id }
    if ($TenantId -and $tid -and ($tid -ne $TenantId)) {
        throw ('This process is signed in to tenant {0}, not {1}. Sign in to tenant {1} and run the same command again.' -f $tid, $TenantId)
    }
    $ctx
}

function Get-SIManagementToken {
    <#
        A bearer token for -Resource (https://graph.microsoft.com, https://database.windows.net/, ...): the guided install's
        own sign-in first ($global:SI_InstallTokenProvider -- the person or app that runs the install), else setup's sign-in
        (Get-SISetupAccessToken). Never printed.
    #>
    param([Parameter(Mandatory)][string]$Resource)
    $tp = Get-Variable -Scope Global -Name SI_InstallTokenProvider -ValueOnly -ErrorAction Ignore
    if ($tp -is [scriptblock]) {
        $t = [string](& $tp $Resource)
        if ("$t".Trim()) { return "$t".Trim() }
    }
    ([string](Get-SISetupAccessToken -Resource $Resource)).Trim()
}

function ConvertFrom-SIManagementJwt {
    <# PURE. The claims of a JWT access token (its payload), or $null when the text is not one. #>
    param([AllowEmptyString()][string]$Token)
    $p = "$Token".Split('.')
    if ($p.Count -lt 2 -or -not $p[1]) { return $null }
    $s = $p[1].Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } 1 { return $null } }
    try { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) | ConvertFrom-Json } catch { $null }
}

function Assert-SIManagementTokenTenant {
    <# PURE. Throws when -Token is a JWT whose tenant (tid) is not -TenantId; a token that cannot be read is not judged. #>
    param([AllowEmptyString()][string]$Token, [Parameter(Mandatory)][string]$TenantId, [string]$What = 'The sign-in')
    $c = ConvertFrom-SIManagementJwt -Token $Token
    if (-not $c -or -not $c.PSObject.Properties['tid']) { return }
    $tid = [string]$c.tid
    if ($tid -and $tid -ne $TenantId) { throw ('{0} is for tenant {1}, not {2}.' -f $What, $tid, $TenantId) }
}

# =====================================================================================================================
#  Container Apps (the web app and the MCP server) -- PURE body builders
# =====================================================================================================================

function ConvertTo-SIManagementEnvEntry {
    <# PURE. One app setting 'N=V' (or 'N=secretref:S') as an ARM env entry. #>
    param([Parameter(Mandatory)][string]$Setting)
    $p = $Setting -split '=', 2
    $v = $(if ($p.Count -gt 1) { $p[1] } else { '' })
    if ($v.StartsWith('secretref:')) { return [ordered]@{ name = $p[0]; secretRef = $v.Substring(10) } }
    [ordered]@{ name = $p[0]; value = $v }
}

function ConvertTo-SIManagementHashtable {
    <# PURE. An ARM object read back (PSCustomObject) as ordered dictionaries + arrays, so it can be changed and sent back. #>
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [ValueType]) { return $InputObject }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}; foreach ($k in @($InputObject.Keys)) { $h[[string]$k] = ConvertTo-SIManagementHashtable $InputObject[$k] }; return $h
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $l = New-Object System.Collections.Generic.List[object]
        foreach ($i in $InputObject) { $l.Add((ConvertTo-SIManagementHashtable $i)) }
        return , $l.ToArray()
    }
    $h = [ordered]@{}
    foreach ($pp in $InputObject.PSObject.Properties) { $h[$pp.Name] = ConvertTo-SIManagementHashtable $pp.Value }
    $h
}

function Get-SIManagementProp {
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

function Get-SIManagementConsumptionProfile {
    <# PURE. The name of the environment's Consumption workload profile ('' when it has no workload profiles). #>
    param($Environment)
    foreach ($w in @(Get-SIManagementProp $Environment @('properties', 'workloadProfiles'))) {
        if ($w -and [string](Get-SIManagementProp $w @('workloadProfileType')) -eq 'Consumption') { return [string](Get-SIManagementProp $w @('name')) }
    }
    ''
}

function New-SIManagementContainerAppBody {
    <#
        PURE. A NEW container app (PUT): one container on port 8080 with -Ingress internal / external, the user-assigned
        identity attached for the registry pull AND the data, 1-2 replicas, session affinity with -Sticky, the app settings
        (-Settings 'N=V'). No secret anywhere. What `az containerapp create` sent.
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$EnvironmentId,
          [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$RegistryServer, [Parameter(Mandatory)][string]$IdentityId,
          [Parameter(Mandatory)][bool]$External, [string[]]$Settings = @(), [switch]$Sticky, [string]$Cpu = '0.5', [string]$Memory = '1Gi',
          [int]$TargetPort = 8080, [string]$WorkloadProfileName = '')
    $ingress = [ordered]@{ external = $External; targetPort = $TargetPort; transport = 'auto'; allowInsecure = $false }
    if ($Sticky) { $ingress.stickySessions = [ordered]@{ affinity = 'sticky' } }
    $envList = @(@($Settings | Where-Object { $_ }) | ForEach-Object { ConvertTo-SIManagementEnvEntry -Setting ([string]$_) })
    $container = [ordered]@{ name = $Name; image = $Image; env = $envList
                             resources = [ordered]@{ cpu = [double]::Parse($Cpu, [Globalization.CultureInfo]::InvariantCulture); memory = $Memory } }
    $uai = [ordered]@{}; $uai[$IdentityId] = [ordered]@{}
    $props = [ordered]@{
        environmentId = $EnvironmentId
        configuration = [ordered]@{ activeRevisionsMode = 'Single'; ingress = $ingress; registries = @([ordered]@{ server = $RegistryServer; identity = $IdentityId }) }
        template      = [ordered]@{ containers = @($container); scale = [ordered]@{ minReplicas = 1; maxReplicas = 2 } }
    }
    if ($WorkloadProfileName) { $props.workloadProfileName = $WorkloadProfileName }
    [ordered]@{ location = $Location; identity = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $uai }; properties = $props }
}

function Merge-SIManagementContainerAppUpdate {
    <#
        PURE. The PATCH body that changes an EXISTING container app, read whole (-App) -- what `az containerapp identity
        assign` + `registry set` + `ingress enable` + `ingress sticky-sessions set` + `update --image --set-env-vars /
        --remove-env-vars` changed, and nothing else:
          -IdentityId        added to the app's user-assigned identities (a system-assigned one stays)
          -RegistryServer    the registry entry for that server pulls as -IdentityId (other registries stay)
          -External          ingress external true / false, port -TargetPort, transport auto (other ingress settings stay:
                             the configuration is a JSON MERGE patch)
          -Sticky            session affinity
          -Image / -SetEnv / -RemoveEnv   the FIRST container (image; settings set / overwritten / dropped by name)
        The template is sent WHOLE -- a template PATCH replaces the container array, so every container goes as read, and
        the revision suffix is dropped (a reused suffix is refused). Secrets are not part of it and stay. Returns $null
        when nothing would change.
    #>
    param([Parameter(Mandatory)]$App, [string]$IdentityId, [string]$RegistryServer, [AllowNull()][object]$External = $null,
          [int]$TargetPort = 8080, [switch]$Sticky, [string]$Image, [string[]]$SetEnv = @(), [string[]]$RemoveEnv = @())
    $body = [ordered]@{}
    $props = [ordered]@{}
    $cfg = [ordered]@{}

    if ($IdentityId) {
        $idn = Get-SIManagementProp $App @('identity')
        $t = [string](Get-SIManagementProp $idn @('type'))
        $uai = [ordered]@{}; $uai[$IdentityId] = [ordered]@{}
        $body.identity = [ordered]@{ type = $(if ($t -match '(?i)SystemAssigned') { 'SystemAssigned,UserAssigned' } else { 'UserAssigned' }); userAssignedIdentities = $uai }
    }
    if ($RegistryServer -and $IdentityId) {
        $regs = @(@(Get-SIManagementProp $App @('properties', 'configuration', 'registries')) | Where-Object { $_ -and [string](Get-SIManagementProp $_ @('server')) -ne $RegistryServer } | ForEach-Object { ConvertTo-SIManagementHashtable $_ })
        $cfg.registries = @($regs) + @([ordered]@{ server = $RegistryServer; identity = $IdentityId })
    }
    if ($null -ne $External -or $Sticky) {
        $ing = [ordered]@{}
        if ($null -ne $External) { $ing.external = [bool]$External; $ing.targetPort = $TargetPort; $ing.transport = 'auto' }
        if ($Sticky) { $ing.stickySessions = [ordered]@{ affinity = 'sticky' } }
        $cfg.ingress = $ing
    }
    if ($cfg.Count) { $props.configuration = $cfg }

    if ($Image -or @($SetEnv | Where-Object { $_ }).Count -or @($RemoveEnv | Where-Object { $_ }).Count) {
        $tpl = ConvertTo-SIManagementHashtable (Get-SIManagementProp $App @('properties', 'template'))
        if ($null -eq $tpl) { $tpl = [ordered]@{} }
        $cs = @(@($(if ($tpl.Contains('containers')) { $tpl.containers } else { @() })) | Where-Object { $_ })
        if (-not $cs.Count) { throw ('The container app {0} has no container to change.' -f [string](Get-SIManagementProp $App @('name'))) }
        $c = $cs[0]
        $changed = $false
        if ($Image -and [string]$c.image -ne $Image) { $c.image = $Image; $changed = $true }
        $envList = New-Object System.Collections.Generic.List[object]
        foreach ($x in @($(if ($c.Contains('env')) { $c.env } else { @() }) | Where-Object { $_ })) { $envList.Add($x) }
        foreach ($a in @($SetEnv | Where-Object { $_ })) {
            $e = ConvertTo-SIManagementEnvEntry -Setting ([string]$a)
            $i = -1; for ($k = 0; $k -lt $envList.Count; $k++) { if ([string]$envList[$k].name -eq [string]$e.name) { $i = $k } }
            if ($i -ge 0) {
                $old = $envList[$i]
                if ([string](Get-SIManagementProp $old @('value')) -ne [string](Get-SIManagementProp $e @('value')) -or [string](Get-SIManagementProp $old @('secretRef')) -ne [string](Get-SIManagementProp $e @('secretRef'))) { $envList[$i] = $e; $changed = $true }
            } else { $envList.Add($e); $changed = $true }
        }
        $drop = @($RemoveEnv | Where-Object { $_ })
        if ($drop.Count) {
            $keep = @($envList | Where-Object { $drop -notcontains [string]$_.name })
            if ($keep.Count -ne $envList.Count) { $changed = $true }
            $envList = New-Object System.Collections.Generic.List[object]; foreach ($x in $keep) { $envList.Add($x) }
        }
        if ($changed -or $props.Count -or $body.Contains('identity')) {
            $c.env = $envList.ToArray()
            $cs[0] = $c
            $tpl.containers = $cs
            if ($tpl.Contains('revisionSuffix')) { $tpl.Remove('revisionSuffix') }
            $props.template = $tpl
        }
    }
    if ($props.Count) { $body.properties = $props }
    if (-not $body.Count) { return $null }
    $body
}

# =====================================================================================================================
#  #564 THE SECURITY ORDER (Invardia + PIM, customer I 2026-10-10): never a public app without sign-in, not even for a minute.
#  A new app is created with INTERNAL ingress; its sign-in is VERIFIED (ARM read-back: the Entra settings on the running
#  revision); only THEN is ingress switched to external, read back, and an anonymous request must be refused (a redirect
#  to the Entra sign-in, or 401 / 403). An app that answers anonymously is put back to internal and the deploy stops.
# =====================================================================================================================

function Get-SIManagementStageExternal {
    <# PURE. The ingress an app is WRITTEN with before its sign-in is verified: a new app, or one that is not external yet,
       internal; an app that is already external (and is wanted external) stays external -- it is not made public by this. #>
    param([AllowNull()]$Existing, [Parameter(Mandatory)][bool]$WantExternal)
    if (-not $Existing -or -not $WantExternal) { return $false }
    [bool](Get-SIManagementProp $Existing @('properties', 'configuration', 'ingress', 'external'))
}

function Test-SIManagementSignInConfigured {
    <#
        PURE. Is the app's Entra sign-in in place on what runs (the ARM read-back): the first container carries
        AzureAd__TenantId = -TenantId and AzureAd__ClientId = -SignInClientId, and Azure reports the app provisioned (and,
        when it says, running). Returns @{ Ok; Why }.
    #>
    param([AllowNull()]$App, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SignInClientId)
    if (-not $App) { return [pscustomobject]@{ Ok = $false; Why = 'the app could not be read back' } }
    $c = @(@(Get-SIManagementProp $App @('properties', 'template', 'containers')) | Where-Object { $_ }) | Select-Object -First 1
    $env = @{}
    foreach ($e in @(@(Get-SIManagementProp $c @('env')) | Where-Object { $_ })) { $env[[string](Get-SIManagementProp $e @('name'))] = [string](Get-SIManagementProp $e @('value')) }
    if ($env['AzureAd__TenantId'] -ne $TenantId) { return [pscustomobject]@{ Ok = $false; Why = ('AzureAd__TenantId is "{0}", not {1}' -f $env['AzureAd__TenantId'], $TenantId) } }
    if ($env['AzureAd__ClientId'] -ne $SignInClientId) { return [pscustomobject]@{ Ok = $false; Why = ('AzureAd__ClientId is "{0}", not {1}' -f $env['AzureAd__ClientId'], $SignInClientId) } }
    $ps = [string](Get-SIManagementProp $App @('properties', 'provisioningState'))
    if ($ps -and $ps -ne 'Succeeded') { return [pscustomobject]@{ Ok = $false; Why = ('provisioning is {0}' -f $ps) } }
    $rs = [string](Get-SIManagementProp $App @('properties', 'runningStatus'))
    # a revision that is still starting ('Processing', 'Activating') is not a refusal; a stopped or failed app is
    if ($rs -and $rs -match '(?i)^(stopped|failed|degraded)') { return [pscustomobject]@{ Ok = $false; Why = ('the app is {0}' -f $rs) } }
    [pscustomobject]@{ Ok = $true; Why = '' }
}

function Test-SIManagementAnonymousRefusedAnswer {
    <# PURE. Does an anonymous answer (status + Location) refuse the caller? A redirect to the Entra sign-in (or the app's
       own sign-in route), 401 or 403 = refused; anything else that answers (e.g. 200 with the page) = NOT refused. #>
    param([int]$StatusCode, [AllowEmptyString()][string]$Location)
    if ($StatusCode -in 401, 403) { return $true }
    if ($StatusCode -ge 300 -and $StatusCode -lt 400) { return [bool]("$Location" -match '(?i)login\.microsoftonline\.com|/signin|/account/signin|/login') }
    $false
}

function Invoke-SIManagementAnonymousProbe {
    <# One anonymous GET of -Url WITHOUT following a redirect: @{ StatusCode (0 = no answer); Location }. Test seam:
       $global:SI_ManagementProbe { param($Url) } returns that shape. #>
    param([Parameter(Mandatory)][string]$Url, [ValidateSet('GET', 'POST')][string]$Method = 'GET')
    $seam = Get-Variable -Scope Global -Name SI_ManagementProbe -ValueOnly -ErrorAction Ignore
    if ($seam -is [scriptblock]) { return (& $seam $Url $Method) }
    $resp = $null
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url); $req.Method = $Method; $req.AllowAutoRedirect = $false; $req.Timeout = 20000
        if ($Method -eq 'POST') {
            # what an MCP client sends first, without any credential: the server must answer 401 before it reads it
            $req.ContentType = 'application/json'; $req.Accept = 'application/json, text/event-stream'
            $bytes = [Text.Encoding]::UTF8.GetBytes('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"anonymous-check","version":"1"}}}')
            $req.ContentLength = $bytes.Length
            $rs = $req.GetRequestStream(); try { $rs.Write($bytes, 0, $bytes.Length) } finally { $rs.Close() }
        }
        try { $resp = $req.GetResponse() } catch { $we = $_.Exception; while ($we -and -not ($we -is [System.Net.WebException])) { $we = $we.InnerException }; if ($we -and $we.Response) { $resp = $we.Response } else { throw } }
        [pscustomobject]@{ StatusCode = [int]$resp.StatusCode; Location = [string]$resp.Headers['Location'] }
    } catch { [pscustomobject]@{ StatusCode = 0; Location = '' } }
    finally { if ($resp) { try { $resp.Close() } catch { } } }
}

function Test-SIManagementAnonymousRefused {
    <# #564: the app (just made external) refuses an anonymous caller: the web app at '/', the MCP server at '/mcp'. A few
       tries while the new address resolves. Returns @{ Refused ($true / $false / $null = no answer); StatusCode; Location }. #>
    param([Parameter(Mandatory)][string]$Fqdn, [ValidateSet('web', 'mcp')][string]$Kind = 'web', [int]$Tries = 6, [int]$WaitSec = 15)
    $url = 'https://{0}/{1}' -f $Fqdn.TrimEnd('/'), $(if ($Kind -eq 'mcp') { 'mcp' } else { '' })
    $a = $null; $code = 0
    for ($i = 1; $i -le $Tries; $i++) {
        $a = Invoke-SIManagementAnonymousProbe -Url $url
        $code = [int]$a.StatusCode
        # #616: the MCP endpoint takes POST only -- an anonymous GET is answered 405 (method not allowed), which says nothing
        # about the sign-in. Then the real question is asked: an anonymous POST, as an MCP client would send it (a new
        # customer install was closed again on the 405, 2026-10-12). Asked on EVERY try: a first answer can be slow.
        if ($Kind -eq 'mcp' -and $code -eq 405) { $a = Invoke-SIManagementAnonymousProbe -Url $url -Method POST; $code = [int]$a.StatusCode }
        # an address opened a moment ago answers 404 (no route yet) or 405 before the app itself answers: NOT READY, tried
        # again -- like no answer and a server error. Neither says anything about the sign-in.
        if ($code -gt 0 -and $code -lt 500 -and $code -ne 404 -and $code -ne 405) { break }
        if ($i -lt $Tries) { $s = Get-Variable -Scope Global -Name SI_ManagementProbeSleep -ValueOnly -ErrorAction Ignore; if ($s -is [scriptblock]) { & $s $WaitSec } else { Start-Sleep -Seconds $WaitSec } }
    }
    # ONLY a page that is served (2xx) is an anonymous answer; 401 / 403 / a redirect to the sign-in is a refusal;
    # everything else (no answer, 404 / 405, a server error, any other status) is "could not be judged" -- never "open".
    $refused = if ($code -ge 200 -and $code -lt 300) { $false }
               elseif ($code -gt 0 -and $code -lt 500 -and (Test-SIManagementAnonymousRefusedAnswer -StatusCode $code -Location ([string]$a.Location))) { $true }
               else { $null }
    [pscustomobject]@{ Refused = $refused; StatusCode = $code; Location = [string]$a.Location; Url = $url }
}

function Set-SIManagementIngressExternal {
    <# #564: ingress external true / false on an existing app (a JSON merge PATCH of the ingress only), waited for and READ
       BACK; throws when Azure does not show what was asked. Returns the app. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][bool]$External, [scriptblock]$Sleep)
    # read through Get-SIManagementContainerApp, the deploy's ONE read of an app (by its path parts)
    if ($Path -notmatch '(?i)/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.App/containerApps/([^/?]+)') { throw ('Not a container app id: {0}' -f $Path) }
    $__sub = $Matches[1]; $__rg = $Matches[2]; $__name = $Matches[3]
    $app = Get-SIManagementContainerApp -SubscriptionId $__sub -ResourceGroup $__rg -Name $__name
    if (-not $app) { throw ('The container app {0} was not found.' -f (($Path -split '/')[-1])) }
    $body = Merge-SIManagementContainerAppUpdate -App $app -External $External
    $app = Invoke-SIManagementArmWrite -Method PATCH -Path $Path -Body $body -Sleep $Sleep
    $back = Get-SIManagementContainerApp -SubscriptionId $__sub -ResourceGroup $__rg -Name $__name
    $is = [bool](Get-SIManagementProp $back @('properties', 'configuration', 'ingress', 'external'))
    if ($is -ne $External) { throw ('The container app {0} reads back {1} ingress after it was set to {2}.' -f (($Path -split '/')[-1]), $(if ($is) { 'external' } else { 'internal' }), $(if ($External) { 'external' } else { 'internal' })) }
    $back
}

function Close-SIManagementAppIngress {
    <# Puts an app back to INTERNAL ingress and says whether that WORKED: '' when Azure shows it internal, else the reason
       (after three tries, 20 s apart). The caller's message must never say "nothing is public" on a close that failed. #>
    param([Parameter(Mandatory)][string]$Path, [scriptblock]$Sleep)
    $why = ''
    for ($i = 1; $i -le 3; $i++) {
        try { $null = Set-SIManagementIngressExternal -Path $Path -External $false -Sleep $Sleep; return '' }
        catch { $why = [string]$_.Exception.Message }
        if ($i -lt 3) { if ($Sleep) { & $Sleep 20 } else { Start-Sleep -Seconds 20 } }
    }
    if (-not $why) { $why = 'no reason given' }
    $why
}

function Get-SIManagementClosedText {
    <# PURE. The sentence after a close: what is true about the app now. #>
    param([AllowEmptyString()][string]$CloseError, [Parameter(Mandatory)][string]$Path)
    if (-not $CloseError) { return 'It was put back to INTERNAL ingress: nothing is public.' }
    'IT COULD NOT BE PUT BACK TO INTERNAL INGRESS ({0}) -- THE APP IS STILL REACHABLE FROM THE INTERNET. Close it now: Azure portal > Container Apps > {1} > Ingress > Limited to Container Apps Environment > Save.' -f $CloseError, (($Path -split '/')[-1])
}

# =====================================================================================================================
#  Container Apps -- the calls (Invoke-SIArm: setup's sign-in, the one HTTP seam)
# =====================================================================================================================

function Get-SIManagementContainerAppPath {
    <# PURE. The ARM id of a container app. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name)
    '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/containerApps/{2}' -f $SubscriptionId, $ResourceGroup, $Name
}

function Get-SIManagementContainerApp {
    <# `az containerapp show`: the app as ARM returns it; $null when it does not exist. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name)
    Invoke-SIArm -Path (Get-SIManagementContainerAppPath $SubscriptionId $ResourceGroup $Name) -ApiVersion (Get-SIManagementAppApi) -AllowNotFound
}

function Invoke-SIManagementArmWrite {
    <#
        One PUT / PATCH of a Microsoft.App resource, then waits until Azure has provisioned it; returns the resource as Azure
        has it. A refusal because a NEW identity's registry pull right has not reached the registry yet (the role assignment
        was made seconds before) is waited out (-IdentityWaitSeconds), never a failure. -Sleep: tests.
    #>
    param([Parameter(Mandatory)][ValidateSet('PUT', 'PATCH')][string]$Method, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Body,
          [int]$IdentityWaitSeconds = 600, [scriptblock]$Sleep)
    $api = Get-SIManagementAppApi
    $until = (Get-Date).AddSeconds($IdentityWaitSeconds)
    while ($true) {
        try { $null = Invoke-SIArm -Method $Method -Path $Path -ApiVersion $api -Body $Body; break }
        catch {
            $text = [string]$_.Exception.Message
            $notReady = [bool]("$text" -match '(?i)unable to pull image using Managed identity|identity .* (is not|has not been) (authorized|granted).*(pull|registry)|UNAUTHORIZED: authentication required')
            if (-not $notReady -or (Get-Date) -ge $until) { throw }
            Write-Host '       the new identity''s registry pull right has not reached the registry yet -- waiting 30 s and trying again ...' -ForegroundColor DarkYellow
            if ($Sleep) { & $Sleep 30 } else { Start-Sleep -Seconds 30 }
        }
    }
    # until it EXISTS and is provisioned: a 404 right after the write is "not yet"; a deadline or a failed app throws with
    # what Azure said -- never a silent $null that would skip the sign-in check and the opening of the app
    Wait-SIArmResourceReady -Path $Path -ApiVersion $api -TimeoutSec 900 -PollSec 5 -Sleep $Sleep -What ('the container app {0}' -f (($Path -split '/')[-1]))
}

function Set-SIManagementContainerAppEnv {
    <#
        `az containerapp update --set-env-vars ... / --remove-env-vars ...` over ARM, READ-MODIFY-WRITE: the app read whole,
        the settings changed on its first container (others kept), the WHOLE template written back by PATCH. Returns $true
        when it changed something, $false when the app already had it. A missing app throws.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [string[]]$SetEnv = @(), [string[]]$RemoveEnv = @(), [scriptblock]$Sleep)
    $app = Get-SIManagementContainerApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    if (-not $app) { throw ("The container app '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroup) }
    $body = Merge-SIManagementContainerAppUpdate -App $app -SetEnv $SetEnv -RemoveEnv $RemoveEnv
    if (-not $body) { return $false }
    $null = Invoke-SIManagementArmWrite -Method PATCH -Path ([string]$app.id) -Body $body -Sleep $Sleep
    $true
}

# =====================================================================================================================
#  The probe job (Test-SIManagementDeployment.ps1) and its log
# =====================================================================================================================

function New-SIManagementProbeJobBody {
    <#
        PURE. A one-off MANUAL Container Apps job (no retry, one replica) on the user-assigned identity, pulling from the
        registry as that identity -- what `az containerapp job create --trigger-type Manual ...` sent. -Secrets 'name=value'
        become job secrets (never printed); -Env 'N=V' / 'N=secretref:S'.
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$EnvironmentId,
          [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$RegistryServer, [Parameter(Mandatory)][string]$IdentityId,
          [string[]]$Env = @(), [string[]]$Secrets = @(), [int]$ReplicaTimeout = 900, [string]$Cpu = '0.5', [string]$Memory = '1Gi')
    $sec = @(@($Secrets | Where-Object { $_ }) | ForEach-Object { $p = ([string]$_) -split '=', 2; [ordered]@{ name = $p[0]; value = $(if ($p.Count -gt 1) { $p[1] } else { '' }) } })
    $envList = @(@($Env | Where-Object { $_ }) | ForEach-Object { ConvertTo-SIManagementEnvEntry -Setting ([string]$_) })
    $uai = [ordered]@{}; $uai[$IdentityId] = [ordered]@{}
    $cfg = [ordered]@{
        triggerType = 'Manual'; replicaTimeout = $ReplicaTimeout; replicaRetryLimit = 0
        manualTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 }
        registries = @([ordered]@{ server = $RegistryServer; identity = $IdentityId })
    }
    if ($sec.Count) { $cfg.secrets = $sec }
    [ordered]@{
        location = $Location
        identity = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $uai }
        properties = [ordered]@{
            environmentId = $EnvironmentId
            configuration = $cfg
            template = [ordered]@{ containers = @([ordered]@{ name = $Name; image = $Image; env = $envList
                                                             resources = [ordered]@{ cpu = [double]::Parse($Cpu, [Globalization.CultureInfo]::InvariantCulture); memory = $Memory } }) }
        }
    }
}

function Get-SIManagementJobLogQuery {
    <#
        PURE. The KQL that reads one job execution's console lines from Log Analytics, oldest first: the resource-specific
        table (ContainerAppConsoleLogs, environments with logs through Azure Monitor) and the classic one
        (ContainerAppConsoleLogs_CL), whichever exists. The execution name is reduced to [A-Za-z0-9-].
    #>
    param([Parameter(Mandatory)][string]$Execution, [int]$Hours = 6)
    $e = $Execution -replace '[^A-Za-z0-9\-]', ''
    "union isfuzzy=true (ContainerAppConsoleLogs | where TimeGenerated > ago($($Hours)h) | where ContainerGroupName startswith '$e' | project TimeGenerated, L = tostring(Log)), (ContainerAppConsoleLogs_CL | where TimeGenerated > ago($($Hours)h) | where ContainerGroupName_s startswith '$e' | project TimeGenerated, L = tostring(Log_s)) | order by TimeGenerated asc"
}

function Get-SIManagementJobExecutionLog {
    <# One job execution's console lines from the workspace (-WorkspaceId = its customer id), over the Log Analytics REST API
       (Invoke-SILaQuery, setup's sign-in -- needs Log Analytics Reader). @() when there is nothing yet; throws when the
       query is refused. #>
    param([Parameter(Mandatory)][string]$WorkspaceId, [Parameter(Mandatory)][string]$Execution, [int]$Hours = 6)
    $r = Invoke-SILaQuery -WorkspaceId $WorkspaceId -Query (Get-SIManagementJobLogQuery -Execution $Execution -Hours $Hours)
    @(@($r.Results) | ForEach-Object { [string](Get-SIManagementProp $_ @('L')) })
}
