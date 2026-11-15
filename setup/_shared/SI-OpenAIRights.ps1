<#
    #1257 AI WITHOUT A KEY -- THE RIGHT THAT LETS THE ENGINE (AND THE WEB CHAT) SIGN IN TO AZURE OPENAI: CHECKED, NEVER GRANTED.

    The engines call Azure OpenAI as the ENGINE'S OWN IDENTITY (engine/_shared/SI-OpenAIAuth.ps1); the web chat calls it as
    the web identity (pro-management/src/SI.Management.Core/ChatService.cs, a TokenCredential). Both need the built-in role
    "Cognitive Services OpenAI User" (5e0bd9bd-7b93-4f28-af87-19fc36ad61bd) on the customer's Azure OpenAI resource -- the
    resource named by the OpenAI_endpoint setting, and ONLY when that setting is set (si-identity-rights.json:
    engine.azure.CognitiveServicesOpenAIUser, web.azure.CognitiveServicesOpenAIUser -- the web one a named exception of
    SECURE-WEB-1: web chat inference, scoped to the chat resource).

    WHO GRANTS IT: the customer, or Invardia on the control plane (owner 2026-11-15: "only modern and secure"). SecurityInsight
    NEVER writes a role assignment for it: only GET is sent through the seam below (tests/pester/SIv3-OpenAIRights.Tests.ps1
    asserts it). The review of the first #1257 build removed the grant its converge made with the installer's / the updater's
    rights.

    Get-SIOpenAIRightsState -- READ ONLY, run by the guided install's web step and by the updater on every update: the
    resource is found from the endpoint (its Azure OpenAI account in the subscription), each identity's assignments on it are
    read; a missing one is a SUPPORT STEP (one plain line: who needs which role on which resource, and where in the portal) --
    never a failed run, never a stop. NEVER throws; a read that fails is said ("not checked").

    Test-SIOpenAIAccessPaths -- the check setup\Validate-SIOpenAI.ps1 runs: which way of signing in works (the key, an Entra
    token, the engine's right on the resource) and the one plain verdict.

    Seam: -Arm { param([string]$Method, [string]$Path, [string]$ApiVersion, $Body) } -> the parsed answer (GET of a list: the
    object with .value; a 404 on GET: $null); anything else that is not a success THROWS (its message carries the status).
#>

function Get-SIOpenAIUserRoleGuid { '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd' }
function Get-SIOpenAIRightsApi { @{ Accounts = '2023-05-01'; Roles = '2022-04-01'; Apps = '2024-03-01' } }

function Get-SIOpenAIEndpointHost {
    <# PURE. The lower-case host of an Azure OpenAI endpoint (a base or a full request URI), '' when it is not an https address. #>
    param([AllowEmptyString()][string]$Endpoint = '')
    $u = $null
    if (-not [Uri]::TryCreate("$Endpoint".Trim(), [UriKind]::Absolute, [ref]$u) -or $u.Scheme -ne 'https') { return '' }
    $u.Host.ToLowerInvariant()
}

function Find-SIOpenAIAccountForEndpoint {
    <# PURE. Of -Accounts (ARM Microsoft.CognitiveServices/accounts objects) the one -Endpoint names: the host of its endpoint,
       of one of its endpoints, or its custom subdomain (the first label of the host). $null when none matches. #>
    param([object[]]$Accounts = @(), [AllowEmptyString()][string]$Endpoint = '')
    $h = Get-SIOpenAIEndpointHost -Endpoint $Endpoint
    if (-not $h) { return $null }
    $label = ($h -split '\.')[0]
    foreach ($a in @($Accounts | Where-Object { $_ })) {
        $p = $a.properties
        if (-not $p) { continue }
        $hosts = New-Object System.Collections.Generic.List[string]
        if ($p.PSObject.Properties['endpoint'] -and $p.endpoint) { $hosts.Add((Get-SIOpenAIEndpointHost -Endpoint ([string]$p.endpoint))) }
        if ($p.PSObject.Properties['endpoints'] -and $p.endpoints) { foreach ($e in @($p.endpoints.PSObject.Properties)) { $hosts.Add((Get-SIOpenAIEndpointHost -Endpoint ([string]$e.Value))) } }
        if ($hosts -contains $h) { return $a }
        if ($p.PSObject.Properties['customSubDomainName'] -and ([string]$p.customSubDomainName).ToLowerInvariant() -eq $label) { return $a }
    }
    $null
}

function Test-SIScopeCovers {
    <# PURE. $true when an assignment at -Scope applies to -ResourceId (the resource itself or a parent scope of it). #>
    param([string]$Scope, [string]$ResourceId)
    $s = "$Scope".Trim().TrimEnd('/').ToLowerInvariant(); $r = "$ResourceId".Trim().TrimEnd('/').ToLowerInvariant()
    if (-not $s -or -not $r) { return $false }
    ($s -eq '/') -or ($r -eq $s) -or $r.StartsWith($s + '/')
}

function Get-SIOpenAIRightsPlan {
    <# PURE. Which of -Principals (@{ PrincipalId; Name }) hold "Cognitive Services OpenAI User" on -ResourceId already (at it
       or above it), from -Assignments (ARM roleAssignment objects): @{ Present = @(principal); Missing = @(principal) }. #>
    param([object[]]$Assignments = @(), [object[]]$Principals = @(), [Parameter(Mandatory)][string]$ResourceId)
    $role = Get-SIOpenAIUserRoleGuid
    $present = New-Object System.Collections.Generic.List[object]; $missing = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($Principals | Where-Object { $_ -and [string]$_.PrincipalId })) {
        $pid_ = ([string]$p.PrincipalId).ToLowerInvariant()
        $have = @($Assignments | Where-Object {
            $_ -and $_.properties -and ([string]$_.properties.principalId).ToLowerInvariant() -eq $pid_ -and
            (([string]$_.properties.roleDefinitionId) -split '/')[-1].ToLowerInvariant() -eq $role -and
            (Test-SIScopeCovers -Scope ([string]$_.properties.scope) -ResourceId $ResourceId) })
        if ($have.Count) { $present.Add($p) } else { $missing.Add($p) }
    }
    [pscustomobject]@{ Present = $present.ToArray(); Missing = $missing.ToArray() }
}

function Get-SIOpenAIRightsPrincipals {
    <#
        PURE. The principals that need the right, from the install's container apps / jobs (ARM objects):
          engine -- every identity of a JOB named like the engine identity (id-si-engine, the old uami-securityinsight, or an
                    old id-si-<ring>-<edition>-<host>); a job's system-assigned identity is never taken (the engine's is a
                    user-assigned one);
          web    -- the identities of the web app -WebAppName (web chat inference; the named exception).
        @{ PrincipalId; Name ('engine' | 'web'); Identity } -- one per principal.
    #>
    param([object[]]$Jobs = @(), [object[]]$Apps = @(), [string]$WebAppName = 'ca-si-management')
    $out = New-Object System.Collections.Generic.List[object]; $seen = @{}
    $isEngine = { param([string]$n) $n -eq 'id-si-engine' -or $n -eq 'uami-securityinsight' -or $n -match '^id-si-(r0|r1|r2|prod)-(community|pro)-(ca|vm)$' }
    foreach ($j in @($Jobs | Where-Object { $_ })) {
        $id = $j.identity
        if (-not $id -or -not $id.PSObject.Properties['userAssignedIdentities'] -or -not $id.userAssignedIdentities) { continue }
        foreach ($u in @($id.userAssignedIdentities.PSObject.Properties)) {
            $name = (([string]$u.Name) -split '/')[-1]
            $p = ([string]$u.Value.principalId).ToLowerInvariant()
            if (-not $p -or $seen.ContainsKey($p) -or -not (& $isEngine $name.ToLowerInvariant())) { continue }
            $seen[$p] = $true; $out.Add([pscustomobject]@{ PrincipalId = $p; Name = 'engine'; Identity = $name })
        }
    }
    foreach ($a in @($Apps | Where-Object { $_ -and [string]$_.name -eq $WebAppName })) {
        $id = $a.identity
        if (-not $id) { continue }
        if ($id.PSObject.Properties['userAssignedIdentities'] -and $id.userAssignedIdentities) {
            foreach ($u in @($id.userAssignedIdentities.PSObject.Properties)) {
                $p = ([string]$u.Value.principalId).ToLowerInvariant()
                if (-not $p -or $seen.ContainsKey($p)) { continue }
                $seen[$p] = $true; $out.Add([pscustomobject]@{ PrincipalId = $p; Name = 'web'; Identity = (([string]$u.Name) -split '/')[-1] })
            }
        }
    }
    $out.ToArray()
}

function Resolve-SIOpenAIEndpointSetting {
    <# PURE. The install's OpenAI_endpoint: the Pro setting row (cfg.Setting: Name / ValueJson), else a job's OPENAI_ENDPOINT,
       else the web app's Chat__Endpoint. '' when none is set (then no right is needed). #>
    param([object[]]$SettingRows = @(), [object[]]$Jobs = @(), [object[]]$Apps = @())
    foreach ($r in @($SettingRows | Where-Object { $_ -and [string]$_.Name -eq 'OpenAI_endpoint' })) {
        $v = [string]$r.ValueJson
        try { $j = $v | ConvertFrom-Json -ErrorAction Stop; if ($j -is [string]) { $v = $j } } catch { }
        $v = $v.Trim().Trim('"')
        if ($v) { return $v }
    }
    foreach ($set in @(@{ Items = $Jobs; Env = 'OPENAI_ENDPOINT' }, @{ Items = $Apps; Env = 'Chat__Endpoint' })) {
        foreach ($x in @($set.Items | Where-Object { $_ })) {
            foreach ($c in @($x.properties.template.containers)) {
                foreach ($e in @($c.env)) { if ($e -and [string]$e.name -eq $set.Env -and "$($e.value)".Trim()) { return "$($e.value)".Trim() } }
            }
        }
    }
    ''
}

function Get-SIOpenAIGrantSupportLine {
    <# PURE. The support step for a missing right: plain, with where to give it (the customer, or the support partner on the
       control plane, gives it -- SecurityInsight never does). #>
    param([string]$Identity, [string]$Name, [string]$ResourceId, [string]$Why = '')
    $who = if ($Name -eq 'web') { 'the web app''s identity (web chat)' } else { 'the engine''s identity (AI)' }
    ('support step: give {0} {1} the role "Cognitive Services OpenAI User" on the Azure OpenAI resource {2}{3} -- Azure portal: the resource > Access control (IAM) > Add role assignment > Cognitive Services OpenAI User > Managed identity' -f $who, $Identity, $ResourceId, $(if ($Why) { " ($Why)" } else { '' }))
}

function Get-SIOpenAIRightsState {
    <#
        READ ONLY. -Endpoint: the install's OpenAI_endpoint ('' = AI not configured: nothing to do). -Principals: @{ PrincipalId;
        Name; Identity } (Get-SIOpenAIRightsPrincipals, or the guided install's own identities). -ResourceId: when the caller
        knows it (else found from the endpoint in -SubscriptionId). Reads the resource and each identity's assignments on it; a
        missing right is a support step -- nothing is ever granted here.
        @{ Ok; State (not-configured | present | missing | not-checked); Lines; Present; Support; ResourceId }. NEVER throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [string]$SubscriptionId = '', [AllowEmptyString()][string]$Endpoint = '',
          [object[]]$Principals = @(), [string]$ResourceId = '')
    $api = Get-SIOpenAIRightsApi
    $lines = New-Object System.Collections.Generic.List[string]
    $res = [pscustomobject]@{ Ok = $false; State = 'not-checked'; Lines = $lines; Present = @(); Support = @(); ResourceId = '' }
    if (-not "$Endpoint".Trim() -and -not $ResourceId) { $res.Ok = $true; $res.State = 'not-configured'; $lines.Add('Azure OpenAI rights: AI is not configured (no OpenAI_endpoint) -- no right is needed'); return $res }
    $ps = @($Principals | Where-Object { $_ -and [string]$_.PrincipalId })
    if (-not $ps.Count) { $lines.Add('Azure OpenAI rights: NOT CHECKED (no engine or web identity was found) -- the next update checks again'); return $res }
    try {
        if (-not $ResourceId) {
            if (-not $SubscriptionId) { throw 'no subscription to look for the Azure OpenAI resource in' }
            $accts = @((& $Arm 'GET' ('/subscriptions/{0}/providers/Microsoft.CognitiveServices/accounts' -f $SubscriptionId) $api.Accounts $null).value)
            $acct = Find-SIOpenAIAccountForEndpoint -Accounts $accts -Endpoint $Endpoint
            if (-not $acct) {
                $lines.Add(('Azure OpenAI rights: NOT CHECKED (the resource {0} names is not in this subscription, or may not be read from here) -- if AI does not answer, these are the steps:' -f $Endpoint))
                foreach ($p in $ps) { $l = Get-SIOpenAIGrantSupportLine -Identity $p.Identity -Name $p.Name -ResourceId ('named by {0}' -f $Endpoint); $lines.Add($l); $res.Support += $l }
                return $res
            }
            $ResourceId = [string]$acct.id
        }
        $res.ResourceId = $ResourceId
        $assign = New-Object System.Collections.Generic.List[object]
        foreach ($p in $ps) {
            $f = [uri]::EscapeDataString(("principalId eq '{0}'" -f $p.PrincipalId))
            foreach ($a in @((& $Arm 'GET' ('{0}/providers/Microsoft.Authorization/roleAssignments?$filter={1}' -f $ResourceId, $f) $api.Roles $null).value)) { $assign.Add($a) }
        }
        $plan = Get-SIOpenAIRightsPlan -Assignments $assign.ToArray() -Principals $ps -ResourceId $ResourceId
    } catch {
        $lines.Add(('Azure OpenAI rights: NOT CHECKED ({0}) -- the next update checks again' -f ($_.Exception.Message -replace '\s+', ' ')))
        return $res
    }
    foreach ($p in @($plan.Present)) { $lines.Add(('Azure OpenAI rights: {0} ({1}) holds "Cognitive Services OpenAI User" on {2}' -f $p.Identity, $p.Name, $ResourceId)) }
    $support = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($plan.Missing)) {
        $l = Get-SIOpenAIGrantSupportLine -Identity $p.Identity -Name $p.Name -ResourceId $ResourceId -Why 'SecurityInsight never gives this role itself'
        $support.Add($l); $lines.Add($l)
    }
    $res.Present = @($plan.Present); $res.Support = $support.ToArray()
    $res.Ok = ($support.Count -eq 0)
    $res.State = if ($support.Count) { 'missing' } else { 'present' }
    $res
}

function Test-SIOpenAIAccessPaths {
    <#
        The check of setup\Validate-SIOpenAI.ps1: which way of signing in to Azure OpenAI works for -Uri (a chat completions
        request URI). Seams: -Send { param($Headers) } -> the HTTP status (0 = no answer); -GetToken { } -> a token (throws =
        none); -EngineHasRight: $true / $false / $null (not checked). Returns @{ Key; Token; Engine; Verdict; Lines } where
        Key / Token = 'works' | 'refused (HTTP n)' | 'failed (...)' | 'not set' | 'no token'; Engine = 'has access' | 'no access' | 'not checked'.
    #>
    param([Parameter(Mandatory)][scriptblock]$Send, [scriptblock]$GetToken, [AllowEmptyString()][string]$Key = '', $EngineHasRight = $null)
    $say = { param([int]$c) if ($c -ge 200 -and $c -lt 300) { 'works' } elseif ($c -eq 401 -or $c -eq 403) { "refused (HTTP $c)" } elseif ($c -le 0) { 'failed (no answer)' } else { "failed (HTTP $c)" } }
    $keyState = 'not set'
    if (-not [string]::IsNullOrWhiteSpace($Key)) { try { $keyState = & $say ([int](& $Send @{ 'api-key' = $Key })) } catch { $keyState = 'failed (' + ($_.Exception.Message -replace '\s+', ' ') + ')' } }
    $tokState = 'no token'
    if ($GetToken) {
        $tok = $null
        try { $tok = [string](& $GetToken) } catch { $tok = $null }
        if ($tok) { try { $tokState = & $say ([int](& $Send @{ Authorization = ('Bearer ' + $tok) })) } catch { $tokState = 'failed (' + ($_.Exception.Message -replace '\s+', ' ') + ')' } }
    }
    $eng = if ($null -eq $EngineHasRight) { 'not checked' } elseif ([bool]$EngineHasRight) { 'has access' } else { 'no access' }
    $verdict = if ($eng -eq 'has access') { 'The engine signs in to Azure OpenAI with its own identity. No key is needed.' }
               elseif ($keyState -eq 'works') { 'The engine uses the key for now. AI is still using a key; ask your support partner to give the engine access to the Azure OpenAI resource.' }
               elseif ($eng -eq 'no access') { 'AI will not work yet: the engine has no access to the Azure OpenAI resource and no working key is set. Ask your support partner to give the engine access to the Azure OpenAI resource.' }
               else { 'Whether the engine may use the Azure OpenAI resource was not checked (no engine identity given). If it has no access, AI uses the key when one is set.' }
    $lines = @(
        ('Sign-in with the key              : {0}' -f $keyState),
        ('Sign-in with an Entra token (you) : {0}' -f $tokState),
        ('The engine''s identity             : {0}' -f $eng),
        ('Result                            : {0}' -f $verdict))
    [pscustomobject]@{ Key = $keyState; Token = $tokState; Engine = $eng; Verdict = $verdict; Lines = $lines }
}
