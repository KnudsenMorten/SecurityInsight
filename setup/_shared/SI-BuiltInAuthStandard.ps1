#Requires -Version 5.1
<#
    MICROSOFT'S BUILT-IN SIGN-IN -- ONE STANDARD AND NO LEFTOVERS (framework SECURE-WEB-1).
    What follows the web app's switch (setup/_shared/SI-BuiltInAuth.ps1, Invoke-SIBuiltInAuthConverge):

      1. THE MCP APP (ca-si-mcp) behind Microsoft's authentication too. MCP clients send "Authorization: Bearer <access token
         for SecurityInsight's API>", so the platform only VALIDATES bearer tokens: an anonymous request is answered 401 by
         the platform (Return401, never a redirect), no sign-in, no login parameters, no token store, NO container-app
         secret (bearer validation needs none: a client secret is only for the sign-in's code exchange). The same sign-in
         app registration (AzureAd__ClientId), the v2.0 issuer, audiences api://<client id> + <client id>. Open without a
         token (excludedPaths, each a NAMED exception with its reason: $script:SIBuiltInAuthMcpOpenPaths) are ONLY /healthz
         (the update's health check of the MCP image asks it without a token) and the RFC 9728 protected-resource metadata
         /.well-known/oauth-protected-resource[/*] (discovery only, no data: a new MCP client cannot find where to sign in
         otherwise -- the platform's 401 carries no resource_metadata). Before it, the sign-in app registration gets the
         MCP's own delegated scope mcp.access (SI-McpScope.ps1, beside its other scopes, read back). The platform forwards
         the Authorization header, so SecurityInsight's own check (Microsoft.Identity.Web in SI.Management.Mcp, its app
         roles and its access table) still runs on every request -- the platform is a second gate, never the only one.
         Proof the 401 is the PLATFORM's: GET /mcp answers 401 AND GET /.auth/me (the platform's own endpoint) does not
         answer 404 -- SecurityInsight has no such route, so a 404 there means the platform is not in front. A failed
         read-back or probe puts the MCP's authentication back as it was (off), read back.
      2. THE LEFTOVERS of the sign-in front era, only after a web app that reads back switched:
           removed (one PATCH of the web app, every secret kept, read back): the web container's SI_Web_SigninFront,
             SI_Web_SigninFrontAccessTokenOnly and every SIGNIN_* setting; a container-app secret only when its name is on
             the short list of secrets nothing but the old sign-in wrote ($script:SIBuiltInAuthEraSecrets) AND nothing
             references it (no container setting, registry, scale rule, secret volume or the authConfig);
           REPORTED only (a line 'leftover: ...'): any other secret whose name looks like the sign-in era; redirect URIs of
             the sign-in app registration other than the platform's callback of the app's own hosts; client secrets and
             certificates on that registration (writing it is the owner of the app's right, and a URI or a credential can
             serve a customer's other use); signin-front images still stored in the install's registry.
      2b. THE DATA-PLANE LEFTOVERS (Invoke-SIBuiltInAuthFrontDataClean; Invardia works on control planes only, so these are
         SecurityInsight's own job): the signin-front images in the install's registry and the Key Vault keys
         signin-front-dp and SI-Web-KeyRing -- deleted ONLY while the web app reads back without the front (see the function).
      3. THE STANDARD as one read-only check (Read-SIBuiltInAuthStandardFacts + Test-SIBuiltInAuthStandard): the updater's
         summary line and Invardia's daily second check (setup/Test-SIBuiltInAuthStandard.ps1) use the same rules.

    Seams (the tests pass fakes), as SI-BuiltInAuth.ps1:
      -Arm   { param([string]$Method, [string]$Path, $Body) }  parsed answer, $null for "not found" on a GET, THROWS otherwise.
      -Graph { param([string]$Method, [string]$Uri, $Body) }
      -Probe { param([string]$Url) } -> @{ Status; Location }
      -ListImages { param([string]$LoginServer, [string]$Repo) } -> @{ Found; Tags }   (THROWS when it cannot be read)
      -Sleep { param([int]$Seconds) }
    No module, no az. PS 5.1 safe.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

# (always loaded into THIS scope: their $script: values -- api-versions, names -- must be where these functions read them)
. ([IO.Path]::Combine($PSScriptRoot, 'SI-BuiltInAuth.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, 'SI-WebJobRights.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, 'SI-McpScope.ps1'))

# THE MCP APP'S NAMED ANONYMOUS PATHS (framework SECURE-WEB-1 (4): every anonymous path is a NAMED EXCEPTION with its reason,
# and the standard's check flags any other). The platform answers everything else without a token with 401. A full PUT of
# the authConfig REPLACES excludedPaths, so the converge always sends all of them.
$script:SIBuiltInAuthMcpOpenPaths = [ordered]@{
    '/healthz'                                 = 'the update''s health check of the MCP image asks it without a token; it answers "ok" and carries no data'
    '/.well-known/oauth-protected-resource'    = 'RFC 9728 discovery; no data -- a new MCP client reads which authorization server signs for the MCP server and which scope to ask for (the platform''s 401 does not say it)'
    '/.well-known/oauth-protected-resource/*'  = 'RFC 9728 discovery; no data -- the same document in the form for the resource /mcp (/.well-known/oauth-protected-resource/mcp)'
}
$script:SIBuiltInAuthMcpExcludedPaths = @($script:SIBuiltInAuthMcpOpenPaths.Keys)
# the web container's settings of the sign-in front (pro-management/src/SI.Management.Web/Auth/SigninFront.cs and the front's
# own SIGNIN_* settings): ignored while SI_Web_BuiltInAuth is on, so removing them changes nothing the app does
$script:SIBuiltInAuthFrontEnvNames  = @('SI_Web_SigninFront', 'SI_Web_SigninFrontAccessTokenOnly')
$script:SIBuiltInAuthFrontEnvPrefix = 'SIGNIN_'
# container-app secrets ONLY the old sign-in wrote: the platform's own name for an Entra client secret (what
# "az containerapp auth microsoft update --client-secret" stores). SecurityInsight's sign-in front was secretless (a
# federated credential), so it left no secret of its own; nothing else ever writes this name.
$script:SIBuiltInAuthEraSecrets     = @('microsoft-provider-authentication-secret')
# names that LOOK like the sign-in era: reported, never removed
$script:SIBuiltInAuthEraSecretRx    = '(?i)easyauth|easy-auth|microsoft-provider|client-?secret|signin|sign-in|front|aad'
$script:SIBuiltInAuthFrontRepo      = 'signin-front'
# EVERY internet-facing container app of the install (ingress.external = true) answers only through Microsoft's
# authentication (framework SECURE-WEB-1: every public endpoint, not only the web UI): the web app RedirectToLoginPage,
# the MCP and any API-only app Return401. The ONLY way out for a WHOLE APP is a named exception with its reason here --
# KEEP IT EMPTY. (A single anonymous PATH of an app that is otherwise behind the sign-in is named in its own list with its
# reason: the MCP app's in $script:SIBuiltInAuthMcpOpenPaths -- /healthz and THE named anonymous exception, the RFC 9728
# protected-resource metadata: discovery only, no data.)
#   e.g. [pscustomobject]@{ App = 'ca-si-example'; Reason = 'why this app may answer without a sign-in' }
$script:SIBuiltInAuthPublicExceptions = @()
$script:SIBuiltInAuthTokenStoreName = 'si-auth-tokens'
# Azure's built-in Key Vault roles (GUIDs are the same in every tenant). Any role whose scope is a vault counts too.
$script:SIBuiltInAuthKeyVaultRoles  = [ordered]@{
    '00482a5a-887f-4fb3-b363-3b7fe8e74483' = 'Key Vault Administrator'
    'a4417e6f-fecd-4de8-b567-7b0420556985' = 'Key Vault Certificates Officer'
    'db79e9a7-68ee-4b58-9aeb-b90e7c24fcba' = 'Key Vault Certificate User'
    'f25e0fa2-a7c8-4377-a976-54943a77a395' = 'Key Vault Contributor'
    '14b46e9e-c2b7-41b4-b07b-48a6ebf60603' = 'Key Vault Crypto Officer'
    'e147488a-f6f5-4113-8e2d-b22465e65bf6' = 'Key Vault Crypto Service Encryption User'
    '12338af0-0e69-4776-bea7-57ae8d297424' = 'Key Vault Crypto User'
    '8b54135c-b56d-4d72-a534-26097cfdc8d8' = 'Key Vault Data Access Administrator'
    '21090545-7ca7-4776-b22c-e363652d74d2' = 'Key Vault Reader'
    'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' = 'Key Vault Secrets Officer'
    '4633458b-17de-408a-b874-0445c86b69e6' = 'Key Vault Secrets User'
}

# ============================================================================================================== 0. HELPERS

function Invoke-SIBuiltInAuthBusyWrite {
    <# A write to a container app (or its authConfig): first waits until the app's provisioningState settles, then a 409
       "operation in progress" is retried after a pause (the converge's own rule, live 2026-11-14). Returns the answer;
       THROWS what the last try threw. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Path, $Body,
          [Parameter(Mandatory)][string]$AppPath, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$BusyTries = 30, [int]$PauseSeconds = 10)
    for ($w = 1; $w -le $BusyTries; $w++) {
        $st = [string](Get-SIBuiltInAuthProp (& $Arm 'GET' $AppPath $null) @('properties', 'provisioningState'))
        if (-not $st -or $st -in 'Succeeded', 'Failed', 'Canceled') { break }
        & $Sleep $PauseSeconds
    }
    for ($t = 1; ; $t++) {
        try { return (& $Arm $Method $Path $Body) }
        catch {
            if ($t -lt $BusyTries -and "$($_.Exception.Message)" -match '(?i)\b409\b|OperationInProgress|another operation is in progress') { & $Sleep $PauseSeconds; continue }
            throw
        }
    }
}

function Get-SIBuiltInAuthEnvMap {
    <# PURE. The settings of the app's web container (the first one that is not the sign-in front) as name -> entry. #>
    param($App)
    $h = [ordered]@{}
    $i = Get-SIBuiltInAuthWebContainerIndex -App $App
    if ($i -lt 0) { return $h }
    $c = @(Get-SIBuiltInAuthProp $App @('properties', 'template', 'containers'))[$i]
    foreach ($e in @(Get-SIBuiltInAuthProp $c @('env'))) { $n = [string](Get-SIBuiltInAuthProp $e @('name')); if ($n) { $h[$n] = $e } }
    $h
}

# ============================================================================================================== 1. THE MCP APP

function Get-SIBuiltInAuthMcpConfigBody {
    <#
        PURE. The ARM body for PUT <MCP app id>/authConfigs/current: bearer validation ONLY -- platform on, an anonymous
        request answered 401 (Return401, never a redirect), the sign-in app registration's client id, the v2.0 issuer (or
        -OpenIdIssuer), audiences api://<client id> + <client id>; NO clientSecretSettingName, NO login parameters, the token
        store OFF; open ONLY the named paths (-ExcludedPaths, ALL of them in every body -- a PUT replaces the list):
        /healthz and the RFC 9728 metadata; HTTPS only. -Enabled:$false = the same body switched off (the way back).
    #>
    param([Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
          [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$ClientId,
          [string]$OpenIdIssuer = '', [string[]]$ExcludedPaths = $script:SIBuiltInAuthMcpExcludedPaths, [bool]$Enabled = $true)
    $cid = $ClientId.Trim().ToLowerInvariant()
    $iss = if ("$OpenIdIssuer".Trim()) { "$OpenIdIssuer".Trim() } else { 'https://login.microsoftonline.com/{0}/v2.0' -f $TenantId.Trim().ToLowerInvariant() }
    $gv = [ordered]@{ unauthenticatedClientAction = 'Return401' }
    $ex = @($ExcludedPaths | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if ($ex.Count) { $gv['excludedPaths'] = $ex }
    [ordered]@{
        properties = [ordered]@{
            platform          = [ordered]@{ enabled = $Enabled }
            globalValidation  = $gv
            identityProviders = [ordered]@{
                azureActiveDirectory = [ordered]@{
                    enabled      = $true
                    registration = [ordered]@{ clientId = $cid; openIdIssuer = $iss }
                    validation   = [ordered]@{ allowedAudiences = @(('api://{0}' -f $cid), $cid) }
                }
            }
            login             = [ordered]@{ tokenStore = [ordered]@{ enabled = $false } }
            httpSettings      = [ordered]@{ requireHttps = $true }
        }
    }
}

function Test-SIBuiltInAuthMcpConfigMatches {
    <# PURE. Does the MCP authConfig as read carry -Want (Get-SIBuiltInAuthMcpConfigBody) -- and nothing of a sign-in (no
       login parameters, no client secret setting, no token store)? @{ Ok; Diff }. #>
    param($Current, [Parameter(Mandatory)]$Want)
    $diff = New-Object System.Collections.Generic.List[string]
    $one = { param([string[]]$Path, [string]$Name)
        $w = Get-SIBuiltInAuthProp $Want $Path; $c = Get-SIBuiltInAuthProp $Current $Path
        if ("$w".Trim().ToLowerInvariant() -ne "$c".Trim().ToLowerInvariant()) { $diff.Add($Name) } }
    $set = { param([string[]]$Path, [string]$Name)
        $w = @(@(Get-SIBuiltInAuthProp $Want $Path) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Sort-Object -Unique)
        $c = @(@(Get-SIBuiltInAuthProp $Current $Path) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Sort-Object -Unique)
        if (($w -join '|') -ne ($c -join '|')) { $diff.Add($Name) } }
    $aad = @('properties', 'identityProviders', 'azureActiveDirectory')
    & $one @('properties', 'platform', 'enabled') 'platform.enabled'
    & $one @('properties', 'globalValidation', 'unauthenticatedClientAction') 'globalValidation.unauthenticatedClientAction'
    & $set @('properties', 'globalValidation', 'excludedPaths') 'globalValidation.excludedPaths'
    & $one ($aad + 'enabled') 'azureActiveDirectory.enabled'
    & $one ($aad + @('registration', 'clientId')) 'registration.clientId'
    & $one ($aad + @('registration', 'openIdIssuer')) 'registration.openIdIssuer'
    & $set ($aad + @('validation', 'allowedAudiences')) 'validation.allowedAudiences'
    if ("$(Get-SIBuiltInAuthProp $Current ($aad + @('registration', 'clientSecretSettingName')))".Trim()) { $diff.Add('registration.clientSecretSettingName (none for bearer validation)') }
    if (@(@(Get-SIBuiltInAuthProp $Current ($aad + @('login', 'loginParameters'))) | Where-Object { "$_".Trim() }).Count) { $diff.Add('azureActiveDirectory.login.loginParameters (none for bearer validation)') }
    if ("$(Get-SIBuiltInAuthProp $Current @('properties', 'login', 'tokenStore', 'enabled'))" -match '^(?i)true$') { $diff.Add('login.tokenStore.enabled (off for bearer validation)') }
    & $one @('properties', 'httpSettings', 'requireHttps') 'httpSettings.requireHttps'
    [pscustomobject]@{ Ok = ($diff.Count -eq 0); Diff = $diff.ToArray() }
}

function Get-SIBuiltInAuthMcpOpenPathFindings {
    <# PURE. The MCP authConfig's excludedPaths (-Current as read) against the NAMED open paths (-Named: path -> reason;
       $script:SIBuiltInAuthMcpOpenPaths): any path not named = a finding (an anonymous path nobody named), a named path
       missing = a finding (a new MCP client cannot discover the sign-in). Exact paths (case as the converge's compare:
       ignored; a trailing '/' ignored). One text per finding. #>
    param($Current, [System.Collections.IDictionary]$Named = $script:SIBuiltInAuthMcpOpenPaths)
    $norm = { param($p) $t = "$p".Trim(); if ($t.Length -gt 1) { $t = $t.TrimEnd('/') }; $t }
    $have = @(@(Get-SIBuiltInAuthProp $Current @('properties', 'globalValidation', 'excludedPaths')) | Where-Object { "$_".Trim() } | ForEach-Object { & $norm $_ } | Select-Object -Unique)
    $want = @(@($Named.Keys) | ForEach-Object { & $norm $_ })
    $out = New-Object System.Collections.Generic.List[string]
    $extra = @($have | Where-Object { $want -notcontains $_ })
    if ($extra.Count) { $out.Add(('mcp: open paths {0} (only the named ones: {1})' -f ($extra -join ','), ($want -join ', '))) }
    $missing = @($want | Where-Object { $have -notcontains $_ })
    if ($missing.Count) { $out.Add(('mcp: the named open path(s) {0} missing' -f ($missing -join ','))) }
    $out.ToArray()
}

function Test-SIBuiltInAuthMcpPlatformRefused {
    <#
        PURE. Is an anonymous request to the MCP app refused BY THE PLATFORM? -Mcp = GET https://<fqdn>/mcp without a token,
        -AuthMe = GET https://<fqdn>/.auth/me without a token. Refused by the platform = /mcp answers 401 AND /.auth/me is
        answered and not 404: /.auth/me exists only while Microsoft's authentication is in front (SecurityInsight has no such
        route -- a 404 there means the 401 was SecurityInsight's own). A 200 or a 403 from /mcp is never accepted.
        @{ Ok; Why }.
    #>
    param($Mcp, $AuthMe)
    $s = [int](0 + (Get-SIBuiltInAuthProp $Mcp @('Status')))
    if ($s -ne 401) { return [pscustomobject]@{ Ok = $false; Why = ('a request to /mcp without a token was answered with HTTP {0}, not 401' -f $s) } }
    $a = [int](0 + (Get-SIBuiltInAuthProp $AuthMe @('Status')))
    if ($a -eq 0 -or $a -eq 404) { return [pscustomobject]@{ Ok = $false; Why = ('/mcp answered 401, but the platform''s /.auth/me answered HTTP {0} -- the 401 came from SecurityInsight, not from Microsoft''s authentication' -f $a) } }
    [pscustomobject]@{ Ok = $true; Why = '' }
}

function Invoke-SIBuiltInAuthMcpConverge {
    <#
        THE MCP APP behind Microsoft's authentication (bearer validation only; see the file header). -Mode plan | apply.
        -McpAppId: the MCP app's ARM id. -TenantId / -ClientId: the web app's sign-in (the SAME app registration); the MCP's
        own AzureAd__ClientId must name it, else nothing is written. apply: PUT the authConfig (the app's busy wait + 409
        retry), read back; then /mcp must be refused by the platform and /healthz must still answer 200; anything else puts
        the MCP's authentication back as it was (off), read back.
        NEVER THROWS. @{ Ok; State (absent | in-place | planned | applied | failed | rolled-back); Lines; Warnings }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [ValidateSet('plan', 'apply')][string]$Mode = 'plan',
          [Parameter(Mandatory)][string]$McpAppId, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId,
          [scriptblock]$Probe, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [string]$OpenIdIssuer = '',
          [int]$Tries = 6, [int]$PauseSeconds = 10, [int]$ProbeTries = 6, [int]$BusyTries = 30,
          [string]$AuthApiVersion = $script:SIBuiltInAuthApi, [string]$AppApiVersion = $script:SIBuiltInAuthAppApi)
    $lines = New-Object System.Collections.Generic.List[string]
    $warn = New-Object System.Collections.Generic.List[string]
    $res = { param([bool]$Ok, [string]$State) [pscustomobject]@{ Ok = $Ok; State = $State; Lines = $lines.ToArray(); Warnings = $warn.ToArray() } }
    $mcp = ($McpAppId.TrimEnd('/') -split '/')[-1]
    $appPath = '{0}?api-version={1}' -f $McpAppId.TrimEnd('/'), $AppApiVersion
    $authPath = '{0}/authConfigs/current?api-version={1}' -f $McpAppId.TrimEnd('/'), $AuthApiVersion
    $written = $false; $before = $null; $want = $null
    try {
        $app = & $Arm 'GET' $appPath $null
        if (-not $app) { $lines.Add(('{0}: not in this install -- nothing to put behind Microsoft''s authentication' -f $mcp)); return (& $res $true 'absent') }
        $fqdn = [string](Get-SIBuiltInAuthProp $app @('properties', 'configuration', 'ingress', 'fqdn'))
        if (-not $fqdn) { $lines.Add(('{0}: has no address -- left as it is' -f $mcp)); return (& $res $true 'absent') }
        $own = (Get-SIBuiltInAuthSetting -App $app -Name 'AzureAd__ClientId').ToLowerInvariant()
        if ($own -and $own -ne $ClientId.Trim().ToLowerInvariant()) {
            $warn.Add(('{0}: Microsoft''s authentication was NOT put in front -- the MCP app names the app registration {1}, the web app {2}; they must be the same one' -f $mcp, $own, $ClientId.ToLowerInvariant()))
            return (& $res $false 'failed')
        }
        $want = Get-SIBuiltInAuthMcpConfigBody -TenantId $TenantId -ClientId $ClientId -OpenIdIssuer $OpenIdIssuer
        $before = & $Arm 'GET' $authPath $null
        $cmp = Test-SIBuiltInAuthMcpConfigMatches -Current $before -Want $want
        $check = {
            if (-not $Probe) { return 'no way to send a request without a token -- it could not be proven that one is refused' }
            $why = ''
            for ($i = 1; $i -le $ProbeTries; $i++) {
                $p1 = $null; $p2 = $null; $p3 = $null
                try { $p1 = & $Probe ("https://$fqdn/mcp") } catch { $p1 = $null }
                try { $p2 = & $Probe ("https://$fqdn/.auth/me") } catch { $p2 = $null }
                $t = Test-SIBuiltInAuthMcpPlatformRefused -Mcp $p1 -AuthMe $p2
                if ($t.Ok) {
                    try { $p3 = & $Probe ("https://$fqdn/healthz") } catch { $p3 = $null }
                    $hs = [int](0 + (Get-SIBuiltInAuthProp $p3 @('Status')))
                    if ($hs -eq 200) { return '' }
                    $why = '/healthz answered HTTP {0}, not 200 -- the update''s health check of the MCP image would fail' -f $hs
                } else { $why = $t.Why }
                if ($i -lt $ProbeTries) { & $Sleep $PauseSeconds }
            }
            $why
        }
        if ($Mode -eq 'plan') {
            if ($cmp.Ok) { $lines.Add(('{0}: Microsoft''s authentication is in front (bearer tokens only; nothing would change)' -f $mcp)); return (& $res $true 'in-place') }
            $lines.Add(('{0}: Microsoft''s authentication -- would: write the bearer-only configuration ({1}): a request without a token answered 401 by the platform, the app registration {2}, no sign-in, no token store, no secret, open only /healthz and the RFC 9728 discovery (nothing was changed)' -f $mcp, ($cmp.Diff -join ', '), $ClientId.ToLowerInvariant()))
            return (& $res $true 'planned')
        }
        if ($cmp.Ok) {
            $why = & $check
            if ($why) { $warn.Add(('{0}: Microsoft''s authentication is set up, but {1} -- the next update checks again' -f $mcp, $why)); return (& $res $false 'failed') }
            $lines.Add(('{0}: Microsoft''s authentication is in front (bearer tokens only; a request without a token is refused by the platform)' -f $mcp))
            return (& $res $true 'in-place')
        }
        $written = $true
        $null = Invoke-SIBuiltInAuthBusyWrite -Arm $Arm -Method 'PUT' -Path $authPath -Body $want -AppPath $appPath -Sleep $Sleep -BusyTries $BusyTries -PauseSeconds $PauseSeconds
        $ok = $false; $last = $null
        for ($i = 1; $i -le $Tries; $i++) {
            try { $last = & $Arm 'GET' $authPath $null; if ((Test-SIBuiltInAuthMcpConfigMatches -Current $last -Want $want).Ok) { $ok = $true; break } } catch { }
            if ($i -lt $Tries) { & $Sleep $PauseSeconds }
        }
        if (-not $ok) { throw ('its authentication configuration does not read back ({0})' -f ((Test-SIBuiltInAuthMcpConfigMatches -Current $last -Want $want).Diff -join ', ')) }
        $why = & $check
        if ($why) { throw $why }
        $lines.Add(('{0}: Microsoft''s authentication is in front now (bearer tokens only: a request without a token is answered 401 by the platform, open only /healthz and the RFC 9728 discovery; read back) -- SecurityInsight still checks every token itself' -f $mcp))
        return (& $res $true 'applied')
    } catch {
        $why = $_.Exception.Message
        if (-not $written) { $warn.Add(('{0}: Microsoft''s authentication could not be checked ({1}) -- nothing was changed; the next update tries again' -f $mcp, $why)); return (& $res $false 'failed') }
        $back = ''
        try {
            $rb = Get-SIBuiltInAuthRestoreBody -Before $before -Want $want
            $wantOn = "$(Get-SIBuiltInAuthProp $rb @('properties', 'platform', 'enabled'))" -match '^(?i)true$'
            $null = Invoke-SIBuiltInAuthBusyWrite -Arm $Arm -Method 'PUT' -Path $authPath -Body $rb -AppPath $appPath -Sleep $Sleep -BusyTries $BusyTries -PauseSeconds $PauseSeconds
            $isOn = "$(Get-SIBuiltInAuthProp (& $Arm 'GET' $authPath $null) @('properties', 'platform', 'enabled'))" -match '^(?i)true$'
            $back = if ($wantOn -eq $isOn) { if ($wantOn) { 'the authentication that ran before was put back (read back)' } else { 'its authentication was switched off again (read back)' } } else { 'its authentication does NOT read back as it was -- check it by hand' }
        } catch { $back = ('its authentication could NOT be put back ({0}) -- switch it off by hand' -f $_.Exception.Message) }
        $warn.Add(('{0}: Microsoft''s authentication was NOT put in front: {1}; {2}' -f $mcp, $why, $back))
        return (& $res $false 'rolled-back')
    }
}

# ============================================================================================================== 2. THE LEFTOVERS

function Get-SIBuiltInAuthLeftoverEnvNames {
    <# PURE. The web container's settings of the sign-in front era: SI_Web_SigninFront, SI_Web_SigninFrontAccessTokenOnly and
       every SIGNIN_*. #>
    param($App)
    @(@((Get-SIBuiltInAuthEnvMap -App $App).Keys) | Where-Object { $n = [string]$_; ($script:SIBuiltInAuthFrontEnvNames -contains $n) -or $n.StartsWith($script:SIBuiltInAuthFrontEnvPrefix, [StringComparison]::OrdinalIgnoreCase) })
}

function Get-SIBuiltInAuthSecretReferences {
    <#
        PURE. Every container-app secret name -App references (lower case): a setting's secretRef in any container or init
        container (minus the settings named in -WithoutEnv: the ones about to go), a registry's passwordSecretRef, a scale
        rule's auth secretRef, a secret volume's secretRef, and -AuthConfig's clientSecretSettingName. A secret volume that
        names no secrets mounts ALL of them: then '*' is in the list (nothing may be removed).
    #>
    param($App, $AuthConfig, [string[]]$WithoutEnv = @())
    $refs = New-Object System.Collections.Generic.List[string]
    $add = { param($v) $x = "$v".Trim().ToLowerInvariant(); if ($x -and -not $refs.Contains($x)) { $refs.Add($x) } }
    $tpl = Get-SIBuiltInAuthProp $App @('properties', 'template')
    foreach ($c in @(@(Get-SIBuiltInAuthProp $tpl @('containers')) + @(Get-SIBuiltInAuthProp $tpl @('initContainers')))) {
        if (-not $c) { continue }
        foreach ($e in @(Get-SIBuiltInAuthProp $c @('env'))) {
            if (-not $e) { continue }
            if ($WithoutEnv -contains [string](Get-SIBuiltInAuthProp $e @('name'))) { continue }
            & $add (Get-SIBuiltInAuthProp $e @('secretRef'))
        }
    }
    foreach ($r in @(Get-SIBuiltInAuthProp $App @('properties', 'configuration', 'registries'))) { if ($r) { & $add (Get-SIBuiltInAuthProp $r @('passwordSecretRef')) } }
    foreach ($rule in @(Get-SIBuiltInAuthProp $tpl @('scale', 'rules'))) {
        if (-not $rule) { continue }
        $props = if ($rule -is [System.Collections.IDictionary]) { @($rule.Keys) } else { @($rule.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($k in $props) { foreach ($au in @(Get-SIBuiltInAuthProp (Get-SIBuiltInAuthProp $rule @($k)) @('auth'))) { if ($au) { & $add (Get-SIBuiltInAuthProp $au @('secretRef')) } } }
    }
    foreach ($v in @(Get-SIBuiltInAuthProp $tpl @('volumes'))) {
        if (-not $v -or [string](Get-SIBuiltInAuthProp $v @('storageType')) -ine 'Secret') { continue }
        $named = @(Get-SIBuiltInAuthProp $v @('secrets') | Where-Object { $_ })
        if (-not $named.Count) { & $add '*' }
        foreach ($s in $named) { & $add (Get-SIBuiltInAuthProp $s @('secretRef')) }
    }
    & $add (Get-SIBuiltInAuthProp $AuthConfig @('properties', 'identityProviders', 'azureActiveDirectory', 'registration', 'clientSecretSettingName'))
    $refs.ToArray()
}

function Get-SIBuiltInAuthLeftoverSecrets {
    <#
        PURE. The container-app secrets of the sign-in era on -App: Remove = the names on $script:SIBuiltInAuthEraSecrets that
        exist and that NOTHING references (Get-SIBuiltInAuthSecretReferences, after -WithoutEnv goes); Report = every other
        name that looks like the sign-in era (never SecurityInsight's own 'override-use-mi-fic-assertion-client-id'), and an
        era secret that is still referenced. @{ Remove; Report (@{ Name; Why }) }.
    #>
    param($App, $AuthConfig, [string[]]$WithoutEnv = @())
    $refs = @(Get-SIBuiltInAuthSecretReferences -App $App -AuthConfig $AuthConfig -WithoutEnv $WithoutEnv)
    $all = $refs -contains '*'
    $remove = New-Object System.Collections.Generic.List[string]
    $report = New-Object System.Collections.Generic.List[object]
    foreach ($s in @(Get-SIBuiltInAuthProp $App @('properties', 'configuration', 'secrets'))) {
        $n = [string](Get-SIBuiltInAuthProp $s @('name')); if (-not $n) { continue }
        if ($n -ieq $script:SIBuiltInAuthSecretName) { continue }
        $era = $script:SIBuiltInAuthEraSecrets -contains $n.ToLowerInvariant()
        $used = $all -or ($refs -contains $n.ToLowerInvariant())
        if ($era -and -not $used) { $remove.Add($n); continue }
        if ($era) { $report.Add([pscustomobject]@{ Name = $n; Why = 'of the old sign-in, but still referenced -- kept' }); continue }
        if ($n -match $script:SIBuiltInAuthEraSecretRx) { $report.Add([pscustomobject]@{ Name = $n; Why = $(if ($used) { 'looks like the sign-in era and is referenced -- kept' } else { 'looks like the sign-in era and nothing references it -- kept; check it by hand' }) }) }
    }
    [pscustomobject]@{ Remove = $remove.ToArray(); Report = $report.ToArray() }
}

function Get-SIBuiltInAuthLeftoverPatch {
    <#
        PURE. The ARM PATCH of the web app without the leftovers: the configuration as read with EVERY secret written back
        (Container Apps replaces the whole list: values from -SecretValues = listSecrets, Key Vault references as read) but
        -RemoveSecrets; the template as read (no revisionSuffix) with -RemoveEnv taken off the web container. A secret whose
        value is not known is in MissingSecrets: the caller does not write. @{ Body; MissingSecrets; Changed }.
    #>
    param([Parameter(Mandatory)]$App, [hashtable]$SecretValues = @{}, [string[]]$RemoveEnv = @(), [string[]]$RemoveSecrets = @())
    $cfg = ConvertTo-SIBuiltInAuthHashtable (Get-SIBuiltInAuthProp $App @('properties', 'configuration'))
    if (-not $cfg) { $cfg = [ordered]@{} }
    $list = New-Object System.Collections.Generic.List[object]
    $missing = New-Object System.Collections.Generic.List[string]
    $changed = $false
    $rm = @($RemoveSecrets | ForEach-Object { "$_".ToLowerInvariant() })
    foreach ($s in @(Get-SIBuiltInAuthProp $App @('properties', 'configuration', 'secrets'))) {
        $sn = [string](Get-SIBuiltInAuthProp $s @('name')); if (-not $sn) { continue }
        if ($rm -contains $sn.ToLowerInvariant()) { $changed = $true; continue }
        $known = $SecretValues[$sn]
        $e = [ordered]@{ name = $sn }
        $kv = [string](Get-SIBuiltInAuthProp $s @('keyVaultUrl')); if (-not $kv -and $known) { $kv = [string](Get-SIBuiltInAuthProp $known @('keyVaultUrl')) }
        if ($kv) {
            $e.keyVaultUrl = $kv
            $sid = [string](Get-SIBuiltInAuthProp $s @('identity')); if (-not $sid -and $known) { $sid = [string](Get-SIBuiltInAuthProp $known @('identity')) }
            if ($sid) { $e.identity = $sid }
        } else {
            $v = Get-SIBuiltInAuthProp $s @('value'); if ($null -eq $v -and $known) { $v = Get-SIBuiltInAuthProp $known @('value') }
            if ($null -eq $v) { $missing.Add($sn) }
            $e.value = [string]$v
        }
        $list.Add($e)
    }
    $cfg['secrets'] = $list.ToArray()
    $props = [ordered]@{ configuration = $cfg }
    $tpl = ConvertTo-SIBuiltInAuthHashtable (Get-SIBuiltInAuthProp $App @('properties', 'template'))
    if ($tpl) {
        if ($tpl.Contains('revisionSuffix')) { $tpl.Remove('revisionSuffix') }
        $i = Get-SIBuiltInAuthWebContainerIndex -App $App
        if ($i -ge 0 -and @($RemoveEnv).Count) {
            $c = $tpl.containers[$i]
            $before = @($c['env']).Count
            $c['env'] = @(@($c['env']) | Where-Object { $null -ne $_ -and $RemoveEnv -notcontains [string]$_['name'] })
            if (@($c['env']).Count -ne $before) { $changed = $true }
        }
        $props['template'] = $tpl
    }
    [pscustomobject]@{ Body = [ordered]@{ properties = $props }; MissingSecrets = $missing.ToArray(); Changed = $changed }
}

function Get-SIBuiltInAuthRegistrationLeftovers {
    <#
        PURE. What the sign-in app registration (Graph: web, spa, publicClient, passwordCredentials, keyCredentials) still
        carries beyond Microsoft's built-in sign-in -- REPORTED, never removed: every redirect URI that is not
        https://<host>/.auth/login/aad/callback for -Fqdn or one of -CustomDomains; every client secret; every certificate.
        Returns the finding texts.
    #>
    param($Registration, [string]$Fqdn = '', [string[]]$CustomDomains = @())
    $out = New-Object System.Collections.Generic.List[string]
    if (-not $Registration) { return $out.ToArray() }
    $ok = @(@(@($Fqdn) + @($CustomDomains)) | ForEach-Object { "$_".Trim() -replace '^(?i)https?://', '' -replace '/.*$', '' } | Where-Object { $_ } | ForEach-Object { ('https://{0}{1}' -f $_.ToLowerInvariant(), $script:SIBuiltInAuthCallbackPath) })
    foreach ($kind in 'web', 'spa', 'publicClient') {
        foreach ($u in @(Get-SIBuiltInAuthProp $Registration @($kind, 'redirectUris'))) {
            $x = "$u".Trim(); if (-not $x) { continue }
            if ($kind -eq 'web' -and @($ok | Where-Object { $_ -ieq $x.TrimEnd('/') }).Count) { continue }
            $out.Add(('the sign-in app registration''s {0} redirect URI {1} (not Microsoft''s built-in sign-in callback) -- reported, not removed' -f $kind, $x))
        }
    }
    $day = { param($d) $t = "$d".Trim(); if ($t.Length -ge 10) { $t.Substring(0, 10) } else { $t } }
    foreach ($pc in @(Get-SIBuiltInAuthProp $Registration @('passwordCredentials'))) {
        if (-not $pc) { continue }
        $out.Add(('the sign-in app registration holds a CLIENT SECRET ''{0}'' (ends {1}) -- the built-in sign-in needs none; reported, not removed' -f [string](Get-SIBuiltInAuthProp $pc @('displayName')), (& $day (Get-SIBuiltInAuthProp $pc @('endDateTime')))))
    }
    foreach ($kc in @(Get-SIBuiltInAuthProp $Registration @('keyCredentials'))) {
        if (-not $kc) { continue }
        $out.Add(('the sign-in app registration holds a CERTIFICATE ''{0}'' (ends {1}) -- the built-in sign-in needs none; reported, not removed' -f [string](Get-SIBuiltInAuthProp $kc @('displayName')), (& $day (Get-SIBuiltInAuthProp $kc @('endDateTime')))))
    }
    $out.ToArray()
}

function Get-SIBuiltInAuthFrontImageTags {
    <# The signin-front images stored in the install's registry: GET https://<login>/v2/<repo>/tags/list with a pull token
       (Get-SIAcrPullToken, setup/_shared/SI-AcrBuild.ps1). @{ Found; Tags }; THROWS when it cannot be read. #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$LoginServer, [string]$Repo = $script:SIBuiltInAuthFrontRepo, [scriptblock]$Token)
    $a = @{ Rest = $Rest; LoginServer = $LoginServer; Repo = $Repo }; if ($Token) { $a['Token'] = $Token }
    $bearer = $null
    try { $bearer = Get-SIAcrPullToken @a } catch { if ("$($_.Exception.Message)" -match '(?i)\b404\b|NAME_UNKNOWN|not found') { return [pscustomobject]@{ Found = $false; Tags = @() } }; throw }
    $r = & $Rest 'GET' ('https://{0}/v2/{1}/tags/list' -f $LoginServer, $Repo) $null '' @{ Authorization = ('Bearer ' + $bearer); Accept = 'application/json' }
    if ([int]$r.Status -eq 404) { return [pscustomobject]@{ Found = $false; Tags = @() } }
    if ([int]$r.Status -lt 200 -or [int]$r.Status -ge 300) { throw ('the images of {0} could not be listed: HTTP {1}' -f $Repo, [int]$r.Status) }
    $j = $null; if ("$($r.Body)".Trim()) { $j = "$($r.Body)" | ConvertFrom-Json }
    [pscustomobject]@{ Found = $true; Tags = @(@(Get-SIBuiltInAuthProp $j @('tags')) | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
}

# ============================================================================================================== 3. THE STANDARD

function Get-SIBuiltInAuthRoleFindings {
    <# PURE. The roles -Assignments (roleAssignments as ARM lists them) give -PrincipalId that the standard forbids for an
       internet-facing identity: any Key Vault role (by its built-in id, or any role on a vault), any role of
       SI-WebJobRights.ps1's forbidden list. One text per assignment. #>
    param([object[]]$Assignments = @(), [Parameter(Mandatory)][string]$PrincipalId, [string]$IdentityName = 'the identity')
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($a in @($Assignments | Where-Object { $_ })) {
        $p = Get-SIBuiltInAuthProp $a @('properties')
        if ("$(Get-SIBuiltInAuthProp $p @('principalId'))".Trim() -ine $PrincipalId.Trim()) { continue }
        $g = ("$(Get-SIBuiltInAuthProp $p @('roleDefinitionId'))" -split '/')[-1].Trim().ToLowerInvariant()
        $scope = "$(Get-SIBuiltInAuthProp $p @('scope'))".TrimEnd('/')
        $where = ($scope -split '/')[-1]
        if ($script:SIBuiltInAuthKeyVaultRoles.Contains($g)) { $out.Add(('{0} holds {1} on {2} (no Key Vault role for an internet-facing identity)' -f $IdentityName, $script:SIBuiltInAuthKeyVaultRoles[$g], $where)); continue }
        if ($scope -match '(?i)/providers/Microsoft\.KeyVault/vaults/') { $out.Add(('{0} holds a role ({1}) on the Key Vault {2} (no Key Vault role for an internet-facing identity)' -f $IdentityName, $g, $where)); continue }
        $f = Get-SIWebForbiddenRoleName -RoleDefinitionId $g
        if ($f) { $out.Add(('{0} holds {1} on {2} (forbidden for an internet-facing identity)' -f $IdentityName, $f, $where)) }
    }
    $out.ToArray()
}

function Read-SIBuiltInAuthPublicApps {
    <# READ ONLY. Every container app of -WebAppId's resource group with an EXTERNAL ingress, each with its authConfig:
       @{ Apps (@{ Name; Id; Auth }); Errors (an app whose authentication could not be read) }. THROWS when the list cannot
       be read. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$WebAppId,
          [string]$AppApiVersion = $script:SIBuiltInAuthAppApi, [string]$AuthApiVersion = $script:SIBuiltInAuthApi)
    $rgId = [string](($WebAppId -split '(?i)/providers/')[0])
    $list = & $Arm 'GET' ('{0}/providers/Microsoft.App/containerApps?api-version={1}' -f $rgId.TrimEnd('/'), $AppApiVersion) $null
    $ext = @(@(Get-SIBuiltInAuthProp $list @('value')) | Where-Object { $_ -and ("$(Get-SIBuiltInAuthProp $_ @('properties', 'configuration', 'ingress', 'external'))" -match '^(?i)true$') })
    $apps = New-Object System.Collections.Generic.List[object]
    $errs = New-Object System.Collections.Generic.List[string]
    foreach ($x in $ext) {
        $aid = [string](Get-SIBuiltInAuthProp $x @('id'))
        $an = [string](Get-SIBuiltInAuthProp $x @('name'))
        if (-not $an) { $an = [string](($aid -split '/')[-1]) }
        $au = $null
        $why = ''
        try { $au = & $Arm 'GET' ('{0}/authConfigs/current?api-version={1}' -f $aid.TrimEnd('/'), $AuthApiVersion) $null } catch { $why = [string]$_.Exception.Message }
        if ($why) { $errs.Add(('the authentication of {0} could not be read ({1})' -f $an, $why)) }
        else { $apps.Add((New-Object psobject -Property ([ordered]@{ Name = $an; Id = $aid; Auth = $au }))) }
    }
    New-Object psobject -Property ([ordered]@{ Apps = $apps.ToArray(); Errors = $errs.ToArray() })
}

function Read-SIBuiltInAuthStandardFacts {
    <#
        READ ONLY. Everything the standard is checked against: the web app and its authConfig, the MCP app and its authConfig,
        the sign-in app registration (+ its federated credentials), the role assignments of id-si-web and id-si-mcp (under
        -RoleScope: the install's resource group for the updater, the subscription for the support check), the signin-front
        images in the registry (-ListImages). A read that fails is in Errors (and that part is "not checked", never "clean");
        an unreadable registry is a Note only (the images are a report, not part of the standard).
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$WebAppId,
          [string]$McpAppId = '', [string]$RoleScope = '', [scriptblock]$ListImages,
          [string]$AuthApiVersion = $script:SIBuiltInAuthApi, [string]$AppApiVersion = $script:SIBuiltInAuthAppApi, [string]$RoleApiVersion = $script:SIBuiltInAuthRoleApi)
    $f = [ordered]@{ Web = $null; WebAuth = $null; Mcp = $null; McpAuth = $null; McpChecked = $false; Registration = $null; Fics = @(); RegistrationRead = $false
                     TenantId = ''; ClientId = ''; WebIdentity = $null; McpIdentity = $null; Roles = [ordered]@{}; RolesRead = $false
                     Images = $null; Errors = (New-Object System.Collections.Generic.List[string]); Notes = (New-Object System.Collections.Generic.List[string])
                     PublicAppsRead = $false; WebName = ''; McpName = '' }
    # (set as plain statements: an if inside this literal does not compile on every PowerShell)
    $f['PublicApps'] = New-Object System.Collections.Generic.List[object]
    $f['WebName'] = [string](($WebAppId.TrimEnd('/') -split '/')[-1])
    if ("$McpAppId".Trim()) { $f['McpName'] = [string](($McpAppId.TrimEnd('/') -split '/')[-1]) }
    $g = 'https://graph.microsoft.com/v1.0'
    try { $f.Web = & $Arm 'GET' ('{0}?api-version={1}' -f $WebAppId.TrimEnd('/'), $AppApiVersion) $null } catch { $f.Errors.Add(('the web app could not be read ({0})' -f $_.Exception.Message)) }
    if ($f.Web) {
        try { $f.WebAuth = & $Arm 'GET' ('{0}/authConfigs/current?api-version={1}' -f $WebAppId.TrimEnd('/'), $AuthApiVersion) $null } catch { $f.Errors.Add(('the web app''s authentication could not be read ({0})' -f $_.Exception.Message)) }
        $f.TenantId = (Get-SIBuiltInAuthSetting -App $f.Web -Name 'AzureAd__TenantId').ToLowerInvariant()
        $f.ClientId = (Get-SIBuiltInAuthSetting -App $f.Web -Name 'AzureAd__ClientId').ToLowerInvariant()
        $f.WebIdentity = Get-SIBuiltInAuthWebIdentity -App $f.Web -Name 'id-si-web'
    }
    if ("$McpAppId".Trim()) {
        try {
            $f.Mcp = & $Arm 'GET' ('{0}?api-version={1}' -f $McpAppId.TrimEnd('/'), $AppApiVersion) $null
            if ($f.Mcp) {
                $f.McpAuth = & $Arm 'GET' ('{0}/authConfigs/current?api-version={1}' -f $McpAppId.TrimEnd('/'), $AuthApiVersion) $null
                $f.McpIdentity = Get-SIBuiltInAuthWebIdentity -App $f.Mcp -Name 'id-si-mcp'
            }
            $f.McpChecked = $true
        } catch { $f.Errors.Add(('the MCP app could not be read ({0})' -f $_.Exception.Message)) }
    }
    # EVERY container app of the install's resource group with an EXTERNAL ingress, each with its authConfig
    try {
        $pa = Read-SIBuiltInAuthPublicApps -Arm $Arm -WebAppId $WebAppId -AppApiVersion $AppApiVersion -AuthApiVersion $AuthApiVersion
        $f['PublicApps'] = @($pa.Apps)
        foreach ($e in @($pa.Errors)) { $f.Errors.Add([string]$e) }
        $f['PublicAppsRead'] = $true
    } catch { $f.Errors.Add(('the container apps of the resource group could not be listed ({0})' -f $_.Exception.Message)) }
    if ($f.ClientId -match '^[0-9a-f-]{36}$') {
        try {
            $f.Registration = & $Graph 'GET' ("$g/applications(appId='{0}')?`$select=id,web,spa,publicClient,passwordCredentials,keyCredentials,identifierUris,api" -f $f.ClientId) $null
            if ($f.Registration -and [string](Get-SIBuiltInAuthProp $f.Registration @('id'))) {
                $f.Fics = @(Get-SIBuiltInAuthProp (& $Graph 'GET' ("$g/applications/{0}/federatedIdentityCredentials" -f [string]$f.Registration.id) $null) @('value'))
            }
            $f.RegistrationRead = $true
        } catch { $f.Errors.Add(('the sign-in app registration could not be read ({0})' -f $_.Exception.Message)) }
    }
    if ("$RoleScope".Trim()) {
        $ok = $true
        foreach ($id in @(@($f.WebIdentity) + @($f.McpIdentity) | Where-Object { $_ })) {
            try {
                $p = "{0}/providers/Microsoft.Authorization/roleAssignments?api-version={1}&`$filter=principalId eq '{2}'" -f $RoleScope.TrimEnd('/'), $RoleApiVersion, $id.PrincipalId
                $f.Roles[$id.Name] = [pscustomobject]@{ PrincipalId = $id.PrincipalId; Assignments = @(Get-SIBuiltInAuthProp (& $Arm 'GET' $p $null) @('value')) }
            } catch { $ok = $false; $f.Errors.Add(('the roles of {0} could not be read ({1})' -f $id.Name, $_.Exception.Message)) }
        }
        $f.RolesRead = $ok
    }
    if ($ListImages -and $f.Web) {
        $img = ''
        $i = Get-SIBuiltInAuthWebContainerIndex -App $f.Web
        if ($i -ge 0) { $img = [string](Get-SIBuiltInAuthProp (@(Get-SIBuiltInAuthProp $f.Web @('properties', 'template', 'containers'))[$i]) @('image')) }
        $login = if ($img -match '^([^/]+\.[^/]+)/') { $Matches[1] } else { '' }
        if ($login) {
            try { $r = & $ListImages $login $script:SIBuiltInAuthFrontRepo; $f.Images = [pscustomobject]@{ LoginServer = $login; Found = [bool]$r.Found; Tags = @($r.Tags) } }
            catch { $f.Notes.Add(('the signin-front images in {0} could not be read ({1}) -- not checked' -f $login, $_.Exception.Message)) }
        }
    }
    [pscustomobject]$f
}

function Get-SIBuiltInAuthPublicAppFindings {
    <#
        PURE. EVERY internet-facing container app of the install (-Facts.PublicApps: ingress.external = true) against the rule
        "every public endpoint answers only through Microsoft's authentication": flagged when it has NO authConfig, the
        platform is OFF, or unauthenticatedClientAction is AllowAnonymous; else when its action is not the expected one (the
        web app RedirectToLoginPage -- checked in depth by name; the MCP and any API-only app Return401). An app on
        -Exceptions (@{ App; Reason }; $script:SIBuiltInAuthPublicExceptions, kept empty) is not flagged. An internal-only
        app is never in the list. One text per finding.
    #>
    param([Parameter(Mandatory)]$Facts, [object[]]$Exceptions = $script:SIBuiltInAuthPublicExceptions)
    $out = New-Object System.Collections.Generic.List[string]
    $ex = @(@($Exceptions) | Where-Object { $_ -and "$(Get-SIBuiltInAuthProp $_ @('App'))".Trim() -and "$(Get-SIBuiltInAuthProp $_ @('Reason'))".Trim() } | ForEach-Object { "$(Get-SIBuiltInAuthProp $_ @('App'))".Trim().ToLowerInvariant() })
    foreach ($p in @($Facts.PublicApps)) {
        if (-not $p) { continue }
        $n = [string]$p.Name
        if ($ex -contains $n.ToLowerInvariant()) { continue }
        $a = $p.Auth
        $act = "$(Get-SIBuiltInAuthProp $a @('properties', 'globalValidation', 'unauthenticatedClientAction'))".Trim()
        $why = if (-not $a) { 'no authentication configuration' }
               elseif ("$(Get-SIBuiltInAuthProp $a @('properties', 'platform', 'enabled'))" -notmatch '^(?i)true$') { 'the platform authentication is OFF' }
               elseif (-not $act -or $act -ieq 'AllowAnonymous') { 'unauthenticatedClientAction AllowAnonymous -- requests without a sign-in reach the app' }
               else { '' }
        if ($why) { $out.Add(('{0}: internet-facing without Microsoft''s authentication ({1})' -f $n, $why)); continue }
        if ($n -ieq [string]$Facts.WebName -or $n -ieq [string]$Facts.McpName) { continue }   # (checked in depth by name)
        if ($act -ine 'Return401') { $out.Add(('{0}: internet-facing with unauthenticatedClientAction {1} (an API-only app answers Return401)' -f $n, $act)) }
    }
    $out.ToArray()
}

function Get-SIBuiltInAuthLeftoverFindings {
    <# PURE. Every leftover of the sign-in front era in -Facts (Read-SIBuiltInAuthStandardFacts), one text each. #>
    param([Parameter(Mandatory)]$Facts)
    $out = New-Object System.Collections.Generic.List[string]
    if ($Facts.Web) {
        foreach ($n in @(Get-SIBuiltInAuthLeftoverEnvNames -App $Facts.Web)) { $out.Add(('the web container''s setting {0} (the sign-in front''s)' -f $n)) }
        $ls = Get-SIBuiltInAuthLeftoverSecrets -App $Facts.Web -AuthConfig $Facts.WebAuth
        foreach ($n in @($ls.Remove)) { $out.Add(('the web app''s container-app secret ''{0}'' (the old sign-in''s, nothing references it)' -f $n)) }
        foreach ($r in @($ls.Report)) { $out.Add(('the web app''s container-app secret ''{0}'' ({1})' -f $r.Name, $r.Why)) }
        $fqdn = [string](Get-SIBuiltInAuthProp $Facts.Web @('properties', 'configuration', 'ingress', 'fqdn'))
        $hosts = @(@(Get-SIBuiltInAuthProp $Facts.Web @('properties', 'configuration', 'ingress', 'customDomains')) | ForEach-Object { [string](Get-SIBuiltInAuthProp $_ @('name')) } | Where-Object { $_ })
        foreach ($t in @(Get-SIBuiltInAuthRegistrationLeftovers -Registration $Facts.Registration -Fqdn $fqdn -CustomDomains $hosts)) { $out.Add($t) }
    }
    if ($Facts.Images -and $Facts.Images.Found -and @($Facts.Images.Tags).Count) {
        $out.Add(('{0} signin-front image(s) still stored in {1} (tags {2}) -- the update removes them once the web app reads back without the sign-in front' -f @($Facts.Images.Tags).Count, $Facts.Images.LoginServer, (@($Facts.Images.Tags) -join ',')))
    }
    $out.ToArray()
}

function Test-SIBuiltInAuthStandard {
    <#
        PURE. -Facts (Read-SIBuiltInAuthStandardFacts) against THE STANDARD:
          web app   its own container only; SI_Web_BuiltInAuth=1; the ingress on 8080; the secret
                    override-use-mi-fic-assertion-client-id; authConfig: platform on, RedirectToLoginPage, the app
                    registration of AzureAd__ClientId, the secret setting, the v2.0 issuer, both audiences,
                    prompt=select_account in the provider's login parameters, the token store ON in si-auth-tokens with
                    id-si-web, FixedTime 08:00:00, HTTPS only;
          MCP app   (when there is one) platform on, Return401, the same app registration, both audiences, no sign-in
                    (no login parameters, no secret setting, no token store), open EXACTLY the named paths (/healthz and the RFC 9728 metadata, $script:SIBuiltInAuthMcpOpenPaths) -- any other or a missing one = DIFF;
          the app registration   ID tokens ON, access tokens OFF, the callback of the web app's address, a federated
                    credential for id-si-web; with an MCP app, the MCP's own delegated scope mcp.access;
          rights    id-si-web and id-si-mcp hold no Key Vault role and none of the forbidden roles.
        @{ Ok (no difference and no leftover); Diff; Leftovers; Summary ('built-in sign-in standard: OK' | 'DIFF: ...') }.
    #>
    param([Parameter(Mandatory)]$Facts)
    $d = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($Facts.Errors)) { if ("$e".Trim()) { $d.Add(('not checked: {0}' -f $e)) } }
    $web = $Facts.Web; $cid = "$($Facts.ClientId)"; $tid = "$($Facts.TenantId)"
    if (-not $web) { if (-not @($Facts.Errors).Count) { $d.Add('the web app was not found') } }
    else {
        $names = @(@(Get-SIBuiltInAuthProp $web @('properties', 'template', 'containers')) | ForEach-Object { [string](Get-SIBuiltInAuthProp $_ @('name')) })
        if ($names.Count -ne 1 -or $names -contains $script:SIBuiltInAuthFrontName) { $d.Add(('containers {0} (want the web container only)' -f ($names -join '+'))) }
        if ((Get-SIBuiltInAuthSetting -App $web) -ne '1') { $d.Add(('{0} is not 1' -f $script:SIBuiltInAuthSettingName)) }
        $port = [int](0 + (Get-SIBuiltInAuthProp $web @('properties', 'configuration', 'ingress', 'targetPort')))
        if ($port -ne $script:SIBuiltInAuthWebPort) { $d.Add(('the ingress targets port {0} (want {1})' -f $port, $script:SIBuiltInAuthWebPort)) }
        if (-not @(@(Get-SIBuiltInAuthProp $web @('properties', 'configuration', 'secrets')) | Where-Object { [string](Get-SIBuiltInAuthProp $_ @('name')) -ieq $script:SIBuiltInAuthSecretName }).Count) { $d.Add(('the secret {0} is missing' -f $script:SIBuiltInAuthSecretName)) }
        $a = $Facts.WebAuth
        $aad = @('properties', 'identityProviders', 'azureActiveDirectory')
        $is = { param($o, [string[]]$p, [string]$v) "$(Get-SIBuiltInAuthProp $o $p)".Trim() -ieq $v }
        if (-not $a) { $d.Add('the web app has no authentication configuration') }
        else {
            if (-not (& $is $a @('properties', 'platform', 'enabled') 'true')) { $d.Add('web: platform authentication OFF') }
            if (-not (& $is $a @('properties', 'globalValidation', 'unauthenticatedClientAction') 'RedirectToLoginPage')) { $d.Add(('web: unauthenticatedClientAction={0}' -f (Get-SIBuiltInAuthProp $a @('properties', 'globalValidation', 'unauthenticatedClientAction')))) }
            if (-not $cid -or -not (& $is $a ($aad + @('registration', 'clientId')) $cid)) { $d.Add(('web: registration.clientId {0} is not AzureAd__ClientId {1}' -f (Get-SIBuiltInAuthProp $a ($aad + @('registration', 'clientId'))), $cid)) }
            if (-not (& $is $a ($aad + @('registration', 'clientSecretSettingName')) $script:SIBuiltInAuthSecretName)) { $d.Add(('web: clientSecretSettingName={0}' -f (Get-SIBuiltInAuthProp $a ($aad + @('registration', 'clientSecretSettingName'))))) }
            if (-not (& $is $a ($aad + @('registration', 'openIdIssuer')) ('https://login.microsoftonline.com/{0}/v2.0' -f $tid))) { $d.Add(('web: openIdIssuer={0}' -f (Get-SIBuiltInAuthProp $a ($aad + @('registration', 'openIdIssuer'))))) }
            $aud = @(@(Get-SIBuiltInAuthProp $a ($aad + @('validation', 'allowedAudiences'))) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Sort-Object -Unique)
            if (($aud -join ',') -ne ((@(('api://{0}' -f $cid), $cid) | Sort-Object -Unique) -join ',')) { $d.Add(('web: allowedAudiences={0}' -f ($aud -join ','))) }
            if (@(Get-SIBuiltInAuthProp $a ($aad + @('login', 'loginParameters'))) -notcontains 'prompt=select_account') { $d.Add('web: the account picker (prompt=select_account) is missing') }
            if (-not (& $is $a @('properties', 'login', 'tokenStore', 'enabled') 'true')) { $d.Add('web: token store OFF') }
            if ("$(Get-SIBuiltInAuthProp $a @('properties', 'login', 'tokenStore', 'azureBlobStorage', 'blobContainerUri'))".TrimEnd('/') -notmatch ('/{0}$' -f [regex]::Escape($script:SIBuiltInAuthTokenStoreName))) { $d.Add(('web: the token store is not the container {0}' -f $script:SIBuiltInAuthTokenStoreName)) }
            if ("$(Get-SIBuiltInAuthProp $a @('properties', 'login', 'tokenStore', 'azureBlobStorage', 'managedIdentityResourceId'))" -notmatch '(?i)/id-si-web$') { $d.Add('web: the token store is not reached with id-si-web') }
            if (-not (& $is $a @('properties', 'login', 'cookieExpiration', 'convention') 'FixedTime') -or -not (& $is $a @('properties', 'login', 'cookieExpiration', 'timeToExpiration') '08:00:00')) { $d.Add(('web: session {0} {1} (want FixedTime 08:00:00)' -f (Get-SIBuiltInAuthProp $a @('properties', 'login', 'cookieExpiration', 'convention')), (Get-SIBuiltInAuthProp $a @('properties', 'login', 'cookieExpiration', 'timeToExpiration')))) }
            if (-not (& $is $a @('properties', 'httpSettings', 'requireHttps') 'true')) { $d.Add('web: HTTPS is not required') }
        }
        # the app registration
        if ($Facts.RegistrationRead) {
            $reg = $Facts.Registration
            if (-not $reg) { $d.Add(('the sign-in app registration {0} was not found' -f $cid)) }
            else {
                $ig = Get-SIBuiltInAuthProp $reg @('web', 'implicitGrantSettings')
                if (-not ("$(Get-SIBuiltInAuthProp $ig @('enableIdTokenIssuance'))" -match '^(?i)true$')) { $d.Add('registration: ID-token issuance OFF') }
                if ("$(Get-SIBuiltInAuthProp $ig @('enableAccessTokenIssuance'))" -match '^(?i)true$') { $d.Add('registration: access-token issuance ON') }
                $fqdn = [string](Get-SIBuiltInAuthProp $web @('properties', 'configuration', 'ingress', 'fqdn'))
                $cb = 'https://{0}{1}' -f $fqdn.ToLowerInvariant(), $script:SIBuiltInAuthCallbackPath
                if (-not @(@(Get-SIBuiltInAuthProp $reg @('web', 'redirectUris')) | Where-Object { "$_".Trim().TrimEnd('/') -ieq $cb }).Count) { $d.Add(('registration: the callback {0} is missing' -f $cb)) }
                if ($Facts.WebIdentity -and $tid -and -not (Test-SIBuiltInAuthFic -Credentials @($Facts.Fics) -TenantId $tid -PrincipalId $Facts.WebIdentity.PrincipalId)) { $d.Add('registration: no federated credential for id-si-web') }
                # the MCP's own delegated scope (SI-McpScope.ps1): what its RFC 9728 metadata names
                if ($Facts.Mcp -and $cid -match '^[0-9a-f-]{36}$') {
                    $mp = Get-SIMcpScopePlan -App $reg -ClientId $cid
                    if ($mp.NeedScope) { $d.Add(('registration: the MCP scope {0} is missing' -f (Get-SIMcpScopeValue -ClientId $cid))) }
                    elseif ($mp.NeedUri) { $d.Add(('registration: the identifier URI api://{0} is missing' -f $cid)) }
                }
            }
        }
        if (-not $Facts.WebIdentity) { $d.Add('the web app has no managed identity id-si-web') }
    }
    # the MCP app
    if ($Facts.Mcp) {
        $m = $Facts.McpAuth
        $want = $null
        if ($tid -match '^[0-9a-f-]{36}$' -and $cid -match '^[0-9a-f-]{36}$') { $want = Get-SIBuiltInAuthMcpConfigBody -TenantId $tid -ClientId $cid }
        if (-not $m) { $d.Add('mcp: no authentication configuration (Return401 wanted)') }
        elseif ($want) {
            $c = Test-SIBuiltInAuthMcpConfigMatches -Current $m -Want $want
            foreach ($x in @($c.Diff)) { if ($x -ne 'globalValidation.excludedPaths') { $d.Add(('mcp: {0}' -f $x)) } }
            # the open paths: EXACTLY the named ones ($script:SIBuiltInAuthMcpOpenPaths) -- any other = DIFF, a missing one too
            foreach ($x in @(Get-SIBuiltInAuthMcpOpenPathFindings -Current $m)) { $d.Add($x) }
        }
        $own = (Get-SIBuiltInAuthSetting -App $Facts.Mcp -Name 'AzureAd__ClientId').ToLowerInvariant()
        if ($own -and $cid -and $own -ne $cid) { $d.Add(('mcp: AzureAd__ClientId {0} is not the web app''s {1}' -f $own, $cid)) }
    }
    # every internet-facing container app, not only the web app and the MCP by name
    foreach ($x in @(Get-SIBuiltInAuthPublicAppFindings -Facts $Facts)) { $d.Add($x) }
    # rights
    foreach ($k in @($Facts.Roles.Keys)) {
        foreach ($x in @(Get-SIBuiltInAuthRoleFindings -Assignments @($Facts.Roles[$k].Assignments) -PrincipalId $Facts.Roles[$k].PrincipalId -IdentityName $k)) { $d.Add($x) }
    }
    $left = @(Get-SIBuiltInAuthLeftoverFindings -Facts $Facts)
    $items = @($d.ToArray()) + @(if ($left.Count) { ('{0} leftover(s)' -f $left.Count) })
    [pscustomobject]@{
        Ok = ($items.Count -eq 0); Diff = $d.ToArray(); Leftovers = $left
        Summary = $(if ($items.Count) { 'built-in sign-in standard: DIFF: ' + ($items -join '; ') } else { 'built-in sign-in standard: OK' })
    }
}

# ============================================================================================================== 4. THE UPDATE'S STEP

function Invoke-SIBuiltInAuthLeftoverClean {
    <#
        The web app WITHOUT the sign-in front's leftovers -- ONLY on a web app that reads back switched (Test-SIBuiltInAuthSwitched):
        the web container's front settings and the unreferenced era secrets go in ONE PATCH (every other secret kept: from
        listSecrets; an unreadable one = nothing written), read back: the settings gone, every kept secret still there, the
        removed ones gone, the app still switched. -Mode plan says what would go. NEVER THROWS; never a failure of the
        update. @{ Lines; Warnings; Removed }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [ValidateSet('plan', 'apply')][string]$Mode = 'plan', [Parameter(Mandatory)][string]$WebAppId,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$Tries = 6, [int]$PauseSeconds = 10, [int]$BusyTries = 30,
          [string]$AuthApiVersion = $script:SIBuiltInAuthApi, [string]$AppApiVersion = $script:SIBuiltInAuthAppApi)
    $lines = New-Object System.Collections.Generic.List[string]
    $warn = New-Object System.Collections.Generic.List[string]
    $removed = New-Object System.Collections.Generic.List[string]
    $res = { [pscustomobject]@{ Lines = $lines.ToArray(); Warnings = $warn.ToArray(); Removed = $removed.ToArray() } }
    $web = ($WebAppId.TrimEnd('/') -split '/')[-1]
    $appPath = '{0}?api-version={1}' -f $WebAppId.TrimEnd('/'), $AppApiVersion
    $listPath = '{0}/listSecrets?api-version={1}' -f $WebAppId.TrimEnd('/'), $AppApiVersion
    try {
        $app = & $Arm 'GET' $appPath $null
        if (-not $app) { return (& $res) }
        if (-not (Test-SIBuiltInAuthSwitched -App $app).Ok) { $lines.Add(('{0}: the sign-in front''s leftovers are left until the web app runs Microsoft''s built-in sign-in' -f $web)); return (& $res) }
        $auth = & $Arm 'GET' ('{0}/authConfigs/current?api-version={1}' -f $WebAppId.TrimEnd('/'), $AuthApiVersion) $null
        $envGo = @(Get-SIBuiltInAuthLeftoverEnvNames -App $app)
        $sec = Get-SIBuiltInAuthLeftoverSecrets -App $app -AuthConfig $auth -WithoutEnv $envGo
        $secGo = @($sec.Remove)
        if (-not $envGo.Count -and -not $secGo.Count) { return (& $res) }
        $what = @(@($envGo | ForEach-Object { 'the setting ' + $_ }) + @($secGo | ForEach-Object { 'the secret ' + $_ })) -join ', '
        # (plan: each of them is also one 'leftover:' line of the standard's check)
        if ($Mode -eq 'plan') { $lines.Add(('{0}: the sign-in front''s leftovers -- would remove: {1} (nothing was changed)' -f $web, $what)); return (& $res) }
        $sv = ConvertTo-SIBuiltInAuthSecretValues (& $Arm 'POST' $listPath $null)
        $p = Get-SIBuiltInAuthLeftoverPatch -App $app -SecretValues $sv -RemoveEnv $envGo -RemoveSecrets $secGo
        if ($p.MissingSecrets.Count) { $warn.Add(('leftover: {0}: {1} -- NOT removed: the secret(s) {2} could not be read, and a write would blank them' -f $web, $what, ($p.MissingSecrets -join ', '))); return (& $res) }
        $null = Invoke-SIBuiltInAuthBusyWrite -Arm $Arm -Method 'PATCH' -Path $appPath -Body $p.Body -AppPath $appPath -Sleep $Sleep -BusyTries $BusyTries -PauseSeconds $PauseSeconds
        $keep = @(@($sv.Keys) | Where-Object { $k = $_; -not @($secGo | Where-Object { $_ -ieq $k }).Count })
        $ok = $false; $why = 'not read yet'
        for ($i = 1; $i -le $Tries; $i++) {
            try {
                $n = & $Arm 'GET' $appPath $null
                $envLeft = @(Get-SIBuiltInAuthLeftoverEnvNames -App $n | Where-Object { $envGo -contains $_ })
                $sb = ConvertTo-SIBuiltInAuthSecretValues (& $Arm 'POST' $listPath $null)
                $lost = @($keep | Where-Object { -not $sb.ContainsKey($_) })
                $still = @($secGo | Where-Object { $sb.ContainsKey($_) })
                $sw = (Test-SIBuiltInAuthSwitched -App $n).Ok
                if (-not $envLeft.Count -and -not $lost.Count -and -not $still.Count -and $sw) { $ok = $true; break }
                $why = 'settings still there: {0}; secrets lost: {1}; secrets still there: {2}; switched: {3}' -f ($envLeft -join ','), ($lost -join ','), ($still -join ','), $sw
            } catch { $why = $_.Exception.Message }
            if ($i -lt $Tries) { & $Sleep $PauseSeconds }
        }
        if (-not $ok) { $warn.Add(('leftover: {0}: the removal of {1} does not read back ({2}) -- check the web app by hand; the next update tries again' -f $web, $what, $why)); return (& $res) }
        foreach ($x in @($envGo + $secGo)) { $removed.Add($x) }
        $lines.Add(('{0}: the sign-in front''s leftovers were removed: {1} (read back; every other secret kept)' -f $web, $what))
    } catch { $warn.Add(('leftover: {0}: the sign-in front''s leftovers could not be checked ({1}) -- the update goes on' -f $web, $_.Exception.Message)) }
    & $res
}

function Invoke-SIBuiltInAuthStandardStep {
    <#
        After the web app's converge (Invoke-SIBuiltInAuthConverge -> -WebResult), in the same update step:
          apply   ONLY when the web app reads back switched (WebResult.State applied / in-place): the MCP's own delegated
                  scope mcp.access on the sign-in app registration (Invoke-SIMcpScopeConverge, SI-McpScope.ps1: with the
                  updater's Graph sign-in, Application.ReadWrite.OwnedBy as the registration's owner; a refusal = a warning
                  and a support step), the MCP app behind Microsoft's authentication (Invoke-SIBuiltInAuthMcpConverge,
                  /healthz and the RFC 9728 metadata open), then the leftovers removed
                  (Invoke-SIBuiltInAuthLeftoverClean); a web app that did not switch -> neither, said once;
          plan    the MCP plan line and the leftovers that would go; nothing is written;
        then the standard read and checked (Test-SIBuiltInAuthStandard): every leftover one 'leftover: ...' warning, and the
        summary 'built-in sign-in standard: OK' or 'built-in sign-in standard: DIFF: ...'.
        NEVER THROWS. @{ Ok (the MCP part ended well); McpState; Lines; Warnings; Standard }. $null for redirect / off.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Graph, [string]$Mode = 'plan',
          [Parameter(Mandatory)][string]$WebAppId, [string]$McpAppId = '', $WebResult, [scriptblock]$Probe, [scriptblock]$ListImages,
          [string]$RoleScope = '', [string]$McpOpenIdIssuer = '', [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          [int]$Tries = 6, [int]$PauseSeconds = 10, [int]$ProbeTries = 6, [int]$BusyTries = 30)
    if ($Mode -notin 'plan', 'apply') { return $null }
    $lines = New-Object System.Collections.Generic.List[string]
    $warn = New-Object System.Collections.Generic.List[string]
    $mcpOk = $true; $mcpState = 'not-run'; $mcpScopeState = 'not-run'; $std = $null; $trace = ''
    try {
        $webSwitched = $WebResult -and $WebResult.Ok -and ([string]$WebResult.State -in 'applied', 'in-place')
        $go = ($Mode -eq 'plan') -or $webSwitched
        if (-not $go) { $lines.Add('the MCP app and the sign-in front''s leftovers wait until the web app runs Microsoft''s built-in sign-in') }
        else {
            $app = & $Arm 'GET' ('{0}?api-version={1}' -f $WebAppId.TrimEnd('/'), $script:SIBuiltInAuthAppApi) $null
            $tid = Get-SIBuiltInAuthSetting -App $app -Name 'AzureAd__TenantId'; $cid = Get-SIBuiltInAuthSetting -App $app -Name 'AzureAd__ClientId'
            if ("$McpAppId".Trim() -and $tid -match '^[0-9a-fA-F-]{36}$' -and $cid -match '^[0-9a-fA-F-]{36}$') {
                # the MCP's own delegated scope mcp.access on the sign-in app registration (SI-McpScope.ps1: beside every
                # other scope, read back) -- what the RFC 9728 metadata names; never a failure of the update
                $sc = Invoke-SIMcpScopeConverge -Graph $Graph -ClientId $cid -Mode $Mode -Sleep $Sleep
                $mcpScopeState = [string]$sc.State
                foreach ($l in @($sc.Lines)) { if ($sc.State -in 'no-rights', 'failed') { $warn.Add($l) } else { $lines.Add($l) } }
                if ("$($sc.Support)".Trim()) { $warn.Add(('support step: {0}' -f $sc.Support)) }
                $ma = @{ Arm = $Arm; Mode = $Mode; McpAppId = $McpAppId; TenantId = $tid; ClientId = $cid; Sleep = $Sleep; Tries = $Tries; PauseSeconds = $PauseSeconds; ProbeTries = $ProbeTries; BusyTries = $BusyTries; OpenIdIssuer = $McpOpenIdIssuer }
                if ($Probe) { $ma['Probe'] = $Probe }
                $m = Invoke-SIBuiltInAuthMcpConverge @ma
                $mcpOk = [bool]$m.Ok; $mcpState = [string]$m.State
                foreach ($l in @($m.Lines)) { $lines.Add($l) }; foreach ($l in @($m.Warnings)) { $warn.Add($l) }
            } elseif ("$McpAppId".Trim()) { $warn.Add('the MCP app was not checked -- the web app''s sign-in settings (AzureAd__TenantId / AzureAd__ClientId) could not be read') }
            $lc = Invoke-SIBuiltInAuthLeftoverClean -Arm $Arm -Mode $Mode -WebAppId $WebAppId -Sleep $Sleep -Tries $Tries -PauseSeconds $PauseSeconds -BusyTries $BusyTries
            foreach ($l in @($lc.Lines)) { $lines.Add($l) }; foreach ($l in @($lc.Warnings)) { $warn.Add($l) }
        }
        $fa = @{ Arm = $Arm; Graph = $Graph; WebAppId = $WebAppId; McpAppId = $McpAppId; RoleScope = $RoleScope }
        if ($ListImages) { $fa['ListImages'] = $ListImages }
        $facts = Read-SIBuiltInAuthStandardFacts @fa
        foreach ($x in @($facts.Notes)) { $lines.Add($x) }
        $std = Test-SIBuiltInAuthStandard -Facts $facts
        foreach ($x in @($std.Leftovers)) { $warn.Add(('leftover: {0}' -f $x)) }
        if ($std.Ok) { $lines.Add($std.Summary) } else { $warn.Add($std.Summary) }
    } catch { $warn.Add(('the built-in sign-in standard could not be checked ({0}) -- the update goes on' -f $_.Exception.Message)); $trace = "$($_.ScriptStackTrace)" }
    [pscustomobject]@{ Ok = $mcpOk; McpState = $mcpState; McpScopeState = $mcpScopeState; Lines = $lines.ToArray(); Warnings = $warn.ToArray(); Standard = $std; Trace = $trace }
}

# ============================================================================================================== 5. THE FRONT'S DATA-PLANE LEFTOVERS

$script:SIBuiltInAuthKvApi = '7.4'   # the Key Vault data plane

function Test-SIBuiltInAuthFrontImage {
    <# PURE. Does the image reference -Image name the sign-in front's repository (<registry>/signin-front:<tag> or @<digest>)? #>
    param([AllowNull()][AllowEmptyString()][string]$Image, [string]$Repo = $script:SIBuiltInAuthFrontRepo)
    "$Image".Trim() -match ('(?i)(^|/){0}([:@]|$)' -f [regex]::Escape($Repo))
}

function Get-SIBuiltInAuthFrontUse {
    <# PURE. Does a template (an app's or a revision's) still run the sign-in front: a container named signin-front, or any
       container / init container whose image is in the signin-front repository? $true / $false. #>
    param($Template)
    foreach ($c in @(@(Get-SIBuiltInAuthProp $Template @('containers')) + @(Get-SIBuiltInAuthProp $Template @('initContainers')))) {
        if (-not $c) { continue }
        if ([string](Get-SIBuiltInAuthProp $c @('name')) -eq $script:SIBuiltInAuthFrontName) { return $true }
        if (Test-SIBuiltInAuthFrontImage -Image ([string](Get-SIBuiltInAuthProp $c @('image')))) { return $true }
    }
    $false
}

function Test-SIBuiltInAuthFrontGone {
    <#
        PURE. May the sign-in front's stored data go? ALL of these, as read:
          1. the web app reads back switched (Test-SIBuiltInAuthSwitched: SI_Web_BuiltInAuth=1, no signin-front container in
             its template, the ingress on the web container's port);
          2. Microsoft's built-in sign-in is ON (its authConfig: platform.enabled true);
          3. its latest revision is its latest READY revision, that revision is listed (-Revisions), Healthy and running;
          4. NO active revision of the web app runs the front (a signin-front container or a signin-front image);
          5. NO container app of the install (-Apps, the resource group's list) names a signin-front image in its template.
        @{ Ok; Why }.
    #>
    param($App, $Auth, [object[]]$Revisions = @(), [object[]]$Apps = @())
    $sw = Test-SIBuiltInAuthSwitched -App $App
    if (-not $sw.Ok) { return [pscustomobject]@{ Ok = $false; Why = ('the web app does not read back on Microsoft''s built-in sign-in ({0})' -f $sw.Why) } }
    if ("$(Get-SIBuiltInAuthProp $Auth @('properties', 'platform', 'enabled'))" -notmatch '^(?i)true$') { return [pscustomobject]@{ Ok = $false; Why = 'Microsoft''s built-in sign-in is not on (its authentication reads back off)' } }
    $latest = [string](Get-SIBuiltInAuthProp $App @('properties', 'latestRevisionName'))
    $ready = [string](Get-SIBuiltInAuthProp $App @('properties', 'latestReadyRevisionName'))
    if (-not $latest) { return [pscustomobject]@{ Ok = $false; Why = 'the web app names no revision' } }
    if ($latest -ne $ready) { return [pscustomobject]@{ Ok = $false; Why = ('its latest revision {0} is not the ready one ({1})' -f $latest, $(if ($ready) { $ready } else { 'none' })) } }
    $rev = @(@($Revisions) | Where-Object { $_ -and [string](Get-SIBuiltInAuthProp $_ @('name')) -eq $latest }) | Select-Object -First 1
    if (-not $rev) { return [pscustomobject]@{ Ok = $false; Why = ('its revision {0} could not be read' -f $latest) } }
    $h = [string](Get-SIBuiltInAuthProp $rev @('properties', 'healthState'))
    if ($h -ne 'Healthy') { return [pscustomobject]@{ Ok = $false; Why = ('its revision {0} is {1}, not Healthy' -f $latest, $(if ($h) { $h } else { 'of no known health' })) } }
    $rs = [string](Get-SIBuiltInAuthProp $rev @('properties', 'runningState'))
    if ($rs -and $rs -notmatch '^(?i)(Running|RunningAtMaxScale)$') { return [pscustomobject]@{ Ok = $false; Why = ('its revision {0} is {1}' -f $latest, $rs) } }
    foreach ($rv in @(@($Revisions) | Where-Object { $_ })) {
        $active = "$(Get-SIBuiltInAuthProp $rv @('properties', 'active'))" -match '^(?i)true$'
        if (($active -or [string](Get-SIBuiltInAuthProp $rv @('name')) -eq $latest) -and (Get-SIBuiltInAuthFrontUse -Template (Get-SIBuiltInAuthProp $rv @('properties', 'template')))) {
            return [pscustomobject]@{ Ok = $false; Why = ('its revision {0} still runs the sign-in front' -f [string](Get-SIBuiltInAuthProp $rv @('name'))) }
        }
    }
    foreach ($a in @(@($Apps) | Where-Object { $_ })) {
        if (Get-SIBuiltInAuthFrontUse -Template (Get-SIBuiltInAuthProp $a @('properties', 'template'))) {
            return [pscustomobject]@{ Ok = $false; Why = ('the container app {0} still names a sign-in front image' -f [string](Get-SIBuiltInAuthProp $a @('name'))) }
        }
    }
    [pscustomobject]@{ Ok = $true; Why = '' }
}

function Test-SIBuiltInAuthKeyRingOnBlob {
    <# PURE. Does the web app keep its sign-in keys in its own blob, read back: DataProtection__BlobUri set (https) on its web
       container AND its latest (ready, Healthy, running) revision runs with that same value (Test-SIBuiltInAuthRevisionRuns)?
       The web app then reads no Key Vault key (pro-management/src/SI.Management.Web/Auth/WebKeyRingSetup.cs). @{ Ok; Why }. #>
    param($App, [object[]]$Revisions = @())
    $blob = Get-SIBuiltInAuthSetting -App $App -Name $script:SIBuiltInAuthKeyRingSetting
    if ($blob -notmatch '^(?i)https://') { return [pscustomobject]@{ Ok = $false; Why = ('the web app does not keep its sign-in keys in its own key store yet ({0} is not set)' -f $script:SIBuiltInAuthKeyRingSetting) } }
    $latest = [string](Get-SIBuiltInAuthProp $App @('properties', 'latestRevisionName'))
    $rev = @(@($Revisions) | Where-Object { $_ -and [string](Get-SIBuiltInAuthProp $_ @('name')) -eq $latest }) | Select-Object -First 1
    $r = Test-SIBuiltInAuthRevisionRuns -App $App -Revision $rev -Name $script:SIBuiltInAuthKeyRingSetting -Value $blob
    if (-not $r.Ok) { return [pscustomobject]@{ Ok = $false; Why = ('the web app does not run on its own key store yet ({0})' -f $r.Why) } }
    [pscustomobject]@{ Ok = $true; Why = '' }
}

function Invoke-SIBuiltInAuthFrontDataClean {
    <#
        THE EARLIER SIGN-IN FRONT'S DATA-PLANE LEFTOVERS, DELETED BY SECURITYINSIGHT'S OWN CODE (Invardia works on control
        planes only: deleting a Key Vault key or a registry image at an install is data plane). -Mode plan says what would go
        and deletes nothing. ONLY when Test-SIBuiltInAuthFrontGone holds -- the web app reads back switched, the built-in
        sign-in is on, its latest revision is the ready, Healthy, running one, and nothing (no active revision, no container
        app) runs the front:
          1. THE IMAGES: every image of the repository signin-front in the install's registry (-Registry: the updater's
             registry seam, New-SIUpdaterRegistrySeam -- List / Delete by digest), then read back: none listed. An image locked
             against deletion is kept and said.
          2. THE KEYS signin-front-dp and SI-Web-KeyRing in the install's Key Vault (-KeyVault { param($Method, $Uri, $Body) }
             -> @{ Status; Json }, the data plane; DELETE = soft delete, recoverable for the vault's retention period), read
             back gone -- EACH only when ALSO the web app keeps its sign-in keys in its own blob, read back
             (Test-SIBuiltInAuthKeyRingOnBlob: then the web app reads neither key), AND id-si-web holds no role on that key any
             more (read at the key's scope through -Arm with -VaultId; a role still there or an unreadable list = kept).
        One plain line per part ("removed" / "none left" / "kept: why"). A refusal (401 / 403: the updater lacks the data
        right) is a warning plus a support step that gives the right back -- never a failure. NEVER THROWS.
        Returns @{ Lines; Warnings; Support; Removed; Images (state); Keys (name -> state) }; states: removed | none |
        planned | kept | refused | failed | not-checked.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [ValidateSet('plan', 'apply')][string]$Mode = 'plan', [Parameter(Mandatory)][string]$WebAppId,
          [hashtable]$Registry, [string]$LoginServer = '', [string]$RegistryNote = '',
          [scriptblock]$KeyVault, [string]$VaultName = '', [string]$VaultId = '',
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$Tries = 4, [int]$PauseSeconds = 10,
          [string]$AuthApiVersion = $script:SIBuiltInAuthApi, [string]$AppApiVersion = $script:SIBuiltInAuthAppApi,
          [string]$RoleApiVersion = $script:SIBuiltInAuthRoleApi, [string]$KvApiVersion = $script:SIBuiltInAuthKvApi)
    $lines = New-Object System.Collections.Generic.List[string]
    $warn = New-Object System.Collections.Generic.List[string]
    $support = New-Object System.Collections.Generic.List[string]
    $removed = New-Object System.Collections.Generic.List[string]
    $keys = [ordered]@{}
    $st = @{ Images = 'not-checked' }
    $res = { [pscustomobject]@{ Lines = $lines.ToArray(); Warnings = $warn.ToArray(); Support = $support.ToArray(); Removed = $removed.ToArray(); Images = $st.Images; Keys = $keys } }
    $refused = { param($t) "$t" -match '(?i)\b(401|403)\b|Unauthorized|Forbidden|AuthorizationFailed|DENIED' }
    $repo = $script:SIBuiltInAuthFrontRepo
    $web = ($WebAppId.TrimEnd('/') -split '/')[-1]
    try {
        $app = & $Arm 'GET' ('{0}?api-version={1}' -f $WebAppId.TrimEnd('/'), $AppApiVersion) $null
        if (-not $app) { $lines.Add(('{0}: not found -- the earlier sign-in''s stored images and keys are left' -f $web)); return (& $res) }
        $auth = & $Arm 'GET' ('{0}/authConfigs/current?api-version={1}' -f $WebAppId.TrimEnd('/'), $AuthApiVersion) $null
        $revs = @(Get-SIBuiltInAuthProp (& $Arm 'GET' ('{0}/revisions?api-version={1}' -f $WebAppId.TrimEnd('/'), $AppApiVersion) $null) @('value'))
        $rgId = [string](($WebAppId -split '(?i)/providers/')[0])
        $apps = @(Get-SIBuiltInAuthProp (& $Arm 'GET' ('{0}/providers/Microsoft.App/containerApps?api-version={1}' -f $rgId.TrimEnd('/'), $AppApiVersion) $null) @('value'))
    } catch {
        $warn.Add(('{0}: the earlier sign-in''s stored images and keys were not checked -- the web app could not be read ({1}); nothing was deleted, the next update checks again' -f $web, $_.Exception.Message))
        return (& $res)
    }
    $gone = Test-SIBuiltInAuthFrontGone -App $app -Auth $auth -Revisions $revs -Apps $apps
    if (-not $gone.Ok) {
        $lines.Add(('{0}: the earlier sign-in''s stored images and keys are kept -- {1}' -f $web, $gone.Why))
        $st.Images = 'kept'; foreach ($k in $script:SIBuiltInAuthWebKeyNames) { $keys[$k] = 'kept' }
        return (& $res)
    }

    # ---- 1. the signin-front images ----
    if (-not $Registry) {
        $lines.Add(('the earlier sign-in''s images ({0}): not checked -- {1}' -f $repo, $(if ("$RegistryNote".Trim()) { $RegistryNote } else { 'the install''s registry is not known here' })))
    } else {
        $where = if ("$LoginServer".Trim()) { $LoginServer.Trim() } elseif ($Registry.ContainsKey('LoginServer')) { [string]$Registry.LoginServer } else { 'the install''s registry' }
        $step = 'the support partner gives the updater back its delete right on the install''s registry {0} (it is Contributor there), so the update removes the earlier sign-in''s images ({1}) itself' -f $where, $repo
        try {
            $ls = & $Registry.List $repo
            $mans = @(if ($ls -and $ls.Found) { @($ls.Manifests) | Where-Object { $_ } })
            if (-not $mans.Count) { $st.Images = 'none'; $lines.Add(('the earlier sign-in''s images ({0} in {1}): none left' -f $repo, $where)) }
            else {
                $tags = @($mans | ForEach-Object { @($_.Tags) } | Where-Object { $_ })
                $tagText = if ($tags.Count) { ' (tags {0})' -f ($tags -join ',') } else { '' }
                if ($Mode -eq 'plan') {
                    $st.Images = 'planned'
                    $lines.Add(('the earlier sign-in''s images ({0} in {1}): would delete {2} image(s){3} -- nothing was deleted' -f $repo, $where, $mans.Count, $tagText))
                } else {
                    $locked = 0; $failed = 0; $denied = $false; $why = ''
                    foreach ($m in $mans) {
                        if (-not $m.DeleteEnabled) { $locked++; continue }
                        $d = & $Registry.Delete $repo ([string]$m.Digest)
                        if ($d -and $d.Ok) { continue }
                        $failed++
                        $t = if ($d) { '{0} {1}' -f [int]$d.Status, [string]$d.Why } else { 'no answer' }
                        if (& $refused $t) { $denied = $true }
                        if (-not $why) { $why = if ($d -and "$($d.Why)".Trim()) { [string]$d.Why } else { $t } }
                    }
                    # the read-back: the registry completes a delete after it answers it -- read again a few times
                    $left = -1
                    for ($i = 1; $i -le $Tries; $i++) {
                        try { $a = & $Registry.List $repo; $left = @(if ($a -and $a.Found) { @($a.Manifests) | Where-Object { $_ } }).Count } catch { $left = -1 }
                        if ($left -eq 0 -or ($left -ge 0 -and $left -le ($locked + $failed))) { break }
                        if ($i -lt $Tries) { & $Sleep $PauseSeconds }
                    }
                    if ($denied) {
                        $st.Images = 'refused'
                        $warn.Add(('the earlier sign-in''s images ({0} in {1}): NOT removed -- the registry refused the delete ({2}); the update goes on' -f $repo, $where, $why))
                        $support.Add($step)
                    } elseif ($left -eq 0) {
                        $st.Images = 'removed'; $removed.Add(('{0} ({1} image(s))' -f $repo, $mans.Count))
                        $lines.Add(('the earlier sign-in''s images ({0} in {1}): removed -- {2} image(s){3}; read back, none left' -f $repo, $where, $mans.Count, $tagText))
                    } else {
                        $st.Images = if ($failed) { 'failed' } else { 'kept' }
                        $parts = @()
                        if ($locked) { $parts += ('{0} locked against deletion -- kept' -f $locked) }
                        if ($failed) { $parts += ('{0} could not be deleted ({1})' -f $failed, $why) }
                        if ($left -lt 0) { $parts += 'what is left could not be read back' } elseif ($left -gt ($locked + $failed)) { $parts += ('{0} still listed right after the deletes (the registry completes them shortly)' -f $left) }
                        $warn.Add(('the earlier sign-in''s images ({0} in {1}): not all removed -- {2}; the next update checks again' -f $repo, $where, ($parts -join '; ')))
                    }
                }
            }
        } catch {
            $m = $_.Exception.Message
            if (& $refused $m) { $st.Images = 'refused'; $warn.Add(('the earlier sign-in''s images ({0} in {1}): not checked -- the registry refused the updater ({2}); the update goes on' -f $repo, $where, $m)); $support.Add($step) }
            else { $st.Images = 'failed'; $warn.Add(('the earlier sign-in''s images ({0} in {1}): not checked -- {2}; nothing was deleted, the next update checks again' -f $repo, $where, $m)) }
        }
    }

    # ---- 2. the Key Vault keys ----
    $ring = Test-SIBuiltInAuthKeyRingOnBlob -App $app -Revisions $revs
    $id = Get-SIBuiltInAuthWebIdentity -App $app -Name 'id-si-web'
    $vault = "$VaultName".Trim().ToLowerInvariant()
    foreach ($k in $script:SIBuiltInAuthWebKeyNames) {
        $keys[$k] = 'kept'
        try {
            if (-not $ring.Ok) { $lines.Add(('the earlier sign-in''s key {0}: kept -- {1}' -f $k, $ring.Why)); continue }
            if (-not $KeyVault -or -not $vault) { $keys[$k] = 'not-checked'; $lines.Add(('the earlier sign-in''s key {0}: not checked -- the install''s Key Vault is not known here' -f $k)); continue }
            $uri = 'https://{0}.vault.azure.net/keys/{1}?api-version={2}' -f $vault, $k, $KvApiVersion
            $step = 'the support partner gives the updater back its Key Vault key right (Key Vault Crypto Officer on the vault {0}), so the update removes the key {1} itself' -f $vault, $k
            $g = & $KeyVault 'GET' $uri $null
            $gs = [int](0 + (Get-SIBuiltInAuthProp $g @('Status')))
            if ($gs -eq 404) { $keys[$k] = 'none'; $lines.Add(('the earlier sign-in''s key {0} in {1}: none left' -f $k, $vault)); continue }
            if ($gs -eq 401 -or $gs -eq 403) { $keys[$k] = 'refused'; $warn.Add(('the earlier sign-in''s key {0} in {1}: not checked -- the Key Vault refused the updater (HTTP {2}); the update goes on' -f $k, $vault, $gs)); $support.Add($step); continue }
            if ($gs -lt 200 -or $gs -ge 300) { $keys[$k] = 'failed'; $warn.Add(('the earlier sign-in''s key {0} in {1}: not checked -- the Key Vault answered HTTP {2}; nothing was deleted, the next update checks again' -f $k, $vault, $gs)); continue }
            # the web identity must hold no role on the key any more (the key-ring step removes it first)
            if (-not "$VaultId".Trim() -or -not $id) { $lines.Add(('the earlier sign-in''s key {0}: kept -- id-si-web''s rights on it could not be read here' -f $k)); continue }
            $scope = '{0}/keys/{1}' -f $VaultId.Trim().TrimEnd('/'), $k
            $held = $null
            try { $held = @(Select-SIBuiltInAuthWebKeyAssignments -Assignments @(Get-SIBuiltInAuthProp (& $Arm 'GET' ("{0}/providers/Microsoft.Authorization/roleAssignments?api-version={1}&`$filter=principalId eq '{2}'" -f $scope, $RoleApiVersion, $id.PrincipalId) $null) @('value')) -PrincipalId $id.PrincipalId -KeyScope $scope) }
            catch { $lines.Add(('the earlier sign-in''s key {0}: kept -- id-si-web''s rights on it could not be read ({1})' -f $k, $_.Exception.Message)); continue }
            if (@($held).Count) { $lines.Add(('the earlier sign-in''s key {0}: kept -- id-si-web still holds a role on it (the key-ring step takes that away first)' -f $k)); continue }
            if ($Mode -eq 'plan') { $keys[$k] = 'planned'; $lines.Add(('the earlier sign-in''s key {0} in {1}: would delete it (soft delete) -- nothing was deleted' -f $k, $vault)); continue }
            $d = & $KeyVault 'DELETE' $uri $null
            $ds = [int](0 + (Get-SIBuiltInAuthProp $d @('Status')))
            if ($ds -eq 401 -or $ds -eq 403) { $keys[$k] = 'refused'; $warn.Add(('the earlier sign-in''s key {0} in {1}: NOT removed -- the Key Vault refused the delete (HTTP {2}); the update goes on' -f $k, $vault, $ds)); $support.Add($step); continue }
            if (($ds -lt 200 -or $ds -ge 300) -and $ds -ne 404) { $keys[$k] = 'failed'; $warn.Add(('the earlier sign-in''s key {0} in {1}: NOT removed -- the Key Vault answered HTTP {2}; the next update tries again' -f $k, $vault, $ds)); continue }
            $ok = $false
            for ($i = 1; $i -le $Tries; $i++) {
                $rb = & $KeyVault 'GET' $uri $null
                if ([int](0 + (Get-SIBuiltInAuthProp $rb @('Status'))) -eq 404) { $ok = $true; break }
                if ($i -lt $Tries) { & $Sleep $PauseSeconds }
            }
            if ($ok) { $keys[$k] = 'removed'; $removed.Add($k); $lines.Add(('the earlier sign-in''s key {0} in {1}: removed (soft delete -- recoverable for the vault''s retention period; read back gone)' -f $k, $vault)) }
            else { $keys[$k] = 'failed'; $warn.Add(('the earlier sign-in''s key {0} in {1}: the delete was answered but the key still reads back -- the next update checks again' -f $k, $vault)) }
        } catch { $keys[$k] = 'failed'; $warn.Add(('the earlier sign-in''s key {0}: not checked ({1}) -- nothing was deleted, the next update checks again' -f $k, $_.Exception.Message)) }
    }
    & $res
}
