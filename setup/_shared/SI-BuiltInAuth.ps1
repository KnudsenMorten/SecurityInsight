#Requires -Version 5.1
<#
    MICROSOFT'S BUILT-IN SIGN-IN IN FRONT OF THE WEB APP (framework SECURE-WEB-1 points 5-7).
    Container Apps authentication, SECRETLESS: the web app's managed identity (id-si-web) is a federated credential on the
    sign-in app registration, and the platform signs in with that identity's token as its client assertion (Microsoft's
    Azure-Samples/containerapps-builtinauth-bicep pattern). No client secret exists anywhere.

    INERT BY DEFAULT: nothing here runs unless the updater job says SI_Updater_BuiltInAuth = plan | redirect | apply.
      plan          read everything, say what would change -- nothing is written
      redirect      the 'one release before the switch' step: the sign-in app registration gets the platform's callback
                    https://<address>/.auth/login/aad/callback (and one per custom host) -- existing redirect URIs are kept
      apply         the callback as above; the token store's blob container in the install's own storage account (created
                    when missing) and id-si-web's Storage Blob Data Contributor on that container only (missing = ONE try,
                    a refusal is a Support-app step and nothing switches on); then the container-app secret the platform
                    reads the identity from, the authConfig (PUT, read back), an anonymous request must be refused; then
                    THE SWITCH in one PATCH -- SI_Web_BuiltInAuth=1, the sign-in front container out, the ingress on the
                    web container's own port (read back) -- and again: refused, and /.auth/login/aad sends to Microsoft
                    Entra. A failed read-back or probe PUTS BACK the web app exactly as it was (ingress, the front
                    container) without the setting, then the sign-in that ran before, and says so.
                    AFTER a switch that read back (Invoke-SIBuiltInAuthKeyRingMove): the web app keeps its sign-in keys in
                    the token-store container (DataProtection__BlobUri, read back), and once it runs on that, id-si-web's
                    Key Vault key roles (signin-front-dp, SI-Web-KeyRing) are removed and read back -- a refusal is a
                    Support-app step.
    Nothing is written to Microsoft Entra except the redirect URIs of the sign-in app registration the updater owns. A
    missing federated credential, a missing data right and shared-key access left on are said as Support-app steps.

    Seams (the tests pass fakes):
      -Arm   { param([string]$Method, [string]$Path, $Body) }  -Path '/subscriptions/...?api-version=...'; parsed answer,
             $null for "not found" on a GET, THROWS on any other error.
      -Graph { param([string]$Method, [string]$Uri, $Body) }   full https://graph.microsoft.com/... URI; parsed answer.
      -Probe { param([string]$Url) }  -> @{ Status; Location }  (one request without a sign-in, no redirect followed)
      -Sleep { param([int]$Seconds) }
    No module, no az. PS 5.1 safe.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

# Microsoft.App/containerApps/authConfigs: the token store kept in blob storage WITH A MANAGED IDENTITY (azureBlobStorage.
# blobContainerUri + managedIdentityResourceId) is in the preview api-versions only (2024-10-02-preview on); the GA
# 2024-03-01 / 2025-01-01 / 2025-07-01 document only the SAS-URL form, which SecurityInsight never uses. A parameter.
$script:SIBuiltInAuthApi            = '2024-10-02-preview'
$script:SIBuiltInAuthStorageApi     = '2023-05-01'   # Microsoft.Storage (the account + its blob containers)
$script:SIBuiltInAuthRoleApi        = '2022-04-01'   # Microsoft.Authorization/roleAssignments
$script:SIBuiltInAuthTokenContainer = 'si-auth-tokens'
$script:SIBuiltInAuthBlobRoleId     = [string]'ba92f5b4-2d11-453d-a403-e96b0029c9fe'   # Storage Blob Data Contributor (a built-in role id, public)
$script:SIBuiltInAuthBlobRoleIds    = @('ba92f5b4-2d11-453d-a403-e96b0029c9fe', 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b')   # ... or Owner
$script:SIBuiltInAuthWebPort        = 8080   # the web container's own port (pro-management/Dockerfile: ASPNETCORE_HTTP_PORTS, EXPOSE)
$script:SIBuiltInAuthFrontName      = 'signin-front'
$script:SIBuiltInAuthAppApi         = '2025-07-01'   # Microsoft.App/containerApps (the updater's own api-version)
$script:SIBuiltInAuthSecretName     = 'override-use-mi-fic-assertion-client-id'
$script:SIBuiltInAuthSettingName    = 'SI_Web_BuiltInAuth'
$script:SIBuiltInAuthMagicPaths     = @('/MagicLink', '/MagicLinkRequest')
$script:SIBuiltInAuthFicAudience    = 'api://AzureADTokenExchange'
$script:SIBuiltInAuthCallbackPath   = '/.auth/login/aad/callback'

function Get-SIBuiltInAuthProp {
    <# PURE. A nested property of an ARM / Graph object (PSCustomObject or hashtable), $null when any step is missing. #>
    param($Object, [string[]]$Names)
    $o = $Object
    foreach ($n in $Names) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o = $o[$n] } else { return $null }; continue }
        $p = $o.PSObject.Properties[$n]
        if (-not $p) { return $null }
        $o = $p.Value
    }
    $o
}

function ConvertTo-SIBuiltInAuthHashtable {
    <# PURE. A deep copy of an ARM object as ordered hashtables / arrays (so a body can be changed without touching the read). #>
    param($Object)
    if ($null -eq $Object) { return $null }
    if ($Object -is [string] -or $Object -is [ValueType]) { return $Object }
    if ($Object -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in @($Object.Keys)) { $h[[string]$k] = ConvertTo-SIBuiltInAuthHashtable $Object[$k] }
        return $h
    }
    if ($Object -is [System.Collections.IEnumerable]) {
        $l = New-Object System.Collections.Generic.List[object]
        foreach ($i in $Object) { $l.Add((ConvertTo-SIBuiltInAuthHashtable $i)) }
        return , $l.ToArray()
    }
    $h = [ordered]@{}
    foreach ($p in $Object.PSObject.Properties) { $h[[string]$p.Name] = ConvertTo-SIBuiltInAuthHashtable $p.Value }
    $h
}

function Get-SIBuiltInAuthMode {
    <# PURE. The updater job's SI_Updater_BuiltInAuth as a converge mode: off (unset, empty, anything unknown -- the DEFAULT) |
       plan | redirect-only ('redirect') | apply. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $v = "$Value".Trim().ToLowerInvariant()
    switch ($v) {
        'plan'          { return 'plan' }
        'redirect'      { return 'redirect-only' }
        'redirect-only' { return 'redirect-only' }
        'apply'         { return 'apply' }
        default         { return 'off' }
    }
}

# ============================================================================================================== 1. THE AUTHCONFIG

function Get-SIBuiltInAuthConfigBody {
    <#
        PURE. The ARM body for PUT <app id>/authConfigs/current of the web app: Microsoft Entra sign-in in front of every
        page (an anonymous request is sent to the sign-in), the identity's federated credential as the client assertion
        (registration.clientSecretSettingName names the container-app secret that holds the managed identity's CLIENT ID),
        a FIXED 8-hour session, HTTPS only, and the token store in the install's own blob container reached with the web
        app's MANAGED IDENTITY (-TokenStoreContainerUri + -TokenStoreIdentityResourceId; never a SAS URL or a connection
        string). Without both the token store is off; -TokenStore $true without them throws.
        -MagicLinksOn: /MagicLink and /MagicLinkRequest open without a sign-in (excludedPaths); off = no excluded path.
        -Enabled:$false = the same body with the platform switched off (the way back).
    #>
    param([Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
          [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$ClientId,
          [switch]$MagicLinksOn,
          [string[]]$ExcludedPaths = $script:SIBuiltInAuthMagicPaths,
          [string]$SecretSettingName = $script:SIBuiltInAuthSecretName,
          [string]$OpenIdIssuer = '',
          [string[]]$AllowedAudiences = @(),
          [string]$UnauthenticatedClientAction = 'RedirectToLoginPage',
          [string]$RedirectToProvider = 'azureactivedirectory',
          [string]$CookieConvention = 'FixedTime',
          [string]$CookieTimeToExpiration = '08:00:00',
          [AllowNull()]$TokenStore = $null,
          [string]$TokenStoreContainerUri = '',
          [string]$TokenStoreIdentityResourceId = '',
          [bool]$RequireHttps = $true,
          [bool]$Enabled = $true,
          # proven at internal 2026-11-14 (EPS): the sign-in asks for the app's own API scope too, so the token store holds an
          # access token for SecurityInsight's API (signed requests); empty = the platform's default scopes
          [AllowNull()][string[]]$LoginParameters = $null)
    $cid = $ClientId.Trim().ToLowerInvariant()
    # prompt=select_account (owner 2026-11-14): Entra ALWAYS shows the account picker -- an admin whose browser is signed in
    # with the office account picks the admin account instead of landing as the wrong user
    $lp = if ($null -eq $LoginParameters) { @(('scope=openid profile email offline_access api://{0}/user_impersonation' -f $cid), 'prompt=select_account') } else { @($LoginParameters | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() }) }
    # the owner's rule is "always the picker": prompt=select_account is ALWAYS there, also next to a caller's own parameters
    $lp = @(@($lp | Where-Object { $_ -notmatch '^(?i)prompt=' }) + 'prompt=select_account')
    $tsUri = "$TokenStoreContainerUri".Trim(); $tsId = "$TokenStoreIdentityResourceId".Trim()
    $tsOn = if ($null -eq $TokenStore) { [bool]($tsUri -and $tsId) } else { [bool]$TokenStore }
    if ($tsOn -and -not ($tsUri -and $tsId)) { throw 'the token store needs its blob container and the managed identity that reaches it -- never a SAS URL' }
    $ts = [ordered]@{ enabled = $tsOn }
    if ($tsOn) { $ts['azureBlobStorage'] = [ordered]@{ blobContainerUri = $tsUri; managedIdentityResourceId = $tsId } }
    $iss = if ("$OpenIdIssuer".Trim()) { "$OpenIdIssuer".Trim() } else { 'https://login.microsoftonline.com/{0}/v2.0' -f $TenantId.Trim().ToLowerInvariant() }
    $aud = if (@($AllowedAudiences | Where-Object { "$_".Trim() }).Count) { @($AllowedAudiences | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() }) } else { @(('api://{0}' -f $cid), $cid) }
    $gv = [ordered]@{ unauthenticatedClientAction = $UnauthenticatedClientAction; redirectToProvider = $RedirectToProvider }
    if ($MagicLinksOn) { $gv['excludedPaths'] = @($ExcludedPaths | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() }) }
    [ordered]@{
        properties = [ordered]@{
            platform          = [ordered]@{ enabled = $Enabled }
            globalValidation  = $gv
            identityProviders = [ordered]@{
                azureActiveDirectory = [ordered]@{
                    enabled      = $true
                    registration = [ordered]@{ clientId = $cid; clientSecretSettingName = $SecretSettingName; openIdIssuer = $iss }
                    validation   = [ordered]@{ allowedAudiences = @($aud) }
                    login        = [ordered]@{ loginParameters = @($lp) }
                }
            }
            login             = [ordered]@{
                cookieExpiration = [ordered]@{ convention = $CookieConvention; timeToExpiration = $CookieTimeToExpiration }
                tokenStore       = $ts
            }
            httpSettings      = [ordered]@{ requireHttps = $RequireHttps }
        }
    }
}

function Test-SIBuiltInAuthConfigMatches {
    <# PURE. Does the authConfig as read (-Current) carry everything of -Want (Get-SIBuiltInAuthConfigBody)? @{ Ok; Diff (the
       field names that differ) }. Text compares ignore case; lists compare as sets. #>
    param($Current, [Parameter(Mandatory)]$Want)
    $diff = New-Object System.Collections.Generic.List[string]
    $one = { param([string[]]$Path, [string]$Name)
        $w = Get-SIBuiltInAuthProp $Want $Path; $c = Get-SIBuiltInAuthProp $Current $Path
        if ("$w".Trim().ToLowerInvariant() -ne "$c".Trim().ToLowerInvariant()) { $diff.Add($Name) } }
    $set = { param([string[]]$Path, [string]$Name)
        $w = @(@(Get-SIBuiltInAuthProp $Want $Path) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Sort-Object -Unique)
        $c = @(@(Get-SIBuiltInAuthProp $Current $Path) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Sort-Object -Unique)
        if (($w -join '|') -ne ($c -join '|')) { $diff.Add($Name) } }
    & $one @('properties', 'platform', 'enabled') 'platform.enabled'
    & $one @('properties', 'globalValidation', 'unauthenticatedClientAction') 'globalValidation.unauthenticatedClientAction'
    & $one @('properties', 'globalValidation', 'redirectToProvider') 'globalValidation.redirectToProvider'
    & $set @('properties', 'globalValidation', 'excludedPaths') 'globalValidation.excludedPaths'
    & $one @('properties', 'identityProviders', 'azureActiveDirectory', 'enabled') 'azureActiveDirectory.enabled'
    & $one @('properties', 'identityProviders', 'azureActiveDirectory', 'registration', 'clientId') 'registration.clientId'
    & $one @('properties', 'identityProviders', 'azureActiveDirectory', 'registration', 'clientSecretSettingName') 'registration.clientSecretSettingName'
    & $one @('properties', 'identityProviders', 'azureActiveDirectory', 'registration', 'openIdIssuer') 'registration.openIdIssuer'
    & $set @('properties', 'identityProviders', 'azureActiveDirectory', 'validation', 'allowedAudiences') 'validation.allowedAudiences'
    & $set @('properties', 'identityProviders', 'azureActiveDirectory', 'login', 'loginParameters') 'azureActiveDirectory.login.loginParameters'
    & $one @('properties', 'login', 'cookieExpiration', 'convention') 'login.cookieExpiration.convention'
    & $one @('properties', 'login', 'cookieExpiration', 'timeToExpiration') 'login.cookieExpiration.timeToExpiration'
    & $one @('properties', 'login', 'tokenStore', 'enabled') 'login.tokenStore.enabled'
    & $one @('properties', 'login', 'tokenStore', 'azureBlobStorage', 'blobContainerUri') 'login.tokenStore.azureBlobStorage.blobContainerUri'
    & $one @('properties', 'login', 'tokenStore', 'azureBlobStorage', 'managedIdentityResourceId') 'login.tokenStore.azureBlobStorage.managedIdentityResourceId'
    & $one @('properties', 'httpSettings', 'requireHttps') 'httpSettings.requireHttps'
    [pscustomobject]@{ Ok = ($diff.Count -eq 0); Diff = $diff.ToArray() }
}

function Get-SIBuiltInAuthRestoreBody {
    <# PURE. The body that puts back the sign-in that ran before: the authConfig as read when it existed and was ON (its
       properties, nothing read-only), else -Want with the platform switched OFF. #>
    param($Before, [Parameter(Mandatory)]$Want)
    $wasOn = "$(Get-SIBuiltInAuthProp $Before @('properties', 'platform', 'enabled'))" -match '^(?i)true$'
    if ($Before -and $wasOn) { return [ordered]@{ properties = (ConvertTo-SIBuiltInAuthHashtable (Get-SIBuiltInAuthProp $Before @('properties'))) } }
    $b = ConvertTo-SIBuiltInAuthHashtable $Want
    $b.properties.platform.enabled = $false
    $b
}

# ============================================================================================================== 2. THE SECRET + THE SETTING

function Get-SIBuiltInAuthWebContainerIndex {
    <# PURE. The web container of the app's template: the first one that is not the sign-in front. -1 = none. #>
    param($App, [string]$FrontName = 'signin-front')
    $cs = @(Get-SIBuiltInAuthProp $App @('properties', 'template', 'containers'))
    for ($i = 0; $i -lt $cs.Count; $i++) { if ($cs[$i] -and [string](Get-SIBuiltInAuthProp $cs[$i] @('name')) -ne $FrontName) { return $i } }
    -1
}

function Get-SIBuiltInAuthSetting {
    <# PURE. The web container's value of -Name ('' = not set). #>
    param($App, [string]$Name = $script:SIBuiltInAuthSettingName)
    $i = Get-SIBuiltInAuthWebContainerIndex -App $App
    if ($i -lt 0) { return '' }
    $c = @(Get-SIBuiltInAuthProp $App @('properties', 'template', 'containers'))[$i]
    foreach ($e in @(Get-SIBuiltInAuthProp $c @('env'))) { if ($e -and [string](Get-SIBuiltInAuthProp $e @('name')) -eq $Name) { return "$(Get-SIBuiltInAuthProp $e @('value'))".Trim() } }
    ''
}

function Get-SIBuiltInAuthSecretPatch {
    <#
        PURE. The ARM PATCH body of the web app that holds the container-app secret 'override-use-mi-fic-assertion-client-id'
        (always lowercase) whose VALUE is the managed identity's CLIENT ID (not a secret: it tells the platform which managed
        identity's token is the client assertion) and -- with -Setting on / off -- the web container's SI_Web_BuiltInAuth
        (on = '1', off = removed; keep = the template is not in the body at all).
        Container Apps REPLACES the whole secret list on a write, so EVERY existing secret goes back: from -SecretValues
        (POST .../listSecrets: name -> @{ value | keyVaultUrl + identity }), else from the app as read. A secret whose value
        is not known (no value, no Key Vault reference) is NOT written: it is in MissingSecrets, and the caller stops.
        THE SWITCH (-Setting on -RemoveFront -WebPort 8080): in the same PATCH the sign-in front container is taken OUT of
        the template (its own settings go with it; the web container's are left alone except SI_Web_BuiltInAuth) and the
        ingress targets the web container's own port -- the rest of the ingress (external, transport, IP restrictions,
        custom domains, sticky sessions, ...) goes back exactly as read. The rest of the template stays as read.
        Returns @{ Body; Changed (the secret, the setting, the front or the port differs); MissingSecrets }.
    #>
    param([Parameter(Mandatory)]$App, [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$IdentityClientId,
          [hashtable]$SecretValues = @{}, [ValidateSet('keep', 'on', 'off')][string]$Setting = 'on',
          [switch]$RemoveFront, [int]$WebPort = 0, [string]$FrontName = $script:SIBuiltInAuthFrontName,
          [string]$SecretName = $script:SIBuiltInAuthSecretName, [string]$SettingName = $script:SIBuiltInAuthSettingName,
          # other settings of the web container to set (name -> value) in the same PATCH; the template is then in the body
          # even with -Setting keep, and the rest of it stays as read
          [hashtable]$WebEnv = @{})
    $name = $SecretName.ToLowerInvariant()
    $want = $IdentityClientId.Trim().ToLowerInvariant()
    $cfg = ConvertTo-SIBuiltInAuthHashtable (Get-SIBuiltInAuthProp $App @('properties', 'configuration'))
    if (-not $cfg) { $cfg = [ordered]@{} }
    $list = New-Object System.Collections.Generic.List[object]
    $missing = New-Object System.Collections.Generic.List[string]
    $changed = $false; $seen = $false
    foreach ($s in @(Get-SIBuiltInAuthProp $App @('properties', 'configuration', 'secrets'))) {
        if (-not $s) { continue }
        $sn = [string](Get-SIBuiltInAuthProp $s @('name')); if (-not $sn) { continue }
        if ($sn -ieq $name) {
            $seen = $true
            $have = $SecretValues[$sn]; $hv = "$(Get-SIBuiltInAuthProp $have @('value'))".Trim().ToLowerInvariant()
            if ($hv -ne $want) { $changed = $true }
            continue
        }
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
    if (-not $seen) { $changed = $true }
    $list.Add([ordered]@{ name = $name; value = $want })
    $cfg['secrets'] = $list.ToArray()
    $props = [ordered]@{ configuration = $cfg }
    if ($Setting -ne 'keep' -or $WebEnv.Count) {
        $tpl = ConvertTo-SIBuiltInAuthHashtable (Get-SIBuiltInAuthProp $App @('properties', 'template'))
        if ($tpl -and $tpl.Contains('revisionSuffix')) { $tpl.Remove('revisionSuffix') }
        $i = Get-SIBuiltInAuthWebContainerIndex -App $App
        if ($tpl -and $i -ge 0) {
            $c = $tpl.containers[$i]
            $envs = @(@($c['env']) | Where-Object { $null -ne $_ })
            if ($Setting -ne 'keep') {
                $now = Get-SIBuiltInAuthSetting -App $App -Name $SettingName
                $envs = @($envs | Where-Object { [string]$_['name'] -ne $SettingName })
                if ($Setting -eq 'on') { $envs += [ordered]@{ name = $SettingName; value = '1' }; if ($now -ne '1') { $changed = $true } }
                elseif ($now) { $changed = $true }
            }
            foreach ($n in @($WebEnv.Keys | ForEach-Object { [string]$_ } | Sort-Object)) {
                $v = [string]$WebEnv[$n]
                if ((Get-SIBuiltInAuthSetting -App $App -Name $n) -cne $v.Trim()) { $changed = $true }
                $envs = @($envs | Where-Object { [string]$_['name'] -ne $n }) + @([ordered]@{ name = $n; value = $v })
            }
            $c['env'] = @($envs)
            if ($RemoveFront) {
                $keep = @(@($tpl.containers) | Where-Object { $null -ne $_ -and [string]$_['name'] -ne $FrontName })
                if ($keep.Count -ne @($tpl.containers).Count) { $changed = $true }
                $tpl['containers'] = @($keep)
            }
            $props['template'] = $tpl
        }
    }
    if ($WebPort -gt 0) {
        if (-not $cfg.Contains('ingress') -or $null -eq $cfg['ingress']) { $cfg['ingress'] = [ordered]@{} }
        if ([int](0 + $cfg['ingress']['targetPort']) -ne $WebPort) { $changed = $true }
        $cfg['ingress']['targetPort'] = $WebPort
    }
    [pscustomobject]@{ Body = [ordered]@{ properties = $props }; Changed = $changed; MissingSecrets = $missing.ToArray() }
}

function Get-SIBuiltInAuthFrontContainer {
    <# PURE. The sign-in front container of the app's template as read, or $null. #>
    param($App, [string]$FrontName = $script:SIBuiltInAuthFrontName)
    @(@(Get-SIBuiltInAuthProp $App @('properties', 'template', 'containers')) | Where-Object { $_ -and [string](Get-SIBuiltInAuthProp $_ @('name')) -eq $FrontName }) | Select-Object -First 1
}

function ConvertTo-SIBuiltInAuthCanonicalJson {
    <# PURE. Compact JSON with every object's keys sorted -- two reads of the same thing compare equal whatever order ARM
       answers in. #>
    param($Object)
    $sort = $null
    $sort = { param($o)
        if ($null -eq $o -or $o -is [string] -or $o -is [ValueType]) { return $o }
        if ($o -is [System.Collections.IDictionary]) { $h = [ordered]@{}; foreach ($k in @($o.Keys | ForEach-Object { [string]$_ } | Sort-Object)) { $h[$k] = & $sort $o[$k] }; return $h }
        if ($o -is [System.Collections.IEnumerable]) { $l = New-Object System.Collections.Generic.List[object]; foreach ($i in $o) { $l.Add((& $sort $i)) }; return , $l.ToArray() }
        $h = [ordered]@{}; foreach ($n in @($o.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)) { $h[$n] = & $sort $o.$n }; $h }
    ConvertTo-Json -InputObject (& $sort $Object) -Depth 60 -Compress
}

function Get-SIBuiltInAuthAppRestorePatch {
    <#
        PURE. The PATCH that puts the web app back as it was before the switch (-Before = the app as read then): its ingress
        exactly as read (the old target port), its template exactly as read (the sign-in front container as it was), with
        -DropSetting SI_Web_BuiltInAuth taken off every container. The secrets come from -Current + -SecretValues (a
        container-app read never carries their values), every one kept. Returns @{ Body; MissingSecrets }.
    #>
    param([Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$Current, [Parameter(Mandatory)][string]$IdentityClientId,
          [hashtable]$SecretValues = @{}, [switch]$DropSetting, [string]$SettingName = $script:SIBuiltInAuthSettingName)
    $sp = Get-SIBuiltInAuthSecretPatch -App $Current -IdentityClientId $IdentityClientId -SecretValues $SecretValues -Setting keep
    $cfg = $sp.Body.properties.configuration
    $ing = ConvertTo-SIBuiltInAuthHashtable (Get-SIBuiltInAuthProp $Before @('properties', 'configuration', 'ingress'))
    if ($ing) { $cfg['ingress'] = $ing }
    $tpl = ConvertTo-SIBuiltInAuthHashtable (Get-SIBuiltInAuthProp $Before @('properties', 'template'))
    if ($tpl -and $tpl.Contains('revisionSuffix')) { $tpl.Remove('revisionSuffix') }
    if ($tpl -and $DropSetting) {
        foreach ($c in @($tpl.containers)) { if ($c -and $c.Contains('env')) { $c['env'] = @(@($c['env']) | Where-Object { $null -ne $_ -and [string]$_['name'] -ne $SettingName }) } }
    }
    $props = [ordered]@{ configuration = $cfg }
    if ($tpl) { $props['template'] = $tpl }
    [pscustomobject]@{ Body = [ordered]@{ properties = $props }; MissingSecrets = $sp.MissingSecrets }
}

function Test-SIBuiltInAuthSwitched {
    <# PURE. Does the app as read run the switch: SI_Web_BuiltInAuth=1, no sign-in front container, the ingress on -WebPort?
       @{ Ok; Why }. #>
    param($App, [int]$WebPort = $script:SIBuiltInAuthWebPort, [string]$FrontName = $script:SIBuiltInAuthFrontName)
    if ((Get-SIBuiltInAuthSetting -App $App) -ne '1') { return [pscustomobject]@{ Ok = $false; Why = ('{0} is not 1' -f $script:SIBuiltInAuthSettingName) } }
    if (Get-SIBuiltInAuthFrontContainer -App $App -FrontName $FrontName) { return [pscustomobject]@{ Ok = $false; Why = 'the sign-in front container is still there' } }
    $p = [int](0 + (Get-SIBuiltInAuthProp $App @('properties', 'configuration', 'ingress', 'targetPort')))
    if ($p -ne $WebPort) { return [pscustomobject]@{ Ok = $false; Why = ('the ingress targets port {0}, not {1}' -f $p, $WebPort) } }
    [pscustomobject]@{ Ok = $true; Why = '' }
}

function ConvertTo-SIBuiltInAuthSecretValues {
    <# PURE. POST .../listSecrets' answer ({ value: [ { name; value | keyVaultUrl + identity } ] }) as name -> secret. #>
    param($ListAnswer)
    $h = @{}
    $items = Get-SIBuiltInAuthProp $ListAnswer @('value')
    if ($null -eq $items -and $ListAnswer -is [System.Collections.IEnumerable] -and -not ($ListAnswer -is [string])) { $items = $ListAnswer }
    foreach ($s in @($items)) { if ($s -and [string](Get-SIBuiltInAuthProp $s @('name'))) { $h[[string](Get-SIBuiltInAuthProp $s @('name'))] = $s } }
    $h
}

function Get-SIBuiltInAuthWebIdentity {
    <# PURE. The web app's managed identity the platform signs in with: id-si-web (by name), else the one the web container
       names as its sign-in credential (AzureAd__ClientCredentials__0__ManagedIdentityClientId), else the only one.
       @{ ClientId; PrincipalId; Name } or $null. #>
    param($App, [string]$Name = 'id-si-web')
    $ua = Get-SIBuiltInAuthProp $App @('identity', 'userAssignedIdentities')
    if ($null -eq $ua) { return $null }
    $list = New-Object System.Collections.Generic.List[object]
    $keys = if ($ua -is [System.Collections.IDictionary]) { @($ua.Keys) } else { @($ua.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($k in $keys) {
        $v = if ($ua -is [System.Collections.IDictionary]) { $ua[$k] } else { $ua.$k }
        $cid = [string](Get-SIBuiltInAuthProp $v @('clientId')); $pid0 = [string](Get-SIBuiltInAuthProp $v @('principalId'))
        if ($cid -notmatch '^[0-9a-fA-F-]{36}$' -or $pid0 -notmatch '^[0-9a-fA-F-]{36}$') { continue }
        $list.Add([pscustomobject]@{ ClientId = $cid.ToLowerInvariant(); PrincipalId = $pid0.ToLowerInvariant(); Name = ([string]$k -split '/')[-1]; ResourceId = [string]$k })
    }
    if (-not $list.Count) { return $null }
    $byName = @($list | Where-Object { $_.Name -ieq $Name }) | Select-Object -First 1
    if ($byName) { return $byName }
    $named = (Get-SIBuiltInAuthSetting -App $App -Name 'AzureAd__ClientCredentials__0__ManagedIdentityClientId').ToLowerInvariant()
    if ($named) { $m = @($list | Where-Object { $_.ClientId -eq $named }) | Select-Object -First 1; if ($m) { return $m } }
    if ($list.Count -eq 1) { return $list[0] }
    $null
}

# ============================================================================================================== 3. REDIRECT URIS + 4. THE FIC

function Get-SIBuiltInAuthRedirectUris {
    <# PURE. The sign-in app registration's web.redirectUris with the platform's callback added for the app's address and for
       every custom host: https://<host>/.auth/login/aad/callback. Existing ones are NEVER removed; de-duplicated (ignoring
       case, the first spelling kept). @{ Uris; Added }. #>
    param([AllowEmptyCollection()][string[]]$Existing = @(), [Parameter(Mandatory)][string]$Fqdn, [string[]]$CustomDomains = @())
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($u in @($Existing)) { $x = "$u".Trim(); if ($x -and -not @($out | Where-Object { $_ -ieq $x }).Count) { $out.Add($x) } }
    $added = New-Object System.Collections.Generic.List[string]
    foreach ($h in @(@($Fqdn) + @($CustomDomains))) {
        $hn = "$h".Trim() -replace '^(?i)https?://', '' -replace '/.*$', ''
        if (-not $hn) { continue }
        $cb = 'https://{0}{1}' -f $hn.ToLowerInvariant(), $script:SIBuiltInAuthCallbackPath
        if (-not @($out | Where-Object { $_ -ieq $cb }).Count) { $out.Add($cb); $added.Add($cb) }
    }
    [pscustomobject]@{ Uris = $out.ToArray(); Added = $added.ToArray() }
}

function Test-SIBuiltInAuthIdTokenIssuance {
    <# PURE. The sign-in app registration's web (as Graph reads it) issues ID tokens and NOT access tokens
       (implicitGrantSettings enableIdTokenIssuance true, enableAccessTokenIssuance false). #>
    param($Web)
    $ig = Get-SIBuiltInAuthProp $Web @('implicitGrantSettings')
    ("$(Get-SIBuiltInAuthProp $ig @('enableIdTokenIssuance'))" -match '^(?i)true$') -and -not ("$(Get-SIBuiltInAuthProp $ig @('enableAccessTokenIssuance'))" -match '^(?i)true$')
}

function Get-SIBuiltInAuthAppWebPatch {
    <# PURE. The Graph PATCH body of the sign-in app registration: web with -RedirectUris, the sign-out address and home
       page kept as read, and implicitGrantSettings SET (never just carried) to ID tokens ON, access tokens OFF --
       Microsoft's built-in sign-in starts with response_type "code id_token". #>
    param($Web, [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$RedirectUris)
    $w = [ordered]@{ redirectUris = @($RedirectUris) }
    foreach ($keep in 'logoutUrl', 'homePageUrl') { $v = Get-SIBuiltInAuthProp $Web @($keep); if ($null -ne $v -and "$v".Trim()) { $w[$keep] = [string]$v } }
    $w['implicitGrantSettings'] = [ordered]@{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false }
    [ordered]@{ web = $w }
}

function Test-SIBuiltInAuthFic {
    <# PURE. Does Graph's federatedIdentityCredentials list of the sign-in app registration trust exactly this identity:
       issuer https://login.microsoftonline.com/<tenant>/v2.0, subject = the identity's PRINCIPAL id, audience
       api://AzureADTokenExchange? (The name si-web-<principal id> is how setup writes it; the three values decide.) #>
    param([AllowEmptyCollection()][object[]]$Credentials = @(), [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$PrincipalId)
    $iss = ('https://login.microsoftonline.com/{0}/v2.0' -f $TenantId.Trim()).ToLowerInvariant()
    $sub = $PrincipalId.Trim().ToLowerInvariant()
    foreach ($c in @($Credentials | Where-Object { $_ })) {
        $ci = "$(Get-SIBuiltInAuthProp $c @('issuer'))".Trim().TrimEnd('/').ToLowerInvariant()
        $cs = "$(Get-SIBuiltInAuthProp $c @('subject'))".Trim().ToLowerInvariant()
        $ca = @(@(Get-SIBuiltInAuthProp $c @('audiences')) | ForEach-Object { "$_".Trim() })
        if ($ci -eq $iss -and $cs -eq $sub -and ($ca -contains $script:SIBuiltInAuthFicAudience)) { return $true }
    }
    $false
}

function Test-SIBuiltInAuthAnonymousRefused {
    <# PURE. An anonymous request is refused by the built-in sign-in: 401 / 403, or a redirect to Microsoft Entra
       (login.microsoftonline.com) or to the platform's own sign-in (/.auth/login/...). Anything else -- a 200 with the page,
       no answer -- is NOT refused. #>
    param([Parameter(Mandatory)]$Probe)
    $s = [int](Get-SIBuiltInAuthProp $Probe @('Status'))
    if ($s -in 401, 403) { return $true }
    if ($s -in 301, 302, 303, 307, 308) {
        $l = "$(Get-SIBuiltInAuthProp $Probe @('Location'))".Trim()
        if ($l -match '^https://login\.microsoftonline\.com/') { return $true }
        if ($l -match '^(?i)(https://[^/]+)?/\.auth/login/') { return $true }
    }
    $false
}

function Test-SIBuiltInAuthLoginAnswers {
    <# PURE. The platform's own sign-in (/.auth/login/aad) answers: a redirect to Microsoft Entra (login.microsoftonline.com). #>
    param([Parameter(Mandatory)]$Probe)
    $s = [int](Get-SIBuiltInAuthProp $Probe @('Status'))
    ($s -in 301, 302, 303, 307, 308) -and ("$(Get-SIBuiltInAuthProp $Probe @('Location'))".Trim() -match '^https://login\.microsoftonline\.com/')
}

# ============================================================================================================== 4b. THE TOKEN STORE

function Select-SIBuiltInAuthStorageAccount {
    <# PURE. The install's own storage account among the resource group's (-Accounts as ARM lists them): the one -Name names
       (the web app's SI_StorageAccount), else the only one, else the only SecurityInsight one (stsi...). $null = not told. #>
    param([object[]]$Accounts = @(), [string]$Name = '')
    $all = @($Accounts | Where-Object { $_ -and [string](Get-SIBuiltInAuthProp $_ @('id')) })
    if ("$Name".Trim()) { return (@($all | Where-Object { [string](Get-SIBuiltInAuthProp $_ @('name')) -ieq "$Name".Trim() }) | Select-Object -First 1) }
    if ($all.Count -eq 1) { return $all[0] }
    $si = @($all | Where-Object { [string](Get-SIBuiltInAuthProp $_ @('name')) -match '^(?i)stsi' })
    if ($si.Count -eq 1) { return $si[0] }
    $null
}

function Test-SIBuiltInAuthBlobRole {
    <# PURE. Does -Assignments (roleAssignments as ARM lists them) give -PrincipalId Storage Blob Data Contributor (or Owner) at
       the container scope -ContainerScope or above it? #>
    param([object[]]$Assignments = @(), [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$ContainerScope)
    $cs = $ContainerScope.TrimEnd('/').ToLowerInvariant()
    foreach ($a in @($Assignments | Where-Object { $_ })) {
        $p = Get-SIBuiltInAuthProp $a @('properties')
        if ("$(Get-SIBuiltInAuthProp $p @('principalId'))".Trim() -ine $PrincipalId.Trim()) { continue }
        $rid = ("$(Get-SIBuiltInAuthProp $p @('roleDefinitionId'))" -split '/')[-1].ToLowerInvariant()
        if ($script:SIBuiltInAuthBlobRoleIds -notcontains $rid) { continue }
        $sc = "$(Get-SIBuiltInAuthProp $p @('scope'))".TrimEnd('/').ToLowerInvariant()
        if ($sc -and ($cs -eq $sc -or $cs.StartsWith($sc + '/'))) { return $true }
    }
    $false
}

function Invoke-SIBuiltInAuthTokenStoreReady {
    <#
        The token store's blob container in the install's OWN storage account and the web identity's data right on it.
          * the account: read; shared-key access must be OFF -- when it is on that is SAID (a Support-app step, the install's
            rule already), never changed here;
          * the container (-Container, default si-auth-tokens, no public access): -Apply or -CreateContainer creates it when
            missing (ARM PUT, read back); plan says it would. #1262: the apply converge always passes -CreateContainer, also
            when it may not try the right itself (no federated credential yet), so the container EXISTS before the Support-app
            step for its data right is reported -- a role cannot be granted on a container that is not there (live). A
            refused create is a Support-app step of its own, never a throw;
          * Storage Blob Data Contributor for -PrincipalId at THAT container (or above): read; missing + -Apply = ONE try to
            add it at the container scope (the updater may not hold that right -- a refusal is the Support-app step, never a
            failure). Missing = the built-in sign-in does NOT switch on.
        Returns @{ Ok (the container and the right are there); ContainerUri; ContainerScope; Lines; Support (the Support-app
        steps) }. Throws only on an unexpected read failure (the converge catches it).
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$StorageAccountId, [Parameter(Mandatory)][string]$PrincipalId,
          [string]$Container = $script:SIBuiltInAuthTokenContainer, [switch]$Apply, [switch]$CreateContainer, [string]$IdentityName = 'id-si-web',
          [scriptblock]$NewGuid = { [guid]::NewGuid().ToString() }, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          [int]$Tries = 6, [int]$PauseSeconds = 10,
          [string]$StorageApiVersion = $script:SIBuiltInAuthStorageApi, [string]$RoleApiVersion = $script:SIBuiltInAuthRoleApi)
    $lines = New-Object System.Collections.Generic.List[string]
    $support = New-Object System.Collections.Generic.List[string]
    $acctId = $StorageAccountId.TrimEnd('/')
    $acctName = ($acctId -split '/')[-1]
    $cScope = '{0}/blobServices/default/containers/{1}' -f $acctId, $Container
    $out = { param([bool]$Ok, [string]$Uri) [pscustomobject]@{ Ok = $Ok; ContainerUri = $Uri; ContainerScope = $cScope; Lines = $lines.ToArray(); Support = $support.ToArray() } }
    $acct = & $Arm 'GET' ('{0}?api-version={1}' -f $acctId, $StorageApiVersion) $null
    if (-not $acct) { $lines.Add(('the storage account {0} for the sign-in tokens was not found' -f $acctName)); return (& $out $false '') }
    $blob = "$(Get-SIBuiltInAuthProp $acct @('properties', 'primaryEndpoints', 'blob'))".Trim()
    # the account's own blob endpoint as Azure names it (right in every cloud); never a guessed address
    if (-not $blob) { $lines.Add(('the storage account {0} names no blob endpoint -- the sign-in token store is not set up' -f $acctName)); return (& $out $false '') }
    $uri = '{0}/{1}' -f $blob.TrimEnd('/'), $Container
    $sk = Get-SIBuiltInAuthProp $acct @('properties', 'allowSharedKeyAccess')
    if (-not ("$sk" -match '^(?i)false$')) { $support.Add(('switch shared-key access OFF on the storage account {0} (it is {1}) -- setup\Set-SIStorageSharedKey.ps1 -Disable through the Support app; it is not changed here' -f $acctName, $(if ($null -eq $sk) { 'not set, so allowed' } else { 'on' }))) }
    # the container
    $cPath = '{0}?api-version={1}' -f $cScope, $StorageApiVersion
    $c = & $Arm 'GET' $cPath $null
    if (-not $c) {
        if (-not $Apply -and -not $CreateContainer) { $lines.Add(('would create the blob container {0} in {1} (no public access)' -f $Container, $acctName)); $support.Add(('give {0} Storage Blob Data Contributor on the blob container {1} in {2}' -f $IdentityName, $Container, $acctName)); return (& $out $false $uri) }
        # (#1262) the container first -- the data right's Support-app step below is only reported once it exists
        try { $null = & $Arm 'PUT' $cPath ([ordered]@{ properties = [ordered]@{ publicAccess = 'None' } }) }
        catch {
            $lines.Add(('the blob container {0} for the sign-in tokens could not be created in {1} ({2})' -f $Container, $acctName, $_.Exception.Message))
            $support.Add(('create the blob container {0} (no public access) in the storage account {1}, then give {2} Storage Blob Data Contributor on it (that container only)' -f $Container, $acctName, $IdentityName))
            return (& $out $false $uri)
        }
        for ($i = 1; $i -le $Tries; $i++) { $c = & $Arm 'GET' $cPath $null; if ($c) { break }; if ($i -lt $Tries) { & $Sleep $PauseSeconds } }
        if (-not $c) { $lines.Add(('the blob container {0} in {1} does not read back after it was created' -f $Container, $acctName)); return (& $out $false $uri) }
        $lines.Add(('the blob container {0} for the sign-in tokens was created in {1} (no public access; read back)' -f $Container, $acctName))
    }
    # the web identity's data right on it
    $listPath = "{0}/providers/Microsoft.Authorization/roleAssignments?api-version={1}&`$filter=principalId eq '{2}'" -f $cScope, $RoleApiVersion, $PrincipalId
    $has = Test-SIBuiltInAuthBlobRole -Assignments @(Get-SIBuiltInAuthProp (& $Arm 'GET' $listPath $null) @('value')) -PrincipalId $PrincipalId -ContainerScope $cScope
    if ($has) { return (& $out $true $uri) }
    $step = 'give {0} Storage Blob Data Contributor on the blob container {1} in {2} (that container only)' -f $IdentityName, $Container, $acctName
    if (-not $Apply) { $support.Add($step); return (& $out $false $uri) }
    try {
        $body = [ordered]@{ properties = [ordered]@{ roleDefinitionId = ('{0}/providers/Microsoft.Authorization/roleDefinitions/{1}' -f (($acctId -split '/')[0..2] -join '/'), $script:SIBuiltInAuthBlobRoleId); principalId = $PrincipalId; principalType = 'ServicePrincipal' } }
        $null = & $Arm 'PUT' ('{0}/providers/Microsoft.Authorization/roleAssignments/{1}?api-version={2}' -f $cScope, (& $NewGuid), $RoleApiVersion) $body
        for ($i = 1; $i -le $Tries; $i++) {
            if (Test-SIBuiltInAuthBlobRole -Assignments @(Get-SIBuiltInAuthProp (& $Arm 'GET' $listPath $null) @('value')) -PrincipalId $PrincipalId -ContainerScope $cScope) { $has = $true; break }
            if ($i -lt $Tries) { & $Sleep $PauseSeconds }
        }
    } catch { $has = $false }
    if ($has) { $lines.Add(('{0} may read and write the sign-in tokens in {1} (Storage Blob Data Contributor on that container only; read back)' -f $IdentityName, $Container)); return (& $out $true $uri) }
    $support.Add($step)
    & $out $false $uri
}

# ============================================================================================================== 5. THE CONVERGE

function Invoke-SIBuiltInAuthConverge {
    <#
        THE CONVERGE (see the file header for the modes). -AppId: the web app's ARM id (/subscriptions/.../containerApps/
        ca-si-management). The sign-in app registration's client id (-ClientId) and tenant (-TenantId) default to the web
        container's AzureAd__ClientId / AzureAd__TenantId; the identity to id-si-web on the app; the address to the app's
        ingress fqdn; custom hosts (-CustomDomains) are added to the ones the ingress names. -StorageAccountId: the install's
        own storage account (default: the web app's SI_StorageAccount in its resource group, else the group's only one).
        THE SWITCH (apply, after the platform is proven in front): ONE PATCH sets SI_Web_BuiltInAuth=1, takes the sign-in
        front container out and points the ingress at the web container's own port (-WebPort, 8080); then an anonymous
        request must still be refused and /.auth/login/aad must send to Microsoft Entra. The way back puts the ingress and
        the template back EXACTLY as read (the front container as it was), the setting off, then the sign-in that ran before.
        NEVER THROWS. Returns @{ Ok; State; Lines; Support }:
          State  off | in-place | planned | redirect-added | applied | needs-support | failed | rolled-back
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Graph,
          [ValidateSet('off', 'plan', 'redirect-only', 'apply')][string]$Mode = 'plan',
          [Parameter(Mandatory)][string]$AppId,
          [string]$TenantId = '', [string]$ClientId = '', [string]$IdentityName = 'id-si-web',
          [switch]$MagicLinksOn, [string[]]$CustomDomains = @(),
          [int]$WebPort = $script:SIBuiltInAuthWebPort, [string]$FrontName = $script:SIBuiltInAuthFrontName,
          [bool]$TokenStore = $true, [string]$StorageAccountId = '', [string]$TokenContainer = $script:SIBuiltInAuthTokenContainer,
          [hashtable]$ConfigOptions = @{},
          [scriptblock]$Probe, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$NewGuid = { [guid]::NewGuid().ToString() },
          [int]$Tries = 6, [int]$PauseSeconds = 10, [int]$ProbeTries = 6,
          # a web app still busy with another operation (an image roll): waited for / retried this many times, -PauseSeconds apart
          [int]$BusyTries = 30,
          [string]$AuthApiVersion = $script:SIBuiltInAuthApi, [string]$AppApiVersion = $script:SIBuiltInAuthAppApi,
          [string]$StorageApiVersion = $script:SIBuiltInAuthStorageApi, [string]$RoleApiVersion = $script:SIBuiltInAuthRoleApi)
    $lines = New-Object System.Collections.Generic.List[string]
    $support = New-Object System.Collections.Generic.List[string]
    $trace = ''
    $tcUri = ''   # the token store's container (apply), for the key ring that follows the switch (Invoke-SIBuiltInAuthKeyRingMove)
    $res = { param([bool]$Ok, [string]$State) [pscustomobject]@{ Ok = $Ok; State = $State; Lines = $lines.ToArray(); Support = $support.ToArray(); Trace = $trace
                                                                 TokenContainerUri = $tcUri; WebPrincipalId = $(if ($id) { [string]$id.PrincipalId } else { '' }); WebIdentityName = $(if ($id) { [string]$id.Name } else { '' }) } }
    if ($Mode -eq 'off') { return (& $res $true 'off') }
    $web = ($AppId.TrimEnd('/') -split '/')[-1]
    $appPath = '{0}?api-version={1}' -f $AppId.TrimEnd('/'), $AppApiVersion
    $authPath = '{0}/authConfigs/current?api-version={1}' -f $AppId.TrimEnd('/'), $AuthApiVersion
    $listPath = '{0}/listSecrets?api-version={1}' -f $AppId.TrimEnd('/'), $AppApiVersion
    # live 2026-11-14 (internal, 3.1.19): the converge ran right after the update rolled the web app's new image, and its
    # write got HTTP 409 ContainerAppOperationInProgress. Every WRITE to the web app (the app or its authConfig) now first
    # waits until the app's provisioningState settles, and a 409 "operation in progress" is retried after a pause before
    # it counts as a failure. Reads go straight through.
    $rawArm = $Arm
    $appBase = $AppId.TrimEnd('/').ToLowerInvariant()
    $Arm = {
        param([string]$Method, [string]$Path, $Body)
        if ($Method -notin 'PUT', 'PATCH', 'DELETE' -or -not "$Path".ToLowerInvariant().StartsWith($appBase)) { return (& $rawArm $Method $Path $Body) }
        for ($w = 1; $w -le $BusyTries; $w++) {
            $st = [string](Get-SIBuiltInAuthProp (& $rawArm 'GET' $appPath $null) @('properties', 'provisioningState'))
            if (-not $st -or $st -in 'Succeeded', 'Failed', 'Canceled') { break }
            & $Sleep $PauseSeconds
        }
        for ($t = 1; ; $t++) {
            try { return (& $rawArm $Method $Path $Body) }
            catch {
                if ($t -lt $BusyTries -and "$($_.Exception.Message)" -match '(?i)\b409\b|OperationInProgress|another operation is in progress') { & $Sleep $PauseSeconds; continue }
                throw
            }
        }
    }
    $g = 'https://graph.microsoft.com/v1.0'
    $authWritten = $false; $switchWritten = $false; $appBeforeSwitch = $null; $authBefore = $null; $app = $null; $want = $null; $settingNow = $false; $id = $null
    $supportLine = { $(if ($support.Count) { ('{0}: Support-app step(s) before Microsoft''s built-in sign-in can switch on: {1}' -f $web, ($support -join '; ')) } else { '' }) }
    try {
        # ---- read ----
        $app = & $Arm 'GET' $appPath $null
        if (-not $app) { $lines.Add(('{0}: Microsoft''s built-in sign-in: the web app was not found -- nothing to do' -f $web)); return (& $res $true 'in-place') }
        if (-not "$TenantId".Trim()) { $TenantId = Get-SIBuiltInAuthSetting -App $app -Name 'AzureAd__TenantId' }
        if (-not "$ClientId".Trim()) { $ClientId = Get-SIBuiltInAuthSetting -App $app -Name 'AzureAd__ClientId' }
        if ("$TenantId" -notmatch '^[0-9a-fA-F-]{36}$' -or "$ClientId" -notmatch '^[0-9a-fA-F-]{36}$') {
            $lines.Add(('{0}: Microsoft''s built-in sign-in was not set up -- the web app''s sign-in settings (AzureAd__TenantId / AzureAd__ClientId) could not be read' -f $web))
            return (& $res $false 'failed')
        }
        $id = Get-SIBuiltInAuthWebIdentity -App $app -Name $IdentityName
        if (-not $id) { $lines.Add(('{0}: Microsoft''s built-in sign-in was not set up -- the web app needs its managed identity {1}' -f $web, $IdentityName)); return (& $res $false 'failed') }
        $fqdn = [string](Get-SIBuiltInAuthProp $app @('properties', 'configuration', 'ingress', 'fqdn'))
        if (-not $fqdn) { $lines.Add(('{0}: Microsoft''s built-in sign-in was not set up -- the web app has no public address' -f $web)); return (& $res $false 'failed') }
        $hosts = @(@(Get-SIBuiltInAuthProp $app @('properties', 'configuration', 'ingress', 'customDomains')) | ForEach-Object { [string](Get-SIBuiltInAuthProp $_ @('name')) } | Where-Object { $_ }) + @($CustomDomains | Where-Object { "$_".Trim() })
        $reg = & $Graph 'GET' ("$g/applications(appId='{0}')?`$select=id,web" -f $ClientId) $null
        if (-not $reg -or -not [string](Get-SIBuiltInAuthProp $reg @('id'))) { $lines.Add(('{0}: Microsoft''s built-in sign-in was not set up -- the sign-in app registration {1} was not found' -f $web, $ClientId)); return (& $res $false 'failed') }
        $regId = [string]$reg.id
        $uris = @(@(Get-SIBuiltInAuthProp $reg @('web', 'redirectUris')) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        $ru = Get-SIBuiltInAuthRedirectUris -Existing $uris -Fqdn $fqdn -CustomDomains $hosts
        $fics = @((Get-SIBuiltInAuthProp (& $Graph 'GET' ("$g/applications/{0}/federatedIdentityCredentials" -f $regId) $null) @('value')))
        $ficOk = Test-SIBuiltInAuthFic -Credentials $fics -TenantId $TenantId -PrincipalId $id.PrincipalId
        $ficStep = ('trust the web app''s managed identity {0} on the sign-in app registration (a federated credential: issuer https://login.microsoftonline.com/{1}/v2.0, subject {2}, audience {3})' -f $id.Name, $TenantId.ToLowerInvariant(), $id.PrincipalId, $script:SIBuiltInAuthFicAudience)
        $authBefore = & $Arm 'GET' $authPath $null
        $secretNow = @(@(Get-SIBuiltInAuthProp $app @('properties', 'configuration', 'secrets')) | Where-Object { $_ -and [string](Get-SIBuiltInAuthProp $_ @('name')) -ieq $script:SIBuiltInAuthSecretName }).Count -gt 0
        $settingNow = (Get-SIBuiltInAuthSetting -App $app) -eq '1'
        $frontNow = [bool](Get-SIBuiltInAuthFrontContainer -App $app -FrontName $FrontName)
        $portNow = [int](0 + (Get-SIBuiltInAuthProp $app @('properties', 'configuration', 'ingress', 'targetPort')))
        $switched = (Test-SIBuiltInAuthSwitched -App $app -WebPort $WebPort -FrontName $FrontName).Ok

        # ---- plan ----
        if ($Mode -eq 'plan') {
            $todo = New-Object System.Collections.Generic.List[string]
            $ts = $null
            if ($TokenStore) {
                if (-not "$StorageAccountId".Trim()) { $StorageAccountId = Resolve-SIBuiltInAuthStorageAccountId -Arm $Arm -App $app -AppId $AppId -StorageApiVersion $StorageApiVersion }
                if (-not "$StorageAccountId".Trim()) { $lines.Add(('{0}: the install''s storage account for the sign-in tokens could not be told -- built-in sign-in cannot switch on' -f $web)) }
                else {
                    $ts = Invoke-SIBuiltInAuthTokenStoreReady -Arm $Arm -StorageAccountId $StorageAccountId -PrincipalId $id.PrincipalId -Container $TokenContainer -IdentityName $id.Name -StorageApiVersion $StorageApiVersion -RoleApiVersion $RoleApiVersion
                    foreach ($l in $ts.Lines) { $todo.Add($l) }; foreach ($l in $ts.Support) { $support.Add($l) }
                }
            }
            $opt = @{ TenantId = $TenantId; ClientId = $ClientId; MagicLinksOn = [bool]$MagicLinksOn }
            if ($ts -and $ts.ContainerUri) { $opt['TokenStoreContainerUri'] = $ts.ContainerUri; $opt['TokenStoreIdentityResourceId'] = $id.ResourceId }
            foreach ($k in @($ConfigOptions.Keys)) { $opt[$k] = $ConfigOptions[$k] }
            $cmp = Test-SIBuiltInAuthConfigMatches -Current $authBefore -Want (Get-SIBuiltInAuthConfigBody @opt)
            if ($ru.Added.Count) { $todo.Add('add the redirect URI(s) ' + ($ru.Added -join ', ')) }
            if (-not (Test-SIBuiltInAuthIdTokenIssuance -Web (Get-SIBuiltInAuthProp $reg @('web')))) { $todo.Add('switch ID-token issuance ON (access-token issuance OFF) on the sign-in app registration') }
            if (-not $secretNow) { $todo.Add(('add the secret {0} (the managed identity''s client id)' -f $script:SIBuiltInAuthSecretName)) }
            if (-not $cmp.Ok) { $todo.Add('write the sign-in configuration (' + ($cmp.Diff -join ', ') + ')') }
            if (-not $switched) {
                $sw = New-Object System.Collections.Generic.List[string]
                if (-not $settingNow) { $sw.Add(('set {0}=1' -f $script:SIBuiltInAuthSettingName)) }
                if ($frontNow) { $sw.Add(('take the sign-in front container {0} out' -f $FrontName)) }
                $sw.Add($(if ($portNow -ne $WebPort) { 'move the ingress from port {0} to {1} (the web app''s own port)' -f $portNow, $WebPort } else { 'the ingress stays on port {0}' -f $WebPort }))
                $todo.Add('then, in one change of the web app: ' + ($sw -join ', '))
            }
            if (-not $ficOk) { $support.Add($ficStep) }
            $sl = & $supportLine; if ($sl) { $lines.Add($sl) }
            if (-not $todo.Count) { $lines.Add(('{0}: Microsoft''s built-in sign-in is in place (nothing would change)' -f $web)); return (& $res $true 'in-place') }
            $lines.Add(('{0}: Microsoft''s built-in sign-in -- would: {1} (nothing was changed)' -f $web, ($todo -join '; ')))
            return (& $res $true 'planned')
        }

        # ---- the sign-in app registration (redirect-only and apply): the callback added, and ID-token issuance ON /
        #      access-token issuance OFF -- the platform asks for "code id_token" (Entra refuses it otherwise: AADSTS700054) ----
        $igOk = Test-SIBuiltInAuthIdTokenIssuance -Web (Get-SIBuiltInAuthProp $reg @('web'))
        $igStep = 'switch ID-token issuance ON (access-token issuance OFF) on the sign-in app registration {0} -- Microsoft''s built-in sign-in asks for an ID token' -f $ClientId
        $regChanged = $false
        if ($ru.Added.Count -or -not $igOk) {
            # SECURE-WEB-1: the updater gets NO new write right. It writes the sign-in app registration only with the right it
            # already holds where it holds it (Application.ReadWrite.OwnedBy as the registration's owner, as the web app name
            # move does); a refusal is the installer's / the Support app's step, never a failure of the update
            try { $null = & $Graph 'PATCH' ("$g/applications/{0}" -f $regId) (Get-SIBuiltInAuthAppWebPatch -Web (Get-SIBuiltInAuthProp $reg @('web')) -RedirectUris $ru.Uris) }
            catch {
                if ("$($_.Exception.Message)" -match '(?i)\b(401|403)\b|Authorization_RequestDenied|Insufficient privileges|Forbidden') {
                    $support.Add(('on the sign-in app registration {0}: add the redirect URI {1} and switch ID-token issuance ON (access-token issuance OFF) -- the updater may not write the registration here' -f $ClientId, (@($ru.Uris | Where-Object { $_ -match '/\.auth/login/aad/callback$' }) -join ', ')))
                    $sl = & $supportLine; if ($sl) { $lines.Add($sl) }
                    return (& $res $false 'needs-support')
                }
                throw
            }
            $regChanged = $true
            $ok = $false; $igOk = $false
            for ($i = 1; $i -le $Tries; $i++) {
                $b = & $Graph 'GET' ("$g/applications/{0}?`$select=id,web" -f $regId) $null
                $now = @(@(Get-SIBuiltInAuthProp $b @('web', 'redirectUris')) | Where-Object { $_ } | ForEach-Object { [string]$_ })
                $lost = @($uris | Where-Object { $u = $_; -not @($now | Where-Object { $_ -ieq $u }).Count })
                $miss = @($ru.Added | Where-Object { $u = $_; -not @($now | Where-Object { $_ -ieq $u }).Count })
                $igOk = Test-SIBuiltInAuthIdTokenIssuance -Web (Get-SIBuiltInAuthProp $b @('web'))
                if (-not $lost.Count -and -not $miss.Count) { $ok = $true; if ($igOk) { break } }
                if ($i -lt $Tries) { & $Sleep $PauseSeconds }
            }
            if (-not $ok) { $lines.Add(('{0}: the sign-in callback {1} does not read back on the sign-in app registration -- the next update tries again' -f $web, ($ru.Added -join ', '))); return (& $res $false 'failed') }
            if ($ru.Added.Count) { $lines.Add(('{0}: the sign-in app registration accepts Microsoft''s built-in sign-in callback {1} (read back)' -f $web, ($ru.Added -join ', '))) }
            if ($igOk) { $lines.Add(('{0}: the sign-in app registration issues ID tokens (access tokens off; read back)' -f $web)) }
        }
        if (-not $igOk) { $support.Add($igStep) }
        if ($Mode -eq 'redirect-only') {
            if (-not $ficOk) { $support.Add($ficStep) }
            $sl = & $supportLine; if ($sl) { $lines.Add($sl) }
            if (-not $igOk) { return (& $res $false 'needs-support') }
            if (-not $regChanged) { $lines.Add(('{0}: the sign-in app registration already accepts Microsoft''s built-in sign-in callback' -f $web)); return (& $res $true 'in-place') }
            return (& $res $true 'redirect-added')
        }
        if (-not $igOk) { $lines.Add((& $supportLine)); return (& $res $false 'needs-support') }

        # ---- apply: what must be there first ----
        if (-not $ficOk) { $support.Add($ficStep) }
        $opt = @{ TenantId = $TenantId; ClientId = $ClientId; MagicLinksOn = [bool]$MagicLinksOn; TokenStore = $false }
        if ($TokenStore) {
            if (-not "$StorageAccountId".Trim()) { $StorageAccountId = Resolve-SIBuiltInAuthStorageAccountId -Arm $Arm -App $app -AppId $AppId -StorageApiVersion $StorageApiVersion }
            if (-not "$StorageAccountId".Trim()) { $lines.Add(('{0}: Microsoft''s built-in sign-in was not switched on -- the install''s storage account for the sign-in tokens could not be told (name it with SI_StorageAccount on the web app)' -f $web)); return (& $res $false 'failed') }
            # #1262: the container is created whether or not the right may be tried now (-Apply needs the federated
            # credential) -- so the Support-app step for id-si-web's data right names a container that exists
            $ts = Invoke-SIBuiltInAuthTokenStoreReady -Arm $Arm -StorageAccountId $StorageAccountId -PrincipalId $id.PrincipalId -Container $TokenContainer -IdentityName $id.Name -Apply:$ficOk -CreateContainer `
                      -NewGuid $NewGuid -Sleep $Sleep -Tries $Tries -PauseSeconds $PauseSeconds -StorageApiVersion $StorageApiVersion -RoleApiVersion $RoleApiVersion
            foreach ($l in $ts.Lines) { $lines.Add(('{0}: {1}' -f $web, $l)) }
            foreach ($l in $ts.Support) { $support.Add($l) }
            if (-not $ts.Ok -and -not $ts.ContainerUri) { return (& $res $false 'failed') }
            if (-not $ts.Ok -and -not @($ts.Support | Where-Object { $_ -match 'Storage Blob Data Contributor' }).Count) { return (& $res $false 'failed') }
            $opt['TokenStore'] = $true; $opt['TokenStoreContainerUri'] = $ts.ContainerUri; $opt['TokenStoreIdentityResourceId'] = $id.ResourceId
            if ($ts.Ok) { $tcUri = [string]$ts.ContainerUri }
            if (-not $ts.Ok) { $lines.Add((& $supportLine)); return (& $res $false 'needs-support') }
        }
        if (-not $ficOk) { $lines.Add((& $supportLine)); return (& $res $false 'needs-support') }
        foreach ($k in @($ConfigOptions.Keys)) { $opt[$k] = $ConfigOptions[$k] }
        $want = Get-SIBuiltInAuthConfigBody @opt
        $cmp = Test-SIBuiltInAuthConfigMatches -Current $authBefore -Want $want
        $sl = & $supportLine; if ($sl) { $lines.Add($sl) }   # (only the shared-key note can be left here: said, not blocking)
        if ($secretNow -and $cmp.Ok -and $switched) {
            $p = $null; if ($Probe) { try { $p = & $Probe ("https://$fqdn/") } catch { $p = $null } }
            if ($p -and -not (Test-SIBuiltInAuthAnonymousRefused -Probe $p)) {
                $lines.Add(('{0}: WARNING: Microsoft''s built-in sign-in is set up, but a request without a sign-in was answered with HTTP {1} -- the next update checks again' -f $web, [int]$p.Status))
                return (& $res $false 'failed')
            }
            $lines.Add(('{0}: Microsoft''s built-in sign-in is in place (an 8-hour session; a request without a sign-in is refused)' -f $web))
            return (& $res $true 'in-place')
        }
        # 1. the secret (the identity's client id) -- every other secret kept
        $sv = ConvertTo-SIBuiltInAuthSecretValues (& $Arm 'POST' $listPath $null)
        $sp = Get-SIBuiltInAuthSecretPatch -App $app -IdentityClientId $id.ClientId -SecretValues $sv -Setting keep
        if ($sp.MissingSecrets.Count) { $lines.Add(('{0}: Microsoft''s built-in sign-in was NOT set up -- the web app''s secret(s) {1} could not be read, and a write would blank them; nothing was changed' -f $web, ($sp.MissingSecrets -join ', '))); return (& $res $false 'failed') }
        if ($sp.Changed) {
            $null = & $Arm 'PATCH' $appPath $sp.Body
            $ok = $false
            for ($i = 1; $i -le $Tries; $i++) {
                try {
                    $sb = ConvertTo-SIBuiltInAuthSecretValues (& $Arm 'POST' $listPath $null)
                    $have = "$(Get-SIBuiltInAuthProp $sb[$script:SIBuiltInAuthSecretName] @('value'))".Trim().ToLowerInvariant()
                    $kept = @(@($sv.Keys) | Where-Object { $_ -ine $script:SIBuiltInAuthSecretName -and -not $sb.ContainsKey($_) })
                    if ($have -eq $id.ClientId -and -not $kept.Count) { $ok = $true; break }
                } catch { }
                if ($i -lt $Tries) { & $Sleep $PauseSeconds }
            }
            if (-not $ok) { $lines.Add(('{0}: Microsoft''s built-in sign-in was NOT set up -- the secret {1} does not read back; the sign-in is unchanged' -f $web, $script:SIBuiltInAuthSecretName)); return (& $res $false 'failed') }
            $lines.Add(('{0}: the web app holds the managed identity''s client id for the built-in sign-in (read back; every other secret kept)' -f $web))
        }
        # 2. the authConfig
        $authWritten = $true
        $null = & $Arm 'PUT' $authPath $want
        $ok = $false; $last = $null
        for ($i = 1; $i -le $Tries; $i++) {
            try { $last = & $Arm 'GET' $authPath $null; if ((Test-SIBuiltInAuthConfigMatches -Current $last -Want $want).Ok) { $ok = $true; break } } catch { }
            if ($i -lt $Tries) { & $Sleep $PauseSeconds }
        }
        if (-not $ok) { throw ('the sign-in configuration does not read back ({0})' -f ((Test-SIBuiltInAuthConfigMatches -Current $last -Want $want).Diff -join ', ')) }
        # 3. an anonymous request must be refused (never page content)
        if (-not $Probe) { throw 'no way to send a request without a sign-in -- it could not be proven that one is refused' }
        $probeRoot = {
            $p = $null
            for ($i = 1; $i -le $ProbeTries; $i++) {
                try { $p = & $Probe ("https://$fqdn/") } catch { $p = $null }
                if ($p -and (Test-SIBuiltInAuthAnonymousRefused -Probe $p)) { return $null }
                if ($i -lt $ProbeTries) { & $Sleep $PauseSeconds }
            }
            'a request without a sign-in was answered with HTTP {0}, not refused' -f $(if ($p) { [int]$p.Status } else { 0 })
        }
        $why0 = & $probeRoot
        if ($why0) { throw $why0 }
        # 4. THE SWITCH -- the web app trusts the platform's sign-in only now, after the platform is proven in front of it: in
        #    ONE PATCH the setting on, the sign-in front out, the ingress on the web container's own port
        if (-not $switched) {
            $appBeforeSwitch = & $Arm 'GET' $appPath $null
            if (-not $appBeforeSwitch) { throw 'the web app could not be read before the switch' }
            $sv2 = ConvertTo-SIBuiltInAuthSecretValues (& $Arm 'POST' $listPath $null)
            $sp2 = Get-SIBuiltInAuthSecretPatch -App $appBeforeSwitch -IdentityClientId $id.ClientId -SecretValues $sv2 -Setting on -RemoveFront -WebPort $WebPort -FrontName $FrontName
            if ($sp2.MissingSecrets.Count) { throw ('the web app''s secret(s) {0} could not be read, and a write would blank them' -f ($sp2.MissingSecrets -join ', ')) }
            $switchWritten = $true
            $null = & $Arm 'PATCH' $appPath $sp2.Body
            $rb = [pscustomobject]@{ Ok = $false; Why = 'not read yet' }
            for ($i = 1; $i -le $Tries; $i++) {
                try { $rb = Test-SIBuiltInAuthSwitched -App (& $Arm 'GET' $appPath $null) -WebPort $WebPort -FrontName $FrontName } catch { $rb = [pscustomobject]@{ Ok = $false; Why = $_.Exception.Message } }
                if ($rb.Ok) { break }
                if ($i -lt $Tries) { & $Sleep $PauseSeconds }
            }
            if (-not $rb.Ok) { throw ('the web app does not read back switched ({0})' -f $rb.Why) }
        }
        # 5. after the switch: still refused, and the platform's own sign-in answers
        $why1 = & $probeRoot
        if ($why1) { throw ('after the switch: ' + $why1) }
        $lp = $null; $lok = $false
        for ($i = 1; $i -le $ProbeTries; $i++) {
            try { $lp = & $Probe ("https://$fqdn/.auth/login/aad") } catch { $lp = $null }
            if ($lp -and (Test-SIBuiltInAuthLoginAnswers -Probe $lp)) { $lok = $true; break }
            if ($i -lt $ProbeTries) { & $Sleep $PauseSeconds }
        }
        if (-not $lok) { throw ('after the switch the platform''s sign-in /.auth/login/aad answered HTTP {0}, not a redirect to Microsoft Entra' -f $(if ($lp) { [int]$lp.Status } else { 0 })) }
        $lines.Add(('{0}: signs users in with Microsoft''s built-in sign-in now (an 8-hour session, the sign-in tokens in {1}{2}; the sign-in front container is out, the ingress on port {3}; read back; a request without a sign-in is refused)' -f $web, $TokenContainer, $(if ($MagicLinksOn) { '; magic links open without a sign-in' } else { '' }), $WebPort))
        return (& $res $true 'applied')
    } catch {
        $why = $_.Exception.Message
        # (where it failed, for the log's verbose detail and the tests -- never in a customer line)
        $trace = "$($_.ScriptStackTrace)"
        if (-not $authWritten) {
            $lines.Add(('{0}: Microsoft''s built-in sign-in could not be checked ({1}) -- nothing was changed; the next update tries again' -f $web, $why))
            return (& $res $false 'failed')
        }
        # ---- roll back: the web app as it was (ingress, template, the front container), the setting off, then the sign-in
        #      that ran before ----
        $back = New-Object System.Collections.Generic.List[string]
        $rbAuth = $null; $wantOn = $false
        try { $rbAuth = Get-SIBuiltInAuthRestoreBody -Before $authBefore -Want $want; $wantOn = "$(Get-SIBuiltInAuthProp $rbAuth @('properties', 'platform', 'enabled'))" -match '^(?i)true$' } catch { $rbAuth = $null }
        $drop = (-not $settingNow) -or (-not $wantOn)
        if ($switchWritten -and $appBeforeSwitch) {
            try {
                $cur = & $Arm 'GET' $appPath $null
                $svR = ConvertTo-SIBuiltInAuthSecretValues (& $Arm 'POST' $listPath $null)
                $rp = Get-SIBuiltInAuthAppRestorePatch -Before $appBeforeSwitch -Current $(if ($cur) { $cur } else { $appBeforeSwitch }) -IdentityClientId $id.ClientId -SecretValues $svR -DropSetting:$drop
                if ($rp.MissingSecrets.Count) { throw ('its secret(s) {0} could not be read' -f ($rp.MissingSecrets -join ', ')) }
                $null = & $Arm 'PATCH' $appPath $rp.Body
                $okR = $false; $whyR = ''
                $wantFront = Get-SIBuiltInAuthFrontContainer -App $appBeforeSwitch -FrontName $FrontName
                $wantPort = [int](0 + (Get-SIBuiltInAuthProp $appBeforeSwitch @('properties', 'configuration', 'ingress', 'targetPort')))
                for ($i = 1; $i -le $Tries; $i++) {
                    try {
                        $n = & $Arm 'GET' $appPath $null
                        $nf = Get-SIBuiltInAuthFrontContainer -App $n -FrontName $FrontName
                        $np = [int](0 + (Get-SIBuiltInAuthProp $n @('properties', 'configuration', 'ingress', 'targetPort')))
                        $frontSame = if ($wantFront) { $nf -and ((ConvertTo-SIBuiltInAuthCanonicalJson $nf) -eq (ConvertTo-SIBuiltInAuthCanonicalJson $wantFront)) } else { -not $nf }
                        $settingGone = (-not $drop) -or (-not (Get-SIBuiltInAuthSetting -App $n))
                        if ($np -eq $wantPort -and $frontSame -and $settingGone) { $okR = $true; break }
                        $whyR = 'port {0}, front {1}, setting {2}' -f $np, $(if ($frontSame) { 'as before' } else { 'NOT as before' }), $(if ($settingGone) { 'as before' } else { 'still on' })
                    } catch { $whyR = $_.Exception.Message }
                    if ($i -lt $Tries) { & $Sleep $PauseSeconds }
                }
                if ($okR) { $back.Add(('the web app was put back as it ran before -- the ingress on port {0}{1}{2} (read back)' -f $wantPort, $(if ($wantFront) { ', the sign-in front container as it was' } else { '' }), $(if ($drop) { (', {0} off' -f $script:SIBuiltInAuthSettingName) } else { '' }))) }
                else { $back.Add(('the web app does NOT read back as it ran before ({0}) -- check it by hand' -f $whyR)) }
            } catch { $back.Add(('the web app could NOT be put back ({0}) -- restore its ingress port, the sign-in front container and {1} by hand' -f $_.Exception.Message, $script:SIBuiltInAuthSettingName)) }
        } elseif ($drop) {
            try {
                $a3 = & $Arm 'GET' $appPath $null
                if (Get-SIBuiltInAuthSetting -App $a3) {
                    $sv3 = ConvertTo-SIBuiltInAuthSecretValues (& $Arm 'POST' $listPath $null)
                    $sp3 = Get-SIBuiltInAuthSecretPatch -App $a3 -IdentityClientId $id.ClientId -SecretValues $sv3 -Setting off
                    if ($sp3.MissingSecrets.Count) { throw ('its secret(s) {0} could not be read' -f ($sp3.MissingSecrets -join ', ')) }
                    $null = & $Arm 'PATCH' $appPath $sp3.Body
                    if (Get-SIBuiltInAuthSetting -App (& $Arm 'GET' $appPath $null)) { throw 'it still reads back' }
                    $back.Add(('{0} was taken off the web app again (read back)' -f $script:SIBuiltInAuthSettingName))
                }
            } catch { $back.Add(('{0} could NOT be taken off the web app ({1}) -- remove it by hand' -f $script:SIBuiltInAuthSettingName, $_.Exception.Message)) }
        }
        try {
            if (-not $rbAuth) { throw 'the earlier sign-in configuration could not be built' }
            $null = & $Arm 'PUT' $authPath $rbAuth
            $now = & $Arm 'GET' $authPath $null
            $isOn = "$(Get-SIBuiltInAuthProp $now @('properties', 'platform', 'enabled'))" -match '^(?i)true$'
            if ($wantOn -eq $isOn) { $back.Add($(if ($wantOn) { 'the sign-in configuration that ran before was put back (read back)' } else { 'the built-in sign-in was switched off again (read back)' })) }
            else { $back.Add('the sign-in configuration could NOT be read back after it was put back -- check it by hand') }
        } catch { $back.Add(('the sign-in configuration could NOT be put back ({0}) -- restore it by hand' -f $_.Exception.Message)) }
        $lines.Add(('{0}: Microsoft''s built-in sign-in was NOT switched on: {1}; {2}' -f $web, $why, ($back -join '; ')))
        return (& $res $false 'rolled-back')
    }
}

# ============================================================================================================== 6. NO KEY VAULT RIGHT AFTER THE SWITCH

$script:SIBuiltInAuthKeyRingSetting = 'DataProtection__BlobUri'
$script:SIBuiltInAuthKeyRingBlob    = 'dataprotection/keys.xml'
$script:SIBuiltInAuthKvCryptoRoleId = [string]'e147488a-f6f5-4113-8e2d-b22465e65bf6'   # Key Vault Crypto Service Encryption User (a built-in role id, public)
$script:SIBuiltInAuthWebKeyNames    = @('signin-front-dp', 'SI-Web-KeyRing')

function Get-SIBuiltInAuthKeyRingBlobUri {
    <# PURE. The blob the web app keeps its sign-in keys in: <token-store container>/dataprotection/keys.xml. #>
    param([Parameter(Mandatory)][string]$ContainerUri)
    '{0}/{1}' -f $ContainerUri.Trim().TrimEnd('/'), $script:SIBuiltInAuthKeyRingBlob
}

function Select-SIBuiltInAuthWebKeyAssignments {
    <# PURE. Of -Assignments (as ARM lists them), the ones that give -PrincipalId "Key Vault Crypto Service Encryption User" AT
       EXACTLY -KeyScope (never above it, never another identity's). #>
    param([object[]]$Assignments = @(), [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$KeyScope)
    $ks = $KeyScope.TrimEnd('/').ToLowerInvariant()
    @(@($Assignments) | Where-Object {
            $_ -and [string](Get-SIBuiltInAuthProp $_ @('id')) -and
            "$(Get-SIBuiltInAuthProp $_ @('properties', 'principalId'))".Trim() -ieq $PrincipalId.Trim() -and
            ("$(Get-SIBuiltInAuthProp $_ @('properties', 'roleDefinitionId'))" -split '/')[-1] -ieq $script:SIBuiltInAuthKvCryptoRoleId -and
            "$(Get-SIBuiltInAuthProp $_ @('properties', 'scope'))".TrimEnd('/').ToLowerInvariant() -eq $ks })
}

function Test-SIBuiltInAuthRevisionRuns {
    <# PURE. Does the web app as read (-App) run a revision that is the latest, ready, Healthy and running, whose template
       (-Revision as read) carries -Name = -Value? @{ Ok; Why }. #>
    param($App, $Revision, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Value)
    $latest = [string](Get-SIBuiltInAuthProp $App @('properties', 'latestRevisionName'))
    $ready = [string](Get-SIBuiltInAuthProp $App @('properties', 'latestReadyRevisionName'))
    if (-not $latest) { return [pscustomobject]@{ Ok = $false; Why = 'the web app names no revision' } }
    if ($latest -ne $ready) { return [pscustomobject]@{ Ok = $false; Why = ('its revision {0} is not ready yet' -f $latest) } }
    if (-not $Revision) { return [pscustomobject]@{ Ok = $false; Why = ('its revision {0} could not be read' -f $latest) } }
    $h = [string](Get-SIBuiltInAuthProp $Revision @('properties', 'healthState'))
    if ($h -ne 'Healthy') { return [pscustomobject]@{ Ok = $false; Why = ('its revision {0} is {1}, not Healthy' -f $latest, $(if ($h) { $h } else { 'of no known health' })) } }
    $rs = [string](Get-SIBuiltInAuthProp $Revision @('properties', 'runningState'))
    if ($rs -and $rs -notmatch '^(?i)(Running|RunningAtMaxScale)$') { return [pscustomobject]@{ Ok = $false; Why = ('its revision {0} is {1}' -f $latest, $rs) } }
    $has = $false
    foreach ($c in @(Get-SIBuiltInAuthProp $Revision @('properties', 'template', 'containers'))) {
        foreach ($e in @(Get-SIBuiltInAuthProp $c @('env'))) { if ($e -and [string](Get-SIBuiltInAuthProp $e @('name')) -eq $Name -and "$(Get-SIBuiltInAuthProp $e @('value'))".Trim() -eq $Value.Trim()) { $has = $true } }
    }
    if (-not $has) { return [pscustomobject]@{ Ok = $false; Why = ('its revision {0} does not run with {1} yet' -f $latest, $Name) } }
    [pscustomobject]@{ Ok = $true; Why = '' }
}

function Invoke-SIBuiltInAuthKeyRingMove {
    <#
        AFTER A SUCCESSFUL SWITCH (Invoke-SIBuiltInAuthConverge: applied / in-place, read back) the web identity gives up its
        Key Vault rights (framework SECURE-WEB-1: the internet-facing identity holds no Key Vault role):
          1. DataProtection__BlobUri on the web container = <token-store container>/dataprotection/keys.xml (the web identity
             already holds Storage Blob Data Contributor on that container): ONE PATCH, every secret kept, read back. The web
             app then keeps its sign-in keys in that blob with no Key Vault, and moves the keys from before in once at start
             (pro-management/src/SI.Management.Web/Auth/BlobKeyRing.cs).
          2. ONLY once the web app runs on it -- its latest revision ready, Healthy, running, with that setting -- and its
             address answers (/healthz: the page, or the built-in sign-in's refusal):
          3. id-si-web's "Key Vault Crypto Service Encryption User" AT the keys signin-front-dp and SI-Web-KeyRing is removed
             and read back gone. ONLY that identity, ONLY that role, ONLY at those two key scopes -- nothing else is touched.
             The updater's role right may be conditioned and refuse: a 401 / 403 is a SUPPORT STEP ("the Support app
             removes ..."), never a failure of the update.
        -Arm / -Probe / -Sleep: the converge's seams. -VaultId: the install's Key Vault (its ARM id; '' = the rights are not
        checked, said). NEVER THROWS. Returns @{ Ok; State; Lines; Support } (+ Transient 'arm-409' when the PATCH of step 1
        still answered 409 after every try: nothing was changed -- #1266):
          State  waiting (the web app does not run on the blob yet: the rights stay) | removed | in-place | needs-support |
                 failed
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$AppId, [Parameter(Mandatory)][string]$ContainerUri,
          [Parameter(Mandatory)][string]$PrincipalId, [string]$IdentityName = 'id-si-web', [AllowEmptyString()][string]$VaultId = '',
          [scriptblock]$Probe, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          [int]$Tries = 6, [int]$PauseSeconds = 10, [int]$RevisionTries = 18,
          [string]$AppApiVersion = $script:SIBuiltInAuthAppApi, [string]$RoleApiVersion = $script:SIBuiltInAuthRoleApi)
    $lines = New-Object System.Collections.Generic.List[string]
    $support = New-Object System.Collections.Generic.List[string]
    $res = { param([bool]$Ok, [string]$State) [pscustomobject]@{ Ok = $Ok; State = $State; Lines = $lines.ToArray(); Support = $support.ToArray() } }
    $web = ($AppId.TrimEnd('/') -split '/')[-1]
    $appPath = '{0}?api-version={1}' -f $AppId.TrimEnd('/'), $AppApiVersion
    $listPath = '{0}/listSecrets?api-version={1}' -f $AppId.TrimEnd('/'), $AppApiVersion
    $name = $script:SIBuiltInAuthKeyRingSetting
    try {
        $blob = Get-SIBuiltInAuthKeyRingBlobUri -ContainerUri $ContainerUri
        $app = & $Arm 'GET' $appPath $null
        if (-not $app) { $lines.Add(('{0}: its sign-in keys were not moved -- the web app was not found' -f $web)); return (& $res $false 'failed') }
        # ---- 1. the setting ----
        if ((Get-SIBuiltInAuthSetting -App $app -Name $name) -ne $blob) {
            $id = Get-SIBuiltInAuthWebIdentity -App $app -Name $IdentityName
            if (-not $id) { $lines.Add(('{0}: its sign-in keys were not moved -- the web app''s managed identity {1} could not be read' -f $web, $IdentityName)); return (& $res $false 'failed') }
            $sv = ConvertTo-SIBuiltInAuthSecretValues (& $Arm 'POST' $listPath $null)
            $sp = Get-SIBuiltInAuthSecretPatch -App $app -IdentityClientId $id.ClientId -SecretValues $sv -Setting keep -WebEnv @{ $name = $blob }
            if ($sp.MissingSecrets.Count) { $lines.Add(('{0}: its sign-in keys were NOT moved -- the web app''s secret(s) {1} could not be read, and a write would blank them; nothing was changed' -f $web, ($sp.MissingSecrets -join ', '))); return (& $res $false 'failed') }
            # live 2026-11-15 (a large installation, two updates in a row): the PATCH right after the switch's / another step's change of
            # the same app answered 409 ContainerAppOperationInProgress. Wait until the app has settled (provisioning
            # Succeeded), and on a 409 wait and send the SAME body again -- never a different change
            for ($i = 1; $i -le $RevisionTries; $i++) {
                $ps = ''; try { $ps = [string](Get-SIBuiltInAuthProp (& $Arm 'GET' $appPath $null) @('properties', 'provisioningState')) } catch { }
                if (-not $ps -or $ps -in 'Succeeded', 'Failed', 'Canceled') { break }
                & $Sleep $PauseSeconds
            }
            for ($i = 1; $i -le $RevisionTries; $i++) {
                try { $null = & $Arm 'PATCH' $appPath $sp.Body; break }
                catch {
                    $busy = "$($_.Exception.Message)" -match '(?i)\b409\b|OperationInProgress'
                    if ($i -lt $RevisionTries -and $busy) { & $Sleep $PauseSeconds; continue }
                    # #1266 / framework TRANSIENT-RETRY-1: still 409 after every try -- Azure refused the PATCH, so NOTHING was
                    # changed (the setting is not written, the Key Vault rights stay); a transient failure the next update
                    # tries again (Transient arm-409), never a fix request on its own
                    if ($busy) {
                        $lines.Add(('{0}: its sign-in keys were NOT moved -- the web app stayed busy with another operation (409 ContainerAppOperationInProgress) through {1} tries; nothing was changed, the Key Vault rights stay; the next update tries again' -f $web, $RevisionTries))
                        $r409 = & $res $false 'failed'
                        $r409 | Add-Member -NotePropertyName Transient -NotePropertyValue 'arm-409' -Force
                        return $r409
                    }
                    throw
                }
            }
            $ok = $false
            for ($i = 1; $i -le $Tries; $i++) {
                try {
                    $now = & $Arm 'GET' $appPath $null
                    $sb = ConvertTo-SIBuiltInAuthSecretValues (& $Arm 'POST' $listPath $null)
                    $lost = @(@($sv.Keys) | Where-Object { -not $sb.ContainsKey($_) })
                    if ((Get-SIBuiltInAuthSetting -App $now -Name $name) -eq $blob -and -not $lost.Count) { $ok = $true; break }
                } catch { }
                if ($i -lt $Tries) { & $Sleep $PauseSeconds }
            }
            if (-not $ok) { $lines.Add(('{0}: its sign-in keys were NOT moved -- {1} does not read back; the Key Vault rights stay, the next update checks again' -f $web, $name)); return (& $res $false 'failed') }
            $lines.Add(('{0}: keeps its sign-in keys in its own key store {1} from now on, without Key Vault (read back; every secret kept)' -f $web, $blob))
        }
        # ---- 2. the web app runs on it ----
        $run = [pscustomobject]@{ Ok = $false; Why = 'not read yet' }
        for ($i = 1; $i -le $RevisionTries; $i++) {
            try {
                $a = & $Arm 'GET' $appPath $null
                $rn = [string](Get-SIBuiltInAuthProp $a @('properties', 'latestRevisionName'))
                $rev = if ($rn) { & $Arm 'GET' ('{0}/revisions/{1}?api-version={2}' -f $AppId.TrimEnd('/'), $rn, $AppApiVersion) $null } else { $null }
                $run = Test-SIBuiltInAuthRevisionRuns -App $a -Revision $rev -Name $name -Value $blob
            } catch { $run = [pscustomobject]@{ Ok = $false; Why = $_.Exception.Message } }
            if ($run.Ok) { break }
            if ($i -lt $RevisionTries) { & $Sleep $PauseSeconds }
        }
        if (-not $run.Ok) { $lines.Add(('{0}: the web app does not run on its own key store yet ({1}) -- its Key Vault rights stay; the next update checks again' -f $web, $run.Why)); return (& $res $true 'waiting') }
        $fqdn = [string](Get-SIBuiltInAuthProp $app @('properties', 'configuration', 'ingress', 'fqdn'))
        if ($Probe -and $fqdn) {
            $p = $null; $answers = $false
            for ($i = 1; $i -le $Tries; $i++) {
                try { $p = & $Probe ("https://$fqdn/healthz") } catch { $p = $null }
                if ($p -and ([int]$p.Status -eq 200 -or (Test-SIBuiltInAuthAnonymousRefused -Probe $p))) { $answers = $true; break }
                if ($i -lt $Tries) { & $Sleep $PauseSeconds }
            }
            if (-not $answers) { $lines.Add(('{0}: the web app runs on its own key store, but its address answered HTTP {1} -- its Key Vault rights stay; the next update checks again' -f $web, $(if ($p) { [int]$p.Status } else { 0 }))); return (& $res $true 'waiting') }
        }
        # ---- 3. the Key Vault rights go ----
        if (-not "$VaultId".Trim()) { $lines.Add(('{0}: runs on its own key store; the install''s Key Vault is not known here, so {1}''s Key Vault rights were not checked' -f $web, $IdentityName)); return (& $res $true 'waiting') }
        $removed = 0; $failed = 0
        foreach ($k in $script:SIBuiltInAuthWebKeyNames) {
            $scope = '{0}/keys/{1}' -f $VaultId.Trim().TrimEnd('/'), $k
            $step = 'the Support app removes {0}''s role "Key Vault Crypto Service Encryption User" on the key {1} ({2}) -- the web app no longer uses it' -f $IdentityName, $k, $scope
            $lp = "{0}/providers/Microsoft.Authorization/roleAssignments?api-version={1}&`$filter=principalId eq '{2}'" -f $scope, $RoleApiVersion, $PrincipalId
            $have = $null
            try { $have = @(Select-SIBuiltInAuthWebKeyAssignments -Assignments @(Get-SIBuiltInAuthProp (& $Arm 'GET' $lp $null) @('value')) -PrincipalId $PrincipalId -KeyScope $scope) }
            catch {
                if ("$($_.Exception.Message)" -match '(?i)\b(401|403)\b|AuthorizationFailed|Forbidden') { $support.Add($step); continue }
                $lines.Add(('{0}: {1}''s rights on the key {2} could not be read ({3}) -- the next update checks again' -f $web, $IdentityName, $k, $_.Exception.Message)); $failed++; continue
            }
            foreach ($as in $have) {
                $aid = [string](Get-SIBuiltInAuthProp $as @('id'))
                try { $null = & $Arm 'DELETE' ('{0}?api-version={1}' -f $aid, $RoleApiVersion) $null }
                catch {
                    if ("$($_.Exception.Message)" -match '(?i)\b(401|403)\b|AuthorizationFailed|Forbidden') { $support.Add($step); continue }
                    $lines.Add(('{0}: {1}''s role on the key {2} could NOT be removed ({3}) -- the next update tries again' -f $web, $IdentityName, $k, $_.Exception.Message)); $failed++; continue
                }
                $gone = $false
                for ($i = 1; $i -le $Tries; $i++) {
                    try { if (-not (& $Arm 'GET' ('{0}?api-version={1}' -f $aid, $RoleApiVersion) $null)) { $gone = $true; break } } catch { }
                    if ($i -lt $Tries) { & $Sleep $PauseSeconds }
                }
                if ($gone) { $removed++; $lines.Add(('{0}: {1} no longer holds "Key Vault Crypto Service Encryption User" on the key {2} (removed; read back)' -f $web, $IdentityName, $k)) }
                else { $failed++; $lines.Add(('{0}: {1}''s role on the key {2} was removed but still reads back -- the next update checks again' -f $web, $IdentityName, $k)) }
            }
        }
        foreach ($s in $support) { $lines.Add(('{0}: Support-app step: {1}' -f $web, $s)) }
        if ($failed) { return (& $res $false 'failed') }
        if ($support.Count) { return (& $res $true 'needs-support') }
        if ($removed) { return (& $res $true 'removed') }
        $lines.Add(('{0}: runs on its own key store; {1} holds no Key Vault right on its keys' -f $web, $IdentityName))
        return (& $res $true 'in-place')
    } catch {
        $lines.Add(('{0}: its sign-in keys could not be checked ({1}) -- the Key Vault rights stay; the next update tries again' -f $web, $_.Exception.Message))
        return (& $res $false 'failed')
    }
}

function Resolve-SIBuiltInAuthStorageAccountId {
    <# The install's own storage account id: the web app's SI_StorageAccount, else the resource group's only (SecurityInsight)
       one. '' = not told. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, $App, [Parameter(Mandatory)][string]$AppId, [string]$StorageApiVersion = $script:SIBuiltInAuthStorageApi)
    try {
        $rg = ($AppId -split '/providers/')[0]
        $list = @(Get-SIBuiltInAuthProp (& $Arm 'GET' ('{0}/providers/Microsoft.Storage/storageAccounts?api-version={1}' -f $rg, $StorageApiVersion) $null) @('value'))
        $a = Select-SIBuiltInAuthStorageAccount -Accounts $list -Name (Get-SIBuiltInAuthSetting -App $App -Name 'SI_StorageAccount')
        if ($a) { return [string](Get-SIBuiltInAuthProp $a @('id')) }
    } catch { }
    ''
}

function Read-SIBuiltInAuthMagicLinks {
    <# Are magic links on (the Settings page's SIWeb_MagicLinksEnabled, any scope)? Through a store's (sql, params, mode) seam;
       no store, no row or an unreadable database = OFF (no page opens without a sign-in). Never throws. #>
    param($Store, [scriptblock]$Invoke)
    if (-not $Invoke -and $Store) { $Invoke = $Store.Invoke }
    if (-not $Invoke) { return $false }
    try {
        $sql = "IF OBJECT_ID(N'cfg.Setting') IS NULL SELECT CAST(NULL AS NVARCHAR(MAX)) AS ValueJson WHERE 1 = 0; ELSE SELECT ValueJson FROM cfg.Setting WHERE Name = N'SIWeb_MagicLinksEnabled';"
        foreach ($r in @(& $Invoke $sql @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ })) {
            $raw = if ($r -is [System.Collections.IDictionary]) { [string]$r['ValueJson'] } elseif ($r.PSObject.Properties['ValueJson']) { [string]$r.ValueJson } else { [string]$r }
            $v = "$raw".Trim().Trim('"')
            if ($v -match '^(?i)(true|1|on|yes)$') { return $true }
        }
    } catch { }
    $false
}
