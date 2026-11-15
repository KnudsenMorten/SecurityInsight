#Requires -Version 7.0
<#
    MICROSOFT'S BUILT-IN SIGN-IN IN FRONT OF THE WEB APP (framework SECURE-WEB-1 points 5-7) -- setup\_shared\SI-BuiltInAuth.ps1
    and its call from the updater (container\updater\Start-SIUpdater.ps1, Invoke-SIUpdaterBuiltInAuthStep).
    Against a FAKE ARM and a FAKE Graph (script scope, never global):
      * the authConfig body: secretless (the lowercase secret name), the tenant's v2.0 issuer, both audiences, a fixed
        8-hour session, HTTPS only, the token store in a blob container reached with the managed identity (never a SAS);
        excluded paths ONLY with magic links on;
      * the secret PATCH keeps EVERY existing secret (plain and Key Vault references), and stops when one cannot be read;
      * the switch: ONE PATCH = the setting on + the sign-in front container out + the ingress on the web port, every other
        ingress field kept; the way back puts the port and the front container back byte-for-byte;
      * the token store: the container created when missing, the web identity's data right checked (one try, a refusal =
        a Support-app step and no switch), shared-key access on is said;
      * redirect URIs are only ever added; plan writes nothing; redirect writes only the redirect URI;
      * mode off = not a single call; the updater calls it after its web app steps and is OFF by default.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    . (Join-Path $script:SIRoot 'setup\_shared\SI-BuiltInAuth.ps1')

    $script:Tenant  = 'aaaaaaaa-1111-2222-3333-444444444444'
    $script:Client  = 'bbbbbbbb-1111-2222-3333-444444444444'
    $script:MiCid   = 'cccccccc-1111-2222-3333-444444444444'
    $script:MiPrin  = 'dddddddd-1111-2222-3333-444444444444'
    $script:RegId   = 'eeeeeeee-1111-2222-3333-444444444444'
    $script:Rg      = '/subscriptions/00000000-0000-0000-0000-00000000aaaa/resourceGroups/rg-si'
    $script:AppId   = $script:Rg + '/providers/Microsoft.App/containerApps/ca-si-management'
    $script:MiId    = $script:Rg + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-web'
    $script:AcctId  = $script:Rg + '/providers/Microsoft.Storage/storageAccounts/stsitest'
    $script:CScope  = $script:AcctId + '/blobServices/default/containers/si-auth-tokens'
    $script:Fqdn    = 'ca-si-management.happy.westeurope.azurecontainerapps.io'
    $script:Callback = "https://$($script:Fqdn)/.auth/login/aad/callback"

    function script:New-FakeApp {
        param([switch]$WithSetting, [switch]$WithOurSecret, [switch]$Switched)
        $env = @(@{ name = 'AzureAd__TenantId'; value = $script:Tenant }, @{ name = 'AzureAd__ClientId'; value = $script:Client }, @{ name = 'SI_StorageAccount'; value = 'stsitest' },
                 @{ name = 'SI_Web_SigninFront'; value = 'true' }, @{ name = 'SIGNIN_UPSTREAM_PORT'; value = '8081' }, @{ name = 'X'; secretRef = 'sql-pw' })
        if ($WithSetting -or $Switched) { $env += @{ name = 'SI_Web_BuiltInAuth'; value = '1' } }
        $secrets = @(@{ name = 'sql-pw' }, @{ name = 'kv-ref'; keyVaultUrl = 'https://kv.vault.azure.net/secrets/a'; identity = $script:MiId })
        if ($WithOurSecret -or $Switched) { $secrets += @{ name = 'override-use-mi-fic-assertion-client-id' } }
        $containers = @(@{ name = 'si-management'; image = 'acr/si:1'; env = $env; resources = @{ cpu = 1; memory = '2Gi' } })
        if (-not $Switched) {
            $containers += @{ name = 'signin-front'; image = 'acr/front:1.4.0'; env = @(@{ name = 'SIGNIN_UPSTREAM_PORT'; value = '8081' }, @{ name = 'SIGNIN_FIC_MI_CLIENT_ID'; value = $script:MiCid })
                              resources = @{ cpu = 0.25; memory = '0.5Gi' }; probes = @(@{ type = 'Liveness'; httpGet = @{ path = '/healthz'; port = 9000 }; periodSeconds = 10 }) }
        }
        $o = @{
            id = $script:AppId; name = 'ca-si-management'
            identity = @{ type = 'UserAssigned'; userAssignedIdentities = @{ $script:MiId = @{ clientId = $script:MiCid; principalId = $script:MiPrin } } }
            properties = @{
                configuration = @{
                    ingress = [ordered]@{ fqdn = $script:Fqdn; external = $true; targetPort = $(if ($Switched) { 8080 } else { 9000 }); transport = 'auto'; allowInsecure = $false
                                          ipSecurityRestrictions = @(@{ name = 'office'; ipAddressRange = '203.0.113.0/24'; action = 'Allow' })
                                          customDomains = @(@{ name = 'si.contoso.com'; bindingType = 'SniEnabled'; certificateId = '/x/cert' })
                                          stickySessions = @{ affinity = 'sticky' } }
                    secrets = $secrets; activeRevisionsMode = 'Single'; registries = @(@{ server = 'acr.azurecr.io'; identity = $script:MiId })
                }
                template = @{ revisionSuffix = 'r1'; containers = $containers; scale = @{ minReplicas = 1; maxReplicas = 1 } }
            }
        }
        ($o | ConvertTo-Json -Depth 30 | ConvertFrom-Json)
    }

    function script:New-Fake {
        param([switch]$NoFic, [int]$ProbeStatus = 302, [string]$ProbeLocation = '/.auth/login/aad?post_login_redirect_uri=/', $Auth = $null,
              [switch]$WithSetting, [switch]$WithOurSecret, [switch]$PutFails, [switch]$FailAfterSwitch, [string[]]$Uris = @('https://ca-si-management.happy.westeurope.azurecontainerapps.io/signin-oidc'),
              [switch]$NoContainer, [switch]$NoRole, [switch]$RolePutRefused, $SharedKey = $false, $Ig = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false }, [switch]$IgSticksOff, [switch]$GraphPatchRefused,
              [int]$Busy409 = 0, [int]$BusyStates = 0)
        $f = [pscustomobject]@{
            App = (New-FakeApp -WithSetting:$WithSetting -WithOurSecret:$WithOurSecret)
            SecretValues = @{ 'sql-pw' = @{ name = 'sql-pw'; value = 'p@ss' }; 'kv-ref' = @{ name = 'kv-ref'; keyVaultUrl = 'https://kv.vault.azure.net/secrets/a'; identity = $script:MiId } }
            Auth = $Auth; Uris = $Uris; NoFic = [bool]$NoFic; PutFails = [bool]$PutFails; FailAfterSwitch = [bool]$FailAfterSwitch
            ProbeStatus = $ProbeStatus; ProbeLocation = $ProbeLocation
            Ig = $(if ($null -ne $Ig) { [pscustomobject]$Ig } else { $null }); IgSticksOff = [bool]$IgSticksOff; GraphPatchRefused = [bool]$GraphPatchRefused
            ContainerExists = (-not $NoContainer); Roles = (New-Object System.Collections.Generic.List[object]); RolePutRefused = [bool]$RolePutRefused; SharedKey = $SharedKey
            Busy409 = $Busy409; BusyStates = $BusyStates; Answered409 = 0
            Calls = (New-Object System.Collections.Generic.List[object]); Probes = (New-Object System.Collections.Generic.List[string])
        }
        if ($WithOurSecret) { $f.SecretValues['override-use-mi-fic-assertion-client-id'] = @{ name = 'override-use-mi-fic-assertion-client-id'; value = $script:MiCid } }
        if (-not $NoRole) { $f.Roles.Add([pscustomobject]@{ properties = [pscustomobject]@{ principalId = $script:MiPrin; roleDefinitionId = '/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe'; scope = $script:CScope } }) }
        $f
    }

    function script:Get-FakeArm($f) {
        $acctId = $script:AcctId; $prin = $script:MiPrin
        {
            param([string]$Method, [string]$Path, $Body)
            $f.Calls.Add([pscustomobject]@{ Kind = 'arm'; Method = $Method; Path = $Path; Body = $(if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 30 | ConvertFrom-Json } else { $null }); Json = $(if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 30 -Compress } else { '' }) })
            if ($Path -like '*/providers/Microsoft.Authorization/roleAssignments*') {
                if ($Method -eq 'GET') { $ra = [object[]]$f.Roles.ToArray(); return [pscustomobject]@{ value = $ra } }
                if ($f.RolePutRefused) { throw 'PUT roleAssignments failed: HTTP 403: AuthorizationFailed' }
                $f.Roles.Add([pscustomobject]@{ properties = [pscustomobject]@{ principalId = $Body.properties.principalId; roleDefinitionId = $Body.properties.roleDefinitionId; scope = ($Path -split '/providers/Microsoft.Authorization/')[0] } }); return $null
            }
            if ($Path -like '*/blobServices/default/containers/*') {
                if ($Method -eq 'GET') { if ($f.ContainerExists) { return [pscustomobject]@{ name = 'si-auth-tokens' } } else { return $null } }
                $f.ContainerExists = $true; return $null
            }
            if ($Path -like '*/providers/Microsoft.Storage/storageAccounts[?]*') { return [pscustomobject]@{ value = @([pscustomobject]@{ id = $acctId; name = 'stsitest' }) } }
            if ($Path -like '*/providers/Microsoft.Storage/storageAccounts/*') { return [pscustomobject]@{ id = $acctId; name = 'stsitest'; properties = [pscustomobject]@{ allowSharedKeyAccess = $f.SharedKey; primaryEndpoints = [pscustomobject]@{ blob = 'https://stsitest.blob.core.windows.net/' } } } }
            if ($Path -like '*/authConfigs/current*') {
                if ($Method -eq 'GET') { return $f.Auth }
                if ($f.PutFails) { throw 'PUT failed: HTTP 500' }
                $f.Auth = ($Body | ConvertTo-Json -Depth 30 | ConvertFrom-Json); return $f.Auth
            }
            if ($Path -like '*/listSecrets*') { return [pscustomobject]@{ value = @($f.SecretValues.Values | ForEach-Object { [pscustomobject]$_ }) } }
            if ($Method -eq 'GET') {
                $a = ($f.App | ConvertTo-Json -Depth 30 | ConvertFrom-Json)
                # an app still busy with another operation: InProgress for the next -BusyStates reads
                $ps = if ($f.BusyStates -gt 0) { $f.BusyStates--; 'InProgress' } else { 'Succeeded' }
                $a.properties | Add-Member -NotePropertyName provisioningState -NotePropertyValue $ps -Force
                return $a
            }
            if ($Method -eq 'PATCH' -and $f.Busy409 -gt 0) { $f.Busy409--; $f.Answered409++; throw 'PATCH failed: HTTP 409: ContainerAppOperationInProgress: Cannot modify a container app while another operation is in progress' }
            if ($Method -eq 'PATCH') {
                $b = $Body | ConvertTo-Json -Depth 30 | ConvertFrom-Json
                $sec = @($b.properties.configuration.secrets)
                $f.SecretValues = @{}
                foreach ($s in $sec) { $f.SecretValues[[string]$s.name] = @{ name = [string]$s.name }; foreach ($p in $s.PSObject.Properties) { $f.SecretValues[[string]$s.name][$p.Name] = $p.Value } }
                $cfg = $b.properties.configuration
                $cfg.secrets = @($sec | ForEach-Object { $x = [ordered]@{ name = $_.name }; if ($_.PSObject.Properties['keyVaultUrl']) { $x.keyVaultUrl = $_.keyVaultUrl; $x.identity = $_.identity }; [pscustomobject]$x })
                $f.App.properties.configuration = $cfg
                if ($b.properties.PSObject.Properties['template']) { $f.App.properties.template = $b.properties.template }
                return $null
            }
            throw "unexpected ARM $Method $Path"
        }.GetNewClosure()
    }

    function script:Get-FakeGraph($f) {
        # (a closure has a scope of its own: the ids go in as locals)
        $prin = $script:MiPrin; $ten = $script:Tenant; $rid = $script:RegId
        {
            param([string]$Method, [string]$Uri, $Body)
            $f.Calls.Add([pscustomobject]@{ Kind = 'graph'; Method = $Method; Path = $Uri; Body = $(if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 30 | ConvertFrom-Json } else { $null }); Json = '' })
            if ($Method -eq 'PATCH') {
                if ($f.GraphPatchRefused) { throw 'HTTP 403: Authorization_RequestDenied: Insufficient privileges to complete the operation.' }
                $f.Uris = @($Body.web.redirectUris)
                if (-not $f.IgSticksOff -and $Body.web.Contains('implicitGrantSettings')) { $f.Ig = [pscustomobject]$Body.web.implicitGrantSettings }
                return $null
            }
            if ($Uri -like '*federatedIdentityCredentials*') {
                if ($f.NoFic) { return [pscustomobject]@{ value = @() } }
                return [pscustomobject]@{ value = @([pscustomobject]@{ name = "si-web-$prin"; issuer = "https://login.microsoftonline.com/$ten/v2.0"; subject = $prin; audiences = @('api://AzureADTokenExchange') }) }
            }
            $w = [ordered]@{ redirectUris = @($f.Uris); logoutUrl = 'https://x/signout-callback-oidc' }
            if ($null -ne $f.Ig) { $w['implicitGrantSettings'] = $f.Ig }
            return [pscustomobject]@{ id = $rid; web = [pscustomobject]$w }
        }.GetNewClosure()
    }

    function script:Get-FakeProbe($f) {
        {
            param([string]$Url)
            $f.Probes.Add($Url)
            if ($Url -like '*/.auth/login/aad') { return [pscustomobject]@{ Status = 302; Location = 'https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=x' } }
            $on = $false; foreach ($e in @($f.App.properties.template.containers[0].env)) { if ($e.name -eq 'SI_Web_BuiltInAuth') { $on = $true } }
            if ($f.FailAfterSwitch -and $on) { return [pscustomobject]@{ Status = 200; Location = '' } }
            [pscustomobject]@{ Status = $f.ProbeStatus; Location = $f.ProbeLocation }
        }.GetNewClosure()
    }

    function script:Invoke-Converge($f, [string]$Mode, [switch]$Magic) {
        Invoke-SIBuiltInAuthConverge -Arm (Get-FakeArm $f) -Graph (Get-FakeGraph $f) -Probe (Get-FakeProbe $f) -Mode $Mode -AppId $script:AppId -MagicLinksOn:$Magic -Sleep { param($s) } -Tries 2 -ProbeTries 2 -NewGuid { '11111111-0000-0000-0000-000000000001' }
    }

    function script:Get-Writes($f) { @($f.Calls | Where-Object { $_.Method -in 'PUT', 'PATCH', 'DELETE' -or ($_.Method -eq 'POST' -and $_.Path -notlike '*/listSecrets*') }) }
    function script:Get-AppPatches($f) { @($f.Calls | Where-Object { $_.Kind -eq 'arm' -and $_.Method -eq 'PATCH' }) }
}

Describe 'the authConfig body' {
    It 'asks for SecurityInsight''s own API scope at sign-in (proven at internal), and the read-back check covers it' {
        $b = Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client
        $lp = @($b.properties.identityProviders.azureActiveDirectory.login.loginParameters)
        $lp | Should -Be @(('scope=openid profile email offline_access api://{0}/user_impersonation' -f $script:Client.ToLowerInvariant()), 'prompt=select_account') -Because 'the account picker always shows (admins sign in with a separate admin account)'
        $cur = $b | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        (Test-SIBuiltInAuthConfigMatches -Current $cur -Want $b).Ok | Should -BeTrue
        $cur.properties.identityProviders.azureActiveDirectory.login.loginParameters = @('scope=openid')
        $m = Test-SIBuiltInAuthConfigMatches -Current $cur -Want $b
        $m.Ok | Should -BeFalse
        @($m.Diff) | Should -Contain 'azureActiveDirectory.login.loginParameters'
    }
    It 'is secretless and complete: the lowercase secret name, the v2.0 issuer, both audiences, a fixed 8-hour session, HTTPS only' {
        $b = Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client
        $j = $b | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $p = $j.properties
        $p.platform.enabled | Should -BeTrue
        $p.globalValidation.unauthenticatedClientAction | Should -Be 'RedirectToLoginPage'
        $p.globalValidation.redirectToProvider | Should -Be 'azureactivedirectory'
        $p.globalValidation.PSObject.Properties['excludedPaths'] | Should -BeNullOrEmpty
        $a = $p.identityProviders.azureActiveDirectory
        $a.enabled | Should -BeTrue
        $a.registration.clientId | Should -Be $script:Client
        $a.registration.clientSecretSettingName | Should -BeExactly 'override-use-mi-fic-assertion-client-id'
        $a.registration.openIdIssuer | Should -Be "https://login.microsoftonline.com/$($script:Tenant)/v2.0"
        @($a.validation.allowedAudiences) | Should -Be @("api://$($script:Client)", $script:Client)
        $p.login.cookieExpiration.convention | Should -Be 'FixedTime'
        $p.login.cookieExpiration.timeToExpiration | Should -Be '08:00:00'
        $p.httpSettings.requireHttps | Should -BeTrue
    }
    It 'the token store: ON in the blob container with the managed identity -- never a SAS URL or a key; off without them; on without them throws' {
        $b = Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client -TokenStoreContainerUri 'https://stsitest.blob.core.windows.net/si-auth-tokens' -TokenStoreIdentityResourceId $script:MiId
        $t = $b.properties.login.tokenStore
        $t.enabled | Should -BeTrue
        $t.azureBlobStorage.blobContainerUri | Should -Be 'https://stsitest.blob.core.windows.net/si-auth-tokens'
        $t.azureBlobStorage.managedIdentityResourceId | Should -Be $script:MiId
        $t.azureBlobStorage.Contains('sasUrlSettingName') | Should -BeFalse
        ($b | ConvertTo-Json -Depth 20) | Should -Not -Match '(?i)sasUrl|sig=|AccountKey|ConnectionString'
        (Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client).properties.login.tokenStore.enabled | Should -BeFalse
        { Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client -TokenStore $true } | Should -Throw
    }
    It 'names /MagicLink and /MagicLinkRequest as excluded paths ONLY when magic links are on' {
        $on = (Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client -MagicLinksOn).properties.globalValidation
        @($on.excludedPaths) | Should -Be @('/MagicLink', '/MagicLinkRequest')
        (Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client).properties.globalValidation.Contains('excludedPaths') | Should -BeFalse
    }
    It 'every value is a parameter (the live proof may change them)' {
        $b = Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client -CookieConvention 'IdentityProviderDerived' -CookieTimeToExpiration '04:00:00' -UnauthenticatedClientAction 'Return401' -AllowedAudiences @('x') -OpenIdIssuer 'https://iss' -SecretSettingName 'other'
        $b.properties.login.cookieExpiration.convention | Should -Be 'IdentityProviderDerived'
        $b.properties.login.cookieExpiration.timeToExpiration | Should -Be '04:00:00'
        $b.properties.globalValidation.unauthenticatedClientAction | Should -Be 'Return401'
        @($b.properties.identityProviders.azureActiveDirectory.validation.allowedAudiences) | Should -Be @('x')
        $b.properties.identityProviders.azureActiveDirectory.registration.openIdIssuer | Should -Be 'https://iss'
        $b.properties.identityProviders.azureActiveDirectory.registration.clientSecretSettingName | Should -Be 'other'
    }
    It 'the read-back compare sees a difference and none on the same body' {
        $w = Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client -TokenStoreContainerUri 'https://a/b' -TokenStoreIdentityResourceId $script:MiId
        (Test-SIBuiltInAuthConfigMatches -Current ($w | ConvertTo-Json -Depth 20 | ConvertFrom-Json) -Want $w).Ok | Should -BeTrue
        $m = Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client -MagicLinksOn
        $r = Test-SIBuiltInAuthConfigMatches -Current ($m | ConvertTo-Json -Depth 20 | ConvertFrom-Json) -Want $w
        $r.Ok | Should -BeFalse
        $r.Diff | Should -Contain 'globalValidation.excludedPaths'
        $r.Diff | Should -Contain 'login.tokenStore.azureBlobStorage.blobContainerUri'
        (Test-SIBuiltInAuthConfigMatches -Current $null -Want $w).Ok | Should -BeFalse
    }
}

Describe 'the secret, the setting and the switch' {
    It 'keeps EVERY existing secret (plain values and Key Vault references) and adds the identity''s client id under the lowercase name' {
        $f = New-Fake
        $p = Get-SIBuiltInAuthSecretPatch -App $f.App -IdentityClientId $script:MiCid.ToUpperInvariant() -SecretValues $f.SecretValues -Setting keep
        $p.MissingSecrets | Should -BeNullOrEmpty
        $p.Changed | Should -BeTrue
        $s = @($p.Body.properties.configuration.secrets)
        $s.Count | Should -Be 3
        ($s | Where-Object { $_.name -eq 'sql-pw' }).value | Should -Be 'p@ss'
        ($s | Where-Object { $_.name -eq 'kv-ref' }).keyVaultUrl | Should -Be 'https://kv.vault.azure.net/secrets/a'
        ($s | Where-Object { $_.name -eq 'kv-ref' }).identity | Should -Be $script:MiId
        ($s | Where-Object { $_.name -ceq 'override-use-mi-fic-assertion-client-id' }).value | Should -Be $script:MiCid
        $p.Body.properties.Contains('template') | Should -BeFalse
        $p.Body.properties.configuration.ingress.targetPort | Should -Be 9000
    }
    It 'a secret whose value cannot be read is reported and the caller stops (it would be blanked)' {
        $f = New-Fake
        $f.SecretValues.Remove('sql-pw')
        $p = Get-SIBuiltInAuthSecretPatch -App $f.App -IdentityClientId $script:MiCid -SecretValues $f.SecretValues
        $p.MissingSecrets | Should -Be @('sql-pw')
    }
    It 'THE SWITCH is one body: the setting on the web container, the front container out, the ingress on 8080 with every other field kept' {
        $f = New-Fake
        $p = Get-SIBuiltInAuthSecretPatch -App $f.App -IdentityClientId $script:MiCid -SecretValues $f.SecretValues -Setting on -RemoveFront -WebPort 8080
        $p.Changed | Should -BeTrue
        $cs = @($p.Body.properties.template.containers)
        $cs.Count | Should -Be 1
        $cs[0].name | Should -Be 'si-management'
        (@($cs[0].env) | Where-Object { $_.name -eq 'SI_Web_BuiltInAuth' }).value | Should -Be '1'
        # the web container's own settings are left alone
        @($cs[0].env | Where-Object { $_.name -in 'AzureAd__ClientId', 'SI_Web_SigninFront', 'SIGNIN_UPSTREAM_PORT' }).Count | Should -Be 3
        $p.Body.properties.template.Contains('revisionSuffix') | Should -BeFalse
        $p.Body.properties.template.scale.maxReplicas | Should -Be 1
        $ing = $p.Body.properties.configuration.ingress
        $ing.targetPort | Should -Be 8080
        $before = $f.App.properties.configuration.ingress
        foreach ($k in 'fqdn', 'external', 'transport', 'allowInsecure') { $ing[$k] | Should -Be $before.$k -Because $k }
        ($ing.ipSecurityRestrictions | ConvertTo-Json -Depth 10 -Compress) | Should -Be ($before.ipSecurityRestrictions | ConvertTo-Json -Depth 10 -Compress)
        ($ing.customDomains | ConvertTo-Json -Depth 10 -Compress) | Should -Be ($before.customDomains | ConvertTo-Json -Depth 10 -Compress)
        ($ing.stickySessions | ConvertTo-Json -Depth 10 -Compress) | Should -Be ($before.stickySessions | ConvertTo-Json -Depth 10 -Compress)
        (Test-SIBuiltInAuthSwitched -App ($p.Body | ConvertTo-Json -Depth 30 | ConvertFrom-Json)).Ok | Should -BeTrue
    }
    It 'the web app''s identity is id-si-web, with its resource id' {
        $i = Get-SIBuiltInAuthWebIdentity -App (New-FakeApp)
        $i.ClientId | Should -Be $script:MiCid
        $i.PrincipalId | Should -Be $script:MiPrin
        $i.ResourceId | Should -Be $script:MiId
    }
}

Describe 'redirect URIs, the federated credential, the probes, the data right' {
    It 'only ever adds: the callback per host, existing ones kept, no duplicate (case ignored)' {
        $r = Get-SIBuiltInAuthRedirectUris -Existing @('https://a/signin-oidc', 'HTTPS://APP.EXAMPLE/.auth/login/aad/callback') -Fqdn 'app.example' -CustomDomains @('si.contoso.com', 'https://si.contoso.com/')
        $r.Uris | Should -Be @('https://a/signin-oidc', 'HTTPS://APP.EXAMPLE/.auth/login/aad/callback', 'https://si.contoso.com/.auth/login/aad/callback')
        $r.Added | Should -Be @('https://si.contoso.com/.auth/login/aad/callback')
        (Get-SIBuiltInAuthRedirectUris -Existing @() -Fqdn 'x.io').Uris | Should -Be @('https://x.io/.auth/login/aad/callback')
    }
    It 'the federated credential must be exactly the tenant issuer, the PRINCIPAL id and the token-exchange audience' {
        $ok = [pscustomobject]@{ issuer = "https://login.microsoftonline.com/$($script:Tenant)/v2.0/"; subject = $script:MiPrin.ToUpperInvariant(); audiences = @('api://AzureADTokenExchange') }
        Test-SIBuiltInAuthFic -Credentials @($ok) -TenantId $script:Tenant -PrincipalId $script:MiPrin | Should -BeTrue
        Test-SIBuiltInAuthFic -Credentials @([pscustomobject]@{ issuer = $ok.issuer; subject = $script:MiCid; audiences = $ok.audiences }) -TenantId $script:Tenant -PrincipalId $script:MiPrin | Should -BeFalse
        Test-SIBuiltInAuthFic -Credentials @([pscustomobject]@{ issuer = $ok.issuer; subject = $script:MiPrin; audiences = @('api://other') }) -TenantId $script:Tenant -PrincipalId $script:MiPrin | Should -BeFalse
        Test-SIBuiltInAuthFic -Credentials @([pscustomobject]@{ issuer = 'https://sts.windows.net/x/'; subject = $script:MiPrin; audiences = $ok.audiences }) -TenantId $script:Tenant -PrincipalId $script:MiPrin | Should -BeFalse
        Test-SIBuiltInAuthFic -Credentials @() -TenantId $script:Tenant -PrincipalId $script:MiPrin | Should -BeFalse
    }
    It 'refused = 401 / 403 or a redirect to the sign-in; a 200 with the page is NOT refused; /.auth/login/aad must send to Entra' {
        Test-SIBuiltInAuthAnonymousRefused -Probe ([pscustomobject]@{ Status = 401; Location = '' }) | Should -BeTrue
        Test-SIBuiltInAuthAnonymousRefused -Probe ([pscustomobject]@{ Status = 302; Location = '/.auth/login/aad?post_login_redirect_uri=/' }) | Should -BeTrue
        Test-SIBuiltInAuthAnonymousRefused -Probe ([pscustomobject]@{ Status = 302; Location = 'https://login.microsoftonline.com/t/oauth2' }) | Should -BeTrue
        Test-SIBuiltInAuthAnonymousRefused -Probe ([pscustomobject]@{ Status = 200; Location = '' }) | Should -BeFalse
        Test-SIBuiltInAuthAnonymousRefused -Probe ([pscustomobject]@{ Status = 302; Location = 'https://evil.example/' }) | Should -BeFalse
        Test-SIBuiltInAuthAnonymousRefused -Probe ([pscustomobject]@{ Status = 0; Location = '' }) | Should -BeFalse
        Test-SIBuiltInAuthLoginAnswers -Probe ([pscustomobject]@{ Status = 302; Location = 'https://login.microsoftonline.com/t/oauth2/v2.0/authorize' }) | Should -BeTrue
        Test-SIBuiltInAuthLoginAnswers -Probe ([pscustomobject]@{ Status = 404; Location = '' }) | Should -BeFalse
    }
    It 'the data right counts at the container or above it, for that principal and Blob Data Contributor / Owner only' {
        $mk = { param($p, $r, $s) [pscustomobject]@{ properties = [pscustomobject]@{ principalId = $p; roleDefinitionId = "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/$r"; scope = $s } } }
        Test-SIBuiltInAuthBlobRole -Assignments @(& $mk $script:MiPrin 'ba92f5b4-2d11-453d-a403-e96b0029c9fe' $script:CScope) -PrincipalId $script:MiPrin -ContainerScope $script:CScope | Should -BeTrue
        Test-SIBuiltInAuthBlobRole -Assignments @(& $mk $script:MiPrin 'ba92f5b4-2d11-453d-a403-e96b0029c9fe' $script:AcctId) -PrincipalId $script:MiPrin -ContainerScope $script:CScope | Should -BeTrue
        Test-SIBuiltInAuthBlobRole -Assignments @(& $mk $script:MiPrin '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1' $script:CScope) -PrincipalId $script:MiPrin -ContainerScope $script:CScope | Should -BeFalse
        Test-SIBuiltInAuthBlobRole -Assignments @(& $mk $script:MiCid 'ba92f5b4-2d11-453d-a403-e96b0029c9fe' $script:CScope) -PrincipalId $script:MiPrin -ContainerScope $script:CScope | Should -BeFalse
        Test-SIBuiltInAuthBlobRole -Assignments @(& $mk $script:MiPrin 'ba92f5b4-2d11-453d-a403-e96b0029c9fe' ($script:AcctId + '/blobServices/default/containers/other')) -PrincipalId $script:MiPrin -ContainerScope $script:CScope | Should -BeFalse
    }
}

Describe 'the converge' {
    It 'mode off makes not a single call' {
        $f = New-Fake
        $r = Invoke-Converge $f 'off'
        $r.Ok | Should -BeTrue; $r.State | Should -Be 'off'
        $f.Calls.Count | Should -Be 0; $f.Probes.Count | Should -Be 0
    }
    It 'plan reads and says what would change (the port, the front container) -- nothing is written' {
        $f = New-Fake -NoContainer
        $r = Invoke-Converge $f 'plan'
        $r.State | Should -Be 'planned'
        @(Get-Writes $f).Count | Should -Be 0
        $t = $r.Lines -join ' '
        $t | Should -Match '/\.auth/login/aad/callback'
        $t | Should -Match 'move the ingress from port 9000 to 8080'
        $t | Should -Match 'take the sign-in front container signin-front out'
        $t | Should -Match 'would create the blob container si-auth-tokens'
        $t | Should -Match 'Support-app step'
        $t | Should -Match 'nothing was changed'
    }
    It 'the updater gets no new right: a REFUSED app-registration write is a support step -- nothing switches on, nothing throws' {
        foreach ($mode in 'redirect-only', 'apply') {
            $f = New-Fake -GraphPatchRefused
            $r = Invoke-Converge $f $mode
            $why = "$mode -> state '$($r.State)'; lines: $(@($r.Lines) -join ' || '); support: $(@($r.Support) -join ' || '); trace: $($r.Trace); graph calls: $(@($f.Calls | Where-Object Kind -eq 'graph' | ForEach-Object { $_.Method + ' ' + $_.Path }) -join ', ')"
            $r.State | Should -Be 'needs-support' -Because $why
            $r.Ok | Should -BeFalse -Because $why
            @($r.Support | Where-Object { $_ -match 'add the redirect URI .*/\.auth/login/aad/callback.* switch ID-token issuance ON' }).Count | Should -Be 1 -Because $why
            @(Get-Writes $f | Where-Object { $_.Kind -eq 'arm' }).Count | Should -Be 0 -Because "$mode must not touch the web app when the registration could not be written; $why"
        }
    }
    It 'redirect writes ONLY the redirect URI (the existing one kept), read back' {
        $f = New-Fake
        $r = Invoke-Converge $f 'redirect-only'
        $r.Ok | Should -BeTrue; $r.State | Should -Be 'redirect-added'
        $w = @(Get-Writes $f)
        $w.Count | Should -Be 1
        $w[0].Kind | Should -Be 'graph'; $w[0].Method | Should -Be 'PATCH'
        $f.Uris | Should -Contain 'https://ca-si-management.happy.westeurope.azurecontainerapps.io/signin-oidc'
        $f.Uris | Should -Contain $script:Callback
        $f.Uris | Should -Contain 'https://si.contoso.com/.auth/login/aad/callback'
        $w[0].Body.web.logoutUrl | Should -Be 'https://x/signout-callback-oidc'
        $f.Calls.Clear()
        (Invoke-Converge $f 'redirect-only').State | Should -Be 'in-place'
        @(Get-Writes $f).Count | Should -Be 0
    }
    It 'apply: secret, authConfig (with the token store), probe, then THE SWITCH in one PATCH, probes again -- each read back' {
        $f = New-Fake
        $r = Invoke-Converge $f 'apply'
        $r.Ok | Should -BeTrue
        $r.State | Should -Be 'applied'
        $w = @(Get-Writes $f | Where-Object { $_.Kind -eq 'arm' })
        $w.Count | Should -Be 3
        $w[0].Method | Should -Be 'PATCH'; $w[0].Body.properties.PSObject.Properties['template'] | Should -BeNullOrEmpty
        $w[1].Method | Should -Be 'PUT'; $w[1].Path | Should -BeLike '*/authConfigs/current?api-version=2024-10-02-preview'
        $w[1].Body.properties.login.tokenStore.enabled | Should -BeTrue
        $w[1].Body.properties.login.tokenStore.azureBlobStorage.blobContainerUri | Should -Be 'https://stsitest.blob.core.windows.net/si-auth-tokens'
        $w[1].Body.properties.login.tokenStore.azureBlobStorage.managedIdentityResourceId | Should -Be $script:MiId
        # THE SWITCH: one PATCH -- the setting, no front container, the web port
        $w[2].Method | Should -Be 'PATCH'
        @($w[2].Body.properties.template.containers).Count | Should -Be 1
        @($w[2].Body.properties.template.containers)[0].name | Should -Be 'si-management'
        (@(@($w[2].Body.properties.template.containers)[0].env) | Where-Object { $_.name -eq 'SI_Web_BuiltInAuth' }).value | Should -Be '1'
        $w[2].Body.properties.configuration.ingress.targetPort | Should -Be 8080
        (Test-SIBuiltInAuthSwitched -App $f.App).Ok | Should -BeTrue
        # the ingress keeps every other field
        $ing = $f.App.properties.configuration.ingress
        $ing.external | Should -BeTrue; $ing.transport | Should -Be 'auto'
        $ing.ipSecurityRestrictions[0].ipAddressRange | Should -Be '203.0.113.0/24'
        $ing.customDomains[0].name | Should -Be 'si.contoso.com'
        $ing.stickySessions.affinity | Should -Be 'sticky'
        $f.SecretValues['override-use-mi-fic-assertion-client-id'].value | Should -Be $script:MiCid
        $f.SecretValues.ContainsKey('sql-pw') | Should -BeTrue
        $f.SecretValues['kv-ref'].keyVaultUrl | Should -Be 'https://kv.vault.azure.net/secrets/a'
        # probed before AND after the switch, and the platform's sign-in answered
        @($f.Probes | Where-Object { $_ -eq "https://$($script:Fqdn)/" }).Count | Should -BeGreaterOrEqual 2
        $f.Probes | Should -Contain "https://$($script:Fqdn)/.auth/login/aad"
        # no SAS, no key, no connection string in anything written
        foreach ($c in $f.Calls) { "$($c.Json)" | Should -Not -Match '(?i)sasUrl|sig=|AccountKey|ConnectionString' }
        # the next run: in place, no write
        $f.Calls.Clear()
        (Invoke-Converge $f 'apply').State | Should -Be 'in-place'
        @(Get-Writes $f).Count | Should -Be 0
    }
    It 'apply right after an image roll: a web app still busy is waited for, and a 409 "operation in progress" is tried again (live 2026-11-14)' {
        $f = New-Fake -BusyStates 3 -Busy409 2
        $r = Invoke-Converge $f 'apply'
        $why = "state '$($r.State)'; lines: $(@($r.Lines) -join ' || '); trace: $($r.Trace)"
        $r.State | Should -Be 'applied' -Because $why
        $r.Ok | Should -BeTrue -Because $why
        $f.Answered409 | Should -Be 2
        Test-SIBuiltInAuthSwitched -App $f.App | Select-Object -ExpandProperty Ok | Should -BeTrue
    }
    It 'a 409 that never clears is a failure (bounded), never an endless wait' {
        $f = New-Fake -Busy409 1000
        $r = Invoke-SIBuiltInAuthConverge -Arm (Get-FakeArm $f) -Graph (Get-FakeGraph $f) -Probe (Get-FakeProbe $f) -Mode apply -AppId $script:AppId -Sleep { param($s) } -Tries 2 -ProbeTries 2 -BusyTries 4 -NewGuid { '11111111-0000-0000-0000-000000000001' }
        $r.Ok | Should -BeFalse
        $f.Answered409 | Should -BeLessOrEqual 4
        (Get-SIBuiltInAuthSetting -App $f.App) | Should -Not -Be '1' -Because 'the switch never happened'
    }
    It 'the account picker is always asked for, also next to a caller''s own login parameters' {
        $b = Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client -LoginParameters @('scope=openid', 'prompt=login')
        @($b.properties.identityProviders.azureActiveDirectory.login.loginParameters) | Should -Be @('scope=openid', 'prompt=select_account')
    }
    It 'apply with magic links on writes the excluded paths' {
        $f = New-Fake
        (Invoke-Converge $f 'apply' -Magic).State | Should -Be 'applied'
        @($f.Auth.properties.globalValidation.excludedPaths) | Should -Be @('/MagicLink', '/MagicLinkRequest')
    }
    It 'the token store''s container is created when missing (no public access), read back' {
        $f = New-Fake -NoContainer
        (Invoke-Converge $f 'apply').State | Should -Be 'applied'
        $put = @($f.Calls | Where-Object { $_.Method -eq 'PUT' -and $_.Path -like '*/blobServices/default/containers/si-auth-tokens*' })
        $put.Count | Should -Be 1
        $put[0].Body.properties.publicAccess | Should -Be 'None'
    }
    It 'a missing data right on the container: ONE try; refused = a Support-app step and NOTHING switches on' {
        $f = New-Fake -NoRole -RolePutRefused -Uris @($script:Callback, 'https://si.contoso.com/.auth/login/aad/callback')
        $r = Invoke-Converge $f 'apply'
        $r.Ok | Should -BeFalse; $r.State | Should -Be 'needs-support'
        @($f.Calls | Where-Object { $_.Method -eq 'PUT' -and $_.Path -like '*roleAssignments/*' }).Count | Should -Be 1
        @($f.Calls | Where-Object { $_.Path -like '*/authConfigs/*' -and $_.Method -ne 'GET' }).Count | Should -Be 0
        @(Get-AppPatches $f).Count | Should -Be 0
        ($r.Lines -join ' ') | Should -Match 'Support-app step.*Storage Blob Data Contributor on the blob container si-auth-tokens'
        @($r.Support | Where-Object { $_ -match 'id-si-web Storage Blob Data Contributor' }).Count | Should -Be 1
    }
    It 'a missing data right the updater MAY add: added at the container scope, read back, then switched on' {
        $f = New-Fake -NoRole
        (Invoke-Converge $f 'apply').State | Should -Be 'applied'
        $rp = @($f.Calls | Where-Object { $_.Method -eq 'PUT' -and $_.Path -like '*roleAssignments/*' })
        $rp.Count | Should -Be 1
        $rp[0].Path | Should -BeLike ($script:CScope + '/providers/Microsoft.Authorization/roleAssignments/*')
        $rp[0].Body.properties.roleDefinitionId | Should -BeLike '*/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe'
        $rp[0].Body.properties.principalId | Should -Be $script:MiPrin
    }
    It 'shared-key access left on is SAID as a Support-app step, never changed here' {
        $f = New-Fake -SharedKey $true
        $r = Invoke-Converge $f 'apply'
        $r.State | Should -Be 'applied'
        ($r.Lines -join ' ') | Should -Match 'shared-key access OFF on the storage account stsitest'
        @($f.Calls | Where-Object { $_.Path -like '*storageAccounts/stsitest?*' -and $_.Method -ne 'GET' }).Count | Should -Be 0
    }
    It 'apply ROLLS BACK when a request without a sign-in gets the page before the switch: the platform off, the app never switched' {
        $f = New-Fake -ProbeStatus 200 -ProbeLocation ''
        $r = Invoke-Converge $f 'apply'
        $r.Ok | Should -BeFalse
        $r.State | Should -Be 'rolled-back'
        $f.Auth.properties.platform.enabled | Should -BeFalse
        (Get-SIBuiltInAuthSetting -App $f.App) | Should -Be ''
        (Get-SIBuiltInAuthFrontContainer -App $f.App) | Should -Not -BeNullOrEmpty
        ($r.Lines -join ' ') | Should -Match 'NOT switched on'
        ($r.Lines -join ' ') | Should -Match 'switched off again'
        $puts = @($f.Calls | Where-Object { $_.Method -eq 'PUT' -and $_.Path -like '*/authConfigs/*' })
        $puts.Count | Should -Be 2
        $puts[-1].Body.properties.platform.enabled | Should -BeFalse
    }
    It 'a failure AFTER the switch puts back the port and the front container byte-for-byte, the setting off, then the sign-in' {
        $f = New-Fake -FailAfterSwitch
        $frontBefore = (Get-SIBuiltInAuthFrontContainer -App $f.App) | ConvertTo-Json -Depth 30 -Compress
        $ingBefore = $f.App.properties.configuration.ingress | ConvertTo-Json -Depth 30 -Compress
        $r = Invoke-Converge $f 'apply'
        $r.State | Should -Be 'rolled-back'
        $f.App.properties.configuration.ingress.targetPort | Should -Be 9000
        ((Get-SIBuiltInAuthFrontContainer -App $f.App) | ConvertTo-Json -Depth 30 -Compress) | Should -BeExactly $frontBefore
        ($f.App.properties.configuration.ingress | ConvertTo-Json -Depth 30 -Compress) | Should -BeExactly $ingBefore
        (Get-SIBuiltInAuthSetting -App $f.App) | Should -Be ''
        $f.Auth.properties.platform.enabled | Should -BeFalse
        # the order: the web app is put back BEFORE the sign-in configuration
        $i = 0; $iApp = -1; $iAuth = -1
        foreach ($c in $f.Calls) { if ($c.Method -eq 'PATCH') { $iApp = $i }; if ($c.Method -eq 'PUT' -and $c.Path -like '*/authConfigs/*') { $iAuth = $i }; $i++ }
        $iApp | Should -BeLessThan $iAuth
        ($r.Lines -join ' ') | Should -Match 'put back as it ran before -- the ingress on port 9000, the sign-in front container as it was'
        # every secret survived the way back
        $f.SecretValues.ContainsKey('sql-pw') | Should -BeTrue
        $f.SecretValues['kv-ref'].keyVaultUrl | Should -Be 'https://kv.vault.azure.net/secrets/a'
    }
    It 'a rollback with a working sign-in before puts THAT back, not an empty one' {
        $before = (Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client -MagicLinksOn) | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $f = New-Fake -Auth $before -WithSetting -WithOurSecret -ProbeStatus 200 -ProbeLocation ''
        $r = Invoke-Converge $f 'apply'
        $r.State | Should -Be 'rolled-back'
        $f.Auth.properties.platform.enabled | Should -BeTrue
        @($f.Auth.properties.globalValidation.excludedPaths) | Should -Be @('/MagicLink', '/MagicLinkRequest')
        (Get-SIBuiltInAuthSetting -App $f.App) | Should -Be '1'
    }
    It 'apply without the federated credential writes nothing to the app and names a Support-app step' {
        $f = New-Fake -NoFic -Uris @($script:Callback, 'https://si.contoso.com/.auth/login/aad/callback')
        $r = Invoke-Converge $f 'apply'
        $r.Ok | Should -BeFalse; $r.State | Should -Be 'needs-support'
        @(Get-Writes $f).Count | Should -Be 0
        ($r.Lines -join ' ') | Should -Match 'Support-app step'
    }
    It 'apply stops before any write when an existing secret cannot be read' {
        $f = New-Fake -Uris @($script:Callback, 'https://si.contoso.com/.auth/login/aad/callback')
        $f.SecretValues.Remove('sql-pw')
        $r = Invoke-Converge $f 'apply'
        ($r.Lines -join ' ') | Should -Match 'sql-pw' -Because ("TRACE: " + $r.Trace)
        $r.State | Should -Be 'failed'
        @(Get-Writes $f).Count | Should -Be 0
    }
    It 'a failed authConfig write never throws and puts back' {
        $f = New-Fake -PutFails -Uris @($script:Callback)
        { Invoke-Converge $f 'apply' } | Should -Not -Throw
        (Invoke-Converge (New-Fake -PutFails) 'apply').Ok | Should -BeFalse
    }
}

Describe 'ID tokens on the sign-in app registration (the platform asks for "code id_token")' {
    It 'the PATCH body SETS ID-token issuance on and access-token issuance off, keeps the sign-out address, takes the new URIs' {
        $b = Get-SIBuiltInAuthAppWebPatch -Web ([pscustomobject]@{ redirectUris = @('https://a/x'); logoutUrl = 'https://a/out'; homePageUrl = 'https://a/'; implicitGrantSettings = [pscustomobject]@{ enableIdTokenIssuance = $false; enableAccessTokenIssuance = $true } }) -RedirectUris @('https://a/x', $script:Callback)
        $b.web.implicitGrantSettings.enableIdTokenIssuance | Should -BeTrue
        $b.web.implicitGrantSettings.enableAccessTokenIssuance | Should -BeFalse
        @($b.web.redirectUris) | Should -Be @('https://a/x', $script:Callback)
        $b.web.logoutUrl | Should -Be 'https://a/out'
        $b.web.homePageUrl | Should -Be 'https://a/'
        (Get-SIBuiltInAuthAppWebPatch -Web $null -RedirectUris @()).web.implicitGrantSettings.enableIdTokenIssuance | Should -BeTrue
        Test-SIBuiltInAuthIdTokenIssuance -Web ([pscustomobject]@{ implicitGrantSettings = [pscustomobject]@{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } }) | Should -BeTrue
        Test-SIBuiltInAuthIdTokenIssuance -Web ([pscustomobject]@{ implicitGrantSettings = [pscustomobject]@{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $true } }) | Should -BeFalse
        Test-SIBuiltInAuthIdTokenIssuance -Web ([pscustomobject]@{ redirectUris = @() }) | Should -BeFalse
    }
    It 'ID-token issuance off: redirect and apply switch it on in the same write, read back' {
        $f = New-Fake -Ig @{ enableIdTokenIssuance = $false; enableAccessTokenIssuance = $false } -Uris @($script:Callback, 'https://si.contoso.com/.auth/login/aad/callback')
        $r = Invoke-Converge $f 'redirect-only'
        $r.Ok | Should -BeTrue
        $g = @(Get-Writes $f | Where-Object { $_.Kind -eq 'graph' })
        $g.Count | Should -Be 1
        $g[0].Body.web.implicitGrantSettings.enableIdTokenIssuance | Should -BeTrue
        $g[0].Body.web.implicitGrantSettings.enableAccessTokenIssuance | Should -BeFalse
        $f.Ig.enableIdTokenIssuance | Should -BeTrue
        ($r.Lines -join ' ') | Should -Match 'issues ID tokens'
        (Invoke-Converge (New-Fake -Ig $null) 'apply').State | Should -Be 'applied'
    }
    It 'when it does not read back ON, plan says it and apply REFUSES to switch on (a Support-app step)' {
        $f = New-Fake -Ig @{ enableIdTokenIssuance = $false; enableAccessTokenIssuance = $false } -IgSticksOff
        ($( Invoke-Converge $f 'plan' ).Lines -join ' ') | Should -Match 'switch ID-token issuance ON'
        $f.Calls.Clear()
        $r = Invoke-Converge $f 'apply'
        $r.Ok | Should -BeFalse; $r.State | Should -Be 'needs-support'
        ($r.Lines -join ' ') | Should -Match 'Support-app step.*ID-token issuance ON'
        @($f.Calls | Where-Object { $_.Path -like '*/authConfigs/*' -and $_.Method -ne 'GET' }).Count | Should -Be 0
        @(Get-AppPatches $f).Count | Should -Be 0
    }
    It 'no SI code path that PATCHes an application''s web turns ID-token issuance off or leaves it out' {
        $files = @('pro-management\deploy\New-SIManagementAppRegistration.ps1', 'container\updater\_shared\SI-UpdaterWebApp.ps1',
                   'setup\_shared\SI-PrivateNetwork.ps1', 'setup\Set-SIPrivateNetworking.ps1', 'setup\_shared\SI-BuiltInAuth.ps1')
        foreach ($rel in $files) {
            $t = Get-Content -Raw (Join-Path $script:SIRoot $rel)
            $t | Should -Not -Match '(?i)enableIdTokenIssuance\s*=\s*\$?false' -Because $rel
            $t | Should -Match '(?i)enableIdTokenIssuance' -Because "$rel writes the sign-in app registration's web"
        }
        # the two carry-through paths set it unconditionally (never only when it was read)
        (Get-Content -Raw (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterWebApp.ps1')) | Should -Match "\`$ig\['enableIdTokenIssuance'\] = \`$true\s+\`$w\['implicitGrantSettings'\] = \`$ig"
        (Get-Content -Raw (Join-Path $script:SIRoot 'setup\_shared\SI-PrivateNetwork.ps1')) | Should -Match "\`$igh\['enableIdTokenIssuance'\] = \`$true\s+\`$web\['implicitGrantSettings'\] = \`$igh"
        (Get-Content -Raw (Join-Path $script:SIRoot 'pro-management\deploy\New-SIManagementAppRegistration.ps1')) | Should -Match 'enableIdTokenIssuance = \$true; enableAccessTokenIssuance = \$false'
        # every product file that sends { web = ... } to an application is one of the files above
        $all = Get-ChildItem -Path $script:SIRoot -Recurse -Filter *.ps1 -File | Where-Object { $_.FullName -notmatch '[\\/]tests[\\/]' }
        foreach ($fi in $all) {
            $t = [IO.File]::ReadAllText($fi.FullName)
            if ($t -match "(?s)'PATCH'.{0,200}applications.{0,200}\bweb\s*=") {
                $rel = $fi.FullName.Substring($script:SIRoot.Length).TrimStart('\', '/') -replace '/', '\'
                $files | Should -Contain $rel -Because "$rel PATCHes an application's web"
            }
        }
    }
}

Describe 'the rights list and the installer' {
    It 'lists id-si-web''s Storage Blob Data Contributor on the token container only (a data right, allowed for an internet-facing identity)' {
        $j = Get-Content -Raw (Join-Path $script:SIRoot 'setup\_shared\si-identity-rights.json') | ConvertFrom-Json
        $web = @($j.identities | Where-Object { $_.role -eq 'web' })[0]
        $r = @($web.rights | Where-Object { $_.id -eq 'web.storage.BlobDataContributorAuthTokens' })
        $r.Count | Should -Be 1
        $r[0].roleDefinitionId | Should -Be 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
        $r[0].scope | Should -Match 'si-auth-tokens'
        $r[0].scope | Should -Match 'container scope only'
    }
    It 'the web app''s deploy makes the container and grants the right at the container scope (step 4f); the guided install passes the account' {
        $d = Get-Content -Raw (Join-Path $script:SIRoot 'pro-management\deploy\Deploy-SIManagement.ps1')
        $d | Should -Match '\[string\]\$AuthTokenStorageAccountName'
        $d | Should -Match "Grant-Role -PrincipalId \`$webId.PrincipalId -Role 'Storage Blob Data Contributor' -Scope \`$tokScope"
        $d | Should -Match "blobServices/default/containers/\{1\}' -f \`$tokAcct, \`$AuthTokenContainer"
        Get-Content -Raw (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstallData.ps1') | Should -Match 'AuthTokenStorageAccountName = \[string\]\$n\.StorageAccount'
    }
}

Describe 'the updater calls it -- OFF by default' {
    It 'Start-SIUpdater loads the library and calls the step after its web app steps' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')
        $src | Should -Match "'SI-BuiltInAuth\.ps1'"
        $body = (Get-Command Invoke-SIUpdaterWebAppStepsAfter).ScriptBlock.ToString()
        $body | Should -Match 'Invoke-SIUpdaterBuiltInAuthStep'
        $body.IndexOf('Invoke-SIUpdaterWebAppSteps -Env') | Should -BeLessThan $body.IndexOf('Invoke-SIUpdaterBuiltInAuthStep')
    }
    It 'unset / off = the converge is never called and no request is made' {
        $script:called = 0; $script:armCalls = 0
        $conv = { param($a) $script:called++ }
        $arm = { param($m, $p, $b) $script:armCalls++ }
        foreach ($v in @($null, '', 'off', 'OFF')) {
            $e = @{}; if ($null -ne $v) { $e['SI_Updater_BuiltInAuth'] = $v }
            $null = Invoke-SIUpdaterBuiltInAuthStep -Env $e -SubscriptionId 's' -ResourceGroup 'rg' -Converge $conv -Arm $arm -Graph $arm
        }
        $script:called | Should -Be 0
        $script:armCalls | Should -Be 0
    }
    It 'the job setting picks the mode: plan, redirect -> redirect-only, apply; an unknown word stays off' {
        $script:seen = New-Object System.Collections.Generic.List[string]
        $conv = { param($a) $script:seen.Add($a.Mode); [pscustomobject]@{ Ok = $true; State = 'in-place'; Lines = @() } }
        foreach ($v in 'plan', 'redirect', 'apply', 'yes') {
            $null = Invoke-SIUpdaterBuiltInAuthStep -Env @{ SI_Updater_BuiltInAuth = $v; SI_UPDATER_WEB_APP = 'ca-si-management' } -SubscriptionId 's' -ResourceGroup 'rg' -Converge $conv -Arm { } -Graph { }
        }
        @($script:seen) | Should -Be @('plan', 'redirect-only', 'apply')
    }
    It 'a failed update never reaches it' {
        $script:called = 0
        $null = Invoke-SIUpdaterBuiltInAuthStep -Rc 1 -Env @{ SI_Updater_BuiltInAuth = 'apply' } -SubscriptionId 's' -ResourceGroup 'rg' -Converge { param($a) $script:called++ } -Arm { } -Graph { }
        $script:called | Should -Be 0
    }
    It 'the web app''s ARM id and magic links (off without a database) reach the converge' {
        $script:got = $null
        $conv = { param($a) $script:got = $a; [pscustomobject]@{ Ok = $true; State = 'planned'; Lines = @('x') } }
        $null = Invoke-SIUpdaterBuiltInAuthStep -Env @{ SI_Updater_BuiltInAuth = 'plan'; SI_UPDATER_WEB_APP = 'ca-si-management' } -SubscriptionId 'sub1' -ResourceGroup 'rg1' -Converge $conv -Arm { } -Graph { }
        $script:got.AppId | Should -BeLike '/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.App/containerApps/*'
        $script:got.MagicLinksOn | Should -BeFalse
        Read-SIBuiltInAuthMagicLinks -Invoke { param($s, $p, $m) @(@{ ValueJson = 'true' }) } | Should -BeTrue
        Read-SIBuiltInAuthMagicLinks -Invoke { param($s, $p, $m) throw 'down' } | Should -BeFalse
    }
}

Describe 'after the switch: the sign-in keys leave Key Vault, then the web identity''s Key Vault rights go' {
    BeforeAll {
        $script:VaultId = $script:Rg + '/providers/Microsoft.KeyVault/vaults/kv-si'
        $script:BlobUri = 'https://stsitest.blob.core.windows.net/si-auth-tokens/dataprotection/keys.xml'
        $script:Crypto = '/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/e147488a-f6f5-4113-8e2d-b22465e65bf6'
        function script:New-RoleAssign([string]$Name, [string]$Principal, [string]$Scope, [string]$Role = $script:Crypto) {
            [pscustomobject]@{ id = "$Scope/providers/Microsoft.Authorization/roleAssignments/$Name"; properties = [pscustomobject]@{ principalId = $Principal; roleDefinitionId = $Role; scope = $Scope } }
        }
        function script:New-MoveFake {
            param([switch]$NotHealthy, [switch]$DeleteRefused, [switch]$ListRefused, [switch]$WithBlob)
            $app = New-FakeApp -Switched
            $app.properties | Add-Member -NotePropertyName latestRevisionName -NotePropertyValue 'ca-si-management--r1' -Force
            $app.properties | Add-Member -NotePropertyName latestReadyRevisionName -NotePropertyValue 'ca-si-management--r1' -Force
            if ($WithBlob) { $app.properties.template.containers[0].env = @(@($app.properties.template.containers[0].env) + [pscustomobject]@{ name = 'DataProtection__BlobUri'; value = $script:BlobUri }) }
            $roles = New-Object System.Collections.Generic.List[object]
            $roles.Add((New-RoleAssign 'w1' $script:MiPrin "$($script:VaultId)/keys/signin-front-dp"))
            $roles.Add((New-RoleAssign 'w2' $script:MiPrin "$($script:VaultId)/keys/SI-Web-KeyRing"))
            $roles.Add((New-RoleAssign 'o1' 'ffffffff-1111-2222-3333-444444444444' "$($script:VaultId)/keys/SI-Web-KeyRing"))   # another identity
            $roles.Add((New-RoleAssign 'v1' $script:MiPrin $script:VaultId))                                                     # above the key
            $roles.Add((New-RoleAssign 'b1' $script:MiPrin $script:CScope '/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe'))
            [pscustomobject]@{
                App = $app; Roles = $roles; NotHealthy = [bool]$NotHealthy; DeleteRefused = [bool]$DeleteRefused; ListRefused = [bool]$ListRefused
                SecretValues = @{ 'sql-pw' = @{ name = 'sql-pw'; value = 'p@ss' }; 'kv-ref' = @{ name = 'kv-ref'; keyVaultUrl = 'https://kv.vault.azure.net/secrets/a'; identity = $script:MiId }
                                  'override-use-mi-fic-assertion-client-id' = @{ name = 'override-use-mi-fic-assertion-client-id'; value = $script:MiCid } }
                Calls = (New-Object System.Collections.Generic.List[object]); Probes = (New-Object System.Collections.Generic.List[string])
            }
        }
        function script:Get-MoveArm($f) {
            {
                param([string]$Method, [string]$Path, $Body)
                $f.Calls.Add([pscustomobject]@{ Method = $Method; Path = $Path; Body = $(if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 30 | ConvertFrom-Json } else { $null }) })
                if ($Path -like '*/providers/Microsoft.Authorization/roleAssignments[?]*') {
                    if ($f.ListRefused) { throw 'GET failed: HTTP 403: AuthorizationFailed' }
                    return [pscustomobject]@{ value = [object[]]$f.Roles.ToArray() }
                }
                if ($Path -like '*/providers/Microsoft.Authorization/roleAssignments/*') {
                    $rid = ($Path -split '\?')[0]
                    if ($Method -eq 'GET') { return @($f.Roles | Where-Object { $_.id -eq $rid })[0] }
                    if ($f.DeleteRefused) { throw 'DELETE failed: HTTP 403: AuthorizationFailed: the client may not perform the action (a condition applies)' }
                    foreach ($x in @($f.Roles | Where-Object { $_.id -eq $rid })) { $null = $f.Roles.Remove($x) }
                    return $null
                }
                if ($Path -like '*/revisions/*') {
                    return [pscustomobject]@{ name = (($Path -split '\?')[0] -split '/')[-1]; properties = [pscustomobject]@{ healthState = $(if ($f.NotHealthy) { 'Unhealthy' } else { 'Healthy' }); runningState = 'Running'; template = $f.App.properties.template } }
                }
                if ($Path -like '*/listSecrets*') { return [pscustomobject]@{ value = @($f.SecretValues.Values | ForEach-Object { [pscustomobject]$_ }) } }
                if ($Method -eq 'GET') { return ($f.App | ConvertTo-Json -Depth 30 | ConvertFrom-Json) }
                if ($Method -eq 'PATCH') {
                    $b = $Body | ConvertTo-Json -Depth 30 | ConvertFrom-Json
                    $sec = @($b.properties.configuration.secrets)
                    $f.SecretValues = @{}
                    foreach ($s in $sec) { $f.SecretValues[[string]$s.name] = @{ name = [string]$s.name }; foreach ($p in $s.PSObject.Properties) { $f.SecretValues[[string]$s.name][$p.Name] = $p.Value } }
                    if ($b.properties.PSObject.Properties['template']) { $f.App.properties.template = $b.properties.template }
                    $f.App.properties.latestRevisionName = 'ca-si-management--r2'; $f.App.properties.latestReadyRevisionName = 'ca-si-management--r2'
                    return $null
                }
                throw "unexpected ARM $Method $Path"
            }.GetNewClosure()
        }
        function script:Invoke-Move($f) {
            $probes = $f.Probes
            Invoke-SIBuiltInAuthKeyRingMove -Arm (Get-MoveArm $f) -AppId $script:AppId -ContainerUri 'https://stsitest.blob.core.windows.net/si-auth-tokens' -PrincipalId $script:MiPrin `
                -VaultId $script:VaultId -Probe ({ param($Url) $probes.Add($Url); [pscustomobject]@{ Status = 302; Location = '/.auth/login/aad?post_login_redirect_uri=/healthz' } }.GetNewClosure()) `
                -Sleep { param($s) } -Tries 2 -RevisionTries 2
        }
    }

    It 'writes DataProtection__BlobUri (every secret kept, read back), and only after the web app runs on it removes the two key roles, read back' {
        $f = New-MoveFake
        $r = Invoke-Move $f
        $r.Ok | Should -BeTrue
        $r.State | Should -Be 'removed'
        Get-SIBuiltInAuthSetting -App $f.App -Name 'DataProtection__BlobUri' | Should -Be $script:BlobUri
        foreach ($k in 'sql-pw', 'kv-ref', 'override-use-mi-fic-assertion-client-id') { $f.SecretValues.ContainsKey($k) | Should -BeTrue -Because "the secret $k is kept" }
        $f.SecretValues['sql-pw'].value | Should -Be 'p@ss'
        # the order: the setting, then the revision that runs it (and the address), then the removals
        $calls = New-Object System.Collections.Generic.List[object]; foreach ($c in $f.Calls) { $calls.Add($c) }
        $patch = -1; $rev = -1; $del = -1
        for ($i = 0; $i -lt $calls.Count; $i++) {
            if ($patch -lt 0 -and $calls[$i].Method -eq 'PATCH') { $patch = $i }
            if ($calls[$i].Path -like '*/revisions/*') { $rev = $i }
            if ($del -lt 0 -and $calls[$i].Method -eq 'DELETE') { $del = $i }
        }
        $patch | Should -BeGreaterOrEqual 0; $rev | Should -BeGreaterThan $patch; $del | Should -BeGreaterThan $rev
        $f.Probes | Should -Contain "https://$($script:Fqdn)/healthz"
        # ONLY id-si-web's role at the two keys: another identity's, one above the key and its data right stay
        @($calls | Where-Object { $_.Method -eq 'DELETE' } | ForEach-Object { (($_.Path -split '\?')[0] -split '/')[-1] } | Sort-Object) | Should -Be @('w1', 'w2')
        @($f.Roles | ForEach-Object { ($_.id -split '/')[-1] } | Sort-Object) | Should -Be @('b1', 'o1', 'v1')
        @($r.Lines | Where-Object { $_ -match 'no longer holds "Key Vault Crypto Service Encryption User" on the key (signin-front-dp|SI-Web-KeyRing) \(removed; read back\)' }).Count | Should -Be 2
        # the next run: nothing written, nothing removed
        $f.Calls.Clear()
        (Invoke-Move $f).State | Should -Be 'in-place'
        @($f.Calls | Where-Object { $_.Method -in 'PATCH', 'DELETE', 'PUT' }).Count | Should -Be 0
    }
    It 'the web app does not run on the blob yet: the Key Vault rights STAY (waiting, not a failure)' {
        $f = New-MoveFake -NotHealthy
        $r = Invoke-Move $f
        $r.Ok | Should -BeTrue; $r.State | Should -Be 'waiting'
        @($f.Calls | Where-Object { $_.Method -eq 'DELETE' }).Count | Should -Be 0
        $f.Roles.Count | Should -Be 5
        @($r.Lines | Where-Object { $_ -match 'does not run on its own key store yet .* its Key Vault rights stay' }).Count | Should -Be 1
    }
    It 'a refused removal (the conditioned role right) is a SUPPORT STEP, never a failure of the update' {
        $f = New-MoveFake -WithBlob -DeleteRefused
        $r = Invoke-Move $f
        $r.Ok | Should -BeTrue
        $r.State | Should -Be 'needs-support'
        @($r.Support).Count | Should -Be 2
        @($r.Support | Where-Object { $_ -match '^the Support app removes id-si-web''s role "Key Vault Crypto Service Encryption User" on the key (signin-front-dp|SI-Web-KeyRing)' }).Count | Should -Be 2
        @($r.Lines | Where-Object { $_ -match 'Support-app step: the Support app removes' }).Count | Should -Be 2
        @($f.Calls | Where-Object { $_.Method -eq 'PATCH' }).Count | Should -Be 0 -Because 'the setting was already there'
    }
    It 'a role list it may not read is a support step too' {
        $r = Invoke-Move (New-MoveFake -WithBlob -ListRefused)
        $r.Ok | Should -BeTrue; $r.State | Should -Be 'needs-support'; @($r.Support).Count | Should -Be 2
    }
    It 'the converge hands the token container and the web identity on (apply)' {
        $f = New-Fake
        $r = Invoke-Converge $f 'apply'
        $r.State | Should -Be 'applied'
        $r.TokenContainerUri | Should -Be 'https://stsitest.blob.core.windows.net/si-auth-tokens'
        $r.WebPrincipalId | Should -Be $script:MiPrin
        Get-SIBuiltInAuthKeyRingBlobUri -ContainerUri $r.TokenContainerUri | Should -Be $script:BlobUri
    }
    It 'the updater moves the keys ONLY after a switch that read back (apply: applied / in-place) -- never when off, planned or failed' {
        $script:moves = New-Object System.Collections.Generic.List[object]
        $move = { param($a) $script:moves.Add($a); [pscustomobject]@{ Ok = $true; State = 'removed'; Lines = @('x'); Support = @() } }
        $res = { param([string]$State, [bool]$Ok = $true) [pscustomobject]@{ Ok = $Ok; State = $State; Lines = @(); TokenContainerUri = 'https://stsitest.blob.core.windows.net/si-auth-tokens'; WebPrincipalId = $script:MiPrin; WebIdentityName = 'id-si-web' } }
        $e = @{ SI_UPDATER_WEB_APP = 'ca-si-management' }
        foreach ($case in @(@{ Mode = ''; State = 'in-place' }, @{ Mode = 'off'; State = 'in-place' }, @{ Mode = 'plan'; State = 'in-place' }, @{ Mode = 'redirect'; State = 'in-place' },
                            @{ Mode = 'apply'; State = 'failed'; Ok = $false }, @{ Mode = 'apply'; State = 'rolled-back'; Ok = $false }, @{ Mode = 'apply'; State = 'needs-support'; Ok = $false })) {
            $st = $case.State; $ok = if ($case.ContainsKey('Ok')) { $case.Ok } else { $true }
            $conv = { param($a) & $res $st $ok }.GetNewClosure()
            $null = Invoke-SIUpdaterBuiltInAuthStep -Env ($e + @{ SI_Updater_BuiltInAuth = $case.Mode }) -SubscriptionId 's' -ResourceGroup 'rg' -Converge $conv -Arm { } -Graph { } -KeyRingMove $move -VaultId $script:VaultId
        }
        $script:moves.Count | Should -Be 0
        foreach ($st in 'applied', 'in-place') {
            $conv = { param($a) & $res $st $true }.GetNewClosure()
            $r = Invoke-SIUpdaterBuiltInAuthStep -Env ($e + @{ SI_Updater_BuiltInAuth = 'apply' }) -SubscriptionId 's' -ResourceGroup 'rg' -Converge $conv -Arm { } -Graph { } -KeyRingMove $move -VaultId $script:VaultId
            $r.KeyRing.State | Should -Be 'removed'
        }
        $script:moves.Count | Should -Be 2
        $script:moves[0].ContainerUri | Should -Be 'https://stsitest.blob.core.windows.net/si-auth-tokens'
        $script:moves[0].PrincipalId | Should -Be $script:MiPrin
        $script:moves[0].VaultId | Should -Be $script:VaultId
        $script:moves[0].AppId | Should -BeLike '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/containerApps/*'
    }
}

Describe 'the Key Vault key ring converge stops once the web app keeps its keys in its own blob' {
    BeforeAll { . (Join-Path $script:SIRoot 'setup\_shared\SI-WebKeyRing.ps1') }
    It 'with DataProtection__BlobUri set: no Key Vault call, no grant, no check, no setting' {
        $script:n = 0
        $count = { $script:n++; [pscustomobject]@{ Status = 200; Json = $null } }
        $r = Invoke-SIWebKeyRingConverge -Arm $count -KeyVault $count -SetEnv { $script:n++; $true } -VaultName 'kv-si' -VaultId '/v' -PrincipalIds @('p') -SubscriptionId 's' -BlobRingEnv 'https://stsitest.blob.core.windows.net/si-auth-tokens/dataprotection/keys.xml'
        $r.Ok | Should -BeTrue
        $script:n | Should -Be 0
        @($r.Actions).Count | Should -Be 0
        @($r.Lines | Where-Object { $_ -match 'without Key Vault' }).Count | Should -Be 1
    }
    It 'setup and the updater pass the web app''s DataProtection__BlobUri to it (wiring)' {
        $d = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'pro-management\deploy\Deploy-SIManagement.ps1'))
        $d | Should -Match '-CurrentEnv \$curKr -IdentityName \$IdentityName -BlobRingEnv \$curBlobRing'
        $d | Should -Match "\[string\]\`$e\.name -eq 'DataProtection__BlobUri'\) \{ \`$curBlobRing = "
        $u = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterSecretHandover.ps1'))
        $u | Should -Match '-CurrentEnv \$cur -BlobRingEnv \$blobRing'
        $u | Should -Match "\[string\]\`$e\.name -eq 'DataProtection__BlobUri'\) \{ \`$blobRing = "
    }
    It 'the person-run update prepares no sign-in front store when the built-in sign-in is on (wiring)' {
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $i = $s.IndexOf("[string]`$e0.name -eq 'SI_Web_BuiltInAuth'")
        $i | Should -BeGreaterThan 0
        $i | Should -BeLessThan $s.IndexOf("Step '9g. SIGN-IN FRONT STORE'")
    }
}
