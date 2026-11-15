#Requires -Version 7.0
<#
    MICROSOFT'S BUILT-IN SIGN-IN -- ONE STANDARD AND NO LEFTOVERS (framework SECURE-WEB-1): setup\_shared\SI-BuiltInAuthStandard.ps1,
    the updater's call after the web app's converge (container\updater\Start-SIUpdater.ps1, Invoke-SIUpdaterBuiltInAuthStep)
    and the read-only check setup\Test-SIBuiltInAuthStandard.ps1. Against a FAKE ARM, a FAKE Graph and a FAKE probe (script
    scope, never global):
      * the MCP authConfig: Return401 (never a redirect), both audiences, no login parameters, no secret setting, no token
        store, /healthz open; apply writes it, reads it back and accepts ONLY a platform 401 (/.auth/me answers) -- an SI 401
        (/.auth/me 404), a 200 or a 403 roll it back (off, read back); plan writes nothing; another app registration = no write;
      * the leftovers: the web container's front settings go in ONE PATCH that keeps every secret, read back; an era secret
        is removed only when nothing references it; an unreadable secret or a web app that is not switched = no write;
        redirect URIs / client secrets / certificates of the registration and signin-front images are REPORTED, Graph is
        never written;
      * the standard's check: OK on a compliant install, every difference named on a deviating one; the script only reads;
      * the updater: the MCP is put behind the platform only after the web app reads back switched.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    . (Join-Path $script:SIRoot 'setup\_shared\SI-BuiltInAuth.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-BuiltInAuthStandard.ps1')

    $script:Tenant  = 'aaaaaaaa-1111-2222-3333-444444444444'
    $script:Client  = 'bbbbbbbb-1111-2222-3333-444444444444'
    $script:WebCid  = 'cccccccc-1111-2222-3333-444444444444'
    $script:WebPrin = 'dddddddd-1111-2222-3333-444444444444'
    $script:McpCid  = 'cccccccc-2222-2222-3333-444444444444'
    $script:McpPrin = 'dddddddd-2222-2222-3333-444444444444'
    $script:RegId   = 'eeeeeeee-1111-2222-3333-444444444444'
    $script:Sub     = '00000000-0000-0000-0000-00000000aaaa'
    $script:Rg      = "/subscriptions/$($script:Sub)/resourceGroups/rg-si"
    $script:WebId   = $script:Rg + '/providers/Microsoft.App/containerApps/ca-si-management'
    $script:McpId   = $script:Rg + '/providers/Microsoft.App/containerApps/ca-si-mcp'
    $script:WebMi   = $script:Rg + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-web'
    $script:McpMi   = $script:Rg + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-mcp'
    $script:WebFqdn = 'ca-si-management.happy.westeurope.azurecontainerapps.io'
    $script:McpFqdn = 'ca-si-mcp.happy.westeurope.azurecontainerapps.io'
    $script:Vault   = $script:Rg + '/providers/Microsoft.KeyVault/vaults/kv-si'

    function script:ConvertTo-Obj($o) { if ($null -eq $o) { return $null }; $o | ConvertTo-Json -Depth 40 | ConvertFrom-Json }

    function script:New-WebApp {
        param([switch]$NotSwitched, [switch]$NoLeftovers, [switch]$EraSecretReferenced, [switch]$SecretVolume)
        $env = @(@{ name = 'AzureAd__TenantId'; value = $script:Tenant }, @{ name = 'AzureAd__ClientId'; value = $script:Client }, @{ name = 'X'; secretRef = 'sql-pw' })
        if (-not $NotSwitched) { $env += @{ name = 'SI_Web_BuiltInAuth'; value = '1' } }
        if (-not $NoLeftovers) { $env += @(@{ name = 'SI_Web_SigninFront'; value = 'true' }, @{ name = 'SIGNIN_UPSTREAM_PORT'; value = '8081' }, @{ name = 'SI_Web_SigninFrontAccessTokenOnly'; value = 'false' }) }
        if ($EraSecretReferenced) { $env += @{ name = 'OLD_AUTH'; secretRef = 'microsoft-provider-authentication-secret' } }
        $secrets = @(@{ name = 'sql-pw' }, @{ name = 'kv-ref'; keyVaultUrl = 'https://kv.vault.azure.net/secrets/a'; identity = $script:WebMi }, @{ name = 'override-use-mi-fic-assertion-client-id' })
        if (-not $NoLeftovers) { $secrets += @(@{ name = 'microsoft-provider-authentication-secret' }, @{ name = 'signin-old-thing' }) }
        $containers = @(@{ name = 'si-management'; image = 'acrsi.azurecr.io/si-management:3.1.20'; env = $env })
        if ($NotSwitched) { $containers += @{ name = 'signin-front'; image = 'acrsi.azurecr.io/signin-front:2.1.2'; env = @(@{ name = 'SIGNIN_UPSTREAM_PORT'; value = '8081' }) } }
        $tpl = @{ revisionSuffix = 'r1'; containers = $containers; scale = @{ minReplicas = 1; maxReplicas = 1 } }
        if ($SecretVolume) { $tpl.volumes = @(@{ name = 'all'; storageType = 'Secret' }) }
        ConvertTo-Obj @{
            id = $script:WebId; name = 'ca-si-management'
            identity = @{ type = 'UserAssigned'; userAssignedIdentities = @{ $script:WebMi = @{ clientId = $script:WebCid; principalId = $script:WebPrin } } }
            properties = @{
                configuration = @{ ingress = @{ fqdn = $script:WebFqdn; external = $true; targetPort = $(if ($NotSwitched) { 9000 } else { 8080 }) }
                                   secrets = $secrets; registries = @(@{ server = 'acrsi.azurecr.io'; identity = $script:WebMi }) }
                template = $tpl
            }
        }
    }

    function script:New-McpApp {
        param([string]$ClientId = $script:Client)
        ConvertTo-Obj @{
            id = $script:McpId; name = 'ca-si-mcp'
            identity = @{ type = 'UserAssigned'; userAssignedIdentities = @{ $script:McpMi = @{ clientId = $script:McpCid; principalId = $script:McpPrin } } }
            properties = @{
                configuration = @{ ingress = @{ fqdn = $script:McpFqdn; external = $true; targetPort = 8080 }; secrets = @() }
                template = @{ containers = @(@{ name = 'si-management-mcp'; image = 'acrsi.azurecr.io/si-management-mcp:3.1.20'
                                                env = @(@{ name = 'AzureAd__TenantId'; value = $script:Tenant }, @{ name = 'AzureAd__ClientId'; value = $ClientId }) }) }
            }
        }
    }

    function script:Add-OtherApp($f, [string]$Name, [bool]$External, $Auth = $null) {
        $id = $script:Rg + '/providers/Microsoft.App/containerApps/' + $Name
        $f.Apps[$id.ToLowerInvariant()] = ConvertTo-Obj @{ id = $id; name = $Name; properties = @{ configuration = @{ ingress = @{ fqdn = "$Name.happy.westeurope.azurecontainerapps.io"; external = $External; targetPort = 8080 } }
                                                                                                    template = @{ containers = @(@{ name = $Name; image = "acrsi.azurecr.io/$($Name):1" }) } } }
        $f.Auth[$id.ToLowerInvariant()] = $Auth
    }

    function script:Get-WebAuthStandard {
        $b = Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client -TokenStoreContainerUri 'https://stsi.blob.core.windows.net/si-auth-tokens' -TokenStoreIdentityResourceId $script:WebMi
        ConvertTo-Obj $b
    }

    function script:New-Fake {
        param($Web = (New-WebApp), $Mcp = (New-McpApp), $McpAuth = $null, $WebAuth = (Get-WebAuthStandard), [switch]$McpPutFails,
              [hashtable]$Probe = @{ '/mcp' = 401; '/.auth/me' = 401; '/healthz' = 200 }, [object[]]$Roles = @(), [string[]]$Uris = @(), [switch]$WithCredentials,
              [string[]]$Tags = @(), [switch]$DropOneSecretValue, [switch]$NoMcpScope, [switch]$GraphRefuseWrite)
        $wk = $script:WebId.ToLowerInvariant(); $mk = $script:McpId.ToLowerInvariant()
        # the sign-in app registration's API: Estate.Read + user_impersonation (+ mcp.access unless -NoMcpScope)
        $regScopes = @([pscustomobject]@{ id = '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a03'; value = 'Estate.Read'; type = 'Admin'; isEnabled = $true },
                       [pscustomobject]@{ id = '8d1c4f0e-3b7a-4e52-9c61-5a2f7e0d9b14'; value = 'user_impersonation'; type = 'Admin'; isEnabled = $true })
        if (-not $NoMcpScope) { $regScopes += [pscustomobject](New-SIMcpApiScope) }
        $f = [pscustomobject]@{
            Apps = @{ $wk = $Web }; Auth = @{ $wk = $WebAuth; $mk = $McpAuth }
            SecretValues = @{ $wk = @{ 'sql-pw' = @{ name = 'sql-pw'; value = 'p@ss' }; 'kv-ref' = @{ name = 'kv-ref'; keyVaultUrl = 'https://kv.vault.azure.net/secrets/a'; identity = $script:WebMi }
                                       'override-use-mi-fic-assertion-client-id' = @{ name = 'override-use-mi-fic-assertion-client-id'; value = $script:WebCid }
                                       'microsoft-provider-authentication-secret' = @{ name = 'microsoft-provider-authentication-secret'; value = 'old' }; 'signin-old-thing' = @{ name = 'signin-old-thing'; value = 'x' } }
                              $mk = @{} }
            McpPutFails = [bool]$McpPutFails; Probe = $Probe; Roles = $Roles
            Uris = $(if ($Uris.Count) { $Uris } else { @("https://$($script:WebFqdn)/.auth/login/aad/callback") }); WithCredentials = [bool]$WithCredentials; Tags = $Tags
            Calls = (New-Object System.Collections.Generic.List[object]); Probes = (New-Object System.Collections.Generic.List[string])
            RegScopes = $regScopes; RegVersion = 2; RegIdUris = @("api://$($script:Client)"); GraphRefuseWrite = [bool]$GraphRefuseWrite
        }
        if ($Mcp) { $f.Apps[$mk] = $Mcp }
        if ($DropOneSecretValue) { $f.SecretValues[$wk].Remove('sql-pw') }
        $f
    }

    function script:Get-FakeArm($f) {
        {
            param([string]$Method, [string]$Path, $Body)
            $f.Calls.Add([pscustomobject]@{ Kind = 'arm'; Method = $Method; Path = $Path; Body = $(if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 40 | ConvertFrom-Json } else { $null }) })
            $base = ($Path -split '\?')[0].ToLowerInvariant()
            if ($base -like '*/providers/microsoft.authorization/roleassignments') { return [pscustomobject]@{ value = [object[]]@($f.Roles) } }
            if ($base.EndsWith('/authconfigs/current')) {
                $k = $base.Substring(0, $base.Length - '/authconfigs/current'.Length)
                if ($Method -eq 'GET') { return $f.Auth[$k] }
                if ($f.McpPutFails -and $k -like '*ca-si-mcp') { throw 'PUT failed: HTTP 500' }
                $f.Auth[$k] = ($Body | ConvertTo-Json -Depth 40 | ConvertFrom-Json); return $f.Auth[$k]
            }
            if ($base.EndsWith('/listsecrets')) { $k = $base.Substring(0, $base.Length - '/listsecrets'.Length); return [pscustomobject]@{ value = @($f.SecretValues[$k].Values | ForEach-Object { [pscustomobject]$_ }) } }
            if ($Method -eq 'GET' -and $base -like '*/providers/microsoft.app/containerapps') { return [pscustomobject]@{ value = @($f.Apps.Values | ForEach-Object { $_ | ConvertTo-Json -Depth 40 | ConvertFrom-Json }) } }
            if ($f.Apps.ContainsKey($base)) {
                if ($Method -eq 'GET') { $a = ($f.Apps[$base] | ConvertTo-Json -Depth 40 | ConvertFrom-Json); $a.properties | Add-Member -NotePropertyName provisioningState -NotePropertyValue 'Succeeded' -Force; return $a }
                if ($Method -eq 'PATCH') {
                    $b = $Body | ConvertTo-Json -Depth 40 | ConvertFrom-Json
                    $sv = @{}
                    foreach ($s in @($b.properties.configuration.secrets)) { $sv[[string]$s.name] = @{ name = [string]$s.name }; foreach ($p in $s.PSObject.Properties) { $sv[[string]$s.name][$p.Name] = $p.Value } }
                    $f.SecretValues[$base] = $sv
                    $cfg = $b.properties.configuration
                    $cfg.secrets = @(@($b.properties.configuration.secrets) | ForEach-Object { $x = [ordered]@{ name = $_.name }; if ($_.PSObject.Properties['keyVaultUrl']) { $x.keyVaultUrl = $_.keyVaultUrl; $x.identity = $_.identity }; [pscustomobject]$x })
                    $f.Apps[$base].properties.configuration = $cfg
                    if ($b.properties.PSObject.Properties['template']) { $f.Apps[$base].properties.template = $b.properties.template }
                    return $null
                }
            }
            if ($Method -eq 'GET') { return $null }
            throw "unexpected ARM $Method $Path"
        }.GetNewClosure()
    }

    function script:Get-FakeGraph($f) {
        $prin = $script:WebPrin; $ten = $script:Tenant; $rid = $script:RegId
        {
            param([string]$Method, [string]$Uri, $Body)
            $f.Calls.Add([pscustomobject]@{ Kind = 'graph'; Method = $Method; Path = $Uri; Body = $(if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 40 | ConvertFrom-Json } else { $null }) })
            if ($Method -eq 'PATCH' -and $Uri -like "*/applications/$rid") {
                # only the API of the registration is ever written here (the MCP scope); a PATCH replaces api as a whole
                if ($f.GraphRefuseWrite) { throw 'HTTP 403 Authorization_RequestDenied: Insufficient privileges to complete the operation.' }
                $b = $Body | ConvertTo-Json -Depth 40 | ConvertFrom-Json
                if ($b.PSObject.Properties['identifierUris']) { $f.RegIdUris = @($b.identifierUris) }
                if ($b.PSObject.Properties['api']) {
                    $f.RegScopes = @($b.api.oauth2PermissionScopes)
                    $f.RegVersion = $(if ($b.api.PSObject.Properties['requestedAccessTokenVersion']) { $b.api.requestedAccessTokenVersion } else { $null })
                }
                return $null
            }
            if ($Method -ne 'GET') { throw "unexpected Graph $Method $Uri" }
            if ($Uri -like '*federatedIdentityCredentials*') { return [pscustomobject]@{ value = @([pscustomobject]@{ issuer = "https://login.microsoftonline.com/$ten/v2.0"; subject = $prin; audiences = @('api://AzureADTokenExchange') }) } }
            $r = [ordered]@{ id = $rid; web = [pscustomobject]@{ redirectUris = @($f.Uris); implicitGrantSettings = [pscustomobject]@{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } }
                             identifierUris = @($f.RegIdUris); api = [pscustomobject]@{ requestedAccessTokenVersion = $f.RegVersion; oauth2PermissionScopes = @($f.RegScopes); preAuthorizedApplications = @() } }
            if ($f.WithCredentials) {
                $r.passwordCredentials = @([pscustomobject]@{ displayName = 'old secret'; endDateTime = '2027-01-31T00:00:00Z' })
                $r.keyCredentials = @([pscustomobject]@{ displayName = 'old cert'; endDateTime = '2026-12-01T00:00:00Z' })
            }
            [pscustomobject]$r
        }.GetNewClosure()
    }

    function script:Get-FakeProbe($f) {
        {
            param([string]$Url)
            $f.Probes.Add($Url)
            $path = ([uri]$Url).AbsolutePath
            if ($f.Probe.ContainsKey($path)) { return [pscustomobject]@{ Status = [int]$f.Probe[$path]; Location = '' } }
            [pscustomobject]@{ Status = 302; Location = '/.auth/login/aad' }
        }.GetNewClosure()
    }

    function script:Get-FakeImages($f) { { param([string]$LoginServer, [string]$Repo) [pscustomobject]@{ Found = (@($f.Tags).Count -gt 0); Tags = @($f.Tags) } }.GetNewClosure() }

    function script:Get-Writes($f) { @($f.Calls | Where-Object { $_.Method -in 'PUT', 'PATCH', 'DELETE' -or ($_.Method -eq 'POST' -and $_.Path -notlike '*/listSecrets*') }) }

    function script:Invoke-Mcp($f, [string]$Mode = 'apply') {
        Invoke-SIBuiltInAuthMcpConverge -Arm (Get-FakeArm $f) -Mode $Mode -McpAppId $script:McpId -TenantId $script:Tenant -ClientId $script:Client -Probe (Get-FakeProbe $f) -Sleep { param($s) } -Tries 2 -ProbeTries 2 -BusyTries 2
    }
    function script:Invoke-Clean($f, [string]$Mode = 'apply') {
        Invoke-SIBuiltInAuthLeftoverClean -Arm (Get-FakeArm $f) -Mode $Mode -WebAppId $script:WebId -Sleep { param($s) } -Tries 2 -BusyTries 2
    }
    function script:Invoke-Step($f, [string]$Mode = 'apply', $WebResult = [pscustomobject]@{ Ok = $true; State = 'applied'; Lines = @() }) {
        Invoke-SIBuiltInAuthStandardStep -Arm (Get-FakeArm $f) -Graph (Get-FakeGraph $f) -Mode $Mode -WebAppId $script:WebId -McpAppId $script:McpId -WebResult $WebResult `
            -Probe (Get-FakeProbe $f) -ListImages (Get-FakeImages $f) -RoleScope $script:Rg -Sleep { param($s) } -Tries 2 -ProbeTries 2 -BusyTries 2
    }
}

Describe 'the MCP authConfig body' {
    It 'is bearer validation only: Return401, the same app registration, both audiences, v2.0 issuer, the named open paths, HTTPS' {
        $p = (ConvertTo-Obj (Get-SIBuiltInAuthMcpConfigBody -TenantId $script:Tenant -ClientId $script:Client)).properties
        $p.platform.enabled | Should -BeTrue
        $p.globalValidation.unauthenticatedClientAction | Should -BeExactly 'Return401'
        $p.globalValidation.PSObject.Properties['redirectToProvider'] | Should -BeNullOrEmpty
        # a PUT replaces excludedPaths: EVERY named open path is in every body
        @($p.globalValidation.excludedPaths) | Should -Be @('/healthz', '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/*')
        $a = $p.identityProviders.azureActiveDirectory
        $a.enabled | Should -BeTrue
        $a.registration.clientId | Should -Be $script:Client
        $a.registration.openIdIssuer | Should -Be "https://login.microsoftonline.com/$($script:Tenant)/v2.0"
        @($a.validation.allowedAudiences) | Should -Be @("api://$($script:Client)", $script:Client)
        $p.httpSettings.requireHttps | Should -BeTrue
    }
    It 'has NO login parameters, NO client secret setting and NO token store' {
        $p = (ConvertTo-Obj (Get-SIBuiltInAuthMcpConfigBody -TenantId $script:Tenant -ClientId $script:Client)).properties
        $p.identityProviders.azureActiveDirectory.PSObject.Properties['login'] | Should -BeNullOrEmpty
        $p.identityProviders.azureActiveDirectory.registration.PSObject.Properties['clientSecretSettingName'] | Should -BeNullOrEmpty
        $p.login.tokenStore.enabled | Should -BeFalse
        $p.login.PSObject.Properties['cookieExpiration'] | Should -BeNullOrEmpty
    }
    It 'the issuer is a parameter (the v1 issuer, if the live proof needs it); off = the same body switched off' {
        $b = Get-SIBuiltInAuthMcpConfigBody -TenantId $script:Tenant -ClientId $script:Client -OpenIdIssuer "https://sts.windows.net/$($script:Tenant)/" -Enabled $false
        $b.properties.identityProviders.azureActiveDirectory.registration.openIdIssuer | Should -Be "https://sts.windows.net/$($script:Tenant)/"
        $b.properties.platform.enabled | Should -BeFalse
    }
    It 'the read-back compare refuses a sign-in on the MCP (login parameters, a secret setting, a token store)' {
        $w = Get-SIBuiltInAuthMcpConfigBody -TenantId $script:Tenant -ClientId $script:Client
        $c = ConvertTo-Obj $w
        (Test-SIBuiltInAuthMcpConfigMatches -Current $c -Want $w).Ok | Should -BeTrue
        $bad = ConvertTo-Obj (Get-WebAuthStandard)
        $m = Test-SIBuiltInAuthMcpConfigMatches -Current $bad -Want $w
        $m.Ok | Should -BeFalse
        ($m.Diff -join '|') | Should -Match 'unauthenticatedClientAction'
        ($m.Diff -join '|') | Should -Match 'loginParameters'
        ($m.Diff -join '|') | Should -Match 'clientSecretSettingName'
        ($m.Diff -join '|') | Should -Match 'tokenStore'
    }
}

Describe 'the MCP probe: only a PLATFORM 401 counts' {
    It '401 on /mcp with the platform''s /.auth/me answering = refused by the platform' {
        (Test-SIBuiltInAuthMcpPlatformRefused -Mcp @{ Status = 401 } -AuthMe @{ Status = 401 }).Ok | Should -BeTrue
        (Test-SIBuiltInAuthMcpPlatformRefused -Mcp @{ Status = 401 } -AuthMe @{ Status = 302 }).Ok | Should -BeTrue
    }
    It 'a 401 with /.auth/me 404 is SecurityInsight''s own 401 -- NOT accepted' {
        $t = Test-SIBuiltInAuthMcpPlatformRefused -Mcp @{ Status = 401 } -AuthMe @{ Status = 404 }
        $t.Ok | Should -BeFalse
        $t.Why | Should -Match 'came from SecurityInsight'
    }
    It '200, 403, a redirect or no answer are never accepted' {
        foreach ($s in 200, 403, 302, 0) { (Test-SIBuiltInAuthMcpPlatformRefused -Mcp @{ Status = $s } -AuthMe @{ Status = 401 }).Ok | Should -BeFalse }
        (Test-SIBuiltInAuthMcpPlatformRefused -Mcp @{ Status = 401 } -AuthMe $null).Ok | Should -BeFalse
    }
}

Describe 'the MCP converge' {
    It 'apply: ONE PUT of the bearer-only body, read back, probed (/mcp, /.auth/me, /healthz) -- no secret, no app PATCH' {
        $f = New-Fake
        $r = Invoke-Mcp $f
        $r.State | Should -Be 'applied'
        $r.Ok | Should -BeTrue
        $w = @(Get-Writes $f)
        $w.Count | Should -Be 1
        $w[0].Method | Should -Be 'PUT'
        $w[0].Path | Should -BeLike "$($script:McpId)/authConfigs/current?api-version=2024-10-02-preview"
        $w[0].Body.properties.globalValidation.unauthenticatedClientAction | Should -Be 'Return401'
        $w[0].Body.properties.identityProviders.azureActiveDirectory.registration.PSObject.Properties['clientSecretSettingName'] | Should -BeNullOrEmpty
        @($f.Calls | Where-Object { $_.Path -like '*listSecrets*' }).Count | Should -Be 0
        @($f.Probes) | Should -Contain "https://$($script:McpFqdn)/mcp"
        @($f.Probes) | Should -Contain "https://$($script:McpFqdn)/.auth/me"
        @($f.Probes) | Should -Contain "https://$($script:McpFqdn)/healthz"
    }
    It 'an SI 401 (no platform /.auth/me) rolls back: the platform OFF for the MCP, read back' {
        $f = New-Fake -Probe @{ '/mcp' = 401; '/.auth/me' = 404; '/healthz' = 200 }
        $r = Invoke-Mcp $f
        $r.State | Should -Be 'rolled-back'
        $r.Ok | Should -BeFalse
        $puts = @($f.Calls | Where-Object { $_.Method -eq 'PUT' })
        $puts.Count | Should -Be 2
        $puts[-1].Body.properties.platform.enabled | Should -BeFalse
        $f.Auth[$script:McpId.ToLowerInvariant()].properties.platform.enabled | Should -BeFalse
        ($r.Warnings -join ' ') | Should -Match 'switched off again \(read back\)'
    }
    It 'a 200 or a 403 from /mcp, or a closed /healthz, roll back too' {
        foreach ($p in @(@{ '/mcp' = 200; '/.auth/me' = 401; '/healthz' = 200 }, @{ '/mcp' = 403; '/.auth/me' = 401; '/healthz' = 200 }, @{ '/mcp' = 401; '/.auth/me' = 401; '/healthz' = 401 })) {
            $f = New-Fake -Probe $p
            (Invoke-Mcp $f).State | Should -Be 'rolled-back'
        }
    }
    It 'plan writes nothing and says what would be written' {
        $f = New-Fake
        $r = Invoke-Mcp $f 'plan'
        $r.State | Should -Be 'planned'
        @(Get-Writes $f).Count | Should -Be 0
        ($r.Lines -join ' ') | Should -Match 'would: write the bearer-only configuration'
    }
    It 'in place = no write; another app registration on the MCP = no write, said' {
        $f = New-Fake -McpAuth (ConvertTo-Obj (Get-SIBuiltInAuthMcpConfigBody -TenantId $script:Tenant -ClientId $script:Client))
        (Invoke-Mcp $f).State | Should -Be 'in-place'
        @(Get-Writes $f).Count | Should -Be 0
        $g = New-Fake -Mcp (New-McpApp -ClientId 'ffffffff-1111-2222-3333-444444444444')
        $r = Invoke-Mcp $g
        $r.State | Should -Be 'failed'
        @(Get-Writes $g).Count | Should -Be 0
    }
    It 'no MCP app = nothing to do' {
        $f = New-Fake -Mcp $null
        (Invoke-Mcp $f).State | Should -Be 'absent'
        @(Get-Writes $f).Count | Should -Be 0
    }
}

Describe 'the leftovers of the sign-in front' {
    It 'removes the front settings and the unreferenced era secret in ONE PATCH that keeps every other secret, read back' {
        $f = New-Fake
        $r = Invoke-Clean $f
        $w = @(Get-Writes $f)
        $w.Count | Should -Be 1
        $w[0].Method | Should -Be 'PATCH'
        $env = @($w[0].Body.properties.template.containers[0].env | ForEach-Object { $_.name })
        $env | Should -Not -Contain 'SI_Web_SigninFront'
        $env | Should -Not -Contain 'SI_Web_SigninFrontAccessTokenOnly'
        @($env | Where-Object { $_ -like 'SIGNIN_*' }).Count | Should -Be 0
        $env | Should -Contain 'SI_Web_BuiltInAuth'
        $env | Should -Contain 'X'
        $w[0].Body.properties.template.PSObject.Properties['revisionSuffix'] | Should -BeNullOrEmpty
        $sec = @($w[0].Body.properties.configuration.secrets)
        @($sec | ForEach-Object { $_.name }) | Should -Not -Contain 'microsoft-provider-authentication-secret'
        @($sec | Where-Object { $_.name -eq 'sql-pw' })[0].value | Should -Be 'p@ss'
        @($sec | Where-Object { $_.name -eq 'kv-ref' })[0].keyVaultUrl | Should -Be 'https://kv.vault.azure.net/secrets/a'
        @($sec | ForEach-Object { $_.name }) | Should -Contain 'override-use-mi-fic-assertion-client-id'
        @($sec | ForEach-Object { $_.name }) | Should -Contain 'signin-old-thing' -Because 'a name that only LOOKS like the sign-in era is reported, never removed'
        @($r.Removed) | Should -Contain 'microsoft-provider-authentication-secret'
        @($r.Removed) | Should -Contain 'SIGNIN_UPSTREAM_PORT'
        ($r.Lines -join ' ') | Should -Match 'read back; every other secret kept'
        @($r.Warnings).Count | Should -Be 0
    }
    It 'never removes an era secret that something references (a setting, the authConfig, a secret volume)' {
        $ls = Get-SIBuiltInAuthLeftoverSecrets -App (New-WebApp -EraSecretReferenced) -AuthConfig $null
        @($ls.Remove) | Should -Not -Contain 'microsoft-provider-authentication-secret'
        @($ls.Report | ForEach-Object { $_.Name }) | Should -Contain 'microsoft-provider-authentication-secret'
        $auth = ConvertTo-Obj @{ properties = @{ identityProviders = @{ azureActiveDirectory = @{ registration = @{ clientSecretSettingName = 'microsoft-provider-authentication-secret' } } } } }
        @((Get-SIBuiltInAuthLeftoverSecrets -App (New-WebApp) -AuthConfig $auth).Remove).Count | Should -Be 0
        @((Get-SIBuiltInAuthLeftoverSecrets -App (New-WebApp -SecretVolume) -AuthConfig $null).Remove).Count | Should -Be 0
        # ... and the update's PATCH keeps it
        $f = New-Fake -Web (New-WebApp -EraSecretReferenced)
        $null = Invoke-Clean $f
        @(@(Get-Writes $f)[0].Body.properties.configuration.secrets | ForEach-Object { $_.name }) | Should -Contain 'microsoft-provider-authentication-secret'
    }
    It 'SecurityInsight''s own secret is never a leftover' {
        $ls = Get-SIBuiltInAuthLeftoverSecrets -App (New-WebApp) -AuthConfig $null
        @($ls.Remove) + @($ls.Report | ForEach-Object { $_.Name }) | Should -Not -Contain 'override-use-mi-fic-assertion-client-id'
    }
    It 'an unreadable secret = nothing written; a web app that is not switched = nothing written; plan = nothing written' {
        $f = New-Fake -DropOneSecretValue
        $r = Invoke-Clean $f
        @(Get-Writes $f).Count | Should -Be 0
        ($r.Warnings -join ' ') | Should -Match 'NOT removed: the secret\(s\) sql-pw could not be read'
        $g = New-Fake -Web (New-WebApp -NotSwitched)
        $null = Invoke-Clean $g
        @(Get-Writes $g).Count | Should -Be 0
        $h = New-Fake
        $p = Invoke-Clean $h 'plan'
        @(Get-Writes $h).Count | Should -Be 0
        ($p.Lines -join ' ') | Should -Match 'would remove'
    }
    It 'redirect URIs, client secrets and certificates of the registration are REPORTED, Graph is never written' {
        $t = @(Get-SIBuiltInAuthRegistrationLeftovers -Registration ([pscustomobject]@{ web = [pscustomobject]@{ redirectUris = @("https://$($script:WebFqdn)/.auth/login/aad/callback", "https://$($script:WebFqdn)/signin-oidc", 'https://old.example.com/.auth/login/aad/callback') }
                                                                                       spa = [pscustomobject]@{ redirectUris = @('https://x/spa') }
                                                                                       passwordCredentials = @([pscustomobject]@{ displayName = 's1'; endDateTime = '2027-01-31T00:00:00Z' }) }) -Fqdn $script:WebFqdn)
        $t.Count | Should -Be 4
        ($t -join '|') | Should -Match 'signin-oidc'
        ($t -join '|') | Should -Match 'old\.example\.com'
        ($t -join '|') | Should -Match 'CLIENT SECRET ''s1'' \(ends 2027-01-31\)'
        ($t -join '|') | Should -Not -Match "$([regex]::Escape($script:WebFqdn))/\.auth/login/aad/callback \("
        $f = New-Fake -Uris @("https://$($script:WebFqdn)/.auth/login/aad/callback", "https://$($script:WebFqdn)/signin-oidc") -WithCredentials -Tags @('2.1.1', '2.1.2')
        $s = Invoke-Step $f
        @($f.Calls | Where-Object { $_.Kind -eq 'graph' -and $_.Method -ne 'GET' }).Count | Should -Be 0
        $lw = @($s.Warnings | Where-Object { $_ -like 'leftover: *' })
        ($lw -join '|') | Should -Match 'signin-oidc'
        ($lw -join '|') | Should -Match 'CLIENT SECRET'
        ($lw -join '|') | Should -Match 'CERTIFICATE'
        ($lw -join '|') | Should -Match '2 signin-front image\(s\) still stored in acrsi\.azurecr\.io \(tags 2\.1\.1,2\.1\.2\)'
    }
}

Describe 'the standard''s check' {
    BeforeAll {
        function script:New-CompliantFake {
            New-Fake -Web (New-WebApp -NoLeftovers) -McpAuth (ConvertTo-Obj (Get-SIBuiltInAuthMcpConfigBody -TenantId $script:Tenant -ClientId $script:Client))
        }
        function script:Read-Facts($f) {
            # (a failure names where it happened)
            try { Read-SIBuiltInAuthStandardFacts -Arm (Get-FakeArm $f) -Graph (Get-FakeGraph $f) -WebAppId $script:WebId -McpAppId $script:McpId -RoleScope $script:Rg -ListImages (Get-FakeImages $f) }
            catch { throw ('{0} AT {1}' -f $_.Exception.Message, $_.ScriptStackTrace) }
        }
    }
    It 'OK on a compliant install' {
        $r = Test-SIBuiltInAuthStandard -Facts (Read-Facts (New-CompliantFake))
        @($r.Diff) | Should -BeNullOrEmpty
        @($r.Leftovers) | Should -BeNullOrEmpty
        $r.Ok | Should -BeTrue
        $r.Summary | Should -BeExactly 'built-in sign-in standard: OK'
    }
    It 'names every difference: the front container, the MCP not on Return401, a Key Vault role, a forbidden role, a missing account picker' {
        $web = New-WebApp -NotSwitched -NoLeftovers
        $auth = Get-WebAuthStandard
        $auth.properties.identityProviders.azureActiveDirectory.login.loginParameters = @('scope=openid')
        $roles = @([pscustomobject]@{ properties = [pscustomobject]@{ principalId = $script:WebPrin; roleDefinitionId = '/x/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6'; scope = $script:Vault } },
                   [pscustomobject]@{ properties = [pscustomobject]@{ principalId = $script:McpPrin; roleDefinitionId = '/x/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c'; scope = $script:Rg } },
                   [pscustomobject]@{ properties = [pscustomobject]@{ principalId = $script:WebPrin; roleDefinitionId = '/x/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7'; scope = $script:Vault } })
        $f = New-Fake -Web $web -WebAuth $auth -McpAuth (ConvertTo-Obj (Get-SIBuiltInAuthConfigBody -TenantId $script:Tenant -ClientId $script:Client)) -Roles $roles
        $r = Test-SIBuiltInAuthStandard -Facts (Read-Facts $f)
        $r.Ok | Should -BeFalse
        $d = $r.Diff -join ' | '
        $d | Should -Match 'containers si-management\+signin-front'
        $d | Should -Match 'SI_Web_BuiltInAuth is not 1'
        $d | Should -Match 'port 9000'
        $d | Should -Match 'account picker'
        $d | Should -Match 'mcp: globalValidation\.unauthenticatedClientAction'
        $d | Should -Match 'id-si-web holds Key Vault Secrets User on kv-si'
        $d | Should -Match 'id-si-web holds a role \(acdd72a7-3385-48ef-bd42-f606fba81ae7\) on the Key Vault kv-si'
        $d | Should -Match 'id-si-mcp holds Contributor on rg-si'
        $r.Summary | Should -Match '^built-in sign-in standard: DIFF: '
    }
    It 'EVERY internet-facing app counts: a third external app without authentication is flagged, an internal-only one is ignored' {
        $f = New-CompliantFake
        Add-OtherApp $f 'ca-si-extra' $true $null
        Add-OtherApp $f 'ca-si-internal' $false $null
        $r = Test-SIBuiltInAuthStandard -Facts (Read-Facts $f)
        $r.Ok | Should -BeFalse
        $d = $r.Diff -join ' | '
        $d | Should -Match 'ca-si-extra: internet-facing without Microsoft''s authentication \(no authentication configuration\)'
        $d | Should -Not -Match 'ca-si-internal'
        @($r.Diff).Count | Should -Be 1 -Because 'the web app and the MCP are compliant'
    }
    It 'platform OFF, AllowAnonymous or a sign-in redirect on an API-only app are flagged; only a named exception with a reason clears one, and the list is empty' {
        $off = ConvertTo-Obj (Get-SIBuiltInAuthMcpConfigBody -TenantId $script:Tenant -ClientId $script:Client -Enabled $false)
        $anon = ConvertTo-Obj (Get-SIBuiltInAuthMcpConfigBody -TenantId $script:Tenant -ClientId $script:Client); $anon.properties.globalValidation.unauthenticatedClientAction = 'AllowAnonymous'
        $redir = ConvertTo-Obj (Get-WebAuthStandard)
        $ok = ConvertTo-Obj (Get-SIBuiltInAuthMcpConfigBody -TenantId $script:Tenant -ClientId $script:Client)
        $facts = [pscustomobject]@{ WebName = 'ca-si-management'; McpName = 'ca-si-mcp'
                                    PublicApps = @([pscustomobject]@{ Name = 'a-off'; Auth = $off }, [pscustomobject]@{ Name = 'a-anon'; Auth = $anon },
                                                   [pscustomobject]@{ Name = 'a-redir'; Auth = $redir }, [pscustomobject]@{ Name = 'a-ok'; Auth = $ok }) }
        $t = @(Get-SIBuiltInAuthPublicAppFindings -Facts $facts)
        $t.Count | Should -Be 3
        ($t -join '|') | Should -Match 'a-off: .*platform authentication is OFF'
        ($t -join '|') | Should -Match 'a-anon: .*AllowAnonymous'
        ($t -join '|') | Should -Match 'a-redir: .*RedirectToLoginPage \(an API-only app answers Return401\)'
        @(Get-SIBuiltInAuthPublicAppFindings -Facts $facts -Exceptions @([pscustomobject]@{ App = 'a-off'; Reason = 'test' })).Count | Should -Be 2
        @(Get-SIBuiltInAuthPublicAppFindings -Facts $facts -Exceptions @([pscustomobject]@{ App = 'a-off'; Reason = '' })).Count | Should -Be 3 -Because 'an exception without a reason is no exception'
        @($script:SIBuiltInAuthPublicExceptions).Count | Should -Be 0
    }
    It 'leftovers alone make it DIFF too (one standard AND no leftovers)' {
        $f = New-Fake -McpAuth (ConvertTo-Obj (Get-SIBuiltInAuthMcpConfigBody -TenantId $script:Tenant -ClientId $script:Client))
        $r = Test-SIBuiltInAuthStandard -Facts (Read-Facts $f)
        @($r.Diff) | Should -BeNullOrEmpty
        @($r.Leftovers).Count | Should -BeGreaterThan 0
        $r.Summary | Should -Match 'leftover\(s\)'
    }
    It 'a read that fails is "not checked", never clean' {
        $f = New-CompliantFake
        $arm = Get-FakeArm $f
        $bad = { param($m, $p, $b) if ($p -like '*roleAssignments*') { throw 'HTTP 403 AuthorizationFailed' }; & $arm $m $p $b }.GetNewClosure()
        $r = Test-SIBuiltInAuthStandard -Facts (Read-SIBuiltInAuthStandardFacts -Arm $bad -Graph (Get-FakeGraph $f) -WebAppId $script:WebId -McpAppId $script:McpId -RoleScope $script:Rg)
        $r.Ok | Should -BeFalse
        ($r.Diff -join ' ') | Should -Match 'not checked: the roles of id-si-web could not be read'
    }
    It 'the script only reads: every call a GET, the result OK on a compliant install' {
        $f = New-CompliantFake
        $out = & (Join-Path $script:SIRoot 'setup\Test-SIBuiltInAuthStandard.ps1') -ResourceGroupName 'rg-si' -SubscriptionId $script:Sub -Name 'test' -Arm (Get-FakeArm $f) -Graph (Get-FakeGraph $f) -ListImages (Get-FakeImages $f) 6>$null
        $res = @($out | Where-Object { $_ -and $_.PSObject.Properties['Install'] })[0]
        $res.Ok | Should -BeTrue
        $res.Line | Should -BeExactly 'OK    test'
        @($f.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'setup\Test-SIBuiltInAuthStandard.ps1')
        $src | Should -Match 'this check only reads'
    }
}

Describe 'the update''s step' {
    It 'apply after a switched web app: the MCP behind the platform, the leftovers removed, the summary said' {
        $f = New-Fake
        $s = Invoke-Step $f
        $s.McpState | Should -Be 'applied'
        $s.Ok | Should -BeTrue
        @($f.Calls | Where-Object { $_.Method -eq 'PUT' -and $_.Path -like '*ca-si-mcp/authConfigs*' }).Count | Should -Be 1
        @($f.Calls | Where-Object { $_.Method -eq 'PATCH' -and $_.Path -like '*ca-si-management?*' }).Count | Should -Be 1
        (@($s.Lines) + @($s.Warnings)) -match '^built-in sign-in standard: ' | Should -Not -BeNullOrEmpty -Because ("{0} {1}" -f (@($s.Warnings) -join ' / '), $s.Trace)
    }
    It 'a web app that did NOT switch: the MCP and the leftovers are not touched (nothing written)' {
        foreach ($st in 'failed', 'rolled-back', 'needs-support') {
            $f = New-Fake
            $s = Invoke-Step $f 'apply' ([pscustomobject]@{ Ok = $false; State = $st; Lines = @() })
            @(Get-Writes $f).Count | Should -Be 0
            ($s.Lines -join ' ') | Should -Match 'wait until the web app runs Microsoft''s built-in sign-in'
        }
    }
    It 'plan writes nothing at all' {
        $f = New-Fake
        $null = Invoke-Step $f 'plan' ([pscustomobject]@{ Ok = $true; State = 'planned'; Lines = @() })
        @(Get-Writes $f).Count | Should -Be 0
    }
    It 'redirect-only (or off) = the step does nothing' {
        $f = New-Fake
        $arm = Get-FakeArm $f; $graph = Get-FakeGraph $f
        foreach ($m in 'redirect-only', 'off') {
            $r = Invoke-SIBuiltInAuthStandardStep -Arm $arm -Graph $graph -Mode $m -WebAppId $script:WebId -McpAppId $script:McpId
            ($null -eq $r) | Should -BeTrue
        }
        [int]$f.Calls.Count | Should -Be 0
    }
    It 'the updater calls it after the converge with the MCP app''s id and the resource group as the role scope; never for redirect' {
        $body = (Get-Command Invoke-SIUpdaterBuiltInAuthStep).Definition
        $body.IndexOf('& $Converge $args1') | Should -BeLessThan $body.IndexOf('& $Standard $sa')
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')
        $src | Should -Match "SI-BuiltInAuthStandard\.ps1"
        $script:got = $null; $script:n = 0
        $conv = { param($a) [pscustomobject]@{ Ok = $true; State = 'applied'; Lines = @() } }
        $std = { param($a) $script:got = $a; $script:n++; [pscustomobject]@{ Ok = $true; McpState = 'applied'; Lines = @('x'); Warnings = @() } }
        $null = Invoke-SIUpdaterBuiltInAuthStep -Env @{ SI_Updater_BuiltInAuth = 'apply'; SI_UPDATER_WEB_APP = 'ca-si-management'; SI_UPDATER_MCP_APP = 'ca-si-mcp' } -SubscriptionId 'sub1' -ResourceGroup 'rg1' -Converge $conv -Standard $std -Arm { } -Graph { } -Probe { } -ListImages { }
        $script:n | Should -Be 1
        $script:got.McpAppId | Should -BeLike '/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.App/containerApps/*'
        $script:got.RoleScope | Should -Be '/subscriptions/sub1/resourceGroups/rg1'
        $script:got.Mode | Should -Be 'apply'
        $script:got.WebResult.State | Should -Be 'applied'
        $null = Invoke-SIUpdaterBuiltInAuthStep -Env @{ SI_Updater_BuiltInAuth = 'redirect'; SI_UPDATER_WEB_APP = 'ca-si-management' } -SubscriptionId 'sub1' -ResourceGroup 'rg1' -Converge $conv -Standard $std -Arm { } -Graph { }
        $script:n | Should -Be 1
    }
}

Describe 'the MCP''s named open paths (framework SECURE-WEB-1 (4))' {
    BeforeAll {
        function script:McpAuthWith([string[]]$Paths) {
            $a = ConvertTo-Obj (Get-SIBuiltInAuthMcpConfigBody -TenantId $script:Tenant -ClientId $script:Client)
            $a.properties.globalValidation.excludedPaths = @($Paths); $a
        }
        function script:Read-Facts2($f) { Read-SIBuiltInAuthStandardFacts -Arm (Get-FakeArm $f) -Graph (Get-FakeGraph $f) -WebAppId $script:WebId -McpAppId $script:McpId -RoleScope $script:Rg -ListImages (Get-FakeImages $f) }
    }
    It 'each named path carries its reason; the metadata is THE named anonymous exception, "RFC 9728 discovery; no data"' {
        @($script:SIBuiltInAuthMcpOpenPaths.Keys) | Should -Be @('/healthz', '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/*')
        foreach ($k in @($script:SIBuiltInAuthMcpOpenPaths.Keys)) { "$($script:SIBuiltInAuthMcpOpenPaths[$k])".Trim() | Should -Not -BeNullOrEmpty -Because $k }
        $script:SIBuiltInAuthMcpOpenPaths['/.well-known/oauth-protected-resource'] | Should -Match 'RFC 9728 discovery; no data'
        $script:SIBuiltInAuthMcpOpenPaths['/.well-known/oauth-protected-resource/*'] | Should -Match 'RFC 9728 discovery; no data'
        @($script:SIBuiltInAuthMcpExcludedPaths) | Should -Be @($script:SIBuiltInAuthMcpOpenPaths.Keys)
        @($script:SIBuiltInAuthPublicExceptions).Count | Should -Be 0 -Because 'no whole app is an exception'
    }
    It 'exactly the three named paths = no finding; any other path is flagged, a missing one too' {
        @(Get-SIBuiltInAuthMcpOpenPathFindings -Current (McpAuthWith @('/healthz', '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/*'))).Count | Should -Be 0
        $x = @(Get-SIBuiltInAuthMcpOpenPathFindings -Current (McpAuthWith @('/healthz', '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/*', '/mcp')))
        $x.Count | Should -Be 1; $x[0] | Should -Match '^mcp: open paths /mcp \(only the named ones'
        $y = @(Get-SIBuiltInAuthMcpOpenPathFindings -Current (McpAuthWith @('/healthz')))
        $y.Count | Should -Be 1; $y[0] | Should -Match 'named open path\(s\) /\.well-known/oauth-protected-resource,/\.well-known/oauth-protected-resource/\* missing'
        # a look-alike is not the named path (exact; case and a trailing '/' as the converge's compare)
        @(Get-SIBuiltInAuthMcpOpenPathFindings -Current (McpAuthWith @('/healthz', '/.well-known/oauth-protected-resource', '/.well-known/*'))).Count | Should -Be 2
        @(Get-SIBuiltInAuthMcpOpenPathFindings -Current (McpAuthWith @('/healthz/', '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/*'))).Count | Should -Be 0
    }
    It 'the standard''s check flags an extra open path and the old /healthz-only list; the compliant install is OK' {
        $ok = Test-SIBuiltInAuthStandard -Facts (Read-Facts2 (New-Fake -Web (New-WebApp -NoLeftovers) -McpAuth (McpAuthWith @('/healthz', '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/*'))))
        $ok.Ok | Should -BeTrue -Because ($ok.Diff -join ' | ')
        $extra = Test-SIBuiltInAuthStandard -Facts (Read-Facts2 (New-Fake -Web (New-WebApp -NoLeftovers) -McpAuth (McpAuthWith @('/healthz', '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/*', '/api/*'))))
        ($extra.Diff -join ' | ') | Should -Match 'mcp: open paths /api/\*'
        $old = Test-SIBuiltInAuthStandard -Facts (Read-Facts2 (New-Fake -Web (New-WebApp -NoLeftovers) -McpAuth (McpAuthWith @('/healthz'))))
        $old.Ok | Should -BeFalse
        ($old.Diff -join ' | ') | Should -Match 'named open path\(s\) .* missing'
    }
    It 'an MCP on the old /healthz-only list is converged: ONE PUT with all three named paths, read back' {
        $f = New-Fake -McpAuth (McpAuthWith @('/healthz'))
        $r = Invoke-Mcp $f
        $r.State | Should -Be 'applied'
        $put = @($f.Calls | Where-Object { $_.Method -eq 'PUT' -and $_.Path -like '*ca-si-mcp/authConfigs*' })
        $put.Count | Should -Be 1
        @($put[0].Body.properties.globalValidation.excludedPaths) | Should -Be @('/healthz', '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/*')
    }
}

Describe 'the MCP scope mcp.access (SI-McpScope.ps1)' {
    BeforeAll {
        function script:App1($Scopes, $Uris = @("api://$($script:Client)"), $Version = 2) {
            [pscustomobject]@{ id = $script:RegId; identifierUris = @($Uris); api = [pscustomobject]@{ requestedAccessTokenVersion = $Version; oauth2PermissionScopes = @($Scopes); preAuthorizedApplications = @() } }
        }
        $script:Er = [pscustomobject]@{ id = '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a03'; value = 'Estate.Read'; type = 'Admin'; isEnabled = $true }
        $script:Ui = [pscustomobject]@{ id = '8d1c4f0e-3b7a-4e52-9c61-5a2f7e0d9b14'; value = 'user_impersonation'; type = 'Admin'; isEnabled = $true }
    }
    It 'the scope: delegated, admin consent, a stable id, plain-English texts for the administrator and the user' {
        $s = New-SIMcpApiScope
        $s.value | Should -BeExactly 'mcp.access'
        $s.type | Should -Be 'Admin'
        $s.isEnabled | Should -BeTrue
        $s.id | Should -Be '3a3db793-b323-4fd6-a435-49fd163fcdbf'
        foreach ($k in 'adminConsentDisplayName', 'adminConsentDescription', 'userConsentDisplayName', 'userConsentDescription') { "$($s[$k])".Trim() | Should -Not -BeNullOrEmpty -Because $k }
        Get-SIMcpScopeValue -ClientId $script:Client.ToUpperInvariant() | Should -BeExactly "api://$($script:Client)/mcp.access"
    }
    It 'the plan ADDS the scope beside every existing one and sends the whole api back as read (requestedAccessTokenVersion kept)' {
        $p = Get-SIMcpScopePlan -App (App1 @($script:Er, $script:Ui) -Version 2) -ClientId $script:Client
        $p.NeedScope | Should -BeTrue; $p.NeedUri | Should -BeFalse
        $p.Body.Contains('identifierUris') | Should -BeFalse
        @($p.Body.api.oauth2PermissionScopes | ForEach-Object { $_.value }) | Should -Be @('Estate.Read', 'user_impersonation', 'mcp.access')
        $p.Body.api.requestedAccessTokenVersion | Should -Be 2
        # every other member of api is sent back as read -- a list stays a list (an empty one, and a one-item one)
        $p.Body.api.Contains('preAuthorizedApplications') | Should -BeTrue
        (ConvertTo-Json -InputObject $p.Body -Depth 20 -Compress) | Should -Match '"preAuthorizedApplications":\[\]'
        $pa = App1 @($script:Er)
        $pa.api.preAuthorizedApplications = @([pscustomobject]@{ appId = 'ffffffff-1111-2222-3333-444444444444'; delegatedPermissionIds = @($script:Er.id) })
        $pp = Get-SIMcpScopePlan -App $pa -ClientId $script:Client
        (ConvertTo-Json -InputObject $pp.Body -Depth 20 -Compress) | Should -Match '"preAuthorizedApplications":\[\{"appId":"ffffffff-1111-2222-3333-444444444444"'
        # an unset version is not sent (nothing set that was not set)
        (Get-SIMcpScopePlan -App (App1 @($script:Er) -Version $null) -ClientId $script:Client).Body.api.Contains('requestedAccessTokenVersion') | Should -BeFalse
        # in place = nothing to send; the identifier URI is added when missing, every other URI kept
        (Get-SIMcpScopePlan -App (App1 @($script:Er, [pscustomobject](New-SIMcpApiScope))) -ClientId $script:Client).Body | Should -BeNullOrEmpty
        $u = Get-SIMcpScopePlan -App (App1 @([pscustomobject](New-SIMcpApiScope)) -Uris @('https://other.example.test')) -ClientId $script:Client
        @($u.Body.identifierUris) | Should -Be @('https://other.example.test', "api://$($script:Client)")
        # the stable id is taken by another scope: a new id, never a clash
        $clash = Get-SIMcpScopePlan -App (App1 @([pscustomobject]@{ id = '3a3db793-b323-4fd6-a435-49fd163fcdbf'; value = 'other'; isEnabled = $true })) -ClientId $script:Client
        (@($clash.Body.api.oauth2PermissionScopes) | Where-Object { $_.value -eq 'mcp.access' }).id | Should -Not -Be '3a3db793-b323-4fd6-a435-49fd163fcdbf'
    }
    It 'the read-back refuses a lost scope, a changed version, a missing or disabled mcp.access' {
        $before = App1 @($script:Er, $script:Ui) -Version 2
        (Test-SIMcpScopeReadBack -Before $before -After (App1 @($script:Er, $script:Ui, [pscustomobject](New-SIMcpApiScope)) -Version 2) -ClientId $script:Client).Ok | Should -BeTrue
        (Test-SIMcpScopeReadBack -Before $before -After (App1 @($script:Er, [pscustomobject](New-SIMcpApiScope)) -Version 2) -ClientId $script:Client).Why | Should -Match 'user_impersonation that was there is gone'
        (Test-SIMcpScopeReadBack -Before $before -After (App1 @($script:Er, $script:Ui, [pscustomobject](New-SIMcpApiScope)) -Version 1) -ClientId $script:Client).Why | Should -Match 'requestedAccessTokenVersion changed'
        (Test-SIMcpScopeReadBack -Before $before -After $before -ClientId $script:Client).Why | Should -Match 'mcp.access is missing'
        $off = [pscustomobject](New-SIMcpApiScope); $off.isEnabled = $false
        (Test-SIMcpScopeReadBack -Before $before -After (App1 @($script:Er, $script:Ui, $off) -Version 2) -ClientId $script:Client).Why | Should -Match 'not enabled'
    }
    It 'apply: ONE PATCH of the registration''s api, read back, every scope kept; in place = no write; plan = no write' {
        $f = New-Fake -NoMcpScope
        $g = Get-FakeGraph $f
        $r = Invoke-SIMcpScopeConverge -Graph $g -ClientId $script:Client -Mode apply -Sleep { param($s) } -Waits @(0)
        $r.State | Should -Be 'given' -Because ($r.Lines -join ' | ')
        $r.Ok | Should -BeTrue
        $r.Scope | Should -Be "api://$($script:Client)/mcp.access"
        $patch = @($f.Calls | Where-Object { $_.Kind -eq 'graph' -and $_.Method -eq 'PATCH' })
        $patch.Count | Should -Be 1
        @($patch[0].Body.api.oauth2PermissionScopes | ForEach-Object { $_.value }) | Should -Be @('Estate.Read', 'user_impersonation', 'mcp.access')
        $patch[0].Body.api.requestedAccessTokenVersion | Should -Be 2
        @($patch[0].Body.PSObject.Properties.Name) | Should -Not -Contain 'web' -Because 'the web app''s sign-in is never touched'
        # the second run finds it in place
        $n = $f.Calls.Count
        (Invoke-SIMcpScopeConverge -Graph $g -ClientId $script:Client -Mode apply -Sleep { param($s) } -Waits @(0)).State | Should -Be 'in-place'
        @($f.Calls | Select-Object -Skip $n | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
        $f2 = New-Fake -NoMcpScope
        $p = Invoke-SIMcpScopeConverge -Graph (Get-FakeGraph $f2) -ClientId $script:Client -Mode plan
        $p.State | Should -Be 'planned'
        ($p.Lines -join ' ') | Should -Match 'would add .*mcp\.access'
        @($f2.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }
    It 'a refused write = no-rights with the support step; a refused read = no-read (information); never throws' {
        $f = New-Fake -NoMcpScope -GraphRefuseWrite
        $r = Invoke-SIMcpScopeConverge -Graph (Get-FakeGraph $f) -ClientId $script:Client -Mode apply -Sleep { param($s) } -Waits @(0)
        $r.State | Should -Be 'no-rights'; $r.Ok | Should -BeFalse
        $r.Support | Should -Match 'add the delegated scope mcp\.access'
        $deny = { param($m, $u, $b) throw 'HTTP 403 Authorization_RequestDenied' }
        $n = Invoke-SIMcpScopeConverge -Graph $deny -ClientId $script:Client -Mode apply
        $n.State | Should -Be 'no-read'; "$($n.Support)" | Should -BeNullOrEmpty
        (Invoke-SIMcpScopeConverge -Graph { throw 'boom' } -ClientId $script:Client -Mode apply).State | Should -Be 'failed'
        (Invoke-SIMcpScopeConverge -Graph $deny -ClientId 'not-a-guid').State | Should -Be 'failed'
    }
    It 'the update''s step adds it (after a switched web app) and the standard flags a registration without it' {
        $f = New-Fake -NoMcpScope
        $s = Invoke-Step $f
        $s.McpScopeState | Should -Be 'given' -Because ((@($s.Lines) + @($s.Warnings)) -join ' | ')
        @($f.RegScopes | ForEach-Object { $_.value }) | Should -Contain 'mcp.access'
        $f2 = New-Fake -NoMcpScope -GraphRefuseWrite
        $s2 = Invoke-Step $f2
        $s2.McpScopeState | Should -Be 'no-rights'
        ($s2.Warnings -join ' ') | Should -Match 'support step: .*mcp\.access'
        $s2.McpState | Should -Be 'applied' -Because 'a refused scope never stops the MCP''s authentication'
        ($s2.Warnings -join ' ') | Should -Match 'registration: the MCP scope api://.*/mcp\.access is missing'
        # plan: nothing written, the plan line said
        $f3 = New-Fake -NoMcpScope
        $s3 = Invoke-Step $f3 'plan' ([pscustomobject]@{ Ok = $true; State = 'planned'; Lines = @() })
        $s3.McpScopeState | Should -Be 'planned'
        @(Get-Writes $f3).Count | Should -Be 0
    }
}

Describe 'the MCP server keeps its own check' {
    It 'SI.Management.Mcp still validates the bearer itself (Microsoft.Identity.Web) and requires its app roles on /mcp' {
        $p = Get-Content -Raw (Join-Path $script:SIRoot 'pro-management\src\SI.Management.Mcp\Program.cs')
        $p | Should -Match 'AddMicrosoftIdentityWebApi'
        $p | Should -Match 'MapMcp\("/mcp"\)\.RequireAuthorization'
        $p | Should -Match 'MapGet\("/healthz".*AllowAnonymous'
    }
    It 'it serves the RFC 9728 metadata on exactly the named paths, anonymous and not rate limited, and person-only with mcp.access' {
        $p = Get-Content -Raw (Join-Path $script:SIRoot 'pro-management\src\SI.Management.Mcp\Program.cs')
        $d = Get-Content -Raw (Join-Path $script:SIRoot 'pro-management\src\SI.Management.Mcp\McpDiscovery.cs')
        $p | Should -Match 'MapGet\(McpDiscovery\.WellKnownPath,.*AllowAnonymous\(\)\.DisableRateLimiting\(\)'
        $p | Should -Match 'MapGet\(McpDiscovery\.WellKnownPath \+ "/\{\*\*rest\}",.*AllowAnonymous\(\)\.DisableRateLimiting\(\)'
        $p | Should -Match 'RequireAssertion\(ctx => McpCallerRule\.IsPersonMcpToken\(ctx\.User\)\)'
        $d | Should -Match 'WellKnownPath = "/\.well-known/oauth-protected-resource"'
        $d | Should -Match 'ScopeName = "mcp\.access"'
        # the server's named paths are the platform's named open paths (the /* form covers /mcp)
        @($script:SIBuiltInAuthMcpOpenPaths.Keys) | Should -Contain '/.well-known/oauth-protected-resource'
    }
}
