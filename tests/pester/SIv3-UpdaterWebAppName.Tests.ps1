#Requires -Version 5.1
<#
    The web sign-in app owned by the install's updater (framework SECAUDIT-1a item 2), then the web app under its framework
    name ca-si-web -- both steps of container/updater/_shared/SI-UpdaterWebApp.ps1 (Invoke-SIUpdaterSignInAppOwner,
    Invoke-SIUpdaterWebAppMove, Invoke-SIUpdaterWebAppSteps) and their wiring at the end of an update.

    What these tests keep true:
      * STEP 1: already an owner = nothing written; not an owner = the updater adds itself and reads it back; no right = ONE
        plain line naming a Support-app step (never a customer action), nothing else done; no Application.ReadWrite.OwnedBy
        = one line, nothing removed; the proof (a notes change as the owner, read back) comes BEFORE any owner is removed,
        and a failed proof keeps the Support app; only the Invardia Support app is removed (never a person, never another
        identity), and never so that the registration is left without the updater as an owner;
      * STEP 2: a fresh move makes ca-si-web from ca-si-management's spec (same image, the same user-assigned identity,
        settings, secrets re-read through listSecrets, scale, ingress without its address / domains), adds its redirect URI
        beside the old one, reads back health and the sign-in start, waits for a signed-in page load, names the install
        after it, and only then removes the old web app and its redirect URI; a failure at ANY sub-step leaves the old app
        serving and the next update finishes the move; after the switch the new app is never re-made from the old one; a
        custom domain stops before the delete; already moved = a no-op; SI_UPDATER_WEB_APP_MOVE=off = nothing checked.
    Offline: fake Microsoft Graph, fake ARM, fake probes. Script-scope stubs only. Generic names only. NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    . (Join-Path $script:SIRoot 'engine\_shared\SI-InstallNames.ps1')
    $script:C = '33333333-3333-3333-3333-333333333333'   # the sign-in app (AzureAd__ClientId)
    $script:U = '44444444-4444-4444-4444-444444444444'   # the updater's identity (SI_UPDATER_CLIENT_ID)
    $script:S = '55555555-5555-5555-5555-555555555555'   # the Invardia Support app recorded on the install
    $script:T0 = '66666666-6666-6666-6666-666666666666'  # another identity (e.g. a Tier0 one) -- never removed
    $script:OwnedBy = '18a4783c-866b-4cc7-a460-3d5e5662c884'
    $script:Uami = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-web'
    $script:OwnerUpd = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 'sp-upd'; appId = $script:U; displayName = 'id-si-updater' }
    $script:OwnerSup = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 'sp-sup'; appId = $script:S; displayName = 'Invardia Support' }
    $script:OwnerT0 = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 'sp-t0'; appId = $script:T0; displayName = 'Tier0' }
    $script:OwnerPerson = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'user-1'; displayName = 'An administrator' }

    function script:New-GraphState {
        param([object[]]$Owners = @(), [string[]]$Roles = @('Application.ReadWrite.OwnedBy'))
        $o = New-Object System.Collections.Generic.List[object]; foreach ($x in $Owners) { $o.Add($x) }
        $script:GS = [pscustomobject]@{ Owners = $o; Roles = $Roles; Notes = 'a line the customer wrote'; DenyAdd = $false; AddNoReadback = $false; RolesRefused = $false; NoToken = $false; DenyRead = $false
            DenyPatch = $false; DenyDelete = $false; LagReads = 0; OldNotes = $null
            Uris = @('https://ca-si-management.env.example.io/signin-oidc', 'https://other-install.env2.example.io/signin-oidc'); Logout = 'https://ca-si-management.env.example.io/signout-callback-oidc' }
    }
    # ONE fake Microsoft Graph for both steps (the state is $script:GS; $script:Fail = 'redirect' refuses the redirect URI change)
    $script:GraphFn = {
        param([string]$Method, [string]$Uri, $Body)
        $u = $Uri -replace '^https://graph\.microsoft\.com/v1\.0', ''
        $script:Calls.Add(('GRAPH {0} {1}' -f $Method, $u))
        $deny = { param($w) throw ('{0} {1} failed: HTTP 403: Authorization_RequestDenied: Insufficient privileges to complete the operation.' -f $Method, $w) }
        if ($Method -eq 'GET' -and $u -like '/applications(appId=*') { if ($script:GS.DenyRead) { & $deny 'applications' }; return [pscustomobject]@{ id = 'obj-1'; appId = $script:C; displayName = 'SecurityInsight'; notes = $script:GS.Notes } }
        if ($Method -eq 'GET' -and $u -like '/servicePrincipals[?]*') { return [pscustomobject]@{ value = @($script:OwnerUpd) } }
        if ($Method -eq 'GET' -and $u -eq '/applications/obj-1/owners') { return [pscustomobject]@{ value = @($script:GS.Owners.ToArray()) } }
        if ($Method -eq 'POST' -and $u -eq '/applications/obj-1/owners/$ref') {
            if ($script:GS.DenyAdd) { & $deny 'owners' }
            if ([string]$Body['@odata.id'] -ne 'https://graph.microsoft.com/v1.0/directoryObjects/sp-upd') { throw 'wrong owner added' }
            if (-not $script:GS.AddNoReadback) { $script:GS.Owners.Add($script:OwnerUpd) }
            return $null
        }
        if ($Method -eq 'GET' -and $u -eq '/servicePrincipals/sp-upd/appRoleAssignments') {
            if ($script:GS.RolesRefused) { & $deny 'appRoleAssignments' }
            return [pscustomobject]@{ value = @($script:GS.Roles | ForEach-Object { [pscustomobject]@{ appRoleId = $(if ($_ -eq 'Application.ReadWrite.OwnedBy') { $script:OwnedBy } else { 'other-role' }) } }) }
        }
        if ($Method -eq 'PATCH' -and $u -eq '/applications/obj-1') {
            if ($Body.Contains('notes')) { if ($script:GS.DenyPatch) { & $deny 'application' }; $script:GS.OldNotes = $script:GS.Notes; $script:GS.Notes = [string]$Body['notes']; return $null }
            if ($Body.Contains('web')) {
                if ($script:Fail -eq 'redirect') { & $deny 'application' }
                $script:GS.Uris = @($Body['web']['redirectUris']); if ($Body['web'].Contains('logoutUrl')) { $script:GS.Logout = [string]$Body['web']['logoutUrl'] }
                return $null
            }
        }
        if ($Method -eq 'GET' -and $u -like '/applications/obj-1[?]*select=notes') { if ($script:GS.LagReads -gt 0) { $script:GS.LagReads--; return [pscustomobject]@{ notes = $script:GS.OldNotes } }; return [pscustomobject]@{ notes = $script:GS.Notes } }
        if ($Method -eq 'GET' -and $u -like '/applications/obj-1[?]*select=id,web') { return [pscustomobject]@{ id = 'obj-1'; web = [pscustomobject]@{ redirectUris = @($script:GS.Uris); logoutUrl = $script:GS.Logout; implicitGrantSettings = [pscustomobject]@{ enableIdTokenIssuance = $true } } } }
        if ($Method -eq 'DELETE' -and $u -like '/applications/obj-1/owners/*/$ref') {
            if ($script:GS.DenyDelete) { & $deny 'owner' }
            $id = ($u -split '/')[4]
            $keep = @($script:GS.Owners.ToArray() | Where-Object { $_.id -ne $id }); $script:GS.Owners.Clear(); foreach ($k in $keep) { $script:GS.Owners.Add($k) }
            return $null
        }
        throw "unexpected Graph call: $Method $u"
    }
    function script:New-WebApp {
        param([string]$Name, [object[]]$Domains = @(), [string]$IdentityType = 'UserAssigned')
        [pscustomobject]@{
            id = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/containerApps/' + $Name; name = $Name; location = 'westeurope'
            tags = [pscustomobject]@{ product = 'securityinsight' }
            identity = [pscustomobject]@{ type = $IdentityType; userAssignedIdentities = [pscustomobject]@{ $script:Uami = [pscustomobject]@{ principalId = 'p-1'; clientId = 'c-1' } } }
            properties = [pscustomobject]@{
                provisioningState = 'Succeeded'; environmentId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/cae-si'; workloadProfileName = 'Consumption'
                latestRevisionName = ($Name + '--r9'); latestReadyRevisionName = ($Name + '--r9')
                configuration = [pscustomobject]@{ activeRevisionsMode = 'Single'
                    ingress = [pscustomobject]@{ external = $true; targetPort = 8080; fqdn = ($Name + '.env.example.io'); customDomains = @($Domains); traffic = @([pscustomobject]@{ revisionName = ($Name + '--r9'); weight = 100 }) }
                    registries = @([pscustomobject]@{ server = 'reg.example.io'; identity = $script:Uami })
                    secrets = @([pscustomobject]@{ name = 'sql-conn' }, [pscustomobject]@{ name = 'kv-key' }) }
                template = [pscustomobject]@{ revisionSuffix = 'r9'
                    containers = @([pscustomobject]@{ name = 'web'; image = 'reg.example.io/si-management:src-0123456789abcdef'
                        env = @([pscustomobject]@{ name = 'AzureAd__ClientId'; value = $script:C }, [pscustomobject]@{ name = 'AzureAd__TenantId'; value = '11111111-1111-1111-1111-111111111111' }, [pscustomobject]@{ name = 'Sql'; secretRef = 'sql-conn' }) })
                    scale = [pscustomobject]@{ minReplicas = 1; maxReplicas = 2 } } } }
    }
    # the web app behind the shared sign-in front: a second container signin-front (-FrontImage)
    function script:New-FrontWebApp {
        param([string]$Name, [string]$FrontImage = 'reg.example.io/signin-front:1.5.0-src-0123456789abcdef', [object[]]$FrontEnv = @())
        $a = New-WebApp $Name
        $fe = @([pscustomobject]@{ name = 'SIGNIN_CLIENT_ID'; value = $script:C }) + @($FrontEnv)
        $a.properties.template.containers = @(@($a.properties.template.containers) + @([pscustomobject]@{ name = 'signin-front'; image = $FrontImage; env = $fe }))
        $a
    }
    function script:FrontEnvOf($App, [string]$N) { @(@(@($App.properties.template.containers) | Where-Object name -eq 'signin-front')[0].env | Where-Object name -eq $N | ForEach-Object { [string]$_.value }) }
    # ONE fake ARM: the container apps of the resource group ($script:Apps), listSecrets, PUT (ready at once unless
    # $script:Fail = 'ready'), DELETE; $script:Fail = 'list' / 'put' / 'delete' refuses that call
    $script:ArmFake = {
        param([string]$Method, [string]$Path, $Body, [bool]$AllowNotFound)
        $rest = $Path -replace '^.*/providers/Microsoft\.App/containerApps/', ''
        $script:Calls.Add(('ARM {0} {1}' -f $Method, $rest))
        $name = $rest -replace '/listSecrets$', ''
        if ($Method -eq 'GET') { return $script:Apps[$name] }
        if ($Method -eq 'POST' -and $rest -like '*/listSecrets') {
            if ($script:Fail -eq 'list') { throw 'POST listSecrets failed: HTTP 403: AuthorizationFailed' }
            return [pscustomobject]@{ value = @([pscustomobject]@{ name = 'sql-conn'; value = 'Server=sql.example.test;Database=si' }, [pscustomobject]@{ name = 'kv-key'; keyVaultUrl = 'https://kv.example.test/secrets/k'; identity = $script:Uami }) }
        }
        if ($Method -eq 'PUT') {
            $script:PutBody = ConvertTo-Json -InputObject $Body -Depth 60 -Compress
            if ($script:Fail -eq 'put') { throw 'PUT failed: HTTP 400: InvalidRequest' }
            $a = $script:PutBody | ConvertFrom-Json
            $a | Add-Member -NotePropertyName name -NotePropertyValue $name -Force
            $a.properties | Add-Member -NotePropertyName provisioningState -NotePropertyValue 'Succeeded' -Force
            $a.properties | Add-Member -NotePropertyName latestRevisionName -NotePropertyValue ($name + '--r1') -Force
            $a.properties | Add-Member -NotePropertyName latestReadyRevisionName -NotePropertyValue $(if ($script:Fail -eq 'ready') { '' } else { $name + '--r1' }) -Force
            $a.properties.configuration.ingress | Add-Member -NotePropertyName fqdn -NotePropertyValue ($name + '.env.example.io') -Force
            $script:Apps[$name] = $a
            return $null
        }
        if ($Method -eq 'DELETE') { if ($script:Fail -eq 'delete') { throw 'DELETE failed: HTTP 409: ContainerAppOperationInProgress' }; $script:Apps.Remove($name); return $null }
        if ($Method -eq 'PATCH') {
            $script:PatchBody = ConvertTo-Json -InputObject $Body -Depth 60 -Compress
            if ($script:Fail -eq 'movedto') { return $null }   # Azure answers, the change never shows
            $a = ConvertTo-Json -InputObject $script:Apps[$name] -Depth 60 | ConvertFrom-Json
            $a.properties.template = ($script:PatchBody | ConvertFrom-Json).properties.template
            $script:Apps[$name] = $a
            return $null
        }
        throw "unexpected ARM call: $Method $Path"
    }
    $script:ProbeFake = {
        param([string]$Url)
        $script:Calls.Add('PROBE ' + $Url)
        if ($Url -like '*/healthz') { return [pscustomobject]@{ Status = $(if ($script:Fail -eq 'health') { 503 } else { 200 }); Location = '' } }
        $h = ([uri]$Url).Host
        $ru = if ($script:Fail -eq 'signin') { 'https://ca-si-management.env.example.io/signin-oidc' } else { "https://$h/signin-oidc" }
        [pscustomobject]@{ Status = 302; Location = ('https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/authorize?client_id={0}&redirect_uri={1}&response_type=code' -f $script:C, [uri]::EscapeDataString($ru)) }
    }
    function script:Invoke-Move {
        param($Owner = $script:Owner)
        Invoke-SIUpdaterWebAppMove -ResourceGroup 'rg' -SubscriptionId 'sub' -OldName 'ca-si-management' -NewName 'ca-si-web' -CurrentName $script:Cur -Owner $Owner `
            -Arm $script:ArmFake -Graph $script:GraphFn -Probe $script:ProbeFake `
            -SignedInProof { param($n) if ($script:Fail -eq 'proof') { [pscustomobject]@{ Ok = $false; Why = 'no signed-in page load is recorded yet' } } else { [pscustomobject]@{ Ok = $true; Why = '' } } } `
            -SwitchName { param($n) $script:Calls.Add('SWITCH ' + $n); if ($script:Fail -eq 'switch') { return [pscustomobject]@{ Ok = $false; Why = 'the install record could not be written' } }; $script:Cur = $n; [pscustomobject]@{ Ok = $true; Why = '' } } `
            -ReadPublicAddress { $script:PublicAddress } -Log { param($m) $script:Logged.Add($m) } -PollSeconds 0 -TimeoutMinutes 0 `
            -SetPublicAddress { param($from, $to) $script:Calls.Add("SETADDR $from -> $to"); if ($script:Fail -eq 'address') { return [pscustomobject]@{ Ok = $false; Why = 'the public address setting does not read back' } }; $script:PublicAddress = $to; [pscustomobject]@{ Ok = $true; Why = '' } }
    }
    function script:Invoke-Owner {
        param([switch]$ProveWrite, [string]$Support = $script:S)
        Invoke-SIUpdaterSignInAppOwner -WebApp 'ca-si-management' -App (New-WebApp 'ca-si-management') -UpdaterClientId $script:U -SupportAppId $Support -ProveWrite:$ProveWrite -Graph $script:GraphFn -WhoAmI $script:WhoAmI
    }
    $script:WhoAmI = { if ($script:GS.NoToken) { $null } else { [pscustomobject]@{ ObjectId = 'sp-upd'; AppId = $script:U; Roles = @($script:GS.Roles) } } }
    function script:Writes { @($script:Calls | Where-Object { $_ -match '^(GRAPH|ARM) (POST|PATCH|PUT|DELETE) ' -and $_ -notlike '*listSecrets' }) }
    function script:OwnerIds { @($script:GS.Owners.ToArray() | ForEach-Object { [string]$_.id }) }
}

Describe 'step 1: the web sign-in app owned by the install''s updater' {
    BeforeEach { $script:Calls = New-Object System.Collections.Generic.List[string]; $script:Fail = '' }
    It 'already an owner, nothing to prove or remove: owned, nothing written, nothing said' {
        New-GraphState -Owners @($script:OwnerUpd)
        $r = Invoke-Owner
        $r.State | Should -Be 'owned'; $r.Owned | Should -BeTrue; $r.Text | Should -BeNullOrEmpty
        @(Writes).Count | Should -Be 0
    }
    It 'not an owner: the updater adds itself, reads it back, proves it may change the app, then removes the Support app (read back)' {
        New-GraphState -Owners @($script:OwnerSup)
        $r = Invoke-Owner
        $r.State | Should -Be 'owned'; $r.Owned | Should -BeTrue
        $r.Text | Should -Match 'owned by this install''s updater id-si-updater'
        $r.Text | Should -Match 'Support app is no longer an owner \(read back\)'
        @(OwnerIds) | Should -Be @('sp-upd')
        $w = @(Writes)
        $w[0] | Should -Be 'GRAPH POST /applications/obj-1/owners/$ref'
        $w[1] | Should -Be 'GRAPH PATCH /applications/obj-1'
        $w[2] | Should -Be 'GRAPH DELETE /applications/obj-1/owners/sp-sup/$ref'
        $script:GS.Notes | Should -Match '^a line the customer wrote\nSecurityInsight updater: may change this registration as its owner \(checked '
    }
    It 'no right to add itself: ONE plain line naming a Support-app step -- never a customer action -- and nothing else done' {
        New-GraphState -Owners @($script:OwnerSup); $script:GS.DenyAdd = $true
        $r = Invoke-Owner
        $r.State | Should -Be 'needs-support-step'; $r.Owned | Should -BeFalse
        $r.Text | Should -Be ("ca-si-management: its sign-in app ($($script:C)) is not owned by this install's updater id-si-updater ($($script:U)) yet, and the updater may not add itself -- a Support-app step adds the updater as an owner; the next update takes it from there")
        $r.Text | Should -Not -Match "`n|Run |download|#\d{3}"
        @(OwnerIds) | Should -Be @('sp-sup') -Because 'the only owner stays: never ownerless'
        @(Writes) | Should -Be @('GRAPH POST /applications/obj-1/owners/$ref')
    }
    It 'the registration may not even be read (not an owner, no directory right): the same Support-app line, nothing written' {
        New-GraphState -Owners @($script:OwnerSup); $script:GS.DenyRead = $true
        $r = Invoke-Owner
        $r.State | Should -Be 'needs-support-step'
        $r.Text | Should -Match 'a Support-app step adds the updater as an owner'
        @(Writes).Count | Should -Be 0
    }
    It 'who the updater is and what it holds come from its own token; without one, from the directory' {
        New-GraphState -Owners @($script:OwnerUpd, $script:OwnerSup) -Roles @('Application.ReadWrite.All')
        (Invoke-Owner).State | Should -Be 'owned' -Because 'Application.ReadWrite.All covers it too'
        New-GraphState -Owners @($script:OwnerUpd) -Roles @(); $script:GS.NoToken = $true
        (Invoke-Owner -ProveWrite).State | Should -Be 'needs-permission' -Because 'the directory says no Application.ReadWrite.OwnedBy'
        @($script:Calls) | Should -Contain 'GRAPH GET /servicePrincipals/sp-upd/appRoleAssignments'
    }
    It 'the token is read: oid, appid and roles (a SecureString or plain), nothing when it carries no oid' {
        $enc = { param($o) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Compress -InputObject $o))).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        $jwt = '{0}.{1}.sig' -f (& $enc @{ alg = 'none' }), (& $enc @{ oid = 'sp-upd'; appid = $script:U; roles = @('Application.ReadWrite.OwnedBy') })
        $i = Get-SIUpdaterGraphIdentity -Token { $jwt }
        $i.ObjectId | Should -Be 'sp-upd'; $i.AppId | Should -Be $script:U; @($i.Roles) | Should -Be @('Application.ReadWrite.OwnedBy')
        (Get-SIUpdaterGraphIdentity -Token { ConvertTo-SecureString $jwt -AsPlainText -Force }).ObjectId | Should -Be 'sp-upd'
        $none = '{0}.{1}.sig' -f (& $enc @{ alg = 'none' }), (& $enc @{ appid = $script:U })
        Get-SIUpdaterGraphIdentity -Token { $none } | Should -BeNullOrEmpty
        Get-SIUpdaterGraphIdentity -Token { throw 'no token' } | Should -BeNullOrEmpty
    }
    It 'added but it does not read back: nothing more is done, the Support app stays' {
        New-GraphState -Owners @($script:OwnerSup); $script:GS.AddNoReadback = $true
        $r = Invoke-Owner
        $r.State | Should -Be 'unknown'; $r.Owned | Should -BeFalse
        @(OwnerIds) | Should -Be @('sp-sup')
        @(Writes | Where-Object { $_ -match 'PATCH|DELETE' }).Count | Should -Be 0
    }
    It 'an owner without Application.ReadWrite.OwnedBy: one line, a Support-app step grants it; nothing changed or removed' {
        New-GraphState -Owners @($script:OwnerUpd, $script:OwnerSup) -Roles @()
        $r = Invoke-Owner
        $r.State | Should -Be 'needs-permission'; $r.Owned | Should -BeFalse
        $r.Text | Should -Match 'Application\.ReadWrite\.OwnedBy -- a Support-app step grants it'
        @(Writes).Count | Should -Be 0
        @(OwnerIds) | Should -Be @('sp-upd', 'sp-sup')
    }
    It 'the proof fails (the notes change is refused): the Support app is NOT removed' {
        New-GraphState -Owners @($script:OwnerUpd, $script:OwnerSup); $script:GS.DenyPatch = $true
        $r = Invoke-Owner
        $r.State | Should -Be 'proof-failed'; $r.Owned | Should -BeFalse
        $r.Text | Should -Match 'could not prove it may change its sign-in app'
        $r.Text | Should -Match 'the Support app stays an owner'
        @(Writes | Where-Object { $_ -like '*DELETE*' }).Count | Should -Be 0
        @(OwnerIds) | Should -Be @('sp-upd', 'sp-sup')
    }
    It 'the proof''s read-back lags (Entra eventually consistent, live 2026-11-07): read again after a wait, then owned and the Support app removed' {
        New-GraphState -Owners @($script:OwnerUpd, $script:OwnerSup); $script:GS.LagReads = 2
        $slept = New-Object System.Collections.Generic.List[int]
        $r = Invoke-SIUpdaterSignInAppOwner -WebApp 'ca-si-management' -App (New-WebApp 'ca-si-management') -UpdaterClientId $script:U -SupportAppId $script:S -Graph $script:GraphFn -WhoAmI $script:WhoAmI -ProofSleep { param($s) $slept.Add($s) }
        $r.State | Should -Be 'owned'; $r.Owned | Should -BeTrue
        @($slept) | Should -Be @(3, 5) -Because 'two stale reads, then the change reads back'
        @(OwnerIds) | Should -Be @('sp-upd')
    }
    It 'the proof''s read-back never shows the change: proof-failed after the last wait, the Support app stays' {
        New-GraphState -Owners @($script:OwnerUpd, $script:OwnerSup); $script:GS.LagReads = 99
        $r = Invoke-SIUpdaterSignInAppOwner -WebApp 'ca-si-management' -App (New-WebApp 'ca-si-management') -UpdaterClientId $script:U -SupportAppId $script:S -Graph $script:GraphFn -WhoAmI $script:WhoAmI -ProofSleep { param($s) }
        $r.State | Should -Be 'proof-failed'
        @(OwnerIds) | Should -Be @('sp-upd', 'sp-sup')
    }
    It 'the app role assignments cannot be read: the proof decides (it passes -> owned)' {
        New-GraphState -Owners @($script:OwnerUpd, $script:OwnerSup); $script:GS.RolesRefused = $true; $script:GS.NoToken = $true
        (Invoke-Owner).State | Should -Be 'owned'
        @(OwnerIds) | Should -Be @('sp-upd')
    }
    It 'only the Support app is removed: a person and any other identity stay owners' {
        New-GraphState -Owners @($script:OwnerPerson, $script:OwnerT0, $script:OwnerUpd, $script:OwnerSup)
        (Invoke-Owner).State | Should -Be 'owned'
        @(OwnerIds) | Should -Be @('user-1', 'sp-t0', 'sp-upd')
    }
    It 'the removal is refused: still owned and proven (the move may go on), the Support app stays, said once' {
        New-GraphState -Owners @($script:OwnerUpd, $script:OwnerSup); $script:GS.DenyDelete = $true
        $r = Invoke-Owner
        $r.State | Should -Be 'owned-support-kept'; $r.Owned | Should -BeTrue
        $r.Text | Should -Match 'the Support app is still an owner'
        @(OwnerIds) | Should -Be @('sp-upd', 'sp-sup')
    }
    It 'no Support app recorded: no owner is removed; the proof still runs when the web app has to move' {
        New-GraphState -Owners @($script:OwnerUpd, $script:OwnerSup)
        $r = Invoke-Owner -ProveWrite -Support ''
        $r.State | Should -Be 'owned'; $r.Owned | Should -BeTrue
        @(OwnerIds) | Should -Be @('sp-upd', 'sp-sup')
        @(Writes) | Should -Be @('GRAPH PATCH /applications/obj-1')
    }
    It 'the notes are never cut: a line that does not fit leaves them as they are (the write is the proof)' {
        $long = 'x' * 1000
        New-SIUpdaterOwnerNotes -Notes $long | Should -Be $long
        $n1 = New-SIUpdaterOwnerNotes -Notes "keep me`nSecurityInsight updater: may change this registration as its owner (checked 2020-01-01T00:00:00Z)" -NowUtc ([datetime]'2026-11-07T10:00:00Z')
        $n1 | Should -Be "keep me`nSecurityInsight updater: may change this registration as its owner (checked 2026-11-07T10:00:00Z)"
    }
    It 'no web app sign-in (no AzureAd__ClientId): nothing at all; a Graph that cannot be read: one line, nothing written' {
        New-GraphState -Owners @($script:OwnerUpd)
        $bare = [pscustomobject]@{ properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'web'; env = @() }) } } }
        $r = Invoke-SIUpdaterSignInAppOwner -App $bare -UpdaterClientId $script:U -Graph $script:GraphFn -WhoAmI $script:WhoAmI
        $r.State | Should -Be ''; $r.Text | Should -BeNullOrEmpty
        $r2 = Invoke-SIUpdaterSignInAppOwner -WebApp 'ca-si-web' -App (New-WebApp 'ca-si-web') -UpdaterClientId $script:U -Graph { throw 'HTTP 500: server error' } -WhoAmI $script:WhoAmI
        $r2.State | Should -Be 'unknown'; $r2.Text | Should -Match 'could not be read'
    }
}

Describe 'step 2: the web app moves to ca-si-web' {
    BeforeEach {
        $script:Calls = New-Object System.Collections.Generic.List[string]; $script:Logged = New-Object System.Collections.Generic.List[string]
        $script:Fail = ''; $script:PublicAddress = ''; $script:Cur = 'ca-si-management'; $script:PutBody = ''
        $script:Apps = @{ 'ca-si-management' = (New-WebApp 'ca-si-management') }
        New-GraphState -Owners @($script:OwnerUpd)
        $script:Owner = [pscustomobject]@{ Owned = $true; ObjectId = 'obj-1'; ClientId = $script:C }
    }
    It 'a fresh move: made from the old app''s spec, redirect URI beside the old one, read back, named, and only then the old app removed' {
        $r = Invoke-Move
        $r.State | Should -Be 'moved'
        $r.Text | Should -Match '^ca-si-management moved to ca-si-web: '
        $script:Apps.ContainsKey('ca-si-management') | Should -BeFalse
        $script:Apps.ContainsKey('ca-si-web') | Should -BeTrue
        $script:Cur | Should -Be 'ca-si-web'
        # the order: listSecrets, PUT, the redirect URI added, health, sign-in start, the name switched, the old app removed, its URI removed
        $c = @($script:Calls)
        $i = { param($p) [array]::IndexOf($c, @($c | Where-Object { $_ -like $p })[0]) }
        (& $i 'ARM POST ca-si-management/listSecrets') | Should -BeLessThan (& $i 'ARM PUT ca-si-web')
        (& $i 'ARM PUT ca-si-web') | Should -BeLessThan (& $i 'GRAPH PATCH /applications/obj-1')
        (& $i 'GRAPH PATCH /applications/obj-1') | Should -BeLessThan (& $i 'PROBE https://ca-si-web.env.example.io/healthz')
        (& $i 'PROBE https://ca-si-web.env.example.io/') | Should -BeLessThan (& $i 'SWITCH ca-si-web')
        (& $i 'SWITCH ca-si-web') | Should -BeLessThan (& $i 'ARM DELETE ca-si-management')
        # the sign-in app: the new address added, the old one removed, another install's address untouched, sign-out moved
        $script:GS.Uris | Should -Be @('https://other-install.env2.example.io/signin-oidc', 'https://ca-si-web.env.example.io/signin-oidc')
        $script:GS.Logout | Should -Be 'https://ca-si-web.env.example.io/signout-callback-oidc'
    }
    It 'the new app''s spec: the same image, the SAME user-assigned identity, environment, settings, secrets re-read, scale -- no address, no domain, no revision suffix' {
        $null = Invoke-Move
        $b = $script:PutBody | ConvertFrom-Json
        $b.location | Should -Be 'westeurope'
        $b.identity.type | Should -Be 'UserAssigned'
        @($b.identity.userAssignedIdentities.PSObject.Properties.Name) | Should -Be @($script:Uami)
        $b.properties.environmentId | Should -Be '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/cae-si'
        $b.properties.workloadProfileName | Should -Be 'Consumption'
        $b.properties.template.containers[0].image | Should -Be 'reg.example.io/si-management:src-0123456789abcdef'
        @($b.properties.template.containers[0].env | ForEach-Object { $_.name }) | Should -Be @('AzureAd__ClientId', 'AzureAd__TenantId', 'Sql')
        $b.properties.template.scale.maxReplicas | Should -Be 2
        $b.properties.template.PSObject.Properties['revisionSuffix'] | Should -BeNullOrEmpty
        ($b.properties.configuration.secrets | Where-Object name -eq 'sql-conn').value | Should -Be 'Server=sql.example.test;Database=si'
        ($b.properties.configuration.secrets | Where-Object name -eq 'kv-key').keyVaultUrl | Should -Be 'https://kv.example.test/secrets/k'
        $b.properties.configuration.ingress.PSObject.Properties['fqdn'] | Should -BeNullOrEmpty
        $b.properties.configuration.ingress.PSObject.Properties['customDomains'] | Should -BeNullOrEmpty
        $b.properties.configuration.ingress.targetPort | Should -Be 8080
        @($b.properties.configuration.ingress.traffic)[0].latestRevision | Should -BeTrue
        $b.properties.configuration.registries[0].identity | Should -Be $script:Uami
    }
    It 'resumed after a failure at <Fail>: the old app keeps serving, nothing removed; the next update finishes the move' -TestCases @(
        @{ Fail = 'list';     State = 'create-failed' }
        @{ Fail = 'put';      State = 'create-failed' }
        @{ Fail = 'ready';    State = 'create-failed' }
        @{ Fail = 'redirect'; State = 'redirect-failed' }
        @{ Fail = 'health';   State = 'signin-failed' }
        @{ Fail = 'signin';   State = 'signin-failed' }
        @{ Fail = 'proof';    State = 'awaiting-signin-proof' }
        @{ Fail = 'switch';   State = 'switch-failed' }
        @{ Fail = 'delete';   State = 'delete-failed' }
    ) {
        param($Fail, $State)
        $script:Fail = $Fail
        $r = Invoke-Move
        $r.State | Should -Be $State
        $script:Apps.ContainsKey('ca-si-management') | Should -BeTrue -Because 'any failure leaves the old app serving'
        $r.Text | Should -Not -Match "`n|#\d{3}"
        if ($Fail -notin 'delete', 'proof') {
            $script:Cur | Should -Be 'ca-si-management' -Because 'the install is named after the new app only after every read-back'
            @($script:GS.Uris) | Should -Contain 'https://ca-si-management.env.example.io/signin-oidc'
        }
        # the next update
        $script:Fail = ''; $script:Calls.Clear()
        $r2 = Invoke-Move
        $r2.State | Should -Be 'moved'
        $script:Apps.ContainsKey('ca-si-management') | Should -BeFalse
        $script:Cur | Should -Be 'ca-si-web'
        @($script:GS.Uris) | Should -Not -Contain 'https://ca-si-management.env.example.io/signin-oidc'
        @($script:GS.Uris) | Should -Contain 'https://ca-si-web.env.example.io/signin-oidc'
        if ($Fail -in 'delete', 'proof') { @($script:Calls | Where-Object { $_ -like 'ARM PUT *' }).Count | Should -Be 0 -Because 'after the switch the new app is never made again from the old one' }
    }
    It 'a custom domain on the old app: said, and it stops BEFORE the switch and the delete' {
        $script:Apps['ca-si-management'] = New-WebApp 'ca-si-management' -Domains @([pscustomobject]@{ name = 'si.install-a.example'; bindingType = 'SniEnabled' })
        $r = Invoke-Move
        $r.State | Should -Be 'custom-domain'
        $r.Text | Should -Match 'custom domain si\.install-a\.example -- the update does not move a domain: a Support-app step moves it'
        $script:Apps.ContainsKey('ca-si-management') | Should -BeTrue
        @($script:Calls | Where-Object { $_ -like 'SWITCH *' -or $_ -like 'ARM DELETE *' }).Count | Should -Be 0
        $script:Cur | Should -Be 'ca-si-management'
    }
    It 'the public address setting is the old app''s default address: rewritten in the switch (before the name), then the move finishes' {
        $script:PublicAddress = 'https://ca-si-management.env.example.io/'
        (Invoke-Move).State | Should -Be 'moved'
        $script:PublicAddress | Should -Be 'https://ca-si-web.env.example.io'
        $c = @($script:Calls)
        $ia = [array]::IndexOf($c, 'SETADDR https://ca-si-management.env.example.io -> https://ca-si-web.env.example.io')
        $ia | Should -BeGreaterThan -1
        $ia | Should -BeLessThan ([array]::IndexOf($c, 'SWITCH ca-si-web'))
        $ia | Should -BeGreaterThan ([array]::IndexOf($c, 'PROBE https://ca-si-web.env.example.io/'))
    }
    It 'the public address setting names a custom host: left as it is, one line, it stops BEFORE the switch and the delete' {
        $script:PublicAddress = 'https://si.install-a.example'
        $r = Invoke-Move
        $r.State | Should -Be 'public-address'
        $r.Text | Should -Match 'names a custom host \(https://si\.install-a\.example\) -- the update does not change it'
        $r.Text | Should -Not -Match "`n"
        $script:PublicAddress | Should -Be 'https://si.install-a.example'
        $script:Apps.ContainsKey('ca-si-management') | Should -BeTrue
        @($script:Calls | Where-Object { $_ -like 'SWITCH *' -or $_ -like 'SETADDR *' -or $_ -like 'ARM DELETE *' }).Count | Should -Be 0
    }
    It 'the rewrite does not read back: nothing is switched or removed; the next update finishes' {
        $script:PublicAddress = 'https://ca-si-management.env.example.io'; $script:Fail = 'address'
        (Invoke-Move).State | Should -Be 'switch-failed'
        $script:Cur | Should -Be 'ca-si-management'
        $script:Apps.ContainsKey('ca-si-management') | Should -BeTrue
        $script:Fail = ''
        (Invoke-Move).State | Should -Be 'moved'
        $script:PublicAddress | Should -Be 'https://ca-si-web.env.example.io'
    }
    It 'resumed after the switch with a custom host set meanwhile: it stops before the delete' {
        $script:Apps['ca-si-web'] = New-WebApp 'ca-si-web'; $script:Cur = 'ca-si-web'; $script:PublicAddress = 'https://si.install-a.example'
        (Invoke-Move).State | Should -Be 'public-address'
        $script:Apps.ContainsKey('ca-si-management') | Should -BeTrue
    }
    It 'the public address plan: not set / new address = none, the old default address = rewrite, anything else = custom' {
        Get-SIUpdaterPublicAddressPlan -Value '' -OldFqdn 'old.env.example.io' -NewFqdn 'new.env.example.io' | Should -Be 'none'
        Get-SIUpdaterPublicAddressPlan -Value 'https://new.env.example.io/' -OldFqdn 'old.env.example.io' -NewFqdn 'new.env.example.io' | Should -Be 'none'
        Get-SIUpdaterPublicAddressPlan -Value 'HTTPS://old.env.example.io' -OldFqdn 'old.env.example.io' -NewFqdn 'new.env.example.io' | Should -Be 'rewrite'
        Get-SIUpdaterPublicAddressPlan -Value 'https://old.env.example.io/x' -OldFqdn 'old.env.example.io' -NewFqdn 'new.env.example.io' | Should -Be 'custom'
        Get-SIUpdaterPublicAddressPlan -Value 'https://si.install-a.example' -OldFqdn 'old.env.example.io' -NewFqdn 'new.env.example.io' | Should -Be 'custom'
    }
    It 'Set-SIUpdaterPublicAddress: one guarded update with its change-log row, read back; a value changed meanwhile is kept' {
        $st = @{ Setting = '"https://old.env.example.io"'; Sqls = (New-Object System.Collections.Generic.List[object]) }
        $store = [pscustomobject]@{ Invoke = { param($sql, $p, $mode)
            $st.Sqls.Add([pscustomobject]@{ Sql = $sql; Mode = $mode })
            if ($mode -eq 'nonquery') { if ([string]$p['OldJson'] -eq $st.Setting) { $st.Setting = [string]$p['ValueJson'] }; return }
            , @([pscustomobject]@{ Value = $st.Setting }) }.GetNewClosure() }
        $r1 = Set-SIUpdaterPublicAddress -Store $store -From 'https://old.env.example.io' -To 'https://new.env.example.io'
        $r1.Why | Should -BeNullOrEmpty
        $r1.Ok | Should -BeTrue
        $st.Setting | Should -Be '"https://new.env.example.io"'
        $w = @($st.Sqls | Where-Object Mode -eq 'nonquery')
        $w.Count | Should -Be 1
        $w[0].Sql | Should -Match 'AND ValueJson = @OldJson'
        $w[0].Sql | Should -Match 'INSERT cfg\.ChangeLog'
        $st.Setting = '"https://si.install-a.example"'
        $r = Set-SIUpdaterPublicAddress -Store $store -From 'https://old.env.example.io' -To 'https://new.env.example.io'
        $r.Ok | Should -BeFalse; $r.Why | Should -Match 'changed in the meantime'
        $st.Setting | Should -Be '"https://si.install-a.example"'
    }
    It 'the switch comes BEFORE the wait for the first sign-in (the old app then redirects there); no sign-in yet = the old app stays' {
        $script:Fail = 'proof'
        $r = Invoke-Move
        $r.State | Should -Be 'awaiting-signin-proof'
        $r.Text | Should -Match 'sends every page request there and is removed after the first sign-in on ca-si-web'
        $script:Cur | Should -Be 'ca-si-web'
        $script:Apps.ContainsKey('ca-si-management') | Should -BeTrue
        @($script:Calls | Where-Object { $_ -like 'ARM DELETE *' }).Count | Should -Be 0
    }
    It 'the SWITCH points the old app''s sign-in front at the new address (SIGNIN_FRONT_MOVED_TO), read back -- AFTER the switch, BEFORE the wait for the first sign-in' {
        $script:Apps['ca-si-management'] = New-FrontWebApp 'ca-si-management'
        $script:Fail = 'proof'
        $r = Invoke-Move
        $r.State | Should -Be 'awaiting-signin-proof'
        $r.Text | Should -Not -Match 'could not be pointed'
        $old = $script:Apps['ca-si-management']
        @(FrontEnvOf $old 'SIGNIN_FRONT_MOVED_TO') | Should -Be @('https://ca-si-web.env.example.io')
        @(FrontEnvOf $old 'SIGNIN_CLIENT_ID') | Should -Be @($script:C) -Because 'every other setting of the front is kept'
        @($old.properties.template.containers)[0].image | Should -Be 'reg.example.io/si-management:src-0123456789abcdef' -Because 'the web container is untouched'
        @(FrontEnvOf $script:Apps['ca-si-web'] 'SIGNIN_FRONT_MOVED_TO').Count | Should -Be 0 -Because 'the new app never redirects'
        $c = @($script:Calls)
        [array]::IndexOf($c, 'SWITCH ca-si-web') | Should -BeLessThan ([array]::IndexOf($c, 'ARM PATCH ca-si-management'))
        @($script:Logged) | Should -Contain 'ca-si-management: its sign-in front sends every request to https://ca-si-web.env.example.io before any sign-in (read back)'
        # the next update: already in place -> not written again; then the proof -> the old app is removed
        $script:Calls.Clear(); $script:Fail = ''
        (Invoke-Move).State | Should -Be 'moved'
        @($script:Calls | Where-Object { $_ -eq 'ARM PATCH ca-si-management' }).Count | Should -Be 0
        $script:Apps.ContainsKey('ca-si-management') | Should -BeFalse
    }
    It 'resumed after an earlier switch: an old app whose front runs an older image gets the new app''s front image with the setting' {
        $script:Apps['ca-si-management'] = New-FrontWebApp 'ca-si-management' -FrontImage 'reg.example.io/signin-front:1.4.5-src-aaaaaaaaaaaaaaaa'
        $script:Apps['ca-si-web'] = New-FrontWebApp 'ca-si-web'; $script:Cur = 'ca-si-web'; $script:Fail = 'proof'
        (Invoke-Move).State | Should -Be 'awaiting-signin-proof'
        $f = @(@($script:Apps['ca-si-management'].properties.template.containers) | Where-Object name -eq 'signin-front')[0]
        $f.image | Should -Be 'reg.example.io/signin-front:1.5.0-src-0123456789abcdef'
        @(FrontEnvOf $script:Apps['ca-si-management'] 'SIGNIN_FRONT_MOVED_TO') | Should -Be @('https://ca-si-web.env.example.io')
    }
    It 'the setting does not read back: said in the line, nothing stops (the web app''s own redirect stays the fallback)' {
        $script:Apps['ca-si-management'] = New-FrontWebApp 'ca-si-management'
        $script:Fail = 'movedto'
        $mv = Set-SIUpdaterOldWebAppMovedTo -Arm $script:ArmFake -OldPath '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/containerApps/ca-si-management' -NewPath '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/containerApps/ca-si-web' -NewFqdn 'ca-si-web.env.example.io' -Tries 3 -PollSeconds 0
        $mv.Ok | Should -BeFalse; $mv.Why | Should -Match 'does not read back with SIGNIN_FRONT_MOVED_TO = https://ca-si-web.env.example.io'
        @($script:Calls | Where-Object { $_ -eq 'ARM GET ca-si-management' }).Count | Should -Be 4 -Because 'one read, then three read-backs'
    }
    It 'an old app without a sign-in front: nothing written (its own redirect answers); the patch keeps every other container' {
        $nf = Set-SIUpdaterOldWebAppMovedTo -Arm $script:ArmFake -OldPath '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/containerApps/ca-si-management' -NewPath '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/containerApps/ca-si-web' -NewFqdn 'ca-si-web.env.example.io' -PollSeconds 0
        $nf.Changed | Should -BeFalse; $nf.Ok | Should -BeTrue; $nf.Why | Should -Match 'no sign-in front'
        @($script:Calls | Where-Object { $_ -like 'ARM PATCH *' }).Count | Should -Be 0
        New-SIUpdaterMovedToPatchBody -App (New-WebApp 'ca-si-management') -BaseUrl 'https://ca-si-web.env.example.io' | Should -BeNullOrEmpty
        $done = New-FrontWebApp 'ca-si-management' -FrontEnv @([pscustomobject]@{ name = 'SIGNIN_FRONT_MOVED_TO'; value = 'https://ca-si-web.env.example.io' })
        New-SIUpdaterMovedToPatchBody -App $done -BaseUrl 'https://ca-si-web.env.example.io' | Should -BeNullOrEmpty
        $b = New-SIUpdaterMovedToPatchBody -App (New-FrontWebApp 'ca-si-management') -BaseUrl 'https://ca-si-web.env.example.io'
        @($b.properties.template.containers).Count | Should -Be 2
        $b.properties.template.PSObject.Properties['revisionSuffix'] | Should -BeNullOrEmpty
        @(@($b.properties.template.containers)[0].env | ForEach-Object { $_.name }) | Should -Be @('AzureAd__ClientId', 'AzureAd__TenantId', 'Sql')
    }
    It 'the new app made from an old one that already redirects never carries SIGNIN_FRONT_MOVED_TO' {
        $old = New-FrontWebApp 'ca-si-management' -FrontEnv @([pscustomobject]@{ name = 'SIGNIN_FRONT_MOVED_TO'; value = 'https://ca-si-web.env.example.io' })
        $b = New-SIUpdaterWebAppCopyBody -App $old -Secrets @([pscustomobject]@{ name = 'sql-conn'; value = 'x' }, [pscustomobject]@{ name = 'kv-key'; keyVaultUrl = 'https://kv.example.test/secrets/k'; identity = $script:Uami })
        (ConvertTo-Json -InputObject $b -Depth 60) | Should -Not -Match 'SIGNIN_FRONT_MOVED_TO'
        (ConvertTo-Json -InputObject $b -Depth 60) | Should -Match 'SIGNIN_CLIENT_ID'
    }
    It 'the first sign-in proof is the new app''s OWN row (one row per app): the old app''s row proves nothing, nothing is ever deleted' {
        $st = @{ Rows = @{ 'WebAppSignedIn:ca-si-management' = '{"app":"ca-si-management","at":"2026-11-07T09:00:00Z"}' }; Writes = 0 }
        $store = [pscustomobject]@{ Invoke = { param($sql, $p, $mode)
            if ($mode -ne 'reader') { $st.Writes++; return }
            $v = $st.Rows[[string]$p['Name']]; if ($v) { , @([pscustomobject]@{ Value = $v }) } else { , @() } }.GetNewClosure() }
        $r = Read-SIUpdaterWebSignedInProof -Store $store -Name 'ca-si-web'
        $r.Ok | Should -BeFalse; $r.Why | Should -Match 'nobody has signed in on it yet'
        $st.Rows['WebAppSignedIn:ca-si-web'] = '{"app":"ca-si-web","at":"2026-11-07T10:00:00Z"}'
        (Read-SIUpdaterWebSignedInProof -Store $store -Name 'ca-si-web').Ok | Should -BeTrue
        $st.Writes | Should -Be 0 -Because 'the updater never deletes or writes a sign-in row'
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterWebApp.ps1')) | Should -Not -Match "DELETE FROM cfg\.InstallState"
    }
    It 'already moved (ca-si-web runs, ca-si-management does not): a no-op -- nothing written, nothing said' {
        $script:Apps = @{ 'ca-si-web' = (New-WebApp 'ca-si-web') }; $script:Cur = 'ca-si-web'
        $script:GS.Uris = @('https://ca-si-web.env.example.io/signin-oidc'); $script:GS.Logout = 'https://ca-si-web.env.example.io/signout-callback-oidc'
        $r = Invoke-Move
        $r.State | Should -Be 'moved'; $r.Text | Should -BeNullOrEmpty
        @(Writes).Count | Should -Be 0
        @($script:Calls | Where-Object { $_ -like 'SWITCH *' }).Count | Should -Be 0
    }
    It 'already moved, but the install still names the old app: named after ca-si-web, nothing else' {
        $script:Apps = @{ 'ca-si-web' = (New-WebApp 'ca-si-web') }
        $script:GS.Uris = @('https://ca-si-web.env.example.io/signin-oidc'); $script:GS.Logout = 'https://ca-si-web.env.example.io/signout-callback-oidc'
        $r = Invoke-Move
        $r.State | Should -Be 'moved'; $r.Text | Should -Match 'the install record names ca-si-web now'
        $script:Cur | Should -Be 'ca-si-web'
        @(Writes).Count | Should -Be 0
    }
    It 'the updater does not own the sign-in app yet: nothing is made, the old app keeps serving' {
        $r = Invoke-Move -Owner ([pscustomobject]@{ Owned = $false; ObjectId = 'obj-1'; ClientId = $script:C })
        $r.State | Should -Be 'waiting-owner'
        @($script:Calls | Where-Object { $_ -like 'ARM PUT *' -or $_ -like 'ARM POST *' }).Count | Should -Be 0
    }
    It 'a web app with a system-assigned identity or a secret that does not come back is not copied' {
        { New-SIUpdaterWebAppCopyBody -App (New-WebApp 'ca-si-management' -IdentityType 'SystemAssigned, UserAssigned') -Secrets @() } | Should -Throw '*system-assigned*'
        { New-SIUpdaterWebAppCopyBody -App (New-WebApp 'ca-si-management') -Secrets @([pscustomobject]@{ name = 'sql-conn'; value = 'x' }) } | Should -Throw '*kv-key*'
    }
    It 'the sign-in start check: a redirect to the Microsoft sign-in with THIS address only' {
        $ok = [pscustomobject]@{ Status = 302; Location = 'https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=x&redirect_uri=https%3A%2F%2Fca-si-web.env.example.io%2Fsignin-oidc' }
        Test-SIUpdaterSignInStart -Probe $ok -Fqdn 'ca-si-web.env.example.io' | Should -BeTrue
        Test-SIUpdaterSignInStart -Probe $ok -Fqdn 'ca-si-management.env.example.io' | Should -BeFalse
        Test-SIUpdaterSignInStart -Probe ([pscustomobject]@{ Status = 200; Location = '' }) -Fqdn 'ca-si-web.env.example.io' | Should -BeFalse
        Test-SIUpdaterSignInStart -Probe ([pscustomobject]@{ Status = 302; Location = 'https://evil.example/?redirect_uri=https%3A%2F%2Fca-si-web.env.example.io%2Fsignin-oidc' }) -Fqdn 'ca-si-web.env.example.io' | Should -BeFalse
    }
}

Describe 'both steps together, the switch, the state rows and the wiring' {
    BeforeEach {
        $script:Calls = New-Object System.Collections.Generic.List[string]; $script:Logged = New-Object System.Collections.Generic.List[string]
        $script:Saved = @{}; $script:Fail = ''; $script:PublicAddress = ''; $script:Cur = 'ca-si-management'
        $script:Apps = @{ 'ca-si-management' = (New-WebApp 'ca-si-management') }
        New-GraphState -Owners @($script:OwnerSup)
        $script:KeepNames = $global:SI_InstallNames; $global:SI_InstallNames = $null
        $script:Store = [pscustomobject]@{ Invoke = { param($sql, $p, $mode) if ($sql -match "N'SupportApp'") { , @([pscustomobject]@{ Value = $script:S }) } else { , @() } } }
        $script:StepArgs = @{
            Env = @{ SI_UPDATER_WEB_APP = 'ca-si-management'; SI_UPDATER_CLIENT_ID = $script:U }
            Store = $script:Store; SubscriptionId = 'sub'; ResourceGroup = 'rg'; Graph = $script:GraphFn; WhoAmI = $script:WhoAmI
            GetApp = { param($n) $script:Calls.Add('GETAPP ' + $n); $script:Apps[$n] }
            SaveState = { param($n, $v) $script:Saved[$n] = $v }
            Log = { param($m) $script:Logged.Add($m) }
            MoveSeams = @{ Arm = $script:ArmFake; Probe = $script:ProbeFake; PollSeconds = 0; TimeoutMinutes = 0
                SignedInProof = { param($n) [pscustomobject]@{ Ok = $true; Why = '' } }
                SwitchName = { param($n) $script:Calls.Add('SWITCH ' + $n); $script:Cur = $n; [pscustomobject]@{ Ok = $true; Why = '' } }
                ReadPublicAddress = { '' } }
        }
    }
    AfterEach { $global:SI_InstallNames = $script:KeepNames }
    It 'ON by default: the owner step (with the recorded Support app) then the move; one line each; both state rows written' {
        $r = Invoke-SIUpdaterWebAppSteps @script:StepArgs
        $r.Owner.State | Should -Be 'owned'
        $r.Move.State | Should -Be 'moved'
        @(OwnerIds) | Should -Be @('sp-upd')
        ($script:Saved['SignInAppOwner'] | ConvertFrom-Json).state | Should -Be 'owned'
        ($script:Saved['SignInAppOwner'] | ConvertFrom-Json).app | Should -Be $script:C
        ($script:Saved['WebAppName'] | ConvertFrom-Json).state | Should -Be 'moved'
        ($script:Saved['WebAppName'] | ConvertFrom-Json).to | Should -Be 'ca-si-web'
        $script:Saved['WebAppName'].Length | Should -BeLessOrEqual 400
        @($script:Logged | Where-Object { $_ -match "`n" }).Count | Should -Be 0
    }
    It 'SI_UPDATER_WEB_APP_MOVE=off: nothing is read or changed; one line says so' {
        $script:StepArgs.Env['SI_UPDATER_WEB_APP_MOVE'] = 'off'
        $r = Invoke-SIUpdaterWebAppSteps @script:StepArgs
        $r.Owner | Should -BeNullOrEmpty; $r.Move | Should -BeNullOrEmpty
        @($script:Calls).Count | Should -Be 0
        $script:Saved.Count | Should -Be 0
        @($script:Logged) | Should -Be @('web app: the sign-in app owner check and the move to ca-si-web are switched off on this install (SI_UPDATER_WEB_APP_MOVE=off) -- nothing was checked')
        Test-SIUpdaterWebAppMoveOn -Value '' | Should -BeTrue
        Test-SIUpdaterWebAppMoveOn -Value 'OFF' | Should -BeFalse
    }
    It 'the owner step needs a Support-app step: the move waits, nothing is made, both rows say so' {
        $script:GS.DenyAdd = $true
        $r = Invoke-SIUpdaterWebAppSteps @script:StepArgs
        $r.Owner.State | Should -Be 'needs-support-step'
        $r.Move.State | Should -Be 'waiting-owner'
        $script:Apps.ContainsKey('ca-si-management') | Should -BeTrue
        @($script:Calls | Where-Object { $_ -like 'ARM PUT *' }).Count | Should -Be 0
        ($script:Saved['WebAppName'] | ConvertFrom-Json).state | Should -Be 'waiting-owner'
    }
    It 'Set-SIUpdaterWebAppName: the updater job''s SI_UPDATER_WEB_APP and the install record name ca-si-web, read back' {
        $script:Job = [pscustomobject]@{ properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'updater'; image = 'u'; env = @([pscustomobject]@{ name = 'SI_UPDATER_WEB_APP'; value = 'ca-si-management' }, [pscustomobject]@{ name = 'X'; value = '1' }) }) } } }
        $script:Rec = '{"web":"ca-si-management","mcp":"ca-si-mcp"}'
        Mock Invoke-SIUpdaterArm {
            $script:Calls.Add(('{0} {1}' -f $Method, $Path))
            if ($Method -eq 'PATCH') { $script:Job = [pscustomobject]@{ properties = (([string](ConvertTo-Json -InputObject $Body -Depth 60)) | ConvertFrom-Json).properties }; return $null }
            $script:Job
        }
        Mock Invoke-SIUpdaterRecordEndpoints { $script:Calls.Add('ENDPOINTS ' + $WebApp) }
        $store = [pscustomobject]@{ Invoke = { param($sql, $p, $mode) if ($mode -eq 'nonquery') { $script:Rec = [string]$p['Value']; return }; , @([pscustomobject]@{ Value = $script:Rec }) } }
        $keepEnv = [Environment]::GetEnvironmentVariable('SI_UPDATER_WEB_APP')
        try {
            $r = Set-SIUpdaterWebAppName -Name 'ca-si-web' -ResourceGroup 'rg' -SubscriptionId 'sub' -Store $store -UpdaterJob 'caj-si-updater'
            $r.Ok | Should -BeTrue
            Get-SIUpdaterWebAppSetting -App $script:Job -Name 'SI_UPDATER_WEB_APP' | Should -Be 'ca-si-web'
            Get-SIUpdaterWebAppSetting -App $script:Job -Name 'X' | Should -Be '1'
            ($script:Rec | ConvertFrom-Json).web | Should -Be 'ca-si-web'
            ($script:Rec | ConvertFrom-Json).mcp | Should -Be 'ca-si-mcp'
            @($script:Calls) | Should -Contain 'ENDPOINTS ca-si-web'
            # a second time: nothing written
            $script:Calls.Clear()
            (Set-SIUpdaterWebAppName -Name 'ca-si-web' -ResourceGroup 'rg' -SubscriptionId 'sub' -Store $store -UpdaterJob 'caj-si-updater').Ok | Should -BeTrue
            @($script:Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
        } finally { [Environment]::SetEnvironmentVariable('SI_UPDATER_WEB_APP', $keepEnv); $global:SI_InstallNames = $script:KeepNames }
    }
    It 'WIRING: both steps run after the update (Community and Invardia), only when it did not fail; the state rows are allowed names' {
        $u = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'))
        $u | Should -Match '(?s)\$rcCommunity = \(Invoke-SIUpdaterFromCommunity .*?Invoke-SIUpdaterWebAppStepsAfter -Rc \$rcCommunity .*?return \$rcCommunity'
        $u | Should -Match '(?s)\$rcInvardia = \(Invoke-SIUpdaterFromInvardia .*?Invoke-SIUpdaterWebAppStepsAfter -Rc \$rcInvardia .*?return \$rcInvardia'
        $u | Should -Match "ValidateSet\([^)]*'SignInAppOwner', 'WebAppName'\)"
        Mock Invoke-SIUpdaterWebAppSteps { $script:Calls.Add('STEPS') }
        Mock Write-UpdLog { $script:Logged.Add($m) }
        Invoke-SIUpdaterWebAppStepsAfter -Rc 1 -Env @{} -SubscriptionId 'sub' -ResourceGroup 'rg'
        @($script:Calls) | Should -Not -Contain 'STEPS'
        Invoke-SIUpdaterWebAppStepsAfter -Rc 0 -Env @{} -SubscriptionId 'sub' -ResourceGroup 'rg'
        @($script:Calls) | Should -Contain 'STEPS'
    }
    It 'WIRING: the heartbeat reads the install record before the performance sample, so it names the moved web app' {
        $hp = Join-Path $script:SIRoot 'engine\heartbeat\Invoke-SIHeartbeat.ps1'
        if (-not (Test-Path -LiteralPath $hp)) { Set-ItResult -Skipped -Because 'this copy carries no heartbeat job (the Community edition)'; return }
        $h = [IO.File]::ReadAllText($hp)
        $h.IndexOf('$global:SI_InstallNames = Read-SIInstallNamesRecord') | Should -BeGreaterThan 0
        $h.IndexOf('$global:SI_InstallNames = Read-SIInstallNamesRecord') | Should -BeLessThan $h.IndexOf('$ps = Invoke-SIPerfSample')
    }
    It 'every function the steps call by default is defined (a missing one is caught here, not at an install)' {
        foreach ($n in 'Read-SIUpdaterPublicAddress', 'Set-SIUpdaterPublicAddress', 'Get-SIUpdaterPublicAddressPlan', 'Read-SIUpdaterWebSignedInProof', 'Set-SIUpdaterWebAppName',
                       'Read-SIUpdaterSupportAppId', 'Get-SIUpdaterGraphIdentity', 'Invoke-SIUpdaterAnonymousProbe', 'New-SIUpdaterWebAppCopyBody', 'Test-SIUpdaterSignInStart') {
            Get-Command -Name $n -CommandType Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because $n
        }
    }
    It 'no internal requirement number in the steps'' code or the lines they say' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterWebApp.ps1'))
        $from = $t.IndexOf('THE SIGN-IN APP OWNED BY THE INSTALL''S UPDATER')
        $from | Should -BeGreaterThan 0
        $t.Substring($from) | Should -Not -Match '#\d{3,4}\b'
    }
}

Describe 'the setup-step grid: the sign-in app owner and the web app name, per install' {
    BeforeAll { . (Join-Path $script:SIRoot 'engine\_shared\SI-SetupSteps.ps1') }
    It 'waiting for the first sign-in on ca-si-web: web-app-name missing, said plainly; moved: ok; no row: left out' {
        $row = { param($n, $v) [pscustomobject]@{ Name = $n; Value = $v; UpdatedAt = $null } }
        $s = @(Get-SISetupSteps -StateRows @((& $row 'WebAppName' '{"state":"awaiting-signin-proof","from":"ca-si-management","to":"ca-si-web","checkedUtc":"2026-11-07T10:00:00Z"}')) -SupportGrant $null)
        $e = @($s | Where-Object key -eq 'web-app-name')[0]
        $e.state | Should -Be 'missing'; $e.how | Should -Be 'updater'
        $e.detail | Should -Match '^Waiting for first sign-in on ca-si-web'
        $e.checkedAt | Should -Be '2026-11-07T10:00:00Z'
        (@(Get-SISetupSteps -StateRows @((& $row 'WebAppName' '{"state":"moved","checkedUtc":"2026-11-07T10:00:00Z"}')) -SupportGrant $null) | Where-Object key -eq 'web-app-name').state | Should -Be 'ok'
        @(Get-SISetupSteps -StateRows @() -SupportGrant $null | Where-Object { $_.key -in 'web-app-name', 'signin-app-owner' }).Count | Should -Be 0
    }
    It 'the sign-in app owner: a Support-app step waited for = missing (how support-app); owned = ok; never a command in the detail' {
        $row = { param($n, $v) [pscustomobject]@{ Name = $n; Value = $v; UpdatedAt = $null } }
        $e = @(Get-SISetupSteps -StateRows @((& $row 'SignInAppOwner' '{"state":"needs-permission","checkedUtc":"2026-11-07T10:00:00Z"}')) -SupportGrant $null | Where-Object key -eq 'signin-app-owner')[0]
        $e.state | Should -Be 'missing'; $e.how | Should -Be 'support-app'; $e.detail | Should -Match 'Application\.ReadWrite\.OwnedBy'
        (@(Get-SISetupSteps -StateRows @((& $row 'SignInAppOwner' '{"state":"owned"}')) -SupportGrant $null) | Where-Object key -eq 'signin-app-owner').state | Should -Be 'ok'
        (Get-SISetupStepRowsSql) | Should -Match "N'SignInAppOwner', N'WebAppName'"
    }
}
