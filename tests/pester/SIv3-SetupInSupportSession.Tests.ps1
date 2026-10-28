#Requires -Version 5.1
<#
    SETUP INSIDE AN INVARDIA SUPPORT SESSION (owner 2026-10-12: a change in an environment -- internal or a customer's --
    is made by running SecurityInsight's own setup script inside that environment's Invardia Support session, so every
    change is recorded in its audit log).

    What must hold when a Support session is open in the shell (Invardia's $global:InvardiaSupportState names a tenant AND
    its recording command Invoke-InvardiaSupportRequest is there):
      * setup signs in to NOTHING itself: no browser, no certificate, no token request -- the context is the session's
      * EVERY HTTP call of the setup layer goes through the recording command: a GET as a read, a POST that only reads
        marked read-only, a role assignment PUT / an app role POST as a CHANGE; never a raw HTTP call
      * a subscription the session does not name is refused before anything is sent
      * SecurityInsight's own rules stay: a 404 with -AllowNotFound is $null, an error status is its own error, paging
        follows nextLink / @odata.nextLink, a 429 is waited for and retried
      * setup\Grant-SIIdentity.ps1 plans and applies end to end; -OnlyAppPermissions / -Only <names> grants exactly the
        application permissions that are missing and nothing else; a permission it may not grant (403) is a task
    And without a Support session the old path is used unchanged.

    OFFLINE. The Support session is a FAKE: the state Connect-InvardiaSupport leaves and a recording command that notes
    every call (method, URL, read-only or change) and answers from a small fake Azure / Microsoft Graph. These are GLOBAL
    names by Invardia's contract, so whatever was there before is saved in BeforeAll and put back in AfterAll.
    Windows PowerShell 5.1 and PowerShell 7. No module, no network, no tenant.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Tid = '11111111-1111-1111-1111-111111111111'
    $script:OtherTid = '99999999-9999-9999-9999-999999999999'
    $script:Sub = '22222222-2222-2222-2222-222222222222'
    $script:Sub2 = '33333333-3333-3333-3333-333333333333'
    $script:OtherSub = '77777777-7777-7777-7777-777777777777'
    $script:Principal = '55555555-5555-5555-5555-555555555555'
    $script:GraphAppId = '00000003-0000-0000-c000-000000000000'

    # ---- everything global this suite touches: saved here, put back in AfterAll ----
    $script:KeepNames = 'SI_AzureAccess_Engine', 'SI_LogIngest_Engine', 'SI_AzRestState', 'SI_LogIngestRunCache', 'SI_SetupSignInState', 'InvardiaSupportState', 'SISupportTestWorld'
    $script:ResetNames = 'SI_AuthMethod', 'SI_UseManagedIdentity', 'UseManagedIdentity', 'SI_UAMI_ClientId', 'SI_SPN_AppId', 'SI_SPN_TenantId', 'SI_SPN_Secret', 'SI_SPN_CertThumbprint',
                         'SpnClientId', 'SpnTenantId', 'SpnClientSecret', 'SpnCertificateThumbprint', 'HighPriv_Modern_ApplicationID_Azure', 'HighPriv_Modern_CertificateThumbprint_Azure',
                         'HighPriv_Modern_TenantID', 'HighPriv_Modern_Secret_Azure', 'HighPriv_Modern_ApplicationSecret_Azure', 'AzureTenantId', 'TenantId', 'SI_AzSubscriptionId',
                         'SI_WorkspaceResourceId', 'SubscriptionId', 'SI_TokenProvider', 'SI_StorageAccount', 'SI_StorageResourceGroup', 'SI_DcrResourceGroup', 'SI_DefenderWorkspaceResourceId'
    $script:Had = @{}; $script:Keep = @{}
    foreach ($n in @($script:KeepNames) + @($script:ResetNames)) {
        $script:Had[$n] = [bool](Get-Variable -Scope Global -Name $n -ErrorAction Ignore)
        $script:Keep[$n] = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction Ignore
    }
    $script:FnNames = 'Invoke-InvardiaSupportRequest', 'Get-InvardiaSupportToken'
    $script:FnsBefore = @{}
    foreach ($n in $script:FnNames) { $fn = Get-Item -LiteralPath ('Function:\' + $n) -ErrorAction Ignore; if ($fn) { $script:FnsBefore[$n] = $fn.ScriptBlock } }
    $script:hadGlobalToken = [bool](Get-Item -Path 'function:global:Get-SIAzureToken' -ErrorAction Ignore)
    $script:QuietBefore = $env:SI_SCRIPT_RUN_QUIET
    $env:SI_SCRIPT_RUN_QUIET = '1'      # the scripts under test print no banner and start no transcript

    . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-GraphRest.ps1')
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')

    # the application permissions of the collection plan, as data for the fake Microsoft Graph
    $script:PlanAppRoles = @(Get-SIContainerIdentityGrantPlan -Mode ManagedIdentity | Where-Object { $_.Kind -eq 'AppRole' })

    function script:Remove-FakeSession {
        foreach ($n in $script:FnNames) {
            $i = 0
            while ((Test-Path -LiteralPath ('Function:\' + $n)) -and $i -lt 5) { Remove-Item -LiteralPath ('Function:\' + $n) -Force -ErrorAction SilentlyContinue; $i++ }
        }
        Remove-Variable -Scope Global -Name InvardiaSupportState -ErrorAction SilentlyContinue
    }

    function script:New-FakeWorld {
        # the fake Azure / Microsoft Graph behind the recording command
        $resources = @{}
        foreach ($grp in ($script:PlanAppRoles | Group-Object ResourceAppId)) {
            $resources[[string]$grp.Name] = [pscustomobject]@{
                id = ('sp-' + $grp.Name); appId = [string]$grp.Name; displayName = [string]$grp.Group[0].Resource
                appRoles = @($grp.Group | ForEach-Object { [pscustomobject]@{ id = ('r-' + $_.Role); value = [string]$_.Role } })
            }
        }
        $roleDefs = @('Reader', 'Monitoring Metrics Publisher', 'Log Analytics Reader', 'Key Vault Secrets User', 'Storage Blob Data Contributor', 'Storage Queue Data Contributor',
                      'Storage Table Data Contributor', 'Monitoring Contributor', 'Log Analytics Contributor', 'AcrPull') | ForEach-Object {
            $g = [guid]::NewGuid().ToString()
            [pscustomobject]@{ id = ('/providers/Microsoft.Authorization/roleDefinitions/' + $g); name = $g; properties = [pscustomobject]@{ roleName = $_; type = 'BuiltInRole' } }
        }
        $global:SISupportTestWorld = @{
            Calls     = New-Object System.Collections.Generic.List[object]
            TokenAsks = New-Object System.Collections.Generic.List[string]
            Resources = $resources
            RoleDefs  = @($roleDefs)
            Assigned  = New-Object System.Collections.Generic.List[object]   # the app role assignments the identity holds
            Deny      = @()                                                   # appRoleIds Microsoft Graph refuses (403)
            Override  = $null                                                 # { param($Method, $Uri, $Body) } -> a response, or $null to go on
            Identity  = [pscustomobject]@{
                id = "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-si"; name = 'uami-si'; location = 'westeurope'
                properties = [pscustomobject]@{ clientId = '66666666-6666-6666-6666-666666666666'; principalId = $script:Principal; tenantId = $script:Tid }
            }
        }
    }

    function script:Open-FakeSession {
        param([string[]]$Subscriptions = @('22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333'))
        New-FakeWorld
        # what Connect-InvardiaSupport leaves in the shell
        $first = $null
        if (@($Subscriptions).Count) { $first = @($Subscriptions)[0] }
        $global:InvardiaSupportState = @{ TenantId = '11111111-1111-1111-1111-111111111111'; AppId = 'support-app-id'; Environment = 'test-env'
            EnvironmentId = '44444444-4444-4444-4444-444444444444'; SessionId = [guid]::NewGuid().ToString(); Subscriptions = @($Subscriptions)
            SubscriptionId = $first; SubscriptionName = 'Sub One'; Tokens = @{}; Reads = @{}; Reason = 'test' }
        function global:Get-InvardiaSupportToken {
            param([Parameter(Mandatory)][string]$Resource, [switch]$ForceRefresh, [string]$Reason)
            $global:SISupportTestWorld.TokenAsks.Add($Resource)
            $b = { param($s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
            '{0}.{1}.sig' -f (& $b '{"alg":"none"}'), (& $b '{"tid":"11111111-1111-1111-1111-111111111111","appid":"support-app-id","oid":"88888888-8888-8888-8888-888888888888"}')
        }
        # THE recording command, as Invardia defines it: never throws on an HTTP status; StatusCode / Content / Headers
        function global:Invoke-InvardiaSupportRequest {
            param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body, [string]$ContentType, [hashtable]$Headers, [string]$Reason,
                  [switch]$AsBytes, [switch]$ReadOnly, [int]$TimeoutSec = 0, [string]$TokenResource)
            $w = $global:SISupportTestWorld
            $verb = $Method.ToUpperInvariant()
            if ($ReadOnly -and $verb -notin 'GET', 'HEAD', 'POST') { throw "-ReadOnly is for a POST that only reads; $verb is always recorded as a change." }
            $text = ''
            if ($Body -is [byte[]]) { $text = [Text.Encoding]::UTF8.GetString($Body) } elseif ($null -ne $Body) { $text = [string]$Body }
            $hasAuth = $false
            if ($Headers) { $hasAuth = [bool](@($Headers.Keys | Where-Object { "$_" -ieq 'Authorization' }).Count) }
            # recorded as Invardia records it: a read (GET / HEAD, or a POST marked read-only) or a CHANGE (anything else)
            $w.Calls.Add([pscustomobject]@{ Method = $verb; Uri = $Uri; Path = ([uri]$Uri).AbsolutePath; IsRead = ($verb -in 'GET', 'HEAD' -or ($verb -eq 'POST' -and [bool]$ReadOnly))
                ReadOnly = [bool]$ReadOnly; HasAuthorization = $hasAuth; Body = $text; TimeoutSec = $TimeoutSec; TokenResource = $TokenResource })
            $resp = { param([int]$Code, $Obj, [hashtable]$H = @{})
                $c = ''
                if ($null -ne $Obj) { if ($Obj -is [string]) { $c = $Obj } else { $c = ConvertTo-Json -InputObject $Obj -Depth 12 -Compress } }
                [pscustomobject]@{ StatusCode = $Code; Content = $c; Headers = $H; Method = $verb } }
            if ($w.Override) { $o = & $w.Override $verb $Uri $text; if ($null -ne $o) { return $o } }
            $u = [uri]$Uri; $path = $u.AbsolutePath; $query = [uri]::UnescapeDataString($u.Query)
            if ($u.Host -eq 'graph.microsoft.com') {
                if ($verb -eq 'GET' -and $path -match '/servicePrincipals/[^/]+/appRoleAssignments$') { return (& $resp 200 @{ value = @($w.Assigned.ToArray()) }) }
                if ($verb -eq 'GET' -and $path -match '/servicePrincipals$' -and $query -match "appId eq '([^']+)'") {
                    $sp = $w.Resources[$Matches[1]]
                    $found = @(); if ($sp) { $found = @($sp) }
                    return (& $resp 200 @{ value = $found })
                }
                if ($verb -eq 'POST' -and $path -match '/servicePrincipals/[^/]+/appRoleAssignments$') {
                    $b = $text | ConvertFrom-Json
                    if (@($w.Deny) -contains [string]$b.appRoleId) { return (& $resp 403 '{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}') }
                    $w.Assigned.Add([pscustomobject]@{ id = [guid]::NewGuid().ToString(); appRoleId = [string]$b.appRoleId; resourceId = [string]$b.resourceId; principalId = [string]$b.principalId })
                    return (& $resp 201 @{ id = 'new'; appRoleId = [string]$b.appRoleId })
                }
            }
            if ($u.Host -eq 'management.azure.com') {
                if ($verb -eq 'GET' -and $path -match '/userAssignedIdentities/[^/]+$') { return (& $resp 200 $w.Identity) }
                if ($verb -eq 'GET' -and $path -match '/providers/Microsoft\.Authorization/roleDefinitions$') { return (& $resp 200 @{ value = @($w.RoleDefs) }) }
                if ($verb -eq 'GET' -and $path -match '/providers/Microsoft\.Authorization/roleAssignments$') { return (& $resp 200 @{ value = @() }) }
                if ($verb -eq 'PUT' -and $path -match '/providers/Microsoft\.Authorization/roleAssignments/([^/]+)$') { return (& $resp 201 @{ id = $path; name = $Matches[1]; properties = @{ scope = 'x' } }) }
            }
            if ($verb -eq 'GET') { return (& $resp 200 '{"value":[]}') }
            return (& $resp 200 '{}')
        }
    }

    function script:Reset-SIState {
        foreach ($n in $script:ResetNames) { Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue }
        $st = Get-SIAzRestState
        $st.Connection = $null; $st.TenantId = $null; $st.SubscriptionId = $null; $st.Cache = @{}; $st['SupportSaid'] = $null
        if ($global:SI_LogIngestRunCache -is [hashtable]) { $global:SI_LogIngestRunCache.Tokens = @{} }
    }

    function script:Invoke-Grant([hashtable]$P) {
        # the script as an operator runs it, in this process (so the fake session is the one it meets)
        $global:LASTEXITCODE = 0
        $lines = @(& (Join-Path $script:SIRoot 'setup\Grant-SIIdentity.ps1') @P *>&1 | ForEach-Object { [string]$_ })
        [pscustomobject]@{ Lines = $lines; Text = ($lines -join "`n"); ExitCode = [int]$global:LASTEXITCODE }
    }
    function script:Get-Changes { @($global:SISupportTestWorld.Calls | Where-Object { -not $_.IsRead }) }
    function script:Add-Assigned([string]$Role) {
        $global:SISupportTestWorld.Assigned.Add([pscustomobject]@{ id = [guid]::NewGuid().ToString(); appRoleId = ('r-' + $Role); resourceId = ('sp-' + $script:GraphAppId); principalId = $script:Principal })
    }
}

AfterAll {
    Remove-FakeSession
    foreach ($n in $script:FnsBefore.Keys) { Set-Item -Path ('function:global:' + $n) -Value $script:FnsBefore[$n] }
    foreach ($n in @($script:KeepNames) + @($script:ResetNames)) {
        if ($script:Had[$n]) { Set-Variable -Scope Global -Name $n -Value $script:Keep[$n] } else { Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue }
    }
    if (-not $script:hadGlobalToken) { Remove-Item -Path 'function:global:Get-SIAzureToken' -ErrorAction SilentlyContinue }
    $env:SI_SCRIPT_RUN_QUIET = $script:QuietBefore
}

Describe 'setup inside an Invardia Support session: the session is the sign-in and every call is recorded' {
    BeforeEach {
        Remove-FakeSession
        Reset-SIState
        Open-FakeSession
        # anything SecurityInsight would do by itself is a failure here
        Mock Invoke-SIAzRestHttp { throw 'a raw HTTP call was made inside a Support session' }
        Mock Connect-SISetupUser { throw 'a browser sign-in was started inside a Support session' }
        Mock Get-SILogIngestToken { throw 'a token of SecurityInsight''s own was requested inside a Support session' }
        Mock Start-Sleep { }
    }
    AfterEach { Remove-FakeSession; Reset-SIState }

    It 'no sign-in of its own: the context is the session''s (tenant, first subscription), no browser / certificate / token request -- and one plain line says so, once' {
        Mock Write-Host { }
        $c = Get-SISetupAzureContext
        $c.SignInMethod | Should -Be 'Support'
        $c.Account.Id | Should -Be 'support-app-id'
        $c.Account.Type | Should -Be 'ServicePrincipal'
        $c.Tenant.Id | Should -Be $script:Tid
        $c.Subscription.Id | Should -Be $script:Sub
        $c.Subscription.Name | Should -Be 'Sub One'
        $c2 = Connect-SISetupAzure -TenantId $script:Tid
        $c2.SignInMethod | Should -Be 'Support'
        $null = Get-SISetupAzureContext
        $global:SISupportTestWorld.TokenAsks.Count | Should -Be 0 -Because 'no token is asked for to say who is signed in'
        $global:SISupportTestWorld.Calls.Count | Should -Be 0 -Because 'the session already names its first subscription'
        Should -Invoke Connect-SISetupUser -Times 0 -Exactly
        Should -Invoke Get-SILogIngestToken -Times 0 -Exactly
        Should -Invoke Invoke-SIAzRestHttp -Times 0 -Exactly
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -eq 'using the Invardia Support session for test-env -- every change is recorded there' }
    }
    It '-SubscriptionId: one the session names is taken; one it does not name is refused -- and so is another tenant' {
        (Connect-SISetupAzure -SubscriptionId $script:Sub2).Subscription.Id | Should -Be $script:Sub2
        (Get-SISetupAzureContext -SubscriptionId $script:Sub).Subscription.Id | Should -Be $script:Sub
        { Connect-SISetupAzure -SubscriptionId $script:OtherSub } | Should -Throw "*Subscription $($script:OtherSub) is not one the Invardia Support session for test-env names*refused*"
        { Get-SISetupAzureContext -SubscriptionId $script:OtherSub } | Should -Throw '*is not one the Invardia Support session for test-env names*'
        { Connect-SISetupAzure -TenantId $script:OtherTid } | Should -Throw "*is for tenant $($script:Tid), not $($script:OtherTid)*refused*"
        (Get-SISetupAzureContext).Subscription.Id | Should -Be $script:Sub -Because 'a refused subscription is never selected'
    }
    It 'a request for a subscription the session does not name is refused BEFORE anything is sent' {
        { Invoke-SIArm -Path "/subscriptions/$($script:OtherSub)/resourceGroups/rg" -ApiVersion '2021-04-01' } | Should -Throw '*is not one the Invardia Support session*refused*'
        { Invoke-SIArm -Method PUT -Path "/subscriptions/$($script:OtherSub)/resourceGroups/rg" -ApiVersion '2021-04-01' -Body @{ location = 'westeurope' } } | Should -Throw '*refused*'
        $global:SISupportTestWorld.Calls.Count | Should -Be 0
        # a session whose environment names no subscription refuses none (Invardia's own rule)
        Remove-FakeSession; Reset-SIState; Open-FakeSession -Subscriptions @()
        $null = Invoke-SIArm -Path "/subscriptions/$($script:OtherSub)/resourceGroups/rg" -ApiVersion '2021-04-01'
        $global:SISupportTestWorld.Calls.Count | Should -Be 1
    }
    It 'a GET is sent as a read; no Authorization header and no token of SecurityInsight''s own' {
        $null = Invoke-SIArm -Path "/subscriptions/$($script:Sub)/resourceGroups/rg-si" -ApiVersion '2021-04-01'
        $null = Find-SIGraphServicePrincipal -AppId $script:GraphAppId
        # .ToArray(), never @( ) around the list itself: wrapping a List[object] in @( ) throws "Argument types do not match"
        $calls = $global:SISupportTestWorld.Calls.ToArray()
        $calls.Count | Should -Be 2
        @($calls | ForEach-Object Method) | Should -Be @('GET', 'GET')
        @($calls | Where-Object { -not $_.IsRead }).Count | Should -Be 0
        @($calls | Where-Object { $_.HasAuthorization }).Count | Should -Be 0
        $calls[0].Uri | Should -Be "https://management.azure.com/subscriptions/$($script:Sub)/resourceGroups/rg-si?api-version=2021-04-01"
        $calls[0].TimeoutSec | Should -BeGreaterThan 0 -Because 'SecurityInsight''s timeout is passed on'
        $global:SISupportTestWorld.TokenAsks.Count | Should -Be 0
        Should -Invoke Get-SILogIngestToken -Times 0 -Exactly
    }
    It 'an Azure role assignment (PUT) and an application permission (POST) are sent as CHANGES' {
        $a = New-SIRoleAssignment -ObjectId $script:Principal -Scope "/subscriptions/$($script:Sub)" -RoleDefinitionName 'Reader'
        $a.RoleDefinitionName | Should -Be 'Reader'
        $null = New-SIGraphAppRoleAssignment -ServicePrincipalId $script:Principal -ResourceId ('sp-' + $script:GraphAppId) -AppRoleId 'r-User.Read.All'
        $changes = @(Get-Changes)
        $changes.Count | Should -Be 2
        $changes[0].Method | Should -Be 'PUT'
        $changes[0].Path | Should -Match "^/subscriptions/$($script:Sub)/providers/Microsoft\.Authorization/roleAssignments/[0-9a-f-]{36}$"
        $changes[0].ReadOnly | Should -BeFalse
        $changes[1].Method | Should -Be 'POST'
        $changes[1].Uri | Should -Be "https://graph.microsoft.com/v1.0/servicePrincipals/$($script:Principal)/appRoleAssignments"
        $changes[1].ReadOnly | Should -BeFalse
        ($changes[1].Body | ConvertFrom-Json).appRoleId | Should -Be 'r-User.Read.All'
        # the role definitions were READ on the way (a GET)
        @($global:SISupportTestWorld.Calls | Where-Object { $_.IsRead -and $_.Path -match 'roleDefinitions$' }).Count | Should -Be 1
        $global:SISupportTestWorld.TokenAsks.Count | Should -Be 0
    }
    It 'a POST that only reads is marked read-only; anything not known to be a read is a change' {
        $null = Invoke-SIAzRestRequest -Method POST -Uri 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01' -Body '{"query":"resources | take 1"}'
        $last = $global:SISupportTestWorld.Calls[$global:SISupportTestWorld.Calls.Count - 1]
        $last.Method | Should -Be 'POST'
        $last.ReadOnly | Should -BeTrue
        $last.IsRead | Should -BeTrue
        $null = Invoke-SIArm -Method POST -Path "/subscriptions/$($script:Sub)/providers/Microsoft.KeyVault/register" -ApiVersion '2021-04-01'
        $global:SISupportTestWorld.Calls[$global:SISupportTestWorld.Calls.Count - 1].ReadOnly | Should -BeFalse
    }
    It 'which POSTs are reads (<Uri>): <Read>' -ForEach @(
        @{ Method = 'POST'; Uri = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01'; Body = '{}'; Read = $true }
        @{ Method = 'POST'; Uri = 'https://management.azure.com/subscriptions/s/providers/Microsoft.Storage/checkNameAvailability?api-version=2023-01-01'; Body = '{}'; Read = $true }
        @{ Method = 'POST'; Uri = 'https://api.loganalytics.io/v1/workspaces/abc/query'; Body = '{}'; Read = $true }
        @{ Method = 'POST'; Uri = 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds'; Body = '{}'; Read = $true }
        @{ Method = 'POST'; Uri = 'https://graph.microsoft.com/v1.0/$batch'; Body = '{"requests":[{"id":"1","method":"GET","url":"/users"},{"id":"2","method":"get","url":"/groups"}]}'; Read = $true }
        @{ Method = 'POST'; Uri = 'https://graph.microsoft.com/v1.0/$batch'; Body = '{"requests":[{"id":"1","method":"GET","url":"/users"},{"id":"2","method":"PATCH","url":"/groups/x"}]}'; Read = $false }
        @{ Method = 'POST'; Uri = 'https://graph.microsoft.com/v1.0/$batch'; Body = 'not json'; Read = $false }
        @{ Method = 'POST'; Uri = 'https://graph.microsoft.com/v1.0/servicePrincipals/x/appRoleAssignments'; Body = '{}'; Read = $false }
        @{ Method = 'POST'; Uri = 'https://management.azure.com/subscriptions/s/resourceGroups/r/providers/Microsoft.App/jobs/j/start?api-version=2025-07-01'; Body = '{}'; Read = $false }
        @{ Method = 'POST'; Uri = 'https://management.azure.com/subscriptions/s/resourceGroups/r/providers/Microsoft.App/jobs/j/listSecrets?api-version=2025-07-01'; Body = '{}'; Read = $false }
        @{ Method = 'PUT'; Uri = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources'; Body = '{}'; Read = $false }
        @{ Method = 'DELETE'; Uri = 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds'; Body = ''; Read = $false }
    ) {
        Test-SISupportReadOnlyPost -Method $Method -Uri $Uri -Body $Body | Should -Be $Read
    }
    It 'a 404 with -AllowNotFound is $null as before; without it -- and any other error status -- is SecurityInsight''s own error' {
        $global:SISupportTestWorld.Override = { param($m, $u, $b) [pscustomobject]@{ StatusCode = 404; Content = '{"error":{"code":"ResourceNotFound"}}'; Headers = @{}; Method = $m } }
        Invoke-SIArm -Path "/subscriptions/$($script:Sub)/resourceGroups/none" -ApiVersion '2021-04-01' -AllowNotFound | Should -BeNullOrEmpty
        Get-SIUserAssignedIdentity -ResourceGroupName rg-si -Name nope -SubscriptionId $script:Sub -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        { Invoke-SIArm -Path "/subscriptions/$($script:Sub)/resourceGroups/none" -ApiVersion '2021-04-01' } | Should -Throw '*HTTP Status: 404*ResourceNotFound*'
        $global:SISupportTestWorld.Override = { param($m, $u, $b) [pscustomobject]@{ StatusCode = 403; Content = '{"error":{"code":"AuthorizationFailed"}}'; Headers = @{}; Method = $m } }
        { Invoke-SIArm -Method PUT -Path "/subscriptions/$($script:Sub)/resourceGroups/x" -ApiVersion '2021-04-01' -Body @{ location = 'westeurope' } } | Should -Throw '*HTTP Status: 403*AuthorizationFailed*'
        { Find-SIGraphServicePrincipal -AppId $script:GraphAppId } | Should -Throw '*Microsoft Graph GET*failed: HTTP 403*'
    }
    It 'paging works: Azure Resource Manager nextLink and Microsoft Graph @odata.nextLink are followed through the session' {
        $sub = $script:Sub
        $global:SISupportTestWorld.Override = {
            param($m, $u, $b)
            $mk = { param($o) [pscustomobject]@{ StatusCode = 200; Content = (ConvertTo-Json -InputObject $o -Depth 6 -Compress); Headers = @{}; Method = $m } }
            if ($u -like 'https://management.azure.com/*page=2*') { return (& $mk @{ value = @(@{ name = 'rg-b' }) }) }
            if ($u -like 'https://management.azure.com/*resourcegroups*') { return (& $mk @{ value = @(@{ name = 'rg-a' }); nextLink = ($u + '&page=2') }) }
            if ($u -like 'https://graph.microsoft.com/*page=2*') { return (& $mk @{ value = @(@{ appRoleId = 'r-2' }) }) }
            if ($u -like 'https://graph.microsoft.com/*appRoleAssignments*') { return (& $mk @{ value = @(@{ appRoleId = 'r-1' }); '@odata.nextLink' = ($u + '?page=2') }) }
            $null
        }
        $rgs = @(Invoke-SIArm -Path "/subscriptions/$sub/resourcegroups" -ApiVersion '2021-04-01' -List)
        @($rgs | ForEach-Object name) | Should -Be @('rg-a', 'rg-b')
        $roles = @(Get-SIGraphAppRoleAssignments -ServicePrincipalId $script:Principal)
        @($roles | ForEach-Object appRoleId) | Should -Be @('r-1', 'r-2')
        $global:SISupportTestWorld.Calls.Count | Should -Be 4
        @($global:SISupportTestWorld.Calls | Where-Object { -not $_.IsRead }).Count | Should -Be 0
    }
    It 'throttling stays SecurityInsight''s own rule: a 429 is waited for and the call repeated' {
        $global:SISupportTestWorld.Hits = 0
        $global:SISupportTestWorld.Override = {
            param($m, $u, $b)
            $global:SISupportTestWorld.Hits++
            if ($global:SISupportTestWorld.Hits -eq 1) { return [pscustomobject]@{ StatusCode = 429; Content = ''; Headers = @{ 'Retry-After' = '1' }; Method = $m } }
            [pscustomobject]@{ StatusCode = 200; Content = '{"name":"rg-si"}'; Headers = @{}; Method = $m }
        }
        (Invoke-SIArm -Path "/subscriptions/$($script:Sub)/resourceGroups/rg-si" -ApiVersion '2021-04-01').name | Should -Be 'rg-si'
        $global:SISupportTestWorld.Calls.Count | Should -Be 2
        Should -Invoke Start-Sleep -Times 1 -Exactly
    }
    It 'a refusal to record the action is rethrown (fail-closed) -- never retried as a network error' {
        $global:SISupportTestWorld.Override = { param($m, $u, $b) throw "The Support app action (change-started arm PUT /x) could not be recorded in the customer's audit log, so it is NOT made (fail-closed): 503" }
        { Invoke-SIArm -Method PUT -Path "/subscriptions/$($script:Sub)/resourceGroups/x" -ApiVersion '2021-04-01' -Body @{ location = 'westeurope' } } | Should -Throw '*audit log*'
        $global:SISupportTestWorld.Calls.Count | Should -Be 1
    }
    It 'a sign-in of SecurityInsight''s own that was open before the session: setup takes the session, not that sign-in' {
        $st = Get-SIAzRestState
        $st.Connection = @{ Mode = 'Secret'; AppId = 'own-app'; TenantId = $script:Tid; Secret = 's' }
        Test-SISupportRequestRoute -Audience Arm | Should -BeFalse -Because 'the engines keep a sign-in that was recorded for them'
        (Get-SISetupAzureContext).SignInMethod | Should -Be 'Support'
        Test-SISupportRequestRoute -Audience Arm | Should -BeTrue
        $null = Invoke-SIArm -Path "/subscriptions/$($script:Sub)/resourceGroups/rg-si" -ApiVersion '2021-04-01'
        $global:SISupportTestWorld.Calls.Count | Should -Be 1
        Should -Invoke Get-SILogIngestToken -Times 0 -Exactly
    }
    It 'an app or managed identity sign-in beside the session is refused -- never a silent sign-in of its own' {
        { Connect-SISetupAzure -TenantId $script:Tid -ApplicationId 'app-1' -CertificateThumbprint 'ABCD' -Force } | Should -Throw '*Support session for test-env is open*would not be recorded*refused*'
        { Connect-SISetupAzure -Identity -Force } | Should -Throw '*a managed identity*refused*'
        Should -Invoke Get-SILogIngestToken -Times 0 -Exactly
    }
    It 'the session''s state without its recording command: said, and nothing is done' {
        Remove-Item -LiteralPath 'Function:\Invoke-InvardiaSupportRequest' -Force
        { Get-SISetupAzureContext } | Should -Throw '*recording command Invoke-InvardiaSupportRequest is not here*Nothing was done*'
        { Invoke-SIArm -Path "/subscriptions/$($script:Sub)/resourceGroups/rg-si" -ApiVersion '2021-04-01' } | Should -Throw '*recording command*'
        Should -Invoke Invoke-SIAzRestHttp -Times 0 -Exactly
    }
}

Describe 'without a Support session nothing changes: SecurityInsight''s own sign-in and its own HTTP' {
    BeforeEach {
        Remove-FakeSession
        Reset-SIState
        Open-FakeSession
        $global:InvardiaSupportState = $null      # as after Disconnect-InvardiaSupport: its commands stay, its state is empty
        $global:SI_SPN_AppId = 'app-1'; $global:SI_SPN_TenantId = $script:Tid; $global:SI_SPN_Secret = 's3cret'
        Mock Get-SILogIngestToken { 'own-token' }
        Mock Invoke-SIAzRestHttp { [pscustomobject]@{ StatusCode = 200; Content = '{"ok":true}'; Bytes = $null; Headers = @{}; RetryAfter = '' } }
        Mock Connect-SISetupUser { throw 'no browser in this test' }
    }
    AfterEach { Remove-FakeSession; Reset-SIState }

    It 'no session is seen, the call is SecurityInsight''s own (its token, its HTTP) and nothing reaches the recording command' {
        Get-SISupportSession | Should -BeNullOrEmpty
        Test-SISupportRequestRoute -Audience Arm | Should -BeFalse
        Test-SISupportRequestRoute -Audience Graph | Should -BeFalse
        (Invoke-SIArm -Path "/subscriptions/$($script:Sub)/resourceGroups/rg-si" -ApiVersion '2021-04-01').ok | Should -BeTrue
        Should -Invoke Invoke-SIAzRestHttp -Times 1 -Exactly -ParameterFilter { $Headers['Authorization'] -eq 'Bearer own-token' -and $Uri -like 'https://management.azure.com/*' }
        $global:SISupportTestWorld.Calls.Count | Should -Be 0
        (Get-SISetupAzureContext -SubscriptionId $script:OtherSub).SignInMethod | Should -Be 'Secret' -Because 'no session = no subscription rule of a session'
    }
    It 'a Support sign-in left from a session that was closed is dropped, and the own sign-in is used' {
        (Get-SIAzRestState).Connection = @{ Mode = 'Support'; AppId = 'support-app-id'; TenantId = $script:Tid; SessionId = 'gone' }
        (Get-SISetupAzureContext).SignInMethod | Should -Be 'Secret'
        $null = Invoke-SIArm -Path "/subscriptions/$($script:Sub)/resourceGroups/rg-si" -ApiVersion '2021-04-01'
        $global:SISupportTestWorld.Calls.Count | Should -Be 0
    }
}

Describe 'setup\Grant-SIIdentity.ps1 inside a Support session, for a user-assigned managed identity' {
    BeforeEach {
        Remove-FakeSession
        Reset-SIState
        Open-FakeSession
        Mock Invoke-SIAzRestHttp { throw 'a raw HTTP call was made inside a Support session' }
        Mock Connect-SISetupUser { throw 'a browser sign-in was started inside a Support session' }
        Mock Get-SILogIngestToken { throw 'a token of SecurityInsight''s own was requested inside a Support session' }
        Mock Start-Sleep { }
        $script:Five = 'SecurityAlert.Read.All', 'AccessReview.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementManagedDevices.Read.All', 'UserAuthenticationMethod.Read.All'
        $script:Uami = @{ IdentityName = 'uami-si'; IdentityResourceGroup = 'rg-si'; SubscriptionId = $script:Sub }
    }
    AfterEach { Remove-FakeSession; Reset-SIState }

    It '-OnlyAppPermissions, the plan: every application permission present / MISSING, nothing changed, no Azure role read, no install configuration needed' {
        Add-Assigned 'User.Read.All'; Add-Assigned 'SecurityAlert.Read.All'
        $p = $script:Uami.Clone(); $p.OnlyAppPermissions = $true
        $r = Invoke-Grant $p
        $r.Text | Should -Match '\[present\]\s+User\.Read\.All\s+\(Microsoft Graph\)'
        $r.Text | Should -Match '\[present\]\s+SecurityAlert\.Read\.All\s+\(Microsoft Graph\)'
        $r.Text | Should -Match '\[MISSING\]\s+AccessReview\.Read\.All\s+\(Microsoft Graph\)'
        $r.Text | Should -Match '\[MISSING\]\s+Machine\.Read\.All\s+\(WindowsDefenderATP\)'
        @($r.Lines | Where-Object { $_ -match '^\s*\[(present|MISSING)\s*\]' }).Count | Should -Be $script:PlanAppRoles.Count -Because 'one line per application permission of the plan'
        $r.ExitCode | Should -Be 1 -Because 'grants are missing'
        @(Get-Changes).Count | Should -Be 0 -Because 'a plan changes nothing'
        @($global:SISupportTestWorld.Calls | Where-Object { $_.Path -match 'Microsoft\.Authorization' }).Count | Should -Be 0 -Because 'no Azure role is read'
        # the identity was found through the session (a read), in the subscription asked for
        @($global:SISupportTestWorld.Calls | Where-Object { $_.Path -eq "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-si" }).Count | Should -Be 1
        $global:SISupportTestWorld.TokenAsks.Count | Should -Be 0
        Should -Invoke Get-SILogIngestToken -Times 0 -Exactly
    }
    It '-Only (five names) -Apply: exactly the missing ones are granted (each a recorded change), the present one is left, a refused one is a task' {
        Add-Assigned 'SecurityAlert.Read.All'
        $global:SISupportTestWorld.Deny = @('r-UserAuthenticationMethod.Read.All')
        $p = $script:Uami.Clone(); $p.Only = $script:Five; $p.Apply = $true
        $r = Invoke-Grant $p
        # the plan, per permission
        $r.Text | Should -Match 'SecurityAlert\.Read\.All\s+Microsoft Graph: present'
        $r.Text | Should -Match 'AccessReview\.Read\.All\s+Microsoft Graph: missing -- will be granted'
        # the result, per permission
        $r.Text | Should -Match '\[present\]\s+SecurityAlert\.Read\.All\s+\(Microsoft Graph\)'
        foreach ($n in 'AccessReview.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementManagedDevices.Read.All') {
            $r.Text | Should -Match ('\[granted\]\s+{0}\s+\(Microsoft Graph\)' -f [regex]::Escape($n))
        }
        $r.Text | Should -Match '\[FAILED\s*\]\s+UserAuthenticationMethod\.Read\.All\s+\(Microsoft Graph\) -- not granted: HTTP 403 Authorization_RequestDenied'
        $r.Text | Should -Match '# API permission UserAuthenticationMethod\.Read\.All on Microsoft Graph'
        $r.ExitCode | Should -Be 1
        # exactly four POSTs: the four that were missing -- never the present one, never another permission of the plan
        $changes = @(Get-Changes)
        @($changes | ForEach-Object Method | Select-Object -Unique) | Should -Be @('POST')
        @($changes | ForEach-Object { ($_.Body | ConvertFrom-Json).appRoleId } | Sort-Object) | Should -Be @('r-AccessReview.Read.All', 'r-DeviceManagementConfiguration.Read.All', 'r-DeviceManagementManagedDevices.Read.All', 'r-UserAuthenticationMethod.Read.All')
        @($changes | ForEach-Object { ($_.Body | ConvertFrom-Json).principalId } | Select-Object -Unique) | Should -Be @($script:Principal)
        @($changes | Where-Object { $_.Uri -ne "https://graph.microsoft.com/v1.0/servicePrincipals/$($script:Principal)/appRoleAssignments" }).Count | Should -Be 0
        # only Microsoft Graph was asked about: the other APIs of the plan were not even looked up
        @($global:SISupportTestWorld.Calls | Where-Object { [uri]::UnescapeDataString($_.Uri) -match 'appId eq' -and [uri]::UnescapeDataString($_.Uri) -notmatch [regex]::Escape($script:GraphAppId) }).Count | Should -Be 0
        @($global:SISupportTestWorld.Calls | Where-Object { $_.Path -match 'Microsoft\.Authorization' }).Count | Should -Be 0
        @($global:SISupportTestWorld.Calls | Where-Object { $_.HasAuthorization }).Count | Should -Be 0
        $global:SISupportTestWorld.TokenAsks.Count | Should -Be 0
    }
    It '-Only -Apply a second time: everything asked for is present, nothing is sent as a change' {
        foreach ($n in $script:Five) { Add-Assigned $n }
        $p = $script:Uami.Clone(); $p.Only = $script:Five; $p.Apply = $true
        $r = Invoke-Grant $p
        @($r.Lines | Where-Object { $_ -match '^\s*\[present\]' }).Count | Should -Be 5
        $r.Text | Should -Match 'All grants present'
        $r.ExitCode | Should -Be 0
        @(Get-Changes).Count | Should -Be 0
    }
    It '-Only with a name that is not in the plan stops before anything is changed' {
        $p = $script:Uami.Clone(); $p.Only = @('SecurityAlert.Read.All', 'Mail.Send'); $p.Apply = $true
        { Invoke-Grant $p } | Should -Throw '*Not an application permission of this plan: Mail.Send*Nothing was changed*'
        @(Get-Changes).Count | Should -Be 0
    }
    It 'a subscription the session does not name is refused before anything is read' {
        $p = @{ IdentityName = 'uami-si'; IdentityResourceGroup = 'rg-si'; SubscriptionId = $script:OtherSub; OnlyAppPermissions = $true }
        { Invoke-Grant $p } | Should -Throw '*is not one the Invardia Support session for test-env names*refused*'
        $global:SISupportTestWorld.Calls.Count | Should -Be 0
    }
    It 'the whole plan with -Apply (install values given): the Azure roles are read, then assigned as changes, in the session''s subscription' {
        $ws = "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.OperationalInsights/workspaces/law-si"
        $p = $script:Uami.Clone(); $p.WorkspaceResourceId = $ws; $p.ConfigPath = (Join-Path $TestDrive 'no-such-config.ps1'); $p.Apply = $true
        $r = Invoke-Grant $p
        $r.Text | Should -Match ('\[granted\]\s+Reader\s+on /subscriptions/{0}' -f $script:Sub)
        $r.Text | Should -Match '\[granted\]\s+Monitoring Metrics Publisher\s+on /subscriptions/[0-9a-f-]+/resourceGroups/rg-si'
        $r.Text | Should -Match '\[granted\]\s+Log Analytics Reader\s+on '
        $puts = @(Get-Changes | Where-Object { $_.Method -eq 'PUT' })
        $puts.Count | Should -Be 3
        @($puts | Where-Object { $_.Path -notmatch '/providers/Microsoft\.Authorization/roleAssignments/[0-9a-f-]{36}$' }).Count | Should -Be 0
        @($puts | ForEach-Object { ($_.Body | ConvertFrom-Json).properties.principalId } | Select-Object -Unique) | Should -Be @($script:Principal)
        # every application permission of the plan was missing and was granted
        @(Get-Changes | Where-Object { $_.Method -eq 'POST' }).Count | Should -Be $script:PlanAppRoles.Count
        $r.ExitCode | Should -Be 0
        $global:SISupportTestWorld.TokenAsks.Count | Should -Be 0
        Should -Invoke Invoke-SIAzRestHttp -Times 0 -Exactly
    }
}

Describe 'the switches of setup\Grant-SIIdentity.ps1 (source pinned)' {
    It 'has -OnlyAppPermissions and -Only, grants only under -Apply, and names no sign-in of its own for a Support session' {
        $tk = $null; $er = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'setup\Grant-SIIdentity.ps1'), [ref]$tk, [ref]$er)
        @($er).Count | Should -Be 0
        $names = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $names | Should -Contain 'OnlyAppPermissions'
        $names | Should -Contain 'Only'
        $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { [string]$_.GetCommandName() })
        foreach ($c in 'Invoke-RestMethod', 'Invoke-WebRequest', 'Get-SIAzureToken', 'Get-InvardiaSupportToken', 'Invoke-InvardiaSupportRequest', 'az') { $calls | Should -Not -Contain $c }
    }
}
