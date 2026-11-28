#Requires -Version 5.1
<#
    THE ENGINE'S RUNTIME ROLES ARE NEVER GIVEN TO THE INVARDIA SUPPORT APP (Invardia's ROOT-RIGHTS-1 review of the 5 ring 0/1
    installs, 2026-11-27; framework RIGHTS-1). Found at three installs: the Support app ran setup, and
    setup\ConfigWizard\backend\Initialize-SIInfra.ps1 gave "the SPN" -- the caller -- the engine's role set (Storage Blob /
    Queue / Table Data Contributor, Key Vault Secrets User + Certificate User, Log Analytics / Monitoring Contributor,
    Monitoring Metrics Publisher). Offline (fakes); PS 5.1 and 7:
      * the Support app is told by its APP ID only, from every source setup knows (Get-SISetupSupportAppIds), ids compared
        through [guid]::TryParse (ConvertTo-SISetupGuid), FAIL-CLOSED (Resolve-SISetupEngineGrantee): a caller that is the
        Support app with no readable object id, a grantee that is not the caller whose application Graph names as the
        Support app or cannot be read -- no role;
      * Initialize-SIInfra run as the Support app with -SpnObjectId = itself: NO role is assigned, one line says so;
      * an engine identity (a separate SPN, or -ManagedIdentityName) still gets every role -- also when the Support app runs it;
      * the guided install passes no caller as -SpnObjectId (the container setup grants the engine's managed identity, which
        still gets the storage data roles and Metrics Publisher) and hands the Support app's id on;
      * nothing here removes a role assignment.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Read = { param($rel) [IO.File]::ReadAllText((Join-Path $script:SIRoot $rel)) }
    # ONLY the pure check from setup\_shared\SI-SetupAzure.ps1 (by its AST) -- the real sign-in / ARM functions are never
    # loaded here, so nothing can reach Azure or wait for a sign-in; the fakes below are all Initialize-SIInfra meets
    $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1'))
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
    foreach ($name in 'ConvertTo-SISetupGuid', 'Get-SISetupSupportAppIds', 'Resolve-SISetupEngineGrantee') {
        $fn = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object { $_.Name -eq $name })[0]
        . ([scriptblock]::Create(($fn.Extent.Text -replace ('^function ' + $name), ('function global:' + $name))))
    }
    $script:Infra = Join-Path $script:SIRoot 'setup\ConfigWizard\backend\Initialize-SIInfra.ps1'
    $script:Tenant = '7a7a7a7a-0000-0000-0000-00000000aaaa'
    $script:SupportApp = '5e5e5e5e-0000-4000-8000-00000000a11d'
    $script:SupportOid = '5e5e5e5e-0000-4000-8000-0000000000b1'
    $script:EngineOid = 'e0e0e0e0-0000-4000-8000-0000000000e1'
    $script:EngineRoles = @('Log Analytics Contributor', 'Monitoring Metrics Publisher', 'Monitoring Contributor', 'Storage Blob Data Contributor',
                            'Storage Table Data Contributor', 'Storage Queue Data Contributor', 'Key Vault Secrets User', 'Key Vault Certificate User')

    # THE FAKE AZURE: who is signed in, the resources (all there already), and every role assignment call recorded
    $global:SIAeRAz = @{ Caller = $null; Session = $null; Granted = (New-Object System.Collections.Generic.List[object]); Removed = 0; Apps = @{}; GraphFails = $false; GraphCalls = 0 }
    function global:Set-Caller([string]$AppId, [string]$Oid, [string]$Type = 'ServicePrincipal', [switch]$Session) {
        $global:SIAeRAz.Caller = [pscustomobject]@{ AppId = $AppId; Oid = $Oid; Type = $Type }
        $global:SIAeRAz.Session = if ($Session) { [pscustomobject]@{ TenantId = '7a7a7a7a-0000-0000-0000-00000000aaaa'; AppId = $AppId } } else { $null }
        $global:SIAeRAz.Granted.Clear(); $global:SIAeRAz.Apps = @{}; $global:SIAeRAz.GraphFails = $false; $global:SIAeRAz.GraphCalls = 0
    }
    function global:Get-SISetupAzureContext { [pscustomobject]@{ Account = [pscustomobject]@{ Id = $global:SIAeRAz.Caller.AppId; Type = $global:SIAeRAz.Caller.Type }; Tenant = [pscustomobject]@{ Id = '7a7a7a7a-0000-0000-0000-00000000aaaa' }; Subscription = [pscustomobject]@{ Id = 'sub-1'; Name = 'sub-1' } } }
    function global:Connect-SISetupAzure { param($TenantId, $SubscriptionId) Get-SISetupAzureContext }
    function global:Get-SISupportSession { $global:SIAeRAz.Session }
    function global:Get-SISetupSignedInObjectId { $global:SIAeRAz.Caller.Oid }
    # Graph (read only): a service principal's appId by its object id; GraphFails = the read is refused
    function global:Invoke-SIGraphRequest { param($Method, $Uri)
        $global:SIAeRAz.GraphCalls++
        if ($global:SIAeRAz.GraphFails) { throw 'Microsoft Graph GET failed: HTTP 403 Authorization_RequestDenied' }
        if ($Method -ne 'GET') { throw "the check only reads ($Method)" }
        $id = ([regex]::Match([string]$Uri, 'servicePrincipals/([^?]+)')).Groups[1].Value
        if ($global:SIAeRAz.Apps.ContainsKey($id)) { return [pscustomobject]@{ appId = $global:SIAeRAz.Apps[$id] } }
        throw 'Microsoft Graph GET failed: HTTP 404 Request_ResourceNotFound' }
    function global:Get-SIResourceProvider { param($ProviderNamespace, $SubscriptionId) [pscustomobject]@{ RegistrationState = 'Registered' } }
    function global:Get-SIAzResourceGroup { param($Name) [pscustomobject]@{ ResourceGroupName = $Name } }
    function global:New-SIUserAssignedIdentity { param($ResourceGroupName, $Name, $Location, $SubscriptionId) [pscustomobject]@{ Name = $Name; ClientId = 'c1c1c1c1-0000-4000-8000-000000000001'; PrincipalId = 'aaaa0000-0000-4000-8000-0000000000a1'; Id = "/x/$Name" } }
    function global:Get-SIAzOperationalInsightsWorkspace { param($ResourceGroupName, $Name) [pscustomobject]@{ ResourceId = "/subscriptions/sub-1/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$Name" } }
    function global:Get-SIAzDataCollectionEndpoint { param($ResourceGroupName, $Name) [pscustomobject]@{ LogIngestionEndpoint = 'https://dce.example'; Id = '/x/dce' } }
    function global:Get-SIAzStorageAccount { param($ResourceGroupName, $Name) [pscustomobject]@{ Id = "/subscriptions/sub-1/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$Name"; PrimaryEndpoints = [pscustomobject]@{ blob = 'https://st.example/' } } }
    function global:Initialize-SIKeyVault { param($VaultName, $ResourceGroupName, $Location, $SubscriptionId, $TenantId, [switch]$EnablePurgeProtection, $PublicNetworkAccess)
        [pscustomobject]@{ Action = 'found'; Changed = $false; Shape = 'public'; Vault = [pscustomobject]@{ ResourceId = "/x/vaults/$VaultName"; VaultUri = 'https://kv.example/'; EnablePurgeProtection = $true; EnableRbacAuthorization = $true } } }
    function global:Get-SIAzRoleAssignment { param($ObjectId, $Scope, $RoleDefinitionName) @() }
    function global:New-SIRoleAssignment { param($ObjectId, $RoleDefinitionName, $Scope, $PrincipalType) $global:SIAeRAz.Granted.Add([pscustomobject]@{ ObjectId = $ObjectId; Role = $RoleDefinitionName; Scope = $Scope }) }
    function global:Remove-SIRoleAssignment { $global:SIAeRAz.Removed++ }

    $script:Run = { param([hashtable]$More = @{})
        $p = @{ TenantId = $script:Tenant; SubscriptionId = 'sub-1'; ResourceGroupName = 'rg-si'; Location = 'westeurope'; WorkspaceName = 'log-si'
                DceName = 'dce-si'; StorageAccountName = 'stsi'; CreateKeyVault = $true; KeyVaultName = 'kv-si'; Hosting = 'ca' }
        foreach ($k in $More.Keys) { $p[$k] = $More[$k] }
        $out = & $script:Infra @p 6>&1
        # plain statements (a List inside @() in a [pscustomobject] literal throws "Argument types do not match")
        [string]$text = (@($out | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { [string]$_.MessageData }) -join "`n")
        [object[]]$granted = $global:SIAeRAz.Granted.ToArray()
        $res = New-Object psobject
        $res | Add-Member -NotePropertyName Text -NotePropertyValue $text
        $res | Add-Member -NotePropertyName Granted -NotePropertyValue $granted
        $res
    }
}

Describe 'the Support app is told by its app id, never by a name -- from every source, fail-closed' {
    It 'ids are compared through [guid]::TryParse: {GUID}, upper case and spaces are the same id; a name is never one' {
        ConvertTo-SISetupGuid ('  {' + $script:SupportApp.ToUpperInvariant() + '}  ') | Should -BeExactly $script:SupportApp
        ConvertTo-SISetupGuid 'Invardia Support' | Should -BeExactly ''
        ConvertTo-SISetupGuid '00000000-0000-0000-0000-000000000000' | Should -BeExactly ''
        ConvertTo-SISetupGuid $null | Should -BeExactly ''
    }
    It 'the id set takes EVERY source: the install answer, the Support session, the recorded Support app, the configuration -- once each' {
        $other = '6f6f6f6f-0000-4000-8000-000000000001'; $rec = '7a7a7a7a-0000-4000-8000-000000000002'; $cfg = '8b8b8b8b-0000-4000-8000-000000000003'
        $ids = @(Get-SISetupSupportAppIds -SupportAppId @($script:SupportApp, 'not-an-id') -SessionAppId ('{' + $other.ToUpperInvariant() + '}') -RecordedAppId @($rec) -ConfigAppId (' ' + $cfg))
        $ids | Should -Be @($script:SupportApp, $other, $rec, $cfg)
        @(Get-SISetupSupportAppIds -SupportAppId @($script:SupportApp) -SessionAppId $script:SupportApp.ToUpperInvariant()).Count | Should -Be 1
        @(Get-SISetupSupportAppIds).Count | Should -Be 0
    }
    It 'refused: the grantee IS the caller and the caller is the Support app (any spelling of its id)' {
        $d = Resolve-SISetupEngineGrantee -GranteeObjectId $script:SupportOid -CallerObjectId $script:SupportOid.ToUpperInvariant() -CallerAppId ('{' + $script:SupportApp.ToUpperInvariant() + '}') -CallerType 'ServicePrincipal' -SupportAppIds @($script:SupportApp)
        $d.Allow | Should -BeFalse; $d.Why | Should -Match 'the grantee is the caller, the Invardia Support app'
    }
    It 'FAIL-CLOSED: the caller is the Support app and its object id cannot be read -> refused, whatever the grantee' {
        foreach ($g in $script:SupportOid, $script:EngineOid) {
            $d = Resolve-SISetupEngineGrantee -GranteeObjectId $g -GranteeLookup 'ok' -GranteeAppId 'c0c0c0c0-0000-4000-8000-000000000000' -CallerObjectId '' -CallerAppId $script:SupportApp -CallerType 'ServicePrincipal' -SupportAppIds @($script:SupportApp)
            $d.Allow | Should -BeFalse -Because "grantee $g"; $d.Why | Should -Match 'object id could not be read'
        }
    }
    It 'a grantee that is NOT the caller: refused when Graph names it the Support app, refused when the lookup failed or was not made; allowed when it is another app' {
        $base = @{ GranteeObjectId = $script:EngineOid; CallerObjectId = 'aaaaaaaa-0000-4000-8000-0000000000c1'; CallerAppId = ''; CallerType = 'User'; SupportAppIds = @($script:SupportApp) }
        (Resolve-SISetupEngineGrantee @base -GranteeLookup 'ok' -GranteeAppId $script:SupportApp.ToUpperInvariant()).Allow | Should -BeFalse
        $f = Resolve-SISetupEngineGrantee @base -GranteeLookup 'failed'
        $f.Allow | Should -BeFalse; $f.Why | Should -Match 'could not be read from Microsoft Graph'
        (Resolve-SISetupEngineGrantee @base).Allow | Should -BeFalse -Because 'no lookup = not told apart = no role'
        (Resolve-SISetupEngineGrantee @base -GranteeLookup 'ok' -GranteeAppId 'c0c0c0c0-0000-4000-8000-000000000000').Allow | Should -BeTrue
    }
    It 'allowed: a person or a group as grantee, a caller that is another app, no Support app id known at all' {
        (Resolve-SISetupEngineGrantee -GranteeObjectId $script:EngineOid -GranteePrincipalType 'User' -CallerObjectId $script:SupportOid -CallerAppId 'c0c0c0c0-0000-4000-8000-000000000000' -CallerType 'ServicePrincipal' -SupportAppIds @($script:SupportApp)).Allow | Should -BeTrue
        (Resolve-SISetupEngineGrantee -GranteeObjectId $script:SupportOid -CallerObjectId $script:SupportOid -CallerAppId 'c0c0c0c0-0000-4000-8000-000000000000' -CallerType 'ServicePrincipal' -SupportAppIds @($script:SupportApp)).Allow | Should -BeTrue
        (Resolve-SISetupEngineGrantee -GranteeObjectId $script:SupportOid -CallerObjectId $script:SupportOid -CallerAppId $script:SupportApp -CallerType 'User' -SupportAppIds @($script:SupportApp)).Allow | Should -BeTrue -Because 'a person is never the Support app'
        (Resolve-SISetupEngineGrantee -GranteeObjectId $script:SupportOid -CallerObjectId $script:SupportOid -CallerAppId $script:SupportApp -CallerType 'ServicePrincipal' -SupportAppIds @('Invardia Support')).Allow | Should -BeTrue -Because 'a name is never an id: nothing to compare'
    }
}

Describe 'Initialize-SIInfra: the engine''s runtime roles never go to the Support app; the engine identity still gets them' {
    It 'run AS the Support app (the install answer''s supportAppId) with -SpnObjectId = itself: NO role assignment at all, one line, nothing removed' {
        Set-Caller -AppId $script:SupportApp -Oid $script:SupportOid
        $r = & $script:Run @{ SpnObjectId = $script:SupportOid; SupportAppId = $script:SupportApp }
        @($r.Granted).Count | Should -Be 0 -Because ([string](@($r.Granted | ForEach-Object Role) -join ', '))
        $r.Text | Should -Match 'NOT given to .*the grantee is the caller, the Invardia Support app'
        $global:SIAeRAz.Removed | Should -Be 0
    }
    It 'run in an Invardia Support session (its AppId, no -SupportAppId): the same -- NO role assignment' {
        Set-Caller -AppId $script:SupportApp -Oid $script:SupportOid -Session
        $r = & $script:Run @{ SpnObjectId = $script:SupportOid }
        @($r.Granted).Count | Should -Be 0
    }
    It 'the Support app runs it for an ENGINE identity (a separate SPN): the engine gets every runtime role, the Support app none' {
        Set-Caller -AppId $script:SupportApp -Oid $script:SupportOid -Session
        $global:SIAeRAz.Apps[$script:EngineOid] = 'e1e1e1e1-0000-4000-8000-0000000000e2'
        $r = & $script:Run @{ SpnObjectId = $script:EngineOid; SupportAppId = $script:SupportApp }
        @($r.Granted | Where-Object { $_.ObjectId -ne $script:EngineOid }).Count | Should -Be 0
        $global:SIAeRAz.GraphCalls | Should -Be 1 -Because 'the grantee is not the caller: its application is read once from Graph'
        foreach ($role in $script:EngineRoles) { @($r.Granted | Where-Object Role -eq $role).Count | Should -BeGreaterOrEqual 1 -Because "$role is an engine runtime role" }
    }
    It '-ManagedIdentityName run by the Support app: the managed identity gets them, never the caller' {
        Set-Caller -AppId $script:SupportApp -Oid $script:SupportOid -Session
        $r = & $script:Run @{ ManagedIdentityName = 'id-si-engine'; SupportAppId = $script:SupportApp }
        @($r.Granted).Count | Should -BeGreaterOrEqual $script:EngineRoles.Count
        @($r.Granted | Where-Object { $_.ObjectId -ne 'aaaa0000-0000-4000-8000-0000000000a1' }).Count | Should -Be 0
    }
    It 'no -SpnObjectId (the guided install): no role to anyone -- the container setup grants the engine''s managed identity' {
        Set-Caller -AppId $script:SupportApp -Oid $script:SupportOid -Session
        $r = & $script:Run @{ SupportAppId = $script:SupportApp }
        @($r.Granted).Count | Should -Be 0
        $r.Text | Should -Match 'granted by the container setup to the jobs'' managed identity'
    }
    It 'the RECORDED Support app (-RecordedSupportAppId) and the configuration ($global:SI_SupportAppId) are sources too' {
        Set-Caller -AppId $script:SupportApp -Oid $script:SupportOid
        (@((& $script:Run @{ SpnObjectId = $script:SupportOid; RecordedSupportAppId = ('{' + $script:SupportApp.ToUpperInvariant() + '}') }).Granted)).Count | Should -Be 0
        Set-Caller -AppId $script:SupportApp -Oid $script:SupportOid
        $global:SI_SupportAppId = $script:SupportApp
        try { (@((& $script:Run @{ SpnObjectId = $script:SupportOid }).Granted)).Count | Should -Be 0 } finally { Remove-Variable -Name SI_SupportAppId -Scope Global -ErrorAction SilentlyContinue }
    }
    It 'FAIL-CLOSED: the caller is the Support app and its object id cannot be read -- no role' {
        Set-Caller -AppId $script:SupportApp -Oid ''
        $r = & $script:Run @{ SpnObjectId = $script:SupportOid; SupportAppId = $script:SupportApp }
        @($r.Granted).Count | Should -Be 0
        $r.Text | Should -Match 'object id could not be read'
    }
    It 'a grantee that is NOT the caller but IS the Support app (Graph says so) -- no role, even when a person runs setup' {
        Set-Caller -AppId 'admin@contoso.example' -Oid 'aaaaaaaa-0000-4000-8000-0000000000c1' -Type 'User'
        $global:SIAeRAz.Apps[$script:SupportOid] = $script:SupportApp.ToUpperInvariant()
        $r = & $script:Run @{ SpnObjectId = $script:SupportOid; SupportAppId = $script:SupportApp }
        @($r.Granted).Count | Should -Be 0
        $r.Text | Should -Match 'is the Invardia Support app'
    }
    It 'a grantee that is NOT the caller and Graph cannot be read -- no role, and a clear line' {
        Set-Caller -AppId 'admin@contoso.example' -Oid 'aaaaaaaa-0000-4000-8000-0000000000c1' -Type 'User'
        $global:SIAeRAz.GraphFails = $true
        $r = & $script:Run @{ SpnObjectId = $script:EngineOid; SupportAppId = $script:SupportApp }
        @($r.Granted).Count | Should -Be 0
        $r.Text | Should -Match 'could not be read from Microsoft Graph'
        $r.Text | Should -Match 'NOT given to'
    }
    It 'nothing in Initialize-SIInfra removes a role assignment' {
        (& $script:Read 'setup\ConfigWizard\backend\Initialize-SIInfra.ps1') | Should -Not -Match 'Remove-SIRoleAssignment|Remove-SIAzRoleAssignment|''DELETE'''
    }
}

Describe 'the guided install hands no caller to Initialize-SIInfra; the engine''s managed identity keeps its roles' {
    It 'Get-SIInstallInfra passes no -SpnObjectId (not the person, never the Support app) and passes the Support app''s id' {
        $g = & $script:Read 'setup\_shared\SI-GuidedInstall.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($g, [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SIInstallInfra' }, $true)
        $fn | Should -Not -BeNullOrEmpty
        $body = ($fn.Extent.Text -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $body | Should -Not -Match 'SpnObjectId\s*='
        $body | Should -Match ([regex]::Escape("SupportAppId = [string]`$v['supportAppId']"))
    }
    It 'the container setup still gives the engine''s managed identity the storage data roles and Metrics Publisher' {
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
        $plan = @(Get-SIContainerIdentityGrantPlan -Mode ManagedIdentity -DcrResourceGroupId '/x/rg' -WorkspaceResourceId '/x/ws' -StorageAccountId '/x/st' -AcrRegistryId '/x/acr')
        foreach ($role in 'Storage Blob Data Contributor', 'Storage Queue Data Contributor', 'Storage Table Data Contributor', 'Monitoring Metrics Publisher') {
            @($plan | Where-Object { $_.Role -eq $role }).Count | Should -Be 1 -Because "$role is the engine identity's"
        }
    }
}

AfterAll {
    Remove-Variable -Name SIAeRAz -Scope Global -ErrorAction SilentlyContinue
    foreach ($n in @('Invoke-SIGraphRequest', 'ConvertTo-SISetupGuid', 'Get-SISetupSupportAppIds', 'Resolve-SISetupEngineGrantee', 'Set-Caller', 'Get-SISetupAzureContext', 'Connect-SISetupAzure', 'Get-SISupportSession', 'Get-SISetupSignedInObjectId', 'Get-SIResourceProvider', 'Get-SIAzResourceGroup', 'New-SIUserAssignedIdentity', 'Get-SIAzOperationalInsightsWorkspace', 'Get-SIAzDataCollectionEndpoint', 'Get-SIAzStorageAccount', 'Initialize-SIKeyVault', 'Get-SIAzRoleAssignment', 'New-SIRoleAssignment', 'Remove-SIRoleAssignment')) { Remove-Item -LiteralPath ("Function:\global:$n") -ErrorAction SilentlyContinue }
}
