#Requires -Version 5.1
<#
    #412 ONE PULL PER SOURCE -- THE SECURITY LEVEL IS UNCHANGED, AND THE FULL LEVEL BUILDS THE SAME SECURITY ROW.

    Operator 2026-10-06: "we dont pull in the same data twice (limited and full) ... if we do asset full, then it is 100%
    the same fields as limited - but with the extra metadata." Approved: one pull per source + history.

    What these keep true (free code -- the profilers; the Pro publisher has its own suite, SIv3-AssetPropertiesProfiler):
      1. SECURITY LEVEL (the default, and the Community edition's only level): every discovery issues EXACTLY the request it
         issued before this change -- the same URL, the same $select, the same Resource Graph query -- and keeps nothing.
      2. FULL LEVEL: each source is read ONCE (one request per source, never a second pass), with the security $select
         first and unchanged and the source's other properties after it; the whole object is kept with its anchor.
      3. GOLDEN: the same source data gives the SAME discovery record at both levels, and therefore the same
         SI_*_Profile_CL row -- the row builders are run on both records (in a child process each, as the builders
         share function names) and the rows compared field by field.
      4. A full $select Graph refuses is read again with the security URL, said, and the record is still identical.

    Graph is simulated honouring $select: the fixture holds every property, the fake returns only what was asked for --
    exactly why the full level must name properties (Graph has no "everything").
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Disc = Join-Path $script:SIRoot 'engine\asset-profiling\discovery'
    $script:Shared = Join-Path $script:SIRoot 'engine\asset-profiling\shared'
    . (Join-Path $script:Shared 'SI-FullAssetProperties.ps1')
    . (Join-Path $script:Shared 'Invoke-SIPagedRest.ps1')
    . (Join-Path $script:Shared 'IdentityRoleFetcher.ps1')
    . (Join-Path $script:Shared 'SI-AuthMethodsRead.ps1')
    . (Join-Path $script:SIRoot 'auth\Get-SIGraphToken.ps1')
    foreach ($f in 'Get-DiscoveryFromMDE.ps1', 'Get-DiscoveryFromEntra.ps1', 'Get-DiscoveryFromEntraUsers.ps1', 'Get-DiscoveryFromEntraServicePrincipals.ps1',
                   'Get-DiscoveryFromAzureResources.ps1', 'Get-DiscoveryFromEndpointViaEG.ps1') { . (Join-Path $script:Disc $f) }
    # the identity discoveries hand the workspace to their (mocked) Log Analytics readers, whose parameters stay mandatory
    $script:SavedWs = $global:SI_WorkspaceResourceId
    $global:SI_WorkspaceResourceId = '/subscriptions/s1/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
    foreach ($n in 'Write-SIInfo', 'Write-SIProgress', 'Reset-SIProgress', 'Write-SIWarn') {
        if (-not (Get-Command -Name $n -ErrorAction SilentlyContinue)) { Set-Item -Path ("function:global:{0}" -f $n) -Value { param() } }
    }

    # ---- the source data: every property the source has (Graph returns what $select names; MDE / ARG everything) ----
    $script:Device = [pscustomobject][ordered]@{
        id = 'd0000000-0000-0000-0000-000000000001'; deviceId = 'aad00000-0000-0000-0000-000000000001'; displayName = 'LAPTOP-7'
        operatingSystem = 'Windows'; operatingSystemVersion = '10.0.26100'; deviceCategory = $null; trustType = 'AzureAd'; profileType = 'RegisteredDevice'
        registrationDateTime = '2026-01-02T03:04:05Z'; approximateLastSignInDateTime = '2026-10-05T06:00:00Z'; accountEnabled = $true
        isCompliant = $true; isManaged = $true; manufacturer = 'Contoso'; model = 'Book 9'; physicalIds = @('[ZTDID]:abc', '[OrderId]:x')
        extensionAttributes = [pscustomobject]@{ extensionAttribute1 = 'cc-100' }; systemLabels = @()
    }
    $script:User = [pscustomobject][ordered]@{
        id = 'u0000000-0000-0000-0000-000000000001'; displayName = 'Ada Admin'; userPrincipalName = 'ada@contoso.test'; accountEnabled = $true
        createdDateTime = '2025-01-01T00:00:00Z'; jobTitle = 'Engineer'; department = 'IT'; onPremisesSyncEnabled = $null; mail = 'ada@contoso.test'
        userType = 'Member'; assignedLicenses = @([pscustomobject]@{ skuId = 's1' }, [pscustomobject]@{ skuId = 's2' })
        signInActivity = [pscustomobject]@{ lastSignInDateTime = '2026-10-04T10:00:00Z'; lastNonInteractiveSignInDateTime = '2026-10-05T09:00:00Z' }
        customSecurityAttributes = $null; givenName = 'Ada'; surname = 'Admin'; city = 'Aarhus'; employeeId = 'E-1'; proxyAddresses = @('SMTP:ada@contoso.test')
        onPremisesSamAccountName = 'ada'
    }
    $script:Spn = [pscustomobject][ordered]@{
        id = 's0000000-0000-0000-0000-000000000001'; displayName = 'payroll-app'; appId = 'a1'; servicePrincipalType = 'Application'
        signInAudience = 'AzureADMyOrg'; accountEnabled = $true; publisherName = 'Contoso'; verifiedPublisher = [pscustomobject]@{ displayName = $null }
        appOwnerOrganizationId = 't1'; passwordCredentials = @([pscustomobject]@{ endDateTime = '2030-01-01T00:00:00Z' }); keyCredentials = @()
        tags = @('WindowsAzureActiveDirectoryIntegratedApp'); homepage = $null; customSecurityAttributes = $null; createdDateTime = '2024-05-05T00:00:00Z'
        appRoles = @([pscustomobject]@{ value = 'Reader'; id = 'r1' }); replyUrls = @('https://payroll.contoso.test/signin'); servicePrincipalNames = @('a1')
    }
    $script:Machine = [pscustomobject][ordered]@{
        id = '0c8545c566aa838508be174878084b0c7a9cfd4e'; computerDnsName = 'laptop-7.contoso.local'; osPlatform = 'Windows11'; version = '24H2'
        osProcessor = 'x64'; healthStatus = 'Active'; riskScore = 'Low'; exposureLevel = 'Medium'; onboardingStatus = 'Onboarded'; rbacGroupName = 'Workstations'
        machineTags = @('vip'); lastSeen = '2026-10-05T06:00:00Z'; firstSeen = '2025-01-01T00:00:00Z'; aadDeviceId = 'aad00000-0000-0000-0000-000000000001'
        managedBy = 'Intune'; managedByStatus = 'Success'; lastIpAddress = '10.0.0.7'; deviceValue = 'Normal'; isPotentialDuplication = $false
        vmMetadata = $null; ipAddresses = @([pscustomobject]@{ ipAddress = '10.0.0.7'; macAddress = '001122334455' })
    }
    $script:ArgRow = [pscustomobject][ordered]@{
        ResourceId = '/subscriptions/s1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm1'; Type = 'microsoft.compute/virtualmachines'
        Name = 'vm1'; Location = 'westeurope'; RG = 'rg1'; Subscription = 's1'
        PropertiesJson = '{"hardwareProfile":{"vmSize":"Standard_D4s_v5"},"storageProfile":{"dataDisks":[{"lun":0},{"lun":1}]}}'
        TagsJson = '{"Environment":"prod"}'; IdentityJson = '{"type":"SystemAssigned"}'; SkuJson = ''; Kind = ''; EnvTag = 'prod'; OwnerTag = ''
    }
    $script:ArgEnvelope = [ordered]@{ FullId = '/subscriptions/s1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1'; FullType = 'Microsoft.Compute/virtualMachines'
                                      FullTenantId = 't1'; FullManagedBy = ''; FullPlan = $null; FullZones = @('1'); FullExtendedLocation = $null }

    # ---- the fakes: they RECORD every request ----
    $script:Calls = New-Object System.Collections.Generic.List[string]
    function script:Project($Obj, [string]$Url) {
        $m = [regex]::Match($Url, '[?&]\$select=([^&]*)')
        if (-not $m.Success) { return $Obj }
        $o = [ordered]@{}
        foreach ($f in ($m.Groups[1].Value -split ',')) { $p = $Obj.PSObject.Properties[$f]; $o[$f] = $(if ($p) { $p.Value } else { $null }) }
        [pscustomobject]$o
    }
    $script:RefuseFullSelect = $false

    # ---- the levels ----
    function script:AtLevel([string]$Level, [string]$Engine) {
        $null = Reset-SIFullAssetProperties -Engine $Engine
        if ($Level -eq 'full') { Set-SIFullAssetPropertiesLevel -Level full }
    }
    # a record as the staging blob hands it on (JSON) -- the same text at both levels means the same record
    function script:Canon($Record) { $o = [ordered]@{}; foreach ($k in @($Record.Keys | Sort-Object)) { $o[[string]$k] = $Record[$k] }; ConvertTo-Json -InputObject $o -Depth 8 -Compress }

    # one built row per record, from a child process (the builders define the same helper names)
    function script:BuildRows {
        param([Parameter(Mandatory)][string]$Builder, [Parameter(Mandatory)][string]$Function, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][object[]]$Records)
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-onepull-' + [guid]::NewGuid().ToString('N') + '.json')
        [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject @($Records) -Depth 10))
        $cmd = @"
`$ErrorActionPreference='Stop'
. '$(Join-Path $script:Shared $Builder)'
`$recs = [IO.File]::ReadAllText('$tmp') | ConvertFrom-Json   # NOT @(...): PS 5.1 hands the whole array on as ONE object
`$rc  = [pscustomobject]@{ CollectionTime = '2026-10-06T00:00:00Z'; Engine = '$Engine'; RunId = 'r1' }
foreach (`$r in `$recs) {
    `$row = $Function -Record `$r -RunContext `$rc
    '<ROW>' + (ConvertTo-Json -Compress -Depth 8 -InputObject `$row)
}
"@
        # the child runs the gate's own PowerShell (v3 gates PowerShell 7 only, 2026-10-09; 5.1 on the opt-in)
        $exe = (Get-Process -Id $PID).Path
        $env51 = $env:PSModulePath
        if ($exe -match '(?i)\\WindowsPowerShell\\v1\.0\\powershell\.exe$') { $env:PSModulePath = 'C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules' }
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
        try { $out = & $exe -NoProfile -NonInteractive -EncodedCommand $enc 2>&1 } finally { $env:PSModulePath = $env51; Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
        $rows = @(@($out) | Where-Object { "$_" -like '<ROW>*' } | ForEach-Object { ([string]$_) -replace '^<ROW>', '' })
        if ($rows.Count -ne @($Records).Count) { throw ("the builder produced {0} row(s) for {1} record(s); output was: {2}" -f $rows.Count, @($Records).Count, (($out | Select-Object -Last 6) -join ' | ')) }
        $rows
    }
}

AfterAll {
    $global:SI_WorkspaceResourceId = $script:SavedWs
    $global:SIFullAssetPropertiesState = $null
}

Describe 'Graph sources: the security level asks exactly what it always asked; full asks ONCE for the same fields plus the rest' {

    BeforeEach {
        $script:Calls.Clear()
        Mock Get-SIGraphToken { 'tok' }
        Mock Invoke-SIPagedRest {
            $script:Calls.Add([string]$Url)
            # the full pull: a wide $select, or -- for a device -- no $select at all (the whole object)
            if ($script:RefuseFullSelect -and ($Url -match 'onPremisesLastSyncDateTime|givenName|appRoles' -or ($Url -match '/devices\?' -and $Url -notmatch '\$select='))) { return [pscustomobject]@{ Rows = @(); Complete = $false; Pages = 0; Retries = 0; Error = "The remote server returned an error: (400) Bad Request. Could not find a property named 'x'." } }
            $src = if ($Url -match '/devices') { $script:Device } elseif ($Url -match '/deletedItems') { $null } elseif ($Url -match '/users') { $script:User } elseif ($Url -match '/servicePrincipals') { $script:Spn } elseif ($Url -match '/api/machines') { $script:Machine } else { $null }
            $rows = if ($src) { @(script:Project $src $Url) } else { @() }
            [pscustomobject]@{ Rows = $rows; Complete = $true; Pages = 1; Retries = 0; Error = $null }
        }
        foreach ($c in 'Get-SIEntraRoleDefinitionMap', 'Get-SIEntraRoleAssignmentsByPrincipal', 'Get-SIEntraPIMEligibleByPrincipal', 'Get-SIEntraMfaRegistrationByPrincipal',
                       'Get-SIRoleAssignedGroups', 'Get-SIIdentityInfoByObjectId', 'Get-SIExposureGraphIdentities', 'Get-SISpnSignInLastActivity', 'Get-SIAzureDelegationsByPrincipal',
                       'Get-SIAppRolePermissionResolver') { Mock $c { @{} } }
        Mock Get-SIInheritedRolesForPrincipal { [pscustomobject]@{ Permanent = @(); Eligible = @() } }
        Mock Get-SIEntraPasswordlessByUser { @{} }   # #549 the sign-in methods read: no Graph call here (SIv3-PasswordlessOnly)
        Mock Get-SISPAppRoleAssignments { @('User.Read.All') }
        Mock Get-SISPOauth2Grants { @() }
        # the tenant-wide delegated-grant read and the applications read are their own requests (SIv3-EntraContext); not
        # answered here, the discovery reads the grants per service principal (above) and counts the principal's own owners
        Mock Get-SIOauth2GrantsByClient { $null }
        Mock Get-SIEntraApplications { $null }
        Mock Reset-SIPermissionFetchFailures { }
        Mock Write-SIPermissionFetchSummary { }
        $script:RefuseFullSelect = $false
    }

    It 'entra-device: the same request at the security level, keeping nothing; ONE wide request at full; the same record' {
        script:AtLevel security endpoint
        $sec = @(Get-DiscoveryFromEntra)
        $script:Calls.ToArray() | Should -Be @('https://graph.microsoft.com/v1.0/devices?$select=id,deviceId,displayName,operatingSystem,deviceCategory,trustType,profileType,registrationDateTime,approximateLastSignInDateTime,accountEnabled,onPremisesSecurityIdentifier,onPremisesSyncEnabled&$top=999')
        @(Get-SIFullSourceObjects).Count | Should -Be 0
        $script:Calls.Clear()
        script:AtLevel full endpoint
        $full = @(Get-DiscoveryFromEntra)
        $script:Calls.Count | Should -Be 1 -Because 'one pull per source -- never a second pass'
        # continuous discovery: a device is read WHOLE at the full level -- no property list, so a property Microsoft adds
        # arrives on the next run with no code change
        $script:Calls[0] | Should -Be 'https://graph.microsoft.com/v1.0/devices?$top=999' -Because 'the whole object: the same URL without its $select'
        (script:Canon $full[0]) | Should -Be (script:Canon $sec[0])
        $kept = @(Get-SIFullSourceObjects)
        $kept.Count | Should -Be 1
        $kept[0].SourceSystem | Should -Be 'entra-device'
        ($kept[0].AnchorColumn, $kept[0].AnchorValue) | Should -Be @('AadDeviceId', 'aad00000-0000-0000-0000-000000000001')
        $kept[0].Object.manufacturer | Should -Be 'Contoso'
        @($kept[0].Object.physicalIds).Count | Should -Be 2 -Because 'arrays stay arrays'
        (Get-SIFullAssetPropertiesState).Pulls['entra-device'].Complete | Should -BeTrue
    }

    It 'entra-user: the same request at security; one wide request at full; the same record; the object is the source''s (no ENTRA_IsDeleted)' {
        script:AtLevel security identity
        $sec = @(Get-DiscoveryFromEntraUsers)
        $usersCalls = @($script:Calls | Where-Object { $_ -match '/v1.0/users\?' })
        $usersCalls | Should -Be @('https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,jobTitle,department,onPremisesSyncEnabled,onPremisesSecurityIdentifier,onPremisesImmutableId,onPremisesSamAccountName,onPremisesDistinguishedName,onPremisesDomainName,mail,userType,assignedLicenses,signInActivity,customSecurityAttributes&$top=999')
        $secAll = $script:Calls.ToArray()
        $script:Calls.Clear()
        script:AtLevel full identity
        $full = @(Get-DiscoveryFromEntraUsers)
        @($script:Calls | Where-Object { $_ -match '/v1.0/users\?' }).Count | Should -Be 1
        @($script:Calls | Where-Object { $_ -match 'deletedItems' }) | Should -Be @($secAll | Where-Object { $_ -match 'deletedItems' }) -Because 'the deleted-users read is the same call at both levels'
        (script:Canon $full[0]) | Should -Be (script:Canon $sec[0])
        $k = @(Get-SIFullSourceObjects | Where-Object SourceSystem -eq 'entra-user')
        $k.Count | Should -Be 1
        $k[0].Object.givenName | Should -Be 'Ada'
        $k[0].Object.PSObject.Properties['ENTRA_IsDeleted'] | Should -BeNullOrEmpty
        $k[0].AnchorColumn | Should -Be 'EntraAccountObjectId'
    }

    It 'entra-serviceprincipal: the same request at security; one wide request at full; the same record' {
        script:AtLevel security identity
        $sec = @(Get-DiscoveryFromEntraServicePrincipals)
        # the owners read (derived.ownerCount) is its own request, not the source pull: the same call at both levels
        @($script:Calls | Where-Object { $_ -notmatch '\$expand=owners' }) | Should -Be @('https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,displayName,appId,servicePrincipalType,signInAudience,accountEnabled,publisherName,verifiedPublisher,appOwnerOrganizationId,passwordCredentials,keyCredentials,tags,homepage,customSecurityAttributes,createdDateTime&$top=999')
        $secOwners = @($script:Calls | Where-Object { $_ -match '\$expand=owners' })
        $secOwners | Should -Be @('https://graph.microsoft.com/v1.0/servicePrincipals?$select=id&$expand=owners($select=id,displayName,userPrincipalName)&$top=100')
        $script:Calls.Clear()
        script:AtLevel full identity
        $full = @(Get-DiscoveryFromEntraServicePrincipals)
        @($script:Calls | Where-Object { $_ -notmatch '\$expand=owners' }).Count | Should -Be 1 -Because 'one pull per source -- never a second pass'
        @($script:Calls | Where-Object { $_ -match '\$expand=owners' }) | Should -Be $secOwners -Because 'the owners read is the same call at both levels'
        (script:Canon $full[0]) | Should -Be (script:Canon $sec[0])
        @(Get-SIFullSourceObjects)[0].Object.replyUrls | Should -Be @('https://payroll.contoso.test/signin')
    }

    It 'mde: the request is the same at both levels (nothing was ever narrowed there); full keeps the whole machine object' {
        script:AtLevel security endpoint
        $sec = @(Get-DiscoveryFromMDE)
        $c1 = $script:Calls.ToArray(); $script:Calls.Clear()
        script:AtLevel full endpoint
        $full = @(Get-DiscoveryFromMDE)
        $script:Calls.ToArray() | Should -Be $c1
        $c1 | Should -Be @('https://api.securitycenter.microsoft.com/api/machines')
        (script:Canon $full[0]) | Should -Be (script:Canon $sec[0])
        $k = @(Get-SIFullSourceObjects)
        $k[0].Object.lastIpAddress | Should -Be '10.0.0.7'
        ($k[0].AnchorColumn, $k[0].AnchorValue) | Should -Be @('MdeDeviceId', '0c8545c566aa838508be174878084b0c7a9cfd4e')
    }

    It 'a full $select Graph refuses is read again with the security URL, said, and the record is unchanged' {
        script:AtLevel security endpoint
        $sec = @(Get-DiscoveryFromEntra)
        $script:Calls.Clear()
        script:AtLevel full endpoint
        $script:RefuseFullSelect = $true
        $full = @(Get-DiscoveryFromEntra 3>$null)
        $script:Calls.Count | Should -Be 2
        $script:Calls[1] | Should -Match 'approximateLastSignInDateTime,accountEnabled,onPremisesSecurityIdentifier,onPremisesSyncEnabled&\$top=999$'
        (script:Canon $full[0]) | Should -Be (script:Canon $sec[0])
        (Get-SIFullAssetPropertiesState).Pulls['entra-device'].Narrowed | Should -BeTrue
    }
}

Describe 'Resource Graph and Exposure Graph: the same query at security; at full the SAME query with the ARM envelope appended' {

    BeforeEach {
        $script:Kql = New-Object System.Collections.Generic.List[string]
        Mock Search-SIAzGraph {
            $script:Kql.Add([string]$Query)
            $r = $script:ArgRow.PSObject.Copy()
            if ($Query -match 'FullId = id') { foreach ($k in $script:ArgEnvelope.Keys) { $r | Add-Member -NotePropertyName $k -NotePropertyValue $script:ArgEnvelope[$k] -Force } }
            , @($r)
        }
    }

    It 'arm: one query per level, the security projection untouched; the same record; the whole resource kept, arrays as arrays' {
        script:AtLevel security azure
        $sec = @(Get-DiscoveryFromAzureResources)
        # the management-group read (derived.managementGroupPath) is its own query over resourcecontainers, not the source
        # pull: the same query at both levels
        $secMg = @($script:Kql | Where-Object { $_ -match 'resourcecontainers' })
        $secMg.Count | Should -Be 1
        @($script:Kql | Where-Object { $_ -notmatch 'resourcecontainers' }).Count | Should -Be 1
        $secKql = @($script:Kql | Where-Object { $_ -notmatch 'resourcecontainers' })[0]
        $secKql | Should -Not -Match 'FullId'
        @(Get-SIFullSourceObjects).Count | Should -Be 0
        $script:Kql.Clear()
        script:AtLevel full azure
        $full = @(Get-DiscoveryFromAzureResources)
        @($script:Kql | Where-Object { $_ -match 'resourcecontainers' }) | Should -Be $secMg -Because 'the management-group read is the same query at both levels'
        $fullKql = @($script:Kql | Where-Object { $_ -notmatch 'resourcecontainers' })
        $fullKql.Count | Should -Be 1 -Because 'one pull per source -- never a second pass'
        $fullKql[0] | Should -Be (Get-SIFullArgKql -SecurityKql $secKql)
        $fullKql[0].Replace((',' + "`r`n" + '    ' + 'FullId = id, FullType = type, FullTenantId = tenantId, FullManagedBy = managedBy, FullPlan = plan, FullZones = zones, FullExtendedLocation = extendedLocation'), '').Replace((',' + "`n" + '    ' + 'FullId = id, FullType = type, FullTenantId = tenantId, FullManagedBy = managedBy, FullPlan = plan, FullZones = zones, FullExtendedLocation = extendedLocation'), '') | Should -Be $secKql
        (script:Canon $full[0]) | Should -Be (script:Canon $sec[0])
        $o = @(Get-SIFullSourceObjects)[0].Object
        $o.id | Should -Be '/subscriptions/s1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1'
        $o.properties.hardwareProfile.vmSize | Should -Be 'Standard_D4s_v5'
        @($o.properties.storageProfile.dataDisks).Count | Should -Be 2
        $o.tags.Environment | Should -Be 'prod'
        @($o.zones) | Should -Be @('1')
    }

    It 'exposure-graph (endpoint): the query is the same at both levels; full keeps the node it already returned' {
        $node = [pscustomobject]@{ NodeId = '39c558c1a469451b92833e523481f998'; NodeName = 'laptop-7'; NodeLabel = 'device'; EntityIds = @()
                                   NodePropertiesJson = '{"rawData":{"deviceName":"laptop-7","osPlatform":"Windows11","ipInterfaces":[{"ip":"10.0.0.7"}]}}' }
        $script:EgBodies = New-Object System.Collections.Generic.List[string]
        Mock Get-SIGraphToken { 'tok' }
        Mock Invoke-RestMethod { $script:EgBodies.Add([string]$Body); [pscustomobject]@{ results = @($node) } }
        script:AtLevel security endpoint
        $sec = @(Get-DiscoveryFromEndpointViaEG)
        script:AtLevel full endpoint
        $full = @(Get-DiscoveryFromEndpointViaEG)
        $script:EgBodies[0] | Should -Be $script:EgBodies[1]
        (script:Canon $full[0]) | Should -Be (script:Canon $sec[0])
        $k = @(Get-SIFullSourceObjects)[0]
        ($k.SourceSystem, $k.AnchorColumn, $k.AnchorValue) | Should -Be @('exposure-graph', 'ExposureGraphNodeId', '39c558c1a469451b92833e523481f998')
        @($k.Object.NodeProperties.rawData.ipInterfaces).Count | Should -Be 1
    }
}

Describe 'GOLDEN: the same source data gives the same SI_*_Profile_CL row at both levels' {

    BeforeAll {
        Mock Get-SIGraphToken { 'tok' }
        Mock Invoke-SIPagedRest {
            $src = if ($Url -match '/devices') { $script:Device } elseif ($Url -match '/users') { $script:User } elseif ($Url -match '/servicePrincipals') { $script:Spn } elseif ($Url -match '/api/machines') { $script:Machine } else { $null }
            [pscustomobject]@{ Rows = $(if ($src -and $Url -notmatch 'deletedItems') { @(script:Project $src $Url) } else { @() }); Complete = $true; Pages = 1; Retries = 0; Error = $null }
        }
        foreach ($c in 'Get-SIEntraRoleDefinitionMap', 'Get-SIEntraRoleAssignmentsByPrincipal', 'Get-SIEntraPIMEligibleByPrincipal', 'Get-SIEntraMfaRegistrationByPrincipal',
                       'Get-SIRoleAssignedGroups', 'Get-SIIdentityInfoByObjectId', 'Get-SIExposureGraphIdentities', 'Get-SISpnSignInLastActivity', 'Get-SIAzureDelegationsByPrincipal',
                       'Get-SIAppRolePermissionResolver') { Mock $c { @{} } }
        Mock Get-SIInheritedRolesForPrincipal { [pscustomobject]@{ Permanent = @(); Eligible = @() } }
        Mock Get-SIEntraPasswordlessByUser { @{} }   # #549 the sign-in methods read: no Graph call here (SIv3-PasswordlessOnly)
        Mock Get-SISPAppRoleAssignments { @('User.Read.All') }
        Mock Get-SISPOauth2Grants { @() }
        # the tenant-wide delegated-grant read and the applications read are their own requests (SIv3-EntraContext); not
        # answered here, the discovery reads the grants per service principal (above) and counts the principal's own owners
        Mock Get-SIOauth2GrantsByClient { $null }
        Mock Get-SIEntraApplications { $null }
        Mock Reset-SIPermissionFetchFailures { }
        Mock Write-SIPermissionFetchSummary { }
        Mock Search-SIAzGraph {
            $r = $script:ArgRow.PSObject.Copy()
            if ($Query -match 'FullId = id') { foreach ($k in $script:ArgEnvelope.Keys) { $r | Add-Member -NotePropertyName $k -NotePropertyValue $script:ArgEnvelope[$k] -Force } }
            , @($r)
        }
        # a record as the Output stage hands it to the row builder: the discovery record is its metadata
        function script:AsRecord($Meta, [string]$Primary) { [pscustomobject]@{ AssetId = $Primary; PrimaryEntityId = $Primary; SI_RunId = 'r1'; TimeGenerated = '2026-10-06T00:00:00Z'; SI_Classify_Status = 'no-ai'; Metadata = $Meta; Verdict = [pscustomobject]@{ SI_Tier = 2 } } }
        function script:Merge([hashtable[]]$Parts) { $m = @{}; foreach ($p in $Parts) { foreach ($k in $p.Keys) { if (-not $m.ContainsKey($k)) { $m[$k] = $p[$k] } } }; $m }
    }

    It 'endpoint (Defender machine + Entra device): every field of the row is the same' {
        script:AtLevel security endpoint
        $s = script:Merge @(@(Get-DiscoveryFromMDE)[0], @(Get-DiscoveryFromEntra)[0])
        script:AtLevel full endpoint
        $f = script:Merge @(@(Get-DiscoveryFromMDE)[0], @(Get-DiscoveryFromEntra)[0])
        $rows = @(script:BuildRows -Builder 'Build-EndpointProfileRow.ps1' -Function 'Build-SIEndpointProfileRow' -Engine 'endpoint' -Records @((script:AsRecord $s $script:Machine.id), (script:AsRecord $f $script:Machine.id)))
        $rows[1] | Should -Be $rows[0]
        $rows[0] | Should -Match '"MdeDeviceId":"0c8545c566aa838508be174878084b0c7a9cfd4e"' -Because 'a real row was built from the record, not an empty one'
        $rows[0] | Should -Match 'laptop-7'
    }

    It 'identity (an Entra user and a service principal): every field of each row is the same' {
        script:AtLevel security identity
        $su = @(Get-DiscoveryFromEntraUsers)[0]; $ss = @(Get-DiscoveryFromEntraServicePrincipals)[0]
        script:AtLevel full identity
        $fu = @(Get-DiscoveryFromEntraUsers)[0]; $fs = @(Get-DiscoveryFromEntraServicePrincipals)[0]
        $rows = @(script:BuildRows -Builder 'Build-IdentityProfileRow.ps1' -Function 'Build-SIIdentityProfileRow' -Engine 'identity' -Records @(
            (script:AsRecord $su $script:User.id), (script:AsRecord $fu $script:User.id), (script:AsRecord $ss $script:Spn.id), (script:AsRecord $fs $script:Spn.id)))
        $rows[1] | Should -Be $rows[0]
        $rows[3] | Should -Be $rows[2]
        $rows[0] | Should -Match 'ada@contoso.test'
    }

    It 'azure (an ARM resource): every field of the row is the same' {
        script:AtLevel security azure
        $s = @(Get-DiscoveryFromAzureResources)[0]
        script:AtLevel full azure
        $f = @(Get-DiscoveryFromAzureResources)[0]
        $rows = @(script:BuildRows -Builder 'Build-AzureProfileRow.ps1' -Function 'Build-SIAzureProfileRow' -Engine 'azure' -Records @((script:AsRecord $s $script:ArgRow.ResourceId), (script:AsRecord $f $script:ArgRow.ResourceId)))
        $rows[1] | Should -Be $rows[0]
        $rows[0] | Should -Match 'Standard_D4s_v5'
    }
}

Describe 'the level: security unless asked for, licensed and present; nothing downstream reads it' {

    It 'security is the default; full needs the setting AND the Pro publisher; the Community copy stays security and says so' {
        $null = Reset-SIFullAssetProperties -Engine endpoint
        Test-SIFullAssetPropertiesOn | Should -BeFalse
        Get-SIFullAssetPropertiesSetting $null | Should -Be 'security'
        Get-SIFullAssetPropertiesSetting 'wide' | Should -Be 'security'
        Get-SIFullAssetPropertiesSetting ' FULL ' | Should -Be 'full'
        Initialize-SIFullAssetProperties -Engine endpoint -SIRoot $script:SIRoot -Setting 'security' | Should -BeNullOrEmpty
        $empty = Join-Path ([IO.Path]::GetTempPath()) ('si-community-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $empty
        try {
            $said = New-Object System.Collections.Generic.List[string]
            Initialize-SIFullAssetProperties -Engine endpoint -SIRoot $empty -Setting 'full' -Log { param($l, $m) $said.Add($m) } | Should -BeNullOrEmpty
            Test-SIFullAssetPropertiesOn | Should -BeFalse
            ($said -join ' ') | Should -Match 'SecurityInsight Pro feature'
        } finally { Remove-Item -LiteralPath $empty -Recurse -Force }
        Initialize-SIFullAssetProperties -Engine publicip -SIRoot $script:SIRoot -Setting 'full' | Should -BeNullOrEmpty -Because 'public IPs are a property, never a CI (3.6)'
        @(Get-SIFullAssetPropertiesEngineSources 'endpoint') | Should -Be @('mde', 'entra-device', 'exposure-graph', 'intune-device')
    }

    It 'nothing is kept at the security level, and a kept object is a COPY (later stamps do not reach it)' {
        $null = Reset-SIFullAssetProperties -Engine identity
        Add-SIFullSourceObject -SourceSystem 'entra-user' -Object ([pscustomobject]@{ id = 'x' })
        @(Get-SIFullSourceObjects).Count | Should -Be 0
        Set-SIFullAssetPropertiesLevel -Level full
        $o = [pscustomobject]@{ id = 'x'; tags = @('a') }
        Add-SIFullSourceObject -SourceSystem 'entra-user' -Object $o -AnchorColumn 'EntraAccountObjectId' -AnchorValue 'x'
        $o | Add-Member -NotePropertyName ENTRA_IsDeleted -NotePropertyValue $true
        @(Get-SIFullSourceObjects)[0].Object.PSObject.Properties['ENTRA_IsDeleted'] | Should -BeNullOrEmpty
    }

    It 'the full $select keeps the security fields first, adds the rest once, and leaves a URL without $select alone' {
        $u = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,city&$top=999'
        $w = Get-SIFullGraphUrl -SourceSystem 'entra-user' -SecurityUrl $u
        $w | Should -Match '^https://graph\.microsoft\.com/v1\.0/users\?\$select=id,displayName,city,businessPhones,'
        $w | Should -Match '&\$top=999$'
        @((Get-SIFullGraphSelectFields -Url $w) | Where-Object { $_ -eq 'city' }).Count | Should -Be 1
        Get-SIFullGraphUrl -SourceSystem 'entra-user' -SecurityUrl 'https://graph.microsoft.com/v1.0/users?$top=999' | Should -Be 'https://graph.microsoft.com/v1.0/users?$top=999'
        # a device is read WHOLE: its full URL is the security URL without the $select, wherever the $select stands
        Get-SIFullGraphUrl -SourceSystem 'entra-device' -SecurityUrl 'https://graph.microsoft.com/v1.0/devices?$select=id,deviceId,model&$top=999' | Should -Be 'https://graph.microsoft.com/v1.0/devices?$top=999'
        Get-SIFullGraphUrl -SourceSystem 'entra-device' -SecurityUrl 'https://graph.microsoft.com/v1.0/devices?$top=999&$select=id,deviceId' | Should -Be 'https://graph.microsoft.com/v1.0/devices?$top=999'
        Get-SIFullGraphUrl -SourceSystem 'entra-device' -SecurityUrl 'https://graph.microsoft.com/v1.0/devices?$select=id' | Should -Be 'https://graph.microsoft.com/v1.0/devices'
        Get-SIFullGraphUrl -SourceSystem 'entra-device' -SecurityUrl 'https://graph.microsoft.com/v1.0/devices?$top=999' | Should -Be 'https://graph.microsoft.com/v1.0/devices?$top=999'
        Get-SIFullGraphUrl -SourceSystem 'mde' -SecurityUrl $u | Should -Be $u
        foreach ($bad in 'mailboxSettings', 'aboutMe', 'birthday', 'hireDate', 'skills', 'employeeLeaveDateTime') {
            (Get-SIFullGraphUrl -SourceSystem 'entra-user' -SecurityUrl 'https://graph.microsoft.com/v1.0/users?$select=id&$top=999') | Should -Not -Match ([regex]::Escape(',' + $bad)) -Because "$bad is not selectable on the collection (or needs another permission) and would refuse the whole request"
        }
    }

    It 'WIRING: no stage after discovery and no row builder reads the level -- the record is the only input' {
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'engine\asset-profiling\stages') -Filter '*.ps1') + @(Get-ChildItem -LiteralPath $script:Shared -Filter 'Build-*ProfileRow.ps1')) {
            if ($f.Name -in 'Invoke-Discover.ps1', 'Invoke-Output.ps1') { continue }
            (Get-Content -Raw -LiteralPath $f.FullName) | Should -Not -Match 'SIFullAssetProperties|Add-SIFullSourceObject|Test-SIFullAssetPropertiesOn' -Because "$($f.Name) must build the same thing at both levels"
        }
        # Output publishes AFTER the profile post, and only through the never-throwing wrapper
        $out = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Output.ps1')
        $out.IndexOf('Publish-SIFullAssetProperties -RunContext') | Should -BeGreaterThan $out.IndexOf('$null = Send-SILogData')
        # the run decides the level once, before discovery
        $run = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1')
        $run.IndexOf('Initialize-SIFullAssetProperties') | Should -BeLessThan $run.IndexOf("foreach (`$s in `$stages)")
    }
}
