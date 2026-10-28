#Requires -Version 7.0
<#
    The CI build at the size of a large install -- the shared fixture of tests\pester\SIv3-CiBuildSpeed.Tests.ps1 and of
    tests\fixtures\ci-perf\Measure-SICiBuildScale.ps1 (the offline measurement on the test VM).

    A synthetic tenant shaped like the large ring 1 install of #605 (~100,000 directory objects -> ~94,000 provider records ->
    ~77,000 CIs at -Scale 1): Entra users (a tenth also seen by Defender for Identity), service principals, Entra devices,
    Defender devices (most joined to an Entra device, the servers to an Azure virtual machine) and Azure virtual machines.
    The raw objects go through the REAL record capture and field mapping (SI-RecordCapture.ps1) and the real record writer
    into a local SQL Server database -- what the CI build reads is what a real collection writes.

      Get-CiPerfShape -Scale s               the counts per kind
      Write-CiPerfTenant -Scale s -Invoke q  makes the raw objects in chunks, captures them, writes the records (SQL seam q)
      New-CiPerfDatabase / Remove-...        a fresh database on the local SQL Server Express with the updater's schema and the
                                             engine's least-privilege identity (as SIv3-CiBuildSql.Tests.ps1 does it)
      Get-CiPerfCiDigest -Invoke q           every CI the build stored, in a comparable form (id, members, links, tier, claims,
                                             CMDB fields, the whole document without the values that change every build)

    Deterministic: every value is derived from the object's index (no random numbers, no clock). Synthetic data only: no
    tenant, no customer value.
#>

function Get-CiPerfShape {
    <# PURE. The counts of one synthetic tenant. -Scale 1 = the large install of #605 (~94,000 records, ~77,000 CIs). #>
    param([double]$Scale = 1.0)
    $n = { param($x) [int][Math]::Max(1, [Math]::Round($x * $Scale)) }
    $users = & $n 52000
    $mdeDev = & $n 12000
    $servers = [int][Math]::Max(1, [Math]::Round($mdeDev / 6))
    [pscustomobject]@{
        Users = $users; MdiUsers = [int][Math]::Floor($users / 10); ServicePrincipals = (& $n 9000); EntraDevices = (& $n 14000); StorageAccounts = [int][Math]::Max(1, [Math]::Round($servers / 4))
        MdeDevices = $mdeDev; Servers = $servers; AzureVms = $servers; Groups = [Math]::Max(50, (& $n 3000))
    }
}

function New-CiPerfGuid {
    <# PURE. A deterministic GUID text from a kind number and an index. #>
    param([int]$Kind, [long]$I)
    '{0:x8}-{1:x4}-4{2:x3}-8{3:x3}-{4:x12}' -f ($I * 2654435761 % 4294967296), $Kind, ($I % 4096), (($I * 7) % 4096), ($I * 1000003 + $Kind)
}

function Get-CiPerfGroupName {
    <# PURE. The pool of group names users are members of: mostly plain, a few the rule packs care about. #>
    param([int]$G)
    $special = @('Domain Admins', 'Enterprise Admins', 'Server Operators', 'Backup Operators', 'Account Operators', 'Print Operators', 'Schema Admins', 'DnsAdmins',
        'SG-Tier0-Admins', 'SG-PAW-Users', 'SG-Helpdesk', 'SG-Finance-Payroll', 'SG-HR-Confidential', 'SG-Developers', 'SG-Contractors')
    if ($G -lt $special.Count) { return $special[$G] }
    $dept = @('Sales', 'Finance', 'IT', 'HR', 'Operations', 'Marketing', 'Legal', 'Support', 'Engineering', 'Logistics')
    'SG-{0}-{1}-{2:D4}' -f $dept[$G % $dept.Count], @('Users', 'Readers', 'Owners', 'Project', 'Share', 'App')[$G % 6], $G
}

function Add-CiPerfUserParts {
    <# The raw parts of Entra user $i (and, every tenth, its Defender for Identity record) -- the shape the identity read keeps. #>
    param([int]$I, $Shape, [datetime]$T)
    $id = New-CiPerfGuid 1 $I
    $upn = 'user{0:D6}@contoso.example' -f $I
    $guest = ($I % 11) -eq 0
    $synced = (-not $guest) -and (($I % 10) -lt 7)
    $u = [ordered]@{ id = $id; userPrincipalName = $upn; displayName = ('User {0:D6}' -f $I); mail = $upn; accountEnabled = (($I % 29) -ne 0)
        userType = $(if ($guest) { 'Guest' } else { 'Member' }); createdDateTime = $T.AddDays(-30 - ($I % 2000)).ToString('o')
        department = @('Sales', 'Finance', 'IT', 'HR', 'Operations', 'Marketing', 'Legal', 'Support')[$I % 8]; jobTitle = @('Engineer', 'Manager', 'Consultant', 'Analyst', 'Administrator', 'Assistant')[$I % 6]
        country = @('Denmark', 'Sweden', 'Norway', 'Germany')[$I % 4]; employeeId = ('E{0:D7}' -f $I); employeeType = @('Employee', 'Contractor')[[int](($I % 9) -eq 0)]
        lastPasswordChangeDateTime = $T.AddDays(-($I % 400)).ToString('o')
        signInActivity = [ordered]@{ lastSignInDateTime = $T.AddHours(-($I % 2000)).ToString('o'); lastNonInteractiveSignInDateTime = $T.AddHours(-($I % 300)).ToString('o'); lastSuccessfulSignInDateTime = $T.AddHours(-($I % 2000)).ToString('o') }
        passwordPolicies = $(if (($I % 37) -eq 0) { 'DisablePasswordExpiration' } else { 'None' })
        onPremisesSyncEnabled = $synced }
    if ($synced) {
        $u['onPremisesSecurityIdentifier'] = 'S-1-5-21-1111111111-2222222222-3333333333-{0}' -f (100000 + $I)
        $u['onPremisesSamAccountName'] = 'user{0:D6}' -f $I
        $ext = [ordered]@{}
        for ($e = 1; $e -le 15; $e++) { $ext["extensionAttribute$e"] = $null }
        $ext['extensionAttribute1'] = @('Copenhagen', 'Aarhus', 'Odense')[$I % 3]
        if (($I % 200) -eq 0) { $ext['extensionAttribute10'] = 'AdminAccounts--tier0--SI' }
        elseif (($I % 50) -eq 0) { $ext['extensionAttribute10'] = 'ServerAdmins--tier1--SI' }
        $u['onPremisesExtensionAttributes'] = $ext
    }
    Add-SIRecordPart -Provider entra -RecordType user -Key $id -Part user -Object ([pscustomobject]$u)
    $methods = @('microsoftAuthenticatorPush', 'softwareOneTimePasscode', 'mobilePhone', 'fido2', 'windowsHelloForBusiness')
    $mr = @(); if (($I % 7) -ne 0) { $mr = @($methods[0..(($I % 4) + 0)]) }
    Add-SIRecordPart -Provider entra -RecordType user -Key $id -Part registration -Object ([pscustomobject]@{ id = $id; isMfaRegistered = ($mr.Count -gt 0); methodsRegistered = $mr; defaultMfaMethod = $(if ($mr.Count) { $mr[0] } else { 'none' }) })
    # transitive group memberships: 4 - 40 names out of the pool
    $nG = 4 + ($I % 37)
    $groups = @(for ($k = 0; $k -lt $nG; $k++) { $g = 15 + (($I * 31 + $k * 97) % ($Shape.Groups - 15)); [ordered]@{ id = (New-CiPerfGuid 9 $g); displayName = (Get-CiPerfGroupName $g) } })
    if (($I % 400) -eq 0) { $groups += [ordered]@{ id = (New-CiPerfGuid 9 ($I % 15)); displayName = (Get-CiPerfGroupName ($I % 15)) } }
    Add-SIRecordPart -Provider entra -RecordType user -Key $id -Part memberOf -Object $groups
    if (($I % 100) -eq 0) {
        $roleSet = @('Global Administrator', 'Security Administrator', 'User Administrator', 'Helpdesk Administrator', 'Global Reader', 'Exchange Administrator')
        $perm = @($roleSet[($I / 100) % $roleSet.Count]); $elig = @($roleSet[(($I / 100) + 2) % $roleSet.Count])
        Add-SIRecordPart -Provider entra -RecordType user -Key $id -Part roles -Object ([pscustomobject]@{ permanent = $perm; eligible = $elig })
    }
    if (($I % 3) -eq 0) {
        $m = $I - ($I % 50)
        Add-SIRecordPart -Provider entra -RecordType user -Key $id -Part manager -Object ([pscustomobject]@{ id = (New-CiPerfGuid 1 $m); userPrincipalName = ('user{0:D6}@contoso.example' -f $m); displayName = ('User {0:D6}' -f $m) })
    }
    Add-SIRecordPart -Provider entra -RecordType user -Key $id -Part ca -Object ([pscustomobject]@{ policyCount = 6 + ($I % 5); mfaEnforced = (($I % 13) -ne 0); mfaPolicies = @('Require MFA for all users'); excluded = @(); excludedFromAll = $false })
    if (($I % 10) -eq 0) {
        $mdi = [ordered]@{ AccountObjectId = $id; AccountUpn = $upn; AccountName = ('user{0:D6}' -f $I); AccountDisplayName = ('User {0:D6}' -f $I); IsAccountEnabled = $true
            Tags = $(if (($I % 1000) -eq 0) { @('Sensitive') } else { @() }); InvestigationPriorityPercentile = ($I % 100) }
        if ($synced) { $mdi['OnPremSid'] = 'S-1-5-21-1111111111-2222222222-3333333333-{0}' -f (100000 + $I) }
        Add-SIRecordPart -Provider mdi -RecordType user -Key $id -Part identity -Object ([pscustomobject]$mdi)
    }
}

function Add-CiPerfSpParts {
    <# The raw parts of service principal $i: applications, managed identities and a few Microsoft first-party apps. #>
    param([int]$I, [datetime]$T)
    $id = New-CiPerfGuid 2 $I; $app = New-CiPerfGuid 3 $I
    $kind = @('Application', 'Application', 'Application', 'ManagedIdentity', 'Application')[$I % 5]
    $own = $(if (($I % 4) -eq 0) { '00000000-0000-0000-0000-0000000000ff' } else { '00000000-0000-0000-0000-0000000000aa' })
    $creds = @(); if ($kind -eq 'Application' -and ($I % 3) -eq 0) { $creds = @([ordered]@{ keyId = (New-CiPerfGuid 4 $I); endDateTime = $T.AddDays(-20 + ($I % 400)).ToString('o'); displayName = 'secret' }) }
    $sp = [ordered]@{ id = $id; appId = $app; displayName = ('App {0:D5} {1}' -f $I, @('Portal', 'Sync', 'Connector', 'Reporting', 'Automation')[$I % 5]); servicePrincipalType = $kind
        accountEnabled = (($I % 31) -ne 0); appOwnerOrganizationId = $own; signInAudience = @('AzureADMyOrg', 'AzureADMultipleOrgs')[[int](($I % 6) -eq 0)]
        createdDateTime = $T.AddDays(-($I % 1500)).ToString('o'); tags = @('WindowsAzureActiveDirectoryIntegratedApp'); passwordCredentials = $creds; publisherName = 'Contoso' }
    Add-SIRecordPart -Provider entra -RecordType service_principal -Key $id -Part sp -Object ([pscustomobject]$sp)
    if ($kind -eq 'Application') {
        Add-SIRecordPart -Provider entra -RecordType service_principal -Key $id -Part app -Object ([pscustomobject]@{ signInAudience = $sp.signInAudience; passwordCredentials = $creds; publisherDomain = 'contoso.example'; notes = $null; hasFederatedCredential = (($I % 17) -eq 0) })
        $nOwn = $I % 3
        $owners = @(for ($k = 0; $k -lt $nOwn; $k++) { $u = ($I * 13 + $k) % 50000; [ordered]@{ id = (New-CiPerfGuid 1 $u); upn = ('user{0:D6}@contoso.example' -f $u); name = ('User {0:D6}' -f $u); type = 'user' } })
        Add-SIRecordPart -Provider entra -RecordType service_principal -Key $id -Part owners -Object ([pscustomobject]@{ count = $nOwn; items = $owners })
    }
    if (($I % 25) -eq 0) {
        $perms = @('User.Read.All', 'Directory.Read.All', 'Mail.Send', 'Sites.Read.All', 'RoleManagement.ReadWrite.Directory')
        Add-SIRecordPart -Provider entra -RecordType service_principal -Key $id -Part appRoleAssignments -Object @(for ($k = 0; $k -le ($I % 4); $k++) { [ordered]@{ resource = 'Microsoft Graph'; permission = $perms[($I + $k) % $perms.Count] } })
    }
    if (($I % 2) -eq 0) {
        Add-SIRecordPart -Provider entra -RecordType service_principal -Key $id -Part signIn -Object ([pscustomobject]@{ lastSignInActivity = [ordered]@{ lastSignInDateTime = $T.AddDays(-($I % 120)).ToString('o') } })
    }
}

function Add-CiPerfEntraDeviceParts {
    <# The raw parts of Entra device $i, with its registered owner. #>
    param([int]$I, [datetime]$T)
    $did = New-CiPerfGuid 5 $I
    $os = @('Windows', 'Windows', 'Windows', 'iOS', 'Android', 'MacMDM')[$I % 6]
    $d = [ordered]@{ id = (New-CiPerfGuid 6 $I); deviceId = $did; displayName = ('PC-{0:D6}' -f $I); operatingSystem = $os; operatingSystemVersion = $(if ($os -eq 'Windows') { '10.0.22631.4317' } else { '17.6' })
        trustType = @('AzureAd', 'ServerAd', 'Workplace')[$I % 3]; isCompliant = (($I % 9) -ne 0); accountEnabled = $true; onPremisesSyncEnabled = (($I % 3) -eq 1)
        registrationDateTime = $T.AddDays(-($I % 900)).ToString('o'); approximateLastSignInDateTime = $T.AddHours(-($I % 700)).ToString('o')
        extensionAttributes = [ordered]@{ extensionAttribute1 = @('Laptop', 'Desktop', 'Kiosk')[$I % 3] } }
    Add-SIRecordPart -Provider entra -RecordType device -Key $did -Part device -Object ([pscustomobject]$d)
    $u = ($I * 3) % 50000
    Add-SIRecordPart -Provider entra -RecordType device -Key $did -Part registeredOwners -Object ([pscustomobject]@{ items = @([ordered]@{ id = (New-CiPerfGuid 1 $u); upn = ('user{0:D6}@contoso.example' -f $u); name = ('User {0:D6}' -f $u); type = 'user' }) })
}

function Add-CiPerfMdeDeviceParts {
    <# The raw parts of Defender device $i: the first ones are the Entra devices' (joined by the Entra device id), the last
       Shape.Servers are servers that run as Azure virtual machines (joined by the resource id). #>
    param([int]$I, $Shape, [datetime]$T)
    $mid = ('{0:x40}' -f ([long]$I * 7919 + 17))
    $server = $I -ge ($Shape.MdeDevices - $Shape.Servers)
    $sv = $I - ($Shape.MdeDevices - $Shape.Servers)
    $name = $(if ($server) { 'srv-app-{0:D5}.corp.contoso.example' -f $sv } else { 'pc-{0:D6}.corp.contoso.example' -f $I })
    $m = [ordered]@{ id = $mid; computerDnsName = $name; osPlatform = $(if ($server) { 'WindowsServer2022' } else { 'Windows11' }); osVersion = '10.0'; osBuild = '22631'
        lastSeen = $T.AddHours(-($I % 48)).ToString('o'); firstSeen = $T.AddDays(-($I % 700)).ToString('o'); lastIpAddress = ('10.{0}.{1}.{2}' -f (($I / 65000) % 250), (($I / 250) % 250), ($I % 250 + 1))
        ipAddresses = @([ordered]@{ ipAddress = ('10.{0}.{1}.{2}' -f (($I / 65000) % 250), (($I / 250) % 250), ($I % 250 + 1)); macAddress = ('00155D{0:X6}' -f $I); type = 'Ethernet'; operationalStatus = 'Up' })
        machineTags = $(if ($server) { @('Servers--tier1--SI', ('app-{0}' -f ($I % 40))) } elseif (($I % 500) -eq 0) { @('PAWDevices--tier0--SI') } else { @(('site-{0}' -f ($I % 12))) })
        rbacGroupName = $(if ($server) { 'Servers' } else { 'Workstations' }); healthStatus = @('Active', 'Active', 'Active', 'Inactive')[$I % 4]; onboardingStatus = 'Onboarded'
        exposureLevel = @('Low', 'Medium', 'High')[$I % 3]; riskScore = @('None', 'Low', 'Medium', 'High')[$I % 4] }
    if (-not $server) { $m['aadDeviceId'] = New-CiPerfGuid 5 $I }
    else { $m['vmMetadata'] = [ordered]@{ vmId = (New-CiPerfGuid 7 $sv); resourceId = ('/subscriptions/00000000-0000-0000-0000-00000000000a/resourceGroups/rg-app-{0}/providers/Microsoft.Compute/virtualMachines/srv-app-{1:D5}' -f ($sv % 12), $sv); subscriptionId = '00000000-0000-0000-0000-00000000000a'; cloudProvider = 'Azure' } }
    Add-SIRecordPart -Provider mde -RecordType device -Key $mid -Part machine -Object ([pscustomobject]$m)
    $nUsers = 1 + ($I % 3)
    $logged = @(for ($k = 0; $k -lt $nUsers; $k++) { $u = ($I * 3 + $k) % 50000; [ordered]@{ UserName = ('user{0:D6}' -f $u); DomainName = 'CORP'; Sid = ('S-1-5-21-1111111111-2222222222-3333333333-{0}' -f (100000 + $u)) } })
    Add-SIRecordPart -Provider mde -RecordType device -Key $mid -Part deviceInfo -Object ([pscustomobject]@{ DeviceId = $mid; LoggedOnUsers = (ConvertTo-Json -InputObject $logged -Compress); MachineGroup = $m.rbacGroupName
            DeviceType = $(if ($server) { 'Server' } else { 'Workstation' }); IsInternetFacing = (($I % 97) -eq 0); Timestamp = $m.lastSeen })
    $swN = $(if ($server) { 150 + ($I % 250) } else { 40 + ($I % 160) }); if (($I % 100) -eq 0) { $swN = 1000 }
    $sw = @(for ($k = 0; $k -lt $swN; $k++) { 'vendor{0}/product_{1}' -f ($k % 90), (($k * 7 + $I) % 3000) })
    if ($server -and ($I % 5) -eq 0) { $sw += 'microsoft/sql_server_2019' }
    if ($server -and ($I % 7) -eq 0) { $sw += 'microsoft/internet_information_services' }
    Add-SIRecordPart -Provider mde -RecordType device -Key $mid -Part software -Object $sw
}

function Add-CiPerfAzureVmParts {
    <# The raw ARM object of Azure virtual machine $i (the server Defender device $i of the servers runs on). #>
    param([int]$I, [datetime]$T)
    $rid = '/subscriptions/00000000-0000-0000-0000-00000000000a/resourceGroups/rg-app-{0}/providers/Microsoft.Compute/virtualMachines/srv-app-{1:D5}' -f ($I % 12), $I
    $o = [ordered]@{ id = $rid; name = ('srv-app-{0:D5}' -f $I); type = 'microsoft.compute/virtualmachines'; location = 'westeurope'; subscriptionId = '00000000-0000-0000-0000-00000000000a'; resourceGroup = ('rg-app-{0}' -f ($I % 12))
        tags = [ordered]@{ Owner = ('owner{0}@contoso.example' -f ($I % 40)); Environment = @('Production', 'Test', 'Development')[$I % 3]; CostCenter = ('CC{0:D4}' -f ($I % 97)); Application = ('app-{0}' -f ($I % 40)) }
        properties = [ordered]@{ vmId = (New-CiPerfGuid 7 $I); provisioningState = 'Succeeded'; hardwareProfile = [ordered]@{ vmSize = 'Standard_D4s_v5' }
            osProfile = [ordered]@{ computerName = ('srv-app-{0:D5}' -f $I); windowsConfiguration = [ordered]@{ patchSettings = [ordered]@{ patchMode = 'AutomaticByPlatform' } } }
            storageProfile = [ordered]@{ osDisk = [ordered]@{ osType = 'Windows' } }; securityProfile = [ordered]@{ securityType = 'TrustedLaunch'; uefiSettings = [ordered]@{ secureBootEnabled = $true; vTpmEnabled = $true } }
            timeCreated = $T.AddDays(-($I % 800)).ToString('o'); extended = [ordered]@{ instanceView = [ordered]@{ powerState = [ordered]@{ code = 'PowerState/running' } } } } }
    Add-SIRecordPart -Provider azure -RecordType azure_resource -Key $rid -Part resource -Object ([pscustomobject]$o) -ResourceType 'microsoft.compute/virtualmachines'
}

function Add-CiPerfStorageParts {
    <# The raw ARM object of Azure storage account $i -- an Azure resource that is a CI of its own (no device joins it). #>
    param([int]$I, [datetime]$T)
    $rid = '/subscriptions/00000000-0000-0000-0000-00000000000a/resourceGroups/rg-data-{0}/providers/Microsoft.Storage/storageAccounts/stdata{1:D5}' -f ($I % 7), $I
    $o = [ordered]@{ id = $rid; name = ('stdata{0:D5}' -f $I); type = 'microsoft.storage/storageaccounts'; location = 'westeurope'; subscriptionId = '00000000-0000-0000-0000-00000000000a'; resourceGroup = ('rg-data-{0}' -f ($I % 7))
        tags = [ordered]@{ Owner = ('owner{0}@contoso.example' -f ($I % 40)); Environment = @('Production', 'Test')[$I % 2] }
        properties = [ordered]@{ provisioningState = 'Succeeded'; allowBlobPublicAccess = (($I % 5) -eq 0); minimumTlsVersion = @('TLS1_2', 'TLS1_0')[[int](($I % 9) -eq 0)]; supportsHttpsTrafficOnly = $true
            publicNetworkAccess = @('Enabled', 'Disabled')[$I % 2]; allowSharedKeyAccess = (($I % 3) -ne 0); networkAcls = [ordered]@{ defaultAction = @('Allow', 'Deny')[$I % 2] }
            creationTime = $T.AddDays(-($I % 600)).ToString('o') } }
    Add-SIRecordPart -Provider azure -RecordType azure_resource -Key $rid -Part resource -Object ([pscustomobject]$o) -ResourceType 'microsoft.storage/storageaccounts'
}

function Write-CiPerfTenant {
    <#
        Makes the synthetic tenant and writes its records through the real capture, mapping and record writer, in chunks (one
        chunk's objects in memory at a time). -Invoke: the SQL seam { param($Sql, $Params, $Mode) }. Answers the counts and
        the seconds of each side (making + mapping the records, writing them).
    #>
    # -Collect: the record rows are handed back (Rows) instead of written (-Invoke is then not needed)
    param([double]$Scale = 1.0, [scriptblock]$Invoke, [Parameter(Mandatory)]$Model, [switch]$Collect, [datetime]$T = [datetime]::SpecifyKind([datetime]'2026-10-16T03:00:00', [DateTimeKind]::Utc), [int]$Chunk = 4000, [scriptblock]$Log)
    $shape = Get-CiPerfShape -Scale $Scale
    $kinds = @(
        @{ Name = 'users'; Count = $shape.Users; Add = { param($i) Add-CiPerfUserParts -I $i -Shape $shape -T $T } }
        @{ Name = 'service principals'; Count = $shape.ServicePrincipals; Add = { param($i) Add-CiPerfSpParts -I $i -T $T } }
        @{ Name = 'Entra devices'; Count = $shape.EntraDevices; Add = { param($i) Add-CiPerfEntraDeviceParts -I $i -T $T } }
        @{ Name = 'Defender devices'; Count = $shape.MdeDevices; Add = { param($i) Add-CiPerfMdeDeviceParts -I $i -Shape $shape -T $T } }
        @{ Name = 'Azure virtual machines'; Count = $shape.AzureVms; Add = { param($i) Add-CiPerfAzureVmParts -I $i -T $T } }
        @{ Name = 'Azure storage accounts'; Count = $shape.StorageAccounts; Add = { param($i) Add-CiPerfStorageParts -I $i -T $T } }
    )
    $scope = ConvertTo-SIAzureCiScope -Document $Model['collection-scope']
    Set-SIAzureCiScope -Scope $scope
    $tot = [ordered]@{ Records = 0; Changed = 0; Failed = 0; MakeSeconds = 0.0; WriteSeconds = 0.0 }
    $kept = New-Object System.Collections.Generic.List[object]
    $sw = [Diagnostics.Stopwatch]::new()
    try {
        foreach ($k in $kinds) {
            for ($from = 0; $from -lt $k.Count; $from += $Chunk) {
                $to = [Math]::Min($from + $Chunk, $k.Count) - 1
                $sw.Restart()
                $null = Reset-SIRecordCapture -Engine 'perf' -Clear
                for ($i = $from; $i -le $to; $i++) { & $k.Add $i }
                $rows = (ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $Model -CollectionTime $T -RunId 'ci-perf').Rows
                $tot.MakeSeconds += $sw.Elapsed.TotalSeconds; $sw.Restart()
                if ($Collect) { foreach ($rr in $rows) { $kept.Add($rr) }; $tot.Records += $rows.Count; continue }
                for ($j = 0; $j -lt $rows.Count; $j += 2000) {
                    $w = Write-SIRecordsToSql -Rows @($rows[$j..([Math]::Min($j + 2000, $rows.Count) - 1)]) -Invoke $Invoke -Now $T
                    $tot.Records += $w.Seen; $tot.Changed += $w.Changed; $tot.Failed += $w.Failed
                }
                $tot.WriteSeconds += $sw.Elapsed.TotalSeconds
            }
            if ($Log) { & $Log ('records: {0} {1} written ({2:N0} records so far; make {3:N0} s, write {4:N0} s)' -f $k.Count, $k.Name, $tot.Records, $tot.MakeSeconds, $tot.WriteSeconds) }
        }
    } finally { Set-SIAzureCiScope -Scope $null; $null = Reset-SIRecordCapture -Clear }
    $tot['Shape'] = $shape
    if ($Collect) { $tot['Rows'] = $kept.ToArray() }
    [pscustomobject]$tot
}

# ---- the local SQL Server Express (test VM): a fresh database, the updater's schema, the engine's identity --------------
function New-CiPerfDatabase {
    <# A fresh database with the schema, and two open connections: AdminConn (the owner) and Conn (the engine's identity:
       db_datareader + db_datawriter, no DDL -- as setup grants it). Answers @{ Name; AdminConn; Conn; Seam; NewEngineConn }. #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$Prefix = 'si_test_ciperf_', [string]$Server = '.\SQLEXPRESS')
    $name = $Prefix + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $m = New-Object System.Data.SqlClient.SqlConnection "Server=$Server;Database=master;Integrated Security=SSPI;Connection Timeout=30"
    $m.Open()
    try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$name]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=$Server;Database=$name;Integrated Security=SSPI;Connection Timeout=30")
    $cn.Open()
    foreach ($f in 'sql\si-data-schema.sql', 'sql\si-identity-schema.sql') {
        $c = $cn.CreateCommand(); $c.CommandTimeout = 600; $c.CommandText = [IO.File]::ReadAllText((Join-Path $SIRoot $f)); [void]$c.ExecuteNonQuery()
    }
    $c = $cn.CreateCommand(); $c.CommandText = 'CREATE USER si_engine WITHOUT LOGIN; ALTER ROLE db_datareader ADD MEMBER si_engine; ALTER ROLE db_datawriter ADD MEMBER si_engine;'; [void]$c.ExecuteNonQuery()
    $db = [pscustomobject]@{ Name = $name; Server = $Server; AdminConn = $cn; Conn = $null; Seam = $null; NewEngineConn = $null; Extra = (New-Object System.Collections.Generic.List[object]) }
    $newEngine = {
        # not pooled: a connection closed while impersonating goes back to the pool unreverted
        $e = New-Object System.Data.SqlClient.SqlConnection ($db.AdminConn.ConnectionString + ';Pooling=false')
        $e.Open()
        $x = $e.CreateCommand(); $x.CommandText = "EXECUTE AS USER = N'si_engine';"; [void]$x.ExecuteNonQuery()
        $db.Extra.Add($e)
        $e
    }.GetNewClosure()
    $db.NewEngineConn = $newEngine
    $db.Conn = & $newEngine
    $conn = $db.Conn
    # the production reader, held as a script block: the closure below does not see the caller's functions
    $readRows = (Get-Command -Name Read-SISqlRows -CommandType Function).ScriptBlock
    $db.Seam = {
        param($Sql, $Params, $Mode)
        $c = $conn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 1800
        if ($Params) { foreach ($k in $Params.Keys) { $pp = $c.Parameters.Add('@' + $k, [System.Data.SqlDbType]::NVarChar, -1); $pp.Value = [string]$Params[$k] } }
        if ($Mode -eq 'scalar') { return $c.ExecuteScalar() }
        if ($Mode -eq 'rows') { return @(& $readRows -Command $c) }     # the production reader (SI-RecordSql.ps1)
        $c.ExecuteNonQuery()
    }.GetNewClosure()
    $db
}

function Remove-CiPerfDatabase {
    <# Drops the database of New-CiPerfDatabase. Never throws. #>
    param($Db)
    if ($null -eq $Db) { return }
    # .ToArray(), never @() around a List[object] held in an object (pwsh 7: "Argument types do not match")
    foreach ($e in $Db.Extra.ToArray()) { try { $e.Dispose() } catch { } }
    try { $Db.AdminConn.Dispose() } catch { }
    [System.Data.SqlClient.SqlConnection]::ClearAllPools()
    try {
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($Db.Server);Database=master;Integrated Security=SSPI;Connection Timeout=30"
        $m.Open()
        try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$($Db.Name)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($Db.Name)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    } catch { Write-Warning ("the test database {0} could not be dropped: {1}" -f $Db.Name, $_.Exception.Message) }
}

function Invoke-CiPerfBuild {
    <# One CI build against the database, as the correlation job runs it: the real rules, the SQL ledger on its own connection,
       the lock on its own connection; SI_CI_CL posted into a counter. Answers the build's result + its log lines (time-stamped). #>
    param([Parameter(Mandatory)]$Database, [AllowEmptyCollection()][object[]]$Rules = @(), [int]$BatchCis = 2000, [switch]$Full, [scriptblock]$Echo)
    $perfEcho = $Echo
    $perfLines = New-Object System.Collections.Generic.List[string]
    $perfPosted = @{ Rows = 0; Full = New-Object System.Collections.Generic.List[object] }
    $lc = & $Database.NewEngineConn
    $perfClock = [Diagnostics.Stopwatch]::StartNew()
    # every statement timed, by what it does (its first statement line that is not SET / DECLARE)
    $perfSql = @{}
    $innerSeam = $Database.Seam
    $timedSeam = {
        param($Sql, $Params, $Mode)
        $key = ''
        foreach ($ln in ([string]$Sql -split "`n")) { $t = $ln.Trim(); if ($t -and $t -notmatch '^(SET |DECLARE |--)') { $key = $t.Substring(0, [Math]::Min(70, $t.Length)); break } }
        $s = [Diagnostics.Stopwatch]::StartNew()
        try { & $innerSeam $Sql $Params $Mode } finally { $e = $perfSql[$key]; if ($null -eq $e) { $e = @{ N = 0; S = 0.0 }; $perfSql[$key] = $e }; $e.N++; $e.S += $s.Elapsed.TotalSeconds }
    }
    $r = Invoke-SICiBuild -SqlInvoke $timedSeam -LockOpen $Database.NewEngineConn -LedgerProvider ([pscustomobject]@{ Kind = 'sql'; Connection = $lc }) -Rules @($Rules) -CmdbIndex (New-SICiCmdbIndex) `
        -Post { param($Rows) foreach ($x in $Rows) { $perfPosted.Rows++; if ([string]$x.si_row_kind -eq 'full') { $perfPosted.Full.Add($x) } }; @($Rows).Count } -BatchCis $BatchCis -LookbackDays 30 -WorkbookMaxCis 0 `
        -FullReconcile:$Full -RunId 'ci-perf' `
        -Log { param($l, $m) $line = ('{0:N1} {1} {2}' -f $perfClock.Elapsed.TotalSeconds, $l, $m); $perfLines.Add($line); if ($perfEcho) { & $perfEcho $line } }
    $sqlTimes = @($perfSql.Keys | Sort-Object { -$perfSql[$_].S } | ForEach-Object { [pscustomobject]@{ Statement = $_; Count = $perfSql[$_].N; Seconds = [Math]::Round($perfSql[$_].S, 1) } })
    [pscustomobject]@{ Result = $r; Seconds = [Math]::Round($perfClock.Elapsed.TotalSeconds, 1); Lines = $perfLines.ToArray(); Posted = $perfPosted; SqlTimes = $sqlTimes }
}

function Get-CiPerfCiDigest {
    <#
        Every CI the build stored, comparable between two builds of the same records: CiId -> one text holding its members
        (record keys), its link rows, its document without the values that change every build (collection time, run id, the
        times the build stamps) -- so the tier, the claims, the CMDB fields and every other field are compared whole -- and its
        service and relation claims. Answers an ordered dictionary (CiId ordinal order).
    #>
    # -Epoch: every time in the text is written as its distance from it in minutes (T+0m) -- two builds of records made from
    # different epochs compare equal when they are the same CIs
    param([Parameter(Mandatory)][scriptblock]$Invoke, [string[]]$Volatile = @('si_collection_time', 'si_run_id', 'si_ci_built', 'si_last_build'), [Nullable[datetime]]$Epoch)
    $out = [System.Collections.Generic.SortedDictionary[string, string]]::new([StringComparer]::Ordinal)
    $mem = @{}
    foreach ($r in @(& $Invoke 'SELECT CiId, RecordKey FROM sidata.CiRecord WHERE CiId IS NOT NULL ORDER BY CiId, RecordKey' @{} 'rows')) {
        $k = [string]$r.CiId; if (-not $mem.ContainsKey($k)) { $mem[$k] = New-Object System.Collections.Generic.List[string] }; $mem[$k].Add([string]$r.RecordKey)
    }
    $links = @{}
    foreach ($r in @(& $Invoke 'SELECT * FROM sidata.CiLink' @{} 'rows')) {
        $k = [string]$r.CiId; if (-not $links.ContainsKey($k)) { $links[$k] = New-Object System.Collections.Generic.List[string] }
        $names = [string[]]@($r.PSObject.Properties | Where-Object { $_.Name -notin 'UpdatedAt', 'CreatedAt', 'LastSeen', 'SeenAt' } | ForEach-Object { $_.Name }); [Array]::Sort($names, [StringComparer]::Ordinal)
        $links[$k].Add((($names | ForEach-Object { '{0}={1}' -f $_, [string]$r.$_ }) -join ';'))
    }
    foreach ($r in @(& $Invoke 'SELECT CiId, DocJson, Lifecycle FROM sidata.Ci' @{} 'rows')) {
        $id = [string]$r.CiId
        $doc = $null; try { $doc = ConvertFrom-Json -InputObject ([string]$r.DocJson) -AsHashtable } catch { }
        $norm = ''
        if ($null -ne $doc) {
            foreach ($v in $Volatile) { $null = $doc.Remove($v) }
            $norm = ConvertTo-CiPerfCanonicalJson $doc
        }
        $m = @(); if ($mem.ContainsKey($id)) { $m = $mem[$id].ToArray() }
        $l = @(); if ($links.ContainsKey($id)) { $l = [string[]]$links[$id].ToArray(); [Array]::Sort($l, [StringComparer]::Ordinal) }
        $out[$id] = ('lifecycle={0}|members={1}|links={2}|doc={3}' -f [string]$r.Lifecycle, ($m -join ','), ($l -join ' / '), $norm)
        if ($null -ne $Epoch) { $out[$id] = ConvertTo-CiPerfRelativeTimes -Text $out[$id] -Epoch ([datetime]$Epoch) }
    }
    $out
}

function ConvertTo-CiPerfRelativeTimes {
    <# PURE. Every ISO-8601 time in -Text (2026-10-16T03:00:00Z, with fractions or an offset) as its distance from -Epoch in
       whole minutes: T+0m, T-90m. #>
    param([string]$Text, [datetime]$Epoch)
    $e = $Epoch.ToUniversalTime()
    [regex]::Replace($Text, '\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?', {
            param($m)
            $d = [datetimeoffset]::MinValue
            if ([datetimeoffset]::TryParse($m.Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { 'T{0:+0;-0;+0}m' -f [Math]::Round(($d.UtcDateTime - $e).TotalMinutes) } else { $m.Value }
        })
}

function ConvertTo-CiPerfCanonicalJson {
    <# PURE. A parsed document as JSON with every object's keys in ordinal order (lists keep their order). #>
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = [string[]]@($Value.Keys); [Array]::Sort($keys, [StringComparer]::Ordinal)
        return '{' + (($keys | ForEach-Object { (ConvertTo-Json -InputObject $_ -Compress) + ':' + (ConvertTo-CiPerfCanonicalJson $Value[$_]) }) -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { return '[' + ((@($Value) | ForEach-Object { ConvertTo-CiPerfCanonicalJson $_ }) -join ',') + ']' }
    ConvertTo-Json -InputObject $Value -Compress
}

function Compare-CiPerfDigest {
    <# PURE. Two digests (Get-CiPerfCiDigest): the CI ids only in one, and the CIs whose text differs (the first -Max). #>
    param([Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$After, [int]$Max = 5)
    $onlyB = @($Before.Keys | Where-Object { -not $After.ContainsKey($_) })
    $onlyA = @($After.Keys | Where-Object { -not $Before.ContainsKey($_) })
    $diff = New-Object System.Collections.Generic.List[object]
    $nDiff = 0
    foreach ($k in $Before.Keys) {
        if (-not $After.ContainsKey($k)) { continue }
        if ($Before[$k] -cne $After[$k]) {
            $nDiff++
            if ($diff.Count -lt $Max) {
                $b = $Before[$k]; $a = $After[$k]; $i = 0; $n = [Math]::Min($a.Length, $b.Length)
                while ($i -lt $n -and $a[$i] -ceq $b[$i]) { $i++ }
                $s = [Math]::Max(0, $i - 80)
                $diff.Add([pscustomobject]@{ CiId = $k; Before = $b.Substring($s, [Math]::Min(240, $b.Length - $s)); After = $a.Substring($s, [Math]::Min(240, $a.Length - $s)) })
            }
        }
    }
    [pscustomobject]@{ Same = ($onlyB.Count -eq 0 -and $onlyA.Count -eq 0 -and $nDiff -eq 0); Cis = $Before.Count; OnlyBefore = $onlyB.Count; OnlyAfter = $onlyA.Count; Different = $nDiff; Examples = $diff.ToArray() }
}

function New-CiPerfBeforeWorld {
    <#
        The CI build AS IT WAS before the speed-up, loaded beside the current one: every function of the CI build's files
        (the current text, or -- for the functions the speed-up changed -- the text kept in before\ci-build.<sha>.txt) under a
        second name ('Test-SICondition' -> 'Test-BeforeSICondition'), every call among them renamed the same way, so
        Invoke-BeforeSICiCore / Invoke-BeforeSICiBuild run the old code from end to end. Answers the text to dot-source in
        the caller's scope ( . ([scriptblock]::Create((New-CiPerfBeforeWorld ...))) ) and the renamed function names.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$BeforeFile = (Join-Path $PSScriptRoot 'before\ci-build.d3b2fe9ed.txt'))
    $dm = Join-Path $SIRoot 'engine\data-model'
    $files = @('SI-CiBuild.ps1', 'SI-CiBuildRun.ps1', 'SI-CiBuildSql.ps1', 'SI-CiEnrich.ps1', 'SI-CiRules.ps1', 'SI-FieldResolution.ps1', 'SI-Conditions.ps1', 'SI-CiGraph.ps1',
        'SI-Classification.ps1', 'SI-RiskFactorCatalog.ps1', 'SI-BreakGlass.ps1', 'identity\SI-ObjectIdentity.ps1', 'identity\SI-ObjectLedgerStore.ps1')
    $texts = [ordered]@{}
    $tk = $null; $er = $null
    foreach ($f in $files) {
        $path = Join-Path $dm $f
        $dir = Split-Path -Parent $path
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tk, [ref]$er)
        foreach ($fd in $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
            # a function body's $PSScriptRoot is its file's folder -- written out, the text is not in a file any more
            $texts[$fd.Name] = $fd.Extent.Text.Replace('$PSScriptRoot', ("'{0}'" -f $dir.Replace("'", "''")))
        }
    }
    $old = [IO.File]::ReadAllText($BeforeFile)
    $oast = [System.Management.Automation.Language.Parser]::ParseInput($old, [ref]$tk, [ref]$er)
    foreach ($fd in $oast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        # (the clock seam of Invoke-SICiBuild is the current text's: two builds compared CI for CI need one clock)
        if ($fd.Name -eq 'Invoke-SICiBuild') { continue }
        $file = @($files | Where-Object { $old.Contains(('# ---- {0} :: {1}' -f ($_ -replace '\\', '/'), $fd.Name)) })[0]
        $dir = $dm; if ($file) { $dir = Split-Path -Parent (Join-Path $dm $file) }
        $text = $fd.Extent.Text
        # #406 (CI build version 10): the current callers pass the lifecycle's inputs; the old function takes them and ignores
        # them (it decides the lifecycle as it did -- the comparison runs with a seen window no record's age reaches)
        $extra = @{ 'New-SICiDocument' = @('$Lifecycle', '$Previous', '[hashtable]$ScopeChangedAt'); 'Invoke-SICiCore' = @('$Lifecycle', '[hashtable]$PreviousLifecycle', '[hashtable]$ScopeChangedAt') }[$fd.Name]
        if ($extra -and $fd.Body.ParamBlock) {
            $have = @($fd.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
            $add = @($extra | Where-Object { $have -notcontains (($_ -replace '^\[[^\]]+\]', '').TrimStart('$')) })
            if ($add.Count) {
                $at = $fd.Body.ParamBlock.Extent.EndOffset - $fd.Extent.StartOffset - 1
                $text = $text.Substring(0, $at) + $(if (@($have).Count) { ', ' } else { '' }) + ($add -join ', ') + $text.Substring($at)
            }
        }
        $texts[$fd.Name] = $text.Replace('$PSScriptRoot', ("'{0}'" -f $dir.Replace("'", "''")))
    }
    $names = [string[]]@($texts.Keys | Sort-Object { -$_.Length })
    $map = @{}; foreach ($n in $names) { $i = $n.IndexOf('-'); $map[$n.ToLowerInvariant()] = $n.Substring(0, $i + 1) + 'Before' + $n.Substring($i + 1) }
    $rx = New-Object System.Text.RegularExpressions.Regex(('(?<![\w-])(' + (($names | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')(?![\w-])'), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $sb = New-Object System.Text.StringBuilder
    foreach ($n in $texts.Keys) { [void]$sb.AppendLine($rx.Replace($texts[$n], { param($m) $map[$m.Value.ToLowerInvariant()] })).AppendLine() }
    [pscustomobject]@{ Text = $sb.ToString(); Names = $map }
}