#Requires -Version 5.1
<#
    AN UPDATE SAYS WHICH READ-ONLY PERMISSIONS AN EXISTING INSTALL HAS NOT GRANTED YET (owner 2026-10-11: SecurityInsight may
    ask for DeviceManagementConfiguration.Read.All, AccessReview.Read.All and Vulnerability.Read.All; "customers grant on
    their next permission setup run"). setup/_shared/SI-PermissionNote.ps1, run as the last step of every update
    (setup/Invoke-SIContainerUpdate.ps1, Complete-SIUpdate):
      * what the collection identity holds is READ (the directory; else the collection engines' own check on their newest
        run) and compared with config/permissions.locked.json -- never guessed;
      * per missing permission ONE plain line, then the two lines that grant them (download from invardia.com + the command
        with this install's names, never a placeholder);
      * nothing is said when all are granted; it never fails the update and never changes anything (GET only, plus the one
        Log Analytics query).
    Offline: a fake directory and a fake Log Analytics behind the update's REST seam. The real permission list is used, so a
    permission added to it later is covered without a change here.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-PermissionNote.ps1')
    $script:Cat = Get-SIPermissionNoteCatalog
    $script:New3 = @('DeviceManagementConfiguration.Read.All', 'AccessReview.Read.All', 'Vulnerability.Read.All')
    $script:Sub = '11111111-0000-4000-8000-000000000001'
    $script:Client = '22222222-0000-4000-8000-000000000002'
    $script:Oid = '33333333-0000-4000-8000-000000000003'
    $script:Rg = 'rg-si-test'
    $script:Ws = "/subscriptions/$($script:Sub)/resourceGroups/rg-logs/providers/Microsoft.OperationalInsights/workspaces/log-si-test"
    $script:UamiId = "/subscriptions/$($script:Sub)/resourceGroups/$($script:Rg)/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-test"

    function script:New-Job([string]$Name, [string]$Engine, [switch]$AppRegistration, [switch]$NoIdentityMap, [hashtable]$Extra = @{}) {
        $ev = New-Object System.Collections.Generic.List[object]
        $add = { param($n, $v) $ev.Add([pscustomobject]@{ name = $n; value = $v }) }
        & $add 'SI_ENGINE' $Engine
        if ($AppRegistration) { & $add 'SI_SPN_APPID' $script:Client; $ev.Add([pscustomobject]@{ name = 'SI_SPN_SECRET'; secretRef = 'si-spn-secret' }) }
        else { & $add 'SI_UAMI_CLIENTID' $script:Client }
        & $add 'SI_SPN_OBJECTID' $script:Oid
        & $add 'SI_WORKSPACE_RESOURCEID' $script:Ws
        & $add 'SI_STORAGE_ACCOUNT' 'stsitest01'
        & $add 'SI_DCR_RESOURCEGROUP' $script:Rg
        foreach ($k in $Extra.Keys) { & $add $k $Extra[$k] }
        $identity = $null
        if (-not $AppRegistration -and -not $NoIdentityMap) {
            $ua = [ordered]@{}; $ua[$script:UamiId] = [pscustomobject]@{ principalId = $script:Oid; clientId = $script:Client }
            $identity = [pscustomobject]@{ type = 'UserAssigned'; userAssignedIdentities = [pscustomobject]$ua }
        }
        [pscustomobject]@{ name = $Name; identity = $identity; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'si'; image = 'acr.io/si-orchestrator:v1'; env = $ev.ToArray() }) } } }
    }

    # A fake directory + Log Analytics behind the REST seam. Held = the roles the identity holds per API (default: all of
    # the list but -Without). Refuse = the directory answers 403. Runs = the rows of the run-record query ($null = 403).
    function script:New-World([string[]]$Without = @(), [switch]$Refuse, [object[]]$Runs, [string[]]$AbsentApis = @(), [switch]$NoRunsAccess) {
        $apis = @{}; $n = 0
        foreach ($a in $script:Cat.Apis) {
            $n++
            $roles = @{}; $r = 0
            foreach ($role in $a.Roles) { $r++; $roles[$role] = ('aaaaaaaa-{0:d4}-4000-8000-{1:d12}' -f $n, $r) }
            $apis[$a.ResourceAppId] = [pscustomobject]@{ Id = ('bbbbbbbb-0000-4000-8000-{0:d12}' -f $n); Roles = $roles }
        }
        [pscustomobject]@{ Apis = $apis; Without = $Without; Refuse = [bool]$Refuse; Runs = $Runs; AbsentApis = $AbsentApis; NoRunsAccess = [bool]$NoRunsAccess
            Calls = (New-Object System.Collections.Generic.List[string]) }
    }
    $script:Rest = {
        param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
        $w = $script:World; $w.Calls.Add(('{0} {1}' -f $Method, $Uri))
        $ok = { param($o) [pscustomobject]@{ Status = 200; Body = (ConvertTo-Json -InputObject $o -Depth 12 -Compress) } }
        if ($Uri -like 'https://graph.microsoft.com/*') {
            if ($Resource -ne 'https://graph.microsoft.com/') { return [pscustomobject]@{ Status = 0; Body = 'wrong audience' } }
            if ($w.Refuse) { return [pscustomobject]@{ Status = 403; Body = '{"error":{"code":"Authorization_RequestDenied"}}' } }
            if ($Uri -like '*/appRoleAssignments*') {
                if ($Uri -notlike ('*servicePrincipals/{0}/appRoleAssignments' -f $script:Oid) -and $Uri -notlike ("*servicePrincipals(appId='{0}')/appRoleAssignments" -f $script:Client)) { return [pscustomobject]@{ Status = 404; Body = 'not found' } }
                $list = New-Object System.Collections.Generic.List[object]
                foreach ($k in $w.Apis.Keys) { foreach ($role in $w.Apis[$k].Roles.Keys) { if ($w.Without -notcontains $role) { $list.Add([pscustomobject]@{ resourceId = $w.Apis[$k].Id; appRoleId = $w.Apis[$k].Roles[$role] }) } } }
                # a grant on an API that is not in the list is ignored
                $list.Add([pscustomobject]@{ resourceId = 'cccccccc-0000-4000-8000-000000000009'; appRoleId = 'dddddddd-0000-4000-8000-000000000009' })
                return (& $ok ([pscustomobject]@{ value = $list.ToArray() }))
            }
            $m = [regex]::Match($Uri, "servicePrincipals\(appId='([^']+)'\)\?\`$select=id,appRoles$")
            if ($m.Success) {
                $appId = $m.Groups[1].Value
                if ($w.AbsentApis -contains $appId -or -not $w.Apis.ContainsKey($appId)) { return [pscustomobject]@{ Status = 404; Body = 'not found' } }
                $roles = @($w.Apis[$appId].Roles.Keys | ForEach-Object { [pscustomobject]@{ id = $w.Apis[$appId].Roles[$_].ToUpperInvariant(); value = $_ } })
                return (& $ok ([pscustomobject]@{ id = $w.Apis[$appId].Id; appRoles = $roles }))
            }
            return [pscustomobject]@{ Status = 400; Body = 'unexpected' }
        }
        if ($Method -eq 'POST' -and $Uri -like '*/api/query*') {
            if ($w.NoRunsAccess -or $null -eq $w.Runs) { return [pscustomobject]@{ Status = 403; Body = 'Forbidden' } }
            $cols = @('Engine', 'At', 'Gaps' | ForEach-Object { [pscustomobject]@{ name = $_ } })
            $rows = @($w.Runs | ForEach-Object { , @($_.Engine, $_.At, $_.Gaps) })
            return (& $ok ([pscustomobject]@{ tables = @([pscustomobject]@{ columns = $cols; rows = $rows }) }))
        }
        [pscustomobject]@{ Status = 400; Body = 'unexpected' }
    }
    # the fingerprint a run of THIS build records when it checked every permission of the list
    $script:ListFp = Get-SIPermissionNoteFingerprint -Apis $script:Cat.Apis
    # A run record as the engines write it. -Checked: the fingerprint of what the run checked (default: this list;
    # '' = a build that recorded none; 'older' = a list that has changed since).
    function script:New-Run([string]$Engine, [object[]]$Items = @(), [string]$Checked = $script:ListFp, [string]$At = '2026-10-11T02:00:00.0000000Z', [string]$Err = '', [int]$More = 0) {
        $o = [ordered]@{ v = 1; engine = $Engine; identity = $script:Client; label = "SecurityInsight's collection identity"; items = @($Items); more = $More }
        if ($Err) { $o['error'] = $Err }
        if ($Checked) { $o['apiChecked'] = $Checked }
        [pscustomobject]@{ Engine = $Engine; At = $At; Gaps = (ConvertTo-Json -InputObject $o -Depth 5 -Compress) }
    }
    function script:Invoke-Note([object[]]$Jobs = @((New-Job 'caj-si-identity' 'identity')), [hashtable]$Globals = @{}) {
        Invoke-SIPermissionNote -Rest $script:Rest -Jobs $Jobs -SubscriptionId $script:Sub -ResourceGroup $script:Rg -Globals $Globals
    }
    # the command-block rule (tests\pester\SIv3-CommandBlocks.Tests.ps1), for a block whose values the code knows
    function script:Get-BlockProblems([string[]]$Lines) {
        $p = New-Object 'System.Collections.Generic.List[string]'
        $l = @($Lines | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ($l.Count -ne 2) { $p.Add('a block is the download line and ONE command line'); return $p.ToArray() }
        $name = ''
        if ($l[0] -cmatch '^Invoke-WebRequest https://invardia\.com/support/si/(?<s>[A-Z][A-Za-z]+-[A-Za-z]+)\.ps1 -OutFile (?<o>[A-Z][A-Za-z]+-[A-Za-z]+)\.ps1$' -and $Matches['s'] -ceq $Matches['o']) { $name = $Matches['s'] }
        else { $p.Add("line 1: $($l[0])") }
        if ($name -and -not $l[1].StartsWith("./$name.ps1 ", [StringComparison]::Ordinal)) { $p.Add("line 2 does not run $name.ps1: $($l[1])") }
        foreach ($x in $l) {
            if ($x -match '(?i)Get-FileHash|SHA-?256|SHA256SUMS|Authenticode|signature|checksum|What does') { $p.Add("checksum / signature / doc text: $x") }
            if ($x -match '(^|\s)#(\s|$)') { $p.Add("a comment: $x") }
            if ($x -match '<[A-Za-z][^<>]*>') { $p.Add("a placeholder: $x") }
        }
        $p.ToArray()
    }
}

Describe 'the permission list (config/permissions.locked.json)' {
    It 'the collection identity carries the three read-only permissions, each on its own API' {
        $graph = @($script:Cat.Apis | Where-Object { $_.ResourceAppId -eq '00000003-0000-0000-c000-000000000000' })[0]
        $mde = @($script:Cat.Apis | Where-Object { $_.ResourceAppId -eq 'fc780465-2017-40d4-a0c5-307022471b92' })[0]
        $graph.Resource | Should -Be 'Microsoft Graph'
        $graph.Roles | Should -Contain 'DeviceManagementConfiguration.Read.All'
        $graph.Roles | Should -Contain 'AccessReview.Read.All'
        $graph.Roles | Should -Not -Contain 'Vulnerability.Read.All'
        $mde.Resource | Should -Be 'WindowsDefenderATP'
        $mde.Roles | Should -Contain 'Vulnerability.Read.All'
    }
    It 'the security alerts permission is on Microsoft Graph only, read only, with its own words (unknown, never 0)' {
        $graph = @($script:Cat.Apis | Where-Object { $_.ResourceAppId -eq '00000003-0000-0000-c000-000000000000' })[0]
        $graph.Roles | Should -Contain 'SecurityAlert.Read.All'
        @($script:Cat.Apis | Where-Object { $_.ResourceAppId -ne '00000003-0000-0000-c000-000000000000' } | ForEach-Object { $_.Roles }) | Should -Not -Contain 'SecurityAlert.Read.All'
        @($script:Cat.Apis | ForEach-Object { $_.Roles }) | Should -Not -Contain 'SecurityAlert.ReadWrite.All' -Because 'read only at collection'
        $script:SIPermissionNoteText['SecurityAlert.Read.All'].For | Should -Be 'the open alerts of each device: how many, their highest severity and the newest one'
        $l = @(Get-SIPermissionNoteLines -Missing @([pscustomobject]@{ Resource = 'Microsoft Graph'; Role = 'SecurityAlert.Read.All' }) -Command '')
        $l[0] | Should -Be "permissions: Microsoft Graph SecurityAlert.Read.All is not granted to SecurityInsight's collection identity -- it is read-only and gives the open alerts of each device: how many, their highest severity and the newest one. Nothing breaks without it: the open alert columns of the devices stay unknown."
    }
    It 'the Defender recommendations permission is on Defender for Endpoint only, read only, with its own words' {
        $mde = @($script:Cat.Apis | Where-Object { $_.ResourceAppId -eq 'fc780465-2017-40d4-a0c5-307022471b92' })[0]
        $mde.Roles | Should -Contain 'SecurityRecommendation.Read.All'
        @($script:Cat.Apis | Where-Object { $_.ResourceAppId -ne 'fc780465-2017-40d4-a0c5-307022471b92' } | ForEach-Object { $_.Roles }) | Should -Not -Contain 'SecurityRecommendation.Read.All'
        $script:SIPermissionNoteText['SecurityRecommendation.Read.All'].For | Should -Be 'the exposure impact and the active alert of a Defender recommendation'
        $l = @(Get-SIPermissionNoteLines -Missing @([pscustomobject]@{ Resource = 'WindowsDefenderATP'; Role = 'SecurityRecommendation.Read.All' }) -Command '')
        $l[0] | Should -Be "permissions: WindowsDefenderATP SecurityRecommendation.Read.All is not granted to SecurityInsight's collection identity -- it is read-only and gives the exposure impact and the active alert of a Defender recommendation. Nothing breaks without it: the exposure impact and active alert columns of the vulnerability and configuration findings stay empty."
    }
    It 'the two security score permissions (2026-10-16) are each on their own API, read only, and an update names them' {
        $graph = @($script:Cat.Apis | Where-Object { $_.ResourceAppId -eq '00000003-0000-0000-c000-000000000000' })[0]
        $mde = @($script:Cat.Apis | Where-Object { $_.ResourceAppId -eq 'fc780465-2017-40d4-a0c5-307022471b92' })[0]
        $graph.Roles | Should -Contain 'SecurityEvents.Read.All'
        $mde.Roles | Should -Contain 'Score.Read.All'
        @($script:Cat.Apis | Where-Object { $_.ResourceAppId -ne '00000003-0000-0000-c000-000000000000' } | ForEach-Object { $_.Roles }) | Should -Not -Contain 'SecurityEvents.Read.All'
        @($script:Cat.Apis | Where-Object { $_.ResourceAppId -ne 'fc780465-2017-40d4-a0c5-307022471b92' } | ForEach-Object { $_.Roles }) | Should -Not -Contain 'Score.Read.All'
        $l = @(Get-SIPermissionNoteLines -Missing @([pscustomobject]@{ Resource = 'Microsoft Graph'; Role = 'SecurityEvents.Read.All' }, [pscustomobject]@{ Resource = 'WindowsDefenderATP'; Role = 'Score.Read.All' }) -Command '')
        $l[0] | Should -Be "permissions: Microsoft Graph SecurityEvents.Read.All is not granted to SecurityInsight's collection identity -- it is read-only and gives the Microsoft Secure Score of the tenant, sent with the hourly status report. Nothing breaks without it: the hourly status report carries no Secure Score."
        $l[1] | Should -Be "permissions: WindowsDefenderATP Score.Read.All is not granted to SecurityInsight's collection identity -- it is read-only and gives the Defender exposure score of the tenant, sent with the hourly status report. Nothing breaks without it: the hourly status report carries no exposure score."
    }
    It 'every permission the collection identity asks for is a read permission' {
        foreach ($a in $script:Cat.Apis) { foreach ($r in $a.Roles) { $r | Should -Match '\.Read\.' -Because "$($a.Resource) $r" ; $r | Should -Not -Match 'Write' } }
    }
    It 'the engines counted are the ones that run as the collection identity and check its application permissions' {
        $script:Cat.Engines | Should -Contain 'identity'
        $script:Cat.Engines | Should -Contain 'endpoint'
        $script:Cat.Engines | Should -Contain 'risk-analysis'
        $script:Cat.Engines | Should -Not -Contain 'asset-tagging'
        $script:Cat.Engines | Should -Not -Contain 'default'
    }
    It 'each of the three has its own words: what it is for and what stays empty' {
        foreach ($r in $script:New3) {
            $script:SIPermissionNoteText.ContainsKey($r) | Should -BeTrue -Because $r
            "$($script:SIPermissionNoteText[$r].For)".Length | Should -BeGreaterThan 20
            "$($script:SIPermissionNoteText[$r].Empty)" | Should -Match 'stay (empty|unknown)$'
        }
    }
}

Describe 'the collection identity, from the jobs the update read' {
    It 'a managed identity job gives the client id, the object id, the identity''s name and resource group and the install''s names' {
        $i = Get-SIPermissionNoteIdentity -Jobs @((New-Job 'caj-si-asset-tagging' 'asset-tagging'), (New-Job 'caj-si-identity' 'identity')) -Engines $script:Cat.Engines
        $i.Job | Should -Be 'caj-si-identity'
        $i.Managed | Should -BeTrue
        $i.ClientId | Should -Be $script:Client
        $i.ObjectId | Should -Be $script:Oid
        $i.IdentityName | Should -Be 'id-si-test'
        $i.IdentityResourceGroup | Should -Be $script:Rg
        $i.WorkspaceResourceId | Should -Be $script:Ws
        $i.StorageAccount | Should -Be 'stsitest01'
        $i.DcrResourceGroup | Should -Be $script:Rg
    }
    It 'asset tagging''s own identity is never taken for the collection identity' {
        Get-SIPermissionNoteIdentity -Jobs @((New-Job 'caj-si-asset-tagging' 'asset-tagging')) -Engines $script:Cat.Engines | Should -BeNullOrEmpty
    }
    It 'a job on an app registration is told apart; a job that names no sign-in is skipped' {
        $i = Get-SIPermissionNoteIdentity -Jobs @((New-Job 'caj-si-endpoint' 'endpoint' -AppRegistration)) -Engines $script:Cat.Engines
        $i.Managed | Should -BeFalse
        $i.ClientId | Should -Be $script:Client
        $bare = [pscustomobject]@{ name = 'caj-si-azure'; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ env = @([pscustomobject]@{ name = 'SI_ENGINE'; value = 'azure' }) }) } } }
        Get-SIPermissionNoteIdentity -Jobs @($bare) -Engines $script:Cat.Engines | Should -BeNullOrEmpty
        Get-SIPermissionNoteIdentity -Jobs @() -Engines $script:Cat.Engines | Should -BeNullOrEmpty
    }
}

Describe 'every permission is granted' {
    It 'says nothing, and only reads' {
        $script:World = New-World
        $n = Invoke-Note
        $n.State | Should -Be 'granted'
        $n.Source | Should -Be 'directory'
        @($n.Lines).Count | Should -Be 0
        @($script:World.Calls | Where-Object { $_ -notlike 'GET *' }) | Should -BeNullOrEmpty
        @($script:World.Calls | Where-Object { $_ -like '*api/query*' }) | Should -BeNullOrEmpty
    }
}

Describe 'the three permissions are not granted yet' {
    BeforeAll {
        $script:World = New-World -Without $script:New3
        $script:Note = Invoke-Note
    }
    It 'names exactly the three, each on its API' {
        $script:Note.State | Should -Be 'missing'
        @($script:Note.Missing | ForEach-Object { '{0}|{1}' -f $_.Resource, $_.Role }) | Should -Be @(
            'Microsoft Graph|DeviceManagementConfiguration.Read.All', 'Microsoft Graph|AccessReview.Read.All', 'WindowsDefenderATP|Vulnerability.Read.All')
    }
    It 'ONE plain line per permission: what it is for, read-only, nothing breaks, what stays empty' {
        $l = @($script:Note.Lines)
        $l[0] | Should -Be "permissions: Microsoft Graph DeviceManagementConfiguration.Read.All is not granted to SecurityInsight's collection identity -- it is read-only and gives which Intune compliance policies a device does not meet, and its update ring. Nothing breaks without it: the failing compliance policy and update ring columns stay empty."
        $l[1] | Should -Be "permissions: Microsoft Graph AccessReview.Read.All is not granted to SecurityInsight's collection identity -- it is read-only and gives when a privileged role, group or application was last reviewed. Nothing breaks without it: the last access review columns stay empty."
        $l[2] | Should -Be "permissions: WindowsDefenderATP Vulnerability.Read.All is not granted to SecurityInsight's collection identity -- it is read-only and gives the exploit details of a vulnerability from Defender (verified exploit, exploit kit, exploit type, exposed devices). Nothing breaks without it: the exploit detail columns of the vulnerability findings stay empty."
        foreach ($r in $script:New3) { @($l | Where-Object { $_ -like "* $r is not granted*" }).Count | Should -Be 1 -Because $r }
    }
    It 'then who grants them and the two lines: the download from invardia.com and the command with this install''s names' {
        $l = @($script:Note.Lines)
        $l.Count | Should -Be 6
        $l[3] | Should -Be 'permissions: to grant them, an admin who can give admin consent (Privileged Role Administrator or Global Administrator) runs these two lines in Azure Cloud Shell or PowerShell 7 -- SecurityInsight keeps running as it does today until then:'
        $l[4] | Should -Be 'Invoke-WebRequest https://invardia.com/support/si/Grant-SIIdentity.ps1 -OutFile Grant-SIIdentity.ps1'
        $l[5] | Should -Be ("./Grant-SIIdentity.ps1 -IdentityName id-si-test -IdentityResourceGroup $($script:Rg) -SubscriptionId $($script:Sub) -WorkspaceResourceId $($script:Ws) -StorageAccountName stsitest01 -StorageResourceGroup $($script:Rg) -DcrResourceGroup $($script:Rg) -AllowSchemaCreate -Apply")
        Get-BlockProblems -Lines @($l[4], $l[5]) | Should -BeNullOrEmpty
    }
    It 'the text carries no internal number, no placeholder and nothing about a ring or a build' {
        foreach ($x in @($script:Note.Lines)) {
            $x | Should -Not -Match '#\d'
            $x | Should -Not -Match '<[A-Za-z]'
            $x | Should -Not -Match '(?i)\bring \d|\brc\.\d|uami|appRole|SI_RunHealth'
        }
    }
    It 'it only read: no call but GET, and no grant was written' {
        @($script:World.Calls | Where-Object { $_ -notlike 'GET *' }) | Should -BeNullOrEmpty
        @($script:World.Calls | Where-Object { $_ -like 'GET https://graph.microsoft.com/v1.0/servicePrincipals/*appRoleAssignments' }).Count | Should -Be 1
    }
    It 'one missing permission reads "it"; a permission SecurityInsight has always needed does not claim that nothing breaks' {
        $script:World = New-World -Without @('AccessReview.Read.All')
        $one = Invoke-Note
        @($one.Lines).Count | Should -Be 4
        @($one.Lines)[1] | Should -Match '^permissions: to grant it, '
        $script:World = New-World -Without @('User.Read.All')
        $core = Invoke-Note
        @($core.Lines)[0] | Should -Be "permissions: Microsoft Graph User.Read.All is not granted to SecurityInsight's collection identity -- it is read-only; the data it gives is not collected until it is granted."
        @($core.Lines)[0] | Should -Not -Match 'Nothing breaks'
    }
    It 'an API that is not in the directory at all is left out (nothing can be granted on it)' {
        $script:World = New-World -Without $script:New3 -AbsentApis @('fc780465-2017-40d4-a0c5-307022471b92')
        $n = Invoke-Note
        @($n.Missing | ForEach-Object { $_.Role }) | Should -Be @('DeviceManagementConfiguration.Read.All', 'AccessReview.Read.All')
    }
}

Describe 'the command' {
    BeforeAll { $script:Id = Get-SIPermissionNoteIdentity -Jobs @((New-Job 'caj-si-identity' 'identity')) -Engines $script:Cat.Engines }
    It 'a setting of the customer wins over the job''s own value' {
        $script:World = New-World -Without @('AccessReview.Read.All')
        $n = Invoke-Note -Globals @{ SI_StorageAccount = 'stcustom01'; SI_StorageResourceGroup = 'rg-storage'; SI_DcrResourceGroup = 'rg-dcr' }
        @($n.Lines)[-1] | Should -Match ' -StorageAccountName stcustom01 -StorageResourceGroup rg-storage -DcrResourceGroup rg-dcr -AllowSchemaCreate -Apply$'
    }
    It 'a managed identity whose name the job does not say is named by its object id' {
        $id = Get-SIPermissionNoteIdentity -Jobs @((New-Job 'caj-si-identity' 'identity' -NoIdentityMap)) -Engines $script:Cat.Engines
        $c = Get-SIPermissionNoteCommand -Identity $id -SubscriptionId $script:Sub -WorkspaceResourceId $script:Ws -StorageAccount 'stsitest01' -StorageResourceGroup $script:Rg -DcrResourceGroup $script:Rg
        $lines = $c -split "`n"
        $lines[1] | Should -Match ('^\./Grant-SIIdentity\.ps1 -PrincipalId {0} -SubscriptionId ' -f $script:Oid)
        Get-BlockProblems -Lines $lines | Should -BeNullOrEmpty
    }
    It 'an install on an app registration gets Grant-SIIdentity -AppId for its client id (never the retired v2 permission script)' {
        $id = Get-SIPermissionNoteIdentity -Jobs @((New-Job 'caj-si-identity' 'identity' -AppRegistration)) -Engines $script:Cat.Engines
        $c = Get-SIPermissionNoteCommand -Identity $id -SubscriptionId $script:Sub -WorkspaceResourceId $script:Ws
        $c | Should -Be ("Invoke-WebRequest https://invardia.com/support/si/Grant-SIIdentity.ps1 -OutFile Grant-SIIdentity.ps1`n./Grant-SIIdentity.ps1 -AppId $($script:Client) -SubscriptionId $($script:Sub) -WorkspaceResourceId $($script:Ws) -AllowSchemaCreate -Apply")
        $c | Should -Not -Match 'SpnAppId|AzureRbacScope'
        Get-BlockProblems -Lines ($c -split "`n") | Should -BeNullOrEmpty
    }
    It 'storage is left out when it is not known; the workspace and the data collection resource group are always given' {
        $c = Get-SIPermissionNoteCommand -Identity $script:Id -SubscriptionId $script:Sub -WorkspaceResourceId $script:Ws -DcrResourceGroup $script:Rg
        $c | Should -Not -Match 'StorageAccountName'
        $c | Should -Match (' -WorkspaceResourceId {0} -DcrResourceGroup {1} -AllowSchemaCreate -Apply$' -f [regex]::Escape($script:Ws), $script:Rg)
    }
    It 'the command lets the repaired install create its tables and rules, as the guided install does (-AllowSchemaCreate)' {
        $c = Get-SIPermissionNoteCommand -Identity $script:Id -SubscriptionId $script:Sub -WorkspaceResourceId $script:Ws -DcrResourceGroup $script:Rg
        $c | Should -Match ' -AllowSchemaCreate -Apply$'
        (Get-Content -LiteralPath (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1') -Raw) | Should -Match 'AllowSchemaCreate = \$true; Apply = \$true'
        # an app registration goes through the same script (by its application id) -- the same switch
        $spn = [pscustomobject]@{ Managed = $false; ClientId = '11111111-2222-3333-4444-555555555555' }
        (Get-SIPermissionNoteCommand -Identity $spn -SubscriptionId $script:Sub -WorkspaceResourceId $script:Ws) | Should -Match ' -AppId 11111111-2222-3333-4444-555555555555 .* -AllowSchemaCreate -Apply$'
    }
    It 'no command when a name is not known or is not a plain resource name -- never a placeholder: <Why>' -ForEach @(
        @{ Why = 'no workspace'; Sub = '11111111-0000-4000-8000-000000000001'; Ws = '' }
        @{ Why = 'no subscription'; Sub = ''; Ws = '/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/z' }
        @{ Why = 'a value that is not a name'; Sub = '11111111-0000-4000-8000-000000000001'; Ws = '/subscriptions/x; Remove-Item y' }
    ) {
        Get-SIPermissionNoteCommand -Identity $script:Id -SubscriptionId $Sub -WorkspaceResourceId $Ws | Should -Be ''
    }
    It 'without a command the note points at Get Started > Permissions' {
        $l = @(Get-SIPermissionNoteLines -Missing @([pscustomobject]@{ Resource = 'Microsoft Graph'; Role = 'AccessReview.Read.All' }) -Command '')
        $l.Count | Should -Be 2
        $l[1] | Should -Be "permissions: to grant it, open Get Started > Permissions in the SecurityInsight web app -- it shows the two lines to run, with this install's names filled in. SecurityInsight keeps running as it does today until then."
        @($l | Where-Object { $_ -match 'Invoke-WebRequest' }) | Should -BeNullOrEmpty
    }
}

Describe 'the sign-in of the update may not read the directory' {
    It 'the fingerprint the update expects is the one an engine records when it checked every permission of the list' {
        $script:ListFp | Should -Match '^[0-9a-f]{16}$'
        $items = foreach ($a in $script:Cat.Apis) { foreach ($r in $a.Roles) { New-SIPermissionItem -Area $a.Resource -Item $r -State $(if ($script:New3 -contains $r) { 'missing' } else { 'ok' }) -Fix 'f' } }
        $all = @($items) + @((New-SIPermissionItem -Area 'Azure' -Item 'Reader (/subscriptions/x)' -State 'ok'), (New-SIPermissionItem -Area 'Pro database' -Item 'db_datareader' -State 'ok'))
        $rec = ConvertTo-SIPermissionGapsJson -Check ([pscustomobject]@{ Engine = 'identity'; Identity = $script:Client; Label = 'l'; Error = ''; Checked = $all }) | ConvertFrom-Json
        $rec.apiChecked | Should -Be $script:ListFp
        @($rec.items).Count | Should -Be 3
        # one API that could not be checked (no token): the record does NOT claim the whole list
        $partial = @($items | ForEach-Object { if ($_.Area -eq 'WindowsDefenderATP') { New-SIPermissionItem -Area $_.Area -Item $_.Item -State 'not-checked' -Fix 'no token' } else { $_ } })
        (ConvertTo-SIPermissionGapsJson -Check ([pscustomobject]@{ Engine = 'identity'; Identity = ''; Label = ''; Error = ''; Checked = $partial }) | ConvertFrom-Json).apiChecked | Should -Not -Be $script:ListFp
        # a list that grew: the older, shorter list has another fingerprint; order and case do not matter
        Get-SIPermissionListFingerprint -Names @('Microsoft Graph|User.Read.All') | Should -Not -Be $script:ListFp
        Get-SIPermissionListFingerprint -Names @('b|Y', 'A|x', 'a|X') | Should -Be (Get-SIPermissionListFingerprint -Names @('a|x', 'B|y'))
        Get-SIPermissionListFingerprint -Names @() | Should -Be ''
        # a check that reached no API at all records no fingerprint
        ((ConvertTo-SIPermissionGapsJson -Check ([pscustomobject]@{ Engine = 'e'; Identity = ''; Label = ''; Error = ''; Checked = @((New-SIPermissionItem -Area 'Pro database' -Item 'db_datareader' -State 'ok')) }) | ConvertFrom-Json).PSObject.Properties['apiChecked']) | Should -BeNullOrEmpty
    }
    It 'a collection run that checked this list recorded nothing missing: nothing is said' {
        $script:World = New-World -Refuse -Runs @((New-Run 'identity'), (New-Run 'endpoint'), (New-Run 'asset-tagging' -Items @(@{ area = 'Microsoft Graph'; item = 'AccessReview.Read.All'; state = 'missing'; fix = 'x' })))
        $n = Invoke-Note
        $n.State | Should -Be 'granted'
        $n.Source | Should -Be 'runs'
        @($n.Lines).Count | Should -Be 0
        @($script:World.Calls | Where-Object { $_ -notlike 'GET *' -and $_ -notlike 'POST *api/query*' }) | Should -BeNullOrEmpty
    }
    It 'a permission an engine recorded as missing on its own token is named, with the command' {
        $items = @(@{ area = 'Microsoft Graph'; item = 'AccessReview.Read.All'; state = 'missing'; fix = 'x' }, @{ area = 'WindowsDefenderATP'; item = 'Vulnerability.Read.All'; state = 'missing'; fix = 'x' },
                   @{ area = 'Azure'; item = 'Reader'; state = 'missing'; fix = 'x' }, @{ area = 'Pro database'; item = 'db_datareader'; state = 'not-checked'; fix = 'x' })
        # no run has checked the current list in full: what the older records say is missing is still named
        $script:World = New-World -Refuse -Runs @((New-Run 'identity' -Items $items -Checked 'older'), (New-Run 'endpoint' -Items @($items[0]) -Checked ''))
        $n = Invoke-Note
        $n.State | Should -Be 'missing'
        $n.Source | Should -Be 'runs'
        @($n.Missing | ForEach-Object { $_.Role }) | Should -Be @('AccessReview.Read.All', 'Vulnerability.Read.All')
        @($n.Lines).Count | Should -Be 5
        @($n.Lines)[-2] | Should -Be 'Invoke-WebRequest https://invardia.com/support/si/Grant-SIIdentity.ps1 -OutFile Grant-SIIdentity.ps1'
    }
    It 'the newest run that checked this list in full is the answer: a permission granted since an older run is not named again' {
        $old = @(@{ area = 'Microsoft Graph'; item = 'AccessReview.Read.All'; state = 'missing'; fix = 'x' }, @{ area = 'WindowsDefenderATP'; item = 'Vulnerability.Read.All'; state = 'missing'; fix = 'x' })
        $new = @(@{ area = 'WindowsDefenderATP'; item = 'Vulnerability.Read.All'; state = 'missing'; fix = 'x' })
        $script:World = New-World -Refuse -Runs @((New-Run 'endpoint' -Items $old -At '2026-10-10T02:00:00.0000000Z'), (New-Run 'identity' -Items $new -At '2026-10-11T02:00:00.0000000Z'),
                                                  (New-Run 'azure' -Items $old -Checked 'older' -At '2026-10-11T03:00:00.0000000Z'))
        $n = Invoke-Note
        @($n.Missing | ForEach-Object { $_.Role }) | Should -Be @('Vulnerability.Read.All')
        @($n.Lines).Count | Should -Be 4
    }
    It 'ONE line instead of a guess: <Why>' -ForEach @(
        @{ Why = 'the newest run checked a list that has changed since (it did not know a permission added later)'; Runs = 'older'; Text = 'no collection run has checked the current permission list yet' }
        @{ Why = 'the newest run was made by a build that recorded no fingerprint'; Runs = 'unmarked'; Text = 'no collection run has checked the current permission list yet' }
        @{ Why = 'the record was cut short'; Runs = 'more'; Text = 'no collection run has checked the current permission list yet' }
        @{ Why = 'no run recorded a check'; Runs = 'none'; Text = 'no collection run has recorded its own check' }
        @{ Why = 'the run records cannot be read either'; Runs = 'refused'; Text = 'the run records could not be read' }
        @{ Why = 'the engine''s check did not run'; Runs = 'error'; Text = 'no collection run has recorded its own check' }
    ) {
        $script:World = New-World -Refuse -Runs @()
        if ($Runs -eq 'older') { $script:World.Runs = @((New-Run 'identity' -Checked '0123456789abcdef')) }
        elseif ($Runs -eq 'unmarked') { $script:World.Runs = @((New-Run 'identity' -Checked '')) }
        elseif ($Runs -eq 'more') { $script:World.Runs = @((New-Run 'identity' -More 3)) }
        elseif ($Runs -eq 'refused') { $script:World.Runs = $null }
        elseif ($Runs -eq 'error') { $script:World.Runs = @((New-Run 'identity' -Err 'The permission check could not run: x')) }
        $n = Invoke-Note
        $n.State | Should -Be 'not-checked'
        @($n.Lines).Count | Should -Be 1
        @($n.Lines)[0] | Should -Be ("permissions: not checked -- the sign-in of this update may not read the directory, and {0}. Get Started > Permissions in the SecurityInsight web app shows any permission that is missing after the next collection run." -f $Text)
        @($n.Missing).Count | Should -Be 0
    }
    It 'the run records are asked once, read only, in the workspace the collection writes to' {
        $script:World = New-World -Refuse -Runs @((New-Run 'identity'))
        $null = Invoke-Note
        $q = @($script:World.Calls | Where-Object { $_ -like 'POST *' })
        $q.Count | Should -Be 1
        $q[0] | Should -Be ("POST https://management.azure.com$($script:Ws)/api/query?api-version=2017-10-01")
        $k = Get-SIPermissionNoteKql
        $k | Should -Match "^SI_RunHealth_CL \| where TimeGenerated > ago\(7d\)"
        $k | Should -Match "Ph == 'End' and isnotempty\(Gaps\) and Eng !startswith 'flow:'"
        $k | Should -Not -Match '//'
    }
}

Describe 'it never fails an update' {
    It 'a REST seam that throws is one line, not an error' {
        $bad = { param($Method, $Uri, $Body, $Resource, $Headers) throw 'network down' }
        $n = Invoke-SIPermissionNote -Rest $bad -Jobs @((New-Job 'caj-si-identity' 'identity')) -SubscriptionId $script:Sub -ResourceGroup $script:Rg
        $n.State | Should -Be 'not-checked'
        @($n.Lines).Count | Should -Be 1
        @($n.Lines)[0] | Should -Match '^permissions: not checked -- the check could not run \(network down\)\. '
    }
    It 'no collection job in the install is one line' {
        $script:World = New-World
        $n = Invoke-Note -Jobs @((New-Job 'caj-si-asset-tagging' 'asset-tagging'))
        $n.State | Should -Be 'not-checked'
        @($n.Lines)[0] | Should -Match 'could not be told from this install''s jobs'
        @($script:World.Calls).Count | Should -Be 0
    }
    It 'a permission list that cannot be read is one line' {
        $n = Invoke-SIPermissionNote -Rest $script:Rest -Jobs @((New-Job 'caj-si-identity' 'identity')) -SubscriptionId $script:Sub -CatalogPath (Join-Path $TestDrive 'missing.json')
        $n.State | Should -Be 'not-checked'
        @($n.Lines).Count | Should -Be 1
    }
    It 'the library writes nothing: no PATCH / PUT / DELETE, no grant call, no module, no az' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-PermissionNote.ps1'))
        $t | Should -Not -Match "'(PATCH|PUT|DELETE)'"
        @([regex]::Matches($t, "'POST'")).Count | Should -Be 1      # the one Log Analytics query
        $t | Should -Not -Match '(?i)Import-Module|Connect-MgGraph|Connect-AzAccount|\baz (login|rest|ad)\b'
        $t | Should -Not -Match '(?i)exit\s+\d|\bthrow\b(?!.*(permission list|collection identity))' -Because 'only the list reader throws, and its caller catches'
    }
}

Describe 'the update runs it (setup\Invoke-SIContainerUpdate.ps1)' {
    BeforeAll { $script:U = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1')) }
    It 'as a step of every completed update, before the templates' {
        # the permission note runs after the web app's size and the sign-in front's store (#852), before the display names and the templates
        $script:U | Should -Match ([regex]::Escape('$null = Invoke-SIUpdateWebAppSize; $null = Invoke-SIUpdateSigninStore; $null = Invoke-SIUpdatePermissionNote; $null = Invoke-SIUpdateDisplayNames; Install-SIUpdateDefaultTemplates }'))
        @([regex]::Matches($script:U, 'exit \(Complete-SIUpdate\)')).Count | Should -Be 3
    }
    It 'with the jobs the update read and this install''s names; its lines are plain lines, never the update''s first warning' {
        $m = [regex]::Match($script:U, '(?s)function Invoke-SIUpdatePermissionNote \{.*?\r?\n\}')
        $m.Success | Should -BeTrue
        $f = $m.Value
        $f | Should -Match ([regex]::Escape('Invoke-SIPermissionNote -Rest $rest -Jobs @($script:SISqlTierJobs) -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Globals $globals -WorkspaceResourceId $ws'))
        $f | Should -Match ([regex]::Escape('if (-not @($n.Lines).Count) { return }'))
        $f | Should -Match ([regex]::Escape('foreach ($l in @($n.Lines)) { Info $l }'))
        $f | Should -Not -Match '\bWarn\b|\bexit\b|\bthrow\b'
        $f | Should -Not -Match '\$Apply|\$DetectOnly' -Because 'it only reads, so it runs the same with and without -Apply'
    }
}
