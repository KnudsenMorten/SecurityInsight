#Requires -Version 5.1
<#
    #507 THE SQL DATABASE SIZE (operator 2026-10-09: "default must be s1 or s2, newer basic. it must be fixed for all prod
    customers"). setup/_shared/SI-SqlTier.ps1: the rule (the Pro database S3 at any size -- S2 until 2026-10-11 --, a size the customer set wins),
    the change for one database (never lowers; vCore / Premium / above S3 / elastic pool untouched), the ARM PATCH body, and
    the upgrade every update runs (setup/Invoke-SIContainerUpdate.ps1 step 7) against a fake ARM / Graph (#521: the update
    talks REST only -- the -Rest seam of setup/_shared/SI-UpdateRest.ps1). The guided install's az seam (-Az, until #521
    phase 2) is kept working and proven once. Offline.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SqlTier.ps1')
    $script:GB250 = [long]268435456000
    # an ARM database (Microsoft.Sql/servers/databases)
    function script:New-Db([string]$Name, [string]$Objective, [string]$SkuName, [string]$Tier, $Capacity, [long]$Max = 2147483648, [string]$Pool = '', [string]$Server = 'sql-si', [string]$Rg = 'rg-si') {
        [pscustomobject]@{ id = "/subscriptions/s1/resourceGroups/$Rg/providers/Microsoft.Sql/servers/$Server/databases/$Name"; name = $Name
            sku = [pscustomobject]@{ name = $SkuName; tier = $Tier; capacity = $Capacity }
            properties = [pscustomobject]@{ currentServiceObjectiveName = $Objective; maxSizeBytes = $Max; elasticPoolId = $Pool } }
    }
    function script:As-Arm($Db) { $Db }
    # the same database as `az sql db list` printed it (flattened) -- the guided install's az seam
    function script:As-Flat($Db) { [pscustomobject]@{ id = $Db.id; name = $Db.name; sku = $Db.sku; currentServiceObjectiveName = $Db.properties.currentServiceObjectiveName; maxSizeBytes = $Db.properties.maxSizeBytes; elasticPoolId = $Db.properties.elasticPoolId } }
    function script:New-Srv([string]$Name, [string]$Rg) { [pscustomobject]@{ id = "/subscriptions/s1/resourceGroups/$Rg/providers/Microsoft.Sql/servers/$Name"; name = $Name; properties = [pscustomobject]@{ fullyQualifiedDomainName = "$Name.db.example" } } }
    # a fake Azure: every call recorded ('<METHOD> <url>'); PATCH bodies kept; -Actions = the identity's actions on the server
    function script:New-World([object[]]$Dbs, [string[]]$Actions = @('*'), [int]$PatchStatus = 0, [string]$PatchError = '', [hashtable]$Counts) {
        [pscustomobject]@{ Dbs = $Dbs; Actions = $Actions; PatchStatus = $PatchStatus; PatchError = $PatchError; Counts = $Counts; Calls = (New-Object System.Collections.Generic.List[string]); Bodies = @{}; Headers = @{}
            Servers = @(New-Srv 'sql-si' 'rg-si'); Other = @(New-Srv 'sql-ledger' 'rg-data') }
    }
    $script:Rest = {
        param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
        $w = $script:World; $w.Calls.Add(('{0} {1}' -f $Method, $Uri))
        $ok = { param($o) [pscustomobject]@{ Status = 200; Body = $(if ($o -is [string]) { $o } else { ConvertTo-Json -InputObject $o -Depth 8 -Compress }) } }
        $list = { param($items) & $ok ([pscustomobject]@{ value = @($items) }) }
        if ($Uri -like 'https://graph.microsoft.com/*') {
            $w.Headers[$Uri] = $Headers
            if ($Resource -ne 'https://graph.microsoft.com/') { return [pscustomobject]@{ Status = 401; Body = 'wrong audience' } }
            if (-not $w.Counts) { return [pscustomobject]@{ Status = 403; Body = '{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}' } }
            $k = ([regex]::Match($Uri, '/v1\.0/(\w+)/')).Groups[1].Value
            return (& $ok ([string]$w.Counts[$k]))
        }
        if ($Resource -ne 'https://management.azure.com/') { return [pscustomobject]@{ Status = 401; Body = 'wrong audience' } }
        if ($Method -eq 'GET' -and $Uri -like '*/resourceGroups/rg-si/providers/Microsoft.Sql/servers?api-version=*') { return (& $list $w.Servers) }
        if ($Method -eq 'GET' -and $Uri -like 'https://management.azure.com/subscriptions/s1/providers/Microsoft.Sql/servers?api-version=*') { return (& $list (@($w.Servers) + @($w.Other))) }
        if ($Method -eq 'GET' -and $Uri -like '*/servers/sql-si/databases?api-version=*') { return (& $list $w.Dbs) }
        if ($Method -eq 'GET' -and $Uri -like '*/servers/sql-ledger/databases?api-version=*') { return (& $list @(New-Db 'sqldb-si-identity' 'Basic' 'Basic' 'Basic' 5 -Server 'sql-ledger' -Rg 'rg-data')) }
        if ($Method -eq 'GET' -and $Uri -like '*/providers/Microsoft.Authorization/permissions?api-version=2022-04-01') { return (& $ok ([pscustomobject]@{ value = @([pscustomobject]@{ actions = @($w.Actions); notActions = @() }) })) }
        if ($Method -eq 'PATCH') {
            if ($w.PatchStatus) { return [pscustomobject]@{ Status = $w.PatchStatus; Body = $w.PatchError } }
            $w.Bodies[$Uri] = [string]$Body
            return [pscustomobject]@{ Status = 202; Body = '' }
        }
        [pscustomobject]@{ Status = 400; Body = "unexpected call: $Method $Uri" }
    }
}

Describe 'the rule: never Basic -- the Pro database S3 at any size (#509; S2 until 2026-10-11), a size the customer set wins' {
    It 'S3 for every Pro database, whatever the tenant''s size, max size 250 GB' {
        foreach ($n in 0, 10, 4999, 5000, 31802) {
            $t = Get-SISqlDatabaseTier -Objects $n
            $t.Name | Should -Be 'S3'; $t.Tier | Should -Be 'Standard'; $t.Capacity | Should -Be 100; $t.MaxSizeBytes | Should -Be $script:GB250; $t.Source | Should -Be 'every-install'
        }
        Get-SISqlTierObjectCount -Counts @{ Users = 22705; Groups = 5097; ServicePrincipals = 900; Devices = 3100 } | Should -Be 31802
        Get-SISqlTierObjectCount -Counts @{ Users = 4000; Devices = 1000 } | Should -Be 5000 -Because 'devices count too'
        (Get-SISqlDatabaseTier -Objects 31802).Reason | Should -Be 'S3 (every SecurityInsight Pro database, at any tenant size)'
    }
    It 'a tenant whose size is not known: still S3; never Basic' {
        Get-SISqlTierObjectCount -Counts $null | Should -BeNullOrEmpty
        Get-SISqlTierObjectCount -Counts @{} | Should -BeNullOrEmpty
        $t = Get-SISqlDatabaseTier -Objects $null
        $t.Name | Should -Be 'S3'; $t.Objects | Should -BeNullOrEmpty
    }
    It 'a size the customer set wins, both ways; an invalid one is ignored with a note' {
        $o = Get-SISqlDatabaseTier -Objects 100 -Override 's4'
        $o.Name | Should -Be 'S4'; $o.Capacity | Should -Be 200; $o.Source | Should -Be 'customer'
        (Get-SISqlDatabaseTier -Objects 100 -Override 'S2').Name | Should -Be 'S2' -Because 'a smaller size the customer set wins too'
        # the identity ledger ignores a size the customer set (owner 2026-10-18: "identity database: keep S1 everywhere")
        $b = Get-SISqlDatabaseTier -Objects 50000 -Override 'Basic' -Role Ledger
        $b.Name | Should -Be 'S1'; $b.Source | Should -Be 'ledger'; $b.MaxSizeBytes | Should -Be $script:GB250
        # the Pro database never below S1 (owner 2026-10-18: a size the customer set lowers too): Basic or S0 -> S1 + 250 GB, said
        foreach ($ov in 'Basic', 'S0', 's0') {
            $d = Get-SISqlDatabaseTier -Objects 50000 -Override $ov -Role Data
            $d.Name | Should -Be 'S1'; $d.Capacity | Should -Be 20; $d.MaxSizeBytes | Should -Be $script:GB250; $d.Source | Should -Be 'customer'
            $d.Note | Should -Match 'never used for the Pro database -- S1 with 250 GB is its minimum'
        }
        (Get-SISqlDatabaseTier -Objects 50000 -Override 'P1').MaxSizeBytes | Should -Be 0 -Because 'Premium keeps its own default max size'
        $bad = Get-SISqlDatabaseTier -Objects 50000 -Override 'GP_Gen5_2'
        $bad.Name | Should -Be 'S3'; $bad.Note | Should -Match "'GP_Gen5_2'.*not a DTU size"
    }
    It 'the identity ledger is S1 at any tenant size (identifiers only) and whatever size the customer set (owner 2026-10-18: "identity database: keep S1 everywhere")' {
        foreach ($n in $null, 10, 5000, 100000) { (Get-SISqlDatabaseTier -Objects $n -Role Ledger).Name | Should -Be 'S1' }
        (Get-SISqlDatabaseTier -Objects 100000 -Role Ledger).Source | Should -Be 'ledger'
        foreach ($ov in 'S2', 'S3', 'S0', 'Basic', 'P1', 'nonsense') {
            $l = Get-SISqlDatabaseTier -Objects 100000 -Role Ledger -Override $ov
            $l.Name | Should -Be 'S1' -Because "$ov is for the Pro database only"; $l.Source | Should -Be 'ledger'; $l.Note | Should -BeNullOrEmpty
        }
    }
    It 'a ledger kept in the Pro database is sized as data; a configured ledger name is S1' {
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'Basic' 'Basic' 'Basic' 5), (New-Db 'my-ledger' 'Basic' 'Basic' 'Basic' 5))
        $u = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -LedgerDatabaseNames @('my-ledger') -Objects 9000
        @($u.Results | ForEach-Object { '{0}={1}' -f $_.Database, $_.Target }) | Should -Be @('sqldb-si-pro=S3', 'my-ledger=S1')
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'Basic' 'Basic' 'Basic' 5))
        $u = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -LedgerDatabaseNames @('sqldb-si-pro') -Objects 9000
        $u.Results[0].Target | Should -Be 'S3'
    }
    It 'a new database is created with the service objective and 250 GB -- no Basic edition' {
        (Get-SISqlDatabaseCreateArgs -Target (Get-SISqlDatabaseTier -Objects 9000)) -join ' ' | Should -Be '--service-objective S3 --max-size 250GB'
        (Get-SISqlDatabaseCreateArgs -Target (Get-SISqlDatabaseTier -Objects 10)) -join ' ' | Should -Be '--service-objective S3 --max-size 250GB'
        (Get-SISqlDatabaseCreateArgs -Target (Get-SISqlDatabaseTier -Objects 10 -Role Ledger)) -join ' ' | Should -Be '--service-objective S1 --max-size 250GB'
    }
    It 'the tenant size from the collection jobs setup sized (an updater that cannot read the directory)' {
        $job = { param($n, $m) [pscustomobject]@{ name = $n; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ resources = [pscustomobject]@{ memory = $m } }) } } } }
        Get-SISqlTierObjectsFromJobs -Jobs @((& $job 'caj-si-identity' '8Gi'), (& $job 'caj-si-flow' '2Gi')) | Should -Be 5000
        Get-SISqlTierObjectsFromJobs -Jobs @((& $job 'caj-si-endpoint' '4.0Gi')) | Should -Be 5000
        Get-SISqlTierObjectsFromJobs -Jobs @((& $job 'caj-si-identity' '2.0Gi'), (& $job 'caj-si-risk-analysis' '8Gi')) | Should -BeNullOrEmpty -Because 'only the tenant-sized collection jobs count'
    }
}

Describe 'one database: raise, never lower, never the customer''s own size' {
    BeforeAll { $script:Pro = Get-SISqlDatabaseTier -Objects 9000; $script:S1 = Get-SISqlDatabaseTier -Objects 10 -Role Ledger }
    It 'Basic -> S3: the PATCH body names the service objective and grows the max size to 250 GB' {
        $c = Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'Basic' 'Basic' 'Basic' 5)) -Target $script:Pro
        $c.Action | Should -Be 'raise'; $c.From | Should -Be 'Basic'
        ConvertTo-SISqlTierPatchJson -Body $c.Body | Should -BeExactly '{"sku":{"name":"S3","tier":"Standard"},"properties":{"maxSizeBytes":268435456000}}'
    }
    It 'S1 (sku Standard/20) -> S3; a max size already 250 GB is not sent' {
        $c = Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S1' 'Standard' 'Standard' 20 $script:GB250)) -Target $script:Pro
        $c.Action | Should -Be 'raise'
        ConvertTo-SISqlTierPatchJson -Body $c.Body | Should -BeExactly '{"sku":{"name":"S3","tier":"Standard"}}'
        # the objective found from the sku alone (no currentServiceObjectiveName)
        $bare = [pscustomobject]@{ sku = [pscustomobject]@{ name = 'Standard'; tier = 'Standard'; capacity = 10 }; properties = [pscustomobject]@{ maxSizeBytes = $script:GB250 } }
        (Get-SISqlTierChange -Current $bare -Target $script:S1).From | Should -Be 'S0'
    }
    It 'an existing S2 Pro database (the rule until 2026-10-11) is raised to S3 -- the sku alone, online (owner: "database S3 100 DTU")' {
        $c = Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S2' 'Standard' 'Standard' 50 $script:GB250)) -Target $script:Pro
        $c.Action | Should -Be 'raise'; $c.From | Should -Be 'S2'; $c.Reason | Should -Match '^S2 -> S3'
        ConvertTo-SISqlTierPatchJson -Body $c.Body | Should -BeExactly '{"sku":{"name":"S3","tier":"Standard"}}'
        # an S2 still at Basic's 2 GB: the size AND the limit in the one PATCH
        ConvertTo-SISqlTierPatchJson -Body (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S2' 'Standard' 'Standard' 50)) -Target $script:Pro).Body | Should -BeExactly '{"sku":{"name":"S3","tier":"Standard"},"properties":{"maxSizeBytes":268435456000}}'
    }
    It 'never lowers: S3 stays S3; S2 against the ledger rule stays S2; S1 stays S1' {
        (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S3' 'Standard' 'Standard' 100 $script:GB250)) -Target $script:Pro).Action | Should -Be 'keep'
        (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S2' 'Standard' 'Standard' 50 $script:GB250)) -Target $script:S1).Action | Should -Be 'keep'
        $k = Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S1' 'Standard' 'Standard' 20 $script:GB250)) -Target $script:S1
        $k.Action | Should -Be 'keep'; $k.Reason | Should -Match 'never lowered'
        # a Basic Pro database whose install set Basic is still raised: to S1 with 250 GB (never below S1); a Basic ledger to S1 (its rule)
        $nb = Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'Basic' 'Basic' 'Basic' 5)) -Target (Get-SISqlDatabaseTier -Objects 9000 -Override 'Basic')
        $nb.Action | Should -Be 'raise'
        ConvertTo-SISqlTierPatchJson -Body $nb.Body | Should -BeExactly '{"sku":{"name":"S1","tier":"Standard"},"properties":{"maxSizeBytes":268435456000}}'
        $nl = Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'Basic' 'Basic' 'Basic' 5)) -Target (Get-SISqlDatabaseTier -Objects 9000 -Override 'Basic' -Role Ledger)
        ConvertTo-SISqlTierPatchJson -Body $nl.Body | Should -BeExactly '{"sku":{"name":"S1","tier":"Standard"},"properties":{"maxSizeBytes":268435456000}}'
    }
    It 'S3 still at Basic''s 2 GB storage limit: the limit alone grows to 250 GB (ring 1 2026-10-09: the database filled up)' {
        $c = Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S3' 'Standard' 'Standard' 100)) -Target $script:Pro
        $c.Action | Should -Be 'raise'; $c.From | Should -Be 'S3'; $c.Reason | Should -Match 'S3 keeps its size; its storage limit grows 2 GB -> 250 GB'
        ConvertTo-SISqlTierPatchJson -Body $c.Body | Should -BeExactly '{"properties":{"maxSizeBytes":268435456000}}' -Because 'the service objective is not sent'
        # the same on a database above the target (the ledger rule: S1, a database already S2)
        (ConvertTo-SISqlTierPatchJson -Body (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S2' 'Standard' 'Standard' 50)) -Target $script:S1).Body) | Should -BeExactly '{"properties":{"maxSizeBytes":268435456000}}'
        (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S3' 'Standard' 'Standard' 100 $script:GB250)) -Target $script:Pro).Action | Should -Be 'keep' -Because 'a limit already at 250 GB is left alone'
        (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S4' 'Standard' 'Standard' 200)) -Target $script:Pro).Action | Should -Be 'keep' -Because 'above S3 is the customer''s size, limit included'
    }
    It 'never touches a database above S3 by the rule, on Premium, on vCore or in an elastic pool' {
        (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S4' 'Standard' 'Standard' 200 $script:GB250)) -Target $script:Pro).Reason | Should -Match 'above S3'
        # a size the customer set above the database's own is the customer's choice: S4 -> S6
        $up = Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S4' 'Standard' 'Standard' 200 $script:GB250)) -Target (Get-SISqlDatabaseTier -Objects 1 -Override 'S6')
        $up.Action | Should -Be 'raise'; ConvertTo-SISqlTierPatchJson -Body $up.Body | Should -BeExactly '{"sku":{"name":"S6","tier":"Standard"}}'
        # Premium is never lowered by a Standard size the customer set
        (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'P1' 'Premium' 'Premium' 125)) -Target (Get-SISqlDatabaseTier -Objects 1 -Override 'S2')).Action | Should -Be 'keep'
        (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'P1' 'Premium' 'Premium' 125)) -Target $script:Pro).Reason | Should -Match 'Premium'
        $v = Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'GP_Gen5_2' 'GP_Gen5' 'GeneralPurpose' 2)) -Target $script:Pro
        $v.Action | Should -Be 'keep'; $v.Reason | Should -Match 'vCore'
        (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'GP_S_Gen5_1' 'GP_S_Gen5' 'GeneralPurpose' 1)) -Target $script:Pro).Action | Should -Be 'keep'
        (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'ElasticPool' 'ElasticPool' 'Standard' 0 0 '/x/elasticPools/p')) -Target $script:Pro).Reason | Should -Match 'elastic pool'
    }
    It 'the identity''s right: Microsoft.Sql/servers/databases/write by an action, a wildcard, or not at all' {
        Test-SISqlTierPermission -Permissions @([pscustomobject]@{ actions = @('*'); notActions = @() }) | Should -BeTrue
        Test-SISqlTierPermission -Permissions @([pscustomobject]@{ actions = @('Microsoft.Sql/servers/databases/*'); notActions = @() }) | Should -BeTrue
        Test-SISqlTierPermission -Permissions @([pscustomobject]@{ actions = @('*/read'); notActions = @() }) | Should -BeFalse
        Test-SISqlTierPermission -Permissions @([pscustomobject]@{ actions = @('*'); notActions = @('Microsoft.Sql/*') }) | Should -BeFalse
        Test-SISqlTierPermission -Permissions @() | Should -BeNullOrEmpty
    }
}

Describe 'every update raises an existing install''s databases (Invoke-SISqlTierUpgrade)' {
    It 'Basic -> S3 by ONE ARM PATCH per SI database; a database SI does not own is never touched' {
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'Basic' 'Basic' 'Basic' 5), (New-Db 'sqldb-si-identity' 'Basic' 'Basic' 'Basic' 5), (New-Db 'customer-db' 'Basic' 'Basic' 'Basic' 5), (New-Db 'master' 'System' 'System' 'System' 0))
        $u = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -ServerFqdns @('sql-si.db.example') -DatabaseNames @('sqldb-si-pro') -Objects 27800
        @($u.Results | Where-Object Action -eq 'raised' | ForEach-Object Database) | Should -Be @('sqldb-si-pro', 'sqldb-si-identity')
        $patches = @($script:World.Calls | Where-Object { $_ -like 'PATCH *' })
        $patches.Count | Should -Be 2
        $patches | ForEach-Object { $_ | Should -Not -Match 'customer-db|master' }
        $url = 'https://management.azure.com/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft.Sql/servers/sql-si/databases/sqldb-si-pro?api-version=2021-11-01'
        $script:World.Bodies[$url] | Should -BeExactly '{"sku":{"name":"S3","tier":"Standard"},"properties":{"maxSizeBytes":268435456000}}'
        @($script:World.Calls) | ForEach-Object { $_ | Should -Match '^(GET|PATCH) https://management\.azure\.com/subscriptions/s1/' }
        @($u.Lines)[0] | Should -Match 'sql-si/sqldb-si-pro raised Basic -> S3: S3 \(every SecurityInsight Pro database, at any tenant size\).*online change'
        $idUrl = 'https://management.azure.com/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft.Sql/servers/sql-si/databases/sqldb-si-identity?api-version=2021-11-01'
        $script:World.Bodies[$idUrl] | Should -BeExactly '{"sku":{"name":"S1","tier":"Standard"},"properties":{"maxSizeBytes":268435456000}}' -Because 'the identity ledger is S1 at any tenant size'
        Get-SISqlTierSummaryLine -Upgrade $u | Should -Be 'SQL database size S3 (every SecurityInsight Pro database, at any tenant size): sqldb-si-pro raised to S3, sqldb-si-identity raised to S1'
    }
    It 'an S3 database left at 2 GB by an earlier raise gets ONE PATCH that grows only its storage limit' {
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'S3' 'Standard' 'Standard' 100), (New-Db 'sqldb-si-identity' 'S1' 'Standard' 'Standard' 20 $script:GB250))
        $u = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Objects 10
        @($u.Results | ForEach-Object Action) | Should -Be @('raised', 'keep')
        $url = 'https://management.azure.com/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft.Sql/servers/sql-si/databases/sqldb-si-pro?api-version=2021-11-01'
        $script:World.Bodies[$url] | Should -BeExactly '{"properties":{"maxSizeBytes":268435456000}}'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 1
        @($u.Lines)[0] | Should -Match 'sqldb-si-pro raised S3 keeps its size; its storage limit grows 2 GB -> 250 GB'
    }
    It 'an existing install on S2 (the rule until 2026-10-11) is raised to S3 by ONE sku PATCH; the ledger stays S1' {
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'S2' 'Standard' 'Standard' 50 $script:GB250), (New-Db 'sqldb-si-identity' 'S1' 'Standard' 'Standard' 20 $script:GB250))
        $u = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Objects 10
        @($u.Results | ForEach-Object Action) | Should -Be @('raised', 'keep')
        $url = 'https://management.azure.com/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft.Sql/servers/sql-si/databases/sqldb-si-pro?api-version=2021-11-01'
        $script:World.Bodies[$url] | Should -BeExactly '{"sku":{"name":"S3","tier":"Standard"}}'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 1
        @($u.Lines)[0] | Should -Match 'sqldb-si-pro raised S2 -> S3'
    }
    It 'never lowers and never touches the customer''s own size: nothing is sent' {
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'S4' 'Standard' 'Standard' 200 $script:GB250), (New-Db 'sqldb-si-identity' 'GP_Gen5_2' 'GP_Gen5' 'GeneralPurpose' 2))
        $u = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Objects 10
        @($u.Results | ForEach-Object Action) | Should -Be @('keep', 'keep')
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
    }
    It '-WhatIf (detect only) plans and sends nothing' {
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'Basic' 'Basic' 'Basic' 5))
        $u = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Objects 10 -WhatIf
        $u.Results[0].Action | Should -Be 'would-raise'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
    }
    It 'an identity without the right is told what is missing, and nothing is sent' {
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'Basic' 'Basic' 'Basic' 5)) -Actions @('*/read')
        $u = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Objects 10
        $u.Results[0].Action | Should -Be 'missing-right'
        $u.Results[0].Line | Should -Match "lacks Microsoft\.Sql/servers/databases/write.*'SQL DB Contributor' on server sql-si.*nothing was changed"
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
    }
    It 'Azure refusing the PATCH (403) says what is missing; another error is a line, and the run never throws' {
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'Basic' 'Basic' 'Basic' 5)) -PatchStatus 403 -PatchError '{"error":{"code":"AuthorizationFailed","message":"The client does not have authorization"}}'
        (Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Objects 10).Results[0].Action | Should -Be 'missing-right'
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'Basic' 'Basic' 'Basic' 5)) -PatchStatus 400 -PatchError '{"error":{"code":"ServiceBusy","message":"try later"}}'
        $r = (Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Objects 10).Results[0]
        $r.Action | Should -Be 'failed'; $r.Line | Should -Match 'NOT raised.*HTTP 400: ServiceBusy: try later.*next update tries again'
    }
    It 'every read that fails is a line, never a throw: no server list = nothing to size' {
        $script:World = New-World -Dbs @()
        $deny = { param($Method, $Uri, $Body, $Resource, $Headers) $script:World.Calls.Add("$Method $Uri"); [pscustomobject]@{ Status = 403; Body = '{"error":{"code":"AuthorizationFailed","message":"no"}}' } }
        $u = Invoke-SISqlTierUpgrade -Rest $deny -SubscriptionId 's1' -ResourceGroup 'rg-si' -Objects 10
        @($u.Results).Count | Should -Be 1
        $u.Results[0].Line | Should -Match 'no SQL server for this install was found'
    }
    It 'one seam only: -Rest (the update and the guided install) -- the az seam is gone (no az path, #521)' {
        { Invoke-SISqlTierUpgrade -SubscriptionId 's1' -Objects 10 } | Should -Throw '*pass -Rest*'
        (Get-Command Invoke-SISqlTierUpgrade).Parameters.ContainsKey('Az') | Should -BeFalse
        (Get-Command Invoke-SISqlTierRead).Parameters.ContainsKey('Az') | Should -BeFalse
        (Get-Command Invoke-SISqlTierPatch).Parameters.ContainsKey('Az') | Should -BeFalse
    }
    It 'a configured server outside the install''s resource group is found by its host name; an unknown one is said' {
        $script:World = New-World -Dbs @()
        $u = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -ServerFqdns @('sql-ledger.db.example', 'nope.db.example') -Objects 10
        @($u.Results | Where-Object Action -eq 'raised' | ForEach-Object { '{0}/{1}' -f $_.Server, $_.Database }) | Should -Be @('sql-ledger/sqldb-si-identity')
        @($u.Results | Where-Object Action -eq 'failed').Line | Should -Match 'nope\.db\.example was not found'
    }
    It 'the tenant''s size through Microsoft Graph ($count with ConsistencyLevel, the Graph audience); a refused read = not known' {
        $script:World = New-World -Dbs @() -Counts @{ users = 22705; groups = 5097; servicePrincipals = 1; devices = 0 }
        $c = Get-SISqlTierTenantCounts -Rest $script:Rest -SubscriptionId 's1'
        Get-SISqlTierObjectCount -Counts $c | Should -Be 27803
        $g = @($script:World.Calls | Where-Object { $_ -like '*graph.microsoft.com*' })
        $g.Count | Should -Be 4
        $g | ForEach-Object { $_ | Should -Match '^GET https://graph\.microsoft\.com/v1\.0/\w+/\$count$' }
        foreach ($h in $script:World.Headers.Values) { $h['ConsistencyLevel'] | Should -Be 'eventual' }
        $script:World = New-World -Dbs @()
        Get-SISqlTierTenantCounts -Rest $script:Rest | Should -BeNullOrEmpty
        # an answer that is not a plain number (a fake or a proxy page) is not a count
        $script:World = New-World -Dbs @() -Counts @{ users = '{"value":[1,2]}'; groups = 1; servicePrincipals = 1; devices = 1 }
        Get-SISqlTierTenantCounts -Rest $script:Rest | Should -BeNullOrEmpty
    }
    It 'every ARM call names the subscription in its URL (never a default context) and asks ARM''s audience' {
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'Basic' 'Basic' 'Basic' 5))
        $null = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -ServerFqdns @('sql-ledger.db.example') -Objects 10
        $script:World.Calls.Count | Should -BeGreaterThan 4
        @($script:World.Calls | Where-Object { $_ -notmatch '^(GET|PATCH) https://management\.azure\.com/subscriptions/s1/' }) | Should -BeNullOrEmpty
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }) | ForEach-Object { $_ | Should -Match 'api-version=2021-11-01$' }
    }
}

# owner 2026-10-18 (7 days of telemetry: small installs' Pro database idle about 98 % of the week on S3): a size the customer
# set applies in BOTH directions -- S2 on an S3 database lowers it; never below S1; without one the rule stays raise-only S3.
Describe 'a size the customer set lowers too (owner 2026-10-18); the rule alone never lowers' {
    BeforeAll { $script:Pro = Get-SISqlDatabaseTier -Objects 9000 }
    It 'S2 set on an S3 database: lowered by ONE sku PATCH; the storage limit is kept' {
        $c = Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S3' 'Standard' 'Standard' 100 $script:GB250)) -Target (Get-SISqlDatabaseTier -Objects 9000 -Override 'S2')
        $c.Action | Should -Be 'lower'; $c.From | Should -Be 'S3'; $c.Reason | Should -Match '^S3 -> S2: S2, the size this install set'
        ConvertTo-SISqlTierPatchJson -Body $c.Body | Should -BeExactly '{"sku":{"name":"S2","tier":"Standard"}}'
        # from S4 (a size the customer once chose) too; a limit larger than the smaller size holds becomes its 250 GB
        $big = Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S4' 'Standard' 'Standard' 200 ([long]536870912000))) -Target (Get-SISqlDatabaseTier -Objects 1 -Override 'S2')
        $big.Action | Should -Be 'lower'
        ConvertTo-SISqlTierPatchJson -Body $big.Body | Should -BeExactly '{"sku":{"name":"S2","tier":"Standard"},"properties":{"maxSizeBytes":268435456000}}'
    }
    It 'never below S1: S0 or Basic set on the Pro database lowers an S3 to S1, not further' {
        foreach ($ov in 'S0', 'Basic') {
            $c = Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S3' 'Standard' 'Standard' 100 $script:GB250)) -Target (Get-SISqlDatabaseTier -Objects 1 -Override $ov)
            $c.Action | Should -Be 'lower'; $c.Body.sku.name | Should -Be 'S1'
        }
        # the identity ledger is never lowered (an S0 set: kept at S1 -- the setting is not for the ledger)
        (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S1' 'Standard' 'Standard' 20 $script:GB250)) -Target (Get-SISqlDatabaseTier -Objects 1 -Override 'S0' -Role Ledger)).Action | Should -Be 'keep'
    }
    It 'NEGATIVE: without a size set the rule never lowers (S4 / S6 kept), and the same size set is a keep' {
        foreach ($db in @((New-Db 'd' 'S4' 'Standard' 'Standard' 200 $script:GB250), (New-Db 'd' 'S6' 'Standard' 'Standard' 400 $script:GB250), (New-Db 'd' 'S3' 'Standard' 'Standard' 100 $script:GB250))) {
            (Get-SISqlTierChange -Current $db -Target $script:Pro).Action | Should -Be 'keep'
        }
        (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'S2' 'Standard' 'Standard' 50 $script:GB250)) -Target (Get-SISqlDatabaseTier -Objects 1 -Override 'S2')).Action | Should -Be 'keep'
        # an elastic pool member and vCore are never sized, whatever was set
        (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'ElasticPool' 'ElasticPool' 'Standard' 0 0 '/x/elasticPools/p')) -Target (Get-SISqlDatabaseTier -Objects 1 -Override 'S1')).Action | Should -Be 'keep'
        (Get-SISqlTierChange -Current (As-Arm (New-Db 'd' 'GP_Gen5_2' 'GP_Gen5' 'GeneralPurpose' 2)) -Target (Get-SISqlDatabaseTier -Objects 1 -Override 'S1')).Action | Should -Be 'keep'
    }
    It 'every update: S2 set lowers the Pro database S3 -> S2 by ONE PATCH, said as lowered; -WhatIf plans it; a refusal is NOT lowered' {
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'S3' 'Standard' 'Standard' 100 $script:GB250), (New-Db 'sqldb-si-identity' 'S2' 'Standard' 'Standard' 50 $script:GB250))
        $u = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Objects 10 -Override 'S2'
        @($u.Results | ForEach-Object Action) | Should -Be @('lowered', 'keep')
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 1
        $url = 'https://management.azure.com/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft.Sql/servers/sql-si/databases/sqldb-si-pro?api-version=2021-11-01'
        $script:World.Bodies[$url] | Should -BeExactly '{"sku":{"name":"S2","tier":"Standard"}}'
        @($u.Lines)[0] | Should -Match 'sql-si/sqldb-si-pro lowered S3 -> S2: S2, the size this install set -- an online change'
        Get-SISqlTierSummaryLine -Upgrade $u | Should -Match 'sqldb-si-pro lowered to S2, sqldb-si-identity kept'
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'S3' 'Standard' 'Standard' 100 $script:GB250))
        $w = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Objects 10 -Override 'S2' -WhatIf
        $w.Results[0].Action | Should -Be 'would-lower'; $w.Results[0].Line | Should -Match 'would be lowered S3 -> S2'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'S3' 'Standard' 'Standard' 100 $script:GB250)) -PatchStatus 400 -PatchError '{"error":{"code":"ServiceBusy","message":"try later"}}'
        (Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Objects 10 -Override 'S2').Results[0].Line | Should -Match 'was NOT lowered S3 -> S2'
    }
    It 'NEGATIVE: S2 set on an install whose identity ledger is S1 -- the Pro database is lowered, the ledger stays S1 (owner 2026-10-18: "identity database: keep S1 everywhere")' {
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'S3' 'Standard' 'Standard' 100 $script:GB250), (New-Db 'sqldb-si-identity' 'S1' 'Standard' 'Standard' 20 $script:GB250))
        $u = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Objects 10 -Override 'S2'
        @($u.Results | ForEach-Object { '{0}={1}:{2}' -f $_.Database, $_.Action, $_.Target }) | Should -Be @('sqldb-si-pro=lowered:S2', 'sqldb-si-identity=keep:S1')
        $patches = @($script:World.Calls | Where-Object { $_ -like 'PATCH *' })
        $patches.Count | Should -Be 1; $patches[0] | Should -Match '/databases/sqldb-si-pro\?'
        @($script:World.Bodies.Keys | Where-Object { $_ -match 'sqldb-si-identity' }) | Should -BeNullOrEmpty -Because 'the ledger is never sent a size'
        # a larger size set (S4) does not raise the ledger either; a configured ledger name is treated the same
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'S3' 'Standard' 'Standard' 100 $script:GB250), (New-Db 'my-ledger' 'S1' 'Standard' 'Standard' 20 $script:GB250))
        $v = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -LedgerDatabaseNames @('my-ledger') -Objects 10 -Override 'S4'
        @($v.Results | ForEach-Object { '{0}={1}:{2}' -f $_.Database, $_.Action, $_.Target }) | Should -Be @('sqldb-si-pro=raised:S4', 'my-ledger=keep:S1')
        # a data database the install is configured with follows the setting like the Pro database
        $script:World = New-World -Dbs @((New-Db 'sqldb-si-pro' 'S3' 'Standard' 'Standard' 100 $script:GB250), (New-Db 'sqldb-si-data' 'S3' 'Standard' 'Standard' 100 $script:GB250))
        $w = Invoke-SISqlTierUpgrade -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -DatabaseNames @('sqldb-si-data') -Objects 10 -Override 'S2'
        @($w.Results | Where-Object Action -eq 'lowered' | ForEach-Object Database) | Should -Be @('sqldb-si-pro', 'sqldb-si-data')
    }
    It 'WIRING: the update reads the size from the Pro database first (cfg.Setting, solution scope), then the config, then the job''s variable' {
        $h = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $fn = [regex]::Match($h, '(?s)function Invoke-SIUpdateSqlTier \{.*?\n\}').Value
        $fn | Should -Match "\`$override = Get-SIUpdateSetting -Name 'SI_Bootstrap_SqlServiceObjective' -EnvName 'SI_UPDATER_SQL_SERVICE_OBJECTIVE'"
        $g = [regex]::Match($h, '(?s)function Get-SIUpdateSetting \{.*?\n\}').Value
        $g | Should -Match "FROM cfg\.Setting WHERE Scope = N'solution' AND Name IN"
        $g | Should -Match 'AddWithValue\(\$p, \$n\)' -Because 'the names are parameters, never pasted into the statement'
        # the order: the Pro database, then the config ($globals), then the variable
        $iDb = $g.IndexOf('$script:SIUpdateProSettings.ContainsKey($Name)'); $iCfg = $g.IndexOf('$globals.ContainsKey($Name)'); $iEnv = $g.IndexOf('GetEnvironmentVariable($EnvName)')
        $iDb | Should -BeGreaterThan -1; $iCfg | Should -BeGreaterThan $iDb; $iEnv | Should -BeGreaterThan $iCfg
        $h | Should -Match "\`$script:SIUpdateProSettingNames = @\('SI_Bootstrap_SqlServiceObjective', 'SI_Bootstrap_WebAppCpu', 'SI_Bootstrap_WebAppMemory'\)"
    }
    It 'the setting is in the settings catalog (support sets it per install), Pro, empty by default, S1 and up only' {
        $catPath = Join-Path $script:SIRoot 'config\settings.catalog.locked.json'   # a Pro file: not in the Community copy
        if (-not (Test-Path $catPath)) { Set-ItResult -Skipped -Because 'the settings catalog is Pro (not in the Community copy)'; return }
        $cat = Get-Content -Raw $catPath | ConvertFrom-Json
        $s = @($cat.settings | Where-Object { $_.name -eq 'SI_Bootstrap_SqlServiceObjective' })[0]
        $s | Should -Not -BeNullOrEmpty
        $s.edition | Should -Be 'pro'; $s.default | Should -BeNullOrEmpty
        foreach ($ok in 'S1', 'S2', 's2', 'S3', 'S12') { $ok | Should -Match $s.pattern }
        foreach ($no in 'S0', 'Basic', 'P1', 'S5', 'GP_Gen5_2') { $no | Should -Not -Match $s.pattern }
        $s.purpose | Should -Match 'Empty = the product''s rule'
    }
    It 'ConvertFrom-SIUpdateSettingJson: a cfg.Setting value as text' {
        $h = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        . ([scriptblock]::Create([regex]::Match($h, '(?s)function ConvertFrom-SIUpdateSettingJson \{.*?\n\}').Value))
        ConvertFrom-SIUpdateSettingJson '"S2"' | Should -BeExactly 'S2'
        ConvertFrom-SIUpdateSettingJson '2.5' | Should -BeExactly '2.5'
        ConvertFrom-SIUpdateSettingJson 'null' | Should -BeExactly ''
        ConvertFrom-SIUpdateSettingJson $null | Should -BeExactly ''
        ConvertFrom-SIUpdateSettingJson ([DBNull]::Value) | Should -BeExactly ''
        ConvertFrom-SIUpdateSettingJson 'S2' | Should -BeExactly 'S2'
    }
}

Describe 'wiring: the installer, every update and the updater record' {
    It 'Invoke-SIContainerUpdate runs the size step on every -Apply exit, never failing the update' {
        $h = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $fn = [regex]::Match($h, '(?s)function Invoke-SIUpdateSqlTier \{.*?\n\}').Value
        $fn | Should -Match 'Invoke-SISqlTierUpgrade -Rest \$rest -SubscriptionId \$sub -ResourceGroup \$target\.ResourceGroupName'
        $fn | Should -Match 'Get-SISqlTierTenantCounts -Rest \$rest'
        $fn | Should -Not -Match '& az|AzArgs'
        $fn | Should -Match '-WhatIf:\(-not \$Apply -or \$DetectOnly\)'
        $fn | Should -Match 'SI_UPDATER_SQL_SERVICE_OBJECTIVE'
        $fn | Should -Match '\$global:SI_UpdateSqlTier = Get-SISqlTierSummaryLine'
        $fn | Should -Match 'catch \{ Warn'
        $fn | Should -Not -Match 'exit 1|return 1|throw'
        @([regex]::Matches($h, 'exit \(Complete-SIUpdate\)')).Count | Should -Be 3
    }
    It '#756 WIRING: with the code current the updater still runs the size steps (-SizingOnly) -- never a build or a roll' {
        $h = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $blk = [regex]::Match($h, '(?s)\nif \(\$SizingOnly\) \{.*?\n\}').Value
        $blk | Should -Match 'Invoke-SIUpdateSqlTier'; $blk | Should -Match 'Invoke-SIUpdateJobSizing'; $blk | Should -Match 'Invoke-SIUpdateWebAppSize'
        $blk | Should -Match 'exit 0'
        $blk | Should -Not -Match 'Start-SIAcrBuild|Invoke-SIJobImageRoll|Get-SIAcrRegistry|Install-SIUpdateDefaultTemplates|exit 1'
        $h.IndexOf('if ($SizingOnly) {') | Should -BeLessThan $h.IndexOf("Step '2. BUILD'")
        # the Invardia update path is Pro: read only after Test-Path finds it (skipped, saying why, in the Community payload)
        $invPath = Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1'
        if (-not (Test-Path -LiteralPath $invPath)) { Set-ItResult -Skipped -Because 'the Invardia update path is not in this payload'; return }
        $inv = [IO.File]::ReadAllText($invPath)
        $inv | Should -Match 'if \(-not \$roll -or \$roll\.Held\)'
        $inv | Should -Match 'Invoke-SIUpdaterSizingPass -SIRoot \$SIRoot'
        $u = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'))
        [regex]::Match($u, '(?s)function Invoke-SIUpdaterSizingPass \{.*?\n\}').Value | Should -Match 'Save-SIUpdaterSqlTierRow -Store \$Store'
    }
    It 'the updater records the line in cfg.InstallState ''SqlTier'' after the roll, never throwing' {
        . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
        $rows = New-Object System.Collections.Generic.List[object]
        $store = [pscustomobject]@{ Invoke = { param($q, $p, $m) $rows.Add([pscustomobject]@{ Sql = $q; P = $p; Mode = $m }) }.GetNewClosure() }
        Save-SIUpdaterSqlTierRow -Store $store -Line ('x' * 450) | Should -BeTrue
        $rows[0].Sql | Should -Match "N'SqlTier'"
        $rows[0].P.Value.Length | Should -Be 400
        $bad = [pscustomobject]@{ Invoke = { throw 'no db' } }
        Save-SIUpdaterSqlTierRow -Store $bad -Line 'x' | Should -BeFalse
        $u = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'))
        $u.IndexOf('Save-SIUpdaterSqlTierRow -Store $Store') | Should -BeGreaterThan $u.IndexOf("& (Join-Path `$SIRoot 'setup/Invoke-SIContainerUpdate.ps1') -Apply")
    }
}
