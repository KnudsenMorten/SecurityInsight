#Requires -Version 7.0
<#
    #1383 -- THE IDENTITY COLLECTION'S THREE FIXES (owner 2026-11-25: "Fix the broken cache", "Batch the Graph calls",
    "Deleted groups = not incomplete"; data quality first).

      1. THE BROKEN CACHE. New-SISignInMethodsCache / New-SIDirectoryNameStore dot-sourced SI-RecordSql.ps1 INSIDE the function,
         so Invoke-SIRecordSqlDb lived only in that function's scope and the seam they returned failed later ("The term
         'Invoke-SIRecordSqlDb' is not recognized") on every identity run since 3.1.3x: no user's work row was recorded and
         caj-si-signin-methods picked nobody. Proven here in a FRESH process shaped like the job (the files dot-sourced inside a
         function, as Get-DiscoveryFromEntraUsers does; the seam called from another function) with NO fake
         Invoke-SIRecordSqlDb anywhere -- and, with a SQL Server, end to end: the page statement writes the work rows and the
         background job's pick then takes them. Plus a static rule: no factory function loads a helper inside its body.
      2. THE GRAPH CALLS BATCHED. Invoke-SIGraphBatchGet: 20 per $batch request, waves at the sign-in methods read's pace,
         Retry-After honoured, a refusal stops further requests, an answer of more than one page read on; the group members,
         the PIM for Groups schedules, the activated memberships and the service principals' application permissions use it.
         The fixture measures the calls before and after (internal's shape: 194 groups, 32 deleted, 1,617 principals).
      3. DELETED GROUPS ARE GONE. An Azure-only group getByIds does not return, or a group read answering 404, is gone (said
         once with its id) and the role read stays complete; a 5xx / 403 / failed kind read still marks it incomplete.
    Offline (Graph is a fake; the SQL block needs the runner's SQL Server). PS 7.
#>

BeforeDiscovery {
    $script:HasSql = [bool]($env:SI_TEST_LOCALSQL)
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Shared = Join-Path $script:SIRoot 'engine\asset-profiling\shared'
    $script:Info = New-Object System.Collections.Generic.List[string]
    function script:Write-SIInfo { param($Message) $script:Info.Add([string]$Message) }
    foreach ($n in 'Write-SIProgress', 'Reset-SIProgress') { if (-not (Get-Command -Name $n -ErrorAction SilentlyContinue)) { Set-Item -Path ("function:script:{0}" -f $n) -Value { param() } } }
    . (Join-Path $script:Shared 'IdentityRoleFetcher.ps1')
    $script:Pwsh = (Get-Process -Id $PID).Path
    $script:Work = Join-Path ([IO.Path]::GetTempPath()) ('si-idb-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $script:Work
    # runs a script in a FRESH process with its OWN script scope (& 'script', as the container starts a job); answers its JSON
    function script:Invoke-Fresh([string]$Name, [string]$Body) {
        $scr = Join-Path $script:Work ($Name + '.ps1')
        Set-Content -LiteralPath $scr -Value $Body
        $out = & $script:Pwsh -NoProfile -NonInteractive -Command ("& '{0}'" -f $scr.Replace("'", "''")) 2>&1 | Out-String
        $line = @(($out -split "`r?`n") | Where-Object { $_ -match '^\{.*\}$' })[-1]
        if (-not $line) { throw ('the fresh process answered no result: ' + $out) }
        $line | ConvertFrom-Json
    }
    function script:Q([string]$s) { $s.Replace("'", "''") }

    # ---- a fake Microsoft Graph for the batched reads: answers each $batch item from $script:G by its URL --------------
    $script:G = @{}
    function script:Reset-G { $script:G = @{ Requests = 0; Items = 0; Bodies = (New-Object System.Collections.Generic.List[int]); Handler = $null } }
    Reset-G
    $script:FakePost = {
        param([string[]]$Bodies)
        $out = New-Object System.Collections.Generic.List[object]
        $script:G.Bodies.Add(@($Bodies).Count)
        foreach ($b in @($Bodies)) {
            $script:G.Requests++
            $req = $b | ConvertFrom-Json
            $resp = foreach ($r in @($req.requests)) {
                $script:G.Items++
                $a = & $script:G.Handler ([uri]::UnescapeDataString([string]$r.url))
                [pscustomobject]@{ id = [string]$r.id; status = [int]$a.status; headers = $a.headers; body = $a.body }
            }
            $out.Add([pscustomobject]@{ Response = [pscustomobject]@{ responses = @($resp) }; Status = 200; RetryAfter = $null; Error = '' })
        }
        , $out.ToArray()
    }
    function script:Ok($Rows) { @{ status = 200; body = [pscustomobject]@{ value = @($Rows) } } }
    function script:Err([int]$Status, [string]$Code = 'Error') { @{ status = $Status; body = [pscustomobject]@{ error = [pscustomobject]@{ code = $Code; message = "status $Status" } } } }
    $script:NoSleep = { param($Seconds) $script:Slept.Add([int]$Seconds) }
    $script:Slept = New-Object System.Collections.Generic.List[int]
}

AfterAll {
    if ($script:Work) { Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue }
    $script:_SICache = @{}; $global:SI_EntraRoleReadState = $null
}

Describe '1. the sign-in methods cache and the people picker''s store reach the database (the broken cache)' {
    It 'in a fresh process shaped like the identity step, with NO fake Invoke-SIRecordSqlDb: the seam reaches the real Invoke-SIRecordSqlDb' {
        $r = Invoke-Fresh 'cache-scope' @"
`$ErrorActionPreference = 'Continue'
function Invoke-SIShapeOfTheDiscovery {
    # loaded INSIDE a function, as Get-DiscoveryFromEntraUsers loads them
    . '$(Q (Join-Path $script:Shared 'SI-AuthMethodsRead.ps1'))'
    . '$(Q (Join-Path $script:Shared 'SI-SignInMethodsChoice.ps1'))'
    . '$(Q (Join-Path $script:Shared 'SI-DirectoryNames.ps1'))'
    # the sign-in of the database (the job's managed identity) is the only thing replaced: proves the seam got THAT far
    function Get-SIObjectLedgerConnection { param(`$Server, `$Database) throw ('OPENER-REACHED ' + `$Server + '/' + `$Database) }
    `$global:SI_ProSqlServer = 'srv.test'; `$global:SI_ProSqlDatabase = 'db1'
    `$cache = New-SISignInMethodsCache
    `$store = New-SIDirectoryNameStore
    `$fake = @(Get-Command -Name Invoke-SIRecordSqlDb -All -ErrorAction SilentlyContinue | ForEach-Object { [string]`$_.ScriptBlock.File })
    `$u = [pscustomobject]@{ id = 'u1'; userPrincipalName = 'u1@contoso.test'; userType = 'Member'; accountEnabled = `$true; displayName = 'User 1' }
    `$null = Invoke-SISignInMethodsPage -Users @(`$u) -Choice ([pscustomobject]@{ Mode = 'all'; MaxAgeDays = 90 }) -Cache `$cache
    `$null = Add-SIDirectoryNamePage -Store `$store -Objects @(`$u) -Kind user
    [pscustomobject]@{ CacheNote = [string]`$cache.Note; StoreNote = [string]`$store.Note; Defined = `$fake } | ConvertTo-Json -Compress
}
Invoke-SIShapeOfTheDiscovery
"@
        @($r.Defined).Count | Should -Be 1 -Because 'one Invoke-SIRecordSqlDb, the real one'
        @($r.Defined)[0] | Should -Match 'SI-RecordSql\.ps1$'
        $r.CacheNote | Should -Not -Match 'is not recognized'
        $r.CacheNote | Should -Match 'OPENER-REACHED srv\.test/db1' -Because 'the sign-in methods seam ran Invoke-SIRecordSqlDb (red on 3.1.50: "The term ''Invoke-SIRecordSqlDb'' is not recognized")'
        $r.StoreNote | Should -Not -Match 'is not recognized'
        $r.StoreNote | Should -Match 'OPENER-REACHED srv\.test/db1' -Because 'the people picker''s store seam ran it too'
    }

    It 'STATIC: no factory loads, inside its body, a helper whose seam calls functions BY NAME (the seam would not find them later)' {
        . (Join-Path $PSScriptRoot '_EntryPointLoads.ps1')
        $files = @(Get-SIFileIndex $script:SIRoot | Where-Object { $_ -match '^(engine|container|setup|auth)/' -and $_ -like '*.ps1' })
        # functions that return seams / handles called later; a load inside them must be at file level instead. Only the
        # helpers whose seams name their functions (New-SIRecordSqlInvoke -> Invoke-SIRecordSqlDb; the collect parts'
        # manifest readers): a factory that hands its helpers over as values (${function:X}) is not this fault
        $factory = '^(New-|Add-SIJobFlowCollectParts$)'
        $byName = 'SI-RecordSql\.ps1|SI-CollectParts\.ps1'
        $bad = @(foreach ($f in $files) {
            $ast = Get-SIFileAst $script:SIRoot $f
            if ($null -eq $ast) { continue }
            foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                if ($fn.Name -notmatch $factory) { continue }
                $dots = $fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot }, $true)
                foreach ($d in $dots) {
                    # the file the load names (literally or through a variable assigned in the function)
                    $txt = $d.Extent.Text
                    if ($d.CommandElements[0] -is [System.Management.Automation.Language.VariableExpressionAst]) {
                        $vn = $d.CommandElements[0].VariablePath.UserPath
                        $asg = @($fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.Left.VariablePath.UserPath -eq $vn }, $true))
                        foreach ($a in $asg) { $txt += ' ' + $a.Extent.Text }
                    }
                    if ($txt -notmatch $byName) { continue }
                    # the nearest script block around the load: the function's own body = a load inside the factory (a load inside
                    # a script block the factory builds runs wherever that block runs -- not this fault)
                    $p = $d.Parent
                    while ($p -and -not ($p -is [System.Management.Automation.Language.ScriptBlockAst])) { $p = $p.Parent }
                    if ($p -eq $fn.Body) { '{0}:{1} {2}' -f $f, $d.Extent.StartLineNumber, $fn.Name }
                }
            }
        })
        $bad | Should -BeNullOrEmpty -Because 'a helper loaded inside a factory lives only in that call; the seam it hands back calls it later, outside'
    }
}

Describe '1. on SQL Server: the identity step writes the work rows, the background job then picks them' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:DbName = 'si_test_idb_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$($script:DbName)]"; $c.CommandTimeout = 120; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$($script:DbName);$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false"
        $script:Admin = New-Object System.Data.SqlClient.SqlConnection $script:Cs
        $script:Admin.Open()
        # the shipped DDL of the two tables (from the schema file the updater applies)
        $schema = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-data-schema.sql'))
        $ddl = @([regex]::Matches($schema, "(?s)IF OBJECT_ID\('sidata\.UserSignInMethods(Detail)?'\) IS NULL\s+CREATE TABLE .*?\n\);") | ForEach-Object { $_.Value })
        $ddl.Count | Should -Be 2
        foreach ($s in @('CREATE SCHEMA sidata') + $ddl) { $c = $script:Admin.CreateCommand(); $c.CommandText = $s; [void]$c.ExecuteNonQuery() }
    }
    AfterAll {
        if ($script:Admin) { try { $script:Admin.Dispose() } catch { } }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        try {
            $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
            $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "ALTER DATABASE [$($script:DbName)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:DbName)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        } catch { Write-Warning $_.Exception.Message }
    }
    It 'three users through the real seam (New-SISignInMethodsCache -> New-SIRecordSqlInvoke -> Invoke-SIRecordSqlDb): three work rows, the pick takes them' {
        $r = Invoke-Fresh 'cache-sql' @"
`$ErrorActionPreference = 'Continue'
function Invoke-SIShapeOfTheDiscovery {
    . '$(Q (Join-Path $script:Shared 'SI-AuthMethodsRead.ps1'))'
    . '$(Q (Join-Path $script:Shared 'SI-SignInMethodsChoice.ps1'))'
    # the job signs in with its managed identity; the test with the runner's SQL login -- nothing else is replaced
    function Get-SIObjectLedgerConnection { param(`$Server, `$Database) `$c = New-Object System.Data.SqlClient.SqlConnection '$(Q $script:Cs)'; `$c.Open(); `$c }
    `$global:SI_ProSqlServer = 'runner-sql'; `$global:SI_ProSqlDatabase = '$($script:DbName)'
    `$cache = New-SISignInMethodsCache
    `$users = @(foreach (`$i in 1..3) { [pscustomobject]@{ id = "U`$i"; userPrincipalName = "u`$i@contoso.test"; userType = 'Member'; accountEnabled = `$true } })
    `$priv = { param(`$User) `$User.id -eq 'U1' }
    `$null = Invoke-SISignInMethodsPage -Users `$users -Choice ([pscustomobject]@{ Mode = 'all'; MaxAgeDays = 90 }) -IsPrivileged `$priv -Cache `$cache
    [pscustomobject]@{ Usable = [bool]`$cache.Usable; Note = [string]`$cache.Note } | ConvertTo-Json -Compress
}
Invoke-SIShapeOfTheDiscovery
"@
        $r.Note | Should -BeNullOrEmpty -Because 'the saved detail was usable (red on 3.1.50: "not recognized")'
        $r.Usable | Should -BeTrue
        $c = $script:Admin.CreateCommand(); $c.CommandText = 'SELECT COUNT(*) FROM sidata.UserSignInMethods'
        [int]$c.ExecuteScalar() | Should -Be 3 -Because 'each user''s work row is recorded by the identity step'
        # the background job's own pick (Invoke-SISignInMethodsFill sends exactly this statement)
        . (Join-Path $script:Shared 'SI-SignInMethodsChoice.ps1')
        $now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
        $p = $script:Admin.CreateCommand(); $p.CommandText = (Get-SISignInMethodsFillPickSql)
        foreach ($kv in @{ n = '200'; maxAge = '90'; all = '1'; now = $now }.GetEnumerator()) { $x = $p.Parameters.Add('@' + $kv.Key, [System.Data.SqlDbType]::NVarChar, -1); $x.Value = [string]$kv.Value }
        $ids = New-Object System.Collections.Generic.List[string]
        $rd = $p.ExecuteReader(); try { do { while ($rd.Read()) { for ($i = 0; $i -lt $rd.FieldCount; $i++) { if ($rd.GetName($i) -eq 'UserId') { $ids.Add([string]$rd.GetValue($i)) } } } } while ($rd.NextResult()) } finally { $rd.Dispose() }
        $ids.Count | Should -BeGreaterThan 0 -Because 'the background job picks users (on 3.1.50 it picked 0: "nothing more is due")'
        $ids[0] | Should -Be 'u1' -Because 'privileged first'
        @($ids | Sort-Object) | Should -Be @('u1', 'u2', 'u3') -Because 'then the users never read'
    }
}

Describe '2. Invoke-SIGraphBatchGet: 20 per request, the sign-in methods read''s pace' {
    BeforeEach { $script:_SICache = @{}; Reset-G; $script:Slept.Clear() }
    It 'every request answered; 20 per $batch; a clean wave doubles the next (1, 2, 4, ...)' {
        $script:G.Handler = { param($u) if ($u -match '^/groups/(g\d+)/') { Ok @([pscustomobject]@{ id = "m-$($Matches[1])" }) } else { Err 400 } }
        $reqs = @(foreach ($i in 1..200) { @{ Key = "g$i"; Url = "/groups/g$i/transitiveMembers?`$select=id&`$top=999" } })
        $r = Invoke-SIGraphBatchGet -Token 't' -Requests $reqs -PostMany $script:FakePost -Sleep $script:NoSleep
        $r.Items.Count | Should -Be 200
        @($r.Items.Values | Where-Object Status -ne 200).Count | Should -Be 0
        @($r.Items['g7'].Rows)[0].id | Should -Be 'm-g7'
        $script:G.Requests | Should -Be 10 -Because '200 reads = 10 requests of 20'
        @($script:G.Bodies) | Should -Be @(1, 2, 4, 3) -Because 'the waves double while Microsoft does not ask to slow down'
        $script:Slept.Count | Should -Be 0
    }
    It 'a throttled item waits its Retry-After once and is asked again; the pace halves' {
        $script:n = 0
        $script:G.Handler = { param($u) if ($u -match 'g3/' -and $script:n -lt 1) { $script:n++; @{ status = 429; headers = [pscustomobject]@{ 'Retry-After' = '7' }; body = $null } } else { Ok @() } }
        $r = Invoke-SIGraphBatchGet -Token 't' -Requests @(foreach ($i in 1..5) { @{ Key = "g$i"; Url = "/groups/g$i/transitiveMembers" } }) -PostMany $script:FakePost -Sleep $script:NoSleep
        @($r.Items.Values | Where-Object Status -ne 200).Count | Should -Be 0
        @($script:Slept) | Should -Be @(7)
        $r.ThrottledWaves | Should -Be 1
    }
    It 'still transient after the last round: answered with its status (the caller marks what the single read marked)' {
        $script:G.Handler = { param($u) if ($u -match 'g2/') { Err 503 } else { Ok @() } }
        $r = Invoke-SIGraphBatchGet -Token 't' -Requests @(@{ Key = 'g1'; Url = '/groups/g1/x' }, @{ Key = 'g2'; Url = '/groups/g2/x' }) -PostMany $script:FakePost -Sleep $script:NoSleep -MaxRounds 5
        $r.Items['g2'].Status | Should -Be 503
        $r.Items['g1'].Status | Should -Be 200
        $script:G.Items | Should -Be 6 -Because 'g2 asked five times (the attempts of the single read), g1 once'
    }
    It 'a refusal (403) stops further requests: the reads not asked are -1, never "no rows"' {
        $script:G.Handler = { param($u) Err 403 'Authorization_RequestDenied' }
        $r = Invoke-SIGraphBatchGet -Token 't' -Requests @(foreach ($i in 1..45) { @{ Key = "g$i"; Url = "/x/g$i" } }) -PostMany $script:FakePost -Sleep $script:NoSleep -StopOnStatus @(401, 403)
        $script:G.Requests | Should -Be 1 -Because 'the first wave is one request; after the refusal nothing more is sent'
        @($r.Items.Values | Where-Object Status -eq 403).Count | Should -Be 20
        @($r.Items.Values | Where-Object Status -eq -1).Count | Should -Be 25
        $r.Items['g1'].Code | Should -Be 'Authorization_RequestDenied'
    }
    It 'an answer of more than one page is read on through Invoke-SIGraphPaged' {
        Mock Invoke-SIGraphPaged { @([pscustomobject]@{ id = 'p2-a' }, [pscustomobject]@{ id = 'p2-b' }) }
        $script:G.Handler = { param($u) @{ status = 200; body = [pscustomobject]@{ value = @([pscustomobject]@{ id = 'p1' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/groups/g1/x?$skiptoken=1' } } }
        $r = Invoke-SIGraphBatchGet -Token 't' -Requests @(@{ Key = 'g1'; Url = '/groups/g1/x' }) -PostMany $script:FakePost -Sleep $script:NoSleep
        @($r.Items['g1'].Rows | ForEach-Object id) | Should -Be @('p1', 'p2-a', 'p2-b')
        Should -Invoke Invoke-SIGraphPaged -Times 1 -Exactly -ParameterFilter { $RelativeUrl -match 'skiptoken=1' }
    }
    It 'a $filter''s spaces are sent as %20; the URL is relative to v1.0' {
        (ConvertTo-SIGraphBatchUrl "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq 'g1'") |
            Should -Be "/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId%20eq%20'g1'"
    }
}

Describe '2+3. the identity reads on the fixture of internal''s shape: the calls before and after; deleted groups are gone' {
    BeforeAll {
        # 162 groups hold an Entra role (confirmed by getByIds); 32 hold only an Azure role and were DELETED (getByIds does not
        # return them, every read of them answers 404); 14 persona groups (no role) lead into role groups through PIM
        $script:Entra = @(foreach ($i in 1..162) { 'e{0:000}' -f $i }); $script:Deleted = @(foreach ($i in 1..32) { 'd{0:000}' -f $i })
        $script:Persona = @(foreach ($i in 1..14) { 'p{0:000}' -f $i }); $script:Sps = @(foreach ($i in 1..1617) { 's{0:0000}' -f $i })
        $script:FixtureHandler = {
            param($u)
            if ($u -match '^/groups/(d\d+)/') { return (Err 404 'Request_ResourceNotFound') }
            if ($u -match '^/groups/(\w+)/transitiveMembers') { return (Ok @([pscustomobject]@{ id = "user-of-$($Matches[1])"; '@odata.type' = '#microsoft.graph.user' })) }
            if ($u -match "eligibilitySchedules\?.*groupId eq '(e(\d+))'") { $k = [int]$Matches[2]; if ($k -le 14) { return (Ok @([pscustomobject]@{ principalId = ('p{0:000}' -f $k); groupId = $Matches[1] })) }; return (Ok @()) }
            if ($u -match 'eligibilitySchedules|assignmentSchedules\?') { return (Ok @()) }
            if ($u -match 'assignmentScheduleInstances') { return (Ok @()) }
            if ($u -match '^/servicePrincipals/(s\d+)/appRoleAssignments') { if ($Matches[1] -eq 's0005') { return (Err 500) }; return (Ok @([pscustomobject]@{ resourceId = 'graph'; appRoleId = 'r1' })) }
            Err 400
        }
        # the kinds read (getByIds): every id but the deleted ones comes back
        Mock Invoke-RestMethod {
            $ids = @(($Body | ConvertFrom-Json).ids)
            [pscustomobject]@{ value = @(foreach ($i in $ids) { if ($i -notlike 'd*') { [pscustomobject]@{ id = $i; '@odata.type' = $(if ($i -like 'user*') { '#microsoft.graph.user' } else { '#microsoft.graph.group' }); displayName = $i } } }) }
        } -ParameterFilter { $Uri -like '*directoryObjects/getByIds*' }
    }
    BeforeEach { $script:_SICache = @{}; $global:SI_EntraRoleReadState = $null; Reset-G; $script:G.Handler = $script:FixtureHandler; $script:Slept.Clear(); $script:Info.Clear(); Reset-SIPermissionFetchFailures }

    It 'members, PIM for Groups, activated memberships and application permissions: one request per 20 reads; the deleted groups gone, the role read complete' {
        $roleGroups = @{}; foreach ($g in $script:Entra) { $roleGroups[$g] = @{ Permanent = @('Global Reader'); Eligible = @() } }
        $script:_SICache['GroupRoles'] = $roleGroups
        $azure = @{}; foreach ($g in $script:Deleted) { $azure[$g] = @([pscustomobject]@{ PrincipalType = 'Group'; Role = 'Reader'; Scope = '/subscriptions/s1' }) }
        Set-SIEntraRoleReadPart -Part 'GroupTypes' -Complete $true
        $priv = Get-SIPrivilegeHoldingGroupMap -RoleAssignedGroupMap $roleGroups -AzureLookup $azure
        $priv.Count | Should -Be 194
        $priv = Remove-SIGonePrivilegeGroups -Token 't' -GroupMap $priv -RoleAssignedGroupMap $roleGroups
        $priv.Count | Should -Be 162 -Because 'the 32 deleted groups an Azure role assignment still names are gone'
        $m2g = Get-SIGroupTransitiveMembers -Token 't' -RoleAssignedGroupMap $priv -PostMany $script:FakePost -Sleep $script:NoSleep 3>$null
        $pim = Get-SIPimForGroupsByPrincipal -Token 't' -RoleAssignedGroupMap $priv -PostMany $script:FakePost -Sleep $script:NoSleep 3>$null
        $groupRequests = $script:G.Requests; $groupItems = $script:G.Items
        $resolver = @{ 'graph|r1' = 'User.Read.All' }
        $perms = Get-SISPAppRoleAssignmentsMany -Token 't' -ObjectIds $script:Sps -AppRoleResolver $resolver -PostMany $script:FakePost -Sleep $script:NoSleep
        $spRequests = $script:G.Requests - $groupRequests

        # the facts are the same as the single reads gave
        $m2g.ContainsKey('user-of-e001') | Should -BeTrue
        @($pim['p001']) | Should -Be @('e001')
        @($perms['s0001']) | Should -Be @('User.Read.All')
        $perms['s0005'].Count | Should -Be 0 -Because 'a failed read is published empty...'
        @($global:SI_PermissionFetchFailures | Where-Object ObjectId -eq 's0005').Count | Should -Be 1 -Because '...and counted exactly as the single read counted it'
        (Test-SIEntraRoleReadComplete -Parts @('GroupMembers', 'PimForGroups')) | Should -BeTrue -Because 'a deleted group is gone, not a read that did not complete'
        @($script:Info | Where-Object { $_ -match 'no longer exist' }).Count | Should -Be 1 -Because 'said once'
        @($script:Info | Where-Object { $_ -match 'no longer exist' })[0] | Should -Match 'd001, d002'

        # THE CALLS. Before (3.1.50, one call per read, the deleted groups read too): 194 members + 208 x 2 schedules + 194
        # activated-membership reads + 14 persona members + 1,617 application permission reads = 2,435
        $before = 194 + (194 + 14) * 2 + 194 + 14 + 1617
        $after = $script:G.Requests
        Write-Host ('CALLS {0} before -> {1} after (groups {2} reads in {3} requests; application permissions {4} reads in {5} requests); deleted groups asked again: 0' -f $before, $after, $groupItems, $groupRequests, $script:Sps.Count, $spRequests)
        $groupItems | Should -Be (162 + (162 + 14) * 2 + 162 + 14) -Because 'the deleted groups are not read at all'
        $groupRequests | Should -Be ([Math]::Ceiling(162 / 20) + [Math]::Ceiling(162 * 2 / 20) + [Math]::Ceiling(28 / 20) + [Math]::Ceiling(14 / 20) + [Math]::Ceiling(162 / 20))
        $spRequests | Should -Be ([Math]::Ceiling(1617 / 20))
        $after | Should -BeLessThan ($before / 15)
    }
    It 'a group deleted after getByIds answered (404 on its members): gone, the read complete' {
        $roleGroups = @{ e001 = @{ Permanent = @('Global Reader'); Eligible = @() }; d001 = @{ Permanent = @('User Administrator'); Eligible = @() } }
        $null = Get-SIGroupTransitiveMembers -Token 't' -RoleAssignedGroupMap $roleGroups -PostMany $script:FakePost -Sleep $script:NoSleep 3>$null
        (Test-SIEntraRoleReadComplete -Parts @('GroupMembers')) | Should -BeTrue
        (Get-SIGoneGroupSet).Contains('d001') | Should -BeTrue
        @($script:Info | Where-Object { $_ -match 'no longer exist.*answered 404.*d001' }).Count | Should -Be 1
    }
    It 'a REAL failure still marks the read incomplete: 500, 403, and a 503 that never cleared' {
        foreach ($st in 500, 403, 503) {
            $script:_SICache = @{}; $global:SI_EntraRoleReadState = $null; Reset-G
            $script:FailStatus = $st
            $script:G.Handler = { param($u) if ($u -match 'e002/') { Err $script:FailStatus } else { Ok @() } }
            $null = Get-SIGroupTransitiveMembers -Token 't' -RoleAssignedGroupMap @{ e001 = @{ Permanent = @('x'); Eligible = @() }; e002 = @{ Permanent = @('x'); Eligible = @() } } -PostMany $script:FakePost -Sleep $script:NoSleep 3>$null
            (Test-SIEntraRoleReadComplete -Parts @('GroupMembers')) | Should -BeFalse -Because "HTTP $st is a read that did not complete"
            (Get-SIGoneGroupSet).Count | Should -Be 0
        }
    }
    It 'the kinds read failed: nothing is called gone (unknown is never gone)' {
        Mock Invoke-RestMethod { throw 'The remote server returned an error: (503) Server Unavailable.' } -ParameterFilter { $Uri -like '*directoryObjects/getByIds*' }
        $priv = Remove-SIGonePrivilegeGroups -Token 't' -GroupMap @{ d001 = @{ Permanent = @(); Eligible = @() }; e001 = @{ Permanent = @('x'); Eligible = @() } } -RoleAssignedGroupMap @{ e001 = @{} }
        $priv.Count | Should -Be 2
        (Get-SIGoneGroupSet).Count | Should -Be 0
    }
}

Describe 'wiring: both discoveries use the batched reads and take the gone groups out' {
    It 'the users and the service principals take the deleted groups out before reading them' {
        foreach ($f in 'Get-DiscoveryFromEntraUsers.ps1', 'Get-DiscoveryFromEntraServicePrincipals.ps1') {
            $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot "engine\asset-profiling\discovery\$f"))
            $t | Should -Match ([regex]::Escape('$privGroups = Remove-SIGonePrivilegeGroups -Token $token -GroupMap $privGroups -RoleAssignedGroupMap $groupRoles'))
            $t.IndexOf('Remove-SIGonePrivilegeGroups') | Should -BeLessThan $t.IndexOf('Get-SIGroupTransitiveMembers -Token')
        }
    }
    It 'the service principals'' application permissions come from one batched read, in BOTH paths (streamed pages and the whole set)' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraServicePrincipals.ps1'))
        ([regex]::Matches($t, [regex]::Escape('$spAppPerms = & $readAppPerms @('))).Count | Should -Be 2
        $t | Should -Match ([regex]::Escape('$m = Get-SISPAppRoleAssignmentsMany -Token $token -ObjectIds $ids -AppRoleResolver $appRoleResolver'))
        $t | Should -Match ([regex]::Escape('if ($null -ne $spAppPerms -and $spAppPerms.ContainsKey([string]$sp.id))'))
    }
    It 'the group reads go through the batched read, never one Invoke-SIGraphPaged per group' {
        $t = [IO.File]::ReadAllText((Join-Path $script:Shared 'IdentityRoleFetcher.ps1'))
        foreach ($fn in 'Get-SIGroupTransitiveMembers', 'Get-SIPimForGroupsByPrincipal', 'Get-SIPimGroupActivatedMemberships', 'Get-SISPAppRoleAssignmentsMany') {
            $body = [regex]::Match($t, "(?s)function $fn \{.*?\r?\n\}\r?\n").Value
            $body | Should -Match 'Invoke-SIGraphBatchGet' -Because $fn
            $body | Should -Not -Match 'Invoke-SIGraphPaged' -Because $fn
        }
    }
}
