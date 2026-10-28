#Requires -Version 5.1
<#
    A CONTAINER-HOSTED INSTALL RUNS THE CODE THE SYNC PULLED (#107).

    Operator ruling 2026-09-29: "use the same flow as PIM is doing, that is proven and works". The sync runs
    SI's deploy hook after a change; setup/Invoke-SIContainerUpdate.ps1 builds the engine image from the
    synced tree, points every SI Container Apps Job at it, verifies, and restores each changed job's previous
    image on failure. These tests run the real script end to end against a fake Azure behind SecurityInsight's own REST
    client (#521: no az CLI) -- the client's two seams (Invoke-SIAzRestRequest with a token, Invoke-SIAzRestHttp without)
    are replaced globally, so the script's REST layer (setup/_shared/SI-UpdateRest.ps1) talks to the fake; every call is
    recorded as '<METHOD> <url>'.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Updater = Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'
    . (Join-Path $script:SIRoot 'setup\_shared\SI-ContainerUpdate.ps1')

    # A fake Azure: answers the handful of calls the update makes, from $global:FakeAz state.
    function global:Invoke-SIFakeAzure {
        param([string]$Method, [string]$Uri, $Body)
        $global:AzCalls.Add(('{0} {1}' -f $Method, $Uri))
        $j = { param($o) [pscustomobject]@{ Status = 200; Content = (ConvertTo-Json -InputObject $o -Depth 10 -Compress) } }
        $jobList = { @($global:FakeAz.Jobs.GetEnumerator() | ForEach-Object {
                        $img = if ($global:FakeAz.VerifyLies -and $global:FakeAz.Patched) { 'reg.example.io/si-orchestrator:wrong' } else { $_.Value }
                        @{ name = $_.Key; properties = @{ provisioningState = 'Succeeded'; template = @{ containers = @(@{ name = 'c'; image = $img; imageType = 'ContainerImage'; env = @(@{ name = 'X'; value = '1' }) }) } } } }) }
        # regexes, not -like: in -like '?' is ANY one character, so '.../registries/acrx?*' also matched '.../registries/acrx/runs/<id>?...'
        # and answered the run-status poll with the registry (found on the test VM, 2026-10-09: the poll then waited out its 30 min)
        if ($Method -eq 'GET' -and $Uri -match '/resourceGroups/rg-x/providers/Microsoft\.ContainerRegistry/registries/acrx\?api-version=') { return (& $j @{ id = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-x/providers/Microsoft.ContainerRegistry/registries/acrx'; name = 'acrx'; properties = @{ loginServer = 'reg.example.io'; publicNetworkAccess = 'Enabled' } }) }
        # #416 (live 2026-10-06): the roll reads the jobs with the PATCH's own api-version
        if ($Method -eq 'GET' -and $Uri -match '/providers/Microsoft\.App/jobs\?api-version=') { return (& $j @{ value = @(& $jobList) }) }
        # #756: the install's SQL server with its Pro database (New-FakeState -SqlObjective), the identity's rights, the size PATCH
        if ($global:FakeAz.SqlObjective) {
            $srvId = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-x/providers/Microsoft.Sql/servers/sql-x'
            if ($Method -eq 'GET' -and $Uri -match '/resourceGroups/rg-x/providers/Microsoft\.Sql/servers\?api-version=') { return (& $j @{ value = @(@{ id = $srvId; name = 'sql-x'; properties = @{ fullyQualifiedDomainName = 'sql-x.db.example' } }) }) }
            if ($Method -eq 'GET' -and $Uri -match '/servers/sql-x/databases\?api-version=') { return (& $j @{ value = @(@{ id = "$srvId/databases/sqldb-si-pro"; name = 'sqldb-si-pro'; sku = @{ name = $global:FakeAz.SqlObjective; tier = 'Standard'; capacity = 100 }; properties = @{ currentServiceObjectiveName = $global:FakeAz.SqlObjective; maxSizeBytes = 268435456000; elasticPoolId = '' } }) }) }
            if ($Method -eq 'GET' -and $Uri -match '/servers/sql-x/providers/Microsoft\.Authorization/permissions\?') { return (& $j @{ value = @(@{ actions = @('*'); notActions = @() }) }) }
            if ($Method -eq 'PATCH' -and $Uri -match '/servers/sql-x/databases/([^?]+)\?') { $global:FakeAz.SqlPatches[$Matches[1]] = [string]$Body; return [pscustomobject]@{ Status = 202; Content = '' } }
        }
        # #416: the parallel swap -- one ARM PATCH of properties.template per job, never configuration
        if ($Method -eq 'PATCH' -and $Uri -match '/Microsoft\.App/jobs/([^?]+)\?') {
            $n = $Matches[1]; $bodyText = [string]$Body
            if ($bodyText -match '"imageType"') { return [pscustomobject]@{ Status = 400; Content = 'Bad Request: Unknown properties imageType in ContainerAppContainer are not supported' } }
            $b = $bodyText | ConvertFrom-Json
            $global:FakeAz.Bodies[$n] = $b
            if ($global:FakeAz.FailOn -eq $n) { $global:FakeAz.FailOn = ''; return [pscustomobject]@{ Status = 400; Content = ('{"error":{"code":"InvalidParameterValue","message":"the job ''' + $n + ''' refused the change"}}') } }
            $global:FakeAz.Patched = $true
            $global:FakeAz.Jobs[$n] = [string]$b.properties.template.containers[0].image
            return [pscustomobject]@{ Status = 200; Content = '' }
        }
        # the tag check: the registry's own token exchange, then the manifest
        if ($Uri -eq 'https://reg.example.io/oauth2/exchange') { return (& $j @{ refresh_token = 'r' }) }
        if ($Uri -eq 'https://reg.example.io/oauth2/token') { return (& $j @{ access_token = 'a' }) }
        if ($Method -eq 'HEAD' -and $Uri -match '^https://reg\.example\.io/v2/[^/]+/manifests/(.+)$') { return [pscustomobject]@{ Status = $(if (@($global:FakeAz.Tags) -contains $Matches[1]) { 200 } else { 404 }); Content = '' } }
        # NO test here expects a build. One that happens anyway (the tree's tag moved under the suite -- the test VM,
        # 2026-10-07: the gate's dotnet build wrote into pro-management\ beside it) FAILS AT ONCE: it used to get no run
        # id, and Wait-SIAcrBuilds polled every 15 s of real time for 30 minutes -- the batch passed its 1,200 s timeout
        if ($Uri -match '/listBuildSourceUploadUrl\?') { return (& $j @{ uploadUrl = 'https://fake-upload.example/ctx?sig=x'; relativePath = 'src/ctx.tar.gz' }) }
        if ($Method -eq 'PUT' -and $Uri -like 'https://fake-upload.example/*') { return [pscustomobject]@{ Status = 201; Content = '' } }
        if ($Uri -match '/scheduleRun\?') { return (& $j @{ runId = 'unexpectedbuild1' }) }
        if ($Method -eq 'GET' -and $Uri -match '/runs/unexpectedbuild1\?') { return (& $j @{ properties = @{ runId = 'unexpectedbuild1'; status = 'Failed' } }) }
        [pscustomobject]@{ Status = 404; Content = '{"error":{"code":"NotFound","message":"not in this fake"}}' }
    }
    function global:Invoke-SIAzRestRequest {
        param([string]$Method = 'GET', [string]$Uri, [string]$Audience = 'Arm', $Body, [string]$ContentType, [hashtable]$Headers, [switch]$AllowNotFound,
              [int[]]$AllowStatus = @(), [switch]$AsBytes, [int]$TimeoutSec, [int]$MaxAttempts, [string]$What, [hashtable]$Auth)
        if ($global:FakeAz.NotSignedIn) { throw 'No sign-in is configured for Azure access over REST: set a managed identity or SI_SPN_AppId ...' }
        $r = Invoke-SIFakeAzure -Method $Method -Uri $Uri -Body $Body
        [pscustomobject]@{ StatusCode = $r.Status; Content = $r.Content; Bytes = $null; Headers = @{}; RetryAfter = '' }
    }
    function global:Invoke-SIAzRestHttp {
        param([string]$Method, [string]$Uri, [hashtable]$Headers, $Body, [string]$ContentType, [int]$TimeoutSec = 300, [switch]$AsBytes)
        if ($Headers -and $Headers.ContainsKey('Authorization') -and $Uri -like 'https://fake-upload.example/*') { throw 'a SAS upload must never carry a bearer token' }
        $r = Invoke-SIFakeAzure -Method $Method -Uri $Uri -Body $Body
        [pscustomobject]@{ StatusCode = $r.Status; Content = $r.Content; Bytes = $null; Headers = @{}; RetryAfter = '' }
    }
    # the REST client's sign-in, as the updater left it (a recorded identity), its tokens, and no other Azure layer
    function global:Get-SIAzRestState { if (-not ($global:FakeRestState -is [hashtable])) { $global:FakeRestState = @{ Connection = @{ Mode = 'Fake' }; SubscriptionId = $null; TenantId = $null; Cache = @{} } }; $global:FakeRestState }
    function global:Get-SIAzureToken { param($Audience, $Resource, $Auth, [switch]$ForceRefresh) 'fake-token' }
    function global:Invoke-SIArm { throw 'the update does not use Invoke-SIArm' }
    function script:New-FakeState([hashtable]$Jobs, [string[]]$Tags = @(), [switch]$VerifyLies, [string]$FailOn = '', [string]$SqlObjective = '') {
        $global:AzCalls = New-Object System.Collections.Generic.List[string]
        $global:FakeAz = @{ Jobs = $Jobs; Tags = $Tags; VerifyLies = [bool]$VerifyLies; FailOn = $FailOn; Bodies = @{}; Patched = $false; SqlObjective = $SqlObjective; SqlPatches = @{} }
    }
    # every ARM call names the install's subscription in its URL (never a default context)
    function script:Get-ArmCallsOutsideSubscription { @($global:AzCalls | Where-Object { $_ -match ' https://management\.azure\.com/' -and $_ -notmatch '/subscriptions/00000000-0000-0000-0000-000000000001/' }) }
    $script:HookLibs = 'SI-ContainerUpdate.ps1', 'SI-BuildStage.ps1', 'SI-FastRoll.ps1', 'SI-ScriptRun.ps1', 'SI-UpdateRest.ps1', 'SI-AcrBuild.ps1'
    $script:Tag = Get-SIContainerImageTag -Version ((Get-Content -Raw (Join-Path $script:SIRoot 'VERSION')).Trim()) -ContentHash (Get-SIContainerContentHash -SolutionRoot $script:SIRoot)
    $script:NewImage = "reg.example.io/si-orchestrator:$($script:Tag)"
    $script:Common = @{ ResourceGroupName = 'rg-x'; AcrName = 'acrx'; SubscriptionId = '00000000-0000-0000-0000-000000000001' }
}

AfterAll {
    foreach ($f in 'Invoke-SIFakeAzure', 'Invoke-SIAzRestRequest', 'Invoke-SIAzRestHttp', 'Get-SIAzRestState', 'Get-SIAzureToken', 'Invoke-SIArm') { Remove-Item -LiteralPath ("Function:\{0}" -f $f) -ErrorAction SilentlyContinue }
    Remove-Variable -Name FakeRestState -Scope Global -ErrorAction SilentlyContinue
}

Describe 'where the container hosting is' {
    It 'nothing configured = a VM install = $null (no update, no default infrastructure)' {
        Resolve-SIContainerUpdateTarget -Globals @{} | Should -BeNullOrEmpty
    }
    It 'half configured is refused, not guessed' {
        { Resolve-SIContainerUpdateTarget -Globals @{ SI_Bootstrap_ResourceGroupName = 'rg' } } | Should -Throw '*half configured*'
    }
    It 'reads the customer''s own setup globals, parameters win, subscription falls back to the workspace id' {
        $g = @{ SI_Bootstrap_ResourceGroupName = 'rg-cfg'; SI_Bootstrap_AcrName = 'acrcfg'; SI_WorkspaceResourceId = '/subscriptions/1111/resourceGroups/r/providers/x/workspaces/w' }
        $t = Resolve-SIContainerUpdateTarget -AcrName 'acrparam' -Globals $g
        $t.ResourceGroupName | Should -Be 'rg-cfg'
        $t.AcrName | Should -Be 'acrparam'
        $t.SubscriptionId | Should -Be '1111'
    }
    It 'the updater ships no default resource names' {
        $src = Get-Content -Raw -LiteralPath $script:Updater
        $src | Should -Not -Match "\[string\]\`$(ResourceGroupName|AcrName)\s*=\s*'"
    }
}

Describe 'the image tag follows the content, not the clock' {
    It 'is v(VERSION)-(12 hex) and identical on two computations of the same tree' {
        $script:Tag | Should -Match '^v[0-9A-Za-z._-]+-[0-9a-f]{12}$'
        Get-SIContainerContentHash -SolutionRoot $script:SIRoot | Should -Be (Get-SIContainerContentHash -SolutionRoot $script:SIRoot)
    }
    It 'changes when an engine file changes, and ignores logs / customer config' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('sicu-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        try {
            New-Item -ItemType Directory -Force (Join-Path $tmp 'engine'), (Join-Path $tmp 'logs'), (Join-Path $tmp 'config') | Out-Null
            Set-Content (Join-Path $tmp 'engine\a.ps1') 'one'
            $h1 = Get-SIContainerContentHash -SolutionRoot $tmp
            Set-Content (Join-Path $tmp 'logs\run.log') 'noise'
            Set-Content (Join-Path $tmp 'config\SecurityInsight.custom.ps1') '$global:x = 1'
            Get-SIContainerContentHash -SolutionRoot $tmp | Should -Be $h1
            Set-Content (Join-Path $tmp 'engine\a.ps1') 'two'
            Get-SIContainerContentHash -SolutionRoot $tmp | Should -Not -Be $h1
        } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'build output (bin / obj / node_modules at any depth) never changes the tag -- and a clean tree hashes EXACTLY as the earlier algorithm did' {
        # the test VM, 2026-10-07: the gate's dotnet build of pro-management\ left thousands of build files in the tree and
        # every end-to-end run below hashed them all on 5.1 -- the batch passed its 1,200 s timeout
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('sicu-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        try {
            foreach ($d in 'engine\x', 'webapp\src\App', 'tests', 'docs', '.hidden') { New-Item -ItemType Directory -Force (Join-Path $tmp $d) | Out-Null }
            Set-Content (Join-Path $tmp 'engine\x\a.ps1') 'one'; Set-Content (Join-Path $tmp 'engine\x\b.yaml') 'k: v'
            Set-Content (Join-Path $tmp 'webapp\src\App\Page.cs') 'class P {}'; Set-Content (Join-Path $tmp 'VERSION') '3.0.0'
            Set-Content (Join-Path $tmp 'tests\t.ps1') 'test'; Set-Content (Join-Path $tmp 'docs\d.md') 'doc'; Set-Content (Join-Path $tmp '.hidden\h.txt') 'h'
            (Get-Item -LiteralPath (Join-Path $tmp '.hidden\h.txt') -Force).Attributes = 'Hidden'
            # the algorithm before 2026-10-07 (Get-ChildItem -Recurse -Force + Get-FileHash), on the same clean tree
            $old = {
                param($Root)
                $skip = @('logs', 'output', 'staging', 'internal', 'tests', 'docs', 'analyzer-web', '.git', 'demo')
                $root = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\', '/'); $l = New-Object System.Collections.Generic.List[string]
                foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -File -Force) {
                    $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/'
                    if ($skip -contains ($rel -split '/')[0].ToLowerInvariant()) { continue }
                    $l.Add(('{0}|{1}' -f $rel, (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash))
                }
                $a = $l.ToArray(); [Array]::Sort($a, [StringComparer]::Ordinal); $s = [System.Security.Cryptography.SHA256]::Create()
                ([BitConverter]::ToString($s.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($a -join "`n")))) -replace '-', '').ToLowerInvariant()
            }
            $h = Get-SIContainerContentHash -SolutionRoot $tmp
            $h | Should -Be (& $old $tmp)
            foreach ($b in 'webapp\src\App\bin\Release', 'webapp\src\App\obj', 'engine\x\node_modules\m', 'bin') {
                New-Item -ItemType Directory -Force (Join-Path $tmp $b) | Out-Null; Set-Content (Join-Path $tmp "$b\out.dll") 'built'
            }
            Get-SIContainerContentHash -SolutionRoot $tmp | Should -Be $h
            Set-Content (Join-Path $tmp 'webapp\src\App\Page.cs') 'class P { int x; }'
            Get-SIContainerContentHash -SolutionRoot $tmp | Should -Not -Be $h -Because 'the source next to the build output still counts'
        } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'which jobs move' {
    It 'only this registry''s si-orchestrator jobs; already-current ones are left alone' {
        $jobs = @(
            [pscustomobject]@{ Name = 'caj-si-endpoint'; Image = 'reg.example.io/si-orchestrator:old' }
            [pscustomobject]@{ Name = 'caj-si-identity'; Image = 'reg.example.io/si-orchestrator:new' }
            [pscustomobject]@{ Name = 'someone-elses';   Image = 'reg.example.io/other:1' }
            [pscustomobject]@{ Name = 'other-registry';  Image = 'elsewhere.io/si-orchestrator:old' }
        )
        $plan = @(Get-SIContainerUpdatePlan -Jobs $jobs -LoginServer 'reg.example.io' -TargetImage 'reg.example.io/si-orchestrator:new')
        ($plan | ForEach-Object { "$($_.Name)=$($_.Action)" }) -join ',' | Should -Be 'caj-si-endpoint=update,caj-si-identity=current'
    }
}

Describe 'the updater, end to end against a fake az' {
    It 'a build nobody expected fails in seconds, never a real-time wait (the fake''s 1,200 s batch on the test VM, 2026-10-07)' {
        New-FakeState -Jobs @{ 'caj-si-endpoint' = 'reg.example.io/si-orchestrator:old' } -Tags @()   # the tag is NOT in the registry
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $err = $null
        try { & $script:Updater @script:Common -Apply *> $null } catch { $err = $_ }
        $sw.Stop()
        "$err" | Should -Match 'build did not succeed \(Failed\)\. No job was changed'
        @($global:AzCalls | Where-Object { $_ -like '*scheduleRun*' }).Count | Should -BeGreaterThan 0
        @($global:AzCalls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0 -Because 'a failed build changes no job'
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 120 -Because 'no 15-second poll for 30 minutes'
    }
    It 'detect-only (the default) reports and changes nothing' {
        New-FakeState -Jobs @{ 'caj-si-endpoint' = 'reg.example.io/si-orchestrator:old' } -Tags @($script:Tag)
        & $script:Updater @script:Common *> $null
        $LASTEXITCODE | Should -Be 0
        @($global:AzCalls | Where-Object { $_ -like 'PATCH *' -or $_ -like '*scheduleRun*' }).Count | Should -Be 0
        $global:FakeAz.Jobs['caj-si-endpoint'] | Should -Be 'reg.example.io/si-orchestrator:old'
    }
    It '-Apply points every SI job at the image of this tree, verifies, and passes --subscription on every call' {
        New-FakeState -Jobs @{ 'caj-si-endpoint' = 'reg.example.io/si-orchestrator:old'; 'caj-si-risk-analysis' = 'reg.example.io/si-orchestrator:old' } -Tags @($script:Tag)
        & $script:Updater @script:Common -Apply *> $null
        $LASTEXITCODE | Should -Be 0
        $global:FakeAz.Jobs['caj-si-endpoint'] | Should -Be $script:NewImage
        $global:FakeAz.Jobs['caj-si-risk-analysis'] | Should -Be $script:NewImage
        @(Get-ArmCallsOutsideSubscription).Count | Should -Be 0
    }
    It 'a re-run with nothing changed is a no-op' {
        New-FakeState -Jobs @{ 'caj-si-endpoint' = $script:NewImage } -Tags @($script:Tag)
        & $script:Updater @script:Common -Apply *> $null
        $LASTEXITCODE | Should -Be 0
        @($global:AzCalls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
    }
    It 'a roll that fails midway restores every changed job that still runs THIS update''s image, and exits 1' {
        $jobs = [ordered]@{ 'caj-si-azure' = 'reg.example.io/si-orchestrator:old1'; 'caj-si-endpoint' = 'reg.example.io/si-orchestrator:old2' }
        New-FakeState -Jobs $jobs -Tags @($script:Tag)
        $order = @($jobs.Keys); $global:AzCalls.Clear()
        $global:FakeAz.FailOn = $order[-1]
        & $script:Updater @script:Common -Apply *> $null
        $LASTEXITCODE | Should -Be 1
        $global:FakeAz.Jobs['caj-si-azure'] | Should -Be 'reg.example.io/si-orchestrator:old1'
        $global:FakeAz.Jobs['caj-si-endpoint'] | Should -Be 'reg.example.io/si-orchestrator:old2'
    }
    It '#350: a job someone ELSE moved meanwhile is NOT rolled back over their image (found live: a manual deploy at the same minute)' {
        New-FakeState -Jobs @{ 'caj-si-endpoint' = 'reg.example.io/si-orchestrator:old1'; 'caj-si-azure' = 'reg.example.io/si-orchestrator:old2' } -Tags @($script:Tag) -VerifyLies
        & $script:Updater @script:Common -Apply *> $null
        $LASTEXITCODE | Should -Be 1
        # the fake reads every job back as a third image -- someone else's: left as it is, never reset to the old one
        @($global:AzCalls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 2   # the swap of both jobs, and NO restore
    }
    It 'the rollback plan: restore what still runs this update''s image; skip what someone else moved; restore all without a read-back' {
        $u = @([pscustomobject]@{ Name = 'a'; PreviousImage = 'r/x:1' }, [pscustomobject]@{ Name = 'b'; PreviousImage = 'r/x:2' })
        $p = @(Get-SIContainerRollbackPlan -Updated $u -NewImage 'r/x:new' -Current @{ a = 'r/x:new'; b = 'r/x:theirs' })
        ($p | ForEach-Object { "$($_.Name)=$($_.Action)" }) -join ',' | Should -Be 'a=restore,b=skip'
        @(Get-SIContainerRollbackPlan -Updated $u | Where-Object { $_.Action -eq 'restore' }).Count | Should -Be 2
    }
}

# #756 (live 2026-10-19): S2 was set, the updater found its release applied already, and the database stayed S3 -- the size
# steps ran only with a roll. -SizingOnly runs them with the code current: nothing built, nothing rolled.
Describe 'the code is current, the sizes still follow the settings (-SizingOnly, #756)' {
    BeforeEach {
        $script:PrevObjective = $env:SI_UPDATER_SQL_SERVICE_OBJECTIVE; $env:SI_UPDATER_SQL_SERVICE_OBJECTIVE = $null
        $global:SI_UpdateSqlTier = ''
    }
    AfterEach { $env:SI_UPDATER_SQL_SERVICE_OBJECTIVE = $script:PrevObjective }
    It 'current code + S2 set: the Pro database S3 -> S2 by ONE sku PATCH; no image built, no job rolled, exit 0' {
        # the jobs run another image and its tag is NOT in the registry: a roll or a build would show at once
        New-FakeState -Jobs @{ 'caj-si-endpoint' = 'reg.example.io/si-orchestrator:old' } -Tags @() -SqlObjective 'S3'
        $env:SI_UPDATER_SQL_SERVICE_OBJECTIVE = 'S2'
        $out = (& $script:Updater @script:Common -Apply -SizingOnly *>&1 | Out-String)
        $LASTEXITCODE | Should -Be 0
        @($global:FakeAz.SqlPatches.Keys) | Should -Be @('sqldb-si-pro')
        $global:FakeAz.SqlPatches['sqldb-si-pro'] | Should -BeExactly '{"sku":{"name":"S2","tier":"Standard"}}'
        $out | Should -Match 'sqldb-si-pro lowered S3 -> S2'
        $global:SI_UpdateSqlTier | Should -Match 'sqldb-si-pro lowered to S2' -Because 'the updater records this line in cfg.InstallState ''SqlTier'''
        $out | Should -Match 'the code is current -- the SQL database, job and web app sizes were checked'
        # NEGATIVE: no image is built or rolled, the registry is not even read
        @($global:AzCalls | Where-Object { $_ -match 'scheduleRun|listBuildSourceUploadUrl|/registries/|reg\.example\.io' }) | Should -BeNullOrEmpty
        $global:FakeAz.Jobs['caj-si-endpoint'] | Should -Not -Be $script:NewImage
        @($global:FakeAz.Bodies.Values | Where-Object { "$($_.properties.template.containers[0].image)" -eq $script:NewImage }) | Should -BeNullOrEmpty
        @(Get-ArmCallsOutsideSubscription).Count | Should -Be 0
    }
    It 'NEGATIVE: current code + no size set -- the S3 database is kept, nothing is sent to it' {
        New-FakeState -Jobs @{ 'caj-si-endpoint' = $script:NewImage } -Tags @($script:Tag) -SqlObjective 'S3'
        $out = (& $script:Updater @script:Common -Apply -SizingOnly *>&1 | Out-String)
        $LASTEXITCODE | Should -Be 0
        $global:FakeAz.SqlPatches.Count | Should -Be 0
        $out | Should -Match 'sqldb-si-pro stays S3'
        $global:SI_UpdateSqlTier | Should -Match 'sqldb-si-pro kept'
        @($global:AzCalls | Where-Object { $_ -match 'scheduleRun|/registries/' }) | Should -BeNullOrEmpty
    }
    It 'without -Apply it plans only: S2 set would lower, nothing is sent' {
        New-FakeState -Jobs @{ 'caj-si-endpoint' = $script:NewImage } -SqlObjective 'S3'
        $env:SI_UPDATER_SQL_SERVICE_OBJECTIVE = 'S2'
        $out = (& $script:Updater @script:Common -SizingOnly *>&1 | Out-String)
        $LASTEXITCODE | Should -Be 0
        $global:FakeAz.SqlPatches.Count | Should -Be 0
        $out | Should -Match 'would be lowered S3 -> S2'
        @($global:AzCalls | Where-Object { $_ -like 'PATCH *' }) | Should -BeNullOrEmpty
    }
    It 'every Azure call refused (no sign-in): exit 0, nothing sent -- the size check never fails the run' {
        New-FakeState -Jobs @{ 'caj-si-endpoint' = $script:NewImage } -SqlObjective 'S3'
        $global:FakeAz.NotSignedIn = $true
        $env:SI_UPDATER_SQL_SERVICE_OBJECTIVE = 'S2'
        { $script:OutNs = (& $script:Updater @script:Common -Apply -SizingOnly *>&1 | Out-String) } | Should -Not -Throw
        $LASTEXITCODE | Should -Be 0
        $global:FakeAz.SqlPatches.Count | Should -Be 0
    }
}

Describe 'setup SAVES where the containers live, so later updates find them (#166)' {
    # Until 2026-09-30 nothing wrote SI_Bootstrap_*: the hook said "no container hosting is configured",
    # exited 0, and a container install stayed on its old image forever -- with no error anywhere.

    BeforeAll {
        # Read a config file the way the hook does: dot-sourced in a child scope, only the names it needs.
        function script:Read-HostingGlobals([string]$Path) {
            & {
                . $Path
                $h = @{}
                foreach ($n in 'SI_Bootstrap_ResourceGroupName', 'SI_Bootstrap_AcrName', 'SI_Bootstrap_SubscriptionId',
                               'SI_Bootstrap_EnvName', 'SI_Bootstrap_Location', 'SI_WorkspaceResourceId', 'SI_Keep') {
                    $v = Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue
                    if ($null -ne $v) { $h[$n] = $v }
                    Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue
                }
                $h
            }
        }
        function script:New-TempDir {
            $d = Join-Path ([IO.Path]::GetTempPath()) ('si166-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -ItemType Directory -Force $d | Out-Null
            $d
        }
        # A throwaway copy of the hook, so the real config is never touched. Its own tree = its own tag.
        function script:New-HookCopy {
            $d = New-TempDir
            New-Item -ItemType Directory -Force (Join-Path $d 'setup\_shared'), (Join-Path $d 'config') | Out-Null
            Copy-Item $script:Updater (Join-Path $d 'setup\Invoke-SIContainerUpdate.ps1')
            Copy-Item (Join-Path $script:SIRoot 'setup\_shared\SI-ContainerUpdate.ps1') (Join-Path $d 'setup\_shared\')
            foreach ($lib in $script:HookLibs) { Copy-Item (Join-Path $script:SIRoot ('setup\_shared\' + $lib)) (Join-Path $d 'setup\_shared\') }
            Copy-Item (Join-Path $script:SIRoot 'VERSION') $d
            $d
        }
        $script:Keep = ('$global:SI_Keep = ' + "'yes'" + "`r`n")
    }

    It 'the block round-trips: every value reads back exactly, including a quote, and empty values are left out' {
        $rg = 'rg-o' + [char]0x27 + 'brien'
        $b = Get-SIContainerHostingBlock -SubscriptionId 'sub-1' -ResourceGroupName $rg -AcrName 'acr1' -EnvName '' -Location 'westeurope'
        $b | Should -Not -Match 'SI_Bootstrap_EnvName'
        $d = New-TempDir
        try {
            $f = Join-Path $d 'c.ps1'
            [IO.File]::WriteAllText($f, $b, [Text.UTF8Encoding]::new($true))
            $g = Read-HostingGlobals $f
            $g.SI_Bootstrap_ResourceGroupName | Should -BeExactly $rg
            $g.SI_Bootstrap_AcrName | Should -BeExactly 'acr1'
            $g.SI_Bootstrap_SubscriptionId | Should -BeExactly 'sub-1'
            $g.SI_Bootstrap_Location | Should -BeExactly 'westeurope'
        } finally { Remove-Item -Recurse -Force $d }
    }

    It 'appends to an existing config and leaves every other byte alone; a re-run replaces, never duplicates' {
        $orig = $script:Keep + "# customer comment`r`n"
        $one = Merge-SIContainerHostingBlock -Text $orig -Block (Get-SIContainerHostingBlock -SubscriptionId 's' -ResourceGroupName 'rg-a' -AcrName 'acra')
        $one.StartsWith($orig) | Should -BeTrue
        $two = Merge-SIContainerHostingBlock -Text $one -Block (Get-SIContainerHostingBlock -SubscriptionId 's' -ResourceGroupName 'rg-b' -AcrName 'acrb')
        $two.StartsWith($orig) | Should -BeTrue
        ([regex]::Matches($two, 'container hosting -- written by setup')).Count | Should -Be 1
        $two | Should -Match 'rg-b'
        $two | Should -Not -Match 'rg-a'
        (Merge-SIContainerHostingBlock -Text $two -Block (Get-SIContainerHostingBlock -SubscriptionId 's' -ResourceGroupName 'rg-b' -AcrName 'acrb')) | Should -BeExactly $two
    }

    It 'two hand-copied blocks collapse into one' {
        $b = Get-SIContainerHostingBlock -SubscriptionId 's' -ResourceGroupName 'rg-a' -AcrName 'acra'
        $twice = "x`r`n" + $b + "`r`n" + "y`r`n" + $b + "`r`n"
        $m = Merge-SIContainerHostingBlock -Text $twice -Block (Get-SIContainerHostingBlock -SubscriptionId 's' -ResourceGroupName 'rg-c' -AcrName 'acrc')
        ([regex]::Matches($m, 'container hosting -- written by setup')).Count | Should -Be 1
        $m | Should -Match '^x'
        $m | Should -Match 'y'
        $m | Should -Match 'rg-c'
    }

    It 'saving writes UTF-8 with a BOM, keeps a backup, keeps non-ASCII values, and does not rewrite an unchanged file' {
        $d = New-TempDir
        try {
            $f = Join-Path $d 'SecurityInsight.custom.ps1'
            $nonAscii = [string][char]0xE6 + [char]0xF8 + [char]0xE5
            [IO.File]::WriteAllText($f, ('$global:SI_Keep = ' + "'" + $nonAscii + "'`r`n"), [Text.UTF8Encoding]::new($true))
            $r = Save-SIContainerHostingConfig -ConfigPath $f -SubscriptionId 's' -ResourceGroupName 'rg' -AcrName 'acr'
            $r.Changed | Should -BeTrue
            Test-Path -LiteralPath $r.Backup | Should -BeTrue
            $bytes = [IO.File]::ReadAllBytes($f)
            ($bytes[0], $bytes[1], $bytes[2]) -join ',' | Should -Be '239,187,191'
            (Read-HostingGlobals $f).SI_Keep | Should -BeExactly $nonAscii
            (Save-SIContainerHostingConfig -ConfigPath $f -SubscriptionId 's' -ResourceGroupName 'rg' -AcrName 'acr').Changed | Should -BeFalse
        } finally { Remove-Item -Recurse -Force $d }
    }

    It 'END TO END: -Save once, and a later run with NO parameters finds the containers and rolls them' {
        $d = New-HookCopy
        try {
            $cfg = Join-Path $d 'config\SecurityInsight.custom.ps1'
            [IO.File]::WriteAllText($cfg, $script:Keep, [Text.UTF8Encoding]::new($true))
            $hook = Join-Path $d 'setup\Invoke-SIContainerUpdate.ps1'
            $tag  = Get-SIContainerImageTag -Version ((Get-Content -Raw (Join-Path $d 'VERSION')).Trim()) -ContentHash (Get-SIContainerContentHash -SolutionRoot $d)

            # Before: nothing saved -> the hook sees a VM install and changes nothing (the old, silent failure).
            New-FakeState -Jobs @{ 'caj-si-endpoint' = 'reg.example.io/si-orchestrator:old' } -Tags @($tag)
            & $hook -Apply *> $null
            $LASTEXITCODE | Should -Be 0
            $global:FakeAz.Jobs['caj-si-endpoint'] | Should -Be 'reg.example.io/si-orchestrator:old'

            # Once: record the containers.
            & $hook @script:Common -Save *> $null
            $LASTEXITCODE | Should -Be 0
            (Read-HostingGlobals $cfg).SI_Bootstrap_AcrName | Should -Be 'acrx'
            (Read-HostingGlobals $cfg).SI_Keep | Should -Be 'yes'

            # After: the sync's own call -- no parameters -- finds them and rolls the job.
            New-FakeState -Jobs @{ 'caj-si-endpoint' = 'reg.example.io/si-orchestrator:old' } -Tags @($tag)
            & $hook -Apply *> $null
            $LASTEXITCODE | Should -Be 0
            $global:FakeAz.Jobs['caj-si-endpoint'] | Should -Be ('reg.example.io/si-orchestrator:' + $tag)
            @(Get-ArmCallsOutsideSubscription).Count | Should -Be 0
        } finally { Remove-Item -Recurse -Force $d }
    }

    It '-Save with nothing to save is refused, not silently a no-op' {
        $d = New-HookCopy
        try {
            { & (Join-Path $d 'setup\Invoke-SIContainerUpdate.ps1') -Save *> $null } | Should -Throw '*-Save needs*'
        } finally { Remove-Item -Recurse -Force $d }
    }

    It 'WIRING: every container setup path saves -- the wizard/unattended step and the bootstrap itself' {
        foreach ($f in 'setup\ConfigWizard\backend\Initialize-SIContainerInfra.ps1', 'Bootstrap-ContainerAppJob.ps1') {
            $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot $f)
            $code = (($src -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            $code | Should -Match 'Save-SIContainerHostingConfig' -Because "$f must save the container location"
        }
    }
}

Describe 'a VM that manages container hosting: sign-in and a stable tag (#178)' {
    It 'not signed in: a clear line naming the cause, exit 1, and nothing is built or rolled' {
        New-FakeState -Jobs @{ 'caj-si-endpoint' = 'reg.example.io/si-orchestrator:old' } -Tags @($script:Tag)
        $global:FakeAz.NotSignedIn = $true
        $out = (& $script:Updater @script:Common -Apply *>&1 | Out-String)
        $LASTEXITCODE | Should -Be 1
        $out | Should -Match 'cannot reach Azure with access to subscription'
        @($global:AzCalls | Where-Object { $_ -like '*scheduleRun*' -or $_ -like 'PATCH *' }).Count | Should -Be 0
    }
    It 'the community launchers do not change the image tag (the VM sync does not carry them; a release archive does)' {
        $d = Join-Path ([IO.Path]::GetTempPath()) ('si178-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        try {
            New-Item -ItemType Directory -Force (Join-Path $d 'engine'), (Join-Path $d 'launcher\endpoint') | Out-Null
            Set-Content -LiteralPath (Join-Path $d 'engine\x.ps1') -Value 'engine'
            Set-Content -LiteralPath (Join-Path $d 'launcher\endpoint\launcher.internal-vm.ps1') -Value 'internal'
            $h1 = Get-SIContainerContentHash -SolutionRoot $d
            Set-Content -LiteralPath (Join-Path $d 'launcher\endpoint\launcher.community-vm.ps1') -Value 'community'
            Get-SIContainerContentHash -SolutionRoot $d | Should -Be $h1
            Set-Content -LiteralPath (Join-Path $d 'engine\x.ps1') -Value 'engine changed'
            Get-SIContainerContentHash -SolutionRoot $d | Should -Not -Be $h1
        } finally { Remove-Item -Recurse -Force $d }
    }
}

Describe 'container setup works in ONE subscription, named explicitly on every az call (live 2026-10-02)' {
    # Measured: setup read the Az PowerShell context (one subscription) while every az call ran unqualified against
    # az's own default (another) -- and step 0 died on `.Trim()` of an az stderr warning.
    It 'the install''s config decides: saved hosting, then SI_AzSubscriptionId, then the workspace id; the Az context last' {
        (Resolve-SIBootstrapSubscription -Globals @{ SI_Bootstrap_SubscriptionId = 'saved'; SI_AzSubscriptionId = 'cfg' } -ContextSubscriptionId 'ctx').SubscriptionId | Should -Be 'saved'
        (Resolve-SIBootstrapSubscription -Globals @{ SI_AzSubscriptionId = 'cfg' } -ContextSubscriptionId 'ctx').Source | Should -Be 'SI_AzSubscriptionId'
        (Resolve-SIBootstrapSubscription -Globals @{ SI_WorkspaceResourceId = '/subscriptions/ws-sub/resourceGroups/r/x' } -ContextSubscriptionId 'ctx').SubscriptionId | Should -Be 'ws-sub'
        (Resolve-SIBootstrapSubscription -ContextSubscriptionId 'ctx').Source | Should -Be 'the signed-in Azure context'
        (Resolve-SIBootstrapSubscription).SubscriptionId | Should -BeNullOrEmpty
    }
    It 'an explicit -SubscriptionId (the guided install''s own answer) wins over every global (live 2026-10-06: ring 1''s was used)' {
        $r = Resolve-SIBootstrapSubscription -Globals @{ SI_Bootstrap_SubscriptionId = 'saved'; SI_AzSubscriptionId = 'ring1' } -ContextSubscriptionId 'ctx' -Explicit ' mine '
        $r.SubscriptionId | Should -Be 'mine'
        $r.Source | Should -Be 'the -SubscriptionId parameter'
        $b = Get-Content -Raw (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        $b | Should -Match '\[Parameter\(\)\]\[string\]\$SubscriptionId'
        $b | Should -Match '\[Parameter\(\)\]\[string\]\$ConfigPath'
        $b | Should -Match '-ContextSubscriptionId \$azCtxSubId -Explicit \$SubscriptionId'
        $b | Should -Match '\$customFile = \$ConfigPath'
        $b | Should -Match '\$siConfig = if \(\$ConfigPath\) \{ \$customFile \}'
    }
    It 'every subscription-scoped az call gets --subscription; directory / REST / account calls do not; one already named is kept' {
        @(Add-SIAzSubscriptionArg -AzArgs @('containerapp', 'job', 'list') -SubscriptionId 's1')[-2..-1] | Should -Be @('--subscription', 's1')
        @(Add-SIAzSubscriptionArg -AzArgs @('provider', 'show', '--namespace', 'Microsoft.App') -SubscriptionId 's1') | Should -Contain '--subscription'
        foreach ($v in 'ad', 'rest', 'account') { @(Add-SIAzSubscriptionArg -AzArgs @($v, 'x') -SubscriptionId 's1') | Should -Not -Contain '--subscription' }
        @(Add-SIAzSubscriptionArg -AzArgs @('acr', 'show', '--subscription', 'mine') -SubscriptionId 's1' | Where-Object { $_ -eq '--subscription' }).Count | Should -Be 1
    }
    It 'WIRING -- setup resolves the subscription once, sets the REST sign-in to it, and every ARM call names it (#521: no az wrapper left)' {
        $b = Get-Content -Raw (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        $b | Should -Not -Match '\$subId\s*=\s*\(Get-(SISetup)?Az(ure)?Context\)\.Subscription\.Id'
        $b | Should -Match '\$subPick = Resolve-SIBootstrapSubscription'
        $b | Should -Match 'Set-SIAzContext -Subscription \$subId'
        $b | Should -Not -Match 'Invoke-Az\b|Invoke-SIAzCliJson'
        $b.IndexOf('$script:SIBootstrapSubscriptionId = $subId') | Should -BeLessThan $b.IndexOf('Get-SIResourceProvider -ProviderNamespace $rp -SubscriptionId $subId')
        $b | Should -Match 'Get-SIContainerAppJob -ResourceGroupName \$ResourceGroupName -Name \$jobName -SubscriptionId \$subId'
    }
    It 'a managed-identity job pulls AS the identity; admin credentials otherwise; a disabled admin is a clear refusal (live 2026-10-02: null-index crash)' {
        @(Get-SIRegistryPullArgs -Mode 'ManagedIdentity' -IdentityResourceId '/sub/x/uami') | Should -Be @('--registry-identity', '/sub/x/uami')
        { Get-SIRegistryPullArgs -Mode 'ManagedIdentity' -IdentityResourceId '' } | Should -Throw '*could not pull*'
        @(Get-SIRegistryPullArgs -Mode 'Secret' -AdminCredential ([pscustomobject]@{ username = 'u'; passwords = @([pscustomobject]@{ value = 'p' }) })) | Should -Be @('--registry-username', 'u', '--registry-password', 'p')
        { Get-SIRegistryPullArgs -Mode 'Secret' -AdminCredential $null -AcrName 'acr1' } | Should -Throw "*'acr1' gives no admin credentials*"
        $b = Get-Content -Raw (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        $b | Should -Not -Match "--registry-password',\`$acrPass"
        # the worker pulls with its job's arguments ($engRegistry: the collection's, or asset tagging's own identity, #236); the producer with the collection's;
        # #742: a Risk Analysis job's queue worker (caj-si-raworker-*) runs the same engine and pulls exactly as its job does
        @([regex]::Matches($b, '\+= \$registryAuthArgs')).Count | Should -Be 1
        @([regex]::Matches($b, '\+= \$engRegistry')).Count | Should -Be 2
        $b | Should -Match '\$createArgs \+= \$engRegistry'
        $b | Should -Match '\$raWorkerArgs \+= \$engRegistry'
        $b | Should -Match '\$engRegistry = if \(\$isAssetTagging\) \{ \$taggingRegistryArgs \} else \{ \$registryAuthArgs \}'
        $b | Should -Match ([regex]::Escape("`$upd['RegistryServer'] = [string]`$acr.loginServer; `$upd['RegistryIdentity'] = [string]`$engAuth.IdentityResourceId"))
        $b | Should -Match '-AcrRegistryId'
    }
}

Describe 'the hook is not killed by a config line that fails here (#182)' {
    It 'a throwing line AFTER the container settings: warned once, the containers are still found and rolled' {
        $d = Join-Path ([IO.Path]::GetTempPath()) ('si182-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        try {
            New-Item -ItemType Directory -Force (Join-Path $d 'setup\_shared'), (Join-Path $d 'config') | Out-Null
            Copy-Item $script:Updater (Join-Path $d 'setup\Invoke-SIContainerUpdate.ps1')
            Copy-Item (Join-Path $script:SIRoot 'setup\_shared\SI-ContainerUpdate.ps1') (Join-Path $d 'setup\_shared\')
            foreach ($lib in $script:HookLibs) { Copy-Item (Join-Path $script:SIRoot ('setup\_shared\' + $lib)) (Join-Path $d 'setup\_shared\') }
            Copy-Item (Join-Path $script:SIRoot 'VERSION') $d
            $cfg = (Get-SIContainerHostingBlock -SubscriptionId '00000000-0000-0000-0000-000000000001' -ResourceGroupName 'rg-x' -AcrName 'acrx') +
                   "`r`nthrow 'a Key Vault read this identity cannot make'`r`n"
            [IO.File]::WriteAllText((Join-Path $d 'config\SecurityInsight.custom.ps1'), $cfg, [Text.UTF8Encoding]::new($true))
            $tag = Get-SIContainerImageTag -Version ((Get-Content -Raw (Join-Path $d 'VERSION')).Trim()) -ContentHash (Get-SIContainerContentHash -SolutionRoot $d)
            New-FakeState -Jobs @{ 'caj-si-endpoint' = 'reg.example.io/si-orchestrator:old' } -Tags @($tag)
            $out = (& (Join-Path $d 'setup\Invoke-SIContainerUpdate.ps1') -Apply *>&1 | Out-String)
            $LASTEXITCODE | Should -Be 0
            $out | Should -Match 'did not load completely here'
            $global:FakeAz.Jobs['caj-si-endpoint'] | Should -Be ('reg.example.io/si-orchestrator:' + $tag)
        } finally { Remove-Item -Recurse -Force $d; foreach ($n in 'SI_Bootstrap_ResourceGroupName', 'SI_Bootstrap_AcrName', 'SI_Bootstrap_SubscriptionId') { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue } }
    }
    It 'the unattended sample defaults to the Community flavour (a public user never hits the internal module)' {
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'config\setup-unattended.sample.json') | ConvertFrom-Json).Flavour | Should -Be 'Community'
    }
}
