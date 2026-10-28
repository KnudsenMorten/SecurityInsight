#Requires -Version 5.1
<#
    #702 -- THE IDENTITY PRODUCER RAN OUT OF MEMORY AND NOBODY WAS TOLD (customer B, ring 2, 3.0.0.202610151701,
    2026-10-15 17:37-19:11Z; read-only from its console log).

    What the log showed, in order: "discovery streams: 26,640 users + 1,499 service principals -> 3 part(s)" (the user and
    service principal PAGES were already streamed, #475) -- then, BEFORE the first user page, the tenant-wide lookups:
    "Azure RBAC: scanning 1195 subscription(s)" and from its 6th minute 773 x "role-assignment read failed --
    OutOfMemoryException"; the Exposure Graph identity nodes (26,748 users, 19,862 groups) all failed for memory; then
    "Discovery source 'EntraUsers' threw -- OutOfMemoryException. Continuing with 0 from this source", the same for
    'EntraServicePrincipals', "RUN FAILED", the end text a blob listing's whole XML, and neither the run-health record nor
    the report to Invardia could be built.

    What these keep true (OFFLINE -- every service is a fake):
      1. MEMORY FOLLOWS A PAGE, NOT THE TENANT: the role-assignment read keeps role NAMES only, built-ins once per run (the
         full definition list per subscription was the leak -- measured below, old vs new); the Exposure Graph identity
         nodes are indexed answer by answer, at most SI_EgIdentityPageRows raw rows held (measured: the transient peak does
         not grow with the number of nodes); the service principal index and the MFA registration map are built page by
         page (nothing returned whole).
      2. a source that runs out of memory stops the collection (it is NOT COMPLETE; never "continuing with 0"); any other
         failed source marks its pulls not complete and the run goes on (Invoke-Discover) -- the Azure RBAC read
         that runs out of memory stops its source instead of trying 1,195 subscriptions.
      3. a failed blob listing is said in one short line, never with the listing; a failed run's report to Invardia is
         tried once more, smaller, when building it ran out of memory.
      4. the job-size rule reads THIS producer's out-of-memory run (an execution that failed, its run health with a start
         and no end -- or an end that says out of memory) and raises the job one band.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    foreach ($n in 'Write-SIInfo', 'Write-SIProgress', 'Reset-SIProgress', 'Write-SIWarn', 'Write-SIDiag') {
        if (-not (Get-Command -Name $n -ErrorAction SilentlyContinue)) { Set-Item -Path ("function:global:{0}" -f $n) -Value { param($Message) } }
    }
    . (Join-Path $script:SIRoot 'engine\_shared\SI-ErrorClass.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Invoke-SIPagedRest.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-JobSizing.ps1')
    function script:MemNow { [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect(); [GC]::GetTotalMemory($true) }

    # ~800 built-in role definitions as ARM returns them: each with its permission lists (the bulk of the answer)
    $defs = for ($i = 0; $i -lt 800; $i++) {
        [ordered]@{ name = ('{0:x8}-0000-4000-8000-000000000000' -f $i); id = "/providers/Microsoft.Authorization/roleDefinitions/$i"
            properties = [ordered]@{ roleName = "Role $i"; type = 'BuiltInRole'; description = ('A built-in role ' + ('d' * 120))
                assignableScopes = @('/'); permissions = @([ordered]@{ actions = @(1..25 | ForEach-Object { "Microsoft.Provider$_/resource$i/action$_/read" }); notActions = @(); dataActions = @(1..5 | ForEach-Object { "Microsoft.Data$_/x/read" }); notDataActions = @() }) } }
    }
    $script:DefsJson = ConvertTo-Json -InputObject @($defs) -Depth 8 -Compress
}

Describe '1a. the role-assignment read keeps role names only -- built-ins once per run (customer B: 1,195 subscriptions)' {
    BeforeEach { $global:SI_AzRestState = $null; $script:DefReads = 0 }
    BeforeAll {
        # a fake ARM: the definition list (fresh objects per call, like a real answer), five assignments per subscription
        Mock Invoke-SIArm {
            param($Path, $ApiVersion, [switch]$List, $Method, $Body)
            if ($Path -like '*/roleDefinitions*') {
                $script:DefReads++
                if ([uri]::UnescapeDataString($Path) -match "type eq 'CustomRole'") { return @([pscustomobject]@{ name = 'cccccccc-0000-4000-8000-000000000000'; properties = [pscustomobject]@{ roleName = 'Custom SI role'; type = 'CustomRole' } }) }
                return @(ConvertFrom-Json -InputObject $script:DefsJson)
            }
            if ($Path -like '*/roleAssignments*') {
                $sub = ($Path -split '/')[2]
                return @(for ($k = 0; $k -lt 5; $k++) { [pscustomobject]@{ id = "$Path/$k"; name = "$sub-$k"; properties = [pscustomobject]@{ scope = "/subscriptions/$sub"; principalId = "p-$k"; principalType = 'User'
                    roleDefinitionId = $(if ($k -eq 4) { '/x/roleDefinitions/cccccccc-0000-4000-8000-000000000000' } else { ('/x/roleDefinitions/{0:x8}-0000-4000-8000-000000000000' -f ($k * 7)) }) } } })
            }
            @()
        }
        Mock Resolve-SIAzRestPrincipalNames { @{} }
    }
    It 'names every role (built-in and custom) the way the full list did' {
        $a = @(Get-SIAzRoleAssignmentRest -Scope '/subscriptions/s-1')
        $a.Count | Should -Be 5
        ($a | ForEach-Object { $_.RoleDefinitionName }) -join '|' | Should -Be 'Role 0|Role 7|Role 14|Role 21|Custom SI role'
    }
    It 'MEASURED: the old per-subscription cache grows with every subscription; the names-only read stays flat (200 subscriptions)' {
        # BEFORE (the 3.0.0.202610151701 code path): the whole definition list cached per subscription scope
        $m0 = MemNow
        for ($s = 0; $s -lt 20; $s++) { $null = Get-SIAzRestRoleDefinitions -Scope "/subscriptions/old-$s" }
        $oldPerSub = ((MemNow) - $m0) / 20
        $global:SI_AzRestState = $null; $null = MemNow
        # AFTER: 200 subscriptions through the assignment read
        $script:DefReads = 0
        $m1 = MemNow
        for ($s = 0; $s -lt 200; $s++) { $null = @(Get-SIAzRoleAssignmentRest -Scope "/subscriptions/new-$s") }
        $newTotal = (MemNow) - $m1
        $reads = $script:DefReads
        Write-Host ('MEASURED role definitions: before {0:N2} MB kept PER subscription (x 1,195 at customer B = {1:N0} MB); after {2:N2} MB for 200 subscriptions ({3} definition reads: 1 built-in + 1 custom per subscription)' -f ($oldPerSub / 1MB), ($oldPerSub * 1195 / 1MB), ($newTotal / 1MB), $reads)
        $oldPerSub | Should -BeGreaterThan (1MB) -Because 'control: the old cache really held the whole list per scope'
        $newTotal | Should -BeLessThan (12MB) -Because 'names only: what stays does not grow with the definitions per subscription'
        $reads | Should -Be 201 -Because 'the built-in list is read once per run'
    }
}

Describe '1b. the Exposure Graph identity nodes are indexed answer by answer (customer B: 26,748 users + 19,862 groups)' {
    BeforeAll {
        # every answer is built FRESH (like a parsed hunting answer): the junk in rawData is the bulk nobody reads
        $script:Junk = ('j' * 12000)
        function script:New-EgRow([int]$i) {
            $oid = '{0:x8}-0000-4000-8000-{1:x12}' -f $i, $i
            [pscustomobject]@{ NodeId = "nid-$i"; NodeLabel = 'user'; NodeName = "User $i"; Categories = '["identity"]'
                EntityIds = ('["{{\"type\":\"AadObjectId\",\"id\":\"objectid={0}\"}}"]' -f $oid)
                NodeProperties = ('{{"rawData":{{"accountObjectId":"{0}","accountUpn":"user{1}@contoso.example","zzUnreadJunk":"{2}"}}}}' -f $oid, $i, $script:Junk) }
        }
        Mock Invoke-SIEgIdentityQuery {
                param($Query)
                # the memory the fetch holds while it waits for the next answer -- sampled at every query
                $now = MemNow; if ($now - $script:Base -gt $script:PeakTransient) { $script:PeakTransient = $now - $script:Base }
                if ($Query -match '\| count$') { return @{ Ok = $true; Rows = @([pscustomobject]@{ Count = $(if ($Query -match "'user'") { $script:EgN } else { 0 }) }); Error = '' } }
                if ($Query -notmatch "NodeLabel == 'user'") { return @{ Ok = $true; Rows = @(); Error = '' } }
                $n = 1; $b = 0
                if ($Query -match '_bucket = hash\(NodeId, (\d+)\) \| where _bucket == (\d+)') { $n = [int]$Matches[1]; $b = [int]$Matches[2] }
                $rows = New-Object System.Collections.Generic.List[object]
                for ($i = $b; $i -lt $script:EgN; $i += $n) { $rows.Add((New-EgRow $i)) }
                @{ Ok = $true; Rows = $rows.ToArray(); Error = '' }
        }
        function script:Invoke-EgRun([int]$N) {
            $script:EgN = $N; $script:PeakTransient = 0L; $script:Base = MemNow
            $script:_SICache = @{}
            $map = Get-SIExposureGraphIdentities 6>$null 3>$null
            $index = (MemNow) - $script:Base
            [pscustomobject]@{ Map = $map; Peak = $script:PeakTransient; Index = $index; Raw = [long]$N * ($script:Junk.Length * 2) }
        }
        $script:SavedPage = $global:SI_EgIdentityPageRows
        $global:SI_EgIdentityPageRows = 500
        # #882 (C6): the buckets go out in parallel waves through -SendMany, whose default signs in to Graph -- the seam
        # sends each query of a wave through the faked query above (never a sign-in in an offline test); free memory for
        # no more than one answer, so the waves hold one answer at a time (the memory cap the waves obey)
        $script:SIEgIdentitySendMany = { param([string[]]$qs) , @(foreach ($q in $qs) { $r = Invoke-SIEgIdentityQuery -Query $q; [pscustomobject]@{ Ok = [bool]$r.Ok; Rows = $r.Rows; Status = 200; RetryAfter = $null; Error = [string]$r.Error } }) }
        $script:SIEgIdentitySleep = { param($s) }
        $script:SIEgIdentityFreeBytes = { 0L }
    }
    AfterAll { $global:SI_EgIdentityPageRows = $script:SavedPage; $script:SIEgIdentitySendMany = $null; $script:SIEgIdentitySleep = $null; $script:SIEgIdentityFreeBytes = $null }
    It 'reads a large label in buckets of at most SI_EgIdentityPageRows and still finds every node' {
        $r = Invoke-EgRun 1800
        $r.Map.Count | Should -BeGreaterThan 1800
        foreach ($i in 0, 777, 1799) { $r.Map[('{0:x8}-0000-4000-8000-{1:x12}' -f $i, $i)].RawData.accountUpn | Should -Be "user$i@contoso.example" }
        $r.Map[('{0:x8}-0000-4000-8000-{1:x12}' -f 5, 5)].RawData.PSObject.Properties['zzUnreadJunk'] | Should -BeNullOrEmpty -Because 'the index keeps only the fields that are read'
        Should -Invoke Invoke-SIEgIdentityQuery -ParameterFilter { $Query -match 'hash\(NodeId, 4\)' } -Times 4 -Exactly
    }
    It 'MEASURED: the memory held between answers does not grow with the number of nodes (2,000 vs 8,000)' {
        $small = Invoke-EgRun 2000
        $large = Invoke-EgRun 8000
        Write-Host ('MEASURED EG identity nodes: 2,000 nodes -> {0:N1} MB held between answers, {1:N1} MB index; 8,000 nodes -> {2:N1} MB held between answers, {3:N1} MB index; the raw answers of 8,000 nodes are {4:N0} MB (the old code held them all before indexing)' -f ($small.Peak / 1MB), ($small.Index / 1MB), ($large.Peak / 1MB), ($large.Index / 1MB), ($large.Raw / 1MB))
        # between answers only the index (the trimmed entries) is held -- never the raw answers read so far
        $large.Peak | Should -BeLessThan ($large.Raw / 4) -Because 'the raw answers are let go as they are indexed'
        ($large.Peak - $large.Index) | Should -BeLessThan (24MB) -Because 'what is held beyond the index is at most one answer'
    }
}

Describe '1c. the service principal index and the MFA registration map are built page by page' {
    It 'Invoke-SIGraphPaged -OnPage hands every page over and returns nothing; the resolver is complete' {
        $script:Pg = 0
        Mock Invoke-RestMethod {
            $p = if ($Uri -match 'page=(\d+)') { [int]$Matches[1] } else { 0 }
            $script:Pg++
            $next = $null; if ($p -lt 2) { $next = "https://graph.microsoft.com/v1.0/servicePrincipals?page=$($p + 1)" }
            [pscustomobject]@{ value = @(1..3 | ForEach-Object { [pscustomobject]@{ id = "sp-$p-$_"; appId = "app-$p-$_"; displayName = "SP $p $_"; servicePrincipalType = 'Application'
                appRoles = @([pscustomobject]@{ id = "ar-$p-$_"; value = "Perm.$p.$_" }); oauth2PermissionScopes = @() } }); '@odata.nextLink' = $next }
        }
        $kept = @(Invoke-SIGraphPaged -RelativeUrl '/servicePrincipals' -Token 't' -OnPage { param($PageRows) })
        $kept.Count | Should -Be 0
        $script:_SICache = @{}
        $res = Get-SIAppRolePermissionResolver -Token 't'
        $res.Count | Should -Be 9
        $res['sp-2-3|ar-2-3'] | Should -Be 'Perm.2.3'
        (Get-SIServicePrincipalIndex).ById.Count | Should -Be 9
    }
    It 'the MFA registration rows are read with -OnPage; a pager that hands back Rows is read the same' {
        Mock Invoke-SIPagedRest {
            if ($OnPage) { & $OnPage @([pscustomobject]@{ id = 'u1'; isMfaRegistered = $true; methodsRegistered = @('fido2', 'password') }); & $OnPage @([pscustomobject]@{ id = 'u2'; isMfaRegistered = $false; methodsRegistered = @('password') }) }
            [pscustomobject]@{ Rows = @(); Complete = $true; Count = 2; Pages = 2; Error = $null }
        }
        $script:_SICache = @{}
        $m = Get-SIEntraMfaRegistrationByPrincipal -Token 't'
        $m.Count | Should -Be 2
        $m['u1'].IsMfaRegistered | Should -BeTrue; $m['u1'].MfaMethods | Should -Be @('fido2')
        $m['u2'].IsMfaRegistered | Should -BeFalse
        Should -Invoke Invoke-SIPagedRest -Times 1 -Exactly -ParameterFilter { $null -ne $OnPage }
    }
}

Describe '2. a source that cannot finish stops the collection; out of memory stops the Azure RBAC read at once' {
    BeforeAll {
        foreach ($n in 'Get-SITierFromAzureRoles', 'Get-SIAzureScopeLevel', 'Get-SIAzureScopeLabel') { if (-not (Get-Command -Name $n -ErrorAction SilentlyContinue)) { Set-Item -Path ("function:global:{0}" -f $n) -Value { 1 } } }
    }
    BeforeEach {
        Mock Get-SIAzSubscription { 1..50 | ForEach-Object { [pscustomobject]@{ Id = "s-$_"; Name = "Azure for Students $_"; State = 'Enabled' } } }
        Mock Set-SIAzContext { }
    }
    It 'the Azure RBAC read that runs out of memory throws (its source fails) instead of trying every subscription' {
        $script:Reads = 0
        Mock Get-SIAzRoleAssignment { $script:Reads++; if ($script:Reads -ge 3) { throw (New-Object System.OutOfMemoryException) }; @() }
        $script:_SICache = @{}
        { Get-SIAzureDelegationsByPrincipal 3>$null } | Should -Throw '*ran out of memory*subscription Azure for Students 3 (3 of 50)*'
        $script:Reads | Should -Be 3
    }
    It 'any other failed subscription is said, counted and summed up as UNKNOWN -- the read goes on' {
        $script:Reads = 0
        Mock Get-SIAzRoleAssignment { $script:Reads++; if ($script:Reads -eq 2) { throw 'HTTP 403 AuthorizationFailed' }; @() }
        $script:_SICache = @{}
        $null = Get-SIAzureDelegationsByPrincipal -WarningVariable w -WarningAction SilentlyContinue
        $script:Reads | Should -Be 50
        (@($w) -join "`n") | Should -Match '1 of 50 subscription\(s\) could not be read.*UNKNOWN this run, not absent'
    }
}

Describe '3. the blob listing is parsed as XML and a failure is one short line' {
    It 'parses the listing (with a byte-order mark) and follows the marker' {
        Mock Invoke-SIStorageRequest {
            if ($Uri -match 'marker=m2') { return [pscustomobject]@{ Content = '<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs><Blob><Name>b</Name><Properties><Content-Length>2</Content-Length></Properties></Blob></Blobs><NextMarker /></EnumerationResults>' } }
            [pscustomobject]@{ Content = ([char]0xFEFF + '<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs><Blob><Name>a</Name><Properties><Content-Length>1</Content-Length></Properties></Blob></Blobs><NextMarker>m2</NextMarker></EnumerationResults>') }
        }
        (@(Get-SIBlobList -Account 'st' -Container 'sistaging' -Prefix 'staging/') | ForEach-Object { '{0}:{1}' -f $_.Name, $_.Length }) -join ',' | Should -Be 'a:1,b:2'
    }
    It 'a listing that cannot be read says so in one short line -- never the listing itself (customer B: the whole XML was the end text)' {
        $big = '<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="https://st.blob.core.windows.net/" ContainerName="sistaging"><Blobs>' + ('<Blob><Name>staging/x</Name></Blob>' * 3000) + '<Blob><Name>broken'
        Mock Invoke-SIStorageRequest { [pscustomobject]@{ Content = $big } }
        $msg = $null; try { $null = Get-SIBlobList -Account 'st' -Container 'sistaging' -Prefix 'staging/run/DiscoverRouted/replica-002/' } catch { $msg = $_.Exception.Message }
        $msg | Should -Match "^The blob list of 'sistaging' \(prefix 'staging/run/DiscoverRouted/replica-002/'\) could not be read: "
        $msg.Length | Should -BeLessThan 600
        $msg | Should -Not -Match '<Blob>|staging/x|ServiceEndpoint=' -Because 'the parser''s own reason, never the listing'
    }
}

Describe '3b. the report to Invardia is tried once more, smaller, when building it ran out of memory' {
    BeforeAll {
        $script:SavedEp = $env:SI_TELEMETRY_ENDPOINT; $env:SI_TELEMETRY_ENDPOINT = 'https://127.0.0.1:9/api/uplink/v1/report'
        . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    }
    AfterAll { $env:SI_TELEMETRY_ENDPOINT = $script:SavedEp; $global:SI_TelemetryHalted = $false; $global:SI_TelemetryWarned = $false }
    It 'first try out of memory -> a second try without the heartbeat sends the run report' {
        $global:SI_TelemetryHalted = $false; $global:SI_TelemetryWarned = $false; $script:SITelemetryOomRetried = $false
        $ctx = [pscustomobject]@{ Mode = 'anonymous'; Endpoint = 'https://stub.example.test/report'; AccessCode = 'invardia-community-telemetry-v1'; Edition = 'community'; LicenceState = 'none'
                                  Version = '3.0.0'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = '0f3c9a2e-5b7d-4c1a-9e8f-1a2b3c4d5e6f'; TenantId = ''; StateDirectory = (Join-Path $TestDrive 'tel') }
        $script:Kinds = New-Object System.Collections.Generic.List[string]; $script:Tries = 0
        $tr = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $script:Tries++; if ($script:Tries -eq 1) { throw (New-Object System.OutOfMemoryException) }; $script:Kinds.Add([string]$Record.Kind); [pscustomobject]@{ Status = 'ok' } }
        $rc = [pscustomobject]@{ RunId = 'r1'; Engine = 'identity'; ShardIndex = 0; ShardCount = 1; StartedAt = [datetime]'2026-10-15T17:37:50Z'; CollectionTime = [datetime]'2026-10-15T17:37:50Z' }
        $r = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'error' -ErrorMessage "The discovery source 'EntraUsers' did not complete (si-col-0501: out of memory)" -Context $ctx -Transport $tr -Now ([datetime]'2026-10-15T19:11:44Z') -WarningAction SilentlyContinue
        $r.Status | Should -Be 'ok'
        @($script:Kinds) | Should -Be @('run') -Because 'the second try is the run report alone'
    }
    It 'a second out of memory gives up with si-upl-0601 in the result, never a throw' {
        $global:SI_TelemetryHalted = $false; $global:SI_TelemetryWarned = $false; $script:SITelemetryOomRetried = $false
        $ctx = [pscustomobject]@{ Mode = 'anonymous'; Endpoint = 'https://stub.example.test/report'; AccessCode = 'invardia-community-telemetry-v1'; Edition = 'community'; LicenceState = 'none'
                                  Version = '3.0.0'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = '0f3c9a2e-5b7d-4c1a-9e8f-1a2b3c4d5e6f'; TenantId = ''; StateDirectory = (Join-Path $TestDrive 'tel2') }
        $tr = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) throw (New-Object System.OutOfMemoryException) }
        $rc = [pscustomobject]@{ RunId = 'r2'; Engine = 'identity'; ShardIndex = 0; ShardCount = 1; StartedAt = [datetime]'2026-10-15T17:37:50Z'; CollectionTime = [datetime]'2026-10-15T17:37:50Z' }
        $r = $null
        { $script:r = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'error' -ErrorMessage 'x' -Context $ctx -Transport $tr -WarningVariable w -WarningAction SilentlyContinue } | Should -Not -Throw
        $script:r.Status | Should -Be 'error'
        $script:r.Reason | Should -Match '^si-upl-0601: '
    }
    It 'GUARD: a failed engine run lets go of its caches before its end record and report are built' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1'))
        $i = $src.IndexOf("if (`$exitReason -eq 'error') {"); $j = $src.IndexOf('$script:_SICache.Clear()'); $k = $src.IndexOf("-Phase 'End'")
        ($i -gt 0 -and $j -gt $i -and $k -gt $j) | Should -BeTrue
    }
}

Describe '4. the job-size rule reads this producer''s out-of-memory run' {
    BeforeAll {
        $script:Exec = @([pscustomobject]@{ name = 'caj-si-identity-producer-rp7kefm'; properties = [pscustomobject]@{ status = 'Failed'; startTime = '2026-10-15T17:37:32Z'; endTime = '2026-10-15T19:12:30Z' } })
    }
    It 'the producer job is sized as identity, role producer' {
        $e = Get-SIJobSizingEngine -JobName 'caj-si-identity-producer'
        ($e.Engine, $e.Role) | Should -Be @('identity', 'producer')
    }
    It 'customer B as it happened: a start, no end (the end record could not be saved) -> out of memory' {
        $rh = @([pscustomobject]@{ TimeGenerated = '2026-10-15T17:37:54Z'; Engine = 'identity'; Phase = 'Start'; ExitReason = ''; ErrorMessage = '' })
        $f = Get-SIJobFailureSignal -JobName 'caj-si-identity-producer' -Engine 'identity' -ReplicaTimeout 14400 -Executions $script:Exec -RunHealthRows $rh
        $f.Kind | Should -Be 'oom'
    }
    It 'customer B after this fix: the end record is saved and says out of memory -> out of memory' {
        $rh = @([pscustomobject]@{ TimeGenerated = '2026-10-15T17:37:54Z'; Engine = 'identity'; Phase = 'Start'; ExitReason = ''; ErrorMessage = '' }
                [pscustomobject]@{ TimeGenerated = '2026-10-15T19:11:45Z'; Engine = 'identity'; Phase = 'End'; ExitReason = 'error'; ErrorMessage = "The discovery source 'EntraUsers' did not complete (si-col-0501: out of memory) -- this identity collection is NOT COMPLETE" })
        $f = Get-SIJobFailureSignal -JobName 'caj-si-identity-producer' -Engine 'identity' -ReplicaTimeout 14400 -Executions $script:Exec -RunHealthRows $rh
        $f.Kind | Should -Be 'oom'
        $f.Reason | Should -Match 'ended out of memory'
    }
}
