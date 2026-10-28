#Requires -Version 5.1
<#
    SecurityInsight -- THE RING ON EVERY REPORT and THE SETUP REPORT (framework §8.4 / §8.7, #491).

    What must hold:
      - every heartbeat and run report carries `Ring`, resolved in the order the web app's header uses: the updater's ring
        (this process) > the updater's recorded state (cfg.InstallState 'UpdateState') > the ring recorded for the install
        (cfg.InstallState 'Ring') > SI_UpdateRing > (Community) config\update.custom.json. Not known = no Ring field;
      - the Pro settings layer reads the two rows on its open connection; the updater and the guided install hand in
        their own ring;
      - config\setup-catalog.locked.json is the closed list in the shape Invardia imports ({ steps, findings, controls },
        stable lower-case ids, title / why / fix, enum + critical on controls), with the framework minimum in it;
      - the setup report (Kind = setup) sends by DEFAULT every catalog control ('all', owner 2026-10-18); refused, it goes again ONCE with only the minimum ids --
        the ones Invardia's closed list holds today (an unknown id rejects the whole report); 'minimum' sends only those;
        'off' and anonymous installs send none; `value` only on enum controls and only one of their values;
      - the release hands the list over as <handover>\docs\securityinsight\<version>\setup-catalog.json.
    Nothing here contacts Invardia: every send goes to a stub transport.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:SavedEndpointEnv = $env:SI_TELEMETRY_ENDPOINT
    $env:SI_TELEMETRY_ENDPOINT = 'https://127.0.0.1:9/api/uplink/v1/report'
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')

    # Invardia's closed list as it stands (data/setup/securityinsight.json, the framework seed) -- the ONLY ids a default
    # setup report may carry.
    $script:InvardiaMinimum = @('updater-deployed', 'updater-schedule', 'update-ring', 'uplink-key', 'licence-valid', 'mail-sender',
                                'alert-recipients', 'identity-permissions', 'last-run-24h', 'backup-configured', 'update-pinned')
    $script:EnumControls = @{ 'updater-schedule' = @('enabled', 'disabled'); 'update-ring' = @('1', '2', '3'); 'update-pinned' = @('no', 'yes') }
    # Every id SecurityInsight has ever handed over. An id is NEVER removed (an older install may still send it): one that
    # is no longer used stays in the catalog with "retired": true. Add new ids here; never delete one.
    $script:KnownIds = @($script:InvardiaMinimum) + @('sql-reachable', 'job-layout', 'run-limits', 'last-pipeline-run', 'sources-returned-rows',
                                                       'last-ci-build', 'la-ingestion', 'licence-edition', 'secret-handover')
    # Invardia's validator (packages/core/src/uplink.ts SETUP_FIELDS): the only fields a setup report may carry.
    $script:SetupFields = @('Schema', 'Kind', 'Product', 'Version', 'Ring', 'Edition', 'LastSeenUtc', 'GetStarted', 'Findings', 'Permissions', 'MissingIds', 'Controls')
    $script:Catalog = Get-SISetupCatalog -SIRoot $script:SIRoot

    function script:New-Ctx([string]$Mode = 'identified', [string]$Dir, $Ring = $null) {
        [pscustomobject]@{ Mode = $Mode; Endpoint = 'https://stub.example.test/report'
                           AccessCode = $(if ($Mode -eq 'anonymous') { 'invardia-community-telemetry-v1' } else { 'inv-TESTKEYabcdefghijklmnopqrstuvwxyz' })
                           Edition = $(if ($Mode -eq 'anonymous') { 'community' } else { 'pro' }); LicenceState = $(if ($Mode -eq 'anonymous') { 'none' } else { 'valid' })
                           Version = '3.0.0'; Hosting = 'container'; RuntimeIdentity = 'mi-container'
                           InstallId = $(if ($Mode -eq 'anonymous') { '0f3c9a2e-5b7d-4c1a-9e8f-1a2b3c4d5e6f' } else { '' })
                           TenantId = $(if ($Mode -eq 'anonymous') { '' } else { '7f3e2a10-4b5c-4d6e-8f90-a1b2c3d4e5f6' }); StateDirectory = $Dir
                           Ring = $Ring; RingSource = $(if ($null -ne $Ring) { 'setting' } else { '' }) }
    }
    function script:New-RunCtx([string]$Engine = 'endpoint') {
        [pscustomobject]@{ RunId = [guid]::NewGuid().ToString(); Engine = $Engine; ShardIndex = 0; ShardCount = 1; StartedAt = [datetime]'2026-10-09T06:00:00Z' }
    }
    $script:Posts = New-Object System.Collections.Generic.List[object]
    $script:StubOk = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $script:Posts.Add($Record); [pscustomobject]@{ Status = 'ok'; Reason = 'accepted' } }
    function script:Reset-Telemetry {
        $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_TelemetryContext = $null; $global:SI_Telemetry_Enabled = $null
        $global:SI_Telemetry_SetupControls = $null; $global:SI_InstallRingFacts = $null; $script:Posts.Clear()
    }
    $script:Now = [datetime]'2026-10-09T07:00:00Z'
    $script:StateCompact = '{"source":"invardia","lastCheckUtc":"2026-10-09T02:00:00Z","code":{"version":"3.0.10","sequence":12,"ring":2,"action":"current","applied":12,"hold":""},"error":""}'
    $script:InstallRow = '{"ring":1,"channel":"invardia","setBy":"bootstrap","source":"setting","setAt":"2026-10-05T10:00:00Z"}'
}

AfterAll {
    $env:SI_TELEMETRY_ENDPOINT = $script:SavedEndpointEnv
    $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_TelemetryContext = $null; $global:SI_Telemetry_Enabled = $null
    $global:SI_Telemetry_SetupControls = $null; $global:SI_InstallRingFacts = $null
}

Describe 'the ring every report carries: its sources and their order' {
    It 'the updater''s ring > the updater''s state > the ring recorded for the install > SI_UpdateRing > Community''s file' {
        $r = Resolve-SIReportedRing -UpdaterRing 3 -UpdateStateJson $script:StateCompact -InstallRingJson $script:InstallRow -Setting 1 -CommunityRing 2
        $r.Ring | Should -Be 3; $r.Source | Should -Be 'updater'
        $r = Resolve-SIReportedRing -UpdaterRing $null -UpdateStateJson $script:StateCompact -InstallRingJson $script:InstallRow -Setting 3
        $r.Ring | Should -Be 2; $r.Source | Should -Be 'updater-state'
        $r = Resolve-SIReportedRing -UpdateStateJson '' -InstallRingJson $script:InstallRow -Setting 3
        $r.Ring | Should -Be 1; $r.Source | Should -Be 'install'
        $r = Resolve-SIReportedRing -UpdateStateJson '' -InstallRingJson '' -Setting '3'
        $r.Ring | Should -Be 3; $r.Source | Should -Be 'setting'
        $r = Resolve-SIReportedRing -CommunityRing 2
        $r.Ring | Should -Be 2; $r.Source | Should -Be 'community'
        $r = Resolve-SIReportedRing
        $r.Ring | Should -BeNullOrEmpty; $r.Source | Should -Be ''
    }
    It 'a value that is not a ring is skipped, never guessed: the next source answers' {
        (Resolve-SIReportedRing -UpdaterRing 'seven' -UpdateStateJson 'not json' -InstallRingJson '{"ring":9}' -Setting 2).Ring | Should -Be 2
        (Resolve-SIReportedRing -Setting 'x').Ring | Should -BeNullOrEmpty
    }
    It 'reads the updater''s state in both forms: the compact database row and the full Key Vault state; code before templates' {
        Get-SIRingFromUpdateState -Json $script:StateCompact | Should -Be 2
        Get-SIRingFromUpdateState -Json '{"code":{"lastRing":3,"appliedRing":1}}' | Should -Be 3
        Get-SIRingFromUpdateState -Json '{"code":{"lastRing":null,"appliedRing":1}}' | Should -Be 1
        Get-SIRingFromUpdateState -Json '{"templates":{"ring":1}}' | Should -Be 1
        Get-SIRingFromUpdateState -Json '{"source":"invardia","error":""}' | Should -BeNullOrEmpty
    }
    It 'the telemetry context carries the ring from the facts the settings layer read, else the setting' {
        $ctx = Get-SITelemetryContext -License $null -InstallKey '' -StateDirectory (Join-Path $TestDrive 'c1') -GetEnv { param($n) $null } -Version '3.0.0' `
                  -RingFacts ([pscustomobject]@{ UpdateState = ''; Ring = $script:InstallRow }) -RingSetting 3
        $ctx.Ring | Should -Be 1; $ctx.RingSource | Should -Be 'install'
        $ctx = Get-SITelemetryContext -License $null -InstallKey '' -StateDirectory (Join-Path $TestDrive 'c2') -GetEnv { param($n) $null } -Version '3.0.0' -RingFacts $null -RingSetting 2
        $ctx.Ring | Should -Be 2; $ctx.RingSource | Should -Be 'setting'
        $ctx = Get-SITelemetryContext -License $null -InstallKey '' -StateDirectory (Join-Path $TestDrive 'c3') -GetEnv { param($n) $null } -Version '3.0.0' -UpdaterRing 3 -RingFacts $null -RingSetting 2
        $ctx.Ring | Should -Be 3; $ctx.RingSource | Should -Be 'updater'
    }
    It 'the defaults: $global:SI_InstallRingFacts (set at run start) before $global:SI_UpdateRing' {
        $savedF = $global:SI_InstallRingFacts; $savedS = $global:SI_UpdateRing
        try {
            $global:SI_InstallRingFacts = [pscustomobject]@{ UpdateState = $script:StateCompact; Ring = '' }; $global:SI_UpdateRing = 3
            (Get-SITelemetryRing -Edition pro).Ring | Should -Be 2
            $global:SI_InstallRingFacts = $null
            (Get-SITelemetryRing -Edition pro).Ring | Should -Be 3
        } finally { $global:SI_InstallRingFacts = $savedF; $global:SI_UpdateRing = $savedS }
    }
}

Describe 'the ring on the wire: every heartbeat and every run report' {
    BeforeEach { Reset-Telemetry }
    It 'identified (Pro): the heartbeat and the run report both carry Ring' {
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context (New-Ctx identified (Join-Path $TestDrive 'w1') 2) -Transport $script:StubOk -Now $script:Now -HeartbeatCounts { @{} }
        $hb = @($script:Posts | Where-Object { $_.Kind -eq 'heartbeat' }); $run = @($script:Posts | Where-Object { $_.Kind -eq 'run' })
        $hb.Count | Should -Be 1; $run.Count | Should -Be 1
        $hb[0].Ring | Should -Be 2; $run[0].Ring | Should -Be 2
        $hb[0].Ring | Should -BeOfType [int]
    }
    It 'anonymous (Community): the ring is sent too -- it identifies nothing' {
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'error' -ErrorMessage 'x' -Context (New-Ctx anonymous (Join-Path $TestDrive 'w2') 3) -Transport $script:StubOk -Now $script:Now
        foreach ($p in $script:Posts) { $p.Ring | Should -Be 3 -Because $p.Kind }
    }
    It 'a failure outside an engine run (the updater) carries the ring as well' {
        $null = Send-SITelemetryFailure -Job updater -Step 'roll' -ErrorMessage 'x' -Context (New-Ctx identified (Join-Path $TestDrive 'w3') 1) -Transport $script:StubOk -Now $script:Now
        $script:Posts[0].Ring | Should -Be 1
    }
    It 'no ring known: the field is left out, never sent empty or as 0' {
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context (New-Ctx anonymous (Join-Path $TestDrive 'w4')) -Transport $script:StubOk -Now $script:Now
        foreach ($p in $script:Posts) { @($p.PSObject.Properties.Name) | Should -Not -Contain 'Ring' }
    }
}

Describe 'the ring is wired where it is known (not only computed)' {
    It 'the guided install hands in the ring the wizard chose' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')) | Should -Match ([regex]::Escape("`$ringArg.UpdaterRing = `$Ctx.Values['updateRing']"))
    }
    It 'the base of every report (heartbeat and run) takes the context''s ring' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')) | Should -Match ([regex]::Escape("Ring = `$(if (`$Context.PSObject.Properties['Ring']) { `$Context.Ring } else { `$null })"))
    }
}

Describe 'the closed setup lists (config\setup-catalog.locked.json)' {
    It 'has the shape Invardia imports: product, steps / findings / controls lists, nothing else but a note' {
        @($script:Catalog.PSObject.Properties.Name | Where-Object { $_ -notin @('product', 'steps', 'findings', 'controls', '_note', '$schema') }) | Should -BeNullOrEmpty
        $script:Catalog.product | Should -Be 'securityinsight'
        foreach ($l in 'steps', 'findings', 'controls') { ($script:Catalog.$l -is [array]) | Should -BeTrue -Because $l }
    }
    It 'every item: a stable lower-case id (once), title / why / fix, only the fields its list allows' {
        $allowed = @{ steps = @('id', 'title', 'why', 'fix', 'docUrl', 'required', 'retired'); findings = @('id', 'title', 'why', 'fix', 'docUrl', 'productDefect', 'retired')
                      controls = @('id', 'title', 'why', 'fix', 'docUrl', 'enum', 'critical', 'retired') }
        foreach ($l in 'steps', 'findings', 'controls') {
            $seen = @{}
            foreach ($x in @($script:Catalog.$l)) {
                $x.id | Should -MatchExactly '^[a-z0-9][a-z0-9.-]{0,59}$'
                $seen.ContainsKey($x.id) | Should -BeFalse -Because "$l '$($x.id)' twice"; $seen[$x.id] = 1
                foreach ($k in 'title', 'why', 'fix') { "$($x.$k)".Trim() | Should -Not -BeNullOrEmpty -Because "$l '$($x.id)' $k"; "$($x.$k)".Length | Should -BeLessOrEqual 600 }
                foreach ($k in $x.PSObject.Properties.Name) { $allowed[$l] | Should -Contain $k -Because "$l '$($x.id)'" }
                if ($x.PSObject.Properties['docUrl']) { $x.docUrl | Should -Match '^https://' }
                if ($l -eq 'steps') { $x.required | Should -BeOfType [bool] }
                if ($l -eq 'controls' -and $x.PSObject.Properties['enum']) {
                    @($x.enum).Count | Should -BeGreaterThan 0; @($x.enum).Count | Should -BeLessOrEqual 10
                    foreach ($v in $x.enum) { $v | Should -MatchExactly '^[a-z0-9][a-z0-9.-]{0,29}$' }
                }
            }
        }
    }
    It 'carries the framework''s minimum control set, with the enums Invardia declared for ring, schedule and pin' {
        $ids = @($script:Catalog.controls | ForEach-Object { $_.id })
        foreach ($m in $script:InvardiaMinimum) { $ids | Should -Contain $m }
        foreach ($k in $script:EnumControls.Keys) {
            $c = @($script:Catalog.controls | Where-Object { $_.id -eq $k })[0]
            (@($c.enum) -join ',') | Should -Be ($script:EnumControls[$k] -join ',') -Because $k
        }
        (@($script:Catalog.controls | Where-Object { $_.id -eq 'update-pinned' })[0]).critical | Should -BeFalse
    }
    It 'carries SI''s extras: SQL, job layout, run limits, last daily run, data sources, last CI build, LA ingestion, licence' {
        $ids = @($script:Catalog.controls | ForEach-Object { $_.id })
        foreach ($x in 'sql-reachable', 'job-layout', 'run-limits', 'last-pipeline-run', 'sources-returned-rows', 'last-ci-build', 'la-ingestion', 'licence-edition', 'secret-handover') { $ids | Should -Contain $x }
    }
    It 'ids are STABLE: every id ever handed over is still in the catalog (a dropped one is marked retired, never removed), and every id is known here' {
        $ids = @(@($script:Catalog.steps) + @($script:Catalog.findings) + @($script:Catalog.controls) | ForEach-Object { $_.id })
        foreach ($k in $script:KnownIds) { $ids | Should -Contain $k -Because "$k was handed over to Invardia -- mark it retired instead" }
        foreach ($i in $ids) { $script:KnownIds | Should -Contain $i -Because "a new id '$i': add it to KnownIds in this test (and it is never removed again)" }
    }
    It 'the code''s minimum list is exactly Invardia''s closed list today' {
        (@(Get-SISetupMinimumControlIds) -join ',') | Should -Be ($script:InvardiaMinimum -join ',')
    }
    It 'the hand-over file: { product, version, steps, findings, controls } with the released version -- nothing else' {
        $h = ConvertTo-SISetupCatalogHandover -Catalog $script:Catalog -Version '3.0.42' | ConvertFrom-Json
        (@($h.PSObject.Properties.Name) -join ',') | Should -Be 'product,version,steps,findings,controls'
        $h.product | Should -Be 'securityinsight'; $h.version | Should -Be '3.0.42'
        @($h.controls).Count | Should -Be @($script:Catalog.controls).Count
        ($h.steps -is [array]) | Should -BeTrue
    }
}

Describe 'the setup report (Kind = setup): which controls it sends' {
    BeforeEach { Reset-Telemetry }
    It 'scope minimum (the builder''s own default) = only the framework minimum ids -- exactly Invardia''s closed list, every one of them, nothing else' {
        $states = @{ 'update-ring' = @{ State = 'ok'; Value = '2' }; 'sql-reachable' = @{ State = 'ok' }; 'made-up' = @{ State = 'ok' } }
        $r = New-SISetupReport -Context (New-Ctx identified 'x' 2) -Catalog $script:Catalog -States $states -Now $script:Now
        $ids = @($r.Controls | ForEach-Object { $_.id })
        (@($ids | Sort-Object) -join ',') | Should -Be (@($script:InvardiaMinimum | Sort-Object) -join ',')
        $ids | Should -Not -Contain 'sql-reachable'; $ids | Should -Not -Contain 'made-up'
    }
    It 'the scope setting: not set / unknown = all (the default, owner 2026-10-18); minimum = the shared list only; off = no report' {
        Resolve-SISetupControlScope -Value $null | Should -Be 'all'
        Resolve-SISetupControlScope -Value 'nonsense' | Should -Be 'all'
        Resolve-SISetupControlScope -Value 'ALL' | Should -Be 'all'
        Resolve-SISetupControlScope -Value 'off' | Should -Be 'off'
        Resolve-SISetupControlScope -Value '$false' | Should -Be 'off'
        $all = New-SISetupReport -Context (New-Ctx identified 'x' 2) -Catalog $script:Catalog -Scope all -Now $script:Now
        @($all.Controls).Count | Should -Be @($script:Catalog.controls | Where-Object { -not ($_.PSObject.Properties['retired'] -and $_.retired) }).Count
        @($all.Controls | ForEach-Object { $_.id }) | Should -Contain 'sql-reachable'
        New-SISetupReport -Context (New-Ctx identified 'x' 2) -Catalog $script:Catalog -Scope off -Now $script:Now | Should -BeNullOrEmpty
    }
    It 'an anonymous install never sends a setup report' {
        New-SISetupReport -Context (New-Ctx anonymous 'x' 2) -Catalog $script:Catalog -Now $script:Now | Should -BeNullOrEmpty
    }
    It 'every control is reported: one without a state is unknown, a bad state is unknown; value only on enum controls and only a declared value' {
        $states = @{ 'update-ring' = @{ State = 'ok'; Value = '0' }; 'updater-schedule' = @{ State = 'ok'; Value = 'enabled' }; 'uplink-key' = @{ State = 'ok'; Value = 'inv-secret' }
                     'licence-valid' = @{ State = 'great' } }
        $r = New-SISetupReport -Context (New-Ctx identified 'x' 0) -Catalog $script:Catalog -States $states -Now $script:Now
        $by = @{}; foreach ($c in $r.Controls) { $by[$c.id] = $c }
        $by['update-ring'].state | Should -Be 'ok'; @($by['update-ring'].PSObject.Properties.Name) | Should -Not -Contain 'value' -Because 'ring 0 is not in 1|2|3'
        $by['updater-schedule'].value | Should -Be 'enabled'
        @($by['uplink-key'].PSObject.Properties.Name) | Should -Not -Contain 'value' -Because 'not an enum control -- and never a key'
        $by['licence-valid'].state | Should -Be 'unknown'
        $by['backup-configured'].state | Should -Be 'unknown'
        foreach ($c in $r.Controls) {
            $c.state | Should -BeIn @('ok', 'missing', 'wrong', 'unknown')
            if ($c.PSObject.Properties['value']) { $script:EnumControls.Keys | Should -Contain $c.id }
        }
    }
    It 'carries only the fields Invardia accepts on a setup report, with the ring and the version' {
        $r = New-SISetupReport -Context (New-Ctx identified 'x' 3) -Catalog $script:Catalog -Now $script:Now
        foreach ($n in $r.PSObject.Properties.Name) { $script:SetupFields | Should -Contain $n }
        $r.Kind | Should -Be 'setup'; $r.Schema | Should -Be 2; $r.Product | Should -Be 'securityinsight'
        $r.Ring | Should -Be 3; $r.Version | Should -Be '3.0.0'; $r.Edition | Should -Be 'pro'
        $json = $r | ConvertTo-Json -Depth 6 -Compress
        $json | Should -Not -Match '7f3e2a10|inv-TESTKEY|ClaimedTenantId|Host'
    }
    It 'what the engine can tell: ring, install key, licence, a successful run, a recent updater check' {
        $s = Get-SISetupControlStates -Context (New-Ctx identified 'x' 2) -ExitReason 'success' -UpdateStateJson $script:StateCompact -NowUtc $script:Now
        $s['update-ring'].State | Should -Be 'ok'; $s['update-ring'].Value | Should -Be '2'
        $s['uplink-key'].State | Should -Be 'ok'; $s['licence-valid'].State | Should -Be 'ok'; $s['last-run-24h'].State | Should -Be 'ok'
        $s['updater-deployed'].State | Should -Be 'ok'; $s['updater-schedule'].Value | Should -Be 'enabled'
        $s = Get-SISetupControlStates -Context (New-Ctx identified 'x' $null) -ExitReason 'error' -UpdateStateJson '' -NowUtc $script:Now
        $s['update-ring'].State | Should -Be 'missing'
        $s.ContainsKey('last-run-24h') | Should -BeFalse
        $s.ContainsKey('updater-deployed') | Should -BeFalse
    }
}

Describe 'the setup report on the wire' {
    BeforeEach { Reset-Telemetry }
    It 'identified, heartbeat due: heartbeat, run, then the setup report LAST -- with EVERY catalog control by default' {
        $r = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context (New-Ctx identified (Join-Path $TestDrive 's1') 2) -Transport $script:StubOk -Now $script:Now -HeartbeatCounts { @{} } -SetupCatalog $script:Catalog
        $r.Status | Should -Be 'ok'
        (@($script:Posts | ForEach-Object { $_.Kind }) -join ',') | Should -Be 'heartbeat,run,setup'
        $setup = $script:Posts[2]
        (@($setup.Controls | ForEach-Object { $_.id } | Sort-Object) -join ',') | Should -Be (@(Get-SISetupControlIds -Catalog $script:Catalog -Scope all | Sort-Object) -join ',')
        foreach ($m in $script:InvardiaMinimum) { @($setup.Controls.id) | Should -Contain $m }
        $setup.Ring | Should -Be 2
        (@($setup.Controls | Where-Object { $_.id -eq 'update-ring' })[0]).value | Should -Be '2'
    }
    It 'not again the same day; SI_Telemetry_SetupControls = off sends none; anonymous sends none' {
        $c = New-Ctx identified (Join-Path $TestDrive 's2') 2
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context $c -Transport $script:StubOk -Now $script:Now -HeartbeatCounts { @{} } -SetupCatalog $script:Catalog
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context $c -Transport $script:StubOk -Now $script:Now.AddHours(2) -HeartbeatCounts { @{} } -SetupCatalog $script:Catalog
        @($script:Posts | Where-Object { $_.Kind -eq 'setup' }).Count | Should -Be 1
        Reset-Telemetry
        $global:SI_Telemetry_SetupControls = 'off'
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context (New-Ctx identified (Join-Path $TestDrive 's3') 2) -Transport $script:StubOk -Now $script:Now -HeartbeatCounts { @{} } -SetupCatalog $script:Catalog
        @($script:Posts | Where-Object { $_.Kind -eq 'setup' }).Count | Should -Be 0
        Reset-Telemetry
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context (New-Ctx anonymous (Join-Path $TestDrive 's4') 2) -Transport $script:StubOk -Now $script:Now -SetupCatalog $script:Catalog
        @($script:Posts | Where-Object { $_.Kind -eq 'setup' }).Count | Should -Be 0
    }
    It 'a refused setup report costs nothing else: the heartbeat and the run report were already accepted' {
        $refuseSetup = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $script:Posts.Add($Record); if ($Record.Kind -eq 'setup') { [pscustomobject]@{ Status = 'refused'; Reason = 'Controls' } } else { [pscustomobject]@{ Status = 'ok'; Reason = 'accepted' } } }
        $r = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context (New-Ctx identified (Join-Path $TestDrive 's5') 2) -Transport $refuseSetup -Now $script:Now -HeartbeatCounts { @{} } -SetupCatalog $script:Catalog -WarningAction SilentlyContinue
        @($r.Sent) -join ',' | Should -Be 'heartbeat,run'
    }
    It 'TELEMETRY ON: a full setup report Invardia refuses goes again ONCE with only the minimum list, said once' {
        $global:SI_SetupControlsFallbackSaid = $null
        $refuseFull = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $script:Posts.Add($Record)
            if ($Record.Kind -eq 'setup' -and @($Record.Controls).Count -gt 11) { [pscustomobject]@{ Status = 'refused'; Reason = 'unknown control id' } } else { [pscustomobject]@{ Status = 'ok'; Reason = 'accepted' } } }
        $r = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context (New-Ctx identified (Join-Path $TestDrive 's6') 2) -Transport $refuseFull -Now $script:Now -HeartbeatCounts { @{} } -SetupCatalog $script:Catalog 6>$null
        $setups = @($script:Posts | Where-Object { $_.Kind -eq 'setup' })
        $setups.Count | Should -Be 2
        (@($setups[1].Controls | ForEach-Object { $_.id } | Sort-Object) -join ',') | Should -Be (@($script:InvardiaMinimum | Sort-Object) -join ',')
        @($r.Sent) -join ',' | Should -Be 'heartbeat,run,setup'
        $global:SI_SetupControlsFallbackSaid | Should -BeTrue
        $global:SI_SetupControlsFallbackSaid = $null
    }
    It 'scope minimum set by the customer: one setup report with the minimum list, no second one' {
        $global:SI_Telemetry_SetupControls = 'minimum'
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context (New-Ctx identified (Join-Path $TestDrive 's7') 2) -Transport $script:StubOk -Now $script:Now -HeartbeatCounts { @{} } -SetupCatalog $script:Catalog
        $setups = @($script:Posts | Where-Object { $_.Kind -eq 'setup' })
        $setups.Count | Should -Be 1
        (@($setups[0].Controls | ForEach-Object { $_.id } | Sort-Object) -join ',') | Should -Be (@($script:InvardiaMinimum | Sort-Object) -join ',')
    }
}
