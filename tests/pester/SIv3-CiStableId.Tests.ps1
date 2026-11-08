#Requires -Version 5.1
<#
    THE CI ID IS THE STABLE ID (owner 2026-11-05: "ci object must be the stable id" / "make sure that the records sent to ci
    shows the state so the servicenow team knows what to do with it and can close it" / "retired cis must go to servicenow"
    / "never delete or stop sending"). A CI id, once sent to ServiceNow, always means the same machine: never reused for
    something else, never resurrected after a merge, never replaced by a new id for the same machine.

    The cases are the ring 1 install's (2026-11-05, read-only), replayed as fixtures:
      * sql-host-05: CI a0b8f186 was merged into 5802bfcd on 2026-10-21, yet on 2026-10-27 the build REUSED a0b8f186 for the
        VM's old Exposure Graph node d12c5e (the ledger anchor still pointed at the merged id) -- the merged id must resolve
        to the survivor and every anchor of it must be re-pointed (identity\SI-ObjectIdentity.ps1);
      * a Defender id recorded as merged into BOTH a0b8f186 and 5802bfcd -- it ends on ONE CI, by a stated rule
        (ConvertTo-SISupersededMap / Resolve-SISupersededId);
      * an Exposure Graph-only VM node unseen 30 days -- not seen, then retired after the grace period, never "fixed"
        (SI-CiLifecycle.ps1); Exposure Graph never outvotes the source it mirrors;
      * the merged twin's ServiceNow row (retired, close, the reason naming the survivor) and the survivor's u_si_replaces;
        a retired CI (each reason kind) and a not-seen CI carry their state and reason (SI-DataOutContract.ps1);
      * the VM's SQL Server IaaS registration (sqlvirtualmachines, same name) is a CHILD of the VM's CI and never a merge
        candidate (collection-scope.locked.json, SI-CorrelationSuspects.ps1);
      * a Defender device with no name at all gets the generated name (SI-CiBuild.ps1).
    On a real SQL Server (.\SQLEXPRESS on the test VM, when running): the one-time repair through the merged-retire pass,
    the CI->CI 'merge' event in sidata.AssetIdHistory, the plain-words reason of an earlier twin, the merged-away ids read.
    pwsh 7 (PS 5.1 syntax). Stubs and helpers in SCRIPT scope.
#>

BeforeDiscovery {
    $script:HasSql = $false
    try { $script:HasSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:HasSql = $false }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
    if (-not (Get-Command -Name Sort-SIOrdinal -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\_shared\SI-AssetIdentity.ps1') }
    if (-not (Get-Command -Name Get-SIMemberIdentifiers -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\asset-correlation\_shared\SI-CorrelationCore.ps1') }
    . (Join-Path $script:SIRoot 'engine\data-out\SI-DataOut.ps1')
    . (Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-CorrelationSuspects.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Cat = $script:Model['field-catalog']
    $script:T = [datetime]::SpecifyKind([datetime]'2026-11-05T06:00:00', [DateTimeKind]::Utc)

    $script:Twin = 'a0b8f186-0000-5000-8000-000000000001'
    $script:Surv = '5802bfcd-0000-5000-8000-000000000002'
    $script:Arm = '/subscriptions/00000000-0000-0000-0000-000000000001/resourcegroups/rg-app1/providers/microsoft.compute/virtualmachines/sql-host-05'

    function script:Id([string]$t, [string]$v) { [pscustomobject]@{ Type = $t; Value = $v } }
    function script:Grp([object[]]$Ids) { [pscustomobject]@{ Members = @([pscustomobject]@{ Engine = 'x'; SIAssetId = 'a'; Identifiers = @($Ids) }) } }
    function script:Anchor([string]$t, [string]$v, [string]$cid, [string]$fs = '2026-10-01') { @{ Key = (Get-SILedgerKey -Type $t -Value $v); Entry = @{ CorrelationId = $cid; FirstSeen = [datetime]$fs } } }
    function script:Ledger([object[]]$Anchors) { $h = @{}; foreach ($a in $Anchors) { $h[$a.Key] = $a.Entry }; $h }
    function script:Rec([string]$p, [string]$rt, [string]$cls, [string]$native, [hashtable]$f) {
        $o = [ordered]@{ si_provider = $p; si_record_type = $rt; si_class = $cls; si_record_key = "${p}:$native"; si_collection_time = $script:T
            si_source_last_seen = $script:T.AddHours(-1); si_collection_complete = $true }
        foreach ($k in $f.Keys) { $o[$k] = $f[$k] }
        [pscustomobject]$o
    }
    function script:Link([string]$p, [string]$state, [datetime]$seen, [string]$reason = '') {
        [pscustomobject]@{ provider = $p; type = 'device'; id = 'x'; state = $state; last_seen = $seen; reason = $reason }
    }
}

Describe 'a merged-away id is never used again (the identity ledger)' {
    It 'sql-host-05: the old Exposure Graph node still points at the merged twin -> it resolves to the SURVIVOR, never the twin' {
        $led = Ledger @((Anchor 'ExposureGraphNodeId' 'd12c5e6e867546e7ad25c1b1fff1f04e' $script:Twin), (Anchor 'ExposureGraphNodeId' '859bdb00000000000000000000000001' $script:Twin),
                        (Anchor 'MdeDeviceId' '2a15057f00000000000000000000000000000001' $script:Surv), (Anchor 'AzureResourceId' $script:Arm $script:Surv))
        $map = ConvertTo-SISupersededMap -Rows @([pscustomobject]@{ OldId = $script:Twin; NewId = $script:Surv; At = [datetime]'2026-10-21' })
        $r = Resolve-SIObjectIdentity -Groups @(Grp @((Id 'ExposureGraphNodeId' 'd12c5e6e867546e7ad25c1b1fff1f04e'))) -Ledger $led -MergedAway $map -Now $script:T
        $d = @($r.Decisions)[0]
        $d.CorrelationId | Should -Be $script:Surv -Because 'a merged-away id is never an id of its own again'
        $d.Action | Should -Be 'reuse'
        # EVERY anchor of the twin is re-pointed -- also the node this group does not carry this run
        $re = @{}; foreach ($n in @($d.NewIdentifiers)) { $re[(Get-SILedgerKey -Type $n.Type -Value $n.Value)] = $n.CorrelationId }
        $re['exposuregraphnodeid|d12c5e6e867546e7ad25c1b1fff1f04e'] | Should -Be $script:Surv
        $re['exposuregraphnodeid|859bdb00000000000000000000000001'] | Should -Be $script:Surv -Because 'an anchor left behind is how the twin came back'
        @($r.Superseded | Where-Object { $_.OldId -eq $script:Twin -and $_.NewId -eq $script:Surv }).Count | Should -Be 1
    }
    It 'a ledger MERGE re-points every anchor of the merged id, not only the ones this run saw' {
        $led = Ledger @((Anchor 'AadDeviceId' 'd1' 'ID-OLD' '2025-01-01'), (Anchor 'MdeDeviceId' 'm1' 'ID-NEW' '2026-06-01'), (Anchor 'ExposureGraphNodeId' 'eg-stale' 'ID-NEW' '2026-06-01'))
        $r = Resolve-SIObjectIdentity -Groups @(Grp @((Id 'AadDeviceId' 'd1'), (Id 'MdeDeviceId' 'm1'))) -Ledger $led -Now $script:T
        $d = @($r.Decisions)[0]
        $d.Action | Should -Be 'merge'; $d.CorrelationId | Should -Be 'ID-OLD'
        @($d.NewIdentifiers | Where-Object { $_.Value -eq 'eg-stale' -and $_.CorrelationId -eq 'ID-OLD' }).Count | Should -Be 1
        @($r.Superseded).Count | Should -Be 1 -Because 'the merged id is recorded once'
        # the next run: the stale node alone resolves to the survivor through the ledger it now holds
        $next = @{}; foreach ($k in $led.Keys) { $next[$k] = $led[$k] }
        foreach ($n in @($d.NewIdentifiers)) { $next[(Get-SILedgerKey -Type $n.Type -Value $n.Value)] = @{ CorrelationId = $n.CorrelationId; FirstSeen = [datetime]'2026-06-01' } }
        @((Resolve-SIObjectIdentity -Groups @(Grp @((Id 'ExposureGraphNodeId' 'eg-stale'))) -Ledger $next).Decisions)[0].CorrelationId | Should -Be 'ID-OLD'
    }
    It 'a record whose identifier is already known to a CI links to it rather than minting' {
        $led = Ledger @((Anchor 'MdeDeviceId' '2a15057f00000000000000000000000000000001' $script:Surv))
        $d = @((Resolve-SIObjectIdentity -Groups @(Grp @((Id 'MdeDeviceId' '2a15057f00000000000000000000000000000001'), (Id 'ExposureGraphNodeId' 'new-node'))) -Ledger $led).Decisions)[0]
        $d.Action | Should -Be 'reuse'; $d.CorrelationId | Should -Be $script:Surv
    }
    It 'without a map nothing changes: an id that was never merged is itself' {
        Resolve-SISupersededId -Id 'abc' -Map $null | Should -Be 'abc'
        Resolve-SISupersededId -Id 'abc' -Map (ConvertTo-SISupersededMap -Rows @()) | Should -Be 'abc'
    }
}

Describe 'the source id merged into two CIs ends on ONE CI (the deterministic rule)' {
    It 'the merge chain is followed to its end (a -> b -> c answers c)' {
        $m = ConvertTo-SISupersededMap -Rows @([pscustomobject]@{ OldId = 'a'; NewId = 'b'; At = [datetime]'2026-10-01' }, [pscustomobject]@{ OldId = 'b'; NewId = 'c'; At = [datetime]'2026-10-02' })
        Resolve-SISupersededId -Id 'a' -Map $m | Should -Be 'c'
    }
    It 'one old id with two merge events: the NEWEST event decides; equal times: the ordinally lowest survivor' {
        $m = ConvertTo-SISupersededMap -Rows @([pscustomobject]@{ OldId = 'x'; NewId = 'zz'; At = [datetime]'2026-10-01' }, [pscustomobject]@{ OldId = 'x'; NewId = 'yy'; At = [datetime]'2026-11-03' })
        Resolve-SISupersededId -Id 'x' -Map $m | Should -Be 'yy'
        $t = [datetime]'2026-11-03'
        $m2 = ConvertTo-SISupersededMap -Rows @([pscustomobject]@{ OldId = 'x'; NewId = 'zz'; At = $t }, [pscustomobject]@{ OldId = 'x'; NewId = 'yy'; At = $t })
        Resolve-SISupersededId -Id 'x' -Map $m2 | Should -Be 'yy'
        $m3 = ConvertTo-SISupersededMap -Rows @([pscustomobject]@{ OldId = 'x'; NewId = 'yy'; At = $t }, [pscustomobject]@{ OldId = 'x'; NewId = 'zz'; At = $t })
        Resolve-SISupersededId -Id 'x' -Map $m3 | Should -Be 'yy' -Because 'the order the rows come in never decides'
    }
    It 'two contradicting merges (a cycle) end on the ordinally lowest id of the cycle, the same from either side' {
        $m = ConvertTo-SISupersededMap -Rows @([pscustomobject]@{ OldId = $script:Twin; NewId = $script:Surv; At = [datetime]'2026-10-21' }, [pscustomobject]@{ OldId = $script:Surv; NewId = $script:Twin; At = [datetime]'2026-10-27' })
        (Resolve-SISupersededId -Id $script:Twin -Map $m) | Should -Be (Resolve-SISupersededId -Id $script:Surv -Map $m)
        (Resolve-SISupersededId -Id $script:Twin -Map $m) | Should -Be $script:Surv -Because '5802bfcd... sorts before a0b8f186...'
    }
    It 'a ring-1 install: Defender id 2a15057f "merged into BOTH" the twin and the survivor -> one CI, the survivor, and its anchor moves there' {
        $led = Ledger @((Anchor 'MdeDeviceId' '2a15057f00000000000000000000000000000001' $script:Twin), (Anchor 'AzureResourceId' $script:Arm $script:Surv))
        $map = ConvertTo-SISupersededMap -Rows @([pscustomobject]@{ OldId = $script:Twin; NewId = $script:Surv; At = [datetime]'2026-10-21' })
        $d = @((Resolve-SIObjectIdentity -Groups @(Grp @((Id 'MdeDeviceId' '2a15057f00000000000000000000000000000001'))) -Ledger $led -MergedAway $map).Decisions)[0]
        $d.CorrelationId | Should -Be $script:Surv
        @($d.NewIdentifiers | Where-Object { $_.Value -eq '2a15057f00000000000000000000000000000001' -and $_.CorrelationId -eq $script:Surv }).Count | Should -Be 1
    }
    It 'the build''s map: the ledger''s superseded rows and the data database''s merges, WITHOUT a pair a person split again' {
        $rows = ConvertTo-SICiSupersededRows -DataRows @(
                    [pscustomobject]@{ OldId = 'a'; NewId = 'b'; At = [datetime]'2026-10-01'; Kind = 'merge' },
                    [pscustomobject]@{ OldId = 'c'; NewId = 'd'; At = [datetime]'2026-10-01'; Kind = 'merge' },
                    [pscustomobject]@{ OldId = 'c'; NewId = 'd'; At = $null; Kind = 'split' }) `
                -LedgerRows @([pscustomobject]@{ OldId = 'e'; NewId = 'f'; SupersededAt = [datetime]'2026-10-02' }, [pscustomobject]@{ OldId = 'd'; NewId = 'c'; SupersededAt = [datetime]'2026-10-02' })
        $m = ConvertTo-SISupersededMap -Rows $rows
        $m['a'] | Should -Be 'b'; $m['e'] | Should -Be 'f'
        $m.ContainsKey('c') | Should -BeFalse -Because 'a person split c from d again'
        $m.ContainsKey('d') | Should -BeFalse
    }
    It 'the merged-away ids are read from AssetIdHistory CI->CI merges only (both ids CIs), retired twins and split decisions' {
        $s = Get-SICiSupersededSql
        $s | Should -Match "h\.EventType = N'merge'"
        $s | Should -Match 'EXISTS \(SELECT 1 FROM sidata\.Ci a WHERE a\.CiId = h\.PreviousId\) AND EXISTS \(SELECT 1 FROM sidata\.Ci b WHERE b\.CiId = h\.CurrentId\)'
        $s | Should -Match "si_merged_into"
        $s | Should -Match "N'split'"
        $s | Should -Not -Match '(?i)\b(UPDATE|DELETE|INSERT\s+sidata)\b'
    }
    It 'the CI build reads the map once and hands it to the ledger resolution of every batch' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1'))
        $t | Should -Match 'Get-SICiSupersededSql'
        $t | Should -Match '-Superseded \$supMap'
        $t | Should -Match 'Resolve-SIObjectIdentity -Groups @\(\$Groups\) -Ledger \$Ledger -Now \$Now -MergedAway \$Superseded'
    }
}

Describe 'Exposure Graph ages out; Exposure Graph never outvotes the source it mirrors' {
    BeforeAll { $script:Life = Get-SICiLifecycleSettings }
    It 'an Exposure Graph record of ANY class gets the seen window (a VM node: cloud_resource); Azure Resource Graph keeps "listed = exists"' {
        $eg = Rec eg azure_resource cloud_resource 'node-d12b565b' @{ si_source_last_seen = $script:T.AddDays(-30) }
        $az = Rec azure azure_resource cloud_resource $script:Arm @{ si_source_last_seen = $script:T.AddDays(-30) }
        (Get-SIRecordSeenWindowDays -Record $eg -SeenWithinDays 8) | Should -BeGreaterThan 0
        (Get-SIRecordSeenWindowDays -Record $az -SeenWithinDays 8) | Should -Be 0
        # an account only Exposure Graph lists keeps "listed = exists": a dormant account is a risk to report, never retired
        (Get-SIRecordSeenWindowDays -Record (Rec eg user identity 'node-ad-user' @{ si_source_last_seen = $script:T.AddDays(-90) }) -SeenWithinDays 8) | Should -Be 0
        $feeds = Get-SIFeedLatest -Records @($eg, $az)
        (Get-SIRecordLink -Record $eg -FeedLatest $feeds -Now $script:T -SeenWithinDays 8).State | Should -Be 'not_seen' -Because 'Exposure Graph still lists it, but last saw it 30 days ago'
        (Get-SIRecordLink -Record $az -FeedLatest $feeds -Now $script:T -SeenWithinDays 8).State | Should -Be 'active'
    }
    It 'an Exposure Graph-only VM node unseen 30 days: not seen in the grace period, then RETIRED after it (mail-host-03, d12b565b)' {
        $seen = $script:T.AddDays(-12)
        $l = Get-SICiLifecycle -Links @(Link eg not_seen $seen 'eg lists it, but last saw it') -Category 'other' -Settings $script:Life -Now $script:T -Previous @{ Lifecycle = 'active'; Since = $script:T.AddDays(-60) }
        $l.Lifecycle | Should -Be 'not_seen'
        $l.Reason | Should -Match '^not seen since '
        $late = Get-SICiLifecycle -Links @(Link eg not_seen $script:T.AddDays(-400)) -Category 'other' -Settings $script:Life -Now $script:T -Previous @{ Lifecycle = 'not_seen'; Since = $script:T.AddDays(-400) }
        $late.Lifecycle | Should -Be 'retired'
        $late.Reason | Should -Match '^retired: not seen since '
    }
    It 'an Exposure Graph link that is "active" does NOT keep a CI active that Defender no longer sees (the 122 device nodes)' {
        $l = Get-SICiLifecycle -Links @((Link mde not_seen $script:T.AddDays(-20) 'mde last saw it'), (Link eg active $script:T)) -Category 'other' -Settings $script:Life -Now $script:T -Previous @{ Lifecycle = 'active'; Since = $script:T.AddDays(-60) }
        $l.Lifecycle | Should -Be 'not_seen' -Because 'Exposure Graph re-lists what Defender holds; its refresh time is no sighting'
    }
    It 'a CI only Exposure Graph links is decided by Exposure Graph; a CMDB record does not count as another source' {
        (Get-SICiLifecycle -Links @(Link eg active $script:T) -Settings $script:Life -Now $script:T).Lifecycle | Should -Be 'active'
        (Get-SICiLifecycle -Links @((Link eg active $script:T), (Link cmdb not_seen $script:T.AddDays(-40))) -Settings $script:Life -Now $script:T).Lifecycle | Should -Be 'active' -Because 'a CMDB record is no observation of the asset: Exposure Graph still decides'
        (Get-SICiLifecycle -Links @(Link eg not_seen $script:T.AddDays(-12)) -Settings $script:Life -Now $script:T).Lifecycle | Should -Be 'not_seen'
    }
    It 'a CI Azure still lists stays active whatever its stale Exposure Graph node says (the 202 Azure resource nodes)' {
        (Get-SICiLifecycle -Links @((Link azure active $script:T), (Link eg not_seen $script:T.AddDays(-40))) -Settings $script:Life -Now $script:T).Lifecycle | Should -Be 'active'
    }
    It 'absence is never remediation: a retired CI''s findings close as asset retired, never as fixed (the rule kept)' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-DataCiLifecycle.ps1'))
        $t | Should -Match "c\.Lifecycle = N'retired' THEN ISNULL\(\(SELECT r\.Why FROM @ret r WHERE r\.CiId = s\.CiId\), N'asset_retired'\)"
        (Get-SIDataOutRecordClass -Grain ci -Item ([pscustomobject]@{ si_lifecycle = 'not_seen' })) | Should -Be 'live' -Because 'a not seen CI is never closed'
    }
}

Describe 'ServiceNow: every CI row says its state, and a retired CI is closed with its reason' {
    It 'each reason kind of a retired CI and a not seen CI is the row''s u_si_reason; an active CI has none' {
        $kinds = @(
            'merged into 5802bfcd (SQL-HOST-05) -- the same machine; use that CI',
            'retired: not seen since 2026-10-01, longer than the 30-day grace period of a server',
            'retired at once: deleted in Entra ID (entra -- ...)',
            'retired at once: every linked object is gone (mde -- mde says it is offboarded)',
            'retired at once: an identity choice leaves it out')
        foreach ($k in $kinds) { Get-SIDataOutCiStateReason -Item ([pscustomobject]@{ si_lifecycle = 'retired'; si_lifecycle_reason = $k }) | Should -Be $k }
        Get-SIDataOutCiStateReason -Item ([pscustomobject]@{ si_lifecycle = 'not_seen'; si_lifecycle_reason = 'not seen since 2026-10-28 -- retired on 2026-11-27 unless it is seen again' }) | Should -Match '^not seen since'
        Get-SIDataOutCiStateReason -Item ([pscustomobject]@{ si_lifecycle = 'active'; si_lifecycle_reason = 'seen by mde' }) | Should -Be ''
        Get-SIDataOutCiStateReason -Item ([pscustomobject]@{ si_lifecycle = 'retired' }) | Should -Match 'close it' -Because 'a retired CI is never sent with an empty reason'
        Get-SIDataOutCiStateReason -Item ([pscustomobject]@{ si_lifecycle = 'retired'; si_merged_into = $script:Surv }) | Should -Match ('^merged into ' + [regex]::Escape($script:Surv))
    }
    It 'the merged twin''s row: u_si_state retired, u_action close, the reason naming the survivor -- and the reason changes the row hash once' {
        $map = $script:Model.Outputs['servicenow-ci']
        $vm = $script:Model['value-maps'].maps
        $twin = [pscustomobject]@{ si_ci_id = $script:Twin; si_class = 'cloud_resource'; si_asset_name = 'sql-host-05'; si_lifecycle = 'retired'; si_merged_into = $script:Surv
                                   si_lifecycle_reason = ('merged into {0} (SQL-HOST-05) -- the same machine; use that CI' -f $script:Surv) }
        $act = Get-SIDataOutContractAction -Now (Get-SIDataOutRecordClass -Grain ci -Item $twin) -Base live
        $act.Action | Should -Be 'close'
        $row = ConvertTo-SIDataOutContractRow -Output 'servicenow-ci' -Map $map -Item $twin -ValueMaps $vm -Action $act.Action
        $row['u_si_state'] | Should -Be 'retired'; $row['u_action'] | Should -Be 'close'
        $row['u_si_reason'] | Should -Be ('merged into {0} (SQL-HOST-05) -- the same machine; use that CI' -f $script:Surv)
        $plain = ConvertTo-SIDataOutContractRow -Output 'servicenow-ci' -Map $map -Item $twin -ValueMaps $vm -Action 'held'
        $row['u_row_hash'] | Should -Not -Be $plain['u_row_hash'] -Because 'a retired row first sent without a reason goes once more'
        Add-SIDataOutReasonToHash -Hash 'abc' -Reason '' | Should -Be 'abc' -Because 'an active CI''s hash never changes because of this'
    }
    It 'the survivor names the twin: u_si_replaces comes from a CI->CI merge event (the previous id is a CI, never a Defender id)' {
        $s = Get-SIDataOutReplacesSql
        $s | Should -Match "h\.EventType IN \(N'rekey', N'merge'\)"
        $s | Should -Match 'EXISTS \(SELECT 1 FROM sidata\.Ci AS c WHERE c\.CiId = h\.PreviousId\)'
        $map = ConvertTo-SIDataOutReplacesMap -Rows @(@{ CurrentId = $script:Surv; PreviousId = $script:Twin })
        $map[$script:Surv] | Should -Be $script:Twin
    }
    It 'the merged-retire pass writes the CI->CI merge event and the plain-words reason (statement)' {
        $s = Get-SICiMergedRetireSql
        $s | Should -Match "INSERT sidata\.AssetIdHistory \(AssetKey, EventType, PreviousId, CurrentId, ViaType, ViaValue, DetectedAt, LoadId\)"
        $s | Should -Match "N' -- the same machine; use that CI'"
        $s | Should -Match "h\.EventType = N'merge'" -Because 'the one-time repair: an active CI the history says was merged is retired into its survivor'
        $s | Should -Not -Match '(?i)\bDELETE\b|\bTRUNCATE\b|\bDROP\b'
    }
    It 'a retired CI is never filtered out of the CI output: the map filters on the class only, the CI read takes every lifecycle' {
        $m = Get-Content -Raw (Join-Path $script:SIRoot 'data-model\outputs\servicenow-ci.locked.json') | ConvertFrom-Json
        @($m.filter.PSObject.Properties.Name) | Should -Be @('si_class')
        Get-SIDataOutCiSql | Should -Not -Match '(?i)Lifecycle\s*(=|<>|IN)'
    }
    It 'no code path deletes a delivered CI row: the only CI rows the gone pass lets go are rows never delivered' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-out\SI-DataOut.ps1'))
        $t | Should -Match ([regex]::Escape("if ((`$meta.Base -eq 'none' -and `$now -eq 'gone') -or (-not `$isCi -and `$meta.Class -eq 'gone' -and `$meta.Delivered)) { `$gone.Add(`$k) }"))
        $t | Should -Match ([regex]::Escape("if (`$W.Replaced.Contains(`$k) -and -not `$isCi) { `$gone.Add(`$k); continue }"))
    }
}

Describe 'the SQL VM resource is a CHILD of its VM''s CI, never a merge candidate' {
    It 'microsoft.sqlvirtualmachine/sqlvirtualmachines keeps its own CI AND is listed on its VM (properties.virtualMachineResourceId)' {
        $doc = Get-Content -Raw (Join-Path $script:SIRoot 'data-model\collection-scope.locked.json') | ConvertFrom-Json
        $scope = ConvertTo-SIAzureCiScope -Document $doc
        $sqlvm = $script:Arm.Replace('microsoft.compute/virtualmachines', 'microsoft.sqlvirtualmachine/sqlvirtualmachines')
        $obj = [pscustomobject]@{ id = $sqlvm; name = 'SQL-HOST-05'; type = 'Microsoft.SqlVirtualMachine/sqlVirtualMachines'; properties = [pscustomobject]@{ virtualMachineResourceId = $script:Arm.ToUpperInvariant(); sqlImageOffer = 'SQL2019-WS2019' } }
        $p = Resolve-SIAzurePlacement -Id $sqlvm -Type 'microsoft.sqlvirtualmachine/sqlvirtualmachines' -Object $obj -Scope $scope
        $p.Action | Should -Be 'record' -Because 'a different object: its own CI'
        $p.AlsoChildOf | Should -Be $script:Arm -Because 'and a linked child of the VM''s CI'
        @(Test-SIAzureCiScopeItems -Document $doc) | Should -BeNullOrEmpty
    }
    It 'the duplicate-candidates check never groups a CI with its own child, nor two different Azure resource types' {
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-CorrelationSuspects.ps1'))
        $s | Should -Match "cl\.RecordType = N'child_resource'"
        $s | Should -Match 'WHERE s\.\[Rule\] = N''name'' AND z\.AzType <> k\.AzType'
        $s | Should -Match "microsoft\.compute/virtualmachines', N'microsoft\.hybridcompute/machines'"
    }
}

Describe 'a device no source names gets the generated name (no active CI is nameless)' {
    It 'a Defender device with NO name at all (no computerDnsName): the generated unnamed name, from = generated' {
        $mdeId = '9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293'
        $r = Rec mde device device $mdeId @{ mde_device_id = $mdeId }
        $ci = New-SICiDocument -CiId 'ci-1' -Records @($r) -Catalog $script:Cat -FeedLatest (Get-SIFeedLatest -Records @($r)) -Now $script:T
        $ci['si_asset_name'] | Should -Match '^unnamed-'
        $ci['si_field_sources']['si_asset_name'].from | Should -Be 'generated'
        $ci2 = New-SICiDocument -CiId 'ci-1' -Records @($r) -Catalog $script:Cat -FeedLatest (Get-SIFeedLatest -Records @($r)) -Now $script:T
        $ci2['si_asset_name'] | Should -Be $ci['si_asset_name'] -Because 'the same name on every build'
    }
    It 'a cloud resource no record names takes the name in its Azure resource id' {
        $r = Rec azure azure_resource cloud_resource $script:Arm @{ azure_resource_id = $script:Arm }
        (New-SICiDocument -CiId 'ci-2' -Records @($r) -Catalog $script:Cat -FeedLatest (Get-SIFeedLatest -Records @($r)) -Now $script:T)['si_asset_name'] | Should -Be 'sql-host-05'
    }
    It 'a real name is untouched' {
        $r = Rec mde device device 'abc' @{ mde_device_id = 'abc'; si_asset_name = 'srv-01' }
        (New-SICiDocument -CiId 'ci-3' -Records @($r) -Catalog $script:Cat -FeedLatest (Get-SIFeedLatest -Records @($r)) -Now $script:T)['si_asset_name'] | Should -Be 'srv-01'
    }
}

Describe 'real SQL: the one-time repair, the merge event, the plain-words reason (local SQL Server Express)' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:DbName = 'si_test_stableid_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$script:DbName]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Cn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$script:DbName;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
        $script:Cn.Open()
        $c = $script:Cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-data-schema.sql')); [void]$c.ExecuteNonQuery()
        $c = $script:Cn.CreateCommand(); $c.CommandText = "CREATE USER si_engine WITHOUT LOGIN; ALTER ROLE db_datareader ADD MEMBER si_engine; ALTER ROLE db_datawriter ADD MEMBER si_engine; EXECUTE AS USER = N'si_engine';"; [void]$c.ExecuteNonQuery()
        $script:Sql = {
            param($Sql, $Params, $Mode)
            $c = $script:Cn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 300
            if ($Params) { foreach ($k in $Params.Keys) { $pp = $c.Parameters.Add('@' + $k, [System.Data.SqlDbType]::NVarChar, -1); $pp.Value = [string]$Params[$k] } }
            if ($Mode -eq 'rows') { return @(Read-SISqlRows -Command $c) }
            $c.ExecuteNonQuery()
        }
        function script:Q([string]$s) { @(& $script:Sql $s @{} 'rows') }
    }
    AfterAll {
        if ($script:Cn) { try { $script:Cn.Dispose() } catch { } }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$script:DbName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:DbName]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    It 'sql-host-05: the active twin the history says was merged is retired into the survivor (named), the merge event is written, an earlier twin gets its reason; nothing deleted' {
        $null = & $script:Sql @"
INSERT sidata.Ci (CiId, Lifecycle, LastSeen, CollectionTime, DocJson, ContentHash) VALUES
 (N'5802bfcd', N'active', SYSUTCDATETIME(), SYSUTCDATETIME(), N'{"si_lifecycle":"active","si_asset_name":"SQL-HOST-05"}', 0x01),
 (N'a0b8f186', N'active', DATEADD(day, -9, SYSUTCDATETIME()), SYSUTCDATETIME(), N'{"si_lifecycle":"active","si_asset_name":"sql-host-05"}', 0x02),
 (N'a7b37ed0', N'retired', DATEADD(day, -3, SYSUTCDATETIME()), SYSUTCDATETIME(), N'{"si_lifecycle":"retired","si_merged_into":"5802bfcd","si_lifecycle_reason":"retired at once: merged into CI 5802bfcd -- its mde record x builds that CI now; one hard id, one active CI"}', NULL);
INSERT sidata.CiRecord (RecordKey, CiId, Provider, CollectionTime) VALUES (N'azure:vm', N'5802bfcd', N'azure', SYSUTCDATETIME());
INSERT sidata.CiGroupMember (RecordKey, GroupKey, BatchNo) VALUES (N'azure:vm', N'g1', 1);
INSERT sidata.AssetIdHistory (AssetKey, EventType, PreviousId, CurrentId, ViaType, ViaValue, DetectedAt, LoadId) VALUES
 (N'5802bfcd', N'merge', N'a0b8f186', N'5802bfcd', N'ExposureGraphNodeId', N'd12c5e6e', '2026-10-21', 7),
 (N'a0b8f186', N'merge', N'2a15057f00000000000000000000000000000001', N'a0b8f186', N'MdeDeviceId', N'2a15057f', '2026-11-03', 8);
"@ @{} 'nonquery'
        $r = @(& $script:Sql (Get-SICiMergedRetireSql) @{ run = 'run-1' } 'rows')[0]
        [int]$r.Retired | Should -Be 1
        $st = @{}; foreach ($x in (Q 'SELECT CiId, Lifecycle, JSON_VALUE(DocJson, ''$.si_lifecycle_reason'') AS Why, JSON_VALUE(DocJson, ''$.si_merged_into'') AS IntoId FROM sidata.Ci')) { $st[[string]$x.CiId] = $x }
        $st['a0b8f186'].Lifecycle | Should -Be 'retired'
        $st['a0b8f186'].IntoId | Should -Be '5802bfcd'
        $st['a0b8f186'].Why | Should -Be 'merged into 5802bfcd (SQL-HOST-05) -- the same machine; use that CI'
        $st['a7b37ed0'].Why | Should -Be 'merged into 5802bfcd (SQL-HOST-05) -- the same machine; use that CI' -Because 'an earlier twin says it in plain words too'
        $st['5802bfcd'].Lifecycle | Should -Be 'active'
        @(Q "SELECT 1 AS X FROM sidata.AssetIdHistory WHERE EventType = N'merge' AND PreviousId = N'a7b37ed0' AND CurrentId = N'5802bfcd'").Count | Should -Be 1
        (Q 'SELECT COUNT(*) AS N FROM sidata.Ci')[0].N | Should -Be 3 -Because 'nothing is deleted'
        # the merged-away ids the next build reads: the CI->CI merges (never the Defender id -> CI row) and the retired twins
        $m = ConvertTo-SISupersededMap -Rows (ConvertTo-SICiSupersededRows -DataRows @(Q (Get-SICiSupersededSql)))
        $m['a0b8f186'] | Should -Be '5802bfcd'; $m['a7b37ed0'] | Should -Be '5802bfcd'
        $m.ContainsKey('2a15057f00000000000000000000000000000001') | Should -BeFalse -Because 'a Defender id -> CI row is not a CI merge'
        # retired once; the reason is not rewritten again
        [int](@(& $script:Sql (Get-SICiMergedRetireSql) @{ run = 'run-2' } 'rows')[0].Retired) | Should -Be 0
        @(Q "SELECT 1 AS X FROM sidata.CiChange WHERE CiId = N'a0b8f186' AND NewValue = N'retired'").Count | Should -Be 1
    }
}
