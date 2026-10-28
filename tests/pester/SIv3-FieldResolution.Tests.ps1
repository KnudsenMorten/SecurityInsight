#Requires -Version 5.1
<#
    SOURCE OF TRUTH BY PROVIDER TIMESTAMPS (REQUIREMENTS #459, V3-DATA-MODEL 2.6) -- the CI's field resolution
    (Resolve-SICiField / New-SICiDocument, SI-CiBuild.ps1) and its conflicts (SI-FieldResolution.ps1).

      * Every provider declares its "last updated" field (the mapping object's timestamp) and the record carries it as
        si_source_last_seen (AD's FILETIME read too; no value = the collection time).
      * A field takes the first FRESH provider of its authority order; an old record (older than the field's staleDays)
        never wins over a fresh one; nothing fresh -> the newest value, marked stale.
      * The winner is recorded (si_field_sources: provider, record, observed_at, stale) and fresh providers that hold a
        different value are recorded beside it as conflicts -- never deciding; a stale value or an any-true field has none.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuild.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Cat = $script:Model['field-catalog']
    $script:Now = ([datetime]'2026-10-10T06:00:00Z').ToUniversalTime()
    function script:Rec([string]$Provider, [string]$Key, [datetime]$Seen, [hashtable]$Fields) {
        $r = [ordered]@{ si_provider = $Provider; si_record_type = 'device'; si_record_key = "${Provider}:$Key"; si_class = 'device'
            si_collection_time = $script:Now.AddHours(-1); si_collection_complete = $true; si_source_last_seen = $Seen }
        foreach ($k in $Fields.Keys) { $r[$k] = $Fields[$k] }
        [pscustomobject]$r
    }
    function script:Ci([object[]]$Records) {
        New-SICiDocument -CiId 'ci-1' -Records $Records -Catalog $script:Cat -FeedLatest (Get-SIFeedLatest -Records $Records) -Now $script:Now
    }
}

Describe 'each provider''s "last updated" field (#459)' {
    It 'every provider object declares its timestamp, from the mappings' {
        $ts = @(Get-SIProviderTimestampFields -Model $script:Model)
        $ts.Count | Should -BeGreaterThan 10
        @($ts | Where-Object { -not $_.Timestamp }) | Should -BeNullOrEmpty
        # Defender also maps its finding record types (vulnerability, configuration); those carry no timestamp of their own
        ($ts | Where-Object { $_.Provider -eq 'mde' -and $_.RecordType -eq 'device' }).Timestamp | Should -Be 'machine.lastSeen'
        @($ts | Where-Object { $_.Provider -eq 'mde' -and $_.RecordType -ne 'device' } | ForEach-Object { $_.Timestamp } | Select-Object -Unique) | Should -Be @('$collection_time')
        ($ts | Where-Object { $_.Provider -eq 'azure' -and $_.RecordType -eq 'azure_resource' }).Timestamp | Should -Be '$collection_time'
        ($ts | Where-Object { $_.Provider -eq 'entra' -and $_.RecordType -eq 'device' }).Timestamp | Should -Be 'device.approximateLastSignInDateTime'
        ($ts | Where-Object { $_.Provider -eq 'intune' }).Timestamp | Should -Be 'device.lastSyncDateTime'
    }
    It 'the record carries it as si_source_last_seen; a provider without one gets the collection time' {
        $ct = ([datetime]'2026-10-10T03:00:00Z').ToUniversalTime()
        $map = { param($p, $o, $rt) (ConvertTo-SIRecord -Object $o -Mapping $script:Model.Mappings[$p] -RecordType $rt -Catalog $script:Cat -ValueMaps $script:Model['value-maps'].maps -CollectionTime $ct -RunId 'r').Record }
        $mde = & $map 'mde' ([pscustomobject]@{ machine = [pscustomobject]@{ id = 'm1'; lastSeen = '2026-10-09T21:15:00Z' } }) 'device'
        ([datetime]$mde['si_source_last_seen']).ToUniversalTime() | Should -Be ([datetime]'2026-10-09T21:15:00Z').ToUniversalTime()
        $none = & $map 'mde' ([pscustomobject]@{ machine = [pscustomobject]@{ id = 'm2' } }) 'device'
        ([datetime]$none['si_source_last_seen']).ToUniversalTime() | Should -Be $ct
    }
}

Describe 'the freshest valid value, by authority (#459)' {
    It 'the first fresh provider of the authority order wins, and the disagreeing fresh providers are recorded' {
        $ci = Ci @(
            (Rec 'mde' 'm1' $script:Now.AddDays(-1) @{ si_os_version = '10.0.20348' }),
            (Rec 'ad' 'a1' $script:Now.AddDays(-3) @{ si_os_version = '10.0.17763' }),
            (Rec 'entra' 'e1' $script:Now.AddDays(-2) @{ si_os_version = '10.0.20348' }),
            (Rec 'eg' 'g1' $script:Now.AddDays(-200) @{ si_os_version = '6.3.9600' }))
        $ci['si_os_version'] | Should -Be '10.0.20348'
        $src = $ci['si_field_sources']['si_os_version']
        $src.provider | Should -Be 'mde'
        $src.record | Should -Be 'mde:m1'
        $src.stale | Should -BeFalse
        @($src.conflicts).Count | Should -Be 1 -Because 'entra agrees and eg is stale -- only ad disagrees while fresh'
        $src.conflicts[0].provider | Should -Be 'ad'
        $src.conflicts[0].value | Should -Be '10.0.17763'
    }
    It 'an old record never wins over a fresh one, even with a better place in the order' {
        $ci = Ci @(
            (Rec 'mde' 'm1' $script:Now.AddDays(-45) @{ si_os_version = '10.0.17763' }),
            (Rec 'ad' 'a1' $script:Now.AddDays(-5) @{ si_os_version = '10.0.20348' }))
        $ci['si_os_version'] | Should -Be '10.0.20348'
        $ci['si_field_sources']['si_os_version'].provider | Should -Be 'ad'
        $ci['si_field_sources']['si_os_version'].Contains('conflicts') | Should -BeFalse -Because 'the old MDE value is not fresh'
    }
    It 'nothing fresh: the newest value, marked stale, no conflicts' {
        $ci = Ci @(
            (Rec 'mde' 'm1' $script:Now.AddDays(-90) @{ si_os_version = 'A' }),
            (Rec 'ad' 'a1' $script:Now.AddDays(-40) @{ si_os_version = 'B' }))
        $ci['si_os_version'] | Should -Be 'B'
        $ci['si_field_sources']['si_os_version'].stale | Should -BeTrue
        $ci['si_field_sources']['si_os_version'].Contains('conflicts') | Should -BeFalse
    }
    It 'a risk boolean resolves any-true and records no conflict' {
        $f = @($script:Cat.fields | Where-Object { $_.resolution.policy -eq 'any_true' -and @($_.classes) -contains 'device' })[0]
        $ci = Ci @(
            (Rec 'mde' 'm1' $script:Now.AddDays(-1) @{ ($f.name) = $false }),
            (Rec 'eg' 'g1' $script:Now.AddDays(-1) @{ ($f.name) = $true }))
        $ci[$f.name] | Should -BeTrue
        $ci['si_field_sources'][$f.name].Contains('conflicts') | Should -BeFalse
    }
    It 'compares values case-insensitively and lists as sets' {
        ConvertTo-SIFieldCompareText 'Windows ' | Should -Be (ConvertTo-SIFieldCompareText 'windows')
        ConvertTo-SIFieldCompareText @('b', 'A') | Should -Be (ConvertTo-SIFieldCompareText @('a', 'B', 'a'))
        ConvertTo-SIFieldCompareText 1 | Should -Not -Be (ConvertTo-SIFieldCompareText 2)
    }
}

Describe 'a CI asks only for the fields its records carry -- and is the same CI as when every catalog field was asked for' {
    # 2026-10-12, a large install: the catalog has several hundred resolved fields, a CI's records carry a few dozen, and
    # asking for every field of every CI was most of the CI build's time.
    BeforeAll {
        # THE CI AS IT WAS BUILT BEFORE: every resolved catalog field asked of the records, one by one
        function script:AskEveryField([object[]]$Records) {
            $feeds = Get-SIFeedLatest -Records $Records
            $cands = @(foreach ($r in $Records) { [pscustomobject]@{ Record = $r; Provider = [string](Get-SIItemValue $r 'si_provider'); Key = [string](Get-SIItemValue $r 'si_record_key'); State = (Get-SIRecordLinkState -Record $r -FeedLatest $feeds) } })
            $class = 'identity'; $best = 99
            foreach ($r in $Records) { $rc = [string](Get-SIItemValue $r 'si_class'); $rk = Get-SICiClassRank $rc; if ($rk -lt $best) { $best = $rk; $class = $rc } }
            $origin = ''; if ($class -eq 'identity') { $origin = Get-SICiIdentityOrigin -Candidates $cands }
            $vals = [ordered]@{}; $unknown = New-Object System.Collections.Generic.List[string]
            foreach ($f in @($script:Cat.fields)) {
                if ([string]$f.level -ne 'both') { continue }
                if ([string]$f.resolution.policy -eq 'computed') { continue }
                $fo = ''
                if ($class -eq 'identity' -and @($f.classes) -contains 'identity') {
                    $fo = $origin
                    if (Test-SICiFieldUnknown -Field $f -Origin $origin -Candidates $cands) { $unknown.Add([string]$f.name) }
                }
                $res = Resolve-SICiField -Field $f -Candidates $cands -Now $script:Now -CmdbOwner 'cmdb' -Origin $fo
                if ($null -ne $res) { $vals[[string]$f.name] = $res }
            }
            [pscustomobject]@{ Values = $vals; Unknown = $unknown.ToArray() }
        }
        function script:IdRec([string]$Provider, [string]$Type, [string]$Key, [hashtable]$Fields) {
            $r = [ordered]@{ si_provider = $Provider; si_record_type = $Type; si_record_key = "${Provider}:$Key"; si_class = 'identity'
                si_collection_time = $script:Now.AddHours(-1); si_collection_complete = $true; si_source_last_seen = $script:Now.AddDays(-1) }
            foreach ($k in $Fields.Keys) { $r[$k] = $Fields[$k] }
            [pscustomobject]$r
        }
        function script:Should-BeTheSameCi([object[]]$Records, [string]$What) {
            $ci = Ci $Records
            $all = AskEveryField $Records
            (@($ci['si_field_sources'].Keys) -join ',') | Should -BeExactly (@($all.Values.Keys) -join ',') -Because "$What -- the same fields, in catalog order"
            foreach ($n in @($all.Values.Keys)) {
                $res = $all.Values[$n]
                (ConvertTo-Json -InputObject @($ci[$n]) -Compress -Depth 6) | Should -BeExactly (ConvertTo-Json -InputObject @($res.Value) -Compress -Depth 6) -Because "$What -- the value of $n"
                $src = $ci['si_field_sources'][$n]
                ([string]$src.provider, [string]$src.record, [bool]$src.stale) | Should -Be @([string]$res.Provider, [string]$res.Record, [bool]$res.Stale) -Because "$What -- who supplied $n"
            }
            (@($ci['si_unknown_fields']) -join ',') | Should -BeExactly ($all.Unknown -join ',') -Because "$What -- the fields that cannot be decided"
            $ci
        }
    }
    It 'a device four providers see: the same fields, values, sources and order' {
        $ci = Should-BeTheSameCi -What 'device' -Records @(
            (Rec 'mde' 'm1' $script:Now.AddDays(-1) @{ si_os_version = '10.0.20348'; si_hostname = 'srv01'; si_os_platform = 'windows_server'; si_internet_exposed = $true; si_ip_addresses = @('10.0.0.5', '10.0.0.6') }),
            (Rec 'ad' 'a1' $script:Now.AddDays(-3) @{ si_os_version = '10.0.17763'; si_hostname = 'SRV01'; si_fqdn = 'srv01.contoso.local' }),
            (Rec 'entra' 'e1' $script:Now.AddDays(-2) @{ si_os_version = '10.0.20348'; si_account_enabled = $true }),
            (Rec 'eg' 'g1' $script:Now.AddDays(-200) @{ si_os_version = '6.3.9600'; si_internet_exposed = $false; si_ip_addresses = @('10.0.0.6', '10.0.0.7') }))
        @($ci['si_field_sources'].Keys).Count | Should -BeGreaterThan 4
        $ci['si_os_version'] | Should -Be '10.0.20348'
    }
    It 'an identity synchronised from Active Directory without its directory record: the same fields, and the same fields that cannot be decided' {
        $ci = Should-BeTheSameCi -What 'identity' -Records @(
            (IdRec 'entra' 'user' 'u1' @{ entra_object_id = 'u1'; si_upn = 'anna@contoso.com'; si_onprem_synced = $true; si_account_enabled = $true; si_password_last_changed = $script:Now.AddDays(-400); si_last_sign_in = $script:Now.AddDays(-2) }),
            (IdRec 'eg' 'user' 'n1' @{ eg_node_id = 'n1'; si_upn = 'anna@contoso.com'; si_is_sensitive_account = $true }))
        $ci['si_identity_origin'] | Should -Be 'synced'
        @($ci['si_unknown_fields']).Count | Should -BeGreaterThan 0 -Because 'the fields Active Directory decides for a synchronised account are unknown without its record -- also when no record carries them'
    }
    It 'records given as dictionaries, a name written in another case: found as Get-SIItemValue finds it' {
        $h = New-Object System.Collections.Hashtable ([StringComparer]::Ordinal)
        foreach ($p in @(@('si_provider', 'mde'), @('si_record_type', 'device'), @('si_record_key', 'mde:m7'), @('si_class', 'device'), @('si_collection_time', $script:Now.AddHours(-1)),
                @('si_collection_complete', $true), @('si_source_last_seen', $script:Now.AddDays(-1)), @('SI_OS_VERSION', '10.0.20348'), @('si_hostname', 'box7'))) { $h[$p[0]] = $p[1] }
        $o = [ordered]@{ si_provider = 'entra'; si_record_type = 'device'; si_record_key = 'entra:e7'; si_class = 'device'; si_collection_time = $script:Now.AddHours(-1)
            si_collection_complete = $true; si_source_last_seen = $script:Now.AddDays(-2); Si_Hostname = 'BOX7'; si_account_enabled = $true }
        $ci = Should-BeTheSameCi -What 'dictionaries' -Records @($h, $o)
        $ci['si_os_version'] | Should -Be '10.0.20348' -Because 'the key SI_OS_VERSION of a case-sensitive dictionary is the field si_os_version'
        $ci['si_hostname'] | Should -Not -BeNullOrEmpty
    }
    It 'a field no record carries is not asked for at all' {
        $recs = @((Rec 'mde' 'm1' $script:Now.AddDays(-1) @{ si_os_version = '10.0.20348'; si_hostname = 'srv01' }), (Rec 'ad' 'a1' $script:Now.AddDays(-3) @{ si_fqdn = 'srv01.contoso.local' }))
        $plan = @(Get-SICiFieldPlan -Catalog $script:Cat)
        $carried = @($recs | ForEach-Object { $_.PSObject.Properties.Name } | Select-Object -Unique)
        $expected = @($plan | Where-Object { $carried -contains $_.Name }).Count
        $expected | Should -BeGreaterThan 2
        $expected | Should -BeLessThan 20
        $plan.Count | Should -BeGreaterThan 300 -Because 'the catalog''s resolved fields'
        Mock Resolve-SICiField { $null }
        $null = Ci $recs
        Should -Invoke Resolve-SICiField -Exactly -Times $expected -Scope It
    }
    It 'the field plan: the resolved fields in catalog order, read once for a set of CIs -- a CI built with it is the CI built without it' {
        $plan = @(Get-SICiFieldPlan -Catalog $script:Cat)
        $want = @($script:Cat.fields | Where-Object { [string]$_.level -eq 'both' -and [string]$_.resolution.policy -ne 'computed' } | ForEach-Object { [string]$_.name })
        (@($plan | ForEach-Object { $_.Name }) -join ',') | Should -BeExactly ($want -join ',')
        @($plan | Where-Object { $_.Name -in 'si_class', 'si_collection_time', 'si_run_id' }).Count | Should -Be 0 -Because 'a computed field is SecurityInsight''s own on the CI'
        $by = @($script:Cat.fields | Where-Object { [string]$_.level -eq 'both' -and $_.resolution -and $null -ne (Get-SIItemValue $_.resolution 'byOrigin') } | ForEach-Object { [string]$_.name })
        $by.Count | Should -BeGreaterThan 0
        (@($plan | Where-Object { $_.ByOrigin } | ForEach-Object { $_.Name }) -join ',') | Should -BeExactly ($by -join ',')
        foreach ($e in $plan) { $e.Identity | Should -Be (@($e.Field.classes) -contains 'identity') }
        $recs = @(
            (IdRec 'entra' 'user' 'u1' @{ entra_object_id = 'u1'; si_upn = 'anna@contoso.com'; si_onprem_synced = $true; si_password_last_changed = $script:Now.AddDays(-400) }),
            (IdRec 'ad' 'user' 'a1' @{ ad_sid = 's-1-5-21-1'; si_upn = 'anna@contoso.com'; si_password_last_changed = $script:Now.AddDays(-30) }))
        $feeds = Get-SIFeedLatest -Records $recs
        $a = New-SICiDocument -CiId 'ci-1' -Records $recs -Catalog $script:Cat -FeedLatest $feeds -Now $script:Now
        $b = New-SICiDocument -CiId 'ci-1' -Records $recs -Catalog $script:Cat -FeedLatest $feeds -Now $script:Now -FieldPlan $plan
        (ConvertTo-Json -InputObject $b -Compress -Depth 12) | Should -BeExactly (ConvertTo-Json -InputObject $a -Compress -Depth 12)
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')) | Should -Match '(?s)\$fieldPlan = @\(Get-SICiFieldPlan -Catalog \$Model\[''field-catalog''\]\)\s+(#[^\r\n]*\s+)*\$byCid = \[ordered\]@\{\}\s+foreach \(\$d in @\(\$idy\.Decisions\)\).*foreach \(\$d in \$one\).*-FieldPlan \$fieldPlan' -Because 'the build reads the plan once for a batch, before its CIs'
    }
}
