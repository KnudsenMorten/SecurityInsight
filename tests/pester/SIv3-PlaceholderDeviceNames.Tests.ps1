#Requires -Version 5.1
<#
    A SOURCE'S PLACEHOLDER NAME IS NEVER A CI'S NAME (REQUIREMENTS #1054, found 2026-11-02 in the owner's data-quality sweep
    at the pilot: 29 active devices named "dummydevicename" -- Defender's placeholder for a device it has no name for; a person
    cannot tell them apart in the CI overview, the reports or ServiceNow).

    What these tests keep true (engine\data-model\SI-CiBuild.ps1, SI-CiBuildRun.ps1, engine\pro-data\_shared\
    SI-CorrelationSuspects.ps1):
      * the CI takes its name from ANOTHER linked source (Entra / Intune / Azure) when Defender gives the placeholder -- the
        authority order of the field catalog decides among the others; the placeholder is named in si_field_sources, never
        listed as a conflicting value;
      * when no linked source has a name: a clear generated name 'unnamed-device-<short id>' (the shared stand-in of
        SI-AssetName.ps1: deterministic, unique per device, 'unnamed-' prefix), si_field_sources says from = generated;
      * the list is the data model's placeholder_device_names (the customer's override wins) -- the same list the correlation
        check reads; a real name is untouched; an identity's name is never touched;
      * a placeholder name never joins devices: three Defender devices named "dummydevicename" stay three CIs with three names;
      * THE DATA-QUALITY FLAG: the correlation check (#1053, rule placeholder) lists a CI the build named, in the group of the
        placeholder its records carry (on a real SQL Server: .\SQLEXPRESS on the test VM, when running).
    pwsh 7 (PS 5.1 syntax).
#>

BeforeDiscovery {
    $script:LocalSql = $false
    try { $script:LocalSql = (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction Stop).Status -eq 'Running' -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
    if (-not (Get-Command -Name Sort-SIOrdinal -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\_shared\SI-AssetIdentity.ps1') }
    . (Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-CorrelationSuspects.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Cat = $script:Model['field-catalog']
    $script:T = [datetime]::SpecifyKind([datetime]'2026-11-02T06:00:00', [DateTimeKind]::Utc)

    function script:Rec([string]$p, [string]$rt, [string]$cls, [string]$native, [hashtable]$f) {
        $o = [ordered]@{ si_provider = $p; si_record_type = $rt; si_class = $cls; si_record_key = "${p}:$native"; si_collection_time = $script:T
            si_source_last_seen = $script:T.AddHours(-1); si_collection_complete = $true }
        foreach ($k in $f.Keys) { $o[$k] = $f[$k] }
        [pscustomobject]$o
    }
    function script:Doc([object[]]$Records, [string[]]$Names) {
        $a = @{ CiId = 'ci-1'; Records = $Records; Catalog = $script:Cat; FeedLatest = (Get-SIFeedLatest -Records $Records); Now = $script:T }
        if ($PSBoundParameters.ContainsKey('Names')) { $a['PlaceholderNames'] = $Names }
        New-SICiDocument @a
    }
    $script:MdeId = '3f1b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d'
}

Describe 'the name comes from another linked source when Defender gives the placeholder' {
    It 'Defender says dummydevicename, Entra knows the device: the CI is named by Entra, the placeholder is recorded, not a conflict' {
        $mde = Rec mde device device $script:MdeId @{ mde_device_id = $script:MdeId; entra_device_id = 'e-1'; si_asset_name = 'dummydevicename' }
        $ent = Rec entra device device 'e-1' @{ entra_device_id = 'e-1'; si_asset_name = 'pc-finance-07' }
        $ci = Doc @($mde, $ent)
        $ci['si_asset_name'] | Should -Be 'pc-finance-07'
        $src = $ci['si_field_sources']['si_asset_name']
        $src.provider | Should -Be 'entra'
        $src.placeholder | Should -Be 'dummydevicename'
        $src.placeholder_record | Should -Be "mde:$($script:MdeId)"
        $src.Contains('conflicts') | Should -BeFalse -Because 'a placeholder is no other opinion about the name'
    }
    It 'the placeholder is compared whole, trimmed and without case (DummyDeviceName); Intune names it when Entra does not' {
        $mde = Rec mde device device $script:MdeId @{ mde_device_id = $script:MdeId; si_asset_name = ' DummyDeviceName ' }
        $int = Rec intune device device 'i-1' @{ mde_device_id = $script:MdeId; si_asset_name = 'lab-kiosk-3' }
        (Doc @($mde, $int))['si_asset_name'] | Should -Be 'lab-kiosk-3'
        (Test-SICiPlaceholderName -Value 'dummydevicename-2' -Names @('dummydevicename')) | Should -BeFalse -Because 'compared whole: a real name that starts like it is a real name'
    }
    It 'the other sources keep the catalog''s authority order among themselves (Intune before Entra before Azure)' {
        $mde = Rec mde device device $script:MdeId @{ mde_device_id = $script:MdeId; si_asset_name = 'dummydevicename' }
        $ent = Rec entra device device 'e-1' @{ mde_device_id = $script:MdeId; si_asset_name = 'from-entra' }
        $int = Rec intune device device 'i-1' @{ mde_device_id = $script:MdeId; si_asset_name = 'from-intune' }
        $az = Rec azure azure_resource device '/subscriptions/s/vm/x' @{ mde_device_id = $script:MdeId; si_asset_name = 'from-azure' }
        (Doc @($mde, $ent, $int, $az))['si_asset_name'] | Should -Be 'from-intune'
    }
    It 'a real Defender name is untouched -- and the field source carries no placeholder' {
        $mde = Rec mde device device $script:MdeId @{ mde_device_id = $script:MdeId; si_asset_name = 'srv-app-01.contoso.local' }
        $ent = Rec entra device device 'e-1' @{ mde_device_id = $script:MdeId; si_asset_name = 'srv-app-01' }
        $ci = Doc @($mde, $ent)
        $ci['si_asset_name'] | Should -Be 'srv-app-01.contoso.local'
        $ci['si_field_sources']['si_asset_name'].Contains('placeholder') | Should -BeFalse
    }
}

Describe 'no linked source has a name: a clear generated name' {
    It 'unnamed-device- plus a short id from the Defender device id -- deterministic, recognisable, from = generated' {
        $mde = Rec mde device device $script:MdeId @{ mde_device_id = $script:MdeId; si_asset_name = 'dummydevicename' }
        $ci = Doc @($mde)
        $ci['si_asset_name'] | Should -Be 'unnamed-device-1a2b3c4d'
        (Test-SISyntheticAssetName -Value $ci['si_asset_name']) | Should -BeTrue
        $src = $ci['si_field_sources']['si_asset_name']
        $src.from | Should -Be 'generated'
        $src.placeholder | Should -Be 'dummydevicename'
        $src.provider | Should -Be 'mde'
        (Doc @($mde))['si_asset_name'] | Should -Be $ci['si_asset_name'] -Because 'the same device gets the same name on every build'
    }
    It 'every placeholder of the list counts (unknown, localhost, (none), n/a) -- and never a blank name' {
        foreach ($n in 'unknown', 'localhost', '(none)', 'n/a') {
            $mde = Rec mde device device $script:MdeId @{ mde_device_id = $script:MdeId; si_asset_name = $n }
            (Doc @($mde))['si_asset_name'] | Should -Be 'unnamed-device-1a2b3c4d'
        }
    }
    It 'a placeholder on an Azure VM''s CI (Defender before Azure in the authority order) gives way to the Azure name' {
        $mde = Rec mde device device $script:MdeId @{ mde_device_id = $script:MdeId; azure_resource_id = '/subscriptions/s/vm/vm-07'; si_asset_name = 'dummydevicename' }
        $az = Rec azure azure_resource cloud_resource '/subscriptions/s/vm/vm-07' @{ azure_resource_id = '/subscriptions/s/vm/vm-07'; si_asset_name = 'vm-07' }
        (Doc @($mde, $az))['si_asset_name'] | Should -Be 'vm-07'
    }
    It 'an identity is never touched (the list is device names)' {
        $u = Rec entra user identity 'u-1' @{ entra_object_id = 'u-1'; si_asset_name = 'unknown' }
        (Doc @($u))['si_asset_name'] | Should -Be 'unknown'
    }
}

Describe 'a placeholder name never joins devices' {
    It 'three Defender devices named dummydevicename: three groups, three CIs, three different names' {
        $ids = @('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa11111111', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa22222222', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa33333333')
        $recs = @(foreach ($i in $ids) { Rec mde device device $i @{ mde_device_id = $i; si_asset_name = 'dummydevicename' } })
        $g = Get-SICiGroups -Records $recs
        @($g.Groups).Count | Should -Be 3
        $names = @(foreach ($grp in $g.Groups) { (Doc @($grp.Members | ForEach-Object Record))['si_asset_name'] })
        @($names | Sort-Object -Unique) | Should -Be @('unnamed-device-11111111', 'unnamed-device-22222222', 'unnamed-device-33333333')
        ($script:Cat.fields | Where-Object name -eq 'si_asset_name').join | Should -Be 'weak' -Because 'a name is never a join key of the grouping'
    }
}

Describe 'the list: the data model''s placeholder_device_names, the customer''s override wins' {
    It 'the shipped list equals the CI build''s and the correlation check''s fall-back' {
        $l = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'data-model\lists.locked.json') | ConvertFrom-Json
        $ph = @(@($l.lists | Where-Object { $_.id -eq 'placeholder_device_names' })[0].values)
        ($ph -join '|') | Should -Be ((Get-SICiPlaceholderNames) -join '|')
        ($ph -join '|') | Should -Be ((Get-SICiPlaceholderNames -Model $script:Model) -join '|')
        ($ph -join '|') | Should -Be (@($script:SICorrelationSuspects.PlaceholderDefault) -join '|')
    }
    It 'an override list (the merged model) is what counts: dummydevicename is then a name like any other' {
        $m = @{ lists = [pscustomobject]@{ lists = @([pscustomobject]@{ id = 'placeholder_device_names'; values = @(' NoName ') }) } }
        $names = Get-SICiPlaceholderNames -Model $m
        $names | Should -Be @('noname')
        $mde = Rec mde device device $script:MdeId @{ mde_device_id = $script:MdeId; si_asset_name = 'dummydevicename' }
        (Doc @($mde) -Names $names)['si_asset_name'] | Should -Be 'dummydevicename'
        $mde2 = Rec mde device device $script:MdeId @{ mde_device_id = $script:MdeId; si_asset_name = 'NoName' }
        (Doc @($mde2) -Names $names)['si_asset_name'] | Should -Be 'unnamed-device-1a2b3c4d'
    }
    It 'wired: the CI build reads the list once per set from the model and hands it to every CI' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1'))
        $src | Should -Match ([regex]::Escape('$placeholderNames = Get-SICiPlaceholderNames -Model $Model'))
        $src | Should -Match ([regex]::Escape('-PlaceholderNames $placeholderNames'))
    }
    It 'the CI build version is bumped: every CI is rebuilt once and takes its new name' {
        . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildSql.ps1')
        $script:SICiBuildVersion | Should -BeGreaterOrEqual 12
    }
}

Describe 'the data-quality flag: the correlation check lists a CI the build named' {
    It 'the statement takes in the generated names, in the group of the placeholder their records carry' {
        $sql = Get-SICorrelationSuspectSql -HasOsFamily -HasHostname -HasDecision
        $sql | Should -Match ([regex]::Escape("WHERE x.Name LIKE N'unnamed-device-%' AND NOT EXISTS"))
        $sql | Should -Match ([regex]::Escape("N'unnamed-device') AS Ph"))
    }
    It 'on a real SQL Server: literal and generated names in ONE placeholder group; a named device is not listed' -Skip:(-not $script:LocalSql) {
        $schema = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'sql\si-data-schema.sql')
        $db = 'siph_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $mk = {
            param([string]$Db)
            $cs = "Server=.\SQLEXPRESS;Database=$Db;Integrated Security=True;TrustServerCertificate=True"
            {
                param([string]$sql, $p, [string]$mode)
                $cn = New-Object System.Data.SqlClient.SqlConnection($cs); $cn.Open()
                try {
                    $c = $cn.CreateCommand(); $c.CommandTimeout = 600; $c.CommandText = $sql
                    if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                    if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                    if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                    $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                    do { $rows.Clear(); while ($r.Read()) { $h = @{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { $null } else { $r.GetValue($i) }) }; $rows.Add($h) } } while ($r.NextResult())
                    $r.Close(); return , $rows.ToArray()
                } finally { $cn.Close() }
            }.GetNewClosure()
        }
        $master = & $mk 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = & $mk $db
            [void](& $inv $schema @{} 'nonquery')
            [void](& $inv @'
DECLARE @t DATETIME2(3) = SYSUTCDATETIME();
INSERT sidata.Ci (CiId, Class, Name, AssetType, Tier, TierSetBy, Lifecycle, OpenFindings, WeightedRiskScore, CollectionTime) VALUES
 (N'ci-lit', N'device', N'dummydevicename', N'Workstation', 3, N'default', N'active', 2, 2, @t),
 (N'ci-gen-1', N'device', N'unnamed-device-11111111', N'Workstation', 3, N'default', N'active', 5, 5, @t),
 (N'ci-gen-2', N'device', N'unnamed-device-22222222', N'Workstation', 3, N'default', N'active', 0, 0, @t),
 (N'ci-gen-old', N'device', N'unnamed-device-33333333', N'Workstation', 3, N'default', N'retired', 9, 9, @t),
 (N'ci-named', N'device', N'pc-finance-07', N'Workstation', 3, N'default', N'active', 1, 1, @t);
INSERT sidata.CiLink (CiId, Provider, RecordType, NativeId, IsPrimary, State, LastSeen) VALUES
 (N'ci-lit', N'mde', N'device', N'l1', 1, N'active', @t), (N'ci-gen-1', N'mde', N'device', N'g1', 1, N'active', @t),
 (N'ci-gen-2', N'mde', N'device', N'g2', 1, N'active', @t), (N'ci-named', N'mde', N'device', N'n1', 1, N'active', @t),
 (N'ci-named', N'entra', N'device', N'e1', 1, N'active', @t);
INSERT sidata.CiRecord (RecordKey, CiId, Provider, RecordType, Class, Name, CollectionTime) VALUES
 (N'mde:l1', N'ci-lit', N'mde', N'device', N'device', N'dummydevicename', @t),
 (N'mde:g1', N'ci-gen-1', N'mde', N'device', N'device', N'dummydevicename', @t),
 (N'mde:g2', N'ci-gen-2', N'mde', N'device', N'device', N'DummyDeviceName', @t),
 (N'mde:n1', N'ci-named', N'mde', N'device', N'device', N'dummydevicename', @t),
 (N'entra:e1', N'ci-named', N'entra', N'device', N'device', N'pc-finance-07', @t);
INSERT sidata.RecordIdentifier (RecordKey, IdType, IdValue, SeenAt) VALUES
 (N'mde:l1', N'MdeDeviceId', N'l1', @t), (N'mde:g1', N'MdeDeviceId', N'g1', @t), (N'mde:g2', N'MdeDeviceId', N'g2', @t),
 (N'mde:n1', N'MdeDeviceId', N'n1', @t), (N'entra:e1', N'AadDeviceId', N'e1', @t);
'@ @{} 'nonquery')
            $r = Invoke-SICorrelationSuspects -Invoke $inv -Log { param($l, $m) }
            $r.Status | Should -Be 'ok'
            $ph = @($r.Groups | Where-Object Rule -eq 'placeholder')
            $ph.Count | Should -Be 1 -Because 'one placeholder, one group: the devices still named by it and the ones the build named'
            $ph[0].Label | Should -Be 'dummydevicename'
            @($ph[0].Members | ForEach-Object CiId | Sort-Object) | Should -Be @('ci-gen-1', 'ci-gen-2', 'ci-lit') -Because 'the device named by Entra is fine; a retired one is never counted'
            @($ph[0].Members | ForEach-Object Name | Sort-Object) | Should -Be @('dummydevicename', 'unnamed-device-11111111', 'unnamed-device-22222222')
            [int](& $inv "SELECT COUNT(*) FROM sidata.CiSuspect WHERE CiId = N'ci-gen-1' AND Evidence LIKE N'no linked source has a name for it (a source gives the placeholder dummydevicename): SecurityInsight named it unnamed-device-11111111'" @{} 'scalar') | Should -Be 1
            $r.Issue | Should -Match '3 device\(s\) with a placeholder name'
            @($r.Groups | Where-Object Rule -eq 'name').Count | Should -Be 0 -Because 'a placeholder or a generated name never makes two CIs one machine'
        } finally {
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            for ($try = 1; $try -le 5; $try++) { try { [void](& $master "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]" @{} 'nonquery'); break } catch { if ($try -eq 5) { throw }; Start-Sleep -Seconds 3 } }
        }
    }
}
