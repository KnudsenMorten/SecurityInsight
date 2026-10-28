#Requires -Version 5.1
<#
    #729 -- THE UPDATER COULD NOT READ THE TENANT'S SIZE (found 2026-10-16: a 153,000-user tenant ran every sized job on
    2 CPU / 4 GiB). The updater's identity has no directory read, so its Microsoft Graph $count is refused.

    The size is now known WITHOUT a new right for anyone: the identity and endpoint collections already count the directory
    (Microsoft Graph $count, with the collection's own directory rights) before they read it, and record those counts in
    the Pro database -- cfg.InstallState 'TenantSize', a table the engine role already writes and the updater already reads
    (engine\_shared\SI-TenantSizeMark.ps1). The update's job-size rule reads them right after its own Graph read.

    OFFLINE: the store is a fake that records each statement; the REAL SQL context (the test VM's SQL Express) runs the
    shipped statement against the shipped cfg.InstallState -- both collections at once keep both halves.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TenantSizeMark.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-JobSizing.ps1')
    $script:T = [datetime]::SpecifyKind([datetime]'2026-10-16T02:10:00', 'Utc')
    function script:New-FakeStore {
        $log = New-Object System.Collections.Generic.List[object]
        [pscustomobject]@{ Log = $log; Invoke = { param([string]$sql, $p, [string]$mode) $log.Add([pscustomobject]@{ Sql = $sql; P = $p; Mode = $mode }) }.GetNewClosure() }
    }
}

Describe 'the collection records the counts it read -- its own half, never a 0 for a count it did not read' {
    It 'identity: users, groups, service principals with their time; the device half is left as it is' {
        $p = ConvertTo-SITenantSizeMarkParams -Counts @{ Users = 153000; ServicePrincipals = 4100; Groups = 21000 } -NowUtc $script:T
        $p.Users | Should -Be '153000'; $p.Groups | Should -Be '21000'; $p.ServicePrincipals | Should -Be '4100'
        $p.Devices | Should -Be '' -Because 'the identity collection did not count the devices'
        $p.IdentityAt | Should -Be '2026-10-16T02:10:00Z'; $p.DevicesAt | Should -Be ''
        $p.Name | Should -Be 'TenantSize'
    }
    It 'endpoint: the devices only; a count that could not be read (null, negative, not a number) is not written; nothing read -> nothing written' {
        $p = ConvertTo-SITenantSizeMarkParams -Counts @{ Devices = 38000; Users = $null } -NowUtc $script:T
        $p.Devices | Should -Be '38000'; $p.DevicesAt | Should -Be '2026-10-16T02:10:00Z'
        $p.Users | Should -Be ''; $p.IdentityAt | Should -Be ''
        (ConvertTo-SITenantSizeMarkParams -Counts @{ Users = 10; Groups = $null; ServicePrincipals = 'x' } -NowUtc $script:T).Groups | Should -Be ''
        ConvertTo-SITenantSizeMarkParams -Counts @{ Users = $null; Devices = -1 } | Should -BeNullOrEmpty
        ConvertTo-SITenantSizeMarkParams -Counts @{} | Should -BeNullOrEmpty
    }
    It 'ONE statement merges the half under an update lock (both collections run at the same time); a 0 is written only when the directory said 0' {
        $s = New-FakeStore
        Save-SITenantSizeMark -Store $s -Counts @{ Users = 0; ServicePrincipals = 5 } -NowUtc $script:T | Should -BeTrue
        $s.Log.Count | Should -Be 1
        $s.Log[0].Mode | Should -Be 'nonquery'
        $s.Log[0].Sql | Should -Match 'WITH \(UPDLOCK, HOLDLOCK\)'
        $s.Log[0].Sql | Should -Match "JSON_MODIFY\(@v, '\`$\.users', CONVERT\(bigint, @Users\)\)"
        $s.Log[0].Sql | Should -Match "IF @Devices <> N'' SET"
        $s.Log[0].P.Users | Should -Be '0'
        Save-SITenantSizeMark -Store $s -Counts @{ Users = $null } | Should -BeFalse
        $s.Log.Count | Should -Be 1 -Because 'nothing read, nothing written'
    }
    It 'from the run: the Pro database the run already opened; none (Community) -> nothing, silently; a failure is one line and never fails the run' {
        $saved = $null
        Invoke-SITenantSizeMarkSave -Counts @{ Users = 7 } -OnSave { param($c) $script:SavedC = $c } -Log { } | Should -BeTrue
        $script:SavedC.Users | Should -Be 7
        $keep = $global:SI_ProSettingsStore
        try {
            $global:SI_ProSettingsStore = $null
            Invoke-SITenantSizeMarkSave -Counts @{ Users = 7 } -Log { param($l) $script:L = $l } | Should -BeFalse
            $global:SI_ProSettingsStore = [pscustomobject]@{ Invoke = { param($a, $b, $c) throw 'The INSERT permission was denied' } }
            $script:L = ''
            Invoke-SITenantSizeMarkSave -Counts @{ Users = 7 } -Log { param($l) $script:L = $l } | Should -BeFalse
            $script:L | Should -Match 'could not be recorded.*INSERT permission was denied.*other sources'
            $f = New-FakeStore; $global:SI_ProSettingsStore = $f
            Invoke-SITenantSizeMarkSave -Counts @{ Devices = 12 } -Log { param($l) $script:L = $l } | Should -BeTrue
            $f.Log.Count | Should -Be 1
        } finally { $global:SI_ProSettingsStore = $keep }
    }
    It 'the value reads back: counts as numbers, the times as written; anything unusable is nothing' {
        $c = ConvertFrom-SITenantSizeMark -Value '{"users":153000,"groups":21000,"servicePrincipals":4100,"devices":38000,"identityAt":"2026-10-16T02:10:00Z","devicesAt":"2026-10-16T02:12:00Z"}'
        $c.Users | Should -Be 153000; $c.Devices | Should -Be 38000; $c.IdentityAt | Should -Be '2026-10-16T02:10:00Z'; $c.DevicesAt | Should -Be '2026-10-16T02:12:00Z'
        ConvertFrom-SITenantSizeMark -Value '' | Should -BeNullOrEmpty
        ConvertFrom-SITenantSizeMark -Value '{"users":0}' | Should -BeNullOrEmpty -Because 'a 0 is not a size'
        ConvertFrom-SITenantSizeMark -Value '{' | Should -BeNullOrEmpty
    }
}

Describe 'WIRING: the collections record what they count; no identity gets a new right' {
    BeforeAll { $script:Disc = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Discover.ps1')) }
    It 'the identity collection records users + service principals (the counts it streams by) and groups; the endpoint collection its devices' {
        $script:Disc | Should -Match '\$__tsCounts = @\{ Users = \$sc\.Users; ServicePrincipals = \$sc\.ServicePrincipals; Groups = \$__tsGroups \}'
        $script:Disc | Should -Match "Get-SIGraphObjectCount -Collection 'groups'"
        $script:Disc | Should -Match '\$__tsCounts = @\{ Devices = \$streamObjects \}'
        $script:Disc | Should -Match 'Invoke-SITenantSizeMarkSave -Counts \$__tsCounts'
        # after the counts were read, before the streams are made -- and inside a try: it never fails a collection
        $i = $script:Disc.IndexOf('Invoke-SITenantSizeMarkSave -Counts'); $i | Should -BeGreaterThan $script:Disc.IndexOf('Get-SIIdentityDiscoverCount -Token')
        $i | Should -BeLessThan $script:Disc.IndexOf('$global:SI_DiscoverStream = New-SIDiscoverStream')
    }
    # the Pro settings files are not in the Community copy: this check runs where they are (Test-Path)
    It 'the engine role already writes cfg.InstallState (no new grant); the updater reads it from the database it already reads -- not the directory' -Skip:(-not (Test-Path -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', 'pro-settings')))) {
        . (Join-Path $script:SIRoot 'engine\pro-settings\SI-EngineGrants.ps1')
        $g = @($script:SIEngineObjectGrants | Where-Object { $_.Object -eq 'cfg.InstallState' })[0]
        $g.Verbs | Should -Match 'INSERT'; $g.Verbs | Should -Match 'UPDATE'; $g.Verbs | Should -Match 'SELECT'
        $script:SIJobSizingTenantMarkSql | Should -Match "SELECT Value FROM cfg\.InstallState WHERE Name = N'TenantSize'"
        $u = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $u | Should -Match 'Invoke-SIJobSizing -Rest \$rest .*\r?\n?.*-SqlRows \$sqlRows'
    }
}

Describe 'REAL SQL (test VM, SQL Express): the shipped statement against the shipped cfg.InstallState' -Skip:(-not [bool](Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running') -or
        -not (Test-Path -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'sql', 'si-pro-settings.sql')))) {
    BeforeAll {
        $script:DbName = 'si_test_ts_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$($script:DbName)]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Cs = "Server=.\SQLEXPRESS;Database=$($script:DbName);Integrated Security=SSPI;Connection Timeout=30;Pooling=false"
        $pro = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-pro-settings.sql'))
        $blk = [regex]::Match($pro, "(?s)IF OBJECT_ID\('cfg\.InstallState'\) IS NULL\s+CREATE TABLE cfg\.InstallState \(.*?\n\);").Value
        $blk | Should -Not -BeNullOrEmpty
        # the store's reader, as New-SIProSettingsStore runs it (parameters as text) -- on a local connection
        $script:Inv = {
            param([string]$sql, $p, [string]$mode)
            $cn = New-Object System.Data.SqlClient.SqlConnection($script:Cs); $cn.Open()
            try {
                $cmd = $cn.CreateCommand(); $cmd.CommandText = $sql; $cmd.CommandTimeout = 60
                if ($p) { foreach ($k in $p.Keys) { [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [System.DBNull]::Value } else { $p[$k] })) } }
                switch ($mode) {
                    'reader' { $rd = $cmd.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]; while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) }; $rd.Close(); , $out.ToArray() }
                    default { [void]$cmd.ExecuteNonQuery() }
                }
            } finally { $cn.Dispose() }
        }
        $script:Store = [pscustomobject]@{ Invoke = $script:Inv }
        $null = & $script:Inv "IF SCHEMA_ID('cfg') IS NULL EXEC ('CREATE SCHEMA cfg');" @{} 'nonquery'
        $null = & $script:Inv $blk @{} 'nonquery'
        function script:ReadMark { $r = @(& $script:Inv $script:SIJobSizingTenantMarkSql @{} 'reader' | ForEach-Object { $_ }); Get-SIJobSizingCountsFromTenantMark -Rows $r }
    }
    AfterAll {
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        try { $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'; $m.Open(); $c = $m.CreateCommand(); $c.CommandText = "ALTER DATABASE [$($script:DbName)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:DbName)]"; [void]$c.ExecuteNonQuery(); $m.Dispose() } catch { }
    }
    It 'nothing recorded: the updater reads nothing; identity then endpoint: both halves kept; a new identity count replaces only its own half' {
        ReadMark | Should -BeNullOrEmpty
        Save-SITenantSizeMark -Store $script:Store -Counts @{ Users = 153000; Groups = 21000; ServicePrincipals = 4100 } -NowUtc $script:T | Should -BeTrue
        $c = ReadMark; $c.Users | Should -Be 153000; $c.Devices | Should -Be 0
        Save-SITenantSizeMark -Store $script:Store -Counts @{ Devices = 38000 } -NowUtc $script:T.AddMinutes(2) | Should -BeTrue
        $c = ReadMark; $c.Users | Should -Be 153000; $c.Groups | Should -Be 21000; $c.ServicePrincipals | Should -Be 4100; $c.Devices | Should -Be 38000
        Save-SITenantSizeMark -Store $script:Store -Counts @{ Users = 154000; Groups = $null; ServicePrincipals = 4200 } -NowUtc $script:T.AddDays(1) | Should -BeTrue
        $c = ReadMark; $c.Users | Should -Be 154000; $c.Groups | Should -Be 21000 -Because 'a count not read this time keeps the last one'; $c.Devices | Should -Be 38000
        $raw = [string](@(& $script:Inv "SELECT Value FROM cfg.InstallState WHERE Name = N'TenantSize'" @{} 'reader')[0].Value)
        $raw | Should -Match '"identityAt":"2026-10-17T02:10:00Z"'; $raw | Should -Match '"devicesAt":"2026-10-16T02:12:00Z"'
        $raw.Length | Should -BeLessThan 400
        # and the whole rule: the updater sizes from it
        (Resolve-SIJobSizingCounts -Collected (ReadMark)).From | Should -Match 'cfg\.InstallState TenantSize'
    }
    It 'a value that is not JSON (written by hand) is replaced, never merged into' {
        $null = & $script:Inv "UPDATE cfg.InstallState SET Value = N'garbage' WHERE Name = N'TenantSize'" @{} 'nonquery'
        Save-SITenantSizeMark -Store $script:Store -Counts @{ Devices = 5 } -NowUtc $script:T | Should -BeTrue
        $c = ReadMark; $c.Devices | Should -Be 5; $c.Users | Should -Be 0
    }
}
