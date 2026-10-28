#Requires -Version 5.1
<#
    PROVIDER RECORDS IN SQL (engine/data-model/SI-RecordSql.ps1) -- #477, V3-DATA-MODEL 2.20 step 1.

      * ITEMS: a batch of record rows -> sidata.CiRecord items (key, provider, type, class, name, the provider's own
        last-seen, collection time, complete, the row as JSON, its CONTENT HASH) and sidata.RecordIdentifier items -- the
        SAME strong identifiers the CI build groups on (Get-SIRecordIdentifiers); a row without a key is left out.
      * HASH (#501): the same content gives the same hash whatever the key order; the per-run fields (collection time,
        complete, source last seen, run id) are left out -- a record that did not change has the same hash every run.
      * WRITE: one statement per batch with the items as JSON; only CHANGED records get their JSON and identifiers
        rewritten, unchanged ones only their per-run columns; it answers Seen / Changed; an empty batch is not sent; a
        failure is a warning and Failed = the batch, never a failed run.
      * SEAM: no database configured -> nothing is written; a configured one -> a seam that calls the database with the
        server and database as literals (a quote in a name cannot break out).
      * PUBLISH: records go to the DATABASE only (operator 2026-10-09: "we dont support la for correlation, sql only").
        Nothing is posted to Log Analytics unless SI_LaExport = records (the optional one-way copy); no database is said.
    (The schema itself is a Pro file: its tables and the identifier index are checked in SIv3-DataSync.)
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordSql.ps1')
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-08T21:00:00', [DateTimeKind]::Utc)
    # PowerShell 5.1 hands a parsed JSON array down the pipeline as ONE object: parse, then count
    function script:JItems([string]$j) { $a = ConvertFrom-Json -InputObject $j; @($a | ForEach-Object { $_ }) }
    function script:JCount([string]$j) { @(JItems $j).Count }
    function script:Row([string]$key, [hashtable]$extra = @{}) {
        $h = [ordered]@{ si_record_key = $key; si_provider = 'entra'; si_record_type = 'user'; si_class = 'identity'; si_asset_name = "name-$key"
            si_collection_time = $script:Now; si_collection_complete = $true }
        foreach ($k in $extra.Keys) { $h[$k] = $extra[$k] }
        [pscustomobject]$h
    }
    # a seam answering the write statement's one row (Seen = the batch, Changed = all of it)
    # (the publish also saves what the sources offered -- continuous discovery, another statement: answered here, not counted)
    function script:WriteSeam { { param($Sql, $Params, $Mode) if (-not $Params.ContainsKey('r')) { return [pscustomobject]@{ Properties = 0; Added = 0; NewContext = 0 } }; $script:Calls.Add(@{ Sql = $Sql; Params = $Params; Mode = $Mode }); $c = JCount $Params.r; [pscustomobject]@{ Seen = $c; Changed = $c; Identifiers = (JCount $Params.i) } } }
}

Describe 'Record rows -> database items' {
    It 'makes one record item per row and the strong identifiers the CI build groups on' {
        $seen = [datetime]::SpecifyKind([datetime]'2026-10-07T10:00:00', [DateTimeKind]::Utc)
        $rows = @(
            (Row 'entra|user|u1' @{ entra_object_id = 'AAA-1'; si_source_last_seen = $seen })
            (Row 'mde|device|d1' @{ si_provider = 'mde'; si_record_type = 'device'; si_class = 'device'; mde_device_id = 'M1'; entra_device_id = @('E1', 'E2'); si_collection_complete = $false })
            (Row '' @{ entra_object_id = 'NOKEY' })
        )
        $x = ConvertTo-SIRecordSqlItems -Rows $rows -Now $script:Now
        @($x.Records).Count | Should -Be 2
        $u = $x.Records[0]
        $u.RecordKey | Should -Be 'entra|user|u1'
        $u.Provider | Should -Be 'entra'; $u.Class | Should -Be 'identity'; $u.Name | Should -Be 'name-entra|user|u1'
        $u.Complete | Should -BeTrue
        ([datetime]$u.SourceLastSeen).ToUniversalTime() | Should -Be $seen
        ($u.DocJson | ConvertFrom-Json).entra_object_id | Should -Be 'AAA-1'
        $u.Hash | Should -Match '^[0-9A-F]{64}$'
        $x.Records[1].Complete | Should -BeFalse
        $ids = @($x.Identifiers | ForEach-Object { '{0}|{1}|{2}' -f $_.RecordKey, $_.IdType, $_.IdValue } | Sort-Object)
        $ids | Should -Be @('entra|user|u1|AadObjectId|aaa-1', 'mde|device|d1|AadDeviceId|e1', 'mde|device|d1|AadDeviceId|e2', 'mde|device|d1|MdeDeviceId|m1')
        # the same extraction as the CI build
        $ciIds = @((Get-SIRecordIdentifiers -Record $rows[1] -TypeMap (Get-SICiLedgerTypeMap)) | ForEach-Object { '{0}|{1}' -f $_.Type, $_.Value } | Sort-Object)
        @($x.Identifiers | Where-Object { $_.RecordKey -eq 'mde|device|d1' } | ForEach-Object { '{0}|{1}' -f $_.IdType, $_.IdValue } | Sort-Object) | Should -Be $ciIds
    }
}

Describe 'One record per key in a batch' {
    It 'keeps the LAST row of a key whole, with only its identifiers (keys compared without case, as the database does)' {
        $x = ConvertTo-SIRecordSqlItems -Rows @((Row 'k1' @{ entra_object_id = 'old'; si_asset_name = 'first' }), (Row 'k2'), (Row 'K1' @{ entra_object_id = 'new'; si_asset_name = 'last' })) -Now $script:Now
        @($x.Records | ForEach-Object { $_.RecordKey }) | Should -Be @('k2', 'K1')
        @($x.Records)[1].Name | Should -Be 'last'
        @($x.Identifiers | ForEach-Object { $_.IdValue }) | Should -Be @('new')
    }
}

Describe 'The content hash' {
    It 'is the same for the same content in any key order, and ignores the per-run fields' {
        $a = [ordered]@{ b = 2; a = 'x'; si_collection_time = '2026-10-08T00:00:00Z'; si_run_id = 'r1' }
        $b = [ordered]@{ a = 'x'; b = 2; si_collection_time = '2026-10-09T00:00:00Z'; si_run_id = 'r2' }
        $ex = @('si_collection_time', 'si_run_id')
        Get-SIContentHash -Item $a -Exclude $ex | Should -Be (Get-SIContentHash -Item $b -Exclude $ex)
        Get-SIContentHash -Item ([pscustomobject]$a) -Exclude $ex | Should -Be (Get-SIContentHash -Item $b -Exclude $ex) -Because 'an object and a dictionary hash alike'
        $b['b'] = 3
        Get-SIContentHash -Item $a -Exclude $ex | Should -Not -Be (Get-SIContentHash -Item $b -Exclude $ex)
    }
    It 'gives an unchanged record the same hash on the next run' {
        $r1 = ConvertTo-SIRecordSqlItems -Rows @((Row 'k1' @{ entra_object_id = 'o1'; si_run_id = 'r1' })) -Now $script:Now
        $r2 = ConvertTo-SIRecordSqlItems -Rows @((Row 'k1' @{ entra_object_id = 'o1'; si_run_id = 'r2'; si_collection_time = $script:Now.AddDays(1); si_collection_complete = $false })) -Now $script:Now
        $r2.Records[0].Hash | Should -Be $r1.Records[0].Hash
    }
}

Describe 'Writing a batch' {
    It 'sends one statement with the items as JSON and answers Seen / Changed' {
        $script:Calls = New-Object System.Collections.Generic.List[object]
        $r = Write-SIRecordsToSql -Rows @((Row 'k1' @{ entra_object_id = 'o1' }), (Row 'k2')) -Invoke (WriteSeam) -Now $script:Now
        ($r.Seen, $r.Changed, $r.Failed) | Should -Be @(2, 2, 0)
        $script:Calls.Count | Should -Be 1
        $c = $script:Calls[0]
        $c.Mode | Should -Be 'rows'
        $c.Sql | Should -Match 'MERGE sidata\.CiRecord'
        $c.Sql | Should -Not -Match 'UPDATE SET[^;]*CiId'          # the CI a record belongs to is the CI build's, never overwritten
        $c.Sql | Should -Match 'DELETE ri FROM sidata\.RecordIdentifier'
        $c.Sql | Should -Match 'INSERT sidata\.RecordIdentifier'
        JCount $c.Params.r | Should -Be 2
        (JItems $c.Params.i)[0].IdValue | Should -Be 'o1'
    }
    It 'rewrites only the records whose content hash changed (#501)' {
        $sql = Get-SIRecordSqlWriteSql
        $sql | Should -Match 't\.ContentHash IS NULL OR t\.ContentHash <> s\.Hash'
        $sql | Should -Match 'USING \(SELECT s\.\* FROM @s s JOIN @changed c'
        $sql | Should -Match 'RecordIdentifier ri WHERE ri\.RecordKey IN \(SELECT RecordKey FROM @changed\)'
        $sql | Should -Match 'WHERE s\.RecordKey NOT IN \(SELECT RecordKey FROM @changed\)' -Because 'an unchanged record gets only its per-run columns'
    }
    It 'sends a JSON array even for one record with no identifiers' {
        $script:P = $null
        $null = Write-SIRecordsToSql -Rows @((Row 'only')) -Invoke { param($Sql, $Params, $Mode) $script:P = $Params; [pscustomobject]@{ Seen = 1; Changed = 1 } } -Now $script:Now
        $script:P.r | Should -Match '^\['
        $script:P.i | Should -Be '[]'
    }
    It 'sends nothing for an empty batch, and a failure is a warning and the batch counted as failed' {
        $script:Hit = 0
        (Write-SIRecordsToSql -Rows @() -Invoke { $script:Hit++ }).Seen | Should -Be 0
        $script:Hit | Should -Be 0
        $w = $null
        $r = Write-SIRecordsToSql -Rows @((Row 'k1')) -Invoke { throw 'login failed' } -WarningVariable w 3>$null
        ($r.Seen, $r.Failed) | Should -Be @(0, 1)
        "$w" | Should -Match 'login failed'
        "$w" | Should -Match 'The next run writes them again'
    }
}

Describe 'The database seam' {
    It 'writes nothing when no database is configured' {
        New-SIRecordSqlInvoke -Server '' -Database 'db' | Should -BeNullOrEmpty
        New-SIRecordSqlInvoke -Server 'srv' -Database '' | Should -BeNullOrEmpty
    }
    It 'calls the database with the server and database as literals, a quote kept inside' {
        $s = New-SIRecordSqlInvoke -Server "srv.example.invalid" -Database "db'x"
        $s | Should -BeOfType [scriptblock]
        "$s" | Should -Match "-Server 'srv\.example\.invalid' -Database 'db''x'"
        Mock Invoke-SIRecordSqlDb { "$Server|$Database|$Mode|$($Params.r)" }
        & $s 'SELECT 1' @{ r = '[]' } 'scalar' | Should -Be "srv.example.invalid|db'x|scalar|[]"
    }
}

Describe 'Publishing writes the records to the database only' {
    BeforeEach {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        foreach ($i in 1..5) { Add-SIRecordPart -Provider entra -RecordType user -Key "U$i" -Part user -Object @{ id = "U$i"; displayName = "User $i" } }
        Set-SIRecordPull -Provider entra -Complete $true
        $script:Calls = New-Object System.Collections.Generic.List[object]
        $script:Posts = New-Object System.Collections.Generic.List[string]
        function global:Send-SIObjectMapRows { param($Rows, $TableName, $DcrName) $script:Posts.Add($TableName); @($Rows).Count }
    }
    AfterEach { Remove-Item Function:\global:Send-SIObjectMapRows -ErrorAction SilentlyContinue; Remove-Variable -Name SI_LaExport -Scope Global -ErrorAction SilentlyContinue }
    It 'writes every batch to the database and posts NOTHING to Log Analytics by default' {
        $saved = $script:SIRecordBatchSize
        try {
            $script:SIRecordBatchSize = 2
            $r = Publish-SIRecords -RunContext ([pscustomobject]@{ CollectionTime = [datetime]::UtcNow; RunId = 'r1' }) -Engine 'identity' -SqlInvoke (WriteSeam)
        } finally { $script:SIRecordBatchSize = $saved }
        @($script:Calls | ForEach-Object { JCount $_.Params.r }) | Should -Be @(2, 2, 1)
        ($r.Sql, $r.Changed, $r.Records) | Should -Be @(5, 5, 0)
        $script:Posts.Count | Should -Be 0 -Because 'records are not posted to Log Analytics (sql only)'
    }
    It 'adds the one-way copy to SI_Record_CL only when SI_LaExport = records' {
        $global:SI_LaExport = 'records'
        $r = Publish-SIRecords -RunContext ([pscustomobject]@{ CollectionTime = [datetime]::UtcNow; RunId = 'r1' }) -Engine 'identity' -SqlInvoke (WriteSeam)
        @($script:Posts) | Should -Be @('SI_Record')
        ($r.Sql, $r.Records) | Should -Be @(5, 5)
    }
    It 'says plainly that the records were not kept when no database is configured' {
        $saved = @($global:SI_ProSqlServer, $global:SI_ProSqlDatabase)
        try {
            $global:SI_ProSqlServer = ''; $global:SI_ProSqlDatabase = ''
            $w = $null
            $r = Publish-SIRecords -RunContext ([pscustomobject]@{ CollectionTime = [datetime]::UtcNow; RunId = 'r1' }) -Engine 'identity' -WarningVariable w 3>$null
        } finally { $global:SI_ProSqlServer = $saved[0]; $global:SI_ProSqlDatabase = $saved[1] }
        "$w" | Should -Match 'records were NOT kept: no database is configured'
        $r.Sql | Should -Be 0
        $script:Posts.Count | Should -Be 0
    }
    It 'reads SI_LaExport as off by default and records only when named' {
        Test-SILaExport -Setting $null -Kind records | Should -BeFalse
        Test-SILaExport -Setting 'off' -Kind records | Should -BeFalse
        Test-SILaExport -Setting 'records' -Kind records | Should -BeTrue
        Test-SILaExport -Setting ' Records , findings ' -Kind records | Should -BeTrue
    }
}
