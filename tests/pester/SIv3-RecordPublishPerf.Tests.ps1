#Requires -Version 5.1
<#
    PUBLISHING A RUN'S RECORDS AT SCALE (#475). customer H 2026-10-08: 96,551 records of a run collected in parts were
    published at ~2,000 every 2.5-5 minutes and the identity job hit its 1-hour limit mid-publish. Measured on the test
    VM per 2,000 records (PS 7): mapping the records to rows 55.6 s of 60 s -- ConvertTo-SIRecord re-read the whole field
    catalog and walked every mapping item twice through the generic accessors, with a pipeline per item, FOR EVERY RECORD.
      * EQUAL: the compiled mapper (the mapping read once per kind, Get-SIMapperPlan) gives every shipped mapping's every
        record type EXACTLY the record and the "missing" list the old mapper gave -- the old one is kept HERE, verbatim,
        as the reference; objects carry a value at every source path, and half of them miss some.
      * FAST: 2,000 records (Entra users + Exposure Graph nodes of a few KB) map in well under the old time; the
        breakdown per phase is written to the test output.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordSql.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')

    # THE OLD MAPPER, verbatim (before #475) -- the reference the compiled one must equal
    function script:ConvertTo-SIRecordReference {
        param($Object, $Mapping, [string]$RecordType, $Catalog, $ValueMaps, [string]$ResourceType, [datetime]$CollectionTime = [datetime]::UtcNow, [string]$RunId)
        $provider = [string](Get-SIItemValue $Mapping 'provider')
        $objDef = $null
        foreach ($o in @(Get-SIItemValue $Mapping 'objects')) { if ([string](Get-SIItemValue $o 'recordType') -eq $RecordType) { $objDef = $o; break } }
        if ($null -eq $objDef) { throw "mapping '$provider' has no object for record type '$RecordType'" }
        $types = @{}
        foreach ($f in @(Get-SIItemValue $Catalog 'fields')) { $types[[string]$f.name] = [string]$f.type }
        $rec = [ordered]@{}
        $keyVals = Resolve-SISourcePath -Object $Object -Path ([string](Get-SIItemValue $objDef 'key'))
        $nativeKey = $null; if ($keyVals.Count -gt 0) { $nativeKey = ([string]$keyVals[0]).ToLowerInvariant() }
        $rec['si_provider'] = $provider
        $rec['si_record_type'] = $RecordType
        $rec['si_class'] = [string](Get-SIItemValue $objDef 'class')
        $rec['si_record_key'] = if ($nativeKey) { "${provider}:$nativeKey" } else { $null }
        $rec['si_collection_time'] = $CollectionTime.ToUniversalTime()
        if ($RunId) { $rec['si_run_id'] = $RunId }
        $tsPath = [string](Get-SIItemValue $objDef 'timestamp')
        $ts = $null
        if ($tsPath -and $tsPath -ne '$collection_time') {
            $tv = Resolve-SISourcePath -Object $Object -Path $tsPath
            if ($tv.Count -gt 0) {
                $tn = Invoke-SINormalize -Values $tv -Chain @('datetime_utc') -ValueMaps $ValueMaps
                if ($tn.Count -eq 0 -and $provider -eq 'ad') { $tn = Invoke-SINormalize -Values $tv -Chain @('filetime_utc') -ValueMaps $ValueMaps }
                if ($tn.Count -gt 0) { $ts = $tn[0] }
            }
        }
        if ($null -eq $ts) { $ts = $CollectionTime.ToUniversalTime() }
        $rec['si_source_last_seen'] = $ts
        $missing = New-Object System.Collections.Generic.List[string]
        $done = New-Object 'System.Collections.Generic.HashSet[string]'
        $rt = ''; if ($ResourceType) { $rt = $ResourceType.ToLowerInvariant() }
        foreach ($item in @(Get-SIItemValue $Mapping 'mappings')) {
            $field = [string]$item.field
            if ($done.Contains($field)) { continue }
            if (@($item.recordTypes) -notcontains $RecordType) { continue }
            $rts = @(Get-SIItemValue $item 'resourceTypes')
            if ($rts.Count -gt 0 -and $rts[0]) { if (-not $rt -or $rts -notcontains $rt) { continue } }
            $vals = Get-SIMappingValues -MapItem $item -Object $Object -ValueMaps $ValueMaps
            if ($vals.Count -eq 0) { continue }
            $type = $types[$field]; if (-not $type) { $type = 'string' }
            $v = ConvertTo-SIFieldValue -Values $vals -Type $type
            if ($null -eq $v) { continue }
            if ([string](Get-SIItemValue $item 'combine') -eq 'union' -and $type -eq 'dynamic') {
                if ($rec.Contains($field)) {
                    $acc = New-Object System.Collections.Generic.List[object]
                    foreach ($x in @($rec[$field])) { $acc.Add($x) }
                    foreach ($x in @($v)) { if (-not ($acc -contains $x)) { $acc.Add($x) } }
                    $rec[$field] = $acc.ToArray()
                } else { $rec[$field] = $v }
                continue
            }
            $rec[$field] = $v
            [void]$done.Add($field)
        }
        foreach ($item in @(Get-SIItemValue $Mapping 'mappings')) {
            $field = [string]$item.field
            if ($done.Contains($field) -or $rec.Contains($field) -or $missing.Contains($field)) { continue }
            if (@($item.recordTypes) -notcontains $RecordType) { continue }
            $rts = @(Get-SIItemValue $item 'resourceTypes')
            if ($rts.Count -gt 0 -and $rts[0] -and ((-not $rt) -or ($rts -notcontains $rt))) { continue }
            $missing.Add($field)
        }
        return @{ Record = $rec; Missing = $missing.ToArray() }
    }

    # an object with a value at every source path of a mapping (or, with -Sparse, at every other one)
    function script:New-MappedObject($Mapping, [string]$RecordType, [int]$Seed, [switch]$Sparse) {
        $root = [ordered]@{}
        $paths = New-Object System.Collections.Generic.List[string]
        foreach ($o in @($Mapping.objects)) { if ($o.recordType -eq $RecordType) { foreach ($p in @($o.key, $o.timestamp)) { if ($p -and $p -ne '$collection_time') { $paths.Add([string]$p) } } } }
        foreach ($it in @($Mapping.mappings)) { if (@($it.recordTypes) -contains $RecordType) { foreach ($s in @($it.sources)) { if ($s) { $paths.Add([string]$s) } } } }
        $i = 0
        $vals = @('Value-{0}', '2026-10-0{1}T08:00:00Z', 'true', '1{0}', '10.0.{1}.4', '{{"a":"x{0}"}}', 'CN=Host{0},OU=X')
        foreach ($p in $paths) {
            $i++
            if ($Sparse -and ($i % 2 -eq 0)) { continue }
            $segs = $p.Split('.')
            $cur = $root
            for ($s = 0; $s -lt $segs.Count; $s++) {
                $seg = $segs[$s]; $arr = $seg.EndsWith('[*]'); if ($arr) { $seg = $seg.Substring(0, $seg.Length - 3) }
                $last = ($s -eq $segs.Count - 1)
                if ($last) {
                    $v = $vals[($i + $Seed) % $vals.Count] -f $Seed, (($Seed % 8) + 1)
                    if ($arr) { $cur[$seg] = @($v, "$v-b") } elseif (-not $cur.Contains($seg)) { $cur[$seg] = $v }
                } else {
                    if (-not $cur.Contains($seg) -or -not ($cur[$seg] -is [System.Collections.IDictionary] -or $cur[$seg] -is [array])) {
                        if ($arr) { $cur[$seg] = @([ordered]@{}) } else { $cur[$seg] = [ordered]@{} }
                    }
                    $cur = if ($cur[$seg] -is [array]) { $cur[$seg][0] } else { $cur[$seg] }
                }
            }
        }
        # through JSON, as captured records are
        (ConvertTo-Json -InputObject $root -Depth 20 -Compress) | ConvertFrom-Json
    }
}

Describe 'the compiled mapper equals the old one (every shipped mapping, every record type)' {
    It 'maps <p> exactly as before' -TestCases @(
        @{ p = 'entra' }, @{ p = 'eg' }, @{ p = 'mde' }, @{ p = 'azure' }, @{ p = 'ad' }, @{ p = 'intune' }, @{ p = 'mdi' }, @{ p = 'shodan' }, @{ p = 'cmdb' }, @{ p = 'servicenow' }
    ) {
        $m = $script:Model.Mappings[$p]
        $m | Should -Not -BeNullOrEmpty
        $cat = $script:Model['field-catalog']; $vm = $script:Model['value-maps'].maps
        $ct = [datetime]::SpecifyKind([datetime]'2026-10-09T01:00:00', 'Utc')
        $n = 0
        foreach ($o in @($m.objects)) {
            $rtList = @('')
            $rtsAll = @(@($m.mappings) | ForEach-Object { @($_.resourceTypes) } | Where-Object { $_ } | Select-Object -Unique)
            if ($rtsAll.Count) { $rtList = @('') + @($rtsAll | Select-Object -First 3) }
            for ($seed = 0; $seed -lt 4; $seed++) {
                foreach ($rt in $rtList) {
                    $obj = New-MappedObject -Mapping $m -RecordType $o.recordType -Seed $seed -Sparse:($seed % 2 -eq 1)
                    $old = ConvertTo-SIRecordReference -Object $obj -Mapping $m -RecordType $o.recordType -Catalog $cat -ValueMaps $vm -ResourceType $rt -CollectionTime $ct -RunId 'r'
                    $new = ConvertTo-SIRecord -Object $obj -Mapping $m -RecordType $o.recordType -Catalog $cat -ValueMaps $vm -ResourceType $rt -CollectionTime $ct -RunId 'r'
                    (ConvertTo-Json -InputObject $new.Record -Depth 12 -Compress) | Should -Be (ConvertTo-Json -InputObject $old.Record -Depth 12 -Compress) -Because "$p/$($o.recordType)/$rt seed $seed"
                    (@($new.Missing) -join ',') | Should -Be (@($old.Missing) -join ',')
                    $n++
                }
            }
        }
        $n | Should -BeGreaterThan 0
    }
    It 'reads a mapping once per kind, and never mistakes another mapping object for one already read' {
        $m = $script:Model.Mappings['eg']; $cat = $script:Model['field-catalog']
        $a = Get-SIMapperPlan -Mapping $m -RecordType 'user' -Catalog $cat
        [object]::ReferenceEquals((Get-SIMapperPlan -Mapping $m -RecordType 'user' -Catalog $cat), $a) | Should -BeTrue
        $copy = ($m | ConvertTo-Json -Depth 30) | ConvertFrom-Json
        [object]::ReferenceEquals((Get-SIMapperPlan -Mapping $copy -RecordType 'user' -Catalog $cat), $a) | Should -BeFalse
        { Get-SIMapperPlan -Mapping $m -RecordType 'no-such-type' -Catalog $cat } | Should -Throw "*has no object for record type 'no-such-type'*"
    }
}

Describe 'publishing 2,000 records: the time per phase' {
    It 'maps 2,000 Entra users and Exposure Graph nodes well inside the old time, the breakdown written out' {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        $pad = 'x' * 60
        for ($i = 0; $i -lt 2000; $i++) {
            $id = [guid]::NewGuid().ToString()
            if ($i % 2 -eq 0) {
                $u = [ordered]@{ id = $id; userPrincipalName = "user$i@contoso.example"; displayName = "User $i"; accountEnabled = $true; mail = "user$i@contoso.example"
                    jobTitle = 'Engineer'; department = 'IT'; onPremisesSyncEnabled = ($i % 3 -eq 0); userType = 'Member'; createdDateTime = '2024-01-02T03:04:05Z'
                    signInActivity = [ordered]@{ lastSignInDateTime = '2026-10-01T10:00:00Z' }; proxyAddresses = @("SMTP:user$i@contoso.example") }
                Add-SIRecordPart -Provider entra -RecordType user -Key $id -Part user -Object ([pscustomobject]$u)
            } else {
                $raw = [ordered]@{ lastSeen = '2026-10-07T08:00:00Z'; accountUpn = "user$i@contoso.example"; accountObjectId = $id; isActive = $true; tags = @('a', 'b') }
                for ($k = 0; $k -lt 30; $k++) { $raw["prop$k"] = "$pad-$k" }
                $node = [ordered]@{ NodeId = [guid]::NewGuid().ToString(); NodeName = "User $i"; NodeLabel = 'user'; EntityIds = @(@{ type = 'AadObjectId'; id = $id }); NodeProperties = [ordered]@{ rawData = $raw } }
                Add-SIRecordPart -Provider eg -RecordType user -Key $node.NodeId -Part node -Object ([pscustomobject]$node)
            }
        }
        $cap = @(Get-SICapturedRecords -Engine identity)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $out = ConvertTo-SIRecordRows -Captured $cap -Model $script:Model -CollectionTime ([datetime]::UtcNow) -RunId 'p'
        $mapMs = $sw.ElapsedMilliseconds
        $sw.Restart(); $null = ConvertTo-SIRecordSqlItems -Rows @($out.Rows); $sqlMs = $sw.ElapsedMilliseconds
        $script:Measured = ('[measure] PS{0}: 2,000 records -> rows {1} ms ({2:N1} ms/record), SQL items {3} ms' -f $PSVersionTable.PSVersion.Major, $mapMs, ($mapMs / 2000), $sqlMs)
        Write-Host $script:Measured
        @($out.Rows).Count | Should -Be 2000
        @($out.Errors).Count | Should -Be 0
        # before: 55.6 s on PS 7 and 118 s on PS 5.1 on this VM; a generous ceiling, not a benchmark
        $ceiling = if ($PSVersionTable.PSVersion.Major -ge 7) { 30000 } else { 60000 }
        $mapMs | Should -BeLessThan $ceiling
    }
}

Describe 'the records of a large run are spread over buckets that publish in parallel' {
    BeforeAll {
        function script:MemStore2 {
            $m = @{}
            [pscustomobject]@{ Data = $m
                Write = { param($Path, $Text) $m[$Path] = [string]$Text }.GetNewClosure()
                Read  = { param($Path) $m[$Path] }.GetNewClosure()
                List  = { param($Prefix) @($m.Keys | Where-Object { $_.StartsWith($Prefix) } | Sort-Object) }.GetNewClosure() }
        }
    }
    It 'counts the buckets: <why>' -TestCases @(
        @{ why = 'a small run: one per part'; r = 1200; p = 1; b = 1 }
        @{ why = 'never fewer than the parts'; r = 0; p = 3; b = 3 }
        @{ why = 'customer H: 96,551 records in 3 parts -> ~5,000 each'; r = 96551; p = 3; b = 20 }
        @{ why = '512,000 users: ~5,000 each'; r = 2600000; p = 52; b = 520 }
        @{ why = '#727 millions of Azure resources: the count grows with the records, ~5,000 each'; r = 9000000; p = 1; b = 1800 }
        @{ why = 'never more than the bucket file names hold (five digits)'; r = 900000000; p = 1; b = 99999 }
    ) {
        Get-SIRecordBucketCount -Records $r -Parts $p | Should -Be $b
    }
    It 'gives each process its slice of the buckets (b mod N): together every bucket, none twice' {
        $s = MemStore2
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        foreach ($i in 1..60) { Add-SIRecordPart -Provider entra -RecordType user -Key "U$i" -Part user -Object @{ id = "U$i" } }
        $null = Save-SIRecordHandover -Store $s -Engine identity -RunId 'sl' -Who 'discover' -Buckets 6 -ChunkSize 4
        $script:Seen = New-Object System.Collections.Generic.List[string]
        Mock Publish-SIRecords { foreach ($r in @(Get-SICapturedRecords -Engine $Engine)) { $script:Seen.Add([string]$r.Key) }; [pscustomobject]@{ Records = @(Get-SICapturedRecords -Engine $Engine).Count } }
        $ctx = [pscustomobject]@{ CollectionTime = [datetime]::UtcNow; RunId = 'sl' }
        $a = Publish-SIRecordHandover -Store $s -Engine identity -RunId 'sl' -RunContext $ctx -Slice 0 -Slices 2
        $b = Publish-SIRecordHandover -Store $s -Engine identity -RunId 'sl' -RunContext $ctx -Slice 1 -Slices 2
        ($a.Buckets + $b.Buckets) | Should -Be 6
        ($a.Records + $b.Records) | Should -Be 60
        $script:Seen.Count | Should -Be 60
        @($script:Seen | Sort-Object -Unique).Count | Should -Be 60
    }
}

Describe 'posting batch after batch: a table and rule made ready once per process, the new-column wait once per table' {
    BeforeAll { . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1') }
    It 'checks the table and rule for the first batch and for a batch with a NEW column only -- every batch is posted' {
        $global:SI_LogIngestRunCache = $null
        Mock Resolve-SICorrelationAuthParams { @{ UseManagedIdentity = $true; ManagedIdentityClientId = 'x' } }
        Mock Initialize-SIIngestGlobals { }
        Mock Select-SIIngestTarget { }
        Mock Update-SILogTableSchema { }
        Mock Repair-SILogColumnName { $Data }
        Mock Format-SILogRowsToSchema { $Data }
        Mock Send-SILogData { }
        $r1 = @([pscustomobject]@{ a = 1; b = 'x' }, [pscustomobject]@{ a = 2; b = 'y' })
        $r2 = @([pscustomobject]@{ a = 3; b = 'z' })
        $r3 = @([pscustomobject]@{ a = 4; b = 'w'; c = 'new' })
        Send-SIObjectMapRows -Rows $r1 -TableName 'SI_Record' -DcrName 'dcr-si-record' | Should -Be 2
        Send-SIObjectMapRows -Rows $r2 -TableName 'SI_Record' -DcrName 'dcr-si-record' | Should -Be 1
        Send-SIObjectMapRows -Rows $r2 -TableName 'SI_Record' -DcrName 'dcr-si-record' | Should -Be 1
        Should -Invoke Update-SILogTableSchema -Times 1 -Exactly
        Send-SIObjectMapRows -Rows $r3 -TableName 'SI_Record' -DcrName 'dcr-si-record' | Should -Be 1
        Should -Invoke Update-SILogTableSchema -Times 2 -Exactly
        Send-SIObjectMapRows -Rows $r1 -TableName 'SI_RecordRaw' -DcrName 'dcr-si-recordraw' | Should -Be 2
        Should -Invoke Update-SILogTableSchema -Times 3 -Exactly      # another table is its own
        Should -Invoke Send-SILogData -Times 5 -Exactly
        $global:SI_LogIngestRunCache = $null
    }
    It 'a ready batch posts through the endpoint and rule the full path pinned for that table (another table''s pins in between)' {
        $code = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1'))
        $code | Should -Match ([regex]::Escape('$global:AzDceDetails = @($ready.Dce); $global:AzDcrDetails = @($ready.Dcr)'))
        $code | Should -Match ([regex]::Escape('$rcache.ObjectMapReady[$readyKey] = [pscustomobject]@{ Columns = $known; Dce = @($global:AzDceDetails); Dcr = @($global:AzDcrDetails) }'))
        # the snapshot is taken after the re-pin of the full path (#199), never before it
        $code.IndexOf('$rcache.ObjectMapReady[$readyKey] = [pscustomobject]') | Should -BeGreaterThan $code.LastIndexOf('Select-SIIngestTarget -AuthParams $authParams -DcrName $DcrName')
    }
    It 'waits for a table''s new columns once per process, and says so when it does not wait again' {
        $global:SI_LogIngestRunCache = $null
        Mock Wait-SILogColumnsStored { [pscustomobject]@{ Verdict = 'stored'; Missing = @(); WaitedSec = 30; Detail = '' } }
        $rows = @([pscustomobject]@{ newcol = 'v'; CollectionTime = [datetime]::UtcNow })
        foreach ($n in 1..3) {
            $global:SI_LogIngestNewColumns = @{ 'dcr-si-record' = [pscustomobject]@{ Table = 'SI_Record'; Columns = @('newcol'); WorkspaceResourceId = '/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/z' } }
            Confirm-SILogNewColumns -DcrName 'dcr-si-record' -TableName 'SI_Record_CL' -Data $rows -Bound @{} 6>$null
        }
        Should -Invoke Wait-SILogColumnsStored -Times 1 -Exactly
        $global:SI_LogIngestNewColumns = $null
        $global:SI_LogIngestRunCache = $null
    }
    It 'takes the cross-process lock one at a time, goes on without it when it stays taken, and has none without a lock file' {
        $f = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('si-lock-test-{0}.lock' -f [guid]::NewGuid().ToString('N')))
        $saved = [Environment]::GetEnvironmentVariable('SI_INGEST_LOCK_FILE')
        try {
            [Environment]::SetEnvironmentVariable('SI_INGEST_LOCK_FILE', $null)
            Enter-SIIngestLock | Should -BeNullOrEmpty
            [Environment]::SetEnvironmentVariable('SI_INGEST_LOCK_FILE', $f)
            $one = Enter-SIIngestLock
            $one | Should -Not -BeNullOrEmpty
            $two = Enter-SIIngestLock -WaitSeconds 1 3>$null
            $two | Should -BeNullOrEmpty
            Exit-SIIngestLock -Lock $one
            $three = Enter-SIIngestLock -WaitSeconds 5
            $three | Should -Not -BeNullOrEmpty
            Exit-SIIngestLock -Lock $three
        } finally { [Environment]::SetEnvironmentVariable('SI_INGEST_LOCK_FILE', $saved); [IO.File]::Delete($f) }
    }
}

Describe 'the container publishes a large run''s records in parallel processes' {
    BeforeAll { $script:Entry = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1')) }
    It 'discovery decides the record buckets and every process of the run uses them' {
        $e = $script:Entry
        $e | Should -Match ([regex]::Escape('$recordBuckets = Get-SIRecordBucketCount -Records'))
        $e | Should -Match ([regex]::Escape('-Who ''discover'' -Buckets $recordBuckets'))
        $e | Should -Match ([regex]::Escape('RecordBuckets = $recordBuckets }'))
        $e | Should -Match ([regex]::Escape('SI_COLLECT_RECORD_BUCKETS = $recordBuckets; SI_COLLECT_ENGINE_RUN'))
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')) | Should -Match ([regex]::Escape("GetEnvironmentVariable('SI_COLLECT_RECORD_BUCKETS')"))
    }
    It 'runs one records process per CPU as the memory allows, each with its slice and the shared table lock, and fails the run when one fails' {
        # #874: the count and the processes are the shared functions (SIv3-RecordsParallelKeda.Tests.ps1 tests them)
        $e = $script:Entry
        $e | Should -Match ([regex]::Escape('$recProcs = Get-SIRecordsProcessCount -Buckets $recordBuckets -Processors ([Environment]::ProcessorCount) -FreeBytes (Get-SIRecordsProcessFreeBytes)'))
        $e | Should -Match ([regex]::Escape('$recPar = Invoke-SIRecordsInProcesses -Script $selfScript -Environment $recBase -Processes $recProcs'))
        $e | Should -Match ([regex]::Escape('if ([int]$recPar.Failed -gt 0 -or [int]$recPar.ExitCode -ne 0) { $rExit = 1 }'))
        $h = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1'))
        $h | Should -Match ([regex]::Escape('$vars[''SI_COLLECT_RECORDS_SLICE''] = (''{0}/{1}'' -f $k, $Processes)'))
        $h | Should -Match ([regex]::Escape('$vars[''SI_INGEST_LOCK_FILE''] = $lockFile'))
        $e | Should -Match ([regex]::Escape('-Slice $slice -Slices $slices'))
    }
}
