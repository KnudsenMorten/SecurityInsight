#Requires -Version 5.1
<#
    THE RECORDS OF A RUN COLLECTED IN PARTS (engine/data-model/SI-RecordHandover.ps1) -- #475.
    Ring 1, 2026-10-08: a run collected in parts dropped the records discovery captured (Entra 1,726 / Exposure Graph 7,296
    / Azure 494 -> 0) and the parts published Collect-stage halves without a key. What these tests keep true:
      * every process SAVES its records in buckets by record id (the parts' hash), parts as JSON text, its pulls along;
      * the buckets MERGE as one process would have built the record: every part kept, the same part captured twice -> the
        later process's (discover first), engines unioned, a pull complete only when complete everywhere;
      * the last step publishes each bucket ONCE -- a record split between discovery and a part comes out WHOLE, with its key;
      * a part publishes nothing: it hands over (and a failed hand-over fails the part); the container wires discovery,
        the parts and the last step.
    Offline. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1')
    function script:MemStore {
        $m = @{}
        [pscustomobject]@{
            Data  = $m
            Write = { param($Path, $Text) $m[$Path] = [string]$Text }.GetNewClosure()
            Read  = { param($Path) $m[$Path] }.GetNewClosure()
            List  = { param($Prefix) @($m.Keys | Where-Object { $_.StartsWith($Prefix) } | Sort-Object) }.GetNewClosure()
        }
    }
}

Describe 'saving a process''s records in buckets' {
    It 'buckets by the record id, keeps parts as JSON text (an object part too), carries the pulls and clears the capture' {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        foreach ($i in 1..40) { Add-SIRecordPart -Provider entra -RecordType user -Key "U$i" -Part user -Object @{ id = "U$i" } }
        $global:SIRecordCaptureState.Records['entra|user|u1'].Parts['software'] = @('a/b')        # an object part (rule index)
        Set-SIRecordPull -Provider entra -Complete $false -ErrorText 'page 3 failed'
        $s = MemStore
        $n = Save-SIRecordHandover -Store $s -Engine identity -RunId 'r1' -Who 'discover' -Buckets 3
        $n | Should -Be 40
        $global:SIRecordCaptureState.Records.Count | Should -Be 0
        @($s.Data.Keys | Where-Object { $_ -notmatch '^collect/identity/r1/records/discover/bucket-\d{5}-\d{5}\.json$' }) | Should -BeNullOrEmpty
        $all = New-Object System.Collections.Generic.List[object]
        foreach ($path in $s.Data.Keys) {
            $bucket = [int]([regex]::Match($path, 'bucket-(\d{5})-\d{5}\.json$').Groups[1].Value)
            $d = $s.Data[$path] | ConvertFrom-Json
            @($d.Pulls)[0].Complete | Should -BeFalse
            foreach ($r in @($d.Records)) { Get-SICollectPartIndex -Key $r.Id -Parts 3 | Should -Be $bucket; $all.Add($r) }
        }
        $all.Count | Should -Be 40
        $u1 = @($all | Where-Object { $_.Id -eq 'entra|user|u1' })[0]
        $u1.Parts.user | Should -BeOfType [string]
        ($u1.Parts.software | ConvertFrom-Json) | Should -Be 'a/b'
    }
}

Describe 'a bucket is written in chunks (customer H 2026-10-08: one file per bucket ran out of memory)' {
    It 'never writes more than -ChunkSize records in one file, and every record exactly once' {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        foreach ($i in 1..53) { Add-SIRecordPart -Provider eg -RecordType node -Key "N$i" -Part node -Object @{ id = "N$i"; raw = ('x' * 50) } }
        $s = MemStore
        $n = Save-SIRecordHandover -Store $s -Engine identity -RunId 'rc' -Who 'discover' -Buckets 2 -ChunkSize 5
        $n | Should -Be 53
        $ids = New-Object System.Collections.Generic.List[string]
        foreach ($path in $s.Data.Keys) {
            $path | Should -Match '/bucket-\d{5}-\d{5}\.json$'
            $recs = @(($s.Data[$path] | ConvertFrom-Json).Records)
            $recs.Count | Should -BeLessOrEqual 5
            foreach ($r in $recs) { $ids.Add([string]$r.Id) }
        }
        $ids.Count | Should -Be 53
        @($ids | Sort-Object -Unique).Count | Should -Be 53
        @($s.Data.Keys).Count | Should -BeGreaterOrEqual 11
    }
    It 'a bucket in many chunks from discovery and a part comes out whole, once, the later capture winning' {
        $s = MemStore
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        foreach ($i in 1..30) { Add-SIRecordPart -Provider entra -RecordType user -Key "U$i" -Part user -Object @{ id = "U$i"; v = 'discover' } }
        $null = Save-SIRecordHandover -Store $s -Engine identity -RunId 'rd' -Who 'discover' -Buckets 1 -ChunkSize 4
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        foreach ($i in 1..30) { Add-SIRecordPart -Provider entra -RecordType user -Key "U$i" -Part user -Object @{ id = "U$i"; v = 'part' } }
        foreach ($i in 1..30) { Add-SIRecordPart -Provider entra -RecordType user -Key "U$i" -Part signins -Object @{ n = $i } }
        $null = Save-SIRecordHandover -Store $s -Engine identity -RunId 'rd' -Who 'part-00000' -Buckets 1 -ChunkSize 7
        $script:Pub = New-Object System.Collections.Generic.List[object]
        Mock Publish-SIRecords { foreach ($r in @(Get-SICapturedRecords -Engine $Engine)) { $script:Pub.Add($r) }; [pscustomobject]@{ Records = @(Get-SICapturedRecords -Engine $Engine).Count } }
        $res = Publish-SIRecordHandover -Store $s -Engine identity -RunId 'rd' -RunContext ([pscustomobject]@{ CollectionTime = [datetime]::UtcNow; RunId = 'rd' })
        $res.Records | Should -Be 30
        $res.Buckets | Should -Be 1
        $script:Pub.Count | Should -Be 30
        $u7 = @($script:Pub | Where-Object { $_.Key -eq 'u7' })[0]
        $u7.Object.user.v | Should -Be 'part'
        $u7.Object.signins.n | Should -Be 7
    }
}
Describe 'merging the buckets' {
    It 'builds the record as one process would have: every part, the later process''s part wins, engines unioned, pulls ANDed' {
        $disc = [pscustomobject]@{ Who = 'discover'; Pulls = @([pscustomobject]@{ Provider = 'entra'; Complete = $true; Error = '' })
            Records = @([pscustomobject]@{ Id = 'entra|user|u1'; Provider = 'entra'; RecordType = 'user'; Key = 'u1'; ResourceType = ''; Engines = @('identity')
                    Parts = [pscustomobject]@{ user = '{"id":"U1"}'; signins = '{"n":1}' } }) }
        $part = [pscustomobject]@{ Who = 'part-00001'; Pulls = @([pscustomobject]@{ Provider = 'entra'; Complete = $false; Error = 'throttled' })
            Records = @(
                [pscustomobject]@{ Id = 'entra|user|u1'; Provider = 'entra'; RecordType = 'user'; Key = 'u1'; ResourceType = ''; Engines = @('identity', 'endpoint')
                    Parts = [pscustomobject]@{ signins = '{"n":2}'; egQueryRules = '["R1"]' } }
                [pscustomobject]@{ Id = 'entra|user|u2'; Provider = 'entra'; RecordType = 'user'; Key = 'u2'; ResourceType = ''; Engines = @('identity')
                    Parts = [pscustomobject]@{ signins = '{"n":5}' } }
            ) }
        $st = Merge-SIRecordHandover -Documents @($part, $disc)          # any order in: discover is merged first
        $st.Records.Count | Should -Be 2
        $u1 = $st.Records['entra|user|u1']
        @($u1.Parts.Keys) | Should -Be @('user', 'signins', 'egQueryRules')
        ($u1.Parts['signins'].SIJson | ConvertFrom-Json).n | Should -Be 2
        @($u1.Engines | Sort-Object) | Should -Be @('endpoint', 'identity')
        $st.Pulls['entra'].Complete | Should -BeFalse
        $st.Pulls['entra'].Error | Should -Be 'throttled'
    }
}

Describe 'the last step publishes every record once, whole' {
    It 'a record split between discovery and a part comes out with every part, once; buckets one at a time' {
        $s = MemStore
        # discovery: the user objects
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        foreach ($i in 1..6) { Add-SIRecordPart -Provider entra -RecordType user -Key "U$i" -Part user -Object @{ id = "U$i"; upn = "u$i@x" } }
        Set-SIRecordPull -Provider entra -Complete $true
        $null = Save-SIRecordHandover -Store $s -Engine identity -RunId 'r2' -Who 'discover' -Buckets 2
        # part 1: sign-ins for some of them (the Collect-stage half)
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        foreach ($i in 2, 4, 6) { Add-SIRecordPart -Provider entra -RecordType user -Key "U$i" -Part signins -Object @{ last = "2026-10-0$i" } }
        $null = Save-SIRecordHandover -Store $s -Engine identity -RunId 'r2' -Who 'part-00001' -Buckets 2
        $script:Published = New-Object System.Collections.Generic.List[object]
        Mock Publish-SIRecords { foreach ($r in @(Get-SICapturedRecords -Engine $Engine)) { $script:Published.Add($r) }; [pscustomobject]@{ Records = @(Get-SICapturedRecords -Engine $Engine).Count } }
        $res = Publish-SIRecordHandover -Store $s -Engine identity -RunId 'r2' -RunContext ([pscustomobject]@{ CollectionTime = [datetime]::UtcNow; RunId = 'r2' })
        $res.Records | Should -Be 6
        $res.Failed | Should -Be 0
        $res.Buckets | Should -BeIn 1, 2
        Should -Invoke Publish-SIRecords -Times $res.Buckets -Exactly
        @($script:Published | ForEach-Object { $_.Key } | Sort-Object) | Should -Be @('u1', 'u2', 'u3', 'u4', 'u5', 'u6')
        $u4 = @($script:Published | Where-Object { $_.Key -eq 'u4' })[0]
        $u4.Object.user.upn | Should -Be 'u4@x'
        $u4.Object.signins.last | Should -Be '2026-10-04'
        $global:SIRecordCaptureState | Should -BeNullOrEmpty
    }
    It 'a bucket that cannot be published is said and counted; the others go on' {
        $s = MemStore
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        foreach ($i in 1..30) { Add-SIRecordPart -Provider entra -RecordType user -Key "U$i" -Part user -Object @{ id = "U$i" } }
        $null = Save-SIRecordHandover -Store $s -Engine identity -RunId 'r3' -Who 'discover' -Buckets 3
        $script:Calls = 0
        Mock Publish-SIRecords { $script:Calls++; if ($script:Calls -eq 1) { throw 'ingest refused' }; [pscustomobject]@{ Records = 1 } }
        $res = Publish-SIRecordHandover -Store $s -Engine identity -RunId 'r3' -RunContext ([pscustomobject]@{ CollectionTime = [datetime]::UtcNow; RunId = 'r3' }) 3>$null
        $res.Failed | Should -Be 1
        $script:Calls | Should -Be $res.Buckets
    }
}

Describe 'a part hands over instead of publishing' {
    It 'with SI_COLLECT_PHASE = parts, Publish-SIRecords saves to the run''s buckets under the part''s name and posts nothing' {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        Add-SIRecordPart -Provider entra -RecordType user -Key 'U9' -Part signins -Object @{ last = 'x' }
        $script:Store = MemStore
        Mock New-SICollectBlobStore { $script:Store }
        function global:Send-SIObjectMapRows { throw 'a part must not post' }
        $vars = @{ SI_COLLECT_PHASE = 'parts'; SI_COLLECT_PART = '2'; SI_COLLECT_PARTS = '3'; SI_COLLECT_ENGINE_RUN = 'r9' }
        $savedAccount = $global:SI_StorageAccount; $global:SI_StorageAccount = 'stsitest'      # a container always has it (the store's -Account is mandatory)
        try {
            foreach ($k in $vars.Keys) { [Environment]::SetEnvironmentVariable($k, $vars[$k]) }
            $r = Publish-SIRecords -RunContext ([pscustomobject]@{ CollectionTime = [datetime]::UtcNow; RunId = 'r9' }) -Engine 'identity'
        } finally {
            foreach ($k in $vars.Keys) { [Environment]::SetEnvironmentVariable($k, $null) }
            Remove-Item Function:\global:Send-SIObjectMapRows -ErrorAction SilentlyContinue; $global:SI_StorageAccount = $savedAccount
        }
        $r.HandedOver | Should -Be 1
        $r.Records | Should -Be 0
        @($script:Store.Data.Keys) | Should -Be @(('collect/identity/r9/records/part-00002/bucket-{0:D5}-00000.json' -f (Get-SICollectPartIndex -Key 'entra|user|u9' -Parts 3)))
    }
    It 'a failed hand-over is flagged for the container, which fails the part' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')) | Should -Match ([regex]::Escape("-eq 'parts') { `$global:SI_RecordHandoverFailed = `$_.Exception.Message }"))
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1')) | Should -Match ([regex]::Escape("if (`$collectChild -eq 'parts' -and `$global:SI_RecordHandoverFailed) {"))
    }
}

Describe 'the container wires discovery, the parts and the last step' {
    BeforeAll { $script:Entry = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1')) }
    It 'discovery hands its records over before it hands its run to the parent' {
        $i = $script:Entry.IndexOf("-Who 'discover' -Buckets `$recordBuckets")
        $j = $script:Entry.IndexOf("[IO.File]::WriteAllText([string](Get-OptionalEnv 'SI_COLLECT_INFO_FILE' '')")
        ($i -gt 0 -and $j -gt $i) | Should -BeTrue
    }
    It 'after the last part, a records child publishes them -- even when a part failed, and the run then still fails' {
        $e = $script:Entry
        $e | Should -Match ([regex]::Escape("`$recBase = @{ SI_COLLECT_PHASE = 'records'; SI_COLLECT_PARTS = `$parts; SI_COLLECT_RECORD_BUCKETS = `$recordBuckets; SI_COLLECT_ENGINE_RUN = [string]`$info.RunId"))
        $r = $e.IndexOf("SI_COLLECT_PHASE = 'records'"); $f = $e.IndexOf('if ($failedParts.Count -gt 0) {')
        ($r -gt 0 -and $f -gt $r) | Should -BeTrue -Because 'the records are published before a failed part ends the run'
        $e | Should -Match ([regex]::Escape("if (`$collectChild -eq 'records') {"))
        $e | Should -Match ([regex]::Escape('Publish-SIRecordHandover -Store (New-SICollectBlobStore'))
    }
}
