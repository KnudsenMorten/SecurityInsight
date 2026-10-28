<#
    #744 -- THE END OF A RISK ANALYSIS RUN, FASTER, WITH THE SAME OUTPUT (a large customer, 1,138,554 Detailed rows,
    2026-10-17: after "the run's result is complete in the database", "Uploading export files" was followed by 52 silent
    minutes; before that the Log Analytics upload took 2.6 h, its preparation on one thread the largest remaining cost).

    What these pin:
      A. THE JSON FILE: the rows' text made on several cores gives the file the writer before made, byte for byte (SHA-256),
         from rows in memory and from a pager; the same bytes go up as blocks WHILE it is written and the blob committed at
         the upload step is the file; a staging that fails never fails the file, and the file then goes up from the disk.
      A. THE UPLOAD: several blocks at once (at most the degree), the retry rule (503 retried, 401 resent with a fresh
         token, 400 fails with the service's words); the backup copy made by the service (no byte downloaded, every range
         against the source's ETag, the content type kept), and the range copy when the service refuses it.
      B. THE DELIVERY ON THE CORES = ONE PASS: the stored rows decoded, and the Log Analytics preparation of a chunk (copies,
         collection time, host columns, legal names, the chunk's columns in schema order, the type alignment and its
         counts) -- the same rows, the same JSON per row, in the same order; through the chunked post the same chunks; a
         worker failure -> one core, the same result, said once.
      C. MEMORY BOUNDED: the blocks in flight never more than the degree, each block at most the block size plus one flush.
      C. PROGRESS: "export: rows X of Y" at least every -ProgressSeconds; "MB of MB" while a file goes up.
      C. THE CONTAINER-SCOPE GUARD (the 2105-type bug): every function a worker part calls -- transitively -- is loaded
         INSIDE the worker (the RA workers, the upload workers); a call guarded by a presence check is allowed to be missing.
      WIRING: Risk Analysis writes the JSON with the upload and the read-ahead pager, commits the staged blocks at the upload
         step; the pager decodes on the cores; ConvertTo-RALaPostRows prepares on the cores.

    Offline, pwsh 7 (the workers are RA-ParallelScore.ps1's). NO EMOJI IN THIS FILE (no BOM).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $raShared = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
    . (Join-Path $raShared 'RA-ColumnTypeAlign.ps1')
    . (Join-Path $raShared 'RA-IngestKeyColumns.ps1')
    . (Join-Path $raShared 'RA-Delivery.ps1')
    . (Join-Path $raShared 'RA-SqlStream.ps1')
    . (Join-Path $raShared 'RA-ParallelScore.ps1')
    . (Join-Path $raShared 'Send-SecurityInsightExportFile.ps1')
    $script:SavedThreads = $global:SI_RA_ScoringThreads; $script:SavedMin = $global:SI_RA_ParallelMinRows
    $global:SI_RA_ScoringThreads = 4; $global:SI_RA_ParallelMinRows = 2
    $script:Said = New-Object 'System.Collections.Generic.List[string]'
    function script:Write-Info { param($m) $script:Said.Add([string]$m) }
    function script:Write-Ok { param($m) $script:Said.Add([string]$m) }
    function script:Write-Warn { param($m) $script:Said.Add('WARN ' + [string]$m) }
    function script:Write-Warn2 { param($m) $script:Said.Add('WARN ' + [string]$m) }
    function script:Write-Diag { param($m) $script:Said.Add('DIAG ' + [string]$m) }

    # rows of every kind of value the result carries
    function script:New-FsRows {
        param([int]$Count, [int]$Seed = 1)
        $rnd = New-Object Random $Seed
        $out = New-Object 'System.Collections.Generic.List[object]'
        for ($i = 0; $i -lt $Count; $i++) {
            $o = [ordered]@{ RowKey = ('r{0:D6}' -f $i); ReportName = @('Vulns', 'Identity', 'Azure')[$i % 3] }
            if ($i % 4 -ne 0) { $o['CollectionTime'] = [datetime]::new(2026, 10, 17, 9, 0, 0, [DateTimeKind]::Utc) }
            $o['Text'] = ('value {0} "q" \ back {1} tab' -f $i, ([string][char]0x00FC)) + "`t" + $(if ($i % 7 -eq 0) { [char]::ConvertFromUtf32(0x1F600) } else { '' })
            $o['Count'] = $(if ($i % 5 -eq 0) { $null } else { [long]($i * 13) })
            $o['Score'] = [double]($rnd.Next(0, 10000)) / 7
            $o['Impact'] = $(if ($i % 9 -eq 0) { '7,9' } elseif ($i % 9 -eq 1) { 'n/a' } else { [string]($i % 10) })
            $o['Flag'] = ($i % 2 -eq 0)
            $o['Seen'] = [datetime]::new(2026, 10, 1 + ($i % 20), 8, $i % 60, 0, [DateTimeKind]::Unspecified)
            if ($i % 3 -eq 0) { $o['id'] = "x$i"; $o['Type'] = 'T'; $o['some-name'] = $i; $o['dotted.name'] = 'd'; $o['_lead'] = 'l' }
            if ($i % 3 -eq 1) { $o['ThisColumnNameIsLongerThanFortyFiveCharactersForSure'] = 'long' }
            if ($i % 11 -eq 0) { $o['Tags'] = @('a', ('t{0}' -f $i)); $o['Nested'] = [pscustomobject]@{ k = $i; s = 'n'; d = @(1, 2) } }
            $o['OnlyNull'] = $null
            if ($i % 6 -eq 0) { $o['Rare'] = "rare $i" }
            $o['When'] = $(if ($i % 8 -eq 0) { [long]1700000000 } else { '2026-10-17T10:00:00Z' })
            [void]$out.Add([pscustomobject]$o)
        }
        , $out.ToArray()
    }

    # THE WRITER BEFORE #744 (RA-Delivery.ps1 at 9a975b5ce), kept here as the reference the bytes are compared with
    function script:Write-JsonBefore {
        param([AllowEmptyCollection()][AllowNull()][object[]]$Rows, [Parameter(Mandatory)][string]$Path, [int]$Depth = 20, $Pager)
        $full = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { [System.IO.Path]::Combine((Get-Location).Path, $Path) }
        $sw = New-Object System.IO.StreamWriter($full, $false, (New-Object System.Text.UTF8Encoding($false)), 65536)
        try {
            $sw.Write('[')
            $first = $true
            if ($null -eq $Rows) { $Rows = @() }
            while ($true) {
                if ($null -ne $Pager) { $Rows = $Pager.Next(); if ($null -eq $Rows) { break } }
                foreach ($r in $Rows) {
                    if ($first) { $sw.WriteLine(); $first = $false } else { $sw.WriteLine(',') }
                    $sw.Write((ConvertTo-Json -Depth $Depth -InputObject $r))
                }
                if ($null -eq $Pager) { break }
            }
            if (-not $first) { $sw.WriteLine() }
            $sw.WriteLine(']')
        } finally { $sw.Dispose() }
    }
    function script:Get-Sha { param([string]$Path) $s = [IO.File]::OpenRead($Path); try { [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($s)) } finally { $s.Dispose() } }
    function script:New-PagerOf {
        param([object[]]$Rows, [int]$PageSize, [int]$SleepMs = 0)
        $pg = [pscustomobject]@{ Rows = $Rows; At = 0; Size = $PageSize; Sleep = $SleepMs }
        $pg | Add-Member -MemberType ScriptMethod -Name Next -Value {
            if ($this.At -ge $this.Rows.Count) { return $null }
            if ($this.Sleep -gt 0) { Start-Sleep -Milliseconds $this.Sleep }
            $n = [Math]::Min($this.Size, $this.Rows.Count - $this.At)
            $part = New-Object 'object[]' $n; [Array]::Copy($this.Rows, $this.At, $part, 0, $n); $this.At += $n
            , $part
        }
        $pg
    }

    # ---- THE FAKE STORAGE SERVICE: the HTTP seam (Invoke-SIAzRestHttp) the main run AND the upload workers call, its
    # state shared through $SIExportSeam. Blocks in memory; a rule per request (-Rules: a script of its own, text).
    $script:FakeHttp = {
        param([string]$Method, [string]$Uri, [hashtable]$Headers, $Body, [string]$ContentType, [int]$TimeoutSec = 300, [switch]$AsBytes)
        $f = $SIExportSeam
        [System.Threading.Monitor]::Enter($f.SyncRoot)
        $len = $(if ($Body -is [byte[]]) { $Body.Length } else { 0 })
        try { $f.Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Headers = $Headers.Clone(); Len = $(if ($Body -is [byte[]]) { $Body.Length } else { -1 }); Thread = [System.Threading.Thread]::CurrentThread.ManagedThreadId }); $f.InFlight++; if ($f.InFlight -gt $f.MaxInFlight) { $f.MaxInFlight = $f.InFlight }
              $f.InFlightBytes += $len; if ($f.InFlightBytes -gt $f.MaxInFlightBytes) { $f.MaxInFlightBytes = $f.InFlightBytes } }
        finally { [System.Threading.Monitor]::Exit($f.SyncRoot) }
        try {
            if ($f.DelayMs -gt 0) { [System.Threading.Thread]::Sleep([int]$f.DelayMs) }
            $u = [uri]$Uri
            $path = [uri]::UnescapeDataString($u.AbsolutePath.TrimStart('/'))
            $q = $u.Query
            # a planned answer: the Nth request matching a pattern
            foreach ($rule in @($f.Rules)) {
                if ($Uri -match $rule.Match -and ($null -eq $rule.Header -or $Headers.ContainsKey($rule.Header))) {
                    [System.Threading.Monitor]::Enter($f.SyncRoot)
                    try { $rule.Seen++; $hit = ($rule.Seen -in $rule.Nth) } finally { [System.Threading.Monitor]::Exit($f.SyncRoot) }
                    if ($hit) { return [pscustomobject]@{ StatusCode = $rule.Code; Content = $rule.Content; Bytes = $null; Headers = @{ 'x-ms-error-code' = $rule.ErrorCode }; RetryAfter = '1' } }
                }
            }
            $concat = {
                param([string]$Blob)
                $ms = New-Object System.IO.MemoryStream
                foreach ($b in $f.Committed[$Blob]) { $ms.Write($b, 0, $b.Length) }
                , $ms.ToArray()
            }
            if ($q -match 'restype=container') { return [pscustomobject]@{ StatusCode = 200; Content = ''; Bytes = $null; Headers = @{}; RetryAfter = $null } }
            if ($Method -eq 'HEAD') {
                if (-not $f.Committed.ContainsKey($path)) { return [pscustomobject]@{ StatusCode = 404; Content = ''; Bytes = $null; Headers = @{}; RetryAfter = $null } }
                [byte[]]$all = & $concat $path
                $h = New-Object 'System.Collections.Hashtable' ([StringComparer]::OrdinalIgnoreCase)
                $h['Content-Length'] = [string]$all.Length; $h['ETag'] = '"etag-src"'; $h['Content-Type'] = 'application/x-test'
                return [pscustomobject]@{ StatusCode = 200; Content = ''; Bytes = $null; Headers = $h; RetryAfter = $null }
            }
            if ($Method -eq 'GET') {
                [byte[]]$all = & $concat $path
                $m = [regex]::Match([string]$Headers['x-ms-range'], 'bytes=(\d+)-(\d+)')
                $s = [int]$m.Groups[1].Value; $e = [int]$m.Groups[2].Value
                [byte[]]$out = [byte[]]::new($e - $s + 1); [Array]::Copy($all, $s, $out, 0, $out.Length)
                [System.Threading.Monitor]::Enter($f.SyncRoot); try { $f.Down += $out.Length } finally { [System.Threading.Monitor]::Exit($f.SyncRoot) }
                return [pscustomobject]@{ StatusCode = 206; Content = ''; Bytes = $out; Headers = @{}; RetryAfter = $null }
            }
            if ($q -match 'comp=block&blockid=([^&]+)') {
                $id = [uri]::UnescapeDataString($Matches[1])
                if ($Headers['x-ms-copy-source']) {
                    $src = [uri]::UnescapeDataString(([uri][string]$Headers['x-ms-copy-source']).AbsolutePath.TrimStart('/'))
                    if ([string]$Headers['x-ms-source-if-match'] -ne '"etag-src"') { return [pscustomobject]@{ StatusCode = 412; Content = 'source changed'; Bytes = $null; Headers = @{}; RetryAfter = $null } }
                    [byte[]]$all = & $concat $src
                    $m = [regex]::Match([string]$Headers['x-ms-source-range'], 'bytes=(\d+)-(\d+)')
                    $s = [int]$m.Groups[1].Value; $e = [int]$m.Groups[2].Value
                    [byte[]]$bytes = [byte[]]::new($e - $s + 1); [Array]::Copy($all, $s, $bytes, 0, $bytes.Length)
                } else {
                    [byte[]]$bytes = if ($f.Discard) { [byte[]]::new(0) } else { ([byte[]]$Body).Clone() }
                }
                $f.Staged[$path + '|' + $id] = $bytes
                return [pscustomobject]@{ StatusCode = 201; Content = ''; Bytes = $null; Headers = @{}; RetryAfter = $null }
            }
            if ($q -match 'comp=blocklist') {
                $text = if ($Body -is [byte[]]) { [Text.Encoding]::UTF8.GetString($Body) } else { [string]$Body }
                $list = New-Object 'System.Collections.Generic.List[byte[]]'
                foreach ($x in [regex]::Matches($text, '<Latest>([^<]+)</Latest>')) {
                    $k = $path + '|' + $x.Groups[1].Value
                    if (-not $f.Staged.ContainsKey($k)) { return [pscustomobject]@{ StatusCode = 400; Content = 'InvalidBlockList'; Bytes = $null; Headers = @{ 'x-ms-error-code' = 'InvalidBlockList' }; RetryAfter = $null } }
                    $list.Add($f.Staged[$k])
                }
                $f.Committed[$path] = $list.ToArray()
                $f.ContentTypes[$path] = [string]$Headers['x-ms-blob-content-type']
                return [pscustomobject]@{ StatusCode = 201; Content = ''; Bytes = $null; Headers = @{ ETag = '"c"' }; RetryAfter = $null }
            }
            if ($Method -eq 'PUT') {
                [byte[]]$bytes = if ($Body -is [byte[]]) { $Body } else { [Text.Encoding]::UTF8.GetBytes([string]$Body) }
                $f.Committed[$path] = [object[]]@(, $bytes)
                return [pscustomobject]@{ StatusCode = 201; Content = ''; Bytes = $null; Headers = @{ ETag = '"p"' }; RetryAfter = $null }
            }
            [pscustomobject]@{ StatusCode = 404; Content = ''; Bytes = $null; Headers = @{}; RetryAfter = $null }
        } finally {
            [System.Threading.Monitor]::Enter($f.SyncRoot); try { $f.InFlight--; $f.InFlightBytes -= $len } finally { [System.Threading.Monitor]::Exit($f.SyncRoot) }
        }
    }
    function script:Reset-FakeStore {
        param([int]$DelayMs = 0, [object[]]$Rules = @())
        $global:SIExportSeam = [hashtable]::Synchronized(@{
            Calls = (New-Object 'System.Collections.Generic.List[object]'); InFlight = 0; MaxInFlight = 0; Down = 0L; DelayMs = $DelayMs
            InFlightBytes = 0L; MaxInFlightBytes = 0L; Discard = $false
            Staged = [System.Collections.Concurrent.ConcurrentDictionary[string, byte[]]]::new()
            Committed = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
            ContentTypes = [System.Collections.Concurrent.ConcurrentDictionary[string, string]]::new()
            Rules = @($Rules | ForEach-Object { [hashtable]::Synchronized($_) })
        })
        $script:Tokens = 0
    }
    function script:Get-FakeBlob { param([string]$Blob) $ms = New-Object System.IO.MemoryStream; foreach ($b in $global:SIExportSeam.Committed[$Blob]) { $ms.Write($b, 0, $b.Length) }; , $ms.ToArray() }
    # in THIS scope (where SI-AzRest.ps1 was dot-sourced above: a definition there would win over a script: / global: one)
    Set-Item -Path function:Invoke-SIAzRestHttp -Value $script:FakeHttp
    Set-Item -Path function:global:Invoke-SIAzRestHttp -Value $script:FakeHttp
    $script:SavedTp = $global:SI_TokenProvider
    $global:SI_TokenProvider = { param($Resource) $script:Tokens++; 'tok-' + $script:Tokens }
    $script:SavedBlock = $script:SIExportBlockBytes
}

AfterAll {
    $global:SI_RA_ScoringThreads = $script:SavedThreads; $global:SI_RA_ParallelMinRows = $script:SavedMin
    $global:SI_TokenProvider = $script:SavedTp
    Remove-Item -Path function:global:Invoke-SIAzRestHttp -ErrorAction SilentlyContinue
    $global:SIExportSeam = $null
    Remove-Variable -Scope Global -Name SI_ExportUpload_Parallel, SI_ExportServerCopy -ErrorAction SilentlyContinue
    if ($script:RAParallelWorkers) { foreach ($w in $script:RAParallelWorkers) { try { $w.Dispose() } catch { } }; $script:RAParallelWorkers = $null }
}

Describe 'A. the JSON file: the same bytes as the writer before (several cores, one core, pages)' {
    It 'rows in memory -- 0, 1, 3 and 600 rows: the file is the writer before''s, byte for byte' {
        foreach ($n in 0, 1, 3, 600) {
            $rows = New-FsRows -Count $n -Seed $n
            $a = Join-Path $TestDrive "before-$n.json"; $b = Join-Path $TestDrive "after-$n.json"; $c = Join-Path $TestDrive "one-$n.json"
            Write-JsonBefore -Rows $rows -Path $a -Depth 20
            Write-RAJsonArrayFile -Rows $rows -Path $b -Depth 20
            Write-RAJsonArrayFile -Rows $rows -Path $c -Depth 20 -OneCore
            Get-Sha $b | Should -BeExactly (Get-Sha $a) -Because "$n row(s), several cores"
            Get-Sha $c | Should -BeExactly (Get-Sha $a) -Because "$n row(s), one core"
        }
        Write-JsonBefore -Rows $null -Path (Join-Path $TestDrive 'n0.json'); Write-RAJsonArrayFile -Rows $null -Path (Join-Path $TestDrive 'n1.json')
        Get-Sha (Join-Path $TestDrive 'n1.json') | Should -BeExactly (Get-Sha (Join-Path $TestDrive 'n0.json'))
    }
    It 'from a pager of several pages (and a page of one row): the same bytes' {
        $rows = New-FsRows -Count 1201 -Seed 5
        $a = Join-Path $TestDrive 'pg-before.json'; $b = Join-Path $TestDrive 'pg-after.json'
        Write-JsonBefore -Pager (New-PagerOf -Rows $rows -PageSize 300) -Path $a -Depth 20
        Write-RAJsonArrayFile -Pager (New-PagerOf -Rows $rows -PageSize 300) -Path $b -Depth 20 -Total 1201
        Get-Sha $b | Should -BeExactly (Get-Sha $a)
    }
    It 'the rows'' text on the cores is ConvertTo-Json''s, row by row, in order' {
        $rows = New-FsRows -Count 400 -Seed 9
        $t = Invoke-RAParallelJsonText -Rows $rows -Depth 20
        $t | Should -Not -BeNullOrEmpty
        $t.Count | Should -Be 400
        for ($i = 0; $i -lt 400; $i++) { $t[$i] | Should -BeExactly (ConvertTo-Json -Depth 20 -InputObject $rows[$i]) }
    }
}

Describe 'A. the JSON file''s blocks go up while it is written; the blob committed = the file' {
    BeforeEach { Reset-FakeStore -DelayMs 150; $script:SIExportBlockBytes = 64KB; $script:RAJsonFlushBytes = 16KB; $global:SI_ExportUpload_Parallel = 4; $script:Said.Clear() }
    AfterEach { $script:SIExportBlockBytes = $script:SavedBlock; $script:RAJsonFlushBytes = 1MB; Remove-Variable -Scope Global -Name SI_ExportUpload_Parallel -ErrorAction SilentlyContinue }
    It 'every byte as blocks, in order; at the upload step the previous file is backed up IN AZURE and the blocks committed: blob = file' {
        $rows = New-FsRows -Count 1500 -Seed 2
        $f = Join-Path $TestDrive 'RiskAnalysis_Detailed.json'
        [byte[]]$prev = [byte[]]::new(300000); (New-Object Random 4).NextBytes($prev)
        $global:SIExportSeam.Committed['sistaging/risk-analysis/RiskAnalysis_Detailed.json'] = [object[]]@(, $prev)
        $up = New-SIExportStagedUpload -Destination 'https://acct.blob.core.windows.net/sistaging/risk-analysis/' -FileName 'RiskAnalysis_Detailed.json'
        $up.Blob | Should -Be 'risk-analysis/RiskAnalysis_Detailed.json'
        Write-RAJsonArrayFile -Pager (New-PagerOf -Rows $rows -PageSize 400) -Path $f -Depth 20 -Upload $up -Total 1500
        Complete-SIExportStagedUpload -Upload $up | Should -BeTrue
        $len = (Get-Item $f).Length
        $len | Should -BeGreaterThan (6 * 64KB)
        [long]$up.Bytes | Should -Be $len
        $blocks = @($global:SIExportSeam.Calls | Where-Object { $_.Uri -match 'comp=block&' })
        $blocks.Count | Should -Be $up.Ids.Count
        @($blocks | Where-Object { $_.Len -gt (64KB + 16KB + 64KB) }).Count | Should -Be 0 -Because 'a block is at most the block size plus one flush of the writer'
        $global:SIExportSeam.MaxInFlight | Should -BeGreaterThan 1
        $global:SIExportSeam.MaxInFlight | Should -BeLessOrEqual 4
        # the committed blob is still the PREVIOUS file until the upload step
        [Convert]::ToBase64String((Get-FakeBlob 'sistaging/risk-analysis/RiskAnalysis_Detailed.json')) | Should -BeExactly ([Convert]::ToBase64String($prev))
        Mock Get-SIAzADServicePrincipal { $null }
        Mock Ensure-SecurityInsightStorageContainer { $true }
        $global:SIExportSeam.Calls.Clear()
        Send-ExportFile -LocalPath $f -Destination 'https://acct.blob.core.windows.net/sistaging/risk-analysis/' -Staged $up
        $sha = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData((Get-FakeBlob 'sistaging/risk-analysis/RiskAnalysis_Detailed.json')))
        $sha | Should -BeExactly (Get-Sha $f)
        $bak = @($global:SIExportSeam.Committed.Keys | Where-Object { $_ -like 'sistaging/risk-analysis/RiskAnalysis_Detailed.*.json.bak' })
        $bak.Count | Should -Be 1
        [Convert]::ToBase64String((Get-FakeBlob $bak[0])) | Should -BeExactly ([Convert]::ToBase64String($prev))
        $global:SIExportSeam.Down | Should -Be 0 -Because 'the backup is copied by the service, nothing downloaded'
        @($global:SIExportSeam.Calls | Where-Object { $_.Len -gt 0 }).Count | Should -Be 0 -Because 'the file is not uploaded again: the blocks sent while it was written are committed'
        ($script:Said -join "`n") | Should -Match 'sent while it was written'
    }
    It 'a staging that fails (403 on a block) stops the staging, never the file; the upload step sends the file from the disk' {
        Reset-FakeStore -Rules @(@{ Match = 'comp=block&'; Nth = @(3); Code = 403; Content = 'AuthorizationPermissionMismatch'; ErrorCode = 'AuthorizationPermissionMismatch'; Seen = 0; Header = $null })
        $rows = New-FsRows -Count 900 -Seed 3
        $f = Join-Path $TestDrive 'RiskAnalysis_Summary.json'
        $up = New-SIExportStagedUpload -Destination 'https://acct.blob.core.windows.net/sistaging/' -FileName 'RiskAnalysis_Summary.json'
        { Write-RAJsonArrayFile -Rows $rows -Path $f -Depth 20 -Upload $up } | Should -Not -Throw
        Complete-SIExportStagedUpload -Upload $up | Should -BeFalse
        $up.Failed | Should -Match '403'
        Write-JsonBefore -Rows $rows -Path (Join-Path $TestDrive 'ref.json') -Depth 20
        Get-Sha $f | Should -BeExactly (Get-Sha (Join-Path $TestDrive 'ref.json')) -Because 'the file is whole'
        ($script:Said -join "`n") | Should -Match 'uploaded from the disk at the upload step instead'
        Mock Get-SIAzADServicePrincipal { $null }; Mock Ensure-SecurityInsightStorageContainer { $true }
        Send-ExportFile -LocalPath $f -Destination 'https://acct.blob.core.windows.net/sistaging/' -Staged $up
        [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData((Get-FakeBlob 'sistaging/RiskAnalysis_Summary.json'))) | Should -BeExactly (Get-Sha $f)
    }
    It 'blocks that are not ALL of this file (a byte count that differs) are never committed: the file goes up from the disk' {
        $rows = New-FsRows -Count 300 -Seed 8
        $f = Join-Path $TestDrive 'RiskAnalysis_Detailed.json'
        $up = New-SIExportStagedUpload -Destination 'https://acct.blob.core.windows.net/sistaging/' -FileName 'RiskAnalysis_Detailed.json'
        Write-RAJsonArrayFile -Rows $rows -Path $f -Depth 20 -Upload $up
        Complete-SIExportStagedUpload -Upload $up | Should -BeTrue
        [IO.File]::AppendAllText($f, ' ')   # the file changed after it was sent
        Mock Get-SIAzADServicePrincipal { $null }; Mock Ensure-SecurityInsightStorageContainer { $true }
        Send-ExportFile -LocalPath $f -Destination 'https://acct.blob.core.windows.net/sistaging/' -Staged $up
        [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData((Get-FakeBlob 'sistaging/RiskAnalysis_Detailed.json'))) | Should -BeExactly (Get-Sha $f)
    }
    It 'a commit the service refuses (the blocks are gone) -> the file goes up from the disk; the blob = the file' {
        $rows = New-FsRows -Count 300 -Seed 10
        $f = Join-Path $TestDrive 'RiskAnalysis_Detailed.json'
        $up = New-SIExportStagedUpload -Destination 'https://acct.blob.core.windows.net/sistaging/' -FileName 'RiskAnalysis_Detailed.json'
        Write-RAJsonArrayFile -Rows $rows -Path $f -Depth 20 -Upload $up
        Complete-SIExportStagedUpload -Upload $up | Should -BeTrue
        $global:SIExportSeam.Staged.Clear()   # another writer committed the blob in between: the uncommitted blocks are gone
        Mock Get-SIAzADServicePrincipal { $null }; Mock Ensure-SecurityInsightStorageContainer { $true }
        Send-ExportFile -LocalPath $f -Destination 'https://acct.blob.core.windows.net/sistaging/' -Staged $up
        [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData((Get-FakeBlob 'sistaging/RiskAnalysis_Detailed.json'))) | Should -BeExactly (Get-Sha $f)
        ($script:Said -join "`n") | Should -Match 'could not be committed'
    }
    It 'block ids: one length per blob, a tag of its own per staged upload' {
        $a = New-SIExportStagedUpload -Destination 'https://acct.blob.core.windows.net/c/' -FileName 'x.json'
        $b = New-SIExportStagedUpload -Destination 'https://acct.blob.core.windows.net/c/' -FileName 'x.json'
        $a.Tag | Should -Not -Be $b.Tag
        (Get-SIExportBlockId -Index 0 -Tag $a.Tag).Length | Should -Be (Get-SIExportBlockId -Index 49999 -Tag $a.Tag).Length
        Get-SIExportBlockId -Index 0 -Tag $a.Tag | Should -Not -Be (Get-SIExportBlockId -Index 0 -Tag $b.Tag)
        New-SIExportStagedUpload -Destination '\\server\share\' -FileName 'x.json' | Should -BeNullOrEmpty
        Close-SIExportRequestPool -Pool $a.Pool; Close-SIExportRequestPool -Pool $b.Pool
    }
}

Describe 'A. the upload: several blocks at once; the backup copy made by the service' {
    BeforeEach { Reset-FakeStore -DelayMs 20; $script:SIExportBlockBytes = 1000; $global:SI_ExportUpload_Parallel = 4; $script:Said.Clear() }
    AfterEach { $script:SIExportBlockBytes = $script:SavedBlock; Remove-Variable -Scope Global -Name SI_ExportUpload_Parallel, SI_ExportServerCopy -ErrorAction SilentlyContinue; $script:SIExportProgressSeconds = 60 }
    It 'a file of 23 blocks: byte-identical; up to 4 in flight; a line while it goes up' {
        $script:SIExportProgressSeconds = 0
        $f = Join-Path $TestDrive 'ra.xlsx'; [byte[]]$d = [byte[]]::new(22500); (New-Object Random 7).NextBytes($d); [IO.File]::WriteAllBytes($f, $d)
        $null = Send-SIExportBlockBlob -Account 'acct' -Container 'exports' -Blob 'ra/RiskAnalysis_Detailed.xlsx' -File $f
        [Convert]::ToBase64String((Get-FakeBlob 'exports/ra/RiskAnalysis_Detailed.xlsx')) | Should -BeExactly ([Convert]::ToBase64String($d))
        @($global:SIExportSeam.Calls | Where-Object { $_.Uri -match 'comp=block&' }).Count | Should -Be 23
        $global:SIExportSeam.MaxInFlight | Should -BeGreaterThan 1
        $global:SIExportSeam.MaxInFlight | Should -BeLessOrEqual 4
        @($script:Said | Where-Object { $_ -match 'export: ra/RiskAnalysis_Detailed\.xlsx -- \d+ MB of \d+ MB sent' }).Count | Should -BeGreaterThan 0
    }
    It 'the retry rule: a 503 is tried again, a 401 is sent once more with a fresh token -- every byte once' {
        Reset-FakeStore -DelayMs 5 -Rules @(
            @{ Match = 'blockid=YmxrMDAwMDAy'; Nth = @(1); Code = 503; Content = 'busy'; ErrorCode = 'ServerBusy'; Seen = 0; Header = $null },
            @{ Match = 'blockid=YmxrMDAwMDA1'; Nth = @(1); Code = 401; Content = 'expired'; ErrorCode = 'InvalidAuthenticationInfo'; Seen = 0; Header = $null })
        $f = Join-Path $TestDrive 'r.bin'; [byte[]]$d = [byte[]]::new(9000); (New-Object Random 3).NextBytes($d); [IO.File]::WriteAllBytes($f, $d)
        $t0 = $script:Tokens
        $null = Send-SIExportBlockBlob -Account 'acct' -Container 'c' -Blob 'r.bin' -File $f
        [Convert]::ToBase64String((Get-FakeBlob 'c/r.bin')) | Should -BeExactly ([Convert]::ToBase64String($d))
        @($global:SIExportSeam.Calls | Where-Object { $_.Uri -match 'blockid=YmxrMDAwMDAy' }).Count | Should -Be 2
        $resent = @($global:SIExportSeam.Calls | Where-Object { $_.Uri -match 'blockid=YmxrMDAwMDA1' })
        $resent.Count | Should -Be 2
        [string]$resent[1].Headers['Authorization'] | Should -Not -Be ([string]$resent[0].Headers['Authorization'])
    }
    It 'a 400 fails the upload with the service''s words; nothing is committed' {
        Reset-FakeStore -Rules @(@{ Match = 'comp=block&'; Nth = @(2); Code = 400; Content = 'InvalidBlockId'; ErrorCode = 'InvalidQueryParameterValue'; Seen = 0; Header = $null })
        $f = Join-Path $TestDrive 'bad.bin'; [IO.File]::WriteAllBytes($f, [byte[]]::new(5000))
        { Send-SIExportBlockBlob -Account 'acct' -Container 'c' -Blob 'bad.bin' -File $f } | Should -Throw '*HTTP Status: 400 InvalidQueryParameterValue*'
        $global:SIExportSeam.Committed.ContainsKey('c/bad.bin') | Should -BeFalse
    }
    It 'the backup copy is made by the service: identical, no byte downloaded, every range against the source''s ETag, the content type kept' {
        $script:SIExportCopyBlockBytesSaved = $script:SIExportCopyBlockBytes; $script:SIExportCopyBlockBytes = 1000
        try {
            [byte[]]$src = [byte[]]::new(3456); (New-Object Random 11).NextBytes($src)
            $global:SIExportSeam.Committed['exports/old.xlsx'] = [object[]]@(, $src)
            Copy-SIExportBlobInBlocks -Account 'acct' -Container 'exports' -SrcBlob 'old.xlsx' -DestBlob 'old.2026-10-17_080000.xlsx.bak'
            [Convert]::ToBase64String((Get-FakeBlob 'exports/old.2026-10-17_080000.xlsx.bak')) | Should -BeExactly ([Convert]::ToBase64String($src))
            $global:SIExportSeam.Down | Should -Be 0
            @($global:SIExportSeam.Calls | Where-Object { $_.Method -eq 'GET' }).Count | Should -Be 0
            $copies = @($global:SIExportSeam.Calls | Where-Object { $_.Headers['x-ms-copy-source'] })
            $copies.Count | Should -Be 4
            @($copies | ForEach-Object { [string]$_.Headers['x-ms-source-range'] } | Sort-Object) | Should -Be @('bytes=0-999', 'bytes=1000-1999', 'bytes=2000-2999', 'bytes=3000-3455')
            @($copies | Where-Object { [string]$_.Headers['x-ms-source-if-match'] -ne '"etag-src"' }).Count | Should -Be 0
            @($copies | Where-Object { [string]$_.Headers['x-ms-copy-source-authorization'] -notmatch '^Bearer tok-' }).Count | Should -Be 0
            $global:SIExportSeam.ContentTypes['exports/old.2026-10-17_080000.xlsx.bak'] | Should -Be 'application/x-test'
        } finally { $script:SIExportCopyBlockBytes = $script:SIExportCopyBlockBytesSaved }
    }
    It 'a service that refuses the copy (403 on the first range): one request, then the range copy -- identical' {
        Reset-FakeStore -Rules @(@{ Match = 'comp=block&'; Nth = @(1); Code = 403; Content = 'CannotVerifyCopySource'; ErrorCode = 'CannotVerifyCopySource'; Seen = 0; Header = 'x-ms-copy-source' })
        [byte[]]$src = [byte[]]::new(3456); (New-Object Random 12).NextBytes($src)
        $global:SIExportSeam.Committed['exports/old.xlsx'] = [object[]]@(, $src)
        Copy-SIExportBlobInBlocks -Account 'acct' -Container 'exports' -SrcBlob 'old.xlsx' -DestBlob 'old.bak'
        [Convert]::ToBase64String((Get-FakeBlob 'exports/old.bak')) | Should -BeExactly ([Convert]::ToBase64String($src))
        @($global:SIExportSeam.Calls | Where-Object { $_.Headers['x-ms-copy-source'] }).Count | Should -Be 1
        @($global:SIExportSeam.Calls | Where-Object { $_.Method -eq 'GET' }).Count | Should -Be 4
        ($script:Said -join "`n") | Should -Match 'copied range by range instead'
    }
    It 'SI_ExportServerCopy = off: the range copy only; a missing source copies nothing' {
        $global:SI_ExportServerCopy = 'off'
        [byte[]]$src = [byte[]]::new(2100); (New-Object Random 13).NextBytes($src)
        $global:SIExportSeam.Committed['exports/old.xlsx'] = [object[]]@(, $src)
        Copy-SIExportBlobInBlocks -Account 'acct' -Container 'exports' -SrcBlob 'old.xlsx' -DestBlob 'old.bak'
        [Convert]::ToBase64String((Get-FakeBlob 'exports/old.bak')) | Should -BeExactly ([Convert]::ToBase64String($src))
        @($global:SIExportSeam.Calls | Where-Object { $_.Headers['x-ms-copy-source'] }).Count | Should -Be 0
        Copy-SIExportBlobInBlocks -Account 'acct' -Container 'exports' -SrcBlob 'missing.xlsx' -DestBlob 'x.bak'
        $global:SIExportSeam.Committed.ContainsKey('exports/x.bak') | Should -BeFalse
    }
    It 'the degree: 4 by default; 1 / off = one at a time; at most 8; never more than one in flight at 1' {
        Get-SIExportUploadDegree -Setting $null -EnvValue '' | Should -Be 4
        Get-SIExportUploadDegree -Setting 'off' -EnvValue '' | Should -Be 1
        Get-SIExportUploadDegree -Setting 1 -EnvValue '' | Should -Be 1
        Get-SIExportUploadDegree -Setting 20 -EnvValue '' | Should -Be 8
        Get-SIExportUploadDegree -Setting $null -EnvValue '2' | Should -Be 2
        Test-SIExportServerCopy -Setting $null | Should -BeTrue
        Test-SIExportServerCopy -Setting 'false' | Should -BeFalse
        $global:SI_ExportUpload_Parallel = 1
        $f = Join-Path $TestDrive 'one.bin'; [byte[]]$d = [byte[]]::new(6000); (New-Object Random 5).NextBytes($d); [IO.File]::WriteAllBytes($f, $d)
        $null = Send-SIExportBlockBlob -Account 'acct' -Container 'c' -Blob 'one.bin' -File $f
        [Convert]::ToBase64String((Get-FakeBlob 'c/one.bin')) | Should -BeExactly ([Convert]::ToBase64String($d))
        $global:SIExportSeam.MaxInFlight | Should -Be 1
    }
}

Describe 'C. progress lines' {
    It 'the JSON file: "export: rows X of Y" at least every -ProgressSeconds, and the last count at the end' {
        $script:Said.Clear()
        $rows = New-FsRows -Count 60 -Seed 4
        Write-RAJsonArrayFile -Pager (New-PagerOf -Rows $rows -PageSize 20 -SleepMs 1100) -Path (Join-Path $TestDrive 'p.json') -Depth 20 -Total 60 -ProgressSeconds 1
        $l = @($script:Said | Where-Object { $_ -match '^  export: rows [\d,.]+ of 60 written to the JSON file$' })
        $l.Count | Should -BeGreaterOrEqual 2
        $l[-1] | Should -Match 'rows 60 of 60'
    }
}

Describe 'B. the delivery on the cores = one pass' {
    It 'the stored rows decoded on the cores: the same rows (value by value, JSON per row), in the same order' {
        $cols = @{ 1 = [string[]]@('RowKey', 'A', 'When', 'N'); 2 = [string[]]@('RowKey', 'B', 'When', 'X') }
        $dc = New-Object 'System.Collections.Generic.HashSet[string]'; [void]$dc.Add('When')
        $byOrd = @{ 1 = @{ Columns = [System.Collections.Generic.List[string]]::new($cols[1]); DateCols = $dc }; 2 = @{ Columns = [System.Collections.Generic.List[string]]::new($cols[2]); DateCols = $dc } }
        $stored = New-Object 'System.Collections.Generic.List[object]'
        for ($i = 0; $i -lt 900; $i++) {
            $ord = 1 + ($i % 2)
            $j = '{"RowKey":"r' + $i + '","A":"a ' + $i + '","When":"2026-10-' + (10 + $i % 9) + 'T08:00:00Z","N":' + ($i * 1.5).ToString([cultureinfo]::InvariantCulture) + ',"Extra":[1,"two",{"k":' + $i + '}]}'
            if ($ord -eq 2) { $j = '{"RowKey":"r' + $i + '","B":true,"X":null,"When":"not a date"}' }
            $stored.Add(@{ Json = $j; RaReport = $ord })
        }
        $par = Invoke-RAParallelDecode -Stored $stored.ToArray() -ByOrd $byOrd
        $par | Should -Not -BeNullOrEmpty
        $par.Count | Should -Be 900
        for ($i = 0; $i -lt 900; $i++) {
            $h = $stored[$i]; $rep = $byOrd[[int]$h['RaReport']]
            $one = ConvertFrom-RAStreamJson -Json $h['Json'] -Columns $rep.Columns.ToArray() -DateCols $rep.DateCols
            (ConvertTo-Json -InputObject $par[$i] -Depth 10 -Compress) | Should -BeExactly (ConvertTo-Json -InputObject $one -Depth 10 -Compress)
            if ($h['RaReport'] -eq 1) { $par[$i].When | Should -BeOfType [datetime] }
        }
    }
    It 'the Log Analytics preparation of a chunk on the cores = one pass: every row (JSON), in order, the type report' {
        $types = @{ Count = 'long'; Score = 'real'; Impact = 'long'; Flag = 'boolean'; When = 'datetime'; Text = 'string'; Seen = 'datetime' }
        foreach ($n in 7, 50, 1203) {
            $rows = New-FsRows -Count $n -Seed (100 + $n)
            $global:SI_LogIngestRunCollectionTime = $null
            $one = ConvertTo-RALaPostRows -Rows $rows -HostName 'h1' -Fqdn 'h1.f' -User 'u' -Types $types -DecimalCompanions @('Impact') -TextCompanions @('Count') -NumberCompanions @('When') -OneCore
            $ct = $global:SI_LogIngestRunCollectionTime
            $par = Invoke-RAParallelLaPrepare -Rows $rows -HostName 'h1' -Fqdn 'h1.f' -User 'u' -Types $types -DecimalCompanions @('Impact') -TextCompanions @('Count') -NumberCompanions @('When')
            $par | Should -Not -BeNullOrEmpty -Because "$n rows go to the cores"
            $global:SI_LogIngestRunCollectionTime | Should -Be $ct -Because 'one collection time per run'
            $par.Rows.Count | Should -Be $one.Rows.Count
            for ($i = 0; $i -lt $one.Rows.Count; $i++) {
                (ConvertTo-Json -Depth 100 -InputObject $par.Rows[$i] -Compress) | Should -BeExactly (ConvertTo-Json -Depth 100 -InputObject $one.Rows[$i] -Compress) -Because "row $i of $n"
            }
            foreach ($k in 'Converted', 'Failed', 'Rounded', 'MovedToText', 'MovedToNumber') {
                $a = $one.Align.$k; $b = $par.Align[$k]
                @($a.Keys | Sort-Object) | Should -Be @($b.Keys | Sort-Object) -Because "$k columns"
                foreach ($c in $a.Keys) { [long]$b[$c] | Should -Be ([long]$a[$c]) -Because "$k $c" }
            }
            # the input rows are not changed (copies are prepared)
            ($rows[0].PSObject.Properties.Name -contains 'Computer') | Should -BeFalse
        }
    }
    It 'through the chunked post: the same chunks and the same JSON per post, one core and several' {
        $rows = New-FsRows -Count 2400 -Seed 77
        $types = @{ Count = 'long'; Impact = 'long' }
        $run = {
            param([bool]$OneCore)
            $posts = New-Object 'System.Collections.Generic.List[string]'
            $null = Invoke-RALaChunkedPost -Rows $rows -TargetBytes 256KB `
                -Prepare { param($c) ConvertTo-RALaPostRows -Rows $c -HostName 'h' -Types $types -DecimalCompanions @('Impact') -OneCore:$OneCore } `
                -Post { param($p) $b = 0L; $sb = [System.Text.StringBuilder]::new(); foreach ($r in $p) { $j = ConvertTo-Json -InputObject $r -Depth 100 -Compress; $b += [Text.Encoding]::UTF8.GetByteCount($j) + 1; [void]$sb.Append($j).Append("`n") }; $posts.Add($sb.ToString()); [pscustomobject]@{ RowsPosted = $p.Count; BytesPosted = $b } }
            , $posts.ToArray()
        }
        $global:SI_LogIngestRunCollectionTime = [datetime]'2026-10-17T09:00:00Z'
        $a = & $run $true; $b = & $run $false
        $a.Count | Should -BeGreaterThan 3
        $b.Count | Should -Be $a.Count
        for ($i = 0; $i -lt $a.Count; $i++) { $b[$i] | Should -BeExactly $a[$i] -Because "post $i" }
    }
    It 'a worker failure: the step on one core, the same result, said once' {
        $script:Said.Clear(); $script:RAParallelFallbackSaid = @{}
        $rows = New-FsRows -Count 300 -Seed 6
        $global:SI_LogIngestRunCollectionTime = [datetime]'2026-10-17T09:00:00Z'
        $ref = ConvertTo-RALaPostRows -Rows $rows -HostName 'h' -OneCore
        Mock Invoke-RAParallelParts { throw 'a worker broke' }
        $got = ConvertTo-RALaPostRows -Rows $rows -HostName 'h'
        $got2 = ConvertTo-RALaPostRows -Rows $rows -HostName 'h'
        for ($i = 0; $i -lt 300; $i += 17) { (ConvertTo-Json -Depth 100 -InputObject $got.Rows[$i] -Compress) | Should -BeExactly (ConvertTo-Json -Depth 100 -InputObject $ref.Rows[$i] -Compress) }
        @($script:Said | Where-Object { $_ -match 'prepared for Log Analytics on one processor core instead of several \(the result is the same\): a worker broke' }).Count | Should -Be 1
        Invoke-RAParallelJsonText -Rows $rows -Depth 20 | Should -BeNullOrEmpty
        $f1 = Join-Path $TestDrive 'w1.json'; $f2 = Join-Path $TestDrive 'w2.json'
        Write-RAJsonArrayFile -Rows $rows -Path $f1; Write-JsonBefore -Rows $rows -Path $f2
        Get-Sha $f1 | Should -BeExactly (Get-Sha $f2)
    }
}

Describe 'C. memory bounded' {
    It 'the JSON file with its blocks going up: what the upload holds is the blocks in flight (at most the degree, each one flush), never the file' {
        Reset-FakeStore -DelayMs 40
        $global:SIExportSeam.Discard = $true
        $script:SIExportBlockBytes = 64KB; $script:RAJsonFlushBytes = 16KB
        try {
            $rows = New-FsRows -Count 9000 -Seed 21
            $f = Join-Path $TestDrive 'mem.json'
            $up = New-SIExportStagedUpload -Destination 'https://acct.blob.core.windows.net/c/' -FileName 'mem.json' -Degree 4
            Write-RAJsonArrayFile -Pager (New-PagerOf -Rows $rows -PageSize 1000) -Path $f -Depth 20 -Upload $up
            Complete-SIExportStagedUpload -Upload $up | Should -BeTrue
            $len = (Get-Item $f).Length
            $bound = 4 * (64KB + 16KB + 16KB)
            $global:SIExportSeam.MaxInFlight | Should -BeLessOrEqual 4
            $global:SIExportSeam.MaxInFlightBytes | Should -BeLessOrEqual $bound
            $len | Should -BeGreaterThan (2 * $bound) -Because 'the bound is far below the file'
            @($global:SIExportSeam.Calls | Where-Object { $_.Len -gt (64KB + 16KB + 16KB) }).Count | Should -Be 0
        } finally { $script:SIExportBlockBytes = $script:SavedBlock; $script:RAJsonFlushBytes = 1MB }
    }
}
Describe 'C. the container-scope guard: every function a worker calls is loaded inside it' {
    BeforeAll {
        # run INSIDE the worker: every command the script calls, transitively through the functions defined there, must
        # resolve; a name the calling function checks for first (Get-Command / Test-Path Function:) may be missing
        $script:Closure = @'
param([string]$RootText)
$seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$missing = New-Object 'System.Collections.Generic.List[object]'
# functions defined INSIDE a scanned function (a helper of its own, e.g. Calculate-RiskScore's) are defined when it runs
$local = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$queue = New-Object 'System.Collections.Generic.Queue[object]'
$queue.Enqueue(@([scriptblock]::Create($RootText).Ast, 'the part script'))
while ($queue.Count -gt 0) {
    $item = $queue.Dequeue(); $ast = $item[0]; $where = $item[1]
    foreach ($fd in $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { [void]$local.Add(($fd.Name -replace '^(?i)(global|script|local):', '')) }
    $guarded = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] -and $a.GetCommandName() -in 'Get-Command', 'Test-Path' }, $true)) {
        foreach ($s in $g.FindAll({ param($a) $a -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $a -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)) {
            $v = ([string]$s.Value) -replace '^(?i)function:\\?', ''
            if ($v) { [void]$guarded.Add($v) }
        }
    }
    foreach ($cmd in $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $n = $cmd.GetCommandName()
        if (-not $n) { continue }
        $c = Get-Command -Name $n -ErrorAction Ignore
        if (-not $c) { if (-not $guarded.Contains($n) -and $seen.Add('missing:' + $n)) { $missing.Add([pscustomobject]@{ Name = $n; Text = ('{0} (called in {1})' -f $n, $where) }) }; continue }
        if ($c.CommandType -eq 'Function' -and $seen.Add($n)) { $queue.Enqueue(@($c.ScriptBlock.Ast, $n)) }
    }
}
, [string[]]@($missing | Where-Object { -not $local.Contains($_.Name) } | ForEach-Object { $_.Text })
'@
    }
    It 'the Risk Analysis workers: the scores, the stored form, the decode, the JSON text, the Log Analytics preparation (both rounds)' {
        # the ONE exception, named: the stored form's SUMMARY branch (ConvertTo-RAStreamRowItems) calls the summary / trend
        # functions, which the workers do not load -- the stored form goes to the workers for a DETAILED slice only (pinned below)
        $script:SummaryOnly = @('ConvertTo-SIDataSummaryItems', 'ConvertTo-SITrendDimensionValue', 'Get-SITrendRowAssetIds')
        ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SqlStream.ps1'))) | Should -Match ([regex]::Escape('if ($Stream.Grain -eq ''Detailed'' -and (Get-Command -Name Invoke-RAParallelStreamItems'))
        $w = Get-RAParallelWorkers -Count 1
        $bad = New-Object 'System.Collections.Generic.List[string]'
        foreach ($name in 'RAParallelScoreScript', 'RAParallelItemsScript', 'RAParallelDecodeScript', 'RAParallelJsonTextScript', 'RAParallelLaShapeScript', 'RAParallelLaAlignScript') {
            $text = Get-Variable -Scope Script -Name $name -ValueOnly
            $text | Should -Not -BeNullOrEmpty -Because $name
            $ps = [powershell]::Create(); $ps.Runspace = $w[0]
            try { $r = @($ps.AddScript($script:Closure).AddArgument([string]$text).Invoke()) } finally { $ps.Dispose() }
            foreach ($x in $r) { foreach ($m in @($x)) { if ($m -and -not ($name -eq 'RAParallelItemsScript' -and ($m -split ' ')[0] -in $script:SummaryOnly)) { $bad.Add(('{0}: {1}' -f $name, $m)) } } }
        }
        ($bad | Select-Object -First 15) -join ' | ' | Should -BeNullOrEmpty
    }
    It 'the engine files every worker loads include those the delivery steps are defined in' {
        foreach ($f in 'risk-analysis/_shared/RA-SqlStream.ps1', '_shared/SI-LogIngest.ps1', 'risk-analysis/_shared/RA-ColumnTypeAlign.ps1') { $script:RAParallelFiles | Should -Contain $f }
    }
    It 'the upload workers: the HTTP seam and every function it calls are handed to them' {
        Reset-FakeStore
        Remove-Item -Path function:global:Invoke-SIAzRestHttp -ErrorAction SilentlyContinue
        Remove-Item -Path function:script:Invoke-SIAzRestHttp -ErrorAction SilentlyContinue
        . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')   # the REAL seam, as a run has it
        try {
            $pool = New-SIExportRequestPool -Degree 2
            $ps = [powershell]::Create(); $ps.RunspacePool = $pool.Pool
            try { $r = @($ps.AddScript($script:Closure).AddArgument((Get-SIExportWorkerScript)).Invoke()) } finally { $ps.Dispose(); Close-SIExportRequestPool -Pool $pool }
            (@($r | ForEach-Object { $_ } | Where-Object { $_ }) -join ' | ') | Should -BeNullOrEmpty
        } finally {
            Set-Item -Path function:global:Invoke-SIAzRestHttp -Value $script:FakeHttp
            Set-Item -Path function:script:Invoke-SIAzRestHttp -Value $script:FakeHttp
        }
    }
}

Describe 'WIRING' {
    BeforeAll {
        $script:Ra = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $script:Exp = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\Send-SecurityInsightExportFile.ps1'))
        $script:Sql = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SqlStream.ps1'))
        $script:Del = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-Delivery.ps1'))
    }
    It 'the JSON file: the read-ahead pager, the blocks sent while it is written (never on a dry run), the rows expected' {
        $script:Ra | Should -Match ([regex]::Escape('Write-RAJsonArrayFile -Pager (New-RARowPager -Stream $script:RAStream -Source View -ReadAhead) -Path $global:OutputJson -Depth 20 -Upload $script:RAJsonStaged -Total $script:RAViewCount'))
        $script:Ra | Should -Match ([regex]::Escape('if (-not $script:SIWhatIf -and -not [string]::IsNullOrWhiteSpace([string]$global:ExportDestination)) {'))
        $script:Ra | Should -Match ([regex]::Escape('$null = Complete-SIExportStagedUpload -Upload $script:RAJsonStaged'))
        $script:Ra | Should -Match ([regex]::Escape('-Staged               $(if ($localPath -eq $global:OutputJson) { $script:RAJsonStaged } else { $null })'))
        $script:Ra.IndexOf('New-SIExportStagedUpload') | Should -BeLessThan $script:Ra.IndexOf('Write-Step ("Uploading export files to:')
    }
    It 'the upload step commits the staged blocks after the backup, the file from the disk otherwise' {
        $iBak = $script:Exp.IndexOf('Copy-SIExportBlobInBlocks -Account $StorageAccount -Container $Container -SrcBlob $blobName -DestBlob $backupName')
        $iCommit = $script:Exp.IndexOf('$null = Complete-SIExportBlockList -Account $StorageAccount -Container $Container -Blob $blobName -Ids $Staged.Ids.ToArray()')
        $iFile = $script:Exp.IndexOf('$null = Send-SIExportBlockBlob -Account $StorageAccount -Container $Container -Blob $blobName -File $LocalPath')
        $iBak | Should -BeGreaterThan 0; $iCommit | Should -BeGreaterThan $iBak; $iFile | Should -BeGreaterThan $iCommit
    }
    It 'the pager decodes on the cores; ConvertTo-RALaPostRows prepares on the cores; -OneCore keeps one pass' {
        $script:Sql | Should -Match ([regex]::Escape('$dec = Invoke-RAParallelDecode -Stored $hs -ByOrd $s.ByOrd'))
        $script:Del | Should -Match ([regex]::Escape('$par = Invoke-RAParallelLaPrepare -Rows $Rows'))
        $script:Del | Should -Match ([regex]::Escape('$texts = Invoke-RAParallelJsonText -Rows $Rows -Depth $Depth'))
    }
}
