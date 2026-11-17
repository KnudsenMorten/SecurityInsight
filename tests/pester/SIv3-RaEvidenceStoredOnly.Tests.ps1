#Requires -Version 5.1
<#
    WHERE THE AFFECTED SOFTWARE IS, ON THE STORED FINDING ONLY -- Risk Analysis' own outputs stay byte for byte as they were.

    Risk Analysis puts si_evidence_paths / si_install_kind / si_bundled_by on the rows of a software whose evidence is stored
    (RA-SoftwareEvidence.ps1). Risk Analysis' outputs take their columns from the rows, so without a rule every install with
    stored evidence would have had three new columns in the workbook, the JSON file and Log Analytics -- with nothing
    switched on. What is pinned here:
      * the stored finding (sidata.Finding DetailJson: the web pages, an output column an admin switched on) CARRIES them;
      * a report's columns never name them (Get-RAOutputColumns), and a stored row read back as the report's row (the
        workbook, the JSON file, Log Analytics, the AI summary, the KPIs, SI_Finding_CL all read through it) does not carry
        them -- one core and several;
      * BYTE-IDENTICAL: the JSON file and the Log Analytics rows made from rows WITH the evidence are the bytes made from the
        same rows WITHOUT it (the result before the evidence existed);
      * every path in full, no cap (owner 2026-11-17);
      * WIRING: Risk Analysis registers the output columns and the workbook column list through Get-RAOutputColumns.
    Offline, pwsh 7 (the decode workers are RA-ParallelScore.ps1's). NO EMOJI IN THIS FILE (no BOM).
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
    . (Join-Path $raShared 'RA-SoftwareEvidence.ps1')
    $script:SavedThreads = $global:SI_RA_ScoringThreads; $script:SavedMin = $global:SI_RA_ParallelMinRows
    $global:SI_RA_ScoringThreads = 4; $global:SI_RA_ParallelMinRows = 2
    function script:Write-Info { param($m) }
    function script:Write-Ok { param($m) }
    function script:Write-Warn { param($m) }
    function script:Write-Warn2 { param($m) }
    function script:Write-Diag { param($m) }

    $script:Dev = 'aaaaaaaa1111bbbb2222cccc3333dddd4444eeee'
    # the Risk Analysis rows of a Detailed report, BEFORE the evidence existed
    function script:New-RaRows {
        param([int]$Count)
        $out = New-Object 'System.Collections.Generic.List[object]'
        for ($i = 0; $i -lt $Count; $i++) {
            $o = [ordered]@{ AssetName = ('host{0}' -f ($i % 7)); AssetId = ('id{0}' -f ($i % 7)); MdeDeviceId = $(if ($i % 3 -eq 2) { 'other-device' } else { $script:Dev })
                ConfigurationId = ('CVE-2026-{0:D4}' -f $i); ConfigurationName = ('Vulnerability {0}' -f $i); SecuritySeverity = @('High', 'Medium', 'Critical')[$i % 3]
                SI_AffectedVendor = 'openssl'; SI_AffectedProduct = 'openssl'; SI_AffectedVersion = $(if ($i % 2) { '3.0.13' } else { '3.0.13;3.5.7' })
                si_affected_path = 'C:\Program Files\Adobe\Acrobat DC\Acrobat\libcrypto-3-x64.dll'
                RiskScoreTotal = [double](10 + $i); CollectionTime = '2026-11-17T06:00:00Z'; Seen = '2026-11-0' + (1 + $i % 9) + 'T08:00:00Z'; TraceName = ('t{0}' -f $i); TraceID = ('{0:x16}' -f $i) }
            $out.Add([pscustomobject]$o)
        }
        , $out.ToArray()
    }
    $script:Ev = @(
        [pscustomobject]@{ DeviceId = $script:Dev; Vendor = 'openssl'; Product = 'openssl'; Version = '3.0.13'; FullPath = 'C:\Program Files\Adobe\Acrobat DC\Acrobat\libcrypto-3-x64.dll'; InstallKind = 'bundled'; Application = 'acrobat_dc'; ApplicationVendor = 'adobe'; ApplicationVersion = '23.008'; ApplicationSource = 'inventory' }
        [pscustomobject]@{ DeviceId = $script:Dev; Vendor = 'openssl'; Product = 'openssl'; Version = '3.5.7'; FullPath = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'; InstallKind = 'installed'; Application = 'openssl'; ApplicationSource = 'inventory' }
    )
    # the shaping of Risk Analysis: the report's columns = the union of the rows' columns, in first-seen order
    function script:Get-Union { param([object[]]$Rows) $l = New-Object 'System.Collections.Generic.List[string]'; foreach ($r in $Rows) { foreach ($n in $r.PSObject.Properties.Name) { if (-not $l.Contains($n)) { $l.Add($n) } } }; , $l.ToArray() }
    # store (sidata.Finding DetailJson) + read back as the report's rows with its registered columns
    function script:Invoke-StoreAndRead {
        param([object[]]$Rows, [string[]]$Columns, [switch]$Cores)
        $stored = @(foreach ($r in $Rows) { @{ Json = (ConvertTo-RAStreamJson -Row $r).Json; RaReport = 1 } })
        $byOrd = @{ 1 = @{ Columns = [System.Collections.Generic.List[string]]::new([string[]]$Columns); DateCols = $null } }
        if ($Cores) { $p = Invoke-RAParallelDecode -Stored $stored -ByOrd $byOrd; if ($null -eq $p) { throw 'the decode did not run on the cores' }; return @{ Stored = $stored; Rows = $p } }
        @{ Stored = $stored; Rows = @(foreach ($h in $stored) { ConvertFrom-RAStreamJson -Json $h['Json'] -Columns $Columns }) }
    }
    function script:Get-Sha { param([string]$Path) $s = [IO.File]::OpenRead($Path); try { [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($s)) } finally { $s.Dispose() } }
}

AfterAll {
    $global:SI_RA_ScoringThreads = $script:SavedThreads; $global:SI_RA_ParallelMinRows = $script:SavedMin
}

Describe 'the evidence fields are on the stored finding, never on the report''s outputs' {
    BeforeAll {
        $script:Before = New-RaRows -Count 240
        $script:After = New-RaRows -Count 240
        # (it answers the rows as ONE array: never wrapped in @())
        $script:After = Add-RASoftwareEvidence -Rows $script:After -Read { param($ids) $script:Ev }
        $script:ColsBefore = Get-Union $script:Before
        $script:ColsAfter = Get-Union $script:After
    }
    It 'the rows really carry the evidence (the proof is not empty)' {
        @($script:After | Where-Object { $_.PSObject.Properties['si_evidence_paths'] }).Count | Should -BeGreaterThan 100
        $script:ColsAfter | Should -Contain 'si_evidence_paths'
        $script:ColsAfter | Should -Contain 'si_bundled_by'
    }
    It 'the report''s columns (workbook, read-back shape) are exactly the columns before' {
        (Get-RAOutputColumns -Columns $script:ColsAfter) | Should -Be $script:ColsBefore
        (Get-RAOutputColumns -Columns @('A', 'SI_EVIDENCE_PATHS', 'B', 'si_install_kind')) | Should -Be @('A', 'B') -Because 'any spelling'
        $none = Get-RAOutputColumns -Columns $null; $none.Count | Should -Be 0
    }
    It 'the stored finding carries them (the web pages and a switched-on output column read them there)' {
        $s = Invoke-StoreAndRead -Rows $script:After -Columns (Get-RAOutputColumns -Columns $script:ColsAfter)
        $withEv = @($s.Stored | Where-Object { $_['Json'] -match '"si_evidence_paths"' }).Count
        $withEv | Should -BeGreaterThan 100
        ($s.Stored[0]['Json'] | ConvertFrom-Json).si_install_kind | Should -Not -BeNullOrEmpty
    }
    It 'read back as the report''s rows (one core and several): every row is the row before, value for value' {
        $b = Invoke-StoreAndRead -Rows $script:Before -Columns $script:ColsBefore
        foreach ($cores in $false, $true) {
            $a = Invoke-StoreAndRead -Rows $script:After -Columns (Get-RAOutputColumns -Columns $script:ColsAfter) -Cores:$cores
            $a.Rows.Count | Should -Be $b.Rows.Count
            for ($i = 0; $i -lt $b.Rows.Count; $i++) {
                (ConvertTo-Json -InputObject $a.Rows[$i] -Depth 10 -Compress) | Should -BeExactly (ConvertTo-Json -InputObject $b.Rows[$i] -Depth 10 -Compress) -Because "row $i, cores=$cores"
            }
        }
    }
    It 'BYTE-IDENTICAL: the JSON file from rows with the evidence = the file before (SHA-256)' {
        $b = Invoke-StoreAndRead -Rows $script:Before -Columns $script:ColsBefore
        $a = Invoke-StoreAndRead -Rows $script:After -Columns (Get-RAOutputColumns -Columns $script:ColsAfter) -Cores
        $pb = Join-Path $TestDrive 'before.json'; $pa = Join-Path $TestDrive 'after.json'
        Write-RAJsonArrayFile -Rows @($b.Rows) -Path $pb -Depth 20 -OneCore
        Write-RAJsonArrayFile -Rows @($a.Rows) -Path $pa -Depth 20
        Get-Sha $pa | Should -BeExactly (Get-Sha $pb)
        [IO.File]::ReadAllText($pa) | Should -Not -Match 'si_evidence_paths|si_install_kind|si_bundled_by'
    }
    It 'BYTE-IDENTICAL: the Log Analytics rows from rows with the evidence = the rows before' {
        $b = Invoke-StoreAndRead -Rows $script:Before -Columns $script:ColsBefore
        $a = Invoke-StoreAndRead -Rows $script:After -Columns (Get-RAOutputColumns -Columns $script:ColsAfter)
        $global:SI_LogIngestRunCollectionTime = '2026-11-17T00:00:00Z'
        $lb = ConvertTo-RALaPostRows -Rows @($b.Rows) -HostName 'h' -Fqdn 'h.f' -User 'u' -OneCore
        $global:SI_LogIngestRunCollectionTime = '2026-11-17T00:00:00Z'
        $la = ConvertTo-RALaPostRows -Rows @($a.Rows) -HostName 'h' -Fqdn 'h.f' -User 'u' -OneCore
        (ConvertTo-Json -InputObject @($la.Rows) -Depth 20 -Compress) | Should -BeExactly (ConvertTo-Json -InputObject @($lb.Rows) -Depth 20 -Compress)
    }
    It 'a read without the report''s columns (the trace / CI reads) is unchanged: it keeps every stored field' {
        $j = (ConvertTo-RAStreamJson -Row $script:After[0]).Json
        (ConvertFrom-RAStreamJson -Json $j).PSObject.Properties['si_evidence_paths'] | Should -Not -BeNullOrEmpty
    }
}

Describe 'every path, in full (owner 2026-11-17): no cap, no "+N more"' {
    It 'Add-RASoftwareEvidence writes every path of the copy on the row' {
        $script:Ev80 = @(1..80 | ForEach-Object { [pscustomobject]@{ DeviceId = $script:Dev; Vendor = 'openssl'; Product = 'openssl'; Version = '3.0.13'; FullPath = ('D:\home\users\u{0:D2}\app\lib.dll' -f $_); InstallKind = 'data-folder' } })
        $r = Add-RASoftwareEvidence -Rows @([pscustomobject]@{ MdeDeviceId = $script:Dev; SI_AffectedVendor = 'openssl'; SI_AffectedProduct = 'openssl'; SI_AffectedVersion = '3.0.13' }) -Read { param($ids) $script:Ev80 }
        @($r[0].si_evidence_paths -split ';').Count | Should -Be 80
        $r[0].si_evidence_paths | Should -Not -Match 'more'
        $r[0].si_evidence_paths | Should -Match ([regex]::Escape('D:\home\users\u01\app\lib.dll')) -Because 'the full path, the user name included'
        Get-Command -Name Limit-RAEvidenceList -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}
Describe 'WIRING' {
    BeforeAll { $script:Ra = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) }
    It 'the stream registers only the output columns; the workbook column union takes only the output columns' {
        $script:Ra | Should -Match ([regex]::Escape('Add-RAStreamColumns -Stream $script:RAStream -Columns @(Get-RAOutputColumns -Columns @($DesiredColumns))'))
        $script:Ra | Should -Match ([regex]::Escape('$__outCols = @(Get-RAOutputColumns -Columns @($DesiredColumns))'))
        $script:Ra | Should -Match ([regex]::Escape('$global:FinalDesiredColumns = @($__outCols)'))
        $script:Ra | Should -Match ([regex]::Escape('foreach ($c in $__outCols)'))
    }
    It 'the evidence is added only on the database path (the in-memory path never gets it)' {
        $script:Ra | Should -Match ([regex]::Escape('if ($script:RAStreamOn -and $script:RAStream) {') + '\s*\r?\n\s*try \{ \$ResultFiltered = Add-RASoftwareEvidence')
    }
}

Describe 'the evidence is read one group of devices at a time' {
    It 'every finding row gets its own device''s paths, across every group, and no group is read twice' {
        $reads = New-Object System.Collections.Generic.List[int]
        $rd = { param($ids) $reads.Add(@($ids).Count); foreach ($i in @($ids)) { [pscustomobject]@{ DeviceId = $i; Vendor = 'apache'; Product = 'log4j'; Version = '2.14.1'; FullPath = ('C:\Users\{0}\app\log4j-core.jar' -f $i); InstallKind = 'bundled'; Application = 'App'; ApplicationSource = 'folder' } } }.GetNewClosure()
        $rows = @(1..5 | ForEach-Object { [pscustomobject]@{ MdeDeviceId = ('d{0}' -f $_); SI_AffectedVendor = 'apache'; SI_AffectedProduct = 'log4j'; SI_AffectedVersion = '2.14.1' } })
        $r = @(Add-RASoftwareEvidence -Rows $rows -Read $rd -DevicesPerRead 2 | ForEach-Object { $_ })
        $r.Count | Should -Be 5
        @($reads) | Should -Be @(2, 2, 1)
        foreach ($x in $r) { $x.si_evidence_paths | Should -Be ('C:\Users\{0}\app\log4j-core.jar' -f $x.MdeDeviceId) }
    }
    It 'a failed read of a later group keeps every row and leaves the unread rows empty (unknown), never guessed' {
        $global:RA_SoftwareEvidenceSaid = $false
        $n = [ref]0
        $rd = { param($ids) $n.Value++; if ($n.Value -ge 2) { throw 'read failed' }; foreach ($i in @($ids)) { [pscustomobject]@{ DeviceId = $i; Vendor = 'apache'; Product = 'log4j'; Version = '2.14.1'; FullPath = ('C:\{0}\x.jar' -f $i); InstallKind = 'bundled'; Application = 'App'; ApplicationSource = 'folder' } } }.GetNewClosure()
        $said = New-Object System.Collections.Generic.List[string]
        $rows = @(1..4 | ForEach-Object { [pscustomobject]@{ MdeDeviceId = ('d{0}' -f $_); SI_AffectedVendor = 'apache'; SI_AffectedProduct = 'log4j'; SI_AffectedVersion = '2.14.1' } })
        $r = @(Add-RASoftwareEvidence -Rows $rows -Read $rd -DevicesPerRead 2 -Log { param($m) $said.Add($m) }.GetNewClosure() | ForEach-Object { $_ })
        $r.Count | Should -Be 4 -Because 'never fewer rows than the source'
        @($r | Where-Object { $_.PSObject.Properties['si_evidence_paths'] }).Count | Should -Be 2
        foreach ($x in @($r | Where-Object { $_.PSObject.Properties['si_evidence_paths'] })) { $x.si_evidence_paths | Should -Be ('C:\{0}\x.jar' -f $x.MdeDeviceId) }
        $said.Count | Should -Be 1
        $global:RA_SoftwareEvidenceSaid = $false
    }
}

Describe 'the faster join writes exactly what the join before wrote (release 3.1.29''s review line, kept as the reference)' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'tests\fixtures\review1\ra-evidence-reference.ps1')
        # varied evidence: dictionaries (DBNull in them) and objects, case and spacing, every install kind, inventory and folder
        # applications, duplicate and empty paths, several versions and vendors -- seeded, the same every run
        $rnd = [Random]::new(1277)
        $script:Ev = New-Object System.Collections.Generic.List[object]
        $prods = @(@('apache', 'log4j'), @('Apache ', 'Log4J'), @('oracle', 'jre'), @('microsoft', '.net'), @('', 'openssl'), @('python', 'python'))
        $vers = @('2.14.1', '2.14.1 ', '8.0.381', '3.0.2', '1.1.1k', '3.11.4', '')
        $kinds = @('installed', 'bundled', 'user-profile', 'data-folder', 'registry-only', 'unknown')
        for ($d = 0; $d -lt 60; $d++) {
            $dev = $(if ($d % 7 -eq 0) { 'DEV{0:D3}' -f $d } else { 'dev{0:D3}' -f $d })
            $n = $rnd.Next(0, 40)
            for ($i = 0; $i -lt $n; $i++) {
                $pv = $prods[$rnd.Next(0, $prods.Count)]; $kd = $kinds[$rnd.Next(0, $kinds.Count)]
                $path = $(switch ($rnd.Next(0, 5)) { 0 { '' } 1 { 'C:\Program Files\App{0}\lib\x.jar' -f $rnd.Next(0, 6) } 2 { 'c:\program files\app{0}\LIB\x.jar' -f $rnd.Next(0, 6) } 3 { 'D:\Users\person{0}\AppData\Local\B\y.dll' -f $rnd.Next(0, 4) } default { 'HKLM\SOFTWARE\Vendor{0}' -f $rnd.Next(0, 3) } })
                $src = @('inventory', 'folder', '')[$rnd.Next(0, 3)]
                $o = [ordered]@{ DeviceId = $dev; Vendor = $pv[0]; Product = $pv[1]; Version = $vers[$rnd.Next(0, $vers.Count)]; FullPath = $path; InstallKind = $kd
                                 Application = @('App A', 'App B', '', 'Tool')[$rnd.Next(0, 4)]; ApplicationSource = $src
                                 ApplicationVendor = @('Contoso', '', 'Fabrikam')[$rnd.Next(0, 3)]; ApplicationVersion = @('1.0', '', '2.5.1')[$rnd.Next(0, 3)] }
                if ($rnd.Next(0, 2) -eq 0) {
                    $h = @{}; foreach ($k in $o.Keys) { $h[$k] = $(if ($o[$k] -eq '' -and $rnd.Next(0, 2) -eq 0) { [DBNull]::Value } else { $o[$k] }) }
                    $script:Ev.Add($h)
                } else { $script:Ev.Add([pscustomobject]$o) }
            }
        }
        $script:Rd = { param($ids) $w = @{}; foreach ($i in @($ids)) { $w[([string]$i).ToLowerInvariant()] = 1 }; foreach ($e in $script:Ev) { $dv = $(if ($e -is [System.Collections.IDictionary]) { [string]$e['DeviceId'] } else { [string]$e.DeviceId }); if ($w.ContainsKey($dv.ToLowerInvariant())) { $e } } }
        function script:New-IdentityRows {
            $rnd = [Random]::new(31)
            $out = New-Object System.Collections.Generic.List[object]
            for ($i = 0; $i -lt 3000; $i++) {
                $d = $rnd.Next(0, 70)   # some devices have no evidence at all
                $dev = $(switch ($rnd.Next(0, 3)) { 0 { 'dev{0:D3}' -f $d } 1 { 'DEV{0:D3}' -f $d } default { ' dev{0:D3} ' -f $d } })
                $vend = @('apache', 'Apache', 'apache;oracle', ';apache;', '', 'microsoft', 'python', 'oracle')[$rnd.Next(0, 8)]
                $prod = @('log4j', 'LOG4J ', 'log4j;jre', 'jre', '.net', 'openssl', 'python', 'nothing')[$rnd.Next(0, 8)]
                $ver = @('2.14.1', '2.14.1;8.0.381', '8.0.381', '', '3.0.2', '1.1.1k', '3.11.4', '9.9')[$rnd.Next(0, 8)]
                $o = [ordered]@{ MdeDeviceId = $dev; SI_AffectedVendor = $vend; SI_AffectedProduct = $prod; SI_AffectedVersion = $ver; n = $i }
                switch ($rnd.Next(0, 6)) {
                    0 { $o['si_evidence_paths'] = 'already there' }
                    1 { $o['si_install_kind'] = 'old value' }
                    default { }
                }
                if ($rnd.Next(0, 2) -eq 0) { $h = @{}; foreach ($k in $o.Keys) { $h[$k] = $o[$k] }; $out.Add($h) } else { $out.Add([pscustomobject]$o) }
            }
            , $out.ToArray()
        }
        function script:Get-Fields($Row) {
            $g = { param($n) if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { 'set:' + [string]$Row[$n] } else { 'absent' } } else { $q = $Row.PSObject.Properties[$n]; if ($q) { 'set:' + [string]$q.Value } else { 'absent' } } }
            '{0} | {1} | {2}' -f (& $g 'si_evidence_paths'), (& $g 'si_install_kind'), (& $g 'si_bundled_by')
        }
    }
    It 'every row: the same three fields, the same values, the same rows (3,000 rows, groups of 7 devices and one group)' {
        foreach ($per in 7, 500) {
            $a = New-IdentityRows; $b = New-IdentityRows
            $ra = @(Add-RASoftwareEvidenceReference -Rows $a -Read $script:Rd | ForEach-Object { $_ })
            $rb = @(Add-RASoftwareEvidence -Rows $b -Read $script:Rd -DevicesPerRead $per | ForEach-Object { $_ })
            $rb.Count | Should -Be $ra.Count
            $diff = 0; $filled = 0
            for ($i = 0; $i -lt $ra.Count; $i++) {
                $fa = Get-Fields $ra[$i]; $fb = Get-Fields $rb[$i]
                if ($fa -cne $fb) { $diff++; if ($diff -le 3) { Write-Host ("row {0}: before [{1}] now [{2}]" -f $i, $fa, $fb) } }
                if ($fa -like 'set:*') { $filled++ }
            }
            Write-Host ("identity (groups of {0}): {1:N0} rows, {2:N0} carry paths, {3} differ" -f $per, $ra.Count, $filled, $diff)
            $filled | Should -BeGreaterThan 300 -Because 'the proof is not empty'
            $diff | Should -Be 0
        }
    }
    It 'the index and one finding''s values equal the reference''s, field by field, on every device and software asked' {
        $old = New-SIFindingEvidenceIndexReference -Rows $script:Ev.ToArray(); $new = New-SIFindingEvidenceIndex -Rows $script:Ev.ToArray()
        @($new.Keys).Count | Should -Be @($old.Keys).Count
        $n = 0
        foreach ($d in 'dev000', 'DEV007', ' dev014 ', 'dev021', 'dev033', 'dev059', 'dev065') {
            foreach ($q in @(@('apache', 'log4j', '2.14.1'), @('', 'log4j', ''), @('apache;oracle', 'log4j;jre', '2.14.1;8.0.381'), @(';', 'openssl', '1.1.1k'), @('Apache ', ' LOG4J', '2.14.1 '), @('python', 'python', '3.11.4'), @('microsoft', '.net', '3.0.2'))) {
                $x = Get-SIFindingEvidenceValuesReference -Index $old -DeviceId $d -Vendors $q[0] -Products $q[1] -Versions $q[2]
                $y = Get-SIFindingEvidenceValues -Index $new -DeviceId $d -Vendors $q[0] -Products $q[1] -Versions $q[2]
                if ($null -eq $x) { $y | Should -BeNullOrEmpty; continue }
                $n++
                $y.Paths | Should -BeExactly $x.Paths; $y.Kinds | Should -BeExactly $x.Kinds; $y.BundledBy | Should -BeExactly $x.BundledBy
                # asked twice (the text kept on the index the second time): the same
                $z = Get-SIFindingEvidenceValues -Index $new -DeviceId $d -Vendors $q[0] -Products $q[1] -Versions $q[2]
                $z.Paths | Should -BeExactly $x.Paths; $z.BundledBy | Should -BeExactly $x.BundledBy
            }
        }
        $n | Should -BeGreaterThan 5 -Because 'the proof is not empty'
    }
}
Describe 'every path at scale (on demand only)' -Tag 'Scale' {
    It 'a large install''s shape: every device''s whole inventory in the evidence, many CVE rows per vulnerable copy -- the same fields as the join before, and the time and memory of both' -Skip:(-not $env:SI_BENCH_SHAPE_DEVICES) {
        # run when SI_BENCH_SHAPE_DEVICES is set: that many devices, each with SI_BENCH_SOFTWARE software in its evidence (default 300, every
        # one of its inventory -- as the endpoint collection stores it) of SI_BENCH_COPY_PATHS paths (2), SI_BENCH_VULN of them
        # vulnerable (15), each with SI_BENCH_CVES CVE rows (23) -- internal 2026-11-17: 7,418 missing-CVE rows over 318 copies
        $devs = 1000; $sw = 300; $cp = 2; $vu = 15; $cv = 23
        if ($env:SI_BENCH_SHAPE_DEVICES) { $devs = [int]$env:SI_BENCH_SHAPE_DEVICES }; if ($env:SI_BENCH_SOFTWARE) { $sw = [int]$env:SI_BENCH_SOFTWARE }
        if ($env:SI_BENCH_COPY_PATHS) { $cp = [int]$env:SI_BENCH_COPY_PATHS }; if ($env:SI_BENCH_VULN) { $vu = [int]$env:SI_BENCH_VULN }; if ($env:SI_BENCH_CVES) { $cv = [int]$env:SI_BENCH_CVES }
        . (Join-Path $script:SIRoot 'tests\fixtures\review1\ra-evidence-reference.ps1')
        $evRows = [ref]0
        $rd = {
            param($ids)
            $o = New-Object System.Collections.Generic.List[object]
            foreach ($id in @($ids)) { $d = [int]$id.Substring(3); for ($s = 0; $s -lt $sw; $s++) { for ($p = 0; $p -lt $cp; $p++) {
                $o.Add(@{ DeviceId = $id; Vendor = ('vendor{0:D3}' -f $s); Product = ('product{0:D3}' -f $s); Version = ('{0}.{1}' -f ($s % 7), ($d % 3)); FullPath = ('C:\Program Files\Vendor{0:D3}\Product{0:D3}\bin{1}\p.dll' -f $s, $p); InstallKind = $(if ($p -eq 1) { 'bundled' } else { 'installed' }); Application = ('Host{0:D2}' -f ($s % 40)); ApplicationSource = 'folder'; ApplicationVendor = [DBNull]::Value; ApplicationVersion = [DBNull]::Value })
            } } }
            $evRows.Value += $o.Count
            $o.ToArray()
        }.GetNewClosure()
        $mk = {
            $out = New-Object System.Collections.Generic.List[object]
            for ($d = 0; $d -lt $devs; $d++) { for ($v = 0; $v -lt $vu; $v++) { $s = ($v * 19 + $d) % $sw; for ($c = 0; $c -lt $cv; $c++) {
                $out.Add([pscustomobject]@{ MdeDeviceId = ('dev{0:D6}' -f $d); SI_AffectedVendor = ('vendor{0:D3}' -f $s); SI_AffectedProduct = ('product{0:D3}' -f $s); SI_AffectedVersion = ('{0}.{1}' -f ($s % 7), ($d % 3)); Cve = ('CVE-2026-{0}' -f $c) })
            } } }
            , $out.ToArray()
        }
        # the join before first: each row's three fields kept as one text (the rows let go), then the join now on fresh rows
        $sig = { param($x) '{0}|{1}|{2}' -f $x.si_evidence_paths, $x.si_install_kind, $x.si_bundled_by }
        $a = & $mk
        $clock = [Diagnostics.Stopwatch]::StartNew(); $evRows.Value = 0
        $ra = @(Add-RASoftwareEvidenceReference -Rows $a -Read $rd | ForEach-Object { $_ })
        $tRef = $clock.Elapsed.TotalSeconds
        $before = New-Object System.Collections.Generic.List[string]; foreach ($x in $ra) { $before.Add((& $sig $x)) }
        $ra = $null; $a = $null; [GC]::Collect()
        $b = & $mk
        $clock.Restart(); $evRows.Value = 0
        $rb = @(Add-RASoftwareEvidence -Rows $b -Read $rd | ForEach-Object { $_ })
        $tNew = $clock.Elapsed.TotalSeconds; $evNew = $evRows.Value
        $clock.Restart(); $null = & $rd @('dev000000'); $fix = $clock.Elapsed.TotalSeconds * $devs
        Write-Host ("bench (large-install shape): {0:N0} devices, {1:N0} finding rows ({2} vulnerable copies x {3} CVE rows each), {4:N0} evidence rows read ({5} software x {6} paths per device)" -f $devs, $rb.Count, $vu, $cv, $evNew, $sw, $cp)
        Write-Host ("bench: the join before {0:N1} s, now {1:N1} s (the fixture making evidence, both: about {2:N1} s) -- per finding row before {3:N3} ms, now {4:N3} ms (fixture taken out)" -f $tRef, $tNew, $fix, (1000 * ($tRef - $fix) / $rb.Count), (1000 * ($tNew - $fix) / $rb.Count))
        $rb.Count | Should -Be $before.Count
        $diff = 0; $filled = 0
        for ($i = 0; $i -lt $rb.Count; $i++) { if ((& $sig $rb[$i]) -cne $before[$i]) { $diff++ }; if ($rb[$i].si_evidence_paths) { $filled++ } }
        Write-Host ("bench: identity on the large-install shape: {0:N0} rows, {1:N0} carry paths, {2} differ" -f $rb.Count, $filled, $diff)
        $filled | Should -Be $rb.Count -Because 'every finding of a copy with evidence carries it'
        $diff | Should -Be 0
    }
    It 'a library in many applications on many servers: every finding row carries every path of its copy, in full, read one group at a time' -Skip:([bool]$env:SI_BENCH_SHAPE_DEVICES -and -not $env:SI_BENCH_DEVICES) {
        $devs = 2000; $per = 60; if ($env:SI_BENCH_DEVICES) { $devs = [int]$env:SI_BENCH_DEVICES }; if ($env:SI_BENCH_PATHS) { $per = [int]$env:SI_BENCH_PATHS }
        # the seam returns the stored evidence of the devices asked for, as the database read does -- never the whole set
        $most = [ref]0; $inSeam = [Diagnostics.Stopwatch]::new()
        # the live managed memory (collected) as each group is read, and how many devices were done before it
        $samples = New-Object System.Collections.Generic.List[object]; $doneDevs = [ref]0
        $rd = {
            param($ids)
            $done0 = $doneDevs.Value; $samples.Add(@([GC]::GetTotalMemory($true), $done0)); $doneDevs.Value += @($ids).Count
            $inSeam.Start()
            $o = New-Object System.Collections.Generic.List[object]
            foreach ($id in @($ids)) { $d = [int]$id.Substring(3); for ($p = 0; $p -lt $per; $p++) { $o.Add([pscustomobject]@{ DeviceId = $id; Vendor = 'apache'; Product = 'log4j'; Version = '2.14.1'; FullPath = ('C:\Users\person{0:D6}\AppData\Local\Programs\App{1:D3}\lib\log4j-core.jar' -f $d, $p); InstallKind = 'bundled'; Application = ('App{0:D3}' -f $p); ApplicationSource = 'folder' }) } }
            if ($o.Count -gt $most.Value) { $most.Value = $o.Count }
            $inSeam.Stop()
            $samples.Add(@([GC]::GetTotalMemory($true), $done0))   # with this group's evidence held
            $o.ToArray()
        }.GetNewClosure()
        $rows = @(0..($devs - 1) | ForEach-Object { [pscustomobject]@{ MdeDeviceId = ('dev{0:D6}' -f $_); SI_AffectedVendor = 'apache'; SI_AffectedProduct = 'log4j'; SI_AffectedVersion = '2.14.1' } })
        [GC]::Collect(); $before = [GC]::GetTotalMemory($true)
        $proc = [Diagnostics.Process]::GetCurrentProcess(); $proc.Refresh(); $peak0 = $proc.PeakWorkingSet64
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = Add-RASoftwareEvidence -Rows $rows -Read $rd
        $secs = $sw.Elapsed.TotalSeconds
        $proc.Refresh(); $after = [GC]::GetTotalMemory($true)
        # WHAT GROWS WITH THE ROWS, AND ITS BOUND (2026-11-17, measured at 1 path a row: 7 MB at 2,000 rows, 73 MB at 20,000): the
        # evidence held stays one group (at most 100 devices'); what grows is PowerShell's cost of adding the three note properties
        # to the CALL'S OWN rows (about 4 KB a row, kept with the row; an Add-Member costs more). Risk Analysis calls this once per
        # query bucket and already holds that bucket's rows, so the bound is rows per bucket x ~4 KB (30,000 rows ~ 120 MB), never
        # the run's row count.
        # the working memory beyond the rows: at each group the live memory, less what it held before, less the rows' share
        # filled so far (the kept rows pro rata) -- what the function itself holds; flat when it does not grow with the rows
        $kept = $after - $before; $work = 0.0
        foreach ($s in $samples) { $w = $s[0] - $before - ($kept * $s[1] / [Math]::Max(1, $devs)); if ($w -gt $work) { $work = $w } }
        Write-Host ("bench: the function's own working memory (live, collected, beyond the rows filled so far) at most {0:N0} MB over {1:N0} group(s)" -f ($work / 1MB), ($samples.Count / 2))
        Write-Host ("bench: {0:N0} finding rows x {1} paths: {2:N1} s ({7:N1} s of it making the fixture's evidence); most evidence rows held at once {3:N0}; managed memory kept after (the rows with their paths) {4:N0} MB; process peak {5:N0} MB (before {6:N0} MB)" -f $devs, $per, $secs, $most.Value, (($after - $before) / 1MB), ($proc.PeakWorkingSet64 / 1MB), ($peak0 / 1MB), $inSeam.Elapsed.TotalSeconds)
        $most.Value | Should -BeLessOrEqual (100 * $per) -Because 'the evidence held at once does not grow with the row count'
        @($r).Count | Should -Be $devs -Because 'never fewer rows than the source'
        foreach ($x in @($r)) {
            $ps = @($x.si_evidence_paths -split ';'); $ps.Count | Should -Be $per
            $own = ('C:\Users\person{0}\' -f $x.MdeDeviceId.Substring(3))
            @($ps | Where-Object { -not $_.StartsWith($own) }).Count | Should -Be 0 -Because 'every path is the row''s own device''s, in full'
        }
        (@($r).si_evidence_paths -join '') | Should -Not -Match 'more'
    }
}