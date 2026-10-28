#Requires -Version 5.1
<#
    #730 -- ONE RISK ANALYSIS REPORT HELD ITS WHOLE ANSWER IN MEMORY (the large ring-1 install, 2026-10-16: si-ra-0303
    OutOfMemory in identity-admin-logonto-vulnerabledevice-summary on 2 CPU / 4 GiB).

    A Risk Analysis lookup is a tenant-sized Log Analytics answer (the identity CI lookup of that report: every key of every
    identity of a 153,000-user tenant). The lean read (#639) held it about three times while it was read: the answer's bytes
    in one array, a JsonDocument index over them, then the rows. Now Risk Analysis' Log Analytics reads (its lookups and its
    Log Analytics answers) are read AS THEY ARRIVE (engine\_shared\SI-LaStreamRead.ps1): row by row through a small buffer,
    only the rows are kept. And the whole text of a lookup that cannot be replicated into every slice is no longer built
    (and kept) only to learn that it does not fit.

    EQUAL OUTPUT is the point of every test here: the streamed rows are compared value by value, type by type, with the rows
    of the lean read of the same bytes; the inline text with the text the builder made before.

    OFFLINE: the HTTP seam is a fake; no network, no tenant. pwsh 7 (the reader is System.Text.Json); on Windows PowerShell
    the reader is not there and the lean read stays (asserted).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-KqlError.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-LogAnalyticsQuery.ps1')
    function script:Write-Info  { param($m) }
    function script:Write-Diag  { param($m) }
    function script:Write-Err2  { param($m) }
    function script:Write-Warn2 { param($m) $script:Warned += , [string]$m }

    $script:Core = ($PSVersionTable.PSEdition -eq 'Core')

    # A stream that hands out at most -Chunk bytes per read (the network does not deliver an answer in one piece)
    if ($script:Core -and -not ('SITest.TrickleStream' -as [type])) {
        Add-Type -TypeDefinition @'
namespace SITest {
    public sealed class TrickleStream : System.IO.Stream {
        private readonly byte[] _b; private int _p; private readonly int _chunk;
        public int Reads;
        public TrickleStream(byte[] b, int chunk) { _b = b; _chunk = chunk; }
        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new System.NotSupportedException(); } }
        public override long Position { get { return _p; } set { throw new System.NotSupportedException(); } }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) {
            Reads++;
            int n = System.Math.Min(System.Math.Min(count, _chunk), _b.Length - _p);
            if (n <= 0) return 0;
            System.Buffer.BlockCopy(_b, _p, buffer, offset, n); _p += n; return n;
        }
        public override long Seek(long o, System.IO.SeekOrigin s) { throw new System.NotSupportedException(); }
        public override void SetLength(long v) { throw new System.NotSupportedException(); }
        public override void Write(byte[] b, int o, int c) { throw new System.NotSupportedException(); }
    }
}
'@
    }

    function script:Get-Bytes([string]$Json) { , [System.Text.Encoding]::UTF8.GetBytes($Json) }
    function script:Read-Lean([byte[]]$Bytes, [switch]$Compact) {
        $before = $global:SI_LaCompactRows
        $global:SI_LaCompactRows = [bool]$Compact
        try { return (ConvertFrom-SILaQueryRows -Bytes $Bytes) } finally { $global:SI_LaCompactRows = $before }
    }
    function script:Read-Stream([byte[]]$Bytes, [int]$Chunk = 7, [int]$Buffer = 1024, [switch]$Compact) {
        $s = [SITest.TrickleStream]::new($Bytes, $Chunk)
        try { return (ConvertFrom-SILaQueryStream -Stream $s -Compact:$Compact -BufferBytes $Buffer) } finally { $s.Dispose() }
    }
    # every row, every column, the same name order, the same value and the same .NET type (null stays null)
    function script:Assert-SameAnswer($Lean, $Streamed, [string]$Name = '') {
        @($Streamed.Rows).Count | Should -Be @($Lean.Rows).Count
        (@($Streamed.Columns | ForEach-Object { '{0}:{1}' -f $_.name, $_.type }) -join ',') | Should -BeExactly (@($Lean.Columns | ForEach-Object { '{0}:{1}' -f $_.name, $_.type }) -join ',')
        for ($i = 0; $i -lt @($Lean.Rows).Count; $i++) {
            $a = @($Lean.Rows)[$i]; $b = @($Streamed.Rows)[$i]
            $b.GetType().FullName | Should -Be $a.GetType().FullName -Because "$Name row $i is the same kind of object"
            (@($b.PSObject.Properties.Name) -join ',') | Should -BeExactly (@($a.PSObject.Properties.Name) -join ',') -Because "$Name row $i"
            foreach ($n in @($a.PSObject.Properties.Name)) {
                $va = $a.PSObject.Properties[$n].Value; $vb = $b.PSObject.Properties[$n].Value
                if ($null -eq $va) { ($null -eq $vb) | Should -BeTrue -Because "row $i, $n stays null" }
                else { $vb | Should -BeExactly $va -Because "$Name row $i, $n"; $vb.GetType().FullName | Should -Be $va.GetType().FullName }
            }
        }
        if ($null -eq $Lean.Error) { $Streamed.Error | Should -BeNullOrEmpty }
        else { (ConvertTo-Json -InputObject $Streamed.Error -Depth 10 -Compress) | Should -BeExactly (ConvertTo-Json -InputObject $Lean.Error -Depth 10 -Compress) }
    }

    # the answers the tests read: the shapes a lookup and a report answer take
    $script:Answers = [ordered]@{
        'a lookup (text, numbers in their own spelling, true / false, null, a short row, nested values, escapes, non-ASCII)' = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"_peerKey","type":"string"},{"name":"peer_tier","type":"int"},{"name":"score","type":"real"},{"name":"peer_rf_p","type":"dynamic"},{"name":"peer_in_scope","type":"bool"},{"name":"peer_cmdb_id","type":"string"},{"name":"obj","type":"dynamic"}],"rows":[["k1",0,1.50,"[\"internet_exposed\"]",true,null,{"a":[1,2,{"b":"c"}],"d":null}],["k2",-3,1e5,"[]",false,"",[1,"x",[]]],["k3\"q\\u00e6øå \n\t",1,0.000001],["k4",12345678901234,-0.0,"",true,"C-1",null]]}]}'
        'the primary table is not the first one' = '{"tables":[{"name":"Other","columns":[{"name":"z","type":"string"}],"rows":[["no"],["never"]]},{"name":"PrimaryResult","columns":[{"name":"a","type":"string"},{"name":"b","type":"long"}],"rows":[["only"],["two",2]]},{"name":"PrimaryResult","columns":[{"name":"q","type":"string"}],"rows":[["not this one"]]}]}'
        'no PrimaryResult: the first table' = '{"tables":[{"name":"First","columns":[{"name":"a","type":"string"}],"rows":[["1"],["2"]]},{"name":"Second","columns":[{"name":"b","type":"string"}],"rows":[["x"]]}]}'
        'a cut answer: its rows and the service''s own error' = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"a","type":"string"}],"rows":[["x"]]}],"error":{"code":"PartialError","message":"There were some errors when processing your query.","details":[{"code":"EngineError","message":"Query result set has exceeded the internal data size limit 64000000 (E_QUERY_RESULT_SET_TOO_LARGE)"}]}}'
        'an empty answer' = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"a","type":"string"},{"name":"b","type":"long"}],"rows":[]}]}'
        'a column without a type; an error that is null; extra properties in between' = '{"statistics":{"query":{"x":[1,2,3]}},"tables":[{"name":"PrimaryResult","extra":[[1]],"columns":[{"name":"a"},{"name":"b","type":"string","more":{"x":1}}],"rows":[["1","2","3"],["4"]]}],"error":null,"render":{"visualization":"table"}}'
        'two column names that differ only in case (the PSCustomObject rows keep one, as before)' = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"Id","type":"string"},{"name":"id","type":"string"},{"name":"x","type":"string"}],"rows":[["A","b","c"]]}]}'
    }
}

Describe 'a Log Analytics answer read as it arrives: the same rows as the lean read' -Skip:(-not ($PSVersionTable.PSEdition -eq 'Core')) {
    It 'the reader is compiled in this process' {
        Get-SILaStreamReaderType | Should -Not -BeNullOrEmpty
    }
    It 'PSCustomObject rows: every answer shape (a lookup, primary table not first, no PrimaryResult, a cut answer, empty, no type / null error / extra properties, names differing only in case)' {
        foreach ($k in @($script:Answers.Keys)) {
            $b = Get-Bytes $script:Answers[$k]
            Assert-SameAnswer -Lean (Read-Lean $b) -Streamed (Read-Stream $b) -Name $k
        }
    }
    It 'compact rows (a lookup): every answer shape' {
        foreach ($k in @($script:Answers.Keys)) {
            $b = Get-Bytes $script:Answers[$k]
            Assert-SameAnswer -Lean (Read-Lean $b -Compact) -Streamed (Read-Stream $b -Compact) -Name $k
        }
    }
    It 'whatever pieces the answer arrives in (1 byte at a time, odd sizes, all at once) and however small the buffer: the same rows' {
        $b = Get-Bytes $script:Answers['a lookup (text, numbers in their own spelling, true / false, null, a short row, nested values, escapes, non-ASCII)']
        $lean = Read-Lean $b -Compact
        foreach ($chunk in 1, 2, 3, 13, 64, 4096, 1MB) { Assert-SameAnswer -Lean $lean -Streamed (Read-Stream $b -Chunk $chunk -Buffer 1024 -Compact) }
    }
    It 'a row larger than the buffer: the buffer grows to that row, nothing is cut' {
        $big = 'x' * 50000
        $json = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"a","type":"string"},{"name":"b","type":"dynamic"}],"rows":[["small","[]"],["' + $big + '","[\"' + $big + '\"]"],["after",null]]}]}'
        $b = Get-Bytes $json
        $s = Read-Stream $b -Chunk 777 -Buffer 1024
        Assert-SameAnswer -Lean (Read-Lean $b) -Streamed $s
        @($s.Rows)[1].a.Length | Should -Be 50000
    }
    It 'a large lookup (20,000 rows): the same rows; the buffer stays small -- the answer is never held whole' {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('{"tables":[{"name":"PrimaryResult","columns":[{"name":"_ciKey","type":"string"},{"name":"si_ci_id","type":"string"},{"name":"si_tier","type":"int"},{"name":"si_rf_p","type":"dynamic"},{"name":"si_in_scope_","type":"bool"}],"rows":[')
        for ($i = 0; $i -lt 20000; $i++) {
            if ($i) { [void]$sb.Append(',') }
            [void]$sb.Append(('["key-{0:x8}","ci-{1}",{2},"[\"internet_exposed\",\"no_mfa\"]",{3}]' -f $i, ($i % 7000), ($i % 4), $(if ($i % 3) { 'true' } else { 'false' })))
        }
        [void]$sb.Append(']}]}')
        $b = Get-Bytes $sb.ToString()
        $lean = Read-Lean $b -Compact
        $s = Read-Stream $b -Chunk 16384 -Buffer 65536 -Compact
        Assert-SameAnswer -Lean $lean -Streamed $s
        $global:SI_LaStreamLast.BytesRead | Should -Be $b.Length
        $global:SI_LaStreamLast.LargestBuffer | Should -BeLessThan ($b.Length / 10) -Because 'only one buffer of a few rows is ever held, not the answer'
    }
    It 'an answer that is not JSON, or ends early, throws -- as the lean read does (never a short answer taken as whole)' {
        { Read-Stream (Get-Bytes '{"tables":[{"name":"PrimaryResult","columns":[{"name":"a","type":"string"}],"rows":[["x"],["y"') } | Should -Throw
        { Read-Stream (Get-Bytes 'not json') } | Should -Throw
        { Read-Lean (Get-Bytes '{"tables":[{"name":"PrimaryResult","columns":[{"name":"a","type":"string"}],"rows":[["x"],["y"') } | Should -Throw
    }
    It 'a byte order mark before the answer is passed over' {
        $b = Get-Bytes $script:Answers['no PrimaryResult: the first table']
        $bom = [byte[]](@(0xEF, 0xBB, 0xBF) + $b)
        Assert-SameAnswer -Lean (Read-Lean $b) -Streamed (Read-Stream $bom)
    }
}

Describe 'who reads as it arrives: Risk Analysis'' Log Analytics reads, nothing else' -Skip:(-not ($PSVersionTable.PSEdition -eq 'Core')) {
    BeforeAll {
        $script:LaBody = $script:Answers['a lookup (text, numbers in their own spelling, true / false, null, a short row, nested values, escapes, non-ASCII)']
        $script:WsGuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    }
    BeforeEach {
        $script:Calls = [System.Collections.Generic.List[object]]::new()
        $global:SI_LaCompactRows = $null; $global:SI_LaStreamRows = $null
        Mock Get-SIAzureToken { 'tok' }
        # the fake service: hands the body to -ReadStream when the caller gives one (as the real seam does for a 2xx)
        Mock Invoke-SIAzRestHttp {
            $script:Calls.Add([pscustomobject]@{ Uri = $Uri; Streamed = [bool]$ReadStream; AsBytes = [bool]$AsBytes })
            $h = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($script:LaBody)
            if ($ReadStream) {
                $ms = New-Object System.IO.MemoryStream -ArgumentList @(, $bytes)
                $p = & $ReadStream $ms
                return [pscustomobject]@{ StatusCode = 200; Content = ''; Bytes = $null; Headers = $h; RetryAfter = ''; Parsed = $p }
            }
            [pscustomobject]@{ StatusCode = 200; Content = ''; Bytes = $bytes; Headers = $h; RetryAfter = '' }
        }
    }
    AfterEach { $global:SI_LaCompactRows = $null; $global:SI_LaStreamRows = $null }

    It 'an ordinary Log Analytics read (any other engine) is the lean read, unchanged' {
        $r = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q'
        @($script:Calls)[0].Streamed | Should -BeFalse
        @($r.Results).Count | Should -Be 4
    }
    It 'a lookup read (compact rows) and a Risk Analysis read are streamed -- and give exactly the rows, columns and schema the lean read gives' {
        $lean = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q'
        $global:SI_LaStreamRows = $true
        $st = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q'
        @($script:Calls)[1].Streamed | Should -BeTrue
        Assert-SameAnswer -Lean ([pscustomobject]@{ Rows = $lean.Results; Columns = $lean.Columns; Error = $lean.Error }) -Streamed ([pscustomobject]@{ Rows = $st.Results; Columns = $st.Columns; Error = $st.Error })
        @($st.Tables).Count | Should -Be 1; @($st.Tables)[0].RowsOmitted | Should -BeTrue
        $global:SI_LaStreamRows = $null; $global:SI_LaCompactRows = $true
        $leanC = Read-Lean ([System.Text.Encoding]::UTF8.GetBytes($script:LaBody)) -Compact
        $stC = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q'
        @($script:Calls)[2].Streamed | Should -BeTrue
        @($stC.Results)[0].GetType().Namespace | Should -Be 'SecurityInsight.LaRows'
        Assert-SameAnswer -Lean $leanC -Streamed ([pscustomobject]@{ Rows = $stC.Results; Columns = $stC.Columns; Error = $stC.Error })
    }
    It 'Invoke-LogAnalyticsKqlQuery (every Risk Analysis Log Analytics read) streams only while it reads, and puts the setting back -- also when the read fails' {
        Mock Resolve-WorkspaceCustomerId { $script:WsGuid }
        $global:SI_LaStreamRows = 'before'
        $rows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId '/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w' -Query 'q'
        @($script:Calls)[-1].Streamed | Should -BeTrue
        $rows.Count | Should -Be 4
        $rows[0]._peerKey | Should -Be 'k1'
        $global:SI_LaStreamRows | Should -Be 'before'
        $global:RA_LastLaQueryColumnTypes['peer_rf_p'] | Should -Be 'dynamic' -Because 'the declared column types still reach the inline datatable'
        Mock Invoke-SIAzOperationalInsightsQuery { throw 'boom' }
        { Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId '/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w' -Query 'q' } | Should -Throw
        $global:SI_LaStreamRows | Should -Be 'before'
    }
    It 'a refused query (4xx) is read as before: never handed to the stream reader; a support session''s recorded call is never streamed' {
        $f = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1'))
        $f | Should -Match '\$rs -and \$ReadStream -and \$sc -ge 200 -and \$sc -lt 300'
        $f | Should -Match 'if \(\$ReadStream\) \{ \$r = Invoke-SIAzRestHttp .* -ReadStream \$ReadStream \}'
        $f | Should -Not -Match 'Invoke-SISupportHttp [^\r\n]*-ReadStream'
        $f | Should -Match '\[int\]\$r\.StatusCode -lt 400'
    }
}

Describe 'Windows PowerShell keeps the lean read' -Tag 'Ps51' -Skip:($PSVersionTable.PSEdition -eq 'Core') {
    It 'the reader is not offered, so nothing changes there' {
        Get-SILaStreamReaderType | Should -BeNullOrEmpty
    }
}

Describe 'the inline text of a lookup: made once, the same characters; never built whole only to learn it does not fit' {
    BeforeAll {
        $script:Rows = @(
            [pscustomobject]@{ _ciKey = 'a'; si_tier = '0'; si_rf_p = '["x"]'; ok = 'true'; at = '2026-10-01T00:00:00Z'; s = 'q"uo\te' },
            [pscustomobject]@{ _ciKey = 'b'; si_tier = ''; si_rf_p = '[]'; ok = 'false'; at = $null; s = "line`nbreak" },
            [pscustomobject]@{ _ciKey = 'c'; si_tier = '12'; si_rf_p = $null; ok = $null; at = '2026-10-02T00:00:00Z'; s = '' })
        $script:Types = @{ _ciKey = 'string'; si_tier = 'int'; si_rf_p = 'dynamic'; ok = 'bool'; at = 'datetime'; s = 'string' }
    }
    It 'the text is the same as TrimEnd + newline + "];" made it -- with rows, with none, with an empty schema hint' {
        $t = Convert-RowsToKqlDatatable -LetVarName '_ciLink' -Rows $script:Rows -ColumnTypes $script:Types
        $t | Should -Match '^let _ciLink = datatable\('
        $t.EndsWith([Environment]::NewLine + '];') | Should -BeTrue
        $t | Should -Not -Match ',\r?\n\];$'
        # rebuild the reference the old way from the same builder output (everything before the trailing ",\n" + "];")
        $body = $t.Substring(0, $t.Length - ([Environment]::NewLine + '];').Length)
        $old = ($body + ',' + [Environment]::NewLine).TrimEnd(",`r`n".ToCharArray()) + [Environment]::NewLine + '];'
        $t | Should -BeExactly $old
        $e = Convert-RowsToKqlDatatable -LetVarName '_x' -Rows @() -TypeReferenceRows $script:Rows -ColumnTypes $script:Types
        $oldEmpty = ('let _x = datatable(_ciKey:string,si_tier:long,si_rf_p:dynamic,ok:bool,at:datetime,s:string) [' + [Environment]::NewLine).TrimEnd(",`r`n".ToCharArray()) + [Environment]::NewLine + '];'
        $e | Should -BeExactly $oldEmpty
    }
    It '-MaxChars: $null as soon as the text is longer; the whole text when it fits (exactly the same text)' {
        $whole = Convert-RowsToKqlDatatable -LetVarName '_ciLink' -Rows $script:Rows -ColumnTypes $script:Types
        Convert-RowsToKqlDatatable -LetVarName '_ciLink' -Rows $script:Rows -ColumnTypes $script:Types -MaxChars ($whole.Length) | Should -BeExactly $whole
        Convert-RowsToKqlDatatable -LetVarName '_ciLink' -Rows $script:Rows -ColumnTypes $script:Types -MaxChars ($whole.Length - 1) | Should -BeNullOrEmpty
        Convert-RowsToKqlDatatable -LetVarName '_ciLink' -Rows $script:Rows -ColumnTypes $script:Types -MaxChars 10 | Should -BeNullOrEmpty
    }
    It 'GUARD: the cross-domain pre-pass builds the whole texts only up to the request budget, and decides as before' {
        $body = (Get-Command -Name Resolve-ProfileCLLetBlocks).ScriptBlock.ToString()
        $body | Should -Match '-MaxChars \(\[long\]\[Math\]::Max\(1, \$_budget - \$_fullBytes\)\)'
        $body | Should -Match 'if \(\$null -eq \$_whole\) \{ \$_over = \$true; break \}'
        $body | Should -Match 'exceed the request budget'
    }
}
