#Requires -Version 5.1
<#
    #836 -- THE STREAMING LOG ANALYTICS READER (#730) WAS NEVER ON IN A CONTAINER ENGINE (found 2026-10-20 while fixing #835).
    The container's entry point (container\Start-SIInContainer.ps1) dot-sources engine\_shared\SI-AzRest.ps1 (and through it
    SI-LaStreamRead.ps1) in ITS script scope and runs the engine with &; the engine skips SI-AzRest.ps1 (Invoke-SIArm is already
    there). A function reads $script: of its CALLER's script, so the reader's C# source -- a $script: variable -- was $null
    in every engine: Add-Type threw "Cannot bind argument to parameter 'TypeDefinition' because it is null", the error was
    swallowed and every Log Analytics read silently took the older (whole) read.
    What these tests keep true:
      * loaded the container's way (a FRESH pwsh process: entry -> SI-AzRest.ps1, then an engine script that does NOT reload
        it) the streaming reader is built and USED, for a Risk Analysis read and a lookup (compact rows) -- no fallback line;
      * when the reader cannot be built the older read is used, the rows are the same, and ONE plain line on the run log says
        so and why (once per process, not per read);
      * a stream read that fails on an answer is read again the older way (data first), said in one line; a reader fault
        turns streaming off for the process (never doubles every read), a network fault does not;
      * THE TWO READ PATHS GIVE IDENTICAL ANSWERS through Invoke-SILaQuery (rows, order, columns, types, values, the error,
        the schema), PSCustomObject and compact rows: large pages, nulls, dynamic / JSON columns, datetime, numbers, empty
        answers, a cut ("too large") answer with its error, and a refused 413 answer (the same error text).
    Offline (the HTTP seam is a fake; no network, no tenant). pwsh 7 (the container's runtime); skipped on Windows PowerShell.
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Core = ($PSVersionTable.PSEdition -eq 'Core')
    $script:Pwsh = Join-Path $PSHOME $(if ($IsWindows -or $PSVersionTable.PSEdition -ne 'Core') { 'pwsh.exe' } else { 'pwsh' })
    $script:Dir = Join-Path $TestDrive 'container'
    [void](New-Item -ItemType Directory -Path $script:Dir -Force)

    # the entry point: SI-AzRest.ps1 in ITS scope, then the engine with & (container\Start-SIInContainer.ps1 line 44 + dispatch)
    Set-Content -LiteralPath (Join-Path $script:Dir 'entry.ps1') -Encoding UTF8 -Value @'
param([string]$Root, [string]$Mode)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $Root 'engine/_shared/SI-AzRest.ps1') }
& (Join-Path $PSScriptRoot 'engine.ps1') -Root $Root -Mode $Mode
'@
    # an engine: its SI-AzRest guard (skipped -- already loaded), then Log Analytics reads through the real Invoke-SILaQuery
    # over a fake HTTP seam (the same body every call). -Mode nobuild: Add-Type cannot compile in this process.
    Set-Content -LiteralPath (Join-Path $script:Dir 'engine.ps1') -Encoding UTF8 -Value @'
param([string]$Root, [string]$Mode)
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $Root 'engine/_shared/SI-AzRest.ps1') }
$ErrorActionPreference = 'Stop'
$out = [ordered]@{}
$out.ReloadedHere = ($null -ne (Get-Variable -Name SILaStreamReaderSource -Scope Script -ErrorAction Ignore))
if ($Mode -eq 'nobuild') { function Add-Type { throw 'simulated: no compiler in this process' } }
$global:FakeBody = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"_peerKey","type":"string"},{"name":"peer_tier","type":"int"},{"name":"at","type":"datetime"},{"name":"rf","type":"dynamic"}],"rows":[["k1",0,"2026-10-20T16:45:01.123Z","[\"internet_exposed\"]"],["k2",null,null,{"a":[1,{"b":null}]}],["k3",-7,"2026-01-01T00:00:00Z",null]]}]}'
$global:Calls = [System.Collections.Generic.List[bool]]::new()
function Get-SIAzureToken { 'tok' }
function Invoke-SIAzRestHttp {
    param($Method, $Uri, $Headers, $Body, $ContentType, $TimeoutSec, [switch]$AsBytes, [scriptblock]$ReadStream)
    $global:Calls.Add([bool]$ReadStream)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($global:FakeBody)
    $h = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
    if ($ReadStream) {
        $ms = New-Object System.IO.MemoryStream -ArgumentList @(, $bytes)
        $p = & $ReadStream $ms
        return [pscustomobject]@{ StatusCode = 200; Content = ''; Bytes = $null; Headers = $h; RetryAfter = ''; Parsed = $p }
    }
    [pscustomobject]@{ StatusCode = 200; Content = ''; Bytes = $bytes; Headers = $h; RetryAfter = '' }
}
$sig = { param($rows) (@($rows) | ForEach-Object { $o = $_; (@($o.PSObject.Properties) | ForEach-Object { '{0}={1}' -f $_.Name, $(if ($null -eq $_.Value) { '<null>' } else { $_.Value }) }) -join '|' }) -join "`n" }
$ws = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
try {
    # a Risk Analysis read (SI_LaStreamRows), twice
    $global:SI_LaStreamRows = $true
    $r1 = Invoke-SILaQuery -WorkspaceId $ws -Query 'q'
    $r1b = Invoke-SILaQuery -WorkspaceId $ws -Query 'q'
    $global:SI_LaStreamRows = $null
    # a lookup (compact rows)
    $global:SI_LaCompactRows = $true
    $r2 = Invoke-SILaQuery -WorkspaceId $ws -Query 'q'
    $global:SI_LaCompactRows = $null
    # an ordinary read (any other engine): the older read
    $r3 = Invoke-SILaQuery -WorkspaceId $ws -Query 'q'
    $out.ReaderType = [string](Get-SILaStreamReaderType)
    $out.Streamed = (@($global:Calls) | ForEach-Object { [string]$_ }) -join ','
    $out.Rows = @($r1.Results).Count
    $out.CompactType = @($r2.Results)[0].GetType().FullName
    $out.SameRows = ((& $sig $r1.Results) -ceq (& $sig $r3.Results))
    $out.SameCompactRows = ((& $sig $r2.Results) -ceq (& $sig $r3.Results))
    $out.Off = [string]$global:SI_LaStreamReaderOff
} catch { $out.Error = $_.Exception.Message }
$out | ConvertTo-Json -Compress -Depth 3
'@
    function script:Invoke-ContainerShape([string]$Mode) {
        $raw = & $script:Pwsh -NoProfile -NonInteractive -File (Join-Path $script:Dir 'entry.ps1') -Root $script:Root -Mode $Mode 2>&1
        $lines = @($raw | ForEach-Object { [string]$_ })
        $json = @($lines | Where-Object { $_ -like '{*' } | Select-Object -Last 1)
        [pscustomobject]@{
            Raw      = ($lines -join "`n")
            R        = $(if ($json.Count) { $json[0] | ConvertFrom-Json } else { $null })
            Fallback = @($lines | Where-Object { $_ -like 'Log Analytics answers are read the older way*' })
        }
    }
    if ($script:Core) {
        $script:On = Invoke-ContainerShape -Mode 'on'
        $script:NoBuild = Invoke-ContainerShape -Mode 'nobuild'
    }

    # ---- in this process: the real files, the fake seam ----
    . (Join-Path $script:Root 'engine\_shared\SI-AzRest.ps1')
    . (Join-Path $script:Root 'engine\_shared\SI-KqlError.ps1')
    $script:WsGuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

    # every row, every column in order, the same value and the same .NET type (null stays null); the schema and the error
    function script:Assert-SameLaAnswer($Older, $Streamed, [string]$Name = '') {
        @($Streamed.Results).Count | Should -Be @($Older.Results).Count -Because "${Name}: the same number of rows"
        (@($Streamed.Columns | ForEach-Object { '{0}:{1}' -f $_.name, $_.type }) -join ',') | Should -BeExactly (@($Older.Columns | ForEach-Object { '{0}:{1}' -f $_.name, $_.type }) -join ',') -Because "${Name}: the same columns"
        (ConvertTo-Json -InputObject @($Streamed.Tables) -Depth 6 -Compress) | Should -BeExactly (ConvertTo-Json -InputObject @($Older.Tables) -Depth 6 -Compress) -Because "${Name}: the same schema"
        # (the differences are collected and asserted once: one Should per value is minutes on a 12,000-row page)
        $ra = @($Older.Results); $rb = @($Streamed.Results)
        $diff = [System.Collections.Generic.List[string]]::new()
        for ($i = 0; $i -lt $ra.Count -and $diff.Count -lt 20; $i++) {
            $a = $ra[$i]; $b = $rb[$i]
            if ($b.GetType().FullName -ne $a.GetType().FullName) { $diff.Add("row ${i}: object $($b.GetType().FullName) vs $($a.GetType().FullName)"); continue }
            $pa = @($a.PSObject.Properties); $pb = @($b.PSObject.Properties)
            if ((@($pb.Name) -join ',') -cne (@($pa.Name) -join ',')) { $diff.Add("row ${i}: columns $(@($pb.Name) -join ',') vs $(@($pa.Name) -join ',')"); continue }
            for ($k = 0; $k -lt $pa.Count; $k++) {
                $va = $pa[$k].Value; $vb = $pb[$k].Value
                if ($null -eq $va) { if ($null -ne $vb) { $diff.Add("row ${i}, $($pa[$k].Name): '$vb' vs null") } }
                elseif ($null -eq $vb) { $diff.Add("row ${i}, $($pa[$k].Name): null vs '$va'") }
                elseif ($vb.GetType() -ne $va.GetType() -or -not [string]::Equals([string]$vb, [string]$va, [System.StringComparison]::Ordinal)) { $diff.Add("row ${i}, $($pa[$k].Name): '$vb' [$($vb.GetType().Name)] vs '$va' [$($va.GetType().Name)]") }
            }
        }
        @($diff) | Should -BeNullOrEmpty -Because "${Name}: every row, column, value and type the same"
        if ($null -eq $Older.Error) { $Streamed.Error | Should -BeNullOrEmpty -Because "${Name} has no error" }
        else { (ConvertTo-Json -InputObject $Streamed.Error -Depth 10 -Compress) | Should -BeExactly (ConvertTo-Json -InputObject $Older.Error -Depth 10 -Compress) -Because "${Name}: the same error" }
    }

    # the recorded answers: every shape a Risk Analysis read and a lookup take
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"tables":[{"name":"PrimaryResult","columns":[{"name":"_ciKey","type":"string"},{"name":"si_ci_id","type":"string"},{"name":"si_tier","type":"int"},{"name":"score","type":"real"},{"name":"count_","type":"long"},{"name":"TimeGenerated","type":"datetime"},{"name":"si_rf_p","type":"dynamic"},{"name":"props","type":"dynamic"},{"name":"si_in_scope_","type":"bool"},{"name":"note","type":"string"}],"rows":[')
    for ($i = 0; $i -lt 12000; $i++) {
        if ($i) { [void]$sb.Append(',') }
        $tier = if ($i % 11 -eq 0) { 'null' } else { [string]($i % 4) }
        $at = if ($i % 13 -eq 0) { 'null' } else { '"2026-10-{0:00}T{1:00}:{2:00}:{3:00}.{4:000}Z"' -f (1 + $i % 28), ($i % 24), ($i % 60), (($i * 7) % 60), ($i % 1000) }
        $props = if ($i % 5 -eq 0) { '{"os":"Windows","ports":[443,3389],"nested":{"x":null,"y":true}}' } elseif ($i % 5 -eq 1) { '[]' } elseif ($i % 5 -eq 2) { 'null' } else { '"{\"raw\":\"text\"}"' }
        $note = if ($i % 17 -eq 0) { '"quote \" back\\slash æøå line\nbreak"' } elseif ($i % 9 -eq 0) { '""' } else { '"n{0}"' -f $i }
        [void]$sb.Append(('["key-{0:x8}","ci-{1}",{2},{3},{4},{5},"[\"internet_exposed\",\"no_mfa\"]",{6},{7},{8}]' -f $i, ($i % 7000), $tier, $(if ($i % 3) { '{0}.{1:000}' -f $i, ($i % 1000) } else { '1e-7' }), (9007199254740993 + $i), $at, $props, $(if ($i % 2) { 'true' } else { 'false' }), $note))
    }
    [void]$sb.Append(']}]}')
    $script:Recorded = [ordered]@{
        'a large page (12,000 rows, ~3 MB: nulls, dynamic objects / arrays / JSON text, datetime, int / long beyond 2^53 / real, bool, escapes)' = $sb.ToString()
        'an empty answer' = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"a","type":"string"},{"name":"b","type":"datetime"}],"rows":[]}]}'
        'a cut answer ("too large"): its rows and the service''s own error' = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"a","type":"string"},{"name":"n","type":"long"}],"rows":[["x",1],["y",null]]}],"error":{"code":"PartialError","message":"There were some errors when processing your query.","details":[{"code":"EngineError","message":"Query result set has exceeded the internal data size limit 64000000 (E_QUERY_RESULT_SET_TOO_LARGE)","innererror":{"code":"-2133196797","message":"E_QUERY_RESULT_SET_TOO_LARGE"}}]}}'
        'the primary table is not the first; statistics and render around it' = '{"statistics":{"query":{"executionTime":1.2}},"tables":[{"name":"Other","columns":[{"name":"z","type":"string"}],"rows":[["no"]]},{"name":"PrimaryResult","columns":[{"name":"a","type":"string"},{"name":"d","type":"dynamic"}],"rows":[["only",{"k":[1,2.50,-0.0,1E+3]}],["short"]]}],"render":{"visualization":"table"}}'
        'numbers in their own spelling, true / false, null in every column' = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"i","type":"int"},{"name":"r","type":"real"},{"name":"b","type":"bool"},{"name":"t","type":"timespan"},{"name":"g","type":"guid"}],"rows":[[0,0.10,true,"00:00:01.5000000","00000000-0000-0000-0000-000000000001"],[null,null,null,null,null],[-1,1.7976931348623157E+308,false,"1.02:03:04","ffffffff-ffff-ffff-ffff-ffffffffffff"]]}]}'
    }
    $script:Body = ''
    $script:Status = 200
}

Describe 'LOADED THE CONTAINER''S WAY, THE STREAMING READER IS ON (#836)' -Skip:(-not ($PSVersionTable.PSEdition -eq 'Core')) {
    It 'the fresh process ran and answered' {
        $script:On.R | Should -Not -BeNullOrEmpty -Because $script:On.Raw
        $script:On.R.PSObject.Properties['Error'] | Should -BeNullOrEmpty -Because $script:On.Raw
    }
    It 'the shape under test: the engine did not reload the files (its own script scope has none of their variables)' {
        $script:On.R.ReloadedHere | Should -BeFalse
    }
    It 'the reader is built in the engine, and a Risk Analysis read and a lookup are STREAMED; an ordinary read is not' {
        $script:On.R.ReaderType | Should -Be 'SecurityInsight.LaStream.LaStreamReader' -Because $script:On.Raw
        $script:On.R.Streamed | Should -Be 'True,True,True,False'
        $script:On.R.Off | Should -BeNullOrEmpty
        $script:On.R.CompactType | Should -BeLike 'SecurityInsight.LaRows.R*'
    }
    It 'the streamed rows are the rows of the older read' {
        $script:On.R.Rows | Should -Be 3
        $script:On.R.SameRows | Should -BeTrue
        $script:On.R.SameCompactRows | Should -BeTrue
    }
    It 'nothing is said about a fallback when there is none' {
        @($script:On.Fallback).Count | Should -Be 0 -Because $script:On.Raw
    }
}

Describe 'THE READER CANNOT BE BUILT: THE OLDER READ, NEVER SILENT (#836)' -Skip:(-not ($PSVersionTable.PSEdition -eq 'Core')) {
    It 'every read is the older read, with the same rows' {
        $script:NoBuild.R | Should -Not -BeNullOrEmpty -Because $script:NoBuild.Raw
        $script:NoBuild.R.PSObject.Properties['Error'] | Should -BeNullOrEmpty -Because $script:NoBuild.Raw
        $script:NoBuild.R.ReaderType | Should -BeNullOrEmpty
        $script:NoBuild.R.Streamed | Should -Be 'False,False,False,False'
        $script:NoBuild.R.Rows | Should -Be 3
        $script:NoBuild.R.SameRows | Should -BeTrue
        $script:NoBuild.R.SameCompactRows | Should -BeTrue
    }
    It 'ONE plain line on the run log says the older read is used and why -- once, not per read' {
        @($script:NoBuild.Fallback).Count | Should -Be 1 -Because $script:NoBuild.Raw
        $script:NoBuild.Fallback[0] | Should -Match 'could not be built in this process: simulated: no compiler in this process'
        $script:NoBuild.Fallback[0] | Should -Match 'The rows are the same'
        $script:NoBuild.Fallback[0] | Should -Not -Match '#\d+|\[\w+\]' -Because 'no internal numbers or jargon in what a customer reads'
        $script:NoBuild.R.Off | Should -Match 'simulated'
    }
}

Describe 'A STREAM READ THAT FAILS ON AN ANSWER IS READ AGAIN THE OLDER WAY (#836)' -Skip:(-not ($PSVersionTable.PSEdition -eq 'Core')) {
    BeforeEach {
        $script:Calls = [System.Collections.Generic.List[object]]::new()
        $script:Said = [System.Collections.Generic.List[string]]::new()
        $global:SI_LaCompactRows = $null; $global:SI_LaStreamRows = $true
        $global:SI_LaStreamReaderOff = $null; $global:SI_LaStreamFallbackSaid = $null
        $script:Body = $script:Recorded['the primary table is not the first; statistics and render around it']
        Mock Get-SIAzureToken { 'tok' }
        Mock Write-Host { $script:Said.Add([string]$Object) }
        # the stream handed to the reader fails: -StreamFault 'reader' (not JSON -- a reader fault) / 'network' (an IOException)
        Mock Invoke-SIAzRestHttp {
            $script:Calls.Add([bool]$ReadStream)
            $h = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($script:Body)
            if ($ReadStream) {
                if ($script:StreamFault -eq 'network') { $ms = [SITest.FailingStream]::new() }
                elseif ($script:StreamFault -eq 'reader') { $ms = New-Object System.IO.MemoryStream -ArgumentList @(, [System.Text.Encoding]::UTF8.GetBytes('{"tables":[{"name":"PrimaryResult","columns":[{"name":"a","type":"string"}],"rows":[["x"],}')) }
                else { $ms = New-Object System.IO.MemoryStream -ArgumentList @(, $bytes) }
                $p = & $ReadStream $ms
                return [pscustomobject]@{ StatusCode = 200; Content = ''; Bytes = $null; Headers = $h; RetryAfter = ''; Parsed = $p }
            }
            [pscustomobject]@{ StatusCode = 200; Content = ''; Bytes = $bytes; Headers = $h; RetryAfter = '' }
        }
        if (-not ('SITest.FailingStream' -as [type])) {
            Add-Type -TypeDefinition 'namespace SITest { public sealed class FailingStream : System.IO.Stream { public override bool CanRead { get { return true; } } public override bool CanSeek { get { return false; } } public override bool CanWrite { get { return false; } } public override long Length { get { throw new System.NotSupportedException(); } } public override long Position { get { return 0; } set { } } public override void Flush() { } public override int Read(byte[] b, int o, int c) { throw new System.IO.IOException("The response ended prematurely."); } public override long Seek(long o, System.IO.SeekOrigin s) { throw new System.NotSupportedException(); } public override void SetLength(long v) { } public override void Write(byte[] b, int o, int c) { } } }'
        }
    }
    AfterEach { $global:SI_LaStreamRows = $null; $global:SI_LaStreamReaderOff = $null; $global:SI_LaStreamFallbackSaid = $null; $script:StreamFault = $null }

    It 'a reader fault: the same query read again the older way (the right rows), one line, and streaming is off for the rest of the process' {
        $script:StreamFault = $null
        $good = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q'
        $script:StreamFault = 'reader'
        $r = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q'
        (@($script:Calls) -join ',') | Should -Be 'True,True,False' -Because 'streamed, streamed and failed, then read again the older way'
        Assert-SameLaAnswer -Older $good -Streamed $r -Name 'read again'
        @($script:Said | Where-Object { $_ -like 'Log Analytics answers are read the older way*' }).Count | Should -Be 1
        $global:SI_LaStreamReaderOff | Should -Match 'failed on an answer'
        $r2 = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q'
        (@($script:Calls) -join ',') | Should -Be 'True,True,False,False' -Because 'off for the process: never a doubled read again'
        @($script:Said | Where-Object { $_ -like 'Log Analytics answers are read the older way*' }).Count | Should -Be 2 -Because 'the reader being off is said once more, then never again'
        $null = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q'
        @($script:Said | Where-Object { $_ -like 'Log Analytics answers are read the older way*' }).Count | Should -Be 2
        @($r2.Results).Count | Should -Be 2
    }
    It 'a network fault mid-answer: read again the older way, said, and streaming stays on' {
        $script:StreamFault = 'network'
        $r = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q'
        (@($script:Calls) -join ',') | Should -Be 'True,False'
        @($r.Results).Count | Should -Be 2
        @($script:Said | Where-Object { $_ -match 'older way .*The response ended prematurely' }).Count | Should -Be 1
        $global:SI_LaStreamReaderOff | Should -BeNullOrEmpty
        $script:StreamFault = $null
        $null = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q'
        @($script:Calls)[-1] | Should -BeTrue
    }
}

Describe 'THE TWO READ PATHS GIVE IDENTICAL ANSWERS (#836)' -Skip:(-not ($PSVersionTable.PSEdition -eq 'Core')) {
    BeforeEach {
        $global:SI_LaCompactRows = $null; $global:SI_LaStreamRows = $null
        $global:SI_LaStreamReaderOff = $null; $global:SI_LaStreamFallbackSaid = $null
        $script:Calls = [System.Collections.Generic.List[object]]::new()
        Mock Get-SIAzureToken { 'tok' }
        Mock Invoke-SIAzRestHttp {
            $script:Calls.Add([bool]$ReadStream)
            $h = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($script:Body)
            if ($ReadStream -and $script:Status -ge 200 -and $script:Status -lt 300) {
                $ms = New-Object System.IO.MemoryStream -ArgumentList @(, $bytes)
                $p = & $ReadStream $ms
                return [pscustomobject]@{ StatusCode = $script:Status; Content = ''; Bytes = $null; Headers = $h; RetryAfter = ''; Parsed = $p }
            }
            [pscustomobject]@{ StatusCode = $script:Status; Content = ''; Bytes = $bytes; Headers = $h; RetryAfter = '' }
        }
    }
    AfterEach { $global:SI_LaCompactRows = $null; $global:SI_LaStreamRows = $null; $script:Status = 200 }

    It 'PSCustomObject rows (a Risk Analysis read) -- every recorded answer: <_>' -ForEach @(
        'a large page (12,000 rows, ~3 MB: nulls, dynamic objects / arrays / JSON text, datetime, int / long beyond 2^53 / real, bool, escapes)',
        'an empty answer', 'a cut answer ("too large"): its rows and the service''s own error',
        'the primary table is not the first; statistics and render around it', 'numbers in their own spelling, true / false, null in every column') {
        $script:Body = $script:Recorded[$_]
        # (-AllowPartial: the cut answer's rows and error are compared too -- by default both paths refuse it, below)
        $older = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q' -AllowPartial
        $global:SI_LaStreamRows = $true
        $streamed = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q' -AllowPartial
        (@($script:Calls) -join ',') | Should -Be 'False,True'
        Assert-SameLaAnswer -Older $older -Streamed $streamed -Name $_
    }
    It 'compact rows (a lookup) -- every recorded answer: <_>' -ForEach @(
        'a large page (12,000 rows, ~3 MB: nulls, dynamic objects / arrays / JSON text, datetime, int / long beyond 2^53 / real, bool, escapes)',
        'an empty answer', 'a cut answer ("too large"): its rows and the service''s own error',
        'the primary table is not the first; statistics and render around it', 'numbers in their own spelling, true / false, null in every column') {
        $script:Body = $script:Recorded[$_]
        # the older read of a lookup: compact rows from the bytes (the lean read), streaming off
        $global:SI_LaCompactRows = $true
        $global:SI_LaStreamReaderOff = 'test: the older read'; $global:SI_LaStreamFallbackSaid = @{ 'test: the older read' = $true }
        $older = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q' -AllowPartial
        $global:SI_LaStreamReaderOff = $null
        $streamed = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q' -AllowPartial
        (@($script:Calls) -join ',') | Should -Be 'False,True'
        Assert-SameLaAnswer -Older $older -Streamed $streamed -Name $_
        if (@($older.Results).Count) { @($streamed.Results)[0].GetType().Namespace | Should -Be 'SecurityInsight.LaRows' }
    }
    It '#639: a cut answer is REFUSED by default on both paths -- the same refusal, the rows never handed out' {
        $script:Body = $script:Recorded['a cut answer ("too large"): its rows and the service''s own error']
        $e1 = $null; try { $null = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q' } catch { $e1 = $_ }
        $global:SI_LaStreamRows = $true
        $e2 = $null; try { $null = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q' } catch { $e2 = $_ }
        (@($script:Calls) -join ',') | Should -Be 'False,True'
        $e1 | Should -Not -BeNullOrEmpty; $e2 | Should -Not -BeNullOrEmpty
        $e2.Exception.Message | Should -BeExactly $e1.Exception.Message
        $e2.Exception.Message | Should -Match 'E_QUERY_RESULT_SET_TOO_LARGE'
        $e2.Exception.Data['SIRALaPartialRows'] | Should -Be 2
    }
    It 'the large page keeps its ORDER and every value (SHA-256 over every row, both paths)' {
        $script:Body = $script:Recorded['a large page (12,000 rows, ~3 MB: nulls, dynamic objects / arrays / JSON text, datetime, int / long beyond 2^53 / real, bool, escapes)']
        $hash = {
            param($rows)
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $sb = New-Object System.Text.StringBuilder
            foreach ($o in @($rows)) { foreach ($p in $o.PSObject.Properties) { [void]$sb.Append($p.Name).Append('=').Append($(if ($null -eq $p.Value) { "`0" } else { $p.Value })).Append("`t") }; [void]$sb.Append("`n") }
            try { [BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sb.ToString()))) } finally { $sha.Dispose() }
        }
        $older = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q'
        $global:SI_LaStreamRows = $true
        $streamed = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q'
        @($streamed.Results).Count | Should -Be 12000
        (& $hash $streamed.Results) | Should -BeExactly (& $hash $older.Results)
        @($streamed.Results)[11999]._ciKey | Should -Be ('key-{0:x8}' -f 11999)
        @($streamed.Results)[0].props | Should -BeExactly '{"os":"Windows","ports":[443,3389],"nested":{"x":null,"y":true}}'
        @($streamed.Results)[0].count_ | Should -BeExactly '9007199254740993' -Because 'a long beyond 2^53 is its own text, never a rounded double'
        @($streamed.Results)[13].TimeGenerated | Should -BeNullOrEmpty
        @($streamed.Results)[1].TimeGenerated | Should -BeExactly '2026-10-02T01:01:07.001Z' -Because 'a datetime stays the exact text the service sent'
    }
    It 'a refused "too large" answer (413): never handed to the stream reader, the same error from both paths' {
        $script:Status = 413
        $script:Body = '{"error":{"code":"ResponsePayloadTooLarge","message":"Response size too large. Maximum allowed response size: 100000000 bytes."}}'
        $e1 = $null; try { $null = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q' } catch { $e1 = $_ }
        $global:SI_LaStreamRows = $true
        $e2 = $null; try { $null = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q' } catch { $e2 = $_ }
        $e1 | Should -Not -BeNullOrEmpty; $e2 | Should -Not -BeNullOrEmpty
        $e2.Exception.Message | Should -BeExactly $e1.Exception.Message
        $e2.Exception.Message | Should -Match 'ResponsePayloadTooLarge'
        [string]$e2.ErrorDetails.Message | Should -BeExactly ([string]$e1.ErrorDetails.Message)
    }
}

Describe 'GUARD: nothing of the reader lives only in a script scope (#836)' {
    It 'SI-LaStreamRead.ps1 reads and writes no $script: variable; its source is a function' {
        $f = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\_shared\SI-LaStreamRead.ps1'))
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($f, [ref]$null, [ref]$null)
        $vars = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.IsScript }, $true))
        @($vars | ForEach-Object { $_.Extent.Text }) | Should -BeNullOrEmpty
        $f | Should -Match 'function Get-SILaStreamReaderSource'
        $f | Should -Match 'Add-Type -TypeDefinition \$src'
    }
    It 'Invoke-SILaQuery says when it falls back, and reads a failed stream again' {
        $body = (Get-Command -Name Invoke-SILaQuery).ScriptBlock.ToString()
        $body | Should -Match 'Write-SILaStreamFallback -Once'
        $body | Should -Match 'Read-SILaQueryStreamSafe'
        $body | Should -Match "Remove\('ReadStream'\)"
    }
}
