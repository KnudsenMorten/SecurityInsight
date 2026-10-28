#Requires -Version 7.0
<#
    #753 -- SEVERAL PARTS OF A RISK ANALYSIS REPORT AT A TIME, AND THE SAME RESULT AS ONE AT A TIME.

    Live 2026-10-18: Risk Analysis Detailed asked its parts one after the other (~1.4 min each; 256 parts ~6 h at one large
    customer, ~20-30 h at two others). Per part: the advanced-hunting answer (10-30 s), the part's own count (#641, a
    second call, "attempt 1/1", 9-50 s), then the engine's work on the rows (~30-45 s). Built:
      * the next parts' requests are on their way while a part is processed (engine/risk-analysis/_shared/RA-PartsInParallel.ps1
        over the transport's ask-ahead store, engine/_shared/SI-GraphRest.ps1); the parts are still processed one by one,
        in order, on the engine's own thread;
      * how many at a time adapts (2 to start; more while Defender answers quickly and the engine waits; half on 429 / 503
        / 504, nothing asked ahead until Retry-After has passed); SI_RA_PartsInParallel_Max (default 6, <= 4 per core);
      * the part's own count only near the source's row limit (Test-RABucketCountWanted); the report's count still checks
        every report once.
    What this file pins:
      * EQUAL OUTPUT: the same report through one part at a time and through several at a time gives the same rows, in
        the same order (in memory, and stored in SQL where the test VM's SQL Server runs) -- with Defender throttling one
        part on the way, too; requests really overlap, and no request is sent twice;
      * the completeness verdict is unchanged for a complete report, a short part at the row limit and a lost slice;
      * asking ahead puts every engine variable back and prints nothing; a request that came out different is sent again
        and the answer asked ahead is never used for it; the adaptive rule; the plain-word lines;
      * the engine's wiring (comment-stripped source): reset before the parts, ask ahead after a part's answer and before
        it is processed, stop after the main pass, the guards in the hunting layer, the count gate at both count sites.
    OFFLINE: an in-process HTTP handler stands in for advanced hunting -- no network, no tenant.
#>

$script:HasSql = [bool](Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')
$script:HasSql = $script:HasSql -and (Test-Path -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'sql', 'si-data-schema.sql')))
$script:HasSql = $script:HasSql -and (Test-Path -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'sql', 'si-identity-schema.sql')))

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ra = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    $script:Said = New-Object System.Collections.Generic.List[string]
    function script:Write-Info { param($m) $script:Said.Add([string]$m) }
    function script:Write-Warn2 { param($m) $script:Said.Add([string]$m) }
    function script:Write-Err2 { param($m) $script:Said.Add([string]$m) }
    function script:Write-Ok { param($m) }
    function script:Write-Diag { param($m) }
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ra 'RA-ExcelReport.ps1'), [ref]$null, [ref]$null)
    . ([scriptblock]::Create(($ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'New-RiskIndex' }, $true)).Extent.Text))
    $ast2 = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ra 'RA-ProfileAugment.ps1'), [ref]$null, [ref]$null)
    . ([scriptblock]::Create(($ast2.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Get-SISha256Bucket' }, $true)).Extent.Text))
    foreach ($f in 'RA-RiskIndexOrder.ps1', 'RA-RiskIndexSi.ps1', 'RA-FactorKeys.ps1', 'RA-CiContext.ps1', 'RA-RiskScore.ps1', 'RA-RowShaping.ps1', 'RA-SummaryBucketMerge.ps1',
                   'RA-Findings.ps1', 'RA-ColumnFillGuard.ps1', 'RA-SqlStream.ps1', 'RA-AutoBucketing.ps1', 'RA-PartsInParallel.ps1') { . (Join-Path $ra $f) }
    foreach ($f in 'engine\_shared\SI-GraphRest.ps1', 'engine\_shared\data-sql\SI-DataModel.ps1', 'engine\_shared\data-sql\SI-DataSql.ps1', 'engine\_shared\data-sql\SI-DataSummary.ps1',
                   'engine\asset-trend\_shared\SI-TrendRollup.ps1') { . (Join-Path $script:SIRoot $f) }
    $global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null; $global:RA_FactorCatalog = $null
    $script:Index = New-RiskIndex -CsvRows @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
    $script:Tiers = @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3')
    $script:EngineSrc = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
    $raw = [regex]::Replace($script:EngineSrc, '(?s)<#.*?#>', '')
    $script:EngineCode = (($raw -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    $ProgressPreference = 'SilentlyContinue'

    # ---- advanced hunting, in process: answers each part's rows after a delay, counts the requests and how many overlap;
    #      a part named in ThrottleOnce answers 429 with Retry-After once
    if (-not ('SiFakeHuntingHandler' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
public class SiFakeHuntingHandler : HttpMessageHandler {
    public int DelayMs = 200;
    public ConcurrentDictionary<int, string> Answers = new ConcurrentDictionary<int, string>();
    public ConcurrentDictionary<int, int> ThrottleOnce = new ConcurrentDictionary<int, int>();
    public ConcurrentQueue<string> Bodies = new ConcurrentQueue<string>();
    public int InFlight; public int MaxInFlight; public int Calls;
    public void Clear() { Answers.Clear(); ThrottleOnce.Clear(); string s; while (Bodies.TryDequeue(out s)) { } InFlight = 0; MaxInFlight = 0; Calls = 0; }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) {
        string body = await request.Content.ReadAsStringAsync();
        Bodies.Enqueue(body);
        Interlocked.Increment(ref Calls);
        int now = Interlocked.Increment(ref InFlight);
        int seen;
        do { seen = MaxInFlight; if (now <= seen) break; } while (Interlocked.CompareExchange(ref MaxInFlight, now, seen) != seen);
        try {
            await Task.Delay(DelayMs, ct);
            Match m = Regex.Match(body, @"part=(\d+)");
            int part = m.Success ? int.Parse(m.Groups[1].Value) : -1;
            int ra;
            if (ThrottleOnce.TryRemove(part, out ra)) {
                HttpResponseMessage t = new HttpResponseMessage((HttpStatusCode)429);
                t.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(ra));
                t.Content = new StringContent("{\"error\":{\"code\":\"TooManyRequests\"}}");
                return t;
            }
            string json;
            if (!Answers.TryGetValue(part, out json)) json = "{\"schema\":[],\"results\":[]}";
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        } finally { Interlocked.Decrement(ref InFlight); }
    }
}
'@
    }
    $script:Fake = New-Object SiFakeHuntingHandler
    $script:SIGraphHttpHandler = $script:Fake

    # the engine's pieces the ask-ahead build goes through, as small stand-ins: the part's query text, and the hunting
    # layer (it changes an engine variable and says a line, as the real one does, then asks advanced hunting)
    function script:New-BucketFilterKql { param($BucketCount, $BucketIndex, $ReportName) "| where part=$BucketIndex" }
    function script:Replace-BucketFilterBlock { param($Query, $BucketFilterKql) "$Query $BucketFilterKql" }
    function script:Invoke-GraphHuntingQuery {
        param($Query, $ReconnectMaxAgeMinutes, $MaxRetries)
        Write-Info ("asking {0}" -f $Query)
        $script:_LastHybridInlineBytes = 1000 + [int]$script:_CurrentBucketIndex
        $script:_RAHybridLastRequest = @{ Part = [int]$script:_CurrentBucketIndex }
        Invoke-SIHuntingQueryRest -Query $Query -Token 'test-token'
    }

    # ---- one generated report: 60 assets x 3 findings, a finding two parts both return, two assets sharing a name
    function script:New-ReportRows {
        $out = New-Object System.Collections.Generic.List[object]
        for ($a = 0; $a -lt 60; $a++) {
            $name = if ($a -eq 7 -or $a -eq 23) { 'shared-name' } else { "host$a" }
            for ($c = 0; $c -lt 3; $c++) {
                $out.Add([ordered]@{ SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs'; ConfigurationName = "CVE-2026-$c"
                    ConfigurationId = "CVE-2026-$c"; SecuritySeverity = @('High', 'Medium', 'Low')[$c]; CriticalityTier = ($a % 4); CriticalityTierLevel = $script:Tiers[$a % 4]
                    AssetName = $name; SI_AssetId = "aid-$a"; MdeDeviceId = "dev-$a"; DeviceKey = "dev-$a"; RiskFactor_Probability_Detailed = ''; RiskFactor_Consequence_Detailed = '' })
            }
        }
        $dup = [ordered]@{}; foreach ($k in $out[4].Keys) { $dup[$k] = $out[4][$k] }; $dup.DeviceKey = 'dup-of-4'; $out.Add($dup)
        $out.ToArray()
    }
    # the report's parts as advanced hunting answers them (Graph's JSON: schema + results), keyed by part
    function script:Set-FakeAnswers([int]$Parts) {
        $bk = @{}; for ($i = 0; $i -lt $Parts; $i++) { $bk[$i] = New-Object System.Collections.Generic.List[object] }
        foreach ($r in @(New-ReportRows)) { $bk[[int](Get-SISha256Bucket -Key ([string]$r.DeviceKey) -BucketCount $Parts)].Add($r) }
        for ($i = 0; $i -lt $Parts; $i++) { $script:Fake.Answers[$i] = (ConvertTo-Json -InputObject @{ schema = @(); results = @($bk[$i].ToArray()) } -Depth 6 -Compress) }
    }
    function script:Score([object[]]$Rows) {
        @(Calculate-RiskScore -Rows @($Rows) -RiskIndex $script:Index -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
            -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -ReportName 'Inv_Detailed')
    }
    # ONE REPORT THROUGH THE MAIN LOOP'S ORDER (Invoke-RiskAnalysis.ps1): per part its coordinates set, its request (the
    # hunting layer -- a 429 retried by the part's own run, as Invoke-GraphHuntingQuery does), the next parts asked ahead,
    # then the part's rows converted, scored, traced and stored (or kept in order). -Max 1 = one part at a time.
    function script:Invoke-TestReport([int]$Parts, [int]$Max, $Stream = $null) {
        $kept = New-Object System.Collections.Generic.List[string]
        Reset-RAPartsInParallel -PartCount $Parts -Max $Max
        if ($Stream) { $null = Start-RAStreamReport -Stream $Stream -ReportName 'Inv_Detailed' -Staged $false }
        for ($b = 0; $b -lt $Parts; $b++) {
            $script:_CurrentBucketCount = $Parts; $script:_CurrentBucketIndex = $b
            $q = Replace-BucketFilterBlock -Query 'DeviceTvmSoftwareVulnerabilities' -BucketFilterKql (New-BucketFilterKql -BucketCount $Parts -BucketIndex $b -ReportName 'Inv_Detailed')
            $resp = $null
            for ($attempt = 1; $attempt -le 3 -and $null -eq $resp; $attempt++) {
                try { $resp = Invoke-GraphHuntingQuery -Query $q -ReconnectMaxAgeMinutes 45 -MaxRetries 1 }
                catch { if ($_.Exception.Message -notmatch '429') { throw }; Start-Sleep -Milliseconds 50 }
            }
            # the part's own variables are its own when it is processed, whatever was asked ahead meanwhile
            Invoke-RAPartsAhead -After $b -PartCount $Parts -Query 'DeviceTvmSoftwareVulnerabilities' -ReportName 'Inv_Detailed'
            [int]$script:_CurrentBucketIndex | Should -Be $b
            [int]$script:_LastHybridInlineBytes | Should -Be (1000 + $b)
            $rows = @(@($resp.Results) | ForEach-Object { $h = [ordered]@{}; foreach ($k in $_.AdditionalProperties.Keys) { $h[[string]$k] = $_.AdditionalProperties[$k] }; [pscustomobject]$h })
            if ($rows.Count -eq 0) { continue }
            $sc = @(Score -Rows $rows)
            Set-RATraceIdentity -Rows $sc -IsDetailed $true
            if ($Stream) {
                Add-RAStreamColumns -Stream $Stream -Columns @($sc[0].PSObject.Properties.Name)
                $null = Write-RAStreamRows -Stream $Stream -Rows $sc -Bucket ('{0}/{1}' -f ($b + 1), $Parts) -IsDetailedShape $true
            }
            foreach ($r in $sc) { $kept.Add((ConvertTo-Json -InputObject $r -Compress -Depth 6)) }
        }
        Stop-RAPartsInParallel
        , $kept.ToArray()
    }
    function script:Sig($r) { '{0}|{1}|{2}|{3}|{4}|{5}' -f $r.AssetName, $r.ConfigurationId, $r.DeviceKey, $r.TraceName, $r.TraceID, ([double]$r.RiskScoreTotal_Weighted) }

    # ---- the local SQL Server (test VM), as SIv3-RaStreamToSql: a fresh database, the engine's seam over one connection
    function script:Open-TestDb {
        $name = 'si_test_raparts_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$name]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=.\SQLEXPRESS;Database=$name;Integrated Security=SSPI;Connection Timeout=30;Pooling=false")
        $cn.Open()
        foreach ($f in 'sql\si-data-schema.sql', 'sql\si-identity-schema.sql') { $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f)); [void]$c.ExecuteNonQuery() }
        $c = $cn.CreateCommand(); $c.CommandText = 'CREATE USER si_engine WITHOUT LOGIN; ALTER ROLE db_datareader ADD MEMBER si_engine; ALTER ROLE db_datawriter ADD MEMBER si_engine;'; [void]$c.ExecuteNonQuery()
        $c = $cn.CreateCommand(); $c.CommandText = "EXECUTE AS USER = N'si_engine';"; [void]$c.ExecuteNonQuery()
        $script:Conn = $cn
        $name
    }
    function script:Close-TestDb([string]$Name) {
        if ($script:Conn) { try { $script:Conn.Dispose() } catch { }; $script:Conn = $null }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$Name] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$Name]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    $script:Seam = {
        param($Sql, $Params, $Mode)
        $c = $script:Conn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 120
        if ($Params) { foreach ($k in $Params.Keys) { $v = $Params[$k]; [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $v) { [System.DBNull]::Value } else { $v })) } }
        switch ($Mode) {
            { $_ -in 'reader', 'rows' } {
                $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $out.Add($h) } } finally { $rd.Close() }
                , $out.ToArray()
            }
            'scalar' { $c.ExecuteScalar() }
            default { [void]$c.ExecuteNonQuery() }
        }
    }
    $script:NoLog = { param($l, $m) }
}

AfterAll {
    $script:SIGraphHttpHandler = $null
    $script:SIHuntingPrefetch = $null
}

Describe 'how many parts at a time (pure)' {
    It 'SI_RA_PartsInParallel_Max: default 6, 1 / 0 / off = one at a time, never more than 4 per processor core' {
        Get-RAPartsInParallelMax -Setting $null -Cores 4 | Should -Be 6
        Get-RAPartsInParallelMax -Setting '' -Cores 4 | Should -Be 6
        Get-RAPartsInParallelMax -Setting 1 -Cores 4 | Should -Be 1
        Get-RAPartsInParallelMax -Setting 0 -Cores 4 | Should -Be 1
        Get-RAPartsInParallelMax -Setting 'off' -Cores 4 | Should -Be 1
        Get-RAPartsInParallelMax -Setting 12 -Cores 4 | Should -Be 12
        Get-RAPartsInParallelMax -Setting 100 -Cores 2 | Should -Be 8 -Because 'no fixed cap, but a sane bound tied to the cores'
        Get-RAPartsInParallelMax -Setting $null -Cores 1 | Should -Be 4
        Get-RAPartsInParallelMax -Setting 'many' -Cores 4 | Should -Be 6
    }
    It 'queue workers (#742) SHARE one job''s budget: together never more at a time than one job; a job or the producer keeps it all' {
        Get-RAPartsInParallelShare -Max 6 | Should -Be 6 -Because 'one job (no worker role): the whole budget'
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Local $true -Workers 4 | Should -Be 6 -Because 'the producer''s own worker in its container is the only one'
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Workers 4 | Should -Be 1
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Workers 2 | Should -Be 3
        Get-RAPartsInParallelShare -Max 8 -Role 'worker' -Workers 4 | Should -Be 2
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Workers 1 | Should -Be 6
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Workers 0 | Should -Be 1 -Because 'a worker made before SI_RA_WORKERS: setup''s default 4 workers'
        Get-RAPartsInParallelShare -Max 1 -Role 'worker' -Workers 4 | Should -Be 1 -Because 'one part at a time stays one part at a time'
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Workers 30 | Should -Be 1 -Because 'never below the one request a worker needs'
        foreach ($m in 1..16) { foreach ($w in 1..8) {
            $s = Get-RAPartsInParallelShare -Max $m -Role 'worker' -Workers $w
            ($s * $w) | Should -BeLessOrEqual ([Math]::Max($m, $w)) -Because "workers $w x share $s never ask more at a time than one job ($m), or one request per worker"
        } }
    }
    It 'the limit a process uses: the role and the worker count from its environment; a queue worker says its share once' {
        $old = @{ R = $global:SI_RA_ScaleOutRole; W = [Environment]::GetEnvironmentVariable('SI_RA_WORKERS'); L = [Environment]::GetEnvironmentVariable('SI_RA_SCALEOUT_LOCAL'); M = $global:SI_RA_PartsInParallel_Max }
        try {
            $global:SI_RA_PartsInParallel_Max = 6
            $global:SI_RA_ScaleOutRole = ''; [Environment]::SetEnvironmentVariable('SI_RA_WORKERS', $null); [Environment]::SetEnvironmentVariable('SI_RA_SCALEOUT_LOCAL', $null)
            Get-RAPartsInParallelLimit | Should -Be ([Math]::Min(6, [Math]::Max(2, 4 * [Environment]::ProcessorCount)))
            $global:SI_RA_ScaleOutRole = 'worker'; [Environment]::SetEnvironmentVariable('SI_RA_WORKERS', '2')
            Get-RAPartsInParallelLimit | Should -Be ([Math]::Max(1, [Math]::Floor((Get-RAPartsInParallelMax) / 2)))
            [Environment]::SetEnvironmentVariable('SI_RA_SCALEOUT_LOCAL', '1')
            Get-RAPartsInParallelLimit | Should -Be (Get-RAPartsInParallelMax)
            # Reset uses it: a queue worker of 4 with the default asks one part at a time
            [Environment]::SetEnvironmentVariable('SI_RA_SCALEOUT_LOCAL', $null); [Environment]::SetEnvironmentVariable('SI_RA_WORKERS', '4')
            Reset-RAPartsInParallel -PartCount 8
            $script:RAParts.Max | Should -Be 1; $script:RAParts.On | Should -BeFalse
            Stop-RAPartsInParallel
        } finally {
            $global:SI_RA_ScaleOutRole = $old.R; $global:SI_RA_PartsInParallel_Max = $old.M
            [Environment]::SetEnvironmentVariable('SI_RA_WORKERS', $old.W); [Environment]::SetEnvironmentVariable('SI_RA_SCALEOUT_LOCAL', $old.L)
        }
    }
    It '#831 A: the last workers of a run share the budget the others left free -- never more than the budget together; unknown = the static share' {
        # Open = the run's items without a marker (this worker's own included); W = 4, budget 6
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Workers 4 -Open 1 | Should -Be 6 -Because 'alone: the whole budget'
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Workers 4 -Open 2 | Should -Be 3
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Workers 4 -Open 3 | Should -Be 2
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Workers 4 -Open 4 | Should -Be 1
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Workers 4 -Open 40 | Should -Be 1 -Because 'a full queue: the static share, as before'
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Workers 4 -Open -1 | Should -Be 1 -Because 'not known: the static share (safe)'
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Workers 4 -Open 0 | Should -Be 1 -Because 'zero open is not a real reading: the static share'
        Get-RAPartsInParallelShare -Max 6 -Role 'worker' -Local $true -Workers 4 -Open 3 | Should -Be 6 -Because 'the producer''s own worker keeps the whole budget'
        Get-RAPartsInParallelShare -Max 6 -Workers 4 -Open 3 | Should -Be 6 -Because 'one job: unchanged'
        # THE BOUND: Open only falls during a run. R workers still running, each read Open at some time (>= the Open now >= R):
        # their shares together never exceed the budget -- every reading order, every budget, every worker count
        foreach ($m in 1..12) { foreach ($w in 1..6) { foreach ($open in 1..8) {
            $running = [Math]::Min($w, $open)
            for ($stale = 0; $stale -le 3; $stale++) {
                $sum = 0
                for ($r = 0; $r -lt $running; $r++) { $sum += Get-RAPartsInParallelShare -Max $m -Role 'worker' -Workers $w -Open ($open + (($r * $stale) % 3)) }
                $sum | Should -BeLessOrEqual ([Math]::Max($m, $running)) -Because "budget $m, $w workers, $open open, readings up to $stale behind"
            }
        } } }
    }
    It '#831 A: a queue worker re-reads its share at the start of a report and every few minutes (one listing, never per part); when it rises the count climbs again' {
        $old = @{ R = $global:SI_RA_ScaleOutRole; W = [Environment]::GetEnvironmentVariable('SI_RA_WORKERS'); L = [Environment]::GetEnvironmentVariable('SI_RA_SCALEOUT_LOCAL'); M = $global:SI_RA_PartsInParallel_Max }
        $script:OpenNow = 4; $script:Reads = 0
        try {
            $global:SI_RA_PartsInParallel_Max = 6
            $global:SI_RA_ScaleOutRole = 'worker'; [Environment]::SetEnvironmentVariable('SI_RA_WORKERS', '4'); [Environment]::SetEnvironmentVariable('SI_RA_SCALEOUT_LOCAL', $null)
            $script:RAPartsOpenProbe = { $script:Reads++; $script:OpenNow }
            $max = Get-RAPartsInParallelMax
            Reset-RAPartsInParallel -PartCount 40
            $script:RAParts.Max | Should -Be ([Math]::Max(1, [Math]::Floor($max / 4)))
            $script:RAParts.On | Should -BeTrue -Because 'the share may rise during the report: asking ahead stays ready'
            $script:Reads | Should -Be 1 -Because 'the start of the report reads it once'
            $t0 = [datetime]::UtcNow
            # the other workers finish
            $script:OpenNow = 1
            Update-RAPartsShare -EverySeconds 300 -Now $t0.AddSeconds(30)
            $script:Reads | Should -Be 1 -Because 'not again within the interval'
            Update-RAPartsShare -EverySeconds 300 -Now $t0.AddSeconds(301)
            $script:Reads | Should -Be 2
            $script:RAParts.Max | Should -Be $max -Because 'alone: the whole budget'
            $script:RAParts.N | Should -Be ([Math]::Min(2, $max)) -Because 'the count climbs again from 2 (the adaptive rule is unchanged)'
            @($script:Said | Where-Object { $_ -match 'the other workers of this run have finished' }).Count | Should -BeGreaterThan 0
            # a probe that cannot tell: the static share
            $script:RAPartsOpenProbe = { throw 'the store is not reachable' }
            Reset-RAPartsInParallel -PartCount 40
            $script:RAParts.Max | Should -Be ([Math]::Max(1, [Math]::Floor($max / 4)))
            Stop-RAPartsInParallel
        } finally {
            $script:RAPartsOpenProbe = $null
            $global:SI_RA_ScaleOutRole = $old.R; $global:SI_RA_PartsInParallel_Max = $old.M
            [Environment]::SetEnvironmentVariable('SI_RA_WORKERS', $old.W); [Environment]::SetEnvironmentVariable('SI_RA_SCALEOUT_LOCAL', $old.L)
        }
    }
    It 'the adaptive rule: half on 429 / 503 / 504 with the Retry-After honoured, one more after a full round of quick answers the engine waited for, nothing learned otherwise' {
        $s = Get-RAPartsInParallelStep -N 4 -Max 6 -Clean 2 -Status 429 -RetryAfterSec 45
        $s.N | Should -Be 2; $s.PauseSeconds | Should -Be 45; $s.Clean | Should -Be 0
        $s.Line | Should -Be 'Defender asked us to slow down -- 2 parts at a time'
        (Get-RAPartsInParallelStep -N 1 -Max 6 -Status 504).N | Should -Be 1
        (Get-RAPartsInParallelStep -N 3 -Max 6 -Status 503).PauseSeconds | Should -Be 30 -Because 'no Retry-After: a pause of its own'
        (Get-RAPartsInParallelStep -N 2 -Max 6 -Status 429 -RetryAfterSec 1).Line | Should -Be 'Defender asked us to slow down -- 1 part at a time'
        # quick answers the engine waited for: N in a row = one more
        $s = Get-RAPartsInParallelStep -N 2 -Max 6 -Clean 0 -Status 200 -WaitedSec 3 -Seconds 20
        $s.N | Should -Be 2; $s.Clean | Should -Be 1; $s.Line | Should -BeNullOrEmpty
        $s = Get-RAPartsInParallelStep -N 2 -Max 6 -Clean 1 -Status 200 -WaitedSec 3 -Seconds 20
        $s.N | Should -Be 3; $s.Clean | Should -Be 0; $s.Line | Should -Be 'Defender answers quickly -- 3 parts at a time'
        (Get-RAPartsInParallelStep -N 6 -Max 6 -Clean 9 -Status 200 -WaitedSec 3 -Seconds 20).N | Should -Be 6 -Because 'the bound'
        # an answer already there (the engine is the slower half), a slow answer, a too-large answer: no change
        (Get-RAPartsInParallelStep -N 2 -Max 6 -Clean 1 -Status 200 -WaitedSec 0 -Seconds 20).N | Should -Be 2
        (Get-RAPartsInParallelStep -N 2 -Max 6 -Clean 1 -Status 200 -WaitedSec 5 -Seconds 300).N | Should -Be 2
        (Get-RAPartsInParallelStep -N 3 -Max 6 -Clean 1 -Status 502 -WaitedSec 5 -Seconds 20).N | Should -Be 3
        (Get-RAPartsInParallelStep -N 3 -Max 6 -Clean 1 -Status 0 -WaitedSec 5 -Seconds 20).N | Should -Be 3
    }
    It 'the lines are plain words -- no internal numbers or names' {
        foreach ($l in (Format-RAPartsLine -N 1), (Format-RAPartsLine -N 4), (Format-RAPartsLine -N 2 -Why 'Defender asked us to slow down')) {
            $l | Should -Not -Match '(?i)bucket|slice|prefetch|#\d|SI_|runspace|http'
        }
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-PartsInParallel.ps1'))
        foreach ($m in [regex]::Matches($src, "(?m)(Write-Info [^\r\n]*|\`$t \+?= [^\r\n]*)$")) { $m.Value | Should -Not -Match '(?i)bucket|prefetch|#\d' }
    }
}

Describe 'the part''s own count: only near the source''s row limit; the report''s verdict unchanged (#641)' {
    BeforeAll {
        . ([scriptblock]::Create([regex]::Match($script:EngineSrc, '(?s)function Test-RABucketRowCount \{.*?\n\}').Value))
        . ([scriptblock]::Create([regex]::Match($script:EngineSrc, '(?s)function Reset-RABucketLoss \{.*?\n\}').Value))
        . ([scriptblock]::Create([regex]::Match($script:EngineSrc, '(?s)function Add-RABucketLoss \{.*?\n\}').Value))
        function Get-RABucketRows { param($Resp) $Resp }
        # ONE PART AS THE MAIN LOOP CHECKS IT (Invoke-RiskAnalysis.ps1, after the part's rows are in): the gate, the part's
        # count, asked again once when short, its loss recorded when it stays short. The source is a stand-in.
        function script:Invoke-TestPartCheck([long]$Rows, [long]$SourceCount, [long]$AgainRows, $Mode) {
            $global:SI_RA_BucketCountCheck = $Mode
            $script:__src = $SourceCount
            if (Test-RABucketCountWanted -Rows $Rows) {
                $bc = Test-RABucketRowCount -Query 'T' -Rows $Rows
                if ($bc.Short) {
                    $r = [Math]::Max($Rows, $AgainRows)
                    if ($r -lt $bc.Expected) { Add-RABucketLoss ("bucket 1/3: the source returned {0} of the {1} row(s) it counts" -f $r, $bc.Expected) }
                    return $r
                }
            }
            $Rows
        }
        function Invoke-GraphHuntingQuery { param($Query, $ReconnectMaxAgeMinutes, $MaxRetries) $script:__counted++; @{ Ok = $true; Rows = @([pscustomobject]@{ Count = [long]$script:__src }) } }
        # THE REPORT'S VERDICT (Complete-RAReportCompleteness): a lost slice decides it; else the source's count of the
        # report against what its parts returned
        function script:Get-TestVerdict([long]$Expected, [long]$Retrieved) {
            $lost = Get-RALostSliceVerdict -Lost @($script:_RABucketLoss)
            if ($lost) { return $lost.State }
            (Get-RACompletenessVerdict -Expected $Expected -Retrieved $Retrieved).State
        }
        # one report's three parts, through every mode; returns @{ Verdict; Counted }
        function script:Invoke-TestVerdict($Mode, [long[]]$Rows, [long[]]$Source, [long[]]$Again, [long]$ReportSource, [int]$LostPart = -1) {
            Reset-RABucketLoss; $script:__counted = 0; $got = 0L
            for ($i = 0; $i -lt $Rows.Count; $i++) {
                if ($i -eq $LostPart) { Add-RABucketLoss ("bucket {0}/3: query failed -- 503 Service Unavailable" -f ($i + 1)); continue }
                $got += Invoke-TestPartCheck -Rows $Rows[$i] -SourceCount $Source[$i] -AgainRows $Again[$i] -Mode $Mode
            }
            @{ Verdict = (Get-TestVerdict -Expected $ReportSource -Retrieved $got); Counted = $script:__counted }
        }
    }
    AfterAll { $global:SI_RA_BucketCountCheck = $null }

    It 'the gate: off never, all every part, unset only a part at half the row limit or more (SI_RA_HuntingRowCap honoured)' {
        Test-RABucketCountWanted -Rows 49999 -Setting $null | Should -BeFalse
        Test-RABucketCountWanted -Rows 50000 -Setting $null | Should -BeTrue
        Test-RABucketCountWanted -Rows 99999 -Setting '' | Should -BeTrue
        Test-RABucketCountWanted -Rows 12 -Setting 'all' | Should -BeTrue
        Test-RABucketCountWanted -Rows 12 -Setting 'on' | Should -BeTrue
        Test-RABucketCountWanted -Rows 99999 -Setting 'off' | Should -BeFalse
        Test-RABucketCountWanted -Rows 600 -Setting $null -RowLimit 1000 | Should -BeTrue
        $global:SI_RA_HuntingRowCap = 1000
        try { Test-RABucketCountWanted -Rows 600 -Setting $null | Should -BeTrue } finally { $global:SI_RA_HuntingRowCap = $null }
    }
    It 'a COMPLETE report: Complete either way -- and no part is counted on its own any more' {
        $all = Invoke-TestVerdict -Mode 'all' -Rows 1200, 900, 1500 -Source 1200, 900, 1500 -Again 0, 0, 0 -ReportSource 3600
        $new = Invoke-TestVerdict -Mode $null -Rows 1200, 900, 1500 -Source 1200, 900, 1500 -Again 0, 0, 0 -ReportSource 3600
        $all.Verdict | Should -Be 'Complete'; $new.Verdict | Should -Be 'Complete'
        $all.Counted | Should -Be 3
        $new.Counted | Should -Be 0 -Because 'the second call per part is gone for parts well below the limit'
    }
    It 'a SHORT part AT the row limit: still counted on its own, asked again, its loss recorded -- NotComplete either way' {
        $all = Invoke-TestVerdict -Mode 'all' -Rows 1200, 60000, 1500 -Source 1200, 61000, 1500 -Again 0, 60000, 0 -ReportSource 63700
        $new = Invoke-TestVerdict -Mode $null -Rows 1200, 60000, 1500 -Source 1200, 61000, 1500 -Again 0, 60000, 0 -ReportSource 63700
        $all.Verdict | Should -Be 'NotComplete'; $new.Verdict | Should -Be 'NotComplete'
        $new.Counted | Should -Be 1 -Because 'only the part near the limit'
        @($script:_RABucketLoss) -join '|' | Should -Match 'the source returned 60000 of the 61000 row\(s\) it counts'
        # asked again and whole the second time: Complete either way
        (Invoke-TestVerdict -Mode $null -Rows 1200, 60000, 1500 -Source 1200, 61000, 1500 -Again 0, 61000, 0 -ReportSource 63700).Verdict | Should -Be 'Complete'
        (Invoke-TestVerdict -Mode 'all' -Rows 1200, 60000, 1500 -Source 1200, 61000, 1500 -Again 0, 61000, 0 -ReportSource 63700).Verdict | Should -Be 'Complete'
    }
    It 'a LOST slice: NotComplete either way, decided by the lost slice' {
        $all = Invoke-TestVerdict -Mode 'all' -Rows 1200, 900, 1500 -Source 1200, 900, 1500 -Again 0, 0, 0 -ReportSource 3600 -LostPart 1
        $new = Invoke-TestVerdict -Mode $null -Rows 1200, 900, 1500 -Source 1200, 900, 1500 -Again 0, 0, 0 -ReportSource 3600 -LostPart 1
        $all.Verdict | Should -Be 'NotComplete'; $new.Verdict | Should -Be 'NotComplete'
        (Get-RALostSliceVerdict -Lost @($script:_RABucketLoss)).Reason | Should -Match 'could not be read'
    }
    It 'a short part well below the limit is still caught -- by the report''s own count: NotComplete either way' {
        (Invoke-TestVerdict -Mode 'all' -Rows 1200, 900, 1500 -Source 1200, 1000, 1500 -Again 0, 900, 0 -ReportSource 3700).Verdict | Should -Be 'NotComplete'
        (Invoke-TestVerdict -Mode $null -Rows 1200, 900, 1500 -Source 1200, 1000, 1500 -Again 0, 900, 0 -ReportSource 3700).Verdict | Should -Be 'NotComplete'
    }
    It 'the engine gates BOTH count sites (the main loop and the split parts) with it, before the count is asked' {
        $c = $script:EngineCode
        $i = $c.IndexOf('if (Test-RABucketCountWanted -Rows $__bcRows) {')
        $i | Should -BeGreaterThan 0
        $i | Should -BeLessThan $c.IndexOf('$__bc = Test-RABucketRowCount -Query $thisQuery -Rows $__bcRows')
        $j = $c.IndexOf('if (Test-RABucketCountWanted -Rows $__sbcRows) {')
        $j | Should -BeGreaterThan 0
        $j | Should -BeLessThan $c.IndexOf('$__sbc = Test-RABucketRowCount -Query $subQuery -Rows $__sbcRows')
        $c | Should -Not -Match "SI_RA_BucketCountCheck\)\.Trim\(\)\.ToLowerInvariant\(\) -notin" -Because 'one gate, not two readings of the setting'
        # the report's own count still runs for every report
        $c | Should -Match ([regex]::Escape('$exp = Get-RAReportExpectedRows -Query $Query -ReportName $ReportName'))
    }
}

Describe 'asking a part ahead' {
    BeforeEach { $script:Fake.Clear(); $script:Fake.DelayMs = 50; $script:Said.Clear() }

    It 'puts every engine variable back and prints nothing; the part''s own request reads the answer and sends nothing' {
        Set-FakeAnswers -Parts 4
        Reset-RAPartsInParallel -PartCount 4 -Max 4
        $script:_CurrentBucketCount = 4; $script:_CurrentBucketIndex = 0; $script:_LastHybridInlineBytes = 42; $script:_RAHybridLastRequest = 'part 0'
        $script:_RALookupReductionOn = @{ a = $true }
        Invoke-RAPartAhead -Part 2 -PartCount 4 -Query 'T' -ReportName 'R' | Should -Be 'Started'
        $script:_CurrentBucketIndex | Should -Be 0
        $script:_LastHybridInlineBytes | Should -Be 42
        $script:_RAHybridLastRequest | Should -Be 'part 0'
        @($script:_RALookupReductionOn.Keys) -join ',' | Should -Be 'a'
        $script:Said.Count | Should -Be 0 -Because 'the part''s own run says everything'
        $script:SIHuntingPrefetch.Entries.Count | Should -Be 1
        $script:SIHuntingPrefetch.Capture | Should -BeFalse
        # the part's own request: the same text, the answer that is already there
        $script:_CurrentBucketIndex = 2
        $r = Invoke-GraphHuntingQuery -Query (Replace-BucketFilterBlock -Query 'T' -BucketFilterKql (New-BucketFilterKql -BucketIndex 2))
        @($r.Results).Count | Should -BeGreaterThan 0
        $script:Fake.Calls | Should -Be 1 -Because 'one request for the part, asked ahead, read once'
        $script:SIHuntingPrefetch.Entries.Count | Should -Be 0
        $script:SIHuntingPrefetch.Answers.Count | Should -Be 1
        Stop-RAPartsInParallel
        $script:SIHuntingPrefetch | Should -BeNullOrEmpty
    }
    It 'a request that came out different is sent again; the answer asked ahead is never used for it, and is dropped' {
        Set-FakeAnswers -Parts 4
        Reset-RAPartsInParallel -PartCount 4 -Max 4
        Invoke-RAPartAhead -Part 1 -PartCount 4 -Query 'T' -ReportName 'R' | Should -Be 'Started'
        $r = Invoke-SIHuntingQueryRest -Query 'T | where part=1 | where grown' -Token 'x'
        $script:Fake.Calls | Should -Be 2
        $script:SIHuntingPrefetch.Entries.Count | Should -Be 1
        Invoke-RAPartsAhead -After 1 -PartCount 4 -Query 'T' -ReportName 'R' -AskAhead { param($k) 'Failed' }
        $script:RAParts.Missed | Should -Be 1
        @($script:SIHuntingPrefetch.Entries.Values | Where-Object { $_.Part -eq 1 }).Count | Should -Be 0
        Stop-RAPartsInParallel
    }
    It 'a report not answered by advanced hunting goes on one part at a time; one part, or the setting 1, asks nothing ahead' {
        Reset-RAPartsInParallel -PartCount 5 -Max 4
        Invoke-RAPartsAhead -After 0 -PartCount 5 -Query 'T' -ReportName 'R' -AskAhead { param($k) 'NotAhead' }
        $script:RAParts.On | Should -BeFalse
        Stop-RAPartsInParallel
        Reset-RAPartsInParallel -PartCount 1 -Max 4; $script:RAParts.On | Should -BeFalse; $script:SIHuntingPrefetch | Should -BeNullOrEmpty
        Reset-RAPartsInParallel -PartCount 9 -Max 1; $script:RAParts.On | Should -BeFalse; $script:SIHuntingPrefetch | Should -BeNullOrEmpty
        Stop-RAPartsInParallel
    }
    It 'a 429 reads the Retry-After into the error the part''s own retry waits on' {
        $script:Fake.ThrottleOnce[3] = 7
        $err = $null
        try { $null = Invoke-SIHuntingQueryRest -Query 'T | where part=3' -Token 'x' } catch { $err = $_ }
        $err.Exception.Message | Should -Match '^429 Too Many Requests \(retry-after 7s\)'
        Get-RABucketRetryDelaySeconds -Attempt 1 -BaseSeconds 1 -Err $err | Should -Be 7
    }
}

Describe 'EQUAL OUTPUT: one part at a time and several at a time give the same rows, in the same order' {
    BeforeEach { $script:Fake.Clear(); $script:Said.Clear() }

    It 'in memory: the same rows, values and order; the requests overlap; no request is sent twice; the count adapts and is said' {
        $script:Fake.DelayMs = 1100      # the engine waits on Defender: more parts at a time pays off
        Set-FakeAnswers -Parts 8
        $one = Invoke-TestReport -Parts 8 -Max 1
        $script:Fake.MaxInFlight | Should -Be 1
        $script:Fake.Calls | Should -Be 8
        $script:Said | Where-Object { $_ -match 'parts? at a time' } | Should -BeNullOrEmpty -Because 'one at a time says nothing new'
        $script:Fake.Clear(); Set-FakeAnswers -Parts 8; $script:Said.Clear()
        $many = Invoke-TestReport -Parts 8 -Max 4
        $script:Fake.Calls | Should -Be 8 -Because 'every part asked once -- ahead or by itself'
        $many.Count | Should -Be $one.Count
        $one.Count | Should -BeGreaterThan 100
        ($many -join "`n") | Should -Be ($one -join "`n")
        $script:Said | Should -Contain '2 parts at a time'
        # (how far it rises depends on whether the engine or Defender is the slower half on this machine -- the rule itself
        # is pinned below and in the pure tests)
        @($script:Said | Where-Object { $_ -match '^[1-9]\d* part\(s\) were asked ahead while earlier parts were processed; [1-9]' }).Count | Should -Be 1
    }
    It 'more at a time after quick answers the engine waited for: the requests really are on their way together' {
        $script:Fake.DelayMs = 1500
        Set-FakeAnswers -Parts 8
        Reset-RAPartsInParallel -PartCount 8 -Max 4
        # two answers the engine waited for (2 s each) that came back quickly: N 2 -> 3
        $script:SIHuntingPrefetch.Answers.Add([pscustomobject]@{ Part = 0; Status = 200; RetryAfterSec = 0; WaitedSec = 2.0; Seconds = 10.0; Peeked = $false })
        $script:SIHuntingPrefetch.Answers.Add([pscustomobject]@{ Part = -1; Status = 200; RetryAfterSec = 0; WaitedSec = 2.0; Seconds = 2.0; Peeked = $false })
        Invoke-RAPartsAhead -After 0 -PartCount 8 -Query 'T' -ReportName 'R'
        $script:Said | Should -Contain 'Defender answers quickly -- 3 parts at a time'
        $script:SIHuntingPrefetch.Entries.Count | Should -Be 2 -Because 'the part being worked on is the third'
        Start-Sleep -Milliseconds 700
        $script:Fake.MaxInFlight | Should -Be 2 -Because 'both requests are on their way at the same time'
        Stop-RAPartsInParallel
    }
    It 'Defender throttles a part asked ahead: fewer at a time, the Retry-After honoured, the part asked again by its own run -- the same rows' {
        $script:Fake.DelayMs = 300
        Set-FakeAnswers -Parts 6
        $one = Invoke-TestReport -Parts 6 -Max 1
        $script:Fake.Clear(); Set-FakeAnswers -Parts 6; $script:Said.Clear()
        $script:Fake.ThrottleOnce[2] = 1
        $many = Invoke-TestReport -Parts 6 -Max 4
        ($many -join "`n") | Should -Be ($one -join "`n")
        $script:Fake.Calls | Should -Be 7 -Because 'the throttled part was asked once more, by its own run'
        @($script:Said | Where-Object { $_ -match '^Defender asked us to slow down -- 1 part at a time$' }).Count | Should -Be 1
    }
    It 'the same report stored in SQL: the same stored rows in the same order (Write-RAStreamRows -- the paced writer)' -Skip:(-not $script:HasSql) {
        $db = Open-TestDb
        try {
            $script:Fake.DelayMs = 200
            $ct = [datetime]::SpecifyKind([datetime]'2026-10-18T06:00:00', 'Utc')
            $read = {
                param($s)
                $fin = Complete-RAStreamReport -Stream $s
                $pg = New-RARowPager -Stream $s -Source All -TargetChars 4KB
                $out = New-Object System.Collections.Generic.List[string]
                while ($null -ne ($p = $pg.Next())) { foreach ($r in $p) { $out.Add((Sig $r)) } }
                @{ Stored = [long]$fin.Stored; Rows = $out.ToArray() }
            }
            Set-FakeAnswers -Parts 6
            $s1 = New-RAStream -Invoke $script:Seam -Grain Detailed -CollectionTime $ct -RunId 'one' -SolutionVersion '3.0.0+v3' -Log $script:NoLog
            $null = Invoke-TestReport -Parts 6 -Max 1 -Stream $s1
            $a = & $read $s1
            $script:Fake.Clear(); Set-FakeAnswers -Parts 6; $script:Said.Clear()
            $s2 = New-RAStream -Invoke $script:Seam -Grain Detailed -CollectionTime $ct.AddMinutes(1) -RunId 'many' -SolutionVersion '3.0.0+v3' -Log $script:NoLog
            $null = Invoke-TestReport -Parts 6 -Max 4 -Stream $s2
            $script:Fake.Calls | Should -Be 6 -Because 'every part asked once'
            # 2 at a time = the next part's request on its way while a part is scored and written
            @($script:Said | Where-Object { $_ -match '^[1-9]\d* part\(s\) were asked ahead while earlier parts were processed; [1-9]' }).Count | Should -Be 1
            $b = & $read $s2
            $b.Stored | Should -Be $a.Stored
            $a.Stored | Should -BeGreaterThan 100
            ($b.Rows -join "`n") | Should -Be ($a.Rows -join "`n")
        } finally { Close-TestDb $db }
    }
}

Describe 'the engine''s wiring' {
    It 'the main loop: reset before the parts, ask ahead after a part''s answer and before it is processed, stop after the main pass' {
        $c = $script:EngineCode
        $c | Should -Match ([regex]::Escape(". (Join-Path `$PSScriptRoot '_shared/RA-PartsInParallel.ps1')"))
        $reset = $c.IndexOf('Reset-RAPartsInParallel -PartCount ([int]$bucketCountToUse)')
        $loop = $c.IndexOf('for ($b = $__soFrom; $b -lt $__soTo; $b++) {')
        $ahead = $c.IndexOf('Invoke-RAPartsAhead -After $b -PartCount ([int]$bucketCountToUse) -Query $Query -ReportName $ReportName -End $__soTo')
        $call = $c.IndexOf('$resp = Invoke-GraphHuntingQuery -Query $thisQuery')
        $convert = $c.IndexOf('$bucketResult = ConvertTo-PSObjectDeep $rawResults')
        $stop = $c.IndexOf('Stop-RAPartsInParallel')
        $late = $c.IndexOf('if ($deferredBucketIndices.Count -gt 0) {')
        $reset | Should -BeGreaterThan 0
        $reset | Should -BeLessThan $loop
        $call | Should -BeLessThan $ahead
        $ahead | Should -BeLessThan $convert
        $ahead | Should -BeLessThan $c.IndexOf('if ($null -eq $resp) { continue }')
        $stop | Should -BeGreaterThan $convert
        $stop | Should -BeLessThan $late -Because 'the late retry and the split parts run one at a time'
        # not for a part built without the slice filter (#401), nor when the lake answers
        $c | Should -Match ([regex]::Escape('if (-not [bool]$script:_SkipEGBucketForCrossDomain -and -not [bool]$script:RALakeAnswered) {'))
    }
    It 'the hunting layer: a part asked ahead is never retried, counted, classified or said there; the lake and Log Analytics are not asked ahead' {
        $gh = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1'))
        $catch = $gh.IndexOf('if ($null -ne $script:SIHuntingPrefetch -and $script:SIHuntingPrefetch.Capture) { throw }')
        $catch | Should -BeGreaterThan 0
        $catch | Should -BeLessThan $gh.IndexOf('Add-SIReportRetryAnswer -Message $msg')
        $gh | Should -Match ([regex]::Escape('if (-not ($null -ne $script:SIHuntingPrefetch -and $script:SIHuntingPrefetch.Capture)) { Flush-SupersededAttempts }'))
        $lake = $gh.IndexOf('if (-not $script:_SentinelLakeUnavailable -and $null -ne $script:SIHuntingPrefetch -and $script:SIHuntingPrefetch.Capture) { throw (Get-SIHuntingNotAheadText) }')
        $lake | Should -BeGreaterThan 0
        $lake | Should -BeLessThan $gh.IndexOf('Invoke-SISentinelLakeQuery -Query $Query')
        $la = $gh.IndexOf("if (`$null -ne `$script:SIHuntingPrefetch -and `$script:SIHuntingPrefetch.Capture) { throw (Get-SIHuntingNotAheadText) }`r`n            # same fallback")
        if ($la -lt 0) { $la = $gh.IndexOf("if (`$null -ne `$script:SIHuntingPrefetch -and `$script:SIHuntingPrefetch.Capture) { throw (Get-SIHuntingNotAheadText) }`n            # same fallback") }
        $la | Should -BeGreaterThan 0
        $la | Should -BeLessThan $gh.IndexOf('Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $wsResId -Query $finalQuery')
        # the transport: the probe (-AsResult) is never asked ahead; every other request reads an answer asked ahead first
        $tr = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-GraphRest.ps1'))
        $tr | Should -Match ([regex]::Escape('if (-not $AsResult -and $null -ne $script:SIHuntingPrefetch) {'))
        # no PowerShell script block ever runs on another thread: the store holds .NET tasks only
        $tr | Should -Not -Match 'ContinueWith|Register\(|ThreadJob|RunspacePool'
    }
}
