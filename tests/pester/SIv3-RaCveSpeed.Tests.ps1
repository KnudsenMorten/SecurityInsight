#Requires -Version 7.0
<#
    THE CVE REPORT ON KUSTO, FASTER -- THE SAME ROWS (owner 2026-11-23: "Drop #1333, stay on Kusto", then "push harder, get
    it all out"). Three changes, each held to: identical rows to today (row for row, every column); a slice that fails after
    its retries is UNKNOWN (its loss recorded, the report NOT COMPLETE), never short.

      1. The exposed-devices count of Device_Missing_CVEs_Detailed (si_exposed_devices) is computed for THE SLICE'S OWN CVEs
         first (risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml, _sliceCves) -- still over every device of the
         tenant. MEASURED on a fixture tenant through a model of the query's joins: every row, every column the same at
         1 .. 16 slices; the template's text implements the model (the CVE set is drawn from exactly the two sources the
         union's rows come from).
      2. The parallel limit is the RUN'S MEASURED BUDGET (RA-PartsInParallel.ps1): no fixed number, halved for every worker
         on any throttle, grown after quiet rounds, weighted by the slices each running report still has to ask -- a worker
         with nothing queued gives its share to the report still running.
      3. A SMALL SLICE MERGES WITH ITS UNTOUCHED PARTNER (slice b of N with b + j*N/D is slice b of N/D): MEASURED through
         the main loop's order over an in-process advanced hunting -- the same rows in the same write order under the same
         slice names, fewer requests; a merged request that fails is asked again as its own slice; a slice that keeps
         failing is lost ALONE (its partners are in), and recorded.
    OFFLINE: an in-process HTTP handler stands in for advanced hunting -- no network, no tenant.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ra = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    $script:Said = New-Object System.Collections.Generic.List[string]
    function script:Write-Info { param($m) $script:Said.Add([string]$m) }
    function script:Write-Warn2 { param($m) $script:Said.Add([string]$m) }
    function script:Write-Err2 { param($m) $script:Said.Add([string]$m) }
    function script:Write-Ok { param($m) }
    function script:Write-Diag { param($m) }
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ra 'RA-ProfileAugment.ps1'), [ref]$null, [ref]$null)
    . ([scriptblock]::Create(($ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Get-SISha256Bucket' }, $true)).Extent.Text))
    . (Join-Path $ra 'RA-PartsInParallel.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-GraphRest.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    $script:EngineSrc = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
    $yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    $cat = $yaml | ConvertFrom-SIYaml
    $script:Detailed = (@((@($cat.Reports) | Where-Object { [string]$_.ReportName -eq 'Device_Missing_CVEs_Detailed' } | Select-Object -First 1).ReportQuery) -join "`n")
    $ProgressPreference = 'SilentlyContinue'

    # ---- advanced hunting, in process: answers a slice "i x N" with its rows, counts the requests; a slice named in FailOnce
    #      answers that status once, a slice named in FailAlways every time
    if (-not ('SiFakeSliceHandler' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
public class SiFakeSliceHandler : HttpMessageHandler {
    public int DelayMs = 30;
    public ConcurrentDictionary<string, string> Answers = new ConcurrentDictionary<string, string>();
    public ConcurrentDictionary<string, int> FailOnce = new ConcurrentDictionary<string, int>();
    public ConcurrentDictionary<string, int> FailAlways = new ConcurrentDictionary<string, int>();
    public ConcurrentQueue<string> Asked = new ConcurrentQueue<string>();
    public int Calls; public int FullN; public int FailCoarse;
    public void Clear() { Answers.Clear(); FailOnce.Clear(); FailAlways.Clear(); string s; while (Asked.TryDequeue(out s)) { } Calls = 0; }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) {
        string body = await request.Content.ReadAsStringAsync();
        Interlocked.Increment(ref Calls);
        await Task.Delay(DelayMs, ct);
        Match m = Regex.Match(body, @"slice=(\d+)x(\d+)");
        string key = m.Success ? (m.Groups[1].Value + "x" + m.Groups[2].Value) : "";
        Asked.Enqueue(key);
        int st;
        if (m.Success && FailCoarse > 0 && int.Parse(m.Groups[2].Value) < FullN) { int s0 = Interlocked.Exchange(ref FailCoarse, 0); if (s0 > 0) { HttpResponseMessage c = new HttpResponseMessage((HttpStatusCode)s0); c.Content = new StringContent("{\"error\":{\"code\":\"BadRequest\"}}"); return c; } }
        if (FailAlways.TryGetValue(key, out st) || FailOnce.TryRemove(key, out st)) {
            HttpResponseMessage f = new HttpResponseMessage((HttpStatusCode)st);
            f.Content = new StringContent("{\"error\":{\"code\":\"BadRequest\",\"message\":\"test failure\"}}");
            return f;
        }
        string json;
        if (!Answers.TryGetValue(key, out json)) json = "{\"schema\":[],\"results\":[]}";
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }
}
'@
    }
    $script:Fake = New-Object SiFakeSliceHandler
    $script:SIGraphHttpHandler = $script:Fake

    # the engine's pieces the loop and the ask-ahead build go through, as stand-ins: the slice's query text, and the hunting layer
    function script:New-BucketFilterKql { param($BucketCount, $BucketIndex, $ReportName) "| where slice=${BucketIndex}x${BucketCount}" }
    function script:Replace-BucketFilterBlock { param($Query, $BucketFilterKql) "$Query $BucketFilterKql" }
    function script:Invoke-GraphHuntingQuery { param($Query, $ReconnectMaxAgeMinutes, $MaxRetries) Invoke-SIHuntingQueryRest -Query $Query -Token 'test-token' }

    # ---- one CVE report of a fixture tenant: the slice key (DeviceKey, as the filter hashes it) is NOT an output column (the
    #      shipped report projects it away) -- the rows carry it as MdeDeviceId, or as the asset id of an asset without a
    #      Defender id. Two copies of one finding (the same CI, two device records) land in different slices: which is kept
    #      depends on the write order, so the write order is part of "the same rows".
    function script:New-FixtureRows([int]$Devices = 120, [switch]$WithUnplaceable, [int]$Slices = 32) {
        $out = New-Object System.Collections.Generic.List[object]
        # the twin of device 10: the device in the PARTNER slice of device 10's slice (b +/- N/2) -- one CI, two device records
        $b10 = Get-SISha256Bucket -Key 'dev-0010' -BucketCount $Slices
        $twin = -1
        for ($d = 11; $d -lt $Devices -and $twin -lt 0; $d++) { if ((Get-SISha256Bucket -Key ('dev-{0:D4}' -f $d) -BucketCount $Slices) -eq (($b10 + $Slices / 2) % $Slices)) { $twin = $d } }
        $script:TwinSlices = @($b10, $(if ($twin -ge 0) { ($b10 + $Slices / 2) % $Slices } else { -1 }))
        for ($d = 0; $d -lt $Devices; $d++) {
            $dk = 'dev-{0:D4}' -f $d
            $shared = ($d -eq 10 -or $d -eq $twin)
            $noMde = ($d % 17 -eq 3) -and -not $shared   # an exposure-graph asset without a Defender id: DeviceKey is its node id, the asset id is too
            for ($c = 0; $c -lt (1 + $d % 4); $c++) {
                $ci = if ($shared) { 'ci-shared' } else { if ($noMde) { $dk } else { 'ci-{0:D4}' -f $d } }
                $cve = if ($shared -and $c -eq 0) { 'CVE-2026-0500' } else { 'CVE-2026-{0:D4}' -f (($d * 7 + $c * 13) % 40) }
                $out.Add([ordered]@{ _key = $dk; SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs'
                    ConfigurationName = $cve; ConfigurationId = $cve
                    AssetName = $(if ($shared) { 'shared-host' } else { "host$d" }); AssetId = $ci
                    MdeDeviceId = $(if ($noMde) { '' } else { $dk }); si_affected_software = ('sw-{0}' -f $d); si_exposed_devices = (3 + $c) })
            }
        }
        if ($WithUnplaceable) {
            # an exposure-graph asset linked to a CI and without a Defender id: nothing in its row hashes to its slice
            $out.Add([ordered]@{ _key = 'node-zz-01'; SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs'; ConfigurationName = 'CVE-2026-9999'
                ConfigurationId = 'CVE-2026-9999'; AssetName = 'graph-only'; AssetId = 'ci-graph-only'; MdeDeviceId = ''; si_affected_software = ''; si_exposed_devices = 1 })
        }
        $out.ToArray()
    }
    # the answer of slice i of every count the loop may ask (N, N/2, N/4, ... 1), ordered as the report orders its rows
    function script:Set-FixtureAnswers([object[]]$Rows, [int]$N) {
        $script:Fake.Clear()
        for ($c = $N; $c -ge 1; $c = [int]($c / 2)) {
            $bk = @{}; for ($i = 0; $i -lt $c; $i++) { $bk[$i] = New-Object System.Collections.Generic.List[object] }
            foreach ($r in $Rows) { $bk[[int](Get-SISha256Bucket -Key ([string]$r._key) -BucketCount $c)].Add($r) }
            for ($i = 0; $i -lt $c; $i++) {
                $res = @($bk[$i] | Sort-Object { $_.AssetName }, { $_.ConfigurationId } | ForEach-Object { $o = [ordered]@{}; foreach ($k in $_.Keys) { if ($k -ne '_key') { $o[$k] = $_[$k] } }; $o })
                $script:Fake.Answers["${i}x${c}"] = (ConvertTo-Json -InputObject @{ schema = @(); results = @($res) } -Depth 6 -Compress)
            }
            if ($c -eq 1) { break }
        }
    }
    # ONE REPORT THROUGH THE MAIN LOOP'S ORDER (Invoke-RiskAnalysis.ps1): per slice -- in already (a merged answer brought its
    # rows: written now, under its own name) or its request (Get-RASliceRequest), retried; a merged request that fails is asked
    # again as its own slice (Stop-RASliceMerge); the next slices asked ahead; the rows placed (Split-RASliceRows) and written.
    function script:Invoke-SliceRun([int]$N, [bool]$Merge, [int]$Max = 4, [double]$RowLimit = 30000) {
        $written = New-Object System.Collections.Generic.List[string]; $lost = New-Object System.Collections.Generic.List[string]
        $script:Fake.Calls = 0
        Reset-RAPartsInParallel -PartCount $N -Max $Max
        $mg = New-RASliceMerge -Count $N -RowLimit $RowLimit -SecondsLimit 180 -On $Merge
        $script:RASliceMerge = $mg
        $held = @{}
        for ($b = 0; $b -lt $N; $b++) {
            if (Test-RASliceCovered -Merge $mg -Slice $b) {
                $rows = @(); if ($held.ContainsKey($b)) { $rows = @($held[$b]); $held.Remove($b) }
                foreach ($r in $rows) { $written.Add(('{0}/{1}|{2}' -f ($b + 1), $N, (ConvertTo-Json -InputObject $r -Compress -Depth 6))) }
                continue
            }
            $req = Get-RASliceRequest -Merge $mg -Slice $b
            $script:_CurrentBucketCount = [int]$req.Count; $script:_CurrentBucketIndex = [int]$req.Index
            $q = Replace-BucketFilterBlock -Query 'DeviceTvmSoftwareVulnerabilities' -BucketFilterKql (New-BucketFilterKql -BucketCount $req.Count -BucketIndex $req.Index)
            $resp = $null; $attempt = 0
            while ($null -eq $resp -and $attempt -lt 3) {
                $attempt++
                try { $resp = Invoke-GraphHuntingQuery -Query $q -ReconnectMaxAgeMinutes 45 -MaxRetries 1 }
                catch {
                    if (@($req.Covers).Count -gt 0) {
                        $req = Stop-RASliceMerge -Merge $mg -Slice $b -Why 'a request that held several parts failed'
                        $script:_CurrentBucketCount = $N; $script:_CurrentBucketIndex = $b
                        $q = Replace-BucketFilterBlock -Query 'DeviceTvmSoftwareVulnerabilities' -BucketFilterKql (New-BucketFilterKql -BucketCount $N -BucketIndex $b)
                        $attempt = 0; continue
                    }
                }
            }
            Invoke-RAPartsAhead -After $b -PartCount $N -Query 'DeviceTvmSoftwareVulnerabilities' -ReportName 'Device_Missing_CVEs_Detailed'
            if ($null -eq $resp) { $lost.Add(('{0}/{1}' -f ($b + 1), $N)); continue }
            $rows = @(@($resp.Results) | ForEach-Object { $h = [ordered]@{}; foreach ($k in $_.AdditionalProperties.Keys) { $h[[string]$k] = $_.AdditionalProperties[$k] }; [pscustomobject]$h })
            if (@($req.Covers).Count -gt 0) {
                $sp = Split-RASliceRows -Rows $rows -Count $N -Slice $b -Covers @($req.Covers)
                $rows = @($sp.Own); foreach ($k in @($sp.Held.Keys)) { $held[[int]$k] = @($sp.Held[$k]) }
                $null = Complete-RASliceRequest -Merge $mg -Slice $b -Rows ([long]@($resp.Results).Count) -Seconds 1
                if ([int]$sp.Unplaced -gt 0) { $null = Stop-RASliceMerge -Merge $mg -Why 'rows could not be placed' }
            } else { $null = Complete-RASliceRequest -Merge $mg -Slice $b -Rows ([long]$rows.Count) -Seconds 1 }
            foreach ($r in $rows) { $written.Add(('{0}/{1}|{2}' -f ($b + 1), $N, (ConvertTo-Json -InputObject $r -Compress -Depth 6))) }
        }
        Stop-RAPartsInParallel
        $script:RASliceMerge = $null
        @{ Written = $written.ToArray(); Lost = $lost.ToArray(); Calls = [int]$script:Fake.Calls; Merge = $mg }
    }
    # "first written is kept" (the report's cross-slice de-duplication): the rows that survive it, in write order
    function script:Kept([string[]]$Written) {
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'; $out = New-Object System.Collections.Generic.List[string]
        foreach ($w in $Written) { $o = ($w.Substring($w.IndexOf('|') + 1) | ConvertFrom-Json); $k = '{0}|{1}|{2}' -f $o.AssetName, $o.AssetId, $o.ConfigurationId; if ($seen.Add($k)) { $out.Add($w.Substring($w.IndexOf('|') + 1)) } }
        $out.ToArray()
    }
}

AfterAll {
    $script:SIGraphHttpHandler = $null
    $script:SIHuntingPrefetch = $null
    $script:RASliceMerge = $null
}

Describe '1. the exposed-devices count reads the slice''s own CVEs first -- the same count, the same rows' {
    BeforeAll {
        # a fixture tenant: 90 devices (every 11th excluded in Defender), 30 CVEs, exposure-graph assets with findings
        $script:Tvm = New-Object System.Collections.Generic.List[object]
        for ($d = 0; $d -lt 90; $d++) { for ($c = 0; $c -lt (1 + $d % 5); $c++) { $script:Tvm.Add(@{ DeviceId = ('Dev-{0:D3}' -f $d); CveId = ('cve-2026-{0:D3}' -f (($d * 3 + $c * 7) % 30)) }) } }
        $script:Tvm.Add(@{ DeviceId = 'Dev-000'; CveId = 'cve-2026-000' })   # the same pair twice: one device once per CVE
        $script:Excluded = @{}; for ($d = 0; $d -lt 90; $d += 11) { $script:Excluded[('dev-{0:D3}' -f $d)] = $true }
        # graph findings of assets: some on Defender devices (DeviceKey = the device id), some graph-only (a node id)
        $script:Graph = New-Object System.Collections.Generic.List[object]
        for ($a = 0; $a -lt 40; $a++) {
            $key = if ($a % 3 -eq 0) { 'node-{0:D3}' -f $a } else { 'dev-{0:D3}' -f ($a * 2) }
            $script:Graph.Add(@{ DeviceKey = $key; FindingName = ('CVE-2026-{0:D3}' -f (($a * 7) % 33)) })   # CVEs 30-32: only the graph knows them
        }
        # the old count: every CVE of the tenant; the new: the slice's own CVEs first -- both over EVERY device of the tenant
        function script:ExposedOld { $m = @{}; foreach ($p in @($script:Tvm | ForEach-Object { '{0}|{1}' -f $_.CveId.ToUpperInvariant(), $_.DeviceId.ToLowerInvariant() } | Sort-Object -Unique)) { $c, $dv = $p -split '\|'; if ($script:Excluded[$dv]) { continue }; $m[$c] = 1 + [int]$m[$c] }; $m }
        function script:ExposedNew([string[]]$SliceCves) { $want = @{}; foreach ($c in $SliceCves) { $want[$c] = $true }; $m = @{}; foreach ($p in @($script:Tvm | Where-Object { $want[$_.CveId.ToUpperInvariant()] } | ForEach-Object { '{0}|{1}' -f $_.CveId.ToUpperInvariant(), $_.DeviceId.ToLowerInvariant() } | Sort-Object -Unique)) { $c, $dv = $p -split '\|'; if ($script:Excluded[$dv]) { continue }; $m[$c] = 1 + [int]$m[$c] }; $m }
        # the report's rows of one slice: the graph rows of the slice's assets and the vulnerability-management rows of its
        # devices (the union), each joined to the count by its CVE (leftouter: no count = empty)
        function script:SliceRows([int]$N, [int]$i, [bool]$New) {
            $inSlice = { param($k) $N -le 1 -or (Get-SISha256Bucket -Key $k -BucketCount $N) -eq $i }
            $g = @($script:Graph | Where-Object { & $inSlice $_.DeviceKey })
            $t = @($script:Tvm | Where-Object { & $inSlice $_.DeviceId.ToLowerInvariant() })
            $union = @($g | ForEach-Object { [ordered]@{ DeviceKey = $_.DeviceKey; FindingName = $_.FindingName; _from = 'graph' } }) + @($t | ForEach-Object { [ordered]@{ DeviceKey = $_.DeviceId.ToLowerInvariant(); FindingName = $_.CveId; _from = 'tvm' } })
            # _sliceCves = the slice's graph findings + the vulnerability-management CVEs of the slice's devices (the template)
            $sliceCves = @(@($g | ForEach-Object { $_.FindingName.ToUpperInvariant() }) + @($t | ForEach-Object { $_.CveId.ToUpperInvariant() }) | Where-Object { $_ } | Sort-Object -Unique)
            $exp = if ($New) { ExposedNew -SliceCves $sliceCves } else { ExposedOld }
            @($union | ForEach-Object { $c = $_.FindingName.ToUpperInvariant(); '{0}|{1}|{2}|{3}' -f $_.DeviceKey, $_.FindingName, $_._from, $(if ($exp.ContainsKey($c)) { [string]$exp[$c] } else { '<empty>' }) })
        }
    }
    It 'MEASURED: every slice''s rows are the same, row for row and every column, at 1, 2, 4, 8 and 16 slices' {
        $rows = 0; $cut = 0
        foreach ($n in 1, 2, 4, 8, 16) {
            for ($i = 0; $i -lt $n; $i++) {
                $old = @(SliceRows -N $n -i $i -New $false); $new = @(SliceRows -N $n -i $i -New $true)
                ($new -join "`n") | Should -BeExactly ($old -join "`n") -Because "slice $i of $n"
                $rows += $old.Count
            }
        }
        $rows | Should -BeGreaterThan 1000
        # the gain: a slice of 16 groups only its own CVEs, not every CVE of the tenant
        $all = @(ExposedOld).Keys.Count
        $g = @($script:Graph | Where-Object { (Get-SISha256Bucket -Key $_.DeviceKey -BucketCount 16) -eq 0 }); $t = @($script:Tvm | Where-Object { (Get-SISha256Bucket -Key $_.DeviceId.ToLowerInvariant() -BucketCount 16) -eq 0 })
        $mine = @(@($g | ForEach-Object { $_.FindingName.ToUpperInvariant() }) + @($t | ForEach-Object { $_.CveId.ToUpperInvariant() }) | Sort-Object -Unique).Count
        Write-Host ("exposed devices, slice 1 of 16: grouped {0} CVE(s) of the tenant before, {1} now -- the same counts" -f $all, $mine)
        $mine | Should -BeLessThan $all
    }
    It 'a CVE no device is exposed to (only the graph knows it) stays empty, never 0 -- as before' {
        $r = @(SliceRows -N 1 -i 0 -New $true | Where-Object { $_ -match '\|CVE-2026-03[0-2]\|' })
        $r.Count | Should -BeGreaterThan 0
        @($r | Where-Object { $_ -notmatch '\|<empty>$' }).Count | Should -Be 0
    }
    It 'the template implements the model: the CVE set is drawn from exactly the two sources the union''s rows come from, and the count stays over the tenant' {
        $q = $script:Detailed
        # the union's two sources: the graph rows come from _Findings (inner join), the vulnerability-management rows from the slice's devices
        $q | Should -Match '(?s)let _AssetFindingEdges =\s*_DeviceFindingEdges\s*\| join kind=inner \(_Findings\)'
        $q | Should -Match '(?s)let _TvmOnly = DeviceTvmSoftwareVulnerabilities\s*\| where tolower\(tostring\(DeviceId\)\) in \(_sliceTvmDevices\)'
        $q | Should -Match '(?s)union _AssetFindingEdges, _TvmOnly'
        # the slice's CVEs: those two sources, the same key the join uses (upper case)
        $q | Should -Match ([regex]::Escape('let _sliceCves = union (_Findings | project _sliceCve = toupper(tostring(FindingName))), (DeviceTvmSoftwareVulnerabilities | where tolower(tostring(DeviceId)) in (_sliceTvmDevices) | project _sliceCve = toupper(tostring(CveId)))'))
        $q | Should -Match ([regex]::Escape('| join kind=leftouter (_cveExposedDevices) on $left._cveUpper == $right._expCve'))
        $q | Should -Match ([regex]::Escape('| extend _cveUpper = toupper(tostring(FindingName))'))
        # the count: the CVE set first, then every device of the tenant (no device filter, no slice filter of its own)
        $at = $q.IndexOf('let _cveExposedDevices'); $end = $q.IndexOf(';', $at)
        $block = $q.Substring($at, $end - $at)
        $block | Should -Match 'where toupper\(tostring\(CveId\)\) in \(_sliceCves\)'
        $block | Should -Not -Match '_sliceTvmDevices|__BUCKET_FILTER'
        # the graph's findings are the slice's (the assets carry the slice filter)
        $q | Should -Match '(?s)let _Assets =.*?//__BUCKET_FILTER_BEGIN__.*?let _AssetNodeIdSet = _Assets \| distinct AssetNodeId;'
    }
    It 'shipped content: the Risk Analysis report templates are fix templates -- they ride the code version, so the change needs no template pack bump; the fingerprint change is declared' {
        $cls = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'config\template-classification.locked.json'))
        $cls | Should -Match '"rareport":\s*"fix"'
        $pack = Get-Content (Join-Path $script:SIRoot 'engine\pro-settings\shipped-template-pack.json') -Raw | ConvertFrom-Json
        [bool]$pack.ClassificationReviewed | Should -BeTrue -Because 'from pack 1.3 on a pack version names the Microsoft content only'
        $carry = Get-Content (Join-Path $script:SIRoot 'data-model\report-fingerprint-carry.locked.json') -Raw | ConvertFrom-Json
        @($carry.changes | Where-Object { $_.id -eq 'report-slice-cves-2026-11-23' }).Count | Should -Be 1
    }
}

Describe '3. a small slice merges with its untouched partner' {
    It 'THE PARTITION: slice b of N and its partners b + j*N/D are exactly slice b of N/D (the engine''s own slice hash)' {
        $keys = @(1..1500 | ForEach-Object { 'k-{0}-{1}' -f $_, ($_ * 7919 % 104729) })
        foreach ($n in 8, 64, 512) {
            $hN = @{}; $keys | ForEach-Object { $hN[$_] = Get-SISha256Bucket -Key $_ -BucketCount $n }
            foreach ($d in 2, 4, 8) {
                $c = $n / $d
                foreach ($b in @(0, 1, ($c - 1) | Where-Object { $_ -lt $c } | Sort-Object -Unique)) {
                    $members = @(0..($d - 1) | ForEach-Object { $b + $_ * $c })
                    $viaParts = @($keys | Where-Object { $members -contains $hN[$_] })
                    $viaMerged = @($keys | Where-Object { (Get-SISha256Bucket -Key $_ -BucketCount $c) -eq $b })
                    ($viaMerged -join ',') | Should -BeExactly ($viaParts -join ',') -Because "slice $b of $c = slices $($members -join ', ') of $n"
                }
            }
        }
    }
    It 'the plan: decided once; small answers widen it, a large one narrows it; only untouched partners inside the range; an odd count never merges' {
        $m = New-RASliceMerge -Count 16 -RowLimit 1000 -SecondsLimit 180
        (Get-RASliceRequest -Merge $m -Slice 0).Count | Should -Be 16 -Because 'the first slice is asked alone'
        Complete-RASliceRequest -Merge $m -Slice 0 -Rows 10 -Seconds 5 | Should -Be 2 -Because 'small: twice as wide'
        $r = Get-RASliceRequest -Merge $m -Slice 1
        $r.Count | Should -Be 8; $r.Index | Should -Be 1; @($r.Covers) | Should -Be @(9)
        (Get-RASliceRequest -Merge $m -Slice 1).Count | Should -Be 8 -Because 'decided once (the part asked ahead and its own turn ask the same)'
        Test-RASliceTaken -Merge $m -Slice 9 | Should -BeTrue
        Test-RASliceCovered -Merge $m -Slice 9 | Should -BeFalse -Because 'not in until its request is'
        Complete-RASliceRequest -Merge $m -Slice 1 -Rows 20 -Seconds 5 | Should -Be 4
        Test-RASliceCovered -Merge $m -Slice 9 | Should -BeTrue
        $r = Get-RASliceRequest -Merge $m -Slice 2
        $r.Count | Should -Be 4; @($r.Covers) | Should -Be @(6, 10, 14)
        # a large answer (over half the planned rows) narrows it
        Complete-RASliceRequest -Merge $m -Slice 2 -Rows 600 -Seconds 5 | Should -Be 2
        # slice 3: width 2 -> partner 11 (untouched)
        @((Get-RASliceRequest -Merge $m -Slice 3).Covers) | Should -Be @(11)
        # a slow answer (over half the time limit) narrows it too
        Complete-RASliceRequest -Merge $m -Slice 3 -Rows 1 -Seconds 100 | Should -Be 1
        (Get-RASliceRequest -Merge $m -Slice 4).Count | Should -Be 16
        # only partners inside [From, To): a split part of the report never takes another part's slices
        $p = New-RASliceMerge -Count 16 -From 0 -To 8 -RowLimit 1000; $null = Complete-RASliceRequest -Merge $p -Slice 0 -Rows 1 -Seconds 1
        @((Get-RASliceRequest -Merge $p -Slice 1).Covers).Count | Should -Be 0 -Because 'its partner 9 is another part''s'
        # an odd count has no partners; off = never
        (New-RASliceMerge -Count 63).On | Should -BeFalse
        (New-RASliceMerge -Count 64 -On $false).On | Should -BeFalse
        Test-RASliceMergeWanted -Setting 'off' | Should -BeFalse
        Test-RASliceMergeWanted -Setting $null | Should -BeTrue
    }
    It 'a failed merged request gives every partner back -- each asked in its own turn; what is in stays in' {
        $m = New-RASliceMerge -Count 16 -RowLimit 1000
        $null = Complete-RASliceRequest -Merge $m -Slice 0 -Rows 1 -Seconds 1
        $null = Get-RASliceRequest -Merge $m -Slice 1
        $null = Complete-RASliceRequest -Merge $m -Slice 1 -Rows 1 -Seconds 1      # 1 with 9: in
        $r2 = Get-RASliceRequest -Merge $m -Slice 2                                 # 2 with 6, 10, 14: asked
        @($r2.Covers).Count | Should -Be 3
        $again = Stop-RASliceMerge -Merge $m -Slice 2 -Why 'test'
        $again.Count | Should -Be 16; @($again.Covers).Count | Should -Be 0
        foreach ($k in 6, 10, 14) { Test-RASliceTaken -Merge $m -Slice $k | Should -BeFalse; (Get-RASliceRequest -Merge $m -Slice $k).Count | Should -Be 16 }
        Test-RASliceCovered -Merge $m -Slice 9 | Should -BeTrue -Because 'a partner already in stays in'
        $m.On | Should -BeFalse
        (Format-RASliceMergeLine -Merge $m) | Should -Match 'asked on its own again'
    }
    It 'the rows of a merged answer are placed in their own slice by the key the filter hashed; a row nothing places stays (never dropped)' {
        $rows = @(New-FixtureRows -Devices 60 -WithUnplaceable)
        $n = 8
        $members = @(1, 5)
        $mine = @($rows | Where-Object { $members -contains (Get-SISha256Bucket -Key ([string]$_._key) -BucketCount $n) } | ForEach-Object { $o = [ordered]@{}; foreach ($k in $_.Keys) { if ($k -ne '_key') { $o[$k] = $_[$k] } }; [pscustomobject]$o })
        $sp = Split-RASliceRows -Rows $mine -Count $n -Slice 1 -Covers @(5)
        (@($sp.Own).Count + @($sp.Held[5]).Count) | Should -Be $mine.Count -Because 'every row is kept'
        foreach ($r in @($sp.Own)) { $k = if ($r.MdeDeviceId) { $r.MdeDeviceId } else { $r.AssetId }; if ($k -ne 'ci-graph-only') { Get-SISha256Bucket -Key $k -BucketCount $n | Should -Be 1 } }
        foreach ($r in @($sp.Held[5])) { $k = if ($r.MdeDeviceId) { $r.MdeDeviceId } else { $r.AssetId }; Get-SISha256Bucket -Key $k -BucketCount $n | Should -Be 5 }
        $unp = @($mine | Where-Object { $_.AssetId -eq 'ci-graph-only' }).Count
        [int]$sp.Unplaced | Should -Be $unp
    }
    It 'EQUAL OUTPUT: merged and one slice at a time write the same rows, in the same order, under the same slice names -- with fewer requests' {
        $rows = @(New-FixtureRows -Devices 160)
        Set-FixtureAnswers -Rows $rows -N 32
        $plain = Invoke-SliceRun -N 32 -Merge $false
        Set-FixtureAnswers -Rows $rows -N 32
        $merged = Invoke-SliceRun -N 32 -Merge $true
        $plain.Written.Count | Should -Be $rows.Count
        ($merged.Written -join "`n") | Should -BeExactly ($plain.Written -join "`n") -Because 'row for row, every column, the write order and the slice names'
        ((Kept $merged.Written) -join "`n") | Should -BeExactly ((Kept $plain.Written) -join "`n") -Because 'the copy of a finding two slices both returned that is kept is the same'
        $merged.Lost.Count | Should -Be 0
        [int]$merged.Merge.Merged | Should -BeGreaterThan 0
        $merged.Calls | Should -BeLessThan $plain.Calls
        Write-Host ("merge measure: the twin copies of one finding sit in slices {0} (partners) -- the same copy is kept" -f ($script:TwinSlices -join ' and '))
        Write-Host ("merge measure: 32 slices of {0} rows -- {1} requests one slice at a time, {2} merged ({3} small slices asked with their partners)" -f $rows.Count, $plain.Calls, $merged.Calls, [int]$merged.Merge.Saved)
    }
    It 'a merged request that fails is asked again as its own slice; its partners each in their own turn -- the same rows' {
        $rows = @(New-FixtureRows -Devices 160)
        Set-FixtureAnswers -Rows $rows -N 32
        $plain = Invoke-SliceRun -N 32 -Merge $false
        Set-FixtureAnswers -Rows $rows -N 32
        # the FIRST merged request (whichever slice it holds) fails once
        $script:Fake.FullN = 32; $script:Fake.FailCoarse = 400
        $merged = Invoke-SliceRun -N 32 -Merge $true
        ($merged.Written -join "`n") | Should -BeExactly ($plain.Written -join "`n")
        $merged.Lost.Count | Should -Be 0
        $merged.Merge.On | Should -BeFalse -Because 'merging stops for the report'
        $script:Fake.FailCoarse | Should -Be 0 -Because 'a merged request was asked, and failed'
        @($script:Fake.Asked.ToArray() | Where-Object { $_ -match 'x32$' } | Sort-Object -Unique).Count | Should -Be 32 -Because 'every slice then asked as its own -- the partners each in their own turn'
    }
    It 'a slice that keeps failing is lost ALONE and recorded (UNKNOWN, never short): its partners are in' {
        $rows = @(New-FixtureRows -Devices 160)
        Set-FixtureAnswers -Rows $rows -N 32
        $plain = Invoke-SliceRun -N 32 -Merge $false
        Set-FixtureAnswers -Rows $rows -N 32
        # slice 2 of 32 fails every time, alone or with its partners
        foreach ($k in '1x32', '1x16', '1x8', '1x4', '1x2') { $script:Fake.FailAlways[$k] = 400 }
        $merged = Invoke-SliceRun -N 32 -Merge $true
        @($merged.Lost) | Should -Be @('2/32') -Because 'only the failing slice is lost, and its loss is recorded'
        $expect = @($plain.Written | Where-Object { -not $_.StartsWith('2/32|') })
        ($merged.Written -join "`n") | Should -BeExactly ($expect -join "`n") -Because 'every other slice -- its partners included -- is in, row for row'
    }
    It 'rows nothing can place: kept with the slice, and merging stops for the report (no row is lost)' {
        $rows = @(New-FixtureRows -Devices 160 -WithUnplaceable)
        Set-FixtureAnswers -Rows $rows -N 32
        $merged = Invoke-SliceRun -N 32 -Merge $true
        $merged.Written.Count | Should -Be $rows.Count
        $plainSet = @($rows | ForEach-Object { '{0}|{1}|{2}' -f $_.AssetName, $_.AssetId, $_.ConfigurationId } | Sort-Object)
        $gotSet = @($merged.Written | ForEach-Object { $o = $_.Substring($_.IndexOf('|') + 1) | ConvertFrom-Json; '{0}|{1}|{2}' -f $o.AssetName, $o.AssetId, $o.ConfigurationId } | Sort-Object)
        ($gotSet -join "`n") | Should -BeExactly ($plainSet -join "`n")
    }
}

Describe '2. the run''s measured budget: no fixed number, one budget for every worker of the run' {
    It 'starts at one request per worker; halves for every worker on any throttle (once per pause window); grows only after a quiet full round; a set ceiling holds' {
        $t0 = [datetime]::SpecifyKind([datetime]'2026-11-23T10:00:00', 'Utc')
        $s = Get-RAPartsRunBudgetNext -Budget $null -Event 'read' -Start 4 -Now $t0
        $s.Budget.Limit | Should -Be 4; $s.Changed | Should -BeTrue
        $b = $s.Budget
        $b = (Get-RAPartsRunBudgetNext -Budget $b -Event 'raise' -Now $t0.AddSeconds(10)).Budget
        $b.Limit | Should -Be 5 -Because 'never throttled: one more'
        $t = Get-RAPartsRunBudgetNext -Budget $b -Event 'throttle' -RetryAfterSec 40 -Now $t0.AddSeconds(20)
        $t.Budget.Limit | Should -Be 2; $t.Budget.PauseUntilUtc | Should -Be $t0.AddSeconds(60)
        $b = $t.Budget
        (Get-RAPartsRunBudgetNext -Budget $b -Event 'throttle' -RetryAfterSec 10 -Now $t0.AddSeconds(25)).Budget.Limit | Should -Be 2 -Because 'a second worker throttled in the same window: the budget is halved once'
        (Get-RAPartsRunBudgetNext -Budget $b -Event 'raise' -Now $t0.AddSeconds(70)).Budget.Limit | Should -Be 2 -Because 'not quiet long enough'
        (Get-RAPartsRunBudgetNext -Budget $b -Event 'raise' -Now $t0.AddSeconds(200)).Budget.Limit | Should -Be 3
        (Get-RAPartsRunBudgetNext -Budget @{ Limit = 6 } -Event 'raise' -Ceiling 6 -Now $t0).Budget.Limit | Should -Be 6 -Because 'a set SI_RA_PartsInParallel_Max is the ceiling'
        (Get-RAPartsRunBudgetNext -Budget @{ Limit = 1 } -Event 'throttle' -Now $t0).Budget.Limit | Should -Be 1 -Because 'never below one'
        Get-RAPartsBudgetCeiling -Setting $null | Should -Be 0
        Get-RAPartsBudgetCeiling -Setting '8' | Should -Be 8
        Get-RAPartsBudgetCeiling -Setting 'off' | Should -Be 1
    }
    It 'the share is weighted by the slices each running report still has to ask -- a worker with nothing queued gives its share to the CVE report' {
        $now = [datetime]::UtcNow
        $claims = @(@{ Item = 1; Remaining = 400; UpdatedUtc = $now.ToString('o') }, @{ Item = 2; Remaining = 20; UpdatedUtc = $now.ToString('o') })
        # the CVE report (item 1, 400 slices left) and a small report (item 2, 20 left) share a budget of 12
        Get-RAPartsWeightedShare -Limit 12 -Mine 400 -Claims $claims -Item 1 -Now $now | Should -Be 11
        Get-RAPartsWeightedShare -Limit 12 -Mine 20 -Claims $claims -Item 2 -Now $now | Should -Be 1
        # the small report is done (its claim gives back: nothing left) -- the CVE report gets the whole budget
        $claims[1].Remaining = 0
        Get-RAPartsWeightedShare -Limit 12 -Mine 400 -Claims $claims -Item 1 -Now $now | Should -Be 12
        # a claim not renewed (a worker that died) holds nothing; the process bound holds
        $old = @(@{ Item = 3; Remaining = 900; UpdatedUtc = $now.AddMinutes(-30).ToString('o') })
        Get-RAPartsWeightedShare -Limit 12 -Mine 10 -Claims $old -Item 1 -Now $now | Should -Be 12
        Get-RAPartsWeightedShare -Limit 40 -Mine 10 -Item 1 -Now $now -Bound 8 | Should -Be 8
    }
    It 'one budget in the run''s storage: two workers read it, a throttle at one halves both, the end of a report gives its claim back' {
        $blobs = @{}
        $store = [pscustomobject]@{
            Read = { param($Path) $blobs[$Path] }.GetNewClosure()
            Write = { param($Path, $Text) $blobs[$Path] = [string]$Text }.GetNewClosure()
            List = { param($Prefix) @($blobs.Keys | Where-Object { ([string]$_).StartsWith($Prefix) }) }.GetNewClosure()
        }
        $now = [datetime]::UtcNow
        $a = Sync-RAPartsRunBudget -Store $store -Engine 'ra-detailed' -RunId 'r1' -Item 1 -Remaining 300 -Start 4 -Now $now
        $b = Sync-RAPartsRunBudget -Store $store -Engine 'ra-detailed' -RunId 'r1' -Item 2 -Remaining 100 -Start 4 -Now $now
        $a.Limit | Should -Be 4; $b.Limit | Should -Be 4
        $b.Share | Should -Be 1 -Because '100 of 400 slices left: a quarter of 4'
        $blobs.Keys | Should -Contain 'collect/ra-detailed/r1/budget/run.json'
        $t = Sync-RAPartsRunBudget -Store $store -Engine 'ra-detailed' -RunId 'r1' -Item 2 -Remaining 90 -Event 'throttle' -RetryAfterSec 30 -Start 4 -Now $now.AddSeconds(5)
        $t.Limit | Should -Be 2
        $a2 = Sync-RAPartsRunBudget -Store $store -Engine 'ra-detailed' -RunId 'r1' -Item 1 -Remaining 290 -Start 4 -Now $now.AddSeconds(6)
        $a2.Limit | Should -Be 2 -Because 'the other worker''s throttle is this worker''s too'
        $a2.PauseUntilUtc | Should -BeGreaterThan $now.AddSeconds(30)
        $null = Sync-RAPartsRunBudget -Store $store -Engine 'ra-detailed' -RunId 'r1' -Item 2 -Event 'release' -Start 4 -Now $now.AddSeconds(7)
        (Sync-RAPartsRunBudget -Store $store -Engine 'ra-detailed' -RunId 'r1' -Item 1 -Remaining 280 -Start 4 -Now $now.AddSeconds(8)).Share | Should -Be 2 -Because 'the other report is done: the whole budget'
        # a store that cannot be read: $null -- the caller keeps the static share
        $bad = [pscustomobject]@{ Read = { throw 'not reachable' }; Write = { }; List = { @() } }
        Sync-RAPartsRunBudget -Store $bad -Engine 'ra-detailed' -RunId 'r1' -Item 1 -Remaining 1 | Should -BeNullOrEmpty
    }
    It 'a worker applies its share: at the report''s start, at once on a throttle (every worker''s pause), and gives its claim back when the report ends' {
        $old = @{ R = $global:SI_RA_ScaleOutRole; M = $global:SI_RA_PartsInParallel_Max; W = [Environment]::GetEnvironmentVariable('SI_RA_WORKERS') }
        $script:Probe = New-Object System.Collections.Generic.List[string]
        $script:ProbeShare = 6
        try {
            $global:SI_RA_ScaleOutRole = 'worker'; $global:SI_RA_PartsInParallel_Max = $null; [Environment]::SetEnvironmentVariable('SI_RA_WORKERS', '4')
            $script:RAPartsBudgetProbe = { param($Event, $Remaining, $RetryAfterSec) $script:Probe.Add(('{0}:{1}:{2}' -f $Event, $Remaining, $RetryAfterSec)); @{ Share = $script:ProbeShare; Limit = 12; PauseUntilUtc = [datetime]::MinValue } }
            Reset-RAPartsInParallel -PartCount 40
            $script:RAParts.On | Should -BeTrue
            $script:RAParts.Max | Should -Be 6 -Because 'the run''s budget, read at the report''s start'
            $script:Probe[0] | Should -Be 'read:40:0'
            # a throttle: told at once, with its pause
            $script:RAParts.RunEvent = 'throttle'; $script:RAParts.RunRetryAfter = 45; $script:ProbeShare = 3
            Update-RAPartsRunShare | Should -BeTrue
            $script:Probe[-1] | Should -Be 'throttle:40:45'
            $script:RAParts.Max | Should -Be 3
            $script:RAParts.RunEvent | Should -BeNullOrEmpty
            # within the interval: no read
            $n = $script:Probe.Count; $null = Update-RAPartsRunShare; $script:Probe.Count | Should -Be $n
            Stop-RAPartsInParallel
            $script:Probe[-1] | Should -Match '^release:'
            # a probe that cannot tell: the static share, as before
            $script:RAPartsBudgetProbe = { param($Event, $Remaining, $RetryAfterSec) $null }
            Reset-RAPartsInParallel -PartCount 40
            $script:RAParts.Max | Should -Be ([Math]::Max(1, [Math]::Floor((Get-RAPartsInParallelMax) / 4)))
            Stop-RAPartsInParallel
        } finally {
            $script:RAPartsBudgetProbe = $null
            $global:SI_RA_ScaleOutRole = $old.R; $global:SI_RA_PartsInParallel_Max = $old.M; [Environment]::SetEnvironmentVariable('SI_RA_WORKERS', $old.W)
        }
    }
    It 'a full round of quick answers at the share asks the run for more (AtMax); a throttle asks it to slow down' {
        $s = Get-RAPartsInParallelStep -N 3 -Max 3 -Clean 2 -Status 200 -WaitedSec 2 -Seconds 10
        $s.AtMax | Should -BeTrue; $s.N | Should -Be 3; $s.Clean | Should -Be 0
        (Get-RAPartsInParallelStep -N 2 -Max 3 -Clean 1 -Status 200 -WaitedSec 2 -Seconds 10).N | Should -Be 3 -Because 'below the share: the count climbs as before'
    }
}

Describe 'the engine''s wiring' {
    BeforeAll {
        $raw = [regex]::Replace($script:EngineSrc, '(?s)<#.*?#>', '')
        $script:Code = (($raw -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    }
    It 'the main loop: the plan per pass, a slice already in writes its held rows under its own name, the request decides the filter and the slice coordinates' {
        $c = $script:Code
        $c | Should -Match ([regex]::Escape('$script:RASliceMerge = New-RASliceMerge -Count ([int]$bucketCountToUse) -From $__soFrom -To $__soTo -RowLimit $__mgRows -SecondsLimit $__mgSec -On $__mgOn'))
        $c | Should -Match ([regex]::Escape('if (Test-RASliceCovered -Merge $__mg -Slice $b) {'))
        $c | Should -Match ([regex]::Escape("Add-RAStreamBucketGuarded -Rows `$__mgRows -Bucket ('{0}/{1}' -f `$bucketNo, `$bucketCountToUse)"))
        $c | Should -Match ([regex]::Escape('$__mgReq = Get-RASliceRequest -Merge $__mg -Slice $b'))
        $c | Should -Match ([regex]::Escape('$bucketFilter = New-BucketFilterKql -BucketCount $__mgCount -BucketIndex $__mgIndex -ReportName $ReportName'))
        $c | Should -Match ([regex]::Escape('$script:_CurrentBucketCount = $__mgCount'))
        # the covered check comes before the request; the request before the hunting call
        $c.IndexOf('Test-RASliceCovered -Merge $__mg -Slice $b') | Should -BeLessThan $c.IndexOf('$__mgReq = Get-RASliceRequest -Merge $__mg -Slice $b')
        $c.IndexOf('$__mgReq = Get-RASliceRequest -Merge $__mg -Slice $b') | Should -BeLessThan $c.IndexOf('$resp = Invoke-GraphHuntingQuery -Query $thisQuery -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries $global:GraphQueryMaxRetries')
    }
    It 'a merged request that fails is never classified: the catch asks the slice again as its own slice first' {
        $c = $script:Code
        $catch = $c.IndexOf('if (@($__mgReq.Covers).Count -gt 0) {', $c.IndexOf('$resp = Invoke-GraphHuntingQuery -Query $thisQuery'))
        $catch | Should -BeGreaterThan 0
        $catch | Should -BeLessThan $c.IndexOf('$errMsg = Get-SIKqlErrorSummary -ErrorRecord $_', $c.IndexOf('$resp = Invoke-GraphHuntingQuery -Query $thisQuery'))
        $c | Should -Match ([regex]::Escape("`$__mgReq = Stop-RASliceMerge -Merge `$__mg -Slice `$b -Why 'a request that held several parts failed'"))
    }
    It 'a merged answer is placed per slice before it is stored; every failure after the answer gives the partners back; the measure is per slice' {
        $c = $script:Code
        $c | Should -Match ([regex]::Escape('$__mgSplit = Split-RASliceRows -Rows @($bucketResult) -Count ([int]$bucketCountToUse) -Slice $b -Covers @($__mgReq.Covers)'))
        $c.IndexOf('Split-RASliceRows -Rows @($bucketResult)') | Should -BeLessThan $c.IndexOf('$__slIn = Add-RAStreamBucketGuarded -Rows $bucketResult -Bucket (''{0}/{1}'' -f $bucketNo, $bucketCountToUse)')
        ([regex]::Matches($c, 'Stop-RASliceMerge -Merge \$__mg -Why')).Count | Should -BeGreaterOrEqual 4 -Because 'an answer that cannot be converted, a store out of memory (a slice''s own rows, a partner''s held rows), unplaced rows'
        ([regex]::Matches($c, 'Complete-RASliceRequest -Merge \$__mg -Slice \$b')).Count | Should -Be 4 -Because 'the two empty answers, a merged answer, a plain answer'
        $c | Should -Match ([regex]::Escape('[long][Math]::Ceiling([double]$bucketCount / $__mgWidth)'))
        $c | Should -Match ([regex]::Escape('$__mgLine = Format-RASliceMergeLine -Merge $__mg'))
    }
    It 'the queue worker keeps the run''s measured budget in the run''s storage (not the producer''s own worker in its container)' {
        $c = $script:Code
        $c | Should -Match ([regex]::Escape("if (([string][Environment]::GetEnvironmentVariable('SI_RA_SCALEOUT_LOCAL')).Trim() -ne '1') {"))
        $c | Should -Match ([regex]::Escape('$script:RAPartsBudgetProbe = {'))
        $c | Should -Match ([regex]::Escape('Sync-RAPartsRunBudget -Store $script:RAScaleStore -Engine ([string]$script:RAScaleManifest[''Engine'']) -RunId ([string]$script:RAScaleRunId) -Item ([int]$script:RAScaleItem.Payload.Item)'))
        $c | Should -Match ([regex]::Escape('-Start $__bw -Ceiling (Get-RAPartsBudgetCeiling) -Bound (Get-RAPartsInParallelMax -Setting $null)'))
    }
}
