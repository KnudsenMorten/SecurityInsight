#Requires -Version 5.1
<#
    #742 -- THE SAME TENANT THROUGH ONE JOB AND THROUGH A PRODUCER + 2 / 4 QUEUE WORKERS GIVES THE SAME RESULT.

    A generated tenant (several Detailed reports: assets x findings, a finding two buckets both return, two assets that share
    a name, equal scores across reports) runs the report loop's stream path (engine/risk-analysis/_shared/RA-SqlStream.ps1:
    per bucket scored, traced and written; the report finished in SQL; its verdict stored):
      ONE JOB      the reports one after another in one stream (the collection begun by the run);
      SCALE-OUT    the producer begins the collection, plans the items and queues them (RA-ScaleOut.ps1); 2 or 4 workers,
                   each in its OWN runspace with its own database connection, take items from the queue AT THE SAME TIME,
                   attach to the collection, run the report with the producer's ordinal and write base and hand it over
                   (a worker NEVER posts to Log Analytics); the producer merges the hand-overs and posts the whole run ONCE
                   from SQL, through the engine's own paged post (Invoke-RALaPagedPost over New-RARowPager -Source All).
    What is kept true, against SQL Server Express (skipped, saying so, without one):
      * identical rows per report (every stored column but the database's own id and the write number), identical verdicts,
        identical ordinals, and the identical final order (score, then the single job's write order);
      * a worker that DIES half-way through a report (one bucket written, the item not finished): the item comes back to the
        queue, another worker runs it -- no row twice, the result identical;
      * an item that kills its worker every time is parked and marked FAILED: that report is NOT COMPLETE with the cause, and
        what its attempts wrote is removed;
      * Log Analytics: what the producer posts after the workers (one of them killed MID-REPORT, its report run again) is
        row for row, in order, what the one job posts -- every row once, none twice.
    THE MEASUREMENT (tag Scale -- on demand only, never in a gate): 100,000 rows, one worker against four, wall time.
#>

$script:HasSql = [bool](Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')
$script:HasSql = $script:HasSql -and (Test-Path -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'sql', 'si-data-schema.sql')))
$script:HasSql = $script:HasSql -and (Test-Path -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'sql', 'si-identity-schema.sql')))

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    # EVERYTHING a worker runs, as text: loaded here and in every worker's runspace (each loads what it calls in ITS scope)
    $script:LibText = @'
param([string]$SIRoot)
function Write-Info { param($m) }
function Write-Warn2 { param($m) }
function Write-Ok { param($m) }
function Write-Diag { param($m) }
$ProgressPreference = 'SilentlyContinue'
$ra = Join-Path $SIRoot 'engine\risk-analysis\_shared'
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ra 'RA-ExcelReport.ps1'), [ref]$null, [ref]$null)
. ([scriptblock]::Create(($ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'New-RiskIndex' }, $true)).Extent.Text))
foreach ($f in 'RA-RiskIndexOrder.ps1', 'RA-RiskIndexSi.ps1', 'RA-FactorKeys.ps1', 'RA-CiContext.ps1', 'RA-RiskScore.ps1', 'RA-RowShaping.ps1', 'RA-SummaryBucketMerge.ps1',
               'RA-Findings.ps1', 'RA-ColumnFillGuard.ps1', 'RA-SqlStream.ps1', 'RA-ScaleOut.ps1', 'RA-Delivery.ps1') { . (Join-Path $ra $f) }
foreach ($f in 'engine\_shared\data-sql\SI-DataModel.ps1', 'engine\_shared\data-sql\SI-DataSql.ps1', 'engine\_shared\data-sql\SI-DataSummary.ps1', 'engine\asset-trend\_shared\SI-TrendRollup.ps1') { . (Join-Path $SIRoot $f) }
$global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null; $global:RA_FactorCatalog = $null
$script:Index = New-RiskIndex -CsvRows @(Import-Csv -LiteralPath (Join-Path $SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
$script:Tiers = @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3')
$script:CT = [datetime]::SpecifyKind([datetime]'2026-10-17T06:00:00', 'Utc')
function New-Seam([string]$Db) {
    $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=.\SQLEXPRESS;Database=$Db;Integrated Security=SSPI;Connection Timeout=30;Pooling=false")
    $cn.Open()
    $c = $cn
    { param($Sql, $Params, $Mode)
      $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql; $cmd.CommandTimeout = 300
      if ($Params) { foreach ($k in $Params.Keys) { $v = $Params[$k]; [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $v) { [System.DBNull]::Value } else { $v })) } }
      switch ($Mode) {
          { $_ -in 'reader', 'rows' } { $rd = $cmd.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
              try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $out.Add($h) } } finally { $rd.Close() }
              , $out.ToArray() }
          'scalar' { $cmd.ExecuteScalar() }
          default { [void]$cmd.ExecuteNonQuery() }
      } }.GetNewClosure()
}
# the generated tenant: report $r has $Assets assets x $Findings findings; asset 7 and 23 share a name; one finding of every
# report comes back from a second bucket (a duplicate the run keeps once); scores repeat across reports (ties)
function New-TenantRows([int]$Report, [int]$Assets = 40, [int]$Findings = 3) {
    $out = New-Object System.Collections.Generic.List[object]
    for ($a = 0; $a -lt $Assets; $a++) {
        $name = if ($a -eq 7 -or $a -eq 23) { 'shared-name' } else { "host$a" }
        for ($c = 0; $c -lt $Findings; $c++) {
            $out.Add([pscustomobject][ordered]@{ SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs'; ConfigurationName = ('CVE-2026-{0}{1}' -f $Report, $c)
                ConfigurationId = ('CVE-2026-{0}{1}' -f $Report, $c); SecuritySeverity = @('High', 'Medium', 'Low')[$c % 3]; CriticalityTier = ($a % 4); CriticalityTierLevel = $script:Tiers[$a % 4]
                AssetName = $name; SI_AssetId = "aid-$a"; MdeDeviceId = "dev-$a"; DeviceKey = "dev-$a"
                RiskFactor_Probability_Detailed = ''; RiskFactor_Consequence_Detailed = ''; LastSeen = [datetime]::SpecifyKind([datetime]'2026-10-12T10:00:00', 'Utc') })
        }
    }
    $dup = $out[4].PSObject.Copy(); $dup.DeviceKey = 'dup-of-4'; $out.Add($dup)
    $out.ToArray()
}
function Split-Buckets([object[]]$Rows, [int]$N) {
    $b = @{}; for ($i = 0; $i -lt $N; $i++) { $b[$i] = New-Object System.Collections.Generic.List[object] }
    foreach ($r in $Rows) {
        $k = [string]$r.DeviceKey; $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($k.ToLowerInvariant())) } finally { $sha.Dispose() }
        $b[[int]([BitConverter]::ToUInt32($h, 0) % $N)].Add($r)
    }
    $b
}
# the slices a report is asked in: Gen3 is the run's BIG report (#831 B: the one split into parts)
function Get-TestBuckets([string]$Name) { if ($Name -eq 'Gen3_Detailed') { 16 } else { 4 } }
# ONE REPORT through the report loop's stream path: per bucket scored, traced, written; then finished in SQL and its verdict
# stored. -Ordinal / -SeqBase: a queue worker's numbering. -CrashAfter: the process "dies" after that many buckets.
function Invoke-TestReport($Stream, [string]$Name, [int]$Report, [int]$Buckets = 4, [int]$Ordinal = 0, [long]$SeqBase = -1, [int]$CrashAfter = -1, [int]$Assets = 40, [int]$LatencyMs = 0) {
    $extra = @{}; if ($Ordinal -gt 0) { $extra = @{ Ordinal = $Ordinal; SeqBase = $SeqBase } }
    $null = Start-RAStreamReport -Stream $Stream -ReportName $Name -Staged $false @extra
    $rows = @(New-TenantRows -Report $Report -Assets $Assets)
    $bk = Split-Buckets -Rows $rows -N $Buckets
    for ($i = 0; $i -lt $Buckets; $i++) {
        if ($CrashAfter -ge 0 -and $i -ge $CrashAfter) { throw 'the worker died' }
        if ($LatencyMs -gt 0) { Start-Sleep -Milliseconds $LatencyMs }      # the hunting query's own time
        if ($bk[$i].Count -eq 0) { continue }
        $sc = @(Calculate-RiskScore -Rows @($bk[$i].ToArray()) -RiskIndex $script:Index -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
                    -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -ReportName $Name)
        foreach ($r in $sc) { Add-Member -InputObject $r -NotePropertyName CollectionTime -NotePropertyValue $script:CT -Force; Add-Member -InputObject $r -NotePropertyName SolutionVersion -NotePropertyValue '3.0.0+v3' -Force }
        Set-RATraceIdentity -Rows $sc -IsDetailed $true
        Add-RAStreamColumns -Stream $Stream -Columns @($sc[0].PSObject.Properties.Name)
        $null = Write-RAStreamRows -Stream $Stream -Rows $sc -Bucket ('{0}/{1}' -f ($i + 1), $Buckets) -IsDetailedShape $true
        $Stream.Current.Retrieved += $bk[$i].Count
    }
    $fin = Complete-RAStreamReport -Stream $Stream
    Set-RAStreamReportStatus -Stream $Stream -ReportName $Name -Expected $rows.Count -Retrieved $Stream.Current.Retrieved -Stored $fin.Stored -State Complete
    $fin
}
# #831 B: ONE PART of a split report as the report loop runs it: its own write bands and own-row removal, its slices
# [From, To) of the report's count, its partial; the LAST part takes every partial and finishes the report in SQL exactly as
# the one job does (the findings two slices returned kept once, the shared trace names, the count, the verdict).
function Invoke-TestPart($Stream, $Store, $Payload, [int[]]$Siblings, [hashtable]$State, [hashtable]$Mark, [int]$CrashAfter = -1, [int]$Assets = 40) {
    $name = [string]$Payload.Report; $ord = [int]$Payload.Ordinal; $part = [int]$Payload.Part; $parts = [int]$Payload.Parts; $n = [int]$Payload.Buckets
    $eng = [string]$Payload.Engine; $run = [string]$Payload.RunId; $item = [int]$Payload.Item
    $own = @(Get-RAScaleOutSplitSeqRanges -Ordinal $ord -Part $part -Parts $parts)
    $already = $null -ne (Read-RAScaleOutPartial -Store $Store -Engine $eng -RunId $run -Item $item)
    $null = Start-RAStreamReport -Stream $Stream -ReportName $name -Staged $false -Ordinal $ord -SeqBase (Get-RAScaleOutSplitSeqBase -Ordinal $ord -Part $part -Parts $parts -Band main) -OwnSeq $own -KeepRows:$already
    $rows = @(New-TenantRows -Report ([int]($name -replace '\D', '')) -Assets $Assets)
    if (-not $already) {
        $bk = Split-Buckets -Rows $rows -N $n
        for ($i = [int]$Payload.From; $i -lt [int]$Payload.To; $i++) {
            if ($CrashAfter -ge 0 -and ($i - [int]$Payload.From) -ge $CrashAfter) { throw 'the worker died' }
            if ($bk[$i].Count -eq 0) { continue }
            $sc = @(Calculate-RiskScore -Rows @($bk[$i].ToArray()) -RiskIndex $script:Index -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
                        -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -ReportName $name)
            foreach ($x in $sc) { Add-Member -InputObject $x -NotePropertyName CollectionTime -NotePropertyValue $script:CT -Force; Add-Member -InputObject $x -NotePropertyName SolutionVersion -NotePropertyValue '3.0.0+v3' -Force }
            Set-RATraceIdentity -Rows $sc -IsDetailed $true
            Add-RAStreamColumns -Stream $Stream -Columns @($sc[0].PSObject.Properties.Name)
            $null = Write-RAStreamRows -Stream $Stream -Rows $sc -Bucket ('{0}/{1}' -f ($i + 1), $n) -IsDetailedShape $true
            $Stream.Current.Retrieved += $bk[$i].Count
        }
        $p = New-RAScaleOutPartial -State $State -Mark $Mark -Report $name -Item $item -Part $part -Parts $parts -Entry $Stream.Current -Evidence @{ Measure = $null }
        Write-RAScaleOutPartial -Store $Store -Engine $eng -RunId $run -Partial $p
    }
    $req = Request-RAScaleOutFinish -Store $Store -Engine $eng -RunId $run -Ordinal $ord -Item $item -Siblings $Siblings
    if (-not $req.Finisher) { return 'part' }
    $m = Merge-RAScaleOutPartials -Partials $req.Partials
    $Stream.Current.OwnSeq = $null
    $Stream.Current.Retrieved = [long]$m.Retrieved
    $Stream.Current.Columns.Clear(); $Stream.Current.ColSet.Clear(); foreach ($c in @($m.Columns)) { if ($Stream.Current.ColSet.Add([string]$c)) { $Stream.Current.Columns.Add([string]$c) } }
    $fin = Complete-RAStreamReport -Stream $Stream
    Set-RAStreamReportStatus -Stream $Stream -ReportName $name -Expected $rows.Count -Retrieved $Stream.Current.Retrieved -Stored $fin.Stored -State Complete
    'finished'
}
# WHAT LOG ANALYTICS RECEIVES from a stream: the engine's own post (Invoke-RALaPagedPost over New-RARowPager -Source All -- the
# pager and the chunked post the run uses) with a fake service that keeps every row it is given, as JSON, in order
function Get-TestLaPosts($Stream) {
    $sent = New-Object System.Collections.Generic.List[string]
    $d = Invoke-RALaPagedPost -Pager (New-RARowPager -Stream $Stream -Source All) -Prepare { param($c) @{ Rows = @($c); Align = $null } } `
            -Post { param($rows) foreach ($r in @($rows)) { $sent.Add((ConvertTo-Json -InputObject $r -Compress -Depth 6)) }; [pscustomobject]@{ RowsPosted = @($rows).Count; BytesPosted = 0 } }.GetNewClosure()
    [pscustomobject]@{ Rows = $sent.ToArray(); Posted = [long]$d.RowsPosted }
}
# THE STATE STORE the producer and the workers share: ONE synchronized hashtable (-Docs), with the store's Read / Write /
# List / Claim / Remove made IN THE RUNSPACE THAT CALLS THEM. HARNESS RACE FIXED (2026-10-25, #873 B review): the store's
# script blocks used to be made once in the test's main runspace and handed to every worker runspace. A script block is
# bound to the runspace that made it: a worker calling it ran it against the MAIN runspace's variables, from the worker's
# thread, while the main thread (Pester) used that runspace too -- the closure's $docs then read back as null now and then
# ("Exception calling Enter ... Value cannot be null", 4 workers) or the main runspace's state was corrupted ("Source
# array was not long enough", the suite wrote no result). Every worker now makes its own closures over the same table;
# what they read and write is unchanged, under the same lock.
function New-TestStore($Docs) {
    $docs = $Docs
    [pscustomobject]@{ Docs = $docs
        Read = { param($x) if ($docs.ContainsKey($x)) { $docs[$x] } else { $null } }.GetNewClosure()
        Write = { param($x, $t) [System.Threading.Monitor]::Enter($docs.SyncRoot); try { $docs[$x] = $t } finally { [System.Threading.Monitor]::Exit($docs.SyncRoot) } }.GetNewClosure()
        List = { param($pre) [System.Threading.Monitor]::Enter($docs.SyncRoot); try { $ks = @($docs.Keys) } finally { [System.Threading.Monitor]::Exit($docs.SyncRoot) }; @($ks | Where-Object { $_.StartsWith($pre) } | Sort-Object) }.GetNewClosure()
        Claim = { param($x, $t) [System.Threading.Monitor]::Enter($docs.SyncRoot); try { if ($docs.ContainsKey($x)) { $false } else { $docs[$x] = $t; $true } } finally { [System.Threading.Monitor]::Exit($docs.SyncRoot) } }.GetNewClosure()
        Remove = { param($x) [System.Threading.Monitor]::Enter($docs.SyncRoot); try { [void]$docs.Remove($x) } finally { [System.Threading.Monitor]::Exit($docs.SyncRoot) } }.GetNewClosure() }
}
# A QUEUE WORKER: takes items until none is left (the queue is shared in memory: a lock around each take / finish),
# runs each report and hands it over -- it never posts to Log Analytics (the producer posts the run once, from SQL)
function Invoke-TestWorker([string]$Db, $Ctx, [string]$Queue, $Store, $Lock, [string]$Worker, [hashtable]$Crash = @{}, [int]$Assets = 40, [int]$LatencyMs = 0, [int]$MaxDequeue = 3) {
    # the store's closures made HERE, in this worker's runspace, over the shared table (New-TestStore: the harness race)
    if ($null -ne $Store -and $Store.PSObject.Properties['Docs'] -and $null -ne $Store.Docs) { $Store = New-TestStore -Docs $Store.Docs }
    if ($null -eq $Lock) { throw 'the harness handed this worker no queue lock' }
    $seam = New-Seam -Db $Db
    $stream = $null; $done = 0
    while ($true) {
        [System.Threading.Monitor]::Enter($Lock)
        try { $r = Receive-RAScaleOutItem -Context $Ctx -QueueName $Queue -Store $Store -NoBeat -Worker $Worker -MaxDequeue $MaxDequeue -Log { param($l, $t) } } finally { [System.Threading.Monitor]::Exit($Lock) }
        if ($r.Kind -ne 'item') { break }
        $m = $r.Manifest
        if ($null -eq $stream) { $stream = New-RAStream -Invoke $seam -Grain Detailed -CollectionTime $script:CT -Log { param($l, $t) } -AttachCollectionId ([int]$m['CollectionId']) }
        $state = @{ RowCounts = @{}; ColumnFill = @{}; StatusDone = @{}; Notes = @{}; QueryHash = @{}; Retries = @{}; EmptyGivers = @{}; DfcCompare = @{}
                    KqlTypes = (New-Object 'System.Collections.Generic.Dictionary[string,string]'); Stream = $stream
                    Failures = (New-Object System.Collections.Generic.List[object]); BucketLossRun = (New-Object System.Collections.Generic.List[string]); Jumps = (New-Object System.Collections.Generic.List[object])
                    Attempted = (New-Object System.Collections.Generic.List[string]); PublishFailures = (New-Object System.Collections.Generic.List[string]); IngestRefused = (New-Object System.Collections.Generic.List[string])
                    NotDelivered = (New-Object System.Collections.Generic.List[string]); IngestNotes = (New-Object System.Collections.Generic.List[object]) }
        $mark = Start-RAScaleOutItemState -State $state
        $name = [string]$r.Payload.Report; $ord = [int]$r.Payload.Ordinal
        $state.Attempted.Add($name)
        $crashAfter = -1; if ($Crash.ContainsKey($name)) { $crashAfter = [int]$Crash[$name] }
        # #831 B: ONE PART of a split report -- its slices, its partial; the last part puts the report together
        if ($null -ne $r.Payload.Parts -and [int]$r.Payload.Parts -gt 1) {
            $pk = '{0}#{1}' -f $name, [int]$r.Payload.Part; $pc = -1; if ($Crash.ContainsKey($pk)) { $pc = [int]$Crash[$pk] }
            $sib = @(Get-RAScaleOutSiblings -Manifest $m -Report $name | ForEach-Object { [int]$_['Item'] })
            try { $res = Invoke-TestPart -Stream $stream -Store $Store -Payload $r.Payload -Siblings $sib -State $state -Mark $mark -CrashAfter $pc -Assets $Assets }
            catch { if ([string]$_.Exception.Message -eq 'the worker died') { return [pscustomobject]@{ Worker = $Worker; Done = $done; Died = $pk } }; throw }
            $full = ($res -eq 'finished'); $reps = @(); if ($full) { $reps = @($name) }
            if ($full) { $state.RowCounts[$name] = [int]$stream.Current.Retrieved; $state.StatusDone[$name] = 'Complete' }
            $stored = [long](Get-RAStreamReportCounts -Stream $stream)[$ord]
            $h = New-RAScaleOutHandover -State $state -Mark $mark -Reports $reps -Item ([int]$r.Payload.Item) -FinalDesiredColumns @($stream.Reports[$name].Columns) -Worker $Worker -NoLists:(-not $full)
            Write-RAScaleOutItemResult -Store $Store -Engine ([string]$r.Payload.Engine) -RunId ([string]$r.Payload.RunId) -Item ([int]$r.Payload.Item) -Handover $h -State done -Rows $stored -Worker $Worker
            [System.Threading.Monitor]::Enter($Lock)
            try { $null = Complete-RAScaleOutItem -Context $Ctx -QueueName $Queue -Received $r } finally { [System.Threading.Monitor]::Exit($Lock) }
            $done++
            continue
        }
        try { $fin = Invoke-TestReport -Stream $stream -Name $name -Report ([int]($name -replace '\D', '')) -Buckets (Get-TestBuckets $name) -Ordinal $ord -SeqBase (Get-RAScaleOutSeqBase -Ordinal $ord) -CrashAfter $crashAfter -Assets $Assets -LatencyMs $LatencyMs }
        catch { if ([string]$_.Exception.Message -eq 'the worker died') { return [pscustomobject]@{ Worker = $Worker; Done = $done; Died = $name } }; throw }
        $state.RowCounts[$name] = [int]$fin.Stored; $state.StatusDone[$name] = 'Complete'
        $stored = [long](Get-RAStreamReportCounts -Stream $stream)[$ord]
        $h = New-RAScaleOutHandover -State $state -Mark $mark -Reports @($name) -Item ([int]$r.Payload.Item) -FinalDesiredColumns @($stream.Reports[$name].Columns) -Worker $Worker
        Write-RAScaleOutItemResult -Store $Store -Engine ([string]$r.Payload.Engine) -RunId ([string]$r.Payload.RunId) -Item ([int]$r.Payload.Item) -Handover $h -State done -Rows $stored -Worker $Worker
        [System.Threading.Monitor]::Enter($Lock)
        try { $null = Complete-RAScaleOutItem -Context $Ctx -QueueName $Queue -Received $r } finally { [System.Threading.Monitor]::Exit($Lock) }
        $done++
    }
    [pscustomobject]@{ Worker = $Worker; Done = $done; Died = '' }
}
'@
    . ([scriptblock]::Create($script:LibText)) -SIRoot $script:SIRoot
    $script:Reports = @(1..6 | ForEach-Object { 'Gen{0}_Detailed' -f $_ })

    function script:New-Db([string]$Tag) {
        $name = 'si_test_raso_{0}_{1}' -f $Tag, [guid]::NewGuid().ToString('N').Substring(0, 6)
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$name]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=.\SQLEXPRESS;Database=$name;Integrated Security=SSPI;Connection Timeout=30;Pooling=false")
        $cn.Open(); try { foreach ($f in 'sql\si-data-schema.sql', 'sql\si-identity-schema.sql') { $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f)); [void]$c.ExecuteNonQuery() } } finally { $cn.Dispose() }
        $name
    }
    function script:Remove-Db([string]$Name) {
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$Name] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$Name]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    function script:Q([string]$Db, [string]$Sql) { $s = New-Seam -Db $Db; @(& $s $Sql @{} 'reader') | ForEach-Object { $_ } }
    # the ONE-JOB run -- in a fresh runspace, as the workers run: what earlier suites left in this session's globals must not
    # make the two sides score differently
    function script:Invoke-OneJob([string]$Db, [int]$Assets = 40, [int]$LatencyMs = 0) {
        $ps = [powershell]::Create()
        try {
            [void]$ps.AddScript($script:LibText).AddArgument($script:SIRoot)
            [void]$ps.AddScript('param($Db, $Reports, $Assets, $Lat) $s = New-RAStream -Invoke (New-Seam -Db $Db) -Grain Detailed -CollectionTime $script:CT -RunId ''one'' -Log { param($l, $t) }
                $i = 0; foreach ($n in $Reports) { $i++; $null = Invoke-TestReport -Stream $s -Name $n -Report $i -Buckets (Get-TestBuckets $n) -Assets $Assets -LatencyMs $Lat }
                [pscustomobject]@{ CollectionId = $s.CollectionId; La = $(if ($Assets -le 40) { Get-TestLaPosts -Stream $s } else { $null }) }', $true)
            foreach ($a in @($Db, $script:Reports, $Assets, $LatencyMs)) { [void]$ps.AddArgument($a) }
            $out = $ps.Invoke()
            if ($ps.Streams.Error.Count) { throw ('the one-job run failed: {0}' -f $ps.Streams.Error[0]) }
            $out | Select-Object -Last 1
        } finally { $ps.Dispose() }
    }
    # a worker run synchronously in a FRESH runspace (what earlier suites left in this session's globals stays out)
    function script:Invoke-FreshWorker([string]$Db, $Ctx, [string]$Queue, $Store, $Lock, [string]$Worker, [hashtable]$Crash = @{}, [int]$Assets = 40, [int]$LatencyMs = 0, [int]$MaxDequeue = 3) {
        $ps = [powershell]::Create()
        try {
            [void]$ps.AddScript($script:LibText).AddArgument($script:SIRoot)
            [void]$ps.AddScript('param($Db, $Ctx, $Q, $Store, $Lock, $W, $Crash, $Assets, $Lat, $Max) Invoke-TestWorker -Db $Db -Ctx $Ctx -Queue $Q -Store $Store -Lock $Lock -Worker $W -Crash $Crash -Assets $Assets -LatencyMs $Lat -MaxDequeue $Max', $true)
            foreach ($a in @($Db, $Ctx, $Queue, $Store, $Lock, $Worker, $Crash, $Assets, $LatencyMs, $MaxDequeue)) { [void]$ps.AddArgument($a) }
            $out = $ps.Invoke()
            if ($ps.Streams.Error.Count) { throw ('a worker failed: {0}' -f $ps.Streams.Error[0]) }
            $out | Select-Object -Last 1
        } finally { $ps.Dispose() }
    }
    # the SCALE-OUT run: the producer plans and queues; -Workers runspaces drain the queue at the same time
    # -SplitWorkers (#831 B): the worker count the producer plans for, with Gen3's 16 remembered slices (0 = no report split)
    function script:Invoke-ScaleOut([string]$Db, [int]$Workers, [hashtable]$Crash = @{}, [int]$Assets = 40, [int]$LatencyMs = 0, [int]$MaxDequeue = 3, [switch]$Sequential, [int]$SplitWorkers = 0) {
        $p = New-RAStream -Invoke (New-Seam -Db $Db) -Grain Detailed -CollectionTime $script:CT -RunId 'prod' -Log { param($l, $t) }
        $plan = @(New-RAScaleOutPlan -Workers $SplitWorkers -Reports @($script:Reports | ForEach-Object { [pscustomobject]@{ Name = $_; HasEntry = $true; Buckets = $(if ($_ -eq 'Gen3_Detailed') { 16 } else { 0 }); Splittable = $true } }))
        $man = New-RAScaleOutManifest -Grain Detailed -TimeText $p.TimeText -CollectionTime $script:CT -CollectionId $p.CollectionId -RunKey $p.RunKey -Items $plan
        $man['WrittenUtc'] = [datetime]::UtcNow.ToString('o')
        $docs = [hashtable]::Synchronized(@{})
        $store = New-TestStore -Docs $docs   # the producer's closures, in THIS runspace; each worker makes its own (the harness race)
        Write-RAScaleOutManifest -Store $store -Manifest $man
        $ctx = New-SIStorageContext -Mock; $q = Get-RAScaleOutQueueName -Grain Detailed
        $null = Publish-RAScaleOutItems -Manifest $man -Context $ctx -QueueName $q
        $lock = New-Object object
        $results = New-Object System.Collections.Generic.List[object]
        if ($Sequential) { for ($w = 1; $w -le $Workers; $w++) { $results.Add((Invoke-FreshWorker -Db $Db -Ctx $ctx -Queue $q -Store $store -Lock $lock -Worker "w$w" -Crash $Crash -Assets $Assets -LatencyMs $LatencyMs -MaxDequeue $MaxDequeue)) } }
        else {
            $runs = @()
            for ($w = 1; $w -le $Workers; $w++) {
                $ps = [powershell]::Create()
                [void]$ps.AddScript($script:LibText).AddArgument($script:SIRoot)
                [void]$ps.AddScript('param($Db, $Ctx, $Q, $Store, $Lock, $W, $Crash, $Assets, $Lat, $Max) Invoke-TestWorker -Db $Db -Ctx $Ctx -Queue $Q -Store $Store -Lock $Lock -Worker $W -Crash $Crash -Assets $Assets -LatencyMs $Lat -MaxDequeue $Max', $true)
                foreach ($a in @($Db, $ctx, $q, $store, $lock, "w$w", $Crash, $Assets, $LatencyMs, $MaxDequeue)) { [void]$ps.AddArgument($a) }
                $runs += @{ PS = $ps; H = $ps.BeginInvoke() }
            }
            foreach ($r in $runs) { foreach ($o in $r.PS.EndInvoke($r.H)) { $results.Add($o) }; if ($r.PS.Streams.Error.Count) { throw ('a worker failed: {0}' -f $r.PS.Streams.Error[0]) }; $r.PS.Dispose() }
        }
        [pscustomobject]@{ Stream = $p; Manifest = $man; Store = $store; Ctx = $ctx; Queue = $q; Lock = $lock; Plan = $plan; Results = $results.ToArray() }
    }
    # THE PRODUCER'S LOG ANALYTICS POST (Invoke-RAScaleOutProducerPass, then the run's post): the workers' stream entries taken
    # into the producer's stream as the engine takes them, then the engine's own paged post from SQL (Get-TestLaPosts)
    function script:Get-ProducerLaPosts($Run, $Merged) {
        foreach ($n in @($Merged.StreamReports.Keys)) {
            $e = $Merged.StreamReports[$n]
            $Run.Stream.Reports[[string]$n] = New-RAStreamReportEntry -Name ([string]$n) -Ordinal ([int]$e['Ordinal']) -Staged ([bool]$e['Staged']) -Columns @($e['Columns']) -DateCols @($e['DateCols']) `
                                                  -Retrieved ([long]$e['Retrieved']) -StageCols @($e['StageCols']) -Pages ([int]$e['Pages'])
        }
        Get-TestLaPosts -Stream $Run.Stream
    }
    # what a run stored, per report and in the final order -- every column but the database's own id and the write number
    function script:Get-Result([string]$Db) {
        $rows = @(Q $Db 'SELECT s.ReportName, f.RaReport, f.RaBucket, f.RaDedup, f.RaSort, f.RaInView, f.RaTraceHash, f.RaTraceKey, f.RaTraceSuffixed, f.RaFindingKey, f.RaAssetId, f.RaAssetTier, f.AssetKey, f.AssetName, f.ReportName AS FReport, f.ConfigurationId, f.Cve, f.Title, f.Severity, f.Tier, f.RiskScore, f.DetailJson FROM sidata.Finding f JOIN (SELECT DISTINCT RaReport, ReportName FROM (SELECT f2.RaReport, JSON_VALUE(f2.DetailJson, ''$.AssetDetectedInReportName'') AS ReportName FROM sidata.Finding f2) x) s ON s.RaReport = f.RaReport ORDER BY f.RaReport, f.RaSeq')
        $sig = { param($h) (@('RaReport', 'RaBucket', 'RaDedup', 'RaSort', 'RaInView', 'RaTraceHash', 'RaTraceKey', 'RaTraceSuffixed', 'RaFindingKey', 'RaAssetId', 'RaAssetTier', 'AssetKey', 'AssetName', 'FReport', 'ConfigurationId', 'Cve', 'Title', 'Severity', 'Tier', 'RiskScore', 'DetailJson') | ForEach-Object { $v = $h[$_]; if ($v -is [byte[]]) { [BitConverter]::ToString($v) } else { [string]$v } }) -join '|' }
        $per = [ordered]@{}; foreach ($r in $rows) { $k = [string]$r['RaReport']; if (-not $per.Contains($k)) { $per[$k] = New-Object System.Collections.Generic.List[string] }; $per[$k].Add((& $sig $r)) }
        $order = @(Q $Db 'SELECT DetailJson FROM sidata.Finding ORDER BY RaSort DESC, RaSeq' | ForEach-Object { [string]$_['DetailJson'] })
        $status = @(Q $Db 'SELECT ReportName, ExpectedRows, RetrievedRows, StoredRows, State FROM sidata.RaReportStatus ORDER BY ReportName' | ForEach-Object { '{0}|{1}|{2}|{3}|{4}' -f $_['ReportName'], $_['ExpectedRows'], $_['RetrievedRows'], $_['StoredRows'], $_['State'] })
        [pscustomobject]@{ Per = $per; Order = $order; Status = $status; Count = $rows.Count }
    }
}

Describe 'one job and a producer + workers give the same result (SQL Server)' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:DbOne = New-Db 'one'; $script:OneRun = Invoke-OneJob -Db $script:DbOne; $script:One = Get-Result $script:DbOne
        $script:Dbs = New-Object System.Collections.Generic.List[string]
    }
    AfterAll { if ($script:DbOne) { Remove-Db $script:DbOne }; foreach ($d in $script:Dbs) { try { Remove-Db $d } catch { } } }

    It 'the one-job run stored every report (the generated tenant is not empty)' {
        $script:One.Per.Count | Should -Be 6
        $script:One.Count | Should -BeGreaterThan 600
        @($script:One.Status | Where-Object { $_ -notmatch '\|Complete$' }).Count | Should -Be 0
    }
    It '<Workers> workers at the same time: identical rows per report, verdicts and final order; every report handed over and confirmed' -ForEach @(@{ Workers = 2 }, @{ Workers = 4 }) {
        $db = New-Db ("w{0}" -f $Workers); $script:Dbs.Add($db)
        $run = Invoke-ScaleOut -Db $db -Workers $Workers
        (@($run.Results | Measure-Object -Property Done -Sum).Sum) | Should -Be 6
        @($run.Results | Where-Object { $_.Done -gt 0 }).Count | Should -BeGreaterThan 1 -Because 'more than one worker took reports'
        $res = Get-Result $db
        foreach ($k in $script:One.Per.Keys) { ($res.Per[$k] -join "`n") | Should -Be ($script:One.Per[$k] -join "`n") -Because "report ordinal $k" }
        ($res.Order -join "`n") | Should -Be ($script:One.Order -join "`n")
        $res.Status | Should -Be $script:One.Status
        # the producer: every item marked, every hand-over read, merged
        $w = Wait-RAScaleOutItems -Store $run.Store -Manifest $run.Manifest -UseKeda $true -Sleep { } -Log { param($l, $t) }
        $w.State | Should -Be 'succeeded'
        $hv = Read-RAScaleOutHandovers -Store $run.Store -Manifest $run.Manifest
        $hv.Count | Should -Be 6
        @(Get-RAScaleOutItemFailures -Manifest $run.Manifest -Markers @($w.Markers) -Handovers $hv).Count | Should -Be 0
        $st = @{ RowCounts = @{}; StatusDone = @{}; Attempted = (New-Object System.Collections.Generic.List[string]); Failures = (New-Object System.Collections.Generic.List[object]) }
        $mg = Merge-RAScaleOutHandovers -State $st -Manifest $run.Manifest -Handovers $hv
        $st.Attempted.ToArray() | Should -Be $script:Reports -Because 'the run reads the reports in the single job''s order'
        # Log Analytics: the producer's one post from SQL is the one job's post, row for row
        $la = Get-ProducerLaPosts -Run $run -Merged $mg
        $la.Posted | Should -Be $script:OneRun.La.Posted
        ($la.Rows -join "`n") | Should -Be ($script:OneRun.La.Rows -join "`n")
    }
    It 'a worker that DIES half-way through a report: another runs it again -- no row twice, the result identical' {
        $db = New-Db 'crash'; $script:Dbs.Add($db)
        # worker 1 takes the first report, writes one bucket and dies (its item is not finished)
        $run = Invoke-ScaleOut -Db $db -Workers 1 -Sequential -Crash @{ 'Gen1_Detailed' = 1 }
        $run.Results[0].Died | Should -Be 'Gen1_Detailed'
        @(Q $db "SELECT COUNT(*) AS N FROM sidata.Finding WHERE RaReport = 1")[0]['N'] | Should -BeGreaterThan 0 -Because 'the dead attempt left a bucket behind'
        # its hold ends; two workers drain the queue
        $run.Ctx.MockState['Now'] = [datetime]::UtcNow.AddMinutes(11)
        $results = @(1, 2 | ForEach-Object { Invoke-FreshWorker -Db $db -Ctx $run.Ctx -Queue $run.Queue -Store $run.Store -Lock $run.Lock -Worker ("again$_") })
        ((@($results | Measure-Object -Property Done -Sum).Sum) + [int]$run.Results[0].Done) | Should -Be 6 -Because '#831: the queue hands out the largest report first, so the killed worker may have finished one before it died'
        $res = Get-Result $db
        foreach ($k in $script:One.Per.Keys) { ($res.Per[$k] -join "`n") | Should -Be ($script:One.Per[$k] -join "`n") -Because "report ordinal $k" }
        $res.Count | Should -Be $script:One.Count
        $res.Status | Should -Be $script:One.Status
        $script:CrashRun = $run
        $script:CrashDb = $db
    }
    It 'a worker KILLED MID-REPORT: Log Analytics gets exactly the one job''s rows -- every row once, none twice, the same order' {
        $script:CrashRun | Should -Not -BeNullOrEmpty -Because 'the test above ran the killed worker'
        # the workers posted nothing (the dead attempt's bucket was in SQL only, and is gone); the producer, after every item is
        # in, posts the run from SQL -- the engine's own paged post
        $w = Wait-RAScaleOutItems -Store $script:CrashRun.Store -Manifest $script:CrashRun.Manifest -UseKeda $true -Sleep { } -Log { param($l, $t) }
        $w.State | Should -Be 'succeeded'
        $mg = Merge-RAScaleOutHandovers -State @{ Attempted = (New-Object System.Collections.Generic.List[string]) } -Manifest $script:CrashRun.Manifest -Handovers (Read-RAScaleOutHandovers -Store $script:CrashRun.Store -Manifest $script:CrashRun.Manifest)
        $la = Get-ProducerLaPosts -Run $script:CrashRun -Merged $mg
        $script:OneRun.La.Posted | Should -BeGreaterThan 600
        $la.Posted | Should -Be $script:OneRun.La.Posted
        $la.Rows.Count | Should -Be $script:OneRun.La.Rows.Count
        @($la.Rows | Select-Object -Unique).Count | Should -Be @($script:OneRun.La.Rows | Select-Object -Unique).Count -Because 'no row twice'
        ($la.Rows -join "`n") | Should -Be ($script:OneRun.La.Rows -join "`n") -Because 'row for row, in the one job''s order'
        # the dead attempt's report: its rows are in the post exactly as often as in the one job's
        $g1 = { param($rows) @($rows | Where-Object { $_ -match '"AssetDetectedInReportName":"Gen1_Detailed"' }).Count }
        (& $g1 $la.Rows) | Should -Be (& $g1 $script:OneRun.La.Rows)
        (& $g1 $la.Rows) | Should -BeGreaterThan 0
    }
    It 'an item that kills its worker EVERY time is parked and FAILED: its report NOT COMPLETE with the cause, its rows removed' {
        $db = New-Db 'fail'; $script:Dbs.Add($db)
        $run = Invoke-ScaleOut -Db $db -Workers 1 -Sequential -Crash @{ 'Gen2_Detailed' = 2 } -MaxDequeue 2
        for ($i = 0; $i -lt 3; $i++) {
            $run.Ctx.MockState['Now'] = ([datetime]$(if ($run.Ctx.MockState['Now']) { $run.Ctx.MockState['Now'] } else { [datetime]::UtcNow })).AddMinutes(11)
            $null = Invoke-FreshWorker -Db $db -Ctx $run.Ctx -Queue $run.Queue -Store $run.Store -Lock $run.Lock -Worker "w$i" -Crash @{ 'Gen2_Detailed' = 2 } -MaxDequeue 2
        }
        $w = Wait-RAScaleOutItems -Store $run.Store -Manifest $run.Manifest -UseKeda $true -Sleep { } -Log { param($l, $t) }
        $w.State | Should -Be 'failed'
        $f = @(Get-RAScaleOutItemFailures -Manifest $run.Manifest -Markers @($w.Markers) -Handovers (Read-RAScaleOutHandovers -Store $run.Store -Manifest $run.Manifest))
        $f.Count | Should -Be 1; $f[0].Report | Should -Be 'Gen2_Detailed'; $f[0].Why | Should -Match 'its work item failed: its worker stopped 2 time\(s\)'
        # the producer: what its attempts wrote is removed, and the report's verdict is NOT COMPLETE with the cause (the end of the run)
        $null = Invoke-RAStreamSql -Stream $run.Stream -Sql (Get-RAStreamDeleteBucketSql -Grain Detailed) -Params @{ CollectionId = [string]$run.Stream.CollectionId; Report = '2'; Bucket = '*'; CollectionTime = $run.Stream.TimeText; RunKey = $run.Stream.RunKey }
        Set-RAStreamReportNotComplete -Stream $run.Stream -ReportName 'Gen2_Detailed' -Reason ('not complete: {0}' -f $f[0].Why)
        @(Q $db "SELECT COUNT(*) AS N FROM sidata.Finding WHERE RaReport = 2")[0]['N'] | Should -Be 0
        $s = @(Q $db "SELECT State, Reason FROM sidata.RaReportStatus WHERE ReportName = 'Gen2_Detailed'")
        ([string]$s[0]['State'], [string]$s[0]['Reason']) | Should -Be @('NotComplete', ('not complete: {0}' -f $f[0].Why))
        # every other report is whole
        $res = Get-Result $db
        foreach ($k in @($script:One.Per.Keys | Where-Object { $_ -ne '2' })) { ($res.Per[$k] -join "`n") | Should -Be ($script:One.Per[$k] -join "`n") }
    }
    It '#831 B: the BIG report in parts, <Workers> workers at the same time: identical rows per report, verdicts, final order and Log Analytics post' -ForEach @(@{ Workers = 2 }, @{ Workers = 4 }) {
        $db = New-Db ("split{0}" -f $Workers); $script:Dbs.Add($db)
        $run = Invoke-ScaleOut -Db $db -Workers $Workers -SplitWorkers $Workers
        $parts = @($run.Plan | Where-Object { $_.Report -eq 'Gen3_Detailed' })
        $parts.Count | Should -BeGreaterThan 1 -Because 'the big report is split'
        (@($run.Results | Measure-Object -Property Done -Sum).Sum) | Should -Be $run.Plan.Count
        $res = Get-Result $db
        foreach ($k in $script:One.Per.Keys) { ($res.Per[$k] -join "`n") | Should -Be ($script:One.Per[$k] -join "`n") -Because "report ordinal $k" }
        ($res.Order -join "`n") | Should -Be ($script:One.Order -join "`n") -Because 'score, then report, then the single job''s write order'
        $res.Status | Should -Be $script:One.Status
        $w = Wait-RAScaleOutItems -Store $run.Store -Manifest $run.Manifest -UseKeda $true -Sleep { } -Log { param($l, $t) }
        $w.State | Should -Be 'succeeded'
        $hv = Read-RAScaleOutHandovers -Store $run.Store -Manifest $run.Manifest
        @(Get-RAScaleOutItemFailures -Manifest $run.Manifest -Markers @($w.Markers) -Handovers $hv).Count | Should -Be 0
        @($hv.Values | Where-Object { @($_['Reports']) -contains 'Gen3_Detailed' }).Count | Should -Be 1 -Because 'one part put the report together'
        $st = @{ RowCounts = @{}; StatusDone = @{}; Attempted = (New-Object System.Collections.Generic.List[string]); Failures = (New-Object System.Collections.Generic.List[object]) }
        $mg = Merge-RAScaleOutHandovers -State $st -Manifest $run.Manifest -Handovers $hv
        $mg.Reports | Should -Be $script:Reports -Because 'the run reads the reports in the single job''s order, the split one once'
        $st.RowCounts['Gen3_Detailed'] | Should -Be ([int](@($script:One.Status | Where-Object { $_ -like 'Gen3_Detailed|*' })[0].Split('|')[2]))
        $la = Get-ProducerLaPosts -Run $run -Merged $mg
        $la.Posted | Should -Be $script:OneRun.La.Posted
        ($la.Rows -join "`n") | Should -Be ($script:OneRun.La.Rows -join "`n")
    }
    It '#831 B: a worker KILLED MID-PART: the part runs again and replaces ONLY its own rows -- no row twice, the result and the Log Analytics post identical' {
        $db = New-Db 'splitcrash'; $script:Dbs.Add($db)
        $run = Invoke-ScaleOut -Db $db -Workers 1 -Sequential -SplitWorkers 3 -Crash @{ 'Gen3_Detailed#1' = 1 }
        $run.Results[0].Died | Should -Be 'Gen3_Detailed#1'
        $p0 = @(Get-RAScaleOutSplitSeqRanges -Ordinal 3 -Part 0 -Parts 3)[0]
        $before = @(Q $db ("SELECT FindingId FROM sidata.Finding WHERE RaReport = 3 AND RaSeq >= {0} AND RaSeq < {1}" -f $p0.From, $p0.To) | ForEach-Object { [long]$_['FindingId'] })
        $before.Count | Should -BeGreaterThan 0 -Because 'part 1 was in before the crash'
        $run.Ctx.MockState['Now'] = [datetime]::UtcNow.AddMinutes(11)
        $results = @(1, 2 | ForEach-Object { Invoke-FreshWorker -Db $db -Ctx $run.Ctx -Queue $run.Queue -Store $run.Store -Lock $run.Lock -Worker ("again$_") })
        ((@($results | Measure-Object -Property Done -Sum).Sum) + $run.Results[0].Done) | Should -Be $run.Plan.Count
        $after = @(Q $db ("SELECT FindingId FROM sidata.Finding WHERE RaReport = 3 AND RaSeq >= {0} AND RaSeq < {1}" -f $p0.From, $p0.To) | ForEach-Object { [long]$_['FindingId'] })
        @($after | Where-Object { $before -notcontains $_ }).Count | Should -Be 0 -Because 'the retried part never removed or rewrote another part''s rows'
        $res = Get-Result $db
        foreach ($k in $script:One.Per.Keys) { ($res.Per[$k] -join "`n") | Should -Be ($script:One.Per[$k] -join "`n") -Because "report ordinal $k" }
        $res.Count | Should -Be $script:One.Count
        ($res.Order -join "`n") | Should -Be ($script:One.Order -join "`n")
        $res.Status | Should -Be $script:One.Status
        $w = Wait-RAScaleOutItems -Store $run.Store -Manifest $run.Manifest -UseKeda $true -Sleep { } -Log { param($l, $t) }
        $w.State | Should -Be 'succeeded'
        $mg = Merge-RAScaleOutHandovers -State @{ Attempted = (New-Object System.Collections.Generic.List[string]) } -Manifest $run.Manifest -Handovers (Read-RAScaleOutHandovers -Store $run.Store -Manifest $run.Manifest)
        $la = Get-ProducerLaPosts -Run $run -Merged $mg
        $la.Posted | Should -Be $script:OneRun.La.Posted
        ($la.Rows -join "`n") | Should -Be ($script:OneRun.La.Rows -join "`n") -Because 'every row once, in the one job''s order'
    }
    It '#831 B: a part that kills its worker EVERY time: the whole report NOT COMPLETE once, with the cause, and none of its rows kept' {
        $db = New-Db 'splitfail'; $script:Dbs.Add($db)
        $crash = @{ 'Gen3_Detailed#2' = 0 }
        $run = Invoke-ScaleOut -Db $db -Workers 1 -Sequential -SplitWorkers 3 -Crash $crash -MaxDequeue 2
        for ($i = 0; $i -lt 3; $i++) {
            $run.Ctx.MockState['Now'] = ([datetime]$(if ($run.Ctx.MockState['Now']) { $run.Ctx.MockState['Now'] } else { [datetime]::UtcNow })).AddMinutes(11)
            $null = Invoke-FreshWorker -Db $db -Ctx $run.Ctx -Queue $run.Queue -Store $run.Store -Lock $run.Lock -Worker "w$i" -Crash $crash -MaxDequeue 2
        }
        $w = Wait-RAScaleOutItems -Store $run.Store -Manifest $run.Manifest -UseKeda $true -Sleep { } -Log { param($l, $t) }
        $w.State | Should -Be 'failed'
        $f = @(Get-RAScaleOutItemFailures -Manifest $run.Manifest -Markers @($w.Markers) -Handovers (Read-RAScaleOutHandovers -Store $run.Store -Manifest $run.Manifest))
        $f.Count | Should -Be 1 -Because 'one report, named once'
        $f[0].Report | Should -Be 'Gen3_Detailed'; $f[0].Why | Should -Match 'its work item failed: part 3 of 3: its worker stopped'
        @(Q $db "SELECT COUNT(*) AS N FROM sidata.Finding WHERE RaReport = 3")[0]['N'] | Should -BeGreaterThan 0 -Because 'parts 1 and 2 are in until the producer decides'
        # the producer: the report keeps no rows (every part's), NOT COMPLETE with the cause
        $null = Invoke-RAStreamSql -Stream $run.Stream -Sql (Get-RAStreamDeleteBucketSql -Grain Detailed) -Params @{ CollectionId = [string]$run.Stream.CollectionId; Report = '3'; Bucket = '*'; CollectionTime = $run.Stream.TimeText; RunKey = $run.Stream.RunKey }
        @(Q $db "SELECT COUNT(*) AS N FROM sidata.Finding WHERE RaReport = 3")[0]['N'] | Should -Be 0
        @(Q $db "SELECT COUNT(*) AS N FROM sidata.RaReportStatus WHERE ReportName = 'Gen3_Detailed'")[0]['N'] | Should -Be 0 -Because 'no part put the report together, so no verdict says Complete'
        $res = Get-Result $db
        foreach ($k in @($script:One.Per.Keys | Where-Object { $_ -ne '3' })) { ($res.Per[$k] -join "`n") | Should -Be ($script:One.Per[$k] -join "`n") }
    }
}

Describe 'the measurement: one worker against four (100,000 rows)' -Tag 'Scale' -Skip:(-not $script:HasSql) {
    It 'wall time, the same result' {
        # 6 reports x 5,555 assets x 3 findings ~ 100,000 rows; every query slice takes 2 s at the service (its own time)
        $one = New-Db 'm1'; $four = New-Db 'm4'
        try {
            $t1 = [System.Diagnostics.Stopwatch]::StartNew(); $null = Invoke-ScaleOut -Db $one -Workers 1 -Assets 5555 -LatencyMs 2000; $t1.Stop()
            $t4 = [System.Diagnostics.Stopwatch]::StartNew(); $null = Invoke-ScaleOut -Db $four -Workers 4 -Assets 5555 -LatencyMs 2000; $t4.Stop()
            $n1 = @(Q $one 'SELECT COUNT(*) AS N FROM sidata.Finding')[0]['N']; $n4 = @(Q $four 'SELECT COUNT(*) AS N FROM sidata.Finding')[0]['N']
            Write-Host ('[measure] {0:N0} rows: 1 worker {1:N1} s, 4 workers {2:N1} s -- x{3:N2}' -f $n1, $t1.Elapsed.TotalSeconds, $t4.Elapsed.TotalSeconds, ($t1.Elapsed.TotalSeconds / [Math]::Max(0.1, $t4.Elapsed.TotalSeconds)))
            $n4 | Should -Be $n1
            $n1 | Should -BeGreaterThan 99000
        } finally { Remove-Db $one; Remove-Db $four }
    }
}
