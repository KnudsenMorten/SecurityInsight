#Requires -Version 7.0
<#
.SYNOPSIS
    The CI build of a large install, measured offline on the test VM (local SQL Server Express). Vendor tool: never shipped.

.DESCRIPTION
    Makes the synthetic tenant of CiPerfFixture.ps1 at -Scale (1 = ~94,000 records -> ~77,000 CIs, the large ring 1 install
    of #605), writes it through the real record writer, then runs the CI build as the correlation job does (real rules, SQL
    ledger, the lock) with the job's CPUs (-Cpus: SI_CiParallel) and writes one JSON:
      Records    the record writer's counts and seconds
      Build      the build's phases (group, feeds, prepare, dirty, read, ledger, core, write, post, finish), seconds, CIs
      Batches    per batch: its CIs and seconds (from the build's own log lines)
      Profile    -ProfileBatches n: the first n batches taken apart step by step (rows -> groups, ids, documents, rules and
                 risk factors, classification, identity links, database items, the JSON of the write, the graph items)
      Digest     -DigestFile: every stored CI in a comparable form (Get-CiPerfCiDigest), written to that file
      Build2     -Again: a second build of the unchanged records (the incremental build of every night)
    -SIRoot points at the tree measured (a before tree and an after tree are measured the same way).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SIRoot,
    [double]$Scale = 1.0,
    [int]$Cpus = 2,
    [int]$BatchCis = 2000,
    [int]$ProfileBatches = 0,
    [switch]$NoBuild,
    [switch]$Again,
    [string]$DigestFile,
    [Parameter(Mandatory)][string]$OutFile,
    [string]$Server = '.\SQLEXPRESS',
    # the profile's batches also time these functions (inclusive, every call; a recursive one counts each level)
    [string]$FunctionProfile = '',
    # the records' times are made from this time (ISO-8601, UTC); two runs to be compared CI for CI start from the same one,
    # at about the same time (default: now)
    [string]$Epoch = ''
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path $SIRoot 'engine\data-model\SI-RecordCapture.ps1')
. (Join-Path $SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
. (Join-Path $here 'CiPerfFixture.ps1')
$global:SI_CiParallel = $Cpus
$global:SI_DataModelOverlayRoot = $null
$model = Get-SIDataModel -Root (Join-Path $SIRoot 'data-model')
$say = { param($m) Write-Host ('[{0:HH:mm:ss}] {1}' -f [datetime]::UtcNow, $m) }
$res = [ordered]@{ SIRoot = $SIRoot; Scale = $Scale; Cpus = $Cpus; BatchCis = $BatchCis; Machine = [Environment]::ProcessorCount; Ps = $PSVersionTable.PSVersion.ToString() }
$db = $null
$epochT = [datetime]::UtcNow
if ($Epoch) { $epochT = ([datetimeoffset]::Parse($Epoch, [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime }
$epochT = [datetime]::SpecifyKind($epochT, [DateTimeKind]::Utc)
$res['Epoch'] = $epochT.ToString('o')
try {
    $db = New-CiPerfDatabase -SIRoot $SIRoot -Server $Server
    & $say ("database {0}" -f $db.Name)
    $w = Write-CiPerfTenant -Scale $Scale -Invoke $db.Seam -Model $model -T $epochT -Log { param($m) & $say $m }
    $res['Records'] = $w
    & $say ("records written: {0:N0} (make {1:N0} s, write {2:N0} s, failed {3})" -f $w.Records, $w.MakeSeconds, $w.WriteSeconds, $w.Failed)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $rules = @(Get-SICiBuildRules -Log { param($l, $m) })
    $res['Rules'] = $rules.Count; $res['RulesSeconds'] = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    & $say ("{0} rule(s) loaded in {1:N1} s" -f $rules.Count, $sw.Elapsed.TotalSeconds)

    if (-not $NoBuild) {
        $b = Invoke-CiPerfBuild -Database $db -Rules $rules -BatchCis $BatchCis -Echo { param($l) Write-Host $l }
        $r = $b.Result
        $res['Build'] = [ordered]@{ Seconds = $b.Seconds; Failed = [bool]$r.Failed; Reason = [string]$r.Reason; CiCount = $r.CiCount; Changed = $r.Changed; Mode = $r.BuildMode; Phases = $r.Phases; PostedRows = $b.Posted.Rows; PostedFull = $b.Posted.Full.Count }
        # per batch: '<sec> INFO CIs: batch b of n started' ... the next start
        $starts = @(); foreach ($ln in $b.Lines) { if ($ln -match '^([\d,.]+) INFO CIs: batch (\d+) of (\d+) started') { $starts += [pscustomobject]@{ T = [double]($Matches[1] -replace ',', ''); B = [int]$Matches[2] } } }
        $bl = @(); for ($i = 0; $i -lt $starts.Count; $i++) { $end = $(if ($i + 1 -lt $starts.Count) { $starts[$i + 1].T } else { $b.Seconds }); $bl += [pscustomobject]@{ Batch = $starts[$i].B; Seconds = [Math]::Round($end - $starts[$i].T, 1) } }
        $res['Batches'] = $bl
        $res['SqlTimes'] = $b.SqlTimes
        foreach ($x in @($b.SqlTimes | Select-Object -First 8)) { & $say ('SQL {0,7:N1} s {1,5} x  {2}' -f $x.Seconds, $x.Count, $x.Statement) }
        $res['Lines'] = @($b.Lines | Where-Object { $_ -notmatch 'INFO CIs: batch \d+ of \d+ -- (looking|its|writing|sending|building)' })
        if ($DigestFile) {
            $sw.Restart()
            $d = Get-CiPerfCiDigest -Invoke $db.Seam -Epoch $epochT
            $lines = New-Object System.Collections.Generic.List[string]
            foreach ($k in $d.Keys) { $lines.Add($k + "`t" + $d[$k]) }
            # the rows posted to SI_CI_CL (full rows, without the per-build values): what Risk Analysis reads
            foreach ($p in ($b.Posted.Full | Sort-Object { [string]$_.si_ci_id })) {
                $h = [ordered]@{}; foreach ($pp in $p.PSObject.Properties) { if ($pp.Name -notin 'si_collection_time', 'si_run_id') { $h[$pp.Name] = $pp.Value } }
                $lines.Add('POST ' + [string]$p.si_ci_id + "`t" + (ConvertTo-CiPerfRelativeTimes -Epoch $epochT -Text (ConvertTo-CiPerfCanonicalJson (ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $h -Depth 12 -Compress) -AsHashtable))))
            }
            [IO.File]::WriteAllLines($DigestFile, $lines)
            $res['DigestCis'] = $d.Count; $res['DigestSeconds'] = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        }
        if ($Again) {
            $b2 = Invoke-CiPerfBuild -Database $db -Rules $rules -BatchCis $BatchCis
            $res['Build2'] = [ordered]@{ Seconds = $b2.Seconds; Failed = [bool]$b2.Result.Failed; CiCount = $b2.Result.CiCount; Changed = $b2.Result.Changed; Mode = $b2.Result.BuildMode; Phases = $b2.Result.Phases }
        }
    }

    if ($ProfileBatches -gt 0) {
        # one batch, step by step: what Invoke-SICiBuild's batch loop does, each step on its own clock
        if ($NoBuild) { $null = Invoke-SICiGrouping -Sql $db.Seam -LookbackDays 30 -BatchCis $BatchCis -Log { param($l, $m) } }
        $types = @{}; foreach ($f in @($model['field-catalog'].fields)) { $types[[string]$f.name] = [string]$f.type }
        $feeds = ConvertTo-SICiFeedLatest -Rows @(& $db.Seam (Get-SICiFeedLatestSql -LookbackDays 30) @{} 'rows')
        $svc = Get-SICiServiceIndex -Sql $db.Seam -Log { param($l, $m) }
        $relRules = @(Get-SICiRelationRules -Model $model)
        $ctxLists = Get-SIDataModelListContext $model
        $prof = New-Object System.Collections.Generic.List[object]
        $fnAcc = @{}; $fnCnt = @{}
        foreach ($fn in @($FunctionProfile -split '[;,]' | Where-Object { $_ })) {
            $cmd = Get-Command -Name $fn -CommandType Function -ErrorAction SilentlyContinue
            if (-not $cmd) { & $say "function profile: $fn not found"; continue }
            $orig = $cmd.ScriptBlock; $name = $fn; $fnAcc[$name] = [long]0; $fnCnt[$name] = 0
            $wrap = { $t0 = [Diagnostics.Stopwatch]::GetTimestamp(); try { & $orig @args } finally { $fnAcc[$name] += [Diagnostics.Stopwatch]::GetTimestamp() - $t0; $fnCnt[$name]++ } }.GetNewClosure()
            Set-Item -Path ("function:script:" + $fn) -Value $wrap
        }
        for ($bn = 1; $bn -le $ProfileBatches; $bn++) {
            $st = [ordered]@{}; $c = @{}
            $t0 = [Diagnostics.Stopwatch]::StartNew()
            $step = { param([string]$Name, [scriptblock]$Block) $t0.Restart(); . $Block; $st[$Name] = [Math]::Round($t0.Elapsed.TotalSeconds, 2) }
            & $step 'read rows (SQL)' { $c.Rows = @(& $db.Seam (Get-SICiBatchSql) @{ b = [string]$bn; only = '0' } 'rows') }
            if ($c.Rows.Count -eq 0) { break }
            & $step 'rows -> groups' { $c.Bg = ConvertTo-SICiBatchGroups -Rows $c.Rows -Types $types; $c.Stored = Get-SICiBatchStored -Rows $c.Rows }
            & $step 'scope + disabled' { $c.G = @((Select-SICiGroupsInScope -Groups @((Select-SICiGroupsEnabled -Groups @($c.Bg.Groups) -Policy (Get-SIDisabledAssetPolicy)).Kept)).Kept) }
            & $step 'ledger subset (SQL)' { $lc = & $db.NewEngineConn; $c.Ledger = Get-SIObjectLedgerSubset -Connection $lc -Keys @(Get-SICiGroupLedgerKeys -Groups $c.G) }
            & $step 'ids' { $c.Idy = Resolve-SIObjectIdentity -Groups @($c.G) -Ledger $c.Ledger -Now ([datetime]::UtcNow) }
            & $step 'documents' {
                $owner = Get-SICmdbOwner; $plan = @(Get-SICiFieldPlan -Catalog $model['field-catalog'])
                $docs = New-Object System.Collections.Generic.List[object]
                foreach ($d in @($c.Idy.Decisions)) {
                    if (-not $d.CorrelationId) { continue }
                    $recs = @(foreach ($m in @($d.Group.Members)) { $m.Record })
                    $doc = New-SICiDocument -CiId ([string]$d.CorrelationId) -Records $recs -Catalog $model['field-catalog'] -FeedLatest $feeds -Now ([datetime]::UtcNow) -RunId 'p' -CmdbOwner $owner -FieldPlan $plan
                    $doc['si_ci_action'] = [string]$d.Action; $docs.Add($doc)
                }
                $c.Docs = $docs.ToArray()
            }
            # the enrichment, call by call on ONE thread (what each costs per CI); Invoke-SICiEnrichment's own loop, unrolled
            $ctx = @{ Lists = (Merge-SIRiskFactorRanges -Lists $ctxLists); Now = [datetime]::UtcNow }
            $trust = Get-SICiTrustIndex $model['trust']; $byClass = Get-SICiRulesByClass -Rules $rules; $fc = @{}; $owner = Get-SICmdbOwner; $cm = $model['criticality-mapping']
            $rfPlan = $null; if (Get-Command -Name New-SICiRiskFactorPlan -ErrorAction SilentlyContinue) { $rfPlan = New-SICiRiskFactorPlan -Factors $model['risk-factors'] }
            $sub = [ordered]@{ 'enrich: break glass' = 0.0; 'enrich: rules' = 0.0; 'enrich: services' = 0.0; 'enrich: criticality' = 0.0; 'enrich: risk factors' = 0.0 }
            $sw2 = [Diagnostics.Stopwatch]::new()
            foreach ($d in $c.Docs) {
                $sw2.Restart(); $null = Set-SICiBreakGlass -Ci $d -Context $ctx; $sub['enrich: break glass'] += $sw2.Elapsed.TotalSeconds
                $sw2.Restart(); $null = Invoke-SICiRules -Ci $d -Rules $rules -Trust $trust -Context $ctx -Now $ctx.Now -RulesByClass $byClass -FieldCache $fc -BudgetSeconds 60; $sub['enrich: rules'] += $sw2.Elapsed.TotalSeconds
                $sw2.Restart(); if ($svc) { $null = Set-SICiServices -Ci $d -Index $svc -Mapping $cm -EnvironmentOrder ([string[]]@()) -CmdbOwner $owner }; $sub['enrich: services'] += $sw2.Elapsed.TotalSeconds
                $sw2.Restart(); $null = Set-SICiCriticality -Ci $d -Mapping $cm -CmdbOwner $owner; $sub['enrich: criticality'] += $sw2.Elapsed.TotalSeconds
                $sw2.Restart(); if ($rfPlan) { $null = Invoke-SICiRiskFactors -Ci $d -Factors $model['risk-factors'] -Checks $model['coverage-checks'] -Context $ctx -Plan $rfPlan } else { $null = Invoke-SICiRiskFactors -Ci $d -Factors $model['risk-factors'] -Checks $model['coverage-checks'] -Context $ctx }; $sub['enrich: risk factors'] += $sw2.Elapsed.TotalSeconds
            }
            foreach ($k in $sub.Keys) { $st[$k] = [Math]::Round($sub[$k], 2) }
            & $step 'classification' { $null = Invoke-SICiClassification -Cis $c.Docs -Model $model -Context @{ Lists = $ctxLists; Now = [datetime]::UtcNow } }
            & $step 'identity links' { if (@($c.Docs | Where-Object { [string]$_['si_class'] -ne 'identity' } | Select-Object -First 1).Count -gt 0) { $null = Set-SICiIdentityLinks -Docs $c.Docs -Index (ConvertTo-SICiIdentityIndex -Rows @(& $db.Seam (Get-SICiIdentityIndexSql) @{} 'rows')) } }
            & $step 'database items' { $c.Items = ConvertTo-SICiSqlItems -Cis $c.Docs -Stored $c.Stored }
            & $step 'write JSON' { $c.J = ConvertTo-SIJsonArray $c.Items.Cis -Depth 14; $c.L = ConvertTo-SIJsonArray $c.Items.Links; $c.M = ConvertTo-SIJsonArray $c.Items.Map }
            & $step 'graph items' { $c.Gi = ConvertTo-SICiGraphItems -Docs $c.Docs -Rules $relRules -Only $null }
            & $step 'post rows' { $rows = New-Object System.Collections.Generic.List[object]; foreach ($p in $c.Items.Post) { $rows.Add($p.Seen); $rows.Add($p.Row) }; $c.PostBytes = (ConvertTo-Json -InputObject $rows.ToArray() -Compress -Depth 8).Length }
            $classes = @{}; foreach ($d in $c.Docs) { $k = [string]$d['si_class']; $classes[$k] = [int]$classes[$k] + 1 }
            $fnLine = (@($fnAcc.Keys | Sort-Object { -$fnAcc[$_] } | ForEach-Object { '{0} {1:N2}s/{2}' -f $_, ($fnAcc[$_] / [Diagnostics.Stopwatch]::Frequency), $fnCnt[$_] }) -join '; ')
            if ($fnLine) { & $say ("functions (batch {0}): {1}" -f $bn, $fnLine) }
            foreach ($k in @($fnAcc.Keys)) { $fnAcc[$k] = [long]0; $fnCnt[$k] = 0 }
            $prof.Add([pscustomobject]@{ Batch = $bn; Cis = @($c.Docs).Count; Records = $c.Rows.Count; Classes = (($classes.Keys | Sort-Object | ForEach-Object { '{0} {1}' -f $_, $classes[$_] }) -join ', '); Steps = $st })
            & $say ("profile batch {0}: {1} CI(s) -- {2}" -f $bn, @($c.Docs).Count, (($st.Keys | ForEach-Object { '{0} {1}' -f $_, $st[$_] }) -join '; '))
        }
        $res['Profile'] = $prof.ToArray()
    }
} catch {
    $res['Error'] = ('{0} @ {1}' -f $_.Exception.Message, ((($_.ScriptStackTrace -split "`n") | Select-Object -First 3) -join ' / '))
    & $say ("ERROR " + $res['Error'])
} finally {
    Remove-CiPerfDatabase -Db $db
    [IO.File]::WriteAllText($OutFile, (ConvertTo-Json -InputObject $res -Depth 8))
    & $say ("result: {0}" -f $OutFile)
}
