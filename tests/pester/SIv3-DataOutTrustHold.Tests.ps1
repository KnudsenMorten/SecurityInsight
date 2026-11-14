#Requires -Version 7.0
<#
    #1226 (owner 2026-11-12: "only send in data for the latest collection that completed ... we dont trust the data"), THE
    HOLD HALF: nothing is sent out from a collection built on partial profile data. Get-SIDataUpstreamTrust (engine\pro-data\
    _shared\SI-DataSync.ps1) reads the same source-run records Risk Analysis reads (SI-RunOutcome.ps1) and applies the same
    rule, incl. #899 RolesOnly; Invoke-SIDataSync.ps1 holds the data-out job's mark AND its own fallback on it.
    Live 2026-11-12: a customer install's run was built on an endpoint run that ended 'success-partial' (#1223) and data out would have sent
    it to ServiceNow (the old hold only covered a FAILED step). Offline: the Log Analytics read is a fake.
#>
BeforeDiscovery {
    $script:LocalSql = $false
    try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
}
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-RunOutcome.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-KqlError.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-SchemaGate.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataModel.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataSql.ps1')
    . (Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-DataSync.ps1')
    $script:StreamSrc = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SqlStream.ps1'))
    # the two pure / SQL-text functions of the Risk Analysis side, taken from their file (the whole stream needs its engine)
    foreach ($fn in 'Get-RACollectionTrustWriteSql', 'Get-RACollectionTrustVerdict') {
        $m = [regex]::Match($script:StreamSrc, "(?s)function $fn \{.*?\n\}")
        . ([scriptblock]::Create($m.Value))
    }
    function script:Rows([object[]]$R) { $rr = @($R); { param($kql) $rr }.GetNewClosure() }
    function script:Rh([string]$Engine, [string]$Exit, [string]$Msg = '') { [pscustomobject]@{ Engine = $Engine; ExitReason = $Exit; ErrorMessage = $Msg; EndedAt = [datetime]::UtcNow } }
    $script:Sync = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\pro-data\Invoke-SIDataSync.ps1'))
    $script:RaSrc = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
    $script:Schema = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'sql\si-data-schema.sql')
    function script:New-LocalInvoke([string]$Db) {
        $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True;Connection Timeout=90"
        {
            param([string]$sql, $p, [string]$mode)
            $cn = New-Object System.Data.SqlClient.SqlConnection($cs); $cn.Open()
            try {
                $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = $sql
                if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                while ($r.Read()) { $h = @{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { $null } else { $r.GetValue($i) }) }; $rows.Add($h) }
                $r.Close(); return , $rows.ToArray()
            } finally { $cn.Close() }
        }.GetNewClosure()
    }
}

Describe 'THE COLLECTION''S OWN VERDICT (Invardia 2026-11-12: "tie the trust check to the collection''s own run")' {
    It 'Risk Analysis''s verdict: no outcome = nothing recorded; success = trusted; success-partial = not trusted with the reason' {
        (Get-RACollectionTrustVerdict -Outcome $null).Write | Should -BeFalse -Because 'never a guessed verdict'
        $ok = Get-RACollectionTrustVerdict -Outcome ([pscustomobject]@{ ExitReason = 'success'; Message = ''; RolesOnly = $false })
        $ok.Write | Should -BeTrue; $ok.Trusted | Should -BeTrue; $ok.Why | Should -Be ''
        $bad = Get-RACollectionTrustVerdict -Outcome ([pscustomobject]@{ ExitReason = 'success-partial'; Message = 'built on incomplete profile data: x'; RolesOnly = $false })
        $bad.Write | Should -BeTrue; $bad.Trusted | Should -BeFalse; $bad.Why | Should -Match '^built on incomplete profile data'
    }
    It 'NEGATIVE: the source-run read returned NO records -> nothing is recorded (an empty read proves nothing)' {
        $ok = [pscustomobject]@{ ExitReason = 'success'; Message = ''; RolesOnly = $false }
        (Get-RACollectionTrustVerdict -Outcome $ok -RowsRead 0).Write | Should -BeFalse
        (Get-RACollectionTrustVerdict -Outcome $ok -RowsRead 3).Write | Should -BeTrue
        $script:RaSrc | Should -Match '\$__upRead = \$\(if \(\$null -eq \$__up\) \{ 0 \} else \{ \(\$__up \| Measure-Object\)\.Count \}\)' -Because 'counted by piping, never @() around a list (PS-LIST-1)'
        $script:RaSrc | Should -Match 'Get-RACollectionTrustVerdict -Outcome \$script:_RAUpstreamOutcome -RowsRead \$__upRead'
    }
    It 'the writer replaces the row in ONE transaction (never a deleted verdict without its new one)' {
        $w = Get-RACollectionTrustWriteSql
        $w | Should -Match 'SET XACT_ABORT ON'
        $w.IndexOf('BEGIN TRAN;') | Should -BeLessThan $w.IndexOf('DELETE FROM sidata.CollectionTrust')
        $w.IndexOf('COMMIT;') | Should -BeGreaterThan $w.IndexOf('INSERT sidata.CollectionTrust')
    }
    It 'the role-read exception: Risk Analysis turns it into success before the verdict -> trusted' {
        # Resolve-RARoleReadUpstream returns ExitReason 'success' when only the role read was partial (RA-SqlStream.ps1)
        $script:StreamSrc | Should -Match "Outcome = \[pscustomobject\]@\{ ExitReason = 'success'; Message = ''; RolesOnly = \`$false \}"
        $script:RaSrc.IndexOf('$__tv = Get-RACollectionTrustVerdict -Outcome $script:_RAUpstreamOutcome -RowsRead') | Should -BeGreaterThan $script:RaSrc.IndexOf('$script:_RAUpstreamOutcome = $__rr.Outcome')
    }
    It 'Risk Analysis writes it WITH the collection: the stream''s own time and grain, never in a what-if run, never fatal' {
        $script:RaSrc | Should -Match 'Invoke-RAStreamSql -Stream \$script:RAStream -Sql \(Get-RACollectionTrustWriteSql\)'
        $script:RaSrc | Should -Match 'CollectionTime = \$script:RAStream\.TimeText; Grain = \[string\]\$script:RAStream\.Grain'
        $script:RaSrc | Should -Match 'if \(\$script:RAStreamOn -and \$null -ne \$script:RAStream -and -not \$script:SIWhatIf'
        $script:RaSrc | Should -Match "\[string\]\`$script:RAScaleRole -ne 'worker'" -Because 'one writer: a scale-out worker never writes the producer''s verdict'
        $script:RaSrc | Should -Match 'Write-Warn2 \("whether this run was built on complete source data was not saved' -Because 'a lost verdict is said, not verbose-only'
    }
    It 'a hold or an unknown verdict is a WARN line, a trusted collection an INFO line' {
        $script:Sync | Should -Match 'if \(\$verdict\.Known -and \$verdict\.Trusted\) \{ Write-DataInfo \$line \} else \{ Write-DataWarn \$line \}'
    }
    It 'without -ByTime (not used by the data sync any more): the newest complete Detailed collection, retired ones left out' {
        try {
            Set-SIDataRetiredReady -Ready $true
            $sql = Get-SIDataCollectionTrustSql
            $sql | Should -Match "Kind = N'Detailed' AND Status = N'Complete' AND RetiredAt IS NULL ORDER BY CollectionTime DESC" -Because 'a retired collection is never judged (the shared live filter)'
            $sql | Should -Match "ct\.CollectionTime = @t AND ct\.Grain = N'Detailed'"
            Set-SIDataRetiredReady -Ready $false
            (Get-SIDataCollectionTrustSql) | Should -Not -Match 'RetiredAt' -Because 'a database without the mark has no such column'
        } finally { Set-SIDataRetiredReady -Ready $false }
    }
    It '-ByTime: the collection being SENT, named by its time (Loading or Complete alike), never the newest complete one' {
        $sql = Get-SIDataCollectionTrustSql -ByTime
        $sql | Should -Match 'DECLARE @t datetime2\(3\) = TRY_CONVERT\(datetime2\(3\), @CollectionTime, 126\);'
        $sql | Should -Not -Match "Status = N'Complete'" -Because 'Risk Analysis leaves its collection Loading until the sync completes it'
        $script:Got = $null
        $inv = { param($s, $p, $m) $script:Got = @{ Sql = $s; P = $p }; , @(@{ CollectionTime = [datetime]'2026-11-12T19:58:36.12'; Trusted = $true; Why = $null; Found = 1 }) }
        (Get-SIDataCollectionTrust -Invoke $inv -CollectionTime '2026-11-12T19:58:36.120Z').Found | Should -BeTrue
        $script:Got.P.CollectionTime | Should -Be '2026-11-12T19:58:36.120' -Because 'a zoned text becomes the zone-less text Risk Analysis wrote'
        $script:Got.Sql | Should -Match 'TRY_CONVERT'
        $null = Get-SIDataCollectionTrust -Invoke $inv -CollectionTime ([datetime]::SpecifyKind([datetime]'2026-11-12T19:58:36.120', 'Utc'))
        $script:Got.P.CollectionTime | Should -Be '2026-11-12T19:58:36.120'
    }
    It 'reading it: not trusted -> held with the reason; trusted -> sent; no verdict -> Found false (the source-run check then); a failure never throws' {
        $t = [datetime]'2026-11-12T19:58:36'
        $v = Get-SIDataCollectionTrust -Invoke ({ param($s, $p, $m) , @(@{ CollectionTime = $t; Trusted = $false; Why = 'built on incomplete profile data: the newest endpoint profile run ended ''success-partial'''; Found = 1 }) }.GetNewClosure())
        $v.Found | Should -BeTrue; $v.Known | Should -BeTrue; $v.Trusted | Should -BeFalse
        $v.Why | Should -Match '^this collection is not trusted: it was built on incomplete profile data'
        $w = Get-SIDataCollectionTrust -Invoke ({ param($s, $p, $m) , @(@{ CollectionTime = $t; Trusted = $true; Why = $null; Found = 1 }) }.GetNewClosure())
        $w.Found | Should -BeTrue; $w.Trusted | Should -BeTrue
        $n = Get-SIDataCollectionTrust -Invoke ({ param($s, $p, $m) , @(@{ CollectionTime = $t; Trusted = $null; Why = $null; Found = 0 }) }.GetNewClosure())
        $n.Found | Should -BeFalse; $n.Why | Should -Match 'no verdict was recorded'
        (Get-SIDataCollectionTrust -Invoke { param($s, $p, $m) , @() }).Found | Should -BeFalse
        $x = Get-SIDataCollectionTrust -Invoke { param($s, $p, $m) throw 'database busy' }
        $x.Found | Should -BeFalse; $x.Known | Should -BeFalse; $x.Why | Should -Match 'database busy'
    }
    It 'the data sync judges the collection BEING SENT (the DataModel''s CollectionTime) by its own verdict, the source runs only without one (said)' {
        $script:Sync | Should -Match "\`$ct = Get-SIDataOutField \`$dm 'CollectionTime'"
        $script:Sync | Should -Match '\$own = Get-SIDataCollectionTrust -Invoke \$invoke -CollectionTime \$ct'
        $script:Sync | Should -Match "if \(\`$own\.Found\) \{ \`$verdict = \`$own; \`$how = 'its own verdict' \}"
        $script:Sync | Should -Match "data out  : the collection \{0\} sends from \(\{1\}\) -- \{2\}: \{3\}"
        $script:Sync.IndexOf('$judgeSent = {') | Should -BeLessThan $script:Sync.IndexOf('$onFindingsStored = {')
        $script:Sync | Should -Not -Match 'Get-SIDataCollectionTrust -Invoke \$invoke \}' -Because 'never "the newest complete collection" (that is the run before)'
    }
    It 'REAL SQL: the schema makes the table; Risk Analysis''s statement writes the verdict, the data sync''s reads it back by the collection''s time' -Skip:(-not $script:LocalSql) {
        $db = 'sitrust_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalInvoke 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = New-LocalInvoke $db
            [void](& $inv $script:Schema @{} 'nonquery')
            [void](& $inv (Get-SIDataRetiredColumnsSql) @{} 'scalar')
            Set-SIDataRetiredReady -Ready $true
            [void](& $inv "SET IDENTITY_INSERT sidata.Collection ON; INSERT sidata.Collection (CollectionId, CollectionTime, Kind, Status) VALUES (1, '2026-11-11T19:00:00', 'Detailed', 'Complete'), (2, '2026-11-12T19:58:36.120', 'Detailed', 'Complete'); SET IDENTITY_INSERT sidata.Collection OFF;" @{} 'nonquery')
            # the older collection trusted, the newest NOT -- written as Risk Analysis writes them
            & $inv (Get-RACollectionTrustWriteSql) @{ CollectionTime = '2026-11-11T19:00:00.000'; Grain = 'Detailed'; Trusted = 1; Why = '' } 'scalar' | Should -Be 1
            & $inv (Get-RACollectionTrustWriteSql) @{ CollectionTime = '2026-11-12T19:58:36.120'; Grain = 'Detailed'; Trusted = 0; Why = 'built on incomplete profile data: x' } 'scalar' | Should -Be 1
            # a re-run of the same collection replaces its row, never a second one
            & $inv (Get-RACollectionTrustWriteSql) @{ CollectionTime = '2026-11-12T19:58:36.120'; Grain = 'Detailed'; Trusted = 0; Why = 'built on incomplete profile data: y' } 'scalar' | Should -Be 1
            (& $inv "SELECT COUNT(*) FROM sidata.CollectionTrust WHERE CollectionTime = '2026-11-12T19:58:36.120'" @{} 'scalar') | Should -Be 1
            $v = Get-SIDataCollectionTrust -Invoke $inv
            $v.Found | Should -BeTrue; $v.Trusted | Should -BeFalse; $v.Why | Should -Match 'incomplete profile data: y$'
            # the newest collection retired -> the one before is judged by ITS verdict (trusted)
            [void](& $inv "UPDATE sidata.Collection SET RetiredAt = SYSUTCDATETIME() WHERE CollectionId = 2" @{} 'nonquery')
            $o = Get-SIDataCollectionTrust -Invoke $inv
            $o.Found | Should -BeTrue; $o.Trusted | Should -BeTrue
            # THE BLOCKER CASE (agent review): tonight's collection is still Loading (the sync completes it) -- judged by ITS
            # OWN verdict by time, never by the newest Complete one (the night before)
            [void](& $inv "SET IDENTITY_INSERT sidata.Collection ON; INSERT sidata.Collection (CollectionId, CollectionTime, Kind, Status) VALUES (3, '2026-11-13T19:00:00.500', 'Detailed', 'Loading'); SET IDENTITY_INSERT sidata.Collection OFF;" @{} 'nonquery')
            & $inv (Get-RACollectionTrustWriteSql) @{ CollectionTime = '2026-11-13T19:00:00.500'; Grain = 'Detailed'; Trusted = 0; Why = 'built on incomplete profile data: tonight' } 'scalar' | Should -Be 1
            $l = Get-SIDataCollectionTrust -Invoke $inv -CollectionTime '2026-11-13T19:00:00.500Z'
            $l.Found | Should -BeTrue; $l.Trusted | Should -BeFalse; $l.Why | Should -Match 'tonight$'
            # a collection with no verdict: Found false -> the source runs decide
            (Get-SIDataCollectionTrust -Invoke $inv -CollectionTime '2026-11-10T01:02:03.000').Found | Should -BeFalse
        } finally {
            Set-SIDataRetiredReady -Ready $false
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            try { [void](& $master "IF DB_ID(N'$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END" @{} 'nonquery') } catch { }
        }
    }
}

Describe 'THIS RUN''S OWN STEPS (owner #1226 rule: "trusted = the run finished every step"; live at internal 2026-11-13)' {
    BeforeAll {
        function script:Step([int]$Order, [string]$Job, [string]$State, [int]$Mine = 0, [string]$Err = '', [string]$Class = '') { @{ FlowRunId = 'fr-1'; StepOrder = $Order; Job = $Job; State = $State; ErrorClass = $Class; Error = $Err; Mine = $Mine } }
        $script:Tonight = @((Step 1 'ptc' 'Success'), (Step 2 'identity' 'Success'), (Step 3 'azure' 'Success'), (Step 4 'endpoint' 'Success'),
                            (Step 5 'publicip' 'Failed' -Err 'the step''s container did not start (an Azure platform problem)'),
                            (Step 6 'asset-correlation' 'Success'), (Step 8 'risk-analysis-detailed' 'Running' 1))
    }
    It 'NEGATIVE (the live case): a source step that FAILED this run -> NOT trusted, the Why names the step and its state' {
        $v = Get-SIFlowStepVerdict -Rows $script:Tonight
        $v.Known | Should -BeTrue; $v.Trusted | Should -BeFalse; $v.FlowRunId | Should -Be 'fr-1'
        $v.Why | Should -Be 'built on a run that did not finish every step: the public IP collection step of this run failed'
        $v.Why | Should -Not -Match 'container|Azure' -Because 'the runner''s raw error text never reaches the customer-facing reason'
    }
    It 'NEGATIVE: a RE-RUN from a later step continues a run whose source step FAILED -> NOT trusted (Invardia: the strict reading)' {
        $a = Step 2 'identity' 'Skipped' -Class 'before-rerun'; $a.PrevState = 'Success'
        $b = Step 5 'publicip' 'Skipped' -Class 'before-rerun'; $b.PrevState = 'Failed'
        $v = Get-SIFlowStepVerdict -Rows @($a, $b, (Step 8 'risk-analysis-detailed' 'Running' 1))
        $v.Known | Should -BeTrue; $v.Trusted | Should -BeFalse
        $v.Why | Should -Be 'built on a run that did not finish every step: the public IP collection step failed in the run this re-run continues'
    }
    It 'a re-run whose earlier steps all finished -> trusted; one that never finished there (still waiting / running) -> not trusted' {
        $a = Step 2 'identity' 'Skipped' -Class 'before-rerun'; $a.PrevState = 'Success'
        $b = Step 5 'publicip' 'Skipped' -Class 'before-rerun'; $b.PrevState = 'Disabled'
        (Get-SIFlowStepVerdict -Rows @($a, $b, (Step 8 'risk-analysis-detailed' 'Running' 1))).Trusted | Should -BeTrue
        $c = Step 5 'publicip' 'Skipped' -Class 'before-rerun'; $c.PrevState = 'Running'
        $w = Get-SIFlowStepVerdict -Rows @($a, $c, (Step 8 'risk-analysis-detailed' 'Running' 1))
        $w.Trusted | Should -BeFalse; $w.Why | Should -Match 'the public IP collection step did not finish in the run this re-run continues'
    }
    It 'a re-run whose earlier run cannot be found -> NOT known (the source records decide, said)' {
        $v = Get-SIFlowStepVerdict -Rows @((Step 5 'publicip' 'Skipped' -Class 'before-rerun'), (Step 8 'risk-analysis-detailed' 'Running' 1))
        $v.Known | Should -BeFalse; $v.Why | Should -Match 'the run it continues could not be found for the public IP collection step'
    }
    It 'NEGATIVE (review 2026-11-13): a run not found for ONE step never hides a failure found for another -> NOT trusted' {
        $a = Step 2 'identity' 'Skipped' -Class 'before-rerun'; $a.PrevState = 'Failed'
        $b = Step 3 'azure' 'Skipped' -Class 'before-rerun'   # no earlier run of it (history pruned, or a step newly added)
        $v = Get-SIFlowStepVerdict -Rows @($a, $b, (Step 8 'risk-analysis-detailed' 'Running' 1))
        $v.Known | Should -BeTrue; $v.Trusted | Should -BeFalse
        $v.Why | Should -Match 'the identity collection step failed in the run this re-run continues'
    }
    It 'the reason names each step in plain words, never its internal key' {
        $v = Get-SIFlowStepVerdict -Rows @((Step 1 'ptc' 'Failed'), (Step 6 'asset-correlation' 'Failed'), (Step 8 'risk-analysis-detailed' 'Running' 1))
        $v.Why | Should -Be 'built on a run that did not finish every step: the privilege tier catalog step of this run failed; the correlation step of this run failed'
        $v.Why | Should -Not -Match '\bptc\b|asset-correlation'
    }
    It 'a run of one step or one stage (no earlier step in the run): NOT known -- the source records decide' {
        $v = Get-SIFlowStepVerdict -Rows @((Step 8 'risk-analysis-detailed' 'Running' 1))
        $v.Known | Should -BeFalse; $v.Why | Should -Match 'one step or one stage'
    }
    It 'timed out and interrupted are failures too (the pipeline''s own failure states); each failed step is named' {
        $v = Get-SIFlowStepVerdict -Rows @((Step 2 'caj-si-identity' 'TimedOut'), (Step 4 'endpoint' 'Interrupted'), (Step 8 'risk-analysis-detailed' 'Running' 1))
        $v.Trusted | Should -BeFalse
        $v.Why | Should -Match 'the identity collection step of this run timed out; the device collection step of this run was interrupted'
    }
    It 'absent by design (Disabled / Skipped) and steps still running are NOT counted -> trusted' {
        $v = Get-SIFlowStepVerdict -Rows @((Step 1 'ptc' 'Success'), (Step 5 'publicip' 'Disabled'), (Step 7 'risk-analysis' 'Skipped'), (Step 6 'asset-correlation' 'Running'), (Step 8 'risk-analysis-detailed' 'Running' 1))
        $v.Known | Should -BeTrue; $v.Trusted | Should -BeTrue; $v.Why | Should -Be ''
    }
    It 'not a pipeline run (no rows, or no own step among them): NOT known -- the source records decide alone, as before' {
        (Get-SIFlowStepVerdict -Rows @()).Known | Should -BeFalse
        (Get-SIFlowStepVerdict -Rows $null).Known | Should -BeFalse
        (Get-SIFlowStepVerdict -Rows @((Step 5 'publicip' 'Failed'))).Known | Should -BeFalse -Because 'without its own step the rows are not this run'
    }
    It 'Risk Analysis''s verdict: a failed step is decisive -- written as not trusted even when the source records say success, and when the source read saw nothing' {
        $ok = [pscustomobject]@{ ExitReason = 'success'; Message = ''; RolesOnly = $false }
        $steps = Get-SIFlowStepVerdict -Rows $script:Tonight
        $a = Get-RACollectionTrustVerdict -Outcome $ok -RowsRead 4 -Steps $steps
        $a.Write | Should -BeTrue; $a.Trusted | Should -BeFalse; $a.Why | Should -Match 'the public IP collection step of this run failed'
        $b = Get-RACollectionTrustVerdict -Outcome $null -RowsRead 0 -Steps $steps
        $b.Write | Should -BeTrue; $b.Trusted | Should -BeFalse -Because 'a known failure needs no source read'
    }
    It 'both reasons: a failed step AND a partial source -> not trusted, the step first, the source reason joined' {
        $partial = [pscustomobject]@{ ExitReason = 'success-partial'; Message = 'built on incomplete profile data: the newest endpoint profile run ended ''success-partial'''; RolesOnly = $false }
        $v = Get-RACollectionTrustVerdict -Outcome $partial -RowsRead 4 -Steps (Get-SIFlowStepVerdict -Rows $script:Tonight)
        $v.Trusted | Should -BeFalse
        $v.Why | Should -Match '^built on a run that did not finish every step: .*public IP collection.*; also built on incomplete profile data'
    }
    It 'every step finished (or the steps are not known): the source-record rule as before -- unchanged' {
        $ok = [pscustomobject]@{ ExitReason = 'success'; Message = ''; RolesOnly = $false }
        $fine = Get-SIFlowStepVerdict -Rows @((Step 5 'publicip' 'Success'), (Step 8 'risk-analysis-detailed' 'Running' 1))
        (Get-RACollectionTrustVerdict -Outcome $ok -RowsRead 4 -Steps $fine).Trusted | Should -BeTrue
        (Get-RACollectionTrustVerdict -Outcome $ok -RowsRead 0 -Steps $fine).Write | Should -BeFalse -Because 'a known-good step read alone does not replace the source check'
        $unknown = Get-SIFlowStepVerdict -Rows @()
        (Get-RACollectionTrustVerdict -Outcome $ok -RowsRead 4 -Steps $unknown).Trusted | Should -BeTrue
        (Get-RACollectionTrustVerdict -Outcome ([pscustomobject]@{ ExitReason = 'success-partial'; Message = 'x'; RolesOnly = $false }) -RowsRead 4 -Steps $unknown).Trusted | Should -BeFalse
    }
    It 'WIRING: Risk Analysis reads its own steps through the settings store, by its grain''s job, before the verdict; a failed read is said' {
        $script:RaSrc | Should -Match "\`$__job = \`$\(if \(\[string\]\`$script:RAStream\.Grain -eq 'Summary'\) \{ 'risk-analysis' \} else \{ 'risk-analysis-detailed' \}\)"
        $script:RaSrc | Should -Match '\$__sr = & \$global:SI_ProSettingsStore\.Invoke \(Get-SIFlowStepOutcomeSql\) @\{ Job = \$__job \} ''reader'''
        $script:RaSrc | Should -Match 'Get-RACollectionTrustVerdict -Outcome \$script:_RAUpstreamOutcome -RowsRead \$__upRead -Steps \$__steps'
        $script:RaSrc.IndexOf('$__steps = Get-SIFlowStepVerdict') | Should -BeLessThan $script:RaSrc.IndexOf('-RowsRead $__upRead -Steps $__steps')
        $script:RaSrc | Should -Match "this run's own steps could not be read"
    }
    It 'REAL SQL: the pipeline''s own tables; the read takes the RUNNING run of this job and its steps up to it -- tonight''s case is not trusted' -Skip:(-not $script:LocalSql) {
        $db = 'siflow_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalInvoke 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = New-LocalInvoke $db
            $settings = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'sql\si-pro-settings.sql')
            [void](& $inv "IF SCHEMA_ID(N'cfg') IS NULL EXEC (N'CREATE SCHEMA cfg');" @{} 'nonquery')
            foreach ($t in 'FlowRun', 'FlowStepRun') {
                $ddl = [regex]::Match($settings, "(?s)IF OBJECT_ID\('cfg\.$t'\) IS NULL\s*CREATE TABLE cfg\.$t \(.*?\n\);").Value
                $ddl | Should -Not -BeNullOrEmpty -Because "the shipped DDL of cfg.$t is used, not a copy"
                [void](& $inv $ddl @{} 'nonquery')
            }
            # an OLDER finished run (its RA step Success) and TONIGHT's running run (publicip Failed, RA Running, a later step Waiting)
            [void](& $inv @"
INSERT cfg.FlowRun (FlowRunId, Day, Trg, State, StartedUtc) VALUES (N'old', N'2026-11-12', N'schedule', N'Succeeded', '2026-11-12T18:00:00'), (N'now', N'2026-11-13', N'manual', N'Running', '2026-11-13T00:14:40');
INSERT cfg.FlowStepRun (FlowRunId, StepOrder, GroupNo, Job, State, StartedUtc) VALUES
 (N'old', 5, 1, N'publicip', N'Success', '2026-11-12T18:30:00'), (N'old', 8, 3, N'risk-analysis-detailed', N'Success', '2026-11-12T18:40:00'),
 (N'now', 1, 1, N'ptc', N'Success', '2026-11-13T00:15:38'), (N'now', 4, 1, N'endpoint', N'Success', '2026-11-13T00:33:09'), (N'now', 5, 1, N'publicip', N'Failed', '2026-11-13T00:39:02'),
 (N'now', 6, 2, N'asset-correlation', N'Success', '2026-11-13T00:47:22'), (N'now', 7, 3, N'risk-analysis', N'Failed', '2026-11-13T00:52:00'), (N'now', 8, 3, N'risk-analysis-detailed', N'Running', '2026-11-13T00:52:00'),
 (N'now', 11, 4, N'asset-datasync', N'Waiting', NULL);
"@ @{} 'nonquery')
            $rows = @(& $inv (Get-SIFlowStepOutcomeSql) @{ Job = 'risk-analysis-detailed' } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            $rows.Count | Should -Be 5 -Because 'the running run only: the groups before Risk Analysis + its own step -- never the Summary beside it, never the later data sync'
            @($rows | Where-Object { [string]$_['Job'] -eq 'risk-analysis' }).Count | Should -Be 0 -Because 'a failed Summary beside Detailed never holds Detailed (review 2026-11-13)'
            @($rows | Where-Object { [int]$_['Mine'] -eq 1 }).Count | Should -Be 1
            $v = Get-SIFlowStepVerdict -Rows $rows
            $v.Known | Should -BeTrue; $v.Trusted | Should -BeFalse; $v.FlowRunId | Should -Be 'now'
            $v.Why | Should -Be 'built on a run that did not finish every step: the public IP collection step of this run failed'
            # the same run with the public IP step finished: only the Summary beside it failed -> TRUSTED
            [void](& $inv "UPDATE cfg.FlowStepRun SET State = N'Success' WHERE FlowRunId = N'now' AND Job = N'publicip';" @{} 'nonquery')
            $ok = Get-SIFlowStepVerdict -Rows @(& $inv (Get-SIFlowStepOutcomeSql) @{ Job = 'risk-analysis-detailed' } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            $ok.Known | Should -BeTrue; $ok.Trusted | Should -BeTrue
            # A RE-RUN from Risk Analysis after the night whose public IP step FAILED: the 'now' run ends; a re-run starts with the
            # steps before it marked before-rerun -> their outcome is read from the run it continues
            [void](& $inv @"
UPDATE cfg.FlowStepRun SET State = N'Failed' WHERE FlowRunId = N'now' AND Job = N'publicip';
UPDATE cfg.FlowStepRun SET State = N'Failed' WHERE FlowRunId = N'now' AND Job = N'risk-analysis-detailed';
UPDATE cfg.FlowRun SET State = N'Failed' WHERE FlowRunId = N'now';
-- a run CANCELLED before its public IP step started (Skipped, never started): never the run the step's outcome is read from
INSERT cfg.FlowRun (FlowRunId, Day, Trg, State, StartedUtc) VALUES (N'cancelled', N'2026-11-13', N'manual', N'Cancelled', '2026-11-13T01:00:00');
INSERT cfg.FlowStepRun (FlowRunId, StepOrder, GroupNo, Job, State, ErrorClass, StartedUtc) VALUES (N'cancelled', 5, 1, N'publicip', N'Skipped', N'cancelled', NULL);
INSERT cfg.FlowRun (FlowRunId, Day, Trg, FromStep, State, StartedUtc) VALUES (N'rerun', N'2026-11-13', N'rerun', N'risk-analysis-detailed', N'Running', '2026-11-13T02:00:00');
INSERT cfg.FlowStepRun (FlowRunId, StepOrder, GroupNo, Job, State, ErrorClass, Error, StartedUtc) VALUES
 (N'rerun', 1, 1, N'ptc', N'Skipped', N'before-rerun', N'before the re-run', NULL), (N'rerun', 5, 1, N'publicip', N'Skipped', N'before-rerun', N'before the re-run', NULL),
 (N'rerun', 6, 2, N'asset-correlation', N'Skipped', N'before-rerun', N'before the re-run', NULL), (N'rerun', 8, 3, N'risk-analysis-detailed', N'Running', NULL, NULL, '2026-11-13T02:00:05');
"@ @{} 'nonquery')
            $re = @(& $inv (Get-SIFlowStepOutcomeSql) @{ Job = 'risk-analysis-detailed' } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            @($re | Where-Object { [string]$_['Job'] -eq 'publicip' })[0]['PrevState'] | Should -Be 'Failed' -Because 'the step''s outcome in the run the re-run continues -- never the cancelled run where it never started'
            @($re | Where-Object { [string]$_['Job'] -eq 'publicip' })[0]['PrevRunId'] | Should -Be 'now'
            $rv = Get-SIFlowStepVerdict -Rows $re
            $rv.Known | Should -BeTrue; $rv.Trusted | Should -BeFalse; $rv.FlowRunId | Should -Be 'rerun'
            $rv.Why | Should -Match 'the public IP collection step failed in the run this re-run continues'
            # A SECOND re-run: the run before it is itself a re-run (its public IP row is before-rerun) -> still read from 'now'
            [void](& $inv @"
UPDATE cfg.FlowStepRun SET State = N'Success' WHERE FlowRunId = N'rerun' AND Job = N'risk-analysis-detailed';
UPDATE cfg.FlowRun SET State = N'Succeeded' WHERE FlowRunId = N'rerun';
INSERT cfg.FlowRun (FlowRunId, Day, Trg, FromStep, State, StartedUtc) VALUES (N'rerun2', N'2026-11-13', N'rerun', N'risk-analysis-detailed', N'Running', '2026-11-13T03:00:00');
INSERT cfg.FlowStepRun (FlowRunId, StepOrder, GroupNo, Job, State, ErrorClass, StartedUtc) VALUES
 (N'rerun2', 5, 1, N'publicip', N'Skipped', N'before-rerun', NULL), (N'rerun2', 8, 3, N'risk-analysis-detailed', N'Running', NULL, '2026-11-13T03:00:05');
"@ @{} 'nonquery')
            $re2 = @(& $inv (Get-SIFlowStepOutcomeSql) @{ Job = 'risk-analysis-detailed' } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            @($re2 | Where-Object { [string]$_['Job'] -eq 'publicip' })[0]['PrevRunId'] | Should -Be 'now' -Because 'an earlier re-run that did not run the step is skipped'
            (Get-SIFlowStepVerdict -Rows $re2).Trusted | Should -BeFalse
            # outside a pipeline run (no running step of the job): no rows -> not known
            (Get-SIFlowStepVerdict -Rows @(& $inv (Get-SIFlowStepOutcomeSql) @{ Job = 'risk-analysis' } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })).Known | Should -BeFalse
        } finally {
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            try { [void](& $master "IF DB_ID(N'$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END" @{} 'nonquery') } catch { }
        }
    }
    It 'REAL SQL: a database without the pipeline''s tables answers no rows (never an error)' -Skip:(-not $script:LocalSql) {
        $db = 'siflow0_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalInvoke 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            @(& (New-LocalInvoke $db) (Get-SIFlowStepOutcomeSql) @{ Job = 'risk-analysis-detailed' } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }).Count | Should -Be 0
        } finally {
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            try { [void](& $master "IF DB_ID(N'$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END" @{} 'nonquery') } catch { }
        }
    }
}

Describe 'Get-SIDataUpstreamTrust -- the collection is trusted only when it was built on whole profile data' {
    It 'every source run ended success: trusted' {
        $t = Get-SIDataUpstreamTrust -Query (Rows @((Rh endpoint success), (Rh identity success), (Rh azure success)))
        $t.Trusted | Should -BeTrue; $t.Known | Should -BeTrue
    }
    It 'NEGATIVE: an endpoint run that ended success-partial (live 2026-11-12) -> NOT trusted, said why' {
        $t = Get-SIDataUpstreamTrust -Query (Rows @((Rh endpoint 'success-partial' 'Enrich: INCOMPLETE'), (Rh identity success)))
        $t.Trusted | Should -BeFalse; $t.Known | Should -BeTrue
        $t.Why | Should -Match 'not trusted: it was built on incomplete profile data: the newest endpoint profile run ended ''success-partial'''
    }
    It 'ONLY the identity run''s role read partial (#899 RolesOnly): trusted -- those reports keep their last complete result' {
        $t = Get-SIDataUpstreamTrust -Query (Rows @((Rh identity 'success-partial' 'entra-roles-partial: the role read was not complete'), (Rh endpoint success)))
        $t.Trusted | Should -BeTrue; $t.Known | Should -BeTrue
        $t.Why | Should -Match 'only the Entra role read'
    }
    It 'NEGATIVE: the role read AND another partial source -> NOT trusted' {
        $t = Get-SIDataUpstreamTrust -Query (Rows @((Rh identity 'success-partial' 'entra-roles-partial: x'), (Rh azure 'success-partial' 'LA write failed')))
        $t.Trusted | Should -BeFalse
    }
    It 'a source that ended error published nothing (the previous whole snapshot is used): trusted, as Risk Analysis decides' {
        (Get-SIDataUpstreamTrust -Query (Rows @((Rh endpoint error)))).Trusted | Should -BeTrue
    }
    It 'the read fails: Known false, NOT held on suspicion ("hold only on real failure"), never throws' {
        $t = Get-SIDataUpstreamTrust -Query { param($kql) throw 'Log Analytics answered 503' }
        $t.Known | Should -BeFalse; $t.Trusted | Should -BeTrue; $t.Why | Should -Match '503'
        (Get-SIDataUpstreamTrust).Known | Should -BeFalse -Because 'no query seam = not checked, said'
    }
    It 'it asks the same records Risk Analysis asks (Get-SIUpstreamRunHealthKql)' {
        $script:Asked = ''
        $null = Get-SIDataUpstreamTrust -Query { param($kql) $script:Asked = $kql; @() }
        $script:Asked | Should -Be (Get-SIUpstreamRunHealthKql)
    }
}

Describe 'WIRING -- the data sync holds BOTH data-out paths on a collection that is not trusted' {
    It 'read once, before the hand-off; a failed read is said and holds nothing' {
        $script:Sync | Should -Match '\$upstreamTrust = if \(Get-Command -Name Get-SIDataUpstreamTrust -ErrorAction SilentlyContinue\) \{ Get-SIDataUpstreamTrust -Query \$query \}'
        ([regex]::Matches($script:Sync, 'Get-SIDataUpstreamTrust -Query')).Count | Should -Be 1 -Because 'one read per sync'
        ([regex]::Matches($script:Sync, 'Get-SIDataCollectionTrust -Invoke')).Count | Should -Be 1 -Because 'one place reads the verdict: the judgement of the collection being sent'
        $script:Sync.IndexOf('$upstreamTrust = if') | Should -BeLessThan $script:Sync.IndexOf('$onFindingsStored = {')
        $script:Sync | Should -Match "Known = \`$false; Why = 'the check of the source runs is not loaded'" -Because 'a missing check never throws (#1227): not checked, said'
    }
    It 'the data-out job''s mark is held, with the reason' {
        $script:Sync | Should -Match "\`$sentTrust = & \`$judgeSent \`$DataModel 'the data-out job'"
        $script:Sync | Should -Match '\$hold = \[bool\]\$os\.OnStored -or -not \[bool\]\$os\.Known -or \(\$sentTrust\.Known -and -not \$sentTrust\.Trusted\)'
        $script:Sync | Should -Match 'elseif \(\$sentTrust\.Known -and -not \$sentTrust\.Trusted\) \{ \[string\]\$sentTrust\.Why \}'
    }
    It 'the sync''s own fallback (no data-out job) is held too, judged by the collection it sends' {
        $script:Sync | Should -Match "(?m)^\`$fallbackTrust = & \`$judgeSent \`$dmPart 'this data sync'"
        $script:Sync | Should -Match '(?m)^if \(\$fallbackTrust\.Known -and -not \$fallbackTrust\.Trusted\) \{ \$holdOutputs = \$true \}'
        $script:Sync.IndexOf('if ($fallbackTrust.Known -and -not $fallbackTrust.Trusted) { $holdOutputs = $true }') | Should -BeGreaterThan $script:Sync.IndexOf('$holdOutputs = [bool]$onStored.OnStored')
    }
}

Describe '#1237 A HELD INSTALL NEVER GOES QUIET (Invardia 2026-11-13: the held output on the heartbeat, the code on the run report)' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatJob.ps1')
        if (-not (Get-Command -Name Get-SIHeartbeatDataOut -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatFields.ps1') }
        $script:T0 = [datetime]::SpecifyKind([datetime]'2026-11-13T02:00:00', 'Utc')
        $script:Untrusted = [pscustomobject]@{ Known = $true; Trusted = $false; Why = 'this collection is not trusted: it was built on a run that did not finish every step' }
        $script:TrustedV = [pscustomobject]@{ Known = $true; Trusted = $true; Why = '' }
        $script:UnknownV = [pscustomobject]@{ Known = $false; Trusted = $true; Why = 'not read' }
        # the newest run of the output: a complete send the night before (the target has that collection)
        $script:HbRuns = @(
            [pscustomobject]@{ K = 'batch'; OutputId = 'servicenow-ci'; BatchId = 'run-1:servicenow-ci'; RunId = 'run-1'; State = 'complete'; StartedAt = $script:T0.AddHours(-24); EndedAt = $script:T0.AddHours(-23)
                               Phase = 'close'; RowsPlanned = 100; RowsSent = 100; RowsHeld = 0; KeptOpenRows = 0; LastProgressUtc = $script:T0.AddHours(-23); Reason = $null }
            [pscustomobject]@{ K = 'run'; OutputId = 'servicenow-ci'; BatchId = $null; RunId = 'run-1'; State = 'success'; StartedAt = $script:T0.AddHours(-24); EndedAt = $script:T0.AddHours(-23); Phase = $null
                               RowsPlanned = $null; RowsSent = $null; RowsHeld = $null; KeptOpenRows = $null; LastProgressUtc = $null; Reason = $null })
        function script:TrustRow([string]$Value) {
            [pscustomobject]@{ K = 'trust'; OutputId = $null; BatchId = $null; RunId = $null; State = $null; StartedAt = $null; EndedAt = $script:T0; Phase = $null
                               RowsPlanned = $null; RowsSent = $null; RowsHeld = $null; KeptOpenRows = $null; LastProgressUtc = $null; Reason = $Value }
        }
        # an in-memory settings database (cfg.InstallState 'DataOutTrust') and a data database that answers the newest trusted collection
        $script:Mem = @{ Value = $null; Writes = 0; Newest = $null }
        $script:SetInv = { param($sql, $p, $mode)
            if ($sql -match 'SELECT Value, UpdatedAt FROM cfg\.InstallState') { if ($null -eq $script:Mem.Value) { return , @() }; return , @(@{ Value = $script:Mem.Value; UpdatedAt = $script:T0 }) }
            if ($sql -match 'INSERT cfg\.InstallState') { $script:Mem.Value = [string]$p['Value']; $script:Mem.Writes++; return 1 }
            throw "unexpected: $sql" }
        $script:DataInv = { param($sql, $p, $mode) if ($sql -match 'sidata\.CollectionTrust') { return $script:Mem.Newest }; throw "unexpected: $sql" }
    }
    BeforeEach { $script:Mem.Value = $null; $script:Mem.Writes = 0; $script:Mem.Newest = $null; $global:SI_RunNoteCodes = $null }
    AfterAll { $global:SI_RunNoteCodes = $null }

    It 'two held runs in a row: heldSinceUtc stays the FIRST one''s time; the newest trusted collection is kept' {
        $a = Get-SIDataOutTrustNext -Previous $null -Verdict $script:Untrusted -CollectionTime '2026-11-13T01:00:00.123' -NowUtc $script:T0 -NewestTrusted ([datetime]'2026-11-12T01:00:00')
        $a.Held | Should -BeTrue; $a.HeldSinceUtc | Should -Be '2026-11-13T02:00:00Z'; $a.NewestTrustedUtc | Should -Be '2026-11-12T01:00:00Z'; $a.CollectionUtc | Should -Be '2026-11-13T01:00:00Z'
        $b = Get-SIDataOutTrustNext -Previous $a -Verdict $script:Untrusted -CollectionTime '2026-11-14T01:00:00' -NowUtc $script:T0.AddDays(1) -NewestTrusted $null
        $b.Held | Should -BeTrue
        $b.HeldSinceUtc | Should -Be '2026-11-13T02:00:00Z' -Because 'the row of held runs goes on'
        $b.NewestTrustedUtc | Should -Be '2026-11-12T01:00:00Z' -Because 'a read that gave nothing keeps the one known'
        $b.AtUtc | Should -Be '2026-11-14T02:00:00Z'
    }
    It 'a trusted run in between ends the row: not held, no since, the newest trusted = that collection; the next hold starts a NEW row' {
        $a = Get-SIDataOutTrustNext -Previous $null -Verdict $script:Untrusted -CollectionTime '2026-11-13T01:00:00' -NowUtc $script:T0 -NewestTrusted $null
        $t = Get-SIDataOutTrustNext -Previous $a -Verdict $script:TrustedV -CollectionTime '2026-11-14T01:00:00' -NowUtc $script:T0.AddDays(1) -NewestTrusted $null
        $t.Held | Should -BeFalse; $t.HeldSinceUtc | Should -BeNullOrEmpty; $t.NewestTrustedUtc | Should -Be '2026-11-14T01:00:00Z'
        $c = Get-SIDataOutTrustNext -Previous $t -Verdict $script:Untrusted -CollectionTime '2026-11-15T01:00:00' -NowUtc $script:T0.AddDays(2) -NewestTrusted ([datetime]'2026-11-14T01:00:00')
        $c.Held | Should -BeTrue
        $c.HeldSinceUtc | Should -Be '2026-11-15T02:00:00Z' -Because 'a new row of held runs'
        $c.NewestTrustedUtc | Should -Be '2026-11-14T01:00:00Z'
    }
    It 'NEGATIVE: a verdict that is NOT known holds nothing (never held on suspicion) and never moves the newest trusted collection' {
        $a = Get-SIDataOutTrustNext -Previous $null -Verdict $script:Untrusted -CollectionTime '2026-11-13T01:00:00' -NowUtc $script:T0 -NewestTrusted ([datetime]'2026-11-12T01:00:00')
        $u = Get-SIDataOutTrustNext -Previous $a -Verdict $script:UnknownV -CollectionTime '2026-11-14T01:00:00' -NowUtc $script:T0.AddDays(1) -NewestTrusted $null
        $u.Held | Should -BeFalse; $u.HeldSinceUtc | Should -BeNullOrEmpty; $u.NewestTrustedUtc | Should -Be '2026-11-12T01:00:00Z'
        (Get-SIDataOutTrustNext -Previous $null -Verdict $null -CollectionTime $null -NowUtc $script:T0 -NewestTrusted $null).Held | Should -BeFalse
    }
    It 'the stored value: plain pairs (no JSON: a JSON reader turns ISO texts into local times), at most 400, read back exactly' {
        $r = Get-SIDataOutTrustNext -Previous $null -Verdict $script:Untrusted -CollectionTime '2026-11-13T01:00:00' -NowUtc $script:T0 -NewestTrusted ([datetime]'2026-11-12T01:00:00')
        $txt = ConvertTo-SIDataOutTrustText -Record $r
        $txt | Should -Be 'held=1;since=2026-11-13T02:00:00Z;collection=2026-11-13T01:00:00Z;trusted=2026-11-12T01:00:00Z;at=2026-11-13T02:00:00Z'
        $txt.Length | Should -BeLessOrEqual 400
        $back = ConvertFrom-SIDataOutTrustText $txt
        foreach ($k in 'Held', 'HeldSinceUtc', 'CollectionUtc', 'NewestTrustedUtc', 'AtUtc') { $back.$k | Should -Be $r.$k -Because $k }
        ConvertFrom-SIDataOutTrustText 'nonsense' | Should -BeNullOrEmpty
        $plain = ConvertTo-SIDataOutTrustText -Record (Get-SIDataOutTrustNext -Previous $null -Verdict $script:TrustedV -CollectionTime $null -NowUtc $script:T0 -NewestTrusted $null)
        $plain | Should -Be 'held=0;at=2026-11-13T02:00:00Z' -Because 'a time not known is left out'
    }
    It 'Save: each run replaces the ONE record; two held runs keep the first since; a failing database never throws and writes nothing' {
        $a = Save-SIDataOutTrustRecord -SettingsInvoke $script:SetInv -DataInvoke $script:DataInv -Verdict $script:Untrusted -CollectionTime '2026-11-13T01:00:00' -NowUtc $script:T0
        $a.HeldSinceUtc | Should -Be '2026-11-13T02:00:00Z'
        $script:Mem.Newest = [datetime]'2026-11-11T01:00:00'
        $b = Save-SIDataOutTrustRecord -SettingsInvoke $script:SetInv -DataInvoke $script:DataInv -Verdict $script:Untrusted -CollectionTime '2026-11-14T01:00:00' -NowUtc $script:T0.AddDays(1)
        $b.HeldSinceUtc | Should -Be '2026-11-13T02:00:00Z'; $b.NewestTrustedUtc | Should -Be '2026-11-11T01:00:00Z'
        $script:Mem.Writes | Should -Be 2
        (ConvertFrom-SIDataOutTrustText $script:Mem.Value).HeldSinceUtc | Should -Be '2026-11-13T02:00:00Z'
        Save-SIDataOutTrustRecord -SettingsInvoke { param($s, $p, $m) throw 'SQL error 40613' } -Verdict $script:Untrusted -NowUtc $script:T0 | Should -BeNullOrEmpty
        Save-SIDataOutTrustRecord -SettingsInvoke $null -Verdict $script:Untrusted -NowUtc $script:T0 | Should -BeNullOrEmpty
        # the newest trusted read failing: still recorded (the soft key is then left out)
        $script:Mem.Value = $null
        $c = Save-SIDataOutTrustRecord -SettingsInvoke $script:SetInv -DataInvoke { param($s, $p, $m) throw 'no table' } -Verdict $script:Untrusted -CollectionTime '2026-11-13T01:00:00' -NowUtc $script:T0
        $c.Held | Should -BeTrue; $c.NewestTrustedUtc | Should -BeNullOrEmpty
    }
    It 'the WIRE NAMES and FORMAT Invardia accepts (its contract is closed: any other key is dropped): heldReason untrusted, heldSinceUtc, newestTrustedUtc as ISO-8601 UTC' {
        $c = Get-SIHeartbeatFieldsContract
        $c.DataOutTrustHeldReason | Should -BeExactly 'untrusted'
        $c.DataOutHeldReasons | Should -Contain 'untrusted'
        @($c.DataOutTrustFields) | Should -Be @('heldSinceUtc', 'newestTrustedUtc')
        @($c.Fields.DataOut) | Should -Not -Contain 'heldSinceUtc' -Because 'the two are SOFT: never part of the fixed keys, sent only when known'
        $d = (Get-SIHeartbeatDataOut -Rows (@($script:HbRuns) + @(TrustRow 'held=1;since=2026-11-13T02:00:00Z;collection=2026-11-13T01:00:00Z;trusted=2026-11-12T01:00:00Z;at=2026-11-13T02:00:00Z')) -NowUtc $script:T0.AddHours(1))   # ONE array: never wrapped in @( ) (it would hold the array as its one element)
        $j = ConvertTo-Json -InputObject $d -Depth 5 -Compress
        $j | Should -Match '"heldReason":"untrusted"'
        $j | Should -Match '"heldSinceUtc":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"'
        $j | Should -Match '"newestTrustedUtc":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"'
        $base = Get-SIHeartbeatDataOutFieldNames   # ONE string[]: assigned first, never wrapped in @( )
        $allowed = @($base) + @($c.DataOutTrustFields)
        foreach ($k in @($d[0].PSObject.Properties.Name)) { $allowed | Should -Contain $k -Because 'no key outside the agreed ones' }
    }
    It 'the heartbeat: the hold is the newest attempt -- phase / lastResult held, heldReason untrusted, the two soft keys LAST, and it passes the validator' {
        $d = (Get-SIHeartbeatDataOut -Rows (@($script:HbRuns) + @(TrustRow 'held=1;since=2026-11-13T02:00:00Z;collection=2026-11-13T01:00:00Z;trusted=2026-11-12T01:00:00Z;at=2026-11-14T02:00:00Z')) -NowUtc $script:T0.AddDays(1))
        $d.Count | Should -Be 1
        $e = $d[0]
        $e.phase | Should -Be 'held'; $e.lastResult | Should -Be 'held'; $e.heldReason | Should -BeExactly 'untrusted'
        $e.heldSinceUtc | Should -Be '2026-11-13T02:00:00Z'; $e.newestTrustedUtc | Should -Be '2026-11-12T01:00:00Z'
        $e.startedUtc | Should -Be '2026-11-14T02:00:00Z'; $e.lastEndedUtc | Should -Be '2026-11-14T02:00:00Z'
        $e.rowsSent | Should -BeNullOrEmpty -Because 'nothing was sent from the held collection -- the old run''s counts are not this attempt''s'
        $e.batchId | Should -BeNullOrEmpty; $e.lastErrorCode | Should -BeNullOrEmpty
        @($e.PSObject.Properties.Name)[-2..-1] | Should -Be @('heldSinceUtc', 'newestTrustedUtc')
        Test-SIHeartbeatField -Name DataOut -Value ([object[]]$d) | Should -Be ''
    }
    It 'soft: a time not known is LEFT OUT (never null) and the entry still passes; a null or non-ISO soft key is refused' {
        $d = (Get-SIHeartbeatDataOut -Rows (@($script:HbRuns) + @(TrustRow 'held=1;since=2026-11-13T02:00:00Z;at=2026-11-13T02:00:00Z')) -NowUtc $script:T0.AddHours(1))
        $d[0].heldReason | Should -Be 'untrusted'
        $d[0].PSObject.Properties['newestTrustedUtc'] | Should -BeNullOrEmpty
        $d[0].heldSinceUtc | Should -Be '2026-11-13T02:00:00Z'
        Test-SIHeartbeatField -Name DataOut -Value ([object[]]$d) | Should -Be ''
        $bad = $d[0].PSObject.Copy(); $bad.heldSinceUtc = $null
        Test-SIHeartbeatField -Name DataOut -Value ([object[]]@($bad)) | Should -Match 'heldSinceUtc is not ISO-8601 UTC'
        $bad2 = $d[0].PSObject.Copy(); $bad2.heldSinceUtc = '13-11-2026 02:00'
        Test-SIHeartbeatField -Name DataOut -Value ([object[]]@($bad2)) | Should -Match 'heldSinceUtc is not ISO-8601 UTC'
    }
    It 'NEGATIVE: not held, a hold OLDER than the output''s newest run, a running send, or the switch off -> the entry is as before (no soft keys)' {
        $plain = (Get-SIHeartbeatDataOut -Rows $script:HbRuns -NowUtc $script:T0)
        foreach ($tv in 'held=0;trusted=2026-11-13T01:00:00Z;at=2026-11-13T02:00:00Z', 'held=1;since=2026-11-11T02:00:00Z;at=2026-11-11T02:00:00Z') {
            $d = (Get-SIHeartbeatDataOut -Rows (@($script:HbRuns) + @(TrustRow $tv)) -NowUtc $script:T0)
            $d[0].phase | Should -Be 'idle' -Because $tv
            $d[0].lastResult | Should -Be 'complete'; $d[0].heldReason | Should -BeNullOrEmpty
            @($d[0].PSObject.Properties.Name) | Should -Be @($plain[0].PSObject.Properties.Name)
        }
        $running = [pscustomobject]@{ K = 'batch'; OutputId = 'servicenow-ci'; BatchId = 'run-2:servicenow-ci'; RunId = 'run-2'; State = 'writing'; StartedAt = $script:T0.AddMinutes(10); EndedAt = $null
                                      Phase = 'send'; RowsPlanned = 10; RowsSent = 5; RowsHeld = 0; KeptOpenRows = 0; LastProgressUtc = $script:T0.AddMinutes(11); Reason = $null }
        $r = (Get-SIHeartbeatDataOut -Rows (@($script:HbRuns | Where-Object K -eq 'run') + @($running) + @(TrustRow 'held=1;since=2026-11-13T02:00:00Z;at=2026-11-13T02:00:00Z')) -NowUtc $script:T0.AddMinutes(12))
        $r[0].phase | Should -Be 'send' -Because 'a running send is never changed'
        $c = Get-SIHeartbeatFieldsContract; $was = $c.DataOutSendTrustHold
        try {
            $c.DataOutSendTrustHold = $false
            $o = (Get-SIHeartbeatDataOut -Rows (@($script:HbRuns) + @(TrustRow 'held=1;since=2026-11-13T02:00:00Z;at=2026-11-13T02:00:00Z')) -NowUtc $script:T0.AddHours(1))
            $o[0].phase | Should -Be 'idle'; $o[0].PSObject.Properties['heldSinceUtc'] | Should -BeNullOrEmpty
        } finally { $c.DataOutSendTrustHold = $was }
    }
    It 'the heartbeat reads the record in its ONE data-out read (cfg.InstallState DataOutTrust, guarded)' {
        $s = Get-SIHeartbeatDataOutSql
        $s | Should -Match ([regex]::Escape("INSERT @r (K, EndedAt, Reason) SELECT N'trust', UpdatedAt, LEFT(Value, 1000) FROM cfg.InstallState WHERE Name = N'DataOutTrust';"))
        $s | Should -Match ([regex]::Escape("IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL"))
    }
    It 'the run''s note si-out-1501: once on a holding run; none on a trusted run or a verdict not known' {
        Add-SIDataOutTrustNote -Verdict $script:TrustedV -Record $null
        Add-SIDataOutTrustNote -Verdict $script:UnknownV -Record $null
        ($global:SI_RunNoteCodes | Measure-Object).Count | Should -Be 0
        $rec = Get-SIDataOutTrustNext -Previous $null -Verdict $script:Untrusted -CollectionTime '2026-11-13T01:00:00' -NowUtc $script:T0 -NewestTrusted ([datetime]'2026-11-12T01:00:00')
        Add-SIDataOutTrustNote -Verdict $script:Untrusted -Record $rec; Add-SIDataOutTrustNote -Verdict $script:Untrusted -Record $rec
        ($global:SI_RunNoteCodes | Measure-Object).Count | Should -Be 1 -Because 'once per run (piped: never @() around a List)'
        $n = $global:SI_RunNoteCodes | Select-Object -First 1
        $n.Code | Should -Be 'si-out-1501'; $n.Step | Should -Be 'data-out'
        $n.Text | Should -Match 'held since 2026-11-13T02:00:00Z'
        $n.Text | Should -Match 'newest trusted collection is of 2026-11-12T01:00:00Z'
    }
    It 'the RUN REPORT carries si-out-1501 on a holding run and NOT on a sending run' {
        $savedEp = $env:SI_TELEMETRY_ENDPOINT
        try {
            $env:SI_TELEMETRY_ENDPOINT = 'https://127.0.0.1:9/api/uplink/v1/report'
            if (-not (Get-Command -Name Send-SITelemetryRunEnd -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1') }
            $script:Posts1237 = New-Object System.Collections.Generic.List[object]
            $stub = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $script:Posts1237.Add(($Record | ConvertTo-Json -Depth 8 -Compress | ConvertFrom-Json)); [pscustomobject]@{ Status = 'ok'; Reason = 'accepted' } }
            $ctx = [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://stub.example.test/report'; AccessCode = 'inv-TESTKEYabcdefghijklmnopqrstuvwxyz'; Edition = 'pro'; LicenceState = 'valid'
                                      Version = '3.1.16.202611130000'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = ''; TenantId = '7f3e2a10-4b5c-4d6e-8f90-a1b2c3d4e5f6'; StateDirectory = $TestDrive; Endpoints = @() }
            $sendRun = {
                $script:Posts1237.Clear(); $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_Telemetry_Enabled = $null
                $rc = [pscustomobject]@{ RunId = 'run-1'; Engine = 'asset-datasync'; ShardIndex = 0; StartedAt = $script:T0 }
                $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'success' -ErrorMessage '' -Context $ctx -Transport $stub -Now $script:T0.AddHours(1) -NoHeartbeat
                @($script:Posts1237 | Where-Object { "$($_.Kind)" -eq 'run' }) | Select-Object -First 1
            }
            # a holding run
            Add-SIDataOutTrustNote -Verdict $script:Untrusted -Record $null
            $held = & $sendRun
            $held | Should -Not -BeNullOrEmpty
            $items = @($held.Reports | Where-Object { $_ -and $_.Code -eq 'si-out-1501' })
            $items.Count | Should -Be 1
            $items[0].Report | Should -Be 'asset-datasync-data-out'
            $items[0].CauseClass | Should -Be 'count-less'; $items[0].Action | Should -Be 'support'
            # a sending run: a trusted verdict adds no note
            $global:SI_RunNoteCodes = $null
            Add-SIDataOutTrustNote -Verdict $script:TrustedV -Record $null
            $sent = & $sendRun
            $sent | Should -Not -BeNullOrEmpty
            @($sent.Reports | Where-Object { $_ -and $_.Code -eq 'si-out-1501' }).Count | Should -Be 0
        } finally {
            $env:SI_TELEMETRY_ENDPOINT = $savedEp
            $global:SI_TelemetryHalted = $null; $global:SI_TelemetryContext = $null; $global:SI_Telemetry_Enabled = $null; $global:SI_RunNoteCodes = $null
        }
    }
    It 'the catalogue: si-out-1501 in its own family, the agreed shape, P2, a ticket, whoActs product -- both copies byte-identical' {
        $a = [IO.File]::ReadAllBytes((Join-Path $script:SIRoot 'data-model\errors.locked.json'))
        $b = [IO.File]::ReadAllBytes((Join-Path $script:SIRoot 'pro-management\src\SI.Management.Core\ProData\DataModel\errors.locked.json'))
        [Convert]::ToBase64String($a) | Should -Be ([Convert]::ToBase64String($b))
        $cat = @([Text.Encoding]::UTF8.GetString($a) | ConvertFrom-Json)
        $found = @($cat | Where-Object { $_.code -eq 'si-out-1501' })
        $found.Count | Should -Be 1
        $e = $found[0]
        @($e.PSObject.Properties.Name) | Should -Be @('code', 'title', 'causeClass', 'appliesTo', 'customerText', 'internalNote', 'whoActs', 'priority', 'opensTicket', 'action', 'fixedIn', 'waitForFix', 'steps', 'lesson', 'since')
        $e.title | Should -BeExactly 'Data out is held: the collection is not trusted'
        $e.priority | Should -Be 'P2'; $e.opensTicket | Should -BeTrue; $e.whoActs | Should -Be 'product'
        $e.code | Should -MatchExactly '^si-out-15\d{2}$'
        $e.customerText | Should -Not -Match '#\d|si-out|CollectionTrust|InstallState' -Because 'plain words for the customer'
        @($cat | Where-Object { $_.code -like 'si-out-*' }).Count | Should -Be 1
    }
    It 'WIRING: the data sync records every decision after the fallback''s judgement (never in a dry run) and adds the note' {
        $script:Sync | Should -Match ([regex]::Escape('$dataOutHand.Trust = $sentTrust'))
        $script:Sync | Should -Match ([regex]::Escape('if (-not $DryRun -and (Get-Command -Name Save-SIDataOutTrustRecord -ErrorAction SilentlyContinue)) {'))
        $script:Sync | Should -Match ([regex]::Escape('$trustUsed = $(if ($dataOutHand.Trust) { $dataOutHand.Trust } else { $fallbackTrust })'))
        $script:Sync | Should -Match ([regex]::Escape('Add-SIDataOutTrustNote -Verdict $trustUsed -Record $trustRec'))
        $script:Sync.IndexOf('Save-SIDataOutTrustRecord -SettingsInvoke') | Should -BeGreaterThan $script:Sync.IndexOf('if ($fallbackTrust.Known -and -not $fallbackTrust.Trusted) { $holdOutputs = $true }')
        $script:Sync.IndexOf('Save-SIDataOutTrustRecord -SettingsInvoke') | Should -BeLessThan $script:Sync.IndexOf('Send-SITelemetryRunEnd -RunContext $runContext')
    }
    It 'REAL SQL: the shipped cfg.InstallState and sidata.CollectionTrust -- two held runs, the newest trusted read, the heartbeat''s read gives the record back' -Skip:(-not $script:LocalSql) {
        $db = 'siheld_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalInvoke 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = New-LocalInvoke $db
            [void](& $inv $script:Schema @{} 'nonquery')
            [void](& $inv "IF SCHEMA_ID(N'cfg') IS NULL EXEC (N'CREATE SCHEMA cfg');" @{} 'nonquery')
            $settings = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'sql\si-pro-settings.sql')
            $ddl = [regex]::Match($settings, "(?s)IF OBJECT_ID\('cfg\.InstallState'\) IS NULL\s*CREATE TABLE cfg\.InstallState \(.*?\n\);").Value
            $ddl | Should -Not -BeNullOrEmpty -Because 'the shipped DDL of cfg.InstallState is used, not a copy'
            [void](& $inv $ddl @{} 'nonquery')
            [void](& $inv (Get-RACollectionTrustWriteSql) @{ CollectionTime = '2026-11-11T19:00:00.000'; Grain = 'Detailed'; Trusted = 1; Why = '' } 'scalar')
            [void](& $inv (Get-RACollectionTrustWriteSql) @{ CollectionTime = '2026-11-12T19:00:00.250'; Grain = 'Detailed'; Trusted = 0; Why = 'x' } 'scalar')
            [void](& $inv (Get-RACollectionTrustWriteSql) @{ CollectionTime = '2026-11-13T19:00:00.500'; Grain = 'Detailed'; Trusted = 0; Why = 'y' } 'scalar')
            $a = Save-SIDataOutTrustRecord -SettingsInvoke $inv -DataInvoke $inv -Verdict $script:Untrusted -CollectionTime '2026-11-12T19:00:00.250' -NowUtc ([datetime]::SpecifyKind([datetime]'2026-11-12T22:00:00', 'Utc')) -By 'test'
            $a | Should -Not -BeNullOrEmpty
            $a.NewestTrustedUtc | Should -Be '2026-11-11T19:00:00Z'
            $b = Save-SIDataOutTrustRecord -SettingsInvoke $inv -DataInvoke $inv -Verdict $script:Untrusted -CollectionTime ([datetime]::SpecifyKind([datetime]'2026-11-13T19:00:00.500', 'Utc')) -NowUtc ([datetime]::SpecifyKind([datetime]'2026-11-13T22:00:00', 'Utc')) -By 'test'
            $b.HeldSinceUtc | Should -Be '2026-11-12T22:00:00Z'; $b.NewestTrustedUtc | Should -Be '2026-11-11T19:00:00Z'
            (& $inv "SELECT COUNT(*) FROM cfg.InstallState WHERE Name = N'DataOutTrust'" @{} 'scalar') | Should -Be 1 -Because 'one row, replaced'
            $rows = @(& $inv (Get-SIHeartbeatDataOutSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            $tr = @($rows | Where-Object { [string]$_['K'] -eq 'trust' })
            $tr.Count | Should -Be 1
            $t = Get-SIHeartbeatDataOutTrust -Row $tr[0]
            $t.Held | Should -BeTrue; $t.HeldSinceUtc | Should -Be '2026-11-12T22:00:00Z'; $t.NewestTrustedUtc | Should -Be '2026-11-11T19:00:00Z'; $t.AtUtc | Should -Be '2026-11-13T22:00:00Z'
            # a trusted run ends the row
            $c = Save-SIDataOutTrustRecord -SettingsInvoke $inv -DataInvoke $inv -Verdict $script:TrustedV -CollectionTime '2026-11-14T19:00:00' -NowUtc ([datetime]::SpecifyKind([datetime]'2026-11-14T22:00:00', 'Utc')) -By 'test'
            $c.Held | Should -BeFalse; $c.NewestTrustedUtc | Should -Be '2026-11-14T19:00:00Z'
            (ConvertFrom-SIDataOutTrustText ([string](& $inv "SELECT Value FROM cfg.InstallState WHERE Name = N'DataOutTrust'" @{} 'scalar'))).Held | Should -BeFalse
        } finally {
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            try { [void](& $master "IF DB_ID(N'$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END" @{} 'nonquery') } catch { }
        }
    }
}
