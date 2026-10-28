#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- the data health cycle behind seams (the reads, the database, the clock, the random pick, the
    telemetry), so the whole cycle is tested on fixtures. The real reads are wired in ..\Invoke-SIDataHealth.ps1.

    -Sources: a hashtable of scriptblocks, one per source id of Get-SIDataHealthSourceCatalog, each returning the source's
    records as @{ Key ('<provider>:<id>', lower-case); Name; Created; Values = @{ <source field> = value } }. A source that
    THROWS (or one left out) is NOT CHECKED with the reason -- never "ok".
    -Defender: { param([string[]]$MdeIds) } -> MdeId -> the CVEs (ids, or @{ Cve; LastModified; Published }; a machine whose read failed: $null). Left out = check (b)
    and the 'vulnerabilities' source are not checked.
    -Invoke: the Pro database (stored records, the population of (b), the state, the writes).
#>

function Invoke-SIDataHealthCycle {
    <#
        One cycle. Never changes anything outside the Pro database. Returns @{ Results; Problems; Cycle; State; Previous;
        Overrides; Written; CycleId; Wire; Telemetry }.
          -Globals   the settings (margins) -- default the run's globals
          -Seed      the random pick (tests)
          -SendTelemetry { param($Record) } -> @{ Status }: the health record's transport (default: none -- the caller wires it)
    #>
    param([Parameter(Mandatory)][hashtable]$Sources, [scriptblock]$Defender, [scriptblock]$Invoke, [System.Collections.IDictionary]$Globals,
          [datetime]$NowUtc = [datetime]::UtcNow, [AllowNull()]$Seed, [switch]$DryRun, $TelemetryContext, [scriptblock]$SendTelemetry,
          # CR2: { param($Report, $Cve, $LastModified) } -> would that report keep the CVE (its own exclusions)? Not given = all.
          [scriptblock]$InScope,
          # why the caller built no -TelemetryContext (Get-SIDataHealthSendSkipReason) -- said in the log, never silent
          [AllowNull()][AllowEmptyString()][string]$TelemetrySkipReason,
          [scriptblock]$Log = { param($level, $msg) Write-Host ("[{0}] {1}" -f $level, $msg) })
    $margins = Get-SIDataHealthMargins -Globals $Globals
    $results = New-Object System.Collections.Generic.List[object]
    $problems = New-Object System.Collections.Generic.List[object]
    $started = $NowUtc.ToUniversalTime()
    $seedN = 0
    $nextSeed = { if ($null -eq $Seed) { $null } else { [int]$Seed + $script:dhSeedN } }
    $script:dhSeedN = 0
    $addResult = {
        # $drift (#747): the part of missing + mismatches explained by a change in the source after the collection
        param($kind, $name, $label, $sampled, $found, $missing, $mism, $margin, $verdict, $reason, $drift = 0)
        $results.Add([pscustomobject]@{ Kind = $kind; Name = $name; Label = $label; Sampled = [long]$sampled; Found = [long]$found; Missing = [long]$missing
            FieldMismatches = [long]$mism; Drift = [long]$drift; Margin = $margin; MarginPercent = [double]$margin.Percent; MarginMinimum = [int]$margin.Minimum
            Allowed = (Get-SIDataHealthAllowed -Sampled ([long]$sampled) -Margin $margin); Verdict = $verdict; Reason = [string]$reason })
    }
    $joinWhy = { param($a, $b) @(@([string]$a, [string]$b) | Where-Object { $_ }) -join '; ' }
    $canRead = [bool]$Invoke
    # ---------------- (a) collections ----------------
    foreach ($s in (Get-SIDataHealthSourceCatalog)) {
        if ($s.Id -eq 'vulnerabilities') { continue }
        $m = $margins[$s.Id]
        if (-not $Sources.ContainsKey($s.Id) -or $null -eq $Sources[$s.Id]) { & $addResult 'source' $s.Id $s.Label 0 0 0 0 $m 'not-used' ('the source {0} is not configured for the check' -f $s.Label); continue }
        if (-not $canRead) { & $addResult 'source' $s.Id $s.Label 0 0 0 0 $m 'not-checked' 'no Pro database -- the newest collection cannot be read'; continue }
        try {
            $feed = @(Read-SIDataHealthRows -Invoke $Invoke -Sql (Get-SIDataHealthNewestFeedSql) -Params @{ Provider = $s.Provider; RecordType = $s.RecordType }) | Select-Object -First 1
            $newest = Get-SIDataHealthItem $feed 'CollectionTime'
            $storedCount = 0L; $sc = Get-SIDataHealthItem $feed 'Records'; if ($null -ne $sc -and "$sc" -match '^\d+$') { $storedCount = [long]"$sc" }
            $rows = @(& $Sources[$s.Id] | Where-Object { $null -ne $_ })
            if ($null -eq (ConvertTo-SIDataHealthUtc $newest)) {
                # this install holds no collection of the source: nothing to compare (an empty source is simply ok)
                if ($rows.Count -eq 0) { & $addResult 'source' $s.Id $s.Label 0 0 0 0 $m 'ok' '' }
                else { & $addResult 'source' $s.Id $s.Label 0 0 0 0 $m 'not-used' ('SecurityInsight holds no collection of this source here ({0} record(s) in the source)' -f $rows.Count) }
                continue
            }
            $eligible = @(Get-SIDataHealthEligible -Rows $rows -NewestCollection $newest)
            $size = Get-SIDataHealthSampleSize -Count $eligible.Count
            $script:dhSeedN++
            $sample = @(Select-SIDataHealthSample -Items $eligible -Size $size -Seed (& $nextSeed))
            $stored = Read-SIDataHealthStored -Invoke $Invoke -Keys @($sample | ForEach-Object { [string](Get-SIDataHealthItem $_ 'Key') }) -Fields @($s.Fields | ForEach-Object { [string]$_.Stored })
            $cmp = Compare-SIDataHealthSource -Source $s -Sampled $sample -Stored $stored -NewestCollection $newest
            $v = Get-SIDataHealthVerdict -Sampled $cmp.Sampled -Differ (Get-SIDataHealthDiffer -Missing $cmp.Missing -Mismatches $cmp.FieldMismatches -Drift $cmp.Drift) -Margin $m -StoredCount $storedCount
            $why = ''
            if ($cmp.Sampled -eq 0 -and $storedCount -gt 0) { $why = ('the source answered with no records while the newest collection holds {0}' -f $storedCount) }
            $why = & $joinWhy $why (Format-SIDataHealthDriftText -Drift $cmp.Drift -Kind 'source')
            & $addResult 'source' $s.Id $s.Label $cmp.Sampled $cmp.Found $cmp.Missing $cmp.FieldMismatches $m $v $why $cmp.Drift
            foreach ($p in @($cmp.Problems)) { $problems.Add([pscustomobject]@{ Kind = 'source'; Name = $s.Id; RecordKey = [string]$p.Key; RecordName = [string]$p.Name; Problem = [string]$p.Problem }) }
        } catch {
            & $addResult 'source' $s.Id $s.Label 0 0 0 0 $m 'not-checked' ('{0} could not be read: {1}' -f $s.Label, $_.Exception.Message)
        }
    }
    # ---------------- (b) Risk Analysis + the 'vulnerabilities' source ----------------
    $vm = $margins['vulnerabilities']; $rm = $margins['risk-analysis']
    $vLabel = (Get-SIDataHealthSourceCatalog | Where-Object { $_.Id -eq 'vulnerabilities' }).Label
    if (-not $Defender) { & $addResult 'source' 'vulnerabilities' $vLabel 0 0 0 0 $vm 'not-used' 'Defender for Endpoint is not configured for the check' }
    elseif (-not $canRead) { & $addResult 'source' 'vulnerabilities' $vLabel 0 0 0 0 $vm 'not-checked' 'no Pro database -- the stored findings cannot be read' }
    else {
        try {
            $pop = @(Read-SIDataHealthRows -Invoke $Invoke -Sql (Get-SIDataHealthRaAssetsSql))
            $pop = @($pop | Where-Object { "$(Get-SIDataHealthItem $_ 'MdeId')".Trim() })
            if ($pop.Count -eq 0) {
                & $addResult 'source' 'vulnerabilities' $vLabel 0 0 0 0 $vm 'not-used' 'the newest complete collection holds no vulnerability findings to compare'
            } else {
                $script:dhSeedN++
                $sample = @(Select-SIDataHealthSample -Items $pop -Size (Get-SIDataHealthSampleSize -Count $pop.Count) -Seed (& $nextSeed))
                $ids = @($sample | ForEach-Object { ([string](Get-SIDataHealthItem $_ 'MdeId')).ToLowerInvariant() })
                $def = & $Defender $ids
                if ($null -eq $def) { $def = @{} }
                $stored = @(Read-SIDataHealthRows -Invoke $Invoke -Sql (Get-SIDataHealthRaFindingsSql) -Params @{ MdeIds = (ConvertTo-SIDataHealthJsonArray -Items $ids) })
                # the stored collection's time (#747): a CVE Defender published after it is drift, not a miss
                $collAt = $null; foreach ($p0 in $pop) { $collAt = Get-SIDataHealthItem $p0 'CollectionTime'; if ($null -ne $collAt) { break } }
                $vc = Compare-SIDataHealthVulnerabilities -Assets $sample -Defender $def -Stored $stored -InScope $InScope -CollectionTime $collAt
                if ($vc.Assets -eq 0) {
                    & $addResult 'source' 'vulnerabilities' $vLabel 0 0 0 0 $vm 'not-checked' ('Defender answered for none of the {0} sampled device(s)' -f $sample.Count)
                } else {
                    $why = ''; if ($vc.NotRead -gt 0) { $why = ('{0} of {1} sampled device(s) could not be read from Defender and were left out' -f $vc.NotRead, $sample.Count) }
                    $why = & $joinWhy $why (Format-SIDataHealthDriftText -Drift $vc.Source.Drift -NewSince $vc.Source.Drift -Kind 'source')
                    & $addResult 'source' 'vulnerabilities' $vLabel $vc.Source.Sampled $vc.Source.Found $vc.Source.Missing 0 $vm (Get-SIDataHealthVerdict -Sampled $vc.Source.Sampled -Differ (Get-SIDataHealthDiffer -Missing $vc.Source.Missing -Mismatches 0 -Drift $vc.Source.Drift) -Margin $vm) $why $vc.Source.Drift
                    foreach ($r in @($vc.Reports)) {
                        # extra = fixed since the collection; a missing CVE published after it -- both drift (#747), said, not counted
                        $rv = Get-SIDataHealthVerdict -Sampled $r.Sampled -Differ (Get-SIDataHealthDiffer -Missing $r.Missing -Mismatches $r.Extra -Drift $r.Drift) -Margin $rm
                        & $addResult 'report' ([string]$r.Report) ([string]$r.Report) $r.Sampled $r.Matched $r.Missing $r.Extra $rm $rv (Format-SIDataHealthDriftText -Drift $r.Drift -FixedSince $r.FixedSince -NewSince $r.NewSince -Kind 'report') $r.Drift
                    }
                    foreach ($p in @($vc.Problems)) { $problems.Add([pscustomobject]@{ Kind = 'report'; Name = 'vulnerabilities'; RecordKey = [string]$p.Key; RecordName = [string]$p.Name; Problem = [string]$p.Problem }) }
                }
            }
        } catch {
            & $addResult 'source' 'vulnerabilities' $vLabel 0 0 0 0 $vm 'not-checked' ('the vulnerability check could not be run: {0}' -f $_.Exception.Message)
        }
    }
    foreach ($r in $results) {
        $lvl = switch ($r.Verdict) { 'ok' { 'OK' } 'not-used' { 'INFO' } default { 'WARN' } }
        $txt = if ($r.Verdict -eq 'not-checked') { 'NOT CHECKED -- ' + $r.Reason } elseif ($r.Verdict -eq 'not-used') { 'not used here -- ' + $r.Reason }
               else { '{0}: {1} checked, {2} found, {3} missing, {4} {5} (allowed {6}){7}' -f $r.Verdict.ToUpperInvariant(), $r.Sampled, $r.Found, $r.Missing, $r.FieldMismatches, $(if ($r.Kind -eq 'report') { 'no longer in Defender' } else { 'differing' }), $r.Allowed, $(if ($r.Reason) { ' -- ' + $r.Reason } else { '' }) }
        & $Log $lvl ('{0} {1}: {2}' -f $(if ($r.Kind -eq 'report') { 'report' } else { 'source' }), $r.Label, $txt)
    }
    $cycle = Get-SIDataHealthCycleVerdict -Results $results.ToArray()
    $out = [ordered]@{ Results = $results.ToArray(); Problems = $problems.ToArray(); Cycle = $cycle; State = $null; Previous = $null; Overrides = @(); Written = $false; CycleId = 0; Wire = $null; Telemetry = 'not-sent'; TelemetryNote = ''; Coverage = '' }
    # ---------------- the state ----------------
    $hasTables = $false; $hasDrift = $false
    if ($canRead) {
        try {
            $pr = @(Read-SIDataHealthRows -Invoke $Invoke -Sql (Get-SIDataHealthProbeSql)) | Select-Object -First 1; $hasTables = ([int](Get-SIDataHealthItem $pr 'HasTables') -eq 1)
            $hd = Get-SIDataHealthItem $pr 'HasDrift'; $hasDrift = ($null -ne $hd -and "$hd" -eq '1')
        } catch { $hasTables = $false }
        if (-not $hasTables) { & $Log 'WARN' 'The Pro database has no data health tables yet (the update adds them) -- this cycle is printed, not stored, and nothing is held.' }
    }
    $prev = $null; $ovr = @()
    if ($hasTables) {
        $prev = @(Read-SIDataHealthRows -Invoke $Invoke -Sql (Get-SIDataHealthStateSql)) | Select-Object -First 1
        $ovr = @(Read-SIDataHealthRows -Invoke $Invoke -Sql (Get-SIDataHealthOverridesSql))
    }
    $state = Step-SIDataHealthState -Previous $prev -Cycle $cycle -NowUtc $NowUtc
    $out.Previous = $prev; $out.State = $state
    $active = @(Get-SIDataHealthActiveOverrides -State $state -Overrides $ovr)
    $out.Overrides = $active
    if ($state.Changed) { & $Log 'WARN' ('The data health state changed: {0} -> {1}.' -f $state.From, $state.State) }
    # what could not be checked is said next to the state -- never a bare Healthy that rests on part of the sources
    $coverage = Format-SIDataHealthCoverage -Results $results.ToArray()
    $out.Coverage = $coverage
    & $Log $(if ($state.State -eq 'Healthy' -and -not $coverage) { 'OK' } else { 'WARN' }) ('Data health: {0}{1} since {2:yyyy-MM-dd HH:mm} UTC ({3} anomalous cycle(s) in a row){4}' -f $state.State, $(if ($coverage) { ' -- ' + $coverage + ' --' } else { '' }), $state.Since, $state.ConsecutiveAnomalous,
        $(if ($state.State -eq 'Unhealthy') { ' -- data-out is held; ' + $active.Count + ' channel(s) let through by a SuperAdmin' } else { '' }))
    $finished = $NowUtc.ToUniversalTime()
    if ($hasTables -and -not $DryRun) {
        $cid = [long](& $Invoke (Get-SIDataHealthCycleStartSql) @{} 'scalar')
        $rj = ConvertTo-SIDataHealthJsonArray -Items @($results | ForEach-Object { [ordered]@{ Kind = $_.Kind; Name = $_.Name; Label = $_.Label; Sampled = $_.Sampled; Found = $_.Found; Missing = $_.Missing; FieldMismatches = $_.FieldMismatches; Drift = $_.Drift; MarginPercent = $_.MarginPercent; MarginMinimum = $_.MarginMinimum; Allowed = $_.Allowed; Verdict = $_.Verdict; Reason = $_.Reason } })
        $mj = ConvertTo-SIDataHealthJsonArray -Items @($problems | ForEach-Object { [ordered]@{ Kind = $_.Kind; Name = $_.Name; RecordKey = $_.RecordKey; RecordName = $_.RecordName; Problem = $_.Problem } })
        # a database the update has not given the Drift column yet: the results are stored without it (the drift is still in
        # the reason text) -- never a failed cycle over a column (#747)
        if (-not $hasDrift -and @($results | Where-Object { $_.Drift -gt 0 }).Count) { & $Log 'INFO' 'cfg.DataHealthResult has no Drift column yet (the update adds it) -- the drift is stored in the reason text only.' }
        [void](& $Invoke (Get-SIDataHealthResultWriteSql -WithDrift:$hasDrift) @{ CycleId = $cid; Json = $rj; MissingJson = $mj } 'nonquery')
        $sum = ConvertTo-Json -InputObject ([ordered]@{ anomalous = $cycle.Anomalous; complete = $cycle.Complete; notChecked = $cycle.NotChecked; from = $state.From
            drift = [long](@($results | ForEach-Object { [long]$_.Drift }) | Measure-Object -Sum).Sum }) -Compress
        [void](& $Invoke (Get-SIDataHealthCycleEndSql) @{ CycleId = $cid; Anomalous = [bool]$cycle.Anomalous; Complete = [bool]$cycle.Complete; State = [string]$state.State
            Changed = [bool]$state.Changed; Consecutive = [int]$state.ConsecutiveAnomalous; Since = $state.Since; SummaryJson = $sum } 'nonquery')
        $out.Written = $true; $out.CycleId = $cid
        $finished = [datetime]::UtcNow
    }
    # ---------------- the health record for Invardia (counts only; behind its switch) ----------------
    if ($TelemetryContext) {
        try {
            $wire = New-SIDataHealthWire -Context $TelemetryContext -State $state -Cycle ([pscustomobject]@{ Id = [string]$out.CycleId; StartedUtc = $started; FinishedUtc = $finished; Anomalous = $cycle.Anomalous; Complete = $cycle.Complete }) `
                -Sources @($results | Where-Object { $_.Kind -eq 'source' }) -Reports @($results | Where-Object { $_.Kind -eq 'report' }) -Overrides $active -DataOutHeld ([bool]($state.State -eq 'Unhealthy')) -NowUtc $finished
            $out.Wire = $wire
            if ($wire -and $SendTelemetry -and -not $DryRun) {
                $tr = & $SendTelemetry $wire
                $out.Telemetry = $(if ($tr -and [string]$tr.Status -eq 'ok') { 'sent' } else { 'failed' })
                if ($out.Telemetry -eq 'failed') { $out.TelemetryNote = ('The health record for Invardia was not accepted: {0}' -f $(if ($tr -and "$($tr.Reason)".Trim()) { [string]$tr.Reason } else { 'no answer' })) }
            } elseif (-not $wire) {
                # a record that is not built is SAID (the first live run: an install that was not identified sent nothing, silently)
                $out.TelemetryNote = Get-SIDataHealthSendSkipReason -SendEnabled $true -DryRun:$DryRun -Context $TelemetryContext
                if (-not $out.TelemetryNote) { $out.TelemetryNote = 'The health record for Invardia is not sent: it could not be built.' }
            } elseif (-not $SendTelemetry) { $out.TelemetryNote = 'The health record for Invardia is not sent: no way to send it is set up in this run.' }
            elseif ($DryRun) { $out.TelemetryNote = Get-SIDataHealthSendSkipReason -SendEnabled $true -DryRun }
        } catch { $out.Telemetry = 'failed'; $out.TelemetryNote = ('The health record for Invardia was not sent: {0}' -f $_.Exception.Message) }
    } else {
        $out.TelemetryNote = $(if ("$TelemetrySkipReason".Trim()) { "$TelemetrySkipReason".Trim() } else { 'The health record for Invardia is not sent: it is not set up for this run.' })
    }
    if ($out.TelemetryNote) { & $Log 'INFO' $out.TelemetryNote }
    [pscustomobject]$out
}

function Get-SIDataHealthOutcome {
    <# PURE. The cycle's run-health end: success when every source and report was checked; success-partial when one or more
       were not (said, never green). An anomalous result is the STATE's business, not a failed run. #>
    param([Parameter(Mandatory)]$Result)
    $nc = @(@($Result.Results) | Where-Object { $_.Verdict -eq 'not-checked' })
    if ($nc.Count -eq 0) { return @{ Exit = 'success'; Message = '' } }
    @{ Exit = 'success-partial'; Message = ('data health not checked: ' + (@($nc | ForEach-Object { '{0} ({1})' -f $_.Label, $_.Reason }) -join '; ')) }
}
