#Requires -Version 5.1
<#
    SI v3 -- the vulnerability close-loop's TARGETS (#195). Where the open / update / close of SI-VulnSync.ps1
    lands: ServiceNow, or a SQL table.

    ONE SHAPE ON BOTH SIDES. The plan (New-SIVulnSyncPlan) and the apply (Invoke-SIVulnSync) never see a
    ServiceNow field or a SQL column -- they see a record:
        SysId, CorrelationId, CiId, AssetName, Cve, Severity, State, FirstSeen, LastSeen, ClosedAt,
        CloseReason, Source
    A target is an object with three operations, so the decision logic -- and every guard in it -- is the
    same code whichever system receives the result:
        .Read()                      -> every record this source owns or could own
        .Open(record)                -> @{ Ok; Id; Error }
        .Update(sysId, values, why)  -> @{ Ok; Error }     values use the record's names (State, LastSeen, ...)

    SQL (operator 2026-10-01, #195: "build this in sql as it will be sufficient as a 2nd integration (besides
    servicenow)"). Entra-only, certificate auth -- the same token path as the identity ledger, no SQL login,
    no secret. Every state change is also written to an EVENT table in the same transaction, so "who changed
    what, and why" is answerable on the target side too: the two parties can be reconciled, not just trusted.
#>

# The token, the certificate lookup and the transient-error classifier are the identity ledger's (same SPN,
# same database host, same 5.1 / pwsh 7 constraints). Loaded, not copied.
if (-not (Get-Command -Name 'Get-SILedgerAccessToken' -ErrorAction SilentlyContinue)) {
    $__ledger = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model\identity\SI-ObjectLedgerStore.ps1'
    if (Test-Path -LiteralPath $__ledger) { . $__ledger }
}

# #835: the list is a FUNCTION too -- a function runs with its caller's script scope, so a script that did not dot-source
# this file itself would read $script:SIVulnRecordFields as $null and every record would come back EMPTY
function Get-SIVulnRecordFieldNames {
                             @('SysId', 'CorrelationId', 'CiId', 'AssetName', 'Cve', 'Severity', 'State', 'FirstSeen',
                               'LastSeen', 'ClosedAt', 'CloseReason', 'Source', 'AbsentRuns', 'LastAbsentSnapshot',
                               # 2026-10-06 (every security recommendation is a vulnerability; one CI key): the asset id the
                               # finding was reported on, the finding's type, its name and the report that reported it
                               'AssetId', 'FindingType', 'Title', 'Report',
                               # #561 the finding's component (SQL, OS, ...) -- only on a database that has the column
                               'Component',
                               # #772 the finding's ServiceNow sub-CI (OS / SQL / Other) -- only on a database that has the column
                               'SubCi',
                               # #772 the OS family of the finding's asset -- only on a database that has the column
                               'OsFamily',
                               # #772 the patch cycle -- only on a database that has the column
                               'PatchCycle')
}
$script:SIVulnRecordFields = Get-SIVulnRecordFieldNames

# ---------------------------------------------------------------------------------------------------------------------
#  CLOSE REASONS ON THE TARGET (#279, operator 2026-10-04)
#  SecurityInsight closes with one of: Remediated | AssetRetired | NoLongerMonitored | Out of scope | Duplicate | Report
#  changed (#690 (34): the report that found it changed its query or is no longer run) (and, with no asset state, "No
#  longer reported by SecurityInsight -- reason not determined"). Only Remediated is a fix.
#  The SQL target stores them as they are (it is SecurityInsight's own table). A ServiceNow table or a REST system may need
#  its OWN values -- a choice list, a close code: the connector's settings.closeReasons maps SI's reason to the value the
#  other system takes, e.g. { "Duplicate": "duplicate", "Out of scope": "not_applicable" } (ServiceNow without a connector
#  row: $global:SI_VulnSync_ServiceNowCloseReasons). A reason that is not mapped is written as it is (the default).
#  Reading back maps the other way, so a record retired as a duplicate is recognised as one on the next run.
# ---------------------------------------------------------------------------------------------------------------------

function ConvertTo-SIVulnCloseReasonMap {
    <# PURE. settings.closeReasons (hashtable, object or JSON text) -> a case-insensitive hashtable SI reason -> value. #>
    param($Value)
    $h = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
    if ($null -eq $Value) { return $h }
    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return $h }
        try { $Value = $Value | ConvertFrom-Json -ErrorAction Stop } catch { throw ("closeReasons is not valid JSON: {0}" -f $_.Exception.Message) }
    }
    if ($Value -is [System.Collections.IDictionary]) { foreach ($k in @($Value.Keys)) { if ("$($Value[$k])".Trim()) { $h[[string]$k] = ([string]$Value[$k]).Trim() } } }
    else { foreach ($p in @($Value.PSObject.Properties)) { if ("$($p.Value)".Trim()) { $h[$p.Name] = ([string]$p.Value).Trim() } } }
    $h
}

function Get-SIVulnTargetCloseReason {
    <# PURE. The value a target stores for SI's close reason (-Map from ConvertTo-SIVulnCloseReasonMap; unmapped = as is). #>
    param([AllowEmptyString()][string]$Reason, [hashtable]$Map)
    if ([string]::IsNullOrEmpty($Reason) -or $null -eq $Map -or $Map.Count -eq 0) { return $Reason }
    if ($Map.ContainsKey($Reason)) { return [string]$Map[$Reason] }
    $Reason
}

function ConvertFrom-SIVulnTargetCloseReason {
    <# PURE. A stored close reason back to SI's (the reverse of Get-SIVulnTargetCloseReason); anything else as is. #>
    param([AllowEmptyString()][string]$Value, [hashtable]$Map)
    if ([string]::IsNullOrEmpty($Value) -or $null -eq $Map -or $Map.Count -eq 0) { return $Value }
    foreach ($k in @($Map.Keys)) { if ([string]::Equals([string]$Map[$k], $Value.Trim(), [StringComparison]::OrdinalIgnoreCase)) { return [string]$k } }
    $Value
}

function Get-SIVulnSnowBatchStartSize {
    <#
        The Batch API size a run STARTS with. A measurement, not a limit -- the target adapts from here (see SendMany).
        Measured on a developer instance, 2026-10-02, opens / refreshes per call:
            50  -> 35 / 42 records/s       100 -> 60 / 56        250 -> 30 / 68        500 -> 65 / 64 (~8 s a call)
            1000 -> 77 / 74 (13 s); one hour later 21/s (47 s)   1500 -> 20/s (74 s)   2000 -> 8/s (240 s)
        (one request per record: ~3.2/s). The rate stops improving after a few hundred and the same size can take 3x
        longer an hour later, so a run starts at 500 -- under 10 s on a good hour, under 30 s on a slow one -- and
        then sizes each call from the rate it measures.
    #>
    500
}

function New-SIVulnTargetServiceNow {
    <#
        ServiceNow table target. Field map u_* <-> record, the table SI-VulnSync.ps1 wrote before #195.
    #>
    param(
        [Parameter(Mandatory)]$Connection,
        [Parameter(Mandatory)][string]$Table,
        [string]$Source = 'SecurityInsight',
        # WHY a state changed (reopen / close). ServiceNow has no event table here, so without a field for it the
        # reopen of an engineer's close lost "it was closed as: ..." (found live on the PDI, #195). Empty = not written.
        [string]$ReasonField = 'u_state_reason',
        # Records per Batch API call -- the STARTING size, not a ceiling on anything. Measured on a developer
        # instance: see Get-SIVulnSnowBatchStartSize. The target lowers it by itself when the instance shows it is
        # too large (a timeout, a refusal of the size, records the instance left unserviced).
        [int]$BatchSize = 0,
        # How long one Batch API call should take. The size of the next call is derived from the measured rate of the
        # last one so that it lands near this -- comfortably inside the client's request timeout (120 s).
        [double]$BatchTargetSeconds = 20,
        # #279: SI close reason -> the value u_close_reason takes (settings.closeReasons). Unmapped = written as is.
        $CloseReasons = $null
    )
    $reasonMap = ConvertTo-SIVulnCloseReasonMap $CloseReasons
    $map = [ordered]@{ CorrelationId = 'u_correlation_id'; CiId = 'u_cmdb_ci'; AssetName = 'u_asset_name'; Cve = 'u_vulnerability'
                       Severity = 'u_severity'; State = 'u_state'; FirstSeen = 'u_first_seen'; LastSeen = 'u_last_seen'
                       ClosedAt = 'u_closed_at'; CloseReason = 'u_close_reason'; Source = 'u_source'
                       # #217: how many complete runs in a row the finding has been absent on a seen asset, and the run
                       # last counted. A table without these fields cannot count, so its findings never close as fixed.
                       AbsentRuns = 'u_absent_runs'; LastAbsentSnapshot = 'u_absent_snapshot' }
    if ($BatchSize -lt 1) { $BatchSize = Get-SIVulnSnowBatchStartSize }
    $t = [pscustomobject]@{ Kind = 'ServiceNow'; Name = $Table; Connection = $Connection; Table = $Table; Map = $map; Source = $Source
                            ReasonField = $ReasonField; KeyLimitCache = @{}; SelfChunking = $true; CountsAbsence = $true; CloseReasons = $reasonMap
                            # Mode 'batch' until the instance refuses the Batch API, then 'per-record' for the rest of
                            # the run. Calls = one entry per Batch API call (Count, Ms, Ok) -- the run's own measurement.
                            Batch = @{ Size = $BatchSize; TargetSec = $BatchTargetSeconds; TooLarge = 0; Mode = 'batch'; Said = @{}; Calls = (New-Object System.Collections.ArrayList) } }
    # The fields a record is MATCHED on. ServiceNow silently SHORTENS a string longer than its column (measured on
    # the PDI, #195): the stored key then never equals the desired one, so every later run opens the finding again
    # -- a new duplicate per run, while each run reports success.
    $t | Add-Member -MemberType ScriptMethod -Name KeyLimits -Value {
        if (-not $this.KeyLimitCache.ContainsKey('done')) {
            $this.KeyLimitCache['done'] = $true
            $keys = @($this.Map['CorrelationId'], $this.Map['Cve'], $this.Map['Source'])
            # Reading the dictionary needs a role a customer's integration user may not have; then the limits are
            # simply unknown and the read-back check after each open still catches a shortened key.
            $d = Get-SISnowRecord -Connection $this.Connection -Table 'sys_dictionary' -Query ('name={0}^elementIN{1}' -f $this.Table, ($keys -join ',')) -Fields @('element', 'max_length')
            if ($d.Complete) {
                foreach ($row in @($d.Rows)) { $n = 0; if ([int]::TryParse([string]$row.max_length, [ref]$n) -and $n -gt 0) { $this.KeyLimitCache[[string]$row.element] = $n } }
            }
        }
        $this.KeyLimitCache
    }
    $t | Add-Member -MemberType ScriptMethod -Name Read -Value { $this.ReadQuery('') }
    # #850 one page of CI keys: every record under these keys (u_correlation_idIN, in calls of a few thousand characters)
    $t | Add-Member -MemberType ScriptMethod -Name ReadKeys -Value {
        param([string[]]$Keys)
        $ks = @($Keys | Where-Object { $_ } | Select-Object -Unique)
        $chunk = New-Object System.Collections.Generic.List[string]; $len = 0
        $field = $this.Map['CorrelationId']
        for ($i = 0; $i -le $ks.Count; $i++) {
            if ($i -lt $ks.Count -and ($chunk.Count -eq 0 -or $len + $ks[$i].Length + 1 -le 4000)) { $chunk.Add($ks[$i]); $len += $ks[$i].Length + 1; continue }
            if ($chunk.Count) { $this.ReadQuery(('^{0}IN{1}' -f $field, ($chunk -join ','))) }
            $chunk.Clear(); $len = 0
            if ($i -lt $ks.Count) { $chunk.Add($ks[$i]); $len = $ks[$i].Length + 1 }
        }
    }
    # #850 the next CI keys the table holds after -After (the instance's own order), from at most -Take records:
    # @{ Keys; Rows; Last; Done }
    $t | Add-Member -MemberType ScriptMethod -Name KeysAfter -Value {
        param([string]$After, [int]$Take)
        $field = $this.Map['CorrelationId']
        $q = ('u_source={0}{1}^ORDERBY{2}' -f $this.Source, $(if ($After) { ('^{0}>{1}' -f $field, $After) } else { '' }), $field)
        $res = Get-SISnowRecord -Connection $this.Connection -Table $this.Table -Query $q -Fields @('sys_id', $field) -MaxRows $Take -PageSize ([Math]::Min(1000, [Math]::Max(1, $Take)))
        if (-not $res.Complete -and @($res.Rows).Count -lt $Take) { throw ("ServiceNow read of {0} is incomplete: {1}" -f $this.Table, $res.Error) }
        $keys = New-Object System.Collections.Generic.List[string]
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $n = 0L
        $counts = New-Object System.Collections.Generic.List[long]
        foreach ($r in @($res.Rows)) { $n++; $k = [string]$r.$field; if (-not $k) { continue }; if ($seen.Add($k)) { $keys.Add($k); $counts.Add(1L) } elseif ($keys.Count -and [string]::Equals($keys[$keys.Count - 1], $k, [StringComparison]::OrdinalIgnoreCase)) { $counts[$counts.Count - 1]++ } }
        [pscustomobject]@{ Keys = $keys.ToArray(); Counts = $counts.ToArray(); Rows = $n; Last = $(if ($keys.Count) { $keys[$keys.Count - 1] } else { $After }); Done = ($n -lt $Take) }
    }
    $t | Add-Member -MemberType ScriptMethod -Name ReadQuery -Value {
        param([string]$Extra)
        # NO ROW CEILING. The client stops at 20,000 rows by default and calls that read partial -- correctly -- but
        # this table only grows (closed findings stay, they are what a reopen is matched against), so a ceiling
        # would turn a healthy install into one that refuses every run once it passes it.
        $res = Get-SISnowRecord -Connection $this.Connection -Table $this.Table -Query (('u_source={0}' -f $this.Source) + $Extra) -Fields (@('sys_id') + @($this.Map.Values)) -MaxRows ([int]::MaxValue)
        # A PARTIAL read of the target is as dangerous as a partial collection: every record it missed would be
        # opened again as a duplicate. Refuse it.
        if (-not $res.Complete) { throw ("ServiceNow read of {0} is incomplete: {1}" -f $this.Table, $res.Error) }
        # #217: a table without the absence field does not return it. Then the count cannot be kept, and the loop
        # holds every would-be close and says so (never a silent close on one absence).
        $rowsRead = @($res.Rows)
        if ($rowsRead.Count -gt 0) { $this.CountsAbsence = (@($rowsRead | Where-Object { $_ -and $_.PSObject.Properties[$this.Map['AbsentRuns']] }).Count -gt 0) }
        foreach ($r in $rowsRead) {
            $o = [ordered]@{ SysId = [string]$r.sys_id }
            foreach ($k in $this.Map.Keys) { $o[$k] = [string]$r.($this.Map[$k]) }
            # #279: the stored close code read back as SI's reason (a retired duplicate is recognised as one)
            $o['CloseReason'] = ConvertFrom-SIVulnTargetCloseReason -Value ([string]$o['CloseReason']) -Map $this.CloseReasons
            [pscustomobject]$o
        }
    }
    # The two key checks an open needs, shared by the one-record and the batch path so they cannot drift.
    $t | Add-Member -MemberType ScriptMethod -Name KeyRefusal -Value {
        param([hashtable]$body)
        # Refuse BEFORE writing when the key cannot fit: the record would match nothing on the next run.
        $limits = $this.KeyLimits()
        foreach ($f in @($this.Map['CorrelationId'], $this.Map['Cve'], $this.Map['Source'])) {
            if ($limits.ContainsKey($f) -and $body.ContainsKey($f) -and ([string]$body[$f]).Length -gt [int]$limits[$f]) {
                return ("not opened: {0} is {1} characters and the ServiceNow field holds {2}. It would be stored shortened, never match again, and be opened as a duplicate on every run -- widen the field." -f $f, ([string]$body[$f]).Length, $limits[$f])
            }
        }
        ''
    }
    $t | Add-Member -MemberType ScriptMethod -Name StoredKeyMismatch -Value {
        param($stored, [hashtable]$body)
        # ...and check what was STORED, not what was sent: the dictionary may be unreadable, or not the whole story.
        foreach ($f in @($this.Map['CorrelationId'], $this.Map['Cve'], $this.Map['Source'])) {
            if ($stored -and $stored.PSObject.Properties[$f] -and $body.ContainsKey($f) -and [string]$stored.$f -cne [string]$body[$f]) {
                return ("opened, but ServiceNow stored {0} as {1} characters instead of {2}: this record will never match again and the finding will be opened as a duplicate on every run -- widen the field." -f $f, ([string]$stored.$f).Length, ([string]$body[$f]).Length)
            }
        }
        ''
    }
    $t | Add-Member -MemberType ScriptMethod -Name Open -Value {
        param($rec)
        $body = @{}
        foreach ($k in $this.Map.Keys) { if ($null -ne $rec.$k) { $body[$this.Map[$k]] = [string]$rec.$k } }
        $refusal = $this.KeyRefusal($body)
        if ($refusal) { return @{ Ok = $false; Id = ''; Error = $refusal } }
        $r = Invoke-SISnowRequest -Connection $this.Connection -Method POST -Path ('/api/now/table/{0}' -f $this.Table) -Body $body
        if (-not $r.Ok) { return @{ Ok = $false; Id = ''; Error = [string]$r.Error } }
        $stored = $r.Content.result
        $id = [string]$stored.sys_id
        $mismatch = $this.StoredKeyMismatch($stored, $body)
        if ($mismatch) { return @{ Ok = $false; Id = $id; Error = $mismatch } }
        @{ Ok = $true; Id = $id; Error = '' }
    }
    $t | Add-Member -MemberType ScriptMethod -Name Update -Value {
        param([string]$sysId, [hashtable]$values, [string]$why)
        $body = @{}
        foreach ($k in $values.Keys) { if ($this.Map.Contains($k)) { $body[$this.Map[$k]] = [string]$values[$k] } }
        # #279: SI's close reason as the value this table takes (settings.closeReasons; unmapped = as is)
        if ($values.ContainsKey('CloseReason')) { $body[$this.Map['CloseReason']] = [string](Get-SIVulnTargetCloseReason -Reason ([string]$values['CloseReason']) -Map $this.CloseReasons) }
        # A STATE change carries its reason onto the record -- the reopen of an engineer's close says what it was
        # closed as. A "still seen" refresh does not: it is not a change, and it runs on every open record.
        if ($this.ReasonField -and $values.ContainsKey('State') -and $why) { $body[$this.ReasonField] = [string]$why }
        $r = Update-SISnowRecord -Connection $this.Connection -Table $this.Table -SysId $sysId -Values $body
        if ($r.Ok) { @{ Ok = $true; Error = '' } } else { @{ Ok = $false; Error = [string]$r.Error } }
    }

    # SET-BASED, through the Batch API (#210). One request per record measured ~3.2 records/s on a developer
    # instance: about an hour to open 12k findings, and another hour of "still seen" refreshes on EVERY run.
    # The same two verbs the SQL target does set-based, with the same contract back to the loop -- plus a result
    # PER RECORD, because a batch is not all-or-nothing: every sub-request succeeds or fails on its own.
    #
    # SendMany(items, idempotent) -> hashtable Index -> @{ Ok; Id; Error; Content; Fallback }
    #   items: @{ Index; Key; Method; Url; Body }. Fallback = $true means the instance refused the Batch API and
    #   the caller must do this record the one-request way.
    $t | Add-Member -MemberType ScriptMethod -Name SendMany -Value {
        param([object[]]$items, [bool]$idempotent)
        $out = @{}
        $pending = New-Object System.Collections.Generic.List[object]
        foreach ($i in $items) { $pending.Add($i) }
        $b = $this.Batch
        $say = {
            param([string]$k, [string]$m)
            # ONE line per kind of event per run -- the run says what happened, it does not narrate every call.
            if (-not $b.Said.ContainsKey($k)) { $b.Said[$k] = $true; Write-Host ("[INFO] ServiceNow: {0}" -f $m) }
        }
        while ($pending.Count -gt 0) {
            if ($b.Mode -ne 'batch') {
                foreach ($i in $pending) { $out[[int]$i.Index] = @{ Ok = $false; Id = ''; Error = ''; Content = $null; Fallback = $true } }
                break
            }
            $n = [Math]::Max(1, [Math]::Min([int]$b.Size, $pending.Count))
            $take = $pending.GetRange(0, $n).ToArray()
            $pending.RemoveRange(0, $n)
            $reqs = @($take | ForEach-Object { @{ Id = [string]$_.Index; Method = $_.Method; Url = $_.Url; Body = $_.Body } })
            $r = Invoke-SISnowBatch -Connection $this.Connection -Requests $reqs -Idempotent:$idempotent
            [void]$b.Calls.Add([pscustomobject]@{ Count = $n; Ms = [int]$r.ElapsedMs; Ok = [bool]$r.Ok; Status = $r.Status })

            if (-not $r.Ok) {
                if ($r.Refused) {
                    # The instance does not offer the Batch API to this user. Everything left -- this chunk too, as
                    # NOTHING in it was executed -- goes the one-request way, and the run says so once.
                    $b.Mode = 'per-record'
                    & $say 'fallback' ("the Batch API was refused (HTTP {0}) -- continuing with one request per record, which is much slower." -f $r.Status)
                    $pending.InsertRange(0, [object[]]$take)
                    continue
                }
                # Too large for the instance: a refusal of the size, or a call that timed out. Halve from what was
                # sent. A refused size executed nothing, so it is sent again; a timeout is sent again only when every
                # sub-request in it is safe to repeat (refreshes) -- an open inside it may already have landed.
                $sizeRefused = ([int]$r.Status -eq 413) -or ([int]$r.Status -eq 400 -and [string]$r.Error -match '(?i)batch|too (large|many)|exceed|limit')
                $timedOut = ([int]$r.Status -eq 0 -or @(408, 502, 503, 504) -contains [int]$r.Status)
                if (($sizeRefused -or $timedOut) -and $n -gt 1) {
                    $b.Size = [int][Math]::Max(1, [Math]::Floor($n / 2))
                    # What the instance showed it cannot carry, it is not offered again in this run.
                    if ($b.TooLarge -le 0 -or $n -lt $b.TooLarge) { $b.TooLarge = $n }
                    & $say ('shrink-' + $b.Size) ("a batch of {0} {1} -- continuing with {2} per batch." -f $n, $(if ($sizeRefused) { "was refused as too large (HTTP $($r.Status))" } else { 'got no answer in time' }), $b.Size)
                    if ($sizeRefused -or $idempotent) { $pending.InsertRange(0, [object[]]$take); continue }
                }
                foreach ($i in $take) {
                    $why = if ($timedOut -and -not $idempotent) { ('{0} -- the batch carried creates and was not resent; the next run reads back what landed.' -f $r.Error) } else { [string]$r.Error }
                    $out[[int]$i.Index] = @{ Ok = $false; Id = ''; Error = ('{0}: {1}' -f $i.Key, $why); Content = $null; Fallback = $false }
                }
                continue
            }

            $unserviced = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($u in @($r.Unserviced)) { [void]$unserviced.Add([string]$u) }
            $again = New-Object System.Collections.Generic.List[object]
            foreach ($i in $take) {
                $id = [string]$i.Index
                if ($r.Responses.ContainsKey($id)) {
                    $s = $r.Responses[$id]
                    if ($s.Ok) { $out[[int]$i.Index] = @{ Ok = $true; Id = ''; Error = ''; Content = $s.Content; Fallback = $false } }
                    else { $out[[int]$i.Index] = @{ Ok = $false; Id = ''; Error = ('{0}: {1}' -f $i.Key, $s.Error); Content = $s.Content; Fallback = $false } }
                }
                elseif ($unserviced.Contains($id) -and $n -gt 1) { $again.Add($i) }
                else {
                    # Never assumed done: no answer for a record is a failure for that record.
                    $out[[int]$i.Index] = @{ Ok = $false; Id = ''; Error = ('{0}: the instance returned no answer for this record in the batch -- not treated as written' -f $i.Key); Content = $null; Fallback = $false }
                }
            }
            # ADAPT TO THE MEASURED RATE. The same instance served 1000 records in 13 s one hour and 47 s the next, and
            # 2000 in 240 s (measured on a developer instance) -- so the size follows how fast THIS instance answers
            # now: the next full call is sized to finish in about TargetSec. It shrinks at once, and grows at most
            # double per call, so a size the instance cannot carry is approached, never jumped into. Only a FULL call
            # is measured: the last, short remainder of a set says nothing about the size.
            if ($again.Count -eq 0 -and $n -eq [int]$b.Size -and [int]$r.ElapsedMs -gt 0) {
                $rate = $n / ([int]$r.ElapsedMs / 1000.0)
                $want = [int][Math]::Max(1, [Math]::Floor($rate * [double]$b.TargetSec))
                $next = if ($want -lt $n) { $want } else { [int][Math]::Min($want, 2 * $n) }
                if ($b.TooLarge -gt 0 -and $next -ge $b.TooLarge) { $next = [int][Math]::Max(1, $b.TooLarge - 1) }
                $b.Size = $next
            }
            if ($again.Count -gt 0) {
                # The instance stopped before the end of the batch (it limits how long one call may run). What it did
                # serve is the size it can manage; the rest was never executed and is sent again.
                $served = $n - $again.Count
                $b.Size = [int][Math]::Max(1, $(if ($served -gt 0) { $served } else { [Math]::Floor($n / 2) }))
                if ($b.TooLarge -le 0 -or $n -lt $b.TooLarge) { $b.TooLarge = $n }
                & $say ('unserviced-' + $b.Size) ("the instance served {0} of {1} records in one batch -- continuing with {2} per batch." -f $served, $n, $b.Size)
                $pending.InsertRange(0, $again.ToArray())
            }
        }
        $out
    }
    $t | Add-Member -MemberType ScriptMethod -Name OpenMany -Value {
        param([object[]]$records)
        $now = (Get-Date).ToUniversalTime().ToString('o')
        $results = New-Object object[] ($records.Count)
        $items = New-Object System.Collections.Generic.List[object]
        $bodies = @{}
        $seen = @{}
        $fields = 'sys_id,{0},{1},{2}' -f $this.Map['CorrelationId'], $this.Map['Cve'], $this.Map['Source']
        for ($x = 0; $x -lt $records.Count; $x++) {
            $rec = $records[$x]
            $key = ('{0}|{1}' -f ([string]$rec.CorrelationId).Trim().ToLowerInvariant(), ([string]$rec.Cve).Trim().ToUpperInvariant())
            # The same record shape the one-record open writes: the finding, Open, both times, and this source.
            $one = [pscustomobject]@{ CorrelationId = [string]$rec.CorrelationId; CiId = [string]$rec.CiId; AssetName = [string]$rec.AssetName
                                      Cve = [string]$rec.Cve; Severity = [string]$rec.Severity; State = 'Open'; FirstSeen = $now; LastSeen = $now; Source = $this.Source; AbsentRuns = '0' }
            $body = @{}
            foreach ($k in $this.Map.Keys) { if ($null -ne $one.$k) { $body[$this.Map[$k]] = [string]$one.$k } }
            if ($seen.ContainsKey($key)) {
                # One key, one record: a second open in the same run would be a duplicate on the target.
                $results[$x] = @{ Ok = $false; Id = ''; Error = ('{0}: not opened -- the same finding appears twice in this run; it is opened once' -f $key) }
                continue
            }
            $seen[$key] = $true
            $refusal = $this.KeyRefusal($body)
            if ($refusal) { $results[$x] = @{ Ok = $false; Id = ''; Error = ('{0}: {1}' -f $key, $refusal) }; continue }
            $bodies[$x] = $body
            $items.Add(@{ Index = $x; Key = $key; Method = 'POST'; Url = ('/api/now/table/{0}?sysparm_fields={1}' -f $this.Table, $fields); Body = $body })
        }
        $sent = $this.SendMany($items.ToArray(), $false)
        foreach ($x in @($sent.Keys)) {
            $s = $sent[$x]
            if ($s.Fallback) { $o = $this.Open($records[$x]); $results[$x] = @{ Ok = [bool]$o.Ok; Id = [string]$o.Id; Error = $(if ($o.Ok) { '' } else { ('{0}|{1}: {2}' -f ([string]$records[$x].CorrelationId).Trim().ToLowerInvariant(), ([string]$records[$x].Cve).Trim().ToUpperInvariant(), $o.Error) }) }; continue }
            if (-not $s.Ok) { $results[$x] = @{ Ok = $false; Id = ''; Error = $s.Error }; continue }
            $stored = $null
            if ($s.Content -and $s.Content.PSObject.Properties['result']) { $stored = $s.Content.result }
            $id = if ($stored) { [string]$stored.sys_id } else { '' }
            $key = ('{0}|{1}' -f ([string]$records[$x].CorrelationId).Trim().ToLowerInvariant(), ([string]$records[$x].Cve).Trim().ToUpperInvariant())
            if (-not $id) { $results[$x] = @{ Ok = $false; Id = ''; Error = ('{0}: the instance answered without a record id -- not treated as opened' -f $key) }; continue }
            $mismatch = $this.StoredKeyMismatch($stored, $bodies[$x])
            if ($mismatch) { $results[$x] = @{ Ok = $false; Id = $id; Error = ('{0}: {1}' -f $key, $mismatch) }; continue }
            $results[$x] = @{ Ok = $true; Id = $id; Error = '' }
        }
        $okN = @($results | Where-Object { $_ -and $_.Ok }).Count
        $first = @($results | Where-Object { $_ -and -not $_.Ok } | Select-Object -First 1)
        @{ Ok = ($okN -eq $records.Count); Count = $okN; Error = $(if ($first.Count) { [string]$first[0].Error } else { '' }); Results = $results }
    }
    $t | Add-Member -MemberType ScriptMethod -Name TouchMany -Value {
        param([object[]]$items)   # SysId, Severity, Cve -- the same input as the SQL target's TouchMany
        $now = (Get-Date).ToUniversalTime().ToString('o')
        $results = New-Object object[] ($items.Count)
        $reqs = New-Object System.Collections.Generic.List[object]
        for ($x = 0; $x -lt $items.Count; $x++) {
            $it = $items[$x]
            $sys = [string]$it.SysId
            $key = ('{0} ({1})' -f $sys, [string]$it.Cve)
            # The same refusal as the one-record PATCH: an unaddressed update is never sent.
            if ([string]::IsNullOrWhiteSpace($sys)) { $results[$x] = @{ Ok = $false; Id = ''; Error = ('{0}: no sys_id supplied -- refusing to PATCH an unaddressed record' -f [string]$it.Cve) }; continue }
            # A "still seen" refresh: last seen and severity, no reason -- exactly what the one-record path writes.
            $body = @{ $this.Map['LastSeen'] = $now; $this.Map['Severity'] = [string]$it.Severity }
            # Seen again after an absence: the count starts over (#217). Only then -- a plain refresh stays two fields.
            if ($it.PSObject.Properties['ResetAbsence'] -and $it.ResetAbsence) { $body[$this.Map['AbsentRuns']] = '0'; $body[$this.Map['LastAbsentSnapshot']] = '' }
            $reqs.Add(@{ Index = $x; Key = $key; Method = 'PATCH'; Url = ('/api/now/table/{0}/{1}?sysparm_fields=sys_id' -f $this.Table, $sys); Body = $body })
        }
        # Refreshes only: every sub-request is a PATCH of an existing record, so the call is safe to repeat.
        $sent = $this.SendMany($reqs.ToArray(), $true)
        foreach ($x in @($sent.Keys)) {
            $s = $sent[$x]
            if ($s.Fallback) {
                $fv = @{ LastSeen = $now; Severity = [string]$items[$x].Severity }
                if ($items[$x].PSObject.Properties['ResetAbsence'] -and $items[$x].ResetAbsence) { $fv['AbsentRuns'] = '0'; $fv['LastAbsentSnapshot'] = '' }
                $o = $this.Update([string]$items[$x].SysId, $fv, 'still reported')
                $results[$x] = @{ Ok = [bool]$o.Ok; Id = [string]$items[$x].SysId; Error = $(if ($o.Ok) { '' } else { ('{0} ({1}): {2}' -f [string]$items[$x].SysId, [string]$items[$x].Cve, $o.Error) }) }
                continue
            }
            $results[$x] = @{ Ok = [bool]$s.Ok; Id = [string]$items[$x].SysId; Error = [string]$s.Error }
        }
        $okN = @($results | Where-Object { $_ -and $_.Ok }).Count
        $first = @($results | Where-Object { $_ -and -not $_.Ok } | Select-Object -First 1)
        @{ Ok = ($okN -eq $items.Count); Count = $okN; Error = $(if ($first.Count) { [string]$first[0].Error } else { '' }); Results = $results }
    }
    # #217: record how many complete runs a finding has been absent on a seen asset. A PATCH of two fields of an
    # existing record -- safe to repeat, so the batch may be resent after a timeout.
    $t | Add-Member -MemberType ScriptMethod -Name MarkAbsentMany -Value {
        param([object[]]$items)   # SysId, Cve, AbsentRuns, Snapshot
        $results = New-Object object[] ($items.Count)
        $reqs = New-Object System.Collections.Generic.List[object]
        for ($x = 0; $x -lt $items.Count; $x++) {
            $it = $items[$x]; $sys = [string]$it.SysId
            if ([string]::IsNullOrWhiteSpace($sys)) { $results[$x] = @{ Ok = $false; Id = ''; Error = ('{0}: no sys_id supplied -- refusing to PATCH an unaddressed record' -f [string]$it.Cve) }; continue }
            $body = @{ $this.Map['AbsentRuns'] = [string][int]$it.AbsentRuns; $this.Map['LastAbsentSnapshot'] = [string]$it.Snapshot }
            $reqs.Add(@{ Index = $x; Key = ('{0} ({1})' -f $sys, [string]$it.Cve); Method = 'PATCH'; Url = ('/api/now/table/{0}/{1}?sysparm_fields=sys_id' -f $this.Table, $sys); Body = $body })
        }
        $sent = $this.SendMany($reqs.ToArray(), $true)
        foreach ($x in @($sent.Keys)) {
            $s = $sent[$x]
            if ($s.Fallback) {
                $o = $this.Update([string]$items[$x].SysId, @{ AbsentRuns = [string][int]$items[$x].AbsentRuns; LastAbsentSnapshot = [string]$items[$x].Snapshot }, '')
                $results[$x] = @{ Ok = [bool]$o.Ok; Id = [string]$items[$x].SysId; Error = [string]$o.Error }
                continue
            }
            $results[$x] = @{ Ok = [bool]$s.Ok; Id = [string]$items[$x].SysId; Error = [string]$s.Error }
        }
        $okN = @($results | Where-Object { $_ -and $_.Ok }).Count
        $first = @($results | Where-Object { $_ -and -not $_.Ok } | Select-Object -First 1)
        @{ Ok = ($okN -eq $items.Count); Count = $okN; Error = $(if ($first.Count) { [string]$first[0].Error } else { '' }); Results = $results }
    }
    # #279 decision 1: move a record to its asset's current id (u_correlation_id, u_asset_name) and retire a duplicate
    # (u_state Closed, u_close_reason = the Duplicate reason as this table takes it, the why in the reason field).
    # ServiceNow has no transaction, so a pair goes in TWO steps: the retire first, then the record that is kept -- only
    # when its pair's retire landed. A pair that fails half-way is then left as "kept record still under the previous
    # id", which the next run re-keys, never as two open records of one finding under one id.
    $t | Add-Member -MemberType ScriptMethod -Name Rekey -Value {
        param([object[]]$ops)   # Pair, Role, SysId, NewId, NewName, Retire, Why
        $self = $this
        $results = New-Object object[] ($ops.Count)
        $now = (Get-Date).ToUniversalTime().ToString('o')
        $valuesOf = {
            param($o)
            $v = @{ CorrelationId = [string]$o.NewId }
            if ($o.NewName) { $v['AssetName'] = [string]$o.NewName }
            if ($o.Retire) { $v['State'] = 'Closed'; $v['CloseReason'] = 'Duplicate'; $v['ClosedAt'] = $now }
            $v
        }
        $phase = {
            param([int[]]$idx)
            if (@($idx).Count -eq 0) { return }
            $reqs = New-Object System.Collections.Generic.List[object]
            foreach ($x in $idx) {
                $o = $ops[$x]; $sys = [string]$o.SysId
                if ([string]::IsNullOrWhiteSpace($sys)) { $results[$x] = @{ Ok = $false; Error = 're-key: no sys_id supplied -- refusing to PATCH an unaddressed record' }; continue }
                $vals = & $valuesOf $o
                $body = @{}
                foreach ($k in $vals.Keys) { $body[$self.Map[$k]] = [string]$vals[$k] }
                if ($vals.ContainsKey('CloseReason')) { $body[$self.Map['CloseReason']] = [string](Get-SIVulnTargetCloseReason -Reason 'Duplicate' -Map $self.CloseReasons) }
                if ($self.ReasonField -and $o.Retire -and $o.Why) { $body[$self.ReasonField] = [string]$o.Why }
                $reqs.Add(@{ Index = $x; Key = ('{0} ({1})' -f $sys, [string]$o.Cve); Method = 'PATCH'; Url = ('/api/now/table/{0}/{1}?sysparm_fields=sys_id' -f $self.Table, $sys); Body = $body })
            }
            # PATCHes of existing records: safe to repeat after a timeout
            $sent = $self.SendMany($reqs.ToArray(), $true)
            foreach ($x in @($sent.Keys)) {
                $s = $sent[$x]
                if ($s.Fallback) { $u = $self.Update([string]$ops[$x].SysId, (& $valuesOf $ops[$x]), $(if ($ops[$x].Retire) { [string]$ops[$x].Why } else { '' })); $results[$x] = @{ Ok = [bool]$u.Ok; Error = [string]$u.Error }; continue }
                $results[$x] = @{ Ok = [bool]$s.Ok; Error = [string]$s.Error }
            }
        }
        $first = @(for ($x = 0; $x -lt $ops.Count; $x++) { if ($ops[$x].Role -eq 'retire') { $x } })
        & $phase $first
        $failed = @{}
        foreach ($x in $first) { if (-not ($results[$x] -and $results[$x].Ok)) { $failed[[string]$ops[$x].Pair] = $true } }
        $second = New-Object System.Collections.Generic.List[int]
        for ($x = 0; $x -lt $ops.Count; $x++) {
            if ($ops[$x].Role -eq 'retire') { continue }
            if ($failed.ContainsKey([string]$ops[$x].Pair)) { $results[$x] = @{ Ok = $false; Error = 'not moved: the duplicate it replaces could not be retired' }; continue }
            $second.Add($x)
        }
        & $phase $second.ToArray()
        $okN = @($results | Where-Object { $_ -and $_.Ok }).Count
        $bad = @($results | Where-Object { $_ -and -not $_.Ok } | Select-Object -First 1)
        @{ Ok = ($okN -eq $ops.Count); Count = $okN; Error = $(if ($bad.Count) { [string]$bad[0].Error } else { '' }); Results = $results }
    }
    $t
}

function ConvertTo-SIVulnSqlRecord {
    <#
        PURE. One SQL data row (column -> value) as the shared record shape; DBNull and $null become ''. -Makers (#639 (7),
        a hashtable the caller keeps for all rows of one read): the record is a LEAN record (New-SIVulnRowMaker -PlanFields,
        the same properties) -- a whole target table is held for the plan; without it, or without a lean type, a
        PSCustomObject as before.
    #>
    param([Parameter(Mandatory)]$Row, [hashtable]$Makers)
    $o = [ordered]@{}
    foreach ($f in $(if ($script:SIVulnRecordFields) { $script:SIVulnRecordFields } else { Get-SIVulnRecordFieldNames })) {
        # #561: a row without the Component column (a database not yet re-initialised) does not carry the field at all, so the
        # #429 diff never sees a difference it could not write
        if ($f -in 'Component', 'SubCi', 'OsFamily', 'PatchCycle' -and -not $(if ($Row -is [System.Collections.IDictionary]) { $Row.Contains($f) } else { $null -ne $Row.PSObject.Properties[$f] })) { continue }
        $v = $null
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($f)) { $v = $Row[$f] } }
        elseif ($Row.PSObject.Properties[$f]) { $v = $Row.$f }
        if ($null -eq $v -or $v -is [System.DBNull]) { $o[$f] = '' }
        elseif ($v -is [datetime]) {
            # Every time in this table is written as UTC (SYSUTCDATETIME / an ISO 'Z' string) and comes back from
            # SqlClient with Kind Unspecified -- converting THAT "to UTC" would shift it by the host's offset (#203's
            # mistake), and the absence count compares these times run against run (#217).
            $dt = [datetime]$v
            if ($dt.Kind -eq [System.DateTimeKind]::Unspecified) { $dt = [datetime]::SpecifyKind($dt, [System.DateTimeKind]::Utc) }
            $o[$f] = $dt.ToUniversalTime().ToString('o')
        }
        else { $o[$f] = [string]$v }
    }
    if ($null -ne $Makers -and (Get-Command -Name New-SIVulnRowMaker -ErrorAction SilentlyContinue)) {
        # #835: get_Keys() / get_Values(), never .Keys / .Values -- on a dictionary a KEY of that name wins over the property
        $names = [string[]]@($o.get_Keys())
        $mk = $names -join "`n"
        if (-not $Makers.ContainsKey($mk)) { $Makers[$mk] = New-SIVulnRowMaker -Names $names -PlanFields }
        return (ConvertTo-SIVulnRow -Maker $Makers[$mk] -Values ([object[]]@($o.get_Values())))
    }
    [pscustomobject]$o
}

function Get-SIVulnSqlUpdateStatement {
    <#
        PURE. The parameterised UPDATE for a record, plus its event row, from record-named values. Only known
        columns are accepted -- a value name becomes SQL text only through this allow-list, never raw.
        Returns @{ Sql; Params } where Params is an ordered name -> value map.
    #>
    param([Parameter(Mandatory)][hashtable]$Values,
          # #914: the batch this write belongs to (vuln.SyncRun) -- stamped on the record AT WRITE TIME, with the action it takes
          [string]$BatchId = '')
    $allowed = @('State', 'LastSeen', 'ClosedAt', 'CloseReason', 'Severity', 'AssetName', 'CiId', 'AbsentRuns', 'LastAbsentSnapshot', 'AssetId', 'FindingType', 'Title', 'Report', 'Component', 'SubCi', 'OsFamily', 'PatchCycle')
    $sets = New-Object System.Collections.Generic.List[string]
    $params = [ordered]@{}
    foreach ($k in $allowed) {
        if (-not $Values.ContainsKey($k)) { continue }
        $sets.Add(('{0} = @{0}' -f $k))
        $v = $Values[$k]
        $params[$k] = if ($null -eq $v -or ([string]$v) -eq '') { [System.DBNull]::Value } else { $v }
    }
    if ($sets.Count -eq 0) { throw 'Get-SIVulnSqlUpdateStatement: nothing to update' }
    if ($BatchId) {
        # a reopen says reopen; a close (or any other state change) leaves the action to the view (close / out_of_scope from
        # the state); a refresh keeps the action this batch already gave the record (new, reopen) and clears an older one
        $la = 'CASE WHEN SiBatchId = @SiBatch THEN LastAction END'
        if ($Values.ContainsKey('State')) { $la = $(if ([string]$Values['State'] -eq 'Open') { "N'reopen'" } else { 'NULL' }) }
        $sets.Add(('LastAction = {0}' -f $la)); $sets.Add('SiBatchId = @SiBatch')
        $params['SiBatch'] = $BatchId
    }
    # An EVENT is written only for a STATE change. "Still seen" refreshes every open record on every run --
    # thousands of rows -- and an event per refresh would bury the changes the history exists to show.
    $event = if ($Values.ContainsKey('State')) { @"
INSERT vuln.VulnerabilityEvent (SysId, Action, FromState, ToState, Reason, RunId, Actor)
VALUES (@SysId, @Action, @from, (SELECT State FROM vuln.VulnerabilityItem WHERE SysId = @SysId), @Reason, @RunId, @Actor);
"@ } else { '' }
    $sql = @"
DECLARE @from nvarchar(20) = (SELECT State FROM vuln.VulnerabilityItem WITH (UPDLOCK) WHERE SysId = @SysId);
IF @from IS NULL THROW 50001, 'no such vulnerability record', 1;
UPDATE vuln.VulnerabilityItem SET $($sets -join ', '), UpdatedAt = SYSUTCDATETIME() WHERE SysId = @SysId;
$event
"@
    @{ Sql = $sql; Params = $params; WithEvent = [bool]$event }
}

function ConvertFrom-SIVulnSqlOpenAnswer {
    <#
        PURE. #429 -- the SQL target's OpenMany answer (one row per record: Pos, SysId, Existing, ExistingState, Twin) -> the
        per-record shape Invoke-SIVulnSync reads: @{ Ok; Count; Error; Results = @( @{ Ok; Id; Error; Existing } ) }. A record
        whose key the target already holds is NOT opened twice and says so in plain words with the record that holds it; the
        same finding twice in one call is opened once. An answer without rows (an older database seam) = all opened.
    #>
    param([AllowEmptyCollection()][object[]]$Answer = @(), [int]$Count = 0)
    $get = { param($o, [string]$n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o[$n] } else { $null } } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $rows = @($Answer | Where-Object { $null -ne $_ -and $null -ne (& $get $_ 'Pos') })
    if (-not $rows.Count) { return @{ Ok = $true; Count = $Count; Error = '' } }
    $results = New-Object object[] ($Count)
    $ok = 0; $first = ''
    foreach ($r in $rows) {
        $pos = [int](& $get $r 'Pos'); if ($pos -lt 0 -or $pos -ge $Count) { continue }
        $ex = & $get $r 'Existing'; $tw = & $get $r 'Twin'
        $exS = if ($null -eq $ex -or $ex -is [System.DBNull]) { '' } else { [string]$ex }
        $twS = if ($null -eq $tw -or $tw -is [System.DBNull]) { '' } else { [string]$tw }
        if ($exS) {
            $st = [string](& $get $r 'ExistingState'); if ($st -eq '' -or (& $get $r 'ExistingState') -is [System.DBNull]) { $st = 'unknown' }
            $results[$pos] = @{ Ok = $false; Id = $exS; Existing = $true; Error = ('already recorded on the target as record {0} ({1}) -- not opened twice' -f $exS, $st) }
        } elseif ($twS) {
            $results[$pos] = @{ Ok = $false; Id = ''; Existing = $true; Error = 'the same finding twice in one call -- opened once' }
        } else { $results[$pos] = @{ Ok = $true; Id = [string](& $get $r 'SysId'); Existing = $false; Error = '' }; $ok++ }
        if (-not $results[$pos].Ok -and -not $first) { $first = [string]$results[$pos].Error }
    }
    for ($i = 0; $i -lt $Count; $i++) { if ($null -eq $results[$i]) { $results[$i] = @{ Ok = $false; Id = ''; Existing = $false; Error = 'no answer for this record' }; if (-not $first) { $first = 'no answer for this record' } } }
    @{ Ok = ($ok -eq $Count); Count = $ok; Error = $first; Results = $results }
}

function New-SIVulnTargetSql {
    <#
        Azure SQL / SQL Server target (#195). Tables from sql/si-vulnerability-target.sql.
        -Invoke is the ONE seam to the database: a scriptblock (sql, params-hashtable, mode 'reader'|'nonquery'|'scalar')
        that tests replace with a fake. The default opens a connection per call with an Entra token, so there is no
        long-lived connection to lose mid-run: on a VM for the engine SPN (certificate); in a container that signs in
        as the job's managed identity (#209), from the identity endpoint -- Pro is container-only, and a container
        has no certificate (#216).
    #>
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$Database,
        [string]$AppId,
        [string]$TenantId,
        [string]$CertThumbprint,
        [string]$Source = 'SecurityInsight',
        [string]$RunId = ([guid]::NewGuid().ToString()),
        [string]$Actor = 'SecurityInsight',
        [scriptblock]$Invoke
    )
    if (-not $Invoke) {
        $srv = $Server; $db = $Database; $app = $AppId; $ten = $TenantId
        # A GetNewClosure() block runs in its own module scope and cannot see functions the caller dot-sourced, so
        # the token function travels INTO the closure as a value. (Found live: the fake seam in the tests hid it.)
        if ($global:SI_UseManagedIdentity) {
            # The container entry point loads the identity helper; an engine never loads it itself.
            if (-not (Get-Command -Name 'Get-SIManagedIdentityToken' -ErrorAction SilentlyContinue)) {
                throw 'New-SIVulnTargetSql: managed identity is on but the identity token helper is not loaded -- this sign-in works only inside a SecurityInsight container.'
            }
            $miFn = ${function:Get-SIManagedIdentityToken}
            $getToken = { & $miFn -Resource 'https://database.windows.net/' }.GetNewClosure()
        } else {
            if (-not (Get-Command -Name 'Get-SILedgerAccessToken' -ErrorAction SilentlyContinue)) {
                throw 'New-SIVulnTargetSql: the SQL token helper (data-model\identity\SI-ObjectLedgerStore.ps1) is not installed.'
            }
            $cert = Get-SILedgerCertificate -Thumbprint $CertThumbprint
            if (-not $cert) { throw ("New-SIVulnTargetSql: certificate {0} with a private key was not found in LocalMachine or CurrentUser." -f $CertThumbprint) }
            $tokenFn = ${function:Get-SILedgerAccessToken}
            $getToken = { & $tokenFn -Certificate $cert -AppId $app -TenantId $ten }.GetNewClosure()
        }
        # ONE token per ~45 minutes, not one per statement: a first sync opens thousands of records (measured on
        # the internal tenant: 12,208), and a sign-in per row is both slow and a throttling risk. The holder is a
        # hashtable so the closure's copy and every later call share it.
        $tokenCache = @{ Token = $null; Until = [datetime]::MinValue }
        $Invoke = {
            param([string]$sql, $p, [string]$mode)
            if (-not $tokenCache.Token -or [datetime]::UtcNow -ge $tokenCache.Until) {
                $tokenCache.Token = & $getToken
                $tokenCache.Until = [datetime]::UtcNow.AddMinutes(45)
            }
            $token = $tokenCache.Token
            $cs = 'Server=tcp:{0},1433;Database={1};Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;' -f $srv, $db
            $cn = New-Object System.Data.SqlClient.SqlConnection($cs)
            $cn.AccessToken = $token
            try {
                $cn.Open()
                $cmd = $cn.CreateCommand(); $cmd.CommandText = $sql; $cmd.CommandTimeout = 0
                if ($p) { foreach ($k in $p.Keys) { [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [System.DBNull]::Value } else { $p[$k] })) } }
                switch ($mode) {
                    'reader' {
                        $rd = $cmd.ExecuteReader()
                        $out = New-Object System.Collections.Generic.List[object]
                        while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $out.Add($h) }
                        $rd.Close(); , $out.ToArray()
                    }
                    'scalar' { $cmd.ExecuteScalar() }
                    default  { [void]$cmd.ExecuteNonQuery() }
                }
            } finally { $cn.Dispose() }
        }.GetNewClosure()
    }
    $t = [pscustomobject]@{ Kind = 'Sql'; Name = ('{0}/{1}' -f $Server, $Database); Source = $Source; RunId = $RunId; Actor = $Actor; Invoke = $Invoke; CountsAbsence = $true
                            # 2026-10-06: AssetId / FindingType / Title / Report (sql\si-vulnerability-target.sql adds them in
                            # place). A database not yet re-initialised is written exactly as before -- without them.
                            HasFindingColumns = $false
                            # #561: the Component column (sql\si-vulnerability-target.sql adds it in place); without it, written as before
                            HasComponentColumn = $false
                            # #772: the SubCi column (the ServiceNow sub-CI; sql\si-vulnerability-target.sql adds it in place)
                            HasSubCiColumn = $false; HasOsFamilyColumn = $false; HasPatchCycleColumn = $false
                            # #914: SiBatchId / LastAction / Cleared (sql\si-vulnerability-target.sql adds them in place); SiBatchId = the
                            # run's batch (Start-SIVulnSqlBatch sets it) -- every write of the run stamps it, never the batch end
                            HasContractColumns = $false; SiBatchId = '' }
    $t | Add-Member -NotePropertyName ColumnsKnown -NotePropertyValue $false
    $t | Add-Member -MemberType ScriptMethod -Name Read -Value { $this.ReadWhere('', @{}) }
    # #850 one page of CI keys: every record (open or closed) stored under these keys -- never the whole table
    $t | Add-Member -MemberType ScriptMethod -Name ReadKeys -Value {
        param([string[]]$Keys)
        $ks = @($Keys | Where-Object { $_ })
        if ($ks.Count -eq 0) { return }
        $this.ReadWhere(' AND CorrelationId IN (SELECT [value] FROM OPENJSON(@KeyList))', @{ KeyList = (ConvertTo-Json -InputObject ([string[]]$ks) -Compress) })
    }
    # #850 the next CI keys the table holds after -After, in the table's own order (the unique key's index), with how
    # many records each has: @{ Keys; Rows; Last; Done }
    $t | Add-Member -MemberType ScriptMethod -Name KeysAfter -Value {
        param([string]$After, [int]$Take)
        $rows = & $this.Invoke 'SELECT TOP (CONVERT(int, @Take)) CorrelationId AS K, COUNT(*) AS N FROM vuln.VulnerabilityItem WHERE Source = @Source AND (@After IS NULL OR CorrelationId > @After) GROUP BY CorrelationId ORDER BY CorrelationId' @{ Source = $this.Source; After = $(if ($After) { $After } else { $null }); Take = $Take } 'reader'
        $rows = @($rows)   # the reader hands back ONE array; wrapping the call itself would nest it
        $keys = New-Object System.Collections.Generic.List[string]; $n = 0L
        $counts = New-Object System.Collections.Generic.List[long]
        foreach ($r in $rows) { if ($null -eq $r) { continue }; $keys.Add([string]$r['K']); $counts.Add([long]$r['N']); $n += [long]$r['N'] }
        [pscustomobject]@{ Keys = $keys.ToArray(); Counts = $counts.ToArray(); Rows = $n; Last = $(if ($keys.Count) { $keys[$keys.Count - 1] } else { $After }); Done = ($keys.Count -lt $Take) }
    }
    $t | Add-Member -MemberType ScriptMethod -Name ReadWhere -Value {
        param([string]$Where, [hashtable]$Params)
        # SELECT * on purpose (#217): a database from before the absence count has no AbsentRuns / LastAbsentSnapshot
        # yet (the job's identity reads and writes rows; it cannot ALTER the table), and naming them would fail every
        # run until the schema is re-applied. Whether they come back decides whether this target can count at all.
        # get_Keys(), never .Keys: the page's parameter IS named Keys, and .Keys would read its value (#835)
        $p = @{ Source = $this.Source }; if ($Params) { foreach ($k in @($Params.get_Keys())) { $p[$k] = $Params[$k] } }
        $rows = & $this.Invoke ('SELECT * FROM vuln.VulnerabilityItem WHERE Source = @Source' + $Where) $p 'reader'
        $rows = @($rows)   # the reader hands back ONE array; wrapping the call itself would nest it
        $first = @($rows | Where-Object { $null -ne $_ } | Select-Object -First 1)
        if ($this.ColumnsKnown -and -not $first.Count) { }
        elseif ($first.Count) {
            $this.ColumnsKnown = $true
            $f0 = $first[0]
            $this.CountsAbsence = [bool]$(if ($f0 -is [System.Collections.IDictionary]) { $f0.Contains('AbsentRuns') } else { $null -ne $f0.PSObject.Properties['AbsentRuns'] })
            $this.HasFindingColumns = [bool]$(if ($f0 -is [System.Collections.IDictionary]) { $f0.Contains('FindingType') } else { $null -ne $f0.PSObject.Properties['FindingType'] })
            $this.HasComponentColumn = [bool]$(if ($f0 -is [System.Collections.IDictionary]) { $f0.Contains('Component') } else { $null -ne $f0.PSObject.Properties['Component'] })
            $this.HasSubCiColumn = [bool]$(if ($f0 -is [System.Collections.IDictionary]) { $f0.Contains('SubCi') } else { $null -ne $f0.PSObject.Properties['SubCi'] })
            $this.HasOsFamilyColumn = [bool]$(if ($f0 -is [System.Collections.IDictionary]) { $f0.Contains('OsFamily') } else { $null -ne $f0.PSObject.Properties['OsFamily'] })
            $this.HasPatchCycleColumn = [bool]$(if ($f0 -is [System.Collections.IDictionary]) { $f0.Contains('PatchCycle') } else { $null -ne $f0.PSObject.Properties['PatchCycle'] })
            $this.HasContractColumns = [bool]$(if ($f0 -is [System.Collections.IDictionary]) { $f0.Contains('Cleared') } else { $null -ne $f0.PSObject.Properties['Cleared'] })
        } else {
            $this.ColumnsKnown = $true
            # an empty table says nothing about its columns: ask
            $has = 0
            try { $has = [int](& $this.Invoke "SELECT CASE WHEN COL_LENGTH('vuln.VulnerabilityItem', 'FindingType') IS NULL THEN 0 ELSE 1 END" @{} 'scalar') } catch { $has = 0 }
            $this.HasFindingColumns = ($has -eq 1)
            $hc = 0
            try { $hc = [int](& $this.Invoke "SELECT CASE WHEN COL_LENGTH('vuln.VulnerabilityItem', 'Component') IS NULL THEN 0 ELSE 1 END" @{} 'scalar') } catch { $hc = 0 }
            $this.HasComponentColumn = ($hc -eq 1)
            $hs = 0
            try { $hs = [int](& $this.Invoke "SELECT CASE WHEN COL_LENGTH('vuln.VulnerabilityItem', 'SubCi') IS NULL THEN 0 ELSE 1 END" @{} 'scalar') } catch { $hs = 0 }
            $this.HasSubCiColumn = ($hs -eq 1)
            $ho = 0
            try { $ho = [int](& $this.Invoke "SELECT CASE WHEN COL_LENGTH('vuln.VulnerabilityItem', 'OsFamily') IS NULL THEN 0 ELSE 1 END" @{} 'scalar') } catch { $ho = 0 }
            $this.HasOsFamilyColumn = ($ho -eq 1)
            $hp = 0
            try { $hp = [int](& $this.Invoke "SELECT CASE WHEN COL_LENGTH('vuln.VulnerabilityItem', 'PatchCycle') IS NULL THEN 0 ELSE 1 END" @{} 'scalar') } catch { $hp = 0 }
            $this.HasPatchCycleColumn = ($hp -eq 1)
            $hk = 0
            try { $hk = [int](& $this.Invoke "SELECT CASE WHEN COL_LENGTH('vuln.VulnerabilityItem', 'Cleared') IS NULL THEN 0 ELSE 1 END" @{} 'scalar') } catch { $hk = 0 }
            $this.HasContractColumns = ($hk -eq 1)
        }
        # #639 (7): lean records, and each data row let go as soon as it is converted (on a copy of the list -- never the
        # reader's own array), so the whole table is never held twice
        $buf = [object[]]::new($rows.Count); [Array]::Copy([object[]]$rows, $buf, $rows.Count); $rows = $null
        $makers = @{}
        for ($i = 0; $i -lt $buf.Length; $i++) {
            $r = $buf[$i]; $buf[$i] = $null
            if ($null -ne $r) { ConvertTo-SIVulnSqlRecord -Row $r -Makers $makers }
        }
    }
    $t | Add-Member -MemberType ScriptMethod -Name Open -Value {
        param($rec)
        $fc = ''; $fv = ''
        if ($this.HasFindingColumns) { $fc = ', AssetId, FindingType, Title, Report'; $fv = ", NULLIF(@AssetId, N''), NULLIF(@FindingType, N''), NULLIF(@Title, N''), NULLIF(@Report, N'')" }
        if ($this.HasComponentColumn) { $fc += ', Component'; $fv += ", NULLIF(@Component, N'')" }
        if ($this.HasSubCiColumn) { $fc += ', SubCi'; $fv += ", NULLIF(@SubCi, N'')" }
        if ($this.HasOsFamilyColumn) { $fc += ', OsFamily'; $fv += ", NULLIF(@OsFamily, N'')" }
        if ($this.HasPatchCycleColumn) { $fc += ', PatchCycle'; $fv += ", NULLIF(@PatchCycle, N'')" }
        $stamp = ($this.HasContractColumns -and [bool]$this.SiBatchId)
        if ($stamp) { $fc += ', SiBatchId, LastAction'; $fv += ", @SiBatch, N'new'" }
        $sql = @"
DECLARE @id uniqueidentifier = NEWID();
INSERT vuln.VulnerabilityItem (SysId, CorrelationId, CiId, AssetName, Cve, Severity, State, FirstSeen, LastSeen, Source$fc)
VALUES (@id, @CorrelationId, @CiId, @AssetName, @Cve, @Severity, 'Open', SYSUTCDATETIME(), SYSUTCDATETIME(), @Source$fv);
INSERT vuln.VulnerabilityEvent (SysId, Action, FromState, ToState, Reason, RunId, Actor)
VALUES (@id, 'Open', NULL, 'Open', @Reason, @RunId, @Actor);
SELECT CONVERT(nvarchar(36), @id);
"@
        $p = [ordered]@{ CorrelationId = [string]$rec.CorrelationId; CiId = [string]$rec.CiId; AssetName = [string]$rec.AssetName
                         Cve = [string]$rec.Cve; Severity = [string]$rec.Severity; Source = $this.Source
                         Reason = 'Reported by SecurityInsight'; RunId = $this.RunId; Actor = $this.Actor }
        if ($this.HasFindingColumns) { foreach ($k in 'AssetId', 'FindingType', 'Title', 'Report') { $p[$k] = $(if ($rec.PSObject.Properties[$k]) { [string]$rec.$k } else { '' }) } }
        if ($this.HasComponentColumn) { $p['Component'] = $(if ($rec.PSObject.Properties['Component']) { [string]$rec.Component } else { '' }) }
        if ($this.HasSubCiColumn) { $p['SubCi'] = $(if ($rec.PSObject.Properties['SubCi']) { [string]$rec.SubCi } else { '' }) }
        if ($this.HasOsFamilyColumn) { $p['OsFamily'] = $(if ($rec.PSObject.Properties['OsFamily']) { [string]$rec.OsFamily } else { '' }) }
        if ($this.HasPatchCycleColumn) { $p['PatchCycle'] = $(if ($rec.PSObject.Properties['PatchCycle']) { [string]$rec.PatchCycle } else { '' }) }
        if ($stamp) { $p['SiBatch'] = [string]$this.SiBatchId }
        try { $id = & $this.Invoke $sql $p 'scalar'; @{ Ok = $true; Id = [string]$id; Error = '' } }
        catch { @{ Ok = $false; Id = ''; Error = $_.Exception.Message } }
    }
    $t | Add-Member -MemberType ScriptMethod -Name Update -Value {
        param([string]$sysId, [hashtable]$values, [string]$why)
        $st = Get-SIVulnSqlUpdateStatement -Values $values -BatchId $(if ($this.HasContractColumns) { [string]$this.SiBatchId } else { '' })
        $p = [ordered]@{ SysId = [guid]$sysId }
        foreach ($k in $st.Params.Keys) { $p[$k] = $st.Params[$k] }
        $action = if ($values.ContainsKey('State')) { [string]$values['State'] } else { 'Seen' }
        if ($action -eq 'Open') { $action = 'Reopen' } elseif ($action -eq 'Closed') { $action = 'Close' }
        $p['Action'] = $action; $p['Reason'] = $(if ($why) { $why } else { [System.DBNull]::Value }); $p['RunId'] = $this.RunId; $p['Actor'] = $this.Actor
        try { & $this.Invoke $st.Sql $p 'nonquery'; @{ Ok = $true; Error = '' } }
        catch { @{ Ok = $false; Error = $_.Exception.Message } }
    }
    # SET-BASED, for the two verbs that touch thousands of rows. Measured on the internal tenant's first sync:
    # one statement per record ran at ~5.6 records/s (12,208 findings = ~36 minutes), and every later run would
    # refresh every open record the same way. A chunk travels as ONE JSON parameter and lands in one statement,
    # inside one transaction -- all of the chunk or none of it.
    $t | Add-Member -MemberType ScriptMethod -Name OpenMany -Value {
        param([object[]]$records)
        $fc = ''; $fv = ''; $fw = ''
        if ($this.HasFindingColumns) {
            $fc = ', AssetId, FindingType, Title, Report'
            $fv = ", NULLIF(j.AssetId, ''), NULLIF(j.FindingType, ''), NULLIF(j.Title, ''), NULLIF(j.Report, '')"
            $fw = ', AssetId nvarchar(400), FindingType nvarchar(32), Title nvarchar(400), Report nvarchar(256)'
        }
        if ($this.HasComponentColumn) { $fc += ', Component'; $fv += ", NULLIF(j.Component, '')"; $fw += ', Component nvarchar(32)' }
        if ($this.HasSubCiColumn) { $fc += ', SubCi'; $fv += ", NULLIF(j.SubCi, '')"; $fw += ', SubCi nvarchar(64)' }
        if ($this.HasOsFamilyColumn) { $fc += ', OsFamily'; $fv += ", NULLIF(j.OsFamily, '')"; $fw += ', OsFamily nvarchar(64)' }
        if ($this.HasPatchCycleColumn) { $fc += ', PatchCycle'; $fv += ", NULLIF(j.PatchCycle, '')"; $fw += ', PatchCycle nvarchar(64)' }
        # #429 -- PER RECORD, NEVER ALL-OR-NOTHING ON A KEY. Ring 1, 2026-10-07: 40 findings whose (source, asset, finding) key
        # was already held by a record (a duplicate retired the run before) failed the WHOLE chunk -- 801 opens, 0 landed.
        # Now every record is checked against the unique key first: one already on the target, or the same finding twice in
        # this call, is answered for on its own (Existing / Twin) and the rest are opened. One answer row per record (Pos).
        $fcols = ''; $fsel = ''
        if ($this.HasFindingColumns) { $fcols = ', AssetId nvarchar(400), FindingType nvarchar(32), Title nvarchar(400), Report nvarchar(256)'; $fsel = ', j.AssetId, j.FindingType, j.Title, j.Report' }
        if ($this.HasComponentColumn) { $fcols += ', Component nvarchar(32)'; $fsel += ', j.Component' }
        if ($this.HasSubCiColumn) { $fcols += ', SubCi nvarchar(64)'; $fsel += ', j.SubCi' }
        if ($this.HasOsFamilyColumn) { $fcols += ', OsFamily nvarchar(64)'; $fsel += ', j.OsFamily' }
        if ($this.HasPatchCycleColumn) { $fcols += ', PatchCycle nvarchar(64)'; $fsel += ', j.PatchCycle' }
        $fv = $fv -replace 'j\.', 'x.'
        $bc = ''; $bv = ''
        if ($this.HasContractColumns -and $this.SiBatchId) { $bc = ', SiBatchId, LastAction'; $bv = ", @SiBatch, N'new'" }
        $sql = @"
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @in TABLE (Pos int PRIMARY KEY, SysId uniqueidentifier NOT NULL, CorrelationId nvarchar(400), CiId nvarchar(400), AssetName nvarchar(400), Cve nvarchar(100), Severity nvarchar(30)$fcols,
                   Existing uniqueidentifier NULL, ExistingState nvarchar(20) NULL, Twin int NULL);
INSERT @in (Pos, SysId, CorrelationId, CiId, AssetName, Cve, Severity$($fc))
SELECT CAST(a.[key] AS int), NEWID(), j.CorrelationId, j.CiId, j.AssetName, j.Cve, j.Severity$fsel
FROM OPENJSON(@j) a CROSS APPLY OPENJSON(a.[value]) WITH (CorrelationId nvarchar(400), CiId nvarchar(400), AssetName nvarchar(400), Cve nvarchar(100), Severity nvarchar(30)$fw) j;
UPDATE x SET Existing = v.SysId, ExistingState = v.State
FROM @in x JOIN vuln.VulnerabilityItem v WITH (UPDLOCK, HOLDLOCK) ON v.Source = @Source AND v.CorrelationId = x.CorrelationId AND v.Cve = x.Cve;
UPDATE x SET Twin = f.Pos FROM @in x CROSS APPLY (SELECT MIN(y.Pos) AS Pos FROM @in y WHERE y.CorrelationId = x.CorrelationId AND y.Cve = x.Cve) f WHERE f.Pos < x.Pos;
INSERT vuln.VulnerabilityItem (SysId, CorrelationId, CiId, AssetName, Cve, Severity, State, FirstSeen, LastSeen, Source$fc$bc)
SELECT x.SysId, x.CorrelationId, NULLIF(x.CiId, ''), NULLIF(x.AssetName, ''), x.Cve, NULLIF(x.Severity, ''), 'Open', SYSUTCDATETIME(), SYSUTCDATETIME(), @Source$fv$bv
FROM @in x WHERE x.Existing IS NULL AND x.Twin IS NULL;
INSERT vuln.VulnerabilityEvent (SysId, Action, FromState, ToState, Reason, RunId, Actor)
SELECT x.SysId, 'Open', NULL, 'Open', 'Reported by SecurityInsight', @RunId, @Actor FROM @in x WHERE x.Existing IS NULL AND x.Twin IS NULL;
COMMIT;
SELECT x.Pos, CONVERT(nvarchar(36), x.SysId) AS SysId, CONVERT(nvarchar(36), x.Existing) AS Existing, x.ExistingState, x.Twin FROM @in x ORDER BY x.Pos;
"@
        $opt = { param($o, [string]$n) if ($o.PSObject.Properties[$n]) { [string]$o.$n } else { '' } }
        $rows = @($records | ForEach-Object { [pscustomobject]@{ CorrelationId = [string]$_.CorrelationId; CiId = [string]$_.CiId; AssetName = [string]$_.AssetName; Cve = [string]$_.Cve; Severity = [string]$_.Severity
                                                                 AssetId = (& $opt $_ 'AssetId'); FindingType = (& $opt $_ 'FindingType'); Title = (& $opt $_ 'Title'); Report = (& $opt $_ 'Report'); Component = (& $opt $_ 'Component'); SubCi = (& $opt $_ 'SubCi'); OsFamily = (& $opt $_ 'OsFamily'); PatchCycle = (& $opt $_ 'PatchCycle') } })
        $json = ConvertTo-Json -InputObject @($rows) -Compress -Depth 3
        $op = [ordered]@{ j = $json; Source = $this.Source; RunId = $this.RunId; Actor = $this.Actor }; if ($bc) { $op['SiBatch'] = [string]$this.SiBatchId }
        try { $answer = @(& $this.Invoke $sql $op 'reader') }
        catch { return @{ Ok = $false; Count = 0; Error = $_.Exception.Message } }
        ConvertFrom-SIVulnSqlOpenAnswer -Answer $answer -Count $rows.Count
    }
    $t | Add-Member -MemberType ScriptMethod -Name TouchMany -Value {
        param([object[]]$items)   # SysId, Severity
        # Seen = the absence count starts over (#217) -- only where the columns exist (see Read).
        $reset = if ($this.CountsAbsence) { ', AbsentRuns = 0, LastAbsentSnapshot = NULL' } else { '' }
        # 2026-10-06: the finding's asset id, type, name and report, as the newest results give them (a record from before
        # gets them on its first refresh) -- only where the columns exist
        $fs = ''; $fw = ''
        if ($this.HasFindingColumns) {
            $fs = ", AssetId = COALESCE(NULLIF(j.AssetId, ''), i.AssetId), FindingType = COALESCE(NULLIF(j.FindingType, ''), i.FindingType), Title = COALESCE(NULLIF(j.Title, ''), i.Title), Report = COALESCE(NULLIF(j.Report, ''), i.Report)"
            $fw = ', AssetId nvarchar(400), FindingType nvarchar(32), Title nvarchar(400), Report nvarchar(256)'
        }
        if ($this.HasComponentColumn) { $fs += ", Component = COALESCE(NULLIF(j.Component, ''), i.Component)"; $fw += ', Component nvarchar(32)' }
        if ($this.HasSubCiColumn) { $fs += ", SubCi = COALESCE(NULLIF(j.SubCi, ''), i.SubCi)"; $fw += ', SubCi nvarchar(64)' }
        if ($this.HasOsFamilyColumn) { $fs += ", OsFamily = COALESCE(NULLIF(j.OsFamily, ''), i.OsFamily)"; $fw += ', OsFamily nvarchar(64)' }
        if ($this.HasPatchCycleColumn) { $fs += ", PatchCycle = COALESCE(NULLIF(j.PatchCycle, ''), i.PatchCycle)"; $fw += ', PatchCycle nvarchar(64)' }
        # #914: still seen = this batch's update (an action the batch already gave -- new, reopen -- is kept)
        $ct = ''; if ($this.HasContractColumns -and $this.SiBatchId) { $ct = ', SiBatchId = @SiBatch, LastAction = CASE WHEN i.SiBatchId = @SiBatch THEN i.LastAction END' }
        $sql = @"
UPDATE i SET LastSeen = SYSUTCDATETIME(), Severity = COALESCE(NULLIF(j.Severity, ''), i.Severity)$reset$fs$ct,
       UpdatedAt = CASE WHEN ISNULL(j.Changed, 1) = 1 THEN SYSUTCDATETIME() ELSE i.UpdatedAt END
FROM vuln.VulnerabilityItem i
JOIN OPENJSON(@j) WITH (SysId uniqueidentifier, Severity nvarchar(30)$fw, Changed bit) j ON i.SysId = j.SysId;
SELECT @@ROWCOUNT;
"@
        # #429: UpdatedAt is the hand-off's change column (u_changed_at) -- a "still seen" refresh that changes no field SI
        # sends leaves it alone, so ServiceNow does not re-import every open record on every run.
        $opt = { param($o, [string]$n) if ($o.PSObject.Properties[$n]) { [string]$o.$n } else { '' } }
        $rows = @($items | ForEach-Object { [pscustomobject]@{ SysId = [string]$_.SysId; Severity = [string]$_.Severity
                                                               AssetId = (& $opt $_ 'AssetId'); FindingType = (& $opt $_ 'FindingType'); Title = (& $opt $_ 'Title'); Report = (& $opt $_ 'Report'); Component = (& $opt $_ 'Component'); SubCi = (& $opt $_ 'SubCi'); OsFamily = (& $opt $_ 'OsFamily'); PatchCycle = (& $opt $_ 'PatchCycle')
                                                               Changed = $(if ($_.PSObject.Properties['Changed']) { [bool]$_.Changed } else { $true }) } })
        $json = ConvertTo-Json -InputObject @($rows) -Compress -Depth 3
        $tp = [ordered]@{ j = $json }; if ($ct) { $tp['SiBatch'] = [string]$this.SiBatchId }
        try { $n = & $this.Invoke $sql $tp 'scalar'; @{ Ok = $true; Count = [int]$n; Error = '' } }
        catch { @{ Ok = $false; Count = 0; Error = $_.Exception.Message } }
    }
    # #217: the absence count, set-based. Not a state change, so no event row (the close that follows is one).
    $t | Add-Member -MemberType ScriptMethod -Name MarkAbsentMany -Value {
        param([object[]]$items)   # SysId, AbsentRuns, Snapshot
        $sql = @'
UPDATE i SET AbsentRuns = j.AbsentRuns, LastAbsentSnapshot = j.Snapshot, UpdatedAt = SYSUTCDATETIME(){CT}
FROM vuln.VulnerabilityItem i
JOIN OPENJSON(@j) WITH (SysId uniqueidentifier, AbsentRuns int, Snapshot datetime2(0)) j ON i.SysId = j.SysId
WHERE i.State = 'Open';
SELECT @@ROWCOUNT;
'@
        # #914: an absence being counted is this batch's held (the view says held while the count runs)
        $mp = [ordered]@{}
        if ($this.HasContractColumns -and $this.SiBatchId) { $sql = $sql.Replace('{CT}', ', SiBatchId = @SiBatch, LastAction = CASE WHEN i.SiBatchId = @SiBatch THEN i.LastAction END'); $mp['SiBatch'] = [string]$this.SiBatchId } else { $sql = $sql.Replace('{CT}', '') }
        $rows = @($items | ForEach-Object { [pscustomobject]@{ SysId = [string]$_.SysId; AbsentRuns = [int]$_.AbsentRuns; Snapshot = ([datetime]$_.Snapshot).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') } })
        $json = ConvertTo-Json -InputObject @($rows) -Compress -Depth 3
        $mp['j'] = $json
        try { $n = & $this.Invoke $sql $mp 'scalar'; @{ Ok = $true; Count = [int]$n; Error = '' } }
        catch { @{ Ok = $false; Count = 0; Error = $_.Exception.Message } }
    }
    # #279 decision 1: the re-key, in ONE transaction and ONE update statement. One statement matters: the table allows one
    # row per (source, asset, CVE), and a duplicate pair SWAPS ids (the older record takes the current id, the retired
    # copy the previous one) -- a key that is only unique again at the end of the statement. Every row gets an event:
    # 'Rekey' (asset id moved, state unchanged) or 'Duplicate' (retired: Closed, CloseReason 'Duplicate', never fixed).
    # All of it lands or none of it does; a record that is not SecurityInsight's (another Source) refuses the whole call.
    $t | Add-Member -MemberType ScriptMethod -Name Rekey -Value {
        param([object[]]$ops)   # Pair, Role, SysId, NewId, NewName, Retire, Why
        $sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @ops TABLE (SysId uniqueidentifier PRIMARY KEY, NewId nvarchar(400) NOT NULL, NewName nvarchar(400) NULL, Retire bit NOT NULL, Why nvarchar(400) NULL);
INSERT @ops (SysId, NewId, NewName, Retire, Why)
SELECT j.SysId, j.NewId, NULLIF(j.NewName, ''), j.Retire, LEFT(j.Why, 400)
FROM OPENJSON(@j) WITH (SysId uniqueidentifier, NewId nvarchar(400), NewName nvarchar(400), Retire bit, Why nvarchar(max)) j;
DECLARE @before TABLE (SysId uniqueidentifier PRIMARY KEY, State nvarchar(20));
INSERT @before (SysId, State)
SELECT i.SysId, i.State FROM vuln.VulnerabilityItem i WITH (UPDLOCK) JOIN @ops o ON o.SysId = i.SysId WHERE i.Source = @Source;
IF (SELECT COUNT(*) FROM @before) <> (SELECT COUNT(*) FROM @ops) THROW 50002, 'a record to re-key is missing or is not SecurityInsight''s -- nothing re-keyed', 1;
UPDATE i SET CorrelationId = o.NewId, AssetName = COALESCE(o.NewName, i.AssetName),
       State = CASE WHEN o.Retire = 1 THEN 'Closed' ELSE i.State END,
       CloseReason = CASE WHEN o.Retire = 1 THEN @Reason ELSE i.CloseReason END,
       ClosedAt = CASE WHEN o.Retire = 1 THEN SYSUTCDATETIME() ELSE i.ClosedAt END,
       UpdatedAt = SYSUTCDATETIME(){CT}
FROM vuln.VulnerabilityItem i JOIN @ops o ON o.SysId = i.SysId;
INSERT vuln.VulnerabilityEvent (SysId, Action, FromState, ToState, Reason, RunId, Actor)
SELECT o.SysId, CASE WHEN o.Retire = 1 THEN 'Duplicate' ELSE 'Rekey' END, b.State, CASE WHEN o.Retire = 1 THEN 'Closed' ELSE b.State END, o.Why, @RunId, @Actor
FROM @ops o JOIN @before b ON b.SysId = o.SysId;
COMMIT;
SELECT COUNT(*) FROM @ops;
'@
        $rows = @($ops | ForEach-Object { [pscustomobject]@{ SysId = [string]$_.SysId; NewId = [string]$_.NewId; NewName = [string]$_.NewName; Retire = [bool]$_.Retire; Why = [string]$_.Why } })
        $json = ConvertTo-Json -InputObject @($rows) -Compress -Depth 3
        $one = $null
        $rk = [ordered]@{ j = $json; Source = $this.Source; Reason = 'Duplicate'; RunId = $this.RunId; Actor = $this.Actor }
        if ($this.HasContractColumns -and $this.SiBatchId) { $sql = $sql.Replace('{CT}', ", SiBatchId = @SiBatch, LastAction = CASE WHEN o.Retire = 1 THEN NULL WHEN i.SiBatchId = @SiBatch THEN i.LastAction END"); $rk['SiBatch'] = [string]$this.SiBatchId } else { $sql = $sql.Replace('{CT}', '') }
        try { $n = & $this.Invoke $sql $rk 'scalar'; $one = @{ Ok = $true; Error = '' } }
        catch { $one = @{ Ok = $false; Error = $_.Exception.Message } }
        $results = New-Object object[] ($ops.Count)
        for ($x = 0; $x -lt $ops.Count; $x++) { $results[$x] = $one }
        @{ Ok = [bool]$one.Ok; Count = $(if ($one.Ok) { $ops.Count } else { 0 }); Error = [string]$one.Error; Results = $results }
    }
    $t
}

# =====================================================================================================================
#  #914 THE ONE CONTRACT FOR THE SQL VULNERABILITY CONNECTOR: every run of a SQL vulnerability connector is ONE BATCH in
#  vuln.SyncRun (sql/si-vulnerability-target.sql), the same words as the ServiceNow staging status table and cmdbsync.SyncRun:
#  'writing' first (an earlier batch of the same connector still 'writing' is ended 'failed' -- never two open batches),
#  then 'complete' (the run applied), 'held' (its guard held it) or 'failed'. Every record the run writes carries its batch
#  id (vuln.VulnerabilityItem.SiBatchId) FROM THE WRITE ITSELF -- the batch row is written first, so the id always names a
#  batch a reader can look up. The close-loop writes record by record, NOT in one transaction: a reader may see a run's rows
#  while its batch is still 'writing' -- and knows it, because those rows carry that batch's id. The rule for every reader:
#  act only on rows whose u_si_batch_id names a complete batch.
# =====================================================================================================================

# #914 THE CLEAR MARKER of a vulnerable item: the clearable columns (data-out\SI-DataOutContract.ps1, the push's list -- the
# parity test holds the two equal) -> the record column that carries each. A held record (open, absence being counted) has none.
$script:SIVulnSqlClearedColumns = [ordered]@{
    'u_cmdb_ci' = 'CiId'; 'u_severity' = 'Severity'; 'u_closed_at' = 'ClosedAt'; 'u_close_reason' = 'CloseReason'; 'u_title' = 'Title'
    'u_si_component' = 'Component'; 'u_si_servicenow_subci' = 'SubCi'; 'u_si_os_family' = 'OsFamily'; 'u_si_patch_cycle' = 'PatchCycle'
}

function Get-SIVulnSqlClearedColumnMap { <# PURE. Clearable view column -> the record column that carries it (a copy). #> $c = [ordered]@{}; foreach ($k in $script:SIVulnSqlClearedColumns.Keys) { $c[$k] = $script:SIVulnSqlClearedColumns[$k] }; $c }

function Get-SIVulnSqlClearedList {
    <# PURE. The clear marker of one record (-Record: vuln.VulnerabilityItem columns), what the batch end writes: $null when held or none is empty. #>
    param($Record)
    $get = { param([string]$n) if ($Record -is [System.Collections.IDictionary]) { if ($Record.Contains($n)) { return $Record[$n] }; return $null }; if ($Record -and $Record.PSObject.Properties[$n]) { return $Record.$n }; $null }
    $ar = 0; [void][int]::TryParse([string](& $get 'AbsentRuns'), [ref]$ar)
    if ([string](& $get 'State') -eq 'Open' -and $ar -gt 0) { return $null }
    $out = @(foreach ($k in $script:SIVulnSqlClearedColumns.Keys) { $v = & $get $script:SIVulnSqlClearedColumns[$k]; if ($null -eq $v -or ([string]$v) -eq '') { $k } })
    if ($out.Count -eq 0) { return $null }
    $out -join ','
}

function Get-SIVulnSqlClearedSql {
    <# PURE. The clear marker as SQL over the record's own columns (quotes doubled for text inside N'...'), NULL when none is empty. #>
    $parts = foreach ($k in $script:SIVulnSqlClearedColumns.Keys) { ("CASE WHEN NULLIF(CAST({0} AS nvarchar(512)), N'''') IS NULL THEN N'',{1}'' END" -f $script:SIVulnSqlClearedColumns[$k], $k) }
    ("CASE WHEN State = N''Open'' AND ISNULL(AbsentRuns, 0) > 0 THEN NULL ELSE NULLIF(STUFF(CONCAT({0}), 1, 1, N''''), N'''') END" -f ($parts -join ', '))
}

function Get-SIVulnSqlBatchId {
    <# PURE. The batch id of one run of a SQL vulnerability connector: <run>:vuln-sql:<connector>, at most 100 characters. #>
    param([Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$Connector)
    $bid = ('{0}:vuln-sql:{1}' -f $RunId, $Connector)
    if ($bid.Length -gt 100) { $bid = $bid.Substring(0, 100) }
    $bid
}

function Get-SIVulnSqlBatchStartSql {
    <# The batch's writing row (every earlier writing batch of the connector ended failed first). Answers Stale. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('vuln.SyncRun') IS NULL BEGIN SELECT CAST(0 AS int) AS Stale; RETURN; END;
DECLARE @n int = 0;
UPDATE vuln.SyncRun SET BatchState = N'failed', EndedAt = SYSUTCDATETIME(),
       Reason = N'a later run started while this run was still writing -- it never ended, so it is ended as failed'
WHERE Connector = @Connector AND BatchState = N'writing' AND SiBatchId <> @BatchId;
SET @n = @@ROWCOUNT;
IF NOT EXISTS (SELECT 1 FROM vuln.SyncRun WHERE SiBatchId = @BatchId)
    INSERT vuln.SyncRun (SiBatchId, RunId, Connector, BatchState, StartedAt, Reason, ContractVersion, Mode, SolutionVersion)
    VALUES (@BatchId, @RunId, @Connector, N'writing', SYSUTCDATETIME(), N'writing -- the run has started', @ContractVersion, @Mode, NULLIF(@SolutionVersion, N''));
SELECT @n AS Stale;
'@
}

function Get-SIVulnSqlBatchEndSql {
    <#
        The batch's end: its state and reason; the batch id on every record the run changed (an event of this run); the counts
        per action from the run's events (Open = new, Seen = update, Close = close, Reopen = reopen, EngineerClose too), the
        held records (the plan's), and what landed (the records the run changed).
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('vuln.SyncRun') IS NULL RETURN;
-- the batch id is on every record this run wrote since its first write (stamped at write time); the clear marker of those
-- records is written here, from what they hold now
IF COL_LENGTH('vuln.VulnerabilityItem', 'Cleared') IS NOT NULL AND COL_LENGTH('vuln.VulnerabilityItem', 'PatchCycle') IS NOT NULL
    EXEC sp_executesql N'UPDATE vuln.VulnerabilityItem SET Cleared = {CLEARED} WHERE SiBatchId = @b',
        N'@b nvarchar(100)', @b = @BatchId;
UPDATE s SET BatchState = @State, EndedAt = SYSUTCDATETIME(), Reason = LEFT(NULLIF(@Reason, N''), 1000),
       NewRows = (SELECT COUNT(*) FROM vuln.VulnerabilityEvent WHERE RunId = @RunId AND Action = N'Open'),
       UpdateRows = (SELECT COUNT(*) FROM vuln.VulnerabilityEvent WHERE RunId = @RunId AND Action = N'Seen'),
       CloseRows = (SELECT COUNT(*) FROM vuln.VulnerabilityEvent WHERE RunId = @RunId AND Action = N'Close'),
       ReopenRows = (SELECT COUNT(*) FROM vuln.VulnerabilityEvent WHERE RunId = @RunId AND Action = N'Reopen'),
       HeldRows = @Held, OutOfScopeRows = @OutOfScope,
       LandedRows = (SELECT COUNT(DISTINCT SysId) FROM vuln.VulnerabilityEvent WHERE RunId = @RunId)
FROM vuln.SyncRun AS s WHERE s.SiBatchId = @BatchId;
'@.Replace('{CLEARED}', (Get-SIVulnSqlClearedSql))
}

function Start-SIVulnSqlBatch {
    <# The writing row of a SQL connector's run (-Target: New-SIVulnTargetSql). Returns the batch id, '' when not recorded. Never throws. #>
    param([Parameter(Mandatory)]$Target, [Parameter(Mandatory)][string]$Connector, [string]$SolutionVersion = '', [string]$Mode = 'live', [scriptblock]$Log)
    $bid = Get-SIVulnSqlBatchId -RunId ([string]$Target.RunId) -Connector $Connector
    try {
        $a = & $Target.Invoke (Get-SIVulnSqlBatchStartSql) @{ BatchId = $bid; RunId = [string]$Target.RunId; Connector = $Connector; ContractVersion = '1'; Mode = $Mode; SolutionVersion = $SolutionVersion } 'reader'
        $n = 0; foreach ($r in @($a)) { if ($r -is [System.Collections.IDictionary] -and $r.Contains('Stale')) { $n = [int]$r['Stale'] } elseif ($r -and $r.PSObject.Properties['Stale']) { $n = [int]$r.Stale } }
        if ($n -gt 0 -and $Log) { & $Log 'WARN' ('{0} earlier run(s) of {1} never ended (still writing) -- ended as failed' -f $n, $Connector) }
        # every write of the run from here on stamps the batch id (the batch row exists first: a reader never meets an id it cannot look up)
        if ($Target.PSObject.Properties['SiBatchId']) { $Target.SiBatchId = $bid } else { $Target | Add-Member -NotePropertyName SiBatchId -NotePropertyValue $bid -Force }
        return $bid
    } catch { if ($Log) { & $Log 'WARN' ('the run''s batch row (vuln.SyncRun) could not be written: {0}' -f $_.Exception.Message) }; return '' }
}

function Stop-SIVulnSqlBatch {
    <# The end of a SQL connector's batch: -Outcome (the connector run's) -> complete | held | failed. Never throws. #>
    param([Parameter(Mandatory)]$Target, [Parameter(Mandatory)][string]$BatchId, [string]$Outcome = 'success', [string]$Reason = '', [int]$Held = 0, [int]$OutOfScope = 0, [scriptblock]$Log)
    if (-not $BatchId) { return }
    $state = switch -Regex ($Outcome) { '^success$' { 'complete' } '^(halted|held|refused)$' { 'held' } default { 'failed' } }
    try { [void](& $Target.Invoke (Get-SIVulnSqlBatchEndSql) @{ BatchId = $BatchId; RunId = [string]$Target.RunId; State = $state; Reason = $Reason; Held = $Held; OutOfScope = $OutOfScope } 'nonquery') }
    catch { if ($Log) { & $Log 'WARN' ('the end of the run''s batch (vuln.SyncRun) could not be written: {0}' -f $_.Exception.Message) } }
}
