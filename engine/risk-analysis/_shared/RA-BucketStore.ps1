#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  #640 BUCKET SIZING IN THE DATABASE (owner 2026-10-13: "we must this one right, as it is the core of si";
#  "also config about sizing should of course be in sql only").
#
#  The Pro database statements of the bucket sizing (sql\si-pro-settings.sql: cfg.RaBucketState, cfg.RaBucketHistory,
#  cfg.RaBucketReset, cfg.RaBucketImport) and the PURE sizing rules: the usual count, the jump warning, sizing down and
#  sizing from a measured result. Every database call goes through ONE seam, -Invoke (sql, params, mode 'reader' |
#  'nonquery' | 'scalar') -- the Pro settings store's -- so tests pass a fake.
#
#  Loaded by Invoke-RiskAnalysis.ps1 (after RA-AutoBucketing.ps1) and by the container entry point (the one-time import of
#  the counts an install learned before). No $PSScriptRoot use, no side effect at load.
#######################################################################################################

# THE SERVICE LIMITS the sizing works against (Defender advanced hunting, as the engine already treats them): an answer of
# at most 30,000 rows (the per-query row ceiling SecurityInsight sizes every split against) and 64 MB; a request (the query
# text with its inlined lookups) of at most 1 MB. Sizing from a measurement uses HALF of each, for safety.
$script:SIRaBucketRowLimit      = 30000
$script:SIRaBucketAnswerBytes   = 64MB
$script:SIRaBucketRequestBytes  = 1MB
# The owner's approved thresholds (wizard 2026-10-13): a jump is 4 x the usual count (with at least 3 earlier runs) or more
# than 256; a run whose every bucket used under 25 % of every limit tries half the count next run.
$script:SIRaBucketJumpFactor    = 4
$script:SIRaBucketJumpAbove     = 256
$script:SIRaBucketJumpMinRuns   = 3
$script:SIRaBucketDownFraction  = 0.25
$script:SIRaBucketHistoryKeep   = 30
# #833: the client ceiling of one advanced-hunting request -- a slice's TIME is measured against half of it like its rows
# and bytes (the same value as RA-AutoBucketing.ps1's $script:RASliceCeilingSeconds; this file loads standalone too).
$script:SIRaBucketSliceSeconds  = 900
# #833: the bucket state of the report certification's own test template (ops\report-certification, default
# 'Test688_Detailed') -- 'Test' + digits + '_' -- is removed by a run of ANOTHER template once no run of the test template
# has left a history row for a week (the certification is weekly). Only state rows, only that name shape, never the run's
# own template.
$script:SIRaBucketTestTemplateLike = 'Test[0-9]%[_]%'
$script:SIRaBucketTestTemplateIdleDays = 7
# #833: whether cfg.RaBucketHistory carries the slice time (MaxBucketSeconds, RanCount) -- an install one schema version
# behind does not; then the history is read and written without them, exactly as before. Set by Test-SIRaBucketTables.
$script:SIRaBucketHistoryHasTime = $false

function Get-SIRaBucketSql {
    <# PURE. The fixed statements; every value is a parameter. -WithTime (#833): History / HistoryAdd with the slice time
       columns (MaxBucketSeconds, RanCount) -- only when the database has them (Test-SIRaBucketTables). #>
    param([Parameter(Mandatory)][ValidateSet('Exists', 'State', 'Upsert', 'Delete', 'DeleteTemplate', 'Resets', 'ConsumeResets',
                                             'History', 'HistoryAdd', 'Imported', 'ImportMark', 'PruneTestTemplates')][string]$Name,
          [switch]$WithTime)
    if ($WithTime -and $Name -eq 'History') {
        return @'
SELECT h.ReportName, h.Id, h.RunUtc, h.Fingerprint, h.StartCount, h.BucketCount, h.Decided, h.ResultRows, h.MaxBucketRows, h.MaxBucketBytes, h.MaxRequestBytes,
       h.RequestRows, h.RequestBytesPerRow, h.RequestOverheadBytes, h.MaxBucketSeconds, h.RanCount
FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY ReportName ORDER BY Id DESC) AS n FROM cfg.RaBucketHistory WHERE Template = @Template) AS h
WHERE h.n <= @Keep ORDER BY h.ReportName, h.Id DESC;
'@
    }
    if ($WithTime -and $Name -eq 'HistoryAdd') {
        return @'
INSERT cfg.RaBucketHistory (Template, ReportName, Fingerprint, RunId, StartCount, BucketCount, Decided, ResultRows, MaxBucketRows, MaxBucketBytes,
                            MaxRequestBytes, RequestRows, RequestBytesPerRow, RequestOverheadBytes, UsualCount, Jump, MaxBucketSeconds, RanCount)
VALUES (@Template, @ReportName, @Fingerprint, @RunId, @StartCount, @BucketCount, @Decided, @ResultRows, @MaxBucketRows, @MaxBucketBytes,
        @MaxRequestBytes, @RequestRows, @RequestBytesPerRow, @RequestOverheadBytes, @UsualCount, @Jump, @MaxBucketSeconds, @RanCount);
DELETE FROM cfg.RaBucketHistory WHERE Template = @Template AND ReportName = @ReportName
   AND Id NOT IN (SELECT TOP (@Keep) Id FROM cfg.RaBucketHistory WHERE Template = @Template AND ReportName = @ReportName ORDER BY Id DESC);
'@
    }
    switch ($Name) {
        'Exists' { "SELECT CASE WHEN OBJECT_ID(N'cfg.RaBucketState') IS NOT NULL AND OBJECT_ID(N'cfg.RaBucketHistory') IS NOT NULL AND OBJECT_ID(N'cfg.RaBucketReset') IS NOT NULL AND OBJECT_ID(N'cfg.RaBucketImport') IS NOT NULL THEN 1 ELSE 0 END AS HasTables, CASE WHEN COL_LENGTH(N'cfg.RaBucketHistory', N'MaxBucketSeconds') IS NOT NULL AND COL_LENGTH(N'cfg.RaBucketHistory', N'RanCount') IS NOT NULL THEN 1 ELSE 0 END AS HasTime;" }
        'PruneTestTemplates' { @'
DELETE s FROM cfg.RaBucketState AS s
WHERE s.Template LIKE @Like AND s.Template <> @Template
  AND NOT EXISTS (SELECT 1 FROM cfg.RaBucketHistory AS h WHERE h.Template = s.Template AND h.RunUtc >= DATEADD(day, -@IdleDays, SYSUTCDATETIME()));
SELECT @@ROWCOUNT AS N;
'@ }
        'State' { "SELECT ReportName, Fingerprint, BucketCount, ConfirmedUtc FROM cfg.RaBucketState WHERE Template = @Template;" }
        'Upsert' { @'
MERGE cfg.RaBucketState WITH (HOLDLOCK) AS t
USING (SELECT @Template AS Template, @ReportName AS ReportName, @Fingerprint AS Fingerprint) AS s
   ON t.Template = s.Template AND t.ReportName = s.ReportName AND t.Fingerprint = s.Fingerprint
WHEN MATCHED THEN UPDATE SET BucketCount = @BucketCount, ConfirmedUtc = @ConfirmedUtc, UpdatedUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Template, ReportName, Fingerprint, BucketCount, ConfirmedUtc) VALUES (@Template, @ReportName, @Fingerprint, @BucketCount, @ConfirmedUtc);
'@ }
        'Delete' { "DELETE FROM cfg.RaBucketState WHERE Template = @Template AND ReportName = @ReportName AND Fingerprint = @Fingerprint;" }
        'DeleteTemplate' { "DELETE FROM cfg.RaBucketState WHERE Template = @Template;" }
        'Resets' { "SELECT ResetId, ReportName FROM cfg.RaBucketReset WHERE Template = @Template AND AppliedUtc IS NULL ORDER BY ResetId;" }
        'ConsumeResets' { @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @r TABLE (ResetId BIGINT, ReportName NVARCHAR(256));
INSERT @r (ResetId, ReportName) SELECT ResetId, ReportName FROM cfg.RaBucketReset WITH (UPDLOCK, HOLDLOCK) WHERE Template = @Template AND AppliedUtc IS NULL;
DELETE s FROM cfg.RaBucketState AS s WHERE s.Template = @Template AND (EXISTS (SELECT 1 FROM @r WHERE ReportName IS NULL) OR s.ReportName IN (SELECT ReportName FROM @r WHERE ReportName IS NOT NULL));
UPDATE x SET AppliedUtc = SYSUTCDATETIME(), AppliedRunId = @RunId FROM cfg.RaBucketReset AS x INNER JOIN @r AS r ON r.ResetId = x.ResetId;
COMMIT;
SELECT ResetId, COALESCE(ReportName, N'*') AS ReportName FROM @r ORDER BY ResetId;
'@ }
        'History' { @'
SELECT h.ReportName, h.Id, h.RunUtc, h.Fingerprint, h.StartCount, h.BucketCount, h.Decided, h.ResultRows, h.MaxBucketRows, h.MaxBucketBytes, h.MaxRequestBytes,
       h.RequestRows, h.RequestBytesPerRow, h.RequestOverheadBytes
FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY ReportName ORDER BY Id DESC) AS n FROM cfg.RaBucketHistory WHERE Template = @Template) AS h
WHERE h.n <= @Keep ORDER BY h.ReportName, h.Id DESC;
'@ }
        'HistoryAdd' { @'
INSERT cfg.RaBucketHistory (Template, ReportName, Fingerprint, RunId, StartCount, BucketCount, Decided, ResultRows, MaxBucketRows, MaxBucketBytes,
                            MaxRequestBytes, RequestRows, RequestBytesPerRow, RequestOverheadBytes, UsualCount, Jump)
VALUES (@Template, @ReportName, @Fingerprint, @RunId, @StartCount, @BucketCount, @Decided, @ResultRows, @MaxBucketRows, @MaxBucketBytes,
        @MaxRequestBytes, @RequestRows, @RequestBytesPerRow, @RequestOverheadBytes, @UsualCount, @Jump);
DELETE FROM cfg.RaBucketHistory WHERE Template = @Template AND ReportName = @ReportName
   AND Id NOT IN (SELECT TOP (@Keep) Id FROM cfg.RaBucketHistory WHERE Template = @Template AND ReportName = @ReportName ORDER BY Id DESC);
'@ }
        'Imported' { "SELECT COUNT(*) AS N FROM cfg.RaBucketImport WHERE Template = @Template;" }
        'ImportMark' { "IF NOT EXISTS (SELECT 1 FROM cfg.RaBucketImport WHERE Template = @Template) INSERT cfg.RaBucketImport (Template, Entries, Source) VALUES (@Template, @Entries, @Source);" }
    }
}

function Split-SIRaBucketKey {
    <# PURE. '<ReportName>|<fingerprint>' -> @{ Report; Fingerprint }, or $null for a key of another shape. #>
    param([string]$Key)
    if ([string]::IsNullOrWhiteSpace($Key) -or $Key.StartsWith('__')) { return $null }
    $i = $Key.IndexOf('|')
    if ($i -lt 1 -or $i -ge ($Key.Length - 1)) { return $null }
    [pscustomobject]@{ Report = $Key.Substring(0, $i); Fingerprint = $Key.Substring($i + 1) }
}

function Get-SIRaBucketRows {
    <# The reader's rows as one array (the store returns a result set as ONE array; unrolled here). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params = @{})
    @(& $Invoke $Sql $Params 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
}

function Get-SIRaBucketValue {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { return $Row[$Name] } else { return $null } }
    $p = $Row.PSObject.Properties[$Name]; if ($p) { $p.Value } else { $null }
}

function Test-SIRaBucketTables {
    <# Whether the database carries the bucket sizing tables (an install one schema version behind does not). #>
    # #833: also notes whether the history carries the slice time ($script:SIRaBucketHistoryHasTime)
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $r = @(Get-SIRaBucketRows -Invoke $Invoke -Sql (Get-SIRaBucketSql 'Exists'))
    $script:SIRaBucketHistoryHasTime = ($r.Count -gt 0 -and [int]('0' + [string](Get-SIRaBucketValue $r[0] 'HasTime')) -eq 1)
    return ($r.Count -gt 0 -and [int](Get-SIRaBucketValue $r[0] 'HasTables') -eq 1)
}

function Invoke-SIRaBucketTestTemplatePrune {
    <#
        #833 THE CERTIFICATION'S TEST TEMPLATE LEAVES NO STATE BEHIND. Removes the remembered counts (cfg.RaBucketState only)
        of a template named like the report certification's test template ('Test' + digits + '_', e.g. Test688_Detailed)
        that no run has used for a week (no history row of it in 7 days). GUARDED: never the run's own -Template (and nothing
        at all when the run itself is such a template), never another name shape, never a history row. Returns the number
        of rows removed (0 when there was nothing, or the statement failed -- it never stops a run).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Template)
    if ([string]::IsNullOrWhiteSpace($Template) -or $Template -match '^(?i)Test\d+_') { return 0 }
    try {
        $r = @(Get-SIRaBucketRows -Invoke $Invoke -Sql (Get-SIRaBucketSql 'PruneTestTemplates') -Params @{ Template = $Template; Like = $script:SIRaBucketTestTemplateLike; IdleDays = [int]$script:SIRaBucketTestTemplateIdleDays })
        if ($r.Count) { return [int]('0' + [string](Get-SIRaBucketValue $r[0] 'N')) }
    } catch { }
    return 0
}

function Read-SIRaBucketState {
    <#
        The template's remembered counts in the shape the bucketing works on: '<ReportName>|<fingerprint>' -> count, and the
        '__confirmed' map of the same keys -> confirmed time (ISO 8601, UTC).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Template)
    $cache = @{}
    $confirmed = @{}
    foreach ($r in @(Get-SIRaBucketRows -Invoke $Invoke -Sql (Get-SIRaBucketSql 'State') -Params @{ Template = $Template })) {
        $key = '{0}|{1}' -f [string](Get-SIRaBucketValue $r 'ReportName'), [string](Get-SIRaBucketValue $r 'Fingerprint')
        $cache[$key] = [int](Get-SIRaBucketValue $r 'BucketCount')
        $c = Get-SIRaBucketValue $r 'ConfirmedUtc'
        if ($null -ne $c -and $c -isnot [System.DBNull]) {
            $confirmed[$key] = ([datetime]::SpecifyKind([datetime]$c, [System.DateTimeKind]::Utc)).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        }
    }
    if ($confirmed.Count) { $cache['__confirmed'] = $confirmed }
    return $cache
}

function Get-SIRaBucketStateDiff {
    <#
        PURE. What changed between two states of the cache: Upserts (key, report, fingerprint, count, confirmed time or $null)
        and Deletes (key, report, fingerprint).
    #>
    param([hashtable]$Before = @{}, [hashtable]$After = @{})
    $fp = {
        param([hashtable]$c)
        $m = @{}
        $stamps = if ($c.ContainsKey('__confirmed') -and $c['__confirmed'] -is [hashtable]) { $c['__confirmed'] } else { @{} }
        foreach ($k in @($c.Keys)) {
            $ks = [string]$k
            if ($ks.StartsWith('__')) { continue }
            $vi = 0
            if (-not [int]::TryParse([string]$c[$k], [ref]$vi)) { continue }
            $m[$ks] = [pscustomobject]@{ N = $vi; Stamp = $(if ($stamps.ContainsKey($ks)) { [string]$stamps[$ks] } else { '' }) }
        }
        $m
    }
    $b = & $fp $Before; $a = & $fp $After
    $up = New-Object System.Collections.Generic.List[object]
    $del = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($a.Keys | Sort-Object)) {
        $parts = Split-SIRaBucketKey -Key $k
        if (-not $parts) { continue }
        if (-not $b.ContainsKey($k) -or $b[$k].N -ne $a[$k].N -or $b[$k].Stamp -ne $a[$k].Stamp) {
            $when = $null
            if ($a[$k].Stamp) {
                $d = [datetime]::MinValue
                if ([datetime]::TryParse($a[$k].Stamp, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$d)) { $when = $d.ToUniversalTime() }
            }
            $up.Add([pscustomobject]@{ Key = $k; Report = $parts.Report; Fingerprint = $parts.Fingerprint; Count = [int]$a[$k].N; Confirmed = $when })
        }
    }
    foreach ($k in @($b.Keys | Sort-Object)) {
        if ($a.ContainsKey($k)) { continue }
        $parts = Split-SIRaBucketKey -Key $k
        if ($parts) { $del.Add([pscustomobject]@{ Key = $k; Report = $parts.Report; Fingerprint = $parts.Fingerprint }) }
    }
    [pscustomobject]@{ Upserts = $up.ToArray(); Deletes = $del.ToArray() }
}

function Save-SIRaBucketStateDiff {
    <# Writes what changed between -Before and -After (Get-SIRaBucketStateDiff). Returns the number of statements sent. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Template, [hashtable]$Before = @{}, [hashtable]$After = @{})
    $d = Get-SIRaBucketStateDiff -Before $Before -After $After
    $n = 0
    $upSql = Get-SIRaBucketSql 'Upsert'; $delSql = Get-SIRaBucketSql 'Delete'
    foreach ($u in @($d.Upserts)) {
        $fpv = [string]$u.Fingerprint; if ($fpv.Length -gt 64) { $fpv = $fpv.Substring(0, 64) }
        $null = & $Invoke $upSql @{ Template = $Template; ReportName = [string]$u.Report; Fingerprint = $fpv; BucketCount = [int]$u.Count; ConfirmedUtc = $u.Confirmed } 'nonquery'
        $n++
    }
    foreach ($x in @($d.Deletes)) {
        $fpv = [string]$x.Fingerprint; if ($fpv.Length -gt 64) { $fpv = $fpv.Substring(0, 64) }
        $null = & $Invoke $delSql @{ Template = $Template; ReportName = [string]$x.Report; Fingerprint = $fpv } 'nonquery'
        $n++
    }
    return $n
}

function Invoke-SIRaBucketResetConsume {
    <#
        The one-time resets of this template, consumed ONCE: in one transaction the reports' remembered counts are removed
        and the reset rows are marked applied with this run's id. Returns the report names ('*' = every report).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Template, [string]$RunId)
    @(Get-SIRaBucketRows -Invoke $Invoke -Sql (Get-SIRaBucketSql 'ConsumeResets') -Params @{ Template = $Template; RunId = $RunId } |
        ForEach-Object { [string](Get-SIRaBucketValue $_ 'ReportName') } | Where-Object { $_ } | Select-Object -Unique)
}

function Test-SIRaBucketImported {
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Template)
    $r = @(Get-SIRaBucketRows -Invoke $Invoke -Sql (Get-SIRaBucketSql 'Imported') -Params @{ Template = $Template })
    return ($r.Count -gt 0 -and [int](Get-SIRaBucketValue $r[0] 'N') -gt 0)
}

function Import-SIRaBucketCountsOnce {
    <#
        THE ONE-TIME IMPORT (no install loses its learned counts): the counts an install kept before the database held them
        (-Cache, the old shape) are written for the template, ONLY where the database has no count for that report and
        query yet, and the import is recorded -- every later run skips it. Returns the number of counts imported, or -1
        when the template was imported before.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Template, [hashtable]$Cache = @{}, [string]$Source = 'earlier runs')
    if (Test-SIRaBucketImported -Invoke $Invoke -Template $Template) { return -1 }
    $current = Read-SIRaBucketState -Invoke $Invoke -Template $Template
    $merged = @{}
    foreach ($k in @($current.Keys)) { $merged[$k] = $current[$k] }
    $mergedStamps = @{}
    if ($current.ContainsKey('__confirmed')) { foreach ($k in @($current['__confirmed'].Keys)) { $mergedStamps[$k] = $current['__confirmed'][$k] } }
    $stamps = if ($Cache.ContainsKey('__confirmed') -and $Cache['__confirmed'] -is [hashtable]) { $Cache['__confirmed'] } else { @{} }
    $added = 0
    foreach ($k in @($Cache.Keys)) {
        $ks = [string]$k
        if (-not (Split-SIRaBucketKey -Key $ks)) { continue }
        if ($merged.ContainsKey($ks)) { continue }
        $vi = 0
        if (-not [int]::TryParse([string]$Cache[$k], [ref]$vi) -or $vi -lt 1) { continue }
        $merged[$ks] = $vi
        if ($stamps.ContainsKey($ks)) { $mergedStamps[$ks] = $stamps[$ks] }
        $added++
    }
    if ($mergedStamps.Count) { $merged['__confirmed'] = $mergedStamps }
    $null = Save-SIRaBucketStateDiff -Invoke $Invoke -Template $Template -Before $current -After $merged
    $null = & $Invoke (Get-SIRaBucketSql 'ImportMark') @{ Template = $Template; Entries = $added; Source = $Source } 'nonquery'
    return $added
}

function Read-SIRaBucketHistory {
    <# The newest history rows of every report of the template: report name -> rows, newest first. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Template, [int]$Keep = $script:SIRaBucketHistoryKeep)
    $h = @{}
    $nn = { param($v) if ($null -eq $v -or $v -is [System.DBNull]) { $null } else { $v } }
    foreach ($r in @(Get-SIRaBucketRows -Invoke $Invoke -Sql (Get-SIRaBucketSql 'History' -WithTime:$script:SIRaBucketHistoryHasTime) -Params @{ Template = $Template; Keep = $Keep })) {
        $n = [string](Get-SIRaBucketValue $r 'ReportName')
        if (-not $h.ContainsKey($n)) { $h[$n] = New-Object System.Collections.Generic.List[object] }
        $h[$n].Add([pscustomobject]@{
            BucketCount = [int](Get-SIRaBucketValue $r 'BucketCount'); StartCount = [int](Get-SIRaBucketValue $r 'StartCount')
            Decided = [string](Get-SIRaBucketValue $r 'Decided'); RunUtc = (Get-SIRaBucketValue $r 'RunUtc')
            ResultRows = (Get-SIRaBucketValue $r 'ResultRows'); MaxBucketRows = (Get-SIRaBucketValue $r 'MaxBucketRows')
            MaxBucketBytes = (Get-SIRaBucketValue $r 'MaxBucketBytes'); MaxRequestBytes = (Get-SIRaBucketValue $r 'MaxRequestBytes')
            RequestRows = (Get-SIRaBucketValue $r 'RequestRows'); RequestBytesPerRow = (Get-SIRaBucketValue $r 'RequestBytesPerRow')
            RequestOverheadBytes = (Get-SIRaBucketValue $r 'RequestOverheadBytes')
            # #833: the query the run asked (a failure proves a count only for its own query) and the slice time
            Fingerprint = [string](& $nn (Get-SIRaBucketValue $r 'Fingerprint'))
            MaxBucketSeconds = (& $nn (Get-SIRaBucketValue $r 'MaxBucketSeconds')); RanCount = (& $nn (Get-SIRaBucketValue $r 'RanCount'))
        })
    }
    $out = @{}
    foreach ($k in $h.Keys) { $out[$k] = $h[$k].ToArray() }
    return $out
}

function Add-SIRaBucketHistory {
    <# One history row for one report of this run (the run keeps the newest 30 per report). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Template, [Parameter(Mandatory)]$Row)
    $p = @{ Template = $Template; Keep = $script:SIRaBucketHistoryKeep }
    foreach ($n in 'ReportName', 'Fingerprint', 'RunId', 'StartCount', 'BucketCount', 'Decided', 'ResultRows', 'MaxBucketRows', 'MaxBucketBytes',
                   'MaxRequestBytes', 'RequestRows', 'RequestBytesPerRow', 'RequestOverheadBytes', 'UsualCount', 'Jump') {
        $p[$n] = Get-SIRaBucketValue $Row $n
    }
    if ($p.Fingerprint -and ([string]$p.Fingerprint).Length -gt 64) { $p.Fingerprint = ([string]$p.Fingerprint).Substring(0, 64) }
    $p.Jump = [bool]$p.Jump
    # #833: the slice time and the count the slices ran at -- only where the database has the columns
    if ($script:SIRaBucketHistoryHasTime) { foreach ($n in 'MaxBucketSeconds', 'RanCount') { $p[$n] = Get-SIRaBucketValue $Row $n } }
    $null = & $Invoke (Get-SIRaBucketSql 'HistoryAdd' -WithTime:$script:SIRaBucketHistoryHasTime) $p 'nonquery'
}

# ---------------------------------------------------------------------------------------------------------------------
# THE SIZING RULES -- PURE
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIRaBucketUsual {
    <# PURE. The report's usual count: the median of its earlier runs' counts; $null with fewer than -MinRuns runs. #>
    param([int[]]$Counts = @(), [int]$MinRuns = $script:SIRaBucketJumpMinRuns)
    $c = @($Counts | Where-Object { $_ -ge 1 } | Sort-Object)
    if ($c.Count -lt $MinRuns -or $c.Count -eq 0) { return $null }
    $n = $c.Count; $mid = [int][Math]::Floor($n / 2)
    if ($n % 2 -eq 1) { return [int]$c[$mid] }
    return [int][Math]::Floor(([int]$c[$mid - 1] + [int]$c[$mid]) / 2)
}

function Test-SIRaBucketJump {
    <#
        PURE. The jump warning (owner, wizard 2026-10-13: "4x usual or over 256"): a count of at least 4 x the report's usual
        count (known only with 3 earlier runs), or above 256 -- the query or its data is likely wrong. Returns the reason in
        plain words, or '' for no jump.
    #>
    param([int]$Count, $Usual)
    if ($Count -gt $script:SIRaBucketJumpAbove) { return ('{0} buckets is above {1}' -f $Count, $script:SIRaBucketJumpAbove) }
    if ($null -ne $Usual -and [int]$Usual -ge 1 -and $Count -ge ($script:SIRaBucketJumpFactor * [int]$Usual)) {
        return ('{0} buckets is {1} x or more its usual {2}' -f $Count, $script:SIRaBucketJumpFactor, [int]$Usual)
    }
    return ''
}

function Get-SIRaNextPowerOfTwo {
    param([double]$Value)
    if ($Value -le 1) { return 1 }
    $p = 1
    while ($p -lt $Value -and $p -lt 1073741824) { $p = $p * 2 }
    return [int]$p
}

function Get-SIRaBucketCountFromMeasure {
    <#
        PURE. STEP 4 -- the count worked out FROM A MEASURED RESULT (after a reset or a changed query), instead of 1, 2, 4, 8.
        From the report's last measured run:
          answer   rows x bytes per row must fit HALF the answer limits in each bucket:
                   need_rows  = ResultRows / (30,000 / 2)
                   need_bytes = ResultRows x (MaxBucketBytes / MaxBucketRows) / (64 MB / 2)
          request  the inlined lookup rows are split across the buckets; the rest of the query is not:
                   need_req   = RequestRows x RequestBytesPerRow x 1.15 / (1 MB / 2 - RequestOverheadBytes)   (at least 32 KB)
        count = the next power of two of the largest need, at least 1. $null when nothing usable was measured.
        #697 (2) THE REQUEST THE REPORT REALLY SENT bounds the request need: the largest request of the run (MaxRequestBytes)
        was sent at BucketCount buckets, and only the split part of it shrinks with more buckets, so at M buckets the largest
        request is at most MaxRequestBytes x BucketCount / M. The request need is therefore never more than
                   need_sent  = MaxRequestBytes x BucketCount / (1 MB / 2)
        and the smaller of need_req and need_sent is used (never more than before). Measured 2026-10-15: three attack-path
        reports returning 1-112 rows were sized to 16 from request numbers that were not their own (the largest lookup, the
        widest row and the longest query text of the whole run up to then), while every request they sent was a few KB.
        #833 THE SLICE TIME is a need like the rows and the bytes: the longest slice of the run (MaxBucketSeconds) at the count
        its slices ran at (RanCount) did at most MaxBucketSeconds x RanCount of work, so at M slices the longest takes at most
        MaxBucketSeconds x RanCount / M -- against HALF the 900 s ceiling:
                   need_time  = MaxBucketSeconds x RanCount / (900 / 2)
        A run that measured its slices and found NO rows (a report that returns nothing) is a measurement too: it needs 1,
        unless its time says more. RanCount (the count the slices ran at) is also the count the largest request was sent at;
        a row without it (written before #833) uses BucketCount as before.
    #>
    param($Measure)
    if ($null -eq $Measure) { return $null }
    $rows = [double]('0' + [string](Get-SIRaBucketValue $Measure 'ResultRows'))
    $maxRows = [double]('0' + [string](Get-SIRaBucketValue $Measure 'MaxBucketRows'))
    $maxBytes = [double]('0' + [string](Get-SIRaBucketValue $Measure 'MaxBucketBytes'))
    $reqRows = [double]('0' + [string](Get-SIRaBucketValue $Measure 'RequestRows'))
    $reqBpr = [double]('0' + [string](Get-SIRaBucketValue $Measure 'RequestBytesPerRow'))
    $reqOver = [double]('0' + [string](Get-SIRaBucketValue $Measure 'RequestOverheadBytes'))
    $sent = [double]('0' + [string](Get-SIRaBucketValue $Measure 'MaxRequestBytes'))
    $ranAt = [double]('0' + [string](Get-SIRaBucketValue $Measure 'RanCount'))
    $sentAt = if ($ranAt -ge 1) { $ranAt } else { [double]('0' + [string](Get-SIRaBucketValue $Measure 'BucketCount')) }
    $secs = [double]('0' + [string](Get-SIRaBucketValue $Measure 'MaxBucketSeconds'))
    $hasSent = ($sent -gt 0 -and $sentAt -ge 1)
    $hasTime = ($secs -gt 0 -and $sentAt -ge 1)
    if ($rows -le 0 -and $reqRows -le 0 -and -not $hasSent -and -not $hasTime) { return $null }
    $need = 0.0
    if ($hasTime) { $need = [Math]::Max($need, ($secs * $sentAt) / ($script:SIRaBucketSliceSeconds / 2.0)) }
    if ($rows -gt 0) {
        $need = [Math]::Max($need, $rows / ($script:SIRaBucketRowLimit / 2.0))
        if ($maxRows -gt 0 -and $maxBytes -gt 0) {
            $bpr = $maxBytes / $maxRows
            $need = [Math]::Max($need, ($rows * $bpr) / ($script:SIRaBucketAnswerBytes / 2.0))
        }
    }
    $needReq = $null
    if ($reqRows -gt 0 -and $reqBpr -gt 0) {
        $budget = [Math]::Max(32KB, ($script:SIRaBucketRequestBytes / 2.0) - $reqOver)
        $needReq = ($reqRows * $reqBpr * 1.15) / $budget
    }
    if ($hasSent) {
        $needSent = ($sent * $sentAt) / ($script:SIRaBucketRequestBytes / 2.0)
        if ($null -eq $needReq -or $needSent -lt $needReq) { $needReq = $needSent }
    }
    if ($null -ne $needReq) { $need = [Math]::Max($need, [double]$needReq) }
    return (Get-SIRaNextPowerOfTwo -Value ([Math]::Ceiling($need)))
}

function Get-SIRaBucketProvenCount {
    <#
        PURE. #697 (2) THE COUNT A FAILED QUERY PROVED NECESSARY -- the largest of the report's earlier runs (-History) that
        either had to RAISE its count during the run (a bucket was refused for its size or ran out of time: 'raised'), or
        was sized by a probe that climbed ABOVE the configured count (-Floor) because a smaller count failed ('probe').
        0 when no failure ever proved a count. The measured sizing never goes below this: a compute ceiling (a 900 s
        timeout) is invisible in the rows and the request size, so only the failure itself can say the count is needed.
        #833 -Fingerprint: only the runs of THAT query prove a count for it (a row without a fingerprint still counts). Live
        2026-10-20: a count of 16 in the history of the report's EARLIER queries (its remembered count was 2) started the
        changed query at 16 buckets for at most 80 rows a bucket (372 s instead of 36 s), and it keeps a count from coming
        down for as long as such a row is among the newest 30.
    #>
    param([object[]]$History = @(), [int]$Floor = 1, [string]$Fingerprint = '')
    $p = 0
    foreach ($x in @($History | Where-Object { $_ })) {
        if ($Fingerprint) {
            $xf = if ($x.PSObject.Properties['Fingerprint']) { [string]$x.Fingerprint } else { '' }
            if ($xf -and $xf -ne $Fingerprint) { continue }
        }
        $d = [string]$x.Decided; $c = [int]$x.BucketCount
        if ($d -eq 'raised' -or ($d -eq 'probe' -and $c -gt $Floor)) { if ($c -gt $p) { $p = $c } }
    }
    return $p
}

function Get-SIRaBucketShrinkCount {
    <#
        PURE. #697 (2) STEP 5 -- A COUNT NO FAILURE PROVED COMES BACK DOWN TO WHAT THE REPORT MEASURED, run over run (owner
        2026-10-15: "16 buckets for 1-112 rows is waste"). For a remembered count (-Count) this run tries
              max( -Floor, the measured need of the report's last run, the count a failure proved, half of -Count )
        when that is lower than -Count, and the last run (-History, newest first) ran at -Count with a measurement:
          * the measured need is Get-SIRaBucketCountFromMeasure of that run (half of every limit, the request it really sent);
          * the count a failure proved (Get-SIRaBucketProvenCount) is never gone below -- a raise or a climbing probe stays;
          * at most HALF per run: a measurement that does not hold shows on the smaller count as a refused or timed-out
            bucket, which raises it again in that run and is then proved (so the count cannot swing up and down).
        Returns @{ Count; Down; Why }.
        #833: -Floor is the lowest count the report may run at (1 unless its template sets a count, see
        Get-AutoBucketLearnFloor) -- a report far inside every limit (rows, bytes, request AND time) comes down to 1;
        -ProbeFloor is the count a first probe starts at (the configured count: a probe that climbed above it proved its
        count); -Fingerprint keeps the proof to the report's CURRENT query (Get-SIRaBucketProvenCount).
    #>
    param([int]$Count, [int]$Floor = 1, [object[]]$History = @(), [int]$ProbeFloor = 0, [string]$Fingerprint = '')
    $keep = [pscustomobject]@{ Count = $Count; Down = $false; Why = '' }
    if ($ProbeFloor -lt 1) { $ProbeFloor = $Floor }
    if ($Count -le 1 -or $Count -le $Floor) { return $keep }
    $h = @($History | Where-Object { $_ })
    if ($h.Count -lt 1) { return $keep }
    $last = $h[0]
    if ([int]$last.BucketCount -ne $Count) { return $keep }
    if ([string]$last.Decided -eq 'incomplete') { return $keep }   # #880: a NOT COMPLETE run's measurement is partial
    $need = Get-SIRaBucketCountFromMeasure -Measure $last
    if ($null -eq $need) { return $keep }
    $proven = Get-SIRaBucketProvenCount -History $h -Floor $ProbeFloor -Fingerprint $Fingerprint
    if ($proven -ge $Count) { return $keep }
    $half = [int][Math]::Ceiling($Count / 2.0)
    $target = [int](@([Math]::Max(1, $Floor), [int]$need, $proven, $half) | Measure-Object -Maximum).Maximum
    if ($target -ge $Count) { return $keep }
    $rows = [long]('0' + [string]$last.ResultRows); $req = [long]('0' + [string]$last.MaxRequestBytes)
    $secs = [long]('0' + [string]$(if ($last.PSObject.Properties['MaxBucketSeconds']) { $last.MaxBucketSeconds } else { '' }))
    $took = if ($secs -gt 0) { (', its longest slice took {0:N0} s' -f $secs) } else { '' }
    [pscustomobject]@{ Count = $target; Down = $true
        Why = ('its last run at {0} buckets returned {1:N0} row(s), its largest request was {2:N0} KB{4}, which {3} bucket(s) can carry; no failed query needed more' -f $Count, $rows, [long][Math]::Ceiling($req / 1024.0), [int]$need, $took) }
}

function Get-SIRaBucketCompleteLowerCount {
    <#
        #880 PURE. THE REPORT HAS RUN COMPLETE AT FEWER SLICES -- the lowest count below -Count at which an earlier run of the
        SAME query (-Fingerprint; a row without one counts) went through whole, on its own answers: it neither raised its count
        nor was NOT COMPLETE ('raised' / 'incomplete' rows are not), it started, ended and ran at that count, and its longest
        slice was measured under half the 900 s ceiling. 0 when there is none. -History: newest first.
        Why: a remembered count raised by a busy backend (live 2026-10-22, internal: 2 -> 18 -> 28 from refused requests,
        while the same query had run complete at 2 the night before) could never come down by "every slice far below every
        limit" alone -- every slice pays the same fixed cost (the full table reads), so the slices of 28 are not much faster
        than the slices of 2. A complete run at the lower count is the measured proof that the report fits it. The count
        comes down one halving per run (Get-RACountAfterSmallRun), never below this count; a slice that no longer fits at the
        smaller count is split in that run and raises it again.
    #>
    param([int]$Count, [object[]]$History = @(), [string]$Fingerprint = '')
    $best = 0
    foreach ($x in @($History | Where-Object { $_ })) {
        if ($Fingerprint) {
            $xf = if ($x.PSObject.Properties['Fingerprint']) { [string]$x.Fingerprint } else { '' }
            if ($xf -and $xf -ne $Fingerprint) { continue }
        }
        if ([string]$x.Decided -in @('raised', 'incomplete')) { continue }
        $c = [int]$x.BucketCount
        if ($c -lt 1 -or $c -ge $Count -or [int]$x.StartCount -ne $c) { continue }
        $ran = if ($x.PSObject.Properties['RanCount']) { [int]('0' + [string]$x.RanCount) } else { 0 }
        if ($ran -ne $c) { continue }
        $secs = if ($x.PSObject.Properties['MaxBucketSeconds']) { [double]('0' + [string]$x.MaxBucketSeconds) } else { 0.0 }
        if ($secs -le 0 -or $secs -ge ($script:SIRaBucketSliceSeconds / 2.0)) { continue }
        if ($best -eq 0 -or $c -lt $best) { $best = $c }
    }
    return [int]$best
}

function Test-SIRaBucketRunFarBelow {
    <# PURE. Whether one run's every bucket stayed under 25 % of every limit (rows and bytes of the largest answer; the inlined
       part of the largest request against the room the request has). A run without a measurement is not "far below". #>
    param($Run)
    if ($null -eq $Run) { return $false }
    $maxRows = [double]('0' + [string]$Run.MaxBucketRows); $maxBytes = [double]('0' + [string]$Run.MaxBucketBytes)
    if ($maxRows -le 0 -and $maxBytes -le 0) { return $false }
    if ($maxRows -ge ($script:SIRaBucketDownFraction * $script:SIRaBucketRowLimit)) { return $false }
    if ($maxBytes -ge ($script:SIRaBucketDownFraction * $script:SIRaBucketAnswerBytes)) { return $false }
    $req = [double]('0' + [string]$Run.MaxRequestBytes); $over = [double]('0' + [string]$Run.RequestOverheadBytes)
    if ($req -gt 0) {
        $room = [Math]::Max(1.0, $script:SIRaBucketRequestBytes - $over)
        if (($req - $over) -ge ($script:SIRaBucketDownFraction * $room)) { return $false }
    }
    return $true
}

function Get-SIRaBucketDownCount {
    <#
        PURE. STEP 3 -- sizing DOWN, carefully (owner 2026-10-13: "better to small than too big so they breaks"; "when in doubt
        go up"). This run tries HALF the count only when ALL of:
          * the last 3 runs (-History, newest first) each ran at THIS count, none raised or sized it, and
          * every bucket of each of those 3 runs stayed under 25 % of every limit (Test-SIRaBucketRunFarBelow), and
          * half is still ABOVE the count that last overflowed (the newest 'raised' run's start count), and not below -Floor.
        An overflow on the smaller count splits that bucket and the next run starts from the higher count again.
        Returns @{ Count; Down; Why }.
    #>
    param([int]$Count, [int]$Floor = 1, [object[]]$History = @())
    $keep = [pscustomobject]@{ Count = $Count; Down = $false; Why = '' }
    if ($Count -le 1 -or $Count -le $Floor) { return $keep }
    $h = @($History | Where-Object { $_ })
    if ($h.Count -lt 3) { return $keep }
    foreach ($x in @($h | Select-Object -First 3)) {
        if ([int]$x.BucketCount -ne $Count -or [int]$x.StartCount -ne $Count) { return $keep }
        if ([string]$x.Decided -in @('raised', 'down', 'measured', 'probe', 'incomplete')) { return $keep }   # #880: a NOT COMPLETE run measured part of it
        if (-not (Test-SIRaBucketRunFarBelow -Run $x)) { return $keep }
    }
    $half = [int][Math]::Max([Math]::Max(1, $Floor), [Math]::Floor($Count / 2))
    $overflowed = @($h | Where-Object { [string]$_.Decided -eq 'raised' } | Select-Object -First 1)
    if ($overflowed.Count -and $half -le [int]$overflowed[0].StartCount) { return $keep }
    if ($half -ge $Count) { return $keep }
    [pscustomobject]@{ Count = $half; Down = $true
        Why = ('the last 3 runs each used under {0:P0} of every limit in every bucket (largest bucket {1} rows)' -f $script:SIRaBucketDownFraction, [long]('0' + [string]$h[0].MaxBucketRows)) }
}
function Get-SIRaBucketJumpGuardCalls {
    <#
        PURE. STEP 2 -- the run's jumps -> ONE guard event 'ra.bucket.count-jump' (a warning: the run completes; on the Guards
        page and in the report to Invardia, never a mail), naming every report.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Jumps, [string]$Template)
    $j = @($Jumps | Where-Object { $_ })
    if (-not $j.Count) { return @() }
    $list = @($j | ForEach-Object { '{0}: {1}' -f $_.Report, $_.Why })
    @(@{ GuardId = 'ra.bucket.count-jump'; Outcome = 'warning'; Subject = $Template
         Detail = ('{0} report(s) needed far more buckets than usual: {1}' -f $j.Count, ((@($list) | Select-Object -First 20) -join '; '))
         Values = @(@{ Name = 'reports'; Label = 'Reports affected'; Measured = $j.Count },
                    @{ Name = 'largest'; Label = 'Largest bucket count'; Measured = (@($j | ForEach-Object { [int]$_.Count }) | Measure-Object -Maximum).Maximum }) })
}