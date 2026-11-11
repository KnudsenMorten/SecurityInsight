#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- the data health check's store in the Pro database (sql\si-pro-settings.sql, CR2 / #656):
      cfg.DataHealthCycle     one row per daily cycle: when, anomalous, complete, the state after it
      cfg.DataHealthResult    one row per cycle per source (Kind 'source') and per Risk Analysis report (Kind 'report'):
                              sampled, found / matched, missing, field mismatches / extra, the margin, the verdict
      cfg.DataHealthMissing   the records of a cycle that did not match (for the install's own Data health page only --
                              never sent anywhere)
      cfg.DataHealthState     ONE row: Healthy | Unhealthy, since when, anomalous cycles in a row
      cfg.DataHealthOverride  a SuperAdmin let ONE data-out channel through while Unhealthy (written by the web app through
                              cfg.DataHealthOverrideSet only); the engine CLEARS every open override when Healthy again
    SQL text plus the writers behind an -Invoke seam (New-SIDataSqlInvoke's shape: & $invoke $sql $params $mode, mode
    'reader' | 'scalar' | default nonquery).
#>

function Get-SIDataHealthProbeSql {
    <# HasTables: every data health table is there. HasDrift (#747): cfg.DataHealthResult has the Drift column. #>
    "SELECT CASE WHEN OBJECT_ID('cfg.DataHealthCycle') IS NOT NULL AND OBJECT_ID('cfg.DataHealthResult') IS NOT NULL AND OBJECT_ID('cfg.DataHealthMissing') IS NOT NULL AND OBJECT_ID('cfg.DataHealthState') IS NOT NULL AND OBJECT_ID('cfg.DataHealthOverride') IS NOT NULL THEN 1 ELSE 0 END AS HasTables, CASE WHEN COL_LENGTH('cfg.DataHealthResult', 'Drift') IS NOT NULL THEN 1 ELSE 0 END AS HasDrift"
}

function Get-SIDataHealthStateSql {
    <# The state and the open overrides, in one read (two result sets are not used: two statements, the reader reads the first). #>
    "IF OBJECT_ID('cfg.DataHealthState') IS NOT NULL SELECT TOP (1) [State], Since, ConsecutiveAnomalous, LastCycleId, LastCycleAt FROM cfg.DataHealthState WHERE Id = 1;"
}

function Get-SIDataHealthOverridesSql {
    "IF OBJECT_ID('cfg.DataHealthOverride') IS NOT NULL SELECT OverrideId, Channel, SetBy AS [By], SetByRole AS [Role], Reason, SinceUtc, ClearedAt FROM cfg.DataHealthOverride WHERE ClearedAt IS NULL;"
}

function Get-SIDataHealthCycleStartSql {
    "INSERT cfg.DataHealthCycle (StartedAt) OUTPUT inserted.CycleId VALUES (SYSUTCDATETIME());"
}

function Get-SIDataHealthCycleEndSql {
    <# The cycle's end AND the state, in one batch (one transaction): the state never moves without its cycle. #>
    @'
SET NOCOUNT ON; SET XACT_ABORT ON;
BEGIN TRAN;
UPDATE cfg.DataHealthCycle SET FinishedAt = SYSUTCDATETIME(), Anomalous = @Anomalous, Complete = @Complete, [State] = @State,
       StateChanged = @Changed, ConsecutiveAnomalous = @Consecutive, SummaryJson = @SummaryJson WHERE CycleId = @CycleId;
IF EXISTS (SELECT 1 FROM cfg.DataHealthState WITH (UPDLOCK, HOLDLOCK) WHERE Id = 1)
    UPDATE cfg.DataHealthState SET [State] = @State, Since = @Since, ConsecutiveAnomalous = @Consecutive, LastCycleId = @CycleId, LastCycleAt = SYSUTCDATETIME() WHERE Id = 1;
ELSE
    INSERT cfg.DataHealthState (Id, [State], Since, ConsecutiveAnomalous, LastCycleId, LastCycleAt) VALUES (1, @State, @Since, @Consecutive, @CycleId, SYSUTCDATETIME());
IF @State = N'Healthy'
    UPDATE cfg.DataHealthOverride SET ClearedAt = SYSUTCDATETIME(), ClearedReason = N'the data is Healthy again' WHERE ClearedAt IS NULL;
COMMIT;
'@
}

function Get-SIDataHealthResultWriteSql {
    <# Every result of a cycle (@Json: an array) and the records that did not match (@MissingJson), in one batch.
       -WithDrift (#747): the Drift column too (only where the probe found it -- an older schema keeps working without it). #>
    param([switch]$WithDrift)
    $dc = ''; $dv = ''
    if ($WithDrift) { $dc = ', Drift'; $dv = ', ISNULL(j.Drift, 0)' }
    @'
SET NOCOUNT ON; SET XACT_ABORT ON;
BEGIN TRAN;
INSERT cfg.DataHealthResult (CycleId, Kind, Name, Label, Sampled, Found, Missing, FieldMismatches{DC}, MarginPercent, MarginMinimum, Allowed, Verdict, Reason)
SELECT @CycleId, LEFT(j.Kind, 16), LEFT(j.Name, 256), LEFT(j.Label, 256), j.Sampled, j.Found, j.Missing, j.FieldMismatches{DV}, j.MarginPercent, j.MarginMinimum, j.Allowed, LEFT(j.Verdict, 16), LEFT(j.Reason, 1000)
FROM OPENJSON(@Json) WITH (Kind NVARCHAR(16) '$.Kind', Name NVARCHAR(256) '$.Name', Label NVARCHAR(256) '$.Label', Sampled BIGINT '$.Sampled', Found BIGINT '$.Found',
     Missing BIGINT '$.Missing', FieldMismatches BIGINT '$.FieldMismatches', Drift BIGINT '$.Drift', MarginPercent FLOAT '$.MarginPercent', MarginMinimum INT '$.MarginMinimum',
     Allowed BIGINT '$.Allowed', Verdict NVARCHAR(16) '$.Verdict', Reason NVARCHAR(1000) '$.Reason') AS j
WHERE j.Name IS NOT NULL;
INSERT cfg.DataHealthMissing (CycleId, Kind, Name, RecordKey, RecordName, Problem)
SELECT @CycleId, LEFT(m.Kind, 16), LEFT(m.Name, 256), LEFT(m.RecordKey, 450), LEFT(m.RecordName, 400), LEFT(m.Problem, 400)
FROM OPENJSON(@MissingJson) WITH (Kind NVARCHAR(16) '$.Kind', Name NVARCHAR(256) '$.Name', RecordKey NVARCHAR(450) '$.RecordKey', RecordName NVARCHAR(400) '$.RecordName', Problem NVARCHAR(400) '$.Problem') AS m
WHERE m.Name IS NOT NULL;
COMMIT;
'@.Replace('{DC}', $dc).Replace('{DV}', $dv)
}

function Get-SIDataHealthNewestFeedSql {
    <#
        The newest collection of one feed (provider + record type) and how many records it holds: the record writer's feed
        close (sidata.RecordCollection, state 'good'), else the newest record of the feed. @Provider / @RecordType.
    #>
    @'
SET NOCOUNT ON;
DECLARE @t DATETIME2(3) = NULL, @n BIGINT = NULL;
IF OBJECT_ID('sidata.RecordCollection') IS NOT NULL
    SELECT TOP (1) @t = CollectionTime, @n = Records FROM sidata.RecordCollection WHERE Provider = @Provider AND RecordType = @RecordType AND State = N'good' ORDER BY CollectionTime DESC;
IF @t IS NULL AND OBJECT_ID('sidata.CiRecord') IS NOT NULL
    SELECT @t = MAX(CollectionTime) FROM sidata.CiRecord WHERE Provider = @Provider AND RecordType = @RecordType;
IF @n IS NULL AND OBJECT_ID('sidata.CiRecord') IS NOT NULL
    SELECT @n = COUNT_BIG(*) FROM sidata.CiRecord WHERE Provider = @Provider AND RecordType = @RecordType AND CollectionTime >= DATEADD(HOUR, -6, @t);
SELECT @t AS CollectionTime, ISNULL(@n, 0) AS Records;
'@
}

function Get-SIDataHealthStoredRecordsSql {
    <# The sampled records as the newest collection holds them: @RecordKeys (a JSON array of record keys; never a parameter named "Keys": a dictionary's .Keys would read it). The record's document
       comes whole; the key fields are read from it here (a JSON path from a column is not on every SQL Server version). #>
    @'
SET NOCOUNT ON;
SELECT r.RecordKey, r.CollectionTime, r.RecordType, r.DocJson
FROM sidata.CiRecord AS r
JOIN (SELECT DISTINCT LEFT([value], 450) AS RecordKey FROM OPENJSON(@RecordKeys)) AS k ON k.RecordKey = r.RecordKey;
'@
}

function Get-SIDataHealthRaAssetsSql {
    <#
        Check (b)'s population: the in-scope assets of the newest complete Detailed collection that HOLD vulnerability
        findings, with their Defender for Endpoint device id (the CI's mde record, else the asset id Risk Analysis wrote),
        and the collection's time (CollectionTime -- what a change in Defender is judged against, #747).
        The CI's mde record is picked in a FIXED order (Get-SIDataHealthMdeRecordApply): a CI can hold more than one Defender
        device record (a device onboarded again), and an unordered TOP (1) could pick one record here and another in the
        stored-findings read -- the device's findings then do not join and the device looks "not in any report" (#1185).
    #>
    @'
SET NOCOUNT ON;
DECLARE @c INT = (SELECT TOP (1) CollectionId FROM sidata.Collection WHERE Kind = N'Detailed' AND Status = N'Complete' ORDER BY CollectionTime DESC);
DECLARE @ct DATETIME2(3) = (SELECT CollectionTime FROM sidata.Collection WHERE CollectionId = @c);
SELECT @c AS CollectionId, @ct AS CollectionTime, x.MdeId, MAX(x.AssetName) AS Name
FROM (
    SELECT LOWER(COALESCE(mr.MdeId, CASE WHEN f.RaAssetId LIKE N'[0-9a-f]%' AND LEN(f.RaAssetId) = 40 THEN f.RaAssetId END)) AS MdeId, f.AssetName
    FROM sidata.Finding AS f
    {MDEAPPLY}
    WHERE f.CollectionId = @c AND f.Cve LIKE N'CVE-%' AND f.CarriedFrom IS NULL
) AS x
WHERE x.MdeId IS NOT NULL
GROUP BY x.MdeId;
'@.Replace('{MDEAPPLY}', (Get-SIDataHealthMdeRecordApply))
}

function Get-SIDataHealthMdeRecordApply {
    <# The CI's Defender device record, ONE and always the same one: the most recently seen, then the newest collected, then
       by key. Both reads of check (b) use this text, so a device is the same device in both (#1185). #>
    "OUTER APPLY (SELECT TOP (1) SUBSTRING(r.RecordKey, 5, 450) AS MdeId FROM sidata.CiRecord AS r WHERE r.CiId = f.AssetKey AND r.Provider = N'mde' AND r.RecordType = N'device' ORDER BY r.SourceLastSeen DESC, r.CollectionTime DESC, r.RecordKey) AS mr"
}

function Get-SIDataHealthRaFindingsSql {
    <# The stored vulnerability findings of the sampled assets (@MdeIds: a JSON array) per report, in the collection the
       sampled assets were taken from (@CollectionId, from Get-SIDataHealthRaAssetsSql; NULL = the newest complete Detailed
       collection). Re-resolving "the newest" here could land on another collection than the population's -- the Defender
       reads in between take minutes (#1185). Every row carries Total: how many rows the statement returns (one statement,
       one snapshot), so the reader can prove it read them all. #>
    @'
SET NOCOUNT ON;
DECLARE @c INT = TRY_CONVERT(INT, @CollectionId);
IF @c IS NULL SET @c = (SELECT TOP (1) CollectionId FROM sidata.Collection WHERE Kind = N'Detailed' AND Status = N'Complete' ORDER BY CollectionTime DESC);
DECLARE @ids TABLE (MdeId NVARCHAR(64) NOT NULL PRIMARY KEY);
INSERT @ids SELECT DISTINCT LOWER(LEFT([value], 64)) FROM OPENJSON(@MdeIds) WHERE [value] IS NOT NULL;
SELECT d.MdeId, d.Report, d.Cve, COUNT_BIG(*) OVER () AS Total
FROM (
    SELECT DISTINCT i.MdeId, f.ReportName AS Report, UPPER(f.Cve) AS Cve
    FROM sidata.Finding AS f
    {MDEAPPLY}
    JOIN @ids AS i ON i.MdeId = LOWER(COALESCE(mr.MdeId, f.RaAssetId))
    WHERE f.CollectionId = @c AND f.Cve LIKE N'CVE-%' AND f.CarriedFrom IS NULL
) AS d;
'@.Replace('{MDEAPPLY}', (Get-SIDataHealthMdeRecordApply))
}

function Test-SIDataHealthStoredFindingsComplete {
    <#
        PURE (#1185). Did the stored-findings read come back WHOLE? -Rows: what the reader returned; -MdeIds: the sampled
        devices asked about. Every sampled device holds findings in that collection (that is how it was picked), so:
          * a row's Total (how many rows the statement returned) above the rows read = the reader ended early;
          * a sampled device with no row at all = its findings were not read.
        A read that is not whole proves nothing about the data. Returns @{ Complete; Read; Total ($null when the rows carry
        none); DevicesMissing; Why }.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [AllowEmptyCollection()][string[]]$MdeIds = @())
    $rs = @($Rows | Where-Object { $null -ne $_ })
    $total = $null
    foreach ($r in $rs) {
        $t = Get-SIDataHealthItem $r 'Total'
        if ($null -ne $t -and "$t" -match '^\d+$') { $total = [long]"$t"; break }
    }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $rs) { $m = [string](Get-SIDataHealthItem $r 'MdeId'); if ($m) { [void]$seen.Add($m.Trim()) } }
    $want = @($MdeIds | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Select-Object -Unique)
    $absent = @($want | Where-Object { -not $seen.Contains($_) }).Count
    $why = New-Object System.Collections.Generic.List[string]
    if ($null -ne $total -and $rs.Count -lt $total) { $why.Add(('{0:N0} of {1:N0} stored finding row(s) were read' -f $rs.Count, $total)) }
    if ($absent -gt 0) { $why.Add(('{0} of {1} sampled device(s) came back without their stored findings' -f $absent, $want.Count)) }
    [pscustomobject]@{ Complete = [bool]($why.Count -eq 0); Read = [long]$rs.Count; Total = $total; DevicesMissing = [long]$absent; Why = ($why.ToArray() -join '; ') }
}

function Read-SIDataHealthStoredFindings {
    <#
        Check (b)'s stored findings, read WHOLE or not at all (#1185). One read (Get-SIDataHealthRaFindingsSql) verified by
        Test-SIDataHealthStoredFindingsComplete; a read that fails or comes back short is read again after a pause (-Waits,
        seconds; one more read per pause). Still not whole: Complete = $false and the reason -- the caller says the check
        could not read, never that data is missing. Returns @{ Complete; Rows; Attempts; Why }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [AllowEmptyCollection()][string[]]$MdeIds = @(), [AllowNull()]$CollectionId,
          [int[]]$Waits = @(15, 60), [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          [scriptblock]$Log = { param($level, $msg) })
    $cid = $null; if ($null -ne $CollectionId -and "$CollectionId" -match '^\d+$') { $cid = [int]"$CollectionId" }
    $params = @{ MdeIds = (ConvertTo-SIDataHealthJsonArray -Items $MdeIds); CollectionId = $cid }
    $attempts = 1 + @($Waits).Count
    $why = ''
    for ($a = 1; $a -le $attempts; $a++) {
        try {
            $rows = @(Read-SIDataHealthRows -Invoke $Invoke -Sql (Get-SIDataHealthRaFindingsSql) -Params $params)
            $chk = Test-SIDataHealthStoredFindingsComplete -Rows $rows -MdeIds $MdeIds
            if ($chk.Complete) { return [pscustomobject]@{ Complete = $true; Rows = $rows; Attempts = $a; Why = '' } }
            $why = 'the read came back short: ' + $chk.Why
        } catch {
            $why = 'the read failed: ' + (([string]$_.Exception.Message) -split "`n")[0].Trim()
        }
        if ($a -lt $attempts) {
            $w = [int]@($Waits)[$a - 1]
            & $Log 'INFO' ('the stored vulnerability findings were not read whole ({0}) -- reading them again in {1} s ({2}/{3})' -f $why, $w, $a, ($attempts - 1))
            if ($w -gt 0) { & $Sleep $w }
        }
    }
    [pscustomobject]@{ Complete = $false; Rows = @(); Attempts = $attempts; Why = $why }
}

function ConvertTo-SIDataHealthJsonArray {
    <# PURE. Items as a JSON array, always an array (PS 5.1 makes one item an object). #>
    param([AllowEmptyCollection()][object[]]$Items = @(), [int]$Depth = 4)
    $a = @($Items | Where-Object { $null -ne $_ })
    if ($a.Count -eq 0) { return '[]' }
    $j = ConvertTo-Json -InputObject $a -Depth $Depth -Compress
    if (-not $j.StartsWith('[')) { $j = '[' + $j + ']' }
    $j
}

function Read-SIDataHealthRows {
    <# The rows of a 'reader' call, one by one. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params = @{})
    $x = & $Invoke $Sql $Params 'reader'
    foreach ($r in @($x)) { if ($null -ne $r) { $r } }
}

function Read-SIDataHealthStored {
    <#
        The sampled records of one source as the newest collection holds them: record key -> @{ CollectionTime; RecordType; Values }.
        Read in batches of 500 keys (one statement each).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [AllowEmptyCollection()][string[]]$Keys = @(), [AllowEmptyCollection()][string[]]$Fields = @())
    $out = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $k = @($Keys | Where-Object { $_ })
    for ($i = 0; $i -lt $k.Count; $i += 500) {
        $part = @($k[$i..([Math]::Min($k.Count, $i + 500) - 1)])
        foreach ($r in @(Read-SIDataHealthRows -Invoke $Invoke -Sql (Get-SIDataHealthStoredRecordsSql) -Params @{ RecordKeys = (ConvertTo-SIDataHealthJsonArray -Items $part) })) {
            $key = [string](Get-SIDataHealthItem $r 'RecordKey'); if (-not $key) { continue }
            $vals = @{}
            $doc = $null
            $dj = [string](Get-SIDataHealthItem $r 'DocJson')
            if ($dj.Trim()) { try { $doc = ConvertFrom-Json -InputObject $dj -ErrorAction Stop } catch { try { $doc = ConvertFrom-Json -InputObject $dj -AsHashtable -ErrorAction Stop } catch { $doc = $null } } }
            foreach ($fn in @($Fields | Where-Object { $_ })) { $vals[[string]$fn] = $(if ($doc) { Get-SIDataHealthItem $doc ([string]$fn) } else { $null }) }
            $out[$key] = [pscustomobject]@{ CollectionTime = (Get-SIDataHealthItem $r 'CollectionTime'); RecordType = [string](Get-SIDataHealthItem $r 'RecordType'); Values = $vals }
        }
    }
    $out
}
