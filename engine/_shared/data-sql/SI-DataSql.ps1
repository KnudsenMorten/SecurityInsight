#Requires -Version 5.1
<#
    SecurityInsight Pro -- the data sync's SQL side (REQUIREMENTS §9.3.3 phase B): the connection, the set-based
    writes, the daily aggregates and the retention purge, against sql/si-data-schema.sql (schema `sidata`).

    ONE SEAM. Every statement goes through -Invoke: a scriptblock (sql, params-hashtable, mode 'reader'|'nonquery'|
    'scalar') -- the vulnerability target's seam (engine/asset-cmdb/_shared/SI-VulnTarget.ps1), so the tests replace
    the database with a fake that records calls. The default opens a connection per call with an Entra token: the
    container job's MANAGED IDENTITY when $global:SI_UseManagedIdentity, else the engine SPN's CERTIFICATE. No SQL
    login, no secret. ONE token per ~45 minutes.

    SET-BASED. Rows travel as ONE JSON parameter per chunk and land in one statement (OPENJSON), each chunk in its own
    transaction. A collection is visible only once its LAST chunk landed and it is marked 'Complete'.

    RETENTION is here, not in the schema file (that one is additive only). It purges sidata collections older than the
    retention, in batches sized from their measured time; vuln.*, si.* and cfg.* are never touched.

    PS 5.1 safe.
#>

# The certificate lookup and the SPN token are the identity ledger's (same SPN, same host). Loaded, not copied.
if (-not (Get-Command -Name 'Get-SILedgerAccessToken' -ErrorAction SilentlyContinue)) {
    $__ledger = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model\identity\SI-ObjectLedgerStore.ps1'
    if (Test-Path -LiteralPath $__ledger) { . $__ledger }
}

function New-SIDataSqlInvoke {
    <# The default -Invoke: a connection per call, Entra token (managed identity in a container, else certificate). #>
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$Database,
        [string]$AppId,
        [string]$TenantId,
        [string]$CertThumbprint,
        # 0 = no limit (owner 2026-10-22: "i accept no limits"): deletes and aggregates touch many rows; long work is batched and says its progress
        [int]$CommandTimeoutSec = 0
    )
    $srv = $Server; $db = $Database; $app = $AppId; $ten = $TenantId; $timeout = $CommandTimeoutSec
    # A GetNewClosure() block cannot see functions the caller dot-sourced, so the token function travels INTO the
    # closure as a value (as in SI-VulnTarget.ps1).
    if ($global:SI_UseManagedIdentity) {
        if (-not (Get-Command -Name 'Get-SIManagedIdentityToken' -ErrorAction SilentlyContinue)) {
            throw 'New-SIDataSqlInvoke: managed identity is on but the identity token helper is not loaded -- this sign-in works only inside a SecurityInsight container.'
        }
        $miFn = ${function:Get-SIManagedIdentityToken}
        $getToken = { & $miFn -Resource 'https://database.windows.net/' }.GetNewClosure()
    } else {
        if (-not (Get-Command -Name 'Get-SILedgerAccessToken' -ErrorAction SilentlyContinue)) {
            throw 'New-SIDataSqlInvoke: the SQL token helper (data-model\identity\SI-ObjectLedgerStore.ps1) is not installed.'
        }
        if (-not $AppId -or -not $TenantId -or -not $CertThumbprint) {
            throw 'New-SIDataSqlInvoke: the engine identity (SI_SPN_AppId / SI_SPN_TenantId / SI_SPN_CertThumbprint) is not set.'
        }
        $cert = Get-SILedgerCertificate -Thumbprint $CertThumbprint
        if (-not $cert) { throw ("New-SIDataSqlInvoke: certificate {0} with a private key was not found in LocalMachine or CurrentUser." -f $CertThumbprint) }
        $tokenFn = ${function:Get-SILedgerAccessToken}
        $getToken = { & $tokenFn -Certificate $cert -AppId $app -TenantId $ten }.GetNewClosure()
    }
    $tokenCache = @{ Token = $null; Until = [datetime]::MinValue }
    # the shared open-with-retry, as a value (the closure below cannot see dot-sourced functions)
    if (-not (Get-Command -Name 'Open-SISqlConnectionRetry' -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'SI-SqlRetry.ps1') }
    $openSql = ${function:Open-SISqlConnectionRetry}
    # #738: what a reader on ANOTHER thread needs to make the same connection (Risk Analysis reads its next page while it
    # posts the current one): the connection string and a current token -- values, never this script block
    $connInfo = {
        if (-not $tokenCache.Token -or [datetime]::UtcNow -ge $tokenCache.Until) {
            $tokenCache.Token = & $getToken
            $tokenCache.Until = [datetime]::UtcNow.AddMinutes(45)
        }
        @{ ConnectionString = ('Server=tcp:{0},1433;Database={1};Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;' -f $srv, $db); AccessToken = $tokenCache.Token; CommandTimeout = $timeout }
    }.GetNewClosure()
    $invoke = {
        # mode 'stream' (#639): each row is handed to -OnRow ({ param($Row) }, a hashtable) as it is read, never collected;
        # the answer is the number of rows. 'reader' / 'rows' collect every row -- for a read that is bounded by its query.
        param([string]$sql, $p, [string]$mode, [scriptblock]$OnRow)
        # THE OPEN is retried (the shared Open-SISqlConnectionRetry, SI-SqlRetry.ps1): a failover, a serverless resume, a busy
        # database or a client timeout -- with a fresh token each time. ONLY the open: a statement that may already have run
        # is never sent again (the sweep of 2026-10-22: one 40613 here failed the whole step).
        $tok = {
            param([bool]$Fresh)
            if ($Fresh -or -not $tokenCache.Token -or [datetime]::UtcNow -ge $tokenCache.Until) {
                $tokenCache.Token = & $getToken
                $tokenCache.Until = [datetime]::UtcNow.AddMinutes(45)
            }
            $tokenCache.Token
        }
        $cn = & $openSql -Server $srv -Database $db -Token $tok
        try {
            # mode 'session' (no fixed limits, owner 2026-10-22): ONE connection for several plain batches, so #temp tables
            # live from one step to the next and each step is its own command -- the caller says its progress between them.
            # -OnRow { param($Run) } gets $Run = { param($Sql, $Mode) } ('scalar' | 'reader' | anything else = no answer);
            # a batch is sent WITHOUT parameters (a parameterised command runs in sp_executesql, which drops its #temp tables)
            if ($mode -eq 'session') {
                if (-not $OnRow) { throw "SQL mode 'session' needs a step callback (OnRow)." }
                $sessionCn = $cn; $sessionTimeout = $timeout
                $run = {
                    param([string]$StepSql, [string]$StepMode)
                    $sc = $sessionCn.CreateCommand(); $sc.CommandText = $StepSql; $sc.CommandTimeout = $sessionTimeout
                    switch ($StepMode) {
                        'scalar' { $v = $sc.ExecuteScalar(); if ($v -is [System.DBNull]) { $null } else { $v } }
                        'reader' {
                            $rd = $sc.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                            try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) } } finally { $rd.Close() }
                            , $out.ToArray()
                        }
                        default { [void]$sc.ExecuteNonQuery() }
                    }
                }.GetNewClosure()
                return (& $OnRow $run)
            }
            $cmd = $cn.CreateCommand(); $cmd.CommandText = $sql; $cmd.CommandTimeout = $timeout
            if ($p) { foreach ($k in $p.Keys) { [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [System.DBNull]::Value } else { $p[$k] })) } }
            switch ($mode) {
                # 'rows' is the same read as 'reader': the callers of the v3 model (which CIs the collection scope leaves out, the
                # finding lifecycle's counts, the finding model's counts) ask for 'rows' -- unanswered, their statements ran
                # but nothing came back, so an out-of-scope CI's findings closed as fixed instead of freezing
                { $_ -in 'reader', 'rows' } {
                    $rd = $cmd.ExecuteReader()
                    $out = New-Object System.Collections.Generic.List[object]
                    while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $out.Add($h) }
                    $rd.Close(); , $out.ToArray()
                }
                'stream' {
                    if (-not $OnRow) { throw "SQL read mode 'stream' needs a row callback (OnRow)." }
                    $rd = $cmd.ExecuteReader()
                    $n = 0L
                    try {
                        $names = [string[]]::new($rd.FieldCount)
                        for ($i = 0; $i -lt $rd.FieldCount; $i++) { $names[$i] = $rd.GetName($i) }
                        while ($rd.Read()) {
                            $h = @{}; for ($i = 0; $i -lt $names.Length; $i++) { $h[$names[$i]] = $rd.GetValue($i) }
                            $null = & $OnRow $h
                            $n++
                        }
                    } finally { $rd.Close() }
                    $n
                }
                'scalar' { $cmd.ExecuteScalar() }
                default  { [void]$cmd.ExecuteNonQuery() }
            }
        } finally { $cn.Dispose() }
    }.GetNewClosure()
    $invoke | Add-Member -NotePropertyName SIConnectionInfo -NotePropertyValue $connInfo
    # the database this seam writes to: the write pacing (SI-SqlPacing.ps1) reads ITS load -- only a seam marked so is read
    $invoke | Add-Member -NotePropertyName SISqlTarget -NotePropertyValue ([pscustomobject]@{ Server = $srv; Database = $db })
    # this seam reads row by row (mode 'stream', Invoke-SIDataSqlStream)
    $invoke | Add-Member -NotePropertyName SISqlStream -NotePropertyValue $true
    # this seam runs several batches on one connection (mode 'session': the key figures in steps, with progress)
    $invoke | Add-Member -NotePropertyName SISqlSession -NotePropertyValue $true
    $invoke
}

function Invoke-SIDataSqlStream {
    <#
        #639: a SQL read of ANY size, a row (or a page) at a time -- never every row collected. -OnRow { param($Row) } gets
        each row (a hashtable: column -> value) as it is read; -OnPage { param($Rows) } gets them in pages of -PageRows
        (both may be given). Returns the number of rows read.
        A seam that reads row by row (New-SIDataSqlInvoke, marked SISqlStream) is asked in mode 'stream'; any other seam (a
        test's fake) is asked in mode 'reader' and its rows are handed on the same way -- the same callbacks either way.
        The 'reader' mode stays for reads bounded by their query (a count, a TOP, one key).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, $Params, [scriptblock]$OnRow,
          [scriptblock]$OnPage, [int]$PageRows = 5000)
    if (-not $OnRow -and -not $OnPage) { throw 'Invoke-SIDataSqlStream: give -OnRow or -OnPage.' }
    if ($PageRows -lt 1) { $PageRows = 1 }
    $state = @{ Page = (New-Object System.Collections.Generic.List[object]) }
    $__on = $OnRow; $__pg = $OnPage; $__n = $PageRows
    $each = {
        param($Row)
        if ($__on) { $null = & $__on $Row }
        if ($__pg) {
            $state.Page.Add($Row)
            if ($state.Page.Count -ge $__n) { $pg = $state.Page.ToArray(); $state.Page.Clear(); $null = & $__pg $pg }
        }
    }.GetNewClosure()
    $n = 0L
    $streams = [bool]($Invoke.PSObject.Properties['SISqlStream'] -and $Invoke.SISqlStream)
    if ($streams) {
        $n = [long](& $Invoke $Sql $Params 'stream' $each)
    } else {
        # (a seam answers its rows as ONE array: , $rows -- assigned, then walked)
        $got = & $Invoke $Sql $Params 'reader'
        foreach ($r in @($got)) { if ($null -eq $r) { continue }; & $each $r; $n++ }
        $got = $null
    }
    if ($__pg -and $state.Page.Count -gt 0) { $pg = $state.Page.ToArray(); $state.Page.Clear(); $null = & $__pg $pg }
    $n
}

# ------------------------------------------------------------------------------------------------------------------
#  THE STATEMENTS -- pure text, so their shape is testable
# ------------------------------------------------------------------------------------------------------------------

function Get-SIDataSchemaCheckSql {
    "SELECT CASE WHEN OBJECT_ID('sidata.Collection') IS NOT NULL AND OBJECT_ID('sidata.Finding') IS NOT NULL AND OBJECT_ID('sidata.FindingDaily') IS NOT NULL AND OBJECT_ID('sidata.VulnLifecycleDaily') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataLoadedSql {
    # #638: with who wrote it (Source 'risk-analysis' = Risk Analysis wrote it itself -- never loaded from Log Analytics again)
    # #717: and whether the retention removed its rows (Retired = 1) -- such a collection is never loaded again either
    @"
IF COL_LENGTH('sidata.Collection', 'Source') IS NULL
    SELECT CollectionId, CollectionTime, Status, CAST(NULL AS nvarchar(16)) AS Source FROM sidata.Collection WHERE Kind = @Kind AND CollectionTime >= CONVERT(datetime2(3), @Since, 126);
ELSE IF COL_LENGTH('sidata.Collection', 'RetiredAt') IS NULL
    EXEC sp_executesql N'SELECT CollectionId, CollectionTime, Status, Source FROM sidata.Collection WHERE Kind = @Kind AND CollectionTime >= CONVERT(datetime2(3), @Since, 126)', N'@Kind nvarchar(16), @Since nvarchar(40)', @Kind = @Kind, @Since = @Since;
ELSE EXEC sp_executesql N'SELECT CollectionId, CollectionTime, Status, Source, CASE WHEN RetiredAt IS NULL THEN 0 ELSE 1 END AS Retired FROM sidata.Collection WHERE Kind = @Kind AND CollectionTime >= CONVERT(datetime2(3), @Since, 126)', N'@Kind nvarchar(16), @Since nvarchar(40)', @Kind = @Kind, @Since = @Since;
"@
}

function Get-SIDataRunUpsertSql {
    @'
IF NOT EXISTS (SELECT 1 FROM sidata.Run WHERE RunId = @RunId)
INSERT sidata.Run (RunId, Engine, CollectionTime, Verdict, StartedAt, EndedAt, SolutionVersion)
VALUES (@RunId, @Engine, CONVERT(datetime2(3), @CollectionTime, 126), @Verdict,
        CONVERT(datetime2(3), NULLIF(@StartedAt, ''), 126), CONVERT(datetime2(3), NULLIF(@EndedAt, ''), 126), NULLIF(@SolutionVersion, ''));
'@
}

function Get-SIDataNewCollectionSql {
    @'
INSERT sidata.Collection (CollectionTime, Kind, RunId, Status, SolutionVersion)
OUTPUT inserted.CollectionId
VALUES (CONVERT(datetime2(3), @CollectionTime, 126), @Kind, NULLIF(@RunId, ''), 'Loading', NULLIF(@SolutionVersion, ''));
'@
}

function Get-SIDataCompleteCollectionSql {
    # Only a 'Loading' collection whose finding count equals what Log Analytics held is marked complete.
    @'
UPDATE sidata.Collection SET Status = 'Complete', [Rows] = @Rows, LoadedAt = SYSUTCDATETIME()
WHERE CollectionId = @CollectionId AND Status = 'Loading'
  AND (SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = @CollectionId) = @Rows;
SELECT @@ROWCOUNT;
'@
}

function Get-SIDataInsertFindingSql {
    @'
SET XACT_ABORT ON;
BEGIN TRAN;
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, DetailJson,
                       ExemptionId, ExemptedUntil, ExemptionRequestId)
SELECT @CollectionId, NULLIF(j.AssetKey, ''), NULLIF(j.AssetName, ''), NULLIF(j.ReportName, ''), NULLIF(j.SecurityDomain, ''),
       NULLIF(j.ConfigurationId, ''), NULLIF(j.Cve, ''), NULLIF(j.Title, ''), NULLIF(j.Severity, ''), j.Tier, j.RiskScore, j.DetailJson,
       j.ExemptionId, CONVERT(datetime2(0), NULLIF(j.ExemptedUntil, ''), 126), j.ExemptionRequestId
FROM OPENJSON(@j) WITH (AssetKey nvarchar(400), AssetName nvarchar(400), ReportName nvarchar(256), SecurityDomain nvarchar(128),
                        ConfigurationId nvarchar(256), Cve nvarchar(100), Title nvarchar(1000), Severity nvarchar(30), Tier tinyint,
                        RiskScore float, DetailJson nvarchar(max), ExemptionId bigint, ExemptedUntil nvarchar(40), ExemptionRequestId bigint) j;
DECLARE @n int = @@ROWCOUNT;
COMMIT;
SELECT @n;
'@
}

function Get-SIDataFindingTierFromAssetSql {
    <#
        A finding loaded WITHOUT a tier, on an asset that HAS one, takes its asset's tier (one collection). The row came
        from a report whose own link to the profile missed (measured 2026-10-05: an attack-path report returned the same
        asset twice, with Tier 3 on one row and none on the other) -- the finding was then "Unclassified" while its asset
        was Tier 3 on the Tier board. A finding's tier is its asset's tier, so the two can no longer disagree.
        Runs after the assets are written and before the collection is completed (the daily aggregates read it after).
    #>
    @'
SET XACT_ABORT ON;
UPDATE f SET f.Tier = a.Tier
FROM sidata.Finding AS f JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
WHERE f.CollectionId = @CollectionId AND f.Tier IS NULL AND a.Tier IS NOT NULL;
SELECT @@ROWCOUNT;
'@
}

function Get-SIDataInsertRecommendationSql {
    @'
SET XACT_ABORT ON;
BEGIN TRAN;
INSERT sidata.Recommendation (CollectionId, AssetKey, RecommendationId, Name, Severity, Tier, DetailJson)
SELECT @CollectionId, NULLIF(j.AssetKey, ''), NULLIF(j.RecommendationId, ''), NULLIF(j.Name, ''), NULLIF(j.Severity, ''), j.Tier, j.DetailJson
FROM OPENJSON(@j) WITH (AssetKey nvarchar(400), RecommendationId nvarchar(400), Name nvarchar(1000), Severity nvarchar(30), Tier tinyint,
                        DetailJson nvarchar(max)) j;
DECLARE @n int = @@ROWCOUNT;
COMMIT;
SELECT @n;
'@
}

function Get-SIDataUpsertAssetSql {
    # Current state: a newer sighting moves LastSeen forward, never back; a value missing this time keeps the old one.
    @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @a TABLE (AssetKey nvarchar(400) PRIMARY KEY, AssetName nvarchar(400), AssetKind nvarchar(16), AssetKinds nvarchar(64), Tier tinyint,
                  KeySource nvarchar(16), LastSeen datetime2(3), PropertiesJson nvarchar(max));
INSERT @a SELECT j.AssetKey, NULLIF(j.AssetName, ''), NULLIF(j.AssetKind, ''), NULLIF(j.AssetKinds, ''), j.Tier, j.KeySource, CONVERT(datetime2(3), j.LastSeen, 126), j.PropertiesJson
FROM OPENJSON(@j) WITH (AssetKey nvarchar(400), AssetName nvarchar(400), AssetKind nvarchar(16), AssetKinds nvarchar(64), Tier tinyint, KeySource nvarchar(16),
                        LastSeen nvarchar(40), PropertiesJson nvarchar(max)) j;
UPDATE t SET AssetName = COALESCE(s.AssetName, t.AssetName), AssetKind = COALESCE(s.AssetKind, t.AssetKind),
             AssetKinds = COALESCE(s.AssetKinds, t.AssetKinds), Tier = COALESCE(s.Tier, t.Tier),
             KeySource = s.KeySource, LastSeen = CASE WHEN s.LastSeen > t.LastSeen THEN s.LastSeen ELSE t.LastSeen END,
             PropertiesJson = COALESCE(s.PropertiesJson, t.PropertiesJson), UpdatedAt = SYSUTCDATETIME()
FROM sidata.Asset t JOIN @a s ON s.AssetKey = t.AssetKey;
INSERT sidata.Asset (AssetKey, AssetName, AssetKind, AssetKinds, Tier, KeySource, FirstSeen, LastSeen, PropertiesJson)
SELECT s.AssetKey, s.AssetName, s.AssetKind, s.AssetKinds, s.Tier, s.KeySource, s.LastSeen, s.LastSeen, s.PropertiesJson
FROM @a s WHERE NOT EXISTS (SELECT 1 FROM sidata.Asset t WHERE t.AssetKey = s.AssetKey);
COMMIT;
SELECT COUNT(*) FROM @a;
'@
}

function Get-SIDataUpsertIdentifierSql {
    @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @i TABLE (AssetKey nvarchar(400), IdentifierType nvarchar(64), IdentifierValue nvarchar(256), SeenAt datetime2(3));
INSERT @i SELECT j.AssetKey, j.IdentifierType, j.IdentifierValue, CONVERT(datetime2(3), j.SeenAt, 126)
FROM OPENJSON(@j) WITH (AssetKey nvarchar(400), IdentifierType nvarchar(64), IdentifierValue nvarchar(256), SeenAt nvarchar(40)) j;
UPDATE t SET LastSeen = CASE WHEN s.SeenAt > t.LastSeen THEN s.SeenAt ELSE t.LastSeen END
FROM sidata.AssetIdentifier t JOIN @i s ON s.AssetKey = t.AssetKey AND s.IdentifierType = t.IdentifierType AND s.IdentifierValue = t.IdentifierValue;
INSERT sidata.AssetIdentifier (AssetKey, IdentifierType, IdentifierValue, FirstSeen, LastSeen)
SELECT s.AssetKey, s.IdentifierType, s.IdentifierValue, s.SeenAt, s.SeenAt
FROM @i s WHERE NOT EXISTS (SELECT 1 FROM sidata.AssetIdentifier t
                            WHERE t.AssetKey = s.AssetKey AND t.IdentifierType = s.IdentifierType AND t.IdentifierValue = s.IdentifierValue);
COMMIT;
SELECT COUNT(*) FROM @i;
'@
}

function Get-SIDataScoreMaxColumnSql {
    <#
        #245 -- adds FindingDaily.ScoreMax (the highest finding score per group) to a database set up before it existed.
        The SAME guarded, additive statement as sql/si-data-schema.sql, run before the aggregate is written, so a
        customer database does not need setup run again for the column to appear. Never alters or drops anything.
    #>
    "IF COL_LENGTH('sidata.FindingDaily', 'ScoreMax') IS NULL ALTER TABLE sidata.FindingDaily ADD ScoreMax FLOAT NULL; SELECT 1;"
}

function Get-SIDataExemptionColumnsSql {
    <#
        #264 -- the exemption MARK on sidata.Finding (ExemptionId, ExemptedUntil, ExemptionRequestId) and
        Collection.ExemptedDerivedAt, added to a database set up before they existed: the SAME guarded, additive statements
        as sql/si-data-schema.sql, run before a collection is loaded, so every finding lands with its mark even before setup
        is run again. Also sidata.Asset.AssetKinds (#431, every kind a CI is made of), which the asset upsert writes.
        Never alters or drops anything. (The counted twin TABLES come with setup; see
        Get-SIDataExemptedSchemaCheckSql.)
    #>
    @'
IF COL_LENGTH('sidata.Finding', 'ExemptionId') IS NULL ALTER TABLE sidata.Finding ADD ExemptionId BIGINT NULL;
IF COL_LENGTH('sidata.Finding', 'ExemptedUntil') IS NULL ALTER TABLE sidata.Finding ADD ExemptedUntil DATETIME2(0) NULL;
IF COL_LENGTH('sidata.Finding', 'ExemptionRequestId') IS NULL ALTER TABLE sidata.Finding ADD ExemptionRequestId BIGINT NULL;
IF COL_LENGTH('sidata.Collection', 'ExemptedDerivedAt') IS NULL ALTER TABLE sidata.Collection ADD ExemptedDerivedAt DATETIME2(0) NULL;
IF COL_LENGTH('sidata.Asset', 'AssetKinds') IS NULL ALTER TABLE sidata.Asset ADD AssetKinds NVARCHAR(64) NULL;
SELECT 1;
'@
}

function Get-SIDataPartialTableSql {
    <#
        A collection an Admin RELEASED although its run was not shown complete (Operations > Guards (safety checks), "Release: load this
        collection anyway") is loaded ONCE and MARKED PARTIAL here (sidata.CollectionPartial: the reason, who released it,
        when) -- the web app shows a "partial" badge wherever the collection is used (working rule 4: a partial result is
        never shown as whole). The SAME guarded, additive statement as sql/si-data-schema.sql, run before such a load, so a
        database does not need setup run again for it. Never alters or drops anything.
    #>
    @'
IF OBJECT_ID('sidata.CollectionPartial') IS NULL
CREATE TABLE sidata.CollectionPartial (
    CollectionId     INT            NOT NULL CONSTRAINT PK_CollectionPartial PRIMARY KEY,
    Reason           NVARCHAR(2000) NULL,
    ReleasedBy       NVARCHAR(256)  NULL,
    ReleasedUtc      DATETIME2(0)   NULL,
    MarkedUtc        DATETIME2(0)   NOT NULL CONSTRAINT DF_CollectionPartial_MarkedUtc DEFAULT SYSUTCDATETIME()
);
SELECT 1;
'@
}

function Get-SIDataMarkPartialSql {
    <# One released collection, just loaded, marked partial (once); marks of collections that are gone are cleared. #>
    @'
DELETE FROM sidata.CollectionPartial WHERE NOT EXISTS (SELECT 1 FROM sidata.Collection AS c WHERE c.CollectionId = sidata.CollectionPartial.CollectionId);
IF NOT EXISTS (SELECT 1 FROM sidata.CollectionPartial WHERE CollectionId = @CollectionId)
INSERT sidata.CollectionPartial (CollectionId, Reason, ReleasedBy, ReleasedUtc)
VALUES (@CollectionId, LEFT(@Reason, 2000), NULLIF(@By, ''), TRY_CONVERT(datetime2(0), NULLIF(@ReleasedUtc, ''), 126));
SELECT 1;
'@
}

function Get-SIDataFindingDailySql {
    <#
        The day's aggregate = the LATEST complete Detailed collection of that day, replacing whatever the day held.
        Per group: findings, assets, the score total (kept ONLY so an average can be formed: ScoreTotal / Findings) and
        the HIGHEST finding score (ScoreMax, #245). The web app shows the average and the highest, never the total.
        -Counted (#264): the same day into sidata.FindingDailyCounted over the findings WITHOUT an exemption mark -- the
        counted twin a dashboard reads when exempted findings are not counted.
    #>
    param([switch]$Counted)
    $table = 'FindingDaily'; $mark = ''; $assets = 'AssetDaily'
    if ($Counted) { $table = 'FindingDailyCounted'; $mark = ' AND f.ExemptionId IS NULL'; $assets = 'AssetDailyCounted' }
    # #295: in the same transaction, the day's DISTINCT assets at every grain (sidata.AssetDaily, a CUBE of the four
    # columns) -- the per-group Assets above is distinct only within its own group and must never be added up. Only where
    # the table exists (the data sync adds it, Get-SIDataAssetDailyTablesSql): deferred name resolution, never executed
    # otherwise.
    (@'
SET XACT_ABORT ON;
DECLARE @d date = CONVERT(date, @Day, 126);
DECLARE @c int = (SELECT TOP (1) CollectionId FROM sidata.Collection
                  WHERE Kind = 'Detailed' AND Status = 'Complete' AND CollectionTime >= @d AND CollectionTime < DATEADD(day, 1, @d)
                  ORDER BY CollectionTime DESC);
-- #717: the day's collection had its finding rows removed by the retention -- its stored day totals are what is left of
-- it, so they are KEPT as they are (never recomputed from no rows)
IF @c IS NOT NULL AND COL_LENGTH('sidata.Collection', 'RetiredAt') IS NOT NULL
BEGIN
    DECLARE @gone int = 0;
    EXEC sp_executesql N'SELECT @g = COUNT(*) FROM sidata.Collection WHERE CollectionId = @c AND RetiredAt IS NOT NULL', N'@c int, @g int OUTPUT', @c = @c, @g = @gone OUTPUT;
    IF @gone > 0 BEGIN SELECT 0; RETURN; END
END
BEGIN TRAN;
DELETE FROM sidata.{TABLE} WHERE [Day] = @d;
-- #855: the CI lifecycle is a KEY of every row (an asset has exactly one lifecycle, so the distinct assets of two lifecycles
-- add up); a view reads the lifecycle a person chose (default: active)
INSERT sidata.{TABLE} ([Day], CollectionId, Tier, Severity, SecurityDomain, ReportName, Findings, Assets, ScoreTotal, ScoreMax, CiLifecycle)
SELECT @d, @c, f.Tier, ISNULL(f.Severity, ''), ISNULL(f.SecurityDomain, ''), ISNULL(f.ReportName, ''),
       COUNT(*), COUNT(DISTINCT f.AssetKey), ISNULL(SUM(f.RiskScore), 0), MAX(f.RiskScore), f.CiLifecycle
FROM sidata.Finding f
WHERE @c IS NOT NULL AND f.CollectionId = @c{MARK}
GROUP BY f.CiLifecycle, f.Tier, ISNULL(f.Severity, ''), ISNULL(f.SecurityDomain, ''), ISNULL(f.ReportName, '');
DECLARE @n int = @@ROWCOUNT;
IF OBJECT_ID('sidata.{ASSETS}') IS NOT NULL
BEGIN
    DELETE FROM sidata.{ASSETS} WHERE [Day] = @d;
    -- GroupingId stays the CUBE of the four columns; the lifecycle is never grouped away
    INSERT sidata.{ASSETS} ([Day], CollectionId, GroupingId, Tier, Severity, SecurityDomain, ReportName, Assets, CiLifecycle)
    SELECT @d, @c, GROUPING_ID(g.Tier, g.Sev, g.Dom, g.Rep), g.Tier, g.Sev, g.Dom, g.Rep, COUNT(DISTINCT g.AssetKey), g.Lc
    FROM (SELECT f.Tier, ISNULL(f.Severity, '') AS Sev, ISNULL(f.SecurityDomain, '') AS Dom, ISNULL(f.ReportName, '') AS Rep, f.AssetKey, f.CiLifecycle AS Lc
          FROM sidata.Finding f WHERE @c IS NOT NULL AND f.CollectionId = @c{MARK}) AS g
    GROUP BY g.Lc, CUBE (g.Tier, g.Sev, g.Dom, g.Rep);
END;
COMMIT;
SELECT @n;
'@).Replace('{TABLE}', $table).Replace('{MARK}', $mark).Replace('{ASSETS}', $assets)
}

function Get-SIDataAssetDailyTablesSql {
    <#
        #295 -- adds sidata.AssetDaily and its counted twin (the distinct assets at every grain) to a database set up before
        they existed: the SAME guarded, additive statements as sql/si-data-schema.sql, so a customer database does not need
        setup run again. Never alters or drops anything.
    #>
    $parts = foreach ($t in 'AssetDaily', 'AssetDailyCounted') {
@"
IF OBJECT_ID('sidata.$t') IS NULL
CREATE TABLE sidata.$t (
    AssetDailyId     BIGINT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_$t PRIMARY KEY NONCLUSTERED,
    [Day]            DATE           NOT NULL,
    CollectionId     INT            NOT NULL CONSTRAINT FK_$($t)_Collection REFERENCES sidata.Collection (CollectionId),
    GroupingId       TINYINT        NOT NULL,
    Tier             TINYINT        NULL,
    Severity         NVARCHAR(30)   NULL,
    SecurityDomain   NVARCHAR(128)  NULL,
    ReportName       NVARCHAR(256)  NULL,
    Assets           INT            NOT NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CX_$($t)_Day' AND object_id = OBJECT_ID('sidata.$t'))
CREATE CLUSTERED INDEX CX_$($t)_Day ON sidata.$t ([Day], GroupingId);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_$($t)_Collection' AND object_id = OBJECT_ID('sidata.$t'))
CREATE INDEX IX_$($t)_Collection ON sidata.$t (CollectionId);
"@
    }
    ($parts -join "`n") + "`nSELECT 1;"
}

function Get-SIDataAssetDailyPendingSql {
    <#
        #295 -- the days whose FindingDaily has rows but whose distinct-asset grains (AssetDaily) were never computed: every
        day loaded before the table existed. The data sync recomputes each such day once (Get-SIDataFindingDailySql, and its
        counted twin where the day's collection has twins). Nothing when the table does not exist yet.
    #>
    @'
DECLARE @q nvarchar(max) = N'SELECT CAST(NULL AS nvarchar(10)) AS [Day], CAST(0 AS bit) AS Counted WHERE 1 = 0';
IF OBJECT_ID('sidata.AssetDaily') IS NOT NULL
    SET @q += N' UNION SELECT DISTINCT CONVERT(nvarchar(10), fd.[Day], 23), CAST(0 AS bit) FROM sidata.FindingDaily AS fd
                 WHERE NOT EXISTS (SELECT 1 FROM sidata.AssetDaily AS ad WHERE ad.[Day] = fd.[Day])';
IF OBJECT_ID('sidata.AssetDailyCounted') IS NOT NULL AND OBJECT_ID('sidata.FindingDailyCounted') IS NOT NULL
    SET @q += N' UNION SELECT DISTINCT CONVERT(nvarchar(10), fc.[Day], 23), CAST(1 AS bit) FROM sidata.FindingDailyCounted AS fc
                 WHERE NOT EXISTS (SELECT 1 FROM sidata.AssetDailyCounted AS ac WHERE ac.[Day] = fc.[Day])';
SET @q += N' ORDER BY 1, 2';
EXEC sp_executesql @q;
'@
}

# ------------------------------------------------------------------------------------------------------------------
#  #855 W10 THE CI LIFECYCLE ON EVERY FINDING (sql\si-data-schema.sql "THE CI LIFECYCLE ON EVERY FINDING")
# ------------------------------------------------------------------------------------------------------------------
#  Owner 2026-10-21: "we need to be able to trust all data" / "default filter is active, so it should be active only". Risk
#  Analysis keeps producing findings for CIs that are not seen or retired; what a view counts is decided by the CI's lifecycle
#  (sidata.Ci.Lifecycle, the CI build's -- the settings in force), never by a day count of the view's own. Each finding of a
#  collection is stamped with its CI's lifecycle when the collection is stored, BEFORE it is marked complete and before any
#  aggregate is built from it, set-based in FindingId ranges sized from their measured time. A collection stored before the
#  column existed is unstamped (every finding counts as active, as before); the newest one is stamped ONCE and derived again
#  (Invoke-SIDataCiLifecycleRestamp), so the views are right from the first data sync after the update.

# the derived tables that carry the lifecycle as a key / a column (the schema file's list; the data sync adds the columns too)
$script:SIDataCiLifecycleTables = @('FindingDaily', 'FindingDailyCounted', 'AssetDaily', 'AssetDailyCounted', 'FindingPivotCell', 'FindingPivotCellCounted',
                                     'PivotCell', 'AssetRiskSummary', 'AssetRiskSummaryCounted', 'Tier0Asset', 'Tier0AssetCounted', 'CiFindingSummary')

function Get-SIDataCiLifecycleColumnsSql {
    <#
        The lifecycle columns -- the SAME guarded, additive statements as sql\si-data-schema.sql (a test holds the two equal),
        so the data sync of an install whose schema was applied before them adds them itself. A column add is metadata only.
        Never alters or drops anything.
    #>
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add("IF COL_LENGTH('sidata.Finding', 'CiLifecycle') IS NULL ALTER TABLE sidata.Finding ADD CiLifecycle NVARCHAR(16) NULL;")
    $l.Add("IF COL_LENGTH('sidata.Collection', 'CiLifecycleAt') IS NULL ALTER TABLE sidata.Collection ADD CiLifecycleAt DATETIME2(0) NULL;")
    foreach ($t in $script:SIDataCiLifecycleTables) {
        if ($t -eq 'FindingDaily') { $l.Add("IF COL_LENGTH('sidata.FindingDaily', 'CiLifecycle') IS NULL ALTER TABLE sidata.FindingDaily ADD CiLifecycle NVARCHAR(16) NULL;"); continue }
        $l.Add("IF COL_LENGTH('sidata.$t', 'CiLifecycle') IS NULL AND OBJECT_ID('sidata.$t') IS NOT NULL ALTER TABLE sidata.$t ADD CiLifecycle NVARCHAR(16) NULL;")
        if ($t -like 'AssetRiskSummary*') { $l.Add("IF COL_LENGTH('sidata.$t', 'Unclassified') IS NULL AND OBJECT_ID('sidata.$t') IS NOT NULL ALTER TABLE sidata.$t ADD Unclassified BIGINT NULL;") }
    }
    # W9: the vulnerabilities' closes by reason
    foreach ($c in 'ClosedFixed', 'ClosedRetired', 'ClosedOther') { $l.Add("IF COL_LENGTH('sidata.VulnLifecycleDaily', '$c') IS NULL ALTER TABLE sidata.VulnLifecycleDaily ADD $c INT NULL;") }
    ($l -join "`r`n") + "`r`nSELECT 1;"
}

function Get-SIDataCiLifecycleReadySql {
    <# 1 when the findings carry the lifecycle column and the CIs exist to stamp it from; else 0. #>
    "SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'CiLifecycle') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'CiLifecycleAt') IS NOT NULL AND OBJECT_ID('sidata.Ci') IS NOT NULL AND OBJECT_ID('sidata.CiLink') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataCiLifecycleStampSql {
    <#
        One FindingId range (@After, @Upto] of one collection: each finding's CI lifecycle, from the CI the key figures resolve
        (SI-DataKeyFigures.ps1): the CI whose id is the finding's AssetKey, else the CI that carries the AssetKey as a linked
        object (sidata.CiLink.NativeId, the primary and newest link first). A CI without a lifecycle is active; a finding no CI
        carries is left NULL (not known to be gone: counted as active). Resolved ONCE per distinct asset of the range, then
        one set-based update of only the rows whose value differs. Answers the rows written.
    #>
    @'
SET NOCOUNT ON;
CREATE TABLE #m (AssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, Lc NVARCHAR(16) COLLATE DATABASE_DEFAULT NULL);
INSERT #m (AssetKey, Lc)
SELECT a.AssetKey,
       CASE WHEN ci.CiId IS NOT NULL THEN ISNULL(NULLIF(ci.Lifecycle, N''), N'active')
            WHEN lk.CiId IS NOT NULL THEN ISNULL(NULLIF(lk.Lifecycle, N''), N'active') END
FROM (SELECT DISTINCT f.AssetKey FROM sidata.Finding AS f
      WHERE f.CollectionId = @CollectionId AND f.FindingId > @After AND f.FindingId <= @Upto AND f.AssetKey IS NOT NULL) AS a
LEFT JOIN sidata.Ci AS ci ON LEN(a.AssetKey) <= 64 AND ci.CiId = a.AssetKey
OUTER APPLY (SELECT TOP (1) l.CiId, c2.Lifecycle FROM sidata.CiLink AS l JOIN sidata.Ci AS c2 ON c2.CiId = l.CiId
             WHERE ci.CiId IS NULL AND LEN(a.AssetKey) <= 450 AND l.NativeId = LOWER(a.AssetKey)
             ORDER BY l.IsPrimary DESC, l.LastSeen DESC) AS lk;
UPDATE f SET CiLifecycle = m.Lc
FROM sidata.Finding AS f
JOIN #m AS m ON m.AssetKey = f.AssetKey
WHERE f.CollectionId = @CollectionId AND f.FindingId > @After AND f.FindingId <= @Upto
  AND (f.CiLifecycle IS NULL AND m.Lc IS NOT NULL OR f.CiLifecycle IS NOT NULL AND m.Lc IS NULL OR f.CiLifecycle <> m.Lc);
SELECT @@ROWCOUNT;
'@
}

function Get-SIDataCiLifecycleStampedSql {
    <# The collection's findings are stamped (Collection.CiLifecycleAt). #>
    "UPDATE sidata.Collection SET CiLifecycleAt = SYSUTCDATETIME() WHERE CollectionId = @CollectionId; SELECT @@ROWCOUNT;"
}

function Invoke-SIDataCiLifecycleStamp {
    <#
        Stamps ONE collection's findings with their CI's lifecycle (Get-SIDataCiLifecycleStampSql) in FindingId ranges sized
        from their measured time and paced by the database's load (as the derive), then CiLifecycleAt. A database without the
        column or the CIs stamps nothing (answers -1). Returns the rows written.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$CollectionId, [ref]$BatchSize, [long]$TargetMs = 5000)
    if (([int](& $Invoke (Get-SIDataCiLifecycleReadySql) @{} 'scalar')) -ne 1) { return -1L }
    $bRaw = & $Invoke (Get-SIDataFindingBoundsSql) @{ CollectionId = $CollectionId } 'reader'
    $b = @($bRaw) | Select-Object -First 1
    $done = 0L
    if ($b -and $null -ne $b['Lo'] -and -not ($b['Lo'] -is [System.DBNull])) {
        $lo = [long]$b['Lo']; $hi = [long]$b['Hi']
        $size = [long]50000; if ($BatchSize -and $BatchSize.Value -gt 0) { $size = [long]$BatchSize.Value }
        $after = $lo - 1
        $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
        $sql = Get-SIDataCiLifecycleStampSql
        while ($after -lt $hi) {
            if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs; if ($pace.Shrink) { $size = [Math]::Max(500L, [long][Math]::Floor($size / 2)) } }
            $upto = [Math]::Min($hi, $after + $size)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $done += [long](& $Invoke $sql @{ CollectionId = $CollectionId; After = $after; Upto = $upto } 'scalar')
            $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
            $after = $upto
            $size = Get-SIDataNextSize -Current $size -ElapsedMs $sw.ElapsedMilliseconds -TargetMs $TargetMs -Minimum 500
        }
        if ($BatchSize) { $BatchSize.Value = $size }
    }
    [void](& $Invoke (Get-SIDataCiLifecycleStampedSql) @{ CollectionId = $CollectionId } 'scalar')
    $done
}

function Get-SIDataCiLifecycleRestampSql {
    <#
        The collections the views open by default that were stored before the lifecycle was stamped: the newest complete
        Detailed collection and the published one (sidata.PublishedRun), when their CiLifecycleAt is empty. Older collections
        stay as they were (their findings count as active -- their trend days are what they were). Never a retired collection.
    #>
    $live = Get-SIDataLiveFilter -Alias 'c'
    @"
SELECT c.CollectionId, CONVERT(nvarchar(10), c.CollectionTime, 23) AS [Day], c.CollectionTime
FROM sidata.Collection AS c
WHERE c.Kind = 'Detailed' AND c.Status = 'Complete' AND c.CiLifecycleAt IS NULL$live
  AND (c.CollectionId = (SELECT TOP (1) n.CollectionId FROM sidata.Collection AS n WHERE n.Kind = 'Detailed' AND n.Status = 'Complete' ORDER BY n.CollectionTime DESC)
       OR (OBJECT_ID('sidata.PublishedRun') IS NOT NULL AND c.CollectionId IN (SELECT p.DetailedCollectionId FROM sidata.PublishedRun AS p WHERE p.Name = N'current')))
ORDER BY c.CollectionTime DESC
"@
}

function Get-SIDataCiLifecycleRederiveSql {
    <#
        A collection stamped after it was derived is derived again: its views' data (DerivedAt -- the facets, and through it
        every per-collection aggregate, the prepared context, the summaries, the remediations and the key figures, which are
        built again when they are older than the derive) and its departments (ResolvedVersion). Its day's FindingDaily is
        worked out again by the caller.
    #>
    "UPDATE sidata.Collection SET DerivedAt = NULL, ResolvedVersion = NULL WHERE CollectionId = @CollectionId; SELECT @@ROWCOUNT;"
}

function Invoke-SIDataCiLifecycleRestamp {
    <#
    .SYNOPSIS  Stamps the newest and the published collection once when they were stored before the lifecycle was stamped, and
               marks them to be derived again by this run's own steps. Never throws.
    .NOTES     Returns @{ Status; Collections; Findings }. Bounded: at most these two collections, ever once each.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        if (([int](& $Invoke (Get-SIDataCiLifecycleReadySql) @{} 'scalar')) -ne 1) { return [pscustomobject]@{ Status = 'no-schema'; Collections = 0; Findings = 0 } }
        $pending = @(@(& $Invoke (Get-SIDataCiLifecycleRestampSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $_ })
        if ($pending.Count -eq 0) { return [pscustomobject]@{ Status = 'ok'; Collections = 0; Findings = 0 } }
        if ($DryRun) {
            & $Log 'INFO' ("lifecycle   : {0} collection(s) would be stamped with their CIs' lifecycle and derived again; nothing is written." -f $pending.Count)
            return [pscustomobject]@{ Status = 'dry-run'; Collections = 0; Findings = 0; Pending = $pending.Count }
        }
        $n = 0L; $bs = [long]0
        foreach ($p in $pending) {
            $cid = [int]$p['CollectionId']
            $n += [long](Invoke-SIDataCiLifecycleStamp -Invoke $Invoke -CollectionId $cid -BatchSize ([ref]$bs))
            [void](& $Invoke (Get-SIDataCiLifecycleRederiveSql) @{ CollectionId = $cid } 'scalar')
            [void](& $Invoke (Get-SIDataFindingDailySql) @{ Day = [string]$p['Day'] } 'scalar')
        }
        & $Log 'OK' ("lifecycle   : {0} collection(s) stamped with their CIs' lifecycle ({1} finding row(s)) -- their views are worked out again in this run, active CIs by default" -f $pending.Count, $n)
        [pscustomobject]@{ Status = 'ok'; Collections = $pending.Count; Findings = $n }
    } catch {
        & $Log 'WARN' ("lifecycle   : the CIs' lifecycle was not stamped on the newest collection this run -- {0}. It is tried again on the next run; until then its findings count as active." -f $_.Exception.Message)
        [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message; Collections = 0; Findings = 0 }
    }
}

function Get-SIDataVulnLifecycleSql {
    <#
        Every day from the first close-loop event to today: opened, closed (by SI or an engineer), reopened, and the
        number open at the end of the day (a running sum of the state changes). -1 when the close-loop is not installed.
        #855 W9: the closes split by reason -- fixed (Remediated), asset retired (AssetRetired), any other reason.
    #>
    @'
SET XACT_ABORT ON;
IF OBJECT_ID('vuln.VulnerabilityEvent') IS NULL BEGIN SELECT -1; RETURN; END;
DECLARE @first date = (SELECT CAST(MIN([At]) AS date) FROM vuln.VulnerabilityEvent);
DECLARE @last date = CAST(SYSUTCDATETIME() AS date);
IF @first IS NULL BEGIN SELECT 0; RETURN; END;
CREATE TABLE #lc ([Day] date PRIMARY KEY, Opened int, Closed int, Reopened int, OpenAtEndOfDay int, ClosedFixed int, ClosedRetired int, ClosedOther int);
WITH firstopen AS (
    -- #292: THE BASELINE. The first snapshot a source sent is what was already there, not what is new: its Open
    -- events (the source's first run, or its first day when the run is not recorded) count toward the open total but
    -- never as "opened". Without this every finding of the connector's first snapshot read as new for a week.
    SELECT i.Source, MIN(e.[At]) AS FirstAt
    FROM vuln.VulnerabilityEvent AS e JOIN vuln.VulnerabilityItem AS i ON i.SysId = e.SysId
    WHERE e.Action = 'Open'
    GROUP BY i.Source
), baseline AS (
    SELECT f.Source, f.FirstAt,
           (SELECT TOP (1) e2.RunId FROM vuln.VulnerabilityEvent AS e2 JOIN vuln.VulnerabilityItem AS i2 ON i2.SysId = e2.SysId
             WHERE i2.Source = f.Source AND e2.Action = 'Open' AND e2.[At] = f.FirstAt) AS RunId
    FROM firstopen AS f
), ev AS (
    SELECT CAST(e.[At] AS date) AS [Day],
           SUM(CASE WHEN e.Action = 'Open'
                     AND NOT (b.Source IS NOT NULL AND ((b.RunId IS NOT NULL AND e.RunId = b.RunId)
                                                     OR (b.RunId IS NULL AND CAST(e.[At] AS date) = CAST(b.FirstAt AS date))))
                    THEN 1 ELSE 0 END) AS Opened,
           SUM(CASE WHEN e.Action IN ('Close', 'EngineerClose') THEN 1 ELSE 0 END) AS Closed,
           -- #855 W9: a close is FIXED only when its reason is Remediated; an asset that retired is not fixed work, nor is any other reason
           SUM(CASE WHEN e.Action IN ('Close', 'EngineerClose') AND LEFT(ISNULL(e.Reason, N''), CHARINDEX(N':', ISNULL(e.Reason, N'') + N':') - 1) = N'Remediated' THEN 1 ELSE 0 END) AS ClosedFixed,
           SUM(CASE WHEN e.Action IN ('Close', 'EngineerClose') AND LEFT(ISNULL(e.Reason, N''), CHARINDEX(N':', ISNULL(e.Reason, N'') + N':') - 1) = N'AssetRetired' THEN 1 ELSE 0 END) AS ClosedRetired,
           SUM(CASE WHEN e.Action = 'Reopen' THEN 1 ELSE 0 END) AS Reopened,
           SUM(CASE WHEN e.ToState = 'Open' AND ISNULL(e.FromState, '') <> 'Open' THEN 1
                    WHEN e.FromState = 'Open' AND ISNULL(e.ToState, '') <> 'Open' THEN -1 ELSE 0 END) AS Delta
    FROM vuln.VulnerabilityEvent AS e
    LEFT JOIN vuln.VulnerabilityItem AS i ON i.SysId = e.SysId
    LEFT JOIN baseline AS b ON b.Source = i.Source
    GROUP BY CAST(e.[At] AS date)
), cal AS (
    SELECT @first AS [Day] UNION ALL SELECT DATEADD(day, 1, [Day]) FROM cal WHERE [Day] < @last
)
INSERT #lc ([Day], Opened, Closed, Reopened, OpenAtEndOfDay, ClosedFixed, ClosedRetired, ClosedOther)
SELECT cal.[Day], ISNULL(ev.Opened, 0), ISNULL(ev.Closed, 0), ISNULL(ev.Reopened, 0),
       SUM(ISNULL(ev.Delta, 0)) OVER (ORDER BY cal.[Day] ROWS UNBOUNDED PRECEDING),
       ISNULL(ev.ClosedFixed, 0), ISNULL(ev.ClosedRetired, 0), ISNULL(ev.Closed, 0) - ISNULL(ev.ClosedFixed, 0) - ISNULL(ev.ClosedRetired, 0)
FROM cal LEFT JOIN ev ON ev.[Day] = cal.[Day]
OPTION (MAXRECURSION 0);
BEGIN TRAN;
DELETE FROM sidata.VulnLifecycleDaily;
INSERT sidata.VulnLifecycleDaily ([Day], Opened, Closed, Reopened, OpenAtEndOfDay)
SELECT [Day], Opened, Closed, Reopened, OpenAtEndOfDay FROM #lc;
-- #855 W9: the closes by reason, where the database carries the columns (the data sync adds them: Get-SIDataCiLifecycleColumnsSql)
IF COL_LENGTH('sidata.VulnLifecycleDaily', 'ClosedFixed') IS NOT NULL
    EXEC sp_executesql N'UPDATE d SET ClosedFixed = l.ClosedFixed, ClosedRetired = l.ClosedRetired, ClosedOther = l.ClosedOther FROM sidata.VulnLifecycleDaily AS d JOIN #lc AS l ON l.[Day] = d.[Day];';
COMMIT;
SELECT COUNT(*) FROM #lc;
'@
}

# ------------------------------------------------------------------------------------------------------------------
#  THE COLLECTION VIEWS' DATA (#241): columns derived from DetailJson + the per-collection aggregate (sidata.FindingFacet)
# ------------------------------------------------------------------------------------------------------------------

function Get-SIDataViewsSchemaCheckSql {
    <# 1 when the database carries the collection views' columns and aggregate table (si-data-schema.sql, #241), else 0. #>
    "SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'RiskRating') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'HasExploit') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'DerivedAt') IS NOT NULL AND OBJECT_ID('sidata.FindingFacet') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataUnderivedSql {
    <#
        Complete collections whose views' data is not computed yet -- new loads and, once, every collection loaded earlier.
        Newest first. -Services (the database carries the Services view's tables, #255): also every collection whose
        service membership is not computed yet, so an install extended later derives its older collections once.
    #>
    param([switch]$Services)
    # #717: never a collection whose finding rows the retention removed (its aggregates are what is left of it)
    $live = Get-SIDataLiveFilter
    if ($Services) { return "SELECT CollectionId, CollectionTime FROM sidata.Collection WHERE Status = 'Complete' AND (DerivedAt IS NULL OR ServicesDerivedAt IS NULL)$live ORDER BY CollectionTime DESC" }
    "SELECT CollectionId, CollectionTime FROM sidata.Collection WHERE Status = 'Complete' AND DerivedAt IS NULL$live ORDER BY CollectionTime DESC"
}

function Get-SIDataFindingBoundsSql {
    "SELECT MIN(FindingId) AS Lo, MAX(FindingId) AS Hi FROM sidata.Finding WHERE CollectionId = @CollectionId"
}

# #830 / #834 THE RISK ANALYSIS ROW'S VALUES THE READERS READ ON EVERY FINDING, stored once at derive time (si-data-schema.sql
# "RaRowAssetId ..."): column -> the row's fields, in the order the readers coalesce them; Kind 'value' = the value as text (a
# list or an object as its JSON text), 'fill' = 1 when the field is not empty or blank (data quality's fill rule). The readers
# (SI-VulnDesired.ps1, SI-DataQuality.ps1) name the same columns; SIv3-SqlOnlyReaders.Tests.ps1 keeps the three in step.
$script:SIDataRowColumns = [ordered]@{
    RaRowAssetId                = @{ Kind = 'value'; Fields = @('AssetId') }
    RaRowSolutionVersion        = @{ Kind = 'value'; Fields = @('SolutionVersion') }
    RaRowCriticalityTier        = @{ Kind = 'value'; Fields = @('CriticalityTier') }
    RaRowSiComponent            = @{ Kind = 'value'; Fields = @('si_component') }
    RaScopeRiskRating           = @{ Kind = 'value'; Fields = @('RiskRating', 'si_risk_rating') }
    RaScopeCategory             = @{ Kind = 'value'; Fields = @('si_category', 'Category') }
    RaScopeSubcategory          = @{ Kind = 'value'; Fields = @('si_subcategory', 'SubCategory', 'Subcategory') }
    RaScopeClass                = @{ Kind = 'value'; Fields = @('si_class', 'AssetClass') }
    RaScopeComponent            = @{ Kind = 'value'; Fields = @('si_component', 'Component') }
    RaScopePatchCycle           = @{ Kind = 'value'; Fields = @('si_patch_cycle') }
    RaScopeOsFamily             = @{ Kind = 'value'; Fields = @('si_os_family') }
    RaScopeSubCi                = @{ Kind = 'value'; Fields = @('si_servicenow_subci') }
    RaScopeAffectedProduct      = @{ Kind = 'value'; Fields = @('si_affected_product') }
    RaFillRiskFactorProbability = @{ Kind = 'fill'; Fields = @('RiskFactor_Probability_Detailed') }
    RaFillRiskFactorConsequence = @{ Kind = 'fill'; Fields = @('RiskFactor_Consequence_Detailed') }
}

function Get-SIDataRowColumnExpr {
    <#
        PURE. The SQL that fills one row column from -Json (an expression of the row's JSON text), exactly the readers' former
        per-finding read: one field = COALESCE(JSON_VALUE, JSON_QUERY); several = the first that is not empty (the readers'
        coalesce, which skips empty text); 'fill' = 1 when the value trimmed of white space is not empty, else 0.
    #>
    param([Parameter(Mandatory)][string]$Column, [string]$Json = 'f.DetailJson',
          # read from the row's ONE parse (Get-SIDataRowFieldsApply, alias rj) instead of one JSON_VALUE / JSON_QUERY per field --
          # the same value: the scalar as text (NULL past 4,000 characters, as JSON_VALUE), else the list or object as JSON text
          [switch]$Parsed)
    $c = $script:SIDataRowColumns[$Column]; if (-not $c) { throw ("not a row column: '{0}'" -f $Column) }
    $one = if ($Parsed) { { param([string]$fld) $n = (Get-SIDataRowFieldList).IndexOf($fld); "COALESCE(CASE WHEN LEN(rj.[v$n]) <= 4000 THEN rj.[v$n] END, rj.[j$n])" } }
           else { { param([string]$fld) "COALESCE(JSON_VALUE($Json, N'$.$fld'), JSON_QUERY($Json, N'$.$fld'))" } }
    if ($c.Kind -eq 'fill') { return ("CASE WHEN LEN(TRIM(CHAR(9) + CHAR(10) + CHAR(13) + CHAR(32) FROM COALESCE({0}, N''))) > 0 THEN 1 ELSE 0 END" -f (& $one $c.Fields[0])) }
    if ($c.Fields.Count -eq 1) { return (& $one $c.Fields[0]) }
    'COALESCE(' + ((@($c.Fields | ForEach-Object { "NULLIF($(& $one $_), N'')" })) -join ', ') + ')'
}

function Get-SIDataRowFieldList {
    <# PURE. Every field the row columns read, once each, in a fixed order (the place names its parsed column). #>
    $flds = New-Object System.Collections.Generic.List[string]
    foreach ($c in $script:SIDataRowColumns.Values) { foreach ($x in $c.Fields) { if (-not $flds.Contains($x)) { $flds.Add($x) } } }
    , $flds
}

function Get-SIDataRowFieldsApply {
    <#
        PURE. #834 the row's fields the row columns read, parsed ONCE per finding: OUTER APPLY OPENJSON ... WITH -- for each
        field its scalar text (v_<field>) and its list or object (j_<field>, AS JSON). Measured at 20,000 findings: one
        JSON_VALUE + JSON_QUERY per column parsed every row ~30 times more and took the derive from 16.3 to 39.7 s.
    #>
    $flds = Get-SIDataRowFieldList
    # the columns by the field's place (v<n> / j<n>): two fields may differ only in case (SubCategory, Subcategory), and SQL names do not
    $w = @(for ($i = 0; $i -lt $flds.Count; $i++) { $x = $flds[$i]; "[v$i] nvarchar(max) N'$.$x'"; "[j$i] nvarchar(max) N'$.$x' AS JSON" }) -join ', '
    "OUTER APPLY OPENJSON(CASE WHEN ISJSON(f.DetailJson) = 1 THEN f.DetailJson END) WITH ($w) AS rj"
}

function Get-SIDataRowColumnsSql {
    <#
        2026-10-25 ONLY the row values ($script:SIDataRowColumns) of one FindingId range: exactly the derive's expressions over
        exactly the derive's rows (ISJSON = 1), so a collection filled here holds what the derive would have written. The
        vulnerability step runs BEFORE the data sync and reads the row values typed (set-based, Test-SIVulnSetBasedReady); it
        fills them here first (Invoke-SIDataRowColumnsFill). -Carried: only the rows the data sync carried in (CarriedFrom),
        for a collection whose own rows were filled that way (Invoke-SIDataDeriveCollection). Idempotent.
    #>
    param([switch]$Carried, [switch]$NoCount)
    $set = @(foreach ($rc in $script:SIDataRowColumns.Keys) { '    {0} = {1}' -f $rc, (Get-SIDataRowColumnExpr -Column $rc -Parsed) }) -join ",`r`n"
    $only = if ($Carried) { ' AND f.CarriedFrom IS NOT NULL' } else { '' }
    $count = if ($NoCount) { '' } else { "`r`nSELECT @@ROWCOUNT;" }
    "UPDATE f SET`r`n$set`r`nFROM sidata.Finding AS f`r`n$(Get-SIDataRowFieldsApply)`r`nWHERE f.CollectionId = @CollectionId AND f.FindingId > @After AND f.FindingId <= @Upto AND ISJSON(f.DetailJson) = 1$only;$count"
}

function Get-SIDataDeriveFindingSql {
    <#
        One FindingId range of one collection: the views' columns from DetailJson (the whole Log Analytics row). A value
        Log Analytics stored as an array is read as its items. Lists are stored ';'-separated without padding, so a
        token filter matches ';' + list + ';'. Re-running a range writes the same values (idempotent).
        -Services (#255): also the CMDB service the row carried (cmdbId / cmdbName), only when the database has those columns.
        -Fix (#590): also the finding's fix -- how to fix it, the recommended security update and its id, the affected
        software (si_fix_remediation / si_fix_recommended_update / si_fix_recommended_update_id / si_affected_software),
        only when the database has those columns (Get-SIDataFixSchemaCheckSql).
        -Category (#834): also the Risk Analysis row's Category (RaCategory) -- exactly the expression the Domain -> Category
        pairs read (Get-SIDataDomainCategorySql), so the pairs come from a narrow index, never every finding's JSON again.
    #>
    param([switch]$Services, [switch]$Fix, [switch]$Category,
          # #830 / #834 also the row values the readers read on every finding ($script:SIDataRowColumns)
          [switch]$RowColumns,
          # 2026-10-25 the collection's own rows already carry the row values (the vulnerability step filled them, RaRowsAt):
          # only the rows the data sync carried in get them here (Get-SIDataRowColumnsSql -Carried)
          [switch]$CarriedRowColumns)
    $svc = ''
    if ($Services) {
        $svc = ",`r`n    CmdbId            = LEFT(NULLIF(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.cmdbId'))), N''), 256)," +
               "`r`n    CmdbName          = LEFT(NULLIF(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.cmdbName'))), N''), 400)"
    }
    if ($Fix) {
        $svc += ",`r`n    FixRemediation         = LEFT(NULLIF(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.si_fix_remediation'))), N''), 4000)," +
                "`r`n    FixRecommendedUpdate   = LEFT(NULLIF(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.si_fix_recommended_update'))), N''), 1000)," +
                "`r`n    FixRecommendedUpdateId = LEFT(NULLIF(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.si_fix_recommended_update_id'))), N''), 1000)," +
                "`r`n    AffectedSoftware       = LEFT(NULLIF(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.si_affected_software'))), N''), 2000)"
    }
    if ($Category) { $svc += ",`r`n    RaCategory        = LEFT(JSON_VALUE(f.DetailJson, '$.Category'), 128)" }
    if ($RowColumns) { foreach ($rc in $script:SIDataRowColumns.Keys) { $svc += (",`r`n    {0} = {1}" -f $rc, (Get-SIDataRowColumnExpr -Column $rc -Parsed)) } }
    $apply = if ($RowColumns) { "`r`n" + (Get-SIDataRowFieldsApply) } else { '' }
    $tail = if ($CarriedRowColumns -and -not $RowColumns) { "DECLARE @n int = @@ROWCOUNT;`r`n" + (Get-SIDataRowColumnsSql -Carried -NoCount) + "`r`nSELECT @n;" } else { 'SELECT @@ROWCOUNT;' }
    (@'
UPDATE f SET
    RiskScoreWeighted = TRY_CONVERT(float, JSON_VALUE(f.DetailJson, '$.RiskScoreTotal_Weighted')),
    RiskRating        = LEFT(NULLIF(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.RiskRating'))), N''), 16),
    MitreTactics      = LEFT(NULLIF(REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(JSON_VALUE(f.DetailJson, '$.MITRE_Tactics'),
                            REPLACE(REPLACE(REPLACE(REPLACE(JSON_QUERY(f.DetailJson, '$.MITRE_Tactics'), N'","', N';'), N'[', N''), N']', N''), N'"', N'')),
                            N', ', N';'), N',', N';'), N'; ', N';'), N' ;', N';'), N''), 1000),
    MitreTechniques   = LEFT(NULLIF(REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(JSON_VALUE(f.DetailJson, '$.MITRE_Techniques'),
                            REPLACE(REPLACE(REPLACE(REPLACE(JSON_QUERY(f.DetailJson, '$.MITRE_Techniques'), N'","', N';'), N'[', N''), N']', N''), N'"', N'')),
                            N', ', N';'), N',', N';'), N'; ', N';'), N' ;', N';'), N''), 2000),
    ComplianceTags    = LEFT(NULLIF(REPLACE(REPLACE(COALESCE(JSON_VALUE(f.DetailJson, '$.ComplianceTags'),
                            REPLACE(REPLACE(REPLACE(REPLACE(JSON_QUERY(f.DetailJson, '$.ComplianceTags'), N'","', N';'), N'[', N''), N']', N''), N'"', N'')),
                            N'; ', N';'), N' ;', N';'), N''), 2000),
    Cvss              = COALESCE(TRY_CONVERT(float, JSON_VALUE(f.DetailJson, '$.MaxCvssScore')),
                                 CASE WHEN f.Cve IS NOT NULL THEN TRY_CONVERT(float, JSON_VALUE(f.DetailJson, '$.Impact')) END),
    HasExploit        = CASE LOWER(JSON_VALUE(f.DetailJson, '$.HasExploit')) WHEN 'true' THEN 1 WHEN '1' THEN 1 WHEN 'false' THEN 0 WHEN '0' THEN 0 END{0}
FROM sidata.Finding AS f{1}
WHERE f.CollectionId = @CollectionId AND f.FindingId > @After AND f.FindingId <= @Upto AND ISJSON(f.DetailJson) = 1;
{2}
'@).Replace('{0}', $svc).Replace('{1}', $apply).Replace('{2}', $tail)
}

function Get-SIDataFacetSql {
    <#
        The collection's aggregates for the facet views, replacing what it held, and DerivedAt -- one transaction, so a
        reader sees the old set or the new one, never half. A list value (tactic, technique, tag) counts each finding
        once per distinct item. CVSS bands are the CVSS v3 qualitative ratings.
        -Counted (#264): the same aggregates over the findings WITHOUT an exemption mark, into sidata.FindingFacetCounted;
        DerivedAt is not touched (the exempted step stamps ExemptedDerivedAt; a DerivedAt newer than it makes the twin stale).
    #>
    param([switch]$Counted)
    $table = 'FindingFacet'; $mark = ''
    $stamp = "UPDATE sidata.Collection SET DerivedAt = SYSUTCDATETIME() WHERE CollectionId = @CollectionId;"
    if ($Counted) { $table = 'FindingFacetCounted'; $mark = ' AND ExemptionId IS NULL'; $stamp = '' }
    (@'
SET XACT_ABORT ON;
CREATE TABLE #ff (Facet nvarchar(16) NOT NULL, Value nvarchar(256) NOT NULL, Findings int NOT NULL, Assets int NOT NULL,
                  ScoreTotal float NOT NULL, WeightedTotal float NULL, MaxScore float NULL);
{FACTS}
INSERT #ff (Facet, Value, Findings, Assets, ScoreTotal, WeightedTotal, MaxScore)
SELECT Facet, Value, COUNT(*), COUNT(DISTINCT AssetKey), ISNULL(SUM(RiskScore), 0), SUM(RiskScoreWeighted), MAX(RiskScore)
FROM d GROUP BY Facet, Value;
BEGIN TRAN;
DELETE FROM sidata.{TABLE} WHERE CollectionId = @CollectionId;
INSERT sidata.{TABLE} (CollectionId, Facet, Value, Findings, Assets, ScoreTotal, WeightedTotal, MaxScore)
SELECT @CollectionId, Facet, Value, Findings, Assets, ScoreTotal, WeightedTotal, MaxScore FROM #ff;
DECLARE @n int = @@ROWCOUNT;
{STAMP}
COMMIT;
SELECT @n;
'@).Replace('{FACTS}', (Get-SIDataFacetFactsSql -Where ('CollectionId = @CollectionId' + $mark))).Replace('{TABLE}', $table).Replace('{STAMP}', $stamp)
}

function Get-SIDataFacetFactsSql {
    <#
        THE facts of the facet aggregates, ONE text for the whole-collection statement (Get-SIDataFacetSql) and the ranged
        one (Get-SIDataFacetRangeSql): the CTE chain f -> facts -> d over the findings -Where selects -- d is one row per
        (finding, facet, value), a value counted once per finding. -FixColumn: the recommended update from the finding's
        stored column (FixRecommendedUpdate, written by the derive with the SAME expression just before) instead of
        parsing DetailJson again -- the same value, one JSON parse less per finding.
    #>
    param([Parameter(Mandatory)][string]$Where, [switch]$FixColumn)
    $fix = "CASE WHEN ISJSON(DetailJson) = 1 THEN LEFT(NULLIF(LTRIM(RTRIM(JSON_VALUE(DetailJson, '$.si_fix_recommended_update'))), N''), 1000) END AS FixUpdate"
    if ($FixColumn) { $fix = 'CASE WHEN ISJSON(DetailJson) = 1 THEN FixRecommendedUpdate END AS FixUpdate' }
    (@'
WITH f AS (
    SELECT FindingId, AssetKey, RiskScore, RiskScoreWeighted, RiskRating, MitreTactics, MitreTechniques, ComplianceTags, Cvss,
           Severity, Tier, SecurityDomain, ReportName,
           CASE WHEN ISJSON(DetailJson) = 1 THEN LEFT(NULLIF(LTRIM(RTRIM(JSON_VALUE(DetailJson, '$.si_component'))), N''), 64) END AS Component,
           {FIX}
    -- #855: the facets count ACTIVE CIs only (a finding no CI carries, or of an unstamped collection, counts as active) -- their
    -- key (CollectionId, Facet, Value) cannot take the lifecycle in an additive schema; the views say so
    FROM sidata.Finding WHERE {WHERE} AND (CiLifecycle IS NULL OR CiLifecycle = N'active')
), facts AS (
    SELECT FindingId, N'rating' AS Facet, COALESCE(RiskRating, N'(none)') AS Value, AssetKey, RiskScore, RiskScoreWeighted FROM f
    UNION ALL SELECT FindingId, N'cvss', CASE WHEN Cvss IS NULL THEN N'(none)' WHEN Cvss >= 9 THEN N'Critical (9.0-10)' WHEN Cvss >= 7 THEN N'High (7.0-8.9)'
                                              WHEN Cvss >= 4 THEN N'Medium (4.0-6.9)' WHEN Cvss > 0 THEN N'Low (0.1-3.9)' ELSE N'None (0)' END, AssetKey, RiskScore, RiskScoreWeighted FROM f
    UNION ALL SELECT FindingId, N'score', COALESCE(CONVERT(nvarchar(32), CONVERT(decimal(19, 1), RiskScore)), N'(none)'), AssetKey, RiskScore, RiskScoreWeighted FROM f
    UNION ALL SELECT FindingId, N'weighted', COALESCE(CONVERT(nvarchar(32), CONVERT(bigint, FLOOR(RiskScoreWeighted))), N'(none)'), AssetKey, RiskScore, RiskScoreWeighted FROM f
    UNION ALL SELECT FindingId, N'severity', COALESCE(Severity, N'(none)'), AssetKey, RiskScore, RiskScoreWeighted FROM f
    UNION ALL SELECT FindingId, N'tier', COALESCE(CONVERT(nvarchar(8), Tier), N'(none)'), AssetKey, RiskScore, RiskScoreWeighted FROM f
    UNION ALL SELECT FindingId, N'domain', COALESCE(SecurityDomain, N'(none)'), AssetKey, RiskScore, RiskScoreWeighted FROM f
    UNION ALL SELECT FindingId, N'report', COALESCE(ReportName, N'(none)'), AssetKey, RiskScore, RiskScoreWeighted FROM f
    UNION ALL SELECT FindingId, N'component', COALESCE(Component, N'(none)'), AssetKey, RiskScore, RiskScoreWeighted FROM f
    UNION ALL SELECT f.FindingId, N'tactic', LTRIM(RTRIM(s.value)), f.AssetKey, f.RiskScore, f.RiskScoreWeighted FROM f CROSS APPLY STRING_SPLIT(f.MitreTactics, N';') AS s WHERE f.MitreTactics IS NOT NULL
    UNION ALL SELECT f.FindingId, N'technique', LTRIM(RTRIM(s.value)), f.AssetKey, f.RiskScore, f.RiskScoreWeighted FROM f CROSS APPLY STRING_SPLIT(f.MitreTechniques, N';') AS s WHERE f.MitreTechniques IS NOT NULL
    UNION ALL SELECT f.FindingId, N'tag', LTRIM(RTRIM(s.value)), f.AssetKey, f.RiskScore, f.RiskScoreWeighted FROM f CROSS APPLY STRING_SPLIT(f.ComplianceTags, N';') AS s WHERE f.ComplianceTags IS NOT NULL
    UNION ALL SELECT f.FindingId, N'update', LTRIM(RTRIM(s.value)), f.AssetKey, f.RiskScore, f.RiskScoreWeighted FROM f CROSS APPLY STRING_SPLIT(f.FixUpdate, N';') AS s WHERE f.FixUpdate IS NOT NULL
), d AS (
    SELECT DISTINCT FindingId, Facet, LEFT(Value, 256) AS Value, AssetKey, RiskScore, RiskScoreWeighted FROM facts WHERE Value <> N''
)
'@).Replace('{FIX}', $fix).Replace('{WHERE}', $Where).TrimEnd()
}

# ---- THE FACETS IN FINDING RANGES (a large collection) --------------------------------------------------------------
#  Live 2026-10-19 (two large installs, 885,300 and 1,164,897 findings in one collection): the whole-collection facet
#  statement (Get-SIDataFacetSql) ran past the data sync's SQL limit, so DerivedAt was never stamped and every run derived
#  the collection again and failed the same way. The SAME aggregates are now built in FindingId ranges -- sized from their
#  measured time and paced by the database's load, exactly as the derive's ranges -- each range staging its partial
#  aggregate per (facet, value, CI) in sidata.FindingFacetStage; ONE closing statement groups the staged rows per (facet,
#  value) and replaces the collection's aggregate (and stamps DerivedAt) in one transaction, as before. The ranges cut the
#  findings in disjoint sets, so: findings = the sum of the ranges' counts, CIs = the distinct CI keys over all ranges
#  (COUNT(DISTINCT), a CI without a key is not counted -- as before), scores = the sums and the maximum. Same rows.
#  A database without the stage table (its schema not applied yet) builds the facets in one statement, as before.

function Get-SIDataFacetStageReadySql { "SELECT CASE WHEN OBJECT_ID('sidata.FindingFacetStage') IS NOT NULL THEN 1 ELSE 0 END" }

function Get-SIDataFacetStageClearSql {
    <# One batch of a collection's staged facet rows of one variant (-Counted = @Counted 1), for Invoke-SIDataBatchedDelete. #>
    "DELETE TOP (@Batch) FROM sidata.FindingFacetStage WHERE CollectionId = @CollectionId AND Counted = @Counted; SELECT @@ROWCOUNT;"
}

function Get-SIDataFacetRangeSql {
    <# One FindingId range (@After, @Upto] of one collection: its partial facet aggregate per (facet, value, CI), staged.
       -Counted: the findings without an exemption mark. Returns the rows staged. #>
    param([switch]$Counted, [switch]$FixColumn)
    $where = 'CollectionId = @CollectionId AND FindingId > @After AND FindingId <= @Upto'
    if ($Counted) { $where += ' AND ExemptionId IS NULL' }
    (@'
SET NOCOUNT ON;
{FACTS}
INSERT sidata.FindingFacetStage (CollectionId, Counted, Facet, Value, AssetKey, Findings, ScoreTotal, WeightedTotal, MaxScore)
SELECT @CollectionId, {C}, Facet, Value, AssetKey, COUNT(*), SUM(RiskScore), SUM(RiskScoreWeighted), MAX(RiskScore)
FROM d GROUP BY Facet, Value, AssetKey;
SELECT @@ROWCOUNT;
'@).Replace('{FACTS}', (Get-SIDataFacetFactsSql -Where $where -FixColumn:$FixColumn)).Replace('{C}', $(if ($Counted) { '1' } else { '0' }))
}

function Get-SIDataFacetFinishSql {
    <# The collection's aggregate from its staged ranges, replacing what it held -- and DerivedAt (not for -Counted) -- in ONE
       transaction (a reader sees the old set or the new one). Returns the aggregate's rows. #>
    param([switch]$Counted)
    $table = 'FindingFacet'; $c = '0'
    $stamp = "UPDATE sidata.Collection SET DerivedAt = SYSUTCDATETIME() WHERE CollectionId = @CollectionId;"
    if ($Counted) { $table = 'FindingFacetCounted'; $c = '1'; $stamp = '' }
    (@'
SET XACT_ABORT ON;
CREATE TABLE #ff (Facet nvarchar(16) NOT NULL, Value nvarchar(256) NOT NULL, Findings int NOT NULL, Assets int NOT NULL,
                  ScoreTotal float NOT NULL, WeightedTotal float NULL, MaxScore float NULL);
INSERT #ff (Facet, Value, Findings, Assets, ScoreTotal, WeightedTotal, MaxScore)
SELECT Facet, Value, SUM(Findings), COUNT(DISTINCT AssetKey), ISNULL(SUM(ScoreTotal), 0), SUM(WeightedTotal), MAX(MaxScore)
FROM sidata.FindingFacetStage WHERE CollectionId = @CollectionId AND Counted = {C}
GROUP BY Facet, Value;
BEGIN TRAN;
DELETE FROM sidata.{TABLE} WHERE CollectionId = @CollectionId;
INSERT sidata.{TABLE} (CollectionId, Facet, Value, Findings, Assets, ScoreTotal, WeightedTotal, MaxScore)
SELECT @CollectionId, Facet, Value, Findings, Assets, ScoreTotal, WeightedTotal, MaxScore FROM #ff;
DECLARE @n int = @@ROWCOUNT;
{STAMP}
COMMIT;
SELECT @n;
'@).Replace('{TABLE}', $table).Replace('{C}', $c).Replace('{STAMP}', $stamp)
}

$script:SIDataFacetStageMissingSaid = $false

function Invoke-SIDataFacet {
    <#
        ONE collection's facet aggregate (-Counted: its counted twin): in FindingId ranges through the stage table when the
        database has it, else in one statement (said once per process). The ranges are sized from their measured time
        (-TargetMs, -BatchSize carries the size between calls) and paced by the database's load. What an earlier run left
        staged for the collection is removed first; the staged rows are removed after the aggregate is replaced.
        -Log { param($Level, $Message) }: a line about once a minute while the ranges run, and the total at the end.
        Returns the aggregate's rows (as the one statement did).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$CollectionId, [switch]$Counted, [switch]$FixColumn,
          [ref]$BatchSize, [long]$TargetMs = 5000, [scriptblock]$Log)
    $ready = $false
    try { $ready = ([int](& $Invoke (Get-SIDataFacetStageReadySql) @{} 'scalar')) -eq 1 } catch { $ready = $false }
    if (-not $ready) {
        if (-not $script:SIDataFacetStageMissingSaid -and $Log) {
            $script:SIDataFacetStageMissingSaid = $true
            & $Log 'WARN' 'facets      : the database does not have the table that builds the facet counts in parts yet -- they are built in one statement (the next update adds the table).'
        }
        return [int](& $Invoke (Get-SIDataFacetSql -Counted:$Counted) @{ CollectionId = $CollectionId } 'scalar')
    }
    $cv = $(if ($Counted) { 1 } else { 0 })
    $del = [long]0
    [void](Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataFacetStageClearSql) -Params @{ CollectionId = $CollectionId; Counted = $cv } -BatchSize ([ref]$del))
    $bRaw = & $Invoke (Get-SIDataFindingBoundsSql) @{ CollectionId = $CollectionId } 'reader'
    $b = @($bRaw) | Select-Object -First 1
    if ($b -and $null -ne $b['Lo'] -and -not ($b['Lo'] -is [System.DBNull])) {
        $lo = [long]$b['Lo']; $hi = [long]$b['Hi']
        $size = [long]20000; if ($BatchSize -and $BatchSize.Value -gt 0) { $size = [long]$BatchSize.Value }
        $after = $lo - 1
        $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
        $sql = Get-SIDataFacetRangeSql -Counted:$Counted -FixColumn:$FixColumn
        $all = [Diagnostics.Stopwatch]::StartNew(); $saidAt = 0.0; $ranges = 0
        while ($after -lt $hi) {
            if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs; if ($pace.Shrink) { $size = [Math]::Max(500L, [long][Math]::Floor($size / 2)) } }
            $upto = [Math]::Min($hi, $after + $size)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            [void](& $Invoke $sql @{ CollectionId = $CollectionId; After = $after; Upto = $upto } 'scalar')
            $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
            $after = $upto; $ranges++
            $size = Get-SIDataNextSize -Current $size -ElapsedMs $sw.ElapsedMilliseconds -TargetMs $TargetMs -Minimum 500
            if ($Log -and ($all.Elapsed.TotalSeconds - $saidAt) -ge 60) {
                $saidAt = $all.Elapsed.TotalSeconds
                $pct = [int][Math]::Floor(100.0 * [double]($after - $lo + 1) / [double]([Math]::Max(1L, $hi - $lo + 1)))
                & $Log 'INFO' ("facets      : the facet counts of the collection are being built -- {0} % of its findings so far" -f $pct)
            }
        }
        if ($BatchSize) { $BatchSize.Value = $size }
    }
    $n = [int](& $Invoke (Get-SIDataFacetFinishSql -Counted:$Counted) @{ CollectionId = $CollectionId } 'scalar')
    $del = [long]0
    [void](Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataFacetStageClearSql) -Params @{ CollectionId = $CollectionId; Counted = $cv } -BatchSize ([ref]$del))
    $n
}

# ------------------------------------------------------------------------------------------------------------------
#  THE SERVICES VIEW (#255): which CMDB service(s) each CI belongs to -- ONE resolver -- and the risk per service
# ------------------------------------------------------------------------------------------------------------------
#
#  THE RESOLVER CONTRACT. "Which service(s) does a CI belong to" is answered in ONE place: the ordered list of
#  membership sources returned by Get-SIDataServiceSources. Each source is @{ Name; Sql }:
#    Name  1-32 of [A-Za-z0-9._-]; stamped on every membership it contributes (ServiceMember.Source)
#    Sql   ONE read-only SELECT (no ';', no write or DDL verb) returning the columns AssetKey (the sidata CI key),
#          ServiceKey (the service's stable id -- its CMDB number), ServiceName (display name, may be NULL), for the
#          collection @CollectionId (the only parameter). It may read sidata.* and cfg.* (an SI-homed CMDB).
#  A CI may belong to several services (one row per service). The same (service, CI) from two sources is kept once,
#  stamped with the EARLIER source in the list. Only CIs with findings in the collection are kept.
#  A new source (the SI-homed CMDB, an external CSV / ServiceNow CMDB) plugs in with Register-SIDataServiceSource;
#  -Replace makes the registered sources the whole list (e.g. an SI-homed CMDB that is authoritative).
#  Get-SIDataServicesSql turns the list into ServiceMember (the resolver's output) and the two aggregates.
#  A membership change after a collection was derived is picked up by setting its ServicesDerivedAt to NULL (the next
#  data sync re-derives it); a collection's membership is otherwise frozen as it was when it was derived.

$script:SIDataServiceSourcesRegistered = @()
$script:SIDataServiceSourcesReplace = $false

function Get-SIDataServiceSourceDefault {
    <# The first source: the CMDB service Risk Analysis carried on the CI's finding rows (cmdbId, else cmdbName). #>
    @{ Name = 'risk-analysis'; Sql = @'
SELECT f.AssetKey, COALESCE(f.CmdbId, f.CmdbName) AS ServiceKey, MAX(COALESCE(f.CmdbName, f.CmdbId)) AS ServiceName
FROM sidata.Finding AS f
WHERE f.CollectionId = @CollectionId AND f.AssetKey IS NOT NULL AND COALESCE(f.CmdbId, f.CmdbName) IS NOT NULL
GROUP BY f.AssetKey, COALESCE(f.CmdbId, f.CmdbName)
'@ }
}

function Test-SIDataServiceSource {
    <# Throws when a source does not keep the contract. #>
    param([Parameter(Mandatory)]$Source)
    $n = [string]$Source.Name; $q = [string]$Source.Sql
    if ($n -notmatch '^[A-Za-z0-9._-]{1,32}$') { throw ("service source '{0}': the name must be 1-32 of letters, digits, '.', '_' or '-'." -f $n) }
    if ($q -notmatch '^\s*SELECT\s') { throw ("service source '{0}': the statement must be ONE SELECT." -f $n) }
    if ($q.Contains(';')) { throw ("service source '{0}': the statement must be ONE SELECT (no ';')." -f $n) }
    if ($q -match '(?i)\b(INSERT|UPDATE|DELETE|MERGE|DROP|ALTER|TRUNCATE|CREATE|EXEC|EXECUTE|GRANT|INTO)\b') { throw ("service source '{0}': the statement must be read-only." -f $n) }
    foreach ($c in 'AssetKey', 'ServiceKey', 'ServiceName') { if ($q -notmatch "\b$c\b") { throw ("service source '{0}': the statement must return {1}." -f $n, $c) } }
    foreach ($m in [regex]::Matches($q, '@(\w+)')) { if ($m.Groups[1].Value -ne 'CollectionId') { throw ("service source '{0}': @CollectionId is the only parameter (found @{1})." -f $n, $m.Groups[1].Value) } }
}

function Register-SIDataServiceSource {
    <# Adds a membership source after the ones already in the list; -Replace: the registered sources become the whole list. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Sql, [switch]$Replace)
    $src = @{ Name = $Name; Sql = $Sql }
    Test-SIDataServiceSource -Source $src
    $script:SIDataServiceSourcesRegistered = @(@($script:SIDataServiceSourcesRegistered | Where-Object { $_.Name -ne $Name }) + $src)
    if ($Replace) { $script:SIDataServiceSourcesReplace = $true }
}

function Reset-SIDataServiceSources {
    <# Back to the default list (the Risk Analysis source only). #>
    $script:SIDataServiceSourcesRegistered = @()
    $script:SIDataServiceSourcesReplace = $false
}

function Get-SIDataServiceSources {
    <# THE resolver's source list, in precedence order. #>
    $list = @()
    if (-not $script:SIDataServiceSourcesReplace) { $list += (Get-SIDataServiceSourceDefault) }
    $list += @($script:SIDataServiceSourcesRegistered)
    foreach ($s in $list) { Test-SIDataServiceSource -Source $s }
    , @($list)
}

# ---- THE CMDB AS A SERVICE SOURCE (#256) ---------------------------------------------------------------------------
#  The Pro database's own CMDB (sql\si-pro-settings.sql: cfg.CmdbService / cfg.CmdbServiceAsset, SI-homed or filled
#  from an external CSV / ServiceNow) plugs into the resolver above as ONE source, through cfg.vCmdbAssetService -- the
#  memberships of the AUTHORITATIVE CMDB only. When it is configured it REPLACES the list (an authoritative CMDB is the
#  answer, not one more opinion); when it is not, the Risk Analysis source (cmdbId / cmdbName from CMDB.csv via the
#  Reconcile stage) stays the fallback. "Configured" = an external source is chosen, or the SI-homed CMDB holds at
#  least one service in force.

$script:SIDataCmdbSourceUsed = $false

function Get-SIDataCmdbStateSql {
    <# Whether the CMDB tables exist, the authoritative source and how many of its services are in force. #>
    @'
IF OBJECT_ID(N'cfg.vCmdbAssetService') IS NULL OR OBJECT_ID(N'cfg.vCmdbSource') IS NULL OR OBJECT_ID(N'cfg.vCmdbService') IS NULL
    SELECT 0 AS HasCmdb, N'SI' AS ActiveSource, 0 AS Services
ELSE
    SELECT 1 AS HasCmdb, (SELECT ActiveSource FROM cfg.vCmdbSource) AS ActiveSource, (SELECT COUNT(*) FROM cfg.vCmdbService) AS Services
'@
}

function Get-SIDataCmdbServiceSourceName {
    <# The name stamped on the memberships the CMDB contributes (sidata.ServiceMember.Source). #>
    param([string]$ActiveSource)
    switch ($ActiveSource) { 'External-CSV' { 'cmdb-csv' } 'External-Connector' { 'cmdb-servicenow' } default { 'cmdb-si' } }
}

function Get-SIDataCmdbServiceSourceSql {
    <# The CMDB's memberships of the CIs with findings in the collection: ServiceKey = the service number. #>
    @'
SELECT v.AssetKey, v.ServiceNumber AS ServiceKey, v.ServiceName AS ServiceName
FROM cfg.vCmdbAssetService AS v
WHERE v.AssetKey IN (SELECT f.AssetKey FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId)
'@
}

function Get-SIDataCmdbRuleSourceSql {
    <#
        The CMDB's services the PROFILE RULES gave a CI (a rule's set.cmdbId, stamped on the findings by Risk Analysis): the
        v2.2 way an asset belongs to a service, and how a migrated CMDB.csv (which has no links) keeps its members. Only a
        service of the AUTHORITATIVE CMDB counts, under its service number: a migrated service answers to its v2.2 cmdbID
        (ExternalId), every other one to its number -- the key Read-SICmdbProServices hands the profilers.
    #>
    @'
SELECT f.AssetKey, v.ServiceNumber AS ServiceKey, MAX(v.Name) AS ServiceName
FROM sidata.Finding AS f
JOIN cfg.vCmdbService AS v ON f.CmdbId = (CASE WHEN v.Source = N'SI' AND NULLIF(v.ExternalId, N'') IS NOT NULL THEN v.ExternalId ELSE v.ServiceNumber END)
WHERE f.CollectionId = @CollectionId AND f.AssetKey IS NOT NULL AND NULLIF(f.CmdbId, N'') IS NOT NULL
GROUP BY f.AssetKey, v.ServiceNumber
'@
}

function Use-SIDataCmdbServiceSource {
    <#
        Reads the CMDB's state and, when it is configured, makes it THE service source (Register-SIDataServiceSource
        -Replace). Returns @{ HasCmdb; ActiveSource; Services; Used; Name }. A database without the CMDB tables keeps the
        default list.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    if ($script:SIDataCmdbSourceUsed) { Reset-SIDataServiceSources; $script:SIDataCmdbSourceUsed = $false }
    $raw = & $Invoke (Get-SIDataCmdbStateSql) @{} 'reader'
    $row = @($raw) | Where-Object { $_ } | Select-Object -First 1
    $st = [ordered]@{ HasCmdb = $false; ActiveSource = 'SI'; Services = 0; Used = $false; Name = $null }
    if ($row) {
        $st.HasCmdb = ([int]$row['HasCmdb'] -eq 1); $st.ActiveSource = [string]$row['ActiveSource']; $st.Services = [int]$row['Services']
    }
    if ($st.HasCmdb -and ($st.ActiveSource -ne 'SI' -or $st.Services -gt 0)) {
        $st.Name = Get-SIDataCmdbServiceSourceName -ActiveSource $st.ActiveSource
        Register-SIDataServiceSource -Name $st.Name -Sql (Get-SIDataCmdbServiceSourceSql) -Replace
        # after the links: the services the profile rules gave a CI, mapped onto the same CMDB (a link wins on a tie)
        Register-SIDataServiceSource -Name ($st.Name + '-rule') -Sql (Get-SIDataCmdbRuleSourceSql)
        $script:SIDataCmdbSourceUsed = $true
        $st.Used = $true
    }
    [pscustomobject]$st
}

function Get-SIDataFixSchemaCheckSql {
    <# 1 when the database carries the finding's fix columns (si-data-schema.sql, #590), else 0. #>
    "SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'FixRemediation') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'FixRecommendedUpdate') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'FixRecommendedUpdateId') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'AffectedSoftware') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataServicesSchemaCheckSql {
    <# 1 when the database carries the Services view's columns and tables (si-data-schema.sql, #255), else 0. #>
    "SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'CmdbId') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'ServicesDerivedAt') IS NOT NULL AND OBJECT_ID('sidata.ServiceMember') IS NOT NULL AND OBJECT_ID('sidata.ServiceAsset') IS NOT NULL AND OBJECT_ID('sidata.ServiceRisk') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataServicesSql {
    <#
        ONE collection: the resolver's membership (every source, in order), the per-(service, CI) and per-service
        aggregates, replacing what the collection held, and ServicesDerivedAt -- one transaction. Returns the number of
        service rows (the no-service row included). Severity: Critical = critical / very high, Medium = medium-high / medium /
        moderate; informational and unknown severities count in Findings only.
        -Counted (#264): the same aggregates over the findings WITHOUT an exemption mark, into sidata.ServiceAssetCounted /
        ServiceRiskCounted. Membership is NOT resolved again: the collection's sidata.ServiceMember (the resolver's output)
        is reused, so a service holds the same CIs in both variants (minus a CI whose every finding is exempted).
    #>
    param([object[]]$Sources = (Get-SIDataServiceSources), [switch]$Counted)
    $ins = New-Object System.Collections.Generic.List[string]
    $i = 0
    if ($Counted) {
        $ins.Add("INSERT #m (AssetKey, ServiceKey, ServiceName, Source, Prio)`r`nSELECT sm.AssetKey, sm.ServiceKey, sm.ServiceName, sm.Source, 1 FROM sidata.ServiceMember AS sm WHERE sm.CollectionId = @CollectionId;")
    }
    else {
        foreach ($s in @($Sources)) {
            Test-SIDataServiceSource -Source $s
            $i++
            $ins.Add(("INSERT #m (AssetKey, ServiceKey, ServiceName, Source, Prio)`r`nSELECT LEFT(src.AssetKey, 400), LEFT(LTRIM(RTRIM(src.ServiceKey)), 256), LEFT(src.ServiceName, 400), N'{0}', {1}`r`nFROM (`r`n{2}`r`n) AS src`r`nWHERE src.AssetKey IS NOT NULL AND NULLIF(LTRIM(RTRIM(src.ServiceKey)), N'') IS NOT NULL;" -f $s.Name, $i, ([string]$s.Sql).Trim()))
        }
    }
    $risk = 'ServiceRisk'; $asset = 'ServiceAsset'; $mark = ''
    $member = "DELETE FROM sidata.ServiceMember WHERE CollectionId = @CollectionId;`r`nINSERT sidata.ServiceMember (CollectionId, ServiceKey, AssetKey, ServiceName, Source)`r`nSELECT @CollectionId, ServiceKey, AssetKey, ServiceName, Source FROM #mem;"
    $stamp = "UPDATE sidata.Collection SET ServicesDerivedAt = SYSUTCDATETIME() WHERE CollectionId = @CollectionId;"
    if ($Counted) { $risk = 'ServiceRiskCounted'; $asset = 'ServiceAssetCounted'; $mark = ' AND f.ExemptionId IS NULL'; $member = ''; $stamp = '' }
    # the web app's one severity order (SeverityOrder.cs): case, spaces, '-' and '_' do not matter; Medium-High counts as Medium
    $k = "LOWER(REPLACE(REPLACE(REPLACE(f.Severity, N' ', N''), N'-', N''), N'_', N''))"
    $sev = @{
        C = "CASE WHEN $k IN (N'critical', N'veryhigh') THEN 1 ELSE 0 END"
        H = "CASE WHEN $k = N'high' THEN 1 ELSE 0 END"
        M = "CASE WHEN $k IN (N'mediumhigh', N'medium', N'moderate') THEN 1 ELSE 0 END"
        L = "CASE WHEN $k = N'low' THEN 1 ELSE 0 END"
    }
    (@'
SET XACT_ABORT ON;
CREATE TABLE #m (AssetKey nvarchar(400) NOT NULL, ServiceKey nvarchar(256) NOT NULL, ServiceName nvarchar(400) NULL, Source nvarchar(32) NOT NULL, Prio int NOT NULL);
{SOURCES}
CREATE TABLE #a (AssetKey nvarchar(400) NOT NULL PRIMARY KEY, AssetName nvarchar(400) NULL, Tier tinyint NULL, Findings int NOT NULL,
                 Critical int NOT NULL, High int NOT NULL, Medium int NOT NULL, Low int NOT NULL,
                 T0 int NOT NULL, T1 int NOT NULL, T2 int NOT NULL, T3 int NOT NULL, TU int NOT NULL,
                 WeightedTotal float NULL, RiskTotal float NULL, MaxWeighted float NULL);
INSERT #a
SELECT f.AssetKey, MAX(f.AssetName), MIN(f.Tier), COUNT(*),
       SUM({C}), SUM({H}), SUM({M}), SUM({L}),
       SUM(CASE WHEN f.Tier = 0 THEN 1 ELSE 0 END), SUM(CASE WHEN f.Tier = 1 THEN 1 ELSE 0 END), SUM(CASE WHEN f.Tier = 2 THEN 1 ELSE 0 END),
       SUM(CASE WHEN f.Tier = 3 THEN 1 ELSE 0 END), SUM(CASE WHEN f.Tier IS NULL OR f.Tier > 3 THEN 1 ELSE 0 END),
       SUM(f.RiskScoreWeighted), SUM(f.RiskScore), MAX(f.RiskScoreWeighted)
FROM sidata.Finding AS f
WHERE f.CollectionId = @CollectionId AND f.AssetKey IS NOT NULL{MARK}
GROUP BY f.AssetKey;
CREATE TABLE #mem (ServiceKey nvarchar(256) NOT NULL, AssetKey nvarchar(400) NOT NULL, ServiceName nvarchar(400) NULL, Source nvarchar(32) NOT NULL);
INSERT #mem (ServiceKey, AssetKey, ServiceName, Source)
SELECT x.ServiceKey, x.AssetKey, x.ServiceName, x.Source
FROM (SELECT m.ServiceKey, m.AssetKey, m.ServiceName, m.Source,
             ROW_NUMBER() OVER (PARTITION BY m.ServiceKey, m.AssetKey ORDER BY m.Prio, m.ServiceName) AS Rn
      FROM #m AS m) AS x
JOIN #a AS a ON a.AssetKey = x.AssetKey
WHERE x.Rn = 1;
CREATE TABLE #sa (ServiceKey nvarchar(256) NOT NULL, AssetKey nvarchar(400) NOT NULL, ServiceName nvarchar(400) NULL, Source nvarchar(32) NULL,
                  ServiceCount int NOT NULL);
WITH cnt AS (SELECT AssetKey, COUNT(*) AS N FROM #mem GROUP BY AssetKey)
INSERT #sa (ServiceKey, AssetKey, ServiceName, Source, ServiceCount)
SELECT m.ServiceKey, m.AssetKey, m.ServiceName, m.Source, cnt.N
FROM #mem AS m JOIN cnt ON cnt.AssetKey = m.AssetKey;
INSERT #sa (ServiceKey, AssetKey, ServiceName, Source, ServiceCount)
SELECT N'', a.AssetKey, NULL, NULL, 0
FROM #a AS a LEFT JOIN #mem AS m ON m.AssetKey = a.AssetKey
WHERE m.AssetKey IS NULL;
-- the service's display name: the one most of its members carry
WITH nm AS (
    SELECT ServiceKey, ServiceName, ROW_NUMBER() OVER (PARTITION BY ServiceKey ORDER BY COUNT(*) DESC, ServiceName) AS Rn
    FROM #sa WHERE ServiceName IS NOT NULL GROUP BY ServiceKey, ServiceName
), top1 AS (
    SELECT s.ServiceKey, s.AssetKey, a.AssetName, a.WeightedTotal,
           ROW_NUMBER() OVER (PARTITION BY s.ServiceKey ORDER BY CASE WHEN a.WeightedTotal IS NULL THEN 1 ELSE 0 END, a.WeightedTotal DESC, s.AssetKey) AS Rn
    FROM #sa AS s JOIN #a AS a ON a.AssetKey = s.AssetKey
), src AS (
    SELECT d.ServiceKey, STRING_AGG(CONVERT(nvarchar(200), d.Source), N', ') WITHIN GROUP (ORDER BY d.Source) AS Sources
    FROM (SELECT DISTINCT ServiceKey, Source FROM #sa WHERE Source IS NOT NULL) AS d
    GROUP BY d.ServiceKey
), agg AS (
    SELECT s.ServiceKey, COUNT(*) AS Assets, SUM(CASE WHEN s.ServiceCount > 1 THEN 1 ELSE 0 END) AS SharedAssets, SUM(a.Findings) AS Findings,
           SUM(a.WeightedTotal) AS WeightedTotal, SUM(a.WeightedTotal) / COUNT(*) AS WeightedPerAsset, SUM(a.RiskTotal) AS RiskTotal, MAX(a.MaxWeighted) AS MaxWeighted,
           SUM(a.Critical) AS Critical, SUM(a.High) AS High, SUM(a.Medium) AS Medium, SUM(a.Low) AS Low,
           SUM(a.T0) AS Tier0, SUM(a.T1) AS Tier1, SUM(a.T2) AS Tier2, SUM(a.T3) AS Tier3, SUM(a.TU) AS TierUnclassified
    FROM #sa AS s JOIN #a AS a ON a.AssetKey = s.AssetKey
    GROUP BY s.ServiceKey
)
SELECT agg.*, nm.ServiceName, top1.AssetKey AS TopAssetKey, top1.AssetName AS TopAssetName, top1.WeightedTotal AS TopAssetWeighted, src.Sources
INTO #sr
FROM agg
LEFT JOIN nm ON nm.ServiceKey = agg.ServiceKey AND nm.Rn = 1
LEFT JOIN top1 ON top1.ServiceKey = agg.ServiceKey AND top1.Rn = 1
LEFT JOIN src ON src.ServiceKey = agg.ServiceKey;
BEGIN TRAN;
DELETE FROM sidata.{RISK} WHERE CollectionId = @CollectionId;
DELETE FROM sidata.{ASSET} WHERE CollectionId = @CollectionId;
{MEMBER}
INSERT sidata.{ASSET} (CollectionId, ServiceKey, AssetKey, ServiceName, Source, AssetName, Tier, ServiceCount, Findings, Critical, High, Medium, Low, WeightedTotal, RiskTotal, MaxWeighted)
SELECT @CollectionId, s.ServiceKey, s.AssetKey, s.ServiceName, s.Source, a.AssetName, a.Tier, s.ServiceCount, a.Findings, a.Critical, a.High, a.Medium, a.Low, a.WeightedTotal, a.RiskTotal, a.MaxWeighted
FROM #sa AS s JOIN #a AS a ON a.AssetKey = s.AssetKey;
INSERT sidata.{RISK} (CollectionId, ServiceKey, ServiceName, Assets, SharedAssets, Findings, WeightedTotal, WeightedPerAsset, RiskTotal, MaxWeighted,
                           Critical, High, Medium, Low, Tier0, Tier1, Tier2, Tier3, TierUnclassified, TopAssetKey, TopAssetName, TopAssetWeighted, Sources)
SELECT @CollectionId, ServiceKey, ServiceName, Assets, SharedAssets, Findings, WeightedTotal, WeightedPerAsset, RiskTotal, MaxWeighted,
       Critical, High, Medium, Low, Tier0, Tier1, Tier2, Tier3, TierUnclassified, TopAssetKey, TopAssetName, TopAssetWeighted, Sources
FROM #sr;
DECLARE @n int = @@ROWCOUNT;
{STAMP}
COMMIT;
SELECT @n;
'@).Replace('{RISK}', $risk).Replace('{ASSET}', $asset).Replace('{MEMBER}', $member).Replace('{STAMP}', $stamp).Replace('{MARK}', $mark).Replace('{SOURCES}', ($ins -join "`r`n")).Replace('{C}', $sev.C).Replace('{H}', $sev.H).Replace('{M}', $sev.M).Replace('{L}', $sev.L)
}

function Invoke-SIDataFindingRanges {
    <#
        One statement (-Sql: @CollectionId, @After, @Upto; answers its row count) over ONE collection's FindingId range
        -Lo..-Hi, in ranges sized from their measured time and paced by the database's own load (SI-SqlPacing.ps1); every
        range is still run. Returns the rows the statement counted. The derive and the row values' fill run the same loop.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$CollectionId, [long]$Lo, [long]$Hi,
          [Parameter(Mandatory)][string]$Sql, [ref]$BatchSize, [long]$TargetMs = 5000)
    $done = 0L
    $size = [long]20000; if ($BatchSize -and $BatchSize.Value -gt 0) { $size = [long]$BatchSize.Value }
    $after = $Lo - 1
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
    while ($after -lt $Hi) {
        if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs; if ($pace.Shrink) { $size = [Math]::Max(500L, [long][Math]::Floor($size / 2)) } }
        $upto = [Math]::Min($Hi, $after + $size)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $done += [long](& $Invoke $Sql @{ CollectionId = $CollectionId; After = $after; Upto = $upto } 'scalar')
        $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
        $after = $upto
        $size = Get-SIDataNextSize -Current $size -ElapsedMs $sw.ElapsedMilliseconds -TargetMs $TargetMs -Minimum 500
    }
    if ($BatchSize) { $BatchSize.Value = $size }
    $done
}

function Invoke-SIDataRowColumnsFill {
    <#
        2026-10-25 (internal, run 0e6bef53: "set-based not used: the collection carries no typed row values"): the row values
        of ONE Risk Analysis Detailed collection, BEFORE the data sync derives it -- the vulnerability step runs first and reads
        them typed. Only a collection Risk Analysis has completed (RaCompletedAt or Complete), not retired, whose RaRowsAt is
        still empty; the same expressions and rows as the derive (Get-SIDataRowColumnsSql), so the data sync then writes them
        once, not again. RaRowsAt is stamped only after the last range. NEVER THROWS: @{ Filled; Rows; Seconds; Why } --
        Filled = $false with the reason, and the reader reads the collection from DetailJson as before.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$CollectionId, [long]$TargetMs = 5000)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $out = { param([bool]$f, [long]$n, [string]$w) [pscustomobject]@{ Filled = $f; Rows = $n; Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2); Why = $w } }
    try {
        $ready = [string](& $Invoke "SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'RaFillRiskFactorConsequence') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'RaRowsAt') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'RaCompletedAt') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'RetiredAt') IS NOT NULL THEN 1 ELSE 0 END" @{} 'scalar')
        if ($ready -ne '1') { return (& $out $false 0 'the database does not have the row value columns yet (the updater adds them)') }
        # scalars only: every seam that runs the derive answers 'scalar' (the vulnerability step's seam has no 'reader')
        $st = [string](& $Invoke "SELECT ISNULL((SELECT CASE WHEN RaRowsAt IS NOT NULL THEN N'done' WHEN RetiredAt IS NULL AND (Status = N'Complete' OR RaCompletedAt IS NOT NULL) THEN N'ok' ELSE N'not' END FROM sidata.Collection WHERE CollectionId = CONVERT(int, @CollectionId)), N'none')" @{ CollectionId = $CollectionId } 'scalar')
        if ($st -eq 'none') { return (& $out $false 0 'the collection is not in the database') }
        if ($st -eq 'done') { return (& $out $true 0 'already filled') }
        if ($st -ne 'ok') { return (& $out $false 0 'the collection is not complete, or retired') }
        $lo = & $Invoke "SELECT MIN(FindingId) FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId)" @{ CollectionId = $CollectionId } 'scalar'
        $hi = & $Invoke "SELECT MAX(FindingId) FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId)" @{ CollectionId = $CollectionId } 'scalar'
        $n = 0L
        if ($null -ne $lo -and -not ($lo -is [System.DBNull])) {
            $n = Invoke-SIDataFindingRanges -Invoke $Invoke -CollectionId $CollectionId -Lo ([long]$lo) -Hi ([long]$hi) -Sql (Get-SIDataRowColumnsSql) -TargetMs $TargetMs
        }
        $null = & $Invoke 'UPDATE sidata.Collection SET RaRowsAt = SYSUTCDATETIME() WHERE CollectionId = @CollectionId AND RaRowsAt IS NULL; SELECT 1;' @{ CollectionId = $CollectionId } 'scalar'
        & $out $true $n ''
    } catch { & $out $false 0 ('the row values could not be filled: ' + $_.Exception.Message) }
}

function Invoke-SIDataDeriveCollection {
    <#
        Fills the views' columns of ONE collection in FindingId ranges sized from their measured time, then its
        aggregates and DerivedAt. -Services (#255): also the CMDB columns, then the service membership and its aggregates.
        Returns @{ CollectionId; Findings; Facets; Services } (Services = $null without -Services).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$CollectionId, [ref]$BatchSize, [long]$TargetMs = 5000, [switch]$Services,
          # #590 also the finding's fix columns (the database carries them: Get-SIDataFixSchemaCheckSql)
          [switch]$Fix,
          # the facets' progress lines (Invoke-SIDataFacet)
          [scriptblock]$Log)
    $bRaw = & $Invoke (Get-SIDataFindingBoundsSql) @{ CollectionId = $CollectionId } 'reader'
    $b = @($bRaw) | Select-Object -First 1
    $done = 0L
    # #834 the Risk Analysis row's Category travels with the derive when the database has its column (the updater adds it)
    $cat = $false
    try { $cat = ([string](& $Invoke "SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'RaCategory') IS NOT NULL THEN 1 ELSE 0 END" @{} 'scalar') -eq '1') } catch { $cat = $false }
    # #830 / #834 the row values the readers read on every finding, when the database has their columns (the updater adds them)
    $rowCols = $false
    try { $rowCols = ([string](& $Invoke "SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'RaFillRiskFactorConsequence') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'RaRowsAt') IS NOT NULL THEN 1 ELSE 0 END" @{} 'scalar') -eq '1') } catch { $rowCols = $false }
    # 2026-10-25 the vulnerability step (before the data sync) already filled this collection's row values with the same
    # expressions (Invoke-SIDataRowColumnsFill, RaRowsAt set): written once, not again -- only rows carried in since get them
    $rowsDone = $false; $carriedCol = $false
    if ($rowCols) {
        try { $rowsDone = ([string](& $Invoke "SELECT CASE WHEN EXISTS (SELECT 1 FROM sidata.Collection WHERE CollectionId = @CollectionId AND RaRowsAt IS NOT NULL) THEN 1 ELSE 0 END" @{ CollectionId = $CollectionId } 'scalar') -eq '1') } catch { $rowsDone = $false }
        try { $carriedCol = ([string](& $Invoke "SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'CarriedFrom') IS NOT NULL THEN 1 ELSE 0 END" @{} 'scalar') -eq '1') } catch { $carriedCol = $false }
    }
    $sql = if ($rowsDone) { Get-SIDataDeriveFindingSql -Services:$Services -Fix:$Fix -Category:$cat -CarriedRowColumns:$carriedCol }
           else { Get-SIDataDeriveFindingSql -Services:$Services -Fix:$Fix -Category:$cat -RowColumns:$rowCols }
    if ($b -and $null -ne $b['Lo'] -and -not ($b['Lo'] -is [System.DBNull])) {
        $rg = @{ Invoke = $Invoke; CollectionId = $CollectionId; Lo = [long]$b['Lo']; Hi = [long]$b['Hi']; Sql = $sql; TargetMs = $TargetMs }
        if ($BatchSize) { $rg.BatchSize = $BatchSize }
        $done = Invoke-SIDataFindingRanges @rg
    }
    # #830 / #834 every range carried the row values: the readers read this collection from its typed columns from now on
    if ($rowCols -and -not $rowsDone) { $null = & $Invoke 'UPDATE sidata.Collection SET RaRowsAt = SYSUTCDATETIME() WHERE CollectionId = @CollectionId; SELECT 1;' @{ CollectionId = $CollectionId } 'scalar' }
    # the facet aggregate in FindingId ranges (a large collection's one statement ran past the SQL limit)
    $fsz = [long]0
    $facets = Invoke-SIDataFacet -Invoke $Invoke -CollectionId $CollectionId -FixColumn:$Fix -BatchSize ([ref]$fsz) -TargetMs $TargetMs -Log $Log
    $svc = $null
    if ($Services) { $svc = [int](& $Invoke (Get-SIDataServicesSql) @{ CollectionId = $CollectionId } 'scalar') }
    [pscustomobject]@{ CollectionId = $CollectionId; Findings = $done; Facets = $facets; Services = $svc }
}

# ------------------------------------------------------------------------------------------------------------------
#  EXEMPTED FINDINGS (#264): the counted twins of every pre-computed aggregate
# ------------------------------------------------------------------------------------------------------------------
#  An exemption never removes a finding: Risk Analysis marks it and the load copies the mark (sidata.Finding.ExemptionId).
#  Each aggregate the pages read exists twice -- the table over EVERY finding and its "...Counted" twin over the findings
#  without a mark -- so a page answers "exempted counted" and "not counted" from a pre-computed table, never from a live
#  GROUP BY over finding rows. CHOICE (measured, see docs\DESIGN.md "Exempted findings"): aggregate both variants at sync
#  time rather than subtract at read time -- the distinct counts (assets per group, CIs per service) and the highest scores
#  cannot be subtracted, and the twin costs one more pass over ONE collection per load.

function Get-SIDataExemptedSchemaCheckSql {
    <# 1 when the database carries the mark columns and every counted twin (si-data-schema.sql, #264), else 0. #>
    "SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'ExemptionId') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'ExemptedDerivedAt') IS NOT NULL AND OBJECT_ID('sidata.FindingDailyCounted') IS NOT NULL AND OBJECT_ID('sidata.FindingFacetCounted') IS NOT NULL AND OBJECT_ID('sidata.DepartmentFacetCounted') IS NOT NULL AND OBJECT_ID('sidata.ServiceRiskCounted') IS NOT NULL AND OBJECT_ID('sidata.ServiceAssetCounted') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataUnexemptedSql {
    <#
        Complete collections whose counted twins are not computed yet (new loads, and once every earlier one) or are STALE: a
        base aggregate (DerivedAt, ServicesDerivedAt, ResolvedAt) was recomputed after them. Newest first. The base steps
        never touch the twins: the timestamps they already stamp are what makes a twin stale.
    #>
    "SELECT CollectionId, CollectionTime, CASE WHEN DerivedAt IS NULL THEN 0 ELSE 1 END AS Derived, CASE WHEN ResolvedVersion IS NULL THEN 0 ELSE 1 END AS Resolved, CASE WHEN ServicesDerivedAt IS NULL THEN 0 ELSE 1 END AS ServicesDerived FROM sidata.Collection WHERE Status = 'Complete' AND Kind = 'Detailed' AND (ExemptedDerivedAt IS NULL OR ExemptedDerivedAt < DerivedAt OR ExemptedDerivedAt < ServicesDerivedAt OR ExemptedDerivedAt < ResolvedAt)$(Get-SIDataLiveFilter) ORDER BY CollectionTime DESC"
}

function Get-SIDataExemptedStampSql {
    "UPDATE sidata.Collection SET ExemptedDerivedAt = SYSUTCDATETIME() WHERE CollectionId = @CollectionId; SELECT @@ROWCOUNT;"
}

function Invoke-SIDataExemptedVariants {
    <#
        ONE collection's counted twins: the day's FindingDailyCounted (the day's latest collection, as the base table), its
        FindingFacetCounted (when its views' data is derived), DepartmentFacetCounted (when its departments are resolved,
        -Departments) and ServiceRiskCounted / ServiceAssetCounted (when its services are derived, -Services) -- then
        ExemptedDerivedAt. A twin whose base is not computed yet (no departments resolved, no services derived) is skipped:
        its base is empty for the collection too, and computing the base later stamps a time newer than ExemptedDerivedAt,
        so the twin follows on the next sync. A collection whose views' data is not derived yet stays pending.
        Returns @{ CollectionId; Daily; Facets; Departments; Services; Stamped }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$Collection, [switch]$Services, [switch]$Departments, [scriptblock]$Log)
    $cid = [int]$Collection.CollectionId
    $t = ConvertTo-SIDataUtc $Collection.CollectionTime
    $out = [ordered]@{ CollectionId = $cid; Daily = $null; Facets = $null; Departments = $null; Services = $null; Stamped = $false }
    $out.Daily = [int](& $Invoke (Get-SIDataFindingDailySql -Counted) @{ Day = $t.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } 'scalar')
    if ([int]$Collection.Derived -ne 1) { return [pscustomobject]$out }
    $fsz = [long]0
    $out.Facets = Invoke-SIDataFacet -Invoke $Invoke -CollectionId $cid -Counted -BatchSize ([ref]$fsz) -Log $Log
    if ($Departments -and [int]$Collection.Resolved -eq 1) { $out.Departments = [int](& $Invoke (Get-SIDataDepartmentFacetSql -Counted) @{ CollectionId = $cid } 'scalar') }
    if ($Services -and [int]$Collection.ServicesDerived -eq 1) { $out.Services = [int](& $Invoke (Get-SIDataServicesSql -Counted) @{ CollectionId = $cid } 'scalar') }
    $out.Stamped = ([int](& $Invoke (Get-SIDataExemptedStampSql) @{ CollectionId = $cid } 'scalar')) -eq 1
    [pscustomobject]$out
}

function Get-SIDataPurgeTargetsSql {
    <# Collections past retention, and loads that died outside the look-back window (they would never be retried). #>
    @'
SET NOCOUNT ON;
-- ONE TRUSTED RUN: the collection the web app shows (sidata.PublishedRun) is never purged, however old it is
DECLARE @pub int = NULL;
IF OBJECT_ID('sidata.PublishedRun') IS NOT NULL
    EXEC sp_executesql N'SELECT @p = DetailedCollectionId FROM sidata.PublishedRun WHERE Name = N''current''', N'@p int OUTPUT', @p = @pub OUTPUT;
SELECT CollectionId, CollectionTime, Status FROM sidata.Collection
WHERE (CollectionTime < CONVERT(datetime2(3), @Cutoff, 126)
   OR (Status = 'Loading' AND CollectionTime < CONVERT(datetime2(3), @StaleLoading, 126)))
  AND CollectionId <> ISNULL(@pub, -1)
ORDER BY CollectionTime ASC
'@
}

function Get-SIDataPurgeBatchSql {
    <# One batch of one collection's child rows. -Table: Finding | Recommendation. The table name is from an allow-list, never input. #>
    param([Parameter(Mandatory)][ValidateSet('Finding', 'Recommendation')][string]$Table)
    "DELETE TOP (@Batch) FROM sidata.$Table WHERE CollectionId = @CollectionId; SELECT @@ROWCOUNT;"
}

function Get-SIDataPurgeCollectionSql {
    @'
SET XACT_ABORT ON;
BEGIN TRAN;
DELETE FROM sidata.FindingDaily WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.FindingDailyCounted') IS NOT NULL DELETE FROM sidata.FindingDailyCounted WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.AssetDaily') IS NOT NULL DELETE FROM sidata.AssetDaily WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.AssetDailyCounted') IS NOT NULL DELETE FROM sidata.AssetDailyCounted WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.FindingFacetCounted') IS NOT NULL DELETE FROM sidata.FindingFacetCounted WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.DepartmentFacetCounted') IS NOT NULL DELETE FROM sidata.DepartmentFacetCounted WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.ServiceRiskCounted') IS NOT NULL DELETE FROM sidata.ServiceRiskCounted WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.ServiceAssetCounted') IS NOT NULL DELETE FROM sidata.ServiceAssetCounted WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.FindingFacet') IS NOT NULL DELETE FROM sidata.FindingFacet WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.DepartmentFacet') IS NOT NULL DELETE FROM sidata.DepartmentFacet WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.ServiceRisk') IS NOT NULL DELETE FROM sidata.ServiceRisk WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.ServiceAsset') IS NOT NULL DELETE FROM sidata.ServiceAsset WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.ServiceMember') IS NOT NULL DELETE FROM sidata.ServiceMember WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.AssetCorrelation') IS NOT NULL DELETE FROM sidata.AssetCorrelation WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.CollectionPartial') IS NOT NULL DELETE FROM sidata.CollectionPartial WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.IssueContext') IS NOT NULL DELETE FROM sidata.IssueContext WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.CveSummary') IS NOT NULL DELETE FROM sidata.CveSummary WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.CveSummaryCounted') IS NOT NULL DELETE FROM sidata.CveSummaryCounted WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.CveSummaryState') IS NOT NULL DELETE FROM sidata.CveSummaryState WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.AssetRiskSummary') IS NOT NULL DELETE FROM sidata.AssetRiskSummary WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.AssetRiskSummaryCounted') IS NOT NULL DELETE FROM sidata.AssetRiskSummaryCounted WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.AssetRiskSummaryState') IS NOT NULL DELETE FROM sidata.AssetRiskSummaryState WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.DomainCategory') IS NOT NULL DELETE FROM sidata.DomainCategory WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.DomainCategoryState') IS NOT NULL DELETE FROM sidata.DomainCategoryState WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.ReportPreviewCount') IS NOT NULL DELETE FROM sidata.ReportPreviewCount WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.ReportPreviewState') IS NOT NULL DELETE FROM sidata.ReportPreviewState WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.CiFindingSummary') IS NOT NULL DELETE FROM sidata.CiFindingSummary WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.CiFindingSummaryState') IS NOT NULL DELETE FROM sidata.CiFindingSummaryState WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.FindingChange') IS NOT NULL DELETE FROM sidata.FindingChange WHERE CollectionId = @CollectionId OR PrevCollectionId = @CollectionId;
IF OBJECT_ID('sidata.FindingChangeCounted') IS NOT NULL DELETE FROM sidata.FindingChangeCounted WHERE CollectionId = @CollectionId OR PrevCollectionId = @CollectionId;
IF OBJECT_ID('sidata.AssetChange') IS NOT NULL DELETE FROM sidata.AssetChange WHERE CollectionId = @CollectionId OR PrevCollectionId = @CollectionId;
IF OBJECT_ID('sidata.AssetChangeCounted') IS NOT NULL DELETE FROM sidata.AssetChangeCounted WHERE CollectionId = @CollectionId OR PrevCollectionId = @CollectionId;
IF OBJECT_ID('sidata.ChangeCount') IS NOT NULL DELETE FROM sidata.ChangeCount WHERE CollectionId = @CollectionId OR PrevCollectionId = @CollectionId;
IF OBJECT_ID('sidata.ChangeCountCounted') IS NOT NULL DELETE FROM sidata.ChangeCountCounted WHERE CollectionId = @CollectionId OR PrevCollectionId = @CollectionId;
IF OBJECT_ID('sidata.ChangeState') IS NOT NULL DELETE FROM sidata.ChangeState WHERE CollectionId = @CollectionId OR PrevCollectionId = @CollectionId;
IF OBJECT_ID('sidata.Tier0Asset') IS NOT NULL DELETE FROM sidata.Tier0Asset WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.Tier0AssetCounted') IS NOT NULL DELETE FROM sidata.Tier0AssetCounted WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.Tier0AssetState') IS NOT NULL DELETE FROM sidata.Tier0AssetState WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.FindingPivotCell') IS NOT NULL DELETE FROM sidata.FindingPivotCell WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.FindingPivotCellCounted') IS NOT NULL DELETE FROM sidata.FindingPivotCellCounted WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.PivotCell') IS NOT NULL DELETE FROM sidata.PivotCell WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.FindingPivotState') IS NOT NULL DELETE FROM sidata.FindingPivotState WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.SummaryGroup') IS NOT NULL DELETE FROM sidata.SummaryGroup WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.SummaryGroupCounted') IS NOT NULL DELETE FROM sidata.SummaryGroupCounted WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.SummaryGroupState') IS NOT NULL DELETE FROM sidata.SummaryGroupState WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.RemediationAsset') IS NOT NULL DELETE FROM sidata.RemediationAsset WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.Remediation') IS NOT NULL DELETE FROM sidata.Remediation WHERE CollectionId = @CollectionId;
IF OBJECT_ID('sidata.KeyFigure') IS NOT NULL DELETE FROM sidata.KeyFigure WHERE CollectionId = @CollectionId;
DELETE FROM sidata.Collection WHERE CollectionId = @CollectionId
  AND NOT EXISTS (SELECT 1 FROM sidata.Finding WHERE CollectionId = @CollectionId)
  AND NOT EXISTS (SELECT 1 FROM sidata.Recommendation WHERE CollectionId = @CollectionId);
DECLARE @n int = @@ROWCOUNT;
COMMIT;
SELECT @n;
'@
}

function Get-SIDataPurgeOrphansSql {
    <# Runs no collection refers to, and CIs not seen since the cutoff that no remaining finding refers to (identifiers first). #>
    param([Parameter(Mandatory)][ValidateSet('Run', 'AssetIdentifier', 'AssetTag', 'Asset', 'AssetEvidence', 'AssetConflict', 'AssetIdHistory')][string]$What)
    switch ($What) {
        # #299: correlation evidence and conflicts no load has carried since the cutoff; the id history of CIs that are
        # gone (after the CI purge). Nothing on a database without the tables.
        'AssetEvidence' { "IF OBJECT_ID('sidata.AssetEvidence') IS NULL BEGIN SELECT 0; RETURN; END; DELETE TOP (@Batch) e FROM sidata.AssetEvidence e WHERE e.LastSeen < CONVERT(datetime2(3), @Cutoff, 126); SELECT @@ROWCOUNT;" }
        'AssetConflict' { "IF OBJECT_ID('sidata.AssetConflict') IS NULL BEGIN SELECT 0; RETURN; END; DELETE TOP (@Batch) c FROM sidata.AssetConflict c WHERE c.LastSeen < CONVERT(datetime2(3), @Cutoff, 126); SELECT @@ROWCOUNT;" }
        'AssetIdHistory' { "IF OBJECT_ID('sidata.AssetIdHistory') IS NULL BEGIN SELECT 0; RETURN; END; DELETE TOP (@Batch) h FROM sidata.AssetIdHistory h WHERE h.DetectedAt < CONVERT(datetime2(3), @Cutoff, 126) AND NOT EXISTS (SELECT 1 FROM sidata.Asset a WHERE a.AssetKey = h.AssetKey); SELECT @@ROWCOUNT;" }
        # the responsibility tags of a CI that is purged (#254); nothing on a database without the table
        'AssetTag' { "IF OBJECT_ID('sidata.AssetTag') IS NULL BEGIN SELECT 0; RETURN; END; DELETE TOP (@Batch) t FROM sidata.AssetTag t JOIN sidata.Asset a ON a.AssetKey = t.AssetKey WHERE a.LastSeen < CONVERT(datetime2(3), @Cutoff, 126) AND NOT EXISTS (SELECT 1 FROM sidata.Finding f WHERE f.AssetKey = a.AssetKey); SELECT @@ROWCOUNT;" }
        'Run' { "DELETE TOP (@Batch) r FROM sidata.Run r WHERE r.CollectionTime < CONVERT(datetime2(3), @Cutoff, 126) AND NOT EXISTS (SELECT 1 FROM sidata.Collection c WHERE c.RunId = r.RunId); SELECT @@ROWCOUNT;" }
        'AssetIdentifier' { "DELETE TOP (@Batch) i FROM sidata.AssetIdentifier i JOIN sidata.Asset a ON a.AssetKey = i.AssetKey WHERE a.LastSeen < CONVERT(datetime2(3), @Cutoff, 126) AND NOT EXISTS (SELECT 1 FROM sidata.Finding f WHERE f.AssetKey = a.AssetKey); SELECT @@ROWCOUNT;" }
        'Asset' { "DELETE TOP (@Batch) a FROM sidata.Asset a WHERE a.LastSeen < CONVERT(datetime2(3), @Cutoff, 126) AND NOT EXISTS (SELECT 1 FROM sidata.Finding f WHERE f.AssetKey = a.AssetKey) AND NOT EXISTS (SELECT 1 FROM sidata.AssetIdentifier i WHERE i.AssetKey = a.AssetKey); SELECT @@ROWCOUNT;" }
    }
}

# ------------------------------------------------------------------------------------------------------------------
#  THE WRITES
# ------------------------------------------------------------------------------------------------------------------

function Invoke-SIDataBatchedDelete {
    <#
        Runs one 'DELETE TOP (@Batch) ...; SELECT @@ROWCOUNT' until it removes nothing, sizing each batch from the last
        one's measured time (Get-SIDataNextSize). Returns the rows removed. -DeadlineUtc (#816): no new batch after it -- the
        caller's time budget (what is left is removed by its next call).
        -Housekeeping (the removal of retired collections): the housekeeping rule of the pacing -- wait until the database is
        calm, never past -DeadlineUtc (Invoke-SISqlPacingHousekeeping). -LockBound (> 0): no batch is ever larger -- the
        lock-escalation bound of the table (Get-SIDataRetireBatchBound), the rule of the key ranges; 0 = none (as before).
        -Stopped: set to $true when the housekeeping wait reached the deadline with rows possibly left.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params = @{},
          [ref]$BatchSize, [long]$TargetMs = 5000, [datetime]$DeadlineUtc = [datetime]::MaxValue,
          [switch]$Housekeeping, [long]$LockBound = 0, [ref]$Stopped)
    $total = 0L
    $size = [long]5000; if ($BatchSize -and $BatchSize.Value -gt 0) { $size = [long]$BatchSize.Value }
    if ($LockBound -gt 0 -and $size -gt $LockBound) { $size = $LockBound }
    # the database's own load paces the batches (SI-SqlPacing.ps1): a pause and a smaller batch only while it is saturated
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
    while ($true) {
        if ($paced) {
            $pace = if ($Housekeeping) { Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Housekeeping -DeadlineUtc $DeadlineUtc } else { Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs }
            if ($pace.Shrink) { $size = [Math]::Max(100L, [long][Math]::Floor($size / 2)) }
            if ($LockBound -gt 0 -and $size -gt $LockBound) { $size = $LockBound }
            if ($Housekeeping -and $pace.PSObject.Properties['Deadline'] -and $pace.Deadline) { if ($Stopped) { $Stopped.Value = $true }; break }
        }
        # housekeeping: no new batch once the wait reached the deadline
        if ($Housekeeping -and [datetime]::UtcNow -ge $DeadlineUtc) { break }
        $p = @{}; foreach ($k in $Params.Keys) { $p[$k] = $Params[$k] }; $p['Batch'] = $size
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $n = [long](& $Invoke $Sql $p 'scalar')
        $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
        $total += $n
        if ($n -lt $size) { break }
        $size = Get-SIDataNextSize -Current $size -ElapsedMs $sw.ElapsedMilliseconds -TargetMs $TargetMs -Minimum 100
        if ($LockBound -gt 0 -and $size -gt $LockBound) { $size = $LockBound }
        if ([datetime]::UtcNow -ge $DeadlineUtc) { break }
    }
    if ($BatchSize) { $BatchSize.Value = $size }
    $total
}

function Get-SIDataIndexCountSql {
    <# The live indexes of one table (@Table, 'schema.name'): the count the lock-escalation bound is worked out from -- the
       same count Get-SIDataRetireRangeSql makes for its own @cap. 0 when the table is not there. #>
    "SELECT COUNT(*) FROM sys.indexes WHERE object_id = OBJECT_ID(@Table) AND index_id > 0 AND is_hypothetical = 0 AND is_disabled = 0;"
}

function Get-SIDataRetireBatchBound {
    <#
        The most rows ONE batched delete of a retired collection's -Table may take: below SQL Server's lock escalation (5,000
        locks of one statement), counting one lock in EVERY index of the table -- 4000 / the table's indexes, at least 1 --
        the rule of the key ranges (Get-SIDataRetireRangeSql, review S5). A lock-escalation bound, not a limit on the work:
        the removal goes on batch after batch until nothing is left. The table comes from the allow-list, never input.
        Indexes that cannot be counted: the bound of a table with one index (4000). -IndexCount: the count (tests).
    #>
    param([scriptblock]$Invoke, [Parameter(Mandatory)][ValidateSet('IssueContext', 'RaStage', 'RaDefenderKey', 'Recommendation', 'Finding', 'SummaryAsset', 'SummaryRow')][string]$Table,
          $IndexCount = $null)
    $ix = $IndexCount
    if ($null -eq $ix -and $Invoke) { try { $ix = & $Invoke (Get-SIDataIndexCountSql) @{ Table = ('sidata.' + $Table) } 'scalar' } catch { $ix = $null } }
    $n = 0; if ($null -ne $ix -and -not ($ix -is [System.DBNull])) { try { $n = [int]$ix } catch { $n = 0 } }
    # a table has at most 1,000 indexes (one clustered + 999): anything else is not a count
    if ($n -lt 1 -or $n -gt 1000) { $n = 1 }
    [long][Math]::Max(1, [Math]::Floor(4000 / $n))
}

function Write-SIDataJsonRows {
    <#
        Sends JSON object texts in chunks through one OPENJSON statement (-Sql reads @j and returns the rows it wrote).
        Each chunk is checked: a chunk that wrote fewer rows than it carried FAILS the load -- it is never counted as
        written. The chunk size follows the measured time of the last chunk. Returns the rows written.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql,
          [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Items, [hashtable]$Params = @{},
          [ref]$ChunkChars, [long]$TargetMs = 10000, [string]$What = 'rows')
    $total = 0L
    $target = [long]2000000; if ($ChunkChars -and $ChunkChars.Value -gt 0) { $target = [long]$ChunkChars.Value }
    $i = 0
    # the database's own load paces the chunks (SI-SqlPacing.ps1): a pause and a smaller chunk only while it is saturated;
    # every item is still written, in the same order
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
    while ($i -lt $Items.Count) {
        if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs; if ($pace.Shrink) { $target = [Math]::Max(50000L, [long][Math]::Floor($target / 2)) } }
        # one chunk at the CURRENT size, so a slow chunk shrinks the next one
        $take = New-Object System.Collections.Generic.List[string]; $len = 0L
        while ($i -lt $Items.Count -and ($take.Count -eq 0 -or ($len + $Items[$i].Length + 1) -le $target)) { $take.Add($Items[$i]); $len += $Items[$i].Length + 1; $i++ }
        $p = @{}; foreach ($k in $Params.Keys) { $p[$k] = $Params[$k] }; $p['j'] = '[' + ($take -join ',') + ']'
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $n = [long](& $Invoke $Sql $p 'scalar')
        $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
        if ($n -ne $take.Count) { throw ("{0}: a chunk of {1} wrote {2} -- the load stops; nothing of this collection is shown until a full load succeeds." -f $What, $take.Count, $n) }
        $total += $n
        # the time measured is the time of THIS chunk ($len characters), so the next size is worked out from $len: a small
        # chunk that was fast (the last of a part, a small Risk Analysis bucket) says nothing about a larger one and never
        # grows the size -- it grew on every such call before, doubling to an overflow over one run (live 2026-10-13)
        $next = Get-SIDataNextSize -Current ([Math]::Max(1L, $len)) -ElapsedMs $sw.ElapsedMilliseconds -TargetMs $TargetMs -Minimum 50000
        if ($len -ge $target -or $i -lt $Items.Count) { $target = $next }   # a full chunk (the size, not the items, ended it): its time sizes the next one (at most double)
        elseif ($next -lt $len) { $target = $next }         # a part chunk that was SLOW: smaller at once
    }
    if ($ChunkChars) { $ChunkChars.Value = $target }
    $total
}

function Get-SIDataPurgeDerivedTables {
    <#
        PURE. #881 The tables the purge of a collection empties for it, read from Get-SIDataPurgeCollectionSql itself (ONE
        list: a table added there is emptied in batches too): @{ Table; Prev ($true = it also holds the collection as the
        EARLIER one of a comparison, PrevCollectionId) }, in the purge's order.
    #>
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($m in [regex]::Matches((Get-SIDataPurgeCollectionSql), '(?m)DELETE FROM sidata\.(\w+) WHERE CollectionId = @CollectionId( OR PrevCollectionId = @CollectionId)?;')) {
        if ($m.Groups[1].Value -eq 'Collection') { continue }
        $out.Add([pscustomobject]@{ Table = $m.Groups[1].Value; Prev = [bool]$m.Groups[2].Success })
    }
    $out.ToArray()
}

function Get-SIDataPurgeDerivedBatchSql {
    <# #881 One batch of one derived table's rows of a collection (-Column CollectionId | PrevCollectionId); 0 on a database
       without the table. -Table comes from Get-SIDataPurgeDerivedTables (the purge's own list), never input. #>
    param([Parameter(Mandatory)][ValidatePattern('^\w+$')][string]$Table, [ValidateSet('CollectionId', 'PrevCollectionId')][string]$Column = 'CollectionId')
    "IF OBJECT_ID(N'sidata.$Table') IS NULL BEGIN SELECT 0; RETURN; END; DELETE TOP (@Batch) FROM sidata.$Table WHERE $Column = @CollectionId; SELECT @@ROWCOUNT;"
}

function Remove-SIDataCollection {
    <# Removes one collection and everything loaded under it (findings, recommendations, its daily rows), in batches.
       #881 every derived table first, in measured batches (each its own short statement -- at the largest tenant the ~50
       tables of a collection in ONE transaction filled the log), the comparisons that name it as the earlier collection too;
       then the purge's own transaction removes whatever is left (nothing, normally) and the collection row. The same rows
       go as before -- the last statement is the purge as it was. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$CollectionId, [ref]$BatchSize)
    $f = Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataPurgeBatchSql -Table Finding) -Params @{ CollectionId = $CollectionId } -BatchSize $BatchSize
    $r = Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataPurgeBatchSql -Table Recommendation) -Params @{ CollectionId = $CollectionId } -BatchSize $BatchSize
    foreach ($d in (Get-SIDataPurgeDerivedTables)) {
        $null = Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataPurgeDerivedBatchSql -Table $d.Table) -Params @{ CollectionId = $CollectionId } -BatchSize $BatchSize
        if ($d.Prev) { $null = Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataPurgeDerivedBatchSql -Table $d.Table -Column PrevCollectionId) -Params @{ CollectionId = $CollectionId } -BatchSize $BatchSize }
    }
    $c = [int](& $Invoke (Get-SIDataPurgeCollectionSql) @{ CollectionId = $CollectionId } 'scalar')
    if ($c -ne 1) { throw ("collection {0} could not be removed (rows still refer to it)" -f $CollectionId) }
    [pscustomobject]@{ CollectionId = $CollectionId; Findings = $f; Recommendations = $r }
}

function Invoke-SIDataRetention {
    <#
        Purges collections taken before the cutoff (and loads that died outside the look-back window), then runs no
        collection refers to and CIs not seen since the cutoff that no remaining finding refers to. sidata only.
        Returns @{ Cutoff; Collections; Findings; Recommendations; Runs; Assets; Identifiers }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$RetentionDays, [int]$LookbackDays = 3,
          [datetime]$Now = [datetime]::UtcNow)
    $cutoff = Get-SIDataRetentionCutoff -RetentionDays $RetentionDays -Now $Now
    $stale = $Now.ToUniversalTime().AddDays(-($LookbackDays + 1))
    $targetsRaw = (& $Invoke (Get-SIDataPurgeTargetsSql) @{ Cutoff = (Format-SIDataSqlTime -Time $cutoff); StaleLoading = (Format-SIDataSqlTime -Time $stale) } 'reader')
    $targets = @($targetsRaw)
    $batch = [long]5000
    $sum = [ordered]@{ Cutoff = $cutoff; Collections = 0; Findings = 0L; Recommendations = 0L; Runs = 0L; Assets = 0L; Identifiers = 0L; Tags = 0L; Evidence = 0L }
    foreach ($t in $targets) {
        if ($null -eq $t) { continue }
        $r = Remove-SIDataCollection -Invoke $Invoke -CollectionId ([int]$t['CollectionId']) -BatchSize ([ref]$batch)
        $sum.Collections++; $sum.Findings += $r.Findings; $sum.Recommendations += $r.Recommendations
    }
    $cp = @{ Cutoff = (Format-SIDataSqlTime -Time $cutoff) }
    $sum.Runs = Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataPurgeOrphansSql -What Run) -Params $cp -BatchSize ([ref]$batch)
    $sum.Identifiers = Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataPurgeOrphansSql -What AssetIdentifier) -Params $cp -BatchSize ([ref]$batch)
    $sum.Tags = Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataPurgeOrphansSql -What AssetTag) -Params $cp -BatchSize ([ref]$batch)
    $sum.Assets = Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataPurgeOrphansSql -What Asset) -Params $cp -BatchSize ([ref]$batch)
    # #299: the correlation evidence past retention, then the id history of the CIs just purged
    $sum.Evidence = Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataPurgeOrphansSql -What AssetEvidence) -Params $cp -BatchSize ([ref]$batch)
    $sum.Evidence += Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataPurgeOrphansSql -What AssetConflict) -Params $cp -BatchSize ([ref]$batch)
    $sum.Evidence += Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataPurgeOrphansSql -What AssetIdHistory) -Params $cp -BatchSize ([ref]$batch)
    [pscustomobject]$sum
}

# ------------------------------------------------------------------------------------------------------------------
#  THE FULL ASSET METADATA'S OWN RETENTION (#301, operator 2026-10-05: "3 days should be sufficient")
# ------------------------------------------------------------------------------------------------------------------

function Get-SIDataAssetPropertiesPruneSql {
    <#
        One batch of the prune: the full asset metadata (the source-system bags from SI_AssetProperties_CL) is removed
        from sidata.Asset.PropertiesJson when it was collected before @Cutoff ("_siPropertiesAt"), or carries no
        collection time at all (written before the stamp existed, or not refreshed by this sync). The tier attribution
        at the top of the bag (SI_TierSetBy / SI_TierReason / SI_TierClaims -- #244) is KEPT: it is SecurityInsight's
        own data, not the metadata. Nothing on a database without the table. Returns the rows changed.
    #>
    @'
IF OBJECT_ID('sidata.Asset') IS NULL BEGIN SELECT 0; RETURN; END;
UPDATE TOP (@Batch) a SET
    PropertiesJson = CASE
        WHEN JSON_VALUE(a.PropertiesJson, '$.SI_TierSetBy') IS NULL THEN NULL
        WHEN JSON_QUERY(a.PropertiesJson, '$.SI_TierClaims') IS NOT NULL THEN
            JSON_MODIFY(JSON_MODIFY(JSON_MODIFY(N'{}', '$.SI_TierSetBy', JSON_VALUE(a.PropertiesJson, '$.SI_TierSetBy')),
                '$.SI_TierReason', JSON_VALUE(a.PropertiesJson, '$.SI_TierReason')), '$.SI_TierClaims', JSON_QUERY(a.PropertiesJson, '$.SI_TierClaims'))
        ELSE
            JSON_MODIFY(JSON_MODIFY(JSON_MODIFY(N'{}', '$.SI_TierSetBy', JSON_VALUE(a.PropertiesJson, '$.SI_TierSetBy')),
                '$.SI_TierReason', JSON_VALUE(a.PropertiesJson, '$.SI_TierReason')), '$.SI_TierClaims', JSON_VALUE(a.PropertiesJson, '$.SI_TierClaims'))
    END
FROM sidata.Asset a
WHERE a.PropertiesJson IS NOT NULL AND ISJSON(a.PropertiesJson) = 1
  AND EXISTS (SELECT 1 FROM OPENJSON(a.PropertiesJson) k WHERE k.[key] NOT IN (N'SI_TierSetBy', N'SI_TierReason', N'SI_TierClaims', N'_siPropertiesAt'))
  AND (TRY_CONVERT(datetime2(3), JSON_VALUE(a.PropertiesJson, '$._siPropertiesAt'), 127) IS NULL
       OR TRY_CONVERT(datetime2(3), JSON_VALUE(a.PropertiesJson, '$._siPropertiesAt'), 127) < CONVERT(datetime2(3), @Cutoff, 126));
SELECT @@ROWCOUNT;
'@
}

function Get-SIDataAssetPropertiesRetentionDays {
    <# PURE. SI_AssetProperties_RetentionDays from a name -> value map: a whole number, at least 1; anything else = 3. #>
    param([hashtable]$Globals = @{})
    $raw = if ($Globals.ContainsKey('SI_AssetProperties_RetentionDays') -and $null -ne $Globals['SI_AssetProperties_RetentionDays']) { "$($Globals['SI_AssetProperties_RetentionDays'])".Trim() } else { '' }
    $n = 0
    if (-not $raw -or -not [int]::TryParse($raw, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return 3 }
    [Math]::Max(1, $n)
}

function Invoke-SIDataAssetPropertiesPrune {
    <#
        Removes the full asset metadata older than -RetentionDays from the Pro database, in batches: the generic store
        (sidata.AssetMetadata, #408) and the older per-asset bags in sidata.Asset.PropertiesJson. Returns @{ Cutoff;
        RetentionDays; Assets (bags); MetadataRows }. The caller audits it (datasync.assetproperties.prune).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [int]$RetentionDays = 3, [datetime]$Now = [datetime]::UtcNow)
    if ($RetentionDays -lt 1) { $RetentionDays = 1 }
    $cutoff = $Now.ToUniversalTime().AddDays(-$RetentionDays)
    $batch = [long]5000
    $n = Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql (Get-SIDataAssetPropertiesPruneSql) -Params @{ Cutoff = (Format-SIDataSqlTime -Time $cutoff) } -BatchSize ([ref]$batch)
    # #408: the generic store (sidata.AssetMetadata) by the same cutoff -- at every level, so metadata stored while 'full'
    # was on ages out after it is switched back
    $m = 0L
    if (Get-Command -Name Invoke-SIDataAssetMetadataPrune -ErrorAction SilentlyContinue) { $m = Invoke-SIDataAssetMetadataPrune -Invoke $Invoke -Cutoff $cutoff }
    [pscustomobject]@{ Cutoff = $cutoff; RetentionDays = $RetentionDays; Assets = [long]$n; MetadataRows = [long]$m }
}

# ------------------------------------------------------------------------------------------------------------------
#  THE COLLECTIONS' OWN RETENTION (#717, owner 2026-10-16: "it can not grow full" / "i bet it is the old failed runs" /
#  "which can be removed"). Measured at a large install: sidata.Finding 10.9M rows / 30.8 GB, ~1M rows per Risk Analysis
#  run, six collections all still 'Loading' (a stopped run never reaches the step that marks it complete).
#
#  THE RULE, per grain (Risk Analysis Detailed = sidata.Collection; Risk Analysis Summary = sidata.SummaryLoad):
#    KEEP     the newest COMPLETE collection (what every view shows) and the complete one before it (the comparison
#             between runs reads it); a complete collection whose rows a kept collection's not-complete report shows
#             (sidata.CollectionReportCarry: the last complete result of that report); every collection still 'Loading'
#             that is NEWER than the newest complete one (a run in progress -- one run at a time per install, the pipeline
#             lock -- or one not superseded yet); everything, while no complete collection of the grain exists.
#    REMOVE   the finding rows of every older complete collection, and of every 'Loading' collection OLDER than the
#             newest complete one (abandoned: its run stopped or failed; a newer run of the same grain completed).
#             ALSO (#746, a large install 2026-10-18: six Detailed collections left Loading by stopped or failed runs; an install whose
#             runs keep stopping never gets a complete one, and kept every attempt): a 'Loading' collection older than
#             -StaleDays (7, the longest a pipeline run may take) that is NOT the newest collection of its grain -- a newer
#             run of the same grain started after it -- and whose result is not waiting to be completed by the data sync
#             (RaCompletedAt) is abandoned too, complete collection or not. The newest collection of a grain is never it.
#  WHAT "REMOVE" REMOVES -- the row-level detail, which is the size: the findings (sidata.Finding, the data sync's rows and
#  Risk Analysis' alike -- every row carries its CollectionId), the recommendations, the prepared issue rows
#  (sidata.IssueContext), and what an abandoned run staged (sidata.RaStage / RaDefenderKey). A Summary collection: its
#  rows and impacted assets. WHAT IT KEEPS: the collection row itself, marked (RetiredAt) -- so the data sync never loads
#  it from Log Analytics again and no view lists it -- and every aggregate (the day totals behind the trends, the facets,
#  the departments, the services, the correlation rows, the per-report verdicts behind the row-count comparison). Those
#  go with the collection row when SI_Pro_DataRetentionDays (90) removes it, as before.
#  ABSENCE IS NOT REMEDIATION: nothing here touches the newest collection, the close-loop (vuln.*) or the per-CI lifecycle
#  (sidata.Ci*), so removing an old collection can never close or change a finding of the current one.
#  SAFE BY CONSTRUCTION: the mark refuses (in SQL) a collection that does not have the newer complete collection(s) the
#  rule needs; every delete removes rows only of a MARKED collection; batches on the clustered keys (CollectionId /
#  CollectionTime / RunKey), sized from their measured time. Idempotent: a removal that stopped part way is finished by the
#  next run (the collection is marked and still has rows). Never throws: a failure is said, and the next run tries again.
# ------------------------------------------------------------------------------------------------------------------

$script:SIDataRetiredReady = $false

function Set-SIDataRetiredReady {
    <# Whether the database carries the retention mark (sidata.Collection.RetiredAt) -- the readers below leave marked collections out only then. #>
    param([bool]$Ready)
    $script:SIDataRetiredReady = $Ready
}

function Get-SIDataLiveFilter {
    <# ' AND <alias>RetiredAt IS NULL' when the database carries the mark (Set-SIDataRetiredReady), else '' -- a collection whose rows the retention removed is never derived, resolved, prepared or shown again. #>
    param([string]$Alias = '')
    if ($script:SIDataRetiredReady) { $p = if ($Alias) { $Alias.TrimEnd('.') + '.' } else { '' }; return (' AND {0}RetiredAt IS NULL' -f $p) }
    ''
}

function Get-SIDataRetiredColumnsSql {
    <# The mark on a database set up before it existed: the SAME guarded, additive statements as sql/si-data-schema.sql. Answers 1 when the mark is there. #>
    @'
IF COL_LENGTH('sidata.Collection', 'RetiredAt') IS NULL ALTER TABLE sidata.Collection ADD RetiredAt DATETIME2(0) NULL;
IF COL_LENGTH('sidata.Collection', 'RetiredWhy') IS NULL ALTER TABLE sidata.Collection ADD RetiredWhy NVARCHAR(32) NULL;
IF OBJECT_ID('sidata.SummaryLoad') IS NOT NULL AND COL_LENGTH('sidata.SummaryLoad', 'RetiredAt') IS NULL ALTER TABLE sidata.SummaryLoad ADD RetiredAt DATETIME2(0) NULL;
IF OBJECT_ID('sidata.SummaryLoad') IS NOT NULL AND COL_LENGTH('sidata.SummaryLoad', 'RetiredWhy') IS NULL ALTER TABLE sidata.SummaryLoad ADD RetiredWhy NVARCHAR(32) NULL;
SELECT CASE WHEN COL_LENGTH('sidata.Collection', 'RetiredAt') IS NOT NULL THEN 1 ELSE 0 END;
'@
}

function Get-SIDataRetiredReadySql {
    "SELECT CASE WHEN COL_LENGTH('sidata.Collection', 'RetiredAt') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataRetentionStateSql {
    <#
        Every collection of both grains, newest first per grain: its status, its mark, and -- for a marked one -- whether
        rows are still left (a removal that stopped part way), and Pending = 1 when Risk Analysis' result is in and waits for
        the data sync to complete it (RaCompletedAt). Small: one row per collection; each check is one seek on the clustered
        key. Nothing on a database without the mark.
    #>
    @'
SET NOCOUNT ON;
IF COL_LENGTH('sidata.Collection', 'RetiredAt') IS NULL
BEGIN
    SELECT CAST(NULL AS nvarchar(16)) AS Grain, CAST(NULL AS int) AS CollectionId, CAST(NULL AS datetime2(3)) AS CollectionTime, CAST(NULL AS nvarchar(16)) AS Status,
           CAST(NULL AS datetime2(0)) AS RetiredAt, CAST(0 AS int) AS HasRows, CAST(0 AS int) AS Pending, CAST(0 AS int) AS Published, CAST(NULL AS nvarchar(32)) AS RetiredWhy WHERE 1 = 0;
    RETURN;
END
DECLARE @pend nvarchar(200) = CASE WHEN COL_LENGTH('sidata.Collection', 'RaCompletedAt') IS NOT NULL THEN N'CASE WHEN c.RaCompletedAt IS NOT NULL THEN 1 ELSE 0 END' ELSE N'0' END;
-- ONE TRUSTED RUN: Published = 1 on the collection of each grain the web app shows (sidata.PublishedRun 'current')
DECLARE @pubD nvarchar(300) = CASE WHEN OBJECT_ID('sidata.PublishedRun') IS NOT NULL THEN N'CASE WHEN EXISTS (SELECT 1 FROM sidata.PublishedRun AS p WHERE p.Name = N''current'' AND p.DetailedCollectionId = c.CollectionId) THEN 1 ELSE 0 END' ELSE N'0' END;
DECLARE @pubS nvarchar(300) = CASE WHEN OBJECT_ID('sidata.PublishedRun') IS NOT NULL THEN N'CASE WHEN EXISTS (SELECT 1 FROM sidata.PublishedRun AS p WHERE p.Name = N''current'' AND p.SummaryCollectionTime = l.CollectionTime) THEN 1 ELSE 0 END' ELSE N'0' END;
DECLARE @q nvarchar(max) = N'SELECT N''Detailed'' AS Grain, c.CollectionId, c.CollectionTime, c.Status, c.RetiredAt,
       CASE WHEN c.RetiredAt IS NOT NULL AND EXISTS (SELECT 1 FROM sidata.Finding AS f WHERE f.CollectionId = c.CollectionId) THEN 1 ELSE 0 END AS HasRows, ' + @pend + N' AS Pending, ' + @pubD + N' AS Published, c.RetiredWhy
FROM sidata.Collection AS c WHERE c.Kind = N''Detailed''';
IF OBJECT_ID('sidata.SummaryLoad') IS NOT NULL AND COL_LENGTH('sidata.SummaryLoad', 'RetiredAt') IS NOT NULL AND OBJECT_ID('sidata.SummaryRow') IS NOT NULL
    SET @q += N'
UNION ALL
SELECT N''Summary'', CAST(NULL AS int), l.CollectionTime, l.Status, l.RetiredAt,
       CASE WHEN l.RetiredAt IS NOT NULL AND EXISTS (SELECT 1 FROM sidata.SummaryRow AS s WHERE s.CollectionTime = l.CollectionTime) THEN 1 ELSE 0 END, 0, ' + @pubS + N', l.RetiredWhy
FROM sidata.SummaryLoad AS l';
SET @q += N' ORDER BY 1, 3 DESC';
EXEC sp_executesql @q;
'@
}

function Get-SIDataRetentionCarrySql {
    <# Which collection a kept collection's not-complete report shows its last complete rows from (sidata.CollectionReportCarry). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.CollectionReportCarry') IS NULL SELECT CAST(NULL AS int) AS CollectionId, CAST(NULL AS int) AS FromCollectionId WHERE 1 = 0;
ELSE SELECT DISTINCT CollectionId, FromCollectionId FROM sidata.CollectionReportCarry WHERE FromCollectionId IS NOT NULL;
'@
}

function Get-SIDataCollectionRetentionPlan {
    <#
        PURE. The rule above, per grain. -Collections: Get-SIDataRetentionStateSql's rows (Grain, CollectionId,
        CollectionTime, Status, RetiredAt, HasRows). -CarryLinks: Get-SIDataRetentionCarrySql's rows. Returns one item per
        collection that is KEPT or acted on -- @{ Grain; CollectionId; CollectionTime; Status; Action; Why; Reason }:
          Keep     never touched (Reason says why)
          Retire   its rows are removed now; Why = 'abandoned' (a 'Loading' collection older than the newest complete one)
                   | 'superseded' (a complete one older than the newest complete one and the one before it)
          Finish   marked by an earlier run whose removal did not finish -- the rest of its rows are removed now
        A marked collection with no rows left is not listed. The newest complete collection of a grain is never Retire.
        #746: a 'Loading' collection older than -StaleDays before -NowUtc that is not the newest collection of its grain and
        not Pending (its result waits for the data sync) is Retire 'abandoned' too -- also while no collection of the grain
        is complete. -StaleDays 0 = that rule off.
        #816: -IdleStaleHours > 0 -- given ONLY when no pipeline run is running (the caller checked cfg.FlowRun) -- a Detailed
        collection still 'Loading' that started more than that many hours before -NowUtc, not Pending, not the published one,
        is Retire 'stopped run' even when it is the newest collection: no run is writing it. 0 = that rule off.
        #882: -IdleBeforeUtc (instead of -IdleStaleHours) -- the start of the oldest Risk Analysis work that may still be
        writing (Get-SIDataLoadingOwnerFloor): a Detailed collection still loading that started BEFORE it, not Pending, not
        the published one, belongs to no live run -- Retire 'stopped run' (-IdleReason says why). Never a complete one.
    #>
    param([AllowEmptyCollection()][object[]]$Collections = @(), [AllowEmptyCollection()][object[]]$CarryLinks = @(),
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$StaleDays = 7, [double]$IdleStaleHours = 0, $IdleBeforeUtc = $null, [string]$IdleReason = '')
    $g = { param($r, [string]$n) $v = $null; if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $v = $r[$n] } } elseif ($null -ne $r -and $r.PSObject.Properties[$n]) { $v = $r.$n }; if ($v -is [System.DBNull]) { $null } else { $v } }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Collections)) {
        if ($null -eq $r) { continue }
        $grain = [string](& $g $r 'Grain'); if ($grain -notin 'Detailed', 'Summary') { continue }
        $t = ConvertTo-SIDataUtc (& $g $r 'CollectionTime'); if ($null -eq $t) { continue }
        $id = & $g $r 'CollectionId'
        $rows.Add([pscustomobject]@{ Grain = $grain; CollectionId = $(if ($null -ne $id) { [int]$id } else { $null }); CollectionTime = $t; Status = [string](& $g $r 'Status')
                                     Retired = ($null -ne (& $g $r 'RetiredAt')); HasRows = ([int](& $g $r 'HasRows') -eq 1); Pending = ([int](& $g $r 'Pending') -eq 1)
                                     Published = ([int](& $g $r 'Published') -eq 1)
                                     # #892 B1: when and why it was marked (only a marked one has them)
                                     RetiredAt = (ConvertTo-SIDataUtc (& $g $r 'RetiredAt')); RetiredWhy = [string](& $g $r 'RetiredWhy') })
    }
    $staleBefore = $null
    if ($StaleDays -gt 0) { $staleBefore = $NowUtc.ToUniversalTime().AddDays(-$StaleDays) }
    # carried-from links: kept collection id -> the collections its reports show rows from
    $from = @{}
    foreach ($l in @($CarryLinks)) {
        if ($null -eq $l) { continue }
        $c = & $g $l 'CollectionId'; $f = & $g $l 'FromCollectionId'
        if ($null -eq $c -or $null -eq $f) { continue }
        $k = [string][int]$c; if (-not $from.ContainsKey($k)) { $from[$k] = New-Object System.Collections.Generic.List[int] }
        $from[$k].Add([int]$f)
    }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($grain in 'Detailed', 'Summary') {
        $all = @($rows | Where-Object { $_.Grain -eq $grain } | Sort-Object CollectionTime -Descending)
        if (-not $all.Count) { continue }
        $item = { param($x, [string]$action, [string]$why, [string]$reason)
            [pscustomobject]@{ Grain = $x.Grain; CollectionId = $x.CollectionId; CollectionTime = $x.CollectionTime; Status = $x.Status; Action = $action; Why = $why; Reason = $reason
                               RetiredAt = $x.RetiredAt; RetiredWhy = $x.RetiredWhy } }
        # a marked collection whose removal stopped part way is finished, whatever else is decided
        # (#892: the published run's collection is never finished, also when it carries a mark -- the views read it)
        foreach ($x in @($all | Where-Object { $_.Retired -and $_.HasRows })) {
            if ($x.Published) { $out.Add((& $item $x 'Keep' '' 'the published run -- what every view shows; its rows are never removed, also when it carries a mark')); continue }
            $out.Add((& $item $x 'Finish' '' 'its rows were being removed when an earlier run stopped -- the rest is removed now'))
        }
        $live = @($all | Where-Object { -not $_.Retired })
        $complete = @($live | Where-Object { $_.Status -eq 'Complete' })
        # #746: a run that stopped long ago, with a newer run of the same grain after it, is abandoned whether or not any
        # collection is complete -- never the newest collection of the grain, never one whose result waits to be completed
        $newestAny = if ($live.Count) { $live[0].CollectionTime } else { $null }
        $stale = {
            param($x)
            $null -ne $staleBefore -and $x.Status -ne 'Complete' -and -not $x.Pending -and $x.CollectionTime -lt $staleBefore -and $null -ne $newestAny -and $x.CollectionTime -lt $newestAny
        }
        $staleReason = [string]::Format($inv, 'its run stopped or failed more than {0} days ago and a newer run of the same kind started after it -- no run can still be writing it', $StaleDays)
        # #816: no pipeline run is running (the caller's check) -- a Detailed collection still loading after IdleStaleHours is a stopped run's
        $idleBefore = if ($null -ne $IdleBeforeUtc -and $grain -eq 'Detailed') { ([datetime]$IdleBeforeUtc).ToUniversalTime() } elseif ($IdleStaleHours -gt 0 -and $grain -eq 'Detailed') { $NowUtc.ToUniversalTime().AddHours(-$IdleStaleHours) } else { $null }
        $stopped = { param($x) $null -ne $idleBefore -and $x.Status -ne 'Complete' -and -not $x.Pending -and -not $x.Published -and $x.CollectionTime -lt $idleBefore }
        $stoppedReason = if ($null -ne $IdleBeforeUtc -and $IdleReason) { $IdleReason } else { [string]::Format($inv, 'its run stopped before it was complete: it is still loading after {0:0.#} hours and no pipeline run is running', $IdleStaleHours) }
        if (-not $complete.Count) {
            foreach ($x in $live) {
                if (& $stale $x) { $out.Add((& $item $x 'Retire' 'abandoned' $staleReason)); continue }
                if (& $stopped $x) { $out.Add((& $item $x 'Retire' 'stopped run' $stoppedReason)); continue }
                $out.Add((& $item $x 'Keep' '' 'no collection of this kind is complete yet -- nothing is removed until one is, or until a stopped run is older than the longest run may take'))
            }
            continue
        }
        $newest = $complete[0]
        $keep = @{}
        $keep[[string]$newest.CollectionTime.Ticks] = 'the newest complete collection -- what every view shows'
        if ($complete.Count -gt 1) { $keep[[string]$complete[1].CollectionTime.Ticks] = 'the complete collection before the newest -- the comparison between runs reads it' }
        # ONE TRUSTED RUN: the published run's collection is what every view shows -- kept, however many newer ones there are
        foreach ($x in @($complete | Where-Object { $_.Published })) { $keep[[string]$x.CollectionTime.Ticks] = 'the published run -- what every view shows' }
        # the collections a kept collection's not-complete reports show their last complete rows from (Detailed only), and theirs
        if ($grain -eq 'Detailed') {
            $byId = @{}; foreach ($x in $complete) { if ($null -ne $x.CollectionId) { $byId[[string]$x.CollectionId] = $x } }
            $changed = $true
            while ($changed) {
                $changed = $false
                foreach ($x in @($complete | Where-Object { $keep.ContainsKey([string]$_.CollectionTime.Ticks) })) {
                    if ($null -eq $x.CollectionId -or -not $from.ContainsKey([string]$x.CollectionId)) { continue }
                    foreach ($fid in $from[[string]$x.CollectionId]) {
                        $src = $byId[[string]$fid]
                        if ($src -and -not $keep.ContainsKey([string]$src.CollectionTime.Ticks)) {
                            $keep[[string]$src.CollectionTime.Ticks] = [string]::Format($inv, 'a report of the kept collection of {0:yyyy-MM-dd HH:mm} UTC shows its last complete rows from here', $x.CollectionTime)
                            $changed = $true
                        }
                    }
                }
            }
        }
        foreach ($x in $live) {
            $k = [string]$x.CollectionTime.Ticks
            if ($keep.ContainsKey($k)) { $out.Add((& $item $x 'Keep' '' $keep[$k])); continue }
            if ($x.Status -ne 'Complete') {
                if ($x.CollectionTime -ge $newest.CollectionTime) {
                    if (& $stale $x) { $out.Add((& $item $x 'Retire' 'abandoned' $staleReason)); continue }
                    if (& $stopped $x) { $out.Add((& $item $x 'Retire' 'stopped run' $stoppedReason)); continue }
                    $out.Add((& $item $x 'Keep' '' 'still loading and newer than the newest complete collection -- a run in progress is never removed')); continue
                }
                $out.Add((& $item $x 'Retire' 'abandoned' ([string]::Format($inv, 'its run stopped or failed before it was complete; the newer collection of {0:yyyy-MM-dd HH:mm} UTC is complete', $newest.CollectionTime))))
                continue
            }
            $out.Add((& $item $x 'Retire' 'superseded' 'older than the newest complete collection and the one before it'))
        }
    }
    , $out.ToArray()
}

function Get-SIDataRetireMarkSql {
    <#
        Marks ONE collection retired (its rows are removed next). The database itself refuses -- answers 0 -- unless newer
        COMPLETE collections of the same grain exist that are not marked: one for a 'Loading' collection, two for a complete
        one. So the newest complete collection, and a run still loading after it, can never be marked whatever the caller
        asks. A Detailed collection also leaves the collection views' list (ViewsReadyAt). Answers 1 when marked.
        #746: a NOT complete collection is also accepted when it is older than @StaleBefore (ISO text; '' = never) and a
        newer, unmarked collection of the same grain exists -- so the newest collection of a grain is never marked this way.
        #816 -Idle (Detailed; the caller found no pipeline run running): a NOT complete collection that started before
        @IdleBefore (ISO text) and whose Risk Analysis result does not wait for the data sync (RaCompletedAt) is accepted too --
        the newest one included: no run is writing it. Never the published run's collection, never a complete one.
    #>
    param([Parameter(Mandatory)][ValidateSet('Detailed', 'Summary')][string]$Grain, [switch]$Idle)
    if ($Grain -eq 'Summary') {
        return @'
SET NOCOUNT ON;
DECLARE @stale datetime2(3) = TRY_CONVERT(datetime2(3), NULLIF(@StaleBefore, N''), 126);
-- ONE TRUSTED RUN: the published run's Summary is never marked, whatever the caller asks (in ONE transaction
-- under the publisher's app lock, the pointer checked again in the UPDATE)
SET XACT_ABORT ON;
BEGIN TRANSACTION;
DECLARE @pubT datetime2(3) = NULL;
IF OBJECT_ID('sidata.PublishedRun') IS NOT NULL
BEGIN
    DECLARE @lk int;
    EXEC @lk = sp_getapplock @Resource = N'sidata.PublishedRun', @LockMode = N'Shared', @LockOwner = N'Transaction', @LockTimeout = 60000;
    IF @lk < 0 BEGIN ROLLBACK TRANSACTION; SELECT 0; RETURN; END
    EXEC sp_executesql N'SELECT @p = SummaryCollectionTime FROM sidata.PublishedRun WHERE Name = N''current''', N'@p datetime2(3) OUTPUT', @p = @pubT OUTPUT;
    IF @pubT = CONVERT(datetime2(3), @CollectionTime, 126) BEGIN ROLLBACK TRANSACTION; SELECT 0; RETURN; END
END
UPDATE l SET RetiredAt = SYSUTCDATETIME(), RetiredWhy = LEFT(@Why, 32)
FROM sidata.SummaryLoad AS l
WHERE l.CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126) AND l.RetiredAt IS NULL AND (@pubT IS NULL OR l.CollectionTime <> @pubT)
  AND ((SELECT COUNT(*) FROM sidata.SummaryLoad AS x WHERE x.Status = N'Complete' AND x.RetiredAt IS NULL AND x.CollectionTime > l.CollectionTime)
      >= CASE WHEN l.Status = N'Complete' THEN 2 ELSE 1 END
    OR (l.Status <> N'Complete' AND @stale IS NOT NULL AND l.CollectionTime < @stale
        AND EXISTS (SELECT 1 FROM sidata.SummaryLoad AS y WHERE y.RetiredAt IS NULL AND y.CollectionTime > l.CollectionTime)));
DECLARE @n int = @@ROWCOUNT;
COMMIT TRANSACTION;
SELECT @n;
'@
    }
    $idleDeclare = ''; $idleCase = ''
    if ($Idle) {
        $idleDeclare = @'
DECLARE @idle datetime2(3) = TRY_CONVERT(datetime2(3), NULLIF(@IdleBefore, N''), 126);
DECLARE @pending bit = 0;
IF COL_LENGTH('sidata.Collection', 'RaCompletedAt') IS NOT NULL
    EXEC sp_executesql N'SELECT @p = CASE WHEN RaCompletedAt IS NOT NULL THEN 1 ELSE 0 END FROM sidata.Collection WHERE CollectionId = @c', N'@c int, @p bit OUTPUT', @c = @c, @p = @pending OUTPUT;

'@
        $idleCase = "`n    OR (c.Status <> N'Complete' AND @idle IS NOT NULL AND @pending = 0 AND c.CollectionTime < @idle)"
    }
    $sql = @'
SET NOCOUNT ON;
DECLARE @c int = CONVERT(int, @CollectionId);
DECLARE @stale datetime2(3) = TRY_CONVERT(datetime2(3), NULLIF(@StaleBefore, N''), 126);
{IDLE}-- ONE TRUSTED RUN: the published run's collection is never marked, whatever the caller asks. The mark and
-- the publisher never interleave -- the pointer is read and the mark made in ONE transaction under the publisher's own app lock
-- (shared here; sidata.PublishedRunSet takes it exclusive before it reads a collection's mark and moves the pointer), and the
-- pointer is checked again in the UPDATE itself.
SET XACT_ABORT ON;
BEGIN TRANSACTION;
DECLARE @pub int = NULL;
IF OBJECT_ID('sidata.PublishedRun') IS NOT NULL
BEGIN
    DECLARE @lk int;
    EXEC @lk = sp_getapplock @Resource = N'sidata.PublishedRun', @LockMode = N'Shared', @LockOwner = N'Transaction', @LockTimeout = 60000;
    IF @lk < 0 BEGIN ROLLBACK TRANSACTION; SELECT 0; RETURN; END
    EXEC sp_executesql N'SELECT @p = DetailedCollectionId FROM sidata.PublishedRun WHERE Name = N''current''', N'@p int OUTPUT', @p = @pub OUTPUT;
    IF @pub = @c BEGIN ROLLBACK TRANSACTION; SELECT 0; RETURN; END
END
UPDATE c SET RetiredAt = SYSUTCDATETIME(), RetiredWhy = LEFT(@Why, 32)
FROM sidata.Collection AS c
WHERE c.CollectionId = @c AND c.Kind = N'Detailed' AND c.RetiredAt IS NULL AND (@pub IS NULL OR c.CollectionId <> @pub)
  AND ((SELECT COUNT(*) FROM sidata.Collection AS x WHERE x.Kind = N'Detailed' AND x.Status = N'Complete' AND x.RetiredAt IS NULL AND x.CollectionTime > c.CollectionTime)
      >= CASE WHEN c.Status = N'Complete' THEN 2 ELSE 1 END
    OR (c.Status <> N'Complete' AND @stale IS NOT NULL AND c.CollectionTime < @stale
        AND EXISTS (SELECT 1 FROM sidata.Collection AS y WHERE y.Kind = N'Detailed' AND y.RetiredAt IS NULL AND y.CollectionTime > c.CollectionTime)){CASE});
DECLARE @n int = @@ROWCOUNT;
IF @n > 0 AND COL_LENGTH('sidata.Collection', 'ViewsReadyAt') IS NOT NULL
    EXEC sp_executesql N'UPDATE sidata.Collection SET ViewsReadyAt = NULL WHERE CollectionId = @c', N'@c int', @c = @c;
COMMIT TRANSACTION;
SELECT @n;
'@
    $sql.Replace('{IDLE}', $idleDeclare).Replace('{CASE}', $idleCase)
}

$script:SIDataRetireTables = [ordered]@{
    # removed in this order: the finding rows LAST, so a removal that stops part way still shows as rows left (HasRows)
    Detailed = @('IssueContext', 'RaStage', 'RaDefenderKey', 'Recommendation', 'Finding')
    Summary  = @('RaStage', 'RaDefenderKey', 'SummaryAsset', 'SummaryRow')
}

function Get-SIDataRetireBatchSql {
    <#
        One batch of one MARKED collection's rows of one table (from an allow-list, never input): 'DELETE TOP (@Batch) ...;
        SELECT @@ROWCOUNT'. Every statement removes rows only while the collection is marked, on the table's clustered key.
        A table the database does not have answers 0.
        #892 (review B1) -DataSyncMarkedBefore (Detailed; while a pipeline run is going): only while the mark is one the data
        sync made (superseded / abandoned) BEFORE @MarkedBefore (ISO text: the running run's start).
    #>
    param([Parameter(Mandatory)][ValidateSet('Detailed', 'Summary')][string]$Grain,
          [Parameter(Mandatory)][ValidateSet('IssueContext', 'RaStage', 'RaDefenderKey', 'Recommendation', 'Finding', 'SummaryAsset', 'SummaryRow')][string]$Table,
          [switch]$DataSyncMarkedBefore)
    $since = if ($DataSyncMarkedBefore -and $Grain -eq 'Detailed') { " AND m.RetiredAt < CONVERT(datetime2(0), @MarkedBefore, 126) AND m.RetiredWhy IN (N'superseded', N'abandoned', N'stopped run')" } else { '' }
    $marked = if ($Grain -eq 'Summary') { "EXISTS (SELECT 1 FROM sidata.SummaryLoad AS m WHERE m.CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126) AND m.RetiredAt IS NOT NULL)" }
              else { "EXISTS (SELECT 1 FROM sidata.Collection AS m WHERE m.CollectionId = CONVERT(int, @CollectionId) AND m.Kind = N'Detailed' AND m.RetiredAt IS NOT NULL$since)" }
    $where = switch ($Table) {
        { $_ -in 'RaStage', 'RaDefenderKey' } { 'RunKey = @RunKey' }
        { $_ -in 'SummaryAsset', 'SummaryRow' } { 'CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126)' }
        default { 'CollectionId = CONVERT(int, @CollectionId)' }
    }
    "IF OBJECT_ID('sidata.$Table') IS NULL BEGIN SELECT 0; RETURN; END; DELETE TOP (@Batch) FROM sidata.$Table WHERE $where AND $marked; SELECT @@ROWCOUNT;"
}

# #892 the two large tables of a MARKED Detailed collection are removed in KEY RANGES on their clustered key (CollectionId,
# <row id>): each statement works out the end of its range first, then removes exactly that range -- so a batch never scans
# the ghost rows of the batches before it, and a removal that is stopped goes on from the collection's first row left.
$script:SIDataRetireRangeKeys = [ordered]@{ Finding = 'FindingId'; Recommendation = 'RecommendationRowId' }

function Get-SIDataRetireRangeSql {
    <#
        ONE KEY RANGE of one MARKED Detailed collection's rows of -Table (Finding | Recommendation, an allow-list, never input).
        Answers ONE row: N (rows removed), Hi (the range's last row id; NULL = nothing is left), Refused (1 = the database
        refused: nothing removed although the caller asked), Cap (the most rows one range may take).
          * @MarkedBefore (ISO text, '' = not asked; review B1): only a mark the data sync made (superseded / abandoned) before
            it -- the running pipeline run's start, so nothing in that run can be writing the collection;
          * the range is never larger than @Cap: below SQL Server's lock escalation (5,000 locks of one statement), counting
            one lock in EVERY index of the table (review S5) -- a range never turns into a table lock that holds a run's writes;
          * @After = 0 starts at the collection's first row (one seek on the clustered key; review M4);
          * the published run's collection is refused INSIDE the DELETE, and the range runs under the publisher's own app lock
            (shared; sidata.PublishedRunSet takes it exclusive), so a publish never interleaves with a range (review S4);
          * the DELETE carries the mark (and the B1 condition) again.
    #>
    param([Parameter(Mandatory)][ValidateSet('Finding', 'Recommendation')][string]$Table)
    $k = $script:SIDataRetireRangeKeys[$Table]
    $mark = "EXISTS (SELECT 1 FROM sidata.Collection AS m WHERE m.CollectionId = @c AND m.Kind = N'Detailed' AND m.RetiredAt IS NOT NULL AND (@mb IS NULL OR (m.RetiredAt < @mb AND m.RetiredWhy IN (N'superseded', N'abandoned', N'stopped run'))))"
    $markQ = $mark.Replace("'", "''")
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @c int = CONVERT(int, @CollectionId); DECLARE @lo bigint = CONVERT(bigint, @After); DECLARE @hi bigint = NULL; DECLARE @n bigint = 0;
DECLARE @mb datetime2(0) = TRY_CONVERT(datetime2(0), NULLIF(@MarkedBefore, N''), 126);
IF OBJECT_ID('sidata.$Table') IS NULL OR NOT $mark
BEGIN SELECT CAST(0 AS bigint) AS N, CAST(NULL AS bigint) AS Hi, CAST(1 AS int) AS Refused, CAST(0 AS int) AS Cap; RETURN; END
DECLARE @ix int = (SELECT COUNT(*) FROM sys.indexes WHERE object_id = OBJECT_ID('sidata.$Table') AND index_id > 0 AND is_hypothetical = 0 AND is_disabled = 0);
DECLARE @cap int = 4000 / CASE WHEN @ix < 1 THEN 1 ELSE @ix END;
IF @cap < 1 SET @cap = 1;
DECLARE @take int = TRY_CONVERT(int, @Batch);
IF @take IS NULL OR @take < 1 OR @take > @cap SET @take = @cap;
IF @lo <= 0 SELECT @lo = ISNULL(MIN($k) - 1, 0) FROM sidata.$Table WHERE CollectionId = @c;
BEGIN TRANSACTION;
IF OBJECT_ID('sidata.PublishedRun') IS NOT NULL
BEGIN
    DECLARE @lk int;
    EXEC @lk = sp_getapplock @Resource = N'sidata.PublishedRun', @LockMode = N'Shared', @LockOwner = N'Transaction', @LockTimeout = 10000;
    IF @lk < 0 BEGIN ROLLBACK TRANSACTION; SELECT CAST(0 AS bigint) AS N, CAST(NULL AS bigint) AS Hi, CAST(1 AS int) AS Refused, @cap AS Cap; RETURN; END
END
SELECT @hi = MAX(x.$k) FROM (SELECT TOP (@take) $k FROM sidata.$Table WHERE CollectionId = @c AND $k > @lo ORDER BY $k) AS x;
IF @hi IS NULL BEGIN COMMIT TRANSACTION; SELECT CAST(0 AS bigint) AS N, CAST(NULL AS bigint) AS Hi, CAST(0 AS int) AS Refused, @cap AS Cap; RETURN; END
IF OBJECT_ID('sidata.PublishedRun') IS NOT NULL
    EXEC sp_executesql N'DELETE FROM sidata.$Table WHERE CollectionId = @c AND $k > @lo AND $k <= @hi
  AND $markQ
  AND NOT EXISTS (SELECT 1 FROM sidata.PublishedRun AS p WHERE p.Name = N''current'' AND p.DetailedCollectionId = @c);
SET @n = @@ROWCOUNT;', N'@c int, @lo bigint, @hi bigint, @mb datetime2(0), @n bigint OUTPUT', @c = @c, @lo = @lo, @hi = @hi, @mb = @mb, @n = @n OUTPUT;
ELSE
BEGIN
    DELETE FROM sidata.$Table WHERE CollectionId = @c AND $k > @lo AND $k <= @hi AND $mark;
    SET @n = @@ROWCOUNT;
END
COMMIT TRANSACTION;
SELECT @n AS N, @hi AS Hi, CASE WHEN @n = 0 THEN 1 ELSE 0 END AS Refused, @cap AS Cap;
"@
}

function Invoke-SIDataRetireRangeDelete {
    <#
        #892 Removes one marked Detailed collection's rows of -Table range by range (Get-SIDataRetireRangeSql) until nothing
        is left, the database refuses, or -DeadlineUtc is reached (no new range after it -- checked after the pacing pause,
        review M7; the next call goes on from what is left). -MarkedBeforeUtc (review B1): only a mark the data sync made
        before it. Each range's size follows the last one's measured time (Get-SIDataNextSize, aim -TargetMs), never above the
        database's own cap (below lock escalation), and the database's load paces them (Invoke-SISqlPacing -Housekeeping: the
        removal waits until the database is calm -- below the LOW mark once it reached the HIGH one -- never past
        -DeadlineUtc, and the first range of a wake-up always runs). A measurement, never a limit on the work.
        Returns @{ Rows; Done ($true = nothing left); Refused ($true = the database refused) }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][ValidateSet('Finding', 'Recommendation')][string]$Table,
          [Parameter(Mandatory)][string]$CollectionId, [ref]$BatchSize, [long]$TargetMs = 5000, [datetime]$DeadlineUtc = [datetime]::MaxValue,
          $MarkedBeforeUtc = $null)
    $sql = Get-SIDataRetireRangeSql -Table $Table
    $mbText = if ($null -ne $MarkedBeforeUtc) { Format-SIDataSqlTime -Time ([datetime]$MarkedBeforeUtc).ToUniversalTime() } else { '' }
    $size = [long]5000; if ($BatchSize -and $BatchSize.Value -gt 0) { $size = [long]$BatchSize.Value }
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
    $after = '0'; $total = 0L; $done = $false; $refused = $false
    $g = { param($r, [string]$n) $v = $null
           if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $v = $r[$n] } }
           elseif ($r -is [System.Data.DataRow]) { $v = $r[$n] }
           elseif ($null -ne $r -and $r.PSObject.Properties[$n]) { $v = $r.$n }
           if ($v -is [System.DBNull]) { $null } else { $v } }
    while ($true) {
        # housekeeping: waits until the database is calm (never past the deadline); the first range of a wake-up always runs
        if ($paced) {
            $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Housekeeping -DeadlineUtc $DeadlineUtc
            if ($pace.Shrink) { $size = [Math]::Max(1L, [long][Math]::Floor($size / 2)) }
            if ($pace.PSObject.Properties['Deadline'] -and $pace.Deadline) { break }
        }
        if ([datetime]::UtcNow -ge $DeadlineUtc) { break }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $row = @(@(& $Invoke $sql @{ CollectionId = $CollectionId; After = $after; Batch = $size; MarkedBefore = $mbText } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
        $nv = & $g $row 'N'; $hi = & $g $row 'Hi'; $rf = & $g $row 'Refused'; $cap = & $g $row 'Cap'
        if ($null -ne $nv) { $total += [long]$nv }
        if ($null -ne $rf -and [int]$rf -eq 1) { $refused = $true; break }
        if ($null -eq $hi) { $done = $true; break }
        $after = ([long]$hi).ToString([Globalization.CultureInfo]::InvariantCulture)
        $size = Get-SIDataNextSize -Current $size -ElapsedMs $lastMs -TargetMs $TargetMs -Minimum 1
        # the database's cap is the most a range takes: a larger asked size only shows up as the same cap
        if ($null -ne $cap -and [long]$cap -gt 0 -and $size -gt [long]$cap) { $size = [long]$cap }
    }
    if ($BatchSize) { $BatchSize.Value = $size }
    [pscustomobject]@{ Rows = $total; Done = $done; Refused = $refused }
}

function Format-SIDataRetentionText {
    <# PURE. The one plain line: what was kept, what was removed and how many rows per table. -Result: Invoke-SIDataCollectionRetention's (before its Text). #>
    param([Parameter(Mandatory)]$Result, [switch]$DryRun)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $label = @{ Detailed = 'Risk Analysis'; Summary = 'Risk Analysis Summary' }
    $kept = foreach ($gr in 'Detailed', 'Summary') {
        $k = @(@($Result.Plan) | Where-Object { $_ -and $_.Grain -eq $gr -and $_.Action -eq 'Keep' -and $_.Status -eq 'Complete' } | Sort-Object CollectionTime -Descending)
        if ($k.Count) { '{0} {1}' -f $label[$gr], ((@($k | ForEach-Object { [string]::Format($inv, '{0:yyyy-MM-dd HH:mm}', $_.CollectionTime) })) -join ' + ') }
    }
    $keptText = if (@($kept).Count) { 'kept ' + (@($kept) -join '; ') + ' (UTC)' } else { 'no complete collection yet' }
    $acted = @(@($Result.Plan) | Where-Object { $_ -and $_.Action -in 'Retire', 'Finish' })
    if ($DryRun) {
        return ('{0}; would remove the rows of {1} older or abandoned collection(s) -- nothing is written in a dry run' -f $keptText, $acted.Count)
    }
    $done = @($Result.Removed)
    $refusedText = ''
    if (@($Result.Refused).Count) { $refusedText = (' {0} collection(s) were not removed: the database did not confirm newer complete collections.' -f @($Result.Refused).Count) }
    # #816: a removal cut short by its time budget -- the collection is marked (never shown again) and the next call finishes it
    $stopped = $Result.PSObject.Properties['Stopped'] -and $Result.Stopped
    if ($stopped) { $refusedText += [string]::Format($inv, ' The time budget of this step ended part way ({0:N0} finding row(s) removed so far) -- the rest is removed next time.', [long]$Result.Rows['findings']) }
    if (-not $done.Count) { return ('{0}; {1}{2}' -f $keptText, $(if ($stopped) { 'removal in progress.' } else { 'nothing older to remove.' }), $refusedText) }
    $ab = @($done | Where-Object { $_.Why -in 'abandoned', 'stopped run' }).Count
    $r = $Result.Rows
    $text = [string]::Format($inv, '{0}; removed the rows of {1} collection(s) ({2} abandoned by a run that stopped, {3} older) -- findings {4:N0}, recommendations {5:N0}, prepared issue rows {6:N0}, staged rows {7:N0}, Summary rows {8:N0}, Summary assets {9:N0}. Their day totals stay for the trends.',
        $keptText, $done.Count, $ab, ($done.Count - $ab), $r['findings'], $r['recommendations'], $r['issueRows'], ($r['stagedRows'] + $r['defenderKeys']), $r['summaryRows'], $r['summaryAssets'])
    $text + $refusedText
}

function Invoke-SIDataCollectionRetention {
    <#
        THE STEP (see above): reads every collection, plans, marks and removes in batches; a dry run plans only. NEVER
        throws -- a failure is Status 'failed' with its Error, and the next run tries again (a marked collection with rows
        left is finished then). Returns @{ Status (ok | nothing | dry-run | failed); Plan; Removed (the plan items done);
        Refused; Rows (per table); Text (the one log line); Error }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log,
          # the FIRST batch's size; every next one follows the last one's measured time (Invoke-SIDataBatchedDelete)
          [long]$BatchSize = 5000,
          # #746: a stopped run's collection older than this many days, with a newer run of its grain after it, is abandoned
          [int]$StaleDays = 7, [datetime]$NowUtc = [datetime]::UtcNow,
          # #816: given ONLY when no pipeline run is running -- a Detailed collection still loading after this many hours is a
          # stopped run's (Get-SIDataCollectionRetentionPlan -IdleStaleHours); 0 = that rule off
          [double]$IdleStaleHours = 0,
          # #816: the step's own time budget (the pipeline runner's wake-up): no new batch after it; the next call finishes
          # what was marked (Finish). 0 = no budget (the data sync)
          [int]$TimeBudgetSeconds = 0,
          # #834: MARK only -- the collections the plan retires are marked (RetiredAt: never derived, prepared or shown again,
          # the views and their own index ranges skip them at once) and NO row is removed. The data sync marks right after its
          # loads (so it never derives a collection it removes in the same run), and -- when the pipeline started it -- leaves
          # the rows to the pipeline runner's wake-ups, which remove them while no run is running (Invoke-SIDataStoppedRunCleanup:
          # 'Finish' for a marked collection with rows left), never on a database the sync itself has saturated.
          [switch]$MarkOnly,
          # with -MarkOnly: the plain words of who removes the rows (said in the line)
          [string]$RowsRemovedBy = '',
          # #882: the owner floor (Get-SIDataLoadingOwnerFloor) in place of -IdleStaleHours, with its plain reason; and
          # -OnlyWhy: act only on the plan's items of these kinds (e.g. 'stopped run' while a pipeline run is going)
          $IdleBeforeUtc = $null, [string]$IdleReason = '', [string[]]$OnlyWhy = @(),
          # #892 -FinishOnly: ONLY the collections that are marked already and still hold rows are removed (Finish); nothing
          # is newly marked, nothing else in the plan is acted on. The pipeline runner's wake-up while a run is going.
          # -FinishFloorUtc (required with -FinishOnly: the owner floor, Get-SIDataLoadingOwnerFloor): a marked collection
          # that is NOT complete and started at or after it is left alone -- a live run may own it. Never the published one
          # (the plan keeps it, and every range statement refuses it).
          # -FinishMarkedBeforeUtc (required with -FinishOnly, review B1: the start of the running pipeline run): ONLY marks the data
          # sync made (RetiredWhy superseded / abandoned) and the 'stopped run' marks (#882) made BEFORE it -- nothing in this run
          # can be writing those. A 'stopped run' mark made while THIS run goes can hit a collection the data sync is still
          # loading: its rows wait for the next run or a wake-up with no run going. The database checks the same on every
          # statement. FAIL SAFE: none given = nothing removed;
          # no time budget = nothing removed (review M5).
          [switch]$FinishOnly, $FinishFloorUtc = $null, $FinishMarkedBeforeUtc = $null)
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    $staleText = if ($StaleDays -gt 0) { Format-SIDataSqlTime -Time ($NowUtc.ToUniversalTime().AddDays(-$StaleDays)) } else { '' }
    $idleText = if ($null -ne $IdleBeforeUtc) { Format-SIDataSqlTime -Time (([datetime]$IdleBeforeUtc).ToUniversalTime()) } elseif ($IdleStaleHours -gt 0) { Format-SIDataSqlTime -Time ($NowUtc.ToUniversalTime().AddHours(-$IdleStaleHours)) } else { '' }
    $deadline = if ($TimeBudgetSeconds -gt 0) { [datetime]::UtcNow.AddSeconds($TimeBudgetSeconds) } else { [datetime]::MaxValue }
    $out = [ordered]@{ Status = 'ok'; Plan = @(); Removed = @(); Refused = @(); Stopped = $false; Text = ''; Error = ''
                       Rows = [ordered]@{ findings = 0L; recommendations = 0L; issueRows = 0L; stagedRows = 0L; defenderKeys = 0L; summaryRows = 0L; summaryAssets = 0L } }
    $key = @{ Finding = 'findings'; Recommendation = 'recommendations'; IssueContext = 'issueRows'; RaStage = 'stagedRows'; RaDefenderKey = 'defenderKeys'; SummaryRow = 'summaryRows'; SummaryAsset = 'summaryAssets' }
    try {
        # the pacing of the batched deletes says its line through this step's log
        if (Get-Command -Name Get-SISqlPacer -ErrorAction SilentlyContinue) { $null = Get-SISqlPacer -Invoke $Invoke -Log $Log }
        $state = @(@(& $Invoke (Get-SIDataRetentionStateSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        if (-not $state.Count) {
            $out.Status = 'nothing'
            $out.Text = 'no collection is stored yet (or the database does not have the retention mark yet -- the updater adds it) -- nothing removed'
            & $Log 'INFO' ('collections : ' + $out.Text)
            return [pscustomobject]$out
        }
        $links = @(@(& $Invoke (Get-SIDataRetentionCarrySql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        # the plan answers as ONE array (', $out.ToArray()'): assigned first, then enumerated -- @(...) around the call would
        # make it a list holding that array as its one item
        $planRaw = Get-SIDataCollectionRetentionPlan -Collections $state -CarryLinks $links -NowUtc $NowUtc -StaleDays $StaleDays -IdleStaleHours $IdleStaleHours -IdleBeforeUtc $IdleBeforeUtc -IdleReason $IdleReason
        $plan = @(foreach ($x in @($planRaw)) { if ($null -ne $x) { $x } })
        # #882: only the kinds asked for are acted on (the rest of the plan is kept as it is, and said as kept)
        if (@($OnlyWhy).Count) { $plan = @(foreach ($x in $plan) { if ($x.Action -in 'Retire', 'Finish' -and @($OnlyWhy) -notcontains [string]$x.Why) { $x.Action = 'Keep'; $x.Reason = 'left to the data sync and to a wake-up with no run running' }; $x }) }
        # #892: only what is marked already; FAIL SAFE -- no floor, no run start or no budget = nothing is removed
        $markedBefore = $null
        if ($FinishOnly) {
            $floor = if ($null -ne $FinishFloorUtc) { ([datetime]$FinishFloorUtc).ToUniversalTime() } else { $null }
            $markedBefore = if ($null -ne $FinishMarkedBeforeUtc) { ([datetime]$FinishMarkedBeforeUtc).ToUniversalTime() } else { $null }
            $plan = @(foreach ($x in $plan) {
                if ($x.Action -eq 'Retire') { $x.Action = 'Keep'; $x.Reason = 'not marked by this step -- only collections marked already are removed while a run is going' }
                elseif ($x.Action -eq 'Finish' -and $TimeBudgetSeconds -le 0) { $x.Action = 'Keep'; $x.Reason = 'no time budget was given -- nothing is removed while a run is going' }
                elseif ($x.Action -eq 'Finish' -and $null -eq $floor) { $x.Action = 'Keep'; $x.Reason = 'which collection the live run owns is not known -- nothing is removed' }
                elseif ($x.Action -eq 'Finish' -and $null -eq $markedBefore) { $x.Action = 'Keep'; $x.Reason = 'when the running pipeline run started is not known -- nothing is removed' }
                # 2026-10-23 (installs at 45-61 % of the database maximum, 4-7 'Loading' collections no live run owns, some with
                # 1.4-1.8 M rows: a run is nearly always going there, so a wake-up with no run going never came): a 'stopped run'
                # mark (#882) made BEFORE the running pipeline run started goes the same way as the data sync's marks -- the
                # run that could have been loading it is over, and a marked collection is never derived or shown again. A mark
                # made during this run still waits (the rule below), and the owner floor still applies.
                elseif ($x.Action -eq 'Finish' -and [string]$x.RetiredWhy -notin 'superseded', 'abandoned', 'stopped run') { $x.Action = 'Keep'; $x.Reason = 'marked for another reason -- its rows are removed by a wake-up with no run going' }
                elseif ($x.Action -eq 'Finish' -and ($null -eq $x.RetiredAt -or $x.RetiredAt -ge $markedBefore)) { $x.Action = 'Keep'; $x.Reason = 'marked after the running pipeline run started -- its rows are removed once that run is over' }
                elseif ($x.Action -eq 'Finish' -and $x.Status -ne 'Complete' -and $x.CollectionTime -ge $floor) { $x.Action = 'Keep'; $x.Reason = 'still loading and started after the Risk Analysis going now -- a live run may own it' }
                $x })
        }
        $out.Plan = $plan
        if ($DryRun) {
            $out.Status = 'dry-run'
            $out.Text = Format-SIDataRetentionText -Result ([pscustomobject]$out) -DryRun
            & $Log 'INFO' ('collections : ' + $out.Text)
            return [pscustomobject]$out
        }
        $batch = [long][Math]::Max(1L, $BatchSize)
        $rangeBatch = @{}   # #892 each large table keeps its own range size (each starts at -BatchSize)
        $lockBound = @{}    # each batched table's lock-escalation bound (Get-SIDataRetireBatchBound)
        $marked = New-Object System.Collections.Generic.List[object]
        foreach ($p in @($plan | Where-Object { $_.Action -in 'Retire', 'Finish' } | Sort-Object CollectionTime)) {
            # #834 -MarkOnly: a collection marked already (Finish) is left as it is; a new one is only marked
            if ($MarkOnly -and $p.Action -ne 'Retire') { $marked.Add($p); continue }
            if ([datetime]::UtcNow -ge $deadline) { $out.Stopped = $true; break }
            $tText = Format-SIDataSqlTime -Time $p.CollectionTime
            $prm = @{ CollectionId = $(if ($null -ne $p.CollectionId) { [string]$p.CollectionId } else { '' }); CollectionTime = $tText; RunKey = ('{0}|{1}' -f $p.Grain, $tText) }
            if ($p.Action -eq 'Retire') {
                # #816: the idle rule's collection is accepted by the database only through its own guarded case
                $isIdle = ($p.Why -eq 'stopped run' -and $p.Grain -eq 'Detailed' -and $idleText)
                $mp = @{ CollectionId = $prm.CollectionId; CollectionTime = $tText; Why = [string]$p.Why; StaleBefore = $staleText }
                if ($isIdle) { $mp['IdleBefore'] = $idleText }
                $m = [int](& $Invoke (Get-SIDataRetireMarkSql -Grain $p.Grain -Idle:([bool]$isIdle)) $mp 'scalar')
                if ($m -ne 1) { $out.Refused += $p; continue }
                if ($MarkOnly) { $marked.Add($p); continue }
            }
            $whole = $true; $refusedHere = $false
            foreach ($t in $script:SIDataRetireTables[$p.Grain]) {
                if ([datetime]::UtcNow -ge $deadline) { $whole = $false; break }
                if ($p.Grain -eq 'Detailed' -and $script:SIDataRetireRangeKeys.Contains($t) -and $prm.CollectionId) {
                    # #892 the large tables in key ranges; a range cut short by the budget leaves the collection unfinished
                    $rb = if ($rangeBatch.ContainsKey($t)) { [long]$rangeBatch[$t] } else { [long][Math]::Max(1L, $BatchSize) }
                    $rr = Invoke-SIDataRetireRangeDelete -Invoke $Invoke -Table $t -CollectionId $prm.CollectionId -BatchSize ([ref]$rb) -DeadlineUtc $deadline -MarkedBeforeUtc $markedBefore
                    $rangeBatch[$t] = $rb
                    $out.Rows[$key[$t]] += [long]$rr.Rows
                    # review M3: a range the database refused is never counted as removed
                    if ($rr.Refused) { $refusedHere = $true; $whole = $false; break }
                    if (-not $rr.Done) { $whole = $false; break }
                    continue
                }
                $bp = $prm; $bsql = Get-SIDataRetireBatchSql -Grain $p.Grain -Table $t
                if ($null -ne $markedBefore -and $p.Grain -eq 'Detailed') { $bsql = Get-SIDataRetireBatchSql -Grain $p.Grain -Table $t -DataSyncMarkedBefore; $bp = @{} + $prm; $bp['MarkedBefore'] = (Format-SIDataSqlTime -Time $markedBefore) }
                # the batches stay below lock escalation (the key ranges' rule, worked out once per table) and wait for the
                # database to be calm (housekeeping)
                if (-not $lockBound.ContainsKey($t)) { $lockBound[$t] = Get-SIDataRetireBatchBound -Invoke $Invoke -Table $t }
                $hkStop = [ref]$false
                $n = Invoke-SIDataBatchedDelete -Invoke $Invoke -Sql $bsql -Params $bp -BatchSize ([ref]$batch) -DeadlineUtc $deadline -Housekeeping -LockBound ([long]$lockBound[$t]) -Stopped $hkStop
                $out.Rows[$key[$t]] += [long]$n
                # the wait reached the deadline: this table may still hold rows -- the next tables (the finding rows last)
                # wait for the next call, so a collection with rows left always shows as one (HasRows)
                if ($hkStop.Value) { $whole = $false; break }
            }
            # review M3: the database refused this collection's rows (not marked as asked, or the published run) -- said as refused,
            # never as removed; the next collection is looked at
            if ($refusedHere) { $out.Refused += $p; continue }
            # a removal its time budget cut short is marked (RetiredAt) and finished by the next call (Finish) -- never shown again
            if (-not $whole -or [datetime]::UtcNow -ge $deadline) { $out.Stopped = $true; break }
            $out.Removed += $p
        }
        $out['Marked'] = $marked.ToArray()
        if ($MarkOnly) {
            $inv = [Globalization.CultureInfo]::InvariantCulture
            $by = if ($RowsRemovedBy) { $RowsRemovedBy } else { 'by the end of this data sync' }
            $newly = @($marked | Where-Object { $_.Action -eq 'Retire' }).Count
            $out.Text = if ($marked.Count -eq 0) { 'nothing older to remove' }
                        else { [string]::Format($inv, '{0} older or abandoned collection(s) are marked removed{1} -- never shown again; their rows are removed {2}', $marked.Count, $(if ($newly -lt $marked.Count) { [string]::Format($inv, ' ({0} newly)', $newly) } else { '' }), $by) }
            if (@($out.Refused).Count) { $out.Text += [string]::Format($inv, '; {0} collection(s) were not marked: the database did not confirm newer complete collections', @($out.Refused).Count) }
            & $Log 'INFO' ('collections : ' + $out.Text)
            return [pscustomobject]$out
        }
        $out.Text = Format-SIDataRetentionText -Result ([pscustomobject]$out)
        & $Log $(if (@($out.Removed).Count) { 'OK' } else { 'INFO' }) ('collections : ' + $out.Text)
    } catch {
        $out.Status = 'failed'; $out.Error = $_.Exception.Message
        $out.Text = ('the older collections were not removed this run ({0}) -- nothing current is affected; the next run tries again' -f $_.Exception.Message)
        & $Log 'WARN' ('collections : ' + $out.Text)
    }
    [pscustomobject]$out
}

# ------------------------------------------------------------------------------------------------------------------
#  STOPPED RUNS (#816, owner 2026-10-20: "put #816 cleanup in the next release too"). A run that failed or was cancelled
#  leaves its Detailed collection 'Loading' with its rows (at a large install ~1 M per attempt; 80 % of one install's
#  sidata.Finding). The collections' retention above removes them, but only at the END of a SUCCESSFUL data sync -- which
#  an install whose runs keep failing never reaches. So the pipeline runner calls this on its wake-up, ONLY while no
#  pipeline run is running: the same plan, marks and batched deletes (Invoke-SIDataCollectionRetention), plus the idle rule
#  (a collection still loading after -IdleStaleHours with no run running is a stopped run's), inside a time budget. The
#  published run's collection, a complete one the views read and a result waiting for the data sync are never touched.
#  Afterwards it records how many collections are still loading and their rows (cfg.InstallState 'StoppedRuns').
# ------------------------------------------------------------------------------------------------------------------

function Get-SIDataRunByPipelineSql {
    <# The settings database: how many of this job's steps run in a running pipeline run (0 = not started by the pipeline). #>
    "IF OBJECT_ID(N'cfg.FlowStepRun') IS NULL OR OBJECT_ID(N'cfg.FlowRun') IS NULL SELECT CAST(0 AS int) ELSE SELECT COUNT(*) FROM cfg.FlowStepRun AS s JOIN cfg.FlowRun AS r ON r.FlowRunId = s.FlowRunId WHERE s.Job = @Job AND s.State IN (N'Starting', N'Running') AND r.State = N'Running';"
}

function Test-SIDataRunByPipeline {
    <#
        #834 Did the pipeline start this data sync? Then the pipeline runner's wake-ups remove the rows of the collections it
        marks, once the run has ended (Invoke-SIDataStoppedRunCleanup). Not shown -- no seam, no record, a database that
        cannot be read -- is $false: the data sync removes the rows itself, as before. Never throws.
    #>
    param([scriptblock]$Invoke, [string]$Job = 'asset-datasync')
    if (-not $Invoke) { return $false }
    try { return ([int](& $Invoke (Get-SIDataRunByPipelineSql) @{ Job = $Job } 'scalar') -gt 0) } catch { return $false }
}

function Get-SIDataLoadingStateSql {
    <# The Detailed collections still 'Loading' (not retired) and -- -WithRows -- their finding rows (counted on the clustered
       key per collection; else Rows = -1, not counted): one row (N, Rows). 0 / 0 on a database without the tables or the mark. #>
    param([switch]$WithRows)
    $rows = if ($WithRows) { '(SELECT COUNT_BIG(*) FROM sidata.Finding AS f WHERE f.CollectionId = c.CollectionId)' } else { 'CAST(0 AS bigint)' }
    $sum = if ($WithRows) { 'ISNULL(SUM(x.R), 0)' } else { 'CAST(-1 AS bigint)' }
    @"
SET NOCOUNT ON;
IF OBJECT_ID('sidata.Collection') IS NULL OR OBJECT_ID('sidata.Finding') IS NULL OR COL_LENGTH('sidata.Collection', 'RetiredAt') IS NULL
BEGIN SELECT CAST(0 AS int) AS N, CAST(0 AS bigint) AS [Rows]; RETURN; END
SELECT COUNT(*) AS N, $sum AS [Rows]
FROM (SELECT c.CollectionId, $rows AS R
      FROM sidata.Collection AS c WHERE c.Kind = N'Detailed' AND c.Status <> N'Complete' AND c.RetiredAt IS NULL) AS x;
"@
}

function Get-SIDataStoppedRunsRecordSql {
    <# The ONE statement that records the state in cfg.InstallState 'StoppedRuns' (settings database; the engine role holds
       SELECT / INSERT / UPDATE there). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'StoppedRuns')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'StoppedRuns';
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'StoppedRuns', @Value, NULL, @By);
END
'@
}

function Get-SIDataStoppedRunsValue {
    <# PURE. The recorded value: compact JSON under 400 characters -- { loading, loadingRows, removed, removedRows, stopped, at }. #>
    param([int]$Loading = 0, [long]$LoadingRows = 0, [int]$Removed = 0, [long]$RemovedRows = 0, [bool]$Stopped = $false, [datetime]$AtUtc = [datetime]::UtcNow)
    ([ordered]@{ loading = $Loading; loadingRows = $LoadingRows; removed = $Removed; removedRows = $RemovedRows; stopped = $Stopped
                 at = $AtUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } | ConvertTo-Json -Compress)
}

function Get-SIDataRaStepOwnerSql {
    <# #882 The settings database: the Risk Analysis Detailed steps of RUNNING pipeline runs that are still open -- how many
       (Open) and when the oldest started (Since; NULL when none, or when an open one has no start recorded: Unknown = 1). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.FlowStepRun') IS NULL OR OBJECT_ID(N'cfg.FlowRun') IS NULL
BEGIN SELECT CAST(-1 AS int) AS [Open], CAST(NULL AS datetime2(3)) AS Since, CAST(1 AS int) AS Unknown; RETURN; END
SELECT COUNT(*) AS [Open], MIN(s.StartedUtc) AS Since, CASE WHEN SUM(CASE WHEN s.StartedUtc IS NULL THEN 1 ELSE 0 END) > 0 THEN 1 ELSE 0 END AS Unknown
FROM cfg.FlowStepRun AS s JOIN cfg.FlowRun AS r ON r.FlowRunId = s.FlowRunId
WHERE s.Job = @Job AND s.State IN (N'Starting', N'Running') AND r.State = N'Running';
'@
}

function Get-SIDataLoadingOwnerFloor {
    <#
        PURE. #882 -- WHICH 'Loading' COLLECTION DOES A LIVE RUN STILL OWN? (largest tenant 2026-10-21: collections 20, 21, 23
        and 24 stayed 'Loading' after broken runs; at that install a pipeline run is nearly always going, so #816's cleanup --
        which waits for NO run to be running -- never reached them.) The Risk Analysis Detailed producer begins its collection
        when it starts, so the only collection a live run can still be writing is one that started at or after the oldest
        Risk Analysis work that is going now: an open Detailed step of a running pipeline run (-OpenSteps / -StepSince /
        -StepUnknown) or a running execution of its job (-ProbeKnown / -ProbeSince: the job's executions, also one started by
        hand). Returns @{ Before; Why }: Before = that start minus 5 minutes (the clocks' slack) -- or, when nothing of Risk
        Analysis is going at all, -NowUtc minus 5 minutes; every not-complete collection that started BEFORE it, not pending,
        not published, belongs to no live run. Before = $null (Why says why) when it cannot be shown: an open step without a
        start, or no open step and the executions could not be read. FAIL SAFE: unknown = nothing is touched.
    #>
    param([int]$OpenSteps = 0, $StepSince = $null, [bool]$StepUnknown = $false, [bool]$ProbeKnown = $false, $ProbeSince = $null,
          [datetime]$NowUtc = [datetime]::UtcNow)
    $o = { param($b, $w) [pscustomobject]@{ Before = $b; Why = [string]$w } }
    if ($OpenSteps -lt 0) { return (& $o $null 'the run records could not be read') }
    if ($OpenSteps -gt 0 -and ($StepUnknown -or $null -eq $StepSince)) { return (& $o $null 'an open Risk Analysis step has no start recorded') }
    # the job's executions are always needed: a step can FOLLOW an execution that started before it (a job that was
    # already running), whose collection then started before the step did
    if (-not $ProbeKnown) { return (& $o $null 'whether Risk Analysis runs right now could not be read') }
    $c = New-Object System.Collections.Generic.List[datetime]
    if ($OpenSteps -gt 0) { $c.Add(([datetime]$StepSince).ToUniversalTime()) }
    if ($null -ne $ProbeSince) { $c.Add(([datetime]$ProbeSince).ToUniversalTime()) }
    if (-not $c.Count) { return (& $o $NowUtc.ToUniversalTime().AddMinutes(-5) 'no Risk Analysis runs now') }
    $min = ($c | Sort-Object | Select-Object -First 1)
    & $o $min.AddMinutes(-5) ([string]::Format([Globalization.CultureInfo]::InvariantCulture, 'the Risk Analysis going now started {0:yyyy-MM-dd HH:mm} UTC', $min))
}

function Invoke-SIDataStoppedRunCleanup {
    <#
        THE PIPELINE RUNNER'S CALL (#816). -Invoke: the data database (sql, params, mode 'reader' | 'nonquery' | 'scalar');
        -SettingsInvoke: the settings database (cfg.FlowRun, cfg.InstallState), same seam. Does nothing -- not one statement on
        the data database -- while a pipeline run is running, or when that cannot be read. NEVER throws. Returns
        @{ Status (ok | skipped | failed); Why; Retention (Invoke-SIDataCollectionRetention's result); Loading; LoadingRows }.
        #882 -RaRunning { } -> @{ Execution; StartedUtc } or $null (the Risk Analysis Detailed job's running execution; a throw
        = cannot be read): WHILE a pipeline run is running, a Detailed collection still 'Loading' that NO live run owns
        (Get-SIDataLoadingOwnerFloor) is MARKED retired at once -- never derived, prepared or shown again -- and its rows are
        removed by a later wake-up with no run running (Finish). Only those ('stopped run'); never a complete collection,
        never the published one, never a result waiting for the data sync, never the collection the live run writes -- the
        plan AND the database's mark refuse them. Without the seam a running run means nothing is touched, as before.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$SettingsInvoke, [double]$IdleStaleHours = 24,
          [int]$TimeBudgetSeconds = 120, [scriptblock]$Log, [datetime]$NowUtc = [datetime]::UtcNow, [string]$By = 'caj-si-flow',
          [scriptblock]$RaRunning, [string]$RaJob = 'risk-analysis-detailed')
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    $out = [ordered]@{ Status = 'skipped'; Why = ''; Retention = $null; Loading = $null; LoadingRows = $null }
    try {
        if (-not $SettingsInvoke) { $out.Why = 'the run records cannot be read here -- stopped runs are removed by the data sync'; return [pscustomobject]$out }
        $running = $null
        try { $running = [int](& $SettingsInvoke "IF OBJECT_ID('cfg.FlowRun') IS NULL SELECT CAST(-1 AS int) ELSE SELECT COUNT(*) FROM cfg.FlowRun WHERE State = N'Running'" @{} 'scalar') } catch { $running = $null }
        if ($null -eq $running -or $running -lt 0) { $out.Why = 'the run records could not be read -- nothing removed'; return [pscustomobject]$out }
        if ($running -gt 0 -and $RaRunning -and $IdleStaleHours -gt 0) {
            # #882: a run is going -- only the 'Loading' collections no live run owns are marked (no row is removed now)
            $own = $null
            try {
                $os = @(@(& $SettingsInvoke (Get-SIDataRaStepOwnerSql) @{ Job = $RaJob } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
                $gv = { param($n) if ($null -eq $os) { $null } elseif ($os -is [System.Collections.IDictionary]) { $os[$n] } else { $os.$n } }
                $open = if ($null -eq $os) { -1 } else { [int](& $gv 'Open') }
                $sinceV = & $gv 'Since'; if ($sinceV -is [System.DBNull]) { $sinceV = $null }
                $unk = [int](& $gv 'Unknown') -eq 1
                $pk = $false; $ps = $null
                try { $px = & $RaRunning; $pk = $true; if ($px -and $px.StartedUtc) { $ps = ([datetime]$px.StartedUtc).ToUniversalTime() } elseif ($px) { $pk = $false } } catch { $pk = $false }
                $own = Get-SIDataLoadingOwnerFloor -OpenSteps $open -StepSince $sinceV -StepUnknown $unk -ProbeKnown $pk -ProbeSince $ps -NowUtc $NowUtc
            } catch { $own = [pscustomobject]@{ Before = $null; Why = $_.Exception.Message } }
            if ($null -eq $own -or $null -eq $own.Before) {
                $out.Why = 'a pipeline run is running and which collection it owns could not be shown ({0}) -- nothing is touched' -f $(if ($own) { $own.Why } else { 'no answer' })
                return [pscustomobject]$out
            }
            $why = [string]::Format([Globalization.CultureInfo]::InvariantCulture, 'its run stopped before it was complete: no live run owns it ({0}; it started before that)', $own.Why)
            $started = [datetime]::UtcNow
            $ret = Invoke-SIDataCollectionRetention -Invoke $Invoke -Log $Log -NowUtc $NowUtc -IdleBeforeUtc $own.Before -IdleReason $why -OnlyWhy @('stopped run') -MarkOnly `
                       -RowsRemovedBy 'by this and the next wake-ups of the pipeline runner, in key ranges' -TimeBudgetSeconds $TimeBudgetSeconds
            $out.Retention = $ret
            # #892 (large install 2026-10-23: 3.75 M of 7.69 M finding rows, about 75 GB, belonged to collections marked days
            # before -- a run is nearly always going there, so the removal never came): the rows of collections that are
            # marked ALREADY are removed now, in key ranges, paced by the database's load, inside what is left of this
            # wake-up's time budget -- the next wake-up goes on. Never one a live run may own (the same floor), never the
            # published one, never a kept one (they are not marked: the database refuses those marks).
            # Review B1: ONLY marks made BEFORE the running pipeline run started (the data sync's superseded / abandoned and,
            # since 2026-10-23, the 'stopped run' marks of earlier wake-ups) -- a 'stopped run' mark made while THIS run goes
            # (above) can hit a collection the data sync is still loading from Log Analytics; its rows wait for the next run.
            # Review M5: no budget = nothing removed.
            $runStart = $null
            try {
                $rs = & $SettingsInvoke "IF OBJECT_ID('cfg.FlowRun') IS NULL SELECT CAST(NULL AS datetime2(0)) ELSE SELECT MIN(StartedUtc) FROM cfg.FlowRun WHERE State = N'Running'" @{} 'scalar'
                if ($rs -is [datetime]) { $runStart = [datetime]::SpecifyKind([datetime]$rs, [DateTimeKind]::Utc) }
            } catch { $runStart = $null }
            $left = if ($TimeBudgetSeconds -gt 0) { [int][Math]::Floor($TimeBudgetSeconds - ([datetime]::UtcNow - $started).TotalSeconds) } else { 0 }
            $fin = $null
            if ($left -gt 0 -and $null -ne $runStart) {
                $fin = Invoke-SIDataCollectionRetention -Invoke $Invoke -Log $Log -NowUtc $NowUtc -FinishOnly -FinishFloorUtc $own.Before -FinishMarkedBeforeUtc $runStart -TimeBudgetSeconds $left
            }
            $out['Finished'] = $fin
            $out.Status = if ($ret.Status -eq 'failed' -or ($fin -and $fin.Status -eq 'failed')) { 'failed' } else { 'ok' }
            $out.Why = 'a pipeline run is running -- collections no live run owns were marked; the rows of collections the data sync marked before this run began are removed in key ranges inside this wake-up''s time budget'
            return [pscustomobject]$out
        }
        if ($running -gt 0) { $out.Why = 'a pipeline run is running -- stopped runs are removed when none is'; return [pscustomobject]$out }
        $ret = Invoke-SIDataCollectionRetention -Invoke $Invoke -Log $Log -NowUtc $NowUtc -IdleStaleHours $IdleStaleHours -TimeBudgetSeconds $TimeBudgetSeconds
        $out.Retention = $ret
        $out.Status = if ($ret.Status -eq 'failed') { 'failed' } else { 'ok' }
        $removed = @($ret.Removed).Count; $removedRows = if ($ret.Rows) { [long]$ret.Rows['findings'] } else { 0L }
        # the rows of what is still loading are counted on the first wake-up of each hour, or when something was removed --
        # never every five minutes on a database that may be at its limit
        $withRows = ($NowUtc.ToUniversalTime().Minute -lt 5 -or $removed -gt 0 -or $removedRows -gt 0)
        $st = $null
        if ($withRows) { $st = @(@(& $Invoke (Get-SIDataLoadingStateSql -WithRows) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1 }
        if ($st) {
            $g = { param($n) if ($st -is [System.Collections.IDictionary]) { $st[$n] } else { $st.$n } }
            $out.Loading = [int](& $g 'N'); $out.LoadingRows = [long](& $g 'Rows')
            $v = Get-SIDataStoppedRunsValue -Loading $out.Loading -LoadingRows $out.LoadingRows -Removed $removed -RemovedRows $removedRows -Stopped ([bool]$ret.Stopped) -AtUtc $NowUtc
            try { $null = & $SettingsInvoke (Get-SIDataStoppedRunsRecordSql) @{ Value = $v; By = $By } 'nonquery' } catch { & $Log 'INFO' ('collections : the state of stopped runs could not be recorded ({0})' -f $_.Exception.Message) }
            if ($out.Loading -gt 0) { & $Log 'INFO' ([string]::Format([Globalization.CultureInfo]::InvariantCulture, 'collections : {0} Risk Analysis collection(s) still loading ({1:N0} finding rows) -- removed once they are older than {2:0.#} h with no run running, or a newer run is complete', $out.Loading, $out.LoadingRows, $IdleStaleHours)) }
        }
    } catch {
        $out.Status = 'failed'; $out.Why = $_.Exception.Message
        & $Log 'WARN' ('collections : stopped runs were not removed this time ({0}) -- nothing current is affected; the next wake-up tries again' -f $_.Exception.Message)
    }
    [pscustomobject]$out
}

# ------------------------------------------------------------------------------------------------------------------
#  HOW FULL THE DATABASE IS (#717 (3)): the space its data uses against its maximum size, read with data rights only (the
#  same reading as the heartbeat's sqlUsedMb / sqlMaxMb). Above -WarnPercent (70) the run says so in plain words.
# ------------------------------------------------------------------------------------------------------------------

function Get-SIDataFillSql {
    # ONE value, 'used|max' in MB -- read as a scalar
    "SET NOCOUNT ON; SELECT CONCAT((SELECT SUM(CAST(FILEPROPERTY(name, 'SpaceUsed') AS bigint)) * 8 / 1024 FROM sys.database_files WHERE type_desc = 'ROWS'), '|', CAST(DATABASEPROPERTYEX(DB_NAME(), 'MaxSizeInBytes') AS bigint) / 1048576);"
}

function Get-SIDataFillVerdict {
    <#
        PURE. 'used|max' (MB) -> @{ UsedMb; MaxMb; Percent; Warn; Text }. Percent is $null when either is unknown (a database
        without a maximum, an unreadable value) -- never guessed. Warn = Percent above -WarnPercent.
    #>
    param($Value, [int]$WarnPercent = 70)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $o = [ordered]@{ UsedMb = $null; MaxMb = $null; Percent = $null; Warn = $false; Text = '' }
    if ($null -ne $Value -and $Value -isnot [System.DBNull]) {
        $p = ([string]$Value).Split('|'); $n = [long]0
        if ($p.Count -ge 1 -and [long]::TryParse($p[0].Trim(), [Globalization.NumberStyles]::Integer, $inv, [ref]$n) -and $n -ge 0) { $o.UsedMb = $n }
        if ($p.Count -ge 2 -and [long]::TryParse($p[1].Trim(), [Globalization.NumberStyles]::Integer, $inv, [ref]$n) -and $n -gt 0) { $o.MaxMb = $n }
    }
    if ($null -ne $o.UsedMb -and $null -ne $o.MaxMb) {
        $o.Percent = [Math]::Round(100.0 * $o.UsedMb / $o.MaxMb, 1)
        $o.Warn = $o.Percent -gt $WarnPercent
        $o.Text = if ($o.Warn) {
            [string]::Format($inv, 'the Pro database is {0:0.#} % full ({1:0.#} of {2:0.#} GB). SecurityInsight removes old collections by itself; if it keeps filling up, raise the database''s maximum size -- when it is full, nothing new can be stored.', $o.Percent, ($o.UsedMb / 1024.0), ($o.MaxMb / 1024.0))
        } else {
            [string]::Format($inv, 'the Pro database is {0:0.#} % full ({1:0.#} of {2:0.#} GB)', $o.Percent, ($o.UsedMb / 1024.0), ($o.MaxMb / 1024.0))
        }
    }
    [pscustomobject]$o
}

function Get-SIDataFill {
    <# How full the database is (Get-SIDataFillVerdict), said once in the log. Never throws: unreadable = Percent $null, said plainly. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [int]$WarnPercent = 70, [scriptblock]$Log)
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    $v = $null
    try { $v = & $Invoke (Get-SIDataFillSql) @{} 'scalar' } catch { & $Log 'INFO' ('database    : how full the database is could not be read ({0})' -f $_.Exception.Message) }
    $f = Get-SIDataFillVerdict -Value $v -WarnPercent $WarnPercent
    if ($f.Warn) { & $Log 'WARN' ('database    : ' + $f.Text) }
    elseif ($null -ne $f.Percent) { & $Log 'INFO' ('database    : ' + $f.Text) }
    $f
}
