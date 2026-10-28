#Requires -Version 7.0
<#
    SecurityInsight Pro -- REMEDIATIONS (#636, owner 2026-10-13: "for remediation it could be a list of top 10 things to fix
    where you have two angles: most imporant assets, and security findings remediations which can be solved by large scale
    operatons" / "maybe we need to map each finding to remediation also, our abiity to close them, how much work is there").

    ONE REMEDIATION = THE SAME FIX APPLIED TO MANY ASSETS (one update, one configuration change, one software upgrade). The
    data has no such key per finding, so the data sync builds it, once per collection, from the finding's own columns
    (sidata.Finding, filled by the views' derive and the prepared context):

      THE KEY -- the first rule that has a value; each part trimmed, lower-cased, spaces removed; the key cut at 400:
        update:<si_fix_recommended_update_id>    the security update(s) Defender recommends, by id
        update:<si_fix_recommended_update>       the update(s) by name, when no id is given
        config:<ConfigurationId>                 one configuration change (a configuration id that is not a CVE)
        software:<vendor>/<product>              a CVE without a named update: upgrading the software closes it
        cve:<CVE id>                             a CVE that names neither an update nor its software
        title:<finding title>                    anything else
      THE KIND -- si_remediation_type when a source says it (patch | configuration | upgrade | policy | manual), else from
        the rule: update -> patch, config -> configuration, software -> upgrade, cve -> patch, title -> manual.

    WHAT IS WRITTEN (sql\si-data-schema.sql, section #636):
      sidata.Finding.RemediationKey   every finding's key (the Detailed view filters a fix's findings on it)
      sidata.Remediation              one row per collection + key (All remediations / Top 10 fixes by reach)
      sidata.RemediationAsset         the 100 most important assets of the collection x their fixes (Top 10 assets to fix)
      sidata.Collection.RemediationAt when (NULL = not yet; the pages say "being prepared")
    READ-ONLY towards every source: reporting only -- nothing is fixed, closed or sent. Never fails the data sync.
    Get-SIRemediationKey is the PowerShell twin of the SQL rule (a test holds the two equal on a real SQL Server).
    No PowerShell module: the statements run through the data sync's own SQL seam.
#>

$script:SIRemediationKinds = @('patch', 'configuration', 'upgrade', 'policy', 'manual')
$script:SIRemediationTopAssets = 100

function ConvertTo-SIRemediationPart {
    <# PURE. One part of the key: trimmed, lower-cased, spaces removed ('' for nothing). #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ($null -eq $Value) { return '' }
    $Value.ToLowerInvariant().Replace(' ', '')
}

function Get-SIRemediationKey {
    <#
        PURE. The remediation of one finding: @{ Key; Kind; Fix } by the rule above. -Type is the finding's
        si_remediation_type ('' = none). The twin of the SQL in Get-SIDataRemediationSql.
    #>
    param([string]$UpdateId, [string]$Update, [string]$ConfigurationId, [string]$Cve, [string]$Vendor, [string]$Product,
          [string]$Title, [string]$Type)
    $uid = ConvertTo-SIRemediationPart $UpdateId
    $upd = ConvertTo-SIRemediationPart $Update
    $cfg = ConvertTo-SIRemediationPart $ConfigurationId
    $cve = ConvertTo-SIRemediationPart $Cve
    $prd = ConvertTo-SIRemediationPart $Product
    $ven = ConvertTo-SIRemediationPart $Vendor
    $ttl = ConvertTo-SIRemediationPart $Title
    $isCveCfg = $cfg.StartsWith('cve-')
    # the words as SQL's LTRIM(RTRIM(...)) leaves them ('' for nothing)
    $w = { param([string]$s) if ($null -eq $s) { '' } else { $s.Trim(' ') } }
    $Update = & $w $Update; $UpdateId = & $w $UpdateId; $Title = & $w $Title; $ConfigurationId = & $w $ConfigurationId
    $Product = & $w $Product; $Vendor = & $w $Vendor; $Cve = & $w $Cve
    if ($uid) { $key = 'update:' + $uid; $kind = 'patch'; $fix = $(if ($Update) { $Update } else { 'Security update ' + $UpdateId }) }
    elseif ($upd) { $key = 'update:' + $upd; $kind = 'patch'; $fix = $Update }
    elseif ($cfg -and -not $isCveCfg) { $key = 'config:' + $cfg; $kind = 'configuration'; $fix = $(if ($Title) { $Title } else { $ConfigurationId }) }
    elseif ($prd -and $cve) { $key = 'software:' + $ven + '/' + $prd; $kind = 'upgrade'; $fix = 'Upgrade ' + $Product + $(if ($Vendor) { ' (' + $Vendor + ')' } else { '' }) }
    elseif ($cve) { $key = 'cve:' + $cve; $kind = 'patch'; $fix = $Cve + $(if ($Title) { ' -- ' + $Title } else { '' }) }
    elseif ($ttl) { $key = 'title:' + $ttl; $kind = 'manual'; $fix = $Title }
    else { $key = 'none:'; $kind = 'manual'; $fix = '' }
    if ($key.Length -gt 400) { $key = $key.Substring(0, 400) }
    $t = ConvertTo-SIRemediationPart $Type
    if ($script:SIRemediationKinds -contains $t) { $kind = $t }
    if ($fix.Length -gt 1000) { $fix = $fix.Substring(0, 1000) }
    [pscustomobject]@{ Key = $key; Kind = $kind; Fix = $fix }
}

function Get-SIRemediationPartSql {
    <# PURE. The SQL twin of ConvertTo-SIRemediationPart over an expression. #>
    param([Parameter(Mandatory)][string]$Expr)
    "ISNULL(LOWER(REPLACE(LTRIM(RTRIM($Expr)), N' ', N'')), N'')"
}

function Get-SIRemediationKeySql {
    <#
        PURE. The SQL expressions of the key, the kind and the fix over a finding row aliased f (sidata.Finding) and its
        parts n (CROSS APPLY of Get-SIRemediationPartsSql) -- the twin of Get-SIRemediationKey.
    #>
    @'
CASE WHEN n.uid <> N'' THEN LEFT(N'update:' + n.uid, 400)
     WHEN n.upd <> N'' THEN LEFT(N'update:' + n.upd, 400)
     WHEN n.cfg <> N'' AND n.cfg NOT LIKE N'cve-%' THEN LEFT(N'config:' + n.cfg, 400)
     WHEN n.prd <> N'' AND n.cve <> N'' THEN LEFT(N'software:' + n.ven + N'/' + n.prd, 400)
     WHEN n.cve <> N'' THEN LEFT(N'cve:' + n.cve, 400)
     WHEN n.ttl <> N'' THEN LEFT(N'title:' + n.ttl, 400)
     ELSE N'none:' END AS RKey,
COALESCE(n.typ,
     CASE WHEN n.uid <> N'' OR n.upd <> N'' THEN N'patch'
          WHEN n.cfg <> N'' AND n.cfg NOT LIKE N'cve-%' THEN N'configuration'
          WHEN n.prd <> N'' AND n.cve <> N'' THEN N'upgrade'
          WHEN n.cve <> N'' THEN N'patch'
          ELSE N'manual' END) AS Kind,
LEFT(CASE WHEN n.uid <> N'' THEN COALESCE(NULLIF(LTRIM(RTRIM(f.FixRecommendedUpdate)), N''), N'Security update ' + LTRIM(RTRIM(f.FixRecommendedUpdateId)))
          WHEN n.upd <> N'' THEN LTRIM(RTRIM(f.FixRecommendedUpdate))
          WHEN n.cfg <> N'' AND n.cfg NOT LIKE N'cve-%' THEN COALESCE(NULLIF(LTRIM(RTRIM(f.Title)), N''), LTRIM(RTRIM(f.ConfigurationId)))
          WHEN n.prd <> N'' AND n.cve <> N'' THEN N'Upgrade ' + LTRIM(RTRIM(f.AffectedProduct)) + CASE WHEN NULLIF(LTRIM(RTRIM(f.AffectedVendor)), N'') IS NOT NULL THEN N' (' + LTRIM(RTRIM(f.AffectedVendor)) + N')' ELSE N'' END
          WHEN n.cve <> N'' THEN LTRIM(RTRIM(f.Cve)) + CASE WHEN NULLIF(LTRIM(RTRIM(f.Title)), N'') IS NOT NULL THEN N' -- ' + LTRIM(RTRIM(f.Title)) ELSE N'' END
          WHEN n.ttl <> N'' THEN LTRIM(RTRIM(f.Title))
          ELSE N'' END, 1000) AS Fix
'@
}

function Get-SIRemediationPartsSql {
    <# PURE. The CROSS APPLY that works out the parts of the key ONCE per finding (alias n). -NoType: no JSON read (tests). #>
    param([switch]$NoType)
    $p = { param($e) Get-SIRemediationPartSql -Expr $e }
    $kinds = ($script:SIRemediationKinds | ForEach-Object { "N'$_'" }) -join ', '
    $typ = "CASE WHEN f.DetailJson IS NOT NULL AND ISJSON(f.DetailJson) = 1 AND LOWER(REPLACE(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.si_remediation_type'))), N' ', N'')) IN ($kinds) THEN LOWER(REPLACE(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.si_remediation_type'))), N' ', N'')) END"
    if ($NoType) { $typ = 'CAST(NULL AS nvarchar(32))' }
    "CROSS APPLY (SELECT $(& $p 'f.FixRecommendedUpdateId') AS uid, $(& $p 'f.FixRecommendedUpdate') AS upd, $(& $p 'f.ConfigurationId') AS cfg, $(& $p 'f.Cve') AS cve, $(& $p 'f.AffectedVendor') AS ven, $(& $p 'f.AffectedProduct') AS prd, $(& $p 'f.Title') AS ttl, $typ AS typ) AS n"
}

function Get-SIDataRemediationSchemaCheckSql {
    <# 1 when the database carries what the remediations are built from and written to; else 0. #>
    $need = @(
        "COL_LENGTH('sidata.Finding', 'RemediationKey')", "COL_LENGTH('sidata.Finding', 'FixRecommendedUpdateId')", "COL_LENGTH('sidata.Finding', 'FixRecommendedUpdate')",
        "COL_LENGTH('sidata.Finding', 'AffectedProduct')", "COL_LENGTH('sidata.Finding', 'AffectedVendor')", "COL_LENGTH('sidata.Finding', 'RemediationEffort')",
        "COL_LENGTH('sidata.Finding', 'FixOwner')", "COL_LENGTH('sidata.Finding', 'FixRemediation')", "COL_LENGTH('sidata.Finding', 'DepartmentId')",
        "COL_LENGTH('sidata.Finding', 'RiskScoreWeighted')", "COL_LENGTH('sidata.Collection', 'RemediationAt')", "COL_LENGTH('sidata.Collection', 'ContextAt')",
        "OBJECT_ID('sidata.Remediation')", "OBJECT_ID('sidata.RemediationAsset')")
    'SELECT CASE WHEN ' + (($need | ForEach-Object { "$_ IS NOT NULL" }) -join ' AND ') + ' THEN 1 ELSE 0 END'
}

function Get-SIDataUnremediatedSql {
    <#
        Complete collections whose context is prepared (the remediation reads the fix, the software, the effort and the owner
        from it) and whose remediations are not built -- or were built before the context was prepared again. Newest first.
    #>
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter }
    "SELECT CollectionId, CollectionTime FROM sidata.Collection WHERE Kind = N'Detailed' AND Status = 'Complete' AND ContextAt IS NOT NULL AND (RemediationAt IS NULL OR RemediationAt < ContextAt)$live ORDER BY CollectionTime DESC"
}

function Get-SIDataRemediationBoundsSql {
    <# The collection's first and last FindingId (Lo, Hi; NULL when it has none) -- one seek on the clustered key. #>
    'SELECT MIN(FindingId) AS Lo, MAX(FindingId) AS Hi FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId);'
}

function Get-SIDataRemediationKeyRangeSql {
    <#
        #881 ONE RANGE of the collection's findings (@After < FindingId <= @Upto): each finding's key into
        sidata.Finding.RemediationKey, only a row whose key differs (log volume) -- its own statement, its own short
        transaction (Invoke-SIDataRemediationKeys sizes the ranges from their measured time). Answers the rows written.
        Before: every range of the collection in ONE command (a 1.3 M-finding collection's command ran past its time limit,
        live 2026-10-22: "remediations: not completed this run -- ExecuteScalar Timeout expired").
    #>
    param([switch]$NoType)
    $parts = Get-SIRemediationPartsSql -NoType:$NoType
    $key = Get-SIRemediationKeySql
    @"
SET NOCOUNT ON;
DECLARE @c int = CONVERT(int, @CollectionId), @a bigint = CONVERT(bigint, @After), @u bigint = CONVERT(bigint, @Upto);
-- #855: the remediations are the to-do list of ACTIVE CIs (a retired CI's findings close as retired, never as fixed; a not
-- seen CI is not worked on until it is seen again) -- a finding no CI carries, or of an unstamped collection, counts as active
UPDATE f SET RemediationKey = x.RKey
FROM sidata.Finding AS f
$parts
CROSS APPLY (SELECT $key) AS x
WHERE f.CollectionId = @c AND f.FindingId > @a AND f.FindingId <= @u AND (f.CiLifecycle IS NULL OR f.CiLifecycle = N'active')
  AND (f.RemediationKey IS NULL OR CONVERT(varbinary(800), f.RemediationKey) <> CONVERT(varbinary(800), x.RKey));
SELECT @@ROWCOUNT;
"@
}

function Invoke-SIDataRemediationKeys {
    <#
        #881 Every finding's key of ONE collection, a range of FindingIds at a time (Get-SIDataRemediationKeyRangeSql), each
        range its own statement: the range size follows the measured time of the one before (Get-SIDataNextSize; -FirstSize
        is only where it starts), the database's own load paces it when SI-SqlPacing.ps1 is loaded, and a long collection
        says how far it is every -ProgressSeconds. No time limit. Answers the rows written. Throws on a failure (the caller
        says it; the next run goes on -- a range whose keys are written is not written again).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [switch]$NoType, [long]$FirstSize = 50000,
          [long]$TargetMs = 5000, [double]$ProgressSeconds = 60, [scriptblock]$Log = { param($l, $m) })
    $b = @(@(& $Invoke (Get-SIDataRemediationBoundsSql) @{ CollectionId = [string]$CollectionId } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
    $get = { param($n) if ($null -eq $b) { $null } elseif ($b -is [System.Collections.IDictionary]) { $b[$n] } else { $b.$n } }
    $lo = & $get 'Lo'; $hi = & $get 'Hi'
    if ($null -eq $lo -or $lo -is [System.DBNull] -or $null -eq $hi -or $hi -is [System.DBNull]) { return 0L }
    $lo = [long]$lo; $hi = [long]$hi
    $sql = Get-SIDataRemediationKeyRangeSql -NoType:$NoType
    $sizer = [bool](Get-Command -Name Get-SIDataNextSize -ErrorAction SilentlyContinue)
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
    $after = $lo - 1; $size = [Math]::Max(1L, $FirstSize); $written = 0L; $lastMs = 0L
    $clock = [Diagnostics.Stopwatch]::StartNew(); $said = [double]0; $total = $hi - $after
    while ($after -lt $hi) {
        if ($paced) {
            $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log
            if ($pace.Shrink) { $size = [Math]::Max(1L, [long][Math]::Floor($size / 2)) }
        }
        $upto = [long][Math]::Min([double]$hi, [double]$after + [double]$size)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $written += [long](& $Invoke $sql @{ CollectionId = [string]$CollectionId; After = [string]$after; Upto = [string]$upto } 'scalar')
        $lastMs = $sw.ElapsedMilliseconds; $after = $upto
        if ($sizer) { $size = Get-SIDataNextSize -Current $size -ElapsedMs $lastMs -TargetMs $TargetMs -Minimum 1 }
        $now = $clock.Elapsed.TotalSeconds
        if ($after -lt $hi -and ($now - $said) -ge $ProgressSeconds) {
            $said = $now; $done = $total - ($hi - $after)
            & $Log 'INFO' ("remediations: collection {0} -- the findings' keys written up to {1:N0} of {2:N0} ids" -f $CollectionId, $done, $total)
        }
    }
    $written
}

function Get-SIDataRemediationSql {
    <#
        ONE collection (@CollectionId), its findings' keys already written (Invoke-SIDataRemediationKeys, #881 -- in measured
        FindingId ranges, each its own statement): sidata.Remediation and sidata.RemediationAsset replaced and
        Collection.RemediationAt stamped -- one transaction for the two tables, so a page reads the old set or the new one.
        Answers the number of remediations. -NoType: the kind is not read from the finding's JSON (tests).
    #>
    param([switch]$NoType, [int]$TopAssets = $script:SIRemediationTopAssets)
    $parts = Get-SIRemediationPartsSql -NoType:$NoType
    $key = Get-SIRemediationKeySql
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @c int = CONVERT(int, @CollectionId);
CREATE TABLE #k (FindingId BIGINT NOT NULL PRIMARY KEY, RKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL, Kind NVARCHAR(32) COLLATE DATABASE_DEFAULT NOT NULL,
                 Fix NVARCHAR(1000) NULL, AssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL, AssetName NVARCHAR(400) NULL, Tier TINYINT NULL,
                 W FLOAT NOT NULL, S FLOAT NULL, Rating NVARCHAR(16) NULL, Ex BIT NOT NULL, Effort TINYINT NULL, FixOwner NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL,
                 DepartmentId INT NULL, Rec NVARCHAR(256) COLLATE DATABASE_DEFAULT NULL, Exploit BIT NOT NULL, Remedy NVARCHAR(4000) NULL);
INSERT #k (FindingId, RKey, Kind, Fix, AssetKey, AssetName, Tier, W, S, Rating, Ex, Effort, FixOwner, DepartmentId, Rec, Exploit, Remedy)
SELECT f.FindingId, x.RKey, x.Kind, NULLIF(x.Fix, N''), f.AssetKey, f.AssetName, f.Tier,
       ISNULL(f.RiskScoreWeighted, ISNULL(f.RiskScore, 0)), f.RiskScore, f.RiskRating,
       CASE WHEN f.ExemptionId IS NULL THEN 0 ELSE 1 END,
       CASE LOWER(LTRIM(RTRIM(f.RemediationEffort))) WHEN N'low' THEN 1 WHEN N'moderate' THEN 2 WHEN N'medium' THEN 2 WHEN N'high' THEN 3 END,
       LEFT(NULLIF(LTRIM(RTRIM(f.FixOwner)), N''), 400), f.DepartmentId, LEFT(COALESCE(f.Cve, f.ConfigurationId), 256), ISNULL(f.HasExploit, 0),
       LEFT(NULLIF(LTRIM(RTRIM(f.FixRemediation)), N''), 4000)
FROM sidata.Finding AS f
$parts
CROSS APPLY (SELECT $key) AS x
-- #855: the remediations are the to-do list of ACTIVE CIs (a retired CI's findings close as retired, never as fixed; a not
-- seen CI is not worked on until it is seen again) -- a finding no CI carries, or of an unstamped collection, counts as active
WHERE f.CollectionId = @c AND (f.CiLifecycle IS NULL OR f.CiLifecycle = N'active');
-- the fix text of each remediation: the most risky finding's own words
CREATE TABLE #w (RKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, Remedy NVARCHAR(4000) NULL);
INSERT #w (RKey, Remedy)
SELECT r.RKey, r.Remedy FROM (SELECT k.RKey, k.Remedy, ROW_NUMBER() OVER (PARTITION BY k.RKey ORDER BY CASE WHEN k.Remedy IS NULL THEN 1 ELSE 0 END, k.W DESC, k.FindingId) AS Rn FROM #k AS k) AS r WHERE r.Rn = 1;
CREATE TABLE #r (RKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, Kind NVARCHAR(32) NOT NULL, Fix NVARCHAR(1000) NULL, Effort TINYINT NULL,
                 Owners INT NOT NULL, FixOwner NVARCHAR(400) NULL, Depts INT NOT NULL, DepartmentId INT NULL, Assets INT NOT NULL, Tier0Assets INT NOT NULL,
                 BestTier TINYINT NULL, Recs INT NOT NULL, Findings INT NOT NULL, Exempted INT NOT NULL, Crit INT NOT NULL, High INT NOT NULL,
                 RiskRemoved FLOAT NOT NULL, MaxRisk FLOAT NULL, Exploit BIT NOT NULL);
INSERT #r
SELECT k.RKey, MAX(k.Kind), MAX(k.Fix), MAX(k.Effort), COUNT(DISTINCT k.FixOwner), MAX(k.FixOwner), COUNT(DISTINCT k.DepartmentId), MAX(k.DepartmentId),
       COUNT(DISTINCT CASE WHEN k.Ex = 0 THEN k.AssetKey END), COUNT(DISTINCT CASE WHEN k.Ex = 0 AND k.Tier = 0 THEN k.AssetKey END),
       MIN(CASE WHEN k.Ex = 0 THEN k.Tier END), COUNT(DISTINCT k.Rec), SUM(CASE WHEN k.Ex = 0 THEN 1 ELSE 0 END), SUM(CASE WHEN k.Ex = 1 THEN 1 ELSE 0 END),
       SUM(CASE WHEN k.Ex = 0 AND k.Rating = N'Critical' THEN 1 ELSE 0 END), SUM(CASE WHEN k.Ex = 0 AND k.Rating = N'High' THEN 1 ELSE 0 END),
       SUM(CASE WHEN k.Ex = 0 THEN k.W ELSE 0 END), MAX(k.S), CONVERT(bit, MAX(CONVERT(int, k.Exploit)))
FROM #k AS k GROUP BY k.RKey;
-- the most important assets of the collection: tier first (unclassified last), then the most open weighted risk
CREATE TABLE #a (AssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, AssetName NVARCHAR(400) NULL, Tier TINYINT NULL, Risk FLOAT NOT NULL, AssetRank INT NOT NULL);
INSERT #a (AssetKey, AssetName, Tier, Risk, AssetRank)
SELECT t.AssetKey, t.AssetName, t.Tier, t.Risk, t.Rn FROM (
    SELECT a.AssetKey, a.AssetName, a.Tier, a.Risk, ROW_NUMBER() OVER (ORDER BY CASE WHEN a.Tier IS NULL THEN 9 ELSE a.Tier END, a.Risk DESC, a.AssetKey) AS Rn
    FROM (SELECT k.AssetKey, MAX(k.AssetName) AS AssetName, MIN(k.Tier) AS Tier, SUM(k.W) AS Risk FROM #k AS k WHERE k.Ex = 0 AND k.AssetKey IS NOT NULL GROUP BY k.AssetKey) AS a
) AS t WHERE t.Rn <= $TopAssets;
BEGIN TRAN;
DELETE FROM sidata.RemediationAsset WHERE CollectionId = @c;
DELETE FROM sidata.Remediation WHERE CollectionId = @c;
INSERT sidata.Remediation (CollectionId, RemediationKey, Kind, Fix, WhatToDo, Effort, FixOwner, DepartmentId, Departments, Assets, Tier0Assets, BestTier,
                           Recommendations, Findings, ExemptedFindings, CriticalFindings, HighFindings, RiskRemoved, MaxRiskScore, HasExploit, Status)
SELECT @c, r.RKey, r.Kind, r.Fix, w.Remedy, CASE r.Effort WHEN 1 THEN N'Low' WHEN 2 THEN N'Moderate' WHEN 3 THEN N'High' END,
       CASE WHEN r.Owners = 1 THEN r.FixOwner WHEN r.Owners > 1 THEN CONCAT(N'several (', r.Owners, N')') END,
       CASE WHEN r.Depts = 1 THEN r.DepartmentId END, r.Depts, r.Assets, r.Tier0Assets, r.BestTier, r.Recs, r.Findings, r.Exempted, r.Crit, r.High,
       r.RiskRemoved, r.MaxRisk, r.Exploit, CASE WHEN r.Findings = 0 THEN N'exempted' ELSE N'open' END
FROM #r AS r LEFT JOIN #w AS w ON w.RKey = r.RKey;
DECLARE @n INT = @@ROWCOUNT;
INSERT sidata.RemediationAsset (CollectionId, AssetRank, FixRank, AssetKey, AssetName, Tier, AssetRisk, RemediationKey, Kind, Fix, Findings, RiskRemoved)
SELECT @c, s.AssetRank, ROW_NUMBER() OVER (PARTITION BY s.AssetRank ORDER BY s.RiskRemoved DESC, s.RKey), s.AssetKey, s.AssetName, s.Tier, s.Risk, s.RKey, s.Kind, s.Fix, s.Findings, s.RiskRemoved
FROM (SELECT a.AssetRank, a.AssetKey, a.AssetName, a.Tier, a.Risk, k.RKey, MAX(k.Kind) AS Kind, MAX(k.Fix) AS Fix, COUNT(*) AS Findings, SUM(k.W) AS RiskRemoved
      FROM #k AS k JOIN #a AS a ON a.AssetKey = k.AssetKey WHERE k.Ex = 0
      GROUP BY a.AssetRank, a.AssetKey, a.AssetName, a.Tier, a.Risk, k.RKey) AS s;
UPDATE sidata.Collection SET RemediationAt = SYSUTCDATETIME() WHERE CollectionId = @c;
COMMIT;
SELECT @n;
"@
}

function Invoke-SIDataRemediations {
    <#
    .SYNOPSIS  Builds the remediations of every complete collection that has none (newest first). Never throws.
    .NOTES     -BudgetSeconds: when an existing install has many collections, the rest follow on the next runs (said). A
               collection without them shows "being prepared" on the Remediations pages -- nothing else waits for it.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 900)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        if (([int](& $Invoke (Get-SIDataRemediationSchemaCheckSql) @{} 'scalar')) -ne 1) {
            & $Log 'INFO' 'remediations: the database does not have the remediation tables yet (the updater adds them) -- the Remediations pages say they are being prepared.'
            return [pscustomobject]@{ Status = 'no-schema'; Collections = 0 }
        }
        $pending = @(@(& $Invoke (Get-SIDataUnremediatedSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        if ($DryRun) {
            & $Log 'INFO' ("remediations: {0} collection(s) would get their remediations; nothing is written." -f $pending.Count)
            return [pscustomobject]@{ Status = 'dry-run'; Collections = 0; Pending = $pending.Count }
        }
        if ($pending.Count -eq 0) { return [pscustomobject]@{ Status = 'ok'; Collections = 0; Pending = 0 } }
        $sql = Get-SIDataRemediationSql
        $clock = [Diagnostics.Stopwatch]::StartNew(); $done = 0; $rems = [long]0
        foreach ($p in $pending) {
            if ($done -gt 0 -and $clock.Elapsed.TotalSeconds -gt $BudgetSeconds) { break }
            $cid = $(if ($p -is [System.Collections.IDictionary]) { $p['CollectionId'] } else { $p.CollectionId })
            # #881 the keys a range at a time (no command over the whole collection), then the two tables in one transaction
            $null = Invoke-SIDataRemediationKeys -Invoke $Invoke -CollectionId ([long]$cid) -Log $Log
            # 2026-10-25 over this run's narrow findings (read ONCE, shared with the steps after) where they can be made
            if (Get-Command -Name Invoke-SIDataNarrowOrWide -ErrorAction SilentlyContinue) { $rems += [long](Invoke-SIDataNarrowOrWide -Invoke $Invoke -Sql $sql -Params @{ CollectionId = [string][int]$cid } -Mode 'scalar' -CollectionId ([long]$cid) -What 'the remediations' -Log $Log) }
            else { $rems += [long](& $Invoke $sql @{ CollectionId = [string][int]$cid } 'scalar') }
            $done++
        }
        $left = $pending.Count - $done
        & $Log 'OK' ("remediations: {0} collection(s) got their remediations ({1} fix(es))" -f $done, $rems)
        if ($left -gt 0) { & $Log 'INFO' ("remediations: {0} older collection(s) follow on the next run(s)" -f $left) }
        return [pscustomobject]@{ Status = 'ok'; Collections = $done; Remediations = $rems; Pending = $left }
    } catch {
        & $Log 'WARN' ("remediations: not completed this run -- {0}. Tried again on the next run; the Remediations pages show the last complete set." -f $_.Exception.Message)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message }
    }
}
