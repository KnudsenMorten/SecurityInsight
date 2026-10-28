#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- the verification service's store in the Pro database (sql\si-pro-settings.sql):
      cfg.VerificationRun           one row per run (started, finished, outcome, the summary per check)
      cfg.VerificationCheckRun      one row per run per check: ok | gaps | not-checked (with the reason)
      cfg.VerificationFinding       the CURRENT state of each finding (open | resolved), keyed '<checkId>|<scope key>'
      cfg.VerificationFindingEvent  its history: opened, reopened, resolved -- per run
      cfg.VerificationDecision      ignored / accepted, who, when, why, the reviewer and the review date (180 days);
                                    append-only: a review is a NEW decision that replaces the old one (RevokedAt)
    SQL text only, plus the run writer behind an -Invoke seam (the data backend's New-SIDataSqlInvoke shape:
    & $invoke $sql $params $mode, mode 'reader' | 'scalar' | default nonquery). The engine writes findings and runs;
    only the web app writes decisions.
#>

function Get-SIVerificationProbeSql {
    "SELECT CASE WHEN OBJECT_ID('cfg.VerificationRun') IS NOT NULL AND OBJECT_ID('cfg.VerificationCheckRun') IS NOT NULL AND OBJECT_ID('cfg.VerificationFinding') IS NOT NULL AND OBJECT_ID('cfg.VerificationFindingEvent') IS NOT NULL AND OBJECT_ID('cfg.VerificationDecision') IS NOT NULL THEN 1 ELSE 0 END AS HasTables"
}

function Get-SIVerificationRunStartSql {
    "INSERT cfg.VerificationRun (CatalogVersion) OUTPUT inserted.RunId VALUES (@CatalogVersion);"
}

function Get-SIVerificationRunEndSql {
    "UPDATE cfg.VerificationRun SET FinishedAt = SYSUTCDATETIME(), Outcome = @Outcome, SummaryJson = @SummaryJson WHERE RunId = @RunId;"
}

function Get-SIVerificationNotCheckedSql {
    <# A check that did not run: recorded as not-checked with the reason; its findings are left exactly as they were. #>
    "INSERT cfg.VerificationCheckRun (RunId, CheckId, State, Reason, Findings) VALUES (@RunId, @CheckId, N'not-checked', LEFT(@Reason, 1000), 0);"
}

function Get-SIVerificationCheckWriteSql {
    <#
        ONE check's result, in one batch: its findings (@Json, an array of { FindingKey, ScopeKind, ScopeKey, ScopeName,
        Severity, Detail }) are opened / reopened / refreshed; every OPEN finding of the check that is not in the result is
        RESOLVED -- except the keys in @KeepJson (parts of the check that could not be read: unknown, never resolved).
        Every open / reopen / resolve is a history event of this run.
    #>
    @'
SET NOCOUNT ON;
DECLARE @rows TABLE (FindingKey NVARCHAR(450) NOT NULL PRIMARY KEY, ScopeKind NVARCHAR(16) NOT NULL, ScopeKey NVARCHAR(400) NOT NULL, ScopeName NVARCHAR(400) NULL, Severity NVARCHAR(16) NOT NULL, Detail NVARCHAR(2000) NULL);
INSERT @rows (FindingKey, ScopeKind, ScopeKey, ScopeName, Severity, Detail)
SELECT DISTINCT LEFT(j.FindingKey, 450), LEFT(j.ScopeKind, 16), LEFT(j.ScopeKey, 400), LEFT(j.ScopeName, 400), LEFT(j.Severity, 16), LEFT(j.Detail, 2000)
FROM OPENJSON(@Json) WITH (FindingKey NVARCHAR(450) '$.FindingKey', ScopeKind NVARCHAR(16) '$.ScopeKind', ScopeKey NVARCHAR(400) '$.ScopeKey', ScopeName NVARCHAR(400) '$.ScopeName', Severity NVARCHAR(16) '$.Severity', Detail NVARCHAR(2000) '$.Detail') AS j
WHERE j.FindingKey IS NOT NULL;
DECLARE @keep TABLE (FindingKey NVARCHAR(450) NOT NULL PRIMARY KEY);
INSERT @keep (FindingKey) SELECT DISTINCT LEFT([value], 450) FROM OPENJSON(@KeepJson) WHERE [value] IS NOT NULL;
INSERT cfg.VerificationFindingEvent (FindingKey, RunId, [Event], Detail)
SELECT r.FindingKey, @RunId, CASE WHEN f.FindingKey IS NULL THEN N'opened' ELSE N'reopened' END, r.Detail
FROM @rows AS r LEFT JOIN cfg.VerificationFinding AS f ON f.FindingKey = r.FindingKey
WHERE f.FindingKey IS NULL OR f.[Status] = N'resolved';
UPDATE f SET f.ScopeKind = r.ScopeKind, f.ScopeKey = r.ScopeKey, f.ScopeName = r.ScopeName, f.Severity = r.Severity, f.Detail = r.Detail,
             f.FirstSeenAt = CASE WHEN f.[Status] = N'resolved' THEN SYSUTCDATETIME() ELSE f.FirstSeenAt END,
             f.[Status] = N'open', f.LastSeenAt = SYSUTCDATETIME(), f.ResolvedAt = NULL, f.LastRunId = @RunId
FROM cfg.VerificationFinding AS f JOIN @rows AS r ON r.FindingKey = f.FindingKey;
INSERT cfg.VerificationFinding (FindingKey, CheckId, ScopeKind, ScopeKey, ScopeName, Severity, Detail, [Status], LastRunId)
SELECT r.FindingKey, @CheckId, r.ScopeKind, r.ScopeKey, r.ScopeName, r.Severity, r.Detail, N'open', @RunId
FROM @rows AS r WHERE NOT EXISTS (SELECT 1 FROM cfg.VerificationFinding AS f WHERE f.FindingKey = r.FindingKey);
INSERT cfg.VerificationFindingEvent (FindingKey, RunId, [Event], Detail)
SELECT f.FindingKey, @RunId, N'resolved', NULL FROM cfg.VerificationFinding AS f
WHERE f.CheckId = @CheckId AND f.[Status] = N'open'
  AND NOT EXISTS (SELECT 1 FROM @rows AS r WHERE r.FindingKey = f.FindingKey) AND NOT EXISTS (SELECT 1 FROM @keep AS k WHERE k.FindingKey = f.FindingKey);
UPDATE f SET f.[Status] = N'resolved', f.ResolvedAt = SYSUTCDATETIME(), f.LastRunId = @RunId FROM cfg.VerificationFinding AS f
WHERE f.CheckId = @CheckId AND f.[Status] = N'open'
  AND NOT EXISTS (SELECT 1 FROM @rows AS r WHERE r.FindingKey = f.FindingKey) AND NOT EXISTS (SELECT 1 FROM @keep AS k WHERE k.FindingKey = f.FindingKey);
INSERT cfg.VerificationCheckRun (RunId, CheckId, State, Reason, Findings)
VALUES (@RunId, @CheckId, CASE WHEN EXISTS (SELECT 1 FROM @rows) THEN N'gaps' ELSE N'ok' END, LEFT(@Reason, 1000), (SELECT COUNT(*) FROM @rows));
'@
}

function Get-SIVerificationDecisionsSql {
    <# Every decision not revoked -- the engine's summary counts ignored / accepted / review due from these. #>
    "SELECT DecisionId, FindingKey, Decision, Reason, [Owner], DecidedBy, DecidedAt, ReviewDueAt, RevokedAt FROM cfg.VerificationDecision WHERE RevokedAt IS NULL;"
}

function ConvertTo-SIVerificationJson {
    <# PURE. The findings as the JSON array the write batch reads; always an array (PS 5.1 makes one item an object). #>
    param([AllowEmptyCollection()][object[]]$Findings = @())
    $items = @($Findings | Where-Object { $_ } | ForEach-Object {
        [ordered]@{ FindingKey = [string]$_.FindingKey; ScopeKind = [string]$_.ScopeKind; ScopeKey = [string]$_.ScopeKey; ScopeName = [string]$_.ScopeName; Severity = [string]$_.Severity; Detail = [string]$_.Detail }
    })
    if ($items.Count -eq 0) { return '[]' }
    $j = ConvertTo-Json -InputObject $items -Depth 4 -Compress
    if (-not $j.StartsWith('[')) { $j = '[' + $j + ']' }
    $j
}

function ConvertTo-SIVerificationKeyJson {
    param([AllowEmptyCollection()][string[]]$Keys = @())
    $k = @($Keys | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    if ($k.Count -eq 0) { return '[]' }
    $j = ConvertTo-Json -InputObject $k -Compress
    if (-not $j.StartsWith('[')) { $j = '[' + $j + ']' }
    $j
}

function Write-SIVerificationResults {
    <#
        Writes one run: the check results (-Results: CheckId -> @{ Ran; Reason; Findings; Keep }), the run's END with the
        summary. -RunId from Get-SIVerificationRunStartSql. A check that did not run touches no finding.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$RunId, [Parameter(Mandatory)][hashtable]$Results)
    foreach ($id in @($Results.Keys | Sort-Object)) {
        $r = $Results[$id]
        if (-not $r.Ran) {
            [void](& $Invoke (Get-SIVerificationNotCheckedSql) @{ RunId = $RunId; CheckId = [string]$id; Reason = [string]$r.Reason } 'nonquery')
            continue
        }
        [void](& $Invoke (Get-SIVerificationCheckWriteSql) @{
            RunId = $RunId; CheckId = [string]$id; Reason = [string]$r.Reason
            Json = (ConvertTo-SIVerificationJson -Findings @($r.Findings)); KeepJson = (ConvertTo-SIVerificationKeyJson -Keys @($r.Keep))
        } 'nonquery')
    }
}
