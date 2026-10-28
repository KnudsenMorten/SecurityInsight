using SI.Management.Core.Holds;
using SI.Management.Web.Data;

namespace SI.Management.Web.RunReports;

/// One ACTIVE acceptance (#902 (5)): an Admin accepted that a source table a report reads is empty for good.
public sealed record SourceAccept(long Id, string Report, string Table, string Reason, string By, DateTime AcceptedUtc);

public interface ISourceAcceptStore
{
    /// The active acceptances (none when the database has no table yet).
    Task<IReadOnlyList<SourceAccept>> ActiveAsync(CancellationToken ct);
    /// Accept -table as empty for good for -report, with its cfg.ChangeLog row, in ONE transaction -- ONLY when the report's
    /// newest verdict is held for a kind that may be accepted (the hold list), that hold names the table, and the table's
    /// newest count was a SUCCESSFUL zero after it had rows (sidata.RaSourceCount: SilentSince set, LastRows = 0).
    /// Outcome: Accepted | Missing | NotHeld | NotSilent | Already.
    Task<string> AcceptAsync(string report, string table, string reason, string by, CancellationToken ct);
    /// Undo one active acceptance (ClearedHow 'revoked'), with its cfg.ChangeLog row. Outcome: Undone | Missing | NotActive.
    Task<string> UndoAsync(long id, string reason, string by, CancellationToken ct);
}

/// <summary>
/// #902 (5) A SOURCE THAT IS EMPTY FOR GOOD -- cfg.RaSourceAccept (INSERT, UPDATE granted in SI-ManagementGrants.ps1) with
/// its cfg.ChangeLog row (Name 'source-accept/&lt;report&gt;/&lt;table&gt;', Scope 'riskanalysis', Kind 'sourceaccept'). The
/// checks that keep a real read failure from ever being accepted are in the SAME statement as the write (never only on the
/// page): a report held for a source that went silent -- a count that SUCCEEDED with zero rows -- and nothing else.
/// </summary>
public sealed class SqlSourceAcceptStore : ISourceAcceptStore
{
    private readonly ISqlExecutor _sql;
    public SqlSourceAcceptStore(ISqlExecutor sql) => _sql = sql;

    public const string ActiveSql = """
IF OBJECT_ID(N'cfg.RaSourceAccept') IS NULL
    SELECT CAST(NULL AS bigint) AS AcceptId, CAST(NULL AS nvarchar(256)) AS ReportName, CAST(NULL AS nvarchar(128)) AS SourceTable,
           CAST(NULL AS nvarchar(400)) AS Reason, CAST(NULL AS nvarchar(256)) AS AcceptedBy, CAST(NULL AS datetime2(0)) AS AcceptedUtc WHERE 1 = 0;
ELSE
    SELECT AcceptId, ReportName, SourceTable, Reason, AcceptedBy, AcceptedUtc FROM cfg.RaSourceAccept WHERE ClearedUtc IS NULL ORDER BY ReportName, SourceTable;
""";

    /// @Kinds: the hold kinds whose source may be accepted as empty (JSON, from the hold list).
    public const string AcceptSql = """
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.RaSourceAccept') IS NULL BEGIN SELECT N'Missing' AS Outcome; RETURN; END;
IF OBJECT_ID(N'sidata.RaReportStatus') IS NULL OR COL_LENGTH('sidata.RaReportStatus', 'HoldNames') IS NULL OR COL_LENGTH('sidata.RaReportStatus', 'HeldRaReport') IS NULL
   OR OBJECT_ID(N'sidata.RaSourceCount') IS NULL BEGIN SELECT N'NotHeld' AS Outcome; RETURN; END;
DECLARE @held int = 0;
EXEC sp_executesql N'SELECT @h = COUNT(*) FROM (SELECT TOP (1) s.State, s.HoldKind, s.HoldNames, s.HeldRaReport FROM sidata.RaReportStatus s WHERE s.ReportName = @r ORDER BY s.CollectionTime DESC) x
                     WHERE x.State = N''NotComplete'' AND x.HeldRaReport IS NULL AND x.HoldKind IN (SELECT [value] FROM OPENJSON(@k))
                       AND CHARINDEX(N'';'' + @tb + N'';'', N'';'' + ISNULL(x.HoldNames, N'''') + N'';'') > 0',
     N'@r nvarchar(256), @tb nvarchar(128), @k nvarchar(max), @h int OUTPUT', @r = @ReportName, @tb = @SourceTable, @k = @Kinds, @h = @held OUTPUT;
IF @held = 0 BEGIN SELECT N'NotHeld' AS Outcome; RETURN; END;
IF NOT EXISTS (SELECT 1 FROM sidata.RaSourceCount WHERE SourceTable = @SourceTable AND SilentSince IS NOT NULL AND LastRows = 0 AND LastCountedAt IS NOT NULL)
BEGIN SELECT N'NotSilent' AS Outcome; RETURN; END;
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM cfg.RaSourceAccept WITH (UPDLOCK, HOLDLOCK) WHERE ReportName = @ReportName AND SourceTable = @SourceTable AND ClearedUtc IS NULL)
BEGIN COMMIT; SELECT N'Already' AS Outcome; RETURN; END;
INSERT cfg.RaSourceAccept (ReportName, SourceTable, Reason, AcceptedBy) VALUES (@ReportName, @SourceTable, LEFT(@Reason, 400), @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'source-accept/' + @ReportName + N'/' + @SourceTable, 128), N'riskanalysis', N'sourceaccept', N'Set', N'held: the source went silent',
        N'accepted as empty for good', @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Accepted' AS Outcome;
""";

    public const string UndoSql = """
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.RaSourceAccept') IS NULL BEGIN SELECT N'Missing' AS Outcome; RETURN; END;
DECLARE @done TABLE (ReportName nvarchar(256), SourceTable nvarchar(128));
BEGIN TRAN;
UPDATE cfg.RaSourceAccept SET ClearedUtc = SYSUTCDATETIME(), ClearedHow = N'revoked', ClearedBy = @By
OUTPUT inserted.ReportName, inserted.SourceTable INTO @done
WHERE AcceptId = @Id AND ClearedUtc IS NULL;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
SELECT LEFT(N'source-accept/' + d.ReportName + N'/' + d.SourceTable, 128), N'riskanalysis', N'sourceaccept', N'Reset', N'accepted as empty for good', NULL, @By, LEFT(@Reason, 400)
FROM @done d;
COMMIT;
SELECT CASE WHEN EXISTS (SELECT 1 FROM @done) THEN N'Undone' ELSE N'NotActive' END AS Outcome;
""";

    private static readonly Dictionary<string, object?> None = new();

    public async Task<IReadOnlyList<SourceAccept>> ActiveAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ActiveSql, None, ct);
        return rows.Where(r => r.Long("AcceptId") is not null)
            .Select(r => new SourceAccept(r.Long("AcceptId") ?? 0, r.Str("ReportName") ?? "", r.Str("SourceTable") ?? "", r.Str("Reason") ?? "", r.Str("AcceptedBy") ?? "", r.Date("AcceptedUtc") ?? DateTime.MinValue))
            .ToList();
    }

    /// The kinds of the hold list whose source may be accepted as empty, as JSON.
    public static string AcceptableKindsJson() =>
        System.Text.Json.JsonSerializer.Serialize(HoldKindList.Default.Kinds.Where(k => k.AcceptEmpty).Select(k => k.Kind).ToArray());

    public async Task<string> AcceptAsync(string report, string table, string reason, string by, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(AcceptSql, new Dictionary<string, object?>
        {
            ["ReportName"] = report, ["SourceTable"] = table, ["Reason"] = reason, ["By"] = by, ["Kinds"] = AcceptableKindsJson(),
        }, ct);
        return rows.FirstOrDefault()?.Str("Outcome") ?? "";
    }

    public async Task<string> UndoAsync(long id, string reason, string by, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(UndoSql, new Dictionary<string, object?> { ["Id"] = id, ["Reason"] = reason, ["By"] = by }, ct);
        return rows.FirstOrDefault()?.Str("Outcome") ?? "";
    }
}
