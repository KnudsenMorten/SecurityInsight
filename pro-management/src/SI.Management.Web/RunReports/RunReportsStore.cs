using SI.Management.Core.Holds;
using SI.Management.Web.Data;

namespace SI.Management.Web.RunReports;

/// One report of one Risk Analysis run, as the run judged it (sidata.RaReportStatus, #641): what the source said the report
/// holds (a count of its whole query), what the run retrieved and stored, and the verdict -- Complete, NotComplete or
/// Unverified (the source could not count it).
/// #902: a NotComplete report SI held ON PURPOSE (a HoldKind of THE list, data-model/hold-kinds.locked.json, and no #877
/// hold-back) is HELD, not "not complete": it keeps its last complete result (KeptResultAt) and nothing of it closes. Held
/// escalateAfterDetailedRuns Detailed runs in a row (HeldRuns) it is ESCALATED -- a real problem SecurityInsight support is
/// told about; the data is still the last complete result. A kind that is not in the list is shown as not complete.
public sealed record RunReportRow(string Grain, DateTime CollectionTime, string Report, long? Expected, long? Retrieved, long? Stored, string State, string? Reason,
                                  string? HoldKind = null, int? HeldRuns = null, DateTime? KeptResultAt = null, string? HoldNames = null, long? HeldRaReport = null)
{
    private bool StoredNotComplete => string.Equals(State, "NotComplete", StringComparison.OrdinalIgnoreCase);

    /// Held on purpose at its last complete result (#902).
    public bool Held => StoredNotComplete && HeldRaReport is null && HoldKindList.Default.Find(HoldKind) is not null;

    /// Held too long: a real problem (a Detailed hold of escalateAfterDetailedRuns runs in a row or more).
    public bool Escalated => Held && HoldKindList.Default.IsEscalated(HeldRuns, Grain);

    /// Not complete for a real cause (a report that really failed) -- a held report is not.
    public bool NotComplete => StoredNotComplete && !Held;
    public bool Unverified => string.Equals(State, "Unverified", StringComparison.OrdinalIgnoreCase);

    /// The catalogue code of a held report (its escalation code once escalated); null when not held.
    public string? HoldCode => Held ? HoldKindList.Default.CodeOf(HoldKind, Escalated) : null;

    /// The catalogue's title of the hold's code.
    public string? HoldTitle => HoldKindList.Default.Entry(HoldCode)?.Title;

    /// The catalogue's sentence for the customer of the hold's code.
    public string? HoldText => HoldKindList.Default.Entry(HoldCode)?.CustomerText;

    /// What the hold is about (the silent tables).
    public IReadOnlyList<string> HoldNameList => string.IsNullOrWhiteSpace(HoldNames)
        ? Array.Empty<string>()
        : HoldNames.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// May an Admin accept the source of this held report as empty for good? (its kind says so and the hold names a table)
    public bool MayAcceptEmpty => Held && HoldKindList.Default.Find(HoldKind) is { AcceptEmpty: true } && HoldNameList.Count > 0;

    /// "5 hours old" / "2 days old" -- the age of the kept result at -nowUtc; null when there is none.
    public string? KeptAge(DateTime nowUtc)
    {
        if (KeptResultAt is not { } k) return null;
        var h = (nowUtc - DateTime.SpecifyKind(k, DateTimeKind.Utc)).TotalHours;
        if (h < 0) h = 0;
        if (h < 48) { var n = (int)Math.Floor(h); return n == 1 ? "1 hour old" : $"{n} hours old"; }
        return $"{(int)Math.Floor(h / 24)} days old";
    }

    /// The order on the page: real failures first, then the held reports, then not verified, then complete.
    public int Rank => NotComplete ? 0 : Held ? 1 : Unverified ? 2 : 3;
}

/// The reports of one run (a RunId), or of the newest run of each grain when no run is named.
public sealed record RunReportsView(bool HasTable, string? RunId, bool RunFound, IReadOnlyList<RunReportRow> Rows)
{
    public static readonly RunReportsView Missing = new(false, null, false, Array.Empty<RunReportRow>());
    /// Not complete for a real cause (a held report is counted under Held).
    public int Incomplete => Rows.Count(r => r.NotComplete);
    /// #902: held on purpose at their last complete result (the escalated ones included).
    public int Held => Rows.Count(r => r.Held);
}

public interface IRunReportsStore
{
    Task<RunReportsView> ReadAsync(string? runId, CancellationToken ct);
}

/// <summary>
/// Operations &gt; Run health &gt; Risk Analysis reports (#641): every report of a Risk Analysis run with its verdict -- the
/// page the run's report to Invardia links to when a report was not complete. Reads sidata.RaReportStatus and, to find a
/// run by its id, sidata.Collection / sidata.SummaryLoad (db_datareader only).
/// </summary>
public sealed class SqlRunReportsStore : IRunReportsStore
{
    private readonly ISqlExecutor _sql;
    public SqlRunReportsStore(ISqlExecutor sql) => _sql = sql;

    public const string ProbeSql = "SELECT CASE WHEN OBJECT_ID(N'sidata.RaReportStatus') IS NOT NULL THEN 1 ELSE 0 END AS HasTable";

    /// The run named by @RunId (its Detailed collection, else its Summary collection); '' = the newest run of each grain.
    /// Not-complete reports first. #902: every column of the verdict (s.*) -- so the hold's columns (HoldKind, HeldRuns,
    /// KeptResultAt, HoldNames, HeldRaReport) are read where the database has them; an older database simply has none.
    public const string ReadSql = """
DECLARE @t datetime2(3) = NULL, @g nvarchar(16) = NULL;
IF @RunId <> N''
BEGIN
    SELECT TOP (1) @t = CollectionTime, @g = N'Detailed' FROM sidata.Collection WHERE RunId = @RunId ORDER BY CollectionTime DESC;
    IF @t IS NULL SELECT TOP (1) @t = CollectionTime, @g = N'Summary' FROM sidata.SummaryLoad WHERE RunId = @RunId ORDER BY CollectionTime DESC;
    SELECT s.*
    FROM sidata.RaReportStatus s WHERE @t IS NOT NULL AND s.CollectionTime = @t AND s.Grain = @g
    ORDER BY CASE s.State WHEN N'NotComplete' THEN 0 WHEN N'Unverified' THEN 1 ELSE 2 END, s.ReportName;
END
ELSE
    SELECT s.*
    FROM sidata.RaReportStatus s
    JOIN (SELECT Grain, MAX(CollectionTime) AS T FROM sidata.RaReportStatus GROUP BY Grain) m ON m.Grain = s.Grain AND m.T = s.CollectionTime
    ORDER BY s.Grain, CASE s.State WHEN N'NotComplete' THEN 0 WHEN N'Unverified' THEN 1 ELSE 2 END, s.ReportName;
""";

    public async Task<RunReportsView> ReadAsync(string? runId, CancellationToken ct)
    {
        var probe = await _sql.QueryAsync(ProbeSql, new Dictionary<string, object?>(), ct);
        if ((probe.FirstOrDefault()?.Long("HasTable") ?? 0) != 1) return RunReportsView.Missing;
        var id = (runId ?? "").Trim();
        var rows = await _sql.QueryAsync(ReadSql, new Dictionary<string, object?> { ["RunId"] = id }, ct);
        var list = rows.Select(r => new RunReportRow(r.Str("Grain") ?? "", r.Date("CollectionTime") ?? DateTime.MinValue, r.Str("ReportName") ?? "",
            r.Long("ExpectedRows"), r.Long("RetrievedRows"), r.Long("StoredRows"), r.Str("State") ?? "", r.Str("Reason"),
            r.Str("HoldKind"), r.Long("HeldRuns") is { } h ? (int)h : null, r.Date("KeptResultAt"), r.Str("HoldNames"), r.Long("HeldRaReport"))).ToList();
        return new RunReportsView(true, id.Length > 0 ? id : null, id.Length == 0 || list.Count > 0, Order(list));
    }

    /// PURE. The statement's grain order kept; within a grain the real failures first, then the held reports (#902).
    public static IReadOnlyList<RunReportRow> Order(IReadOnlyList<RunReportRow> rows)
    {
        var grains = rows.Select(r => r.Grain).Distinct(StringComparer.Ordinal).ToList();
        return rows.Select((r, i) => (r, i)).OrderBy(x => grains.IndexOf(x.r.Grain)).ThenBy(x => x.r.Rank).ThenBy(x => x.i).Select(x => x.r).ToList();
    }
}
