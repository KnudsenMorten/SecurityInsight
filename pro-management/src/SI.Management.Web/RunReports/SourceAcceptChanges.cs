using System.Globalization;
using SI.Management.Web.Changes;
using SI.Management.Web.Settings;

namespace SI.Management.Web.RunReports;

/// <summary>
/// #902 (5): an Admin accepts, PER REPORT, that a source the report reads is empty for good (the feature was turned off) --
/// or undoes it -- through THE staging (Review &amp; commit) like every Admin change: staging writes nothing; the commit
/// writes the cfg.RaSourceAccept row with its cfg.ChangeLog row, and the database refuses it unless the report is held for a
/// source that went silent (a count that SUCCEEDED with zero rows). From the next run the report is not held for that table:
/// it shows empty and complete, and its findings close as 'Report changed' (never as fixed). The run clears the acceptance
/// by itself when the table has rows again.
/// </summary>
public sealed class SourceAcceptChanges : IStagedChangeHandler
{
    public const string AcceptKind = "source-accept";
    public const string UndoKind = "source-accept-undo";
    private readonly IRunReportsStore _reports;
    private readonly ISourceAcceptStore _store;
    public SourceAcceptChanges(IRunReportsStore reports, ISourceAcceptStore store) { _reports = reports; _store = store; }

    public bool Handles(string kind) => kind is AcceptKind or UndoKind;

    private static string? ReasonProblem(string? reason) =>
        string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3 ? "say why (at least 3 characters) -- it is on the audit trail" : null;

    /// The newest verdict of -report that holds -table and may be accepted; null when there is none.
    private async Task<RunReportRow?> HeldRowAsync(string? report, string? table, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(report) || string.IsNullOrWhiteSpace(table)) return null;
        var view = await _reports.ReadAsync(null, ct);
        return view.Rows.Where(r => r.Report == report).OrderByDescending(r => r.CollectionTime)
            .FirstOrDefault(r => r.MayAcceptEmpty && r.HoldNameList.Contains(table, StringComparer.Ordinal));
    }

    /// Build (never write) the acceptance of -table as empty for good for -report.
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewAcceptAsync(string? report, string? table, string? reason, CancellationToken ct)
    {
        if (ReasonProblem(reason) is { } p) return (null, new[] { p });
        var row = await HeldRowAsync(report, table, ct);
        if (row is null) return (null, new[] { $"{report} is not held for a source that went silent ({table}) -- only such a source can be accepted as empty" });
        return (new StagedChange
        {
            Kind = AcceptKind, Title = $"Accept {table} as empty for good for {report}",
            Data = new(StringComparer.Ordinal) { ["report"] = report!, ["table"] = table!, ["reason"] = reason!.Trim() },
        }, Array.Empty<string>());
    }

    /// Build (never write) the undo of one active acceptance.
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewUndoAsync(long id, string? reason, CancellationToken ct)
    {
        if (ReasonProblem(reason) is { } p) return (null, new[] { p });
        var a = (await _store.ActiveAsync(ct)).FirstOrDefault(x => x.Id == id);
        if (a is null) return (null, new[] { "this acceptance is not active any more -- nothing to undo" });
        return (new StagedChange
        {
            Kind = UndoKind, Title = $"Undo: {a.Table} accepted as empty for {a.Report}",
            Data = new(StringComparer.Ordinal) { ["id"] = id.ToString(CultureInfo.InvariantCulture), ["report"] = a.Report, ["table"] = a.Table, ["reason"] = reason!.Trim() },
        }, Array.Empty<string>());
    }

    public async Task<ChangePreview> PreviewAsync(StagedChange c, CancellationToken ct)
    {
        var why = new List<string>(); var warnings = new List<string>();
        var report = c.Get("report"); var table = c.Get("table");
        if (c.Kind == AcceptKind)
        {
            if (await HeldRowAsync(report, table, ct) is null) why.Add($"{report} is not held for {table} any more -- nothing to accept");
            warnings.Add($"From the next run {report} is not held for {table}: it shows empty and complete, and the findings it showed close as 'Report changed' (never as fixed). If {table} has rows again, the acceptance ends by itself.");
            return new ChangePreview(c, $"{report}: held at its last complete result ({table} returned no rows)", $"{report}: {table} accepted as empty for good", why, warnings);
        }
        if (!long.TryParse(c.Get("id"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var id) || (await _store.ActiveAsync(ct)).All(x => x.Id != id))
            why.Add("this acceptance is not active any more -- nothing to undo");
        warnings.Add($"From the next run {report} is held again while {table} returns no rows.");
        return new ChangePreview(c, $"{report}: {table} accepted as empty for good", $"{report}: judged as usual (held while {table} returns no rows)", why, warnings);
    }

    public async Task<WriteResult> CommitAsync(StagedChange c, string by, CancellationToken ct)
    {
        var report = c.Get("report") ?? ""; var table = c.Get("table") ?? ""; var reason = c.Get("reason") ?? c.Title;
        if (c.Kind == AcceptKind)
        {
            var o = await _store.AcceptAsync(report, table, reason, by, ct);
            return o switch
            {
                "Accepted" => new WriteResult(WriteStatus.Saved, $"{table} accepted as empty for good for {report} -- from the next run"),
                "Already" => new WriteResult(WriteStatus.Saved, $"{table} was already accepted as empty for {report}"),
                "Missing" => new WriteResult(WriteStatus.Refused, "this database has no place for the acceptance yet -- the next update adds it"),
                "NotSilent" => new WriteResult(WriteStatus.Refused, $"{table} did not return zero rows in a count that succeeded -- a read that failed is never accepted"),
                _ => new WriteResult(WriteStatus.Refused, $"{report} is not held for {table} any more -- nothing was accepted"),
            };
        }
        if (!long.TryParse(c.Get("id"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var id)) return new WriteResult(WriteStatus.Refused, "the change names no acceptance");
        var u = await _store.UndoAsync(id, reason, by, ct);
        return u switch
        {
            "Undone" => new WriteResult(WriteStatus.Saved, $"{report}: {table} is no longer accepted as empty -- from the next run"),
            "Missing" => new WriteResult(WriteStatus.Refused, "this database has no place for the acceptance yet -- the next update adds it"),
            _ => new WriteResult(WriteStatus.Refused, "this acceptance is not active any more -- nothing to undo"),
        };
    }
}
