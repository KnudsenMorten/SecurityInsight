using System.Globalization;
using SI.Management.Web.Changes;
using SI.Management.Web.Settings;

namespace SI.Management.Web.QuerySplitting;

/// <summary>
/// #640: a ONE-TIME reset of a Risk Analysis report's bucket count (or of every report), through THE staging (Review &amp;
/// commit) like every Admin change: staging writes nothing; the commit writes one cfg.RaBucketReset row per template with
/// its cfg.ChangeLog row; the next Risk Analysis run of that template consumes it -- it forgets the count, sizes the report
/// again and records that it did -- so the reset happens exactly once.
/// </summary>
public sealed class QuerySplittingChanges : IStagedChangeHandler
{
    public const string ChangeKind = "bucket-reset";
    public const string AllReports = "*";
    private readonly IQuerySplittingStore _store;
    public QuerySplittingChanges(IQuerySplittingStore store) => _store = store;

    public bool Handles(string kind) => kind == ChangeKind;

    private static IReadOnlyList<string> TemplatesOf(StagedChange c) =>
        (c.Get("templates") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// Build (never write) a reset of one report of one template, or (report null) of every report of every template shown.
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewResetAsync(string? template, string? report, string? reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return (null, new[] { "say why (at least 3 characters) -- it is on the audit trail" });
        var view = await _store.ReadAsync(ct);
        if (!view.HasTables) return (null, new[] { MissingMessage });
        if (report is null)
        {
            var templates = view.Templates;
            if (templates.Count == 0) return (null, new[] { "no report has a bucket count yet -- nothing to reset" });
            return (new StagedChange
            {
                Kind = ChangeKind, Title = "Size every Risk Analysis report's buckets again on the next run",
                Data = new(StringComparer.Ordinal) { ["templates"] = string.Join(";", templates), ["report"] = AllReports, ["reason"] = reason.Trim() },
            }, Array.Empty<string>());
        }
        var row = view.Rows.FirstOrDefault(r => string.Equals(r.Template, template, StringComparison.OrdinalIgnoreCase) && r.Report == report);
        if (row is null) return (null, new[] { $"{report} ({template}) has no bucket count -- nothing to reset" });
        return (new StagedChange
        {
            Kind = ChangeKind, Title = $"Size the buckets of {report} ({row.Template}) again on the next run",
            Data = new(StringComparer.Ordinal) { ["templates"] = row.Template, ["report"] = report, ["reason"] = reason.Trim() },
        }, Array.Empty<string>());
    }

    public const string MissingMessage = "this database has no bucket sizing tables yet -- the next update applies them";

    private static string Describe(BucketView view, IReadOnlyList<string> templates, string? report)
    {
        var rows = view.Rows.Where(r => templates.Contains(r.Template, StringComparer.OrdinalIgnoreCase) && (report is null || r.Report == report)).ToList();
        if (rows.Count == 0) return "(no bucket count)";
        return string.Join("\n", rows.Take(25).Select(r => $"{r.Report} ({r.Template}): {(r.Now is { } n ? n.ToString(CultureInfo.InvariantCulture) : "--")} bucket(s)"))
               + (rows.Count > 25 ? $"\n... and {rows.Count - 25} more" : "");
    }

    public async Task<ChangePreview> PreviewAsync(StagedChange c, CancellationToken ct)
    {
        var why = new List<string>(); var warnings = new List<string>();
        var view = await _store.ReadAsync(ct);
        if (!view.HasTables) return new ChangePreview(c, "", "", new[] { MissingMessage }, warnings);
        var report = c.Get("report") is { } r && r != AllReports ? r : null;
        var templates = TemplatesOf(c);
        if (templates.Count == 0) why.Add("the change names no report template");
        warnings.Add("The next run of each report reset here sizes its buckets again (from its last measured result, or 1, 2, 4, 8 when nothing was measured), so that run can take longer.");
        return new ChangePreview(c, Describe(view, templates, report),
            (report is null ? "Every report" : report) + ": sized again on the next run, once -- the run then remembers the new count", why, warnings);
    }

    public async Task<WriteResult> CommitAsync(StagedChange c, string by, CancellationToken ct)
    {
        var report = c.Get("report") is { } r && r != AllReports ? r : null;
        var templates = TemplatesOf(c);
        if (templates.Count == 0) return new WriteResult(WriteStatus.Refused, "the change names no report template");
        var view = await _store.ReadAsync(ct);
        if (!view.HasTables) return new WriteResult(WriteStatus.Refused, MissingMessage);
        foreach (var t in templates)
        {
            var outcome = await _store.RequestResetAsync(t, report, c.Get("reason") ?? c.Title, Describe(view, new[] { t }, report), by, ct);
            if (outcome == "Missing") return new WriteResult(WriteStatus.Refused, MissingMessage);
            if (outcome != "Saved") return new WriteResult(WriteStatus.Refused, "the reset was not saved: the database gave no answer");
        }
        return new WriteResult(WriteStatus.Saved, (report is null ? "every report" : report) + ": sized again on the next Risk Analysis run");
    }
}
