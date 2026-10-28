using System.Text.Json;
using SI.Management.Core.ProData;
using SI.Management.Web.Changes;
using SI.Management.Web.Settings;
using ItemWrite = SI.Management.Core.ProData.ItemWrite; // the report designer's write (not the editors' Changes.ItemWrite)

namespace SI.Management.Web.Reports;

/// <summary>
/// The report designer's changes (#274) and the per-report weights (#275 G7), through THE staging (Review &amp; commit),
/// plugged in as an <see cref="IStagedChangeHandler"/>: each staged change holds its item writes (cfg.ItemOverride rows of
/// kind rareport / outputscope / weights) with the row each one was made against. Review shows them; the commit writes them
/// in one transaction with a cfg.ChangeLog row each, or nothing at all when any row moved since (Stale).
/// </summary>
public sealed class ReportChanges : IStagedChangeHandler
{
    public const string Catalog = "report-catalog";
    public const string Template = "report-template";
    public const string Custom = "report-custom";
    public const string Output = "output-scope";
    public const string Weights = "report-weights";
    public static readonly IReadOnlyList<string> AllKinds = [Catalog, Template, Custom, Output, Weights];
    private const int Listed = 40;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly IReportStore _store;
    public ReportChanges(IReportStore store) => _store = store;

    public bool Handles(string kind) => AllKinds.Contains(kind);

    public static IReadOnlyList<ItemWrite> WritesOf(StagedChange c)
    {
        try { return JsonSerializer.Deserialize<List<ItemWrite>>(c.Get("writes") ?? "[]", Json) ?? new List<ItemWrite>(); }
        catch (JsonException) { return Array.Empty<ItemWrite>(); }
    }

    /// The targets a change writes (two staged changes of the designer touching the same item replace each other).
    public static IReadOnlyList<string> Targets(StagedChange c) => WritesOf(c).Select(w => w.Kind + "/" + w.Key).ToList();

    /// Build (never write) a change; the problems when it cannot be staged.
    public static (StagedChange? Change, IReadOnlyList<string> Problems) New(string kind, string title, IReadOnlyList<ItemWrite> writes, string? reason)
    {
        if (!AllKinds.Contains(kind)) return (null, new[] { $"'{kind}' is not a report designer change" });
        if (writes.Count == 0) return (null, new[] { "nothing changed -- this is what is in force" });
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return (null, new[] { "give a reason (at least 3 characters)" });
        var why = Problems(writes);
        if (why.Count > 0) return (null, why);
        return (new StagedChange
        {
            Kind = kind, Title = title,
            Data = new(StringComparer.Ordinal) { ["writes"] = JsonSerializer.Serialize(writes, Json), ["reason"] = reason.Trim() },
        }, Array.Empty<string>());
    }

    /// The body rules of every write (the engine's Test-SIProItem rules for the kind).
    public static IReadOnlyList<string> Problems(IReadOnlyList<ItemWrite> writes)
    {
        var why = new List<string>();
        foreach (var w in writes.Where(w => w.State == "override"))
        {
            switch (w.Kind)
            {
                case "rareport": why.AddRange(ReportBody.Validate(w.Key, w.Body).Select(x => $"{w.Key}: {x}")); break;
                case "outputscope":
                    var s = OutputScope.FromBody(w.Key, w.Body);
                    if (s is null) why.Add($"{w.Key}: the output scope is not a JSON object");
                    else why.AddRange(s.Validate(s.Templates, s.Reports).Select(x => $"{w.Key}: {x}"));
                    break;
                case "weights":
                    if (!w.Key.StartsWith("report/", StringComparison.Ordinal)) { why.Add($"{w.Key}: only per-report weights are written here"); break; }
                    why.AddRange(DocumentValidator.Validate("weights", "solution", w.Body, Array.Empty<string>()).Select(x => $"{w.Key}: {x}"));
                    break;
                default: why.Add($"'{w.Kind}' is not a kind the report designer writes"); break;
            }
        }
        return why;
    }

    public async Task<ChangePreview> PreviewAsync(StagedChange c, CancellationToken ct)
    {
        var warnings = new List<string>();
        if (!await _store.SchemaAsync(ct)) return new ChangePreview(c, "", "", new[] { SqlReportStore.MissingSchemaMessage }, warnings);
        var state = await _store.LoadAsync(ct);
        var writes = WritesOf(c);
        var why = Problems(writes).ToList();
        if (writes.Count == 0) why.Add("this change holds no write -- discard it");
        var moved = writes.Where(w => state.ExpectedOld(w.Kind, w.Key) != w.ExpectedOld).Select(w => w.Key).ToList();
        if (moved.Count > 0) why.Add($"{string.Join(", ", moved.Take(5))} changed since this was staged -- discard this change and stage it again");
        if (!state.CatalogFromDatabase && writes.Any(w => w.Kind == "rareport")) warnings.Add("the report templates are not published in this database yet: Risk Analysis reads the installation's catalog until they are, so this change applies from then on");
        var now = string.Join("\n", writes.Take(Listed).Select(w => $"  {w.Kind}/{w.Key}: {Was(w.ExpectedOld)}"));
        var after = string.Join("\n", writes.Take(Listed).Select(w => $"  {w.Kind}/{w.Key}: {w.Describe}"))
                    + (writes.Count > Listed ? $"\n  ... and {writes.Count - Listed} more" : "");
        return new ChangePreview(c, now, after, why, warnings);
    }

    private static string Was(string old) => old.Length == 0 ? "as shipped / not set" : old.StartsWith("disable", StringComparison.Ordinal) ? "switched off" : "changed by you";

    public async Task<WriteResult> CommitAsync(StagedChange c, string by, CancellationToken ct)
    {
        if (!await _store.SchemaAsync(ct)) return new WriteResult(WriteStatus.Refused, SqlReportStore.MissingSchemaMessage);
        var writes = WritesOf(c);
        if (writes.Count == 0) return new WriteResult(WriteStatus.Refused, "this change holds no write");
        var why = Problems(writes);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        return await _store.CommitAsync(writes, by, c.Get("reason") ?? c.Title, ct);
    }
}
