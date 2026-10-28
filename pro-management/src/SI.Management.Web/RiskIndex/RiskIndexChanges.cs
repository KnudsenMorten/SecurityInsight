using System.Globalization;
using System.Text.Json;
using SI.Management.Core.ProData;
using SI.Management.Web.Changes;
using SI.Management.Web.Settings;

namespace SI.Management.Web.RiskIndex;

/// One finding whose score the edit changes: the asset side and the vulnerability side before / after, and the rows that
/// set each base.
public sealed record RiskIndexPreviewRow(RiskIndexSampleFinding Finding, double AssetBefore, double VulnBefore, double TotalBefore, double AssetAfter, double VulnAfter, double TotalAfter,
    int AssetRowBefore, int VulnRowBefore, int AssetRowAfter, int VulnRowAfter)
{
    /// The risk rating bands in force (risk_rating_bands; null = the built-in 50 / 30 / 15).
    public RiskRatingBands? Bands { get; init; }
    public string RatingBefore => RiskIndexScoring.Rating(TotalBefore, Bands);
    public string RatingAfter => RiskIndexScoring.Rating(TotalAfter, Bands);
}

public sealed record RiskIndexPreview(int Scored, int Changed, int Up, int Down, int RatingChanged, IReadOnlyList<RiskIndexPreviewRow> Rows, DateTime? CollectionTime, string? Note);

/// <summary>
/// The dry run: score findings with the committed index and with the edited one, by the SAME rule Risk Analysis uses
/// (<see cref="RiskIndexScoring"/>, the C# twin of RA-RiskIndexSi.ps1). A finding's risk factors are what its stored
/// sides carry beyond the committed index's base (stored asset side - committed asset base, the same for the
/// vulnerability side), so only the index changes between "before" and "after".
/// </summary>
public static class RiskIndexDryRun
{
    public const int MaxListed = 200;

    public static RiskIndexPreview Compute(IReadOnlyList<RiskIndexRow> committedOrdered, IReadOnlyList<RiskIndexRow> editedOrdered, RiskIndexSample sample, RiskRatingBands? bands = null)
    {
        var before = RiskIndexScoring.BuildRules(committedOrdered);
        var after = RiskIndexScoring.BuildRules(editedOrdered);
        var changed = new List<RiskIndexPreviewRow>();
        int up = 0, down = 0, rating = 0;
        foreach (var f in sample.Findings)
        {
            var (ab, vb) = RiskIndexScoring.Score(before, f.Values);
            var (aa, va) = RiskIndexScoring.Score(after, f.Values);
            var rfA = f.StoredAsset is { } sa ? sa - ab.Score : 0.0;
            var rfV = f.StoredVulnerability is { } sv ? sv - vb.Score : 0.0;
            var tb = RiskIndexScoring.Total(ab.Score, rfA, vb.Score, rfV);
            var ta = RiskIndexScoring.Total(aa.Score, rfA, va.Score, rfV);
            if (ab.Score == aa.Score && vb.Score == va.Score) continue;
            var row = new RiskIndexPreviewRow(f, ab.Score + rfA, vb.Score + rfV, tb, aa.Score + rfA, va.Score + rfV, ta, ab.Row, vb.Row, aa.Row, va.Row) { Bands = bands };
            if (ta > tb) up++; else if (ta < tb) down++;
            if (row.RatingBefore != row.RatingAfter) rating++;
            changed.Add(row);
        }
        var listed = changed.OrderByDescending(r => Math.Abs(r.TotalAfter - r.TotalBefore)).ThenBy(r => r.Finding.Id).Take(MaxListed).ToList();
        return new RiskIndexPreview(sample.Findings.Count, changed.Count, up, down, rating, listed, sample.CollectionTime, sample.Note);
    }
}

/// <summary>
/// The Risk index editor's change, through THE staging (Review &amp; commit): ONE staged change holds the whole edited
/// index (rows in order, each with the Precedence a commit stores) and the stamp of the riskindex rows it was made against.
/// Review shows the per-row writes (override / own / disable / back to the vendor); the commit re-derives them from the
/// staged rows and writes them in one transaction with a cfg.ChangeLog row each, refused as stale when anything changed.
/// </summary>
public sealed class RiskIndexChanges : IStagedChangeHandler
{
    public const string ChangeKind = "risk-index";
    private const int Listed = 40;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly IRiskIndexStore _store;
    public RiskIndexChanges(IRiskIndexStore store) => _store = store;

    public bool Handles(string kind) => kind == ChangeKind;

    public static IReadOnlyList<RiskIndexRow> RowsOf(StagedChange c)
    {
        try { return JsonSerializer.Deserialize<List<RiskIndexRow>>(c.Get("rows") ?? "[]", Json) ?? new List<RiskIndexRow>(); }
        catch (JsonException) { return Array.Empty<RiskIndexRow>(); }
    }

    /// The edited rows with the Precedence a commit stores (vendor rows keep the vendor's own place where they can).
    public static IReadOnlyList<RiskIndexRow> WithPrecedence(IReadOnlyList<RiskIndexRow> edited, RiskIndexState state)
    {
        var keys = RiskIndexEditor.Keys(edited);
        var prec = RiskIndexEditor.AssignPrecedence(edited, keys, state.Templates);
        return edited.Select((r, i) => r with { Precedence = prec[i] }).ToList();
    }

    /// Build (never write) the change. The reasons it is refused, or the change to stage.
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewAsync(IReadOnlyList<RiskIndexRow> edited, string? reason, CancellationToken ct)
    {
        if (!await _store.SchemaAsync(ct)) return (null, new[] { SqlRiskIndexStore.MissingSchemaMessage });
        var state = await _store.LoadAsync(ct);
        if (!state.Editable)
            return (null, new[] { (state.NotEditableReason ?? "the vendor's risk index in this database cannot be changed here") + " -- install the newest template pack (Template releases, or the next update) and stage it again" });
        var issues = RiskIndexEditor.Validate(edited);
        if (!RiskIndexEditor.CanStage(issues)) return (null, issues.Where(i => i.Error).Select(i => (i.Row >= 0 ? $"row {i.Row + 1}: " : "") + i.Message).ToList());
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return (null, new[] { "give a reason (at least 3 characters)" });
        var rows = WithPrecedence(edited, state);
        var writes = RiskIndexEditor.Writes(rows, state.Templates, state.Overrides);
        if (writes.Count == 0) return (null, new[] { "nothing changed -- the edited index is the committed one" });
        return (new StagedChange
        {
            Kind = ChangeKind,
            Title = $"Risk index: {Plural(writes.Count, "row change")} ({Plural(rows.Count, "row")} in force)",
            Data = new(StringComparer.Ordinal)
            {
                ["rows"] = JsonSerializer.Serialize(rows, Json), ["stamp"] = state.Stamp, ["reason"] = reason.Trim(),
            },
        }, Array.Empty<string>());
    }

    private static string Plural(int n, string one) => n == 1 ? "1 " + one : ScoreFormat.Count(n) + " " + one + "s";

    public async Task<ChangePreview> PreviewAsync(StagedChange c, CancellationToken ct)
    {
        var warnings = new List<string>();
        if (!await _store.SchemaAsync(ct)) return new ChangePreview(c, "", "", new[] { SqlRiskIndexStore.MissingSchemaMessage }, warnings);
        var state = await _store.LoadAsync(ct);
        var rows = RowsOf(c);
        var why = new List<string>();
        if (state.Stamp != c.Get("stamp")) why.Add("the risk index changed since this was staged -- discard this change and stage it again from the Risk index page");
        var writes = RiskIndexEditor.Writes(rows, state.Templates, state.Overrides);
        if (writes.Count == 0) why.Add("nothing to write any more -- discard this change");
        var issues = RiskIndexEditor.Validate(rows);
        why.AddRange(issues.Where(i => i.Error).Select(i => (i.Row >= 0 ? $"row {i.Row + 1}: " : "") + i.Message));
        warnings.AddRange(issues.Where(i => !i.Error && i.Message.StartsWith("never used", StringComparison.Ordinal)).Select(i => $"row {i.Row + 1}: {i.Message}").Take(10));
        var now = $"{Plural(state.Items.Count, "row")} in force ({Plural(state.Items.Count(i => i.Origin == RiskIndexOrigin.Template), "vendor row")}, {Plural(state.Items.Count(i => i.Origin == RiskIndexOrigin.Override), "changed vendor row")}, {Plural(state.Items.Count(i => i.Origin == RiskIndexOrigin.Own), "row")} of yours)";
        var lines = writes.Take(Listed).Select(w => $"  {w.Key}: {w.Describe}");
        var after = $"{Plural(rows.Count, "row")} in force, first match wins in this order -- {Plural(writes.Count, "row change")}:\n" + string.Join("\n", lines)
                    + (writes.Count > Listed ? $"\n  ... and {ScoreFormat.Count(writes.Count - Listed)} more" : "");
        return new ChangePreview(c, now, after, why, warnings);
    }

    public async Task<WriteResult> CommitAsync(StagedChange c, string by, CancellationToken ct)
    {
        if (!await _store.SchemaAsync(ct)) return new WriteResult(WriteStatus.Refused, SqlRiskIndexStore.MissingSchemaMessage);
        var rows = RowsOf(c);
        if (!RiskIndexEditor.CanStage(RiskIndexEditor.Validate(rows))) return new WriteResult(WriteStatus.Refused, "the staged index is not valid -- discard it and stage it again");
        var state = await _store.LoadAsync(ct);
        var stamp = c.Get("stamp") ?? "";
        if (state.Stamp != stamp) return new WriteResult(WriteStatus.Stale, "the risk index changed since this was staged -- nothing was written; open the Risk index page and stage it again");
        var writes = RiskIndexEditor.Writes(rows, state.Templates, state.Overrides);
        return await _store.CommitAsync(writes, stamp, by, c.Get("reason") ?? c.Title, ct);
    }
}
