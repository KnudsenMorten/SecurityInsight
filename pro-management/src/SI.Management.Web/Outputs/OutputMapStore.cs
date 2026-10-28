using System.Globalization;
using SI.Management.Core.ProData;
using SI.Management.Web.Changes;
using SI.Management.Web.Data;

namespace SI.Management.Web.Outputs;

/// One column of an output as the next run sends it: the shipped column (null = the customer's own), the customer's
/// change (null = none), its conformance state (UpToDate / Overridden / Disabled / UpgradeAvailable / Own) and the
/// override row's version (what a staged change is checked against).
public sealed record OutputColumnRow(string Key, OutputColumn? Shipped, OutputColumn? Override, string State, int SortOrder, long? Version, string? OverrideState,
    DateTime? UpdatedAt, string? UpdatedBy)
{
    /// The column in force: the override, else the shipped one (a removed column is still listed, as removed).
    public OutputColumn InForce => Override ?? Shipped ?? new OutputColumn(OutputMapRules.SplitKey(Key)?.Target ?? Key, "", null, null);
    public bool Removed => OverrideState == ItemOverrideRepository.StateDisable;
    public bool Own => Shipped is null;
    public bool Changed => OverrideState is not null;
}

/// One output with its columns in the order the engine puts them back (the shipped order, the customer's own after).
public sealed record OutputMapView(DataOutEntry Entry, string? Description, string? Grain, IReadOnlyList<OutputColumnRow> Columns)
{
    /// The targets of every column, in the MAP's order (no column moved) -- what a new order's places are counted from.
    public IReadOnlyList<string> MapOrder { get; init; } = Array.Empty<string>();
    /// The output's filter ({ "field": [ values ] }: only those items are sent), as JSON, or null.
    public string? FilterJson { get; init; }
    public int UpgradeAvailable => Columns.Count(c => c.State == TemplateConformance.UpgradeAvailable);
    public int ChangedCount => Columns.Count(c => c.Changed);
    /// The names of the columns the output sends, except one (a name is unique per output).
    public IEnumerable<string> NamesExcept(string key) => Columns.Where(c => c.Key != key && !c.Removed).Select(c => c.InForce.Name);
}

/// <summary>
/// THE OUTPUT MAPS IN THE SETTINGS DATABASE (V3-DATA-MODEL 2.12, REQUIREMENTS #467): the shipped columns are cfg.Template
/// rows of kind 'datamodel' (key 'outputs/&lt;id&gt;:&lt;target&gt;', the header 'outputs/&lt;id&gt;'), installed with the code on
/// every update; the customer's changes are cfg.ItemOverride rows of the same keys. Read-only here -- a change goes through
/// Review &amp; commit (<see cref="OutputMapChanges"/>) and is written by <see cref="ItemOverrideRepository"/>.
/// </summary>
public sealed class OutputMapStore
{
    private readonly ISqlExecutor _sql;
    public OutputMapStore(ISqlExecutor sql) => _sql = sql;

    public const string NotPublishedMessage = "The output maps are not in the settings database yet -- they are installed with the next update. Until then the outputs use the shipped columns and nothing can be changed here.";

    /// Every output-map template row and override (the versioning columns only when the schema has them).
    public const string ListSql = """
IF OBJECT_ID(N'cfg.Template') IS NULL OR OBJECT_ID(N'cfg.ItemOverride') IS NULL
BEGIN
    SELECT CAST(NULL AS nvarchar(128)) AS ItemKey WHERE 1 = 0;
    RETURN;
END;
DECLARE @v bit = CASE WHEN COL_LENGTH(N'cfg.Template', N'ContentHash') IS NULL THEN 0 ELSE 1 END;
IF @v = 1
    EXEC sp_executesql N'
SELECT COALESCE(t.ItemKey, o.ItemKey) AS ItemKey, CASE WHEN t.TemplateId IS NULL THEN 0 ELSE 1 END AS HasTemplate, t.BodyJson AS TemplateBody,
       t.ContentHash, t.BodyHash, t.RetiredAt, t.SortOrder, o.State, o.BodyJson AS OverrideBody, o.BaseHash, o.UpdatedAt, o.UpdatedBy,
       CONVERT(bigint, o.RowVersion) AS Version
FROM cfg.Template AS t
FULL OUTER JOIN cfg.ItemOverride AS o ON o.Kind = t.Kind AND o.ItemKey = t.ItemKey
WHERE COALESCE(t.Kind, o.Kind) = N''datamodel'' AND COALESCE(t.ItemKey, o.ItemKey) LIKE N''outputs/%''
ORDER BY COALESCE(t.ItemKey, o.ItemKey);';
ELSE
SELECT COALESCE(t.ItemKey, o.ItemKey) AS ItemKey, CASE WHEN t.TemplateId IS NULL THEN 0 ELSE 1 END AS HasTemplate, t.BodyJson AS TemplateBody,
       CAST(NULL AS char(64)) AS ContentHash, t.BodyHash, t.RetiredAt, t.SortOrder, o.State, o.BodyJson AS OverrideBody, o.BaseHash, o.UpdatedAt, o.UpdatedBy,
       CONVERT(bigint, o.RowVersion) AS Version
FROM cfg.Template AS t
FULL OUTER JOIN cfg.ItemOverride AS o ON o.Kind = t.Kind AND o.ItemKey = t.ItemKey
WHERE COALESCE(t.Kind, o.Kind) = N'datamodel' AND COALESCE(t.ItemKey, o.ItemKey) LIKE N'outputs/%'
ORDER BY COALESCE(t.ItemKey, o.ItemKey);
""";

    /// Every listed output that has an output map in the database, with its columns; empty when none is published yet.
    public async Task<IReadOnlyList<OutputMapView>> LoadAsync(CancellationToken ct) => Build(await _sql.QueryAsync(ListSql, new Dictionary<string, object?>(), ct));

    /// One output, or null.
    public async Task<OutputMapView?> LoadAsync(string outputId, CancellationToken ct) => (await LoadAsync(ct)).FirstOrDefault(o => o.Entry.Output == outputId);

    /// PURE. The rows of <see cref="ListSql"/> -> one view per listed output (catalog order).
    public static IReadOnlyList<OutputMapView> Build(IEnumerable<SqlRow> rows)
    {
        var byOutput = new Dictionary<string, (string? Description, string? Grain, List<OutputColumnRow> Cols)>(StringComparer.Ordinal);
        var filters = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var r in rows)
        {
            var key = r.Str("ItemKey") ?? "";
            var hasTemplate = r.Long("HasTemplate") == 1;
            var retired = r.Date("RetiredAt") is not null;
            if (!key.StartsWith("outputs/", StringComparison.Ordinal)) continue;
            var colon = key.IndexOf(':');
            var id = colon < 0 ? key[8..] : key[8..colon];
            if (!byOutput.TryGetValue(id, out var e)) { e = (null, null, new List<OutputColumnRow>()); byOutput[id] = e; }
            if (colon < 0)
            {
                // the header: the output's description and grain
                if (hasTemplate && !retired && r.Str("TemplateBody") is { } hb)
                {
                    try
                    {
                        using var d = System.Text.Json.JsonDocument.Parse(hb);
                        var desc = d.RootElement.TryGetProperty("description", out var dv) && dv.ValueKind == System.Text.Json.JsonValueKind.String ? dv.GetString() : null;
                        var grain = d.RootElement.TryGetProperty("grain", out var gv) && gv.ValueKind == System.Text.Json.JsonValueKind.String ? gv.GetString() : null;
                        byOutput[id] = (desc, grain, e.Cols);
                        if (d.RootElement.TryGetProperty("filter", out var fv) && fv.ValueKind == System.Text.Json.JsonValueKind.Object) filters[id] = fv.GetRawText();
                    }
                    catch (System.Text.Json.JsonException) { }
                }
                continue;
            }
            var state = r.Str("State");
            var shipped = hasTemplate && !retired ? OutputMapRules.ParseColumn(r.Str("TemplateBody")) : null;
            var over = state == ItemOverrideRepository.StateOverride ? OutputMapRules.ParseColumn(r.Str("OverrideBody")) : null;
            if (shipped is null && over is null && state != ItemOverrideRepository.StateDisable) continue;   // a retired column nobody changed
            var conf = TemplateConformance.StateOf(shipped is not null, retired, state, r.Str("BaseHash"), r.Str("ContentHash"), r.Str("BodyHash"));
            var sort = (int)(r.Long("SortOrder") ?? int.MaxValue);
            e.Cols.Add(new OutputColumnRow(key, shipped, over, conf, shipped is null ? int.MaxValue : sort, r.Long("Version"), state, r.Date("UpdatedAt"), r.Str("UpdatedBy")));
        }
        var list = new List<OutputMapView>();
        foreach (var entry in OutputMapRules.Catalog)
        {
            if (!byOutput.TryGetValue(entry.Output, out var e) || e.Cols.Count == 0) continue;
            // the order the engine sends them in: the map's order, a column the customer moved at its place
            // (OutputMapRules.Arrange); the columns no longer sent after them
            var mapOrder = e.Cols.OrderBy(c => c.SortOrder).ThenBy(c => c.Key, StringComparer.Ordinal).ToList();
            var cols = OutputMapRules.Arrange(mapOrder.Where(c => !c.Removed).ToList(), c => c.InForce.Position).ToList();
            // a column no longer sent stays listed where the map has it (after the column sent before it in the map)
            foreach (var (removed, at) in mapOrder.Select((c, i) => (c, i)).Where(x => x.c.Removed).ToList())
            {
                var before = mapOrder.Take(at).LastOrDefault(c => cols.Contains(c));
                cols.Insert(before is null ? 0 : cols.IndexOf(before) + 1, removed);
            }
            list.Add(new OutputMapView(entry, e.Description, e.Grain, cols) { MapOrder = mapOrder.Select(c => c.InForce.Target).ToList(), FilterJson = filters.GetValueOrDefault(entry.Output) });
        }
        return list;
    }

    public static string VersionText(long? v) => v?.ToString(CultureInfo.InvariantCulture) ?? "";
}
