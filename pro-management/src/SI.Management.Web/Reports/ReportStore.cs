using System.Globalization;
using System.Text;
using SI.Management.Core.ProData;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Reports;

/// <summary>
/// The report catalog as Risk Analysis will read it on its next run (#274): the vendor's rareport templates with the
/// customer's cfg.ItemOverride rows over them (Merge-SIProItems: template only -> the template; override -> theirs;
/// disable -> switched off; a retired template without an override -> gone; an override without a template -> their own),
/// plus the output scope items and the per-report weights items (#275 G7), in the catalog's order.
/// </summary>
public sealed record ReportState(IReadOnlyList<ReportItem> Items, IReadOnlyDictionary<string, (string State, string? Body)> Scopes,
    IReadOnlyDictionary<string, (string State, string? Body)> Weights, bool CatalogFromDatabase, IReadOnlyList<string> Notes)
{
    public IEnumerable<ReportItem> Reports => Items.Where(i => !i.IsTemplate);
    public IEnumerable<ReportItem> Templates => Items.Where(i => i.IsTemplate);
    public ReportItem? Find(string key) => Items.FirstOrDefault(i => i.Key == key);

    /// Report template name -> the reports it includes (switched-off templates left out).
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Membership() =>
        Templates.Where(t => t.Enabled).ToDictionary(t => t.Name, t => ReportBody.Included(t.Json), StringComparer.Ordinal);

    public OutputScope ScopeOf(string dest) =>
        Scopes.TryGetValue(dest, out var s) && s.State == "override" ? OutputScope.FromBody(dest, s.Body) ?? OutputScope.Empty(dest) : OutputScope.Empty(dest);

    public string ExpectedOld(string kind, string key)
    {
        var d = kind == "outputscope" ? Scopes : kind == "weights" ? Weights : null;
        if (d is not null) return d.TryGetValue(key, out var s) ? s.State + (s.Body is null ? "" : ":" + s.Body) : "";
        return Find(key)?.ExpectedOld ?? "";
    }
}

/// The newest collection's findings and the current assets, grouped for the per-destination preview counts.
public sealed record ReportPreviewData(IReadOnlyList<FindingGroup> Findings, IReadOnlyList<AssetGroup> Assets, DateTime? CollectionTime, string? Note);

public interface IReportStore
{
    /// cfg.Template and cfg.ItemOverride exist.
    Task<bool> SchemaAsync(CancellationToken ct);
    Task<ReportState> LoadAsync(CancellationToken ct);
    /// All the writes in ONE transaction, a cfg.ChangeLog row each; refused as Stale (nothing written) when any item's row
    /// is not what the editor saw (ItemWrite.ExpectedOld).
    Task<WriteResult> CommitAsync(IReadOnlyList<ItemWrite> writes, string by, string reason, CancellationToken ct);
    Task<ReportPreviewData> PreviewAsync(CancellationToken ct);
    /// Owner 2026-10-19: how many findings on how many assets a finding destination's scope lets through, of the newest
    /// complete Detailed collection (null = no such collection).
    Task<ScopeCount?> ScopeCountAsync(OutputScope scope, IReadOnlySet<string>? resolved, CancellationToken ct) => Task.FromResult<ScopeCount?>(null);
    /// The values of one finding column in the newest complete Detailed collection, with how many findings hold each.
    Task<IReadOnlyList<(string Value, long N)>> ValueCountsAsync(string column, CancellationToken ct) => Task.FromResult<IReadOnlyList<(string, long)>>(Array.Empty<(string, long)>());
}

public sealed class SqlReportStore : IReportStore
{
    public const string MissingSchemaMessage = "this database has no template tables yet (cfg.Template, cfg.ItemOverride) -- the report catalog is still read from the installation; setup or the next update creates them";
    public static readonly IReadOnlyList<string> Kinds = ["rareport", "outputscope", "weights"];

    public const string SchemaSql = """
SELECT CASE WHEN OBJECT_ID(N'cfg.Template') IS NULL OR OBJECT_ID(N'cfg.ItemOverride') IS NULL THEN 0 ELSE 1 END AS HasTables;
""";

    public const string TemplatesSql = """
SELECT ItemKey, BodyJson, SortOrder, RetiredAt
FROM cfg.Template
WHERE Kind = N'rareport'
ORDER BY SortOrder, ItemKey;
""";

    public const string OverridesSql = """
SELECT Kind, ItemKey, State, BodyJson
FROM cfg.ItemOverride
WHERE Kind IN (N'rareport', N'outputscope', N'weights')
ORDER BY Kind, ItemKey;
""";

    /// <summary>
    /// What each output would hold, per (report, domain, severity, tier, CVE or not) of the published run's collection, and
    /// the assets per kind and tier -- #812: the finding groups as the data sync wrote them once per collection
    /// (sidata.ReportPreviewCount; a large customer's 1,117,524 findings were grouped on each open of the page before). A
    /// collection without them answers one 'preparing' row (the page says so), a database without the tables 'noschema'.
    /// The assets (sidata.Asset, one row per CI) are grouped as before.
    /// </summary>
    /// <summary>
    /// #855 M17 (owner 2026-10-21: "default filter is active, so it should be active only"): the assets per kind and tier
    /// are the ACTIVE CIs' -- an asset whose CI (the CI id = the asset key, else the CI that carries it as a linked object) is
    /// not seen or retired is left out; an asset no CI carries counts (it is not known to be gone).
    /// </summary>
    public const string ActiveAsset =
        "NOT EXISTS (SELECT 1 FROM sidata.Ci AS lc WHERE lc.CiId = a.AssetKey AND lc.Lifecycle IN (N'not_seen', N'retired')) " +
        "AND NOT EXISTS (SELECT 1 FROM sidata.Ci AS lc WHERE NOT EXISTS (SELECT 1 FROM sidata.Ci AS own WHERE own.CiId = a.AssetKey) " +
        "AND lc.Lifecycle IN (N'not_seen', N'retired') AND lc.CiId = (SELECT TOP (1) l.CiId FROM sidata.CiLink AS l WHERE l.NativeId = LOWER(a.AssetKey) ORDER BY l.IsPrimary DESC, l.LastSeen DESC))";
    public const string PreviewSql = $$"""
IF OBJECT_ID(N'sidata.Finding') IS NULL OR OBJECT_ID(N'sidata.Collection') IS NULL
BEGIN
    SELECT CAST(NULL AS nvarchar(16)) AS Grp WHERE 1 = 0;
    RETURN;
END;
DECLARE @c int, @t datetime2(3);
SELECT TOP (1) @c = pc.CollectionId, @t = pc.CollectionTime FROM sidata.vPublishedCollection AS pc WHERE pc.Kind = N'Detailed';
IF OBJECT_ID(N'sidata.ReportPreviewCount') IS NULL OR OBJECT_ID(N'sidata.ReportPreviewState') IS NULL
    SELECT N'noschema' AS Grp, CAST(NULL AS nvarchar(256)) AS ReportName, CAST(NULL AS nvarchar(128)) AS SecurityDomain, CAST(NULL AS nvarchar(30)) AS Severity,
           CAST(NULL AS int) AS Tier, 0 AS IsCve, CONVERT(bigint, 0) AS N, @t AS CollectionTime, CAST(NULL AS nvarchar(16)) AS AssetKind
    UNION ALL
    SELECT N'asset', NULL, NULL, NULL, CONVERT(int, a.Tier), 0, COUNT_BIG(*), @t, a.AssetKind
    FROM sidata.Asset a WHERE {{ActiveAsset}} GROUP BY a.AssetKind, a.Tier;
ELSE
    SELECT N'finding' AS Grp, p.ReportName, p.SecurityDomain, p.Severity, CONVERT(int, p.Tier) AS Tier, CONVERT(int, p.IsCve) AS IsCve, p.Findings AS N,
           @t AS CollectionTime, CAST(NULL AS nvarchar(16)) AS AssetKind
    FROM sidata.ReportPreviewCount AS p WHERE p.CollectionId = @c
    UNION ALL
    SELECT N'preparing', NULL, NULL, NULL, NULL, 0, CONVERT(bigint, 0), @t, NULL
    WHERE @c IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sidata.ReportPreviewState AS s WHERE s.CollectionId = @c)
    UNION ALL
    SELECT N'asset', NULL, NULL, NULL, CONVERT(int, a.Tier), 0, COUNT_BIG(*), @t, a.AssetKind
    FROM sidata.Asset a WHERE {{ActiveAsset}} GROUP BY a.AssetKind, a.Tier;
""";

    /// The same finding groups computed per request from every finding -- what the page read before 2026-10-19. Kept ONLY as
    /// the reference the equality check and the measurement compare the stored groups with; nothing reads it.
    public const string PreviewLiveSql = $$"""
IF OBJECT_ID(N'sidata.Finding') IS NULL OR OBJECT_ID(N'sidata.Collection') IS NULL
BEGIN
    SELECT CAST(NULL AS nvarchar(16)) AS Grp WHERE 1 = 0;
    RETURN;
END;
DECLARE @c int, @t datetime2(3);
SELECT TOP (1) @c = pc.CollectionId, @t = pc.CollectionTime FROM sidata.vPublishedCollection AS pc WHERE pc.Kind = N'Detailed';
SELECT N'finding' AS Grp, f.ReportName, f.SecurityDomain, f.Severity, CONVERT(int, f.Tier) AS Tier,
       CASE WHEN f.Cve IS NULL OR f.Cve = N'' THEN 0 ELSE 1 END AS IsCve, COUNT_BIG(*) AS N, @t AS CollectionTime, CAST(NULL AS nvarchar(16)) AS AssetKind
FROM sidata.Finding f WHERE f.CollectionId = @c
GROUP BY f.ReportName, f.SecurityDomain, f.Severity, f.Tier, CASE WHEN f.Cve IS NULL OR f.Cve = N'' THEN 0 ELSE 1 END
UNION ALL
SELECT N'asset', NULL, NULL, NULL, CONVERT(int, a.Tier), 0, COUNT_BIG(*), @t, a.AssetKind
FROM sidata.Asset a WHERE {{ActiveAsset}} GROUP BY a.AssetKind, a.Tier;
""";

    private readonly ISqlExecutor _sql;
    public SqlReportStore(ISqlExecutor sql) => _sql = sql;

    public async Task<bool> SchemaAsync(CancellationToken ct)
    {
        var r = await _sql.QueryAsync(SchemaSql, new Dictionary<string, object?>(), ct);
        return r.Count > 0 && r[0].Long("HasTables") == 1;
    }

    public sealed record TemplateRow(string Key, string? Body, int SortOrder, bool Retired);
    public sealed record OverrideRow(string Kind, string Key, string State, string? Body);

    public async Task<ReportState> LoadAsync(CancellationToken ct)
    {
        var t = await _sql.QueryAsync(TemplatesSql, new Dictionary<string, object?>(), ct);
        var o = await _sql.QueryAsync(OverridesSql, new Dictionary<string, object?>(), ct);
        return Merge(t.Select(r => new TemplateRow(r.Str("ItemKey") ?? "", r.Str("BodyJson"), (int)(r.Long("SortOrder") ?? 0), r.Date("RetiredAt") is not null)).ToList(),
                     o.Select(r => new OverrideRow(r.Str("Kind") ?? "", r.Str("ItemKey") ?? "", r.Str("State") ?? "", r.Str("BodyJson"))).ToList());
    }

    /// Merge-SIProItems for the rareport kind (and the outputscope / weights rows as they are).
    public static ReportState Merge(IReadOnlyList<TemplateRow> templates, IReadOnlyList<OverrideRow> overrides)
    {
        var notes = new List<string>();
        var ovr = overrides.Where(x => x.Kind == "rareport").ToDictionary(x => x.Key, StringComparer.Ordinal);
        var items = new List<ReportItem>();
        foreach (var t in templates)
        {
            ovr.TryGetValue(t.Key, out var o);
            if (t.Body is null) { notes.Add($"the vendor item {t.Key} has no body -- republish the templates"); continue; }
            if (o?.State == "override" && o.Body is not null) { items.Add(new ReportItem(t.Key, ReportOrigin.Changed, true, o.Body, t.Retired ? null : t.Body, o.State, o.Body, t.SortOrder)); continue; }
            if (t.Retired) continue;
            if (o?.State == "disable") { items.Add(new ReportItem(t.Key, ReportOrigin.Vendor, false, t.Body, t.Body, o.State, o.Body, t.SortOrder)); continue; }
            items.Add(new ReportItem(t.Key, ReportOrigin.Vendor, true, t.Body, t.Body, o?.State, o?.Body, t.SortOrder));
        }
        var tplKeys = templates.Select(x => x.Key).ToHashSet(StringComparer.Ordinal);
        foreach (var o in overrides.Where(x => x.Kind == "rareport" && !tplKeys.Contains(x.Key) && x.State == "override" && x.Body is not null).OrderBy(x => x.Key, StringComparer.Ordinal))
            items.Add(new ReportItem(o.Key, ReportOrigin.Own, true, o.Body!, null, o.State, o.Body, int.MaxValue));
        var scopes = overrides.Where(x => x.Kind == "outputscope").ToDictionary(x => x.Key, x => (x.State, x.Body), StringComparer.Ordinal);
        var weights = overrides.Where(x => x.Kind == "weights").ToDictionary(x => x.Key, x => (x.State, x.Body), StringComparer.Ordinal);
        if (templates.Count == 0) notes.Add("no Risk Analysis report templates are published in this database yet -- the catalog is read from the installation until setup (or the next update) publishes them; reports created here apply from then on");
        return new ReportState(items, scopes, weights, templates.Count > 0, notes);
    }

    public async Task<WriteResult> CommitAsync(IReadOnlyList<ItemWrite> writes, string by, string reason, CancellationToken ct)
    {
        if (writes.Count == 0) return new WriteResult(WriteStatus.Refused, "nothing to write");
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var (sql, p) = CommitBatch(writes, by, reason);
        var rows = await _sql.QueryAsync(sql, p, ct);
        return (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
        {
            "Saved" => new WriteResult(WriteStatus.Saved, $"saved: {writes.Count} item change(s)"),
            "Stale" => new WriteResult(WriteStatus.Stale, "an item changed since this was staged -- nothing was written; stage it again"),
            "Missing" => new WriteResult(WriteStatus.Refused, MissingSchemaMessage + " -- nothing was written"),
            _ => throw new InvalidOperationException("the report write returned no outcome"),
        };
    }

    /// The ONE batch a commit sends: per write, the row is checked against what the editor saw (under lock), then the
    /// cfg.ItemOverride change and its cfg.ChangeLog row (Name = the item key, Scope 'item', Kind = the item kind). Any
    /// item that moved -> the whole batch is rolled back and answers Stale.
    public static (string Sql, Dictionary<string, object?> Params) CommitBatch(IReadOnlyList<ItemWrite> writes, string by, string reason)
    {
        var p = new Dictionary<string, object?>
        {
            ["By"] = by.Length > 256 ? by[..256] : by,
            ["Reason"] = string.IsNullOrWhiteSpace(reason) ? "" : reason.Trim().Length > 400 ? reason.Trim()[..400] : reason.Trim(),
        };
        var sb = new StringBuilder();
        sb.Append("""
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.ItemOverride') IS NULL OR OBJECT_ID(N'cfg.Template') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @old nvarchar(max), @bv nvarchar(32), @bh char(64);

""");
        for (var i = 0; i < writes.Count; i++)
        {
            var w = writes[i];
            if (!SqlReportStore.Kinds.Contains(w.Kind)) throw new InvalidOperationException($"'{w.Kind}' is not a kind the report designer writes");
            if (w.State is not ("override" or "disable" or "inherit")) throw new InvalidOperationException($"'{w.State}' is not a state");
            p[$"kd{i}"] = w.Kind; p[$"k{i}"] = w.Key; p[$"s{i}"] = w.State; p[$"b{i}"] = w.State == "override" ? w.Body : null; p[$"e{i}"] = w.ExpectedOld;
            sb.Append(CultureInfo.InvariantCulture, $"""
SET @old = (SELECT State + COALESCE(N':' + BodyJson, N'') FROM cfg.ItemOverride WITH (UPDLOCK, HOLDLOCK) WHERE Kind = @kd{i} AND ItemKey = @k{i});
IF COALESCE(@old, N'') <> @e{i}
BEGIN
    ROLLBACK;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;
SELECT @bv = NULL, @bh = NULL;
SELECT @bv = [Version], @bh = BodyHash FROM cfg.Template WHERE Kind = @kd{i} AND ItemKey = @k{i} AND RetiredAt IS NULL;
IF @s{i} = N'inherit'
    DELETE FROM cfg.ItemOverride WHERE Kind = @kd{i} AND ItemKey = @k{i};
ELSE IF @old IS NOT NULL
    UPDATE cfg.ItemOverride SET State = @s{i}, BodyJson = @b{i}, Format = N'json', BaseVersion = @bv, BaseHash = @bh, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Kind = @kd{i} AND ItemKey = @k{i};
ELSE
    INSERT cfg.ItemOverride (Kind, ItemKey, State, BodyJson, Format, BaseVersion, BaseHash, UpdatedBy) VALUES (@kd{i}, @k{i}, @s{i}, @b{i}, N'json', @bv, @bh, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@k{i}, N'item', @kd{i}, CASE WHEN @s{i} = N'inherit' THEN N'Reset' ELSE N'Set' END, @old, @s{i} + COALESCE(N':' + @b{i}, N''), @By, @Reason);

""");
        }
        sb.Append("COMMIT;\nSELECT N'Saved' AS Outcome;\n");
        return (sb.ToString(), p);
    }

    /// The finding columns a scope count and the scope filters' value lists may read.
    /// The fixed columns plus every scope filter's finding column (ScopeFilters.Fields) -- a filter that offers counts can read them.
    public static readonly IReadOnlySet<string> CountColumns = new HashSet<string>(
        new[] { "Severity", "SecurityDomain", "Tier", "ReportName" }.Concat(OutputScopeSql.OptionalColumns), StringComparer.Ordinal);

    private IReadOnlySet<string>? _columns;

    private async Task<IReadOnlySet<string>> ColumnsAsync(CancellationToken ct)
    {
        if (_columns is { } c) return c;
        var row = (await _sql.QueryAsync(OutputScopeSql.ColumnsSql, new Dictionary<string, object?>(), ct)).FirstOrDefault();
        var set = new HashSet<string>(OutputScopeSql.OptionalColumns.Where(n => row?.Long(n) == 1), StringComparer.Ordinal);
        if (set.Count == OutputScopeSql.OptionalColumns.Count) _columns = set;   // keep it once the schema is complete
        return set;
    }

    public async Task<ScopeCount?> ScopeCountAsync(OutputScope scope, IReadOnlySet<string>? resolved, CancellationToken ct)
    {
        var (text, p, notCounted) = OutputScopeSql.Count(scope, resolved, await ColumnsAsync(ct));
        var r = (await _sql.QueryAsync(text, p, ct)).FirstOrDefault();
        if (r is null || r.Date("CollectionTime") is null) return null;
        return new ScopeCount(r.Long("Findings") ?? 0, r.Long("Assets") ?? 0, r.Long("TotalFindings") ?? 0, r.Long("TotalAssets") ?? 0, r.Date("CollectionTime"), notCounted);
    }

    public async Task<IReadOnlyList<(string Value, long N)>> ValueCountsAsync(string column, CancellationToken ct)
    {
        if (!CountColumns.Contains(column)) throw new ArgumentException($"'{column}' is not a column the scope counts");
        if (OutputScopeSql.OptionalColumns.Contains(column) && !(await ColumnsAsync(ct)).Contains(column)) return Array.Empty<(string, long)>();
        var text = $"""
IF OBJECT_ID(N'sidata.Finding') IS NULL OR OBJECT_ID(N'sidata.vPublishedCollection') IS NULL
BEGIN
    SELECT CAST(NULL AS nvarchar(400)) AS V, CAST(NULL AS bigint) AS N WHERE 1 = 0;
    RETURN;
END;
DECLARE @c int;
-- one trusted run (PublishedRun.cs): the published Detailed collection's values, never "the newest" worked out here
SELECT TOP (1) @c = pc.CollectionId FROM sidata.vPublishedCollection AS pc WHERE pc.Kind = N'Detailed';
SELECT TOP (500) CONVERT(nvarchar(400), f.[{column}]) AS V, COUNT_BIG(*) AS N
FROM sidata.Finding AS f WHERE f.CollectionId = @c AND f.[{column}] IS NOT NULL
GROUP BY f.[{column}] ORDER BY COUNT_BIG(*) DESC;
""";
        return (await _sql.QueryAsync(text, new Dictionary<string, object?>(), ct)).Where(x => !string.IsNullOrWhiteSpace(x.Str("V"))).Select(x => (x.Str("V")!.Trim(), x.Long("N") ?? 0)).ToList();
    }

    public async Task<ReportPreviewData> PreviewAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(PreviewSql, new Dictionary<string, object?>(), ct);
        if (rows.Count == 0) return new ReportPreviewData([], [], null, "no findings in the Pro database yet (no complete Detailed collection)");
        int? Tier(SqlRow r) => r.Long("Tier") is { } n ? (int)n : null;
        // #812: the finding groups are the data sync's per collection -- not written yet / no tables: the assets only, and said
        var waiting = rows.Any(r => r.Str("Grp") == "preparing") ? PreparingNote : rows.Any(r => r.Str("Grp") == "noschema") ? NoSchemaNote : null;
        return new ReportPreviewData(
            rows.Where(r => r.Str("Grp") == "finding").Select(r => new FindingGroup(r.Str("ReportName"), r.Str("SecurityDomain"), r.Str("Severity"), Tier(r), r.Long("IsCve") == 1, r.Long("N") ?? 0)).ToList(),
            rows.Where(r => r.Str("Grp") == "asset").Select(r => new AssetGroup(r.Str("AssetKind"), Tier(r), r.Long("N") ?? 0)).ToList(),
            rows[0].Date("CollectionTime"), waiting);
    }

    /// What the Outputs page says while the published collection's finding groups are not written (#812).
    public const string PreparingNote = "the counts per report of this collection are being prepared: the data sync works them out once per collection, right after it is loaded -- open the page again in a few minutes";
    public const string NoSchemaNote = "the counts per report need the database update that adds their table: the updater adds it (setup\\Initialize-SIDataSql.ps1 -- it only adds), and the next data sync fills it";
}
