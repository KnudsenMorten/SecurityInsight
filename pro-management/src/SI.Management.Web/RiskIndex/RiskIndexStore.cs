using System.Globalization;
using System.Text;
using SI.Management.Core.ProData;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.RiskIndex;

/// <summary>
/// The committed risk index as Risk Analysis will read it on its next run: the vendor's riskindex templates with the
/// customer's cfg.ItemOverride rows over them (Merge-SIProItems, engine\pro-settings\SI-ProConfig.ps1), in the order the
/// materialiser writes them (by Precedence, a row without one last). <see cref="HasOrder"/> is false for an index from
/// before the order (v2.2 rows): the engine then puts it in precedence order itself with the same scores, and the editor
/// shows exactly that conversion (<see cref="RiskIndexScoring.ConvertFromV22"/>).
/// </summary>
public sealed record RiskIndexState(
    IReadOnlyList<RiskIndexItem> Items,
    IReadOnlyDictionary<string, RiskIndexRow> Templates,
    IReadOnlyDictionary<string, RiskIndexEditor.OverrideState> Overrides,
    bool HasOrder,
    bool TemplatesHaveOrder,
    string Stamp,
    IReadOnlyList<string> Notes)
{
    /// #559: an index from before the order AND the re-key (2.2 rows, no Precedence), put in first-match order by the 2.2
    /// ladder and then translated -- what Export-SIProConfig writes for the engine. Null otherwise.
    public IReadOnlyList<RiskIndexRow>? LegacyOrdered { get; init; }
    /// #559: the vendor's rows in the database are still keyed by the 2.2 columns (a template pack from before the re-key).
    public bool TemplatesV22 { get; init; }

    /// The rows first-match walks (the converted rows for an index without an order).
    public IReadOnlyList<RiskIndexRow> Ordered => HasOrder ? Items.Select(i => i.Row).ToList() : LegacyOrdered ?? Items.Select(i => i.Row).ToList();
    public int Unplaced => HasOrder ? Items.Count(i => string.IsNullOrWhiteSpace(i.Row.Precedence)) : 0;

    /// Every row in force has its place (the customer's own rows and overrides cover every vendor row): an edit then keeps
    /// the order exactly as shown, even while the vendor's rows in the database are from before the order.
    public bool InForceHasOrder => HasOrder && Items.Count > 0 && Unplaced == 0;

    /// The index can be changed here: the vendor's rows are ordered and keyed by the SI fields, or none of the unordered
    /// ones is in force. Otherwise an edit would have to turn the whole vendor index into the customer's own rows, which
    /// would never follow the vendor again.
    public bool Editable => !TemplatesV22 && (TemplatesHaveOrder || InForceHasOrder);

    /// Why it cannot be changed here (null when it can): one sentence an Admin can act on.
    public string? NotEditableReason => Editable ? null : Templates.Count == 0
        ? "This database has no vendor risk index yet."
        : TemplatesV22
            ? "This database still has the vendor's risk index keyed by the 2.2 columns (it is shown translated to the SI fields)."
            : "This database still has the vendor's risk index from before rows had an order.";
}

/// One current finding to score in the preview: its matcher values and the risk factors its stored sides carry
/// (StoredAsset = RiskConsequenceScore, the asset side; StoredVulnerability = RiskProbabilityScore, the vulnerability side).
public sealed record RiskIndexSampleFinding(long Id, string? AssetName, string? ReportName, string? Title, RiskIndexFinding Values,
    double? StoredAsset, double? StoredVulnerability, double? StoredTotal);

public sealed record RiskIndexSample(IReadOnlyList<RiskIndexSampleFinding> Findings, DateTime? CollectionTime, bool HasData, string? Note);

public interface IRiskIndexStore
{
    /// cfg.Template and cfg.ItemOverride exist.
    Task<bool> SchemaAsync(CancellationToken ct);
    Task<RiskIndexState> LoadAsync(CancellationToken ct);
    /// All the writes, in ONE transaction with one cfg.ChangeLog row each; refused as Stale when the riskindex rows changed
    /// since <paramref name="expectedStamp"/> was read.
    Task<WriteResult> CommitAsync(IReadOnlyList<RiskIndexWrite> writes, string expectedStamp, string by, string reason, CancellationToken ct);
    /// At most <paramref name="max"/> findings of the newest complete Detailed collection.
    Task<RiskIndexSample> SampleAsync(int max, CancellationToken ct);
}

public sealed class SqlRiskIndexStore : IRiskIndexStore
{
    public const string Kind = RiskIndexEditor.Kind;
    public const string MissingSchemaMessage = "this database has no template tables yet (cfg.Template, cfg.ItemOverride) -- the risk index is still read from the installation; setup or the next update creates them";

    public const string SchemaSql = """
SELECT CASE WHEN OBJECT_ID(N'cfg.Template') IS NULL OR OBJECT_ID(N'cfg.ItemOverride') IS NULL THEN 0 ELSE 1 END AS HasTables;
""";

    public const string TemplatesSql = """
SELECT ItemKey, BodyJson, SortOrder, BodyHash, [Version] AS TemplateVersion, RetiredAt
FROM cfg.Template
WHERE Kind = N'riskindex'
ORDER BY SortOrder, ItemKey;
""";

    public const string OverridesSql = """
SELECT ItemKey, State, BodyJson, BaseHash
FROM cfg.ItemOverride
WHERE Kind = N'riskindex'
ORDER BY ItemKey;
""";

    /// What a commit is checked against: the number and the newest RowVersion of the riskindex rows on both sides. Any
    /// insert, update or delete moves one of the four.
    public const string StampSql = """
SELECT (SELECT COUNT(*) FROM cfg.ItemOverride WHERE Kind = N'riskindex') AS OCount,
       (SELECT MAX(CONVERT(bigint, RowVersion)) FROM cfg.ItemOverride WHERE Kind = N'riskindex') AS OMax,
       (SELECT COUNT(*) FROM cfg.Template WHERE Kind = N'riskindex') AS TCount,
       (SELECT MAX(CONVERT(bigint, RowVersion)) FROM cfg.Template WHERE Kind = N'riskindex') AS TMax;
""";

    public const string SampleSql = """
IF OBJECT_ID(N'sidata.Finding') IS NULL OR OBJECT_ID(N'sidata.Collection') IS NULL
BEGIN
    SELECT CAST(NULL AS bigint) AS FindingId WHERE 1 = 0;
    RETURN;
END;
DECLARE @c int, @t datetime2(3);
SELECT TOP (1) @c = pc.CollectionId, @t = pc.CollectionTime FROM sidata.vPublishedCollection AS pc WHERE pc.Kind = N'Detailed';
SELECT TOP (@Max) f.FindingId, f.AssetName, f.ReportName, f.Title, f.SecurityDomain, f.ConfigurationId, f.Severity, f.Tier, f.RiskScore, @t AS CollectionTime,
       COALESCE(JSON_VALUE(f.DetailJson, '$.si_category'), JSON_VALUE(f.DetailJson, '$.Category')) AS Category,
       COALESCE(JSON_VALUE(f.DetailJson, '$.si_subcategory'), JSON_VALUE(f.DetailJson, '$.Subcategory'), JSON_VALUE(f.DetailJson, '$.SubCategory')) AS SubCategory,
       JSON_VALUE(f.DetailJson, '$.si_finding_type') AS FindingType,
       JSON_VALUE(f.DetailJson, '$.si_finding_key') AS FindingKey,
       JSON_VALUE(f.DetailJson, '$.si_component') AS Component,
       JSON_VALUE(f.DetailJson, '$.si_asset_class') AS AssetClass,
       JSON_VALUE(f.DetailJson, '$.si_class') AS SiClass,
       COALESCE(JSON_VALUE(f.DetailJson, '$.si_device_category'), JSON_VALUE(f.DetailJson, '$.DeviceCategory')) AS DeviceCategory,
       COALESCE(JSON_VALUE(f.DetailJson, '$.si_os_platform'), JSON_VALUE(f.DetailJson, '$.OSPlatform'), JSON_VALUE(f.DetailJson, '$.MDE_OSPlatform')) AS OsPlatform,
       JSON_VALUE(f.DetailJson, '$.si_os_name') AS OsName,
       JSON_VALUE(f.DetailJson, '$.si_severity') AS SiSeverity,
       JSON_VALUE(f.DetailJson, '$.CriticalityTierLevel') AS CriticalityTierLevel,
       JSON_VALUE(f.DetailJson, '$.RiskConsequenceScore') AS RiskConsequenceScore,
       JSON_VALUE(f.DetailJson, '$.RiskProbabilityScore') AS RiskProbabilityScore
FROM sidata.Finding f
WHERE f.CollectionId = @c
ORDER BY f.FindingId;
""";

    private readonly ISqlExecutor _sql;
    public SqlRiskIndexStore(ISqlExecutor sql) => _sql = sql;

    public async Task<bool> SchemaAsync(CancellationToken ct)
    {
        var r = await _sql.QueryAsync(SchemaSql, new Dictionary<string, object?>(), ct);
        return r.Count > 0 && r[0].Long("HasTables") == 1;
    }

    public async Task<RiskIndexState> LoadAsync(CancellationToken ct)
    {
        var t = await _sql.QueryAsync(TemplatesSql, new Dictionary<string, object?>(), ct);
        var o = await _sql.QueryAsync(OverridesSql, new Dictionary<string, object?>(), ct);
        var s = await _sql.QueryAsync(StampSql, new Dictionary<string, object?>(), ct);
        var templates = t.Select(r => new TemplateRow(r.Str("ItemKey") ?? "", r.Str("BodyJson"), (int)(r.Long("SortOrder") ?? 0), r.Date("RetiredAt") is not null)).ToList();
        var overrides = o.Select(r => new OverrideRow(r.Str("ItemKey") ?? "", r.Str("State") ?? "", r.Str("BodyJson"))).ToList();
        return Merge(templates, overrides, StampOf(s.Count > 0 ? s[0] : null));
    }

    public static string StampOf(SqlRow? r) => r is null ? "0:0:0:0" : string.Join(':',
        (r.Long("OCount") ?? 0).ToString(CultureInfo.InvariantCulture), (r.Long("OMax") ?? 0).ToString(CultureInfo.InvariantCulture),
        (r.Long("TCount") ?? 0).ToString(CultureInfo.InvariantCulture), (r.Long("TMax") ?? 0).ToString(CultureInfo.InvariantCulture));

    public sealed record TemplateRow(string Key, string? Body, int SortOrder, bool Retired);
    public sealed record OverrideRow(string Key, string State, string? Body);

    /// <summary>
    /// Merge-SIProItems for the riskindex kind, then the materialiser's order. Template only -> the template; override ->
    /// the customer's body; disable -> left out; a retired template without an override -> left out; an override with no
    /// template -> the customer's own row (after the templates, by key). Then: when any row has a Precedence, a stable
    /// sort by it (a row without one last) -- what Export-SIProConfig writes for the engine.
    /// </summary>
    public static RiskIndexState Merge(IReadOnlyList<TemplateRow> templates, IReadOnlyList<OverrideRow> overrides, string stamp)
    {
        var notes = new List<string>();
        var tpl = new Dictionary<string, (TemplateRow T, RiskIndexRow? Row)>(StringComparer.Ordinal);
        foreach (var t in templates) tpl[t.Key] = (t, RiskIndexEditor.FromBody(t.Body));
        var ovr = overrides.ToDictionary(x => x.Key, x => x, StringComparer.Ordinal);
        var items = new List<(RiskIndexItem Item, int Sort, string Key)>();
        foreach (var (key, (t, row)) in tpl)
        {
            if (row is null) { notes.Add($"the vendor row {key} could not be read -- republish the templates"); continue; }
            ovr.TryGetValue(key, out var o);
            if (o?.State == "disable") continue;
            if (o?.State == "override")
            {
                var mine = RiskIndexEditor.FromBody(o.Body);
                if (mine is null) { notes.Add($"your row {key} could not be read -- it is not applied"); continue; }
                items.Add((new RiskIndexItem(key, RiskIndexOrigin.Override, mine, t.Retired ? null : row, false), t.SortOrder, key));
                continue;
            }
            if (t.Retired) continue;
            items.Add((new RiskIndexItem(key, RiskIndexOrigin.Template, row, row, false), t.SortOrder, key));
        }
        foreach (var o in overrides)
        {
            if (tpl.ContainsKey(o.Key) || o.State != "override") continue;
            var mine = RiskIndexEditor.FromBody(o.Body);
            if (mine is null) { notes.Add($"your row {o.Key} could not be read -- it is not applied"); continue; }
            items.Add((new RiskIndexItem(o.Key, RiskIndexOrigin.Own, mine, null, false), int.MaxValue, o.Key));
        }
        var merged = items.OrderBy(x => x.Sort).ThenBy(x => x.Key, StringComparer.Ordinal).Select(x => x.Item).ToList();
        var hasOrder = merged.Any(i => !string.IsNullOrWhiteSpace(i.Row.Precedence));
        if (hasOrder)
            merged = merged.Select((x, i) => (x, i, p: RiskIndexScoring.IsNumber(x.Row.Precedence) ? RiskIndexScoring.Number(x.Row.Precedence.Trim()) : double.MaxValue))
                           .OrderBy(z => z.p).ThenBy(z => z.i).Select(z => z.x).ToList();
        var live = tpl.Where(x => !x.Value.T.Retired && x.Value.Row is not null).ToDictionary(x => x.Key, x => x.Value.Row!, StringComparer.Ordinal);
        var tplOrder = live.Count > 0 && live.Values.All(r => !string.IsNullOrWhiteSpace(r.Precedence));
        // #559: the bodies in force as stored -- 2.2-keyed ones are translated row by row by FromBody; an unordered 2.2 set
        // is first put in first-match order by the 2.2 ladder, then translated (the engine's Export-SIProConfig does the same)
        var tplV22 = templates.Any(t => !t.Retired && RiskIndexEditor.IsV22Body(t.Body));
        IReadOnlyList<RiskIndexRow>? legacy = null;
        if (!hasOrder && merged.Count > 0)
        {
            var bodies = merged.Select(i => i.Origin == RiskIndexOrigin.Template ? tpl[i.Key].T.Body : ovr.TryGetValue(i.Key, out var oo) ? oo.Body : null).ToList();
            if (bodies.All(RiskIndexEditor.IsV22Body))
            {
                var v22 = bodies.Select(b => { using var d = System.Text.Json.JsonDocument.Parse(b!); return RiskIndexV22.RowFromBody(d.RootElement)! with { Precedence = "" }; }).ToList();
                legacy = RiskIndexV22.ConvertToFirstMatch(v22).Select(RiskIndexV22.Translate).ToList();
            }
        }
        return new RiskIndexState(merged, live, overrides.ToDictionary(x => x.Key, x => new RiskIndexEditor.OverrideState(x.State, x.Body), StringComparer.Ordinal),
            hasOrder, tplOrder, stamp, notes) { LegacyOrdered = legacy, TemplatesV22 = tplV22 };
    }

    public async Task<WriteResult> CommitAsync(IReadOnlyList<RiskIndexWrite> writes, string expectedStamp, string by, string reason, CancellationToken ct)
    {
        if (writes.Count == 0) return new WriteResult(WriteStatus.Refused, "nothing to write -- the edited index is the committed one");
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var (sql, p) = CommitBatch(writes, expectedStamp, by, reason);
        var rows = await _sql.QueryAsync(sql, p, ct);
        return (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
        {
            "Saved" => new WriteResult(WriteStatus.Saved, $"risk index saved: {writes.Count} row change(s)"),
            "Stale" => new WriteResult(WriteStatus.Stale, "the risk index changed since this was staged -- nothing was written; open the Risk index page and stage it again"),
            "Missing" => new WriteResult(WriteStatus.Refused, MissingSchemaMessage + " -- nothing was written"),
            _ => throw new InvalidOperationException("the risk index write returned no outcome"),
        };
    }

    /// The ONE batch a commit sends: the stamp check under lock, then per write the cfg.ItemOverride change and its
    /// cfg.ChangeLog row (Name = the item key, Scope 'item', Kind 'riskindex', Action Set | Reset). All or nothing.
    /// #881 the writes travel as ONE JSON parameter (@W: [{ k; s; b }], in order) and are applied one after the other in the
    /// batch -- three parameters per write hit SQL Server's 2,100-parameter limit at about 700 changes.
    public static (string Sql, Dictionary<string, object?> Params) CommitBatch(IReadOnlyList<RiskIndexWrite> writes, string expectedStamp, string by, string reason)
    {
        var p = new Dictionary<string, object?>
        {
            ["Stamp"] = expectedStamp, ["By"] = by.Length > 256 ? by[..256] : by,
            ["Reason"] = string.IsNullOrWhiteSpace(reason) ? "" : reason.Trim().Length > 400 ? reason.Trim()[..400] : reason.Trim(),
            ["W"] = System.Text.Json.JsonSerializer.Serialize(writes.Select(w => new Dictionary<string, string?> { ["k"] = w.Key, ["s"] = w.State, ["b"] = w.State == "override" ? w.Body : null })),
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
DECLARE @oc bigint, @om bigint, @tc bigint, @tm bigint, @old nvarchar(max), @bv nvarchar(32), @bh char(64);
SELECT @oc = COUNT(*), @om = MAX(CONVERT(bigint, RowVersion)) FROM cfg.ItemOverride WITH (UPDLOCK, HOLDLOCK) WHERE Kind = N'riskindex';
SELECT @tc = COUNT(*), @tm = MAX(CONVERT(bigint, RowVersion)) FROM cfg.Template WITH (HOLDLOCK) WHERE Kind = N'riskindex';
IF CONCAT(@oc, N':', COALESCE(@om, 0), N':', @tc, N':', COALESCE(@tm, 0)) <> @Stamp
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;

""");
        sb.Append("""
DECLARE @wr TABLE (N int NOT NULL PRIMARY KEY, K nvarchar(450) NOT NULL, S nvarchar(32) NOT NULL, B nvarchar(max) NULL);
INSERT @wr (N, K, S, B)
SELECT CONVERT(int, j.[key]), x.k, x.s, x.b FROM OPENJSON(@W) AS j
CROSS APPLY OPENJSON(j.value) WITH (k nvarchar(450) '$.k', s nvarchar(32) '$.s', b nvarchar(max) '$.b') AS x;
DECLARE @i int = 0, @last int = ISNULL((SELECT MAX(N) FROM @wr), -1), @k nvarchar(450), @s nvarchar(32), @b nvarchar(max);
WHILE @i <= @last
BEGIN
    SELECT @k = K, @s = S, @b = B FROM @wr WHERE N = @i;
    SET @old = (SELECT State + COALESCE(N':' + BodyJson, N'') FROM cfg.ItemOverride WITH (UPDLOCK, HOLDLOCK) WHERE Kind = N'riskindex' AND ItemKey = @k);
    SELECT @bv = NULL, @bh = NULL;
    SELECT @bv = [Version], @bh = BodyHash FROM cfg.Template WHERE Kind = N'riskindex' AND ItemKey = @k AND RetiredAt IS NULL;
    IF @s = N'inherit'
        DELETE FROM cfg.ItemOverride WHERE Kind = N'riskindex' AND ItemKey = @k;
    ELSE IF @old IS NOT NULL
        UPDATE cfg.ItemOverride SET State = @s, BodyJson = @b, Format = N'json', BaseVersion = @bv, BaseHash = @bh, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Kind = N'riskindex' AND ItemKey = @k;
    ELSE
        INSERT cfg.ItemOverride (Kind, ItemKey, State, BodyJson, Format, BaseVersion, BaseHash, UpdatedBy) VALUES (N'riskindex', @k, @s, @b, N'json', @bv, @bh, @By);
    INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
    VALUES (@k, N'item', N'riskindex', CASE WHEN @s = N'inherit' THEN N'Reset' ELSE N'Set' END, @old, @s + COALESCE(N':' + @b, N''), @By, @Reason);
    SET @i += 1;
END
COMMIT;
SELECT N'Saved' AS Outcome;

""");
        return (sb.ToString(), p);
    }

    public async Task<RiskIndexSample> SampleAsync(int max, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(SampleSql, new Dictionary<string, object?> { ["Max"] = Math.Clamp(max, 1, 20000) }, ct);
        if (rows.Count == 0) return new RiskIndexSample(Array.Empty<RiskIndexSampleFinding>(), null, false, "no findings in the Pro database yet (no complete Detailed collection)");
        // #559: the finding's SI fields when it carries them, else its 2.2 columns translated (Get-SIRiskIndexFindingValues).
        // Stored sides: RiskConsequenceScore = the ASSET side, RiskProbabilityScore = the VULNERABILITY side (RA-RiskScore.ps1).
        var list = rows.Select(r =>
        {
            var values = RiskIndexV22.FindingOf(r.Str("FindingType"), r.Str("FindingKey"), r.Str("ConfigurationId"), r.Str("Category"), r.Str("SubCategory"), r.Str("Component"),
                r.Str("AssetClass"), r.Str("SiClass"), r.Str("SecurityDomain"), r.Str("DeviceCategory"), r.Str("OsPlatform"), r.Str("OsName"),
                r.Str("Severity"), r.Str("SiSeverity"), r.Long("Tier") is { } n ? (int)n : null, r.Str("CriticalityTierLevel"));
            return new RiskIndexSampleFinding(r.Long("FindingId") ?? 0, r.Str("AssetName"), r.Str("ReportName"), r.Str("Title"), values,
                Num(r.Str("RiskConsequenceScore")), Num(r.Str("RiskProbabilityScore")), r.TryGetValue("RiskScore", out var rs) && rs is not null ? Convert.ToDouble(rs, CultureInfo.InvariantCulture) : null);
        }).ToList();
        return new RiskIndexSample(list, rows[0].Date("CollectionTime"), true, null);
    }

    private static double? Num(string? s) => RiskIndexScoring.IsNumber(s) ? RiskIndexScoring.Number(s!.Trim()) : null;
}
