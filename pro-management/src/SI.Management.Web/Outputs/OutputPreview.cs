using System.Text.Json.Nodes;
using SI.Management.Core.ProData;
using SI.Management.Web.Data;

namespace SI.Management.Web.Outputs;

/// The first rows an output would send with a set of columns: the header (the names sent) and the cells, or why none.
public sealed record OutputPreviewResult(IReadOnlyList<string> Header, IReadOnlyList<IReadOnlyList<string>> Rows, string? Note);

/// <summary>
/// THE 10-ROW PREVIEW of Configuration &gt; Connectors &gt; Fields sent (and Reports &gt; Workbook fields), owner 2026-10-19:
/// the items read as the data sync reads them for the output (engine\data-out\SI-DataOut.ps1: the CI with the totals of
/// its row, the finding with its CI's values and its lifecycle, the record), a few at a time and by key -- never a whole
/// table -- then mapped by <see cref="OutputMapper"/>. Read-only.
/// </summary>
public sealed class OutputRowPreview(ISqlExecutor sql)
{
    /// How many items are read to find the rows (an output with a filter skips the ones it leaves out).
    public const int Sample = 200;

    public const string CiSql = """
IF OBJECT_ID(N'sidata.Ci') IS NULL
    SELECT CAST(NULL AS nvarchar(64)) AS CiId WHERE 1 = 0;
ELSE
    SELECT TOP (@Take) c.CiId, c.Lifecycle, c.Tier, c.RiskScore, c.WeightedRiskScore, c.OpenFindings, c.LinkCount, c.DocJson
    FROM sidata.Ci AS c
    WHERE c.DocJson IS NOT NULL
    ORDER BY c.WeightedRiskScore DESC, c.CiId;
""";

    public const string FindingSql = """
IF OBJECT_ID(N'sidata.CiFinding') IS NULL OR OBJECT_ID(N'sidata.Ci') IS NULL
    SELECT CAST(NULL AS bigint) AS CiFindingId WHERE 1 = 0;
ELSE IF OBJECT_ID(N'sidata.CiFindingState') IS NULL
    SELECT TOP (@Take) f.CiFindingId, f.CiId, f.AssetId, f.FindingKey, f.RiskScore, f.WeightedRiskScore, f.Tier, f.DocJson,
           c.Name AS CiName, c.Class AS CiClass, c.AssetType AS CiAssetType, c.CmdbId, c.CmdbName, c.CmdbCriticality,
           CAST(NULL AS nvarchar(64)) AS CmdbDataSensitivity,
           CAST(NULL AS nvarchar(16)) AS State, CAST(NULL AS datetime2(3)) AS FirstDetected, CAST(NULL AS datetime2(3)) AS LastSeen,
           CAST(NULL AS datetime2(3)) AS ClosedAt, CAST(NULL AS nvarchar(32)) AS CloseReason, CAST(NULL AS int) AS AbsentRuns
    FROM sidata.CiFinding AS f
    LEFT JOIN sidata.Ci AS c ON c.CiId = f.CiId
    ORDER BY f.CiFindingId;
ELSE
    SELECT TOP (@Take) f.CiFindingId, f.CiId, f.AssetId, f.FindingKey, f.RiskScore, f.WeightedRiskScore, f.Tier, f.DocJson,
           c.Name AS CiName, c.Class AS CiClass, c.AssetType AS CiAssetType, c.CmdbId, c.CmdbName, c.CmdbCriticality,
           CAST(NULL AS nvarchar(64)) AS CmdbDataSensitivity,
           s.State, s.FirstDetected, s.LastSeen, s.ClosedAt, s.CloseReason, s.AbsentRuns
    FROM sidata.CiFinding AS f
    LEFT JOIN sidata.Ci AS c ON c.CiId = f.CiId
    LEFT JOIN sidata.CiFindingState AS s ON s.OwnerKey = COALESCE(f.CiId, N'asset:' + f.AssetId) AND s.FindingKey = f.FindingKey
    ORDER BY f.CiFindingId;
""";

    /// Every finding item, a page at a time by its own key (the test mode export reads them all; never one big read).
    public static string FindingPageSql => FindingSql
        .Replace("SELECT TOP (@Take) f.CiFindingId", "SELECT TOP (@Take) f.CiFindingId", StringComparison.Ordinal)
        .Replace("    ORDER BY f.CiFindingId;", "    WHERE f.CiFindingId > @After\n    ORDER BY f.CiFindingId;", StringComparison.Ordinal);

    /// The finding items, page by page (<see cref="FindingPageSql"/>).
    public async IAsyncEnumerable<JsonObject> FindingItemsAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct, int page = 5000)
    {
        long after = 0;
        var text = FindingPageSql;
        while (true)
        {
            var rows = await sql.QueryAsync(text, new Dictionary<string, object?> { ["Take"] = page, ["After"] = after }, ct);
            if (rows.Count == 0) yield break;
            foreach (var r in rows) yield return FindingItem(r);
            after = rows[^1].Long("CiFindingId") ?? after;
            if (rows.Count < page) yield break;
        }
    }

    /// The first <paramref name="take"/> CI items (<see cref="CiSql"/>: the highest weighted risk first) -- the ServiceNow team
    /// pack's sample of the CI hand-off.
    public async IAsyncEnumerable<JsonObject> CiItemsAsync(int take, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        foreach (var r in await sql.QueryAsync(CiSql, new Dictionary<string, object?> { ["Take"] = take }, ct)) yield return CiItem(r);
    }

    /// Every CI item, a page at a time by its key -- the engine's own read of the CI hand-off (Get-SIDataOutCiSql: the CIs
    /// with a document, by CiId), for the ServiceNow export of every row the CI hand-off would send.
    public const string CiPageSql = """
IF OBJECT_ID(N'sidata.Ci') IS NULL
    SELECT CAST(NULL AS nvarchar(64)) AS CiId WHERE 1 = 0;
ELSE
    SELECT TOP (@Take) c.CiId, c.Lifecycle, c.Tier, c.RiskScore, c.WeightedRiskScore, c.OpenFindings, c.LinkCount, c.DocJson
    FROM sidata.Ci AS c
    WHERE c.CiId > @After AND c.DocJson IS NOT NULL
    ORDER BY c.CiId;
""";

    /// The CI items, page by page (<see cref="CiPageSql"/>); never one big read.
    public async IAsyncEnumerable<JsonObject> CiPagesAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct, int page = 5000)
    {
        var after = "";
        while (true)
        {
            var rows = await sql.QueryAsync(CiPageSql, new Dictionary<string, object?> { ["Take"] = page, ["After"] = after }, ct);
            if (rows.Count == 0) yield break;
            foreach (var r in rows) yield return CiItem(r);
            after = rows[^1].Str("CiId") ?? after;
            if (rows.Count < page) yield break;
        }
    }

    /// Whether the findings per CI hold any row (the data sync builds them per collection).
    public const string HasCiFindingsSql = """
IF OBJECT_ID(N'sidata.CiFinding') IS NULL
    SELECT CAST(0 AS int) AS N;
ELSE
    SELECT CASE WHEN EXISTS (SELECT 1 FROM sidata.CiFinding) THEN 1 ELSE 0 END AS N;
""";

    public async Task<bool> HasCiFindingsAsync(CancellationToken ct) =>
        (await sql.QueryAsync(HasCiFindingsSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Long("N") is > 0;

    /// The published Detailed collection's id, read on its own first (a subquery in the paging statement read the whole
    /// collection at a customer -- the same lesson as the column chooser's sample).
    public static readonly string PublishedRunIdSql = $"SELECT {PublishedRun.DetailedId} AS Id;";

    /// #817 / owner 2026-10-20 ("the export must contain data from the source (si)"): the published run's OWN findings, a
    /// page at a time -- every vulnerability finding (a configuration id on an asset), as the vulnerability connectors'
    /// snapshot reads the run (SI-VulnDesired.ps1). Read when the findings per CI are not built yet.
    public const string RunFindingPageSql = """
SELECT TOP (@Take) f.FindingId, f.AssetKey, f.AssetName, f.ReportName, f.SecurityDomain, f.ConfigurationId, f.Cve, f.Title, f.Severity, f.Tier,
       f.RiskScore, f.RiskScoreWeighted, f.RiskRating, f.Category, f.Subcategory, f.DetailJson
FROM sidata.Finding AS f
WHERE f.CollectionId = @c AND f.FindingId > @After AND NULLIF(f.ConfigurationId, N'') IS NOT NULL AND f.AssetKey IS NOT NULL
ORDER BY f.FindingId;
""";

    /// The published run's finding items, page by page (<see cref="RunFindingPageSql"/>); none when nothing is published.
    public async IAsyncEnumerable<JsonObject> RunFindingItemsAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct, int page = 5000)
    {
        var id = (await sql.QueryAsync(PublishedRunIdSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Long("Id");
        if (id is null) yield break;
        long after = 0;
        while (true)
        {
            var rows = await sql.QueryAsync(RunFindingPageSql, new Dictionary<string, object?> { ["Take"] = page, ["After"] = after, ["c"] = (int)id.Value }, ct);
            if (rows.Count == 0) yield break;
            foreach (var r in rows) yield return RunFindingItem(r);
            after = rows[^1].Long("FindingId") ?? after;
            if (rows.Count < page) yield break;
        }
    }

    /// A run finding as an output item: its row (DetailJson: the Risk Analysis row) with the SI fields the outputs and the
    /// scope read, from the typed columns where the row has no value.
    public static JsonObject RunFindingItem(SqlRow r)
    {
        var it = Doc(r);
        foreach (var (field, col) in new[] { ("si_asset_id", "AssetKey"), ("si_asset_name", "AssetName"), ("si_finding_key", "ConfigurationId"), ("si_cve", "Cve"),
                     ("si_report_name", "ReportName"), ("si_security_domain", "SecurityDomain"), ("si_severity", "Severity"), ("si_tier", "Tier"),
                     ("si_risk_score", "RiskScore"), ("si_weighted_risk_score", "RiskScoreWeighted"), ("si_risk_rating", "RiskRating"),
                     ("si_category", "Category"), ("si_subcategory", "Subcategory"), ("si_title", "Title") })
            Set(it, field, r.GetValueOrDefault(col), true);
        Set(it, "si_finding_state", "open", true);
        Set(it, "record_id", r.GetValueOrDefault("FindingId"));
        return it;
    }

    public const string RecordSql = """
IF OBJECT_ID(N'sidata.CiRecord') IS NULL
    SELECT CAST(NULL AS nvarchar(400)) AS RecordKey WHERE 1 = 0;
ELSE
    SELECT TOP (@Take) r.RecordKey, r.CiId, r.Provider, r.RecordType, r.Class, r.Name, r.SourceLastSeen, r.CollectionTime, r.DocJson
    FROM sidata.CiRecord AS r
    ORDER BY r.RecordKey;
""";

    public const string SummaryNote = "This output sums every finding into groups when it is sent, so its rows cannot be previewed from a few findings.";
    public const string NoItemsNote = "There is no data to preview yet: the rows appear after the next CI build and data sync.";

    /// The preview of <paramref name="columns"/> (in the order sent) for an output of <paramref name="grain"/>.
    public async Task<OutputPreviewResult> ReadAsync(string? grain, IReadOnlyList<OutputColumn> columns, JsonObject? filter, CancellationToken ct, int take = 10)
    {
        var header = columns.Select(c => c.Name).ToList();
        if (grain == "finding_summary") return new OutputPreviewResult(header, Array.Empty<IReadOnlyList<string>>(), SummaryNote);
        var (text, convert) = grain switch
        {
            "ci_finding" => (FindingSql, (Func<SqlRow, JsonObject>)FindingItem),
            "record" => (RecordSql, RecordItem),
            _ => (CiSql, CiItem),
        };
        var rows = await sql.QueryAsync(text, new Dictionary<string, object?> { ["Take"] = Sample }, ct);
        var preview = OutputMapper.Preview(columns, rows.Select(convert), filter, OutputMapper.ShippedValueMaps, take);
        return new OutputPreviewResult(header, preview, preview.Count == 0 ? NoItemsNote : null);
    }

    private static JsonObject Doc(SqlRow r)
    {
        try { return JsonNode.Parse(r.Str("DocJson") ?? "{}") as JsonObject ?? new JsonObject(); }
        catch (System.Text.Json.JsonException) { return new JsonObject(); }
    }

    private static JsonNode? Node(object? v) => v switch
    {
        null or DBNull => null,
        string s => JsonValue.Create(s),
        DateTime d => JsonValue.Create(DateTime.SpecifyKind(d, DateTimeKind.Utc).ToString("o", System.Globalization.CultureInfo.InvariantCulture)),
        bool b => JsonValue.Create(b),
        _ => double.TryParse(Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var n)
            ? JsonValue.Create(n) : JsonValue.Create(Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture)),
    };

    /// The engine's Set-SIDataOutValue: always, or (<paramref name="ifMissing"/>) only where the document has no value.
    private static void Set(JsonObject it, string name, object? value, bool ifMissing = false)
    {
        if (ifMissing && OutputMapper.Get(it, name) is { } have && OutputMapper.Text(have).Length > 0) return;
        if (value is null or DBNull && ifMissing) return;
        it[name] = Node(value);
    }

    /// ConvertFrom-SIDataOutCiRow.
    public static JsonObject CiItem(SqlRow r)
    {
        var it = Doc(r);
        Set(it, "si_ci_id", r.GetValueOrDefault("CiId"), true);
        Set(it, "si_lifecycle", r.GetValueOrDefault("Lifecycle"), true);
        Set(it, "si_tier", r.GetValueOrDefault("Tier"), true);
        Set(it, "si_ci_risk_score", r.GetValueOrDefault("RiskScore"));
        Set(it, "si_ci_weighted_risk_score", r.GetValueOrDefault("WeightedRiskScore"));
        Set(it, "si_open_findings", r.GetValueOrDefault("OpenFindings"));
        Set(it, "si_link_count", r.GetValueOrDefault("LinkCount"), true);
        return it;
    }

    /// ConvertFrom-SIDataOutFindingRow.
    public static JsonObject FindingItem(SqlRow r)
    {
        var it = Doc(r);
        foreach (var (field, col) in new[] { ("si_ci_id", "CiId"), ("si_asset_id", "AssetId"), ("si_finding_key", "FindingKey"), ("si_risk_score", "RiskScore"),
                     ("si_weighted_risk_score", "WeightedRiskScore"), ("si_tier", "Tier"), ("si_asset_name", "CiName"), ("si_class", "CiClass"), ("si_asset_type", "CiAssetType"),
                     ("si_cmdb_id", "CmdbId"), ("si_cmdb_name", "CmdbName"), ("si_cmdb_criticality", "CmdbCriticality"), ("si_cmdb_data_sensitivity", "CmdbDataSensitivity") })
            Set(it, field, r.GetValueOrDefault(col), true);
        Set(it, "si_finding_state", r.Str("State") is { Length: > 0 } st ? st : "open");
        Set(it, "si_first_detected", r.GetValueOrDefault("FirstDetected"), true);
        Set(it, "si_last_detected", r.GetValueOrDefault("LastSeen"));
        Set(it, "si_close_reason", r.GetValueOrDefault("CloseReason"));
        Set(it, "closed_at", r.GetValueOrDefault("ClosedAt"));
        Set(it, "absent_runs", r.GetValueOrDefault("AbsentRuns"));
        Set(it, "record_id", r.GetValueOrDefault("CiFindingId"));
        return it;
    }

    /// ConvertFrom-SIDataOutRecordRow.
    public static JsonObject RecordItem(SqlRow r)
    {
        var it = Doc(r);
        Set(it, "si_record_key", r.GetValueOrDefault("RecordKey"));
        foreach (var (field, col) in new[] { ("si_ci_id", "CiId"), ("si_provider", "Provider"), ("si_record_type", "RecordType"), ("si_class", "Class"), ("si_asset_name", "Name"),
                     ("si_source_last_seen", "SourceLastSeen"), ("si_collection_time", "CollectionTime") })
            Set(it, field, r.GetValueOrDefault(col), true);
        return it;
    }
}
