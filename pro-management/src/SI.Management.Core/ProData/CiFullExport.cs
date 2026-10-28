using System.Globalization;
using System.Text.Json;

namespace SI.Management.Core.ProData;

// =====================================================================================================================
// "EXPORT ALL COLUMNS" (the CI pages: All CIs and At risk) -- the reads behind a workbook with EVERY field of each CI's
// document (sidata.Ci.DocJson) and the FULL DETAILS each source reported about it (sidata.AssetMetadata, filled when
// SI_AssetProperties = 'full'). Read-only statements, every caller value a parameter (the keys travel as ONE JSON array).
//
// HOW A CI FINDS ITS FULL DETAILS. sidata.AssetMetadata.AssetKey is the collection's CI key (Resolve-SICiKey in the data
// sync: the correlation ledger's id, else the source record's own SI_AssetId) -- the same key sidata.Asset and the At
// risk page use. In v3 the ledger id IS sidata.Ci.CiId, so most rows match the CI directly. A record the ledger did not
// correlate is stored under its own SI_AssetId -- the source's native id (an MDE device id, an Exposure Graph node id,
// 'az:' + an ARM id) -- which the CI build records as sidata.CiLink.NativeId / the part of sidata.CiRecord.RecordKey after
// "provider:". So the keys of one CI are: its CiId, each linked native id, each record's native id, and 'az:' + an ARM id.
// =====================================================================================================================

/// Which v3 tables the database has (a missing one is never named in a statement).
public sealed record CiExportSchema(bool Ci, bool Links, bool Records, bool Metadata);

/// What the export's keys are: CI ids (All CIs) or the collection's asset keys (At risk).
public enum CiExportKeys { CiId, AssetKey }

/// One CI document. Owner = the key asked for; CiId / Name / DocJson null when no CI answers it.
public sealed record CiExportDoc(string Owner, string? CiId, string? Name, string? DocJson);

/// The newest object of one (owner, source system, source record, item).
public sealed record CiExportObject(string Owner, string SourceSystem, string MemberAssetId, string ItemName, DateTime CollectionTime, string PropertiesJson);

/// One linked object of a CI (sidata.CiLink): the source that reported it, what kind of record it is, the source's own id
/// of it, and -- where the source's record is stored (sidata.CiRecord) -- the name the source gives it.
public sealed record CiExportLink(string Owner, string Provider, string RecordType, string NativeId, bool IsPrimary, string? State, DateTime? LastSeen, string? Name);

public interface ICiFullExportViews
{
    /// The linked objects of these CIs (keys = CI ids), per CI the primary one first. Empty on a database without sidata.CiLink.
    Task<IReadOnlyList<CiExportLink>> LinksAsync(CiExportSchema schema, IReadOnlyList<string> keys, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<CiExportLink>>(Array.Empty<CiExportLink>());
    Task<CiExportSchema> SchemaAsync(CancellationToken ct);
    /// Every top-level field name of the documents of these keys.
    Task<IReadOnlyList<string>> DocFieldsAsync(CiExportSchema schema, CiExportKeys by, IReadOnlyList<string> keys, CancellationToken ct);
    Task<IReadOnlyList<CiExportDoc>> DocsAsync(CiExportSchema schema, CiExportKeys by, IReadOnlyList<string> keys, CancellationToken ct);
    /// Every column (<see cref="CiExportFlatten"/> names: source.property[.child]) of the newest objects of these keys.
    Task<IReadOnlyList<string>> MetadataColumnsAsync(CiExportSchema schema, CiExportKeys by, IReadOnlyList<string> keys, CancellationToken ct);
    Task<IReadOnlyList<CiExportObject>> MetadataAsync(CiExportSchema schema, CiExportKeys by, IReadOnlyList<string> keys, CancellationToken ct);
}

/// <summary>The statements. Fixed text (assembled from fixed parts by which tables exist), parameters only, read-only.</summary>
public static class CiFullExportSql
{
    public const string Schema = """
SELECT CASE WHEN OBJECT_ID(N'sidata.Ci') IS NULL THEN 0 ELSE 1 END AS HasCi,
       CASE WHEN OBJECT_ID(N'sidata.CiLink') IS NULL THEN 0 ELSE 1 END AS HasLink,
       CASE WHEN OBJECT_ID(N'sidata.CiRecord') IS NULL THEN 0 ELSE 1 END AS HasRecord,
       CASE WHEN OBJECT_ID(N'sidata.AssetMetadata') IS NULL THEN 0 ELSE 1 END AS HasMetadata;
""";

    /// The keys asked for (one JSON array parameter).
    private const string Ids = "ids AS (SELECT DISTINCT CONVERT(nvarchar(400), j.[value]) AS Owner FROM OPENJSON(@Keys) AS j WHERE j.[value] IS NOT NULL AND j.[value] <> N'')";

    /// The CI documents of the keys: by CI id directly; by asset key the CI whose id it is, else the CI that links it.
    public static string DocsCte(CiExportSchema s, CiExportKeys by)
    {
        if (by == CiExportKeys.CiId)
            return Ids + ",\nd AS (SELECT i.Owner, c.CiId, c.Name, c.DocJson FROM ids AS i JOIN sidata.Ci AS c ON c.CiId = i.Owner)";
        var viaLink = !s.Links ? "" : """

        UNION ALL SELECT l.CiId, 1 FROM sidata.CiLink AS l WHERE l.NativeId = i.Owner
        UNION ALL SELECT l.CiId, 2 FROM sidata.CiLink AS l WHERE i.Owner LIKE N'az:%' AND l.NativeId = SUBSTRING(i.Owner, 4, 450)
""".TrimEnd();
        return Ids + $"""
,
d AS (
    SELECT i.Owner, c.CiId, c.Name, c.DocJson
    FROM ids AS i
    OUTER APPLY (SELECT TOP (1) x.CiId FROM (
        SELECT c0.CiId, 0 AS P FROM sidata.Ci AS c0 WHERE c0.CiId = i.Owner{viaLink}
    ) AS x ORDER BY x.P) AS r
    JOIN sidata.Ci AS c ON c.CiId = r.CiId
)
""";
    }

    public static string DocFields(CiExportSchema s, CiExportKeys by) => "WITH " + DocsCte(s, by) + """

SELECT DISTINCT p.[key] AS Name
FROM d
CROSS APPLY OPENJSON(CASE WHEN ISJSON(d.DocJson) = 1 AND LEFT(LTRIM(d.DocJson), 1) = N'{' THEN d.DocJson END) AS p;
""";

    public static string Docs(CiExportSchema s, CiExportKeys by) => "WITH " + DocsCte(s, by) + """

SELECT d.Owner, d.CiId, d.Name, d.DocJson FROM d;
""";

    /// The linked objects of the CIs asked for (keys = CI ids): one row per CI and linked object, by key (CX_CiLink). The
    /// name is the source record's own (sidata.CiRecord, whose key is "provider:native id" -- a seek on its primary key);
    /// a database without the records leaves it empty.
    public static string Links(CiExportSchema s) => "WITH " + Ids + $"""

SELECT i.Owner, l.Provider, l.RecordType, l.NativeId, CONVERT(int, l.IsPrimary) AS IsPrimary, l.State, l.LastSeen,
       {(s.Records ? "r.Name" : "CAST(NULL AS nvarchar(400))")} AS Name
FROM ids AS i
JOIN sidata.CiLink AS l ON l.CiId = i.Owner{(s.Records ? "\nLEFT JOIN sidata.CiRecord AS r ON r.RecordKey = l.Provider + N':' + l.NativeId" : "")}
ORDER BY i.Owner, l.IsPrimary DESC, l.Provider, l.RecordType, l.NativeId;
""";

    /// Every storage key of each owner (see the header), then the newest object of each (owner, source, record, item).
    /// <paramref name="sourceFilter"/>: only the sources of the JSON array parameter @Sources (the data views' extra columns).
    public static string MetadataCte(CiExportSchema s, CiExportKeys by, bool sourceFilter = false)
    {
        var filter = sourceFilter ? "\n    WHERE a.SourceSystem IN (SELECT CONVERT(nvarchar(32), sf.[value]) FROM OPENJSON(@Sources) AS sf)" : "";
        var keys = "SELECT i.Owner, i.Owner AS AssetKey FROM ids AS i";
        if (by == CiExportKeys.CiId && s.Links)
            keys += """

    UNION SELECT i.Owner, l.NativeId FROM ids AS i JOIN sidata.CiLink AS l ON l.CiId = i.Owner
    UNION SELECT i.Owner, N'az:' + l.NativeId FROM ids AS i JOIN sidata.CiLink AS l ON l.CiId = i.Owner WHERE l.NativeId LIKE N'/subscriptions/%'
""".TrimEnd();
        if (by == CiExportKeys.CiId && s.Records)
            keys += """

    UNION SELECT i.Owner, x.Native FROM ids AS i JOIN sidata.CiRecord AS r ON r.CiId = i.Owner
        CROSS APPLY (SELECT SUBSTRING(r.RecordKey, CHARINDEX(N':', r.RecordKey) + 1, 450) AS Native) AS x
    UNION SELECT i.Owner, N'az:' + x.Native FROM ids AS i JOIN sidata.CiRecord AS r ON r.CiId = i.Owner
        CROSS APPLY (SELECT SUBSTRING(r.RecordKey, CHARINDEX(N':', r.RecordKey) + 1, 450) AS Native) AS x WHERE x.Native LIKE N'/subscriptions/%'
""".TrimEnd();
        return Ids + $"""
,
k AS (
    {keys}
),
m AS (
    SELECT k.Owner, a.SourceSystem, a.MemberAssetId, a.ItemName, a.CollectionTime, a.PropertiesJson,
           ROW_NUMBER() OVER (PARTITION BY k.Owner, a.SourceSystem, a.MemberAssetId, a.ItemName ORDER BY a.CollectionTime DESC, a.AssetMetadataId DESC) AS Rn
    FROM k
    JOIN sidata.AssetMetadata AS a ON a.AssetKey = k.AssetKey{filter}
)
""";
    }

    /// The column names <see cref="CiExportFlatten.Metadata"/> gives, decided in SQL: a top-level object with properties
    /// gives one column per property (source.key.child), anything else one column (source.key).
    public static string MetadataColumns(CiExportSchema s, CiExportKeys by) => "WITH " + MetadataCte(s, by) + """

SELECT DISTINCT (LOWER(m.SourceSystem) COLLATE Latin1_General_BIN2) + N'.' + p.[key] + CASE WHEN c.[key] IS NULL THEN N'' ELSE N'.' + c.[key] END AS Name
FROM m
CROSS APPLY OPENJSON(CASE WHEN LEFT(LTRIM(m.PropertiesJson), 1) = N'{' THEN m.PropertiesJson END) AS p
OUTER APPLY (SELECT q.[key] FROM OPENJSON(CASE WHEN p.[type] = 5 THEN p.[value] END) AS q) AS c
WHERE m.Rn = 1;
""";

    public static string Metadata(CiExportSchema s, CiExportKeys by) => "WITH " + MetadataCte(s, by) + """

SELECT m.Owner, m.SourceSystem, m.MemberAssetId, m.ItemName, m.CollectionTime, m.PropertiesJson
FROM m
WHERE m.Rn = 1
ORDER BY m.Owner, m.SourceSystem, m.MemberAssetId, m.ItemName;
""";
}

/// <summary>The SQL implementation over <see cref="IProSql"/>; every statement passes <see cref="SqlGuard"/> first.</summary>
public sealed class CiFullExportViews(IProSql sql) : ICiFullExportViews
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(120);

    private async Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> Run(string text, IReadOnlyList<string>? keys, CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(text);
        var p = new Dictionary<string, object?>();
        if (keys is not null) p["Keys"] = JsonSerializer.Serialize(keys);
        return await ViewTimeout.Run(t => sql.QueryAsync(new SqlQuery(text, p), t), Timeout, ct).ConfigureAwait(false);
    }

    private static bool Flag(IReadOnlyDictionary<string, object?> r, string c) => r.TryGetValue(c, out var v) && v is not null && Convert.ToInt64(v, CultureInfo.InvariantCulture) != 0;

    public async Task<CiExportSchema> SchemaAsync(CancellationToken ct)
    {
        var rows = await Run(CiFullExportSql.Schema, null, ct).ConfigureAwait(false);
        var r = rows.Count > 0 ? rows[0] : new Dictionary<string, object?>();
        return new CiExportSchema(Flag(r, "HasCi"), Flag(r, "HasLink"), Flag(r, "HasRecord"), Flag(r, "HasMetadata"));
    }

    public async Task<IReadOnlyList<string>> DocFieldsAsync(CiExportSchema schema, CiExportKeys by, IReadOnlyList<string> keys, CancellationToken ct) =>
        !schema.Ci || keys.Count == 0 ? [] : (await Run(CiFullExportSql.DocFields(schema, by), keys, ct).ConfigureAwait(false)).Select(r => ProDataQueries.S(r, "Name")).Where(n => n.Length > 0).ToList();

    public async Task<IReadOnlyList<CiExportDoc>> DocsAsync(CiExportSchema schema, CiExportKeys by, IReadOnlyList<string> keys, CancellationToken ct) =>
        !schema.Ci || keys.Count == 0 ? [] : (await Run(CiFullExportSql.Docs(schema, by), keys, ct).ConfigureAwait(false))
            .Select(r => new CiExportDoc(ProDataQueries.S(r, "Owner"), ProDataQueries.SN(r, "CiId"), ProDataQueries.SN(r, "Name"), ProDataQueries.SN(r, "DocJson"))).ToList();

    public async Task<IReadOnlyList<CiExportLink>> LinksAsync(CiExportSchema schema, IReadOnlyList<string> keys, CancellationToken ct) =>
        !schema.Ci || !schema.Links || keys.Count == 0 ? [] : (await Run(CiFullExportSql.Links(schema), keys, ct).ConfigureAwait(false))
            .Select(r => new CiExportLink(ProDataQueries.S(r, "Owner"), ProDataQueries.S(r, "Provider"), ProDataQueries.S(r, "RecordType"), ProDataQueries.S(r, "NativeId"),
                Flag(r, "IsPrimary"), ProDataQueries.SN(r, "State"), ProDataQueries.T(r, "LastSeen"), ProDataQueries.SN(r, "Name"))).ToList();

    public async Task<IReadOnlyList<string>> MetadataColumnsAsync(CiExportSchema schema, CiExportKeys by, IReadOnlyList<string> keys, CancellationToken ct) =>
        !schema.Metadata || keys.Count == 0 ? [] : (await Run(CiFullExportSql.MetadataColumns(schema, by), keys, ct).ConfigureAwait(false)).Select(r => ProDataQueries.S(r, "Name")).Where(n => n.Length > 0).ToList();

    public async Task<IReadOnlyList<CiExportObject>> MetadataAsync(CiExportSchema schema, CiExportKeys by, IReadOnlyList<string> keys, CancellationToken ct) =>
        !schema.Metadata || keys.Count == 0 ? [] : (await Run(CiFullExportSql.Metadata(schema, by), keys, ct).ConfigureAwait(false))
            .Select(r => new CiExportObject(ProDataQueries.S(r, "Owner"), ProDataQueries.S(r, "SourceSystem"), ProDataQueries.S(r, "MemberAssetId"), ProDataQueries.S(r, "ItemName"),
                ProDataQueries.T(r, "CollectionTime") ?? default, ProDataQueries.S(r, "PropertiesJson"))).ToList();
}

/// <summary>
/// PURE. A document as cells. A CI document: one cell per top-level field. A source object (full details): flattened
/// ONE level -- a top-level value is one column "source.key"; a top-level object with properties is one column per
/// property "source.key.child"; anything deeper, and every array, is its compact JSON text. Numbers are numbers, true /
/// false booleans, null empty -- Excel then shows them in the reader's own number format.
/// </summary>
public static class CiExportFlatten
{
    public static IReadOnlyDictionary<string, object?> Doc(string? json)
    {
        var cells = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (Root(json) is not { } root) return cells;
        using (root) foreach (var p in root.RootElement.EnumerateObject()) cells.TryAdd(p.Name, Value(p.Value));
        return cells;
    }

    public static IReadOnlyDictionary<string, object?> Metadata(string sourceSystem, string? json)
    {
        var cells = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (Root(json) is not { } root) return cells;
        var src = sourceSystem.ToLowerInvariant();
        using (root)
            foreach (var p in root.RootElement.EnumerateObject())
            {
                if (p.Value.ValueKind == JsonValueKind.Object && p.Value.EnumerateObject().Any())
                    foreach (var c in p.Value.EnumerateObject()) cells.TryAdd(src + "." + p.Name + "." + c.Name, Value(c.Value));
                else cells.TryAdd(src + "." + p.Name, Value(p.Value));
            }
        return cells;
    }

    private static JsonDocument? Root(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            var d = JsonDocument.Parse(json);
            if (d.RootElement.ValueKind == JsonValueKind.Object) return d;
            d.Dispose();
        }
        catch (JsonException) { }
        return null;
    }

    /// A value as a cell: number, boolean, text, empty -- an object or array as compact JSON text.
    public static object? Value(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.String => v.GetString(),
        JsonValueKind.Number => v.TryGetDouble(out var d) ? d : v.GetRawText(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Object or JsonValueKind.Array => JsonSerializer.Serialize(v),
        _ => null,
    };
}
