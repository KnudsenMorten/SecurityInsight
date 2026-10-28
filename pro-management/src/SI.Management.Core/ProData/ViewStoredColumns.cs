using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Core.ProData;

// =====================================================================================================================
// WHAT A VIEW SHOWS BY DEFAULT IS A STORED COLUMN (owner 2026-10-11: "dont foget the caching in sql so performance works
// flawless", "indexing", "again all views must be having the new requirement and performance fast").
//
// A column of a data view's DEFAULT layout is a typed column the data sync fills -- the page reads its 50 rows by key from
// columns. The JSON documents (sidata.Ci.DocJson, sidata.Finding.DetailJson) are read only for a column a person ADDS on
// top of the default, and then only for the rows of the page.
//
// THE LIST of the prepared columns is ONE file, ProData/DataModel/view-stored-columns.json: embedded here, and read from
// this very path by the data sync (engine/pro-data/_shared/SI-DataViewContext.ps1). To add a field: one entry there, and
// its guarded column in sql/si-data-schema.sql (a test names the missing line). Next to it, two fixed sets the CI already
// had as columns: the CI's own columns (<see cref="CiNative"/>) and the CI grid's (<see cref="CiColumns.Promoted"/>).
// =====================================================================================================================

/// How a prepared column holds its value: a text, a list / object as its JSON text, values '; '-joined, a number (INT /
/// FLOAT), a yes / no (BIT) or a date (DATETIME2(3), UTC) -- typed, so a filter or a sort compares values, never text.
public enum StoredKind { Text, Json, List, Number, Flag, Date }

/// Where a CI column comes from -- and so which marker says it is current (see <see cref="ViewStoredColumns.CiCurrentSql"/>).
public enum CiStoredSource { Native, Promoted, Context }

/// One entry of the list's "ci" part: the layout key (ci.f.&lt;field&gt; | ci.i.&lt;identifier type&gt; | ci.links), the
/// sidata.Ci column, its declared type (NVARCHAR(n) | INT | FLOAT | BIT | DATETIME2(3) | JSON | LIST), whether the column is
/// indexed, and whether the CI grid filters it by its VALUES (a short closed vocabulary: environment, MFA strength ...).
public sealed record CiStoredColumn(string Key, string Column, string SqlType, bool Indexed, bool Values = false)
{
    public StoredKind Kind => ViewStoredColumns.KindOf(SqlType);
    /// The CI document field of a ci.f.* entry, else null.
    public string? Field => DataColumnKeys.FieldOf(Key);
    /// The column's SQL type as the schema declares it.
    public string SchemaType => Kind is StoredKind.Json or StoredKind.List ? "NVARCHAR(MAX)" : SqlType;
}

/// One entry of the list's "finding" part: the context key (fc.*), the sidata.Finding column, the sidata.IssueContext
/// column ("" = none), the declared type (NVARCHAR(n) | NVARCHAR(MAX) | INT | FLOAT | DATETIME2(3)) and the names the value
/// is read under in the finding's row.
public sealed record FindingStoredColumn(string Key, string Column, string Issue, string SqlType, IReadOnlyList<string> Fields,
    IReadOnlyList<(string Field, string Words)> Flags)
{
    public StoredKind Kind => ViewStoredColumns.KindOf(SqlType);
    /// The type of the column on the per-issue row: a text holds the distinct values of every finding of the key
    /// (NVARCHAR(MAX)); a number (the highest) and a date (the earliest) keep their type.
    public string IssueType => Kind == StoredKind.Text ? "NVARCHAR(MAX)" : SqlType;
}

/// A layout key resolved to its sidata.Ci column.
public sealed record CiStoredRef(string Key, string Column, CiStoredSource Source, StoredKind Kind);

/// <summary>The list, what a key resolves to, and how a stored value becomes a cell. PURE.</summary>
public static partial class ViewStoredColumns
{
    public const string ResourceName = "view-stored-columns.json";
    /// The second part of the affected software: the product a finding names when it carries no software list.
    public const string ProductKey = "fc.software#product";

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9]{0,60}$", RegexOptions.CultureInvariant)]
    private static partial Regex ColumnPattern();

    [GeneratedRegex(@"^(NVARCHAR\((?:[1-9][0-9]{0,2}|[1-3][0-9]{3}|4000)\)|JSON|LIST|INT|FLOAT|BIT|DATETIME2\(3\))$", RegexOptions.CultureInvariant)]
    private static partial Regex TypePattern();

    [GeneratedRegex(@"^(NVARCHAR\((?:[1-9][0-9]{0,2}|[1-3][0-9]{3}|4000|MAX)\)|INT|FLOAT|DATETIME2\(3\))$", RegexOptions.CultureInvariant)]
    private static partial Regex FindingTypePattern();

    /// How a declared type holds its value.
    public static StoredKind KindOf(string sqlType) => sqlType switch
    {
        "JSON" => StoredKind.Json,
        "LIST" => StoredKind.List,
        "INT" or "FLOAT" => StoredKind.Number,
        "BIT" => StoredKind.Flag,
        "DATETIME2(3)" => StoredKind.Date,
        _ => StoredKind.Text,
    };

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9_]{0,80}$", RegexOptions.CultureInvariant)]
    private static partial Regex FieldPattern();

    private sealed record Loaded(IReadOnlyList<CiStoredColumn> Ci, IReadOnlyList<FindingStoredColumn> Finding, string CiSetId, string FindingSetId);

    private static readonly Lazy<Loaded> Lazy = new(() =>
    {
        using var stream = typeof(ViewStoredColumns).Assembly.GetManifestResourceStream("DataModel/" + ResourceName)
            ?? throw new InvalidOperationException($"the embedded data model file {ResourceName} is missing from the build");
        using var doc = JsonDocument.Parse(stream);
        return Load(doc);
    });

    private static string Str(JsonElement e, string p) => e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    /// The list from its JSON (a name that is not a plain identifier is refused: a column name becomes SQL text).
    private static Loaded Load(JsonDocument doc)
    {
        var ci = new List<CiStoredColumn>();
        if (doc.RootElement.TryGetProperty("ci", out var cis) && cis.ValueKind == JsonValueKind.Array)
            foreach (var e in cis.EnumerateArray())
            {
                var c = new CiStoredColumn(Str(e, "key"), Str(e, "column"), Str(e, "type"), e.TryGetProperty("indexed", out var ix) && ix.ValueKind == JsonValueKind.True,
                    Str(e, "filter") == "values");
                if (!ColumnPattern().IsMatch(c.Column) || !TypePattern().IsMatch(c.SqlType) || !DataColumnKeys.IsValid(c.Key) || !DataColumnKeys.IsCi(c.Key)
                    || Str(e, "filter") is not ("" or "values") || (c.Values && c.Kind != StoredKind.Text))
                    throw new InvalidOperationException($"{ResourceName}: the CI entry '{c.Key}' -> '{c.Column}' ({c.SqlType}) is not well formed");
                ci.Add(c);
            }
        var fi = new List<FindingStoredColumn>();
        if (doc.RootElement.TryGetProperty("finding", out var fis) && fis.ValueKind == JsonValueKind.Array)
            foreach (var e in fis.EnumerateArray())
            {
                var fields = e.TryGetProperty("fields", out var fs) && fs.ValueKind == JsonValueKind.Array
                    ? fs.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? "").ToList() : new List<string>();
                var flags = e.TryGetProperty("flags", out var gs) && gs.ValueKind == JsonValueKind.Array
                    ? gs.EnumerateArray().Select(x => (Field: Str(x, "field"), Words: Str(x, "words"))).ToList() : new List<(string Field, string Words)>();
                var f = new FindingStoredColumn(Str(e, "key"), Str(e, "column"), Str(e, "issue"), Str(e, "type"), fields, flags);
                if (!ColumnPattern().IsMatch(f.Column) || (f.Issue.Length > 0 && !ColumnPattern().IsMatch(f.Issue)) || !FindingTypePattern().IsMatch(f.SqlType)
                    || fields.Any(x => !FieldPattern().IsMatch(x)) || flags.Any(x => !FieldPattern().IsMatch(x.Field)))
                    throw new InvalidOperationException($"{ResourceName}: the finding entry '{f.Key}' -> '{f.Column}' is not well formed");
                fi.Add(f);
            }
        return new Loaded(ci, fi, SetId(ci), FindingSetId(fi));
    }

    /// The identity of a FINDING list: the first 8 bytes (hex) of the SHA-256 of "key|column|issue|type|fields|flags" per
    /// entry (fields ','-joined; flags as field=words, ','-joined), one per line -- what the data sync stamps on every
    /// collection it prepared for this list (sidata.Collection.ContextSet; the same rule in SI-DataViewContext.ps1,
    /// Get-SIViewFindingSetId). A collection prepared for another list is read from its finding rows until the data sync
    /// prepared it again, so a field added to the list is never shown empty where the data has it.
    public static string FindingSetId(IEnumerable<FindingStoredColumn> finding) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", finding.Select(f =>
            f.Key + "|" + f.Column + "|" + f.Issue + "|" + f.SqlType + "|" + string.Join(",", f.Fields) + "|" + string.Join(",", f.Flags.Select(g => g.Field + "=" + g.Words)))))).AsSpan(0, 8));

    /// The identity of a CI list: the first 8 bytes (hex) of the SHA-256 of "key|column|type" per entry, one per line --
    /// what the data sync stamps on every CI it filled for this list (sidata.Ci.CtxSet; the same rule in SI-DataViewContext.ps1).
    public static string SetId(IEnumerable<CiStoredColumn> ci) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", ci.Select(c => c.Key + "|" + c.Column + "|" + c.SqlType)))).AsSpan(0, 8));

    /// The list's CI entries.
    public static IReadOnlyList<CiStoredColumn> Ci => Lazy.Value.Ci;
    /// The list's finding entries.
    public static IReadOnlyList<FindingStoredColumn> Finding => Lazy.Value.Finding;
    /// The identity of the shipped CI list (16 hex characters).
    public static string CiSetId => Lazy.Value.CiSetId;
    /// The identity of the shipped finding list (16 hex characters).
    public static string FindingContextSetId => Lazy.Value.FindingSetId;

    /// The CI's own columns (sidata.Ci carried them from the start; the CI build writes them with the document).
    public static readonly IReadOnlyDictionary<string, string> CiNative = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["si_ci_id"] = "CiId", ["si_asset_name"] = "Name", ["si_class"] = "Class", ["si_asset_type"] = "AssetType", ["si_tier_set_by"] = "TierSetBy",
        ["si_tier_reason"] = "TierReason", ["si_lifecycle"] = "Lifecycle", ["si_cmdb_id"] = "CmdbId", ["si_cmdb_name"] = "CmdbName",
        ["si_cmdb_criticality"] = "CmdbCriticality", ["si_last_seen"] = "LastSeen",
    };

    /// The sidata.Ci column a layout key reads, or null when the key is not prepared (a source property, a field or an
    /// identifier type outside the list: read late, for the rows of the page, when a person adds it).
    public static CiStoredRef? CiRef(string key)
    {
        if (key == DataColumnKeys.CiId) return new CiStoredRef(key, "CiId", CiStoredSource.Native, StoredKind.Text);
        if (Ci.FirstOrDefault(c => c.Key == key) is { } listed) return new CiStoredRef(key, listed.Column, CiStoredSource.Context, listed.Kind);
        if (DataColumnKeys.FieldOf(key) is not { } field) return null;
        if (CiNative.TryGetValue(field, out var native)) return new CiStoredRef(key, native, CiStoredSource.Native, StoredKind.Text);
        if (CiColumns.Promoted.TryGetValue(field, out var promoted)) return new CiStoredRef(key, promoted, CiStoredSource.Promoted, StoredKind.Text);
        return null;
    }

    /// The list's entry of a CI document field (the CI grid reads its own catalog columns through it), or null.
    public static CiStoredColumn? CiField(string field) => Ci.FirstOrDefault(c => c.Field == field);

    /// The entry of a finding context key, or null.
    public static FindingStoredColumn? FindingRef(string key) => Finding.FirstOrDefault(f => f.Key == key);

    /// Whether an extra column key of a layout is prepared: a CI key with a column, a finding context key with one (the
    /// affected assets of an aggregate row are sidata.IssueContext's). Every finding FIELD (fi.*) is read from the row.
    public static bool IsStored(string key)
    {
        if (DataColumnKeys.IsCi(key)) return CiRef(key) is not null;
        if (key == DataColumnKeys.Assets) return true;
        return DataColumnKeys.ContextOf(key) is not null && FindingRef(key) is not null;
    }

    /// The columns a database must have before the web app names them: every CI entry and the two markers ...
    public static IReadOnlyList<string> CiSchemaColumns => Ci.Select(c => c.Column).Concat(new[] { "CtxHash", "CtxSet", "DocFieldsHash" }).ToList();

    /// ... a CASE-able test that sidata.Ci has them all (0 / 1).
    public static string CiSchemaProbe =>
        "CASE WHEN " + string.Join(" AND ", CiSchemaColumns.Select(c => $"COL_LENGTH(N'sidata.Ci', N'{c}') IS NOT NULL")) + " THEN 1 ELSE 0 END";

    /// ... and that sidata.Finding, sidata.Collection and sidata.IssueContext have the finding context (0 / 1).
    public static string FindingSchemaProbe =>
        "CASE WHEN " + string.Join(" AND ", Finding.Select(f => $"COL_LENGTH(N'sidata.Finding', N'{f.Column}') IS NOT NULL")
            .Append("COL_LENGTH(N'sidata.Collection', N'ContextAt') IS NOT NULL").Append("COL_LENGTH(N'sidata.Collection', N'ContextSet') IS NOT NULL")
            .Append("OBJECT_ID(N'sidata.IssueContext') IS NOT NULL")
            .Concat(Finding.Where(f => f.Issue.Length > 0).Select(f => $"COL_LENGTH(N'sidata.IssueContext', N'{f.Issue}') IS NOT NULL"))) + " THEN 1 ELSE 0 END";

    /// A collection (alias k) whose context was prepared for the shipped finding list (@FSet = <see cref="FindingContextSetId"/>).
    public const string CollectionPreparedSql = "k.ContextAt IS NOT NULL AND k.ContextSet = @FSet";

    /// A CI (alias c) whose list columns were filled from its current document, for this list.
    public static string CiContextFilledSql(string setLiteralOrParameter) =>
        $"c.CtxHash = ISNULL(c.ContentHash, 0x00) AND c.CtxSet = {setLiteralOrParameter}";

    /// A CI (alias c) whose every prepared column is current: the CI grid's columns (<see cref="CiColumns.FilledSql"/>) and
    /// the list's (@Set = <see cref="CiSetId"/>).
    public const string CiCurrentSql = "c.DocFieldsHash = ISNULL(c.ContentHash, 0x00) AND c.CtxHash = ISNULL(c.ContentHash, 0x00) AND c.CtxSet = @Set";

    /// The shipped list's identity as a SQL literal (16 hex characters -- nothing else can be in it).
    public static string CiSetLiteral => "N'" + CiSetId + "'";

    // ---- a stored value as the cell the late read would give -----------------------------------------------------------

    /// A value SQL handed back as a cell: text stays text, a number is a number, a time is its UTC text.
    public static object? Cell(object? v) => v switch
    {
        null or DBNull => null,
        string s => s.Length == 0 ? null : s,
        bool b => b,
        DateTime d => DateTime.SpecifyKind(d, DateTimeKind.Utc).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
        DateTimeOffset o => o.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
        byte or short or int or long or float or double or decimal => Convert.ToDouble(v, CultureInfo.InvariantCulture),
        _ => Convert.ToString(v, CultureInfo.InvariantCulture),
    };

    /// A stored CI value as a cell: a JSON column as the compact JSON text the document read gives (a scalar kept there as
    /// its text), everything else by <see cref="Cell"/>.
    public static object? CiCell(StoredKind kind, object? v)
    {
        if (kind != StoredKind.Json || v is not string s || s.Length == 0) return Cell(v);
        var t = s.TrimStart();
        if (t.Length == 0 || (t[0] != '[' && t[0] != '{')) return s;
        try
        {
            using var doc = JsonDocument.Parse(s);
            return JsonSerializer.Serialize(doc.RootElement);
        }
        catch (JsonException) { return s; }
    }

    /// The values of a '; '-joined column.
    public static IEnumerable<string> ListItems(object? v) =>
        v is string s && s.Length > 0 ? s.Split(DataColumnKeys.Separator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) : Array.Empty<string>();

    /// A text that is a plain number as that number (the impact of a CVE row is its score), anything else as it is.
    public static object? NumberOrText(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        return text.Length <= 24 && (char.IsAsciiDigit(text[0]) || text[0] == '-') && double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && double.IsFinite(d) ? d : text;
    }
}
