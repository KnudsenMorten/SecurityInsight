using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SI.Management.Core.ProData;
using SI.Management.Web.Changes;
using SI.Management.Web.Data;

namespace SI.Management.Web.NewContext;

/// <summary>
/// One property a source offers (sidata.SourceProperty, filled by the engine on every run and by the weekly sweep): where
/// it was seen (source, record type, Azure resource type, record part), since when, a sample value, how many records
/// carried it in the newest run, whether SecurityInsight reads it, the SI fields that already read it, and the
/// full-details source it is a column of. Times are UTC.
/// </summary>
public sealed record SourcePropertyRow(string Source, string RecordType, string ResourceType, string Part, string Property, string? SourceSystem,
    string? ValueType, string? SampleValue, int Records, int RecordsOf, bool Collected, bool Baseline, string? MappedFields, string? NeedsPermission,
    DateTime FirstSeen, DateTime LastSeen)
{
    /// What a mapping reads it as: the record part, then the property.
    public string MappingPath => Part + "." + Property;

    /// The SI fields whose mapping already reads the property.
    public IReadOnlyList<string> Mapped =>
        string.IsNullOrWhiteSpace(MappedFields) ? Array.Empty<string>() : MappedFields.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// The data views' column of the property ("Source: ..." in the column chooser); null when it is not a column there
    /// (a part the full asset details do not keep, a path into a list, or deeper than one nested level).
    public string? ColumnKey
    {
        get
        {
            if (string.IsNullOrWhiteSpace(SourceSystem)) return null;
            var key = DataColumnKeys.Source(SourceSystem.Trim().ToLowerInvariant() + "." + Property);
            return DataColumnKeys.IsValid(key) ? key : null;
        }
    }

    /// The row's identity in a form post (the natural key, '|'-joined; none of the parts holds a '|').
    public string Id => string.Join('|', Source, RecordType, ResourceType, Part, Property);
}

/// One source / record type / part as discovery last saw it: how many records, and when it could not be asked, why (and
/// the read permission that would be needed). Origin 'records' = from the objects the runs read; 'schema' = what the
/// source says it offers (the weekly sweep).
public sealed record SourceStateRow(string Source, string RecordType, string ResourceType, string Part, string Origin, int Records, string? Error,
    string? NeedsPermission, DateTime FirstRunAt, DateTime LastRunAt);

/// What a source holds in the discovery tables.
public sealed record SourceCount(string Source, int Known, int NewSinceStart, int NotRead);

/// What the page shows: the tables exist, the properties of the chosen window, every source's state and counts.
public sealed record NewContextView(bool HasTables, IReadOnlyList<SourcePropertyRow> Properties, bool More, IReadOnlyList<SourceStateRow> States, IReadOnlyList<SourceCount> Counts)
{
    public static readonly NewContextView Missing = new(false, Array.Empty<SourcePropertyRow>(), false, Array.Empty<SourceStateRow>(), Array.Empty<SourceCount>());
}

/// <summary>
/// CONTINUOUS DISCOVERY, the web app's part: the page reads PREPARED rows (two small tables the engine fills) -- it never
/// walks a JSON document, and it only reads. What an Admin decides on the page goes through the column layouts (a
/// promoted column) or the change flow (a mapping), never through this store.
/// </summary>
public interface INewContextStore
{
    /// <paramref name="days"/> &gt; 0: first seen within that many days; 0: everything first seen after discovery started;
    /// <paramref name="known"/>: also what was there when discovery started.
    Task<NewContextView> ReadAsync(int days, bool known, CancellationToken ct);
    /// One property by its identity (<see cref="SourcePropertyRow.Id"/>); null when it is not there.
    Task<SourcePropertyRow?> FindAsync(string id, CancellationToken ct);
    /// How many properties each source offers that were first seen at or after <paramref name="sinceUtc"/> (and after
    /// discovery started) -- one grouped read of the prepared rows; empty when there is none or the tables are not there.
    Task<IReadOnlyList<NewContextSource>> NewSinceAsync(DateTime sinceUtc, CancellationToken ct);
}

/// One source and how many of its properties are new in a period.
public sealed record NewContextSource(string Source, int Properties);

public sealed class SqlNewContextStore(ISqlExecutor sql) : INewContextStore
{
    /// How many properties one page lists (the newest first); the page says when there are more.
    public const int PageRows = 1000;

    public const string ProbeSql = """
SELECT CASE WHEN OBJECT_ID(N'sidata.SourceProperty') IS NOT NULL AND OBJECT_ID(N'sidata.SourceDiscoveryState') IS NOT NULL THEN 1 ELSE 0 END AS HasDiscovery
""";

    private const string Columns = """
p.Source, p.RecordType, p.ResourceType, p.Part, p.Property, p.SourceSystem, p.ValueType, p.SampleValue, p.Records,
       ISNULL((SELECT TOP (1) s.Records FROM sidata.SourceDiscoveryState AS s
               WHERE s.Source = p.Source AND s.RecordType = p.RecordType AND s.ResourceType = p.ResourceType AND s.Part = p.Part AND s.Origin = N'records'), 0) AS RecordsOf,
       CAST(p.Collected AS int) AS Collected, CAST(p.Baseline AS int) AS Baseline, p.MappedFields, p.NeedsPermission, p.FirstSeen, p.LastSeen
""";

    /// The properties first seen after discovery started, inside the window, the newest first (IX_SourceProperty_New).
    public const string NewSql = "SELECT TOP (@Top) " + Columns + " " + """
FROM sidata.SourceProperty AS p
WHERE p.Baseline = 0 AND p.FirstSeen >= @Since
ORDER BY p.FirstSeen DESC, p.Source, p.RecordType, p.ResourceType, p.Part, p.Property;
""";

    /// Everything known, the newest first.
    public const string KnownSql = "SELECT TOP (@Top) " + Columns + " " + """
FROM sidata.SourceProperty AS p
ORDER BY p.Baseline, p.FirstSeen DESC, p.Source, p.RecordType, p.ResourceType, p.Part, p.Property;
""";

    public const string FindSql = "SELECT TOP (1) " + Columns + " " + """
FROM sidata.SourceProperty AS p
WHERE p.Source = @Source AND p.RecordType = @RecordType AND p.ResourceType = @ResourceType AND p.Part = @Part AND p.Property = @Property;
""";

    public const string StatesSql = """
SELECT Source, RecordType, ResourceType, Part, Origin, Records, Error, NeedsPermission, FirstRunAt, LastRunAt
FROM sidata.SourceDiscoveryState
ORDER BY Source, RecordType, ResourceType, Part, Origin;
""";

    public const string CountsSql = """
SELECT Source, COUNT(*) AS Known, SUM(CASE WHEN Baseline = 0 THEN 1 ELSE 0 END) AS NewSinceStart, SUM(CASE WHEN Collected = 0 THEN 1 ELSE 0 END) AS NotRead
FROM sidata.SourceProperty
GROUP BY Source
ORDER BY Source;
""";

    /// The properties first seen after discovery started and at or after a time, counted per source (IX_SourceProperty_New).
    public const string NewSinceSql = """
SELECT p.Source, COUNT(*) AS N
FROM sidata.SourceProperty AS p
WHERE p.Baseline = 0 AND p.FirstSeen >= @Since
GROUP BY p.Source
ORDER BY p.Source;
""";

    public static SourcePropertyRow ToProperty(SqlRow r) => new(
        r.Str("Source") ?? "", r.Str("RecordType") ?? "", r.Str("ResourceType") ?? "", r.Str("Part") ?? "", r.Str("Property") ?? "", r.Str("SourceSystem"),
        r.Str("ValueType"), r.Str("SampleValue"), (int)(r.Long("Records") ?? 0), (int)(r.Long("RecordsOf") ?? 0), (r.Long("Collected") ?? 0) == 1,
        (r.Long("Baseline") ?? 0) == 1, r.Str("MappedFields"), r.Str("NeedsPermission"), r.Date("FirstSeen") ?? DateTime.MinValue, r.Date("LastSeen") ?? DateTime.MinValue);

    public static SourceStateRow ToState(SqlRow r) => new(
        r.Str("Source") ?? "", r.Str("RecordType") ?? "", r.Str("ResourceType") ?? "", r.Str("Part") ?? "", r.Str("Origin") ?? "", (int)(r.Long("Records") ?? 0),
        r.Str("Error"), r.Str("NeedsPermission"), r.Date("FirstRunAt") ?? DateTime.MinValue, r.Date("LastRunAt") ?? DateTime.MinValue);

    private async Task<bool> HasTablesAsync(CancellationToken ct) =>
        ((await sql.QueryAsync(ProbeSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Long("HasDiscovery") ?? 0) == 1;

    public async Task<NewContextView> ReadAsync(int days, bool known, CancellationToken ct)
    {
        if (!await HasTablesAsync(ct)) return NewContextView.Missing;
        var p = new Dictionary<string, object?> { ["Top"] = PageRows + 1 };
        if (!known) p["Since"] = days > 0 ? DateTime.UtcNow.AddDays(-Math.Min(days, 3650)) : new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var rows = (await sql.QueryAsync(known ? KnownSql : NewSql, p, ct)).Select(ToProperty).ToList();
        var more = rows.Count > PageRows;
        if (more) rows.RemoveAt(rows.Count - 1);
        var states = (await sql.QueryAsync(StatesSql, new Dictionary<string, object?>(), ct)).Select(ToState).ToList();
        var counts = (await sql.QueryAsync(CountsSql, new Dictionary<string, object?>(), ct))
            .Select(r => new SourceCount(r.Str("Source") ?? "", (int)(r.Long("Known") ?? 0), (int)(r.Long("NewSinceStart") ?? 0), (int)(r.Long("NotRead") ?? 0))).ToList();
        return new NewContextView(true, rows, more, states, counts);
    }

    public async Task<SourcePropertyRow?> FindAsync(string id, CancellationToken ct)
    {
        var parts = (id ?? "").Split('|');
        if (parts.Length != 5 || parts[0].Length == 0 || parts[4].Length == 0) return null;
        if (!await HasTablesAsync(ct)) return null;
        var r = (await sql.QueryAsync(FindSql, new Dictionary<string, object?>
        {
            ["Source"] = parts[0], ["RecordType"] = parts[1], ["ResourceType"] = parts[2], ["Part"] = parts[3], ["Property"] = parts[4],
        }, ct)).FirstOrDefault();
        return r is null ? null : ToProperty(r);
    }

    public async Task<IReadOnlyList<NewContextSource>> NewSinceAsync(DateTime sinceUtc, CancellationToken ct)
    {
        if (!await HasTablesAsync(ct)) return Array.Empty<NewContextSource>();
        return (await sql.QueryAsync(NewSinceSql, new Dictionary<string, object?> { ["Since"] = sinceUtc }, ct))
            .Select(r => new NewContextSource(r.Str("Source") ?? "", (int)(r.Long("N") ?? 0)))
            .Where(s => s.Source.Length > 0 && s.Properties > 0).ToList();
    }
}

/// <summary>The words and the pure rules of the page, shared with its tests.</summary>
public static partial class NewContextText
{
    private static readonly IReadOnlyDictionary<string, string> Labels = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["mde"] = "Microsoft Defender for Endpoint",
        ["entra"] = "Microsoft Entra ID (Microsoft Graph)",
        ["azure"] = "Azure (Resource Graph / Resource Manager)",
        ["eg"] = "Exposure Graph",
        ["intune"] = "Microsoft Intune",
        ["mdc"] = "Microsoft Defender for Cloud",
        ["shodan"] = "Public IP scan (Shodan)",
        ["mdi"] = "Microsoft Defender for Identity",
        ["ad"] = "Active Directory",
        ["cmdb"] = "CMDB",
        ["servicenow"] = "ServiceNow",
    };

    /// A source's name as a person reads it.
    public static string Source(string source) => Labels.TryGetValue(source ?? "", out var l) ? l : source ?? "";

    /// The sources the page always lists, in this order (a source never discovered says so instead of being absent).
    public static readonly IReadOnlyList<string> Sources = ["entra", "azure", "intune", "mdc", "mde", "eg", "shodan", "servicenow"];

    /// "device", "azure resource -- microsoft.compute/virtualmachines", ...
    public static string RecordType(SourcePropertyRow r) =>
        r.RecordType.Replace('_', ' ') + (r.ResourceType.Length > 0 ? " -- " + r.ResourceType : "");

    /// "12 of 340 records", "offered by the source, not read yet", "no record carried a value in the newest run".
    public static string Carried(SourcePropertyRow r, Func<long, string> n)
    {
        if (!r.Collected) return "offered by the source -- SecurityInsight does not read it yet";
        if (r.Records <= 0) return "listed, but no record carried a value in the newest run";
        return r.RecordsOf > 0 ? $"{n(r.Records)} of {n(r.RecordsOf)} records" : $"{n(r.Records)} records";
    }

    /// The views a column can be promoted into: every view whose rows can carry it, or one of the views of CIs.
    public static readonly IReadOnlyList<(string Target, string Label)> Targets =
    [
        ("", "Every view whose rows are CIs"),
        ("cis", "All CIs"),
        ("records", "Records per source"),
        ("collection-assets", "At risk"),
    ];

    public static string TargetLabel(string target) => Targets.FirstOrDefault(t => t.Target == target).Label ?? target;

    [GeneratedRegex(@"^si_[a-z0-9_]{1,80}$", RegexOptions.CultureInvariant)]
    private static partial Regex SiFieldPattern();

    /// Whether a name is an SI field of the shipped field catalog (what a mapping may fill).
    public static bool IsSiField([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] string? field) => field is not null && SiFieldPattern().IsMatch(field) && CiColumns.FieldClasses.ContainsKey(field);

    /// The SI fields a property can be mapped to, by name.
    public static IReadOnlyList<string> SiFields() => CiColumns.FieldClasses.Keys.Where(k => SiFieldPattern().IsMatch(k)).OrderBy(k => k, StringComparer.Ordinal).ToList();

    /// The data-model key of an item, shortened with a hash when it would pass the key limit -- the engine's rule
    /// (Get-SIDataModelProItemKey).
    public static string ItemKey(string template, string item)
    {
        var full = template + ":" + item;
        if (full.Length <= DataModelItemValidator.KeyMax) return full;
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(item))).ToLowerInvariant()[..12];
        var keep = DataModelItemValidator.KeyMax - template.Length - 1 - 13;
        return template + ":" + item[..keep] + "~" + hash;
    }

    private static IReadOnlyList<string> Strings(JsonNode? n)
    {
        var list = new List<string>();
        if (n is JsonArray a) { foreach (var x in a) if (x is JsonValue) list.Add(x.ToString()); }
        else if (n is JsonValue v) list.Add(v.ToString());
        return list;
    }

    /// <summary>
    /// PURE. The mapping change that makes <paramref name="field"/> read the property: when the provider's mapping already
    /// has a row for that field and record type (that applies to the property's Azure resource type), THAT row with the
    /// property's path added last to its sources (everything else of the row kept); else a new row for the field, the
    /// record type and -- for an Azure property -- its resource type. Returns the data-model item key and its body, or the reasons
    /// it cannot be done. Nothing is written here: the caller stages it.
    /// </summary>
    public static (string? Key, string? Body, IReadOnlyList<string> Problems) Mapping(IEnumerable<DataModelRow> rows, SourcePropertyRow p, string? field)
    {
        if (!IsSiField(field)) return (null, null, new[] { $"'{field}' is not an SI field of the field catalog" });
        if (!p.Collected) return (null, null, new[] { "SecurityInsight does not read this property yet -- a mapping would stay empty" });
        var template = "mappings/" + p.Source;
        var path = p.MappingPath;
        foreach (var r in rows.Where(x => x.Template == template && x.Item.Length > 0 && !x.Disabled))
        {
            JsonObject? o;
            try { o = JsonNode.Parse(r.Effective ?? "{}") as JsonObject; }
            catch (JsonException) { continue; }
            if (o is null || !string.Equals(o["field"]?.ToString(), field, StringComparison.Ordinal)) continue;
            if (!Strings(o["recordTypes"]).Contains(p.RecordType, StringComparer.OrdinalIgnoreCase)) continue;
            var res = Strings(o["resourceTypes"]);
            // a row limited to other Azure resource types does not apply to this property's type
            if (res.Count > 0 && !res.Contains(p.ResourceType, StringComparer.OrdinalIgnoreCase)) continue;
            // the path is added LAST: the sources the row already reads keep winning where they have a value
            var sources = Strings(o["sources"]);
            if (sources.Contains(path, StringComparer.Ordinal)) return (null, null, new[] { $"{field} already reads {path}" });
            var list = new JsonArray();
            foreach (var s in sources) list.Add(s);
            list.Add(path);
            o["sources"] = list;
            return (r.ItemKey, o.ToJsonString(), Array.Empty<string>());
        }
        var item = new JsonObject { ["field"] = field, ["recordTypes"] = new JsonArray(p.RecordType) };
        if (p.ResourceType.Length > 0) item["resourceTypes"] = new JsonArray(p.ResourceType);
        item["sources"] = new JsonArray(path);
        var own = field + "|" + p.RecordType + "|" + p.ResourceType;
        return (ItemKey(template, own), item.ToJsonString(), Array.Empty<string>());
    }

    /// The read permissions SecurityInsight's own permission set holds (config\permissions.locked.json) that a refused
    /// read can name -- for these the page shows the filled-in grant command; any other permission is named and NOT
    /// requested (it is not part of the product's permission set).
    public static readonly IReadOnlySet<string> Grantable = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "ThreatHunting.Read.All", "AuditLog.Read.All", "User.Read.All", "Device.Read.All", "Application.Read.All", "Directory.Read.All",
        "DeviceManagementManagedDevices.Read.All", "DeviceManagementConfiguration.Read.All", "AccessReview.Read.All", "SecurityAlert.Read.All", "Machine.Read.All",
        "Vulnerability.Read.All", "SecurityRecommendation.Read.All", "SecurityEvents.Read.All", "Score.Read.All", "Reader",
    };
}
