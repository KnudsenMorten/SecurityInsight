using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Core.ProData;

// =====================================================================================================================
// THE COLUMNS OF THE CI GRID (V3-DATA-MODEL 2.13): the fields the grid can show, read from the field catalog
// (data-model/field-catalog.locked.json -- every field valid on a CI: level "ci" or "both") and the default set from the
// CI output map (data-model/outputs/excel-ci.locked.json -- the CI sheet and the CIs grid share it). Both files are
// embedded copies (ProData/DataModel/*): the web app's image is built from pro-management alone, and a test holds the
// copies byte for byte to the originals, so a catalog change fails the build until the copy follows.
// A column that sidata.Ci carries as a column of its own reads that column; every other field is read from the CI
// document (DocJson) by its field name. Field names come from the catalog, never from a request: a request names
// a column KEY, which is looked up here.
// =====================================================================================================================

/// One column the CI grid can show. <see cref="Field"/> is the catalog field name (si_os_name); <see cref="Key"/> the
/// grid key (URL name, SQL alias, cfg.ColumnLayout entry); <see cref="Sql"/> the expression over sidata.Ci AS c and the
/// checked document d.J. <see cref="Promoted"/>: the sidata.Ci column the data sync fills from the document for this field
/// (<see cref="CiColumns.Promoted"/>) -- read instead of the document once the database has it (<see cref="CiFieldMode"/>).
/// <see cref="Ctx"/>: the promoted column is one of the view columns' list (<see cref="ViewStoredColumns.Ci"/>) -- filled by the
/// same data sync but with its own marker (CtxHash / CtxSet), so it has its own <see cref="CiFieldMode"/>.
public sealed record CiColumn(string Field, string Key, string Label, string Group, GridType Type, GridFilter Filter, bool Search,
    string Sql, string Description, bool Stored, bool Dynamic, bool DefaultVisible, string? Promoted = null, bool Ctx = false)
{
    public GridColumn ToGrid(bool hidden, string? lateSql = null) => new(Key, Label, Type, Filter, Search, Sortable: !Dynamic, Hidden: hidden, LateSql: lateSql);
}

/// <summary>
/// How the CI grid reads the fields of <see cref="CiColumns.Promoted"/> (owner 2026-10-11: "why is the performance so bad"):
///   Document -- the database has no such columns yet (the schema update has not run): from the CI document, as before;
///   Fallback -- the columns exist, but some CIs' columns are not filled from their current document yet (the data sync
///               fills them after every CI build): the column where it is current, else the document, row by row;
///   Columns  -- every CI's columns are current: the columns alone, no document read.
/// </summary>
public enum CiFieldMode { Document, Fallback, Columns }

/// <summary>The catalog of CI columns and the default layout.</summary>
public static partial class CiColumns
{
    /// The key column (always in the grid, shown or not).
    public const string KeyColumn = "CiId";
    public const string DefaultSort = "WeightedRiskScore";
    /// Asset subtype (one generic classification mapping, with asset type): a column and a filter of the CI views. Read
    /// from the CI document; ensured even before the field catalog lists the field, so the grid shows it from day one.
    public const string AssetSubtypeField = "si_asset_subtype";
    public const string AssetSubtypeKey = "AssetSubtype";

    /// The columns every grid statement carries (shown or not): the key, what the filters above the grid read, and what
    /// the sort choice offers.
    public static readonly IReadOnlyList<string> Always = [KeyColumn, "Name", "Class", "AssetType", AssetSubtypeKey, "Tier", TierSetByKey, "Lifecycle", "WeightedRiskScore", "LastSeen"];

    /// #856 the IP address field: the IpAddress column holds a device's best address too, not only a public IP CI's.
    public const string IpAddressField = "si_ip_address";

    /// <summary>
    /// #856 the fallback of a nameless CI (<see cref="CiDisplayName"/>): a hidden column every CI grid statement carries, read
    /// for the page's rows only (late) -- never a column a person chooses, filters or sorts on, never exported as the name.
    /// <paramref name="mode"/>: how the promoted columns are read (Columns: the columns alone, never the CI document).
    /// </summary>
    public static CiColumn NameFallbackColumn(CiFieldMode mode) =>
        new("si_name_fallback", CiDisplayName.FallbackKey, "Name (fallback)", "identity", GridType.Text, GridFilter.None, false,
            CiDisplayName.FallbackSql(mode), "A nameless CI's best identifier: IP address, else MAC address, else the source's id.", Stored: false, Dynamic: true, DefaultVisible: false);

    /// #579 who decided the tier (rule / tag / override / default): a filter above the grid, so carried by every statement.
    public const string TierSetByKey = "TierSetBy";
    /// #579 the tier in one plain sentence -- shown whole in the grid (never cut at the cell limit).
    public const string TierExplanationField = "si_tier_explanation";
    public const string TierExplanationKey = "TierExplanation";

    /// The words for who decided the tier (si_tier_set_by), as the filter and the CI page say them.
    public static string TierSetByText(string? setBy) => setBy switch
    {
        "rule" => "an SI rule",
        "tag" => "your tag",
        "override" => "a manual override",
        "default" => "the default",
        "cmdb" => "the CMDB",
        null or "" => "not recorded",
        _ => setBy,
    };

    /// The values the "decided by" filter always offers (more come from the data).
    public static readonly IReadOnlyList<string> TierSetByValues = ["rule", "tag", "override", "default"];

    /// Text fields read whole from the CI document (a sentence longer than the 400-character cell read).
    private static readonly HashSet<string> LongTextFields = new(StringComparer.Ordinal) { TierExplanationField, "si_credential_fix" };

    /// The sorts offered above the grid (key -> words); a column header sorts on any shown column too.
    public static readonly IReadOnlyList<(string Key, string Label)> Sorts =
        [("WeightedRiskScore", "Weighted asset risk score"), ("Tier", "Tier"), ("Name", "Name"), ("LastSeen", "Last seen")];

    /// <summary>
    /// The CI document fields sidata.Ci also carries as columns (owner 2026-10-11, the CIs page took ~10 s: every value the
    /// default layout shows, filters or sorts was read out of DocJson per row): field -> column. The data sync fills them
    /// (engine/pro-data/_shared/SI-DataCi.ps1, $SIDataCiDocFields -- a test holds the two lists equal); a bool field is a
    /// BIT, every other one NVARCHAR(400) (sql/si-data-schema.sql).
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> Promoted = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        [AssetSubtypeField] = "AssetSubtype", ["si_os_name"] = "OsName", ["si_os_platform"] = "OsPlatform", ["si_os_version"] = "OsVersion",
        ["si_onboarding_status"] = "OnboardingStatus", ["si_owner"] = "Owner", ["si_department"] = "Department", ["si_hostname"] = "Hostname",
        ["si_ip_address"] = "IpAddress", ["si_azure_resource_type"] = "AzureResourceType", ["si_identity_type"] = "IdentityType", ["si_purpose"] = "Purpose",
        ["si_account_enabled"] = "AccountEnabled", ["si_mfa_registered"] = "MfaRegistered",
        // #579 the tier sentence (NVARCHAR(4000), not in IX_Ci_Page: long text, read for the shown rows only)
        ["si_tier_explanation"] = "TierExplanation",
    };

    /// A CI whose promoted columns were filled from its current document (DocFieldsHash = its content hash; 0x00 for a CI
    /// written before content hashes existed).
    public const string FilledSql = "c.DocFieldsHash = ISNULL(c.ContentHash, 0x00)";

    /// The CI document of the row when it is valid JSON (d.J) -- what every document expression reads.
    public const string DocApply = "CROSS APPLY (SELECT CASE WHEN ISJSON(c.DocJson) = 1 THEN c.DocJson END AS J) AS d";

    [GeneratedRegex("^[a-z][a-z0-9_]{0,80}$", RegexOptions.CultureInvariant)]
    private static partial Regex FieldPattern();

    /// The fields sidata.Ci holds as columns of its own: field -> (key, expression, type, filter, search).
    private static readonly Dictionary<string, (string Key, string Sql, GridType Type, GridFilter Filter, bool Search)> StoredFields = new(StringComparer.Ordinal)
    {
        ["si_ci_id"] = ("CiId", "c.CiId", GridType.Text, GridFilter.Contains, true),
        ["si_asset_name"] = ("Name", "c.Name", GridType.Text, GridFilter.Contains, true),
        ["si_class"] = ("Class", "c.Class", GridType.Text, GridFilter.Values, false),
        ["si_asset_type"] = ("AssetType", "c.AssetType", GridType.Text, GridFilter.Values, false),
        // the grid's tier: "0".."3" or "Unclassified" -- the one tier vocabulary of every page
        ["si_tier"] = ("Tier", "CASE WHEN c.Tier BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), c.Tier) ELSE N'Unclassified' END", GridType.Tier, GridFilter.Values, false),
        ["si_tier_set_by"] = ("TierSetBy", "c.TierSetBy", GridType.Text, GridFilter.Values, false),
        ["si_tier_reason"] = ("TierReason", "c.TierReason", GridType.Text, GridFilter.Contains, false),
        ["si_ci_risk_score"] = ("RiskScore", "c.RiskScore", GridType.Number, GridFilter.Range, false),
        ["si_ci_weighted_risk_score"] = ("WeightedRiskScore", "c.WeightedRiskScore", GridType.Number, GridFilter.Range, false),
        ["si_open_findings"] = ("OpenFindings", "c.OpenFindings", GridType.Number, GridFilter.Range, false),
        ["si_risk_factors"] = ("RiskFactors", "c.RiskFactors", GridType.Text, GridFilter.Tokens, false),
        ["si_internet_exposed"] = ("InternetExposed", "CONVERT(int, c.InternetExposed)", GridType.Flag, GridFilter.Values, false),
        ["si_cmdb_id"] = ("CmdbId", "c.CmdbId", GridType.Text, GridFilter.Contains, true),
        ["si_cmdb_name"] = ("CmdbName", "c.CmdbName", GridType.Text, GridFilter.Contains, true),
        ["si_cmdb_criticality"] = ("CmdbCriticality", "c.CmdbCriticality", GridType.Text, GridFilter.Values, false),
        ["si_criticality_factor"] = ("CriticalityFactor", "c.CriticalityFactor", GridType.Number, GridFilter.Range, false),
        ["si_lifecycle"] = ("Lifecycle", "c.Lifecycle", GridType.Text, GridFilter.Values, false),
        ["si_last_seen"] = ("LastSeen", "c.LastSeen", GridType.Date, GridFilter.Dates, false),
        ["si_link_count"] = ("LinkCount", "c.LinkCount", GridType.Number, GridFilter.Range, false),
    };

    /// Words a label keeps in capitals (an abbreviation reads as one).
    private static readonly Dictionary<string, string> Words = new(StringComparer.Ordinal)
    {
        ["os"] = "OS", ["ip"] = "IP", ["ips"] = "IPs", ["cmdb"] = "CMDB", ["mde"] = "MDE", ["mdi"] = "MDI", ["eg"] = "Exposure Graph", ["ad"] = "AD",
        ["av"] = "AV", ["edr"] = "EDR", ["tpm"] = "TPM", ["smb1"] = "SMB1", ["rdp"] = "RDP", ["nla"] = "NLA", ["tls"] = "TLS", ["https"] = "HTTPS",
        ["waf"] = "WAF", ["nsg"] = "NSG", ["ssh"] = "SSH", ["ddos"] = "DDoS", ["mfa"] = "MFA", ["upn"] = "UPN", ["sp"] = "service principal",
        ["ms"] = "Microsoft", ["fqdn"] = "FQDN", ["mac"] = "MAC", ["asn"] = "ASN", ["isp"] = "ISP", ["cvss"] = "CVSS", ["ci"] = "CI", ["id"] = "id",
        ["sam"] = "SAM", ["entra"] = "Entra", ["azure"] = "Azure", ["intune"] = "Intune", ["shodan"] = "Shodan", ["servicenow"] = "ServiceNow",
        ["onprem"] = "on-premises",
    };

    /// "si_os_name" -> "OS name"; "si_link_mde" -> "Link MDE".
    public static string LabelOf(string field)
    {
        var parts = (field.StartsWith("si_", StringComparison.Ordinal) ? field[3..] : field).Split('_', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => Words.TryGetValue(p, out var w) ? w : p).ToList();
        if (parts.Count == 0) return field;
        var s = string.Join(" ", parts);
        return char.ToUpperInvariant(s[0]) + s[1..];
    }

    /// "si_os_name" -> "OsName" (a grid key: letters and digits only).
    public static string KeyOf(string field)
    {
        var name = field.StartsWith("si_", StringComparison.Ordinal) ? field[3..] : field;
        return string.Concat(name.Split('_', StringSplitOptions.RemoveEmptyEntries).Select(p => char.ToUpperInvariant(p[0]) + p[1..]));
    }

    /// The expression that reads one catalog field from the CI document (d.J: the DocJson when it is valid JSON).
    public static string DocSql(string field, string type)
    {
        if (!FieldPattern().IsMatch(field)) throw new ArgumentException($"'{field}' is not a field name");
        // #856 a device's IP address: the public IP of a public IP CI, else the best of the device's own addresses -- the
        // same value the data sync fills the IpAddress column with (a discovered device had the column empty)
        if (field == IpAddressField) return CiDisplayName.IpFromDocumentSql();
        var path = "N'$." + field + "'";
        return type switch
        {
            "int" or "real" => $"TRY_CONVERT(float, JSON_VALUE(d.J, {path}))",
            "bool" => $"CASE JSON_VALUE(d.J, {path}) WHEN N'true' THEN 1 WHEN N'false' THEN 0 END",
            "datetime" => $"TRY_CONVERT(datetime2(3), LEFT(JSON_VALUE(d.J, {path}), 23), 127)",
            "dynamic" => $"COALESCE(JSON_QUERY(d.J, {path}), JSON_VALUE(d.J, {path}))",
            _ when LongTextFields.Contains(field) => $"CONVERT(nvarchar(4000), JSON_VALUE(d.J, {path}))",
            _ => $"CONVERT(nvarchar(400), JSON_VALUE(d.J, {path}))",
        };
    }

    /// How a catalog type is held by a column of the view columns' list (<see cref="ViewStoredColumns.Ci"/>).
    public static StoredKind StoredKindOf(string catalogType) => catalogType switch
    {
        "dynamic" => StoredKind.Json,
        "int" or "real" => StoredKind.Number,
        "bool" => StoredKind.Flag,
        "datetime" => StoredKind.Date,
        _ => StoredKind.Text,
    };

    private static Stream Resource(string name) =>
        typeof(CiColumns).Assembly.GetManifestResourceStream("DataModel/" + name)
        ?? throw new InvalidOperationException($"the embedded data model file {name} is missing from the build");

    private static readonly Lazy<CiColumnCatalog> Lazy = new(() =>
    {
        using var cat = Resource("field-catalog.locked.json");
        using var map = Resource("excel-ci.locked.json");
        return Load(JsonDocument.Parse(cat), JsonDocument.Parse(map));
    });

    /// The shipped catalog (embedded copies of the data-model files).
    public static CiColumnCatalog Default => Lazy.Value;

    private static readonly Lazy<IReadOnlyDictionary<string, string[]>> LazyClasses = new(() =>
    {
        using var cat = Resource("field-catalog.locked.json");
        using var doc = JsonDocument.Parse(cat);
        var d = new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (doc.RootElement.TryGetProperty("fields", out var fields) && fields.ValueKind == JsonValueKind.Array)
            foreach (var e in fields.EnumerateArray())
            {
                var name = Str(e, "name");
                if (name is null) continue;
                // a field of ONE class carries it as a string ("classes": "identity"), of several as an array -- both are read
                d[name] = !e.TryGetProperty("classes", out var c) ? Array.Empty<string>()
                    : c.ValueKind == JsonValueKind.Array
                        ? c.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToArray()
                        : c.ValueKind == JsonValueKind.String && c.GetString() is { Length: > 0 } one ? new[] { one } : Array.Empty<string>();
            }
        return d;
    });

    /// #541: every catalog field's classes (device / identity / cloud_resource / public_ip) -- what the Risk factors page's
    /// report x factor matrix needs to derive a report's factors exactly as the engine does (RA-ScopePreamble.ps1).
    public static IReadOnlyDictionary<string, string[]> FieldClasses => LazyClasses.Value;

    /// <summary>
    /// THE ORDER of the CI views' default filters (owner 2026-10-19: "Class, Device type, OS family, Patch cycle, Tier,
    /// Lifecycle, Domain > Category > Subcategory, Risk rating, Severity, Component, Environment, Department"): the CI
    /// fields of that list in that order -- the asset type is the device type; the finding's domain, category, rating and
    /// severity are the finding views' (<see cref="FindingFilterColumns"/>). A field the data model does not have yet (OS
    /// family, patch cycle) is offered by itself once it is a prepared column with a value list
    /// (<see cref="CiColumnCatalog.ValueFilters"/>); every other filter follows in its own order.
    /// </summary>
    public static readonly IReadOnlyList<string> DefaultFilterOrder =
        ["si_class", "si_asset_type", "si_asset_subtype", "si_os_family", "si_patch_cycle", "si_tier", "si_tier_set_by", "si_lifecycle", OnboardingField, "si_components", "si_component", "si_environment", "si_department"];

    /// Where a field's filter stands among the filters above the CI grid (<see cref="DefaultFilterOrder"/>; the rest after).
    public static int FilterRank(string field) { var i = DefaultFilterOrder.ToList().IndexOf(field); return i < 0 ? DefaultFilterOrder.Count : i; }

    /// CI fields held as a column of the CI grid's own (<see cref="Promoted"/>) that filter by their values: the department
    /// (owner 2026-10-19), read from IX_Ci_Page, which covers it; #855 item 3 (owner 2026-10-21: "another filter can easily be
    /// unonboarded, makes sense"): the Defender onboarding status, next to the lifecycle -- devices Defender only DISCOVERED on
    /// the network (can be onboarded / unsupported / insufficient info) shown or hidden.
    public static readonly IReadOnlySet<string> PromotedValueFields = new HashSet<string>(StringComparer.Ordinal) { "si_department", OnboardingField };

    /// #855 item 3: the onboarding status field, its address parameter (the CI list's /Cis/Index?onboarding=can_be_onboarded,
    /// the executive coverage figure's link) and its stored values in the order the filter offers them.
    public const string OnboardingField = "si_onboarding_status";
    public const string OnboardingParam = "onboarding";
    public static readonly IReadOnlyList<string> OnboardingStatuses = ["onboarded", "can_be_onboarded", "unsupported", "insufficient_info", "offboarded"];

    /// "can_be_onboarded" -> "Can be onboarded" (an unknown value as it is, underscores as spaces).
    public static string OnboardingLabel(string? value) => (value ?? "").Trim().ToLowerInvariant() switch
    {
        "onboarded" => "Onboarded",
        "can_be_onboarded" => "Can be onboarded",
        "unsupported" => "Unsupported",
        "insufficient_info" => "Insufficient info",
        "offboarded" => "Offboarded",
        "unknown" or "" => "Unknown (no status)",
        var v => v.Replace('_', ' '),
    };

    /// The column catalog from a field catalog and the CI output map (both as parsed JSON). <paramref name="stored"/>: the
    /// prepared CI columns' list (default: view-stored-columns.json; a test passes its own).
    public static CiColumnCatalog Load(JsonDocument catalog, JsonDocument outputMap, Func<string, CiStoredColumn?>? stored = null)
    {
        stored ??= ViewStoredColumns.CiField;
        var labels = new Dictionary<string, string>(StringComparer.Ordinal);
        var defaults = new List<string>();
        if (outputMap.RootElement.TryGetProperty("columns", out var cols) && cols.ValueKind == JsonValueKind.Array)
            foreach (var c in cols.EnumerateArray())
            {
                var from = c.TryGetProperty("from", out var f) && f.ValueKind == JsonValueKind.String ? f.GetString() : null;
                var target = c.TryGetProperty("target", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null;
                if (string.IsNullOrEmpty(from) || from.StartsWith('$')) continue;
                if (!string.IsNullOrEmpty(target)) labels.TryAdd(from, target);
                defaults.Add(from);
            }
        var columns = new List<CiColumn>();
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (catalog.RootElement.TryGetProperty("fields", out var fields) && fields.ValueKind == JsonValueKind.Array)
            foreach (var e in fields.EnumerateArray())
            {
                var name = Str(e, "name");
                var level = Str(e, "level");
                if (name is null || level is not ("ci" or "both") || !FieldPattern().IsMatch(name)) continue;
                var type = Str(e, "type") ?? "string";
                var group = Str(e, "group") ?? "other";
                var desc = Str(e, "description") ?? "";
                var visible = e.TryGetProperty("defaultVisible", out var dv) && dv.ValueKind == JsonValueKind.True;
                var label = labels.TryGetValue(name, out var l) ? l : LabelOf(name);
                CiColumn col;
                if (StoredFields.TryGetValue(name, out var s))
                    col = new CiColumn(name, s.Key, label, group, s.Type, s.Filter, s.Search, s.Sql, desc, true, false, visible);
                else
                {
                    var key = KeyOf(name);
                    if (keys.Contains(key)) key = "F" + key;
                    if (!GridSql.IsKey(key)) continue;
                    var (gt, gf) = type switch
                    {
                        "int" or "real" => (GridType.Number, GridFilter.Range),
                        "bool" => (GridType.Flag, GridFilter.Values),
                        "datetime" => (GridType.Date, GridFilter.None),
                        "dynamic" => (GridType.Text, GridFilter.None),
                        _ => (GridType.Text, GridFilter.Contains),
                    };
                    // a column of its own: the CI grid's (Promoted), else the view columns' list -- a list field as its JSON
                    // text, a text as text, a number, a yes / no and a date TYPED (an entry of another kind than the
                    // catalog's type is not this field's column). A listed text column with a short closed vocabulary
                    // (environment, MFA strength, risk level ...) filters by its values, like the asset type.
                    string? promoted = null;
                    var ctx = false;
                    if (type != "dynamic" && Promoted.TryGetValue(name, out var pc)) promoted = pc;
                    else if (stored(name) is { } listed && listed.Kind == StoredKindOf(type))
                    {
                        promoted = listed.Column; ctx = true;
                        if (listed.Values) gf = GridFilter.Values;
                    }
                    // a date held as a typed column filters by a range of days (owner 2026-10-19: "+ Add filter: date ranges")
                    if (gt == GridType.Date && promoted is not null) gf = GridFilter.Dates;
                    if (!ctx && promoted is not null && PromotedValueFields.Contains(name)) gf = GridFilter.Values;
                    col = new CiColumn(name, key, label, group, gt, gf, false, DocSql(name, type), desc, false, type == "dynamic", visible, promoted, ctx);
                }
                // asset subtype filters by its values (a short closed list), like asset type
                if (name == AssetSubtypeField) col = col with { Key = AssetSubtypeKey, Filter = GridFilter.Values, DefaultVisible = true };
                if (!keys.Add(col.Key)) continue;
                columns.Add(col);
            }
        // asset subtype sits next to asset type: ensured when the catalog has asset type but not (yet) the subtype
        var typeAt = columns.FindIndex(c => c.Field == "si_asset_type");
        if (typeAt >= 0 && !columns.Any(c => c.Field == AssetSubtypeField) && keys.Add(AssetSubtypeKey))
            columns.Insert(typeAt + 1, new CiColumn(AssetSubtypeField, AssetSubtypeKey, LabelOf(AssetSubtypeField), columns[typeAt].Group, GridType.Text, GridFilter.Values, false,
                DocSql(AssetSubtypeField, "string"), "The asset's subtype (e.g. SQL Database, SQL Server, Domain controller), from the classification mapping.", false, false, true,
                Promoted[AssetSubtypeField]));
        // the default layout: the CI output map's columns in its order, then every other field the catalog shows by default
        var byField = columns.ToDictionary(c => c.Field, StringComparer.Ordinal);
        var layout = defaults.Where(byField.ContainsKey).Select(f => byField[f].Key)
            .Concat(columns.Where(c => c.DefaultVisible).Select(c => c.Key)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        // ... with asset subtype right after asset type
        if (byField.ContainsKey(AssetSubtypeField) && layout.Contains("AssetType"))
        {
            layout.RemoveAll(k => k == AssetSubtypeKey);
            layout.Insert(layout.IndexOf("AssetType") + 1, AssetSubtypeKey);
        }
        return new CiColumnCatalog(columns, layout, stored);
    }

    private static string? Str(JsonElement e, string p) => e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// The columns the CI grid can show (catalog order) and the shipped default layout (column keys, in order).
public sealed class CiColumnCatalog(IReadOnlyList<CiColumn> columns, IReadOnlyList<string> defaultLayout, Func<string, CiStoredColumn?>? stored = null)
{
    private readonly Func<string, CiStoredColumn?> _stored = stored ?? ViewStoredColumns.CiField;
    public IReadOnlyList<CiColumn> Columns { get; } = columns;
    public IReadOnlyList<string> DefaultLayout { get; } = defaultLayout;
    private readonly Dictionary<string, CiColumn> _byKey = columns.ToDictionary(c => c.Key, StringComparer.OrdinalIgnoreCase);

    public CiColumn? Find(string? key) => key is not null && _byKey.TryGetValue(key, out var c) ? c : null;

    /// The column of a catalog field, or null.
    public CiColumn? OfField(string field) => Columns.FirstOrDefault(c => c.Field == field);

    /// <summary>
    /// The context columns the CI views offer a filter for above the grid: a listed column with a short closed vocabulary
    /// (<see cref="CiStoredColumn.Values"/>: environment, MFA strength, risk level, device value, Defender plan tier ...)
    /// that is INDEXED -- its value list is read from its index (IX_Ci_&lt;column&gt;), never from the CI rows.
    /// </summary>
    /// Owner 2026-10-19: also a column of the CI grid's own with a value list (<see cref="CiColumns.PromotedValueFields"/>:
    /// the department), and in the order of <see cref="CiColumns.DefaultFilterOrder"/>.
    public IReadOnlyList<CiColumn> ValueFilters => _valueFilters ??= Columns
        .Where(c => c.Promoted is not null && c.Filter == GridFilter.Values
                    && (c.Ctx ? _stored(c.Field) is { Indexed: true, Values: true } : CiColumns.PromotedValueFields.Contains(c.Field)))
        .OrderBy(c => CiColumns.FilterRank(c.Field)).ToList();
    private IReadOnlyList<CiColumn>? _valueFilters;

    /// The catalog groups in the order they first appear, each with its columns.
    public IEnumerable<IGrouping<string, CiColumn>> Groups() => Columns.GroupBy(c => c.Group);

    /// <summary>
    /// The grid spec for a layout: the chosen columns in the chosen order, shown; the columns every statement needs
    /// (<see cref="CiColumns.Always"/>) carried hidden when not chosen. Read-only SELECT over sidata.Ci.
    /// <paramref name="mode"/>: how the promoted fields are read (<see cref="CiFieldMode"/>). A column read from the CI
    /// document is LATE (<see cref="GridLate"/>): computed only for the rows of the page, unless the request filters, sorts
    /// or searches on it -- a page never reads every CI's document (owner 2026-10-11; internal, 8,799 CIs: ~27 s -> ~0.3 s).
    /// </summary>
    /// <paramref name="ctxMode"/>: the same for the columns of the view columns' list (<see cref="CiColumn.Ctx"/>: subscription,
    /// resource group, management group, the list fields ...) -- they have their own marker, so their own mode.
    /// <paramref name="carry"/>: columns the statement carries hidden although the layout does not show them -- the ones this
    /// request FILTERS on (a filter above the grid works whatever columns a person chose).
    public GridSpec Spec(IReadOnlyList<string> layout, CiFieldMode mode = CiFieldMode.Document, CiFieldMode ctxMode = CiFieldMode.Document,
        IReadOnlyCollection<string>? carry = null)
    {
        var chosen = layout.Select(Find).Where(c => c is not null).Select(c => c!).DistinctBy(c => c.Key, StringComparer.OrdinalIgnoreCase).ToList();
        var hidden = CiColumns.Always.Concat(carry ?? Array.Empty<string>()).Distinct(StringComparer.OrdinalIgnoreCase);
        var all = chosen.Select(c => (Col: c, Hidden: false))
            .Concat(hidden.Select(Find).Where(c => c is not null && !chosen.Any(x => x.Key.Equals(c.Key, StringComparison.OrdinalIgnoreCase))).Select(c => (Col: c!, Hidden: true)))
            .Select(x => (x.Col, x.Hidden, Sql: SqlOf(x.Col, x.Col.Ctx ? ctxMode : mode), Late: IsLate(x.Col, x.Col.Ctx ? ctxMode : mode)))
            .ToList();
        // #856 a nameless CI's fallback, carried hidden by every statement and read for the page's rows only
        var fallback = CiColumns.NameFallbackColumn(mode);
        if (!all.Any(x => x.Col.Key.Equals(fallback.Key, StringComparison.OrdinalIgnoreCase))) all.Add((fallback, true, fallback.Sql, true));
        var select = string.Join(",\n       ", all.Select(x => x.Sql + " AS [" + x.Col.Key + "]"));
        var source = $"""
SELECT {select}
FROM sidata.Ci AS c
{CiColumns.DocApply}
""";
        // the narrow source: every column read without the document, and the late ones this request filters, sorts or searches on
        string Narrow(IReadOnlyCollection<string> needed)
        {
            var cols = all.Where(x => !x.Late || needed.Contains(x.Col.Key)).Select(x => x.Sql + " AS [" + x.Col.Key + "]");
            var text = "SELECT " + string.Join(",\n       ", cols) + "\nFROM sidata.Ci AS c";
            return all.Any(x => x.Late && needed.Contains(x.Col.Key)) ? text + "\n" + CiColumns.DocApply : text;
        }
        // the late join names the document only when a late column still reads it (none does once every column is filled)
        var lateDoc = all.Any(x => x.Late && x.Sql.Contains("d.J", StringComparison.Ordinal));
        var late = new GridLate(Narrow, "JOIN sidata.Ci AS c ON c.CiId = g.[" + CiColumns.KeyColumn + "]" + (lateDoc ? "\n" + CiColumns.DocApply : ""));
        return GridSql.Check(new GridSpec("cis", "", source, all.Select(x => x.Col.ToGrid(x.Hidden, x.Late ? x.Sql : null)).ToList(),
            CiColumns.DefaultSort, true, CiColumns.KeyColumn, Array.Empty<string>(), Immutable: false, Late: late));
    }

    /// The expression a column reads in <paramref name="mode"/>.
    public static string SqlOf(CiColumn c, CiFieldMode mode)
    {
        if (c.Promoted is null || mode == CiFieldMode.Document) return c.Sql;
        var col = c.Type == GridType.Flag ? $"CONVERT(int, c.[{c.Promoted}])" : $"c.[{c.Promoted}]";
        // a column of the view columns' list is current by its own marker (the list it was filled for is a fixed literal)
        var filled = c.Ctx ? ViewStoredColumns.CiContextFilledSql(ViewStoredColumns.CiSetLiteral) : CiColumns.FilledSql;
        return mode == CiFieldMode.Columns ? col : $"CASE WHEN {filled} THEN {col} ELSE {c.Sql} END";
    }

    /// Whether a column reads the CI document in <paramref name="mode"/> -- and so is computed for the page's rows only.
    /// A column of the view columns' list stays late also when it is read from its column: it is not in the page's covering
    /// index (IX_Ci_Page), so the page is chosen without it and its value is read for the page's rows by their key.
    public static bool IsLate(CiColumn c, CiFieldMode mode) => !c.Stored && (c.Promoted is null || mode != CiFieldMode.Columns || c.Ctx);
}

/// <summary>
/// Which columns a person sees on a grid (V3-DATA-MODEL 2.13, cfg.ColumnLayout): their own choice, else the tenant
/// default an Admin set, else the shipped default. A stored layout is a JSON array of column keys; a key the catalog no
/// longer knows is dropped (a renamed or removed field never breaks the grid), and a layout left with no column counts
/// as not set.
/// </summary>
public static class ColumnLayout
{
    public const int MaxColumns = 1000;
    public const string FromUser = "user";
    public const string FromTenant = "tenant";
    public const string FromDefault = "default";

    /// A stored layout's column keys (empty for nothing, invalid JSON or anything that is not an array of strings).
    public static IReadOnlyList<string> Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Array.Empty<string>();
        try
        {
            using var d = JsonDocument.Parse(json);
            if (d.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<string>();
            return d.RootElement.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToList();
        }
        catch (JsonException) { return Array.Empty<string>(); }
    }

    /// The known keys of a choice, in its order, each once, at most <see cref="MaxColumns"/> (the catalog's spelling).
    public static IReadOnlyList<string> Clean(IEnumerable<string?> keys, Func<string, string?> known) =>
        keys.Where(k => !string.IsNullOrWhiteSpace(k)).Select(k => known(k!.Trim())).Where(k => k is not null).Select(k => k!)
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(MaxColumns).ToList();

    /// The layout a person sees, and where it came from (<see cref="FromUser"/>, <see cref="FromTenant"/>, <see cref="FromDefault"/>).
    public static (IReadOnlyList<string> Columns, string Source) Resolve(IReadOnlyList<string> shipped, string? tenantJson, string? userJson, Func<string, string?> known)
    {
        var user = Clean(Parse(userJson), known);
        if (user.Count > 0) return (user, FromUser);
        var tenant = Clean(Parse(tenantJson), known);
        if (tenant.Count > 0) return (tenant, FromTenant);
        return (Clean(shipped, known), FromDefault);
    }

    /// The tenant default alone (what "reset to the tenant default" brings back).
    public static IReadOnlyList<string> TenantDefault(IReadOnlyList<string> shipped, string? tenantJson, Func<string, string?> known) =>
        Resolve(shipped, tenantJson, null, known).Columns;

    public static string ToJson(IReadOnlyList<string> keys) => JsonSerializer.Serialize(keys);

    /// The catalog's lookup for <see cref="Resolve"/>: a key in any case -> its spelling, or null.
    public static Func<string, string?> KnownIn(CiColumnCatalog catalog) => k => catalog.Find(k)?.Key;

}
