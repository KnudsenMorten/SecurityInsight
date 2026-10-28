using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Changes;

/// <summary>
/// THE ONE generic classification mapping -- pure, no I/O. Built once and reused by asset type / subtype, the
/// classification dimensions (component, and the ones to come) and later classifications. Each row says:
/// <code>
///   source + SI field (or source path) + match (equals / in / prefix / pattern) over typed values
///   -> target SI field = value, with a priority (the highest priority match wins; one value per target)
/// </code>
/// Published into the Pro database as 'datamodel' rows keyed 'classification:&lt;row id&gt;' and evaluated in the CI build
/// with the same condition engine as the risk factors. The body (read defensively -- the data lane names the fields):
/// <code>
///   { "id": "azure-sql-database", "source": "azure", "field": "si_azure_resource_type", "match": "equals",
///     "values": [ "microsoft.sql/servers/databases" ], "target": "si_asset_subtype", "set": "SQL Database", "priority": 100 }
/// </code>
/// The web app edits the rows with the same wizard pattern as the risk factor criteria: the source, the field, the match,
/// the target and the target value are dropdowns of closed sets; an equals / in value is one SecurityInsight COLLECTED
/// for the field; a prefix / pattern is a glob of plain characters only -- nothing typed reaches a query unchecked. A
/// change is a cfg.ItemOverride row, staged on Review &amp; commit and validated again there (<see cref="Validate"/>).
/// </summary>
public static partial class ClassificationMapping
{
    public const string Template = "classification";
    public const int PriorityMin = 0;
    public const int PriorityMax = 10000;
    public const int MaxValues = 200;

    public static readonly string[] Matches = { "equals", "in", "prefix", "pattern" };
    public static readonly IReadOnlyList<(string Match, string Label)> MatchLabels = new[]
    {
        ("equals", "is"), ("in", "is one of"), ("prefix", "starts with"), ("pattern", "matches the pattern"),
    };

    /// The sources a row may name ("any" = whatever source filled the field).
    public static readonly string[] Sources = { "any", "azure", "mdc", "mde", "eg", "entra", "ad", "intune", "mdi", "servicenow", "cmdb", "shodan" };

    /// The SI fields a row may read in the wizard, what they are about, and how the wizard names them.
    public static readonly IReadOnlyList<(string Field, string Subject, string Label)> Fields = new[]
    {
        ("si_azure_resource_type", "asset", "Azure resource type"),
        ("si_record_type", "asset", "Record type"),
        ("si_os_platform", "asset", "Operating system platform"),
        ("si_os_name", "asset", "Operating system"),
        ("si_device_category", "asset", "Device category"),
        ("si_device_subtype", "asset", "Device subtype"),
        ("si_asset_type_source", "asset", "Asset type (as the source gave it)"),
        ("si_device_roles", "asset", "Device roles"),
        ("si_installed_software", "asset", "Installed software"),
        ("si_cmdb_class", "asset", "CMDB class"),
        ("si_identity_type", "asset", "Identity type"),
        ("si_class", "asset", "Asset class"),
        ("si_affected_product", "finding", "Affected product (vulnerability)"),
        ("si_category", "finding", "Category (finding)"),
        ("si_subcategory", "finding", "Subcategory (finding)"),
        ("si_finding_type", "finding", "Finding type"),
    };

    /// The asset type list of the owner's model (one list across sources).
    public static readonly string[] AssetTypes =
    {
        "Workstation", "Server", "Mobile", "Network device", "IoT", "Printer", "Database", "Storage", "Web app", "Key vault", "Network",
        "Container", "Compute", "Monitoring", "AI", "Integration", "Backup", "Security", "Management", "User", "Guest", "Service principal",
        "Managed identity", "Group", "Public IP", "Other", "Unknown",
    };

    /// The asset subtypes the owner named; the rows in force add any other subtype they set.
    public static readonly string[] AssetSubtypes =
    {
        "General", "SQL Database", "SQL Managed Instance", "PostgreSQL", "MySQL", "Cosmos DB", "SQL Server", "SQL Server instance",
        "Domain controller", "Web server", "Exchange", "ADFS", "File server",
    };

    /// The component values used until the 'dimensions:component' row is in the database.
    public static readonly string[] ComponentDefault = { "OS", "SQL", "Network", "Hardware", "Browser", "Office", "Application", "Other" };

    [GeneratedRegex(@"^[a-z0-9][a-z0-9_\-]{0,80}$", RegexOptions.CultureInvariant)]
    private static partial Regex RowId();

    [GeneratedRegex(@"^si_[a-z0-9_]+$", RegexOptions.CultureInvariant)]
    private static partial Regex SiField();

    [GeneratedRegex(@"^[a-z][a-z0-9_]{0,30}$", RegexOptions.CultureInvariant)]
    private static partial Regex SourceName();

    /// A prefix / pattern: plain characters and the wildcards * and ? -- no quote, backslash, bracket or bar.
    [GeneratedRegex(@"^[A-Za-z0-9 ._@/:+#\-*?]+$", RegexOptions.CultureInvariant)]
    private static partial Regex Glob();

    /// One row as the editor shows it. Stage = the row's state (enabled | disabled); When = its optional extra condition as
    /// text (shown read-only -- the wizard keeps it as it is).
    public sealed record Row(DataModelRow Data, string Id, string Source, string Field, string Match, IReadOnlyList<string> Values, string Target, string Set, int Priority, string Stage)
    {
        public string When { get; init; } = "";
        public bool Own => Data.Own;
        public bool Off => Data.Disabled || Stage == "disabled";
        public string Subject => SubjectOf(Field);
        public string Text => $"{FieldLabel(Field)} {MatchLabel(Match)} {string.Join(", ", Values.Select(v => "\"" + v + "\""))}";
    }

    /// One classification target (the template header's 'targets'): the SI field, its dimension, assets or findings,
    /// whether an asset carries every matching value, and the fallback when no row matches.
    public sealed record Target(string Field, string Dimension, string AppliesTo, bool Multi, string Fallback);

    /// The targets used until the template header is in the database (the shipped classification.locked.json's).
    public static readonly IReadOnlyList<Target> DefaultTargets = new[]
    {
        new Target("si_asset_type", "asset_type", "asset", false, "$keep"),
        // #772 the OS family (its own editor: /Admin/Settings/Mapping/os-family, DimensionMapping)
        new Target("si_os_family", "os_family", "asset", false, "Unknown"),
        new Target("si_asset_subtype", "asset_subtype", "asset", false, "General"),
        new Target("si_components", "component", "asset", true, "Other"),
        new Target("si_component", "component", "finding", false, "Other"),
        // #772 the ServiceNow sub-CI (its own editor: /Admin/Settings/Mapping/servicenow-subci, DimensionMapping)
        new Target("si_servicenow_subci", "servicenow_subci", "finding", false, "Other"),
        // #772 the patch cycle (rows patch-cycle-* over the facts Risk Analysis works out: si_patch_fix, si_patch_age)
        new Target("si_patch_cycle", "patch_cycle", "finding", false, "Unknown"),
    };

    public static string SubjectOf(string? field) => Fields.FirstOrDefault(f => f.Field == field).Subject ?? (field is not null && field.StartsWith("si_", StringComparison.Ordinal) ? "" : "source path");
    public static string FieldLabel(string? field) => Fields.FirstOrDefault(f => f.Field == field).Label ?? field ?? "";
    public static string MatchLabel(string? m) => MatchLabels.FirstOrDefault(x => x.Match == m).Label ?? m ?? "";
    public static string TargetLabel(string target) => target switch
    {
        "si_asset_type" => "Asset type",
        "si_asset_subtype" => "Asset subtype",
        "si_components" => "Components (asset)",
        "si_component" => "Component (finding)",
        "si_servicenow_subci" => "ServiceNow sub-CI",
        "si_os_family" => "OS family",
        "si_patch_cycle" => "Patch cycle",
        _ => target.StartsWith("si_", StringComparison.Ordinal) && target.Length > 3 ? char.ToUpperInvariant(target[3]) + target[4..].Replace('_', ' ') : target,
    };

    private static string S(JsonElement o, string p) => o.ValueKind == JsonValueKind.Object && o.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    /// equals / in read 'values'; prefix / pattern read 'pattern' (one glob, or a list).
    private static List<string> MatchValues(JsonElement o)
    {
        var list = new List<string>();
        foreach (var p in new[] { "values", "pattern", "value" })
        {
            if (!o.TryGetProperty(p, out var v)) continue;
            if (v.ValueKind == JsonValueKind.Array) list.AddRange(v.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() ?? "" : x.GetRawText()));
            else if (v.ValueKind == JsonValueKind.String && (v.GetString() ?? "").Length > 0) list.Add(v.GetString()!);
            else if (v.ValueKind == JsonValueKind.Number) list.Add(v.GetRawText());
        }
        return list;
    }

    private static int? PriorityOf(JsonElement o) =>
        o.TryGetProperty("priority", out var p) && p.ValueKind == JsonValueKind.Number && p.TryGetDouble(out var d) && d == Math.Floor(d) && d >= PriorityMin && d <= PriorityMax ? (int)d : null;

    /// A condition as text a person reads ("si_os_platform is windows and ...").
    public static string ConditionText(JsonElement c) =>
        string.Join(c.ValueKind == JsonValueKind.Object && c.TryGetProperty("any", out _) ? " or " : " and ",
            FactorCriteria.Leaves(c).Select(l => $"{l.Field} {l.Op}{(l.Value.ValueKind == JsonValueKind.Undefined ? "" : " " + (l.Value.ValueKind == JsonValueKind.String ? "\"" + l.Value.GetString() + "\"" : l.Value.GetRawText()))}"));

    /// The classification rows of a row list (highest priority first), parsed for display.
    public static IReadOnlyList<Row> Of(IEnumerable<DataModelRow> rows) =>
        rows.Where(r => r.Template == Template && r.Item.Length > 0).Select(View)
            .OrderBy(r => r.Target, StringComparer.Ordinal).ThenByDescending(r => r.Priority).ThenBy(r => r.Id, StringComparer.Ordinal).ToList();

    public static Row View(DataModelRow r)
    {
        var body = r.Effective ?? r.TemplateBody ?? r.OverrideBody;
        try
        {
            using var d = JsonDocument.Parse(body ?? "{}");
            var o = d.RootElement;
            return new Row(r, S(o, "id") is { Length: > 0 } id ? id : r.Item, S(o, "source") is { Length: > 0 } s ? s : "any", S(o, "field"),
                S(o, "match") is { Length: > 0 } m ? m : "equals", MatchValues(o), S(o, "target"), S(o, "set"),
                PriorityOf(o) ?? 0, S(o, "state") is { Length: > 0 } st ? st : "enabled")
            {
                When = o.TryGetProperty("when", out var w) && w.ValueKind == JsonValueKind.Object ? ConditionText(w) : "",
            };
        }
        catch (JsonException) { return new Row(r, r.Item, "", "", "", Array.Empty<string>(), "", "", 0, ""); }
    }

    /// The targets of the template header ('classification' -- its 'targets' block); the shipped defaults when the header
    /// is not in the database yet or carries no targets.
    public static IReadOnlyList<Target> Targets(IEnumerable<DataModelRow> rows)
    {
        var header = rows.FirstOrDefault(r => r.ItemKey == Template);
        var body = header?.Effective ?? header?.TemplateBody;
        if (string.IsNullOrWhiteSpace(body)) return DefaultTargets;
        try
        {
            using var d = JsonDocument.Parse(body);
            if (!d.RootElement.TryGetProperty("targets", out var ts) || ts.ValueKind != JsonValueKind.Array) return DefaultTargets;
            var list = ts.EnumerateArray().Where(t => t.ValueKind == JsonValueKind.Object && S(t, "field").StartsWith("si_", StringComparison.Ordinal))
                .Select(t => new Target(S(t, "field"), S(t, "dimension"), S(t, "appliesTo") is { Length: > 0 } a ? a : "asset",
                    t.TryGetProperty("multi", out var mu) && mu.ValueKind == JsonValueKind.True, S(t, "fallback"))).ToList();
            return list.Count > 0 ? list : DefaultTargets;
        }
        catch (JsonException) { return DefaultTargets; }
    }

    /// The values a target may be set to (a closed set): its dimension's values (dimensions:&lt;dimension&gt;); while that row
    /// is not in the database, the owner's lists; plus every value a row in force already sets for that target.
    public static IReadOnlyList<string> TargetValues(string target, IReadOnlyList<Target> targets, IEnumerable<Dimensions.DimensionView> dims, IEnumerable<Row> rows)
    {
        var t = targets.FirstOrDefault(x => x.Field == target);
        var dim = t is null ? null : dims.FirstOrDefault(d => d.Id == t.Dimension);
        IEnumerable<string> baseList = dim is not null ? dim.Values.Select(v => v.Value)
            : t?.Dimension == "asset_type" ? AssetTypes : t?.Dimension == "asset_subtype" ? AssetSubtypes : t?.Dimension == "component" ? ComponentDefault
            : DimensionMapping.All.FirstOrDefault(s => s.DimensionId == t?.Dimension) is { } ms ? ms.BucketDefault : Array.Empty<string>();
        return baseList.Concat(rows.Where(r => r.Target == target && r.Set.Length > 0).Select(r => r.Set))
            .Where(Dimensions.IsPlainValue).Distinct(StringComparer.Ordinal).ToList();
    }

    // ------------------------------------------------------------------------------------------------ validation

    /// The reasons a classification row is refused (empty = accepted) -- delegated to THE validator of the mechanism,
    /// ClassificationItemValidator.Rule (the twin of Test-SIClassificationRule); the wizard adds its own glob safety in Build.
    public static IReadOnlyList<string> Validate(string item, JsonElement o) => ClassificationItemValidator.Rule(item, o);

    // ------------------------------------------------------------------------------------------------ the wizard

    public sealed record Posted(string? Source, string? Field, string? Match, string[]? Picked, string? Pattern, string? Target, string? Set, string? Priority);

    /// ADD / EDIT A ROW: the key and body of a classification row built ONLY from closed sets -- the source, field, match
    /// and target from their lists, the value to set from <paramref name="targetValues"/>, an equals / in value from the
    /// values SecurityInsight collected (the posted tokens must be among them), a prefix / pattern as a plain glob.
    /// <paramref name="existing"/> = the row being edited (its id and other fields are kept), null = a new customer row.
    public static (string? Key, string? Body, IReadOnlyList<string> Problems) Build(Row? existing, IEnumerable<string> takenIds, Posted p,
        IReadOnlyCollection<FactorCriteria.Collected> collected, IReadOnlyCollection<string> targets, IReadOnlyCollection<string> targetValues)
    {
        var why = new List<string>();
        if (p.Source is null || !Sources.Contains(p.Source, StringComparer.Ordinal)) why.Add("pick a source from the list");
        var f = Fields.FirstOrDefault(x => x.Field == p.Field);
        if (f.Field is null) why.Add("pick a field from the list");
        if (p.Match is null || !Matches.Contains(p.Match, StringComparer.Ordinal)) why.Add("pick how it matches from the list");
        if (p.Target is null || !targets.Contains(p.Target)) why.Add("pick what it sets from the list");
        if (p.Set is null || !targetValues.Contains(p.Set)) why.Add("pick the value to set from the list");
        if (!int.TryParse(p.Priority, NumberStyles.Integer, CultureInfo.InvariantCulture, out var prio) || prio < PriorityMin || prio > PriorityMax)
            why.Add($"the priority is a whole number from {PriorityMin} to {PriorityMax}");
        var values = new List<string>();
        if (p.Match is "equals" or "in")
        {
            var byToken = collected.GroupBy(c => c.Token, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First().Value, StringComparer.Ordinal);
            foreach (var t in (p.Picked ?? Array.Empty<string>()).Where(t => !string.IsNullOrEmpty(t)))
            {
                if (!byToken.TryGetValue(t, out var v)) { why.Add("a picked value is not one SecurityInsight collected -- reload the page and pick again"); continue; }
                if (!values.Contains(v, StringComparer.Ordinal)) values.Add(v);
            }
            if (values.Count == 0) why.Add("pick at least one collected value");
            if (p.Match == "equals" && values.Count > 1) why.Add("'is' matches one value -- use 'is one of' for several");
        }
        else if (p.Match is "prefix" or "pattern")
        {
            var g = (p.Pattern ?? "").Trim();
            if (g.Length == 0) why.Add("type the beginning or the pattern to match");
            else if (g.Length > FactorCriteria.MaxValueLength || !Glob().IsMatch(g)) why.Add($"'{g}' is not a plain pattern -- letters, digits, space, . _ @ / : + # - and the wildcards * and ?");
            else if (g.All(c => c is '*' or '?' or ' ')) why.Add($"'{g}' matches everything -- a pattern needs at least one letter or digit");
            else values.Add(g);
        }
        if (why.Count > 0) return (null, null, why);
        var id = existing?.Id;
        if (id is null)
        {
            var taken = takenIds.ToHashSet(StringComparer.Ordinal);
            var stem = Regex.Replace((TargetLabel(p.Target!) + "-" + p.Set).ToLowerInvariant(), "[^a-z0-9]+", "-").Trim('-');
            var n = 1;
            do { id = $"customer-{stem}-{n++}"; } while (taken.Contains(id));
        }
        JsonObject o;
        try { o = (existing is null ? null : JsonNode.Parse(existing.Data.Effective ?? existing.Data.TemplateBody ?? existing.Data.OverrideBody ?? "{}") as JsonObject) ?? new JsonObject(); }
        catch (JsonException) { o = new JsonObject(); }
        o["id"] = id;
        o["source"] = p.Source;
        o["field"] = f.Field;
        o["match"] = p.Match;
        // the shape of classification.locked.json: equals / in -> values (a list); prefix / pattern -> pattern (a glob).
        // An existing row's optional 'when' is kept as it is (shown read-only).
        o.Remove("value"); o.Remove("pattern"); o.Remove("values");
        if (p.Match is "equals" or "in") { var arr = new JsonArray(); foreach (var v in values) arr.Add(v); o["values"] = arr; }
        else o["pattern"] = values[0];
        o["target"] = p.Target;
        o["set"] = p.Set;
        o["priority"] = prio;
        if (existing is null) { o["state"] = "enabled"; o["origin"] = "customer"; }
        var body = o.ToJsonString();
        using var check = JsonDocument.Parse(body);
        var problems = Validate(id, check.RootElement);
        return problems.Count > 0 ? (null, null, problems) : (Template + ":" + id, body, Array.Empty<string>());
    }
}
