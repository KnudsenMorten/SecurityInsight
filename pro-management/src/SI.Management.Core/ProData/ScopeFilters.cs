using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SI.Management.Core.ProData;

/// One filter of an output scope (owner 2026-10-19): the SI field and the values that pass (OR). A row WITHOUT a value for
/// the field does not pass (owner: "we can NOT have a finding without a risk rating").
public sealed record ScopeFilter(string Field, IReadOnlyList<string> Values);

/// One field a scope filter offers by name: its words, the row columns it is read from (first with a value), its values
/// when the list is closed, and the sidata.Finding column the preview counts it from (null = not counted in the preview).
public sealed record ScopeFilterField(string Field, string Label, IReadOnlyList<string> Columns, IReadOnlyList<string> Values, string? FindingColumn);

/// <summary>
/// THE FILTERS OF AN OUTPUT SCOPE (owner 2026-10-19: "define filters on one or more filters like risk rating ... critical,
/// high by default but exclude medium and low ... filter on security domain"): the C# twin of engine\_shared\
/// SI-OutputScope.ps1 ($SIOutputScopeFilterFields, Test-SIOutputScopeFilters) -- a test holds the two lists and the two
/// rules to one fixture. Any other si_* field of the finding is accepted by name.
/// </summary>
public static partial class ScopeFilters
{
    public static readonly IReadOnlyList<ScopeFilterField> Fields =
    [
        new("si_risk_rating", "Risk rating", ["RiskRating", "si_risk_rating"], ["Critical", "High", "Moderate", "Low"], "RiskRating"),
        // #817: the correlated data's own dimensions (Domain > Category > Subcategory) -- the vulnerability connectors are
        // scoped by what the finding IS, not by the report template that produced it
        new("si_category", "Category", ["si_category", "Category"], [], "Category"),
        new("si_subcategory", "Subcategory", ["si_subcategory", "SubCategory", "Subcategory"], [], "Subcategory"),
        new("si_class", "Class", ["si_class", "AssetClass"], ["device", "identity", "cloud_resource", "public_ip"], null),
        new("si_component", "Component", ["si_component", "Component"], ["OS", "SQL", "Network", "Hardware", "Browser", "Office", "Application", "Other"], "Component"),
        new("si_patch_cycle", "Patch cycle", ["si_patch_cycle"], [], "ContextPatchCycle"),
        new("si_os_family", "OS family", ["si_os_family"], [], "ContextOsFamily"),
        new("si_servicenow_subci", "ServiceNow sub-CI", ["si_servicenow_subci"], [], "ContextSubCi"),
    ];

    /// The quick choices of the editor (owner 2026-10-19): one click sets the values -- never a shipped default.
    public static readonly IReadOnlyList<(string Field, string Words, IReadOnlyList<string> Values)> QuickChoices =
    [
        ("si_risk_rating", "Critical and High only", ["Critical", "High"]),
    ];

    [GeneratedRegex("^si_[a-z0-9_]{1,80}$", RegexOptions.CultureInvariant)]
    private static partial Regex FieldPattern();

    public static ScopeFilterField? Find(string field) => Fields.FirstOrDefault(f => f.Field == field);

    public static string Label(string field) => Find(field)?.Label ?? CiColumns.LabelOf(field);

    /// The columns a row carries a field under (a named field's list, else the field itself).
    public static IReadOnlyList<string> Columns(string field) => Find(field)?.Columns ?? [field];

    /// The values in the field's own order (a closed list), else as given.
    public static IReadOnlyList<string> Ordered(string field, IReadOnlyList<string> values) =>
        Find(field) is { Values.Count: > 0 } k ? k.Values.Where(v => values.Contains(v, StringComparer.OrdinalIgnoreCase)).ToList() : values.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// Test-SIOutputScopeBody's rules for one filter.
    public static IReadOnlyList<string> Validate(ScopeFilter f)
    {
        var why = new List<string>();
        if (!FieldPattern().IsMatch(f.Field)) { why.Add($"'{f.Field}' is not an SI field (si_...)"); return why; }
        if (f.Values.Count == 0) why.Add($"the filter on {Label(f.Field)} names no value");
        foreach (var v in f.Values) if (v.Length > 200) why.Add($"a value of {Label(f.Field)} is longer than 200 characters");
        if (Find(f.Field) is { Values.Count: > 0 } k)
            foreach (var v in f.Values) if (!k.Values.Contains(v, StringComparer.OrdinalIgnoreCase)) why.Add($"'{v}' is not a {k.Label.ToLowerInvariant()} ({string.Join(", ", k.Values)})");
        return why;
    }

    /// A row's values for a scope's filters, from a JSON item (the first of each field's columns that has a value; a list
    /// gives each of its values).
    public static IReadOnlyDictionary<string, IReadOnlyList<string?>> ValuesOf(JsonObject item, IEnumerable<ScopeFilter> filters)
    {
        var d = new Dictionary<string, IReadOnlyList<string?>>(StringComparer.Ordinal);
        foreach (var f in filters)
        {
            IReadOnlyList<string?> vals = Array.Empty<string?>();
            foreach (var c in Columns(f.Field))
            {
                var node = OutputMapper.Get(item, c);
                var list = node is JsonArray a ? a.Select(x => (string?)OutputMapper.Text(x)).ToList() : new List<string?> { OutputMapper.Text(node) };
                if (list.Any(x => !string.IsNullOrWhiteSpace(x))) { vals = list; break; }
            }
            d[f.Field] = vals;
        }
        return d;
    }
}

/// The preview count of a finding destination's scope (owner 2026-10-19: "N findings on M assets would be sent (of T)").
public sealed record ScopeCount(long Findings, long Assets, long TotalFindings, long TotalAssets, DateTime? CollectionTime, IReadOnlyList<string> NotCounted);

/// <summary>
/// THE SCOPE AS ONE SQL STATEMENT over the published Detailed collection (sidata.Finding, the one trusted run): the same rule as
/// <see cref="OutputScope.Passes"/> -- a blank severity, tier, domain or report passes (today's rule); a row without a
/// value never passes a filter -- so the page counts findings AND distinct assets without reading the rows. Fixed text from fixed
/// parts (a filter's column comes from <see cref="ScopeFilters.Fields"/>, never a request); every value a parameter.
/// A filter on a field the findings table has no column for is not counted (<see cref="ScopeCount.NotCounted"/>).
/// </summary>
public static class OutputScopeSql
{
    public const string SeverityKeyExpr =
        "CASE LOWER(REPLACE(REPLACE(REPLACE(LTRIM(RTRIM(f.Severity)), N' ', N''), N'-', N''), N'_', N'')) WHEN N'critical' THEN N'veryhigh' WHEN N'moderate' THEN N'medium' " +
        "WHEN N'info' THEN N'informational' WHEN N'information' THEN N'informational' ELSE LOWER(REPLACE(REPLACE(REPLACE(LTRIM(RTRIM(f.Severity)), N' ', N''), N'-', N''), N'_', N'')) END";

    /// The statement and its parameters; <paramref name="columns"/> = the sidata.Finding columns this database has.
    public static (string Text, Dictionary<string, object?> Parameters, IReadOnlyList<string> NotCounted) Count(OutputScope s, IReadOnlySet<string>? resolved, IReadOnlySet<string> columns)
    {
        var p = new Dictionary<string, object?>(StringComparer.Ordinal);
        var where = new List<string>();
        if (s.Severities.Count > 0)
        {
            p["Sev"] = JsonSerializer.Serialize(s.Severities.Select(OutputScope.Key).Distinct());
            where.Add($"(NULLIF(LTRIM(RTRIM(f.Severity)), N'') IS NULL OR {SeverityKeyExpr} IN (SELECT v.[value] FROM OPENJSON(@Sev) AS v))");
        }
        if (s.Tiers.Count > 0)
        {
            p["Tiers"] = JsonSerializer.Serialize(s.Tiers);
            where.Add("(f.Tier IS NULL OR f.Tier IN (SELECT CONVERT(int, v.[value]) FROM OPENJSON(@Tiers) AS v))");
        }
        if (s.Domains.Count > 0)
        {
            p["Dom"] = JsonSerializer.Serialize(s.Domains.Select(d => d.Trim().ToLowerInvariant()));
            where.Add("(NULLIF(LTRIM(RTRIM(f.SecurityDomain)), N'') IS NULL OR LOWER(LTRIM(RTRIM(f.SecurityDomain))) IN (SELECT v.[value] FROM OPENJSON(@Dom) AS v))");
        }
        if (resolved is not null)
        {
            p["Rep"] = JsonSerializer.Serialize(resolved);
            where.Add("(NULLIF(LTRIM(RTRIM(f.ReportName)), N'') IS NULL OR LTRIM(RTRIM(f.ReportName)) IN (SELECT v.[value] FROM OPENJSON(@Rep) AS v))");
        }
        var notCounted = new List<string>();
        var i = 0;
        foreach (var f in s.Filters)
        {
            var col = ScopeFilters.Find(f.Field)?.FindingColumn;
            if (col is null || !columns.Contains(col)) { notCounted.Add(ScopeFilters.Label(f.Field)); continue; }
            var name = "F" + (i++).ToString(System.Globalization.CultureInfo.InvariantCulture);
            p[name] = JsonSerializer.Serialize(f.Values.Select(v => v.Trim().ToLowerInvariant()));
            where.Add($"LOWER(LTRIM(RTRIM(f.[{col}]))) IN (SELECT v.[value] FROM OPENJSON(@{name}) AS v)");
        }
        // every finding with a configuration id is a vulnerability to the connectors (operator ruling 2026-10-06), as the
        // close-loop's snapshot reads them -- not only the CVE ones
        var all = s.Destination.StartsWith("vuln-", StringComparison.Ordinal) ? "NULLIF(f.ConfigurationId, N'') IS NOT NULL AND f.AssetKey IS NOT NULL" : "1 = 1";
        // The filters are IN (SELECT .. OPENJSON ..) subqueries, and SQL Server refuses an aggregate over an expression
        // holding a subquery (error 130, a customer 2026-10-20) -- so each finding's in-scope flag is worked out per row
        // first (the CTE), and the counts aggregate that plain column.
        var text = $"""
IF OBJECT_ID(N'sidata.Finding') IS NULL OR OBJECT_ID(N'sidata.vPublishedCollection') IS NULL
BEGIN
    SELECT CAST(NULL AS bigint) AS Findings WHERE 1 = 0;
    RETURN;
END;
DECLARE @c int, @t datetime2(3);
-- one trusted run (PublishedRun.cs): the published Detailed collection, never "the newest" worked out here
SELECT TOP (1) @c = pc.CollectionId, @t = pc.CollectionTime FROM sidata.vPublishedCollection AS pc WHERE pc.Kind = N'Detailed';
{CountSelect(where, all)}
""";
        return (text, p, notCounted);
    }

    /// The count itself, a plain read (<see cref="SqlGuard.AssertReadOnly"/>): the in-scope flag per finding, then the sums.
    private static string CountSelect(IReadOnlyList<string> where, string all) => $"""
WITH x AS (
    SELECT f.AssetKey, CASE WHEN {(where.Count == 0 ? "1 = 1" : string.Join("\n  AND ", where))} THEN 1 ELSE 0 END AS InScope
    FROM sidata.Finding AS f
    WHERE f.CollectionId = @c AND {all})
SELECT SUM(x.InScope) AS Findings,
       COUNT(DISTINCT CASE WHEN x.InScope = 1 THEN x.AssetKey END) AS Assets,
       COUNT_BIG(*) AS TotalFindings, COUNT(DISTINCT x.AssetKey) AS TotalAssets, @t AS CollectionTime
FROM x;
""";

    /// The finding columns the count may read (when the database has them).
    public static readonly IReadOnlyList<string> OptionalColumns = ScopeFilters.Fields.Select(f => f.FindingColumn).Where(c => c is not null).Select(c => c!).Distinct().ToList();

    public static string ColumnsSql => "SELECT " + string.Join(", ", OptionalColumns.Select(c => $"CASE WHEN COL_LENGTH(N'sidata.Finding', N'{c}') IS NULL THEN 0 ELSE 1 END AS [{c}]")) + ";";
}
