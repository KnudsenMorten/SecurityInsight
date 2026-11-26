using SI.Management.Web.Data;

namespace SI.Management.Web.Changes;

/// <summary>
/// #772 the mapping page's preview: the facts a mapping reads, GROUPED in SQL (one row per distinct combination with its
/// count), so a page counts a large install's findings without reading them. Read-only, every value a parameter.
/// <list type="bullet">
/// <item>ServiceNow sub-CI: the findings of ONE collection (the newest complete one the views list) -- component, vendor,
/// product, category, configuration id, report, and the sub-CI the last run stored.</item>
/// <item>OS family: the CIs -- OS platform, OS name, device category, asset type, and the OS family the last build stored.</item>
/// </list>
/// </summary>
public sealed class DimensionMappingPreview(ISqlExecutor sql)
{
    public const string FindingsSql = """
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.Finding') IS NULL RETURN;
SELECT TOP (@Top) j.Component, j.Vendor, j.Product, j.Category, f.ConfigurationId, f.ReportName, j.Stored, COUNT_BIG(*) AS N,
       COUNT_BIG(*) OVER () AS AllGroups, SUM(COUNT_BIG(*)) OVER () AS AllN
FROM sidata.Finding AS f
CROSS APPLY (SELECT
    CONVERT(nvarchar(64), JSON_VALUE(f.DetailJson, N'$.si_component')) AS Component,
    CONVERT(nvarchar(400), COALESCE(JSON_VALUE(f.DetailJson, N'$.si_affected_vendor'), JSON_VALUE(f.DetailJson, N'$.SI_AffectedVendor'))) AS Vendor,
    CONVERT(nvarchar(1000), COALESCE(JSON_VALUE(f.DetailJson, N'$.si_affected_product'), JSON_VALUE(f.DetailJson, N'$.SI_AffectedProduct'))) AS Product,
    CONVERT(nvarchar(256), COALESCE(JSON_VALUE(f.DetailJson, N'$.si_category'), JSON_VALUE(f.DetailJson, N'$.Category'))) AS Category,
    CONVERT(nvarchar(64), JSON_VALUE(f.DetailJson, N'$.si_servicenow_subci')) AS Stored) AS j
WHERE f.CollectionId = @CollectionId AND ISJSON(f.DetailJson) = 1
GROUP BY j.Component, j.Vendor, j.Product, j.Category, f.ConfigurationId, f.ReportName, j.Stored
ORDER BY N DESC;
""";

    public const string CisSql = """
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.Ci') IS NULL RETURN;
SELECT TOP (@Top) j.OsPlatform, j.OsName, j.DeviceCategory, c.AssetType, j.Stored, COUNT_BIG(*) AS N,
       COUNT_BIG(*) OVER () AS AllGroups, SUM(COUNT_BIG(*)) OVER () AS AllN
FROM sidata.Ci AS c
CROSS APPLY (SELECT
    CONVERT(nvarchar(400), JSON_VALUE(c.DocJson, N'$.si_os_platform')) AS OsPlatform,
    CONVERT(nvarchar(400), JSON_VALUE(c.DocJson, N'$.si_os_name')) AS OsName,
    CONVERT(nvarchar(400), JSON_VALUE(c.DocJson, N'$.si_device_category')) AS DeviceCategory,
    CONVERT(nvarchar(64), JSON_VALUE(c.DocJson, N'$.si_os_family')) AS Stored) AS j
WHERE ISJSON(c.DocJson) = 1
GROUP BY j.OsPlatform, j.OsName, j.DeviceCategory, c.AssetType, j.Stored
ORDER BY N DESC;
""";

    public sealed record Group(IReadOnlyDictionary<string, IReadOnlyList<string>> Facts, string? Stored, long N);

    /// <summary>
    /// #1400 (owner 2026-11-26: "memory issues must not be a problem in any step"): the most combinations a preview reads --
    /// the most common first (TOP, ordered by count in SQL), never every distinct combination of a large install's findings
    /// into the web app. When there are more, <see cref="Read"/> says how many and how many findings the counted ones hold.
    /// </summary>
    public const int MaxGroups = 5_000;

    /// The groups read, and how many there are in all (combinations and findings / CIs).
    public sealed record Read(IReadOnlyList<Group> Groups, long AllGroups, long AllN)
    {
        public bool Cut => AllGroups > Groups.Count;
        public long CountedN => Groups.Sum(g => g.N);

        /// "The preview counts the 5,000 most common combinations of 12,345 -- 1,234,000 of 1,250,000 findings; ..." (null = all).
        public string? Note(string noun) => !Cut ? null
            : $"The preview counts the {Groups.Count:N0} most common combinations of the {AllGroups:N0} there are -- {CountedN:N0} of {AllN:N0} {noun}; "
              + $"the other {AllN - CountedN:N0} {noun} are not in these counts.";
    }

    /// The grouped facts of the spec's subject (at most <paramref name="top"/> combinations, the most common first); null when
    /// the tables are not there yet.
    public async Task<Read?> ReadAsync(DimensionMapping.Spec spec, int? collectionId, CancellationToken ct, int top = MaxGroups)
    {
        if (!spec.Assets && collectionId is null) return null;
        var take = Math.Clamp(top, 1, MaxGroups);
        var rows = await sql.QueryAsync(spec.Assets ? CisSql : FindingsSql,
            spec.Assets ? new Dictionary<string, object?> { ["Top"] = take } : new Dictionary<string, object?> { ["CollectionId"] = collectionId, ["Top"] = take }, ct).ConfigureAwait(false);
        var groups = rows.Select(r => new Group(spec.Assets
                ? new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                {
                    ["si_os_platform"] = One(r.Str("OsPlatform")), ["si_os_name"] = One(r.Str("OsName")),
                    ["si_device_category"] = One(r.Str("DeviceCategory")), ["si_asset_type"] = One(r.Str("AssetType")),
                }
                : new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                {
                    ["si_component"] = One(r.Str("Component")), ["si_affected_vendor"] = DimensionMapping.Values(r.Str("Vendor")),
                    ["si_affected_product"] = DimensionMapping.Values(r.Str("Product")), ["si_category"] = One(r.Str("Category")),
                    ["si_finding_key"] = One(r.Str("ConfigurationId")), ["si_report_name"] = One(r.Str("ReportName")),
                },
            r.Str("Stored"), r.Long("N") ?? 0)).ToList();
        var first = rows.FirstOrDefault();
        return new Read(groups, Math.Max(groups.Count, first?.Long("AllGroups") ?? groups.Count), Math.Max(groups.Sum(g => g.N), first?.Long("AllN") ?? 0));
    }

    private static IReadOnlyList<string> One(string? s) => string.IsNullOrWhiteSpace(s) ? Array.Empty<string>() : [s.Trim()];
}
