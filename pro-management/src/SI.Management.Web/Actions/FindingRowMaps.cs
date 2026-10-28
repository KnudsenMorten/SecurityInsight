using System.Globalization;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Actions;

/// <summary>
/// Which findings of the collection one row of an aggregated grid stands for (#286). Every part is optional; a finding
/// matches when every given part equals the finding's (case-insensitive): the asset (its key or, for the close-loop and
/// connector rows that carry no key, its name), the issue (the CVE, else the configuration id, else the title -- the
/// "what changed" view's issue key) and the report.
/// </summary>
public sealed record FindingMatch(string? AssetKey = null, string? Issue = null, string? Report = null, string? AssetName = null)
{
    private static string? S(IReadOnlyDictionary<string, object?> r, string k) =>
        r.TryGetValue(k, out var v) && v is not null ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;
    private static bool Eq(string? a, string? b) => string.Equals(a?.Trim(), b?.Trim(), StringComparison.OrdinalIgnoreCase);

    /// A finding row (the collection's raw rows grid) matches.
    public bool Matches(IReadOnlyDictionary<string, object?> row)
    {
        if (AssetKey is not null && !Eq(S(row, "AssetKey"), AssetKey)) return false;
        if (AssetName is not null && !Eq(S(row, "AssetName"), AssetName)) return false;
        if (Report is not null && !Eq(S(row, "ReportName"), Report)) return false;
        if (Issue is not null && !Eq(S(row, "Cve"), Issue) && !Eq(S(row, "ConfigurationId"), Issue) && !Eq(S(row, "Title"), Issue)) return false;
        return AssetKey is not null || AssetName is not null || Issue is not null;
    }

    /// A match names something: an empty one would stand for the whole collection, and never does.
    public bool IsEmpty => AssetKey is null && AssetName is null && Issue is null;
}

public enum RowMapKind
{
    /// The grid's rows ARE findings (raw rows, a CI's findings, the facet views, the department grids).
    Findings,
    /// The row key alone says which findings (a CVE, a CI, a "what changed" key).
    FromKey,
    /// The row is read back (by its key) and its columns say which findings (an exemption, a close-loop event, a
    /// connector item).
    FromRow,
    /// A service: the findings of its CIs in the collection.
    Service,
    /// A group of CI findings (the CI data's Findings summary: one finding x tier x severity x CMDB group): the CIs that
    /// hold it are read back from the CI data, then that finding on each of them in the collection.
    CiGroup,
    /// The rows stand for no finding (a connector run). Declared with its reason, never silently.
    None,
}

/// <summary>
/// One grid's row-to-finding mapping (#286). Every grid of every view declares one here (<see cref="FindingRowMaps"/>),
/// so the shared action bar acts on the SAME findings whatever view the rows were selected on: an aggregated row becomes
/// the findings it stands for in the current collection, read again on the server by <see cref="FindingSelectionResolver"/>
/// (department visibility, the bulk guard, the refused list and the audit apply unchanged).
/// </summary>
public sealed record FindingRowMap(string Grid, RowMapKind Kind, string Describe, string RowNoun)
{
    public Func<string, FindingMatch?>? FromKey { get; init; }
    /// The grid itself, to read its rows back: by key (FromRow), or every row matching the page's filter ("all matching").
    public GridSpec? Spec { get; init; }
    /// The grid's parameters for the collection (and the selection's page state, e.g. the service drilled into).
    public Func<ViewCollection, FindingSelection, IReadOnlyDictionary<string, object?>>? Parameters { get; init; }
    public Func<IReadOnlyDictionary<string, object?>, FindingMatch?>? FromRow { get; init; }
    /// "Apply to all N matching" re-reads the grid with the page's filter: only where the server can rebuild exactly the
    /// rows the page showed (a time-window view -- close-loop events, connector items, what changed -- asks for a selection).
    public bool AllMatching { get; init; }
    /// The grid acts on findings (everything except <see cref="RowMapKind.None"/>).
    public bool Acts => Kind != RowMapKind.None;
    /// The rows are aggregates (one row = possibly many findings).
    public bool Aggregated => Kind is RowMapKind.FromKey or RowMapKind.FromRow or RowMapKind.Service or RowMapKind.CiGroup;
}

public static class FindingRowMaps
{
    private static string? S(IReadOnlyDictionary<string, object?> r, string k) =>
        r.TryGetValue(k, out var v) && v is not null && Convert.ToString(v, CultureInfo.InvariantCulture) is { Length: > 0 } s ? s : null;

    private static readonly DateTime Ever = new(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime Never = new(9999, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static IReadOnlyDictionary<string, object?> InCollection(ViewCollection c, FindingSelection _) => new Dictionary<string, object?> { ["CollectionId"] = c.CollectionId };

    private static FindingRowMap ByAsset(string grid, string noun, GridSpec spec, Func<ViewCollection, FindingSelection, IReadOnlyDictionary<string, object?>>? p = null, bool all = true) =>
        new(grid, RowMapKind.FromKey, $"a {noun} = every finding on that asset in this collection", noun)
        { FromKey = k => new FindingMatch(AssetKey: k), Spec = spec, Parameters = p ?? InCollection, AllMatching = all };

    /// Every grid of the collection and department views, by spec name (a department-restricted spec is "name@dept").
    public static readonly IReadOnlyDictionary<string, FindingRowMap> All = new Dictionary<string, FindingRowMap>(StringComparer.OrdinalIgnoreCase)
    {
        ["rows"] = new("rows", RowMapKind.Findings, "a row = one finding", "finding"),
        ["department"] = new("department", RowMapKind.Findings, "a row = one finding", "finding"),
        // #330: one issue's findings, read by exact equality when an aggregated row is resolved (no page shows it)
        ["rowsofissue"] = new("rowsofissue", RowMapKind.Findings, "a row = one finding", "finding"),
        ["rowsoffix"] = new("rowsoffix", RowMapKind.Findings, "a row = one finding", "finding"),
        ["vulns"] = new("vulns", RowMapKind.FromKey, "a CVE row = every finding of that CVE on the assets in this collection", "CVE")
        { FromKey = k => new FindingMatch(Issue: k), Spec = CollectionViewSql.Vulnerabilities, Parameters = InCollection, AllMatching = true },
        // the same rows grouped live, for an account limited to departments (the header search only)
        ["vulnslive"] = new("vulnslive", RowMapKind.FromKey, "a CVE row = every finding of that CVE on the assets in this collection", "CVE")
        { FromKey = k => new FindingMatch(Issue: k), Spec = CollectionViewSql.VulnerabilitiesLive, Parameters = InCollection, AllMatching = true },
        // #290: the mail's Top critical findings -- a row = every finding of that issue (CVE / configuration) in this
        // collection; read back by key through the collection's issues (the list itself is the kept view's, so "all
        // matching" cannot be rebuilt on the server: select the rows).
        ["topissues"] = new("topissues", RowMapKind.FromKey, "a finding row = every finding of that CVE / configuration in this collection", "finding")
        { FromKey = k => new FindingMatch(Issue: k), Spec = CollectionViewSql.IssueKeys, Parameters = InCollection, AllMatching = false },
        ["issuekeys"] = new("issuekeys", RowMapKind.FromKey, "an issue row = every finding of that CVE / configuration in this collection", "issue")
        { FromKey = k => new FindingMatch(Issue: k), Spec = CollectionViewSql.IssueKeys, Parameters = InCollection, AllMatching = true },
        ["assets"] = ByAsset("assets", "CI", CollectionViewSql.Assets),
        ["assetrisk"] = ByAsset("assetrisk", "CI", CollectionViewSql.AssetRisk),
        // the Correlation quality drill-down: one row per CI of the collection (its correlation evidence)
        ["correlation"] = ByAsset("correlation", "CI", CorrelationViewSql.Grid),
        ["serviceassets"] = ByAsset("serviceassets", "asset", CollectionViewSql.ServiceAssets, (c, s) => new Dictionary<string, object?> { ["CollectionId"] = c.CollectionId, ["Service"] = s.Get("svc") }),
        ["assetchanges"] = ByAsset("assetchanges", "CI", CollectionViewSql.AssetChanges, (c, s) => new Dictionary<string, object?> { ["A"] = s.Get("a"), ["B"] = c.CollectionId }, all: false),
        ["findingchanges"] = new("findingchanges", RowMapKind.FromKey, "a change = that finding in this collection (a finding no longer reported stands for none)", "change")
        {
            FromKey = k => k.Split('|') is { Length: 3 } p && (p[0].Length > 0 || p[1].Length > 0)
                ? new FindingMatch(AssetKey: p[0].Length > 0 ? p[0] : null, Issue: p[1].Length > 0 ? p[1] : null, Report: p[2].Length > 0 ? p[2] : null) : null,
        },
        ["services"] = new("services", RowMapKind.Service, "a service = every finding on its assets in this collection", "service")
        { Spec = CollectionViewSql.Services, Parameters = InCollection, AllMatching = true },
        // #360: the weighted risk page by CMDB service -- the criticality is the CMDB's (it moves), so "all matching" is
        // not rebuilt on the server: tick the rows
        ["svccrit"] = new("svccrit", RowMapKind.Service, "a service = every finding on its assets in this collection", "service") { AllMatching = false },
        ["assetsvc"] = ByAsset("assetsvc", "asset", WeightedServiceSql.ByAsset(false), all: false),
        ["svcassetw"] = ByAsset("svcassetw", "asset", WeightedServiceSql.ServiceAssets, (c, s) => new Dictionary<string, object?> { ["CollectionId"] = c.CollectionId, ["Service"] = s.Get("svc") }),
        ["assetsvcs"] = new("assetsvcs", RowMapKind.Service, "a service = every finding on its assets in this collection", "service") { AllMatching = false },
        ["exemptions"] = new("exemptions", RowMapKind.FromRow, "an exemption = the findings it covers in this collection (its asset, its issue, or both)", "exemption")
        {
            Spec = CollectionViewSql.Exemptions,
            Parameters = (c, _) => new Dictionary<string, object?> { ["At"] = DateTime.SpecifyKind(c.CollectionTime, DateTimeKind.Utc) },
            AllMatching = false,   // the page applies a default state filter the selection form does not carry
            FromRow = r => (S(r, "Scope") ?? "finding").ToLowerInvariant() switch
            {
                "asset" => S(r, "AssetKey") is { } a ? new FindingMatch(AssetKey: a) : null,
                "issue" => S(r, "Issue") is { } i ? new FindingMatch(Issue: i, Report: S(r, "ReportName")) : null,
                _ => S(r, "Issue") is { } i2 ? new FindingMatch(AssetKey: S(r, "AssetKey"), Issue: i2, Report: S(r, "ReportName")) : null,
            },
        },
        ["events"] = new("events", RowMapKind.FromRow, "a close-loop event = that CVE on that asset in this collection", "event")
        {
            Spec = CollectionViewSql.Events,
            Parameters = (_, _) => new Dictionary<string, object?> { ["From"] = Ever, ["To"] = Never },
            FromRow = r => S(r, "Cve") is { } cve ? new FindingMatch(Issue: cve, AssetName: S(r, "AssetName")) : null,
        },
        ["connectoritems"] = new("connectoritems", RowMapKind.FromRow, "a connector item = that CVE on that asset in this collection", "item")
        {
            Spec = CollectionViewSql.ConnectorItems,
            Parameters = (_, _) => new Dictionary<string, object?> { ["From"] = Ever, ["To"] = Never },
            FromRow = r => S(r, "Cve") is { } cve ? new FindingMatch(Issue: cve, AssetName: S(r, "AssetName")) : null,
        },
        // #812: the named views' groups (Risk rating, MITRE ATT&CK, Compliance, CVSS) -- a group opens its findings on Raw rows
        ["grprating"] = new("grprating", RowMapKind.None, "a group is a count of findings, not a finding: open it (its value) to act on its findings on Raw rows", "group"),
        ["grptactic"] = new("grptactic", RowMapKind.None, "a group is a count of findings, not a finding: open it (its value) to act on its findings on Raw rows", "group"),
        ["grptechnique"] = new("grptechnique", RowMapKind.None, "a group is a count of findings, not a finding: open it (its value) to act on its findings on Raw rows", "group"),
        ["grpcontrol"] = new("grpcontrol", RowMapKind.None, "a group is a count of findings, not a finding: open it (its value) to act on its findings on Raw rows", "group"),
        ["grpcvss"] = new("grpcvss", RowMapKind.None, "a group is a count of findings, not a finding: open it (its value) to act on its findings on Raw rows", "group"),
        ["connectorruns"] = new("connectorruns", RowMapKind.None,
            "a connector run is a run of the connector, not a finding: open the connector's items (\"Items\") to act on their findings", "run"),
        // the CI data views (Findings per CI, Findings summary) hold the newest finding collection: they act on it. "All
        // matching" is not rebuilt on the server there (their filters are the CI data's, not the collection's): tick the rows.
        ["cifindings"] = new("cifindings", RowMapKind.FromKey, "a CI finding row = that finding on that CI in the newest collection", "CI finding")
        { FromKey = CiFindingMatch, AllMatching = false },
        ["cisummary"] = new("cisummary", RowMapKind.CiGroup, "a summary row = that finding on every CI of its tier, severity and CMDB group in the newest collection", "finding group")
        { AllMatching = false },
    };

    /// <summary>
    /// A "Findings per CI" row key (<c>CiSql.FindingSpec</c>'s RowKey: "&lt;CI id&gt;|&lt;finding key&gt;", or
    /// "asset:&lt;asset id&gt;|&lt;finding key&gt;" for a finding on an asset no CI holds) as the finding it stands for: the
    /// collection keys an asset by its CI id, else by its own asset id. Null = not such a key.
    /// </summary>
    public static FindingMatch? CiFindingMatch(string key)
    {
        var i = key.IndexOf('|');
        if (i <= 0 || i >= key.Length - 1) return null;
        var owner = key[..i].Trim();
        if (owner.StartsWith("asset:", StringComparison.OrdinalIgnoreCase)) owner = owner[6..].Trim();
        var issue = key[(i + 1)..].Trim();
        return owner.Length == 0 || issue.Length == 0 ? null : new FindingMatch(AssetKey: owner, Issue: issue);
    }

    /// <summary>
    /// A "Findings summary" row key (<c>CiSql.SummarySpec</c>'s RowKey: "&lt;finding key&gt;|&lt;tier&gt;|&lt;severity&gt;|&lt;CMDB id&gt;",
    /// an empty part = none) as its parts; read from the right, so a finding key that holds a '|' stays whole. Null = not such a key.
    /// </summary>
    public static (string FindingKey, string Tier, string Severity, string CmdbId)? CiSummaryKey(string key)
    {
        var c = key.LastIndexOf('|');
        var b = c > 0 ? key.LastIndexOf('|', c - 1) : -1;
        var a = b > 0 ? key.LastIndexOf('|', b - 1) : -1;
        if (a <= 0) return null;
        var finding = key[..a].Trim();
        return finding.Length == 0 ? null : (finding, key[(a + 1)..b].Trim(), key[(b + 1)..c].Trim(), key[(c + 1)..].Trim());
    }

    /// The map of a grid (by its spec name; "department@3" -> "department"); null = undeclared.
    public static FindingRowMap? Of(string? grid)
    {
        if (string.IsNullOrWhiteSpace(grid)) return null;
        var name = grid.Split('@')[0];
        return All.TryGetValue(name, out var m) ? m : null;
    }
}
