using SI.Management.Core.ProData;
using SI.Management.Web.Pages;

namespace SI.Management.Web.Outputs;

/// The CIs of one (class, asset type, OS family, tier) -- <see cref="ServiceNowRowCount.CiGroupsAsync"/>.
public sealed record CiGroup(string? Class, string? AssetType, string? OsFamily, int? Tier, long N)
{
    public IReadOnlyDictionary<string, string?> Values => new Dictionary<string, string?>(StringComparer.Ordinal)
    {
        ["si_asset_type"] = AssetType, ["si_os_family"] = OsFamily, ["si_class"] = Class,
    };

    public string? ValueOf(string field) => field switch { "si_asset_type" => AssetType, "si_os_family" => OsFamily, "si_class" => Class, _ => null };
}

/// One choice of a CI rule field with its counts: how many CIs hold it, and how many of those the scope would send.
public sealed record CiChoice(string Value, long Cis, long Sent, bool InCatalog);

/// One field of the CI rules with every choice it offers.
public sealed record CiChoiceField(string Field, string Label, IReadOnlyList<CiChoice> Choices);

/// <summary>
/// #1055 "N CIs WOULD BE SENT, M LEFT OUT BY THE FILTER" (owner 2026-11-02: "add all the filter options on the snow
/// connector ... also show the per-category counts"): the ServiceNow CI output's scope (as in force, or as the page posted
/// it) over the CIs per category -- the same rule the engine applies (Test-SIDataOutInScope -Grain ci: the output's own class
/// filter, the tier, the asset kind, the include / exclude rules). Pure: the groups come from one aggregate query.
/// </summary>
public static class CiScopePreview
{
    public sealed record Result(long Total, long Sent, long LeftOutByRules, long LeftOutOther, IReadOnlyList<(string Rule, long N)> PerRule,
        IReadOnlyList<CiChoiceField> Fields, string? MapFilterNote)
    {
        /// "6,120 CIs would be sent, 1,522 left out by the filter (leave out asset type Mobile: 1,211; ...)".
        public string Words
        {
            get
            {
                var s = $"{Fmt.Int(Sent)} of {Fmt.Int(Total)} CI(s) would be sent";
                if (LeftOutByRules > 0)
                    s += $", {Fmt.Int(LeftOutByRules)} left out by the filter" + (PerRule.Count > 0 ? " (" + string.Join("; ", PerRule.Select(p => p.Rule + ": " + Fmt.Int(p.N))) + ")" : "");
                if (LeftOutOther > 0) s += $", {Fmt.Int(LeftOutOther)} left out by the tier, asset kind or the output's class filter";
                return s + (MapFilterNote is null ? "" : " -- " + MapFilterNote);
            }
        }
    }

    /// <paramref name="classes"/>: the output's own class filter (null = none); <paramref name="countable"/> false = that
    /// filter names another field (the export applies it; not counted here). <paramref name="catalog"/>: per CI field the
    /// values the classification catalog offers, in its order.
    public static Result Of(OutputScope scope, IReadOnlyList<CiGroup> groups, IReadOnlyList<string>? classes, bool countable,
        IReadOnlyDictionary<string, IReadOnlyList<string>> catalog)
    {
        bool MapPasses(CiGroup g) => !countable || classes is null || classes.Contains(g.Class ?? "", StringComparer.OrdinalIgnoreCase);
        bool BasePasses(CiGroup g) => MapPasses(g) && scope.PassesAsset(g.Tier, CiRules.KindOf(g.Class));
        bool Sent(CiGroup g) => BasePasses(g) && scope.PassesCiRules(g.Values);
        long total = 0, sent = 0, byRules = 0, other = 0;
        foreach (var g in groups)
        {
            total += g.N;
            if (!BasePasses(g)) other += g.N;
            else if (!scope.PassesCiRules(g.Values)) byRules += g.N;
            else sent += g.N;
        }
        var perRule = new List<(string, long)>();
        if (scope.CiInclude.Count > 0)
            perRule.Add(("not in " + string.Join(" or ", scope.CiInclude.Select(r => r.Describe())), groups.Where(g => BasePasses(g) && !scope.CiInclude.Any(r => r.Matches(g.Values))).Sum(g => g.N)));
        foreach (var r in scope.CiExclude)
            perRule.Add(("leave out " + r.Describe(), groups.Where(g => BasePasses(g) && r.Matches(g.Values)).Sum(g => g.N)));
        var fields = CiRules.Fields.Select(f =>
        {
            var offered = (catalog.TryGetValue(f.Field, out var c) && c.Count > 0 ? c : f.Values).ToList();
            var inData = groups.Select(g => g.ValueOf(f.Field)).Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v!.Trim())
                .Where(v => !offered.Contains(v, StringComparer.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(v => v, StringComparer.OrdinalIgnoreCase);
            var choices = offered.Select(v => (v, true)).Concat(inData.Select(v => (v, false))).Select(p =>
            {
                var mine = groups.Where(g => string.Equals((g.ValueOf(f.Field) ?? "").Trim(), p.v, StringComparison.OrdinalIgnoreCase)).ToList();
                return new CiChoice(p.v, mine.Sum(g => g.N), mine.Where(Sent).Sum(g => g.N), p.Item2);
            }).ToList();
            return new CiChoiceField(f.Field, f.Label, choices);
        }).ToList();
        return new Result(total, sent, byRules, other, perRule, fields, countable ? null : "the output's own filter names another field: the export applies it, this count does not");
    }
}
