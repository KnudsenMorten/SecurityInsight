using SI.Management.Core;
using SI.Management.Core.ProData;
using SI.Management.Web.Columns;

namespace SI.Management.Web.Pages.Management;

/// <summary>
/// #589: the management drill-downs' asset lists as THE data table -- the Risk Analysis run's ranking and numbers as the
/// mail has them, then each asset's CI: its id, identifier values, linked objects, owner, department, OS, IP, subscription,
/// CMDB and last seen (owner 2026-10-11: "enable all relevant columns per view").
/// </summary>
public static class ExecTables
{
    /// The mail's top risky assets; <paramref name="keys"/> maps an asset id (lower case) to its CI key.
    public static DataTable TopAssets(IReadOnlyList<ExecTopAsset> assets, IReadOnlyDictionary<string, string> keys, Func<ExecTopAsset, string> link,
        string id, string view, string title, RowCiKey ci = RowCiKey.AssetKey)
    {
        static ExecTopAsset A(object o) => (ExecTopAsset)o;
        string? Key(ExecTopAsset a) => a.AssetId is { } i && keys.TryGetValue(i.ToLowerInvariant(), out var k) ? k : null;
        return new DataTable
        {
            // #863: a list built from the database names each CI by its CI id (RowCiKey.CiId), the run's list by its asset key
            Id = id, View = view, Title = title, Rows = assets.Cast<object>().ToList(), Marker = "data-exec-top-table",
            Ci = ci, RefOf = o => new RowRef(Key(A(o)) ?? A(o).AssetId),
            RowAttributes = o => new Dictionary<string, string?> { ["data-asset"] = A(o).Asset },
            Columns =
            [
                new("Rank", "#", o => A(o).Rank, Number: true),
                new("AssetName", "Asset", o => A(o).Asset, Link: o => link(A(o))),
                new("AssetKey", "Asset (CI) key", o => Key(A(o)) ?? A(o).AssetId),
                new("Tier", "Tier", o => A(o).Tier),
                new("WeightedRiskScore", "Weighted Risk Score", o => A(o).WeightedRiskScore, Number: true, Text: o => Fmt.Int((long)Math.Round(A(o).WeightedRiskScore))),
                new("TotalRiskScore", "Total Risk Score", o => A(o).TotalRiskScore, Number: true, Text: o => Fmt.Int((long)Math.Round(A(o).TotalRiskScore))),
                new("Findings", "Findings", o => A(o).Findings, Number: true),
                new("Domains", "Domains", o => string.Join(", ", A(o).Domains)),
                new("TopItems", "Top items in the report", o => string.Join("; ", A(o).TopItems)),
            ],
        };
    }

    /// Every tier-0 asset with findings, by estate rank.
    public static DataTable Tier0(IReadOnlyList<TopRisk> risks, Func<TopRisk, bool> inTop, int topN)
    {
        static TopRisk R(object o) => (TopRisk)o;
        return new DataTable
        {
            Id = "tier0", View = "management-tier0", Title = "Tier-0 assets", Rows = risks.Cast<object>().ToList(), Marker = "data-tier0-list",
            Ci = RowCiKey.AssetKey, RefOf = o => new RowRef(R(o).AssetId),
            RowAttributes = o => new Dictionary<string, string?> { ["data-in-top"] = inTop(R(o)) ? "1" : "0" },
            Columns =
            [
                new("Rank", "Estate rank", o => R(o).Rank, Number: true, Description: "The asset's place among ALL the estate's assets (1 = riskiest)"),
                new("InTop", "Top " + topN, o => inTop(R(o)) ? "yes" : "no"),
                new("AssetName", "Asset", o => R(o).AssetName, Link: o => "/Collection/Asset?key=" + Uri.EscapeDataString(R(o).AssetId)),
                new("AssetKey", "Asset (CI) key", o => R(o).AssetId),
                new("Tier", "Tier", o => R(o).Tier),
                new("WeightedRiskScore", "Weighted risk", o => R(o).WeightedRiskScore, Number: true, Text: o => Fmt.Score(R(o).WeightedRiskScore)),
                new("Findings", "Findings", o => R(o).Findings, Number: true),
                new("Domains", "Domains", o => string.Join(", ", R(o).Domains)),
            ],
        };
    }
}
