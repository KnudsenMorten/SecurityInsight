using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Pages.Tiers;

/// <summary>
/// Where an "Unclassified" count or label leads: the tier board, filtered to the assets with no tier, where an Admin gives
/// one of them a tier (open its row and use "Pin to a tier" -- staged, reviewed and audited as every tier change). One
/// definition of Unclassified everywhere: the asset's tier is not 0..3 (<see cref="ProDataSql.TierExpr"/>), and a
/// finding's tier is its asset's tier.
/// </summary>
public static class TierLinks
{
    /// The tier board with its table filtered to one tier (that tier's tile is marked and scrolled to).
    public static string Lane(string tier) =>
        "/Tiers?tier=" + Uri.EscapeDataString(tier) + "#tier-" + Uri.EscapeDataString(tier);

    /// The tier board filtered to the assets with no tier.
    public static string Unclassified => Lane(ProDataFilters.Unclassified);

    /// One asset opened on the tier board, by its asset key (its panel: who decided the tier, every claim, and the pin form).
    public static string Asset(string assetKey) => "/Tiers?asset=" + Uri.EscapeDataString(assetKey) + "#" + IndexModel.PanelAnchor;

    /// The hover text of an Unclassified link.
    public const string Title = "Open the tier board at the assets with no tier, to give them one";

    /// The hover text of one Unclassified asset's link.
    public const string AssetTitle = "Open this asset on the tier board to give it a tier";

    public static bool IsUnclassified(string? tier) => string.IsNullOrEmpty(tier) || tier == ProDataFilters.Unclassified;

    /// "Tier N", or "Unclassified" as a link to the tier board filtered to the assets with no tier.
    public static IHtmlContent Label(string? tier) => IsUnclassified(tier)
        ? Link(Unclassified, Title)
        : new HtmlString(HtmlEncoder.Default.Encode("Tier " + tier));

    /// One asset's tier: "Tier N", or "Unclassified" as a link to that asset on the tier board (the filtered board when no key).
    public static IHtmlContent AssetLabel(string? tier, string? assetKey) => IsUnclassified(tier) && !string.IsNullOrWhiteSpace(assetKey)
        ? Link(Asset(assetKey), AssetTitle)
        : Label(tier);

    private static IHtmlContent Link(string href, string title) => new HtmlString(
        "<a class=\"tier-link\" href=\"" + HtmlEncoder.Default.Encode(href) + "\" title=\"" + HtmlEncoder.Default.Encode(title) + "\">Unclassified</a>");
}
