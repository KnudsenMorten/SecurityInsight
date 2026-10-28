using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Changes;

/// <summary>
/// #696: the customer's risk rating thresholds (Admin &gt; Settings &gt; Risk rating) -- pure, no I/O. The rating
/// (Critical / High / Moderate / Low, si_risk_rating) is for management and keeps its four words; what a band MEANS differs
/// per customer, so the three thresholds are the customer's. They are the data-model list 'lists:risk_rating_bands'
/// (shipped 50 / 30 / 15 in data-model/lists.locked.json); a change is that list's cfg.ItemOverride body, staged on Review
/// &amp; commit like every other data-model override and validated by <see cref="RiskRatingBands.Problems"/> before it is
/// staged and again when it is committed (<see cref="DataModelItemValidator"/>). The engine reads the override on its next
/// Risk Analysis run (Get-RARiskRatingBands); nothing is re-scored here.
/// </summary>
public static class RiskRatingThresholds
{
    public const string Description = "The risk rating bands of the risk score (asset side x vulnerability side): a finding scoring at least the first value is Critical, at least the second High, at least the third Moderate, below that Low. Three whole numbers, highest first.";
    /// The four ratings, highest first, and the "not scored yet" value of the facet.
    public static readonly string[] Ratings = ["Critical", "High", "Moderate", "Low"];
    public const string None = "(none)";

    /// The three posted numbers as bands: whole numbers (an optional sign and digits, read the same in every region),
    /// above 0, highest first. Null + the reasons when they are not.
    public static (RiskRatingBands? Bands, IReadOnlyList<string> Problems) Parse(string? critical, string? high, string? moderate)
    {
        var why = new List<string>();
        int? One(string label, string? text)
        {
            var t = (text ?? "").Trim();
            if (t.Length == 0) { why.Add($"{label}: enter a whole number"); return null; }
            if (!int.TryParse(t, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n)) { why.Add($"{label}: '{Short(t)}' is not a whole number"); return null; }
            if (n <= 0) { why.Add($"{label}: the threshold must be above 0"); return null; }
            return n;
        }
        var c = One("Critical", critical);
        var h = One("High", high);
        var m = One("Moderate", moderate);
        if (c is null || h is null || m is null) return (null, why);
        if (!(c > h && h > m)) why.Add("the thresholds must be highest first: Critical above High, High above Moderate");
        return why.Count > 0 ? (null, why) : (new RiskRatingBands(c.Value, h.Value, m.Value), Array.Empty<string>());
    }

    private static string Short(string s) => s.Length > 20 ? s[..20] + "..." : s;

    /// The override body with these bands: the list in force (or the shipped one) with only its 'values' replaced -- its id,
    /// type, description and labels are kept; a list SecurityInsight does not ship is created as a values list. Validated
    /// with <see cref="RiskRatingBands.Problems"/> before it is returned: null + the reasons when it would be refused.
    public static (string? Body, IReadOnlyList<string> Problems) WithBands(string? listJson, RiskRatingBands bands)
    {
        JsonObject o;
        try { o = (string.IsNullOrWhiteSpace(listJson) ? null : JsonNode.Parse(listJson) as JsonObject) ?? new JsonObject(); }
        catch (JsonException) { o = new JsonObject(); }
        o["id"] = RiskRatingBands.ListId;
        o["type"] = "values";
        if (o["description"] is null) o["description"] = Description;
        o.Remove("entries");
        o["values"] = new JsonArray((int)bands.Critical, (int)bands.High, (int)bands.Moderate);
        if (o["labels"] is null) o["labels"] = new JsonArray("Critical", "High", "Moderate");
        var body = o.ToJsonString();
        using var d = JsonDocument.Parse(body);
        var why = RiskRatingBands.Problems(d.RootElement);
        return why.Count > 0 ? (null, why) : (body, Array.Empty<string>());
    }

    /// The shipped bands: the template row's (cfg.Template, the release), else the built-in default (= the engine's).
    public static RiskRatingBands Shipped(DataModelRow? row) => RiskRatingBands.FromList(row?.TemplateBody) ?? RiskRatingBands.Default;

    /// The bands in force: the override when there is a valid one, else the shipped list, else the built-in default --
    /// exactly what the next Risk Analysis run scores with (<see cref="RiskFactorStore.Bands"/>).
    public static RiskRatingBands InForce(DataModelRow? row) => RiskRatingBands.FromList(row?.Effective) ?? RiskRatingBands.Default;

    /// "50 / 30 / 15" -- the thresholds in the region's number format.
    public static string Text(RiskRatingBands b) => Pages.Fmt.Num(b.Critical, 0) + " / " + Pages.Fmt.Num(b.High, 0) + " / " + Pages.Fmt.Num(b.Moderate, 0);

    /// How many findings of a collection fall in each rating with these bands, from the collection's precomputed score
    /// distribution (sidata.FindingFacet, facet 'score': the risk score rounded to one decimal, with its finding count) --
    /// the same SQL rows the Collection pages read; no engine run, no finding read one by one. Findings without a score
    /// count under "(none)".
    public static IReadOnlyDictionary<string, long> Preview(IEnumerable<FacetRow> facets, RiskRatingBands bands)
    {
        var counts = Ratings.Append(None).ToDictionary(r => r, _ => 0L, StringComparer.Ordinal);
        foreach (var f in facets.Where(f => f.Facet == Facets.Score))
        {
            if (double.TryParse(f.Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var score)) counts[bands.Rate(score)] += f.Findings;
            else counts[None] += f.Findings;
        }
        return counts;
    }

    /// How many findings carry each rating now (the stored si_risk_rating, facet 'rating') -- scored by the last run.
    public static IReadOnlyDictionary<string, long> Now(IEnumerable<FacetRow> facets)
    {
        var counts = Ratings.Append(None).ToDictionary(r => r, _ => 0L, StringComparer.Ordinal);
        foreach (var f in facets.Where(f => f.Facet == Facets.Rating))
        {
            var key = Ratings.FirstOrDefault(r => string.Equals(r, f.Value, StringComparison.OrdinalIgnoreCase)) ?? None;
            counts[key] += f.Findings;
        }
        return counts;
    }
}
