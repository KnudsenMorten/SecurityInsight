using System.Globalization;

namespace SI.Management.Web.Pages.Collection;

/// One factor of a side: its name and the points it added (null = an older collection that did not record each factor's points).
public sealed record ExplainFactor(string Name, double? Impact);

/// <summary>
/// One side of a risk score: its base (the risk index), the factors that counted and the side's score (base + their points).
/// <paramref name="Derived"/>: the row is from a collection made before each part was recorded -- the base is worked out as
/// the side's score minus its factors' points (<paramref name="Sum"/>) and the factors carry no points of their own.
/// </summary>
public sealed record ExplainSide(double? Base, bool Derived, IReadOnlyList<ExplainFactor> Factors, double? Sum, double? Score);

/// <summary>
/// #910 THE EXPLAINED RISK SCORE of one finding row (RiskExplainSql's grid): asset side (consequence) x vulnerability side
/// (probability) = risk score; x the weight = the weighted score. PURE over the row; the numbers come in invariant text from
/// the row document, and every text it writes uses the number format it is given (the viewer's on screen, invariant in a CSV).
/// </summary>
public sealed record RiskExplanation(ExplainSide Asset, ExplainSide Vulnerability, double? Score, double? WeightPct, string? WeightBy, double? Weighted)
{
    /// Either side worked out from an older collection.
    public bool Derived => Asset.Derived || Vulnerability.Derived;

    public static RiskExplanation Of(IReadOnlyDictionary<string, object?> row)
    {
        var asset = SideOf(Str(row, "AssetBase"), Str(row, "AssetFactors"), Str(row, "AssetFactorNames"), Str(row, "AssetFactorSum"), Str(row, "AssetSide"));
        var vuln = SideOf(Str(row, "VulnBase"), Str(row, "VulnFactors"), Str(row, "VulnFactorNames"), Str(row, "VulnFactorSum"), Str(row, "VulnSide"));
        var score = Num(Str(row, "RiskScore")) ?? (asset.Score is { } a && vuln.Score is { } v ? a * v : null);
        return new RiskExplanation(asset, vuln, score, Num(Str(row, "Weight")), Str(row, "WeightBy"), Num(Str(row, "RiskScoreWeighted")));
    }

    /// One side from its parts as the row document holds them.
    public static ExplainSide SideOf(string? baseText, string? impacts, string? names, string? sum, string? side)
    {
        var score = Num(side);
        if (Num(baseText) is { } b)
        {
            var factors = Split(impacts).Select(e =>
            {
                var i = e.LastIndexOf('=');
                return i > 0 ? new ExplainFactor(e[..i].Trim(), Num(e[(i + 1)..])) : new ExplainFactor(e, null);
            }).ToList();
            return new ExplainSide(b, false, factors, factors.Sum(f => f.Impact ?? 0), score);
        }
        // an older collection: the base is the side minus its factors' points, the factors by name only
        var s = Num(sum) ?? 0;
        return new ExplainSide(score is { } sc ? sc - s : null, true, Split(names).Select(n => new ExplainFactor(n, null)).ToList(), s, score);
    }

    // ---- the texts -----------------------------------------------------------------------------------------------------

    /// "4", or "4 (derived)" when worked out.
    public static string BaseText(ExplainSide s, Func<double, string> num) =>
        s.Base is { } b ? num(b) + (s.Derived ? " (derived)" : "") : "";

    /// "HighMachineRisk +3, InternetExposed +4" (an older collection: the names only).
    public static string FactorsText(ExplainSide s, Func<double, string> num) =>
        string.Join(", ", s.Factors.Select(f => f.Impact is { } i ? f.Name + " +" + num(i) : f.Name));

    /// "225 % (cmdbCriticality=Critical; cmdbDataSensitivity=confidential)".
    public string WeightText(Func<double, string> num) =>
        WeightPct is not { } w ? "" : num(w) + " %" + (Split(WeightBy).ToList() is { Count: > 0 } by ? " (" + string.Join("; ", by) + ")" : "");

    /// "(4 + HighMachineRisk 3 + InternetExposed 4) x (4 + RCE 4) = 11 x 8 = 88; x 225 % = 198" -- empty when a side is unknown.
    public string Formula(Func<double, string> num)
    {
        if (Asset.Score is not { } a || Vulnerability.Score is not { } v || Score is not { } score) return "";
        var text = SideFormula(Asset, num) + " x " + SideFormula(Vulnerability, num) + " = " + num(a) + " x " + num(v) + " = " + num(score);
        if (WeightPct is { } w && Weighted is { } wt) text += "; x " + num(w) + " % = " + num(wt);
        return text;
    }

    private static string SideFormula(ExplainSide s, Func<double, string> num)
    {
        var b = s.Base is { } x ? num(x) : "?";
        if (!s.Derived) return "(" + b + string.Concat(s.Factors.Select(f => " + " + f.Name + (f.Impact is { } i ? " " + num(i) : ""))) + ")";
        var names = s.Factors.Count > 0 ? " [" + string.Join(", ", s.Factors.Select(f => f.Name)) + "]" : "";
        return "(" + b + " (derived)" + (s.Sum is { } sum && (sum != 0 || s.Factors.Count > 0) ? " + " + num(sum) + names : "") + ")";
    }

    // ---- reading the row -----------------------------------------------------------------------------------------------

    private static string? Str(IReadOnlyDictionary<string, object?> row, string key) =>
        row.TryGetValue(key, out var v) && v is not null && Convert.ToString(v, CultureInfo.InvariantCulture) is { Length: > 0 } s ? s : null;

    /// A number written invariant ("4", "17.0", "225"); null when there is none.
    public static double? Num(string? s) =>
        s is not null && double.TryParse(s.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && double.IsFinite(d) ? d : null;

    private static IEnumerable<string> Split(string? list) =>
        (list ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
