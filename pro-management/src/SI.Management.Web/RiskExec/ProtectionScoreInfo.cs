using System.Globalization;
using SI.Management.Core.ProData;
using SI.Management.Web.Pages;

namespace SI.Management.Web.RiskExec;

/// <summary>
/// #1361 (owner 2026-11-25: "tier 0 must impact harder where tier 3 less" / "vulnerability must also be weighted" / "Yes, this
/// model"): the protection score's model as the install sets it -- each tier's share of the score
/// (SI_ProtectionScore_TierShares, Tier 0..3), the points an open fix costs an asset's health by severity
/// (SI_ProtectionScore_SeverityPoints) and the most Medium + Low may cost one asset (SI_ProtectionScore_MinorPointsCap). The
/// same settings, defaults and rules the engine computes with (engine/_shared/SI-ProtectionScore.ps1 Get-SIProtectionScoreSettings:
/// a missing or invalid value = the default). PURE.
/// </summary>
public sealed record ProtectionModel(IReadOnlyList<double> Shares, int VeryHigh, int High, int Medium, int Low, int MinorCap)
{
    public static readonly ProtectionModel Default = new([40, 30, 20, 10], 25, 10, 3, 1, 20);

    /// PURE. The model from the setting rows (each value as the engine parses it).
    public static ProtectionModel From(IReadOnlyList<SI.Management.Web.Settings.SettingRow> rows)
    {
        string? Val(string name) => rows.FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase))?.ValueJson?.Trim().Trim('"');
        var shares = Default.Shares;
        if (Val("SI_ProtectionScore_TierShares") is { Length: > 0 } s)
        {
            var parts = s.Split([',', ';', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            var vals = parts.Select(p => double.TryParse(p, NumberStyles.Float, CultureInfo.InvariantCulture, out var x) && x >= 0 ? x : double.NaN).ToList();
            if (parts.Length == 4 && vals.All(v => !double.IsNaN(v)) && vals.Sum() > 0) shares = vals;
        }
        var pts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase) { ["Very High"] = Default.VeryHigh, ["High"] = Default.High, ["Medium"] = Default.Medium, ["Low"] = Default.Low };
        if (Val("SI_ProtectionScore_SeverityPoints") is { Length: > 0 } p)
        {
            var set = new Dictionary<string, int>(pts, StringComparer.OrdinalIgnoreCase);
            var ok = true;
            foreach (var e in p.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var kv = e.Split('=', 2);
                if (kv.Length != 2 || !set.ContainsKey(kv[0].Trim()) || !int.TryParse(kv[1].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) || n is < 0 or > 100) { ok = false; break; }
                set[kv[0].Trim()] = n;
            }
            if (ok) pts = set;
        }
        var cap = int.TryParse(Val("SI_ProtectionScore_MinorPointsCap"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var c) && c is >= 0 and <= 100 ? c : Default.MinorCap;
        return new ProtectionModel(shares, pts["Very High"], pts["High"], pts["Medium"], pts["Low"], cap);
    }

    /// An asset's health: max(0, 100 - its Very High / High points - min(the cap, its Medium / Low points)).
    public double Health(int veryHigh, int high, int medium, int low) =>
        Math.Max(0, 100 - veryHigh * VeryHigh - high * High - Math.Min(MinorCap, medium * Medium + low * Low));

    /// The score from each tier's %: the tiers given (null = no assets) weighted by their shares, scaled to 100.
    public double? Score(IReadOnlyList<double?> tierPct)
    {
        double num = 0, den = 0;
        for (var i = 0; i < 4; i++) if (tierPct[i] is { } v) { num += Shares[i] * v; den += Shares[i]; }
        return den > 0 ? num / den : null;
    }
}

/// <summary>
/// #1360 (owner 2026-11-25: "can you include formula for protection score. people ask how it is calc. add to gui" -- "Info box on
/// score"; #1361: "show formula in gui so customers see how they impact it"): the text of the (i) beside every Protection Score
/// value (the Executive overview / report, the wall board). Every factor with the install's values: the points per open fix,
/// the Medium / Low cap, the tier shares, the scope, the two views with the grace per asset type, the age rule, the bands
/// (the embedded ProtectionBands copy) and an example computed from the install's values -- in the viewer's number format. PURE.
/// </summary>
public sealed record ProtectionScoreInfo(string Headline, string Title, IReadOnlyList<string> Formula, IReadOnlyList<string> Bullets, IReadOnlyList<string> Paragraphs, string? Note)
{
    public const string TitleText = "How the Protection Score is calculated";
    public const string HeadlineText = "Every fix raises the score; Tier 0 counts most.";

    /// Beside a value in a line of text (the protection score block's two lines) rather than in a tile's corner.
    public bool Inline { get; init; }

    private static CultureInfo C => ScoreFormat.Culture;
    private static string N(double v) => v.ToString("#,##0.##", C);
    private static string I(int v) => v.ToString(CultureInfo.InvariantCulture);
    private static string Days(int d) => I(d) + (d == 1 ? " day" : " days");

    /// PURE. The info text for the accepted lifecycle (grace, other grace) and the model in force. A settings store that could
    /// not be read shows the engine's defaults and says so.
    public static ProtectionScoreInfo For(AcceptedLifecycle life, ProtectionModel? model)
    {
        string? note = null;
        if (!life.Readable || life.Grace.Count != 4)
        {
            life = AcceptedLifecycle.From([]);
            model = ProtectionModel.Default;
            note = "The settings could not be read: the defaults are shown.";
        }
        var m = model ?? ProtectionModel.Default;
        int G(int i) => life.Grace[i].Days;
        var other = life.Other is { Count: 4 } o ? o : AcceptedLifecycle.From([]).Other!;
        string otherWords;
        if (other.Select(x => x.Days).Distinct().Count() == 1)
            otherWords = other[0].Days == 0 ? "count from day one" : "count after " + Days(other[0].Days);
        else
            otherWords = "count after " + other[0].Type + " " + Days(other[0].Days) + ", " + string.Join(", ", other.Skip(1).Select(x => x.Type + " " + I(x.Days)));

        var total = m.Shares.Sum();
        var sh = m.Shares.Select(s => s / total * 100).ToList();
        // the examples: one device (1 Very High, 2 High, 5 Medium; then the Very High fixed), and a score
        var before = m.Health(1, 2, 5, 0);
        var after = m.Health(0, 2, 5, 0);
        var minor = Math.Min(m.MinorCap, 5 * m.Medium);
        var score = m.Score([50, 90, 90, 90]) ?? 0;
        var bands = ProtectionBands.All;
        var bandWords = string.Join(", ", bands.Select((b, i) => b.Min <= 0 && i > 0 ? b.Name + " below " + N(bands[i - 1].Min) : b.Name + " " + N(b.Min) + "+"));

        return new ProtectionScoreInfo(HeadlineText, TitleText,
            [
                "Asset health = 100 - (" + I(m.VeryHigh) + " per open Very High fix, " + I(m.High) + " per High, " + I(m.Medium) + " per Medium, " + I(m.Low) + " per Low), never below 0. One fix = one recommended update however many CVEs it closes; other findings count one each.",
                "Medium and Low together cost at most " + I(m.MinorCap) + " points per asset.",
                "Tier % = average asset health in the tier.",
                "Score = Tier 0 x " + N(sh[0]) + " % + Tier 1 x " + N(sh[1]) + " % + Tier 2 x " + N(sh[2]) + " % + Tier 3 x " + N(sh[3]) + " % (whatever the number of assets; unclassified = Tier 3; an empty tier hands its share to the others).",
            ],
            [
                "Assets in scope: active devices, identities (groups left out), cloud resources, public IPs. Inactive assets do not count.",
                "Actual Risks: every open fix counts.",
                "Within Accepted Lifecycle: a patch finding (one with a vendor fix) younger than its grace (devices " + Days(G(0)) + ", identities " + I(G(1))
                    + ", cloud resources " + I(G(2)) + ", public IPs " + I(G(3)) + ") does not count. Other findings (configuration, identity, Azure, attack paths) "
                    + otherWords + " (their own grace, default 0). Age = fix release date, else source first-seen, else SI's first detection; a finding with no date always counts.",
                "Assets in good standing: no open Very High / High fix.",
            ],
            [
                "Example: a device with 1 Very High, 2 High and 5 Medium fixes = 100 - " + I(m.VeryHigh) + " - " + I(2 * m.High) + " - " + I(minor) + " = " + N(before)
                    + "; fix the Very High = " + N(after) + ".",
                "Tier 0 at 50 %, Tiers 1-3 at 90 % = " + N(sh[0] / 100) + "x50 + " + N(sh[1] / 100) + "x90 + " + N(sh[2] / 100) + "x90 + " + N(sh[3] / 100) + "x90 = " + score.ToString("N1", C) + ".",
                "Bands: " + bandWords + ".",
            ],
            note);
    }
}
