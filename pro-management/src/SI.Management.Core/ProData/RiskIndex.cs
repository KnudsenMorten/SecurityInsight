using System.Globalization;
using System.Text;

namespace SI.Management.Core.ProData;

/// <summary>
/// One row of the risk-score index (riskscore.index.locked.csv), keyed by the SI generic fields (REQUIREMENTS #559).
/// Matchers: si_finding_type, si_category, si_subcategory, si_component, si_finding_key, asset_class (blank = any);
/// si_severity is a matcher of the VULNERABILITY base only, si_tier of the ASSET base only. A blank base = "this row does
/// not set that base". Precedence = the row's place (1 = checked first).
/// A row stored with the 2.2 columns is translated on read (<see cref="RiskIndexV22"/>), every base value carried over.
/// </summary>
public sealed record RiskIndexRow
{
    public string FindingType { get; init; } = "";
    public string Category { get; init; } = "";
    public string SubCategory { get; init; } = "";
    public string Component { get; init; } = "";
    public string FindingKey { get; init; } = "";
    public string AssetClass { get; init; } = "";
    public string Severity { get; init; } = "";
    public string VulnerabilityBase { get; init; } = "";
    public string Tier { get; init; } = "";
    public string AssetBase { get; init; } = "";
    public string Comments { get; init; } = "";
    public string Precedence { get; init; } = "";

    /// The value of one column by its CSV name ("" for an unknown one).
    public string Get(string column) => column switch
    {
        RiskIndexColumns.FindingType => FindingType,
        RiskIndexColumns.Category => Category,
        RiskIndexColumns.SubCategory => SubCategory,
        RiskIndexColumns.Component => Component,
        RiskIndexColumns.FindingKey => FindingKey,
        RiskIndexColumns.AssetClass => AssetClass,
        RiskIndexColumns.Severity => Severity,
        RiskIndexColumns.VulnerabilityBase => VulnerabilityBase,
        RiskIndexColumns.Tier => Tier,
        RiskIndexColumns.AssetBase => AssetBase,
        RiskIndexColumns.Comments => Comments,
        RiskIndexColumns.Precedence => Precedence,
        _ => "",
    };

    public RiskIndexRow With(string column, string? value)
    {
        var v = value ?? "";
        return column switch
        {
            RiskIndexColumns.FindingType => this with { FindingType = v },
            RiskIndexColumns.Category => this with { Category = v },
            RiskIndexColumns.SubCategory => this with { SubCategory = v },
            RiskIndexColumns.Component => this with { Component = v },
            RiskIndexColumns.FindingKey => this with { FindingKey = v },
            RiskIndexColumns.AssetClass => this with { AssetClass = v },
            RiskIndexColumns.Severity => this with { Severity = v },
            RiskIndexColumns.VulnerabilityBase => this with { VulnerabilityBase = v },
            RiskIndexColumns.Tier => this with { Tier = v },
            RiskIndexColumns.AssetBase => this with { AssetBase = v },
            RiskIndexColumns.Comments => this with { Comments = v },
            RiskIndexColumns.Precedence => this with { Precedence = v },
            _ => this,
        };
    }

    /// Same content, ignoring Precedence (what a row DOES, apart from its place).
    public bool SameContent(RiskIndexRow o) =>
        RiskIndexColumns.Content.All(c => string.Equals(Get(c), o.Get(c), StringComparison.Ordinal));
}

/// The CSV column names of the SI-keyed index -- exactly the engine's (SI-ProConfig.ps1 $SIRiskIndexColumns, RA-RiskIndexSi.ps1).
public static class RiskIndexColumns
{
    public const string FindingType = "si_finding_type";
    public const string Category = "si_category";
    public const string SubCategory = "si_subcategory";
    public const string Component = "si_component";
    public const string FindingKey = "si_finding_key";
    public const string AssetClass = "asset_class";
    public const string Severity = "si_severity";
    public const string VulnerabilityBase = "VulnerabilityBase";
    public const string Tier = "si_tier";
    public const string AssetBase = "AssetBase";
    public const string Comments = "Comments";
    public const string Precedence = "Precedence";

    /// The file's columns, in order.
    public static readonly string[] All = { FindingType, Category, SubCategory, Component, FindingKey, AssetClass, Severity, VulnerabilityBase, Tier, AssetBase, Comments, Precedence };
    /// Everything but Precedence.
    public static readonly string[] Content = All.Where(c => c != Precedence).ToArray();
    /// The eight columns the item key is made of (Get-SIRiskIndexKey).
    public static readonly string[] Key = { FindingType, Category, SubCategory, Component, FindingKey, AssetClass, Severity, Tier };
    /// The six matchers both bases use.
    public static readonly string[] SharedMatchers = { FindingType, Category, SubCategory, Component, FindingKey, AssetClass };
    public static readonly string[] Bases = { AssetBase, VulnerabilityBase };

    /// Spellings accepted on import, mapped to the column (case-insensitive). The export always writes <see cref="All"/>.
    public static readonly IReadOnlyDictionary<string, string> Aliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        [FindingType] = FindingType, ["FindingType"] = FindingType,
        [Category] = Category,
        [SubCategory] = SubCategory,
        [Component] = Component, ["Component"] = Component,
        [FindingKey] = FindingKey, ["FindingKey"] = FindingKey,
        [AssetClass] = AssetClass, ["AssetClass"] = AssetClass,
        [Severity] = Severity,
        [VulnerabilityBase] = VulnerabilityBase,
        [Tier] = Tier,
        [AssetBase] = AssetBase,
        ["Comments"] = Comments, ["Comment"] = Comments,
        ["Precedence"] = Precedence,
    };

    /// Plain names for the page.
    public static string Label(string column) => column switch
    {
        FindingType => "Finding type",
        Category => "Category",
        SubCategory => "Subcategory",
        Component => "Component",
        FindingKey => "Finding key",
        AssetClass => "Asset class",
        Severity => "Severity",
        VulnerabilityBase => "Vulnerability base",
        Tier => "Tier",
        AssetBase => "Asset base",
        Comments => "Comments",
        Precedence => "Order",
        _ => column,
    };
}

/// The vocabularies the matchers are compared with (case-insensitive): SI's finding severities (with v2.2's Medium-High
/// band kept as medium_high so its own base survives), the tiers 0-3, and the asset classes the index keys on.
public static class RiskIndexVocabulary
{
    public static readonly IReadOnlyList<string> Severities = new[] { "critical", "high", "medium_high", "medium", "low", "info" };
    public static readonly IReadOnlyList<string> Tiers = new[] { "0", "1", "2", "3" };
    public static readonly IReadOnlyList<string> AssetClasses = new[] { "device_server", "device_client", "device", "identity", "cloud_resource", "public_ip" };
    /// The allowed base range (inclusive). The engine reads any number; the shipped index uses 1..5.
    public const double MinScore = 0, MaxScore = 10;
}

/// One finding's values the index is matched on (the SI generic fields; Tier "0".."3", blank = unknown).
public sealed record RiskIndexFinding(string? FindingType, string? Category, string? SubCategory, string? Component, string? FindingKey, string? AssetClass, string? Severity, string? Tier);

/// The two bases: Asset (keyed by tier) and Vulnerability (keyed by severity).
public enum RiskIndexScoreKind { Vulnerability, Asset }

/// The base of one lookup and the 1-based row (in precedence order) that set it (0 = none matched).
public readonly record struct RiskIndexHit(double Score, int Row);

/// One rule of a lookup: the seven matchers (six shared + tier or severity, lower-cased; null = any) and the base.
public sealed record RiskIndexRule(string?[] Matchers, double Score, int Position);

/// <summary>
/// THE risk index rule in C# -- a 1:1 mirror of engine\risk-analysis\_shared\RA-RiskIndexSi.ps1 (New-SIRiskIndexSiRules /
/// Find-SIRiskIndexSiRule). FIRST MATCH WINS in Precedence order, per base: the asset base is the AssetBase of the first row
/// with one whose filled matchers among the six shared matchers and si_tier all equal the finding's values (case-insensitive);
/// the vulnerability base likewise with VulnerabilityBase and si_severity. asset_class 'device' is the family of
/// device_server / device_client (a 'device' row fits both). None -> 0.
/// RiskScoreTotal = (AssetBase + asset factor impacts) x (VulnerabilityBase + vulnerability factor impacts) -- no cap.
/// </summary>
public static class RiskIndexScoring
{
    private static bool Blank(string? s) => string.IsNullOrWhiteSpace(s);

    /// A number the way the engine parses it: invariant, anything else -> 0.
    public static double Number(string? s) =>
        double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : 0.0;

    public static bool IsNumber(string? s) => !Blank(s) && double.TryParse(s!.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out _);

    public static string ScoreColumn(RiskIndexScoreKind kind) => kind == RiskIndexScoreKind.Asset ? RiskIndexColumns.AssetBase : RiskIndexColumns.VulnerabilityBase;
    /// The seventh matcher of a kind: si_tier (asset) or si_severity (vulnerability).
    public static string KindMatcher(RiskIndexScoreKind kind) => kind == RiskIndexScoreKind.Asset ? RiskIndexColumns.Tier : RiskIndexColumns.Severity;
    /// The seven matcher columns of a kind, in the engine's order.
    public static string[] Matchers(RiskIndexScoreKind kind) => RiskIndexColumns.SharedMatchers.Append(KindMatcher(kind)).ToArray();

    private static string?[] FindingValues(RiskIndexFinding f, RiskIndexScoreKind kind) => new[]
    {
        f.FindingType, f.Category, f.SubCategory, f.Component, f.FindingKey, f.AssetClass, kind == RiskIndexScoreKind.Asset ? f.Tier : f.Severity,
    }.Select(v => Blank(v) ? null : v!.Trim().ToLowerInvariant()).ToArray();

    /// True when the rows carry an order; a file without a Precedence column keeps its file order.
    public static bool HasOrder(IReadOnlyList<RiskIndexRow> rows) => rows.Any(r => !Blank(r.Precedence));

    /// The rows in the order first-match walks them: stably sorted by Precedence, a row without one after the numbered rows.
    public static IReadOnlyList<RiskIndexRow> Ordered(IReadOnlyList<RiskIndexRow> rows) =>
        rows.Select((r, i) => (r, i, p: IsNumber(r.Precedence) ? Number(r.Precedence.Trim()) : double.MaxValue))
            .OrderBy(x => x.p).ThenBy(x => x.i).Select(x => x.r).ToList();

    public sealed record Rules(IReadOnlyList<RiskIndexRule> Vulnerability, IReadOnlyList<RiskIndexRule> Asset);

    /// Ordered rows -> the two rule lists (a row without a base of a kind is not a rule of it).
    public static Rules BuildRules(IReadOnlyList<RiskIndexRow> ordered)
    {
        List<RiskIndexRule> Of(RiskIndexScoreKind kind)
        {
            var list = new List<RiskIndexRule>();
            var cols = Matchers(kind);
            for (var i = 0; i < ordered.Count; i++)
            {
                var r = ordered[i];
                var s = r.Get(ScoreColumn(kind));
                if (Blank(s)) continue;
                var m = cols.Select(c => { var v = r.Get(c).Trim(); return v.Length == 0 ? null : v.ToLowerInvariant(); }).ToArray();
                list.Add(new RiskIndexRule(m, Number(s.Trim()), i + 1));
            }
            return list;
        }
        return new Rules(Of(RiskIndexScoreKind.Vulnerability), Of(RiskIndexScoreKind.Asset));
    }

    /// The family of an asset class: device_server / device_client -> device; anything else none.
    public static string? Family(string? assetClass) =>
        assetClass is { } a && a.StartsWith("device_", StringComparison.OrdinalIgnoreCase) ? "device" : null;

    public static RiskIndexHit Find(IReadOnlyList<RiskIndexRule> rules, RiskIndexFinding f, RiskIndexScoreKind kind)
    {
        var lv = FindingValues(f, kind);
        var fam = Family(lv[5]);
        foreach (var rule in rules)
        {
            var fit = true;
            for (var i = 0; i < 7; i++)
            {
                if (rule.Matchers[i] is not { } m) continue;
                if (string.Equals(m, lv[i], StringComparison.Ordinal)) continue;
                if (i == 5 && fam is not null && m == fam) continue;
                fit = false; break;
            }
            if (fit) return new RiskIndexHit(rule.Score, rule.Position);
        }
        return new RiskIndexHit(0.0, 0);
    }

    public static (RiskIndexHit Asset, RiskIndexHit Vulnerability) Score(Rules rules, RiskIndexFinding f) =>
        (Find(rules.Asset, f, RiskIndexScoreKind.Asset), Find(rules.Vulnerability, f, RiskIndexScoreKind.Vulnerability));

    /// The scoring contract (RA-RiskScore.ps1 _setScores, #559): (AssetBase + asset impacts) x (VulnerabilityBase + vulnerability impacts).
    public static double Total(double assetBase, double assetImpacts, double vulnerabilityBase, double vulnerabilityImpacts) =>
        (assetBase + assetImpacts) * (vulnerabilityBase + vulnerabilityImpacts);

    /// RiskRating, banded on RiskScoreTotal exactly as Get-SIRiskRating bands it (#559): by the data-model list
    /// risk_rating_bands (the customer's override included), else the engine's built-in 50 / 30 / 15.
    public static string Rating(double total, RiskRatingBands? bands = null) => (bands ?? RiskRatingBands.Default).Rate(total);
}

/// <summary>
/// The risk rating bands -- the data-model list risk_rating_bands: a values list of three NUMBERS, highest first
/// (Critical, High, Moderate thresholds; below = Low). The C# twin of ConvertTo-RARiskRatingBands (RA-FactorKeys.ps1) and
/// Test-SIRiskRatingBands (SI-RiskFactorCatalog.ps1): a list that is not three whole numbers above 0, strictly descending,
/// is not used -- the engine then falls back to its built-in 50 / 30 / 15 (Get-RARiskRatingBands; the values
/// data-model/lists.locked.json ships), and so does this. The thresholds are the CUSTOMER'S: Admin &gt; Settings &gt; Risk
/// rating stages the list's override (#696); a guard test holds this default, the engine's and the shipped list equal.
/// </summary>
public sealed record RiskRatingBands(double Critical, double High, double Moderate)
{
    public const string ListId = "risk_rating_bands";
    public const string ItemKey = "lists:" + ListId;
    public static readonly RiskRatingBands Default = new(50, 30, 15);

    public string Rate(double total) => total >= Critical ? "Critical" : total >= High ? "High" : total >= Moderate ? "Moderate" : "Low";

    /// The numbers of a list's 'values' (a number or a numeric string each); null when one is not a number.
    private static List<double>? Numbers(System.Text.Json.JsonElement list)
    {
        if (list.ValueKind != System.Text.Json.JsonValueKind.Object || !list.TryGetProperty("values", out var v) || v.ValueKind != System.Text.Json.JsonValueKind.Array) return null;
        var n = new List<double>();
        foreach (var x in v.EnumerateArray())
        {
            if (x.ValueKind == System.Text.Json.JsonValueKind.Number && x.TryGetDouble(out var d)) n.Add(d);
            else if (x.ValueKind == System.Text.Json.JsonValueKind.String && double.TryParse(x.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var s)) n.Add(s);
            else return null;
        }
        return n;
    }

    /// The bands of a list body (the effective risk_rating_bands item); null when missing or not valid.
    public static RiskRatingBands? FromList(string? listJson)
    {
        if (string.IsNullOrWhiteSpace(listJson)) return null;
        try
        {
            using var d = System.Text.Json.JsonDocument.Parse(listJson);
            var n = Numbers(d.RootElement);
            if (n is null || n.Count != 3 || n[2] <= 0 || n[0] <= n[1] || n[1] <= n[2]) return null;
            return new RiskRatingBands(n[0], n[1], n[2]);
        }
        catch (System.Text.Json.JsonException) { return null; }
    }

    /// Test-SIRiskRatingBands: type values, exactly three whole numbers above 0, highest first.
    public static IReadOnlyList<string> Problems(System.Text.Json.JsonElement list)
    {
        var why = new List<string>();
        var type = list.TryGetProperty("type", out var t) && t.ValueKind == System.Text.Json.JsonValueKind.String ? t.GetString() : null;
        if (type != "values") why.Add($"risk_rating_bands: type '{type}' -- it is a values list of three numbers");
        var n = Numbers(list);
        var ok = n is { Count: 3 } && n.All(x => x > 0 && x == Math.Floor(x)) && n[0] > n[1] && n[1] > n[2];
        if (!ok) why.Add("risk_rating_bands: the values must be three whole numbers above 0, highest first (Critical, High, Moderate)");
        return why;
    }
}

/// <summary>
/// The risk index CSV, both ways. Reads the SI-keyed file, and a file written with the 2.2 columns -- put in first-match
/// form when it has no Precedence column, then translated row for row (<see cref="RiskIndexV22"/>). Writes the SI columns
/// plus Precedence. RFC 4180 quoting.
/// </summary>
public static class RiskIndexCsv
{
    /// Rows (SI-keyed); HasPrecedenceColumn = the rows carry their order (always true for a translated 2.2 file); FromV22 =
    /// the file was written with the 2.2 columns and was translated.
    public sealed record ParseResult(IReadOnlyList<RiskIndexRow> Rows, bool HasPrecedenceColumn, IReadOnlyList<string> Problems, IReadOnlyList<string> Notes, bool FromV22 = false);

    public const int MaxRows = 2000;

    public static ParseResult Parse(string text)
    {
        var problems = new List<string>(); var notes = new List<string>();
        var records = ReadRecords((text ?? "").TrimStart('﻿'));
        records = records.Where(r => !(r.Count == 1 && r[0].Length == 0)).ToList();
        if (records.Count == 0) return new ParseResult(Array.Empty<RiskIndexRow>(), false, new[] { "the file is empty" }, notes);
        var header = records[0].Select(h => h.Trim()).ToList();
        if (RiskIndexV22.IsV22Header(header)) return RiskIndexV22.ParseRecords(header, records.Skip(1).ToList());
        var map = new string?[header.Count];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < header.Count; i++)
        {
            var h = header[i];
            if (RiskIndexColumns.Aliases.TryGetValue(h, out var col))
            {
                if (!seen.Add(col)) { problems.Add($"the column {col} appears twice"); continue; }
                map[i] = col;
                if (!string.Equals(h, col, StringComparison.Ordinal)) notes.Add($"the column '{h}' was read as {col}");
            }
            else if (h.Length > 0) notes.Add($"the column '{h}' is not a risk index column and was left out");
        }
        foreach (var need in new[] { RiskIndexColumns.AssetBase, RiskIndexColumns.VulnerabilityBase })
            if (!seen.Contains(need)) problems.Add($"the column {need} is missing (the engine requires it)");
        if (!RiskIndexColumns.SharedMatchers.Any(seen.Contains)) problems.Add("no matcher column (si_finding_type, si_category, si_subcategory, si_component, si_finding_key, asset_class)");
        var rows = new List<RiskIndexRow>();
        for (var n = 1; n < records.Count; n++)
        {
            if (rows.Count >= MaxRows) { problems.Add($"more than {MaxRows} rows -- the rest was not read"); break; }
            var rec = records[n];
            var row = new RiskIndexRow();
            for (var i = 0; i < map.Length; i++) if (map[i] is { } col) row = row.With(col, i < rec.Count ? rec[i] : "");
            rows.Add(row);
        }
        return new ParseResult(rows, seen.Contains(RiskIndexColumns.Precedence), problems, notes);
    }

    /// The rows (in this order) as the CSV the engine reads, Precedence renumbered 1..n.
    public static string Write(IReadOnlyList<RiskIndexRow> ordered)
    {
        var sb = new StringBuilder();
        sb.Append(string.Join(',', RiskIndexColumns.All)).Append("\r\n");
        for (var i = 0; i < ordered.Count; i++)
        {
            var r = ordered[i];
            sb.Append(string.Join(',', RiskIndexColumns.All.Select(c => c == RiskIndexColumns.Precedence ? (i + 1).ToString(CultureInfo.InvariantCulture) : Quote(r.Get(c))))).Append("\r\n");
        }
        return sb.ToString();
    }

    private static string Quote(string s) =>
        s.IndexOfAny(new[] { '"', ',', '\r', '\n' }) >= 0 || s != s.Trim() ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;

    internal static List<List<string>> ReadRecords(string text)
    {
        var res = new List<List<string>>(); var cur = new List<string>(); var f = new StringBuilder();
        var q = false;
        for (var i = 0; i < text.Length; i++)
        {
            var ch = text[i];
            if (q)
            {
                if (ch == '"') { if (i + 1 < text.Length && text[i + 1] == '"') { f.Append('"'); i++; } else q = false; }
                else f.Append(ch);
                continue;
            }
            switch (ch)
            {
                case '"': q = true; break;
                case ',': cur.Add(f.ToString()); f.Clear(); break;
                case '\r': break;
                case '\n': cur.Add(f.ToString()); f.Clear(); res.Add(cur); cur = new List<string>(); break;
                default: f.Append(ch); break;
            }
        }
        if (f.Length > 0 || cur.Count > 0) { cur.Add(f.ToString()); res.Add(cur); }
        return res;
    }
}
