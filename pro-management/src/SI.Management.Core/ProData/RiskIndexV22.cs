using System.Globalization;
using System.Text.Json;

namespace SI.Management.Core.ProData;

/// <summary>
/// The risk index as it was written before the re-key to the SI generic fields (#559): the 2.2 columns (SecurityDomain,
/// Category, SubCategory, ConfigurationId, SecuritySeverity, the consequence score, CriticalityTierLevel, the probability
/// score). Such a file, a customer's 2.2 / 3.0 custom file or a Pro item stored before the re-key is TRANSLATED, never
/// lost: a file without a Precedence column is put in first-match form by the v2.2 ladder (RA-RiskIndexOrder.ps1
/// ConvertTo-SIRiskIndexFirstMatch, step for step), then every row is translated column by column with the shipped table
/// (risk-analysis-detection\riskscore.index.translation.locked.json -- a test holds <see cref="Columns"/> and
/// <see cref="Values"/> to it), so every 2.2 base value is carried over. The C# twin of RA-RiskIndexSi.ps1
/// ConvertTo-SIRiskIndexSiRow(s).
/// </summary>
public static class RiskIndexV22
{
    public const string SecurityDomain = "SecurityDomain";
    public const string Category = "Category";
    public const string SubCategory = "SubCategory";
    public const string ConfigurationId = "ConfigurationId";
    public const string SecuritySeverity = "SecuritySeverity";
    public const string ConsequenceScore = "RiskConsequenceScore_SecuritySeverity";
    public const string CriticalityTierLevel = "CriticalityTierLevel";
    public const string ProbabilityScore = "RiskProbablityScore_CriticialityTierLevel";

    /// One 2.2 row (Precedence blank in a 2.2 file).
    public sealed record Row
    {
        public string SecurityDomain { get; init; } = "";
        public string Category { get; init; } = "";
        public string SubCategory { get; init; } = "";
        public string ConfigurationId { get; init; } = "";
        public string SecuritySeverity { get; init; } = "";
        public string ConsequenceScore { get; init; } = "";
        public string CriticalityTierLevel { get; init; } = "";
        public string ProbabilityScore { get; init; } = "";
        public string Comments { get; init; } = "";
        public string Precedence { get; init; } = "";

        public string Get(string c) => c switch
        {
            RiskIndexV22.SecurityDomain => SecurityDomain, RiskIndexV22.Category => Category, RiskIndexV22.SubCategory => SubCategory,
            RiskIndexV22.ConfigurationId => ConfigurationId, RiskIndexV22.SecuritySeverity => SecuritySeverity, RiskIndexV22.ConsequenceScore => ConsequenceScore,
            RiskIndexV22.CriticalityTierLevel => CriticalityTierLevel, RiskIndexV22.ProbabilityScore => ProbabilityScore,
            RiskIndexColumns.Comments => Comments, RiskIndexColumns.Precedence => Precedence, _ => "",
        };

        public Row With(string c, string? value)
        {
            var v = value ?? "";
            return c switch
            {
                RiskIndexV22.SecurityDomain => this with { SecurityDomain = v }, RiskIndexV22.Category => this with { Category = v },
                RiskIndexV22.SubCategory => this with { SubCategory = v }, RiskIndexV22.ConfigurationId => this with { ConfigurationId = v },
                RiskIndexV22.SecuritySeverity => this with { SecuritySeverity = v }, RiskIndexV22.ConsequenceScore => this with { ConsequenceScore = v },
                RiskIndexV22.CriticalityTierLevel => this with { CriticalityTierLevel = v }, RiskIndexV22.ProbabilityScore => this with { ProbabilityScore = v },
                RiskIndexColumns.Comments => this with { Comments = v }, RiskIndexColumns.Precedence => this with { Precedence = v }, _ => this,
            };
        }
    }

    /// 2.2 spellings accepted on import (the common corrected spellings of the two score columns included).
    public static readonly IReadOnlyDictionary<string, string> Aliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["SecurityDomain"] = SecurityDomain, ["Domain"] = SecurityDomain,
        ["Category"] = Category,
        ["SubCategory"] = SubCategory, ["Subcategory"] = SubCategory,
        ["ConfigurationId"] = ConfigurationId,
        ["SecuritySeverity"] = SecuritySeverity, ["Severity"] = SecuritySeverity,
        ["RiskConsequenceScore_SecuritySeverity"] = ConsequenceScore, ["RiskConsequenceScore"] = ConsequenceScore, ["ConsequenceScore"] = ConsequenceScore,
        ["CriticalityTierLevel"] = CriticalityTierLevel, ["TierLevel"] = CriticalityTierLevel,
        ["RiskProbablityScore_CriticialityTierLevel"] = ProbabilityScore, ["RiskProbabilityScore_CriticalityTierLevel"] = ProbabilityScore,
        ["RiskProbabilityScore_CriticialityTierLevel"] = ProbabilityScore, ["RiskProbablityScore_CriticalityTierLevel"] = ProbabilityScore,
        ["RiskProbabilityScore"] = ProbabilityScore, ["ProbabilityScore"] = ProbabilityScore,
        ["Comments"] = RiskIndexColumns.Comments, ["Comment"] = RiskIndexColumns.Comments,
        ["Precedence"] = RiskIndexColumns.Precedence,
    };

    /// THE translation table (riskscore.index.translation.locked.json 'columns'): 2.2 column -> SI column.
    public static readonly IReadOnlyList<(string From, string To)> Columns = new[]
    {
        (SecurityDomain, RiskIndexColumns.AssetClass), (Category, RiskIndexColumns.Category), (SubCategory, RiskIndexColumns.SubCategory),
        (ConfigurationId, RiskIndexColumns.FindingKey), (SecuritySeverity, RiskIndexColumns.Severity), (ConsequenceScore, RiskIndexColumns.VulnerabilityBase),
        (CriticalityTierLevel, RiskIndexColumns.Tier), (ProbabilityScore, RiskIndexColumns.AssetBase),
        (RiskIndexColumns.Comments, RiskIndexColumns.Comments), (RiskIndexColumns.Precedence, RiskIndexColumns.Precedence),
    };

    /// THE value maps (the table's 'values'): per SI column, lower-case 2.2 value -> SI value; an unlisted value is kept.
    public static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Values = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal)
    {
        [RiskIndexColumns.AssetClass] = new Dictionary<string, string>(StringComparer.Ordinal) { ["endpoint"] = "device", ["identity"] = "identity", ["azure"] = "cloud_resource", ["publicip"] = "public_ip" },
        [RiskIndexColumns.Severity] = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["very high"] = "critical", ["critical"] = "critical", ["high"] = "high", ["medium-high"] = "medium_high", ["medium"] = "medium",
            ["moderate"] = "medium", ["low"] = "low", ["informational"] = "info", ["info"] = "info",
        },
        [RiskIndexColumns.Tier] = new Dictionary<string, string>(StringComparer.Ordinal) { ["critical - tier 0"] = "0", ["high - tier 1"] = "1", ["medium - tier 2"] = "2", ["low - tier 3"] = "3" },
    };

    /// ConvertTo-SIRiskIndexSiValue: one 2.2 value -> its SI value for an SI column.
    public static string Value(string siColumn, string? value)
    {
        var v = (value ?? "").Trim();
        if (v.Length == 0) return "";
        return Values.TryGetValue(siColumn, out var m) && m.TryGetValue(v.ToLowerInvariant(), out var to) ? to : v;
    }

    /// ConvertTo-SIRiskIndexSiRow: one 2.2 row -> the SI row (its Precedence kept).
    public static RiskIndexRow Translate(Row r)
    {
        var o = new RiskIndexRow();
        foreach (var (from, to) in Columns) o = o.With(to, Value(to, r.Get(from)));
        return o;
    }

    /// A header written with the 2.2 columns: it carries a 2.2 score / tier column and no SI base column.
    public static bool IsV22Header(IEnumerable<string> header)
    {
        var cols = header.Select(h => h.Trim()).ToList();
        if (cols.Any(c => c.Equals(RiskIndexColumns.AssetBase, StringComparison.OrdinalIgnoreCase) || c.Equals(RiskIndexColumns.VulnerabilityBase, StringComparison.OrdinalIgnoreCase))) return false;
        return cols.Any(c => Aliases.TryGetValue(c, out var k) && k is ConsequenceScore or ProbabilityScore or CriticalityTierLevel);
    }

    /// A body (a Pro item) written with the 2.2 columns.
    public static bool IsV22Body(JsonElement o) =>
        o.ValueKind == JsonValueKind.Object && IsV22Header(o.EnumerateObject().Select(p => p.Name));

    /// A 2.2 item body -> the 2.2 row (null when it is not a JSON object).
    public static Row? RowFromBody(JsonElement o)
    {
        if (o.ValueKind != JsonValueKind.Object) return null;
        var r = new Row();
        foreach (var p in o.EnumerateObject())
        {
            if (!Aliases.TryGetValue(p.Name, out var col)) continue;
            r = r.With(col, p.Value.ValueKind switch { JsonValueKind.String => p.Value.GetString() ?? "", JsonValueKind.Null => "", _ => p.Value.GetRawText() });
        }
        return r;
    }

    /// The 2.2 records of a file (header already read) -> SI rows in first-match order, Precedence 1..n.
    internal static RiskIndexCsv.ParseResult ParseRecords(IReadOnlyList<string> header, IReadOnlyList<List<string>> records)
    {
        var problems = new List<string>(); var notes = new List<string>();
        var map = new string?[header.Count];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < header.Count; i++)
        {
            if (Aliases.TryGetValue(header[i], out var col))
            {
                if (!seen.Add(col)) { problems.Add($"the column {col} appears twice"); continue; }
                map[i] = col;
                if (!string.Equals(header[i], col, StringComparison.Ordinal)) notes.Add($"the column '{header[i]}' was read as {col}");
            }
            else if (header[i].Length > 0) notes.Add($"the column '{header[i]}' is not a risk index column and was left out");
        }
        foreach (var need in new[] { Category, SubCategory, ConfigurationId, SecuritySeverity, ConsequenceScore, CriticalityTierLevel, ProbabilityScore })
            if (!seen.Contains(need)) problems.Add($"the column {need} is missing (a 2.2 index needs it)");
        var rows = new List<Row>();
        foreach (var rec in records)
        {
            if (rows.Count >= RiskIndexCsv.MaxRows) { problems.Add($"more than {RiskIndexCsv.MaxRows} rows -- the rest was not read"); break; }
            var row = new Row();
            for (var i = 0; i < map.Length; i++) if (map[i] is { } col) row = row.With(col, i < rec.Count ? rec[i] : "");
            rows.Add(row);
        }
        var hasPrec = seen.Contains(RiskIndexColumns.Precedence);
        var ordered = hasPrec
            ? rows.Select((r, i) => (r, i, p: RiskIndexScoring.IsNumber(r.Precedence) ? RiskIndexScoring.Number(r.Precedence.Trim()) : double.MaxValue)).OrderBy(x => x.p).ThenBy(x => x.i).Select(x => x.r).ToList()
            : ConvertToFirstMatch(rows);
        var si = ordered.Select((r, i) => Translate(r) with { Precedence = (i + 1).ToString(CultureInfo.InvariantCulture) }).ToList();
        notes.Insert(0, $"the file uses the 2.2 columns: {rows.Count} row(s) translated to the SI keys ({si.Count} row(s) in first-match order) with every base value carried over");
        return new RiskIndexCsv.ParseResult(si, true, problems, notes, FromV22: true);
    }

    // ------------------------------------------------------------------------------------------------ a finding's values

    /// Get-SIRiskIndexAssetClass: the asset class the index keys on -- device_server / device_client (a device with a known
    /// category or OS), device (neither says), identity, cloud_resource, public_ip; "" when unknown.
    public static string AssetClassOf(string? cls, string? deviceCategory, string? osPlatform, string? osName)
    {
        var c = (cls ?? "").Trim().ToLowerInvariant();
        switch (c)
        {
            case "device":
                var cat = (deviceCategory ?? "").Trim().ToLowerInvariant();
                var os = ((osPlatform ?? "") + " " + (osName ?? "")).Trim().ToLowerInvariant();
                if (cat == "server" || os.Contains("server", StringComparison.Ordinal)) return "device_server";
                if (cat is "endpoint" or "workstation" or "desktop" or "laptop" or "mobile" or "client") return "device_client";
                if (System.Text.RegularExpressions.Regex.IsMatch(os, "^(windows ?(7|8|10|11|xp|vista))|macos|mac os|ios|ipados|android")) return "device_client";
                return "device";
            case "identity" or "cloud_resource" or "public_ip": return c;
            default: return "";
        }
    }

    /// Get-SIRiskIndexFindingValues for a stored finding: the SI fields when the row carries them, else its 2.2 columns
    /// translated (the security domain -> asset class, split by the OS; the severity label -> the SI severity).
    public static RiskIndexFinding FindingOf(string? findingType, string? findingKey, string? configurationId, string? category, string? subCategory, string? component,
        string? assetClass, string? siClass, string? securityDomain, string? deviceCategory, string? osPlatform, string? osName, string? severityLabel, string? siSeverity, int? tier, string? tierLabel)
    {
        static string T(string? s) => (s ?? "").Trim();
        var key = T(findingKey).Length > 0 ? T(findingKey) : T(configurationId);
        var ftype = T(findingType);
        if (ftype.Length == 0 && System.Text.RegularExpressions.Regex.IsMatch(key, @"^(?i)CVE-\d{4}-\d+$")) ftype = "cve";
        var ac = T(assetClass);
        if (ac.Length == 0 && T(siClass).Length > 0) ac = AssetClassOf(siClass, deviceCategory, osPlatform, osName);
        if (ac.Length == 0)
        {
            ac = Value(RiskIndexColumns.AssetClass, securityDomain);
            if (ac == "device" && T(osPlatform).Length > 0) ac = AssetClassOf("device", deviceCategory, osPlatform, null);
        }
        var t = tier is >= 0 and <= 3 ? tier.Value.ToString(CultureInfo.InvariantCulture) : Value(RiskIndexColumns.Tier, tierLabel);
        var sev = T(severityLabel).Length > 0 ? Value(RiskIndexColumns.Severity, severityLabel) : T(siSeverity).ToLowerInvariant();
        return new RiskIndexFinding(ftype, T(category), T(subCategory), T(component), key, ac, sev, t);
    }

    // ------------------------------------------------------------------------------------------------ the v2.2 ladder

    private enum Kind { Consequence, Probability }

    /// The v2.2 pattern ladder, most specific first. D C S I = Domain Category SubCategory ConfigurationId;
    /// V = Severity (consequence) or Tier (probability).
    public static readonly string[][] Ladder =
    {
        new[] { "D", "C", "S", "I", "V" }, new[] { "D", "C", "S", "V" }, new[] { "D", "C", "V" }, new[] { "D", "V" },
        new[] { "D", "C", "S", "I" }, new[] { "D", "C", "S" }, new[] { "D", "C" }, new[] { "D" },
        new[] { "C", "S", "I", "V" }, new[] { "C", "S", "V" }, new[] { "C", "V" }, new[] { "V" },
        new[] { "C", "S", "I" }, new[] { "C", "S" }, new[] { "C" },
    };

    private static string Col(string letter, Kind kind) => letter switch
    {
        "D" => SecurityDomain, "C" => Category, "S" => SubCategory, "I" => ConfigurationId,
        _ => kind == Kind.Consequence ? SecuritySeverity : CriticalityTierLevel,
    };

    private static string ScoreCol(Kind kind) => kind == Kind.Consequence ? ConsequenceScore : ProbabilityScore;
    private static bool Blank(string? s) => string.IsNullOrWhiteSpace(s);

    private sealed record Entry(string[] Vals, string Score, string Comment);

    /// A v2.2 index (file order) -> the same index as first-match rows in precedence order, Precedence 1..n.
    /// ConvertTo-SIRiskIndexFirstMatch, step for step.
    public static IReadOnlyList<Row> ConvertToFirstMatch(IReadOnlyList<Row> rows)
    {
        var outRows = new List<Row>();
        foreach (var pat in Ladder)
        {
            var byKey = new Dictionary<string, (List<Entry> Cons, List<Entry> Prob)>(StringComparer.Ordinal);
            var order = new List<string>();
            foreach (var kind in new[] { Kind.Consequence, Kind.Probability })
            {
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var r in rows)
                {
                    var vals = new string[pat.Length];
                    var ok = true;
                    for (var i = 0; i < pat.Length; i++)
                    {
                        var v = r.Get(Col(pat[i], kind));
                        if (Blank(v)) { ok = false; break; }
                        vals[i] = v;
                    }
                    if (!ok) continue;
                    var key = string.Join('|', vals).ToLowerInvariant();
                    if (!seen.Add(key)) continue;
                    var gk = string.Join('|', vals.Where((_, i) => pat[i] != "V")).ToLowerInvariant();
                    if (!byKey.ContainsKey(gk)) { byKey[gk] = (new List<Entry>(), new List<Entry>()); order.Add(gk); }
                    var raw = r.Get(ScoreCol(kind)).Trim();
                    var score = raw.Length > 0 && double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out _) ? raw : "0";
                    var wider = new[] { "D", "C", "S", "I", "V" }.Any(l => !pat.Contains(l) && !Blank(r.Get(Col(l, kind))));
                    var e = new Entry(vals, score, wider ? "" : r.Comments);
                    if (kind == Kind.Consequence) byKey[gk].Cons.Add(e); else byKey[gk].Prob.Add(e);
                }
            }
            foreach (var gk in order)
            {
                var (c, p) = byKey[gk];
                var pairs = new List<(Entry? C, Entry? P)>();
                if (pat.Contains("V")) { pairs.AddRange(c.Select(e => ((Entry?)e, (Entry?)null))); pairs.AddRange(p.Select(e => ((Entry?)null, (Entry?)e))); }
                else pairs.Add((c.FirstOrDefault(), p.FirstOrDefault()));
                foreach (var (ce, pe) in pairs)
                {
                    var src = (ce ?? pe)!;
                    var row = new Row();
                    for (var j = 0; j < pat.Length; j++)
                    {
                        if (pat[j] == "V")
                        {
                            if (ce is not null) row = row with { SecuritySeverity = ce.Vals[j] };
                            if (pe is not null) row = row with { CriticalityTierLevel = pe.Vals[j] };
                        }
                        else row = row.With(Col(pat[j], Kind.Consequence), src.Vals[j]);
                    }
                    if (ce is not null) row = row with { ConsequenceScore = ce.Score };
                    if (pe is not null) row = row with { ProbabilityScore = pe.Score };
                    row = row with { Comments = ce is not null && ce.Comment.Length > 0 ? ce.Comment : pe is not null ? pe.Comment : "" };
                    outRows.Add(row);
                }
            }
        }
        return outRows.Select((r, i) => r with { Precedence = (i + 1).ToString(CultureInfo.InvariantCulture) }).ToList();
    }
}
