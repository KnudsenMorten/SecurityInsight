using System.Globalization;
using System.Text.Json;

namespace SI.Management.Core.ProData;

/// One problem of the edited index: the row (0-based, in the edited order; -1 = the whole index), the column ("" = the
/// row), the message, and whether it blocks staging (an error) or only informs (a warning).
public sealed record RiskIndexIssue(int Row, string Column, string Message, bool Error);

/// Where an item of the committed index comes from (the per-row diff against the vendor template).
public enum RiskIndexOrigin { Template, Override, Own }

/// One row of the committed index as the editor shows it: its item key, where it comes from, the vendor's body (when there
/// is a template of that key) and whether the row has a place in the order.
public sealed record RiskIndexItem(string Key, RiskIndexOrigin Origin, RiskIndexRow Row, RiskIndexRow? Template, bool Stale);

/// One cfg.ItemOverride write of a commit: State 'override' (with Body), 'disable', or 'inherit' (the row is removed).
public sealed record RiskIndexWrite(string Key, string State, string? Body, string Describe);

/// <summary>
/// The Risk index editor's model -- pure, no I/O: validation per column, the item keys, sort by specificity, shadowed rows,
/// the Precedence a commit stores, and the writes (override / own / disable / inherit) that turn the committed index into
/// the edited one. Mirrors Test-SIProItem's riskindex rules and Get-SIRiskIndexKey (engine\pro-settings\SI-ProConfig.ps1).
/// </summary>
public static class RiskIndexEditor
{
    public const string Kind = "riskindex";
    public const int MaxKeyLength = 128;
    public const int MaxRows = RiskIndexCsv.MaxRows;
    private static bool Blank(string? s) => string.IsNullOrWhiteSpace(s);

    // ------------------------------------------------------------------------------------------------ keys

    /// Get-SIRiskIndexKey: 'row/' + the eight SI key columns, trimmed, '|'-joined.
    public static string BaseKey(RiskIndexRow r) => "row/" + string.Join('|', RiskIndexColumns.Key.Select(c => r.Get(c).Trim()));

    /// The item keys of rows in this order: a repeat of the same dimensions is '&lt;key&gt;#2', '#3', ... (as the templates key it).
    public static IReadOnlyList<string> Keys(IReadOnlyList<RiskIndexRow> rows)
    {
        var count = new Dictionary<string, int>(StringComparer.Ordinal);
        var res = new List<string>(rows.Count);
        foreach (var r in rows)
        {
            var k = BaseKey(r);
            count[k] = count.TryGetValue(k, out var n) ? n + 1 : 1;
            res.Add(count[k] == 1 ? k : k + "#" + count[k].ToString(CultureInfo.InvariantCulture));
        }
        return res;
    }

    // ------------------------------------------------------------------------------------------------ validation

    public static IReadOnlyList<RiskIndexIssue> Validate(IReadOnlyList<RiskIndexRow> rows)
    {
        var issues = new List<RiskIndexIssue>();
        if (rows.Count == 0) issues.Add(new(-1, "", "the index has no rows -- Risk Analysis would score every finding 0", true));
        if (rows.Count > MaxRows) issues.Add(new(-1, "", $"at most {MaxRows} rows", true));
        var keys = Keys(rows);
        for (var i = 0; i < rows.Count; i++)
        {
            var r = rows[i];
            foreach (var c in RiskIndexColumns.Content)
            {
                var v = r.Get(c);
                if (v.IndexOfAny(new[] { '"', '\r', '\n' }) >= 0) issues.Add(new(i, c, $"{RiskIndexColumns.Label(c)} may not hold quotes or line breaks", true));
                if (v.Length > 400) issues.Add(new(i, c, $"{RiskIndexColumns.Label(c)} is longer than 400 characters", true));
            }
            if (keys[i].Length > MaxKeyLength) issues.Add(new(i, "", $"the matchers are too long together (the row's key is {keys[i].Length} characters, at most {MaxKeyLength})", true));
            foreach (var c in RiskIndexColumns.Bases)
            {
                var v = r.Get(c);
                if (Blank(v)) continue;
                if (!RiskIndexScoring.IsNumber(v)) { issues.Add(new(i, c, $"{RiskIndexColumns.Label(c)} must be a number (a decimal point, not a comma)", true)); continue; }
                var d = RiskIndexScoring.Number(v.Trim());
                if (d < RiskIndexVocabulary.MinScore || d > RiskIndexVocabulary.MaxScore)
                    issues.Add(new(i, c, $"{RiskIndexColumns.Label(c)} must be between {RiskIndexVocabulary.MinScore.ToString(CultureInfo.InvariantCulture)} and {RiskIndexVocabulary.MaxScore.ToString(CultureInfo.InvariantCulture)}", true));
            }
            var hasV = !Blank(r.VulnerabilityBase); var hasA = !Blank(r.AssetBase);
            if (!hasV && !hasA) issues.Add(new(i, "", "the row sets no base -- give it an asset base, a vulnerability base or both", true));
            // the engine refuses an unknown asset class (Test-SIProItem) and a tier that is not a number
            if (!Blank(r.AssetClass) && !RiskIndexVocabulary.AssetClasses.Contains(r.AssetClass.Trim(), StringComparer.Ordinal))
                issues.Add(new(i, RiskIndexColumns.AssetClass, $"'{r.AssetClass}' is not an asset class ({string.Join(", ", RiskIndexVocabulary.AssetClasses)}, or blank for any)", true));
            if (!Blank(r.Tier) && !RiskIndexScoring.IsNumber(r.Tier)) issues.Add(new(i, RiskIndexColumns.Tier, "the tier must be a number (0, 1, 2 or 3)", true));
            else if (!Blank(r.Tier) && !RiskIndexVocabulary.Tiers.Contains(r.Tier.Trim(), StringComparer.Ordinal))
                issues.Add(new(i, RiskIndexColumns.Tier, $"'{r.Tier}' is not a tier (0, 1, 2 or 3) -- the row matches no finding", false));
            if (!Blank(r.Severity) && !RiskIndexVocabulary.Severities.Contains(r.Severity.Trim(), StringComparer.OrdinalIgnoreCase))
                issues.Add(new(i, RiskIndexColumns.Severity, $"'{r.Severity}' is not an SI severity ({string.Join(", ", RiskIndexVocabulary.Severities)}) -- the row matches only a finding with exactly this text", false));
            if (r.Severity != r.Severity.Trim() || r.Tier != r.Tier.Trim() || RiskIndexColumns.SharedMatchers.Any(c => r.Get(c) != r.Get(c).Trim()))
                issues.Add(new(i, "", "a matcher starts or ends with a space -- it matches only a finding value with the same spaces", false));
            if (!Blank(r.Severity) && !hasV) issues.Add(new(i, RiskIndexColumns.Severity, "the severity is read only by the vulnerability lookup, and this row has no vulnerability base -- the severity does nothing", false));
            if (!Blank(r.Tier) && !hasA) issues.Add(new(i, RiskIndexColumns.Tier, "the tier is read only by the asset lookup, and this row has no asset base -- the tier does nothing", false));
            if (hasV && hasA && Blank(r.Severity) != Blank(r.Tier))
                issues.Add(new(i, "", "the vulnerability lookup ignores the tier and the asset lookup ignores the severity: this row's " + (Blank(r.Severity) ? "vulnerability base applies at every severity" : "asset base applies at every tier") + " -- split it into two rows if that is not meant", false));
        }
        foreach (var s in Shadowed(rows))
            issues.Add(new(s.Row, "", $"never used for the {(s.Kind == RiskIndexScoreKind.Vulnerability ? "vulnerability" : "asset")} base: row {s.By + 1} above it already matches every finding this row matches", false));
        return issues;
    }

    public static bool CanStage(IReadOnlyList<RiskIndexIssue> issues) => !issues.Any(i => i.Error);

    // ------------------------------------------------------------------------------------------------ precedence

    private static string? Matcher(RiskIndexRow r, string column)
    {
        var v = r.Get(column).Trim();
        return v.Length == 0 ? null : v.ToLowerInvariant();
    }

    public sealed record Shadow(int Row, RiskIndexScoreKind Kind, int By);

    /// Rows (or one of their bases) that can never be used: a row above with a base of the same kind whose filled
    /// matchers are all filled the same in this row (asset_class 'device' covering device_server / device_client) matches
    /// every finding this row matches, first.
    public static IReadOnlyList<Shadow> Shadowed(IReadOnlyList<RiskIndexRow> rows)
    {
        var res = new List<Shadow>();
        foreach (var kind in new[] { RiskIndexScoreKind.Vulnerability, RiskIndexScoreKind.Asset })
        {
            var sc = RiskIndexScoring.ScoreColumn(kind);
            var cols = RiskIndexScoring.Matchers(kind);
            for (var i = 0; i < rows.Count; i++)
            {
                if (Blank(rows[i].Get(sc))) continue;
                for (var j = 0; j < i; j++)
                {
                    if (Blank(rows[j].Get(sc))) continue;
                    var covers = cols.All(c =>
                    {
                        if (Matcher(rows[j], c) is not { } a) return true;
                        var b = Matcher(rows[i], c);
                        return a == b || (c == RiskIndexColumns.AssetClass && a == RiskIndexScoring.Family(b));
                    });
                    if (covers) { res.Add(new Shadow(i, kind, j)); break; }
                }
            }
        }
        return res;
    }

    /// How specific a row is: asset-class-qualified first (a device_server / device_client row before a 'device' row),
    /// then tier / severity-qualified, then finding key, subcategory, category, component, finding type. Lower = more specific.
    public static (int, int, int, int, int, int, int) Specificity(RiskIndexRow r)
    {
        var ac = r.AssetClass.Trim();
        var acRank = ac.Length == 0 ? 2 : RiskIndexScoring.Family(ac) is not null ? 0 : 1;
        var v = (!Blank(r.VulnerabilityBase) && !Blank(r.Severity)) || (!Blank(r.AssetBase) && !Blank(r.Tier));
        return (acRank, v ? 0 : 1, Blank(r.FindingKey) ? 1 : 0, Blank(r.SubCategory) ? 1 : 0, Blank(r.Category) ? 1 : 0, Blank(r.Component) ? 1 : 0, Blank(r.FindingType) ? 1 : 0);
    }

    /// "Sort by specificity": most specific first, rows of equal specificity keep their order (a stable sort).
    public static IReadOnlyList<RiskIndexRow> SortBySpecificity(IReadOnlyList<RiskIndexRow> rows) =>
        rows.Select((r, i) => (r, i)).OrderBy(x => Specificity(x.r)).ThenBy(x => x.i).Select(x => x.r).ToList();

    /// Move a row (0-based) by delta places; out of range = unchanged.
    public static IReadOnlyList<RiskIndexRow> Move(IReadOnlyList<RiskIndexRow> rows, int index, int delta)
    {
        var to = index + delta;
        if (index < 0 || index >= rows.Count || to < 0 || to >= rows.Count) return rows;
        var l = rows.ToList(); var r = l[index]; l.RemoveAt(index); l.Insert(to, r);
        return l;
    }

    /// <summary>
    /// The Precedence each row of the edited order stores. A row whose key has a vendor template keeps the template's own
    /// Precedence when it can (the longest run of template rows still in the vendor's order), so following the vendor
    /// stays "inherit"; every other row (own, moved) gets a value between its neighbours. Strictly increasing.
    /// </summary>
    public static IReadOnlyList<string> AssignPrecedence(IReadOnlyList<RiskIndexRow> rows, IReadOnlyList<string> keys, IReadOnlyDictionary<string, RiskIndexRow> templates)
    {
        var n = rows.Count;
        var anchor = new double?[n];
        for (var i = 0; i < n; i++)
            if (templates.TryGetValue(keys[i], out var t) && RiskIndexScoring.IsNumber(t.Precedence)) anchor[i] = RiskIndexScoring.Number(t.Precedence.Trim());
        // longest strictly increasing run of anchors (O(n^2) is fine at <= 2000 rows)
        var len = new int[n]; var prev = new int[n]; var best = -1;
        for (var i = 0; i < n; i++)
        {
            prev[i] = -1;
            if (anchor[i] is not { } a || a <= 0) continue;
            len[i] = 1;
            for (var j = 0; j < i; j++)
                if (anchor[j] is { } b && len[j] > 0 && b < a && len[j] + 1 > len[i]) { len[i] = len[j] + 1; prev[i] = j; }
            if (best < 0 || len[i] > len[best]) best = i;
        }
        var value = new double?[n];
        for (var k = best; k >= 0; k = prev[k]) value[k] = anchor[k];
        // fill the gaps between kept anchors evenly
        var res = new string[n];
        var start = 0; var lo = 0.0;
        for (var i = 0; i <= n; i++)
        {
            if (i < n && value[i] is null) continue;
            var hi = i < n ? value[i]!.Value : lo + (i - start) + 1;
            var gap = i - start;
            for (var g = 0; g < gap; g++) res[start + g] = Format(lo + (hi - lo) * (g + 1) / (gap + 1));
            if (i < n) { res[i] = Format(value[i]!.Value); lo = value[i]!.Value; start = i + 1; }
        }
        // a value rounded onto its neighbour (a very narrow gap): renumber everything from 1 instead
        for (var i = 1; i < n; i++)
            if (RiskIndexScoring.Number(res[i]) <= RiskIndexScoring.Number(res[i - 1]))
                return Enumerable.Range(1, n).Select(x => x.ToString(CultureInfo.InvariantCulture)).ToList();
        return res;
    }

    private static string Format(double d)
    {
        var r = Math.Round(d, 4);
        return r == Math.Floor(r) ? ((long)r).ToString(CultureInfo.InvariantCulture) : r.ToString("0.####", CultureInfo.InvariantCulture);
    }

    // ------------------------------------------------------------------------------------------------ bodies + writes

    /// The item body: every column, in the file's order (what Get-SITemplateRows publishes).
    public static string Body(RiskIndexRow r)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
        {
            w.WriteStartObject();
            foreach (var c in RiskIndexColumns.All) w.WriteString(c, r.Get(c));
            w.WriteEndObject();
        }
        return System.Text.Encoding.UTF8.GetString(ms.ToArray());
    }

    /// A body written with the 2.2 columns (stored before the re-key; translated on read).
    public static bool IsV22Body(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        try { using var d = JsonDocument.Parse(body.TrimStart('﻿')); return RiskIndexV22.IsV22Body(d.RootElement); }
        catch (JsonException) { return false; }
    }

    /// A body back into a row (null when it is not a JSON object). A body stored with the 2.2 columns is translated to the
    /// SI keys (ConvertTo-SIRiskIndexSiRow), its base values and Precedence kept.
    public static RiskIndexRow? FromBody(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try
        {
            using var d = JsonDocument.Parse(body.TrimStart('﻿'));
            if (d.RootElement.ValueKind != JsonValueKind.Object) return null;
            if (RiskIndexV22.IsV22Body(d.RootElement)) return RiskIndexV22.RowFromBody(d.RootElement) is { } old ? RiskIndexV22.Translate(old) : null;
            var r = new RiskIndexRow();
            foreach (var p in d.RootElement.EnumerateObject())
            {
                if (!RiskIndexColumns.All.Contains(p.Name, StringComparer.Ordinal)) continue;
                var v = p.Value.ValueKind switch
                {
                    JsonValueKind.String => p.Value.GetString() ?? "",
                    JsonValueKind.Null => "",
                    JsonValueKind.Number => p.Value.GetRawText(),
                    _ => p.Value.GetRawText(),
                };
                r = r.With(p.Name, v);
            }
            return r;
        }
        catch (JsonException) { return null; }
    }

    /// Same row, Precedence compared as a number.
    public static bool Same(RiskIndexRow a, RiskIndexRow b) =>
        a.SameContent(b) && (Blank(a.Precedence) && Blank(b.Precedence)
            || RiskIndexScoring.IsNumber(a.Precedence) && RiskIndexScoring.IsNumber(b.Precedence) && RiskIndexScoring.Number(a.Precedence.Trim()) == RiskIndexScoring.Number(b.Precedence.Trim()));

    /// The current customer state of one item (cfg.ItemOverride) -- null when there is none.
    public sealed record OverrideState(string State, string? Body);

    /// <summary>
    /// The writes that make the committed index the edited one. -Edited rows in the edited order WITH the Precedence a
    /// commit stores (AssignPrecedence); -Templates the live vendor rows by key; -Overrides the customer's current
    /// cfg.ItemOverride rows of the kind by key. A row equal to its template -> inherit (no row); a row differing from its
    /// template -> override; a row without a template -> own (override); a template row not in the edit -> disable; an own
    /// row not in the edit -> removed (inherit).
    /// </summary>
    public static IReadOnlyList<RiskIndexWrite> Writes(IReadOnlyList<RiskIndexRow> edited, IReadOnlyDictionary<string, RiskIndexRow> templates, IReadOnlyDictionary<string, OverrideState> overrides)
    {
        var keys = Keys(edited);
        var res = new List<RiskIndexWrite>();
        var wanted = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < edited.Count; i++)
        {
            var k = keys[i]; var r = edited[i];
            wanted.Add(k);
            overrides.TryGetValue(k, out var cur);
            if (templates.TryGetValue(k, out var t) && Same(r, t))
            {
                if (cur is not null) res.Add(new RiskIndexWrite(k, "inherit", null, "follows the vendor template again"));
                continue;
            }
            if (cur is { State: "override" } && FromBody(cur.Body) is { } curRow && Same(curRow, r)) continue;
            var what = templates.TryGetValue(k, out var t2)
                ? (t2.SameContent(r) ? "moved (order " + Show(t2.Precedence) + " -> " + Show(r.Precedence) + ")" : "changed from the vendor template: " + Describe(t2, r))
                : cur is { State: "override" } && FromBody(cur.Body) is { } was ? "your row changed: " + Describe(was, r) : "new row of yours at order " + Show(r.Precedence);
            res.Add(new RiskIndexWrite(k, "override", Body(r), what));
        }
        foreach (var (k, _) in templates.OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            if (wanted.Contains(k)) continue;
            if (overrides.TryGetValue(k, out var cur) && cur.State == "disable") continue;
            res.Add(new RiskIndexWrite(k, "disable", null, "vendor row switched off"));
        }
        foreach (var (k, cur) in overrides.OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            if (wanted.Contains(k) || templates.ContainsKey(k)) continue;
            res.Add(new RiskIndexWrite(k, "inherit", null, cur.State == "override" ? "your row removed" : "leftover state removed"));
        }
        return res;
    }

    private static string Show(string p) => Blank(p) ? "(none)" : p;

    /// "Severity: High -> Very High; Consequence score: 3 -> 4" (Precedence left out).
    public static string Describe(RiskIndexRow a, RiskIndexRow b)
    {
        var parts = RiskIndexColumns.Content.Where(c => a.Get(c) != b.Get(c))
            .Select(c => $"{RiskIndexColumns.Label(c)}: {(a.Get(c).Length == 0 ? "(any)" : a.Get(c))} -> {(b.Get(c).Length == 0 ? "(any)" : b.Get(c))}").ToList();
        return parts.Count == 0 ? "order only" : string.Join("; ", parts);
    }
}
